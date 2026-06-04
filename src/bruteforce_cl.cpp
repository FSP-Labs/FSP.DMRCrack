// FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
// Copyright (C) 2026 FSP-Labs
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

/*
 * OpenCL brute-force backend - vendor-neutral (NVIDIA / AMD / Intel).
 *
 * This is a drop-in replacement for bruteforce.cu / bruteforce.c that runs the
 * proven scoring pipeline on any OpenCL 1.2 device. The two GPU kernels
 * (kernel_strict for MOTOTRBO KMI9 modes 2/3, kernel_hytera for Hytera EP
 * mode 4) are ported 1:1 from the CUDA kernels and embedded from src/dmrcrack.cl.
 *
 * If no usable OpenCL device is found, or the capture has no ALG/MI metadata
 * (legacy statistical mode), the engine transparently falls back to the proven
 * multi-threaded CPU scorer - so the tool still works in GPU-less VMs.
 *
 * The host-side scoring helpers (precompute_cipher_packs, score_candidate, ...)
 * are self-contained copies of the proven CPU pipeline; this TU is the only
 * engine implementation compiled in the OpenCL build, so there is no symbol
 * clash with bruteforce.c / bruteforce.cu (which are excluded by CMake).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>

#include "bruteforce.h"
#include "payload_io.h"
#include "platform.h"
extern "C" {
#include "rc4.h"
}

#define CL_TARGET_OPENCL_VERSION 120
#if defined(__APPLE__)
#  include <OpenCL/cl.h>
#else
#  include <CL/cl.h>
#endif

/* Embedded OpenCL kernel source (generated from src/dmrcrack.cl by CMake). */
#include "dmrcrack_cl_embed.h"

extern "C" {

/* =========================================================================
 * Host-side scoring pipeline (self-contained copies of the proven CPU code)
 * ========================================================================= */

static const int rW_cpu[36] = {
    0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,2, 0,2,0,2,0,2, 0,2,0,2,0,2
};
static const int rX_cpu[36] = {
    23,10,22,9,21,8, 20,7,19,6,18,5, 17,4,16,3,15,2, 14,1,13,0,12,10, 11,9,10,8,9,7, 8,6,7,5,6,4
};
static const int rY_cpu[36] = {
    0,2,0,2,0,2, 0,2,0,3,0,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3
};
static const int rZ_cpu[36] = {
    5,3,4,2,3,1, 2,0,1,13,0,12, 22,11,21,10,20,9, 19,8,18,7,17,6, 16,5,15,4,14,3, 13,2,12,1,11,0
};
static const int sf_dibit_idx_cpu[3][36] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
      12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
      24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 },
    { 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
      48, 49, 50, 51, 52, 53, 78, 79, 80, 81, 82, 83,
      84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95 },
    { 96, 97, 98, 99,100,101,102,103,104,105,106,107,
     108,109,110,111,112,113,114,115,116,117,118,119,
     120,121,122,123,124,125,126,127,128,129,130,131 }
};

static int popcount_byte(unsigned char b)
{
    int c = 0;
    while (b) { c += (b & 1); b >>= 1; }
    return c;
}

static void key_to_5bytes(uint64_t key, unsigned char out[5])
{
    out[0] = (unsigned char)((key >> 32) & 0xFFu);
    out[1] = (unsigned char)((key >> 24) & 0xFFu);
    out[2] = (unsigned char)((key >> 16) & 0xFFu);
    out[3] = (unsigned char)((key >> 8) & 0xFFu);
    out[4] = (unsigned char)(key & 0xFFu);
}

static void rc4_discard_cpu(RC4_CTX *ctx, int nbytes)
{
    unsigned char dummy[64];
    unsigned char zeros[64];
    memset(zeros, 0, sizeof(zeros));
    while (nbytes > 0) {
        int step = nbytes > 64 ? 64 : nbytes;
        rc4_crypt(ctx, zeros, dummy, (size_t)step);
        nbytes -= step;
    }
}

static int is_rc4_alg_cpu(uint8_t alg)
{
    return alg == 0x21 || alg == 0x01 || ((alg & 0x07u) == 0x01u);
}

static int is_hytera_ep_alg_cpu(uint8_t alg)
{
    return alg == 0x02;
}

/* Inter-frame Hamming score for one burst (MOTOTRBO KMI9 pipeline). */
static double score_burst_correct_cpu(
    const unsigned char *payload33,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos)
{
    unsigned char kmi9[9];
    int sf, i, j, bi;
    unsigned char dec24[3][24];

    kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
    kmi9[3] = key5[3]; kmi9[4] = key5[4];
    kmi9[5] = (unsigned char)((mi >> 24) & 0xFFu);
    kmi9[6] = (unsigned char)((mi >> 16) & 0xFFu);
    kmi9[7] = (unsigned char)((mi >> 8) & 0xFFu);
    kmi9[8] = (unsigned char)(mi & 0xFFu);

    {
        RC4_CTX rc4;
        rc4_init(&rc4, kmi9, 9);
        rc4_discard_cpu(&rc4, 256 + burst_pos * 21);

        for (sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24];
            unsigned char bits49[49];
            unsigned char cipher7[7];
            unsigned char plain7[7];

            memset(ambe_fr, 0, sizeof(ambe_fr));

            for (i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_cpu[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[rW_cpu[i]][rX_cpu[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[rY_cpu[i]][rZ_cpu[i]] = (unsigned char)(dibit & 1u);
            }

            {
                int foo = 0;
                int pr_val;
                for (i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
                pr_val = 16 * foo;
                for (j = 22; j >= 0; --j) {
                    pr_val = (173 * pr_val + 13849) & 0xFFFF;
                    ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
                }
            }

            bi = 0;
            for (j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];

            memset(cipher7, 0, 7);
            for (i = 0; i < 49; ++i) {
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            }

            rc4_crypt(&rc4, cipher7, plain7, 7);

            for (i = 0; i < 24; ++i) {
                dec24[sf][i] = (unsigned char)((plain7[i >> 3] >> (7 - (i & 7))) & 1u);
            }
        }
    }

    {
        int h01 = 0, h12 = 0;
        for (i = 0; i < 24; ++i) {
            h01 += dec24[0][i] ^ dec24[1][i];
            h12 += dec24[1][i] ^ dec24[2][i];
        }
        return (double)(48 - h01 - h12);
    }
}

static double score_candidate(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    size_t line_count;
    size_t line_idx;
    double score = 0.0;
    int mode_policy = 0;

    line_count = payloads->count;
    if (sample_lines > 0 && (size_t)sample_lines < line_count) {
        line_count = (size_t)sample_lines;
    }

    {
        int mi_rc4_lines = 0;
        for (line_idx = 0; line_idx < line_count; ++line_idx) {
            const PayloadLine *line = &payloads->items[line_idx];
            uint8_t alg = line->has_algid ? line->algid : payloads->global_algid;
            if (line->has_mi && is_rc4_alg_cpu(alg)) mi_rc4_lines++;
        }
        if (line_count > 0 && mi_rc4_lines * 3 >= (int)line_count) {
            mode_policy = 2;
        }
    }

    if (mode_policy >= 2) {
        for (line_idx = 0; line_idx < line_count; ++line_idx) {
            const PayloadLine *line = &payloads->items[line_idx];
            uint32_t mi = line->has_mi ? line->mi : payloads->global_mi;
            int burst_pos = (int)(line_idx % 6);
            if (line->len >= 33) {
                score += score_burst_correct_cpu(line->data, key, mi, burst_pos);
            }
        }
        return score;
    }

    /* Legacy statistical path (no MI): autocorrelation + transitions + bit ratio. */
    {
    RC4_CTX rc4_base;
    rc4_init(&rc4_base, key, 5);

    for (line_idx = 0; line_idx < line_count; ++line_idx) {
        const PayloadLine *line = &payloads->items[line_idx];
        size_t bytes_to_test = line->len;
        unsigned char out[64];
        RC4_CTX rc4;
        size_t i;
        double local_score = 0.0;

        if (sample_bytes > 0 && (size_t)sample_bytes < bytes_to_test) {
            bytes_to_test = (size_t)sample_bytes;
        }
        if (bytes_to_test == 0) continue;
        if (bytes_to_test > sizeof(out)) bytes_to_test = sizeof(out);

        rc4 = rc4_base;
        rc4_crypt(&rc4, line->data, out, bytes_to_test);

        {
            int lag;
            int max_lag = (int)(bytes_to_test / 2);
            if (max_lag > 13) max_lag = 13;
            double autocorr_score = 0.0;
            for (lag = 1; lag <= max_lag; ++lag) {
                int n_bytes = (int)(bytes_to_test) - lag;
                int hamming = 0, expected, deviation, j;
                for (j = 0; j < n_bytes; ++j)
                    hamming += popcount_byte(out[j] ^ out[j + lag]);
                expected = n_bytes * 4;
                deviation = hamming - expected;
                if (deviation < 0) deviation = -deviation;
                autocorr_score += (double)deviation;
            }
            local_score += autocorr_score * 2.5;
        }
        {
            int transitions = 0;
            int total_bit_pairs = (int)(bytes_to_test * 8) - 1;
            int expected_transitions, deviation;
            for (i = 0; i < bytes_to_test; ++i) {
                unsigned char b = out[i];
                int k;
                for (k = 0; k < 7; ++k) {
                    int bit_k = (b >> (7 - k)) & 1;
                    int bit_k1 = (b >> (6 - k)) & 1;
                    if (bit_k != bit_k1) transitions++;
                }
                if (i + 1 < bytes_to_test) {
                    int last_bit = b & 1;
                    int first_bit = (out[i + 1] >> 7) & 1;
                    if (last_bit != first_bit) transitions++;
                }
            }
            expected_transitions = total_bit_pairs / 2;
            deviation = transitions - expected_transitions;
            if (deviation < 0) deviation = -deviation;
            local_score += (double)deviation * 3.0;
        }
        {
            int total_bits = 0;
            double bit_ratio, dev;
            for (i = 0; i < bytes_to_test; ++i) total_bits += popcount_byte(out[i]);
            bit_ratio = (double)total_bits / (double)(bytes_to_test * 8);
            dev = bit_ratio - 0.5;
            local_score += dev * dev * (double)(bytes_to_test * 8) * 60.0;
        }
        if (bytes_to_test >= 10) {
            static const int pair_offsets[] = { 1, 3, 9 };
            int p;
            for (p = 0; p < 3 && pair_offsets[p] < (int)bytes_to_test; ++p) {
                int off = pair_offsets[p];
                int n_pairs = (int)bytes_to_test - off;
                int xor_sum = 0, j;
                double mean_xor, var_xor;
                for (j = 0; j < n_pairs; ++j) xor_sum += (int)(out[j] ^ out[j + off]);
                mean_xor = (double)xor_sum / (double)n_pairs;
                var_xor = 0.0;
                for (j = 0; j < n_pairs; ++j) {
                    double d = (double)(out[j] ^ out[j + off]) - mean_xor;
                    var_xor += d * d;
                }
                var_xor /= (double)n_pairs;
                {
                    double random_var = 5440.0;
                    double var_dev = var_xor - random_var;
                    if (var_dev < 0) var_dev = -var_dev;
                    local_score += var_dev * 0.008;
                }
            }
        }
        {
            int max_run = 1, run = 1;
            for (i = 1; i < bytes_to_test; ++i) {
                if (out[i] == out[i - 1]) { run++; if (run > max_run) max_run = run; }
                else run = 1;
            }
            if (max_run > 5) local_score -= (max_run - 5) * 50.0;
        }
        score += local_score;
    }
    }
    return score;
}

/* Exported: precompute cipher packs (3x7 bytes per burst) for all payloads. */
void precompute_cipher_packs(const PayloadSet *payloads, unsigned char *out_cipher_packs, int payload_limit)
{
    for (int p = 0; p < payload_limit; ++p) {
        const unsigned char *payload33 = payloads->items[p].data;
        for (int sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24];
            memset(ambe_fr, 0, sizeof(ambe_fr));
            for (int i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_cpu[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[rW_cpu[i]][rX_cpu[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[rY_cpu[i]][rZ_cpu[i]] = (unsigned char)(dibit & 1u);
            }
            int foo = 0;
            for (int i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
            int pr_val = 16 * foo;
            for (int j = 22; j >= 0; --j) {
                pr_val = (173 * pr_val + 13849) & 0xFFFF;
                ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
            }
            unsigned char bits49[49];
            int bi = 0;
            for (int j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (int j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (int j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (int j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];
            unsigned char cipher7[7];
            memset(cipher7, 0, 7);
            for (int i = 0; i < 49; ++i)
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            memcpy(out_cipher_packs + p * DMR_CIPHER_PACK_BYTES + sf * 7, cipher7, 7);
        }
    }
}

/* =========================================================================
 * Score/key packing (matches the kernel's pack_score_key / unpack_score)
 * ========================================================================= */

static uint64_t host_pack_score_key(float score, uint64_t key)
{
    uint32_t u;
    memcpy(&u, &score, sizeof(u));
    uint32_t sortable = u ^ (uint32_t)(-(int32_t)(u >> 31) | 0x80000000u);
    return ((uint64_t)(sortable >> 8) << 40) | (key & 0xFFFFFFFFFFULL);
}

static uint64_t host_unpack_key(uint64_t packed)
{
    return packed & 0xFFFFFFFFFFULL;
}

/* =========================================================================
 * OpenCL engine state
 * ========================================================================= */

typedef struct {
    cl_platform_id   platform;
    cl_device_id     device;
    cl_context       context;
    cl_command_queue queue;
    cl_program       program;
    cl_kernel        kernel;       /* active kernel (strict or hytera) */
    cl_mem           buf_cipher;
    cl_mem           buf_mi;
    cl_mem           buf_meta;
    cl_mem           buf_absfloor;
    cl_mem           buf_best;
    int              mode_policy;
    int              payload_count;
    uint32_t         global_mi;
    size_t           local_size;
    int              gpu_ok;       /* 1 if OpenCL path is active */
} ClState;

typedef struct {
    BruteforceEngine *engine;
    uint64_t start_key;
    uint64_t end_key;
    int      worker_index;
} CpuWorkerCtx;

static void cl_set_error(BruteforceEngine *e, const char *msg)
{
    snprintf(e->cuda_error, sizeof(e->cuda_error), "%s", msg);
}

static void cl_release_state(ClState *st)
{
    if (!st) return;
    if (st->buf_best)     clReleaseMemObject(st->buf_best);
    if (st->buf_absfloor) clReleaseMemObject(st->buf_absfloor);
    if (st->buf_meta)     clReleaseMemObject(st->buf_meta);
    if (st->buf_mi)       clReleaseMemObject(st->buf_mi);
    if (st->buf_cipher)   clReleaseMemObject(st->buf_cipher);
    if (st->kernel)       clReleaseKernel(st->kernel);
    if (st->program)      clReleaseProgram(st->program);
    if (st->queue)        clReleaseCommandQueue(st->queue);
    if (st->context)      clReleaseContext(st->context);
    free(st);
}

/* Pick the first GPU device across all platforms; fall back to any device. */
static int cl_pick_device(cl_platform_id *out_plat, cl_device_id *out_dev)
{
    cl_uint nplat = 0;
    if (clGetPlatformIDs(0, NULL, &nplat) != CL_SUCCESS || nplat == 0) return 0;
    cl_platform_id *plats = (cl_platform_id *)calloc(nplat, sizeof(cl_platform_id));
    if (!plats) return 0;
    clGetPlatformIDs(nplat, plats, NULL);

    cl_device_id any_dev = NULL; cl_platform_id any_plat = NULL;
    int found = 0;
    for (cl_uint i = 0; i < nplat && !found; ++i) {
        cl_uint ndev = 0;
        if (clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_GPU, 0, NULL, &ndev) == CL_SUCCESS && ndev > 0) {
            cl_device_id d = NULL;
            clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_GPU, 1, &d, NULL);
            *out_plat = plats[i]; *out_dev = d; found = 1; break;
        }
        if (!any_dev) {
            cl_uint na = 0;
            if (clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_ALL, 0, NULL, &na) == CL_SUCCESS && na > 0) {
                clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_ALL, 1, &any_dev, NULL);
                any_plat = plats[i];
            }
        }
    }
    if (!found && any_dev) { *out_plat = any_plat; *out_dev = any_dev; found = 1; }
    free(plats);
    return found;
}

/* Build the embedded program and select the kernel for the active mode. */
static int cl_build(BruteforceEngine *engine, ClState *st)
{
    cl_int err;
    const char *src = DMRCRACK_CL_SRC;
    size_t src_len = strlen(src);

    st->context = clCreateContext(NULL, 1, &st->device, NULL, NULL, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateContext failed"); return 0; }

    st->queue = clCreateCommandQueue(st->context, st->device, 0, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateCommandQueue failed"); return 0; }

    st->program = clCreateProgramWithSource(st->context, 1, &src, &src_len, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateProgramWithSource failed"); return 0; }

    err = clBuildProgram(st->program, 1, &st->device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        char log[4096]; size_t loglen = 0;
        clGetProgramBuildInfo(st->program, st->device, CL_PROGRAM_BUILD_LOG,
                              sizeof(log) - 1, log, &loglen);
        log[loglen < sizeof(log) ? loglen : sizeof(log) - 1] = '\0';
        snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                 "OpenCL build failed: %.200s", log);
        return 0;
    }

    const char *kname = (st->mode_policy == 4) ? "kernel_hytera" : "kernel_strict";
    st->kernel = clCreateKernel(st->program, kname, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateKernel failed"); return 0; }

    return 1;
}

static int cl_upload(BruteforceEngine *engine, ClState *st,
                     const unsigned char *cipher_packs,
                     const uint32_t *line_mi,
                     const unsigned char *meta_flags,
                     const float *abs_floor,
                     int payload_count)
{
    cl_int err;
    size_t cipher_bytes = (size_t)payload_count * DMR_CIPHER_PACK_BYTES;

    st->buf_cipher = clCreateBuffer(st->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                    cipher_bytes, (void *)cipher_packs, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateBuffer(cipher) failed"); return 0; }

    st->buf_mi = clCreateBuffer(st->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                (size_t)payload_count * sizeof(uint32_t), (void *)line_mi, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateBuffer(mi) failed"); return 0; }

    st->buf_meta = clCreateBuffer(st->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  (size_t)payload_count, (void *)meta_flags, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateBuffer(meta) failed"); return 0; }

    st->buf_absfloor = clCreateBuffer(st->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                      (size_t)(payload_count + 1) * sizeof(float),
                                      (void *)abs_floor, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateBuffer(absfloor) failed"); return 0; }

    st->buf_best = clCreateBuffer(st->context, CL_MEM_READ_WRITE, sizeof(cl_ulong), NULL, &err);
    if (err != CL_SUCCESS) { cl_set_error(engine, "clCreateBuffer(best) failed"); return 0; }

    return 1;
}

/* Write the progress checkpoint sidecar (same format as the CUDA backend). */
static void cl_write_checkpoint(BruteforceEngine *engine, uint64_t next_key)
{
    if (engine->progress_path[0] == '\0') return;
    uint64_t orig = engine->cfg.has_resume_context
                  ? engine->cfg.original_start_key : engine->cfg.start_key;
    FILE *fp = fopen(engine->progress_path, "wt");
    if (!fp) return;
    uint64_t best_key;
    double best_score;
    plat_mutex_lock(&engine->lock);
    best_key = engine->best_key;
    best_score = engine->best_score;
    plat_mutex_unlock(&engine->lock);
    fprintf(fp, "offset=%llu\nend=%llu\nbest_key=%010llX\nbest_score=%.6f\noriginal_start=%llu\n",
            (unsigned long long)next_key,
            (unsigned long long)engine->cfg.end_key,
            (unsigned long long)best_key,
            best_score,
            (unsigned long long)orig);
    fclose(fp);
}

/* Recompute the exact (double-precision) score for a candidate key and update
 * the engine's best if it improves on the current best. */
static void cl_consider_best(BruteforceEngine *engine, uint64_t key)
{
    unsigned char key5[5];
    key_to_5bytes(key, key5);
    double s = score_candidate(engine->payloads, engine->cfg.sample_lines,
                               engine->cfg.sample_bytes, key5);
    plat_mutex_lock(&engine->lock);
    if (s > engine->best_score) {
        engine->best_score = s;
        engine->best_key = key;
    }
    plat_mutex_unlock(&engine->lock);
}

/* GPU launcher: enqueue the keyspace in chunks, poll for stop/pause, checkpoint. */
static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL cl_launcher_proc(void *arg)
{
    BruteforceEngine *engine = (BruteforceEngine *)arg;
    ClState *st = (ClState *)engine->workers;
    const uint64_t CHUNK = 1ULL << 23;            /* 8M keys per enqueue */
    uint64_t offset = engine->cfg.start_key;
    uint64_t last_best_key = (uint64_t)-1;
    uint64_t last_ckpt_ms = plat_ticks_ms();

    plat_atomic32_store(&engine->cuda_stage, 2);   /* scanning */

    while (offset <= engine->cfg.end_key) {
        if (plat_atomic32_load(&engine->stop_requested)) break;
        if (plat_atomic32_load(&engine->paused)) {
            plat_event_wait(&engine->pause_event);
            if (plat_atomic32_load(&engine->stop_requested)) break;
        }

        uint64_t remaining = engine->cfg.end_key - offset + 1ULL;
        uint64_t this_chunk = remaining < CHUNK ? remaining : CHUNK;
        int enable_prune = (this_chunk > (1ULL << 20)) ? 1 : 0;

        cl_ulong  cl_start = (cl_ulong)offset;
        cl_ulong  cl_total = (cl_ulong)this_chunk;
        cl_int    ci = st->payload_count;
        cl_uint   cmi = st->global_mi;
        cl_int    cprune = enable_prune;

        clSetKernelArg(st->kernel, 0, sizeof(cl_ulong), &cl_start);
        clSetKernelArg(st->kernel, 1, sizeof(cl_ulong), &cl_total);
        clSetKernelArg(st->kernel, 2, sizeof(cl_int),   &ci);
        clSetKernelArg(st->kernel, 3, sizeof(cl_uint),  &cmi);
        clSetKernelArg(st->kernel, 4, sizeof(cl_int),   &cprune);
        clSetKernelArg(st->kernel, 5, sizeof(cl_mem),   &st->buf_cipher);
        clSetKernelArg(st->kernel, 6, sizeof(cl_mem),   &st->buf_mi);
        clSetKernelArg(st->kernel, 7, sizeof(cl_mem),   &st->buf_meta);
        clSetKernelArg(st->kernel, 8, sizeof(cl_mem),   &st->buf_absfloor);
        clSetKernelArg(st->kernel, 9, sizeof(cl_mem),   &st->buf_best);

        size_t local = st->local_size;
        size_t global = ((this_chunk + local - 1) / local) * local;

        cl_int err = clEnqueueNDRangeKernel(st->queue, st->kernel, 1, NULL,
                                            &global, &local, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                     "clEnqueueNDRangeKernel failed (%d)", (int)err);
            break;
        }
        cl_int fin = clFinish(st->queue);
        if (fin != CL_SUCCESS) {
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                     "clFinish failed (%d)", (int)fin);
            break;
        }

        plat_atomic64_add(&engine->keys_tested, (int64_t)this_chunk);
        plat_atomic64_add(&engine->gpu_keys_tested, (int64_t)this_chunk);

        cl_ulong packed = 0;
        if (clEnqueueReadBuffer(st->queue, st->buf_best, CL_TRUE, 0,
                                sizeof(cl_ulong), &packed, 0, NULL, NULL) == CL_SUCCESS
            && packed != 0) {
            uint64_t key = host_unpack_key((uint64_t)packed);
            if (key != last_best_key) {
                last_best_key = key;
                cl_consider_best(engine, key);
            }
        }

        offset += this_chunk;

        uint64_t now = plat_ticks_ms();
        if (now - last_ckpt_ms >= 30000ULL) {
            cl_write_checkpoint(engine, offset);
            last_ckpt_ms = now;
        }
    }

    if (plat_atomic32_load(&engine->stop_requested) == 0) {
        plat_atomic32_store(&engine->search_completed, 1);
        if (engine->progress_path[0] != '\0') {
            plat_delete_file(engine->progress_path);
            engine->progress_path[0] = '\0';
        }
    }
    plat_atomic32_store(&engine->cuda_stage, 3);
    plat_atomic32_store(&engine->running, 0);
    plat_event_set(&engine->pause_event);
    PLAT_THREAD_RETURN;
}

/* CPU fallback worker (legacy mode or no OpenCL device). */
static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL cl_cpu_worker_proc(void *arg)
{
    CpuWorkerCtx *ctx = (CpuWorkerCtx *)arg;
    BruteforceEngine *engine = ctx->engine;
    uint64_t k;
    uint64_t local_count = 0;
    double   local_best_score = -DBL_MAX;
    uint64_t local_best_key = ctx->start_key;

    for (k = ctx->start_key; k <= ctx->end_key; ++k) {
        if ((local_count & STOP_POLL_MASK) == 0) {
            if (plat_atomic32_load(&engine->stop_requested)) break;
            if (plat_atomic32_load(&engine->paused)) plat_event_wait(&engine->pause_event);
            if (plat_atomic32_load(&engine->stop_requested)) break;
        }
        unsigned char key5[5];
        key_to_5bytes(k, key5);
        double s = score_candidate(engine->payloads, engine->cfg.sample_lines,
                                   engine->cfg.sample_bytes, key5);
        if (s > local_best_score) { local_best_score = s; local_best_key = k; }

        if (++local_count >= 1024) {
            plat_atomic64_add(&engine->keys_tested, (int64_t)local_count);
            local_count = 0;
        }
    }
    if (local_count) plat_atomic64_add(&engine->keys_tested, (int64_t)local_count);

    plat_mutex_lock(&engine->lock);
    if (local_best_score > engine->best_score) {
        engine->best_score = local_best_score;
        engine->best_key = local_best_key;
    }
    plat_mutex_unlock(&engine->lock);

    if (plat_atomic32_inc(&engine->finished_threads) == engine->cfg.thread_count) {
        if (plat_atomic32_load(&engine->stop_requested) == 0)
            plat_atomic32_store(&engine->search_completed, 1);
        plat_atomic32_store(&engine->running, 0);
        plat_event_set(&engine->pause_event);
    }
    PLAT_THREAD_RETURN;
}

/* =========================================================================
 * Engine API
 * ========================================================================= */

void bruteforce_engine_init(BruteforceEngine *engine)
{
    memset(engine, 0, sizeof(*engine));
    plat_mutex_init(&engine->lock);
    plat_hrfreq_init(&engine->qpc_freq);
    engine->pause_event = plat_event_create(1);
}

void bruteforce_engine_destroy(BruteforceEngine *engine)
{
    bruteforce_stop(engine);
    plat_event_destroy(&engine->pause_event);
    plat_mutex_destroy(&engine->lock);
}

static void cl_free_workers(BruteforceEngine *engine)
{
    if (engine->thread_handles) { free(engine->thread_handles); engine->thread_handles = NULL; }
    /* engine->workers holds either ClState* (GPU) or CpuWorkerCtx[] (CPU). */
}

/* Determine mode_policy from the payload metadata (matches the CUDA selector). */
static int cl_select_mode(const PayloadSet *payloads, int payload_count)
{
    int mi_rc4 = 0, mi_hytera = 0, has_any_mi = 0;
    for (int i = 0; i < payload_count; ++i) {
        const PayloadLine *line = &payloads->items[i];
        uint8_t alg = line->has_algid ? line->algid : payloads->global_algid;
        if (line->has_mi) {
            has_any_mi = 1;
            if (is_rc4_alg_cpu(alg))       mi_rc4++;
            if (is_hytera_ep_alg_cpu(alg)) mi_hytera++;
        }
    }
    if (payload_count > 0 && mi_hytera * 10 >= payload_count * 9) return 4;
    if (payload_count > 0 && mi_rc4   * 10 >= payload_count * 9) return 3;
    if (payload_count > 0 && mi_rc4   * 3  >= payload_count)     return 2;
    if (!payloads->has_global_mi && !has_any_mi)                 return 1;
    return 0;
}

int bruteforce_start(
    BruteforceEngine *engine,
    const BruteforceConfig *cfg,
    const PayloadSet *payloads,
    char *err,
    size_t err_len)
{
    if (plat_atomic32_load(&engine->running) != 0) {
        snprintf(err, err_len, "A search is already running");
        return 0;
    }
    cl_free_workers(engine);
    engine->workers = NULL;

    if (cfg->start_key > cfg->end_key) { snprintf(err, err_len, "Start key must be <= end key"); return 0; }
    if (cfg->end_key > 0xFFFFFFFFFFull) { snprintf(err, err_len, "End key exceeds 40 bits"); return 0; }
    if (payloads == NULL || payloads->count == 0) { snprintf(err, err_len, "No payloads loaded"); return 0; }

    engine->cfg = *cfg;
    if (engine->cfg.sample_bytes <= 0) engine->cfg.sample_bytes = 33;
    if (engine->cfg.sample_lines <= 0 || (size_t)engine->cfg.sample_lines > payloads->count)
        engine->cfg.sample_lines = (int)payloads->count;
    if (engine->cfg.thread_count <= 0 || engine->cfg.thread_count > 64) {
        int n = plat_cpu_count();
        engine->cfg.thread_count = (n > 0 && n <= 64) ? n : 4;
    }
    engine->payloads = payloads;
    engine->cuda_error[0] = '\0';

    plat_atomic64_store(&engine->keys_tested, 0);
    plat_atomic64_store(&engine->gpu_keys_tested, 0);
    plat_atomic32_store(&engine->stop_requested, 0);
    plat_atomic32_store(&engine->paused, 0);
    plat_atomic32_store(&engine->finished_threads, 0);
    plat_atomic32_store(&engine->search_completed, 0);
    plat_atomic32_store(&engine->cuda_stage, 0);
    engine->best_key   = cfg->has_seed_best ? cfg->seed_best_key   : cfg->start_key;
    engine->best_score = cfg->has_seed_best ? cfg->seed_best_score : -DBL_MAX;
    plat_event_set(&engine->pause_event);
    plat_hrtimer_now(&engine->qpc_start);

    int payload_count = (int)payloads->count;
    if (payload_count > 256) payload_count = 256;   /* cap matches CUDA constant memory */
    int mode_policy = cl_select_mode(payloads, payload_count);

    /* Try the OpenCL GPU path for the proven KMI9 / Hytera modes (2/3/4). */
    int use_gpu = (mode_policy >= 2);
    ClState *st = NULL;
    if (use_gpu) {
        cl_platform_id plat = NULL; cl_device_id dev = NULL;
        if (cl_pick_device(&plat, &dev)) {
            st = (ClState *)calloc(1, sizeof(ClState));
            if (st) {
                st->platform = plat; st->device = dev;
                st->mode_policy = mode_policy;
                st->payload_count = payload_count;
                st->global_mi = payloads->has_global_mi ? payloads->global_mi : 0u;

                /* Build per-line MI / meta arrays + abs_floor thresholds. */
                unsigned char *cipher = (unsigned char *)calloc((size_t)payload_count, DMR_CIPHER_PACK_BYTES);
                uint32_t *line_mi = (uint32_t *)calloc((size_t)payload_count, sizeof(uint32_t));
                unsigned char *meta = (unsigned char *)calloc((size_t)payload_count, 1);
                float *absf = (float *)calloc((size_t)(payload_count + 1), sizeof(float));
                if (cipher && line_mi && meta && absf) {
                    precompute_cipher_packs(payloads, cipher, payload_count);
                    for (int i = 0; i < payload_count; ++i) {
                        if (payloads->items[i].has_mi) { meta[i] |= 0x1u; line_mi[i] = payloads->items[i].mi; }
                        else line_mi[i] = st->global_mi;
                    }
                    absf[0] = -FLT_MAX;
                    for (int k = 1; k <= payload_count; ++k) {
                        float sigma_k = 3.46f * sqrtf((float)k);
                        absf[k] = 33.0f * (float)k - 2.0f * sigma_k;
                    }

                    size_t lsz = 64;
                    if (cl_build(engine, st) &&
                        cl_upload(engine, st, cipher, line_mi, meta, absf, payload_count)) {
                        clGetKernelWorkGroupInfo(st->kernel, st->device,
                                                 CL_KERNEL_WORK_GROUP_SIZE,
                                                 sizeof(lsz), &lsz, NULL);
                        if (lsz == 0) lsz = 64;
                        if (lsz > 256) lsz = 256;
                        st->local_size = lsz;

                        cl_ulong zero = 0;
                        if (cfg->has_seed_best)
                            zero = (cl_ulong)host_pack_score_key((float)cfg->seed_best_score, cfg->seed_best_key);
                        clEnqueueWriteBuffer(st->queue, st->buf_best, CL_TRUE, 0,
                                             sizeof(cl_ulong), &zero, 0, NULL, NULL);

                        char devname[128] = {0};
                        clGetDeviceInfo(st->device, CL_DEVICE_NAME, sizeof(devname) - 1, devname, NULL);
                        snprintf(engine->cuda_device_name, sizeof(engine->cuda_device_name),
                                 "%s (OpenCL)", devname);
                        st->gpu_ok = 1;
                    }
                }
                free(cipher); free(line_mi); free(meta); free(absf);
                if (!st->gpu_ok) { cl_release_state(st); st = NULL; }
            }
        }
    }

    if (st && st->gpu_ok) {
        /* GPU path: a single launcher thread drives the queue. */
        engine->workers = st;
        engine->cfg.thread_count = 1;
        engine->thread_handles = (plat_thread_t *)calloc(1, sizeof(plat_thread_t));
        if (!engine->thread_handles) {
            cl_release_state(st); engine->workers = NULL;
            snprintf(err, err_len, "Out of memory");
            return 0;
        }
        plat_atomic32_store(&engine->cuda_active, 1);
        plat_atomic32_store(&engine->running, 1);
        if (plat_thread_create(&engine->thread_handles[0], cl_launcher_proc, engine) != 0) {
            plat_atomic32_store(&engine->running, 0);
            cl_release_state(st); engine->workers = NULL;
            free(engine->thread_handles); engine->thread_handles = NULL;
            snprintf(err, err_len, "Failed to create OpenCL launcher thread");
            return 0;
        }
        return 1;
    }

    /* CPU fallback (no OpenCL device, or legacy statistical mode). */
    {
        engine->cuda_device_name[0] = '\0';
        plat_atomic32_store(&engine->cuda_active, 0);

        uint64_t total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
        if ((uint64_t)engine->cfg.thread_count > total) engine->cfg.thread_count = (int)total;
        int nthreads = engine->cfg.thread_count;

        engine->thread_handles = (plat_thread_t *)calloc((size_t)nthreads, sizeof(plat_thread_t));
        CpuWorkerCtx *workers = (CpuWorkerCtx *)calloc((size_t)nthreads, sizeof(CpuWorkerCtx));
        if (!engine->thread_handles || !workers) {
            free(engine->thread_handles); engine->thread_handles = NULL;
            free(workers);
            snprintf(err, err_len, "Out of memory allocating worker threads");
            return 0;
        }
        engine->workers = workers;

        uint64_t chunk = total / (uint64_t)nthreads;
        uint64_t rem = total % (uint64_t)nthreads;
        uint64_t start = engine->cfg.start_key;
        plat_atomic32_store(&engine->running, 1);
        for (int t = 0; t < nthreads; ++t) {
            uint64_t this_count = chunk + ((uint64_t)t < rem ? 1ull : 0ull);
            workers[t].engine = engine;
            workers[t].start_key = start;
            workers[t].end_key = start + this_count - 1ull;
            workers[t].worker_index = t;
            if (plat_thread_create(&engine->thread_handles[t], cl_cpu_worker_proc, &workers[t]) != 0) {
                plat_atomic32_store(&engine->stop_requested, 1);
                plat_atomic32_store(&engine->running, 0);
                plat_event_set(&engine->pause_event);
                plat_threads_join(engine->thread_handles, t);
                free(engine->thread_handles); engine->thread_handles = NULL;
                free(workers); engine->workers = NULL;
                snprintf(err, err_len, "Error creating brute-force threads");
                return 0;
            }
            start = workers[t].end_key + 1ull;
        }
        return 1;
    }
}

void bruteforce_pause(BruteforceEngine *engine)
{
    if (plat_atomic32_load(&engine->running) == 0) return;
    plat_atomic32_store(&engine->paused, 1);
    plat_event_reset(&engine->pause_event);
}

void bruteforce_resume(BruteforceEngine *engine)
{
    if (plat_atomic32_load(&engine->running) == 0) return;
    plat_atomic32_store(&engine->paused, 0);
    plat_event_set(&engine->pause_event);
}

void bruteforce_stop(BruteforceEngine *engine)
{
    if (engine->thread_handles == NULL) {
        plat_atomic32_store(&engine->running, 0);
        return;
    }
    plat_atomic32_store(&engine->stop_requested, 1);
    plat_atomic32_store(&engine->paused, 0);
    plat_event_set(&engine->pause_event);

    plat_threads_join(engine->thread_handles, engine->cfg.thread_count);
    plat_atomic32_store(&engine->running, 0);

    if (plat_atomic32_load(&engine->cuda_active)) {
        cl_release_state((ClState *)engine->workers);
        engine->workers = NULL;
        plat_atomic32_store(&engine->cuda_active, 0);
    } else if (engine->workers) {
        free(engine->workers);
        engine->workers = NULL;
    }
    /* Close each thread handle (Windows _beginthreadex handles must be closed)
     * before freeing the array, so repeated start/stop cycles do not leak. */
    for (int t = 0; t < engine->cfg.thread_count; ++t)
        plat_thread_close(engine->thread_handles[t]);
    free(engine->thread_handles);
    engine->thread_handles = NULL;
}

void bruteforce_get_snapshot(const BruteforceEngine *engine, BruteforceSnapshot *out)
{
    plat_hrtimer_t now;
    double elapsed;
    uint64_t keys, total = 0;

    keys = (uint64_t)plat_atomic64_load((plat_atomic64_t *)&engine->keys_tested);
    if (engine->cfg.end_key >= engine->cfg.start_key)
        total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;

    plat_hrtimer_now(&now);
    elapsed = plat_hrtimer_elapsed_s(&engine->qpc_start, &now, &engine->qpc_freq);
    if (elapsed < 0.0) elapsed = 0.0;

    out->keys_tested = keys;
    out->gpu_keys_tested = (uint64_t)plat_atomic64_load((plat_atomic64_t *)&engine->gpu_keys_tested);
    out->total_keys = total;
    plat_mutex_lock((plat_mutex_t *)&engine->lock);
    out->best_key = engine->best_key;
    out->best_score = engine->best_score;
    plat_mutex_unlock((plat_mutex_t *)&engine->lock);
    out->elapsed_seconds = elapsed;
    out->running  = (int)plat_atomic32_load((plat_atomic32_t *)&engine->running);
    out->paused   = (int)plat_atomic32_load((plat_atomic32_t *)&engine->paused);
    out->finished = (int)plat_atomic32_load((plat_atomic32_t *)&engine->search_completed);
    out->keys_per_second = (elapsed > 0.0) ? (double)keys / elapsed : 0.0;
    out->eta_seconds = (out->keys_per_second > 0.0 && total > keys)
                     ? (double)(total - keys) / out->keys_per_second : -1.0;
}

double bruteforce_test_score(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    return score_candidate(payloads, sample_lines, sample_bytes, key);
}

} /* extern "C" */
