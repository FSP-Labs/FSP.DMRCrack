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
 * bruteforce.cu - GPU acceleration engine (NVIDIA CUDA) for FSP.DMRCrack
 * File adapted for NVCC. Replaces the original standard bruteforce.c.
 */

#include "../include/bruteforce.h"
#include <float.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <process.h>
#include <string.h>

// CUDA headers
#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "../include/rc4.h"
#ifdef __cplusplus
}
#endif

/*
 * =========================================================================
 * GPU RC4 PROTOCOL MACROS AND COPIES (__device__)
 * =========================================================================
 */

// Ultra-fast constant memory (1-cycle L1 cache) for payloads shared by all threads
#define MAX_CONST_LINES 256
__constant__ unsigned char d_const_payloads[8192];
__constant__ unsigned char d_const_cipher_packs[MAX_CONST_LINES * 21]; // 21 bytes per burst (3x7)
__constant__ unsigned int d_const_mi[MAX_CONST_LINES];
__constant__ unsigned char d_const_algid[MAX_CONST_LINES];
__constant__ unsigned char d_const_meta_flags[MAX_CONST_LINES];
__constant__ float d_abs_floor[MAX_CONST_LINES + 1]; // Absolute screening threshold by burst count

typedef struct {
    unsigned char S[256];
    unsigned char i;
    unsigned char j;
} RC4_CTX_DEV;

__device__ __forceinline__ uint32_t dmr_mi_lfsr_next_dev(uint32_t mi)
{
    uint32_t bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1u;
    return (mi << 1) | bit;
}

__device__ __forceinline__ uint32_t dmr_mi_lfsr_prev_dev(uint32_t mi)
{
    uint32_t old31 = ((mi >> 0) ^ (mi >> 4) ^ (mi >> 2)) & 1u;
    return (mi >> 1) | (old31 << 31);
}

__device__ __forceinline__ uint8_t is_rc4_alg_dev(uint8_t alg)
{
    return (uint8_t)(alg == 0x21 || alg == 0x01 || ((alg & 0x07u) == 0x01u));
}

__device__ __forceinline__ void compose_kmi9_dev(const unsigned char key5[5], uint32_t mi, unsigned char out9[9])
{
    out9[0] = key5[0];
    out9[1] = key5[1];
    out9[2] = key5[2];
    out9[3] = key5[3];
    out9[4] = key5[4];
    out9[5] = (unsigned char)((mi >> 24) & 0xFFu);
    out9[6] = (unsigned char)((mi >> 16) & 0xFFu);
    out9[7] = (unsigned char)((mi >> 8) & 0xFFu);
    out9[8] = (unsigned char)(mi & 0xFFu);
}

__device__ __forceinline__ void rc4_init_dev_len(RC4_CTX_DEV *ctx, const unsigned char *key, int key_len)
{
    int i, j;
    int k_idx = 0;
    if (key_len <= 0) key_len = 1;
    #pragma unroll 4
    for (i = 0; i < 256; i++) {
        ctx->S[i] = (unsigned char)i;
    }
    j = 0;
    ctx->i = 0;
    ctx->j = 0;

    #pragma unroll 4
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[k_idx]) & 0xFF;
        {
            unsigned char t = ctx->S[i];
            ctx->S[i] = ctx->S[j];
            ctx->S[j] = t;
        }
        k_idx++;
        if (k_idx == key_len) k_idx = 0;
    }
}

/* Specialized KSA for 9-byte key: eliminates branch in inner loop via chunk-of-9 unrolling */
__device__ __forceinline__ void rc4_ksa9_dev(RC4_CTX_DEV *ctx, const unsigned char key9[9])
{
    #pragma unroll
    for (int i = 0; i < 256; i++) ctx->S[i] = (unsigned char)i;
    int j = 0;
    ctx->i = 0;
    ctx->j = 0;

    /* 28 full rounds of 9 iterations = 252, then 4 remainder */
    for (int round = 0; round < 28; ++round) {
        int base = round * 9;
        #pragma unroll
        for (int k = 0; k < 9; ++k) {
            int idx = base + k;
            j = (j + ctx->S[idx] + key9[k]) & 0xFF;
            unsigned char t = ctx->S[idx]; ctx->S[idx] = ctx->S[j]; ctx->S[j] = t;
        }
    }
    #pragma unroll
    for (int k = 0; k < 4; ++k) {
        int idx = 252 + k;
        j = (j + ctx->S[idx] + key9[k]) & 0xFF;
        unsigned char t = ctx->S[idx]; ctx->S[idx] = ctx->S[j]; ctx->S[j] = t;
    }
}

__device__ __forceinline__ void rc4_init_dev(RC4_CTX_DEV *ctx, const unsigned char *key)
{
    rc4_init_dev_len(ctx, key, 5);
}

__device__ __forceinline__ void rc4_crypt_dev(RC4_CTX_DEV *ctx, const unsigned char *in, unsigned char *out, int len)
{
    unsigned char i = ctx->i;
    unsigned char j = ctx->j;
    
    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        unsigned char t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
        
        unsigned char K = ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];
        out[k] = in[k] ^ K;
    }
    
    ctx->i = i;
    ctx->j = j;
}

__device__ __forceinline__ void rc4_discard_dev(RC4_CTX_DEV *ctx, int nbytes)
{
    unsigned char i = ctx->i;
    unsigned char j = ctx->j;
    for (int k = 0; k < nbytes; ++k) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        unsigned char t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
        // Removed unnecessary S-box read
    }
    ctx->i = i;
    ctx->j = j;
}

__device__ __forceinline__ void rc4_crypt_first3_skip4_dev(
    RC4_CTX_DEV *ctx,
    const unsigned char in7[7],
    unsigned char out3[3])
{
    unsigned char i = ctx->i;
    unsigned char j = ctx->j;

    #pragma unroll
    for (int k = 0; k < 7; ++k) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        unsigned char t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;

        unsigned char K = ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];
        if (k < 3) {
            out3[k] = in7[k] ^ K;
        }
    }

    ctx->i = i;
    ctx->j = j;
}

__device__ __forceinline__ void key_to_5bytes_dev(uint64_t key, unsigned char out[5])
{
    out[0] = (unsigned char)((key >> 32) & 0xFFu);
    out[1] = (unsigned char)((key >> 24) & 0xFFu);
    out[2] = (unsigned char)((key >> 16) & 0xFFu);
    out[3] = (unsigned char)((key >> 8) & 0xFFu);
    out[4] = (unsigned char)(key & 0xFFu);
}

__device__ __forceinline__ int popcount_byte_dev(unsigned char b)
{
    return __popc((unsigned int)b);
}

__device__ __forceinline__ void update_best_score_dev(
    float score,
    uint64_t current_key,
    float* __restrict__ dev_best_score,
    unsigned long long* __restrict__ dev_best_key)
{
    /* Lock-free update: atomicCAS on the float reinterpreted as int.
     * IEEE754 floats preserve ordering under int comparison for positive values,
     * but we use float comparison explicitly for safety. */
    if (score > *dev_best_score) {
        int *score_int = (int *)dev_best_score;
        int old_val = *score_int, assumed;
        for (;;) {
            assumed = old_val;
            if (score <= __int_as_float(assumed)) break;
            old_val = atomicCAS(score_int, assumed, __float_as_int(score));
            if (old_val == assumed) {
                atomicExch(dev_best_key, (unsigned long long int)current_key);
                __threadfence();
                break;
            }
        }
    }
}

__device__ __constant__ int dmr_rW_dev[36] = {
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 2,
    0, 2, 0, 2, 0, 2,
    0, 2, 0, 2, 0, 2
};

__device__ __constant__ int dmr_rX_dev[36] = {
    23, 10, 22, 9, 21, 8,
    20, 7, 19, 6, 18, 5,
    17, 4, 16, 3, 15, 2,
    14, 1, 13, 0, 12, 10,
    11, 9, 10, 8, 9, 7,
    8, 6, 7, 5, 6, 4
};

__device__ __constant__ int dmr_rY_dev[36] = {
    0, 2, 0, 2, 0, 2,
    0, 2, 0, 3, 0, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3
};

__device__ __constant__ int dmr_rZ_dev[36] = {
    5, 3, 4, 2, 3, 1,
    2, 0, 1, 13, 0, 12,
    22, 11, 21, 10, 20, 9,
    19, 8, 18, 7, 17, 6,
    16, 5, 15, 4, 14, 3,
    13, 2, 12, 1, 11, 0
};

/*
 * Sub-frame dibit indices into the 33-byte (132-dibit) payload:
 * SF0: dibits 0-35
 * SF1: dibits 36-53 then 78-95 (split by sync at 54-77)
 * SF2: dibits 96-131
 */
__device__ __constant__ int sf_dibit_idx_dev[3][36] = {
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

/* Host-side copies for precompute_cipher_packs */
static const int dmr_rW_host[36] = {
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 2,
    0, 2, 0, 2, 0, 2,
    0, 2, 0, 2, 0, 2
};

static const int dmr_rX_host[36] = {
    23, 10, 22, 9, 21, 8,
    20, 7, 19, 6, 18, 5,
    17, 4, 16, 3, 15, 2,
    14, 1, 13, 0, 12, 10,
    11, 9, 10, 8, 9, 7,
    8, 6, 7, 5, 6, 4
};

static const int dmr_rY_host[36] = {
    0, 2, 0, 2, 0, 2,
    0, 2, 0, 3, 0, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3
};

static const int dmr_rZ_host[36] = {
    5, 3, 4, 2, 3, 1,
    2, 0, 1, 13, 0, 12,
    22, 11, 21, 10, 20, 9,
    19, 8, 18, 7, 17, 6,
    16, 5, 15, 4, 14, 3,
    13, 2, 12, 1, 11, 0
};

static const int sf_dibit_idx_host[3][36] = {
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

/* Host-side copies for precompute_cipher_packs (cannot read __constant__ device vars on host) */

/*
 * =========================================================================
 * CORRECT DECRYPTION PIPELINE (proven by Python roundtrip + real data tests)
 *
 * Per-burst scoring using the exact DSD-FME / mbelib algorithm:
 *   1. De-interleave raw payload into ambe_fr[4][24] per sub-frame
 *   2. mbe_demodulate: XOR row1 with PR sequence seeded from encrypted C0
 *   3. Extract 49 AMBE-d bits (C0+C1+C2+C3)
 *   4. Pack 49 bits -> 7 bytes (MSB-first)
 *   5. RC4 decrypt 7 bytes with key9=key5||MI, drop=256+burst_pos*21+sf*7
 *   6. Unpack 7 bytes -> 49 plaintext bits
 *   7. Score: inter-frame Hamming on first 24 bits (C0+C1)
 * =========================================================================
 */
__device__ float score_burst_correct_dev(
    const unsigned char *cipher_packs,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos)
{
    // Build KMI9 key = key5 || MI[4]
    unsigned char kmi9[9];
    compose_kmi9_dev(key5, mi, kmi9);
    // RC4 KSA with 9-byte key, then discard to drop_base
    RC4_CTX_DEV rc4;
    rc4_init_dev_len(&rc4, kmi9, 9);
    rc4_discard_dev(&rc4, 256 + burst_pos * 21);
    unsigned char plain7[3][7];
    // RC4 decrypt 7 bytes per sub-frame
    for (int sf = 0; sf < 3; ++sf) {
        rc4_crypt_dev(&rc4, cipher_packs + sf * 7, plain7[sf], 7);
    }
    // Score: inter-frame Hamming on first 24 bits (C0+C1)
    int h01 = 0, h12 = 0;
    for (int i = 0; i < 3; ++i) {
        for (int b = 0; b < 3; ++b) {
            if (i < 2) h01 += __popc((plain7[i][b] ^ plain7[i+1][b]) & 0xFF);
            if (i == 1) h12 += __popc((plain7[i][b] ^ plain7[i+1][b]) & 0xFF);
        }
    }
    return (float)(48 - h01 - h12);
}
// Host-side: Precompute cipher packs for all payloads
void precompute_cipher_packs(const PayloadSet *payloads, unsigned char *out_cipher_packs, int payload_limit) {
    // For each payload, for each sub-frame (0,1,2), output 7 bytes
    for (int p = 0; p < payload_limit; ++p) {
        const unsigned char *payload33 = payloads->items[p].data;
        for (int sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24] = {0};
            for (int i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_host[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[dmr_rW_host[i]][dmr_rX_host[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[dmr_rY_host[i]][dmr_rZ_host[i]] = (unsigned char)(dibit & 1u);
            }
            // mbe_demodulate
            int foo = 0;
            for (int i = 23; i >= 12; --i) {
                foo = (foo << 1) | (int)ambe_fr[0][i];
            }
            int pr_val = 16 * foo;
            for (int j = 22; j >= 0; --j) {
                pr_val = (173 * pr_val + 13849) & 0xFFFF;
                ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
            }
            // Extract 49 bits
            unsigned char bits49[49];
            int bi = 0;
            for (int j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (int j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (int j = 10; j >= 0; --j) bits49[bi++] = ambe_fr[2][j];
            for (int j = 13; j >= 0; --j) bits49[bi++] = ambe_fr[3][j];
            // Pack 49 bits -> 7 bytes (MSB-first)
            unsigned char cipher7[7] = {0};
            for (int i = 0; i < 49; ++i) {
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            }
            memcpy(out_cipher_packs + p * 21 + sf * 7, cipher7, 7);
        }
    }
}

__device__ __forceinline__ int extract_voice_dibits_dev(
    const unsigned char *bytes,
    int bytes_to_test,
    int dibit_variant,
    unsigned char out_dibits[108])
{
    int total_dibits = bytes_to_test * 4;
    if (total_dibits >= 132) {
        int di = 0;
        for (int i = 0; i < 54; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[di++] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        for (int i = 78; i < 132; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[di++] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        return 108;
    }

    if (total_dibits >= 108) {
        for (int i = 0; i < 108; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[i] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        return 108;
    }

    return 0;
}

__device__ __forceinline__ float score_dmr_ambe_dev(
    const unsigned char *bytes,
    int bytes_to_test,
    unsigned int *out_sig_first,
    unsigned int *out_sig_last)
{
    unsigned char voice_dibits[108];
    unsigned char ambe[3][4][24];
    float best_score = -1.0e30f;
    unsigned int best_s0 = 0u, best_s2 = 0u;

    for (int variant = 0; variant < 2; ++variant) {
        int dcount = extract_voice_dibits_dev(bytes, bytes_to_test, variant, voice_dibits);
        float score = 0.0f;

        if (dcount < 108) continue;

        for (int f = 0; f < 3; ++f) {
            for (int r = 0; r < 4; ++r) {
                for (int c = 0; c < 24; ++c) {
                    ambe[f][r][c] = 0;
                }
            }

            for (int i = 0; i < 36; ++i) {
                unsigned char dibit = voice_dibits[f * 36 + i];
                ambe[f][dmr_rW_dev[i]][dmr_rX_dev[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe[f][dmr_rY_dev[i]][dmr_rZ_dev[i]] = (unsigned char)(dibit & 1u);
            }
        }

        {
            int h01 = 0, h12 = 0, h02 = 0;
            int hp = 0;

            for (int c = 0; c < 24; ++c) {
                h01 += (ambe[0][0][c] ^ ambe[1][0][c]) & 1u;
                h12 += (ambe[1][0][c] ^ ambe[2][0][c]) & 1u;
                h02 += (ambe[0][0][c] ^ ambe[2][0][c]) & 1u;
            }
            for (int c = 0; c < 12; ++c) {
                h01 += (ambe[0][1][c] ^ ambe[1][1][c]) & 1u;
                h12 += (ambe[1][1][c] ^ ambe[2][1][c]) & 1u;
                h02 += (ambe[0][1][c] ^ ambe[2][1][c]) & 1u;
            }
            for (int c = 0; c < 8; ++c) {
                hp += (ambe[0][2][c] ^ ambe[2][2][c]) & 1u;
            }

            score += (18.0f - (float)h01) * 10.0f;
            score += (18.0f - (float)h12) * 10.0f;
            score += (18.0f - (float)h02) * 6.0f;
            score += (4.0f - (float)hp) * 5.0f;
        }

        {
            unsigned int s0 = 0u;
            unsigned int s2 = 0u;
            for (int c = 0; c < 24; ++c) {
                s0 = (s0 << 1) | (unsigned int)(ambe[0][0][c] & 1u);
                s2 = (s2 << 1) | (unsigned int)(ambe[2][0][c] & 1u);
            }
            for (int c = 0; c < 8; ++c) {
                s0 = (s0 << 1) | (unsigned int)(ambe[0][1][c] & 1u);
                s2 = (s2 << 1) | (unsigned int)(ambe[2][1][c] & 1u);
            }
            if (score > best_score) {
                best_score = score;
                best_s0 = s0;
                best_s2 = s2;
            }
        }
    }

    if (best_score < -1.0e20f) return 0.0f;
    if (out_sig_first != NULL) *out_sig_first = best_s0;
    if (out_sig_last != NULL) *out_sig_last = best_s2;
    return best_score;
}

__global__ __launch_bounds__(256, 2)
void bruteforce_kernel_strict(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    uint32_t global_mi,
    unsigned long long* __restrict__ dev_keys_tested,
    float* __restrict__ dev_best_score,
    unsigned long long* __restrict__ dev_best_key,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;
    int local_keys = 0;

    for (uint64_t i = tid; i < total_keys; i += stride) {
        if ((i & 0x3FFu) == 0 && dev_stop_requested[0]) return;

        uint64_t current_key = start_key + i;
        unsigned char key[5];
        key_to_5bytes_dev(current_key, key);

        float total_score = 0.0f;
        int processed_bursts = 0;

        /* Unified loop: single pass through all superframes, no redundant prefilter */
        for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
            uint32_t line_mi = global_mi;
            if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u)) {
                line_mi = d_const_mi[sf_base];
            }

            unsigned char kmi9[9];
            compose_kmi9_dev(key, line_mi, kmi9);
            RC4_CTX_DEV rc4;
            rc4_ksa9_dev(&rc4, kmi9);
            rc4_discard_dev(&rc4, 256);

            for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                int p = sf_base + burst_pos;
                if (p >= payload_count) break;

                const unsigned char *cp = d_const_cipher_packs + (p * 21);
                unsigned char p0[3], p1[3], p2[3];
                rc4_crypt_first3_skip4_dev(&rc4, cp + 0,  p0);
                rc4_crypt_first3_skip4_dev(&rc4, cp + 7,  p1);
                rc4_crypt_first3_skip4_dev(&rc4, cp + 14, p2);

                int h01 = __popc((unsigned int)(p0[0] ^ p1[0]))
                        + __popc((unsigned int)(p0[1] ^ p1[1]))
                        + __popc((unsigned int)(p0[2] ^ p1[2]));
                int h12 = __popc((unsigned int)(p1[0] ^ p2[0]))
                        + __popc((unsigned int)(p1[1] ^ p2[1]))
                        + __popc((unsigned int)(p1[2] ^ p2[2]));

                total_score += (float)(48 - h01 - h12);
                processed_bursts++;

                /* Per-burst absolute pruning: reject wrong keys as early as possible */
                if (enable_prune && processed_bursts >= 3 &&
                    total_score < d_abs_floor[processed_bursts]) {
                    goto next_key;
                }
            }

            /* Relative pruning at superframe boundary: can't beat current global best */
            if (enable_prune && processed_bursts >= 6) {
                float best_now = __ldg((const float*)dev_best_score);
                float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
                if (max_possible <= best_now) {
                    break;
                }
            }
        }

        if (processed_bursts == payload_count) {
            update_best_score_dev(total_score, current_key, dev_best_score, dev_best_key);
        }

        next_key:
        local_keys++;
        if (local_keys >= 16384) {
            atomicAdd((unsigned long long int*)dev_keys_tested, 16384ULL);
            local_keys = 0;
        }
    }

    if (local_keys > 0) {
        atomicAdd((unsigned long long int*)dev_keys_tested, (unsigned long long)local_keys);
    }
}

__global__ __launch_bounds__(256, 4)
void bruteforce_kernel(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    int payload_max_len,
    int sample_bytes,
    int mode_policy,
    uint32_t global_mi,
    uint8_t has_global_mi,
    uint8_t global_algid,
    uint8_t has_global_algid,
    unsigned long long* __restrict__ dev_keys_tested,
    float* __restrict__ dev_best_score,
    unsigned long long* __restrict__ dev_best_key,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;

    int local_keys = 0;

    for (uint64_t i = tid; i < total_keys; i += stride) {
        // Check stop every 1024 iterations to reduce global memory traffic
        if ((i & 0x3FFu) == 0 && dev_stop_requested[0]) return;
        uint64_t current_key = start_key + i;
        unsigned char key[5];
        key_to_5bytes_dev(current_key, key);
        float score = -3.402823e38f;
        // CORRECT PIPELINE PATH (mode_policy >= 2: payloads have MI+RC4)
        if (mode_policy >= 2) {
            float total_score = 0.0f;
            int processed_bursts = 0;
            int pruned = 0;
            // Process in groups of 6 bursts (superframe)
            for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
                // Validate all bursts in the superframe share the same MI
                uint32_t line_mi = global_mi;
                if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u)) {
                    line_mi = d_const_mi[sf_base];
                }
                // Build KMI9 key = key5 || MI[4]
                unsigned char kmi9[9];
                compose_kmi9_dev(key, line_mi, kmi9);
                RC4_CTX_DEV rc4;
                rc4_init_dev_len(&rc4, kmi9, 9);
                rc4_discard_dev(&rc4, 256);
                // Process the 6 bursts of the superframe
                for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                    int p = sf_base + burst_pos;
                    if (p >= payload_count) break;
                    const unsigned char *cipher_packs = d_const_cipher_packs + (p * 21);
                    // RC4 stream is already at the correct position
                    // Decrypt only bytes needed for scoring (3 per sub-frame),
                    // still advancing 7 bytes of keystream per sub-frame.
                    unsigned char p0[3], p1[3], p2[3];
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 0,  p0);
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 7,  p1);
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 14, p2);
                    // Score: inter-frame Hamming on first 24 bits (C0+C1)
                    int h01 = __popc((unsigned int)(p0[0] ^ p1[0]))
                            + __popc((unsigned int)(p0[1] ^ p1[1]))
                            + __popc((unsigned int)(p0[2] ^ p1[2]));
                    int h12 = __popc((unsigned int)(p1[0] ^ p2[0]))
                            + __popc((unsigned int)(p1[1] ^ p2[1]))
                            + __popc((unsigned int)(p1[2] ^ p2[2]));
                    total_score += (float)(48 - h01 - h12);
                    processed_bursts++;

                    // Early-prune: even with maximum possible remaining (48/burst),
                    // cannot exceed current global best.
                    if (enable_prune && ((processed_bursts & 0x1) == 0)) {
                        float best_now = __ldg((const float*)dev_best_score);
                        float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
                        if (max_possible <= best_now) {
                            pruned = 1;
                            break;
                        }
                    }
                }
                if (pruned) break;
            }
            score = pruned ? -3.402823e38f : total_score;
        }
        else {

        /* ================================================================
         * LEGACY PATH (mode_policy 0/1: no MI, statistical scoring)
         * ================================================================ */

        /* Pre-compute RC4 KSA once per key */
        RC4_CTX_DEV rc4_base;
        rc4_init_dev(&rc4_base, key);

        float best_mode_1 = -3.402823e38f;
        float best_mode_2 = -3.402823e38f;

        int mode_iter_count = (mode_policy == 1) ? 4 : 12;

        for (int mode_iter = 0; mode_iter < mode_iter_count; ++mode_iter) {
            int mode;
            int base_mode = 0;
            int mi_offset = 0;
            int use_reset;
            int use_drop256;
            int use_kmi;
            int use_mi_lfsr;
            int use_kmi_force;
            float mode_score = 0.0f;
            RC4_CTX_DEV rc4_cont = rc4_base;
            uint32_t running_mi = global_mi;
            unsigned int prev_last_sig = 0u;
            int has_prev_sig = 0;

            if (mode_policy == 1) {
                mode = mode_iter;
            } else if (mode_policy == 2) {
                const int kmi_modes[6] = { 5, 7, 8, 9, 10, 11 };
                mode = kmi_modes[mode_iter];
            } else if (mode_policy == 3) {
                const int strict_modes[2] = { 5, 7 };
                mode = strict_modes[mode_iter];
            } else {
                mode = mode_iter;
            }

            base_mode = mode;

            if (mode >= 8) {
                if (mode == 8) { base_mode = 5; mi_offset = +1; }
                else if (mode == 9) { base_mode = 5; mi_offset = -1; }
                else if (mode == 10) { base_mode = 7; mi_offset = +1; }
                else { base_mode = 7; mi_offset = -1; }
            }

            use_reset = (base_mode == 0 || base_mode == 2);
            use_drop256 = (base_mode >= 2);
            use_kmi = (base_mode >= 4);
            use_mi_lfsr = (base_mode == 5 || base_mode == 7);
            use_kmi_force = (base_mode == 6 || base_mode == 7);

            if (use_kmi) {
                use_reset = 1;
                use_drop256 = 1;
            }

            if (!use_reset && use_drop256) {
                rc4_discard_dev(&rc4_cont, 256);
            }

            for (int p = 0; p < payload_count; ++p) {
                unsigned char out[64];
                RC4_CTX_DEV rc4;
                int bytes_to_decrypt = sample_bytes;
                int bytes_to_test;
                const unsigned char* current_line_data;
                uint32_t line_mi = 0;
                uint8_t line_alg = 0;
                uint8_t line_has_mi = 0;
                uint8_t line_has_alg = 0;
                uint8_t line_rc4 = 0;
                float local_score = 0.0f;
                unsigned int sig_first = 0u;
                unsigned int sig_last = 0u;

                if (bytes_to_decrypt > payload_max_len) bytes_to_decrypt = payload_max_len;
                if (bytes_to_decrypt <= 0) bytes_to_decrypt = payload_max_len;
                if (payload_max_len >= 33 && bytes_to_decrypt < 33) bytes_to_decrypt = 33;
                if (bytes_to_decrypt > 64) bytes_to_decrypt = 64;

                bytes_to_test = bytes_to_decrypt;
                if (bytes_to_test >= 33) bytes_to_test = 33;

                current_line_data = d_const_payloads + (p * payload_max_len);

                if (p < MAX_CONST_LINES) {
                    uint8_t flags = d_const_meta_flags[p];
                    line_has_mi = (uint8_t)(flags & 0x1u);
                    line_has_alg = (uint8_t)(flags & 0x2u);
                    if (line_has_mi) line_mi = d_const_mi[p];
                    if (line_has_alg) line_alg = d_const_algid[p];
                }
                if (!line_has_mi && has_global_mi) line_mi = global_mi;
                if (!line_has_alg && has_global_algid) line_alg = global_algid;
                line_rc4 = is_rc4_alg_dev(line_alg);

                if (use_mi_lfsr) {
                    if (line_has_mi) running_mi = line_mi;
                    else if (has_global_mi) line_mi = running_mi;
                }

                if (mi_offset != 0 && line_mi != 0u) {
                    if (mi_offset > 0) {
                        for (int s = 0; s < mi_offset; ++s) line_mi = dmr_mi_lfsr_next_dev(line_mi);
                    } else {
                        for (int s = 0; s < -mi_offset; ++s) line_mi = dmr_mi_lfsr_prev_dev(line_mi);
                    }
                }

                if (use_reset) {
                    if (use_kmi && line_mi != 0u && (line_rc4 || use_kmi_force)) {
                        unsigned char kmi9[9];
                        compose_kmi9_dev(key, line_mi, kmi9);
                        rc4_init_dev_len(&rc4, kmi9, 9);
                    } else {
                        rc4 = rc4_base;
                    }
                    if (use_drop256) rc4_discard_dev(&rc4, 256);
                    rc4_crypt_dev(&rc4, current_line_data, out, bytes_to_decrypt);
                } else {
                    rc4_crypt_dev(&rc4_cont, current_line_data, out, bytes_to_decrypt);
                }

                if (use_mi_lfsr && line_rc4 && line_mi != 0u) {
                    running_mi = dmr_mi_lfsr_next_dev(line_mi);
                }

                local_score += score_dmr_ambe_dev(out, bytes_to_decrypt, &sig_first, &sig_last);
                if (has_prev_sig) {
                    int h = __popc(prev_last_sig ^ sig_first);
                    float continuity_w = (mode_policy == 3) ? 18.0f : 12.0f;
                    local_score += (16.0f - (float)h) * continuity_w;
                }
                prev_last_sig = sig_last;
                has_prev_sig = 1;

            if (mode_policy != 3) {
                /* A) Multi-lag autocorrelation (interleaving-safe) */
                {
                    int max_lag = bytes_to_test / 2;
                    if (max_lag > 13) max_lag = 13;
                    for (int lag = 1; lag <= max_lag; ++lag) {
                        int n_bytes = bytes_to_test - lag;
                        int hamming = 0;
                        int expected = n_bytes * 4;
                        for (int bx = 0; bx < n_bytes; ++bx) {
                            hamming += popcount_byte_dev(out[bx] ^ out[bx + lag]);
                        }
                        {
                            int deviation = hamming - expected;
                            if (deviation < 0) deviation = -deviation;
                            local_score += (float)deviation * 2.5f;
                        }
                    }
                }

                /* B) Bit transition rate */
                {
                    int transitions = 0;
                    int total_bit_pairs = (bytes_to_test * 8) - 1;
                    int expected_transitions;

                    for (int bx = 0; bx < bytes_to_test; ++bx) {
                        unsigned char b = out[bx];
                        for (int k = 0; k < 7; ++k) {
                            int bit_k = (b >> (7 - k)) & 1;
                            int bit_k1 = (b >> (6 - k)) & 1;
                            if (bit_k != bit_k1) transitions++;
                        }
                        if (bx + 1 < bytes_to_test) {
                            int last_bit = b & 1;
                            int first_bit = (out[bx + 1] >> 7) & 1;
                            if (last_bit != first_bit) transitions++;
                        }
                    }
                    expected_transitions = total_bit_pairs / 2;
                    {
                        int deviation = transitions - expected_transitions;
                        if (deviation < 0) deviation = -deviation;
                        local_score += (float)deviation * 3.0f;
                    }
                }

                /* C) Bit-ratio deviation (cumulative across payloads) */
                {
                    int total_bits = 0;
                    float bit_ratio, dev;
                    for (int bx = 0; bx < bytes_to_test; ++bx) {
                        total_bits += popcount_byte_dev(out[bx]);
                    }
                    bit_ratio = (float)total_bits / (float)(bytes_to_test * 8);
                    dev = bit_ratio - 0.5f;
                    local_score += dev * dev * (float)(bytes_to_test * 8) * 60.0f;
                }

                /* D) Byte pair consistency */
                if (bytes_to_test >= 10) {
                    const int pair_offsets[3] = { 1, 3, 9 };
                    for (int pidx = 0; pidx < 3; ++pidx) {
                        int off = pair_offsets[pidx];
                        if (off >= bytes_to_test) continue;
                        {
                            int n_pairs = bytes_to_test - off;
                            int xor_sum = 0;
                            float mean_xor, var_xor;
                            for (int bx = 0; bx < n_pairs; ++bx) {
                                xor_sum += (int)(out[bx] ^ out[bx + off]);
                            }
                            mean_xor = (float)xor_sum / (float)n_pairs;
                            var_xor = 0.0f;
                            for (int bx = 0; bx < n_pairs; ++bx) {
                                float d = (float)(out[bx] ^ out[bx + off]) - mean_xor;
                                var_xor += d * d;
                            }
                            var_xor /= (float)n_pairs;
                            {
                                float var_dev = var_xor - 5440.0f;
                                if (var_dev < 0.0f) var_dev = -var_dev;
                                local_score += var_dev * 0.008f;
                            }
                        }
                    }
                }

                /* E) Penalty for long runs (obvious garbage) */
                {
                    int max_run = 1, run = 1;
                    for (int bx = 1; bx < bytes_to_test; ++bx) {
                        if (out[bx] == out[bx - 1]) {
                            run++;
                            if (run > max_run) max_run = run;
                        } else {
                            run = 1;
                        }
                    }
                    if (max_run > 5) {
                        local_score -= (float)(max_run - 5) * 50.0f;
                    }
                }
            }

                mode_score += local_score;
            }

            if (mode_score > best_mode_1) {
                best_mode_2 = best_mode_1;
                best_mode_1 = mode_score;
            } else if (mode_score > best_mode_2) {
                best_mode_2 = mode_score;
            }
        }

        score = (best_mode_2 > -3.0e38f)
            ? (best_mode_1 * 0.70f + best_mode_2 * 0.30f)
            : best_mode_1;

        } /* end else (legacy path) */

        /* Atomic update of best score (float CAS, no FP64) */
        update_best_score_dev(score, current_key, dev_best_score, dev_best_key);

        local_keys++;
        if (local_keys >= 16384) {
            atomicAdd((unsigned long long int*)dev_keys_tested, 16384ULL);
            local_keys = 0;
        }
    }
    
    // Add remaining local keys
    if (local_keys > 0) {
        atomicAdd((unsigned long long int*)dev_keys_tested, (unsigned long long)local_keys);
    }
}

/*
 * =========================================================================
 * HOST IMPLEMENTATION (CONTROLS THE GPU FROM WINDOWS/C)
 * =========================================================================
 */

static int infer_line_mi_host(const PayloadSet *payloads, int line_idx, uint32_t *out_mi);
static int is_rc4_alg_host(uint8_t alg);

typedef struct {
    int threads_per_block;
    int blocks_per_sm;
    int chunk_mult;
} CudaLaunchProfile;

static void build_tune_profile_path(const cudaDeviceProp *prop, int strict_mode, char *out_path, size_t out_len)
{
    snprintf(out_path, out_len,
             "bin\\cuda_tune_sm%d%d_mode%d.cfg",
             prop->major,
             prop->minor,
             strict_mode ? 2 : 0);
}

static int load_cuda_launch_profile(const cudaDeviceProp *prop, int strict_mode, CudaLaunchProfile *out)
{
    char path[260];
    FILE *fp;
    int tpb = 0, bpsm = 0, chunk = 0;

    build_tune_profile_path(prop, strict_mode, path, sizeof(path));
    fp = fopen(path, "rt");
    if (fp == NULL) return 0;

    if (fscanf(fp, "TPB=%d\nBPSM=%d\nCHUNK=%d\n", &tpb, &bpsm, &chunk) != 3) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    if (tpb < 64 || tpb > 1024 || (tpb % 32) != 0) return 0;
    if (bpsm < 1 || bpsm > 64) return 0;
    if (chunk < 32 || chunk > 2048) return 0;

    out->threads_per_block = tpb;
    out->blocks_per_sm = bpsm;
    out->chunk_mult = chunk;
    return 1;
}

static void save_cuda_launch_profile(const cudaDeviceProp *prop, int strict_mode, const CudaLaunchProfile *profile)
{
    char path[260];
    FILE *fp;

    build_tune_profile_path(prop, strict_mode, path, sizeof(path));
    /* Ensure bin\ directory exists before writing (not tracked by git). */
    CreateDirectoryA("bin", NULL);
    fp = fopen(path, "wt");
    if (fp == NULL) return;

    fprintf(fp, "TPB=%d\nBPSM=%d\nCHUNK=%d\n",
            profile->threads_per_block,
            profile->blocks_per_sm,
            profile->chunk_mult);
    fclose(fp);
}

/* Consistent CUDA error checking macro used throughout cuda_launcher_thread.
 * On failure: records message in engine->cuda_error and jumps to cleanup. */
#define CUDA_CHECK(call, msg) do { \
    cudaError_t _cuda_err_ = (call); \
    if (_cuda_err_ != cudaSuccess) { \
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), \
                 "%s: %s", (msg), cudaGetErrorString(_cuda_err_)); \
        goto cleanup; \
    } \
} while (0)

static unsigned __stdcall cuda_launcher_thread(void *arg)
{
    BruteforceEngine *engine = (BruteforceEngine *)arg;
    unsigned char *host_payload_flat = NULL;
    unsigned int host_mi[MAX_CONST_LINES];
    unsigned char host_algid[MAX_CONST_LINES];
    unsigned char host_meta_flags[MAX_CONST_LINES];
    unsigned long long *d_keys_tested = NULL;
    float *d_best_score = NULL;
    unsigned long long *d_best_key = NULL;
    int *d_stop_requested = NULL;
    cudaStream_t compute_stream = NULL;
    cudaStream_t compute_stream2 = NULL;  /* double-buffer stream */
    cudaStream_t query_stream = NULL;
    /* Pinned host memory for truly async D2H polling */
    struct { unsigned long long keys_tested; float best_score; unsigned long long best_key; } *h_poll = NULL;
    cudaError_t cu_err;
    uint64_t total_keys, chunk_size, offset;
    int threadsPerBlock, blocksPerGrid;
    int max_payload_len = 0;
    int bytes_per_line = 27;
    size_t payload_bytes = 0;
    cudaDeviceProp prop;

    int payload_limit = engine->cfg.sample_lines;
    uint8_t has_global_mi = engine->payloads->has_global_mi ? 1u : 0u;
    uint8_t has_global_algid = engine->payloads->has_global_algid ? 1u : 0u;
    uint8_t global_algid = engine->payloads->global_algid;
    uint32_t global_mi = engine->payloads->global_mi;
    int mode_policy = 0;

    InterlockedExchange(&engine->cuda_stage, 0);
    InterlockedExchange64(&engine->cuda_last_update_ms, (LONG64)GetTickCount64());

    if (payload_limit > MAX_CONST_LINES) payload_limit = MAX_CONST_LINES;
    if ((size_t)payload_limit > engine->payloads->count) payload_limit = (int)engine->payloads->count;
    if (payload_limit <= 0) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "No payloads for CUDA");
        goto cleanup;
    }

    memset(host_mi, 0, sizeof(host_mi));
    memset(host_algid, 0, sizeof(host_algid));
    memset(host_meta_flags, 0, sizeof(host_meta_flags));
    // Precompute cipher packs
    unsigned char host_cipher_packs[MAX_CONST_LINES * 21];
    memset(host_cipher_packs, 0, sizeof(host_cipher_packs));
    precompute_cipher_packs(engine->payloads, host_cipher_packs, payload_limit);
    /* Compute actual max payload length instead of hardcoding 64 */
    max_payload_len = 0;
    for (int i = 0; i < payload_limit && (size_t)i < engine->payloads->count; i++) {
        int plen = (int)engine->payloads->items[i].len;
        if (plen > max_payload_len) max_payload_len = plen;
    }
    if (max_payload_len <= 0) max_payload_len = 27;  /* default DMR voice burst */
    if (max_payload_len > 64) max_payload_len = 64;  /* cap for constant memory */
    bytes_per_line = max_payload_len;
    payload_bytes = (size_t)payload_limit * (size_t)bytes_per_line;
    if (payload_bytes > 8192) payload_bytes = 8192;
    host_payload_flat = (unsigned char *)malloc(payload_bytes);
    if (host_payload_flat == NULL) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "malloc payload_flat failed");
        goto cleanup;
    }
    memset(host_payload_flat, 0, payload_bytes);
    for (int i = 0; i < payload_limit && ((size_t)i * bytes_per_line) < 8192; i++) {
        size_t cp_len = engine->payloads->items[i].len;
        if (cp_len > (size_t)bytes_per_line) cp_len = (size_t)bytes_per_line;
        memcpy(host_payload_flat + ((size_t)i * bytes_per_line), engine->payloads->items[i].data, cp_len);
        if (engine->payloads->items[i].has_mi) {
            host_meta_flags[i] |= 0x1u;
            host_mi[i] = engine->payloads->items[i].mi;
        }
        if (engine->payloads->items[i].has_algid) {
            host_meta_flags[i] |= 0x2u;
            host_algid[i] = engine->payloads->items[i].algid;
        }
    }

    {
        int mi_rc4_lines = 0;
        for (int i = 0; i < payload_limit; ++i) {
            int has_mi = (host_meta_flags[i] & 0x1u) != 0;
            uint8_t alg = (host_meta_flags[i] & 0x2u) ? host_algid[i] : global_algid;
            int rc4 = is_rc4_alg_host(alg);
            if (has_mi && rc4) mi_rc4_lines++;
        }
        if (payload_limit > 0 && mi_rc4_lines * 10 >= payload_limit * 9) {
            mode_policy = 3;
        } else if (payload_limit > 0 && mi_rc4_lines * 3 >= payload_limit) {
            mode_policy = 2;
        } else if (!has_global_mi && mi_rc4_lines == 0) {
            mode_policy = 1;
        }
    }

    {
        int has_any_mi = 0;
        for (int i = 0; i < payload_limit; ++i) {
            if (host_meta_flags[i] & 0x1u) {
                has_any_mi = 1;
                break;
            }
        }
        if (has_any_mi) {
            for (int i = 0; i < payload_limit; ++i) {
                if ((host_meta_flags[i] & 0x1u) == 0u) {
                    uint32_t mi;
                    if (infer_line_mi_host(engine->payloads, i, &mi)) {
                        host_mi[i] = mi;
                        host_meta_flags[i] |= 0x1u;
                    }
                }
            }
        }
    }

    cu_err = cudaMemcpyToSymbol(d_const_payloads, host_payload_flat, payload_bytes);
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    cu_err = cudaMemcpyToSymbol(d_const_cipher_packs, host_cipher_packs, sizeof(host_cipher_packs));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol(cipher_packs): %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
// DOCUMENTATION: burst_pos alignment issue
// Note: The kernel assumes the first payload in the .bin corresponds to burst_pos=0 of a superframe.
// If the file is not aligned, the drop value will be incorrect and the score will not be valid.
// For maximum robustness, it is recommended to validate alignment on the host and/or add a burst_pos_start field to PayloadItem.

    cu_err = cudaMemcpyToSymbol(d_const_mi, host_mi, sizeof(host_mi));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol(mi): %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    cu_err = cudaMemcpyToSymbol(d_const_algid, host_algid, sizeof(host_algid));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol(alg): %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    cu_err = cudaMemcpyToSymbol(d_const_meta_flags, host_meta_flags, sizeof(host_meta_flags));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol(flags): %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }

    /* Precompute absolute screening thresholds (Change 1: hashcat-style early reject) */
    {
        float host_abs_floor[MAX_CONST_LINES + 1];
        host_abs_floor[0] = -FLT_MAX;
        for (int k = 1; k <= payload_limit; ++k) {
            /* Wrong key: mean=24*k, sigma=3.46*sqrt(k)
             * Correct key: mean~38.7*k
             * Floor at midpoint(31*k) - 2*sigma: rejects 99.8% of wrong keys after 6 bursts */
            float sigma_k = 3.46f * sqrtf((float)k);
            host_abs_floor[k] = 31.0f * (float)k - 2.0f * sigma_k;
        }
        for (int k = payload_limit + 1; k <= MAX_CONST_LINES; ++k) {
            host_abs_floor[k] = -FLT_MAX;
        }
        cu_err = cudaMemcpyToSymbol(d_abs_floor, host_abs_floor, sizeof(host_abs_floor));
        if (cu_err != cudaSuccess) {
            snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMemcpyToSymbol(abs_floor): %s", cudaGetErrorString(cu_err));
            goto cleanup;
        }
    }

    cu_err = cudaMalloc(&d_keys_tested, sizeof(unsigned long long));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMalloc keys_tested: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    CUDA_CHECK(cudaMemset(d_keys_tested, 0, sizeof(unsigned long long)), "cudaMemset keys_tested");

    cu_err = cudaMalloc(&d_best_score, sizeof(float));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMalloc best_score: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    { float init_score = -FLT_MAX; CUDA_CHECK(cudaMemcpy(d_best_score, &init_score, sizeof(float), cudaMemcpyHostToDevice), "cudaMemcpy best_score init"); }

    cu_err = cudaMalloc(&d_best_key, sizeof(unsigned long long));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMalloc best_key: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    CUDA_CHECK(cudaMemset(d_best_key, 0, sizeof(unsigned long long)), "cudaMemset best_key");

    cu_err = cudaMalloc(&d_stop_requested, sizeof(int));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMalloc stop_requested: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    CUDA_CHECK(cudaMemset(d_stop_requested, 0, sizeof(int)), "cudaMemset stop_requested");

    total_keys = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;

    cu_err = cudaGetDeviceProperties(&prop, 0);
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaGetDeviceProperties: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }

    InterlockedExchange(&engine->cuda_sm_count, prop.multiProcessorCount);
    InterlockedExchange(&engine->cuda_compute_major, prop.major);
    InterlockedExchange(&engine->cuda_compute_minor, prop.minor);

    cu_err = cudaStreamCreateWithFlags(&compute_stream, cudaStreamNonBlocking);
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaStreamCreate compute: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    cu_err = cudaStreamCreateWithFlags(&query_stream, cudaStreamNonBlocking);
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaStreamCreate query: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    /* Second compute stream for double-buffered dispatch (Change 6) */
    CUDA_CHECK(cudaStreamCreateWithFlags(&compute_stream2, cudaStreamNonBlocking), "cudaStreamCreate compute2");
    /* Pinned host buffer for truly async D2H transfers (Change 5) */
    if (cudaHostAlloc(&h_poll, sizeof(*h_poll), cudaHostAllocDefault) != cudaSuccess) {
        h_poll = NULL;  /* fallback to stack vars in polling loop */
    }

    {
        const int strict_mode = (mode_policy >= 2) ? 1 : 0;
        CudaLaunchProfile profile;
        int profile_loaded = 0;

        profile.threads_per_block = 256;
        profile.blocks_per_sm = strict_mode ? 24 : 12;
        profile.chunk_mult = strict_mode ? 384 : 128;

        profile_loaded = load_cuda_launch_profile(&prop, strict_mode, &profile);
        InterlockedExchange(&engine->cuda_profile_cached, profile_loaded ? 1 : 0);

        if (!profile_loaded) {
            int tpb_candidates[2] = { 128, 256 };
            int bpsm_candidates_strict[2] = { 20, 24 };
            int bpsm_candidates_legacy[2] = { 10, 12 };
            int chunk_candidates_strict[2] = { 192, 256 };
            int chunk_candidates_legacy[2] = { 96, 128 };
            int bpsm_count = 2;
            int chunk_count = 2;
            uint64_t tune_keys = total_keys;
            float best_kps = -1.0f;
            cudaEvent_t ev_start = NULL;
            cudaEvent_t ev_stop = NULL;
            ULONGLONG tune_start_tick = GetTickCount64();
            const ULONGLONG tune_budget_ms = 1800ULL;
            int skip_benchmark = (total_keys > (1ULL << 28));

            InterlockedExchange(&engine->cuda_stage, 1);

            if (tune_keys > (1ULL << 18)) tune_keys = (1ULL << 18);
            if (tune_keys > total_keys) tune_keys = total_keys;
            if (tune_keys == 0) tune_keys = total_keys;

            if (!skip_benchmark) {
                if (cudaEventCreate(&ev_start) != cudaSuccess ||
                    cudaEventCreate(&ev_stop)  != cudaSuccess) {
                    skip_benchmark = 1;
                }
            }

            for (int ti = 0; ti < 2 && !skip_benchmark; ++ti) {
                int tpb = tpb_candidates[ti];
                if (tpb > prop.maxThreadsPerBlock || (tpb & 31) != 0) continue;

                for (int bi = 0; bi < bpsm_count; ++bi) {
                    if (GetTickCount64() - tune_start_tick >= tune_budget_ms) {
                        skip_benchmark = 1;
                        break;
                    }
                    int bpsm = strict_mode ? bpsm_candidates_strict[bi] : bpsm_candidates_legacy[bi];
                    int blocks = prop.multiProcessorCount * bpsm;
                    if (blocks < 1) blocks = 1;
                    if (blocks > 65535) blocks = 65535;

                    for (int ci = 0; ci < chunk_count; ++ci) {
                        int chunk_mult = strict_mode ? chunk_candidates_strict[ci] : chunk_candidates_legacy[ci];
                        uint64_t cand_chunk = (uint64_t)blocks * (uint64_t)tpb * (uint64_t)chunk_mult;
                        uint64_t tuned = 0;
                        float ms = 0.0f;
                        float kps;
                        float init_score = -FLT_MAX;

                        if (cand_chunk == 0) continue;

                        cudaMemsetAsync(d_keys_tested, 0, sizeof(unsigned long long), compute_stream);
                        cudaMemcpyAsync(d_best_score, &init_score, sizeof(float), cudaMemcpyHostToDevice, compute_stream);
                        cudaMemsetAsync(d_best_key, 0, sizeof(unsigned long long), compute_stream);
                        cudaMemsetAsync(d_stop_requested, 0, sizeof(int), compute_stream);
                        cudaStreamSynchronize(compute_stream);

                        cudaEventRecord(ev_start, compute_stream);
                        while (tuned < tune_keys) {
                            if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) {
                                skip_benchmark = 1;
                                break;
                            }
                            if (GetTickCount64() - tune_start_tick >= tune_budget_ms) {
                                skip_benchmark = 1;
                                break;
                            }
                            uint64_t cur = cand_chunk;
                            if (tuned + cur > tune_keys) cur = tune_keys - tuned;

                            if (strict_mode) {
                                bruteforce_kernel_strict<<<blocks, tpb, 0, compute_stream>>>(
                                    engine->cfg.start_key + tuned,
                                    cur,
                                    payload_limit,
                                    global_mi,
                                    d_keys_tested,
                                    d_best_score,
                                    d_best_key,
                                    d_stop_requested
                                );
                            } else {
                                bruteforce_kernel<<<blocks, tpb, 0, compute_stream>>>(
                                    engine->cfg.start_key + tuned,
                                    cur,
                                    payload_limit,
                                    bytes_per_line,
                                    engine->cfg.sample_bytes,
                                    mode_policy,
                                    global_mi,
                                    has_global_mi,
                                    global_algid,
                                    has_global_algid,
                                    d_keys_tested,
                                    d_best_score,
                                    d_best_key,
                                    d_stop_requested
                                );
                            }
                            cu_err = cudaGetLastError();
                            if (cu_err != cudaSuccess) {
                                ms = 0.0f;
                                break;
                            }
                            tuned += cur;
                            InterlockedExchange64(&engine->keys_tested, (LONG64)tuned);
                            InterlockedExchange64(&engine->cuda_last_update_ms, (LONG64)GetTickCount64());
                        }
                        if (skip_benchmark) break;
                        cudaEventRecord(ev_stop, compute_stream);
                        cudaEventSynchronize(ev_stop);
                        cudaEventElapsedTime(&ms, ev_start, ev_stop);

                        if (ms > 0.05f) {
                            kps = ((float)tune_keys * 1000.0f) / ms;
                            if (kps > best_kps) {
                                best_kps = kps;
                                profile.threads_per_block = tpb;
                                profile.blocks_per_sm = bpsm;
                                profile.chunk_mult = chunk_mult;
                            }
                        }
                    }
                    if (skip_benchmark) break;
                }
                if (skip_benchmark) break;
            }

            if (ev_start) cudaEventDestroy(ev_start);
            if (ev_stop) cudaEventDestroy(ev_stop);
            save_cuda_launch_profile(&prop, strict_mode, &profile);
        }

        InterlockedExchange(&engine->cuda_tpb, profile.threads_per_block);
        InterlockedExchange(&engine->cuda_bpsm, profile.blocks_per_sm);
        InterlockedExchange(&engine->cuda_chunk_mult, profile.chunk_mult);

        threadsPerBlock = profile.threads_per_block;
        if (threadsPerBlock < 64) threadsPerBlock = 64;
        if (threadsPerBlock > prop.maxThreadsPerBlock) threadsPerBlock = prop.maxThreadsPerBlock;
        if ((threadsPerBlock & 31) != 0) threadsPerBlock = 256;

        blocksPerGrid = prop.multiProcessorCount * profile.blocks_per_sm;
        if (blocksPerGrid < prop.multiProcessorCount) blocksPerGrid = prop.multiProcessorCount;
        if (blocksPerGrid > 65535) blocksPerGrid = 65535;

        chunk_size = (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * (uint64_t)profile.chunk_mult;
        if (chunk_size < (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * 32ULL) {
            chunk_size = (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * 32ULL;
        }
    }

    InterlockedExchange(&engine->cuda_stage, 2);

    // Batch chunking (TDR-Safe): adjusted by autotune/cache
    {
        float init_score = -FLT_MAX;
        CUDA_CHECK(cudaMemset(d_keys_tested, 0, sizeof(unsigned long long)), "cudaMemset keys_tested (scan reset)");
        CUDA_CHECK(cudaMemcpy(d_best_score, &init_score, sizeof(float), cudaMemcpyHostToDevice), "cudaMemcpy best_score (scan reset)");
        CUDA_CHECK(cudaMemset(d_best_key, 0, sizeof(unsigned long long)), "cudaMemset best_key (scan reset)");
        CUDA_CHECK(cudaMemset(d_stop_requested, 0, sizeof(int)), "cudaMemset stop_requested (scan reset)");
    }

    /* === Double-buffer multi-stream dispatch (Change 6) + pinned polling (Change 5) === */
    {
        cudaStream_t streams[2] = { compute_stream, compute_stream2 };
        int active = 0;
        int have_pending = 0;

        /* Helper: poll GPU results into engine using pinned memory */
        #define POLL_GPU_RESULTS() do { \
            if (h_poll) { \
                cudaMemcpyAsync(&h_poll->keys_tested, d_keys_tested, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&h_poll->best_score, d_best_score, sizeof(float), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&h_poll->best_key, d_best_key, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaStreamSynchronize(query_stream); \
                InterlockedExchange64(&engine->keys_tested, h_poll->keys_tested); \
                EnterCriticalSection(&engine->lock); \
                if (h_poll->best_score > (-FLT_MAX * 0.5f)) { \
                    engine->best_score = (double)h_poll->best_score; \
                    engine->best_key = h_poll->best_key; \
                } \
                LeaveCriticalSection(&engine->lock); \
            } else { \
                unsigned long long _k = 0, _bk = 0; float _bs = 0.0f; \
                cudaMemcpyAsync(&_k, d_keys_tested, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&_bs, d_best_score, sizeof(float), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&_bk, d_best_key, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaStreamSynchronize(query_stream); \
                InterlockedExchange64(&engine->keys_tested, _k); \
                EnterCriticalSection(&engine->lock); \
                if (_bs > (-FLT_MAX * 0.5f)) { \
                    engine->best_score = (double)_bs; engine->best_key = _bk; \
                } \
                LeaveCriticalSection(&engine->lock); \
            } \
            InterlockedExchange64(&engine->cuda_last_update_ms, (LONG64)GetTickCount64()); \
        } while(0)

        /* Helper: launch kernel on given stream */
        #define LAUNCH_CHUNK(stream_idx, off, cnt) do { \
            if (mode_policy >= 2) { \
                bruteforce_kernel_strict<<<blocksPerGrid, threadsPerBlock, 0, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, global_mi, \
                    d_keys_tested, d_best_score, d_best_key, d_stop_requested); \
            } else { \
                bruteforce_kernel<<<blocksPerGrid, threadsPerBlock, 0, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, bytes_per_line, \
                    engine->cfg.sample_bytes, mode_policy, global_mi, has_global_mi, \
                    global_algid, has_global_algid, \
                    d_keys_tested, d_best_score, d_best_key, d_stop_requested); \
            } \
        } while(0)

        for (offset = 0; offset < total_keys; offset += chunk_size) {
            /* Pause check */
            while (InterlockedCompareExchange(&engine->paused, 0, 0) != 0) {
                WaitForSingleObject(engine->pause_event, INFINITE);
                if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) break;
            }
            if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) {
                int stop_sig = 1;
                cudaMemcpyAsync(d_stop_requested, &stop_sig, sizeof(int), cudaMemcpyHostToDevice, query_stream);
                cudaStreamSynchronize(query_stream);
                break;
            }

            uint64_t current_chunk = chunk_size;
            if (offset + chunk_size > total_keys) current_chunk = total_keys - offset;

            /* Launch on current stream */
            LAUNCH_CHUNK(active, offset, current_chunk);
            cu_err = cudaGetLastError();
            if (cu_err != cudaSuccess) {
                snprintf(engine->cuda_error, sizeof(engine->cuda_error), "Kernel launch: %s", cudaGetErrorString(cu_err));
                goto cleanup;
            }

            /* If we have a pending chunk on the other stream, wait for it */
            if (have_pending) {
                int other = 1 - active;
                while (cudaStreamQuery(streams[other]) == cudaErrorNotReady) {
                    if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) != 0) {
                        int stop_sig = 1;
                        cudaMemcpyAsync(d_stop_requested, &stop_sig, sizeof(int), cudaMemcpyHostToDevice, query_stream);
                        cudaStreamSynchronize(query_stream);
                    }
                    POLL_GPU_RESULTS();
                    Sleep(5);
                }
            }

            have_pending = 1;
            active = 1 - active;
        }

        /* Wait for last chunk(s) */
        cudaStreamSynchronize(streams[0]);
        cudaStreamSynchronize(streams[1]);

        #undef POLL_GPU_RESULTS
        #undef LAUNCH_CHUNK
    }

    /* Final result read */
    {
        unsigned long long final_k = 0, final_b_key = 0;
        float final_score_f = 0.0f;
        CUDA_CHECK(cudaMemcpy(&final_k,       d_keys_tested, sizeof(unsigned long long), cudaMemcpyDeviceToHost), "cudaMemcpy final keys_tested");
        CUDA_CHECK(cudaMemcpy(&final_score_f, d_best_score,  sizeof(float),              cudaMemcpyDeviceToHost), "cudaMemcpy final best_score");
        CUDA_CHECK(cudaMemcpy(&final_b_key,   d_best_key,    sizeof(unsigned long long), cudaMemcpyDeviceToHost), "cudaMemcpy final best_key");
        InterlockedExchange64(&engine->keys_tested, (LONG64)final_k);
        EnterCriticalSection(&engine->lock);
        if (final_score_f > (-FLT_MAX * 0.5f)) {
            engine->best_score = (double)final_score_f;
            engine->best_key = final_b_key;
        }
        LeaveCriticalSection(&engine->lock);
    }

    if (InterlockedCompareExchange(&engine->stop_requested, 0, 0) == 0) {
        InterlockedExchange(&engine->search_completed, 1);
    }

cleanup:
    if (d_keys_tested) cudaFree(d_keys_tested);
    if (d_best_score) cudaFree(d_best_score);
    if (d_best_key) cudaFree(d_best_key);
    if (d_stop_requested) cudaFree(d_stop_requested);
    free(host_payload_flat);
    if (h_poll) cudaFreeHost(h_poll);
    if (compute_stream) cudaStreamDestroy(compute_stream);
    if (compute_stream2) cudaStreamDestroy(compute_stream2);
    if (query_stream) cudaStreamDestroy(query_stream);

    InterlockedExchange(&engine->cuda_stage, 3);
    InterlockedExchange64(&engine->cuda_last_update_ms, (LONG64)GetTickCount64());
    InterlockedExchange(&engine->running, 0);
    SetEvent(engine->pause_event);
    return 0;
}

#undef CUDA_CHECK

// ==== ORIGINAL HOST API EXPORTS (bruteforce.h) ====

void bruteforce_engine_init(BruteforceEngine *engine)
{
    ZeroMemory(engine, sizeof(*engine));
    InitializeCriticalSection(&engine->lock);
    QueryPerformanceFrequency(&engine->qpc_freq);
    engine->cuda_active = 0;
    engine->cuda_device_name[0] = '\0';
    engine->cuda_stage = 0;
    engine->cuda_profile_cached = 0;
    engine->cuda_tpb = 0;
    engine->cuda_bpsm = 0;
    engine->cuda_chunk_mult = 0;
    engine->cuda_sm_count = 0;
    engine->cuda_compute_major = 0;
    engine->cuda_compute_minor = 0;
    engine->cuda_last_update_ms = 0;
}

void bruteforce_engine_destroy(BruteforceEngine *engine)
{
    bruteforce_stop(engine);
    if (engine->pause_event != NULL) {
        CloseHandle(engine->pause_event);
        engine->pause_event = NULL;
    }
    DeleteCriticalSection(&engine->lock);
}

static void set_error(char *err, size_t err_len, const char *msg)
{
    if (err != NULL && err_len > 0) {
        snprintf(err, err_len, "%s", msg);
    }
}

int bruteforce_start(
    BruteforceEngine *engine,
    const BruteforceConfig *cfg,
    const PayloadSet *payloads,
    char *err,
    size_t err_len)
{
    if (InterlockedCompareExchange(&engine->running, 0, 0) != 0) {
        set_error(err, err_len, "A search is already active");
        return 0;
    }

    if (cfg->start_key > cfg->end_key) {
        set_error(err, err_len, "Start key must be <= End key");
        return 0;
    }
    if (cfg->end_key > 0xFFFFFFFFFFull) {
        set_error(err, err_len, "End key exceeds 40 bits");
        return 0;
    }
    if (payloads == NULL || payloads->count == 0) {
        set_error(err, err_len, "No payloads loaded");
        return 0;
    }

    int deviceCount = 0;
    cudaError_t cu_err = cudaGetDeviceCount(&deviceCount);
    if (cu_err != cudaSuccess || deviceCount == 0) {
        engine->cuda_active = 0;
        engine->cuda_device_name[0] = '\0';
        snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                 "CUDA not available: %s", cudaGetErrorString(cu_err));
        set_error(err, err_len, "NVIDIA CUDA Error o no hay GPUs compatibles.");
        return 0;
    }

    {
        cudaDeviceProp prop;
        cu_err = cudaGetDeviceProperties(&prop, 0);
        if (cu_err == cudaSuccess) {
            strncpy(engine->cuda_device_name, prop.name, sizeof(engine->cuda_device_name) - 1);
            engine->cuda_device_name[sizeof(engine->cuda_device_name) - 1] = '\0';
            engine->cuda_active = 1;
        } else {
            engine->cuda_active = 1;
            engine->cuda_device_name[0] = '\0';
        }
    }

    engine->cfg = *cfg;
    {
        size_t max_len = 0;
        for (size_t i = 0; i < payloads->count; ++i) {
            if (payloads->items[i].len > max_len) max_len = payloads->items[i].len;
        }
        if (max_len > 33) max_len = 33;

        if (engine->cfg.sample_bytes <= 0) {
            if (max_len == 0) max_len = 27;
            engine->cfg.sample_bytes = (int)max_len;
        } else if (engine->cfg.sample_bytes == 27 && max_len >= 33) {
            engine->cfg.sample_bytes = 33;
        }
    }
    if (engine->cfg.sample_lines <= 0 || (size_t)engine->cfg.sample_lines > payloads->count) {
        engine->cfg.sample_lines = (int)payloads->count;
    }
    engine->payloads = payloads;

    if (engine->pause_event != NULL) {
        CloseHandle(engine->pause_event);
    }
    engine->pause_event = CreateEventA(NULL, TRUE, TRUE, NULL);

    InterlockedExchange64(&engine->keys_tested, 0);
    InterlockedExchange(&engine->stop_requested, 0);
    InterlockedExchange(&engine->paused, 0);
    InterlockedExchange(&engine->search_completed, 0);
    engine->best_key = engine->cfg.start_key;
    engine->best_score = -DBL_MAX;
    InterlockedExchange(&engine->cuda_stage, 0);
    InterlockedExchange(&engine->cuda_profile_cached, 0);
    InterlockedExchange(&engine->cuda_tpb, 0);
    InterlockedExchange(&engine->cuda_bpsm, 0);
    InterlockedExchange(&engine->cuda_chunk_mult, 0);
    InterlockedExchange(&engine->cuda_sm_count, 0);
    InterlockedExchange(&engine->cuda_compute_major, 0);
    InterlockedExchange(&engine->cuda_compute_minor, 0);
    InterlockedExchange64(&engine->cuda_last_update_ms, (LONG64)GetTickCount64());

    engine->cuda_error[0] = '\0';
    QueryPerformanceCounter(&engine->qpc_start);

    /* Allocate handle array before launching thread so the handle is never lost. */
    engine->thread_handles = (HANDLE *)calloc(1, sizeof(HANDLE));
    if (engine->thread_handles == NULL) {
        set_error(err, err_len, "Insufficient memory for handles");
        return 0;
    }

    InterlockedExchange(&engine->running, 1);

    uintptr_t th = _beginthreadex(NULL, 0, cuda_launcher_thread, engine, 0, NULL);
    if (th == 0) {
        InterlockedExchange(&engine->running, 0);
        free(engine->thread_handles);
        engine->thread_handles = NULL;
        set_error(err, err_len, "Error creating CUDA Launcher thread");
        return 0;
    }
    engine->thread_handles[0] = (HANDLE)th;

    return 1;
}

void bruteforce_pause(BruteforceEngine *engine)
{
    if (InterlockedCompareExchange(&engine->running, 0, 0) == 0) return;
    InterlockedExchange(&engine->paused, 1);
    ResetEvent(engine->pause_event);
}

void bruteforce_resume(BruteforceEngine *engine)
{
    if (InterlockedCompareExchange(&engine->running, 0, 0) == 0) return;
    InterlockedExchange(&engine->paused, 0);
    SetEvent(engine->pause_event);
}

void bruteforce_stop(BruteforceEngine *engine)
{
    if (engine->thread_handles == NULL) {
        InterlockedExchange(&engine->running, 0);
        return;
    }

    InterlockedExchange(&engine->stop_requested, 1);
    InterlockedExchange(&engine->paused, 0);
    SetEvent(engine->pause_event);

    WaitForSingleObject(engine->thread_handles[0], INFINITE);
    CloseHandle(engine->thread_handles[0]);
    free(engine->thread_handles);
    engine->thread_handles = NULL;

    InterlockedExchange(&engine->running, 0);
}

static uint64_t read_u64(const volatile LONG64 *value)
{
    return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)value, 0, 0);
}

void bruteforce_get_snapshot(BruteforceEngine *engine, BruteforceSnapshot *out)
{
    LARGE_INTEGER now;
    double elapsed;
    uint64_t keys;
    uint64_t total;

    keys = read_u64(&engine->keys_tested);
    total = 0;
    if (engine->cfg.end_key >= engine->cfg.start_key) {
        total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    }

    QueryPerformanceCounter(&now);
    elapsed = (double)(now.QuadPart - engine->qpc_start.QuadPart) / (double)engine->qpc_freq.QuadPart;
    if (elapsed < 0.0) elapsed = 0.0;

    out->keys_tested = keys;
    out->total_keys = total;
    EnterCriticalSection(&engine->lock);
    out->best_key = engine->best_key;
    out->best_score = engine->best_score;
    LeaveCriticalSection(&engine->lock);
    out->elapsed_seconds = elapsed;
    out->running = InterlockedCompareExchange(&engine->running, 0, 0);
    out->paused = InterlockedCompareExchange(&engine->paused, 0, 0);
    out->finished = InterlockedCompareExchange(&engine->search_completed, 0, 0);

    if (elapsed > 0.0) out->keys_per_second = (double)keys / elapsed;
    else out->keys_per_second = 0.0;

    if (out->keys_per_second > 0.0 && total > keys) {
        out->eta_seconds = (double)(total - keys) / out->keys_per_second;
    } else out->eta_seconds = -1.0;
}

static int popcount_byte_host(unsigned char b)
{
    int c = 0;
    while (b) {
        c += (b & 1);
        b >>= 1;
    }
    return c;
}

static int popcount_u32_host(uint32_t v)
{
    int c = 0;
    c += popcount_byte_host((unsigned char)(v & 0xFFu));
    c += popcount_byte_host((unsigned char)((v >> 8) & 0xFFu));
    c += popcount_byte_host((unsigned char)((v >> 16) & 0xFFu));
    c += popcount_byte_host((unsigned char)((v >> 24) & 0xFFu));
    return c;
}

static void rc4_discard_host(RC4_CTX *ctx, int nbytes)
{
    unsigned char in[64] = {0};
    unsigned char out[64];

    while (nbytes > 0) {
        int step = nbytes > 64 ? 64 : nbytes;
        rc4_crypt(ctx, in, out, (size_t)step);
        nbytes -= step;
    }
}

static uint32_t dmr_mi_lfsr_next_host(uint32_t mi)
{
    uint32_t bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1u;
    return (mi << 1) | bit;
}

static uint32_t dmr_mi_lfsr_prev_host(uint32_t mi)
{
    uint32_t old31 = ((mi >> 0) ^ (mi >> 4) ^ (mi >> 2)) & 1u;
    return (mi >> 1) | (old31 << 31);
}

static uint32_t lfsr_step_n_fwd(uint32_t mi, int n)
{
    while (n-- > 0) mi = dmr_mi_lfsr_next_host(mi);
    return mi;
}

static uint32_t lfsr_step_n_back(uint32_t mi, int n)
{
    while (n-- > 0) mi = dmr_mi_lfsr_prev_host(mi);
    return mi;
}

static int infer_line_mi_host(const PayloadSet *payloads, int line_idx, uint32_t *out_mi)
{
    int i;
    int best_idx = -1;
    int best_dist = 0x7FFFFFFF;

    for (i = 0; i < (int)payloads->count; ++i) {
        if (!payloads->items[i].has_mi) continue;
        {
            int dist = i - line_idx;
            if (dist < 0) dist = -dist;
            if (dist < best_dist) {
                best_dist = dist;
                best_idx = i;
            }
        }
    }

    if (best_idx >= 0) {
        uint32_t mi = payloads->items[best_idx].mi;
        int delta = line_idx - best_idx;
        if (delta > 0) mi = lfsr_step_n_fwd(mi, delta);
        else if (delta < 0) mi = lfsr_step_n_back(mi, -delta);
        *out_mi = mi;
        return 1;
    }

    if (payloads->has_global_mi) {
        *out_mi = payloads->global_mi;
        return 1;
    }

    return 0;
}

static int extract_voice_dibits_host(
    const unsigned char *bytes,
    size_t bytes_to_test,
    int dibit_variant,
    unsigned char out_dibits[108])
{
    int total_dibits = (int)bytes_to_test * 4;
    if (total_dibits >= 132) {
        int di = 0;
        int i;
        for (i = 0; i < 54; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[di++] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        for (i = 78; i < 132; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[di++] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        return 108;
    }

    if (total_dibits >= 108) {
        int i;
        for (i = 0; i < 108; ++i) {
            int byte_idx = i >> 2;
            int shift = (dibit_variant == 0) ? ((3 - (i & 3)) * 2) : ((i & 3) * 2);
            out_dibits[i] = (unsigned char)((bytes[byte_idx] >> shift) & 0x3u);
        }
        return 108;
    }

    return 0;
}

static double score_dmr_ambe_host(
    const unsigned char *bytes,
    size_t bytes_to_test,
    uint32_t *out_sig_first,
    uint32_t *out_sig_last)
{
    unsigned char voice_dibits[108];
    unsigned char ambe[3][4][24];
    double best_score = -1.0e300;
    uint32_t best_s0 = 0u, best_s2 = 0u;

    for (int variant = 0; variant < 2; ++variant) {
        int dcount = extract_voice_dibits_host(bytes, bytes_to_test, variant, voice_dibits);
        double score = 0.0;
        int f, c;

        if (dcount < 108) continue;

        memset(ambe, 0, sizeof(ambe));

        for (f = 0; f < 3; ++f) {
            for (int i = 0; i < 36; ++i) {
                unsigned char dibit = voice_dibits[f * 36 + i];
                ambe[f][dmr_rW_host[i]][dmr_rX_host[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe[f][dmr_rY_host[i]][dmr_rZ_host[i]] = (unsigned char)(dibit & 1u);
            }
        }

        {
            int h01 = 0, h12 = 0, h02 = 0;
            int hp = 0;

            for (c = 0; c < 24; ++c) {
                h01 += (ambe[0][0][c] ^ ambe[1][0][c]) & 1u;
                h12 += (ambe[1][0][c] ^ ambe[2][0][c]) & 1u;
                h02 += (ambe[0][0][c] ^ ambe[2][0][c]) & 1u;
            }
            for (c = 0; c < 12; ++c) {
                h01 += (ambe[0][1][c] ^ ambe[1][1][c]) & 1u;
                h12 += (ambe[1][1][c] ^ ambe[2][1][c]) & 1u;
                h02 += (ambe[0][1][c] ^ ambe[2][1][c]) & 1u;
            }
            for (c = 0; c < 8; ++c) {
                hp += (ambe[0][2][c] ^ ambe[2][2][c]) & 1u;
            }

            score += (18.0 - (double)h01) * 10.0;
            score += (18.0 - (double)h12) * 10.0;
            score += (18.0 - (double)h02) * 6.0;
            score += (4.0 - (double)hp) * 5.0;
        }

        {
            uint32_t s0 = 0u;
            uint32_t s2 = 0u;
            for (c = 0; c < 24; ++c) {
                s0 = (s0 << 1) | (uint32_t)(ambe[0][0][c] & 1u);
                s2 = (s2 << 1) | (uint32_t)(ambe[2][0][c] & 1u);
            }
            for (c = 0; c < 8; ++c) {
                s0 = (s0 << 1) | (uint32_t)(ambe[0][1][c] & 1u);
                s2 = (s2 << 1) | (uint32_t)(ambe[2][1][c] & 1u);
            }
            if (score > best_score) {
                best_score = score;
                best_s0 = s0;
                best_s2 = s2;
            }
        }
    }

    if (best_score < -1.0e200) return 0.0;
    if (out_sig_first != NULL) *out_sig_first = best_s0;
    if (out_sig_last != NULL) *out_sig_last = best_s2;
    return best_score;
}

static int is_rc4_alg_host(uint8_t alg)
{
    return alg == 0x21 || alg == 0x01 || ((alg & 0x07u) == 0x01u);
}

static void rc4_init_kmi_host(RC4_CTX *ctx, const unsigned char key[5], uint32_t mi)
{
    unsigned char kmi[9];
    kmi[0] = key[0];
    kmi[1] = key[1];
    kmi[2] = key[2];
    kmi[3] = key[3];
    kmi[4] = key[4];
    kmi[5] = (unsigned char)((mi >> 24) & 0xFFu);
    kmi[6] = (unsigned char)((mi >> 16) & 0xFFu);
    kmi[7] = (unsigned char)((mi >> 8) & 0xFFu);
    kmi[8] = (unsigned char)(mi & 0xFFu);
    rc4_init(ctx, kmi, 9);
}

/*
 * Host-side correct scoring pipeline (mirrors score_burst_correct_dev).
 * Used by bruteforce_test_score() and CPU fallback.
 */
static double score_burst_correct_host(
    const unsigned char *payload33,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos)
{
    unsigned char kmi9[9];
    kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
    kmi9[3] = key5[3]; kmi9[4] = key5[4];
    kmi9[5] = (unsigned char)((mi >> 24) & 0xFFu);
    kmi9[6] = (unsigned char)((mi >> 16) & 0xFFu);
    kmi9[7] = (unsigned char)((mi >> 8) & 0xFFu);
    kmi9[8] = (unsigned char)(mi & 0xFFu);

    RC4_CTX rc4;
    rc4_init(&rc4, kmi9, 9);
    rc4_discard_host(&rc4, 256 + burst_pos * 21);

    unsigned char dec24[3][24];

    for (int sf = 0; sf < 3; ++sf) {
        unsigned char ambe_fr[4][24];
        memset(ambe_fr, 0, sizeof(ambe_fr));

        for (int i = 0; i < 36; ++i) {
            int d = sf_dibit_idx_host[sf][i];
            int byte_idx = d >> 2;
            int shift = (3 - (d & 3)) * 2;
            unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
            ambe_fr[dmr_rW_host[i]][dmr_rX_host[i]] = (unsigned char)((dibit >> 1) & 1u);
            ambe_fr[dmr_rY_host[i]][dmr_rZ_host[i]] = (unsigned char)(dibit & 1u);
        }

        /* mbe_demodulate */
        {
            int foo = 0;
            for (int i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
            int pr_val = 16 * foo;
            for (int j = 22; j >= 0; --j) {
                pr_val = (173 * pr_val + 13849) & 0xFFFF;
                ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
            }
        }

        /* extract 49 bits */
        unsigned char bits49[49];
        {
            int bi = 0;
            for (int j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (int j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (int j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (int j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];
        }

        /* pack 49 bits -> 7 bytes */
        unsigned char cipher7[7] = {0};
        for (int i = 0; i < 49; ++i) {
            cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
        }

        /* RC4 decrypt 7 bytes */
        unsigned char plain7[7];
        rc4_crypt(&rc4, cipher7, plain7, 7);

        /* unpack first 24 bits */
        for (int i = 0; i < 24; ++i) {
            dec24[sf][i] = (unsigned char)((plain7[i >> 3] >> (7 - (i & 7))) & 1u);
        }
    }

    int h01 = 0, h12 = 0;
    for (int i = 0; i < 24; ++i) {
        h01 += dec24[0][i] ^ dec24[1][i];
        h12 += dec24[1][i] ^ dec24[2][i];
    }

    return (double)(48 - h01 - h12);
}

static double score_candidate_host(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    size_t line_count = payloads->count;
    double score = 0.0;
    int mode_policy = 0;

    if (sample_lines > 0 && (size_t)sample_lines < line_count) {
        line_count = (size_t)sample_lines;
    }

    /* Determine mode policy */
    {
        int mi_rc4_lines = 0;
        for (size_t i = 0; i < line_count; ++i) {
            const PayloadLine *line = &payloads->items[i];
            uint8_t alg = line->has_algid ? line->algid : payloads->global_algid;
            if (line->has_mi && is_rc4_alg_host(alg)) mi_rc4_lines++;
        }
        if (line_count > 0 && mi_rc4_lines * 10 >= (int)line_count * 9) {
            mode_policy = 3;
        } else if (line_count > 0 && mi_rc4_lines * 3 >= (int)line_count) {
            mode_policy = 2;
        } else if (!payloads->has_global_mi && mi_rc4_lines == 0) {
            mode_policy = 1;
        }
    }

    /* Correct pipeline for mode_policy >= 2 */
    if (mode_policy >= 2) {
        for (size_t p = 0; p < line_count; ++p) {
            const PayloadLine *line = &payloads->items[p];
            uint32_t mi = line->has_mi ? line->mi : payloads->global_mi;
            int burst_pos = (int)(p % 6);
            if (line->len >= 33) {
                score += score_burst_correct_host(line->data, key, mi, burst_pos);
            }
        }
        return score;
    }

    /* Legacy path for mode_policy 0/1 */
    RC4_CTX rc4_base;
    rc4_init(&rc4_base, key, 5);

    {
        double best_mode_1 = -1e300;
        double best_mode_2 = -1e300;

        int mode_iter_count = (mode_policy == 1) ? 4 : ((mode_policy == 2) ? 6 : ((mode_policy == 3) ? 2 : 12));
        for (int mode_iter = 0; mode_iter < mode_iter_count; ++mode_iter) {
            int mode;
            int base_mode = 0;
            int mi_offset = 0;
            int use_reset;
            int use_drop256;
            int use_kmi;
            int use_mi_lfsr;
            int use_kmi_force;
            double mode_score = 0.0;
            RC4_CTX rc4_cont = rc4_base;
            uint32_t running_mi = payloads->global_mi;
            uint32_t prev_last_sig = 0u;
            int has_prev_sig = 0;

            if (mode_policy == 1) {
                mode = mode_iter;
            } else if (mode_policy == 2) {
                const int kmi_modes[6] = { 5, 7, 8, 9, 10, 11 };
                mode = kmi_modes[mode_iter];
            } else if (mode_policy == 3) {
                const int strict_modes[2] = { 5, 7 };
                mode = strict_modes[mode_iter];
            } else {
                mode = mode_iter;
            }

            base_mode = mode;

            if (mode >= 8) {
                if (mode == 8) { base_mode = 5; mi_offset = +1; }
                else if (mode == 9) { base_mode = 5; mi_offset = -1; }
                else if (mode == 10) { base_mode = 7; mi_offset = +1; }
                else { base_mode = 7; mi_offset = -1; }
            }

            use_reset = (base_mode == 0 || base_mode == 2);
            use_drop256 = (base_mode >= 2);
            use_kmi = (base_mode >= 4);
            use_mi_lfsr = (base_mode == 5 || base_mode == 7);
            use_kmi_force = (base_mode == 6 || base_mode == 7);

            if (use_kmi) {
                use_reset = 1;
                use_drop256 = 1;
            }

            if (!use_reset && use_drop256) {
                rc4_discard_host(&rc4_cont, 256);
            }

            for (size_t line_idx = 0; line_idx < line_count; ++line_idx) {
                const PayloadLine *line = &payloads->items[line_idx];
                size_t bytes_to_decrypt = line->len;
                size_t bytes_to_test;
                unsigned char out[64];
                RC4_CTX rc4;
                uint32_t line_mi = 0;
                uint8_t line_alg = line->has_algid ? line->algid : payloads->global_algid;
                int line_rc4 = is_rc4_alg_host(line_alg);
                double local_score = 0.0;
                uint32_t sig_first = 0u;
                uint32_t sig_last = 0u;

                if (sample_bytes > 0 && (size_t)sample_bytes < bytes_to_decrypt) {
                    bytes_to_decrypt = (size_t)sample_bytes;
                }
                if (line->len >= 33 && bytes_to_decrypt < 33) {
                    bytes_to_decrypt = 33;
                }
                if (bytes_to_decrypt == 0) continue;
                if (bytes_to_decrypt > sizeof(out)) bytes_to_decrypt = sizeof(out);

                bytes_to_test = bytes_to_decrypt;
                if (bytes_to_test >= 33) {
                    bytes_to_test = 33;
                }

                if (line->has_mi) line_mi = line->mi;
                else if (!infer_line_mi_host(payloads, (int)line_idx, &line_mi)) line_mi = payloads->global_mi;

                if (use_mi_lfsr) {
                    if (line->has_mi) running_mi = line_mi;
                    else if (line_mi != 0u) running_mi = line_mi;
                }

                if (mi_offset != 0 && line_mi != 0u) {
                    if (mi_offset > 0) {
                        line_mi = lfsr_step_n_fwd(line_mi, mi_offset);
                    } else {
                        line_mi = lfsr_step_n_back(line_mi, -mi_offset);
                    }
                }

                if (use_reset) {
                    if (use_kmi && line_mi != 0u && (line_rc4 || use_kmi_force)) {
                        rc4_init_kmi_host(&rc4, key, line_mi);
                    } else {
                        rc4 = rc4_base;
                    }
                    if (use_drop256) rc4_discard_host(&rc4, 256);
                    rc4_crypt(&rc4, line->data, out, bytes_to_decrypt);
                } else {
                    rc4_crypt(&rc4_cont, line->data, out, bytes_to_decrypt);
                }

                if (use_mi_lfsr && line_rc4 && line_mi != 0u) {
                    running_mi = dmr_mi_lfsr_next_host(line_mi);
                }

                local_score += score_dmr_ambe_host(out, bytes_to_decrypt, &sig_first, &sig_last);
                if (has_prev_sig) {
                    int h = popcount_u32_host(prev_last_sig ^ sig_first);
                    double continuity_w = (mode_policy == 3) ? 18.0 : 12.0;
                    local_score += (16.0 - (double)h) * continuity_w;
                }
                prev_last_sig = sig_last;
                has_prev_sig = 1;

        if (mode_policy != 3) {
            {
                int max_lag = (int)(bytes_to_test / 2);
                if (max_lag > 13) max_lag = 13;
                for (int lag = 1; lag <= max_lag; ++lag) {
                    int n_bytes = (int)bytes_to_test - lag;
                    int hamming = 0;
                    int expected;
                    for (int j = 0; j < n_bytes; ++j) {
                        hamming += popcount_byte_host(out[j] ^ out[j + lag]);
                    }
                    expected = n_bytes * 4;
                    {
                        int deviation = hamming - expected;
                        if (deviation < 0) deviation = -deviation;
                        local_score += (double)deviation * 2.5;
                    }
                }
            }

            {
                int transitions = 0;
                int total_bit_pairs = (int)(bytes_to_test * 8) - 1;
                int expected_transitions;

                for (size_t i = 0; i < bytes_to_test; ++i) {
                    unsigned char b = out[i];
                    for (int k = 0; k < 7; ++k) {
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
                {
                    int deviation = transitions - expected_transitions;
                    if (deviation < 0) deviation = -deviation;
                    local_score += (double)deviation * 3.0;
                }
            }

            {
                int total_bits = 0;
                for (size_t i = 0; i < bytes_to_test; ++i) {
                    total_bits += popcount_byte_host(out[i]);
                }
                {
                    double bit_ratio = (double)total_bits / (double)(bytes_to_test * 8);
                    double dev = bit_ratio - 0.5;
                    local_score += dev * dev * (double)(bytes_to_test * 8) * 60.0;
                }
            }

            if (bytes_to_test >= 10) {
                static const int pair_offsets[] = { 1, 3, 9 };
                for (int p = 0; p < 3 && pair_offsets[p] < (int)bytes_to_test; ++p) {
                    int off = pair_offsets[p];
                    int n_pairs = (int)bytes_to_test - off;
                    int xor_sum = 0;
                    double mean_xor, var_xor;

                    for (int j = 0; j < n_pairs; ++j) {
                        xor_sum += (int)(out[j] ^ out[j + off]);
                    }
                    mean_xor = (double)xor_sum / (double)n_pairs;
                    var_xor = 0.0;
                    for (int j = 0; j < n_pairs; ++j) {
                        double d = (double)(out[j] ^ out[j + off]) - mean_xor;
                        var_xor += d * d;
                    }
                    var_xor /= (double)n_pairs;

                    {
                        double var_dev = var_xor - 5440.0;
                        if (var_dev < 0.0) var_dev = -var_dev;
                        local_score += var_dev * 0.008;
                    }
                }
            }

            {
                int max_run = 1;
                int run = 1;
                for (size_t i = 1; i < bytes_to_test; ++i) {
                    if (out[i] == out[i - 1]) {
                        run++;
                        if (run > max_run) max_run = run;
                    } else {
                        run = 1;
                    }
                }
                if (max_run > 5) local_score -= (double)(max_run - 5) * 50.0;
            }
        }

                mode_score += local_score;
            }

            if (mode_score > best_mode_1) {
                best_mode_2 = best_mode_1;
                best_mode_1 = mode_score;
            } else if (mode_score > best_mode_2) {
                best_mode_2 = mode_score;
            }
        }

        score = (best_mode_2 > -1e290)
            ? (best_mode_1 * 0.70 + best_mode_2 * 0.30)
            : best_mode_1;
    }

    return score;
}

double bruteforce_test_score(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    return score_candidate_host(payloads, sample_lines, sample_bytes, key);
}
