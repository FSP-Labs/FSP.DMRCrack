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
#include "../include/platform.h"
#include "../include/gpu_compat.h"
#include <float.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#  include <immintrin.h>   /* AVX2 intrinsics for 4-way CPU worker S-box init */
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "../include/rc4.h"
#ifdef __cplusplus
}
#endif

#include "../include/lang.h"   /* has its own extern "C" wrapper */

/*
 * =========================================================================
 * GPU RC4 PROTOCOL MACROS AND COPIES (__device__)
 * =========================================================================
 */

// Ultra-fast constant memory (1-cycle L1 cache) for payloads shared by all threads
#define MAX_CONST_LINES 256
__constant__ unsigned char d_const_payloads[8192];
__constant__ unsigned char d_const_cipher_packs[MAX_CONST_LINES * DMR_CIPHER_PACK_BYTES]; // 21 bytes per burst (3x7)
__constant__ unsigned int d_const_mi[MAX_CONST_LINES];
__constant__ unsigned char d_const_algid[MAX_CONST_LINES];
__constant__ unsigned char d_const_meta_flags[MAX_CONST_LINES];
__constant__ float d_abs_floor[MAX_CONST_LINES + 1]; // Absolute screening threshold by burst count
__constant__ uint16_t d_const_silence_idx[64];
__constant__ int      d_const_n_silence;

typedef struct {
    unsigned char S[RC4_SBOX_SIZE];
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

__device__ __forceinline__ void rc4_init_dev_len(RC4_CTX_DEV *ctx, const unsigned char *key, int key_len)
{
    int i, j;
    int k_idx = 0;
    if (key_len <= 0) key_len = 1;
    #pragma unroll 4
    for (i = 0; i < RC4_SBOX_SIZE; i++) {
        ctx->S[i] = (unsigned char)i;
    }
    j = 0;
    ctx->i = 0;
    ctx->j = 0;

    #pragma unroll 4
    for (i = 0; i < RC4_SBOX_SIZE; i++) {
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
    for (int i = 0; i < RC4_SBOX_SIZE; i++) ctx->S[i] = (unsigned char)i;
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

/* Specialized KSA for 5-byte key: eliminates the modulo branch in rc4_init_dev_len.
 * 51 full rounds of 5 iterations = 255 bytes, then 1 remainder = 256 total. */
__device__ __forceinline__ void rc4_ksa5_dev(RC4_CTX_DEV *ctx, const unsigned char key5[5])
{
    #pragma unroll
    for (int i = 0; i < RC4_SBOX_SIZE; i++) ctx->S[i] = (unsigned char)i;
    int j = 0;
    ctx->i = 0;
    ctx->j = 0;

    #pragma unroll 8
    for (int round = 0; round < 51; ++round) {
        int base = round * 5;
        #pragma unroll
        for (int k = 0; k < 5; ++k) {
            int idx = base + k;
            j = (j + ctx->S[idx] + key5[k]) & 0xFF;
            unsigned char t = ctx->S[idx]; ctx->S[idx] = ctx->S[j]; ctx->S[j] = t;
        }
    }
    /* Remaining byte: index 255 (= 51*5), cycles back to key5[0] */
    j = (j + ctx->S[255] + key5[0]) & 0xFF;
    { unsigned char t = ctx->S[255]; ctx->S[255] = ctx->S[j]; ctx->S[j] = t; }
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

__device__ __forceinline__ void rc4_init_dev(RC4_CTX_DEV *ctx, const unsigned char *key)
{
    rc4_ksa5_dev(ctx, key);
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
    }
    ctx->i = i;
    ctx->j = j;
}

/* KPA 24-bit pre-filter for silence frames: decrypt 3 bytes (C0+C1) and verify
 * they equal the AMBE silence pattern (all zeros = unvoiced, zero pitch, all bands
 * unvoiced).  A wrong key passes by chance with probability 2^-24 ≈ 60 ppb —
 * ~16 million times stronger than the old single-bit check.
 * burst_drop = 256 + (silence_idx % 6) * 21 */
__device__ __forceinline__ int kpa_silence_check_dev(
    const unsigned char key5[5],
    uint16_t silence_idx,
    uint32_t burst_drop)
{
    uint32_t mi = d_const_mi[silence_idx];
    unsigned char kmi9[9];
    compose_kmi9_dev(key5, mi, kmi9);

    RC4_CTX_DEV rc4;
    rc4_ksa9_dev(&rc4, kmi9);
    rc4_discard_dev(&rc4, burst_drop);

    /* Decrypt 3 bytes of the silence frame's cipher pack (covers C0+C1 = 24 bits).
     * For AMBE silence: C0=0 (unvoiced, zero pitch), C1=0 (all bands unvoiced). */
    const unsigned char *cp = d_const_cipher_packs + (int)silence_idx * DMR_CIPHER_PACK_BYTES;
    unsigned char plain3[3];
    rc4_crypt_dev(&rc4, cp, plain3, 3);

    return (plain3[0] == 0 && plain3[1] == 0 && plain3[2] == 0) ? 1 : 0;
}

/* Hytera Enhanced Privacy (ALG=0x02) keystream generation.
 * RC4 KSA with key5 (drop=0), then kiv-XOR: ks[i] = rc4[i] ^ kiv[i%5].
 * kiv[0]=key5[0], kiv[1..4]=key5[1..4]^MI_bytes[0..3] (big-endian MI).
 * All 6 bursts in a superframe share the same 21-byte keystream. */
__device__ __forceinline__ void compute_hytera_ks_dev(
    const unsigned char key5[5], uint32_t mi,
    unsigned char ks_out[21])
{
    unsigned char kiv[5];
    kiv[0] = key5[0];
    kiv[1] = key5[1] ^ (unsigned char)((mi >> 24) & 0xFFu);
    kiv[2] = key5[2] ^ (unsigned char)((mi >> 16) & 0xFFu);
    kiv[3] = key5[3] ^ (unsigned char)((mi >>  8) & 0xFFu);
    kiv[4] = key5[4] ^ (unsigned char)( mi        & 0xFFu);

    RC4_CTX_DEV rc4;
    rc4_ksa5_dev(&rc4, key5);  /* KSA with key5, drop=0 */

    unsigned char ri = 0, rj = 0;
    #pragma unroll
    for (int idx = 0; idx < 21; idx++) {
        ri++;
        rj = (unsigned char)(rj + rc4.S[ri]);
        unsigned char t = rc4.S[ri]; rc4.S[ri] = rc4.S[rj]; rc4.S[rj] = t;
        ks_out[idx] = kiv[idx % 5] ^ rc4.S[(unsigned char)(rc4.S[ri] + rc4.S[rj])];
    }
}

/* KPA pre-filter macros — used inside kernel loops.
 * The strict kernel uses goto next_key; the ILP-2 kernel uses pruned flags. */
#define KPA_PREFILTER(key5_ptr)                                                   \
    if (d_const_n_silence > 0) {                                                  \
        int _kpa_pass = 1;                                                        \
        for (int _si = 0; _si < d_const_n_silence && _kpa_pass; _si++) {         \
            uint16_t _idx = d_const_silence_idx[_si];                             \
            uint32_t _bpos = (uint32_t)(_idx % 6u);                              \
            uint32_t _drop = RC4_DISCARD_BYTES + _bpos * DMR_CIPHER_PACK_BYTES;   \
            if (!kpa_silence_check_dev((key5_ptr), _idx, _drop))                  \
                _kpa_pass = 0;                                                    \
        }                                                                         \
        if (!_kpa_pass) goto next_key;                                            \
    }

#define KPA_PREFILTER_A(key5_ptr)                                                 \
    if (d_const_n_silence > 0) {                                                  \
        for (int _si = 0; _si < d_const_n_silence && !pruned_a; _si++) {         \
            uint16_t _idx = d_const_silence_idx[_si];                             \
            uint32_t _bpos = (uint32_t)(_idx % 6u);                              \
            uint32_t _drop = RC4_DISCARD_BYTES + _bpos * DMR_CIPHER_PACK_BYTES;   \
            if (!kpa_silence_check_dev((key5_ptr), _idx, _drop))                  \
                pruned_a = 1;                                                     \
        }                                                                         \
    }

#define KPA_PREFILTER_B(key5_ptr)                                                 \
    if (d_const_n_silence > 0) {                                                  \
        for (int _si = 0; _si < d_const_n_silence && !pruned_b; _si++) {         \
            uint16_t _idx = d_const_silence_idx[_si];                             \
            uint32_t _bpos = (uint32_t)(_idx % 6u);                              \
            uint32_t _drop = RC4_DISCARD_BYTES + _bpos * DMR_CIPHER_PACK_BYTES;   \
            if (!kpa_silence_check_dev((key5_ptr), _idx, _drop))                  \
                pruned_b = 1;                                                     \
        }                                                                         \
    }


/* Process 7 bytes of RC4 keystream but only output the first 3.
 * Split into two separate loops to eliminate the inner branch and avoid
 * 4 unnecessary S-box reads for the trailing bytes that are discarded. */
__device__ __forceinline__ void rc4_crypt_first3_skip4_dev(
    RC4_CTX_DEV *ctx,
    const unsigned char in7[7],
    unsigned char out3[3])
{
    unsigned char i = ctx->i;
    unsigned char j = ctx->j;

    /* First 3 bytes: decrypt and write output */
    #pragma unroll
    for (int k = 0; k < 3; ++k) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        unsigned char t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
        out3[k] = in7[k] ^ ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];
    }

    /* Last 4 bytes: advance state only — no keystream read needed */
    #pragma unroll
    for (int k = 3; k < 7; ++k) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        unsigned char t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
    }

    ctx->i = i;
    ctx->j = j;
}

/* ── Shared-memory RC4 helpers (interleaved layout) ─────────────────────── *
 * S-box layout: S_base[byte_index * stride + lane], where stride=blockDim.x *
 * and lane=threadIdx.x.  This interleaves per-thread S-boxes so that threads *
 * 0-3 access bank 0, threads 4-7 access bank 1, etc. (4-way conflict) rather *
 * than the 32-way conflict of the contiguous layout (S_base[lane*256+k]).    *
 * All S_base accesses: address = k * stride + lane; bank = (k*stride/4+lane/4)%32. */

__device__ __forceinline__ void rc4_ksa9_smem(
    unsigned char * __restrict__ S_base, int stride, int lane,
    const unsigned char key9[9],
    unsigned char *out_i, unsigned char *out_j)
{
    #pragma unroll
    for (int k = 0; k < 256; ++k) S_base[k * stride + lane] = (unsigned char)k;
    unsigned char j = 0;
    for (int round = 0; round < 28; ++round) {
        int base = round * 9;
        #pragma unroll
        for (int k = 0; k < 9; ++k) {
            int idx = base + k;
            unsigned char s_idx = S_base[idx * stride + lane];
            j = (unsigned char)((j + s_idx + key9[k]) & 0xFF);
            unsigned char s_j = S_base[(int)j * stride + lane];
            S_base[idx * stride + lane] = s_j;
            S_base[(int)j * stride + lane] = s_idx;
        }
    }
    #pragma unroll
    for (int k = 0; k < 4; ++k) {
        int idx = 252 + k;
        unsigned char s_idx = S_base[idx * stride + lane];
        j = (unsigned char)((j + s_idx + key9[k]) & 0xFF);
        unsigned char s_j = S_base[(int)j * stride + lane];
        S_base[idx * stride + lane] = s_j;
        S_base[(int)j * stride + lane] = s_idx;
    }
    *out_i = 0;
    *out_j = 0;
}

__device__ __forceinline__ void rc4_discard_smem(
    unsigned char * __restrict__ S_base, int stride, int lane,
    unsigned char *pi, unsigned char *pj, int n)
{
    unsigned char ci = *pi, cj = *pj;
    for (int k = 0; k < n; ++k) {
        ci = (ci + 1) & 0xFF;
        unsigned char s_ci = S_base[(int)ci * stride + lane];
        cj = (unsigned char)((cj + s_ci) & 0xFF);
        unsigned char s_cj = S_base[(int)cj * stride + lane];
        S_base[(int)ci * stride + lane] = s_cj;
        S_base[(int)cj * stride + lane] = s_ci;
    }
    *pi = ci; *pj = cj;
}

__device__ __forceinline__ void rc4_crypt_first3_skip4_smem(
    unsigned char * __restrict__ S_base, int stride, int lane,
    unsigned char *pi, unsigned char *pj,
    const unsigned char in7[7], unsigned char out3[3])
{
    unsigned char ci = *pi, cj = *pj;
    #pragma unroll
    for (int k = 0; k < 3; ++k) {
        ci = (ci + 1) & 0xFF;
        unsigned char s_ci = S_base[(int)ci * stride + lane];
        cj = (unsigned char)((cj + s_ci) & 0xFF);
        unsigned char s_cj = S_base[(int)cj * stride + lane];
        S_base[(int)ci * stride + lane] = s_cj;
        S_base[(int)cj * stride + lane] = s_ci;
        out3[k] = in7[k] ^ S_base[((unsigned char)((s_ci + s_cj) & 0xFF)) * stride + lane];
    }
    #pragma unroll
    for (int k = 3; k < 7; ++k) {
        ci = (ci + 1) & 0xFF;
        unsigned char s_ci = S_base[(int)ci * stride + lane];
        cj = (unsigned char)((cj + s_ci) & 0xFF);
        unsigned char s_cj = S_base[(int)cj * stride + lane];
        S_base[(int)ci * stride + lane] = s_cj;
        S_base[(int)cj * stride + lane] = s_ci;
    }
    *pi = ci; *pj = cj;
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

/* Pack float score (top 24 sortable bits) and 40-bit key into one uint64 for atomicMax.
 * Encoding: bits[63:40] = sortable_float >> 8, bits[39:0] = key & 0xFFFFFFFFFF.
 * The sortable transform (flip sign bit; flip all bits for negatives) makes IEEE754
 * floats compare correctly as unsigned integers, so atomicMax picks the best score
 * and its associated key in a single indivisible operation — no race window. */
__device__ __forceinline__ unsigned long long pack_score_key_dev(float score, uint64_t key)
{
    unsigned int u = __float_as_uint(score);
    unsigned int sortable = u ^ (-(u >> 31) | 0x80000000u);
    return ((unsigned long long)(sortable >> 8) << 40) | (key & 0xFFFFFFFFFFULL);
}

__device__ __forceinline__ float unpack_score_dev(unsigned long long packed)
{
    unsigned int sortable = (unsigned int)(packed >> 40) << 8;
    unsigned int bits = sortable ^ ((~sortable >> 31) | 0x80000000u);
    return __uint_as_float(bits);
}

__device__ __forceinline__ void update_best_packed(
    float score,
    uint64_t current_key,
    unsigned long long* __restrict__ dev_best_packed)
{
    atomicMax(dev_best_packed, pack_score_key_dev(score, current_key));
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
    const unsigned char * __restrict__ cipher_packs,
    const unsigned char * __restrict__ key5,
    uint32_t mi,
    int burst_pos)
{
    // Build KMI9 key = key5 || MI[4]
    unsigned char kmi9[9];
    compose_kmi9_dev(key5, mi, kmi9);
    // RC4 KSA with 9-byte key, then discard to drop_base
    RC4_CTX_DEV rc4;
    rc4_init_dev_len(&rc4, kmi9, 9);
    rc4_discard_dev(&rc4, RC4_DISCARD_BYTES + burst_pos * DMR_CIPHER_PACK_BYTES);
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
            memcpy(out_cipher_packs + p * DMR_CIPHER_PACK_BYTES + sf * 7, cipher7, 7);
        }
    }
}

__device__ __forceinline__ int extract_voice_dibits_dev(
    const unsigned char * __restrict__ bytes,
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
    const unsigned char * __restrict__ bytes,
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
    unsigned long long* __restrict__ dev_best_packed,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;
    int local_keys = 0;

    for (uint64_t i = tid; i < total_keys; i += stride) {
        if ((i & STOP_POLL_MASK) == 0 && dev_stop_requested[0]) return;

        uint64_t current_key = start_key + i;
        unsigned char key[5];
        key_to_5bytes_dev(current_key, key);

        float total_score = 0.0f;
        int processed_bursts = 0;

        /* Bit-frequency accumulators packed as uint16 pairs in uint32 registers.
         * bcnt_p[k] = (count[2k+1] << 16) | count[2k], max count = MAX_CONST_LINES = 256 < 65535.
         * 12 uint32 registers vs 24 int previously — saves 12 registers toward the
         * __launch_bounds__(256,2) target of ≤128 regs/thread. */
        unsigned int bcnt_p[12];
        #pragma unroll
        for (int k = 0; k < 12; k++) bcnt_p[k] = 0u;

/* Helpers: b in [0,23], two uint16 counters packed per uint32.
 * BCNT_ADD: adds bit (0 or 1) to counter b — branchless.
 * BCNT_GET: extracts counter b as float. */
#define BCNT_ADD(b, bit) bcnt_p[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define BCNT_GET(b)      ((float)((bcnt_p[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))

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
            rc4_discard_dev(&rc4, RC4_DISCARD_BYTES);

            for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                int p = sf_base + burst_pos;
                if (p >= payload_count) break;

                const unsigned char *cp = d_const_cipher_packs + (p * DMR_CIPHER_PACK_BYTES);
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

                /* Accumulate bit-frequency from sf=0 (p0 = first 3 decrypted bytes = C0+C1) */
                #pragma unroll
                for (int b = 0; b < 8; b++) BCNT_ADD(b,    (p0[0] >> (7-b)) & 1);
                #pragma unroll
                for (int b = 0; b < 8; b++) BCNT_ADD(8+b,  (p0[1] >> (7-b)) & 1);
                #pragma unroll
                for (int b = 0; b < 8; b++) BCNT_ADD(16+b, (p0[2] >> (7-b)) & 1);

                /* Per-burst absolute pruning: reject wrong keys as early as possible */
                if (enable_prune && processed_bursts >= 1 &&
                    total_score < d_abs_floor[processed_bursts]) {
                    goto next_key;
                }
            }

            /* Relative pruning at superframe boundary: can't beat current global best */
            if (enable_prune && processed_bursts >= 6) {
                float best_now = unpack_score_dev(__ldg(dev_best_packed));
                float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
                if (max_possible <= best_now) {
                    break;
                }
            }

            /* Chi²-floor pruning at superframe boundary.
             * E[chi²|wrong] = 6n, 3σ floor = 6n − 3·sqrt(48n).
             * Correct key: chi²/n ≈ 212 — never triggers this floor. */
            if (enable_prune && processed_bursts >= 12) {
                float half_n = (float)processed_bursts * 0.5f;
                float chi2_mid = 0.0f;
                #pragma unroll
                for (int b = 0; b < 24; b++) {
                    float dev = BCNT_GET(b) - half_n;
                    chi2_mid += dev * dev;
                }
                float chi2_floor = 6.0f * (float)processed_bursts
                                 - 3.0f * __fsqrt_rn(48.0f * (float)processed_bursts);
                if (chi2_mid < chi2_floor) goto next_key;
            }
        }

        if (processed_bursts == payload_count) {
            /* Add bit-frequency chi-squared component.
             * Wrong key: E[chi2/n] ≈ 6. Correct key: chi2/n ≈ 212 (Z≈335 with 126 payloads). */
            if (processed_bursts >= 6) {
                float half_n = (float)processed_bursts * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b = 0; b < 24; b++) {
                    float dev = BCNT_GET(b) - half_n;
                    chi2 += dev * dev;
                }
                total_score += chi2 / (float)processed_bursts;
            }
            update_best_packed(total_score, current_key, dev_best_packed);
        }

#undef BCNT_ADD
#undef BCNT_GET

        next_key:
        local_keys++;
        if (local_keys >= LOCAL_KEYS_FLUSH) {
            atomicAdd((unsigned long long int*)dev_keys_tested, LOCAL_KEYS_FLUSH);
            local_keys = 0;
        }
    }

    if (local_keys > 0) {
        atomicAdd((unsigned long long int*)dev_keys_tested, (unsigned long long)local_keys);
    }
}

/* =========================================================================
 * ILP-2 STRICT KERNEL — 2 keys per thread, 128 threads/block
 * S-boxes live in 64 KB dynamic shared memory (2 × 128 × 256 bytes/block).
 * __launch_bounds__(128, 2): compiler targets ≤2 active blocks/SM so that
 * the register file is partitioned for 256 threads, reducing spill pressure.
 * Hardware constraint: 2 × 64 KB = 128 KB shared per SM (Ada limit).
 * ========================================================================= */
__global__ __launch_bounds__(128, 2)
void bruteforce_kernel_strict_ilp2(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    uint32_t global_mi,
    unsigned long long* __restrict__ dev_keys_tested,
    unsigned long long* __restrict__ dev_best_packed,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid     = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride  = (uint64_t)gridDim.x * blockDim.x;
    /* Each thread processes 2 consecutive keys: base_key and base_key+1 */
    uint64_t stride2 = stride * 2ULL;
    extern __shared__ unsigned char sh_s[];
    /* Interleaved layout: S_base[byte_k * 128 + lane] — 4-way bank conflicts
     * vs 32-way for the contiguous layout (S[lane*256+k]). */
    const int lane = (int)threadIdx.x;
    constexpr int smem_stride = 128;
    unsigned char * const Sa = sh_s;               /* first 32 KB */
    unsigned char * const Sb = sh_s + 256 * 128;   /* next  32 KB */
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;
    int local_keys = 0;

    for (uint64_t i = tid * 2; i < total_keys; i += stride2) {
        if ((i & STOP_POLL_MASK) == 0 && dev_stop_requested[0]) return;

        /* --- Key A --- */
        uint64_t key_a = start_key + i;
        unsigned char ka[5];
        key_to_5bytes_dev(key_a, ka);

        /* --- Key B (next key) --- */
        uint64_t key_b = key_a + 1;
        if (key_b >= start_key + total_keys) key_b = key_a; /* last key: duplicate */
        unsigned char kb[5];
        key_to_5bytes_dev(key_b, kb);

        float score_a = 0.0f, score_b = 0.0f;
        int bursts_a = 0, bursts_b = 0;
        int pruned_a = 0, pruned_b = 0;

        KPA_PREFILTER_A(ka);
        KPA_PREFILTER_B(kb);

        /* Packed uint16 bit-freq accumulators — one set per key */
        unsigned int ba[12], bb[12];
        #pragma unroll
        for (int k = 0; k < 12; k++) { ba[k] = 0u; bb[k] = 0u; }

#define BA_ADD(b, bit) ba[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define BB_ADD(b, bit) bb[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define BA_GET(b) ((float)((ba[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))
#define BB_GET(b) ((float)((bb[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))

        for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
            /* --- MI for this superframe --- */
            uint32_t mi = global_mi;
            if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u))
                mi = d_const_mi[sf_base];

            /* --- KSA for key A and key B in parallel (interleaved) --- */
            unsigned char kmi_a[9], kmi_b[9];
            compose_kmi9_dev(ka, mi, kmi_a);
            compose_kmi9_dev(kb, mi, kmi_b);

            unsigned char ia, ja, ib, jb;
            rc4_ksa9_smem(Sa, smem_stride, lane, kmi_a, &ia, &ja);
            rc4_ksa9_smem(Sb, smem_stride, lane, kmi_b, &ib, &jb);
            rc4_discard_smem(Sa, smem_stride, lane, &ia, &ja, RC4_DISCARD_BYTES);
            rc4_discard_smem(Sb, smem_stride, lane, &ib, &jb, RC4_DISCARD_BYTES);

            for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                int p = sf_base + burst_pos;
                if (p >= payload_count) break;
                const unsigned char *cp = d_const_cipher_packs + (p * DMR_CIPHER_PACK_BYTES);

                /* --- Decrypt 3 sub-frames for A and B, interleaved --- */
                unsigned char pa0[3], pa1[3], pa2[3];
                unsigned char pb0[3], pb1[3], pb2[3];

                rc4_crypt_first3_skip4_smem(Sa, smem_stride, lane, &ia, &ja, cp + 0,  pa0);
                rc4_crypt_first3_skip4_smem(Sb, smem_stride, lane, &ib, &jb, cp + 0,  pb0);
                rc4_crypt_first3_skip4_smem(Sa, smem_stride, lane, &ia, &ja, cp + 7,  pa1);
                rc4_crypt_first3_skip4_smem(Sb, smem_stride, lane, &ib, &jb, cp + 7,  pb1);
                rc4_crypt_first3_skip4_smem(Sa, smem_stride, lane, &ia, &ja, cp + 14, pa2);
                rc4_crypt_first3_skip4_smem(Sb, smem_stride, lane, &ib, &jb, cp + 14, pb2);

                /* --- Hamming scores --- */
                int ha01 = __popc((unsigned int)(pa0[0]^pa1[0]))
                         + __popc((unsigned int)(pa0[1]^pa1[1]))
                         + __popc((unsigned int)(pa0[2]^pa1[2]));
                int ha12 = __popc((unsigned int)(pa1[0]^pa2[0]))
                         + __popc((unsigned int)(pa1[1]^pa2[1]))
                         + __popc((unsigned int)(pa1[2]^pa2[2]));
                int hb01 = __popc((unsigned int)(pb0[0]^pb1[0]))
                         + __popc((unsigned int)(pb0[1]^pb1[1]))
                         + __popc((unsigned int)(pb0[2]^pb1[2]));
                int hb12 = __popc((unsigned int)(pb1[0]^pb2[0]))
                         + __popc((unsigned int)(pb1[1]^pb2[1]))
                         + __popc((unsigned int)(pb1[2]^pb2[2]));

                if (!pruned_a) { score_a += (float)(48 - ha01 - ha12); bursts_a++; }
                if (!pruned_b) { score_b += (float)(48 - hb01 - hb12); bursts_b++; }

                /* Bit-freq accumulators */
                if (!pruned_a) {
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(b,    (pa0[0]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(8+b,  (pa0[1]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BA_ADD(16+b, (pa0[2]>>(7-b))&1);
                }
                if (!pruned_b) {
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(b,    (pb0[0]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(8+b,  (pb0[1]>>(7-b))&1);
                    #pragma unroll
                    for (int b=0;b<8;b++) BB_ADD(16+b, (pb0[2]>>(7-b))&1);
                }

                /* Per-burst floor — applied to both independently */
                if (enable_prune && bursts_a >= 1 && !pruned_a &&
                    score_a < d_abs_floor[bursts_a]) pruned_a = 1;
                if (enable_prune && bursts_b >= 1 && !pruned_b &&
                    score_b < d_abs_floor[bursts_b]) pruned_b = 1;
                if (pruned_a && pruned_b) break;
            }

            if (pruned_a && pruned_b) break;

            /* Chi2-floor at superframe boundary for both */
            if (enable_prune && bursts_a >= 6 && !pruned_a) {
                float hn = (float)bursts_a * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b=0;b<24;b++) { float d=BA_GET(b)-hn; chi2+=d*d; }
                float floor_v = 6.0f*(float)bursts_a - 3.0f*__fsqrt_rn(48.0f*(float)bursts_a);
                if (chi2 < floor_v) pruned_a = 1;
            }
            if (enable_prune && bursts_b >= 6 && !pruned_b) {
                float hn = (float)bursts_b * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b=0;b<24;b++) { float d=BB_GET(b)-hn; chi2+=d*d; }
                float floor_v = 6.0f*(float)bursts_b - 3.0f*__fsqrt_rn(48.0f*(float)bursts_b);
                if (chi2 < floor_v) pruned_b = 1;
            }
            if (pruned_a && pruned_b) break;
        }

#undef BA_ADD
#undef BB_ADD
#undef BA_GET
#undef BB_GET

        /* Chi2 final score boost for non-pruned keys */
        if (!pruned_a && bursts_a > 0) {
            float hn = (float)bursts_a * 0.5f;
            float chi2 = 0.0f;
            for (int b=0;b<12;b++) {
                float d0 = (float)(ba[b] & 0xFFFFu) - hn; chi2 += d0*d0;
                float d1 = (float)(ba[b] >> 16)     - hn; chi2 += d1*d1;
            }
            score_a += chi2 * 0.1f;
        }
        if (!pruned_b && bursts_b > 0) {
            float hn = (float)bursts_b * 0.5f;
            float chi2 = 0.0f;
            for (int b=0;b<12;b++) {
                float d0 = (float)(bb[b] & 0xFFFFu) - hn; chi2 += d0*d0;
                float d1 = (float)(bb[b] >> 16)     - hn; chi2 += d1*d1;
            }
            score_b += chi2 * 0.1f;
        }

        if (!pruned_a)                   update_best_packed(score_a, key_a, dev_best_packed);
        if (!pruned_b && key_b != key_a) update_best_packed(score_b, key_b, dev_best_packed);

        local_keys += (key_b != key_a) ? 2 : 1;
        if (local_keys >= 64) {
            atomicAdd(dev_keys_tested, 64ULL);
            local_keys -= 64;
        }
    }

    if (local_keys > 0)
        atomicAdd(dev_keys_tested, (unsigned long long)local_keys);
}

/* =========================================================================
 * HYTERA EP KERNEL — Hytera Enhanced Privacy (ALG=0x02, mode_policy=4)
 * Same scoring structure as bruteforce_kernel_strict but uses a fixed
 * 21-byte keystream per superframe instead of KMI9 RC4.
 * Kept in a separate kernel so the MOTOTRBO kernels carry zero overhead.
 * ========================================================================= */
__global__ __launch_bounds__(256, 2)
void bruteforce_kernel_hytera(
    uint64_t start_key,
    uint64_t total_keys,
    int payload_count,
    uint32_t global_mi,
    unsigned long long* __restrict__ dev_keys_tested,
    unsigned long long* __restrict__ dev_best_packed,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;
    int local_keys = 0;

    for (uint64_t i = tid; i < total_keys; i += stride) {
        if ((i & STOP_POLL_MASK) == 0 && dev_stop_requested[0]) return;

        uint64_t current_key = start_key + i;
        unsigned char key[5];
        key_to_5bytes_dev(current_key, key);

        float total_score = 0.0f;
        int processed_bursts = 0;

        unsigned int bcnt_p[12];
        #pragma unroll
        for (int k = 0; k < 12; k++) bcnt_p[k] = 0u;

#define HBCNT_ADD(b, bit) bcnt_p[(b)>>1] += ((unsigned int)(bit)) << (((b)&1u)<<4)
#define HBCNT_GET(b)      ((float)((bcnt_p[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))

        for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
            uint32_t line_mi = global_mi;
            if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u))
                line_mi = d_const_mi[sf_base];

            unsigned char ks[21];
            compute_hytera_ks_dev(key, line_mi, ks);

            for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                int p = sf_base + burst_pos;
                if (p >= payload_count) break;

                const unsigned char *cp = d_const_cipher_packs + (p * DMR_CIPHER_PACK_BYTES);
                unsigned char p0[3], p1[3], p2[3];
                p0[0]=cp[0]^ks[0];  p0[1]=cp[1]^ks[1];  p0[2]=cp[2]^ks[2];
                p1[0]=cp[7]^ks[7];  p1[1]=cp[8]^ks[8];  p1[2]=cp[9]^ks[9];
                p2[0]=cp[14]^ks[14];p2[1]=cp[15]^ks[15];p2[2]=cp[16]^ks[16];

                int h01 = __popc((unsigned int)(p0[0]^p1[0]))
                        + __popc((unsigned int)(p0[1]^p1[1]))
                        + __popc((unsigned int)(p0[2]^p1[2]));
                int h12 = __popc((unsigned int)(p1[0]^p2[0]))
                        + __popc((unsigned int)(p1[1]^p2[1]))
                        + __popc((unsigned int)(p1[2]^p2[2]));

                total_score += (float)(48 - h01 - h12);
                processed_bursts++;

                #pragma unroll
                for (int b = 0; b < 8; b++) HBCNT_ADD(b,    (p0[0] >> (7-b)) & 1);
                #pragma unroll
                for (int b = 0; b < 8; b++) HBCNT_ADD(8+b,  (p0[1] >> (7-b)) & 1);
                #pragma unroll
                for (int b = 0; b < 8; b++) HBCNT_ADD(16+b, (p0[2] >> (7-b)) & 1);

                if (enable_prune && processed_bursts >= 1 &&
                    total_score < d_abs_floor[processed_bursts]) {
                    goto hytera_next_key;
                }
            }

            if (enable_prune && processed_bursts >= 6) {
                float best_now = unpack_score_dev(__ldg(dev_best_packed));
                float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
                if (max_possible <= best_now) break;
            }

            if (enable_prune && processed_bursts >= 12) {
                float half_n = (float)processed_bursts * 0.5f;
                float chi2_mid = 0.0f;
                #pragma unroll
                for (int b = 0; b < 24; b++) {
                    float dev = HBCNT_GET(b) - half_n;
                    chi2_mid += dev * dev;
                }
                float chi2_floor = 6.0f * (float)processed_bursts
                                 - 3.0f * __fsqrt_rn(48.0f * (float)processed_bursts);
                if (chi2_mid < chi2_floor) goto hytera_next_key;
            }
        }

        if (processed_bursts == payload_count) {
            if (processed_bursts >= 6) {
                float half_n = (float)processed_bursts * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b = 0; b < 24; b++) {
                    float dev = HBCNT_GET(b) - half_n;
                    chi2 += dev * dev;
                }
                total_score += chi2 / (float)processed_bursts;
            }
            update_best_packed(total_score, current_key, dev_best_packed);
        }

#undef HBCNT_ADD
#undef HBCNT_GET

        hytera_next_key:
        local_keys++;
        if (local_keys >= LOCAL_KEYS_FLUSH) {
            atomicAdd((unsigned long long int*)dev_keys_tested, LOCAL_KEYS_FLUSH);
            local_keys = 0;
        }
    }

    if (local_keys > 0)
        atomicAdd((unsigned long long int*)dev_keys_tested, (unsigned long long)local_keys);
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
    unsigned long long* __restrict__ dev_best_packed,
    int* __restrict__ dev_stop_requested)
{
    uint64_t tid = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    const int enable_prune = (total_keys > (1ULL << 20)) ? 1 : 0;

    int local_keys = 0;

    for (uint64_t i = tid; i < total_keys; i += stride) {
        // Check stop every 1024 iterations to reduce global memory traffic
        if ((i & STOP_POLL_MASK) == 0 && dev_stop_requested[0]) return;
        uint64_t current_key = start_key + i;
        unsigned char key[5];
        key_to_5bytes_dev(current_key, key);
        float score = -3.402823e38f;
        // KMI9 path: payloads carry MI + RC4 algid, scored per-superframe
        if (mode_policy >= 2) {
            float total_score = 0.0f;
            int processed_bursts = 0;
            int pruned = 0;
            /* Bit-frequency accumulators: how often each of the 24 AMBE bits is 1 across all frames */
            int bcnt[24];
            #pragma unroll
            for (int b = 0; b < 24; b++) bcnt[b] = 0;
            int n_freq = 0;

            // Process in groups of 6 bursts (superframe)
            for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
                uint32_t line_mi = global_mi;
                if (sf_base < MAX_CONST_LINES && (d_const_meta_flags[sf_base] & 0x1u)) {
                    line_mi = d_const_mi[sf_base];
                }
                unsigned char kmi9[9];
                compose_kmi9_dev(key, line_mi, kmi9);
                RC4_CTX_DEV rc4;
                rc4_ksa9_dev(&rc4, kmi9);
                rc4_discard_dev(&rc4, RC4_DISCARD_BYTES);

                for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
                    int p = sf_base + burst_pos;
                    if (p >= payload_count) break;
                    const unsigned char *cipher_packs = d_const_cipher_packs + (p * DMR_CIPHER_PACK_BYTES);
                    unsigned char p0[3], p1[3], p2[3];
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 0,  p0);
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 7,  p1);
                    rc4_crypt_first3_skip4_dev(&rc4, cipher_packs + 14, p2);

                    int h01 = __popc((unsigned int)(p0[0] ^ p1[0]))
                            + __popc((unsigned int)(p0[1] ^ p1[1]))
                            + __popc((unsigned int)(p0[2] ^ p1[2]));
                    int h12 = __popc((unsigned int)(p1[0] ^ p2[0]))
                            + __popc((unsigned int)(p1[1] ^ p2[1]))
                            + __popc((unsigned int)(p1[2] ^ p2[2]));
                    total_score += (float)(48 - h01 - h12);
                    processed_bursts++;

                    /* Accumulate bit-frequency from sf=0 */
                    #pragma unroll
                    for (int b = 0; b < 8; b++) bcnt[b]    += (p0[0] >> (7-b)) & 1;
                    #pragma unroll
                    for (int b = 0; b < 8; b++) bcnt[8+b]  += (p0[1] >> (7-b)) & 1;
                    #pragma unroll
                    for (int b = 0; b < 8; b++) bcnt[16+b] += (p0[2] >> (7-b)) & 1;
                    n_freq++;

                    if (enable_prune && ((processed_bursts & 0x1) == 0)) {
                        float best_now = unpack_score_dev(__ldg(dev_best_packed));
                        float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
                        if (max_possible <= best_now) {
                            pruned = 1;
                            break;
                        }
                    }
                }
                if (pruned) break;

                /* Chi²-floor at superframe boundary (same logic as strict kernel) */
                if (enable_prune && n_freq >= 12) {
                    float half_n = (float)n_freq * 0.5f;
                    float chi2_mid = 0.0f;
                    #pragma unroll
                    for (int b = 0; b < 24; b++) {
                        float dev = (float)bcnt[b] - half_n;
                        chi2_mid += dev * dev;
                    }
                    float chi2_floor = 6.0f * (float)n_freq
                                     - 3.0f * __fsqrt_rn(48.0f * (float)n_freq);
                    if (chi2_mid < chi2_floor) { pruned = 1; break; }
                }
            }

            if (!pruned && n_freq >= 6) {
                float half_n = (float)n_freq * 0.5f;
                float chi2 = 0.0f;
                #pragma unroll
                for (int b = 0; b < 24; b++) {
                    float dev = (float)bcnt[b] - half_n;
                    chi2 += dev * dev;
                }
                total_score += chi2 / (float)n_freq;
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
                rc4_discard_dev(&rc4_cont, RC4_DISCARD_BYTES);
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
                    if (use_drop256) rc4_discard_dev(&rc4, RC4_DISCARD_BYTES);
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

                /* F) Nibble entropy (valid AMBE ~3.0-3.8 bits/nibble; random ~4.0) */
                {
                    int nhist[16];
                    #pragma unroll
                    for (int ni = 0; ni < 16; ni++) nhist[ni] = 0;
                    for (int bx = 0; bx < bytes_to_test; ++bx) {
                        nhist[out[bx] & 0x0F]++;
                        nhist[(out[bx] >> 4) & 0x0F]++;
                    }
                    {
                        float entropy = 0.0f;
                        float inv_total = 1.0f / (float)(bytes_to_test * 2);
                        #pragma unroll
                        for (int ni = 0; ni < 16; ni++) {
                            if (nhist[ni] > 0) {
                                float p = (float)nhist[ni] * inv_total;
                                entropy -= p * __log2f(p);
                            }
                        }
                        /* Reward entropy below max (4.0): bonus = (4.0 - entropy) * 30 */
                        float bonus = 4.0f - entropy;
                        if (bonus > 0.0f) local_score += bonus * 30.0f;
                    }
                }

                /* G) Silence frame bonus (many 0x00/0xFF bytes → valid AMBE silence) */
                {
                    int silence_count = 0;
                    for (int bx = 0; bx < bytes_to_test; ++bx) {
                        if (out[bx] == 0x00 || out[bx] == 0xFF) silence_count++;
                    }
                    if (silence_count > bytes_to_test / 2) {
                        local_score += (float)silence_count * 5.0f;
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

        update_best_packed(score, current_key, dev_best_packed);

        local_keys++;
        if (local_keys >= LOCAL_KEYS_FLUSH) {
            atomicAdd((unsigned long long int*)dev_keys_tested, LOCAL_KEYS_FLUSH);
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
static int is_hytera_ep_alg_host(uint8_t alg);
static void compute_hytera_ks_cpu(const unsigned char key5[5], uint32_t mi, unsigned char ks_out[21]);

typedef struct {
    int threads_per_block;
    int blocks_per_sm;
    int chunk_mult;
} CudaLaunchProfile;

/* Bump this when the kernel changes enough to invalidate old tuning profiles.
 * Stale .cfg files (different VER) are deleted automatically on load. */
#define CUDA_PROFILE_VERSION 1

static void build_tune_profile_path(const cudaDeviceProp *prop, int strict_mode, char *out_path, size_t out_len)
{
    /* Include SM count so GPUs of the same compute capability but different
     * sizes (e.g. RTX 3050 Ti vs RTX 3080, both sm_86) get separate profiles. */
    snprintf(out_path, out_len,
             "bin\\cuda_tune_sm%d%d_sm%d_mode%d.cfg",
             prop->major,
             prop->minor,
             prop->multiProcessorCount,
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

    {
        int ver = 0;
        if (fscanf(fp, "VER=%d\n", &ver) != 1 || ver != CUDA_PROFILE_VERSION) {
            fclose(fp);
            plat_delete_file(path); /* stale profile — delete so autotune re-runs */
            return 0;
        }
    }
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
    /* Ensure bin/ directory exists before writing (not tracked by git). */
    plat_mkdir("bin");
    fp = fopen(path, "wt");
    if (fp == NULL) return;

    fprintf(fp, "VER=%d\nTPB=%d\nBPSM=%d\nCHUNK=%d\n",
            CUDA_PROFILE_VERSION,
            profile->threads_per_block,
            profile->blocks_per_sm,
            profile->chunk_mult);
    fclose(fp);
}

/* Forward declaration — defined after scoring helpers, called from cuda_launcher_thread */
static void run_dictionary_phase(BruteforceEngine *engine);

/* CpuWorkerCtx and forward declarations needed by cpu_4way_worker_proc / cuda_launcher_thread */
typedef struct {
    BruteforceEngine *engine;
    uint64_t start_key;
    uint64_t end_key;
    int worker_index;
    const unsigned char *cipher_packs; /* [payload_count*21], precomputed key-independent data */
    int payload_count;
    int mode_policy;
    volatile uint64_t current_k; /* updated every ~4K iterations for CPU-path checkpointing */
} CpuWorkerCtx;

static void key_to_5bytes_cpu(uint64_t key, unsigned char out[5]);
static double score_candidate_host(
    const PayloadSet *payloads, int sample_lines,
    int sample_bytes, const unsigned char key[5]);

/* ─── Identity table for AVX2 S-box initialisation ──────────────────────── */
static const unsigned char rc4_id256[RC4_SBOX_SIZE] = {
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
     32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
     48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
     64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
     80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
     96, 97, 98, 99,100,101,102,103,104,105,106,107,108,109,110,111,
    112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
    128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
    144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
    160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
    176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
    192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
    208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
    224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
    240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
};

/* ─── 4-way interleaved RC4 KSA (9-byte key) ────────────────────────────── *
 * Runs four independent RC4 key-scheduling passes in the same loop body so
 * the CPU out-of-order engine overlaps independent load/store chains.
 * AVX2 is used for the identity S-box initialisation (8 × 256-bit stores
 * per S-box instead of 256 byte stores) when compiled with /arch:AVX2.    */
static void rc4_ksa9_4way(
    unsigned char Sa[RC4_SBOX_SIZE], unsigned char Sb[RC4_SBOX_SIZE],
    unsigned char Sc[RC4_SBOX_SIZE], unsigned char Sd[RC4_SBOX_SIZE],
    const unsigned char ka[9], const unsigned char kb[9],
    const unsigned char kc[9], const unsigned char kd[9])
{
    int i;
    unsigned char t;
    unsigned ja, jb, jc, jd;

    /* S-box init: identity permutation */
#if defined(__AVX2__)
    for (i = 0; i < 8; i++) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(rc4_id256 + i * 32));
        _mm256_storeu_si256((__m256i *)(Sa + i * 32), v);
        _mm256_storeu_si256((__m256i *)(Sb + i * 32), v);
        _mm256_storeu_si256((__m256i *)(Sc + i * 32), v);
        _mm256_storeu_si256((__m256i *)(Sd + i * 32), v);
    }
#else
    for (i = 0; i < RC4_SBOX_SIZE; i++)
        Sa[i] = Sb[i] = Sc[i] = Sd[i] = (unsigned char)i;
#endif

    /* 4-way interleaved KSA — four independent j-chains */
    ja = jb = jc = jd = 0u;
    for (i = 0; i < RC4_SBOX_SIZE; i++) {
        int ki = i % 9;
        ja = (ja + Sa[i] + ka[ki]) & 0xFFu;
        jb = (jb + Sb[i] + kb[ki]) & 0xFFu;
        jc = (jc + Sc[i] + kc[ki]) & 0xFFu;
        jd = (jd + Sd[i] + kd[ki]) & 0xFFu;
        t = Sa[i]; Sa[i] = Sa[ja]; Sa[ja] = t;
        t = Sb[i]; Sb[i] = Sb[jb]; Sb[jb] = t;
        t = Sc[i]; Sc[i] = Sc[jc]; Sc[jc] = t;
        t = Sd[i]; Sd[i] = Sd[jd]; Sd[jd] = t;
    }
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

/* ─── 4-way AVX2 CPU assist worker ──────────────────────────────────────── *
 * Processes 4 candidate keys per outer loop iteration using:
 *   • AVX2 S-box init (8 × 256-bit stores per box, vs 256 byte stores)
 *   • 4-way interleaved KSA — lets the CPU OOO engine overlap 4 independent
 *     scatter/gather chains, roughly doubling effective IPC on the KSA loop
 *   • Per-superframe KSA: one KSA per 6-burst superframe (instead of 6),
 *     then continuous PRGA across all bursts — 6× fewer KSA calls
 *   • P-core pinning via plat_thread_set_affinity(worker_index)
 *
 * Scores keys using the same inter-frame Hamming metric as the GPU kernel
 * (score_burst = 48 − HD(sf0,sf1) − HD(sf1,sf2)) so GPU/CPU best_score are
 * directly comparable.
 *
 * Falls back to scalar score_candidate_host() for legacy mode (mode_policy<2)
 * or when cipher_packs is NULL.
 *
 * Does NOT touch finished_threads/search_completed/running — the GPU thread
 * owns those. */
static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL cpu_4way_worker_proc(void *arg)
{
    CpuWorkerCtx *ctx = (CpuWorkerCtx *)arg;
    BruteforceEngine *engine = ctx->engine;
    const unsigned char *cipher_packs = ctx->cipher_packs;
    int pcount = ctx->payload_count;
    uint64_t local_count = 0;
    uint64_t k;
    int b;

    plat_thread_set_affinity(ctx->worker_index);

    if (ctx->mode_policy >= 2 && cipher_packs != NULL && pcount > 0) {
        /* ── Correct pipeline: 4-way KSA + per-superframe PRGA ── */
        k = ctx->start_key;
        while (k <= ctx->end_key) {
            int batch, sf_base;
            unsigned char key5[4][5];
            double scores[4];
            int pruned[4], all_pruned_cpu, processed_bursts_cpu;

            /* Stop/pause check every 4096 keys */
            if ((local_count & 0xFFFu) == 0) {
                if (plat_atomic32_load(&engine->stop_requested) != 0) break;
                if (plat_atomic32_load(&engine->paused) != 0) {
                    plat_event_wait(&engine->pause_event);
                    if (plat_atomic32_load(&engine->stop_requested) != 0) break;
                }
            }

            /* Batch up to 4 keys; pad unused slots with copies of key5[0] */
            batch = (ctx->end_key - k >= 3) ? 4 : (int)(ctx->end_key - k + 1);
            key_to_5bytes_cpu(k,                           key5[0]);
            key_to_5bytes_cpu(k + (batch > 1 ? 1u : 0u),  key5[1]);
            key_to_5bytes_cpu(k + (batch > 2 ? 2u : 0u),  key5[2]);
            key_to_5bytes_cpu(k + (batch > 3 ? 3u : 0u),  key5[3]);

            scores[0] = scores[1] = scores[2] = scores[3] = 0.0;

            /* Pruning state: mark pad slots as already-pruned */
            {
                int _b;
                for (_b = 0; _b < 4; _b++) pruned[_b] = (_b >= batch) ? 1 : 0;
            }
            processed_bursts_cpu = 0;
            all_pruned_cpu = (batch <= 0);

            /* Iterate over superframes (6 consecutive bursts share the same MI) */
            sf_base = 0;
            while (sf_base < pcount && !all_pruned_cpu) {
                int n_bursts = pcount - sf_base;
                unsigned char Sa[RC4_SBOX_SIZE], Sb[RC4_SBOX_SIZE], Sc[RC4_SBOX_SIZE], Sd[RC4_SBOX_SIZE];
                unsigned ia, ja, ib, jb, ic, jc, id, jd;
                unsigned char _t;
                int n, burst, sf;
                uint32_t mi;
                unsigned char hytera_ks[4][21];

                if (n_bursts > 6) n_bursts = 6;

                /* Same MI for all bursts in the superframe */
                mi = engine->payloads->items[sf_base].has_mi
                     ? engine->payloads->items[sf_base].mi
                     : engine->payloads->global_mi;

                if (ctx->mode_policy == 4) {
                    /* Hytera EP: pre-compute 21-byte keystream for each of the 4 keys */
                    for (b = 0; b < 4; b++)
                        compute_hytera_ks_cpu(key5[b], mi, hytera_ks[b]);
                    ia = ja = ib = jb = ic = jc = id = jd = 0u; /* unused */
                } else {
                    /* KMI9 path: one 4-way KSA + discard per superframe */
                    unsigned char kmi9[4][9];
                    for (b = 0; b < 4; b++) {
                        kmi9[b][0] = key5[b][0]; kmi9[b][1] = key5[b][1];
                        kmi9[b][2] = key5[b][2]; kmi9[b][3] = key5[b][3];
                        kmi9[b][4] = key5[b][4];
                        kmi9[b][5] = (unsigned char)((mi >> 24) & 0xFFu);
                        kmi9[b][6] = (unsigned char)((mi >> 16) & 0xFFu);
                        kmi9[b][7] = (unsigned char)((mi >>  8) & 0xFFu);
                        kmi9[b][8] = (unsigned char)( mi        & 0xFFu);
                    }
                    rc4_ksa9_4way(Sa, Sb, Sc, Sd, kmi9[0], kmi9[1], kmi9[2], kmi9[3]);
                    ia = ja = ib = jb = ic = jc = id = jd = 0u;
                    for (n = 0; n < RC4_DISCARD_BYTES; n++) {
                        ia=(ia+1u)&0xFFu; ja=(ja+Sa[ia])&0xFFu;
                        _t=Sa[ia]; Sa[ia]=Sa[ja]; Sa[ja]=_t;
                        ib=(ib+1u)&0xFFu; jb=(jb+Sb[ib])&0xFFu;
                        _t=Sb[ib]; Sb[ib]=Sb[jb]; Sb[jb]=_t;
                        ic=(ic+1u)&0xFFu; jc=(jc+Sc[ic])&0xFFu;
                        _t=Sc[ic]; Sc[ic]=Sc[jc]; Sc[jc]=_t;
                        id=(id+1u)&0xFFu; jd=(jd+Sd[id])&0xFFu;
                        _t=Sd[id]; Sd[id]=Sd[jd]; Sd[jd]=_t;
                    }
                }

                /* Continuous PRGA across all bursts in the superframe (MOTOTRBO path).
                 * Burst b uses keystream positions 257+b*21 .. 277+b*21,
                 * identical to rc4_init(kmi9) + rc4_discard(256+b*21) per burst. */
                for (burst = 0; burst < n_bursts; burst++) {
                    int burst_idx = sf_base + burst;
                    const unsigned char *cp_base = cipher_packs + burst_idx * DMR_CIPHER_PACK_BYTES;
                    unsigned char dec24[4][3][24]; /* [key][sf][bit] */

                    for (sf = 0; sf < 3; sf++) {
                        const unsigned char *cp = cp_base + sf * 7;
                        unsigned char pa[7], pb[7], pc[7], pd[7];
                        int i;

                        if (ctx->mode_policy == 4) {
                            /* Hytera EP: XOR cipher with precomputed keystream (same for all bursts) */
                            for (n = 0; n < 7; n++) {
                                pa[n] = cp[n] ^ hytera_ks[0][sf*7+n];
                                pb[n] = cp[n] ^ hytera_ks[1][sf*7+n];
                                pc[n] = cp[n] ^ hytera_ks[2][sf*7+n];
                                pd[n] = cp[n] ^ hytera_ks[3][sf*7+n];
                            }
                        } else {
                            /* MOTOTRBO: 7 bytes of keystream per sub-frame (4-way PRGA) */
                            for (n = 0; n < 7; n++) {
                                ia=(ia+1u)&0xFFu; ja=(ja+Sa[ia])&0xFFu;
                                _t=Sa[ia]; Sa[ia]=Sa[ja]; Sa[ja]=_t;
                                pa[n] = cp[n] ^ Sa[(Sa[ia]+Sa[ja])&0xFFu];

                                ib=(ib+1u)&0xFFu; jb=(jb+Sb[ib])&0xFFu;
                                _t=Sb[ib]; Sb[ib]=Sb[jb]; Sb[jb]=_t;
                                pb[n] = cp[n] ^ Sb[(Sb[ib]+Sb[jb])&0xFFu];

                                ic=(ic+1u)&0xFFu; jc=(jc+Sc[ic])&0xFFu;
                                _t=Sc[ic]; Sc[ic]=Sc[jc]; Sc[jc]=_t;
                                pc[n] = cp[n] ^ Sc[(Sc[ic]+Sc[jc])&0xFFu];

                                id=(id+1u)&0xFFu; jd=(jd+Sd[id])&0xFFu;
                                _t=Sd[id]; Sd[id]=Sd[jd]; Sd[jd]=_t;
                                pd[n] = cp[n] ^ Sd[(Sd[id]+Sd[jd])&0xFFu];
                            }
                        }

                        /* Unpack first 24 bits of each 7-byte plaintext block */
                        for (i = 0; i < 24; i++) {
                            int sh = 7 - (i & 7);
                            dec24[0][sf][i] = (pa[i>>3] >> sh) & 1u;
                            dec24[1][sf][i] = (pb[i>>3] >> sh) & 1u;
                            dec24[2][sf][i] = (pc[i>>3] >> sh) & 1u;
                            dec24[3][sf][i] = (pd[i>>3] >> sh) & 1u;
                        }
                    } /* sf */

                    /* Hamming score per key: burst_score = 48 − HD(sf0,sf1) − HD(sf1,sf2)
                     * Matches GPU kernel score_burst_correct_dev(). */
                    for (b = 0; b < 4; b++) {
                        int h01 = 0, h12 = 0, i;
                        if (pruned[b]) continue;
                        for (i = 0; i < 24; i++) {
                            h01 += dec24[b][0][i] ^ dec24[b][1][i];
                            h12 += dec24[b][1][i] ^ dec24[b][2][i];
                        }
                        scores[b] += (double)(48 - h01 - h12);
                    }

                    /* Per-burst absolute floor (mirrors GPU kernel d_abs_floor[k]).
                     * floor[k] = 33k − 2σ_k, σ_k = 3.46·√k.
                     * Rejects >99.9997% of wrong keys from burst 1 onward. */
                    {
                        float fv;
                        processed_bursts_cpu++;
                        fv = 33.0f * (float)processed_bursts_cpu
                           - 6.92f * sqrtf((float)processed_bursts_cpu);
                        all_pruned_cpu = 1;
                        for (b = 0; b < 4; b++) {
                            if (!pruned[b]) {
                                if ((float)scores[b] < fv)
                                    pruned[b] = 1;
                                else
                                    all_pruned_cpu = 0;
                            }
                        }
                    }
                    if (all_pruned_cpu) break;
                } /* burst */

                sf_base += n_bursts;
            } /* superframe */

            /* Update global best only for keys that survived all pruning checks */
            for (b = 0; b < batch; b++) {
                if (pruned[b]) continue;
                plat_mutex_lock(&engine->lock);
                if (scores[b] > engine->best_score) {
                    engine->best_score = scores[b];
                    engine->best_key   = k + (uint64_t)b;
                }
                plat_mutex_unlock(&engine->lock);
            }

            local_count += (uint64_t)batch;
            k           += (uint64_t)batch;
            if ((local_count & STOP_POLL_MASK) == 0)
                plat_atomic64_add(&engine->keys_tested, 1024LL);
        }
    } else {
        /* ── Fallback: scalar scoring for legacy mode (mode_policy < 2) ── */
        for (k = ctx->start_key; k <= ctx->end_key; ++k) {
            unsigned char key_bytes[5];
            double score;

            if ((local_count & 0xFFFu) == 0) {
                if (plat_atomic32_load(&engine->stop_requested) != 0) break;
                if (plat_atomic32_load(&engine->paused) != 0) {
                    plat_event_wait(&engine->pause_event);
                    if (plat_atomic32_load(&engine->stop_requested) != 0) break;
                }
            }

            key_to_5bytes_cpu(k, key_bytes);
            score = score_candidate_host(engine->payloads, engine->cfg.sample_lines,
                                         engine->cfg.sample_bytes, key_bytes);

            plat_mutex_lock(&engine->lock);
            if (score > engine->best_score) {
                engine->best_score = score;
                engine->best_key   = k;
            }
            plat_mutex_unlock(&engine->lock);

            local_count++;
            if ((local_count & STOP_POLL_MASK) == 0)
                plat_atomic64_add(&engine->keys_tested, 1024LL);

            if (k == ctx->end_key) break;
        }
    }

    if ((local_count & STOP_POLL_MASK) != 0)
        plat_atomic64_add(&engine->keys_tested, (int64_t)(local_count & STOP_POLL_MASK));

    PLAT_THREAD_RETURN;
}

static float host_unpack_score(unsigned long long packed)
{
    unsigned int sortable = (unsigned int)(packed >> 40) << 8;
    unsigned int bits = sortable ^ ((~sortable >> 31) | 0x80000000u);
    float f; memcpy(&f, &bits, sizeof(f)); return f;
}

static unsigned long long host_unpack_key(unsigned long long packed)
{
    return packed & 0xFFFFFFFFFFULL;
}

static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL cuda_launcher_thread(void *arg)
{
    BruteforceEngine *engine = (BruteforceEngine *)arg;
    unsigned char *host_payload_flat = NULL;
    unsigned int host_mi[MAX_CONST_LINES];
    unsigned char host_algid[MAX_CONST_LINES];
    unsigned char host_meta_flags[MAX_CONST_LINES];
    unsigned long long *d_keys_tested = NULL;
    unsigned long long *d_best_packed = NULL;
    int *d_stop_requested = NULL;
    cudaStream_t compute_stream = NULL;
    cudaStream_t compute_stream2 = NULL;  /* double-buffer stream */
    cudaStream_t query_stream = NULL;
    /* Pinned host memory for truly async D2H polling */
    struct { unsigned long long keys_tested; unsigned long long best_packed; } *h_poll = NULL;
    cudaError_t cu_err;
    uint64_t total_keys, chunk_size, offset;
    int threadsPerBlock, blocksPerGrid;
    int max_payload_len = 0;
    int bytes_per_line = 27;
    size_t payload_bytes = 0;
    int cuda_sm = 0;
    int use_ilp2 = 0;
    CpuWorkerCtx *cpu_assist_ctxs = NULL;
    plat_thread_t *cpu_assist_handles = NULL;
    int n_cpu_assist = 0;
    unsigned long long last_gpu_kt = 0; /* GPU keys_tested at last poll — for delta-add */
    cudaDeviceProp prop;

    int payload_limit = engine->cfg.sample_lines;
    uint8_t has_global_mi = engine->payloads->has_global_mi ? 1u : 0u;
    uint8_t has_global_algid = engine->payloads->has_global_algid ? 1u : 0u;
    uint8_t global_algid = engine->payloads->global_algid;
    uint32_t global_mi = engine->payloads->global_mi;
    int mode_policy = 0;

    plat_atomic32_store(&engine->cuda_stage, 0);
    plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());

    /* Dictionary phase: test common/default keys before GPU scan */
    run_dictionary_phase(engine);
    if (plat_atomic32_load(&engine->stop_requested) != 0) goto cleanup;

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
    unsigned char host_cipher_packs[MAX_CONST_LINES * DMR_CIPHER_PACK_BYTES];
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
        int mi_rc4_lines = 0, mi_hytera_lines = 0;
        for (int i = 0; i < payload_limit; ++i) {
            int has_mi = (host_meta_flags[i] & 0x1u) != 0;
            uint8_t alg = (host_meta_flags[i] & 0x2u) ? host_algid[i] : global_algid;
            if (has_mi && is_rc4_alg_host(alg))    mi_rc4_lines++;
            if (has_mi && is_hytera_ep_alg_host(alg)) mi_hytera_lines++;
        }
        /* Hytera EP takes priority: if ≥90% of payloads have MI + ALG=0x02, use mode 4 */
        if (payload_limit > 0 && mi_hytera_lines * 10 >= payload_limit * 9) {
            mode_policy = 4;
        } else if (payload_limit > 0 && mi_rc4_lines * 10 >= payload_limit * 9) {
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
    /* NOTE: the kernel assumes payload[0] is burst_pos=0 of a superframe. A misaligned
     * .bin file will produce wrong drop values and garbage scores. Validating alignment
     * on the host (or adding a burst_pos_start field to PayloadItem) would fix this. */
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

    /* Precompute absolute screening thresholds (hashcat-style early reject) */
    {
        float host_abs_floor[MAX_CONST_LINES + 1];
        host_abs_floor[0] = -FLT_MAX;
        for (int k = 1; k <= payload_limit; ++k) {
            /* Wrong key:   mean=24*k,  sigma≈3.46*sqrt(k)
             * Correct key: mean≈44*k  (h01≈2, h12≈2 → score≈44 per burst)
             * Floor at 33*k - 2*sigma: rejects ~99.9997% of wrong keys at k=6.
             * Margin to correct-key mean: +11 per burst → safe from false negatives. */
            float sigma_k = 3.46f * sqrtf((float)k);
            host_abs_floor[k] = 33.0f * (float)k - 2.0f * sigma_k;
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

    cu_err = cudaMalloc(&d_best_packed, sizeof(unsigned long long));
    if (cu_err != cudaSuccess) {
        snprintf(engine->cuda_error, sizeof(engine->cuda_error), "cudaMalloc best_packed: %s", cudaGetErrorString(cu_err));
        goto cleanup;
    }
    CUDA_CHECK(cudaMemset(d_best_packed, 0, sizeof(unsigned long long)), "cudaMemset best_packed");

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

    plat_atomic32_store(&engine->cuda_sm_count, prop.multiProcessorCount);
    plat_atomic32_store(&engine->cuda_compute_major, prop.major);
    plat_atomic32_store(&engine->cuda_compute_minor, prop.minor);

    /* ILP-2 kernel: 2 keys/thread, 128 tpb, interleaved RC4 chains.
     * ILP-2: safe on all Turing+ (sm_75+); the double S-box concern was for
     * legacy mode. KMI9 path (mode_policy>=2) uses one S-box per thread. */
    cuda_sm = prop.major * 10 + prop.minor;
    /* ILP-2 only for MOTOTRBO (mode 2/3): Hytera EP has its own kernel (no smem S-box needed) */
    use_ilp2 = (mode_policy >= 2 && mode_policy != 4) && (cuda_sm >= 75);
    if (use_ilp2) {
        cudaFuncSetAttribute(bruteforce_kernel_strict_ilp2,
            cudaFuncAttributeMaxDynamicSharedMemorySize, 65536);
    }

    /* KPA silence pre-filter activation — must come after use_ilp2 is set.
     * Disabled for ILP-2: its main loop uses shared-memory RC4 (~10-20x faster than
     * local memory), so the KPA's local-memory KSA9 costs more than abs-floor saves.
     * Disabled for Hytera EP (mode_policy==4): KPA uses KMI9 algorithm. */
    {
        int n_sil = (!use_ilp2 && mode_policy != 4) ? (int)engine->payloads->n_silence : 0;
        uint16_t host_sil_idx[64];
        int n_sil_valid = 0;
        for (int k = 0; k < n_sil && k < 64; k++) {
            if (engine->payloads->silence_indices[k] < (uint16_t)payload_limit)
                host_sil_idx[n_sil_valid++] = engine->payloads->silence_indices[k];
        }
        cu_err = cudaMemcpyToSymbol(d_const_silence_idx, host_sil_idx,
                                    (size_t)n_sil_valid * sizeof(uint16_t));
        if (cu_err != cudaSuccess) {
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                     "cudaMemcpyToSymbol(silence_idx): %s", cudaGetErrorString(cu_err));
            goto cleanup;
        }
        cu_err = cudaMemcpyToSymbol(d_const_n_silence, &n_sil_valid, sizeof(int));
        if (cu_err != cudaSuccess) {
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
                     "cudaMemcpyToSymbol(n_silence): %s", cudaGetErrorString(cu_err));
            goto cleanup;
        }
    }

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
    /* Second compute stream for double-buffered dispatch */
    CUDA_CHECK(cudaStreamCreateWithFlags(&compute_stream2, cudaStreamNonBlocking), "cudaStreamCreate compute2");
    /* Pinned host buffer for async D2H transfers in the polling loop */
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
        plat_atomic32_store(&engine->cuda_profile_cached, profile_loaded ? 1 : 0);

        if (!profile_loaded) {
            /* Auto-tune: find the best TPB/BPSM/CHUNK for this specific GPU.
             * Always runs on first launch (no cached profile); uses at most
             * tune_budget_ms and only tune_keys keys -- independent of the
             * actual search keyspace so it is fast even for full 40-bit runs. */
            int tpb_candidates[2] = { 128, 256 };
            int bpsm_candidates_strict[4] = { 16, 20, 24, 32 };
            int bpsm_candidates_legacy[4] = {  8, 10, 12, 16 };
            int chunk_candidates_strict[3] = { 128, 192, 256 };
            int chunk_candidates_legacy[3] = {  64,  96, 128 };
            int bpsm_count = 4;
            int chunk_count = 3;
            uint64_t tune_keys = (1ULL << 18); /* 262144 keys — enough for timing */
            float best_kps = -1.0f;
            cudaEvent_t ev_start = NULL;
            cudaEvent_t ev_stop = NULL;
            uint64_t tune_start_ms = plat_ticks_ms();
            const uint64_t tune_budget_ms = 2500ULL; /* 2.5 s max */
            int skip_benchmark = 0; /* always benchmark when no profile cached */

            plat_atomic32_store(&engine->cuda_stage, 1);

            if (cudaEventCreate(&ev_start) != cudaSuccess ||
                cudaEventCreate(&ev_stop)  != cudaSuccess) {
                skip_benchmark = 1;
            }

            for (int ti = 0; ti < 2 && !skip_benchmark; ++ti) {
                int tpb = tpb_candidates[ti];
                if (tpb > prop.maxThreadsPerBlock || (tpb & 31) != 0) continue;
                if (use_ilp2 && tpb != 128) continue; /* ILP-2 fixed to 128 tpb */

                for (int bi = 0; bi < bpsm_count; ++bi) {
                    if (plat_ticks_ms() - tune_start_ms >= tune_budget_ms) {
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
                        if (cand_chunk == 0) continue;

                        cudaMemsetAsync(d_keys_tested, 0, sizeof(unsigned long long), compute_stream);
                        cudaMemsetAsync(d_best_packed, 0, sizeof(unsigned long long), compute_stream);
                        cudaMemsetAsync(d_stop_requested, 0, sizeof(int), compute_stream);
                        cudaStreamSynchronize(compute_stream);

                        cudaEventRecord(ev_start, compute_stream);
                        while (tuned < tune_keys) {
                            if (plat_atomic32_load(&engine->stop_requested) != 0) {
                                skip_benchmark = 1;
                                break;
                            }
                            if (plat_ticks_ms() - tune_start_ms >= tune_budget_ms) {
                                skip_benchmark = 1;
                                break;
                            }
                            uint64_t cur = cand_chunk;
                            if (tuned + cur > tune_keys) cur = tune_keys - tuned;

                            if (mode_policy == 4) {
                                bruteforce_kernel_hytera<<<blocks, tpb, 0, compute_stream>>>(
                                    engine->cfg.start_key + tuned,
                                    cur,
                                    payload_limit,
                                    global_mi,
                                    d_keys_tested,
                                    d_best_packed,
                                    d_stop_requested
                                );
                            } else if (use_ilp2) {
                                bruteforce_kernel_strict_ilp2<<<blocks, 128, 0, compute_stream>>>(
                                    engine->cfg.start_key + tuned,
                                    cur,
                                    payload_limit,
                                    global_mi,
                                    d_keys_tested,
                                    d_best_packed,
                                    d_stop_requested
                                );
                            } else if (strict_mode) {
                                bruteforce_kernel_strict<<<blocks, tpb, 0, compute_stream>>>(
                                    engine->cfg.start_key + tuned,
                                    cur,
                                    payload_limit,
                                    global_mi,
                                    d_keys_tested,
                                    d_best_packed,
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
                                    d_best_packed,
                                    d_stop_requested
                                );
                            }
                            cu_err = cudaGetLastError();
                            if (cu_err != cudaSuccess) {
                                ms = 0.0f;
                                break;
                            }
                            tuned += cur;
                            plat_atomic64_store(&engine->keys_tested, (int64_t)tuned);
                            plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());
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

        /* ILP-2 kernel is __launch_bounds__(128,4) -- actual tpb is always 128.
         * Report 128 in the status bar so the user sees the real value. */
        plat_atomic32_store(&engine->cuda_tpb, use_ilp2 ? 128 : profile.threads_per_block);
        plat_atomic32_store(&engine->cuda_bpsm, profile.blocks_per_sm);
        plat_atomic32_store(&engine->cuda_chunk_mult, profile.chunk_mult);

        threadsPerBlock = profile.threads_per_block;
        if (threadsPerBlock < 64) threadsPerBlock = 64;
        if (threadsPerBlock > prop.maxThreadsPerBlock) threadsPerBlock = prop.maxThreadsPerBlock;
        if ((threadsPerBlock & 31) != 0) threadsPerBlock = 256;

        blocksPerGrid = prop.multiProcessorCount * profile.blocks_per_sm;
        if (blocksPerGrid < prop.multiProcessorCount) blocksPerGrid = prop.multiProcessorCount;
        if (blocksPerGrid > 65535) blocksPerGrid = 65535;

        /* chunk_size uses threadsPerBlock from the profile (may be 256 for ILP-2).
         * For ILP-2 this is intentional: the kernel processes 2 keys/thread, so
         * effective coverage = blocksPerGrid * 128_actual * chunk_mult * 2
         *                    = blocksPerGrid * 256_profile * chunk_mult  (same value). */
        chunk_size = (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * (uint64_t)profile.chunk_mult;
        if (chunk_size < (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * 32ULL) {
            chunk_size = (uint64_t)blocksPerGrid * (uint64_t)threadsPerBlock * 32ULL;
        }
    }

    plat_atomic32_store(&engine->cuda_stage, 2);

    /* === CPU assist workers: 4-way AVX2 workers cover remaining keyspace ===== *
     * GPU handles gpu_split_pct% (cfg, default 80); CPU workers cover the rest
     * using cpu_4way_worker_proc (4-way interleaved KSA + per-superframe PRGA).
     * Workers are pinned to logical processors 0..n_cpu_assist-1 (P-cores). */
    {
        int avail = plat_cpu_count() - 2;
        if (avail < 1) avail = 1;
        if (avail > 8) avail = 8;
        n_cpu_assist = avail;

        int gp = (engine->cfg.gpu_split_pct > 0) ? engine->cfg.gpu_split_pct : 80;
        if (gp < 50) gp = 50;
        if (gp > 95) gp = 95;
        uint64_t gpu_range = (total_keys * (uint64_t)gp) / 100ULL;
        uint64_t cpu_range = total_keys - gpu_range;
        if (cpu_range > 0 && mode_policy >= 2) {
            uint64_t cpu_start = engine->cfg.start_key + gpu_range;
            uint64_t cpu_chunk = cpu_range / (uint64_t)n_cpu_assist;

            cpu_assist_ctxs   = (CpuWorkerCtx *)calloc(n_cpu_assist, sizeof(CpuWorkerCtx));
            cpu_assist_handles = (plat_thread_t *)calloc(n_cpu_assist, sizeof(plat_thread_t));
            if (cpu_assist_ctxs && cpu_assist_handles) {
                for (int t = 0; t < n_cpu_assist; t++) {
                    cpu_assist_ctxs[t].engine        = engine;
                    cpu_assist_ctxs[t].start_key     = cpu_start + (uint64_t)t * cpu_chunk;
                    cpu_assist_ctxs[t].end_key        = (t == n_cpu_assist - 1)
                                                        ? engine->cfg.start_key + total_keys - 1
                                                        : cpu_assist_ctxs[t].start_key + cpu_chunk - 1;
                    cpu_assist_ctxs[t].worker_index  = t;
                    cpu_assist_ctxs[t].cipher_packs  = host_cipher_packs;
                    cpu_assist_ctxs[t].payload_count = payload_limit;
                    cpu_assist_ctxs[t].mode_policy   = mode_policy;
                    if (plat_thread_create(&cpu_assist_handles[t], cpu_4way_worker_proc,
                                           &cpu_assist_ctxs[t]) != 0)
                        { n_cpu_assist = t; break; }
                }
                total_keys = gpu_range; /* GPU only covers its share */
            } else {
                free(cpu_assist_ctxs);   cpu_assist_ctxs = NULL;
                free(cpu_assist_handles); cpu_assist_handles = NULL;
                n_cpu_assist = 0;
            }
        } else {
            n_cpu_assist = 0;
        }
    }

    // Batch chunking (TDR-Safe): adjusted by autotune/cache
    {
        CUDA_CHECK(cudaMemset(d_keys_tested, 0, sizeof(unsigned long long)), "cudaMemset keys_tested (scan reset)");
        CUDA_CHECK(cudaMemset(d_best_packed, 0, sizeof(unsigned long long)), "cudaMemset best_packed (scan reset)");
        CUDA_CHECK(cudaMemset(d_stop_requested, 0, sizeof(int)), "cudaMemset stop_requested (scan reset)");
        /* Reset combined counter and GPU baseline so CPU+GPU deltas accumulate correctly */
        plat_atomic64_store(&engine->keys_tested, 0LL);
        plat_atomic64_store(&engine->gpu_keys_tested, 0LL);
        last_gpu_kt = 0;
    }

    /* === Double-buffer multi-stream dispatch + pinned async polling === */
    {
        cudaStream_t streams[2] = { compute_stream, compute_stream2 };
        int active = 0;
        int have_pending = 0;
        const int stop_sig = 1;             /* #6: hoisted — stable address for async memcpy */
        uint64_t last_checkpoint_ms = plat_ticks_ms(); /* #34: periodic checkpoint timer */

        /* Helper: poll GPU results into engine using pinned memory */
        #define POLL_GPU_RESULTS() do { \
            if (h_poll) { \
                cudaMemcpyAsync(&h_poll->keys_tested,  d_keys_tested,  sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&h_poll->best_packed,  d_best_packed,  sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaStreamSynchronize(query_stream); \
                { unsigned long long _gkt = h_poll->keys_tested; \
                  plat_atomic64_add(&engine->keys_tested, (int64_t)(_gkt - last_gpu_kt)); \
                  plat_atomic64_add(&engine->gpu_keys_tested, (int64_t)(_gkt - last_gpu_kt)); \
                  last_gpu_kt = _gkt; } \
                if (h_poll->best_packed != 0ULL) { \
                    plat_mutex_lock(&engine->lock); \
                    engine->best_score = (double)host_unpack_score(h_poll->best_packed); \
                    engine->best_key   = host_unpack_key(h_poll->best_packed); \
                    plat_mutex_unlock(&engine->lock); \
                } \
            } else { \
                unsigned long long _k = 0, _bp = 0; \
                cudaMemcpyAsync(&_k,  d_keys_tested, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaMemcpyAsync(&_bp, d_best_packed, sizeof(unsigned long long), cudaMemcpyDeviceToHost, query_stream); \
                cudaStreamSynchronize(query_stream); \
                { plat_atomic64_add(&engine->keys_tested, (int64_t)(_k - last_gpu_kt)); \
                  plat_atomic64_add(&engine->gpu_keys_tested, (int64_t)(_k - last_gpu_kt)); \
                  last_gpu_kt = _k; } \
                if (_bp != 0ULL) { \
                    plat_mutex_lock(&engine->lock); \
                    engine->best_score = (double)host_unpack_score(_bp); \
                    engine->best_key   = host_unpack_key(_bp); \
                    plat_mutex_unlock(&engine->lock); \
                } \
            } \
            plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms()); \
        } while(0)

        /* Helper: launch kernel on given stream.
         * ILP-2 kernel MUST use exactly 128 threads/block -- that is the value in
         * __launch_bounds__(128,4).  Launching with more causes a silent deferred
         * cudaErrorInvalidConfiguration on WDDM (the kernel never runs). */
        #define LAUNCH_CHUNK(stream_idx, off, cnt) do { \
            if (mode_policy == 4) { \
                bruteforce_kernel_hytera<<<blocksPerGrid, threadsPerBlock, 0, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, global_mi, \
                    d_keys_tested, d_best_packed, d_stop_requested); \
            } else if (use_ilp2) { \
                bruteforce_kernel_strict_ilp2<<<blocksPerGrid, 128, 65536, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, global_mi, \
                    d_keys_tested, d_best_packed, d_stop_requested); \
            } else if (mode_policy >= 2) { \
                bruteforce_kernel_strict<<<blocksPerGrid, threadsPerBlock, 0, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, global_mi, \
                    d_keys_tested, d_best_packed, d_stop_requested); \
            } else { \
                bruteforce_kernel<<<blocksPerGrid, threadsPerBlock, 0, streams[stream_idx]>>>( \
                    engine->cfg.start_key + (off), (cnt), payload_limit, bytes_per_line, \
                    engine->cfg.sample_bytes, mode_policy, global_mi, has_global_mi, \
                    global_algid, has_global_algid, \
                    d_keys_tested, d_best_packed, d_stop_requested); \
            } \
        } while(0)

        for (offset = 0; offset < total_keys; offset += chunk_size) {
            /* Pause check */
            while (plat_atomic32_load(&engine->paused) != 0) {
                plat_event_wait(&engine->pause_event);
                if (plat_atomic32_load(&engine->stop_requested) != 0) break;
            }
            if (plat_atomic32_load(&engine->stop_requested) != 0) {
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
                    if (plat_atomic32_load(&engine->stop_requested) != 0) {
                        cudaMemcpyAsync(d_stop_requested, &stop_sig, sizeof(int), cudaMemcpyHostToDevice, query_stream);
                        cudaStreamSynchronize(query_stream);
                    }
                    POLL_GPU_RESULTS();
                    plat_sleep_ms(5);
                }
            }

            have_pending = 1;
            active = 1 - active;

            /* #34: write checkpoint every 30 s so the search can be resumed */
            if (engine->progress_path[0] != '\0') {
                uint64_t now_ms = plat_ticks_ms();
                if (now_ms - last_checkpoint_ms >= 30000ULL) {
                    plat_mutex_lock(&engine->lock);
                    uint64_t ck_bk = engine->best_key;
                    double   ck_bs = engine->best_score;
                    plat_mutex_unlock(&engine->lock);
                    FILE *fp_ckpt = fopen(engine->progress_path, "wt");
                    if (fp_ckpt) {
                        uint64_t orig = engine->cfg.has_resume_context
                            ? engine->cfg.original_start_key : engine->cfg.start_key;
                        fprintf(fp_ckpt,
                                "offset=%llu\nend=%llu\nbest_key=%010llX\nbest_score=%.6f\noriginal_start=%llu\n",
                                (unsigned long long)(engine->cfg.start_key + offset),
                                (unsigned long long)engine->cfg.end_key,
                                (unsigned long long)ck_bk,
                                ck_bs,
                                (unsigned long long)orig);
                        fclose(fp_ckpt);
                    }
                    last_checkpoint_ms = now_ms;
                }
            }
        }

        /* Wait for last chunk(s), then read final GPU key/score counters.
         * When kernels are fast the polling while-loop may never execute,
         * so we always do one explicit poll here after both streams drain. */
        cudaStreamSynchronize(streams[0]);
        cudaStreamSynchronize(streams[1]);
        POLL_GPU_RESULTS();

        #undef POLL_GPU_RESULTS
        #undef LAUNCH_CHUNK
    }

    /* Wait for CPU assist workers to finish */
    if (n_cpu_assist > 0 && cpu_assist_handles) {
        plat_threads_join(cpu_assist_handles, n_cpu_assist);
        for (int t = 0; t < n_cpu_assist; t++) plat_thread_close(cpu_assist_handles[t]);
    }
    free(cpu_assist_handles); cpu_assist_handles = NULL;
    free(cpu_assist_ctxs);    cpu_assist_ctxs = NULL;

    /* Final result read */
    {
        unsigned long long final_k = 0, final_bp = 0;
        CUDA_CHECK(cudaMemcpy(&final_k,  d_keys_tested, sizeof(unsigned long long), cudaMemcpyDeviceToHost), "cudaMemcpy final keys_tested");
        CUDA_CHECK(cudaMemcpy(&final_bp, d_best_packed, sizeof(unsigned long long), cudaMemcpyDeviceToHost), "cudaMemcpy final best_packed");
        plat_atomic64_add(&engine->keys_tested, (int64_t)(final_k - last_gpu_kt));
        plat_atomic64_add(&engine->gpu_keys_tested, (int64_t)(final_k - last_gpu_kt));
        if (final_bp != 0ULL) {
            plat_mutex_lock(&engine->lock);
            engine->best_score = (double)host_unpack_score(final_bp);
            engine->best_key   = host_unpack_key(final_bp);
            plat_mutex_unlock(&engine->lock);
        }
    }

    if (plat_atomic32_load(&engine->stop_requested) == 0) {
        plat_atomic32_store(&engine->search_completed, 1);
        /* #34: search finished cleanly — delete the progress file */
        if (engine->progress_path[0] != '\0') {
            plat_delete_file(engine->progress_path);
            engine->progress_path[0] = '\0';
        }
    }

cleanup:
    /* Stop and wait for CPU assist workers if still running (e.g. CUDA error path) */
    if (n_cpu_assist > 0 && cpu_assist_handles) {
        plat_threads_join(cpu_assist_handles, n_cpu_assist);
        for (int t = 0; t < n_cpu_assist; t++) plat_thread_close(cpu_assist_handles[t]);
        free(cpu_assist_handles); cpu_assist_handles = NULL;
        free(cpu_assist_ctxs);    cpu_assist_ctxs = NULL;
    }
    if (d_keys_tested) cudaFree(d_keys_tested);
    if (d_best_packed) cudaFree(d_best_packed);
    if (d_stop_requested) cudaFree(d_stop_requested);
    free(host_payload_flat);
    if (h_poll) cudaFreeHost(h_poll);
    if (compute_stream) cudaStreamDestroy(compute_stream);
    if (compute_stream2) cudaStreamDestroy(compute_stream2);
    if (query_stream) cudaStreamDestroy(query_stream);

    plat_atomic32_store(&engine->cuda_stage, 3);
    plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());
    plat_atomic32_store(&engine->running, 0);
    plat_event_set(&engine->pause_event);
    PLAT_THREAD_RETURN;
}

#undef CUDA_CHECK

// ==== CPU FALLBACK WORKER (used when no CUDA GPU is available) ====

static void key_to_5bytes_cpu(uint64_t key, unsigned char out[5])
{
    out[0] = (unsigned char)((key >> 32) & 0xFFu);
    out[1] = (unsigned char)((key >> 24) & 0xFFu);
    out[2] = (unsigned char)((key >> 16) & 0xFFu);
    out[3] = (unsigned char)((key >> 8) & 0xFFu);
    out[4] = (unsigned char)(key & 0xFFu);
}

/* Forward declaration — defined later, after scoring helpers */
static double score_candidate_host(
    const PayloadSet *payloads, int sample_lines,
    int sample_bytes, const unsigned char key[5]);

static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL cpu_worker_proc(void *arg)
{
    CpuWorkerCtx *ctx = (CpuWorkerCtx *)arg;
    BruteforceEngine *engine = ctx->engine;
    uint64_t k;
    uint64_t local_count = 0;
    double local_best_score = -DBL_MAX;
    uint64_t last_checkpoint_ms = (ctx->worker_index == 0) ? plat_ticks_ms() : 0;

    plat_thread_set_ideal_processor(ctx->worker_index);

    for (k = ctx->start_key; k <= ctx->end_key; ++k) {
        unsigned char key_bytes[5];
        double score;

        if ((local_count & 0xFFFu) == 0) {
            if (plat_atomic32_load(&engine->stop_requested) != 0) break;
            if (plat_atomic32_load(&engine->paused) != 0) {
                plat_event_wait(&engine->pause_event);
                if (plat_atomic32_load(&engine->stop_requested) != 0) break;
            }
            /* Worker 0 writes periodic checkpoints for CPU-only path */
            ctx->current_k = k;
            if (ctx->worker_index == 0 && engine->progress_path[0] != '\0') {
                uint64_t now_ms = plat_ticks_ms();
                if (now_ms - last_checkpoint_ms >= 30000ULL) {
                    CpuWorkerCtx *all = (CpuWorkerCtx *)engine->workers;
                    uint64_t min_k = k;
                    for (int w = 1; w < engine->cfg.thread_count; w++) {
                        uint64_t wk = all[w].current_k;
                        if (wk < min_k) min_k = wk;
                    }
                    plat_mutex_lock(&engine->lock);
                    uint64_t ck_bk = engine->best_key;
                    double   ck_bs = engine->best_score;
                    plat_mutex_unlock(&engine->lock);
                    FILE *fp_ckpt = fopen(engine->progress_path, "wt");
                    if (fp_ckpt) {
                        uint64_t orig = engine->cfg.has_resume_context
                            ? engine->cfg.original_start_key : engine->cfg.start_key;
                        fprintf(fp_ckpt,
                                "offset=%llu\nend=%llu\nbest_key=%010llX\nbest_score=%.6f\noriginal_start=%llu\n",
                                (unsigned long long)min_k,
                                (unsigned long long)engine->cfg.end_key,
                                (unsigned long long)ck_bk,
                                ck_bs,
                                (unsigned long long)orig);
                        fclose(fp_ckpt);
                    }
                    last_checkpoint_ms = now_ms;
                }
            }
        }

        key_to_5bytes_cpu(k, key_bytes);
        score = score_candidate_host(engine->payloads, engine->cfg.sample_lines,
                                     engine->cfg.sample_bytes, key_bytes);

        if (score > local_best_score) {
            local_best_score = score;
            plat_mutex_lock(&engine->lock);
            if (score > engine->best_score) {
                engine->best_score = score;
                engine->best_key = k;
            }
            plat_mutex_unlock(&engine->lock);
        }

        local_count++;
        if ((local_count & STOP_POLL_MASK) == 0) {
            plat_atomic64_add(&engine->keys_tested, 1024LL);
        }

        if (k == ctx->end_key) break;
    }

    if ((local_count & STOP_POLL_MASK) != 0) {
        plat_atomic64_add(&engine->keys_tested, (int64_t)(local_count & STOP_POLL_MASK));
    }

    if (plat_atomic32_inc(&engine->finished_threads) == engine->cfg.thread_count) {
        if (plat_atomic32_load(&engine->stop_requested) == 0) {
            plat_atomic32_store(&engine->search_completed, 1);
            if (engine->progress_path[0] != '\0') {
                plat_delete_file(engine->progress_path);
                engine->progress_path[0] = '\0';
            }
        }
        plat_atomic32_store(&engine->running, 0);
        plat_event_set(&engine->pause_event);
    }

    PLAT_THREAD_RETURN;
}

// ==== ORIGINAL HOST API EXPORTS (bruteforce.h) ====

void bruteforce_engine_init(BruteforceEngine *engine)
{
    memset(engine, 0, sizeof(*engine));
    plat_mutex_init(&engine->lock);
    plat_hrfreq_init(&engine->qpc_freq);
    engine->pause_event = plat_event_create(1); /* signaled — workers run immediately */
}

void bruteforce_engine_destroy(BruteforceEngine *engine)
{
    bruteforce_stop(engine);
    plat_event_destroy(&engine->pause_event);
    plat_mutex_destroy(&engine->lock);
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
    if (plat_atomic32_load(&engine->running) != 0) {
        set_error(err, err_len, g_lang.err_search_already_active);
        return 0;
    }

    if (cfg->start_key > cfg->end_key) {
        set_error(err, err_len, g_lang.err_start_gt_end);
        return 0;
    }
    if (cfg->end_key > 0xFFFFFFFFFFull) {
        set_error(err, err_len, g_lang.err_end_exceeds_40bit);
        return 0;
    }
    if (payloads == NULL || payloads->count == 0) {
        set_error(err, err_len, g_lang.err_no_payloads_loaded);
        return 0;
    }

    int deviceCount = 0;
    cudaError_t cu_err = cudaGetDeviceCount(&deviceCount);
    if (cu_err != cudaSuccess || deviceCount == 0) {
        /* No CUDA GPU: fall back to CPU multi-threaded search */
        engine->cuda_active = 0;
        engine->cuda_device_name[0] = '\0';
        if (cu_err != cudaSuccess)
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
#if defined(USE_HIP)
                     "hipGetDeviceCount failed: %s (error %d). "
                     "This binary was built with HIP %d.%d -- "
                     "rebuild from source with the ROCm toolkit that matches your driver.",
#else
                     "cudaGetDeviceCount failed: %s (error %d). "
                     "This binary was built with CUDA %d.%d -- "
                     "rebuild from source with the CUDA toolkit that matches your driver.",
#endif
                     cudaGetErrorString(cu_err), (int)cu_err,
                     CUDART_VERSION / 1000, (CUDART_VERSION % 1000) / 10);
        else
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
#if defined(USE_HIP)
                     "No ROCm-capable GPU detected (hipGetDeviceCount returned 0). "
                     "This binary was built with HIP %d.%d. "
                     "Verify the ROCm driver is installed (run: rocm-smi).",
#else
                     "No CUDA-capable GPU detected (cudaGetDeviceCount returned 0). "
                     "This binary was built with CUDA %d.%d. "
                     "Verify the NVIDIA driver is installed and the GPU is not in TCC mode "
#  if defined(_WIN32)
                     "(run: nvidia-smi -q | findstr \"Compute Mode\").",
#  else
                     "(run: nvidia-smi -q | grep 'Compute Mode').",
#  endif
#endif
                     CUDART_VERSION / 1000, (CUDART_VERSION % 1000) / 10);

    cpu_fallback:
        {
            int t;
            uint64_t total, chunk, rem, start;
            int n_threads = cfg->thread_count;
            if (n_threads <= 0 || n_threads > 64) n_threads = 1;

            /* Initialize engine config and payloads (normally done later in GPU path) */
            engine->cfg = *cfg;
            engine->payloads = payloads;
            if (engine->cfg.sample_bytes <= 0) engine->cfg.sample_bytes = 33;
            if (engine->cfg.sample_lines <= 0 || (size_t)engine->cfg.sample_lines > payloads->count)
                engine->cfg.sample_lines = (int)payloads->count;

            plat_event_set(&engine->pause_event); /* ensure threads won't block initially */

            engine->thread_handles = (plat_thread_t *)calloc((size_t)n_threads, sizeof(plat_thread_t));
            engine->workers = calloc((size_t)n_threads, sizeof(CpuWorkerCtx));
            if (engine->thread_handles == NULL || engine->workers == NULL) {
                free(engine->thread_handles); engine->thread_handles = NULL;
                free(engine->workers);        engine->workers = NULL;
                set_error(err, err_len, g_lang.err_oom_cpu_threads);
                return 0;
            }
            CpuWorkerCtx *workers = (CpuWorkerCtx *)engine->workers;

            total = (cfg->end_key - cfg->start_key) + 1ull;
            if ((uint64_t)n_threads > total) n_threads = (int)total;
            engine->cfg.thread_count = n_threads;
            chunk = total / (uint64_t)n_threads;
            rem   = total % (uint64_t)n_threads;
            start = cfg->start_key;

            plat_atomic64_store(&engine->keys_tested, 0LL);
            plat_atomic32_store(&engine->stop_requested, 0);
            plat_atomic32_store(&engine->paused, 0);
            plat_atomic32_store(&engine->finished_threads, 0);
            plat_atomic32_store(&engine->search_completed, 0);
            engine->best_key   = cfg->has_seed_best ? cfg->seed_best_key   : cfg->start_key;
            engine->best_score = cfg->has_seed_best ? cfg->seed_best_score : -DBL_MAX;
            plat_hrtimer_now(&engine->qpc_start);
            plat_atomic32_store(&engine->running, 1);

            /* Dictionary phase: test common/default keys before CPU scan */
            run_dictionary_phase(engine);

            for (t = 0; t < n_threads; ++t) {
                uint64_t this_count = chunk + ((uint64_t)t < rem ? 1ull : 0ull);
                workers[t].engine       = engine;
                workers[t].start_key    = start;
                workers[t].end_key      = start + this_count - 1ull;
                workers[t].worker_index = t;
                workers[t].current_k    = start;
                start += this_count;

                if (plat_thread_create(&engine->thread_handles[t], cpu_worker_proc, &workers[t]) != 0) {
                    int j;
                    plat_atomic32_store(&engine->running, 0);
                    plat_atomic32_store(&engine->stop_requested, 1);
                    plat_event_set(&engine->pause_event);
                    for (j = 0; j < t; ++j) {
                        plat_thread_join(engine->thread_handles[j]);
                        plat_thread_close(engine->thread_handles[j]);
                    }
                    free(engine->thread_handles); engine->thread_handles = NULL;
                    free(engine->workers);        engine->workers = NULL;
                    set_error(err, err_len, g_lang.err_create_cpu_threads);
                    return 0;
                }
            }
        }
        return 1;
    }

    /* Force CUDA primary context creation.
     * cudaGetDeviceCount() is context-free; the primary context is created on
     * the first runtime call that requires it.  On some WDDM configurations the
     * deferred context creation inside the launcher thread fails silently,
     * leaving GPU utilisation at 0 %.
     *
     * cudaFree(0) is the NVIDIA-recommended idiom for eager context init:
     * it is a no-op allocation (frees a null pointer) but forces the runtime to
     * create and validate the primary context before we return to the caller.
     * If it fails we fall back to CPU and show an actionable error message. */
    {
        cu_err = cudaSetDevice(0);
        if (cu_err == cudaSuccess)
            cu_err = cudaFree(0); /* no-op alloc; forces primary context creation */
        if (cu_err != cudaSuccess) {
            engine->cuda_active = 0;
            engine->cuda_device_name[0] = '\0';
            snprintf(engine->cuda_error, sizeof(engine->cuda_error),
#if defined(USE_HIP)
                     "GPU context init failed: %s (error %d). "
                     "Built with HIP %d.%d. "
                     "Check: ROCm driver installed, GPU supported (run: rocm-smi).",
#else
                     "GPU context init failed: %s (error %d). "
                     "Built with CUDA %d.%d. "
                     "Check: driver installed, GPU not in TCC/exclusive mode, "
                     "NvOptimusEnablement exported (laptop users).",
#endif
                     cudaGetErrorString(cu_err), (int)cu_err,
                     CUDART_VERSION / 1000, (CUDART_VERSION % 1000) / 10);
            goto cpu_fallback;
        }

        /* Context is live -- query device name. */
        cudaDeviceProp prop;
        if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess)
            strncpy(engine->cuda_device_name, prop.name, sizeof(engine->cuda_device_name) - 1);
        engine->cuda_device_name[sizeof(engine->cuda_device_name) - 1] = '\0';
        engine->cuda_active = 1;
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

    plat_event_set(&engine->pause_event); /* ensure threads won't block initially */

    plat_atomic64_store(&engine->keys_tested, 0LL);
    plat_atomic32_store(&engine->stop_requested, 0);
    plat_atomic32_store(&engine->paused, 0);
    plat_atomic32_store(&engine->search_completed, 0);
    engine->best_key   = cfg->has_seed_best ? cfg->seed_best_key   : cfg->start_key;
    engine->best_score = cfg->has_seed_best ? cfg->seed_best_score : -DBL_MAX;
    plat_atomic32_store(&engine->cuda_stage, 0);
    plat_atomic32_store(&engine->cuda_profile_cached, 0);
    plat_atomic32_store(&engine->cuda_tpb, 0);
    plat_atomic32_store(&engine->cuda_bpsm, 0);
    plat_atomic32_store(&engine->cuda_chunk_mult, 0);
    plat_atomic32_store(&engine->cuda_sm_count, 0);
    plat_atomic32_store(&engine->cuda_compute_major, 0);
    plat_atomic32_store(&engine->cuda_compute_minor, 0);
    plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());

    engine->cuda_error[0] = '\0';
    plat_hrtimer_now(&engine->qpc_start);

    /* Allocate handle array before launching thread so the handle is never lost. */
    engine->thread_handles = (plat_thread_t *)calloc(1, sizeof(plat_thread_t));
    if (engine->thread_handles == NULL) {
        set_error(err, err_len, g_lang.err_oom_handles);
        return 0;
    }

    plat_atomic32_store(&engine->running, 1);

    if (plat_thread_create(&engine->thread_handles[0], cuda_launcher_thread, engine) != 0) {
        plat_atomic32_store(&engine->running, 0);
        free(engine->thread_handles);
        engine->thread_handles = NULL;
        set_error(err, err_len, g_lang.err_create_cuda_thread);
        return 0;
    }

    return 1;
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

    if (engine->workers != NULL) {
        /* CPU fallback mode: wait on all worker threads */
        int t;
        for (t = 0; t < engine->cfg.thread_count; ++t) {
            plat_thread_join(engine->thread_handles[t]);
            plat_thread_close(engine->thread_handles[t]);
        }
        free(engine->workers);
        engine->workers = NULL;
    } else {
        /* GPU mode: single CUDA launcher thread */
        plat_thread_join(engine->thread_handles[0]);
        plat_thread_close(engine->thread_handles[0]);
    }

    free(engine->thread_handles);
    engine->thread_handles = NULL;

    plat_atomic32_store(&engine->running, 0);
}

static void enter_snapshot_lock(const BruteforceEngine *engine)
{
    /* Logically read-only, but mutex guarantees consistency with worker threads. */
    plat_mutex_lock((plat_mutex_t *)&engine->lock);
}

static void leave_snapshot_lock(const BruteforceEngine *engine)
{
    plat_mutex_unlock((plat_mutex_t *)&engine->lock);
}

void bruteforce_get_snapshot(const BruteforceEngine *engine, BruteforceSnapshot *out)
{
    plat_hrtimer_t now;
    double elapsed;
    uint64_t keys;
    uint64_t total;

    keys = (uint64_t)plat_atomic64_load((plat_atomic64_t *)&engine->keys_tested);
    total = 0;
    if (engine->cfg.has_resume_context) {
        /* Show overall progress spanning original start → end */
        uint64_t orig = engine->cfg.original_start_key;
        if (engine->cfg.end_key >= orig)
            total = (engine->cfg.end_key - orig) + 1ull;
        /* Add keys already done in prior sessions */
        if (engine->cfg.start_key > orig)
            keys += engine->cfg.start_key - orig;
    } else if (engine->cfg.end_key >= engine->cfg.start_key) {
        total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    }

    plat_hrtimer_now(&now);
    elapsed = plat_hrtimer_elapsed_s(&engine->qpc_start, &now, &engine->qpc_freq);
    if (elapsed < 0.0) elapsed = 0.0;

    out->keys_tested = keys;
    out->gpu_keys_tested = (uint64_t)plat_atomic64_load((plat_atomic64_t *)&engine->gpu_keys_tested);
    out->total_keys = total;
    enter_snapshot_lock(engine);
    out->best_key = engine->best_key;
    out->best_score = engine->best_score;
    leave_snapshot_lock(engine);
    out->elapsed_seconds = elapsed;
    out->running  = (int)plat_atomic32_load((plat_atomic32_t *)&engine->running);
    out->paused   = (int)plat_atomic32_load((plat_atomic32_t *)&engine->paused);
    out->finished = (int)plat_atomic32_load((plat_atomic32_t *)&engine->search_completed);

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

static int is_hytera_ep_alg_host(uint8_t alg)
{
    return alg == 0x02;
}

static void compute_hytera_ks_cpu(
    const unsigned char key5[5], uint32_t mi,
    unsigned char ks_out[21])
{
    unsigned char kiv[5];
    kiv[0] = key5[0];
    kiv[1] = key5[1] ^ (unsigned char)((mi >> 24) & 0xFFu);
    kiv[2] = key5[2] ^ (unsigned char)((mi >> 16) & 0xFFu);
    kiv[3] = key5[3] ^ (unsigned char)((mi >>  8) & 0xFFu);
    kiv[4] = key5[4] ^ (unsigned char)( mi        & 0xFFu);

    RC4_CTX rc4;
    rc4_init(&rc4, key5, 5);  /* KSA with key5, drop=0 */

    unsigned char zeros[21];
    memset(zeros, 0, sizeof(zeros));
    rc4_crypt(&rc4, zeros, ks_out, 21);

    for (int i = 0; i < 21; i++) ks_out[i] ^= kiv[i % 5];
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
 *
 * out_sf0_bits24: if non-NULL, receives the 24 decrypted AMBE bits (C0+C1)
 * from sub-frame 0. Used by score_candidate_host for bit-frequency chi² scoring
 * Bit-frequency chi² is the primary metric: Z≈335 with 126 payloads.
 */
static double score_burst_correct_host(
    const unsigned char *payload33,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos,
    unsigned char out_sf0_bits24[24])   /* nullable */
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
    rc4_discard_host(&rc4, RC4_DISCARD_BYTES + burst_pos * DMR_CIPHER_PACK_BYTES);

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

    if (out_sf0_bits24 != NULL)
        memcpy(out_sf0_bits24, dec24[0], 24);

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
        int mi_rc4_lines = 0, mi_hytera_lines = 0;
        for (size_t i = 0; i < line_count; ++i) {
            const PayloadLine *line = &payloads->items[i];
            uint8_t alg = line->has_algid ? line->algid : payloads->global_algid;
            if (line->has_mi && is_rc4_alg_host(alg))    mi_rc4_lines++;
            if (line->has_mi && is_hytera_ep_alg_host(alg)) mi_hytera_lines++;
        }
        if (line_count > 0 && mi_hytera_lines * 10 >= (int)line_count * 9) {
            mode_policy = 4;
        } else if (line_count > 0 && mi_rc4_lines * 10 >= (int)line_count * 9) {
            mode_policy = 3;
        } else if (line_count > 0 && mi_rc4_lines * 3 >= (int)line_count) {
            mode_policy = 2;
        } else if (!payloads->has_global_mi && mi_rc4_lines == 0) {
            mode_policy = 1;
        }
    }

    /* Hytera EP path (mode_policy == 4): Hamming + bit-frequency, same structure as KMI9 */
    if (mode_policy == 4) {
        long bit_counts[24];
        int n_freq = 0, b;
        memset(bit_counts, 0, sizeof(bit_counts));

        for (size_t sf_base = 0; sf_base < line_count; sf_base += 6) {
            uint32_t mi = payloads->items[sf_base].has_mi
                          ? payloads->items[sf_base].mi
                          : payloads->global_mi;
            unsigned char ks[21];
            compute_hytera_ks_cpu(key, mi, ks);

            for (size_t p = sf_base; p < sf_base + 6 && p < line_count; ++p) {
                const PayloadLine *line = &payloads->items[p];
                if (line->len < 33) continue;

                /* Precomputed cipher packs for this line would require precompute_cipher_packs_host.
                 * Instead, re-use score_burst_correct_host but substitute Hytera ks for the RC4 output.
                 * We do this by inlining the de-interleave+demodulate+pack step, then XOR with ks. */
                unsigned char dec24[3][24];
                for (int sf = 0; sf < 3; sf++) {
                    unsigned char ambe_fr[4][24];
                    memset(ambe_fr, 0, sizeof(ambe_fr));
                    for (int i2 = 0; i2 < 36; ++i2) {
                        int d = sf_dibit_idx_host[sf][i2];
                        int byte_idx = d >> 2;
                        int shift = (3 - (d & 3)) * 2;
                        unsigned char dibit = (unsigned char)((line->data[byte_idx] >> shift) & 0x3u);
                        ambe_fr[dmr_rW_host[i2]][dmr_rX_host[i2]] = (unsigned char)((dibit >> 1) & 1u);
                        ambe_fr[dmr_rY_host[i2]][dmr_rZ_host[i2]] = (unsigned char)(dibit & 1u);
                    }
                    { /* mbe_demodulate */
                        int foo = 0;
                        for (int i2 = 23; i2 >= 12; --i2) foo = (foo << 1) | (int)ambe_fr[0][i2];
                        int pr_val = 16 * foo;
                        for (int j = 22; j >= 0; --j) {
                            pr_val = (173 * pr_val + 13849) & 0xFFFF;
                            ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
                        }
                    }
                    /* extract 49 bits → pack 7 bytes */
                    unsigned char cipher7[7] = {0};
                    {
                        unsigned char bits49[49];
                        int bi = 0;
                        for (int j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
                        for (int j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
                        for (int j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
                        for (int j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];
                        for (int i2 = 0; i2 < 49; ++i2)
                            cipher7[i2 >> 3] |= (unsigned char)((bits49[i2] & 1u) << (7 - (i2 & 7)));
                    }
                    /* Hytera EP decrypt: XOR with ks[sf*7..sf*7+6] */
                    unsigned char plain7[7];
                    for (int j = 0; j < 7; j++) plain7[j] = cipher7[j] ^ ks[sf*7 + j];
                    for (int i2 = 0; i2 < 24; ++i2)
                        dec24[sf][i2] = (unsigned char)((plain7[i2 >> 3] >> (7 - (i2 & 7))) & 1u);
                }

                int h01 = 0, h12 = 0;
                for (b = 0; b < 24; b++) {
                    h01 += dec24[0][b] ^ dec24[1][b];
                    h12 += dec24[1][b] ^ dec24[2][b];
                }
                score += (double)(48 - h01 - h12);
                for (b = 0; b < 24; b++) bit_counts[b] += dec24[0][b];
                n_freq++;
            }
        }

        if (n_freq >= 6) {
            double half_n = (double)n_freq * 0.5;
            double chi2 = 0.0;
            for (b = 0; b < 24; b++) {
                double dev = (double)bit_counts[b] - half_n;
                chi2 += dev * dev;
            }
            score += chi2 / (double)n_freq;
        }
        return score;
    }

    /* KMI9 path (mode_policy >= 2): two metrics in a single pass —
     *   1. Inter-frame Hamming on C0+C1 (24 bits), Z≈38 with 126 payloads.
     *   2. Bit-frequency chi² across all frames, Z≈335 with 126 payloads. */
    if (mode_policy >= 2) {
        long bit_counts[24];
        int n_freq = 0, b;
        memset(bit_counts, 0, sizeof(bit_counts));

        for (size_t p = 0; p < line_count; ++p) {
            const PayloadLine *line = &payloads->items[p];
            uint32_t mi = line->has_mi ? line->mi : payloads->global_mi;
            int burst_pos = (int)(p % 6);
            if (line->len >= 33) {
                unsigned char sf0_bits[24];
                score += score_burst_correct_host(line->data, key, mi, burst_pos, sf0_bits);
                for (b = 0; b < 24; b++) bit_counts[b] += sf0_bits[b];
                n_freq++;
            }
        }

        /* Bit-frequency chi-squared: sum_i (count_i - N/2)^2 / N.
         * Wrong key:   E[result] ≈ 6  (uniform distribution, 24 * N/4 / N).
         * Correct key: result >> 6     (non-uniform speech bit distribution). */
        if (n_freq >= 6) {
            double half_n = (double)n_freq * 0.5;
            double chi2 = 0.0;
            for (b = 0; b < 24; b++) {
                double dev = (double)bit_counts[b] - half_n;
                chi2 += dev * dev;
            }
            score += chi2 / (double)n_freq;
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
                rc4_discard_host(&rc4_cont, RC4_DISCARD_BYTES);
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
                else if (!infer_line_mi_host(payloads, (int)line_idx, &line_mi)) {
                    /* Use LFSR-tracked MI when available (use_mi_lfsr mode), else fall back to global */
                    line_mi = (use_mi_lfsr && running_mi != 0u) ? running_mi : payloads->global_mi;
                }

                if (use_mi_lfsr) {
                    running_mi = line_mi;
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
                    if (use_drop256) rc4_discard_host(&rc4, RC4_DISCARD_BYTES);
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

/*
 * =========================================================================
 * DICTIONARY ATTACK PHASE (Level 1 & 2 from improvement roadmap)
 *
 * Tests a curated set of common/default 40-bit ARC4 keys before the main
 * GPU/CPU brute-force scan. Uses the same score_candidate_host() pipeline.
 * Sets cuda_stage=4 ("DICT") in the GUI while running.
 *
 * Key selection rationale:
 *   Level 1: all-same-nibble (factory resets), trivial incrementing patterns
 *   Level 2: common installer defaults, alternating patterns, magic numbers
 *
 * Each key is a uint64_t ≤ 0xFFFFFFFFFF (40 bits = 5 bytes = 10 hex digits).
 * =========================================================================
 */
static const uint64_t s_dict_keys[] = {
    /* --- Level 1: All-same-nibble (factory reset defaults) --- */
    0x0000000000ULL,  /* 0000000000 */
    0x1111111111ULL,  /* 1111111111 */
    0x2222222222ULL,  /* 2222222222 */
    0x3333333333ULL,  /* 3333333333 */
    0x4444444444ULL,  /* 4444444444 */
    0x5555555555ULL,  /* 5555555555 */
    0x6666666666ULL,  /* 6666666666 */
    0x7777777777ULL,  /* 7777777777 */
    0x8888888888ULL,  /* 8888888888 */
    0x9999999999ULL,  /* 9999999999 */
    0xAAAAAAAAAAULL,  /* AAAAAAAAAA */
    0xBBBBBBBBBBULL,  /* BBBBBBBBBB */
    0xCCCCCCCCCCULL,  /* CCCCCCCCCC */
    0xDDDDDDDDDDULL,  /* DDDDDDDDDD */
    0xEEEEEEEEEEULL,  /* EEEEEEEEEE */
    0xFFFFFFFFFFULL,  /* FFFFFFFFFF */

    /* --- Level 1: Sequential and near-trivial --- */
    0x0123456789ULL,  /* 0123456789 */
    0x9876543210ULL,  /* 9876543210 */
    0x1234567890ULL,  /* 1234567890 */
    0x0987654321ULL,  /* 0987654321 */
    0xFEDCBA9876ULL,  /* FEDCBA9876 */
    0x0000000001ULL,  /* 0000000001 */
    0xFFFFFFFFFEULL,  /* FFFFFFFFE  */
    0x0000000010ULL,  /* 0000000010 */
    0x0000000100ULL,  /* 0000000100 */
    0x0000001000ULL,  /* 0000001000 */
    0x0000010000ULL,  /* 0000010000 */
    0x0001000000ULL,  /* 0001000000 */

    /* --- Level 2: Common installer patterns --- */
    0x0102030405ULL,  /* 0102030405 */
    0x0504030201ULL,  /* 0504030201 */
    0x1122334455ULL,  /* 1122334455 */
    0x5544332211ULL,  /* 5544332211 */
    0xAABBCCDDEEULL,  /* AABBCCDDEE */
    0xEEDDCCBBAAULL,  /* EEDDCCBBAA */
    0x1234ABCDEFULL,  /* 1234ABCDEF */
    0xABCDEF1234ULL,  /* ABCDEF1234 */
    0xABCDE12345ULL,  /* ABCDE12345 */
    0x6789ABCDEFULL,  /* 6789ABCDEF */
    0xABCDEF0123ULL,  /* ABCDEF0123 */

    /* --- Level 2: Alternating / XOR patterns --- */
    0xA5A5A5A5A5ULL,  /* A5A5A5A5A5 */
    0x5A5A5A5A5AULL,  /* 5A5A5A5A5A */
    0x0F0F0F0F0FULL,  /* 0F0F0F0F0F */
    0xF0F0F0F0F0ULL,  /* F0F0F0F0F0 */
    0xABABABABABULL,  /* ABABABABAB */
    0xBABABABABAULL,  /* BABABABABA */
    0x0A0A0A0A0AULL,  /* 0A0A0A0A0A */
    0xA0A0A0A0A0ULL,  /* A0A0A0A0A0 */

    /* --- Level 2: Common magic numbers (Motorola/radio defaults) --- */
    0xDEADBEEF00ULL,  /* DEADBEEF00 */
    0xCAFEBABE00ULL,  /* CAFEBABE00 */
    0xDEADC0DE00ULL,  /* DEADC0DE00 */
    0xBAADF00D00ULL,  /* BAADF00D00 */
    0x0000FFFFFFULL,  /* 0000FFFFFF */
    0xFFFFFF0000ULL,  /* FFFFFF0000 */
    0xFF00FF00FFULL,  /* FF00FF00FF */
    0x00FF00FF00ULL,  /* 00FF00FF00 */

    /* --- Level 3: Radio freq as 10-digit hex (decimal kHz padded with zeros) --- */
    0x0000145500ULL,  /* 145.500 MHz VHF */
    0x0000146000ULL,  /* 146.000 MHz VHF */
    0x0000146500ULL,  /* 146.500 MHz VHF */
    0x0000147000ULL,  /* 147.000 MHz VHF */
    0x0000155000ULL,  /* 155.000 MHz VHF */
    0x0000160000ULL,  /* 160.000 MHz VHF */
    0x0000438000ULL,  /* 438.000 MHz UHF */
    0x0000440000ULL,  /* 440.000 MHz UHF */
    0x0000446000ULL,  /* 446.000 MHz PMR446 */
    0x0000450000ULL,  /* 450.000 MHz UHF */
    0x0000462000ULL,  /* 462.000 MHz GMRS */
    0x0000462125ULL,  /* 462.125 MHz GMRS */
    0x0000462550ULL,  /* 462.550 MHz GMRS */
    0x0000467000ULL,  /* 467.000 MHz GMRS repeater output */
    0x0000470000ULL,  /* 470.000 MHz UHF */

    /* --- Level 3: Year/date patterns (YYYYMMDD decimal as hex digits) --- */
    0x0000002024ULL,  /* year 2024 */
    0x0000002025ULL,  /* year 2025 */
    0x0000002023ULL,  /* year 2023 */
    0x0020240101ULL,  /* 20240101 */
    0x0020241231ULL,  /* 20241231 */
    0x0020250101ULL,  /* 20250101 */
    0x0020231231ULL,  /* 20231231 */

    /* --- Level 3: Keyboard/numpad patterns --- */
    0x1357924680ULL,  /* skip-one ascending */
    0x0864297531ULL,  /* skip-one descending */
    0x0011223344ULL,  /* paired ascending low */
    0x5566778899ULL,  /* paired ascending high */
    0x0099887766ULL,  /* paired descending */
    0x1234512345ULL,  /* 5-digit repeat */
    0xABCDEABCDEULL,  /* 5-hex repeat */
};

#define S_DICT_KEY_COUNT ((int)(sizeof(s_dict_keys)/sizeof(s_dict_keys[0])))

/*
 * run_dictionary_phase - Run before GPU/CPU brute-force to test common keys.
 *
 * Sets cuda_stage=4 while running (GUI displays "DICT").
 * Updates engine->best_key / engine->best_score for any key scoring better
 * than the current best. Respects stop_requested.
 */
static void run_dictionary_phase(BruteforceEngine *engine)
{
    int i;
    int sample_lines = engine->cfg.sample_lines;
    int sample_bytes = engine->cfg.sample_bytes;

    plat_atomic32_store(&engine->cuda_stage, 4);
    plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());

    for (i = 0; i < S_DICT_KEY_COUNT; ++i) {
        unsigned char key5[5];
        double score;

        if (plat_atomic32_load(&engine->stop_requested) != 0) break;

        key_to_5bytes_cpu(s_dict_keys[i], key5);
        score = score_candidate_host(engine->payloads, sample_lines, sample_bytes, key5);

        plat_mutex_lock(&engine->lock);
        if (score > engine->best_score) {
            engine->best_score = score;
            engine->best_key   = s_dict_keys[i];
        }
        plat_mutex_unlock(&engine->lock);
    }

    plat_atomic32_store(&engine->cuda_stage, 0);
    plat_atomic64_store(&engine->cuda_last_update_ms, (int64_t)plat_ticks_ms());
}
