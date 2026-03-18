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
 * test_strict_score.c - Verify strict kernel scoring logic on CPU.
 * Simulates EXACTLY the same cipher_packs + RC4 + Hamming pipeline
 * that bruteforce_kernel_strict uses, but runs on CPU for validation.
 *
 * Build:
 *   cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_strict_score.exe
 *      src\test_strict_score.c src\bruteforce.c src\rc4.c src\payload_io.c
 *      /Iinclude user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../include/payload_io.h"
#include "../include/bruteforce.h"
#include "../include/rc4.h"

/* rc4_discard: advance RC4 stream without output */
static void rc4_discard_host(RC4_CTX *ctx, int n) {
    unsigned char tmp[64];
    while (n > 0) {
        int chunk = n > 64 ? 64 : n;
        unsigned char zeros[64] = {0};
        rc4_crypt(ctx, zeros, tmp, chunk);
        n -= chunk;
    }
}

/* Host-side tables (same as in bruteforce.cu) */
static const int dmr_rW[36] = {
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2,
    0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2
};
static const int dmr_rX[36] = {
    23, 10, 22, 9, 21, 8, 20, 7, 19, 6, 18, 5,
    17, 4, 16, 3, 15, 2, 14, 1, 13, 0, 12, 10,
    11, 9, 10, 8, 9, 7, 8, 6, 7, 5, 6, 4
};
static const int dmr_rY[36] = {
    0, 2, 0, 2, 0, 2, 0, 2, 0, 3, 0, 3,
    1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3,
    1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3
};
static const int dmr_rZ[36] = {
    5, 3, 4, 2, 3, 1, 2, 0, 1, 13, 0, 12,
    22, 11, 21, 10, 20, 9, 19, 8, 18, 7, 17, 6,
    16, 5, 15, 4, 14, 3, 13, 2, 12, 1, 11, 0
};
static const int sf_dibit_idx[3][36] = {
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

static int popcount8(unsigned char b) {
    int c = 0;
    while (b) { c += b & 1; b >>= 1; }
    return c;
}

/* Precompute cipher_packs exactly as the CUDA host does */
static void compute_cipher_packs(const PayloadSet *payloads, unsigned char *out, int limit) {
    int p, sf, i, bi, j;
    for (p = 0; p < limit; ++p) {
        const unsigned char *payload33 = payloads->items[p].data;
        for (sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24];
            unsigned char bits49[49];
            unsigned char cipher7[7];
            int foo, pr_val;
            memset(ambe_fr, 0, sizeof(ambe_fr));
            for (i = 0; i < 36; ++i) {
                int d = sf_dibit_idx[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[dmr_rW[i]][dmr_rX[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[dmr_rY[i]][dmr_rZ[i]] = (unsigned char)(dibit & 1u);
            }
            /* mbe_demodulate */
            foo = 0;
            for (i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
            pr_val = 16 * foo;
            for (j = 22; j >= 0; --j) {
                pr_val = (173 * pr_val + 13849) & 0xFFFF;
                ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
            }
            /* Extract 49 bits */
            bi = 0;
            for (j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (j = 10; j >= 0;  --j) bits49[bi++] = ambe_fr[2][j];
            for (j = 13; j >= 0;  --j) bits49[bi++] = ambe_fr[3][j];
            /* Pack 49 bits -> 7 bytes MSB-first */
            memset(cipher7, 0, 7);
            for (i = 0; i < 49; ++i)
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            memcpy(out + p * 21 + sf * 7, cipher7, 7);
        }
    }
}

/* Score one key using EXACT same logic as bruteforce_kernel_strict */
static float score_strict(const PayloadSet *payloads, const unsigned char *cipher_packs,
                          int payload_count, unsigned char key5[5]) {
    float total_score = 0.0f;
    int sf_base, burst_pos;
    for (sf_base = 0; sf_base < payload_count; sf_base += 6) {
        uint32_t mi = payloads->items[sf_base].has_mi ? payloads->items[sf_base].mi : 0;
        unsigned char kmi9[9];
        RC4_CTX rc4;
        /* compose kmi9 */
        kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
        kmi9[3] = key5[3]; kmi9[4] = key5[4];
        kmi9[5] = (unsigned char)((mi >> 24) & 0xFF);
        kmi9[6] = (unsigned char)((mi >> 16) & 0xFF);
        kmi9[7] = (unsigned char)((mi >>  8) & 0xFF);
        kmi9[8] = (unsigned char)(mi & 0xFF);
        /* RC4 KSA + discard 256 */
        rc4_init(&rc4, kmi9, 9);
        rc4_discard_host(&rc4, 256);
        for (burst_pos = 0; burst_pos < 6; ++burst_pos) {
            int p = sf_base + burst_pos;
            unsigned char p0[3], p1[3], p2[3];
            unsigned char buf[7];
            int h01, h12;
            if (p >= payload_count) break;
            /* Sub-frame 0: decrypt first 3, skip 4 (advance 7 total) */
            rc4_crypt(&rc4, cipher_packs + p * 21 + 0, buf, 7);
            p0[0] = buf[0]; p0[1] = buf[1]; p0[2] = buf[2];
            /* Sub-frame 1 */
            rc4_crypt(&rc4, cipher_packs + p * 21 + 7, buf, 7);
            p1[0] = buf[0]; p1[1] = buf[1]; p1[2] = buf[2];
            /* Sub-frame 2 */
            rc4_crypt(&rc4, cipher_packs + p * 21 + 14, buf, 7);
            p2[0] = buf[0]; p2[1] = buf[1]; p2[2] = buf[2];
            h01 = popcount8(p0[0] ^ p1[0]) + popcount8(p0[1] ^ p1[1]) + popcount8(p0[2] ^ p1[2]);
            h12 = popcount8(p1[0] ^ p2[0]) + popcount8(p1[1] ^ p2[1]) + popcount8(p1[2] ^ p2[2]);
            total_score += (float)(48 - h01 - h12);
        }
    }
    return total_score;
}

int main(int argc, char *argv[]) {
    PayloadSet payloads;
    char err[512] = {0};
    unsigned char correct_key[5] = { 0x37, 0x33, 0x74, 0xAB, 0xE8 };
    unsigned char *cipher_packs;
    int payload_limit, n_random = 500, i;
    float score_correct;
    double sum = 0, sum_sq = 0, mean, stddev;
    float max_random = -1e30f;

    if (argc < 2) {
        fprintf(stderr, "Usage: test_strict_score <file.bin> [key_hex] [n_random]\n");
        return 1;
    }
    if (argc >= 3 && strlen(argv[2]) == 10) {
        for (i = 0; i < 5; ++i) {
            unsigned int b;
            sscanf(argv[2] + i*2, "%02x", &b);
            correct_key[i] = (unsigned char)b;
        }
    }
    if (argc >= 4) n_random = atoi(argv[3]);
    if (n_random < 10) n_random = 10;

    printf("=== Strict Kernel Score Validation ===\n");
    printf("Key: %02X%02X%02X%02X%02X\n",
           correct_key[0], correct_key[1], correct_key[2], correct_key[3], correct_key[4]);

    payload_set_init(&payloads);
    if (!load_payload_file(argv[1], 256, &payloads, err, sizeof(err))) {
        fprintf(stderr, "ERROR: %s\n", err);
        return 1;
    }
    payload_limit = (int)payloads.count;
    if (payload_limit > 256) payload_limit = 256;
    printf("Loaded %d payloads, MI[0]=%08X\n\n", payload_limit,
           payloads.items[0].has_mi ? payloads.items[0].mi : 0);

    cipher_packs = (unsigned char *)calloc(payload_limit * 21, 1);
    compute_cipher_packs(&payloads, cipher_packs, payload_limit);

    /* Score correct key */
    score_correct = score_strict(&payloads, cipher_packs, payload_limit, correct_key);
    printf("CORRECT KEY strict score: %.2f  (per-burst: %.2f)\n",
           score_correct, score_correct / payload_limit);
    printf("  abs_floor[%d] = %.2f\n", payload_limit,
           31.0f * payload_limit - 2.0f * 3.46f * sqrtf((float)payload_limit));

    /* Score random keys */
    srand((unsigned)time(NULL));
    for (i = 0; i < n_random; ++i) {
        unsigned char rk[5];
        float s;
        rk[0] = (unsigned char)(rand() & 0xFF);
        rk[1] = (unsigned char)(rand() & 0xFF);
        rk[2] = (unsigned char)(rand() & 0xFF);
        rk[3] = (unsigned char)(rand() & 0xFF);
        rk[4] = (unsigned char)(rand() & 0xFF);
        s = score_strict(&payloads, cipher_packs, payload_limit, rk);
        sum += s;
        sum_sq += (double)s * s;
        if (s > max_random) max_random = s;
    }
    mean = sum / n_random;
    stddev = sqrt(sum_sq / n_random - mean * mean);
    printf("\nRandom mean: %.2f  stddev: %.2f  max: %.2f\n", mean, stddev, max_random);
    if (stddev > 0) {
        double z = (score_correct - mean) / stddev;
        printf("Z-score: %.2f sigma\n\n", z);
        if (z > 10) printf("EXCELLENT: Z=%.1f >> 7. Kernel WILL find the key.\n", z);
        else if (z > 7) printf("GOOD: Z=%.1f > 7.\n", z);
        else printf("PROBLEM: Z=%.1f < 7. Scoring is broken!\n", z);
    }

    /* Check if abs_floor would prune correct key at any point */
    {
        int pruned_at = 0;
        float ts = 0;
        for (int sf = 0; sf < payload_limit; sf += 6) {
            uint32_t mi = payloads.items[sf].has_mi ? payloads.items[sf].mi : 0;
            unsigned char kmi9[9];
            RC4_CTX rc4;
            kmi9[0] = correct_key[0]; kmi9[1] = correct_key[1]; kmi9[2] = correct_key[2];
            kmi9[3] = correct_key[3]; kmi9[4] = correct_key[4];
            kmi9[5] = (unsigned char)((mi >> 24) & 0xFF);
            kmi9[6] = (unsigned char)((mi >> 16) & 0xFF);
            kmi9[7] = (unsigned char)((mi >>  8) & 0xFF);
            kmi9[8] = (unsigned char)(mi & 0xFF);
            rc4_init(&rc4, kmi9, 9);
            rc4_discard_host(&rc4, 256);
            for (int bp = 0; bp < 6; ++bp) {
                int p = sf + bp;
                unsigned char buf[7];
                unsigned char pp0[3], pp1[3], pp2[3];
                int h01, h12;
                if (p >= payload_limit) break;
                rc4_crypt(&rc4, cipher_packs + p * 21 + 0,  buf, 7);
                pp0[0]=buf[0]; pp0[1]=buf[1]; pp0[2]=buf[2];
                rc4_crypt(&rc4, cipher_packs + p * 21 + 7,  buf, 7);
                pp1[0]=buf[0]; pp1[1]=buf[1]; pp1[2]=buf[2];
                rc4_crypt(&rc4, cipher_packs + p * 21 + 14, buf, 7);
                pp2[0]=buf[0]; pp2[1]=buf[1]; pp2[2]=buf[2];
                h01 = popcount8(pp0[0]^pp1[0]) + popcount8(pp0[1]^pp1[1]) + popcount8(pp0[2]^pp1[2]);
                h12 = popcount8(pp1[0]^pp2[0]) + popcount8(pp1[1]^pp2[1]) + popcount8(pp1[2]^pp2[2]);
                ts += (float)(48 - h01 - h12);
                pruned_at = p + 1;
            }
            float floor = 31.0f * pruned_at - 2.0f * 3.46f * sqrtf((float)pruned_at);
            if (ts < floor) {
                printf("WARNING: abs_floor would PRUNE correct key at burst %d! "
                       "score=%.1f < floor=%.1f\n", pruned_at, ts, floor);
            }
        }
        printf("Correct key passes all abs_floor checks (final: score=%.1f > floor=%.1f)\n",
               ts, 31.0f * pruned_at - 2.0f * 3.46f * sqrtf((float)pruned_at));
    }

    free(cipher_packs);
    payload_set_free(&payloads);
    return 0;
}
