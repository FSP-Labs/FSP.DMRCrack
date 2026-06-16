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
 * test_score_canonical.c - Pin the CANONICAL strict scoring metric.
 *
 * The strict per-key score MUST be, on every backend:
 *
 *     score = Sum_bursts ( 48 - HD(sf0,sf1) - HD(sf1,sf2) )      <- inter-frame Hamming
 *           + chi2 / processed_bursts                             <- bit-frequency chi2
 *
 * where chi2 = Sum_{b=0..23} (count_b - n/2)^2 over the 24 sub-frame-0 bits
 * (C0+C1) accumulated across the n = processed_bursts scored bursts.
 *
 * This is the ONLY blessed combination. It is what bruteforce_kernel_strict,
 * bruteforce_kernel_strict_ilp2, bruteforce_kernel_hytera, the OpenCL
 * kernel_strict, score_candidate_host, and the cpu_4way CPU-assist worker all
 * compute. Historically these diverged silently:
 *   - ilp2 used `chi2 * 0.1f`   (inflated NVIDIA scores ~12.6x)
 *   - cpu_4way used Hamming only (no chi2 term)
 * Recovery still worked (the correct key dominates either way) but scores were
 * not comparable across backends nor in the GPU<->CPU-assist max-merge. This
 * test is the regression guard against that divergence recurring: it pins the
 * canonical score of a known capture + key so any future drift is caught.
 *
 * Self-contained oracle (re-implements the pipeline independently, like
 * tests/test_hytera_ks.c) -- links only rc4.c + payload_io.c.
 *
 * Build: build_test_canonical.bat
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/payload_io.h"
#include "../include/rc4.h"
#include "../include/dmr_tables.h"

/* NO capture, key, or expected score is embedded in this source. They are all
 * supplied at runtime, because the test/ tree (the real capture + its key) is
 * gitignored and must never be committed. Invoke as:
 *   test_score_canonical <capture.bin> <key10hex> [expected_score]
 * With no args the test SKIPs (CI builds it for compile coverage but cannot run
 * it without the gitignored data). */
#define SCORE_TOL        3.0            /* float-vs-double + payload-order slack */
#define DOMINANCE_MIN    1500.0         /* key must beat the best random key by this */
#define N_RANDOM         500            /* random keys for the dominance check */

static const int dmr_rW[36] = DMR_RW_INIT;
static const int dmr_rX[36] = DMR_RX_INIT;
static const int dmr_rY[36] = DMR_RY_INIT;
static const int dmr_rZ[36] = DMR_RZ_INIT;
static const int sf_dibit_idx[3][36] = DMR_SF_DIBIT_IDX_INIT;

static int popcount8(unsigned char b) { int c = 0; while (b) { c += b & 1; b >>= 1; } return c; }

static void rc4_discard_host(RC4_CTX *ctx, int n) {
    unsigned char zeros[64] = {0}, tmp[64];
    while (n > 0) { int chunk = n > 64 ? 64 : n; rc4_crypt(ctx, zeros, tmp, chunk); n -= chunk; }
}

/* deinterleave -> mbe_demodulate -> extract 49 -> pack 7 (key-independent). */
static void compute_cipher_packs(const PayloadSet *payloads, unsigned char *out, int limit) {
    for (int p = 0; p < limit; ++p) {
        const unsigned char *payload33 = payloads->items[p].data;
        for (int sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24], bits49[49], cipher7[7];
            int foo, pr_val, bi;
            memset(ambe_fr, 0, sizeof(ambe_fr));
            for (int i = 0; i < 36; ++i) {
                int d = sf_dibit_idx[sf][i];
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[d >> 2] >> shift) & 0x3u);
                ambe_fr[dmr_rW[i]][dmr_rX[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[dmr_rY[i]][dmr_rZ[i]] = (unsigned char)(dibit & 1u);
            }
            foo = 0;
            for (int i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
            pr_val = 16 * foo;
            for (int j = 22; j >= 0; --j) { pr_val = (173 * pr_val + 13849) & 0xFFFF; ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15); }
            bi = 0;
            for (int j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (int j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (int j = 10; j >= 0;  --j) bits49[bi++] = ambe_fr[2][j];
            for (int j = 13; j >= 0;  --j) bits49[bi++] = ambe_fr[3][j];
            memset(cipher7, 0, 7);
            for (int i = 0; i < 49; ++i) cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            memcpy(out + p * 21 + sf * 7, cipher7, 7);
        }
    }
}

/* Canonical strict score: inter-frame Hamming + chi2/processed_bursts. */
static double score_canonical(const PayloadSet *payloads, const unsigned char *packs,
                              int payload_count, const unsigned char key5[5]) {
    double total = 0.0;
    long   bit_counts[24];
    int    processed = 0;
    memset(bit_counts, 0, sizeof(bit_counts));

    for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
        uint32_t mi = (uint32_t)(payloads->items[sf_base].has_mi ? payloads->items[sf_base].mi : 0);
        unsigned char kmi9[9];
        RC4_CTX rc4;
        kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
        kmi9[3] = key5[3]; kmi9[4] = key5[4];
        kmi9[5] = (unsigned char)((mi >> 24) & 0xFF);
        kmi9[6] = (unsigned char)((mi >> 16) & 0xFF);
        kmi9[7] = (unsigned char)((mi >>  8) & 0xFF);
        kmi9[8] = (unsigned char)( mi        & 0xFF);
        rc4_init(&rc4, kmi9, 9);
        rc4_discard_host(&rc4, 256);

        for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
            int p = sf_base + burst_pos;
            unsigned char p0[3], p1[3], p2[3], buf[7];
            int h01, h12;
            if (p >= payload_count) break;
            rc4_crypt(&rc4, packs + p * 21 + 0,  buf, 7); p0[0]=buf[0]; p0[1]=buf[1]; p0[2]=buf[2];
            rc4_crypt(&rc4, packs + p * 21 + 7,  buf, 7); p1[0]=buf[0]; p1[1]=buf[1]; p1[2]=buf[2];
            rc4_crypt(&rc4, packs + p * 21 + 14, buf, 7); p2[0]=buf[0]; p2[1]=buf[1]; p2[2]=buf[2];
            h01 = popcount8(p0[0]^p1[0]) + popcount8(p0[1]^p1[1]) + popcount8(p0[2]^p1[2]);
            h12 = popcount8(p1[0]^p2[0]) + popcount8(p1[1]^p2[1]) + popcount8(p1[2]^p2[2]);
            total += (double)(48 - h01 - h12);
            /* sub-frame-0 bit-frequency (C0+C1), MSB-first, same as the kernels */
            for (int b = 0; b < 8; ++b) bit_counts[b]    += (p0[0] >> (7-b)) & 1;
            for (int b = 0; b < 8; ++b) bit_counts[8+b]  += (p0[1] >> (7-b)) & 1;
            for (int b = 0; b < 8; ++b) bit_counts[16+b] += (p0[2] >> (7-b)) & 1;
            processed++;
        }
    }
    if (processed >= 6) {
        double half_n = (double)processed * 0.5, chi2 = 0.0;
        for (int b = 0; b < 24; ++b) { double dev = (double)bit_counts[b] - half_n; chi2 += dev * dev; }
        total += chi2 / (double)processed;
    }
    return total;
}

static void parse_key(const char *hex, unsigned char key[5]) {
    for (int i = 0; i < 5; ++i) { unsigned int b = 0; sscanf(hex + i * 2, "%02x", &b); key[i] = (unsigned char)b; }
}

int main(int argc, char *argv[]) {
    PayloadSet payloads;
    char err[512] = {0};
    unsigned char *packs;
    unsigned char key[5];
    double s_key, max_random = -1e30;
    int limit, fails = 0, have_expect = (argc >= 4);
    double expected = have_expect ? atof(argv[3]) : 0.0;

    if (argc < 3) {
        printf("Usage: test_score_canonical <capture.bin> <key10hex> [expected_score]\n"
               "  Computes the CANONICAL strict score (Hamming + chi2/processed_bursts)\n"
               "  of <key> over <capture.bin>, asserts it dominates %d random keys, and\n"
               "  (if given) pins it to [expected_score] +/- %.1f. No key/capture is\n"
               "  embedded here -- the test/ tree is gitignored.\n", N_RANDOM, (double)SCORE_TOL);
        return 0;   /* SKIP: builds in CI, runs locally against the gitignored fixture */
    }

    payload_set_init(&payloads);
    if (!load_payload_file(argv[1], 256, &payloads, err, sizeof(err))) {
        fprintf(stderr, "ERROR loading %s: %s\n", argv[1], err);
        return 2;
    }
    limit = (int)payloads.count; if (limit > 256) limit = 256;
    packs = (unsigned char *)calloc((size_t)limit * 21, 1);
    if (!packs) { fprintf(stderr, "OOM\n"); return 2; }
    compute_cipher_packs(&payloads, packs, limit);

    parse_key(argv[2], key);
    s_key = score_canonical(&payloads, packs, limit, key);

    /* Dominance: the supplied key must beat the best of N random keys by a wide
     * margin. Fixed seed -> reproducible. */
    srand(0x9E3779B9u);
    for (int r = 0; r < N_RANDOM; ++r) {
        unsigned char rk[5];
        double sr;
        for (int i = 0; i < 5; ++i) rk[i] = (unsigned char)(rand() & 0xFF);
        sr = score_canonical(&payloads, packs, limit, rk);
        if (sr > max_random) max_random = sr;
    }

    printf("Canonical strict score (Hamming + chi2/n), %d payloads\n", limit);
    printf("  supplied key : %.4f\n", s_key);
    if (have_expect) printf("  expected     : %.2f +/- %.1f\n", expected, (double)SCORE_TOL);
    printf("  best random  : %.4f   (dominance %.4f, min %.0f)\n",
           max_random, s_key - max_random, (double)DOMINANCE_MIN);

    if (have_expect && fabs(s_key - expected) > SCORE_TOL) { printf("FAIL: score off the expected canonical value\n"); fails++; }
    if (s_key - max_random < DOMINANCE_MIN)                { printf("FAIL: supplied key does not dominate random keys\n"); fails++; }

    free(packs);
    payload_set_free(&payloads);
    if (fails) { printf("\nRESULT: FAIL (%d)\n", fails); return 1; }
    printf("\nRESULT: PASS\n");
    return 0;
}
