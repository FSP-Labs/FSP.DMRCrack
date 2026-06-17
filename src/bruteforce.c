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

#include "../include/bruteforce.h"
#include "../include/platform.h"

#include <float.h>
#include <math.h>
#include <stdlib.h>

#include "../include/rc4.h"
#include "../include/dmr_tables.h"

typedef struct {
    BruteforceEngine *engine;
    uint64_t start_key;
    uint64_t end_key;
    int worker_index;
} WorkerCtx;

static void set_error(char *err, size_t err_len, const char *msg)
{
    if (err != NULL && err_len > 0) {
        size_t n = 0;
        while (msg[n] != '\0' && n + 1 < err_len) {
            err[n] = msg[n];
            n++;
        }
        err[n] = '\0';
    }
}

static void enter_snapshot_lock(const BruteforceEngine *engine)
{
    plat_mutex_lock((plat_mutex_t *)&engine->lock);
}

static void leave_snapshot_lock(const BruteforceEngine *engine)
{
    plat_mutex_unlock((plat_mutex_t *)&engine->lock);
}

static void close_worker_resources(BruteforceEngine *engine)
{
    int t;

    if (engine->thread_handles != NULL) {
        for (t = 0; t < engine->cfg.thread_count; ++t) {
            plat_thread_close(engine->thread_handles[t]);
        }
        free(engine->thread_handles);
        engine->thread_handles = NULL;
    }

    free(engine->workers);
    engine->workers = NULL;

    free(engine->cpu_cipher_packs);
    engine->cpu_cipher_packs = NULL;
    engine->cpu_pack_lines = 0;
    engine->cpu_mode_correct = 0;
}

static void key_to_5bytes(uint64_t key, unsigned char out[5])
{
    out[0] = (unsigned char)((key >> 32) & 0xFFu);
    out[1] = (unsigned char)((key >> 24) & 0xFFu);
    out[2] = (unsigned char)((key >> 16) & 0xFFu);
    out[3] = (unsigned char)((key >> 8) & 0xFFu);
    out[4] = (unsigned char)(key & 0xFFu);
}


/*
 * ==========================================================================
 * Scoring heuristics for DMR Basic Privacy (ARC4 40-bit) -- v3
 * ==========================================================================
 *
 * FUNDAMENTAL PRINCIPLE:
 * In DMR, the 216 bits of the burst are INTERLEAVED (BPTC), so
 * consecutive payload bytes do NOT correspond to specific AMBE+2
 * fields. Therefore, patterns like "silence frame" (B9E88148) at
 * fixed offsets are USELESS.
 *
 * The ONLY exploitable signal is the INTRA-PAYLOAD structure:
 * statistical relationships between positions within the same payload,
 * which change with the keystream mask of each candidate key.
 *
 * METRICS that DO discriminate:
 *
 * A) MULTI-LAG AUTOCORRELATION: Hamming distance between bytes at different
 *    lags (distances) within the payload. Structured data tends to
 *    have autocorrelation at certain lags; random data does not.
 *
 * B) BIT TRANSITION RATE: Count 0->1 and 1->0 changes in the bit
 *    stream. Interleaved AMBE data has transition rates that differ
 *    from the theoretical 50% of random data.
 *
 * C) BIT RATIO (ones distribution): With the correct key, the plaintext
 *    has a bit ratio different from the 50% of random data.
 *    NOTE: bit ratio PER PAYLOAD does depend on the key (the XOR mask
 *    flips specific bits, changing the popcount). The effect is weak
 *    but cumulative.
 *
 * USELESS METRICS (removed):
 *
 * - Silence frame matching: requires de-interleaving which we do not perform
 * - Cross-payload hamming: mathematically invariant to the key (RC4)
 * - Per-position byte statistics: invariant (XOR with constant = bijection)
 * - Byte quartile distribution: invariant
 * ==========================================================================
 */

#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* Portable popcount for counting set bits */
static int popcount_byte(unsigned char b)
{
    int c = 0;
    while (b) { c += (b & 1); b >>= 1; }
    return c;
}

/* DMR AMBE de-interleave tables (verified identical to DSD-FME dmr_const.h) */
/* De-interleave tables -- values shared via include/dmr_tables.h */
static const int rW_cpu[36] = DMR_RW_INIT;
static const int rX_cpu[36] = DMR_RX_INIT;
static const int rY_cpu[36] = DMR_RY_INIT;
static const int rZ_cpu[36] = DMR_RZ_INIT;
static const int sf_dibit_idx_cpu[3][36] = DMR_SF_DIBIT_IDX_INIT;

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

/*
 * ==========================================================================
 * Precomputed-pack fast path (mode_policy >= 2)
 * ==========================================================================
 * The de-interleave -> mbe_demodulate -> extract -> pack step depends only on
 * the payload, never on the candidate key. The original score_burst_correct_cpu
 * recomputed it for every one of the ~10^12 keys. Here it is hoisted out and
 * precomputed once per scan into a 21-byte "cipher pack" per line (3 sub-frames
 * x 7 bytes), exactly like precompute_cipher_packs() does for the GPU. The
 * per-key hot loop then collapses to RC4 + inter-frame Hamming, and within a
 * superframe a single KSA + continuous PRGA replaces six per-burst KSAs.
 */
static void precompute_packs_cpu(const PayloadSet *payloads, size_t line_count,
                                 unsigned char *out /* line_count * 21 */)
{
    size_t p;
    int sf, i, j, bi;
    for (p = 0; p < line_count; ++p) {
        const unsigned char *payload33 = payloads->items[p].data;
        unsigned char *dst = out + p * 21;
        if (payloads->items[p].len < 33) { memset(dst, 0, 21); continue; }
        for (sf = 0; sf < 3; ++sf) {
            unsigned char ambe_fr[4][24];
            unsigned char bits49[49];
            unsigned char cipher7[7];
            int foo, pr_val;
            memset(ambe_fr, 0, sizeof(ambe_fr));
            for (i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_cpu[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[rW_cpu[i]][rX_cpu[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[rY_cpu[i]][rZ_cpu[i]] = (unsigned char)(dibit & 1u);
            }
            foo = 0;
            for (i = 23; i >= 12; --i) foo = (foo << 1) | (int)ambe_fr[0][i];
            pr_val = 16 * foo;
            for (j = 22; j >= 0; --j) {
                pr_val = (173 * pr_val + 13849) & 0xFFFF;
                ambe_fr[1][j] ^= (unsigned char)(pr_val >> 15);
            }
            bi = 0;
            for (j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];
            memset(cipher7, 0, 7);
            for (i = 0; i < 49; ++i)
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            memcpy(dst + sf * 7, cipher7, 7);
        }
    }
}

/*
 * Score a candidate key from precomputed packs. Bit-for-bit identical to the
 * mode_policy>=2 branch of score_candidate() for any key, but ~Nx faster.
 * When prune != 0, the per-burst absolute floor (33k - 6.92*sqrt(k), the same
 * threshold the GPU kernel applies via d_abs_floor[]) rejects a key the moment
 * its running score can no longer belong to the correct key; a pruned key
 * returns -DBL_MAX so the caller skips it. With prune == 0 the full score is
 * always returned.
 */
static double score_packed_cpu(const unsigned char *packs,
                               const PayloadSet *payloads,
                               size_t line_count,
                               const unsigned char key5[5],
                               int prune)
{
    double total = 0.0;
    int processed = 0;
    long bit_counts[24];
    size_t sf_base;
    memset(bit_counts, 0, sizeof(bit_counts));

    for (sf_base = 0; sf_base < line_count; sf_base += 6) {
        uint32_t mi = (uint32_t)(payloads->items[sf_base].has_mi
                    ? payloads->items[sf_base].mi : payloads->global_mi);
        unsigned char kmi9[9];
        RC4_CTX rc4;
        int bp;

        kmi9[0] = key5[0]; kmi9[1] = key5[1]; kmi9[2] = key5[2];
        kmi9[3] = key5[3]; kmi9[4] = key5[4];
        kmi9[5] = (unsigned char)((mi >> 24) & 0xFFu);
        kmi9[6] = (unsigned char)((mi >> 16) & 0xFFu);
        kmi9[7] = (unsigned char)((mi >>  8) & 0xFFu);
        kmi9[8] = (unsigned char)(mi & 0xFFu);

        /* One KSA + discard(256) per superframe; the six bursts then stream
         * consecutively (burst b consumes keystream bytes 257+b*21 .. 277+b*21),
         * identical to rc4_init(kmi9) + rc4_discard(256 + b*21) done per burst. */
        rc4_init(&rc4, kmi9, 9);
        rc4_discard_cpu(&rc4, 256);

        for (bp = 0; bp < 6; ++bp) {
            size_t pidx = sf_base + (size_t)bp;
            const unsigned char *cp;
            unsigned char buf[7];
            unsigned char d0[3], d1[3], d2[3];
            int h01, h12;
            if (pidx >= line_count) break;
            cp = packs + pidx * 21;

            rc4_crypt(&rc4, cp + 0,  buf, 7); d0[0] = buf[0]; d0[1] = buf[1]; d0[2] = buf[2];
            rc4_crypt(&rc4, cp + 7,  buf, 7); d1[0] = buf[0]; d1[1] = buf[1]; d1[2] = buf[2];
            rc4_crypt(&rc4, cp + 14, buf, 7); d2[0] = buf[0]; d2[1] = buf[1]; d2[2] = buf[2];

            h01 = popcount_byte(d0[0] ^ d1[0]) + popcount_byte(d0[1] ^ d1[1])
                + popcount_byte(d0[2] ^ d1[2]);
            h12 = popcount_byte(d1[0] ^ d2[0]) + popcount_byte(d1[1] ^ d2[1])
                + popcount_byte(d1[2] ^ d2[2]);
            total += (double)(48 - h01 - h12);
            { int _b;
              for (_b = 0; _b < 8; ++_b) bit_counts[_b]      += (d0[0] >> (7 - _b)) & 1;
              for (_b = 0; _b < 8; ++_b) bit_counts[8 + _b]  += (d0[1] >> (7 - _b)) & 1;
              for (_b = 0; _b < 8; ++_b) bit_counts[16 + _b] += (d0[2] >> (7 - _b)) & 1; }
            processed++;

            if (prune) {
                double floor_v = 33.0 * (double)processed
                               - 6.92 * sqrt((double)processed);
                if (total < floor_v) return -DBL_MAX;
            }
        }
    }
    /* Canonical chi2/processed_bursts bit-frequency term (matches the GPU/OpenCL/
     * host scorers). Pruning above stays Hamming-only, exactly like the kernels. */
    if (processed >= 6) {
        double half_n = (double)processed * 0.5, chi2 = 0.0;
        int _b;
        for (_b = 0; _b < 24; ++_b) { double dev = (double)bit_counts[_b] - half_n; chi2 += dev * dev; }
        total += chi2 / (double)processed;
    }
    return total;
}

/*
 * Correct scoring pipeline for a single burst (33-byte payload).
 * Uses the proven DSD-FME / mbelib algorithm:
 *   deinterleave -> mbe_demodulate -> extract -> pack -> RC4 -> unpack -> score
 */
static double score_burst_correct_cpu(
    const unsigned char *payload33,
    const unsigned char key5[5],
    uint32_t mi,
    int burst_pos,
    unsigned char sf0_out[24])
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

            /* De-interleave */
            for (i = 0; i < 36; ++i) {
                int d = sf_dibit_idx_cpu[sf][i];
                int byte_idx = d >> 2;
                int shift = (3 - (d & 3)) * 2;
                unsigned char dibit = (unsigned char)((payload33[byte_idx] >> shift) & 0x3u);
                ambe_fr[rW_cpu[i]][rX_cpu[i]] = (unsigned char)((dibit >> 1) & 1u);
                ambe_fr[rY_cpu[i]][rZ_cpu[i]] = (unsigned char)(dibit & 1u);
            }

            /* mbe_demodulate */
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

            /* Extract 49 bits */
            bi = 0;
            for (j = 23; j >= 12; --j) bits49[bi++] = ambe_fr[0][j];
            for (j = 22; j >= 11; --j) bits49[bi++] = ambe_fr[1][j];
            for (j = 10; j >=  0; --j) bits49[bi++] = ambe_fr[2][j];
            for (j = 13; j >=  0; --j) bits49[bi++] = ambe_fr[3][j];

            /* Pack 49 bits -> 7 bytes */
            memset(cipher7, 0, 7);
            for (i = 0; i < 49; ++i) {
                cipher7[i >> 3] |= (unsigned char)((bits49[i] & 1u) << (7 - (i & 7)));
            }

            /* RC4 decrypt 7 bytes */
            rc4_crypt(&rc4, cipher7, plain7, 7);

            /* Unpack first 24 bits */
            for (i = 0; i < 24; ++i) {
                dec24[sf][i] = (unsigned char)((plain7[i >> 3] >> (7 - (i & 7))) & 1u);
            }
        }
    }

    /* Expose sub-frame-0 bits (C0+C1) so the caller can accumulate the canonical
     * chi2 bit-frequency term across bursts. */
    if (sf0_out) { for (i = 0; i < 24; ++i) sf0_out[i] = dec24[0][i]; }

    /* Inter-frame Hamming on first 24 bits (C0+C1) */
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

    /* Determine mode policy: use correct pipeline if payloads have MI+RC4 */
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

    /* Correct pipeline path for payloads with MI. Canonical metric:
     * Hamming + chi2/processed_bursts (matches the GPU/OpenCL/host scorers). */
    if (mode_policy >= 2) {
        long bit_counts[24];
        int processed = 0, b;
        memset(bit_counts, 0, sizeof(bit_counts));
        for (line_idx = 0; line_idx < line_count; ++line_idx) {
            const PayloadLine *line = &payloads->items[line_idx];
            uint32_t mi = (uint32_t)(line->has_mi ? line->mi : payloads->global_mi);
            int burst_pos = (int)(line_idx % 6);
            if (line->len >= 33) {
                unsigned char sf0[24];
                score += score_burst_correct_cpu(line->data, key, mi, burst_pos, sf0);
                for (b = 0; b < 24; ++b) bit_counts[b] += sf0[b];
                processed++;
            }
        }
        if (processed >= 6) {
            double half_n = (double)processed * 0.5, chi2 = 0.0;
            for (b = 0; b < 24; ++b) { double dev = (double)bit_counts[b] - half_n; chi2 += dev * dev; }
            score += chi2 / (double)processed;
        }
        return score;
    }

    /* Legacy path: plain RC4 without MI */
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
        if (bytes_to_test == 0) {
            continue;
        }
        if (bytes_to_test > sizeof(out)) {
            bytes_to_test = sizeof(out);
        }

        rc4 = rc4_base;
        rc4_crypt(&rc4, line->data, out, bytes_to_test);

        /* ---------------------------------------------------------------
         * A. MULTI-LAG AUTOCORRELATION
         *
         * For each lag l (1..max_lag), compute the Hamming distance
         * between out[0..n-l-1] and out[l..n-1].
         *
         * With structured data: certain lags show low Hamming distance
         * (periodic structure from interleaving).
         * With random data: Hamming ~50% for ALL lags.
         *
         * We sum the squared deviation of the Hamming distance from the
         * expected value (n_bits/2). Greater deviation = more structure.
         * ---------------------------------------------------------------*/
        {
            /* Lags of interest: 1-13 (cover up to half-payload) */
            int lag;
            int max_lag = (int)(bytes_to_test / 2);
            if (max_lag > 13) max_lag = 13;
            double autocorr_score = 0.0;

            for (lag = 1; lag <= max_lag; ++lag) {
                int n_bytes = (int)(bytes_to_test) - lag;
                int hamming = 0;
                int expected;
                int deviation;
                int j;

                for (j = 0; j < n_bytes; ++j) {
                    hamming += popcount_byte(out[j] ^ out[j + lag]);
                }
                /* Expected hamming for random: n_bytes * 4 */
                expected = n_bytes * 4;
                deviation = hamming - expected;
                /* Use absolute deviation - both positive and negative
                 * deviations indicate structure */
                if (deviation < 0) deviation = -deviation;
                autocorr_score += (double)deviation;
            }
            /* Scale: weight autocorrelation heavily */
            local_score += autocorr_score * 2.5;
        }

        /* ---------------------------------------------------------------
         * B. BIT TRANSITION RATE
         *
         * Count the number of transitions (0->1 or 1->0) in the
         * decrypted payload bit stream.
         *
         * Random data: ~50% of consecutive bit pairs are transitions
         * (expected = (n_bits - 1) / 2).
         * AMBE data: typically different (fields with bit runs).
         *
         * A significant deviation from 50% indicates structured data.
         * ---------------------------------------------------------------*/
        {
            int transitions = 0;
            int total_bit_pairs = (int)(bytes_to_test * 8) - 1;
            int expected_transitions;
            int deviation;

            for (i = 0; i < bytes_to_test; ++i) {
                unsigned char b = out[i];
                /* Transitions within this byte (7 bit pairs) */
                int k;
                for (k = 0; k < 7; ++k) {
                    int bit_k = (b >> (7 - k)) & 1;
                    int bit_k1 = (b >> (6 - k)) & 1;
                    if (bit_k != bit_k1) transitions++;
                }
                /* Transition between last bit of this byte and first of next */
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

        /* ---------------------------------------------------------------
         * C. BIT RATIO (ones distribution)
         *
         * Data encrypted with the wrong key produces ~50% ones.
         * With the correct key, the plaintext (interleaved AMBE) may
         * have a ratio consistently > 50% or < 50%.
         *
         * NOTE: bit ratio PER PAYLOAD depends on the key because the
         * XOR mask flips specific bits, changing the popcount.
         * The effect is CUMULATIVE across many payloads.
         *
         * We use squared deviation from 50% for greater sensitivity.
         * ---------------------------------------------------------------*/
        {
            int total_bits = 0;
            double bit_ratio, dev;
            for (i = 0; i < bytes_to_test; ++i) {
                total_bits += popcount_byte(out[i]);
            }
            bit_ratio = (double)total_bits / (double)(bytes_to_test * 8);
            dev = bit_ratio - 0.5;
            /* Square the deviation for greater sensitivity, then scale */
            local_score += dev * dev * (double)(bytes_to_test * 8) * 60.0;
        }

        /* ---------------------------------------------------------------
         * D. BYTE PAIR CONSISTENCY
         *
         * For structured data, certain byte pairs tend to have specific
         * relationships. We compute the variance of XOR values for
         * pairs (i, i+offset) at specific offsets.
         * High XOR variance = random data. Low variance = structure.
         * ---------------------------------------------------------------*/
        if (bytes_to_test >= 10) {
            /* Check a few strategic offsets */
            static const int pair_offsets[] = { 1, 3, 9 };
            int p;
            for (p = 0; p < 3 && pair_offsets[p] < (int)bytes_to_test; ++p) {
                int off = pair_offsets[p];
                int n_pairs = (int)bytes_to_test - off;
                int xor_sum = 0;
                double mean_xor, var_xor;
                int j;

                /* Compute mean of XOR values (as integers 0-255) */
                for (j = 0; j < n_pairs; ++j) {
                    xor_sum += (int)(out[j] ^ out[j + off]);
                }
                mean_xor = (double)xor_sum / (double)n_pairs;

                /* Compute variance */
                var_xor = 0.0;
                for (j = 0; j < n_pairs; ++j) {
                    double d = (double)(out[j] ^ out[j + off]) - mean_xor;
                    var_xor += d * d;
                }
                var_xor /= (double)n_pairs;

                /* Random XOR of two uniform bytes: mean=127.5, var~5440
                 * Structured data: lower or higher variance */
                {
                    double random_var = 5440.0;
                    double var_dev = var_xor - random_var;
                    if (var_dev < 0) var_dev = -var_dev;
                    local_score += var_dev * 0.008;
                }
            }
        }

        /* ---------------------------------------------------------------
         * E. OBVIOUS GARBAGE PENALTY
         *
         * If the decryption produces very long runs of identical bytes
         * or too many 0x00/0xFF, it is probably garbage.
         * This acts as a safety net to discard clearly bad keys,
         * not as a primary discriminator.
         * ---------------------------------------------------------------*/
        {
            int max_run = 1, run = 1;
            for (i = 1; i < bytes_to_test; ++i) {
                if (out[i] == out[i - 1]) {
                    run++;
                    if (run > max_run) max_run = run;
                } else {
                    run = 1;
                }
            }
            if (max_run > 5) {
                local_score -= (max_run - 5) * 50.0;
            }
        }

        score += local_score;
    }
    } /* end legacy path */

    return score;
}

static PLAT_THREAD_RETURN_T PLAT_THREAD_CALL worker_proc(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;
    BruteforceEngine *engine = ctx->engine;
    uint64_t k;
    uint64_t local_count = 0;
    double local_best_score = -DBL_MAX;

    /* Fast path for MOTOTRBO RC4 + MI captures: precomputed packs let the hot
     * loop run RC4 + Hamming only, with hashcat-style abs_floor pruning. Pruning
     * is gated on a wide keyspace so narrow ranges (mask/known-prefix) still
     * score in full and never risk rejecting the sought key. */
    const int            correct = engine->cpu_mode_correct;
    const unsigned char *packs   = engine->cpu_cipher_packs;
    const size_t         scn     = (size_t)engine->cfg.sample_lines;
    const int            prune   =
        (correct && (engine->cfg.end_key - engine->cfg.start_key) > (1ULL << 20)) ? 1 : 0;

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
        }

        key_to_5bytes(k, key_bytes);
        if (correct) {
            score = score_packed_cpu(packs, engine->payloads, scn, key_bytes, prune);
            if (score == -DBL_MAX) {          /* pruned: cannot be the best key */
                local_count++;
                if ((local_count & 0x3FFu) == 0)
                    plat_atomic64_add(&engine->keys_tested, 1024LL);
                if (k == ctx->end_key) break;
                continue;
            }
        } else {
            score = score_candidate(engine->payloads, engine->cfg.sample_lines,
                                    engine->cfg.sample_bytes, key_bytes);
        }

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
        if ((local_count & 0x3FFu) == 0) {
            plat_atomic64_add(&engine->keys_tested, 1024LL);
        }

        if (k == ctx->end_key) break;
    }

    if ((local_count & 0x3FFu) != 0) {
        plat_atomic64_add(&engine->keys_tested, (int64_t)(local_count & 0x3FFu));
    }

    if (plat_atomic32_inc(&engine->finished_threads) == engine->cfg.thread_count) {
        if (plat_atomic32_load(&engine->stop_requested) == 0) {
            plat_atomic32_store(&engine->search_completed, 1);
        }
        plat_atomic32_store(&engine->running, 0);
        plat_event_set(&engine->pause_event);
    }

    PLAT_THREAD_RETURN;
}

void bruteforce_engine_init(BruteforceEngine *engine)
{
    memset(engine, 0, sizeof(*engine));
    plat_mutex_init(&engine->lock);
    plat_hrfreq_init(&engine->qpc_freq);
    plat_event_init(&engine->pause_event, 1); /* signaled - workers run immediately */
}

void bruteforce_engine_destroy(BruteforceEngine *engine)
{
    bruteforce_stop(engine);
    close_worker_resources(engine);
    plat_event_destroy(&engine->pause_event);
    plat_mutex_destroy(&engine->lock);
}

int bruteforce_start(
    BruteforceEngine *engine,
    const BruteforceConfig *cfg,
    const PayloadSet *payloads,
    char *err,
    size_t err_len)
{
    int t;
    uint64_t total;
    uint64_t chunk;
    uint64_t rem;
    uint64_t start;

    if (plat_atomic32_load(&engine->running) != 0) {
        set_error(err, err_len, "A search is already running");
        return 0;
    }

    close_worker_resources(engine);

    if (cfg->thread_count <= 0 || cfg->thread_count > 64) {
        set_error(err, err_len, "Invalid thread count (must be 1..64)");
        return 0;
    }
    if (cfg->start_key > cfg->end_key) {
        set_error(err, err_len, "Start key must be <= end key");
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

    engine->cfg = *cfg;
    if (engine->cfg.sample_bytes <= 0) engine->cfg.sample_bytes = 33;
    if (engine->cfg.sample_lines <= 0 || (size_t)engine->cfg.sample_lines > payloads->count)
        engine->cfg.sample_lines = (int)payloads->count;
    engine->payloads = payloads;

    /* If the capture is MOTOTRBO RC4 + MI (>= 1/3 of scored lines), precompute
     * the key-independent cipher packs once so every worker runs the fast
     * RC4 + Hamming scorer instead of re-deriving the AMBE packing per key.
     * Same classification rule score_candidate() uses to pick mode_policy 2. */
    engine->cpu_mode_correct = 0;
    engine->cpu_cipher_packs = NULL;
    engine->cpu_pack_lines = 0;
    {
        size_t lc = (size_t)engine->cfg.sample_lines;
        size_t li;
        int mi_rc4 = 0;
        for (li = 0; li < lc; ++li) {
            const PayloadLine *ln = &payloads->items[li];
            uint8_t alg = ln->has_algid ? ln->algid : payloads->global_algid;
            if (ln->has_mi && is_rc4_alg_cpu(alg)) mi_rc4++;
        }
        if (lc > 0 && mi_rc4 * 3 >= (int)lc) {
            engine->cpu_cipher_packs = (unsigned char *)malloc(lc * 21);
            if (engine->cpu_cipher_packs != NULL) {
                precompute_packs_cpu(payloads, lc, engine->cpu_cipher_packs);
                engine->cpu_pack_lines = (int)lc;
                engine->cpu_mode_correct = 1;
            }
            /* malloc failure simply falls back to the per-key scorer below */
        }
    }

    engine->thread_handles = (plat_thread_t *)calloc((size_t)engine->cfg.thread_count, sizeof(plat_thread_t));
    engine->workers = calloc((size_t)engine->cfg.thread_count, sizeof(WorkerCtx));
    if (engine->thread_handles == NULL || engine->workers == NULL) {
        close_worker_resources(engine);
        set_error(err, err_len, "Out of memory allocating worker threads");
        return 0;
    }
    WorkerCtx *workers = (WorkerCtx *)engine->workers;

    plat_event_set(&engine->pause_event); /* ensure threads won't block initially */

    total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    if ((uint64_t)engine->cfg.thread_count > total)
        engine->cfg.thread_count = (int)total;
    chunk = total / (uint64_t)engine->cfg.thread_count;
    rem   = total % (uint64_t)engine->cfg.thread_count;
    start = engine->cfg.start_key;

    plat_atomic64_store(&engine->keys_tested, 0LL);
    plat_atomic32_store(&engine->stop_requested, 0);
    plat_atomic32_store(&engine->paused, 0);
    plat_atomic32_store(&engine->finished_threads, 0);
    plat_atomic32_store(&engine->search_completed, 0);
    engine->best_key = engine->cfg.start_key;
    engine->best_score = -DBL_MAX;
    plat_hrtimer_now(&engine->qpc_start);
    plat_atomic32_store(&engine->running, 1);

    for (t = 0; t < engine->cfg.thread_count; ++t) {
        uint64_t this_count = chunk + ((uint64_t)t < rem ? 1ull : 0ull);
        uint64_t end = start + this_count - 1ull;

        workers[t].engine = engine;
        workers[t].start_key = start;
        workers[t].end_key = end;
        workers[t].worker_index = t;

        if (plat_thread_create(&engine->thread_handles[t], worker_proc, &workers[t]) != 0) {
            plat_atomic32_store(&engine->running, 0);
            plat_atomic32_store(&engine->stop_requested, 1);
            plat_event_set(&engine->pause_event);
            bruteforce_stop(engine);
            set_error(err, err_len, "Error creating brute-force threads");
            return 0;
        }

        start = end + 1ull;
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

    plat_threads_join(engine->thread_handles, engine->cfg.thread_count);
    plat_atomic32_store(&engine->running, 0);
    close_worker_resources(engine);
}

void bruteforce_get_snapshot(const BruteforceEngine *engine, BruteforceSnapshot *out)
{
    plat_hrtimer_t now;
    double elapsed;
    uint64_t keys;
    uint64_t total;

    keys = (uint64_t)plat_atomic64_load((plat_atomic64_t *)&engine->keys_tested);
    total = 0;
    if (engine->cfg.end_key >= engine->cfg.start_key) {
        total = (engine->cfg.end_key - engine->cfg.start_key) + 1ull;
    }

    plat_hrtimer_now(&now);
    elapsed = plat_hrtimer_elapsed_s(&engine->qpc_start, &now, &engine->qpc_freq);
    if (elapsed < 0.0) elapsed = 0.0;

    out->keys_tested = keys;
    out->total_keys = total;
    enter_snapshot_lock(engine);
    out->best_key = engine->best_key;
    out->best_score = engine->best_score;
    leave_snapshot_lock(engine);
    out->elapsed_seconds = elapsed;
    out->running  = (int)plat_atomic32_load((plat_atomic32_t *)&engine->running);
    out->paused   = (int)plat_atomic32_load((plat_atomic32_t *)&engine->paused);
    out->finished = (int)plat_atomic32_load((plat_atomic32_t *)&engine->search_completed);

    if (elapsed > 0.0) {
        out->keys_per_second = (double)keys / elapsed;
    } else {
        out->keys_per_second = 0.0;
    }

    if (out->keys_per_second > 0.0 && total > keys) {
        out->eta_seconds = (double)(total - keys) / out->keys_per_second;
    } else {
        out->eta_seconds = -1.0;
    }
}

double bruteforce_test_score(
    const PayloadSet *payloads,
    int sample_lines,
    int sample_bytes,
    const unsigned char key[5])
{
    return score_candidate(payloads, sample_lines, sample_bytes, key);
}
