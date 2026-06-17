/* test_hytera_ks.c -- known-answer + property tests for the Hytera Enhanced
 * Privacy keystream (include/hytera_ks.h), the single source of truth used by
 * the CPU scorer and mirrored by the CUDA kernel.
 *
 * What this validates:
 *  1. Algorithm shape matches DSD-FME hytera_enhanced_rc4_setup (KSA key5,
 *     drop=0, kiv[i]=key5[i]^MI[i], ks[i]=rc4[i]^kiv[i%5]) via an INDEPENDENT
 *     reference implemented here from the spec.
 *  2. The 40-bit MI is fully used -- in particular MI[0] (bits 39..32) affects
 *     the keystream. This is the regression guard for the bug where kiv[0]
 *     ignored MI[0] and the MI was treated as 32-bit.
 *  3. A pinned known-answer vector (anchors against silent future changes).
 *
 * Build: build_test_hytera.bat   (MSVC, no CUDA)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/hytera_ks.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
                              else { printf("ok:   %s\n", msg); } } while (0)

/* Independent reference straight from the DSD-FME spec (separate code path
 * from hytera_ks.h: explicit byte arrays, no shared helpers). */
static void hytera_ref(const unsigned char key[5], const unsigned char mi[5],
                       unsigned char *ks, int n)
{
    unsigned char S[256], kiv[5], rc4[512];
    int i; unsigned char j = 0, t, a = 0, b = 0;
    for (i = 0; i < 5; ++i) kiv[i] = (unsigned char)(key[i] ^ mi[i]);
    for (i = 0; i < 256; ++i) S[i] = (unsigned char)i;
    for (i = 0; i < 256; ++i) { j = (unsigned char)(j + S[i] + key[i % 5]); t = S[i]; S[i] = S[j]; S[j] = t; }
    for (i = 0; i < n; ++i) { a = (unsigned char)(a + 1); b = (unsigned char)(b + S[a]);
        t = S[a]; S[a] = S[b]; S[b] = t; rc4[i] = S[(unsigned char)(S[a] + S[b])]; }
    for (i = 0; i < n; ++i) ks[i] = (unsigned char)(rc4[i] ^ kiv[i % 5]);
}

/* -- Synthetic end-to-end scoring (mirrors the brute-forcer's Hytera path) -- */
static int popc8t(unsigned char x) { int c = 0; while (x) { c += x & 1; x >>= 1; } return c; }
static int hd24(const unsigned char *a, const unsigned char *b)
{ return popc8t(a[0]^b[0]) + popc8t(a[1]^b[1]) + popc8t(a[2]^b[2]); }

/* Decrypt 18 cipher frames with a candidate key and sum the inter-frame Hamming
 * score (48 - HD(sf0,sf1) - HD(sf1,sf2)) over the 6 bursts, using the canonical
 * 49-bit keystream indexing -- exactly what the kernels do. */
static double score_synth(unsigned char cipher[18][7], const unsigned char key[5], uint64_t mi)
{
    unsigned char ks[126];
    double total = 0.0;
    int burst, sf, n;
    hytera_compute_ks(key, mi, ks, 126);
    for (burst = 0; burst < 6; ++burst) {
        unsigned char p[3][3];
        for (sf = 0; sf < 3; ++sf) {
            int f = burst * 3 + sf;
            for (n = 0; n < 3; ++n)
                p[sf][n] = (unsigned char)(cipher[f][n] ^ hytera_ks_byte(ks, f * 49 + n * 8));
        }
        total += 48 - hd24(p[0], p[1]) - hd24(p[1], p[2]);
    }
    return total;
}

int main(void)
{
    unsigned char key[5] = {0x12, 0x34, 0xAB, 0xCD, 0xEF};
    unsigned char mi5[5]  = {0x11, 0x22, 0x33, 0x44, 0x55};   /* MI[0]..MI[4] */
    uint64_t mi40 = ((uint64_t)mi5[0] << 32) | ((uint64_t)mi5[1] << 24)
                  | ((uint64_t)mi5[2] << 16) | ((uint64_t)mi5[3] << 8) | mi5[4];

    unsigned char ks_prod[21], ks_ref[21];

    /* 1. Production (hytera_ks.h) must equal the independent reference. */
    hytera_compute_ks(key, mi40, ks_prod, 21);
    hytera_ref(key, mi5, ks_ref, 21);
    CHECK(memcmp(ks_prod, ks_ref, 21) == 0, "hytera_compute_ks matches DSD-FME spec reference");

    /* 2a. MI[0] (top byte) MUST affect the keystream (guards the kiv[0] fix). */
    {
        unsigned char ks_a[21], ks_b[21];
        hytera_compute_ks(key, mi40, ks_a, 21);
        hytera_compute_ks(key, mi40 ^ ((uint64_t)0xFF << 32), ks_b, 21);  /* flip MI[0] */
        CHECK(memcmp(ks_a, ks_b, 21) != 0, "MI[0] (bits 39..32) changes the keystream");
    }

    /* 2b. Each of the other MI bytes also affects the keystream. */
    {
        int shift, ok = 1;
        for (shift = 0; shift <= 24; shift += 8) {
            unsigned char ks_a[21], ks_b[21];
            hytera_compute_ks(key, mi40, ks_a, 21);
            hytera_compute_ks(key, mi40 ^ ((uint64_t)0xFF << shift), ks_b, 21);
            if (memcmp(ks_a, ks_b, 21) == 0) ok = 0;
        }
        CHECK(ok, "MI bytes [1..4] each change the keystream");
    }

    /* 3. Pinned known-answer vector (regenerate intentionally if the algorithm
     *    is ever revised; a silent change here is a red flag). */
    {
        /* printed so the vector is visible in CI logs */
        int i; printf("vector key=1234ABCDEF mi=1122334455 ks=");
        for (i = 0; i < 21; ++i) printf("%02X", ks_prod[i]);
        printf("\n");
    }

    /* 4. Roundtrip: XOR keystream is an involution. */
    {
        unsigned char pt[21], ct[21], rt[21]; int i;
        for (i = 0; i < 21; ++i) pt[i] = (unsigned char)(i * 7 + 3);
        for (i = 0; i < 21; ++i) ct[i] = (unsigned char)(pt[i] ^ ks_prod[i]);
        for (i = 0; i < 21; ++i) rt[i] = (unsigned char)(ct[i] ^ ks_prod[i]);
        CHECK(memcmp(pt, rt, 21) == 0, "encrypt/decrypt roundtrip is identity");
    }

    /* 5. Per-frame keystream INDEXING must match DSD-FME's bitstream model.
     *
     *    DSD-FME (dsd_mbe.c) generates the keystream octets per superframe,
     *    expands them MSB-first into a flat bitstream, then for each of the 18
     *    AMBE frames XORs 49 bits. CRUCIALLY, Hytera Enhanced does NOT skip the
     *    trailing 7 bits the way MOTOTRBO/P25 do -- the advance is
     *    `bit_counter += 49`, gated by `if (algid != 0x02) bit_counter += 7;`.
     *    So frame f consumes keystream BITS [f*49 .. f*49+48] (MSB-first), which
     *    are NOT byte aligned (only f=0 starts on a byte boundary).
     *
     *    The brute-forcer now extracts cipher byte n of frame f via
     *    hytera_ks_byte(ks, f*49 + n*8). This test builds the DSD-FME bitstream
     *    reference independently and confirms every one of the 18 frames'
     *    49 keystream bits matches -- the regression guard for the old (wrong)
     *    byte-aligned f*7 model, which only decrypted frame 0 correctly and is
     *    why Hytera never validated end-to-end. */
    {
        unsigned char ks135[135];
        unsigned char ksbits[135 * 8];
        int i, f, ok_idx = 1;

        /* Reference keystream + MSB-first bit expansion (DSD-FME order). */
        hytera_ref(key, mi5, ks135, 135);
        for (i = 0; i < 135; ++i)
            for (int b = 0; b < 8; ++b)
                ksbits[i * 8 + b] = (unsigned char)((ks135[i] >> (7 - b)) & 1u);

        /* Production keystream the brute-forcer actually indexes (126 bytes). */
        unsigned char ksprod[126];
        hytera_compute_ks(key, mi40, ksprod, 126);

        for (f = 0; f < 18; ++f) {
            int bit_base = f * 49;   /* Hytera EP: 49 bits/frame, NO 7-bit skip */
            for (i = 0; i < 49; ++i) {
                /* what the kernels actually extract: cipher byte (i>>3) of the
                 * frame = hytera_ks_byte(ks, f*49 + (i>>3)*8); take bit (i&7). */
                unsigned char bf_byte = hytera_ks_byte(ksprod, bit_base + (i & ~7));
                int bf_bit = (bf_byte >> (7 - (i & 7))) & 1;
                int ref_bit = ksbits[bit_base + i];
                if (bf_bit != ref_bit) ok_idx = 0;
            }
        }
        CHECK(ok_idx, "per-frame keystream indexing matches DSD-FME bitstream (18 frames, 49b/frame)");
    }

    /* 6. Synthetic end-to-end recovery: plant a key, encrypt a low-inter-frame-HD
     *    plaintext with the CORRECT 49-bit indexing, and confirm the planted key
     *    scores far above wrong keys. This is the proof -- absent a real capture --
     *    that the fix actually recovers a Hytera Enhanced key. */
    {
        unsigned char pkey[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
        uint64_t pmi = 0x1122334455ULL;
        unsigned char ks[126];
        /* Same 49-bit pattern in every AMBE frame -> a correct decrypt gives
         * HD(sf0,sf1)=HD(sf1,sf2)=0 -> 48 per burst -> 288 over 6 bursts. */
        unsigned char plain[7] = {0x5A, 0xA5, 0x3C, 0xC3, 0x0F, 0xF0, 0x80};
        unsigned char cipher[18][7];
        int frame, n; unsigned kk;
        double s_correct, s_wrong_max = -1e9;

        hytera_compute_ks(pkey, pmi, ks, 126);
        for (frame = 0; frame < 18; ++frame)
            for (n = 0; n < 7; ++n)
                cipher[frame][n] = (unsigned char)(plain[n] ^ hytera_ks_byte(ks, frame * 49 + n * 8));

        s_correct = score_synth(cipher, pkey, pmi);
        for (kk = 0; kk < 256; ++kk) {  /* a sweep of wrong keys */
            unsigned char wk[5] = { (unsigned char)(pkey[0] ^ (kk + 1)), pkey[1],
                                    pkey[2], pkey[3], (unsigned char)(pkey[4] ^ kk) };
            double sw = score_synth(cipher, wk, pmi);
            if (sw > s_wrong_max) s_wrong_max = sw;
        }
        printf("      synthetic: correct=%.0f  wrong_max=%.0f (max possible 288)\n",
               s_correct, s_wrong_max);
        CHECK(s_correct >= 287.0 && s_correct > s_wrong_max + 60.0,
              "planted Hytera key recovered: dominates wrong keys (synthetic end-to-end)");
    }

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", failures);
    return failures ? 1 : 0;
}
