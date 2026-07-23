/* gen_hytera_synth.c -- generate a SYNTHETIC Hytera Enhanced Privacy (.bin)
 * capture with a planted key, so the GPU/CPU brute-forcer can be exercised
 * end-to-end on the ALG=0x02 path (no real ALG=0x02 capture exists yet).
 *
 * It inverts the brute-forcer's raw-payload -> cipher-pack pipeline
 * (precompute_cipher_packs in bruteforce.cu):
 *   de-interleave (bijection)  ->  mbe_demodulate (row1 ^= PRNG seeded by C0)
 *   ->  extract 49 ambe_d bits  ->  pack 7 bytes MSB-first.
 * For each AMBE frame f it picks a fixed low-inter-frame-HD plaintext, encrypts
 * it with the real Hytera keystream (hytera_ks.h, the verified single source of
 * truth) at the canonical 49-bit/frame bitstream offset, then back-constructs the
 * 33-byte raw payload so that precompute_cipher_packs reproduces exactly that
 * ciphertext. Decrypting with the planted key therefore yields the fixed
 * plaintext (HD 0) -> a clean, recoverable peak.
 *
 * Usage: gen_hytera_synth <key10hex> <mi10hex> <superframes> <out.bin>
 *   e.g. gen_hytera_synth A1B2C3D4E5 1122334455 21 synth_hytera.bin
 *
 * Build: cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\gen_hytera_synth.exe \
 *           tools\gen_hytera_synth.c /Iinclude
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/dmr_tables.h"
#include "../include/hytera_ks.h"

/* The brute-forcer generates this many keystream bytes per superframe (covers
 * bit 881 = octet 110 of the last frame). Defined per-backend; mirror it here. */
#define HYTERA_KS_BYTES 126

static const int rW[36]        = DMR_RW_INIT;
static const int rX[36]        = DMR_RX_INIT;
static const int rY[36]        = DMR_RY_INIT;
static const int rZ[36]        = DMR_RZ_INIT;
static const int sfidx[3][36]  = DMR_SF_DIBIT_IDX_INIT;

/* Fixed 49-bit plaintext used for every frame: C0+C1 (first 24 bits) are held
 * constant, so the correct key gives inter-frame HD 0 (48/burst). MSB-first
 * unpack of these 7 bytes, exactly how the brute-forcer reads a cipher pack. */
static const unsigned char PLAIN7[7] = { 0x5A, 0xA5, 0x3C, 0xC3, 0x0F, 0xF0, 0x80 };

int main(int argc, char **argv)
{
    unsigned char key5[5];
    uint64_t key_val, mi;
    int nsf, s, burst, sf, i, k, b;
    FILE *fout;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <key10hex> <mi10hex> <superframes> <out.bin>\n", argv[0]);
        return 2;
    }
    key_val = strtoull(argv[1], NULL, 16);
    mi      = strtoull(argv[2], NULL, 16);
    nsf     = atoi(argv[3]);
    if (nsf < 1) nsf = 1;
    key5[0] = (unsigned char)((key_val >> 32) & 0xFF);
    key5[1] = (unsigned char)((key_val >> 24) & 0xFF);
    key5[2] = (unsigned char)((key_val >> 16) & 0xFF);
    key5[3] = (unsigned char)((key_val >>  8) & 0xFF);
    key5[4] = (unsigned char)( key_val        & 0xFF);

    /* 49-bit plaintext, MSB-first from PLAIN7 (bit i -> byte i/8, bit 7-(i%8)). */
    unsigned char plain49[49];
    for (i = 0; i < 49; ++i) plain49[i] = (PLAIN7[i >> 3] >> (7 - (i & 7))) & 1u;

    fout = fopen(argv[4], "w");
    if (!fout) { fprintf(stderr, "cannot open %s\n", argv[4]); return 1; }

    for (s = 0; s < nsf; ++s) {
        unsigned char ks[HYTERA_KS_BYTES];
        unsigned char ksbits[HYTERA_KS_BYTES * 8];
        hytera_compute_ks(key5, mi, ks, HYTERA_KS_BYTES);
        for (i = 0; i < HYTERA_KS_BYTES; ++i)
            for (b = 0; b < 8; ++b) ksbits[i * 8 + b] = (ks[i] >> (7 - b)) & 1u;

        for (burst = 0; burst < 6; ++burst) {
            unsigned char dibits[132];
            unsigned char payload[33];
            memset(dibits, 0, sizeof(dibits));

            for (sf = 0; sf < 3; ++sf) {
                int f = burst * 3 + sf;
                unsigned char cipher49[49];
                int ambe[4][24];
                int foo, pr;

                /* cipher = plaintext XOR keystream, 49-bit bitstream offset f*49 */
                for (i = 0; i < 49; ++i)
                    cipher49[i] = plain49[i] ^ ksbits[f * 49 + i];

                /* back-construct the PRE-demod ambe_fr that extracts to cipher49 */
                memset(ambe, 0, sizeof(ambe));
                for (k = 0; k < 12; ++k) ambe[0][23 - k] = cipher49[k];        /* C0 */
                for (k = 0; k < 11; ++k) ambe[2][10 - k] = cipher49[24 + k];   /* C2 */
                for (k = 0; k < 14; ++k) ambe[3][13 - k] = cipher49[35 + k];   /* C3 */
                /* row1: post-demod row1[22..11] must equal cipher49[12..23];
                 * the demod XORs row1[j] with PRNG bit seeded by C0, so set the
                 * PRE-demod bit = wanted ^ prbit. */
                foo = 0;
                for (k = 0; k < 12; ++k) foo = (foo << 1) | cipher49[k];
                pr = 16 * foo;
                for (i = 22; i >= 0; --i) {
                    pr = (173 * pr + 13849) & 0xFFFF;
                    if (i >= 11) {
                        int t = 22 - i;                       /* cipher49 index 12..23 */
                        ambe[1][i] = cipher49[12 + t] ^ ((pr >> 15) & 1);
                    }
                }

                /* invert the de-interleave: each step's two cells -> one dibit */
                for (i = 0; i < 36; ++i) {
                    int hi = ambe[rW[i]][rX[i]] & 1;
                    int lo = ambe[rY[i]][rZ[i]] & 1;
                    dibits[sfidx[sf][i]] = (unsigned char)((hi << 1) | lo);
                }
            }

            /* pack 132 dibits -> 33 bytes (4 dibits/byte, MSB dibit first) */
            for (i = 0; i < 33; ++i)
                payload[i] = (unsigned char)((dibits[i*4] << 6) | (dibits[i*4+1] << 4) |
                                             (dibits[i*4+2] << 2) | dibits[i*4+3]);

            for (i = 0; i < 33; ++i) fprintf(fout, "%02X", payload[i]);
            fprintf(fout, ";ALG=02;KID=01;MI=%010llX\n", (unsigned long long)mi);
        }
    }
    fclose(fout);
    fprintf(stderr, "wrote %d payloads (%d superframes) to %s\n", nsf * 6, nsf, argv[4]);
    return 0;
}
