/* hytera_ks.h -- Hytera Enhanced Privacy (ALG=0x02) keystream, single source.
 *
 * Mirrors DSD-FME hytera_enhanced_rc4_setup() (src/crypt-rc4.c):
 *   - RC4 KSA with the 5-byte key, NO drop/discard.
 *   - kiv[i] = key5[i] ^ MI[i]  for ALL 5 bytes (MI is 40-bit, big-endian:
 *     MI[0] is the most significant byte).
 *   - ks[i] = rc4[i] ^ kiv[i % 5].
 *   - ONE keystream per superframe, consumed LINEARLY across the 18 AMBE frames
 *     (6 bursts x 3 sub-frames). DSD-FME (dsd_mbe.c) XORs each frame's 49 ambe_d
 *     bits then skips 7 bits => 56 bits = exactly 7 keystream bytes per AMBE frame
 *     (byte-aligned). AMBE frame f (= burst_pos*3 + sf) uses bytes [f*7 .. f*7+6].
 *     The 18 frames need 18*7 = 126 bytes (DSD-FME allocates 135).
 *
 * This header is the single source of truth for the host scorer
 * (compute_hytera_ks_cpu in bruteforce.cu) and the keystream self-test
 * (tests/test_hytera_ks.c). The CUDA device kernel (compute_hytera_ks_dev)
 * mirrors this exact formula with its own device-side RC4 state.
 */
#ifndef HYTERA_KS_H
#define HYTERA_KS_H

#include <stdint.h>

/* Generate `n` keystream bytes (n <= 256 of practical use; a full voice
 * superframe needs 126 = 18 AMBE frames x 7 bytes). */
static inline void hytera_compute_ks(const unsigned char key5[5], uint64_t mi,
                                     unsigned char *ks_out, int n)
{
    unsigned char S[256];
    unsigned char kiv[5];
    unsigned char j = 0, t, a = 0, b = 0;
    int i;

    kiv[0] = (unsigned char)(key5[0] ^ (unsigned char)((mi >> 32) & 0xFFu));
    kiv[1] = (unsigned char)(key5[1] ^ (unsigned char)((mi >> 24) & 0xFFu));
    kiv[2] = (unsigned char)(key5[2] ^ (unsigned char)((mi >> 16) & 0xFFu));
    kiv[3] = (unsigned char)(key5[3] ^ (unsigned char)((mi >>  8) & 0xFFu));
    kiv[4] = (unsigned char)(key5[4] ^ (unsigned char)( mi        & 0xFFu));

    for (i = 0; i < 256; ++i) S[i] = (unsigned char)i;
    for (i = 0; i < 256; ++i) {
        j = (unsigned char)(j + S[i] + key5[i % 5]);   /* KSA, key5 only, drop=0 */
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (i = 0; i < n; ++i) {
        a = (unsigned char)(a + 1);
        b = (unsigned char)(b + S[a]);
        t = S[a]; S[a] = S[b]; S[b] = t;
        ks_out[i] = (unsigned char)(kiv[i % 5] ^ S[(unsigned char)(S[a] + S[b])]);
    }
}

#endif /* HYTERA_KS_H */
