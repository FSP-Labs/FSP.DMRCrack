/* hytera_ks.h -- Hytera Enhanced Privacy (ALG=0x02) keystream, single source.
 *
 * Mirrors DSD-FME hytera_enhanced_rc4_setup() (src/crypt-rc4.c):
 *   - RC4 KSA with the 5-byte key, NO drop/discard.
 *   - kiv[i] = key5[i] ^ MI[i]  for ALL 5 bytes (MI is 40-bit, big-endian:
 *     MI[0] is the most significant byte).
 *   - ks[i] = rc4[i] ^ kiv[i % 5].
 *   - ONE keystream per superframe, consumed as a BITSTREAM, 49 bits per AMBE
 *     frame, across the 18 frames (6 bursts x 3 sub-frames). CRUCIALLY, Hytera EP
 *     does NOT skip the trailing 7 bits the way MOTOTRBO/P25 do: in DSD-FME
 *     (dsd_mbe.c) the per-frame advance is `bit_counter += 49`, gated by
 *     `if (algid != 0x02) bit_counter += 7;` -- so the +7 skip is suppressed for
 *     Hytera Enhanced. AMBE frame f (= burst_pos*3 + sf) therefore consumes BITS
 *     [f*49 .. f*49+48] (MSB-first), which are NOT byte aligned. Use
 *     hytera_ks_byte(ks, f*49 + n*8) to extract cipher-pack byte n (n = 0..6).
 *     The last frame needs bit 17*49+48 = 881, i.e. octet 110 -> 126 bytes is
 *     plenty (DSD-FME allocates 135).
 *
 * This header is the single source of truth for the host scorer
 * (compute_hytera_ks_cpu in bruteforce.cu) and the keystream self-test
 * (tests/test_hytera_ks.c). The CUDA device kernel (compute_hytera_ks_dev)
 * mirrors this exact formula with its own device-side RC4 state.
 */
#ifndef HYTERA_KS_H
#define HYTERA_KS_H

#include <stdint.h>

/* MI-FREE RC4 keystream: KSA(key5) + PRGA -> raw[i] = S[S[a]+S[b]]. This is the
 * expensive part and it depends ONLY on the 40-bit key -- it is byte-identical
 * for every superframe of a session. Hot paths compute it ONCE per key and then
 * apply the cheap per-superframe MI mask with hytera_apply_kiv(). */
static inline void hytera_compute_raw(const unsigned char key5[5],
                                      unsigned char *raw, int n)
{
    unsigned char S[256];
    unsigned char j = 0, t, a = 0, b = 0;
    int i;
    for (i = 0; i < 256; ++i) S[i] = (unsigned char)i;
    for (i = 0; i < 256; ++i) {
        j = (unsigned char)(j + S[i] + key5[i % 5]);   /* KSA, key5 only, drop=0 */
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (i = 0; i < n; ++i) {
        a = (unsigned char)(a + 1);
        b = (unsigned char)(b + S[a]);
        t = S[a]; S[a] = S[b]; S[b] = t;
        raw[i] = S[(unsigned char)(S[a] + S[b])];
    }
}

/* Apply the per-superframe MI mask: ks[i] = raw[i] ^ (key5[i%5] ^ MI[i%5]), MI
 * 40-bit big-endian. Cheap (n XORs); call once per superframe over the MI-free
 * stream from hytera_compute_raw(). */
static inline void hytera_apply_kiv(const unsigned char *raw,
                                    const unsigned char key5[5], uint64_t mi,
                                    unsigned char *ks_out, int n)
{
    unsigned char kiv[5];
    int i;
    kiv[0] = (unsigned char)(key5[0] ^ (unsigned char)((mi >> 32) & 0xFFu));
    kiv[1] = (unsigned char)(key5[1] ^ (unsigned char)((mi >> 24) & 0xFFu));
    kiv[2] = (unsigned char)(key5[2] ^ (unsigned char)((mi >> 16) & 0xFFu));
    kiv[3] = (unsigned char)(key5[3] ^ (unsigned char)((mi >>  8) & 0xFFu));
    kiv[4] = (unsigned char)(key5[4] ^ (unsigned char)( mi        & 0xFFu));
    for (i = 0; i < n; ++i)
        ks_out[i] = (unsigned char)(raw[i] ^ kiv[i % 5]);
}

/* Full keystream (raw + MI mask) in one call. Thin wrapper the self-test and any
 * non-hot-path caller use; behaviour is identical to before the raw/kiv split.
 * n <= 256 (a full voice superframe needs 126 = 18 AMBE frames x 7 bytes). */
static inline void hytera_compute_ks(const unsigned char key5[5], uint64_t mi,
                                     unsigned char *ks_out, int n)
{
    unsigned char raw[256];
    hytera_compute_raw(key5, raw, n);
    hytera_apply_kiv(raw, key5, mi, ks_out, n);
}

/* Extract 8 keystream bits starting at MSB-first bit offset `bit_off`, spanning
 * up to two octets. Hytera EP consumes the keystream at 49 bits/frame with NO
 * byte alignment (see the header note above), so callers decrypt cipher-pack
 * byte n of AMBE frame f via hytera_ks_byte(ks, f*49 + n*8). */
static inline unsigned char hytera_ks_byte(const unsigned char *ks, int bit_off)
{
    int B = bit_off >> 3;
    int s = bit_off & 7;
    return (unsigned char)(s ? ((ks[B] << s) | (ks[B + 1] >> (8 - s))) : ks[B]);
}

#endif /* HYTERA_KS_H */
