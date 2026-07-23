/* FSP.DMRCrack - OpenCL brute-force kernels (NVIDIA / AMD / Intel)
 *
 * Ported 1:1 from the proven CUDA kernels in src/bruteforce.cu:
 *   - bruteforce_kernel_strict  -> kernel_strict   (MOTOTRBO KMI9, mode_policy 2/3)
 *   - bruteforce_kernel_hytera  -> kernel_hytera   (Hytera Enhanced Privacy, mode_policy 4)
 *
 * One work-item processes exactly one candidate key. The host enqueues the
 * keyspace in chunks (start_key + global_id) and accumulates keys_tested itself,
 * so the kernel never touches a global counter - only the packed best result.
 *
 * Cipher packs are precomputed on the host (deinterleave -> mbe_demodulate ->
 * extract 49 bits -> pack 7 bytes), identical to precompute_cipher_packs().
 */

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define DMR_CIPHER_PACK_BYTES 21
#define RC4_DISCARD_BYTES     256

typedef struct {
    uchar S[256];
    uchar i;
    uchar j;
} RC4_CTX;

/* -- score/key packing (matches pack_score_key_dev / unpack_score_dev) -----
 * bits[63:40] = sortable_float >> 8, bits[39:0] = key & 0xFFFFFFFFFF.
 * The sortable transform makes IEEE-754 floats order correctly as integers,
 * so a single atomic max selects the best (score,key) without a race window. */
inline ulong pack_score_key(float score, ulong key)
{
    uint u = as_uint(score);
    uint sortable = u ^ (-(u >> 31) | 0x80000000u);
    return ((ulong)(sortable >> 8) << 40) | (key & 0xFFFFFFFFFFUL);
}

inline float unpack_score(ulong packed)
{
    uint sortable = (uint)(packed >> 40) << 8;
    uint bits = sortable ^ ((~sortable >> 31) | 0x80000000u);
    return as_float(bits);
}

/* 64-bit atomic max built from cmpxchg (cl_khr_int64_base_atomics). */
inline void atomic_max_u64(volatile __global ulong *addr, ulong val)
{
    ulong old = *addr;
    while (val > old) {
        ulong prev = atom_cmpxchg(addr, old, val);
        if (prev == old) break;
        old = prev;
    }
}

inline void update_best_packed(float score, ulong key, volatile __global ulong *best)
{
    atomic_max_u64(best, pack_score_key(score, key));
}

inline void key_to_5bytes(ulong key, uchar out[5])
{
    out[0] = (uchar)((key >> 32) & 0xFFu);
    out[1] = (uchar)((key >> 24) & 0xFFu);
    out[2] = (uchar)((key >> 16) & 0xFFu);
    out[3] = (uchar)((key >> 8)  & 0xFFu);
    out[4] = (uchar)( key        & 0xFFu);
}

inline void compose_kmi9(const uchar key5[5], uint mi, uchar out9[9])
{
    out9[0] = key5[0]; out9[1] = key5[1]; out9[2] = key5[2];
    out9[3] = key5[3]; out9[4] = key5[4];
    out9[5] = (uchar)((mi >> 24) & 0xFFu);
    out9[6] = (uchar)((mi >> 16) & 0xFFu);
    out9[7] = (uchar)((mi >> 8)  & 0xFFu);
    out9[8] = (uchar)( mi        & 0xFFu);
}

/* RC4 KSA with a 9-byte key (KMI9). */
inline void rc4_ksa9(RC4_CTX *ctx, const uchar key9[9])
{
    for (int i = 0; i < 256; ++i) ctx->S[i] = (uchar)i;
    int j = 0, k_idx = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + ctx->S[i] + key9[k_idx]) & 0xFF;
        uchar t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
        if (++k_idx == 9) k_idx = 0;
    }
    ctx->i = 0; ctx->j = 0;
}

/* RC4 KSA with a 5-byte key (Hytera). */
inline void rc4_ksa5(RC4_CTX *ctx, const uchar key5[5])
{
    for (int i = 0; i < 256; ++i) ctx->S[i] = (uchar)i;
    int j = 0, k_idx = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + ctx->S[i] + key5[k_idx]) & 0xFF;
        uchar t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
        if (++k_idx == 5) k_idx = 0;
    }
    ctx->i = 0; ctx->j = 0;
}

inline void rc4_discard(RC4_CTX *ctx, int nbytes)
{
    uchar i = ctx->i, j = ctx->j;
    for (int k = 0; k < nbytes; ++k) {
        i = (uchar)(i + 1);
        j = (uchar)(j + ctx->S[i]);
        uchar t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
    }
    ctx->i = i; ctx->j = j;
}

/* Decrypt the first 3 bytes of a 7-byte sub-frame, advance state over all 7. */
inline void rc4_crypt_first3_skip4(RC4_CTX *ctx, const uchar in7[7], uchar out3[3])
{
    uchar i = ctx->i, j = ctx->j;
    for (int k = 0; k < 3; ++k) {
        i = (uchar)(i + 1);
        j = (uchar)(j + ctx->S[i]);
        uchar t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
        out3[k] = in7[k] ^ ctx->S[(uchar)(ctx->S[i] + ctx->S[j])];
    }
    for (int k = 3; k < 7; ++k) {
        i = (uchar)(i + 1);
        j = (uchar)(j + ctx->S[i]);
        uchar t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
    }
    ctx->i = i; ctx->j = j;
}

/* Hytera EP keystream: RC4 KSA with key5 (drop=0), then ks[i]=rc4[i]^kiv[i%5].
 * Matches DSD-FME hytera_enhanced_rc4_setup: kiv[i]=key5[i]^MI[i] for all 5 bytes,
 * MI is 40-bit big-endian (MI[0] = bits 39..32). Mirrors include/hytera_ks.h.
 * One keystream per superframe, consumed as a bitstream at 49 bits per AMBE
 * frame (no 7-bit skip, unlike MOTOTRBO): frame f reads bits [f*49 .. f*49+48]
 * via hytera_ks_byte. 126 bytes cover all 18 frames. */
#define HYTERA_KS_BYTES 126
/* MI-free RC4 keystream (KSA(key5)+PRGA): depends only on the key, so build it
 * once per key and reuse across superframes. Mirrors hytera_compute_raw. */
inline void compute_hytera_raw(const uchar key5[5], uchar raw[HYTERA_KS_BYTES])
{
    RC4_CTX rc4;
    rc4_ksa5(&rc4, key5);

    uchar ri = 0, rj = 0;
    for (int idx = 0; idx < HYTERA_KS_BYTES; ++idx) {
        ri = (uchar)(ri + 1);
        rj = (uchar)(rj + rc4.S[ri]);
        uchar t = rc4.S[ri]; rc4.S[ri] = rc4.S[rj]; rc4.S[rj] = t;
        raw[idx] = rc4.S[(uchar)(rc4.S[ri] + rc4.S[rj])];
    }
}

/* Per-superframe MI mask: ks[i] = raw[i] ^ (key5[i%5] ^ MI[i%5]). Mirrors
 * hytera_apply_kiv. */
inline void apply_hytera_kiv(const uchar raw[HYTERA_KS_BYTES], const uchar key5[5],
                             ulong mi, uchar ks_out[HYTERA_KS_BYTES])
{
    uchar kiv[5];
    kiv[0] = key5[0] ^ (uchar)((mi >> 32) & 0xFFu);
    kiv[1] = key5[1] ^ (uchar)((mi >> 24) & 0xFFu);
    kiv[2] = key5[2] ^ (uchar)((mi >> 16) & 0xFFu);
    kiv[3] = key5[3] ^ (uchar)((mi >>  8) & 0xFFu);
    kiv[4] = key5[4] ^ (uchar)( mi        & 0xFFu);
    for (int idx = 0; idx < HYTERA_KS_BYTES; ++idx)
        ks_out[idx] = kiv[idx % 5] ^ raw[idx];
}

inline int popc8(uchar b) { return popcount((uint)b); }

/* Extract 8 keystream bits at MSB-first bit offset bit_off (mirrors
 * hytera_ks_byte in include/hytera_ks.h). Hytera EP consumes 49 bits/frame with
 * no byte alignment, so frame f decrypts cipher byte n at bit offset f*49+n*8. */
inline uchar hytera_ks_byte(const uchar *ks, int bit_off)
{
    int B = bit_off >> 3;
    int s = bit_off & 7;
    return (uchar)(s ? ((ks[B] << s) | (ks[B + 1] >> (8 - s))) : ks[B]);
}

#define BCNT_ADD(b, bit) bcnt_p[(b)>>1] += ((uint)(bit)) << (((b)&1u)<<4)
#define BCNT_GET(b)      ((float)((bcnt_p[(b)>>1] >> (((b)&1u)<<4)) & 0xFFFFu))

/* -- MOTOTRBO KMI9 strict kernel (mode_policy 2/3) -- */
__kernel void kernel_strict(
    const ulong start_key,
    const ulong total_keys,
    const int   payload_count,
    const ulong global_mi,
    const int   enable_prune,
    __global const uchar *cipher_packs,
    __global const ulong *line_mi,
    __global const uchar *meta_flags,
    __global const float *abs_floor,
    volatile __global ulong *best_packed)
{
    ulong gid = get_global_id(0);
    if (gid >= total_keys) return;

    ulong current_key = start_key + gid;
    uchar key[5];
    key_to_5bytes(current_key, key);

    float total_score = 0.0f;
    int processed_bursts = 0;
    uint bcnt_p[12];
    for (int k = 0; k < 12; ++k) bcnt_p[k] = 0u;

    for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
        uint mi = (uint)global_mi;   /* MOTOTRBO KMI9 uses the low 32 bits */
        if (meta_flags[sf_base] & 0x1u) mi = (uint)line_mi[sf_base];

        uchar kmi9[9];
        compose_kmi9(key, mi, kmi9);
        RC4_CTX rc4;
        rc4_ksa9(&rc4, kmi9);
        rc4_discard(&rc4, RC4_DISCARD_BYTES);

        for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
            int p = sf_base + burst_pos;
            if (p >= payload_count) break;

            __global const uchar *cp = cipher_packs + (p * DMR_CIPHER_PACK_BYTES);
            uchar in7[7], p0[3], p1[3], p2[3];
            for (int b = 0; b < 7; ++b) in7[b] = cp[b];
            rc4_crypt_first3_skip4(&rc4, in7, p0);
            for (int b = 0; b < 7; ++b) in7[b] = cp[7 + b];
            rc4_crypt_first3_skip4(&rc4, in7, p1);
            for (int b = 0; b < 7; ++b) in7[b] = cp[14 + b];
            rc4_crypt_first3_skip4(&rc4, in7, p2);

            int h01 = popc8(p0[0]^p1[0]) + popc8(p0[1]^p1[1]) + popc8(p0[2]^p1[2]);
            int h12 = popc8(p1[0]^p2[0]) + popc8(p1[1]^p2[1]) + popc8(p1[2]^p2[2]);
            total_score += (float)(48 - h01 - h12);
            processed_bursts++;

            for (int b = 0; b < 8; ++b) BCNT_ADD(b,    (p0[0] >> (7-b)) & 1);
            for (int b = 0; b < 8; ++b) BCNT_ADD(8+b,  (p0[1] >> (7-b)) & 1);
            for (int b = 0; b < 8; ++b) BCNT_ADD(16+b, (p0[2] >> (7-b)) & 1);

            /* Noise-tolerant per-burst early-reject (floor = 24*n + 8*sqrt(n),
             * mirrors the CUDA HFLOOR_* constants): rejects wrong keys within a
             * superframe while keeping a near-baseline correct key. (abs_floor
             * kernel arg is now unused.) */
            if (enable_prune && processed_bursts >= 6 &&
                total_score < 24.0f * (float)processed_bursts
                            + 8.0f * sqrt((float)processed_bursts)) {
                return;
            }
        }

        if (enable_prune && processed_bursts >= 6) {
            float best_now = unpack_score(*best_packed);
            float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
            if (max_possible <= best_now) break;
        }

        if (enable_prune && processed_bursts >= 12) {
            float half_n = (float)processed_bursts * 0.5f;
            float chi2_mid = 0.0f;
            for (int b = 0; b < 24; ++b) {
                float dev = BCNT_GET(b) - half_n;
                chi2_mid += dev * dev;
            }
            float chi2_floor = 6.0f * (float)processed_bursts
                             - 3.0f * sqrt(48.0f * (float)processed_bursts);
            if (chi2_mid < chi2_floor) return;
        }
    }

    if (processed_bursts == payload_count) {
        if (processed_bursts >= 6) {
            float half_n = (float)processed_bursts * 0.5f;
            float chi2 = 0.0f;
            for (int b = 0; b < 24; ++b) {
                float dev = BCNT_GET(b) - half_n;
                chi2 += dev * dev;
            }
            total_score += chi2 / (float)processed_bursts;
        }
        update_best_packed(total_score, current_key, best_packed);
    }
}

/* -- Hytera Enhanced Privacy kernel (mode_policy 4) -- */
__kernel void kernel_hytera(
    const ulong start_key,
    const ulong total_keys,
    const int   payload_count,
    const ulong global_mi,
    const int   enable_prune,
    __global const uchar *cipher_packs,
    __global const ulong *line_mi,
    __global const uchar *meta_flags,
    __global const float *abs_floor,
    volatile __global ulong *best_packed)
{
    ulong gid = get_global_id(0);
    if (gid >= total_keys) return;

    ulong current_key = start_key + gid;
    uchar key[5];
    key_to_5bytes(current_key, key);

    float total_score = 0.0f;
    int processed_bursts = 0;
    uint bcnt_p[12];
    for (int k = 0; k < 12; ++k) bcnt_p[k] = 0u;

    /* RC4 keystream is MI-independent: build it once per key, re-apply only the
     * cheap MI mask per superframe (was a full KSA+PRGA per superframe). */
    uchar hraw[HYTERA_KS_BYTES];
    compute_hytera_raw(key, hraw);

    for (int sf_base = 0; sf_base < payload_count; sf_base += 6) {
        ulong mi = global_mi;   /* Hytera EP uses the full 40-bit MI */
        if (meta_flags[sf_base] & 0x1u) mi = line_mi[sf_base];

        uchar ks[HYTERA_KS_BYTES];
        apply_hytera_kiv(hraw, key, mi, ks);

        for (int burst_pos = 0; burst_pos < 6; ++burst_pos) {
            int p = sf_base + burst_pos;
            if (p >= payload_count) break;

            /* Keystream consumed as a BITSTREAM, 49 bits per AMBE frame, NO 7-bit
             * skip (Hytera EP != MOTOTRBO). Frame f = burst_pos*3 + sf decrypts
             * cipher byte n at bit offset f*49 + n*8. */
            int f0 = burst_pos * 3, f1 = f0 + 1, f2 = f0 + 2;
            __global const uchar *cp = cipher_packs + (p * DMR_CIPHER_PACK_BYTES);
            uchar p0[3], p1[3], p2[3];
            p0[0]=cp[0] ^hytera_ks_byte(ks,f0*49+0); p0[1]=cp[1] ^hytera_ks_byte(ks,f0*49+8); p0[2]=cp[2] ^hytera_ks_byte(ks,f0*49+16);
            p1[0]=cp[7] ^hytera_ks_byte(ks,f1*49+0); p1[1]=cp[8] ^hytera_ks_byte(ks,f1*49+8); p1[2]=cp[9] ^hytera_ks_byte(ks,f1*49+16);
            p2[0]=cp[14]^hytera_ks_byte(ks,f2*49+0); p2[1]=cp[15]^hytera_ks_byte(ks,f2*49+8); p2[2]=cp[16]^hytera_ks_byte(ks,f2*49+16);

            int h01 = popc8(p0[0]^p1[0]) + popc8(p0[1]^p1[1]) + popc8(p0[2]^p1[2]);
            int h12 = popc8(p1[0]^p2[0]) + popc8(p1[1]^p2[1]) + popc8(p1[2]^p2[2]);
            total_score += (float)(48 - h01 - h12);
            processed_bursts++;

            for (int b = 0; b < 8; ++b) BCNT_ADD(b,    (p0[0] >> (7-b)) & 1);
            for (int b = 0; b < 8; ++b) BCNT_ADD(8+b,  (p0[1] >> (7-b)) & 1);
            for (int b = 0; b < 8; ++b) BCNT_ADD(16+b, (p0[2] >> (7-b)) & 1);

            /* Noise-tolerant per-burst early-reject (floor = 24*n + 8*sqrt(n),
             * mirrors the CUDA HFLOOR_* constants): rejects wrong keys within a
             * superframe while keeping a near-baseline correct key. (abs_floor
             * kernel arg is now unused.) */
            if (enable_prune && processed_bursts >= 6 &&
                total_score < 24.0f * (float)processed_bursts
                            + 8.0f * sqrt((float)processed_bursts)) {
                return;
            }
        }

        if (enable_prune && processed_bursts >= 6) {
            float best_now = unpack_score(*best_packed);
            float max_possible = total_score + (float)(payload_count - processed_bursts) * 48.0f;
            if (max_possible <= best_now) break;
        }

        if (enable_prune && processed_bursts >= 12) {
            float half_n = (float)processed_bursts * 0.5f;
            float chi2_mid = 0.0f;
            for (int b = 0; b < 24; ++b) {
                float dev = BCNT_GET(b) - half_n;
                chi2_mid += dev * dev;
            }
            float chi2_floor = 6.0f * (float)processed_bursts
                             - 3.0f * sqrt(48.0f * (float)processed_bursts);
            if (chi2_mid < chi2_floor) return;
        }
    }

    if (processed_bursts == payload_count) {
        if (processed_bursts >= 6) {
            float half_n = (float)processed_bursts * 0.5f;
            float chi2 = 0.0f;
            for (int b = 0; b < 24; ++b) {
                float dev = BCNT_GET(b) - half_n;
                chi2 += dev * dev;
            }
            total_score += chi2 / (float)processed_bursts;
        }
        update_best_packed(total_score, current_key, best_packed);
    }
}
