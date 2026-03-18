#!/usr/bin/env python3
# FSP.DMRCrack - GPU-accelerated ARC4 key recovery for DMR communications
# Copyright (C) 2026 FSP-Labs
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.
"""
verify_decrypt.py - Empirically validate & score KMI9 RC4 decryption for DMR Enhanced Privacy.

Pipeline (correct mbelib / DSD-FME order):
  For each payload -> each sub-frame:
    1. de-interleave(payload, sf)      -> ambe_fr[4][24]   (raw air bits)
    2. mbe_demodulate(ambe_fr)         -> XOR row1 with PR(encrypted C0)
    3. extract_ambe_d(ambe_fr)         -> 49 encrypted info bits
    4. pack_ambe(49 bits)              -> cipher[7]
    5. rc4_decrypt(KMI9, drop, 7)      -> plain[7]
    6. unpack_ambe(plain[7])           -> 49 plaintext AMBE bits

Scoring (PRIMARY):
    For N frames, accumulate per-bit counts[0..48].
    score = sum_i (counts[i] - N/2)^2   (chi-squared style)
    Correctly decrypted AMBE speech has non-uniform bit distributions;
    a wrong key produces counts ~= N/2 everywhere -> score ~= 0.

Usage:
    python tools/verify_decrypt.py --bin test/aaaaa/RC4-40.fromdsdfme.bin --key <YOUR_KEY_HEX>
"""

import argparse
import random
import sys

# ---------------------------------------------------------------------------
# rW/rX/rY/rZ de-interleave tables  (standard AMBE3600x2450 / DMR)
# ---------------------------------------------------------------------------
rW = [0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,2, 0,2,0,2,0,2, 0,2,0,2,0,2]
rX = [23,10,22,9,21,8, 20,7,19,6,18,5, 17,4,16,3,15,2, 14,1,13,0,12,10, 11,9,10,8,9,7, 8,6,7,5,6,4]
rY = [0,2,0,2,0,2, 0,2,0,3,0,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3]
rZ = [5,3,4,2,3,1, 2,0,1,13,0,12, 22,11,21,10,20,9, 19,8,18,7,17,6, 16,5,15,4,14,3, 13,2,12,1,11,0]

# Sub-frame dibit ranges (in the 33-byte / 132-dibit payload)
_SF_DIBITS = [
    list(range(0, 36)),
    list(range(36, 54)) + list(range(78, 96)),
    list(range(96, 132)),
]


# ---------------------------------------------------------------------------
# LFSR helpers  (taps {31,3,1}  --  poly x^32+x^4+x^2+1, confirmed from DSD-FME)
# ---------------------------------------------------------------------------
def lfsr_next(mi: int, steps: int = 1) -> int:
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1
        mi = ((mi << 1) | bit) & 0xFFFFFFFF
    return mi


def lfsr_prev(mi: int, steps: int = 1) -> int:
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        old31 = ((mi >> 0) ^ (mi >> 4) ^ (mi >> 2)) & 1
        mi = (mi >> 1) | (old31 << 31)
    return mi & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# RC4 (matches DSD-FME crypt-rc4.c exactly)
# ---------------------------------------------------------------------------
def rc4_ksa(key: bytes) -> list:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def rc4_decrypt(key9: bytes, drop: int, cipher: bytes) -> bytes:
    S = rc4_ksa(key9)
    i = j = 0
    for _ in range(drop):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = []
    for c in cipher:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def make_key9(key5: bytes, mi: int) -> bytes:
    return key5 + bytes([(mi >> 24) & 0xFF, (mi >> 16) & 0xFF, (mi >> 8) & 0xFF, mi & 0xFF])


# ---------------------------------------------------------------------------
# De-interleave one sub-frame
# ---------------------------------------------------------------------------
def get_dibit(payload: bytes, d: int) -> int:
    return (payload[d >> 2] >> ((3 - (d & 3)) * 2)) & 0x3


def deinterleave_subframe(payload: bytes, sf: int) -> list:
    ambe_fr = [[0] * 24 for _ in range(4)]
    for i, d in enumerate(_SF_DIBITS[sf]):
        dibit = get_dibit(payload, d)
        ambe_fr[rW[i]][rX[i]] = (dibit >> 1) & 1
        ambe_fr[rY[i]][rZ[i]] = dibit & 1
    return ambe_fr


# ---------------------------------------------------------------------------
# mbelib demodulate  (mbe_demodulateAmbe3600x2450Data)
# Uses ENCRYPTED C0 as seed -- correct for RC4-encrypted DMR voice.
# ---------------------------------------------------------------------------
def mbe_demodulate(ambe_fr: list) -> list:
    import copy
    fr = copy.deepcopy(ambe_fr)
    foo = 0
    for i in range(23, 11, -1):          # row0[23..12] = encrypted C0
        foo = (foo << 1) | fr[0][i]
    pr = [0] * 24
    pr[0] = 16 * foo
    for i in range(1, 24):
        pr[i] = (173 * pr[i-1] + 13849) % 65536
    for i in range(1, 24):
        pr[i] = pr[i] // 32768           # 0 or 1
    k = 1
    for j in range(22, -1, -1):
        fr[1][j] ^= pr[k]
        k += 1
    return fr


# ---------------------------------------------------------------------------
# Extract 49 AMBE info bits  (mbe_eccAmbe3600x2450Data, no-error path)
# ---------------------------------------------------------------------------
def extract_ambe_d(ambe_fr: list) -> list:
    bits = []
    for j in range(23, 11, -1):    # C0 [12]: row0[23..12]
        bits.append(ambe_fr[0][j])
    for j in range(22, 10, -1):    # C1 [12]: row1[22..11]  (after demod)
        bits.append(ambe_fr[1][j])
    for j in range(10, -1, -1):    # C2 [11]: row2[10..0]
        bits.append(ambe_fr[2][j])
    for j in range(13, -1, -1):    # C3 [14]: row3[13..0]
        bits.append(ambe_fr[3][j])
    assert len(bits) == 49
    return bits


# ---------------------------------------------------------------------------
# Pack / unpack 49 bits <-> 7 bytes   (MSB-first: bit i -> byte i//8, bit 7-i%8)
# ---------------------------------------------------------------------------
def pack_ambe(bits49: list) -> bytes:
    result = bytearray(7)
    for i, b in enumerate(bits49):
        result[i >> 3] |= (b & 1) << (7 - (i & 7))
    return bytes(result)


def unpack_ambe(data7: bytes) -> list:
    return [((data7[i >> 3]) >> (7 - (i & 7))) & 1 for i in range(49)]


# ---------------------------------------------------------------------------
# Full per-sub-frame decrypt  ->  49 plaintext AMBE bits
# ---------------------------------------------------------------------------
def decrypt_sf(payload: bytes, sf: int, key5: bytes, mi: int, drop: int) -> list:
    ambe_fr   = deinterleave_subframe(payload, sf)
    ambe_fr_d = mbe_demodulate(ambe_fr)
    bits_enc  = extract_ambe_d(ambe_fr_d)
    cipher7   = pack_ambe(bits_enc)
    key9      = make_key9(key5, mi)
    plain7    = rc4_decrypt(key9, drop, cipher7)
    return unpack_ambe(plain7)


# ---------------------------------------------------------------------------
# Superframe-aware MI/drop computation
# ---------------------------------------------------------------------------
def compute_mi_drop(base_mi: int, idx: int, b0: int, lfsr_steps: int):
    """
    base_mi    : payloads[0]['mi']   (MI from first PI packet in .bin)
    idx        : payload index in .bin (0-based)
    b0         : burst_pos of payloads[0] within its superframe (0..5)
    lfsr_steps : LFSR steps between superframes (32 for DSD-FME / ETSI)

    DSD-FME keeps the same MI for all 6 bursts of a superframe;
    advances by `lfsr_steps` between superframes.
    """
    abs_burst  = b0 + idx
    sf_num     = abs_burst // 6
    burst_pos  = abs_burst % 6
    correct_mi = lfsr_next(base_mi, lfsr_steps * sf_num)
    drop_base  = 256 + burst_pos * 21
    return correct_mi, drop_base


# ---------------------------------------------------------------------------
# PRIMARY SCORING: bit-frequency deviation from 50%
# ---------------------------------------------------------------------------
def score_bit_frequencies(payloads, key5, b0, lfsr_steps=32, max_p=126):
    """
    For correctly decrypted AMBE speech, each of the 49 plaintext bit
    positions has a non-uniform distribution (the AMBE VQ codebook indices
    and voicing flags are biased toward typical speech patterns).

    Score = sum_i (count_i - N/2)^2    (chi-squared style, higher = better)

    For a wrong key: count_i ~= N/2  ->  score ~= 0.
    For the correct key: sum of squared deviations is significantly > 0.
    """
    base_mi = payloads[0]['mi']
    counts = [0] * 49
    n_frames = 0
    for idx, p in enumerate(payloads[:max_p]):
        mi, drop_base = compute_mi_drop(base_mi, idx, b0, lfsr_steps)
        for sf in range(3):
            bits = decrypt_sf(p['bytes'], sf, key5, mi, drop_base + sf * 7)
            for j in range(49):
                counts[j] += bits[j]
            n_frames += 1
    half = n_frames / 2.0
    return sum((c - half) ** 2 for c in counts)


def score_bit_frequencies_rand(payloads, b0, lfsr_steps=32, max_p=126):
    rk = bytes([random.randint(0, 255) for _ in range(5)])
    return score_bit_frequencies(payloads, rk, b0, lfsr_steps, max_p)


# ---------------------------------------------------------------------------
# Z-score test: bit-frequency (PRIMARY)
# ---------------------------------------------------------------------------
def zscore_bit_freq(payloads, key5, b0, lfsr_steps, n_random, max_p, label):
    print(f"\n=== BIT-FREQ {label} (b0={b0}, lfsr={lfsr_steps}) ===")
    score_correct = score_bit_frequencies(payloads, key5, b0, lfsr_steps, max_p)
    n = min(max_p, len(payloads))
    n_frames = n * 3
    print(f"  Correct key: {score_correct:.1f}  ({score_correct / n_frames:.2f} / frame)")

    random_scores = [score_bit_frequencies_rand(payloads, b0, lfsr_steps, max_p)
                     for _ in range(n_random)]

    mean   = sum(random_scores) / len(random_scores)
    stddev = (sum((s - mean) ** 2 for s in random_scores) / len(random_scores)) ** 0.5
    z      = (score_correct - mean) / stddev if stddev > 0 else 0.0
    above  = sum(1 for s in random_scores if s >= score_correct)

    print(f"  Random: mean={mean:.1f}  stddev={stddev:.1f}")
    print(f"  Z-score: {z:.2f} sigma")
    print(f"  Random >= correct: {above}/{n_random} ({100*above/n_random:.2f}%)")

    if z > 7:   print("  => EXCELLENT")
    elif z > 5: print("  => GOOD")
    elif z > 3: print("  => MARGINAL")
    else:       print("  => INSUFFICIENT")
    return z


# ---------------------------------------------------------------------------
# Debug: print per-bit frequencies for the correct key
# ---------------------------------------------------------------------------
def debug_bit_freq(payloads, key5, b0, lfsr_steps=32, max_p=126):
    base_mi = payloads[0]['mi']
    counts = [0] * 49
    n_frames = 0
    for idx, p in enumerate(payloads[:max_p]):
        mi, drop_base = compute_mi_drop(base_mi, idx, b0, lfsr_steps)
        for sf in range(3):
            bits = decrypt_sf(p['bytes'], sf, key5, mi, drop_base + sf * 7)
            for j in range(49):
                counts[j] += bits[j]
            n_frames += 1
    print(f"\n=== Per-bit frequencies (correct key, b0={b0}, lfsr={lfsr_steps}, N={n_frames} frames) ===")
    print(f"  {'bit':>4}  {'count':>6}  {'freq':>6}  {'dev':>7}")
    for j in range(49):
        freq = counts[j] / n_frames
        dev  = freq - 0.5
        print(f"  {j:>4}  {counts[j]:>6}  {freq:>6.3f}  {dev:>+7.3f}")
    print(f"  Sum |dev|: {sum(abs(c/n_frames - 0.5) for c in counts):.4f}")
    print(f"  Score (sum dev^2 * N^2): {sum((c - n_frames/2)**2 for c in counts):.1f}")


# ---------------------------------------------------------------------------
# Debug: print C0 HD across frames (legacy metric -- shows why it fails)
# ---------------------------------------------------------------------------
def debug_c0_hamming(payloads, key5, b0, lfsr_steps=32, n_payloads=12):
    base_mi = payloads[0]['mi']
    print(f"\n=== C0 inter-sub-frame Hamming (b0={b0}, lfsr={lfsr_steps}) ===")
    hds = []
    for idx in range(min(n_payloads, len(payloads))):
        mi, drop_base = compute_mi_drop(base_mi, idx, b0, lfsr_steps)
        dec  = [decrypt_sf(payloads[idx]['bytes'], sf, key5, mi, drop_base + sf * 7)
                for sf in range(3)]
        c0   = [dec[sf][:12] for sf in range(3)]
        h01  = sum(a != b for a, b in zip(c0[0], c0[1]))
        h12  = sum(a != b for a, b in zip(c0[1], c0[2]))
        hds += [h01, h12]
        bp   = (b0 + idx) % 6
        print(f"  idx={idx:>3} bp={bp} MI={mi:08X}  h01={h01}  h12={h12}")
    avg = sum(hds) / len(hds) if hds else 0
    print(f"  avg HD={avg:.2f} (expect ~6.0 for random bits -- bad metric)")


# ---------------------------------------------------------------------------
# Legacy Hamming-based scoring (kept for comparison -- expected to be near 0)
# ---------------------------------------------------------------------------
def hamming(a, b, n=12):
    return sum(a[i] != b[i] for i in range(n))


def score_all_payloads_sf(payloads, key5, b0, lfsr_steps=32, n_bits=12, max_p=126):
    base_mi   = payloads[0]['mi']
    total     = 0.0
    max_score = n_bits * 2
    for idx, p in enumerate(payloads[:max_p]):
        mi, drop_base = compute_mi_drop(base_mi, idx, b0, lfsr_steps)
        dec  = [decrypt_sf(p['bytes'], sf, key5, mi, drop_base + sf * 7) for sf in range(3)]
        h01  = hamming(dec[0], dec[1], n_bits)
        h12  = hamming(dec[1], dec[2], n_bits)
        total += (max_score - h01 - h12)
    return total


def zscore_hamming_sf(payloads, key5, b0, lfsr_steps, n_bits, n_random, max_p, label):
    print(f"\n=== HAMMING {label} (b0={b0}, lfsr={lfsr_steps}, n_bits={n_bits}) ===")
    score_correct = score_all_payloads_sf(payloads, key5, b0, lfsr_steps, n_bits, max_p)
    n = min(max_p, len(payloads))
    print(f"  Correct key: {score_correct:.0f} ({score_correct/n:.2f}/payload, max={n_bits*2})")
    random_scores = [
        score_all_payloads_sf(
            payloads,
            bytes([random.randint(0, 255) for _ in range(5)]),
            b0, lfsr_steps, n_bits, max_p)
        for _ in range(n_random)]
    mean   = sum(random_scores) / len(random_scores)
    stddev = (sum((s - mean) ** 2 for s in random_scores) / len(random_scores)) ** 0.5
    z      = (score_correct - mean) / stddev if stddev > 0 else 0.0
    above  = sum(1 for s in random_scores if s >= score_correct)
    print(f"  Random: mean={mean:.0f}  stddev={stddev:.1f}")
    print(f"  Z-score: {z:.2f} sigma")
    print(f"  Random >= correct: {above}/{n_random}")
    if z > 7:   print("  => EXCELLENT")
    elif z > 5: print("  => GOOD")
    elif z > 3: print("  => MARGINAL")
    else:       print("  => INSUFFICIENT (expected for Hamming on VQ indices)")
    return z


# ---------------------------------------------------------------------------
# Per-payload scan: find best (mi_offset, drop_base) for a single payload
# ---------------------------------------------------------------------------
def scan_payload(payload: bytes, base_mi: int, key5: bytes):
    print(f"\nPayload: {payload.hex()[:16]}...  MI={base_mi:08X}")
    results = []
    for mi_off in range(-5, 40):
        mi = lfsr_next(base_mi, mi_off) if mi_off >= 0 else lfsr_prev(base_mi, -mi_off)
        for burst_pos in range(6):
            drop_base = 256 + burst_pos * 21
            dec  = [decrypt_sf(payload, sf, key5, mi, drop_base + sf * 7) for sf in range(3)]
            h01  = hamming(dec[0], dec[1], 12)
            h12  = hamming(dec[1], dec[2], 12)
            results.append((h01 + h12, mi_off, drop_base, mi))
    results.sort()
    print(f"  Top 5 (mi_off, drop, h):")
    for total, mi_off, drop_base, mi in results[:5]:
        print(f"    mi_off={mi_off:+d}  drop={drop_base}  h={total}  MI={mi:08X}")
    return results[0]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--bin',          required=True,  help='.bin payload file')
    parser.add_argument('--key',          required=True,  help='10 hex chars e.g. <YOUR_KEY_HEX>')
    parser.add_argument('--random-keys',  type=int, default=300)
    parser.add_argument('--max-payloads', type=int, default=126)
    parser.add_argument('--debug-bits',   action='store_true',
                        help='Print per-bit frequencies for correct key')
    parser.add_argument('--scan-payloads',type=int, default=0,
                        help='Scan N first payloads individually (slow)')
    args = parser.parse_args()

    key5 = bytes.fromhex(args.key)

    payloads = []
    with open(args.bin, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or len(line) < 66:
                continue
            parts = line.split(';')
            meta  = {k.strip().upper(): v.strip()
                     for part in parts[1:]
                     for k, v in [part.split('=', 1)] if '=' in part}
            payloads.append({
                'bytes': bytes.fromhex(parts[0][:66]),
                'mi':    int(meta.get('MI', '0'), 16),
            })

    print(f"Loaded {len(payloads)} payloads")
    print(f"Key:    {args.key.upper()}")
    print(f"MI[0]:  {payloads[0]['mi']:08X}")

    # ----------------------------------------------------------------
    # STEP 1: PRIMARY -- bit-frequency scoring (correct pipeline)
    # ----------------------------------------------------------------
    print("\n" + "="*60)
    print("STEP 1: Bit-frequency Z-score  (PRIMARY METRIC)")
    print("="*60)
    best_z    = -1e9
    best_cfg  = None
    for b0 in range(6):
        for lfsr in [32, 1]:
            z = zscore_bit_freq(payloads, key5, b0, lfsr,
                                args.random_keys, args.max_payloads,
                                f"b0={b0} lfsr={lfsr}")
            if z > best_z:
                best_z   = z
                best_cfg = (b0, lfsr)

    print(f"\n>>> BEST BIT-FREQ: b0={best_cfg[0]}  lfsr={best_cfg[1]}  Z={best_z:.2f}")

    # ----------------------------------------------------------------
    # STEP 2: Per-bit frequency table for best configuration
    # ----------------------------------------------------------------
    if args.debug_bits or best_z > 3:
        debug_bit_freq(payloads, key5, best_cfg[0], best_cfg[1], args.max_payloads)

    # ----------------------------------------------------------------
    # STEP 3: C0 Hamming (legacy -- expected to show Z~=0, confirms VQ issue)
    # ----------------------------------------------------------------
    print("\n" + "="*60)
    print("STEP 3: C0 inter-frame Hamming  (legacy -- expected Z~=0)")
    print("="*60)
    debug_c0_hamming(payloads, key5, best_cfg[0], best_cfg[1], n_payloads=6)
    zscore_hamming_sf(payloads, key5, best_cfg[0], best_cfg[1], 12,
                      min(args.random_keys, 100), args.max_payloads,
                      f"best_cfg b0={best_cfg[0]} lfsr={best_cfg[1]}")

    # ----------------------------------------------------------------
    # STEP 4: Optional per-payload scan
    # ----------------------------------------------------------------
    if args.scan_payloads > 0:
        print("\n" + "="*60)
        print("STEP 4: Per-payload (mi_offset, drop) scan")
        print("="*60)
        for pidx in range(min(args.scan_payloads, len(payloads))):
            scan_payload(payloads[pidx]['bytes'], payloads[pidx]['mi'], key5)

    # ----------------------------------------------------------------
    # Final verdict
    # ----------------------------------------------------------------
    print("\n" + "="*60)
    if best_z >= 7:
        print(f"RESULT: EXCELLENT Z={best_z:.2f} -- kernel WILL find the key reliably")
    elif best_z >= 5:
        print(f"RESULT: GOOD Z={best_z:.2f} -- may work but borderline")
    elif best_z >= 3:
        print(f"RESULT: MARGINAL Z={best_z:.2f} -- need more payloads or better metric")
    else:
        print(f"RESULT: INSUFFICIENT Z={best_z:.2f} -- scoring metric does not discriminate")
        print("  Possible causes:")
        print("  - Wrong MI / drop scheme (try different b0 / lfsr values)")
        print("  - Short recording (few frames -> weak statistics)")
        print("  - Unvoiced/silence content (uniform AMBE parameters)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
