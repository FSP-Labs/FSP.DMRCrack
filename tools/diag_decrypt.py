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
diag_decrypt.py - Definitive decryption pipeline diagnostic.

Tests whether rc4 decryption of payload[0] with known key produces
non-random AMBE data, by brute-scanning (mi_offset, drop) across a
wide range and checking inter-frame Hamming distance + bit uniformity.

Usage:
    python tools/diag_decrypt.py --bin test/aaaaa/RC4-40.fromdsdfme.bin --key <YOUR_KEY_HEX>
"""
import sys, random, argparse

# -----------------------------------------------------------------------
# De-interleave tables (standard AMBE3600x2450 / DMR)
# -----------------------------------------------------------------------
rW = [0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1, 0,1,0,1,0,2, 0,2,0,2,0,2, 0,2,0,2,0,2]
rX = [23,10,22,9,21,8, 20,7,19,6,18,5, 17,4,16,3,15,2, 14,1,13,0,12,10, 11,9,10,8,9,7, 8,6,7,5,6,4]
rY = [0,2,0,2,0,2, 0,2,0,3,0,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3, 1,3,1,3,1,3]
rZ = [5,3,4,2,3,1, 2,0,1,13,0,12, 22,11,21,10,20,9, 19,8,18,7,17,6, 16,5,15,4,14,3, 13,2,12,1,11,0]

_SF_DIBITS = [
    list(range(0, 36)),
    list(range(36, 54)) + list(range(78, 96)),
    list(range(96, 132)),
]

# -----------------------------------------------------------------------
# LFSR (taps {31,3,1})
# -----------------------------------------------------------------------
def lfsr_next(mi, steps=1):
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        bit = ((mi >> 31) ^ (mi >> 3) ^ (mi >> 1)) & 1
        mi = ((mi << 1) | bit) & 0xFFFFFFFF
    return mi

def lfsr_prev(mi, steps=1):
    mi &= 0xFFFFFFFF
    for _ in range(steps):
        old31 = ((mi >> 0) ^ (mi >> 4) ^ (mi >> 2)) & 1
        mi = (mi >> 1) | (old31 << 31)
    return mi & 0xFFFFFFFF

# -----------------------------------------------------------------------
# RC4
# -----------------------------------------------------------------------
def rc4_decrypt(key, drop, cipher):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    # drop N bytes
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

def make_key9(key5, mi):
    return key5 + bytes([(mi >> 24) & 0xFF, (mi >> 16) & 0xFF, (mi >> 8) & 0xFF, mi & 0xFF])

# -----------------------------------------------------------------------
# De-interleave
# -----------------------------------------------------------------------
def get_dibit(payload, d):
    return (payload[d >> 2] >> ((3 - (d & 3)) * 2)) & 0x3

def deinterleave_sf(payload, sf):
    ambe_fr = [[0]*24 for _ in range(4)]
    for i, d in enumerate(_SF_DIBITS[sf]):
        dibit = get_dibit(payload, d)
        ambe_fr[rW[i]][rX[i]] = (dibit >> 1) & 1
        ambe_fr[rY[i]][rZ[i]] = dibit & 1
    return ambe_fr

# -----------------------------------------------------------------------
# mbe_demodulate (uses encrypted C0 as seed)
# -----------------------------------------------------------------------
def mbe_demodulate(ambe_fr):
    import copy
    fr = copy.deepcopy(ambe_fr)
    foo = 0
    for i in range(23, 11, -1):
        foo = (foo << 1) | fr[0][i]
    pr = [0]*24
    pr[0] = 16 * foo
    for i in range(1, 24):
        pr[i] = (173 * pr[i-1] + 13849) % 65536
    for i in range(1, 24):
        pr[i] = pr[i] // 32768
    k = 1
    for j in range(22, -1, -1):
        fr[1][j] ^= pr[k]
        k += 1
    return fr

# -----------------------------------------------------------------------
# extract_ambe_d: 49 info bits from ambe_fr
# -----------------------------------------------------------------------
def extract_ambe_d(ambe_fr):
    bits = []
    for j in range(23, 11, -1):    # C0: 12 bits
        bits.append(ambe_fr[0][j])
    for j in range(22, 10, -1):    # C1: 12 bits (after demod)
        bits.append(ambe_fr[1][j])
    for j in range(10, -1, -1):    # C2: 11 bits
        bits.append(ambe_fr[2][j])
    for j in range(13, -1, -1):    # C3: 14 bits
        bits.append(ambe_fr[3][j])
    return bits

# -----------------------------------------------------------------------
# pack / unpack  49 bits <-> 7 bytes  (MSB-first)
# -----------------------------------------------------------------------
def pack_ambe(bits49):
    result = bytearray(7)
    for i, b in enumerate(bits49):
        result[i >> 3] |= (b & 1) << (7 - (i & 7))
    return bytes(result)

def unpack_ambe(data7):
    return [((data7[i >> 3]) >> (7 - (i & 7))) & 1 for i in range(49)]

# -----------------------------------------------------------------------
# Full decrypt: payload + sf + key9 + drop -> 49 plaintext bits
# -----------------------------------------------------------------------
def decrypt_sf(payload, sf, key5, mi, drop):
    ambe_fr = deinterleave_sf(payload, sf)
    ambe_fr = mbe_demodulate(ambe_fr)
    bits_enc = extract_ambe_d(ambe_fr)
    cipher7  = pack_ambe(bits_enc)
    key9     = make_key9(key5, mi)
    plain7   = rc4_decrypt(key9, drop, cipher7)
    return unpack_ambe(plain7)

# -----------------------------------------------------------------------
# Hamming distance on first n bits
# -----------------------------------------------------------------------
def hamming(a, b, n=12):
    return sum(a[i] != b[i] for i in range(n))

# -----------------------------------------------------------------------
# Load .bin
# -----------------------------------------------------------------------
def load_bin(path):
    payloads = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or len(line) < 66:
                continue
            parts = line.split(';')
            meta = {}
            for p in parts[1:]:
                if '=' in p:
                    k, v = p.split('=', 1)
                    meta[k.strip().upper()] = v.strip()
            payloads.append({
                'bytes': bytes.fromhex(parts[0][:66]),
                'mi': int(meta.get('MI', '0'), 16),
            })
    return payloads


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--bin',  required=True)
    parser.add_argument('--key',  required=True, help='10 hex chars e.g. <YOUR_KEY_HEX>')
    args = parser.parse_args()

    key5 = bytes.fromhex(args.key)
    payloads = load_bin(args.bin)
    print(f"Loaded {len(payloads)} payloads")
    print(f"Key5:   {args.key.upper()}")
    print(f"MI[0]:  {payloads[0]['mi']:08X}")
    print(f"MI[1]:  {payloads[1]['mi']:08X}  (should = lfsr(MI[0],1) = {lfsr_next(payloads[0]['mi'],1):08X})")
    print(f"MI[6]:  {payloads[6]['mi']:08X}  (should = lfsr(MI[0],6) = {lfsr_next(payloads[0]['mi'],6):08X})")
    print()

    # -----------------------------------------------------------------------
    # TEST 1: Decrypt payload[0] with MI=.bin_MI and drop=256
    # Then print 49 decrypted bits vs random key
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 1: payload[0], MI from .bin (F2E3C97C), drop=256")
    print("="*60)
    for sf in range(3):
        bits_correct = decrypt_sf(payloads[0]['bytes'], sf, key5,
                                  payloads[0]['mi'], 256)
        bits_random  = decrypt_sf(payloads[0]['bytes'], sf,
                                  bytes([random.randint(0,255) for _ in range(5)]),
                                  payloads[0]['mi'], 256)
        cnt_correct = sum(bits_correct)
        cnt_random  = sum(bits_random)
        print(f"  sf={sf}  correct: {cnt_correct:>3}/49 ones  {''.join(str(b) for b in bits_correct)}")
        print(f"  sf={sf}  random:  {cnt_random:>3}/49 ones  {''.join(str(b) for b in bits_random)}")
    print()

    # -----------------------------------------------------------------------
    # TEST 2: Brute scan (mi_offset, drop) for payload[0] — find min HD
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 2: Wide brute scan payload[0] — min Hamming distance (C0+C1 24 bits)")
    print("="*60)
    base_mi = payloads[0]['mi']
    results = []
    for mi_off in range(-10, 64):
        if mi_off >= 0:
            mi = lfsr_next(base_mi, mi_off)
        else:
            mi = lfsr_prev(base_mi, -mi_off)
        for burst_pos in range(6):
            drop = 256 + burst_pos * 21
            dec = [decrypt_sf(payloads[0]['bytes'], sf, key5, mi, drop + sf*7)
                   for sf in range(3)]
            h01 = hamming(dec[0], dec[1], 24)
            h12 = hamming(dec[1], dec[2], 24)
            results.append((h01 + h12, mi_off, burst_pos, drop, mi))
    results.sort()
    print(f"  Best 10 results (sum_h, mi_off, burst_pos, drop, MI):")
    for total, mi_off, bp, drop, mi in results[:10]:
        print(f"    sum_h={total:>2}  mi_off={mi_off:+3d}  burst_pos={bp}  drop={drop}  MI={mi:08X}")
    print(f"  Random key would give sum_h ~= {24} on average (12 per pair)")
    print()

    # -----------------------------------------------------------------------
    # TEST 3: Bit frequency over first 6 payloads (one superframe) using correct params
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 3: Bit frequencies for first superframe (6 payloads)")
    print("  Using: MI=payloads[0]['mi']=F2E3C97C for all, drops 256..361")
    print("="*60)
    base_mi = payloads[0]['mi']
    counts  = [0]*49
    n_frames = 0
    for pidx in range(6):
        burst_pos = pidx  # b0=0, so burst_pos = pidx%6 = pidx
        drop_base = 256 + burst_pos * 21
        for sf in range(3):
            bits = decrypt_sf(payloads[pidx]['bytes'], sf, key5, base_mi, drop_base + sf*7)
            for j in range(49):
                counts[j] += bits[j]
            n_frames += 1
    half = n_frames / 2.0
    score = sum((c - half)**2 for c in counts)
    max_dev = max(abs(c - half) for c in counts)
    print(f"  {n_frames} frames, score={score:.1f}")
    print(f"  Max |count - half|: {max_dev:.1f}  (random key expect ~{(n_frames*0.5)**0.5:.1f})")
    print(f"  Bit counts [0..48]: {' '.join(str(c) for c in counts)}")
    print()

    # -----------------------------------------------------------------------
    # TEST 4: Check if any payload pair in same superframe has low Hamming
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 4: Inter-burst Hamming across ALL 126 payloads (correct params b0=0,lfsr=32)")
    print("="*60)
    base_mi = payloads[0]['mi']
    all_hd = []
    for pidx in range(0, len(payloads)):
        abs_burst = pidx   # b0=0
        sf_num    = abs_burst // 6
        burst_pos = abs_burst  % 6
        mi        = lfsr_next(base_mi, 32 * sf_num)
        drop      = 256 + burst_pos * 21
        dec = [decrypt_sf(payloads[pidx]['bytes'], sf, key5, mi, drop + sf*7)
               for sf in range(3)]
        h01 = hamming(dec[0], dec[1], 24)
        h12 = hamming(dec[1], dec[2], 24)
        all_hd.append(h01 + h12)

    mean_hd = sum(all_hd) / len(all_hd)
    min_hd  = min(all_hd)
    max_hd  = max(all_hd)
    below_8 = sum(1 for h in all_hd if h <= 8)
    print(f"  mean={mean_hd:.2f}  min={min_hd}  max={max_hd}  count<=8: {below_8}/{len(all_hd)}")
    print(f"  First 20: {all_hd[:20]}")
    print()

    # -----------------------------------------------------------------------
    # TEST 5: Same, but use direct .bin MI (1-step per entry, no 32-step reset)
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 5: Same but using DIRECT .bin MI (1-step per entry)")
    print("="*60)
    all_hd2 = []
    for pidx in range(len(payloads)):
        burst_pos = pidx % 6   # assume b0=0
        mi_direct = payloads[pidx]['mi']
        drop      = 256 + burst_pos * 21
        dec = [decrypt_sf(payloads[pidx]['bytes'], sf, key5, mi_direct, drop + sf*7)
               for sf in range(3)]
        h01 = hamming(dec[0], dec[1], 24)
        h12 = hamming(dec[1], dec[2], 24)
        all_hd2.append(h01 + h12)
    mean_hd2 = sum(all_hd2) / len(all_hd2)
    min_hd2  = min(all_hd2)
    below_8_2 = sum(1 for h in all_hd2 if h <= 8)
    print(f"  mean={mean_hd2:.2f}  min={min_hd2}  max={max(all_hd2)}  count<=8: {below_8_2}/{len(all_hd2)}")
    print(f"  First 20: {all_hd2[:20]}")
    print()

    # -----------------------------------------------------------------------
    # TEST 6: Per-bit frequency over all 126 payloads (best params)
    # -----------------------------------------------------------------------
    print("="*60)
    print("TEST 6: Per-bit frequencies all 126 payloads, correct key, b0=0, lfsr=32")
    print("="*60)
    base_mi = payloads[0]['mi']
    counts6 = [0]*49
    n6 = 0
    for pidx in range(len(payloads)):
        sf_num    = pidx // 6
        burst_pos = pidx  % 6
        mi        = lfsr_next(base_mi, 32 * sf_num)
        drop      = 256 + burst_pos * 21
        for sf in range(3):
            bits = decrypt_sf(payloads[pidx]['bytes'], sf, key5, mi, drop + sf*7)
            for j in range(49):
                counts6[j] += bits[j]
            n6 += 1
    half6 = n6 / 2.0
    score6 = sum((c - half6)**2 for c in counts6)
    print(f"  {n6} frames total  score={score6:.1f}")
    devs = [(abs(c - half6), j, c) for j, c in enumerate(counts6)]
    devs.sort(reverse=True)
    print(f"  Top 10 biased bits:")
    for dev, j, cnt in devs[:10]:
        print(f"    bit {j:>2}: count={cnt:>3}/{n6}  bias={cnt/n6:.3f}  (0.5={half6:.1f})")
    print(f"  All counts: {counts6}")

    # Compare with random key
    rk = bytes([random.randint(0,255) for _ in range(5)])
    counts_rand = [0]*49
    for pidx in range(len(payloads)):
        sf_num    = pidx // 6
        burst_pos = pidx  % 6
        mi        = lfsr_next(base_mi, 32 * sf_num)
        drop      = 256 + burst_pos * 21
        for sf in range(3):
            bits = decrypt_sf(payloads[pidx]['bytes'], sf, rk, mi, drop + sf*7)
            for j in range(49):
                counts_rand[j] += bits[j]
    score_rand = sum((c - half6)**2 for c in counts_rand)
    print(f"\n  Random key score={score_rand:.1f}")
    print()

    print("="*60)
    print("CONCLUSION:")
    if min_hd <= 4:
        print("  TEST 2 shows decryption WORKS (HD <= 4 found) for correct key!")
    elif min_hd <= 8:
        print("  TEST 2 marginal: best HD=" + str(min_hd) + " (borderline)")
    else:
        print("  TEST 2: No low-HD solution found — decryption may be broken!")
    if score6 > score_rand * 1.5:
        print("  TEST 6: Correct key has notably higher bit-freq score than random")
    elif score6 > score_rand:
        print("  TEST 6: Correct key slightly higher than random (weak signal)")
    else:
        print("  TEST 6: Correct key score <= random — no bit-freq discrimination!")
    print("="*60)


if __name__ == '__main__':
    raise SystemExit(main())
