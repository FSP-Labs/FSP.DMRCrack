# How FSP.DMRCrack works

Technical reference for how FSP.DMRCrack recovers a 40-bit RC4 key from captured
DMR Enhanced Privacy voice, with no known plaintext and no key material to start
from. Audience: contributors and technically-minded users.

> For authorized testing only. See the [legal notice](../README.md#legal--responsible-use).

---

## The problem

DMR Enhanced Privacy encrypts voice with RC4 under a 40-bit key (~2⁴⁰
candidates), small enough to search exhaustively on a GPU. The hard part is the
**oracle**: with no reference audio, how do you tell the right key from a
trillion wrong ones?

The answer is the voice codec. DMR voice is AMBE, and valid speech has
**slowly-varying** parameters between frames. Decrypt with the correct key and
consecutive frames differ little; decrypt with a wrong key and the differences
are large and random. Scored across a capture, the correct key is a sharp
Z-score spike above the noise floor:

```
score
  │                              █   <- the key
  │                              █
  │ · · · · · · · · · · · · · · ·█· · · · ·  Z = 7 threshold
  │~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~█~~~~~~~~~~  noise floor (wrong keys)
  └─────────────────────────────────────── keyspace
```

---

## DMR Enhanced Privacy

Two dialects are supported, both with a 40-bit (5-byte) base key:

| Dialect | ALG id | Key schedule |
|---|---|---|
| MOTOTRBO EP | `0x21` (also `0x01`) | RC4 with a 9-byte key: `key9 = key5 ‖ MI[4]` |
| Hytera EP | `0x02` | RC4 with the 5-byte key; keystream XOR'd with a key-IV from `key5` + MI |

Both mix in a per-superframe **Message Indicator (MI)** transmitted in the clear
in PI headers, so it is known to an attacker (MOTOTRBO: 32-bit MI; Hytera:
40-bit MI). The only unknown is the 5-byte key.

`ALG=0x26` is **Caltta Basic Privacy**, not EP; the RC4-40 model cannot decode it
(its bitstream keeps the +7-bit skip genuine EP omits), so it is rejected rather
than mis-decoded. AES (DMR-AES / Hytera HP) and DMRA are not supported.

---

## Pipeline

Capture and playback are handled by a bundled
[DSD-FME](https://github.com/lwvmobile/dsd-fme); the brute-forcer sits in the
middle.

```
[1 Capture]     WAV file, or RTL-SDR live  ──►  DSD-FME demodulates
[2 Demodulate]  encrypted AMBE bursts       ──►  .bin (per-burst MI, ALG, KID)
[3 Crack]       GPU sweeps the keyspace      ──►  key5 (10 hex)
[4 Listen]      DSD-FME with -1 <key5>        ──►  decrypted WAV + playback
```

### The `.bin` payload format

One voice burst per line, 33 bytes (66 hex chars) of de-interleaved dibits, with
metadata after `;`:

```
AABBCCDD...;ALG=21;KID=0F;MI=12345678
```

- 33 bytes = 132 dibits = one voice burst payload, excluding the sync slot.
- The **same MI** is shared by all 6 bursts of a superframe.
- Between superframes the MOTOTRBO MI advances by **32 LFSR steps** (taps
  `{31, 3, 1}`): `bit = ((mi>>31) ^ (mi>>3) ^ (mi>>1)) & 1; mi = (mi<<1) | bit`.

---

## Per-candidate decode (MOTOTRBO, ALG 0x21)

For **every** candidate key the kernel runs the full DSD-FME / mbelib decode per
burst. This is the expensive inner loop. For burst `k` (0..5) of a superframe:

1. Build the RC4 key: `key9 = key5 ‖ MI[4]` (same MI for all 6 bursts).
2. RC4 KSA, then discard `256 + k·21` bytes of keystream (accumulated across
   sub-frames within the burst).
3. For each of the 3 sub-frames:
   1. **De-interleave** the 33-byte payload into `ambe_fr[4][24]`.
   2. **mbelib demodulate**: derive a 12-bit seed from `C0`, run the mbelib PRNG,
      XOR it onto row 1.
   3. **Extract** 49 AMBE bits (`C0..C3`) and pack to 7 bytes (MSB-first).
   4. **RC4 decrypt** those 7 bytes, then unpack back to 49 bits.
4. **Score** the recovered bits (below).

De-interleave layout for a 33-byte payload (132 dibits):

```
SF0:  dibits 0..35
SF1:  dibits 36..53  and  78..95   (split by the sync at 54..77)
SF2:  dibits 96..131
sync: dibits 54..77  (skipped, not voice)
```

RC4 is applied to the **packed AMBE sub-frames, not the raw interleaved
payload** — de-interleave first, then decrypt the 7-byte packed cipher. Applying
RC4 to the raw burst scores like noise even for the correct key.

---

## Scoring

Two metrics, each clearing the detection threshold on its own.

**Inter-frame Hamming (primary).** `C0` (12 bits) and `C1` (12 bits) encode
slowly-varying voice parameters. For each pair of consecutive sub-frames, measure
the Hamming distance over those 24 bits:

- Correct key: HD ≈ 0..4 (speech changes little frame to frame).
- Wrong key: HD ≈ 12 (random — half the bits differ).

`score = Σ (24 − HammingDistance)` across consecutive sub-frame pairs.

**Bit-frequency chi-squared.** Accumulate per-bit counts across all frames. A
wrong key gives a uniform distribution; the correct key is strongly non-uniform.
`score = Σ (countᵢ − N/2)²`.

**Z-score and verdict.** The best candidate is normalized to a capture-size
significance `Z = (r − 24)·√n / √12`, where `r` is its mean per-burst inter-frame
agreement over `n` bursts (a wrong key sits at `r ≈ 24`, so `Z ≈ 0`). The
luckiest wrong key in a full 2⁴⁰ scan peaks near `Z ≈ √(2·40·ln2) ≈ 7.5`, so the
tool reports a verdict, not a raw number:

- **CONFIRMED** — `Z ≥ 12` and `chi²/n ≥ 20`: a genuine recovery.
- **UNVERIFIED** — `7 ≤ Z < 12`: possible but weak; confirm the key with DSD-FME.
- **no confirmed key** — below that: indistinguishable from the luckiest wrong key.

A dictionary/statistical latch inflates the chi² term but cannot fake inter-frame
agreement, so its `Z` stays near zero and it is never presented as a recovery. On
the 126-payload test capture the correct key reaches `Z ≈ 48`.

---

## The Hytera dialect (ALG 0x02)

A dedicated kernel handles Hytera EP, so it adds zero overhead to the MOTOTRBO
path:

- RC4 KSA with the **5-byte key only** (no MI in the KSA, drop = 0).
- Keystream octets are XOR'd with a key-IV: `kiv[i] = key5[i] ⊕ MI[i]` over all 5
  bytes (40-bit big-endian MI), matching DSD-FME's `hytera_enhanced_rc4_setup`.
- **One keystream per superframe, consumed as a bitstream at 49 bits per AMBE
  frame.** Unlike MOTOTRBO/P25, Hytera does **not** skip the trailing 7 bits, so
  frame `f = burst·3 + sf` reads keystream bits `[f·49 … f·49+48]` (MSB-first,
  not byte-aligned — only frame 0 starts on a byte boundary). An earlier
  byte-aligned model decrypted only the first frame correctly, which is why
  Hytera never validated until it was fixed.
- The RC4 output depends only on the 5-byte key (MI enters only as the `kiv`
  mask), so the keystream is built **once per key** and re-masked per superframe —
  the dominant cost, hoisted out of the loop.
- The Hytera inter-superframe MI advances with its own 5-byte Galois LFSR (taps
  `12 24 48 22 14`), distinct from the MOTOTRBO LFSR, so one decoded PI header
  tags a whole capture.

The keystream is single-sourced in `include/hytera_ks.h`, verified byte-for-byte
against DSD-FME's model and end-to-end against a planted-key synthetic capture.
Scoring (inter-frame Hamming + bit-frequency) is identical to MOTOTRBO; the mode
is auto-selected from the ALG distribution of the loaded capture.

---

## On the GPU

Each thread tests one key by running the full decode + score above.

- **One engine, three back-ends.** CUDA (NVIDIA), HIP (AMD ROCm) and a portable
  OpenCL path (NVIDIA / AMD / Intel), the OpenCL kernels ported 1:1 from the CUDA
  source. With no GPU it falls back to a multi-threaded CPU scorer.
- **No torn reads on the best key.** The best score and its key are packed into a
  single 64-bit value updated with one `atomicMax`. The score is truncated to
  24 bits for the GPU ordering compare; full precision is recomputed host-side for
  the final result.
- **Checkpointing.** A `.progress` sidecar is written every 30 s, so a long run
  survives a stop or reboot and resumes where it left off (single-GPU runs; an
  N-GPU work-queue claims blocks out of order, so those skip the linear
  checkpoint).
- **Noise-tolerant early-reject.** A wrong key sits at the random inter-frame
  baseline (24/burst); the correct key beats it. Rather than score all bursts for
  every candidate, the kernel drops a key once its running Hamming falls below the
  floor `24·n + 8·√n` after one superframe (`n ≥ 6`). An earlier, tighter floor
  (`33·n`) was faster but pruned the correct key whenever demod noise dragged it
  below 33/burst — the reason real captures once "found nothing". The current
  floor keeps even a badly degraded correct key while rejecting the bulk of the
  keyspace within a superframe or two.

Throughput figures are in the [README](../README.md#supported-ciphers).

---

## Correctness

Verified end to end:

- **Synthetic roundtrip:** 600/600 encrypt-then-decrypt cycles pass.
- **Real data:** the recovered key on a real EP capture produces the Z-scores
  above, and feeding it back into DSD-FME (`-1 <key> -w out.wav`) yields
  intelligible voice.
- **Same algorithm everywhere:** the CPU scorer, the CUDA/HIP kernel and the
  OpenCL kernel run the identical decode, cross-checked against DSD-FME's own
  decoder and guarded by the host tests (`build_tests.bat`).

---

## Source map

| Topic | Where |
|---|---|
| GPU kernels + CPU fallback | `src/bruteforce.cu` |
| OpenCL kernels (1:1 port) | `src/dmrcrack.cl`, `src/bruteforce_cl.cpp` |
| `.bin` loader + MI/ALG/KID parsing | `src/payload_io.c` |
| RC4 KSA/PRGA | `src/rc4.c` |
| Hytera keystream (single source) | `include/hytera_ks.h` |
| De-interleave tables (single source) | `include/dmr_tables.h` |
| Scoring validation against a known key | `tests/test_strict_score.c` |
| Capture → `.bin` conversion | `tools/dsdfme_dsp_to_bin.py` |
| Key validation (Z-scores) | `tools/verify_decrypt.py` |

To contribute, see [CONTRIBUTING.md](../CONTRIBUTING.md). Benchmarks on
AMD / Intel / Apple GPUs are welcome.
