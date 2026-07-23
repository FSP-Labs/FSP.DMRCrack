# How FSP.DMRCrack works

A technical walkthrough of how FSP.DMRCrack recovers a 40-bit RC4 key from
captured DMR Enhanced Privacy voice, with no known plaintext and no key
material to start from.

> For authorized testing only. See the [legal notice](../README.md#legal--responsible-use).

---

## The short version

DMR Enhanced Privacy encrypts voice with RC4 under a 40-bit key, roughly a
trillion (2⁴⁰) candidates. That is small enough to search exhaustively on a GPU.
The hard part is not the search, it is the **oracle**: how do you know, without
any reference audio, which of a trillion keys is the right one?

The answer comes from the voice codec. DMR voice is AMBE, and valid speech has
**slowly varying** parameters between frames. Decrypt a capture with the correct
key and consecutive frames look like speech (tiny differences). Decrypt with a
wrong key and you get noise (large, random differences). Score that difference
across a capture and the correct key stands out as a sharp **Z-score spike**
well above the noise floor.

```
score
  │                              █   <- the key
  │                              █
  │ · · · · · · · · · · · · · · ·█· · · · ·  Z = 7 threshold
  │~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~█~~~~~~~~~~  noise floor (wrong keys)
  └─────────────────────────────────────── keyspace
```

---

## Background: DMR Enhanced Privacy

DMR Enhanced Privacy (EP) is the encryption built into MOTOTRBO, Hytera and
other DMR Tier II/III radios. Two dialects matter here:

| Dialect | ALG id | Key schedule |
|---|---|---|
| MOTOTRBO EP | `0x21` (also `0x01`) | RC4 with a 9-byte key: `key9 = key5 ‖ MI[4]` |
| Hytera EP | `0x02` | RC4 with the 5-byte key, keystream XOR'd with a key-IV derived from `key5` + MI |

Both use a **40-bit (5-byte) base key**. Both mix in a per-superframe
**Message Indicator (MI)** that is transmitted in the clear in PI headers, so it
is known to an attacker (MOTOTRBO uses a 32-bit MI, Hytera a 40-bit MI). The
unknown is only the 5-byte key.

A 2⁴⁰ keyspace at tens of millions of keys/s finishes in hours. The search is
embarrassingly parallel, which is why this is a GPU problem.

---

## The pipeline

FSP.DMRCrack orchestrates four stages; capture and playback are handled by a
bundled [DSD-FME](https://github.com/lwvmobile/dsd-fme), the brute-forcer sits
in the middle.

```
[1 Capture]   WAV file, or RTL-SDR live  ──►  DSD-FME demodulates
[2 Demodulate]  encrypted AMBE bursts     ──►  .bin (per-burst MI, ALG, KID)
[3 Crack]       GPU sweeps the keyspace    ──►  key5 (10 hex)
[4 Listen]      DSD-FME with -1 <key5>      ──►  decrypted WAV + playback
```

### The `.bin` payload format

One voice burst per line, 33 bytes (66 hex chars) of de-interleaved dibits, with
metadata after `;`:

```
AABBCCDD...;ALG=21;KID=0F;MI=12345678
```

- 33 bytes = 132 dibits = one voice burst payload, excluding the sync slot.
- The **same MI** is shared by all 6 bursts of a superframe.
- Between superframes the MI advances by **32 LFSR steps** (taps `{31, 3, 1}`):
  `bit = ((mi>>31) ^ (mi>>3) ^ (mi>>1)) & 1; mi = (mi<<1) | bit`.

---

## Cracking: the per-candidate decode (MOTOTRBO, ALG 0x21)

For **every** candidate key, the kernel runs the complete DSD-FME / mbelib decode
pipeline per burst. This is the expensive inner loop; everything is tuned around
making it fast on a GPU.

For burst `k` (0..5) of a superframe:

1. **Build the RC4 key.** `key9 = key5 ‖ MI[4]` (same MI for all 6 bursts).
2. **RC4 KSA**, then discard `256 + k·21` bytes of keystream (accumulated across
   sub-frames within the burst).
3. For each of the 3 sub-frames:
   1. **De-interleave** the 33-byte payload into `ambe_fr[4][24]`.
   2. **mbelib demodulate**: derive a 12-bit seed from `C0`, run the mbelib PRNG,
      XOR it onto row 1.
   3. **Extract 49 AMBE bits** (`C0..C3`) and pack to 7 bytes (MSB-first).
   4. **RC4 decrypt** those 7 bytes.
   5. **Unpack** back to 49 bits.
4. **Score** the recovered bits (below).

The de-interleave layout for a 33-byte payload (132 dibits) is:

```
SF0: dibits 0..35
SF1: dibits 36..53  and  78..95   (split by the sync at 54..77)
SF2: dibits 96..131
sync: dibits 54..77 (skipped, not voice)
```

**RC4 is applied to the packed AMBE sub-frames, not to the raw interleaved
payload.** De-interleave first, then decrypt the 7-byte packed cipher. Applying
RC4 to the raw burst scores like noise even for the correct key.

---

## The scoring oracle

After decrypt, we have the AMBE parameter bits for each sub-frame. Two metrics,
both of which clear the detection threshold on their own:

### 1. Inter-frame Hamming (primary)

`C0` (12 bits) and `C1` (12 bits) encode slowly varying voice parameters. For
each pair of consecutive sub-frames, measure the Hamming distance over those
24 bits:

- **Correct key:** HD ≈ 0..4 (speech changes little frame to frame).
- **Wrong key:** HD ≈ 12 (random, half the bits differ).

`score = Σ (24 − HammingDistance)` across consecutive sub-frame pairs.

### 2. Bit-frequency chi-squared

Accumulate per-bit counts across all frames. A wrong key gives a uniform
(coin-flip) distribution; the correct key produces strongly non-uniform bits.
`score = Σ (countᵢ − N/2)²`.

### Why a Z-score

Express the best candidate as a capture-size-normalized significance
`Z = (r − 24)·√n / √12`, where `r` is its mean per-burst inter-frame agreement
over `n` bursts (a wrong key sits at `r ≈ 24`, so `Z ≈ 0`). The luckiest wrong
key in a full 2⁴⁰ scan peaks near `Z ≈ √(2·40·ln2) ≈ 7.5`, so the tool reports a
verdict rather than a raw number:

- **CONFIRMED** — `Z ≥ 12` (and chi²/n ≥ 20): a genuine recovery.
- **UNVERIFIED** — `7 ≤ Z < 12`: possible but weak; confirm the key with DSD-FME.
- **no confirmed key** — below that: indistinguishable from the luckiest wrong key.

A dictionary/statistical latch inflates the bit-frequency term but cannot fake
inter-frame agreement, so its `Z` stays near zero and it is never presented as a
recovery. On the 126-payload test capture the correct key reaches `Z ≈ 48`
(inter-frame Hamming) — far above any plausible noise peak.

---

## The Hytera dialect (ALG 0x02)

Hytera Enhanced Privacy uses a different key schedule, handled by a dedicated
kernel so it adds zero overhead to the MOTOTRBO path:

- RC4 KSA with the **5-byte key only** (no MI in the KSA, drop = 0).
- The keystream octets are XOR'd with a key-IV: `kiv[i] = key5[i] ⊕ MI[i]` over
  all 5 bytes (40-bit big-endian MI), matching DSD-FME's
  `hytera_enhanced_rc4_setup`.
- **One keystream per superframe, consumed as a bitstream at 49 bits per AMBE
  frame.** Unlike MOTOTRBO/P25, Hytera does **not** skip the trailing 7 bits, so
  frame `f = burst·3 + sf` reads keystream bits `[f·49 … f·49+48]` (MSB-first,
  not byte-aligned — only frame 0 starts on a byte boundary). This 49-bit
  indexing is the subtle part; an earlier byte-aligned model decrypted only the
  first frame correctly, which is why Hytera never validated until it was fixed.
- Because the RC4 output depends only on the 5-byte key (the MI enters only as
  the `kiv` mask), the keystream is built **once per key** and re-masked per
  superframe — the dominant cost of the Hytera kernel, hoisted out of the loop.
- Between superframes the Hytera MI advances with its own 5-byte Galois LFSR
  (taps `12 24 48 22 14`), distinct from the MOTOTRBO 32-bit LFSR; one decoded PI
  header therefore tags a whole capture.

The keystream is single-sourced in `include/hytera_ks.h` and verified byte-for-byte
against DSD-FME's model. Hytera EP is signalled under two algids, `0x02` and
`0x26`. The scoring (inter-frame Hamming + bit-frequency) is identical; the mode
is auto-selected from the ALG distribution of the loaded capture.

---

## On the GPU

Each thread tests one key by running the full decode + score above. A few things
make it fast and correct:

- **One engine, three back-ends.** CUDA for NVIDIA, HIP for AMD ROCm, and a
  portable OpenCL path (NVIDIA / AMD / Intel). The OpenCL kernels are ported 1:1
  from the CUDA source. With no GPU it falls back to a multi-threaded CPU scorer.
- **No torn reads on the best key.** The best score and its key are packed into a
  single 64-bit value updated with one `atomicMax`, so there is no race between
  reading the score and the key. The score is truncated to 24 bits for the GPU
  ordering compare; full precision is recomputed host-side for the final result.
- **Checkpointing.** A `.progress` sidecar is written every 30 s, so a long run
  survives a stop or reboot and resumes exactly where it left off.

### Throughput

Measured on an **RTX 3050 Ti laptop GPU (CUDA)**: MOTOTRBO **~38 M keys/s**
(~8 h for the full 2⁴⁰) and Hytera EP **~10 M keys/s**. The MOTOTRBO figure
reflects the noise-tolerant early-reject (below) — it trades raw speed for
recovering keys from real, noisy captures rather than only pristine ones. This is
the **only** configuration benchmarked so far. The portable OpenCL path omits the
CUDA shared-memory ILP-2 kernel and is slower; other GPUs and the HIP/ROCm path
are not yet benchmarked. Narrow the key range whenever you can.

**The early-reject.** A wrong key sits at the random inter-frame baseline
(24/burst); the correct key beats it. Rather than score all 126 bursts for every
candidate, the kernel drops a key the moment its running Hamming falls below a
noise-tolerant floor `24·n + 8·√n` after one superframe (`n ≥ 6`). An earlier,
tighter floor (`33·n`) was faster but pruned the correct key whenever demod noise
dragged it below 33/burst — the reason real captures once "found nothing." The
current floor keeps even a badly degraded correct key while still rejecting the
bulk of the keyspace within a superframe or two.

---

## How we know it is correct

The pipeline is verified end to end:

- **Synthetic roundtrip:** 600/600 encrypt-then-decrypt cycles pass.
- **Real data:** the recovered key on a real Enhanced Privacy capture produces
  the Z-scores above, and feeding that key back into DSD-FME
  (`-1 <key> -w out.wav`) yields intelligible voice.
- **Same algorithm everywhere:** the CPU scorer, the CUDA/HIP kernel and the
  OpenCL kernel run the identical decode, cross-checked against DSD-FME's own
  decoder.

---

## What this does not do

- No non-RC4 ciphers (no AES / DMR-AES / Hytera HP).
- No captures without MI: the strict pipeline needs the Message Indicator. Without
  it, only a much weaker statistical fallback runs.
- No magic on bad audio: if DSD-FME cannot cleanly demodulate the signal, the
  search runs but finds nothing.
- No third-party targets: authorized auditing of systems you own or are
  permitted in writing to test, and nothing else.

---

## References in the source

| Topic | Where |
|---|---|
| GPU kernels + CPU fallback | `src/bruteforce.cu` |
| OpenCL kernels (1:1 port) | `src/dmrcrack.cl`, `src/bruteforce_cl.cpp` |
| `.bin` loader + MI/ALG/KID parsing | `src/payload_io.c` |
| RC4 KSA/PRGA | `src/rc4.c` |
| Scoring validation against a known key | `tests/test_strict_score.c` |
| Capture → `.bin` conversion | `tools/dsdfme_dsp_to_bin.py` |
| Key validation (Z-scores) | `tools/verify_decrypt.py` |

To contribute, see [CONTRIBUTING.md](../CONTRIBUTING.md). Benchmarks on
AMD / Intel / Apple GPUs are welcome.
