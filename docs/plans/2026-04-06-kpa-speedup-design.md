# KPA + Speed-Up Design — 2026-04-06

## Summary

Two independent tracks that improve brute-force throughput and add an optional
Known-Plaintext Attack (KPA) pre-filter that reduces the effective search space
by up to 99.6 % when silence frames are present in the captured payload set.

---

## Track 1 — Speed

### 1.1 ILP-2 kernel enabled

`bruteforce_kernel_ilp2` already exists in `bruteforce.cu` but is gated by
`use_ilp2 = 0`.  Change the selection condition to:

```c
int use_ilp2 = (mode_policy >= 2) && (cuda_sm >= 75);
```

This activates the 2-keys-per-thread kernel on all Turing+ GPUs whenever the
correct KMI9 pipeline is in use (the default for any payload with MI metadata).
Estimated gain: +50–80 % GPU throughput.

### 1.2 GPU / CPU split changed to 80 / 20

The current formula gives the larger share to CPU.  Invert it:

```c
uint64_t gpu_range = (total_keys * (uint64_t)cfg->gpu_split_pct) / 100ULL;
uint64_t cpu_range = total_keys - gpu_range;
```

Default `gpu_split_pct = 80`.

### 1.3 Split configurable — not hardcoded

Add `int gpu_split_pct` to `BruteforceConfig` (range 50–95, step 5, default 80).
Expose it in the GUI as a spin / edit control labelled "GPU %" in the brute-force
panel.  Persisted like the other brute-force options (no file, just in-memory for
the session — same as current key-range fields).

---

## Track 2 — KPA Silence Frame Pre-Filter

### Background

In AMBE 3600×2450, bit 0 of the C0 field (`ambe_d[0]`) is the voicing flag:
`0` = unvoiced (silence), `1` = voiced (speech).  After MSB-first packing,
`ambe_d[0]` lands on **bit 7 of `plaintext[0]`** for every sub-frame.

When a frame contains silence, we therefore know:

```
plaintext[0] bit 7 == 0
⟹  keystream[0] bit 7 == ciphertext[0] bit 7
```

This 1-bit constraint is independent of the exact silence codec pattern and
works for any radio vendor.  With N independent silence candidates (each with a
different `key9 = key5 ∥ MI` and a different `drop` offset) the probability
that a **wrong** key passes all N checks is `(1/2)^N`:

| N silence candidates | Wrong-key pass rate |
|---|---|
| 4 | 6.25 % |
| 8 | 0.39 % |
| 16 | 0.0015 % |
| 40 | ≈ 0 (< 2^-40) |

### Silence candidate identification

`dsdfme_dsp_to_bin.py` already parses the DSP output line-by-line.  The DSP
format includes a burst-type field per line:

```
<slot> <type_hex> <66_hex_chars>
  type 98 = voice header  (start of transmission)
  type 10 = voice burst
  type 99 = LE silence burst (superframe boundary)
```

The converter tracks position within each superframe (counts `10` lines since
last `98` or `99`).  A line is marked as a **silence candidate** when it is the
first `10` burst after a `98` (= burst 0 of the first superframe of a
transmission).

New metadata tag appended to the `.bin` line:

```
...;SILENCE=1
```

`payload_io.c` already parses semicolon-delimited tags; add `SILENCE` → `PayloadLine.silence_candidate`.

### Pre-filter in the CUDA kernel

At the top of the inner loop (before the scoring pass), if the payload set
contains any silence candidates, perform the 1-bit check for each candidate
with `mode_policy >= 2`:

```c
for (int si = 0; si < ps->n_silence; si++) {
    const PayloadLine *sl = &ps->lines[ps->silence_idx[si]];
    /* Build key9, RC4 KSA, discard to drop, read byte 0 */
    uint8_t ks0 = rc4_byte0(key9, sl->drop);
    uint8_t expected_msb = (sl->cipher[0] >> 7) & 1;
    uint8_t actual_msb   = (ks0 >> 7) & 1;
    if (actual_msb != expected_msb) goto next_key;
}
/* Full scoring pass only if all silence checks pass */
```

`ps->silence_idx[]` is a small pre-computed array (max 64 entries) of indices
into `ps->lines[]` where `silence_candidate == 1`.  Built once in
`bruteforce_start()` before the kernel launch.

The CPU path in `bruteforce.c` (`score_burst_correct_cpu`) receives the same
pre-filter before calling the full scoring function.

### Fallback

If `ps->n_silence == 0` (no silence metadata in the `.bin` file — e.g. file
loaded from an older converter or manually constructed), the pre-filter loop is
skipped entirely and search behaviour is identical to today.

### GUI change

The metric tile for THROUGHPUT (or a small label below it) shows:

```
KPA: 8 silence frames  →  ~250× pre-filter
```

when `n_silence > 0`.  No new controls.

---

## Data-flow diagram

```
WAV file
  └─ dsd-fme -Q → DSP output (.dsdsp.txt)
       └─ dsdfme_dsp_to_bin.py
            ├─ parses PI headers  → ALG / KID / MI
            ├─ tracks burst type  → marks SILENCE=1 on first burst of each TX
            └─ writes .bin file
                 └─ BruteforceEngine
                      ├─ builds silence_idx[] from PayloadSet
                      ├─ CUDA kernel:
                      │    ├─ [KPA pre-filter]  ← NEW (Track 2)
                      │    └─ [full scoring]
                      └─ CPU workers (20 %) ← split change (Track 1)
```

---

## Files touched

| File | Change |
|---|---|
| `src/bruteforce.cu` | Enable ILP-2; invert GPU/CPU split; add KPA pre-filter |
| `src/bruteforce.c` | Invert split; add KPA pre-filter before `score_burst_correct_cpu` |
| `include/bruteforce.h` | Add `gpu_split_pct` to `BruteforceConfig`; add `silence_idx[]` / `n_silence` to `PayloadSet` proxy passed to kernel |
| `src/payload_io.c` | Parse `SILENCE=` tag into `PayloadLine.silence_candidate` |
| `include/payload_io.h` | Add `uint8_t silence_candidate` to `PayloadLine` |
| `src/gui.c` | GPU % spin control; KPA badge in throughput tile |
| `tools/dsdfme_dsp_to_bin.py` | Track burst type per line; emit `SILENCE=1` on first burst of each TX |

---

## Success criteria

- `test_strict_score.exe` on `test/aaaaa/RC4-40.fromdsdfme.bin` still gives
  Z ≥ 48 sigma (no regression).
- With a `.bin` that has `SILENCE=1` tags and 8 candidates, wrong-key pass rate
  through the pre-filter ≈ 0.4 % (verifiable with a synthetic sweep in Python).
- GPU % spin control changes the split visible in brute-force progress (GPU keys
  / CPU keys breakdown in the throughput tile).
- Build succeeds without warnings on sm_75 / sm_86 / sm_89.
