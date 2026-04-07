# KPA + Speed-Up Design — 2026-04-07

## Scope

Two independent tracks executed together:

- **Track A – Speed**: ILP-2 kernel activation, GPU/CPU split corrected to 80/20 (configurable)
- **Track B – KPA**: Known-plaintext pre-filter using AMBE voicing bit from silence frame candidates

---

## Track A: Speed Improvements

### A1 — ILP-2 kernel activated

`use_ilp2` in `bruteforce.cu` is currently hardcoded to `0`. Change to:
```c
use_ilp2 = (mode_policy >= 2) && (cuda_sm >= 75);
```
All GPUs capable of `mode_policy=2/3` support ILP-2. Expected gain: +50-80% GPU throughput.

### A2 — GPU/CPU split corrected to 80/20

Current code gives the larger range to CPU. Correct to:
```c
uint64_t gpu_range = (total_keys * cfg->gpu_split_pct) / 100ULL;
uint64_t cpu_range = total_keys - gpu_range;
```
Default `gpu_split_pct = 80`.

### A3 — Split configurable via BruteforceConfig

Add `int gpu_split_pct` (range 50–95, default 80) to `BruteforceConfig`.
GUI: spin control "GPU %" (step 5) in the BF config section.
Stored in `AppState` and passed through to the engine on each scan start.

---

## Track B: KPA — Silence Frame Pre-Filter

### Principle

In AMBE 3600x2450, `ambe_d[0]` (first of the 49 decoded bits) is the **voicing bit**: 0 = unvoiced/silence, 1 = voiced.
After packing (`bit i → byte i//8, bit 7 - i%8`), `ambe_d[0]` maps to **bit 7 of `cipher_plaintext[0]`** (MSB of first packed byte).

For a silence frame: `plaintext[0] & 0x80 == 0` → `keystream_byte0 & 0x80 == ciphertext[0] & 0x80`.

This gives 1 bit of known keystream at a known `(key9, drop)` without knowing the full silence pattern.
With **N independent silence candidates** (different MI + drop): rejection rate = `1 − (½)^N`.

| N silence candidates | Keys rejected before full scoring |
|---|---|
| 1 | 50% |
| 8 | 99.6% |
| 40 | ~100% (2^40 keyspace fully filtered) |

### B1 — DSP output parser extended

`dsdfme_dsp_to_bin.py` already parses the DSP output line by line. Extend to:
- Track burst type per line (`98`=header, `10`=voice, `99`=LE silence burst, `00`=sync)
- Count voice bursts within each superframe (reset on `99`)
- Mark the **first `10` burst of the first superframe of each transmission** with `SILENCE=1` in the `.bin` metadata

Detection rule:
- First superframe: voice burst that follows the preamble sequence (`98`+ / `01`* / `00`?)
- Subsequent silence candidates: burst 0 of each superframe (index resets on `99`)

New `.bin` metadata tag: `SILENCE=1` (appended after MI= if applicable).

### B2 — PayloadLine struct extended

```c
uint8_t silence_candidate; /* 1 = first burst of superframe, potential silence frame */
```
`payload_io.c`: parse `SILENCE=1` tag → set `silence_candidate = 1`.

### B3 — PayloadSet: count silence candidates

Add `size_t n_silence_candidates` to `PayloadSet`, populated in `payload_set_push`.

### B4 — CUDA kernel pre-filter

At the top of the per-key evaluation loop in `bruteforce_kernel_strict` (and `_ilp2`), before the scoring loop:

```c
if (ps.n_silence > 0) {
    for each silence candidate (max 8):
        build key9, compute drop
        RC4 KSA + PRGA to (drop) bytes, read byte 0
        expected_bit = (ciphertext[0] >> 7) & 1
        actual_bit   = (keystream[0] >> 7) & 1
        if (actual_bit != expected_bit) → goto next_key
}
```

Use at most 8 candidates (256× speedup cap, avoids wasting time when many frames marked).

### B5 — GUI badge

In the BF panel, below the payload count label: `"KPA: N silence frames"` (shown only when `n_silence_candidates > 0`, hidden otherwise). No new controls.

---

## Fallback Behaviour

- If `n_silence_candidates == 0`: pre-filter is skipped entirely; behaviour identical to current.
- If a silence candidate is actually a voiced frame (misdetected): the correct key will be rejected by the pre-filter. Mitigation: the pre-filter uses at most 8 candidates; a **consensus mode** (key must fail **all** 8 to be rejected) can be added later if false-rejection is observed in practice. Not in scope now.

---

## Files Changed

| File | Change |
|---|---|
| `src/bruteforce.cu` | ILP-2 activation, 80/20 split, configurable split, KPA pre-filter |
| `include/bruteforce.h` | `gpu_split_pct` in `BruteforceConfig`; `n_silence_candidates` in `PayloadSet` |
| `include/payload_io.h` | `silence_candidate` in `PayloadLine`; `n_silence_candidates` in `PayloadSet` |
| `src/payload_io.c` | Parse `SILENCE=1` tag, count silence candidates |
| `tools/dsdfme_dsp_to_bin.py` | Burst type tracking, silence candidate marking |
| `src/gui.c` | `gpu_split_pct` spin control; KPA badge label |

---

## Success Criteria

- Build succeeds with no new warnings
- `gpu_split_pct` defaults to 80; changing the spin control changes the split passed to engine
- ILP-2 activates on sm_75+ with mode_policy >= 2 (verified via log)
- `.bin` files generated from DSP output with silence frames contain `SILENCE=1` on the first payload of each transmission
- KPA pre-filter passes the correct key (Z=48.5 σ test data), rejects wrong keys at rate ≥ 99% with 8 candidates
- With 0 silence candidates: behaviour unchanged (same score, same keys tested)
