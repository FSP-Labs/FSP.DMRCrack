# KPA + Speed-Up Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable the ILP-2 CUDA kernel on all Turing+ GPUs, make the GPU/CPU keyspace split configurable (default 80 %), and add a KPA silence-frame pre-filter that rejects wrong keys using the voicing-bit constraint before the expensive scoring pass.

**Architecture:** Three independent tracks — speed (ILP-2 threshold + configurable split), data layer (PayloadLine silence flag + converter emission), and engine (CUDA/CPU pre-filter + GUI badge). Tracks can be reviewed independently; build after each track.

**Tech Stack:** C + CUDA (NVCC), Win32 GDI, Python 3 (converter script).

---

## Track 1 — Speed (ILP-2 + configurable GPU split)

### Task 1: Lower ILP-2 SM threshold and make GPU split configurable

**Files:**
- Modify: `src/bruteforce.cu` (line ~1990 and line ~2201)
- Modify: `include/bruteforce.h` (`BruteforceConfig` struct)

**Background:** The ILP-2 kernel exists and works but is gated to `cuda_sm >= 89` (Ada). The comment at line ~1985 explains the old concern about L1 overflow on sm_86 — this concern was for the *legacy* scoring path; on `mode_policy >= 2` each thread only needs one 256-byte S-box so it is safe to enable on Turing (sm_75). The GPU/CPU split is already hardcoded to 80 % with `(total_keys * 4u) / 5u` — we only need to make it read from config.

**Step 1: Add `gpu_split_pct` to `BruteforceConfig`**

In `include/bruteforce.h`, change:
```c
typedef struct {
    uint64_t start_key;
    uint64_t end_key;
    int thread_count;
    int sample_lines;
    int sample_bytes;
} BruteforceConfig;
```
to:
```c
typedef struct {
    uint64_t start_key;
    uint64_t end_key;
    int thread_count;
    int sample_lines;
    int sample_bytes;
    int gpu_split_pct;  /* GPU share of keyspace [50..95], default 80 */
} BruteforceConfig;
```

**Step 2: Use `gpu_split_pct` in `bruteforce.cu`**

Find line ~1990:
```c
use_ilp2 = (mode_policy >= 2) && (cuda_sm >= 89);
```
Replace with:
```c
/* ILP-2: safe on all Turing+ (sm_75+); the double S-box concern was for
 * legacy mode. KMI9 path (mode_policy>=2) uses one S-box per thread. */
use_ilp2 = (mode_policy >= 2) && (cuda_sm >= 75);
```

Find line ~2201:
```c
uint64_t gpu_range = (total_keys * 4u) / 5u; /* GPU takes 80% */
uint64_t cpu_range = total_keys - gpu_range;  /* CPU takes 20% */
```
Replace with:
```c
int gp = (engine->cfg.gpu_split_pct > 0) ? engine->cfg.gpu_split_pct : 80;
if (gp < 50) gp = 50;
if (gp > 95) gp = 95;
uint64_t gpu_range = (total_keys * (uint64_t)gp) / 100ULL;
uint64_t cpu_range = total_keys - gpu_range;
```

**Step 3: Default `gpu_split_pct = 80` wherever `BruteforceConfig` is zero-initialised**

In `src/gui.c`, find where `BruteforceConfig cfg` is populated before calling `bruteforce_start` (inside `start_bruteforce()`). After the existing fields, add:
```c
cfg.gpu_split_pct = g_app.gpu_split_pct;  /* read from spin control (Task 2) */
```
(In Task 2 we add the spin control. For now, add a field `int gpu_split_pct` to `AppState` and default it to `80` in `WM_CREATE`.)

**Step 4: Add GPU % spin control to GUI**

In `src/gui.c`:

a) Add control ID after existing IDs:
```c
#define ID_EDIT_GPU_PCT  1028
```

b) Add to `AppState` struct:
```c
HWND edit_gpu_pct;
HWND lbl_gpu_pct;
int  gpu_split_pct;   /* 50..95, default 80 */
```

c) In `WM_CREATE`, near the start/end key edits (line ~2132), add:
```c
y += 30;  /* new row below start/end key row */
g_app.lbl_gpu_pct = CreateWindowA("STATIC", "GPU %:", WS_CHILD | WS_VISIBLE | SS_RIGHT,
    bf_x, y + 2, 45, 18, hwnd, NULL, NULL, NULL);
g_app.edit_gpu_pct = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "80",
    WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER,
    bf_x + 50, y, 50, 24, hwnd, (HMENU)ID_EDIT_GPU_PCT, NULL, NULL);
g_app.gpu_split_pct = 80;
```

d) In `layout_controls()`, move the new controls into the BF panel (same row height logic as start/end keys, just shifted down one row).

e) In `start_bruteforce()`, read the value:
```c
char pct_buf[8] = {0};
read_edit_text(g_app.edit_gpu_pct, pct_buf, sizeof(pct_buf));
int pct = atoi(pct_buf);
if (pct < 50 || pct > 95) pct = 80;
g_app.gpu_split_pct = pct;
cfg.gpu_split_pct = pct;
```

**Step 5: Build and verify**

Run:
```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: `dmrcrack.exe` builds with zero errors and zero warnings.

**Step 6: Commit**
```bash
git add include/bruteforce.h src/bruteforce.cu src/gui.c
git commit -m "feat: enable ILP-2 on sm_75+, make GPU split configurable"
```

---

## Track 2 — Data Layer (silence candidate detection)

### Task 2: Add `silence_candidate` to `PayloadLine` and emit `SILENCE=1` in converters

**Files:**
- Modify: `include/payload_io.h`
- Modify: `src/payload_io.c`
- Modify: `tools/dsdfme_dsp_to_bin.py`

**Background:** The DSP output format is `<slot> <type_hex> <66hex>`. Type `0x98` = voice header (marks start of a transmission). The first `0x10` (voice burst) that follows `0x98` is burst 0 of the first superframe of a new call — this is the silence candidate. We mark it with `SILENCE=1` in the `.bin` metadata.

**Step 1: Add `silence_candidate` field to `PayloadLine`**

In `include/payload_io.h`, change:
```c
typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t has_mi;
    uint8_t has_algid;
    uint8_t has_keyid;
    uint8_t algid;
    uint8_t keyid;
    uint32_t mi;
} PayloadLine;
```
to:
```c
typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t has_mi;
    uint8_t has_algid;
    uint8_t has_keyid;
    uint8_t silence_candidate; /* 1 = first voice burst of a new TX (voicing bit = 0) */
    uint8_t algid;
    uint8_t keyid;
    uint32_t mi;
} PayloadLine;
```

**Step 2: Add silence index arrays to `PayloadSet`**

In `include/payload_io.h`, change `PayloadSet`:
```c
typedef struct {
    PayloadLine *items;
    size_t count;
    size_t capacity;
    uint8_t has_global_mi;
    uint8_t has_global_algid;
    uint8_t has_global_keyid;
    uint8_t global_algid;
    uint8_t global_keyid;
    uint32_t global_mi;
    /* KPA silence frame index cache (built by load_payload_file) */
    uint16_t silence_indices[64];
    uint8_t  n_silence;          /* count, capped at 64 */
} PayloadSet;
```

**Step 3: Parse `SILENCE=` tag in `load_payload_file`**

In `src/payload_io.c`, in the function `parse_line_metadata` (line ~150), add after KID parsing:
```c
p = find_tag_ci(line, "SILENCE=");
if (p != NULL) {
    uint32_t sv = 0; int sd = 0;
    if (parse_hex_token_u32(p + 8, 1, &sv, &sd))
        *silence_candidate = (sv != 0) ? 1 : 0;
}
```
(Add `int *silence_candidate` parameter to the signature of `parse_line_metadata`.)

In the caller (line ~294), pass `&silence_cand` and assign to `pl->silence_candidate`.

After the `items` loop completes (end of `load_payload_file`), build the silence index cache:
```c
set->n_silence = 0;
for (size_t i = 0; i < set->count && set->n_silence < 64; i++) {
    if (set->items[i].silence_candidate && set->items[i].has_mi) {
        set->silence_indices[set->n_silence++] = (uint16_t)i;
    }
}
```

**Step 4: Emit `SILENCE=1` in `dsp_convert_to_bin` (C converter)**

In `src/payload_io.c`, in `dsp_convert_to_bin` (line ~486):

Add a per-slot flag `int after_voice_hdr[2] = {0, 0};` before the `while(fgets)` loop.

Change the burst-type filter:
```c
/* was: if (burst_type != 0x10) continue; */
if (burst_type == 0x98) {          /* voice header: next 0x10 is silence candidate */
    if (slot >= 1 && slot <= 2) after_voice_hdr[slot-1] = 1;
    continue;
}
if (burst_type != 0x10) continue;  /* skip everything else */
```

When writing the line (line ~522), add `SILENCE=1` if the flag is set:
```c
int is_silence = after_voice_hdr[si];
after_voice_hdr[si] = 0;  /* clear: only first burst after header */

if (has_meta) {
    if (is_silence)
        fprintf(fout, "%s;ALG=%02X;KID=%02X;MI=%08X;SILENCE=1\n", hex, alg, kid, mi);
    else
        fprintf(fout, "%s;ALG=%02X;KID=%02X;MI=%08X\n", hex, alg, kid, mi);
} else {
    if (is_silence)
        fprintf(fout, "%s;SILENCE=1\n", hex);
    else
        fprintf(fout, "%s\n", hex);
}
```

**Step 5: Emit `SILENCE=1` in Python converter**

In `tools/dsdfme_dsp_to_bin.py`, in `convert_dsp_to_bin`:

Add per-slot flag:
```python
after_voice_hdr = {1: False, 2: False}
```

Change the burst_type filter block (line ~107):
```python
if burst_type == "98":      # voice header: next voice burst is silence candidate
    after_voice_hdr[slot] = True
    continue
if burst_type != VOICE_TYPE:
    continue
```

When building `line_out` (just before `fout.write`):
```python
is_silence = after_voice_hdr.get(slot, False)
after_voice_hdr[slot] = False   # clear after first voice burst

# ... existing MI/ALG/KID tags ...
if is_silence:
    line_out += ";SILENCE=1"
```

**Step 6: Also update `payload_save_file` to write `SILENCE=1` if set**

In `src/payload_io.c`, near line ~564:
```c
if (line->has_algid) fprintf(f, ";ALG=%02X", line->algid);
if (line->has_keyid) fprintf(f, ";KID=%02X", line->keyid);
if (line->has_mi)    fprintf(f, ";MI=%08X", line->mi);
if (line->silence_candidate) fprintf(f, ";SILENCE=1");
```

**Step 7: Build and verify**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: zero errors/warnings.

Also run `test_strict_score.exe` to confirm no regression on existing data:
```bat
bin\test_strict_score.exe test\aaaaa\RC4-40.fromdsdfme.bin 373374ABE8
```
Expected: `Z >= 48.0` sigma output.

**Step 8: Commit**
```bash
git add include/payload_io.h src/payload_io.c tools/dsdfme_dsp_to_bin.py
git commit -m "feat: add silence_candidate metadata tag and emission in DSP converters"
```

---

## Track 3 — KPA Engine (CUDA pre-filter + CPU pre-filter + GUI badge)

### Task 3: CUDA constant memory + KPA pre-filter in both kernels

**Files:**
- Modify: `src/bruteforce.cu`

**Background:** The CUDA kernel stores MI per burst in `d_const_mi[MAX_CONST_LINES]` and cipher packs in `d_const_cipher_packs[MAX_CONST_LINES * 21]`. Both are already in constant memory. For each silence candidate at index `idx`, the KPA check is:
1. Build `key9 = key5 || MI[idx]`
2. RC4 KSA(key9, 9 bytes), skip `256 + (idx % 6) * 21` bytes
3. Read keystream byte 0: `ks0`
4. Compare `ks0 >> 7` against `d_const_cipher_packs[idx*21] >> 7`
5. Mismatch → reject key immediately

`idx % 6` gives the burst position within the superframe (drop offset). For a silence candidate (first burst after voice header), burst_pos = 0, so drop = 256. We store this fixed.

**Step 1: Add silence index constant arrays**

After the existing `__constant__` declarations (line ~55), add:
```c
__constant__ uint16_t d_const_silence_idx[64];
__constant__ int      d_const_n_silence;
```

**Step 2: Copy to device in `bruteforce_start`**

In `bruteforce_start`, after the `cudaMemcpyToSymbol` for `d_const_mi` (near line ~1897), add:
```c
{
    uint16_t h_sil_idx[64] = {0};
    int h_n_sil = 0;
    const PayloadSet *ps = engine->payloads;
    if (ps) {
        h_n_sil = (int)ps->n_silence;
        for (int si = 0; si < h_n_sil; si++)
            h_sil_idx[si] = ps->silence_indices[si];
    }
    CUDA_CHECK(cudaMemcpyToSymbol(d_const_silence_idx, h_sil_idx, sizeof(h_sil_idx)),
               "cudaMemcpyToSymbol(silence_idx)");
    CUDA_CHECK(cudaMemcpyToSymbol(d_const_n_silence, &h_n_sil, sizeof(h_n_sil)),
               "cudaMemcpyToSymbol(n_silence)");
}
```

**Step 3: Add KPA pre-filter helper device function**

After `compose_kmi9_dev` (line ~81), add:
```c
/* KPA 1-bit pre-filter: check voicing bit (MSB of plaintext[0] == 0 for silence).
 * Returns 1 if key PASSES the filter (might be correct), 0 if definitely wrong. */
__device__ __forceinline__ int kpa_silence_check_dev(
    const unsigned char key5[5],
    uint16_t silence_idx,
    uint32_t burst_drop   /* 256 + burst_pos_in_sf * 21 */
) {
    uint32_t mi = d_const_mi[silence_idx];
    unsigned char kmi9[9];
    compose_kmi9_dev(key5, mi, kmi9);

    Rc4State rc4;
    rc4_ksa_dev(&rc4, kmi9, 9);

    /* Skip burst_drop bytes */
    for (uint32_t d = 0; d < burst_drop; d++) {
        rc4.i++;
        rc4.j = (rc4.j + rc4.s[rc4.i]) & 0xFF;
        unsigned char tmp = rc4.s[rc4.i];
        rc4.s[rc4.i] = rc4.s[rc4.j];
        rc4.s[rc4.j] = tmp;
    }
    /* Read one keystream byte */
    rc4.i++;
    rc4.j = (rc4.j + rc4.s[rc4.i]) & 0xFF;
    {
        unsigned char tmp = rc4.s[rc4.i];
        rc4.s[rc4.i] = rc4.s[rc4.j];
        rc4.s[rc4.j] = tmp;
    }
    unsigned char ks0 = rc4.s[(rc4.s[rc4.i] + rc4.s[rc4.j]) & 0xFF];

    /* For silence: plaintext[0] bit7 == 0
     * So: ks0 bit7 must equal ciphertext[0] bit7 */
    unsigned char c0 = d_const_cipher_packs[silence_idx * 21];
    return ((ks0 >> 7) == (c0 >> 7)) ? 1 : 0;
}
```

**Step 4: Add KPA pre-filter macro**

After the helper function, define a macro to be used in both kernels:
```c
#define KPA_PREFILTER(key5_ptr)                                              \
    if (d_const_n_silence > 0) {                                             \
        int _kpa_pass = 1;                                                   \
        for (int _si = 0; _si < d_const_n_silence && _kpa_pass; _si++) {    \
            uint16_t _idx = d_const_silence_idx[_si];                        \
            uint32_t _bpos = (uint32_t)(_idx % 6);                           \
            uint32_t _drop = 256u + _bpos * 21u;                             \
            if (!kpa_silence_check_dev((key5_ptr), _idx, _drop))             \
                _kpa_pass = 0;                                               \
        }                                                                    \
        if (!_kpa_pass) goto next_key;                                       \
    }
```

**Step 5: Insert macro in `bruteforce_kernel_strict`**

In `bruteforce_kernel_strict` (line ~594), find the inner loop body where `key` is assembled and before `score_burst_correct_dev` is called. The pattern is:
```c
for (uint64_t i = tid; i < total_keys; i += stride) {
    /* unpack key from i+start_key */
    ...
    /* INSERT KPA pre-filter here */
    KPA_PREFILTER(key)
    /* existing scoring loop */
    ...
    next_key:;
}
```
Make sure the `next_key:` label already exists or add it before the closing `}` of the loop.

**Step 6: Insert macro in `bruteforce_kernel_ilp2`**

Similarly, in `bruteforce_kernel_ilp2` (line ~746), the loop processes `key_a` and `key_b`. Insert after each key is unpacked:
```c
KPA_PREFILTER(ka)
/* existing scoring for ka */
...
next_key_a:;

KPA_PREFILTER(kb)
/* existing scoring for kb */
...
next_key_b:;
```
(Adapt `goto` labels to match existing ones in the ILP-2 kernel.)

**Step 7: Build and verify**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: zero errors/warnings. The pre-filter is a no-op when `d_const_n_silence == 0`, so existing `.bin` files without `SILENCE=` tags are unaffected.

**Step 8: Commit**
```bash
git add src/bruteforce.cu
git commit -m "feat: CUDA KPA silence-frame pre-filter (voicing-bit 1-bit check per candidate)"
```

---

### Task 4: CPU path KPA pre-filter

**Files:**
- Modify: `src/bruteforce.c`

**Background:** The CPU path uses `score_burst_correct_cpu` in `cpu_4way_worker_proc`. Add the same pre-filter there before the full scoring call.

**Step 1: Add KPA check helper in `bruteforce.c`**

In `src/bruteforce.c`, after the existing `rc4.c` includes, add:
```c
/* KPA 1-bit pre-filter for silence candidates (mirrors CUDA version) */
static int kpa_silence_passes_cpu(
    const unsigned char key5[5],
    const PayloadSet *ps,
    uint16_t silence_idx)
{
    const PayloadLine *sl = &ps->items[silence_idx];
    if (!sl->has_mi) return 1;  /* no MI: can't check, let it through */

    unsigned char kmi9[9];
    memcpy(kmi9, key5, 5);
    kmi9[5] = (sl->mi >> 24) & 0xFF;
    kmi9[6] = (sl->mi >> 16) & 0xFF;
    kmi9[7] = (sl->mi >>  8) & 0xFF;
    kmi9[8] =  sl->mi        & 0xFF;

    uint32_t bpos = (uint32_t)(silence_idx % 6);
    uint32_t drop = 256u + bpos * 21u;

    Rc4State rc4;
    rc4_init(&rc4, kmi9, 9);
    /* skip drop bytes then read one */
    unsigned char ks0;
    rc4_prga_n(&rc4, drop, NULL); /* skip */
    rc4_prga_n(&rc4, 1, &ks0);

    /* Plaintext[0] MSB = 0 for silence → keystream MSB = ciphertext MSB */
    /* cipher[0] for sf0 of this burst */
    unsigned char c0;
    /* Re-use existing precompute or re-derive from payload */
    /* Simplest: de-interleave sf0 byte0 directly from sl->data */
    /* For the 1-bit test we only need bit7 of the first packed byte.
     * The MSB of the 7-byte packed sub-frame corresponds to ambe_d[0]
     * which is C0 bit 11 = the first bit extracted from the frame.
     * Rather than de-interleaving here, use the pre-computed cipher packs
     * from ctx->cipher_packs. */
    if (ctx->cipher_packs == NULL) return 1;
    c0 = ctx->cipher_packs[silence_idx * 21];

    return ((ks0 >> 7) == (c0 >> 7)) ? 1 : 0;
}
```

Note: The function needs access to `ctx->cipher_packs`. Restructure as an inline check inside `cpu_4way_worker_proc` instead:

In `cpu_4way_worker_proc` (in `src/bruteforce.cu`, since CPU workers are there), find the inner key loop and add before the scoring call:
```c
/* KPA pre-filter */
if (ps && ps->n_silence > 0 && cipher_packs != NULL) {
    int kpa_ok = 1;
    for (int si = 0; si < (int)ps->n_silence && kpa_ok; si++) {
        uint16_t idx = ps->silence_indices[si];
        const PayloadLine *sl = &ps->items[idx];
        if (!sl->has_mi) continue;
        unsigned char kmi9[9];
        memcpy(kmi9, key5, 5);
        kmi9[5] = (sl->mi >> 24) & 0xFF;
        kmi9[6] = (sl->mi >> 16) & 0xFF;
        kmi9[7] = (sl->mi >>  8) & 0xFF;
        kmi9[8] =  sl->mi        & 0xFF;
        uint32_t drop = 256u + (uint32_t)(idx % 6) * 21u;
        Rc4State rc4cpu;
        rc4_init_host(&rc4cpu, kmi9, 9);
        unsigned char ks0 = rc4_skip_and_byte_host(&rc4cpu, drop);
        unsigned char c0  = cipher_packs[idx * 21];
        if ((ks0 >> 7) != (c0 >> 7)) { kpa_ok = 0; }
    }
    if (!kpa_ok) continue;  /* skip to next key in CPU loop */
}
```
(Use the host-side RC4 functions already available. If `rc4_skip_and_byte_host` doesn't exist as a single function, inline the skip+read as a short loop.)

**Step 2: Build and verify**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Also verify CPU test still gives correct Z:
```bat
bin\test_strict_score.exe test\aaaaa\RC4-40.fromdsdfme.bin 373374ABE8
```

**Step 3: Commit**
```bash
git add src/bruteforce.cu
git commit -m "feat: CPU path KPA silence-frame pre-filter"
```

---

### Task 5: GUI KPA badge in throughput tile

**Files:**
- Modify: `src/gui.c`

**Background:** `draw_all_tiles` builds the THROUGHPUT tile content. When `g_app.payloads->n_silence > 0`, add a sub-line showing the KPA filter strength.

**Step 1: Update `draw_all_tiles` throughput tile sub-lines**

In `src/gui.c`, in `draw_all_tiles` (line ~741), find the section that builds `line2` and `line3` for the THROUGHPUT tile. After building the existing GPU/CPU breakdown string, add a KPA line:

```c
/* line3: KPA badge or empty */
char line3[64] = {0};
if (g_app.payload_set.n_silence > 0) {
    int n = g_app.payload_set.n_silence;
    /* rejection rate: (1 - 1/2^n) * 100 */
    /* approximate: 2^n grow fast, cap display at ">99.9%" */
    if (n >= 10)
        snprintf(line3, sizeof(line3), "KPA: %d silence frames (>99.9%%)", n);
    else {
        double pass_rate = 100.0 / (1 << n);  /* % of wrong keys that pass */
        snprintf(line3, sizeof(line3), "KPA: %d frames (%.1f%% pass)", n, pass_rate);
    }
}
```
Pass `line3` as the third sub-line to `draw_tile`.

**Step 2: Verify badge appears**

Build and run the app. Load a `.bin` file that has at least one `SILENCE=1` line (or manually add one for testing). Verify the THROUGHPUT tile shows the KPA badge text.

**Step 3: Build and final regression check**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
bin\test_strict_score.exe test\aaaaa\RC4-40.fromdsdfme.bin 373374ABE8
```
Expected: build OK, Z ≥ 48.

**Step 4: Commit**
```bash
git add src/gui.c
git commit -m "feat: KPA silence-frame badge in THROUGHPUT tile"
```

---

## Smoke-Test Checklist

After all tasks complete:

- [ ] Build succeeds, zero warnings
- [ ] `test_strict_score.exe` on existing `.bin` gives Z ≥ 48 (no regression)
- [ ] Loading a `.bin` without `SILENCE=` tags: KPA badge absent, brute-force unchanged
- [ ] Converting the test DSP file via `dsdfme_dsp_to_bin.py`: first voice burst after `98` gets `SILENCE=1`
- [ ] C converter (`dsp_convert_to_bin` in the app's internal demod flow) also emits `SILENCE=1`
- [ ] GPU % control in GUI accepts values 50–95 and defaults to 80
- [ ] ILP-2 kernel activates on sm_75 GPU (log/debug shows `use_ilp2=1` on RTX card)
- [ ] (Optional) Synthetic Python test: generate a 40-key sweep where 39 fail the 1-bit filter

---

## Notes

- The `next_key` / `next_key_a` / `next_key_b` goto labels: check if they already exist in the kernel loops. If not, add `next_key: ;` before the loop increment / closing brace.
- `rc4_ksa_dev` and `Rc4State` struct: already defined in `bruteforce.cu` — reuse them in `kpa_silence_check_dev`.
- `ps->silence_indices[]` indices are `uint16_t`; `MAX_CONST_LINES` is 512, so `uint16_t` is sufficient.
- The Python converter `after_voice_hdr` dict keys must match the `slot` values parsed (integers 1 and 2). Use `after_voice_hdr.get(slot, False)` for safety.
