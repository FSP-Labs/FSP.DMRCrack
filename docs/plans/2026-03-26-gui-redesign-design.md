# DMRCrack GUI Redesign + Feature Improvements — Design Doc

**Date:** 2026-03-26
**Status:** Approved
**Scope:** `src/gui.c`, `src/bruteforce.cu`, `include/bruteforce.h`, `include/lang.h`, `src/lang_en.c`, `src/lang_es.c`

---

## 1. Goal

Redesign the GUI from a basic Win32 form into a professional **Operator Dashboard** while adding:
- RTL-SDR direct capture mode
- GPU vs CPU speed breakdown
- Robustness improvements (bin validation, CPU fallback, low-payload warnings)

---

## 2. Visual Design

### 2.1 Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  ▣ FSP.DMRCrack  v2.x     RTX 3050 Ti · sm_86 · 20 SMs    [ES][?] │  Header (36px)
├───────────────────────────────┬─────────────────────────────────────┤
│  ── CAPTURE ──────────────────│── BRUTE FORCE ─────────────────────│
│  [○ WAV]  [○ RTL-SDR]         │  .bin [___________________] [⊞]    │
│  WAV: [_____________] [⊞]     │  126 payloads · KMI9 · KID=0F     │
│  RTL: Freq[___]MHz Gain[__]   │  From [__________] To [__________] │
│       PPM[__] Dev[_]          │  Threads [__]  Samples [_____]     │
│  Slot [Both▼]  [□ Inverted]  │  [▶ Start] [⏸ Pause] [■ Stop]     │
│  [▶ Demod/Capture] [■] [⊡]   │  [⎘ Copy Key]                      │
│  ○ Ready                      │                                     │
├───────────────────────────────┴─────────────────────────────────────┤
│  ╔═ THROUGHPUT ══════╗  ╔═ PROGRESS ═══════════════════╗  ╔═ KEY ╗ │
│  ║  17.3 M/s         ║  ║  ████████░░░░  42.1%         ║  ║3733 ║ │
│  ║  GPU  14.1 M/s    ║  ║  450.2G / 1.09T              ║  ║74AB ║ │
│  ║  CPU   3.2 M/s    ║  ║  ETA  08:22:11               ║  ║E8   ║ │
│  ╚═══════════════════╝  ╚═══════════════════════════════╝  ║5083 ║ │
│                                                            ╚═════╝ │
│  ● RUNNING  ·  CUDA GPU  ·  Stage: SCANNING  ·  TPB=256  CHUNK=4  │
├─────────────────────────────────────────────────────────────────────┤
│  [Keys/s graph — left half]      [Best Score graph — right half]    │
├─────────────────────────────────────────────────────────────────────┤
│  ████████████████░░░░░░░░░░░░░░░░  42.1%                           │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Color Palette

| Token | Hex | Use |
|---|---|---|
| `CLR_HEADER` | `#141415` | Header bar background |
| `CLR_BG` | `#1a1a1b` | Main window background |
| `CLR_PANEL` | `#252526` | Section panels |
| `CLR_TILE` | `#2d2d30` | Metric tile background |
| `CLR_TILE_BORDER` | `#007acc` | Top accent line on tiles |
| `CLR_ACCENT` | `#007acc` | Blue accent (section headers, borders) |
| `CLR_METRIC_PRIMARY` | `#ffffff` | Large numbers in tiles |
| `CLR_METRIC_LABEL` | `#9cdcfe` | Sub-labels inside tiles |
| `CLR_TEXT` | `#cccccc` | Normal text |
| `CLR_DIM` | `#808080` | Secondary / dimmed text |
| `CLR_RUNNING` | `#4ec9b0` | Status dot — RUNNING |
| `CLR_PAUSED` | `#ce9178` | Status dot — PAUSED |
| `CLR_STOPPED` | `#6a6a6a` | Status dot — STOPPED |
| `CLR_WARN` | `#f44747` | Warning text (low payloads, errors) |

### 2.3 Typography

| Element | Font | Size | Weight |
|---|---|---|---|
| Header app name | Segoe UI | 10pt | Bold |
| Header GPU info | Segoe UI | 8pt | Regular |
| Section headers | Segoe UI | 9pt | SemiBold + accent underline |
| Tile primary metric | Consolas | 14pt | Bold |
| Tile sub-labels | Segoe UI | 8pt | Regular |
| Status strip | Segoe UI | 8pt | Regular |
| Controls (labels, buttons) | System default (NONCLIENTMETRICS) | — | — |

---

## 3. Feature Changes

### 3.1 Header Bar (new)

A fixed 36px bar painted in `WM_PAINT`:
- Left: small square icon glyph (`▣`) + `FSP.DMRCrack` bold + `v{VERSION_STR}` dimmed
- Center: GPU device name + compute + SM count (from `engine.cuda_device_name`, `cuda_compute_major/minor`, `cuda_sm_count`). Colored dot: green if CUDA active and scanning, gray otherwise.
- Right: `[ES]`/`[EN]` lang button + `[?]` help button

The header replaces the top-most control row. `layout_controls` must reserve `y=36` as the starting offset.

### 3.2 CAPTURE Section Redesign

**Two radio buttons:** `WAV` and `RTL-SDR`. Default: WAV.

**WAV mode controls** (same as today):
- File path edit + Browse button
- Demodulate / Stop / Export buttons
- Demod status label

**RTL-SDR mode controls** (shown/hidden with `ShowWindow`):
- `Freq (MHz)` edit (e.g. `851.375`)
- `Gain` edit (0–49, default 0)
- `PPM` edit (default 0)
- `Device` edit (default 0)
- Produces cmdline: `dsd-fme.exe -fs -i rtl:DEV:FREQHz:GAIN:PPM -Q <file> -o null`

**Shared controls** (always visible):
- `Slot` dropdown: `Both` / `Slot 1` / `Slot 2` → maps to `-V 3` / `-V 1` / `-V 2`
- `Inverted` checkbox → appends `-xr` when checked
- `[▶ Demod/Capture]` / `[■ Stop]` / `[⊡ Export]` buttons
- Demod status label (small, below buttons)

RTL-SDR capture runs indefinitely until Stop is pressed. Payloads accumulate in memory in real time (existing `demod_thread_proc` pattern; the python converter is invoked after Stop, same as WAV).

### 3.3 BRUTE FORCE Section

No functional changes. Layout is cleaned up:
- .bin file field + Browse + payload stats label (inline, same row or next row)
- Key range row (From / To)
- Threads + Samples on same row
- Start / Pause / Stop / Copy Key buttons on same row
- **Payload validation label** (new): shown below .bin field immediately after load:
  - `126 payloads  ·  KMI9: 126/126  ·  KID=0F  ·  Slot 1` (green/normal)
  - `⚠ Only 18 payloads — low confidence` (orange, `CLR_PAUSED`)
  - `⚠ Alignment warning — first burst ≠ pos 0` (red)

Validation runs in `load_payload_file()` (new helper that calls `payload_io` + inspects result).

### 3.4 Metric Tiles (replaces status edit box)

Three side-by-side tiles painted in `WM_PAINT`. Each tile has:
- A 2px top border in `CLR_TILE_BORDER` (accent)
- Title in `CLR_METRIC_LABEL`, small caps style (uppercase via DrawText)
- Primary metric in Consolas 14pt bold, `CLR_METRIC_PRIMARY`
- Secondary lines in Segoe UI 8pt, `CLR_DIM`

**THROUGHPUT tile:**
```
THROUGHPUT
17.3 M/s
GPU  14.1 M/s
CPU   3.2 M/s
```

**PROGRESS tile:**
- Mini progress bar (12px high, inside tile, same fill logic as current footer bar)
- `42.1%`
- `450.2G / 1.09T keys`
- `ETA  08:22:11  ·  Elapsed  01:15:33`

**CANDIDATE tile:**
- Monospace key in groups of 4: `3733 74AB E8`
- `Score  5083.96`
- `[⎘]` copy button integrated (small, top-right corner of tile)

### 3.5 Status Strip (replaces CUDA debug lines)

A single text line below the tiles:
```
● RUNNING  ·  CUDA GPU  ·  Stage: SCANNING  ·  TPB=256  CHUNK=4  BPSM=2
```
- The `●` dot is colored: `CLR_RUNNING` / `CLR_PAUSED` / `CLR_STOPPED`
- Fallback banner: when CUDA error triggers CPU fallback, prepend `⚠ CUDA error — continued on CPU  ·` for 8 seconds (timer-cleared)

### 3.6 Graphs (side-by-side)

Currently stacked vertically. Change to **side-by-side** (each 50% width) to use horizontal space better at 960px+ widths. Fall back to stacked below 800px (not needed for min-size enforcement).

Visual refinements:
- Add a translucent polygon fill under the graph line (filled area chart)
- Graph border: 1px `CLR_TILE_BORDER` rectangle instead of plain background edge

### 3.7 GPU/CPU Breakdown (engine change)

**`include/bruteforce.h`:**
```c
volatile LONG64 gpu_keys_tested;   // add to BruteforceEngine
```
And in `BruteforceSnapshot`:
```c
uint64_t gpu_keys_tested;          // added field
```

**`src/bruteforce.cu`:**
- In `cuda_launcher_thread`: use `InterlockedAdd64(&engine->gpu_keys_tested, delta)` in addition to the existing combined `keys_tested` delta.
- Reset `gpu_keys_tested = 0` on scan start (same place as `keys_tested`).
- `bruteforce_get_snapshot`: copy `engine->gpu_keys_tested` → `out->gpu_keys_tested`.

**`src/gui.c`:** In `update_ui_timer`:
```c
double gpu_frac = (snap.keys_tested > 0)
    ? (double)snap.gpu_keys_tested / (double)snap.keys_tested : 1.0;
double gpu_kps = snap.keys_per_second * gpu_frac;
double cpu_kps = snap.keys_per_second * (1.0 - gpu_frac);
```

### 3.8 Robustness

**D1 — .bin validation on load:**
New function `validate_payload_set(const PayloadSet *ps, char *out_summary, char *out_warn)`:
- Counts total, KMI9-capable (has MI + ALG 0x21/0x01), unique KIDs
- Checks burst alignment: if `ps->items[0]` burst_pos derived from metadata is not 0 → warn
- Returns summary string + optional warning string
- Called in `WM_COMMAND` after successful `payload_io_load`; result shown in `payload_label`

**D2 — CUDA fallback to CPU:**
In `IDT_UI_REFRESH` timer handler:
```c
if (engine.cuda_active && engine.cuda_error[0] && snapshot.running && !fallback_triggered) {
    fallback_triggered = 1;
    uint64_t remaining_start = snapshot.keys_tested + cfg.start_key;
    bruteforce_stop(&engine);
    // reconfigure: no CUDA, CPU only, keyspace [remaining_start, cfg.end_key]
    cfg.start_key = remaining_start;
    bruteforce_start(&engine, &cfg, &payloads, err, sizeof(err));
    // set fallback_banner_timer = 8 * UI_REFRESH_HZ
}
```
`AppState` gets `int fallback_triggered` and `int fallback_banner_ticks`.

**D3 — Low payload warning:**
In `on_start_clicked()` (before `bruteforce_start`):
```c
if (payloads.count < 30) {
    // set warning text in status strip, continue anyway
}
```
Also shown in the payload validation label when loading the .bin.

---

## 4. Files Changed

| File | Changes |
|---|---|
| `src/gui.c` | Full layout redesign, header bar, tiles, status strip, RTL-SDR mode, side-by-side graphs, fallback logic, validation |
| `src/bruteforce.cu` | Add `gpu_keys_tested` counter; reset on start; increment in CUDA launcher |
| `include/bruteforce.h` | Add `gpu_keys_tested` to `BruteforceEngine` and `BruteforceSnapshot` |
| `include/lang.h` | Add strings: `label_freq`, `label_gain`, `label_ppm`, `label_device`, `label_slot`, `label_inverted`, `btn_capture`, `btn_stop_capture`, `warn_low_payloads_count`, `msg_cuda_fallback`, `tile_throughput`, `tile_progress`, `tile_candidate`, `status_strip_fmt` |
| `src/lang_en.c` | Implement new strings |
| `src/lang_es.c` | Implement new strings |

---

## 5. Minimum Window Size

Change from `940×720` to `960×740`.

---

## 6. Out of Scope

- TCP input (explicitly excluded)
- Dictionary/key-list mode
- Export to JSON/CSV
- Audio playback of decoded speech
