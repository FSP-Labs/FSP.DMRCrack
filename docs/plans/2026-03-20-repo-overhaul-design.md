# Repository Overhaul Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Translate all Spanish content to English, move hardcoded GUI strings to i18n, improve GUI (resizable layout, visual polish, functional enhancements), update documentation.

**Architecture:** Extend existing `Lang` struct with ~20 new fields for status/graph/dialog strings. Refactor `gui.c` to use `WM_SIZE` for dynamic layout, add DPI awareness, rounded buttons, graph improvements, copy-to-clipboard, and key-found notification. Translate all Spanish comments in `bruteforce.c`, `bruteforce.cu`, `bruteforce.h`, `test_score_windows.c`, and `extract_encrypted_from_dsdfme.bat`.

**Tech Stack:** C (Win32 API), CUDA, Inno Setup

---

### Task 1: Extend i18n system with new string fields

**Files:**
- Modify: `include/lang.h`
- Modify: `src/lang_en.c`

**Step 1: Add new fields to Lang struct in lang.h**

Add after the existing `err_wnd_create` field:

```c
    /* ---- Status panel format strings ---- */
    const char *fmt_keys_tested;       /* "Keys tested: %llu / %llu (%.2f%%)" */
    const char *fmt_speed;             /* "Speed: %.2f keys/s"                */
    const char *fmt_time;              /* "Time: %s  |  ETA: %s"             */
    const char *fmt_backend;           /* "Backend: %s"                       */
    const char *fmt_best_candidate;    /* "Best candidate: %s"                */
    const char *fmt_best_score;        /* "Best score: %s"                    */
    const char *fmt_status;            /* "Status: %s"                        */
    const char *fmt_cuda_error;        /* "CUDA error: %s"                    */
    const char *fmt_payloads_loaded;   /* "%zu payloads loaded"               */

    /* ---- State labels ---- */
    const char *state_running;         /* "RUNNING"  */
    const char *state_paused;          /* "PAUSED"   */
    const char *state_stopped;         /* "STOPPED"  */

    /* ---- Graph titles ---- */
    const char *graph_keys_title;      /* "Keys/s (history)"       */
    const char *graph_score_title;     /* "Best score (evolution)" */

    /* ---- File dialog filters ---- */
    const char *dlg_bin_filter;        /* "BIN payload (*.bin)\0*.bin\0All files (*.*)\0*.*\0" */
    const char *dlg_audio_filter;      /* "DMR Audio (*.wav;...)\0...\0All files (*.*)\0*.*\0" */

    /* ---- Copy / notification ---- */
    const char *btn_copy_key;          /* "Copy"                              */
    const char *msg_key_found;         /* "Key found! %s (score: %.1f)"      */
    const char *msg_key_copied;        /* "Key copied to clipboard"           */
```

**Step 2: Add corresponding values in lang_en.c**

Add after the existing `.err_wnd_create` field, matching the new struct fields with English strings.

**Step 3: Commit**

```
git add include/lang.h src/lang_en.c
git commit -m "i18n: add status, graph, dialog, and notification string fields"
```

---

### Task 2: Move hardcoded Spanish strings from gui.c to i18n

**Files:**
- Modify: `src/gui.c`

**Step 1: Replace status text format strings (lines 223-239)**

Replace the Spanish format string block in `update_status_text()` with references to `g_lang.*` fields.

**Step 2: Replace graph title strings (lines 333, 398)**

- `"Claves/s (historial)"` → `g_lang.graph_keys_title`
- `"Mejor score (evolucion)"` → `g_lang.graph_score_title`

**Step 3: Replace file dialog filter strings (lines 448, 463-464)**

- `"Todos (*.*)"` → use `g_lang.dlg_bin_filter` / `g_lang.dlg_audio_filter`

**Step 4: Replace CUDA error string (line 267)**

- `"Error CUDA: %s"` → `g_lang.fmt_cuda_error`

**Step 5: Commit**

```
git add src/gui.c
git commit -m "i18n: move all hardcoded Spanish GUI strings to lang system"
```

---

### Task 3: GUI improvements -- Resizable layout with WM_SIZE

**Files:**
- Modify: `src/gui.c`

**Step 1: Add layout_controls() function**

Create a static function that repositions all controls based on current client rect width/height. This replaces the hardcoded pixel positions used only at creation time.

**Step 2: Add WM_SIZE handler**

Call `layout_controls()` from `WM_SIZE` in the window procedure.

**Step 3: Add WM_GETMINMAXINFO handler**

Set minimum size to 940x720 so the window can't be shrunk below the original design.

**Step 4: Update WM_CREATE**

After creating all controls, call `layout_controls()` to set initial positions.

**Step 5: Commit**

```
git add src/gui.c
git commit -m "gui: add resizable window layout with minimum size constraint"
```

---

### Task 4: GUI improvements -- DPI awareness

**Files:**
- Modify: `src/main.c`

**Step 1: Add DPI awareness call before window creation**

```c
#include <shellscalingapi.h>
// In WinMain, before run_gui():
SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
```

**Step 2: Commit**

```
git add src/main.c
git commit -m "gui: enable per-monitor DPI awareness"
```

---

### Task 5: GUI improvements -- Visual polish

**Files:**
- Modify: `src/gui.c`

**Step 1: Rounded buttons**

In `draw_button()`, replace `FillRect()` with `RoundRect()` using 4px corner radius. Use `CreateRoundRectRgn()` to clip the button region.

**Step 2: Graph grid lines**

In `draw_graph()` and `draw_score_graph()`, add horizontal dashed grid lines at 25%, 50%, 75% of max value with axis tick labels.

**Step 3: Commit**

```
git add src/gui.c
git commit -m "gui: rounded buttons and graph grid lines with tick labels"
```

---

### Task 6: GUI improvements -- Functional enhancements

**Files:**
- Modify: `src/gui.c`
- Modify: `include/gui.h` (if needed for new control IDs)

**Step 1: Copy key to clipboard button**

Add a small "Copy" button next to the status text area. On click, copy `best_key` hex string to clipboard via `OpenClipboard()` / `SetClipboardData()`.

**Step 2: Key found notification**

In `refresh_snapshot_and_ui()`, detect when `search_completed` becomes 1 and `best_score` exceeds threshold. Flash taskbar via `FlashWindowEx()` and show a balloon notification.

**Step 3: Payload count indicator**

After loading a .bin file (in `start_bruteforce()` and `demod_thread_proc()`), show payload count in the demod_label or a dedicated label.

**Step 4: Commit**

```
git add src/gui.c
git commit -m "gui: add copy-key button, key-found notification, payload count"
```

---

### Task 7: Translate Spanish comments -- bruteforce.c

**Files:**
- Modify: `src/bruteforce.c`

**Step 1: Translate all Spanish comments to English**

Key translations:
- Lines 84-121: Scoring heuristics header block
- Line 128: "Popcount portátil" → "Portable popcount"
- Lines 339-351: "AUTOCORRELACIÓN MULTI-LAG" → "MULTI-LAG AUTOCORRELATION"
- Lines 381-392: "TASA DE TRANSICIONES BIT" → "BIT TRANSITION RATE"
- Lines 422-434: "BIT RATIO" section
- Lines 447-454: "CONSISTENCIA DE PARES DE BYTES" → "BYTE PAIR CONSISTENCY"
- Lines 491-498: "PENALIZACIÓN POR BASURA PATENTE" → "OBVIOUS GARBAGE PENALTY"
- Line 529: "Afinidad de hilo" → "Thread affinity"

**Step 2: Commit**

```
git add src/bruteforce.c
git commit -m "translate: convert all Spanish comments to English in bruteforce.c"
```

---

### Task 8: Translate Spanish comments -- bruteforce.cu

**Files:**
- Modify: `src/bruteforce.cu`

**Step 1: Translate all Spanish comments to English**

Key translations:
- Lines 17-19: File description header
- Line 30: "Cabeceras CUDA" → "CUDA headers"
- Lines 42-46: "MACROS Y COPIAS..." → "GPU RC4 MACROS AND PROTOCOL"
- Line 48: "Memoria constante ultra-rápida..." → "Ultra-fast constant memory..."
- Line 181: "Eliminada lectura innecesaria..." → "Removed unnecessary S-box read"
- Line 671: "Check stop cada 1024..." → "Check stop every 1024 iterations..."
- Line 682: "Procesar en grupos de 6 bursts" → "Process in groups of 6 bursts"
- Lines 695-702: Various inline Spanish comments
- Line 738: "Pre-compute RC4 KSA una vez por clave" → "Pre-compute RC4 KSA once per key"

**Step 2: Commit**

```
git add src/bruteforce.cu
git commit -m "translate: convert all Spanish comments to English in bruteforce.cu"
```

---

### Task 9: Translate Spanish -- bruteforce.h, test_score_windows.c

**Files:**
- Modify: `include/bruteforce.h`
- Modify: `src/test_score_windows.c`

**Step 1: Translate bruteforce.h comment (lines 90-92)**

```c
// Note: The CUDA kernel assumes the first payload in the .bin corresponds to burst_pos=0 of a superframe.
// If the file is not aligned, the drop value will be incorrect and the scoring will not be valid.
// For maximum robustness, validate alignment on the host and/or add a burst_pos_start field to PayloadItem.
```

**Step 2: Translate test_score_windows.c usage message (line 69)**

```c
fprintf(stderr, "Usage: test_score_windows <file.bin> [key_hex] [window] [step] [n_random] [sample_bytes]\n");
```

**Step 3: Commit**

```
git add include/bruteforce.h src/test_score_windows.c
git commit -m "translate: convert Spanish to English in bruteforce.h and test_score_windows.c"
```

---

### Task 10: Translate extract_encrypted_from_dsdfme.bat

**Files:**
- Modify: `tools/extract_encrypted_from_dsdfme.bat`

**Step 1: Translate all user-facing strings to English**

- "Uso:" → "Usage:"
- "Ejemplo:" → "Example:"
- "ERROR: no existe dsd-fme.exe" → "ERROR: dsd-fme.exe not found"
- "ERROR: no existe WAV" → "ERROR: WAV file not found"
- "Limpiar salidas previas..." → "Clean up previous outputs..."
- "Ejecutando DSD-FME..." → "Running DSD-FME..."
- "ERROR: dsd-fme fallo" → "ERROR: dsd-fme failed"
- "ERROR: no se encontro el DSP..." → "ERROR: DSP output not found"
- "Convirtiendo DSP a BIN..." → "Converting DSP to BIN..."
- "ERROR: conversion fallo" → "ERROR: conversion failed"
- "Listo:" → "Done:"

**Step 2: Commit**

```
git add tools/extract_encrypted_from_dsdfme.bat
git commit -m "translate: convert extract_encrypted_from_dsdfme.bat to English"
```

---

### Task 11: Update documentation

**Files:**
- Modify: `CHANGELOG.md`

**Step 1: Add entries to CHANGELOG.md under [Unreleased]**

```markdown
- Translate all Spanish comments and UI strings to English
- Move all hardcoded GUI strings to i18n system (lang.h / lang_en.c)
- Add resizable window layout with minimum size constraint
- Enable per-monitor DPI awareness
- Add rounded buttons and graph grid lines with tick labels
- Add copy-key-to-clipboard button
- Add taskbar flash notification when key is found
- Show payload count after loading .bin file
```

**Step 2: Commit**

```
git add CHANGELOG.md
git commit -m "docs: update CHANGELOG with overhaul changes"
```
