# KPA + Speed-Up Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the build-breaking KPA ordering error, then expose gpu_split_pct and KPA silence count in the GUI.

**Architecture:** The backend (bruteforce.cu, payload_io.c, dsdfme_dsp_to_bin.py) already has ILP-2, 80/20 split, SILENCE tag parsing, and the KPA pre-filter fully implemented. Only a forward-declaration ordering issue in bruteforce.cu breaks the build, and the GUI is missing the spin control (GPU%) and the KPA badge label.

**Tech Stack:** C + CUDA (NVCC), Win32 GUI, GDI owner-drawn controls.

---

### Task 1: Fix bruteforce.cu — move KPA block after rc4_ksa9_dev

The `kpa_silence_check_dev` function (line ~99) calls `rc4_ksa9_dev` (line ~197).
CUDA requires callees to be defined before callers for `__device__ __forceinline__` functions.
Solution: cut the KPA block (lines 96–168: `compose_kmi9_dev`, `kpa_silence_check_dev`, and the three KPA macros) and paste it immediately after `rc4_ksa9_dev` ends (after line ~246, before `rc4_init_dev`).

**Files:**
- Modify: `src/bruteforce.cu`

**Step 1: Identify the exact line ranges**

Read `src/bruteforce.cu` lines 83–170 and lines 196–252.
Note: `compose_kmi9_dev` starts ~line 83, KPA macros end ~line 168. `rc4_ksa9_dev` ends ~line 224, `rc4_ksa5_dev` ends ~line 246.

**Step 2: Relocate the block**

Move these functions/macros to appear after `rc4_ksa5_dev` ends and before `rc4_init_dev`:
1. `compose_kmi9_dev` (builds 9-byte KMI key from key5 + MI)
2. `kpa_silence_check_dev` (1-bit voicing pre-filter)
3. `KPA_PREFILTER` macro
4. `KPA_PREFILTER_A` macro
5. `KPA_PREFILTER_B` macro

After the move, lines 83–168 should only contain the `RC4_CTX_DEV` struct and any other device helpers that don't call RC4 functions.

**Step 3: Verify the constant declarations remain in place**

Confirm these constant declarations (before line 83) are NOT moved:
```c
__constant__ uint8_t  d_const_cipher_packs[...];
__constant__ uint32_t d_const_mi[...];
__constant__ uint16_t d_const_silence_idx[64];
__constant__ int      d_const_n_silence;
```

**Step 4: Build**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: build succeeds, zero errors. Warnings about unused variables are acceptable.

**Step 5: Commit**

```bash
git add src/bruteforce.cu
git commit -m "fix: move KPA helpers after rc4_ksa9_dev to fix forward-ref build error"
```

---

### Task 2: GUI — GPU split spin control

Add a labeled spin control to the BF panel that reads/writes `g_app.gpu_split_pct` (range 50–95, step 5, default 80). Passing the value to `cfg.gpu_split_pct` on scan start is already done at line ~1707.

**Files:**
- Modify: `src/gui.c`

**Step 1: Add control ID**

In the `#define` block of control IDs near the top of `gui.c`, add:
```c
#define ID_SPIN_GPU   1028
#define ID_EDIT_GPU   1029
```

**Step 2: Add HWND members to AppState**

In the `AppState` struct (where other HWNDs are declared), add:
```c
HWND edit_gpu_split;   /* shows current GPU% value */
HWND spin_gpu_split;   /* UpDown spin buddy */
```

**Step 3: Create controls in WM_CREATE**

In the `WM_CREATE` handler, after the other BF-panel controls are created, add:
```c
/* GPU split spin: default 80 */
g_app.edit_gpu_split = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "80",
    WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER,
    0, 0, 38, 20, hwnd, (HMENU)ID_EDIT_GPU, NULL, NULL);
SendMessageA(g_app.edit_gpu_split, WM_SETFONT, (WPARAM)g_app.font_ui, TRUE);

g_app.spin_gpu_split = CreateWindowExA(0, UPDOWN_CLASSA, NULL,
    WS_CHILD | WS_VISIBLE | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
    0, 0, 0, 0, hwnd, (HMENU)ID_SPIN_GPU, NULL, NULL);
SendMessageA(g_app.spin_gpu_split, UDM_SETBUDDY, (WPARAM)g_app.edit_gpu_split, 0);
SendMessageA(g_app.spin_gpu_split, UDM_SETRANGE32, 50, 95);
SendMessageA(g_app.spin_gpu_split, UDM_SETPOS32, 0, 80);
```

Add `#include <commctrl.h>` near the top if not already present. Also ensure `InitCommonControls()` or `InitCommonControlsEx()` is called in `WinMain` (check `src/main.c`).

**Step 4: Position in layout_controls**

In `layout_controls()`, place the edit+spin near the "Start" button row in the BF right panel. Add a static label "GPU%" to the left:
```c
/* GPU split label + spin — right panel, near start button */
int gpu_y = /* row just above or below the start button */;
MoveWindow(lbl_gpu_split,    bf_x,        gpu_y, 36, 18, FALSE);
MoveWindow(g_app.edit_gpu_split, bf_x+38, gpu_y, 38, 20, FALSE);
/* spin is auto-positioned by buddy */
```
Create the label in WM_CREATE as a static LTEXT with text "GPU%".

**Step 5: Handle UDN_DELTAPOS (spin change)**

In `WM_NOTIFY` handler:
```c
case ID_SPIN_GPU: {
    NMUPDOWN *pud = (NMUPDOWN *)lParam;
    if (pud->hdr.code == UDN_DELTAPOS) {
        int newval = pud->iPos + pud->iDelta;
        if (newval < 50) newval = 50;
        if (newval > 95) newval = 95;
        /* snap to multiple of 5 */
        newval = (newval / 5) * 5;
        g_app.gpu_split_pct = newval;
    }
    break;
}
```

**Step 6: Build and verify**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: build succeeds. Spin is visible in BF panel; changing it updates `g_app.gpu_split_pct`.

**Step 7: Commit**

```bash
git add src/gui.c
git commit -m "feat: add GPU split% spin control to BF panel"
```

---

### Task 3: GUI — KPA silence badge label

Show "KPA: N silence frames" below the payload info label in the BF panel when `g_app.payload_set.n_silence > 0`. Hidden otherwise.

**Files:**
- Modify: `src/gui.c`

**Step 1: Add HWND member**

In `AppState`, add:
```c
HWND lbl_kpa_badge;  /* "KPA: N silence frames" — visible when n_silence > 0 */
```

**Step 2: Create in WM_CREATE**

```c
g_app.lbl_kpa_badge = CreateWindowExA(0, "STATIC", "",
    WS_CHILD | SS_LEFT,   /* NOT WS_VISIBLE — starts hidden */
    0, 0, 200, 18, hwnd, (HMENU)0, NULL, NULL);
SendMessageA(g_app.lbl_kpa_badge, WM_SETFONT, (WPARAM)g_app.font_ui, TRUE);
```

**Step 3: Position in layout_controls**

Place it directly below the payload count label in the BF panel:
```c
MoveWindow(g_app.lbl_kpa_badge, bf_x, payload_lbl_y + 20, bf_w - 4, 18, FALSE);
```

**Step 4: Update after payload load**

In `choose_file()` (and wherever the payload set is reloaded), after loading succeeds:
```c
if (g_app.payload_set.n_silence > 0) {
    char kpa_text[64];
    snprintf(kpa_text, sizeof(kpa_text),
             "KPA: %u silence frame%s",
             (unsigned)g_app.payload_set.n_silence,
             g_app.payload_set.n_silence == 1 ? "" : "s");
    SetWindowTextA(g_app.lbl_kpa_badge, kpa_text);
    ShowWindow(g_app.lbl_kpa_badge, SW_SHOW);
} else {
    ShowWindow(g_app.lbl_kpa_badge, SW_HIDE);
}
```

**Step 5: Build**

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```
Expected: build succeeds. Load a `.bin` file with `SILENCE=1` lines → badge appears. Load one without → badge hidden.

**Step 6: Commit**

```bash
git add src/gui.c
git commit -m "feat: KPA silence frame badge in BF panel"
```

---

## Build command (reference)

```bat
powershell.exe -Command "& cmd.exe /c 'D:\Proyectos\FSP.DMRCrack\build.bat'"
```

## Test data with SILENCE frames

`test/aaaaa/RC4-40.fromdsdfme.bin` — check if any lines contain `SILENCE=1`.
If none, run `tools/dsdfme_dsp_to_bin.py` on `test/aaaaa/DSP/RC4-40.fromdsdfme.dsdsp.txt`
with the existing log to regenerate a `.bin` that includes silence markers.
