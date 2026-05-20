# Changelog

All notable changes to FSP.DMRCrack will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [0.3.0] - 2026-05-20

### Fixed
- **CUDA atomic race on `best_key` / `best_score`** (#1) — the two-step
  `atomicCAS(score)` + `atomicExch(key)` update was replaced with a single `atomicMax`
  on a packed `unsigned long long` that encodes both the score (top 24 sortable bits)
  and the 40-bit key. Eliminates the race window where a polling read could observe a
  new score paired with a stale key, which caused the blank best-candidate display
  reported in #4.
- **CUDA error auto-fallback to CPU** — if the GPU returns an error mid-run, the engine
  now stops the CUDA path, restarts from the same offset on CPU threads, and shows a
  banner in the status strip. Replaces the v0.2.1 behaviour of aborting with
  *"NVIDIA CUDA Error o no hay GPUs compatibles."*
- **GPU/CPU keyspace split inverted** — the engine was giving 20 % of the keyspace to
  the GPU and 80 % to the CPU; now it's 80 / 20 as documented, configurable via the
  new GPU % spin control.
- **Demodulation silent failure** — `run_process_stderr_redirect` only redirected stderr;
  stdout was set to `GetStdHandle(STD_OUTPUT_HANDLE)`, which returns `NULL` in a GUI
  process. Cygwin apps (dsd-fme) received a `NULL` stdout handle and could exit 0
  without producing DSP output. Both streams now go to the log file.
- **DSP output search too narrow** — added two more candidate paths under the
  dsd-fme.exe directory so captures from non-default installs are found.
- **Test/production parity** — `test_strict_score.c` used `31.0f * k` as the absolute
  pruning floor while the GPU kernel uses `33.0f * k`; the test could pass keys the
  kernel would have rejected. Aligned to `33.0f`.
- **`#undef BCNT_INC` typo** — `BCNT_ADD` was leaking out of the strict kernel
  translation unit because the `#undef` referenced a macro that never existed.
- **Documentation drift** — `CONTRIBUTING.md` referenced non-existent files
  (`build_test_bin.bat`, `test_bin_score.exe`) and pointed contributors at the wrong
  scoring file. README claimed a CPU fallback that, in practice, takes days; both
  corrected.

### Added
- **Operator Dashboard GUI** — full visual redesign:
  - Header bar with GPU status dot (running / paused / stopped) and the GPU's
    `sm_XY · N SMs` summary.
  - Metric tiles with hierarchy: **THROUGHPUT** dominant (Consolas 22 pt, 58 % wide),
    **BEST CANDIDATE** beside it, **PROGRESS** as a full-width row with a large bar
    and one-line metadata.
  - Side-by-side line charts (keys/s, best score) with area fill, grid lines, and a
    Z = 400 threshold marker on the score chart.
  - Status strip anchored at the bottom of the window (Win32 convention).
- **KPA silence-frame detection** — DMR voice frames whose first 24 bits are
  consistent silence are flagged at load time (`SILENCE=` tag in `.bin`). The CUDA
  kernel uses these as a pre-filter to reject wrong keys earlier in the search.
  A badge in the GUI shows how many silence frames were detected.
- **Configurable GPU/CPU split** — spin control (50–95 %, step 5) lets the user
  adjust how the keyspace is divided between the GPU and CPU workers at scan start.
- **ILP-2 kernel enabled on sm_75+** — the dual-key kernel that was previously
  restricted to sm_89+ now runs on Turing and Ampere too, improving throughput on
  GTX 16xx / RTX 20xx and RTX 30xx cards.
- **Multi-arch build** — single `dmrcrack.exe` ships with native SASS for sm_75 /
  sm_86 / sm_89 plus a `compute_75` PTX fallback for RTX 50xx and future GPUs
  (JIT-compiled by the driver on first run).
- **`.bin` validation on load** — payload set is inspected on file open: KMI9
  coverage stats (how many lines carry MI metadata), KID histogram, low-payload
  warning when `count < 64`, alignment warning if the first frame isn't at
  `burst_pos == 0`.
- **Full EN/ES i18n with runtime toggle** — every user-facing string routed through
  the `Lang` struct, including engine startup errors emitted by `bruteforce.cu`.
  The language toggle button in the header switches `g_lang_ptr` and persists the
  choice to `dmrcrack.ini`. The help dialog is also fully localized.
- **Help dialog** — quick-start guide accessible from the **Help** button: capture
  with SDR# → demodulate → brute-force, with NFM / de-emphasis caveats.
- **Copy-key button** — copies the current best-candidate key to the clipboard.
- **Key-found notification** — taskbar flash + system beep when the search completes
  with a candidate above the Z threshold.
- **Resizable window with per-monitor DPI awareness** — minimum 980 × 720; all
  controls and graphs reposition via `WM_SIZE`.
- **WinSparkle auto-updater** — replaced the custom WinHTTP + GitHub-API updater
  (no signature verification) with WinSparkle 0.9.2: built-in UI, EdDSA (Ed25519)
  signature verification, Sparkle appcast support. Each release now publishes an
  `appcast.xml` alongside the installer.
- **`gpu_keys_tested` counter** — engine snapshot now exposes GPU and CPU
  contributions separately, used by the THROUGHPUT tile to display
  *"GPU 1.6 G/s · CPU 240 M/s"*.
- **ILP test bench** — `build_bench.bat` builds `bin/test_bench.exe`, a standalone
  micro-benchmark for the strict vs ILP-2 kernels.

### Changed
- **Capture module simplified** — WAV input + **Demodulate** + **Export** kept;
  RTL-SDR mode, slot selector (Both / 1 / 2), inverted-polarity checkbox and the
  WAV/RTL mode toggle removed. DSD-FME is invoked with `-V 3` (both slots) by
  default. Users who need slot-specific or polarity-inverted demodulation can run
  dsd-fme manually and load the resulting `.bin`.
- **All English source code** — Spanish comments and identifiers translated to
  English across `bruteforce.cu`, `bruteforce.c`, `bruteforce.h`,
  `test_score_windows.c` and the DSP-converter helper script.
- **`build.bat` rewrite** — auto-detects Visual Studio via `vswhere`, sets
  `INCLUDE` / `PATH` for the CUDA toolkit, compiles with `-O3 /arch:AVX2`.

### Internal
- 13 new GitHub issues filed for community contributors (`good first issue`,
  `help wanted`): magic-number cleanup, `__restrict__` annotations, CMake build,
  POSIX HAL, headless CLI, KPA pre-filter optimisation, legacy-kernel test
  coverage, and more.

> ⚠️ The releases v0.1.2, v0.2.0 and v0.2.1 were tagged without updating this
> changelog. Their content is rolled forward into the 0.3.0 entry above; the
> individual tags remain on GitHub for reference.

---

## [0.1.0] - 2026-03-18

### Added
- Initial public release
- CUDA GPU kernel (`bruteforce.cu`) for 40-bit ARC4 key exhaustive search
- CPU multi-threaded fallback path (`bruteforce.c`) with identical scoring logic
- KMI9 decryption pipeline: `key9 = key5 || MI[4]`, RC4 with per-sub-frame drop values
- DMR 4FSK demodulator (`dmr_demod.c`): WAV load, timing recovery, sync detection, voice burst extraction
- Win32 GUI with progress display and result graphs
- Inter-frame Hamming scoring and bit-frequency scoring (Z > 7 threshold for reliable detection)
- `.bin` payload file format with per-line `ALG/KID/MI` metadata
- `dsdfme_dsp_to_bin.py` — converts DSD-FME `-Q` DSP output + log into `.bin` payload file
- `verify_decrypt.py` — validates a candidate key against a `.bin` file (Z-score output)
- `diag_decrypt.py` — decryption pipeline diagnostic tool
- Inno Setup installer script (`installer/FSP.DMRCrack.iss`)

### Verified
- Correct key pipeline gives Z=48.5 sigma (C/CPU path) and Z=335.85 (Python bit-frequency) on 126-payload test capture
- LFSR taps `{31,3,1}` confirmed correct; MI advances by 32 steps between superframes
