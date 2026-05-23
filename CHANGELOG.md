# Changelog

All notable changes to FSP.DMRCrack will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [0.3.3] - 2026-05-23

### Performance
- **ILP-2 kernel S-boxes moved to shared memory** — RC4 S-boxes in
  `bruteforce_kernel_strict_ilp2` previously spilled to L2 cache (~100-cycle
  latency per access). They are now allocated in 64 KB of dynamic shared memory
  (4–30 cycle latency). Three new `__device__ __forceinline__` helpers operate
  on the shared-memory S-box: `rc4_ksa9_smem`, `rc4_discard_smem`, and
  `rc4_crypt_first3_skip4_smem`.
- **Interleaved S-box layout eliminates 32-way bank conflicts** — the initial
  layout stored each thread's S-box contiguously (`S[threadIdx.x * 256 + k]`),
  causing all 32 threads in a warp to access the same shared-memory bank on
  every instruction (32-way serialization). The new interleaved layout
  (`S_base[k * 128 + threadIdx.x]`) distributes accesses across banks so that
  each warp incurs at most 4-way conflicts — an 8× reduction in bank-conflict
  penalty.
- **`__launch_bounds__(128, 2)` (was 4)** — lower occupancy hint lets the
  compiler allocate the full register budget for ≤ 256 threads/SM. ILP-2 now
  compiles with **0 bytes of spill** on sm_86 and sm_89 (was non-zero), using
  all 255 available registers.
- **`cudaFuncSetAttribute(MaxDynamicSharedMemorySize, 65536)`** — required on
  Ada Lovelace (sm_89) and later to use more than 48 KB of dynamic shared
  memory per block. Called once after `use_ilp2` is determined.
- **KPA prefilter wired into ILP-2 hot path** — `KPA_PREFILTER_A/B` macros are
  now invoked for each key pair. They are no-ops when no silence frames are
  loaded (`d_const_n_silence == 0`), adding zero overhead in the common case.

### Fixed
- **VELOCIDAD tile sub-labels did not add up to the displayed total** — the
  displayed GPU and CPU speeds were derived by splitting the since-start
  cumulative average (`keys_tested / elapsed`) using the cumulative
  `gpu_keys_tested / keys_tested` ratio. Mixed display units (GPU in `M/s`,
  CPU in `K/s` with no decimals) produced apparent sums that differed from
  the primary value by up to 0.1 M/s. Fixed: all three values are now derived
  from delta-based instantaneous rates (Δkeys / Δt between consecutive UI
  timer ticks). CPU is derived as `total − GPU` before formatting, so the
  three displayed numbers are always exactly consistent. CPU speed now uses
  `M/s` units when ≥ 1 M/s, matching the GPU format.

---

## [0.3.2] - 2026-05-22

### Fixed
- **GPU kernel never executing on WDDM (GPU-Util 0 %)** — `LAUNCH_CHUNK` was launching
  `bruteforce_kernel_strict_ilp2` with `threadsPerBlock=256`, but the kernel declares
  `__launch_bounds__(128, 4)`. On Windows consumer-GPU mode (WDDM) this mismatch causes
  a deferred `cudaErrorInvalidConfiguration` that `cudaGetLastError()` doesn't catch
  synchronously, so the kernel was submitted to the stream driver-side but never ran on
  hardware. Fixed by hardcoding `128` in the ILP-2 branch of `LAUNCH_CHUNK`.
- **GPU not selected on Optimus/switchable-graphics laptops** — added
  `NvOptimusEnablement = 1` and `AmdPowerXpressRequestHighPerformance = 1` exports to
  `main.c`. Without these, the OS may route CUDA to the Intel iGPU on hybrid-graphics
  systems, causing `cudaGetDeviceCount()` to return 0 or `cudaErrorInitializationError`.
- **CUDA context lazy-init race** — replaced the probe `cudaMalloc` with `cudaFree(0)`,
  the NVIDIA-recommended idiom for eager primary-context creation. The context is now
  forced before launching the search thread, with a clear actionable error message if it
  fails (driver version, TCC mode, Optimus).
- **`gpu_keys_tested` counter never updated when GPU runs fast** — `POLL_GPU_RESULTS()`
  was only called inside the `while (cudaStreamQuery == cudaErrorNotReady)` loop. When
  kernels completed before the next launch the loop never ran and the final GPU counter
  was never read. Added an explicit `POLL_GPU_RESULTS()` after both stream syncs.
- **Autotuning always skipped for 40-bit searches** — `skip_benchmark` was set to true
  whenever `total_keys > 2^28`, meaning the benchmark never ran for real searches. Fixed:
  always benchmark on first launch using a fixed `tune_keys = 2^18` (fast, independent
  of keyspace size). Result cached per GPU.
- **Tune profile path collision for same compute capability** — profile filenames now
  include `multiProcessorCount` so an RTX 3050 Ti (sm_86, 20 SMs) and an RTX 3080
  (sm_86, 68 SMs) get separate cached profiles.
- **Status bar showed TPB=256 for ILP-2 kernel** — cosmetic: `cuda_tpb` is now reported
  as 128 (the actual launch value) instead of the profile's 256 when `use_ilp2` is true.

### Added
- **Named constants in `bruteforce.h`** (contributed by AndrewSheff, PR #19):
  - `DMR_CIPHER_PACK_BYTES` (21) — 3 sub-frames × 7 RC4 bytes per burst
  - `RC4_SBOX_SIZE` (256) — S-box array size, used in S[] declarations and KSA init loops
  - `RC4_DISCARD_BYTES` (256) — keystream bytes discarded before decryption
  - `STOP_POLL_MASK` (0x3FFu) — stop-flag poll interval in kernel/CPU worker loops
  - `LOCAL_KEYS_FLUSH` (16384) — local counter flush threshold for `atomicAdd`

  All five constants replace the corresponding magic numbers throughout `bruteforce.cu`.
  GPU-specific parameters (`__launch_bounds__`, thread-count candidates) intentionally
  retain literal `256` to avoid conflating S-box semantics with GPU block-sizing.

---

## [0.3.1] - 2026-05-22

### Fixed
- **`cudaGetDeviceProperties` failure not handled as GPU-absent** — if the device count
  was > 0 but properties query failed, `cuda_active` was set to `1` with an empty device
  name. The GPU launcher thread then failed silently while CPU workers ran, so the UI
  showed *"GPU 0 K/s"* with no error. Now correctly falls back to CPU and surfaces the
  error string.
- **Throughput tile shows GPU rate when GPU contributes nothing** — tile no longer
  displays *"GPU X M/s"* when `gpu_keys_tested` remains 0 after the first 100 k keys.

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
