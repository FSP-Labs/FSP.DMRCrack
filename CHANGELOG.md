# Changelog

All notable changes to FSP.DMRCrack will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added
- **i18n: status panel, graph, and dialog strings**: Moved all hardcoded Spanish GUI strings
  to the `Lang` struct (`lang.h` / `lang_en.c`). New fields: `fmt_keys_tested`, `fmt_speed`,
  `fmt_time`, `fmt_backend`, `fmt_best_candidate`, `fmt_best_score`, `fmt_status`,
  `fmt_cuda_error`, `fmt_payloads_loaded`, `state_running/paused/stopped`,
  `graph_keys_title`, `graph_score_title`, `dlg_bin_filter`, `dlg_audio_filter`,
  `btn_copy_key`, `msg_key_found`, `msg_key_copied`.
- **Resizable window**: Window can now be resized freely (minimum 940x720). All controls and
  graphs reposition dynamically via `WM_SIZE` handler.
- **DPI awareness**: Per-monitor DPI awareness (V2) enabled for crisp rendering on high-DPI displays.
- **Copy key button**: "Copy" button next to Start/Pause/Stop copies the best candidate key
  to the clipboard.
- **Key-found notification**: Taskbar flashes and a system beep sounds when the brute-force
  search completes with a result.
- **Payload count indicator**: Shows how many payloads are loaded after demodulation or file load.
- **Graph grid lines**: Horizontal grid lines at 25%/50%/75% with Y-axis tick labels on both
  the keys/s and score graphs.
- **Rounded buttons**: Owner-drawn buttons now use `RoundRect` with 8px corner radius.
- **G/s speed display**: Speed display now auto-formats to G/s for very high throughput.

### Changed
- **Full English translation**: All Spanish comments translated to English in `bruteforce.c`,
  `bruteforce.cu`, `bruteforce.h`, `test_score_windows.c`, and
  `tools/extract_encrypted_from_dsdfme.bat`.
- **Auto-update system replaced with WinSparkle**: Removed the custom WinHTTP + GitHub API
  updater (`updater.c`, 278 lines) which had no integrity verification. Replaced with WinSparkle
  0.9.2 (MIT license), which provides its own UI, EdDSA (Ed25519) signature verification, and
  Sparkle appcast support. The release workflow now signs the installer and publishes an appcast
  XML alongside each release.

### Fixed
- **Demodulation silent failure**: `run_process_stderr_redirect` redirected only stderr to the log
  file; stdout was set to `GetStdHandle(STD_OUTPUT_HANDLE)` which returns NULL in a GUI process
  (no console). Cygwin apps (dsd-fme) received a NULL stdout handle, which could cause silent
  failures with exit code 0 and no DSP output produced. Both stdout and stderr are now redirected
  to the log file, giving dsd-fme a valid write handle and capturing all its output.
- **DSP output search too narrow**: after dsd-fme ran, the app only looked for the DSP file in
  `wav_dir\DSP\qname` and `wav_dir\qname`. Some versions of dsd-fme write relative to their own
  executable directory. Two additional candidate paths under the dsd-fme.exe directory are now
  searched before reporting failure.
- **Opaque error messages**: "DSD output not found — check .dslog.txt" gave no path. All error
  dialogs now include the full resolved path of the log file and its last ~480 bytes, so the user
  sees what went wrong without hunting for a file.
- **No startup warning for broken install**: if `tools\dsd-fme.exe` was missing the app started
  normally and only failed when the user clicked Demodulate. The Demodulate button is now disabled
  at startup and a permanent label warns immediately if dsd-fme.exe is not found.
- **Unhelpful "missing dsd-fme" message**: previous message suggested the user install dsd-fme
  manually. Since the app is fully self-contained (dsd-fme and all Cygwin DLLs are bundled by the
  installer), the message now says "reinstall the app" instead.

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
