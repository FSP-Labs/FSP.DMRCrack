# Changelog

All notable changes to FSP.DMRCrack will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
