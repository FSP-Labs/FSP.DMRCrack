# FSP.DMRCrack

**GPU-accelerated ARC4 key recovery for DMR Enhanced Privacy voice communications.**

FSP.DMRCrack performs exhaustive 40-bit RC4 key search against captured DMR Enhanced Privacy voice frames. On Windows it ships as a native GUI application with DSD-FME integration. On Linux it runs as a headless CLI tool.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform: Windows x64](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-blue)](https://github.com/FSP-Labs)
[![Platform: Linux x64](https://img.shields.io/badge/Platform-Linux%20x64-orange)](https://github.com/FSP-Labs)
[![Download](https://img.shields.io/github/v/release/FSP-Labs/FSP.DMRCrack?label=Download&color=green)](https://github.com/FSP-Labs/FSP.DMRCrack/releases/latest)

> **[Download the latest installer →](https://github.com/FSP-Labs/FSP.DMRCrack/releases/latest)**

> **Use on systems you own or have explicit written permission to test. Unauthorized interception of radio communications is illegal in most jurisdictions.**

---

## Use case

DMR Enhanced Privacy (EP) is the encryption layer built into MOTOTRBO, Hytera, and other DMR Tier II/III radios. It uses ARC4 (RC4) with a 40-bit (5-byte) key. At roughly one trillion candidates that keyspace is tractable on a modern GPU in a few hours.

FSP.DMRCrack exploits the structure of AMBE voice coding: valid speech produces predictable inter-frame parameter distributions, so the correct key stands out as a Z-score spike well above the noise floor (Z > 7 threshold). It runs the same pipeline as DSD-FME's own decoder, so what the tool finds actually decrypts the audio.

**Intended users:** licensed radio operators auditing their own systems, security researchers, and CTF participants.

---

## Requirements

### Windows (GUI)

| Requirement | Details |
|---|---|
| OS | Windows 10/11, 64-bit |
| GPU | NVIDIA sm_75+ (GTX 16xx / RTX 20xx or newer). CPU fallback available but expect days instead of hours — a GPU is strongly recommended. |
| Runtime | None — DSD-FME and all Cygwin DLLs are bundled by the installer |
| Python | 3.8+ (optional, for `verify_decrypt.py` and `diag_decrypt.py`) |
| CUDA Toolkit | 12.x (build-time only) |
| Visual Studio | 2022 with Desktop C++ workload (build-time only) |

### Linux (CLI)

| Requirement | Details |
|---|---|
| OS | Any x86-64 Linux distribution |
| GPU | Any OpenCL 1.2+ GPU (NVIDIA / AMD / Intel) via `-DUSE_OPENCL=ON` — **or** NVIDIA sm_75+ with CUDA 12.x — **or** AMD RDNA/CDNA with ROCm 6.x (`-DUSE_HIP=ON`). Runs CPU-only when no GPU is present. |
| Build tools | CMake ≥ 3.21, GCC/Clang. OpenCL: `opencl-headers` + an ICD loader. CUDA: Toolkit 12.x. HIP: ROCm 6.x. |
| Python | 3.8+ (optional) |

---

## Installation

### Installer (recommended)

1. Download `FSP.DMRCrack-Setup.exe` from [Releases](https://github.com/FSP-Labs/FSP.DMRCrack/releases).
2. Run the installer (requires Windows 10/11 x64, admin rights).
3. Launch **FSP.DMRCrack** from the Start menu or desktop shortcut.

Everything is included: the GPU brute-force engine, the DSD-FME demodulator, and all required Cygwin runtime DLLs. No additional downloads or configuration needed.

### Build from source (Windows)

Clone the repo and build with `build.bat` (requires CUDA Toolkit + Visual Studio). `dsd-fme.exe` and the Cygwin DLLs are already in `tools/`. If they are missing (e.g. on a clean CI checkout), run `tools\get_runtime.bat` to fetch them. See [Building from source](#building-from-source) below.

### Build from source (Linux)

The portable OpenCL back-end has free build deps and runs on NVIDIA, AMD and
Intel GPUs (and CPU-only when no GPU is present):

```bash
sudo apt-get install -y cmake build-essential opencl-headers ocl-icd-opencl-dev
cmake -S . -B build -DUSE_OPENCL=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
# binary at bin/dmrcrack
```

See [Building from source](#building-from-source) for the CUDA and ROCm/HIP
back-ends.

---

## Quick start

### From SDR capture to recovered key

1. Record a WAV file of the DMR RF signal (discriminator audio, 48 kHz mono recommended).
2. Open FSP.DMRCrack and select the WAV file in the **Capture** section.
3. Click **Demodulate** — DSD-FME runs automatically, extracts encrypted voice payloads, and writes a `.bin` file.
4. Click **Start** in the **Brute-force** section to begin the GPU search.
5. Monitor progress: keys/sec graph, best-score evolution, ETA.
6. The correct key produces a sharp score spike well above the noise floor.
7. Click **Listen** to re-run DSD-FME with the recovered key, decrypt the capture to a plain WAV, and play it back.

### Live capture (experimental)

The GUI can also drive an **RTL-SDR** directly: click **Live capture**, enter a
frequency, and FSP.DMRCrack runs DSD-FME unattended, watches for encrypted voice,
and once it has accumulated enough frames it saves a `.bin` and auto-starts the
crack. This path is newly added and **not yet validated on hardware** — treat it
as experimental and verify against a signal you are authorized to test. The
offline file workflow above remains the supported path.

### From an existing .bin file

If you already have a `.bin` payload file (e.g., generated by DSD-FME + `dsdfme_dsp_to_bin.py`):

1. Select the `.bin` file in the BRUTEFORCE section.
2. Configure the key range (default: full 40-bit space `0000000000`–`FFFFFFFFFF`).
3. Click **Start**.

### Command-line usage (Linux)

The headless binary (`bin/dmrcrack`) takes the `.bin` file via `--bin` and runs
the same engine as the GUI:

```bash
# Full 40-bit brute-force (auto-detects MOTOTRBO / Hytera / legacy mode)
dmrcrack --bin capture.bin

# Score a single candidate key and exit
dmrcrack --bin capture.bin --key <KEY_HEX>

# Dictionary attack: try a list of hex keys first (one per line, '#' comments)
dmrcrack --bin capture.bin --wordlist keys.txt --potfile found.pot

# Measure throughput on this machine (~5 s) and exit
dmrcrack --bin capture.bin --benchmark

# Machine-readable result
dmrcrack --bin capture.bin --key <KEY_HEX> --json
```

Recovered keys can be appended to a potfile (`basename:key:score`) with
`--potfile`, and any mode can emit a JSON result with `--json`. Run
`dmrcrack --help` for the full option list. A bash-completion script is
installed by the Debian package and by `cmake --install`.

---

## .bin payload format

One payload per line, hex-encoded (33 bytes = 66 hex characters). Optional metadata after `;`:

```
AABBCCDDEEFF112233...;ALG=21;KID=0F;MI=12345678
```

| Tag | Meaning |
|---|---|
| `ALG=21` | MOTOTRBO RC4 Enhanced Privacy — uses KMI9 pipeline (`key9 = key5 \|\| MI[4]`) |
| `ALG=02` | Hytera Enhanced Privacy — RC4 KSA with key5, keystream XOR'd with KIV derived from key5+MI |
| `KID=XX` | Key ID |
| `MI=XXXXXXXX` | Message Indicator (32-bit, hex) |

The pipeline is auto-selected at scan start based on the ALG distribution of loaded lines. If ≥ 90 % carry `ALG=02` + MI, the Hytera EP kernel is used. If ≥ 90 % carry `ALG=21`/`ALG=01` + MI, the MOTOTRBO KMI9 kernel is used. Otherwise the legacy 5-byte key mode runs.

---

## Tools

### dsdfme_dsp_to_bin.py

Converts DSD-FME `-Q` DSP output + stderr log into a `.bin` payload file with correct per-frame MI assignment.

```bat
python tools\dsdfme_dsp_to_bin.py --dsp RC4.dsdsp.txt --out RC4.bin --log RC4.dslog.txt
```

### verify_decrypt.py

Validates a candidate key against a `.bin` file and prints Z-score metrics.

```bat
python tools\verify_decrypt.py --bin RC4.bin --key <YOUR_KEY_HEX>
```

Expected output for a correct key on 126 payloads: Z ≈ 335 (bit-frequency), Z ≈ 38 (Hamming).

---

## How it works

### MOTOTRBO pipeline (ALG=0x21, KMI9 mode)

For each key candidate, the GPU kernel (CUDA, HIP or OpenCL — same algorithm) runs the complete DSD-FME/mbelib pipeline per burst:

1. Build `key9 = key5 || MI[4]`
2. RC4 KSA with 9-byte key; discard `256 + burst_pos × 21` bytes of keystream
3. For each sub-frame (0, 1, 2):
   - De-interleave 33-byte payload → `ambe_fr[4][24]`
   - mbelib demodulate (PRNG XOR on row 1)
   - Extract 49 AMBE bits → pack to 7 bytes
   - RC4 decrypt → unpack 24 bits
4. Score = Σ(24 − Hamming distance) across consecutive sub-frame pairs

Valid speech has slowly-varying AMBE parameters (HD ≈ 0–4). Random keys produce HD ≈ 12. At 126 payloads the correct key achieves Z ≈ 48.5 sigma (C/CPU path).

Between superframes (every 6 bursts), MI advances by 32 LFSR steps: taps `{31,3,1}`.

### Hytera Enhanced Privacy pipeline (ALG=0x02)

Hytera EP uses a different key schedule: RC4 KSA with the 5-byte key only (no MI in the KSA), then a 21-byte keystream is generated and XOR'd with a key-IV (`kiv`) derived from `key5` and the MI bytes. All 6 bursts in a superframe share the same 21-byte keystream. The scoring algorithm is identical to MOTOTRBO (inter-frame Hamming + bit-frequency chi-squared). A dedicated `bruteforce_kernel_hytera` kernel handles these payloads without adding any overhead to MOTOTRBO paths.

### GPU throughput

Measured: an **RTX 3050 Ti laptop GPU (CUDA back-end) sustains ~100 M keys/s**,
which completes the full 2⁴⁰ keyspace in roughly 3 hours. Throughput scales with
the GPU, so faster cards finish proportionally sooner; these are the only figures
verified so far, and other hardware has not yet been benchmarked.

The portable OpenCL back-end trades some throughput for vendor-neutrality
(NVIDIA / AMD / Intel) — it omits the CUDA ILP-2 shared-memory kernel — so it is
expected to be slower than native CUDA on the same card (not yet benchmarked).
When no GPU device is present it falls back to the multi-threaded CPU scorer.
Narrow the key range (`--start` / `--end`) whenever you can to cut search time.

---

## What this does NOT do

- **Other ciphers.** Supported: DMR Enhanced Privacy RC4 (MOTOTRBO ALG=0x21 and Hytera Enhanced Privacy ALG=0x02), both with a 40-bit key. Not supported: AES-256 (Motorola DMR-AES / Hytera HP), Tytera DMRA, or any non-RC4 cipher.
- **Captures without MI metadata.** The strict pipeline needs the Message Indicator extracted from each superframe. Without it the legacy statistical scorer runs, which is much less reliable.
- **Bad audio.** If DSD-FME can't cleanly demodulate the WAV, the search will run but won't find the key. Garbage in, garbage out.
- **Production live SDR ingest.** The offline file workflow (record to WAV, then feed it in) is the supported path. Direct RTL-SDR live capture exists in the GUI but is experimental and not yet hardware-validated.
- **Targeting third-party systems.** This is for authorized auditing of systems you own or have written permission to test. See `LICENSE`.

---

## Building from source

### Linux (CMake)

Requires CMake >= 3.21 and GCC/Clang. Pick a GPU back-end:

**Portable OpenCL (recommended — NVIDIA / AMD / Intel).** This is what the
Debian/Kali package builds. Only needs `opencl-headers` and an ICD loader
(`ocl-icd-opencl-dev`); falls back to the multi-threaded CPU engine when no
OpenCL device is found.

```bash
cmake -S . -B build -DUSE_OPENCL=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

**NVIDIA CUDA** (peak throughput on NVIDIA; requires CUDA Toolkit 12.x). This is
the default back-end when no `-DUSE_*` flag is given:

```bash
cmake -S . -B build -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

**AMD ROCm / HIP** (requires ROCm 6.x):

```bash
cmake -S . -B build -DUSE_HIP=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_HIP_COMPILER=/opt/rocm/bin/amdclang++ -DCMAKE_PREFIX_PATH=/opt/rocm
cmake --build build --parallel
```

GPU targets default to common RDNA/CDNA architectures; override with
`-DCMAKE_HIP_ARCHITECTURES="gfx1100;gfx1030"`.

Output: `bin/dmrcrack`. The three GPU back-ends are mutually exclusive
(priority HIP > OpenCL > CUDA).

### Windows (GUI, batch file)

Open an **x64 Native Tools Command Prompt for VS** and run:

```bat
build.bat
```

Output: `bin\dmrcrack.exe`. The script auto-detects Visual Studio via `vswhere.exe`. Targets sm_75/86/89 natively with a PTX fallback for newer GPUs (JIT-compiled on first run).

### Test tools (MSVC, no CUDA)

```bat
build_test.bat       # → bin\test_strict_score.exe
```

### Installer

1. Install [Inno Setup](https://jrsoftware.org/isinfo.php)
2. Open `installer\FSP.DMRCrack.iss`
3. Build

---

## Project structure

```
FSP.DMRCrack/
  src/
    main.c             WinMain entry point (Windows GUI)
    gui.c              Win32 GUI, dark theme, progress graphs
    cli.c              Headless CLI entry point (Linux / NO_GUI builds)
    bruteforce.cu      CUDA/HIP GPU kernels + CPU fallback
    bruteforce_cl.cpp  OpenCL host engine (-DUSE_OPENCL) + CPU fallback
    dmrcrack.cl        OpenCL kernels (ported 1:1 from bruteforce.cu)
    bruteforce.c       CPU-only build path (used by test tools)
    rc4.c              RC4 KSA + PRGA, host-side
    payload_io.c       .bin loader/saver, ALG/KID/MI metadata parser
    lang.c / lang_en.c / lang_es.c   i18n string tables
    updater.c          WinSparkle auto-update integration
  include/
    platform.h         Win32/POSIX abstraction (threads, atomics, timing)
    gpu_compat.h       CUDA/HIP compatibility shim
    bruteforce.h       Engine API and BruteforceEngine struct
    lang.h / version.h / payload_io.h / updater.h
  src/
    test_strict_score.c    Per-burst scoring validation against known key
    test_score_windows.c   Score distribution analysis tool
    test_bench.cu          GPU kernel throughput micro-benchmark
  tools/
    dsd-fme.exe                    DSD-FME demodulator (Cygwin DLLs required alongside)
    dsdfme_dsp_to_bin.py           DSD-FME DSP output → .bin converter
    verify_decrypt.py              Key validation with Z-score output
    diag_decrypt.py                Decryption pipeline diagnostic
  debian/              Debian packaging (control, rules, changelog, copyright)
  completions/
    dmrcrack.bash      bash completion (installed as bash-completion/completions/dmrcrack)
  man/
    dmrcrack.1         Man page
  installer/
    FSP.DMRCrack.iss   Inno Setup script
  CMakeLists.txt       Cross-platform build (Linux + Windows)
  build.bat            Windows batch build (auto-detects VS + CUDA)
  Dockerfile           Multi-stage OpenCL build on a Debian/Kali base
  bin/                 Compiled output (not tracked in git)
```

---

## Contributing

PRs are welcome. The [issue tracker](https://github.com/FSP-Labs/FSP.DMRCrack/issues) has tagged issues if you want somewhere to start:

- [**`good first issue`**](https://github.com/FSP-Labs/FSP.DMRCrack/labels/good%20first%20issue) — well-scoped tasks: magic-number cleanup, i18n audit, test coverage
- [**`help wanted`**](https://github.com/FSP-Labs/FSP.DMRCrack/labels/help%20wanted) — bigger items that need more familiarity with the codebase

Build setup, code style, and PR guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Legal & responsible use

FSP.DMRCrack is a **security-auditing and research tool**. It exists so that
radio operators, security researchers, and CTF participants can assess the
strength of DMR Enhanced Privacy on systems **they own or are explicitly
authorized in writing to test**.

By downloading, building, or running this software you agree that:

- You will use it **only** against radio communications you own or have explicit,
  documented permission to audit.
- **Unauthorized interception, decryption, or disclosure of radio communications
  is illegal** in most jurisdictions (e.g. the U.S. Wiretap Act / 47 U.S.C. § 605,
  the U.K. Investigatory Powers Act, and equivalent laws worldwide) and may carry
  serious criminal and civil penalties.
- All responsibility and liability for how you use this tool rests **entirely with
  you**. The authors and contributors accept **no liability** for misuse or for any
  damage, loss, or legal consequence arising from its use.
- The software is provided **"as is", without warranty of any kind**, as set out in
  the GPLv3.

If you are not certain you are legally authorized to analyze a given transmission,
**do not use this tool on it.** When in doubt, don't.

---

## License

FSP.DMRCrack is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License version 3** as published by the Free Software Foundation. See [LICENSE](LICENSE) for the full text.

DSD-FME (required companion tool, distributed in `tools/`) is licensed under ISC + GPLv2. See [NOTICE](NOTICE). The Cygwin runtime DLLs bundled alongside DSD-FME are LGPL-licensed.
