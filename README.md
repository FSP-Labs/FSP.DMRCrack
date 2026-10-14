<h1 align="center">FSP.DMRCrack</h1>

<p align="center"><b>GPU-accelerated ARC4 key recovery for DMR Enhanced Privacy voice.</b></p>

<p align="center">
  <a href="https://github.com/FSP-Labs/FSP.DMRCrack/actions/workflows/build.yml"><img src="https://github.com/FSP-Labs/FSP.DMRCrack/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPLv3"></a>
  <a href="https://github.com/FSP-Labs/FSP.DMRCrack/releases/latest"><img src="https://img.shields.io/github/v/release/FSP-Labs/FSP.DMRCrack?label=Download&color=green" alt="Download"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational" alt="Platform: Windows | Linux">
  <img src="https://img.shields.io/badge/GPU-CUDA%20%7C%20OpenCL%20%7C%20HIP-76B900" alt="GPU: CUDA | OpenCL | HIP">
</p>

<!-- Drop a GUI capture at docs/screenshot.png: the dashboard with a recovered
     key shown CONFIRMED (amber), live throughput and the progress graphs. -->
<p align="center">
  <img src="docs/screenshot.png" width="820"
       alt="FSP.DMRCrack GUI: a recovered DMR Enhanced Privacy key shown CONFIRMED, with live keys/sec throughput and progress graphs">
</p>

> **Use only on systems you own or are explicitly authorized in writing to test.
> Unauthorized interception of radio communications is illegal in most
> jurisdictions.** See [SECURITY.md](SECURITY.md) and
> [Legal & responsible use](#legal--responsible-use).

---

## Features

- Recovers the full **40-bit RC4 key** of DMR Enhanced Privacy from recorded voice
- **MOTOTRBO** and **Hytera** Enhanced Privacy, auto-detected per capture
- **Multi-backend:** CUDA, OpenCL and HIP/ROCm, with a CPU fallback
- **Multi-GPU** work-queue that self-balances across asymmetric rigs
- **Decode-accurate oracle** — a recovered key actually decrypts the audio
- Reports a plain **CONFIRMED / UNVERIFIED / no-key** verdict, not a raw score
- **Dictionary + mask** modes, with hashcat-style potfile auto-skip
- Checkpoint/resume, benchmark mode, and JSON output
- Native **Windows GUI** (record -> crack -> listen) and a headless **Linux CLI**
- Free and open source, under the GPLv3

---

## About

DMR Enhanced Privacy (EP) is the encryption in MOTOTRBO, Hytera and other DMR
Tier II/III radios. It uses RC4 with a 40-bit (5-byte) key — roughly a trillion
candidates, tractable on a modern GPU in hours.

There is no known plaintext, so the trick is the oracle: valid AMBE voice has
slowly-varying parameters between frames, so the correct key produces a sharp
statistical spike well above the noise floor. FSP.DMRCrack runs the same decode
as DSD-FME, so a recovered key actually decrypts the audio, and reports a plain
**CONFIRMED / UNVERIFIED / no-key** verdict instead of a raw score.

For the full algorithm — the decode pipeline, scoring, and the confidence
verdict — see **[docs/how-it-works.md](docs/how-it-works.md)**.

---

## Install

### Windows (GUI)

Download `FSP.DMRCrack-Setup.exe` from
[Releases](https://github.com/FSP-Labs/FSP.DMRCrack/releases/latest) and run it
(Windows 10/11 x64, admin rights). DSD-FME and all Cygwin runtime DLLs are
bundled — nothing else to install. An NVIDIA GPU (sm_75+: GTX 16xx / RTX 20xx
through RTX 50xx) is strongly recommended; the CPU fallback works but takes days
instead of hours.

### Linux (CLI)

Build the portable OpenCL back-end (runs on NVIDIA / AMD / Intel, or CPU-only
when no GPU is present — this is what the Debian/Kali package builds):

```bash
sudo apt-get install -y cmake build-essential opencl-headers ocl-icd-opencl-dev
cmake -S . -B build -DUSE_OPENCL=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel   # → bin/dmrcrack
```

For the CUDA and ROCm/HIP back-ends and the Windows build, see
[Building from source](#building-from-source).

---

## Usage

### GUI (Windows): record → crack → listen

1. Record a WAV of the DMR RF signal (discriminator audio, 48 kHz mono) with
   your own SDR software (e.g. SDR#).
2. Select the WAV and click **Demodulate** — DSD-FME extracts the encrypted
   voice payloads into a `.bin`.
3. Click **Start** to run the GPU search; watch keys/sec, best score and ETA.
4. On recovery the candidate tile shows **CONFIRMED** (a wrong or dictionary key
   never reaches that verdict). Click **Listen** to decrypt and play back.

FSP.DMRCrack has no radio-capture capability of its own: it works on a recording
you supply, never over the air.

### CLI (Linux)

```bash
dmrcrack --bin capture.bin                 # full 40-bit search (mode auto-detected)
dmrcrack --bin capture.bin --key <HEX>     # score one candidate and exit
dmrcrack --bin capture.bin --wordlist keys.txt --potfile found.pot   # dictionary first
dmrcrack --bin capture.bin --benchmark     # measure throughput (~5 s)
dmrcrack --bin capture.bin --key <HEX> --json
```

Narrow the range with `--start` / `--end`, pick GPUs with `--gpus N`. Run
`dmrcrack --help`, or `man dmrcrack`, for the full option list.

The `.bin` is one hex-encoded voice burst per line with `ALG`/`KID`/`MI`
metadata; produce it from a DSD-FME `-Q` dump with `tools/dsdfme_dsp_to_bin.py`.
Format details are in [docs/how-it-works.md](docs/how-it-works.md).

---

## Supported ciphers

| Cipher | ALG | Status |
|---|---|---|
| MOTOTRBO Enhanced Privacy (RC4-40) | `0x21` / `0x01` | Supported (KMI9 pipeline) |
| Hytera Enhanced Privacy (RC4-40)   | `0x02`          | Supported (dedicated kernel) |
| Caltta Basic Privacy               | `0x26`          | Rejected — different scheme |
| AES (DMR-AES / Hytera HP), DMRA     | —               | Not supported |

The pipeline is auto-selected from the ALG distribution of the loaded capture.
Both RC4 variants need the Message Indicator (MI) carried in the clear in PI
headers; without MI only a much weaker statistical fallback runs. If DSD-FME
can't cleanly demodulate the WAV, the search runs but won't find the key.

Measured on an RTX 3050 Ti laptop GPU (CUDA): MOTOTRBO ~38 M keys/s (~8 h for a
full 2⁴⁰ scan), Hytera EP ~10 M keys/s. Throughput scales with the GPU; other
hardware and the OpenCL/HIP paths are not yet benchmarked.

---

## Building from source

### Linux (CMake, ≥ 3.21)

```bash
# Portable OpenCL (NVIDIA / AMD / Intel) — the default Debian/Kali build
cmake -S . -B build -DUSE_OPENCL=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release

# NVIDIA CUDA (peak throughput; CUDA Toolkit 12.x) — omit -DUSE_OPENCL
cmake -S . -B build -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release

# AMD ROCm / HIP (ROCm 6.x)
cmake -S . -B build -DUSE_HIP=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_HIP_COMPILER=/opt/rocm/bin/amdclang++ -DCMAKE_PREFIX_PATH=/opt/rocm

cmake --build build --parallel   # → bin/dmrcrack
```

The three GPU back-ends are mutually exclusive (priority HIP > OpenCL > CUDA).

### Windows (GUI)

In an **x64 Native Tools Command Prompt for VS**, run `build.bat` (→
`bin\dmrcrack.exe`). It auto-detects Visual Studio and targets sm_75/86/89/120
natively, with a PTX fallback for other GPUs. VS 2026 needs the **MSVC v143**
toolset — nvcc rejects v145; `_vsenv.bat` selects v143 automatically.

Headless CLI: `build_cli.bat [opencl|cpu]`. Host tests: `build_tests.bat`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup.

---

## Documentation

- **[docs/how-it-works.md](docs/how-it-works.md)** — the decode pipeline, scoring
  oracle, Hytera dialect, and GPU internals.
- **`man dmrcrack`** ([man/dmrcrack.1](man/dmrcrack.1)) — full CLI reference.
- **[CHANGELOG.md](CHANGELOG.md)** — release history.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — build setup and PR guidelines.
- **[SECURITY.md](SECURITY.md)** — intended use and vulnerability reporting.

---

## Contributing

PRs are welcome. The [issue tracker](https://github.com/FSP-Labs/FSP.DMRCrack/issues)
tags [`good first issue`](https://github.com/FSP-Labs/FSP.DMRCrack/labels/good%20first%20issue)
and [`help wanted`](https://github.com/FSP-Labs/FSP.DMRCrack/labels/help%20wanted).
See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Legal & responsible use

FSP.DMRCrack is a security-auditing and research tool for assessing DMR Enhanced
Privacy on systems **you own or are explicitly authorized in writing to test**.
Unauthorized interception, decryption, or disclosure of radio communications is
illegal in most jurisdictions and may carry serious penalties. All responsibility
rests with you; the software is provided **"as is", without warranty**, under the
GPLv3. If you are not certain you are authorized, do not use it. See
[SECURITY.md](SECURITY.md) for the full statement of intended use — the app also
asks you to confirm authorized use on first launch.

---

## License

FSP.DMRCrack is free software under the **GNU General Public License v3** — see
[LICENSE](LICENSE). DSD-FME (bundled in `tools/`) is ISC + GPLv2; the Cygwin
runtime DLLs are LGPLv3+ with the Cygwin linking exception. See [NOTICE](NOTICE).
