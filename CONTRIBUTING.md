# Contributing to FSP.DMRCrack

## Prerequisites

**Windows:**
- Windows 10/11 x64
- [Visual Studio 2022](https://visualstudio.microsoft.com/) with the Desktop C++ workload
- [CUDA Toolkit 12.x](https://developer.nvidia.com/cuda-downloads) and an NVIDIA GPU (sm_75+)

**Linux:**
- GCC or Clang
- CMake >= 3.21
- A GPU back-end (any one): portable OpenCL (`opencl-headers` + an ICD loader,
  `-DUSE_OPENCL=ON`), NVIDIA CUDA Toolkit 12.x (default), or AMD ROCm 6.x
  (`-DUSE_HIP=ON`). Builds CPU-only when no GPU toolkit is present.

Python 3.8+ is optional; only needed for the conversion and verification scripts in `tools/`.

## Building

### Linux

```bash
# Portable OpenCL (what the Debian/Kali package builds; NVIDIA / AMD / Intel)
cmake -S . -B build -DUSE_OPENCL=ON -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Omit `-DUSE_OPENCL=ON` for the NVIDIA CUDA back-end, or pass `-DUSE_HIP=ON` for
AMD ROCm. The three GPU back-ends are mutually exclusive.

### Windows (GUI)

Open an **x64 Native Tools Command Prompt for VS** in the project root:

```bat
build.bat
```

Output: `bin\dmrcrack.exe`

### Test tools (MSVC, no CUDA required)

```bat
build_tests.bat      # all host tests (or: strict | canonical | hytera | silence | dsp)
```

On Linux the same tests build and run via `cmake -DBUILD_TESTS=ON` + `ctest`.

## Code style

- C99, no C++ in `.c` files
- CUDA/HIP kernel code in `.cu` files
- 4-space indentation, `snake_case` for all identifiers
- Platform-specific code goes through `include/platform.h`. Don't call Win32 APIs directly outside `src/gui.c` and `src/main.c`
- GPU kernel logic and host-side scoring helpers both live in `src/bruteforce.cu` so the strict pipeline stays in sync between the two

## Submitting changes

1. Fork and create a feature branch
2. Make your changes; `build.bat` (Windows) or CMake (Linux) should succeed without new warnings
3. If you touched scoring logic, run `build_tests.bat` (at least `strict` and `canonical`) and `tools\verify_decrypt.py` against the test data in `test/aaaaa/`. Keep all scorers on the canonical strict metric — GPU, OpenCL, CPU and host paths must agree.
4. Open a PR with a description of what changed and why

## Reporting issues

Open an issue and include:

- OS and GPU model
- CUDA Toolkit version (`nvcc --version`)
- Exact error message or unexpected behavior
- Steps to reproduce (anonymized `.bin` file if relevant)

## Acceptable use of contributed data

FSP.DMRCrack is for auditing systems you own or are explicitly authorized in
writing to test. Keep that boundary in the project itself:

- Do **not** attach, paste, or link captured radio traffic, payloads, or keys
  from systems you do not own or are not authorized to test — in issues, pull
  requests, discussions, or commits.
- Sample data for a bug report must come from your own or an authorized system,
  or be synthetic (see `tools/gen_hytera_synth.c`). Redact MI/key material that
  is not yours.
- The project does not host third-party captures or recovered keys, and PRs that
  add any will be declined.

## License

By contributing you agree that your work will be licensed under GPL v3.0 (see [LICENSE](LICENSE)).
