# Contributing to FSP.DMRCrack

## Prerequisites

**Windows:**
- Windows 10/11 x64
- [Visual Studio 2022](https://visualstudio.microsoft.com/) with the Desktop C++ workload
- [CUDA Toolkit 12.x](https://developer.nvidia.com/cuda-downloads) and an NVIDIA GPU (sm_75+)

**Linux:**
- GCC or Clang
- CMake >= 3.18
- CUDA Toolkit 12.x (or ROCm 5.7+ for AMD, with `-DUSE_HIP=ON`)

Python 3.8+ is optional; only needed for the conversion and verification scripts in `tools/`.

## Building

### Linux

```bash
cmake -S . -B build -DNO_GUI=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### Windows (GUI)

Open an **x64 Native Tools Command Prompt for VS** in the project root:

```bat
build.bat
```

Output: `bin\dmrcrack.exe`

### Test tools (no CUDA required)

```bat
build_test.bat       # builds bin\test_strict_score.exe
```

## Code style

- C99, no C++ in `.c` files
- CUDA/HIP kernel code in `.cu` files
- 4-space indentation, `snake_case` for all identifiers
- Platform-specific code goes through `include/platform.h`. Don't call Win32 APIs directly outside `src/gui.c` and `src/main.c`
- GPU kernel logic and host-side scoring helpers both live in `src/bruteforce.cu` so the strict pipeline stays in sync between the two

## Submitting changes

1. Fork and create a feature branch
2. Make your changes; `build.bat` (Windows) or CMake (Linux) should succeed without new warnings
3. If you touched scoring logic, run `bin\test_strict_score.exe` and `tools\verify_decrypt.py` against the test data in `test/aaaaa/`
4. Open a PR with a description of what changed and why

## Reporting issues

Open an issue and include:

- OS and GPU model
- CUDA Toolkit version (`nvcc --version`)
- Exact error message or unexpected behavior
- Steps to reproduce (anonymized `.bin` file if relevant)

## License

By contributing you agree that your work will be licensed under GPL v3.0 (see [LICENSE](LICENSE)).
