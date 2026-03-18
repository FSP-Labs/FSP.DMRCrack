# Contributing to FSP.DMRCrack

## Prerequisites

- Windows 10/11 x64
- [Visual Studio 2022](https://visualstudio.microsoft.com/) with **Desktop development with C++** workload (includes MSVC x64 toolchain)
- [CUDA Toolkit 12.x](https://developer.nvidia.com/cuda-downloads) with an NVIDIA GPU (sm_75 or newer)
- Python 3.8+ (optional, for conversion/verification tools)

## Building

Open an **x64 Native Tools Command Prompt for VS** in the project root and run:

```bat
build.bat
```

Output: `bin\dmrcrack.exe`

To adjust the GPU architecture target, edit `-arch=sm_86` in `build.bat`:

| GPU generation | `-arch` value |
|---|---|
| Turing (RTX 20xx) | `sm_75` |
| Ampere (RTX 30xx) | `sm_86` |
| Ada (RTX 40xx) | `sm_89` |
| Blackwell (RTX 50xx) | `sm_100` |

### Test tools (MSVC only, no CUDA required)

```bat
build_test_bin.bat   # builds test_bin_score.exe
build_test.bat       # builds test_score.exe
```

## Code style

- C99, no C++ in `.c` files
- CUDA kernel code in `.cu` files
- 4-space indentation, `snake_case` for all identifiers
- Keep GPU kernel logic in `src/bruteforce.cu`; host-side scoring helpers in `src/bruteforce.c`
- Do not add Windows API calls outside `src/gui.c` and `src/main.c`

## Submitting changes

1. Fork the repository and create a feature branch
2. Make your changes; ensure `build.bat` succeeds without warnings
3. If touching scoring logic, verify with `bin\test_bin_score.exe` and `tools\verify_decrypt.py`
4. Open a pull request with a clear description of the change and why it is needed

## Reporting issues

Open an issue on GitHub and include:

- OS version and GPU model
- CUDA Toolkit version (`nvcc --version`)
- The exact error message or unexpected behavior
- Minimal reproduction steps (anonymized `.bin` file if relevant)

## License

By contributing you agree that your contributions will be licensed under the
GNU General Public License v3.0 (see [LICENSE](LICENSE)).
