@echo off
cd /d "%~dp0"

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin

echo Building FSP.DMRCrack...
REM Multi-arch: native SASS for sm_75/86/89/120; compute_89 PTX JITs everything else.
REM sm_75  = GTX 16xx / RTX 20xx (Turing)
REM sm_86  = RTX 30xx (Ampere)
REM sm_89  = RTX 40xx (Ada Lovelace)
REM sm_120 = RTX 50xx (Blackwell consumer) -- native SASS, needs CUDA 12.8+. Without it
REM          the 50-series runs via compute_89 PTX JIT, which can silently fail to launch
REM          on some driver/toolkit combos and leaves the scan producing nothing.
REM compute_89 PTX = Hopper/datacenter-Blackwell + any future GPU (JIT at first launch)
nvcc -O3 ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  -gencode arch=compute_120,code=sm_120 ^
  -gencode arch=compute_89,code=compute_89 ^
  --ptxas-options=-v ^
  -cudart static -Iinclude -Ivendor\winsparkle\include ^
  -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" ^
  src\main.c src\gui.c src\bruteforce.cu src\payload_io.c src\rc4.c ^
  src\lang.c src\lang_en.c src\lang_es.c src\updater.c ^
  -o bin\dmrcrack.exe ^
  -luser32 -lgdi32 -lcomdlg32 -lkernel32 -ldwmapi -lshell32 -ladvapi32 ^
  vendor\winsparkle\x64\WinSparkle.lib
if %ERRORLEVEL% EQU 0 (
    copy vendor\winsparkle\x64\WinSparkle.dll bin\ >nul 2>&1
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
