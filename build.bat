@echo off
cd /d "%~dp0"

REM Auto-detect Visual Studio installation using vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Install Visual Studio 2017 or later.
    exit /b 1
)
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL (
    echo ERROR: No suitable Visual Studio installation found.
    exit /b 1
)
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b %errorlevel%

REM Ensure CUDA paths are available after vcvarsall resets the environment
if defined CUDA_PATH (
    set "PATH=%CUDA_PATH%\bin;%PATH%"
    set "INCLUDE=%CUDA_PATH%\include;%INCLUDE%"
)

echo Building FSP.DMRCrack...
REM Multi-arch: native SASS for sm_75/86/89; PTX fallback for sm_100+ (JIT on first run)
REM sm_75 = GTX 16xx / RTX 20xx (Turing)
REM sm_86 = RTX 30xx (Ampere)
REM sm_89 = RTX 40xx (Ada Lovelace)
REM compute_75 PTX = RTX 50xx + future GPUs (JIT-compiled by driver at first launch)
nvcc -O3 ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  -gencode arch=compute_75,code=compute_75 ^
  -cudart static -Iinclude -Ivendor\winsparkle\include ^
  -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" ^
  src\main.c src\gui.c src\bruteforce.cu src\payload_io.c src\rc4.c src\lang_en.c src\updater.c ^
  -o bin\dmrcrack.exe ^
  -luser32 -lgdi32 -lcomdlg32 -lkernel32 -ldwmapi -lshell32 -ladvapi32 ^
  vendor\winsparkle\x64\WinSparkle.lib
if %ERRORLEVEL% EQU 0 (
    copy vendor\winsparkle\x64\WinSparkle.dll bin\ >nul 2>&1
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
