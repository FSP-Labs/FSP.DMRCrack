@echo off
cd /d "%~dp0\.."

REM Auto-detect Visual Studio using vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found.
    exit /b 1
)
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL (
    echo ERROR: No suitable Visual Studio installation found.
    exit /b 1
)
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1

if defined CUDA_PATH (
    set "PATH=%CUDA_PATH%\bin;%PATH%"
    set "INCLUDE=%CUDA_PATH%\include;%INCLUDE%"
)

echo Building test_bench.exe (sm_86, rdc=true)...

REM -rdc=true is required so that extern __constant__ in test_bench.cu
REM resolves against the definitions in bruteforce.cu across TUs.
nvcc -O3 ^
  -gencode arch=compute_86,code=sm_86 ^
  -rdc=true ^
  --ptxas-options=-v ^
  -cudart static ^
  -Iinclude ^
  -Ivendor\winsparkle\include ^
  -Xcompiler "/W3 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS /DSTANDALONE_BENCH" ^
  tests\test_bench.cu src\bruteforce.cu src\payload_io.c src\rc4.c ^
  -o bin\test_bench.exe ^
  -luser32 -lgdi32 -lcomdlg32 -lkernel32 -ldwmapi -lshell32 -ladvapi32

if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
