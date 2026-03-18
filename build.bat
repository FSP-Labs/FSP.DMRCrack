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
nvcc -O3 -arch=sm_86 -cudart static -Iinclude -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" src\main.c src\gui.c src\bruteforce.cu src\payload_io.c src\rc4.c src\lang_en.c src\updater.c -o bin\dmrcrack.exe -luser32 -lgdi32 -lcomdlg32 -lkernel32 -ldwmapi -lshell32 -ladvapi32 -lwinhttp
if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
