@echo off
REM Shared MSVC + CUDA environment setup for the build scripts.
REM Detects Visual Studio via vswhere, runs vcvarsall x64, and (when the CUDA
REM toolkit is installed) re-adds it to PATH/INCLUDE after vcvars resets them.
REM
REM Must be invoked with CALL so the environment changes propagate to the
REM caller (do NOT use setlocal here).

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Install Visual Studio 2017 or later.
    exit /b 1
)

REM Pick a CUDA-supported MSVC host compiler. nvcc (through CUDA 13.x) rejects the
REM VS 2026 v145 toolset -- its support is "experimental" and NVIDIA warns it can
REM produce incorrect runtime behaviour, which is unacceptable for a brute-forcer.
REM
REM Strategy: prefer a native VS 2019-2022 install (its default toolset is fine);
REM if only VS 2026 is present, still use it but force the v143 (VS 2022) toolset
REM via -vcvars_ver. That requires the "MSVC v143 - VS 2022 C++ build tools"
REM individual component to be installed alongside VS 2026 (it coexists with v145).
set "VSINSTALL="
set "VCVARS_TOOLSET="
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "&'%VSWHERE%' -latest -version '[16.0,18.0)' -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath"`) do set "VSINSTALL=%%v"
if not defined VSINSTALL (
    REM Fall back to the newest VS (2026+), but select the v143 toolset for nvcc.
    for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "&'%VSWHERE%' -latest -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath"`) do set "VSINSTALL=%%v"
    set "VCVARS_TOOLSET=-vcvars_ver=14.4"
)
if not defined VSINSTALL (
    echo ERROR: No suitable Visual Studio installation found.
    exit /b 1
)

call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64 %VCVARS_TOOLSET%
if errorlevel 1 (
    echo.
    echo ERROR: MSVC toolset setup failed.
    if defined VCVARS_TOOLSET echo   Only VS 2026 was found. nvcc cannot use its v145 toolset -- install the
    if defined VCVARS_TOOLSET echo   "MSVC v143 - VS 2022 C++ x64/x86 build tools" component in the VS Installer.
    exit /b %errorlevel%
)

REM Ensure CUDA paths are available after vcvarsall resets the environment
if defined CUDA_PATH (
    set "PATH=%CUDA_PATH%\bin;%PATH%"
    set "INCLUDE=%CUDA_PATH%\include;%INCLUDE%"
)

exit /b 0
