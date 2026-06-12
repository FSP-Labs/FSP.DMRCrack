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

REM Prefer the newest CUDA-supported toolset (VS 2019-2022). nvcc rejects the
REM VS 2026 (v18.0+) host compiler. VS2026_FALLBACK lets the caller force -latest.
set "VSINSTALL="
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$p=&'%VSWHERE%' -latest -version '[16.0,18.0)' -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath; if(-not $p){$p=&'%VSWHERE%' -latest -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -property installationPath}; $p"`) do set "VSINSTALL=%%v"
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

exit /b 0
