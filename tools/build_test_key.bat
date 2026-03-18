@echo off
cd /d "%~dp0.."

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
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNDEBUG /I include src\test_key.c src\dmr_demod.c src\payload_io.c src\rc4.c /Fe:bin\test_key.exe user32.lib gdi32.lib comdlg32.lib kernel32.lib
exit /b %errorlevel%
