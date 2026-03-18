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

echo Building test_strict_score.exe...
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_strict_score.exe src\test_strict_score.c src\bruteforce.c src\rc4.c src\payload_io.c /Iinclude user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
