@echo off
REM Build the headless CPU-only CLI (no CUDA toolkit needed).
REM This is the portable engine shipped in the Debian/Kali package; GPU users
REM build dmrcrack-cli.exe via build_cli.bat instead.
cd /d "%~dp0"

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin

echo Building dmrcrack-cli-cpu.exe (CPU-only engine)...
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNO_GUI /Fe:bin\dmrcrack-cli-cpu.exe ^
   src\cli.c src\bruteforce.c src\rc4.c src\payload_io.c ^
   src\lang.c src\lang_en.c src\lang_es.c ^
   /Iinclude user32.lib advapi32.lib
if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCEEDED: bin\dmrcrack-cli-cpu.exe
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
