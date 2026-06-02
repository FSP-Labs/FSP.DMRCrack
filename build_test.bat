@echo off
cd /d "%~dp0"

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin

echo Building test_strict_score.exe...
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_strict_score.exe tests\test_strict_score.c src\bruteforce.c src\rc4.c src\payload_io.c /Iinclude user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCEEDED
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
)
