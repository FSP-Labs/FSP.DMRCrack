@echo off
cd /d "%~dp0"
call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%
if not exist bin mkdir bin
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_silence_guard.exe tests\test_silence_guard.c src\payload_io.c /Iinclude
if %ERRORLEVEL% EQU 0 (echo BUILD SUCCEEDED) else (echo BUILD FAILED %ERRORLEVEL%)
