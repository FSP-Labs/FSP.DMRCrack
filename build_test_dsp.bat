@echo off
cd /d "%~dp0"
call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%
if not exist bin mkdir bin
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_dsp_convert.exe tests\test_dsp_convert.c src\payload_io.c /Iinclude
if %ERRORLEVEL% EQU 0 (echo BUILD SUCCEEDED) else (echo BUILD FAILED %ERRORLEVEL%)
