@echo off
cd /d "%~dp0"
call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%
if not exist bin mkdir bin
echo Building test_hytera_ks.exe...
cl /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fe:bin\test_hytera_ks.exe tests\test_hytera_ks.c /Iinclude
if %ERRORLEVEL% EQU 0 (echo BUILD SUCCEEDED) else (echo BUILD FAILED %ERRORLEVEL%)
