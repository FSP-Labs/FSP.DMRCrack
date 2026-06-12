@echo off
cd /d "%~dp0"
call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%
if not exist bin mkdir bin
if not defined CUDA_PATH set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
echo Building dmrcrack-cli-cl.exe (OpenCL backend)...
cl /nologo /O2 /W3 /EHsc /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS /DUSE_OPENCL /DNO_GUI /DCL_TARGET_OPENCL_VERSION=120 ^
   /Iinclude /Ibuild_cl /I"%CUDA_PATH%\include" ^
   src\cli.c src\bruteforce_cl.cpp src\payload_io.c src\rc4.c src\lang.c src\lang_en.c src\lang_es.c ^
   /Fe:bin\dmrcrack-cli-cl.exe ^
   /link "%CUDA_PATH%\lib\x64\OpenCL.lib" user32.lib kernel32.lib advapi32.lib
if %ERRORLEVEL% EQU 0 (echo BUILD SUCCEEDED) else (echo BUILD FAILED %ERRORLEVEL%)
