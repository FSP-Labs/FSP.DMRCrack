@echo off
REM Build a headless CLI for the chosen backend (default: cuda):
REM   build_cli.bat            -> bin\dmrcrack-cli.exe       (NVIDIA CUDA)
REM   build_cli.bat cuda       -> bin\dmrcrack-cli.exe       (NVIDIA CUDA)
REM   build_cli.bat opencl     -> bin\dmrcrack-cli-cl.exe    (portable OpenCL)
REM   build_cli.bat cpu        -> bin\dmrcrack-cli-cpu.exe   (CPU-only, no toolkit)
cd /d "%~dp0"

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin

set "BACKEND=%~1"
if "%BACKEND%"=="" set "BACKEND=cuda"

if /i "%BACKEND%"=="cuda"   goto cuda
if /i "%BACKEND%"=="opencl" goto opencl
if /i "%BACKEND%"=="cl"     goto opencl
if /i "%BACKEND%"=="cpu"    goto cpu
echo Usage: build_cli.bat [cuda^|opencl^|cpu]   (default: cuda)
exit /b 2

:cuda
echo Building bin\dmrcrack-cli.exe (NVIDIA CUDA)...
nvcc -O3 ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  -gencode arch=compute_89,code=compute_89 ^
  -cudart static -Iinclude ^
  -DNO_GUI ^
  -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" ^
  src\bruteforce.cu src\payload_io.c src\rc4.c ^
  src\lang.c src\lang_en.c src\lang_es.c src\cli.c ^
  -o bin\dmrcrack-cli.exe ^
  -luser32 -lkernel32 -ladvapi32
goto check

:cpu
echo Building bin\dmrcrack-cli-cpu.exe (CPU-only engine, no toolkit)...
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNO_GUI /Fe:bin\dmrcrack-cli-cpu.exe ^
   src\cli.c src\bruteforce.c src\rc4.c src\payload_io.c ^
   src\lang.c src\lang_en.c src\lang_es.c ^
   /Iinclude user32.lib advapi32.lib
goto check

:opencl
if not defined CUDA_PATH set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
echo Generating build_cl\dmrcrack_cl_embed.h from src\dmrcrack.cl...
if not exist build_cl mkdir build_cl
> build_cl\dmrcrack_cl_embed.h echo /* Auto-generated from src\dmrcrack.cl - do not edit. */
>>build_cl\dmrcrack_cl_embed.h echo static const char *DMRCRACK_CL_SRC = R"DMRCLSRC(
>>build_cl\dmrcrack_cl_embed.h type src\dmrcrack.cl
>>build_cl\dmrcrack_cl_embed.h echo )DMRCLSRC";
echo Building bin\dmrcrack-cli-cl.exe (portable OpenCL)...
cl /nologo /O2 /W3 /EHsc /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS /DUSE_OPENCL /DNO_GUI /DCL_TARGET_OPENCL_VERSION=120 ^
   /Iinclude /Ibuild_cl /I"%CUDA_PATH%\include" ^
   src\cli.c src\bruteforce_cl.cpp src\payload_io.c src\rc4.c src\lang.c src\lang_en.c src\lang_es.c ^
   /Fe:bin\dmrcrack-cli-cl.exe ^
   /link "%CUDA_PATH%\lib\x64\OpenCL.lib" user32.lib kernel32.lib advapi32.lib
goto check

:check
if %ERRORLEVEL% EQU 0 (echo BUILD SUCCEEDED) else (echo BUILD FAILED with error %ERRORLEVEL%)
exit /b %ERRORLEVEL%
