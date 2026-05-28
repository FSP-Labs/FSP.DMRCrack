@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (echo ERROR: vcvars64 failed & exit /b 1)
nvcc -O3 ^
  -gencode arch=compute_75,code=sm_75 ^
  -gencode arch=compute_86,code=sm_86 ^
  -gencode arch=compute_89,code=sm_89 ^
  -cudart static -Iinclude ^
  -DNO_GUI ^
  -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" ^
  src\bruteforce.cu src\payload_io.c src\rc4.c ^
  src\lang.c src\lang_en.c src\lang_es.c src\cli.c ^
  -o bin\dmrcrack-cli.exe ^
  -luser32 -lkernel32 -ladvapi32
if errorlevel 1 (echo ERROR: nvcc failed & exit /b 1)
echo Build OK: bin\dmrcrack-cli.exe
