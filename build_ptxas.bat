@echo off
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1
if defined CUDA_PATH set "PATH=%CUDA_PATH%\bin;%PATH%"

echo Compiling for sm_86 with ptxas register info...
nvcc -O3 ^
  -gencode arch=compute_86,code=sm_86 ^
  --ptxas-options=-v ^
  -cudart static -Iinclude -Ivendor\winsparkle\include ^
  -Xcompiler "/W4 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS" ^
  src\main.c src\gui.c src\bruteforce.cu src\payload_io.c src\rc4.c ^
  src\lang.c src\lang_en.c src\lang_es.c src\updater.c ^
  -o bin\dmrcrack.exe ^
  -luser32 -lgdi32 -lcomdlg32 -lkernel32 -ldwmapi -lshell32 -ladvapi32 ^
  vendor\winsparkle\x64\WinSparkle.lib
echo Exit code: %ERRORLEVEL%
