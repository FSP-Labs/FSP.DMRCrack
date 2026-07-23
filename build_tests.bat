@echo off
REM Build the host test tools (no CUDA toolkit required). Default: all.
REM   build_tests.bat            -> build all
REM   build_tests.bat all
REM   build_tests.bat strict     -> test_strict_score.exe
REM   build_tests.bat canonical  -> test_score_canonical.exe
REM   build_tests.bat hytera     -> test_hytera_ks.exe
REM   build_tests.bat silence    -> test_silence_guard.exe
REM   build_tests.bat dsp        -> test_dsp_convert.exe
REM (On Linux these build + run via CMake -DBUILD_TESTS=ON and ctest.)
cd /d "%~dp0"

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin
set "FAIL=0"

set "T=%~1"
if "%T%"=="" set "T=all"

if /i "%T%"=="all" goto all
if /i "%T%"=="strict"    ( call :strict    & goto end )
if /i "%T%"=="canonical" ( call :canonical & goto end )
if /i "%T%"=="hytera"    ( call :hytera    & goto end )
if /i "%T%"=="silence"   ( call :silence   & goto end )
if /i "%T%"=="dsp"       ( call :dsp       & goto end )
echo Usage: build_tests.bat [all^|strict^|canonical^|hytera^|silence^|dsp]
exit /b 2

:all
call :strict
call :canonical
call :hytera
call :silence
call :dsp
goto end

:strict
echo [test_strict_score]
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fo:bin\ /Fe:bin\test_strict_score.exe tests\test_strict_score.c src\bruteforce.c src\rc4.c src\payload_io.c /Iinclude user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
if errorlevel 1 set "FAIL=1"
exit /b 0

:canonical
echo [test_score_canonical]
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Fo:bin\ /Fe:bin\test_score_canonical.exe tests\test_score_canonical.c src\rc4.c src\payload_io.c /Iinclude user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib
if errorlevel 1 set "FAIL=1"
exit /b 0

:hytera
echo [test_hytera_ks]
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fo:bin\ /Fe:bin\test_hytera_ks.exe tests\test_hytera_ks.c /Iinclude
if errorlevel 1 set "FAIL=1"
exit /b 0

:silence
echo [test_silence_guard]
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fo:bin\ /Fe:bin\test_silence_guard.exe tests\test_silence_guard.c src\payload_io.c /Iinclude
if errorlevel 1 set "FAIL=1"
exit /b 0

:dsp
echo [test_dsp_convert]
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fo:bin\ /Fe:bin\test_dsp_convert.exe tests\test_dsp_convert.c src\payload_io.c /Iinclude
if errorlevel 1 set "FAIL=1"
exit /b 0

:end
if "%FAIL%"=="0" (echo ALL BUILDS SUCCEEDED) else (echo SOME BUILDS FAILED)
exit /b %FAIL%
