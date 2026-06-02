@echo off
cd /d "%~dp0"

REM ---------------------------------------------------------------------------
REM build_analysis.bat - compile-only build used to feed the CodeQL database.
REM
REM Compiles the product's hand-written C sources (no linking, no CUDA, no test
REM utilities) so the security scanner sees the real application code -- the
REM Win32 GUI, CLI, updater and payload/RC4 logic -- instead of a test harness.
REM bruteforce.cu is excluded (device code); its CPU twin bruteforce.c carries
REM the same host-side scoring logic and IS analysed.
REM
REM Object files land in bin\ and are disposable (gitignored *.obj).
REM ---------------------------------------------------------------------------

call "%~dp0_vsenv.bat"
if errorlevel 1 exit /b %errorlevel%

if not exist bin mkdir bin
pushd bin

set "CFLAGS=/c /W3 /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINDOWS /I..\include /I..\vendor\winsparkle\include"

REM GUI build configuration
for %%f in (
    rc4
    payload_io
    bruteforce
    lang
    lang_en
    lang_es
    gui
    updater
    main
) do (
    cl %CFLAGS% ..\src\%%f.c
    if errorlevel 1 (echo ERROR: failed to compile src\%%f.c & popd & exit /b 1)
)

REM Headless CLI entry point (compiled in its NO_GUI configuration)
cl %CFLAGS% /DNO_GUI ..\src\cli.c
if errorlevel 1 (echo ERROR: failed to compile src\cli.c & popd & exit /b 1)

popd
echo ANALYSIS BUILD OK
exit /b 0
