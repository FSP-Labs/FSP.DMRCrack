@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~3"=="" (
  echo Usage:
  echo   %~nx0 ^<ruta_dsd-fme.exe^> ^<input.wav^> ^<output.bin^>
  echo Example:
  echo   %~nx0 "C:\dsd-fme\dsd-fme.exe" "test\aaaaa\RC4-40.wav" "test\aaaaa\RC4-40.fromdsdfme.bin"
  exit /b 1
)

set "DSDFME=%~1"
set "INWAV=%~2"
set "OUTBIN=%~3"

if not exist "%DSDFME%" (
  echo ERROR: dsd-fme.exe not found: "%DSDFME%"
  exit /b 2
)
if not exist "%INWAV%" (
  echo ERROR: WAV file not found: "%INWAV%"
  exit /b 3
)

for %%I in ("%OUTBIN%") do (
  set "OUTDIR=%%~dpI"
  set "OUTNAME=%%~nI"
)
if not exist "%OUTDIR%" mkdir "%OUTDIR%" >nul 2>&1

set "QNAME=%OUTNAME%.dsdsp.txt"
set "DSPFILE="
set "LOGFILE=%OUTDIR%%OUTNAME%.dslog.txt"

REM Clean up previous outputs to avoid accumulation between runs
if exist "%OUTBIN%" del /f /q "%OUTBIN%" >nul 2>&1
if exist "%LOGFILE%" del /f /q "%LOGFILE%" >nul 2>&1
if exist "DSP\%QNAME%" del /f /q "DSP\%QNAME%" >nul 2>&1
if exist "%QNAME%" del /f /q "%QNAME%" >nul 2>&1

echo [1/2] Running DSD-FME and dumping encrypted DSP...
"%DSDFME%" -fs -i "%INWAV%" -Q "%QNAME%" -Z 2> "%LOGFILE%"
if errorlevel 1 (
  echo ERROR: dsd-fme failed. Check: "%LOGFILE%"
  exit /b 4
)

if exist "DSP\%QNAME%" (
  set "DSPFILE=%CD%\DSP\%QNAME%"
) else if exist "%QNAME%" (
  set "DSPFILE=%CD%\%QNAME%"
) else (
  for /f "delims=" %%F in ('dir /s /b /o-d "%QNAME%" 2^>nul') do (
    if not defined DSPFILE set "DSPFILE=%%F"
  )
)

if not defined DSPFILE (
  echo ERROR: DSP output not found "%QNAME%"
  echo Check the log: "%LOGFILE%"
  exit /b 6
)

echo [2/2] Converting DSP to BIN compatible with FSP.DMRCrack...
py -3 "%~dp0dsdfme_dsp_to_bin.py" --dsp "%DSPFILE%" --out "%OUTBIN%" --log "%LOGFILE%"
if errorlevel 1 (
  echo ERROR: conversion failed
  exit /b 5
)

echo Done:
echo   BIN:  "%OUTBIN%"
echo   DSP:  "%DSPFILE%"
echo   LOG:  "%LOGFILE%"
exit /b 0
