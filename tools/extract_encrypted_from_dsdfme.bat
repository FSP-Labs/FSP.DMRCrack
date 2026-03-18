@echo off
setlocal EnableExtensions EnableDelayedExpansion

if "%~3"=="" (
  echo Uso:
  echo   %~nx0 ^<ruta_dsd-fme.exe^> ^<input.wav^> ^<output.bin^>
  echo Ejemplo:
  echo   %~nx0 "C:\dsd-fme\dsd-fme.exe" "test\aaaaa\RC4-40.wav" "test\aaaaa\RC4-40.fromdsdfme.bin"
  exit /b 1
)

set "DSDFME=%~1"
set "INWAV=%~2"
set "OUTBIN=%~3"

if not exist "%DSDFME%" (
  echo ERROR: no existe dsd-fme.exe: "%DSDFME%"
  exit /b 2
)
if not exist "%INWAV%" (
  echo ERROR: no existe WAV: "%INWAV%"
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

REM Limpiar salidas previas para evitar acumulacion entre ejecuciones
if exist "%OUTBIN%" del /f /q "%OUTBIN%" >nul 2>&1
if exist "%LOGFILE%" del /f /q "%LOGFILE%" >nul 2>&1
if exist "DSP\%QNAME%" del /f /q "DSP\%QNAME%" >nul 2>&1
if exist "%QNAME%" del /f /q "%QNAME%" >nul 2>&1

echo [1/2] Ejecutando DSD-FME y volcando DSP cifrado...
"%DSDFME%" -fs -i "%INWAV%" -Q "%QNAME%" -Z 2> "%LOGFILE%"
if errorlevel 1 (
  echo ERROR: dsd-fme fallo. Revisa: "%LOGFILE%"
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
  echo ERROR: no se encontro el DSP de salida "%QNAME%"
  echo Revisa el log: "%LOGFILE%"
  exit /b 6
)

echo [2/2] Convirtiendo DSP a BIN compatible con FSP.DMRCrack...
py -3 "%~dp0dsdfme_dsp_to_bin.py" --dsp "%DSPFILE%" --out "%OUTBIN%" --log "%LOGFILE%"
if errorlevel 1 (
  echo ERROR: conversion fallo
  exit /b 5
)

echo Listo:
echo   BIN:  "%OUTBIN%"
echo   DSP:  "%DSPFILE%"
echo   LOG:  "%LOGFILE%"
exit /b 0
