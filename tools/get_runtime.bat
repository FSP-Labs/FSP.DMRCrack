@echo off
setlocal

set "RELEASE_URL=https://github.com/lwvmobile/dsd-fme/releases/download/v1.8-OHIO/dsd-fme-portable-win64-20251214.zip"
set "ZIP_FILE=%TEMP%\dsd-fme-portable.zip"
set "TOOLS_DIR=%~dp0"

echo FSP.DMRCrack -- DSD-FME Runtime Downloader
echo ============================================
echo.
echo This script downloads dsd-fme.exe and its required Cygwin DLLs
echo from the official dsd-fme portable release and places them in:
echo   %TOOLS_DIR%
echo.

if exist "%TOOLS_DIR%dsd-fme.exe" (
    echo dsd-fme.exe already present. Delete it first to re-download.
    goto :done
)

echo Downloading dsd-fme portable...
powershell -NoProfile -Command ^
    "try { Invoke-WebRequest -Uri '%RELEASE_URL%' -OutFile '%ZIP_FILE%' -UseBasicParsing } catch { Write-Error $_.Exception.Message; exit 1 }"
if errorlevel 1 (
    echo ERROR: Download failed. Check your internet connection.
    exit /b 1
)

echo Extracting...
powershell -NoProfile -Command ^
    "try { Add-Type -AssemblyName System.IO.Compression.FileSystem; $z = [IO.Compression.ZipFile]::OpenRead('%ZIP_FILE%'); foreach ($e in $z.Entries) { if ($e.FullName -match '^dsd-fme/[^/]+$' -and ($e.Name -match '\.(dll|exe)$' -or $e.Name -eq 'dsd-fme.exe')) { $dst = '%TOOLS_DIR%' + $e.Name; [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dst, $true) } }; $z.Dispose() } catch { Write-Error $_.Exception.Message; exit 1 }"
if errorlevel 1 (
    echo ERROR: Extraction failed.
    del /q "%ZIP_FILE%" 2>nul
    exit /b 1
)

del /q "%ZIP_FILE%" 2>nul

if exist "%TOOLS_DIR%dsd-fme.exe" (
    echo.
    echo Done. dsd-fme.exe and Cygwin DLLs are ready in tools\
) else (
    echo ERROR: dsd-fme.exe not found after extraction.
    exit /b 1
)

:done
echo.
pause
endlocal
