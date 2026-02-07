@echo off
setlocal enabledelayedexpansion

echo ============================================
echo CloudCrypt Release Build Script
echo ============================================

:: Change to script directory
cd /d "%~dp0"

:: ============================================
:: Step 1: Set up RAD Studio environment
:: ============================================
echo.
echo Setting up RAD Studio environment...

call "C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
if errorlevel 1 (
    echo ERROR: Failed to set RAD Studio environment
    exit /b 1
)

:: ============================================
:: Step 2: Compile Win64 Release
:: ============================================
echo.
echo Compiling Win64 Release Build...

msbuild CloudCrypt.dproj /t:Build /p:Config=Release /p:Platform=Win64 /v:m /nologo
if errorlevel 1 (
    echo ERROR: Win64 Release build failed
    exit /b 1
)

echo Win64 Release build successful.

:: ============================================
:: Step 3: Verify build output
:: ============================================
echo.
echo Verifying build output...

if not exist "Win64\Release\CloudCrypt.exe" (
    echo ERROR: Win64\Release\CloudCrypt.exe not found
    exit /b 1
)

echo Build output verified.

:: ============================================
:: Step 4: Create release archive
:: ============================================
echo.
echo Creating release archive...

if exist "CloudCrypt.zip" del /f "CloudCrypt.zip"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$tempDir = 'release_temp'; " ^
    "if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }; " ^
    "New-Item -ItemType Directory -Path $tempDir | Out-Null; " ^
    "Copy-Item -Path 'Win64\Release\CloudCrypt.exe' -Destination $tempDir; " ^
    "Copy-Item -Path 'README.md' -Destination $tempDir; " ^
    "Compress-Archive -Path \"$tempDir\*\" -DestinationPath 'CloudCrypt.zip' -Force; " ^
    "Remove-Item -Recurse -Force $tempDir"

if errorlevel 1 (
    echo ERROR: Failed to create release archive
    exit /b 1
)

if not exist "CloudCrypt.zip" (
    echo ERROR: CloudCrypt.zip was not created
    exit /b 1
)

echo.
echo ============================================
echo Release build completed successfully!
echo Archive: CloudCrypt.zip
echo ============================================

endlocal
