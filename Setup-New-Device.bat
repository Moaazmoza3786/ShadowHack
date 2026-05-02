@echo off
title Setup ShadowHack - New Device
color 0B

echo ============================================================
echo       ShadowHack V6 - Device Setup Kernel
echo ============================================================
echo.
echo [*] Checking System Requirements...

:: Check if Docker is installed and running
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [X] CRITICAL: Docker Desktop is not installed or not running!
    echo     ShadowHack V6 requires Docker to run the AI and Pentesting Tools.
    echo.
    echo     DOWNLOAD LINK: https://www.docker.com/products/docker-desktop/
    echo     Please install it, open Docker Desktop, and then run this file again.
    echo.
    pause
    exit /b 1
)

echo [OK] Docker is detected.
echo.
echo [*] Phase 1/2: Building ShadowHack Engine (Frontend, Backend, Tools)...
echo     (This will take a few minutes to install all pentesting tools like nmap/sqlmap)
docker-compose build --no-cache

echo.
echo [*] Phase 2/2: Starting Services and Downloading AI...
echo     (The system will now download the qwen2.5-coder 4.5GB AI model)
docker-compose up -d

echo.
echo ============================================================
echo [SUCCESS] SHADOWHACK IS INSTALLED!
echo The AI model might still be downloading in the background.
echo Next time, just open "Start-ShadowHack.bat"!
echo ============================================================
pause
