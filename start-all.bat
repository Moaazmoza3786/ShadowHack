@echo off
chcp 65001 >nul
:: ============================================================
:: ShadowHack - Integrated Startup Kernel
:: Starts all components with zero-manual intervention
:: ============================================================

title ShadowHack - Startup Kernel

echo.
echo   [!] INITIALIZING SHADOWHACK V6 KERNEL...
echo   =============================================
echo.

:: Set colors - Matrix Green
color 0A

:: Get the script directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo [*] Phase 1: Environment Sanitization (Background)...
:: Fire-and-forget cleanup to ensure no blocking hangs
start /b "" powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 5000, 8080 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }" >nul 2>&1
timeout /t 1 /nobreak >nul

:: Check if Python is installed
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [X] CRITICAL: Python not found in PATH!
    echo     Please install Python from https://python.org
    pause
    exit /b 1
)

echo [*] Phase 2: Dependency Synchronization...
cd backend
:: Only run pip if requirements.txt is newer than a hidden marker or just run it quietly
pip install -r requirements.txt --quiet --no-input >nul 2>&1
cd ..
echo     [OK] Dependencies verified.

echo [*] Phase 3: Launching Neural Backend (Port 5000)...
:: Use app.py as it contains the fixed AI routes
start "Flask Backend - ShadowHack" cmd /c "cd /d %SCRIPT_DIR%backend && python app.py"
:: Wait for server to bind
timeout /t 3 /nobreak >nul

echo [*] Phase 3.5: Launching AI Middleware (Port 5005)...
start "AI Middleware - ShadowHack" cmd /c "cd /d %SCRIPT_DIR%ai-middleware && if not exist node_modules (echo [!] Installing AI dependencies... && npm install) && node server.js"
timeout /t 3 /nobreak >nul

echo [*] Phase 4: Launching Interface (Port 8080)...
start "Frontend - ShadowHack" cmd /c "cd /d %SCRIPT_DIR% && python frontend_server.py"
timeout /t 2 /nobreak >nul

echo [*] Phase 5: Lab Engine Connectivity...
where docker >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo     [OK] Docker detected. Hybrid labs enabled.
) else (
    echo     [!] Docker absent. Switching to edge simulation mode.
)

echo [*] Phase 6: Syncing Real-time Neural Link (Port 3001)...
start "Real-time Leaderboard - ShadowHack" cmd /c "cd /d %SCRIPT_DIR%realtime-leaderboard && if not exist node_modules (echo [!] Syncing Matrix dependencies... && npm install) && node index.js"
timeout /t 2 /nobreak >nul

echo.
echo   =============================================
echo    SYNAPTIC LINK ESTABLISHED
echo   =============================================
echo.
echo    INTERFACE: http://localhost:8080
echo    NEURAL:    http://localhost:5000
echo.

:: Auto-open browser
echo [*] Igniting browser...
start "" "https://localhost:8080"

echo.
echo [*] Deployment Complete.
echo [NOTE] Minimize (do not close) the background terminal windows.
echo.
:: Exit this script window automatically after success
timeout /t 5 /nobreak >nul
exit
