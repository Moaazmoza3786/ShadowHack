@echo off
title ShadowHack V6 - Direct Launcher (No Docker)
color 0A

echo ============================================================
echo       ShadowHack V6 - Neural Engine & Pentest Suite
echo       Direct Launcher (No Docker)
echo ============================================================
echo.

:: Get the script directory
set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "FRONTEND_DIR=%ROOT_DIR%study-hub-react"

echo [*] Checking Node.js...
node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] ERROR: Node.js is not installed!
    echo     Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

echo [*] Checking Python...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] ERROR: Python is not installed!
    echo     Please install Python 3.8+
    pause
    exit /b 1
)

echo.
echo ============================================================
echo    STARTING BACKEND SERVICES
echo ============================================================
echo.

cd /d "%BACKEND_DIR%"
start "ShadowHack Backend" cmd /k "echo Starting Backend Server... && python main.py"

echo [*] Waiting for Backend to initialize...
timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo    STARTING FRONTEND SERVICES  
echo ============================================================
echo.

cd /d "%FRONTEND_DIR%"

:: Check if node_modules exists
if not exist "node_modules" (
    echo     [.] Installing frontend dependencies...
    npm install
)

start "ShadowHack Frontend" cmd /k "echo Starting Frontend Server... && npm run dev"

:: Return to root
cd /d "%ROOT_DIR%"

echo.
echo ============================================================
echo    SYNAPTIC LINK ESTABLISHED
echo ============================================================
echo.
echo    INTERFACE:  http://localhost:3000
echo    BACKEND:    http://localhost:5000
echo.
echo [NOTE] Close the Backend/Frontend windows to stop them.
echo.

timeout /t 5 /nobreak >nul
exit