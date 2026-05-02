@echo off
title ShadowHack V6 - Optimized Launcher
color 0A

echo ============================================================
echo       ShadowHack V6 - Neural System Launcher
echo       Optimized for Performance
echo ============================================================
echo.

:: Get the script directory
set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "FRONTEND_DIR=%ROOT_DIR%study-hub-react"

:: ============================================
:: 1. SYSTEM CHECKS
:: ============================================
echo [*] Checking System Requirements...

node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] ERROR: Node.js not found!
    echo     Installing Node.js dependencies will fail.
    pause
    exit /b 1
)

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] ERROR: Python not found!
    echo     Installing Python dependencies will fail.
    pause
    exit /b 1
)

echo [OK] Node.js: Found
python --version >nul 2>&1
echo [OK] Python: Found

:: Check Docker Status
docker --info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [X] ERROR: Docker is not running!
    echo     Please start Docker Desktop and try again.
    pause
    exit /b 1
)
echo [OK] Docker: Found and Running

:: ============================================
:: 2. START AI ENGINE (Docker)
:: ============================================
echo.
echo ============================================================
echo    AI NEURAL ENGINE (Docker)
:: ============================================================
echo.

docker run -d --name shadowhack-ai -p 11434:11434 --gpus=all --restart unless-stopped ollama/ollama:latest 2>nul

echo [*] Waiting for Ollama...
timeout /t 3 /nobreak >nul

:wait_ai
curl -s http://localhost:11434/api/tags >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    timeout /t 2 /nobreak >nul
    goto wait_ai
)

echo     [OK] AI Engine: Online (qwen2.5-coder:7b)

:: ============================================
:: 3. START BACKEND (Python)
:: ============================================
echo.
echo ============================================================
echo    BACKEND API (Python Flask)
:: ============================================================
echo.

cd /d "%BACKEND_DIR%"

echo [*] Installing Dependencies...
pip install -r requirements.txt -q --no-cache-dir 2>nul

echo [*] Starting Backend...
start "ShadowHack Backend" cmd /k "echo Backend running on http://localhost:5000 && python main.py"

timeout /t 4 /nobreak >nul

curl -s http://localhost:5000/health >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    timeout /t 5 /nobreak >nul
)

echo     [OK] Backend: http://localhost:5000

:: ============================================
:: 4. START FRONTEND (React)
:: ============================================
echo.
echo ============================================================
echo    FRONTEND (React Vite)
:: ============================================================
echo.

cd /d "%FRONTEND_DIR%"

echo [*] Checking Cache...
if exist "node_modules\.cache" (
    rmdir /s /q "node_modules\.cache" >nul 2>&1
)

echo [*] Installing Dependencies...
if not exist "node_modules" (
    echo     [Optimization] Fresh install...
    call npm install --silent --no-audit
) else (
    echo     [Optimization] Cache preserved...
)

echo [*] Starting Frontend...
start "ShadowHack Frontend" cmd /k "echo Frontend running on http://localhost:3000 && npm run dev"

timeout /t 5 /nobreak >nul

curl -s http://localhost:3000 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    timeout /t 5 /nobreak >nul
)

echo     [OK] Frontend: http://localhost:3000

:: ============================================
:: 5. SUMMARY
:: ============================================
echo.
echo ============================================================
echo    ✨ SYSTEM READY
:: ============================================================
echo.
echo    🖥️  INTERFACE:  http://localhost:3000
echo    🔧  BACKEND:    http://localhost:5000
echo    🤖  AI ENGINE:  http://localhost:11434
echo    💾  DATABASE:   localhost:5432
echo    📦  CACHE:      localhost:6379
echo    ⚡  PERFORMANCE: Optimized
echo.
echo ============================================================
echo    ACTIVE MODULES
:: ============================================================
echo.
echo    🎯  Ollama AI (7B Model)
echo    🔌  Flask Backend (FastAPI)
echo    ⚡  React Vite (Fast HMR)
echo    💾  PostgreSQL
echo    📦  Redis
echo    🛠️  All Your Tools
echo    🔐  Auth System
echo    🏆  Gamification
echo    📊  Performance Optimized
echo.
echo    The Neural Interface is ready for operation!
echo.

echo [*] Opening Interface...
start "" "http://localhost:3000"

echo.
echo ============================================================
echo    [NOTE] Close service windows to stop them.
echo           Run STOP-ShadowHack.bat to shut down.
echo ============================================================
echo.
timeout /t 8 /nobreak >nul
exit