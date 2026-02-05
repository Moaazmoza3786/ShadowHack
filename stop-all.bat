@echo off
:: ============================================================
:: ShadowHack - Stop All Services
:: Stops all running servers
:: ============================================================

title ShadowHack - Stopping Services

echo.
echo [*] Stopping all ShadowHack services...
echo.

:: Kill Flask backend
taskkill /F /FI "WINDOWTITLE eq Flask Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq *Flask*" >nul 2>&1
echo [X] Flask Backend stopped.

:: Kill Frontend server
taskkill /F /FI "WINDOWTITLE eq Frontend*" >nul 2>&1
echo [X] Frontend server stopped.

:: Stop Docker containers if running
where docker >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Stopping Docker lab containers...
    cd backend
    docker-compose -f docker-compose.labs.yml down >nul 2>&1
    cd ..
    echo [X] Docker labs stopped.
)

echo.
echo ============================================================
echo  All services stopped successfully!
echo ============================================================
echo.
pause
