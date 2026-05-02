@echo off
title ShadowHack V6 - System Shutdown
color 0C

echo ============================================================
echo       ShadowHack V6 - Neural Shutdown Sequence
:: ============================================================
echo.

echo [*] Stopping all containers...
docker stop shadowhack-ai >nul 2>&1
docker rm shadowhack-ai >nul 2>&1

echo [*] Terminating Backend processes...
taskkill /FI "WINDOWTITLE eq ShadowHack Backend*" /F >nul 2>&1

echo [*] Terminating Frontend processes...
taskkill /FI "WINDOWTITLE eq ShadowHack Frontend*" /F >nul 2>&1

echo [*] Stopping Node processes on port 3000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000') do taskkill /PID %%a /F >nul 2>&1

echo [*] Stopping Python processes on port 5000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000') do taskkill /PID %%a /F >nul 2>&1

echo.
echo ============================================================
echo    SHUTDOWN COMPLETE
:: ============================================================
echo.
echo    All services have been terminated.
echo.
timeout /t 3 /nobreak >nul
exit