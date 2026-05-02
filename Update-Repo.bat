@echo off
chcp 65001 >nul
title ShadowHack - GitHub Auto Updater
color 0B

echo ===================================================
echo       ShadowHack - Auto GitHub Update Script
echo ===================================================
echo.

:: Check if git is installed
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Git is not installed or not in PATH.
    echo Please install Git from https://git-scm.com/
    pause
    exit /b
)

:: Show current branch and status
echo [*] Current Git Status:
git status -s
echo.

:: Ask for commit message
set /p commit_msg="Enter commit message (or press Enter for auto-date message): "

if "%commit_msg%"=="" (
    for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
    set commit_msg=Auto-update: %date% %time%
)

echo.
echo [*] Staging all changes...
git add .

echo [*] Committing changes...
git commit -m "%commit_msg%"

echo [*] Pushing to GitHub...
:: Get current branch name
for /f %%I in ('git rev-parse --abbrev-ref HEAD') do set CURRENT_BRANCH=%%I
git push origin %CURRENT_BRANCH%

if %errorlevel% equ 0 (
    echo.
    color 0A
    echo ===================================================
    echo [SUCCESS] Changes have been successfully pushed to GitHub!
    echo ===================================================
) else (
    echo.
    color 0C
    echo ===================================================
    echo [ERROR] Failed to push changes to GitHub.
    echo ===================================================
)

echo.
pause
