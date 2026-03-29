#!/usr/bin/env powershell
# Vercel Token Setup Script for Windows

Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Vercel Authentication Setup Script      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if Vercel CLI is installed
Write-Host "Checking Vercel CLI..." -ForegroundColor Yellow
$vercelCheck = npm list -g vercel 2>&1 | Select-String "vercel"

if ($vercelCheck) {
    Write-Host "✅ Vercel CLI is installed" -ForegroundColor Green
} else {
    Write-Host "❌ Vercel CLI not found. Installing..." -ForegroundColor Red
    npm install -g vercel
}

Write-Host ""
Write-Host "Choose an option:" -ForegroundColor Cyan
Write-Host "  1. Authenticate with Vercel (Recommended)" -ForegroundColor White
Write-Host "  2. Check current authentication status" -ForegroundColor White
Write-Host "  3. Logout and re-authenticate" -ForegroundColor White
Write-Host "  4. View token location" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "Starting Vercel authentication..." -ForegroundColor Green
        Write-Host "You will be prompted to verify your identity." -ForegroundColor Yellow
        Write-Host ""
        vercel login
        Write-Host ""
        Write-Host "✅ Authentication complete!" -ForegroundColor Green
        Write-Host "You can now deploy with: vercel --prod" -ForegroundColor Cyan
    }
    
    "2" {
        Write-Host ""
        Write-Host "Checking current authentication..." -ForegroundColor Yellow
        Write-Host ""
        vercel whoami
        Write-Host ""
    }
    
    "3" {
        Write-Host ""
        Write-Host "Logging out..." -ForegroundColor Yellow
        vercel logout
        Write-Host ""
        Write-Host "Now logging in..." -ForegroundColor Green
        vercel login
        Write-Host ""
        Write-Host "✅ Re-authentication complete!" -ForegroundColor Green
    }
    
    "4" {
        Write-Host ""
        $tokenPath = "$env:USERPROFILE\.vercel\auth.json"
        Write-Host "Token location: $tokenPath" -ForegroundColor Cyan
        
        if (Test-Path $tokenPath) {
            Write-Host "✅ Token file found" -ForegroundColor Green
            Write-Host ""
            Write-Host "Token file contents (first 100 chars):" -ForegroundColor Yellow
            $content = Get-Content $tokenPath -Raw
            Write-Host $content.Substring(0, [Math]::Min(100, $content.Length)) -ForegroundColor White
        } else {
            Write-Host "❌ Token file not found (not authenticated)" -ForegroundColor Red
            Write-Host "Run option 1 to authenticate" -ForegroundColor Yellow
        }
    }
    
    default {
        Write-Host "Invalid choice. Please run the script again." -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "For more help, see VERCEL_TOKEN_FIX.md" -ForegroundColor Cyan
