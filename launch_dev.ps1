# ============================================================
#  ShadowHack - Local Development Launcher
#  Starts Flask backend (SQLite) + React frontend (Vite)
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = $PSScriptRoot

Write-Host ""
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host "   SHADOWHACK DEV LAUNCHER" -ForegroundColor Cyan
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Read secrets from backend/.env ────────────────────────
$EnvFile = Join-Path $ScriptDir "backend\.env"
$EnvLines = Get-Content $EnvFile -ErrorAction SilentlyContinue

function Get-EnvValue($lines, $key)
{
    $line = $lines | Where-Object { $_ -match "^$key=(.+)" } | Select-Object -First 1
    if ($line -match "^$key=(.+)")
    { return $Matches[1].Trim()
    }
    return ""
}

$SecretKey = Get-EnvValue $EnvLines "SECRET_KEY"
$JwtSecret = Get-EnvValue $EnvLines "JWT_SECRET"

if (-not $SecretKey -or $SecretKey -like "change-me*")
{
    Write-Host "  [!] Generating new SECRET_KEY..." -ForegroundColor Yellow
    $SecretKey = -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Max 256) })
}
if (-not $JwtSecret -or $JwtSecret -like "change-me*")
{
    Write-Host "  [!] Generating new JWT_SECRET..." -ForegroundColor Yellow
    $JwtSecret = -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Max 256) })
}

Write-Host "  [OK] Secrets loaded." -ForegroundColor Green

# ── 2. Kill any old processes on ports 5000 & 3000 ───────────
Write-Host "  [*] Clearing ports 5000 and 3000..." -ForegroundColor Gray
$ports = @(5000, 3000)
foreach ($port in $ports)
{
    $pids = (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).OwningProcess | Sort-Object -Unique
    foreach ($pid in $pids)
    {
        if ($pid -gt 0)
        {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    }
}
Start-Sleep -Seconds 1
Write-Host "  [OK] Ports cleared." -ForegroundColor Green

# ── 3. Build environment block for backend ────────────────────
$BackendEnv = [System.Collections.Generic.Dictionary[string,string]]::new()
$BackendEnv["SECRET_KEY"]             = $SecretKey
$BackendEnv["JWT_SECRET"]             = $JwtSecret
$BackendEnv["FLASK_ENV"]              = "development"
$BackendEnv["FLASK_DEBUG"]            = "true"
$BackendEnv["DATABASE_URL"]           = ""          # force SQLite
$BackendEnv["PLATFORM_ACCESS_CODE"]   = "shadowhackmz.mrx"
$BackendEnv["SQL_DEBUG"]              = "false"
$BackendEnv["CORS_ORIGINS"]           = "http://localhost:3000,http://127.0.0.1:3000"
$BackendEnv["RATELIMIT_STORAGE_URI"]  = "memory://"

# Build env var string for cmd /c set ... && python main.py
$EnvSetStr = ($BackendEnv.GetEnumerator() | ForEach-Object { "set `"$($_.Key)=$($_.Value)`"" }) -join " && "

# ── 4. Start Flask backend ────────────────────────────────────
Write-Host ""
Write-Host "  [*] Starting Flask backend on http://localhost:5000 ..." -ForegroundColor Yellow

$BackendDir = Join-Path $ScriptDir "backend"
$PythonExe  = Join-Path $ScriptDir "backend\venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe))
{
    $PythonExe = "python"
    Write-Host "  [!] venv not found, using system python." -ForegroundColor Yellow
}

$BackendCmd = "$EnvSetStr && `"$PythonExe`" run_dev.py"

$BackendProc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c $EnvSetStr && `"$PythonExe`" run_dev.py" `
    -WorkingDirectory $BackendDir `
    -RedirectStandardOutput (Join-Path $ScriptDir "backend_out.log") `
    -RedirectStandardError  (Join-Path $ScriptDir "backend_err.log") `
    -WindowStyle Hidden `
    -PassThru

Write-Host "  [OK] Backend started (PID $($BackendProc.Id))" -ForegroundColor Green

# ── 5. Wait for backend to be ready ──────────────────────────
Write-Host "  [*] Waiting for backend to be ready..." -ForegroundColor Gray
$ready = $false
for ($i = 0; $i -lt 20; $i++)
{
    Start-Sleep -Seconds 1
    try
    {
        $resp = Invoke-WebRequest -Uri "http://localhost:5000/" -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200)
        { $ready = $true; break
        }
    } catch
    {
    }
    Write-Host "  ... ($($i+1)/20)" -ForegroundColor DarkGray
}

if ($ready)
{
    Write-Host "  [OK] Backend is up!" -ForegroundColor Green
} else
{
    Write-Host "  [!] Backend did not respond in time. Check backend_err.log" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Last backend error output:" -ForegroundColor Red
    Get-Content (Join-Path $ScriptDir "backend_err.log") -Tail 20 -ErrorAction SilentlyContinue
}

# ── 6. Start React/Vite frontend ─────────────────────────────
Write-Host ""
Write-Host "  [*] Starting React frontend on http://localhost:3000 ..." -ForegroundColor Yellow

$FrontendDir = Join-Path $ScriptDir "study-hub-react"
$NpmCmd      = "npm run dev"

$FrontendProc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c $NpmCmd" `
    -WorkingDirectory $FrontendDir `
    -RedirectStandardOutput (Join-Path $ScriptDir "frontend_out.log") `
    -RedirectStandardError  (Join-Path $ScriptDir "frontend_err.log") `
    -WindowStyle Hidden `
    -PassThru

Write-Host "  [OK] Frontend started (PID $($FrontendProc.Id))" -ForegroundColor Green

# ── 7. Wait for Vite dev server ───────────────────────────────
Write-Host "  [*] Waiting for Vite dev server..." -ForegroundColor Gray
$frontendReady = $false
for ($i = 0; $i -lt 30; $i++)
{
    Start-Sleep -Seconds 1
    try
    {
        $resp = Invoke-WebRequest -Uri "http://localhost:3000/" -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -lt 500)
        { $frontendReady = $true; break
        }
    } catch
    {
    }
    Write-Host "  ... ($($i+1)/30)" -ForegroundColor DarkGray
}

if ($frontendReady)
{
    Write-Host "  [OK] Frontend is up!" -ForegroundColor Green
} else
{
    Write-Host "  [!] Frontend did not respond. Check frontend_err.log" -ForegroundColor Red
}

# ── 8. Summary ────────────────────────────────────────────────
Write-Host ""
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host "   SHADOWHACK IS RUNNING" -ForegroundColor Cyan
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Frontend : http://localhost:3000" -ForegroundColor White
Write-Host "   Backend  : http://localhost:5000" -ForegroundColor White
Write-Host "   API Docs : http://localhost:5000/" -ForegroundColor White
Write-Host ""
Write-Host "   Access Code : shadowhackmz.mrx" -ForegroundColor Yellow
Write-Host "   Database    : SQLite (local, backend/studyhub.db)" -ForegroundColor Gray
Write-Host "   Docker Labs : SIMULATION MODE" -ForegroundColor Gray
Write-Host ""
Write-Host "   Logs:" -ForegroundColor Gray
Write-Host "     backend_out.log  backend_err.log" -ForegroundColor DarkGray
Write-Host "     frontend_out.log frontend_err.log" -ForegroundColor DarkGray
Write-Host ""

# ── 9. Open browser ───────────────────────────────────────────
if ($frontendReady)
{
    Write-Host "  [*] Opening browser..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000"
}

# ── 10. Keep alive & show live backend log tail ───────────────
Write-Host "  [*] Press Ctrl+C to stop all servers." -ForegroundColor Red
Write-Host ""

try
{
    while ($true)
    {
        Start-Sleep -Seconds 5

        # Restart backend if it crashed
        if ($BackendProc.HasExited)
        {
            Write-Host "  [!!] Backend crashed! Restarting..." -ForegroundColor Red
            $BackendProc = Start-Process -FilePath "cmd.exe" `
                -ArgumentList "/c $BackendCmd" `
                -WorkingDirectory $BackendDir `
                -RedirectStandardOutput (Join-Path $ScriptDir "backend_out.log") `
                -RedirectStandardError  (Join-Path $ScriptDir "backend_err.log") `
                -WindowStyle Hidden `
                -PassThru
            Write-Host "  [OK] Backend restarted (PID $($BackendProc.Id))" -ForegroundColor Green
        }

        # Restart frontend if it crashed
        if ($FrontendProc.HasExited)
        {
            Write-Host "  [!!] Frontend crashed! Restarting..." -ForegroundColor Red
            $FrontendProc = Start-Process -FilePath "cmd.exe" `
                -ArgumentList "/c $NpmCmd" `
                -WorkingDirectory $FrontendDir `
                -RedirectStandardOutput (Join-Path $ScriptDir "frontend_out.log") `
                -RedirectStandardError  (Join-Path $ScriptDir "frontend_err.log") `
                -WindowStyle Hidden `
                -PassThru
            Write-Host "  [OK] Frontend restarted (PID $($FrontendProc.Id))" -ForegroundColor Green
        }
    }
} finally
{
    Write-Host ""
    Write-Host "  [*] Shutting down ShadowHack..." -ForegroundColor Yellow
    if (-not $BackendProc.HasExited)
    { Stop-Process -Id $BackendProc.Id  -Force -ErrorAction SilentlyContinue
    }
    if (-not $FrontendProc.HasExited)
    { Stop-Process -Id $FrontendProc.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK] All processes stopped. Goodbye." -ForegroundColor Green
}
