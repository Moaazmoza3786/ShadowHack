<#
.SYNOPSIS
    Smart Launcher for ShadowHack Hybrid System
    Starts Backend, Tunnels to Cloudflare, and Updates Frontend Config Automatically.

.DESCRIPTION
    1. Checks for required tools (python, cloudflared).
    2. Starts the Flask Backend.
    3. Starts a temporary Cloudflare Tunnel.
    4. Captures the Tunnel URL.
    5. Updates public/config.json with the new URL.
    6. Keeps the session alive.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$BackendDir = Join-Path $ScriptDir "backend"
$FrontendConfigPath = Join-Path $ScriptDir "study-hub-react\public\config.json"

Write-Host "🚀 Starting ShadowHack Smart Launcher..." -ForegroundColor Cyan

# 1. Check Prerequisites and Setup Cloudflared
$CloudflaredPath = "cloudflared"
if (Test-Path "$ScriptDir\cloudflared.exe") {
    $CloudflaredPath = "$ScriptDir\cloudflared.exe"
    Write-Host "✅ Found local cloudflared.exe" -ForegroundColor Green
}
elseif (-not (Get-Command "cloudflared" -ErrorAction SilentlyContinue)) {
    Write-Error "Cloudflared not found! Please ensure 'cloudflared.exe' is in the folder."
    exit 1
}

# 2. Start Backend
Write-Host "📦 Starting Flask Backend..." -ForegroundColor Yellow
$BackendProcess = Start-Process -FilePath "python" -ArgumentList "main.py" -WorkingDirectory $BackendDir -PassThru -NoNewWindow
Start-Sleep -Seconds 5

if ($BackendProcess.HasExited) {
    Write-Error "Backend failed to start!"
    exit 1
}

# 3. Start Tunnel
Write-Host "🌐 Starting Cloudflare Tunnel..." -ForegroundColor Yellow
$TunnelProcess = Start-Process -FilePath $CloudflaredPath -ArgumentList "tunnel --url http://localhost:5000" -PassThru -NoNewWindow -RedirectStandardError "tunnel.log"

Write-Host "⏳ Waiting for Tunnel URL..." -ForegroundColor Gray

# 4. Extract URL
$TunnelUrl = $null
$Timeout = 30
$Counter = 0

while (-not $TunnelUrl -and $Counter -lt $Timeout) {
    Start-Sleep -Seconds 1
    $LogPath = Join-Path $ScriptDir "tunnel.log"
    if (Test-Path $LogPath) {
        $Lines = Get-Content $LogPath -ErrorAction SilentlyContinue
        foreach ($Line in $Lines) {
            if ($Line -match "(https://[a-zA-Z0-9-]+\.trycloudflare\.com)") {
                $TunnelUrl = $matches[1]
                break
            }
        }
    }
    if (-not $TunnelUrl) {
        Write-Host "   ... still searching in logs ($Counter/30)" -ForegroundColor Gray
    }
    $Counter++
}

if (-not $TunnelUrl) {
    Write-Error "Failed to obtain Tunnel URL. Check tunnel.log."
    Stop-Process -Id $BackendProcess.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $TunnelProcess.Id -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "✅ Tunnel Established: $TunnelUrl" -ForegroundColor Green

# 5. Update Frontend Config
$Config = @{
    apiUrl = "$TunnelUrl/api"
} | ConvertTo-Json

Set-Content -Path $FrontendConfigPath -Value $Config
Write-Host "📝 Updated Frontend Config at $FrontendConfigPath" -ForegroundColor Green

Write-Host "`n🎉 System Ready! You can now access the Smart Hybrid System." -ForegroundColor Cyan
Write-Host "👉 Frontend URL: https://study-hub3-react-rho.vercel.app/" -ForegroundColor White
Write-Host "🛑 Press Ctrl+C to stop servers..." -ForegroundColor Red

# Keep script running
try {
    while ($true) {
        Start-Sleep -Seconds 1
        if ($BackendProcess.HasExited) { throw "Backend stopped unexpectedly" }
        if ($TunnelProcess.HasExited) { throw "Tunnel stopped unexpectedly" }
    }
}
finally {
    Write-Host "`nShutting down..." -ForegroundColor Yellow
    Stop-Process -Id $BackendProcess.Id -ErrorAction SilentlyContinue
    Stop-Process -Id $TunnelProcess.Id -ErrorAction SilentlyContinue
}
