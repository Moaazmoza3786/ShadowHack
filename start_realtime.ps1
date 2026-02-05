# Start the Real-time Leaderboard System

Write-Host "🚀 Starting Real-time Leaderboard Server..." -ForegroundColor Cyan

# Check if node_modules exists
if (!(Test-Path "realtime-leaderboard/node_modules")) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    Set-Location realtime-leaderboard
    npm install
    Set-Location ..
}

# Start the Node.js server
# Note: This runs in the foreground. Open a new terminal for the Flask backend.
Set-Location realtime-leaderboard
node index.js
