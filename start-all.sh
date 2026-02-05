#!/bin/bash
# ============================================================
# ShadowHack - Integrated Startup Kernel (Linux/Mac)
# Starts all components with zero-manual intervention
# ============================================================

echo ""
echo "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗"
echo "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║  ██║██╔══██╗██╔════╝██║ ██╔╝"
echo "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████║███████║██║     █████╔╝ "
echo "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██║██╔══██║██║     ██╔═██╗ "
echo "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║██║  ██║╚██████╗██║  ██╗"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝"
echo ""
echo "  [!] INITIALIZING SHADOWHACK V6 KERNEL..."
echo "  =========================================="
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if Python is installed
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    if command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo "[X] CRITICAL: Python not found!"
        exit 1
    fi
fi

# Cleanup old processes if any
if [ -f .pids ]; then
    echo "[*] Phase 1: Environment Sanitization..."
    while read p; do
        kill -9 $p 2>/dev/null
    done < .pids
    rm .pids
fi

# Dependency check
echo "[*] Phase 2: Dependency Synchronization..."
cd backend
$PYTHON_CMD -m pip install -r requirements.txt --quiet --no-input 2>/dev/null
cd ..

# Start Backend Flask Server
echo ""
echo "[*] Phase 3: Launching Neural Backend (Port 5000)..."
cd backend
$PYTHON_CMD app.py > /dev/null 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > ../.pids
cd ..
sleep 3

# Start AI Middleware
echo "[*] Phase 3.5: Launching AI Middleware (Port 5005)..."
cd ai-middleware
# Install dependencies if node_modules missing
if [ ! -d "node_modules" ]; then
    echo "    [!] First run detected. Installing middleware dependencies..."
    npm install --quiet --no-progress
fi
node server.js > /dev/null 2>&1 &
MIDDLEWARE_PID=$!
echo $MIDDLEWARE_PID >> ../.pids
cd ..
sleep 2

# Start Frontend Server
echo "[*] Phase 4: Launching Interface (Port 8080)..."
$PYTHON_CMD frontend_server.py > /dev/null 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID >> .pids
sleep 2

# Check if Docker is installed
echo "[*] Phase 5: Lab Engine Connectivity..."
if command -v docker &> /dev/null; then
    echo "    [OK] Docker detected. Hybrid labs enabled."
else
    echo "    [!] Docker absent. Switching to edge simulation mode."
fi

# Start Real-time Leaderboard Server
echo "[*] Phase 6: Syncing Real-time Neural Link (Port 3001)..."
(cd realtime-leaderboard && [ ! -d "node_modules" ] && npm install; node index.js) > /dev/null 2>&1 &
REALTIME_PID=$!
echo $REALTIME_PID >> .pids
sleep 2

echo ""
echo "============================================================"
echo "  SYNAPTIC LINK ESTABLISHED"
echo "============================================================"
echo ""
echo " INTERFACE: http://localhost:8080"
echo " NEURAL:    http://localhost:5000"
echo ""

# Open browser
echo "[*] Igniting browser..."
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:8080" 2>/dev/null
elif command -v open &> /dev/null; then
    open "http://localhost:8080" 2>/dev/null
fi

echo ""
echo "[*] Deployment Complete."
echo "[NOTE] Platform is running in the background."
echo "[NOTE] To stop all services, run: kill \$(cat .pids)"
echo ""
exit 0
