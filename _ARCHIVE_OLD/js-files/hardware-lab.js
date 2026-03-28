/* ==================== HARDWARE & IOT LAB 🔌 ==================== */

window.HardwareLab = {
    // --- STATE ---
    connectedPin: null,
    uartActive: false,
    baudRate: 9600,
    firmwareExtracted: false,

    // --- SIMULATION DATA ---
    signals: [], // Array for canvas

    // --- INIT ---
    init() {
        this.renderPCB();
        requestAnimationFrame(() => this.drawLogicAnalyzer());
    },

    // --- RENDER UI ---
    render() {
        setTimeout(() => this.init(), 100);
        return `
            <div class="hw-container fade-in">
                <div class="hw-header">
                    <h1><i class="fas fa-microchip"></i> Hardware Hacking Lab</h1>
                    <p>Probe pins, analyze logic, and root the IoT device via UART.</p>
                </div>

                <div class="hw-grid">
                    <!-- LEFT: PCB INSPECTOR -->
                    <div class="hw-panel pcb-panel">
                        <div class="panel-head">
                            <span>PCB Inspector (Target: SmartCamera V2)</span>
                            <span class="status-led" id="board-led"></span>
                        </div>
                        <div class="pcb-viewport" id="pcb-view">
                            <!-- SVG PCB generated in JS -->
                        </div>
                        <div class="pcb-controls">
                            <button onclick="HardwareLab.probePin('GND')">Probe GND</button>
                            <button onclick="HardwareLab.probePin('VCC')">Probe VCC</button>
                            <button onclick="HardwareLab.probePin('TX')">Probe TX</button>
                            <button onclick="HardwareLab.probePin('RX')">Probe RX</button>
                        </div>
                    </div>

                    <!-- RIGHT: TOOLS -->
                    <div class="hw-tools">
                        <!-- LOGIC ANALYZER -->
                        <div class="hw-panel analyzer-panel">
                            <div class="panel-head">Logic Analyzer (Saleae Clone)</div>
                            <canvas id="logic-canvas" height="150"></canvas>
                            <div class="signal-info" id="signal-info">Status: Idle</div>
                        </div>

                        <!-- UART CONSOLE -->
                        <div class="hw-panel uart-panel">
                            <div class="panel-head">
                                <span>UART Serial Console</span>
                                <select id="baud-rate" onchange="HardwareLab.setBaud(this.value)">
                                    <option value="9600">9600</option>
                                    <option value="115200">115200</option>
                                    <option value="19200">19200</option>
                                </select>
                                <button class="btn-tiny" onclick="HardwareLab.connectSerial()">Connect</button>
                            </div>
                            <div class="uart-screen" id="uart-screen">
                                <span class="dim">Select correct Baud Rate and Connect TX/RX pins...</span>
                            </div>
                            <input type="text" class="uart-input" id="uart-input" placeholder="Enter command..." onkeydown="HardwareLab.handleUartInput(event)" disabled>
                        </div>
                    </div>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    // --- PCB LOGIC ---
    renderPCB() {
        const pcb = document.getElementById('pcb-view');
        if (!pcb) return;

        // Simple SVG for PCB
        pcb.innerHTML = `
            <svg width="100%" height="100%" viewBox="0 0 400 300">
                <!-- BOARD -->
                <rect x="20" y="20" width="360" height="260" rx="10" fill="#0b5e2a" stroke="#063b19" stroke-width="4"/>
                
                <!-- MOUNTING HOLES -->
                <circle cx="40" cy="40" r="8" fill="#d4aa70" stroke="#b8860b" stroke-width="2"/>
                <circle cx="360" cy="40" r="8" fill="#d4aa70" stroke="#b8860b" stroke-width="2"/>
                <circle cx="40" cy="260" r="8" fill="#d4aa70" stroke="#b8860b" stroke-width="2"/>
                <circle cx="360" cy="260" r="8" fill="#d4aa70" stroke="#b8860b" stroke-width="2"/>

                <!-- MAIN CHIP (SoC) -->
                <rect x="140" y="100" width="120" height="100" fill="#222" stroke="#444"/>
                <text x="200" y="150" fill="#888" font-family="monospace" font-size="12" text-anchor="middle">ARM CORTEX</text>
                <text x="200" y="165" fill="#666" font-family="monospace" font-size="10" text-anchor="middle">A7-SoC</text>

                <!-- FLASH CHIP -->
                <rect x="60" y="120" width="40" height="60" fill="#111" stroke="#333"/>
                <text x="80" y="155" fill="#aaa" font-size="8" text-anchor="middle">NAND</text>

                <!-- UART_HEADER PINS -->
                <g transform="translate(300, 180)">
                    <text x="0" y="-15" fill="#fff" font-size="10" font-weight="bold">UART</text>
                    <!-- VCC -->
                    <rect x="0" y="0" width="10" height="10" fill="#d4aa70" class="pin" onclick="HardwareLab.probePin('VCC')"/>
                    <text x="20" y="8" fill="#fff" font-size="10">VCC</text>
                    <!-- GND -->
                    <rect x="0" y="20" width="10" height="10" fill="#d4aa70" class="pin" onclick="HardwareLab.probePin('GND')"/>
                    <text x="20" y="28" fill="#fff" font-size="10">GND</text>
                    <!-- RX -->
                    <rect x="0" y="40" width="10" height="10" fill="#d4aa70" class="pin" onclick="HardwareLab.probePin('RX')"/>
                    <text x="20" y="48" fill="#fff" font-size="10">RX</text>
                    <!-- TX -->
                    <rect x="0" y="60" width="10" height="10" fill="#d4aa70" class="pin" onclick="HardwareLab.probePin('TX')"/>
                    <text x="20" y="68" fill="#fff" font-size="10">TX</text>
                </g>

                <!-- TRACES -->
                <path d="M 140 120 L 100 120" stroke="#1a8c44" stroke-width="2" fill="none"/>
                <path d="M 140 140 L 100 140" stroke="#1a8c44" stroke-width="2" fill="none"/>
                <path d="M 260 160 L 300 220 L 300 240" stroke="#1a8c44" stroke-width="2" fill="none"/>
            </svg>
        `;
    },

    // --- PROBING & ANALYZER ---
    probePin(pin) {
        this.connectedPin = pin;
        document.getElementById('signal-info').innerText = `Probing: ${pin}`;

        // Update Signal Data for Canvas
        if (pin === 'TX' || pin === 'RX') {
            this.signals = this.generateUartSignal();
        } else if (pin === 'VCC') {
            this.signals = new Array(100).fill(1); // High
        } else {
            this.signals = new Array(100).fill(0); // Low
        }
    },

    generateUartSignal() {
        // Create square wave
        const arr = [];
        for (let i = 0; i < 100; i++) {
            if (i % 10 < 5) arr.push(1); else arr.push(0);
            // Add some jitter
            if (Math.random() > 0.9) arr.push(Math.random() > 0.5 ? 1 : 0);
        }
        return arr;
    },

    drawLogicAnalyzer() {
        const cvs = document.getElementById('logic-canvas');
        if (!cvs) return; // Exit if page changed
        const ctx = cvs.getContext('2d');
        const w = cvs.width = cvs.parentElement.offsetWidth;
        const h = cvs.height;

        ctx.fillStyle = '#111';
        ctx.fillRect(0, 0, w, h);

        // Grid
        ctx.strokeStyle = '#222';
        ctx.lineWidth = 1;
        for (let x = 0; x < w; x += 20) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }

        // DRAW SIGNAL
        if (this.signals.length > 0) {
            ctx.strokeStyle = '#00ffcc';
            ctx.lineWidth = 2;
            ctx.beginPath();

            const step = w / this.signals.length;
            let x = 0;
            const highY = h * 0.2;
            const lowY = h * 0.8;

            ctx.moveTo(0, this.signals[0] ? highY : lowY);

            for (let i = 1; i < this.signals.length; i++) {
                const val = this.signals[i];
                const prev = this.signals[i - 1];

                // If value changed, draw vertical line
                if (val !== prev) {
                    ctx.lineTo(x, val ? highY : lowY);
                }
                x += step;
                ctx.lineTo(x, val ? highY : lowY);
            }
            ctx.stroke();

            // Scrolling effect
            this.signals.push(this.signals.shift());
        }

        requestAnimationFrame(() => this.drawLogicAnalyzer());
    },

    // --- UART CONSOLE ---
    setBaud(rate) {
        this.baudRate = parseInt(rate);
        this.updateConsoleLog(`Baud rate set to ${rate}`);
    },

    connectSerial() {
        if (!this.connectedPin || (this.connectedPin !== 'TX' && this.connectedPin !== 'RX')) {
            this.updateConsoleLog("[ERROR] No valid probe on TX/RX line.");
            return;
        }

        if (this.baudRate !== 115200) {
            this.updateConsoleLog("[ERROR] Garbage data received... ðŸ½¿ðŸ±...");
            return;
        }

        this.uartActive = true;
        document.getElementById('uart-input').disabled = false;
        this.updateConsoleLog("[SUCCESS] Serial Connected. 115200 8-N-1");

        setTimeout(() => {
            this.updateConsoleLog("");
            this.updateConsoleLog("U-Boot 2024.01-g83 (Jan 01 2025 - 12:00:00)");
            this.updateConsoleLog("Board: SmartCam V2");
            this.updateConsoleLog("");
            this.updateConsoleLog("Hit any key to stop autoboot: 0");
            setTimeout(() => this.updateConsoleLog("Loading Kernel... OK"), 1000);
            setTimeout(() => this.updateConsoleLog("Welcome to BusyBox v1.35.0"), 2000);
            setTimeout(() => this.updateConsoleLog("cam-v2 login: admin"), 3000);
            setTimeout(() => {
                this.updateConsoleLog("#");
                this.updateConsoleLog("# Root Shell Access Granted.");
            }, 3500);
        }, 500);
    },

    handleUartInput(e) {
        if (e.key === 'Enter') {
            const cmd = e.target.value;
            this.updateConsoleLog(`# ${cmd}`);
            this.processCommand(cmd);
            e.target.value = '';
        }
    },

    processCommand(cmd) {
        if (cmd === 'ls') {
            this.updateConsoleLog("bin  dev  etc  home  lib  proc  sys  tmp  usr  var");
        } else if (cmd === 'cat /etc/shadow') {
            this.updateConsoleLog("root:$1$O3J3...:0:0:99999:7:::");
            this.updateConsoleLog("admin:$1$9aK1...:0:0:99999:7:::");
        } else if (cmd === 'whoami') {
            this.updateConsoleLog("root");
        } else {
            this.updateConsoleLog(`sh: ${cmd}: command not found`);
        }
    },

    updateConsoleLog(text) {
        const screen = document.getElementById('uart-screen');
        if (screen) {
            const line = document.createElement('div');
            line.innerText = text;
            screen.appendChild(line);
            screen.scrollTop = screen.scrollHeight;
        }
    },

    getStyles() {
        return `
        <style>
            .hw-container { padding: 30px; height: calc(100vh - 80px); display: flex; flex-direction: column; color: #fff;  }
            .hw-header { margin-bottom: 20px; }
            .hw-header h1 { color: #00ffcc; font-size: 2rem; margin: 0; }
            
            .hw-grid { display: flex; gap: 20px; flex: 1; min-height: 0; }
            .hw-panel { background: #1a1a2e; border: 1px solid #333; border-radius: 8px; overflow: hidden; display: flex; flex-direction: column; }
            
            .pcb-panel { flex: 2; position: relative; }
            .hw-tools { flex: 1; display: flex; flex-direction: column; gap: 20px; }
            .analyzer-panel { height: 200px; }
            .uart-panel { flex: 1; }

            .panel-head { background: #111; padding: 10px; border-bottom: 1px solid #333; font-size: 0.9rem; font-weight: bold; color: #aaa; display: flex; justify-content: space-between; align-items: center; }
            
            .pcb-viewport { flex: 1; background: #050505; cursor: crosshair; }
            .pcb-controls { padding: 10px; display: flex; gap: 10px; background: #111; justify-content: center; }
            .pcb-controls button { background: #222; border: 1px solid #444; color: #fff; padding: 5px 15px; cursor: pointer; border-radius: 4px; }
            .pcb-controls button:hover { background: #333; border-color: #00ffcc; color: #00ffcc; }

            .pin { cursor: pointer; opacity: 0.5; transition: 0.2s; }
            .pin:hover { opacity: 1; fill: #00ffcc; }
            
            canvas { width: 100%; display: block; background: #000; }
            .signal-info { padding: 5px 10px; background: #000; color: #00ffcc; font-size: 0.8rem; border-top: 1px solid #333; font-family: monospace; }
            
            .uart-screen { flex: 1; background: #000; color: #0f0; padding: 10px; font-family: 'Consolas', monospace; font-size: 0.9rem; overflow-y: auto; }
            .uart-input { background: #111; border: none; color: #fff; padding: 10px; border-top: 1px solid #333; outline: none; font-family: 'Consolas', monospace; }
            .uart-input:disabled { cursor: not-allowed; opacity: 0.5; }

            .btn-tiny { font-size: 0.7rem; padding: 2px 8px; margin-left:10px; background: #00ffcc; color: #000; border: none; cursor: pointer; }

            .fade-in { animation: fadeIn 0.5s ease; }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        </style>
        `;
    }
};

function pageHardwareLab() {
    return HardwareLab.render();
}
