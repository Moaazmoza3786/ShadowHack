/* ============================================================
   ATTACKBOX INTERFACE - BreachLabs
   In-browser virtual machine interface for hands-on practice
   ============================================================ */

const AttackBox = {
    isRunning: false,
    machineIp: null,
    timeRemaining: 0,
    timerInterval: null,
    connectionType: 'browser', // 'browser' or 'split-view'

    // AttackBox configuration
    config: {
        defaultDuration: 60 * 60, // 1 hour in seconds
        extendDuration: 30 * 60,  // 30 minutes extension
        maxExtensions: 2,
        currentExtensions: 0
    },

    // Initialize AttackBox
    init() {
        this.injectStyles();
    },

    // Inject CSS styles
    injectStyles() {
        if (document.getElementById('attackbox-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'attackbox-styles';
        styles.textContent = `
            /* AttackBox Panel */
            .attackbox-panel {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border-radius: 16px;
                padding: 24px;
                margin: 16px 0;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(102, 126, 234, 0.2);
            }

            .attackbox-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }

            .attackbox-title {
                display: flex;
                align-items: center;
                gap: 12px;
                color: #fff;
                font-size: 1.25rem;
                font-weight: 600;
            }

            .attackbox-title i {
                color: #22c55e;
                font-size: 1.5rem;
            }

            .attackbox-badge {
                background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            /* Machine Card */
            .attackbox-machine {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 16px;
            }

            .machine-info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 16px;
                margin-bottom: 16px;
            }

            .machine-info-item {
                text-align: center;
            }

            .machine-info-label {
                color: #94a3b8;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 4px;
            }

            .machine-info-value {
                color: #fff;
                font-size: 1.1rem;
                font-weight: 600;
            }

            .machine-info-value.ip-address {
                font-family: 'JetBrains Mono', monospace;
                color: #22c55e;
                font-size: 1.25rem;
            }

            /* Timer */
            .attackbox-timer {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 12px;
                background: rgba(34, 197, 94, 0.1);
                border: 1px solid rgba(34, 197, 94, 0.3);
                border-radius: 8px;
                margin-bottom: 16px;
            }

            .attackbox-timer.warning {
                background: rgba(245, 158, 11, 0.1);
                border-color: rgba(245, 158, 11, 0.3);
            }

            .attackbox-timer.critical {
                background: rgba(239, 68, 68, 0.1);
                border-color: rgba(239, 68, 68, 0.3);
                animation: pulse 1s infinite;
            }

            .timer-icon {
                font-size: 1.25rem;
            }

            .timer-text {
                color: #fff;
                font-family: 'JetBrains Mono', monospace;
                font-size: 1.5rem;
                font-weight: 600;
            }

            /* Buttons */
            .attackbox-actions {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }

            .attackbox-btn {
                flex: 1;
                min-width: 140px;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 0.9rem;
                font-weight: 600;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                transition: all 0.3s ease;
            }

            .attackbox-btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }

            .attackbox-btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
            }

            .attackbox-btn-success {
                background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
                color: white;
            }

            .attackbox-btn-danger {
                background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                color: white;
            }

            .attackbox-btn-outline {
                background: transparent;
                border: 2px solid #667eea;
                color: #667eea;
            }

            .attackbox-btn-outline:hover {
                background: rgba(102, 126, 234, 0.1);
            }

            .attackbox-btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none !important;
            }

            /* Terminal Preview */
            .terminal-preview {
                background: #0d1117;
                border-radius: 8px;
                padding: 16px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.875rem;
                color: #22c55e;
                margin-top: 16px;
                max-height: 200px;
                overflow-y: auto;
            }

            .terminal-prompt {
                color: #f59e0b;
            }

            /* Connection Options */
            .connection-options {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-top: 16px;
            }

            .connection-option {
                background: rgba(255, 255, 255, 0.05);
                border: 2px solid transparent;
                border-radius: 12px;
                padding: 16px;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
            }

            .connection-option:hover {
                border-color: rgba(102, 126, 234, 0.3);
            }

            .connection-option.selected {
                border-color: #667eea;
                background: rgba(102, 126, 234, 0.1);
            }

            .connection-option i {
                font-size: 2rem;
                color: #667eea;
                margin-bottom: 8px;
            }

            .connection-option-title {
                color: #fff;
                font-weight: 600;
                margin-bottom: 4px;
            }

            .connection-option-desc {
                color: #94a3b8;
                font-size: 0.75rem;
            }

            /* Split View */
            .attackbox-split-view {
                display: flex;
                height: calc(100vh - 200px);
                min-height: 500px;
                border-radius: 12px;
                overflow: hidden;
                border: 1px solid rgba(102, 126, 234, 0.2);
            }

            .split-left {
                flex: 1;
                overflow-y: auto;
                background: #fff;
                padding: 20px;
            }

            .split-right {
                flex: 1;
                background: #1a1a2e;
                display: flex;
                flex-direction: column;
            }

            .split-resize-handle {
                width: 8px;
                background: #2d3748;
                cursor: col-resize;
                transition: background 0.2s;
            }

            .split-resize-handle:hover {
                background: #667eea;
            }

            /* VNC Container */
            .vnc-container {
                flex: 1;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #000;
            }

            .vnc-placeholder {
                text-align: center;
                color: #94a3b8;
            }

            .vnc-placeholder i {
                font-size: 4rem;
                margin-bottom: 16px;
                color: #667eea;
            }

            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }

            /* Loading State */
            .attackbox-loading {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 40px;
                color: #fff;
            }

            .loading-spinner {
                width: 50px;
                height: 50px;
                border: 4px solid rgba(102, 126, 234, 0.2);
                border-top-color: #667eea;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-bottom: 16px;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(styles);
    },

    // Render AttackBox panel
    renderPanel(containerId = 'attackbox-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = `
            <div class="attackbox-panel">
                <div class="attackbox-header">
                    <div class="attackbox-title">
                        <i class="fa-solid fa-terminal"></i>
                        AttackBox
                    </div>
                    <span class="attackbox-badge">
                        ${this.isRunning ? 'Running' : 'Ready'}
                    </span>
                </div>

                ${this.isRunning ? this.renderRunningState() : this.renderIdleState()}
            </div>
        `;
    },

    // Render idle state
    renderIdleState() {
        return `
            <div class="attackbox-machine">
                <h4 style="color: #fff; margin-bottom: 16px;">Start Your Hacking Environment</h4>
                <p style="color: #94a3b8; margin-bottom: 20px;">
                    Launch a pre-configured Kali Linux environment right in your browser. 
                    No VPN or VM setup required!
                </p>

                <div class="connection-options">
                    <div class="connection-option ${this.connectionType === 'browser' ? 'selected' : ''}" 
                         onclick="AttackBox.setConnectionType('browser')">
                        <i class="fa-solid fa-globe"></i>
                        <div class="connection-option-title">Browser View</div>
                        <div class="connection-option-desc">Full screen desktop in browser</div>
                    </div>
                    <div class="connection-option ${this.connectionType === 'split-view' ? 'selected' : ''}"
                         onclick="AttackBox.setConnectionType('split-view')">
                        <i class="fa-solid fa-table-columns"></i>
                        <div class="connection-option-title">Split View</div>
                        <div class="connection-option-desc">Tasks on left, terminal on right</div>
                    </div>
                </div>

                <div class="attackbox-actions" style="margin-top: 20px;">
                    <button class="attackbox-btn attackbox-btn-success" onclick="AttackBox.start()">
                        <i class="fa-solid fa-play"></i>
                        Start AttackBox
                    </button>
                </div>
            </div>

            <div style="color: #94a3b8; font-size: 0.875rem;">
                <i class="fa-solid fa-info-circle me-1"></i>
                Session duration: 1 hour (can be extended)
            </div>
        `;
    },

    // Render running state
    renderRunningState() {
        const timerClass = this.getTimerClass();
        const timeStr = this.formatTime(this.timeRemaining);

        return `
            <div class="attackbox-machine">
                <div class="machine-info-grid">
                    <div class="machine-info-item">
                        <div class="machine-info-label">IP Address</div>
                        <div class="machine-info-value ip-address">${this.machineIp}</div>
                    </div>
                    <div class="machine-info-item">
                        <div class="machine-info-label">Username</div>
                        <div class="machine-info-value">root</div>
                    </div>
                    <div class="machine-info-item">
                        <div class="machine-info-label">Password</div>
                        <div class="machine-info-value">toor</div>
                    </div>
                    <div class="machine-info-item">
                        <div class="machine-info-label">OS</div>
                        <div class="machine-info-value">Kali Linux</div>
                    </div>
                </div>

                <div class="attackbox-timer ${timerClass}" id="attackbox-timer">
                    <i class="fa-solid fa-clock timer-icon" style="color: ${this.getTimerColor()};"></i>
                    <span class="timer-text">${timeStr}</span>
                </div>

                <div class="attackbox-actions">
                    <button class="attackbox-btn attackbox-btn-primary" onclick="AttackBox.openDesktop()">
                        <i class="fa-solid fa-desktop"></i>
                        Open Desktop
                    </button>
                    <button class="attackbox-btn attackbox-btn-outline" onclick="AttackBox.extend()" 
                            ${this.config.currentExtensions >= this.config.maxExtensions ? 'disabled' : ''}>
                        <i class="fa-solid fa-plus"></i>
                        Extend +30min
                    </button>
                    <button class="attackbox-btn attackbox-btn-danger" onclick="AttackBox.stop()">
                        <i class="fa-solid fa-stop"></i>
                        Terminate
                    </button>
                </div>
            </div>

            <div class="terminal-preview">
                <div><span class="terminal-prompt">root@attackbox:~#</span> Ready to attack!</div>
                <div><span class="terminal-prompt">root@attackbox:~#</span> Target IP from room above</div>
                <div><span class="terminal-prompt">root@attackbox:~#</span> Tools: nmap, gobuster, hydra, metasploit, burpsuite</div>
            </div>
        `;
    },

    // Set connection type
    setConnectionType(type) {
        this.connectionType = type;
        this.renderPanel();
    },

    // Start AttackBox
    async start() {
        const container = document.getElementById('attackbox-container');
        if (container) {
            container.innerHTML = `
                <div class="attackbox-panel">
                    <div class="attackbox-loading">
                        <div class="loading-spinner"></div>
                        <div style="font-size: 1.1rem; font-weight: 600;">Launching AttackBox...</div>
                        <div style="color: #94a3b8; margin-top: 8px;">This may take up to 30 seconds</div>
                    </div>
                </div>
            `;
        }

        // Simulate startup (in real implementation, this would call backend)
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Set running state
        this.isRunning = true;
        // Check for active room simulation
        if (window.roomViewer && window.roomViewer.machineIP) {
            this.machineIp = window.roomViewer.machineIP;
        } else {
            this.machineIp = this.generateIp();
        }
        this.timeRemaining = this.config.defaultDuration;
        this.config.currentExtensions = 0;

        // Start timer
        this.startTimer();

        // Render panel
        this.renderPanel();

        // Show notification
        if (typeof showToast === 'function') {
            showToast('🚀 AttackBox is ready!', 'success');
        }
    },

    // Stop AttackBox
    stop() {
        if (!confirm('Are you sure you want to terminate the AttackBox?')) return;

        this.isRunning = false;
        this.machineIp = null;
        this.timeRemaining = 0;

        if (this.timerInterval) {
            clearInterval(this.timerInterval);
            this.timerInterval = null;
        }

        this.renderPanel();

        if (typeof showToast === 'function') {
            showToast('AttackBox terminated', 'info');
        }
    },

    // Extend time
    extend() {
        if (this.config.currentExtensions >= this.config.maxExtensions) {
            if (typeof showToast === 'function') {
                showToast('Maximum extensions reached', 'warning');
            }
            return;
        }

        this.timeRemaining += this.config.extendDuration;
        this.config.currentExtensions++;

        this.renderPanel();

        if (typeof showToast === 'function') {
            showToast('+30 minutes added!', 'success');
        }
    },

    // Open Desktop / Terminal (Handles both Popup and Embedded)
    openDesktop() {
        // If embedded mode is active and running in split view, render inline
        if (this.connectionType === 'split-view') {
            const splitRight = document.querySelector('.split-right');
            if (splitRight) {
                // Clear existing
                splitRight.innerHTML = `<div id="embedded-terminal" style="height: 100%; width: 100%; background: #000;"></div>`;
                setTimeout(() => this.embedTerminal('embedded-terminal'), 100);
                return;
            }
        }

        // Fallback to Popup
        const win = window.open('', 'AttackBox', 'width=1200,height=800');
        win.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>AttackBox - Terminal</title>
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
                <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
                <style>
                    body, html { height: 100%; margin: 0; background: #000; overflow: hidden; }
                    #terminal { height: 100%; width: 100%; }
                </style>
            </head>
            <body>
                <div id="terminal"></div>
                <script>
                    ${this.getTerminalScript()}
                </script>
            </body>
            </html>
        `);
    },

    // Embed Terminal in a specific container ID
    embedTerminal(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Initialize xterm.js
        const term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Consolas, "Courier New", monospace',
            theme: { background: '#0d1117', foreground: '#22c55e' }
        });

        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(container);
        fitAddon.fit();

        // Handle resizing
        window.addEventListener('resize', () => fitAddon.fit());

        // Initial Message
        term.writeln('\\x1b[1;32mWelcome to AttackBox V2.0 (Embedded)\\x1b[0m');
        term.writeln(`Connected to ${this.machineIp}`);
        term.writeln('Type "help" for functionality.\\r\\n');

        let currLine = '';
        term.write('root@attackbox:~# ');

        term.onData(e => {
            switch (e) {
                case '\\r': // Enter
                    term.writeln('');
                    this.handleCommand(currLine, term);
                    currLine = '';
                    term.write('root@attackbox:~# ');
                    break;
                case '\\u007F': // Backspace
                    if (currLine.length > 0) {
                        currLine = currLine.substr(0, currLine.length - 1);
                        term.write('\\b \\b');
                    }
                    break;
                default:
                    currLine += e;
                    term.write(e);
            }
        });

        // Expose term for external use
        this.activeTerminal = term;
    },

    // Shared Command Handler
    handleCommand(cmd, term) {
        const args = cmd.trim().split(' ');
        switch (args[0]) {
            case 'help':
                term.writeln('Available commands: nmap, ping, help, clear');
                break;
            case 'clear':
                term.clear();
                break;
            case 'ping':
                term.writeln('PING ' + (args[1] || 'target') + ' (127.0.0.1): 56 data bytes');
                term.writeln('64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms');
                break;
            case 'nmap':
                term.writeln('Starting Nmap 7.92 ( https://nmap.org )');
                term.writeln('Nmap scan report for ' + (args[1] || 'target'));
                term.writeln('Host is up (0.0004s latency).');
                term.writeln('Not shown: 998 closed ports');
                term.writeln('PORT   STATE SERVICE');
                term.writeln('22/tcp open  ssh');
                term.writeln('80/tcp open  http');
                break;
            case '':
                break;
            default:
                term.writeln('bash: ' + args[0] + ': command not found');
                term.writeln('\x1b[1;36m[GRAVITY]: Would you like me to analyze this error? \x1b[0m');
                term.writeln('\x1b[1;36m[GRAVITY]: Click here: \x1b[4;36mhttps://antigravity.academy/ai-debug/' + args[0] + '\x1b[0m');
                // In a real implementation, we would hook a click handler to the terminal or use a separate UI button
                if (window.AISecurityAssistant) {
                    AISecurityAssistant.showDebugButton(args[0], term);
                }
        }
    },

    // Helper for popup script generation
    getTerminalScript() {
        return `
            const term = new Terminal({
                cursorBlink: true,
                fontSize: 14,
                fontFamily: 'Consolas, "Courier New", monospace',
                theme: { background: '#0d1117', foreground: '#22c55e' }
            });
            const fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(document.getElementById('terminal'));
            fitAddon.fit();
            
            window.onresize = () => fitAddon.fit();
            
            term.writeln('\\x1b[1;32mWelcome to AttackBox V2.0\\x1b[0m');
            term.writeln('Connected to ${this.machineIp}');
            term.writeln('Type "help" for functionality.\\r\\n');
            
            let currLine = '';
            term.write('root@attackbox:~# ');

            term.onData(e => {
                switch (e) {
                    case '\\r': // Enter
                        term.writeln('');
                        handleCommand(currLine);
                        currLine = '';
                        term.write('root@attackbox:~# ');
                        break;
                    case '\\u007F': // Backspace
                        if (currLine.length > 0) {
                            currLine = currLine.substr(0, currLine.length - 1);
                            term.write('\\b \\b');
                        }
                        break;
                    default:
                        currLine += e;
                        term.write(e);
                }
            });

            function handleCommand(cmd) {
                const args = cmd.trim().split(' ');
                switch(args[0]) {
                    case 'help':
                        term.writeln('Available commands: nmap, ping, help, clear, exit');
                        break;
                    case 'clear':
                        term.clear();
                        break;
                    case 'ping':
                        term.writeln('PING ' + (args[1] || 'target') + ' (127.0.0.1): 56 data bytes');
                        term.writeln('64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms');
                        break;
                    case 'nmap':
                        term.writeln('Starting Nmap 7.92 ( https://nmap.org )');
                        term.writeln('Nmap scan report for ' + (args[1] || 'target'));
                        term.writeln('Host is up (0.0004s latency).');
                        term.writeln('Not shown: 998 closed ports');
                        term.writeln('PORT   STATE SERVICE');
                        term.writeln('22/tcp open  ssh');
                        term.writeln('80/tcp open  http');
                        break;
                    case 'exit':
                        window.close();
                        break;
                    case '':
                        break;
                    default:
                        term.writeln('bash: ' + args[0] + ': command not found');
                }
            }
        `;
    },

    // Start countdown timer
    startTimer() {
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
        }

        this.timerInterval = setInterval(() => {
            this.timeRemaining--;

            if (this.timeRemaining <= 0) {
                this.stop();
                if (typeof showToast === 'function') {
                    showToast('⏰ AttackBox session expired', 'warning');
                }
                return;
            }

            // Update timer display
            const timerEl = document.getElementById('attackbox-timer');
            if (timerEl) {
                timerEl.className = `attackbox-timer ${this.getTimerClass()}`;
                const textEl = timerEl.querySelector('.timer-text');
                const iconEl = timerEl.querySelector('.timer-icon');
                if (textEl) textEl.textContent = this.formatTime(this.timeRemaining);
                if (iconEl) iconEl.style.color = this.getTimerColor();
            }

            // Warn user when time is low
            if (this.timeRemaining === 300) { // 5 minutes
                if (typeof showToast === 'function') {
                    showToast('⚠️ Only 5 minutes remaining!', 'warning');
                }
            }
        }, 1000);
    },

    // Format time as MM:SS
    formatTime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = seconds % 60;

        if (h > 0) {
            return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
        }
        return `${m}:${s.toString().padStart(2, '0')}`;
    },

    // Get timer CSS class based on time remaining
    getTimerClass() {
        if (this.timeRemaining <= 300) return 'critical'; // < 5 min
        if (this.timeRemaining <= 600) return 'warning';  // < 10 min
        return '';
    },

    // Get timer color
    getTimerColor() {
        if (this.timeRemaining <= 300) return '#ef4444';
        if (this.timeRemaining <= 600) return '#f59e0b';
        return '#22c55e';
    },

    // Generate random IP for simulation
    generateIp() {
        return `10.10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
    }
};

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    AttackBox.init();
});

// Export globally
window.AttackBox = AttackBox;
