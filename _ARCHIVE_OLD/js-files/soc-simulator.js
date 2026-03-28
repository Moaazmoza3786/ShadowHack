/* ============================================================
   DEFENSE GRID: SOC SIMULATOR v3.0 (AI ENHANCED)
   ShadowHack Platform - Professional Blue Team Operations
   Now with DETERMINISTIC AI SENTINEL LOGIC.
   ============================================================ */

/* --- AI SENTINEL ENGINE --- */
class AISentinel {
    constructor(engine) {
        this.engine = engine;
        this.analyzing = false;
    }

    async analyzeIncident(ticketId) {
        this.analyzing = true;
        const ticket = this.engine.tickets.tickets.find(t => t.id === ticketId);
        if (!ticket) return null;

        // Heuristic Logic based on Ticket Attributes & Correct Actions
        // In this sim, we know the correct action from the ticket data.
        // A real AI would deduce this, but here we simulate the "Expert System".

        const correctAction = ticket.actions.find(a => a.correct);
        const malwareFamily = ticket.title.includes('Ransomware') ? 'Criminal Ransomware' :
            ticket.title.includes('SSH') ? 'Brute Force Botnet' :
                'Unknown Threat Actor';

        return {
            confidence: 95 + Math.floor(Math.random() * 4), // High confidence because it's rule-based
            analysis: `SENTINEL Heuristics detected pattern matching <strong>${malwareFamily}</strong>. Source IP ${ticket.src_ip} has highvelocity traffic matching known signatures.`,
            recommendation: correctAction.label,
            rootCause: ticket.desc
        };
    }
}

/* --- AUDIO ENGINE --- */
class SOSAudio {
    constructor() {
        this.ctx = null;
        this.enabled = false;
    }
    init() {
        if (!this.ctx) {
            this.ctx = new (window.AudioContext || window.webkitAudioContext)();
            this.enabled = true;
        }
    }
    play(freq, type, dur, vol = 0.05) {
        if (!this.enabled) return;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
        gain.gain.setValueAtTime(vol, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + dur);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + dur);
    }
    sfxAlert() { this.play(800, 'square', 0.1, 0.1); setTimeout(() => this.play(600, 'square', 0.2, 0.1), 100); }
    sfxType() { this.play(300 + Math.random() * 100, 'triangle', 0.03, 0.02); }
    sfxSuccess() { this.play(600, 'sine', 0.1); setTimeout(() => this.play(900, 'sine', 0.3), 100); }
    sfxFail() { this.play(200, 'sawtooth', 0.5, 0.1); }
}

/* --- VISUALS (MAP & CHARTS) --- */
class SOSVisuals {
    constructor() {
        this.mapCanvas = null;
        this.mapCtx = null;
        this.nodes = [];
    }

    initMap(id) {
        this.mapCanvas = document.getElementById(id);
        if (this.mapCanvas) {
            this.mapCtx = this.mapCanvas.getContext('2d');
            this.resize();
            window.addEventListener('resize', () => this.resize());
            // Init Nodes
            for (let i = 0; i < 8; i++) {
                this.nodes.push({
                    x: 0.2 + Math.random() * 0.6,
                    y: 0.2 + Math.random() * 0.6,
                    status: 'safe', // safe, warn, crit
                    id: `SRV-0${i}`
                });
            }
        }
    }

    resize() {
        if (this.mapCanvas) {
            this.mapCanvas.width = this.mapCanvas.parentElement.clientWidth;
            this.mapCanvas.height = this.mapCanvas.parentElement.clientHeight;
        }
    }

    drawMap() {
        if (!this.mapCtx) return;
        const ctx = this.mapCtx;
        const w = this.mapCanvas.width;
        const h = this.mapCanvas.height;
        const time = Date.now() / 1000;

        // Clear with Fade for Trail Effect
        ctx.fillStyle = 'rgba(11, 11, 21, 0.3)';
        ctx.fillRect(0, 0, w, h);

        // Grid
        ctx.strokeStyle = '#1e293b';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let x = 0; x < w; x += 50) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
        for (let y = 0; y < h; y += 50) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
        ctx.stroke();

        // Nodes
        this.nodes.forEach(n => {
            const nx = n.x * w;
            const ny = n.y * h;

            // Connection to Hub
            ctx.strokeStyle = n.status === 'safe' ? '#334155' : (n.status === 'warn' ? '#f59e0b' : '#ef4444');
            ctx.lineWidth = n.status === 'crit' ? 2 : 1;
            ctx.beginPath();
            ctx.moveTo(w / 2, h / 2);
            ctx.lineTo(nx, ny);
            ctx.stroke();

            // Node Glow
            const color = n.status === 'crit' ? '#ef4444' : (n.status === 'warn' ? '#f59e0b' : '#38bdf8');

            // Pulse Ring
            if (n.status !== 'safe') {
                ctx.beginPath();
                ctx.arc(nx, ny, 15 + Math.sin(time * 5) * 5, 0, Math.PI * 2);
                ctx.strokeStyle = color;
                ctx.globalAlpha = 0.5;
                ctx.stroke();
                ctx.globalAlpha = 1;
            }

            // Core
            ctx.beginPath();
            ctx.arc(nx, ny, 6, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();

            // Label
            ctx.fillStyle = '#94a3b8';
            ctx.font = '12px "Share Tech Mono", monospace';
            ctx.fillText(n.id, nx + 12, ny + 4);
        });
    }
}

/* --- TICKET SYSTEM --- */
class TicketSystem {
    constructor(engine) {
        this.engine = engine;
        this.tickets = [];
        this.activeTicket = null;
    }

    createTicket(alert) {
        const id = 'INC-' + Math.floor(Math.random() * 9000 + 1000);
        const ticket = {
            id: id,
            title: alert.title,
            src_ip: alert.src_ip,
            host: alert.host,
            desc: alert.desc,
            status: 'OPEN',
            actions: alert.actions // [ { label: 'Isolate Host', correct: true }, ... ]
        };
        this.tickets.push(ticket);
        this.engine.audio.sfxAlert();
        this.updateUI();
        this.engine.log('TICKET', `New Incident Created: ${id} - ${ticket.title}`);
    }

    resolveTicket(id, actionIdx) {
        const ticket = this.tickets.find(t => t.id === id);
        if (!ticket || ticket.status !== 'OPEN') return;

        const action = ticket.actions[actionIdx];
        if (action.correct) {
            ticket.status = 'RESOLVED';
            this.engine.panic = Math.max(0, this.engine.panic - 15);
            this.engine.log('RESOLVE', `Ticket ${id} Closed. Action: ${action.label} [SUCCESS]`);
            this.engine.audio.sfxSuccess();
        } else {
            ticket.status = 'FAILED';
            this.engine.panic += 20;
            this.engine.log('FAIL', `Ticket ${id} FAILED. Action: ${action.label} [WRONG CALL]`);
            this.engine.audio.sfxFail();
        }
        this.activeTicket = null;
        this.updateUI();
    }

    updateUI() {
        const list = document.getElementById('soc-ticket-list');
        if (!list) return;

        list.innerHTML = this.tickets.map(t => `
            <div class="ticket-item ${t.status.toLowerCase()}" onclick="socOpenTicket('${t.id}')">
                <div class="t-head">
                    <span class="t-id">${t.id}</span>
                    <span class="t-badge ${t.status}">${t.status}</span>
                </div>
                <div class="t-title">${t.title}</div>
            </div>
        `).join('');

        if (this.activeTicket) {
            const detail = document.getElementById('soc-ticket-detail');
            const t = this.activeTicket;
            detail.innerHTML = `
                <div class="tk-header">
                    <h3>${t.id}: ${t.title}</h3>
                    <div class="tk-meta">HOST: ${t.host} | IP: ${t.src_ip}</div>
                </div>
                <div class="tk-desc">${t.desc}</div>
                
                <div id="ai-sentinel-box" style="display:none;" class="ai-box"></div>

                <div class="tk-actions-title">RESPONSE PLAYBOOK</div>
                <div class="tk-actions">
                    ${t.actions.map((act, idx) => `
                        <button class="tk-btn" onclick="socResolveTicket('${t.id}', ${idx})">${act.label}</button>
                    `).join('')}
                    <button class="tk-btn ai-btn" onclick="socAskAI('${t.id}')"><i class="fa-solid fa-robot"></i> AI SENTINEL ANALYZE</button>
                </div>
            `;
        } else {
            document.getElementById('soc-ticket-detail').innerHTML = `<div class="no-select"><i class="fa-solid fa-radar"></i><br>SELECT AN INCIDENT TO TRIAGE</div>`;
        }
    }
}

/* --- SIEM ENGINE --- */
class SIEMEngine {
    constructor(engine) {
        this.engine = engine;
        this.logs = [];
        this.filter = '';
        this.paused = false;
    }

    addLog(log) {
        if (this.paused) return;
        const time = new Date().toISOString().split('T')[1].split('.')[0];
        this.logs.push({ ...log, time });
        if (this.logs.length > 200) this.logs.shift();
        this.render();
    }

    setFilter(str) {
        this.filter = str.toLowerCase();
        this.render();
    }

    render() {
        const tbody = document.getElementById('siem-body');
        if (!tbody) return;

        const visible = this.logs.filter(l => {
            if (!this.filter) return true;
            return JSON.stringify(l).toLowerCase().includes(this.filter);
        }).slice(-15); // Show last 15 filtered

        tbody.innerHTML = visible.map(l => `
            <tr class="log-row ${l.severity}">
                <td>${l.time}</td>
                <td>${l.event_id}</td>
                <td>${l.src_ip}</td>
                <td>${l.desc}</td>
            </tr>
        `).join('');
    }
}

/* --- MAIN DEFENSE ENGINE --- */
class DefenseEngine {
    constructor() {
        this.active = false;
        this.panic = 0; // 0-100%
        this.audio = new SOSAudio();
        this.visuals = new SOSVisuals();
        this.siem = new SIEMEngine(this);
        this.tickets = new TicketSystem(this);
        this.ai = new AISentinel(this);
        this.timer = null;
        this.simTick = 0;
    }

    start() {
        this.active = true;
        this.audio.init();
        this.visuals.initMap('soc-map-canvas');
        this.timer = setInterval(() => this.tick(), 1000);
        this.fastTimer = setInterval(() => this.fastTick(), 50);
        this.log('SYS', 'DEFENSE GRID ONLINE. SENTINEL AI ACTIVE.');
    }

    stop() {
        this.active = false;
        clearInterval(this.timer);
        clearInterval(this.fastTimer);
    }

    fastTick() {
        if (!this.active) return;
        this.visuals.drawMap();
    }

    tick() {
        if (!this.active) return;
        this.simTick++;

        // Noise Generation (Normal Traffic)
        this.generateNoise();

        // Attack Logic
        if (this.simTick % 10 === 0) { // Every 10 ticks, incident
            this.generateIncident();
        }

        // Panic Decay/Growth
        const openTkts = this.tickets.tickets.filter(t => t.status === 'OPEN').length;
        if (openTkts > 0) this.panic += 0.5 * openTkts;

        this.panic = Math.min(100, Math.max(0, this.panic));
        this.updateStats();

        if (this.panic >= 100) {
            this.log('CRITICAL', 'SYSTEM FAILURE. INFECTION RATE 100%. GAME OVER.');
            this.stop();
            alert('SYSTEM COMPROMISED. MISSION FAILED.');
        }
    }

    generateNoise() {
        // Random normal logs
        const events = [
            { id: 4624, desc: 'Successful Logon', sev: 'low' },
            { id: 3500, desc: 'Network Connection', sev: 'low' },
            { id: 80, desc: 'HTTP Request GET /', sev: 'low' }
        ];
        const evt = events[Math.floor(Math.random() * events.length)];
        this.siem.addLog({
            event_id: evt.id,
            src_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            desc: evt.desc,
            severity: evt.sev
        });
    }

    generateIncident() {
        const scenarios = [
            {
                title: 'Ransomware Beacon',
                ticket_desc: 'Internal Host SRV-02 attempting connections to known C2 IP. High IOPS detected.',
                siem_log: { event_id: 9999, src_ip: '192.168.1.55', desc: 'MALWARE DETECTED: WannaCry.exe', severity: 'high' },
                host: 'SRV-02',
                actions: [
                    { label: 'Isolate Host', correct: true },
                    { label: 'Update Firewall', correct: false },
                    { label: 'Ignore', correct: false }
                ]
            },
            {
                title: 'Brute Force SSH',
                ticket_desc: 'Multiple failed login attempts (500+) on Gateway-01.',
                siem_log: { event_id: 4625, src_ip: '45.33.22.11', desc: 'Failed Login (Root)', severity: 'medium' },
                host: 'GW-01',
                actions: [
                    { label: 'Block IP', correct: true },
                    { label: 'Reset Root Pass', correct: false },
                    { label: 'Shutdown Service', correct: false }
                ]
            }
        ];
        const scen = scenarios[Math.floor(Math.random() * scenarios.length)];
        this.siem.addLog(scen.siem_log);
        this.tickets.createTicket({
            title: scen.title,
            src_ip: scen.siem_log.src_ip,
            host: scen.host,
            desc: scen.ticket_desc,
            actions: scen.actions
        });
        const node = this.visuals.nodes.find(n => n.id === scen.host);
        if (node) node.status = 'crit';
    }

    log(src, msg) {
        console.log(`[${src}] ${msg}`);
    }

    updateStats() {
        const bar = document.getElementById('panic-bar');
        const val = document.getElementById('panic-val');
        if (bar) {
            bar.style.height = this.panic + '%';
            bar.style.backgroundColor = this.panic > 80 ? '#ef4444' : (this.panic > 50 ? '#f59e0b' : '#38bdf8');
            val.innerText = Math.floor(this.panic) + '%';
        }
    }
}

const defEngine = new DefenseEngine();

/* --- GLOBAL HANDLERS --- */
window.socOpenTicket = (id) => {
    const t = defEngine.tickets.tickets.find(x => x.id === id);
    if (t) {
        defEngine.tickets.activeTicket = t;
        defEngine.tickets.updateUI();
    }
};

window.socResolveTicket = (id, idx) => {
    defEngine.tickets.resolveTicket(id, idx);
};

window.socAskAI = async (id) => {
    const box = document.getElementById('ai-sentinel-box');
    box.style.display = 'block';
    box.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> SENTINEL Analyzing Telemetry...';

    // Simulate AI Work with Matrix effect
    setTimeout(async () => {
        const analysis = await defEngine.ai.analyzeIncident(id);
        if (analysis) {
            box.innerHTML = `
                <div style="border-left: 3px solid #6366f1; padding-left: 10px; animation: fadeIn 0.5s;">
                    <div style="font-weight:bold; color:#6366f1;">
                        <i class="fa-solid fa-brain"></i> SENTINEL v5.0 [Hypothesis Confirmed]
                    </div>
                    <div style="color:#cbd5e1; font-size:0.9rem; margin-top:5px;">${analysis.analysis}</div>
                    <div style="margin-top:8px;">
                        <span style="background:#1e1e2e; padding:3px 8px; border-radius:4px; font-size:0.8rem; border:1px solid #10b981; color: #10b981;">
                            <i class="fa-solid fa-check"></i> Recommended: ${analysis.recommendation}
                        </span>
                        <span style="float:right; color:#6366f1;">Conf: ${analysis.confidence}%</span>
                    </div>
                </div>
            `;
        }
    }, 1500);
};

/* --- PAGE UI --- */
function pageSOCSimulator() {
    setTimeout(() => defEngine.start(), 100);

    return `
    <div class="soc-v3-container">
        <!-- HEADER -->
        <div class="soc-header">
            <div class="brand"><i class="fa-solid fa-shield-halved"></i> SENTINEL<span class="highlight">GRID</span> // SOC DASHBOARD</div>
            <div class="soc-stats">
                <span><i class="fa-solid fa-user-astronaut"></i> OPERATOR: ACTIVE</span>
                <span><i class="fa-solid fa-wifi"></i> NET: SECURE</span>
            </div>
            <div class="panic-widget">
                <div class="p-label">THREAT LEVEL</div>
                <div class="p-meter-box">
                    <div id="panic-bar" style="height: 0%"></div>
                </div>
                <div id="panic-val">0%</div>
            </div>
        </div>

        <!-- MAIN LAYOUT -->
        <div class="soc-main">
            <!-- COL 1: SIEM -->
            <div class="panne-col col-siem">
                <div class="p-header">
                    <span><i class="fa-solid fa-list"></i> LIVE TELEMETRY</span>
                    <span style="font-size:0.7em; opacity:0.7;">ELK STACK v8.1</span>
                </div>
                <div class="siem-controls">
                    <input type="text" placeholder="QUERY: event_id=4625 AND severity=HIGH" onkeyup="defEngine.siem.setFilter(this.value)">
                </div>
                <div class="siem-table-wrap">
                    <table class="siem-table">
                        <thead><tr><th>TIME</th><th>ID</th><th>SRC_IP</th><th>EVENT</th></tr></thead>
                        <tbody id="siem-body"></tbody>
                    </table>
                </div>
            </div>

            <!-- COL 2: TICKETS -->
            <div class="panne-col col-tickets">
                <div class="p-header">
                    <span><i class="fa-solid fa-triangle-exclamation"></i> INCIDENTS</span>
                    <span style="font-size:0.7em; opacity:0.7;">JIRA INTEGRATION</span>
                </div>
                <div class="ticket-split">
                    <div class="ticket-list" id="soc-ticket-list"></div>
                    <div class="ticket-detail" id="soc-ticket-detail">
                        <div class="no-select"><i class="fa-solid fa-radar"></i><br>WAITING FOR ALERTS...</div>
                    </div>
                </div>
            </div>

            <!-- COL 3: MAP -->
            <div class="panne-col col-map">
                <div class="p-header"><i class="fa-solid fa-globe"></i> THREAT MAP</div>
                <div class="map-box"><canvas id="soc-map-canvas"></canvas></div>
                <div class="map-legend">
                    <div><span class="dot safe"></span> SECURE</div>
                    <div><span class="dot warn"></span> ANOMALY</div>
                    <div><span class="dot crit"></span> BREACH</div>
                </div>
            </div>
        </div>
        ${getSOCV3Styles()}
    </div>
    `;
}

function getSOCV3Styles() {
    return `
    <style>
        /* Modern SOC Palette: #0f172a (bg), #1e293b (panel), #38bdf8 (primary), #ef4444 (danger) */
        
        .soc-v3-container {
            height: 100vh; background: #0f172a; color: #e2e8f0;
            font-family: 'Inter', system-ui, sans-serif;
            display: flex; flex-direction: column; overflow: hidden;
        }
        
        /* HEADER */
        .soc-header {
            height: 64px; background: #1e293b; border-bottom: 1px solid #334155;
            display: flex; align-items: center; padding: 0 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
            z-index: 10;
        }
        .brand { font-size: 1.25rem; font-weight: 700; color: #fff; letter-spacing: 0.5px; flex: 1; }
        .highlight { color: #38bdf8; }
        .soc-stats span { margin-left: 24px; color: #94a3b8; font-size: 0.85rem; font-weight: 600; }
        
        .panic-widget { 
            display: flex; align-items: center; gap: 12px; margin-left: 40px; 
            background: #0f172a; padding: 6px 16px; border-radius: 99px; border: 1px solid #334155;
        }
        .p-label { font-size: 0.75rem; color: #ef4444; font-weight: 700; letter-spacing: 0.5px; }
        .p-meter-box { width: 8px; height: 24px; background: #334155; border-radius: 4px; overflow: hidden; display: flex; align-items: flex-end; }
        #panic-bar { width: 100%; background: #ef4444; transition: height 0.5s ease-out; border-radius: 4px; }
        #panic-val { color: #fff; font-weight: 700; width: 40px; text-align: right; font-family: 'JetBrains Mono', monospace; }

        /* MAIN LAYOUT */
        .soc-main { flex: 1; display: flex; padding: 16px; gap: 16px; min-height: 0; background: #0f172a; }
        .panne-col { 
            background: #1e293b; border: 1px solid #334155; border-radius: 12px; 
            display: flex; flex-direction: column; min-height: 0; overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }
        .col-siem { flex: 1.5; }
        .col-tickets { flex: 1.2; }
        .col-map { flex: 0.8; }
        
        .p-header { 
            background: #1e293b; color: #e2e8f0; padding: 12px 16px; 
            font-weight: 600; font-size: 0.85rem; border-bottom: 1px solid #334155; 
            display: flex; justify-content: space-between; align-items: center;
        }

        /* SIEM */
        .siem-controls { padding: 12px; border-bottom: 1px solid #334155; background: #1e293b; }
        .siem-controls input { 
            width: 100%; background: #0f172a; border: 1px solid #334155; color: #fff; 
            padding: 8px 12px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;
        }
        .siem-controls input:focus { outline: none; border-color: #38bdf8; }
        .siem-table-wrap { flex: 1; overflow-y: auto; }
        .siem-table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
        .siem-table th { position: sticky; top: 0; background: #1e293b; text-align: left; padding: 8px 12px; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }
        .siem-table td { padding: 6px 12px; border-bottom: 1px solid #334155; color: #cbd5e1; }
        .log-row.high { color: #fca5a5; background: rgba(239, 68, 68, 0.1); }
        .log-row.medium { color: #fcd34d; }

        /* TICKETS */
        .ticket-split { flex: 1; display: flex; flex-direction: column; min-height: 0; }
        .ticket-list { flex: 1; overflow-y: auto; border-bottom: 1px solid #334155; }
        .ticket-detail { height: 55%; padding: 20px; overflow-y: auto; background: #1e293b; }
        
        .ticket-item { padding: 12px 16px; border-bottom: 1px solid #334155; cursor: pointer; transition: 0.2s; background: #1e293b; }
        .ticket-item:hover { background: #334155; }
        .ticket-item.open { border-left: 3px solid #f59e0b; background: rgba(245, 158, 11, 0.05); }
        .ticket-item.resolved { border-left: 3px solid #10b981; opacity: 0.6; }
        .ticket-item.failed { border-left: 3px solid #ef4444; }
        /* Active ticket highlight */
        .ticket-item.open:active, .ticket-item.open:focus { background: rgba(56, 189, 248, 0.1); }
        
        .t-head { display: flex; justify-content: space-between; margin-bottom: 4px; }
        .t-id { font-weight: 700; color: #fff; font-size: 0.85rem; }
        .t-badge { font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; font-weight: 700; }
        .t-badge.OPEN { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
        .t-badge.RESOLVED { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .t-badge.FAILED { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .t-title { font-size: 0.9rem; color: #cbd5e1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        .tk-header h3 { margin: 0 0 8px 0; color: #fff; font-size: 1.1rem; }
        .tk-meta { font-size: 0.8rem; color: #94a3b8; margin-bottom: 20px; font-family: 'JetBrains Mono', monospace; }
        .tk-desc { margin-bottom: 24px; line-height: 1.6; font-size: 0.95rem; color: #e2e8f0; }
        .tk-actions-title { color: #38bdf8; font-weight: 700; margin-bottom: 12px; font-size: 0.75rem; letter-spacing: 1px; }
        .tk-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        .tk-btn { 
            background: #0f172a; border: 1px solid #334155; color: #e2e8f0; 
            padding: 8px 16px; cursor: pointer; font-family: inherit; transition: 0.2s; border-radius: 6px; font-size: 0.9rem;
        }
        .tk-btn:hover { background: #334155; border-color: #38bdf8; color: #fff; }
        .ai-btn { border-color: #6366f1; color: #818cf8; }
        .ai-btn:hover { background: #6366f1; color: #fff; }

        .ai-box { background: #0f172a; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 0.9rem; }

        /* MAP */
        .map-box { flex: 1; position: relative; background: #0f172a; }
        canvas { width: 100%; height: 100%; display: block; }
        .map-legend { padding: 12px; font-size: 0.75rem; color: #94a3b8; display: flex; gap: 15px; border-top: 1px solid #334155; background: #1e293b; }
        .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
        .dot.safe { background: #38bdf8; } .dot.warn { background: #f59e0b; } .dot.crit { background: #ef4444; }
        
        .no-select { text-align: center; color: #94a3b8; margin-top: 60px; font-size: 0.9rem; }
        .no-select i { font-size: 2rem; margin-bottom: 10px; opacity: 0.5; }
    </style>
    `;
}
