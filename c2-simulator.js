/* ============================================================
   RED TEAM C2 SIMULATOR v2.0 - GOD MODE
   Study Hub Platform - Advanced Adversary Operations
   ============================================================ */

/* --- AUDIO ENGINE --- */
class C2Audio {
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

    sfxType() { this.play(800 + Math.random() * 200, 'square', 0.05, 0.02); }
    sfxConnect() {
        this.play(1200, 'sawtooth', 0.1, 0.05);
        setTimeout(() => this.play(2400, 'sawtooth', 0.2, 0.05), 100);
    }
    sfxError() { this.play(150, 'sawtooth', 0.3, 0.1); }
    sfxSuccess() { this.play(600, 'sine', 0.1, 0.05); setTimeout(() => this.play(900, 'sine', 0.2, 0.05), 100); }
}

/* --- VIRTUAL FILE SYSTEM --- */
class C2FileSystem {
    constructor() {
        this.root = {
            'Users': {
                'Admin': {
                    'Documents': {
                        'passwords.txt': 'root:toor\nadmin:Hunter2!',
                        'financials.xlsx': '[ENCRYPTED DATA]',
                        'project_chimera.pdf': 'CONFIDENTIAL BLUEPRINTS'
                    },
                    'Downloads': { 'mimikatz.exe': '[BINARY]' }
                }
            },
            'Windows': { 'System32': { 'cmd.exe': '[BIN]', 'calc.exe': '[BIN]' } }
        };
        this.cwd = ['Users', 'Admin', 'Documents'];
    }

    resolve(path) {
        let current = this.root;
        this.cwd.forEach(dir => current = current[dir]);
        return current;
    }

    ls() {
        const dir = this.resolve();
        return Object.keys(dir).map(f => typeof dir[f] === 'object' ? `[DIR] ${f}` : `[FILE] ${f}`).join('\n');
    }

    cd(dir) {
        if (dir === '..') { if (this.cwd.length > 0) this.cwd.pop(); return; }
        const current = this.resolve();
        if (current[dir] && typeof current[dir] === 'object') this.cwd.push(dir);
        else return 'ERR: Directory not found.';
    }

    cat(file) {
        const dir = this.resolve();
        if (dir[file] && typeof dir[file] !== 'object') return dir[file];
        return 'ERR: File not found.';
    }
}

/* --- VISUAL ENGINE --- */
class C2Visuals {
    constructor() {
        this.canvas = null;
        this.ctx = null;
        this.particles = [];
    }

    init(id) {
        this.canvas = document.getElementById(id);
        if (this.canvas) {
            this.ctx = this.canvas.getContext('2d');
            this.resize();
            window.addEventListener('resize', () => this.resize());
            // Init Hex Grid Particles
            for (let i = 0; i < 40; i++) this.particles.push(this.createParticle());
        }
    }

    createParticle() {
        return {
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            size: Math.random() * 2 + 1,
            speed: Math.random() * 2 + 0.5,
            char: Math.random() > 0.5 ? '1' : '0'
        };
    }

    resize() {
        if (!this.canvas) return;
        this.canvas.width = this.canvas.parentElement.clientWidth;
        this.canvas.height = this.canvas.parentElement.clientHeight;
    }

    draw(beacons) {
        if (!this.ctx) return;
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;

        ctx.fillStyle = 'rgba(0, 0, 0, 0.1)';
        ctx.fillRect(0, 0, w, h);

        // Matrix Rain
        ctx.fillStyle = '#0f0';
        ctx.font = '12px monospace';
        this.particles.forEach(p => {
            ctx.fillText(p.char, p.x, p.y);
            p.y += p.speed;
            if (p.y > h) p.y = 0;
            if (Math.random() > 0.95) p.char = Math.random() > 0.5 ? '1' : '0';
        });

        // Hex Grid Overlay
        ctx.strokeStyle = '#003300';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let x = 0; x < w; x += 50) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
        for (let y = 0; y < h; y += 50) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
        ctx.stroke();

        // Beacons
        beacons.forEach(b => {
            const bx = b.x * w;
            const by = b.y * h;

            // Connection Line to Center (Mock C2)
            ctx.beginPath();
            ctx.moveTo(bx, by);
            ctx.lineTo(w / 2, h / 2);
            ctx.strokeStyle = `rgba(0, 255, 0, ${Math.random() * 0.3})`;
            ctx.stroke();

            // Beacon Node
            ctx.fillStyle = b.status === 'burned' ? '#333' : (b.id === c2Engine.selectedId ? '#fff' : '#0f0');
            ctx.beginPath();
            ctx.arc(bx, by, 4, 0, Math.PI * 2);
            ctx.fill();

            // Label
            ctx.fillStyle = '#0f0';
            ctx.fillText(b.id, bx + 10, by);
        });
    }
}

/* --- C2 LOGIC --- */
class C2Engine {
    constructor() {
        this.active = false;
        this.beacons = [
            { id: 'HV-09', ip: '45.33.22.11', os: 'Win10', status: 'active', x: 0.2, y: 0.3, fs: new C2FileSystem() },
            { id: 'XR-77', ip: '102.99.1.5', os: 'Linux', status: 'active', x: 0.7, y: 0.6, fs: new C2FileSystem() },
            { id: 'OM-22', ip: '198.51.100.2', os: 'WinSvr', status: 'dormant', x: 0.8, y: 0.2, fs: new C2FileSystem() }
        ];
        this.selectedId = null;
        this.visuals = new C2Visuals();
        this.audio = new C2Audio();
        this.timer = null;
        this.noise = 0;
        this.loot = [];
    }

    start() {
        this.active = true;
        this.audio.init();
        this.visuals.init('c2-canvas');
        this.log('SYS', 'DARKMATTER C2 v2.0 ONLINE // SECURE CHANNEL ESTABLISHED');
        this.timer = setInterval(() => this.tick(), 50);
    }

    stop() {
        this.active = false;
        clearInterval(this.timer);
    }

    tick() {
        if (!this.active) return;
        this.visuals.draw(this.beacons);
        if (this.noise > 0) this.noise -= 0.05;
        this.updateUI();
    }

    log(src, msg) {
        const stream = document.getElementById('c2-term-body');
        if (stream) {
            const line = document.createElement('div');
            line.className = 'log-line';
            line.innerHTML = `<span class="tm">[${new Date().toLocaleTimeString()}]</span> <span class="src"><${src}></span> ${msg}`;
            stream.appendChild(line);
            stream.scrollTop = stream.scrollHeight;
        }
    }

    execute(cmd) {
        this.log('OP', cmd);
        if (!this.selectedId) { this.audio.sfxError(); return this.log('ERR', 'NO AGENT SELECTED. USE "list" THEN "use [id]".'); }

        const agent = this.beacons.find(b => b.id === this.selectedId);
        if (agent.status === 'burned') { this.audio.sfxError(); return this.log('ERR', 'AGENT BURNED/OFFLINE.'); }

        // Core Commands
        const args = cmd.split(' ');
        const op = args[0].toLowerCase();

        this.audio.sfxType(); // Sound effect per command

        switch (op) {
            case 'ls':
                this.log('OUT', agent.fs.ls());
                break;
            case 'cd':
                const cdErr = agent.fs.cd(args[1]);
                if (cdErr) this.log('ERR', cdErr); else this.log('OUT', `CWD: ${agent.fs.cwd.join('/')}`);
                break;
            case 'cat':
                const catOut = agent.fs.cat(args[1]);
                this.log('OUT', catOut);
                break;
            case 'download':
                const file = agent.fs.cat(args[1]);
                if (file.startsWith('ERR')) { this.log('ERR', file); }
                else {
                    this.log('SYS', `DOWNLOADING ${args[1]}... 100%`);
                    this.loot.push(args[1]);
                    this.audio.sfxSuccess();
                    this.updateLoot();
                }
                break;
            case 'ps':
                this.log('OUT', 'PID  NAME\n445  svchost.exe\n992  explorer.exe\n102  chrome.exe');
                break;
            case 'mimikatz':
                this.log('OUT', 'Dumping Credentials... FOUND: Administrator / P@ssw0rd123');
                this.noise += 50;
                this.audio.sfxSuccess();
                break;
            default: this.log('ERR', 'UNKNOWN COMMAND');
        }

        this.noise += 2;
        if (this.noise > 100) {
            agent.status = 'burned';
            this.log('ALARM', `AGENT ${agent.id} DETECTED AND BURNED!`);
            this.audio.sfxError();
        }
    }

    updateUI() {
        const bar = document.getElementById('c2-noise-bar');
        const list = document.getElementById('c2-loot-list');
        if (bar) bar.style.width = Math.min(100, this.noise) + '%';
        // Simplified loot update
    }

    updateLoot() {
        const list = document.getElementById('c2-loot-list');
        if (list) list.innerHTML = this.loot.map(i => `<div><i class="fas fa-file"></i> ${i}</div>`).join('');
    }
}

const c2Engine = new C2Engine();

/* --- UI --- */
function pageC2Simulator() {
    setTimeout(() => c2Engine.start(), 100);

    return `
    <div class="c2-screen">
        <div class="scanlines"></div>
        
        <!-- Header -->
        <div class="c2-header">
            <div class="title">DARKMATTER // C2</div>
            <div class="stats">
                <span>OP: RED_STORM</span>
                <span>AGENTS: 3</span>
                <span>STATUS: <span style="color:#0f0">SECURE</span></span>
            </div>
        </div>

        <!-- Main Layout -->
        <div class="c2-grid">
            <!-- Left: Map & Agents -->
            <div class="c2-col-left">
                <div class="c2-box visual-box">
                    <div class="box-header">GLOBAL_GRID</div>
                    <canvas id="c2-canvas"></canvas>
                </div>
                <div class="c2-box agents-box">
                    <div class="box-header">ACTIVE_BEACONS</div>
                    <div class="agent-list">
                        ${c2Engine.beacons.map(b =>
        `<div class="agent-row" onclick="selectAgent('${b.id}')">
                                <span class="dot ${b.status}"></span>
                                <b>${b.id}</b> 
                                <span class="ip">${b.ip}</span>
                            </div>`
    ).join('')}
                    </div>
                </div>
            </div>

            <!-- Right: Terminal -->
            <div class="c2-col-right">
                <div class="c2-box term-box">
                    <div class="box-header">COMMAND_SHELL // ${c2Engine.selectedId || 'DISCONNECTED'}</div>
                    <div class="term-window" id="c2-term-body"></div>
                    <div class="term-input">
                        <span class="prompt">root@c2:~#</span>
                        <input type="text" id="c2-cmd-in" autofocus onkeydown="if(event.key=='Enter'){ c2Engine.execute(this.value); this.value=''; }">
                    </div>
                </div>
                
                <div class="c2-panels">
                    <div class="c2-box noise-box">
                        <div class="box-header">NOISE_LEVEL</div>
                        <div class="noise-meter"><div id="c2-noise-bar" style="width:0%"></div></div>
                    </div>
                    <div class="c2-box loot-box">
                        <div class="box-header">EXFIL_DATA</div>
                        <div id="c2-loot-list" class="loot-list"></div>
                    </div>
                </div>
            </div>
        </div>

        ${getC2Styles()}
    </div>
    `;
}

function selectAgent(id) {
    c2Engine.selectedId = id;
    c2Engine.audio.sfxConnect();
    c2Engine.log('SYS', `ATTACHING TO AGENT ${id}... SUCCESS.`);
    // Force UI refresh handled by engine tick or next action
    document.querySelector('.term-box .box-header').innerText = `COMMAND_SHELL // ${id}`;
}

window.selectAgent = selectAgent; // Expose globally

function getC2Styles() {
    return `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=VT323&display=swap');

        .c2-screen {
            background: #000; color: #00ff00; font-family: 'VT323', monospace;
            height: 100vh; display: flex; flex-direction: column; overflow: hidden;
            position: relative;
        }

        /* SCANLINES */
        .scanlines {
            position: fixed; top:0; left:0; width:100%; height:100%;
            background: linear-gradient(to bottom, rgba(255,255,255,0), rgba(255,255,255,0) 50%, rgba(0,0,0,0.2) 50%, rgba(0,0,0,0.2));
            background-size: 100% 4px; pointer-events: none; z-index: 999;
            animation: flicker 0.15s infinite; opacity: 0.3;
        }

        .c2-header {
            display: flex; justify-content: space-between; padding: 10px 20px;
            border-bottom: 2px solid #003300; background: #051105;
        }
        .title { font-size: 1.5rem; letter-spacing: 2px; text-shadow: 0 0 5px #0f0; }
        .stats span { margin-left: 20px; font-size: 1.1rem; color: #008800; }

        .c2-grid { display: flex; flex: 1; padding: 10px; gap: 10px; min-height: 0; }
        .c2-col-left { width: 30%; display: flex; flex-direction: column; gap: 10px; min-height: 0; }
        .c2-col-right { flex: 1; display: flex; flex-direction: column; gap: 10px; min-height: 0; }

        .c2-box { border: 1px solid #003300; background: #020502; display: flex; flex-direction: column; position: relative; min-height: 0; }
        .box-header { background: #001100; color: #006600; padding: 5px 10px; font-size: 0.9rem; border-bottom: 1px solid #003300; flex-shrink: 0; }

        /* VISUALS */
        .visual-box { height: 250px; flex-shrink: 0; }
        #c2-canvas { width: 100%; height: 100%; }

        /* AGENTS */
        .agents-box { flex: 1; overflow-y: auto; }
        .agent-row { padding: 8px 10px; cursor: pointer; border-bottom: 1px solid #002200; display: flex; align-items: center; }
        .agent-row:hover { background: #002200; color: #fff; }
        .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 10px; box-shadow: 0 0 5px currentColor; }
        .dot.active { background: #0f0; color: #0f0; } .dot.burned { background: #555; color: #555; }
        .ip { margin-left: auto; color: #005500; }

        /* TERMINAL */
        .term-box { flex: 1; font-size: 1.2rem; display: flex; flex-direction: column; overflow: hidden; }
        .term-window { flex: 1; overflow-y: auto; padding: 10px; color: #00cc00; scroll-behavior: smooth; }
        .log-line { margin-bottom: 4px; word-break: break-all; }
        .tm { color: #004400; font-size: 0.9rem; } .src { color: #008800; margin-right: 5px; }
        .term-input { display: flex; border-top: 1px solid #003300; padding: 10px; background: #000500; flex-shrink: 0; }
        .term-input input { flex: 1; background: transparent; border: none; color: #0f0; font-family: inherit; font-size: inherit; outline: none; margin-left: 10px; }

        /* PANELS */
        .c2-panels { height: 150px; display: flex; gap: 10px; flex-shrink: 0; }
        .noise-box { width: 40%; }
        .loot-box { flex: 1; }
        
        .noise-meter { flex: 1; background: #110000; margin: 20px; border: 1px solid #330000; position: relative; }
        #c2-noise-bar { height: 100%; background: #f00; box-shadow: 0 0 10px #f00; transition: width 0.2s; }
        
        .loot-list { padding: 10px; font-size: 0.9rem; color: #ffff00; }

        @keyframes flicker { 0% { opacity: 0.27; } 5% { opacity: 0.33; } 10% { opacity: 0.28; } 15% { opacity: 1; } 50% { opacity: 0.25; } 100% { opacity: 0.27; } }
    </style>
    `;
}

window.pageC2Simulator = pageC2Simulator;
