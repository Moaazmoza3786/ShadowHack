/* ============================================================
   SHADOW OS - KERNEL & WINDOW MANAGER 🖥️
   The operating system logic: Boot, State, App Management.
   ============================================================ */

class ShadowKernel {
    constructor() {
        // WORLD STATE
        this.money = 500; // Starting BTC (micro-units)
        this.reputation = 0; // Street Cred
        this.heat = 0; // FBI Attention (0-100)
        this.inventory = []; // Tools owned
        this.activeMissions = [];

        // SYSTEM STATE
        this.runningApps = []; // List of open app IDs
        this.zIndexCounter = 100;

        // REFERENCES
        this.db = window.SHADOW_DB;

        // MISSION STATE
        this.mission = { active: false, step: 0 };

        // APP STATES
        this.mailState = {
            inbox: [
                { id: 'welcome', sender: 'Admin', subject: 'Welcome to Shadow OS', body: 'Welcome Agent.\n\nSystem initialization complete.\nUse the Terminal to check for active operations.\n\n- The Administrator', read: false, time: 'Now' }
            ],
            openEmailId: null
        };
    }

    init() {
        this.renderDesktop();
        this.bootSequence();
        console.log("Red Team Ops Center Initialized");
        setTimeout(() => this.initVoiceControl(), 2000);
    }

    // --- VOICE CONTROL ---
    initVoiceControl() {
        if (!('webkitSpeechRecognition' in window)) {
            console.log("Voice API not supported.");
            return;
        }

        this.recognition = new webkitSpeechRecognition();
        this.recognition.continuous = false;
        this.recognition.lang = 'en-US';
        this.recognition.interimResults = false;

        this.recognition.onstart = () => {
            this.voiceActive = true;
            this.showToast('Listening...', 'info');
            const btn = document.getElementById('term-mic-btn');
            if (btn) btn.classList.add('recording');
        };

        this.recognition.onend = () => {
            this.voiceActive = false;
            const btn = document.getElementById('term-mic-btn');
            if (btn) btn.classList.remove('recording');
        };

        this.recognition.onresult = (event) => {
            const transcript = event.results[0][0].transcript.toLowerCase();
            this.handleVoiceCommand(transcript);
        };
    }

    toggleVoice() {
        if (!this.recognition) this.initVoiceControl();
        if (this.voiceActive) this.recognition.stop();
        else this.recognition.start();
    }

    handleVoiceCommand(cmd) {
        this.showToast(`Voice: "${cmd}"`, 'info');
        const output = document.getElementById('shadow-term-output');

        // Voice Mappings
        if (cmd.includes('scan') || cmd.includes('map')) {
            this.speak("Initiating Network Scan Protocol.");
            if (output) this.simulateNmap('10.50.1.5', output);
        }
        else if (cmd.includes('status') || cmd.includes('report')) {
            this.speak(`System Status: Online. Heat Level at ${this.heat} percent. Wallet Balance: ${this.money} Bitcoin.`);
            if (output) output.innerHTML += `<div>[VOICE] > Status Report generated.</div>`;
        }
        else if (cmd.includes('clear')) {
            this.speak("Clearing Terminal.");
            if (output) output.innerHTML = '';
        }
        else if (cmd.includes('help')) {
            this.speak("Showing available commands.");
            if (output) output.innerHTML += `<div>[VOICE] > listing commands...</div>`;
        }
        else {
            this.speak("Command not recognized.");
        }
    }

    speak(text) {
        if (!window.speechSynthesis) return;
        const synth = window.speechSynthesis;
        const utter = new SpeechSynthesisUtterance(text);
        utter.pitch = 0.5; // Low pitch for hacker vibe
        utter.rate = 1.0;
        synth.speak(utter);
    }
    // --- BOOT SEQUENCE ---
    bootSequence() {
        const boot = document.getElementById('shadow-boot-screen');
        if (!boot) return;

        const logs = [
            "Initializing Kernel...",
            "Loading Modules: [NET] [CRYPTO] [AI]...",
            "Connecting to Onion Relay...",
            "Bypassing Regional Firewalls...",
            "System Ready."
        ];

        let index = 0;
        const interval = setInterval(() => {
            if (index >= logs.length) {
                clearInterval(interval);
                this.login();
            } else {
                const p = document.createElement('p');
                p.innerText = "> " + logs[index];
                document.getElementById('boot-log').appendChild(p);
                index++;
            }
        }, 600);
    }

    login() {
        document.getElementById('shadow-boot-screen').style.opacity = '0';
        setTimeout(() => {
            document.getElementById('shadow-boot-screen').style.display = 'none';
            this.playSound('startup');
        }, 1000);
    }

    // --- APP MANAGEMENT ---
    openApp(appId) {
        // Check if already open
        if (this.runningApps.includes(appId)) {
            this.focusWindow(appId);
            return;
        }

        // Create Container
        const win = document.createElement('div');
        win.id = `win-${appId}`;
        win.className = `shadow-window ${appId}-theme glass-panel`;
        win.style.zIndex = ++this.zIndexCounter;

        // Header
        const appName = appId.toUpperCase(); // Placeholder
        win.innerHTML = `
            <div class="win-header" onmousedown="shadowOS.startDrag(event, '${appId}')">
                <div class="win-title"><i class="fas fa-terminal"></i> ${appName}.EXE</div>
                <div class="win-ctrls">
                    <button onclick="shadowOS.minimizeApp('${appId}')">_</button>
                    <button class="close" onclick="shadowOS.closeApp('${appId}')">×</button>
                </div>
            </div>
            <div class="win-content" id="content-${appId}">
                 ${this.getAppContent(appId)}
            </div>
        `;

        // Initial Position
        win.style.top = (50 + (this.runningApps.length * 30)) + 'px';
        win.style.left = (50 + (this.runningApps.length * 30)) + 'px';

        document.getElementById('shadow-desktop-area').appendChild(win);
        this.runningApps.push(appId);
        this.updateTaskbar();
    }

    closeApp(appId) {
        const win = document.getElementById(`win-${appId}`);
        if (win) win.remove();
        this.runningApps = this.runningApps.filter(id => id !== appId);
        this.updateTaskbar();
    }

    focusWindow(appId) {
        const win = document.getElementById(`win-${appId}`);
        if (win) win.style.zIndex = ++this.zIndexCounter;
    }

    minimizeApp(appId) {
        const win = document.getElementById(`win-${appId}`);
        if (win) win.style.display = 'none';
    }

    restoreApp(appId) {
        const win = document.getElementById(`win-${appId}`);
        if (win) {
            win.style.display = 'flex';
            this.focusWindow(appId);
        }
    }

    // --- DRAG LOGIC ---
    startDrag(e, appId) {
        e.preventDefault();
        this.focusWindow(appId);
        const win = document.getElementById(`win-${appId}`);

        let startX = e.clientX;
        let startY = e.clientY;
        let startLeft = win.offsetLeft;
        let startTop = win.offsetTop;

        const doDrag = (ev) => {
            win.style.left = (startLeft + ev.clientX - startX) + 'px';
            win.style.top = (startTop + ev.clientY - startY) + 'px';
        };

        const stopDrag = () => {
            document.removeEventListener('mousemove', doDrag);
            document.removeEventListener('mouseup', stopDrag);
        };

        document.addEventListener('mousemove', doDrag);
        document.addEventListener('mouseup', stopDrag);
    }

    // --- RENDERERS ---
    renderDesktop() {
        const root = document.getElementById('shadow-root');
        root.innerHTML = `
            <div id="shadow-boot-screen">
                <div class="logo-glitch">SHADOW OS <br> <span style="font-size:12px; letter-spacing:5px;">KERNEL v9.0.1</span></div>
                <div id="boot-log" class="boot-log"></div>
            </div>
            
            <div class="shadow-ui">
                <!-- TOP BAR (Status) -->
                <div class="shadow-topbar">
                    <div class="top-left">
                        <span class="sys-menu-btn"><i class="fas fa-bars"></i> SYSTEM</span>
                        <div class="resource-mon">
                            <span>CPU: <span style="color:#fff">12%</span></span>
                            <span>RAM: <span style="color:#fff">4.2GB</span></span>
                            <span class="heat-meter" title="Heat Level">HEAT: ${this.heat}%</span>
                        </div>
                    </div>
                    <div class="top-right">
                        <span class="net-stat"><i class="fas fa-network-wired"></i> VPN: <span style="color:#0f0">CONNECTED</span></span>
                        <span class="net-stat" title="Network Traffic"><i class="fas fa-exchange-alt"></i> 450kb/s</span>
                        <span class="wallet"><i class="fab fa-bitcoin"></i> ${this.money} BTC</span>
                        <span class="time">${new Date().toLocaleTimeString()}</span>
                    </div>
                </div>

                <!-- DESKTOP AREA -->
                <div id="shadow-desktop-area" class="desktop-area">
                    <canvas id="matrix-bg"></canvas>
                    <div class="desktop-icons">
                        ${this.renderIcon('terminal', 'Terminal', 'fa-terminal')}
                        ${this.renderIcon('browser', 'TorGate', 'fa-globe')}
                        ${this.renderIcon('mail', 'MailBox', 'fa-envelope')}
                        ${this.renderIcon('market', 'BlackMarket', 'fa-shopping-cart')}
                        ${this.renderIcon('c2', 'Viper C2', 'fa-network-wired')}
                        ${this.renderIcon('sdr', 'Signal Hunter', 'fa-broadcast-tower')}
                        ${this.renderIcon('social', 'GraphMind', 'fa-project-diagram')}
                        ${this.renderIcon('cleaner', 'Log Wiper', 'fa-eraser')}
                        ${this.renderIcon('chat', 'The Underground', 'fa-comments-dollar')}
                    </div>
                </div>

                <!-- DOCK (Mac/Win11 Style) -->
                <div class="shadow-dock">
                    <div id="taskbar-apps" class="dock-apps"></div>
                </div>
            </div>
        `;
        this.addStyles();
        this.initMatrixRain();
    }

    initMatrixRain() {
        const canvas = document.getElementById('matrix-bg');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const nums = '01';
        const alphabet = katakana + nums;

        const fontSize = 16;
        const columns = canvas.width / fontSize;

        const drops = [];
        for (let x = 0; x < columns; x++) drops[x] = 1;

        const draw = () => {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975)
                    drops[i] = 0;

                drops[i]++;
            }
        };

        setInterval(draw, 30);
    }

    renderIcon(id, label, icon) {
        return `
            <div class="desktop-icon" ondblclick="shadowOS.openApp('${id}')">
                <div class="icon-img"><i class="fas ${icon}"></i></div>
                <div class="icon-label">${label}</div>
            </div>
        `;
    }

    updateTaskbar() {
        const bar = document.getElementById('taskbar-apps');
        bar.innerHTML = this.runningApps.map(id => `
            <div class="dock-item active" onclick="shadowOS.restoreApp('${id}')">
                <i class="fas fa-window-maximize"></i>
            </div>
        `).join('');
    }

    getAppContent(appId) {
        switch (appId) {
            case 'terminal': return this.renderTerminal();
            case 'market': return this.renderMarket();
            case 'news': return this.renderNews();
            case 'bank': return this.renderBank();
            case 'mail': return this.renderMail();
            case 'browser': return this.renderBrowser();
            case 'c2': return this.renderC2();
            case 'sdr': return this.renderSDR();
            case 'social': return this.renderGraphMind();
            case 'cleaner': return this.renderCleaner();
            case 'chat': return this.renderChat();
            default: return `<div class="placeholder-app">
                <div class="loader-ring"></div>
                <p>Loading Module: ${appId.toUpperCase()}...</p>
            </div>`;
        }
    }

    // --- APP RENDERERS ---

    renderTerminal() {
        return `
            <div id="shadow-term-output" class="term-output">
                <span class="sys-msg">ShadowOS Kernel v9.0.1 - Root Access Granted.</span><br>
                <span class="sys-msg">Type 'help' for a list of tools.</span><br><br>
                ${this.mission.active ? '<span class="sys-msg" style="color:#00ffcc;">[MISSION ACTIVE]: Operation Chimera</span><br>' : ''}
                ${this.mission.step === 1 ? '<span class="sys-msg" style="color:#ffcc00;">> OBJECTIVE: Intercept 315MHz Signal (Use SDR)</span><br>' : ''}
                ${this.mission.step === 2 ? '<span class="sys-msg" style="color:#ffcc00;">> OBJECTIVE: Profile "Susan Vance" (Use Browser -> GraphMind)</span><br>' : ''}
                ${this.mission.step === 3 ? '<span class="sys-msg" style="color:#ffcc00;">> OBJECTIVE: Upload "payload.exe" to WORKSTATION_01 (Use Viper C2)</span><br>' : ''}
            </div>
            <div class="term-input-line">
                <span class="prompt">root@shadow:~#</span>
                <input type="text" id="shadow-term-input" autocomplete="off" onkeydown="shadowOS.handleTermInput(event)">
                <button id="term-mic-btn" onclick="shadowOS.toggleVoice()" title="Voice Command"><i class="fas fa-microphone"></i></button>
            </div>
        `;
    }

    handleTermInput(e) {
        if (e.key === 'Enter') {
            const input = e.target.value;
            const output = document.getElementById('shadow-term-output');

            // Echo command
            output.innerHTML += `<div><span class="prompt">root@shadow:~#</span> ${input}</div>`;

            // CMD LOGIC
            const args = input.trim().split(' ');
            const cmd = args[0].toLowerCase();

            let res = '';

            // --- REALISTIC COMMANDS ---
            if (cmd === 'help') {
                res = `
                <div class="cmd-help">
                    <div>GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)</div>
                    <div>These shell commands are defined internally. Type 'help' to see this list.</div>
                    <br>
                    <div><span class="cmd">nmap [target]</span>   Network exploration tool and security scanner.</div>
                    <div><span class="cmd">ifconfig</span>        Configure a network interface.</div>
                    <div><span class="cmd">whoami</span>          Print effective userid.</div>
                    <div><span class="cmd">ps</span>              Report a snapshot of the current processes.</div>
                    <div><span class="cmd">mission</span>         Access Mission Control Interface.</div>
                    <div><span class="cmd">clear</span>           Clear the terminal screen.</div>
                </div>`;
            }
            else if (cmd === 'clear') { output.innerHTML = ''; e.target.value = ''; return; }
            else if (cmd === 'whoami') res = "root";
            else if (cmd === 'ifconfig') {
                res = `
                <div class="code-block">
tun0: flags=4305&lt;UP,POINTOPOINT,RUNNING,NOARP,MULTICAST&gt;  mtu 1500
        inet 10.10.14.35  netmask 255.255.254.0  destination 10.10.14.35
        inet6 fe80::a2b3:c4d5:e6f7:8901  prefixlen 64  scopeid 0x20&lt;link&gt;
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 4502  bytes 342190 (334.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5120  bytes 581023 (567.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163&lt;UP,BROADCAST,RUNNING,MULTICAST&gt;  mtu 1500
        inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:0c:29:1a:2b:3c  txqueuelen 1000  (Ethernet)
                </div>`;
            }
            else if (cmd === 'nmap') {
                if (!args[1]) res = "nmap: missing operand";
                else {
                    this.simulateNmap(args[1], output);
                    e.target.value = '';
                    return; // Async output handling
                }
            }
            else if (cmd === 'mission') {
                if (args[1] === 'start' && args[2] === 'operation_chimera') {
                    this.mission.active = true;
                    this.mission.step = 1;
                    res = "Initializing Operation Chimera...<br>Sending Secure Briefing to Inbox... [SENT]<br>Check Mail for details.";
                    this.showToast('Mission Started: Operation Chimera', 'success');

                    // Send Briefing Email (Async)
                    setTimeout(() => {
                        this.receiveMail({
                            sender: 'Handler (Chimera)',
                            subject: 'OP: Chimera - Briefing',
                            body: "Agent,\n\nTarget is Nexus Corp. We need access to their mainframe.\n\nPHASE 1: SIGINT\nIntercept the key fob signal (315MHz) from the security guard's car. Use the SDR.\n\nPHASE 2: HUMINT\nProfile 'Susan Vance' in HR. We need her VPN credentials. Use GraphMind.\n\nPHASE 3: NETWORK\nDeploy the provided 'payload.exe' to WORKSTATION_01 via the C2 framework.\n\nGood hunting."
                        });
                    }, 1500);

                } else if (args[1] === 'start' && args[2] === 'operation_blackout') {
                    this.mission.active = true;
                    this.mission.id = 'blackout';
                    this.mission.step = 1;
                    res = "Initializing Operation Blackout...<br>Target: City Power Grid.<br>Briefing sent to Inbox.";
                    this.showToast('Mission Started: Operation Blackout', 'error');

                    setTimeout(() => {
                        this.receiveMail({
                            sender: 'The Architect',
                            subject: 'OP: Blackout - Briefing',
                            body: "Objective: Total Darkness.\n\nWe need to shut down the city's power grid to cover our tracks.\n\nPHASE 1: RECON\nScan the grid controller at 10.50.1.5 using nmap.\n\nPHASE 2: ACCESS\nAccess the SCADA Web Interface (http://scada.grid.local) via the Browser.\n\nPHASE 3: SABOTAGE\nOverride the failsafes and execute the SHUTDOWN command.\n\nDo not fail."
                        });
                    }, 1500);

                } else if (args[1] === 'start' && args[2] === 'operation_payday') {
                    this.mission.active = true;
                    this.mission.id = 'payday';
                    this.mission.step = 1;
                    res = "Initializing Operation Payday...<br>Target: Crypto Wallet 0x9f...<br>Briefing sent to Inbox.";
                    this.showToast('Mission Started: Operation Payday', 'warning');

                    setTimeout(() => {
                        this.receiveMail({
                            sender: 'The Broker',
                            subject: 'OP: Payday - Briefing',
                            body: "Objective: Financial Reallocation.\n\nTarget is holding 500 BTC in a cold wallet.\n\nPHASE 1: RECOVERY\nWe found a partial hash of their private key: '8f4b...'.\nUse the 'crack' command to recover the PIN.\n\nPHASE 2: TRANSFER\nLogin to the Bank Service with the PIN.\n\nPHASE 3: LAUNDER\nTransfer the funds to your account."
                        });
                    }, 1500);

                } else {
                    res = "Usage: mission start <operation_name><br>Available Operations:<br>- operation_chimera<br>- operation_blackout<br>- operation_payday";
                }
            }
            else if (cmd === 'crack') {
                if (this.mission.id === 'payday' && this.mission.step === 1) {
                    this.simulateCrack(output);
                    e.target.value = '';
                    return;
                } else {
                    res = "No active target for decryption.";
                }
            }
            else res = `bash: ${cmd}: command not found`;

            output.innerHTML += `<div style="margin-bottom:10px;">${res}</div>`;
            e.target.value = '';
            output.scrollTop = output.scrollHeight;
        }
    }

    simulateNmap(target, output) {
        this.increaseHeat(10); // Heat Spike
        output.innerHTML += `<div>Starting Nmap 7.92 ( https://nmap.org ) at ${new Date().toLocaleTimeString()}</div>`;

        let progress = 0;
        const interval = setInterval(() => {
            progress += 20;
            // Removed intermediate progress updates to reduce spam, or render simple dots?
            // output.innerHTML += `.`; 

            if (progress >= 100) {
                clearInterval(interval);

                let results = '';
                if (target.includes('nexus') || target === '10.50.1.5') {
                    results = `
                    <div class="code-block">
Nmap scan report for ${target} (10.50.1.5)
Host is up (0.045s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  many  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
                    </div>`;
                } else if (target === 'localhost' || target === '127.0.0.1') {
                    results = `
                    <div class="code-block">
Nmap scan report for localhost (127.0.0.1)
Host is up.
PORT     STATE SERVICE
8080/tcp open  http-proxy
                    </div>`;
                } else {
                    results = `
                    <div class="code-block">
Nmap scan report for ${target}
Host is up (0.12s latency).
All 1000 scanned ports on ${target} are filtered.
                    </div>`;
                }

                output.innerHTML += results;
                output.innerHTML += `<div>Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds</div>`;
                output.innerHTML += `<br><div class="term-input-line"><span class="prompt">root@shadow:~#</span> <input type="text" id="shadow-term-input-2" onkeydown="shadowOS.handleTermInput(event)"></div>`;
                // Re-focus logic would be needed here technically, but we just append output.
                // Actually the input is fixed at bottom. We just updated innerHTML.
                output.scrollTop = output.scrollHeight;
            }
        }, 300);
    }

    simulateCrack(output) {
        this.increaseHeat(20); // High Heat Action
        output.innerHTML += `<div>Starting HashCat v6.2.5...</div>`;
        output.innerHTML += `<div>Target: 8f4b... (Wallet PIN)</div>`;

        let progress = 0;
        const interval = setInterval(() => {
            progress += 5;
            if (Math.random() > 0.8) output.innerHTML += `<div>[STATUS] Speed: ${Math.floor(Math.random() * 1000)} kH/s, Temp: 65C</div>`;

            if (progress >= 100) {
                clearInterval(interval);
                output.innerHTML += `<div style="color:#0f0; margin-top:10px;">[+] CRACKED: 9284</div>`;
                output.innerHTML += `<div>Session Complete. PIN found: 9284</div>`;
                this.showToast('Hash Cracked: PIN 9284', 'success');

                if (this.mission.id === 'payday' && this.mission.step === 1) {
                    this.mission.step = 2;
                    this.showToast('OBJECTIVE COMPLETE: PIN Recovered', 'success');
                    this.showToast('NEW OBJECTIVE: Login to Bank', 'warning');
                }
                output.scrollTop = output.scrollHeight;
            }
            output.scrollTop = output.scrollHeight;
        }, 200);
    }

    renderMarket() {
        return `
            <div class="market-container">
                <div class="market-header">
                    <h3><i class="fas fa-shopping-cart"></i> EXPLOIT ZERO // MARKET</h3>
                    <div class="market-balance">WALLET: <span class="accent">${this.money} BTC</span></div>
                </div>
                <div class="market-grid">
                    ${this.db.BLACK_MARKET.map(item => `
                        <div class="market-card ${item.type}">
                            <div class="card-top">
                                <span class="badge">${item.type.toUpperCase()}</span>
                                <div class="price">${item.price} BTC</div>
                            </div>
                            <h4>${item.name}</h4>
                            <p>${item.desc}</p>
                            <button onclick="shadowOS.buyItem('${item.id}', ${item.price})">
                                <i class="fas fa-cart-plus"></i> PURCHASE
                            </button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    buyItem(id, price) {
        if (this.inventory.includes(id)) {
            this.showToast('Item already owned.', 'warning');
            return;
        }
        if (this.money >= price) {
            this.money -= price;
            this.inventory.push(id);
            this.showToast(`Purchased: ${id}`, 'success');

            // Refresh visuals
            this.renderDesktop(); // Update top bar money
            this.renderAppRefresh('market'); // Update market UI if needed (could disable button)
        } else {
            this.showToast('Insufficient Funds', 'error');
        }
    }

    renderNews() {
        // Fetch news if not already fetched
        if (!this.newsFeed) {
            this.newsFeed = [
                { title: "Connecting to Global News Network...", time: "Now", cat: "SYSTEM" }
            ];

            fetch('http://localhost:5000/api/ai/news')
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        this.newsFeed = data.news;
                        this.renderAppRefresh('news');
                    }
                })
                .catch(e => console.log("News Fetch Error", e));
        }

        return `
            <div class="news-container">
                <div class="news-ticker">
                    <span class="tick-text">SHADOW NETWORK // GLOBAL INTELLIGENCE FEED // UPDATED ${new Date().toLocaleTimeString()}</span>
                </div>
                <div class="news-list">
                    ${this.newsFeed.map(n => `
                        <div class="news-item">
                            <div class="news-meta"><span class="news-cat">${n.cat}</span> • ${n.time}</div>
                            <h3>${n.title}</h3>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    renderBank() {
        return `
            <div class="bank-container">
                <div class="bank-card">
                    <div class="chip"></div>
                    <div class="bank-logo">SHADOW<span class="accent">BANK</span></div>
                    <div class="acct-num">**** **** **** 8892</div>
                    <div class="acct-name">OPERATOR_X</div>
                </div>
                <div class="bank-stats">
                    <div class="stat-box">
                        <label>Current Balance</label>
                        <div class="val">${this.money.toLocaleString()} <small>BTC</small></div>
                    </div>
                    <div class="stat-box">
                        <label>Laundered</label>
                        <div class="val">0.00 <small>BTC</small></div>
                    </div>
                </div>
                <div class="tx-history">
                    <h4>Recent Transactions</h4>
                    <div class="tx-row"><span>Received (Contract #4402)</span> <span class="green">+500.00</span></div>
                    <div class="tx-row"><span>Service Fee (VPN)</span> <span class="red">-20.00</span></div>
                </div>
                
                <div style="margin-top:20px; border-top:1px solid #444; padding-top:20px; width:100%;">
                    <h4>Quick Actions</h4>
                    <div style="display:flex; gap:10px;">
                         <button onclick="shadowOS.bankAction('deposit')" style="flex:1; padding:10px; background:#004400; color:#0f0; border:none; cursor:pointer;">DEPOSIT</button>
                         <button onclick="shadowOS.bankAction('withdraw')" style="flex:1; padding:10px; background:#440000; color:#f00; border:none; cursor:pointer;">WITHDRAW</button>
                    </div>
                </div>
            </div>
        `;
    }

    bankAction(action) {
        if (action === 'withdraw' && this.mission.id === 'payday' && this.mission.step === 2) {
            const pin = prompt("ENTER WALLET PIN:");
            if (pin === '9284') {
                this.mission.step = 3;
                this.money += 500;
                this.showToast('TRANSFER SUCCESSFUL: +500 BTC', 'success');
                this.updateTopBar();
                setTimeout(() => {
                    alert('MISSION COMPLETE: OPERATION PAYDAY SUCCESSFUL.\n\nFunds secured. You are now richer.');
                }, 1000);
                this.renderAppRefresh('bank');
            } else {
                this.showToast('INVALID PIN', 'error');
            }
        } else {
            this.showToast('Transaction Failed: Network Busy', 'error');
        }
    }

    renderC2() {
        if (!this.c2State) {
            this.c2State = {
                listeners: [
                    { id: 'HTTP_80', type: 'HTTP', port: 80, status: 'Active' },
                    { id: 'DNS_53', type: 'DNS', port: 53, status: 'Silent' }
                ],
                beacons: [
                    { id: 'WORKSTATION_01', ip: '192.168.1.44', user: 'jsmith', last: '2s', status: 'alive' },
                    { id: 'DB_PROD_04', ip: '10.0.0.88', user: 'svc_sql', last: '5m', status: 'dead' }
                ],
                activeBeacon: null,
                logs: {} // logs per beacon
            };
        }

        const activeBeacon = this.c2State.activeBeacon
            ? this.c2State.beacons.find(b => b.id === this.c2State.activeBeacon)
            : null;

        const logs = activeBeacon && this.c2State.logs[activeBeacon.id]
            ? this.c2State.logs[activeBeacon.id]
            : [];

        return `
            <div class="c2-layout">
                <div class="c2-main">
                    <div class="c2-sidebar">
                        <h4>LISTENERS</h4>
                        <div class="c2-list">
                            ${this.c2State.listeners.map(l => `
                                <div class="c2-item" onclick="shadowOS.toggleListener('${l.id}')">
                                    <i class="fas fa-satellite-dish" style="color:${l.status === 'Active' ? '#00ff88' : '#666'}"></i>
                                    <span>${l.id}</span>
                                </div>
                            `).join('')}
                        </div>
                        <h4>BEACONS</h4>
                        <div class="c2-list">
                            ${this.c2State.beacons.map(b => `
                                <div class="c2-item ${activeBeacon && activeBeacon.id === b.id ? 'active' : ''}" 
                                     onclick="shadowOS.selectBeacon('${b.id}')">
                                    <div class="beacon-status ${b.status === 'alive' ? 'alive' : ''}"></div>
                                    <div style="display:flex; flex-direction:column; line-height:1.2;">
                                        <span>${b.id}</span>
                                        <span style="font-size:0.7rem; color:#888;">${b.user}@${b.ip}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    <div class="c2-console-area">
                        <div class="c2-logs" id="c2-logs-container">
                            ${activeBeacon ? logs.map(l => `
                                <div class="c2-log-entry ${l.type}">> ${l.text}</div>
                            `).join('') : '<div style="padding:20px; color:#666; text-align:center;">Select a Beacon to interact.</div>'}
                        </div>
                        <div class="c2-input-bar">
                            <span>viper@${activeBeacon ? activeBeacon.id : 'disconnected'} ~#</span>
                            <input type="text" ${!activeBeacon ? 'disabled' : ''} 
                                   placeholder="Enter command..." 
                                   onkeydown="shadowOS.handleC2Input(event)">
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    selectBeacon(id) {
        this.c2State.activeBeacon = id;
        this.renderAppRefresh('c2');
    }

    toggleListener(id) {
        const l = this.c2State.listeners.find(L => L.id === id);
        if (l) {
            l.status = l.status === 'Active' ? 'Silent' : 'Active';
            this.showToast(`Listener ${id} is now ${l.status}`);
            this.renderAppRefresh('c2');
        }
    }

    handleC2Input(e) {
        if (e.key === 'Enter') {
            const cmd = e.target.value;
            if (!cmd) return;

            const bId = this.c2State.activeBeacon;
            if (!this.c2State.logs[bId]) this.c2State.logs[bId] = [];

            // Add user command
            this.c2State.logs[bId].push({ type: 'cmd', text: cmd });

            // Mock Response
            setTimeout(() => {
                let res = '';
                if (cmd === 'help') res = "Available commands: shell, whoami, ls, download, upload, exit";
                else if (cmd.startsWith('shell whoami')) res = this.c2State.beacons.find(b => b.id === bId).user;
                else if (cmd.startsWith('ls')) res = "Desktop\nDocuments\nDownloads\nsecrets.txt";
                else if (cmd.startsWith('upload payload.exe')) {
                    res = "Uploading payload.exe... 100% [Done]";
                    // MISSION CHECK: Step 3 -> WIN
                    if (this.mission.active && this.mission.step === 3 && bId === 'WORKSTATION_01') {
                        this.mission.step = 4;
                        setTimeout(() => {
                            alert("MISSION COMPLETE: OPERATOR_CHIMERA SUCCESSFUL.\n\nACCESS GRANTED TO MAINFRAME.\n\nThank you for playing Shadow OS.");
                        }, 1000);
                    }
                }
                else res = `Tasked beacon ${bId} with '${cmd}'... result pending.`;

                this.c2State.logs[bId].push({ type: 'res', text: res });
                this.renderAppRefresh('c2');

                // Scroll to bottom
                setTimeout(() => {
                    const el = document.getElementById('c2-logs-container');
                    if (el) el.scrollTop = el.scrollHeight;
                }, 50);
            }, 600);

            e.target.value = '';
            this.renderAppRefresh('c2'); // Immediate update for input clear
        }
    }

    renderAppRefresh(appId) {
        const content = document.getElementById(`content-${appId}`);
        if (content) content.innerHTML = this.getAppContent(appId);
    }

    renderSocial() {
        return `
            <div class="social-container">
                <div class="social-search">
                    <input type="text" placeholder="Enter Target Name..." id="osint-query">
                    <button onclick="shadowOS.runOsint()"><i class="fas fa-search"></i> SCAN</button>
                </div>
                <div id="osint-results" class="osint-results">
                    <div class="empty-state">
                        <i class="fas fa-user-secret"></i>
                        <p>Awaiting Query...</p>
                    </div>
                </div>
            </div>
        `;
    }

    renderSDR() {
        // Start animation loop if not running
        if (!this.sdrState) {
            this.sdrState = { active: true, offset: 0 };
            setTimeout(() => this.initSDRCanvas(), 100);
        }

        return `
            <div class="sdr-container">
                <div class="waterfall-display">
                    <div class="sdr-canvas-container">
                        <canvas id="sdr-canvas"></canvas>
                        <div class="sdr-overlay"></div>
                    </div>
                    <div class="freq-scale">
                         <span>900MHz</span> <span>|</span> <span>2.4GHz</span> <span>|</span> <span>5GHz</span>
                    </div>
                </div>
                <div class="sdr-controls">
                    <button class="btn-sdr rec" onclick="shadowOS.recordSignal()"><i class="fas fa-circle"></i> REC</button>
                    <button class="btn-sdr play" onclick="shadowOS.showToast('No Capture Loaded', 'error')"><i class="fas fa-play"></i> REPLAY ATTACK</button>
                    <div class="signal-info">SCANNING ISM BANDS...</div>
                </div>
            </div>
        `;
    }

    initSDRCanvas() {
        const canvas = document.getElementById('sdr-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const resize = () => {
            canvas.width = canvas.parentElement.offsetWidth;
            canvas.height = canvas.parentElement.offsetHeight;
        };
        window.addEventListener('resize', resize);
        resize();

        const draw = () => {
            if (!document.getElementById('sdr-canvas')) return; // Stop if closed

            // Create scrolling effect
            const w = canvas.width;
            const h = canvas.height;

            // Shift down
            const imgData = ctx.getImageData(0, 0, w, h - 2);
            ctx.putImageData(imgData, 0, 2);

            // Draw new line at top
            const noise = ctx.createImageData(w, 2);
            for (let i = 0; i < noise.data.length; i += 4) {
                const val = Math.random() * 50;
                // Add "Signal" spikes
                const x = (i / 4) % w;
                let signal = 0;
                if (Math.abs(x - w * 0.3) < 5) signal = 200; // Spike at 30%
                if (Math.abs(x - w * 0.7) < 20) signal = 150 * Math.random(); // Wide band at 70%

                noise.data[i] = 0;   // R
                noise.data[i + 1] = val + signal; // G
                noise.data[i + 2] = 0; // B
                noise.data[i + 3] = 255; // A
            }
            ctx.putImageData(noise, 0, 0);

            requestAnimationFrame(draw);
        };
        draw();
    }

    recordSignal() {
        this.showToast('Recording Signal...', 'info');
        setTimeout(() => {
            this.showToast('Capture Saved: REMOTE_KEY_315MHz', 'success');
            this.inventory.push('capture_315mhz');

            // MISSION CHECK: Step 1 -> 2
            if (this.mission.active && this.mission.step === 1) {
                this.mission.step = 2;
                this.showToast("OBJECTIVE COMPLETE: Signal Intercepted.", 'success');
                this.showToast("NEW OBJECTIVE: Profile 'Susan Vance' on GraphMind.", 'warning');
            }
        }, 2000);
    }

    renderMail() {
        if (this.mailState.openEmailId) {
            const mail = this.mailState.inbox.find(m => m.id === this.mailState.openEmailId);
            if (!mail) return this.closeMail(); // Safety

            return `
                <div class="mail-view">
                    <div class="mail-header-view">
                        <button class="btn-back" onclick="shadowOS.closeMail()"><i class="fas fa-arrow-left"></i> Back</button>
                        <div class="mail-meta-view">
                            <h3>${mail.subject}</h3>
                            <span>From: <strong>${mail.sender}</strong></span>
                            <span>${mail.time}</span>
                        </div>
                    </div>
                    <div class="mail-body">${mail.body.replace(/\n/g, '<br>')}</div>
                </div>
            `;
        }

        return `
            <div class="mail-container">
                <div class="mail-header">
                    <h3><i class="fas fa-envelope"></i> SecureMail</h3>
                </div>
                <div class="mail-list">
                    ${this.mailState.inbox.length === 0 ? '<div class="empty-msg">Inbox Empty</div>' : ''}
                    ${this.mailState.inbox.map(mail => `
                        <div class="mail-item ${mail.read ? 'read' : 'unread'}" onclick="shadowOS.openMail('${mail.id}')">
                            <div class="mail-icon"><i class="fas fa-envelope${mail.read ? '-open' : ''}"></i></div>
                            <div class="mail-info">
                                <div class="mail-subject">${mail.subject}</div>
                                <div class="mail-sender">${mail.sender}</div>
                            </div>
                            <div class="mail-time">${mail.time}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    openMail(id) {
        this.mailState.openEmailId = id;
        const mail = this.mailState.inbox.find(m => m.id === id);
        if (mail) mail.read = true;
        this.renderAppRefresh('mail');
    }

    closeMail() {
        this.mailState.openEmailId = null;
        this.renderAppRefresh('mail');
    }

    receiveMail(input) {
        // input: { sender, subject, body }
        const newMail = {
            id: 'mail_' + Date.now(),
            sender: input.sender || 'Unknown',
            subject: input.subject || 'No Subject',
            body: input.body || '',
            read: false,
            time: 'Just now'
        };
        this.mailState.inbox.unshift(newMail);
        this.showToast(`New Mail: ${newMail.subject}`, 'info');
        this.playSound('notification');
        if (document.getElementById('content-mail')) this.renderAppRefresh('mail');
    }

    renderBrowser() {
        // Initialize State if not exists
        if (!this.browserState) {
            this.browserState = {
                url: 'www.linkedup.local/in/susan-vance',
                history: []
            };
        }

        setTimeout(() => this.navigateBrowser(this.browserState.url), 100);

        return `
            <div class="browser-container">
                <div class="browser-bar">
                    <button><i class="fas fa-arrow-left"></i></button>
                    <button><i class="fas fa-redo"></i></button>
                    <input type="text" class="url-input" value="${this.browserState.url}" id="browser-url-bar" onkeydown="shadowOS.handleBrowserInput(event)">
                </div>
                <div class="browser-viewport" id="browser-viewport">
                    <div class="loader-ring" style="margin-top:50px;"></div>
                </div>
            </div>
        `;
    }

    handleBrowserInput(e) {
        if (e.key === 'Enter') {
            this.navigateBrowser(e.target.value);
        }
    }

    navigateBrowser(url) {
        this.browserState.url = url;
        const viewport = document.getElementById('browser-viewport');
        const urlBar = document.getElementById('browser-url-bar');
        if (urlBar) urlBar.value = url;

        if (!viewport) return;

        viewport.innerHTML = '<div class="loader-ring" style="margin-top:50px; border-color:#888;"></div>';

        setTimeout(() => {
            // Routing Logic
            if (url.includes('linkedup.local')) {
                const handle = url.split('/in/')[1] || 'susan-vance';
                const target = Object.values(this.db.NPCS).find(n => n.social.linkedUp.handle === handle) || this.db.NPCS['susan_vance']; // Fallback for demo
                viewport.innerHTML = this.renderLinkedUp(target);
            }
            else if (url.includes('facespace.local')) {
                const handle = url.split('/').pop() || 'susan.v88';
                const target = Object.values(this.db.NPCS).find(n => n.social.faceSpace.handle === handle) || this.db.NPCS['susan_vance']; // Fallback
                viewport.innerHTML = this.renderFaceSpace(target);
            }
            else if (url.includes('vpn.corp-x.local')) {
                viewport.innerHTML = this.renderCorpLogin();
            }
            else if (url.includes('scada.grid.local')) {
                viewport.innerHTML = this.renderSCADA();
                if (this.mission.id === 'blackout' && this.mission.step === 1) {
                    this.mission.step = 2;
                    this.showToast("OBJECTIVE COMPLETE: SCADA Accessed", 'success');
                }
            }
            else {
                viewport.innerHTML = `<div style="padding:50px; text-align:center;"><h1>404 Not Found</h1><p>The DNS could not resolve ${url}</p></div>`;
            }
        }, 500);
    }

    renderLinkedUp(target) {
        if (!target) return 'Profile Not Found';
        const data = target.social.linkedUp;
        return `
            <div class="site-nav"><span>LinkedUp</span> <i class="fas fa-user-circle"></i></div>
            <div class="site-profile">
                <div class="profile-hero">
                    <img src="assets/avatars/${target.id}.png" class="profile-pic" onerror="this.src='https://api.dicebear.com/7.x/avataaars/svg?seed=${target.id}'">
                    <div class="profile-info">
                        <h1>${target.name}</h1>
                        <p>${target.role} at ${target.company}</p>
                        <p style="font-size:0.9rem; color:#888;">${target.details.vacation ? '🌴 On Vacation' : 'Working'}</p>
                        <button style="background:#0a66c2; color:#fff; border:none; padding:5px 15px; border-radius:15px; cursor:pointer;" oncontextmenu="shadowOS.addToBoard('${target.name}', 'Name')">Connect</button>
                    </div>
                </div>
                <div style="background:#fff; border:1px solid #eee; padding:20px; border-radius:8px;">
                    <h3>About</h3>
                    <p>Experienced HR professional specializing in ${data.skills.join(', ')}.</p>
                    <hr style="border:0; border-top:1px solid #eee; margin:15px 0;">
                    <h3>Activity</h3>
                    ${data.posts.map(p => `
                        <div style="margin-bottom:15px;">
                            <div style="font-size:0.8rem; color:#666;">${target.name} posted this • ${p.date}</div>
                            <p>"${p.text}"</p>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    renderFaceSpace(target) {
        if (!target) return 'User Not Found';
        const data = target.social.faceSpace;
        return `
            <div class="site-nav fb"><span>FaceSpace</span> <i class="fas fa-user-friends"></i></div>
            <div class="site-profile">
                 <div style="text-align:center; margin-bottom:20px;">
                    <img src="assets/avatars/${target.id}.png" class="profile-pic" style="width:150px; height:150px;" onerror="this.src='https://api.dicebear.com/7.x/avataaars/svg?seed=${target.id}'">
                    <h1>${target.name}</h1>
                    <p>@${data.handle}</p>
                 </div>
                 <div class="feed">
                    ${data.photos.map(photo => `
                        <div class="feed-post">
                            <div class="post-header">
                                <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=${target.id}" style="width:40px; height:40px; border-radius:50%;">
                                <div><strong>${target.name}</strong><br><span style="font-size:0.8rem; color:#888;">2h ago</span></div>
                            </div>
                            <div class="post-content">
                                <p>${photo.caption}</p>
                                <div style="height:200px; background:#eee; display:flex; align-items:center; justify-content:center; color:#aaa;">[Image: ${photo.img}]</div>
                            </div>
                            <div class="post-footer" style="padding-top:10px; border-top:1px solid #eee; margin-top:10px; display:flex; gap:20px; color:#666;">
                                <span><i class="far fa-thumbs-up"></i> Like</span>
                                <span><i class="far fa-comment"></i> Comment</span>
                            </div>
                        </div>
                    `).join('')}
                 </div>
            </div>
        `;
    }

    renderSCADA() {
        return `
            <div style="background:#000; color:#0f0; height:100%; padding:20px; font-family:'Courier New', monospace;">
                <div style="border-bottom:2px solid #0f0; margin-bottom:20px; display:flex; justify-content:space-between;">
                    <h2>SCADA SYSTEMS V4.0</h2>
                    <h2 style="color:red;">WARNING: RESTRICTED ACCESS</h2>
                </div>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                    <div style="border:1px solid #004400; padding:10px;">
                        <h3>NON-CRITICAL SYSTEMS</h3>
                        <div style="color:#00ff00;">[OK] Street Lights</div>
                        <div style="color:#00ff00;">[OK] Traffic Signals</div>
                        <div style="color:#00ff00;">[OK] Water Pumps</div>
                    </div>
                    <div style="border:1px solid #004400; padding:10px;">
                         <h3>CRITICAL INFRASTRUCTURE</h3>
                         <div style="color:#00ff00;">[OK] Sector 7 Substation</div>
                         <div style="color:#00ff00;">[OK] Main Turbine</div>
                         <div style="color:#00ff00;">[OK] Failsafes Active</div>
                    </div>
                </div>
                <div style="margin-top:40px; text-align:center;">
                    <p>MASTER CONTROL OVERRIDE</p>
                    <button style="background:red; color:white; border:none; padding:15px 30px; font-size:1.2rem; cursor:pointer;" onclick="shadowOS.triggerBlackout()">INITIATE SHUTDOWN</button>
                </div>
            </div>
        `;
    }

    triggerBlackout() {
        if (this.mission.id === 'blackout') {
            this.mission.step = 3;
            document.getElementById('browser-viewport').innerHTML = `
                <div style="background:black; color:white; height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center;">
                    <h1 style="color:red; font-size:3rem; animation:glitch 0.2s infinite;">SYSTEM FAILURE</h1>
                    <p>SHUTTING DOWN GRID...</p>
                </div>
            `;
            setTimeout(() => {
                alert("MISSION COMPLETE: CITY BLACKOUT INITIATED.\n\nChaos ensues. Good work.");
            }, 2000);
        } else {
            alert("ACCESS DENIED. AUTHORIZATION REQUIRED.");
        }
    }

    renderCorpLogin() {
        return `
            <div class="corp-login">
                <div class="login-box">
                    <h2 style="color:#333;">Corp-X Secure Portal</h2>
                    <p style="color:#666; font-size:0.9rem; margin-bottom:20px;">Employee Access Only</p>
                    <input type="text" placeholder="Username (e.g., jsmith)">
                    <input type="password" placeholder="Password">
                    <button onclick="shadowOS.showToast('Access Denied: 2FA Required', 'error')">Sign In</button>
                    <p style="margin-top:15px; font-size:0.8rem; color:#0a66c2; cursor:pointer;">Forgot Password?</p>
                </div>
            </div>
        `;
    }

    renderGraphMind() {
        // Initialize State if not exists
        if (!this.graphState) {
            this.graphState = {
                nodes: [],
                edges: [],
                nodeIdCounter: 1
            };
        }

        setTimeout(() => this.initGraphSystem(), 100);

        return `
            <div id="graph-container" class="graph-container">
                <div class="graph-bg"></div>
                <svg id="graph-svg" width="100%" height="100%"></svg>
                <div class="graph-toolbar">
                    <button class="graph-tool-btn" onclick="shadowOS.addGraphNode('Note')" title="Add Note"><i class="fas fa-sticky-note"></i></button>
                    <button class="graph-tool-btn" onclick="shadowOS.addGraphNode('Person')" title="Add Person"><i class="fas fa-user"></i></button>
                    <button class="graph-tool-btn" onclick="shadowOS.clearGraph()" title="Clear Board"><i class="fas fa-trash"></i></button>
                </div>
                <div id="graph-nodes-area"></div>
            </div>
        `;
    }

    addToBoard(text, type) {
        if (!this.graphState) {
            this.graphState = { nodes: [], edges: [], nodeIdCounter: 1 };
        }

        const newNode = {
            id: `node-${this.graphState.nodeIdCounter++}`,
            type: type || 'Data',
            content: text,
            x: 100 + (Math.random() * 50),
            y: 100 + (Math.random() * 50)
        };

        this.graphState.nodes.push(newNode);
        this.showToast(`Added to GraphMind: ${text}`, 'success');

        // MISSION CHECK: Step 2 -> 3
        if (this.mission.active && this.mission.step === 2 && text.includes('Susan')) {
            this.mission.step = 3;
            this.showToast("OBJECTIVE COMPLETE: Target Profiled.", 'success');
            this.showToast("NEW OBJECTIVE: Check Terminal for Instructions.", 'warning');
        }

        // If Graph app is open, refresh it
        const container = document.getElementById('graph-nodes-area');
        if (container) {
            this.renderGraphNodes();
        }
    }

    // --- GRAPH SYSTEM LOGIC ---

    initGraphSystem() {
        const container = document.getElementById('graph-container');
        if (!container) return;

        this.renderGraphNodes();
        this.renderGraphEdges();

        // Event Listeners for Dragging
        // Note: Actual drag logic is handled by global listeners or specific handlers attached to nodes
    }

    addGraphNode(type) {
        const text = prompt("Enter Node Content:");
        if (!text) return;

        this.addToBoard(text, type);
    }

    clearGraph() {
        if (confirm('Clear Detective Board?')) {
            this.graphState = { nodes: [], edges: [], nodeIdCounter: 1 };
            this.renderGraphNodes();
            this.renderGraphEdges();
        }
    }

    renderGraphNodes() {
        const area = document.getElementById('graph-nodes-area');
        if (!area) return;

        area.innerHTML = this.graphState.nodes.map(node => `
            <div id="${node.id}" class="graph-node" style="left:${node.x}px; top:${node.y}px;" 
                onmousedown="shadowOS.startGraphDrag(event, '${node.id}')">
                <div class="node-header">
                    <span>${node.type.toUpperCase()}</span>
                    <i class="fas fa-times" style="cursor:pointer;" onclick="shadowOS.removeGraphNode('${node.id}')"></i>
                </div>
                <div class="node-content">${node.content}</div>
                <div class="node-handle" onmousedown="shadowOS.startGraphConnect(event, '${node.id}')"></div>
            </div>
        `).join('');
    }

    renderGraphEdges() {
        const svg = document.getElementById('graph-svg');
        if (!svg) return;

        svg.innerHTML = this.graphState.edges.map(edge => {
            const n1 = this.graphState.nodes.find(n => n.id === edge.from);
            const n2 = this.graphState.nodes.find(n => n.id === edge.to);
            if (!n1 || !n2) return '';

            // Calculate centers roughly
            const x1 = n1.x + 75; const y1 = n1.y + 40;
            const x2 = n2.x + 75; const y2 = n2.y + 40;

            return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="graph-edge" />`;
        }).join('');
    }

    removeGraphNode(id) {
        this.graphState.nodes = this.graphState.nodes.filter(n => n.id !== id);
        this.graphState.edges = this.graphState.edges.filter(e => e.from !== id && e.to !== id);
        this.renderGraphNodes();
        this.renderGraphEdges();
    }

    startGraphDrag(e, nodeId) {
        if (e.target.classList.contains('fa-times') || e.target.classList.contains('node-handle')) return;

        e.preventDefault();
        const node = this.graphState.nodes.find(n => n.id === nodeId);
        if (!node) return;

        let startX = e.clientX;
        let startY = e.clientY;
        let startLeft = node.x;
        let startTop = node.y;

        const doDrag = (ev) => {
            node.x = startLeft + ev.clientX - startX;
            node.y = startTop + ev.clientY - startY;
            document.getElementById(nodeId).style.left = node.x + 'px';
            document.getElementById(nodeId).style.top = node.y + 'px';
            this.renderGraphEdges(); // Re-render lines
        };

        const stopDrag = () => {
            document.removeEventListener('mousemove', doDrag);
            document.removeEventListener('mouseup', stopDrag);
        };

        document.addEventListener('mousemove', doDrag);
        document.addEventListener('mouseup', stopDrag);
    }

    startGraphConnect(e, nodeId) {
        e.stopPropagation();
        e.preventDefault();

        const svg = document.getElementById('graph-svg');
        const node = this.graphState.nodes.find(n => n.id === nodeId);
        const originX = node.x + 75;
        const originY = node.y + 40;

        // Create temp line
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", originX);
        line.setAttribute("y1", originY);
        line.setAttribute("x2", originX);
        line.setAttribute("y2", originY);
        line.setAttribute("class", "graph-edge");
        svg.appendChild(line);

        const doConnect = (ev) => {
            // Get relative coords for SVG is hard, simplifying: assuming full screen canvas
            const rect = svg.getBoundingClientRect();
            line.setAttribute("x2", ev.clientX - rect.left);
            line.setAttribute("y2", ev.clientY - rect.top);
        };

        const stopConnect = (ev) => {
            document.removeEventListener('mousemove', doConnect);
            document.removeEventListener('mouseup', stopConnect);
            line.remove();

            // Check if dropped on a node
            const elem = document.elementFromPoint(ev.clientX, ev.clientY);
            const targetNode = elem.closest('.graph-node');

            if (targetNode && targetNode.id !== nodeId) {
                this.graphState.edges.push({ from: nodeId, to: targetNode.id });
                this.renderGraphEdges();
            }
        };

        document.addEventListener('mousemove', doConnect);
        document.addEventListener('mouseup', stopConnect);
    }

    // --- ACTIONS ---

    buyItem(id, price) {
        if (this.money >= price) {
            this.money -= price;
            this.inventory.push(id);
            this.showToast(`Purchased: ${id}`, 'success');
            // Re-render to update balance
            this.updateTopBar();
            const mkt = document.getElementById('content-market');
            if (mkt) mkt.innerHTML = this.renderMarket();
        } else {
            this.showToast('Insufficient Funds', 'error');
        }
    }

    runOsint() {
        const query = document.getElementById('osint-query').value.toLowerCase();
        const resDiv = document.getElementById('osint-results');

        resDiv.innerHTML = '<div class="loader-ring"></div> Scanning Public Sources...';

        setTimeout(() => {
            // Safe access trying to find target
            let target = null;
            if (this.db && this.db.NPCS) {
                target = Object.values(this.db.NPCS).find(n => n.name.toLowerCase().includes(query));
            }

            if (target) {
                resDiv.innerHTML = `
                    <div class="profile-card">
                        <div class="profile-header">
                            <img src="assets/avatars/${target.id}.png" onerror="this.src='https://api.dicebear.com/7.x/pixel-art/svg?seed=${target.id}'">
                            <div>
                                <h2>${target.name}</h2>
                                <p>${target.role}</p>
                            </div>
                        </div>
                        <div class="profile-body">
                            <div class="data-row"><label>Email:</label> ${target.email}</div>
                            <div class="data-row"><label>DISC:</label> ${target.discProfile}</div>
                            <div class="data-row"><label>Interests:</label> ${target.interests.join(', ')}</div>
                            
                            <h4>Recent Activity</h4>
                            ${target.socialPosts.map(p => `
                                <div class="post-item">
                                    <span class="platform ${p.platform}">${p.platform}</span>
                                    <div class="post-text">"${p.text}"</div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            } else {
                resDiv.innerHTML = '<div class="error-msg">Target Not Found in Public Databases.</div>';
            }
        }, 1500);
    }

    showToast(msg, type = 'info') {
        const t = document.createElement('div');
        t.className = `shadow-toast ${type}`;
        t.innerText = msg;
        document.querySelector('.shadow-ui').appendChild(t);
        setTimeout(() => t.remove(), 3000);
    }

    updateTopBar() {
        const el = document.querySelector('.wallet');
        if (el) el.innerHTML = `<i class="fab fa-bitcoin"></i> ${this.money} BTC`;
    }

    handleTermInput(e) {
        if (e.key === 'Enter') {
            const input = e.target;
            const cmd = input.value;
            const output = document.getElementById('shadow-term-output');
            output.innerHTML += `<div><span class="prompt">root@shadow:~#</span> ${cmd}</div>`;
            output.innerHTML += `<div>Command not found: ${cmd} (Try 'help')</div><br>`;
            input.value = '';
            output.scrollTop = output.scrollHeight;
        }
    }

    playSound(type) {
        // Hook for audio
    }

    addStyles() {
        const style = document.createElement('style');
        style.innerHTML = `
            #shadow-root { 
                width: 100vw; height: 100vh; overflow: hidden; 
                background: radial-gradient(circle at center, #1a1a2e 0%, #000000 100%);
                font-family: 'Consolas', 'Rajdhani', monospace; 
                color: #00ffcc;
            }
            #matrix-bg {
                position: absolute; top: 0; left: 0; width: 100%; height: 100%;
                z-index: 0; opacity: 0.2; pointer-events: none;
            }
            .glass-panel { background: rgba(10, 15, 20, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(0, 255, 204, 0.2); box-shadow: 0 0 20px rgba(0, 255, 204, 0.1); }
            
            /* BOOT SCREEN */
            #shadow-boot-screen { position:absolute; top:0; left:0; width:100%; height:100%; background:#000; z-index:9999; display:flex; flex-direction:column; justify-content:center; align-items:center; transition: opacity 1s; }
            .logo-glitch { font-size:4rem; font-weight:bold; color:#00ffcc; text-shadow:2px 0 #f0f, -2px 0 #0ff; animation: glitch 0.2s infinite alternate; text-align:center; }
            .boot-log { width:400px; height:200px; margin-top:20px; font-size:0.9rem; color:#0f0; text-align:left; }

            /* DESKTOP */
            .shadow-ui { width:100%; height:100%; display:flex; flex-direction:column; }
            .shadow-topbar { height:30px; background:rgba(0,0,0,0.8); display:flex; justify-content:space-between; align-items:center; padding:0 10px; border-bottom:1px solid #333; font-size:0.8rem; }
            .top-left, .top-right { display:flex; gap:15px; }
            .resource-mon { color:#666; display:flex; gap:10px; }
            .heat-meter { color:#ff3333; font-weight:bold; }
            
            .desktop-area { flex:1; position:relative; overflow:hidden; padding:20px; }
            .desktop-icons { display:flex; flex-direction:column; gap:20px; flex-wrap:wrap; align-content:flex-start; height:100%; }
            .desktop-icon { width:80px; text-align:center; cursor:pointer; opacity:0.8; transition:0.2s; }
            .desktop-icon:hover { opacity:1; transform:scale(1.1); }
            .icon-img { font-size:2.5rem; margin-bottom:5px; color:#00ffcc; filter: drop-shadow(0 0 5px #00ffcc); }
            .icon-label { font-size:0.8rem; text-shadow:1px 1px 2px #000; }

            /* WINDOWS */
            .shadow-window { position:absolute; width:600px; height:400px; display:flex; flex-direction:column; border-radius:4px; overflow:hidden; resize:both; min-width:300px; min-height:200px; }
            .win-header { height:30px; background:rgba(0, 255, 204, 0.1); display:flex; justify-content:space-between; align-items:center; padding:0 10px; cursor:default; border-bottom:1px solid rgba(0, 255, 204, 0.2); }
            .win-title { font-weight:bold; letter-spacing:1px; }
            .win-ctrls button { background:transparent; border:none; color:#00ffcc; cursor:pointer; font-size:1.2rem; }
            .win-ctrls button:hover { color:#fff; }
            .win-ctrls button.close:hover { color:#ff3333; }
            .win-content { flex:1; overflow:auto; padding:10px; background:rgba(0,0,0,0.4); }

            /* DOCK */
            .shadow-dock { height:60px; background:rgba(0,0,0,0.6); display:flex; justify-content:center; align-items:center; border-top:1px solid #333; }
            .dock-apps { display:flex; gap:10px; }
            .dock-item { width:40px; height:40px; background:rgba(255,255,255,0.1); border-radius:8px; display:flex; justify-content:center; align-items:center; cursor:pointer; transition:0.2s; }
            .dock-item:hover { background:rgba(255,255,255,0.2); transform:translateY(-5px); }

            /* APP SPECIFIC */
            .market-item { padding:10px; border-bottom:1px solid #333; display:flex; justify-content:space-between; }
            .market-item:hover { background:rgba(0,255,204,0.1); }

            /* APP: MARKET */
            .market-container { display:flex; flex-direction:column; height:100%; gap:15px; }
            .market-header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #333; padding-bottom:10px; }
            .market-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap:15px; overflow-y:auto; }
            .market-card { background:rgba(255,255,255,0.05); padding:15px; border-radius:6px; border:1px solid rgba(0,255,204,0.1); display:flex; flex-direction:column; gap:8px; transition:0.2s; }
            .market-card:hover { border-color:#00ffcc; transform:translateY(-2px); box-shadow:0 0 10px rgba(0,255,204,0.1); }
            .card-top { display:flex; justify-content:space-between; font-size:0.8rem; }
            .market-card h4 { margin:0; font-size:1rem; color:#fff; }
            .market-card p { font-size:0.8rem; color:#aaa; flex:1; }
            .market-card button { background:rgba(0,255,204,0.2); border:none; color:#00ffcc; padding:5px; border-radius:4px; font-weight:bold; cursor:pointer; }
            .market-card button:hover { background:#00ffcc; color:#000; }
            
            /* APP: TERMINAL */
            .term-output { flex:1; overflow:auto; font-family:'Consolas', monospace; font-size:0.9rem; padding-bottom:10px; }
            .term-input-line { display:flex; gap:10px; align-items:center; }
            .prompt { color:#00ffcc; font-weight:bold; }
            #shadow-term-input { background:none; border:none; color:#fff; flex:1; font-family:inherit; font-size:1rem; outline:none; }
            .sys-msg { color:#aaa; font-style:italic; }
            
            #term-mic-btn { background:transparent; border:1px solid #333; color:#666; width:30px; height:30px; border-radius:50%; cursor:pointer; transition:0.3s; display:flex; align-items:center; justify-content:center; }
            #term-mic-btn:hover { color:#00ffcc; border-color:#00ffcc; }
            #term-mic-btn.recording { color:#f00; border-color:#f00; animation: pulse 1s infinite; }
            @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(255, 0, 0, 0); } 100% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); } }

            /* APP: BANK */
            .bank-container { display:flex; flex-direction:column; gap:20px; align-items:center; padding:20px; }
            .bank-card { width:320px; height:200px; background:linear-gradient(135deg, #111, #222); border-radius:15px; border:1px solid #444; position:relative; padding:20px; box-shadow:0 10px 30px rgba(0,0,0,0.5); }
            .bank-logo { position:absolute; top:20px; right:20px; font-weight:bold; font-size:1.2rem; }
            .chip { width:40px; height:30px; background:linear-gradient(135deg, #d4af37, #f9f295); border-radius:5px; margin-top:30px; }
            .acct-num { font-size:1.4rem; letter-spacing:2px; margin-top:20px; font-family:'Courier New', monospace; }
            .acct-name { position:absolute; bottom:20px; left:20px; text-transform:uppercase; color:#888; }
            .bank-stats { display:flex; gap:20px; width:100%; justify-content:center; }
            .stat-box { text-align:center; background:rgba(255,255,255,0.05); padding:10px; border-radius:8px; width:100px; }
            .stat-box .val { font-size:1.2rem; font-weight:bold; color:#00ffcc; }
            .tx-history { width:100%; background:rgba(0,0,0,0.3); border-radius:8px; padding:10px; flex:1; }
            .tx-row { display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:0.9rem; }
            .green { color:#00ff88; } .red { color:#ff3333; }

            /* APP: NEWS */
            .news-container { display:flex; flex-direction:column; height:100%; }
            .news-ticker { background:#cc0000; color:#fff; padding:5px; font-weight:bold; white-space:nowrap; overflow:hidden; }
            .news-list { padding:15px; display:flex; flex-direction:column; gap:10px; overflow-y:auto; }
            .news-item { background:rgba(255,255,255,0.05); padding:10px; border-left:3px solid #cc0000; }
            .news-meta { font-size:0.7rem; color:#aaa; margin-bottom:5px; }
            .news-item h3 { margin:0; font-size:1rem; }

            /* APP: VIPER C2 */
            .c2-container { display:flex; height:100%; gap:10px; }
            .c2-sidebar { width:180px; background:rgba(0,0,0,0.3); padding:10px; border-right:1px solid #333; display:flex; flex-direction:column; gap:5px; }
            .c2-sidebar h4 { font-size:0.7rem; color:#666; margin-top:10px; margin-bottom:5px; letter-spacing:1px; }
            .list-item { font-size:0.8rem; padding:5px; cursor:pointer; display:flex; justify-content:space-between; align-items:center; }
            .list-item:hover, .list-item.active { background:rgba(0,255,204,0.1); color:#00ffcc; }
            .status { width:8px; height:8px; border-radius:50%; }
            .status.online { background:#00ff88; box-shadow:0 0 5px #00ff88; }
            .status.offline { background:#555; }
            .c2-map { flex:1; position:relative; background:#050505; overflow:hidden; }
            .map-grid { position:absolute; width:100%; height:100%; background:linear-gradient(rgba(0,255,204,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,204,0.05) 1px, transparent 1px); background-size:30px 30px; }
            .c2-node { position:absolute; padding:5px 10px; background:#000; border:1px solid #00ffcc; border-radius:4px; font-size:0.7rem; color:#00ffcc; transform:translate(-50%, -50%); display:flex; gap:5px; align-items:center; }
            .c2-link { position:absolute; height:2px; background:#00ffcc; opacity:0.3; transform-origin:left center; }

            /* APP: PROFILEX */
            .social-container { display:flex; flex-direction:column; height:100%; gap:15px; }
            .social-search { display:flex; gap:10px; }
            .social-search input { flex:1; background:rgba(0,0,0,0.5); border:1px solid #333; padding:8px; color:#fff; }
            .social-search button { background:#00ffcc; border:none; padding:0 15px; font-weight:bold; cursor:pointer; }
            .osint-results { flex:1; background:rgba(0,0,0,0.2); border:1px solid #333; padding:15px; overflow-y:auto; }
            .profile-card { display:flex; flex-direction:column; gap:15px; animation:fadeIn 0.5s; }
            .profile-header { display:flex; gap:15px; align-items:center; border-bottom:1px solid #333; padding-bottom:15px; }
            .profile-header img { width:60px; height:60px; border-radius:50%; border:2px solid #00ffcc; }
            .profile-header h2 { margin:0; font-size:1.4rem; color:#fff; }
            .profile-body { display:flex; flex-direction:column; gap:8px; }
            .data-row label { color:#888; width:80px; display:inline-block; }
            .post-item { background:rgba(255,255,255,0.05); padding:8px; border-radius:4px; margin-top:5px; }
            .post-item .platform { font-size:0.6rem; padding:2px 5px; border-radius:2px; text-transform:uppercase; margin-right:5px; }
            .LinkedUp { background:#0a66c2; color:#fff; }
            .Twitter { background:#1d9bf0; color:#fff; }

            /* APP: SDR */
            .sdr-container { display:flex; flex-direction:column; height:100%; gap:10px; }
            .waterfall-display { flex:1; background:#000; position:relative; border:1px solid #333; overflow:hidden; }
            #sdr-canvas { width:100%; height:100%; background:linear-gradient(180deg, #001100, #004400, #00ff00); opacity:0.2; }
            .freq-scale { position:absolute; bottom:0; width:100%; display:flex; justify-content:space-between; padding:2px 10px; color:#00ffcc; font-size:0.7rem; background:rgba(0,0,0,0.8); }
            .sdr-controls { display:flex; gap:10px; align-items:center; background:rgba(0,0,0,0.5); padding:10px; }
            .btn-sdr { background:#333; border:none; color:#fff; padding:5px 10px; border-radius:4px; cursor:pointer; display:flex; gap:5px; align-items:center; font-size:0.8rem; }
            .btn-sdr.rec { color:#ff3333; }
            .btn-sdr.play { color:#00ff88; }
            .signal-info { margin-left:auto; font-family:'Consolas', monospace; color:#00ffcc; font-size:0.8rem; }

            /* APP: BROWSER */
            .browser-container { display:flex; flex-direction:column; height:100%; background:#fff; color:#000; font-family:'Arial', sans-serif; }
            .browser-bar { background:#f1f1f1; padding:5px; display:flex; gap:10px; border-bottom:1px solid #ccc; align-items:center; }
            .browser-bar button { border:none; background:transparent; cursor:pointer; color:#555; }
            .browser-bar button:hover { color:#000; }
            .url-input { flex:1; background:#fff; border:1px solid #ccc; padding:4px 10px; border-radius:15px; font-size:0.9rem; outline:none; }
            .browser-viewport { flex:1; overflow-y:auto; background:#fff; position:relative; }
            
            /* SITES: LINKEDUP & FACESPACE */
            .site-profile { max-width:800px; margin:0 auto; padding:20px; }
            .site-nav { background:#0a66c2; color:#fff; padding:10px 20px; display:flex; justify-content:space-between; margin-bottom:20px; }
            .site-nav.fb { background:#1877f2; }
            .profile-hero { display:flex; gap:20px; align-items:flex-start; margin-bottom:20px; }
            .profile-pic { width:120px; height:120px; border-radius:50%; border:4px solid #fff; background:#eee; object-fit:cover; }
            .profile-info h1 { margin:0; font-size:1.8rem; }
            .profile-info p { color:#666; margin:5px 0; }
            .feed-post { border:1px solid #ddd; border-radius:8px; padding:15px; margin-bottom:15px; background:#fff; }
            .post-header { display:flex; gap:10px; align-items:center; margin-bottom:10px; }
            .post-content img { width:100%; border-radius:4px; margin-top:10px; }
            
            /* CORPORATE LOGIN */
            .corp-login { height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center; background:#f0f2f5; }
            .login-box { background:#fff; padding:30px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1); width:350px; text-align:center; }
            .login-box input { width:100%; padding:10px; margin:10px 0; border:1px solid #ddd; border-radius:4px; }
            .login-box button { width:100%; padding:10px; background:#000; color:#fff; border:none; border-radius:4px; cursor:pointer; }
            
            /* APP: GRAPHMIND (DETECTIVE BOARD) */
            .graph-container { position:relative; width:100%; height:100%; background:#1a1a2e; overflow:hidden; user-select:none; }
            .graph-bg { position:absolute; width:100%; height:100%; background-image: radial-gradient(#333 1px, transparent 1px); background-size: 20px 20px; opacity:0.3; }
            
            .graph-node { position:absolute; background:rgba(0, 255, 204, 0.1); border:1px solid #00ffcc; border-radius:6px; padding:10px; min-width:150px; cursor:grab; backdrop-filter:blur(5px); box-shadow:0 0 10px rgba(0,255,204,0.1); display:flex; flex-direction:column; gap:5px; z-index:10; }
            .graph-node:active { cursor:grabbing; }
            .graph-node.selected { border-width:2px; box-shadow:0 0 15px rgba(0,255,204,0.3); }
            
            .node-header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(0,255,204,0.2); padding-bottom:5px; margin-bottom:5px; font-size:0.8rem; letter-spacing:1px; color:#00ffcc; font-weight:bold; }
            .node-content { font-size:0.9rem; color:#fff; }
            .node-handle { width:10px; height:10px; background:#00ffcc; border-radius:50%; margin:0 auto; cursor:crosshair; transition:0.2s; }
            .node-handle:hover { transform:scale(1.5); }
            
            .graph-toolbar { position:absolute; top:10px; left:10px; display:flex; gap:5px; background:rgba(0,0,0,0.7); padding:5px; border-radius:4px; border:1px solid #333; z-index:100; }
            .graph-tool-btn { background:transparent; border:none; color:#fff; cursor:pointer; padding:5px 8px; font-size:1.1rem; }
            .graph-tool-btn:hover { color:#00ffcc; }
            
            #graph-svg { position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none; z-index:0; }
            .graph-edge { stroke:#00ffcc; stroke-width:2; stroke-opacity:0.6; fill:none; }

            /* APP: VIPER C2 - ENHANCED */
            .c2-layout { display:flex; flex-direction:column; height:100%; }
            .c2-main { display:flex; flex:1; overflow:hidden; }
            .c2-sidebar { width:200px; background:rgba(0,0,0,0.4); border-right:1px solid #333; display:flex; flex-direction:column; }
            .c2-sidebar h4 { padding:10px; background:rgba(255,255,255,0.05); margin:0; font-size:0.8rem; letter-spacing:1px; }
            .c2-list { flex:1; overflow-y:auto; }
            .c2-item { padding:8px 10px; cursor:pointer; font-size:0.85rem; display:flex; align-items:center; gap:8px; border-bottom:1px solid rgba(255,255,255,0.05); }
            .c2-item:hover { background:rgba(0,255,204,0.1); }
            .c2-item.active { background:rgba(0,255,204,0.2); border-left:3px solid #00ffcc; }
            .beacon-status { width:8px; height:8px; border-radius:50%; background:#555; }
            .beacon-status.alive { background:#00ff88; box-shadow:0 0 5px #00ff88; }
            
            .c2-console-area { flex:1; display:flex; flex-direction:column; background:#000; font-family:'Consolas', monospace; }
            .c2-logs { flex:1; padding:10px; overflow-y:auto; font-size:0.9rem; color:#ccc; }
            .c2-log-entry.cmd { color:#fff; font-weight:bold; margin-top:5px; }
            .c2-log-entry.res { color:#00ffcc; margin-bottom:5px; white-space:pre-wrap; }
            .c2-input-bar { display:flex; border-top:1px solid #333; padding:5px; }
            .c2-input-bar span { color:#00ffcc; padding:5px; }
            .c2-input-bar input { flex:1; background:transparent; border:none; color:#fff; outline:none; font-family:inherit; }

            /* APP: SDR - ENHANCED */
            .sdr-canvas-container { position:relative; flex:1; background:#000; overflow:hidden; }
            .sdr-overlay { position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none; background:linear-gradient(90deg, rgba(0,0,0,0.8) 0%, transparent 10%, transparent 90%, rgba(0,0,0,0.8) 100%); }
            
            /* UTILS */
            .shadow-toast { position:absolute; bottom:70px; right:20px; background:rgba(0,0,0,0.9); border:1px solid #00ffcc; color:#fff; padding:10px 20px; border-radius:4px; animation:slideIn 0.3s; z-index:10000; }
            @keyframes slideIn { from{transform:translateX(100%);} to{transform:translateX(0);} }
            @keyframes fadeIn { from{opacity:0;} to{opacity:1;} }
            .loader-ring { width:20px; height:20px; border:2px solid #00ffcc; border-top-color:transparent; border-radius:50%; animation:spin 1s linear infinite; margin:0 auto; }
            @keyframes glitch { 0% { transform: translate(2px,0); } 100% { transform: translate(-2px,0); } }
        `;
        document.head.appendChild(style);
    }

    // --- HEAT & TRACE LOGIC ---
    increaseHeat(amount) {
        this.heat += amount;
        if (this.heat > 100) this.heat = 100;
        this.updateTopBar();

        if (this.heat >= 100) {
            this.triggerLockdown();
        } else if (this.heat > 80) {
            this.showToast('WARNING: TRACE DETECTED! PURGE LOGS!', 'error');
        }

        // Add a log entry for the activity
        if (!this.systemLogs) this.systemLogs = [];
        this.systemLogs.push({
            time: new Date().toLocaleTimeString(),
            event: `Suspicious Activity Detected (Heat +${amount}%)`,
            risk: 'High'
        });
    }

    decreaseHeat(amount) {
        this.heat -= amount;
        if (this.heat < 0) this.heat = 0;
        this.updateTopBar();
        this.showToast('Trace signature reduced.', 'success');
    }

    triggerLockdown() {
        document.body.innerHTML = `
            <div style="background:#000; color:#f00; height:100vh; display:flex; flex-direction:column; justify-content:center; align-items:center; font-family:'Courier New', monospace; text-align:center; z-index:9999; position:fixed; top:0; left:0; width:100%;">
                <i class="fas fa-exclamation-triangle" style="font-size:5rem; margin-bottom:20px;"></i>
                <h1 style="font-size:4rem; margin:0; text-shadow: 0 0 10px #f00;">SYSTEM COMPROMISED</h1>
                <p style="font-size:1.5rem; letter-spacing:2px; margin-top:20px;">AUTHORITIES NOTIFIED. LOCATION TRACED.</p>
                <div style="margin-top:40px; border:2px solid #f00; padding:20px;">
                    <p>CRITICAL FAIL: OPSEC COMPROMISED</p>
                    <button onclick="location.reload()" style="padding:15px 30px; background:#f00; border:none; color:#000; font-weight:bold; font-size:1.2rem; cursor:pointer; text-transform:uppercase;">INITIATE HARD RESET</button>
                </div>
            </div>
        `;
    }

    updateTopBar() {
        const heatEl = document.querySelector('.heat-meter');
        if (heatEl) {
            heatEl.innerHTML = `HEAT: ${this.heat}%`;
            heatEl.style.color = this.heat > 80 ? '#f00' : (this.heat > 50 ? '#fa0' : '#fff');
        }

        const moneyEl = document.querySelector('.wallet');
        if (moneyEl) moneyEl.innerHTML = `<i class="fab fa-bitcoin"></i> ${this.money} BTC`;
    }

    // --- LOG WIPER APP ---
    renderCleaner() {
        if (!this.systemLogs) {
            this.systemLogs = [
                { time: 'System Boot', event: 'Kernel Loaded', risk: 'Low' },
                { time: 'Network', event: 'Connected to Onion Router', risk: 'Medium' }
            ];
        }

        return `
            <div class="cleaner-container">
                <div class="cleaner-header">
                    <div class="heat-status">
                        <span>CURRENT TRACE LEVEL</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${this.heat}%; background: ${this.heat > 80 ? '#f00' : '#0f0'}"></div>
                        </div>
                        <span style="font-size:1.2rem; font-weight:bold; color:${this.heat > 80 ? '#f00' : '#fff'}">${this.heat}%</span>
                    </div>
                    <button class="purge-btn" onclick="shadowOS.purgeLogs()">
                        <i class="fas fa-biohazard"></i> PURGE LOGS
                    </button>
                </div>
                <div class="log-list">
                    ${this.systemLogs.length === 0 ? '<div class="empty-logs">SYSTEM CLEAN</div>' : ''}
                    ${this.systemLogs.map(log => `
                        <div class="log-row">
                            <span class="log-time">${log.time || 'Now'}</span>
                            <span class="log-event">${log.event}</span>
                            <span class="log-risk ${log.risk.toLowerCase()}">${log.risk}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    purgeLogs() {
        if (this.systemLogs.length === 0) {
            this.showToast('No logs to purge.', 'warning');
            return;
        }

        const btn = document.querySelector('.purge-btn');
        if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SCRUBBING...';

        setTimeout(() => {
            const removed = this.systemLogs.splice(0, 5); // Remove 5 logs at a time
            this.decreaseHeat(removed.length * 5); // Decrease heat based on logs cleared
            this.renderAppRefresh('cleaner');
            this.showToast('Logs Scrubbed. Trace reduced.', 'success');
        }, 1000);
    }

    // --- UNDERGROUND CHAT APP (AI POWERED) ---
    renderChat() {
        if (!this.chatHistory) {
            this.chatHistory = [
                { user: 'System', msg: 'Connecting to Encrypted Uplink...', time: 'Now' }
            ];
            // Initial AI Greeting
            this.sendAiMessage('System', 'Welcome to the Underground. Stay unmatched.');
        }

        return `
            <style>
                .chat-container { display:flex; flex-direction:column; height:100%; font-family:'Consolas', monospace; }
                .chat-history { flex:1; overflow-y:auto; padding:10px; background:rgba(0,0,0,0.5); display:flex; flex-direction:column; gap:8px; }
                .chat-msg { display:flex; gap:10px; font-size:0.9rem; }
                .chat-user { font-weight:bold; color:#00ffcc; min-width:80px; text-align:right; }
                .chat-user.me { color:#f0f; }
                .chat-user.system { color:#fa0; }
                .chat-text { color:#ccc; }
                .chat-input-area { display:flex; padding:10px; border-top:1px solid #333; background:#111; }
                .chat-input-area input { flex:1; background:#222; border:none; color:#fff; padding:8px; outline:none; font-family:inherit; }
                .chat-input-area button { background:#333; color:#fff; border:none; padding:0 15px; cursor:pointer; }
                .chat-input-area button:hover { background:#444; }
            </style>
            <div class="chat-container">
                <div class="chat-history" id="chat-history-box">
                    ${this.chatHistory.map(m => `
                        <div class="chat-msg">
                            <span class="chat-user ${m.user === 'Me' ? 'me' : (m.user === 'System' ? 'system' : '')}">[${m.user}]</span>
                            <span class="chat-text">${m.msg}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="chat-input-area">
                    <input type="text" id="chat-input" placeholder="Say something..." onkeydown="if(event.key==='Enter') shadowOS.sendChatMessage()">
                    <button onclick="shadowOS.sendChatMessage()">SEND</button>
                </div>
            </div>
        `;
    }

    async sendChatMessage() {
        const input = document.getElementById('chat-input');
        if (!input || !input.value.trim()) return;

        const msg = input.value.trim();
        this.chatHistory.push({ user: 'Me', msg: msg, time: new Date().toLocaleTimeString() });
        this.renderAppRefresh('chat');
        input.value = '';

        this.scrollToBottom('chat-history-box');

        // AI Response
        const personas = ['Neo', 'Trinity', 'Morpheus', 'Cypher', 'Tank'];
        const randomPersona = personas[Math.floor(Math.random() * personas.length)];

        try {
            const res = await fetch('http://localhost:5000/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    persona: randomPersona,
                    message: msg,
                    history: this.chatHistory.slice(-5)
                })
            });
            const data = await res.json();

            if (data.success) {
                this.receiveChatMessage(randomPersona, data.response);
            } else {
                this.receiveChatMessage('System', 'Uplink unstable. Message lost.');
            }
        } catch (e) {
            console.error(e);
            this.receiveChatMessage('System', 'Connection Error.');
        }
    }

    receiveChatMessage(user, msg) {
        this.chatHistory.push({ user: user, msg: msg, time: new Date().toLocaleTimeString() });
        this.renderAppRefresh('chat');
        this.scrollToBottom('chat-history-box');
    }

    scrollToBottom(id) {
        setTimeout(() => {
            const el = document.getElementById(id);
            if (el) el.scrollTop = el.scrollHeight;
        }, 50);
    }

    // Helper to send initial AI msg
    sendAiMessage(user, msg) {
        this.receiveChatMessage(user, msg);
    }

    initChatBot() {
        if (this.chatInterval) return;

        // Random banter
        const banter = [
            { user: 'Cypher', msg: 'Anyone got a 0day for the new Bank API?' },
            { user: 'Tank', msg: 'Stay clear of the Grid today. heavy monitoring.' },
            { user: 'Apoc', msg: 'Just compiled a new rootkit. PM me.' },
            { user: 'Mouse', msg: 'I think they found me...' }
        ];

        this.chatInterval = setInterval(() => {
            if (Math.random() > 0.7) {
                const r = banter[Math.floor(Math.random() * banter.length)];
                this.receiveChatMessage(r.user, r.msg);
            }

            // Mission Hints
            if (this.mission.active) {
                if (this.mission.id === 'chimera' && this.mission.step === 1 && Math.random() > 0.8) {
                    this.receiveChatMessage('Handler', 'Hint: The signal is on 315MHz. Adjust your SDR gain.');
                }
                if (this.mission.id === 'payday' && this.mission.step === 1 && Math.random() > 0.8) {
                    this.receiveChatMessage('The Broker', 'Hint: The hash starts with 8f4b. Use hashcat.');
                }
            }

        }, 8000); // Check every 8 seconds
    }

}

// Global Instance
const shadowOS = new ShadowKernel();
window.shadowOS = shadowOS;

// Start Function for Router
function pageShadowOS() {
    setTimeout(() => shadowOS.init(), 100);
    return `<div id="shadow-root"></div>`;
}
window.pageShadowOS = pageShadowOS;
