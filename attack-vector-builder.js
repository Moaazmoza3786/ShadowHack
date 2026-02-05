/* ==================== ATTACK VECTOR BUILDER 🎯 ==================== */
/* Professional Attack Scenario Planning Tool for OSCP/OSEP/EJPT */

window.AttackVectorBuilder = {
    // === STATE ===
    blocks: [],
    connections: [],
    selectedBlock: null,
    draggedBlock: null,
    scenarios: JSON.parse(localStorage.getItem('avb_scenarios') || '[]'),
    currentScenario: null,
    canvas: null,
    nextId: 1,

    // === ATTACK BLOCK LIBRARY ===
    blockLibrary: {
        recon: {
            category: 'Reconnaissance',
            icon: 'fa-search',
            color: '#3b82f6',
            blocks: [
                { id: 'nmap', name: 'Nmap Scan', desc: 'Port scanning and service detection', mitre: 'T1046' },
                { id: 'gobuster', name: 'Gobuster', desc: 'Directory and file enumeration', mitre: 'T1083' },
                { id: 'nikto', name: 'Nikto', desc: 'Web vulnerability scanner', mitre: 'T1595' },
                { id: 'osint', name: 'OSINT', desc: 'Open source intelligence gathering', mitre: 'T1593' },
                { id: 'enum4linux', name: 'Enum4Linux', desc: 'SMB/NetBIOS enumeration', mitre: 'T1135' },
                { id: 'dnsenum', name: 'DNS Enum', desc: 'DNS enumeration and zone transfer', mitre: 'T1590' }
            ]
        },
        initial: {
            category: 'Initial Access',
            icon: 'fa-door-open',
            color: '#ef4444',
            blocks: [
                { id: 'phishing', name: 'Phishing', desc: 'Social engineering attack', mitre: 'T1566' },
                { id: 'exploit_public', name: 'Public Exploit', desc: 'Known vulnerability exploitation', mitre: 'T1190' },
                { id: 'webshell', name: 'Web Shell', desc: 'Upload malicious web shell', mitre: 'T1505.003' },
                { id: 'sqli', name: 'SQL Injection', desc: 'Database manipulation attack', mitre: 'T1190' },
                { id: 'rfi_lfi', name: 'RFI/LFI', desc: 'File inclusion vulnerabilities', mitre: 'T1190' },
                { id: 'default_creds', name: 'Default Creds', desc: 'Try default credentials', mitre: 'T1078' }
            ]
        },
        creds: {
            category: 'Credential Access',
            icon: 'fa-key',
            color: '#f59e0b',
            blocks: [
                { id: 'brute_force', name: 'Brute Force', desc: 'Password cracking attack', mitre: 'T1110' },
                { id: 'cred_dump', name: 'Credential Dump', desc: 'Extract credentials from memory', mitre: 'T1003' },
                { id: 'kerberoast', name: 'Kerberoasting', desc: 'Request service tickets for cracking', mitre: 'T1558.003' },
                { id: 'hashdump', name: 'Hash Dump', desc: 'Extract password hashes', mitre: 'T1003.002' },
                { id: 'mimikatz', name: 'Mimikatz', desc: 'Windows credential extraction', mitre: 'T1003.001' },
                { id: 'responder', name: 'Responder', desc: 'LLMNR/NBT-NS poisoning', mitre: 'T1557.001' }
            ]
        },
        privesc: {
            category: 'Privilege Escalation',
            icon: 'fa-arrow-up',
            color: '#8b5cf6',
            blocks: [
                { id: 'suid', name: 'SUID Exploit', desc: 'Abuse SUID binaries', mitre: 'T1548.001' },
                { id: 'kernel', name: 'Kernel Exploit', desc: 'Exploit kernel vulnerabilities', mitre: 'T1068' },
                { id: 'sudo', name: 'Sudo Abuse', desc: 'Misconfigured sudo permissions', mitre: 'T1548.003' },
                { id: 'token', name: 'Token Impersonation', desc: 'Steal and impersonate tokens', mitre: 'T1134' },
                { id: 'uac_bypass', name: 'UAC Bypass', desc: 'Bypass User Account Control', mitre: 'T1548.002' },
                { id: 'dll_hijack', name: 'DLL Hijacking', desc: 'Exploit DLL search order', mitre: 'T1574.001' }
            ]
        },
        lateral: {
            category: 'Lateral Movement',
            icon: 'fa-arrows-alt',
            color: '#10b981',
            blocks: [
                { id: 'pth', name: 'Pass-the-Hash', desc: 'Authenticate with NTLM hash', mitre: 'T1550.002' },
                { id: 'psexec', name: 'PSExec', desc: 'Remote command execution', mitre: 'T1569.002' },
                { id: 'ssh_pivot', name: 'SSH Pivot', desc: 'Pivot through SSH tunnel', mitre: 'T1021.004' },
                { id: 'wmi', name: 'WMI Exec', desc: 'WMI remote execution', mitre: 'T1047' },
                { id: 'rdp', name: 'RDP Access', desc: 'Remote desktop connection', mitre: 'T1021.001' },
                { id: 'smb_relay', name: 'SMB Relay', desc: 'Relay SMB authentication', mitre: 'T1557.001' }
            ]
        },
        persist: {
            category: 'Persistence',
            icon: 'fa-anchor',
            color: '#ec4899',
            blocks: [
                { id: 'backdoor', name: 'Backdoor', desc: 'Install persistent backdoor', mitre: 'T1505' },
                { id: 'scheduled', name: 'Scheduled Task', desc: 'Create scheduled task/cron', mitre: 'T1053' },
                { id: 'registry', name: 'Registry Key', desc: 'Add registry run key', mitre: 'T1547.001' },
                { id: 'ssh_key', name: 'SSH Key', desc: 'Add authorized SSH key', mitre: 'T1098.004' },
                { id: 'service', name: 'Service Install', desc: 'Install malicious service', mitre: 'T1543.003' },
                { id: 'startup', name: 'Startup Script', desc: 'Modify startup scripts', mitre: 'T1037' }
            ]
        },
        exfil: {
            category: 'Exfiltration',
            icon: 'fa-cloud-upload-alt',
            color: '#06b6d4',
            blocks: [
                { id: 'data_collect', name: 'Data Collection', desc: 'Gather sensitive data', mitre: 'T1005' },
                { id: 'compress', name: 'Compress Data', desc: 'Archive data for exfil', mitre: 'T1560' },
                { id: 'exfil_http', name: 'HTTP Exfil', desc: 'Exfiltrate over HTTP/S', mitre: 'T1048.002' },
                { id: 'exfil_dns', name: 'DNS Exfil', desc: 'Exfiltrate over DNS', mitre: 'T1048.001' },
                { id: 'cloud_upload', name: 'Cloud Upload', desc: 'Upload to cloud storage', mitre: 'T1567.002' },
                { id: 'encrypt', name: 'Encrypt Data', desc: 'Encrypt before exfil', mitre: 'T1486' }
            ]
        }
    },

    // === AI SUGGESTIONS ===
    aiSuggestions: {
        'nmap': ['gobuster', 'nikto', 'enum4linux', 'default_creds'],
        'gobuster': ['sqli', 'rfi_lfi', 'webshell'],
        'sqli': ['webshell', 'cred_dump', 'hashdump'],
        'webshell': ['suid', 'kernel', 'sudo'],
        'phishing': ['mimikatz', 'cred_dump'],
        'brute_force': ['ssh_pivot', 'rdp', 'psexec'],
        'cred_dump': ['pth', 'kerberoast', 'psexec'],
        'mimikatz': ['pth', 'token', 'kerberoast'],
        'suid': ['data_collect', 'backdoor', 'ssh_key'],
        'kernel': ['data_collect', 'backdoor', 'scheduled'],
        'sudo': ['data_collect', 'ssh_key'],
        'pth': ['psexec', 'wmi', 'rdp'],
        'psexec': ['mimikatz', 'cred_dump', 'scheduled'],
        'backdoor': ['data_collect', 'compress'],
        'data_collect': ['compress', 'exfil_http', 'cloud_upload']
    },

    // === RENDER ===
    render() {
        return `
        <style>${this.getStyles()}</style>
        <div class="avb-container">
            ${this.renderHeader()}
            <div class="avb-main">
                ${this.renderBlockLibrary()}
                <div class="avb-canvas-wrapper">
                    <div class="avb-canvas" id="avb-canvas"></div>
                    ${this.renderAIPanel()}
                </div>
                ${this.renderDetailsPanel()}
            </div>
        </div>`;
    },

    renderHeader() {
        return `
        <div class="avb-header">
            <div class="avb-title">
                <i class="fas fa-chess-king"></i>
                <span>Attack Campaign <span class="accent">Manager Pro</span></span>
                <span class="subtitle">Red Team Operations & Planning</span>
            </div>
            <div class="avb-actions">
                <input type="text" id="scenario-name" class="scenario-input" placeholder="Scenario Name..." value="${this.currentScenario?.name || ''}">
                <button onclick="AttackVectorBuilder.showAICampaignModal()" class="avb-btn primary"><i class="fas fa-magic"></i> AI Architect</button>
                <button onclick="AttackVectorBuilder.generateC2Profile()" class="avb-btn"><i class="fas fa-network-wired"></i> C2 Profile</button>
                <button onclick="AttackVectorBuilder.newScenario()" class="avb-btn"><i class="fas fa-plus"></i> New</button>
                <button onclick="AttackVectorBuilder.saveScenario()" class="avb-btn"><i class="fas fa-save"></i> Save</button>
                <button onclick="AttackVectorBuilder.showLoadModal()" class="avb-btn"><i class="fas fa-folder-open"></i> Load</button>
                <button onclick="AttackVectorBuilder.exportMarkdown()" class="avb-btn"><i class="fas fa-file-export"></i> Export</button>
                <button onclick="AttackVectorBuilder.clearCanvas()" class="avb-btn danger"><i class="fas fa-trash"></i> Clear</button>
            </div>
        </div>`;
    },

    renderBlockLibrary() {
        let html = '<div class="avb-library">';
        html += '<h3><i class="fas fa-cubes"></i> Attack Blocks</h3>';

        for (const [key, cat] of Object.entries(this.blockLibrary)) {
            html += `
            <div class="lib-category">
                <div class="lib-cat-header" onclick="this.parentElement.classList.toggle('collapsed')" style="border-left: 3px solid ${cat.color}">
                    <i class="fas ${cat.icon}" style="color: ${cat.color}"></i>
                    <span>${cat.category}</span>
                    <i class="fas fa-chevron-down"></i>
                </div>
                <div class="lib-blocks">
                    ${cat.blocks.map(b => `
                        <div class="lib-block" draggable="true" 
                             ondragstart="AttackVectorBuilder.onDragStart(event, '${key}', '${b.id}')"
                             style="--block-color: ${cat.color}">
                            <span class="block-name">${b.name}</span>
                            <span class="mitre-tag">${b.mitre}</span>
                        </div>
                    `).join('')}
                </div>
            </div>`;
        }
        html += '</div>';
        return html;
    },

    renderAIPanel() {
        return `
        <div class="avb-ai-panel" id="ai-panel">
            <div class="ai-header">
                <i class="fas fa-robot"></i> AI Suggestions
            </div>
            <div class="ai-content" id="ai-suggestions">
                <p class="ai-hint">Add blocks to get AI-powered next step suggestions</p>
            </div>
        </div>`;
    },

    renderDetailsPanel() {
        return `
        <div class="avb-details" id="details-panel">
            <h3><i class="fas fa-info-circle"></i> Block Details & AI Tools</h3>
            <div id="block-details">
                <p class="detail-hint">Select a block to view details or generate templates.</p>
            </div>
        </div>`;
    },

    // === DRAG & DROP ===
    onDragStart(e, category, blockId) {
        this.draggedBlock = { category, blockId };
        e.dataTransfer.setData('text/plain', JSON.stringify({ category, blockId }));
        e.dataTransfer.effectAllowed = 'copy';
    },

    initCanvas() {
        const canvas = document.getElementById('avb-canvas');
        if (!canvas) return;
        this.canvas = canvas;

        canvas.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });

        canvas.addEventListener('drop', (e) => {
            e.preventDefault();
            const data = JSON.parse(e.dataTransfer.getData('text/plain'));
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left - 75;
            const y = e.clientY - rect.top - 30;
            this.addBlockToCanvas(data.category, data.blockId, x, y);
        });

        canvas.addEventListener('click', (e) => {
            if (e.target === canvas) {
                this.deselectAll();
            }
        });

        this.renderCanvasBlocks();
    },

    addBlockToCanvas(category, blockId, x, y) {
        const catData = this.blockLibrary[category];
        const blockData = catData.blocks.find(b => b.id === blockId);
        if (!blockData) return;

        const block = {
            uid: this.nextId++,
            category,
            blockId,
            name: blockData.name,
            desc: blockData.desc,
            mitre: blockData.mitre,
            color: catData.color,
            icon: catData.icon,
            x: Math.max(0, x),
            y: Math.max(0, y),
            notes: ''
        };

        this.blocks.push(block);
        this.renderCanvasBlocks();
        this.updateAISuggestions();
    },

    renderCanvasBlocks() {
        const canvas = document.getElementById('avb-canvas');
        if (!canvas) return;

        // Render connections first (behind blocks)
        let svg = `<svg class="connections-svg" width="100%" height="100%">
            <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                    <polygon points="0 0, 10 3.5, 0 7" fill="#00ff88"/>
                </marker>
            </defs>`;

        this.connections.forEach(conn => {
            const from = this.blocks.find(b => b.uid === conn.from);
            const to = this.blocks.find(b => b.uid === conn.to);
            if (from && to) {
                svg += `<line x1="${from.x + 75}" y1="${from.y + 30}" x2="${to.x + 75}" y2="${to.y + 30}" 
                        stroke="#00ff88" stroke-width="2" marker-end="url(#arrowhead)"/>`;
            }
        });
        svg += '</svg>';

        // Render blocks
        let blocksHtml = svg;
        this.blocks.forEach(b => {
            blocksHtml += `
            <div class="canvas-block ${this.selectedBlock === b.uid ? 'selected' : ''}" 
                 id="block-${b.uid}"
                 style="left: ${b.x}px; top: ${b.y}px; --block-color: ${b.color}"
                 onclick="AttackVectorBuilder.selectBlock(${b.uid})"
                 onmousedown="AttackVectorBuilder.startDrag(event, ${b.uid})">
                <div class="block-header">
                    <i class="fas ${b.icon}"></i>
                    <span>${b.name}</span>
                </div>
                <div class="block-mitre">${b.mitre}</div>
                <div class="block-actions">
                    <button onclick="AttackVectorBuilder.startConnect(${b.uid})" title="Connect"><i class="fas fa-link"></i></button>
                    <button onclick="AttackVectorBuilder.deleteBlock(${b.uid})" title="Delete"><i class="fas fa-times"></i></button>
                </div>
            </div>`;
        });

        canvas.innerHTML = blocksHtml;
    },

    startDrag(e, uid) {
        if (e.target.closest('.block-actions')) return;
        e.preventDefault();

        const block = this.blocks.find(b => b.uid === uid);
        if (!block) return;

        const startX = e.clientX - block.x;
        const startY = e.clientY - block.y;

        const moveHandler = (me) => {
            block.x = me.clientX - startX;
            block.y = me.clientY - startY;
            this.renderCanvasBlocks();
        };

        const upHandler = () => {
            document.removeEventListener('mousemove', moveHandler);
            document.removeEventListener('mouseup', upHandler);
        };

        document.addEventListener('mousemove', moveHandler);
        document.addEventListener('mouseup', upHandler);
    },

    selectBlock(uid) {
        this.selectedBlock = uid;
        this.renderCanvasBlocks();
        this.showBlockDetails(uid);
    },

    deselectAll() {
        this.selectedBlock = null;
        this.renderCanvasBlocks();
        document.getElementById('block-details').innerHTML = '<p class="detail-hint">Select a block to view details</p>';
    },

    showBlockDetails(uid) {
        const block = this.blocks.find(b => b.uid === uid);
        if (!block) return;

        document.getElementById('block-details').innerHTML = `
        <div class="detail-card" style="--block-color: ${block.color}">
            <div class="detail-header">
                <i class="fas ${block.icon}"></i>
                <h4>${block.name}</h4>
            </div>
            <p class="detail-desc">${block.desc}</p>
            <div class="detail-mitre">
                <span>MITRE ATT&CK:</span>
                <a href="https://attack.mitre.org/techniques/${block.mitre.replace('.', '/')}" target="_blank">${block.mitre}</a>
            </div>
            <div class="detail-notes">
                <label>Notes:</label>
                <textarea id="block-notes" placeholder="Add your notes..." 
                    onchange="AttackVectorBuilder.updateBlockNotes(${uid}, this.value)">${block.notes || ''}</textarea>
            </div>
            ${block.blockId === 'phishing' ? `
            <div class="ai-tool-btn">
                 <button onclick="AttackVectorBuilder.generatePhishingTemplate()">
                    <i class="fas fa-envelope-open-text"></i> Generate Phishing Lure (AI)
                 </button>
            </div>` : ''}
        </div>`;
    },

    updateBlockNotes(uid, notes) {
        const block = this.blocks.find(b => b.uid === uid);
        if (block) block.notes = notes;
    },

    deleteBlock(uid) {
        this.blocks = this.blocks.filter(b => b.uid !== uid);
        this.connections = this.connections.filter(c => c.from !== uid && c.to !== uid);
        this.renderCanvasBlocks();
        this.updateAISuggestions();
    },

    // === CONNECTIONS ===
    connectMode: null,

    startConnect(uid) {
        if (this.connectMode === null) {
            this.connectMode = uid;
            document.getElementById(`block-${uid}`).classList.add('connecting');
        } else {
            if (this.connectMode !== uid) {
                this.connections.push({ from: this.connectMode, to: uid });
            }
            document.getElementById(`block-${this.connectMode}`)?.classList.remove('connecting');
            this.connectMode = null;
            this.renderCanvasBlocks();
        }
    },

    // === AI SUGGESTIONS ===
    updateAISuggestions() {
        const panel = document.getElementById('ai-suggestions');
        if (!panel) return;

        if (this.blocks.length === 0) {
            panel.innerHTML = '<p class="ai-hint">Add blocks to get AI-powered next step suggestions</p>';
            return;
        }

        // Get last added block
        const lastBlock = this.blocks[this.blocks.length - 1];
        const suggestions = this.aiSuggestions[lastBlock.blockId] || [];

        if (suggestions.length === 0) {
            panel.innerHTML = `<p class="ai-hint">✓ "${lastBlock.name}" added. Consider your next phase.</p>`;
            return;
        }

        let html = `<p class="ai-context">After <strong>${lastBlock.name}</strong>, consider:</p><div class="ai-suggestions-list">`;

        suggestions.forEach(sug => {
            for (const [key, cat] of Object.entries(this.blockLibrary)) {
                const block = cat.blocks.find(b => b.id === sug);
                if (block) {
                    html += `
                    <div class="ai-suggestion" onclick="AttackVectorBuilder.addSuggestedBlock('${key}', '${sug}')" style="--block-color: ${cat.color}">
                        <i class="fas ${cat.icon}"></i>
                        <span>${block.name}</span>
                        <i class="fas fa-plus add-icon"></i>
                    </div>`;
                    break;
                }
            }
        });

        html += '</div>';
        panel.innerHTML = html;
    },

    addSuggestedBlock(category, blockId) {
        const lastBlock = this.blocks[this.blocks.length - 1];
        const newX = lastBlock ? lastBlock.x + 180 : 50;
        const newY = lastBlock ? lastBlock.y : 50;
        this.addBlockToCanvas(category, blockId, newX, newY);

        // Auto-connect
        if (lastBlock) {
            this.connections.push({ from: lastBlock.uid, to: this.blocks[this.blocks.length - 1].uid });
            this.renderCanvasBlocks();
        }
    },

    // === SAVE/LOAD ===
    newScenario() {
        this.blocks = [];
        this.connections = [];
        this.nextId = 1;
        this.currentScenario = null;
        document.getElementById('scenario-name').value = '';
        this.renderCanvasBlocks();
        this.updateAISuggestions();
    },

    saveScenario() {
        const name = document.getElementById('scenario-name').value.trim() || `Scenario ${Date.now()}`;

        const scenario = {
            id: this.currentScenario?.id || Date.now(),
            name,
            blocks: this.blocks,
            connections: this.connections,
            nextId: this.nextId,
            date: new Date().toLocaleDateString()
        };

        const idx = this.scenarios.findIndex(s => s.id === scenario.id);
        if (idx >= 0) {
            this.scenarios[idx] = scenario;
        } else {
            this.scenarios.push(scenario);
        }

        localStorage.setItem('avb_scenarios', JSON.stringify(this.scenarios));
        this.currentScenario = scenario;

        this.showNotification('Scenario saved successfully!', 'success');
    },

    showLoadModal() {
        const modal = document.createElement('div');
        modal.className = 'avb-modal';
        modal.innerHTML = `
        <div class="avb-modal-content">
            <h3><i class="fas fa-folder-open"></i> Load Scenario</h3>
            <div class="scenarios-list">
                ${this.scenarios.length === 0 ? '<p class="empty">No saved scenarios</p>' :
                this.scenarios.map(s => `
                    <div class="scenario-item" onclick="AttackVectorBuilder.loadScenario(${s.id})">
                        <i class="fas fa-project-diagram"></i>
                        <div class="scenario-info">
                            <strong>${s.name}</strong>
                            <span>${s.blocks.length} blocks · ${s.date}</span>
                        </div>
                        <button onclick="event.stopPropagation(); AttackVectorBuilder.deleteScenario(${s.id})" class="del-btn">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                  `).join('')}
            </div>
            <button onclick="this.closest('.avb-modal').remove()" class="avb-btn">Close</button>
        </div>`;
        document.body.appendChild(modal);
    },

    loadScenario(id) {
        const scenario = this.scenarios.find(s => s.id === id);
        if (!scenario) return;

        this.blocks = scenario.blocks;
        this.connections = scenario.connections;
        this.nextId = scenario.nextId;
        this.currentScenario = scenario;

        document.getElementById('scenario-name').value = scenario.name;
        document.querySelector('.avb-modal')?.remove();

        this.renderCanvasBlocks();
        this.updateAISuggestions();
    },

    deleteScenario(id) {
        this.scenarios = this.scenarios.filter(s => s.id !== id);
        localStorage.setItem('avb_scenarios', JSON.stringify(this.scenarios));
        this.showLoadModal();
    },

    // === EXPORT ===
    exportMarkdown() {
        const name = document.getElementById('scenario-name').value || 'Attack Scenario';
        let md = `# ${name}\n\n`;
        md += `**Generated:** ${new Date().toLocaleString()}\n\n`;
        md += `## Attack Chain\n\n`;

        // Build ordered chain
        const visited = new Set();
        const chain = [];

        // Find starting blocks (no incoming connections)
        const targets = new Set(this.connections.map(c => c.to));
        const starts = this.blocks.filter(b => !targets.has(b.uid));

        const traverse = (block) => {
            if (visited.has(block.uid)) return;
            visited.add(block.uid);
            chain.push(block);

            const nextConns = this.connections.filter(c => c.from === block.uid);
            nextConns.forEach(conn => {
                const nextBlock = this.blocks.find(b => b.uid === conn.to);
                if (nextBlock) traverse(nextBlock);
            });
        };

        starts.forEach(traverse);
        // Add any unconnected blocks
        this.blocks.forEach(b => { if (!visited.has(b.uid)) chain.push(b); });

        chain.forEach((b, i) => {
            md += `### ${i + 1}. ${b.name}\n`;
            md += `- **MITRE ATT&CK:** [${b.mitre}](https://attack.mitre.org/techniques/${b.mitre.replace('.', '/')})\n`;
            md += `- **Description:** ${b.desc}\n`;
            if (b.notes) md += `- **Notes:** ${b.notes}\n`;
            md += '\n';
        });

        // Download
        const blob = new Blob([md], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name.replace(/\s+/g, '_')}.md`;
        a.click();
        URL.revokeObjectURL(url);
    },

    clearCanvas() {
        if (this.blocks.length === 0) return;
        if (confirm('Clear all blocks from canvas?')) {
            this.blocks = [];
            this.connections = [];
            this.renderCanvasBlocks();
            this.updateAISuggestions();
        }
    },

    showNotification(msg, type = 'info') {
        const notif = document.createElement('div');
        notif.className = `avb-notif ${type}`;
        notif.innerHTML = `<i class="fas fa-${type === 'success' ? 'check' : 'info'}-circle"></i> ${msg}`;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 3000);
    },

    // === AI CAMPAIGN ARCHITECT ===
    showAICampaignModal() {
        const modal = document.createElement('div');
        modal.className = 'avb-modal';
        modal.innerHTML = `
        <div class="avb-modal-content">
            <h3><i class="fas fa-magic"></i> AI Campaign Architect</h3>
            <p>Describe your target objective and threat profile.</p>
            <div class="input-group">
                <label>Campaign Name</label>
                <input type="text" id="ai-camp-name" placeholder="e.g. Operation Blackout">
            </div>
            <div class="input-group">
                <label>Objective</label>
                <select id="ai-camp-obj">
                    <option value="ransomware">Ransomware Deployment</option>
                    <option value="espionage">Data Espionage / IP Theft</option>
                    <option value="destruction">System Destruction</option>
                    <option value="persistence">Long-term Persistence</option>
                </select>
            </div>
            <div class="input-group">
                <label>Threat Actor Profile</label>
                <select id="ai-camp-actor">
                    <option value="apt">APT (Nation State)</option>
                    <option value="fin">Financially Motivated (eCrime)</option>
                    <option value="insider">Insider Threat</option>
                </select>
            </div>
            <button onclick="AttackVectorBuilder.generateAICampaign()" class="avb-btn primary" style="width:100%; justify-content:center; margin-top:15px;">
                <i class="fas fa-bolt"></i> Generate Campaign
            </button>
            <button onclick="this.closest('.avb-modal').remove()" class="avb-btn" style="width:100%; justify-content:center; margin-top:10px;">Cancel</button>
        </div>`;
        document.body.appendChild(modal);
    },

    generateAICampaign() {
        const name = document.getElementById('ai-camp-name').value || 'AI Generated Campaign';
        const obj = document.getElementById('ai-camp-obj').value;
        const actor = document.getElementById('ai-camp-actor').value;

        this.newScenario();
        document.getElementById('scenario-name').value = name;
        document.querySelector('.avb-modal')?.remove();

        this.showNotification('AI Architect is building your campaign...', 'info');

        // Logic to build scenario based on params
        setTimeout(() => {
            let chain = [];

            if (actor === 'apt') {
                chain = ['osint', 'phishing', 'webshell', 'privesc', 'cred_dump', 'lateral', 'persistence', 'exfil'];
            } else if (actor === 'fin') {
                chain = ['shodan', 'exploit_public', 'rfi_lfi', 'webshell', 'ransomware'];
            } else {
                chain = ['phishing', 'mimikatz', 'psexec', 'data_collect', 'exfil_http'];
            }

            // Map simple keywords to robust blocks
            // This is a simplified logic for demo, in prod use mapping dict
            const map = {
                'osint': { cat: 'recon', id: 'osint' },
                'shodan': { cat: 'recon', id: 'nmap' }, // fallback
                'phishing': { cat: 'initial', id: 'phishing' },
                'exploit_public': { cat: 'initial', id: 'exploit_public' },
                'rfi_lfi': { cat: 'initial', id: 'rfi_lfi' },
                'webshell': { cat: 'initial', id: 'webshell' },
                'privesc': { cat: 'privesc', id: 'kernel' },
                'cred_dump': { cat: 'creds', id: 'cred_dump' },
                'mimikatz': { cat: 'creds', id: 'mimikatz' },
                'lateral': { cat: 'lateral', id: 'ssh_pivot' },
                'psexec': { cat: 'lateral', id: 'psexec' },
                'persistence': { cat: 'persist', id: 'scheduled' },
                'exfil': { cat: 'exfil', id: 'exfil_http' },
                'exfil_http': { cat: 'exfil', id: 'exfil_http' },
                'ransomware': { cat: 'exfil', id: 'encrypt' },
                'data_collect': { cat: 'exfil', id: 'data_collect' }
            };

            let lastUid = null;
            let startX = 50;
            let startY = 100;

            chain.forEach((key, idx) => {
                const def = map[key];
                if (def) {
                    this.addBlockToCanvas(def.cat, def.id, startX + (idx * 220), startY);
                    const currentBlock = this.blocks[this.blocks.length - 1];
                    if (lastUid) {
                        this.connections.push({ from: lastUid, to: currentBlock.uid });
                    }
                    lastUid = currentBlock.uid;
                }
            });

            this.renderCanvasBlocks();
            this.showNotification('Campaign generated successfully!', 'success');
        }, 1000);
    },

    // === C2 PROFILE GENERATOR ===
    generateC2Profile() {
        const name = document.getElementById('scenario-name').value || 'Campaign';
        const profile = `
# Malleable C2 Profile for ${name}
# Generated by BreachLabs Campaign Manager

set sample_name "${name}_agent";
set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/api/v1/updates";
    client {
        header "Accept" "*/*";
        metadata {
            base64;
            prepend "SESSION=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            print;
        }
    }
}
        `;

        // Download fake profile
        const blob = new Blob([profile], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name.replace(/\s+/g, '_')}_profile.c2`;
        a.click();
        URL.revokeObjectURL(url);
        this.showNotification('C2 Profile generated!', 'success');
    },

    // === PHISHING TEMPLATE ===
    generatePhishingTemplate() {
        alert("Generating phishing lure for this context...\n\nSubject: Urgent: Account Verification Required\n\nDear User,\n\nWe detected unusual activity on your account. Please verify your identity immediately to avoid service interruption.\n\n[Link: malicious-link.com]\n\nIT Security Team");
    },

    // === STYLES ===
    getStyles() {
        return `
        .avb-container { min-height: 100vh; background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%); color: #fff; font-family: 'Rajdhani', sans-serif; }
        
        .avb-header { display: flex; justify-content: space-between; align-items: center; padding: 15px 25px; background: rgba(0,0,0,0.5); border-bottom: 1px solid rgba(0,255,136,0.2); flex-wrap: wrap; gap: 15px; }
        .avb-title { display: flex; align-items: center; gap: 12px; font-size: 1.6rem; font-weight: 700; }
        .avb-title i { color: #00ff88; font-size: 1.8rem; }
        .avb-title .accent { color: #00ff88; }
        .avb-title .subtitle { font-size: 0.85rem; color: rgba(255,255,255,0.5); margin-left: 15px; }
        
        .avb-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        .scenario-input { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 8px 15px; border-radius: 6px; width: 180px; }
        .avb-btn { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 8px 15px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }
        .avb-btn:hover { background: rgba(255,255,255,0.1); }
        .avb-btn.primary { background: rgba(0,255,136,0.2); border-color: #00ff88; }
        .avb-btn.primary:hover { background: rgba(0,255,136,0.3); }
        .avb-btn.danger { border-color: #ef4444; }
        .avb-btn.danger:hover { background: rgba(239,68,68,0.2); }
        
        .avb-main { display: grid; grid-template-columns: 220px 1fr 280px; height: calc(100vh - 70px); }
        
        .avb-library { background: rgba(0,0,0,0.3); border-right: 1px solid rgba(255,255,255,0.1); overflow-y: auto; padding: 15px; }
        .avb-library h3 { font-size: 1rem; margin-bottom: 15px; color: rgba(255,255,255,0.7); display: flex; align-items: center; gap: 8px; }
        
        .lib-category { margin-bottom: 10px; }
        .lib-cat-header { display: flex; align-items: center; gap: 10px; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 8px; cursor: pointer; }
        .lib-cat-header:hover { background: rgba(255,255,255,0.05); }
        .lib-cat-header .fa-chevron-down { margin-left: auto; transition: transform 0.2s; }
        .lib-category.collapsed .fa-chevron-down { transform: rotate(-90deg); }
        .lib-category.collapsed .lib-blocks { display: none; }
        
        .lib-blocks { padding: 8px 0 0 15px; }
        .lib-block { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; margin: 4px 0; background: rgba(var(--block-color-rgb, 255,255,255), 0.05); border-left: 3px solid var(--block-color); border-radius: 4px; cursor: grab; transition: all 0.2s; }
        .lib-block:hover { background: rgba(var(--block-color-rgb, 255,255,255), 0.1); transform: translateX(3px); }
        .lib-block:active { cursor: grabbing; }
        .block-name { font-size: 0.9rem; }
        .mitre-tag { font-size: 0.7rem; color: rgba(255,255,255,0.4); background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px; }
        
        .avb-canvas-wrapper { position: relative; display: flex; flex-direction: column; }
        .avb-canvas { flex: 1; background: rgba(0,0,0,0.2); background-image: radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px); background-size: 20px 20px; position: relative; overflow: auto; }
        
        .connections-svg { position: absolute; top: 0; left: 0; pointer-events: none; }
        
        .canvas-block { position: absolute; width: 150px; background: rgba(0,0,0,0.6); border: 2px solid var(--block-color); border-radius: 10px; cursor: move; transition: box-shadow 0.2s; }
        .canvas-block:hover { box-shadow: 0 0 20px rgba(var(--block-color-rgb, 0,255,136), 0.3); }
        .canvas-block.selected { box-shadow: 0 0 25px rgba(0,255,136,0.5); border-color: #00ff88; }
        .canvas-block.connecting { animation: pulse-connect 1s infinite; }
        
        @keyframes pulse-connect { 0%, 100% { box-shadow: 0 0 10px rgba(0,255,136,0.3); } 50% { box-shadow: 0 0 25px rgba(0,255,136,0.6); } }
        
        .block-header { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .block-header i { color: var(--block-color); }
        .block-header span { font-weight: 600; font-size: 0.85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .block-mitre { padding: 5px 12px; font-size: 0.75rem; color: rgba(255,255,255,0.5); }
        .block-actions { display: flex; justify-content: flex-end; gap: 5px; padding: 5px; }
        .block-actions button { background: rgba(255,255,255,0.05); border: none; color: rgba(255,255,255,0.5); width: 24px; height: 24px; border-radius: 4px; cursor: pointer; }
        .block-actions button:hover { background: rgba(255,255,255,0.1); color: #fff; }
        
        .avb-ai-panel { background: rgba(0,255,136,0.05); border-top: 1px solid rgba(0,255,136,0.2); padding: 15px; max-height: 180px; overflow-y: auto; }
        .ai-header { display: flex; align-items: center; gap: 10px; font-weight: 600; color: #00ff88; margin-bottom: 10px; }
        .ai-hint { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
        .ai-context { color: rgba(255,255,255,0.7); font-size: 0.9rem; margin-bottom: 10px; }
        .ai-suggestions-list { display: flex; flex-wrap: wrap; gap: 8px; }
        .ai-suggestion { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(0,0,0,0.3); border: 1px solid var(--block-color); border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .ai-suggestion:hover { background: rgba(var(--block-color-rgb, 0,255,136), 0.2); }
        .ai-suggestion i { color: var(--block-color); }
        .ai-suggestion .add-icon { margin-left: auto; opacity: 0.5; }
        
        .avb-details { background: rgba(0,0,0,0.3); border-left: 1px solid rgba(255,255,255,0.1); padding: 20px; overflow-y: auto; }
        .avb-details h3 { font-size: 1rem; margin-bottom: 15px; color: rgba(255,255,255,0.7); display: flex; align-items: center; gap: 8px; }
        .detail-hint { color: rgba(255,255,255,0.4); font-size: 0.9rem; }
        
        .detail-card { background: rgba(0,0,0,0.3); border: 1px solid var(--block-color); border-radius: 10px; padding: 20px; }
        .detail-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
        .detail-header i { font-size: 1.5rem; color: var(--block-color); }
        .detail-header h4 { font-size: 1.2rem; margin: 0; }
        .detail-desc { color: rgba(255,255,255,0.7); font-size: 0.9rem; margin-bottom: 15px; }
        .detail-mitre { background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 6px; margin-bottom: 15px; }
        .detail-mitre span { color: rgba(255,255,255,0.5); margin-right: 10px; }
        .detail-mitre a { color: #00ff88; text-decoration: none; }
        .detail-notes label { display: block; color: rgba(255,255,255,0.5); margin-bottom: 8px; }
        .detail-notes textarea { width: 100%; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 10px; border-radius: 6px; min-height: 100px; resize: vertical; }
        
        .avb-modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 9999; }
        .avb-modal-content { background: #1a1a2e; border: 1px solid rgba(0,255,136,0.3); border-radius: 15px; padding: 25px; width: 400px; max-height: 80vh; overflow-y: auto; }
        .avb-modal-content h3 { margin-bottom: 20px; display: flex; align-items: center; gap: 10px; color: #00ff88; }
        .scenarios-list { margin-bottom: 20px; }
        .scenarios-list .empty { color: rgba(255,255,255,0.4); text-align: center; padding: 20px; }
        .scenario-item { display: flex; align-items: center; gap: 12px; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; }
        .scenario-item:hover { background: rgba(0,255,136,0.1); }
        .scenario-item i { color: #00ff88; }
        .scenario-info { flex: 1; }
        .scenario-info strong { display: block; }
        .scenario-info span { font-size: 0.8rem; color: rgba(255,255,255,0.5); }
        .del-btn { background: none; border: none; color: rgba(255,255,255,0.3); cursor: pointer; padding: 5px; }
        .del-btn:hover { color: #ef4444; }
        
        .avb-notif { position: fixed; top: 20px; right: 20px; padding: 15px 25px; background: rgba(0,0,0,0.9); border: 1px solid rgba(0,255,136,0.3); border-radius: 8px; display: flex; align-items: center; gap: 10px; z-index: 10000; animation: slideIn 0.3s; }
        .avb-notif.success { border-color: #00ff88; }
        .avb-notif.success i { color: #00ff88; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        
        @media (max-width: 1200px) {
            .avb-main { grid-template-columns: 180px 1fr 220px; }
        }
        @media (max-width: 900px) {
            .avb-main { grid-template-columns: 1fr; grid-template-rows: auto 1fr auto; }
            .avb-library, .avb-details { max-height: 200px; }
        }
        
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 5px; color: #ccc; font-size: 0.9rem; }
        .input-group input, .input-group select { width: 100%; padding: 10px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); color: #fff; border-radius: 6px; outline: none; }
        .ai-tool-btn { margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1); }
        .ai-tool-btn button { width: 100%; padding: 10px; background: rgba(0,255,136,0.1); border: 1px solid #00ff88; color: #00ff88; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .ai-tool-btn button:hover { background: rgba(0,255,136,0.2); }
        `;
    }
};

// Page function
function pageAttackBuilder() {
    setTimeout(() => AttackVectorBuilder.initCanvas(), 100);
    return AttackVectorBuilder.render();
}
window.pageAttackBuilder = pageAttackBuilder;
