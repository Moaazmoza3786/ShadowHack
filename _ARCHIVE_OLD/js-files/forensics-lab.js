/* ==================== FORENSICS INVESTIGATION LAB 🔍💻 ==================== */
/* Disk Analysis, Memory Forensics & Investigation Challenges */

window.ForensicsLab = {
    // --- STATE ---
    currentTab: 'cases',
    selectedCase: null,
    solvedCases: JSON.parse(localStorage.getItem('forensics_solved') || '[]'),

    // --- CASES DATA ---
    cases: [
        {
            id: 'disk-1',
            name: 'Deleted Evidence',
            difficulty: 'Easy',
            points: 50,
            category: 'Disk Forensics',
            description: 'Recover a deleted file from the disk image.',
            scenario: 'A suspect deleted important files before seizure. Recover the password file.',
            tools: ['Autopsy', 'FTK Imager', 'PhotoRec'],
            evidence: [
                { type: 'file', name: 'recovered_passwords.txt', content: 'admin:FLAG{R3C0V3R3D_D4T4}' }
            ],
            answer: 'FLAG{R3C0V3R3D_D4T4}'
        },
        {
            id: 'memory-1',
            name: 'RAM Dump Analysis',
            difficulty: 'Medium',
            points: 100,
            category: 'Memory Forensics',
            description: 'Analyze a memory dump to find running processes.',
            scenario: 'Extract suspicious process information from the memory dump.',
            tools: ['Volatility', 'Rekall', 'MemProcFS'],
            evidence: [
                { type: 'process', name: 'evil.exe', pid: '1337', connections: '10.0.0.50:4444' },
                { type: 'registry', name: 'Run Key', value: 'C:\\Users\\Public\\evil.exe' }
            ],
            answer: 'FLAG{M3M0RY_4N4LY515}'
        },
        {
            id: 'logs-1',
            name: 'Log Investigation',
            difficulty: 'Easy',
            points: 50,
            category: 'Log Analysis',
            description: 'Analyze Windows Event logs to find the intrusion.',
            scenario: 'Find the IP address that performed the brute force attack.',
            tools: ['Event Viewer', 'LogParser', 'Splunk'],
            evidence: [
                { type: 'log', time: '2024-01-15 03:45:12', event: '4625 - Failed Login', user: 'Administrator', ip: '192.168.1.200' },
                { type: 'log', time: '2024-01-15 03:45:13', event: '4625 - Failed Login', user: 'Administrator', ip: '192.168.1.200' },
                { type: 'log', time: '2024-01-15 03:47:55', event: '4624 - Successful Login', user: 'Administrator', ip: '192.168.1.200' }
            ],
            answer: '192.168.1.200'
        },
        {
            id: 'network-1',
            name: 'PCAP Investigation',
            difficulty: 'Medium',
            points: 100,
            category: 'Network Forensics',
            description: 'Analyze network capture to find exfiltrated data.',
            scenario: 'A malicious actor exfiltrated data via DNS. Find the encoded message.',
            tools: ['Wireshark', 'NetworkMiner', 'Zeek'],
            evidence: [
                { type: 'dns', query: 'RkxBR3tETlNfM3hGMWx0cjR0MTBufQ==.evil.com', answer: '127.0.0.1' }
            ],
            answer: 'FLAG{DNS_3xF1ltr4t10n}'
        },
        {
            id: 'malware-1',
            name: 'Ransomware Incident',
            difficulty: 'Hard',
            points: 200,
            category: 'Incident Response',
            description: 'Investigate a ransomware attack and find the decryption key.',
            scenario: 'The company was hit by ransomware. Find the hardcoded key in the malware sample.',
            tools: ['IDA Pro', 'Ghidra', 'x64dbg'],
            evidence: [
                { type: 'string', offset: '0x00401234', value: 'AES_KEY=SuperSecret123!' },
                { type: 'registry', name: 'Ransom Note', value: 'Your files are encrypted. Pay 1 BTC.' }
            ],
            answer: 'SuperSecret123!'
        }
    ],

    // --- TOOLS ---
    tools: [
        { name: 'Autopsy', icon: 'fa-hard-drive', desc: 'Disk image analysis' },
        { name: 'Volatility', icon: 'fa-memory', desc: 'Memory forensics' },
        { name: 'Wireshark', icon: 'fa-network-wired', desc: 'Network capture analysis' },
        { name: 'Ghidra', icon: 'fa-bug', desc: 'Reverse engineering' },
        { name: 'FTK Imager', icon: 'fa-clone', desc: 'Disk imaging' },
        { name: 'Splunk', icon: 'fa-chart-line', desc: 'Log analysis' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="forensics-app fade-in">
                <div class="forensics-header">
                    <div class="header-left">
                        <h1><i class="fas fa-search-plus"></i> Forensics Investigation Lab</h1>
                        <p class="subtitle">Digital Evidence Analysis & Incident Response</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat"><span class="val">${this.solvedCases.length}/${this.cases.length}</span><span class="label">Cases Solved</span></div>
                        <div class="stat"><span class="val">${this.getTotalPoints()}</span><span class="label">Points</span></div>
                    </div>
                </div>

                <div class="forensics-tabs">
                    <div class="tab ${this.currentTab === 'cases' ? 'active' : ''}" onclick="ForensicsLab.switchTab('cases')">
                        <i class="fas fa-folder-open"></i> Active Cases
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="ForensicsLab.switchTab('tools')">
                        <i class="fas fa-toolbox"></i> Forensics Toolkit
                    </div>
                    <div class="tab ${this.currentTab === 'methodology' ? 'active' : ''}" onclick="ForensicsLab.switchTab('methodology')">
                        <i class="fas fa-book"></i> Methodology
                    </div>
                </div>

                <div class="forensics-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'cases': return this.renderCases();
            case 'tools': return this.renderTools();
            case 'methodology': return this.renderMethodology();
            default: return '';
        }
    },

    renderCases() {
        return `
            <div class="cases-container">
                <div class="cases-list">
                    ${this.cases.map(c => {
            const solved = this.solvedCases.includes(c.id);
            return `
                            <div class="case-card ${solved ? 'solved' : ''} ${this.selectedCase === c.id ? 'active' : ''}" onclick="ForensicsLab.selectCase('${c.id}')">
                                <div class="case-icon ${c.category.toLowerCase().replace(' ', '-')}">
                                    ${solved ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-folder"></i>'}
                                </div>
                                <div class="case-info">
                                    <h4>${c.name}</h4>
                                    <span class="case-category">${c.category}</span>
                                </div>
                                <div class="case-meta">
                                    <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                                    <span class="pts">${c.points} pts</span>
                                </div>
                            </div>
                        `;
        }).join('')}
                </div>
                ${this.selectedCase ? this.renderCaseDetail() : `
                    <div class="no-case">
                        <i class="fas fa-folder-open"></i>
                        <p>Select a case to investigate</p>
                    </div>
                `}
            </div>
        `;
    },

    renderCaseDetail() {
        const c = this.cases.find(cs => cs.id === this.selectedCase);
        if (!c) return '';
        const solved = this.solvedCases.includes(c.id);

        return `
            <div class="case-detail">
                <div class="case-header">
                    <h2><i class="fas fa-file-alt"></i> Case: ${c.name}</h2>
                    <div class="case-badges">
                        <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                        <span class="cat">${c.category}</span>
                    </div>
                </div>

                <div class="case-scenario">
                    <h3><i class="fas fa-info-circle"></i> Scenario</h3>
                    <p>${c.scenario}</p>
                </div>

                <div class="case-description">
                    <h3><i class="fas fa-tasks"></i> Objective</h3>
                    <p>${c.description}</p>
                </div>

                <div class="case-tools">
                    <h3><i class="fas fa-tools"></i> Recommended Tools</h3>
                    <div class="tools-list">
                        ${c.tools.map(t => `<span class="tool-tag">${t}</span>`).join('')}
                    </div>
                </div>

                <div class="evidence-section">
                    <h3><i class="fas fa-search"></i> Evidence Found</h3>
                    <div class="evidence-table">
                        ${c.evidence.map(e => `
                            <div class="evidence-row">
                                <span class="evid-type">${e.type.toUpperCase()}</span>
                                <span class="evid-name">${e.name || e.query || e.event || e.offset}</span>
                                <code class="evid-value">${e.content || e.value || e.pid || e.ip || e.answer || ''}</code>
                            </div>
                        `).join('')}
                    </div>
                </div>

                ${solved ? `
                    <div class="solved-banner"><i class="fas fa-trophy"></i> Case Closed! +${c.points} pts</div>
                ` : `
                    <div class="answer-section">
                        <h3><i class="fas fa-flag"></i> Submit Finding</h3>
                        <div class="answer-form">
                            <input type="text" id="forensics-answer" placeholder="Enter your answer/flag...">
                            <button onclick="ForensicsLab.submitAnswer()"><i class="fas fa-paper-plane"></i> Submit</button>
                        </div>
                    </div>
                `}
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-overview">
                <h2><i class="fas fa-toolbox"></i> Forensics Toolkit</h2>
                <p class="tools-intro">Essential tools for digital forensics investigations</p>
                <div class="tools-grid">
                    ${this.tools.map(t => `
                        <div class="tool-card">
                            <i class="fas ${t.icon}"></i>
                            <h4>${t.name}</h4>
                            <p>${t.desc}</p>
                        </div>
                    `).join('')}
                </div>
                <div class="commands-section">
                    <h3><i class="fas fa-terminal"></i> Quick Commands</h3>
                    <div class="command-group">
                        <h4>Volatility (Memory)</h4>
                        <code>vol.py -f memory.dmp --profile=Win10x64 pslist</code>
                        <code>vol.py -f memory.dmp --profile=Win10x64 netscan</code>
                        <code>vol.py -f memory.dmp --profile=Win10x64 cmdline</code>
                    </div>
                    <div class="command-group">
                        <h4>Strings & File Carving</h4>
                        <code>strings -n 10 file.bin | grep -i password</code>
                        <code>foremost -i disk.dd -o output/</code>
                        <code>binwalk -e firmware.bin</code>
                    </div>
                </div>
            </div>
        `;
    },

    renderMethodology() {
        return `
            <div class="methodology-section">
                <h2><i class="fas fa-book"></i> Forensics Methodology</h2>
                <div class="method-grid">
                    <div class="method-card">
                        <div class="step-num">1</div>
                        <h3>Identification</h3>
                        <p>Identify and recognize an incident. Document everything.</p>
                    </div>
                    <div class="method-card">
                        <div class="step-num">2</div>
                        <h3>Preservation</h3>
                        <p>Secure the crime scene. Create forensic images. Maintain chain of custody.</p>
                    </div>
                    <div class="method-card">
                        <div class="step-num">3</div>
                        <h3>Collection</h3>
                        <p>Collect evidence from all sources: disk, memory, network, logs.</p>
                    </div>
                    <div class="method-card">
                        <div class="step-num">4</div>
                        <h3>Examination</h3>
                        <p>Systematically examine collected data using appropriate tools.</p>
                    </div>
                    <div class="method-card">
                        <div class="step-num">5</div>
                        <h3>Analysis</h3>
                        <p>Analyze findings to draw conclusions. Correlate evidence.</p>
                    </div>
                    <div class="method-card">
                        <div class="step-num">6</div>
                        <h3>Reporting</h3>
                        <p>Document findings in a clear, detailed report for stakeholders.</p>
                    </div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    selectCase(id) {
        this.selectedCase = id;
        this.reRender();
    },

    submitAnswer() {
        const c = this.cases.find(cs => cs.id === this.selectedCase);
        const input = document.getElementById('forensics-answer').value.trim();

        if (input === c.answer || input.toUpperCase() === c.answer.toUpperCase()) {
            if (!this.solvedCases.includes(c.id)) {
                this.solvedCases.push(c.id);
                localStorage.setItem('forensics_solved', JSON.stringify(this.solvedCases));
            }
            this.showNotification('🎉 Case Solved! +' + c.points + ' pts', 'success');
            this.reRender();
        } else {
            this.showNotification('❌ Incorrect finding. Keep investigating!', 'error');
        }
    },

    getTotalPoints() {
        return this.cases.filter(c => this.solvedCases.includes(c.id))
            .reduce((sum, c) => sum + c.points, 0);
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `forensics-notif ${type}`;
        n.innerHTML = msg;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    },

    reRender() {
        const app = document.querySelector('.forensics-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .forensics-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a28 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            .forensics-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .forensics-header h1 { margin: 0; color: #3498db; font-size: 1.8rem; }
            .forensics-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats { display: flex; gap: 20px; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(52,152,219,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #3498db; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            .forensics-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #3498db; color: #fff; }

            /* CASES */
            .cases-container { display: grid; grid-template-columns: 320px 1fr; gap: 25px; }
            .cases-list { display: flex; flex-direction: column; gap: 10px; }
            .case-card { display: flex; align-items: center; gap: 12px; padding: 15px; background: rgba(255,255,255,0.03); border-radius: 10px; cursor: pointer; transition: 0.2s; border: 1px solid transparent; }
            .case-card:hover { background: rgba(255,255,255,0.08); }
            .case-card.active { border-color: #3498db; background: rgba(52,152,219,0.1); }
            .case-card.solved .case-icon { background: rgba(46,204,113,0.2); color: #2ecc71; }
            .case-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; background: rgba(52,152,219,0.2); color: #3498db; }
            .case-info { flex: 1; }
            .case-info h4 { margin: 0; color: #fff; }
            .case-category { font-size: 0.8rem; color: #888; }
            .case-meta { display: flex; flex-direction: column; gap: 5px; }
            
            .diff { padding: 3px 10px; border-radius: 10px; font-size: 0.7rem; font-weight: bold; }
            .diff.easy { background: #2ecc71; color: #000; }
            .diff.medium { background: #f39c12; color: #000; }
            .diff.hard { background: #e74c3c; color: #fff; }
            .pts { font-size: 0.75rem; color: #ffd700; }

            .no-case { text-align: center; padding: 80px; color: #555; }
            .no-case i { font-size: 3rem; margin-bottom: 15px; }

            /* CASE DETAIL */
            .case-detail { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .case-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 15px; }
            .case-header h2 { margin: 0; color: #3498db; }
            .case-badges { display: flex; gap: 10px; }
            .cat { background: rgba(52,152,219,0.2); color: #3498db; padding: 3px 10px; border-radius: 10px; font-size: 0.75rem; }

            .case-scenario, .case-description, .case-tools, .evidence-section, .answer-section { margin-bottom: 20px; }
            .case-scenario h3, .case-description h3, .case-tools h3, .evidence-section h3, .answer-section h3 { color: #3498db; font-size: 1rem; margin: 0 0 10px; }
            .case-scenario p, .case-description p { color: #aaa; }
            .tools-list { display: flex; flex-wrap: wrap; gap: 8px; }
            .tool-tag { background: rgba(255,255,255,0.1); padding: 5px 12px; border-radius: 15px; font-size: 0.8rem; }

            .evidence-table { background: #0a0a12; border-radius: 10px; overflow: hidden; }
            .evidence-row { display: grid; grid-template-columns: 100px 1fr 1fr; gap: 15px; padding: 12px 15px; border-bottom: 1px solid #222; }
            .evid-type { background: rgba(52,152,219,0.2); color: #3498db; padding: 3px 8px; border-radius: 5px; font-size: 0.7rem; text-align: center; }
            .evid-name { color: #fff; }
            .evid-value { color: #2ecc71; font-family: monospace; }

            .solved-banner { background: #2ecc71; padding: 15px; border-radius: 10px; text-align: center; color: #fff; font-weight: bold; }
            .answer-form { display: flex; gap: 10px; }
            .answer-form input { flex: 1; padding: 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .answer-form button { padding: 12px 20px; background: #3498db; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

            /* TOOLS */
            .tools-overview h2 { color: #3498db; margin: 0 0 10px; }
            .tools-intro { color: #888; margin-bottom: 20px; }
            .tools-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .tool-card { background: rgba(255,255,255,0.03); padding: 20px; border-radius: 12px; text-align: center; border: 1px solid transparent; transition: 0.2s; }
            .tool-card:hover { border-color: #3498db; }
            .tool-card i { font-size: 2rem; color: #3498db; margin-bottom: 10px; }
            .tool-card h4 { margin: 0 0 5px; color: #fff; }
            .tool-card p { margin: 0; color: #666; font-size: 0.8rem; }

            .commands-section h3 { color: #3498db; margin: 0 0 15px; }
            .command-group { margin-bottom: 20px; }
            .command-group h4 { color: #888; margin: 0 0 10px; font-size: 0.9rem; }
            .command-group code { display: block; background: #0a0a12; padding: 10px 15px; border-radius: 5px; margin-bottom: 8px; color: #2ecc71; font-family: monospace; font-size: 0.85rem; }

            /* METHODOLOGY */
            .methodology-section h2 { color: #3498db; margin: 0 0 20px; }
            .method-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
            .method-card { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; position: relative; }
            .step-num { position: absolute; top: -10px; left: 20px; background: #3498db; color: #fff; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; }
            .method-card h3 { margin: 10px 0 10px; color: #fff; }
            .method-card p { margin: 0; color: #888; }

            .forensics-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 9999; animation: slideIn 0.3s ease; }
            .forensics-notif.success { background: #2ecc71; color: #fff; }
            .forensics-notif.error { background: #e74c3c; color: #fff; }
            @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

            @media (max-width: 900px) { .cases-container { grid-template-columns: 1fr; } }
        </style>
        `;
    }
};

function pageForensicsLab() {
    return ForensicsLab.render();
}
