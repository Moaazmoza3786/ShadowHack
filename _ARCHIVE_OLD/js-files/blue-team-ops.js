/* ==================== BLUE TEAM OPERATIONS CENTER (SIEM) 🛡️ v2.0 ==================== */
/* Enhanced with Threat Intelligence, IOCs, and Detection Rules */

window.BlueTeamOps = {
    // --- STATE ---
    activeTab: 'dashboard',
    selectedIOC: null,

    // --- FIREWALL RULES ---
    firewallRules: [
        { id: 1, type: 'DENY', ip: '192.168.1.100', port: 'Any', reason: 'Brute Force Detected', created: '2024-01-05' },
        { id: 2, type: 'ALLOW', ip: '10.0.0.5', port: '22', reason: 'Admin Access', created: '2024-01-04' },
        { id: 3, type: 'DENY', ip: '45.33.22.11', port: '80', reason: 'SQLi Attempt', created: '2024-01-05' },
        { id: 4, type: 'DENY', ip: '185.147.32.45', port: '443', reason: 'C2 Traffic Detected', created: '2024-01-05' },
        { id: 5, type: 'DENY', ip: '91.240.118.0/24', port: 'Any', reason: 'Known Malicious Range', created: '2024-01-03' }
    ],

    // --- LOGS ---
    logs: [],

    // --- THREAT INTEL FEEDS ---
    threatFeeds: [
        { name: 'AlienVault OTX', status: 'active', lastSync: '2 min ago', iocs: 15420 },
        { name: 'Abuse.ch URLhaus', status: 'active', lastSync: '5 min ago', iocs: 8932 },
        { name: 'Emerging Threats', status: 'active', lastSync: '15 min ago', iocs: 24100 },
        { name: 'VirusTotal', status: 'active', lastSync: '1 min ago', iocs: 45000 },
        { name: 'MISP Community', status: 'active', lastSync: '30 min ago', iocs: 12500 },
        { name: 'ThreatFox', status: 'warning', lastSync: '2 hr ago', iocs: 6780 }
    ],

    // --- IOC DATABASE ---
    iocs: [
        { id: 1, type: 'IP', value: '185.147.32.45', threat: 'Cobalt Strike C2', confidence: 'High', source: 'AlienVault', firstSeen: '2024-01-02', tags: ['apt', 'c2', 'cobalt-strike'] },
        { id: 2, type: 'Domain', value: 'malware-update.xyz', threat: 'Phishing Domain', confidence: 'High', source: 'URLhaus', firstSeen: '2024-01-04', tags: ['phishing', 'trojan'] },
        { id: 3, type: 'Hash', value: '5d41402abc4b2a76b9719d911017c592', threat: 'Emotet Payload', confidence: 'Critical', source: 'ThreatFox', firstSeen: '2024-01-01', tags: ['emotet', 'banking-trojan'] },
        { id: 4, type: 'IP', value: '91.240.118.172', threat: 'REvil Ransomware C2', confidence: 'Critical', source: 'Emerging Threats', firstSeen: '2023-12-28', tags: ['ransomware', 'revil', 'c2'] },
        { id: 5, type: 'Domain', value: 'secure-microsoft-login.com', threat: 'Credential Harvester', confidence: 'High', source: 'MISP', firstSeen: '2024-01-03', tags: ['phishing', 'credentials'] },
        { id: 6, type: 'Hash', value: 'a3f5e9d8c2b1a4f7e8d6c5b4a3f2e1d0', threat: 'LockBit 3.0', confidence: 'Critical', source: 'VirusTotal', firstSeen: '2024-01-05', tags: ['ransomware', 'lockbit'] },
        { id: 7, type: 'URL', value: 'hxxp://evil.com/malware.exe', threat: 'Malware Distribution', confidence: 'Medium', source: 'URLhaus', firstSeen: '2024-01-04', tags: ['dropper', 'malware'] },
        { id: 8, type: 'IP', value: '45.33.22.11', threat: 'SQL Injection Source', confidence: 'High', source: 'Internal', firstSeen: '2024-01-05', tags: ['sqli', 'web-attack'] }
    ],

    // --- DETECTION RULES ---
    detectionRules: [
        { id: 1, name: 'Brute Force SSH', type: 'Sigma', enabled: true, hits: 45, severity: 'High' },
        { id: 2, name: 'Mimikatz Execution', type: 'YARA', enabled: true, hits: 3, severity: 'Critical' },
        { id: 3, name: 'PowerShell Encoded Command', type: 'Sigma', enabled: true, hits: 12, severity: 'Medium' },
        { id: 4, name: 'Lateral Movement SMB', type: 'Sigma', enabled: true, hits: 7, severity: 'High' },
        { id: 5, name: 'DNS Tunneling', type: 'Zeek', enabled: true, hits: 2, severity: 'High' },
        { id: 6, name: 'Ransomware File Extension', type: 'YARA', enabled: false, hits: 0, severity: 'Critical' },
        { id: 7, name: 'Kerberoasting Activity', type: 'Sigma', enabled: true, hits: 8, severity: 'High' },
        { id: 8, name: 'LSASS Memory Access', type: 'Sysmon', enabled: true, hits: 5, severity: 'Critical' }
    ],

    // --- INIT ---
    init() {
        if (this.logs.length === 0) this.generateMockLogs();
        this.render();
    },

    generateMockLogs() {
        const events = [
            { type: 'SSH Failed Login', severity: 'Medium', source: 'auth.log' },
            { type: 'SQL Injection Attempt', severity: 'High', source: 'waf.log' },
            { type: 'Port Scan Detected', severity: 'Low', source: 'firewall.log' },
            { type: 'XSS Payload Blocked', severity: 'Medium', source: 'waf.log' },
            { type: 'Malware Signature Match', severity: 'Critical', source: 'edr.log' },
            { type: 'C2 Beacon Detected', severity: 'Critical', source: 'ndr.log' },
            { type: 'Privilege Escalation', severity: 'High', source: 'sysmon.log' },
            { type: 'Kerberoasting Attempt', severity: 'High', source: 'dc.log' },
            { type: 'Lateral Movement', severity: 'High', source: 'smb.log' },
            { type: 'Data Exfiltration', severity: 'Critical', source: 'proxy.log' }
        ];
        const ips = ['192.168.1.50', '10.0.0.2', '172.16.0.5', '8.8.8.8', '185.147.32.45', '45.33.22.11'];
        const users = ['admin', 'john.doe', 'SYSTEM', 'svc_backup', 'guest'];

        for (let i = 0; i < 30; i++) {
            const evt = events[Math.floor(Math.random() * events.length)];
            this.logs.push({
                id: i,
                time: new Date(Date.now() - Math.random() * 86400000).toLocaleTimeString(),
                date: new Date(Date.now() - Math.random() * 86400000).toLocaleDateString(),
                ip: ips[Math.floor(Math.random() * ips.length)],
                user: users[Math.floor(Math.random() * users.length)],
                event: evt.type,
                severity: evt.severity,
                source: evt.source
            });
        }
        this.logs.sort((a, b) => new Date(b.time) - new Date(a.time));
    },

    // --- RENDER UI ---
    render() {
        const container = document.getElementById('btoc-container');
        if (!container && !document.getElementById('btoc-app')) {
            return `
                <div id="btoc-app" class="btoc-app fade-in">
                    ${this.renderSidebar()}
                    <div id="btoc-content" class="btoc-content">
                        ${this.renderCurrentTab()}
                    </div>
                </div>
                ${this.getStyles()}
            `;
        } else if (document.getElementById('btoc-content')) {
            document.getElementById('btoc-content').innerHTML = this.renderCurrentTab();
            document.querySelectorAll('.btoc-nav-item').forEach(el => el.classList.remove('active'));
            document.querySelector(`.btoc-nav-item[data-tab="${this.activeTab}"]`)?.classList.add('active');
        }
    },

    renderSidebar() {
        const criticalAlerts = this.logs.filter(l => l.severity === 'Critical').length;
        return `
            <div class="btoc-sidebar">
                <div class="btoc-logo"><i class="fas fa-shield-alt"></i> DEFENSE CENTER</div>
                <div class="btoc-nav">
                    <div class="btoc-nav-item ${this.activeTab === 'dashboard' ? 'active' : ''}" data-tab="dashboard" onclick="BlueTeamOps.switchTab('dashboard')">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </div>
                    <div class="btoc-nav-item ${this.activeTab === 'logs' ? 'active' : ''}" data-tab="logs" onclick="BlueTeamOps.switchTab('logs')">
                        <i class="fas fa-list-alt"></i> Log Analysis
                    </div>
                    <div class="btoc-nav-item ${this.activeTab === 'firewall' ? 'active' : ''}" data-tab="firewall" onclick="BlueTeamOps.switchTab('firewall')">
                        <i class="fas fa-fire-alt"></i> Firewall Rules
                    </div>
                    <div class="btoc-nav-item ${this.activeTab === 'intel' ? 'active' : ''}" data-tab="intel" onclick="BlueTeamOps.switchTab('intel')">
                        <i class="fas fa-globe"></i> Threat Intel
                        <span class="nav-badge">${this.iocs.length}</span>
                    </div>
                    <div class="btoc-nav-item ${this.activeTab === 'rules' ? 'active' : ''}" data-tab="rules" onclick="BlueTeamOps.switchTab('rules')">
                        <i class="fas fa-shield-virus"></i> Detection Rules
                    </div>
                </div>
                <div class="btoc-status">
                    <div>System Status: <span class="${criticalAlerts > 0 ? 'text-danger' : 'text-success'}">${criticalAlerts > 0 ? 'ALERT' : 'SECURE'}</span></div>
                    <div style="font-size:0.8rem; color:#666">Critical: ${criticalAlerts} | Uptime: 14d 2h</div>
                </div>
            </div>
        `;
    },

    renderCurrentTab() {
        switch (this.activeTab) {
            case 'dashboard': return this.renderDashboard();
            case 'logs': return this.renderLogs();
            case 'firewall': return this.renderFirewall();
            case 'intel': return this.renderIntel();
            case 'rules': return this.renderRules();
            default: return this.renderDashboard();
        }
    },

    // --- TABS ---
    renderDashboard() {
        const critical = this.logs.filter(l => l.severity === 'Critical').length;
        const high = this.logs.filter(l => l.severity === 'High').length;
        const blocked = this.firewallRules.filter(r => r.type === 'DENY').length;

        return `
            <div class="btoc-dash-grid">
                <!-- METRIC CARDS -->
                <div class="dash-card metric-card critical">
                    <div class="icon"><i class="fas fa-skull-crossbones"></i></div>
                    <div class="data">
                        <h3>Critical Alerts</h3>
                        <span class="val">${critical}</span>
                    </div>
                </div>
                <div class="dash-card metric-card high">
                    <div class="icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="data">
                        <h3>High Severity</h3>
                        <span class="val">${high}</span>
                    </div>
                </div>
                <div class="dash-card metric-card">
                    <div class="icon"><i class="fas fa-ban"></i></div>
                    <div class="data">
                        <h3>IPs Blocked</h3>
                        <span class="val">${blocked}</span>
                    </div>
                </div>
                <div class="dash-card metric-card intel">
                    <div class="icon"><i class="fas fa-database"></i></div>
                    <div class="data">
                        <h3>Active IOCs</h3>
                        <span class="val">${this.iocs.length}</span>
                    </div>
                </div>

                <!-- CHART -->
                <div class="dash-card chart-card">
                    <h3><i class="fas fa-chart-bar me-2"></i>Events / Hour</h3>
                    <div class="chart-bars">
                        ${[40, 60, 30, 80, 50, 45, 70, 55, 35, 90, 65, 40].map((h, i) => `
                            <div class="bar ${h > 70 ? 'high' : ''}" style="height: ${h}%" title="${Math.floor(h / 10)} events"></div>
                        `).join('')}
                    </div>
                    <div class="chart-labels">
                        ${['00', '02', '04', '06', '08', '10', '12', '14', '16', '18', '20', '22'].map(h => `<span>${h}:00</span>`).join('')}
                    </div>
                </div>

                <!-- THREAT FEEDS STATUS -->
                <div class="dash-card feeds-card">
                    <h3><i class="fas fa-rss me-2"></i>Threat Feeds</h3>
                    <div class="feeds-list">
                        ${this.threatFeeds.map(f => `
                            <div class="feed-item">
                                <span class="feed-status ${f.status}"></span>
                                <span class="feed-name">${f.name}</span>
                                <span class="feed-iocs">${(f.iocs / 1000).toFixed(1)}K IOCs</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- RECENT CRITICAL -->
                <div class="dash-card list-card">
                    <h3><i class="fas fa-fire me-2"></i>Critical Events</h3>
                    <div class="event-list">
                        ${this.logs.filter(l => l.severity === 'Critical').slice(0, 5).map(l => `
                            <div class="event-item">
                                <span class="sev-dot critical"></span>
                                <span class="event-type">${l.event}</span>
                                <span class="event-ip">${l.ip}</span>
                                <span class="event-time">${l.time}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderLogs() {
        return `
            <div class="btoc-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-list-alt me-2"></i>Log Analysis</h2>
                    <div class="header-actions">
                        <select class="btoc-select" onchange="BlueTeamOps.filterBySeverity(this.value)">
                            <option value="all">All Severities</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                        <input type="text" placeholder="Search Logs..." class="btoc-input" onkeyup="BlueTeamOps.filterLogs(this.value)">
                    </div>
                </div>
                <div class="log-table-wrapper">
                    <table class="btoc-table full">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Severity</th>
                                <th>Event</th>
                                <th>Source IP</th>
                                <th>User</th>
                                <th>Log Source</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="log-body">
                            ${this.logs.map(l => `
                                <tr class="log-row ${l.severity.toLowerCase()}">
                                    <td>${l.time}</td>
                                    <td><span class="sev-badge ${l.severity.toLowerCase()}">${l.severity}</span></td>
                                    <td>${l.event}</td>
                                    <td><code>${l.ip}</code></td>
                                    <td>${l.user}</td>
                                    <td><span class="source-badge">${l.source}</span></td>
                                    <td>
                                        <button class="btn-action" onclick="BlueTeamOps.blockIp('${l.ip}')" title="Block IP">
                                            <i class="fas fa-ban"></i>
                                        </button>
                                        <button class="btn-action investigate" onclick="BlueTeamOps.investigateIP('${l.ip}')" title="Investigate">
                                            <i class="fas fa-search"></i>
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    },

    renderFirewall() {
        return `
            <div class="btoc-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-fire-alt me-2"></i>Firewall Rules (IPTables)</h2>
                    <button class="btn-primary" onclick="BlueTeamOps.addRulePrompt()"><i class="fas fa-plus"></i> Add Rule</button>
                </div>
                <table class="btoc-table full">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>IP Address</th>
                            <th>Port</th>
                            <th>Reason</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.firewallRules.map(r => `
                            <tr>
                                <td><span class="rule-type ${r.type.toLowerCase()}">${r.type}</span></td>
                                <td><code>${r.ip}</code></td>
                                <td>${r.port}</td>
                                <td>${r.reason}</td>
                                <td>${r.created}</td>
                                <td><button class="btn-del" onclick="BlueTeamOps.deleteRule(${r.id})"><i class="fas fa-trash"></i></button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },

    renderIntel() {
        return `
            <div class="btoc-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-globe me-2"></i>Threat Intelligence</h2>
                    <div class="header-actions">
                        <select class="btoc-select" onchange="BlueTeamOps.filterIOCType(this.value)">
                            <option value="all">All Types</option>
                            <option value="IP">IP Addresses</option>
                            <option value="Domain">Domains</option>
                            <option value="Hash">File Hashes</option>
                            <option value="URL">URLs</option>
                        </select>
                        <button class="btn-primary"><i class="fas fa-sync"></i> Sync Feeds</button>
                    </div>
                </div>

                <!-- FEED STATUS -->
                <div class="intel-feeds-grid">
                    ${this.threatFeeds.map(f => `
                        <div class="intel-feed-card ${f.status}">
                            <div class="feed-header">
                                <span class="status-indicator ${f.status}"></span>
                                <strong>${f.name}</strong>
                            </div>
                            <div class="feed-stats">
                                <span><i class="fas fa-database"></i> ${(f.iocs / 1000).toFixed(1)}K IOCs</span>
                                <span><i class="fas fa-clock"></i> ${f.lastSync}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>

                <!-- IOC TABLE -->
                <h3 class="mt-4"><i class="fas fa-fingerprint me-2"></i>Indicators of Compromise</h3>
                <table class="btoc-table full">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Indicator</th>
                            <th>Threat</th>
                            <th>Confidence</th>
                            <th>Source</th>
                            <th>Tags</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.iocs.map(ioc => `
                            <tr>
                                <td><span class="ioc-type ${ioc.type.toLowerCase()}">${ioc.type}</span></td>
                                <td><code class="ioc-value">${ioc.value}</code></td>
                                <td>${ioc.threat}</td>
                                <td><span class="confidence-badge ${ioc.confidence.toLowerCase()}">${ioc.confidence}</span></td>
                                <td>${ioc.source}</td>
                                <td>${ioc.tags.map(t => `<span class="tag">${t}</span>`).join('')}</td>
                                <td>
                                    <button class="btn-action" onclick="BlueTeamOps.blockIOC(${ioc.id})" title="Block">
                                        <i class="fas fa-ban"></i>
                                    </button>
                                    <button class="btn-action" onclick="navigator.clipboard.writeText('${ioc.value}')" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },

    renderRules() {
        return `
            <div class="btoc-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-shield-virus me-2"></i>Detection Rules</h2>
                    <button class="btn-primary"><i class="fas fa-plus"></i> Add Rule</button>
                </div>
                
                <div class="rules-stats">
                    <div class="rule-stat">
                        <span class="val">${this.detectionRules.filter(r => r.enabled).length}</span>
                        <span class="label">Active Rules</span>
                    </div>
                    <div class="rule-stat">
                        <span class="val">${this.detectionRules.reduce((sum, r) => sum + r.hits, 0)}</span>
                        <span class="label">Total Hits</span>
                    </div>
                    <div class="rule-stat">
                        <span class="val">${this.detectionRules.filter(r => r.severity === 'Critical').length}</span>
                        <span class="label">Critical Rules</span>
                    </div>
                </div>

                <table class="btoc-table full">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Rule Name</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Hits (24h)</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.detectionRules.map(r => `
                            <tr class="${r.enabled ? '' : 'disabled'}">
                                <td>
                                    <label class="switch">
                                        <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="BlueTeamOps.toggleRule(${r.id})">
                                        <span class="slider"></span>
                                    </label>
                                </td>
                                <td>${r.name}</td>
                                <td><span class="rule-type-badge ${r.type.toLowerCase()}">${r.type}</span></td>
                                <td><span class="sev-badge ${r.severity.toLowerCase()}">${r.severity}</span></td>
                                <td><span class="hits-badge">${r.hits}</span></td>
                                <td>
                                    <button class="btn-action" title="Edit"><i class="fas fa-edit"></i></button>
                                    <button class="btn-action" title="View Logs"><i class="fas fa-search"></i></button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.activeTab = tab;
        this.render();
    },

    blockIp(ip) {
        if (confirm(`Add DENY rule for ${ip}?`)) {
            this.firewallRules.push({
                id: Date.now(),
                type: 'DENY',
                ip: ip,
                port: 'Any',
                reason: 'Manual Block from Logs',
                created: new Date().toISOString().split('T')[0]
            });
            this.showToast(`Blocked IP: ${ip}`);
            this.switchTab('firewall');
        }
    },

    blockIOC(id) {
        const ioc = this.iocs.find(i => i.id === id);
        if (ioc && ioc.type === 'IP') {
            this.blockIp(ioc.value);
        } else {
            this.showToast(`Added ${ioc.type} to blocklist: ${ioc.value}`);
        }
    },

    investigateIP(ip) {
        const relatedLogs = this.logs.filter(l => l.ip === ip).length;
        const isIOC = this.iocs.some(i => i.value === ip);
        alert(`Investigation for ${ip}:\n\n• Related Events: ${relatedLogs}\n• Known IOC: ${isIOC ? 'YES ⚠️' : 'No'}\n• Whois: Check abuseipdb.com\n• Reputation: Check virustotal.com`);
    },

    toggleRule(id) {
        const rule = this.detectionRules.find(r => r.id === id);
        if (rule) rule.enabled = !rule.enabled;
        this.render();
    },

    deleteRule(id) {
        if (confirm('Remove this firewall rule?')) {
            this.firewallRules = this.firewallRules.filter(r => r.id !== id);
            this.render();
        }
    },

    addRulePrompt() {
        const ip = prompt("Enter IP to Block/Allow:");
        if (ip) {
            const type = confirm("Allow this IP? (Cancel for DENY)") ? 'ALLOW' : 'DENY';
            this.firewallRules.push({
                id: Date.now(),
                type: type,
                ip: ip,
                port: 'Any',
                reason: 'Manual Entry',
                created: new Date().toISOString().split('T')[0]
            });
            this.render();
        }
    },

    showToast(msg) {
        // Simple toast notification
        const toast = document.createElement('div');
        toast.className = 'btoc-toast';
        toast.innerHTML = `<i class="fas fa-check-circle"></i> ${msg}`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    },

    getStyles() {
        return `
        <style>
            /* BTOC THEME: Dark Blue/Grey */
            .btoc-app { display: flex; height: calc(100vh - 60px); background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
            
            /* SIDEBAR */
            .btoc-sidebar { width: 250px; background: #1e293b; border-right: 1px solid #334155; display: flex; flex-direction: column; }
            .btoc-logo { padding: 20px; font-size: 1.2rem; font-weight: bold; color: #38bdf8; border-bottom: 1px solid #334155; }
            .btoc-nav { flex: 1; padding: 20px 0; }
            .btoc-nav-item { padding: 15px 25px; cursor: pointer; color: #94a3b8; transition: 0.2s; display: flex; gap: 10px; align-items: center; position: relative; }
            .btoc-nav-item:hover { background: #334155; color: #fff; }
            .btoc-nav-item.active { background: #38bdf8; color: #0f172a; font-weight: bold; }
            .nav-badge { position: absolute; right: 15px; background: #ef4444; color: #fff; font-size: 0.7rem; padding: 2px 6px; border-radius: 10px; }
            .btoc-status { padding: 20px; border-top: 1px solid #334155; font-size: 0.9rem; }
            .text-danger { color: #ef4444 !important; }
            .text-success { color: #22c55e !important; }
            
            /* CONTENT */
            .btoc-content { flex: 1; padding: 30px; overflow-y: auto; }
            
            /* DASHBOARD GRID */
            .btoc-dash-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
            .dash-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
            
            .metric-card { display: flex; align-items: center; gap: 20px; }
            .metric-card .icon { font-size: 2rem; color: #38bdf8; opacity: 0.8; }
            .metric-card.critical .icon { color: #ef4444; }
            .metric-card.high .icon { color: #f59e0b; }
            .metric-card.intel .icon { color: #8b5cf6; }
            .metric-card .data h3 { margin: 0; font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }
            .metric-card .data .val { font-size: 2rem; font-weight: bold; color: #fff; }
            
            .chart-card { grid-column: span 2; }
            .chart-bars { display: flex; align-items: flex-end; gap: 8px; height: 120px; padding: 20px 0; }
            .bar { flex: 1; background: #38bdf8; border-radius: 4px 4px 0 0; opacity: 0.7; transition: 0.3s; }
            .bar:hover { opacity: 1; transform: scaleY(1.05); }
            .bar.high { background: #ef4444; }
            .chart-labels { display: flex; justify-content: space-between; font-size: 0.7rem; color: #64748b; }
            
            .feeds-card { grid-column: span 2; }
            .feeds-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 15px; }
            .feed-item { display: flex; align-items: center; gap: 10px; padding: 10px; background: #0f172a; border-radius: 8px; }
            .feed-status { width: 8px; height: 8px; border-radius: 50%; }
            .feed-status.active { background: #22c55e; }
            .feed-status.warning { background: #f59e0b; }
            .feed-name { flex: 1; }
            .feed-iocs { font-size: 0.8rem; color: #64748b; }
            
            .list-card { grid-column: span 2; }
            .event-list { margin-top: 15px; }
            .event-item { display: flex; align-items: center; gap: 15px; padding: 10px; border-bottom: 1px solid #334155; }
            .sev-dot { width: 10px; height: 10px; border-radius: 50%; }
            .sev-dot.critical { background: #ef4444; animation: pulse 1.5s infinite; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
            .event-type { flex: 1; }
            .event-ip { color: #64748b; font-family: monospace; }
            .event-time { font-size: 0.8rem; color: #64748b; }

            /* PANELS */
            .btoc-panel { background: #1e293b; border-radius: 12px; padding: 25px; border: 1px solid #334155; }
            .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .panel-header h2 { margin: 0; }
            .header-actions { display: flex; gap: 10px; }
            
            /* TABLES */
            .btoc-table { width: 100%; border-collapse: collapse; }
            .btoc-table th { text-align: left; padding: 12px; color: #64748b; font-size: 0.8rem; border-bottom: 2px solid #334155; text-transform: uppercase; }
            .btoc-table td { padding: 12px; border-bottom: 1px solid #334155; }
            .btoc-table tr.disabled { opacity: 0.5; }
            .log-row.critical { background: rgba(239,68,68,0.1); }
            
            /* BADGES */
            .sev-badge { padding: 3px 10px; border-radius: 20px; font-weight: bold; font-size: 0.75rem; }
            .sev-badge.critical { background: #ef4444; color: #fff; }
            .sev-badge.high { background: #f59e0b; color: #000; }
            .sev-badge.medium { background: #3b82f6; color: #fff; }
            .sev-badge.low { background: #22c55e; color: #000; }
            
            .rule-type { padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
            .rule-type.deny { background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444; }
            .rule-type.allow { background: rgba(34,197,94,0.2); color: #22c55e; border: 1px solid #22c55e; }
            
            .ioc-type { padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
            .ioc-type.ip { background: #3b82f6; color: #fff; }
            .ioc-type.domain { background: #8b5cf6; color: #fff; }
            .ioc-type.hash { background: #f59e0b; color: #000; }
            .ioc-type.url { background: #ef4444; color: #fff; }
            
            .confidence-badge { padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; }
            .confidence-badge.critical { background: #ef4444; color: #fff; }
            .confidence-badge.high { background: #f59e0b; color: #000; }
            .confidence-badge.medium { background: #3b82f6; color: #fff; }
            
            .tag { display: inline-block; padding: 2px 6px; background: #334155; border-radius: 4px; font-size: 0.7rem; margin: 2px; }
            .source-badge { background: #475569; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }
            
            /* INTEL */
            .intel-feeds-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 25px; }
            .intel-feed-card { background: #0f172a; padding: 15px; border-radius: 10px; border: 1px solid #334155; }
            .intel-feed-card.warning { border-color: #f59e0b; }
            .feed-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
            .status-indicator { width: 10px; height: 10px; border-radius: 50%; background: #22c55e; }
            .status-indicator.warning { background: #f59e0b; }
            .feed-stats { display: flex; justify-content: space-between; font-size: 0.8rem; color: #64748b; }
            
            /* RULES */
            .rules-stats { display: flex; gap: 20px; margin-bottom: 20px; }
            .rule-stat { background: #0f172a; padding: 20px 30px; border-radius: 10px; text-align: center; }
            .rule-stat .val { display: block; font-size: 2rem; font-weight: bold; color: #38bdf8; }
            .rule-stat .label { font-size: 0.8rem; color: #64748b; }
            
            .rule-type-badge { padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; }
            .rule-type-badge.sigma { background: #8b5cf6; color: #fff; }
            .rule-type-badge.yara { background: #ef4444; color: #fff; }
            .rule-type-badge.zeek { background: #22c55e; color: #000; }
            .rule-type-badge.sysmon { background: #3b82f6; color: #fff; }
            
            .hits-badge { background: #334155; padding: 3px 10px; border-radius: 20px; font-size: 0.8rem; }
            
            /* SWITCH */
            .switch { position: relative; display: inline-block; width: 40px; height: 22px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #475569; border-radius: 22px; transition: 0.3s; }
            .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: 0.3s; }
            input:checked + .slider { background: #22c55e; }
            input:checked + .slider:before { transform: translateX(18px); }
            
            /* BUTTONS */
            .btoc-input, .btoc-select { padding: 8px 15px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #fff; }
            .btn-primary { background: #38bdf8; color: #0f172a; border: none; padding: 8px 16px; border-radius: 8px; font-weight: bold; cursor: pointer; display: flex; align-items: center; gap: 8px; }
            .btn-action { background: none; border: none; color: #64748b; cursor: pointer; padding: 5px 8px; border-radius: 4px; }
            .btn-action:hover { background: #334155; color: #fff; }
            .btn-action.investigate { color: #38bdf8; }
            .btn-del { color: #94a3b8; background: none; border: none; cursor: pointer; }
            .btn-del:hover { color: #ef4444; }

            /* TOAST */
            .btoc-toast { position: fixed; bottom: 30px; right: 30px; background: #22c55e; color: #fff; padding: 15px 25px; border-radius: 10px; display: flex; align-items: center; gap: 10px; animation: slideIn 0.3s, fadeOut 0.3s 2.7s; z-index: 9999; }
            @keyframes slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
            @keyframes fadeOut { from { opacity: 1; } to { opacity: 0; } }

            code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }
            .mt-4 { margin-top: 25px; }
            .me-2 { margin-right: 8px; }
        </style>
        `;
    }
};

function pageBlueTeam() {
    BlueTeamOps.init();
    return BlueTeamOps.render();
}
