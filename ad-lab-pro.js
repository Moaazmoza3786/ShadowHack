/* ==================== ACTIVE DIRECTORY LAB PRO 🏢 ==================== */
/* Advanced AD Forest Enumeration & Exploitation Simulator */

window.AdLabPro = {
    state: {
        activeModule: 'forest',
        findings: [],
        scanned: false
    },

    init() {
        this.state = {
            activeModule: 'forest',
            findings: [],
            scanned: false
        };
    },

    render() {
        return `
        <div class="ad-app fade-in">
            <div class="ad-sidebar">
                <div class="ad-logo"><i class="fas fa-network-wired"></i> AD MASTER <span class="pro-badge">PRO</span></div>
                <div class="ad-nav">
                    <div class="nav-item ${this.state.activeModule === 'forest' ? 'active' : ''}" onclick="AdLabPro.switchModule('forest')">
                        <i class="fas fa-sitemap"></i> Forest Topology
                    </div>
                    <div class="nav-item ${this.state.activeModule === 'enum' ? 'active' : ''}" onclick="AdLabPro.switchModule('enum')">
                        <i class="fas fa-users-cog"></i> User Enum
                    </div>
                    <div class="nav-item ${this.state.activeModule === 'gpo' ? 'active' : ''}" onclick="AdLabPro.switchModule('gpo')">
                        <i class="fas fa-file-invoice"></i> GPO Auditor
                    </div>
                    <div class="nav-item ${this.state.activeModule === 'kerberoast' ? 'active' : ''}" onclick="AdLabPro.switchModule('kerberoast')">
                        <i class="fas fa-fire"></i> Kerberoasting
                    </div>
                </div>
            </div>

            <div class="ad-main">
                <div id="ad-viewport" class="ad-viewport">
                    ${this.renderModule()}
                </div>
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderModule() {
        switch (this.state.activeModule) {
            case 'forest': return this.renderForest();
            case 'enum': return this.renderEnum();
            case 'gpo': return this.renderGPO();
            case 'kerberoast': return this.renderKerberoast();
            default: return this.renderForest();
        }
    },

    renderForest() {
        return `
            <div class="module-view fade-in">
                <div class="view-header">
                    <h2><i class="fas fa-sitemap"></i> Forest Topology Visualization</h2>
                    <p>Understanding Trust Relationships and Domain Layout.</p>
                </div>
                <div class="forest-map">
                    <div class="domain root">
                        <div class="dom-label">MEGACORP.LOCAL (Root)</div>
                        <div class="trust-line"></div>
                        <div class="children">
                            <div class="domain child">DEV.MEGACORP.LOCAL</div>
                            <div class="domain child">HR.MEGACORP.LOCAL</div>
                        </div>
                    </div>
                    <div class="forest-details">
                        <div class="detail-card">
                            <label>Domain Functional Level</label>
                            <span>Windows Server 2019</span>
                        </div>
                        <div class="detail-card">
                            <label>Trust Type</label>
                            <span>Parent-Child (Two-way transitive)</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderEnum() {
        return `
            <div class="module-view fade-in">
                <div class="view-header">
                    <h2><i class="fas fa-users-cog"></i> Advanced User Enumeration</h2>
                    <p>Automated discovery of high-value targets and stale accounts.</p>
                </div>
                <div class="enum-actions">
                    <button class="btn-primary" onclick="AdLabPro.runEnum()">Run PowerView Enum</button>
                </div>
                <div class="enum-results" id="enum-results">
                    ${this.state.scanned ? this.renderEnumResults() : '<div class="placeholder">Click run to start enumeration...</div>'}
                </div>
            </div>
        `;
    },

    renderEnumResults() {
        return `
            <table class="ad-table">
                <thead>
                    <tr><th>Username</th><th>Groups</th><th>Last Logon</th><th>Risk</th></tr>
                </thead>
                <tbody>
                    <tr><td>Admin-SVC</td><td>Domain Admins</td><td>2026-01-01</td><td><span class="risk high">HIGH</span></td></tr>
                    <tr><td>j.doe</td><td>Domain Users</td><td>2025-12-30</td><td><span class="risk low">LOW</span></td></tr>
                    <tr><td>backup_user</td><td>Backup Operators</td><td>2025-11-15</td><td><span class="risk med">MED</span></td></tr>
                </tbody>
            </table>
        `;
    },

    renderGPO() {
        return `
            <div class="module-view fade-in">
                <div class="view-header">
                    <h2><i class="fas fa-file-invoice"></i> Group Policy Auditor</h2>
                    <p>Detecting insecure GPO settings like GPP passwords or broad permissions.</p>
                </div>
                <div class="gpo-list">
                    <div class="gpo-card risk-high">
                        <div class="gpo-name">Default Domain Policy</div>
                        <div class="gpo-finding">Finding: Insecure Password Complexity (Disabled)</div>
                        <button class="btn-exploit" onclick="alert('Analysis path: GPO extraction -> XML Parsing -> Detection')">Analyze Path</button>
                    </div>
                    <div class="gpo-card risk-med">
                        <div class="gpo-name">Workstation Management</div>
                        <div class="gpo-finding">Finding: GPP Password found in groups.xml (Simulated)</div>
                    </div>
                </div>
            </div>
        `;
    },

    renderKerberoast() {
        return `
            <div class="module-view fade-in">
                <div class="view-header">
                    <h2><i class="fas fa-fire"></i> Kerberoasting Simulator</h2>
                    <p>Extracting TGS tickets for Service Accounts to crack offline.</p>
                </div>
                <div class="terminal-mock">
                    <div class="term-output" id="ad-term">
                        <div>PS C:\\> Get-DomainUser -SPN</div>
                        <div>SamAccountName : SQL-SVC</div>
                        <div>ServicePrincipalName : MSSQLSvc/sql01.megacorp.local:1433</div>
                        <div>PS C:\\> <span class="cursor">_</span></div>
                    </div>
                </div>
                <button class="btn-primary" onclick="AdLabPro.runKerberoast()">Request TGS Tickets</button>
            </div>
        `;
    },

    runEnum() {
        this.state.scanned = true;
        this.switchModule('enum');
    },

    runKerberoast() {
        const term = document.getElementById('ad-term');
        if (term) {
            term.innerHTML += `<div>PS C:\\> Request-SPNTicket -SPN MSSQLSvc/...</div>
            <div class="hash">$krb5tgs$23$*SQL-SVC$... [TICKET EXTRACTED]</div>
            <div>PS C:\\> <span class="cursor">_</span></div>`;
            alert("TGS Ticket Captured! Ready for Hashcat.");
        }
    },

    switchModule(mod) {
        this.state.activeModule = mod;
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .ad-app { display: flex; height: calc(100vh - 60px); background: #0b0c14; color: #e0e0e0; font-family: 'Inter', sans-serif; }
            
            .ad-sidebar { width: 260px; background: #161925; border-right: 1px solid #2d2d3a; display: flex; flex-direction: column; }
            .ad-logo { padding: 25px; font-weight: 800; color: #fff; font-size: 1.1rem; border-bottom: 1px solid #1c1c26; }
            .pro-badge { background: #6366f1; color: #fff; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; vertical-align: middle; margin-left: 5px; }
            
            .ad-nav { flex: 1; padding: 15px 0; }
            .nav-item { padding: 12px 25px; cursor: pointer; color: #888; transition: 0.3s; display: flex; align-items: center; gap: 12px; font-size: 0.95rem; }
            .nav-item:hover { color: #fff; background: rgba(255,255,255,0.03); }
            .nav-item.active { color: #fff; background: rgba(99,102,241,0.1); border-left: 3px solid #6366f1; }
            
            .ad-main { flex: 1; padding: 40px; overflow-y: auto; }
            .ad-viewport { max-width: 1000px; margin: 0 auto; }
            
            .view-header { margin-bottom: 35px; }
            .view-header h2 { margin: 0; font-size: 1.8rem; color: #fff; }
            .view-header p { color: #666; margin-top: 8px; }

            .forest-map { display: flex; flex-direction: column; align-items: center; padding: 40px 0; }
            .domain { background: #1c1c26; padding: 15px 30px; border: 1px solid #2d2d3a; border-radius: 8px; text-align: center; }
            .domain.root { border-top: 4px solid #6366f1; width: 300px; }
            .trust-line { height: 40px; width: 2px; background: #2d2d3a; margin: 0 auto; }
            .children { display: flex; gap: 40px; }
            .domain.child { width: 200px; }

            .forest-details { display: flex; gap: 20px; margin-top: 50px; }
            .detail-card { background: #161925; padding: 15px 25px; border-radius: 12px; border: 1px solid #2d2d3a; flex: 1; }
            .detail-card label { display: block; font-size: 0.75rem; color: #555; text-transform: uppercase; margin-bottom: 5px; }
            .detail-card span { font-weight: 700; color: #fff; }

            .ad-table { width: 100%; border-collapse: collapse; margin-top: 25px; }
            .ad-table th { text-align: left; padding: 15px; background: rgba(255,255,255,0.02); color: #888; font-size: 0.85rem; }
            .ad-table td { padding: 15px; border-bottom: 1px solid #1c1c26; }
            .risk { font-size: 0.75rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; }
            .risk.high { background: rgba(239, 68, 68, 0.15); color: #f87171; }
            .risk.med { background: rgba(245, 158, 11, 0.15); color: #fb923c; }
            .risk.low { background: rgba(34, 197, 94, 0.15); color: #4ade80; }

            .gpo-list { display: grid; gap: 20px; }
            .gpo-card { background: #161925; padding: 25px; border-radius: 16px; border: 1px solid #2d2d3a; border-left: 6px solid #333; }
            .gpo-card.risk-high { border-left-color: #ef4444; }
            .gpo-card.risk-med { border-left-color: #fbbf24; }
            .gpo-name { font-weight: 800; color: #fff; margin-bottom: 10px; }
            .gpo-finding { color: #888; font-size: 0.9rem; margin-bottom: 15px; }
            
            .terminal-mock { background: #000; color: #4ade80; padding: 25px; border-radius: 12px; font-family: 'JetBrains Mono', monospace; min-height: 250px; margin-bottom: 25px; border: 1px solid #1c1c26; font-size: 0.9rem; }
            .hash { color: #ef4444; word-break: break-all; margin-top: 10px; }
            .cursor { animation: blink 1s infinite; border-left: 2px solid #4ade80; margin-left: 5px; }
            @keyframes blink { 50% { opacity: 0; } }

            .btn-primary { background: #6366f1; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; }
            .btn-exploit { background: transparent; border: 1px solid #333; color: #888; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
            .btn-exploit:hover { border-color: #6366f1; color: #fff; }

            .placeholder { text-align: center; color: #333; padding: 100px 0; font-style: italic; }
        </style>`;
    }
};

function pageAdLabPro() {
    AdLabPro.init();
    return AdLabPro.render();
}
