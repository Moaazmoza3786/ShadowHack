/* ==================== ZERO-TRUST NETWORK SIMULATION 🛡️ ==================== */
/* Modern architectural simulation for Identity-Aware access control */

window.ZeroTrustLab = {
    state: {
        activeTab: 'visualizer',
        segmentStatus: {
            app: 'Unverfied',
            db: 'Isolated',
            user: 'Authorized'
        },
        logs: []
    },

    init() {
        this.state = {
            activeTab: 'visualizer',
            segmentStatus: {
                app: 'Unverified',
                db: 'Isolated',
                user: 'Authorized'
            },
            logs: []
        };
    },

    render() {
        return `
        <div class="zt-app fade-in">
            <div class="zt-header">
                <div>
                    <h1><i class="fas fa-fingerprint"></i> Zero-Trust Architecture Lab</h1>
                    <p>Micro-segmentation & Identity-Aware Proxy (IAP) Simulation</p>
                </div>
                <div class="header-status">
                    <div class="status-indicator">
                        <span class="pulse green"></span> Global Policy: Enforced
                    </div>
                </div>
            </div>

            <div class="zt-tabs">
                <button class="zt-tab ${this.state.activeTab === 'visualizer' ? 'active' : ''}" onclick="ZeroTrustLab.switchTab('visualizer')">Policy Visualizer</button>
                <button class="zt-tab ${this.state.activeTab === 'proxy' ? 'active' : ''}" onclick="ZeroTrustLab.switchTab('proxy')">Identity Proxy</button>
                <button class="zt-tab ${this.state.activeTab === 'logs' ? 'active' : ''}" onclick="ZeroTrustLab.switchTab('logs')">Access Logs</button>
            </div>

            <div class="zt-content">
                ${this.renderTabContent()}
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderTabContent() {
        switch (this.state.activeTab) {
            case 'visualizer': return this.renderVisualizer();
            case 'proxy': return this.renderProxy();
            case 'logs': return this.renderLogs();
            default: return this.renderVisualizer();
        }
    },

    renderVisualizer() {
        return `
            <div class="visualizer-view fade-in">
                <div class="zt-grid">
                    <div class="segment untrusted">
                        <div class="s-header">Public Internet</div>
                        <div class="node"><i class="fas fa-globe"></i> External User</div>
                    </div>
                    
                    <div class="connector"><i class="fas fa-chevron-right"></i></div>

                    <div class="segment iam">
                        <div class="s-header">Identity Proxy</div>
                        <div class="node iap ${this.state.segmentStatus.app === 'Verified' ? 'active' : ''}">
                            <i class="fas fa-key"></i> ${this.state.segmentStatus.app === 'Verified' ? 'JWT Verified' : 'Awaiting Auth'}
                        </div>
                    </div>

                    <div class="connector"><i class="fas fa-chevron-right"></i></div>

                    <div class="segment internal">
                        <div class="s-header">App Segment</div>
                        <div class="node app-server"><i class="fas fa-server"></i> Payroll-App</div>
                    </div>

                    <div class="connector"><i class="fas fa-lock"></i></div>

                    <div class="segment data">
                        <div class="s-header">Micro-segment</div>
                        <div class="node db-server"><i class="fas fa-database"></i> DB-Secure</div>
                    </div>
                </div>

                <div class="zt-actions">
                    <div class="action-card">
                        <h3>Test Policy Propagation</h3>
                        <p>Simulate a request from an untrusted device to the secure DB segment.</p>
                        <button class="btn-zt" onclick="ZeroTrustLab.runTest()">Initiate Request</button>
                    </div>
                </div>
            </div>
        `;
    },

    renderProxy() {
        return `
            <div class="proxy-view fade-in">
                <div class="proxy-header">
                    <h2>Bearer Token Inspection</h2>
                    <p>Simulating JWT verification and environment context checking.</p>
                </div>
                <div class="proxy-controls">
                    <div class="jwt-mock">
                        <div class="jwt-header">JWT Header (RS256)</div>
                        <code class="json">{"alg": "RS256", "typ": "JWT"}</code>
                        <div class="jwt-payload">Payload Claims</div>
                        <code class="json">{
  "sub": "admin-account",
  "scope": "payroll:read",
  "iat": 1704480000,
  "mfa": "true",
  "risk_score": 12
}</code>
                    </div>
                    <div class="proxy-actions">
                        <button class="btn-zt" onclick="ZeroTrustLab.verifyToken()">Verify Token</button>
                        <button class="btn-zt danger" onclick="ZeroTrustLab.simulateAttack()">Simulate Token Theft</button>
                    </div>
                </div>
            </div>
        `;
    },

    renderLogs() {
        return `
            <div class="logs-view fade-in">
                <div class="log-table">
                    <div class="log-row header">
                        <span>Timestamp</span><span>Source IP</span><span>Identity</span><span>Action</span><span>Status</span>
                    </div>
                    ${this.state.logs.length === 0 ? '<div class="empty-log">Log stream initialized...</div>' : this.state.logs.map(l => `
                        <div class="log-row">
                            <span>${l.time}</span>
                            <span>${l.ip}</span>
                            <span>${l.user}</span>
                            <span>${l.action}</span>
                            <span class="${l.status.toLowerCase()}">${l.status}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    switchTab(tab) {
        this.state.activeTab = tab;
        this.renderAll();
    },

    runTest() {
        this.addLog("External-User", "Attempted Connection", "DENIED", "192.168.1.5");
        alert("Policy Enforced: Request from untrusted segment BLOCKED by micro-segmentation rules.");
    },

    verifyToken() {
        this.state.segmentStatus.app = 'Verified';
        this.addLog("admin-account", "Token Verified", "ALLOWED", "10.0.5.22");
        this.switchTab('visualizer');
        setTimeout(() => alert("Identity Verified. Proxy has granted temporary access to payroll-app segment."), 100);
    },

    simulateAttack() {
        this.addLog("Unknown", "Expired Token Playback", "BLOCKED", "45.1.55.2");
        alert("Alert Triggered: Identity-Aware Proxy detected an expired or tampered token. Session terminated.");
    },

    addLog(user, action, status, ip) {
        const time = new Date().toLocaleTimeString();
        this.state.logs.unshift({ time, user, action, status, ip });
    },

    renderAll() {
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .zt-app { padding: 40px; color: #e0e0e0; font-family: 'Inter', sans-serif; background: #0f111a; min-height: 100%; box-sizing: border-box; }
            .zt-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 1px solid #1c1c26; padding-bottom: 25px; }
            .zt-header h1 { margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 15px; }
            .zt-header p { margin: 8px 0 0; color: #6366f1; font-weight: 500; }
            
            .header-status { background: #161925; padding: 10px 20px; border-radius: 12px; border: 1px solid #2d2d3a; font-size: 0.9rem; font-weight: 700; color: #fff; }
            .pulse { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 10px; }
            .pulse.green { background: #22c55e; box-shadow: 0 0 10px #22c55e; animation: pulse-green 2s infinite; }
            @keyframes pulse-green { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }

            .zt-tabs { display: flex; gap: 15px; margin-bottom: 30px; }
            .zt-tab { background: #161925; border: 1px solid #2d2d3a; color: #888; padding: 12px 25px; border-radius: 8px; cursor: pointer; transition: 0.3s; font-weight: 600; }
            .zt-tab:hover { color: #fff; border-color: #6366f1; }
            .zt-tab.active { background: #6366f1; color: #fff; border-color: #6366f1; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3); }

            .zt-grid { display: flex; justify-content: center; align-items: center; gap: 15px; margin-bottom: 50px; padding: 40px; background: rgba(22, 25, 37, 0.4); border-radius: 20px; border: 1px solid #1c1c26; }
            .segment { background: #161925; padding: 20px; border-radius: 15px; width: 160px; text-align: center; border: 1px solid #2d2d3a; position: relative; }
            .s-header { font-size: 0.75rem; color: #555; text-transform: uppercase; margin-bottom: 15px; font-weight: 800; border-bottom: 1px solid #2d2d3a; padding-bottom: 8px; }
            .node { padding: 15px; background: #0b0c14; border-radius: 10px; font-size: 0.9rem; border: 1px solid #1c1c26; color: #fff; }
            .node.iap.active { color: #4ade80; border-color: #4ade80; background: rgba(74, 222, 128, 0.05); }
            
            .connector { color: #2d2d3a; font-size: 1.2rem; }
            .connector .fa-lock { color: #f87171; }

            .zt-actions { max-width: 600px; margin: 0 auto; }
            .action-card { background: #161925; padding: 30px; border-radius: 16px; border: 1px solid #2d2d3a; text-align: center; }
            .btn-zt { background: #6366f1; color: #fff; border: none; padding: 12px 30px; border-radius: 10px; font-weight: 700; cursor: pointer; transition: 0.3s; margin: 10px; }
            .btn-zt:hover { background: #4f46e5; transform: translateY(-2px); }
            .btn-zt.danger { background: #ef4444; }

            .jwt-mock { background: #0b0c14; padding: 25px; border-radius: 12px; border: 1px solid #2d2d3a; font-family: 'JetBrains Mono', monospace; line-height: 1.5; margin-bottom: 30px; }
            .jwt-header { color: #6366f1; font-weight: bold; margin-bottom: 5px; }
            .jwt-payload { color: #f43f5e; font-weight: bold; margin-top: 20px; margin-bottom: 5px; }
            .json { color: #4ade80; display: block; white-space: pre-wrap; font-size: 0.9rem; border-left: 2px solid #222; padding-left: 15px; }

            .log-table { background: #161925; border-radius: 12px; border: 1px solid #2d2d3a; overflow: hidden; }
            .log-row { display: grid; grid-template-columns: 150px 150px 150px 1fr 100px; padding: 15px 25px; border-bottom: 1px solid #1c1c26; font-size: 0.85rem; }
            .log-row.header { background: rgba(255,255,255,0.02); color: #555; text-transform: uppercase; font-weight: 800; font-size: 0.75rem; }
            .log-row:last-child { border-bottom: none; }
            .denied { color: #ef4444; font-weight: bold; }
            .allowed { color: #22c55e; font-weight: bold; }
            .blocked { color: #f59e0b; font-weight: bold; }
        </style>`;
    }
};

function pageZeroTrustLab() {
    ZeroTrustLab.init();
    return ZeroTrustLab.render();
}
