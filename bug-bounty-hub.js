/* ==================== BUG BOUNTY RECON HUB 🐞🎯 ==================== */

window.BugBountyHub = {
    // --- STATE ---
    targets: [
        { id: 1, name: 'HackerOne Public', scope: '*.hackerone-user-content.com', status: 'Active', assets: 12, progress: 35 },
        { id: 2, name: 'Google VRP', scope: '*.google.com', status: 'Paused', assets: 1540, progress: 10 },
        { id: 3, name: 'Mega Corp', scope: 'app.megacorp.com', status: 'Active', assets: 5, progress: 80 }
    ],
    activeTargetId: null,

    // --- INIT ---
    init() {
        this.activeTargetId = this.targets[0].id; // Default Select first
        this.render();
    },

    // --- RENDER UI ---
    render() {
        const activeTarget = this.targets.find(t => t.id === parseInt(this.activeTargetId));

        return `
            <div class="bb-app fade-in">
                <!-- SIDEBAR: TARGETS -->
                <div class="bb-sidebar">
                    <div class="bb-logo"><i class="fas fa-crosshairs"></i> BUG BOUNTY HUB</div>
                    <div class="bb-add-btn" onclick="BugBountyHub.addTarget()">
                        <i class="fas fa-plus"></i> New Target
                    </div>
                    <div class="bb-target-list">
                        ${this.targets.map(t => `
                            <div class="bb-target-item ${t.id === parseInt(this.activeTargetId) ? 'active' : ''}" onclick="BugBountyHub.switchTarget(${t.id})">
                                <div class="t-name">${t.name}</div>
                                <div class="t-scope">${t.scope}</div>
                                <div class="t-meta">
                                    <span class="status ${t.status.toLowerCase()}">${t.status}</span>
                                    <span>${t.assets} Assets</span>
                                </div>
                                <div class="progress-bar-sm"><div class="fill" style="width:${t.progress}%"></div></div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- MAIN: RECON DASHBOARD -->
                <div class="bb-main">
                    <div class="bb-header">
                        <div class="header-info">
                            <h1>${activeTarget.name}</h1>
                            <p class="scope-badge">${activeTarget.scope}</p>
                        </div>
                        <div class="header-actions">
                            <button class="btn-tool" onclick="BugBountyHub.runSubfinder()"><i class="fas fa-satellite-dish"></i> Run Subfinder</button>
                            <button class="btn-tool" onclick="BugBountyHub.runPortScan()"><i class="fas fa-network-wired"></i> Scan Ports</button>
                        </div>
                    </div>

                    <div class="bb-grid">
                        <!-- ASSET LIST -->
                        <div class="bb-panel assets-panel">
                            <h3><i class="fas fa-list"></i> Discovered Assets</h3>
                            <div class="asset-table-wrapper">
                                <table class="bb-table">
                                    <thead>
                                        <tr>
                                            <th>Subdomain</th>
                                            <th>IP</th>
                                            <th>Tech Stack</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${this.getMockAssets(activeTarget.id).map(a => `
                                            <tr>
                                                <td><i class="fas fa-globe"></i> ${a.domain}</td>
                                                <td>${a.ip}</td>
                                                <td>${a.tech}</td>
                                                <td><span class="http-status s-${a.status}">${a.status}</span></td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- VULN CHECKLIST -->
                        <div class="bb-panel checklist-panel">
                            <h3><i class="fas fa-tasks"></i> Methodology Checklist</h3>
                            <div class="checklist-container">
                                ${this.getChecklist(activeTarget.id).map(c => `
                                    <label class="check-item">
                                        <input type="checkbox" ${c.done ? 'checked' : ''} onchange="BugBountyHub.toggleCheck(${c.id})">
                                        <span class="checkmark"></span>
                                        <div class="check-content">
                                            <div class="c-title">${c.title}</div>
                                            <div class="c-desc">${c.desc}</div>
                                        </div>
                                    </label>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    // --- MOCK DATA LOGIC ---
    getMockAssets(targetId) {
        if (targetId === 1) { // HackerOne
            return [
                { domain: 'api.hackerone.com', ip: '104.16.2.1', tech: 'Nginx, RoR', status: 200 },
                { domain: 'docs.hackerone.com', ip: '199.232.2.1', tech: 'Gatsby', status: 200 },
                { domain: 'staging.hackerone.com', ip: '10.0.5.2', tech: 'Nginx', status: 403 },
                { domain: 'dev.hackerone-user-content.com', ip: '52.33.22.11', tech: 'AWS S3', status: 404 }
            ];
        } else if (targetId === 2) {
            return [
                { domain: 'mail.google.com', ip: '172.217.1.1', tech: 'GSE', status: 200 },
                { domain: 'admin-test.google.com', ip: '172.217.2.2', tech: 'GSE', status: 403 }
            ];
        }
        return [{ domain: 'app.target.com', ip: '127.0.0.1', tech: 'Unknown', status: 200 }];
    },

    getChecklist(targetId) {
        // In real app, this would be saved per target
        return [
            { id: 1, title: 'Subdomain Enumeration', desc: 'Run subfinder, assetfinder, amass.', done: true },
            { id: 2, title: 'HTTP Probing (httpx)', desc: 'Check for live hosts and status codes.', done: true },
            { id: 3, title: 'Check for Subdomain Takeover', desc: 'Identify 404 CNAME records (S3, Github).', done: false },
            { id: 4, title: 'Fuzzing Endpoints', desc: 'Run ffuf on main app /api/ endpoints.', done: false },
            { id: 5, title: 'Test for IDOR', desc: 'Change User IDs in API requests.', done: false },
            { id: 6, title: 'Test for XSS', desc: 'Inject Polyglots in input fields.', done: false }
        ];
    },

    // --- ACTIONS ---
    switchTarget(id) {
        this.activeTargetId = id;
        this.renderSimulated();
    },

    renderSimulated() {
        const app = document.querySelector('.bb-app');
        if (app) app.outerHTML = this.render();
    },

    addTarget() {
        const name = prompt("Enter Target Name (e.g., Yahoo)");
        if (name) {
            this.targets.push({
                id: Date.now(),
                name: name,
                scope: `*.${name.toLowerCase().replace(/\s/g, '')}.com`,
                status: 'New',
                assets: 0,
                progress: 0
            });
            this.renderSimulated();
        }
    },

    runSubfinder() {
        this.showToast("🚀 Starting Subfinder...", "info");
        setTimeout(() => this.showToast("✅ Found 12 new subdomains!", "success"), 2000);
    },

    runPortScan() {
        this.showToast("🔎 Starting Naabu Port Scan...", "info");
        setTimeout(() => this.showToast("⚠️ Open Ports: 80, 443, 8080", "warning"), 2500);
    },

    toggleCheck(id) {
        // Placeholder for saving state
        this.showToast("Progress Updated", "success");
    },

    showToast(msg, type) {
        // Simple alert replacement or integrating with existing toast system if available
        // Assuming console log for now or simple UI if needed, but alert is annoying.
        // Let's create a temporary UI toast
        const div = document.createElement('div');
        div.innerText = msg;
        div.style.position = 'fixed';
        div.style.bottom = '20px';
        div.style.right = '20px';
        div.style.padding = '10px 20px';
        div.style.background = type === 'success' ? '#00cc66' : (type === 'warning' ? '#ffaa00' : '#333');
        div.style.color = '#fff';
        div.style.borderRadius = '5px';
        div.style.zIndex = '9999';
        document.body.appendChild(div);
        setTimeout(() => div.remove(), 3000);
    },

    getStyles() {
        return `
        <style>
            .bb-app { display: flex; height: calc(100vh - 60px); background: #121212; color: #e0e0e0; font-family: 'Inter', sans-serif; }
            
            /* SIDEBAR */
            .bb-sidebar { width: 280px; background: #1a1a1a; border-right: 1px solid #333; display: flex; flex-direction: column; }
            .bb-logo { padding: 20px; font-size: 1.2rem; font-weight: 800; color: #ff9f43; border-bottom: 1px solid #333; letter-spacing: 1px; }
            .bb-add-btn { margin: 15px 20px; padding: 10px; border: 1px dashed #555; text-align: center; cursor: pointer; color: #888; border-radius: 6px; transition: 0.2s; }
            .bb-add-btn:hover { border-color: #ff9f43; color: #ff9f43; background: rgba(255, 159, 67, 0.1); }
            
            .bb-target-list { flex: 1; overflow-y: auto; padding-bottom: 20px; }
            .bb-target-item { padding: 15px 20px; border-bottom: 1px solid #252525; cursor: pointer; transition: 0.2s; border-left: 3px solid transparent; }
            .bb-target-item:hover { background: #222; }
            .bb-target-item.active { background: #252525; border-left-color: #ff9f43; }
            
            .t-name { font-weight: bold; font-size: 1rem; color: #fff; margin-bottom: 4px; }
            .t-scope { font-size: 0.8rem; color: #888; margin-bottom: 8px; font-family: monospace; }
            .t-meta { display: flex; justify-content: space-between; font-size: 0.75rem; color: #666; margin-bottom: 8px; }
            
            .status { padding: 2px 6px; border-radius: 4px; font-weight: bold; }
            .status.active { background: rgba(0, 204, 102, 0.2); color: #00cc66; }
            .status.paused { background: rgba(255, 170, 0, 0.2); color: #ffaa00; }
            .status.new { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }

            .progress-bar-sm { height: 4px; background: #333; border-radius: 2px; overflow: hidden; }
            .progress-bar-sm .fill { height: 100%; background: #ff9f43; }

            /* MAIN */
            .bb-main { flex: 1; padding: 30px; display: flex; flex-direction: column; overflow-y: auto; }
            
            .bb-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 30px; }
            .bb-header h1 { margin: 0 0 10px 0; font-size: 2rem; color: #fff; }
            .scope-badge { display: inline-block; background: #222; padding: 5px 10px; border-radius: 4px; color: #aaa; font-family: monospace; border: 1px solid #333; }
            
            .btn-tool { background: #222; border: 1px solid #444; color: #ddd; padding: 8px 15px; border-radius: 6px; cursor: pointer; margin-left: 10px; transition: 0.2s; font-weight: 500; }
            .btn-tool:hover { background: #333; border-color: #ff9f43; color: #ff9f43; }
            
            .bb-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
            @media (max-width: 1000px) { .bb-grid { grid-template-columns: 1fr; } }

            .bb-panel { background: #1a1a1a; border: 1px solid #333; border-radius: 10px; overflow: hidden; display: flex; flex-direction: column; }
            .bb-panel h3 { margin: 0; padding: 15px 20px; background: #222; font-size: 1rem; color: #ccc; border-bottom: 1px solid #333; }
            
            /* ASSET TABLE */
            .bb-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
            .bb-table th { text-align: left; padding: 12px 20px; color: #666; font-weight: 600; border-bottom: 1px solid #333; }
            .bb-table td { padding: 12px 20px; border-bottom: 1px solid #2a2a2a; color: #ccc; }
            .http-status { padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.75rem; }
            .s-200 { background: rgba(0, 204, 102, 0.2); color: #00cc66; }
            .s-403 { background: rgba(255, 170, 0, 0.2); color: #ffaa00; }
            .s-404 { background: rgba(255, 51, 51, 0.2); color: #ff3333; }
            
            /* CHECKLIST */
            .checklist-container { padding: 0; }
            .check-item { display: flex; padding: 15px 20px; border-bottom: 1px solid #2a2a2a; cursor: pointer; transition: 0.2s; position: relative; }
            .check-item:hover { background: #222; }
            .check-item input { display: none; }
            
            .checkmark { width: 20px; height: 20px; border: 2px solid #555; border-radius: 50%; margin-right: 15px; display: flex; align-items: center; justify-content: center; transition: 0.2s; }
            .checkmark::after { content: '✔'; opacity: 0; font-size: 12px; color: #000; }
            
            .check-item input:checked ~ .checkmark { background: #ff9f43; border-color: #ff9f43; }
            .check-item input:checked ~ .checkmark::after { opacity: 1; }
            .check-item input:checked ~ .check-content { opacity: 0.5; text-decoration: line-through; }
            
            .c-title { font-weight: bold; margin-bottom: 2px; color: #ddd; }
            .c-desc { font-size: 0.8rem; color: #666; }
        </style>
        `;
    }
};

function pageBugBounty() {
    BugBountyHub.init();
    return BugBountyHub.render();
}
