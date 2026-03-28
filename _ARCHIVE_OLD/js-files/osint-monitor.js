/* ==================== OSINT & ATTACK SURFACE MONITOR 🛰️ ==================== */
/* Continuous monitoring of target subdomains, ports, and leaks */

window.OsintMonitor = {
    state: {
        targets: JSON.parse(localStorage.getItem('osint_targets') || '[]'),
        activeTarget: null
    },

    init() {
        if (this.state.targets.length === 0) {
            this.addTarget('MegaCorp Inc.', 'megacorp.com');
            this.addTarget('Cyberdyne Systems', 'cyberdyne.io');
        }
    },

    addTarget(name, domain) {
        const target = {
            id: Date.now() + Math.random(),
            name: name,
            domain: domain,
            assets: [],
            leaks: [],
            lastScan: 'Never',
            status: 'Idle'
        };
        this.state.targets.push(target);
        this.save();
        this.renderTargets();
    },

    save() {
        localStorage.setItem('osint_targets', JSON.stringify(this.state.targets));
    },

    render() {
        return `
        <div class="osint-app fade-in">
            <div class="osint-header">
                <div class="header-info">
                    <h1><i class="fas fa-satellite"></i> Target Intelligence Hub</h1>
                    <p>Attack Surface Monitoring & OSINT Automation</p>
                </div>
                <div class="header-actions">
                    <button class="btn-primary" onclick="OsintMonitor.showAddModal()"><i class="fas fa-plus"></i> Monitor New Target</button>
                </div>
            </div>

            <div class="osint-main">
                <div class="target-list" id="osint-target-list">
                    ${this.renderTargetsHtml()}
                </div>
                
                <div class="target-details" id="osint-details">
                    <div class="empty-state">
                        <i class="fas fa-bullseye"></i>
                        <h3>Select a target to view attack surface</h3>
                    </div>
                </div>
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderTargetsHtml() {
        return this.state.targets.map(t => `
            <div class="target-card ${this.state.activeTarget === t.id ? 'active' : ''}" onclick="OsintMonitor.selectTarget(${t.id})">
                <div class="target-icon"><i class="fas fa-building"></i></div>
                <div class="target-meta">
                    <div class="t-name">${t.name}</div>
                    <div class="t-domain">${t.domain}</div>
                </div>
                <div class="target-badge">${t.assets.length} Assets</div>
            </div>
        `).join('');
    },

    renderTargets() {
        const list = document.getElementById('osint-target-list');
        if (list) list.innerHTML = this.renderTargetsHtml();
    },

    selectTarget(id) {
        this.state.activeTarget = id;
        this.renderTargets();
        this.renderDetails();
    },

    renderDetails() {
        const target = this.state.targets.find(t => t.id === this.state.activeTarget);
        const container = document.getElementById('osint-details');
        if (!target || !container) return;

        container.innerHTML = `
            <div class="details-view fade-in">
                <div class="details-header">
                    <div class="d-title">
                        <h2>${target.name} <span class="d-domain">(${target.domain})</span></h2>
                        <div class="d-status">Status: <span class="status-val ${target.status.toLowerCase()}">${target.status}</span></div>
                    </div>
                    <div class="d-actions">
                        <button class="btn-scan" onclick="OsintMonitor.runScan(${target.id})">
                            <i class="fas fa-search-location"></i> Run Deep Scan
                        </button>
                    </div>
                </div>

                <div class="details-grid">
                    <div class="grid-box assets">
                        <h3><i class="fas fa-network-wired"></i> Discovered Subdomains</h3>
                        <div class="asset-list">
                            ${target.assets.length === 0 ? '<p class="empty">No assets discovered yet. Run scan.</p>' :
                target.assets.map(a => `
                                <div class="asset-row">
                                    <span class="a-host">${a.host}</span>
                                    <span class="a-ip">${a.ip}</span>
                                    <span class="a-ports">${a.ports.join(', ')}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <div class="grid-box leaks">
                        <h3><i class="fas fa-user-secret"></i> Leaked Credentials</h3>
                        <div class="leak-list">
                             ${target.leaks.length === 0 ? '<p class="empty">No leaks found in simulated datasets.</p>' :
                target.leaks.map(l => `
                                <div class="leak-row">
                                    <span class="l-email">${l.email}</span>
                                    <span class="l-source">${l.source}</span>
                                    <button class="btn-view" onclick="alert('Password: ${l.pass}')">View</button>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    runScan(id) {
        const target = this.state.targets.find(t => t.id === id);
        if (!target) return;

        target.status = 'Scanning...';
        this.renderDetails();

        setTimeout(() => {
            // Simulated results
            target.assets = [
                { host: `vpn.${target.domain}`, ip: '1.2.3.4', ports: [443, 1194] },
                { host: `dev.${target.domain}`, ip: '1.2.3.5', ports: [80, 8080, 22] },
                { host: `mx.${target.domain}`, ip: '1.2.3.6', ports: [25, 587] }
            ];
            target.leaks = [
                { email: `admin@${target.domain}`, source: 'LinkedIn Breach', pass: 'P@ssw0rd123' },
                { email: `dev01@${target.domain}`, source: 'Dropbox Leak', pass: 'developer_root' }
            ];
            target.status = 'Idle';
            target.lastScan = new Date().toLocaleString();
            this.save();
            this.renderDetails();
            this.renderTargets();
        }, 2000);
    },

    showAddModal() {
        const name = prompt("Target Organization Name:");
        const domain = prompt("Main Domain (e.g. target.com):");
        if (name && domain) this.addTarget(name, domain);
    },

    getStyles() {
        return `<style>
            .osint-app { padding: 30px; color: #e0e0e0; font-family: 'Inter', sans-serif; display: flex; flex-direction: column; height: 100%; }
            .osint-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 20px; }
            .header-info h1 { margin: 0; font-size: 1.8rem; color: #fff; display: flex; align-items: center; gap: 12px; }
            .header-info p { margin: 5px 0 0; color: #888; }
            
            .btn-primary { background: #6366f1; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 8px; border: 1px solid rgba(255,255,255,0.1); }
            
            .osint-main { display: grid; grid-template-columns: 350px 1fr; gap: 30px; flex: 1; min-height: 0; }
            
            .target-list { display: flex; flex-direction: column; gap: 12px; overflow-y: auto; }
            .target-card { background: #1c1c26; border-radius: 12px; padding: 18px; border: 1px solid #2d2d3a; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 15px; position: relative; }
            .target-card:hover { border-color: #6366f1; background: #252533; }
            .target-card.active { border-color: #6366f1; background: rgba(99,102,241,0.1); }
            .target-card.active::before { content: ''; position: absolute; left: 0; top: 20%; height: 60%; width: 4px; background: #6366f1; border-radius: 0 4px 4px 0; }
            
            .target-icon { background: #2d2d3a; color: #888; width: 45px; height: 45px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }
            .target-card.active .target-icon { background: #6366f1; color: #fff; }
            
            .t-name { font-weight: 600; color: #fff; }
            .t-domain { font-size: 0.85rem; color: #666; margin-top: 2px; }
            .target-badge { font-size: 0.75rem; background: rgba(255,255,255,0.05); color: #888; padding: 4px 10px; border-radius: 20px; margin-left: auto; }
            
            .target-details { background: #1c1c26; border-radius: 16px; border: 1px solid #2d2d3a; display: flex; flex-direction: column; min-height: 500px; }
            .empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #444; }
            .empty-state i { font-size: 4rem; margin-bottom: 20px; color: #2d2d3a; }
            
            .details-view { padding: 30px; display: flex; flex-direction: column; height: 100%; gap: 30px; }
            .details-header { display: flex; justify-content: space-between; align-items: flex-start; }
            .d-title h2 { margin: 0; color: #fff; font-size: 1.5rem; }
            .d-domain { color: #6366f1; font-weight: normal; margin-left: 10px; }
            .d-status { font-size: 0.9rem; color: #888; margin-top: 8px; }
            .status-val.scanning { color: #fbbf24; }
            .status-val.idle { color: #22c55e; }
            
            .btn-scan { background: #111; color: #fff; border: 1px solid #333; padding: 10px 20px; border-radius: 8px; cursor: pointer; transition: 0.2s; }
            .btn-scan:hover { background: #6366f1; border-color: #6366f1; }
            
            .details-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .grid-box { background: #14141c; border-radius: 12px; padding: 20px; border: 1px solid #2d2d3a; }
            .grid-box h3 { margin: 0 0 20px; font-size: 1.1rem; color: #aaa; display: flex; align-items: center; gap: 10px; }
            
            .asset-row, .leak-row { display: grid; grid-template-columns: 1fr 1fr 80px; gap: 10px; padding: 12px; background: rgba(255,255,255,0.02); border-radius: 8px; margin-bottom: 8px; font-size: 0.9rem; align-items: center; }
            .asset-row { grid-template-columns: 1fr 120px 100px; }
            .a-host { color: #fff; font-weight: 500; }
            .a-ports { color: #fbbf24; font-family: monospace; }
            
            .l-email { color: #fff; font-weight: 500; }
            .l-source { color: #ef4444; font-size: 0.8rem; }
            .btn-view { background: #333; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; }
            .btn-view:hover { background: #444; }
            
            .empty { text-align: center; color: #444; padding: 40px 0; font-style: italic; }
        </style>`;
    }
};

OsintMonitor.init();
function pageOsintMonitor() { return OsintMonitor.render(); }
