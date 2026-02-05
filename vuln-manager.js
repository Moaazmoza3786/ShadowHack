/* ==================== SMART VULNERABILITY MANAGER 🛡️ ==================== */
/* Lifecycle tracking for discovered risks and remediation progress */

window.VulnManager = {
    state: {
        vulns: JSON.parse(localStorage.getItem('smart_vulns') || '[]'),
        filter: 'all' // all, critical, pending, fixed
    },

    init() {
        if (this.state.vulns.length === 0) {
            this.seedData();
        }
    },

    seedData() {
        const initial = [
            { id: 1, title: 'Log4Shell (CVE-2021-44228)', asset: 'prod-web-01', cvss: 10.0, status: 'New', exploit: 'Public', date: '2025-12-01' },
            { id: 2, title: 'Unauthenticated RCE in Jenkins', asset: 'build-ci-node', cvss: 9.8, status: 'In Progress', exploit: 'Private', date: '2025-12-05' },
            { id: 3, title: 'S3 Bucket Public Read Access', asset: 'megacorp-backup', cvss: 7.5, status: 'Fixed', exploit: 'N/A', date: '2025-12-10' },
            { id: 4, title: 'Expired SSL Certificate', asset: 'api.megacorp.com', cvss: 5.3, status: 'New', exploit: 'N/A', date: '2025-12-15' }
        ];
        this.state.vulns = initial;
        this.save();
    },

    save() {
        localStorage.setItem('smart_vulns', JSON.stringify(this.state.vulns));
    },

    render() {
        return `
        <div class="vuln-app fade-in">
            <div class="vuln-header">
                <div>
                    <h1><i class="fas fa-shield-alt"></i> VulnOps Command Center</h1>
                    <p>Remediation Lifecycle & Risk Prioritization</p>
                </div>
                <div class="header-stats">
                    <div class="stat-bubble cri"><span>${this.countByRisk('critical')}</span> Critical</div>
                    <div class="stat-bubble pen"><span>${this.countByStatus('New')}</span> Pending</div>
                </div>
            </div>

            <div class="vuln-toolbar">
                <div class="tabs">
                    <button class="tab-btn ${this.state.filter === 'all' ? 'active' : ''}" onclick="VulnManager.setFilter('all')">All Flaws</button>
                    <button class="tab-btn ${this.state.filter === 'pending' ? 'active' : ''}" onclick="VulnManager.setFilter('pending')">Pending</button>
                    <button class="tab-btn ${this.state.filter === 'fixed' ? 'active' : ''}" onclick="VulnManager.setFilter('fixed')">Fixed</button>
                </div>
                <button class="btn-add" onclick="VulnManager.showAddModal()"><i class="fas fa-plus"></i> Manual Entry</button>
            </div>

            <div class="vuln-table-container">
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Target Asset</th>
                            <th>Risk (CVSS)</th>
                            <th>Exploit</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${this.renderRows()}
                    </tbody>
                </table>
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderRows() {
        let filtered = this.state.vulns;
        if (this.state.filter === 'pending') filtered = this.state.vulns.filter(v => v.status !== 'Fixed');
        if (this.state.filter === 'fixed') filtered = this.state.vulns.filter(v => v.status === 'Fixed');

        if (filtered.length === 0) return '<tr><td colspan="6" class="empty-msg">No vulnerabilities found in this category.</td></tr>';

        return filtered.map(v => {
            const riskClass = v.cvss >= 9 ? 'r-crit' : v.cvss >= 7 ? 'r-high' : v.cvss >= 4 ? 'r-med' : 'r-low';
            return `
            <tr class="vuln-row">
                <td>
                    <div class="v-title">${v.title}</div>
                    <div class="v-date">Detected: ${v.date}</div>
                </td>
                <td class="v-asset"><code>${v.asset}</code></td>
                <td><span class="cvss-chip ${riskClass}">${v.cvss.toFixed(1)}</span></td>
                <td><span class="exploit-badge ${v.exploit.toLowerCase()}">${v.exploit}</span></td>
                <td>
                    <select class="status-select ${v.status.replace(' ', '-').toLowerCase()}" onchange="VulnManager.updateStatus(${v.id}, this.value)">
                        <option value="New" ${v.status === 'New' ? 'selected' : ''}>New</option>
                        <option value="In Progress" ${v.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                        <option value="Fixed" ${v.status === 'Fixed' ? 'selected' : ''}>Fixed</option>
                    </select>
                </td>
                <td>
                    <button class="btn-icon" onclick="VulnManager.deleteVuln(${v.id})"><i class="fas fa-trash"></i></button>
                    <button class="btn-icon" onclick="alert('CVE Details: ${v.title}\\nExploit availability: ${v.exploit}')"><i class="fas fa-info-circle"></i></button>
                </td>
            </tr>
            `;
        }).join('');
    },

    setFilter(f) {
        this.state.filter = f;
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    updateStatus(id, status) {
        const vuln = this.state.vulns.find(v => v.id === id);
        if (vuln) {
            vuln.status = status;
            this.save();
            this.setFilter(this.state.filter);
        }
    },

    deleteVuln(id) {
        if (confirm('Delete this record?')) {
            this.state.vulns = this.state.vulns.filter(v => v.id !== id);
            this.save();
            this.setFilter(this.state.filter);
        }
    },

    countByRisk(risk) {
        if (risk === 'critical') return this.state.vulns.filter(v => v.cvss >= 9).length;
        return 0;
    },

    countByStatus(status) {
        return this.state.vulns.filter(v => v.status === status).length;
    },

    showAddModal() {
        const title = prompt("Vulnerability Title:");
        const asset = prompt("Target Asset:");
        const cvss = parseFloat(prompt("CVSS Score (0-10):") || '0');
        if (title && asset) {
            this.state.vulns.push({
                id: Date.now(),
                title: title,
                asset: asset,
                cvss: cvss,
                status: 'New',
                exploit: 'N/A',
                date: new Date().toISOString().split('T')[0]
            });
            this.save();
            this.setFilter('all');
        }
    },

    getStyles() {
        return `<style>
            .vuln-app { padding: 40px; color: #e0e0e0; font-family: 'Inter', sans-serif; background: #0b0c14; min-height: 100%; box-sizing: border-box; }
            .vuln-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 1px solid #1c1c26; padding-bottom: 25px; }
            .vuln-header h1 { margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 15px; }
            .vuln-header p { margin: 8px 0 0; color: #6366f1; font-weight: 500; font-size: 1rem; }
            
            .header-stats { display: flex; gap: 20px; }
            .stat-bubble { background: #161925; padding: 10px 20px; border-radius: 12px; border: 1px solid #2d2d3a; font-size: 0.9rem; color: #888; }
            .stat-bubble span { font-weight: 800; font-size: 1.2rem; color: #fff; margin-right: 5px; }
            .stat-bubble.cri { border-color: #ef4444; }
            .stat-bubble.cri span { color: #ef4444; }

            .vuln-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
            .tabs { display: flex; background: #161925; padding: 5px; border-radius: 10px; border: 1px solid #2d2d3a; }
            .tab-btn { background: none; border: none; color: #888; padding: 8px 20px; border-radius: 8px; cursor: pointer; transition: 0.2s; font-weight: 600; }
            .tab-btn:hover { color: #fff; }
            .tab-btn.active { background: #6366f1; color: #fff; }

            .btn-add { background: #6366f1; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 8px; }

            .vuln-table-container { background: #161925; border-radius: 16px; border: 1px solid #2d2d3a; overflow: hidden; }
            .vuln-table { width: 100%; border-collapse: collapse; text-align: left; }
            .vuln-table th { padding: 18px 25px; background: rgba(255,255,255,0.02); color: #888; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; border-bottom: 1px solid #2d2d3a; }
            .vuln-table td { padding: 18px 25px; border-bottom: 1px solid #1c1c26; vertical-align: middle; }
            
            .v-title { font-weight: 700; color: #fff; font-size: 1rem; }
            .v-date { font-size: 0.75rem; color: #555; margin-top: 3px; }
            .v-asset code { background: #000; padding: 4px 8px; border-radius: 4px; color: #4ade80; font-family: monospace; }

            .cvss-chip { padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.85rem; }
            .r-crit { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
            .r-high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
            .r-med { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
            .r-low { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }

            .exploit-badge { font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
            .exploit-badge.public { background: #ef4444; color: #fff; }
            .exploit-badge.private { background: #f59e0b; color: #000; }
            .exploit-badge.n\\/a { background: #333; color: #888; }

            .status-select { background: #0b0c14; border: 1px solid #333; color: #fff; padding: 6px 12px; border-radius: 6px; font-size: 0.85rem; outline: none; cursor: pointer; }
            .status-select.new { border-color: #ef4444; color: #ef4444; }
            .status-select.in-progress { border-color: #fbbf24; color: #fbbf24; }
            .status-select.fixed { border-color: #22c55e; color: #22c55e; }

            .btn-icon { background: none; border: none; color: #555; cursor: pointer; padding: 8px; transition: 0.2s; font-size: 1.1rem; }
            .btn-icon:hover { color: #fff; }

            .empty-msg { text-align: center; color: #444; padding: 50px 0; font-style: italic; }
        </style>`;
    }
};

VulnManager.init();
function pageVulnManager() { return VulnManager.render(); }
