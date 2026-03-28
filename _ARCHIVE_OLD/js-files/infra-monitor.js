/* ==================== INFRASTRUCTURE MONITOR 🌐 ==================== */
/* Tracks Domain & SSL Expirations for Red Teaming Support */

window.InfraMonitor = {
    state: {
        domains: JSON.parse(localStorage.getItem('infra_domains') || '[]')
    },

    init() {
        if (this.state.domains.length === 0) {
            // Default seed data
            this.addDomain('target-corp.com', 'Client Production', 45, 12);
            this.addDomain('phish-support.net', 'Phishing Campaign', 3, 150); // Warning
            this.addDomain('c2-beacon.io', 'C2 Infrastructure', 120, 110);
        }
    },

    addDomain(domain, tag, sslDays, domainDays) {
        // Randomize days if not provided (Simulation)
        if (sslDays === undefined) sslDays = Math.floor(Math.random() * 300) + 1;
        if (domainDays === undefined) domainDays = Math.floor(Math.random() * 400) + 1;

        const entry = {
            id: Date.now() + Math.random(),
            domain: domain,
            tag: tag || 'General',
            sslExpiry: sslDays,
            domainExpiry: domainDays,
            lastChecked: new Date().toLocaleString()
        };

        this.state.domains.push(entry);
        this.save();
        this.renderTable();
    },

    removeDomain(id) {
        this.state.domains = this.state.domains.filter(d => d.id !== id);
        this.save();
        this.renderTable();
    },

    save() {
        localStorage.setItem('infra_domains', JSON.stringify(this.state.domains));
    },

    render() {
        return `
        <div class="infra-app fade-in">
            <div class="infra-header">
                <div class="header-left">
                    <h1><i class="fas fa-globe-americas"></i> Infrastructure Monitor</h1>
                    <p>Track Domain & SSL Health for Red Team Ops</p>
                </div>
                <div class="header-right">
                    <button class="btn-refresh" onclick="InfraMonitor.refreshAll()"><i class="fas fa-sync-alt"></i> Check All</button>
                    <button class="btn-add" onclick="InfraMonitor.showAddModal()"><i class="fas fa-plus"></i> Add Domain</button>
                </div>
            </div>

            <div class="infra-stats">
               <div class="stat-card">
                   <span class="stat-val">${this.state.domains.length}</span>
                   <span class="stat-label">Total Assets</span>
               </div>
               <div class="stat-card warning">
                   <span class="stat-val">${this.state.domains.filter(d => d.sslExpiry < 7 || d.domainExpiry < 7).length}</span>
                   <span class="stat-label">Expiring Soon (< 7 days)</span>
               </div>
               <div class="stat-card ok">
                   <span class="stat-val">${this.state.domains.filter(d => d.sslExpiry >= 7 && d.domainExpiry >= 7).length}</span>
                   <span class="stat-label">Healthy</span>
               </div>
            </div>

            <div class="infra-table-container">
                <table class="infra-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Tag</th>
                            <th>SSL Status</th>
                            <th>Domain Status</th>
                            <th>Last Checked</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="infra-table-body">
                        ${this.renderRows()}
                    </tbody>
                </table>
            </div>

            ${this.renderAddModal()}
        </div>
        ${this.getStyles()}`;
    },

    renderRows() {
        if (this.state.domains.length === 0) return '<tr><td colspan="6" class="empty-cell">No domains monitored. Add one to start.</td></tr>';

        return this.state.domains.map(d => {
            const sslClass = d.sslExpiry < 7 ? 'risk-high' : d.sslExpiry < 30 ? 'risk-med' : 'risk-low';
            const domClass = d.domainExpiry < 7 ? 'risk-high' : d.domainExpiry < 30 ? 'risk-med' : 'risk-low';

            return `
            <tr>
                <td class="col-domain">
                    <div class="dom-name">${d.domain}</div>
                    <a href="https://${d.domain}" target="_blank" class="dom-link"><i class="fas fa-external-link-alt"></i></a>
                </td>
                <td><span class="tag-badge">${d.tag}</span></td>
                <td>
                    <div class="status-pill ${sslClass}">
                        <i class="fas fa-lock"></i> ${d.sslExpiry} Days
                    </div>
                </td>
                <td>
                    <div class="status-pill ${domClass}">
                        <i class="fas fa-clock"></i> ${d.domainExpiry} Days
                    </div>
                </td>
                <td class="text-muted">${d.lastChecked}</td>
                <td>
                    <button class="btn-icon delete" onclick="InfraMonitor.removeDomain(${d.id})"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
            `;
        }).join('');
    },

    renderTable() {
        const tbody = document.getElementById('infra-table-body');
        if (tbody) tbody.innerHTML = this.renderRows();
    },

    refreshAll() {
        // Simulate checking API
        const btn = document.querySelector('.btn-refresh i');
        if (btn) btn.classList.add('fa-spin');

        setTimeout(() => {
            if (btn) btn.classList.remove('fa-spin');
            this.state.domains.forEach(d => {
                d.lastChecked = new Date().toLocaleString();
                // Simulate mostly stable but slightly changing days? No, days just decrement ideally.
                // For demo, we keep them static or slight jitter
            });
            this.save();
            this.renderTable();
        }, 800);
    },

    showAddModal() {
        const modal = document.createElement('div');
        modal.className = 'infra-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <h3>Add New Asset</h3>
                <div class="form-group">
                    <label>Domain Name</label>
                    <input type="text" id="new-domain" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>Tag (Client/Campaign)</label>
                    <input type="text" id="new-tag" placeholder="Phishing">
                </div>
                <div class="modal-actions">
                    <button class="btn-cancel" onclick="this.closest('.infra-modal').remove()">Cancel</button>
                    <button class="btn-confirm" onclick="InfraMonitor.confirmAdd(this)">Add Monitor</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        document.getElementById('new-domain').focus();
    },

    confirmAdd(btn) {
        const domain = document.getElementById('new-domain').value;
        const tag = document.getElementById('new-tag').value;
        if (domain) {
            this.addDomain(domain, tag);
            btn.closest('.infra-modal').remove();
        }
    },

    getStyles() {
        return `<style>
            .infra-app { padding: 30px; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; }
            .infra-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 20px; }
            .header-left h1 { margin: 0; font-size: 1.8rem; color: #fff; display: flex; gap: 10px; align-items: center; }
            .header-left p { margin: 5px 0 0; color: #888; }
            
            .header-right { display: flex; gap: 10px; }
            .btn-refresh, .btn-add { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; display: flex; gap: 8px; align-items: center; }
            .btn-refresh { background: #2d2d3a; color: #fff; }
            .btn-add { background: #6366f1; color: #fff; }
            .btn-add:hover { background: #4f46e5; }
            
            .infra-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: #1c1c26; padding: 20px; border-radius: 12px; border: 1px solid #2d2d3a; display: flex; flex-direction: column; align-items: center; }
            .stat-val { font-size: 2rem; font-weight: 700; color: #fff; }
            .stat-label { color: #888; font-size: 0.9rem; margin-top: 5px; }
            .stat-card.warning .stat-val { color: #ef4444; }
            .stat-card.ok .stat-val { color: #22c55e; }
            
            .infra-table-container { background: #1c1c26; border-radius: 12px; overflow: hidden; border: 1px solid #2d2d3a; }
            .infra-table { width: 100%; border-collapse: collapse; }
            .infra-table th { background: #14141c; padding: 15px 20px; text-align: left; color: #888; font-weight: 600; font-size: 0.9rem; }
            .infra-table td { padding: 15px 20px; border-top: 1px solid #2d2d3a; color: #ddd; vertical-align: middle; }
            
            .col-domain { display: flex; align-items: center; gap: 10px; }
            .dom-name { font-weight: 600; color: #fff; }
            .dom-link { color: #6366f1; font-size: 0.8rem; opacity: 0; transition: 0.2s; }
            .infra-table tr:hover .dom-link { opacity: 1; }
            
            .tag-badge { background: rgba(255, 255, 255, 0.1); padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; }
            
            .status-pill { display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 6px; font-weight: 600; font-size: 0.9rem; }
            .risk-low { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
            .risk-med { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
            .risk-high { background: rgba(239, 68, 68, 0.15); color: #f87171; }
            
            .btn-icon.delete { background: none; border: none; color: #666; cursor: pointer; transition: 0.2s; }
            .btn-icon.delete:hover { color: #ef4444; }
            
            .infra-modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); display: flex; justify-content: center; align-items: center; z-index: 1000; animation: fadeIn 0.2s; }
            .modal-content { background: #1c1c26; padding: 30px; border-radius: 12px; width: 400px; border: 1px solid #333; }
            .modal-content h3 { margin-top: 0; color: #fff; }
            .form-group { margin-bottom: 20px; }
            .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-size: 0.9rem; }
            .form-group input { width: 100%; padding: 10px; background: #0f0f13; border: 1px solid #333; border-radius: 6px; color: #fff; outline: none; }
            .form-group input:focus { border-color: #6366f1; }
            
            .modal-actions { display: flex; justify-content: flex-end; gap: 10px; }
            .btn-cancel { background: transparent; border: 1px solid #333; color: #ccc; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
            .btn-confirm { background: #6366f1; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
            
            .text-muted { color: #666; font-size: 0.85rem; }
            .empty-cell { text-align: center; padding: 40px !important; color: #666; font-style: italic; }
            
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        </style>`;
    }
};

// Auto-initialize if no data
InfraMonitor.init();

function pageInfraMonitor() { return InfraMonitor.render(); }
