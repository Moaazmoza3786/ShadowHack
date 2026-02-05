/* ============================================================
   RED TEAM OPERATIONS CENTER (RTOC)
   Management Dashboard for Projects, Findings, and Reporting
   ============================================================ */

window.RedTeamOps = {
    // --- STATE MANAGEMENT ---
    state: {
        projects: [],
        currentProjectId: null
    },

    init() {
        this.loadState();
        console.log("Red Team Ops Center Initialized");
    },

    loadState() {
        const saved = localStorage.getItem('rtoc_state');
        if (saved) {
            this.state = JSON.parse(saved);
        } else {
            // Seed Data
            this.state.projects = [{
                id: 'proj-1',
                name: 'MegaCorp External Pentest',
                client: 'MegaCorp Global',
                status: 'In Progress',
                scope: ['*.megacorp.com', '192.168.1.0/24'],
                startDate: '2025-01-10',
                findings: [
                    { id: 'f1', title: 'SQL Injection in Login', severity: 'Critical', cvss: 9.8, status: 'Open', description: 'Union-based SQLi found on /login parameter username.' }
                ]
            }];
            this.saveState();
        }
    },

    saveState() {
        localStorage.setItem('rtoc_state', JSON.stringify(this.state));
    },

    getProject(id) {
        return this.state.projects.find(p => p.id === id);
    },

    // --- RENDERERS ---

    render() {
        // Main Entry Point
        this.init();
        return `
            <div class="rtoc-container fade-in">
                ${this.renderHeader()}
                ${this.state.currentProjectId ? this.renderProjectView(this.state.currentProjectId) : this.renderDashboard()}
            </div>
            ${this.getStyles()}
            ${this.renderModals()}
        `;
    },

    renderHeader() {
        return `
            <div class="rtoc-header">
                <div>
                    <h1 class="rtoc-title"><i class="fa-solid fa-user-secret"></i> RED TEAM OPERATIONS</h1>
                    <p class="rtoc-subtitle">Engagement Management // Reporting // Intelligence</p>
                </div>
                <div class="rtoc-actions">
                    ${this.state.currentProjectId ?
                `<button class="rtoc-btn secondary" onclick="RedTeamOps.closeProject()"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</button>` :
                `<button class="rtoc-btn primary" onclick="RedTeamOps.openNewProjectModal()"><i class="fa-solid fa-plus"></i> New Engagement</button>`
            }
                </div>
            </div>
        `;
    },

    renderDashboard() {
        const activeCount = this.state.projects.filter(p => p.status === 'In Progress').length;
        const totalFindings = this.state.projects.reduce((acc, p) => acc + p.findings.length, 0);

        return `
            <!-- Stats Row -->
            <div class="rtoc-stats-row">
                <div class="rtoc-stat-card">
                    <div class="icon"><i class="fa-solid fa-briefcase"></i></div>
                    <div class="info">
                        <h3>${this.state.projects.length}</h3>
                        <p>Total Projects</p>
                    </div>
                </div>
                <div class="rtoc-stat-card active">
                    <div class="icon"><i class="fa-solid fa-bolt"></i></div>
                    <div class="info">
                        <h3>${activeCount}</h3>
                        <p>Active Engagements</p>
                    </div>
                </div>
                <div class="rtoc-stat-card danger">
                    <div class="icon"><i class="fa-solid fa-bug"></i></div>
                    <div class="info">
                        <h3>${totalFindings}</h3>
                        <p>Total Findings</p>
                    </div>
                </div>
            </div>

            <!-- Projects Grid -->
            <h2 class="section-title">Active Engagements</h2>
            <div class="rtoc-grid">
                ${this.state.projects.map(p => `
                    <div class="rtoc-project-card" onclick="RedTeamOps.openProject('${p.id}')">
                        <div class="card-header">
                            <span class="badge ${p.status === 'In Progress' ? 'processing' : 'done'}">${p.status}</span>
                            <i class="fa-solid fa-server"></i>
                        </div>
                        <h3>${p.name}</h3>
                        <p class="client">${p.client}</p>
                        <div class="meta">
                            <span><i class="fa-solid fa-calendar"></i> ${p.startDate}</span>
                            <span><i class="fa-solid fa-bug"></i> ${p.findings.length} Findings</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderProjectView(id) {
        const p = this.getProject(id);
        if (!p) return `<div class="alert alert-danger">Project not found</div>`;

        return `
            <div class="project-view">
                <div class="project-meta-bar">
                    <h2>${p.name} <span class="badge processing">${p.status}</span></h2>
                    <div>Client: <strong>${p.client}</strong></div>
                </div>

                <div class="project-tabs">
                    <button class="tab-btn active" onclick="RedTeamOps.switchTab('findings')">Findings Tracker</button>
                    <button class="tab-btn" onclick="RedTeamOps.switchTab('scope')">Scope & Details</button>
                    <button class="tab-btn" onclick="RedTeamOps.switchTab('report')">Report Generator</button>
                </div>

                <div id="project-content">
                    ${this.renderFindingsTable(p)}
                </div>
            </div>
        `;
    },

    renderFindingsTable(p) {
        return `
            <div class="findings-toolbar">
                <h3>Vulnerabilities Found</h3>
                <button class="rtoc-btn primary small" onclick="RedTeamOps.openNewFindingModal()"><i class="fa-solid fa-plus"></i> Add Finding</button>
            </div>
            
            <div class="rtoc-table-wrapper">
                <table class="rtoc-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>CVSS</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${p.findings.length === 0 ? `<tr><td colspan="5" style="text-align:center; padding: 20px;">No findings recorded yet.</td></tr>` :
                p.findings.map(f => `
                            <tr>
                                <td><span class="sev-badge ${f.severity.toLowerCase()}">${f.severity}</span></td>
                                <td style="font-weight:600; color: #fff;">${f.title}</td>
                                <td>${f.cvss}</td>
                                <td>${f.status}</td>
                                <td>
                                    <button class="action-btn text-danger" onclick="RedTeamOps.deleteFinding('${f.id}')"><i class="fa-solid fa-trash"></i></button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },

    renderReportTab(p) {
        return `
            <div class="report-controls">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3><i class="fa-solid fa-file-pdf"></i> Generate Professional Report</h3>
                    <button class="rtoc-btn secondary small" onclick="RedTeamOps.generateAIReport('${p.id}')">
                        <i class="fa-solid fa-brain"></i> Enhance with AI
                    </button>
                </div>
                <p class="text-muted">This module compiles all tracked findings into a standard Pentest Report format.</p>
                
                <div class="report-preview-card">
                    <h4>Executive Summary</h4>
                    <div id="ai-summary-content">
                        ${p.aiSummary ? p.aiSummary :
                `<p>This report details the security assessment performed for <strong>${p.client}</strong> on <strong>${p.name}</strong>. A total of <strong>${p.findings.length}</strong> vulnerabilities were identified.</p>`}
                    </div>
                    <div class="sev-breakdown">
                        <span>Critical: ${p.findings.filter(f => f.severity === 'Critical').length}</span>
                        <span>High: ${p.findings.filter(f => f.severity === 'High').length}</span>
                        <span>Medium: ${p.findings.filter(f => f.severity === 'Medium').length}</span>
                    </div>
                </div>

                <div id="report-actions" style="margin-top:20px;">
                    <button class="rtoc-btn primary large" onclick="RedTeamOps.generatePDF('${p.id}')">
                        <i class="fa-solid fa-download"></i> Export PDF Report
                    </button>
                </div>
            </div>
        `;
    },

    async generateAIReport(pid) {
        const p = this.getProject(pid);
        const container = document.getElementById('ai-summary-content');
        if (container) container.innerHTML = '<p class="text-muted"><i class="fas fa-circle-notch fa-spin"></i> Analyzing findings with AI...</p>';

        try {
            const res = await fetch('http://localhost:5000/api/ai/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ findings: p.findings })
            });
            const data = await res.json();

            if (data.success) {
                p.aiSummary = `<p>${data.summary}</p>`;
                this.saveState();
                if (container) container.innerHTML = p.aiSummary;
            } else {
                if (container) container.innerHTML = '<p class="text-danger">AI Analysis Failed.</p>';
            }
        } catch (e) {
            console.error(e);
            if (container) container.innerHTML = '<p class="text-danger">Connection Error.</p>';
        }
    },

    // --- ACTIONS ---

    openProject(id) {
        this.state.currentProjectId = id;
        // Re-render handled by main app loop or manual call -> for now just full re-render
        // In a real SPA we'd update just the view container
        document.querySelector('.rtoc-container').outerHTML = this.render();
    },

    closeProject() {
        this.state.currentProjectId = null;
        document.querySelector('.rtoc-container').outerHTML = this.render();
    },

    switchTab(tab) {
        const p = this.getProject(this.state.currentProjectId);
        const container = document.getElementById('project-content');

        // Update Active Class
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active'); // Dirty event usage but works for simple onclick

        if (tab === 'findings') container.innerHTML = this.renderFindingsTable(p);
        else if (tab === 'scope') container.innerHTML = `<div class="p-4 bg-dark rounded"><h4>Target Scope</h4><pre>${p.scope.join('\n')}</pre></div>`;
        else if (tab === 'report') container.innerHTML = this.renderReportTab(p);
    },

    // --- MODALS ---

    renderModals() {
        return `
            <!-- New Project Modal -->
            <div id="modal-new-project" class="rtoc-modal" style="display:none;">
                <div class="rtoc-modal-box">
                    <h3>New Engagement</h3>
                    <input type="text" id="np-name" placeholder="Project Name" class="rtoc-input">
                    <input type="text" id="np-client" placeholder="Client Name" class="rtoc-input">
                    <textarea id="np-scope" placeholder="Scope (one per line)" class="rtoc-input"></textarea>
                    <div class="modal-actions">
                        <button class="rtoc-btn secondary" style="margin-right:auto; background: linear-gradient(135deg, #a855f7, #6366f1); border: 1px solid rgba(255,255,255,0.2);" onclick="RedTeamOps.generateAICampaign()">
                            <i class="fa-solid fa-wand-magic-sparkles"></i> AI Auto-Gen
                        </button>
                        <button class="rtoc-btn secondary" onclick="document.getElementById('modal-new-project').style.display='none'">Cancel</button>
                        <button class="rtoc-btn primary" onclick="RedTeamOps.createProject()">Create</button>
                    </div>
                </div>
            </div>

            <!-- New Finding Modal -->
            <div id="modal-new-finding" class="rtoc-modal" style="display:none;">
                <div class="rtoc-modal-box large">
                    <h3>Log Vulnerability</h3>
                    <input type="text" id="nf-title" placeholder="Finding Title (e.g. Reflected XSS)" class="rtoc-input">
                    <div class="row">
                        <select id="nf-severity" class="rtoc-input">
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                        <input type="number" id="nf-cvss" placeholder="CVSS Score (0-10)" class="rtoc-input" step="0.1">
                    </div>
                    <textarea id="nf-desc" placeholder="Description & Impact..." class="rtoc-input" style="height: 100px;"></textarea>
                    <div class="modal-actions">
                        <button class="rtoc-btn secondary" onclick="document.getElementById('modal-new-finding').style.display='none'">Cancel</button>
                        <button class="rtoc-btn primary" onclick="RedTeamOps.addFinding()">Log Finding</button>
                    </div>
                </div>
            </div>
        `;
    },

    openNewProjectModal() { document.getElementById('modal-new-project').style.display = 'flex'; },
    openNewFindingModal() { document.getElementById('modal-new-finding').style.display = 'flex'; },

    createProject() {
        const name = document.getElementById('np-name').value;
        const client = document.getElementById('np-client').value;
        const scope = document.getElementById('np-scope').value.split('\n');

        if (!name || !client) return alert('Name and Client required');

        const newProj = {
            id: 'proj-' + Date.now(),
            name, client, scope,
            status: 'In Progress',
            startDate: new Date().toISOString().split('T')[0],
            findings: []
        };

        this.state.projects.push(newProj);
        this.saveState();
        document.getElementById('modal-new-project').style.display = 'none';

        // Refresh
        document.querySelector('.rtoc-container').outerHTML = this.render();
    },

    addFinding() {
        const title = document.getElementById('nf-title').value;
        const severity = document.getElementById('nf-severity').value;
        const cvss = document.getElementById('nf-cvss').value;
        const desc = document.getElementById('nf-desc').value;

        if (!title) return alert('Title required');

        const p = this.getProject(this.state.currentProjectId);
        p.findings.push({
            id: 'f-' + Date.now(),
            title, severity, cvss, status: 'Open', description: desc
        });

        this.saveState();
        document.getElementById('modal-new-finding').style.display = 'none';

        // Refresh Table
        this.switchTab('findings');
    },

    deleteFinding(fid) {
        if (!confirm('Delete this finding?')) return;
        const p = this.getProject(this.state.currentProjectId);
        p.findings = p.findings.filter(f => f.id !== fid);
        this.saveState();
        this.switchTab('findings');
    },

    async generateAICampaign() {
        const btn = event.currentTarget;
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Generating...';
        btn.disabled = true;

        const sectors = ['Banking', 'Healthcare', 'Energy', 'Tech', 'Defense', 'Retail'];
        const sector = sectors[Math.floor(Math.random() * sectors.length)];

        try {
            const res = await fetch('http://localhost:5000/api/ai/campaign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sector: sector })
            });

            const data = await res.json();

            if (data.success) {
                const c = typeof data.campaign === 'string' ? JSON.parse(data.campaign) : data.campaign;

                // Populate Modal Fields
                document.getElementById('np-name').value = c.name;
                document.getElementById('np-client').value = c.client;
                document.getElementById('np-scope').value = c.scope.join('\\n');

                // Construct findings with IDs
                const aiFindings = c.findings.map(f => ({
                    ...f,
                    id: 'f-' + Date.now() + Math.random().toString(36).substr(2, 5)
                }));

                // Auto Create Project
                const newProj = {
                    id: 'proj-' + Date.now(),
                    name: c.name,
                    client: c.client,
                    scope: c.scope,
                    status: 'In Progress',
                    startDate: new Date().toISOString().split('T')[0],
                    findings: aiFindings,
                    aiSummary: `<p>${c.description}</p>`
                };

                this.state.projects.push(newProj);
                this.saveState();

                document.getElementById('modal-new-project').style.display = 'none';
                document.querySelector('.rtoc-container').outerHTML = this.render();

                // Optional: Show toast or alert
                alert('AI Campaign Generated Successfully!');

            } else {
                alert('AI Generation Failed.');
            }
        } catch (e) {
            console.error(e);
            alert('Error connecting to AI Node.');
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    },

    // --- REPORT GENERATION ---

    generatePDF(pid) {
        const p = this.getProject(pid);

        // Create a temporary print-friendly container
        const element = document.createElement('div');
        element.style.padding = '40px';
        element.style.fontFamily = 'Arial, sans-serif';
        element.style.color = '#000';
        element.style.background = '#fff';

        element.innerHTML = `
            <div style="text-align:center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px;">
                <h1 style="color:#D32F2F; font-size: 32px; margin: 0;">CONFIDENTIAL</h1>
                <h2 style="margin: 10px 0;">Penetration Test Report</h2>
                <h3 style="color:#555;">${p.name} - ${p.client}</h3>
                <p>Date: ${new Date().toLocaleDateString()}</p>
            </div>

            <h3>Executive Summary</h3>
            ${p.aiSummary ? p.aiSummary : `<p>This document presents the findings of the security assessment conducted against the scope defined by ${p.client}.</p>`}
            
            <h3>Findings Summary</h3>
            <table style="width:100%; border-collapse: collapse; margin-top: 20px;">
                <tr style="background:#f0f0f0;">
                    <th style="padding:10px; border:1px solid #ccc;">Title</th>
                    <th style="padding:10px; border:1px solid #ccc;">Severity</th>
                    <th style="padding:10px; border:1px solid #ccc;">CVSS</th>
                </tr>
                ${p.findings.map(f => `
                    <tr>
                        <td style="padding:10px; border:1px solid #ccc;">${f.title}</td>
                        <td style="padding:10px; border:1px solid #ccc; color: ${f.severity === 'Critical' ? 'red' : f.severity === 'High' ? 'orange' : 'black'}">${f.severity}</td>
                        <td style="padding:10px; border:1px solid #ccc;">${f.cvss}</td>
                    </tr>
                `).join('')}
            </table>
            
            <div style="page-break-before: always;"></div>
            <h3>Detailed Findings</h3>
            ${p.findings.map(f => `
                <div style="border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px;">
                    <h4 style="margin-top:0; color:#333;">${f.title} <span style="font-size:0.8em; color:white; background:${f.severity === 'Critical' ? '#D32F2F' : '#F57C00'}; padding: 3px 8px; border-radius: 4px;">${f.severity}</span></h4>
                    <p><strong>Description:</strong><br>${f.description}</p>
                    <p><strong>Remediation:</strong><br>Implement input validation and parameterized queries to mitigate this vulnerability.</p>
                </div>
            `).join('')}
            
            <div style="margin-top: 50px; font-size: 0.8em; color: #888; text-align: center;">
                Generated by Red Team Operations Center (Study Hub)
            </div>
        `;

        // Generate PDF
        const opt = {
            margin: 1,
            filename: `${p.client.replace(/\s/g, '_')}_Report.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2 },
            jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
        };

        html2pdf().set(opt).from(element).save();
    },

    getStyles() {
        return `
        <style>
            .rtoc-container { padding: 40px; color: #e2e8f0; font-family: 'Outfit', sans-serif; max-width: 1400px; margin: 0 auto; }
            .rtoc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.1); }
            .rtoc-title { font-size: 2.2rem; font-weight: 800; color: #f43f5e; margin: 0; letter-spacing: 1px; }
            .rtoc-subtitle { color: #94a3b8; font-family: 'JetBrains Mono', monospace; margin: 5px 0 0; }
            
            .rtoc-btn { padding: 10px 20px; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 8px; }
            .rtoc-btn.primary { background: #f43f5e; color: #fff; }
            .rtoc-btn.primary:hover { background: #e11d48; }
            .rtoc-btn.secondary { background: rgba(255,255,255,0.1); color: #fff; }
            .rtoc-btn.secondary:hover { background: rgba(255,255,255,0.2); }
            .rtoc-btn.small { padding: 6px 12px; font-size: 0.85rem; }

            /* Dashboard Stats */
            .rtoc-stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
            .rtoc-stat-card { background: #1e1e2e; padding: 25px; border-radius: 16px; display: flex; align-items: center; gap: 20px; border: 1px solid rgba(255,255,255,0.05); }
            .rtoc-stat-card .icon { width: 50px; height: 50px; border-radius: 12px; background: rgba(255,255,255,0.05); display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: #94a3b8; }
            .rtoc-stat-card.active .icon { background: rgba(99,102,241,0.2); color: #6366f1; }
            .rtoc-stat-card.danger .icon { background: rgba(244,63,94,0.2); color: #f43f5e; }
            .rtoc-stat-card h3 { font-size: 1.8rem; margin: 0; color: #fff; }
            .rtoc-stat-card p { margin: 0; color: #94a3b8; font-size: 0.9rem; }

            /* Projects Grid */
            .rtoc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 25px; }
            .rtoc-project-card { background: #151520; padding: 25px; border-radius: 16px; border: 1px solid #2d2d44; cursor: pointer; transition: 0.3s; position: relative; overflow: hidden; }
            .rtoc-project-card:hover { transform: translateY(-5px); border-color: #f43f5e; }
            .rtoc-project-card h3 { margin: 15px 0 5px 0; color: #fff; }
            .rtoc-project-card .client { color: #94a3b8; margin-bottom: 20px; font-size: 0.95rem; }
            .rtoc-project-card .meta { display: flex; justify-content: space-between; font-size: 0.85rem; color: #64748b; border-top: 1px solid #2d2d44; padding-top: 15px; }

            .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
            .badge.processing { background: rgba(245,158,11,0.2); color: #fbbf24; }
            .badge.done { background: rgba(16,185,129,0.2); color: #34d399; }

            /* Project View */
            .project-meta-bar { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 30px; border-bottom: 1px solid #2d2d44; padding-bottom: 20px; }
            .project-tabs { display: flex; gap: 10px; margin-bottom: 30px; }
            .tab-btn { background: transparent; border: none; color: #94a3b8; padding: 10px 20px; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 600; }
            .tab-btn.active { color: #f43f5e; border-bottom-color: #f43f5e; }

            /* Table */
            .rtoc-table-wrapper { background: #1e1e2e; border-radius: 12px; overflow: hidden; border: 1px solid #2d2d44; }
            .rtoc-table { width: 100%; border-collapse: collapse; }
            .rtoc-table th { background: #151520; padding: 15px; text-align: left; color: #94a3b8; font-size: 0.9rem; border-bottom: 1px solid #2d2d44; }
            .rtoc-table td { padding: 15px; border-bottom: 1px solid #2d2d44; color: #cbd5e1; }
            .sev-badge { padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.8rem; }
            .sev-badge.critical { background: #7f1d1d; color: #fecaca; }
            .sev-badge.high { background: #7c2d12; color: #fdba74; }
            .sev-badge.medium { background: #78350f; color: #fcd34d; }
            
            .action-btn { background: none; border: none; cursor: pointer; color: #64748b; font-size: 1.1rem; }
            .action-btn:hover { color: #f43f5e; }

            /* Modals */
            .rtoc-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; backdrop-filter: blur(5px); }
            .rtoc-modal-box { background: #1e1e2e; padding: 30px; border-radius: 16px; width: 400px; border: 1px solid #2d2d44; }
            .rtoc-modal-box.large { width: 600px; }
            .rtoc-input { width: 100%; padding: 12px; background: #0f0f16; border: 1px solid #2d2d44; color: #fff; margin-bottom: 15px; border-radius: 8px; }
            .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
        </style>
        `;
    }
};
