/* ==================== BUG BOUNTY DASHBOARD 🎯💰 ==================== */
/* Target Management, Methodology Tracker & Findings Organizer */

window.BugBountyDash = {
    // --- STATE ---
    currentTab: 'programs',
    targets: [],
    findings: [],
    notes: '',

    // --- INITIALIZATION ---
    init() {
        try {
            this.targets = JSON.parse(localStorage.getItem('bb_targets') || '[]');
            this.findings = JSON.parse(localStorage.getItem('bb_findings') || '[]');
            this.notes = JSON.parse(localStorage.getItem('bb_notes') || '""'); // Fix for notes being just a string sometimes
        } catch (e) {
            console.error('Error loading Bug Bounty Data:', e);
            this.targets = [];
            this.findings = [];
            this.notes = '';
        }
    },

    // --- PROGRAMS DATABASE ---
    programs: [
        { name: 'HackerOne', url: 'https://hackerone.com/directory/programs', type: 'Platform', icon: '🔴' },
        { name: 'Bugcrowd', url: 'https://bugcrowd.com/programs', type: 'Platform', icon: '🟠' },
        { name: 'Intigriti', url: 'https://intigriti.com/programs', type: 'Platform', icon: '🟢' },
        { name: 'YesWeHack', url: 'https://yeswehack.com/programs', type: 'Platform', icon: '🔵' },
        { name: 'Google VRP', url: 'https://bughunters.google.com/', type: 'Direct', icon: '🟡' },
        { name: 'Meta', url: 'https://facebook.com/whitehat', type: 'Direct', icon: '🔵' },
        { name: 'Microsoft', url: 'https://msrc.microsoft.com/bounty', type: 'Direct', icon: '🟦' },
        { name: 'Apple', url: 'https://security.apple.com/', type: 'Direct', icon: '⚪' }
    ],

    // --- AI MODULE ---
    ai: {
        analyzeScope(scope) {
            const suggestions = [];
            if (scope.includes('*')) suggestions.push({ text: 'Wildcard Domain Detected: Use Subfinder & Amass for enumeration.', icon: 'fa-sitemap' });
            if (scope.includes('api')) suggestions.push({ text: 'API Endpoint: Check for IDOR, Broken Auth, and improper asset management.', icon: 'fa-plug' });
            if (scope.includes('admin') || scope.includes('internal')) suggestions.push({ text: 'High Value Target: Focus on Access Control & Privilege Escalation.', icon: 'fa-lock' });
            if (scope.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) suggestions.push({ text: 'IP Range: Perform port scanning (Nmap/Masscan) & search for specific services.', icon: 'fa-network-wired' });
            if (suggestions.length === 0) suggestions.push({ text: 'General Scope: Start with recon and technology fingerprinting.', icon: 'fa-search' });
            return suggestions;
        },
        generateDorks(domain) {
            if (!domain) return [];
            return [
                { title: 'Public Documents', query: `site:${domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv` },
                { title: 'Config Files', query: `site:${domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini` },
                { title: 'Database Files', query: `site:${domain} ext:sql | ext:dbf | ext:mdb` },
                { title: 'Backup Files', query: `site:${domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup` },
                { title: 'Login Pages', query: `site:${domain} inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth` },
                { title: 'Sensitive Git', query: `site:${domain} inurl:.git` }
            ];
        }
    },

    // --- METHODOLOGY ---
    methodology: {
        recon: {
            title: 'Reconnaissance', icon: 'fa-search',
            tasks: [
                { id: 'r1', text: 'Subdomain enumeration (subfinder, amass)', done: false },
                { id: 'r2', text: 'Port scanning (nmap, masscan)', done: false },
                { id: 'r3', text: 'Technology fingerprinting', done: false },
                { id: 'r4', text: 'Content discovery (ffuf, gobuster)', done: false },
                { id: 'r5', text: 'JavaScript analysis', done: false },
                { id: 'r6', text: 'Wayback URLs collection', done: false },
                { id: 'r7', text: 'Parameter discovery', done: false },
                { id: 'r8', text: 'GitHub/GitLab dorking', done: false }
            ]
        },
        auth: {
            title: 'Authentication', icon: 'fa-key',
            tasks: [
                { id: 'a1', text: 'Test login bypass', done: false },
                { id: 'a2', text: 'Password reset flaws', done: false },
                { id: 'a3', text: 'Session management', done: false },
                { id: 'a4', text: 'JWT vulnerabilities', done: false },
                { id: 'a5', text: 'OAuth/SSO issues', done: false },
                { id: 'a6', text: '2FA bypass', done: false }
            ]
        },
        authz: {
            title: 'Authorization', icon: 'fa-lock',
            tasks: [
                { id: 'z1', text: 'IDOR testing', done: false },
                { id: 'z2', text: 'Privilege escalation', done: false },
                { id: 'z3', text: 'Access control bypass', done: false },
                { id: 'z4', text: 'Role manipulation', done: false }
            ]
        },
        injection: {
            title: 'Injection', icon: 'fa-syringe',
            tasks: [
                { id: 'i1', text: 'XSS (Reflected, Stored, DOM)', done: false },
                { id: 'i2', text: 'SQL Injection', done: false },
                { id: 'i3', text: 'NoSQL Injection', done: false },
                { id: 'i4', text: 'Command Injection', done: false },
                { id: 'i5', text: 'SSTI/Template Injection', done: false },
                { id: 'i6', text: 'LDAP/XML Injection', done: false }
            ]
        },
        server: {
            title: 'Server-Side', icon: 'fa-server',
            tasks: [
                { id: 's1', text: 'SSRF testing', done: false },
                { id: 's2', text: 'XXE/XML attacks', done: false },
                { id: 's3', text: 'File upload vulnerabilities', done: false },
                { id: 's4', text: 'Path traversal', done: false },
                { id: 's5', text: 'Deserialization', done: false },
                { id: 's6', text: 'Race conditions', done: false }
            ]
        },
        misc: {
            title: 'Miscellaneous', icon: 'fa-ellipsis-h',
            tasks: [
                { id: 'm1', text: 'CORS misconfiguration', done: false },
                { id: 'm2', text: 'CSRF vulnerabilities', done: false },
                { id: 'm3', text: 'Open redirects', done: false },
                { id: 'm4', text: 'Information disclosure', done: false },
                { id: 'm5', text: 'Subdomain takeover', done: false },
                { id: 'm6', text: 'Business logic flaws', done: false }
            ]
        }
    },

    // --- SEVERITY ---
    severities: [
        { name: 'Critical', color: '#dc2626', bounty: '$3,000 - $20,000+' },
        { name: 'High', color: '#ea580c', bounty: '$1,000 - $5,000' },
        { name: 'Medium', color: '#ca8a04', bounty: '$250 - $1,500' },
        { name: 'Low', color: '#16a34a', bounty: '$50 - $500' },
        { name: 'Info', color: '#6b7280', bounty: 'Usually no bounty' }
    ],

    // --- RENDER ---
    render() {
        if (!this.targets) this.init(); // Ensure init

        return `
            <div class="bb-app fade-in">
                <div class="bb-header">
                    <h1><i class="fas fa-bullseye"></i> Target Manager <span style="font-size:0.6em;background:#10b981;color:#000;padding:2px 8px;border-radius:10px;vertical-align:middle;">AI ENABLED</span></h1>
                    <p class="subtitle">Smart Target Management & Methodology Tracker</p>
                </div>

                <div class="bb-tabs">
                    <div class="tab ${this.currentTab === 'programs' ? 'active' : ''}" onclick="BugBountyDash.switchTab('programs')">
                        <i class="fas fa-globe"></i> Programs
                    </div>
                    <div class="tab ${this.currentTab === 'targets' ? 'active' : ''}" onclick="BugBountyDash.switchTab('targets')">
                        <i class="fas fa-crosshairs"></i> My Targets
                    </div>
                    <div class="tab ${this.currentTab === 'ai_insight' ? 'active' : ''}" onclick="BugBountyDash.switchTab('ai_insight')" style="border: 1px solid #10b981; color: #10b981;">
                        <i class="fas fa-robot"></i> AI Assistant
                    </div>
                    <div class="tab ${this.currentTab === 'methodology' ? 'active' : ''}" onclick="BugBountyDash.switchTab('methodology')">
                        <i class="fas fa-tasks"></i> Methodology
                    </div>
                    <div class="tab ${this.currentTab === 'findings' ? 'active' : ''}" onclick="BugBountyDash.switchTab('findings')">
                        <i class="fas fa-bug"></i> Findings
                    </div>
                    <div class="tab ${this.currentTab === 'notes' ? 'active' : ''}" onclick="BugBountyDash.switchTab('notes')">
                        <i class="fas fa-sticky-note"></i> Notes
                    </div>
                </div>

                <div class="bb-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'programs': return this.renderPrograms();
            case 'targets': return this.renderTargets();
            case 'ai_insight': return this.renderAIInsight();
            case 'methodology': return this.renderMethodology();
            case 'findings': return this.renderFindings();
            case 'notes': return this.renderNotes();
            default: return '';
        }
    },

    renderAIInsight() {
        return `
            <div class="ai-section">
                <div class="ai-header">
                    <h2><i class="fas fa-robot"></i> AI Target Assistant</h2>
                    <p class="ai-subtitle">Select a target to get AI-powered analysis and recon data</p>
                </div>

                <div class="ai-controls">
                     <select id="ai-target-select" onchange="BugBountyDash.updateAIAnalysis()">
                        <option value="">-- Select Target --</option>
                        ${this.targets.map(t => `<option value="${t.name}">${t.name}</option>`).join('')}
                     </select>
                </div>

                <div id="ai-results" class="ai-results">
                    <div class="empty-state">
                        <i class="fas fa-brain" style="color:#10b981"></i>
                        <p>Select a target to start AI analysis...</p>
                    </div>
                </div>
            </div>
        `;
    },

    updateAIAnalysis() {
        const select = document.getElementById('ai-target-select');
        const targetName = select.value;
        const container = document.getElementById('ai-results');

        if (!targetName) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-brain" style="color:#10b981"></i><p>Select a target to start AI analysis...</p></div>';
            return;
        }

        const target = this.targets.find(t => t.name === targetName);
        if (!target) return;

        const scopeAnalysis = this.ai.analyzeScope(target.scope);
        const dorks = this.ai.generateDorks(targetName.replace(' ', '').toLowerCase() + '.com'); // Simple heuristic for domain

        container.innerHTML = `
            <div class="ai-dashboard-grid">
                <!-- Scope Analysis -->
                <div class="ai-card">
                    <h3><i class="fas fa-microscope"></i> Scope Intel</h3>
                    <div class="suggestion-list">
                        ${scopeAnalysis.map(s => `
                            <div class="suggestion-item">
                                <i class="fas ${s.icon}"></i>
                                <span>${s.text}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Google Dorks -->
                <div class="ai-card">
                    <h3><i class="fab fa-google"></i> Generated Dorks</h3>
                    <div class="dork-list">
                        ${dorks.map(d => `
                            <div class="dork-item">
                                <span class="dork-title">${d.title}</span>
                                <code onclick="navigator.clipboard.writeText(this.innerText); alert('Copied!')">${d.query}</code>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Recommended Tools -->
                <div class="ai-card">
                    <h3><i class="fas fa-toolbox"></i> Toolkit Recommendation</h3>
                    <div class="tool-tags">
                        ${this.getRecommendedTools(target.scope).map(t => `<span class="tool-tag">${t}</span>`).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    getRecommendedTools(scope) {
        const tools = ['Burp Suite', 'FFUF'];
        if (scope.includes('*')) tools.push('Subfinder', 'Amass', 'httpx');
        if (scope.includes('api')) tools.push('Postman', 'Kiterunner', 'Arjun');
        if (scope.includes('js')) tools.push('JSLinkFinder', 'Retire.js');
        tools.push('Nuclei'); // Always recommend Nuclei
        return tools;
    },

    renderPrograms() {
        return `
            <div class="programs-section">
                <h2><i class="fas fa-globe"></i> Bug Bounty Platforms</h2>
                <div class="programs-grid">
                    ${this.programs.map(p => `
                        <a href="${p.url}" target="_blank" class="program-card">
                            <span class="program-icon">${p.icon}</span>
                            <div class="program-info">
                                <h4>${p.name}</h4>
                                <span class="program-type">${p.type}</span>
                            </div>
                            <i class="fas fa-external-link-alt"></i>
                        </a>
                    `).join('')}
                </div>

                <div class="severity-guide">
                    <h3><i class="fas fa-dollar-sign"></i> Bounty Ranges</h3>
                    <div class="severity-grid">
                        ${this.severities.map(s => `
                            <div class="severity-card" style="border-left-color: ${s.color}">
                                <span class="severity-name" style="color: ${s.color}">${s.name}</span>
                                <span class="severity-bounty">${s.bounty}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderTargets() {
        return `
            <div class="targets-section">
                <div class="targets-header">
                    <h2><i class="fas fa-crosshairs"></i> My Targets</h2>
                    <button onclick="BugBountyDash.addTarget()"><i class="fas fa-plus"></i> Add Target</button>
                </div>
                
                <div class="targets-list">
                    ${this.targets.length === 0 ?
                '<div class="empty-state"><i class="fas fa-crosshairs"></i><p>No targets yet. Add your first target!</p></div>' :
                this.targets.map((t, i) => `
                            <div class="target-card">
                                <div class="target-header">
                                    <h4>${t.name}</h4>
                                    <span class="target-status status-${t.status}">${t.status}</span>
                                </div>
                                <p class="target-scope">${t.scope}</p>
                                <div class="target-meta">
                                    <span><i class="fas fa-calendar"></i> ${t.date}</span>
                                    <span><i class="fas fa-bug"></i> ${t.findings || 0} findings</span>
                                </div>
                                <div class="target-actions">
                                    <button onclick="BugBountyDash.editTarget(${i})"><i class="fas fa-edit"></i></button>
                                    <button onclick="BugBountyDash.deleteTarget(${i})"><i class="fas fa-trash"></i></button>
                                </div>
                            </div>
                        `).join('')
            }
                </div>
            </div>
        `;
    },

    renderMethodology() {
        const savedProgress = JSON.parse(localStorage.getItem('bb_methodology') || '{}');

        return `
            <div class="methodology-section">
                <div class="methodology-header">
                    <h2><i class="fas fa-tasks"></i> Testing Methodology</h2>
                    <button onclick="BugBountyDash.resetMethodology()"><i class="fas fa-redo"></i> Reset</button>
                </div>
                
                <div class="methodology-grid">
                    ${Object.entries(this.methodology).map(([key, phase]) => `
                        <div class="phase-card">
                            <div class="phase-header">
                                <i class="fas ${phase.icon}"></i>
                                <h3>${phase.title}</h3>
                                <span class="phase-progress">${this.getPhaseProgress(key, savedProgress)}%</span>
                            </div>
                            <div class="phase-tasks">
                                ${phase.tasks.map(task => `
                                    <label class="task-item">
                                        <input type="checkbox" ${savedProgress[task.id] ? 'checked' : ''} 
                                               onchange="BugBountyDash.toggleTask('${task.id}')">
                                        <span>${task.text}</span>
                                    </label>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderFindings() {
        return `
            <div class="findings-section">
                <div class="findings-header">
                    <h2><i class="fas fa-bug"></i> My Findings</h2>
                    <button onclick="BugBountyDash.addFinding()"><i class="fas fa-plus"></i> Add Finding</button>
                </div>
                
                <div class="findings-stats">
                    <div class="stat"><span class="stat-num">${this.findings.filter(f => f.severity === 'Critical').length}</span><span>Critical</span></div>
                    <div class="stat"><span class="stat-num">${this.findings.filter(f => f.severity === 'High').length}</span><span>High</span></div>
                    <div class="stat"><span class="stat-num">${this.findings.filter(f => f.severity === 'Medium').length}</span><span>Medium</span></div>
                    <div class="stat"><span class="stat-num">${this.findings.filter(f => f.severity === 'Low').length}</span><span>Low</span></div>
                </div>

                <div class="findings-list">
                    ${this.findings.length === 0 ?
                '<div class="empty-state"><i class="fas fa-bug"></i><p>No findings yet. Start hunting!</p></div>' :
                this.findings.map((f, i) => `
                            <div class="finding-card severity-${f.severity.toLowerCase()}">
                                <div class="finding-header">
                                    <span class="finding-severity">${f.severity}</span>
                                    <h4>${f.title}</h4>
                                </div>
                                <p class="finding-target">${f.target}</p>
                                <p class="finding-desc">${f.description}</p>
                                <div class="finding-meta">
                                    <span class="finding-status status-${f.status}">${f.status}</span>
                                    <span class="finding-date">${f.date}</span>
                                </div>
                                <div class="finding-actions">
                                    <button onclick="BugBountyDash.deleteFinding(${i})"><i class="fas fa-trash"></i></button>
                                </div>
                            </div>
                        `).join('')
            }
                </div>
            </div>
        `;
    },

    renderNotes() {
        return `
            <div class="notes-section">
                <h2><i class="fas fa-sticky-note"></i> Quick Notes</h2>
                <textarea id="bb-notes" placeholder="Write your notes here... (auto-saved)"
                          onchange="BugBountyDash.saveNotes()">${this.notes}</textarea>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    addTarget() {
        const name = prompt('Target Name:');
        if (!name) return;
        const scope = prompt('Scope (domains, IPs):') || '';
        this.targets.push({
            name,
            scope,
            status: 'active',
            date: new Date().toLocaleDateString(),
            findings: 0
        });
        this.saveTargets();
        this.reRender();
    },

    editTarget(index) {
        const t = this.targets[index];
        const name = prompt('Target Name:', t.name);
        if (!name) return;
        const scope = prompt('Scope:', t.scope);
        const status = prompt('Status (active/paused/done):', t.status);
        this.targets[index] = { ...t, name, scope, status: status || t.status };
        this.saveTargets();
        this.reRender();
    },

    deleteTarget(index) {
        if (confirm('Delete this target?')) {
            this.targets.splice(index, 1);
            this.saveTargets();
            this.reRender();
        }
    },

    addFinding() {
        const title = prompt('Vulnerability Title:');
        if (!title) return;
        const target = prompt('Target:') || '';
        const severity = prompt('Severity (Critical/High/Medium/Low):') || 'Medium';
        const description = prompt('Description:') || '';
        this.findings.push({
            title,
            target,
            severity,
            description,
            status: 'reported',
            date: new Date().toLocaleDateString()
        });
        this.saveFindings();
        this.reRender();
    },

    deleteFinding(index) {
        if (confirm('Delete this finding?')) {
            this.findings.splice(index, 1);
            this.saveFindings();
            this.reRender();
        }
    },

    toggleTask(taskId) {
        const progress = JSON.parse(localStorage.getItem('bb_methodology') || '{}');
        progress[taskId] = !progress[taskId];
        localStorage.setItem('bb_methodology', JSON.stringify(progress));
        this.reRender();
    },

    getPhaseProgress(phaseKey, savedProgress) {
        const tasks = this.methodology[phaseKey].tasks;
        const done = tasks.filter(t => savedProgress[t.id]).length;
        return Math.round((done / tasks.length) * 100);
    },

    resetMethodology() {
        if (confirm('Reset all methodology progress?')) {
            localStorage.removeItem('bb_methodology');
            this.reRender();
        }
    },

    saveNotes() {
        this.notes = document.getElementById('bb-notes').value;
        localStorage.setItem('bb_notes', JSON.stringify(this.notes));
    },

    saveTargets() {
        localStorage.setItem('bb_targets', JSON.stringify(this.targets));
    },

    saveFindings() {
        localStorage.setItem('bb_findings', JSON.stringify(this.findings));
    },

    reRender() {
        const app = document.querySelector('.bb-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .bb-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .bb-header h1 { margin: 0; color: #10b981; font-size: 1.8rem; }
            .bb-header .subtitle { color: #888; margin: 5px 0 20px; }

            .bb-tabs { display: flex; gap: 5px; margin-bottom: 20px; flex-wrap: wrap; }
            .tab { padding: 10px 16px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #10b981; color: #fff; }

            .programs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .program-card { display: flex; align-items: center; gap: 12px; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; text-decoration: none; color: inherit; transition: 0.2s; }
            .program-card:hover { background: rgba(16,185,129,0.1); transform: translateY(-2px); }
            .program-icon { font-size: 1.5rem; }
            .program-info h4 { margin: 0; color: #fff; }
            .program-type { color: #888; font-size: 0.8rem; }
            .program-card .fa-external-link-alt { margin-left: auto; color: #666; }

            .severity-guide h3 { color: #10b981; margin: 0 0 15px; }
            .severity-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
            .severity-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; border-left: 3px solid; }
            .severity-name { font-weight: bold; }
            .severity-bounty { color: #888; font-size: 0.85rem; display: block; margin-top: 5px; }

            .targets-header, .findings-header, .methodology-header, .ai-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .targets-header h2, .findings-header h2, .methodology-header h2, .ai-header h2 { color: #10b981; margin: 0; }
            .targets-header button, .findings-header button, .methodology-header button { padding: 10px 20px; background: #10b981; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .empty-state { text-align: center; padding: 60px 20px; color: #666; }
            .empty-state i { font-size: 3rem; margin-bottom: 15px; }

            .targets-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
            .target-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .target-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .target-header h4 { margin: 0; color: #fff; }
            .target-status { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; }
            .status-active { background: rgba(16,185,129,0.2); color: #10b981; }
            .status-paused { background: rgba(234,179,8,0.2); color: #eab308; }
            .status-done { background: rgba(107,114,128,0.2); color: #6b7280; }
            .target-scope { color: #888; margin: 0 0 10px; font-size: 0.9rem; }
            .target-meta { display: flex; gap: 15px; color: #666; font-size: 0.85rem; margin-bottom: 15px; }
            .target-actions { display: flex; gap: 10px; }
            .target-actions button { padding: 8px 12px; background: rgba(255,255,255,0.05); border: none; border-radius: 6px; color: #888; cursor: pointer; }
            .target-actions button:hover { color: #10b981; }
            
            /* AI Section */
            .ai-subtitle { color: #888; margin-top: 5px; }
            .ai-controls select { padding: 10px; background: rgba(0,0,0,0.3); color: #fff; border: 1px solid #333; border-radius: 8px; width: 100%; max-width: 300px; font-size: 1rem; }
            .ai-dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
            .ai-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; border: 1px solid rgba(16,185,129,0.1); }
            .ai-card h3 { color: #10b981; margin: 0 0 15px; display: flex; align-items: center; gap: 10px; }
            .suggestion-list { display: flex; flex-direction: column; gap: 12px; }
            .suggestion-item { display: flex; align-items: flex-start; gap: 12px; background: rgba(255,255,255,0.02); padding: 10px; border-radius: 8px; }
            .suggestion-item i { color: #10b981; margin-top: 3px; }
            .dork-list { display: flex; flex-direction: column; gap: 10px; }
            .dork-item { background: rgba(0,0,0,0.5); padding: 10px; border-radius: 8px; }
            .dork-title { color: #888; font-size: 0.8rem; display: block; margin-bottom: 4px; }
            .dork-item code { color: #10b981; font-family: monospace; cursor: pointer; display: block; overflow-x: auto; white-space: nowrap; }
            .tool-tags { display: flex; flex-wrap: wrap; gap: 8px; }
            .tool-tag { background: rgba(16,185,129,0.15); color: #10b981; padding: 4px 10px; border-radius: 20px; font-size: 0.85rem; }

            .methodology-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
            .phase-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .phase-header { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
            .phase-header i { color: #10b981; font-size: 1.2rem; }
            .phase-header h3 { margin: 0; color: #fff; flex: 1; }
            .phase-progress { background: rgba(16,185,129,0.2); color: #10b981; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; }
            .phase-tasks { display: flex; flex-direction: column; gap: 8px; }
            .task-item { display: flex; align-items: center; gap: 10px; padding: 8px; background: rgba(255,255,255,0.02); border-radius: 6px; cursor: pointer; }
            .task-item input { accent-color: #10b981; }
            .task-item input:checked + span { color: #10b981; text-decoration: line-through; }

            .findings-stats { display: flex; gap: 20px; margin-bottom: 25px; }
            .stat { background: rgba(0,0,0,0.3); padding: 20px 30px; border-radius: 12px; text-align: center; }
            .stat-num { display: block; font-size: 2rem; font-weight: bold; color: #10b981; }

            .findings-list { display: flex; flex-direction: column; gap: 15px; }
            .finding-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; border-left: 3px solid; }
            .finding-card.severity-critical { border-color: #dc2626; }
            .finding-card.severity-high { border-color: #ea580c; }
            .finding-card.severity-medium { border-color: #ca8a04; }
            .finding-card.severity-low { border-color: #16a34a; }
            .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
            .finding-severity { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
            .severity-critical .finding-severity { background: rgba(220,38,38,0.2); color: #dc2626; }
            .severity-high .finding-severity { background: rgba(234,88,12,0.2); color: #ea580c; }
            .severity-medium .finding-severity { background: rgba(202,138,4,0.2); color: #ca8a04; }
            .severity-low .finding-severity { background: rgba(22,163,74,0.2); color: #16a34a; }
            .finding-header h4 { margin: 0; color: #fff; }
            .finding-target { color: #10b981; margin: 0 0 5px; font-size: 0.9rem; }
            .finding-desc { color: #888; margin: 0 0 10px; }
            .finding-meta { display: flex; gap: 15px; }
            .finding-status { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; }
            .status-reported { background: rgba(59,130,246,0.2); color: #3b82f6; }
            .finding-date { color: #666; font-size: 0.85rem; }
            .finding-actions { position: absolute; top: 20px; right: 20px; }
            .finding-card { position: relative; }
            .finding-actions button { background: none; border: none; color: #666; cursor: pointer; }

            .notes-section h2 { color: #10b981; margin: 0 0 20px; }
            .notes-section textarea { width: 100%; height: 400px; background: rgba(0,0,0,0.3); border: 1px solid #333; border-radius: 12px; padding: 20px; color: #fff; font-size: 1rem; resize: vertical; }

            @media (max-width: 800px) { .methodology-grid, .targets-list { grid-template-columns: 1fr; } .findings-stats { flex-wrap: wrap; } }
        </style>`;
    }
};

function pageBugBountyDash() {
    BugBountyDash.init(); // Auto init
    return BugBountyDash.render();
}
