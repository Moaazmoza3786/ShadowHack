/* ==================== OSINT INVESTIGATION LAB 🕵️🌐 ==================== */
/* Open Source Intelligence Gathering & Analysis */

window.OSINTLab = {
    // --- STATE ---
    currentTab: 'challenges',
    selectedChallenge: null,
    solvedChallenges: JSON.parse(localStorage.getItem('osint_solved') || '[]'),

    // --- CHALLENGES DATA ---
    challenges: [
        {
            id: 'username-1',
            name: 'Username Hunter',
            difficulty: 'Easy',
            points: 50,
            category: 'Social Media',
            description: 'Find which platforms this username exists on.',
            scenario: 'Target username: "h4ck3r_j0hn_2024"',
            task: 'Identify the platforms where this username is registered.',
            hint: 'Use tools like Sherlock, WhatsMyName, or Namechk.',
            answer: 'TWITTER,GITHUB,REDDIT'
        },
        {
            id: 'email-1',
            name: 'Email Investigation',
            difficulty: 'Easy',
            points: 50,
            category: 'Email OSINT',
            description: 'Investigate what you can find about this email.',
            scenario: 'Email: john.smith.security@protonmail.com',
            task: 'Find data breaches associated with this email.',
            hint: 'Check HaveIBeenPwned, DeHashed, or IntelX.',
            answer: 'LINKEDIN_BREACH_2021'
        },
        {
            id: 'image-1',
            name: 'Geolocation Challenge',
            difficulty: 'Medium',
            points: 100,
            category: 'Image OSINT',
            description: 'Identify the location from the image metadata and clues.',
            scenario: 'You received an anonymous photo. Find where it was taken.',
            task: 'Extract GPS coordinates or identify the landmark.',
            hint: 'Check EXIF data first, then use Google Lens or reverse image search.',
            answer: '40.7128,-74.0060'
        },
        {
            id: 'domain-1',
            name: 'Domain Reconnaissance',
            difficulty: 'Medium',
            points: 100,
            category: 'Infrastructure',
            description: 'Gather intelligence on the target domain.',
            scenario: 'Target: evil-corp-example.com',
            task: 'Find the registrant, nameservers, and subdomains.',
            hint: 'Use WHOIS, DNSDumpster, Subfinder, crt.sh',
            answer: 'FLAG{D0M41N_3NUM3R4T10N}'
        },
        {
            id: 'person-1',
            name: 'Person of Interest',
            difficulty: 'Hard',
            points: 200,
            category: 'People Search',
            description: 'Build a profile on the target individual.',
            scenario: 'Name: Alex Mercer, Company: TechSecure Inc.',
            task: 'Find their LinkedIn, previous employers, and education.',
            hint: 'Use LinkedIn, Pipl, Google Dorks, company websites.',
            answer: 'FLAG{P30PL3_05INT}'
        },
        {
            id: 'breach-1',
            name: 'Dark Web Discovery',
            difficulty: 'Hard',
            points: 200,
            category: 'Dark Web',
            description: 'Investigate a suspected data leak.',
            scenario: 'Company "SecureVault" reported a breach. Find leaked data.',
            task: 'Identify what type of data was exposed.',
            hint: 'Check paste sites, breach databases, and dark web monitoring.',
            answer: 'EMAILS,PASSWORDS,SSN'
        }
    ],

    // --- TOOLS DATA ---
    tools: [
        { name: 'Sherlock', icon: 'fa-user-secret', desc: 'Username search across platforms', cmd: 'sherlock username' },
        { name: 'theHarvester', icon: 'fa-seedling', desc: 'Email & subdomain gathering', cmd: 'theHarvester -d domain.com -b all' },
        { name: 'Maltego', icon: 'fa-project-diagram', desc: 'Visual link analysis', cmd: 'GUI Tool' },
        { name: 'SpiderFoot', icon: 'fa-spider', desc: 'Automated OSINT', cmd: 'spiderfoot -s target.com' },
        { name: 'Recon-ng', icon: 'fa-terminal', desc: 'Recon framework', cmd: 'recon-ng' },
        { name: 'Google Dorks', icon: 'fa-search', desc: 'Advanced search queries', cmd: 'site:target.com filetype:pdf' },
        { name: 'Shodan', icon: 'fa-server', desc: 'IoT & server search', cmd: 'shodan search hostname:target.com' },
        { name: 'WHOIS', icon: 'fa-info-circle', desc: 'Domain registration info', cmd: 'whois domain.com' }
    ],

    // --- DORKS DATABASE ---
    dorks: [
        { category: 'Files', query: 'site:target.com filetype:pdf', desc: 'Find PDF documents' },
        { category: 'Files', query: 'site:target.com filetype:xlsx', desc: 'Find Excel files' },
        { category: 'Credentials', query: 'site:target.com intext:password', desc: 'Find exposed passwords' },
        { category: 'Credentials', query: '"target.com" intext:@target.com filetype:txt', desc: 'Find email lists' },
        { category: 'Admin', query: 'site:target.com inurl:admin', desc: 'Find admin panels' },
        { category: 'Admin', query: 'site:target.com intitle:"index of"', desc: 'Find directory listings' },
        { category: 'Config', query: 'site:target.com ext:env OR ext:config', desc: 'Find config files' },
        { category: 'Backup', query: 'site:target.com ext:bak OR ext:old', desc: 'Find backup files' },
        { category: 'AWS', query: 'site:s3.amazonaws.com "target"', desc: 'Find S3 buckets' },
        { category: 'GitHub', query: 'site:github.com "target.com" password', desc: 'Find leaked secrets' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="osint-app fade-in">
                <div class="osint-header">
                    <div class="header-left">
                        <h1><i class="fas fa-globe"></i> OSINT Investigation Lab</h1>
                        <p class="subtitle">Open Source Intelligence Gathering</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat"><span class="val">${this.solvedChallenges.length}/${this.challenges.length}</span><span class="label">Solved</span></div>
                        <div class="stat"><span class="val">${this.getTotalPoints()}</span><span class="label">Points</span></div>
                    </div>
                </div>

                <div class="osint-tabs">
                    <div class="tab ${this.currentTab === 'challenges' ? 'active' : ''}" onclick="OSINTLab.switchTab('challenges')">
                        <i class="fas fa-flag"></i> Challenges
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="OSINTLab.switchTab('tools')">
                        <i class="fas fa-toolbox"></i> Tools
                    </div>
                    <div class="tab ${this.currentTab === 'dorks' ? 'active' : ''}" onclick="OSINTLab.switchTab('dorks')">
                        <i class="fas fa-search"></i> Google Dorks
                    </div>
                    <div class="tab ${this.currentTab === 'workflow' ? 'active' : ''}" onclick="OSINTLab.switchTab('workflow')">
                        <i class="fas fa-sitemap"></i> Methodology
                    </div>
                </div>

                <div class="osint-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'challenges': return this.renderChallenges();
            case 'tools': return this.renderTools();
            case 'dorks': return this.renderDorks();
            case 'workflow': return this.renderWorkflow();
            default: return '';
        }
    },

    renderChallenges() {
        return `
            <div class="challenges-container">
                <div class="challenges-list">
                    ${this.challenges.map(c => {
            const solved = this.solvedChallenges.includes(c.id);
            return `
                            <div class="challenge-card ${solved ? 'solved' : ''} ${this.selectedChallenge === c.id ? 'active' : ''}" onclick="OSINTLab.selectChallenge('${c.id}')">
                                <div class="challenge-icon ${solved ? 'done' : ''}">
                                    ${solved ? '<i class="fas fa-check"></i>' : '<i class="fas fa-search"></i>'}
                                </div>
                                <div class="challenge-info">
                                    <h4>${c.name}</h4>
                                    <span class="category">${c.category}</span>
                                </div>
                                <div class="challenge-meta">
                                    <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                                    <span class="pts">${c.points} pts</span>
                                </div>
                            </div>
                        `;
        }).join('')}
                </div>
                ${this.selectedChallenge ? this.renderChallengeDetail() : `
                    <div class="no-selection"><i class="fas fa-crosshairs"></i><p>Select a challenge to start investigating</p></div>
                `}
            </div>
        `;
    },

    renderChallengeDetail() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        if (!c) return '';
        const solved = this.solvedChallenges.includes(c.id);

        return `
            <div class="challenge-detail">
                <div class="detail-header">
                    <h2><i class="fas fa-crosshairs"></i> ${c.name}</h2>
                    <div class="badges">
                        <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                        <span class="cat">${c.category}</span>
                        <span class="pts">${c.points} pts</span>
                    </div>
                </div>

                <div class="detail-section">
                    <h3><i class="fas fa-info-circle"></i> Scenario</h3>
                    <p class="scenario-text">${c.scenario}</p>
                </div>

                <div class="detail-section">
                    <h3><i class="fas fa-bullseye"></i> Objective</h3>
                    <p>${c.task}</p>
                </div>

                <div class="hint-box" onclick="this.classList.toggle('revealed')">
                    <span class="hint-label"><i class="fas fa-lightbulb"></i> Hint (click to reveal)</span>
                    <span class="hint-text">${c.hint}</span>
                </div>

                ${solved ? `
                    <div class="solved-banner"><i class="fas fa-trophy"></i> Investigation Complete!</div>
                ` : `
                    <div class="answer-form">
                        <input type="text" id="osint-answer" placeholder="Enter your findings...">
                        <button onclick="OSINTLab.submitAnswer()"><i class="fas fa-paper-plane"></i> Submit</button>
                    </div>
                `}
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-section">
                <h2><i class="fas fa-toolbox"></i> OSINT Toolkit</h2>
                <div class="tools-grid">
                    ${this.tools.map(t => `
                        <div class="tool-card">
                            <i class="fas ${t.icon}"></i>
                            <h4>${t.name}</h4>
                            <p>${t.desc}</p>
                            <code>${t.cmd}</code>
                        </div>
                    `).join('')}
                </div>

                <div class="quick-resources">
                    <h3><i class="fas fa-link"></i> Quick Resources</h3>
                    <div class="resources-grid">
                        <a href="https://haveibeenpwned.com" target="_blank" class="resource-link">HaveIBeenPwned</a>
                        <a href="https://hunter.io" target="_blank" class="resource-link">Hunter.io</a>
                        <a href="https://crt.sh" target="_blank" class="resource-link">crt.sh</a>
                        <a href="https://shodan.io" target="_blank" class="resource-link">Shodan</a>
                        <a href="https://dnsdumpster.com" target="_blank" class="resource-link">DNSDumpster</a>
                        <a href="https://wayback.archive.org" target="_blank" class="resource-link">Wayback Machine</a>
                    </div>
                </div>
            </div>
        `;
    },

    renderDorks() {
        return `
            <div class="dorks-section">
                <h2><i class="fas fa-search"></i> Google Dorks Database</h2>
                <p class="dorks-intro">Advanced search queries for reconnaissance</p>

                <div class="dorks-input">
                    <input type="text" id="target-domain" placeholder="Enter target domain (e.g., target.com)">
                    <button onclick="OSINTLab.generateDorks()"><i class="fas fa-magic"></i> Generate</button>
                </div>

                <div class="dorks-table">
                    <div class="dorks-header">
                        <span>Category</span>
                        <span>Query</span>
                        <span>Description</span>
                        <span></span>
                    </div>
                    ${this.dorks.map(d => `
                        <div class="dork-row">
                            <span class="dork-cat">${d.category}</span>
                            <code class="dork-query">${d.query}</code>
                            <span class="dork-desc">${d.desc}</span>
                            <button class="copy-btn" onclick="OSINTLab.copyDork('${d.query}')"><i class="fas fa-copy"></i></button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderWorkflow() {
        return `
            <div class="workflow-section">
                <h2><i class="fas fa-sitemap"></i> OSINT Methodology</h2>
                <div class="workflow-grid">
                    <div class="workflow-step">
                        <div class="step-icon"><i class="fas fa-bullseye"></i></div>
                        <h3>1. Define Scope</h3>
                        <ul>
                            <li>Identify the target (person, company, domain)</li>
                            <li>Set boundaries and objectives</li>
                            <li>Determine legal considerations</li>
                        </ul>
                    </div>
                    <div class="workflow-step">
                        <div class="step-icon"><i class="fas fa-search"></i></div>
                        <h3>2. Passive Recon</h3>
                        <ul>
                            <li>WHOIS & DNS records</li>
                            <li>Social media profiles</li>
                            <li>Search engines & archives</li>
                        </ul>
                    </div>
                    <div class="workflow-step">
                        <div class="step-icon"><i class="fas fa-database"></i></div>
                        <h3>3. Data Collection</h3>
                        <ul>
                            <li>Breach databases</li>
                            <li>Email & username correlation</li>
                            <li>Infrastructure mapping</li>
                        </ul>
                    </div>
                    <div class="workflow-step">
                        <div class="step-icon"><i class="fas fa-project-diagram"></i></div>
                        <h3>4. Analysis</h3>
                        <ul>
                            <li>Connect the dots</li>
                            <li>Build relationship graphs</li>
                            <li>Identify patterns</li>
                        </ul>
                    </div>
                    <div class="workflow-step">
                        <div class="step-icon"><i class="fas fa-file-alt"></i></div>
                        <h3>5. Reporting</h3>
                        <ul>
                            <li>Document findings</li>
                            <li>Visualize connections</li>
                            <li>Provide actionable intel</li>
                        </ul>
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

    selectChallenge(id) {
        this.selectedChallenge = id;
        this.reRender();
    },

    submitAnswer() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        const input = document.getElementById('osint-answer').value.trim().toUpperCase();

        if (input === c.answer.toUpperCase()) {
            if (!this.solvedChallenges.includes(c.id)) {
                this.solvedChallenges.push(c.id);
                localStorage.setItem('osint_solved', JSON.stringify(this.solvedChallenges));
            }
            this.showNotification('🕵️ Correct! +' + c.points + ' pts', 'success');
            this.reRender();
        } else {
            this.showNotification('❌ Incorrect. Keep investigating!', 'error');
        }
    },

    generateDorks() {
        const domain = document.getElementById('target-domain').value.trim();
        if (domain) {
            this.dorks.forEach(d => d.query = d.query.replace(/target\.com/g, domain));
            this.reRender();
        }
    },

    copyDork(query) {
        navigator.clipboard.writeText(query);
        this.showNotification('Copied to clipboard!', 'success');
    },

    getTotalPoints() {
        return this.challenges.filter(c => this.solvedChallenges.includes(c.id))
            .reduce((sum, c) => sum + c.points, 0);
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `osint-notif ${type}`;
        n.innerHTML = msg;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    },

    reRender() {
        const app = document.querySelector('.osint-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .osint-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #16213e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            .osint-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .osint-header h1 { margin: 0; color: #27ae60; font-size: 1.8rem; }
            .osint-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats { display: flex; gap: 20px; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(39,174,96,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #27ae60; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            .osint-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #27ae60; color: #fff; }

            /* CHALLENGES */
            .challenges-container { display: grid; grid-template-columns: 320px 1fr; gap: 25px; }
            .challenges-list { display: flex; flex-direction: column; gap: 10px; }
            .challenge-card { display: flex; align-items: center; gap: 12px; padding: 15px; background: rgba(255,255,255,0.03); border-radius: 10px; cursor: pointer; transition: 0.2s; border: 1px solid transparent; }
            .challenge-card:hover { background: rgba(255,255,255,0.08); }
            .challenge-card.active { border-color: #27ae60; background: rgba(39,174,96,0.1); }
            .challenge-card.solved .challenge-icon { background: rgba(46,204,113,0.2); color: #2ecc71; }
            .challenge-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; background: rgba(39,174,96,0.2); color: #27ae60; }
            .challenge-icon.done { background: rgba(46,204,113,0.3); color: #2ecc71; }
            .challenge-info { flex: 1; }
            .challenge-info h4 { margin: 0; color: #fff; }
            .category { font-size: 0.8rem; color: #888; }
            .challenge-meta { display: flex; flex-direction: column; gap: 5px; }
            
            .diff { padding: 3px 10px; border-radius: 10px; font-size: 0.7rem; font-weight: bold; }
            .diff.easy { background: #2ecc71; color: #000; }
            .diff.medium { background: #f39c12; color: #000; }
            .diff.hard { background: #e74c3c; color: #fff; }
            .pts { font-size: 0.75rem; color: #ffd700; }

            .no-selection { text-align: center; padding: 80px; color: #555; }
            .no-selection i { font-size: 3rem; margin-bottom: 15px; display: block; }

            /* DETAIL */
            .challenge-detail { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .detail-header { margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 15px; }
            .detail-header h2 { margin: 0 0 10px; color: #27ae60; }
            .badges { display: flex; gap: 10px; }
            .cat { background: rgba(39,174,96,0.2); color: #27ae60; padding: 3px 10px; border-radius: 10px; font-size: 0.75rem; }
            .detail-section { margin-bottom: 20px; }
            .detail-section h3 { color: #27ae60; font-size: 1rem; margin: 0 0 10px; }
            .detail-section p { color: #aaa; }
            .scenario-text { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; border-left: 3px solid #27ae60; }

            .hint-box { background: rgba(255,215,0,0.1); padding: 12px 15px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
            .hint-label { color: #ffd700; }
            .hint-text { display: none; color: #aaa; margin-top: 8px; }
            .hint-box.revealed .hint-text { display: block; }

            .solved-banner { background: #27ae60; padding: 15px; border-radius: 10px; text-align: center; color: #fff; font-weight: bold; }
            .answer-form { display: flex; gap: 10px; }
            .answer-form input { flex: 1; padding: 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .answer-form button { padding: 12px 20px; background: #27ae60; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

            /* TOOLS */
            .tools-section h2 { color: #27ae60; margin: 0 0 20px; }
            .tools-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .tool-card { background: rgba(255,255,255,0.03); padding: 20px; border-radius: 12px; border: 1px solid transparent; transition: 0.2s; }
            .tool-card:hover { border-color: #27ae60; }
            .tool-card i { font-size: 2rem; color: #27ae60; margin-bottom: 10px; }
            .tool-card h4 { margin: 0 0 5px; color: #fff; }
            .tool-card p { margin: 0 0 10px; color: #666; font-size: 0.8rem; }
            .tool-card code { display: block; background: #0a0a12; padding: 8px; border-radius: 5px; font-size: 0.75rem; color: #2ecc71; }

            .quick-resources h3 { color: #27ae60; margin: 0 0 15px; }
            .resources-grid { display: flex; flex-wrap: wrap; gap: 10px; }
            .resource-link { background: rgba(39,174,96,0.2); color: #27ae60; padding: 8px 15px; border-radius: 20px; text-decoration: none; font-size: 0.85rem; transition: 0.2s; }
            .resource-link:hover { background: #27ae60; color: #fff; }

            /* DORKS */
            .dorks-section h2 { color: #27ae60; margin: 0 0 10px; }
            .dorks-intro { color: #888; margin-bottom: 20px; }
            .dorks-input { display: flex; gap: 10px; margin-bottom: 20px; }
            .dorks-input input { flex: 1; padding: 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .dorks-input button { padding: 12px 20px; background: #27ae60; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

            .dorks-table { background: rgba(0,0,0,0.3); border-radius: 12px; overflow: hidden; }
            .dorks-header { display: grid; grid-template-columns: 100px 1fr 1fr 40px; gap: 15px; padding: 12px 15px; background: rgba(39,174,96,0.2); font-weight: bold; color: #27ae60; }
            .dork-row { display: grid; grid-template-columns: 100px 1fr 1fr 40px; gap: 15px; padding: 12px 15px; border-bottom: 1px solid #222; align-items: center; }
            .dork-cat { background: rgba(39,174,96,0.2); color: #27ae60; padding: 3px 8px; border-radius: 5px; font-size: 0.75rem; text-align: center; }
            .dork-query { color: #f39c12; font-family: monospace; font-size: 0.8rem; }
            .dork-desc { color: #888; font-size: 0.85rem; }
            .copy-btn { background: transparent; border: none; color: #666; cursor: pointer; }
            .copy-btn:hover { color: #27ae60; }

            /* WORKFLOW */
            .workflow-section h2 { color: #27ae60; margin: 0 0 20px; }
            .workflow-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; }
            .workflow-step { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .step-icon { width: 50px; height: 50px; background: rgba(39,174,96,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 15px; }
            .step-icon i { font-size: 1.5rem; color: #27ae60; }
            .workflow-step h3 { margin: 0 0 10px; color: #fff; }
            .workflow-step ul { margin: 0; padding-left: 20px; color: #888; }
            .workflow-step li { margin: 5px 0; }

            .osint-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 9999; animation: slideIn 0.3s ease; }
            .osint-notif.success { background: #27ae60; color: #fff; }
            .osint-notif.error { background: #e74c3c; color: #fff; }
            @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

            @media (max-width: 900px) { .challenges-container { grid-template-columns: 1fr; } .dorks-header, .dork-row { grid-template-columns: 1fr; } }
        </style>
        `;
    }
};

function pageOSINTLab() {
    return OSINTLab.render();
}
