/* ==================== BUG BOUNTY SIMULATOR v2.0 (AI ENHANCED) 🎯💰 ==================== */
/* HackerOne-Style Bug Bounty Training Environment with HEURISTIC AI TRIAGER */

/* --- AI TRIAGER ENGINE --- */
class AITriager {
    constructor() {
        this.personas = [
            { name: "Triager Bot", role: "Automated Check", strictness: "High" },
            { name: "Sarah (HackerOne Staff)", role: "Manual Review", strictness: "Medium" }
        ];
    }

    async evaluate(report, vuln) {
        // Simulate analysis delay with visual feedback in UI
        return new Promise(resolve => {
            setTimeout(() => {
                let score = 0;
                let feedback = [];
                let tips = [];

                // 0. Knowledge Base Lookup
                // If the vuln has specific AI rules, use them. Otherwise default.
                const generalKeywords = ['reproduce', 'browser', 'request', 'response', 'impact', 'poc'];
                const requiredKeywords = vuln.aiKnowledge ? vuln.aiKnowledge.keywords : generalKeywords;

                // 1. Keyword Analysis (Heuristic Density)
                const content = (report.description + report.steps).toLowerCase();
                const matched = requiredKeywords.filter(k => content.includes(k));
                const density = matched.length / requiredKeywords.length;

                if (density === 1) { score += 40; feedback.push("Excellent technical terminology."); }
                else if (density > 0.5) { score += 20; feedback.push("Good use of technical terms, but could be more precise."); }
                else {
                    feedback.push(`Report is missing key technical terms. Try to include words like: ${requiredKeywords.slice(0, 3).join(', ')}.`);
                }

                // 2. Anti-Pattern Check
                if (vuln.aiKnowledge && vuln.aiKnowledge.antiPatterns) {
                    for (const [badTerm, advice] of Object.entries(vuln.aiKnowledge.antiPatterns)) {
                        if (content.includes(badTerm)) {
                            score -= 15; // Penalty
                            tips.push(`⛔ <strong>Anti-Pattern Detected:</strong> ${advice}`);
                        }
                    }
                }

                // 3. Structure Check
                if (report.steps.split('\n').length >= 3) { score += 30; }
                else { feedback.push("Steps to reproduce are too brief. Please itemize step-by-step."); }

                // 4. Impact Assessment
                if (report.impact.length > 50) { score += 20; }
                else { feedback.push("Impact section is weak. Describe the BUSINESS risk, not just the technical flaw."); }

                // 5. Flag Verification (The Proof)
                const isFlagCorrect = report.flag === vuln.flag;
                if (isFlagCorrect) {
                    score += 10;
                } else {
                    score = 0; // Automatic fail if flag is wrong
                    feedback = ["PoC/Flag is incorrect. We cannot verify the vulnerability."];
                }

                // Final Decision
                const accepted = score >= 70 && isFlagCorrect;

                // Construct Final Feedback
                let finalComment = feedback.join(' ');
                if (tips.length > 0) finalComment += '<br><br>' + tips.join('<br>');

                resolve({
                    score,
                    accepted,
                    feedback: finalComment,
                    triager: this.personas[accepted ? 1 : 0].name
                });
            }, 2000);
        });
    }

    async getReconData(company) {
        // Simulate AI Scoping
        return new Promise(resolve => {
            setTimeout(() => {
                const techs = ['Nginx', 'Apache', 'React', 'Node.js', 'PHP', 'Laravel'];
                const tech = techs[Math.floor(Math.random() * techs.length)];

                // Generate detailed recon data
                resolve({
                    techStack: tech,
                    openPorts: '80, 443, 8080',
                    subdomains: Math.floor(Math.random() * 50) + 10,
                    hint: `AI RECON: Target running ${tech}. Large attack surface on ${company.scope[0]}. Recommended focus: ${company.industry === 'Finance' ? 'IDOR & Logic' : 'XSS & Injection'}.`
                });
            }, 1500);
        });
    }
}

window.BugBountySimulator = {
    // === STATE ===
    wallet: JSON.parse(localStorage.getItem('bb_sim_wallet') || '{"balance":0,"history":[]}'),
    currentProgram: null,
    currentVuln: null,
    submittedReports: JSON.parse(localStorage.getItem('bb_sim_reports') || '[]'),
    view: 'programs', // programs, details, report, wallet
    ai: new AITriager(),

    // === VIRTUAL COMPANIES (Now with AI Knowledge) ===
    companies: [
        {
            id: 'securebank',
            name: 'SecureBank Financial',
            logo: '🏦',
            industry: 'Finance',
            description: 'Leading digital banking platform serving millions of customers worldwide.',
            website: 'securebank.example.com',
            status: 'Active',
            launched: '2024-01-15',
            scope: ['*.securebank.example.com', 'api.securebank.example.com', 'mobile.securebank.example.com'],
            outOfScope: ['blog.securebank.example.com', 'careers.securebank.example.com'],
            rewards: { critical: 5000, high: 2000, medium: 500, low: 100 },
            vulnerabilities: [
                {
                    id: 'sb-1', type: 'SQLi', severity: 'critical', title: 'Login Bypass via SQLi',
                    hint: 'The login form sends username directly to SQL query', flag: 'FLAG{sql1_l0g1n_byp4ss}', reward: 5000,
                    aiKnowledge: {
                        keywords: ['quote', 'error', 'database', 'union', 'select', 'bypass', 'login'],
                        antiPatterns: { 'sqlmap': 'Do not use automated tools like sqlmap. Show manual verification.' }
                    }
                },
                {
                    id: 'sb-2', type: 'XSS', severity: 'high', title: 'Stored XSS in Profile',
                    hint: 'User bio field is not sanitized', flag: 'FLAG{st0r3d_xss_pr0f1le}', reward: 2000,
                    aiKnowledge: {
                        keywords: ['script', 'alert', 'cookie', 'document', 'stored', 'persistent'],
                        antiPatterns: { 'self': 'Self-XSS is not accepted. Demonstrate how it affects other users.' }
                    }
                },
                {
                    id: 'sb-3', type: 'IDOR', severity: 'high', title: 'Account Balance Disclosure',
                    hint: 'Account ID in API is predictable', flag: 'FLAG{1d0r_b4l4nc3_l34k}', reward: 1500,
                    aiKnowledge: {
                        keywords: ['parameter', 'id', 'user', 'access', 'change', 'authorization'],
                        antiPatterns: { 'guess': 'Brute forcing IDs is noisy. Show why the object reference is insecure.' }
                    }
                }
            ]
        },
        {
            id: 'cloudnine',
            name: 'CloudNine Technologies',
            logo: '☁️',
            industry: 'SaaS',
            description: 'Enterprise cloud infrastructure and DevOps automation platform.',
            website: 'cloudnine.example.io',
            status: 'Active',
            launched: '2023-11-01',
            scope: ['app.cloudnine.example.io', 'api.cloudnine.example.io'],
            outOfScope: ['docs.cloudnine.example.io'],
            rewards: { critical: 10000, high: 4000, medium: 1000, low: 250 },
            vulnerabilities: [
                {
                    id: 'cn-1', type: 'SSRF', severity: 'critical', title: 'SSRF in Webhook Handler',
                    hint: 'Webhook URL validation can be bypassed', flag: 'FLAG{ssrf_cl0ud_m3t4}', reward: 10000,
                    aiKnowledge: {
                        keywords: ['metadata', 'internal', 'aws', '169.254', 'localhost', 'loopback'],
                        antiPatterns: { 'dos': 'Do not attempt Denial of Service (DoS) via SSRF.' }
                    }
                },
                {
                    id: 'cn-2', type: 'RCE', severity: 'critical', title: 'Command Injection in Deploy',
                    hint: 'Git branch name is passed to shell', flag: 'FLAG{rc3_d3pl0y_pwn3d}', reward: 8000,
                    aiKnowledge: {
                        keywords: ['shell', 'command', 'execute', 'pipe', 'concatenate', 'reverse'],
                        antiPatterns: { 'rm -rf': 'Destructive commands are strictly prohibited.' }
                    }
                }
            ]
        },
        {
            id: 'shopeasy',
            name: 'ShopEasy Marketplace',
            logo: '🛒',
            industry: 'E-commerce',
            description: 'Popular online marketplace. Heavy focus on business logic security.',
            website: 'shopeasy.example.com',
            status: 'Active',
            launched: '2023-08-10',
            scope: ['*.shopeasy.example.com', 'api.shopeasy.example.com'],
            outOfScope: ['seller.shopeasy.example.com'],
            rewards: { critical: 3000, high: 1000, medium: 300, low: 50 },
            vulnerabilities: [
                {
                    id: 'se-1', type: 'CSRF', severity: 'high', title: 'CSRF on Checkout',
                    hint: 'No CSRF token on payment confirmation', flag: 'FLAG{csrf_ch3ck0ut}', reward: 1000,
                    aiKnowledge: {
                        keywords: ['token', 'state', 'origin', 'submit', 'form', 'validate'],
                        antiPatterns: { 'clickjacking': 'CSRF is distinct from Clickjacking. Focus on state changing actions.' }
                    }
                },
                {
                    id: 'se-2', type: 'Price Manipulation', severity: 'critical', title: 'Cart Price Tampering',
                    hint: 'Price is sent from client-side', flag: 'FLAG{pr1c3_t4mp3r}', reward: 3000,
                    aiKnowledge: {
                        keywords: ['parameter', 'price', 'value', 'negative', 'modify', 'proxy'],
                        antiPatterns: { 'ui': 'Changing the HTML in Inspect Element is not a vulnerability. Use Burp Suite.' }
                    }
                }
            ]
        }
    ],

    // === MAIN RENDER ===
    render() {
        let content = '';
        switch (this.view) {
            case 'programs': content = this.renderPrograms(); break;
            case 'details': content = this.renderProgramDetails(); break;
            case 'report': content = this.renderReportForm(); break;
            case 'wallet': content = this.renderWallet(); break;
            default: content = this.renderPrograms();
        }
        return `<style>${this.getStyles()}</style><div class="bb-sim-container fade-in">${this.renderHeader()}${content}</div>`;
    },

    renderHeader() {
        return `
        <div class="bb-sim-header">
            <div class="bb-sim-logo">
                <i class="fas fa-bug"></i>
                <span>BugBounty<span class="accent">Sim</span></span>
            </div>
            <div class="bb-sim-nav">
                <button class="${this.view === 'programs' ? 'active' : ''}" onclick="BugBountySimulator.switchView('programs')">
                    <i class="fas fa-building"></i> Programs
                </button>
                <button class="${this.view === 'wallet' ? 'active' : ''}" onclick="BugBountySimulator.switchView('wallet')">
                    <i class="fas fa-wallet"></i> Wallet <span class="wallet-badge">$${this.wallet.balance.toLocaleString()}</span>
                </button>
            </div>
        </div>`;
    },

    renderPrograms() {
        return `
        <div class="bb-programs-hero">
            <h1><i class="fas fa-shield-alt"></i> Public Programs</h1>
            <p>Hack safe. Get paid. Practice your skills on these virtual targets.</p>
        </div>
        <div class="bb-programs-grid">
            ${this.companies.map(c => this.renderProgramCard(c)).join('')}
        </div>`;
    },

    renderProgramCard(company) {
        const vulnsFound = this.submittedReports.filter(r => r.companyId === company.id && r.accepted).length;
        return `
        <div class="bb-program-card" onclick="BugBountySimulator.openProgram('${company.id}')">
            <div class="program-status ${company.status.toLowerCase()}">${company.status}</div>
            <div class="program-logo">${company.logo}</div>
            <div class="program-info-mini">
                <h3>${company.name}</h3>
                <p class="program-industry"><i class="fas fa-industry"></i> ${company.industry}</p>
            </div>
            <div class="program-rewards">
                <span class="critical">crit: $${company.rewards.critical / 1000}k</span>
                <span class="high">high: $${company.rewards.high / 1000}k</span>
            </div>
            <div class="program-stats">
                <span><i class="fas fa-globe"></i> Scope: ${company.scope.length}</span>
                <span><i class="fas fa-trophy"></i> ${vulnsFound} Found</span>
            </div>
        </div>`;
    },

    renderProgramDetails() {
        const c = this.currentProgram;
        if (!c) return '<p>No program selected</p>';
        return `
        <button class="bb-back-btn" onclick="BugBountySimulator.switchView('programs')"><i class="fas fa-arrow-left"></i> Back</button>
        <div class="bb-program-header">
            <div class="program-logo-large">${c.logo}</div>
            <div class="program-info">
                <h1>${c.name}</h1>
                <p>${c.description}</p>
                <div class="program-meta">
                    <span><i class="fas fa-globe"></i> ${c.website}</span>
                    <button id="ai-recon-btn" onclick="BugBountySimulator.runAIRecon('${c.id}')" class="ai-btn-small">
                        <i class="fas fa-robot"></i> AI Recon
                    </button>
                </div>
            </div>
        </div>
        
        <div id="recon-result" class="recon-box" style="display:none;"></div>

        <div class="bb-program-content">
            <div class="bb-col-main">
                <div class="bb-section">
                    <h2><i class="fas fa-crosshairs"></i> In Scope</h2>
                    <ul class="scope-list">${c.scope.map(s => `<li><i class="fas fa-check-circle"></i> ${s}</li>`).join('')}</ul>
                    <h3 style="margin-top:20px; font-size:1rem; color:#ef4444;"><i class="fas fa-ban"></i> Out of Scope</h3>
                    <ul class="scope-list out">${c.outOfScope.map(s => `<li><i class="fas fa-times-circle"></i> ${s}</li>`).join('')}</ul>
                </div>
                
                <div class="bb-section">
                    <h2><i class="fas fa-bug"></i> Vulnerabilities</h2>
                    <div class="vuln-grid">${c.vulnerabilities.map(v => this.renderVulnCard(v, c)).join('')}</div>
                </div>
            </div>
            
            <div class="bb-col-side">
                <div class="bb-section">
                    <h2>Reward Table</h2>
                    <div class="reward-table">
                        <div class="reward-row critical"><span>Crit</span><span>$${c.rewards.critical}</span></div>
                        <div class="reward-row high"><span>High</span><span>$${c.rewards.high}</span></div>
                        <div class="reward-row medium"><span>Med</span><span>$${c.rewards.medium}</span></div>
                        <div class="reward-row low"><span>Low</span><span>$${c.rewards.low}</span></div>
                    </div>
                </div>
            </div>
        </div>`;
    },

    renderVulnCard(vuln, company) {
        const reported = this.submittedReports.find(r => r.vulnId === vuln.id);

        let footer = `<button class="vuln-submit-btn" onclick="BugBountySimulator.startReport('${company.id}','${vuln.id}')">Submit Report</button>`;
        if (reported) {
            if (reported.accepted) footer = `<div class="vuln-status solved"><i class="fas fa-check"></i> Resolved (+$${reported.reward})</div>`;
            else footer = `<div class="vuln-status failed"><i class="fas fa-times"></i> Rejected</div><button class="retry-btn" onclick="BugBountySimulator.startReport('${company.id}','${vuln.id}')">Retry</button>`;
        }

        return `
        <div class="vuln-card">
            <div class="vuln-severity ${vuln.severity}">${vuln.severity}</div>
            <h4>${vuln.type}</h4>
            <div class="vuln-reward">Max: $${vuln.reward.toLocaleString()}</div>
            ${footer}
        </div>`;
    },

    renderReportForm() {
        const v = this.currentVuln;
        const c = this.currentProgram;
        return `
        <button class="bb-back-btn" onclick="BugBountySimulator.openProgram('${c.id}')"><i class="fas fa-arrow-left"></i> Cancel</button>
        <div class="bb-report-container">
            <div class="report-header">
                <h1>Submit Report</h1>
                <p>${c.name} &bull; ${v.type}</p>
            </div>
            
            <div id="ai-triage-overlay" class="ai-triage-overlay" style="display:none;">
                <div class="triage-modal">
                    <div class="loader-spinner"></div>
                    <h2>AI Triager Analyzing...</h2>
                    <p>Checking keyword density, reproducibility, and PoC validity.</p>
                </div>
            </div>

            <form id="bb-report-form" onsubmit="BugBountySimulator.submitReport(event)">
                <div class="form-group">
                    <label>Report Title</label>
                    <input type="text" id="report-title" required placeholder="[${v.type}] ...">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Asset</label>
                        <select><option>${c.scope[0]}</option></select>
                    </div>
                    <div class="form-group">
                        <label>Severity</label>
                        <input type="text" value="${v.severity}" disabled style="text-transform:capitalize;">
                    </div>
                </div>
                <div class="form-group">
                    <label>Description & Impact</label>
                    <textarea id="report-description" rows="4" required placeholder="Explain the vulnerability and its business impact..."></textarea>
                </div>
                <div class="form-group">
                    <label>Steps to Reproduce</label>
                    <textarea id="report-steps" rows="5" required placeholder="1. Go to...\n2. Payload...\n3. Observe..."></textarea>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Proof of Concept (Flag)</label>
                        <input type="text" id="report-poc" required placeholder="FLAG{...}">
                    </div>
                </div>
                <button type="submit" class="submit-report-btn">Submit to Triage</button>
            </form>
        </div>`;
    },

    renderWallet() {
        return `
        <div class="bb-wallet-container">
            <div class="wallet-header">
                <div class="wallet-balance">
                    <span class="label">Current Balance</span>
                    <span class="amount">$${this.wallet.balance.toLocaleString()}</span>
                </div>
                <div class="wallet-stats">
                    <div class="stat"><span class="num">${this.submittedReports.filter(r => r.accepted).length}</span><span>Accepted</span></div>
                    <div class="stat"><span class="num">${this.submittedReports.length}</span><span>Submitted</span></div>
                </div>
            </div>
            <h2>Transaction History</h2>
            <div class="wallet-history">
                ${this.wallet.history.slice().reverse().map(h => `
                    <div class="history-item">
                        <div class="history-icon"><i class="fas fa-bug"></i></div>
                        <div class="history-details">
                            <strong>${h.title}</strong>
                            <span>${h.company}</span>
                        </div>
                        <div class="history-amount">+$${h.amount.toLocaleString()}</div>
                    </div>
                `).join('') || '<p class="empty">No bounties yet.</p>'}
            </div>
        </div>`;
    },

    // === ACTIONS ===
    switchView(view) {
        this.view = view;
        document.getElementById('content').innerHTML = this.render();
        window.scrollTo(0, 0);
    },

    openProgram(id) {
        this.currentProgram = this.companies.find(c => c.id === id);
        this.view = 'details';
        document.getElementById('content').innerHTML = this.render();
        window.scrollTo(0, 0);
    },

    startReport(companyId, vulnId) {
        this.currentProgram = this.companies.find(c => c.id === companyId);
        this.currentVuln = this.currentProgram.vulnerabilities.find(v => v.id === vulnId);
        this.view = 'report';
        document.getElementById('content').innerHTML = this.render();
        window.scrollTo(0, 0);
    },

    async runAIRecon(companyId) {
        const btn = document.getElementById('ai-recon-btn');
        const box = document.getElementById('recon-result');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

        const data = await this.ai.getReconData(this.currentProgram);

        btn.innerHTML = '<i class="fas fa-robot"></i> AI Recon';
        box.style.display = 'block';
        box.innerHTML = `
            <strong><i class="fas fa-satellite-dish"></i> Reconnaissance Report</strong>
            <ul>
                <li>Tech Stack: ${data.techStack}</li>
                <li>Open Ports: ${data.openPorts}</li>
                <li>Subdomains: ${data.subdomains} discovered</li>
            </ul>
            <p style="margin-top:10px; color:#38bdf8;"><em>${data.hint}</em></p>
        `;
    },

    async submitReport(e) {
        e.preventDefault();
        const flag = document.getElementById('report-poc').value.trim();
        const title = document.getElementById('report-title').value;
        const description = document.getElementById('report-description').value;
        const steps = document.getElementById('report-steps').value;

        // Show AI Triage Animation
        document.getElementById('ai-triage-overlay').style.display = 'flex';

        // Evaluate with Heuristic AI
        const evaluation = await this.ai.evaluate({ title, description, steps, impact: description, flag }, this.currentVuln);

        const report = {
            id: Date.now(),
            companyId: this.currentProgram.id,
            vulnId: this.currentVuln.id,
            title, description, steps, flag,
            accepted: evaluation.accepted,
            reward: evaluation.accepted ? this.currentVuln.reward : 0,
            date: new Date().toLocaleDateString()
        };

        // Update State
        // Remove old report if exists (re-test)
        this.submittedReports = this.submittedReports.filter(r => r.vulnId !== this.currentVuln.id);
        this.submittedReports.push(report);
        localStorage.setItem('bb_sim_reports', JSON.stringify(this.submittedReports));

        if (report.accepted) {
            this.wallet.balance += report.reward;
            this.wallet.history.push({ title: this.currentVuln.title, company: this.currentProgram.name, amount: report.reward, date: report.date });
            localStorage.setItem('bb_sim_wallet', JSON.stringify(this.wallet));
        }

        // Show Result
        this.showResultModal(report, evaluation);
    },

    showResultModal(report, evaluation) {
        const html = `
        <div class="bb-result-overlay">
            <div class="bb-result-modal ${report.accepted ? 'success' : 'fail'}">
                <div class="result-icon">${report.accepted ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-times-circle"></i>'}</div>
                <h2>${report.accepted ? 'Bounty Awarded!' : 'Report Closed'}</h2>
                <div class="triage-info">
                    <p><strong>Triaged By:</strong> ${evaluation.triager}</p>
                    <p><strong>Feedback:</strong> ${evaluation.feedback}</p>
                </div>
                ${report.accepted ? `<div class="reward-display">+$${report.reward.toLocaleString()}</div>` : ''}
                <button onclick="BugBountySimulator.openProgram('${this.currentProgram.id}')" class="continue-btn">Done</button>
            </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', html);
    },

    // === STYLES ===
    getStyles() {
        return `
        /* Variables from Career Hub */
        .bb-sim-container { min-height: 100vh; background: #0f172a; padding: 20px; color: #e2e8f0; font-family: 'Inter', system-ui, sans-serif; }
        
        /* HEADER */
        .bb-sim-header { display: flex; justify-content: space-between; align-items: center; padding: 15px 30px; background: #1e293b; border-bottom: 1px solid #334155; border-radius: 12px; margin-bottom: 30px; }
        .bb-sim-logo { display: flex; align-items: center; gap: 10px; font-size: 1.5rem; font-weight: 700; color: #fff; }
        .bb-sim-logo i { color: #38bdf8; }
        .bb-sim-nav { display: flex; gap: 12px; }
        .bb-sim-nav button { background: transparent; border: 1px solid transparent; color: #94a3b8; padding: 8px 16px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-weight: 500; transition:all 0.2s;}
        .bb-sim-nav button:hover { color: #fff; background: #334155; }
        .bb-sim-nav button.active { background: #334155; color: #fff; border-color: #475569; }
        .wallet-badge { background: #22c55e; color: #000; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem; font-weight: 700; }

        /* PROGRAMS GRID */
        .bb-programs-hero { text-align: center; padding: 40px 20px; }
        .bb-programs-hero h1 { font-size: 2.5rem; margin-bottom: 10px; color: #fff; letter-spacing: -1px; }
        .bb-programs-hero p { color:#94a3b8; font-size:1.1rem; }
        
        .bb-programs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; max-width: 1200px; margin: 0 auto; }
        .bb-program-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; cursor: pointer; transition: all 0.2s; position: relative; }
        .bb-program-card:hover { transform: translateY(-4px); border-color: #38bdf8; }
        .program-logo { font-size: 2rem; margin-bottom: 15px; }
        .program-status { position: absolute; top: 20px; right: 20px; font-size: 0.7rem; padding: 4px 8px; background: rgba(34, 197, 94, 0.1); color: #22c55e; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
        .program-rewards { display: flex; gap: 10px; margin: 15px 0; font-size: 0.85rem; }
        .program-rewards span { background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #cbd5e1; }
        
        /* PROGRAM DETAILS */
        .bb-program-header { display: flex; gap: 25px; background: #1e293b; padding: 30px; border-radius: 16px; border: 1px solid #334155; margin-bottom: 25px; align-items: start; }
        .program-logo-large { font-size: 4rem; background: #0f172a; width: 100px; height: 100px; display: flex; align-items: center; justify-content: center; border-radius: 12px; }
        .program-info h1 { margin: 0 0 10px; color: #fff; }
        .program-info p { color: #94a3b8; max-width: 600px; line-height: 1.5; }
        
        .bb-program-content { display: grid; grid-template-columns: 2fr 1fr; gap: 25px; }
        .bb-section { background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; margin-bottom: 20px; }
        .bb-section h2 { font-size: 1.1rem; color: #fff; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        
        .scope-list li { padding: 8px; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; color: #cbd5e1; font-family: monospace; }
        .scope-list li i { color: #22c55e; }
        .scope-list.out li i { color: #ef4444; }

        .reward-table .reward-row { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #334155; font-size: 0.9rem; }
        .reward-row span:last-child { font-weight: bold; color: #fff; }

        .vuln-grid { display: grid; gap: 15px; }
        .vuln-card { background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
        .vuln-severity { font-size: 0.7rem; font-weight: bold; text-transform: uppercase; padding: 4px 8px; border-radius: 4px; width: 70px; text-align: center; }
        .vuln-severity.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .vuln-severity.high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
        .vuln-submit-btn { background: #38bdf8; color: #000; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .vuln-submit-btn:hover { background: #7dd3fc; }
        .vuln-status.solved { color: #22c55e; font-size: 0.9rem; font-weight: bold; }
        .vuln-status.failed { color: #ef4444; font-size: 0.9rem; font-weight: bold; }

        /* RECON & AI */
        .recon-box { background: #0f172a; border: 1px solid #38bdf8; padding: 20px; border-radius: 12px; margin-bottom: 25px; color: #cbd5e1; }
        .ai-btn-small { background: #1e1e2e; border: 1px solid #38bdf8; color: #38bdf8; padding: 6px 12px; border-radius: 6px; cursor: pointer; margin-top: 10px; font-weight: 600; }
        .ai-btn-small:hover { background: #38bdf8; color: #000; }

        /* REPORT FORM */
        .bb-report-container { max-width: 800px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 16px; border: 1px solid #334155; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #94a3b8; font-size: 0.9rem; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; background: #0f172a; border: 1px solid #334155; padding: 12px; color: #fff; border-radius: 8px; font-family: inherit; }
        .form-group input:focus { outline: none; border-color: #38bdf8; }
        .submit-report-btn { width: 100%; padding: 15px; background: #22c55e; color: #000; font-weight: bold; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; margin-top: 20px; }
        .submit-report-btn:hover { background: #16a34a; }

        /* MODALS */
        .ai-triage-overlay, .bb-result-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 100; backdrop-filter: blur(5px); }
        .triage-modal { background: #1e293b; padding: 40px; border-radius: 16px; text-align: center; border: 1px solid #334155; }
        .loader-spinner { width: 40px; height: 40px; border: 4px solid #334155; border-top-color: #38bdf8; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .bb-result-modal { background: #1e293b; padding: 40px; border-radius: 16px; max-width: 400px; width: 100%; border: 1px solid #334155; text-align: center; }
        .bb-result-modal.success { border-color: #22c55e; }
        .bb-result-modal.fail { border-color: #ef4444; }
        .result-icon { font-size: 4rem; margin-bottom: 20px; }
        .bb-result-modal.success .result-icon { color: #22c55e; }
        .bb-result-modal.fail .result-icon { color: #ef4444; }
        .triage-info { background: #0f172a; padding: 15px; border-radius: 8px; margin: 20px 0; text-align: left; font-size: 0.9rem; line-height: 1.5; color: #cbd5e1; }
        .menu-btn, .continue-btn { padding: 10px 20px; background: #334155; color: #fff; border:none; border-radius: 6px; cursor: pointer; margin-top: 10px; width: 100%; }
        .reward-display { font-size: 2rem; color: #22c55e; font-weight: bold; margin-bottom: 20px; }
        `;
    }
};

function pageBugBountySim() { return BugBountySimulator.render(); }
window.pageBugBountySim = pageBugBountySim;
