/* ==================== DEVSECOPS CI/CD LAB 🚀 ==================== */
/* Secure Development Lifecycle & Automated Pipeline Security Simulator */

window.DevSecOpsLab = {
    state: {
        activeTab: 'pipeline',
        pipelineStatus: 'Idle',
        steps: [
            { id: 'git', name: 'Source (Git)', status: 'ready', icon: 'fab fa-git-alt' },
            { id: 'sast', name: 'SAST Scan', status: 'pending', icon: 'fas fa-search-code' },
            { id: 'secret', name: 'Secret Scan', status: 'pending', icon: 'fas fa-key' },
            { id: 'build', name: 'Build (Docker)', status: 'pending', icon: 'fab fa-docker' },
            { id: 'dast', name: 'DAST Scan', status: 'pending', icon: 'fas fa-bug' },
            { id: 'deploy', name: 'Deploy (K8s)', status: 'pending', icon: 'fas fa-cloud-upload-alt' }
        ],
        scanResults: {
            sast: [],
            secret: [],
            dast: []
        },
        logs: []
    },

    init() {
        this.resetState();
    },

    resetState() {
        this.state.pipelineStatus = 'Idle';
        this.state.steps.forEach(s => s.status = s.id === 'git' ? 'ready' : 'pending');
        this.state.scanResults = { sast: [], secret: [], dast: [] };
        this.state.logs = [];
    },

    render() {
        return `
        <div class="devops-app fade-in">
            <div class="devops-header">
                <div class="header-info">
                    <h1><i class="fas fa-rocket"></i> DevSecOps Pipeline Lab</h1>
                    <p>Automated Security Orchestration & Gated Deployment</p>
                </div>
                <div class="header-actions">
                    <button class="btn-run" onclick="DevSecOpsLab.startPipeline()"><i class="fas fa-play"></i> Run Secure Pipeline</button>
                    <button class="btn-secondary" onclick="DevSecOpsLab.resetPipeline()"><i class="fas fa-undo"></i> Reset</button>
                </div>
            </div>

            <div class="devops-tabs">
                <button class="d-tab ${this.state.activeTab === 'pipeline' ? 'active' : ''}" onclick="DevSecOpsLab.switchTab('pipeline')">Pipeline View</button>
                <button class="d-tab ${this.state.activeTab === 'sec' ? 'active' : ''}" onclick="DevSecOpsLab.switchTab('sec')">Security Findings</button>
                <button class="d-tab ${this.state.activeTab === 'logs' ? 'active' : ''}" onclick="DevSecOpsLab.switchTab('logs')">Console Logs</button>
            </div>

            <div class="devops-main">
                ${this.renderContent()}
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderContent() {
        switch (this.state.activeTab) {
            case 'pipeline': return this.renderPipeline();
            case 'sec': return this.renderFindings();
            case 'logs': return this.renderLogs();
            default: return this.renderPipeline();
        }
    },

    renderPipeline() {
        return `
            <div class="pipeline-view fade-in">
                <div class="pipeline-line">
                    ${this.state.steps.map((step, idx) => `
                        <div class="step-container">
                            <div class="step-node ${step.status}" id="step-${step.id}">
                                <i class="${step.icon}"></i>
                                <span class="step-label">${step.name}</span>
                                ${step.status === 'running' ? '<div class="spinner-tiny"></div>' : ''}
                                ${step.status === 'failed' ? '<i class="fas fa-times-circle fail-icon"></i>' : ''}
                                ${step.status === 'success' ? '<i class="fas fa-check-circle pass-icon"></i>' : ''}
                            </div>
                            ${idx < this.state.steps.length - 1 ? '<div class="pipe"></div>' : ''}
                        </div>
                    `).join('')}
                </div>

                <div class="pipeline-intro">
                    <div class="intro-card">
                        <h3><i class="fas fa-info-circle"></i> Lab Objective</h3>
                        <p>Simulate a modern CI/CD pipeline where security is integrated at every stage (Shift-Left). The pipeline will automatically fail if critical vulnerabilities are found during SAST or Secret scanning.</p>
                    </div>
                </div>
            </div>
        `;
    },

    renderFindings() {
        const allFindings = [...this.state.scanResults.sast, ...this.state.scanResults.secret, ...this.state.scanResults.dast];
        return `
            <div class="findings-view fade-in">
                ${allFindings.length === 0 ? '<div class="empty-state">No scans performed yet. Run the pipeline to see results.</div>' : `
                    <div class="findings-grid">
                        ${allFindings.map(f => `
                            <div class="find-card ${f.severity.toLowerCase()}">
                                <div class="f-severity">${f.severity}</div>
                                <div class="f-type">${f.type}</div>
                                <div class="f-msg">${f.msg}</div>
                                <div class="f-file"><code>${f.location}</code></div>
                            </div>
                        `).join('')}
                    </div>
                `}
            </div>
        `;
    },

    renderLogs() {
        return `
            <div class="logs-view fade-in">
                <div class="log-terminal">
                    ${this.state.logs.length === 0 ? '<div class="t-line">Waiting for pipeline trigger...</div>' : this.state.logs.map(l => `<div class="t-line"><span class="t-time">[${l.time}]</span> <span class="t-msg">${l.msg}</span></div>`).join('')}
                </div>
            </div>
        `;
    },

    switchTab(tab) {
        this.state.activeTab = tab;
        this.renderAll();
    },

    async startPipeline() {
        if (this.state.pipelineStatus === 'Running') return;
        this.resetState();
        this.state.pipelineStatus = 'Running';
        this.addLog("Pipeline started by user...");

        for (const step of this.state.steps) {
            step.status = 'running';
            this.renderAll();
            this.addLog(`Starting step: ${step.name}...`);

            await new Promise(r => setTimeout(r, 1500));

            const failure = this.simulateStep(step);
            if (failure) {
                step.status = 'failed';
                this.state.pipelineStatus = 'Failed';
                this.addLog(`CRITICAL: Step ${step.name} failed! Gated cleanup initiated.`);
                this.renderAll();
                return;
            }

            step.status = 'success';
            this.addLog(`Step ${step.name} passed.`);
        }

        this.state.pipelineStatus = 'Success';
        this.addLog("PIPELINE COMPLETE: Application deployed to Production.");
        this.renderAll();
    },

    simulateStep(step) {
        if (step.id === 'sast') {
            const found = Math.random() > 0.4;
            if (found) {
                this.state.scanResults.sast.push({ type: 'SAST', severity: 'High', msg: 'Potential SQL Injection in login.py', location: 'src/auth/login.py:45' });
            }
            return false;
        }
        if (step.id === 'secret') {
            const found = Math.random() > 0.7;
            if (found) {
                this.state.scanResults.secret.push({ type: 'Secret', severity: 'Critical', msg: 'Hardcoded AWS Access Key found', location: 'config/aws.yaml:12' });
                return true; // Fail pipeline on critical secrets
            }
            return false;
        }
        if (step.id === 'dast') {
            const found = Math.random() > 0.5;
            if (found) {
                this.state.scanResults.dast.push({ type: 'DAST', severity: 'Medium', msg: 'Missing Security Headers (HSTS)', location: 'https://staging-app.internal' });
            }
            return false;
        }
        return false;
    },

    resetPipeline() {
        this.init();
        this.renderAll();
    },

    addLog(msg) {
        const time = new Date().toLocaleTimeString([], { hour12: false });
        this.state.logs.push({ time, msg });
        if (this.state.activeTab === 'logs') this.renderAll();
    },

    renderAll() {
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .devops-app { padding: 40px; color: #e0e0e0; font-family: 'Inter', sans-serif; background: #0f111a; min-height: 100%; box-sizing: border-box; }
            .devops-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 1px solid #1c1c26; padding-bottom: 25px; }
            .header-info h1 { margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 15px; }
            .header-info p { margin: 8px 0 0; color: #6366f1; font-weight: 500; }
            
            .btn-run { background: #6366f1; color: #fff; border: none; padding: 12px 25px; border-radius: 10px; font-weight: 700; cursor: pointer; transition: 0.3s; display: flex; align-items: center; gap: 10px; }
            .btn-run:hover { background: #4f46e5; transform: translateY(-2px); }
            .btn-secondary { background: #1c1c26; color: #888; border: 1px solid #2d2d3a; padding: 12px 25px; border-radius: 10px; cursor: pointer; margin-left: 10px; transition: 0.2s; }
            .btn-secondary:hover { color: #fff; border-color: #555; }

            .devops-tabs { display: flex; gap: 15px; margin-bottom: 30px; }
            .d-tab { background: #161925; border: 1px solid #2d2d3a; color: #888; padding: 10px 20px; border-radius: 8px; cursor: pointer; transition: 0.3s; font-weight: 600; }
            .d-tab.active { background: #6366f1; color: #fff; border-color: #6366f1; }

            .pipeline-line { display: flex; justify-content: space-between; align-items: center; background: #161925; padding: 40px; border-radius: 20px; border: 1px solid #2d2d3a; margin-bottom: 30px; position: relative; }
            .step-container { display: flex; align-items: center; flex: 1; justify-content: center; }
            .step-node { position: relative; display: flex; flex-direction: column; align-items: center; gap: 10px; z-index: 2; }
            .step-node i { font-size: 1.5rem; width: 50px; height: 50px; background: #0b0c14; border: 2px solid #2d2d3a; border-radius: 50%; display: flex; align-items: center; justify-content: center; transition: 0.5s; color: #444; }
            .step-label { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #555; }
            
            .step-node.ready i { border-color: #6366f1; color: #6366f1; }
            .step-node.running i { border-color: #fbbf24; color: #fbbf24; box-shadow: 0 0 15px rgba(251, 191, 36, 0.3); }
            .step-node.success i { border-color: #22c55e; color: #22c55e; }
            .step-node.failed i { border-color: #ef4444; color: #ef4444; }

            .pipe { flex: 1; height: 2px; background: #2d2d3a; margin: 0 -25px; position: relative; top: -12px; }
            
            .spinner-tiny { width: 14px; height: 14px; border: 2px solid #fbbf24; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; position: absolute; top: -5px; right: -5px; }
            @keyframes spin { to { transform: rotate(360deg); } }
            
            .pass-icon { position: absolute; top: -5px; right: -5px; color: #22c55e; background: #0f111a; border-radius: 50%; width: 18px; height: 18px; font-size: 0.9rem; }
            .fail-icon { position: absolute; top: -5px; right: -5px; color: #ef4444; background: #0f111a; border-radius: 50%; width: 18px; height: 18px; font-size: 0.9rem; }

            .findings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
            .find-card { background: #161925; padding: 20px; border-radius: 12px; border: 1px solid #2d2d3a; border-left: 4px solid #333; }
            .find-card.critical { border-left-color: #eb0000; }
            .find-card.high { border-left-color: #ef4444; }
            .find-card.medium { border-left-color: #fbbf24; }
            .f-severity { font-size: 0.7rem; font-weight: 900; background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius: 4px; display: inline-block; margin-bottom: 10px; }
            .f-type { font-weight: 800; color: #fff; margin-bottom: 5px; }
            .f-msg { font-size: 0.9rem; color: #888; margin-bottom: 15px; }
            .f-file code { background: #000; padding: 3px 6px; border-radius: 4px; color: #6366f1; font-size: 0.8rem; }

            .log-terminal { background: #0b0c14; padding: 25px; border-radius: 12px; font-family: 'JetBrains Mono', monospace; border: 1px solid #1c1c26; min-height: 400px; font-size: 0.85rem; }
            .t-line { margin-bottom: 8px; }
            .t-time { color: #555; margin-right: 12px; }
            .t-msg { color: #4ade80; }

            .intro-card { background: #161925; padding: 25px; border-radius: 15px; border: 1px solid #2d2d3a; max-width: 600px; margin: 40px auto; }
            .intro-card h3 { margin: 0 0 10px; color: #fff; font-size: 1.1rem; }
            .intro-card p { line-height: 1.6; color: #888; font-size: 0.95rem; }
            
            .empty-state { text-align: center; color: #444; padding: 100px 0; font-style: italic; }
        </style>`;
    }
};

function pageDevSecOpsLab() {
    DevSecOpsLab.init();
    return DevSecOpsLab.render();
}
