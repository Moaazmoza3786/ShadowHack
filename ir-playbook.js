/* ==================== INCIDENT RESPONSE PLAYBOOK DESIGNER 📒 ==================== */
/* Advanced IR Workflow Orchestration & Evidence Management Simulator */

window.IRPlaybook = {
    state: {
        activeIncident: 'Ransomware Outbreak',
        incidentTypes: ['Ransomware Outbreak', 'Data Exfiltration', 'Account Takeover', 'Infected Host'],
        workflow: [],
        evidence: [],
        aiAdvice: "Detecting incident context... select a type to begin."
    },

    init() {
        this.loadPlaybook(this.state.activeIncident);
    },

    loadPlaybook(type) {
        this.state.activeIncident = type;
        const playbooks = {
            'Ransomware Outbreak': [
                { id: 1, step: 'Detection & Analysis', status: 'completed', desc: 'Identify affected hosts and ransom note type.' },
                { id: 2, step: 'Containment (Short-term)', status: 'current', desc: 'Isolate affected network segments and disable compromised accounts.' },
                { id: 3, step: 'Eradication', status: 'pending', desc: 'Wipe infected systems and restore from clean backups.' },
                { id: 4, step: 'Recovery', status: 'pending', desc: 'Gradually restore service and monitor for re-infection.' }
            ],
            'Data Exfiltration': [
                { id: 1, step: 'Traffic Analysis', status: 'completed', desc: 'Identify egress point and destination IPs.' },
                { id: 2, step: 'Access Revocation', status: 'current', desc: 'Terminate sessions and rotate credentials.' },
                { id: 3, step: 'DLP Audit', status: 'pending', desc: 'Review exported datasets to determine PII impact.' }
            ]
        };
        this.state.workflow = playbooks[type] || playbooks['Ransomware Outbreak'];
        this.state.aiAdvice = `For ${type}, prioritize ${this.state.workflow.find(s => s.status === 'current')?.step || 'Containment'}. Ensure all evidence is hashed before analysis.`;
    },

    render() {
        return `
        <div class="ir-app fade-in">
            <div class="ir-header">
                <div class="header-info">
                    <h1><i class="fas fa-book-medical"></i> IR Ops Command</h1>
                    <p>Tactical Incident Orchestration & Digital Evidence Vault</p>
                </div>
                <div class="header-actions">
                    <select class="ir-selector" onchange="IRPlaybook.handleIncidentChange(this.value)">
                        ${this.state.incidentTypes.map(t => `<option value="${t}" ${t === this.state.activeIncident ? 'selected' : ''}>${t}</option>`).join('')}
                    </select>
                </div>
            </div>

            <div class="ir-layout">
                <div class="ir-workflow-col">
                    <div class="col-header"><i class="fas fa-project-diagram"></i> Active Playbook Flow</div>
                    <div class="workflow-list">
                        ${this.state.workflow.map(s => `
                            <div class="wf-card ${s.status}">
                                <div class="wf-marker"><i class="fas ${s.status === 'completed' ? 'fa-check' : s.status === 'current' ? 'fa-spinner fa-spin' : 'fa-clock'}"></i></div>
                                <div class="wf-content">
                                    <div class="wf-step">${s.step}</div>
                                    <div class="wf-desc">${s.desc}</div>
                                </div>
                                ${s.status === 'current' ? '<button class="btn-done" onclick="alert(\'Step marked as complete.\')">Mark Done</button>' : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="ir-ops-col">
                    <div class="vault-section">
                        <div class="col-header"><i class="fas fa-archive"></i> Evidence Vault</div>
                        <div class="evidence-grid" id="evidence-vault">
                            ${this.state.evidence.length === 0 ? '<div class="empty-vault">No artifacts collected.</div>' : this.state.evidence.map(e => `
                                <div class="ev-card">
                                    <i class="fas ${e.type === 'log' ? 'fa-file-alt' : 'fa-microchip'}"></i>
                                    <div class="ev-info">
                                        <div class="ev-name">${e.name}</div>
                                        <div class="ev-tag">MD5: ${e.hash}</div>
                                    </div>
                                    <button class="btn-view" onclick="alert('Viewing evidence metadata...')">View</button>
                                </div>
                            `).join('')}
                        </div>
                        <button class="btn-primary" onclick="IRPlaybook.addEvidence()"><i class="fas fa-plus"></i> Collect Artifact</button>
                    </div>

                    <div class="ai-assistant">
                        <div class="col-header"><i class="fas fa-robot"></i> AI Playbook Assistant</div>
                        <div class="ai-speech">
                            <p>${this.state.aiAdvice}</p>
                        </div>
                        <div class="ai-input">
                            <input type="text" placeholder="Ask AI about next steps..." onkeydown="if(event.key==='Enter') alert('AI suggests: Check firewall logs for egress patterns.')">
                        </div>
                    </div>
                </div>
            </div>
        </div>
        ${this.getStyles()}`;
    },

    handleIncidentChange(val) {
        this.loadPlaybook(val);
        this.renderAll();
    },

    addEvidence() {
        const name = prompt("Evidence Name (e.g., auth.log, memory_dump.raw):");
        if (name) {
            this.state.evidence.push({
                name,
                type: name.includes('.log') ? 'log' : 'dump',
                hash: Math.random().toString(16).substr(2, 8)
            });
            this.renderAll();
        }
    },

    renderAll() {
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .ir-app { padding: 40px; color: #e0e0e0; font-family: 'Inter', sans-serif; background: #0b0c14; min-height: 100%; box-sizing: border-box; }
            .ir-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 1px solid #1c1c26; padding-bottom: 25px; }
            .header-info h1 { margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 15px; }
            .header-info p { margin: 5px 0 0; color: #6366f1; font-weight: 500; }
            
            .ir-selector { background: #161925; color: #fff; border: 1px solid #2d2d3a; padding: 10px 20px; border-radius: 10px; font-weight: 600; outline: none; }

            .ir-layout { display: grid; grid-template-columns: 1fr 400px; gap: 40px; }
            .col-header { font-size: 0.85rem; text-transform: uppercase; color: #555; font-weight: 800; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; }
            
            .wf-card { background: #161925; padding: 25px; border-radius: 16px; border: 1px solid #2d2d3a; margin-bottom: 20px; display: flex; gap: 20px; align-items: flex-start; position: relative; }
            .wf-card.completed { border-color: #22c55e; opacity: 0.7; }
            .wf-card.current { border-color: #6366f1; box-shadow: 0 0 20px rgba(99, 102, 241, 0.1); border-left: 5px solid #6366f1; }
            .wf-marker { width: 30px; height: 30px; border-radius: 50%; background: #0b0c14; display: flex; align-items: center; justify-content: center; border: 1px solid #2d2d3a; flex-shrink: 0; }
            .wf-card.completed .wf-marker { color: #22c55e; }
            .wf-card.current .wf-marker { color: #6366f1; }
            .wf-step { font-weight: 800; color: #fff; font-size: 1.1rem; margin-bottom: 5px; }
            .wf-desc { color: #888; font-size: 0.9rem; line-height: 1.5; }
            .btn-done { margin-top: 15px; background: #6366f1; border: none; color: #fff; padding: 6px 15px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 700; }

            .vault-section { background: #161925; padding: 30px; border-radius: 20px; border: 1px solid #2d2d3a; margin-bottom: 30px; }
            .evidence-grid { margin-bottom: 25px; }
            .ev-card { background: #0b0c14; border: 1px solid #1c1c26; padding: 15px; border-radius: 12px; margin-bottom: 12px; display: flex; align-items: center; gap: 15px; position: relative; transition: 0.2s; }
            .ev-card:hover { border-color: #333; }
            .ev-card i { font-size: 1.2rem; color: #6366f1; }
            .ev-name { font-weight: 700; color: #fff; font-size: 0.9rem; }
            .ev-tag { font-size: 0.7rem; font-family: monospace; color: #444; }
            .btn-view { position: absolute; right: 15px; background: none; border: 1px solid #2d2d3a; color: #555; padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; }
            .empty-vault { text-align: center; color: #333; padding: 40px 0; font-style: italic; }

            .ai-assistant { background: #0b0c14; padding: 30px; border-radius: 20px; border: 1px solid #1c1c26; }
            .ai-speech { background: #161925; padding: 20px; border-radius: 16px; border: 1px solid #2d2d3a; position: relative; margin-bottom: 20px; }
            .ai-speech:after { content: ''; position: absolute; bottom: -10px; left: 30px; border-width: 10px 10px 0; border-style: solid; border-color: #161925 transparent; }
            .ai-speech p { margin: 0; font-size: 0.95rem; line-height: 1.6; color: #e0e0e0; }
            
            .ai-input input { width: 100%; background: #1c1c26; border: 1px solid #2d2d3a; color: #fff; padding: 12px 20px; border-radius: 10px; outline: none; box-sizing: border-box; }
            .btn-primary { background: #6366f1; color: #fff; border: none; padding: 12px 20px; border-radius: 10px; font-weight: 700; cursor: pointer; width: 100%; transition: 0.3s; }
            .btn-primary:hover { background: #4f46e5; }
        </style>`;
    }
};

function pageIRPlaybook() {
    IRPlaybook.init();
    return IRPlaybook.render();
}
