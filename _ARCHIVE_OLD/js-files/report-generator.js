/* ==================== PROFESSIONAL REPORT GENERATOR 📝 ==================== */

window.ReportGenerator = {
    // --- STATE ---
    currentReport: {
        title: 'Penetration Test Report',
        client: 'Acme Corp',
        date: new Date().toISOString().split('T')[0],
        executiveSummary: 'This assessment identified several critical vulnerabilities...',
        findings: []
    },

    // --- INIT ---
    init() {
        this.loadPotentialFindings();
    },

    loadPotentialFindings() {
        // Mock data if RedTeamOps is not active or empty
        let potentialCoords = [];

        // Try to get from Red Team Ops
        if (window.RedTeamOps && window.RedTeamOps.state && window.RedTeamOps.state.projects) {
            // Flatten findings from all active projects
            window.RedTeamOps.state.projects.forEach(p => {
                if (p.findings) {
                    p.findings.forEach(f => {
                        f.sourceProject = p.name;
                        potentialCoords.push(f);
                    });
                }
            });
        }

        // If empty, seed with samples for demo
        if (potentialCoords.length === 0) {
            potentialCoords = [
                { id: 'f1', title: 'SQL Injection in Login', severity: 'High', description: 'The login parameter `user` is vulnerable to SQLi.', cvss: 8.5 },
                { id: 'f2', title: 'Reflected XSS on Search', severity: 'Medium', description: 'Search query is reflected without encoding.', cvss: 6.1 },
                { id: 'f3', title: 'Outdated Apache Version', severity: 'Low', description: 'Server running Apache 2.4.10.', cvss: 3.5 }
            ];
        }

        this.potentialFindings = potentialCoords;
        // Default select all
        this.currentReport.findings = [...potentialCoords];
    },

    // --- RENDER UI ---
    render() {
        setTimeout(() => this.init(), 100);

        return `
            <div class="report-app fade-in">
                <!-- BUILDER UI (Visible on Screen) -->
                <div class="report-builder no-print">
                    <div class="builder-header">
                        <h1><i class="fas fa-file-contract"></i> Report Generator</h1>
                        <div class="actions">
                            <button class="btn-preview" onclick="ReportGenerator.togglePreview()">Toggle Preview</button>
                            <button class="btn-export" onclick="window.print()"><i class="fas fa-file-pdf"></i> Export PDF</button>
                        </div>
                    </div>

                    <div class="builder-grid">
                        <div class="builder-panel">
                            <h3><i class="fas fa-edit"></i> Report Details</h3>
                            <div class="form-group">
                                <label>Report Title</label>
                                <input type="text" value="${this.currentReport.title}" oninput="ReportGenerator.updateField('title', this.value)">
                            </div>
                            <div class="form-group">
                                <label>Client Name</label>
                                <input type="text" value="${this.currentReport.client}" oninput="ReportGenerator.updateField('client', this.value)">
                            </div>
                            <div class="form-group">
                                <label>Executive Summary</label>
                                <textarea rows="6" oninput="ReportGenerator.updateField('executiveSummary', this.value)">${this.currentReport.executiveSummary}</textarea>
                            </div>
                        </div>

                        <div class="builder-panel">
                            <h3><i class="fas fa-bug"></i> Select Findings</h3>
                            <div class="findings-list">
                                ${this.potentialFindings.map(f => `
                                    <div class="finding-item ${this.isSelected(f.id) ? 'selected' : ''}" onclick="ReportGenerator.toggleFinding('${f.id}')">
                                        <div class="f-severity ${f.severity.toLowerCase()}"></div>
                                        <div class="f-info">
                                            <div class="f-title">${f.title}</div>
                                            <div class="f-meta">${f.sourceProject || 'Manual Entry'} • CVSS ${f.cvss || 'N/A'}</div>
                                        </div>
                                        <i class="fas fa-check-circle check-icon"></i>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- PREVIEW / PRINT LAYOUT (A4 Style) -->
                <div class="report-preview" id="report-preview">
                    
                    <!-- PAGE 1: COVER -->
                    <div class="print-page cover-page">
                        <div class="report-logo"><i class="fas fa-shield-alt"></i> STUDY HUB SECURITY</div>
                        <div class="report-title-block">
                            <h1 id="p-title">${this.currentReport.title}</h1>
                            <h2 id="p-client">Prepared for: ${this.currentReport.client}</h2>
                            <p id="p-date" class="report-date">${this.currentReport.date}</p>
                        </div>
                        <div class="report-footer">Confidential & Proprietary</div>
                    </div>

                    <!-- PAGE 2: EXEC SUMMARY -->
                    <div class="print-page">
                        <div class="page-header">Executive Summary</div>
                        <div class="page-content" id="p-summary">
                            <p>${this.currentReport.executiveSummary}</p>
                        </div>
                        
                        <!-- STATISTICS OPTIONAL -->
                        <div class="vuln-stats">
                            <h3>Vulnerability Summary</h3>
                            <div class="stat-bar">
                                <div class="s-label">High Risk</div>
                                <div class="s-val">${this.countSeverity('High')}</div>
                            </div>
                             <div class="stat-bar">
                                <div class="s-label">Medium Risk</div>
                                <div class="s-val">${this.countSeverity('Medium')}</div>
                            </div>
                             <div class="stat-bar">
                                <div class="s-label">Low Risk</div>
                                <div class="s-val">${this.countSeverity('Low')}</div>
                            </div>
                        </div>
                    </div>

                    <!-- FINDINGS PAGES -->
                    ${this.currentReport.findings.map((f, i) => `
                        <div class="print-page">
                            <div class="page-header">Finding #${i + 1}: ${f.title}</div>
                            <div class="finding-detail">
                                <div class="finding-meta-box">
                                    <div class="meta-row"><label>Severity:</label> <span class="sev-tag ${f.severity.toLowerCase()}">${f.severity}</span></div>
                                    <div class="meta-row"><label>CVSS Score:</label> <span>${f.cvss || 'N/A'}</span></div>
                                </div>
                                <h3>Description</h3>
                                <p>${f.description}</p>
                                <h3>Recommendation</h3>
                                <p>Remediate by implementing proper input validation and encoding routines according to OWASP guidelines.</p>
                            </div>
                            <div class="page-number">Page ${i + 3}</div>
                        </div>
                    `).join('')}

                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    // --- LOGIC ---
    updateField(field, val) {
        this.currentReport[field] = val;
        // Update Preview DOM directly
        if (field === 'title') document.getElementById('p-title').innerText = val;
        if (field === 'client') document.getElementById('p-client').innerText = `Prepared for: ${val}`;
        if (field === 'executiveSummary') document.getElementById('p-summary').innerText = val;
    },

    toggleFinding(id) {
        const output = document.getElementById('report-preview'); // To force re-render logic if complex, but simple array filter mainly
        const exists = this.currentReport.findings.find(f => f.id === id);

        if (exists) {
            this.currentReport.findings = this.currentReport.findings.filter(f => f.id !== id);
        } else {
            const original = this.potentialFindings.find(f => f.id === id);
            this.currentReport.findings.push(original);
        }

        this.refresh();
    },

    isSelected(id) {
        return !!this.currentReport.findings.find(f => f.id === id);
    },

    refresh() {
        document.querySelector('.report-app').outerHTML = this.render();
    },

    countSeverity(sev) {
        return this.currentReport.findings.filter(f => f.severity && f.severity.toLowerCase() === sev.toLowerCase()).length;
    },

    togglePreview() {
        // Toggle view class
        alert('Scroll down to see the "Print Preview" generated below the editor.');
    },

    getStyles() {
        return `
        <style>
            /* APP STYLES */
            .report-app { padding: 20px; color: #fff; max-width: 1200px; margin: 0 auto; }
            .builder-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .builder-header h1 { color: #00ffcc; margin: 0; }
            .actions button { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; margin-left: 10px; }
            .btn-preview { background: #333; color: #fff; }
            .btn-export { background: #00ffcc; color: #000; }

            .builder-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .builder-panel { background: #1a1a2e; border: 1px solid #333; padding: 20px; border-radius: 8px; }
            
            .form-group { margin-bottom: 15px; }
            .form-group label { display: block; color: #aaa; margin-bottom: 5px; font-size: 0.9rem; }
            .form-group input, .form-group textarea { width: 100%; padding: 10px; background: #0f0f1a; border: 1px solid #333; color: #fff; border-radius: 4px; }
            
            .findings-list { margin-top: 10px; display: flex; flex-direction: column; gap: 10px; max-height: 400px; overflow-y: auto; }
            .finding-item { display: flex; align-items: center; background: #0f0f1a; padding: 10px; border-radius: 6px; cursor: pointer; border: 1px solid transparent; transition: 0.2s; }
            .finding-item:hover { background: #222; }
            .finding-item.selected { border-color: #00ffcc; background: rgba(0, 255, 204, 0.05); }
            .finding-item.selected .check-icon { opacity: 1; color: #00ffcc; }
            .check-icon { opacity: 0; margin-left: auto; transition: 0.2s; }
            
            .f-severity { width: 10px; height: 40px; border-radius: 4px; margin-right: 15px; }
            .f-severity.high { background: #ff3333; }
            .f-severity.medium { background: #ffaa00; }
            .f-severity.low { background: #00cc66; }
            
            .f-title { font-weight: bold; }
            .f-meta { font-size: 0.8rem; color: #666; }

            /* PREVIEW / PRINT STYLES */
            .report-preview {
                background: #555;
                padding: 40px;
                margin-top: 40px;
                display: flex;
                flex-direction: column;
                gap: 40px;
                align-items: center;
                border-top: 2px dashed #333;
            }

            .print-page {
                width: 210mm;
                height: 297mm;
                background: #fff;
                color: #000;
                padding: 25mm;
                box-shadow: 0 0 20px rgba(0,0,0,0.5);
                position: relative;
                font-family: 'Georgia', serif;
                overflow: hidden;
            }

            @media print {
                body * { visibility: hidden; }
                .report-preview, .report-preview * { visibility: visible; }
                .report-preview { position: absolute; left: 0; top: 0; padding: 0; margin: 0; background: none; }
                .print-page { box-shadow: none; page-break-after: always; margin: 0; width: 100%; height: 100vh; }
                .no-print { display: none !important; }
            }

            /* PAGE DESIGN */
            .report-logo { color: #333; font-weight: bold; font-family: sans-serif; letter-spacing: 2px; border-bottom: 2px solid #333; padding-bottom: 15px; margin-bottom: 50mm; }
            .report-title-block h1 { font-size: 3rem; color: #000; line-height: 1.2; margin-bottom: 20px; }
            .report-title-block h2 { font-size: 1.5rem; color: #555; font-weight: normal; }
            .report-footer { position: absolute; bottom: 20mm; left: 25mm; right: 25mm; text-align: center; color: #aaa; font-size: 0.8rem; border-top: 1px solid #eee; padding-top: 10px; font-family: sans-serif; }
            
            .page-header { font-family: sans-serif; font-weight: bold; font-size: 1.2rem; color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 30px; }
            .page-content { font-size: 1.1rem; line-height: 1.6; color: #333; }
            
            .finding-detail h3 { color: #d62828; margin-top: 30px; font-family: sans-serif; }
            .finding-meta-box { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-family: sans-serif; }
            .meta-row { display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 5px 0; }
            .meta-row:last-child { border: none; }
            .sev-tag { padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.8rem; font-weight: bold; }
            .sev-tag.high { background: #d62828; }
            .sev-tag.medium { background: #f77f00; }
            .sev-tag.low { background: #2a9d8f; }
            
            .vuln-stats { margin-top: 50px; }
            .stat-bar { display: flex; align-items: center; margin-bottom: 10px; font-family: sans-serif; }
            .s-label { width: 120px; font-weight: bold; }
            .s-val { font-weight: bold; color: #333; }
        </style>
        `;
    }
};

function pageReportGenerator() {
    return ReportGenerator.render();
}
