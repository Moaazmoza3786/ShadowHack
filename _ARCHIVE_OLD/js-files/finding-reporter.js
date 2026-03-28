/* ==================== FINDING REPORT SIMULATOR 📋💼 ==================== */
/* Professional Security Report Writing & CVSS Calculator */

window.FindingReporter = {
    // --- STATE ---
    currentTab: 'new',
    findings: JSON.parse(localStorage.getItem('pro_findings') || '[]'),
    currentFinding: null,

    // --- CVSS 3.1 METRICS ---
    cvssMetrics: {
        // Attack Vector
        AV: {
            label: 'Attack Vector',
            options: [
                { value: 'N', label: 'Network', score: 0.85, desc: 'Remotely exploitable' },
                { value: 'A', label: 'Adjacent', score: 0.62, desc: 'Same network segment' },
                { value: 'L', label: 'Local', score: 0.55, desc: 'Local access required' },
                { value: 'P', label: 'Physical', score: 0.20, desc: 'Physical access required' }
            ]
        },
        // Attack Complexity
        AC: {
            label: 'Attack Complexity',
            options: [
                { value: 'L', label: 'Low', score: 0.77, desc: 'No special conditions' },
                { value: 'H', label: 'High', score: 0.44, desc: 'Specialized conditions required' }
            ]
        },
        // Privileges Required
        PR: {
            label: 'Privileges Required',
            options: [
                { value: 'N', label: 'None', score: 0.85, desc: 'No authentication needed' },
                { value: 'L', label: 'Low', score: 0.62, desc: 'Basic user privileges' },
                { value: 'H', label: 'High', score: 0.27, desc: 'Admin/elevated privileges' }
            ]
        },
        // User Interaction
        UI: {
            label: 'User Interaction',
            options: [
                { value: 'N', label: 'None', score: 0.85, desc: 'No user action required' },
                { value: 'R', label: 'Required', score: 0.62, desc: 'User must take action' }
            ]
        },
        // Scope
        S: {
            label: 'Scope',
            options: [
                { value: 'U', label: 'Unchanged', desc: 'Impact limited to vulnerable component' },
                { value: 'C', label: 'Changed', desc: 'Can impact other components' }
            ]
        },
        // Confidentiality Impact
        C: {
            label: 'Confidentiality',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No information disclosure' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Some data exposed' },
                { value: 'H', label: 'High', score: 0.56, desc: 'All data exposed' }
            ]
        },
        // Integrity Impact
        I: {
            label: 'Integrity',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No data modification' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Some data modifiable' },
                { value: 'H', label: 'High', score: 0.56, desc: 'All data modifiable' }
            ]
        },
        // Availability Impact
        A: {
            label: 'Availability',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No availability impact' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Partial service disruption' },
                { value: 'H', label: 'High', score: 0.56, desc: 'Complete service disruption' }
            ]
        }
    },

    // --- VULNERABILITY TYPES ---
    vulnTypes: [
        'SQL Injection', 'Cross-Site Scripting (XSS)', 'Server-Side Request Forgery (SSRF)',
        'Insecure Direct Object Reference (IDOR)', 'Authentication Bypass', 'Broken Access Control',
        'Remote Code Execution (RCE)', 'Local File Inclusion (LFI)', 'XML External Entity (XXE)',
        'Cross-Site Request Forgery (CSRF)', 'Information Disclosure', 'Business Logic Flaw',
        'Subdomain Takeover', 'Open Redirect', 'Command Injection', 'Privilege Escalation',
        'Insecure Deserialization', 'Server-Side Template Injection (SSTI)', 'Race Condition', 'Other'
    ],

    // --- BUSINESS IMPACT TEMPLATES ---
    businessImpacts: {
        'Critical': [
            'Complete compromise of customer data affecting millions of users',
            'Full access to financial systems and ability to perform unauthorized transactions',
            'Complete system takeover allowing attackers to control all infrastructure',
            'Regulatory violations (GDPR, PCI-DSS) with potential fines exceeding $10M'
        ],
        'High': [
            'Unauthorized access to sensitive customer PII (names, addresses, SSN)',
            'Ability to impersonate any user including administrators',
            'Access to internal systems and confidential business documents',
            'Potential reputational damage affecting customer trust'
        ],
        'Medium': [
            'Limited access to user data without critical information',
            'Ability to perform actions on behalf of users with their session',
            'Information disclosure of internal infrastructure details',
            'Service disruption affecting subset of users'
        ],
        'Low': [
            'Minor information disclosure (software versions, paths)',
            'Low-impact denial of service affecting single sessions',
            'Security misconfiguration without direct exploitation path',
            'Verbose error messages revealing technical details'
        ]
    },

    // --- REMEDIATION TEMPLATES ---
    remediationTemplates: {
        'SQL Injection': 'Use parameterized queries or prepared statements. Implement input validation and output encoding. Apply principle of least privilege to database accounts.',
        'Cross-Site Scripting (XSS)': 'Implement context-aware output encoding. Use Content Security Policy (CSP) headers. Validate and sanitize all user inputs.',
        'Server-Side Request Forgery (SSRF)': 'Implement allowlist for permitted URLs/domains. Disable unnecessary URL schemes. Use network segmentation to limit internal access.',
        'Insecure Direct Object Reference (IDOR)': 'Implement proper authorization checks on all object references. Use indirect references (UUIDs) instead of sequential IDs. Verify user permissions server-side.',
        'Authentication Bypass': 'Review and strengthen authentication logic. Implement multi-factor authentication. Use secure session management practices.',
        'Remote Code Execution (RCE)': 'Validate and sanitize all user inputs. Avoid using dangerous functions with user-controlled data. Implement sandboxing and container isolation.',
        'Local File Inclusion (LFI)': 'Avoid passing user input to file system functions. Use allowlists for permitted files. Implement proper access controls on file system.',
        'Command Injection': 'Avoid shell commands with user input. Use parameterized APIs. Implement strict input validation with allowlists.',
        'Broken Access Control': 'Implement role-based access control (RBAC). Verify authorization on every request. Apply defense in depth at multiple layers.'
    },

    // --- RENDER ---
    render() {
        return `
            <div class="reporter-app fade-in">
                <div class="reporter-header">
                    <h1><i class="fas fa-file-medical-alt"></i> Finding Report Simulator</h1>
                    <p class="subtitle">Professional Security Report Writing & CVSS Calculator</p>
                </div>

                <div class="reporter-tabs">
                    <div class="tab ${this.currentTab === 'new' ? 'active' : ''}" onclick="FindingReporter.switchTab('new')">
                        <i class="fas fa-plus-circle"></i> New Finding
                    </div>
                    <div class="tab ${this.currentTab === 'reports' ? 'active' : ''}" onclick="FindingReporter.switchTab('reports')">
                        <i class="fas fa-folder-open"></i> My Reports (${this.findings.length})
                    </div>
                    <div class="tab ${this.currentTab === 'cvss' ? 'active' : ''}" onclick="FindingReporter.switchTab('cvss')">
                        <i class="fas fa-calculator"></i> CVSS Calculator
                    </div>
                    <div class="tab ${this.currentTab === 'templates' ? 'active' : ''}" onclick="FindingReporter.switchTab('templates')">
                        <i class="fas fa-book"></i> Templates
                    </div>
                </div>

                <div class="reporter-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'new': return this.renderNewFinding();
            case 'reports': return this.renderReports();
            case 'cvss': return this.renderCVSSCalculator();
            case 'templates': return this.renderTemplates();
            default: return '';
        }
    },

    renderNewFinding() {
        return `
            <div class="new-finding-form">
                <h2><i class="fas fa-bug"></i> Document New Finding</h2>
                
                <div class="form-section">
                    <h3>📋 Basic Information</h3>
                    <div class="form-grid">
                        <div class="form-group">
                            <label>Finding Title *</label>
                            <input type="text" id="finding-title" placeholder="e.g., Stored XSS in User Profile Bio Field">
                        </div>
                        <div class="form-group">
                            <label>Vulnerability Type *</label>
                            <select id="finding-type" onchange="FindingReporter.updateRemediation()">
                                <option value="">Select type...</option>
                                ${this.vulnTypes.map(v => `<option value="${v}">${v}</option>`).join('')}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Affected Asset *</label>
                            <input type="text" id="finding-asset" placeholder="e.g., https://example.com/profile">
                        </div>
                        <div class="form-group">
                            <label>Parameter/Endpoint</label>
                            <input type="text" id="finding-param" placeholder="e.g., bio parameter, /api/v1/users">
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <h3>🔍 Technical Details</h3>
                    <div class="form-group">
                        <label>Description *</label>
                        <textarea id="finding-desc" rows="4" placeholder="Detailed technical description of the vulnerability..."></textarea>
                    </div>
                    <div class="form-group">
                        <label>Steps to Reproduce *</label>
                        <textarea id="finding-steps" rows="5" placeholder="1. Navigate to...&#10;2. Enter payload...&#10;3. Click submit...&#10;4. Observe..."></textarea>
                    </div>
                    <div class="form-group">
                        <label>Proof of Concept (PoC)</label>
                        <textarea id="finding-poc" rows="3" placeholder="Payload used, curl command, or code snippet..."></textarea>
                    </div>
                </div>

                <div class="form-section">
                    <h3>📊 CVSS Score</h3>
                    <div class="cvss-quick">
                        <div class="cvss-score-display">
                            <span id="quick-cvss-score">0.0</span>
                            <span id="quick-cvss-severity" class="severity-badge">N/A</span>
                        </div>
                        <button onclick="FindingReporter.openCVSSModal()">
                            <i class="fas fa-calculator"></i> Calculate CVSS
                        </button>
                    </div>
                    <input type="hidden" id="finding-cvss" value="0">
                    <input type="hidden" id="finding-cvss-vector" value="">
                </div>

                <div class="form-section">
                    <h3>💼 Business Impact *</h3>
                    <div class="impact-suggestions" id="impact-suggestions">
                        <p class="hint">Select severity to see impact examples</p>
                    </div>
                    <textarea id="finding-impact" rows="4" placeholder="Describe the potential business impact...&#10;&#10;Example: An attacker could exploit this vulnerability to steal user session cookies, leading to account takeover of any affected user. This could result in unauthorized access to sensitive customer data..."></textarea>
                    <button class="ai-assist-btn" onclick="FindingReporter.generateImpactWithAI()">
                        <i class="fas fa-robot"></i> Generate with AI
                    </button>
                </div>

                <div class="form-section">
                    <h3>🔧 Remediation</h3>
                    <div id="remediation-suggestion" class="remediation-box"></div>
                    <textarea id="finding-remediation" rows="4" placeholder="Recommended fix or mitigation..."></textarea>
                    <button class="ai-assist-btn" onclick="FindingReporter.generateRemediationWithAI()">
                        <i class="fas fa-robot"></i> Enhance with AI
                    </button>
                </div>

                <div class="form-section">
                    <h3>📎 Additional Information</h3>
                    <div class="form-grid">
                        <div class="form-group">
                            <label>CWE ID</label>
                            <input type="text" id="finding-cwe" placeholder="e.g., CWE-79">
                        </div>
                        <div class="form-group">
                            <label>OWASP Category</label>
                            <select id="finding-owasp">
                                <option value="">Select...</option>
                                <option value="A01">A01:2021 - Broken Access Control</option>
                                <option value="A02">A02:2021 - Cryptographic Failures</option>
                                <option value="A03">A03:2021 - Injection</option>
                                <option value="A04">A04:2021 - Insecure Design</option>
                                <option value="A05">A05:2021 - Security Misconfiguration</option>
                                <option value="A06">A06:2021 - Vulnerable Components</option>
                                <option value="A07">A07:2021 - Auth Failures</option>
                                <option value="A08">A08:2021 - Software Integrity Failures</option>
                                <option value="A09">A09:2021 - Logging Failures</option>
                                <option value="A10">A10:2021 - SSRF</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>References</label>
                        <textarea id="finding-refs" rows="2" placeholder="Links to related CVEs, blog posts, or documentation..."></textarea>
                    </div>
                </div>

                <div class="form-actions">
                    <button class="btn-primary" onclick="FindingReporter.saveFinding()">
                        <i class="fas fa-save"></i> Save Finding
                    </button>
                    <button class="btn-secondary" onclick="FindingReporter.generateFullReport()">
                        <i class="fas fa-file-pdf"></i> Generate Report
                    </button>
                    <button class="btn-ai" onclick="FindingReporter.reviewWithAI()">
                        <i class="fas fa-robot"></i> AI Review
                    </button>
                </div>
            </div>
        `;
    },

    renderCVSSCalculator() {
        return `
            <div class="cvss-calculator">
                <h2><i class="fas fa-calculator"></i> CVSS 3.1 Calculator</h2>
                
                <div class="cvss-result">
                    <div class="cvss-score-big" id="cvss-score-display">0.0</div>
                    <div class="cvss-severity-big" id="cvss-severity-display">None</div>
                    <div class="cvss-vector" id="cvss-vector-display">CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_</div>
                </div>

                <div class="cvss-metrics">
                    ${Object.entries(this.cvssMetrics).map(([key, metric]) => `
                        <div class="metric-group">
                            <label>${metric.label}</label>
                            <div class="metric-options">
                                ${metric.options.map(opt => `
                                    <button class="metric-btn" data-metric="${key}" data-value="${opt.value}"
                                            onclick="FindingReporter.setCVSSMetric('${key}', '${opt.value}')"
                                            title="${opt.desc}">
                                        ${opt.label}
                                    </button>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>

                <div class="cvss-actions">
                    <button onclick="FindingReporter.resetCVSS()"><i class="fas fa-redo"></i> Reset</button>
                    <button onclick="FindingReporter.copyCVSSVector()"><i class="fas fa-copy"></i> Copy Vector</button>
                </div>

                <div class="cvss-reference">
                    <h4>Severity Ratings</h4>
                    <div class="severity-guide">
                        <div class="sev-item critical"><span>9.0-10.0</span> Critical</div>
                        <div class="sev-item high"><span>7.0-8.9</span> High</div>
                        <div class="sev-item medium"><span>4.0-6.9</span> Medium</div>
                        <div class="sev-item low"><span>0.1-3.9</span> Low</div>
                        <div class="sev-item none"><span>0.0</span> None</div>
                    </div>
                </div>
            </div>
        `;
    },

    renderReports() {
        if (this.findings.length === 0) {
            return `
                <div class="empty-state">
                    <i class="fas fa-folder-open"></i>
                    <h3>No Findings Yet</h3>
                    <p>Start documenting your security findings like a professional!</p>
                    <button onclick="FindingReporter.switchTab('new')">
                        <i class="fas fa-plus"></i> Create Your First Finding
                    </button>
                </div>
            `;
        }

        return `
            <div class="reports-section">
                <div class="reports-header">
                    <h2><i class="fas fa-folder-open"></i> My Findings</h2>
                    <button onclick="FindingReporter.exportAllReports()">
                        <i class="fas fa-download"></i> Export All
                    </button>
                </div>

                <div class="reports-stats">
                    <div class="stat critical"><span>${this.findings.filter(f => f.severity === 'Critical').length}</span>Critical</div>
                    <div class="stat high"><span>${this.findings.filter(f => f.severity === 'High').length}</span>High</div>
                    <div class="stat medium"><span>${this.findings.filter(f => f.severity === 'Medium').length}</span>Medium</div>
                    <div class="stat low"><span>${this.findings.filter(f => f.severity === 'Low').length}</span>Low</div>
                </div>

                <div class="reports-list">
                    ${this.findings.map((f, i) => `
                        <div class="report-card" onclick="FindingReporter.viewFinding(${i})">
                            <div class="report-header">
                                <span class="severity-badge ${f.severity?.toLowerCase()}">${f.severity}</span>
                                <span class="cvss-badge">${f.cvss || 'N/A'}</span>
                            </div>
                            <h4>${f.title}</h4>
                            <p class="report-type">${f.type}</p>
                            <p class="report-asset"><i class="fas fa-link"></i> ${f.asset}</p>
                            <div class="report-meta">
                                <span><i class="fas fa-calendar"></i> ${f.date}</span>
                                <button onclick="event.stopPropagation(); FindingReporter.deleteFinding(${i})">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderTemplates() {
        return `
            <div class="templates-section">
                <h2><i class="fas fa-book"></i> Report Templates & Examples</h2>

                <div class="template-grid">
                    <div class="template-card">
                        <h4><i class="fas fa-file-alt"></i> Executive Summary Template</h4>
                        <pre>
During the security assessment of [TARGET], [X] vulnerabilities were identified:
- [X] Critical
- [X] High  
- [X] Medium
- [X] Low

The most severe finding was [TITLE], which could allow an attacker to [IMPACT].

Immediate remediation is recommended for all Critical and High severity findings.
                        </pre>
                        <button onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>

                    <div class="template-card">
                        <h4><i class="fas fa-exclamation-triangle"></i> Finding Template</h4>
                        <pre>
## [FINDING TITLE]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**CVSS Score:** [X.X] ([CVSS VECTOR])
**CWE:** [CWE-XXX]

### Description
[Technical description]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept
\`\`\`
[Payload or command]
\`\`\`

### Business Impact
[Business impact description]

### Remediation
[Recommended fix]

### References
- [Link 1]
- [Link 2]
                        </pre>
                        <button onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                </div>

                <h3>💼 Business Impact Examples by Severity</h3>
                <div class="impact-examples">
                    ${Object.entries(this.businessImpacts).map(([sev, impacts]) => `
                        <div class="impact-card ${sev.toLowerCase()}">
                            <h4>${sev}</h4>
                            <ul>
                                ${impacts.map(i => `<li>${i}</li>`).join('')}
                            </ul>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    // --- CVSS CALCULATION ---
    cvssValues: {},

    setCVSSMetric(metric, value) {
        this.cvssValues[metric] = value;

        // Update button states
        document.querySelectorAll(`[data-metric="${metric}"]`).forEach(btn => {
            btn.classList.toggle('active', btn.dataset.value === value);
        });

        this.calculateCVSS();
    },

    calculateCVSS() {
        const v = this.cvssValues;

        // Check if all metrics are set
        const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        const allSet = requiredMetrics.every(m => v[m]);

        if (!allSet) {
            this.updateCVSSDisplay(0, 'Incomplete');
            return;
        }

        // Get metric scores
        const getScore = (metric, val) => {
            const opt = this.cvssMetrics[metric].options.find(o => o.value === val);
            return opt?.score || 0;
        };

        // Calculate Impact Sub-Score
        const C = getScore('C', v.C);
        const I = getScore('I', v.I);
        const A = getScore('A', v.A);
        const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));

        let impact;
        if (v.S === 'U') {
            impact = 6.42 * ISS;
        } else {
            impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
        }

        // Calculate Exploitability
        const AV = getScore('AV', v.AV);
        const AC = getScore('AC', v.AC);
        let PR = getScore('PR', v.PR);

        // Adjust PR for scope change
        if (v.S === 'C') {
            if (v.PR === 'L') PR = 0.68;
            if (v.PR === 'H') PR = 0.50;
        }

        const UI = getScore('UI', v.UI);
        const exploitability = 8.22 * AV * AC * PR * UI;

        // Calculate Base Score
        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else if (v.S === 'U') {
            baseScore = Math.min(impact + exploitability, 10);
        } else {
            baseScore = Math.min(1.08 * (impact + exploitability), 10);
        }

        // Round up to 1 decimal
        baseScore = Math.ceil(baseScore * 10) / 10;

        // Determine severity
        let severity;
        if (baseScore === 0) severity = 'None';
        else if (baseScore < 4) severity = 'Low';
        else if (baseScore < 7) severity = 'Medium';
        else if (baseScore < 9) severity = 'High';
        else severity = 'Critical';

        // Generate vector string
        const vector = `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;

        this.updateCVSSDisplay(baseScore, severity, vector);
    },

    updateCVSSDisplay(score, severity, vector = '') {
        const scoreEl = document.getElementById('cvss-score-display');
        const severityEl = document.getElementById('cvss-severity-display');
        const vectorEl = document.getElementById('cvss-vector-display');

        if (scoreEl) scoreEl.textContent = score.toFixed(1);
        if (severityEl) {
            severityEl.textContent = severity;
            severityEl.className = 'cvss-severity-big ' + severity.toLowerCase();
        }
        if (vectorEl && vector) vectorEl.textContent = vector;

        // Also update quick display in form
        const quickScore = document.getElementById('quick-cvss-score');
        const quickSev = document.getElementById('quick-cvss-severity');
        if (quickScore) quickScore.textContent = score.toFixed(1);
        if (quickSev) {
            quickSev.textContent = severity;
            quickSev.className = 'severity-badge ' + severity.toLowerCase();
        }

        // Store for form
        const cvssInput = document.getElementById('finding-cvss');
        const vectorInput = document.getElementById('finding-cvss-vector');
        if (cvssInput) cvssInput.value = score;
        if (vectorInput) vectorInput.value = vector;

        // Update impact suggestions
        this.updateImpactSuggestions(severity);
    },

    resetCVSS() {
        this.cvssValues = {};
        document.querySelectorAll('.metric-btn').forEach(btn => btn.classList.remove('active'));
        this.updateCVSSDisplay(0, 'None');
    },

    copyCVSSVector() {
        const vector = document.getElementById('cvss-vector-display')?.textContent || '';
        navigator.clipboard.writeText(vector);
    },

    // --- FORM ACTIONS ---
    updateRemediation() {
        const type = document.getElementById('finding-type')?.value;
        const box = document.getElementById('remediation-suggestion');
        const textarea = document.getElementById('finding-remediation');

        if (type && this.remediationTemplates[type]) {
            box.innerHTML = `<strong>💡 Suggested:</strong> ${this.remediationTemplates[type]}`;
            box.style.display = 'block';
            if (!textarea.value) {
                textarea.value = this.remediationTemplates[type];
            }
        } else {
            box.style.display = 'none';
        }
    },

    updateImpactSuggestions(severity) {
        const box = document.getElementById('impact-suggestions');
        if (box && this.businessImpacts[severity]) {
            box.innerHTML = `
                <p class="hint">💡 Example impacts for ${severity}:</p>
                <ul>${this.businessImpacts[severity].map(i => `<li onclick="document.getElementById('finding-impact').value += '\\n• ' + this.textContent">${i}</li>`).join('')}</ul>
            `;
        }
    },

    saveFinding() {
        const finding = {
            title: document.getElementById('finding-title')?.value,
            type: document.getElementById('finding-type')?.value,
            asset: document.getElementById('finding-asset')?.value,
            param: document.getElementById('finding-param')?.value,
            description: document.getElementById('finding-desc')?.value,
            steps: document.getElementById('finding-steps')?.value,
            poc: document.getElementById('finding-poc')?.value,
            cvss: document.getElementById('finding-cvss')?.value,
            cvssVector: document.getElementById('finding-cvss-vector')?.value,
            impact: document.getElementById('finding-impact')?.value,
            remediation: document.getElementById('finding-remediation')?.value,
            cwe: document.getElementById('finding-cwe')?.value,
            owasp: document.getElementById('finding-owasp')?.value,
            refs: document.getElementById('finding-refs')?.value,
            date: new Date().toLocaleDateString(),
            severity: this.getSeverityFromCVSS(parseFloat(document.getElementById('finding-cvss')?.value || 0))
        };

        if (!finding.title || !finding.type || !finding.asset) {
            alert('Please fill in required fields (Title, Type, Asset)');
            return;
        }

        this.findings.push(finding);
        localStorage.setItem('pro_findings', JSON.stringify(this.findings));
        alert('Finding saved successfully!');
        this.switchTab('reports');
    },

    getSeverityFromCVSS(score) {
        if (score >= 9) return 'Critical';
        if (score >= 7) return 'High';
        if (score >= 4) return 'Medium';
        if (score > 0) return 'Low';
        return 'None';
    },

    deleteFinding(index) {
        if (confirm('Delete this finding?')) {
            this.findings.splice(index, 1);
            localStorage.setItem('pro_findings', JSON.stringify(this.findings));
            this.reRender();
        }
    },

    viewFinding(index) {
        const f = this.findings[index];
        const modal = document.createElement('div');
        modal.className = 'finding-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${f.title}</h2>
                    <button onclick="this.closest('.finding-modal').remove()"><i class="fas fa-times"></i></button>
                </div>
                <div class="modal-body">
                    <div class="finding-badges">
                        <span class="severity-badge ${f.severity?.toLowerCase()}">${f.severity}</span>
                        <span class="cvss-badge">CVSS: ${f.cvss}</span>
                        <span class="type-badge">${f.type}</span>
                    </div>
                    
                    <section><h4>Asset</h4><p>${f.asset}</p></section>
                    <section><h4>Description</h4><p>${f.description}</p></section>
                    <section><h4>Steps to Reproduce</h4><pre>${f.steps}</pre></section>
                    ${f.poc ? `<section><h4>Proof of Concept</h4><pre>${f.poc}</pre></section>` : ''}
                    <section><h4>Business Impact</h4><p>${f.impact}</p></section>
                    <section><h4>Remediation</h4><p>${f.remediation}</p></section>
                    
                    <div class="modal-actions">
                        <button onclick="FindingReporter.exportFinding(${index})"><i class="fas fa-download"></i> Export</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
    },

    exportFinding(index) {
        const f = this.findings[index];
        const report = `# ${f.title}

**Severity:** ${f.severity}
**CVSS Score:** ${f.cvss} (${f.cvssVector})
**Type:** ${f.type}
**CWE:** ${f.cwe}
**OWASP:** ${f.owasp}

## Affected Asset
${f.asset}
${f.param ? `Parameter: ${f.param}` : ''}

## Description
${f.description}

## Steps to Reproduce
${f.steps}

## Proof of Concept
\`\`\`
${f.poc}
\`\`\`

## Business Impact
${f.impact}

## Remediation
${f.remediation}

## References
${f.refs}

---
Generated: ${new Date().toISOString()}
`;
        const blob = new Blob([report], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${f.title.replace(/[^a-z0-9]/gi, '_')}.md`;
        a.click();
    },

    // --- AI INTEGRATION ---
    // --- AI INTEGRATION (SIMULATED) ---
    /* 
       In a real app, this would call an LLM API. 
       Here we simulate "Intelligence" using heuristic templates and keyword matching.
    */

    aiKnowledge: {
        impacts: {
            'XSS': "The attacker could execute arbitrary JavaScript in the victim's browser context. This could lead to session hijacking (stealing cookies), redirection to malicious sites, or unauthorized actions performed on behalf of the user.",
            'SQL': "An attacker could manipulate database queries to access, modify, or delete sensitive data. This could result in a complete database dump, including user passwords and PII, or even administrative takeover.",
            'RCE': "This is a critical vulnerability allowing full system compromise. An attacker could execute system-level commands, install malware, pivot to internal networks, and access all data stored on the server.",
            'IDOR': "Unauthorized access to sensitive resources belonging to other users. This breach of confidentiality allows attackers to scrape massive amounts of user data by iterating through object identifiers.",
            'SSRF': "The server can be induced to make requests to internal resources. This could expose internal services (like cloud metadata APIs), lead to RCE via internal admin panels, or allow scanning of the internal network.",
            'Auth': "Authentication mechanisms can be bypassed, allowing attackers to log in as any user (including admins) without valid credentials, leading to full account takeover.",
            'Default': "This vulnerability poses a significant risk to the confidentiality, integrity, and availability of the application. It could allow unauthorized actors to disrupt services or access restricted information."
        },
        remediations: {
            'Input': "Implement strict allow-listing for all user inputs. Use framework-specific built-in protection (e.g., ORM for SQLi, Auto-escaping for XSS). \n\nCode Example:\n```javascript\n// Bad\nconst query = `SELECT * FROM users WHERE id = ${id}`;\n\n// Good\nconst query = 'SELECT * FROM users WHERE id = ?';\ndb.execute(query, [id]);\n```",
            'Logic': "Review the business logic flow. Ensure that every sensitive action requires a valid session and proper authorization token. Implement state checks on the server side, never trust client-side state.",
            'Config': "Disable unnecessary services and features. Ensure all default credentials are changed. Implement 'Least Privilege' principle for service accounts. Enable rigorous logging and monitoring.",
            'Default': "Apply defense-in-depth strategies. Validate inputs, encode outputs, and verify authorization for every request. refer to OWASP Top 10 specific guidance for this category."
        }
    },

    async generateImpactWithAI() {
        const type = document.getElementById('finding-type')?.value || '';
        const desc = document.getElementById('finding-desc')?.value || '';
        const target = document.querySelector('#finding-impact');

        this.simulateAIProcess(() => {
            let coreImpact = this.aiKnowledge.impacts['Default'];

            if (type.includes('XSS') || type.includes('Cross')) coreImpact = this.aiKnowledge.impacts['XSS'];
            else if (type.includes('SQL') || type.includes('Injection')) coreImpact = this.aiKnowledge.impacts['SQL'];
            else if (type.includes('Code') || type.includes('RCE')) coreImpact = this.aiKnowledge.impacts['RCE'];
            else if (type.includes('IDOR') || type.includes('Object')) coreImpact = this.aiKnowledge.impacts['IDOR'];
            else if (type.includes('SSRF') || type.includes('Request')) coreImpact = this.aiKnowledge.impacts['SSRF'];
            else if (type.includes('Auth')) coreImpact = this.aiKnowledge.impacts['Auth'];

            // Contextualize
            const context = desc.length > 20 ? `Given that ${desc.substring(0, 50)}... ` : '';
            const text = `${context}${coreImpact}\n\nThis would likely result in significant reputational damage and potential regulatory fines if customer data is exposed.`;

            this.typewriterEffect(target, text);
        });
    },

    async generateRemediationWithAI() {
        const type = document.getElementById('finding-type')?.value || '';
        const target = document.querySelector('#finding-remediation');

        this.simulateAIProcess(() => {
            let coreRemediation = this.aiKnowledge.remediations['Default'];

            if (type.includes('XSS') || type.includes('SQL') || type.includes('Command')) coreRemediation = this.aiKnowledge.remediations['Input'];
            else if (type.includes('Logic') || type.includes('Auth') || type.includes('Access')) coreRemediation = this.aiKnowledge.remediations['Logic'];
            else if (type.includes('Config') || type.includes('Server')) coreRemediation = this.aiKnowledge.remediations['Config'];

            this.typewriterEffect(target, coreRemediation);
        });
    },

    async reviewWithAI() {
        const title = document.getElementById('finding-title')?.value;
        const desc = document.getElementById('finding-desc')?.value || '';
        const steps = document.getElementById('finding-steps')?.value || '';

        this.simulateAIProcess(() => {
            // Quality Heuristics
            let score = 100;
            let suggestions = [];

            if (!title) { score -= 20; suggestions.push("• Missing Title"); }
            if (desc.length < 50) { score -= 20; suggestions.push("• Description is too short. Add technical details causing the issue."); }
            if (steps.length < 50) { score -= 20; suggestions.push("• Steps to reproduce are vague. Be specific (URLs, Parameters)."); }
            if (!document.getElementById('finding-impact').value) { score -= 15; suggestions.push("• Missing Business Impact section."); }
            if (score < 0) score = 0;

            const feedback = score > 80 ? "Excellent report! Clear and professional." :
                score > 50 ? "Good start, but needs more detail." : "Needs significant improvement.";

            const modal = document.createElement('div');
            modal.className = 'finding-modal';
            modal.innerHTML = `
                <div class="modal-content" style="max-width: 500px">
                    <div class="modal-header">
                        <h2><i class="fas fa-robot"></i> AI Quality Review</h2>
                        <button onclick="this.closest('.finding-modal').remove()"><i class="fas fa-times"></i></button>
                    </div>
                    <div class="modal-body" style="text-align: center">
                        <div class="score-circle" style="
                            width: 100px; height: 100px; border-radius: 50%; 
                            background: conic-gradient(${this.getScoreColor(score)} ${score}%, #333 0);
                            display: flex; align-items: center; justify-content: center;
                            margin: 0 auto 20px; font-size: 2rem; font-weight: bold; color: #fff;
                            border: 5px solid #222;
                        ">
                            ${score}
                        </div>
                        <h3>${feedback}</h3>
                        <div style="text-align: left; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin-top: 20px;">
                            ${suggestions.length > 0 ? suggestions.join('<br>') : "• No major issues found. Ready for export!"}
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        });
    },

    generateFullReport() {
        alert("Feature coming in V2.1 - Use 'Export All' in Reports tab for now.");
    },

    // --- AI HELPERS ---
    simulateAIProcess(callback) {
        const btn = event.currentTarget;
        const ogContent = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Analying...';
        btn.disabled = true;

        setTimeout(() => {
            callback();
            btn.innerHTML = ogContent;
            btn.disabled = false;
        }, 1500); // 1.5s thinking time
    },

    typewriterEffect(element, text, speed = 10) {
        let i = 0;
        element.value = '';
        const timer = setInterval(() => {
            if (i < text.length) {
                element.value += text.charAt(i);
                element.scrollTop = element.scrollHeight;
                i++;
            } else {
                clearInterval(timer);
            }
        }, speed);
    },

    getScoreColor(score) {
        if (score >= 80) return '#2ecc71'; // Green
        if (score >= 60) return '#f1c40f'; // Yellow
        return '#e74c3c'; // Red
    },

    openCVSSModal() {
        this.switchTab('cvss');
    },

    exportAllReports() {
        const reports = this.findings.map(f => `# ${f.title}\n${f.description}\nCVSS: ${f.cvss}\n---`).join('\n\n');
        const blob = new Blob([reports], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'all_findings.md';
        a.click();
    },

    // --- NAVIGATION ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    reRender() {
        const app = document.querySelector('.reporter-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .reporter-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .reporter-header h1 { margin: 0; color: #3b82f6; font-size: 1.8rem; }
            .reporter-header .subtitle { color: #888; margin: 5px 0 20px; }

            .reporter-tabs { display: flex; gap: 5px; margin-bottom: 25px; flex-wrap: wrap; }
            .tab { padding: 12px 20px; border-radius: 8px; cursor: pointer; color: #888; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #3b82f6; color: #fff; }

            .form-section { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 12px; margin-bottom: 20px; }
            .form-section h3 { margin: 0 0 20px; color: #3b82f6; }
            .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
            .form-group { display: flex; flex-direction: column; gap: 8px; }
            .form-group label { color: #888; font-size: 0.9rem; }
            .form-group input, .form-group select, .form-group textarea { padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 0.95rem; }
            .form-group textarea { resize: vertical; font-family: inherit; }

            .cvss-quick { display: flex; align-items: center; gap: 20px; }
            .cvss-score-display { display: flex; align-items: center; gap: 10px; }
            .cvss-score-display span:first-child { font-size: 2rem; font-weight: bold; color: #fff; }
            .severity-badge { padding: 5px 12px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }
            .severity-badge.critical { background: rgba(220,38,38,0.2); color: #ef4444; }
            .severity-badge.high { background: rgba(234,88,12,0.2); color: #ea580c; }
            .severity-badge.medium { background: rgba(202,138,4,0.2); color: #ca8a04; }
            .severity-badge.low { background: rgba(34,197,94,0.2); color: #22c55e; }
            .cvss-quick button { padding: 10px 20px; background: rgba(59,130,246,0.2); border: 1px solid rgba(59,130,246,0.3); border-radius: 8px; color: #60a5fa; cursor: pointer; }

            .impact-suggestions { background: rgba(59,130,246,0.1); padding: 15px; border-radius: 8px; margin-bottom: 15px; }
            .impact-suggestions .hint { color: #888; margin: 0 0 10px; }
            .impact-suggestions ul { margin: 0; padding-left: 20px; }
            .impact-suggestions li { margin: 5px 0; color: #60a5fa; cursor: pointer; transition: 0.2s; }
            .impact-suggestions li:hover { color: #fff; }

            .remediation-box { background: rgba(34,197,94,0.1); padding: 15px; border-radius: 8px; margin-bottom: 15px; color: #22c55e; display: none; }

            .ai-assist-btn { margin-top: 10px; padding: 8px 15px; background: rgba(139,92,246,0.2); border: 1px solid rgba(139,92,246,0.3); border-radius: 8px; color: #a78bfa; cursor: pointer; }

            .form-actions { display: flex; gap: 15px; flex-wrap: wrap; margin-top: 20px; }
            .btn-primary { padding: 15px 30px; background: #3b82f6; border: none; border-radius: 10px; color: #fff; cursor: pointer; font-size: 1rem; }
            .btn-secondary { padding: 15px 30px; background: rgba(255,255,255,0.1); border: none; border-radius: 10px; color: #fff; cursor: pointer; }
            .btn-ai { padding: 15px 30px; background: rgba(139,92,246,0.3); border: none; border-radius: 10px; color: #a78bfa; cursor: pointer; }

            .cvss-calculator { max-width: 900px; }
            .cvss-result { text-align: center; background: rgba(0,0,0,0.3); padding: 30px; border-radius: 16px; margin-bottom: 30px; }
            .cvss-score-big { font-size: 4rem; font-weight: bold; color: #fff; }
            .cvss-severity-big { font-size: 1.5rem; margin: 10px 0; }
            .cvss-severity-big.critical { color: #ef4444; }
            .cvss-severity-big.high { color: #ea580c; }
            .cvss-severity-big.medium { color: #ca8a04; }
            .cvss-severity-big.low { color: #22c55e; }
            .cvss-vector { font-family: monospace; color: #888; margin-top: 15px; }

            .cvss-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .metric-group { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; }
            .metric-group label { display: block; color: #3b82f6; margin-bottom: 10px; font-weight: 500; }
            .metric-options { display: flex; gap: 8px; flex-wrap: wrap; }
            .metric-btn { padding: 8px 15px; background: rgba(255,255,255,0.05); border: 1px solid #333; border-radius: 6px; color: #888; cursor: pointer; transition: 0.2s; }
            .metric-btn:hover { border-color: #3b82f6; color: #3b82f6; }
            .metric-btn.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }

            .cvss-actions { display: flex; gap: 15px; margin-top: 25px; }
            .cvss-actions button { padding: 12px 20px; background: rgba(255,255,255,0.1); border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .cvss-reference { margin-top: 30px; }
            .cvss-reference h4 { color: #888; margin: 0 0 15px; }
            .severity-guide { display: flex; gap: 10px; flex-wrap: wrap; }
            .sev-item { padding: 10px 20px; border-radius: 8px; }
            .sev-item span { font-weight: bold; margin-right: 8px; }
            .sev-item.critical { background: rgba(220,38,38,0.2); color: #ef4444; }
            .sev-item.high { background: rgba(234,88,12,0.2); color: #ea580c; }
            .sev-item.medium { background: rgba(202,138,4,0.2); color: #ca8a04; }
            .sev-item.low { background: rgba(34,197,94,0.2); color: #22c55e; }
            .sev-item.none { background: rgba(107,114,128,0.2); color: #6b7280; }

            .reports-section h2 { color: #3b82f6; margin: 0 0 20px; }
            .reports-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
            .reports-header button { padding: 10px 20px; background: #3b82f6; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .reports-stats { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
            .stat { background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px; text-align: center; }
            .stat span { display: block; font-size: 2rem; font-weight: bold; }
            .stat.critical span { color: #ef4444; }
            .stat.high span { color: #ea580c; }
            .stat.medium span { color: #ca8a04; }
            .stat.low span { color: #22c55e; }

            .reports-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
            .report-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; cursor: pointer; transition: 0.2s; border-left: 3px solid transparent; }
            .report-card:hover { transform: translateY(-3px); border-left-color: #3b82f6; }
            .report-header { display: flex; gap: 10px; margin-bottom: 10px; }
            .cvss-badge { padding: 5px 10px; background: rgba(139,92,246,0.2); color: #a78bfa; border-radius: 12px; font-size: 0.8rem; }
            .report-card h4 { margin: 0 0 10px; color: #fff; }
            .report-type { color: #3b82f6; margin: 0 0 5px; }
            .report-asset { color: #888; margin: 0 0 15px; font-size: 0.9rem; }
            .report-meta { display: flex; justify-content: space-between; align-items: center; color: #666; font-size: 0.85rem; }
            .report-meta button { background: none; border: none; color: #666; cursor: pointer; }

            .templates-section h2 { color: #3b82f6; margin: 0 0 25px; }
            .template-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .template-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .template-card h4 { margin: 0 0 15px; color: #3b82f6; }
            .template-card pre { background: #0a0a12; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; color: #ccc; white-space: pre-wrap; }
            .template-card button { margin-top: 10px; padding: 8px 15px; background: rgba(59,130,246,0.2); border: none; border-radius: 6px; color: #60a5fa; cursor: pointer; }

            .impact-examples { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; }
            .impact-card { padding: 20px; border-radius: 12px; border-left: 3px solid; }
            .impact-card.critical { background: rgba(220,38,38,0.1); border-color: #ef4444; }
            .impact-card.high { background: rgba(234,88,12,0.1); border-color: #ea580c; }
            .impact-card.medium { background: rgba(202,138,4,0.1); border-color: #ca8a04; }
            .impact-card.low { background: rgba(34,197,94,0.1); border-color: #22c55e; }
            .impact-card h4 { margin: 0 0 15px; }
            .impact-card ul { margin: 0; padding-left: 20px; }
            .impact-card li { margin: 8px 0; color: #ccc; }

            .empty-state { text-align: center; padding: 60px 20px; color: #666; }
            .empty-state i { font-size: 4rem; margin-bottom: 20px; color: #3b82f6; }
            .empty-state button { margin-top: 20px; padding: 12px 25px; background: #3b82f6; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .finding-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 10001; display: flex; align-items: center; justify-content: center; padding: 20px; }
            .finding-modal .modal-content { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 16px; max-width: 800px; width: 100%; max-height: 90vh; overflow-y: auto; }
            .finding-modal .modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px; border-bottom: 1px solid #333; }
            .finding-modal .modal-header h2 { margin: 0; color: #fff; font-size: 1.3rem; }
            .finding-modal .modal-header button { background: none; border: none; color: #888; cursor: pointer; font-size: 1.2rem; }
            .finding-modal .modal-body { padding: 25px; }
            .finding-badges { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .type-badge { padding: 5px 12px; background: rgba(59,130,246,0.2); color: #60a5fa; border-radius: 12px; font-size: 0.8rem; }
            .finding-modal section { margin-bottom: 20px; }
            .finding-modal section h4 { color: #3b82f6; margin: 0 0 10px; }
            .finding-modal section p { color: #ccc; margin: 0; line-height: 1.6; }
            .finding-modal section pre { background: #0a0a12; padding: 15px; border-radius: 8px; white-space: pre-wrap; color: #ccc; }
            .modal-actions { display: flex; gap: 10px; margin-top: 20px; }
            .modal-actions button { padding: 10px 20px; background: #3b82f6; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            @media (max-width: 800px) { .form-grid { grid-template-columns: 1fr; } .reports-list { grid-template-columns: 1fr; } .template-grid { grid-template-columns: 1fr; } }
        </style>`;
    }
};

function pageFindingReporter() {
    return FindingReporter.render();
}
