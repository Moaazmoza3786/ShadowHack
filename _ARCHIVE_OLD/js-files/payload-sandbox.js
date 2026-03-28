/* ============================================================
   BREACHLABS - PAYLOAD SANDBOX & LIVE LAB
   Interactive environment for testing payloads and launching labs
   ============================================================ */

function pagePayloadSandbox() {
    return `
    <div class="container-fluid learn-container">
        
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <div>
                <h1 class="display-4 fw-bold text-white mb-2">
                    <span class="text-primary"><i class="fas fa-flask"></i> Live</span> Lab
                </h1>
                <p class="text-muted fs-5">Test payloads safely and launch vulnerable environments.</p>
            </div>
            <button onclick="loadPage('home')" class="cyber-btn back-btn">
                <i class="fas fa-home ms-2"></i> Home
            </button>
        </div>

        <div class="row g-4">
            
            <!-- LEFT COLUMN: Payload Sandbox -->
            <div class="col-lg-7 fade-in delay-1">
                <div class="cyber-card h-100 p-4">
                    <div class="d-flex align-items-center justify-content-between mb-4">
                        <h3 class="text-white mb-0"><i class="fas fa-microscope text-info me-2"></i> Payload Sanitizer</h3>
                        <select id="sandbox-mode" class="form-select cyber-input w-auto" onchange="resetSandbox()">
                            <option value="html">HTML / XSS</option>
                            <option value="sql">SQL Injection</option>
                            <option value="command">Command Injection</option>
                        </select>
                    </div>

                    <div class="mb-3">
                        <label class="text-muted mb-2">Input Payload</label>
                        <textarea id="sandbox-input" class="form-control cyber-input code-font" rows="4" 
                            placeholder="<script>alert(1)</script> OR ' OR 1=1"></textarea>
                    </div>

                    <div class="d-flex gap-2 mb-4">
                        <button onclick="analyzePayload()" class="cyber-btn w-100">
                            <i class="fas fa-bug border-0"></i> Analyze Payload
                        </button>
                        <button onclick="optimizePayloadWithAI()" class="cyber-btn w-100" style="background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #10b981;">
                            <i class="fas fa-wand-magic-sparkles"></i> Optimize with AI
                        </button>
                    </div>

                    <div id="sandbox-result" class="d-none">
                        <h5 class="text-white mb-3">Analysis Result:</h5>
                        
                        <!-- Status Badge -->
                        <div id="sandbox-status" class="mb-3"></div>

                        <!-- Analysis Log -->
                        <div class="bg-black p-3 rounded border border-secondary mb-3">
                            <ul id="sandbox-log" class="list-unstyled mb-0 text-muted small font-monospace"></ul>
                        </div>

                        <!-- Output Preview -->
                        <div class="mb-2 text-muted small">Sanitized Output (Backend View):</div>
                        <div class="bg-dark p-3 rounded code-font text-success border border-success border-opacity-25" id="sandbox-output">
                        </div>
                    </div>
                </div>
            </div>

            <!-- RIGHT COLUMN: Docker Labs -->
            <div class="col-lg-5 fade-in delay-2">
                <div class="cyber-card h-100 p-4">
                    <h3 class="text-white mb-4"><i class="fab fa-docker text-primary me-2"></i> Vulnerable Apps</h3>
                    <p class="text-muted small mb-4">
                        Launch isolated Docker containers. Instances are destroyed after 2 hours.
                        <br><span class="text-danger">* Requires Backend Running</span>
                    </p>

                    <div class="d-flex flex-column gap-3">
                        ${renderLabCard('dvwa', 'DVWA', 'Damn Vulnerable Web App', 'medium')}
                        ${renderLabCard('juice-shop', 'OWASP Juice Shop', 'Modern E-Commerce vulnerabilities', 'hard')}
                        ${renderLabCard('mutillidae', 'Mutillidae II', 'Comprehensive hacking practice', 'hard')}
                    </div>

                    <div id="active-lab-status" class="mt-4 pt-4 border-top border-secondary d-none">
                        <h5 class="text-white mb-3">Active Instance:</h5>
                        <div class="bg-success bg-opacity-10 border border-success rounded p-3">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span class="fw-bold text-success" id="lab-name">DVWA</span>
                                <span class="badge bg-success">RUNNING</span>
                            </div>
                            <div class="font-monospace text-white fs-4 mb-2" id="lab-ip">127.0.0.1:8080</div>
                            <a href="#" target="_blank" id="lab-link" class="btn btn-sm btn-outline-success w-100 mb-2">
                                <i class="fas fa-external-link-alt"></i> Open Lab
                            </a>
                            <button onclick="stopLab()" class="btn btn-sm btn-danger w-100">
                                <i class="fas fa-stop"></i> Terminate
                            </button>
                        </div>
                    </div>

                </div>
            </div>

        </div>
    </div>
    `;
}

function renderLabCard(id, title, desc, diff) {
    const colors = { easy: 'success', medium: 'warning', hard: 'danger' };
    return `
    <div class="bg-dark bg-opacity-50 p-3 rounded border border-secondary hover-effect" onclick="startLab('${id}', '${title}')">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <div class="fw-bold text-white">${title}</div>
                <div class="small text-muted">${desc}</div>
            </div>
            <span class="badge bg-${colors[diff] || 'secondary'}">${diff.toUpperCase()}</span>
        </div>
    </div>
    `;
}

// --- Logic ---

async function analyzePayload() {
    const input = document.getElementById('sandbox-input').value;
    const mode = document.getElementById('sandbox-mode').value;
    const resultDiv = document.getElementById('sandbox-result');

    if (!input) return;

    // Show loading
    resultDiv.classList.remove('d-none');
    document.getElementById('sandbox-status').innerHTML = '<span class="spinner-border spinner-border-sm text-info"></span> Processing...';

    try {
        const response = await fetch('/api/tools/sanitize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: input, mode: mode })
        });

        const data = await response.json();

        // Render Status
        const statusHtml = data.safe
            ? `<div class="alert alert-success py-2"><i class="fas fa-check-circle"></i> Input appears safe (sanitized)</div>`
            : `<div class="alert alert-danger py-2"><i class="fas fa-exclamation-triangle"></i> Malicious pattern detected!</div>`;

        document.getElementById('sandbox-status').innerHTML = statusHtml;

        // Render Log
        const logHtml = data.analysis.map(line => `<li>> ${line}</li>`).join('');
        document.getElementById('sandbox-log').innerHTML = logHtml;

        // Render Output
        const outputEl = document.getElementById('sandbox-output');
        outputEl.textContent = data.sanitized;

        // Highlight logic
        if (!data.safe) {
            outputEl.classList.remove('border-success', 'text-success');
            outputEl.classList.add('border-danger', 'text-danger');
        } else {
            outputEl.classList.add('border-success', 'text-success');
            outputEl.classList.remove('border-danger', 'text-danger');
        }

    } catch (e) {
        console.error(e);
        document.getElementById('sandbox-status').innerHTML = `<div class="text-danger">API Error: Backend not reachable</div>`;
    }
}

async function optimizePayloadWithAI() {
    const input = document.getElementById('sandbox-input').value;
    const resultDiv = document.getElementById('sandbox-result');

    if (!input) return;

    resultDiv.classList.remove('d-none');
    document.getElementById('sandbox-status').innerHTML = '<span class="spinner-border spinner-border-sm text-success"></span> Optimizing with AI...';
    document.getElementById('sandbox-log').innerHTML = '';
    document.getElementById('sandbox-output').innerHTML = '';

    try {
        const response = await fetch('/api/ai/optimize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload: input })
        });

        const data = await response.json();
        if (data.success) {
            const r = typeof data.result === 'string' ? JSON.parse(data.result) : data.result;

            document.getElementById('sandbox-status').innerHTML = '<div class="alert alert-success py-2"><i class="fas fa-magic"></i> Payload Optimized Successfully</div>';

            document.getElementById('sandbox-log').innerHTML = `
                <li>> Technique: <span class="text-info">${r.technique_used}</span></li>
                <li>> Explanation: ${r.explanation}</li>
            `;

            const outputEl = document.getElementById('sandbox-output');
            outputEl.textContent = r.optimized;
            outputEl.classList.add('border-success', 'text-success');

            // Auto-update input for convenience
            document.getElementById('sandbox-input').value = r.optimized;

        } else {
            document.getElementById('sandbox-status').innerHTML = '<div class="text-danger">Optimization Failed.</div>';
        }

    } catch (e) {
        console.error(e);
        document.getElementById('sandbox-status').innerHTML = '<div class="text-danger">Connection Error.</div>';
    }
}

async function startLab(slug, title) {
    if (!confirm(`Launch ${title}? This will stop any other running labs.`)) return;

    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = `<div class="text-center"><span class="spinner-border spinner-border-sm"></span> Spawning Docker...</div>`;

    try {
        const response = await fetch('/api/labs/spawn', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: 1, // Default user
                lab_slug: slug,
                lab_id: 999 // Virtual ID for standalone apps
            })
        });

        const data = await response.json();

        if (data.success) {
            showActiveLab(data.lab_instance, title);
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        alert('Failed to connect to backend.');
    } finally {
        btn.innerHTML = originalText;
    }
}

function showActiveLab(instance, title) {
    const statusDiv = document.getElementById('active-lab-status');
    const ipDiv = document.getElementById('lab-ip');
    const linkBtn = document.getElementById('lab-link');
    const nameSpan = document.getElementById('lab-name');

    statusDiv.classList.remove('d-none');
    nameSpan.textContent = title;

    // Construct real IP
    const url = `http://${instance.ip_address}:${instance.port}`;
    ipDiv.textContent = `${instance.ip_address}:${instance.port}`;
    linkBtn.href = url;
}

async function stopLab() {
    if (!confirm('Stop current lab?')) return;

    await fetch('/api/labs/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: 1 })
    });

    document.getElementById('active-lab-status').classList.add('d-none');
}
