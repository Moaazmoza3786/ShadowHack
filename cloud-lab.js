/* ==================== CLOUD ATTACK VECTOR LAB (PRO) ☁️⚡ ==================== */
/* Advanced AWS/Azure/GCP Exploitation Simulations */

window.CloudLab = {
    // --- STATE ---
    activeService: 's3',
    scanProgress: 0,
    scanResults: [],
    iamPolicyContent: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    }
  ]
}`,

    // --- RE-INIT ---
    init() {
        // State reset for fresh load
        this.scanProgress = 0;
        this.scanResults = [];
    },

    // --- RENDER UI ---
    render() {
        return `
            <div class="cloud-app fade-in">
                <!-- SIDEBAR -->
                <div class="cloud-sidebar">
                    <div class="cloud-logo"><i class="fas fa-cloud"></i> CLOUD STORM <span class="pro-badge">PRO</span></div>
                    <div class="cloud-nav">
                        <div class="nav-item ${this.activeService === 's3' ? 'active' : ''}" onclick="CloudLab.switchService('s3')">
                            <i class="fab fa-aws"></i> S3 Bucket Hunter
                        </div>
                        <div class="nav-item ${this.activeService === 'iam' ? 'active' : ''}" onclick="CloudLab.switchService('iam')">
                            <i class="fas fa-user-shield"></i> IAM Policy Audit
                        </div>
                        <div class="nav-item ${this.activeService === 'lambda' ? 'active' : ''}" onclick="CloudLab.switchService('lambda')">
                            <i class="fas fa-bolt"></i> Serverless Lab
                        </div>
                        <div class="nav-item ${this.activeService === 'metadata' ? 'active' : ''}" onclick="CloudLab.switchService('metadata')">
                            <i class="fas fa-server"></i> IMDS Exploitation
                        </div>
                    </div>
                </div>

                <!-- MAIN CONTENT -->
                <div class="cloud-main" id="cloud-content">
                    ${this.renderCurrentService()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderCurrentService() {
        switch (this.activeService) {
            case 's3': return this.renderS3();
            case 'iam': return this.renderIAM();
            case 'lambda': return this.renderLambda();
            case 'metadata': return this.renderMetadata();
            default: return this.renderS3();
        }
    },

    // --- S3 MODULE PRO ---
    renderS3() {
        return `
            <div class="cloud-panel">
                <div class="panel-header">
                    <h2><i class="fab fa-aws"></i> S3 Wordlist Bruteforcer</h2>
                    <p class="desc">Iterate subdomains and phrases against S3 naming patterns.</p>
                </div>
                
                <div class="s3-controls">
                    <input type="text" id="s3-target" placeholder="Target Base (e.g. megacorp)">
                    <button class="btn-primary" onclick="CloudLab.startS3Brute()"><i class="fas fa-play"></i> Start Discovery</button>
                </div>

                <div class="s3-monitor">
                    <div class="progress-bar-container">
                        <div class="progress-bar" id="s3-progress" style="width: ${this.scanProgress}%"></div>
                    </div>
                    <div class="s3-results" id="s3-results-container">
                        ${this.scanResults.length === 0 ? '<div class="empty-log">Log waiting for scan...</div>' : this.scanResults.map(r => `
                            <div class="res-row ${r.type}">
                                <span class="res-url">${r.url}</span>
                                <span class="res-status">${r.status}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    startS3Brute() {
        const target = document.getElementById('s3-target').value || 'target';
        const container = document.getElementById('s3-results-container');
        const bar = document.getElementById('s3-progress');

        this.scanResults = [];
        this.scanProgress = 0;
        container.innerHTML = '<div class="scanning-dots">Scanning namespaces...</div>';

        const patterns = ['-prod', '-dev', '-backup', '-internal', '-staging', '-pub', '.internal'];
        let idx = 0;

        const interval = setInterval(() => {
            if (idx >= patterns.length) {
                clearInterval(interval);
                this.scanProgress = 100;
                bar.style.width = '100%';
                return;
            }

            const url = `${target}${patterns[idx]}.s3.amazonaws.com`;
            const isHit = Math.random() > 0.7 || patterns[idx] === '-prod';

            this.scanResults.unshift({
                url: url,
                status: isHit ? '200 OK (PUBLIC)' : '403 Forbidden',
                type: isHit ? 'hit' : 'miss'
            });

            this.scanProgress = ((idx + 1) / patterns.length) * 100;
            bar.style.width = `${this.scanProgress}%`;

            container.innerHTML = this.scanResults.map(r => `
                <div class="res-row ${r.type}">
                    <span class="res-url"><i class="fas fa-archive"></i> ${r.url}</span>
                    <span class="res-status">${r.status}</span>
                </div>
            `).join('');

            idx++;
        }, 800);
    },

    // --- IAM POLICY AUDIT MODULE ---
    renderIAM() {
        return `
            <div class="cloud-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-shield-virus"></i> IAM Policy Analyzer</h2>
                    <p class="desc">Paste a JSON policy to identify Privilege Escalation paths.</p>
                </div>
                
                <div class="iam-workspace">
                    <div class="policy-editor">
                        <textarea id="iam-policy-input" spellcheck="false">${this.iamPolicyContent}</textarea>
                        <button class="btn-primary" onclick="CloudLab.auditPolicy()"><i class="fas fa-microscope"></i> Audit Policy</button>
                    </div>
                    <div class="audit-results" id="iam-audit-results">
                        <div class="placeholder-text">Enter policy and click Audit to start analysis.</div>
                    </div>
                </div>
            </div>
        `;
    },

    auditPolicy() {
        const json = document.getElementById('iam-policy-input').value;
        const resultContainer = document.getElementById('iam-audit-results');

        try {
            const policy = JSON.parse(json);
            this.iamPolicyContent = json;

            let findings = [];
            // Simple heuristic mapping
            const riskyActions = {
                'iam:PassRole': 'Allows assigning roles to resources (Potential SSRF/RCE escalation).',
                'ec2:RunInstances': 'Can create new servers (PrivEsc if coupled with PassRole).',
                'iam:CreateAccessKey': 'Direct backdoor creation.',
                'lambda:CreateFunction': 'Code execution in cloud context.',
                's3:GetObject': 'Potentially sensitive data access.'
            };

            const statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];

            statements.forEach(st => {
                if (st.Effect === 'Allow') {
                    const actions = Array.isArray(st.Action) ? st.Action : [st.Action];
                    actions.forEach(act => {
                        if (act === '*' || riskyActions[act]) {
                            findings.push({
                                action: act,
                                risk: act === '*' ? 'CRITICAL' : 'HIGH',
                                desc: act === '*' ? 'Full Administrator Access!' : riskyActions[act]
                            });
                        }
                    });
                }
            });

            resultContainer.innerHTML = `
                <div class="findings-list">
                    <h3>Audit Report</h3>
                    ${findings.length === 0 ? '<p class="clean">No high-risk patterns identified.</p>' : findings.map(f => `
                        <div class="finding-item ${f.risk.toLowerCase()}">
                            <span class="f-risk">${f.risk}</span>
                            <span class="f-action"><code>${f.action}</code></span>
                            <p class="f-desc">${f.desc}</p>
                        </div>
                    `).join('')}
                </div>
            `;
        } catch (e) {
            resultContainer.innerHTML = `<div class="error-msg">Invalid JSON Format.</div>`;
        }
    },

    // --- LAMBDA LAB MODULE ---
    renderLambda() {
        return `
            <div class="cloud-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-bolt"></i> Lambda / Serverless Lab</h2>
                    <p class="desc">Environment variables often contain keys. Simulate Variable Injection.</p>
                </div>

                <div class="lambda-grid">
                    <div class="function-card">
                        <div class="f-header"><i class="fas fa-code"></i> process-payment.js</div>
                        <div class="env-vars">
                            <div class="env-row"><span>DB_PASS</span>: <span>****************</span></div>
                            <div class="env-row"><span>AWS_KEY</span>: <span>AKIA...M4X</span></div>
                        </div>
                        <button class="btn-exploit" onclick="alert('Attempting to leak environment memory...')">LFI to Env</button>
                    </div>

                    <div class="exploit-log">
                        <h4>Attack Surface:</h4>
                        <ul>
                            <li><b>Insecure Secrets</b>: Dumping <code>process.env</code></li>
                            <li><b>Cold Start Injection</b>: Injecting malicious dependencies.</li>
                            <li><b>Event Injection</b>: Spoofing SNS/SQS event triggers.</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    },

    // --- IMDS MODULE ---
    renderMetadata() {
        return `
            <div class="cloud-panel">
                <div class="panel-header">
                    <h2><i class="fas fa-terminal"></i> Instance Metadata Attack (IMDS)</h2>
                    <p class="desc">Bypassing IMDSv2 sessions to extract IAM Role tokens.</p>
                </div>
                <div class="terminal-mock">
                    <div class="term-output" id="meta-output">
                        <div>root@compromised-app:~# curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT "http://169.254.169.254/latest/api/token"</div>
                        <div><span class="key">AQAEAO...==</span></div>
                        <div>root@compromised-app:~# curl -H "X-aws-ec2-metadata-token: [token]" http://169.254.169.254/latest/meta-data/iam/security-credentials/WebRole</div>
                        <div>root@compromised-app:~# <span class="cursor">_</span></div>
                    </div>
                </div>
                <div class="meta-controls">
                    <button class="btn-cmd" onclick="CloudLab.runIMDS('token')">Request Session Token</button>
                    <button class="btn-cmd" onclick="CloudLab.runIMDS('creds')">Dump WebRole Creds</button>
                </div>
            </div>
        `;
    },

    runIMDS(type) {
        const out = document.getElementById('meta-output');
        if (type === 'token') {
            out.innerHTML += `<div>root@compromised-app:~# curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT "http://169.254.169.254/latest/api/token"</div><div class="key">AQAEAO...XYZ</div>`;
        } else {
            out.innerHTML += `<div>root@compromised-app:~# curl -H "X-aws-ec2-metadata-token: AQAEAO...XYZ" http://169.254.169.254/latest/meta-data/iam/security-credentials/WebRole</div>
            <div class="json-resp">{ "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }</div>`;
            alert("IMDSv2 Bypassed! Tokens Acquired.");
        }
        out.scrollTop = out.scrollHeight;
    },

    switchService(service) {
        this.activeService = service;
        this.init();
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .cloud-app { display: flex; height: calc(100vh - 60px); background: #0f111a; color: #e0e0e0; font-family: 'Inter', sans-serif; overflow: hidden; }
            
            .cloud-sidebar { width: 260px; background: #161925; border-right: 1px solid #2d2d3a; display: flex; flex-direction: column; }
            .cloud-logo { padding: 25px; font-weight: 800; color: #fff; font-size: 1.1rem; border-bottom: 1px solid #1c1c26; }
            .pro-badge { background: #ff9900; color: #000; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; vertical-align: middle; margin-left: 5px; }
            
            .cloud-nav { flex: 1; padding: 15px 0; }
            .nav-item { padding: 12px 25px; cursor: pointer; color: #888; transition: 0.3s; display: flex; align-items: center; gap: 12px; font-size: 0.95rem; }
            .nav-item:hover { color: #fff; background: rgba(255,255,255,0.03); }
            .nav-item.active { color: #fff; background: rgba(255,153,0,0.1); border-left: 3px solid #ff9900; }
            
            .cloud-main { flex: 1; padding: 40px; overflow-y: auto; }
            .cloud-panel { max-width: 1000px; margin: 0 auto; }
            
            .panel-header { margin-bottom: 35px; }
            .panel-header h2 { margin: 0; font-size: 1.8rem; color: #fff; }
            .desc { color: #666; margin-top: 8px; font-size: 0.95rem; }

            /* S3 BRUTE */
            .s3-controls { display: flex; gap: 15px; margin-bottom: 25px; }
            .s3-controls input { background: #0a0a0f; border: 1px solid #333; padding: 12px; border-radius: 8px; color: #fff; flex: 1; outline: none; }
            .s3-controls input:focus { border-color: #ff9900; }
            
            .progress-bar-container { background: #1c1c26; height: 8px; border-radius: 4px; overflow: hidden; margin-bottom: 20px; }
            .progress-bar { background: #ff9900; height: 100%; width: 0%; transition: 0.4s; }
            
            .s3-results { background: #0a0a0f; border-radius: 12px; border: 1px solid #1c1c26; padding: 15px; height: 400px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; }
            .res-row { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #1c1c26; font-size: 0.9rem; }
            .res-row.hit { color: #4ade80; background: rgba(74, 222, 128, 0.05); }
            .res-row.miss { color: #ef4444; opacity: 0.6; }

            /* IAM ANALYSIS */
            .iam-workspace { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
            .policy-editor textarea { width: 100%; height: 400px; background: #0a0a0f; border: 1px solid #333; border-radius: 12px; padding: 15px; color: #fbbf24; font-family: monospace; font-size: 0.9rem; outline: none; resize: none; margin-bottom: 15px; }
            
            .finding-item { padding: 15px; border-radius: 8px; margin-bottom: 15px; border: 1px solid #333; }
            .finding-item.critical { border-color: #ef4444; background: rgba(239, 68, 68, 0.05); }
            .finding-item.high { border-color: #f59e0b; background: rgba(245, 158, 11, 0.05); }
            .f-risk { font-weight: 800; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; margin-right: 10px; }
            .critical .f-risk { background: #ef4444; color: #fff; }
            .high .f-risk { background: #f59e0b; color: #000; }
            .f-desc { margin: 10px 0 0; color: #888; font-size: 0.85rem; }

            /* LAMBDA GIRD */
            .lambda-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
            .function-card { background: #161925; border-radius: 12px; padding: 25px; border: 1px solid #2d2d3a; }
            .f-header { color: #4ade80; font-weight: bold; margin-bottom: 20px; border-bottom: 1px solid #222; padding-bottom: 10px; }
            .env-row { display: flex; justify-content: space-between; margin-bottom: 12px; font-family: monospace; font-size: 0.9rem; }
            .btn-exploit { background: #ef4444; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; width: 100%; margin-top: 20px; cursor: pointer; }

            /* TERMINAL */
            .terminal-mock { background: #000; color: #0f0; padding: 25px; border-radius: 12px; font-family: 'JetBrains Mono', monospace; height: 350px; overflow-y: auto; font-size: 0.9rem; border: 1px solid #1c1c26; }
            .json-resp { color: #fbbf24; white-space: pre-wrap; margin-top: 10px; }
            .key { color: #ef4444; font-weight: bold; }
            .btn-cmd { background: #1c1c26; color: #fff; border: 1px solid #333; padding: 10px 15px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; margin-top: 15px; }

            .btn-primary { background: #ff9900; color: #000; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; transition: 0.2s; }
            .btn-primary:hover { transform: scale(1.02); }

            @keyframes blink { 50% { opacity: 0; } }
            .cursor { animation: blink 1s infinite; border-left: 2px solid #0f0; margin-left: 5px; }
        </style>`;
    }
};

function pageCloudLab() {
    CloudLab.init();
    return CloudLab.render();
}
