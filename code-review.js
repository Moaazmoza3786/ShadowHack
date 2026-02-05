/* ==================== SOURCE CODE REVIEW DOJO 🔍📝 ==================== */
/* Static Analysis & Vulnerability Hunting */

window.CodeReviewDojo = {
    state: { tab: 'analyzer', code: '', lang: 'php', findings: [], selectedFinding: null },

    // Dangerous patterns by language
    patterns: {
        php: [
            { fn: 'eval', cat: 'RCE', sev: 'CRITICAL', desc: 'Arbitrary code execution' },
            { fn: 'system', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'exec', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'shell_exec', cat: 'RCE', sev: 'CRITICAL', desc: 'Shell command execution' },
            { fn: 'passthru', cat: 'RCE', sev: 'CRITICAL', desc: 'Command with output' },
            { fn: 'popen', cat: 'RCE', sev: 'HIGH', desc: 'Process open' },
            { fn: 'proc_open', cat: 'RCE', sev: 'HIGH', desc: 'Process open' },
            { fn: 'pcntl_exec', cat: 'RCE', sev: 'CRITICAL', desc: 'Process execution' },
            { fn: 'assert', cat: 'RCE', sev: 'HIGH', desc: 'Can execute code' },
            { fn: 'preg_replace.*e', cat: 'RCE', sev: 'CRITICAL', desc: 'Code execution via /e modifier', regex: true },
            { fn: 'create_function', cat: 'RCE', sev: 'HIGH', desc: 'Dynamic function creation' },
            { fn: 'include', cat: 'LFI', sev: 'HIGH', desc: 'Local file inclusion' },
            { fn: 'include_once', cat: 'LFI', sev: 'HIGH', desc: 'Local file inclusion' },
            { fn: 'require', cat: 'LFI', sev: 'HIGH', desc: 'Local file inclusion' },
            { fn: 'require_once', cat: 'LFI', sev: 'HIGH', desc: 'Local file inclusion' },
            { fn: 'file_get_contents', cat: 'SSRF/LFI', sev: 'MEDIUM', desc: 'File/URL read' },
            { fn: 'fopen', cat: 'LFI', sev: 'MEDIUM', desc: 'File operations' },
            { fn: 'readfile', cat: 'LFI', sev: 'MEDIUM', desc: 'File read' },
            { fn: 'unserialize', cat: 'DESER', sev: 'CRITICAL', desc: 'Insecure deserialization' },
            { fn: 'mysqli_query', cat: 'SQLi', sev: 'HIGH', desc: 'SQL query (check for prepared statements)' },
            { fn: 'mysql_query', cat: 'SQLi', sev: 'CRITICAL', desc: 'Deprecated, likely vulnerable' },
            { fn: '\\$_GET', cat: 'INPUT', sev: 'INFO', desc: 'User input - trace usage' },
            { fn: '\\$_POST', cat: 'INPUT', sev: 'INFO', desc: 'User input - trace usage' },
            { fn: '\\$_REQUEST', cat: 'INPUT', sev: 'INFO', desc: 'User input - trace usage' },
            { fn: 'echo.*\\$_', cat: 'XSS', sev: 'HIGH', desc: 'Potential XSS', regex: true },
            { fn: 'print.*\\$_', cat: 'XSS', sev: 'HIGH', desc: 'Potential XSS', regex: true },
            { fn: 'header\\s*\\(.*\\$', cat: 'REDIRECT', sev: 'MEDIUM', desc: 'Open redirect', regex: true },
            { fn: 'curl_exec', cat: 'SSRF', sev: 'HIGH', desc: 'Server-side request' },
            { fn: 'mail', cat: 'INJECTION', sev: 'MEDIUM', desc: 'Email header injection' },
            { fn: 'extract', cat: 'OVERWRITE', sev: 'HIGH', desc: 'Variable overwrite' }
        ],
        python: [
            { fn: 'eval', cat: 'RCE', sev: 'CRITICAL', desc: 'Arbitrary code execution' },
            { fn: 'exec', cat: 'RCE', sev: 'CRITICAL', desc: 'Code execution' },
            { fn: 'os.system', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'os.popen', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'subprocess', cat: 'RCE', sev: 'HIGH', desc: 'Command execution' },
            { fn: 'commands.getoutput', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'pickle.loads', cat: 'DESER', sev: 'CRITICAL', desc: 'Insecure deserialization' },
            { fn: 'yaml.load', cat: 'DESER', sev: 'HIGH', desc: 'YAML deserialization (use safe_load)' },
            { fn: 'marshal.loads', cat: 'DESER', sev: 'HIGH', desc: 'Unsafe deserialization' },
            { fn: '__import__', cat: 'RCE', sev: 'HIGH', desc: 'Dynamic import' },
            { fn: 'input\\(', cat: 'RCE', sev: 'HIGH', desc: 'Python2 input() executes code', regex: true },
            { fn: 'open\\(', cat: 'LFI', sev: 'MEDIUM', desc: 'File operations', regex: true },
            { fn: 'request.args', cat: 'INPUT', sev: 'INFO', desc: 'Flask user input' },
            { fn: 'request.form', cat: 'INPUT', sev: 'INFO', desc: 'Flask user input' },
            { fn: 'render_template_string', cat: 'SSTI', sev: 'CRITICAL', desc: 'Template injection' },
            { fn: '%s.*%.*request', cat: 'SQLi', sev: 'HIGH', desc: 'String formatting in query', regex: true },
            { fn: 'f".*{.*}"', cat: 'SQLi', sev: 'MEDIUM', desc: 'F-string in query', regex: true }
        ],
        javascript: [
            { fn: 'eval', cat: 'RCE', sev: 'CRITICAL', desc: 'Arbitrary code execution' },
            { fn: 'Function\\(', cat: 'RCE', sev: 'CRITICAL', desc: 'Dynamic code execution', regex: true },
            { fn: 'setTimeout.*\\$', cat: 'RCE', sev: 'HIGH', desc: 'Delayed code execution', regex: true },
            { fn: 'setInterval.*\\$', cat: 'RCE', sev: 'HIGH', desc: 'Interval code execution', regex: true },
            { fn: 'child_process', cat: 'RCE', sev: 'CRITICAL', desc: 'Node.js command execution' },
            { fn: 'innerHTML', cat: 'XSS', sev: 'HIGH', desc: 'DOM XSS sink' },
            { fn: 'outerHTML', cat: 'XSS', sev: 'HIGH', desc: 'DOM XSS sink' },
            { fn: 'document.write', cat: 'XSS', sev: 'HIGH', desc: 'DOM XSS sink' },
            { fn: 'location.*=', cat: 'REDIRECT', sev: 'MEDIUM', desc: 'Open redirect', regex: true },
            { fn: 'location.href', cat: 'REDIRECT', sev: 'MEDIUM', desc: 'Open redirect' },
            { fn: 'window.open', cat: 'REDIRECT', sev: 'LOW', desc: 'New window' },
            { fn: 'localStorage', cat: 'STORAGE', sev: 'INFO', desc: 'Client storage' },
            { fn: 'sessionStorage', cat: 'STORAGE', sev: 'INFO', desc: 'Client storage' },
            { fn: 'JSON.parse', cat: 'INPUT', sev: 'LOW', desc: 'Parse untrusted JSON' },
            { fn: 'req.query', cat: 'INPUT', sev: 'INFO', desc: 'Express user input' },
            { fn: 'req.body', cat: 'INPUT', sev: 'INFO', desc: 'Express user input' },
            { fn: 'req.params', cat: 'INPUT', sev: 'INFO', desc: 'Express user input' }
        ],
        java: [
            { fn: 'Runtime.getRuntime\\(\\).exec', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution', regex: true },
            { fn: 'ProcessBuilder', cat: 'RCE', sev: 'CRITICAL', desc: 'Command execution' },
            { fn: 'ObjectInputStream', cat: 'DESER', sev: 'CRITICAL', desc: 'Insecure deserialization' },
            { fn: 'readObject', cat: 'DESER', sev: 'CRITICAL', desc: 'Deserialization' },
            { fn: 'XMLDecoder', cat: 'DESER', sev: 'CRITICAL', desc: 'XML deserialization' },
            { fn: 'ScriptEngine', cat: 'RCE', sev: 'HIGH', desc: 'Script execution' },
            { fn: 'executeQuery.*\\+', cat: 'SQLi', sev: 'CRITICAL', desc: 'SQL concatenation', regex: true },
            { fn: 'createQuery.*\\+', cat: 'SQLi', sev: 'CRITICAL', desc: 'HQL injection', regex: true },
            { fn: 'getParameter', cat: 'INPUT', sev: 'INFO', desc: 'User input' },
            { fn: 'getHeader', cat: 'INPUT', sev: 'INFO', desc: 'Header input' },
            { fn: 'File\\(.*request', cat: 'PATH', sev: 'HIGH', desc: 'Path traversal', regex: true },
            { fn: 'XXE', cat: 'XXE', sev: 'HIGH', desc: 'XML External Entity' }
        ]
    },

    sevColors: { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', INFO: '#3b82f6' },

    sampleCode: {
        php: `<?php
// Example vulnerable PHP code
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);

// Command injection
$file = $_POST['filename'];
system("cat " . $file);

// LFI vulnerability
$page = $_GET['page'];
include($page . ".php");

// XSS vulnerability
echo "Hello, " . $_GET['name'];

// Insecure deserialization
$obj = unserialize($_COOKIE['data']);
?>`,
        python: `# Example vulnerable Python code
from flask import Flask, request, render_template_string
import os, pickle

app = Flask(__name__)

@app.route('/cmd')
def cmd():
    # Command injection
    cmd = request.args.get('cmd')
    os.system(cmd)
    
@app.route('/ssti')
def ssti():
    # Server-Side Template Injection
    name = request.args.get('name')
    return render_template_string(f"Hello {name}")
    
@app.route('/deser')
def deser():
    # Insecure deserialization
    data = request.args.get('data')
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)
    
@app.route('/sqli')
def sqli():
    # SQL Injection
    user = request.args.get('user')
    query = "SELECT * FROM users WHERE name = '%s'" % user
    cursor.execute(query)`,
        javascript: `// Example vulnerable Node.js code
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/exec', (req, res) => {
    // Command injection
    const cmd = req.query.cmd;
    exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/xss', (req, res) => {
    // XSS vulnerability
    const name = req.query.name;
    res.send(\`<h1>Hello \${name}</h1>\`);
});

app.get('/eval', (req, res) => {
    // Code injection
    const code = req.query.code;
    eval(code);
});

// DOM XSS in client
document.getElementById('output').innerHTML = userInput;`
    },

    render() {
        const s = this.state;
        return `
        <div class="crd fade-in">
            <div class="crd-h"><h1>🔍 Source Code Review Dojo</h1><p>Static Analysis & Vulnerability Hunting</p></div>
            <div class="crd-tabs">
                <button class="${s.tab === 'analyzer' ? 'act' : ''}" onclick="CodeReviewDojo.tab('analyzer')">📝 Analyzer</button>
                <button class="${s.tab === 'patterns' ? 'act' : ''}" onclick="CodeReviewDojo.tab('patterns')">📋 Patterns</button>
                <button class="${s.tab === 'practice' ? 'act' : ''}" onclick="CodeReviewDojo.tab('practice')">🎯 Practice</button>
            </div>
            <div class="crd-body">${this.renderTab()}</div>
        </div>
        <style>
        .crd{min-height:100vh;background:linear-gradient(135deg,#0a0a12,#1a1a2e);color:#e0e0e0;padding:20px;font-family:system-ui}
        .crd-h h1{margin:0;color:#3b82f6;font-size:1.8rem}.crd-h p{color:#888;margin:5px 0 20px}
        .crd-tabs{display:flex;gap:10px;margin-bottom:20px}.crd-tabs button{padding:12px 24px;background:rgba(255,255,255,.05);border:1px solid #333;border-radius:8px;color:#888;cursor:pointer;transition:.2s}
        .crd-tabs button:hover{color:#fff;border-color:#3b82f6}.crd-tabs button.act{background:#3b82f6;color:#fff;border-color:#3b82f6}
        .crd-grid{display:grid;grid-template-columns:1fr 350px;gap:20px}
        .crd-code{background:rgba(0,0,0,.4);border-radius:12px;overflow:hidden}
        .crd-code-header{padding:15px 20px;background:rgba(0,0,0,.3);display:flex;justify-content:space-between;align-items:center}
        .crd-code-header h3{margin:0;color:#3b82f6}
        .crd-code-header select{padding:8px 15px;background:#0a0a12;border:1px solid #333;border-radius:6px;color:#fff}
        .crd-code-body{padding:20px;max-height:500px;overflow:auto}
        .crd-code-body pre{margin:0;font-size:.9rem;line-height:1.6}
        .crd-code-body textarea{width:100%;height:400px;background:transparent;border:none;color:#e0e0e0;font-family:monospace;font-size:.9rem;resize:none;outline:none}
        .crd-findings{background:rgba(0,0,0,.4);padding:20px;border-radius:12px}
        .crd-findings h3{margin:0 0 15px;color:#ef4444}
        .finding-list{display:flex;flex-direction:column;gap:8px;max-height:450px;overflow-y:auto}
        .finding{padding:12px;background:#0a0a12;border-radius:8px;border-left:3px solid;cursor:pointer;transition:.2s}
        .finding:hover{transform:translateX(3px)}
        .finding-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
        .finding-fn{font-weight:bold;color:#fff}.finding-cat{padding:2px 8px;border-radius:4px;font-size:.75rem;background:rgba(255,255,255,.1)}
        .finding-desc{color:#888;font-size:.85rem}.finding-line{color:#666;font-size:.8rem}
        .sev-CRITICAL{border-color:#ef4444;}.sev-HIGH{border-color:#f97316;}.sev-MEDIUM{border-color:#eab308;}.sev-LOW{border-color:#22c55e;}.sev-INFO{border-color:#3b82f6;}
        .hl-CRITICAL{background:rgba(239,68,68,.3);color:#fca5a5}.hl-HIGH{background:rgba(249,115,22,.3);color:#fdba74}.hl-MEDIUM{background:rgba(234,179,8,.3);color:#fde047}.hl-LOW{background:rgba(34,197,94,.3);color:#86efac}.hl-INFO{background:rgba(59,130,246,.3);color:#93c5fd}
        .crd-actions{margin-top:15px;display:flex;gap:10px;flex-wrap:wrap}
        .crd-actions button{padding:10px 15px;background:rgba(59,130,246,.2);border:1px solid #3b82f6;border-radius:8px;color:#60a5fa;cursor:pointer}
        .crd-stats{display:flex;gap:15px;margin-bottom:20px;flex-wrap:wrap}
        .stat{padding:15px 20px;background:rgba(0,0,0,.4);border-radius:10px;text-align:center;min-width:100px}
        .stat-num{font-size:1.8rem;font-weight:bold;display:block}.stat-label{color:#888;font-size:.85rem}
        .patterns-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:15px}
        .pattern-card{background:rgba(0,0,0,.4);padding:15px;border-radius:10px;border-left:3px solid}
        .pattern-card h5{margin:0 0 8px;color:#fff}.pattern-card p{margin:0;color:#888;font-size:.85rem}
        .pattern-card code{display:inline-block;margin-top:8px;padding:4px 8px;background:#0a0a12;border-radius:4px;color:#22c55e;font-size:.85rem}
        .practice-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:15px}
        .practice-card{background:rgba(0,0,0,.4);padding:20px;border-radius:12px;cursor:pointer;transition:.2s;border:1px solid #333}
        .practice-card:hover{border-color:#3b82f6;transform:translateY(-3px)}
        .practice-card h4{margin:0 0 10px;color:#3b82f6}.practice-card p{margin:0;color:#888;font-size:.9rem}
        @media(max-width:900px){.crd-grid{grid-template-columns:1fr}}
        </style>`;
    },

    renderTab() {
        switch (this.state.tab) {
            case 'analyzer': return this.renderAnalyzer();
            case 'patterns': return this.renderPatterns();
            case 'practice': return this.renderPractice();
        }
    },

    renderAnalyzer() {
        const s = this.state;
        const stats = this.getStats();
        return `
            <div class="crd-stats">
                <div class="stat"><span class="stat-num" style="color:#ef4444">${stats.critical}</span><span class="stat-label">Critical</span></div>
                <div class="stat"><span class="stat-num" style="color:#f97316">${stats.high}</span><span class="stat-label">High</span></div>
                <div class="stat"><span class="stat-num" style="color:#eab308">${stats.medium}</span><span class="stat-label">Medium</span></div>
                <div class="stat"><span class="stat-num" style="color:#22c55e">${stats.low}</span><span class="stat-label">Low</span></div>
                <div class="stat"><span class="stat-num" style="color:#3b82f6">${stats.info}</span><span class="stat-label">Info</span></div>
            </div>
            <div class="crd-grid">
                <div class="crd-code">
                    <div class="crd-code-header">
                        <h3>📝 Source Code</h3>
                        <select id="crd-lang" onchange="CodeReviewDojo.setLang(this.value)">
                            <option value="php" ${s.lang === 'php' ? 'selected' : ''}>PHP</option>
                            <option value="python" ${s.lang === 'python' ? 'selected' : ''}>Python</option>
                            <option value="javascript" ${s.lang === 'javascript' ? 'selected' : ''}>JavaScript</option>
                            <option value="java" ${s.lang === 'java' ? 'selected' : ''}>Java</option>
                        </select>
                    </div>
                    <div class="crd-code-body"><textarea id="crd-input" placeholder="Paste code here..." onkeyup="CodeReviewDojo.analyze()">${s.code}</textarea></div>
                    <div class="crd-actions" style="padding:0 20px 20px">
                        <button onclick="CodeReviewDojo.analyze()">🔍 Analyze</button>
                        <button onclick="CodeReviewDojo.loadSample()">📂 Load Sample</button>
                        <button onclick="CodeReviewDojo.aiReview()">🤖 AI Deep Review</button>
                        <button onclick="CodeReviewDojo.exportReport()">📋 Export</button>
                    </div>
                </div>
                <div class="crd-findings">
                    <h3>⚠️ Findings (${s.findings.length})</h3>
                    <div class="finding-list">${s.findings.length === 0 ? '<p style="color:#666">No vulnerabilities found yet. Paste code and analyze.</p>' : s.findings.map((f, i) => `
                        <div class="finding sev-${f.sev}" onclick="CodeReviewDojo.highlight(${i})">
                            <div class="finding-header">
                                <span class="finding-fn">${f.fn}</span>
                                <span class="finding-cat">${f.cat}</span>
                            </div>
                            <div class="finding-desc">${f.desc}</div>
                            <div class="finding-line">Line ${f.line}</div>
                        </div>
                    `).join('')}</div>
                </div>
            </div>`;
    },

    renderPatterns() {
        return `
            <div class="patterns-section">
                <h3 style="color:#3b82f6;margin:0 0 20px">📋 Dangerous Patterns Reference</h3>
                ${Object.entries(this.patterns).map(([lang, patterns]) => `
                    <h4 style="color:#888;margin:20px 0 15px">${lang.toUpperCase()}</h4>
                    <div class="patterns-grid">${patterns.slice(0, 12).map(p => `
                        <div class="pattern-card sev-${p.sev}">
                            <h5>${p.fn}</h5>
                            <p>${p.desc}</p>
                            <span style="color:${this.sevColors[p.sev]};font-size:.8rem">${p.sev}</span> • <span style="color:#888;font-size:.8rem">${p.cat}</span>
                        </div>
                    `).join('')}</div>
                `).join('')}
            </div>`;
    },

    renderPractice() {
        return `
            <div class="practice-section">
                <h3 style="color:#3b82f6;margin:0 0 20px">🎯 Practice Vulnerable Code Review</h3>
                <div class="practice-grid">
                    <div class="practice-card" onclick="CodeReviewDojo.loadPractice('php')">
                        <h4>🐘 PHP Vulnerabilities</h4>
                        <p>SQLi, RCE, LFI, XSS, Deserialization</p>
                    </div>
                    <div class="practice-card" onclick="CodeReviewDojo.loadPractice('python')">
                        <h4>🐍 Python Vulnerabilities</h4>
                        <p>SSTI, RCE, Pickle Deserialization, SQLi</p>
                    </div>
                    <div class="practice-card" onclick="CodeReviewDojo.loadPractice('javascript')">
                        <h4>📜 JavaScript Vulnerabilities</h4>
                        <p>XSS, DOM-based, Prototype Pollution, RCE</p>
                    </div>
                </div>
            </div>`;
    },

    analyze() {
        const code = document.getElementById('crd-input')?.value || '';
        this.state.code = code;
        this.state.findings = [];

        if (!code.trim()) return;

        const lines = code.split('\n');
        const patterns = this.patterns[this.state.lang] || [];

        lines.forEach((line, lineNum) => {
            patterns.forEach(p => {
                const regex = p.regex ? new RegExp(p.fn, 'gi') : new RegExp(p.fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
                if (regex.test(line)) {
                    this.state.findings.push({
                        fn: p.fn.replace(/\\\\/g, ''),
                        cat: p.cat,
                        sev: p.sev,
                        desc: p.desc,
                        line: lineNum + 1,
                        content: line.trim()
                    });
                }
            });
        });

        // Sort by severity
        const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        this.state.findings.sort((a, b) => sevOrder[a.sev] - sevOrder[b.sev]);

        this.rr();
    },

    getStats() {
        const f = this.state.findings;
        return {
            critical: f.filter(x => x.sev === 'CRITICAL').length,
            high: f.filter(x => x.sev === 'HIGH').length,
            medium: f.filter(x => x.sev === 'MEDIUM').length,
            low: f.filter(x => x.sev === 'LOW').length,
            info: f.filter(x => x.sev === 'INFO').length
        };
    },

    setLang(lang) { this.state.lang = lang; this.analyze(); },
    loadSample() { this.state.code = this.sampleCode[this.state.lang] || ''; document.getElementById('crd-input').value = this.state.code; this.analyze(); },
    loadPractice(lang) { this.state.lang = lang; this.state.tab = 'analyzer'; this.loadSample(); },

    highlight(index) {
        const f = this.state.findings[index];
        const textarea = document.getElementById('crd-input');
        const lines = this.state.code.split('\n');
        const lineStart = lines.slice(0, f.line - 1).join('\n').length + (f.line > 1 ? 1 : 0);
        const lineEnd = lineStart + lines[f.line - 1].length;
        textarea.focus();
        textarea.setSelectionRange(lineStart, lineEnd);
        alert(`Line ${f.line}: ${f.fn}\n\n${f.desc}\n\nCategory: ${f.cat}\nSeverity: ${f.sev}`);
    },

    aiReview() {
        if (!this.state.code) { alert('Please paste code first'); return; }
        if (window.AISecurityAssistant) {
            const prompt = `Perform a security code review on this ${this.state.lang} code. Identify all vulnerabilities, explain the security impact, and provide remediation:\n\n\`\`\`${this.state.lang}\n${this.state.code.substring(0, 2000)}\n\`\`\``;
            AISecurityAssistant.toggle();
            setTimeout(() => { document.getElementById('ai-input').value = prompt; AISecurityAssistant.send(); }, 300);
        }
    },

    exportReport() {
        const s = this.state;
        const stats = this.getStats();
        let report = `# Source Code Security Review\n\n## Summary\n- Critical: ${stats.critical}\n- High: ${stats.high}\n- Medium: ${stats.medium}\n- Low: ${stats.low}\n\n## Findings\n\n`;
        s.findings.forEach((f, i) => {
            report += `### ${i + 1}. ${f.fn} (${f.sev})\n- **Category:** ${f.cat}\n- **Line:** ${f.line}\n- **Description:** ${f.desc}\n- **Code:** \`${f.content}\`\n\n`;
        });
        const blob = new Blob([report], { type: 'text/markdown' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'code_review_report.md'; a.click();
    },

    tab(t) { this.state.tab = t; this.rr(); },
    rr() { const app = document.querySelector('.crd'); if (app) app.outerHTML = this.render(); }
};

function pageCodeReview() { return CodeReviewDojo.render(); }
