/* ==================== API HACKING LAB (OWASP API TOP 10) 🔐📡 ==================== */

window.APILab = {
    // --- STATE ---
    activeTab: 'tester',
    requestMethod: 'GET',
    requestUrl: '/api/users/1',
    requestHeaders: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTcwNDMyNjQwMH0.FAKESIGNATURE',
    requestBody: '',

    // Mock API Database
    mockDB: {
        users: [
            { id: 1, name: 'Alice', email: 'alice@target.com', role: 'user' },
            { id: 2, name: 'Bob', email: 'bob@target.com', role: 'user' },
            { id: 3, name: 'Admin', email: 'admin@target.com', role: 'admin', ssn: '123-45-6789' }
        ],
        orders: [
            { id: 101, userId: 1, product: 'Laptop', total: 1200 },
            { id: 102, userId: 2, product: 'Phone', total: 800 },
            { id: 103, userId: 3, product: 'Server', total: 5000 }
        ]
    },

    // --- INIT ---
    init() {
        this.render();
    },

    // --- RENDER UI ---
    render() {
        return `
            <div class="api-app fade-in">
                <!-- TABS -->
                <div class="api-tabs">
                    <div class="tab ${this.activeTab === 'tester' ? 'active' : ''}" onclick="APILab.switchTab('tester')">
                        <i class="fas fa-paper-plane"></i> API Tester
                    </div>
                    <div class="tab ${this.activeTab === 'jwt' ? 'active' : ''}" onclick="APILab.switchTab('jwt')">
                        <i class="fas fa-key"></i> JWT Decoder
                    </div>
                    <div class="tab ${this.activeTab === 'graphql' ? 'active' : ''}" onclick="APILab.switchTab('graphql')">
                        <i class="fas fa-project-diagram"></i> GraphQL
                    </div>
                    <div class="tab ${this.activeTab === 'scenarios' ? 'active' : ''}" onclick="APILab.switchTab('scenarios')">
                        <i class="fas fa-bug"></i> Vuln Scenarios
                    </div>
                </div>

                <!-- CONTENT -->
                <div class="api-content" id="api-content">
                    ${this.renderCurrentTab()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderCurrentTab() {
        switch (this.activeTab) {
            case 'tester': return this.renderTester();
            case 'jwt': return this.renderJWT();
            case 'graphql': return this.renderGraphQL();
            case 'scenarios': return this.renderScenarios();
            default: return this.renderTester();
        }
    },

    // --- API TESTER ---
    renderTester() {
        return `
            <div class="tester-panel">
                <div class="request-bar">
                    <select id="req-method" onchange="APILab.requestMethod=this.value">
                        <option value="GET" ${this.requestMethod === 'GET' ? 'selected' : ''}>GET</option>
                        <option value="POST" ${this.requestMethod === 'POST' ? 'selected' : ''}>POST</option>
                        <option value="PUT" ${this.requestMethod === 'PUT' ? 'selected' : ''}>PUT</option>
                        <option value="DELETE" ${this.requestMethod === 'DELETE' ? 'selected' : ''}>DELETE</option>
                    </select>
                    <input type="text" id="req-url" value="${this.requestUrl}" placeholder="/api/..." onchange="APILab.requestUrl=this.value">
                    <button class="btn-send" onclick="APILab.sendRequest()"><i class="fas fa-bolt"></i> Send</button>
                </div>

                <div class="req-sections">
                    <div class="section">
                        <h4>Headers</h4>
                        <textarea id="req-headers" placeholder="Authorization: Bearer ...">${this.requestHeaders}</textarea>
                    </div>
                    <div class="section">
                        <h4>Body (JSON)</h4>
                        <textarea id="req-body" placeholder='{"key": "value"}'>${this.requestBody}</textarea>
                    </div>
                </div>

                <div class="response-panel">
                    <h4>Response</h4>
                    <pre id="api-response">// Click "Send" to see response</pre>
                </div>
            </div>
        `;
    },

    sendRequest() {
        const url = document.getElementById('req-url').value;
        const method = document.getElementById('req-method').value;
        const headers = document.getElementById('req-headers').value;
        const resPanel = document.getElementById('api-response');

        // Parse JWT from headers
        const authMatch = headers.match(/Bearer\s+([\w.-]+)/i);
        let userRole = 'guest';
        let userId = null;

        if (authMatch) {
            try {
                const payload = JSON.parse(atob(authMatch[1].split('.')[1]));
                userRole = payload.role || 'user';
                userId = payload.userId;
            } catch (e) { /* Invalid JWT */ }
        }

        // Mock API Logic
        let response = { status: 404, body: { error: 'Not Found' } };

        // /api/users/:id
        const userMatch = url.match(/\/api\/users\/(\d+)/);
        if (userMatch) {
            const id = parseInt(userMatch[1]);
            const user = this.mockDB.users.find(u => u.id === id);
            if (user) {
                // IDOR Check: Can guest access admin?
                if (user.role === 'admin' && userRole !== 'admin') {
                    // Vulnerable! Returns admin data
                    response = { status: 200, body: { ...user, flag: '🚩 IDOR: Accessed Admin Data!' } };
                } else {
                    response = { status: 200, body: user };
                }
            }
        }

        // /api/orders/:id
        const orderMatch = url.match(/\/api\/orders\/(\d+)/);
        if (orderMatch) {
            const id = parseInt(orderMatch[1]);
            const order = this.mockDB.orders.find(o => o.id === id);
            if (order) {
                // BOLA: User accessing other user's orders
                if (userId && order.userId !== userId) {
                    response = { status: 200, body: { ...order, flag: '🚩 BOLA: Accessed Another Users Order!' } };
                } else {
                    response = { status: 200, body: order };
                }
            }
        }

        // /api/admin
        if (url.includes('/api/admin')) {
            if (userRole === 'admin') {
                response = { status: 200, body: { message: 'Welcome Admin!', secret: 'FLAG{admin_access}' } };
            } else {
                response = { status: 403, body: { error: 'Forbidden' } };
            }
        }

        resPanel.innerHTML = '// ' + method + ' ' + url + '\n// Status: ' + response.status + '\n\n' + JSON.stringify(response.body, null, 2);
    },

    // --- JWT DECODER ---
    renderJWT() {
        const sampleJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTcwNDMyNjQwMH0.FAKESIGNATURE';
        return `
            <div class="jwt-panel">
                <h2>JWT Token Analyzer</h2>
                <div class="jwt-input">
                    <label>Paste JWT Token:</label>
                    <textarea id="jwt-token" onkeyup="APILab.decodeJWT()">${sampleJWT}</textarea>
                </div>
                <div class="jwt-output">
                    <div class="jwt-section header">
                        <h4>Header</h4>
                        <pre id="jwt-header">{"alg": "HS256", "typ": "JWT"}</pre>
                    </div>
                    <div class="jwt-section payload">
                        <h4>Payload (EDITABLE)</h4>
                        <textarea id="jwt-payload">{"user": "guest", "role": "user", "iat": 1704326400}</textarea>
                    </div>
                    <div class="jwt-section signature">
                        <h4>Signature</h4>
                        <pre id="jwt-sig">FAKESIGNATURE</pre>
                    </div>
                </div>
                <div class="jwt-actions">
                    <button class="btn-action" onclick="APILab.forgeJWT()"><i class="fas fa-edit"></i> Forge Token (Change Role to Admin)</button>
                    <button class="btn-action warn" onclick="APILab.algoNone()"><i class="fas fa-skull"></i> Algorithm: None Attack</button>
                </div>
                <div id="jwt-forged" class="forged-output"></div>
            </div>
        `;
    },

    decodeJWT() {
        const token = document.getElementById('jwt-token').value;
        const parts = token.split('.');
        if (parts.length !== 3) return;

        try {
            document.getElementById('jwt-header').textContent = JSON.stringify(JSON.parse(atob(parts[0])), null, 2);
            document.getElementById('jwt-payload').value = JSON.stringify(JSON.parse(atob(parts[1])), null, 2);
            document.getElementById('jwt-sig').textContent = parts[2];
        } catch (e) { /* Invalid */ }
    },

    forgeJWT() {
        const payload = JSON.parse(document.getElementById('jwt-payload').value);
        payload.role = 'admin';
        payload.user = 'attacker';

        const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
        const newPayload = btoa(JSON.stringify(payload));
        const forgedToken = header + '.' + newPayload + '.FORGED_SIGNATURE';

        document.getElementById('jwt-forged').innerHTML = '<h4>🚩 Forged Token:</h4><code>' + forgedToken + '</code><p class="hint">Use this in the API Tester Authorization header!</p>';
    },

    algoNone() {
        const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
        const payload = btoa(JSON.stringify({ user: 'attacker', role: 'admin' }));
        const forgedToken = header + '.' + payload + '.';

        document.getElementById('jwt-forged').innerHTML = '<h4>🚩 Algorithm None Attack Token:</h4><code>' + forgedToken + '</code><p class="hint">This bypasses signature verification on vulnerable servers!</p>';
    },

    // --- GRAPHQL ---
    renderGraphQL() {
        return `
            <div class="graphql-panel">
                <h2>GraphQL Console</h2>
                <div class="gql-grid">
                    <div class="gql-query">
                        <h4>Query</h4>
                        <textarea id="gql-input">{ __schema { types { name } } }</textarea>
                        <button class="btn-send" onclick="APILab.runGraphQL()"><i class="fas fa-play"></i> Execute</button>
                    </div>
                    <div class="gql-result">
                        <h4>Result</h4>
                        <pre id="gql-output">// Run introspection to discover schema</pre>
                    </div>
                </div>
                <div class="gql-hints">
                    <h4>Common Attacks:</h4>
                    <button onclick="APILab.setGQLQuery('introspection')">Full Introspection</button>
                    <button onclick="APILab.setGQLQuery('users')">Dump All Users</button>
                    <button onclick="APILab.setGQLQuery('mutation')">Password Reset Mutation</button>
                </div>
            </div>
        `;
    },

    setGQLQuery(type) {
        const queries = {
            introspection: '{\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types {\n      name\n      fields { name type { name } }\n    }\n  }\n}',
            users: '{\n  users {\n    id\n    email\n    role\n    ssn\n  }\n}',
            mutation: 'mutation {\n  resetPassword(email: "admin@target.com") {\n    success\n    tempPassword\n  }\n}'
        };
        document.getElementById('gql-input').value = queries[type];
    },

    runGraphQL() {
        const query = document.getElementById('gql-input').value;
        const output = document.getElementById('gql-output');

        // Mock responses
        if (query.includes('__schema')) {
            output.textContent = JSON.stringify({
                data: {
                    __schema: {
                        types: [
                            { name: 'User', fields: ['id', 'name', 'email', 'role', 'ssn'] },
                            { name: 'Order', fields: ['id', 'userId', 'product', 'total'] },
                            { name: 'Mutation', fields: ['resetPassword', 'deleteUser'] }
                        ]
                    },
                    flag: '🚩 Introspection should be disabled in production!'
                }
            }, null, 2);
        } else if (query.includes('users')) {
            output.textContent = JSON.stringify({
                data: { users: this.mockDB.users },
                flag: '🚩 Sensitive data (SSN) exposed via API!'
            }, null, 2);
        } else if (query.includes('resetPassword')) {
            output.textContent = JSON.stringify({
                data: { resetPassword: { success: true, tempPassword: 'P@ssw0rd123' } },
                flag: '🚩 Password reset without proper authorization!'
            }, null, 2);
        }
    },

    // --- VULN SCENARIOS ---
    renderScenarios() {
        return `
            <div class="scenarios-panel">
                <h2>OWASP API Top 10 Scenarios</h2>
                <div class="scenario-grid">
                    <div class="scenario-card" onclick="APILab.runScenario('bola')">
                        <div class="s-icon"><i class="fas fa-user-secret"></i></div>
                        <h4>API1: BOLA</h4>
                        <p>Broken Object Level Authorization</p>
                    </div>
                    <div class="scenario-card" onclick="APILab.runScenario('auth')">
                        <div class="s-icon"><i class="fas fa-lock-open"></i></div>
                        <h4>API2: Broken Auth</h4>
                        <p>Weak authentication mechanisms</p>
                    </div>
                    <div class="scenario-card" onclick="APILab.runScenario('excessive')">
                        <div class="s-icon"><i class="fas fa-database"></i></div>
                        <h4>API3: Excessive Data</h4>
                        <p>API returns more data than needed</p>
                    </div>
                    <div class="scenario-card" onclick="APILab.runScenario('massassign')">
                        <div class="s-icon"><i class="fas fa-edit"></i></div>
                        <h4>API6: Mass Assignment</h4>
                        <p>Modifying fields you should not</p>
                    </div>
                </div>
                <div id="scenario-result" class="scenario-result"></div>
            </div>
        `;
    },

    runScenario(type) {
        const result = document.getElementById('scenario-result');
        const adminUser = JSON.stringify(this.mockDB.users[2], null, 2);
        const allUsers = JSON.stringify(this.mockDB.users, null, 2);

        const scenarios = {
            bola: '<h3>🔓 BOLA Exploit</h3><p>Request: GET /api/users/3 (Admin ID)</p><pre>' + adminUser + '</pre><p class="flag">🚩 FLAG{bola_accessed_admin}</p>',
            auth: '<h3>🔓 Broken Authentication</h3><p>JWT with alg:none accepted!</p><pre>Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.</pre><p class="flag">🚩 FLAG{alg_none_ftw}</p>',
            excessive: '<h3>🔓 Excessive Data Exposure</h3><p>GET /api/users returns SSN!</p><pre>' + allUsers + '</pre><p class="flag">🚩 FLAG{ssn_leaked}</p>',
            massassign: '<h3>🔓 Mass Assignment</h3><p>PUT /api/users/1 with {"role":"admin"}</p><pre>{ "id": 1, "name": "Alice", "role": "admin" }</pre><p class="flag">🚩 FLAG{mass_assign_privesc}</p>'
        };
        result.innerHTML = scenarios[type];
    },

    switchTab(tab) {
        this.activeTab = tab;
        document.getElementById('api-content').innerHTML = this.renderCurrentTab();
    },

    getStyles() {
        return `
        <style>
            .api-app { display: flex; flex-direction: column; height: calc(100vh - 60px); background: #1e1e2e; color: #cdd6f4; font-family: 'JetBrains Mono', monospace; }
            
            /* TABS */
            .api-tabs { display: flex; background: #181825; border-bottom: 2px solid #313244; }
            .tab { padding: 15px 25px; cursor: pointer; color: #6c7086; transition: 0.2s; display: flex; gap: 8px; align-items: center; }
            .tab:hover { background: #313244; color: #cdd6f4; }
            .tab.active { background: #1e1e2e; color: #89b4fa; border-bottom: 2px solid #89b4fa; margin-bottom: -2px; }

            /* CONTENT */
            .api-content { flex: 1; padding: 30px; overflow-y: auto; }
            
            /* TESTER */
            .request-bar { display: flex; gap: 10px; margin-bottom: 20px; }
            .request-bar select { padding: 10px; background: #313244; color: #f38ba8; border: none; border-radius: 6px; font-weight: bold; }
            .request-bar input { flex: 1; padding: 10px 15px; background: #313244; border: none; border-radius: 6px; color: #cdd6f4; font-family: inherit; }
            .btn-send { background: #a6e3a1; color: #1e1e2e; padding: 10px 20px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
            .btn-send:hover { background: #94e2d5; }
            
            .req-sections { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
            .section h4 { margin: 0 0 10px; color: #89b4fa; }
            .section textarea { width: 100%; height: 100px; background: #313244; border: 1px solid #45475a; color: #cdd6f4; padding: 10px; border-radius: 6px; font-family: inherit; resize: none; }
            
            .response-panel { background: #181825; border: 1px solid #313244; border-radius: 6px; padding: 20px; }
            .response-panel h4 { margin: 0 0 10px; color: #a6e3a1; }
            .response-panel pre { background: #11111b; padding: 15px; border-radius: 6px; overflow-x: auto; color: #fab387; }

            /* JWT */
            .jwt-panel h2 { color: #f9e2af; margin-bottom: 20px; }
            .jwt-input textarea { width: 100%; height: 80px; background: #313244; border: 1px solid #45475a; color: #89b4fa; padding: 10px; border-radius: 6px; font-family: inherit; margin-bottom: 20px; }
            
            .jwt-output { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
            .jwt-section { background: #313244; padding: 15px; border-radius: 6px; }
            .jwt-section.header { border-top: 3px solid #f38ba8; }
            .jwt-section.payload { border-top: 3px solid #a6e3a1; }
            .jwt-section.signature { border-top: 3px solid #89b4fa; }
            .jwt-section h4 { margin: 0 0 10px; font-size: 0.9rem; }
            .jwt-section pre, .jwt-section textarea { background: #181825; padding: 10px; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; width: 100%; border: none; color: #cdd6f4; min-height: 80px; }
            
            .jwt-actions { display: flex; gap: 10px; }
            .btn-action { background: #89b4fa; color: #1e1e2e; padding: 10px 20px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
            .btn-action.warn { background: #f38ba8; }
            
            .forged-output { margin-top: 20px; background: #181825; padding: 20px; border-radius: 6px; border-left: 4px solid #f9e2af; }
            .forged-output code { display: block; word-break: break-all; color: #fab387; margin: 10px 0; }
            .hint { color: #6c7086; font-size: 0.9rem; }

            /* GRAPHQL */
            .gql-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
            .gql-query textarea { width: 100%; height: 200px; background: #313244; border: 1px solid #45475a; color: #cdd6f4; padding: 10px; border-radius: 6px; font-family: inherit; }
            .gql-result pre { background: #181825; padding: 15px; border-radius: 6px; height: 200px; overflow: auto; color: #a6e3a1; }
            .gql-hints button { background: #45475a; color: #cdd6f4; border: none; padding: 8px 15px; border-radius: 4px; margin-right: 10px; cursor: pointer; }
            .gql-hints button:hover { background: #585b70; }

            /* SCENARIOS */
            .scenario-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
            .scenario-card { background: #313244; padding: 25px; border-radius: 10px; text-align: center; cursor: pointer; transition: 0.2s; border: 2px solid transparent; }
            .scenario-card:hover { border-color: #89b4fa; transform: translateY(-5px); }
            .s-icon { font-size: 2.5rem; color: #f38ba8; margin-bottom: 15px; }
            .scenario-card h4 { margin: 0 0 5px; color: #cdd6f4; }
            .scenario-card p { margin: 0; color: #6c7086; font-size: 0.8rem; }
            
            .scenario-result { background: #181825; padding: 20px; border-radius: 10px; border-left: 4px solid #a6e3a1; }
            .flag { color: #f9e2af; font-weight: bold; margin-top: 15px; }
        </style>
        `;
    }
};

function pageAPILab() {
    APILab.init();
    return APILab.render();
}
