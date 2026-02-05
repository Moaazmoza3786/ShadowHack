/* ============================================================
   OWASP CYBER RANGE (ELITE EDITION)
   Study Hub Platform - Professional Threat Simulation
   ============================================================ */

class OWASPEngine {
    constructor() {
        this.currentView = 'dashboard';
        this.activeModuleId = null;
        this.terminalLog = [];
        this.xray = false;

        // --- SCENARIO DATABASE ---
        this.scenarios = {
            'm01': {
                title: 'Broken Access Control',
                theme: 'theme-shop',
                targetUrl: 'https://shop.nexus-corp.com/account?uid=105',
                targetHtml: `
                    <div class="shop-ui">
                        <div class="shop-nav">
                            <span>NEXUS SHOP</span>
                            <span><i class="fas fa-user-circle"></i> ID: 105</span>
                        </div>
                        <div class="shop-card">
                            <div class="shop-avatar"><i class="fas fa-user"></i></div>
                            <h3>Customer Profile</h3>
                            <p><strong>Name:</strong> John Doe</p>
                            <p><strong>Tier:</strong> Bronze</p>
                            <hr>
                            <div class="shop-orders">
                                <p><i class="fas fa-box"></i> Order #9921 - Pending</p>
                                <p><i class="fas fa-box"></i> Order #9918 - Delivered</p>
                            </div>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M01
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">IDOR</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val crit">HIGH (CVSS 7.5)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The target application exposes database keys (User IDs) directly in the URL query parameters without verifying session ownership.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Manipulate the <code>uid</code> parameter to access the Administrator's account (ID: 1).</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Implement Server-Side Ownership Checks.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Profile Controller
const userId = req.query.uid;

// ⚠️ VULNERABILITY DETECTED
// The application does not verify if the
// requester is authorized to view this ID.

const userProfile = db.query(
  "SELECT * FROM users WHERE id = ?", 
  [userId]
);

return res.json(userProfile);`,
                checkSuccess: (input) => input.includes('uid=1') && !input.includes('105'),
                patchKeyword: 'req.session.id'
            },

            'm02': {
                title: 'Cryptographic Failures',
                theme: 'theme-crypto',
                targetUrl: 'https://vault.secure-enclave.io/login',
                targetHtml: `
                    <div class="crypto-ui">
                        <div class="lock-icon"><i class="fas fa-fingerprint"></i></div>
                        <h3>SECURE ENCLAVE</h3>
                        <div class="debug-console">
                            <span class="debug-label">DEBUG_LOG:</span>
                            <span class="debug-val typed-text">auth_token = "c3VwZXJzZWNyZXQ="</span>
                        </div>
                        <input type="password" id="pass-input" placeholder="ENTER MASTER KEY">
                        <button onclick="owaspEngine.runCheck()"><i class="fas fa-unlock"></i> DECRYPT & ACCESS</button>
                    </div>
                `,
                theory: `
                     <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M02
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Crypto Failure</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val med">MEDIUM (CVSS 6.2)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>A dev artifact reveals a "secret" token. The format suggests simple encoding rather than strong encryption.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Decode the Base64 string to recover the plaintext password.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Use strong hashing algorithms (Bcrypt/Argon2).
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Auth Service
const storedSecret = "c3VwZXJzZWNyZXQ="; // Base64

// ⚠️ WEAK CRYPTOGRAPHY
// Base64 is an encoding scheme, not encryption.
// It can be trivially decoded.

if (input === base64Decode(storedSecret)) {
    grantAdminAccess();
}`,
                checkSuccess: (input) => input === 'supersecret',
                patchKeyword: 'bcrypt'
            },

            'm03': {
                title: 'Injection (SQLi)',
                theme: 'theme-admin',
                targetUrl: 'https://admin-intranet.corp/sso',
                targetHtml: `
                    <div class="admin-ui">
                        <div class="admin-header">
                            <i class="fas fa-building"></i> CORP INTRANET
                        </div>
                        <div class="login-panel">
                            <h3>EMPLOYEE SSO</h3>
                            <div class="input-group">
                                <i class="fas fa-user"></i>
                                <input type="text" id="login-user" placeholder="Username" onkeyup="owaspEngine.handleSQLiInput(this.value)">
                            </div>
                            <div class="input-group">
                                <i class="fas fa-key"></i>
                                <input type="password" placeholder="Password">
                            </div>
                            <button onclick="owaspEngine.runCheck()">AUTHENTICATE</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M03
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">SQL Injection</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val crit">CRITICAL (CVSS 9.0)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The authentication interface concatenates user input directly into the SQL command string, allowing for query manipulation.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Inject SQL syntax to alter the query logic and bypass authentication (e.g., <code>' OR 1=1 --</code>).</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Use Prepared Statements (Parameterized Queries).
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Database Adapter
const user = req.body.username;

// ⚠️ VULNERABLE CODE
// Direct concatenation allows SQL injection.
const query = "SELECT * FROM users WHERE user = '" + user + "'";

db.execute(query);`,
                checkSuccess: (input) => (input.includes("' OR '1'='1") || input.includes("' --")),
                patchKeyword: 'PreparedStatement'
            },

            'm04': {
                title: 'Insecure Design',
                theme: 'theme-shop',
                targetUrl: 'https://store.tech-giant.com/checkout',
                targetHtml: `
                    <div class="shop-ui">
                        <div class="cart-header">CHECKOUT - STEP 3/4</div>
                        <div class="cart-item">
                            <div class="item-img"><i class="fas fa-microchip"></i></div>
                            <div class="item-details">
                                <h4>Quantum GPU X90</h4>
                                <p>Price: $4,999.00</p>
                            </div>
                        </div>
                        <div class="coupon-area">
                            <label>Apply Discount Code:</label>
                            <input type="text" id="discount-input" placeholder="Promotional Code">
                            <button onclick="owaspEngine.runCheck()">APPLY</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M04
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Business Logic</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val high">HIGH (CVSS 7.1)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>A "Developer Backdoor" was left in the payment logic to facilitate testing. It allows a specific code to bypass payment.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Identify the hardcoded developer coupon in the source code and use it to get a 100% discount.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Separate Test/Prod Logic; Code Reviews.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Price Calculator
let total = cart.sum();

// ⚠️ BUSINESS LOGIC FLAW
// This backdoor should not exist in production.
if (couponCode === 'DEV_100_OFF') {
    total = 0; 
}

return processPayment(total);`,
                checkSuccess: (input) => input === 'DEV_100_OFF',
                patchKeyword: 'const coupons ='
            },

            'm05': {
                title: 'Security Misconfiguration',
                theme: 'theme-admin',
                targetUrl: 'http://legacy-app.local:8080/manager/html',
                targetHtml: `
                    <div class="tomcat-ui">
                        <div class="tomcat-head">
                            <span class="t-logo">Apache Tomcat/9.0.0</span>
                        </div>
                        <div class="tomcat-body">
                            <h3>Tomcat Web Application Manager</h3>
                            <p class="warn">Authentication Required</p>
                            <div class="t-form">
                                <label>Username:</label>
                                <input type="text" id="m05-user">
                                <label>Password:</label>
                                <input type="password" id="m05-pass">
                                <button onclick="owaspEngine.runCheck()">Log In</button>
                            </div>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M05
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Default Creds</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val high">HIGH (CVSS 8.8)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The application server was deployed using default vendor configurations. Many default accounts are well-known to attackers.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Log in to the Manager App using the standard Tomcat default credentials.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Hardening Process; Disable default accounts.
                            </div>
                        </div>
                    </div>
                `,
                code: `<!-- CONFIG: tomcat-users.xml -->
<tomcat-users>
  <!-- ⚠️ CONFIGURATION ERROR -->
  <!-- Default credentials enabled -->
  <user username="tomcat" password="s3cret" roles="manager-gui"/>
</tomcat-users>`,
                checkSuccess: (input) => input === 'tomcat:s3cret',
                patchKeyword: 'scrypt'
            },

            'm06': {
                title: 'Vuln & Outdated Components',
                theme: 'theme-retro',
                targetUrl: 'minecraft://survival.server.net:25565',
                targetHtml: `
                    <div class="retro-ui">
                        <div class="mc-logo">MINECRAFT SERVER</div>
                        <div class="mc-status">STATUS: ONLINE (12/100)</div>
                        <div class="mc-form">
                            <label>USERNAME:</label>
                            <input type="text" id="m06-input" placeholder="Steve">
                            <button onclick="owaspEngine.runCheck()">JOIN WORLD</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M06
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Log4Shell</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val crit">CRITICAL (CVSS 10.0)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The server uses a vulnerable version of the Log4j library (CVE-2021-44228). It improperly parses JNDI lookups in log messages.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Achieve RCE by injecting a malicious JNDI string (<code>\${jndi:ldap://...}</code>) into the username field.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Patch libraries; Disable JNDI lookups.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: LoginHandler.java
import org.apache.logging.log4j.Logger;

// ⚠️ CRITICAL COMPONENT BUG (Log4Shell)
// Log4j will execute code inside JNDI strings.
logger.info("Login attempt: " + username);`,
                checkSuccess: (input) => input.includes('${jndi:ldap://'),
                patchKeyword: 'formatMsgNoLookups'
            },

            'm07': {
                title: 'Identification & Auth Failures',
                theme: 'theme-admin',
                targetUrl: 'https://admin-panel.sys/login',
                targetHtml: `
                    <div class="admin-ui dark-mode">
                        <div class="admin-header">SYSTEM ADMINISTRATION</div>
                        <div class="login-panel">
                            <div class="user-display">
                                <i class="fas fa-user-shield"></i> User: <strong>admin</strong>
                            </div>
                            <input type="password" id="m07-pass" placeholder="Password">
                            <button onclick="owaspEngine.runCheck()">VERIFY IDENTITY</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M07
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Weak Auth</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val high">HIGH (CVSS 7.5)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The system allows weak passwords and lacks rate limiting, making it susceptible to credential stuffing and brute-force attacks.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Guess the administrator's password using common weak credentials (e.g., <code>password123</code>, <code>admin</code>).</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> MFA; Strong Password Policy; Rate Limiting.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Auth Logic
const maxAttempts = Infinity; // No Limit
const minLength = 3; // Too Short

// ⚠️ WEAK POLICY
// Allows common passwords without lockout.
if (password === 'password123') {
    return session.create();
}`,
                checkSuccess: (input) => input === 'password123',
                patchKeyword: 'rateLimit'
            },

            'm08': {
                title: 'Software & Data Integrity',
                theme: 'theme-shop',
                targetUrl: 'https://app-v2.cloud/profile',
                targetHtml: `
                    <div class="shop-ui">
                        <div class="shop-nav">CLOUD DASHBOARD</div>
                        <div class="shop-card">
                            <h3>Session Info</h3>
                            <div class="cookie-display">
                                <span class="c-name">COOKIE:</span>
                                <span class="c-val">session_role=user</span>
                            </div>
                            <hr>
                            <label>Modify Cookie (DevTools):</label>
                            <input type="text" id="m08-input" placeholder="New Cookie Value">
                            <button onclick="owaspEngine.runCheck()">REFRESH PAGE</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M08
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Integrity Failure</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val high">HIGH (CVSS 8.1)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The application trusts client-side state (cookies) to define user roles without a cryptographic signature (HMAC).</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Tamper with the cookie value to elevate privileges to 'admin'.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Use Signed JWTs or Server-Side Sessions.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Middleware

// ⚠️ UNVERIFIED INPUT
// The server trusts the cookie content blindly.
const role = req.cookies.session_role;

if (role === 'admin') {
    enableSuperUserMode();
}`,
                checkSuccess: (input) => input === 'session_role=admin',
                patchKeyword: 'JWT'
            },

            'm09': {
                title: 'Security Logging Failures',
                theme: 'theme-bank',
                targetUrl: 'https://bank-portal.finance/transfer',
                targetHtml: `
                    <div class="bank-ui">
                        <div class="bank-head"><i class="fas fa-university"></i> GLOBAL FINANCE</div>
                        <div class="bank-form">
                            <h3>WIRE TRANSFER</h3>
                            <div class="form-row">
                                <label>Amount ($):</label>
                                <input type="number" id="m09-amount" value="5000">
                            </div>
                            <div class="form-row">
                                <label>Recipient:</label>
                                <input type="text" id="m09-account" placeholder="Account Number">
                            </div>
                            <button onclick="owaspEngine.runCheck()">AUTHORIZE TRANSFER</button>
                        </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M09
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">Log Injection</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val med">MEDIUM (CVSS 5.3)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>User input is written directly to logs without sanitizing newline characters. This allows attackers to forge log entries.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Inject a CRLF sequence (<code>%0a</code> or <code>\\n</code>) to create a fake <code>[INFO] Verified</code> log entry.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Sanitize all input before logging.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Transaction Logger
const dest = req.body.account;

// ⚠️ LOG FORGERY RISK
// Attackers can inject new lines to fake logs.
logFile.write(
  "Transfer initiated to: " + dest + "\\n"
);`,
                checkSuccess: (input) => (input.includes('%0a') || input.includes('\\n')),
                patchKeyword: 'sanitize'
            },

            'm10': {
                title: 'SSRF',
                theme: 'theme-bank',
                targetUrl: 'https://bank-portal.finance/tools/proxy',
                targetHtml: `
                    <div class="bank-ui">
                         <div class="bank-head"><i class="fas fa-network-wired"></i> UTILITY PROXY</div>
                         <div class="bank-form">
                            <h3>IMAGE FETCHER</h3>
                            <p class="hint">Fetch remote resources for the intranet.</p>
                            <input type="text" id="url-input" value="http://public-images.com/logo.png">
                            <button onclick="owaspEngine.runCheck()">FETCH RESOURCE</button>
                         </div>
                    </div>
                `,
                theory: `
                    <div class="intel-brief">
                        <div class="brief-header">
                            <i class="fas fa-folder-open"></i> MISSION DOSSIER #M10
                        </div>
                        <div class="brief-body">
                            <div class="stat-row">
                                <div class="stat-item"><span class="label">TYPE</span> <span class="val">SSRF</span></div>
                                <div class="stat-item"><span class="label">SEVERITY</span> <span class="val high">HIGH (CVSS 8.6)</span></div>
                            </div>
                            <h4><i class="fas fa-crosshairs"></i> VULNERABILITY ANALYSIS</h4>
                            <p>The application fetches URLs provided by the user without validation, allowing access to internal network resources.</p>
                            
                            <h4><i class="fas fa-bullseye"></i> OBJECTIVE</h4>
                            <p>Trick the server into accessing its own internal admin panel at <code>http://localhost/admin</code>.</p>
                            
                            <div class="mitigation-box">
                                <i class="fas fa-shield-alt"></i> <strong>DEFENSE:</strong> Whitelist allowed domains; Block private IPs.
                            </div>
                        </div>
                    </div>
                `,
                code: `// BACKEND: Proxy Service
const target = req.query.url;

// ⚠️ NO VALIDATION mechanism
// Server will request any URL, including internal ones.
axios.get(target).then(response => {
    res.send(response.data);
});`,
                checkSuccess: (input) => input.includes('localhost') && input.includes('admin'),
                patchKeyword: 'allowList'
            }
        };

        // Initialize Modules List (All Active)
        this.modules = [
            { id: 'm01', title: 'Broken Access Control', icon: 'fa-id-lock', diff: 'Hard', active: true },
            { id: 'm02', title: 'Cryptographic Failures', icon: 'fa-key', diff: 'Medium', active: true },
            { id: 'm03', title: 'Injection (SQLi)', icon: 'fa-database', diff: 'Easy', active: true },
            { id: 'm04', title: 'Insecure Design', icon: 'fa-pencil-ruler', diff: 'Medium', active: true },
            { id: 'm05', title: 'Security Misconfig', icon: 'fa-cogs', diff: 'Easy', active: true },
            { id: 'm06', title: 'Vuln Components', icon: 'fa-cubes', diff: 'Medium', active: true },
            { id: 'm07', title: 'Auth Failures', icon: 'fa-user-shield', diff: 'Hard', active: true },
            { id: 'm08', title: 'Integrity Failures', icon: 'fa-code-branch', diff: 'Hard', active: true },
            { id: 'm09', title: 'Logging Failures', icon: 'fa-clipboard-list', diff: 'Easy', active: true },
            { id: 'm10', title: 'SSRF', icon: 'fa-server', diff: 'Hard', active: true }
        ];
    }

    // --- CORE NAVIGATION ---
    loadScenario(id) {
        const mod = this.modules.find(m => m.id === id);
        if (!mod.active) return;

        this.activeModuleId = id;
        this.currentView = 'scenario';
        this.terminalLog = [];
        this.render();
        this.renderScenarioData();
        this.log("SYS", `[CONNECTION ESTABLISHED] Target: ${mod.title}`);
        this.log("INTEL", "Downloading Threat Brief...");
    }

    goBack() {
        this.currentView = 'dashboard';
        this.render();
    }

    // --- RENDERER ---
    render() {
        const container = document.getElementById('owasp-app-root');
        if (!container) return;

        if (this.currentView === 'dashboard') {
            container.innerHTML = this.renderDashboard();
        } else {
            container.innerHTML = this.renderScenarioUI();
            this.renderScenarioData();
        }
    }

    renderDashboard() {
        return `
        <div class="owasp-dash">
            <div class="dash-bg"></div>
            <div class="dash-header">
                <h1><i class="fas fa-shield-virus"></i> OWASP <span class="h-light">CYBER RANGE</span></h1>
                <p>Professional Vulnerability Assessment & Exploitation Simulation</p>
                <div class="dash-stats">
                    <span><i class="fas fa-layer-group"></i> 10 MODULES</span>
                    <span><i class="fas fa-signal"></i> LIVE SIMULATION</span>
                    <span><i class="fas fa-certificate"></i> PRO CERTIFICATION</span>
                </div>
            </div>
            <div class="modules-grid">
                ${this.modules.map(m => `
                <div class="owasp-card">
                    <div class="card-icon"><i class="fas ${m.icon}"></i></div>
                    <div class="card-content">
                        <h3>${m.title}</h3>
                        <div class="card-meta">
                            <span class="diff-badge ${m.diff.toLowerCase()}">${m.diff}</span>
                            <span class="active-dot"></span>
                        </div>
                        <div class="card-actions" style="margin-top: 15px; display: flex; gap: 8px;">
                            <button class="btn btn-sm btn-primary" style="flex: 1; font-size: 0.8rem;" onclick="event.stopPropagation(); startOwaspLearn('${m.id}')">
                                <i class="fas fa-book-open"></i> Learn
                            </button>
                            <button class="btn btn-sm btn-outline-light" style="flex: 1; font-size: 0.8rem;" onclick="event.stopPropagation(); startOwaspPractice('${m.id}')">
                                <i class="fas fa-gamepad"></i> Practice
                            </button>
                        </div>
                    </div>
                    <div class="card-hover-effect"></div>
                </div>
            `).join('')}
            </div>
        </div>
        `;
    }

    renderScenarioUI() {
        const sc = this.scenarios[this.activeModuleId];
        const themeClass = sc.theme || 'theme-default';

        return `
        <div class="owasp-layout ${themeClass}">
            <!-- Header -->
            <div class="owasp-navbar">
                <div class="nav-brand">
                    <button class="nav-back" onclick="owaspEngine.goBack()"><i class="fas fa-chevron-left"></i> ESCAPE</button>
                    <span class="nav-sep">/</span>
                    <span class="nav-title">${sc.title}</span>
                </div>
                <div class="nav-status">
                    <span class="status-indicator"><span class="blink">●</span> LIVE ENVIRONMENT</span>
                    <button class="nav-btn xray-btn" onclick="owaspEngine.toggleXray()"><i class="fas fa-code-branch"></i> X-RAY TRACE</button>
                </div>
            </div>

            <!-- Grid Content -->
            <div class="mission-grid">
                
                <!-- QUADRANT 1: INTEL -->
                <div class="grid-panel panel-intel">
                    <div class="panel-header"><i class="fas fa-file-contract"></i> BRIEFING</div>
                    <div class="panel-content custom-scrollbar">
                        ${sc.theory}
                    </div>
                </div>

                <!-- QUADRANT 2: TARGET -->
                <div class="grid-panel panel-target">
                    <div class="browser-frame">
                        <div class="browser-ctrls">
                            <div class="traffic-lights"><span></span><span></span><span></span></div>
                            <div class="browser-tabs">
                                <div class="tab active"><i class="fas fa-globe"></i> Target Site <span class="tab-close">×</span></div>
                                <div class="tab-add">+</div>
                            </div>
                        </div>
                        <div class="browser-addr-bar">
                            <button class="addr-btn"><i class="fas fa-arrow-left"></i></button>
                            <button class="addr-btn"><i class="fas fa-redo"></i></button>
                            <div class="addr-input-wrapper">
                                <i class="fas fa-lock addr-lock"></i>
                                <input type="text" id="browser-url" value="${sc.targetUrl}" onchange="owaspEngine.handleUrlChange(this.value)">
                            </div>
                        </div>
                        <div class="browser-viewport" id="sim-browser">
                             <div class="content" id="sim-browser-content">
                                ${sc.targetHtml}
                            </div>
                            <!-- XRAY OVERLAY -->
                            <div id="xray-panel" class="xray-overlay" style="display:none">
                                <div class="xray-header">
                                    <span><i class="fas fa-bug"></i> BACKEND EXECUTION TRACE</span>
                                    <span class="close-xray" onclick="owaspEngine.toggleXray()">×</span>
                                </div>
                                <div class="code-block language-javascript" id="live-query">Waiting for input...</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- QUADRANT 3: ATTACK -->
                <div class="grid-panel panel-attack">
                    <div class="panel-header term-header"><i class="fas fa-terminal"></i> KALI TERMINAL</div>
                    <div class="term-viewport" id="owasp-term-body">
                         <div class="term-line sys">Kali GNU/Linux Rolling [Version 2025.1]</div>
                         <div class="term-line sys">Connected to Cyber Range VPN (10.10.10.5).Type exploit command below.</div>
                         <br>
                    </div>
                    <div class="term-input-row">
                        <span class="prompt">root@kali:~/exploits#</span>
                        <input type="text" class="term-cmd" placeholder="..." onkeydown="if(event.key==='Enter')owaspEngine.log('TERM', 'Command not found. Please interact with the Target directly.')">
                    </div>
                </div>

                <!-- QUADRANT 4: CODE -->
                <div class="grid-panel panel-code">
                    <div class="panel-header code-header">
                        <span><i class="fas fa-code"></i> SECURE EDITOR</span>
                        <button class="action-btn" onclick="owaspEngine.deployPatch(document.getElementById('code-area').value)"><i class="fas fa-play"></i> DEPLOY PATCH</button>
                    </div>
                    <div class="ide-wrapper">
                        <div class="ide-gutter">1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12</div>
                        <textarea id="code-area" class="ide-editor" spellcheck="false">${sc.code}</textarea>
                    </div>
                </div>

            </div>
        </div>`;
    }

    renderScenarioData() {
        if (this.xray) this.updateXray();
    }

    // --- INTERACTION LOGIC ---
    handleUrlChange(val) {
        if (this.activeModuleId === 'm01') this.runCheck(val);
    }

    handleSQLiInput(val) {
        const el = document.getElementById('live-query');
        if (el) {
            el.innerHTML = `// LIVE EXECUTION<br>SELECT * FROM users WHERE user = '<span style="color:#f43f5e;font-weight:bold;">${val}</span>'`;
        }
    }

    runCheck(optionalInput) {
        const sc = this.scenarios[this.activeModuleId];
        let input = optionalInput;

        if (!input) {
            // Auto-detect input based on module
            if (this.activeModuleId === 'm02') input = document.getElementById('pass-input').value;
            if (this.activeModuleId === 'm03') input = document.getElementById('login-user').value;
            if (this.activeModuleId === 'm04') input = document.getElementById('discount-input').value;
            if (this.activeModuleId === 'm05') input = document.getElementById('m05-user').value + ':' + document.getElementById('m05-pass').value;
            if (this.activeModuleId === 'm06') input = document.getElementById('m06-input').value;
            if (this.activeModuleId === 'm07') input = document.getElementById('m07-pass').value;
            if (this.activeModuleId === 'm08') input = document.getElementById('m08-input').value;
            if (this.activeModuleId === 'm09') input = document.getElementById('m09-account').value;
            if (this.activeModuleId === 'm10') input = document.getElementById('url-input').value;
        }

        this.log("Target", `Processing Request: ${input}`);

        if (sc.checkSuccess(input)) {
            this.triggerSuccess();
        } else {
            this.log("SYS", "Server Response: 403 Forbidden / Action Failed.");
            this.shakeBrowser();
        }
    }

    triggerSuccess() {
        const content = document.getElementById('sim-browser-content');
        this.log("SYS", "VULNERABILITY EXPLOITED SUCCESSFULLY.");
        this.log("LOOT", `FLAG_${this.activeModuleId.toUpperCase()}_CAPTURED`);
        content.innerHTML = `
            <div class="success-screen">
                <i class="fas fa-check-circle"></i>
                <h2>SYSTEM COMPROMISED</h2>
                <div class="flag">CTF{OWASP_${this.activeModuleId.toUpperCase()}_PWNED}</div>
            </div>
        `;
    }

    // --- DEFENSE LOGIC ---
    deployPatch(code) {
        this.log("DEV", "Committing patch to repository...");
        setTimeout(() => {
            this.log("CI/CD", "Running Unit Tests...");
            const sc = this.scenarios[this.activeModuleId];
            if (code.includes(sc.patchKeyword)) {
                this.log("CI/CD", "[SUCCESS] Build Passed. Vulnerability Remediated.");
                alert("PATCH VERIFIED: You have secured the application!");
            } else {
                this.log("CI/CD", "[FAILED] Security Regression Detected. Try again.");
            }
        }, 1000);
    }

    // --- UTILS ---
    log(src, msg) {
        let color = '#00ff00';
        if (src === 'SYS') color = '#00ccff';
        if (src === 'Target') color = '#ffcc00';
        if (src === 'LOOT') color = '#ff00ff';
        if (src === 'CI/CD') color = '#3b82f6';
        if (src === 'DEV') color = '#a855f7';

        this.terminalLog.push(`<span style="color:#666">[${new Date().toLocaleTimeString()}]</span> <b style="color:${color}">${src}</b>: ${msg}`);
        const el = document.getElementById('owasp-term-body');
        if (el) {
            el.innerHTML = this.terminalLog.map(l => `<div>${l}</div>`).join('');
            el.scrollTop = el.scrollHeight;
        }
    }

    toggleXray() {
        this.xray = !this.xray;
        const panel = document.getElementById('xray-panel');
        if (panel) panel.style.display = this.xray ? 'flex' : 'none';
        this.updateXray();
    }

    updateXray() {
        const el = document.getElementById('live-query');
        if (!el) return;

        let t = "// WAITING FOR INPUT...";
        if (this.activeModuleId === 'm01') t = 'query("SELECT * FROM users WHERE id = ' + (document.getElementById('browser-url')?.value.split('=')[1] || '?') + '")';
        if (this.activeModuleId === 'm03') t = "SELECT * FROM users WHERE user = '" + (document.getElementById('login-user')?.value || '') + "'";
        if (this.activeModuleId === 'm05') t = "<user name='tomcat' pass='s3cret' />";
        if (this.activeModuleId === 'm06') t = "logger.info('Login: " + (document.getElementById('m06-input')?.value || '') + "')";

        el.innerText = t;
    }

    shakeBrowser() {
        const b = document.querySelector('.browser-viewport');
        if (b) {
            b.classList.add('shake');
            setTimeout(() => b.classList.remove('shake'), 500);
        }
    }
}

const owaspEngine = new OWASPEngine();

function pageOWASPSimulator() {
    setTimeout(() => owaspEngine.render(), 50);
    return `<div id="owasp-app-root" style="height:100vh; overflow:hidden;"></div>` + getOWASPStyles();
}

function getOWASPStyles() {
    return `
    <style>
        /* BASE & DASHBOARD - Preserved from Preview Version */
        .owasp-dash {
            height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #020617 100%);
            color: #fff; padding: 40px; font-family: 'Segoe UI', sans-serif; overflow-y: auto;
        }
        .dash-header { text-align: center; margin-bottom: 50px; position:relative; z-index:2; }
        .dash-header h1 { font-size: 3rem; margin: 0; letter-spacing: 2px; }
        .dash-header p { color: #94a3b8; font-size: 1.1rem; margin-top: 10px; }
        .h-light { color: #f43f5e; text-shadow: 0 0 20px rgba(244, 63, 94, 0.4); }
        .dash-stats { margin-top:20px; display:flex; gap:30px; justify-content:center; color:#64748b; font-size:0.9rem; font-weight:600;}
        .dash-stats span i { color:#3b82f6; margin-right:8px; }

        .modules-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 25px;
            max-width: 1300px; margin: 0 auto; position:relative; z-index:2;
        }
        .owasp-card {
            background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 12px; padding: 30px;
            cursor: pointer; position: relative; overflow: hidden; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
        }
        .owasp-card:hover { transform: translateY(-8px); border-color: #f43f5e; box-shadow: 0 20px 40px rgba(0,0,0,0.3); }
        .owasp-card:hover .card-icon { color: #f43f5e; transform: scale(1.1); }
        
        .card-icon { font-size: 2.5rem; color: #3b82f6; margin-bottom: 20px; transition:0.3s; }
        .card-content h3 { margin: 0 0 15px 0; font-size: 1.2rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .card-meta { display: flex; justify-content: space-between; align-items: center; }
        .diff-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform:uppercase; letter-spacing:1px; }
        .diff-badge.easy { background: rgba(16, 185, 129, 0.2); color: #34d399; border:1px solid #10b981; }
        .diff-badge.medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border:1px solid #f59e0b; }
        .diff-badge.hard { background: rgba(239, 68, 68, 0.2); color: #f87171; border:1px solid #ef4444; }
        .active-dot { width:8px; height:8px; background:#10b981; border-radius:50%; box-shadow:0 0 10px #10b981; }

        /* === ELITE LAYOUT (GRID) === */
        .owasp-layout {
            height: 100vh; background: #0b1120; color: #cbd5e1;
            display: flex; flex-direction: column; overflow: hidden;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }

        /* HEADER */
        .owasp-navbar {
            height: 50px; background: rgba(15, 23, 42, 0.9); border-bottom: 1px solid #1e293b;
            display: flex; align-items: center; justify-content: space-between; padding: 0 20px;
            backdrop-filter: blur(5px); z-index:100;
        }
        .nav-brand { display:flex; align-items:center; gap:10px; }
        .nav-back { background:#1e293b; border:1px solid #334155; color:#94a3b8; padding:5px 12px; border-radius:4px; font-size:0.75rem; font-weight:700; cursor:pointer; display:flex; align-items:center; gap:6px; transition:0.2s;}
        .nav-back:hover { border-color:#f43f5e; color:#f43f5e; }
        .nav-sep { color:#334155; }
        .nav-title { font-weight:600; font-size:1rem; letter-spacing:0.5px; }

        .nav-status { display:flex; align-items:center; gap:15px; font-size:0.8rem; font-weight:600; color:#10b981; }
        .blink { animation: blink 1.5s infinite; color:#10b981; }
        .nav-btn.xray-btn { background:rgba(59, 130, 246, 0.1); color:#3b82f6; border:1px solid rgba(59, 130, 246, 0.3); padding:5px 10px; border-radius:4px; cursor:pointer; font-weight:700; display:flex; gap:6px; align-items:center;}
        .nav-btn.xray-btn:hover { background:rgba(59, 130, 246, 0.2); box-shadow:0 0 10px rgba(59,130,246,0.2); }

        /* GRID SYSTEM */
        .mission-grid {
            flex: 1; display: grid; padding: 10px; gap: 10px;
            grid-template-columns: 35% 65%;
            grid-template-rows: 55% 45%;
            /* Areas: 
               Target (Top Left/Right - Actually Left is Intel, Right is Target)
               But we want: Left Col = Intel(Top) & Attack(Bot), Right Col = Target(Top) & Code(Bot) 
            */
            grid-template-areas: 
                "intel target"
                "attack code";
        }
        
        .grid-panel {
            background: #1e293b; border: 1px solid #334155; border-radius: 8px; overflow: hidden;
            display: flex; flex-direction: column; position:relative;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }

        .panel-intel { grid-area: intel; background: rgba(30, 41, 59, 0.5); }
        .panel-target { grid-area: target; border-color: #475569; }
        .panel-attack { grid-area: attack; background: #000; border-color: #333; }
        .panel-code   { grid-area: code; background: #0d1117; }

        .panel-header {
            padding: 8px 12px; font-size: 0.75rem; font-weight: 700; letter-spacing: 1px;
            background: rgba(30,41,59,0.8); border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex; justify-content: space-between; align-items: center; color:#94a3b8;
        }

        /* INTEL PANEL STYLES */
        .panel-content { padding: 15px; overflow-y: auto; height: 100%; color:#cbd5e1; }
        .intel-brief h4 { color:#e2e8f0; font-size:0.85rem; margin-top:15px; margin-bottom:10px; border-bottom:1px solid #334155; padding-bottom:5px; }
        .brief-header { background:linear-gradient(90deg, #3b82f6 0%, transparent 100%); padding:5px 10px; color:#fff; font-weight:bold; font-size:0.8rem; border-radius:4px; margin-bottom:15px; }
        .stat-row { display:flex; gap:10px; margin-bottom:15px; }
        .stat-item { flex:1; background:#0f172a; padding:8px; border-radius:4px; font-size:0.75rem; display:flex; flex-direction:column; gap:4px; border:1px solid #334155; }
        .stat-item .label { color:#64748b; font-weight:bold; }
        .stat-item .val { font-weight:bold; color:#f8fafc; }
        .stat-item .val.crit { color:#f43f5e; }
        .stat-item .val.high { color:#fb923c; }
        .mitigation-box { margin-top:20px; background:rgba(16, 185, 129, 0.1); border-left:3px solid #10b981; padding:10px; font-size:0.85rem; color:#d1fae5; }

        /* BROWSER UI (CHROME STYLE) */
        .browser-frame { display:flex; flex-direction:column; height:100%; width:100%; background:#fff; }
        .browser-ctrls { background:#1e293b; padding:8px 12px 0 12px; display:flex; gap:15px; align-items:center; }
        .traffic-lights { display:flex; gap:6px; }
        .traffic-lights span { width:10px; height:10px; border-radius:50%; background:#475569; }
        .traffic-lights span:nth-child(1) { background:#ef4444; }
        .traffic-lights span:nth-child(2) { background:#f59e0b; }
        .traffic-lights span:nth-child(3) { background:#10b981; }
        
        .browser-tabs { display:flex; gap:5px; flex:1; align-items:flex-end; }
        .browser-tabs .tab { background:#334155; color:#cbd5e1; padding:6px 15px; border-radius: 8px 8px 0 0; font-size:0.75rem; display:flex; align-items:center; gap:8px; width:150px; justify-content:space-between; }
        .browser-tabs .tab.active { background:#f1f5f9; color:#0f172a; font-weight:600; }
        .browser-tabs .tab-add { padding:5px 8px; color:#64748b; font-weight:bold; cursor:pointer; }
        
        .browser-addr-bar { background:#f1f5f9; padding:8px; display:flex; gap:8px; border-bottom:1px solid #cbd5e1; align-items:center; }
        .addr-btn { border:none; background:transparent; color:#64748b; font-size:0.9rem; cursor:pointer; padding:4px; border-radius:50%; }
        .addr-btn:hover { background:#e2e8f0; color:#333; }
        .addr-input-wrapper { flex:1; background:#fff; border:1px solid #cbd5e1; border-radius:20px; padding:4px 12px; display:flex; align-items:center; gap:8px; font-size:0.85rem; }
        .addr-lock { color:#10b981; font-size:0.75rem; }
        .addr-input-wrapper input { border:none; outline:none; width:100%; font-family:'Segoe UI'; color:#333; }

        .browser-viewport { flex:1; position:relative; overflow:hidden; display:flex; flex-direction:column; }
        .content { flex:1; overflow:auto; display:flex; align-items:center; justify-content:center; }

        /* TERMINAL PANEL */
        .term-header { color: #f43f5e; border-bottom-color:#333; background:rgba(0,0,0,0.5); }
        .term-viewport { flex:1; padding:10px; font-family:'Courier New', monospace; font-size:0.85rem; overflow-y:auto; color:#d1d5db; }
        .term-line.sys { color:#6b7280; }
        .term-input-row { display:flex; background:#111; padding:8px 10px; border-top:1px solid #333; align-items:center; }
        .term-input-row .prompt { color:#f43f5e; font-weight:bold; margin-right:10px; font-family:'Courier New', monospace; font-size:0.85rem; }
        .term-input-row input { background:transparent; border:none; color:#f43f5e; font-family:'Courier New', monospace; flex:1; outline:none; }

        /* CODE PANEL */
        .code-header { color:#3b82f6; background:#0d1117; border-bottom-color:#30363d; }
        .action-btn { background:#238636; border:1px solid rgba(255,255,255,0.1); color:#fff; padding:3px 10px; border-radius:4px; font-size:0.7rem; font-weight:bold; cursor:pointer; display:flex; align-items:center; gap:5px; transition:0.2s; }
        .action-btn:hover { background:#2ea043; }
        .ide-wrapper { flex:1; display:flex; font-family:'Consolas', monospace; font-size:0.9rem; }
        .ide-gutter { width:40px; background:#0d1117; color:#484f58; text-align:right; padding:10px 8px; line-height:1.5; border-right:1px solid #30363d; user-select:none; }
        .ide-editor { flex:1; background:#0d1117; color:#e6edf3; border:none; outline:none; padding:10px; resize:none; line-height:1.5; }

        /* XRAY UPGRADE */
        .xray-overlay {
            position: absolute; bottom: 0; left: 0; width: 100%; height:180px; 
            background: rgba(15, 23, 42, 0.98); backdrop-filter:blur(10px);
            border-top: 1px solid #3b82f6; display:flex; flex-direction:column; z-index:50;
        }
        .xray-header { 
            background: rgba(59, 130, 246, 0.1); color: #3b82f6; padding: 6px 15px; 
            font-size: 0.75rem; font-weight: 700; display:flex; justify-content:space-between; align-items:center; 
        }
        .close-xray { cursor:pointer; font-size:1.2rem; }
        .close-xray:hover { color:#fff; }
        .code-block { padding:15px; font-family:'Consolas', monospace; color:#e2e8f0; font-size:0.9rem; overflow:auto; flex:1; }

        /* CUSTOM THEME OVERRIDES (UI COLORS) */
        
        /* THEME SHOP */
        .shop-ui { width:100%; height:100%; background:#f8fafc; font-family:'Segoe UI', sans-serif; display:flex; flex-direction:column; }
        .shop-nav { background:#fff; padding:15px 20px; border-bottom:1px solid #e2e8f0; font-weight:700; display:flex; justify-content:space-between; color:#1e293b; box-shadow:0 2px 4px rgba(0,0,0,0.02); }
        .shop-card { background:#fff; margin:30px auto; padding:25px; width:320px; border-radius:12px; box-shadow:0 10px 25px rgba(0,0,0,0.05); text-align:center; border:1px solid #e2e8f0; }
        .shop-avatar { font-size:3.5rem; color:#cbd5e1; margin-bottom:15px; background:#f1f5f9; width:80px; height:80px; line-height:80px; border-radius:50%; margin:0 auto 15px; }
        .shop-orders { margin-top:15px; text-align:left; font-size:0.9rem; color:#64748b; }
        .shop-orders p { margin:5px 0; display:flex; align-items:center; gap:8px; }
        
        .coupon-area { margin-top:20px; text-align:left; border-top:1px dashed #e2e8f0; padding-top:15px; }
        .coupon-area h4 { margin:0 0 10px; font-size:0.9rem; color:#475569; }
        .coupon-area input { width:100%; padding:10px 12px; border:2px solid #e2e8f0; margin:5px 0 10px; border-radius:6px; background:#fff; color:#1e293b !important; font-weight:500; font-size:0.9rem; transition:0.2s; }
        .coupon-area input:focus { border-color:#3b82f6; outline:none; box-shadow:0 0 0 3px rgba(59,130,246,0.1); }
        .coupon-area button { width:100%; background:#1e293b; color:#fff; padding:10px; border:none; border-radius:6px; cursor:pointer; font-weight:600; transition:0.2s; }
        .coupon-area button:hover { background:#0f172a; transform:translateY(-1px); }

        /* THEME BANK */
        .bank-ui { width:100%; height:100%; background:linear-gradient(180deg, #0f172a 0%, #1e293b 100%); color:#fff; font-family:'Segoe UI', sans-serif; display:flex; flex-direction:column; align-items:center; }
        .bank-head { width:100%; padding:20px; font-size:1.1rem; font-weight:700; border-bottom:1px solid rgba(255,255,255,0.1); background:rgba(0,0,0,0.2); display:flex; align-items:center; gap:10px; }
        .bank-form { background:#fff; color:#333; padding:30px; border-radius:8px; width:340px; margin-top:40px; box-shadow:0 20px 50px rgba(0,0,0,0.5); }
        .bank-form h3 { margin-top:0; color:#0f172a; border-bottom:2px solid #3b82f6; padding-bottom:15px; margin-bottom:20px; font-size:1.2rem; }
        .bank-form .hint { font-size:0.85rem; color:#64748b; margin-bottom:15px; }
        .bank-form input { width:100%; padding:10px 12px; border:2px solid #cbd5e1; margin-bottom:15px; border-radius:6px; background:#fff; color:#1e293b !important; font-size:0.95rem; }
        .bank-form input:focus { border-color:#3b82f6; outline:none; }
        .bank-form button { width:100%; background:#2563eb; color:#fff; padding:12px; border:none; border-radius:6px; font-weight:700; cursor:pointer; transition:0.2s; }
        .bank-form button:hover { background:#1d4ed8; }

        /* THEME ADMIN (NEW) - Used in m03 SQLi */
        .admin-ui { width:100%; height:100%; background:#e2e8f0; font-family:'Segoe UI', sans-serif; display:flex; flex-direction:column; align-items:center; justify-content:center; position:relative; }
        .admin-header { position:absolute; top:0; left:0; width:100%; background:#1e293b; color:#fff; padding:15px 20px; font-weight:700; display:flex; align-items:center; gap:10px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1); }
        .login-panel { background:#fff; padding:40px 30px; border-radius:12px; width:360px; box-shadow:0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04); text-align:center; }
        .login-panel h3 { margin:0 0 25px; color:#1e293b; font-size:1.5rem; letter-spacing: -0.5px; font-weight: 800; }
        .input-group { position:relative; margin-bottom:20px; text-align:left; }
        .input-group i { position:absolute; left:12px; top:50%; transform:translateY(-50%); color:#94a3b8; z-index: 5; }
        .input-group input { width:100%; padding:12px 12px 12px 40px; border:2px solid #e2e8f0; border-radius:8px; background:#f8fafc; color:#334155 !important; font-size:0.95rem; transition:0.2s; position:relative; z-index: 1;}
        .input-group input:focus { border-color:#3b82f6; background:#fff; outline:none; }
        .login-panel button { width:100%; padding:12px; background:#3b82f6; color:#fff; border:none; border-radius:8px; font-weight:700; font-size:1rem; cursor:pointer; transition:0.2s; box-shadow:0 4px 6px -1px rgba(59,130,246,0.5); }
        .login-panel button:hover { background:#2563eb; transform:translateY(-1px); box-shadow:0 6px 8px -1px rgba(59,130,246,0.6); }

        /* THEME RETRO */
        .retro-ui { background:#111; width:100%; height:100%; color:#0f0; font-family:'Courier New', monospace; display:flex; flex-direction:column; align-items:center; justify-content:center; }
        .mc-logo { font-size:2rem; text-shadow:4px 4px #000; margin-bottom:20px; color:#fff; font-weight:bold; }
        .mc-form { border:4px solid #fff; padding:30px; background:#000; box-shadow:10px 10px 0 #555; width:300px; }
        .mc-form input { background:#000; color:#fff !important; border:2px solid #fff; padding:8px; font-family:inherit; width:100%; margin-bottom:15px; font-size:1.1rem; }
        .mc-form button { background:#fff; color:#000; border:2px solid #fff; padding:8px 15px; cursor:pointer; font-family:inherit; width:100%; font-weight:bold; text-transform:uppercase; }
        .mc-form button:hover { background:#ccc; }

        /* THEME CRYPTO */
        .crypto-ui { text-align:center; color:#0f0; font-family:'Courier New'; background:#000; width:100%; height:100%; padding-top:40px; }
        .lock-icon { font-size:4rem; margin-bottom:20px; }
        .debug-console { border:1px dashed #0f0; padding:10px; display:inline-block; margin-bottom:20px; background:rgba(0,255,0,0.05); }
        .crypto-ui input { background:transparent; border:1px solid #0f0; color:#0f0; padding:10px; width:220px; font-family:inherit; text-align:center; }
        .crypto-ui button { background:#0f0; color:#000; border:none; padding:10px 20px; font-family:inherit; font-weight:bold; cursor:pointer; margin-left:10px; }

        .success-screen { text-align: center; color: #10b981; animation: popIn 0.5s; padding-top:20px; }
        .success-screen i { font-size: 4rem; margin-bottom: 20px; filter:drop-shadow(0 0 10px #10b981); }
        .flag { background: #000; color: #0f0; padding: 10px 20px; font-family: 'Courier New', monospace; margin-top: 15px; border: 1px solid #0f0; display: inline-block; font-weight:bold; box-shadow:0 0 15px rgba(0,255,0,0.2); }

        @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        @keyframes popIn { from { transform: scale(0.8); opacity:0; } to { transform: scale(1); opacity:1; } }
        .shake { animation: shake 0.5s; }
        @keyframes shake { 0% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } 100% { transform: translateX(0); } }

        /* RESPONSIVE */
        @media (max-width: 1000px) {
            .mission-grid { grid-template-columns: 1fr; grid-template-rows: auto auto auto auto; grid-template-areas: "intel" "target" "attack" "code"; overflow-y:auto; }
            .grid-panel { min-height:300px; }
        }
    </style>
    `;
}

window.pageOWASPSimulator = pageOWASPSimulator;
