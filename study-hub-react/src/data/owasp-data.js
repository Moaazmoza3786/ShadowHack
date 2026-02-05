
export const owaspEducationData = {
  'm01': {
    id: 'm01',
    title: 'Broken Access Control',
    icon: 'Lock',
    difficulty: 'HARD',
    severity: 'High',
    type: 'Access Control',
    cvss: '7.5',
    description: 'When users can act outside of their intended permissions.',
    objective: 'Bypass authorization checks to access sensitive administrative data.',
    defense: 'Implement deny-by-default and robust middleware authorization.',
    theory: `
      <h3>What is it?</h3>
      <p>Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Bypassing access control checks by modifying the URL.</li>
        <li>Permitting viewing or editing someone else's account.</li>
        <li>Accessing API with missing access controls.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Except for public resources, deny by default.</li>
        <li>Implement access control mechanisms once and re-use them throughout the application.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE CODE
app.get('/account', (req, res) => {
  const id = req.query.id;
  const data = db.getAccount(id);
  res.render('account', { data }); 
});

// SECURE CODE
app.get('/account', (req, res) => {
  const id = req.query.id;
  if (req.session.userId !== id && !req.session.isAdmin) {
    return res.status(403).send('Access Denied');
  }
  const data = db.getAccount(id);
  res.render('account', { data });
});
    `,
    simulation: {
      targetSite: 'https://bank.cybercore.com/profile?id=admin',
      vulnerableCode: 'if (id === req.query.id) { showProfile(); }',
      terminalLogs: [
        '[7:41:55 AM] SYS: [CONNECTION ESTABLISHED] Target: Bank v2.0',
        '[7:41:55 AM] INTEL: Analyzing authorization headers...',
        '[7:41:56 AM] ALERT: ID parameter detected in query string.'
      ]
    }
  },
  'm02': {
    id: 'm02',
    title: 'Cryptographic Failures',
    icon: 'Key',
    difficulty: 'MEDIUM',
    severity: 'Critical',
    type: 'Cryptography',
    cvss: '9.1',
    description: 'Failures related to cryptography which often lead to sensitive data exposure.',
    objective: 'Identify and exploit weak hashing algorithms to crack user passwords.',
    defense: 'Use strong adaptive hashing functions like Argon2 or bcrypt with salts.',
    theory: `
      <h3>What is it?</h3>
      <p>Previously known as Sensitive Data Exposure. The focus is on failures related to cryptography, leading to sensitive data being stolen.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Transmitting data in clear text.</li>
        <li>Storing passwords in plain text or using weak hashing algorithms (MD5).</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Encrypt all data in transit with secure protocols like TLS.</li>
        <li>Store passwords using strong adaptive and salted hashing functions.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE CODE
const hash = md5(password); 
db.saveUser(user, hash);

// SECURE CODE
const saltRounds = 10;
bcrypt.hash(password, saltRounds, function(err, hash) {
  db.saveUser(user, hash);
});
    `,
    simulation: {
      targetSite: 'https://portal.secure-vault.io/login',
      vulnerableCode: 'const userHash = md5(userPassword);',
      terminalLogs: [
        '[8:12:10 AM] SYS: Crawling target for hash patterns...',
        '[8:12:11 AM] SCAN: Found MD5 sequence in database dump.',
        '[8:12:15 AM] CRACK: Starting multi-core dictionary attack...'
      ]
    }
  },
  'm03': {
    id: 'm03',
    title: 'Injection (SQLi)',
    icon: 'Database',
    difficulty: 'EASY',
    severity: 'High',
    type: 'Injection',
    cvss: '8.4',
    description: 'Untrusted data is sent to an interpreter as part of a command or query.',
    objective: 'Inject SQL commands to bypass login or leak the entire user database.',
    defense: 'Use parameterized queries or ORMs instead of raw string concatenation.',
    theory: `
      <h3>What is it?</h3>
      <p>Injection flaws occur when untrusted data is sent to an interpreter. Hostile data can trick the interpreter into executing unintended commands.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>User input is not validated or sanitized.</li>
        <li>Dynamic queries are used directly in the interpreter.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Use parameterized queries or ORM/ODM tools.</li>
        <li>Whitelist server-side input validation.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE CODE
const query = "SELECT * FROM users WHERE user = '" + username + "'";
db.execute(query);

// SECURE CODE
const query = "SELECT * FROM users WHERE user = ?";
db.execute(query, [username]);
    `,
    simulation: {
      targetSite: 'https://store.vulnerable.com/search?q=apple',
      vulnerableCode: "db.query(`SELECT * FROM products WHERE name LIKE '%${userInput}%'`);",
      terminalLogs: [
        '[9:05:22 AM] SYS: Injecting test vectors...',
        '[9:05:23 AM] DB: Error detected: syntax error at or near "\'"',
        '[9:05:24 AM] VULN: Boolean-based blind SQL injection confirmed.'
      ]
    }
  },
  'm04': {
    id: 'm04',
    title: 'Insecure Design',
    icon: 'Code',
    difficulty: 'MEDIUM',
    severity: 'High',
    type: 'Business Logic',
    cvss: '7.1',
    description: 'Risks related to design and architectural flaws.',
    objective: 'Identify the hardcoded developer coupon in the source code and use it to get a 100% discount.',
    defense: 'Separate Test/Prod Logic; Code Reviews; Threat Modeling.',
    theory: `
      <h3>What is it?</h3>
      <p>A category focusing on risks related to design and architectural flaws. It calls for more use of threat modeling and secure design patterns.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Failing to consider security during the planning phase.</li>
        <li>Implementing business logic that is inherently unsafe.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Establish a secure development lifecycle.</li>
        <li>Limit user and service resource consumption.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE DESIGN
// User sends: { itemId: 1, price: 0.01 }
processOrder(req.body.itemId, req.body.price);

// SECURE DESIGN
const item = db.getItem(req.body.itemId);
processOrder(item.id, item.price); // Ignore client price
    `,
    simulation: {
      targetSite: 'https://store.tech-giant.com/checkout',
      vulnerableCode: `
// BACKEND: Price Calculator
let total = cart.sum();

// ⚠️ BUSINESS LOGIC FLAW
// This backdoor should not exist in production.
if (couponCode === 'DEV_100_OFF') {
  total = 0;
}
      `,
      terminalLogs: [
        '[7:41:55 AM] SYS: [CONNECTION ESTABLISHED] Target: Insecure Design',
        '[7:41:55 AM] INTEL: Downloading Threat Brief...',
        '[7:41:56 AM] SCAN: Source code leak detected in public repository.'
      ]
    }
  },
  'm05': {
    id: 'm05',
    title: 'Security Misconfig',
    icon: 'Settings',
    difficulty: 'EASY',
    severity: 'Medium',
    type: 'Configuration',
    cvss: '5.3',
    description: 'Insecure default configurations, open cloud storage, etc.',
    objective: 'Find and exploit default credentials or exposed configuration files.',
    defense: 'Implement a repeatable hardening process and remove unused features.',
    theory: `
      <h3>What is it?</h3>
      <p>Security misconfiguration is the most common issue. This includes default configurations, open storage, and verbose error messages.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Default accounts and passwords still enabled.</li>
        <li>Error handling reveals stack traces.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Hardening process for every environment.</li>
        <li>Remove or do not install unused features.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE CONFIG
app.use((err, req, res, next) => {
  res.status(500).send(err.stack); 
});

// SECURE CONFIG
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong!');
});
    `,
    simulation: {
      targetSite: 'https://admin-panel.internal.io/login',
      vulnerableCode: '// Default: admin:admin',
      terminalLogs: [
        '[10:15:00 AM] SYS: Bruteforcing common default credentials...',
        '[10:15:02 AM] FOUND: admin:password123',
        '[10:15:05 AM] AUTH: Login successful. Accessing system logs.'
      ]
    }
  },
  'm06': {
    id: 'm06',
    title: 'Vuln Components',
    icon: 'Package',
    difficulty: 'MEDIUM',
    severity: 'Variable',
    type: 'Supply Chain',
    cvss: '7.8',
    description: 'Using libraries or frameworks with known vulnerabilities.',
    objective: 'Identify a vulnerable library in use and exploit a known CVE.',
    defense: 'Keep all dependencies updated and run regular security audits.',
    theory: `
      <h3>What is it?</h3>
      <p>Components run with the same privileges as the application. Exploiting a vulnerable component can facilitate server takeover.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>You do not know the versions of all components.</li>
        <li>You do not scan for vulnerabilities regularly.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Remove unused dependencies.</li>
        <li>Continuously inventory component versions.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE
"lodash": "4.17.15" // Known vuln

// SECURE
"lodash": "4.17.21" // Patched
    `,
    simulation: {
      targetSite: 'https://api.legacy-system.com/status',
      vulnerableCode: '"jquery": "1.12.4"',
      terminalLogs: [
        '[11:20:10 AM] SYS: Fingerprinting application stack...',
        '[11:20:11 AM] VULN: Outdated library detected: jquery@1.12.4',
        '[11:20:15 AM] EXPLOIT: Triggering Prototype Pollution...'
      ]
    }
  },
  'm07': {
    id: 'm07',
    title: 'Auth Failures',
    icon: 'UserCheck',
    difficulty: 'HARD',
    severity: 'High',
    type: 'Authentication',
    cvss: '8.1',
    description: 'Failures in authentication and session management.',
    objective: 'Bypass MFA or hijack an active session through weak identifiers.',
    defense: 'Implement MFA and align password policies with NIST standards.',
    theory: `
      <h3>What is it?</h3>
      <p>Confirmation of the user's identity is critical. Failures allow attackers to hijack sessions or crack passwords.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Permits brute force attacks.</li>
        <li>Session IDs are exposed in the URL.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Implement multi-factor authentication.</li>
        <li>Do not deploy with default credentials.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE
app.post('/login', (req, res) => { /* no rate limiting */ });

// SECURE
const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
app.use('/login', limiter);
    `,
    simulation: {
      targetSite: 'https://auth.cloud-node.com/reset-password',
      vulnerableCode: 'const token = Math.random(); // Predictable',
      terminalLogs: [
        '[12:45:30 AM] SYS: Intercepting password reset traffic...',
        '[12:45:32 AM] ANALYZE: Session token entropy is low.',
        '[12:45:35 AM] HIJACK: Forging active session cookie...'
      ]
    }
  },
  'm08': {
    id: 'm08',
    title: 'Integrity Failures',
    icon: 'GitBranch',
    difficulty: 'HARD',
    severity: 'High',
    type: 'Integrity',
    cvss: '7.5',
    description: 'Making assumptions about software and data integrity.',
    objective: 'Exploit insecure deserialization to execute remote code on the server.',
    defense: 'Use JSON.parse; Do not trust serialized objects from users.',
    theory: `
      <h3>What is it?</h3>
      <p>Focuses on making assumptions about software and data integrity. This includes CI/CD pipelines and insecure deserialization.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Accepting serialized objects from untrusted sources.</li>
        <li>Insecure CI/CD pipeline configuration.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Ensure unsigned code is not executed.</li>
        <li>Do not accept serialized objects from untruth sources.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE
const obj = eval("(" + userInput + ")"); 

// SECURE
const obj = JSON.parse(userInput);
    `,
    simulation: {
      targetSite: 'https://worker-node-1.compute.io/task',
      vulnerableCode: 'const data = serialize.unserialize(req.body.task);',
      terminalLogs: [
        '[01:30:10 PM] SYS: Crafting malicious serialized object...',
        '[01:30:11 PM] SEND: Transmitting payload to compute node...',
        '[01:30:15 PM] SHELL: Reverse connection received from 10.0.5.21'
      ]
    }
  },
  'm09': {
    id: 'm09',
    title: 'Logging Failures',
    icon: 'Activity',
    difficulty: 'MEDIUM',
    severity: 'Medium',
    type: 'Monitoring',
    cvss: '5.8',
    description: 'Insufficient logging and monitoring allowing persistence.',
    objective: 'Simulate a stealthy breach and identify the lack of audit logs in the application console.',
    defense: 'Implement structured logging and real-time monitoring alerts.',
    theory: `
      <h3>What is it?</h3>
      <p>This category is to help identify, detect, and respond to active breakthroughs. Without logging and monitoring, breakthroughs cannot be detected.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Auditable events, such as logins, are not logged.</li>
        <li>Warnings and errors generate no or inadequate logs.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Log all login, access control, and server-side validation failures.</li>
        <li>Ensure logs are generated in a format that can be easily consumed by centralized log management solutions.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE
try { doTask(); } catch (e) { /* silent */ }

// SECURE
try { doTask(); } catch (e) {
  logger.error({ 
    user: req.user.id, 
    error: e.message,
    timestamp: new Date()
  });
}
    `,
    simulation: {
      targetSite: 'https://logs.cyber-hub.com/viewer',
      vulnerableCode: 'catch (err) { console.log("error"); }',
      terminalLogs: [
        '[02:15:22 PM] SYS: Attempting unauthorized database sweep...',
        '[02:15:25 PM] ALERT: No audit logs generated for query failure.',
        '[02:15:30 PM] INTEL: Attacker persistence confirmed due to lack of monitoring.'
      ]
    }
  },
  'm10': {
    id: 'm10',
    title: 'SSRF',
    icon: 'Globe',
    difficulty: 'MEDIUM',
    severity: 'High',
    type: 'Server-Side',
    cvss: '7.2',
    description: 'Server-Side Request Forgery fetching remote resources without validation.',
    objective: 'Coerce the server into fetching metadata from the internal AWS instance.',
    defense: 'Enforce a strict whitelist of permitted domains and protocols.',
    theory: `
      <h3>What is it?</h3>
      <p>SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>The application fetches a URL provided by the user.</li>
        <li>Attackers can coerce the application to send requests to an unexpected destination.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Segment remote resource access in separate networks.</li>
        <li>Enforce "deny by default" firewall policies.</li>
      </ul>
    `,
    codeFix: `
// VULNERABLE
const url = req.query.url;
request(url, (err, response, body) => { res.send(body); });

// SECURE
const url = req.query.url;
if (!isWhitelisted(url)) { return res.status(400).send('Invalid Domain'); }
request(url, ...);
    `,
    simulation: {
      targetSite: 'https://proxy.internal-services.io/fetch?url=http://169.254.169.254',
      vulnerableCode: 'fetch(req.query.sourceUrl).then(r => r.text());',
      terminalLogs: [
        '[03:45:10 PM] SYS: Probing internal metadata service...',
        '[03:45:12 PM] FOUND: AWS Metadata detected at 169.254.169.254',
        '[03:45:15 PM] EXPLOIT: Leaking IAM role credentials via SSRF...'
      ]
    }
  }
};
