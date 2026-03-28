
/* ============================================================
   OWASP EDUCATION MODULE
   Detailed educational content for OWASP Top 10
   ============================================================ */

const owaspEducationData = {
    'm01': {
        id: 'm01',
        title: 'Broken Access Control',
        icon: 'fa-lock-open',
        severity: 'High',
        description: 'When users can act outside of their intended permissions.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Bypassing access control checks by modifying the URL (e.g., changing <code>?id=105</code> to <code>?id=106</code>).</li>
        <li>Permitting viewing or editing someone else's account.</li>
        <li>Accessing API with missing access controls for POST, PUT and DELETE.</li>
        <li>Elevation of privilege (acting as an admin when logged in as a user).</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Except for public resources, deny by default.</li>
        <li>Implement access control mechanisms once and re-use them throughout the application (e.g., middleware).</li>
        <li>Model access controls should enforce record ownership rather than accepting that the user can create, read, update, or delete any record.</li>
        <li>Disable web server directory listing and ensure file metadata (e.g., .git) and backup files are not present within web roots.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE CODE
app.get('/account', (req, res) => {
  // ❌ No check if the user is authorized to view this ID
  const id = req.query.id;
  const data = db.getAccount(id);
  res.render('account', { data }); 
});

// SECURE CODE
app.get('/account', (req, res) => {
  const id = req.query.id;
  // ✅ Verify the logged-in user owns the requested ID
  if (req.session.userId !== id && !req.session.isAdmin) {
    return res.status(403).send('Access Denied');
  }
  const data = db.getAccount(id);
  res.render('account', { data });
});
    `
    },
    'm02': {
        id: 'm02',
        title: 'Cryptographic Failures',
        icon: 'fa-file-code',
        severity: 'Critical',
        description: 'Failures related to cryptography which often lead to sensitive data exposure.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Previously known as Sensitive Data Exposure. The focus is on failures related to cryptography (or lack thereof). This can lead to sensitive data like passwords, credit card numbers, and personal information being stolen.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Transmitting data in clear text (HTTP, FTP, SMTP).</li>
        <li>Storing passwords in plain text or using weak hashing algorithms (MD5, SHA1).</li>
        <li>Using default or weak crypto keys.</li>
        <li>Not enforcing encryption (missing strict-transport-security headers).</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Encrypt all data in transit with secure protocols such as TLS with forward secrecy (PFS) and strict parameters.</li>
        <li>Don't store sensitive data unnecessarily. Discard it as soon as possible.</li>
        <li>Store passwords using strong adaptive and salted hashing functions with a work factor (delay), such as Argon2, scrypt, bcrypt, or PBKDF2.</li>
        <li>Ensure that up-to-date and strong standard algorithms, protocols, and keys are used; use proper key management.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE CODE
// ❌ Storing password as plain text or simple hash
const password = req.body.password;
const hash = md5(password); 
db.saveUser(user, hash);

// SECURE CODE
// ✅ Using bcrypt with salt
const password = req.body.password;
const saltRounds = 10;
bcrypt.hash(password, saltRounds, function(err, hash) {
  db.saveUser(user, hash);
});
    `
    },
    'm03': {
        id: 'm03',
        title: 'Injection',
        icon: 'fa-syringe',
        severity: 'High',
        description: 'Untrusted data is sent to an interpreter as part of a command or query.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>User-supplied data is not validated, filtered, or sanitized by the application.</li>
        <li>Dynamic queries or non-parameterized calls are used directly in the interpreter.</li>
        <li>Hostile data is used within object-relational mapping (ORM) search parameters to extract sensitive records.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs).</li>
        <li>Use positive or "whitelist" server-side input validation.</li>
        <li>For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE CODE
// ❌ Concatenating user input directly into SQL
const query = "SELECT * FROM users WHERE user = '" + username + "'";
db.execute(query);

// SECURE CODE
// ✅ Using parameterized queries
const query = "SELECT * FROM users WHERE user = ?";
db.execute(query, [username]);
    `
    },
    'm04': {
        id: 'm04',
        title: 'Insecure Design',
        icon: 'fa-pencil-ruler',
        severity: 'High',
        description: 'Risks related to design and architectural flaws.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>A new category for 2021, focusing on risks related to design and architectural flaws. It calls for more use of threat modeling, secure design patterns, and reference architectures.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Failing to consider security requirements during the planning phase.</li>
        <li>Implementing business logic that is inherently unsafe (e.g., "secret" questions for password reset that are easily guessable).</li>
        <li>Lack of threat modeling for critical features.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Establish a secure development lifecycle with AppSec professionals.</li>
        <li>Limit user and service resource consumption (Rate Limiting).</li>
        <li>Write unit and integration tests that validate critical flows withstand the threat model.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE DESIGN
// ❌ Trusting client-side validation for price
// User sends: { itemId: 1, price: 0.01 }
processOrder(req.body.itemId, req.body.price);

// SECURE DESIGN
// ✅ Validate price on server from database
const item = db.getItem(req.body.itemId);
processOrder(item.id, item.price); // Ignore client price
    `
    },
    'm05': {
        id: 'm05',
        title: 'Security Misconfiguration',
        icon: 'fa-cogs',
        severity: 'Medium',
        description: 'Insecure default configurations, open cloud storage, etc.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Security misconfiguration is the most common issue. This includes insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Default accounts and passwords still enabled.</li>
        <li>Error handling reveals stack traces or other sensitive info to users.</li>
        <li>Unnecessary features are enabled or installed (e.g., unused ports, services, pages).</li>
        <li>The security settings in the application frameworks (e.g., Struts, Spring, ASP.NET) are not set to secure values.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>A repeatable hardening process that makes it fast and easy to deploy another environment that is properly locked down.</li>
        <li>Remove or do not install any unused features and frameworks.</li>
        <li>A segmented application architecture.</li>
        <li>Review and update the configurations appropriate to all security notes, updates and patches.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE CONFIG (Express.js)
// ❌ Verbose error details in production
app.use((err, req, res, next) => {
  res.status(500).send(err.stack); 
});

// SECURE CONFIG
// ✅ Generic error message, log details internally
app.use((err, req, res, next) => {
  console.error(err); // Log for admin
  res.status(500).send('Something went wrong!');
});
    `
    },
    'm06': {
        id: 'm06',
        title: 'Vulnerable Components',
        icon: 'fa-cube',
        severity: 'Variable',
        description: 'Using libraries or frameworks with known vulnerabilities.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>You do not know the versions of all components you use (both client-side and server-side).</li>
        <li>You do not scan for vulnerabilities regularly.</li>
        <li>You do not fix or upgrade the underlying platform, frameworks, and dependencies in a timely fashion.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Remove unused dependencies, unnecessary features, components, files, and documentation.</li>
        <li>Continuously inventory the versions of both client-side and server-side components (e.g., package.json, pom.xml).</li>
        <li>Obtain components from official sources over secure links.</li>
        <li>Monitor for libraries and components that are unmaintained or do not create security patches for older versions.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE (package.json)
// ❌ Using "latest" or old vulnerable versions
"dependencies": {
  "lodash": "4.17.15" // Known vuln
}

// SECURE
// ✅ Use fixed, patched versions
"dependencies": {
  "lodash": "4.17.21" // Patched
}
// Run: npm audit fix
    `
    },
    'm07': {
        id: 'm07',
        title: 'Identification Failures',
        icon: 'fa-id-card',
        severity: 'High',
        description: 'Failures in authentication and session management.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Previously Broker Authentication. Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Permits brute force or other automated attacks (credential stuffing).</li>
        <li>Permits default, weak, or well-known passwords.</li>
        <li>Weak or ineffective password recovery and forgotten password processes.</li>
        <li>Missing multi-factor authentication.</li>
        <li>Session IDs are exposed in the URL.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Implement multi-factor authentication (MFA).</li>
        <li>Do not ship or deploy with any default credentials.</li>
        <li>Align password length, complexity, and rotation policies with NIST 800-63b.</li>
        <li>Limit or increasingly delay failed login attempts.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE
// ❌ No rate limiting
app.post('/login', (req, res) => {
  // check credentials...
});

// SECURE
// ✅ Implement Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5 // limit each IP to 5 requests per windowMs
});
app.use('/login', limiter);
    `
    },
    'm08': {
        id: 'm08',
        title: 'Integrity Failures',
        icon: 'fa-file-signature',
        severity: 'High',
        description: 'Making assumptions about software and data integrity.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Focuses on making assumptions about software and data integrity throughout the CI/CD pipeline. This includes critical data, software updates, and CI/CD pipelines.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Using code from untrusted repositories or CDNs.</li>
        <li>Insecure CI/CD pipeline configuration (unauthorized access to code or build process).</li>
        <li>Insecure deserialization: Accepting serialized objects from untrusted sources.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Ensure your CI/CD pipeline has proper segregation, configuration, and access control.</li>
        <li>Ensure that unsigned or unverified code is not executed.</li>
        <li>Ensure that there is a review process for code and configuration changes.</li>
        <li>Do not accept serialized objects from untrusted sources.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE (Node.js Deserialization)
// ❌ Using eval or unsafe deserialization
const userInput = req.body.data;
const obj = eval("(" + userInput + ")"); 

// SECURE
// ✅ Use JSON.parse for data
const obj = JSON.parse(userInput);
    `
    },
    'm09': {
        id: 'm09',
        title: 'Logging Failures',
        icon: 'fa-clipboard-list',
        severity: 'Medium',
        description: 'Insufficient logging and monitoring.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>Auditable events, such as logins, failed logins, and high-value transactions, are not logged.</li>
        <li>Warnings and errors generate no, inadequate, or unclear log messages.</li>
        <li>Logs of applications and APIs are not monitored for suspicious activity.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts.</li>
        <li>Ensure that logs are generated in a format that can be easily consumed by a centralized log management solutions.</li>
        <li>Establish an incident response and recovery plan.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE
// ❌ Catching error silently or just printing to console
try {
  doCriticalTask();
} catch (e) {
  console.log("Error happened"); 
}

// SECURE
// ✅ Structured logging with timestamp and context
try {
  doCriticalTask();
} catch (e) {
  logger.error({
    timestamp: new Date(),
    user: req.user.id,
    action: 'critical_task',
    error: e.message
  });
}
    `
    },
    'm10': {
        id: 'm10',
        title: 'SSRF',
        icon: 'fa-server',
        severity: 'Medium',
        description: 'Server-Side Request Forgery.',
        theory: `
      <h3><i class="fas fa-book-open"></i> What is it?</h3>
      <p>Server-Side Request Forgery flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.</p>
      
      <h3><i class="fas fa-stethoscope"></i> How does it happen?</h3>
      <ul>
        <li>The application fetches a URL provided by the user (e.g., for an image upload via URL, webhook, etc.).</li>
        <li>The application does not validate if the destination is internal or external.</li>
      </ul>
      
      <h3><i class="fas fa-shield-alt"></i> Prevention</h3>
      <ul>
        <li>Enforce a strict whitelist of permitted domains and protocols.</li>
        <li>Disable HTTP redirections.</li>
        <li>Use a positive allow list for any URL input.</li>
        <li>Do not send raw responses to the client.</li>
      </ul>
    `,
        codeFix: `
// VULNERABLE
// ❌ Fetching any URL user provides
const url = req.query.url;
request(url, (err, response, body) => {
  res.send(body);
});

// SECURE
// ✅ Validate domain against whitelist
const url = req.query.url;
const allowedDomains = ['api.example.com', 'cdn.example.com'];
const domain = new URL(url).hostname;

if (allowedDomains.includes(domain)) {
  request(url, ...);
} else {
  res.status(400).send('Invalid Domain');
}
    `
    }
};

// Function to Show the Selection Modal
function showOwaspOptions(vulnId) {
    const vuln = owaspEducationData[vulnId] || { title: 'Unknown Vulnerability' };

    // Convert ID to match existing simulator IDs (usually m01, m02... and sometimes A01, A02...)
    // The 'owaspEducationData' uses 'm01', 'm02'. 
    // Let's ensure mapping is correct.
    // If input is 'A01', map to 'm01'
    let mappedId = vulnId;
    if (vulnId.startsWith('A')) {
        const num = parseInt(vulnId.substring(1));
        mappedId = 'm' + (num < 10 ? '0' + num : num);
    }

    // Check if we have data for this ID, if not try looking it up
    const data = owaspEducationData[mappedId];
    if (!data) {
        // Fallback if data missing, just load simulator directly to avoid breaking
        if (typeof loadScenario === 'function') {
            loadScenario(mappedId); // Direct sim load
        } else if (typeof owaspEngine !== 'undefined') {
            loadPage('owaspsimulator');
            setTimeout(() => owaspEngine.loadScenario(mappedId), 500);
        }
        return;
    }

    Swal.fire({
        title: `<i class="fa-solid ${data.icon} text-primary me-2"></i> ${data.title}`,
        text: 'How would you like to proceed?',
        showDenyButton: true,
        showCancelButton: true,
        confirmButtonText: '<i class="fa-solid fa-gamepad me-2"></i> Practice (Simulator)',
        denyButtonText: '<i class="fa-solid fa-book-open me-2"></i> Learn (Education)',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3085d6',
        denyButtonColor: '#10b981',
        background: '#1a1a2e',
        color: '#fff',
        customClass: {
            popup: 'cyber-modal-popup',
            title: 'text-light',
            htmlContainer: 'text-light'
        }
    }).then((result) => {
        if (result.isConfirmed) {
            // PRACTICE: Launch Simulator
            // We need to switch to the simulator page and load the specific scenario
            loadPage('owaspsimulator');

            // Wait for page to load then trigger scenario
            setTimeout(() => {
                if (typeof owaspEngine !== 'undefined') {
                    owaspEngine.loadScenario(mappedId);
                } else {
                    console.error("OWASP Engine not found");
                }
            }, 500);

        } else if (result.isDenied) {
            // LEARN: Show Education Page
            renderEducationPage(mappedId);
        }
    });
}

// Function to Render the Education Page
function renderEducationPage(vulnId) {
    const data = owaspEducationData[vulnId];
    if (!data) return;

    const contentDiv = document.getElementById('content');

    const html = `
    <div class="container mt-4 animate__animated animate__fadeIn">
      <button class="btn btn-outline-secondary mb-3" onclick="loadPage('vulns')">
        <i class="fa-solid fa-arrow-left me-2"></i> Back to List
      </button>
      
      <div class="card shadow-lg border-0 overflow-hidden">
        <div class="card-header bg-gradient-primary text-white p-4" style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-bottom: 2px solid #3b82f6;">
          <div class="d-flex justify-content-between align-items-center">
            <h2 class="mb-0 fw-bold"><i class="fa-solid ${data.icon} me-3 text-primary"></i> ${data.title}</h2>
            <span class="badge bg-danger rounded-pill px-3 py-2 fs-6">Severity: ${data.severity}</span>
          </div>
          <p class="lead text-muted mt-2 mb-0">${data.description}</p>
        </div>
        
        <div class="card-body bg-dark text-light p-4">
          
          <div class="row">
            <!-- Theory Section -->
            <div class="col-lg-7 mb-4">
              <div class="bg-opacity-10 bg-white p-4 rounded-3 h-100">
                ${data.theory}
              </div>
            </div>
            
            <!-- Code Fix Section -->
            <div class="col-lg-5 mb-4">
              <div class="card bg-black border-dark h-100">
                <div class="card-header border-dark d-flex justify-content-between align-items-center">
                  <h6 class="mb-0 text-success"><i class="fa-solid fa-code me-2"></i> Code Remediation</h6>
                  <span class="badge bg-secondary">JavaScript</span>
                </div>
                <div class="card-body p-0 position-relative">
                  <pre class="m-0 p-3" style="max-height: 500px; overflow-y: auto;"><code class="language-javascript text-light" style="font-family: 'Consolas', monospace; font-size: 0.85rem;">${data.codeFix.trim()}</code></pre>
                </div>
              </div>
            </div>
          </div>
          
          <div class="row mt-3">
             <div class="col-12 text-center">
               <button class="btn btn-lg btn-primary px-5 rounded-pill shadow-sm hover-scale" onclick="loadPage('owaspsimulator'); setTimeout(() => owaspEngine.loadScenario('${vulnId}'), 500);">
                 <i class="fa-solid fa-gamepad me-2"></i> Ready to Practice? Start Simulation
               </button>
             </div>
          </div>

        </div>
      </div>
    </div>
  `;

    contentDiv.innerHTML = html;
    window.scrollTo(0, 0);

    // Initialize syntax highlighting if available
    if (typeof hljs !== 'undefined') {
        hljs.highlightAll();
    }
}

// ============================================================
// NEW HELPER FUNCTIONS FOR SEPARATE BUTTONS
// ============================================================

function mapOwaspId(vulnId) {
    if (vulnId.startsWith('A')) {
        const num = parseInt(vulnId.substring(1));
        return 'm' + (num < 10 ? '0' + num : num);
    }
    return vulnId;
}

function startOwaspPractice(vulnId) {
    const mappedId = mapOwaspId(vulnId);

    // Check availability
    const data = owaspEducationData[mappedId];
    if (!data) {
        // Fallback for missing data
        console.warn(`No education data for ${mappedId}, trying generic load`);
    }

    // Launch Simulator directly
    loadPage('owaspsimulator');
    setTimeout(() => {
        if (typeof owaspEngine !== 'undefined') {
            owaspEngine.loadScenario(mappedId);
        } else {
            console.error("OWASP Engine not found");
        }
    }, 500);
}

function startOwaspLearn(vulnId) {
    const mappedId = mapOwaspId(vulnId);

    // Check availability
    if (!owaspEducationData[mappedId]) {
        Swal.fire({
            icon: 'info',
            title: 'Content Coming Soon',
            text: 'This educational module is under development.',
            background: '#1a1a2e',
            color: '#fff'
        });
        return;
    }

    renderEducationPage(mappedId);
}

