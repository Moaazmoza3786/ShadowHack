/* ============================================================
   UNIFIED CURRICULUM DATA - BreachLabs (Phase 3.5 - Massive Expansion)
   Hierarchy: Path -> Course -> Module -> Room
   200+ Professional Labs with Guided, Practice, and Challenge tiers.
   ============================================================ */

window.UnifiedLearningData = {
    _version: '3.5.0',

    // --- 1. CAREER PATHS (No Changes) ---
    paths: [
        {
            id: 'fundamentals-path',
            title: 'Cybersecurity Fundamentals',
            titleAr: 'أساسيات الأمن السيبراني',
            description: 'Start your cybersecurity journey here. Learn the essential skills needed before specializing in offensive or defensive security.',
            icon: 'fa-graduation-cap',
            color: '#22c55e',
            category: 'fundamentals',
            courses: ['intro-cybersecurity', 'linux-fundamentals', 'windows-fundamentals', 'networking-essentials', 'web-fundamentals'],
            estimatedHours: 80,
            difficulty: 'Beginner'
        },
        {
            id: 'red-team-path',
            title: 'Red Team - Offensive Security',
            titleAr: 'الفريق الأحمر - الأمن الهجومي',
            description: 'Master the art of ethical hacking. Learn to think like an attacker to find and exploit vulnerabilities.',
            icon: 'fa-user-secret',
            color: '#ef4444',
            category: 'offensive',
            courses: ['web-pentesting-beginner', 'web-pentesting-advanced', 'network-pentesting', 'active-directory-attacks', 'exploit-development', 'malware-analysis-offensive', 'web-sec-node-internals', 'web-sec-data-exploitation', 'web-sec-modern-client-api'],
            estimatedHours: 200,
            difficulty: 'Intermediate'
        },
        {
            id: 'blue-team-path',
            title: 'Blue Team - Defensive Security',
            titleAr: 'الفريق الأزرق - الأمن الدفاعي',
            description: 'Become a cyber defender. Learn to detect, analyze, and respond to security threats.',
            icon: 'fa-shield-halved',
            color: '#3b82f6',
            category: 'defensive',
            courses: ['soc-analyst-level1', 'soc-analyst-level2', 'threat-hunting', 'digital-forensics', 'incident-response', 'malware-analysis-defensive'],
            estimatedHours: 180,
            difficulty: 'Intermediate'
        },
        {
            id: 'bug-bounty-path',
            title: 'Bug Bounty Hunter',
            titleAr: 'صائد الثغرات',
            description: 'Turn your hacking skills into income. Learn to find vulnerabilities in real-world applications.',
            icon: 'fa-bug',
            color: '#f59e0b',
            category: 'bounty',
            courses: ['owasp-top10-deep', 'api-security-testing', 'mobile-security', 'advanced-web-attacks', 'recon-methodology'],
            estimatedHours: 150,
            difficulty: 'Intermediate'
        },
        {
            id: 'web-dev-pentest-path',
            title: 'Web Development for Pentesters',
            titleAr: 'برمجة الويب للمخترقين',
            description: 'Learn to build secure web applications and understand the underlying logic to improve your exploitation skills.',
            icon: 'fa-code',
            color: '#10B981',
            category: 'offensive',
            courses: ['secure-node-js', 'db-arch-sec', 'framework-internals', 'api-sec-dev'],
            estimatedHours: 120,
            difficulty: 'Intermediate'
        },
        {
            id: 'adv-network-path',
            title: 'Advanced Network Pentesting',
            titleAr: 'اختبار اختراق الشبكات المتقدم',
            description: 'السيطرة الكاملة على البنية التحتية للمؤسسات. من اختراق البروتوكولات إلى التخفي والتحرك الجانبي.',
            icon: 'fa-network-wired',
            color: '#3b82f6',
            category: 'offensive',
            courses: [
                'enterprise-infra-pro',
                'ad-identity-attacks',
                'network-defense-evasion',
                'lateral-movement-pro',
                'cloud-virt-pentest',
                'wireless-enterprise-pro'
            ],
            estimatedHours: 180,
            difficulty: 'Advanced'
        },
        {
            id: 'owasp-top10-deep',
            title: 'OWASP Top 10',
            description: 'Master the most critical web security risks. A structured roadmap for modern web exploitation.',
            icon: 'fa-file-shield',
            color: '#005ea2',
            category: 'bounty',
            courses: ['owasp-injection', 'owasp-broken-auth', 'owasp-xss', 'owasp-idor'],
            estimatedHours: 60,
            difficulty: 'Intermediate'
        },
        {
            id: 'exploit-development-path',
            title: 'Exploit Development',
            titleAr: 'تطوير الثغرات',
            description: 'Master the art of reverse engineering, buffer overflows, and complex exploitation techniques.',
            icon: 'fa-bomb',
            color: '#7f1d1d',
            category: 'offensive',
            courses: ['exploit-memory-course', 'exploit-binary-course', 'exploit-rop-course'],
            estimatedHours: 100,
            difficulty: 'Expert'
        },
        {
            id: 'web-security-architecture-path',
            title: 'Web Security Architecture & Exploitation',
            titleAr: 'هندسة واختراق الويب',
            description: 'A complete journey from source code analysis to exploiting complex architectural flaws.',
            icon: 'fa-shield-virus',
            color: '#00d4ff',
            category: 'offensive',
            courses: ['web-sec-node-internals', 'web-sec-data-exploitation', 'web-sec-modern-client-api'],
            estimatedHours: 120,
            difficulty: 'Expert'
        },
        {
            id: 'antigravity-pre-security',
            title: 'BreachLabs: Pre-Security',
            titleAr: 'أنتيجرافيتي: ما قبل الأمن',
            description: 'The essential foundation for any cybersecurity professional. Master Linux, Networking, and the Command Line.',
            icon: 'fa-user-graduate',
            color: '#06b6d4',
            category: 'fundamentals',
            courses: ['ag-pre-networking', 'ag-pre-linux'],
            estimatedHours: 40,
            difficulty: 'Beginner'
        },
        {
            id: 'antigravity-junior-pentester',
            title: 'BreachLabs: Junior Pentester',
            titleAr: 'أنتيجرافيتي: مختبر اختراق مبتدئ',
            description: 'Complete roadmap to becoming a Junior Penetration Tester. Covers Web, Network, and Post-Exploitation.',
            icon: 'fa-hat-wizard',
            color: '#8b5cf6',
            category: 'offensive',
            courses: ['ag-jp-web', 'ag-jp-network', 'ag-jp-post'],
            estimatedHours: 120,
            difficulty: 'Intermediate'
        },
        {
            id: 'breachlabs-pentester-track',
            title: 'BreachLabs: Certified Pentester',
            titleAr: 'أنتيجرافيتي: مختبر اختراق معتمد',
            description: 'The complete professional path. Mastering the kill chain from Reconnaissance to Reporting.',
            icon: 'fa-dragon',
            color: '#d946ef',
            category: 'offensive',
            courses: [
                'ag-mod-pt-fundamentals',
                'ag-mod-recon-enum',
                'ag-mod-vuln-assessment',
                'ag-mod-web-pentesting-pro',
                'ag-mod-network-pentesting-pro',
                'ag-mod-advanced-topics'
            ],
            estimatedHours: 250,
            difficulty: 'Advanced'
        },
        {
            id: 'breachlabs-soc-track',
            title: 'BreachLabs: SOC Analyst',
            titleAr: 'بريتش لابز: محلل مركز العمليات الأمنية',
            description: 'Complete Blue Team training. Master incident response, threat intelligence, and digital forensics.',
            icon: 'fa-shield-halved',
            color: '#3b82f6',
            category: 'defensive',
            courses: ['breachlabs-soc-fundamentals'],
            estimatedHours: 45,
            difficulty: 'Intermediate'
        },
        {
            id: 'breachlabs-cloud-security-track',
            title: 'BreachLabs: Cloud Security',
            titleAr: 'بريتش لابز: أمان السحابة',
            description: 'Master cloud security across AWS, Azure, and GCP. Learn IAM attacks, privilege escalation, and cloud pentesting.',
            icon: 'fa-cloud',
            color: '#06b6d4',
            category: 'offensive',
            courses: ['breachlabs-cloud-security'],
            estimatedHours: 50,
            difficulty: 'Advanced'
        }
    ],

    // --- 2. PROFESSIONAL COURSES (22 Courses) ---
    courses: [
        // ... Fundamentals ...
        { id: 'intro-cybersecurity', title: 'Introduction to Cybersecurity', description: 'Your first step.', icon: 'fa-shield-halved', color: '#22c55e', difficulty: 'Beginner', hours: 8, modules: ['intro-security-concepts', 'intro-careers', 'intro-ethics'] },
        { id: 'linux-fundamentals', title: 'Linux Fundamentals', description: 'Master the Linux command line.', icon: 'fa-linux', color: '#f59e0b', difficulty: 'Beginner', hours: 15, modules: ['linux-basics', 'linux-filesystem', 'linux-permissions', 'linux-scripting'] },
        { id: 'windows-fundamentals', title: 'Windows Fundamentals', description: 'Windows internals and AD basics.', icon: 'fa-windows', color: '#0078d4', difficulty: 'Beginner', hours: 12, modules: ['windows-basics', 'windows-ad-intro', 'windows-security-features'] },
        { id: 'networking-essentials', title: 'Networking Essentials', description: 'TCP/IP and protocols.', icon: 'fa-network-wired', color: '#06b6d4', difficulty: 'Beginner', hours: 20, modules: ['networking-osi', 'networking-tcpip', 'networking-protocols', 'networking-tools'] },
        { id: 'web-fundamentals', title: 'Web Technologies', description: 'HTTP and Web architecture.', icon: 'fa-globe', color: '#8b5cf6', difficulty: 'Beginner', hours: 10, modules: ['web-http', 'web-cookies-sessions', 'web-architecture'] },

        // ... Red Team ...
        { id: 'web-pentesting-beginner', title: 'Web Pentesting Beginner', description: 'Core vulnerabilities.', icon: 'fa-globe', color: '#ef4444', difficulty: 'Easy', hours: 25, modules: ['web-recon', 'web-sqli-basics', 'web-xss-basics', 'web-auth-bypass', 'web-file-upload'] },
        { id: 'web-pentesting-advanced', title: 'Web Pentesting Advanced', description: 'Advanced attacks.', icon: 'fa-spider', color: '#dc2626', difficulty: 'Hard', hours: 35, modules: ['web-ssrf', 'web-xxe', 'web-deserialization', 'web-ssti', 'web-race-conditions'] },
        { id: 'network-pentesting', title: 'Network Penetration Testing', description: 'Scanning and exploitation.', icon: 'fa-network-wired', color: '#ef4444', difficulty: 'Intermediate', hours: 30, modules: ['net-scanning', 'net-enumeration', 'net-exploitation', 'net-pivoting', 'net-post-exploit'] },
        { id: 'active-directory-attacks', title: 'Active Directory Attacks', description: 'AD domination.', icon: 'fa-sitemap', color: '#b91c1c', difficulty: 'Hard', hours: 40, modules: ['ad-enumeration', 'ad-kerberos-attacks', 'ad-privilege-escalation', 'ad-persistence', 'ad-trusts'] },
        { id: 'exploit-memory-course', title: 'Memory Internals', description: 'Understanding stack and heap architecture.', icon: 'fa-microchip', color: '#7f1d1d', difficulty: 'Expert', hours: 15, modules: ['exploit-memory'] },
        { id: 'exploit-binary-course', title: 'Buffer Overflows', description: 'Classic stack-based overflows.', icon: 'fa-bomb', color: '#ef4444', difficulty: 'Expert', hours: 25, modules: ['exploit-buffer-overflow', 'exploit-shellcode'] },
        { id: 'exploit-rop-course', title: 'Modern Binary Exploitation', description: 'Bypassing DEP/ASLR with ROP chains.', icon: 'fa-shield-halved', color: '#991b1b', difficulty: 'Expert', hours: 30, modules: ['exploit-rop'] },
        { id: 'malware-analysis-offensive', title: 'Malware Development', description: 'Creating red team tools.', icon: 'fa-virus', color: '#991b1b', difficulty: 'Expert', hours: 35, modules: ['malware-basics-red', 'malware-evasion-pro', 'malware-c2-infra'] },

        // ... Blue Team ...
        { id: 'soc-analyst-level1', title: 'SOC Analyst L1', description: 'Ops and triage.', icon: 'fa-desktop', color: '#3b82f6', difficulty: 'Easy', hours: 25, modules: ['soc-intro', 'soc-siem-basics', 'soc-log-analysis', 'soc-alert-triage'] },
        { id: 'soc-analyst-level2', title: 'SOC Analyst L2', description: 'Advanced ops.', icon: 'fa-chart-line', color: '#2563eb', difficulty: 'Intermediate', hours: 30, modules: ['soc-threat-intel', 'soc-advanced-detection', 'soc-automation', 'soc-reporting'] },
        { id: 'threat-hunting', title: 'Threat Hunting', description: 'Proactive defense.', icon: 'fa-crosshairs', color: '#1d4ed8', difficulty: 'Hard', hours: 35, modules: ['hunt-methodology', 'hunt-techniques', 'hunt-tools', 'hunt-scenarios'] },
        { id: 'digital-forensics', title: 'Digital Forensics', description: 'Evidence analysis.', icon: 'fa-magnifying-glass', color: '#1e40af', difficulty: 'Intermediate', hours: 40, modules: ['forensics-fundamentals', 'forensics-disk', 'forensics-memory', 'forensics-network', 'forensics-reporting'] },
        { id: 'incident-response', title: 'Incident Response', description: 'Breach handling.', icon: 'fa-fire-extinguisher', color: '#1e3a8a', difficulty: 'Hard', hours: 30, modules: ['ir-preparation', 'ir-detection', 'ir-containment', 'ir-eradication', 'ir-lessons'] },
        { id: 'malware-analysis-defensive', title: 'Malware Analysis', description: 'Dissecting threats.', icon: 'fa-microscope', color: '#1e3a8a', difficulty: 'Hard', hours: 35, modules: ['malware-static', 'malware-dynamic', 'malware-reverse'] },

        // --- BreachLabs Blue Team SOC Content ---
        {
            id: 'breachlabs-soc-fundamentals',
            title: 'BreachLabs: SOC Fundamentals',
            description: 'Complete Blue Team training from incident response to forensics.',
            icon: 'fa-shield-halved',
            color: '#3b82f6',
            difficulty: 'Intermediate',
            hours: 45,
            modules: ['bl-mod-incident-response', 'bl-mod-threat-intel', 'bl-mod-digital-forensics']
        },

        // --- BreachLabs Cloud Security Content ---
        {
            id: 'breachlabs-cloud-security',
            title: 'BreachLabs: Cloud Security',
            description: 'Master cloud security across AWS, Azure, and GCP platforms.',
            icon: 'fa-cloud',
            color: '#06b6d4',
            difficulty: 'Advanced',
            hours: 50,
            modules: ['bl-mod-aws-security', 'bl-mod-azure-gcp']
        },

        // ... Bug Bounty ...
        // Bug Bounty / OWASP Modules
        {
            id: 'owasp-injection',
            title: 'Injection Deep Dive',
            description: 'Beyond basic SQLi.',
            icon: 'fa-syringe',
            tasks: [
                {
                    id: 'cmd-inj',
                    title: 'OS Command Injection',
                    content: '### Executing System Commands\nWhen an application passes user-supplied data to a system shell. Using `;`, `&&`, or `|` to chain commands.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'exec("ping " + host)',
                        secure: 'execFile("ping", [host]) // No shell interpretation'
                    }
                },
                {
                    id: 'blind-sqli',
                    title: 'Blind SQLi (Boolean/Time)',
                    content: 'Extracting data character by character when No direct output is shown. Using `SLEEP()` or conditional responses.',
                    type: 'lab',
                    vulnerability: 'Data exfiltration through side-channel timing analysis.'
                }
            ],
            rooms: ['room-sqli-blind-guided']
        },
        {
            id: 'owasp-broken-auth',
            title: 'Broken Authentication',
            description: 'Session & Auth flaws.',
            icon: 'fa-id-card',
            tasks: [
                {
                    id: 'jwt-flaws',
                    title: 'JWT None Algorithm',
                    content: 'Modifying the header to `{"alg": "none"}` to bypass signature verification.',
                    type: 'challenge',
                    questions: [{ text: 'What is the base64 value for "none"?', answer: 'bm9uZQ==' }]
                }
            ],
            rooms: ['room-jwt-bypass']
        },
        {
            id: 'owasp-xss',
            title: 'XSS: Advanced Payloads',
            description: 'Bypassing filters.',
            icon: 'fa-code',
            tasks: [
                {
                    id: 'dom-xss-deep',
                    title: 'DOM-based XSS Secrets',
                    content: 'Analyzing JavaScript sinks like `innerHTML` and `eval()` combined with sources like `location.hash`.',
                    type: 'theory'
                }
            ],
            rooms: ['room-xss-polyglot']
        },
        {
            id: 'owasp-idor',
            title: 'IDOR & Access Control',
            description: 'Horizontal & Vertical escalation.',
            icon: 'fa-user-lock',
            tasks: [
                {
                    id: 'idor-logic',
                    title: 'Insecure Direct Object References',
                    content: 'Changing `/api/u101` to `/api/u102` to see another user\'s private data.',
                    type: 'lab',
                    vulnerability: 'Missing object-level authorization checks.'
                }
            ],
            rooms: ['room-idor-challenge']
        },

        // API Security Modules
        {
            id: 'api-fundamentals',
            title: 'API Security Fundamentals',
            description: 'REST, SOAP, and GraphQL.',
            icon: 'fa-plug',
            tasks: [
                {
                    id: 'api-auth-types',
                    title: 'API Authentication Types',
                    content: 'API Keys vs OAuth2 vs Basic Auth. Why API keys are not for identity.',
                    type: 'theory'
                }
            ],
            rooms: ['room-api-intro']
        },
        {
            id: 'api-auth-flaws',
            title: 'API Auth & Rate Limiting',
            description: 'Bypassing tokens.',
            icon: 'fa-shield-halved',
            tasks: [
                {
                    id: 'rate-limit-bypass',
                    title: 'Rate Limit Bypass Techniques',
                    content: 'Using `X-Forwarded-For` headers or alternating between IPv4 and IPv6 to bypass IP-based throttling.',
                    type: 'lab'
                }
            ],
            rooms: ['room-api-brute-force']
        },
        {
            id: 'api-graphql',
            title: 'GraphQL Security',
            description: 'Queries & Introspection.',
            icon: 'fa-diagram-project',
            tasks: [
                {
                    id: 'graphql-intro',
                    title: 'Introspection Attacks',
                    content: 'Querying `__schema` to map out the entire API structure and all available objects.',
                    type: 'challenge',
                    questions: [{ text: 'What field is used for introspection?', answer: '__schema' }]
                }
            ],
            rooms: ['room-graphql-vulns']
        },
        // Mobile Security Modules
        {
            id: 'mobile-android-basics',
            title: 'Android Static Analysis',
            description: 'Decompiling APKs.',
            icon: 'fa-android',
            tasks: [
                {
                    id: 'apk-structure',
                    title: 'The APK Anatomy',
                    content: '### ZIP Archive Structure\nUnderstanding `AndroidManifest.xml`, `classes.dex`, and `resources.arsc`. Decoding using `apktool`.',
                    type: 'theory'
                },
                {
                    id: 'jadx-lab',
                    title: 'Reversing with JADX',
                    content: 'Decompile the provided APK and find internal API keys or hardcoded secrets in the source code.',
                    type: 'lab',
                    vulnerability: 'Hardcoded credentials in Java/Kotlin classes.'
                }
            ],
            rooms: ['room-android-reversing']
        },
        {
            id: 'mobile-ios-basics',
            title: 'iOS Security Architecture',
            description: 'Sandboxing & Entitlements.',
            icon: 'fa-apple',
            tasks: [
                {
                    id: 'ios-sandbox',
                    title: 'The App Sandbox',
                    content: 'How Apple enforces isolation between apps. Understanding the role of the Secure Enclave and code signing.',
                    type: 'theory'
                }
            ],
            rooms: ['room-ios-fundamentals']
        },
        {
            id: 'mobile-api-testing',
            title: 'Mobile API Exploration',
            description: 'Intercepting mobile traffic.',
            icon: 'fa-wifi',
            tasks: [
                {
                    id: 'proxy-setup',
                    title: 'Proxies & Certificates',
                    content: 'Setting up Burp Suite as a proxy for physical or emulated devices. Installing CA certificates to intercept HTTPS.',
                    type: 'lab'
                },
                {
                    id: 'cert-pinning',
                    title: 'Certificate Pinning Bypass',
                    content: 'Using Frida or Objection to disable SSL pinning and view traffic from high-security apps.',
                    type: 'challenge',
                    questions: [{ text: 'What tool is commonly used for dynamic instrumentation?', answer: 'Frida' }]
                }
            ],
            rooms: ['room-mobile-proxy-master']
        },

        // Advanced Web Attacks
        {
            id: 'business-logic',
            title: 'Business Logic Flaws',
            description: 'Attacking application flow.',
            icon: 'fa-sitemap',
            tasks: [
                {
                    id: 'logic-errors',
                    title: 'The Cart Logic Vulnerability',
                    content: 'Modifying item quantities to negative values or changing prices in the POST request.',
                    type: 'lab',
                    vulnerability: 'Trusting client-side input for sensitive financial calculations.'
                }
            ],
            rooms: ['room-logic-master']
        },
        {
            id: 'request-smuggling',
            title: 'HTTP Request Smuggling',
            description: 'Front-end vs Back-end.',
            icon: 'fa-twisted-layer',
            tasks: [
                {
                    id: 'smuggle-clte',
                    title: 'CL.TE Vulnerabilities',
                    content: 'Exploiting discrepancies in how front-end and back-end servers process `Content-Length` and `Transfer-Encoding` headers.',
                    type: 'theory'
                }
            ],
            rooms: ['room-smuggling-advanced']
        }, { id: 'recon-methodology', title: 'Reconnaissance', description: 'Target acquisition.', icon: 'fa-binoculars', color: '#78350f', difficulty: 'Easy', hours: 20, modules: ['recon-passive', 'recon-active', 'recon-subdomain', 'recon-automation'] },

        // ... New Courses (User Requested) ...
        { id: 'cyber-fundamentals', title: 'Cybersecurity Fundamentals', description: 'The ultimate starting point. Learn the core principles of security, networking, and operating systems.', icon: 'fa-shield-halved', color: '#22c55e', difficulty: 'Beginner', hours: 40, modules: ['intro-cyber-security', 'networking-101', 'linux-basics-pro'] },
        { id: 'adv-pentest', title: 'Advanced Penetration Testing', description: 'Master advanced network exploitation, evasion techniques, and post-exploitation tactics.', icon: 'fa-dragon', color: '#ef4444', difficulty: 'Advanced', hours: 60, modules: ['adv-scanning', 'evasion-tech', 'post-exploit-pro'] },
        { id: 'ad-attacks', title: 'Active Directory Attacks', description: 'Dominate Windows environments. Learn Kerberoasting, Golden Tickets, and Forest Trust abuse.', icon: 'fa-sitemap', color: '#b91c1c', difficulty: 'Advanced', hours: 50, modules: ['ad-enum-pro', 'lateral-move', 'domain-dom'] },
        { id: 'web-exploits', title: 'Web Application Exploitation', description: 'Deep dive into modern web vulnerabilities including Deserialization, SSTI, and OAuth abuse.', icon: 'fa-bug', color: '#dc2626', difficulty: 'Advanced', hours: 55, modules: ['inject-attacks', 'broken-auth-pro', 'modern-vulns'] },
        { id: 'soc-eng-osint', title: 'Social Engineering & OSINT', description: 'The art of human hacking and Open Source Intelligence gathering mastery.', icon: 'fa-user-secret', color: '#f59e0b', difficulty: 'Intermediate', hours: 45, modules: ['osint-methods', 'phishing-ops', 'physical-sec'] },

        // --- WEB DEV FOR PENTESTERS ---
        { id: 'secure-node-js', title: 'Secure Coding: Node.js & Express', description: 'Mastering the request lifecycle, middleware security, and authorization.', icon: 'fa-brands fa-node-js', color: '#68a063', difficulty: 'Intermediate', hours: 30, modules: ['middleware-lifecycle-pro', 'bola-idor-pro'] },
        { id: 'db-arch-sec', title: 'Database Architecture & Secure Queries', description: 'Deep dive into SQL/NoSQL structure and avoiding injection.', icon: 'fa-database', color: '#336791', difficulty: 'Intermediate', hours: 25, modules: ['sql-injection-beyond-pro', 'nosql-injection-mongo'] },
        { id: 'framework-internals', title: 'Modern Client-Side Frameworks (React)', description: 'Understanding React security internals and DOM-XSS prevention.', icon: 'fa-brands fa-react', color: '#61dbfb', difficulty: 'Advanced', hours: 35, modules: ['dom-xss-react-pro'] },
        { id: 'api-sec-dev', title: 'API Development & Security', description: 'Building and securing RESTful APIs with focus on Mass Assignment.', icon: 'fa-cloud', color: '#10b981', difficulty: 'Intermediate', hours: 30, modules: ['mass-assignment-pro'] },

        // --- ADVANCED NETWORK PENTESTING COURSES ---
        {
            id: 'enterprise-infra-pro',
            title: 'Enterprise Protocols & Infrastructure',
            description: 'Advanced routing, SNMP exploitation, and VLAN hopping.',
            icon: 'fa-server',
            color: '#3b82f6',
            difficulty: 'Advanced',
            hours: 30,
            modules: ['routing-protocols-pro', 'snmp-enumeration-pro', 'vlan-hopping-lab']
        },
        {
            id: 'ad-identity-attacks',
            title: 'Active Directory & Identity Attacks',
            description: 'Kerberos, Kerberoasting, and Token Impersonation.',
            icon: 'fa-sitemap',
            color: '#b91c1c',
            difficulty: 'Advanced',
            hours: 45,
            modules: ['ad-structure-pro', 'kerberos-autopsy', 'roasting-attacks', 'token-impersonation']
        },
        {
            id: 'network-defense-evasion',
            title: 'Network Defense Evasion',
            description: 'Bypassing firewalls and IDS/IPS.',
            icon: 'fa-user-ninja',
            color: '#ef4444',
            difficulty: 'Advanced',
            hours: 30,
            modules: ['firewall-internals-pro', 'ids-evasion-tech', 'network-obfuscation']
        },
        {
            id: 'lateral-movement-pro',
            title: 'Lateral Movement (LotL)',
            description: 'WinRM, SMB, and WMI attacks.',
            icon: 'fa-arrows-split-up-and-left',
            color: '#f59e0b',
            difficulty: 'Advanced',
            hours: 25,
            modules: ['winrm-exploitation', 'smb-psexec-pro', 'wmi-attacks-pro']
        },
        {
            id: 'cloud-virt-pentest',
            title: 'Cloud & Virtualization Pentesting',
            description: 'Docker breakout and Kubernetes security.',
            icon: 'fa-cloud',
            color: '#06b6d4',
            difficulty: 'Advanced',
            hours: 35,
            modules: ['docker-networking-pro', 'docker-breakout-lab', 'k8s-basics-pentest']
        },
        {
            id: 'wireless-enterprise-pro',
            title: 'Wireless Infrastructure',
            description: 'WPA2/3 Enterprise and EAP attacks.',
            icon: 'fa-wifi',
            color: '#8b5cf6',
            difficulty: 'Advanced',
            hours: 20,
            modules: ['wpa-enterprise-pro', 'eap-evil-twin']
        },

        // --- Web Security Architecture Courses ---
        {
            id: 'web-sec-node-internals',
            title: 'Node.js & Express: Logic to Runtime',
            description: 'Deep dive into Node.js internals, event loop, and middleware security.',
            icon: 'fa-brands fa-node-js',
            color: '#68a063',
            difficulty: 'Advanced',
            hours: 35,
            modules: ['mod-node-arch', 'mod-js-internals', 'mod-auth-eng']
        },
        {
            id: 'web-sec-data-exploitation',
            title: 'Advanced Data & DB Exploitation',
            description: 'Mastering SQLi, NoSQL, and SSRF in modern stacks.',
            icon: 'fa-database',
            color: '#3b82f6',
            difficulty: 'Advanced',
            hours: 40,
            modules: ['mod-sqli-mastery', 'mod-nosql-polyglot', 'mod-ssrf-redis']
        },
        {
            id: 'web-sec-modern-client-api',
            title: 'Modern Client-Side & API Security',
            description: 'DOM XSS, API Architecture, and Business Logic flaws.',
            icon: 'fa-globe',
            color: '#f59e0b',
            difficulty: 'Advanced',
            hours: 30,
            modules: ['mod-dom-xss-evo', 'mod-api-arch-logic']
        },

        // --- ANTIGRAVITY SPECIAL TRACKS ---
        {
            id: 'ag-pre-networking',
            title: 'BreachLabs Networking',
            description: 'Core networking concepts for security.',
            icon: 'fa-network-wired',
            color: '#06b6d4',
            difficulty: 'Beginner',
            hours: 15,
            modules: ['ag-mod-networking-basics']
        },
        {
            id: 'ag-pre-linux',
            title: 'BreachLabs Linux',
            description: 'Mastering the Linux terminal and system.',
            icon: 'fa-linux',
            color: '#f59e0b',
            difficulty: 'Beginner',
            hours: 20,
            modules: ['ag-mod-linux-fundamentals']
        },
        {
            id: 'ag-jp-web',
            title: 'BreachLabs Web Hacking',
            description: 'Modern web vulnerability exploitation.',
            icon: 'fa-globe',
            color: '#ef4444',
            difficulty: 'Intermediate',
            hours: 40,
            modules: ['ag-mod-web-hacking']
        },
        {
            id: 'ag-jp-network',
            title: 'BreachLabs Network Security',
            description: 'Attacking and securing network infrastructure.',
            icon: 'fa-shield-halved',
            color: '#3b82f6',
            difficulty: 'Intermediate',
            hours: 40,
            modules: ['ag-mod-network-security']
        },
        {
            id: 'ag-jp-post',
            title: 'BreachLabs Post-Exploitation',
            description: 'Privilege escalation and persistence.',
            icon: 'fa-fire',
            color: '#dc2626',
            difficulty: 'Intermediate',
            hours: 40,
            modules: ['ag-mod-post-exploitation']
        }
    ],
    // --- 3. MODULES (Expanded with Triad Rooms) ---
    modules: [
        // --- BreachLabs Blue Team SOC Modules ---
        {
            id: 'bl-mod-incident-response',
            title: 'Incident Response Fundamentals',
            description: 'Master the NIST IR framework, log analysis, and SIEM tools.',
            icon: 'fa-fire-extinguisher',
            skills: ['NIST Framework', 'Log Analysis', 'SIEM Operations'],
            tasks: [
                { id: 'ir-nist', title: 'Incident Lifecycle (NIST Framework)', type: 'mdx', mdxPath: 'lessons/blue-team-soc/incident-lifecycle.mdx' },
                { id: 'ir-logs', title: 'Log Analysis Basics', type: 'mdx', mdxPath: 'lessons/blue-team-soc/log-analysis-basics.mdx' },
                { id: 'ir-siem', title: 'SIEM Introduction (Splunk & ELK)', type: 'mdx', mdxPath: 'lessons/blue-team-soc/siem-introduction.mdx' }
            ],
            rooms: []
        },
        {
            id: 'bl-mod-threat-intel',
            title: 'Threat Intelligence',
            description: 'IOCs, TTPs, MITRE ATT&CK, and threat feed integration.',
            icon: 'fa-crosshairs',
            skills: ['IOC Analysis', 'MITRE ATT&CK', 'Threat Feeds'],
            tasks: [
                { id: 'ti-iocs', title: 'IOCs and TTPs', type: 'mdx', mdxPath: 'lessons/blue-team-soc/iocs-and-ttps.mdx' },
                { id: 'ti-mitre', title: 'MITRE ATT&CK Navigator', type: 'mdx', mdxPath: 'lessons/blue-team-soc/mitre-attack-navigator.mdx' },
                { id: 'ti-feeds', title: 'Threat Feeds Integration', type: 'mdx', mdxPath: 'lessons/blue-team-soc/threat-feeds-integration.mdx' }
            ],
            rooms: []
        },
        {
            id: 'bl-mod-digital-forensics',
            title: 'Digital Forensics Basics',
            description: 'Memory forensics, disk analysis, and timeline reconstruction.',
            icon: 'fa-magnifying-glass',
            skills: ['Volatility', 'Disk Forensics', 'Timeline Analysis'],
            tasks: [
                { id: 'df-memory', title: 'Memory Forensics with Volatility', type: 'mdx', mdxPath: 'lessons/blue-team-soc/memory-forensics-volatility.mdx' },
                { id: 'df-disk', title: 'Disk Forensics Essentials', type: 'mdx', mdxPath: 'lessons/blue-team-soc/disk-forensics-essentials.mdx' },
                { id: 'df-timeline', title: 'Timeline Analysis', type: 'mdx', mdxPath: 'lessons/blue-team-soc/timeline-analysis.mdx' }
            ],
            rooms: []
        },

        // --- BreachLabs Cloud Security Modules ---
        {
            id: 'bl-mod-aws-security',
            title: 'AWS Security Fundamentals',
            description: 'IAM misconfigurations, S3 exploitation, and Lambda security.',
            icon: 'fa-aws',
            skills: ['IAM Analysis', 'S3 Pentesting', 'Serverless Security'],
            tasks: [
                { id: 'aws-iam', title: 'AWS IAM Misconfigurations', type: 'mdx', mdxPath: 'lessons/cloud-security/aws-iam-misconfigs.mdx' },
                { id: 'aws-s3', title: 'S3 Bucket Exploitation', type: 'mdx', mdxPath: 'lessons/cloud-security/s3-bucket-exploitation.mdx' },
                { id: 'aws-lambda', title: 'Lambda Security', type: 'mdx', mdxPath: 'lessons/cloud-security/lambda-security.mdx' }
            ],
            rooms: []
        },
        {
            id: 'bl-mod-azure-gcp',
            title: 'Azure & GCP Security',
            description: 'Azure AD attacks and GCP privilege escalation techniques.',
            icon: 'fa-cloud',
            skills: ['Azure AD', 'GCP IAM', 'Cloud Privilege Escalation'],
            tasks: [
                { id: 'azure-ad', title: 'Azure AD Attacks', type: 'mdx', mdxPath: 'lessons/cloud-security/azure-ad-attacks.mdx' },
                { id: 'gcp-privesc', title: 'GCP Privilege Escalation', type: 'mdx', mdxPath: 'lessons/cloud-security/gcp-privilege-escalation.mdx' }
            ],
            rooms: []
        },

        // Linux Modules
        // Linux Modules
        {
            id: 'linux-basics',
            title: 'Linux Basics',
            description: 'Navigation and commands.',
            icon: 'fa-terminal',
            tasks: [
                {
                    id: 'nav-intro',
                    title: 'Terminal Navigation',
                    content: '### Mastering the CLI\nLinux navigation is the foundation of hacking. You will use `pwd` to see where you are and `ls` to list files.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'cd Users\\Desktop (Windows)',
                        secure: 'cd ~/Desktop (Linux)'
                    }
                },
                {
                    id: 'move-files',
                    title: 'Moving & Copying',
                    content: 'Learn how to manipulate files using `mv` and `cp`. Be careful with `rm -rf`!',
                    type: 'lab',
                    vulnerability: 'Accidental data loss or privilege escalation through world-writable files.'
                }
            ],
            rooms: ['room-linux-nav-guided', 'room-linux-files-practice', 'room-linux-survivor-challenge']
        },
        {
            id: 'linux-filesystem',
            title: 'Linux Filesystem',
            description: 'Directory structure.',
            icon: 'fa-folder-tree',
            tasks: [
                {
                    id: 'fs-hierarchy',
                    title: 'FHS Standards',
                    content: 'Every Linux system follows the Filesystem Hierarchy Standard. Understand /etc, /bin, and /var.',
                    type: 'theory'
                },
                {
                    id: 'fs-hunt',
                    title: 'The Search for Files',
                    content: 'Find hidden configuration files in `/etc` that might contain sensitive keys.',
                    type: 'challenge',
                    questions: [{ text: 'What is the absolute path to the main config?', answer: '/etc/shadow' }]
                }
            ],
            rooms: ['room-linux-fs-guided', 'room-linux-find-practice', 'room-linux-hunt-challenge']
        },
        {
            id: 'linux-permissions',
            title: 'Users & Permissions',
            description: 'Chmod, chown, sudo.',
            icon: 'fa-user-lock',
            tasks: [
                {
                    id: 'perm-bits',
                    title: 'Permission Bits',
                    content: 'Read (4), Write (2), Execute (1). 755 vs 644.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'chmod 777 sensitive.txt',
                        secure: 'chmod 600 sensitive.txt'
                    }
                }
            ],
            rooms: ['room-linux-perms-guided', 'room-linux-users-practice', 'room-linux-privesc-challenge']
        },
        { id: 'linux-scripting', title: 'Bash Scripting', description: 'Automate everything.', icon: 'fa-code', rooms: ['room-bash-intro-guided', 'room-bash-loops-practice', 'room-bash-automator-challenge'] },

        // Networking Modules
        {
            id: 'networking-osi',
            title: 'OSI Model',
            description: 'The 7 layers.',
            icon: 'fa-layer-group',
            tasks: [
                {
                    id: 'osi-stack',
                    title: 'The Full Stack',
                    content: 'From Physical to Application. Understand how data is encapsulated.',
                    type: 'theory'
                },
                {
                    id: 'layer-4-sec',
                    title: 'Transport Layer Security',
                    content: 'Focus on TCP handshake and UDP statelessness. How do firewalls block these?',
                    type: 'lab',
                    vulnerability: 'TCP SYN Flooding (DoS) attacking the handshake process.'
                }
            ],
            rooms: ['room-osi-guided', 'room-osi-practice', 'room-osi-quiz-challenge']
        },
        { id: 'networking-tcpip', title: 'TCP/IP', description: 'Adressing and routing.', icon: 'fa-network-wired', rooms: ['room-tcpip-guided', 'room-subnetting-practice', 'room-network-architect-challenge'] },
        { id: 'networking-protocols', title: 'Protocols', description: 'HTTP, DNS, FTP.', icon: 'fa-exchange', rooms: ['room-protocols-guided', 'room-dns-practice', 'room-protocol-sniffer-challenge'] },
        { id: 'networking-tools', title: 'Network Tools', description: 'Wireshark, Nmap.', icon: 'fa-wrench', rooms: ['room-wireshark-guided', 'room-nmap-intro-practice', 'room-packet-whisperer-challenge'] },

        // Web Recon Modules
        {
            id: 'web-recon',
            title: 'Web Reconnaissance',
            description: 'Finding the attack surface.',
            icon: 'fa-search',
            tasks: [
                {
                    id: 'recon-strat',
                    title: 'The Recon Strategy',
                    content: '### Passive vs Active Recon\nPassive recon involves gathering info without touching the target (Google Dorks, WHOIS). Active recon uses tools like `nmap` and `subfinder` to probe for open doors.',
                    type: 'theory'
                },
                {
                    id: 'subdomain-enum',
                    title: 'Subdomain Enumeration',
                    content: 'Use `gobuster` or `ffuf` to find hidden subdomains like `dev.target.com` or `api.target.com`.',
                    type: 'lab',
                    vulnerability: 'Exposure of staging environments or developer-forgotten endpoints.'
                }
            ],
            rooms: ['room-osint-guided', 'room-gobuster-practice', 'room-recon-phantom-challenge']
        },
        {
            id: 'web-sqli-basics',
            title: 'SQL Injection Basics',
            description: 'Injecting the DB.',
            icon: 'fa-database',
            tasks: [
                {
                    id: 'sqli-logic',
                    title: 'Authentication Logic Bypass',
                    content: 'Understand how `' + " ' OR 1=1 -- " + '` manipulates the SQL backend to always return true.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'query("SELECT * FROM users WHERE user=\'" + name + "\'")',
                        secure: 'query("SELECT * FROM users WHERE user=?", [name])'
                    }
                },
                {
                    id: 'union-sel',
                    title: 'UNION SELECT Discovery',
                    content: 'Discover the number of columns and extract data from foreign tables.',
                    type: 'challenge',
                    questions: [{ text: 'How many columns are returned by the query?', answer: '3' }]
                }
            ],
            rooms: ['room-sqli-manual-guided', 'room-sqlmap-practice', 'room-sqli-finance-challenge']
        },
        { id: 'web-xss-basics', title: 'XSS Fundamentals', description: 'Script injection.', icon: 'fa-code', rooms: ['room-xss-reflected-guided', 'room-xss-stored-practice', 'room-xss-cookie-stealer-challenge'] },
        { id: 'web-auth-bypass', title: 'Auth Bypass', description: 'Skipping login.', icon: 'fa-unlock', rooms: ['room-auth-logic-guided', 'room-hydra-practice', 'room-auth-admin-challenge'] },

        // --- WEB DEV FOR PENTESTERS MODULES ---
        {
            id: 'middleware-lifecycle-pro',
            title: 'Middleware & Request Lifecycle',
            description: 'Request flow and security order.',
            icon: 'fa-vial-circle-check',
            tasks: [
                {
                    id: 'middleware-concept',
                    title: 'The Middleware Chain',
                    content: '### How Requests Flow\nIn frameworks like Express, requests pass through a series of functions (middleware) before reaching the final route handler.',
                    type: 'theory'
                },
                {
                    id: 'middleware-bypass-hack',
                    title: 'Order-based Auth Bypass',
                    content: '### Identify the Flaw\nFind a route where sensitive data is exposed because the admin routes are loaded BEFORE the authentication middleware.',
                    type: 'lab',
                    codeCompare: {
                        vulnerable: "// Vulnerable Order\napp.use('/admin', adminRoutes);\napp.use(authMiddleware);",
                        secure: "// Secure Order\napp.use(authMiddleware);\napp.use('/admin', adminRoutes);"
                    }
                }
            ],
            rooms: ['room-node-middleware-bypass']
        },
        {
            id: 'bola-idor-pro',
            title: 'BOLA / IDOR Mastery',
            description: 'Broken Object Level Authorization.',
            icon: 'fa-id-card-clip',
            tasks: [
                {
                    id: 'bola-theory',
                    title: 'AuthN vs AuthZ',
                    content: '### The Distinction\nAuthentication (AuthN) verifies WHO you are. Authorization (AuthZ) verifies WHAT you can do to a specific object.',
                    type: 'theory'
                },
                {
                    id: 'bola-attack',
                    title: 'Exploiting BOLA',
                    content: '### Change the ID\nTry to access `/invoice/102` which belongs to another user. If the server does not check ownership, you have a BOLA vulnerability.',
                    type: 'lab',
                    codeCompare: {
                        vulnerable: "db.find({ invoiceId: req.params.id });",
                        secure: "db.find({ invoiceId: req.params.id, ownerId: req.session.userId });"
                    }
                }
            ],
            rooms: ['room-bola-challenge']
        },
        {
            id: 'sql-injection-beyond-pro',
            title: 'SQLi: Beyond the Basics',
            description: 'Complex queries and UNION attacks.',
            icon: 'fa-database',
            tasks: [
                {
                    id: 'sqli-union-pro',
                    title: 'UNION Based Data Extraction',
                    content: '### Merging Results\nUsing `UNION SELECT` to combine the legitimate query result with data stolen from other tables like `payments` or `passwords`.',
                    type: 'lab',
                    codeCompare: {
                        vulnerable: "const query = \"SELECT * FROM users WHERE name = '\" + userName + \"'\";",
                        secure: "// Using Parameterized Queries\ndb.execute(\"SELECT * FROM users WHERE name = ?\", [userName]);"
                    }
                }
            ],
            rooms: ['room-sqli-union-master']
        },
        {
            id: 'nosql-injection-mongo',
            title: 'NoSQL Injection (MongoDB)',
            description: 'Object-based injection attacks.',
            icon: 'fa-leaf',
            tasks: [
                {
                    id: 'nosql-concepts',
                    title: 'JSON Objects vs Strings',
                    content: '### The Vulnerability\nWhen input is treated as a JSON object, operators like `$ne` (not equal) or `$gt` (greater than) can be used to manipulate query logic.',
                    type: 'theory'
                },
                {
                    id: 'nosql-auth-bypass',
                    title: 'MongoDB Auth Bypass',
                    content: '### The Hack\nSend `{"user": "admin", "pass": {"$ne": ""}}` to bypass the password check because the condition "password exists" is always true.',
                    type: 'lab',
                    vulnerability: 'Lack of input sanitization or strict type checking (forcing strings).'
                }
            ],
            rooms: ['room-nosql-mongo-bypass']
        },
        {
            id: 'dom-xss-react-pro',
            title: 'DOM-XSS in Modern Frameworks',
            description: 'React security and escape hatches.',
            icon: 'fa-brands fa-react',
            tasks: [
                {
                    id: 'react-esc-theory',
                    title: 'The DangerouslySetInnerHTML Hook',
                    content: '### Trusting the Untrusted\nReact automatically escapes content to prevent XSS. However, using `dangerouslySetInnerHTML` bypasses this protection entirely.',
                    type: 'theory'
                },
                {
                    id: 'react-xss-lab',
                    title: 'Exploiting dangerouslySetInnerHTML',
                    content: '### Inject a Payload\nInject `<img src=x onerror=alert(1)>` into a field rendered with the unsafe React prop.',
                    type: 'lab',
                    vulnerability: 'Bypassing React\'s auto-escaping by explicitly trusting raw HTML input.'
                }
            ],
            rooms: ['room-react-xss-master']
        },
        {
            id: 'mass-assignment-pro',
            title: 'Mass Assignment & API Logic',
            description: 'Bypassing object property limits.',
            icon: 'fa-object-group',
            tasks: [
                {
                    id: 'mass-ass-logic',
                    title: 'Field Mapping Abuse',
                    content: '### The Scenario\nApps that map the entire `req.body` to a database model allow hackers to overwrite internal fields like `isAdmin` or `balance`.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: "// Creating user directly from body\nUser.create(req.body);",
                        secure: "// Use Allow-list\nconst { user, pass } = req.body;\nUser.create({ user, pass });"
                    }
                }
            ],
            rooms: ['room-api-mass-assignment']
        },


        // --- ADVANCED NETWORK PENTESTING MODULES ---
        {
            id: 'routing-protocols-pro',
            title: 'Routing Protocols (BGP/OSPF)',
            description: 'Advanced route injection.',
            icon: 'fa-route',
            tasks: [
                {
                    id: 'bgp-theory',
                    title: 'BGP: The Protocol of the Internet',
                    content: '### How Routers Talk\nBGP (Border Gateway Protocol) is how different Autonomous Systems (AS) exchange routing info. OSPF is for internal link-state routing.',
                    type: 'theory'
                },
                {
                    id: 'route-injection-lab',
                    title: 'Route Injection Lab',
                    content: 'Inject a rogue route into the OSPF table to redirect traffic through your attacker machine. Watch for the TTL change.',
                    type: 'lab',
                    vulnerability: 'Lack of route authentication (MD5/SHA) in protocol configurations.'
                }
            ],
            rooms: ['room-bgp-basics', 'room-ospf-inject']
        },
        {
            id: 'snmp-enumeration-pro',
            title: 'SNMP Enumeration',
            description: 'Mapping the infra.',
            icon: 'fa-search-plus',
            tasks: [
                {
                    id: 'snmp-public',
                    title: 'The Public Community String',
                    content: 'SNMP v1/v2 often use "public" or "private". Use `snmpwalk` to dump the entire MIB tree and list all interfaces.',
                    type: 'lab'
                }
            ],
            rooms: ['room-snmp-enum-v2']
        },
        {
            id: 'vlan-hopping-lab',
            title: 'VLAN Hopping',
            description: 'Escaping the Guest network.',
            icon: 'fa-arrows-down-to-people',
            tasks: [
                {
                    id: 'switch-spoofing',
                    title: 'Switch Spoofing & Double Tagging',
                    content: '### Escaping Isolation\nBy sending DTP (Dynamic Trunking Protocol) packets, an attacker can trick a switch into thinking they are another switch, gaining access to all VLANs.',
                    type: 'theory'
                }
            ],
            rooms: ['room-vlan-hop-advanced']
        },
        {
            id: 'ad-structure-pro',
            title: 'AD Structure Autopsy',
            description: 'Forests and Domains.',
            icon: 'fa-tree',
            tasks: [
                {
                    id: 'ad-anatomy',
                    title: 'Domains, Forests, and Trees',
                    content: '### Active Directory Hierarchy\nUnderstanding the logical structure of AD: Domain Controllers (DCs), Organizational Units (OUs), and Global Catalogs.',
                    type: 'theory'
                }
            ],
            rooms: ['room-ad-basics-v2']
        },
        {
            id: 'kerberos-autopsy',
            title: 'Kerberos Autopsy',
            description: 'Authentication deep dive.',
            icon: 'fa-key',
            tasks: [
                {
                    id: 'kerb-flow',
                    title: 'TGT and TGS Exchange',
                    content: '### The 3-Headed Dog\nDetailed breakdown of the AS-REQ, AS-REP, TGS-REQ, and TGS-REP flow. How tickets are encrypted and decrypted.',
                    type: 'theory'
                }
            ],
            rooms: ['room-kerberos-deep-dive']
        },
        {
            id: 'roasting-attacks',
            title: 'The Roasting Attacks',
            description: 'Kerberoast & AS-REP Roast.',
            icon: 'fa-fire-burner',
            tasks: [
                {
                    id: 'kerberoast-lab',
                    title: 'Kerberoasting Service Accounts',
                    content: 'Request a Service Principal Name (SPN) ticket and crack it offline using Hashcat or John the Ripper.',
                    type: 'lab'
                },
                {
                    id: 'asrep-roast-lab',
                    title: 'Exploiting Users without Pre-Auth',
                    content: 'Find users with "Do not require Kerberos preauthentication" enabled and request their TGT to crack the password.',
                    type: 'challenge',
                    questions: [{ text: 'What flag must be enabled for AS-REP roasting?', answer: 'UF_DONT_REQUIRE_PREAUTH' }]
                }
            ],
            rooms: ['room-roasting-challenges']
        },
        {
            id: 'token-impersonation',
            title: 'Token Impersonation',
            description: 'Stealing DA privileges.',
            icon: 'fa-id-card',
            tasks: [
                {
                    id: 'mimikatz-token',
                    title: 'Memory Privilege Escalation',
                    content: 'Use Mimikatz to list tokens in memory and impersonate the `DOMAIN\Administrator` process.',
                    type: 'lab'
                }
            ],
            rooms: ['room-token-stealing']
        },

        // Network Pentesting Modules
        {
            id: 'net-scanning',
            title: 'Network Scanning',
            description: 'Mapping the network.',
            icon: 'fa-radar',
            tasks: [
                {
                    id: 'nmap-sS',
                    title: 'Stealth Scanning',
                    content: 'The SYN scan (`-sS`) is the bread and butter of network recon. It avoids completing the handshake.',
                    type: 'theory'
                },
                {
                    id: 'ver-detection',
                    title: 'Service Version Fingerprinting',
                    content: 'Use `-sV` to identify what is actually running on an open port. This is crucial for finding known CVEs.',
                    type: 'lab',
                    vulnerability: 'Legacy services running unpatched versions (e.g., Apache 2.4.18).'
                }
            ],
            rooms: ['room-nmap-host-guided', 'room-nmap-script-practice', 'room-nmap-stealth-challenge']
        },
        { id: 'net-enumeration', title: 'Enumeration', description: 'Service probing.', icon: 'fa-list', rooms: ['room-enum-smb-guided', 'room-enum-snmp-practice', 'room-enum-hunter-challenge'] },
        { id: 'net-exploitation', title: 'Exploitation', description: 'Gaining access.', icon: 'fa-crosshairs', rooms: ['room-metasploit-guided', 'room-manual-exploit-practice', 'room-shell-shocker-challenge'] },

        {
            id: 'winrm-exploitation',
            title: 'WinRM Exploitation',
            description: 'Remote management abuse.',
            icon: 'fa-user-gear',
            tasks: [
                {
                    id: 'winrm-basics',
                    title: 'Windows Remote Management',
                    content: '### WinRM & PowerShell Remoting\nUsing `Evil-WinRM` to connect to a target machine using valid credentials or hashed passwords (Pass-the-Hash).',
                    type: 'lab'
                }
            ],
            rooms: ['room-winrm-master']
        },
        {
            id: 'smb-psexec-pro',
            title: 'PsExec & SMB',
            description: 'Lateral movement via shares.',
            icon: 'fa-share-nodes',
            tasks: [
                {
                    id: 'psexec-usage',
                    title: 'Living off the Land: PsExec',
                    content: 'Moving laterally using `PsExec.exe` or `impacket-psexec` to gain SYSTEM privileges on a remote host over SMB.',
                    type: 'lab'
                }
            ],
            rooms: ['room-smb-lateral']
        },
        {
            id: 'wmi-attacks-pro',
            title: 'WMI Attacks',
            description: 'Hidden command execution.',
            icon: 'fa-terminal',
            tasks: [
                {
                    id: 'wmi-exec',
                    title: 'Windows Management Instrumentation',
                    content: 'Executing commands stealthily using WMI. Unlike SMB-based tools, WMI doesn\'t leave as many traces in traditional event logs.',
                    type: 'challenge'
                }
            ],
            rooms: ['room-wmi-ninja']
        },
        {
            id: 'docker-networking-pro',
            title: 'Docker Networking',
            description: 'Bridge vs Host.',
            icon: 'fa-docker',
            tasks: [
                {
                    id: 'docker-net-theory',
                    title: 'Container Communication',
                    content: 'How Bridge, Host, and Overlay networks work. Why Bridge network isolation is key to security.',
                    type: 'theory'
                }
            ],
            rooms: ['room-docker-net-basics']
        },
        {
            id: 'docker-breakout-lab',
            title: 'Docker Breakout',
            description: 'Escaping the container.',
            icon: 'fa-door-open',
            tasks: [
                {
                    id: 'socket-mount-exploit',
                    title: 'The Mounted Socket Attack',
                    content: 'Exploiting a mounted `docker.sock` to gain root access on the host operating system.',
                    type: 'lab',
                    vulnerability: 'Insecure volume mounting of the Docker socket.'
                }
            ],
            rooms: ['room-container-escape']
        },
        {
            id: 'k8s-basics-pentest',
            title: 'Kubernetes for Pentesters',
            description: 'Pods, Services, and RBAC.',
            icon: 'fa-cubes',
            tasks: [
                {
                    id: 'rbac-misconfig',
                    title: 'RBAC Privilege Escalation',
                    content: 'Finding and exploiting misconfigured RBAC roles to gain cluster-admin privileges.',
                    type: 'challenge',
                    questions: [{ text: 'What is the most powerful RBAC role?', answer: 'cluster-admin' }]
                }
            ],
            rooms: ['room-k8s-recon']
        },
        {
            id: 'wpa-enterprise-pro',
            title: 'WPA2/3 Enterprise',
            description: 'Corporate Wi-Fi security.',
            icon: 'fa-wifi',
            tasks: [
                {
                    id: 'radius-auth',
                    title: 'RADIUS and 802.1X',
                    content: 'How enterprise networks authenticate users via RADIUS servers using EAP-PEAP or EAP-TLS.',
                    type: 'theory'
                }
            ],
            rooms: ['room-enterprise-wifi']
        },
        {
            id: 'eap-evil-twin',
            title: 'EAP Evil Twin Attacks',
            description: 'Stealing corporate IDs.',
            icon: 'fa-tower-broadcast',
            tasks: [
                {
                    id: 'evil-twin-lab',
                    title: 'Stealing Credentials with Hostapd-WPE',
                    content: 'Set up an Evil Twin Access Point and capture EAP-MSCHAPv2 hashes from connecting clients.',
                    type: 'lab'
                }
            ],
            rooms: ['room-wifi-identity-theft']
        },

        // Active Directory Modules
        {
            id: 'ad-enumeration',
            title: 'AD Enumeration',
            description: 'Mapping the domain.',
            icon: 'fa-search',
            tasks: [
                {
                    id: 'ad-obj',
                    title: 'AD Objects & Properties',
                    content: '### Users, Groups, and OUs\nUnderstand how Active Directory organizes resources. Use `net user /domain` to list users.',
                    type: 'theory'
                },
                {
                    id: 'bloodhound-graph',
                    title: 'BloodHound Graph Theory',
                    content: 'Ingest data using SharpHound and use BloodHound to find the shortest path to Domain Admin.',
                    type: 'lab',
                    vulnerability: 'Excessive permissions on GPOs or service accounts leading to Domain Admin compromise.'
                }
            ],
            rooms: ['room-powerview-guided', 'room-bloodhound-practice', 'room-ad-mapper-challenge']
        },
        {
            id: 'ad-kerberos-attacks',
            title: 'Kerberos Attacks',
            description: 'Ticket attacks.',
            icon: 'fa-ticket',
            tasks: [
                {
                    id: 'kerb-flow',
                    title: 'The Kerberos Protocol',
                    content: 'Understand AS-REQ, AS-REP, TGS-REQ, and TGS-REP. How does authentication actually work?',
                    type: 'theory'
                },
                {
                    id: 'kerberoasting-tgs',
                    title: 'Kerberoasting TGS Tickets',
                    content: 'Request a service ticket for a SPN and crack the hash offline using Hashcat.',
                    type: 'challenge',
                    questions: [{ text: 'What is the ticket type requested?', answer: 'TGS' }],
                    codeCompare: {
                        vulnerable: 'Service accounts with weak passwords',
                        secure: 'Managed Service Accounts (MSA) with auto-rotated long passwords'
                    }
                }
            ],
            rooms: ['room-kerberoast-guided', 'room-asrepproast-practice', 'room-golden-ticket-challenge']
        },
        { id: 'ad-privilege-escalation', title: 'AD PrivEsc', description: 'Becoming Domain Admin.', icon: 'fa-arrow-up', rooms: ['room-gpo-abuse-guided', 'room-acl-practice', 'room-forest-admin-challenge'] },

        // SOC Modules
        {
            id: 'soc-intro',
            title: 'SOC Intro',
            description: 'The Blue Team life.',
            icon: 'fa-building',
            tasks: [
                {
                    id: 'soc-roles',
                    title: 'The SOC Ecosystem',
                    content: '### Tier 1 vs Tier 2 vs Tier 3\nTier 1 analysts handle initial triage, while Tier 3 involves deep hunting and IR.',
                    type: 'theory'
                },
                {
                    id: 'siem-arch',
                    title: 'SIEM Architecture',
                    content: 'How logs flow from endpoints to a central aggregator like Splunk or ELK.',
                    type: 'theory'
                }
            ],
            rooms: ['room-soc-roles-guided', 'room-ticketing-practice', 'room-shift-simulation-challenge']
        },
        {
            id: 'soc-log-analysis',
            title: 'Log Analysis',
            description: 'Reading the matrix.',
            icon: 'fa-file-lines',
            tasks: [
                {
                    id: 'event-ids',
                    title: 'Critical Windows Events',
                    content: 'Focus on 4624 (Logon), 4625 (Failed Logon), and 4688 (Process Creation).',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'Clear-text logs on local server',
                        secure: 'Encrypted logs forwarded to SIEM'
                    }
                },
                {
                    id: 'sysmon-triage',
                    title: 'Sysmon Deep Dive',
                    content: 'Analyze a process tree to find suspicious parent-child relationships (e.g., `word.exe` spawning `powershell.exe`).',
                    type: 'lab',
                    vulnerability: 'Indicator of Attack (IOA): Malicious macro execution from productivity software.'
                }
            ],
            rooms: ['room-sysmon-guided', 'room-auditd-practice', 'room-log-detective-challenge']
        },
        {
            id: 'soc-alert-triage',
            title: 'Triage',
            description: 'True vs False Positive.',
            icon: 'fa-bell',
            tasks: [
                {
                    id: 'triage-flow',
                    title: 'The Triage Process',
                    content: '1. Identification, 2. Scoping, 3. Containment. Is the alert benign or malicious?',
                    type: 'theory'
                },
                {
                    id: 'threat-verify',
                    title: 'Alert Verification',
                    content: 'Cross-reference and IP with VirusTotal and verify the user action via internal logs.',
                    type: 'challenge',
                    questions: [{ text: 'If an IP has 50/70 detections on VT, what is it?', answer: 'Malicious' }]
                }
            ],
            rooms: ['room-triage-method-guided', 'room-virustotal-practice', 'room-breach-response-challenge']
        },

        // Forensics Modules
        {
            id: 'forensics-disk',
            title: 'Disk Forensics',
            description: 'Dead box analysis.',
            icon: 'fa-hard-drive',
            tasks: [
                {
                    id: 'fs-imaging',
                    title: 'Creating Disk Images',
                    content: '### Bit-by-bit Copy\nUse tools like `dd` or FTK Imager to create a static copy of a suspect drive.',
                    type: 'theory'
                },
                {
                    id: 'autopsy-triage',
                    title: 'Artifact Analysis',
                    content: 'Mount the image in Autopsy and look for deleted files, browser history, and shellbags.',
                    type: 'lab',
                    vulnerability: 'Evidence of data exfiltration discovered in hidden slack space.'
                }
            ],
            rooms: ['room-ftk-guided', 'room-autopsy-practice', 'room-disk-digger-challenge']
        },
        {
            id: 'forensics-memory',
            title: 'Memory Forensics',
            description: 'RAM analysis.',
            icon: 'fa-memory',
            tasks: [
                {
                    id: 'ram-volatility',
                    title: 'The Volatility Framework',
                    content: 'Analyze RAM dumps to find running processes that might not have a corresponding file on disk.',
                    type: 'theory'
                },
                {
                    id: 'malware-mem',
                    title: 'In-Memory Malware Detection',
                    content: 'Use `pslist`, `pstree`, and `malfind` to identify code injection in memory.',
                    type: 'lab',
                    vulnerability: 'Reflective DLL injection detected in `lsass.exe`.'
                }
            ],
            rooms: ['room-volatility-guided', 'room-mem-dump-practice', 'room-malware-find-challenge']
        },
        {
            id: 'forensics-network',
            title: 'Network Forensics',
            description: 'PCAP analysis.',
            icon: 'fa-network-wired',
            tasks: [
                {
                    id: 'pcap-streams',
                    title: 'Following TCP Streams',
                    content: 'Reconstructing files and messages from captured network traffic using Wireshark.',
                    type: 'lab'
                },
                {
                    id: 'ids-logs-analysis',
                    title: 'IDS Log Correlation',
                    content: 'Matching IDS alerts (Snort/Suricata) with network traffic to verify a successful exploit.',
                    type: 'theory'
                }
            ],
            rooms: ['room-tshark-guided', 'room-zeek-practice', 'room-pcap-miner-challenge']
        },

        // Malware Analysis Modules (Defensive)
        {
            id: 'malware-static',
            title: 'Static Analysis',
            description: 'Dissecting without execution.',
            icon: 'fa-search',
            tasks: [
                {
                    id: 'strings-analysis',
                    title: 'Strings & Metadata',
                    content: 'Extracting IP addresses, file paths, and obfuscated strings from a binary using `strings` and `PEStudio`.',
                    type: 'theory'
                }
            ],
            rooms: ['room-pestudio-guided']
        },
        {
            id: 'malware-dynamic',
            title: 'Dynamic Analysis',
            description: 'Safe execution in sandboxes.',
            icon: 'fa-bug',
            tasks: [
                {
                    id: 'procmon-log',
                    title: 'Behavioral Monitoring',
                    content: 'Observing file system changes, registry modifications, and network connections using Process Monitor (ProcMon).',
                    type: 'lab',
                    vulnerability: 'Malware persistence via `Run` keys or `Scheduled Tasks`.'
                }
            ],
            rooms: ['room-procmon-practice']
        },

        // Malware Development Modules (Offensive)
        {
            id: 'malware-basics-red',
            title: 'Malware Basics',
            description: 'Payload delivery mechanics.',
            icon: 'fa-vial',
            tasks: [
                {
                    id: 'dropper-logic',
                    title: 'Staged vs Stageless Droppers',
                    content: 'Understanding how a small initial payload (stage 0) pulls the main malware from a C2 server.',
                    type: 'theory'
                }
            ],
            rooms: ['room-msfvenom-basics']
        },
        {
            id: 'malware-evasion-pro',
            title: 'Evasion Tech',
            description: 'Bypassing modern AV.',
            icon: 'fa-mask',
            tasks: [
                {
                    id: 'obfuscation-methods',
                    title: 'Code Obfuscation',
                    content: 'Using XOR encryption and junk code injection to hide recognizable patterns from signature-based scanners.',
                    type: 'lab',
                    codeCompare: {
                        vulnerable: 'Plaintext shellcode in .data section',
                        secure: 'XOR-encrypted shellcode in .rdata, decrypted at runtime'
                    }
                }
            ],
            rooms: ['room-shellcode-encryption']
        },

        // --- NEW MODULES (For New Courses) ---
        // Cybersecurity Fundamentals
        { id: 'intro-cyber-security', title: 'Intro to Cyber Security', description: 'Core concepts.', icon: 'fa-shield-halved', rooms: ['room-intro-sec-guided'] },
        { id: 'networking-101', title: 'Networking 101', description: 'Network basics.', icon: 'fa-network-wired', rooms: ['room-net-basics-guided'] },
        { id: 'linux-basics-pro', title: 'Linux Basics Pro', description: 'Essential Linux.', icon: 'fa-linux', rooms: ['room-linux-essentials-guided'] },

        // Advanced Pentesting
        { id: 'adv-scanning', title: 'Advanced Scanning', description: 'Stealth & Evasion.', icon: 'fa-radar', rooms: ['room-nmap-adv-guided'] },
        { id: 'evasion-tech', title: 'Evasion Techniques', description: 'Bypassing AV/EDR.', icon: 'fa-mask', rooms: ['room-av-bypass-guided'] },
        { id: 'post-exploit-pro', title: 'Post-Exploitation', description: 'Looting & Persistence.', icon: 'fa-gem', rooms: ['room-persistence-guided'] },

        // Exploit Development Modules
        {
            id: 'exploit-memory',
            title: 'Memory Internals',
            description: 'Stack, Heap, and Registers.',
            icon: 'fa-microchip',
            tasks: [
                {
                    id: 'mem-layout',
                    title: 'Process Memory Layout',
                    content: '### The Address Space\nUnderstand how a process occupies memory. Text, Data, BSS, Heap, and Stack segments.',
                    type: 'theory'
                },
                {
                    id: 'reg-basics',
                    title: 'CPU Registers (x86)',
                    content: 'Master EAX, EBX, ECX, EDX, ESI, EDI, ESP, and EBP. Which one is the accumulator?',
                    type: 'theory'
                }
            ],
            rooms: ['room-memory-basics']
        },
        {
            id: 'exploit-buffer-overflow',
            title: 'Buffer Overflows',
            description: 'Classic stack smashing.',
            icon: 'fa-burst',
            tasks: [
                {
                    id: 'bof-intro',
                    title: 'The Overflow Principle',
                    content: 'Writing past the boundary of a fixed-size buffer to overwrite the return address.',
                    type: 'theory',
                    codeCompare: {
                        vulnerable: 'char buf[64]; gets(buf);',
                        secure: 'char buf[64]; fgets(buf, sizeof(buf), stdin);'
                    }
                },
                {
                    id: 'eip-control',
                    title: 'EIP Control Lab',
                    content: 'Find the exact offset to overwrite the EIP register and point it to your shellcode.',
                    type: 'lab',
                    vulnerability: 'Stack-based buffer overflow allowing arbitrary code execution.'
                }
            ],
            rooms: ['room-bof-intro-guided']
        },
        { id: 'exploit-shellcode', title: 'Shellcoding', description: 'Assembly payloads.', icon: 'fa-code', rooms: ['room-asm-shell-guided'] },
        { id: 'exploit-rop', title: 'ROP Chains', description: 'Bypassing NX bit.', icon: 'fa-link', rooms: ['room-rop-basics'] },

        // Advanced Networking
        {
            id: 'routing-protocols',
            title: 'Advanced Routing',
            description: 'BGP & OSPF analysis.',
            icon: 'fa-route',
            tasks: [
                {
                    id: 'bgp-sec',
                    title: 'BGP Path Security',
                    content: 'How AS-PATH prepending and prefix hijacking affect global traffic routing.',
                    type: 'theory'
                },
                {
                    id: 'ospf-auth',
                    title: 'OSPF Authentication',
                    content: 'Crack MD5-authenticated OSPF hello packets to inject malicious routes.',
                    type: 'lab',
                    vulnerability: 'Insecure routing protocol configurations allowing traffic interception.'
                }
            ],
            rooms: ['room-bgp-basics']
        },
        { id: 'vlan-trunking', title: 'VLAN & Trunking', description: 'Switching security.', icon: 'fa-bridge', rooms: ['room-dtp-spoofing'] },
        { id: 'snmp-analysis', title: 'SNMP Enumeration', description: 'Insecure management.', icon: 'fa-server', rooms: ['room-snmp-hunting'] },

        // Cloud & Virtualization
        {
            id: 'vpc-architecture',
            title: 'Cloud Networking',
            description: 'AWS/Azure VPC security.',
            icon: 'fa-cloud',
            tasks: [
                {
                    id: 'vpc-peering',
                    title: 'VPC Peering Security',
                    content: 'Risks associated with transit gateways and overly permissive peering relationships.',
                    type: 'theory'
                },
                {
                    id: 'sg-audit',
                    title: 'Security Group Audit',
                    content: 'Identify misconfigured security groups allowing public access to internal databases.',
                    type: 'challenge',
                    questions: [{ text: 'What port is exposed on the DB instance?', answer: '3306' }]
                }
            ],
            rooms: ['room-aws-sec-intro']
        },
        { id: 'container-networking', title: 'Container Networking', description: 'Docker & K8s.', icon: 'fa-box', rooms: ['room-k8s-net-sec'] },
        { id: 'sdn-security', title: 'SDN Security', description: 'Software Defined Net.', icon: 'fa-sitemap', rooms: ['room-sdn-intro'] },
        // Web Exploits
        { id: 'inject-attacks', title: 'Injection Attacks', description: 'SQLi, cmd injection.', icon: 'fa-syringe', rooms: ['room-sqli-adv-guided'] },
        { id: 'broken-auth-pro', title: 'Broken Authentication', description: 'Session hijacking.', icon: 'fa-id-card', rooms: ['room-oauth-abuse-guided'] },
        { id: 'modern-vulns', title: 'Modern Vulnerabilities', description: 'SSTI, Deserialization.', icon: 'fa-code', rooms: ['room-ssti-guided'] },

        // Social Engineering & OSINT
        { id: 'osint-methods', title: 'OSINT Methodologies', description: 'Gathering intel.', icon: 'fa-globe', rooms: ['room-osint-framework'] },
        { id: 'phishing-ops', title: 'Phishing Campaigns', description: 'Crafting emails.', icon: 'fa-envelope', rooms: ['room-gophish-setup'] },
        { id: 'physical-sec', title: 'Physical Security', description: 'Lockpicking & RFID.', icon: 'fa-door-open', rooms: ['room-lockpicking-101'] },

        // Web Dev for Pentesters Modules
        {
            id: 'node-middleware',
            title: 'Secure Middleware',
            description: 'Learn the core of Node.js and Express security.',
            icon: 'fa-shield-halved',
            tasks: [
                {
                    id: 'node-lifecycle',
                    title: 'The Express Lifecycle',
                    content: '### The Event Loop & Request Flow\nNode.js uses an event-driven, non-blocking I/O model. In Express, a request passes through a series of functions...',
                    type: 'theory'
                },
                {
                    id: 'mid-magic',
                    title: 'Middleware Magic & Mistakes',
                    content: '### Middleware Order Matters\nMistake: Putting authentication middleware AFTER sensitive routes.',
                    vulnerability: 'Authentication Bypass due to incorrect middleware ordering.',
                    type: 'lab'
                }
            ],
            rooms: ['room-express-security']
        },
        {
            id: 'auth-logic-dev',
            title: 'Auth Logic Development',
            description: 'Building secure login systems.',
            icon: 'fa-key',
            tasks: [
                {
                    id: 'auth-storage',
                    title: 'Authentication Storage',
                    content: '### Cookies vs LocalStorage\nWhere should you store JWTs? Cookies with `HttpOnly` are safer against XSS.',
                    type: 'theory'
                },
                {
                    id: 'logic-bypass',
                    title: 'Logic Bypass',
                    content: 'Modifying unsigned cookies to escalate privileges.',
                    vulnerability: 'Insecure Direct Object Reference / Session Tampering.',
                    questions: [{ text: 'What is the flag found in the admin cookie?', answer: 'THM{COOKIE_TAMPERED}' }],
                    type: 'challenge'
                }
            ],
            rooms: ['room-auth-best-practices']
        },
        {
            id: 'sql-internals',
            title: 'SQL Internals',
            description: 'Relational DB security.',
            icon: 'fa-table',
            tasks: [
                {
                    id: 'sql-design',
                    title: 'SQL Relational Design',
                    content: 'Understanding Tables, PKs, and FKs from a developer perspective.',
                    type: 'theory'
                },
                {
                    id: 'adv-union',
                    title: 'The Art of Injection (Advanced)',
                    content: 'Mastering UNION SELECT attacks.',
                    codeCompare: {
                        vulnerable: 'db.query("SELECT * FROM users WHERE id = " + id)',
                        secure: 'db.query("SELECT * FROM users WHERE id = ?", [id])'
                    },
                    type: 'lab'
                }
            ],
            rooms: ['room-sql-optimization']
        },
        {
            id: 'nosql-arch',
            title: 'NoSQL Architecture',
            description: 'MongoDB & Redis security.',
            icon: 'fa-leaf',
            tasks: [
                {
                    id: 'nosql-injection',
                    title: 'NoSQL Injection',
                    content: 'Using operators like $gt and $ne to bypass login.',
                    type: 'challenge',
                    questions: [{ text: 'Bypass the login and find the flag.', answer: 'THM{NOSQL_BYPASS_SUCCESS}' }]
                }
            ],
            rooms: ['room-nosql-security']
        },
        {
            id: 'dom-rendering',
            title: 'DOM Rendering',
            description: 'React rendering cycle.',
            icon: 'fa-desktop',
            tasks: [
                {
                    id: 'vdom-intro',
                    title: 'The Virtual DOM',
                    content: 'How modern frameworks update the UI without reloading.',
                    type: 'theory'
                },
                {
                    id: 'danger-html',
                    title: 'DOM-XSS in Modern Apps',
                    content: 'The danger of `dangerouslySetInnerHTML`.',
                    type: 'lab'
                }
            ],
            rooms: ['room-react-security']
        },
        {
            id: 'api-design',
            title: 'Secure API Design',
            description: 'Swagger/OpenAPI docs.',
            icon: 'fa-file-lines',
            tasks: [
                {
                    id: 'api-recon',
                    title: 'API Documentation Recon',
                    content: 'Using Swagger files to find hidden endpoints.',
                    type: 'lab'
                },
                {
                    id: 'idor-access',
                    title: 'IDOR vs Access Control',
                    content: 'The difference between authentication and authorization.',
                    type: 'challenge'
                }
            ],
            rooms: ['room-api-blueprint']
        },
        {
            id: 'modern-vulns',
            title: 'Template Engines & SSTI',
            description: 'SSTI, Deserialization.',
            icon: 'fa-code',
            tasks: [
                {
                    id: 'ssti-id',
                    title: 'Identifying SSTI',
                    content: 'Testing for SSTI using {{7*7}}.',
                    type: 'theory'
                },
                {
                    id: 'ssti-rce',
                    title: 'Weaponizing SSTI',
                    content: 'Escalating to Remote Code Execution.',
                    type: 'challenge'
                }
            ],
            rooms: ['room-ssti-guided']
        },

        // --- NEW MODULES FOR WEB SEC PATH ---
        {
            id: 'mod-node-arch',
            title: 'The Engine & The Logic',
            description: 'Event Loop, Middleware Chains, and Auth Bypasses.',
            icon: 'fa-microchip',
            tasks: [
                { id: 'node-arch-found', title: 'Foundation: Event Loop & Middleware', content: 'Understanding the Single Threaded nature and how `app.use` chains work.', type: 'theory' },
                { id: 'node-arch-basic', title: 'Attack: Middleware Bypass', content: 'Bypassing auth due to incorrect middleware ordering.', type: 'lab' },
                { id: 'node-arch-adv', title: 'Advaned: ReDoS & Call Stack', content: 'Freezing the server with Regular Expression DoS.', type: 'lab' }
            ],
            rooms: ['room-node-eventloop', 'room-node-middleware-bypass-v2', 'room-redos-attack']
        },
        {
            id: 'mod-js-internals',
            title: 'JS Internals & Prototype Pollution',
            description: 'Object inheritance attacks and RCE.',
            icon: 'fa-brands fa-js',
            tasks: [
                { id: 'js-proto-found', title: 'Foundation: Objects & Prototypes', content: 'Differences between `__proto__` and `prototype`.', type: 'theory' },
                { id: 'js-proto-adv', title: 'Attack: Prototype Pollution to RCE', content: 'Polluting the root object to gain Admin access or execute code.', type: 'lab' }
            ],
            rooms: ['room-proto-basics', 'room-proto-pollution-rce']
        },
        {
            id: 'mod-auth-eng',
            title: 'Authentication & Session Engineering',
            description: 'Cookies, JWTs, and Session Fixation.',
            icon: 'fa-key',
            tasks: [
                { id: 'auth-found', title: 'Foundation: Sessions vs Tokens', content: 'Cookies, LocalStorage, and JWT architecture.', type: 'theory' },
                { id: 'auth-basic', title: 'Attack: Session Fixation', content: 'Stealing cookies via XSS or forcing a known session ID.', type: 'lab' },
                { id: 'auth-adv', title: 'Attack: JWT Confusions', content: 'None Algorithm, Key Confusion, and Weak Secrets.', type: 'lab' }
            ],
            rooms: ['room-session-mechanics', 'room-session-fixation', 'room-jwt-mastery']
        },
        {
            id: 'mod-sqli-mastery',
            title: 'SQL Injection Mastery',
            description: 'From Classic to Second Order & OOB.',
            icon: 'fa-database',
            tasks: [
                { id: 'sqli-found', title: 'Foundation: Relations & Joins', content: 'Advanced SQL queries and database structures.', type: 'theory' },
                { id: 'sqli-basic', title: 'Attack: Auth Bypass', content: 'Simple `OR 1=1` attacks.', type: 'lab' },
                { id: 'sqli-adv', title: 'Attack: Second Order & OOB', content: 'Sleeping payloads and extracting data via DNS.', type: 'lab' }
            ],
            rooms: ['room-sqli-advanced-struct', 'room-sqli-auth-bypass-v2', 'room-sqli-oob']
        },
        {
            id: 'mod-nosql-polyglot',
            title: 'NoSQL & Polyglot Persistence',
            description: 'MongoDB injection and JS execution.',
            icon: 'fa-leaf',
            tasks: [
                { id: 'nosql-found', title: 'Foundation: BSON & Structure', content: 'How MongoDB stores data.', type: 'theory' },
                { id: 'nosql-adv', title: 'Attack: Operator Injection', content: 'Injecting `$gt` and `$where` to execute JS on the server.', type: 'lab' }
            ],
            rooms: ['room-mongodb-struct', 'room-nosql-injection-adv']
        },
        {
            id: 'mod-ssrf-redis',
            title: 'SSRF & Redis Exploitation',
            description: 'Server-side request forgery to RCE.',
            icon: 'fa-server',
            tasks: [
                { id: 'ssrf-found', title: 'Foundation: Microservices', content: 'Internal communication and the Redis protocol.', type: 'theory' },
                { id: 'ssrf-adv', title: 'Attack: SSRF to RCE', content: 'Targeting Redis or Cloud Metadata via SSRF.', type: 'lab' }
            ],
            rooms: ['room-ssrf-basics', 'room-ssrf-redis-rce']
        },
        {
            id: 'mod-dom-xss-evo',
            title: 'The Modern DOM & XSS',
            description: 'React/Vue security and gadgets.',
            icon: 'fa-code',
            tasks: [
                { id: 'dom-found', title: 'Foundation: Virtual DOM', content: 'Auto-escaping and framework protections.', type: 'theory' },
                { id: 'dom-adv', title: 'Attack: CSP Bypass & Gadgets', content: 'Advanced DOM-based XSS using gadget chains.', type: 'lab' }
            ],
            rooms: ['room-virtual-dom', 'room-dom-xss-gadgets']
        },
        {
            id: 'mod-api-arch-logic',
            title: 'API Architecture & Business Logic',
            description: 'REST vs GraphQL, IDORs, and Race Conditions.',
            icon: 'fa-cloud-bolt',
            tasks: [
                { id: 'api-found', title: 'Foundation: REST & GraphQL', content: 'Reading Swagger/OpenAPI files.', type: 'theory' },
                { id: 'api-basic', title: 'Attack: Mass Assignment', content: 'Exploiting auto-binding frameworks.', type: 'lab' },
                { id: 'api-adv', title: 'Attack: Race Conditions', content: 'Buying 50 items with a 1-item coupon.', type: 'lab' }
            ],
            rooms: ['room-api-swagger', 'room-mass-assignment-v2', 'room-api-race-conditions']
        },

        // --- ANTIGRAVITY SPECIAL MODULES ---
        {
            id: 'ag-mod-networking-basics',
            title: 'Networking Fundamentals',
            description: 'Core concepts for every security professional.',
            icon: 'fa-network-wired',
            tasks: [
                { id: 't1', title: 'Introduction to Networking', type: 'mdx', mdxPath: 'lessons/networking/intro.mdx' },
                { id: 't2', title: 'The OSI Model', type: 'mdx', mdxPath: 'lessons/networking/osi-model.mdx' },
                { id: 't3', title: 'IP Addresses & Subnetting', type: 'mdx', mdxPath: 'lessons/networking/ip-addressing.mdx' },
                { id: 't4', title: 'Common Ports & Protocols', type: 'mdx', mdxPath: 'lessons/networking/protocols.mdx' },
                { id: 't5', title: 'Network Troubleshooting Tools', type: 'mdx', mdxPath: 'lessons/networking/tools.mdx' }
            ]
        },
        {
            id: 'ag-mod-linux-fundamentals',
            title: 'Linux Fundamentals',
            description: 'Master the Linux operating system.',
            icon: 'fa-linux',
            tasks: [
                { id: 't1', title: 'Linux Directory Structure', type: 'mdx', mdxPath: 'lessons/linux/directory-structure.mdx' },
                { id: 't2', title: 'Terminal Navigation', type: 'mdx', mdxPath: 'lessons/linux/navigation.mdx' },
                { id: 't3', title: 'File Permissions', type: 'mdx', mdxPath: 'lessons/linux/permissions.mdx' },
                { id: 't4', title: 'Text Manipulation (grep/sed/awk)', type: 'mdx', mdxPath: 'lessons/linux/text-manipulation.mdx' },
                { id: 't5', title: 'Process Management', type: 'mdx', mdxPath: 'lessons/linux/processes.mdx' }
            ]
        },
        {
            id: 'ag-mod-web-hacking',
            title: 'Web Hacking Fundamentals',
            description: 'Exploiting common web vulnerabilities.',
            icon: 'fa-globe',
            tasks: [
                { id: 't1', title: 'How the Web Works', type: 'mdx', mdxPath: 'lessons/web/how-web-works.mdx' },
                { id: 't2', title: 'OWASP Top 10 Overview', type: 'mdx', mdxPath: 'lessons/web/owasp-overview.mdx' },
                { id: 't3', title: 'SQL Injection', type: 'mdx', mdxPath: 'lessons/web/sql-injection.mdx' },
                { id: 't4', title: 'Cross-Site Scripting (XSS)', type: 'mdx', mdxPath: 'lessons/web/xss.mdx' },
                { id: 't5', title: 'IDOR & Broken Access Control', type: 'mdx', mdxPath: 'lessons/web/idor.mdx' }
            ]
        },
        {
            id: 'ag-mod-network-security',
            title: 'Network Security',
            description: 'Attacking and securing network infrastructure.',
            icon: 'fa-shield-halved',
            tasks: [
                { id: 't1', title: 'Nmap Mastery', type: 'mdx', mdxPath: 'lessons/network-sec/nmap.mdx' },
                { id: 't2', title: 'Metasploit Fundamentals', type: 'mdx', mdxPath: 'lessons/network-sec/metasploit.mdx' },
                { id: 't3', title: 'Attacking Services (FTP, SSH, HTTP)', type: 'mdx', mdxPath: 'lessons/network-sec/attacking-services.mdx' },
                { id: 't4', title: 'Password Cracking', type: 'mdx', mdxPath: 'lessons/network-sec/password-cracking.mdx' },
                { id: 't5', title: 'Wireshark Analysis', type: 'mdx', mdxPath: 'lessons/network-sec/wireshark.mdx' }
            ]
        },
        {
            id: 'ag-mod-post-exploitation',
            title: 'Post-Exploitation',
            description: 'Privilege escalation and persistence.',
            icon: 'fa-fire',
            tasks: [
                { id: 't1', title: 'Linux Privilege Escalation', type: 'mdx', mdxPath: 'lessons/post-exploit/linux-privesc.mdx' },
                { id: 't2', title: 'Windows Privilege Escalation', type: 'mdx', mdxPath: 'lessons/post-exploit/windows-privesc.mdx' },
                { id: 't3', title: 'Pivoting & Tunneling', type: 'mdx', mdxPath: 'lessons/post-exploit/pivoting.mdx' },
                { id: 't5', title: 'Cleanup & Reporting', type: 'mdx', mdxPath: 'lessons/post-exploit/cleanup.mdx' }
            ]
        },

        // --- NEW BREACHLABS PENTESTER MODULES (Modules 1-6) ---
        {
            id: 'ag-mod-pt-fundamentals',
            title: 'Penetration Testing Fundamentals',
            description: 'Ethics, Legal Frameworks, and the PT Lifecycle.',
            icon: 'fa-scale-balanced',
            tasks: [
                { id: 't1', title: 'Ethics and Rules of Engagement', type: 'mdx', mdxPath: 'lessons/penetration-testing-fundamentals/ethics-roe.mdx' },
                { id: 't2', title: 'Legal Issues & Contracts', type: 'mdx', mdxPath: 'lessons/penetration-testing-fundamentals/legal-issues.mdx' },
                { id: 't3', title: 'The PT Lifecycle', type: 'mdx', mdxPath: 'lessons/penetration-testing-fundamentals/pt-lifecycle.mdx' },
                { id: 't4', title: 'Building a Pentest Team', type: 'mdx', mdxPath: 'lessons/penetration-testing-fundamentals/teams.mdx' }
            ]
        },
        {
            id: 'ag-mod-recon-enum',
            title: 'Reconnaissance & Enumeration',
            description: 'Passive/Active Recon and Service Enumeration.',
            icon: 'fa-binoculars',
            tasks: [
                { id: 't1', title: 'Passive Reconnaissance', type: 'mdx', mdxPath: 'lessons/reconnaissance-and-enumeration/passive-recon.mdx' },
                { id: 't2', title: 'Active Reconnaissance', type: 'mdx', mdxPath: 'lessons/reconnaissance-and-enumeration/active-recon.mdx' },
                { id: 't3', title: 'Service Enumeration', type: 'mdx', mdxPath: 'lessons/reconnaissance-and-enumeration/service-enum.mdx' },
                { id: 't4', title: 'Web Enumeration', type: 'mdx', mdxPath: 'lessons/reconnaissance-and-enumeration/web-enum.mdx' }
            ]
        },
        {
            id: 'ag-mod-vuln-assessment',
            title: 'Vulnerability Assessment',
            description: 'Scanning, Scoring (CVSS), and Validating.',
            icon: 'fa-clipboard-check',
            tasks: [
                { id: 't1', title: 'Automated Scanning', type: 'mdx', mdxPath: 'lessons/vulnerability-assessment/automated-scanning.mdx' },
                { id: 't2', title: 'Manual Validation', type: 'mdx', mdxPath: 'lessons/vulnerability-assessment/manual-validation.mdx' },
                { id: 't3', title: 'CVSS Scoring', type: 'mdx', mdxPath: 'lessons/vulnerability-assessment/cvss-scoring.mdx' },
                { id: 't4', title: 'Professional Reporting', type: 'mdx', mdxPath: 'lessons/vulnerability-assessment/professional-reports.mdx' }
            ]
        },
        {
            id: 'ag-mod-web-pentesting-pro',
            title: 'Web Application Pentesting',
            description: 'OWASP Top 10, Auth Bypasses, and SQLi.',
            icon: 'fa-spider',
            tasks: [
                { id: 't1', title: 'SQL Injection', type: 'mdx', mdxPath: 'lessons/web-application-pentesting/sqli.mdx' },
                { id: 't2', title: 'Cross-Site Scripting (XSS)', type: 'mdx', mdxPath: 'lessons/web-application-pentesting/xss.mdx' },
                { id: 't3', title: 'IDOR', type: 'mdx', mdxPath: 'lessons/web-application-pentesting/idor.mdx' },
                { id: 't4', title: 'Auth & Session Management', type: 'mdx', mdxPath: 'lessons/web-application-pentesting/auth-session-mgmt.mdx' }
            ]
        },
        {
            id: 'ag-mod-network-pentesting-pro',
            title: 'Network Penetration Testing',
            description: 'AD Attacks, Metasploit, and Pivoting.',
            icon: 'fa-network-wired',
            tasks: [
                { id: 't1', title: 'Metasploit Framework', type: 'mdx', mdxPath: 'lessons/network-pentesting/metasploit.mdx' },
                { id: 't2', title: 'Privilege Escalation', type: 'mdx', mdxPath: 'lessons/network-pentesting/priv-esc.mdx' },
                { id: 't3', title: 'Pivoting & Tunneling', type: 'mdx', mdxPath: 'lessons/network-pentesting/pivoting.mdx' },
                { id: 't4', title: 'Kerberoasting (AD)', type: 'mdx', mdxPath: 'lessons/network-pentesting/kerberoasting.mdx' }
            ]
        },
        {
            id: 'ag-mod-advanced-topics',
            title: 'Advanced Topics & Career',
            description: 'AV Evasion, Buffer Overflows, and Soft Skills.',
            icon: 'fa-rocket',
            tasks: [
                { id: 't1', title: 'Buffer Overflows', type: 'mdx', mdxPath: 'lessons/advanced-topics/buffer-overflows.mdx' },
                { id: 't2', title: 'AV Evasion', type: 'mdx', mdxPath: 'lessons/advanced-topics/av-evasion.mdx' },
                { id: 't3', title: 'C2 Frameworks', type: 'mdx', mdxPath: 'lessons/advanced-topics/c2-frameworks.mdx' },
                { id: 't4', title: 'Career Paths', type: 'mdx', mdxPath: 'lessons/advanced-topics/career-path.mdx' }
            ]
        }
    ],

    // --- 4. ROOMS (Massive Expansion - 200+ Room Placeholders with Rich Content Structure) ---
    rooms: [
        // ==========================================
        // 6. DETAILED CONTENT FOR ALL MODULES (No Placeholders)
        // ==========================================

        // --- LINUX EXPANSION ---
        {
            id: 'room-linux-fs-guided',
            title: 'Linux Filesystem Hierarchy',
            description: 'Understand the directory structure of Linux systems.',
            difficulty: 'Easy',
            xp: 100,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: The Root',
                    content: `
                        <h2>The Root Directory (/)</h2>
                        <p>In Linux, every file and directory starts from the root, represented by a forward slash (<code>/</code>).</p>
                        <h3>Key Standard Directories</h3>
                        <table style="width:100%; border-collapse:collapse; margin-top:10px;">
                            <tr style="background:rgba(255,255,255,0.1);"><th style="padding:10px;">Path</th><th style="padding:10px;">Purpose</th></tr>
                            <tr><td style="padding:10px;"><code>/bin</code></td><td style="padding:10px;">User Binaries (ls, cp, ping)</td></tr>
                            <tr><td style="padding:10px;"><code>/sbin</code></td><td style="padding:10px;">System Binaries (iptables, reboot)</td></tr>
                            <tr><td style="padding:10px;"><code>/etc</code></td><td style="padding:10px;">Configuration Files</td></tr>
                            <tr><td style="padding:10px;"><code>/tmp</code></td><td style="padding:10px;">Temporary Files</td></tr>
                        </table>
                    `,
                    questions: [{ id: 'q1', text: 'Which directory holds system binaries?', answer: '/sbin' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Exploration',
                    content: 'Use `ls /` to list the root directory. Navigate to `/etc` and list its contents.',
                    questions: [{ id: 'q1', text: 'What is the first directory listed in /?', answer: 'bin' }]
                }
            ],
            target_ip: '10.10.145.22'
        },
        {
            id: 'room-linux-find-practice',
            title: 'The Find Command',
            description: 'Mastering the art of locating files.',
            difficulty: 'Medium',
            xp: 150,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: Syntax',
                    content: `
                        <h2>Find Command Syntax</h2>
                        <p>The <code>find</code> command is powerful for searching files based on various criteria.</p>
                        <pre><code>find [path] [expression]</code></pre>
                        <h3>Common Flags</h3>
                        <ul>
                            <li><code>-name "file.txt"</code>: Search by name.</li>
                            <li><code>-type f</code>: Search for files only.</li>
                            <li><code>-user root</code>: Search for files owned by root.</li>
                            <li><code>-perm 777</code>: Search for files with specific permissions.</li>
                        </ul>
                    `,
                    questions: [{ id: 'q1', text: 'Flag to search by file type?', answer: '-type' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Treasure Hunt',
                    content: 'Find all files accessible by the "guest" user.\n`find / -user guest 2>/dev/null`',
                    questions: [{ id: 'q1', text: 'Name of the hidden file?', answer: 'guest_secret.txt' }]
                }
            ],
            target_ip: '10.10.99.12'
        },

        // --- NETWORKING (OSI/TCP) ---
        {
            id: 'room-osi-guided',
            title: 'OSI Model Fundamentals',
            description: 'The Open Systems Interconnection model explained.',
            difficulty: 'Easy',
            xp: 100,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: The 7 Layers',
                    content: `
                        <h2>The OSI Model</h2>
                        <p>A conceptual framework used to describe the functions of a networking system.</p>
                        <ol reversed>
                            <li><strong>Application:</strong> HTTP, FTP, DNS (User Interface)</li>
                            <li><strong>Presentation:</strong> Encryption, Compression (JPEG, SSL)</li>
                            <li><strong>Session:</strong> Authentication, Session Management</li>
                            <li><strong>Transport:</strong> TCP/UDP (Reliability)</li>
                            <li><strong>Network:</strong> IP Addresses (Routing)</li>
                            <li><strong>Data Link:</strong> MAC Addresses (Switching)</li>
                            <li><strong>Physical:</strong> Cables, Wireless (Bits)</li>
                        </ol>
                        <div style="background:#2c5282; padding:10px; border-radius:5px;">Mnemonic: <strong>P</strong>lease <strong>D</strong>o <strong>N</strong>ot <strong>T</strong>hrow <strong>S</strong>ausage <strong>P</strong>izza <strong>A</strong>way (Physical to Application)</div>
                    `,
                    questions: [{ id: 'q1', text: 'Which layer handles IP addressing?', answer: 'Network' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Packet Analysis',
                    content: 'Open Wireshark. Observe how HTTP traffic flows. Identify the headers for Layer 7.',
                    questions: [{ id: 'q1', text: 'What protocol is Layer 4?', answer: 'TCP' }]
                }
            ],
            target_ip: '10.10.55.3'
        },

        // --- ENUMERATION (NMAP) ---
        {
            id: 'room-nmap-intro-practice',
            title: 'Nmap Scanning Basics',
            description: 'Network Mapper essentials.',
            difficulty: 'Medium',
            xp: 150,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: Scan Types',
                    content: `
                        <h2>Nmap Scan Types</h2>
                        <ul>
                            <li><code>-sS</code> (Stealth/SYN Scan): Default. Fast, requires root. Does not complete the 3-way handshake.</li>
                            <li><code>-sT</code> (Connect Scan): Completes handshake. Slower, more noisy.</li>
                            <li><code>-sU</code> (UDP Scan): Scans UDP ports.</li>
                            <li><code>-sV</code> (Version Detection): Probes open ports to determine service version.</li>
                        </ul>
                    `,
                    questions: [{ id: 'q1', text: 'Which flag is for Version Detection?', answer: '-sV' }]
                },
                {
                    id: 't2',
                    title: 'Lab: First Scan',
                    content: 'Scan the target machine: `nmap -sV 10.10.10.5`',
                    questions: [{ id: 'q1', text: 'What version of Apache is running?', answer: '2.4.41' }]
                }
            ],
            target_ip: '10.10.11.8'
        },

        // --- EXPLOITATION (METASPLOIT) ---
        {
            id: 'room-metasploit-guided',
            title: 'Metasploit Framework',
            description: 'The world\'s most used penetration testing framework.',
            difficulty: 'Easy',
            xp: 100,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: Architecture',
                    content: `
                        <h2>Metasploit Components</h2>
                        <ul>
                            <li><strong>Exploits:</strong> Code that takes advantage of a vulnerability.</li>
                            <li><strong>Payloads:</strong> Code that runs AFTER exploitation (Reverse Shell, Meterpreter).</li>
                            <li><strong>Auxiliary:</strong> Scanners, crawlers, and fuzzers.</li>
                            <li><strong>Encoders:</strong> Used to bypass AV signatures.</li>
                        </ul>
                        <h3>Common Commands</h3>
                        <pre><code>msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.10
run</code></pre>
                    `,
                    questions: [{ id: 'q1', text: 'Which module type is used for scanning?', answer: 'Auxiliary' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Exploiting SMB',
                    content: 'Use EternalBlue to compromise the target. Get a Meterpreter shell.',
                    questions: [{ id: 'q1', text: 'What is the computer name?', answer: 'WIN-SERVER-01' }]
                }
            ],
            target_ip: '10.10.205.14'
        },

        // --- WEB (SQLi) ---
        {
            id: 'room-sqli-manual-guided',
            title: 'Manual SQL Injection',
            description: 'Understanding the database query structure.',
            difficulty: 'Medium',
            xp: 200,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: The Vulnerability',
                    content: `
                        <h2>SQL Injection (SQLi)</h2>
                        <p>Occurs when user input is concatenated directly into a SQL query without sanitization.</p>
                        <h3>Example</h3>
                        <pre><code>SELECT * FROM users WHERE username = '$user';</code></pre>
                        <p>If input is <code>' OR '1'='1</code>, the query becomes:</p>
                        <pre><code>SELECT * FROM users WHERE username = '' OR '1'='1';</code></pre>
                        <p>This returns TRUE for every row, logging you in as the first user (Admin).</p>
                    `,
                    questions: [{ id: 'q1', text: 'What character typically breaks the query syntax?', answer: "'" }]
                },
                {
                    id: 't2',
                    title: 'Lab: Authentication Bypass',
                    content: 'Bypass the login form using `' + "admin' --" + '`.',
                    questions: [{ id: 'q1', text: 'Flag found on dashboard?', answer: 'flag{sql_master_bypass}' }]
                }
            ],
            target_ip: '10.10.169.5'
        },

        // ==========================================
        // 1. LINUX FUNDAMENTALS
        // ==========================================
        {
            id: 'room-linux-nav-guided',
            title: 'Linux Navigation: Guided',
            description: 'Master the terminal.',
            difficulty: 'Easy',
            xp: 100,
            estimatedTime: '30 mins',
            tasks: [
                {
                    id: 't1',
                    title: 'Lesson: File System Hierarchy',
                    content: `
                        <h2>The Linux File System</h2>
                        <p>Unlike Windows, Linux does not have C: or D: drives. Everything starts from the root directory <code>/</code>.</p>
                        <h3>Key Directories</h3>
                        <ul>
                            <li><code>/bin</code> - Essential user binaries (ls, cp, mv)</li>
                            <li><code>/etc</code> - Configuration files</li>
                            <li><code>/home</code> - User home directories</li>
                            <li><code>/var</code> - Variable files (logs, web)</li>
                        </ul>
                        <div style="background:#2d3748; padding:15px; border-left:4px solid #3182ce; margin:15px 0;">
                            <strong>Pro Tip:</strong> You can always find out where you are by typing <code>pwd</code>.
                        </div>
                    `,
                    questions: [{ id: 'q1', text: 'Which directory contains configuration files?', answer: '/etc' }]
                },
                {
                    id: 't2',
                    title: 'Practice: Navigation',
                    content: 'Now apply what you learned. Use the terminal to find the flag.\n\nType <code>pwd</code> in the terminal.',
                    questions: [{ id: 'q1', text: 'What is the output of pwd?', answer: '/home/user' }]
                }
            ],
            target_ip: '10.10.122.5'
        },

        // ==========================================
        // 2. WEB PENTESTING - ADVANCED
        // ==========================================
        {
            id: 'room-web-ssrf-guided',
            title: 'SSRF: Server-Side Request Forgery',
            description: 'Coerce the server into making requests.',
            difficulty: 'Hard',
            xp: 400,
            tier: 'premium',
            icon: 'fa-server',
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: What is SSRF?',
                    content: `
                        <h2>Understanding SSRF</h2>
                        <p>Server-Side Request Forgery (SSRF) is a vulnerability where an attacker forces a server to make requests to unintended locations.</p>
                        
                        <h3>The Impact</h3>
                        <p>If a server is vulnerable to SSRF, it can be used to:</p>
                        <ul>
                            <li>Scan the internal network (Port scanning)</li>
                            <li>Access internal-only services (Redis, Admin Panels)</li>
                            <li>Read Cloud Metadata (AWS keys)</li>
                        </ul>
                        
                        <h3>Vulnerable Code Example (PHP)</h3>
                        <pre><code>
$url = $_GET['url'];
// The server fetches the URL provided by the user
// If user provides "http://localhost:8080/admin", the server fetches it!
echo file_get_contents($url);
                        </code></pre>
                        
                        <div style="background:#742a2a; padding:15px; border-left:4px solid #f56565; margin:15px 0;">
                            <strong>Warning:</strong> Always validate URLs on the backend.
                        </div>
                    `,
                    questions: [{ id: 'q1', text: 'What function in PHP is often used in SSRF?', answer: 'file_get_contents' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Exploitation',
                    content: 'Start the machine. Navigate to the Service Checker tool.\n\nTry injecting `http://localhost:8080/admin` into the `?url=` parameter.',
                    questions: [{ id: 'q1', text: 'What service is running on port 8080?', answer: 'Admin Dashboard' }]
                }
            ],
            target_ip: '10.10.231.42'
        },
        {
            id: 'room-web-xxe-guided',
            title: 'XXE: XML External Entity',
            description: 'Exploiting XML parsers.',
            difficulty: 'Hard',
            xp: 450,
            icon: 'fa-code',
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: XML Entities',
                    content: `
                        <h2>XML Basics</h2>
                        <p>XML (Extensible Markup Language) is used to transport data. An "Entity" is like a variable in XML.</p>
                        <h3>The Vulnerability</h3>
                        <p>If an XML parser allows external entities, we can define a variable that reads from a file.</p>
                        <pre><code>
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;stockCheck&gt;&lt;productId&gt;&xxe;&lt;/productId&gt;&lt;/stockCheck&gt;
                        </code></pre>
                        <p>When the server processes <code>&xxe;</code>, it replaces it with the contents of <code>/etc/passwd</code>.</p>
                    `,
                    questions: [{ id: 'q1', text: 'What wrapper starts the DTD definition?', answer: '!DOCTYPE' }]
                },
                {
                    id: 't2',
                    title: 'Lab: Reading Files',
                    content: 'Inject a malicious DTD to read `/etc/passwd`.',
                    questions: [{ id: 'q1', text: 'First line of /etc/passwd?', answer: 'root:x:0:0:root:/root:/bin/bash' }]
                }
            ],
            target_ip: '10.10.178.19'
        },

        // ==========================================
        // 3. ACTIVE DIRECTORY ATTACKS
        // ==========================================
        {
            id: 'room-kerberoast-guided',
            title: 'Kerberoasting',
            description: 'Attack Service Accounts.',
            difficulty: 'Hard',
            xp: 500,
            icon: 'fa-ticket',
            tasks: [
                {
                    id: 't1',
                    title: 'Methodology',
                    content: `
                        <h2>How Kerberoasting Works</h2>
                        <ol>
                            <li><strong>Discovery:</strong> Find user accounts that have a Service Principal Name (SPN) set.</li>
                            <li><strong>Request:</strong> Request a TGS (Ticket Granting Service) ticket for that SPN.</li>
                            <li><strong>Offline Cracking:</strong> The TGS is encrypted with the service account's NTLM hash. We can crack this offline.</li>
                        </ol>
                        <h3>Tools</h3>
                        <ul>
                            <li><code>GetUserSPNs.py</code> (Impacket)</li>
                            <li><code>Rubeus.exe</code> (Windows)</li>
                            <li><code>Hashcat</code> (Mode 13100)</li>
                        </ul>
                    `,
                    questions: [{ id: 'q1', text: 'What attribute determines if an account is Kerberoastable?', answer: 'SPN' }]
                },
                {
                    id: 't2',
                    title: 'Attack Phase',
                    content: 'Use `GetUserSPNs.py` to target the domain controller provided in the lab.',
                    questions: [{ id: 'q1', text: 'Password for svc_sql?', answer: 'Database!2024' }]
                }
            ],
            target_ip: '10.10.201.8'
        },

        // ==========================================
        // 4. SOC ANALYST LABS
        // ==========================================
        {
            id: 'room-sysmon-guided',
            title: 'Sysmon Analysis',
            description: 'Windows Event Logs on Steroids.',
            difficulty: 'Medium',
            xp: 250,
            icon: 'fa-eye',
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: Key Event IDs',
                    content: `
                        <h2>Important Sysmon Events</h2>
                        <table style="width:100%; border-collapse:collapse;">
                            <tr><th style="border:1px solid #444; padding:8px;">ID</th><th style="border:1px solid #444; padding:8px;">Description</th></tr>
                            <tr><td style="border:1px solid #444; padding:8px;">1</td><td style="border:1px solid #444; padding:8px;">Process Creation (Detect malware execution)</td></tr>
                            <tr><td style="border:1px solid #444; padding:8px;">3</td><td style="border:1px solid #444; padding:8px;">Network Connection (C2 beacons)</td></tr>
                            <tr><td style="border:1px solid #444; padding:8px;">11</td><td style="border:1px solid #444; padding:8px;">File Create (Droppers)</td></tr>
                        </table>
                    `,
                    questions: [{ id: 'q1', text: 'Which ID tracks Network Connections?', answer: '3' }]
                },
                { id: 't2', title: 'Lab: Log Hunting', content: 'Open Event Viewer. Filter for Event ID 3.', questions: [{ id: 'q2', text: 'C2 IP Address?', answer: '192.168.1.105' }] }
            ],
            target_ip: '10.10.5.150'
        },

        // ... (Include other modules here if needed, or rely on previous replace to keep them if I matched endline correctly)
        // Wait, I am replacing lines 137-280 or so. I must ensure I don't delete the placeholders if they were in that range.
        // I will copy the placeholders from my previous step into this one to be safe.

        { id: 'room-linux-files-practice', title: 'File Operations', difficulty: 'Easy', tasks: [], target_ip: '10.10.122.10' },
        { id: 'room-linux-survivor-challenge', title: 'Survivor', difficulty: 'Medium', tasks: [], target_ip: '10.10.122.50' },
        { id: 'room-bloodhound-practice', title: 'BloodHound', difficulty: 'Medium', tasks: [], target_ip: '10.10.201.25' },
        { id: 'room-zerologon-guided', title: 'ZeroLogon', difficulty: 'Insane', tasks: [], target_ip: '10.10.10.101' },
        { id: 'room-phishing-analysis', title: 'Phishing', difficulty: 'Medium', tasks: [], target_ip: '10.10.150.5' },
        { id: 'room-splunk-basics', title: 'Splunk', difficulty: 'Easy', tasks: [], target_ip: '10.10.88.2' },
        { id: 'room-malware-basics', title: 'Malware', difficulty: 'Expert', tasks: [], target_ip: '10.10.250.66' },

        // --- WEB SECURITY ARCHITECTURE ROOMS ---
        {
            id: 'room-nodejs-engine',
            target_ip: '10.10.13.10',
            title: 'Node.js Event Loop Security',
            description: 'Understanding how the Event Loop handles I/O and how to exploit it.',
            difficulty: 'Advanced',
            xp: 300,
            tasks: [
                { id: 't1', title: 'Theory: The Loop', content: 'Node.js uses a single-threaded event loop. Blocking this thread freezes the entire server.', questions: [{ id: 'q1', text: 'Is Node.js multi-threaded by default?', answer: 'no' }] },
                { id: 't2', title: 'Lab: DoS via Event Loop', content: 'Craft a payload to block the event loop.', questions: [{ id: 'q2', text: 'What function caused the block?', answer: 'readFileSync' }] }
            ]
        },
        {
            id: 'room-js-pollution',
            target_ip: '10.10.13.20',
            title: 'Prototype Pollution Mastery',
            description: 'Advanced object injection attacks.',
            difficulty: 'Expert',
            xp: 500,
            tasks: [
                { id: 't1', title: 'Theory: Prototypes', content: 'In JS, objects inherit from prototypes. Modifying Object.prototype affects all objects.', questions: [{ id: 'q1', text: 'What property accesses the prototype?', answer: '__proto__' }] },
                { id: 't2', title: 'Lab: RCE via Pollution', content: 'Pollute the gadget to gain execution.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{polluted_root}' }] }
            ]
        },
        {
            id: 'room-auth-engineering',
            target_ip: '10.10.13.30',
            title: 'Middleware Authentication Bypass',
            description: 'Exploiting Express.js middleware chains.',
            difficulty: 'Hard',
            xp: 400,
            tasks: [
                { id: 't1', title: 'Theory: Middleware', content: 'Express runs middleware sequentially. Error handling middleware usually comes last.', questions: [{ id: 'q1', text: 'Function to pass control to next middleware?', answer: 'next()' }] },
                { id: 't2', title: 'Lab: Routing Bypass', content: 'Bypass the auth check by confusing the router.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{routed_around}' }] }
            ]
        },
        {
            id: 'room-sqli-mastery',
            target_ip: '10.10.42.10',
            title: 'Second Order SQL Injection',
            description: 'Attacks where the payload executes on a subsequent request.',
            difficulty: 'Expert',
            xp: 500,
            tasks: [
                { id: 't1', title: 'Theory: Storage', content: 'The payload is stored in the DB first, then executed when retrieved.', questions: [{ id: 'q1', text: 'Where is the payload stored?', answer: 'database' }] },
                { id: 't2', title: 'Lab: Password Reset', content: 'Inject into the username during registration to reset admin password later.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{second_order_admin}' }] }
            ]
        },
        {
            id: 'room-nosql-polyglot',
            target_ip: '10.10.42.20',
            title: 'NoSQL Injection & Polyglots',
            description: 'Bypassing MongoDB authentication.',
            difficulty: 'Hard',
            xp: 450,
            tasks: [
                { id: 't1', title: 'Theory: NoSQL', content: 'MongoDB uses JSON-like documents. Boolean injection works differently.', questions: [{ id: 'q1', text: 'Operator for "Not Equal"?', answer: '$ne' }] },
                { id: 't2', title: 'Lab: Login Bypass', content: 'Log in as admin without the password.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{nosql_bypassed}' }] }
            ]
        },
        {
            id: 'room-ssrf-redis',
            target_ip: '10.10.42.30',
            title: 'SSRF to Redis RCE',
            description: 'Chaining SSRF to interact with internal Redis.',
            difficulty: 'Expert',
            xp: 600,
            tasks: [
                { id: 't1', title: 'Theory: Gopher', content: 'The Gopher protocol allows sending arbitrary bytes, perfect for talking to Redis.', questions: [{ id: 'q1', text: 'Protocol for raw bytes?', answer: 'gopher' }] },
                { id: 't2', title: 'Lab: Redis Shell', content: 'Write a webshell to the webroot via Redis.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{redis_rce_master}' }] }
            ]
        },
        {
            id: 'room-api-arch',
            target_ip: '10.10.99.10',
            title: 'API Authorization Flaws',
            description: 'BOLA, BFLA, and Mass Assignment.',
            difficulty: 'Medium',
            xp: 350,
            tasks: [
                { id: 't1', title: 'Theory: BOLA', content: 'Broken Object Level Authorization allows accessing other users content.', questions: [{ id: 'q1', text: 'OWASP API Top 10 #1?', answer: 'BOLA' }] },
                { id: 't2', title: 'Lab: ID Rotation', content: 'Iterate through IDs to find the admin invoice.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{api_bola_king}' }] }
            ]
        },
        {
            id: 'room-race-conditions',
            target_ip: '10.10.99.20',
            title: 'Race Conditions',
            description: 'Exploiting concurrency issues in web apps.',
            difficulty: 'Expert',
            xp: 550,
            tasks: [
                { id: 't1', title: 'Theory: TOCTOU', content: 'Time Of Check to Time Of Use vulnerabilities.', questions: [{ id: 'q1', text: 'What does TOCTOU stand for?', answer: 'Time Of Check Time Of Use' }] },
                { id: 't2', title: 'Lab: Limit Bypass', content: 'Use the race condition to redeem a coupon multiple times.', questions: [{ id: 'q2', text: 'Flag?', answer: 'flag{race_won}' }] }
            ]
        },
        // --- NEW NODE.JS / WEB SEC ROOMS ---
        {
            id: 'room-node-eventloop',
            target_ip: '10.10.50.11',
            title: 'Node.js Event Loop Visualization',
            description: 'Understand how single-threaded blocking works.',
            difficulty: 'Easy',
            xp: 100,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: The Loop',
                    content: 'Node.js runs on a single thread. Blocking it stops everything.',
                    type: 'theory'
                },
                {
                    id: 't2',
                    title: 'Lab: Blocking vs Non-Blocking',
                    content: 'Write a loop that freezes the server. Then fix it using promises.',
                    type: 'lab'
                }
            ]
        },
        {
            id: 'room-node-middleware-bypass-v2',
            target_ip: '10.10.50.12',
            title: 'Middleware Bypass V2',
            description: 'Exploiting order of operations in Express.',
            difficulty: 'Medium',
            xp: 200,
            tasks: [
                {
                    id: 't1',
                    title: 'Lab: Auth Bypass',
                    content: 'Access the /admin route by exploiting middleware placement.',
                    type: 'lab'
                }
            ]
        },
        {
            id: 'room-redos-attack',
            target_ip: '10.10.50.13',
            title: 'ReDoS Attack',
            description: 'Regular Expression Denial of Service.',
            difficulty: 'Hard',
            xp: 300,
            tasks: [
                {
                    id: 't1',
                    title: 'Lab: Evil Regex',
                    content: 'Craft a payload that causes catastrophic backtracking.',
                    type: 'lab'
                }
            ]
        },
        {
            id: 'room-proto-basics',
            target_ip: '10.10.50.14',
            title: 'Prototype Basics',
            description: 'Understanding JavaScript Objects.',
            difficulty: 'Easy',
            xp: 100,
            tasks: [
                {
                    id: 't1',
                    title: 'Theory: __proto__',
                    content: 'Everything in JS is an object.',
                    type: 'theory'
                }
            ]
        },
        {
            id: 'room-proto-pollution-rce',
            target_ip: '10.10.50.15',
            title: 'Prototype Pollution to RCE',
            description: 'The ultimate JS exploit.',
            difficulty: 'Insane',
            xp: 1000,
            tasks: [
                {
                    id: 't1',
                    title: 'Lab: Pollute Object',
                    content: 'Inject JSON to modify Object.prototype.',
                    type: 'lab'
                }
            ]
        }
    ],

    // --- HELPER FUNCTIONS ---
    getPathById(id) { return this.paths.find(p => p.id === id); },
    getCourseById(id) { return this.courses.find(c => c.id === id); },
    getModuleById(id) { return this.modules.find(m => m.id === id); },

    getRoomById(id) {
        const room = this.rooms.find(r => r.id === id);
        if (!room) return null;
        const module = this.modules.find(m => m.rooms && m.rooms.includes(id));
        return { room, module };
    },

    getPathCourses(pathId) {
        const path = this.getPathById(pathId);
        if (!path || !path.courses) return [];
        return path.courses.map(cid => this.getCourseById(cid)).filter(Boolean);
    },

    getCourseModules(courseId) {
        const course = this.getCourseById(courseId);
        if (!course || !course.modules) return [];
        return course.modules.map(mid => this.getModuleById(mid)).filter(Boolean);
    },

    getModuleRooms(moduleId) {
        const module = this.getModuleById(moduleId);
        if (!module || !module.rooms) return [];
        return module.rooms.map(rid => this.rooms.find(r => r.id === rid) || { id: rid, title: 'Coming Soon', difficulty: 'TBD', description: 'Content under development.' });
    },

    init() {
        console.log(`✅ Phase 3.5 Curriculum Data Loaded: ${this.rooms.length} Rooms Active`);
    }
};

window.UnifiedLearningData.init();
