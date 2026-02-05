// ==================== PLATFORM DATA ====================
// Unified data structure for the ShadowHack Platform
// Contains domains, paths, modules, and smart guidance rules

const platformData = {
    // ========== DOMAINS ==========
    domains: [
        {
            id: 'red-team',
            code: 'red-team',
            name: 'Red Team',
            nameAr: 'الفريق الأحمر',
            subtitle: 'Offensive Security',
            subtitleAr: 'الأمن الهجومي',
            description: 'Master offensive security techniques including penetration testing, vulnerability exploitation, and advanced attack methodologies.',
            descriptionAr: 'أتقن تقنيات الأمن الهجومي بما في ذلك اختبار الاختراق واستغلال الثغرات ومنهجيات الهجوم المتقدمة.',
            icon: 'fa-crosshairs',
            emoji: '🔴',
            color: '#ef4444',
            gradient: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
            paths: ['web-pentesting', 'network-hacking', 'exploit-dev', 'mobile-hacking', 'wireless-hacking', 'social-engineering', 'web-security-architecture-path']
        },
        {
            id: 'blue-team',
            code: 'blue-team',
            name: 'Blue Team',
            nameAr: 'الفريق الأزرق',
            subtitle: 'Defensive Security',
            subtitleAr: 'الأمن الدفاعي',
            description: 'Learn defensive security operations including SOC analysis, incident response, digital forensics, and threat hunting.',
            descriptionAr: 'تعلم عمليات الأمن الدفاعي بما في ذلك تحليل SOC والاستجابة للحوادث والتحليل الجنائي الرقمي وصيد التهديدات.',
            icon: 'fa-shield-halved',
            emoji: '🔵',
            color: '#3b82f6',
            gradient: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
            paths: ['soc-analyst', 'digital-forensics', 'malware-analysis', 'threat-hunting', 'incident-response', 'security-engineering']
        }
    ],

    // ========== CAREER PATHS ==========
    paths: {
        // ===== RED TEAM PATHS =====
        'web-pentesting': {
            id: 'web-pentesting',
            domainId: 'red-team',
            name: 'Web Penetration Testing',
            nameAr: 'اختبار اختراق الويب',
            description: 'Master web application vulnerabilities from basics to advanced exploitation including OWASP Top 10 and beyond.',
            descriptionAr: 'أتقن ثغرات تطبيقات الويب من الأساسيات إلى الاستغلال المتقدم بما في ذلك OWASP Top 10 وما بعدها.',
            icon: 'fa-globe',
            color: '#667eea',
            difficulty: 'intermediate',
            estimatedHours: 40,
            prerequisites: [],
            certification: 'Web Security Specialist',
            modules: [
                {
                    id: 'web-recon',
                    name: 'Web Reconnaissance',
                    nameAr: 'استطلاع الويب',
                    order: 1,
                    estimatedMinutes: 120,
                    description: 'Learn to gather information about target web applications before testing.',
                    descriptionAr: 'تعلم جمع المعلومات عن تطبيقات الويب المستهدفة قبل الاختبار.',
                    objectives: [
                        'Enumerate subdomains and virtual hosts',
                        'Discover hidden directories and files',
                        'Identify technologies and frameworks',
                        'Gather OSINT information'
                    ],
                    objectivesAr: [
                        'تعداد النطاقات الفرعية والمضيفين الافتراضيين',
                        'اكتشاف المجلدات والملفات المخفية',
                        'تحديد التقنيات والأطر',
                        'جمع معلومات OSINT'
                    ],
                    tools: ['Subfinder', 'Amass', 'Dirsearch', 'Gobuster', 'Wappalyzer', 'WhatWeb'],
                    content: {
                        sections: [
                            {
                                title: 'Passive Reconnaissance',
                                titleAr: 'الاستطلاع السلبي',
                                content: 'Passive recon involves gathering information without directly interacting with the target. This includes WHOIS lookups, DNS enumeration, certificate transparency logs, and search engine dorking.',
                                contentAr: 'يتضمن الاستطلاع السلبي جمع المعلومات دون التفاعل المباشر مع الهدف. يشمل ذلك البحث في WHOIS، تعداد DNS، سجلات شفافية الشهادات، واستخدام محركات البحث.'
                            },
                            {
                                title: 'Active Reconnaissance',
                                titleAr: 'الاستطلاع النشط',
                                content: 'Active recon involves direct interaction with the target. Techniques include port scanning, directory bruteforcing, technology fingerprinting, and spider/crawling.',
                                contentAr: 'يتضمن الاستطلاع النشط التفاعل المباشر مع الهدف. تشمل التقنيات فحص المنافذ، تخمين المجلدات، بصمة التقنيات، والزحف.'
                            }
                        ],
                        commands: [
                            { tool: 'subfinder', command: 'subfinder -d target.com -o subdomains.txt', description: 'Enumerate subdomains' },
                            { tool: 'gobuster', command: 'gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt', description: 'Directory bruteforce' },
                            { tool: 'whatweb', command: 'whatweb -v https://target.com', description: 'Technology fingerprinting' }
                        ]
                    },
                    quiz: {
                        passingScore: 70,
                        questions: [
                            {
                                question: 'Which tool is best for subdomain enumeration?',
                                questionAr: 'ما الأداة الأفضل لتعداد النطاقات الفرعية؟',
                                options: ['Nmap', 'Subfinder', 'Burp Suite', 'Metasploit'],
                                correct: 1,
                                explanation: 'Subfinder is specifically designed for passive subdomain enumeration.'
                            },
                            {
                                question: 'What information can Certificate Transparency logs reveal?',
                                questionAr: 'ما المعلومات التي يمكن أن تكشفها سجلات شفافية الشهادات؟',
                                options: ['User passwords', 'Hidden subdomains', 'Server source code', 'Database schemas'],
                                correct: 1,
                                explanation: 'CT logs can reveal all SSL certificates issued for a domain, exposing hidden subdomains.'
                            },
                            {
                                question: 'Which HTTP header reveals the web server type?',
                                questionAr: 'أي HTTP header يكشف نوع خادم الويب؟',
                                options: ['Content-Type', 'Server', 'Accept', 'Host'],
                                correct: 1,
                                explanation: 'The Server header typically reveals the web server software and version.'
                            }
                        ]
                    },
                    lab: {
                        title: 'Web Recon Challenge',
                        titleAr: 'تحدي استطلاع الويب',
                        difficulty: 'easy',
                        points: 100,
                        estimatedTime: 30,
                        description: 'Use reconnaissance techniques to discover hidden information about the target application.',
                        descriptionAr: 'استخدم تقنيات الاستطلاع لاكتشاف معلومات مخفية عن التطبيق المستهدف.',
                        flag: 'FLAG{r3c0n_m4st3r_2024}',
                        hints: ['Check robots.txt', 'Look for backup files', 'Try common admin paths']
                    }
                },
                {
                    id: 'sql-injection',
                    name: 'SQL Injection Mastery',
                    nameAr: 'إتقان حقن SQL',
                    order: 2,
                    estimatedMinutes: 180,
                    description: 'Master all types of SQL injection attacks from basic to advanced techniques.',
                    descriptionAr: 'أتقن جميع أنواع هجمات حقن SQL من التقنيات الأساسية إلى المتقدمة.',
                    objectives: [
                        'Identify SQL injection vulnerabilities',
                        'Exploit UNION-based SQL injection',
                        'Perform Blind SQL injection attacks',
                        'Extract data using SQLMap'
                    ],
                    objectivesAr: [
                        'تحديد ثغرات حقن SQL',
                        'استغلال حقن SQL القائم على UNION',
                        'تنفيذ هجمات حقن SQL العمياء',
                        'استخراج البيانات باستخدام SQLMap'
                    ],
                    tools: ['SQLMap', 'Burp Suite', 'sqlninja'],
                    content: {
                        sections: [
                            {
                                title: 'Understanding SQL Injection',
                                titleAr: 'فهم حقن SQL',
                                content: 'SQL injection occurs when user input is incorporated into SQL queries without proper sanitization. Attackers can manipulate queries to access, modify, or delete data.',
                                contentAr: 'يحدث حقن SQL عندما يتم دمج إدخال المستخدم في استعلامات SQL دون تنظيف مناسب. يمكن للمهاجمين التلاعب بالاستعلامات للوصول إلى البيانات أو تعديلها أو حذفها.'
                            },
                            {
                                title: 'UNION-Based SQL Injection',
                                titleAr: 'حقن SQL القائم على UNION',
                                content: 'UNION attacks allow combining results from multiple SELECT statements. First determine the number of columns, then extract data from other tables.',
                                contentAr: 'تسمح هجمات UNION بدمج النتائج من عبارات SELECT متعددة. حدد أولاً عدد الأعمدة، ثم استخرج البيانات من جداول أخرى.'
                            },
                            {
                                title: 'Blind SQL Injection',
                                titleAr: 'حقن SQL الأعمى',
                                content: 'When no visible output is returned, use boolean-based or time-based techniques to infer information one bit at a time.',
                                contentAr: 'عندما لا يتم إرجاع أي مخرجات مرئية، استخدم تقنيات قائمة على Boolean أو الوقت لاستنتاج المعلومات بت واحد في كل مرة.'
                            }
                        ],
                        commands: [
                            { tool: 'sqlmap', command: "sqlmap -u 'http://target.com/page?id=1' --dbs", description: 'Enumerate databases' },
                            { tool: 'sqlmap', command: "sqlmap -u 'http://target.com/page?id=1' -D dbname --tables", description: 'Enumerate tables' },
                            { tool: 'manual', command: "' OR '1'='1' --", description: 'Basic bypass payload' }
                        ]
                    },
                    quiz: {
                        passingScore: 70,
                        questions: [
                            {
                                question: 'What is the purpose of ORDER BY in SQL injection?',
                                questionAr: 'ما هو الغرض من ORDER BY في حقن SQL؟',
                                options: ['To sort results', 'To find column count', 'To delete data', 'To create tables'],
                                correct: 1,
                                explanation: 'ORDER BY is used to determine the number of columns in UNION-based attacks.'
                            },
                            {
                                question: 'Which technique is used when no output is visible?',
                                questionAr: 'ما التقنية المستخدمة عندما لا يكون هناك مخرجات مرئية؟',
                                options: ['UNION attack', 'Blind SQL injection', 'Error-based injection', 'Stacked queries'],
                                correct: 1,
                                explanation: 'Blind SQL injection uses inference techniques when output is not directly visible.'
                            },
                            {
                                question: 'What does -- do in SQL?',
                                questionAr: 'ماذا يفعل -- في SQL؟',
                                options: ['Subtracts values', 'Comments out rest of query', 'Joins tables', 'Creates index'],
                                correct: 1,
                                explanation: 'Double dash (--) is a SQL comment that ignores the rest of the line.'
                            }
                        ]
                    },
                    lab: {
                        title: 'SQL Injection Lab',
                        titleAr: 'مختبر حقن SQL',
                        difficulty: 'medium',
                        points: 200,
                        estimatedTime: 45,
                        description: 'Exploit SQL injection to extract the admin password from the database.',
                        descriptionAr: 'استغل حقن SQL لاستخراج كلمة مرور المدير من قاعدة البيانات.',
                        flag: 'FLAG{sql_1nj3ct10n_pr0}',
                        hints: ['Try single quote first', 'Use UNION SELECT', 'information_schema is your friend']
                    }
                },
                {
                    id: 'xss-attacks',
                    name: 'XSS Attack Techniques',
                    nameAr: 'تقنيات هجوم XSS',
                    order: 3,
                    estimatedMinutes: 150,
                    description: 'Learn Cross-Site Scripting from reflected to stored and DOM-based attacks.',
                    descriptionAr: 'تعلم هجمات XSS من المنعكس إلى المخزن والقائم على DOM.',
                    objectives: [
                        'Identify XSS vulnerabilities',
                        'Craft effective XSS payloads',
                        'Bypass WAF and filters',
                        'Exploit XSS for session hijacking'
                    ],
                    objectivesAr: [
                        'تحديد ثغرات XSS',
                        'صياغة حمولات XSS فعالة',
                        'تجاوز WAF والفلاتر',
                        'استغلال XSS لاختطاف الجلسات'
                    ],
                    tools: ['XSS Hunter', 'BeEF', 'Burp Suite'],
                    content: {
                        sections: [
                            {
                                title: 'Types of XSS',
                                titleAr: 'أنواع XSS',
                                content: 'Reflected XSS: payload is in the request and immediately reflected. Stored XSS: payload is saved and served to other users. DOM XSS: manipulation happens entirely client-side.',
                                contentAr: 'XSS المنعكس: الحمولة في الطلب وتنعكس فوراً. XSS المخزن: يتم حفظ الحمولة وتقديمها للمستخدمين الآخرين. DOM XSS: يحدث التلاعب بالكامل في جانب العميل.'
                            },
                            {
                                title: 'Filter Bypass Techniques',
                                titleAr: 'تقنيات تجاوز الفلاتر',
                                content: 'Use different event handlers (onerror, onload, onfocus), encoding tricks, case variations, and nested tags to bypass security filters.',
                                contentAr: 'استخدم معالجات أحداث مختلفة (onerror، onload، onfocus)، حيل التشفير، تغيير الحالة، والعلامات المتداخلة لتجاوز فلاتر الأمان.'
                            }
                        ],
                        commands: [
                            { tool: 'payload', command: '<script>alert(document.cookie)</script>', description: 'Basic XSS' },
                            { tool: 'payload', command: '<img src=x onerror=alert(1)>', description: 'Event handler XSS' },
                            { tool: 'payload', command: '<svg/onload=alert(1)>', description: 'SVG-based XSS' }
                        ]
                    },
                    quiz: {
                        passingScore: 70,
                        questions: [
                            {
                                question: 'Which XSS type is most dangerous for other users?',
                                questionAr: 'أي نوع من XSS الأكثر خطورة على المستخدمين الآخرين؟',
                                options: ['Reflected XSS', 'Stored XSS', 'DOM XSS', 'Self XSS'],
                                correct: 1,
                                explanation: 'Stored XSS affects all users who view the compromised content.'
                            },
                            {
                                question: 'What cookie flag prevents JavaScript access?',
                                questionAr: 'ما علامة الكوكي التي تمنع وصول JavaScript؟',
                                options: ['Secure', 'HttpOnly', 'SameSite', 'Path'],
                                correct: 1,
                                explanation: 'HttpOnly flag prevents document.cookie access from JavaScript.'
                            }
                        ]
                    },
                    lab: {
                        title: 'XSS Challenge',
                        titleAr: 'تحدي XSS',
                        difficulty: 'medium',
                        points: 150,
                        estimatedTime: 35,
                        description: 'Bypass the XSS filter and steal the admin cookie.',
                        descriptionAr: 'تجاوز فلتر XSS واسرق كوكي المدير.',
                        flag: 'FLAG{x55_hunt3r_2024}',
                        hints: ['Try different event handlers', 'Check for DOM sinks', 'Encoding might help']
                    }
                },
                {
                    id: 'auth-bypass',
                    name: 'Authentication Bypass',
                    nameAr: 'تجاوز المصادقة',
                    order: 4,
                    estimatedMinutes: 140,
                    description: 'Learn techniques to bypass authentication and authorization mechanisms.',
                    descriptionAr: 'تعلم تقنيات تجاوز آليات المصادقة والتفويض.',
                    objectives: ['Break weak authentication', 'Exploit session management flaws', 'Bypass 2FA', 'Exploit OAuth vulnerabilities'],
                    objectivesAr: ['كسر المصادقة الضعيفة', 'استغلال عيوب إدارة الجلسات', 'تجاوز 2FA', 'استغلال ثغرات OAuth'],
                    tools: ['Burp Suite', 'Hydra', 'JWT Tool'],
                    content: {
                        sections: [
                            { title: 'Password Attacks', titleAr: 'هجمات كلمات المرور', content: 'Brute force, credential stuffing, and password spraying attacks against login forms.', contentAr: 'هجمات القوة الغاشمة وحشو بيانات الاعتماد ورش كلمات المرور ضد نماذج تسجيل الدخول.' },
                            { title: 'Session Hijacking', titleAr: 'اختطاف الجلسة', content: 'Stealing or predicting session tokens to take over user accounts.', contentAr: 'سرقة أو توقع رموز الجلسة للاستيلاء على حسابات المستخدمين.' },
                            { title: 'JWT Attacks', titleAr: 'هجمات JWT', content: 'Algorithm confusion, key brute force, and claim manipulation attacks on JWTs.', contentAr: 'هجمات ارتباك الخوارزمية وتخمين المفتاح وتلاعب المطالبات على JWTs.' }
                        ]
                    },
                    quiz: { passingScore: 70, questions: [{ question: 'What is credential stuffing?', questionAr: 'ما هو حشو بيانات الاعتماد؟', options: ['Random password guessing', 'Using leaked credentials', 'SQL injection', 'XSS attack'], correct: 1, explanation: 'Credential stuffing uses username/password pairs from data breaches.' }] },
                    lab: { title: 'Auth Bypass Lab', titleAr: 'مختبر تجاوز المصادقة', difficulty: 'hard', points: 250, estimatedTime: 50, description: 'Bypass the login and access the admin panel.', descriptionAr: 'تجاوز تسجيل الدخول والوصول إلى لوحة الإدارة.', flag: 'FLAG{4uth_byp4ss_m4st3r}', hints: ['Check JWT algorithm', 'Try admin:admin', 'Look for IDOR'] }
                },
                {
                    id: 'file-upload',
                    name: 'File Upload Exploitation',
                    nameAr: 'استغلال رفع الملفات',
                    order: 5,
                    estimatedMinutes: 120,
                    description: 'Exploit insecure file upload functionality to achieve code execution.',
                    descriptionAr: 'استغلال وظيفة رفع الملفات غير الآمنة لتحقيق تنفيذ الكود.',
                    objectives: ['Bypass file type restrictions', 'Upload web shells', 'Achieve RCE via file upload'],
                    objectivesAr: ['تجاوز قيود نوع الملف', 'رفع أصداف الويب', 'تحقيق RCE عبر رفع الملفات'],
                    tools: ['Burp Suite', 'Weevely', 'PHP shells'],
                    content: { sections: [{ title: 'Bypass Techniques', titleAr: 'تقنيات التجاوز', content: 'Extension manipulation, MIME type spoofing, magic byte injection, and null byte injection.', contentAr: 'تلاعب الامتداد وتزوير نوع MIME وحقن البايت السحري وحقن البايت الفارغ.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is a web shell?', questionAr: 'ما هو الويب شل؟', options: ['CSS framework', 'Malicious script for RCE', 'Database tool', 'Network scanner'], correct: 1, explanation: 'A web shell is a script that provides remote command execution.' }] },
                    lab: { title: 'File Upload Lab', titleAr: 'مختبر رفع الملفات', difficulty: 'medium', points: 200, estimatedTime: 40, description: 'Upload a web shell and read the flag.', descriptionAr: 'ارفع ويب شل واقرأ الفلاج.', flag: 'FLAG{f1l3_upl04d_pwn3d}', hints: ['Try double extensions', 'Check content-type', 'Magic bytes'] }
                },
                {
                    id: 'ssrf-attacks',
                    name: 'SSRF & XXE Attacks',
                    nameAr: 'هجمات SSRF و XXE',
                    order: 6,
                    estimatedMinutes: 160,
                    description: 'Server-Side Request Forgery and XML External Entity attacks.',
                    descriptionAr: 'هجمات تزوير طلبات جانب الخادم وكيانات XML الخارجية.',
                    objectives: ['Exploit SSRF to access internal services', 'Read files via XXE', 'Achieve blind XXE exploitation'],
                    objectivesAr: ['استغلال SSRF للوصول إلى الخدمات الداخلية', 'قراءة الملفات عبر XXE', 'تحقيق استغلال XXE الأعمى'],
                    tools: ['Burp Suite', 'XXEinjector'],
                    content: { sections: [{ title: 'SSRF Basics', titleAr: 'أساسيات SSRF', content: 'SSRF allows attackers to make requests from the server to internal or external resources.', contentAr: 'يسمح SSRF للمهاجمين بإجراء طلبات من الخادم إلى موارد داخلية أو خارجية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What can SSRF access?', questionAr: 'ما الذي يمكن لـ SSRF الوصول إليه؟', options: ['Only external URLs', 'Internal network services', 'Only images', 'User browsers'], correct: 1, explanation: 'SSRF can access internal services like metadata endpoints.' }] },
                    lab: { title: 'SSRF Lab', titleAr: 'مختبر SSRF', difficulty: 'hard', points: 300, estimatedTime: 55, description: 'Use SSRF to access the internal admin panel.', descriptionAr: 'استخدم SSRF للوصول إلى لوحة الإدارة الداخلية.', flag: 'FLAG{55rf_1nt3rn4l_4cc355}', hints: ['Try localhost', 'Check for redirects', 'Cloud metadata'] }
                },
                {
                    id: 'api-security',
                    name: 'API Security Testing',
                    nameAr: 'اختبار أمان API',
                    order: 7,
                    estimatedMinutes: 140,
                    description: 'Test REST and GraphQL APIs for common vulnerabilities.',
                    descriptionAr: 'اختبار واجهات REST و GraphQL للثغرات الشائعة.',
                    objectives: ['Test REST API security', 'Exploit GraphQL vulnerabilities', 'Find IDOR in APIs', 'Bypass rate limiting'],
                    objectivesAr: ['اختبار أمان REST API', 'استغلال ثغرات GraphQL', 'إيجاد IDOR في APIs', 'تجاوز تحديد المعدل'],
                    tools: ['Postman', 'Burp Suite', 'GraphQL Voyager'],
                    content: { sections: [{ title: 'API Vulnerabilities', titleAr: 'ثغرات API', content: 'BOLA, broken authentication, excessive data exposure, lack of rate limiting, and mass assignment.', contentAr: 'BOLA، المصادقة المكسورة، التعرض المفرط للبيانات، عدم تحديد المعدل، والتعيين الجماعي.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is BOLA?', questionAr: 'ما هو BOLA؟', options: ['Buffer overflow', 'Broken Object Level Authorization', 'Binary operation', 'Batch operation'], correct: 1, explanation: 'BOLA allows accessing other users objects by changing IDs.' }] },
                    lab: { title: 'API Security Lab', titleAr: 'مختبر أمان API', difficulty: 'medium', points: 200, estimatedTime: 45, description: 'Find and exploit the API IDOR vulnerability.', descriptionAr: 'اعثر على ثغرة IDOR في API واستغلها.', flag: 'FLAG{4p1_1d0r_hunt3r}', hints: ['Change user ID', 'Check response data', 'Try PUT/DELETE'] }
                },
                {
                    id: 'advanced-web',
                    name: 'Advanced Web Exploitation',
                    nameAr: 'استغلال ويب متقدم',
                    order: 8,
                    estimatedMinutes: 200,
                    description: 'Advanced techniques including deserialization, SSTI, and prototype pollution.',
                    descriptionAr: 'تقنيات متقدمة تشمل إلغاء التسلسل و SSTI وتلوث النموذج الأولي.',
                    objectives: ['Exploit deserialization vulnerabilities', 'Perform SSTI attacks', 'Understand prototype pollution', 'Chain vulnerabilities'],
                    objectivesAr: ['استغلال ثغرات إلغاء التسلسل', 'تنفيذ هجمات SSTI', 'فهم تلوث النموذج الأولي', 'تسلسل الثغرات'],
                    tools: ['ysoserial', 'Tplmap', 'Burp Suite'],
                    content: { sections: [{ title: 'Insecure Deserialization', titleAr: 'إلغاء التسلسل غير الآمن', content: 'Exploiting how applications deserialize data can lead to RCE. Common in Java, PHP, Python, and .NET.', contentAr: 'استغلال كيفية إلغاء تسلسل التطبيقات للبيانات يمكن أن يؤدي إلى RCE. شائع في Java و PHP و Python و .NET.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What can SSTI lead to?', questionAr: 'إلى ماذا يمكن أن يؤدي SSTI؟', options: ['XSS only', 'Remote Code Execution', 'SQL injection', 'CSRF'], correct: 1, explanation: 'SSTI can lead to RCE by injecting code into server-side templates.' }] },
                    lab: { title: 'Advanced Exploitation', titleAr: 'استغلال متقدم', difficulty: 'hard', points: 400, estimatedTime: 60, description: 'Chain multiple vulnerabilities to achieve RCE.', descriptionAr: 'سلسل ثغرات متعددة لتحقيق RCE.', flag: 'FLAG{4dv4nc3d_w3b_pr0}', hints: ['Check template engine', 'Try {{7*7}}', 'Look for serialize'] }
                }
            ]
        },
        'network-hacking': {
            id: 'network-hacking',
            domainId: 'red-team',
            name: 'Network Hacking',
            nameAr: 'اختراق الشبكات',
            description: 'Learn network penetration testing, pivoting, infrastructure attacks, and enterprise network exploitation.',
            descriptionAr: 'تعلم اختبار اختراق الشبكات والـ Pivoting وهجمات البنية التحتية واستغلال شبكات المؤسسات.',
            icon: 'fa-network-wired',
            color: '#f59e0b',
            difficulty: 'intermediate',
            estimatedHours: 50,
            prerequisites: ['web-pentesting'],
            certification: 'Network Penetration Tester',
            modules: [
                {
                    id: 'network-scanning', name: 'Network Scanning & Enumeration', nameAr: 'فحص الشبكات والتعداد', order: 1,
                    estimatedMinutes: 150,
                    description: 'Master network discovery, port scanning, and service enumeration techniques.',
                    descriptionAr: 'إتقان اكتشاف الشبكات وفحص المنافذ وتقنيات تعداد الخدمات.',
                    objectives: ['Perform host discovery', 'Conduct port scanning', 'Enumerate services and versions', 'Identify vulnerabilities'],
                    objectivesAr: ['إجراء اكتشاف المضيفين', 'إجراء فحص المنافذ', 'تعداد الخدمات والإصدارات', 'تحديد الثغرات'],
                    tools: ['Nmap', 'Masscan', 'Netcat', 'Enum4linux', 'SNMPwalk'],
                    content: {
                        sections: [
                            { title: 'Host Discovery', titleAr: 'اكتشاف المضيفين', content: 'Identify live hosts using ICMP, ARP, TCP, and UDP probes. Use Nmap ping scans and ARP scanning for local networks.', contentAr: 'تحديد المضيفين النشطين باستخدام ICMP و ARP و TCP و UDP. استخدام فحص ping لـ Nmap ومسح ARP للشبكات المحلية.' },
                            { title: 'Port Scanning Techniques', titleAr: 'تقنيات فحص المنافذ', content: 'TCP SYN scan (stealth), TCP connect scan, UDP scan, and version detection. Understanding scan timing and evasion.', contentAr: 'فحص TCP SYN (خفي)، فحص TCP connect، فحص UDP، واكتشاف الإصدارات. فهم توقيت الفحص وتقنيات المراوغة.' }
                        ], commands: [
                            { tool: 'nmap', command: 'nmap -sn 192.168.1.0/24', description: 'Host discovery' },
                            { tool: 'nmap', command: 'nmap -sS -sV -p- -T4 target', description: 'Full port scan with version detection' },
                            { tool: 'enum4linux', command: 'enum4linux -a target', description: 'SMB enumeration' }
                        ]
                    },
                    quiz: {
                        passingScore: 70, questions: [
                            { question: 'What is SYN scan also known as?', questionAr: 'ما هو الاسم الآخر لفحص SYN؟', options: ['Connect scan', 'Stealth scan', 'UDP scan', 'Ping scan'], correct: 1, explanation: 'SYN scan is called stealth scan because it does not complete the TCP handshake.' }
                        ]
                    },
                    lab: { title: 'Network Recon Lab', titleAr: 'مختبر استطلاع الشبكات', difficulty: 'easy', points: 150, estimatedTime: 40, description: 'Discover and enumerate all services on the target network.', descriptionAr: 'اكتشف وحدد جميع الخدمات على الشبكة المستهدفة.', flag: 'FLAG{n3tw0rk_sc4nn3r}', hints: ['Start with ping sweep', 'Use -sV for versions', 'Check common ports'] }
                },
                {
                    id: 'smb-attacks', name: 'SMB & AD Attacks', nameAr: 'هجمات SMB و Active Directory', order: 2,
                    estimatedMinutes: 180,
                    description: 'Attack Windows networks, exploit SMB vulnerabilities, and compromise Active Directory.',
                    descriptionAr: 'هجوم شبكات Windows واستغلال ثغرات SMB واختراق Active Directory.',
                    objectives: ['Enumerate SMB shares', 'Exploit SMB vulnerabilities', 'Attack Active Directory', 'Perform Pass-the-Hash attacks'],
                    objectivesAr: ['تعداد مشاركات SMB', 'استغلال ثغرات SMB', 'هجوم Active Directory', 'تنفيذ هجمات Pass-the-Hash'],
                    tools: ['CrackMapExec', 'Impacket', 'BloodHound', 'Mimikatz', 'Responder'],
                    content: {
                        sections: [
                            { title: 'SMB Enumeration', titleAr: 'تعداد SMB', content: 'Enumerate shares, users, and policies via SMB. Use null sessions and guest access when available.', contentAr: 'تعداد المشاركات والمستخدمين والسياسات عبر SMB. استخدام الجلسات الفارغة ووصول الضيف عند توفرها.' },
                            { title: 'Active Directory Attacks', titleAr: 'هجمات Active Directory', content: 'Kerberoasting, AS-REP roasting, DCSync, and Golden/Silver ticket attacks.', contentAr: 'Kerberoasting و AS-REP roasting و DCSync وهجمات Golden/Silver ticket.' }
                        ]
                    },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool is used for AD enumeration?', questionAr: 'ما الأداة المستخدمة لتعداد AD؟', options: ['Nmap', 'BloodHound', 'Burp Suite', 'SQLMap'], correct: 1, explanation: 'BloodHound maps AD relationships.' }] },
                    lab: { title: 'AD Attack Lab', titleAr: 'مختبر هجوم AD', difficulty: 'hard', points: 300, estimatedTime: 60, description: 'Compromise the domain controller.', descriptionAr: 'اخترق الـ Domain Controller.', flag: 'FLAG{4d_pwn3d_2024}', hints: ['Enumerate with BloodHound', 'Try Kerberoasting', 'Check for AS-REP'] }
                },
                {
                    id: 'ssh-attacks', name: 'SSH & Remote Services', nameAr: 'SSH والخدمات البعيدة', order: 3,
                    estimatedMinutes: 120,
                    description: 'Attack SSH, RDP, VNC, and other remote access services.',
                    descriptionAr: 'هجوم SSH و RDP و VNC وخدمات الوصول البعيد الأخرى.',
                    objectives: ['Brute force credentials', 'Exploit misconfigurations', 'Leverage stolen keys', 'Tunnel traffic securely'],
                    objectivesAr: ['تخمين بيانات الاعتماد', 'استغلال الإعدادات الخاطئة', 'استخدام المفاتيح المسروقة', 'تمرير الحركة بأمان'],
                    tools: ['Hydra', 'Medusa', 'ssh-audit', 'Crowbar'],
                    content: { sections: [{ title: 'SSH Attacks', titleAr: 'هجمات SSH', content: 'Password brute forcing, key-based authentication attacks, and SSH tunneling for pivoting.', contentAr: 'تخمين كلمات المرور وهجمات المصادقة بالمفاتيح واستخدام SSH tunneling للـ pivoting.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What flag enables verbose mode in SSH?', questionAr: 'ما الـ flag الذي يفعل الوضع المفصل في SSH؟', options: ['-p', '-v', '-l', '-i'], correct: 1, explanation: '-v enables verbose output for debugging.' }] },
                    lab: { title: 'SSH Attack Lab', titleAr: 'مختبر هجوم SSH', difficulty: 'medium', points: 200, estimatedTime: 45, description: 'Gain SSH access to the target.', descriptionAr: 'احصل على وصول SSH للهدف.', flag: 'FLAG{55h_4cc355}', hints: ['Try common passwords', 'Check for key files', 'Use hydra'] }
                },
                {
                    id: 'pivoting', name: 'Pivoting & Tunneling', nameAr: 'Pivoting و Tunneling', order: 4,
                    estimatedMinutes: 160,
                    description: 'Navigate through networks using pivoting, port forwarding, and tunneling.',
                    descriptionAr: 'التنقل عبر الشبكات باستخدام الـ Pivoting وإعادة توجيه المنافذ والأنفاق.',
                    objectives: ['Create SSH tunnels', 'Use Chisel and Ligolo', 'Perform dynamic port forwarding', 'Chain multiple pivots'],
                    objectivesAr: ['إنشاء أنفاق SSH', 'استخدام Chisel و Ligolo', 'إجراء إعادة توجيه المنافذ الديناميكية', 'تسلسل pivots متعددة'],
                    tools: ['SSH', 'Chisel', 'Ligolo', 'Proxychains', 'sshuttle'],
                    content: { sections: [{ title: 'Tunneling Techniques', titleAr: 'تقنيات الأنفاق', content: 'Local, remote, and dynamic port forwarding. SOCKS proxies and proxy chains for network access.', contentAr: 'إعادة توجيه المنافذ المحلية والبعيدة والديناميكية. وكلاء SOCKS وسلاسل الوكلاء للوصول للشبكة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is dynamic port forwarding?', questionAr: 'ما هو إعادة توجيه المنافذ الديناميكية؟', options: ['Single port forward', 'SOCKS proxy', 'VPN tunnel', 'HTTP proxy'], correct: 1, explanation: 'Dynamic forwarding creates a SOCKS proxy.' }] },
                    lab: { title: 'Pivot Lab', titleAr: 'مختبر Pivot', difficulty: 'hard', points: 350, estimatedTime: 70, description: 'Reach the internal network through the compromised host.', descriptionAr: 'الوصول للشبكة الداخلية عبر المضيف المخترق.', flag: 'FLAG{p1v0t_m4st3r}', hints: ['Set up SOCKS proxy', 'Use proxychains', 'Check internal subnets'] }
                },
                {
                    id: 'priv-escalation', name: 'Privilege Escalation', nameAr: 'رفع الصلاحيات', order: 5,
                    estimatedMinutes: 180,
                    description: 'Escalate privileges on Linux and Windows systems.',
                    descriptionAr: 'رفع الصلاحيات على أنظمة Linux و Windows.',
                    objectives: ['Find SUID binaries', 'Exploit sudo misconfigurations', 'Abuse Windows services', 'Leverage kernel exploits'],
                    objectivesAr: ['إيجاد ملفات SUID', 'استغلال إعدادات sudo الخاطئة', 'استغلال خدمات Windows', 'استخدام ثغرات النواة'],
                    tools: ['LinPEAS', 'WinPEAS', 'GTFOBins', 'PowerUp', 'BeRoot'],
                    content: {
                        sections: [
                            { title: 'Linux Privilege Escalation', titleAr: 'رفع صلاحيات Linux', content: 'SUID/SGID binaries, sudo abuse, cron jobs, capabilities, and kernel exploits.', contentAr: 'ملفات SUID/SGID وإساءة استخدام sudo ومهام cron والقدرات وثغرات النواة.' },
                            { title: 'Windows Privilege Escalation', titleAr: 'رفع صلاحيات Windows', content: 'Service misconfigurations, unquoted paths, DLL hijacking, and token impersonation.', contentAr: 'إعدادات الخدمات الخاطئة والمسارات غير المقتبسة واختطاف DLL وانتحال الرموز.' }
                        ]
                    },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool automates Linux privesc checks?', questionAr: 'ما الأداة التي تؤتمت فحوصات رفع صلاحيات Linux؟', options: ['Burp Suite', 'LinPEAS', 'Nmap', 'Metasploit'], correct: 1, explanation: 'LinPEAS automates privilege escalation checks on Linux.' }] },
                    lab: { title: 'PrivEsc Lab', titleAr: 'مختبر رفع الصلاحيات', difficulty: 'hard', points: 300, estimatedTime: 55, description: 'Escalate from user to root.', descriptionAr: 'ارفع من مستخدم عادي إلى root.', flag: 'FLAG{r00t_4cc355}', hints: ['Run LinPEAS', 'Check GTFOBins', 'Look for SUID'] }
                },
                {
                    id: 'post-exploitation', name: 'Post-Exploitation', nameAr: 'ما بعد الاستغلال', order: 6,
                    estimatedMinutes: 150,
                    description: 'Maintain access, collect data, and cover tracks.',
                    descriptionAr: 'الحفاظ على الوصول وجمع البيانات وإخفاء الآثار.',
                    objectives: ['Establish persistence', 'Dump credentials', 'Exfiltrate data', 'Clear logs'],
                    objectivesAr: ['إنشاء استمرارية', 'تفريغ بيانات الاعتماد', 'تسريب البيانات', 'مسح السجلات'],
                    tools: ['Mimikatz', 'Empire', 'Cobalt Strike', 'Meterpreter'],
                    content: { sections: [{ title: 'Persistence Techniques', titleAr: 'تقنيات الاستمرارية', content: 'Registry keys, scheduled tasks, services, and startup folders for maintaining access.', contentAr: 'مفاتيح السجل والمهام المجدولة والخدمات ومجلدات بدء التشغيل للحفاظ على الوصول.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does Mimikatz extract?', questionAr: 'ماذا يستخرج Mimikatz؟', options: ['Network packets', 'Credentials from memory', 'SQL data', 'Web cookies'], correct: 1, explanation: 'Mimikatz extracts credentials from Windows memory.' }] },
                    lab: { title: 'Post-Exploitation Lab', titleAr: 'مختبر ما بعد الاستغلال', difficulty: 'hard', points: 350, estimatedTime: 60, description: 'Dump all credentials and establish persistence.', descriptionAr: 'استخرج جميع بيانات الاعتماد وأنشئ استمرارية.', flag: 'FLAG{p0st_3xpl01t}', hints: ['Use Mimikatz', 'Create scheduled task', 'Check LSASS'] }
                }
            ]
        },
        'exploit-dev': {
            id: 'exploit-dev',
            domainId: 'red-team',
            name: 'Exploit Development',
            nameAr: 'تطوير الثغرات',
            description: 'Advanced binary exploitation, buffer overflows, shellcoding, and vulnerability research.',
            descriptionAr: 'استغلال متقدم للبرامج وثغرات Buffer Overflow وكتابة Shellcode وأبحاث الثغرات.',
            icon: 'fa-bug',
            color: '#ef4444',
            difficulty: 'advanced',
            estimatedHours: 80,
            prerequisites: ['network-hacking'],
            certification: 'Exploit Developer',
            modules: [
                {
                    id: 'assembly-basics', name: 'Assembly & Low-Level Programming', nameAr: 'Assembly والبرمجة منخفضة المستوى', order: 1,
                    estimatedMinutes: 200, description: 'Learn x86/x64 assembly language and low-level programming concepts.', descriptionAr: 'تعلم لغة Assembly x86/x64 ومفاهيم البرمجة منخفضة المستوى.',
                    objectives: ['Understand CPU architecture', 'Read and write assembly', 'Use debuggers', 'Analyze binaries'], objectivesAr: ['فهم بنية المعالج', 'قراءة وكتابة Assembly', 'استخدام المنقحات', 'تحليل البرامج'],
                    tools: ['GDB', 'Radare2', 'IDA Pro', 'x64dbg', 'NASM'],
                    content: { sections: [{ title: 'x86 Architecture', titleAr: 'بنية x86', content: 'Registers (EAX, EBX, ESP, EBP, EIP), memory layout, stack operations, and calling conventions.', contentAr: 'السجلات (EAX، EBX، ESP، EBP، EIP)، تخطيط الذاكرة، عمليات المكدس، واتفاقيات الاستدعاء.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What register holds the return address?', questionAr: 'أي سجل يحتوي على عنوان العودة؟', options: ['EAX', 'ESP', 'EIP', 'EBX'], correct: 2, explanation: 'EIP (Instruction Pointer) holds the address of the next instruction.' }] },
                    lab: { title: 'Assembly Lab', titleAr: 'مختبر Assembly', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Write a simple assembly program.', descriptionAr: 'اكتب برنامج Assembly بسيط.', flag: 'FLAG{4ss3mbly_b4s1cs}', hints: ['Use NASM syntax', 'Check registers', 'Set breakpoints'] }
                },
                {
                    id: 'buffer-overflow', name: 'Buffer Overflow Attacks', nameAr: 'هجمات Buffer Overflow', order: 2,
                    estimatedMinutes: 220, description: 'Exploit stack-based and heap-based buffer overflows.', descriptionAr: 'استغلال ثغرات Buffer Overflow القائمة على المكدس والـ Heap.',
                    objectives: ['Identify buffer overflows', 'Control EIP', 'Find bad characters', 'Redirect execution'], objectivesAr: ['تحديد ثغرات Buffer Overflow', 'التحكم في EIP', 'إيجاد الحروف السيئة', 'إعادة توجيه التنفيذ'],
                    tools: ['Immunity Debugger', 'mona.py', 'GDB', 'pwntools'],
                    content: { sections: [{ title: 'Stack-Based Overflow', titleAr: 'Buffer Overflow القائم على المكدس', content: 'Overwrite the return address to redirect execution. Find offset, control EIP, and jump to shellcode.', contentAr: 'الكتابة فوق عنوان العودة لإعادة توجيه التنفيذ. إيجاد الـ offset والتحكم في EIP والقفز إلى Shellcode.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is the purpose of JMP ESP?', questionAr: 'ما هو الغرض من JMP ESP؟', options: ['Exit program', 'Jump to shellcode', 'Clear stack', 'Call function'], correct: 1, explanation: 'JMP ESP redirects execution to shellcode on the stack.' }] },
                    lab: { title: 'Buffer Overflow Lab', titleAr: 'مختبر Buffer Overflow', difficulty: 'hard', points: 350, estimatedTime: 70, description: 'Exploit the vulnerable service and get a shell.', descriptionAr: 'استغل الخدمة الضعيفة واحصل على shell.', flag: 'FLAG{buff3r_0v3rfl0w}', hints: ['Find the offset', 'Check for bad chars', 'Look for JMP ESP'] }
                },
                {
                    id: 'shellcoding', name: 'Shellcoding', nameAr: 'كتابة Shellcode', order: 3,
                    estimatedMinutes: 180, description: 'Write custom shellcode for various platforms.', descriptionAr: 'كتابة Shellcode مخصص لمنصات مختلفة.',
                    objectives: ['Write position-independent code', 'Avoid null bytes', 'Create reverse shells', 'Encode shellcode'], objectivesAr: ['كتابة كود مستقل عن الموقع', 'تجنب البايتات الفارغة', 'إنشاء reverse shells', 'ترميز Shellcode'],
                    tools: ['NASM', 'msfvenom', 'objdump', 'Encoder scripts'],
                    content: { sections: [{ title: 'Writing Shellcode', titleAr: 'كتابة Shellcode', content: 'System calls, avoiding bad characters, shellcode encoding, and polymorphic shellcode.', contentAr: 'استدعاءات النظام وتجنب الحروف السيئة وترميز Shellcode و Shellcode متعدد الأشكال.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'Why avoid null bytes in shellcode?', questionAr: 'لماذا نتجنب البايتات الفارغة في Shellcode؟', options: ['Slow execution', 'String termination', 'Memory errors', 'CPU limits'], correct: 1, explanation: 'Null bytes terminate strings in C, stopping shellcode execution.' }] },
                    lab: { title: 'Shellcode Lab', titleAr: 'مختبر Shellcode', difficulty: 'hard', points: 400, estimatedTime: 80, description: 'Write shellcode without null bytes.', descriptionAr: 'اكتب Shellcode بدون بايتات فارغة.', flag: 'FLAG{5h3llc0d3r}', hints: ['Use XOR encoding', 'Check for nulls', 'Test in debugger'] }
                },
                {
                    id: 'rop-chains', name: 'ROP Chains & Advanced Techniques', nameAr: 'ROP وتقنيات متقدمة', order: 4,
                    estimatedMinutes: 200, description: 'Bypass modern protections with ROP, ASLR bypass, and more.', descriptionAr: 'تجاوز الحمايات الحديثة مع ROP وتجاوز ASLR والمزيد.',
                    objectives: ['Build ROP chains', 'Bypass DEP', 'Defeat ASLR', 'Use ret2libc'], objectivesAr: ['بناء سلاسل ROP', 'تجاوز DEP', 'هزيمة ASLR', 'استخدام ret2libc'],
                    tools: ['ROPgadget', 'ropper', 'pwntools', 'one_gadget'],
                    content: { sections: [{ title: 'Return Oriented Programming', titleAr: 'البرمجة المبنية على العودة', content: 'Chain gadgets to execute arbitrary code without injecting shellcode. Bypass NX/DEP protections.', contentAr: 'تسلسل الأدوات لتنفيذ كود تعسفي دون حقن Shellcode. تجاوز حماية NX/DEP.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does ROP bypass?', questionAr: 'ماذا يتجاوز ROP؟', options: ['Firewalls', 'DEP/NX', 'Antivirus', 'IDS'], correct: 1, explanation: 'ROP bypasses DEP/NX by reusing existing code.' }] },
                    lab: { title: 'ROP Lab', titleAr: 'مختبر ROP', difficulty: 'hard', points: 450, estimatedTime: 90, description: 'Build a ROP chain to bypass DEP.', descriptionAr: 'ابنِ سلسلة ROP لتجاوز DEP.', flag: 'FLAG{r0p_ch41n_m4st3r}', hints: ['Find gadgets', 'Check libc', 'Use pwntools'] }
                },
                {
                    id: 'vulnerability-research', name: 'Vulnerability Research', nameAr: 'أبحاث الثغرات', order: 5,
                    estimatedMinutes: 180, description: 'Find and responsibly disclose vulnerabilities.', descriptionAr: 'اكتشاف الثغرات والإفصاح المسؤول عنها.',
                    objectives: ['Fuzz applications', 'Analyze crashes', 'Write PoC exploits', 'Responsible disclosure'], objectivesAr: ['اختبار التطبيقات بالـ Fuzzing', 'تحليل الانهيارات', 'كتابة استغلالات PoC', 'الإفصاح المسؤول'],
                    tools: ['AFL', 'libFuzzer', 'ASAN', 'Ghidra'],
                    content: { sections: [{ title: 'Fuzzing', titleAr: 'الـ Fuzzing', content: 'Automated testing with random inputs to find crashes and vulnerabilities.', contentAr: 'اختبار آلي بمدخلات عشوائية لإيجاد الانهيارات والثغرات.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is fuzzing?', questionAr: 'ما هو الـ Fuzzing؟', options: ['Code review', 'Random input testing', 'Encryption', 'Logging'], correct: 1, explanation: 'Fuzzing sends random data to find vulnerabilities.' }] },
                    lab: { title: 'Vuln Research Lab', titleAr: 'مختبر أبحاث الثغرات', difficulty: 'hard', points: 400, estimatedTime: 85, description: 'Fuzz and find a vulnerability.', descriptionAr: 'استخدم الـ Fuzzing لإيجاد ثغرة.', flag: 'FLAG{vuln_r3s34rch3r}', hints: ['Use AFL', 'Check crashes', 'Analyze core dumps'] }
                }
            ]
        },
        'mobile-hacking': {
            id: 'mobile-hacking',
            domainId: 'red-team',
            name: 'Mobile Application Hacking',
            nameAr: 'اختراق تطبيقات الجوال',
            description: 'Android and iOS security assessment, reverse engineering, and mobile exploitation.',
            descriptionAr: 'تقييم أمان تطبيقات Android و iOS والهندسة العكسية واستغلال الجوال.',
            icon: 'fa-mobile-screen',
            color: '#8b5cf6',
            difficulty: 'intermediate',
            estimatedHours: 45,
            prerequisites: ['web-pentesting'],
            certification: 'Mobile Security Specialist',
            modules: [
                {
                    id: 'android-basics', name: 'Android Security Fundamentals', nameAr: 'أساسيات أمان Android', order: 1,
                    estimatedMinutes: 150, description: 'Understand Android architecture and security model.', descriptionAr: 'فهم بنية Android ونموذج الأمان.',
                    objectives: ['Understand Android components', 'Set up testing environment', 'Use ADB', 'Analyze APK structure'], objectivesAr: ['فهم مكونات Android', 'إعداد بيئة الاختبار', 'استخدام ADB', 'تحليل بنية APK'],
                    tools: ['Android Studio', 'ADB', 'Jadx', 'Drozer', 'Frida'],
                    content: { sections: [{ title: 'Android Architecture', titleAr: 'بنية Android', content: 'Activities, Services, Broadcast Receivers, Content Providers, and the Android Manifest.', contentAr: 'الأنشطة والخدمات ومستقبلات البث وموفري المحتوى وملف Android Manifest.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What file contains app permissions?', questionAr: 'أي ملف يحتوي على صلاحيات التطبيق؟', options: ['build.gradle', 'AndroidManifest.xml', 'strings.xml', 'config.xml'], correct: 1, explanation: 'AndroidManifest.xml declares permissions and components.' }] },
                    lab: { title: 'Android Setup Lab', titleAr: 'مختبر إعداد Android', difficulty: 'easy', points: 100, estimatedTime: 35, description: 'Extract and analyze an APK.', descriptionAr: 'استخراج وتحليل ملف APK.', flag: 'FLAG{4ndr01d_b4s1cs}', hints: ['Use jadx-gui', 'Check manifest', 'Find hardcoded strings'] }
                },
                {
                    id: 'android-reversing', name: 'Android Reverse Engineering', nameAr: 'الهندسة العكسية لـ Android', order: 2,
                    estimatedMinutes: 180, description: 'Decompile and analyze Android applications.', descriptionAr: 'فك تجميع وتحليل تطبيقات Android.',
                    objectives: ['Decompile APKs', 'Analyze smali code', 'Modify and repack', 'Bypass root detection'], objectivesAr: ['فك تجميع APKs', 'تحليل كود smali', 'التعديل وإعادة التجميع', 'تجاوز اكتشاف root'],
                    tools: ['Jadx', 'APKTool', 'Frida', 'Objection'],
                    content: { sections: [{ title: 'APK Decompilation', titleAr: 'فك تجميع APK', content: 'Use jadx to decompile to Java, apktool to extract resources, and modify smali code.', contentAr: 'استخدام jadx للتحويل إلى Java و apktool لاستخراج الموارد وتعديل كود smali.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is smali code?', questionAr: 'ما هو كود smali؟', options: ['JavaScript', 'Dalvik bytecode representation', 'Native code', 'XML'], correct: 1, explanation: 'Smali is human-readable Dalvik bytecode.' }] },
                    lab: { title: 'Android Reversing Lab', titleAr: 'مختبر الهندسة العكسية Android', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Bypass the login check.', descriptionAr: 'تجاوز فحص تسجيل الدخول.', flag: 'FLAG{r3v3rs3d_4pk}', hints: ['Find login logic', 'Modify smali', 'Use Frida'] }
                },
                {
                    id: 'ios-security', name: 'iOS Security Assessment', nameAr: 'تقييم أمان iOS', order: 3,
                    estimatedMinutes: 160, description: 'Test iOS applications for security vulnerabilities.', descriptionAr: 'اختبار تطبيقات iOS للثغرات الأمنية.',
                    objectives: ['Set up iOS testing', 'Analyze IPA files', 'Use Objection', 'Bypass SSL pinning'], objectivesAr: ['إعداد اختبار iOS', 'تحليل ملفات IPA', 'استخدام Objection', 'تجاوز SSL pinning'],
                    tools: ['Objection', 'Frida', 'Hopper', 'iOSReverse'],
                    content: { sections: [{ title: 'iOS App Analysis', titleAr: 'تحليل تطبيقات iOS', content: 'Extract IPA, analyze binary, check for jailbreak detection, and SSL pinning bypass.', contentAr: 'استخراج IPA وتحليل الملف الثنائي والتحقق من اكتشاف الجيلبريك وتجاوز SSL pinning.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool bypasses SSL pinning?', questionAr: 'ما الأداة التي تتجاوز SSL pinning؟', options: ['Nmap', 'Frida', 'SQLMap', 'Hydra'], correct: 1, explanation: 'Frida can hook and bypass SSL pinning.' }] },
                    lab: { title: 'iOS Security Lab', titleAr: 'مختبر أمان iOS', difficulty: 'hard', points: 300, estimatedTime: 60, description: 'Extract sensitive data from the app.', descriptionAr: 'استخراج بيانات حساسة من التطبيق.', flag: 'FLAG{i0s_h4ck3r}', hints: ['Check Keychain', 'Use Objection', 'Dump memory'] }
                },
                {
                    id: 'mobile-api', name: 'Mobile API Testing', nameAr: 'اختبار API للجوال', order: 4,
                    estimatedMinutes: 140, description: 'Test mobile application backends.', descriptionAr: 'اختبار خوادم تطبيقات الجوال.',
                    objectives: ['Intercept traffic', 'Test API endpoints', 'Find IDOR', 'Bypass authentication'], objectivesAr: ['اعتراض الحركة', 'اختبار نقاط API', 'إيجاد IDOR', 'تجاوز المصادقة'],
                    tools: ['Burp Suite', 'mitmproxy', 'Postman', 'Frida'],
                    content: { sections: [{ title: 'Traffic Interception', titleAr: 'اعتراض الحركة', content: 'Configure proxy, install CA certificate, bypass certificate pinning.', contentAr: 'إعداد الوكيل وتثبيت شهادة CA وتجاوز تثبيت الشهادة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'How to intercept HTTPS traffic?', questionAr: 'كيف تعترض حركة HTTPS؟', options: ['Use VPN', 'Install proxy CA cert', 'Change DNS', 'Use firewall'], correct: 1, explanation: 'Install proxy CA certificate to decrypt HTTPS.' }] },
                    lab: { title: 'Mobile API Lab', titleAr: 'مختبر API للجوال', difficulty: 'medium', points: 200, estimatedTime: 45, description: 'Find and exploit API vulnerabilities.', descriptionAr: 'اعثر على ثغرات API واستغلها.', flag: 'FLAG{m0b1l3_4p1_pwn}', hints: ['Set up proxy', 'Check for IDOR', 'Test auth tokens'] }
                }
            ]
        },
        'wireless-hacking': {
            id: 'wireless-hacking',
            domainId: 'red-team',
            name: 'Wireless Hacking',
            nameAr: 'اختراق الشبكات اللاسلكية',
            description: 'WiFi security, WPA/WPA2 cracking, Evil Twin attacks, and wireless pentesting.',
            descriptionAr: 'أمان WiFi وكسر WPA/WPA2 وهجمات Evil Twin واختبار الاختراق اللاسلكي.',
            icon: 'fa-wifi',
            color: '#10b981',
            difficulty: 'intermediate',
            estimatedHours: 25,
            prerequisites: [],
            certification: 'Wireless Security Specialist',
            modules: [
                {
                    id: 'wifi-basics', name: 'WiFi Security Fundamentals', nameAr: 'أساسيات أمان WiFi', order: 1,
                    estimatedMinutes: 120, description: 'Understand wireless protocols and security mechanisms.', descriptionAr: 'فهم البروتوكولات اللاسلكية وآليات الأمان.',
                    objectives: ['Understand 802.11 standards', 'Learn encryption types', 'Set up monitoring mode', 'Capture handshakes'], objectivesAr: ['فهم معايير 802.11', 'تعلم أنواع التشفير', 'إعداد وضع المراقبة', 'التقاط المصافحات'],
                    tools: ['Aircrack-ng', 'Wireshark', 'Kismet', 'WiFi adapters'],
                    content: { sections: [{ title: 'Wireless Protocols', titleAr: 'البروتوكولات اللاسلكية', content: 'WEP, WPA, WPA2, WPA3 security mechanisms and their vulnerabilities.', contentAr: 'آليات أمان WEP و WPA و WPA2 و WPA3 وثغراتها.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'Which encryption is most secure?', questionAr: 'أي تشفير هو الأكثر أماناً؟', options: ['WEP', 'WPA', 'WPA2', 'WPA3'], correct: 3, explanation: 'WPA3 is the latest and most secure.' }] },
                    lab: { title: 'WiFi Basics Lab', titleAr: 'مختبر أساسيات WiFi', difficulty: 'easy', points: 100, estimatedTime: 30, description: 'Set up monitor mode and capture packets.', descriptionAr: 'إعداد وضع المراقبة والتقاط الحزم.', flag: 'FLAG{w1f1_b4s1cs}', hints: ['Use airmon-ng', 'Check interface', 'Capture traffic'] }
                },
                {
                    id: 'wpa-cracking', name: 'WPA/WPA2 Cracking', nameAr: 'كسر WPA/WPA2', order: 2,
                    estimatedMinutes: 150, description: 'Capture handshakes and crack WPA/WPA2 passwords.', descriptionAr: 'التقاط المصافحات وكسر كلمات مرور WPA/WPA2.',
                    objectives: ['Capture 4-way handshake', 'Deauth clients', 'Crack with wordlist', 'Use GPU cracking'], objectivesAr: ['التقاط المصافحة الرباعية', 'قطع اتصال العملاء', 'الكسر باستخدام قائمة كلمات', 'استخدام GPU للكسر'],
                    tools: ['Aircrack-ng', 'Hashcat', 'hcxdumptool', 'hcxtools'],
                    content: { sections: [{ title: 'Handshake Capture', titleAr: 'التقاط المصافحة', content: 'Use airodump-ng to capture handshakes and aireplay-ng for deauthentication.', contentAr: 'استخدام airodump-ng لالتقاط المصافحات و aireplay-ng لقطع الاتصال.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What do you need to crack WPA2?', questionAr: 'ما الذي تحتاجه لكسر WPA2؟', options: ['IV packets', '4-way handshake', 'SSID only', 'MAC address'], correct: 1, explanation: 'You need to capture the 4-way handshake.' }] },
                    lab: { title: 'WPA Cracking Lab', titleAr: 'مختبر كسر WPA', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Crack the WPA2 password.', descriptionAr: 'اكسر كلمة مرور WPA2.', flag: 'FLAG{wp4_cr4ck3d}', hints: ['Capture handshake', 'Use rockyou.txt', 'Try aircrack-ng'] }
                },
                {
                    id: 'evil-twin', name: 'Evil Twin & Rogue AP', nameAr: 'Evil Twin و Rogue AP', order: 3,
                    estimatedMinutes: 140, description: 'Create fake access points to capture credentials.', descriptionAr: 'إنشاء نقاط وصول وهمية لالتقاط بيانات الاعتماد.',
                    objectives: ['Create Evil Twin AP', 'Capture credentials', 'Perform MITM attacks', 'Use captive portals'], objectivesAr: ['إنشاء Evil Twin AP', 'التقاط بيانات الاعتماد', 'تنفيذ هجمات MITM', 'استخدام البوابات المقيدة'],
                    tools: ['Hostapd', 'dnsmasq', 'WiFi-Pumpkin', 'Fluxion'],
                    content: { sections: [{ title: 'Evil Twin Attack', titleAr: 'هجوم Evil Twin', content: 'Create a fake AP with the same SSID to capture credentials when users connect.', contentAr: 'إنشاء AP وهمي بنفس الـ SSID لالتقاط بيانات الاعتماد عند اتصال المستخدمين.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is an Evil Twin?', questionAr: 'ما هو Evil Twin؟', options: ['Malware', 'Fake access point', 'Encryption type', 'Router model'], correct: 1, explanation: 'Evil Twin is a rogue AP impersonating a legitimate one.' }] },
                    lab: { title: 'Evil Twin Lab', titleAr: 'مختبر Evil Twin', difficulty: 'hard', points: 250, estimatedTime: 55, description: 'Capture user credentials with Evil Twin.', descriptionAr: 'التقط بيانات اعتماد المستخدم باستخدام Evil Twin.', flag: 'FLAG{3v1l_tw1n_4tt4ck}', hints: ['Clone the SSID', 'Set up captive portal', 'Monitor traffic'] }
                },
                {
                    id: 'wireless-tools', name: 'Wireless Pentesting Tools', nameAr: 'أدوات اختبار الاختراق اللاسلكي', order: 4,
                    estimatedMinutes: 120, description: 'Master essential wireless security tools.', descriptionAr: 'إتقان أدوات أمان الشبكات اللاسلكية الأساسية.',
                    objectives: ['Use Aircrack-ng suite', 'Configure Wireshark for WiFi', 'Use Bettercap', 'Automate with scripts'], objectivesAr: ['استخدام مجموعة Aircrack-ng', 'إعداد Wireshark للـ WiFi', 'استخدام Bettercap', 'الأتمتة بالـ scripts'],
                    tools: ['Aircrack-ng', 'Bettercap', 'Wifite', 'Kismet'],
                    content: { sections: [{ title: 'Tool Overview', titleAr: 'نظرة عامة على الأدوات', content: 'Comprehensive guide to wireless pentesting tools and their use cases.', contentAr: 'دليل شامل لأدوات اختبار الاختراق اللاسلكي وحالات استخدامها.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'Which tool automates WiFi attacks?', questionAr: 'أي أداة تؤتمت هجمات WiFi؟', options: ['Nmap', 'Wifite', 'SQLMap', 'Burp Suite'], correct: 1, explanation: 'Wifite automates WiFi attacking.' }] },
                    lab: { title: 'Tools Lab', titleAr: 'مختبر الأدوات', difficulty: 'easy', points: 150, estimatedTime: 40, description: 'Complete a wireless assessment.', descriptionAr: 'أكمل تقييم لاسلكي.', flag: 'FLAG{w1r3l3ss_t00ls}', hints: ['Use wifite', 'Try all tools', 'Document findings'] }
                }
            ]
        },
        'social-engineering': {
            id: 'social-engineering',
            domainId: 'red-team',
            name: 'Social Engineering',
            nameAr: 'الهندسة الاجتماعية',
            description: 'Phishing, pretexting, vishing, and human-factor exploitation techniques.',
            descriptionAr: 'تقنيات التصيد والتظاهر والاتصال الاحتيالي واستغلال العامل البشري.',
            icon: 'fa-user-secret',
            color: '#f97316',
            difficulty: 'beginner',
            estimatedHours: 20,
            prerequisites: [],
            certification: 'Social Engineering Specialist',
            modules: [
                {
                    id: 'phishing', name: 'Phishing Campaigns', nameAr: 'حملات التصيد', order: 1,
                    estimatedMinutes: 120, description: 'Create and execute phishing campaigns.', descriptionAr: 'إنشاء وتنفيذ حملات التصيد.',
                    objectives: ['Craft phishing emails', 'Clone websites', 'Track campaigns', 'Analyze results'], objectivesAr: ['صياغة رسائل تصيد', 'استنساخ المواقع', 'تتبع الحملات', 'تحليل النتائج'],
                    tools: ['GoPhish', 'SET', 'King Phisher', 'Evilginx2'],
                    content: { sections: [{ title: 'Phishing Fundamentals', titleAr: 'أساسيات التصيد', content: 'Email phishing, spear phishing, whaling, and credential harvesting techniques.', contentAr: 'تصيد البريد الإلكتروني والتصيد الموجه وصيد الحيتان وتقنيات حصاد بيانات الاعتماد.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is spear phishing?', questionAr: 'ما هو التصيد الموجه؟', options: ['Mass email', 'Targeted phishing', 'Phone call', 'USB attack'], correct: 1, explanation: 'Spear phishing targets specific individuals.' }] },
                    lab: { title: 'Phishing Lab', titleAr: 'مختبر التصيد', difficulty: 'easy', points: 100, estimatedTime: 35, description: 'Create a phishing campaign.', descriptionAr: 'أنشئ حملة تصيد.', flag: 'FLAG{ph1sh1ng_m4st3r}', hints: ['Use GoPhish', 'Clone login page', 'Track clicks'] }
                },
                {
                    id: 'pretexting', name: 'Pretexting & Manipulation', nameAr: 'التظاهر والتلاعب', order: 2,
                    estimatedMinutes: 100, description: 'Master pretexting and psychological manipulation.', descriptionAr: 'إتقان التظاهر والتلاعب النفسي.',
                    objectives: ['Create believable pretexts', 'Use influence principles', 'Conduct vishing', 'Physical social engineering'], objectivesAr: ['إنشاء ذرائع مقنعة', 'استخدام مبادئ التأثير', 'إجراء التصيد الصوتي', 'الهندسة الاجتماعية المادية'],
                    tools: ['Voice changers', 'Caller ID spoofing', 'Social scripts'],
                    content: { sections: [{ title: 'Influence Principles', titleAr: 'مبادئ التأثير', content: 'Cialdinis principles: reciprocity, scarcity, authority, consistency, liking, consensus.', contentAr: 'مبادئ Cialdini: المقابلة بالمثل، الندرة، السلطة، الاتساق، الإعجاب، الإجماع.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is vishing?', questionAr: 'ما هو التصيد الصوتي؟', options: ['Video phishing', 'Voice phishing', 'Virus phishing', 'VPN phishing'], correct: 1, explanation: 'Vishing is phishing over phone calls.' }] },
                    lab: { title: 'Pretexting Lab', titleAr: 'مختبر التظاهر', difficulty: 'medium', points: 150, estimatedTime: 40, description: 'Create a pretext scenario.', descriptionAr: 'أنشئ سيناريو تظاهر.', flag: 'FLAG{pr3t3xt_pr0}', hints: ['Research target', 'Build trust', 'Use urgency'] }
                },
                {
                    id: 'osint', name: 'OSINT for Social Engineering', nameAr: 'OSINT للهندسة الاجتماعية', order: 3,
                    estimatedMinutes: 130, description: 'Gather intelligence for social engineering attacks.', descriptionAr: 'جمع المعلومات لهجمات الهندسة الاجتماعية.',
                    objectives: ['Gather target info', 'Use social media', 'Find email formats', 'Build target profiles'], objectivesAr: ['جمع معلومات الهدف', 'استخدام وسائل التواصل', 'إيجاد صيغ البريد', 'بناء ملفات الأهداف'],
                    tools: ['theHarvester', 'Maltego', 'SpiderFoot', 'Sherlock', 'LinkedIn'],
                    content: { sections: [{ title: 'OSINT Techniques', titleAr: 'تقنيات OSINT', content: 'Email harvesting, social media analysis, company reconnaissance, and personal information gathering.', contentAr: 'حصاد البريد الإلكتروني وتحليل وسائل التواصل الاجتماعي واستطلاع الشركات وجمع المعلومات الشخصية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool finds usernames?', questionAr: 'ما الأداة التي تجد أسماء المستخدمين؟', options: ['Nmap', 'Sherlock', 'SQLMap', 'Metasploit'], correct: 1, explanation: 'Sherlock finds usernames across platforms.' }] },
                    lab: { title: 'OSINT Lab', titleAr: 'مختبر OSINT', difficulty: 'easy', points: 120, estimatedTime: 45, description: 'Build a target profile.', descriptionAr: 'ابنِ ملف هدف.', flag: 'FLAG{0s1nt_hunt3r}', hints: ['Check LinkedIn', 'Use theHarvester', 'Find email format'] }
                }
            ]
        },

        // ===== BLUE TEAM PATHS =====
        'soc-analyst': {
            id: 'soc-analyst',
            domainId: 'blue-team',
            name: 'SOC Analyst',
            nameAr: 'محلل SOC',
            description: 'Security Operations Center analysis, monitoring, SIEM operations, and incident response.',
            descriptionAr: 'تحليل مركز عمليات الأمن والمراقبة وعمليات SIEM والاستجابة للحوادث.',
            icon: 'fa-eye',
            color: '#3b82f6',
            difficulty: 'beginner',
            estimatedHours: 35,
            prerequisites: [],
            certification: 'SOC Analyst Level 1',
            modules: [
                {
                    id: 'soc-fundamentals', name: 'SOC Fundamentals', nameAr: 'أساسيات SOC', order: 1,
                    estimatedMinutes: 120, description: 'Understand SOC operations and analyst roles.', descriptionAr: 'فهم عمليات SOC وأدوار المحللين.',
                    objectives: ['Understand SOC structure', 'Learn analyst tiers', 'Know SOC tools', 'Understand metrics'], objectivesAr: ['فهم هيكل SOC', 'تعلم مستويات المحللين', 'معرفة أدوات SOC', 'فهم المقاييس'],
                    tools: ['SIEM', 'Ticketing systems', 'EDR', 'SOAR'],
                    content: { sections: [{ title: 'SOC Structure', titleAr: 'هيكل SOC', content: 'Tier 1 (Alert monitoring), Tier 2 (Investigation), Tier 3 (Threat hunting). SOC metrics and KPIs.', contentAr: 'المستوى 1 (مراقبة التنبيهات)، المستوى 2 (التحقيق)، المستوى 3 (صيد التهديدات). مقاييس ومؤشرات أداء SOC.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does Tier 1 analyst do?', questionAr: 'ماذا يفعل محلل المستوى 1؟', options: ['Threat hunting', 'Alert monitoring', 'Malware analysis', 'Penetration testing'], correct: 1, explanation: 'Tier 1 monitors and triages alerts.' }] },
                    lab: { title: 'SOC Intro Lab', titleAr: 'مختبر مقدمة SOC', difficulty: 'easy', points: 100, estimatedTime: 30, description: 'Explore SOC dashboard.', descriptionAr: 'استكشف لوحة تحكم SOC.', flag: 'FLAG{s0c_4n4lyst}', hints: ['Check alerts', 'Review queue', 'Note severity'] }
                },
                {
                    id: 'log-analysis', name: 'Log Analysis', nameAr: 'تحليل السجلات', order: 2,
                    estimatedMinutes: 150, description: 'Analyze various log types for security events.', descriptionAr: 'تحليل أنواع السجلات المختلفة لأحداث الأمان.',
                    objectives: ['Read Windows logs', 'Analyze Linux logs', 'Parse web server logs', 'Correlate events'], objectivesAr: ['قراءة سجلات Windows', 'تحليل سجلات Linux', 'فحص سجلات خادم الويب', 'ربط الأحداث'],
                    tools: ['Event Viewer', 'Syslog', 'Splunk', 'ELK Stack'],
                    content: { sections: [{ title: 'Log Types', titleAr: 'أنواع السجلات', content: 'Windows Security logs, Syslog, Apache/Nginx logs, firewall logs, and authentication logs.', contentAr: 'سجلات أمان Windows، Syslog، سجلات Apache/Nginx، سجلات الجدار الناري، وسجلات المصادقة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What Event ID is successful login?', questionAr: 'ما رقم الحدث لتسجيل دخول ناجح؟', options: ['4625', '4624', '4648', '4672'], correct: 1, explanation: 'Event ID 4624 is successful logon.' }] },
                    lab: { title: 'Log Analysis Lab', titleAr: 'مختبر تحليل السجلات', difficulty: 'medium', points: 150, estimatedTime: 45, description: 'Find the malicious activity.', descriptionAr: 'اعثر على النشاط الضار.', flag: 'FLAG{l0g_4n4lyz3r}', hints: ['Check failed logins', 'Look for patterns', 'Correlate IPs'] }
                },
                {
                    id: 'siem-operations', name: 'SIEM Operations', nameAr: 'عمليات SIEM', order: 3,
                    estimatedMinutes: 160, description: 'Master SIEM platforms for security monitoring.', descriptionAr: 'إتقان منصات SIEM للمراقبة الأمنية.',
                    objectives: ['Create SIEM queries', 'Build dashboards', 'Configure alerts', 'Write detection rules'], objectivesAr: ['إنشاء استعلامات SIEM', 'بناء لوحات التحكم', 'إعداد التنبيهات', 'كتابة قواعد الكشف'],
                    tools: ['Splunk', 'QRadar', 'Elastic SIEM', 'Microsoft Sentinel'],
                    content: { sections: [{ title: 'SIEM Queries', titleAr: 'استعلامات SIEM', content: 'SPL for Splunk, KQL for Sentinel, and Lucene for ELK. Building effective searches and dashboards.', contentAr: 'SPL لـ Splunk و KQL لـ Sentinel و Lucene لـ ELK. بناء عمليات بحث ولوحات تحكم فعالة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What language does Splunk use?', questionAr: 'ما اللغة التي يستخدمها Splunk؟', options: ['SQL', 'SPL', 'KQL', 'Python'], correct: 1, explanation: 'Splunk uses SPL (Search Processing Language).' }] },
                    lab: { title: 'SIEM Lab', titleAr: 'مختبر SIEM', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Write a detection rule.', descriptionAr: 'اكتب قاعدة كشف.', flag: 'FLAG{s13m_m4st3r}', hints: ['Use SPL syntax', 'Filter by source', 'Set threshold'] }
                },
                {
                    id: 'alert-triage', name: 'Alert Triage & Investigation', nameAr: 'فرز التنبيهات والتحقيق', order: 4,
                    estimatedMinutes: 140, description: 'Prioritize and investigate security alerts.', descriptionAr: 'ترتيب أولويات والتحقيق في التنبيهات الأمنية.',
                    objectives: ['Triage alerts by severity', 'Investigate indicators', 'Document findings', 'Escalate incidents'], objectivesAr: ['فرز التنبيهات حسب الخطورة', 'التحقيق في المؤشرات', 'توثيق النتائج', 'تصعيد الحوادث'],
                    tools: ['VirusTotal', 'AbuseIPDB', 'Shodan', 'MITRE ATT&CK'],
                    content: { sections: [{ title: 'Triage Process', titleAr: 'عملية الفرز', content: 'Evaluate alert context, check IOCs, correlate with other events, determine true/false positive.', contentAr: 'تقييم سياق التنبيه، التحقق من IOCs، الربط مع أحداث أخرى، تحديد إيجابي حقيقي/زائف.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is a false positive?', questionAr: 'ما هو الإيجابي الزائف؟', options: ['Real attack', 'Benign flagged as malicious', 'Missed attack', 'System error'], correct: 1, explanation: 'False positive is benign activity flagged as malicious.' }] },
                    lab: { title: 'Triage Lab', titleAr: 'مختبر الفرز', difficulty: 'medium', points: 180, estimatedTime: 45, description: 'Triage 5 alerts.', descriptionAr: 'افرز 5 تنبيهات.', flag: 'FLAG{tr14g3_pr0}', hints: ['Check IOCs first', 'Use VirusTotal', 'Document all'] }
                },
                {
                    id: 'incident-handling', name: 'Incident Handling', nameAr: 'التعامل مع الحوادث', order: 5,
                    estimatedMinutes: 130, description: 'Handle security incidents from detection to closure.', descriptionAr: 'التعامل مع الحوادث الأمنية من الكشف إلى الإغلاق.',
                    objectives: ['Follow IR procedures', 'Coordinate response', 'Document incidents', 'Write reports'], objectivesAr: ['اتباع إجراءات IR', 'تنسيق الاستجابة', 'توثيق الحوادث', 'كتابة التقارير'],
                    tools: ['Ticketing systems', 'Playbooks', 'Communication tools'],
                    content: { sections: [{ title: 'Incident Lifecycle', titleAr: 'دورة حياة الحادث', content: 'Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned.', contentAr: 'التحضير، الكشف، الاحتواء، الإزالة، الاستعادة، الدروس المستفادة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What comes after containment?', questionAr: 'ماذا يأتي بعد الاحتواء؟', options: ['Detection', 'Recovery', 'Eradication', 'Preparation'], correct: 2, explanation: 'Eradication follows containment.' }] },
                    lab: { title: 'Incident Lab', titleAr: 'مختبر الحوادث', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Handle a phishing incident.', descriptionAr: 'تعامل مع حادثة تصيد.', flag: 'FLAG{1nc1d3nt_h4ndl3r}', hints: ['Follow playbook', 'Document timeline', 'Identify scope'] }
                }
            ]
        },
        'digital-forensics': {
            id: 'digital-forensics',
            domainId: 'blue-team',
            name: 'Digital Forensics',
            nameAr: 'التحليل الجنائي الرقمي',
            description: 'Computer and mobile forensics, evidence collection, analysis, and reporting.',
            descriptionAr: 'التحليل الجنائي للحاسوب والجوال وجمع الأدلة وتحليلها وإعداد التقارير.',
            icon: 'fa-magnifying-glass',
            color: '#10b981',
            difficulty: 'intermediate',
            estimatedHours: 55,
            prerequisites: ['soc-analyst'],
            certification: 'Digital Forensics Investigator',
            modules: [
                {
                    id: 'forensics-fundamentals', name: 'Forensics Fundamentals', nameAr: 'أساسيات التحليل الجنائي', order: 1,
                    estimatedMinutes: 130, description: 'Learn forensic principles and investigation process.', descriptionAr: 'تعلم مبادئ التحليل الجنائي وعملية التحقيق.',
                    objectives: ['Understand evidence handling', 'Create forensic images', 'Document chain of custody', 'Use write blockers'], objectivesAr: ['فهم التعامل مع الأدلة', 'إنشاء صور جنائية', 'توثيق سلسلة الحفظ', 'استخدام حاصرات الكتابة'],
                    tools: ['FTK Imager', 'dd', 'Autopsy', 'Write blockers'],
                    content: { sections: [{ title: 'Evidence Handling', titleAr: 'التعامل مع الأدلة', content: 'Chain of custody, evidence integrity, forensic imaging, and hash verification.', contentAr: 'سلسلة الحفظ وسلامة الأدلة والتصوير الجنائي والتحقق من التجزئة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'Why use write blockers?', questionAr: 'لماذا نستخدم حاصرات الكتابة؟', options: ['Speed up copy', 'Prevent evidence modification', 'Encrypt data', 'Compress files'], correct: 1, explanation: 'Write blockers prevent accidental modification of evidence.' }] },
                    lab: { title: 'Imaging Lab', titleAr: 'مختبر التصوير', difficulty: 'easy', points: 100, estimatedTime: 35, description: 'Create a forensic image.', descriptionAr: 'أنشئ صورة جنائية.', flag: 'FLAG{f0r3ns1cs_101}', hints: ['Use FTK Imager', 'Calculate hashes', 'Document process'] }
                },
                {
                    id: 'disk-forensics', name: 'Disk & File System Forensics', nameAr: 'التحليل الجنائي للأقراص', order: 2,
                    estimatedMinutes: 160, description: 'Analyze disk images and file systems.', descriptionAr: 'تحليل صور الأقراص وأنظمة الملفات.',
                    objectives: ['Parse file systems', 'Recover deleted files', 'Analyze artifacts', 'Extract metadata'], objectivesAr: ['فهم أنظمة الملفات', 'استعادة الملفات المحذوفة', 'تحليل القطع الأثرية', 'استخراج البيانات الوصفية'],
                    tools: ['Autopsy', 'Sleuth Kit', 'X-Ways', 'PhotoRec'],
                    content: { sections: [{ title: 'File System Analysis', titleAr: 'تحليل نظام الملفات', content: 'NTFS, FAT32, ext4 structures. MFT analysis, deleted file recovery, and timeline creation.', contentAr: 'هياكل NTFS و FAT32 و ext4. تحليل MFT واستعادة الملفات المحذوفة وإنشاء الجداول الزمنية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What stores file metadata in NTFS?', questionAr: 'ما الذي يخزن البيانات الوصفية للملفات في NTFS؟', options: ['FAT', 'MFT', 'Inode', 'Registry'], correct: 1, explanation: 'Master File Table (MFT) stores NTFS metadata.' }] },
                    lab: { title: 'Disk Analysis Lab', titleAr: 'مختبر تحليل الأقراص', difficulty: 'medium', points: 200, estimatedTime: 55, description: 'Recover the deleted evidence.', descriptionAr: 'استعد الأدلة المحذوفة.', flag: 'FLAG{d1sk_f0r3ns1cs}', hints: ['Check unallocated space', 'Carve files', 'Check $MFT'] }
                },
                {
                    id: 'memory-forensics', name: 'Memory Forensics', nameAr: 'التحليل الجنائي للذاكرة', order: 3,
                    estimatedMinutes: 180, description: 'Analyze RAM dumps for malware and artifacts.', descriptionAr: 'تحليل تفريغ RAM للبرمجيات الخبيثة والقطع الأثرية.',
                    objectives: ['Capture memory', 'Analyze processes', 'Extract credentials', 'Find injected code'], objectivesAr: ['التقاط الذاكرة', 'تحليل العمليات', 'استخراج بيانات الاعتماد', 'إيجاد الكود المحقون'],
                    tools: ['Volatility', 'WinDbg', 'Rekall', 'DumpIt'],
                    content: { sections: [{ title: 'Memory Analysis', titleAr: 'تحليل الذاكرة', content: 'Process analysis, network connections, registry hives, and malware detection in memory.', contentAr: 'تحليل العمليات واتصالات الشبكة وخلايا السجل واكتشاف البرمجيات الخبيثة في الذاكرة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool analyzes memory dumps?', questionAr: 'ما الأداة التي تحلل تفريغ الذاكرة؟', options: ['Autopsy', 'Volatility', 'Wireshark', 'Burp Suite'], correct: 1, explanation: 'Volatility is the main memory forensics tool.' }] },
                    lab: { title: 'Memory Lab', titleAr: 'مختبر الذاكرة', difficulty: 'hard', points: 300, estimatedTime: 65, description: 'Find the malware in memory.', descriptionAr: 'اعثر على البرمجية الخبيثة في الذاكرة.', flag: 'FLAG{m3m0ry_hunt3r}', hints: ['Use pslist', 'Check malfind', 'Dump suspicious process'] }
                },
                {
                    id: 'network-forensics', name: 'Network Forensics', nameAr: 'التحليل الجنائي للشبكات', order: 4,
                    estimatedMinutes: 150, description: 'Analyze network captures for incidents.', descriptionAr: 'تحليل التقاطات الشبكة للحوادث.',
                    objectives: ['Capture traffic', 'Analyze protocols', 'Extract files', 'Detect C2 traffic'], objectivesAr: ['التقاط الحركة', 'تحليل البروتوكولات', 'استخراج الملفات', 'اكتشاف حركة C2'],
                    tools: ['Wireshark', 'tcpdump', 'NetworkMiner', 'Zeek'],
                    content: { sections: [{ title: 'PCAP Analysis', titleAr: 'تحليل PCAP', content: 'Protocol analysis, session reconstruction, file carving from network traffic.', contentAr: 'تحليل البروتوكولات وإعادة بناء الجلسات واستخراج الملفات من حركة الشبكة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What filter shows HTTP traffic?', questionAr: 'ما الفلتر الذي يعرض حركة HTTP؟', options: ['tcp.port == 80', 'http', 'port 80', 'protocol http'], correct: 1, explanation: 'The http filter shows HTTP traffic in Wireshark.' }] },
                    lab: { title: 'Network Forensics Lab', titleAr: 'مختبر التحليل الجنائي للشبكات', difficulty: 'medium', points: 200, estimatedTime: 50, description: 'Find the exfiltrated data.', descriptionAr: 'اعثر على البيانات المسربة.', flag: 'FLAG{n3tw0rk_f0r3ns1cs}', hints: ['Follow TCP streams', 'Export objects', 'Check DNS'] }
                },
                {
                    id: 'mobile-forensics', name: 'Mobile Forensics', nameAr: 'التحليل الجنائي للجوال', order: 5,
                    estimatedMinutes: 140, description: 'Extract and analyze data from mobile devices.', descriptionAr: 'استخراج وتحليل البيانات من الأجهزة المحمولة.',
                    objectives: ['Acquire mobile data', 'Analyze app data', 'Extract messages', 'Recover deleted data'], objectivesAr: ['الحصول على بيانات الجوال', 'تحليل بيانات التطبيقات', 'استخراج الرسائل', 'استعادة البيانات المحذوفة'],
                    tools: ['Cellebrite', 'Oxygen Forensic', 'MVT', 'adb'],
                    content: { sections: [{ title: 'Mobile Acquisition', titleAr: 'الحصول على بيانات الجوال', content: 'Logical vs physical acquisition, app data analysis, cloud data extraction.', contentAr: 'الحصول المنطقي مقابل المادي وتحليل بيانات التطبيقات واستخراج البيانات السحابية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is logical acquisition?', questionAr: 'ما هو الحصول المنطقي؟', options: ['Full disk copy', 'Accessible files only', 'Memory dump', 'Network capture'], correct: 1, explanation: 'Logical acquisition extracts accessible files through APIs.' }] },
                    lab: { title: 'Mobile Forensics Lab', titleAr: 'مختبر التحليل الجنائي للجوال', difficulty: 'hard', points: 250, estimatedTime: 55, description: 'Analyze the phone backup.', descriptionAr: 'حلل نسخة الهاتف الاحتياطية.', flag: 'FLAG{m0b1l3_f0r3ns1cs}', hints: ['Check SQLite DBs', 'Look at app data', 'Analyze timestamps'] }
                }
            ]
        },
        'malware-analysis': {
            id: 'malware-analysis',
            domainId: 'blue-team',
            name: 'Malware Analysis',
            nameAr: 'تحليل البرمجيات الخبيثة',
            description: 'Static and dynamic malware analysis, reverse engineering, and threat intelligence.',
            descriptionAr: 'التحليل الثابت والديناميكي للبرمجيات الخبيثة والهندسة العكسية واستخبارات التهديدات.',
            icon: 'fa-virus',
            color: '#ec4899',
            difficulty: 'advanced',
            estimatedHours: 70,
            prerequisites: ['digital-forensics'],
            certification: 'Malware Analyst',
            modules: [
                {
                    id: 'malware-fundamentals', name: 'Malware Analysis Fundamentals', nameAr: 'أساسيات تحليل البرمجيات الخبيثة', order: 1,
                    estimatedMinutes: 140, description: 'Understand malware types and analysis environment.', descriptionAr: 'فهم أنواع البرمجيات الخبيثة وبيئة التحليل.',
                    objectives: ['Classify malware types', 'Set up analysis lab', 'Understand evasion techniques', 'Safe sample handling'], objectivesAr: ['تصنيف أنواع البرمجيات الخبيثة', 'إعداد مختبر التحليل', 'فهم تقنيات التهرب', 'التعامل الآمن مع العينات'],
                    tools: ['VirtualBox', 'FlareVM', 'REMnux', 'Any.Run'],
                    content: { sections: [{ title: 'Malware Types', titleAr: 'أنواع البرمجيات الخبيثة', content: 'Ransomware, trojans, worms, rootkits, bootkits, fileless malware, and APT tools.', contentAr: 'برامج الفدية وأحصنة طروادة والديدان وروتكيتس وبوتكيتس والبرمجيات الخبيثة بدون ملفات وأدوات APT.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is fileless malware?', questionAr: 'ما هي البرمجيات الخبيثة بدون ملفات؟', options: ['Deleted malware', 'Lives in memory only', 'Small file size', 'Cloud malware'], correct: 1, explanation: 'Fileless malware operates entirely in memory.' }] },
                    lab: { title: 'Lab Setup', titleAr: 'إعداد المختبر', difficulty: 'easy', points: 100, estimatedTime: 40, description: 'Set up your analysis VM.', descriptionAr: 'أعد جهازك الظاهري للتحليل.', flag: 'FLAG{m4lw4r3_l4b}', hints: ['Use FlareVM', 'Snapshot before analysis', 'Network isolation'] }
                },
                {
                    id: 'static-analysis', name: 'Static Analysis', nameAr: 'التحليل الثابت', order: 2,
                    estimatedMinutes: 180, description: 'Analyze malware without execution.', descriptionAr: 'تحليل البرمجيات الخبيثة دون تنفيذها.',
                    objectives: ['Extract strings', 'Analyze PE headers', 'Identify packers', 'Find IOCs'], objectivesAr: ['استخراج النصوص', 'تحليل رؤوس PE', 'تحديد الحزم', 'إيجاد IOCs'],
                    tools: ['PEStudio', 'FLOSS', 'Detect It Easy', 'CFF Explorer'],
                    content: { sections: [{ title: 'PE Analysis', titleAr: 'تحليل PE', content: 'PE headers, imports, exports, sections, and resource analysis for Windows executables.', contentAr: 'رؤوس PE والاستيرادات والتصديرات والأقسام وتحليل الموارد لملفات Windows التنفيذية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does high entropy indicate?', questionAr: 'ماذا تشير الانتروبيا العالية؟', options: ['Normal file', 'Packed/encrypted', 'Corrupted', 'Empty file'], correct: 1, explanation: 'High entropy suggests packing or encryption.' }] },
                    lab: { title: 'Static Analysis Lab', titleAr: 'مختبر التحليل الثابت', difficulty: 'medium', points: 200, estimatedTime: 55, description: 'Analyze the suspicious PE file.', descriptionAr: 'حلل ملف PE المشبوه.', flag: 'FLAG{st4t1c_4n4lys1s}', hints: ['Check imports', 'Extract strings', 'Identify packer'] }
                },
                {
                    id: 'dynamic-analysis', name: 'Dynamic Analysis', nameAr: 'التحليل الديناميكي', order: 3,
                    estimatedMinutes: 200, description: 'Execute and observe malware behavior.', descriptionAr: 'تنفيذ ومراقبة سلوك البرمجيات الخبيثة.',
                    objectives: ['Monitor processes', 'Capture network traffic', 'Track file changes', 'Observe registry modifications'], objectivesAr: ['مراقبة العمليات', 'التقاط حركة الشبكة', 'تتبع تغييرات الملفات', 'مراقبة تعديلات السجل'],
                    tools: ['Process Monitor', 'Wireshark', 'Regshot', 'Fakenet-NG'],
                    content: { sections: [{ title: 'Behavioral Analysis', titleAr: 'التحليل السلوكي', content: 'Monitor process creation, file operations, registry changes, and network connections.', contentAr: 'مراقبة إنشاء العمليات وعمليات الملفات وتغييرات السجل واتصالات الشبكة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What tool monitors file/registry changes?', questionAr: 'ما الأداة التي تراقب تغييرات الملفات/السجل؟', options: ['Wireshark', 'Process Monitor', 'Nmap', 'Burp Suite'], correct: 1, explanation: 'Process Monitor tracks file and registry activity.' }] },
                    lab: { title: 'Dynamic Analysis Lab', titleAr: 'مختبر التحليل الديناميكي', difficulty: 'hard', points: 300, estimatedTime: 70, description: 'Execute and analyze the malware.', descriptionAr: 'نفذ وحلل البرمجية الخبيثة.', flag: 'FLAG{dyn4m1c_4n4lys1s}', hints: ['Run procmon first', 'Capture network', 'Check persistence'] }
                },
                {
                    id: 'malware-reversing', name: 'Malware Reverse Engineering', nameAr: 'الهندسة العكسية للبرمجيات الخبيثة', order: 4,
                    estimatedMinutes: 220, description: 'Disassemble and debug malware code.', descriptionAr: 'تفكيك وتصحيح كود البرمجيات الخبيثة.',
                    objectives: ['Use disassemblers', 'Debug malware', 'Decode obfuscation', 'Extract C2 configs'], objectivesAr: ['استخدام المفككات', 'تصحيح البرمجيات الخبيثة', 'فك التشويش', 'استخراج إعدادات C2'],
                    tools: ['IDA Pro', 'Ghidra', 'x64dbg', 'Binary Ninja'],
                    content: { sections: [{ title: 'Reverse Engineering', titleAr: 'الهندسة العكسية', content: 'Control flow analysis, function identification, string decryption, and configuration extraction.', contentAr: 'تحليل تدفق التحكم وتحديد الوظائف وفك تشفير النصوص واستخراج التكوينات.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is Ghidra?', questionAr: 'ما هو Ghidra؟', options: ['Malware', 'Free disassembler by NSA', 'Operating system', 'Programming language'], correct: 1, explanation: 'Ghidra is a free reverse engineering tool by NSA.' }] },
                    lab: { title: 'Reversing Lab', titleAr: 'مختبر الهندسة العكسية', difficulty: 'hard', points: 400, estimatedTime: 90, description: 'Extract the C2 server address.', descriptionAr: 'استخرج عنوان خادم C2.', flag: 'FLAG{r3v3rs3_3ng1n33r}', hints: ['Find main function', 'Check string references', 'Decrypt config'] }
                }
            ]
        },
        'threat-hunting': {
            id: 'threat-hunting',
            domainId: 'blue-team',
            name: 'Threat Hunting',
            nameAr: 'صيد التهديدات',
            description: 'Proactive threat detection, hunting methodologies, and threat intelligence.',
            descriptionAr: 'الكشف الاستباقي عن التهديدات ومنهجيات الصيد واستخبارات التهديدات.',
            icon: 'fa-crosshairs',
            color: '#f97316',
            difficulty: 'advanced',
            estimatedHours: 60,
            prerequisites: ['soc-analyst'],
            certification: 'Threat Hunter',
            modules: [
                {
                    id: 'hunting-fundamentals', name: 'Threat Hunting Fundamentals', nameAr: 'أساسيات صيد التهديدات', order: 1,
                    estimatedMinutes: 130, description: 'Learn proactive threat detection mindset.', descriptionAr: 'تعلم عقلية الكشف الاستباقي عن التهديدات.',
                    objectives: ['Understand hunting vs monitoring', 'Know ATT&CK framework', 'Create hypotheses', 'Document findings'], objectivesAr: ['فهم الصيد مقابل المراقبة', 'معرفة إطار ATT&CK', 'إنشاء فرضيات', 'توثيق النتائج'],
                    tools: ['MITRE ATT&CK', 'SIEM', 'EDR', 'Hunting notebooks'],
                    content: { sections: [{ title: 'Hunting Mindset', titleAr: 'عقلية الصيد', content: 'Assume breach mentality, hypothesis-driven hunting, and intelligence-led detection.', contentAr: 'عقلية افتراض الاختراق والصيد المبني على الفرضيات والكشف المبني على الاستخبارات.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is hypothesis-driven hunting?', questionAr: 'ما هو الصيد المبني على الفرضيات؟', options: ['Random search', 'Testing specific theory', 'Automated detection', 'Wait for alerts'], correct: 1, explanation: 'Hypothesis-driven hunting tests specific threat theories.' }] },
                    lab: { title: 'Hunting Basics Lab', titleAr: 'مختبر أساسيات الصيد', difficulty: 'easy', points: 100, estimatedTime: 35, description: 'Create a hunting hypothesis.', descriptionAr: 'أنشئ فرضية صيد.', flag: 'FLAG{hunt3r_m1nd}', hints: ['Use ATT&CK', 'Pick a technique', 'Define data sources'] }
                },
                {
                    id: 'hunting-methodologies', name: 'Hunting Methodologies', nameAr: 'منهجيات الصيد', order: 2,
                    estimatedMinutes: 160, description: 'Apply structured hunting approaches.', descriptionAr: 'تطبيق منهجيات صيد منظمة.',
                    objectives: ['Use data-driven hunting', 'Apply PEAK methodology', 'Hunt across data sources', 'Measure effectiveness'], objectivesAr: ['استخدام الصيد المبني على البيانات', 'تطبيق منهجية PEAK', 'الصيد عبر مصادر البيانات', 'قياس الفعالية'],
                    tools: ['Jupyter notebooks', 'KQL', 'SPL', 'Python'],
                    content: { sections: [{ title: 'Hunting Methods', titleAr: 'طرق الصيد', content: 'Intel-driven, hypothesis-driven, data-driven, and situational hunting approaches.', contentAr: 'الصيد المبني على الاستخبارات والفرضيات والبيانات والوضعية.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is situational hunting?', questionAr: 'ما هو الصيد الوضعي؟', options: ['Random hunting', 'Based on current threats', 'Automated only', 'Historical analysis'], correct: 1, explanation: 'Situational hunting responds to current threat landscape.' }] },
                    lab: { title: 'Methodology Lab', titleAr: 'مختبر المنهجيات', difficulty: 'medium', points: 180, estimatedTime: 50, description: 'Execute a hunt using PEAK.', descriptionAr: 'نفذ صيدة باستخدام PEAK.', flag: 'FLAG{m3th0d0l0gy}', hints: ['Define scope', 'Collect data', 'Analyze patterns'] }
                },
                {
                    id: 'ioc-analysis', name: 'IOC & IOA Analysis', nameAr: 'تحليل IOC و IOA', order: 3,
                    estimatedMinutes: 150, description: 'Work with indicators of compromise and attack.', descriptionAr: 'العمل مع مؤشرات الاختراق والهجوم.',
                    objectives: ['Differentiate IOC vs IOA', 'Create detection rules', 'Use YARA rules', 'Hunt for behaviors'], objectivesAr: ['التفريق بين IOC و IOA', 'إنشاء قواعد كشف', 'استخدام قواعد YARA', 'الصيد بالسلوكيات'],
                    tools: ['YARA', 'Sigma', 'OpenIOC', 'STIX/TAXII'],
                    content: { sections: [{ title: 'IOC vs IOA', titleAr: 'IOC مقابل IOA', content: 'IOCs are artifacts (hashes, IPs), IOAs are behaviors (process injection, lateral movement).', contentAr: 'IOCs هي قطع أثرية (تجزئات، IPs)، IOAs هي سلوكيات (حقن العمليات، الحركة الجانبية).' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is an IOA?', questionAr: 'ما هو IOA؟', options: ['File hash', 'IP address', 'Attack behavior', 'Domain name'], correct: 2, explanation: 'IOA is an Indicator of Attack - a behavior pattern.' }] },
                    lab: { title: 'IOC Hunting Lab', titleAr: 'مختبر صيد IOC', difficulty: 'medium', points: 200, estimatedTime: 45, description: 'Hunt using provided IOCs.', descriptionAr: 'اصطد باستخدام IOCs المقدمة.', flag: 'FLAG{10c_hunt3r}', hints: ['Search for hashes', 'Check IPs', 'Write YARA rule'] }
                },
                {
                    id: 'threat-intel', name: 'Threat Intelligence', nameAr: 'استخبارات التهديدات', order: 4,
                    estimatedMinutes: 140, description: 'Use threat intelligence for hunting.', descriptionAr: 'استخدام استخبارات التهديدات للصيد.',
                    objectives: ['Consume threat feeds', 'Analyze APT reports', 'Create intel from hunts', 'Share intelligence'], objectivesAr: ['استهلاك موجزات التهديدات', 'تحليل تقارير APT', 'إنشاء استخبارات من الصيد', 'مشاركة الاستخبارات'],
                    tools: ['MISP', 'OpenCTI', 'AlienVault OTX', 'ThreatConnect'],
                    content: { sections: [{ title: 'Threat Intelligence', titleAr: 'استخبارات التهديدات', content: 'Strategic, tactical, and operational intelligence. TLP levels and information sharing.', contentAr: 'الاستخبارات الاستراتيجية والتكتيكية والتشغيلية. مستويات TLP ومشاركة المعلومات.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does TLP:RED mean?', questionAr: 'ماذا يعني TLP:RED؟', options: ['Public', 'Internal only', 'Limited sharing', 'No sharing outside'], correct: 3, explanation: 'TLP:RED means no sharing outside authorized recipients.' }] },
                    lab: { title: 'Intel Lab', titleAr: 'مختبر الاستخبارات', difficulty: 'medium', points: 180, estimatedTime: 50, description: 'Hunt using threat intel.', descriptionAr: 'اصطد باستخدام استخبارات التهديدات.', flag: 'FLAG{thr34t_1nt3l}', hints: ['Check APT report', 'Extract IOCs', 'Search in logs'] }
                }
            ]
        },
        'incident-response': {
            id: 'incident-response',
            domainId: 'blue-team',
            name: 'Incident Response',
            nameAr: 'الاستجابة للحوادث',
            description: 'Incident handling, containment, eradication, and recovery procedures.',
            descriptionAr: 'التعامل مع الحوادث والاحتواء والإزالة وإجراءات الاستعادة.',
            icon: 'fa-fire-extinguisher',
            color: '#ef4444',
            difficulty: 'intermediate',
            estimatedHours: 40,
            prerequisites: ['soc-analyst'],
            certification: 'Incident Response Handler',
            modules: [
                {
                    id: 'ir-fundamentals', name: 'Incident Response Fundamentals', nameAr: 'أساسيات الاستجابة للحوادث', order: 1,
                    estimatedMinutes: 120, description: 'Learn IR frameworks and preparation.', descriptionAr: 'تعلم أطر IR والتحضير.',
                    objectives: ['Know NIST IR phases', 'Create IR plans', 'Build IR team', 'Prepare playbooks'], objectivesAr: ['معرفة مراحل NIST IR', 'إنشاء خطط IR', 'بناء فريق IR', 'إعداد كتب اللعب'],
                    tools: ['IR playbooks', 'Case management', 'Communication tools'],
                    content: { sections: [{ title: 'IR Phases', titleAr: 'مراحل IR', content: 'NIST phases: Preparation, Detection/Analysis, Containment/Eradication/Recovery, Post-Incident.', contentAr: 'مراحل NIST: التحضير، الكشف/التحليل، الاحتواء/الإزالة/الاستعادة، ما بعد الحادث.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is the first IR phase?', questionAr: 'ما هي أول مرحلة IR؟', options: ['Detection', 'Preparation', 'Containment', 'Recovery'], correct: 1, explanation: 'Preparation is the first phase - before incidents occur.' }] },
                    lab: { title: 'IR Prep Lab', titleAr: 'مختبر التحضير IR', difficulty: 'easy', points: 100, estimatedTime: 35, description: 'Create an IR playbook.', descriptionAr: 'أنشئ كتاب لعب IR.', flag: 'FLAG{1r_pr3p4r3d}', hints: ['Define roles', 'List tools', 'Document steps'] }
                },
                {
                    id: 'detection', name: 'Detection & Analysis', nameAr: 'الكشف والتحليل', order: 2,
                    estimatedMinutes: 150, description: 'Detect and analyze security incidents.', descriptionAr: 'اكتشاف وتحليل الحوادث الأمنية.',
                    objectives: ['Identify incident indicators', 'Perform initial analysis', 'Determine scope', 'Classify severity'], objectivesAr: ['تحديد مؤشرات الحادث', 'إجراء التحليل الأولي', 'تحديد النطاق', 'تصنيف الخطورة'],
                    tools: ['SIEM', 'EDR', 'SOAR', 'Log analyzers'],
                    content: { sections: [{ title: 'Incident Detection', titleAr: 'كشف الحوادث', content: 'Indicators of compromise, alert correlation, initial scoping, and severity classification.', contentAr: 'مؤشرات الاختراق وربط التنبيهات والنطاق الأولي وتصنيف الخطورة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What determines incident severity?', questionAr: 'ما الذي يحدد خطورة الحادث؟', options: ['Time of day', 'Impact and scope', 'Analyst preference', 'Random assignment'], correct: 1, explanation: 'Severity is based on impact and scope of the incident.' }] },
                    lab: { title: 'Detection Lab', titleAr: 'مختبر الكشف', difficulty: 'medium', points: 180, estimatedTime: 50, description: 'Analyze the incident indicators.', descriptionAr: 'حلل مؤشرات الحادث.', flag: 'FLAG{d3t3ct10n_pr0}', hints: ['Check timeline', 'Correlate events', 'Identify affected systems'] }
                },
                {
                    id: 'containment', name: 'Containment & Eradication', nameAr: 'الاحتواء والإزالة', order: 3,
                    estimatedMinutes: 160, description: 'Contain and remove threats.', descriptionAr: 'احتواء وإزالة التهديدات.',
                    objectives: ['Isolate affected systems', 'Block malicious IOCs', 'Remove malware', 'Patch vulnerabilities'], objectivesAr: ['عزل الأنظمة المتأثرة', 'حظر IOCs الخبيثة', 'إزالة البرمجيات الخبيثة', 'ترقيع الثغرات'],
                    tools: ['EDR', 'Firewall', 'Network isolation', 'Antimalware'],
                    content: { sections: [{ title: 'Containment Strategies', titleAr: 'استراتيجيات الاحتواء', content: 'Short-term vs long-term containment, evidence preservation, and eradication steps.', contentAr: 'الاحتواء قصير الأمد مقابل طويل الأمد والحفاظ على الأدلة وخطوات الإزالة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'Why preserve evidence during containment?', questionAr: 'لماذا نحافظ على الأدلة أثناء الاحتواء؟', options: ['Not important', 'For legal/forensic purposes', 'To slow response', 'Regulatory only'], correct: 1, explanation: 'Evidence preservation supports forensics and legal action.' }] },
                    lab: { title: 'Containment Lab', titleAr: 'مختبر الاحتواء', difficulty: 'hard', points: 250, estimatedTime: 60, description: 'Contain the active breach.', descriptionAr: 'احتوِ الاختراق النشط.', flag: 'FLAG{c0nt41nm3nt}', hints: ['Isolate systems', 'Block C2', 'Collect evidence first'] }
                },
                {
                    id: 'recovery', name: 'Recovery & Lessons Learned', nameAr: 'الاستعادة والدروس المستفادة', order: 4,
                    estimatedMinutes: 130, description: 'Restore operations and improve defenses.', descriptionAr: 'استعادة العمليات وتحسين الدفاعات.',
                    objectives: ['Restore systems safely', 'Verify clean state', 'Document lessons', 'Update defenses'], objectivesAr: ['استعادة الأنظمة بأمان', 'التحقق من الحالة النظيفة', 'توثيق الدروس', 'تحديث الدفاعات'],
                    tools: ['Backups', 'Monitoring', 'Documentation tools'],
                    content: { sections: [{ title: 'Recovery Process', titleAr: 'عملية الاستعادة', content: 'Phased recovery, validation, monitoring for reinfection, and post-incident review.', contentAr: 'الاستعادة المرحلية والتحقق ومراقبة إعادة الإصابة ومراجعة ما بعد الحادث.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is a post-incident review?', questionAr: 'ما هي مراجعة ما بعد الحادث؟', options: ['Blame session', 'Learning from incident', 'Ignore mistakes', 'Delete evidence'], correct: 1, explanation: 'Post-incident review identifies improvements, not blame.' }] },
                    lab: { title: 'Recovery Lab', titleAr: 'مختبر الاستعادة', difficulty: 'medium', points: 180, estimatedTime: 45, description: 'Complete the recovery process.', descriptionAr: 'أكمل عملية الاستعادة.', flag: 'FLAG{r3c0v3ry_c0mpl3t3}', hints: ['Verify backups', 'Monitor closely', 'Document everything'] }
                }
            ]
        },
        'security-engineering': {
            id: 'security-engineering',
            domainId: 'blue-team',
            name: 'Security Engineering',
            nameAr: 'هندسة الأمان',
            description: 'Security architecture, hardening, and defensive infrastructure implementation.',
            descriptionAr: 'بنية الأمان والتقوية وتنفيذ البنية التحتية الدفاعية.',
            icon: 'fa-helmet-safety',
            color: '#6366f1',
            difficulty: 'advanced',
            estimatedHours: 65,
            prerequisites: ['soc-analyst'],
            certification: 'Security Engineer',
            modules: [
                {
                    id: 'security-architecture', name: 'Security Architecture', nameAr: 'بنية الأمان', order: 1,
                    estimatedMinutes: 160, description: 'Design secure systems and networks.', descriptionAr: 'تصميم أنظمة وشبكات آمنة.',
                    objectives: ['Apply defense in depth', 'Design secure networks', 'Implement zero trust', 'Use security frameworks'], objectivesAr: ['تطبيق الدفاع المتعمق', 'تصميم شبكات آمنة', 'تنفيذ الثقة المعدومة', 'استخدام أطر الأمان'],
                    tools: ['Network diagrams', 'Security frameworks', 'Risk assessment tools'],
                    content: { sections: [{ title: 'Defense in Depth', titleAr: 'الدفاع المتعمق', content: 'Multiple security layers, network segmentation, and zero trust architecture principles.', contentAr: 'طبقات أمان متعددة وتجزئة الشبكة ومبادئ بنية الثقة المعدومة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is zero trust principle?', questionAr: 'ما هو مبدأ الثقة المعدومة؟', options: ['Trust internal', 'Never trust, always verify', 'Trust everyone', 'No security needed'], correct: 1, explanation: 'Zero trust: Never trust, always verify, regardless of location.' }] },
                    lab: { title: 'Architecture Lab', titleAr: 'مختبر البنية', difficulty: 'medium', points: 180, estimatedTime: 55, description: 'Design a secure network.', descriptionAr: 'صمم شبكة آمنة.', flag: 'FLAG{s3cur3_4rch}', hints: ['Segment networks', 'Apply least privilege', 'Plan DMZ'] }
                },
                {
                    id: 'hardening', name: 'System Hardening', nameAr: 'تقوية الأنظمة', order: 2,
                    estimatedMinutes: 170, description: 'Secure operating systems and applications.', descriptionAr: 'تأمين أنظمة التشغيل والتطبيقات.',
                    objectives: ['Harden Windows', 'Harden Linux', 'Apply CIS benchmarks', 'Secure configurations'], objectivesAr: ['تقوية Windows', 'تقوية Linux', 'تطبيق معايير CIS', 'تكوينات آمنة'],
                    tools: ['CIS benchmarks', 'GPO', 'Ansible', 'SCAP'],
                    content: { sections: [{ title: 'System Hardening', titleAr: 'تقوية الأنظمة', content: 'Remove unnecessary services, configure secure settings, apply CIS benchmarks, and regular patching.', contentAr: 'إزالة الخدمات غير الضرورية وتكوين إعدادات آمنة وتطبيق معايير CIS والترقيع المنتظم.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What are CIS benchmarks?', questionAr: 'ما هي معايير CIS؟', options: ['Malware', 'Security configuration standards', 'Hacking tools', 'Programming language'], correct: 1, explanation: 'CIS benchmarks are security configuration best practices.' }] },
                    lab: { title: 'Hardening Lab', titleAr: 'مختبر التقوية', difficulty: 'medium', points: 200, estimatedTime: 60, description: 'Harden the server.', descriptionAr: 'قوِّ الخادم.', flag: 'FLAG{h4rd3n3d}', hints: ['Apply CIS', 'Disable services', 'Configure firewall'] }
                },
                {
                    id: 'network-defense', name: 'Network Defense', nameAr: 'الدفاع عن الشبكات', order: 3,
                    estimatedMinutes: 160, description: 'Deploy network security controls.', descriptionAr: 'نشر ضوابط أمان الشبكة.',
                    objectives: ['Configure firewalls', 'Deploy IDS/IPS', 'Implement network monitoring', 'Set up VPNs'], objectivesAr: ['إعداد الجدران النارية', 'نشر IDS/IPS', 'تنفيذ مراقبة الشبكة', 'إعداد VPNs'],
                    tools: ['pfSense', 'Suricata', 'Zeek', 'WireGuard'],
                    content: { sections: [{ title: 'Network Security', titleAr: 'أمان الشبكة', content: 'Firewalls, IDS/IPS, network segmentation, VPNs, and traffic monitoring.', contentAr: 'الجدران النارية و IDS/IPS وتجزئة الشبكة و VPNs ومراقبة الحركة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What is IPS vs IDS?', questionAr: 'ما الفرق بين IPS و IDS؟', options: ['Same thing', 'IPS blocks, IDS detects', 'IDS blocks, IPS detects', 'Neither detects'], correct: 1, explanation: 'IPS actively blocks while IDS only detects and alerts.' }] },
                    lab: { title: 'Network Defense Lab', titleAr: 'مختبر الدفاع عن الشبكات', difficulty: 'hard', points: 280, estimatedTime: 70, description: 'Deploy IDS rules.', descriptionAr: 'انشر قواعد IDS.', flag: 'FLAG{n3tw0rk_d3f3ns3}', hints: ['Configure Suricata', 'Write custom rules', 'Monitor alerts'] }
                },
                {
                    id: 'security-automation', name: 'Security Automation', nameAr: 'أتمتة الأمان', order: 4,
                    estimatedMinutes: 150, description: 'Automate security operations.', descriptionAr: 'أتمتة عمليات الأمان.',
                    objectives: ['Use SOAR platforms', 'Write automation scripts', 'Create playbooks', 'Integrate tools'], objectivesAr: ['استخدام منصات SOAR', 'كتابة سكريبتات الأتمتة', 'إنشاء كتب اللعب', 'دمج الأدوات'],
                    tools: ['Shuffle', 'TheHive', 'Cortex', 'Python'],
                    content: { sections: [{ title: 'Security Automation', titleAr: 'أتمتة الأمان', content: 'SOAR platforms, playbook automation, API integrations, and response automation.', contentAr: 'منصات SOAR وأتمتة كتب اللعب وتكامل API وأتمتة الاستجابة.' }] },
                    quiz: { passingScore: 70, questions: [{ question: 'What does SOAR stand for?', questionAr: 'ما معنى SOAR؟', options: ['Security operations and response', 'Security Orchestration Automation Response', 'Software security', 'System analysis'], correct: 1, explanation: 'SOAR = Security Orchestration, Automation, and Response.' }] },
                    lab: { title: 'Automation Lab', titleAr: 'مختبر الأتمتة', difficulty: 'hard', points: 300, estimatedTime: 75, description: 'Create an automated response.', descriptionAr: 'أنشئ استجابة آلية.', flag: 'FLAG{4ut0m4t10n}', hints: ['Use Shuffle', 'Create workflow', 'Test playbook'] }
                }
            ]
        },
        'web-security-architecture-path': {
            id: 'web-security-architecture-path',
            domainId: 'red-team',
            name: 'Web Security Architecture & Exploitation',
            nameAr: 'أمن تطبيقات الويب المعماري',
            description: 'A complete journey from source code analysis to exploiting complex architectural flaws. Master Node.js, Advanced Data, and API Security.',
            descriptionAr: 'رحلة كاملة من فهم الكود المصدري إلى استغلال أعقد الثغرات المعمارية.',
            icon: 'fa-shield-virus',
            color: '#8b5cf6',
            difficulty: 'expert',
            estimatedHours: 350,
            prerequisites: ['web-pentesting'],
            certification: 'OSWE / BSC',
            modules: [
                {
                    id: 'web-sec-node-internals',
                    name: 'Node.js & Express: From Logic to Runtime',
                    nameAr: 'أمن Node.js و Express',
                    order: 1,
                    estimatedMinutes: 2400,
                    description: 'Deep dive into Node.js internals, event loop security, and Express.js middleware vulnerabilities.',
                    descriptionAr: 'تعمق في داخلية Node.js وأمان حلقة الأحداث وثغرات Express.js middleware.'
                },
                {
                    id: 'web-sec-data-exploitation',
                    name: 'Advanced Data & Database Exploitation',
                    nameAr: 'استغلال قواعد البيانات المتقدم',
                    order: 2,
                    estimatedMinutes: 2400,
                    description: 'Master advanced SQL injection, NoSQL injection, and data exfiltration techniques.',
                    descriptionAr: 'إتقان حقن SQL المتقدم وحقن NoSQL وتقنيات استخراج البيانات.'
                },
                {
                    id: 'web-sec-modern-client-api',
                    name: 'Modern Client-Side & API Security',
                    nameAr: 'أمن الواجهات والأ API الحديثة',
                    order: 3,
                    estimatedMinutes: 2400,
                    description: 'Exploit modern client-side frameworks and complex API logic flaws.',
                    descriptionAr: 'استغلال أطر العمل الحديثة من جانب العميل وثغرات منطق API المعقدة.'
                }
            ]
        }
    },

    // ========== SMART GUIDANCE RULES ==========
    guidanceRules: {
        // Topics with their related supplementary resources
        topics: {
            'sql_injection': {
                name: 'SQL Injection',
                nameAr: 'حقن SQL',
                subtopics: ['union_attacks', 'blind_sqli', 'error_based_sqli'],
                supplementaryContent: [
                    { type: 'video', url: 'https://www.youtube.com/watch?v=example1', duration: 5, title: 'Understanding UNION Attacks' },
                    { type: 'article', url: '/resources/sqli-cheatsheet', title: 'SQL Injection Cheat Sheet' }
                ]
            },
            'xss': {
                name: 'Cross-Site Scripting',
                nameAr: 'XSS',
                subtopics: ['reflected_xss', 'stored_xss', 'dom_xss'],
                supplementaryContent: [
                    { type: 'video', url: 'https://www.youtube.com/watch?v=example2', duration: 7, title: 'XSS Filter Bypass Techniques' },
                    { type: 'exercise', url: '/labs/xss-practice', title: 'Interactive XSS Practice' }
                ]
            }
        },

        // Trigger conditions for recommendations
        triggers: {
            'quiz_fail_2': {
                message: 'نلاحظ أنك تواجه صعوبة في هذا المفهوم. إليك بعض الموارد الإضافية!',
                messageEn: 'We noticed you\'re having difficulty with this concept. Here are some extra resources!',
                action: 'suggest_supplementary'
            },
            'score_below_60': {
                message: 'درجتك أقل من المطلوب. دعنا نراجع المفهوم معاً!',
                messageEn: 'Your score is below required. Let\'s review the concept together!',
                action: 'review_module'
            }
        }
    },

    // ========== USER RANKS ==========
    ranks: [
        { level: 1, name: 'Script Kiddie', nameAr: 'مبتدئ', minPoints: 0, color: '#94a3b8' },
        { level: 2, name: 'Rookie Hacker', nameAr: 'هاكر مبتدئ', minPoints: 500, color: '#22c55e' },
        { level: 3, name: 'Security Analyst', nameAr: 'محلل أمني', minPoints: 2000, color: '#3b82f6' },
        { level: 4, name: 'Penetration Tester', nameAr: 'مختبر اختراق', minPoints: 5000, color: '#8b5cf6' },
        { level: 5, name: 'Security Expert', nameAr: 'خبير أمني', minPoints: 10000, color: '#f59e0b' },
        { level: 6, name: 'Elite Hacker', nameAr: 'هاكر نخبة', minPoints: 20000, color: '#ef4444' },
        { level: 7, name: 'Security Guru', nameAr: 'خبير متمرس', minPoints: 50000, color: '#ec4899' },
        { level: 8, name: 'Legend', nameAr: 'أسطورة', minPoints: 100000, color: '#ffd700' }
    ],

    // ========== ACHIEVEMENTS ==========
    achievements: [
        { id: 'first-blood', name: 'First Blood', nameAr: 'الدم الأول', description: 'Complete your first lab', icon: '🩸', points: 50 },
        { id: 'path-starter', name: 'Path Starter', nameAr: 'بداية المسار', description: 'Start a learning path', icon: '🚀', points: 25 },
        { id: 'path-completer', name: 'Path Completer', nameAr: 'منهي المسار', description: 'Complete a full learning path', icon: '🏆', points: 500 },
        { id: 'quiz-master', name: 'Quiz Master', nameAr: 'سيد الاختبارات', description: 'Score 100% on 5 quizzes', icon: '🧠', points: 200 },
        { id: 'lab-rat', name: 'Lab Rat', nameAr: 'فأر المختبر', description: 'Complete 10 labs', icon: '🐀', points: 300 },
        { id: 'speed-demon', name: 'Speed Demon', nameAr: 'شيطان السرعة', description: 'Complete a lab in under 10 minutes', icon: '⚡', points: 100 },
        { id: 'streak-week', name: 'Week Warrior', nameAr: 'محارب الأسبوع', description: 'Maintain a 7-day streak', icon: '🔥', points: 150 },
        { id: 'red-certified', name: 'Red Team Certified', nameAr: 'شهادة الفريق الأحمر', description: 'Earn a Red Team certification', icon: '🔴', points: 1000 },
        { id: 'blue-certified', name: 'Blue Team Certified', nameAr: 'شهادة الفريق الأزرق', description: 'Earn a Blue Team certification', icon: '🔵', points: 1000 }
    ]
};

// ========== HELPER FUNCTIONS ==========

/**
 * Get domain by ID
 */
function getDomainById(domainId) {
    return platformData.domains.find(d => d.id === domainId);
}

/**
 * Get path by ID
 */
function getPathById(pathId) {
    return platformData.paths[pathId];
}

/**
 * Get all paths for a domain
 */
function getPathsByDomain(domainId) {
    return Object.values(platformData.paths).filter(p => p.domainId === domainId);
}

/**
 * Get user rank based on points
 */
function getUserRank(points) {
    const ranks = platformData.ranks.slice().reverse();
    return ranks.find(r => points >= r.minPoints) || platformData.ranks[0];
}

/**
 * Get next rank and points needed
 */
function getNextRank(points) {
    const currentRank = getUserRank(points);
    const nextIndex = platformData.ranks.findIndex(r => r.level === currentRank.level) + 1;
    if (nextIndex >= platformData.ranks.length) {
        return { rank: null, pointsNeeded: 0 };
    }
    const nextRank = platformData.ranks[nextIndex];
    return {
        rank: nextRank,
        pointsNeeded: nextRank.minPoints - points
    };
}

/**
 * Check if guidance is needed for a topic
 */
function checkGuidanceNeeded(userPerformance) {
    const rules = platformData.guidanceRules.triggers;

    if (userPerformance.failures >= 2) {
        return {
            needed: true,
            trigger: 'quiz_fail_2',
            ...rules['quiz_fail_2']
        };
    }

    if (userPerformance.lastScore && userPerformance.lastScore < 60) {
        return {
            needed: true,
            trigger: 'score_below_60',
            ...rules['score_below_60']
        };
    }

    return { needed: false };
}

/**
 * Get supplementary content for a topic
 */
function getSupplementaryContent(topic) {
    const topicData = platformData.guidanceRules.topics[topic];
    return topicData ? topicData.supplementaryContent : [];
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        platformData,
        getDomainById,
        getPathById,
        getPathsByDomain,
        getUserRank,
        getNextRank,
        checkGuidanceNeeded,
        getSupplementaryContent
    };
}
