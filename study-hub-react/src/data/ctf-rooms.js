export const ctfRooms = {
    web: [
        {
            id: 'ctf-intern-mistake',
            title: { ar: 'خطأ المتدرب', en: "The Intern's Mistake" },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 50,
            tags: ['source-code', 'comments', 'devtools'],
            description: {
                ar: 'متدرب نسي يحذف الملاحظات. هل تستطيع إيجاد الأسرار في الكود؟',
                en: 'An intern forgot to scrub the notes. Can you find the secrets in the source?'
            },
            scenario: {
                ar: 'مطور مبتدئ في TechCorp نشر نسخة تجريبية من صفحتهم الرئيسية. للأسف، لم يتبع قائمة الأمان وترك تعليقات المطور تحتوي على رموز وصول حساسة.',
                en: "A junior developer at 'TechCorp' just pushed a beta version of their landing page. Unfortunately, they didn't follow the security checklist and left developer comments containing sensitive access tokens."
            },
            labConfig: {
                type: 'web',
                target: 'https://intern-landing-page.studyhub.local',
                content: `<!-- [TODO] Remove this before prod - FLAG: AG{Y0u_F0und_7h3_C0mm3n7} -->`
            },
            hints: [
                { id: 1, text: { ar: 'تحقق من كود الصفحة (View Source) وابحث عن التعليقات.', en: 'Check the page source code (View Source) and look for comments.' }, cost: 10 }
            ],
            writeup: {
                ar: 'يبدأ هذا التحدي بتعريفك على "فحص المصدر". في العالم الحقيقي، يترك المطورون أحياناً تعليقات حساسة (Sensitive Comments) تحتوي على كلمات مرور أو مسارات ملفات مخفية.',
                en: "This challenge introduces 'Source Inspection'. In the real world, developers occasionally leave sensitive comments containing passwords or hidden file paths."
            },
            tasks: [
                { id: 1, question: { ar: 'افحص كود المصدر', en: 'Inspect Site Source Code' }, points: 10 },
                { id: 2, question: { ar: 'ابحث عن تعليقات HTML', en: 'Find HTML Comments' }, points: 20 },
                { id: 3, question: { ar: 'استخرج رمز الوصول (Flag)', en: 'Extract Access Token (Flag)' }, answer: 'AG{Y0u_F0und_7h3_C0mm3n7}', points: 20 }
            ]
        },
        {
            id: 'ctf-leaky-bucket',
            title: { ar: 'الدلو المتسرب', en: 'The Leaky Bucket' },
            difficulty: 'easy',
            estimatedTime: '30 min',
            points: 100,
            tags: ['data-exposure', 'enumeration', 'robots.txt'],
            description: {
                ar: 'موظف غاضب ترك أكثر من مجرد خطاب استقالة. هل يمكنك العثور على ملفات robots؟',
                en: 'A disgruntled employee left more than just a resignation letter. Can you find the robots?'
            },
            scenario: {
                ar: 'أحد الموظفين تم فصله وترك ملفات حساسة في مسارات غير متوقعة. اكتشف ملفات التحكم في الزحف.',
                en: 'An employee was fired and left sensitive files in unexpected paths. Discover the crawling control files.'
            },
            labConfig: {
                type: 'web',
                target: 'https://api.techcorp.local/robots.txt'
            },
            hints: [
                { id: 1, text: { ar: 'الملفات المخفية غالباً ما توجد في robots.txt.', en: 'Hidden files are often listed in robots.txt.' }, cost: 20 }
            ],
            writeup: {
                ar: 'ملف robots.txt ليس أداة أمان، بل هو وسيلة لإرشاد محركات البحث. المخترقون يستخدمونه لمعرفة المسارات التي يريد المالك إخفاءها.',
                en: 'The robots.txt file is not a security tool; it guides search engines. Hackers use it to find paths the owner wants to hide.'
            },
            tasks: [
                { id: 1, question: { ar: 'عدد مجلدات الويب', en: 'Enumerate Web Directories' }, points: 25 },
                { id: 2, question: { ar: 'حدد موقع robots.txt', en: 'Locate robots.txt' }, points: 25 },
                { id: 3, question: { ar: 'استخرج ملف flag.txt', en: 'Extract flag.txt' }, answer: 'AG{robots_reveal_too_much_2024}', points: 50 }
            ]
        },
        {
            id: 'ctf-hidden-sauce',
            title: { ar: 'الصلصة المخفية', en: 'Hidden Sauce' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            tags: ['html', 'devtools', 'source-code'],
            description: {
                ar: 'موقع مخبز بسيط. هل يمكنك العثور على المكون السري؟',
                en: 'A simple bakery website. Can you find the secret ingredient?'
            },
            tasks: [
                { id: 1, question: { ar: 'افحص كود المصدر', en: 'Inspect Source Code' }, points: 15 },
                { id: 2, question: { ar: 'ابحث عن التعليقات', en: 'Find HTML Comments' }, points: 15 },
                { id: 3, question: { ar: 'اعثر على flag.txt', en: 'Locate flag.txt' }, answer: 'AG{s0urce_cod3_d1scov3ry}', points: 20 }
            ]
        },
        {
            id: 'ctf-login-limbo',
            title: { ar: 'حد الدخول', en: 'Login Limbo' },
            difficulty: 'medium',
            estimatedTime: '35 min',
            points: 250,
            tags: ['sqli', 'auth-bypass', 'sqlite'],
            description: {
                ar: 'بوابة قديمة محمية بقفل ضعيف. هل يمكنك تجاوز البوابة؟',
                en: 'An outdated portal guarded by a weak lock. Can you bypass the gate?'
            },
            scenario: {
                ar: 'نظام إدارة الموارد في شركة "GlobalLogistics" يستخدم نسخة قديمة من محرك البحث. اكتشفنا أن حقل اسم المستخدم لا يتم فلترته بشكل صحيح.',
                en: "The resource management system at 'GlobalLogistics' uses an outdated search engine. We've discovered that the username field is not properly sanitized."
            },
            labConfig: {
                type: 'web',
                target: 'https://admin-portal.globallogistics.local/login',
                vulnerability: 'sqli',
                payload: "' OR 1=1 --"
            },
            hints: [
                { id: 1, text: { ar: 'جرب استخدام علامة الاقتباس الأحادية لكسر الاستعلام.', en: "Try using a single quote (') to break the query." }, cost: 30 },
                { id: 2, text: { ar: 'قاعدة البيانات هي SQLite، استخدم -- للتعليق.', en: 'The database is SQLite; use -- for commenting out.' }, cost: 50 }
            ],
            writeup: {
                ar: 'حقن SQL (SQL Injection) هي واحدة من أخطر الثغرات. في هذا التحدي، قمنا باستغلال عدم وجود "Parameterized Queries" لتغيير منطق الاستعلام ليكون دائماً True.',
                en: "SQL Injection is one of the most critical vulnerabilities. In this challenge, we exploited the lack of 'Parameterized Queries' to manipulate the logic to always return True."
            },
            tasks: [
                { id: 1, question: { ar: 'اكتشف ثغرة المصادقة', en: 'Discover Authentication Vulnerability' }, points: 50 },
                { id: 2, question: { ar: 'تجاوز تسجيل الدخول', en: 'Bypass Login without Password' }, points: 100 },
                { id: 3, question: { ar: 'استخرج flag.txt', en: 'Extract flag.txt from Dashboard' }, answer: 'AG{SQL_Inj3ct10n_M4st3r}', points: 100 }
            ]
        },
        {
            id: 'ctf-celestial-logbook',
            title: { ar: 'سجل السماء', en: 'The Celestial Logbook' },
            difficulty: 'medium',
            estimatedTime: '40 min',
            points: 350,
            tags: ['lfi', 'traversal', 'php'],
            description: {
                ar: 'تنقل في أرشيف المرصد الصحراوي وابحث عن مفاتيح التشفير المخفية.',
                en: "Navigate the desert observatory's archives and find the hidden encryption keys."
            },
            labConfig: {
                type: 'web',
                target: 'https://archive.desert-obs.local/view?file=welcome.txt',
                vulnerability: 'lfi'
            },
            tasks: [
                { id: 1, question: { ar: 'اكتشف نقطة عرض السجل', en: 'Discover Log Viewing Endpoint' }, points: 100 },
                { id: 2, question: { ar: 'اختبر Directory Traversal', en: 'Test for Directory Traversal' }, points: 100 },
                { id: 3, question: { ar: 'احصل على flag.txt', en: 'Capture flag.txt from Root' }, answer: 'AG{LFI_1n_th3_St4rs_8ce3}', points: 150 }
            ]
        },
        {
            id: 'ctf-ghost-archive',
            title: { ar: 'الأرشيف الشبح', en: 'The Ghost Archive' },
            difficulty: 'medium',
            estimatedTime: '35 min',
            points: 300,
            tags: ['lfi', 'traversal', 'php'],
            description: {
                ar: 'نظام استرجاع قديم به عيب في المسار. هل يمكنك الوصول للملفات؟',
                en: 'A legacy retrieval system with a pathing flaw. Can you ghost the files?'
            },
            labConfig: {
                type: 'web',
                target: 'https://ghost.archive.local/get?item=intro.html',
                vulnerability: 'lfi'
            },
            tasks: [
                { id: 1, question: { ar: 'حدد نقطة تضمين الملف', en: 'Identify File Inclusion Point' }, points: 80 },
                { id: 2, question: { ar: 'نفذ Directory Traversal', en: 'Perform Directory Traversal' }, points: 100 },
                { id: 3, question: { ar: 'اعثر على secret_flag.txt', en: 'Locate secret_flag.txt' }, answer: 'AG{LFI_Tr4v3rs4l_M4st3r_2026}', points: 120 }
            ]
        },
        {
            id: 'ctf-ping-pong',
            title: { ar: 'بينج بونج', en: 'Ping Pong' },
            difficulty: 'hard',
            estimatedTime: '45 min',
            points: 500,
            tags: ['rce', 'command-injection', 'linux'],
            description: {
                ar: 'أداة تشخيص بها عيب منطقي خطير. هل يمكنك الخروج من السكريبت؟',
                en: 'A diagnostic tool with a serious logic flaw. Can you break out of the script?'
            },
            labConfig: {
                type: 'web',
                target: 'https://diag.utils.local/ping',
                vulnerability: 'rce',
                payload: '; cat /root/flag.txt'
            },
            tasks: [
                { id: 1, question: { ar: 'اكتشف نقطة Command Injection', en: 'Discover Command Injection Entry Point' }, points: 100 },
                { id: 2, question: { ar: 'تجاوز الفلاتر', en: 'Bypass Basic Filters' }, points: 150 },
                { id: 3, question: { ar: 'نفذ أوامر عن بعد', en: 'Execute Remote Commands' }, points: 100 },
                { id: 4, question: { ar: 'احصل على flag.txt من /root/', en: 'Capture flag.txt from /root/' }, answer: 'AG{C0mm4nd_Inj3ct10n_1s_L3th4l}', points: 150 }
            ]
        },
        {
            id: 'ctf-blind-fury',
            title: { ar: 'غضب أعمى', en: 'Blind Fury' },
            difficulty: 'hard',
            estimatedTime: '50 min',
            points: 500,
            tags: ['blind-sqli', 'python', 'automation'],
            description: {
                ar: 'بوابة تبدو آمنة مع ثغرة Blind SQLi مخفية.',
                en: 'A secure-looking portal with a hidden blind SQLi vulnerability.'
            },
            tasks: [
                { id: 1, question: { ar: 'اكتشف SQLi يدوياً', en: 'Manual SQLi Discovery' }, points: 100 },
                { id: 2, question: { ar: 'اكتب سكريبت استخراج', en: 'Write Extraction Script' }, points: 150 },
                { id: 3, question: { ar: 'استخرج مخطط قاعدة البيانات', en: 'Dump Database Schema' }, points: 100 },
                { id: 4, question: { ar: 'استخرج كلمة مرور Admin', en: 'Extract Admin Password' }, answer: 'AG{bl1nd_sql_m4st3ry}', points: 150 }
            ]
        },
        {
            id: 'ctf-identity-paradox',
            title: { ar: 'مفارقة الهوية', en: 'The Identity Paradox' },
            difficulty: 'hard',
            estimatedTime: '55 min',
            points: 750,
            tags: ['jwt', 'auth-bypass', 'brute-force'],
            description: {
                ar: 'رابط اتصال محمي بسر ضعيف. هل يمكنك تزوير هوية عالية المستوى؟',
                en: 'A communication link secured by a weak secret. Can you forge a high-level identity?'
            },
            tasks: [
                { id: 1, question: { ar: 'احصل على رمز JWT', en: 'Capture JWT Authentication Token' }, points: 150 },
                { id: 2, question: { ar: 'اكسر سر HMAC الضعيف', en: 'Crack Weak HMAC Secret' }, points: 250 },
                { id: 3, question: { ar: 'ازرع رمز Admin', en: 'Forge Identity Token with Admin Role' }, answer: 'AG{W34k_JWT_S3cr3ts_Cr4ck3d}', points: 350 }
            ]
        },
        {
            id: 'ctf-ssrf-internal',
            title: { ar: 'SSRF للداخل', en: 'SSRF to Internal' },
            difficulty: 'hard',
            estimatedTime: '45 min',
            points: 500,
            tags: ['ssrf', 'web', 'internal'],
            description: {
                ar: 'مولد PDF به عيب قاتل. الوصول إلى لوحة الإدارة الداخلية.',
                en: 'A PDF generator with a fatal flaw. Reach the internal admin panel.'
            },
            tasks: [
                { id: 1, question: { ar: 'حدد SSRF Vector', en: 'Identify SSRF Vector' }, points: 100 },
                { id: 2, question: { ar: 'تجاوز فلاتر URL', en: 'Bypass URL Filters' }, points: 150 },
                { id: 3, question: { ar: 'الوصول للوحة الداخلية', en: 'Access Internal Panel' }, points: 100 },
                { id: 4, question: { ar: 'استخرج الـ Flag', en: 'Extract Flag' }, answer: 'BL{ssrf_1nt3rn4l_pwn3d}', points: 150 }
            ]
        },
        {
            id: 'ctf-xxe-exfil',
            title: { ar: 'استخراج XXE', en: 'XXE Exfiltration' },
            difficulty: 'hard',
            estimatedTime: '50 min',
            points: 550,
            tags: ['xxe', 'xml', 'oob'],
            description: {
                ar: 'محلل XML يثق بالكيانات الخارجية. حان وقت الاستخراج.',
                en: 'An XML parser that trusts external entities. Time to exfiltrate.'
            },
            tasks: [
                { id: 1, question: { ar: 'صمم XXE Payload', en: 'Craft XXE Payload' }, points: 150 },
                { id: 2, question: { ar: 'استخرج /etc/passwd', en: 'Exfiltrate /etc/passwd' }, answer: 'BL{xx3_00b_3xf1ltr4t10n}', points: 400 }
            ]
        },
        {
            id: 'ctf-graphql-introspection',
            title: { ar: 'أسرار GraphQL', en: 'GraphQL Secrets' },
            difficulty: 'medium',
            estimatedTime: '40 min',
            points: 400,
            tags: ['graphql', 'api', 'introspection'],
            description: {
                ar: 'GraphQL API مع introspection مفعل. ارسم المخطط واعثر على البيانات المخفية.',
                en: 'A GraphQL API with introspection enabled. Map the schema and find the hidden data.'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج الـ Flag من introspection', en: 'Extract Flag from Introspection' }, answer: 'BL{gr4phql_1ntr0sp3ct10n}', points: 400 }
            ]
        },
        {
            id: 'ctf-race-condition',
            title: { ar: 'السباق للبنك', en: 'Race to the Bank' },
            difficulty: 'hard',
            estimatedTime: '55 min',
            points: 600,
            tags: ['race-condition', 'concurrency', 'web'],
            description: {
                ar: 'نظام كوبونات به ثغرة توقيت. احصل على خصومات لانهائية.',
                en: 'A coupon system with a timing vulnerability. Get infinite discounts.'
            },
            tasks: [
                { id: 1, question: { ar: 'احصل على Flag من Admin', en: 'Get Flag from Admin' }, answer: 'BL{r4c3_c0nd1t10n_w1nn3r}', points: 600 }
            ]
        },
        {
            id: 'ctf-prototype-pollution',
            title: { ar: 'تلويث النموذج الأولي', en: 'Prototype Pollution' },
            difficulty: 'hard',
            estimatedTime: '60 min',
            points: 600,
            tags: ['prototype-pollution', 'nodejs', 'rce'],
            description: {
                ar: 'لوث سلسلة النموذج الأولي لتحقيق RCE.',
                en: 'Pollute the prototype chain to achieve RCE.'
            },
            tasks: [
                { id: 1, question: { ar: 'اقرأ /flag.txt', en: 'Read /flag.txt' }, answer: 'BL{pr0t0typ3_p0llut10n_rc3}', points: 600 }
            ]
        },
        {
            id: 'ctf-jwt-confusion',
            title: { ar: 'ارتباك مفتاح JWT', en: 'JWT Key Confusion' },
            difficulty: 'hard',
            estimatedTime: '65 min',
            points: 800,
            tags: ['jwt', 'rs256', 'hs256', 'crypto'],
            description: {
                ar: 'هجوم ارتباك المفتاح العام RS256. قم بتزوير رموز admin.',
                en: 'RS256 public key confusion attack. Forge admin tokens.'
            },
            tasks: [
                { id: 1, question: { ar: 'الوصول لنقطة Admin', en: 'Access Admin Endpoint' }, answer: 'BL{jwt_4lg0_c0nfus10n}', points: 800 }
            ]
        },
        {
            id: 'ctf-dark-matter-object',
            title: { ar: 'جسم المادة المظلمة', en: 'Dark Matter Object' },
            difficulty: 'hard',
            estimatedTime: '80 min',
            points: 1500,
            tags: ['deserialization', 'rce', 'pickle', 'python'],
            description: {
                ar: 'نواة غير مستقرة تعالج تيارات متسلسلة خام. هل يمكنك تحقيق السيطرة الكاملة؟',
                en: 'An unstable core processing raw serialized streams. Can you achieve total control?'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج الـ Flag من النظام', en: 'Extract Flag from the system' }, answer: 'AG{D3s3r1al1z4t10n_1s_D3adly_RCE}', points: 1500 }
            ]
        }
    ],
    crypto: [
        {
            id: 'ctf-base-jump',
            title: { ar: 'قفزة القاعدة', en: 'Base Jump' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            tags: ['base64', 'decoding', 'warmup'],
            description: {
                ar: 'فك شفرة البث من القاعدة القمرية.',
                en: 'Decode the transmission from the lunar base.'
            },
            tasks: [
                { id: 1, question: { ar: 'حدد نوع التشفير', en: 'Identify Encoding' }, points: 15 },
                { id: 2, question: { ar: 'فك شفرة Base64', en: 'Decode Base64' }, points: 15 },
                { id: 3, question: { ar: 'أرسل الـ Flag', en: 'Submit Flag' }, answer: 'AG{lunar_transm1ssion_dec0ded}', points: 20 }
            ]
        },
        {
            id: 'caesar-cipher',
            title: { ar: 'شفرة قيصر', en: 'Caesar Cipher' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            tags: ['crypto', 'classical', 'cipher'],
            description: {
                ar: 'فك شفرة قيصر الكلاسيكية.',
                en: 'Decrypt the classic Caesar cipher.'
            },
            intel: {
                ar: 'النص المشفر عالي السرية المكتشف في الاتصال هو: "PBATERGHGHYNGVBAF". لقد تم تأكيد استخدام إزاحة ROT13.',
                en: 'The high-secret cipher text discovered in the transmission is: "PBATERGHGHYNGVBAF". ROT13 shift has been confirmed.'
            },
            tasks: [
                { id: 1, question: { ar: 'ما هو النص المفكوك؟', en: 'What is the decrypted text?' }, answer: 'CONGRATULATIONS', points: 25 },
                { id: 2, question: { ar: 'ما هو مفتاح الإزاحة المستخدم؟', en: 'What is the shift key used?' }, answer: '13', points: 25 }
            ]
        },
        {
            id: 'ctf-reentrancy-shadow',
            title: { ar: 'ظل إعادة الدخول', en: 'Reentrancy Shadow' },
            difficulty: 'hard',
            estimatedTime: '70 min',
            points: 750,
            tags: ['blockchain', 'solidity', 'crypto', 'web3'],
            description: {
                ar: 'عقد ذكي للصرافة الآلية يحتوي على ثغرة قاتلة. هل يمكنك سحب الرصيد بالكامل؟',
                en: 'An ATM smart contract with a fatal flaw. Can you drain the entire balance?'
            },
            scenario: {
                ar: 'أطلق بروتوكول "DeFi-Secure" عقداً ذكياً جديداً. اكتشف الباحثون أن العقد سحب الأموال قبل تحديث الرصيد الداخلي.',
                en: "The 'DeFi-Secure' protocol launched a new smart contract. Researchers found the contract sends funds before updating internal balances."
            },
            labConfig: {
                type: 'blockchain',
                contract: 'VulnerableBank.sol',
                vulnerability: 'reentrancy'
            },
            hints: [
                { id: 1, text: { ar: 'ابحث عن هجوم الـ Recursive Call في Solidity.', en: 'Research the Recursive Call attack in Solidity.' }, cost: 100 },
                { id: 2, text: { ar: 'استخدم عقد مهاجم (Attacker Contract) مع دالة fallback.', en: 'Use an Attacker Contract with a fallback function.' }, cost: 150 }
            ],
            writeup: {
                ar: 'ثغرة Reentrancy هي السبب وراء اختراق The DAO الشهير. تحدث عندما يقوم العقد باستدعاء عقد خارجي قبل تحديث حالته الداخلية.',
                en: "Reentrancy was the root cause of the infamous DAO hack. It occurs when a contract calls an external contract before updating its internal state."
            },
            tasks: [
                { id: 1, question: { ar: 'حلل كود العقد الذكي', en: 'Analyze the Smart Contract code' }, points: 150 },
                { id: 2, question: { ar: 'نفذ هجوم سحب الرصيد', en: 'Execute the balance drain attack' }, points: 300 },
                { id: 3, question: { ar: 'استخرج الـ Flag من سجلات العقد', en: 'Extract the Flag from contract logs' }, answer: 'AG{R33ntr4ncy_Is_St1ll_Al1v3}', points: 300 }
            ]
        }
    ],
    pwn: [
        {
            id: 'buffer-overflow-basics',
            title: { ar: 'أساسيات Buffer Overflow', en: 'Buffer Overflow Basics' },
            difficulty: 'hard',
            estimatedTime: '45 min',
            points: 250,
            tags: ['pwn', 'overflow', 'binary'],
            description: {
                ar: 'تعلم أساسيات Buffer Overflow والسيطرة على EIP.',
                en: 'Learn buffer overflow basics and control EIP.'
            },
            labConfig: {
                type: 'terminal',
                initialFiles: [
                    { name: 'bof', content: 'ELF 64-bit LSB executable, x86-64, version 1 (SYSV)', size: '14.2KB' },
                    { name: 'flag.txt', content: 'Locked file. You must exploit the binary to read this.', size: '24B' }
                ]
            },
            tasks: [
                { id: 1, question: { ar: 'ما هو الـ offset للوصول لـ EIP؟', en: 'What is the offset to reach EIP?' }, answer: '64', points: 100 },
                { id: 2, question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' }, answer: 'AG{b0f_m4st3r_2024}', points: 150 }
            ]
        },
        {
            id: 'ctf-docker-breakout',
            title: { ar: 'الهروب من الحاوية', en: 'Container Escape' },
            difficulty: 'hard',
            estimatedTime: '60 min',
            points: 600,
            tags: ['docker', 'privesc', 'cloud'],
            description: {
                ar: 'أنت محاصر في حاوية. هل يمكنك الوصول إلى المضيف؟',
                en: 'You are trapped in a container. Can you reach the host?'
            },
            labConfig: {
                type: 'terminal',
                initialFiles: [
                    { name: 'docker-compose.yml', content: 'version: "3"\nservices:\n  vulnerable-app:\n    privileged: true...', size: '1.1KB' }
                ]
            },
            tasks: [
                { id: 1, question: { ar: 'احصل على host_flag.txt', en: 'Capture host_flag.txt' }, answer: 'AG{d0ck3r_3sc4p3_succ3ss}', points: 600 }
            ]
        },
        {
            id: 'ctf-black-box-protocol',
            title: { ar: 'بروتوكول الصندوق الأسود', en: 'Black Box Protocol' },
            difficulty: 'hard',
            estimatedTime: '90 min',
            points: 1000,
            tags: ['satellite', 'reverse', 'insane'],
            description: {
                ar: 'إشارات من قمر صناعي مارق. قم بالدوران عبر الشبكة واستغل النواة.',
                en: 'Signals from a rogue satellite. Pivot through the network and exploit the core.'
            },
            tasks: [
                { id: 1, question: { ar: 'عطل عملية التعدين واحصل على العلم', en: 'Disable the mining operation and get the flag' }, answer: 'AG{s4t3llit3_r3cl4im3d}', points: 1000 }
            ]
        }
    ],
    cloud: [
        {
            id: 'ctf-s3-treasure',
            title: { ar: 'صيد كنز S3', en: 'S3 Treasure Hunt' },
            difficulty: 'medium',
            estimatedTime: '35 min',
            points: 300,
            tags: ['aws', 's3', 'cloud'],
            description: {
                ar: 'شركة ناشئة تركت دلو النسخ الاحتياطي عام. حان وقت البحث عن الذهب.',
                en: 'A startup left their backup bucket public. Time to dig for gold.'
            },
            intel: {
                ar: 'تم التعرف على مساحة التخزين المستهدفة: "s3://vulnerable-startup-backups-99". ابحث عن ملفات حساسة قد تحتوي على بيانات الاعتماد.',
                en: 'Target storage bucket identified: "s3://vulnerable-startup-backups-99". Look for sensitive files that might contain credentials.'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج credentials.json', en: 'Extract credentials.json' }, answer: 'BL{s3_buck3t_l00t_4cqu1r3d}', points: 300 }
            ]
        },
        {
            id: 'ctf-lambda-backdoor',
            title: { ar: 'باب خلفي Lambda', en: 'Lambda Backdoor' },
            difficulty: 'hard',
            estimatedTime: '55 min',
            points: 600,
            tags: ['aws', 'lambda', 'ssrf', 'iam'],
            description: {
                ar: 'SSRF في دالة serverless يؤدي لسرقة بيانات الاعتماد.',
                en: 'An SSRF in a serverless function leads to credential theft.'
            },
            intel: {
                ar: 'نقطة النهاية المعرضة للخطر: "https://api.startup-dev.io/v1/fetch?url=". حاول الوصول لخدمة الـ Metadata الداخلية.',
                en: 'Vulnerable endpoint: "https://api.startup-dev.io/v1/fetch?url=". Attempt to access the internal Metadata service.'
            },
            tasks: [
                { id: 1, question: { ar: 'الوصول لـ Secrets Manager', en: 'Access Secrets Manager' }, answer: 'BL{l4mbd4_cr3ds_3xf1ltr4t3d}', points: 600 }
            ]
        },
        {
            id: 'ctf-azure-consent',
            title: { ar: 'فخ موافقة OAuth', en: 'OAuth Consent Trap' },
            difficulty: 'hard',
            estimatedTime: '50 min',
            points: 550,
            tags: ['azure-ad', 'oauth', 'phishing'],
            intel: {
                ar: 'رابط هجوم الـ Phishing المجهز: "https://portal.azure-security.net/common/oauth2/v2.0/authorize?client_id=evil-app-id".',
                en: 'Prepared Phishing link: "https://portal.azure-security.net/common/oauth2/v2.0/authorize?client_id=evil-app-id".'
            },
            description: {
                ar: 'تطبيق OAuth خبيث يحصد بيانات الشركة.',
                en: 'A malicious OAuth application is harvesting corporate data.'
            },
            tasks: [
                { id: 1, question: { ar: 'اعثر على العلم في البيانات المخترقة', en: 'Find the flag in the compromised data' }, answer: 'BL{c0ns3nt_ph1sh1ng_d3t3ct3d}', points: 550 }
            ]
        }
    ],
    forensics: [
        {
            id: 'ctf-log-hunter',
            title: { ar: 'صائد السجلات', en: 'Log Hunter' },
            difficulty: 'medium',
            estimatedTime: '40 min',
            points: 350,
            tags: ['windows-logs', 'powershell', 'siem'],
            description: {
                ar: '400 جيجابايت من السجلات. مؤشر واحد للاختراق. هل أنت مستعد؟',
                en: '400GB of logs. One indicator of compromise. Ready?'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج الـ Flag', en: 'Extract the Flag' }, answer: 'BL{l0g_4n4lys1s_pr0}', points: 350 }
            ]
        },
        {
            id: 'ctf-disk-forensics',
            title: { ar: 'محقق القرص', en: 'Disk Detective' },
            difficulty: 'medium',
            estimatedTime: '45 min',
            points: 400,
            tags: ['disk-forensics', 'autopsy', 'recovery'],
            description: {
                ar: 'صورة قرص من ضحية برامج الفدية. استرجع الملفات المحذوفة.',
                en: 'A disk image from a ransomware victim. Recover the deleted files.'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج Flag من PDF', en: 'Extract Flag from PDF' }, answer: 'BL{d3l3t3d_f1l3s_r3c0v3r3d}', points: 400 }
            ]
        },
        {
            id: 'ctf-memory-ghost',
            title: { ar: 'شبح الذاكرة', en: 'Memory Ghost' },
            difficulty: 'hard',
            estimatedTime: '50 min',
            points: 650,
            tags: ['volatility', 'memory-forensics', 'dfir'],
            description: {
                ar: 'تفريغ ذاكرة من جهاز مخترق. هل يمكنك العثور على البرمجيات الخبيثة؟',
                en: 'A memory dump from a compromised machine. Can you find the malware?'
            },
            tasks: [
                { id: 1, question: { ar: 'اعثر على Flag المخفي', en: 'Find Hidden Flag' }, answer: 'BL{m3m0ry_f0r3ns1cs_m4st3r}', points: 650 }
            ]
        }
    ],
    redteam: [
        {
            id: 'ctf-packers-paradox',
            title: { ar: 'مفارقة الحزم', en: "Packer's Paradox" },
            difficulty: 'hard',
            estimatedTime: '90 min',
            points: 800,
            tags: ['reveng', 'upx', 'binary', 'malware'],
            description: {
                ar: 'فيروس مشفر باستخدام UPX. هل يمكنك فك الضغط واستخراج الأسرار؟',
                en: 'A virus packed with UPX. Can you unpack it and extract the secrets?'
            },
            scenario: {
                ar: 'عينة خبيثة تم اكتشافها في نظام "CyberDefense". العينة مضغوطة ومشفرة لتجاوز برامج الحماية. نحتاج منك تحليلها لمعرفة عنوان السيرفر المخفي (C2).',
                en: "A malicious sample was detected in the 'CyberDefense' system. It is packed to bypass AV detection. We need you to reverse it and find the hidden C2 server address."
            },
            labConfig: {
                type: 'terminal',
                tool: 'upx',
                commands: ['upx -d packed.exe', 'strings unpacked.exe']
            },
            hints: [
                { id: 1, text: { ar: 'استخدم أداة upx ببارامتير -d لفك الضغط.', en: 'Use the upx tool with the -d parameter to unpack.' }, cost: 100 },
                { id: 2, text: { ar: 'بعد فك الضغط، ابحث عن السلاسل النصية (Strings).', en: 'After unpacking, search for readable strings.' }, cost: 150 }
            ],
            writeup: {
                ar: 'ضغط الملفات التنفيذية (Packing) هو وسيلة شائعة لإخفاء الكود الخبيث. باستخدام UPX، يسهل فك الضغط إذا لم يتم تعديل الرأس (Header) الخاص به.',
                en: "Packing executables is a common way to hide malicious code. Using UPX, it's easy to unpack if the header hasn't been heavily modified."
            },
            tasks: [
                { id: 1, question: { ar: 'فك ضغط الملف التنفيذي', en: 'Unpack the executable' }, points: 150 },
                { id: 2, question: { ar: 'استخرج السلاسل النصية', en: 'Extract readable strings' }, points: 200 },
                { id: 3, question: { ar: 'استخرج الـ Flag', en: 'Extract the Flag' }, answer: 'AG{UPX_Unp4ck1ng_S4v3s_Th3_D4y}', points: 450 }
            ]
        },
        {
            id: 'ctf-singularity-bank',
            title: { ar: 'مشروع سينجولاريتي', en: 'Project Singularity' },
            difficulty: 'hard',
            estimatedTime: '120 min',
            points: 2500,
            tags: ['full-chain', 'edr-bypass', 'simulation'],
            description: {
                ar: 'الاختبار النهائي. اختراق البنك المركزي شديد التأمين.',
                en: 'The ultimate test. Compromise the highly secure Central Bank.'
            },
            tasks: [
                { id: 1, question: { ar: 'استخرج مفاتيح الجذر', en: 'Exfiltrate the root keys' }, answer: 'AG{th3_s1ngul4r1ty_1s_h3r3_2026}', points: 2500 }
            ]
        }
    ]
};

export const achievements = [
    {
        id: 'first-blood',
        title: { ar: 'أول دم', en: 'First Blood' },
        description: { ar: 'حل أول تحدي CTF', en: 'Solve your first CTF challenge' },
        icon: 'Trophy',
        color: '#fbbf24'
    },
    {
        id: 'web-master',
        title: { ar: 'خبير الويب', en: 'Web Master' },
        description: { ar: 'حل جميع تحديات الويب', en: 'Solve all web challenges' },
        icon: 'Globe',
        color: '#3b82f6'
    },
    {
        id: 'crypto-wizard',
        title: { ar: 'ساحر التشفير', en: 'Crypto Wizard' },
        description: { ar: 'حل جميع تحديات التشفير', en: 'Solve all crypto challenges' },
        icon: 'Lock',
        color: '#10b981'
    },
    {
        id: 'pwn-legend',
        title: { ar: 'أسطورة البايناري', en: 'PWN Legend' },
        description: { ar: 'حل جميع تحديات البايناري', en: 'Solve all binary challenges' },
        icon: 'Flame',
        color: '#ef4444'
    }
];
