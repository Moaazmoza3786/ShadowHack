/* ctf-rooms.js - TryHackMe-Style CTF Rooms */

const ctfRooms = {
    web: [
        {
            id: 'sql-injection-basics',
            title: { ar: 'أساسيات SQL Injection', en: 'SQL Injection Basics' },
            difficulty: 'easy',
            estimatedTime: '30 min',
            points: 100,
            solveCount: 0,
            tags: ['web', 'sql', 'injection', 'authentication'],

            description: {
                ar: 'تعلم أساسيات SQL Injection من خلال استغلال نظام تسجيل دخول ضعيف. ستتعلم كيفية تجاوز المصادقة واستخراج البيانات من قاعدة البيانات.',
                en: 'Learn SQL Injection basics by exploiting a vulnerable login system. You will learn how to bypass authentication and extract data from the database.'
            },

            learningObjectives: [
                { ar: 'فهم كيفية عمل SQL Injection', en: 'Understand how SQL Injection works' },
                { ar: 'تجاوز نظام المصادقة', en: 'Bypass authentication system' },
                { ar: 'استخراج معلومات قاعدة البيانات', en: 'Extract database information' },
                { ar: 'الحصول على الـ flag', en: 'Capture the flag' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو اسم قاعدة البيانات المستخدمة؟', en: 'What is the database name?' },
                    answer: 'securebank_db',
                    hint: { ar: 'استخدم UNION SELECT database()', en: 'Use UNION SELECT database()' },
                    points: 20
                },
                {
                    id: 2,
                    question: { ar: 'كم عدد المستخدمين في الجدول؟', en: 'How many users are in the table?' },
                    answer: '5',
                    hint: { ar: 'استخدم UNION SELECT COUNT(*) FROM users', en: 'Use UNION SELECT COUNT(*) FROM users' },
                    points: 30
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{sql_1nj3ct10n_m4st3r_2024}',
                    hint: { ar: 'ابحث في جدول secrets', en: 'Look in the secrets table' },
                    points: 50
                }
            ],

            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/sql-injection/index.html',
                deployable: true
            },

            hints: [
                { cost: 5, text: { ar: 'جرب إدخال \' في حقل اسم المستخدم', en: 'Try entering \' in the username field' } },
                { cost: 10, text: { ar: 'استخدم \' OR 1=1-- لتجاوز المصادقة', en: 'Use \' OR 1=1-- to bypass authentication' } },
                { cost: 15, text: { ar: 'استخدم UNION SELECT للحصول على معلومات إضافية', en: 'Use UNION SELECT to get additional information' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: `# حل تحدي SQL Injection Basics

## الخطوة 1: اكتشاف الثغرة
أدخل \` في حقل اسم المستخدم لاختبار وجود ثغرة SQL Injection.

## الخطوة 2: تجاوز المصادقة
استخدم: \` OR 1=1--

## الخطوة 3: استخراج اسم قاعدة البيانات
استخدم: \` UNION SELECT database(),null--

## الخطوة 4: الحصول على عدد المستخدمين
استخدم: \` UNION SELECT COUNT(*),null FROM users--

## الخطوة 5: الحصول على الـ flag
استخدم: \` UNION SELECT flag,null FROM secrets--
`,
                    en: `# SQL Injection Basics Solution

## Step 1: Discover the vulnerability
Enter \` in the username field to test for SQL Injection.

## Step 2: Bypass authentication
Use: \` OR 1=1--

## Step 3: Extract database name
Use: \` UNION SELECT database(),null--

## Step 4: Get user count
Use: \` UNION SELECT COUNT(*),null FROM users--

## Step 5: Capture the flag
Use: \` UNION SELECT flag,null FROM secrets--
`
                }
            }
        },

        {
            id: 'xss-reflected',
            title: { ar: 'XSS المنعكس', en: 'Reflected XSS' },
            difficulty: 'easy',
            estimatedTime: '25 min',
            points: 80,
            solveCount: 0,
            tags: ['web', 'xss', 'javascript'],

            description: {
                ar: 'اكتشف واستغل ثغرة XSS منعكسة في نظام بحث. تعلم كيفية تنفيذ كود JavaScript في متصفح الضحية.',
                en: 'Discover and exploit a Reflected XSS vulnerability in a search system. Learn how to execute JavaScript code in the victim\'s browser.'
            },

            learningObjectives: [
                { ar: 'فهم Reflected XSS', en: 'Understand Reflected XSS' },
                { ar: 'تنفيذ كود JavaScript', en: 'Execute JavaScript code' },
                { ar: 'سرقة الكوكيز', en: 'Steal cookies' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ payload الأساسي الذي يعمل؟', en: 'What basic payload works?' },
                    answer: '<script>alert(1)</script>',
                    points: 30
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag المخفي في الكوكيز؟', en: 'What is the flag hidden in cookies?' },
                    answer: 'FLAG{xss_c00k13_st34l3r}',
                    points: 50
                }
            ],

            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/xss-reflected/index.html',
                deployable: true
            },

            hints: [
                { cost: 5, text: { ar: 'جرب <script>alert(1)</script>', en: 'Try <script>alert(1)</script>' } },
                { cost: 10, text: { ar: 'استخدم document.cookie للحصول على الكوكيز', en: 'Use document.cookie to get cookies' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل تحدي XSS المنعكس\n\n...',
                    en: '# Reflected XSS Solution\n\n...'
                }
            }
        },
        {
            id: 'file-upload-practice',
            title: { ar: 'File Upload Master', en: 'File Upload Master' },
            difficulty: 'hard',
            estimatedTime: '45 min',
            points: 300,
            solveCount: 0,
            tags: ['web', 'upload', 'rce', 'bypass'],
            description: {
                ar: 'تعلم كيفية استغلال ثغرات رفع الملفات. تجاوز الفلاتر، تلاعب بـ MIME Types، واحقن Magic Bytes لتنفيذ كود خبيث.',
                en: 'Learn how to exploit file upload vulnerabilities. Bypass filters, manipulate MIME types, and inject Magic Bytes to execute malicious code.'
            },
            learningObjectives: [
                { ar: 'رفع ملفات PHP خبيثة', en: 'Upload malicious PHP files' },
                { ar: 'تجاوز القوائم السوداء للامتدادات', en: 'Bypass extension blacklists' },
                { ar: 'تزوير نوع الملف (MIME Type)', en: 'Spoof MIME types' },
                { ar: 'حقن Magic Bytes', en: 'Inject Magic Bytes' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag الخاص بالرفع غير المقيد؟', en: 'What is the Unrestricted Upload flag?' },
                    answer: 'FLAG{unr3str1ct3d_upl04d_succ3ss}',
                    points: 50
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag الخاص بتجاوز الامتداد؟', en: 'What is the Extension Bypass flag?' },
                    answer: 'FLAG{ext3ns10n_byp4ss_m4st3r}',
                    points: 75
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag الخاص بـ MIME Type؟', en: 'What is the MIME Type flag?' },
                    answer: 'FLAG{m1m3_typ3_sp00f1ng}',
                    points: 75
                },
                {
                    id: 4,
                    question: { ar: 'ما هو الـ flag الخاص بـ Magic Bytes؟', en: 'What is the Magic Bytes flag?' },
                    answer: 'FLAG{m4g1c_byt3s_inj3ct10n}',
                    points: 100
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/file-upload-practice/index.html',
                deployable: true
            }
        }
    ],

    crypto: [
        {
            id: 'caesar-cipher',
            title: { ar: 'شفرة قيصر', en: 'Caesar Cipher' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            solveCount: 0,
            tags: ['crypto', 'classical', 'cipher'],

            description: {
                ar: 'فك تشفير رسالة مشفرة بشفرة قيصر. واحدة من أقدم تقنيات التشفير.',
                en: 'Decrypt a message encrypted with Caesar cipher. One of the oldest encryption techniques.'
            },

            learningObjectives: [
                { ar: 'فهم شفرة قيصر', en: 'Understand Caesar cipher' },
                { ar: 'تقنيات فك التشفير', en: 'Decryption techniques' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو النص المفكوك؟', en: 'What is the decrypted text?' },
                    answer: 'CONGRATULATIONS',
                    points: 25
                },
                {
                    id: 2,
                    question: { ar: 'ما هو مفتاح الإزاحة المستخدم؟', en: 'What is the shift key used?' },
                    answer: '13',
                    points: 25
                }
            ],

            encryptedMessage: 'PBATENGHYNGVBAF',

            hints: [
                { cost: 5, text: { ar: 'جرب ROT13', en: 'Try ROT13' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل شفرة قيصر\n\nالرسالة المشفرة: PBATENGHYNGVBAF\nالإزاحة: 13 (ROT13)\nالنص الأصلي: CONGRATULATIONS',
                    en: '# Caesar Cipher Solution\n\nEncrypted: PBATENGHYNGVBAF\nShift: 13 (ROT13)\nDecrypted: CONGRATULATIONS'
                }
            }
        },

        {
            id: 'base64-encoding',
            title: { ar: 'تشفير Base64', en: 'Base64 Encoding' },
            difficulty: 'easy',
            estimatedTime: '10 min',
            points: 40,
            solveCount: 0,
            tags: ['crypto', 'encoding', 'base64'],

            description: {
                ar: 'فك تشفير رسالة مشفرة بـ Base64. تعلم كيفية التعرف على Base64 وفك تشفيره.',
                en: 'Decrypt a Base64 encoded message. Learn how to recognize and decode Base64.'
            },

            learningObjectives: [
                { ar: 'التعرف على Base64', en: 'Recognize Base64' },
                { ar: 'فك تشفير Base64', en: 'Decode Base64' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{b4s364_1s_n0t_3ncrypt10n}',
                    points: 40
                }
            ],

            encodedMessage: 'RkxBR3tiNHMzNjRfMXNfbjB0XzNuY3J5cHQxMG59',

            hints: [
                { cost: 5, text: { ar: 'استخدم أداة Base64 decoder', en: 'Use a Base64 decoder tool' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل Base64\n\nالمشفر: RkxBR3tiNHMzNjRfMXNfbjB0XzNuY3J5cHQxMG59\nالأصلي: FLAG{b4s364_1s_n0t_3ncrypt10n}',
                    en: '# Base64 Solution\n\nEncoded: RkxBR3tiNHMzNjRfMXNfbjB0XzNuY3J5cHQxMG59\nDecoded: FLAG{b4s364_1s_n0t_3ncrypt10n}'
                }
            }
        }
    ],

    forensics: [
        {
            id: 'hidden-text',
            title: { ar: 'نص مخفي', en: 'Hidden Text' },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 60,
            solveCount: 0,
            tags: ['forensics', 'steganography', 'text'],

            description: {
                ar: 'ابحث عن نص مخفي في ملف HTML. تعلم تقنيات البحث عن البيانات المخفية.',
                en: 'Find hidden text in an HTML file. Learn techniques for finding hidden data.'
            },

            learningObjectives: [
                { ar: 'فحص الكود المصدري', en: 'Inspect source code' },
                { ar: 'البحث عن البيانات المخفية', en: 'Find hidden data' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag المخفي؟', en: 'What is the hidden flag?' },
                    answer: 'FLAG{h1dd3n_1n_pl41n_s1ght}',
                    points: 60
                }
            ],

            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/hidden-text/index.html',
                deployable: true
            },

            hints: [
                { cost: 10, text: { ar: 'افحص الكود المصدري للصفحة', en: 'Inspect the page source code' } },
                { cost: 15, text: { ar: 'ابحث عن تعليقات HTML', en: 'Look for HTML comments' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل النص المخفي\n\nافتح الكود المصدري (Ctrl+U)\nابحث عن <!-- -->\nستجد الـ flag في تعليق مخفي',
                    en: '# Hidden Text Solution\n\nOpen source code (Ctrl+U)\nSearch for <!-- -->\nYou will find the flag in a hidden comment'
                }
            }
        }
    ],

    osint: [
        {
            id: 'username-osint',
            title: { ar: 'البحث عن اسم مستخدم', en: 'Username OSINT' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            solveCount: 0,
            tags: ['osint', 'username', 'investigation'],

            description: {
                ar: 'ابحث عن معلومات حول اسم مستخدم معين على الإنترنت.',
                en: 'Find information about a specific username on the internet.'
            },

            learningObjectives: [
                { ar: 'استخدام أدوات OSINT', en: 'Use OSINT tools' },
                { ar: 'البحث عن المعلومات', en: 'Information gathering' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الاسم الحقيقي للمستخدم "cybermaster2024"؟', en: 'What is the real name of user "cybermaster2024"?' },
                    answer: 'John Smith',
                    hint: { ar: 'ابحث على GitHub', en: 'Search on GitHub' },
                    points: 25
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{0s1nt_m4st3r_2024}',
                    points: 25
                }
            ],

            hints: [
                { cost: 5, text: { ar: 'جرب البحث على GitHub', en: 'Try searching on GitHub' } },
                { cost: 10, text: { ar: 'افحص الـ bio في الملف الشخصي', en: 'Check the bio in the profile' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل OSINT\n\n1. ابحث عن "cybermaster2024" على GitHub\n2. افتح الملف الشخصي\n3. ستجد الاسم الحقيقي في الـ bio\n4. الـ flag موجود في أول repository',
                    en: '# OSINT Solution\n\n1. Search for "cybermaster2024" on GitHub\n2. Open the profile\n3. Find the real name in the bio\n4. Flag is in the first repository'
                }
            }
        }
    ],

    network: [
        {
            id: 'port-scanning',
            title: { ar: 'فحص المنافذ', en: 'Port Scanning' },
            difficulty: 'medium',
            estimatedTime: '30 min',
            points: 120,
            solveCount: 0,
            tags: ['network', 'nmap', 'scanning'],

            description: {
                ar: 'استخدم nmap لفحص المنافذ المفتوحة واكتشاف الخدمات.',
                en: 'Use nmap to scan open ports and discover services.'
            },

            learningObjectives: [
                { ar: 'استخدام nmap', en: 'Use nmap' },
                { ar: 'اكتشاف الخدمات', en: 'Service discovery' },
                { ar: 'تحليل النتائج', en: 'Analyze results' }
            ],

            tasks: [
                {
                    id: 1,
                    question: { ar: 'كم عدد المنافذ المفتوحة؟', en: 'How many ports are open?' },
                    answer: '3',
                    hint: { ar: 'استخدم nmap -p-', en: 'Use nmap -p-' },
                    points: 40
                },
                {
                    id: 2,
                    question: { ar: 'ما هي الخدمة على المنفذ 8080؟', en: 'What service is on port 8080?' },
                    answer: 'http',
                    points: 40
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{nm4p_sc4nn1ng_pr0}',
                    points: 40
                }
            ],

            simulatedScan: {
                target: '10.10.10.100',
                openPorts: [22, 80, 8080],
                services: {
                    22: 'ssh',
                    80: 'http',
                    8080: 'http'
                }
            },

            hints: [
                { cost: 10, text: { ar: 'استخدم nmap -sV للكشف عن الإصدارات', en: 'Use nmap -sV for version detection' } }
            ],

            writeup: {
                available: false,
                content: {
                    ar: '# حل فحص المنافذ\n\n```bash\nnmap -p- 10.10.10.100\nnmap -sV -p 22,80,8080 10.10.10.100\n```',
                    en: '# Port Scanning Solution\n\n```bash\nnmap -p- 10.10.10.100\nnmap -sV -p 22,80,8080 10.10.10.100\n```'
                }
            }
        }
    ],

    reversing: [
        {
            id: 'strings-basics',
            title: { ar: 'استخراج النصوص', en: 'Strings Analysis' },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 60,
            solveCount: 0,
            tags: ['reversing', 'strings', 'linux'],
            description: {
                ar: 'تعلم كيفية استخراج النصوص المخفية من الملفات التنفيذية باستخدام أداة strings.',
                en: 'Learn how to extract hidden strings from executables using the strings tool.'
            },
            learningObjectives: [
                { ar: 'استخدام أداة strings', en: 'Use strings tool' },
                { ar: 'تحليل الملفات التنفيذية', en: 'Analyze executables' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag المخفي في البرنامج؟', en: 'What is the hidden flag in the program?' },
                    answer: 'FLAG{str1ngs_4r3_us3ful}',
                    hint: { ar: 'استخدم: strings binary | grep FLAG', en: 'Use: strings binary | grep FLAG' },
                    points: 60
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'reversing-lab',
                ports: [22]
            },
            hints: [
                { cost: 10, text: { ar: 'الأمر strings يستخرج النصوص القابلة للقراءة', en: 'The strings command extracts readable text' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل الـ Strings\n\n```bash\nstrings crackme | grep FLAG\n```',
                    en: '# Strings Solution\n\n```bash\nstrings crackme | grep FLAG\n```'
                }
            }
        },
        {
            id: 'assembly-basics',
            title: { ar: 'أساسيات Assembly', en: 'Assembly Basics' },
            difficulty: 'medium',
            estimatedTime: '45 min',
            points: 150,
            solveCount: 0,
            tags: ['reversing', 'assembly', 'x86'],
            description: {
                ar: 'تعلم قراءة كود Assembly وفهم منطق البرنامج للعثور على كلمة المرور الصحيحة.',
                en: 'Learn to read Assembly code and understand program logic to find the correct password.'
            },
            learningObjectives: [
                { ar: 'فهم تعليمات x86 الأساسية', en: 'Understand basic x86 instructions' },
                { ar: 'استخدام Ghidra أو IDA', en: 'Use Ghidra or IDA' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هي قيمة المقارنة في تعليمة CMP؟', en: 'What is the comparison value in CMP instruction?' },
                    answer: '0x1337',
                    points: 50
                },
                {
                    id: 2,
                    question: { ar: 'ما هي كلمة المرور الصحيحة؟', en: 'What is the correct password?' },
                    answer: 'letmein2024',
                    points: 50
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{4ss3mbly_m4st3r_2024}',
                    points: 50
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'reversing-lab',
                ports: [22]
            },
            hints: [
                { cost: 15, text: { ar: 'ابحث عن تعليمات CMP و JE/JNE', en: 'Look for CMP and JE/JNE instructions' } },
                { cost: 20, text: { ar: 'استخدم Ghidra لتحويل الكود لـ C', en: 'Use Ghidra to decompile to C' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل Assembly\n\n1. افتح الملف في Ghidra\n2. ابحث عن دالة main\n3. حلل تعليمات المقارنة',
                    en: '# Assembly Solution\n\n1. Open file in Ghidra\n2. Find main function\n3. Analyze comparison instructions'
                }
            }
        },
        {
            id: 'patching-binary',
            title: { ar: 'تعديل البرنامج', en: 'Binary Patching' },
            difficulty: 'hard',
            estimatedTime: '60 min',
            points: 250,
            solveCount: 0,
            tags: ['reversing', 'patching', 'hex'],
            description: {
                ar: 'قم بتعديل البرنامج لتجاوز فحص الترخيص والحصول على الـ flag.',
                en: 'Patch the binary to bypass license check and get the flag.'
            },
            learningObjectives: [
                { ar: 'تعديل bytes في الملف', en: 'Modify bytes in file' },
                { ar: 'تغيير تعليمات القفز', en: 'Change jump instructions' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ offset الذي يجب تعديله؟', en: 'What offset needs to be patched?' },
                    answer: '0x401234',
                    hint: { ar: 'ابحث عن JNE وحوّلها إلى JE', en: 'Find JNE and change it to JE' },
                    points: 100
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag بعد التعديل؟', en: 'What is the flag after patching?' },
                    answer: 'FLAG{b1n4ry_p4tch1ng_pr0}',
                    points: 150
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'reversing-lab',
                ports: [22]
            },
            hints: [
                { cost: 25, text: { ar: 'JNE = 0x75, JE = 0x74', en: 'JNE = 0x75, JE = 0x74' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل Patching\n\n1. اعثر على فحص الترخيص\n2. غيّر 0x75 إلى 0x74\n3. شغّل البرنامج المعدل',
                    en: '# Patching Solution\n\n1. Find license check\n2. Change 0x75 to 0x74\n3. Run patched binary'
                }
            }
        }
    ],

    pwn: [
        {
            id: 'buffer-overflow-intro',
            title: { ar: 'مقدمة Buffer Overflow', en: 'Buffer Overflow Intro' },
            difficulty: 'medium',
            estimatedTime: '45 min',
            points: 180,
            solveCount: 0,
            tags: ['pwn', 'bof', 'stack'],
            description: {
                ar: 'تعلم أساسيات Buffer Overflow واستغلالها للتحكم في سير البرنامج.',
                en: 'Learn Buffer Overflow basics and exploit them to control program flow.'
            },
            learningObjectives: [
                { ar: 'فهم Stack layout', en: 'Understand Stack layout' },
                { ar: 'إعادة كتابة Return Address', en: 'Overwrite Return Address' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'كم عدد الـ bytes المطلوبة للوصول إلى Return Address؟', en: 'How many bytes needed to reach Return Address?' },
                    answer: '76',
                    hint: { ar: 'استخدم pattern_create و pattern_offset', en: 'Use pattern_create and pattern_offset' },
                    points: 60
                },
                {
                    id: 2,
                    question: { ar: 'ما هو عنوان دالة win()؟', en: 'What is the address of win() function?' },
                    answer: '0x08049196',
                    points: 60
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{buff3r_0v3rfl0w_b4s1cs}',
                    points: 60
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'pwn-lab',
                ports: [22, 1337]
            },
            hints: [
                { cost: 15, text: { ar: 'Buffer حجمه 64 bytes + saved EBP', en: 'Buffer is 64 bytes + saved EBP' } },
                { cost: 20, text: { ar: 'استخدم pwntools لبناء الـ exploit', en: 'Use pwntools to build exploit' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل Buffer Overflow\n\n```python\nfrom pwn import *\npayload = b"A"*76 + p32(0x08049196)\n```',
                    en: '# Buffer Overflow Solution\n\n```python\nfrom pwn import *\npayload = b"A"*76 + p32(0x08049196)\n```'
                }
            }
        },
        {
            id: 'format-string',
            title: { ar: 'Format String Attack', en: 'Format String Attack' },
            difficulty: 'hard',
            estimatedTime: '60 min',
            points: 300,
            solveCount: 0,
            tags: ['pwn', 'format-string', 'memory'],
            description: {
                ar: 'استغل ثغرة Format String لقراءة الذاكرة والحصول على الـ flag.',
                en: 'Exploit Format String vulnerability to read memory and get the flag.'
            },
            learningObjectives: [
                { ar: 'فهم printf vulnerabilities', en: 'Understand printf vulnerabilities' },
                { ar: 'قراءة من Stack', en: 'Read from Stack' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ payload لقراءة العنصر الأول من Stack؟', en: 'What payload reads first stack element?' },
                    answer: '%x',
                    points: 50
                },
                {
                    id: 2,
                    question: { ar: 'في أي موقع على Stack يوجد الـ flag؟', en: 'At what stack position is the flag?' },
                    answer: '7',
                    hint: { ar: 'جرب %7$s', en: 'Try %7$s' },
                    points: 100
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{f0rm4t_str1ng_m4st3r}',
                    points: 150
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'pwn-lab',
                ports: [22, 1338]
            },
            hints: [
                { cost: 20, text: { ar: 'استخدم %n$x لقراءة موقع محدد', en: 'Use %n$x to read specific position' } },
                { cost: 30, text: { ar: 'استخدم %s لقراءة النص بدلاً من الرقم', en: 'Use %s to read string instead of number' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل Format String\n\n```bash\necho "%7$s" | nc target 1338\n```',
                    en: '# Format String Solution\n\n```bash\necho "%7$s" | nc target 1338\n```'
                }
            }
        },
        {
            id: 'ret2libc',
            title: { ar: 'Return to Libc', en: 'Return to Libc' },
            difficulty: 'hard',
            estimatedTime: '90 min',
            points: 400,
            solveCount: 0,
            tags: ['pwn', 'ret2libc', 'nx-bypass'],
            description: {
                ar: 'تجاوز حماية NX باستخدام تقنية ret2libc للحصول على shell.',
                en: 'Bypass NX protection using ret2libc technique to get a shell.'
            },
            learningObjectives: [
                { ar: 'فهم حماية NX', en: 'Understand NX protection' },
                { ar: 'استخدام دوال libc', en: 'Use libc functions' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو عنوان system() في libc؟', en: 'What is system() address in libc?' },
                    answer: '0xf7e12420',
                    points: 100
                },
                {
                    id: 2,
                    question: { ar: 'ما هو عنوان "/bin/sh" في libc؟', en: 'What is "/bin/sh" address in libc?' },
                    answer: '0xf7f5a1db',
                    points: 100
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag في /root/flag.txt؟', en: 'What is the flag in /root/flag.txt?' },
                    answer: 'FLAG{r3t2l1bc_sh3ll_p0pp3d}',
                    points: 200
                }
            ],
            requiresMachine: true,
            machineConfig: {
                type: 'docker',
                image: 'pwn-lab-advanced',
                ports: [22, 1339]
            },
            hints: [
                { cost: 30, text: { ar: 'استخدم ldd و strings للعثور على العناوين', en: 'Use ldd and strings to find addresses' } },
                { cost: 40, text: { ar: 'Payload: padding + system + exit + /bin/sh', en: 'Payload: padding + system + exit + /bin/sh' } }
            ],
            writeup: {
                available: false,
                content: {
                    ar: '# حل Ret2Libc\n\n```python\nfrom pwn import *\nsystem = 0xf7e12420\nexit_addr = 0xf7e05f80\nbinsh = 0xf7f5a1db\npayload = b"A"*76 + p32(system) + p32(exit_addr) + p32(binsh)\n```',
                    en: '# Ret2Libc Solution\n\n```python\nfrom pwn import *\nsystem = 0xf7e12420\nexit_addr = 0xf7e05f80\nbinsh = 0xf7f5a1db\npayload = b"A"*76 + p32(system) + p32(exit_addr) + p32(binsh)\n```'
                }
            }
        }
    ],

    owasp: [
        // A01: Broken Access Control (IDOR)
        {
            id: 'idor-edu',
            title: { ar: 'شرح IDOR (تعليمي)', en: 'IDOR Explained (Edu)' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            solveCount: 0,
            tags: ['owasp', 'idor', 'access-control', 'educational'],
            description: {
                ar: 'تعلم كيف تحدث ثغرة IDOR (Insecure Direct Object Reference). في هذا التحدي التعليمي، سنقوم بتغيير معرف المستخدم للوصول إلى بيانات شخص آخر.',
                en: 'Learn how IDOR (Insecure Direct Object Reference) works. In this educational challenge, we will change the user ID to access someone else\'s data.'
            },
            learningObjectives: [
                { ar: 'فهم مفهوم IDOR', en: 'Understand IDOR concept' },
                { ar: 'التعرف على المعرفات في الروابط', en: 'Identify IDs in URLs' },
                { ar: 'تغيير المعرفات للوصول لبيانات غير مصرح بها', en: 'Manipulate IDs to access unauthorized data' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو معرف المستخدم الخاص بك (guest)؟', en: 'What is your user ID (guest)?' },
                    answer: '1001',
                    hint: { ar: 'انظر إلى الرابط: ?id=...', en: 'Look at the URL: ?id=...' },
                    points: 10
                },
                {
                    id: 2,
                    question: { ar: 'قم بتغيير المعرف إلى 1000. ما هو اسم المستخدم الذي ظهر؟', en: 'Change ID to 1000. What username appears?' },
                    answer: 'admin',
                    points: 20
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag الموجود في حساب الـ admin؟', en: 'What is the flag in the admin account?' },
                    answer: 'FLAG{idor_is_easy_to_miss}',
                    points: 20
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/idor-edu/index.html',
                deployable: true
            }
        },
        {
            id: 'idor-practice',
            title: { ar: 'تحدي IDOR (تطبيق)', en: 'IDOR Challenge (Practice)' },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 100,
            solveCount: 0,
            tags: ['owasp', 'idor', 'access-control', 'practice'],
            description: {
                ar: 'طبق ما تعلمته. أنت موظف برقم 105. حاول الوصول إلى تقرير سري خاص بالمدير.',
                en: 'Apply what you learned. You are employee #105. Try to access a confidential report belonging to the manager.'
            },
            learningObjectives: [
                { ar: 'تخمين نمط المعرفات', en: 'Guess ID patterns' },
                { ar: 'استغلال IDOR في سيناريو واقعي', en: 'Exploit IDOR in a realistic scenario' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو رقم معرف المدير؟', en: 'What is the manager\'s ID?' },
                    answer: '100',
                    hint: { ar: 'المدرراء عادة لديهم أرقام مميزة وصغيرة', en: 'Managers usually have distinct, small numbers' },
                    points: 40
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag الموجود في التقرير السري؟', en: 'What is the flag in the confidential report?' },
                    answer: 'FLAG{manager_access_granted_1337}',
                    points: 60
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/idor-practice/index.html',
                deployable: true
            }
        },

        // A03: Injection (SQLi)
        {
            id: 'sqli-edu',
            title: { ar: 'شرح SQL Injection (تعليمي)', en: 'SQL Injection Explained (Edu)' },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 50,
            solveCount: 0,
            tags: ['owasp', 'sqli', 'injection', 'educational'],
            description: {
                ar: 'شرح تفاعلي لكيفية عمل SQL Injection. شاهد كيف يتم بناء الاستعلام وكيف يكسره الهاكر.',
                en: 'Interactive explanation of SQL Injection. See how the query is built and how a hacker breaks it.'
            },
            learningObjectives: [
                { ar: 'رؤية استعلام SQL', en: 'Visualize SQL query' },
                { ar: 'فهم دور الرموز الخاصة (\' و --)', en: 'Understand special characters (\' and --)' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الرمز الذي يسبب خطأ في قاعدة البيانات؟', en: 'What character causes a database error?' },
                    answer: "'",
                    points: 10
                },
                {
                    id: 2,
                    question: { ar: 'أدخل payload يجعل الشرط صحيحاً دائماً.', en: 'Enter a payload that makes the condition always true.' },
                    answer: "' OR '1'='1",
                    points: 40
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/sqli-edu/index.html',
                deployable: true
            }
        },
        {
            id: 'sqli-practice',
            title: { ar: 'تجاوز تسجيل الدخول (تطبيق)', en: 'Login Bypass (Practice)' },
            difficulty: 'medium',
            estimatedTime: '30 min',
            points: 120,
            solveCount: 0,
            tags: ['owasp', 'sqli', 'injection', 'practice'],
            description: {
                ar: 'حاول الدخول إلى لوحة التحكم كـ admin بدون معرفة كلمة المرور.',
                en: 'Try to access the admin dashboard without knowing the password.'
            },
            learningObjectives: [
                { ar: 'تجاوز المصادقة', en: 'Bypass authentication' },
                { ar: 'التعامل مع فلاتر بسيطة', en: 'Deal with simple filters' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{admin_login_bypassed_success}',
                    hint: { ar: 'جرب استخدام التعليقات -- أو #', en: 'Try using comments -- or #' },
                    points: 120
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/sqli-practice/index.html',
                deployable: true
            }
        },

        // A03: Injection (XSS)
        {
            id: 'xss-edu',
            title: { ar: 'شرح XSS (تعليمي)', en: 'XSS Explained (Edu)' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 50,
            solveCount: 0,
            tags: ['owasp', 'xss', 'injection', 'educational'],
            description: {
                ar: 'تعلم كيف يتم تنفيذ كود JavaScript خبيث في متصفح المستخدم.',
                en: 'Learn how malicious JavaScript code is executed in the user\'s browser.'
            },
            learningObjectives: [
                { ar: 'فهم سياق HTML', en: 'Understand HTML context' },
                { ar: 'تنفيذ alert بسيط', en: 'Execute simple alert' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'اجعل الموقع يظهر نافذة منبثقة (alert) تحتوي على الرقم 1.', en: 'Make the site show a popup (alert) with number 1.' },
                    answer: '<script>alert(1)</script>',
                    points: 50
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/xss-edu/index.html',
                deployable: true
            }
        },
        {
            id: 'xss-practice',
            title: { ar: 'سرقة الجلسة (تطبيق)', en: 'Session Stealing (Practice)' },
            difficulty: 'medium',
            estimatedTime: '25 min',
            points: 100,
            solveCount: 0,
            tags: ['owasp', 'xss', 'injection', 'practice'],
            description: {
                ar: 'الموقع يقوم بحظر كلمة script. هل يمكنك تجاوز الحماية وتنفيذ الكود؟',
                en: 'The site blocks the word "script". Can you bypass the protection and execute code?'
            },
            learningObjectives: [
                { ar: 'تجاوز فلاتر XSS', en: 'Bypass XSS filters' },
                { ar: 'استخدام وسوم بديلة', en: 'Use alternative tags' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{img_onerror_is_awesome}',
                    hint: { ar: 'جرب استخدام وسم <img> مع حدث onerror', en: 'Try using <img> tag with onerror event' },
                    points: 100
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/xss-practice/index.html',
                deployable: true
            }
        },

        // A02: Cryptographic Failures
        {
            id: 'crypto-weak-encryption',
            title: { ar: 'تشفير ضعيف', en: 'Weak Encryption' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 60,
            solveCount: 0,
            tags: ['owasp', 'crypto-failures', 'encryption'],
            description: {
                ar: 'اكتشف البيانات المشفرة بخوارزمية ضعيفة وقم بفك تشفيرها.',
                en: 'Discover data encrypted with a weak algorithm and decrypt it.'
            },
            learningObjectives: [
                { ar: 'التعرف على التشفير الضعيف', en: 'Identify weak encryption' },
                { ar: 'فك تشفير Base64', en: 'Decode Base64' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag المخفي؟', en: 'What is the hidden flag?' },
                    answer: 'FLAG{weak_crypto_is_dangerous}',
                    hint: { ar: 'ابحث في ملفات JavaScript', en: 'Look in JavaScript files' },
                    points: 60
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/weak-crypto/index.html',
                deployable: true
            }
        },
        {
            id: 'crypto-exposed-secrets',
            title: { ar: 'أسرار مكشوفة', en: 'Exposed Secrets' },
            difficulty: 'easy',
            estimatedTime: '20 min',
            points: 80,
            solveCount: 0,
            tags: ['owasp', 'crypto-failures', 'secrets'],
            description: {
                ar: 'ابحث عن مفاتيح API وكلمات مرور مخزنة بشكل غير آمن.',
                en: 'Find API keys and passwords stored insecurely.'
            },
            learningObjectives: [
                { ar: 'فحص الكود المصدري', en: 'Inspect source code' },
                { ar: 'البحث عن الأسرار المكشوفة', en: 'Find exposed secrets' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو مفتاح API المكشوف؟', en: 'What is the exposed API key?' },
                    answer: 'sk_live_51HxYz2KqP9L8mN3O',
                    points: 40
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{never_hardcode_secrets}',
                    points: 40
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/exposed-secrets/index.html',
                deployable: true
            }
        },

        // A04: Insecure Design
        {
            id: 'insecure-design-logic',
            title: { ar: 'خلل منطقي', en: 'Logic Flaw' },
            difficulty: 'medium',
            estimatedTime: '30 min',
            points: 150,
            solveCount: 0,
            tags: ['owasp', 'insecure-design', 'logic'],
            description: {
                ar: 'استغل خللاً منطقياً في نظام الخصومات للحصول على منتجات مجانية.',
                en: 'Exploit a logic flaw in the discount system to get free products.'
            },
            learningObjectives: [
                { ar: 'فهم المنطق التجاري', en: 'Understand business logic' },
                { ar: 'اكتشاف الثغرات المنطقية', en: 'Discover logic vulnerabilities' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'كم السعر النهائي بعد استغلال الثغرة؟', en: 'What is the final price after exploiting the flaw?' },
                    answer: '0',
                    hint: { ar: 'جرب تطبيق كوبون الخصم أكثر من مرة', en: 'Try applying the discount coupon multiple times' },
                    points: 70
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{business_logic_bypass_2024}',
                    points: 80
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/logic-flaw/index.html',
                deployable: true
            }
        },

        // A05: Security Misconfiguration
        {
            id: 'misconfig-default-creds',
            title: { ar: 'بيانات افتراضية', en: 'Default Credentials' },
            difficulty: 'easy',
            estimatedTime: '10 min',
            points: 50,
            solveCount: 0,
            tags: ['owasp', 'misconfiguration', 'credentials'],
            description: {
                ar: 'ابحث عن لوحة إدارة تستخدم بيانات دخول افتراضية.',
                en: 'Find an admin panel using default credentials.'
            },
            learningObjectives: [
                { ar: 'البحث عن صفحات الإدارة', en: 'Search for admin pages' },
                { ar: 'تجربة بيانات افتراضية شائعة', en: 'Try common default credentials' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو اسم المستخدم الافتراضي؟', en: 'What is the default username?' },
                    answer: 'admin',
                    points: 20
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{change_default_passwords}',
                    points: 30
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/default-creds/index.html',
                deployable: true
            }
        },
        {
            id: 'misconfig-directory-listing',
            title: { ar: 'قائمة المجلدات', en: 'Directory Listing' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 70,
            solveCount: 0,
            tags: ['owasp', 'misconfiguration', 'directory'],
            description: {
                ar: 'استكشف المجلدات المكشوفة للعثور على ملفات حساسة.',
                en: 'Explore exposed directories to find sensitive files.'
            },
            learningObjectives: [
                { ar: 'استكشاف هيكل المجلدات', en: 'Explore directory structure' },
                { ar: 'العثور على ملفات مخفية', en: 'Find hidden files' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما اسم الملف السري؟', en: 'What is the secret file name?' },
                    answer: 'backup.sql',
                    points: 30
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{disable_directory_listing}',
                    points: 40
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/directory-listing/index.html',
                deployable: true
            }
        },

        // A07: Identification and Authentication Failures
        {
            id: 'auth-weak-password',
            title: { ar: 'كلمة مرور ضعيفة', en: 'Weak Password' },
            difficulty: 'easy',
            estimatedTime: '15 min',
            points: 60,
            solveCount: 0,
            tags: ['owasp', 'authentication', 'password'],
            description: {
                ar: 'استخدم هجوم القوة الغاشمة لاختراق حساب بكلمة مرور ضعيفة.',
                en: 'Use brute force to crack an account with a weak password.'
            },
            learningObjectives: [
                { ar: 'فهم هجمات القوة الغاشمة', en: 'Understand brute force attacks' },
                { ar: 'تجربة كلمات مرور شائعة', en: 'Try common passwords' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هي كلمة المرور؟', en: 'What is the password?' },
                    answer: 'password123',
                    hint: { ar: 'جرب كلمات مرور شائعة', en: 'Try common passwords' },
                    points: 30
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{use_strong_passwords}',
                    points: 30
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/weak-password/index.html',
                deployable: true
            }
        },
        {
            id: 'auth-session-fixation',
            title: { ar: 'تثبيت الجلسة', en: 'Session Fixation' },
            difficulty: 'medium',
            estimatedTime: '25 min',
            points: 130,
            solveCount: 0,
            tags: ['owasp', 'authentication', 'session'],
            description: {
                ar: 'استغل ثغرة تثبيت الجلسة للوصول إلى حساب آخر.',
                en: 'Exploit session fixation vulnerability to access another account.'
            },
            learningObjectives: [
                { ar: 'فهم إدارة الجلسات', en: 'Understand session management' },
                { ar: 'استغلال تثبيت الجلسة', en: 'Exploit session fixation' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{session_fixation_exploited}',
                    hint: { ar: 'انظر إلى معرف الجلسة في الرابط', en: 'Look at the session ID in the URL' },
                    points: 130
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/session-fixation/index.html',
                deployable: true
            }
        },

        // A08: Software and Data Integrity Failures
        {
            id: 'integrity-unsigned-code',
            title: { ar: 'كود غير موقع', en: 'Unsigned Code' },
            difficulty: 'medium',
            estimatedTime: '20 min',
            points: 110,
            solveCount: 0,
            tags: ['owasp', 'integrity', 'code'],
            description: {
                ar: 'اكتشف كيف يمكن تعديل الكود غير الموقع.',
                en: 'Discover how unsigned code can be modified.'
            },
            learningObjectives: [
                { ar: 'فهم أهمية توقيع الكود', en: 'Understand code signing importance' },
                { ar: 'تعديل الكود غير المحمي', en: 'Modify unprotected code' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{always_verify_integrity}',
                    hint: { ar: 'افحص ملف JavaScript', en: 'Inspect the JavaScript file' },
                    points: 110
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/unsigned-code/index.html',
                deployable: true
            }
        },

        // A09: Security Logging and Monitoring Failures
        {
            id: 'logging-injection',
            title: { ar: 'حقن السجلات', en: 'Log Injection' },
            difficulty: 'medium',
            estimatedTime: '25 min',
            points: 120,
            solveCount: 0,
            tags: ['owasp', 'logging', 'injection'],
            description: {
                ar: 'احقن بيانات خبيثة في سجلات النظام.',
                en: 'Inject malicious data into system logs.'
            },
            learningObjectives: [
                { ar: 'فهم حقن السجلات', en: 'Understand log injection' },
                { ar: 'تزوير سجلات النظام', en: 'Forge system logs' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag؟', en: 'What is the flag?' },
                    answer: 'FLAG{sanitize_log_inputs}',
                    hint: { ar: 'جرب إدخال أسطر جديدة', en: 'Try entering new lines' },
                    points: 120
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/log-injection/index.html',
                deployable: true
            }
        },

        // A10: Server-Side Request Forgery (SSRF)
        {
            id: 'ssrf-practice',
            title: { ar: 'SSRF Master Class', en: 'SSRF Master Class' },
            difficulty: 'hard',
            estimatedTime: '45 min',
            points: 300,
            solveCount: 0,
            tags: ['owasp', 'ssrf', 'server', 'cloud'],
            description: {
                ar: 'تحدي شامل لثغرة SSRF. تعلم كيفية الوصول للخدمات الداخلية، فحص المنافذ، سرقة بيانات السحابة، وتجاوز الفلاتر.',
                en: 'Comprehensive SSRF challenge. Learn how to access internal services, scan ports, steal cloud metadata, and bypass filters.'
            },
            learningObjectives: [
                { ar: 'الوصول للموارد الداخلية (Localhost)', en: 'Access internal resources (Localhost)' },
                { ar: 'فحص المنافذ الداخلية', en: 'Internal port scanning' },
                { ar: 'سرقة بيانات AWS Metadata', en: 'Steal AWS Metadata' },
                { ar: 'تجاوز فلاتر الحماية', en: 'Bypass security filters' }
            ],
            tasks: [
                {
                    id: 1,
                    question: { ar: 'ما هو الـ flag الخاص بـ Localhost؟', en: 'What is the Localhost flag?' },
                    answer: 'FLAG{ssrf_l0c4lh0st_acc3ss_succ3ss}',
                    hint: { ar: 'حاول الوصول إلى /admin', en: 'Try accessing /admin' },
                    points: 50
                },
                {
                    id: 2,
                    question: { ar: 'ما هو الـ flag الخاص بفحص المنافذ؟', en: 'What is the Port Scanning flag?' },
                    answer: 'FLAG{p0rt_sc4nn1ng_v14_ssrf}',
                    hint: { ar: 'ابحث في النطاق 192.168.1.x', en: 'Scan the 192.168.1.x range' },
                    points: 75
                },
                {
                    id: 3,
                    question: { ar: 'ما هو الـ flag الخاص بـ AWS؟', en: 'What is the AWS flag?' },
                    answer: 'FLAG{aws_m3t4d4t4_l34k3d}',
                    hint: { ar: 'عنوان Metadata هو 169.254.169.254', en: 'Metadata IP is 169.254.169.254' },
                    points: 75
                },
                {
                    id: 4,
                    question: { ar: 'ما هو الـ flag الخاص بتجاوز الفلتر؟', en: 'What is the Filter Bypass flag?' },
                    answer: 'FLAG{f1lt3r_byp4ss_m4st3r}',
                    hint: { ar: 'استخدم 0.0.0.0 أو [::]', en: 'Use 0.0.0.0 or [::]' },
                    points: 100
                }
            ],
            vulnerableApp: {
                type: 'iframe',
                path: 'ctf-apps/ssrf-practice/index.html',
                deployable: true
            }
        }
    ]
};

// Achievements system
const achievements = [
    {
        id: 'first-blood',
        title: { ar: 'أول دم', en: 'First Blood' },
        description: { ar: 'حل أول room', en: 'Solve your first room' },
        icon: 'fa-trophy',
        color: 'gold',
        points: 10
    },
    {
        id: 'web-master',
        title: { ar: 'خبير الويب', en: 'Web Master' },
        description: { ar: 'حل جميع rooms الويب', en: 'Solve all web rooms' },
        icon: 'fa-globe',
        color: 'blue',
        points: 500
    },
    {
        id: 'crypto-expert',
        title: { ar: 'خبير التشفير', en: 'Crypto Expert' },
        description: { ar: 'حل جميع rooms التشفير', en: 'Solve all crypto rooms' },
        icon: 'fa-lock',
        color: 'purple',
        points: 400
    },
    {
        id: 'speed-demon',
        title: { ar: 'شيطان السرعة', en: 'Speed Demon' },
        description: { ar: 'حل room في أقل من 10 دقائق', en: 'Solve a room in under 10 minutes' },
        icon: 'fa-bolt',
        color: 'yellow',
        points: 50
    },
    {
        id: 'hint-free',
        title: { ar: 'بدون مساعدة', en: 'Hint Free' },
        description: { ar: 'حل room بدون استخدام hints', en: 'Solve a room without using hints' },
        icon: 'fa-brain',
        color: 'green',
        points: 100
    },
    {
        id: 'perfect-score',
        title: { ar: 'النتيجة الكاملة', en: 'Perfect Score' },
        description: { ar: 'احصل على جميع النقاط في room', en: 'Get all points in a room' },
        icon: 'fa-star',
        color: 'gold',
        points: 75
    }
];

// Helper functions
function getRoomById(roomId) {
    for (const category in ctfRooms) {
        const room = ctfRooms[category].find(r => r.id === roomId);
        if (room) return room;
    }
    return null;
}

function getAllRooms() {
    const allRooms = [];
    for (const category in ctfRooms) {
        allRooms.push(...ctfRooms[category]);
    }
    return allRooms;
}

function getRoomsByDifficulty(difficulty) {
    return getAllRooms().filter(room => room.difficulty === difficulty);
}

function getRoomsByCategory(category) {
    return ctfRooms[category] || [];
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ctfRooms, achievements, getRoomById, getAllRooms, getRoomsByDifficulty, getRoomsByCategory };
}

console.log('CTF Rooms loaded successfully! Total rooms:', getAllRooms().length);
