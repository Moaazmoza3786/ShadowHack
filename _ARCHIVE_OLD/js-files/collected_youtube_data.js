// ==================== YOUTUBE COURSES DATA ====================
// Real YouTube playlists organized by category for Study Hub

const youtubeCoursesData = {
    categories: [
        // ========== WEB SECURITY ==========
        {
            id: 'web-security',
            name: 'Web Application Security',
            nameAr: 'أمن تطبيقات الويب',
            icon: 'fa-globe',
            color: '#e74c3c'
        },
        {
            id: 'network',
            name: 'Network Security',
            nameAr: 'أمن الشبكات',
            icon: 'fa-network-wired',
            color: '#3498db'
        },
        {
            id: 'linux',
            name: 'Linux & System Administration',
            nameAr: 'لينكس وإدارة الأنظمة',
            icon: 'fa-terminal',
            color: '#27ae60'
        },
        {
            id: 'ctf',
            name: 'CTF & Practical Labs',
            nameAr: 'تحديات CTF والتدريب العملي',
            icon: 'fa-flag',
            color: '#9b59b6'
        },
        {
            id: 'certs',
            name: 'Certifications',
            nameAr: 'الشهادات المعتمدة',
            icon: 'fa-certificate',
            color: '#f39c12'
        }
    ],

    playlists: [
        // ========== SQL INJECTION ==========
        {
            id: 'sql-injection',
            title: 'SQL Injection Complete Course',
            titleAr: 'كورس SQL Injection الكامل',
            description: 'تعلم ثغرات SQL Injection من الصفر للاحتراف مع تطبيقات عملية على Portswigger',
            descriptionEn: 'Learn SQL Injection vulnerabilities from scratch with Portswigger labs',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLX621demLUSbqhfsi88Be2JFrWmhZ6CfJ',
            channel: 'Web Security Academy',
            thumbnail: 'tMkS_o_iXOc',
            totalVideos: 7,
            videos: [
                { position: 1, title: 'شرح ثغرة SQL injection بالتفصيل للمبتدئين', videoId: 'tMkS_o_iXOc' },
                { position: 2, title: 'SQL Injection: اختراق المواقع بالتطبيق العملي (LAB 1)', videoId: 'IwNbzcBaIc8' },
                { position: 3, title: 'SQL injection: لاختراق صفحة تسجيل الدخول (LAB 2)', videoId: 'kHQDYFo7kDg' },
                { position: 4, title: 'SQL injection: معرفة اصدار قاعدة البيانات (LAB 3)', videoId: 'jYUFti7uFh4' },
                { position: 5, title: 'SQL injection: اختراق باسوورد الادمن (LAB 4&5)', videoId: 'CzZSCmd1i5Q' },
                { position: 6, title: 'SQL injection: اختراق صفحات تسجيل الدخول (LAB 6-10)', videoId: 'yy7Q8zEep_I' },
                { position: 7, title: 'شرح Blind SQLi + Out-Of-Band SQLi', videoId: 'Yj71iAGPOzw' }
            ],
            quizzes: [
                {
                    id: 'sql-1',
                    videoId: 'tMkS_o_iXOc',
                    question: 'ما هو الهدف الأساسي من ثغرة SQL Injection؟',
                    options: [
                        'تخمين كلمات المرور فقط',
                        'التلاعب باستعلامات قاعدة البيانات للوصول لبيانات غير مصرح بها',
                        'إيقاف خدمة الموقع (DoS)',
                        'تشفير قاعدة البيانات'
                    ],
                    correctAnswer: 1,
                    explanation: 'ثغرة SQL Injection تسمح للمهاجم بحقن كود SQL ضار في الاستعلامات، مما يؤدي للتلاعب بقاعدة البيانات وسحب البيانات منها.'
                },
                {
                    id: 'sql-2',
                    videoId: 'tMkS_o_iXOc',
                    question: 'أي من الرموز التالية يُستخدم عادةً لاختبار وجود ثغرة SQLi؟',
                    options: [
                        '#',
                        '$',
                        "' (Single Quote)",
                        '@'
                    ],
                    correctAnswer: 2,
                    explanation: 'الرمز \' (Single Quote) يُستخدم لكسر استعلام SQL واكتشاف الأخطاء التي تدل على وجود الثغرة.'
                }
            ]
        },

        // ========== XSS ==========
        {
            id: 'xss-complete',
            title: 'Cross-Site Scripting (XSS) Full Course',
            titleAr: 'كورس XSS الكامل',
            description: 'شرح شامل لثغرات XSS بكل أنواعها مع 33 تطبيق عملي على Portswigger',
            descriptionEn: 'Complete XSS course with 33 Portswigger labs',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLX621demLUSaeP8x6tbt8H1Wfee5UH_hi',
            channel: 'Web Security Academy',
            thumbnail: 'G6XOKfkWGSg',
            totalVideos: 33,
            videos: [
                { position: 1, title: 'XSS هتفهمها بنسبة 100% | Bug Bounty', videoId: 'G6XOKfkWGSg' },
                { position: 2, title: 'Types of Cross site scripting (XSS)', videoId: 'sW2OYqxWOI4' },
                { position: 3, title: 'Reflected XSS into HTML context', videoId: 'IdUej-3554s' },
                { position: 4, title: 'Stored XSS into HTML context', videoId: 'w20ywrGUF90' },
                { position: 5, title: 'DOM XSS in document.write sink', videoId: 'YF6KGwepMro' },
                { position: 6, title: 'DOM XSS in innerHTML', videoId: 'x6dkvIyBoas' },
                { position: 7, title: 'DOM XSS in jQuery anchor href', videoId: '8aJLj6DQ824' },
                { position: 8, title: 'DOM XSS in jQuery selector', videoId: 'XLPW_0VtFOI' },
                { position: 9, title: 'Reflected XSS into attribute', videoId: 'OPi8p67g-bw' },
                { position: 10, title: 'Stored XSS into anchor href', videoId: '6Rh0Oxntw3U' },
                { position: 11, title: 'Reflected XSS into JavaScript string', videoId: 'eOF4R5wwsHM' },
                { position: 12, title: 'DOM XSS in Select Element', videoId: 'eq8SinMYLhs' },
                { position: 13, title: 'DOM XSS in AngularJS expression', videoId: 'L68V3DrbbIo' },
                { position: 14, title: 'Reflected DOM XSS', videoId: 'L-l4eGQvqwE' },
                { position: 15, title: 'Stored DOM XSS', videoId: 'ffkMUk1iw1k' },
                { position: 16, title: 'Reflected XSS most tags blocked', videoId: '6-21VqDlGpU' },
                { position: 17, title: 'Reflected XSS custom tags only', videoId: '0qmxwzIl7Ig' },
                { position: 18, title: 'Reflected XSS with SVG markup', videoId: 'qpFemIRfcDc' },
                { position: 19, title: 'Reflected XSS in canonical link', videoId: 'PUIf6pSPs20' },
                { position: 20, title: 'Reflected XSS into JavaScript string', videoId: 'QadBfHheFOE' },
                { position: 21, title: 'Reflected XSS into JavaScript', videoId: '2n-Ae42Ih_M' },
                { position: 22, title: 'Stored XSS into onclick event', videoId: 'qz_Y914Jzxo' },
                { position: 23, title: 'Reflected XSS into template literal', videoId: 'NNL-VrleuBs' },
                { position: 24, title: 'Blind XSS to steal cookies', videoId: 'T8p-WJhCohk' },
                { position: 25, title: 'Blind XSS to capture passwords', videoId: '89avjhiD7tI' },
                { position: 26, title: 'Exploiting XSS to perform CSRF', videoId: '_GUz6ZDlJx0' },
                { position: 27, title: 'Reflected XSS with AngularJS sandbox', videoId: 'jdMSnxs_0Ns' },
                { position: 28, title: 'Reflected XSS with AngularJS + CSP', videoId: 'UyTpW2Hhqu0' },
                { position: 29, title: 'Reflected XSS event handlers blocked', videoId: '48mX7Z102fU' },
                { position: 30, title: 'Reflected XSS in JavaScript URL', videoId: 'zZwacYyEbhs' },
                { position: 31, title: 'Reflected XSS (CSP) + Dangling markup', videoId: '-GbNFcgNdtE' },
                { position: 32, title: 'Reflected XSS with CSP bypass', videoId: 'OardxUlrWD0' },
                { position: 33, title: 'اخترق المواقع على Hackerone للمبتدئين', videoId: 'X7Zib1zn24s' }
            ]
        },

        // ========== WEB APP PENTESTING ==========
        {
            id: 'web-app-pentesting',
            title: 'Web Application Penetration Testing',
            titleAr: 'اختبار اختراق تطبيقات الويب',
            description: 'كورس شامل في اختبار اختراق تطبيقات الويب يغطي XSS, CSRF, SQLi, SSRF وأكثر',
            descriptionEn: 'Complete Web App Pentesting covering XSS, CSRF, SQLi, SSRF and more',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLDRMxi70CdSBHODkNy87kqqGUSnl0ASxg',
            channel: 'Cyber Talents',
            thumbnail: 'gjpwWj-u8Ew',
            totalVideos: 36,
            videos: [
                { position: 1, title: 'DNS Zone Transfer', videoId: 'gjpwWj-u8Ew' },
                { position: 2, title: 'Practice Lab Installation', videoId: 'hH2tRZ2l-Oc' },
                { position: 3, title: 'Reflected XSS', videoId: 'c9R9hJBSUmQ' },
                { position: 4, title: 'Stored XSS', videoId: '5VccS6cuFgo' },
                { position: 5, title: 'Google XSS Game Walkthrough', videoId: 'zg1gpXJ5bSA' },
                { position: 6, title: 'XSS Exploitation Part 1', videoId: '51aCbGvuyC0' },
                { position: 7, title: 'XSS Exploitation Part 2', videoId: 'PhA2LykHZSQ' },
                { position: 8, title: 'XSS Exploitation Part 2 (cont)', videoId: 'DzwwJflFdKQ' },
                { position: 9, title: 'XSS Exploitation', videoId: 'eIHkFshMuhU' },
                { position: 10, title: 'XSS via HTTP Headers', videoId: 'L6mbtzyHkwM' },
                { position: 11, title: 'XSS WAF Bypass', videoId: 'tVKr5l3FLS4' },
                { position: 12, title: 'CSRF Introduction', videoId: 'k3vwqfzqW1s' },
                { position: 13, title: 'CSRF Password Manipulation', videoId: 'NbtNJrYSpG0' },
                { position: 14, title: 'CSRF Secret Manipulation', videoId: 'pPYI7YpfyFI' },
                { position: 15, title: 'CSRF Balance Manipulation', videoId: 'ybkSlILo6QY' },
                { position: 16, title: 'CSRF Exploit Craft', videoId: 'XRS8ysq1SgA' },
                { position: 17, title: 'LFI/LFD/LFR Introduction', videoId: 'AaZ3sndI2dI' },
                { position: 18, title: 'LFI Exploitation', videoId: 'o6fAfLqUK6Y' },
                { position: 19, title: 'SSRF Part 1', videoId: 'zPdlOU7orzw' },
                { position: 20, title: 'SSRF Part 2', videoId: 'lbiILrk958g' },
                { position: 21, title: 'SSRF Exploitation', videoId: 'BkNu9X1LlKU' },
                { position: 22, title: 'SSRF WAF Bypass', videoId: 'q4sC6GwngTM' },
                { position: 23, title: 'Bug Bounty Reporting', videoId: 'CZ2ESAafXG4' },
                { position: 24, title: 'CVSS Explained', videoId: 'tSiDtksX3xg' },
                { position: 25, title: 'SQL Injection Part 1', videoId: 'GhZMixFBTMY' },
                { position: 26, title: 'SQL Injection Part 2', videoId: 'aQnbnmJuDaA' },
                { position: 27, title: 'SQL Injection Part 3', videoId: 'rPTiWWeRoxE' },
                { position: 28, title: 'SQL Injection Part 4', videoId: 'F0iKeJZqWOA' },
                { position: 29, title: 'SQL Injection Part 5', videoId: 'XIAIUCe_d6c' },
                { position: 30, title: 'SQL Injection Part 6', videoId: '1_qcEw6br9w' },
                { position: 31, title: 'SQLMap Part 1', videoId: 'YeFJ9vaMhVg' },
                { position: 32, title: 'SQLMap Part 2', videoId: 'OfIt1gzaLZ8' },
                { position: 33, title: 'SQLMap Part 3', videoId: 'jLdYgyTpT-Y' },
                { position: 34, title: 'SQLMap Part 4', videoId: '-PkGNjp-fXo' },
                { position: 35, title: 'SQLMap Part 5', videoId: '3jpJTYjRCEU' },
                { position: 36, title: 'SQLMap Part 6', videoId: 'sZzZIWuq-FM' }
            ]
        },

        // ========== EBRAHIM HEGAZY COURSE ==========
        {
            id: 'hegazy-web-pentest',
            title: 'Web Pentesting Course - Ebrahim Hegazy',
            titleAr: 'كورس اختبار اختراق الويب - إبراهيم حجازي',
            description: 'كورس شامل من المهندس إبراهيم حجازي يغطي أساسيات الأمان وصولاً للاحتراف',
            descriptionEn: 'Comprehensive course by Ebrahim Hegazy from basics to advanced',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLv7cogHXoVhXvHPzIl1dWtBiYUAL8baHj',
            channel: 'Ebrahim Hegazy',
            thumbnail: 'BjfCWSFmIFI',
            totalVideos: 48,
            videos: [
                { position: 1, title: 'مقدمة الكورس', videoId: 'BjfCWSFmIFI' },
                { position: 2, title: 'تحميل وتشغيل متطلبات الكورس', videoId: 'F7b48a2pek4' },
                { position: 3, title: 'شرح تسريبات قواعد البيانات', videoId: 'MUN1CaC-wPE' },
                { position: 4, title: 'Exploiting Leaked Databases', videoId: 'L-7dN3C-cOE' },
                { position: 5, title: 'مقدمة لنظام Linux', videoId: 'lN7JLDvP3_8' },
                { position: 6, title: 'Linux Command Line Part 1', videoId: 'Lki6Gu8opGA' },
                { position: 7, title: 'Linux Command Line Part 2', videoId: 'Jp2iAAGqADw' },
                { position: 8, title: 'Linux Command Part 3', videoId: 'PxRm5GKSNMI' },
                { position: 9, title: 'Linux Command Part 4', videoId: 'C8pPNa79K2Y' },
                { position: 10, title: 'Linux Command Part 5', videoId: 'LKIXbNW-B5g' },
                { position: 11, title: 'ما هو ال Hashing', videoId: '4TBStYr8t4g' },
                { position: 12, title: 'ما هو ال Encoding', videoId: 'gOos5go5h2c' },
                { position: 13, title: 'Symmetric Encryption', videoId: 'LOtK2IDBGik' },
                { position: 14, title: 'Asymmetric Encryption', videoId: '8lW2kvCVpHc' },
                { position: 15, title: 'كيف يعمل HTTPS', videoId: 'Iws5GpUVnq4' },
                { position: 16, title: 'What Happens when I open Google.com', videoId: '8XKbJWnktc8' },
                { position: 17, title: 'شرح TCP & UDP', videoId: 'fiFBpFjfYyo' },
                { position: 18, title: 'ما هو DNS وكيف يعمل', videoId: 'ynbtZbwcCjA' },
                { position: 19, title: 'Subdomain Takeover & DNS Records', videoId: 'Qo37c0v9Gdo' },
                { position: 20, title: 'اكتشاف Subdomain Takeover', videoId: '1tESU4F4Gt8' },
                { position: 21, title: 'شرح أداة NMAP', videoId: 'Ru4mFT0yANo' },
                { position: 22, title: 'Advanced Nmap', videoId: 'WpWlTOnOA94' },
                { position: 23, title: 'Nmap MoreOver', videoId: 'uQcCa-xVnSM' },
                { position: 24, title: 'شرح BurpSuite', videoId: '5f7Z52I0Y2s' },
                { position: 25, title: 'BurpSuite Tabs Part 1', videoId: 'OaXEDgW8SUE' },
                { position: 26, title: 'Burp Tabs Part 2', videoId: 'JEsyUw7WuIM' },
                { position: 27, title: 'HTTP Methods, Request & Response', videoId: 'PsdimP_-TKY' },
                { position: 28, title: 'لماذا تحدث الثغرات؟', videoId: 'sUUAzIa7F_A' },
                { position: 29, title: 'شرح ثغرات XSS', videoId: 'xiw_O5shcK4' },
                { position: 30, title: 'ترقيع ثغرات XSS', videoId: 'qp264U2QyY8' },
                { position: 31, title: 'Advanced XSS Exploitation', videoId: 'ZfYG3U6XueM' },
                { position: 32, title: 'SOP, CORS, CSP & CORS Exploitation', videoId: 'OcrmPMSjdSw' },
                { position: 33, title: 'WAF Bypass & XSS Filters', videoId: 'TQbKf4ZkzZ0' },
                { position: 34, title: 'XSS Challenges Part 1', videoId: 'TeIK1244sSk' },
                { position: 35, title: 'XSS Challenges Part 2', videoId: 'PRDO0ZjYGfc' },
                { position: 36, title: 'شرح ثغرات CSRF', videoId: 'Vb4md5w6JJ8' },
                { position: 37, title: 'كيف تتربح من اكتشاف الثغرات Part 1', videoId: 'z0qEQ-fF7uI' },
                { position: 38, title: 'كيف تتربح من اكتشاف الثغرات Part 2', videoId: 'KYVcCoksjSQ' },
                { position: 39, title: 'Information Disclosure Tips', videoId: 'V9Bc_Addfps' },
                { position: 40, title: 'شرح ثغرات SSRF', videoId: '9e1rSOH63ME' },
                { position: 41, title: 'LFI/RFI, LFD & Path Traversal', videoId: 'FOVnU-ud4V0' },
                { position: 42, title: 'Host Header Attacks', videoId: 'klBJDJ5s3XM' },
                { position: 43, title: 'Cache Poisoning & Deception', videoId: 'mCC-i4DaCgM' },
                { position: 44, title: 'Web App Pentest Methodology Part 1', videoId: 'zvJ3irTVDfc' },
                { position: 45, title: 'Web App Pentest Methodology Part 2', videoId: 'nmxoQP0Ca5k' },
                { position: 46, title: 'Google Bug Bounty Part 1', videoId: 'USyJjpjXEao' },
                { position: 47, title: 'Google Bug Bounty Part 2', videoId: 'zmAFVRMhqPk' },
                { position: 48, title: 'File Upload Vulnerabilities (15 طريقة)', videoId: 'E9yyhxzxeok' }
            ]
        },

        // ========== BURPSUITE ==========
        {
            id: 'burpsuite-crash',
            title: 'Burp Suite Crash Course',
            titleAr: 'كورس Burp Suite السريع',
            description: 'تعلم استخدام Burp Suite للاختبار الأمني - من قناة Cyber Guy',
            descriptionEn: 'Learn to use Burp Suite for security testing - by Cyber Guy',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSBzjCKsC0clrioNmlAPvASK',
            channel: 'Cyber Guy',
            thumbnail: 'Q9xOyOdgNf0',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'Burpsuite Crash Course | Part 1 (Arabic)', videoId: 'Q9xOyOdgNf0' },
                { position: 2, title: 'Burpsuite Crash Course | Part 2 (Arabic)', videoId: 'is_XmuY1l-I' },
                { position: 3, title: 'Burpsuite Crash Course | Part 3 (Arabic)', videoId: 'N4T21HO3src' }
            ]
        },

        // ========== ACCESS CONTROL ==========
        {
            id: 'access-control',
            title: 'Access Control Vulnerabilities',
            titleAr: 'ثغرات Access Control',
            description: 'شرح ثغرات التحكم في الوصول و IDOR و Privilege Escalation - قناة سايبر عرب',
            descriptionEn: 'Access Control, IDOR & Privilege Escalation - by Cyber 3rb',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLT3xpfeVr-PNkAR0AQlnkugAaQ006gYQ4',
            channel: 'سايبر عرب | Cyber 3rb',
            thumbnail: 'FjiCbidb8v8',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'الفرق بين Authentication و Authorization | ثغرات Access Control', videoId: 'FjiCbidb8v8' },
                { position: 2, title: 'شرح أنواع الـ Access Control', videoId: 'GiqqRJNO5EY' },
                { position: 3, title: 'شرح ثغرة IDOR و Privilege Escalation و BAC', videoId: 'placeholder' }
            ]
        },

        // ========== NMAP ==========
        {
            id: 'nmap-course',
            title: 'Nmap Course For Beginners',
            titleAr: 'دورة فحص الأنظمة Nmap للمبتدئين',
            description: 'دورة شاملة لتعلم Nmap لفحص الشبكات والأنظمة - قناة Coder-Web',
            descriptionEn: 'Complete Nmap course for network scanning - by Coder-Web',
            category: 'network',
            level: 'beginner',
            playlistId: 'PLMuAdKgHarVrTKlVhf516LwkyWsBxMQCq',
            channel: 'Coder-Web',
            thumbnail: '71mhRUJnhwo',
            totalVideos: 9,
            videos: [
                { position: 1, title: '#01 دورة فحص الانظمة | Nmap Course For Beginners', videoId: '71mhRUJnhwo' },
                { position: 2, title: '#02 دورة فحص الانظمة | Nmap Course For Beginners', videoId: 'placeholder' }
            ]
        },

        // ========== CCNA ==========
        {
            id: 'ccna',
            title: 'CCNA Full Course',
            titleAr: 'كورس CCNA الكامل',
            description: 'كورس CCNA الشامل لشهادة سيسكو',
            descriptionEn: 'Complete CCNA course for Cisco certification',
            category: 'network',
            level: 'beginner',
            playlistId: 'PLZmPGUyBFvUrvoa-NYzcUWFpxoZR11id_',
            channel: 'Network Academy',
            thumbnail: '1yv0kjxKwes',
            totalVideos: 27,
            videos: [
                {
                    "position": 1,
                    "title": "1- OSI Model - Full Arabic course كورس شبكات الجديد من الصفر للاحتراف ٢٠٢٥",
                    "videoId": "1yv0kjxKwes"
                },
                {
                    "position": 2,
                    "title": "2- IP & Subnet - Full Arabic course الكورس الجديد ٢٠٢٥",
                    "videoId": "yBpvDCTXlEs"
                },
                {
                    "position": 3,
                    "title": "3- Private IP vs Public IP - Full Arabic course الكورس الجديد ٢٠٢٥",
                    "videoId": "dyuGo_TIAJg"
                },
                {
                    "position": 4,
                    "title": "4- NAT vs PAT - Full Arabic course الكورس الجديد ٢٠٢٥",
                    "videoId": "qdhPqcGGP2U"
                },
                {
                    "position": 5,
                    "title": "5- Router vs Switch - Full Arabic course الكورس الجديد ٢٠٢٥",
                    "videoId": "oiwvEq_xHdg"
                },
                {
                    "position": 6,
                    "title": "6- Firewall vs IPS - CCNA Arabic الكورس الجديد",
                    "videoId": "uya9rhMfFmU"
                },
                {
                    "position": 7,
                    "title": "7-TCP vs UDP - CCNA Arabic الكورس الجديد",
                    "videoId": "qv9wPbf7DNg"
                },
                {
                    "position": 8,
                    "title": "8-LAN, WAN, Unicast, Broadcast & Multicast - CCNA Arabic الكورس الجديد",
                    "videoId": "LPZJ0L2r31c"
                },
                {
                    "position": 9,
                    "title": "9- DHCP, DNS & ARP - CCNA Arabic الكورس الجديد",
                    "videoId": "OxRnsVaoI38"
                },
                {
                    "position": 10,
                    "title": "10- Static Routing - CCNA Arabic الكورس الجديد",
                    "videoId": "qp2R8E5dFD0"
                },
                {
                    "position": 11,
                    "title": "11- Static Route lab - Full CCNA Arabic الكورس الجديد",
                    "videoId": "xCOV5cnw0XQ"
                },
                {
                    "position": 12,
                    "title": "12- Ping, Traceroute & Best Path Selection Lab - CCNA Arabic الكورس الجديد",
                    "videoId": "c09JadRHJ-8"
                },
                {
                    "position": 13,
                    "title": "13- Default Route & Router Memory - CCNA Arabic الكورس الجديد",
                    "videoId": "E48ENvbVnng"
                },
                {
                    "position": 14,
                    "title": "14- OSPF Routing - CCNA Arabic الكورس الجديد",
                    "videoId": "UPtjhDSwa-k"
                },
                {
                    "position": 15,
                    "title": "15- OSPF Lab - CCNA Arabic الكورس الجديد",
                    "videoId": "HzOpPEsXl9o"
                },
                {
                    "position": 16,
                    "title": "16- Switching, VLAN, Access & Trunk - CCNA Arabic الكورس الجديد",
                    "videoId": "ox1mii0Ox8I"
                },
                {
                    "position": 17,
                    "title": "17-Switching STP, Etherchannel, HSRP, Intervlan - CCNA Arabic الكورس الجديد",
                    "videoId": "wG6lTqumR-4"
                },
                {
                    "position": 18,
                    "title": "18-BPDU Guard, BPDU Filter, Root Guard & Loop Guard - CCNA Arabic الكورس الجديد",
                    "videoId": "LyYLMQiXIaw"
                },
                {
                    "position": 19,
                    "title": "19-Switching Full LAB - CCNA Arabic الكورس الجديد",
                    "videoId": "-3bhk5_K1Ko"
                },
                {
                    "position": 20,
                    "title": "20-Security- CIA, AAA, PortSecurity, IPSEC, Access-list, DHCP snooping CCNA Arabic الكورس الجديد",
                    "videoId": "2ZGxf6IGovs"
                },
                {
                    "position": 21,
                    "title": "21-SSH, SNMP, Syslog, NTP, QOS - CCNA Arabic الكورس الجديد",
                    "videoId": "nRhu5Rh6xk4"
                },
                {
                    "position": 22,
                    "title": "22-SSH LAB & Physical layer - CCNA Arabic الكورس الجديد",
                    "videoId": "QXDXx8MC-fc"
                },
                {
                    "position": 23,
                    "title": "23- DHCP & NAT Lab- CCNA Arabic ��لكورس الجديد",
                    "videoId": "Qyd05qxi7gg"
                },
                {
                    "position": 24,
                    "title": "24-IPv6 full with lab- CCNA Arabic الكورس الجديد",
                    "videoId": "kKVgXWc_tWk"
                },
                {
                    "position": 25,
                    "title": "25-SDN, Automation & Cloud - CCNA Arabic الكورس الجديد",
                    "videoId": "UYUvoXzbWdI"
                },
                {
                    "position": 26,
                    "title": "26-VRF, Virtualization & Containers - Full Arabic course الكورس الجديد ٢٠٢٥",
                    "videoId": "srRGotXGFZc"
                },
                {
                    "position": 27,
                    "title": "27-Wireless LAN, APs & WLC - CCNA Arabic الكورس الجديد",
                    "videoId": "b4ErAk1TB2Q"
                }
            ]
        },

        // ========== LINUX ADMINISTRATION ==========
        {
            id: 'linux-admin',
            title: 'Linux Administration',
            titleAr: 'إدارة نظام Linux',
            description: 'كورس شامل في إدارة أنظمة Linux',
            descriptionEn: 'Complete Linux system administration course',
            category: 'linux',
            level: 'beginner',
            playlistId: 'PLLlr6jKKdyK0Cc3Bm-3kFutfwIgMlgcT9',
            channel: 'Linux Academy',
            thumbnail: 'EIjr6HSTJss',
            totalVideos: 40,
            videos: [
                {
                    "position": 1,
                    "title": "01-#Linux Administration (Intro and Linux History) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "EIjr6HSTJss"
                },
                {
                    "position": 2,
                    "title": "02-#Linux Administration (Linux Distributions - download Debian) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "8X3GFkZS4Fs"
                },
                {
                    "position": 3,
                    "title": "03-#Linux Administration (Install Rocky Linux on VMWare Workstation) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "RLMdH1KA1w4"
                },
                {
                    "position": 4,
                    "title": "04-#Linux Administration (Install Debian on VMWare Workstation) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "f8nogA5NkfM"
                },
                {
                    "position": 5,
                    "title": "05-#Linux Administration (Accessing Shell - Terminal and Switch TTY) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "2RlfrM-44Gk"
                },
                {
                    "position": 6,
                    "title": "06-#Linux Administration (date -  cal - whoami -  su- pwd - clear) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "Krbx540F-vA"
                },
                {
                    "position": 7,
                    "title": "07-#Linux Administration (Linux File System Hierarchy) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "IloSMIEl4fQ"
                },
                {
                    "position": 8,
                    "title": "08-#Linux Administration (Navigation, absolute path - relative path) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "urr8t0Lbu7Y"
                },
                {
                    "position": 9,
                    "title": "09-#Linux Administration (Command options, arguments, touch, cat) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "GHX2Tep04g8"
                },
                {
                    "position": 10,
                    "title": "10-#Linux Administration (copy, move file and directory) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "eqITrOHzHvE"
                },
                {
                    "position": 11,
                    "title": "11-#Linux Administration (Rename, Remove, Command Shortcuts) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "W-crw98uIvc"
                },
                {
                    "position": 12,
                    "title": "12-#Linux Administration (Describe Users and Groups Concepts) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "zDMq-6JMEV8"
                },
                {
                    "position": 13,
                    "title": "13-#Linux Administration (Gain Superuser Access) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "D7zkfxnkb-o"
                },
                {
                    "position": 14,
                    "title": "14-#Linux Administration (Create users from Command Line) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "P8fgk6qAxY0"
                },
                {
                    "position": 15,
                    "title": "15-#Linux Administration (Lecture 15) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "XMs31az7CLE"
                },
                {
                    "position": 16,
                    "title": "16-#Linux Administration (Manage local groups) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "8eArfH24yFI"
                },
                {
                    "position": 17,
                    "title": "17-#Linux Administration (Shadow file format) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "Cbtu0T1ySEw"
                },
                {
                    "position": 18,
                    "title": "18-#Linux Administration (Configure Password Aging) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "DCWoOXMqkG8"
                },
                {
                    "position": 19,
                    "title": "19-#Linux Administration (Linux File System Permissions) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "F9ob8TtHIv0"
                },
                {
                    "position": 20,
                    "title": "20-#Linux Administration (Change Permissions) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "4ukFDu_CTXw"
                },
                {
                    "position": 21,
                    "title": "21-#Linux Administration ( Change Permission With Octal Method) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "l5cm7Oy7mnU"
                },
                {
                    "position": 22,
                    "title": "22-#Linux Administration (Change User or Group Ownership) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "qiLzsIwedXI"
                },
                {
                    "position": 23,
                    "title": "23-#Linux Administration (Special permissions and umask Part 1) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "2Fdg3PVGgfc"
                },
                {
                    "position": 24,
                    "title": "24-#Linux Administration (Special permissions and umask Part 2) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "CjnFz7GiaKY"
                },
                {
                    "position": 25,
                    "title": "25-#Linux Administration (help, man pages, info pages) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "WHuByINYNCY"
                },
                {
                    "position": 26,
                    "title": "26-#Linux Administration (searching files and directories, locate) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "nPxc6JVXv38"
                },
                {
                    "position": 27,
                    "title": "27-#Linux Administration (Searching using find) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "5fPT1j9ugLE"
                },
                {
                    "position": 28,
                    "title": "28-#Linux Administration (Rredirection, standard in, standard out) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "FKqdojH3mho"
                },
                {
                    "position": 29,
                    "title": "29-#Linux Administration (Edit text file using vim) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "z7ocHCexX-Q"
                },
                {
                    "position": 30,
                    "title": "30-#Linux Administration (Compressing and Archiving) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "A-R1Q2tXO_U"
                },
                {
                    "position": 31,
                    "title": "31-#Linux Administration (Inodes and Soft link and Hard link) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "48Swq42R0O4"
                },
                {
                    "position": 32,
                    "title": "32-#Linux Administration (Monitor and Manage Linux Processes Part 1) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "8SygIa2xXWs"
                },
                {
                    "position": 33,
                    "title": "33-#Linux Administration (Monitor and Manage Linux Processes Part 2) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "StWWKrFIZ04"
                },
                {
                    "position": 34,
                    "title": "34-#Linux Administration (Linux Boot Process, and Control Services) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "cTD1o3kwmXE"
                },
                {
                    "position": 35,
                    "title": "35-#Linux Administration (Manage Network, Network Manager) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "8KxEVK8Nvgk"
                },
                {
                    "position": 36,
                    "title": "36-#Linux Administration (Diffie Hellman, Configure and Secure SSH) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "xVDxCf8DFjA"
                },
                {
                    "position": 37,
                    "title": "37-#Linux Administration (Analyze and Store Logs - rsyslog) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "7TRdiCtl3Lc"
                },
                {
                    "position": 38,
                    "title": "38-#Linux Administration (Analyze and Store Logs  Systemd journald) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "D9hkYopRMxg"
                },
                {
                    "position": 39,
                    "title": "39-#Linux Administration (difference between Packages and scripts) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "7j7DBLn5XrM"
                },
                {
                    "position": 40,
                    "title": "40-#Linux Administration (Debian Package Manager - apt) By Eng-Mohamed Tanany | Arabic",
                    "videoId": "2eLsXT6HyPo"
                }
            ]
        },

        // ========== POWERSHELL FOR PENTESTERS ==========
        {
            id: 'powershell-pentest',
            title: 'PowerShell for Penetration Testers',
            titleAr: 'PowerShell لمختبري الاختراق',
            description: 'تعلم PowerShell للاختراق والأتمتة',
            descriptionEn: 'Learn PowerShell for pentesting and automation',
            category: 'linux',
            level: 'intermediate',
            playlistId: 'PLLlr6jKKdyK12Gna1Q5SylK7YZjO7HG7s',
            channel: 'Hacking Academy',
            thumbnail: 'E8dp8IMKNWI',
            totalVideos: 12,
            videos: [
                {
                    "position": 1,
                    "title": "01-PowerShell for Penetration Testers (Introduction) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "E8dp8IMKNWI"
                },
                {
                    "position": 2,
                    "title": "02-PowerShell for Penetration Testers (Intro to PowerShell Cmdlet) Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "WLvFCgTsNx0"
                },
                {
                    "position": 3,
                    "title": "03-PowerShell for Penetration Testers (PowerShell Cmdlets 1) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "ah3E1zDzEbo"
                },
                {
                    "position": 4,
                    "title": "04-PowerShell for Penetration Testers (PowerShell Cmdlets 2) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "3BdojfWG9_U"
                },
                {
                    "position": 5,
                    "title": "05-PowerShell for Penetration Testers (Lecture 5) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "8fmXwVG13vw"
                },
                {
                    "position": 6,
                    "title": "06-PowerShell for Penetration Testers (Variables and Data Types) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "WekItymobPI"
                },
                {
                    "position": 7,
                    "title": "07-PowerShell for Penetration Testers (Lecture 7) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "q0hOALU_Exc"
                },
                {
                    "position": 8,
                    "title": "08-PowerShell for Penetration Testers (Operators in PowerShell) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "oMIyF9-4iVU"
                },
                {
                    "position": 9,
                    "title": "09-PowerShell for Penetration Testers (Logical Operators) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "GUBRgR-l9Yg"
                },
                {
                    "position": 10,
                    "title": "10-PowerShell for Penetration Testers (Redirection - Split) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "HKW84zkiOyc"
                },
                {
                    "position": 11,
                    "title": "11-PowerShell for Penetration Testers (Conditional Statements) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "Br6r3GzJJG4"
                },
                {
                    "position": 12,
                    "title": "12-PowerShell for Penetration Testers (Switch Statement) By Eng-Mostafa Abd ElSalam | Arabic",
                    "videoId": "G4qHxuFEAe0"
                },
                {
                    "position": 13,
                    "title": "Private video",
                    "videoId": "Q-Y81jrEqFo"
                },
                {
                    "position": 14,
                    "title": "Private video",
                    "videoId": "GaPg2dyo6lc"
                },
                {
                    "position": 15,
                    "title": "Private video",
                    "videoId": "kqr5E58a8WA"
                }
            ]
        },

        // ========== CTF COURSE ==========
        {
            id: 'ctf-course',
            title: 'CTF Course - Capture The Flag',
            titleAr: 'كورس CTF - التحديات الأمنية',
            description: 'تعلم حل تحديات CTF من المبتدئ للمحترف',
            descriptionEn: 'Learn to solve CTF challenges from beginner to expert',
            category: 'ctf',
            level: 'intermediate',
            playlistId: 'PLdxfDCLPISTTSCRZyUXvW6shfNyt0wbKA',
            channel: 'CTF Academy',
            thumbnail: 'eO6cLnOty10',
            totalVideos: 39,
            videos: [
                {
                    "position": 1,
                    "title": "#1  CTF course - Learn cyber security in Arabic -- Introduction",
                    "videoId": "eO6cLnOty10"
                },
                {
                    "position": 2,
                    "title": "#2  CTF course - Learn cyber security in Arabic -- Forensics 101 CTFLearn",
                    "videoId": "tQ0CMTT3wa0"
                },
                {
                    "position": 3,
                    "title": "#3 CTF course - Learn cyber Security in Arabic  -- Taking ls challenge CTFlearn",
                    "videoId": "Gf83TRatH2Y"
                },
                {
                    "position": 4,
                    "title": "#4 CTF course - Learn cyber Security in Arabic  --  07601 challenge CTFlearn",
                    "videoId": "9pDPZ2fDdFA"
                },
                {
                    "position": 5,
                    "title": "#5 CTF course - Learn cyber Security in Arabic  --  POST practice challenge CTFlearn",
                    "videoId": "muIEj7g5DXg"
                },
                {
                    "position": 6,
                    "title": "#6 CTF course - Learn cyber Security in Arabic  --  Android Reverse engineering challenge CTFlearn",
                    "videoId": "4fP6KMkpX0o"
                },
                {
                    "position": 7,
                    "title": "#7 CTF course - Learn cyber Security in Arabic  -- TUX forensics challenge CTFlearn",
                    "videoId": "-b0n_jpbkks"
                },
                {
                    "position": 8,
                    "title": "#8 CTF course - Learn cyber Security in Arabic  -- Lazy Game Binary challenge CTFlearn",
                    "videoId": "qxUp49WefWo"
                },
                {
                    "position": 9,
                    "title": "#9 CTF course - Learn cyber Security in Arabic  -- Where can My robot go challenge CTFlearn",
                    "videoId": "xyb6CqopHOE"
                },
                {
                    "position": 10,
                    "title": "#10 CTF course - Learn cyber Security in Arabic  -- WOW so META forensics challenge CTFlearn",
                    "videoId": "QUJLPrZhETg"
                },
                {
                    "position": 11,
                    "title": "#11 CTF course - Learn cyber Security in Arabic  -- binwalk forensics challenge CTFlearn",
                    "videoId": "PoHVOwIMK1s"
                },
                {
                    "position": 12,
                    "title": "Learn reverse engineering and binary exploitation in Arabic (CTF بالعربي)",
                    "videoId": "naqI6PqozyY"
                },
                {
                    "position": 13,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (Easy access challenge)",
                    "videoId": "SJCwqrPUuHE"
                },
                {
                    "position": 14,
                    "title": "SQL injection Basics course in Arabic - CTF شرح بالعربي",
                    "videoId": "hMg20i4qE5c"
                },
                {
                    "position": 15,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (This is Sparta challenge)",
                    "videoId": "vu8Q-N8R-go"
                },
                {
                    "position": 16,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (hide data challenge)",
                    "videoId": "4iX6YwyoUzQ"
                },
                {
                    "position": 17,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (crack the hash challenge)",
                    "videoId": "S2ZfUtWJ4-w"
                },
                {
                    "position": 18,
                    "title": "#1 Understand RSA encryption in Arabic for CTF players --  CTF بالعربي",
                    "videoId": "e7st-f611fI"
                },
                {
                    "position": 19,
                    "title": "#2 decrypting RSA using python in Arabic -- RACTF 2020 -- Really simple algorithm",
                    "videoId": "e8si14OoDAY"
                },
                {
                    "position": 20,
                    "title": "#3 decrypting RSA without knowing the factors in Arabic -- CTF بالعربي",
                    "videoId": "wWM-GDCfAAA"
                },
                {
                    "position": 21,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (Cheers web challenge) شرح بالعربي",
                    "videoId": "WJFcJorPyvM"
                },
                {
                    "position": 22,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (Dark project web challenge)",
                    "videoId": "VDrIFgsW2s8"
                },
                {
                    "position": 23,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (Postbase crypto challenge)",
                    "videoId": "SeCCgwvZv68"
                },
                {
                    "position": 24,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (RSA101 crypto challenge)",
                    "videoId": "sJbYjl9mRYs"
                },
                {
                    "position": 25,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (cool name effect web challenge)",
                    "videoId": "5yCnjuDPnng"
                },
                {
                    "position": 26,
                    "title": "CyberTalents challenges explained -- Learn CTF in Arabic (encrypted database web challenge) شرح",
                    "videoId": "R5e0wgI1epo"
                },
                {
                    "position": 27,
                    "title": "#0 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x00  CTF بالعربي",
                    "videoId": "GJwZp_ORFdE"
                },
                {
                    "position": 28,
                    "title": "#1 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x01 CTF بالعربي",
                    "videoId": "BCQaiaro_og"
                },
                {
                    "position": 29,
                    "title": "#2 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x02 CTF بالعربي",
                    "videoId": "uf3XOaK5uZE"
                },
                {
                    "position": 30,
                    "title": "#3 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x03  CTF بالعربي",
                    "videoId": "S5SizZN2KQU"
                },
                {
                    "position": 31,
                    "title": "#4 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x04 CTF شرح بالعربي",
                    "videoId": "WKHJ30x5pPo"
                },
                {
                    "position": 32,
                    "title": "#5 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x05  CTF شرح بالعربي",
                    "videoId": "DY0giEYcFcA"
                },
                {
                    "position": 33,
                    "title": "#1 exploiting basic cross-site scripting vulnerability in Arabic -- CTF شرح بالعربي",
                    "videoId": "Wm41qITeTCE"
                },
                {
                    "position": 34,
                    "title": "#2 using JavaScript attributes to exploit XSS vulnerability in Arabic -- CTF شرح بالعربي",
                    "videoId": "MjUKo2tLx_8"
                },
                {
                    "position": 35,
                    "title": "#3 learn how source code flaws lead to XSS vulnerability in Arabic --CTF شرح بالعربي",
                    "videoId": "hCIz6XYGDYM"
                },
                {
                    "position": 36,
                    "title": "#1 warm up -- cross-site scripting XSS exploitation (alf.nu alert 1 to win)",
                    "videoId": "1evTnQGa44c"
                },
                {
                    "position": 37,
                    "title": "#6 Learn Reverse engineering in Arabic By solving Crackmes -- Crackme 0x06  CTF بالعربي",
                    "videoId": "VniSd_dVwPA"
                },
                {
                    "position": 38,
                    "title": "#0 CTF Roadmap for beginners in Arabic - Watch till the end - CTF بالعربي للمبتدئين",
                    "videoId": "bDfZ-LA0ZkA"
                },
                {
                    "position": 39,
                    "title": "practicing with base64 and morse code - PicoCTF 2019 - Cryptography",
                    "videoId": "y1hodnvObHo"
                }
            ]
        },

        // ========== PTS - PENETRATION TESTING STUDENT ==========
        {
            id: 'pts-course',
            title: 'PTS - Penetration Testing Student',
            titleAr: 'PTS - اختبار الاختراق للطلاب',
            description: 'كورس تحضيري لشهادة PTS',
            descriptionEn: 'Preparatory course for PTS certification',
            category: 'certs',
            level: 'beginner',
            playlistId: 'PLxfR7vYuDV2VctHrrq7hC2H3DQ4iW3m1N',
            channel: 'eLearnSecurity',
            thumbnail: 'snH9NTE4BoI',
            totalVideos: 20,
            videos: [
                {
                    "position": 1,
                    "title": "Learn PTS In Arabic #01 - Introduction and What is PTS? [بالعربي]",
                    "videoId": "snH9NTE4BoI"
                },
                {
                    "position": 2,
                    "title": "Learn PTS In Arabic #02  LABS PTS FREE [ بالعربي]",
                    "videoId": "mM4wFoWrxhY"
                },
                {
                    "position": 3,
                    "title": "[بالعربي] Learn PTS In Arabic #03  Installing our Penetration Testing Lab OS",
                    "videoId": "tXz45MuZLwc"
                },
                {
                    "position": 4,
                    "title": "[بالعربي] Learn PTS In Arabic #04  Basic command kali linux",
                    "videoId": "16myZH0Tuv4"
                },
                {
                    "position": 5,
                    "title": "[ بالعربي ] Learn PTS In Arabic #05  Web Basic-Burpsuite part 1",
                    "videoId": "qDrrplEsEiA"
                },
                {
                    "position": 6,
                    "title": "Learn PTS In Arabic #06 -Web Basic - Burp Suite part 2  [بالعربي]",
                    "videoId": "-O0BiS4zESs"
                },
                {
                    "position": 7,
                    "title": "[ بالعربي ] Learn PTS In Arabic #07  Web Basic-Burp Suite (foxy proxy) part 3",
                    "videoId": "7mwQLFrWJPM"
                },
                {
                    "position": 8,
                    "title": "Learn PTS In Arabic #08  Web Basic -Burp Suite (CTF) part 4",
                    "videoId": "Sf0OJITevPo"
                },
                {
                    "position": 9,
                    "title": "Learn PTS In Arabic #09 Footprinting and Scanning and Vulnerability Assessments part 1",
                    "videoId": "BRHnNUdNdTE"
                },
                {
                    "position": 10,
                    "title": "Learn PTS In Arabic #10 Footprinting and Scanning and Vulnerability Assessments (nmap) part 2",
                    "videoId": "Hl4D80qG2s4"
                },
                {
                    "position": 11,
                    "title": "Learn PTS In Arabic #11 Footprinting and Scanning and Vulnerability Assessments (Nessus)  part 3",
                    "videoId": "TiHE6gl144o"
                },
                {
                    "position": 12,
                    "title": "(بالعربي )Learn PTS In Arabic #13  System Attack  part 1",
                    "videoId": "sYX_luq-UXc"
                },
                {
                    "position": 13,
                    "title": "Learn PTS In Arabic #14  System Attack  part 2",
                    "videoId": "ZOlJp4Wbeic"
                },
                {
                    "position": 14,
                    "title": "Learn PTS In Arabic #12 Footprinting and Scanning and Vulnerability Assessments (Metasploit)  part 4",
                    "videoId": "QHDAr6sVH_M"
                },
                {
                    "position": 15,
                    "title": "Learn PTS In Arabic #15  System Attack  part 3",
                    "videoId": "-SWiVH8IeOo"
                },
                {
                    "position": 16,
                    "title": "Learn PTS In Arabic #16-Network Attack",
                    "videoId": "dmD5Pz3bDyw"
                },
                {
                    "position": 17,
                    "title": "Learn PTS In Arabic #17 - Web Attack part 1",
                    "videoId": "zJHNfBK1Skc"
                },
                {
                    "position": 18,
                    "title": "Learn PTS In Arabic #18  Web Attack XSS part 2",
                    "videoId": "rTWEXSCTLeY"
                },
                {
                    "position": 19,
                    "title": "Learn PTS In Arabic #19 - Web Attack (SQL Injection) part 3",
                    "videoId": "uSg5mJfl270"
                },
                {
                    "position": 20,
                    "title": "Learn PTS In Arabic #20 - Web Attack (BurpSuite-brute force) part 4",
                    "videoId": "JwwS3IdI-7E"
                }
            ]
        },

        // ========== SECURITY+ ==========
        {
            id: 'security-plus',
            title: 'CompTIA Security+ (SY0-601)',
            titleAr: 'شهادة Security+ من CompTIA',
            description: 'كورس التحضير لشهادة Security+',
            descriptionEn: 'Security+ certification prep course',
            category: 'certs',
            level: 'beginner',
            playlistId: 'PLky4bd7_03m8o1NB0j96OsxZs0KcKlgMO',
            channel: 'CompTIA Academy',
            thumbnail: 'dyKg_bQOXfU',
            totalVideos: 52,
            videos: [
                {
                    "position": 1,
                    "title": "00- Security+ (SY0-601) Course Introduction -  عربي",
                    "videoId": "dyKg_bQOXfU"
                },
                {
                    "position": 2,
                    "title": "01- Comparing Security Roles and Security Controls",
                    "videoId": "H_u72hlzyoE"
                },
                {
                    "position": 3,
                    "title": "02- Explaining Threat Actors and Threat Intelligence",
                    "videoId": "PQSF_1cWMCk"
                },
                {
                    "position": 4,
                    "title": "03.1- Performing Security Assessments - Part 1",
                    "videoId": "Z6sxhcyJ8Kc"
                },
                {
                    "position": 5,
                    "title": "03.2- Performing Security Assessments - Part 2 (Exploring the Lab Environment Lab)",
                    "videoId": "NFTVFOubAUg"
                },
                {
                    "position": 6,
                    "title": "03.3- Performing Security Assessments - Part 3 (Scanning and Identifying Network Nodes Lab)",
                    "videoId": "vyaBoVd_Zj8"
                },
                {
                    "position": 7,
                    "title": "03.4- Performing Security Assessments - Part 4",
                    "videoId": "IfUGpBZbBkQ"
                },
                {
                    "position": 8,
                    "title": "03.5- Performing Security Assessments - Part 5 (Intercepting and Interpreting Network Traffic Lab)",
                    "videoId": "0eWWS5g0KHU"
                },
                {
                    "position": 9,
                    "title": "03.6- Performing Security Assessments - Part 6",
                    "videoId": "q8kzykuxWpk"
                },
                {
                    "position": 10,
                    "title": "03.7- Performing Security Assessments - Part 7 ( Credentialed Vulnerability Scan Lab)",
                    "videoId": "nAZjbj0nq8A"
                },
                {
                    "position": 11,
                    "title": "04.1- Identifying Social Engineering and Malware - Part 1",
                    "videoId": "5bwzteyoUsU"
                },
                {
                    "position": 12,
                    "title": "04.2- Identifying Social Engineering and Malware - Part 2",
                    "videoId": "f-pgjZzid-o"
                },
                {
                    "position": 13,
                    "title": "04.3- Identifying Social Engineering and Malware - Part 3 (Malware-based Backdoor Lab)",
                    "videoId": "r69MX51XzEQ"
                },
                {
                    "position": 14,
                    "title": "05- Summarizing Basic Cryptographic Concepts",
                    "videoId": "3eZjVNCpyDU"
                },
                {
                    "position": 15,
                    "title": "06.1- Implementing Public Key Infrastructure - Part 1",
                    "videoId": "q1rLVrMFbcY"
                },
                {
                    "position": 16,
                    "title": "06.2- Implementing Public Key Infrastructure - Part 2 (Managing the Lifecycle of a Certificate Lab)",
                    "videoId": "9RUzcNv37Wk"
                },
                {
                    "position": 17,
                    "title": "07.1- Implementing Authentication Controls - Part 1",
                    "videoId": "ftIpzBeBIqw"
                },
                {
                    "position": 18,
                    "title": "07.2- Implementing Authentication Controls - Part 2 (Password Cracking Lab)",
                    "videoId": "GJAN7oU0kKA"
                },
                {
                    "position": 19,
                    "title": "07.3- Implementing Authentication Controls - Part 3 (Managing Centralized Authentication Lab)",
                    "videoId": "sls2j_jTrHc"
                },
                {
                    "position": 20,
                    "title": "08.1- Implementing Identity and Account Management Controls - Part 1",
                    "videoId": "0v51j2EmzFY"
                },
                {
                    "position": 21,
                    "title": "08.2- Implementing Identity and Account Management Controls - Part 2 (Access Controls Lab)",
                    "videoId": "xy0GPXg-yss"
                },
                {
                    "position": 22,
                    "title": "08.3- Implementing Identity and Account Management Controls - Part 3 (Auditing Policies Lab)",
                    "videoId": "6A0cUYVbdK0"
                },
                {
                    "position": 23,
                    "title": "08.4- Implementing Identity and Account Management Controls - Part 4 (Access Controls in Linux Lab)",
                    "videoId": "AEAEmsywsbE"
                },
                {
                    "position": 24,
                    "title": "09.1- Implementing Secure Network Designs - Part 1",
                    "videoId": "0uZ_lxxYrxk"
                },
                {
                    "position": 25,
                    "title": "09.2- Implementing Secure Network Designs - Part 2",
                    "videoId": "Gmjuy6m5_9s"
                },
                {
                    "position": 26,
                    "title": "09.3- Implementing Secure Network Designs - Part 3 (Implementing a Secure Network Design Lab)",
                    "videoId": "X24w8M7SLCE"
                },
                {
                    "position": 27,
                    "title": "10.1- Implementing Network Security Appliances - Part 1",
                    "videoId": "LwUHbTfjOZU"
                },
                {
                    "position": 28,
                    "title": "10.2- Implementing Network Security Appliances - Part 2 (Configuring a Firewall Lab)",
                    "videoId": "LyxLUdrsLuU"
                },
                {
                    "position": 29,
                    "title": "10.3- Implementing Network Security Appliances - Part 3 (Intrusion Detection System Lab)",
                    "videoId": "yh3AfEmD4MQ"
                },
                {
                    "position": 30,
                    "title": "11.1- Implementing Secure Network Protocols  - Part 1",
                    "videoId": "6oCNbljA7Zo"
                },
                {
                    "position": 31,
                    "title": "11.2 - Implementing Secure Network Protocols - Part 2 (Secure Network Addressing Services Lab)",
                    "videoId": "xzz2cxzTtMw"
                },
                {
                    "position": 32,
                    "title": "11.3- Implementing Secure Network Protocols - Part 3 (Implementing a Virtual Private Network Lab)",
                    "videoId": "fx6OsgNl7Bk"
                },
                {
                    "position": 33,
                    "title": "11.4- Implementing Secure Network Protocols - Part 4 (Implementing a Secure SSH Server Lab)",
                    "videoId": "kVUK3SSHl88"
                },
                {
                    "position": 34,
                    "title": "12.1- Implementing Host Security Solutions - Part 1",
                    "videoId": "EToNpewImjs"
                },
                {
                    "position": 35,
                    "title": "12.2- Implementing Host Security Solutions - Part 2 (Implementing Endpoint Protection Lab)",
                    "videoId": "DG5kfBgT7r4"
                },
                {
                    "position": 36,
                    "title": "13- Implementing Secure Mobile Solutions",
                    "videoId": "T1JXEG85r40"
                },
                {
                    "position": 37,
                    "title": "14.1- Summarizing Secure Application Concepts - Part 1",
                    "videoId": "cs4lKSsgvkY"
                },
                {
                    "position": 38,
                    "title": "14.2- Summarizing Secure Application Concepts - Part 2 (Application Attack Indicators Lab)",
                    "videoId": "BxvjYO3G4Ew"
                },
                {
                    "position": 39,
                    "title": "14.3- Summarizing Secure Application Concepts - Part 3 (Identifying a Browser Attack Lab)",
                    "videoId": "xPLSITWpx3w"
                },
                {
                    "position": 40,
                    "title": "14.4- Summarizing Secure Application Concepts - Part 4 (Implementing PowerShell Security Lab)",
                    "videoId": "hevbOcH0S8s"
                },
                {
                    "position": 41,
                    "title": "14.5- Summarizing Secure Application Concepts - Part 5 (Identifying Malicious Code Lab)",
                    "videoId": "8Ad2-DIJRpc"
                },
                {
                    "position": 42,
                    "title": "15- Implementing Secure Cloud Solutions",
                    "videoId": "GrEINwEZSm0"
                },
                {
                    "position": 43,
                    "title": "16- Explaining Data Privacy and Protection Concepts",
                    "videoId": "QLbr-I6DP4Y"
                },
                {
                    "position": 44,
                    "title": "17.1- Performing Incident Response - Part 1",
                    "videoId": "hn4XGgsc6nI"
                },
                {
                    "position": 45,
                    "title": "17.2- Performing Incident Response - Part 2 (Managing Data Sources for Incident Response Lab)",
                    "videoId": "xd6HXJfSKJc"
                },
                {
                    "position": 46,
                    "title": "17.3- Performing Incident Response - Part 3 (Configuring Mitigation Controls Lab)",
                    "videoId": "jr6RNQZaihg"
                },
                {
                    "position": 47,
                    "title": "18.1- Explaining Digital Forensics - Part 1",
                    "videoId": "VRlldq5snmM"
                },
                {
                    "position": 48,
                    "title": "18.2- Explaining Digital Forensics - Part 2 (Acquiring Digital Forensics Evidence Lab)",
                    "videoId": "8QCMP-nYW-A"
                },
                {
                    "position": 49,
                    "title": "19- Summarizing Risk Management Concepts",
                    "videoId": "piw75hexagQ"
                },
                {
                    "position": 50,
                    "title": "20.1- Implementing Cybersecurity Resilience - Part 1",
                    "videoId": "QT4xFnC1Mh4"
                }
            ]
        },

        // ========== ETHICAL HACKING (ARABIC) ==========
        {
            id: 'ethical-hacking-ar',
            title: 'دورة القرصنة الأخلاقية',
            titleAr: 'دورة القرصنة الأخلاقية الشاملة',
            description: 'دورة شاملة في الهكر الأخلاقي باللغة العربية',
            descriptionEn: 'Complete Ethical Hacking course in Arabic',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLMuAdKgHarVrcZCqzJFdNlTiKz66U19Xk',
            channel: 'Hacking Academy',
            thumbnail: 'IyxgtWKtzQw',
            totalVideos: 72,
            videos: [
                {
                    "position": 1,
                    "title": "#01- دورة القرصنة الاخلاقية  - Install kali linux And  important Tools (Ethical Hacking Course)",
                    "videoId": "IyxgtWKtzQw"
                },
                {
                    "position": 2,
                    "title": "Downloading VMware 2025 | VMware 2025 تنزيل",
                    "videoId": "bcL6apHMxOM"
                },
                {
                    "position": 3,
                    "title": "#02 - دورة القرصنة الاخلاقية  -  Kali Overview | (Ethical Hacking Course)",
                    "videoId": "d_zfVMM-tQQ"
                },
                {
                    "position": 4,
                    "title": "#03 - دورة القرصنه الاخلاقيه - Sudo Overview | (Ethical Hacking Course)",
                    "videoId": "wrh-7AtXy60"
                },
                {
                    "position": 5,
                    "title": "#04 - دورة القرصنه الاخلاقيه - Navigating the File system (Ethical Hacking Course)",
                    "videoId": "jwVyzE7S9iY"
                },
                {
                    "position": 6,
                    "title": "#05 - دورة القرصنه الاخلاقيه | Users & Privileges (Ethical Hacking Course)",
                    "videoId": "hROttpGKuwM"
                },
                {
                    "position": 7,
                    "title": "# - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Networking 3 hours",
                    "videoId": "GVJshZrKV5k"
                },
                {
                    "position": 8,
                    "title": "#06 - دورة القرصنه الاخلاقيه | Common Network Commands (Ethical Hacking Course)",
                    "videoId": "Fi_Yu8Faf2U"
                },
                {
                    "position": 9,
                    "title": "#07 - دورة القرصنه الاخلاقيه | Viewing, Creating, & Editing Files (Ethical Hacking Course)",
                    "videoId": "r0F-c_-q9fo"
                },
                {
                    "position": 10,
                    "title": "#08 - دورة القرصنه الاخلاقيه  | Starting And Stopping Services (Ethical Hacking Course)",
                    "videoId": "kc4wQ88ULOU"
                },
                {
                    "position": 11,
                    "title": "#09 - دورة القرصنه الاخلاقيه | Installing and Updating Tools (Ethical Hacking Course)",
                    "videoId": "SAI-K8gFpvk"
                },
                {
                    "position": 12,
                    "title": "#10 - دورة القرصنه الاخلاقيه | Bash Scripting (Ethical Hacking Course)",
                    "videoId": "Uht505yY9Mg"
                },
                {
                    "position": 13,
                    "title": "#11 تعلم بايثون | Introduction | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "c-nar4iyTaw"
                },
                {
                    "position": 14,
                    "title": "#12  تعلم بايثون | Strings | كورس ��لاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "8JUyMh8FsG8"
                },
                {
                    "position": 15,
                    "title": "#13 تعلم البايثون | Math | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "UoXCn-MvMHw"
                },
                {
                    "position": 16,
                    "title": "#14 تعلم بايثون | Variables And Methods | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "nU2dH33Mxqs"
                },
                {
                    "position": 17,
                    "title": "#15 تعلم بايثون | Functions | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "i-E7Esu0WgE"
                },
                {
                    "position": 18,
                    "title": "#16 تعلم بايثون | Boolean Expressions | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "3iZ8USG9gJI"
                },
                {
                    "position": 19,
                    "title": "#17 تعلم بايثون | Conditional Statements | كورس الاختراق الاخلاقي (Ethical Hacking Course)",
                    "videoId": "soyY0PXhemg"
                },
                {
                    "position": 20,
                    "title": "#18 تعلم بايثون | Lists | كورس الاختراق الاخلاقي (Ethical Hacking course)",
                    "videoId": "8bmT2MBHRqU"
                },
                {
                    "position": 21,
                    "title": "#19 تعلم بايثون | Tuples | كورس الاختراق الاخلاقي",
                    "videoId": "VLUQMZBLreY"
                },
                {
                    "position": 22,
                    "title": "#20 تعلم بايثون | Looping | كورس الاختراق الاخلاقي",
                    "videoId": "pJcQWHMZ8po"
                },
                {
                    "position": 23,
                    "title": "#21 تعلم بايثون | Advanced Strings | كورس الاختراق الاخلاقي",
                    "videoId": "DTRJvKQojFY"
                },
                {
                    "position": 24,
                    "title": "#22 تعلم بايثون | Dictionaries | كورس الاختراق الاخلاقي",
                    "videoId": "8dFcHEbc0VE"
                },
                {
                    "position": 25,
                    "title": "#23 تعلم بايثون | Importing Modules |  كورس الاختراق الاخلاقي",
                    "videoId": "5sS3RD3Fxa4"
                },
                {
                    "position": 26,
                    "title": "#24 تعلم بايثون | SOCKETS |  كورس الاختراق الاخلاقي",
                    "videoId": "YvSuFqT6UX8"
                },
                {
                    "position": 27,
                    "title": "#25 تعلم بايثون | Building A Port Scanner |  كورس الاختراق الاخلاقي",
                    "videoId": "gdm_xr4WiJw"
                },
                {
                    "position": 28,
                    "title": "#26 تعلم بايثون | User Input - Building Calculator |  كورس الاختراق الاخلاقي",
                    "videoId": "QWtyopBPcYw"
                },
                {
                    "position": 29,
                    "title": "#27 تعلم بايثون |  Reading and Writing Files |  كورس الاختراق الاخلاقي",
                    "videoId": "JWNvpRDOtVg"
                },
                {
                    "position": 30,
                    "title": "#28 تعلم بايثون | Classes And Objects |  كورس الاختراق الاخلاقي",
                    "videoId": "zhJfVl1QLF4"
                },
                {
                    "position": 31,
                    "title": "#29 تعلم بايثون | Building Product Budget Tool |  كورس الاختراق الاخلاقي",
                    "videoId": "8TKa_xkYPdI"
                },
                {
                    "position": 32,
                    "title": "#30 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Five Stages of Ethical Hacking",
                    "videoId": "gnvpkoTQwnE"
                },
                {
                    "position": 33,
                    "title": "#31 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Passive Recon Overview",
                    "videoId": "YnRmH2_CKqg"
                },
                {
                    "position": 34,
                    "title": "#32 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Identifying Our Target",
                    "videoId": "0NlU0m12ysI"
                },
                {
                    "position": 35,
                    "title": "#33 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Discovering Email Addresses",
                    "videoId": "E1RG1CjGW4M"
                },
                {
                    "position": 36,
                    "title": "#35 - دورة الاختراق الاخلاق��  (Ethical Hacking Course)  | SubDomains",
                    "videoId": "9B8wuX_g07M"
                },
                {
                    "position": 37,
                    "title": "#36 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Identifying Website Technologies",
                    "videoId": "vg1qoiq58X8"
                },
                {
                    "position": 38,
                    "title": "#37 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Burp Suite",
                    "videoId": "QowK4vajS2c"
                },
                {
                    "position": 39,
                    "title": "#38 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Google Fu & Utilizing Social Media",
                    "videoId": "uPHwxq4PCnk"
                },
                {
                    "position": 40,
                    "title": "#39 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Install Kioptrix Machine & Scan With Nmap",
                    "videoId": "XVb3J-SleJI"
                },
                {
                    "position": 41,
                    "title": "#40 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Enumerating HTTP/HTTPS (Part 1)",
                    "videoId": "Gkcq5G0gYYY"
                },
                {
                    "position": 42,
                    "title": "#41 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Enumerating HTTP/HTTPS (Part 2)",
                    "videoId": "lT9GK1xRquU"
                },
                {
                    "position": 43,
                    "title": "#42 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Enumerating SMB",
                    "videoId": "RfcJMhVH6rQ"
                },
                {
                    "position": 44,
                    "title": "#43 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Enumerating SSH",
                    "videoId": "4zfj9OsG8vE"
                },
                {
                    "position": 45,
                    "title": "#44 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Researching Potential Vulnerabilities",
                    "videoId": "nPhiJXJDYeI"
                },
                {
                    "position": 46,
                    "title": "#45 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Organize Notes",
                    "videoId": "PJDTFz21J20"
                },
                {
                    "position": 47,
                    "title": "#46 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Scanning With Nessus (part 1)",
                    "videoId": "p9YVgYEGVto"
                },
                {
                    "position": 48,
                    "title": "#47 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Scanning With Nessus (part 2)",
                    "videoId": "Rowzzjka7a0"
                },
                {
                    "position": 49,
                    "title": "#48 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Reverse Shells Vs Bind Shells",
                    "videoId": "RSsp02cYHqY"
                },
                {
                    "position": 50,
                    "title": "#49 - دورة الاختراق الاخلاقي  (Ethical Hacking Course)  | Staged Vs Non-Staged Payloads",
                    "videoId": "fAYywKItlRY"
                }
            ]
        },

        // ========== PHP SECURITY ==========
        {
            id: 'php-security',
            title: 'PHP for Web Security',
            titleAr: 'PHP لأمن الويب',
            description: 'تعلم PHP من منظور أمني',
            descriptionEn: 'Learn PHP from a security perspective',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PL7mt2FDjAkPfuS1Vt4AAqGAjHEuKEFAPB',
            channel: 'PHP Security',
            thumbnail: 'RbuLNDobNv8',
            totalVideos: 28,
            videos: [
                {
                    "position": 1,
                    "title": "احترف حمايه المواقع درس 1# مقدمه الي الكورس",
                    "videoId": "RbuLNDobNv8"
                },
                {
                    "position": 2,
                    "title": "احترف حمايه المواقع درس 2# بعض المفاهيم  الامنيه التي يجب معرفتها",
                    "videoId": "lgZDTqSRjxs"
                },
                {
                    "position": 3,
                    "title": "احترف حمايه المواقع درس #3 بعض المفاهيم الامنيه التي يجب معرفتها الجزء الثاني",
                    "videoId": "ig04Q5nIdxM"
                },
                {
                    "position": 4,
                    "title": "احترف حمايه المواقع درس #4 Laravel Security",
                    "videoId": "DT8wUzqAJJs"
                },
                {
                    "position": 5,
                    "title": "احترف حمايه المواقع درس #5 :  ما هو ال SQL injection",
                    "videoId": "8H8VS54I-tk"
                },
                {
                    "position": 6,
                    "title": "SQL Injection part 2",
                    "videoId": "HwOmTPrQfDg"
                },
                {
                    "position": 7,
                    "title": "SQL injection part 3",
                    "videoId": "jtL3O88JfvU"
                },
                {
                    "position": 8,
                    "title": "XSS Part 1",
                    "videoId": "7ZYctg_qk70"
                },
                {
                    "position": 9,
                    "title": "XSS part 2",
                    "videoId": "jEjwyTgGMS8"
                },
                {
                    "position": 10,
                    "title": "XSS part 3",
                    "videoId": "OF-nFJDKRAY"
                },
                {
                    "position": 11,
                    "title": "XSS  part 4",
                    "videoId": "dTFjVXskQqU"
                },
                {
                    "position": 12,
                    "title": "XSS  part 5",
                    "videoId": "LiQyNv3wmmc"
                },
                {
                    "position": 13,
                    "title": "XSS part 6",
                    "videoId": "GIZgMsAetgQ"
                },
                {
                    "position": 14,
                    "title": "Cookies theft",
                    "videoId": "LkCFkNbKyxY"
                },
                {
                    "position": 15,
                    "title": "Weak Hashing",
                    "videoId": "s3dXPzqaKXM"
                },
                {
                    "position": 16,
                    "title": "File Inclusion Part 1",
                    "videoId": "yWeAkC0MjFE"
                },
                {
                    "position": 17,
                    "title": "File Inclusion Part 2",
                    "videoId": "hjgpqisPe2c"
                },
                {
                    "position": 18,
                    "title": "Input Validation part 1",
                    "videoId": "g3Qubg3OntE"
                },
                {
                    "position": 19,
                    "title": "Input Validation part 2",
                    "videoId": "1RwLM7tRWOQ"
                },
                {
                    "position": 20,
                    "title": "Remote Code Execution",
                    "videoId": "5Jl3ApClGTc"
                },
                {
                    "position": 21,
                    "title": "File upload part 1",
                    "videoId": "e8lqV7ZgsR8"
                },
                {
                    "position": 22,
                    "title": "File upload part 2",
                    "videoId": "NhP4b0ipRuc"
                },
                {
                    "position": 23,
                    "title": "Captcha",
                    "videoId": "3uHVy6ZFyzM"
                },
                {
                    "position": 24,
                    "title": "Pro PHP Security IN Arabic : #21 Session Hijacking Part 1",
                    "videoId": "Ozit4sgLP_Q"
                },
                {
                    "position": 25,
                    "title": "Session Hijacking part 2",
                    "videoId": "Xys3HCAssT0"
                },
                {
                    "position": 26,
                    "title": "Session Hijacking part 3",
                    "videoId": "aL8x8RjaMHk"
                },
                {
                    "position": 27,
                    "title": "CSRF part 1",
                    "videoId": "lNIfwSfNBtU"
                },
                {
                    "position": 28,
                    "title": "CSRF part 2",
                    "videoId": "_eFEho_z8nI"
                }
            ]
        },

        // ========== CRYPTOGRAPHY ==========
        {
            id: 'basic-cryptography',
            title: 'Basic Cryptography',
            titleAr: 'أساسيات التشفير',
            description: 'مقدمة في علم التشفير وتطبيقاته الأمنية',
            descriptionEn: 'Introduction to cryptography and security applications',
            category: 'network',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSCjBdDL3LcTJD1F46Sjy_zy',
            channel: 'Crypto Academy',
            thumbnail: '9wgEO3_GxcQ',
            totalVideos: 4,
            videos: [
                {
                    "position": 1,
                    "title": "Basic Cryptography | Hashing (Arabic)",
                    "videoId": "9wgEO3_GxcQ"
                },
                {
                    "position": 2,
                    "title": "Basic Cryptography | Symmetric Encryption (Arabic)",
                    "videoId": "7a8AxImXGXQ"
                },
                {
                    "position": 3,
                    "title": "Basic Cryptography | Asymmetric Encryption (Arabic)",
                    "videoId": "pvN_sUviFwU"
                },
                {
                    "position": 4,
                    "title": "Basic Cryptography | Encoding (Arabic)",
                    "videoId": "R28nvK8kjOA"
                }
            ]
        },

        // ========== WEB TECHNOLOGY ==========
        {
            id: 'web-technology',
            title: 'Web Technology Fundamentals',
            titleAr: 'أساسيات تقنيات الويب',
            description: 'فهم تقنيات الويب الأساسية للأمان',
            descriptionEn: 'Understanding web technologies for security',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSCnfKDKYGNhkZB0iq0QVJ8D',
            channel: 'Web Academy',
            thumbnail: 'CVFi9v2gmBk',
            totalVideos: 3,
            videos: [
                {
                    "position": 1,
                    "title": "Web Technologies | Part 1 (Arabic)",
                    "videoId": "CVFi9v2gmBk"
                },
                {
                    "position": 2,
                    "title": "Web Technologies | Part 2 (Arabic)",
                    "videoId": "tGpwEHTvcFE"
                },
                {
                    "position": 3,
                    "title": "Web Technologies | Part 3 (Arabic)",
                    "videoId": "_hwGoXc7trc"
                }
            ]
        },

        // ========== FREECODECAMP COURSES ==========
        {
            id: 'freecodecamp-network-pentest',
            title: 'Full Ethical Hacking Course - Network Penetration Testing',
            titleAr: 'كورس الاختراق الأخلاقي الكامل - اختبار اختراق الشبكات',
            description: 'تعلم اختبار اختراق الشبكات والاختراق الأخلاقي - دورة كاملة للمبتدئين من freeCodeCamp',
            descriptionEn: 'Learn network penetration testing / ethical hacking in this full tutorial course for beginners',
            category: 'network',
            level: 'beginner',
            playlistId: 'single-video-3Kq1MIfTWCE',
            channel: 'freeCodeCamp.org',
            thumbnail: '3Kq1MIfTWCE',
            totalVideos: 1,
            videos: [
                { position: 1, title: 'Full Ethical Hacking Course - Network Penetration Testing for Beginners (2019)', videoId: '3Kq1MIfTWCE' }
            ]
        },
        {
            id: 'freecodecamp-webapp-pentest',
            title: 'Ethical Hacking 101: Web App Penetration Testing',
            titleAr: 'الاختراق الأخلاقي 101: اختبار اختراق تطبيقات الويب',
            description: 'تعلم اختبار اختراق تطبيقات الويب من المبتدئ للمتقدم - دورة كاملة للمبتدئين',
            descriptionEn: 'Learn web application penetration testing from beginner to advanced - full course for beginners',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'single-video-2_lswM1S264',
            channel: 'freeCodeCamp.org',
            thumbnail: '2_lswM1S264',
            totalVideos: 1,
            videos: [
                { position: 1, title: 'Ethical Hacking 101: Web App Penetration Testing - a full course for beginners', videoId: '2_lswM1S264' }
            ]
        },

        // ========== OSCP+ 2025 (MrLimbo) ==========
        {
            id: 'mrlimbo-oscp-2025',
            title: 'OSCP+ 2025',
            titleAr: 'كورس OSCP+ 2025',
            description: 'التحضير الكامل لشهادة OSCP+ لعام 2025 - من الصفر للاحتراف',
            descriptionEn: 'Complete OSCP+ 2025 preparation course - from zero to professional',
            category: 'certs',
            level: 'advanced',
            playlistId: 'PL5dZpxpUkHPM0HMefFCFjGeLAwyty4LYm',
            channel: 'MrLimbo',
            thumbnail: 'VAV0Z8GGT9g',
            totalVideos: 59,
            videos: [
                { position: 1, title: 'سلسلة OSCP رجعت… بس النسخة الجديدة!', videoId: 'VAV0Z8GGT9g' },
                { position: 2, title: '00 OSCP VS OSCP+ 2025', videoId: '7gXkwAmLCzI' },
                { position: 3, title: '01 Introduction - OSCP 2025', videoId: 'nZjAtv6-RMg' },
                { position: 4, title: '02 Defense in Depth - OSCP 2025', videoId: 'jsJ_3-QSJs4' },
                { position: 5, title: '03 Backups - OSCP 2025', videoId: 'CJ7ZPXFN35g' },
                { position: 6, title: '04 Kali Linux - OSCP 2025', videoId: 'f8P9Kle3RN4' },
                { position: 7, title: '05 Kali Basics - OSCP 2025', videoId: 'x9Y_AcvVBS8' },
                { position: 8, title: '06 Bash Environment - OSCP 2025', videoId: 'AIN9-NXGCAc' },
                { position: 9, title: '07 Piping & Redirection - OSCP 2025', videoId: 'RlMCy_9tgFc' },
                { position: 10, title: '08 Text Searching & Manipulation - OSCP 2025', videoId: 'v0k6skhEyng' },
                { position: 11, title: '09 Managing Processes - OSCP 2025', videoId: '0ToPhYnzvZ0' },
                { position: 12, title: '10 Downloading Files - OSCP 2025', videoId: 'HrUrJbGl2xE' },
                { position: 13, title: '11 Netcat - OSCP 2025', videoId: 'vuzqFa9nt8A' },
                { position: 14, title: '12 Socat - OSCP 2025', videoId: 'SxXcD6mdODE' },
                { position: 15, title: '13 PowerShell - OSCP 2025', videoId: 'f2I0lDVAihA' },
                { position: 16, title: '14 Powercat - OSCP 2025', videoId: 'oaoDAlAtVzg' },
                { position: 17, title: '15 Sniffing Traffic - OSCP 2025', videoId: '5Uk1eHDPyU4' },
                { position: 18, title: '16 Bash Scripting - OSCP 2025', videoId: 'un-59bjnHV8' },
                { position: 19, title: '17 IF, Loops & Functions - OSCP 2025', videoId: '-uh9PvAyW4E' },
                { position: 20, title: '18 Scripting Exercise - OSCP 2025', videoId: 'ONBd5Lt5wgk' },
                { position: 21, title: '19 Scripting Exercise - OSCP 2025', videoId: 'hQNau05UA8I' },
                { position: 22, title: '20 Passive Recon - OSCP 2025', videoId: 'TFiPtu24obQ' },
                { position: 23, title: '21 Website & User Recon - OSCP 2025', videoId: 'EZnnNpo5KN0' },
                { position: 24, title: '22 Google Hacking Database GHDB - OSCP', videoId: 'Vr3s8G0j-nA' },
                { position: 25, title: '23 Whois & Subdomain Enumeration - OSCP 2025', videoId: 'B2alGkaMSws' },
                { position: 26, title: '24 OpenSource Code Enumeration - OSCP 2025', videoId: 'QVoQll_v53k' },
                { position: 27, title: '25 OSINT & Maltego - OSCP 2025', videoId: '3ymLB6wzHBE' },
                { position: 28, title: '26 DNS Enumeration - OSCP 2025', videoId: 't-5gTUSH0bs' },
                { position: 29, title: '27 TCP/UDP Port Scanning - OSCP 2025', videoId: '3MxktYjd43Q' },
                { position: 30, title: '28 Nmap TCP/UDP - OSCP 2025', videoId: 'WrYDpJLZCRI' },
                { position: 31, title: '29 Nmap NSE, OS & Service Enumeration - OSCP', videoId: 'A3aSsYuQdOQ' },
                { position: 32, title: '30 SMB & Netbios Enumeration - OSCP 2025', videoId: 'ncWZFimW0ac' },
                { position: 33, title: '31 NFS, SMTP & SNMP Enumeration - OSCP 2025', videoId: 'Lby0HEgJSZs' },
                { position: 34, title: '32 Vulnerability Scanning with Nessus - OSCP', videoId: 'SRRoopL8ddE' },
                { position: 35, title: '33 Fuzzing Directories - OSCP 2025', videoId: 'T3zEtuHCwtU' },
                { position: 36, title: '34 Nikto - OSCP 2025', videoId: '4pIcFMVj5aI' },
                { position: 37, title: '35 Burp Suite - OSCP 2025', videoId: 'NGk8fRj9bR4' },
                { position: 38, title: '36 Cross Site Scripting XSS - OSCP 2025', videoId: 'iROtl6ZiCTw' },
                { position: 39, title: '37 Local and Remote File Inclusion - OSCP 2025', videoId: 'fzuwTLSKEX0' },
                { position: 40, title: '38 Introduction to SQL injection - OSCP 2025', videoId: 'ikh2xPLienA' },
                { position: 41, title: '39 Exploit SQL injection - OSCP 2025', videoId: '7ySuq1u18cM' },
                { position: 42, title: '40 SQL injection Dumping all database - OSCP 2025', videoId: 'BT56Tc5vSmY' },
                { position: 43, title: '41 SQLmap - OSCP 2025', videoId: '071_BS7dxv4' },
                { position: 44, title: '42 Client-Side Attacks - OSCP 2025', videoId: 'wHU7ZhT41k8' },
                { position: 45, title: '43 Locating Public Exploit - OSCP 2025', videoId: 'TYZzZoMQx2Q' },
                { position: 46, title: '44 Fixing Exploits - OSCP 2025', videoId: 'CRoaHcpAkHM' },
                { position: 47, title: '45 File Transfer - OSCP 2025', videoId: 'WZx_iAIe5vs' },
                { position: 48, title: '46 Antivirus Evasion - OSCP 2025', videoId: 'D5k_Z65aNl8' },
                { position: 49, title: '47 Privilege Escalation - OSCP', videoId: '-UldpdHpRTk' },
                { position: 50, title: '48 Windows Privilege Escalation - OSCP 2025', videoId: '1-vBCWeDL-w' },
                { position: 51, title: '49 Linux Privilege Escalation - OSCP 2025', videoId: 'BB_5CN4gJ98' },
                { position: 52, title: '50 Password Attacks - OSCP 2025', videoId: 'nzmPiNNZ1YI' },
                { position: 53, title: '51 Port Redirection and Tunneling - OSCP 2025', videoId: 'rLppe_DDAMg' },
                { position: 54, title: '52 Active Directory Attacks - OSCP 2025', videoId: 'T8q2UxuhVmw' },
                { position: 55, title: '53 AD Kerberos Authentication - OSCP 2025', videoId: 'FJ_au3ynarU' },
                { position: 56, title: '54 Active Directory - Full Control - OSCP 2025', videoId: 'SfDB8zwXm5I' },
                { position: 57, title: '55 The Metasploit Framework - OSCP 2025', videoId: 'd5bpEysSMkE' },
                { position: 58, title: '56 Powershell Empire - OSCP 2025', videoId: '6KiuK4sdz7k' },
                { position: 59, title: '60 Documentation and Reporting - OSCP 2025', videoId: 'n6KEUh4iG0A' }
            ]
        },

        // ========== INTRODUCTION TO RED TEAMING ==========
        {
            id: 'red-teaming-intro',
            title: 'Introduction To Red Teaming',
            titleAr: 'مقدمة في Red Teaming',
            description: 'تعلم أساسيات Red Teaming والاختبار المتقدم - تقنيات الهجوم والمحاكاة',
            descriptionEn: 'Learn Red Teaming fundamentals - attack techniques and adversary emulation',
            category: 'network',
            level: 'advanced',
            playlistId: 'PLBf0hzazHTGMjSlPmJ73Cydh9vCqxukCu',
            channel: 'HackerSploit',
            thumbnail: 'rHxYZwMz-DY',
            totalVideos: 35,
            videos: [
                { position: 1, title: 'Introduction To Red Teaming', videoId: 'rHxYZwMz-DY' },
                { position: 2, title: 'Red Team Frameworks & Methodologies', videoId: 'UafxorrS3mQ' },
                { position: 3, title: 'Introduction To The MITRE ATT&CK Framework', videoId: 'LCec9K0aAkM' },
                { position: 4, title: 'Mapping APT TTPs With MITRE ATT&CK Navigator', videoId: 'hN_r3JW6xsY' },
                { position: 5, title: 'Planning Red Team Operations | Scope, ROE & Reporting', videoId: 'usDt-s2sACI' },
                { position: 6, title: 'Red Team Reconnaissance Techniques', videoId: 'BWaGnsRirtU' },
                { position: 7, title: 'Red Team Adversary Emulation With Caldera', videoId: 'EIHLXWnK1Dw' },
                { position: 8, title: 'Windows Red Team Exploitation Techniques', videoId: 'dRebw65X5eQ' },
                { position: 9, title: 'Windows Red Team - Dynamic Shellcode Injection', videoId: '6xexyQwG7SY' },
                { position: 10, title: 'Windows Red Team Privilege Escalation Techniques', videoId: 'vPTbWnCZ0sg' },
                { position: 11, title: 'Windows Red Team Credential Access | Mimikatz & WCE', videoId: 'wH2kE527cwQ' },
                { position: 12, title: 'Windows Red Team Persistence Techniques', videoId: '7h_5BJHIpnU' },
                { position: 13, title: 'Windows Red Team Lateral Movement - PsExec & RDP', videoId: 'QGkmlsvjMYI' },
                { position: 14, title: 'PowerShell Empire Complete Tutorial For Beginners', videoId: '52xkWbDMUUM' },
                { position: 15, title: 'Post Exploitation With Empire And LaZagne', videoId: 'AwFyiFOXrd0' },
                { position: 16, title: 'Post Exploitation With Windows Credentials Editor', videoId: 'u0RppDmw1So' },
                { position: 17, title: 'Pivoting And Persistence With Armitage', videoId: 'kRXVQdzRbzI' },
                { position: 18, title: 'Linux Red Team Exploitation Techniques', videoId: '_1QnyKTqQ6w' },
                { position: 19, title: 'Linux Red Team Privilege Escalation Techniques', videoId: 'w2rElXYV2Fs' },
                { position: 20, title: 'Linux Red Team Persistence Techniques', videoId: 'tNJs8CFj_B8' },
                { position: 21, title: 'Linux Defense Evasion - Apache2 Rootkit', videoId: 'ChgqGBwl8NQ' },
                { position: 22, title: 'Linux Red Team Defense Evasion - Hiding Processes', videoId: 'GT-ClZAi6rE' },
                { position: 23, title: 'Using an Apache2 Rootkit for Stealth', videoId: 'Ra2altDvPYI' },
                { position: 24, title: 'Introduction To Adversary Emulation', videoId: 'CUMhiSdOSkY' },
                { position: 25, title: 'Introduction To Advanced Persistent Threats (APTs)', videoId: 'CwSG5sa0Nao' },
                { position: 26, title: 'Developing An Adversary Emulation Plan', videoId: '1N49x1EWw7s' },
                { position: 27, title: 'FIN6 Adversary Emulation Plan (TTPs & Tooling)', videoId: 'qEfk44G4zFM' },
                { position: 28, title: 'Emulating FIN6 - Gaining Initial Access', videoId: 'hUBRnh5dzrI' },
                { position: 29, title: 'Offensive VBA 0x1 - Your First Macro', videoId: 'jGy7_NusjuQ' },
                { position: 30, title: 'Offensive VBA 0x2 - Program & Command Execution', videoId: 'ogbrNZ3SCRY' },
                { position: 31, title: 'Offensive VBA 0x3 - Developing PowerShell Droppers', videoId: 'ot3053UxJOc' },
                { position: 32, title: 'Offensive VBA 0x4 - Reverse Shell Macro with Powercat', videoId: '0W3Z3Br56XM' },
                { position: 33, title: 'SECRET to Embedding Metasploit Payloads in VBA', videoId: 'Q1wQuHw5JKI' },
                { position: 34, title: 'Emulating FIN6 - Active Directory Enumeration', videoId: 'Iwxmscx3XXc' },
                { position: 35, title: 'How FIN6 Exfiltrates Files Over FTP', videoId: 'SbZ7JUII-SQ' }
            ]
        },

        // ========== REVERSE ENGINEERING (Arabic) ==========
        {
            id: 'reverse-engineering-ar',
            title: 'Reverse Engineering Course',
            titleAr: 'كورس الهندسة العكسية',
            description: 'تعلم الهندسة العكسية وتحليل البرامج - من الأساسيات للمتقدم',
            descriptionEn: 'Learn reverse engineering and software analysis - from basics to advanced',
            category: 'ctf',
            level: 'advanced',
            playlistId: 'PLzp8FYHY3OhJnblFFZFCmbOl42Jd0hmRs',
            channel: 'Arabic Security',
            thumbnail: 'B-ig97fNEO4',
            totalVideos: 42,
            videos: [
                { position: 1, title: 'اساسيات الهندسة العكسية Reverse Engineering gdb - ghidra', videoId: 'B-ig97fNEO4' },
                { position: 2, title: 'عمل كيجين بالهندسة العكسية reverse engineering simple keygen', videoId: 'fHJR3WXfERo' },
                { position: 3, title: 'حل تحدي بسيط Stack Buffer over flow', videoId: 'cV1kBZWYpSM' },
                { position: 4, title: 'طريقة قراءة محتويات الرجيسترز في الهندسة العكسية GDB', videoId: 'J9_i8CMNopA' },
                { position: 5, title: 'هندسة عكسية تخطي الفترة التجريبية وانشاء سيريال', videoId: 'jt8dvLZX5iw' },
                { position: 6, title: 'هندسة عكسية شرح تخطي الـ anti-debugger', videoId: '1dpM7pDUSPo' },
                { position: 7, title: 'حل تحدي بالهندسة العكسية وشرح الxoring', videoId: 'C9rX3_W0AF4' },
                { position: 8, title: 'طريقة عمل هندسة عكسية للالعاب المبنية على godot', videoId: 'bTMIS1TAx6c' },
                { position: 9, title: 'شرح استغلال سترنق فورمات وكتابة اكسبلويت', videoId: 'DVqCnHDYMTo' },
                { position: 10, title: 'هندسة عكسية لبرامج الدوت نت', videoId: 'gViubT1c3oQ' },
                { position: 11, title: 'عمل هندسة عكسية لالعاب مبنية على محرك يونيتي', videoId: 'k8mxt4ogaSY' },
                { position: 12, title: 'هندسة عكسية - حل تحدي تشفير عن طريق تحليل الكود', videoId: 'QJupXXArJE8' },
                { position: 13, title: 'شرح عمل هندسة عكسية باكثر من طريقة', videoId: 'obrstpGbfOM' },
                { position: 14, title: 'هندسة عكسية , استخراج ومعالجة النصوص برمجياً', videoId: 'tfD4poYgK8Y' },
                { position: 15, title: 'كيف تجيب تحديات ريفيرس وتحلها ؟', videoId: 'wihhhk8QGPU' },
                { position: 16, title: 'شرح الباكرز بشكل نظري وعملي', videoId: 'FdH4qZGOzyg' },
                { position: 17, title: 'تخطي Advanced anti-debugging', videoId: 's8o93CimfPQ' },
                { position: 18, title: 'assembly x64 linux system calls', videoId: 'jNpl3MXVkfs' },
                { position: 19, title: 'كيف تتعلم اساسيات الهندسة العكسية واسيمبلي بالعربي', videoId: 'MisMeruezic' },
                { position: 20, title: 'شرح الشيل كود | كيف تكتب اول شيل كود بسيط', videoId: '7iekgEp3pD0' },
                { position: 21, title: 'كيف المبرمج يسوي برنامج غش في لعبة؟', videoId: 'mWTvYl-4sNo' },
                { position: 22, title: 'مدخل الى الهندسة العكسية للالعاب', videoId: 'emPh3AUSemE' },
                { position: 23, title: 'PicoCTF WinAntiDbg0x300', videoId: 'ytALpqrPAoI' },
                { position: 24, title: 'كيف تشتغل الباكرز وكيف ممكن فكها بشكل يدوي', videoId: 'cQammtCUP5g' },
                { position: 25, title: 'شرح تخطي الفترة التجريبية وكود التفعيل', videoId: '4K10N5OTXwQ' },
                { position: 26, title: 'تفعيل البرامج بأستعمال x64dbg', videoId: 'tiW5obGfDCM' },
                { position: 27, title: 'كيف تفك حماية الـpackers بشكل يدوي', videoId: 'iohGDHvfxeQ' },
                { position: 28, title: 'هل الذكاء الاصطناعي يقدر يسوي هندسة عكسية؟', videoId: '7ePt0sv0_dc' },
                { position: 29, title: 'كيف تتعلم الهندسة العكسية وتحليل البرمجيات الخبيثة', videoId: '4fVZYXqENh0' },
                { position: 30, title: 'كيف تتبع وتحذف نافذة التفعيل المزعجة', videoId: 'GsopIGeOJ08' },
                { position: 31, title: 'Flareon24 1-2 كيف تصحح أخطاء الديكومبايلر', videoId: 'Qb23Di0r3WQ' },
                { position: 32, title: 'اساسيات الهندسة العكسية وحل تحديات الـCTF', videoId: 'zK6gAI1goIQ' },
                { position: 33, title: 'تفكيك كود مشفر على عدة مراحل (Obfuscation)', videoId: 'wJKBa7jDkwQ' },
                { position: 34, title: 'تحليل برنامج كوده يتغير اثناء التشغيل', videoId: 'R44SV6rpzNY' },
                { position: 35, title: 'كيف تسوي هندسة عكسية لبرنامج يغير كوده', videoId: 'Lrf4KZDvQNI' },
                { position: 36, title: 'اسهل طريقة للتلاعب في كود البرنامج اثناء التشغيل', videoId: 'E74hWlgA3l8' },
                { position: 37, title: 'لمحة بسيطة عن تحليل الـVM', videoId: 'Af6jvbJpsV0' },
                { position: 38, title: 'يقدر الذكاء الاصطناعي يحلل مالوير بالكامل؟', videoId: 'xgWsqmjpMKA' },
                { position: 39, title: 'كيف تحل تحديات الهندسة العكسية في الـCTF', videoId: 'y3MT7maXV-c' },
                { position: 40, title: 'محاكاة اسيمبلي شيل كود باستعمال Unicorn', videoId: 'T0uYPu7Wbr0' },
                { position: 41, title: 'كيف تتعامل مع Packers', videoId: 'LoowTK44sag' },
                { position: 42, title: 'شرح الـCalling conventions', videoId: 'amllwuAUyEY' }
            ]
        },

        // ========== معسكر الأمن السيبراني (Abdalla Hijjawe) ==========
        {
            id: 'hijjawe-cybersecurity-bootcamp',
            title: 'Cybersecurity Bootcamp',
            titleAr: 'معسكر الأمن السيبراني',
            description: 'معسكر تدريبي شامل في الأمن السيبراني - من الشبكات للبرمجة للينكس للاختراق',
            descriptionEn: 'Comprehensive cybersecurity bootcamp - networking, programming, Linux, and hacking',
            category: 'network',
            level: 'beginner',
            playlistId: 'PLPE_LivMIWm51WrKEc00auJnn0cxN-pWL',
            channel: 'Abdalla Hijjawe',
            thumbnail: 'HiDKyQYqd4w',
            totalVideos: 101,
            videos: [
                { position: 1, title: 'محاضرة #1 مقدمة الى المعسكر', videoId: 'HiDKyQYqd4w' },
                { position: 2, title: '#2 هو ايه يعني network', videoId: 'svN6ArkenA0' },
                { position: 3, title: '#3 ما هو IP address', videoId: 'eps03HT5vGY' },
                { position: 4, title: '#4 public ip VS private ip', videoId: 'r4lkUFBM1qA' },
                { position: 5, title: '#5 Subnet Mask', videoId: 'q-04bhNv5hQ' },
                { position: 6, title: '#6 امثلة على Subnet Mask', videoId: 'bzLYW29AumI' },
                { position: 7, title: '#7 NAT وانواعها', videoId: '5NKVfZ2IKH0' },
                { position: 8, title: '#8 MAC Address', videoId: 'aweK0ABc-dQ' },
                { position: 9, title: '#9 Casting and Transmission mode', videoId: 'bbZpAn3XczY' },
                { position: 10, title: '#10 OSI && tcp/ip model', videoId: 'oClnAPsoiQs' },
                { position: 11, title: '#11 OSI model (Application & Session & Presentation)', videoId: '3tgBxZ1xynE' },
                { position: 12, title: '#12 OSI model (Transport Layer & TCP Vs UDP)', videoId: 'CN8Rj7PlIXE' },
                { position: 13, title: '#13 OSI model (Network Layer)', videoId: 'NNtE6_utCnA' },
                { position: 14, title: '#14 OSI model (Data && physical layer)', videoId: 'AeShAquxLH4' },
                { position: 15, title: '#15 Socket && Port Number', videoId: 'PLbloEAiXtc' },
                { position: 16, title: '#16 DNS', videoId: 'iR3vb5xEL_o' },
                { position: 17, title: '#17 DHCP', videoId: 'QN_xOv4Wx4M' },
                { position: 18, title: '#18 ARP', videoId: 'NCvLMGwrDbg' },
                { position: 19, title: '#19 network devices (Hub & Switch & Router)', videoId: 'DlrgquunK-Y' },
                { position: 20, title: '#20 VLAN', videoId: 'EoXRHft0Hyk' },
                { position: 21, title: '#21 جدار الحماية Firewall', videoId: 'IQTjLGC7yGo' },
                { position: 22, title: '#22 منطقه منزوعة السلاح DMZ', videoId: '8HHElRbeZw8' },
                { position: 23, title: '#23 VPN', videoId: 'omifx4HuLfI' },
                { position: 24, title: '#24 Http VS Https', videoId: 'nXFStOJjDg8' },
                { position: 25, title: '#25 HTTP Status Code', videoId: 'VwCmLK0PimI' },
                { position: 26, title: '#26 Cookie VS Session', videoId: 'UiBZSPzDvgo' },
                { position: 27, title: '#27 Interpreter vs Compiler', videoId: 'YOGd2yFxN-U' },
                { position: 28, title: '#28 تحميل Dev C++', videoId: 'sFvObbQh7Co' },
                { position: 29, title: '#29 Escape Sequence', videoId: 'rV6grh6IhiM' },
                { position: 30, title: '#30 Variables && Data type', videoId: 'npmPTdRpUSg' },
                { position: 31, title: '#31 Basic Arithmetic', videoId: 'h0_LZkK_NOs' },
                { position: 32, title: '#32 Postfix and Prefix', videoId: 'dvdFpLNkKq8' },
                { position: 33, title: '#33 Variable Scope', videoId: '2Ip6MRIe4Hw' },
                { position: 34, title: '#34 Selection Statement', videoId: 'mm8prkaXw3w' },
                { position: 35, title: '#35 Logical Operators', videoId: 'WRSaTqTH2F4' },
                { position: 36, title: '#36 Selection Statement With Logical Operators', videoId: 'yLmTjXMnGRc' },
                { position: 37, title: '#37 Switch', videoId: 'BsOutu-jHeA' },
                { position: 38, title: '#38 While Loop', videoId: '0MQpmTc0kAk' },
                { position: 39, title: '#39 For Loop', videoId: '8ic7bX40ENM' },
                { position: 40, title: '#40 Do-While Loop', videoId: 'uAbr9CnqVjM' },
                { position: 41, title: '#41 Break and continue + لعبه توقعات', videoId: 'nsHdIoeINHA' },
                { position: 42, title: '#42 Nested Loop', videoId: 'KQc-53oSkAc' },
                { position: 43, title: '#43 Function', videoId: 'pS6dSoLZgMI' },
                { position: 44, title: '#44 Built-in Function (Math)', videoId: '4tdT3a5-u9w' },
                { position: 45, title: '#45 Built-in Function (Algorithms)', videoId: 'LZ9rEIWE5a0' },
                { position: 46, title: '#46 Call By Reference vs Call By Value', videoId: 'm87GSA86-24' },
                { position: 47, title: '#47 Function Recursion', videoId: '8fO1MNk1gJY' },
                { position: 48, title: '#48 Array طرق تعريفها', videoId: 'yJZ7P3VVWWA' },
                { position: 49, title: '#49 Array طرق التعامل معها', videoId: 'Z3rKdIuqV_U' },
                { position: 50, title: '#50 ما هو نظام لينكس linux', videoId: 'ICk74KhCv6M' },
                { position: 51, title: '#51 تثبيت الكالي لينكس', videoId: 'BYtlOs8s4a4' },
                { position: 52, title: '#52 Basic Command part 1', videoId: 'j3KS1G8e_XU' },
                { position: 53, title: '#53 Basic Command part 2', videoId: 'S03YJFufEDI' },
                { position: 54, title: '#54 Relative Path vs Absolute Path', videoId: 'FLgIp3WY2kc' },
                { position: 55, title: '#55 Root User', videoId: 'trzY7I2R7MQ' },
                { position: 56, title: '#56 Basic Command part 3', videoId: 'gYbQCnusYcc' },
                { position: 57, title: '#57 مدير الحزم (APT)', videoId: 'wAJ1468bzQU' },
                { position: 58, title: '#58 الصلاحيات في اللينكس', videoId: 'AgO1UchgL_8' },
                { position: 59, title: '#59 Basic Command part 4', videoId: 'KnmAdAzLAyw' },
                { position: 60, title: '#60 فك الملفات المضغوطه + GitHub', videoId: 'qsaNHwSPnC8' },
                { position: 61, title: '#61 Redirection in Linux', videoId: 'QfJI6DhLFjE' },
                { position: 62, title: '#62 Information security vs Cyber security', videoId: 'HKsX0gIW6go' },
                { position: 63, title: '#63 CIA triad', videoId: 'uYDWLC70sEw' },
                { position: 64, title: '#64 مصطلحات سيبرانيه', videoId: '6-O2RbI7ZWA' },
                { position: 65, title: '#65 انواع ممثلين التهديدات', videoId: 'MozLePTNRpA' },
                { position: 66, title: '#66 مبادئ اساسيه في الدفاع', videoId: 'mvPF-X-UU2k' },
                { position: 67, title: '#67 البرامج الخبيثة والفيروسات', videoId: 'kGnLu43N5vs' },
                { position: 68, title: '#68 Trojan and Ransomware', videoId: 'ZW0qfE_0-Qo' },
                { position: 69, title: '#69 Rootkits', videoId: '1OuZG2RPz3U' },
                { position: 70, title: '#70 Spyware, Key loggers and Adware', videoId: 'lEllSQZwIQ4' },
                { position: 71, title: '#71 Logic Bomb and Backdoor', videoId: 'f7dwdO-Wzxk' },
                { position: 72, title: '#72 الزومبي وهجوم حجب الخدمة DDOS', videoId: 'N54rbj8AbYo' },
                { position: 73, title: '#73 الهندسة الاجتماعية', videoId: 'O0p5nGh_4so' },
                { position: 74, title: '#74 هجوم الرجل في المنتصف', videoId: 'dUQP4AF4wAc' },
                { position: 75, title: '#75 رفع الصلاحيات وهجوم اليوم صفر', videoId: '2BwlgEpQFJU' },
                { position: 76, title: '#76 Cross-Site Scripting (XSS)', videoId: 'Aevfl0urRxk' },
                { position: 77, title: '#77 حقن قواعد البيانات SQL injection', videoId: 'spWiy6Y5eB8' },
                { position: 78, title: '#78 Buffer overflow attack', videoId: 'y-cG7yEwHXw' },
                { position: 79, title: '#79 علم التشفير Cryptography', videoId: 'y-RufZ8_1qA' },
                { position: 80, title: '#80 التشفير المتماثل والغير متماثل', videoId: '0MHtDsyH1Ls' },
                { position: 81, title: '#81 اختبار الاختراق Penetration Testing', videoId: 'Y77Vo5M49kc' },
                { position: 82, title: '#82 جمع المعلومات', videoId: 'YIHfoldZTcw' },
                { position: 83, title: '#83 جمع المعلومات الجزء الثاني', videoId: 'CoUqF_NgkhY' },
                { position: 84, title: '#84 Lab OSINT', videoId: 'bpjc4zX5EjE' },
                { position: 85, title: '#85 Scanning and Fingerprinting', videoId: '9Ivn1wo5W1w' },
                { position: 86, title: '#86 شرح Tryhackme', videoId: '3eNbBEQk8f4' },
                { position: 87, title: '#87 NMAP', videoId: 'PDdQQ9Zav0M' },
                { position: 88, title: '#88 تقييم الثغرات Vulnerability Assessment', videoId: 'h_PMFpu41LM' },
                { position: 89, title: '#89 استغلال الثغرات Exploit', videoId: 'Oqx5CVDPOnQ' },
                { position: 90, title: '#90 هجومات الويب Web Application Attack', videoId: 'rbDZeigyR4s' },
                { position: 91, title: '#91 Gobuster Tool', videoId: 'WUVofe5vAVg' },
                { position: 92, title: '#92 Wireshark Tool', videoId: '2iHHtrKAGLI' },
                { position: 93, title: '#93 John the Ripper Tool', videoId: 'a5sU0i3xvyA' },
                { position: 94, title: '#94 Burp Suite', videoId: '--j1IIjLOFs' },
                { position: 95, title: '#95 هجوم القوة الغاشمة Hydra', videoId: '3Calir6KnQ8' },
                { position: 96, title: '#96 Metasploit Framework', videoId: 'GrGJysotIu4' },
                { position: 97, title: '#97 حل مشين RootMe', videoId: 'o_xhHTbp8fg' },
                { position: 98, title: '#98 استغلال ثغرة في الويندوز 7 Blue', videoId: '8-MRym9nE6A' },
                { position: 99, title: '#99 حل مشين Brooklyn Nine Nine', videoId: '_UXhsOnCmbw' },
                { position: 100, title: '#100 النهاية The Last Dance', videoId: 'k4Ovm-kil_0' },
                { position: 101, title: 'معسكر الامن السيبراني على يوديمي', videoId: 'HCGLYUAM65Q' }
            ]
        },

        // ========== BUG BOUNTY (SYS TECH) ==========
        {
            id: 'systech-bugbounty',
            title: 'Bug Bounty Course',
            titleAr: 'كورس Bug Bounty - اكتشاف ثغرات المواقع',
            description: 'كورس تعلم اكتشاف ثغرات المواقع والـ Bug Bounty',
            descriptionEn: 'Learn to find web vulnerabilities and bug bounty hunting',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLiWBr7sjooxFZNxor5-4ooqRao-JP_ksP',
            channel: 'SYS TECH',
            thumbnail: '5CrrvCFwEJA',
            totalVideos: 12,
            videos: [
                { position: 1, title: 'Source code disclosure via backup files', videoId: '5CrrvCFwEJA' },
                { position: 2, title: 'Information disclosure on debug page', videoId: '1qHdIDzffc4' },
                { position: 3, title: 'Information disclosure in version control', videoId: 'VKFqqv0lM7s' },
                { position: 4, title: 'Information disclosure in error message', videoId: 'Gc-nMTsseEY' },
                { position: 5, title: 'User role controlled by request parameter', videoId: 'h2GAwqYGMM0' },
                { position: 6, title: 'Insecure Direct object reference', videoId: 'ipazCaNNBns' },
                { position: 7, title: 'User role can modified in user profile', videoId: 'BFAOW5m9E0I' },
                { position: 8, title: 'File path traversal Bug', videoId: 'qkM_aRstVNM' },
                { position: 9, title: 'File path traversal cases', videoId: 'a9dSAxOiqB8' },
                { position: 10, title: 'File path traversal automation testing', videoId: 'flW3dbgSUE4' },
                { position: 11, title: 'Cross Site Scripts XSS', videoId: 'wKge8mi8bPk' },
                { position: 12, title: 'Cross Site Scripts DOM XSS', videoId: 'L0ehMNsidy4' }
            ]
        },

        // ========== ACTIVE DIRECTORY 101 (Green Hack) ==========
        {
            id: 'green-hack-ad101',
            title: 'ActiveDirectory-101',
            titleAr: 'أساسيات Active Directory',
            description: 'تعلم أساسيات Active Directory بالعربي - كورس مجاني 100%',
            descriptionEn: 'Learn Active Directory basics in Arabic - 100% free',
            category: 'network',
            level: 'intermediate',
            playlistId: 'PLyyAUp-Erl9WhBzp1ma2NzYQEb1nfQM1t',
            channel: 'Green Hack',
            thumbnail: 'l5jryNnDhjk',
            totalVideos: 33,
            videos: [
                { position: 1, title: 'مقدمة (00)', videoId: 'l5jryNnDhjk' },
                { position: 2, title: 'introduction-1', videoId: 'XhxUK1JnCkE' },
                { position: 3, title: 'introduction-2', videoId: '5oPCp16u4oY' },
                { position: 4, title: 'Authentication Lsass & SAM & NTDS', videoId: '1WKjes03eTw' },
                { position: 5, title: 'Kerberos Authentication TGT', videoId: 'AiViWZ-kaPA' },
                { position: 6, title: 'Kerberos Authentication TGS', videoId: 'XAnkaKZUAEU' },
                { position: 7, title: 'NTLM v2 Authentication', videoId: 'wRlf6UrMiRM' },
                { position: 8, title: 'Authentication VS Authorization / ACL', videoId: 'lQ62fIBQB0Y' },
                { position: 9, title: 'Building the Lab Part-1', videoId: 'Ptafjei0hJg' },
                { position: 10, title: 'Building the Lab Part-2', videoId: 'enKb_oSgEzM' },
                { position: 11, title: 'Building the Lab Part-3', videoId: 'MuGct8zUWlg' },
                { position: 12, title: 'Building the Lab Part-4', videoId: '3zWtbtzvtT4' },
                { position: 13, title: 'GreenADtoolKit', videoId: '6x-dvcyfziI' },
                { position: 14, title: 'AMSI & Execution Policy', videoId: 'oiRTjHZ2NXc' },
                { position: 15, title: 'Manual Enumeration Using net.exe', videoId: 'WJM2afHBBy8' },
                { position: 16, title: 'Manual Enumeration Using LDAP', videoId: 'lj2RxCq2dxw' },
                { position: 17, title: 'Enumeration Using PowerView', videoId: '8tWyqBPuZnQ' },
                { position: 18, title: 'Enumeration Using PsLoggedon', videoId: 'fPAoKAiDq30' },
                { position: 19, title: 'Password attack', videoId: 'MtuOWHS8kmE' },
                { position: 20, title: 'AS REP Roasting', videoId: '76sS2CJZno8' },
                { position: 21, title: 'Kerberoasting (SPN)', videoId: 'Te5JaWjxytU' },
                { position: 22, title: 'Mimikatz', videoId: 'uraVxY0Vgzs' },
                { position: 23, title: 'Pass the Hash [PtH]', videoId: 'ZubtjRx5dSs' },
                { position: 24, title: 'Overpass the Hash', videoId: 'tZw1BJKjD2Y' },
                { position: 25, title: 'Pass the Ticket', videoId: 'kuNfcznAYTw' },
                { position: 26, title: 'Dcsync', videoId: 'mD_5rj05ZvM' },
                { position: 27, title: 'Golden tickets', videoId: 'udpb0-HQ6qU' },
                { position: 28, title: 'Silver Tickets -1', videoId: 'fINOZE6i54s' },
                { position: 29, title: 'Silver Tickets -2', videoId: 'Aj2eZ0RuO4M' },
                { position: 30, title: 'Lateral Movement via WMI', videoId: 'X-Mr7RD-BxY' },
                { position: 31, title: 'Lateral Movement via WinRM', videoId: 'eOdRB4sFar4' },
                { position: 32, title: 'Lateral Movement via DCOM', videoId: '8ren5jfpv8s' },
                { position: 33, title: 'Lateral Movement via Psexec', videoId: 'GYTzM6OeUZA' }
            ]
        },

        // ========== WEB APPLICATION ATTACK BASICS (Green Hack) ==========
        {
            id: 'green-hack-webapp-attacks',
            title: 'Web Application Attack Basics',
            titleAr: 'أساسيات هجمات تطبيقات الويب',
            description: 'تعلم أساسيات هجمات تطبيقات الويب',
            descriptionEn: 'Learn web application attack basics',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLyyAUp-Erl9VfT0e52QaSqJ9dvnxiOLda',
            channel: 'Green Hack',
            thumbnail: '7c6AC0dfQaE',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'What is | Burp Suite', videoId: '7c6AC0dfQaE' },
                { position: 2, title: 'What is | Dirbuster', videoId: '0UP-GKK8FV0' },
                { position: 3, title: 'What is | cookie', videoId: 'TI6_dA6mIWI' },
                { position: 4, title: 'What is | XSS', videoId: 'PIMSE3LtAJM' },
                { position: 5, title: 'What is | XSS (2)', videoId: '_lRL1LxdRzE' }
            ]
        },

        // ========== BURP SUITE (HackerOne) ==========
        {
            id: 'hackerone-burpsuite',
            title: 'Burp Suite Course',
            titleAr: 'كورس Burp Suite من HackerOne',
            description: 'تعلم استخدام Burp Suite من خبراء HackerOne',
            descriptionEn: 'Learn Burp Suite from HackerOne experts',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLxhvVyxYRviajtnHaICLg_ZcY47TpgGjR',
            channel: 'HackerOne',
            thumbnail: 'LSqC9qgEMi0',
            totalVideos: 3,
            videos: [
                { position: 1, title: 'Getting Started With Burp', videoId: 'LSqC9qgEMi0' },
                { position: 2, title: 'Maximizing Burp', videoId: 'bHTxJIC_jGI' },
                { position: 3, title: 'Burp Hacks for Bounty Hunters', videoId: 'boHIjDHGmIo' }
            ]
        },

        // ========== JAVASCRIPT/NODE.JS (Yehia Tech) ==========
        {
            id: 'yehiatech-javascript',
            title: 'JavaScript/Node.js Course (Arabic)',
            titleAr: 'كورس جافاسكريبت و Node.js',
            description: 'كورس جافاسكريبت و Node.js بالعربي',
            descriptionEn: 'JavaScript and Node.js course in Arabic',
            category: 'linux',
            level: 'beginner',
            playlistId: 'PL8q8h6vqfkSXcfaCL_nqsbLkDnodHpBG8',
            channel: 'Yehia Tech يحيى تك',
            thumbnail: '2EAV2cB3FWY',
            totalVideos: 11,
            videos: [
                { position: 1, title: '#0 Intro', videoId: '2EAV2cB3FWY' },
                { position: 2, title: '#1 Variables', videoId: 'ClkIRKlmplY' },
                { position: 3, title: '#2 Arithmetic Operators', videoId: 'XUreKLul1og' },
                { position: 4, title: '#3 Strings', videoId: 'Sr04cTu5abY' },
                { position: 5, title: '#4 Arrays', videoId: 'R16IMAWDGyg' },
                { position: 6, title: '#5 Functions', videoId: 'XhM9px0OFkc' },
                { position: 7, title: '#6 Conditions', videoId: 'GgqCm46vAL8' },
                { position: 8, title: '#7 Switch Case', videoId: 'B-X4hrHtJ58' },
                { position: 9, title: '#8 Objects', videoId: 'ZzEg_BSVN0A' },
                { position: 10, title: '#9 Loops', videoId: 'lRsvuBB8n80' },
                { position: 11, title: '#10 Outro النهاية', videoId: 'SS-HnTEHkss' }
            ]
        },

        // ========== PHP (Yehia Tech) ==========
        {
            id: 'yehiatech-php',
            title: 'PHP for Beginners (Arabic)',
            titleAr: 'كورس PHP للمبتدئين',
            description: 'كورس بي اتش بي للمبتدئين بالعربي',
            descriptionEn: 'PHP for beginners course in Arabic',
            category: 'linux',
            level: 'beginner',
            playlistId: 'PL8q8h6vqfkSUqEs_Ziqoeq_meU-YeWaUA',
            channel: 'Yehia Tech يحيى تك',
            thumbnail: '-cK6d9_FGGc',
            totalVideos: 2,
            videos: [
                { position: 1, title: 'Laravel 12: Vibe Coding with Cursor', videoId: '-cK6d9_FGGc' },
                { position: 2, title: 'كورس شرح بي اتش بي متكامل في 6 ساعات', videoId: 'qmvjwRbtNww' }
            ]
        },

        // ========== CEH - PROFESSIONAL ETHICAL HACKER ==========
        {
            id: 'ceh-mahmoud-atef',
            title: 'Professional Ethical Hacker (CEH)',
            titleAr: 'الهكر الأخلاقي المحترف CEH',
            description: 'دورة CEH كاملة بالعربي - م. محمود عاطف',
            descriptionEn: 'Complete CEH course in Arabic by Eng. Mahmoud Atef',
            category: 'certs',
            level: 'intermediate',
            playlistId: 'PLLlr6jKKdyK39fb-fpv4l_1OKiZG0-p8d',
            channel: 'Eng. Mahmoud Atef',
            thumbnail: 'JzdJQfnFOzc',
            totalVideos: 32,
            videos: [
                { position: 1, title: '01-Setup Lab', videoId: 'JzdJQfnFOzc' },
                { position: 2, title: '02-Introduction Ethical Hacking', videoId: 'ZDLhiyR2ehs' },
                { position: 3, title: '03-Footprinting and Reconnaissance Part 1', videoId: 'bqy2UoqXJNQ' },
                { position: 4, title: '04-Footprinting and Reconnaissance Part 2', videoId: '8H9Ocyz16lY' },
                { position: 5, title: '05-Footprinting and Reconnaissance Part 3', videoId: 'sWlpXzXU2w4' },
                { position: 6, title: '06-Footprinting and Reconnaissance Part 4', videoId: '0GYgzhdEj6s' },
                { position: 7, title: '07-Scanning Methodology Part 1', videoId: 'ciJ1O4chQVk' },
                { position: 8, title: '08-Scanning Methodology Part 2', videoId: 'NlyDS6PVosw' },
                { position: 9, title: '09-Scanning Methodology Part 3', videoId: 'GhVgjBVFpF4' },
                { position: 10, title: '10-Scanning Methodology Part 4', videoId: 'vNtAp7uyGXc' },
                { position: 11, title: '11-Scanning Methodology Part 5', videoId: 'O-u5NDn7GMk' },
                { position: 12, title: '12-Enumeration Methodology', videoId: 'NoIzYU5NM78' },
                { position: 13, title: '13-System Hacking Part 1', videoId: '5yQpSvSMO3U' },
                { position: 14, title: '14-System Hacking Part 2', videoId: 'JXGT5iOBKg8' },
                { position: 15, title: '15-System Hacking Part 3', videoId: 'MYrAXzr0sKk' },
                { position: 16, title: '16-System Hacking Part 4', videoId: '40hj1QgZUmc' },
                { position: 17, title: '17-Trojans Backdoors Viruses Worms 1', videoId: 'AEHUE2lePtE' },
                { position: 18, title: '18-Trojans Backdoors Viruses Worms 2', videoId: 'AU0hMO6sLoc' },
                { position: 19, title: '19-Trojans Backdoors Viruses Worms 3', videoId: 'u46gFOqb8gQ' },
                { position: 20, title: '20-Trojans Backdoors Viruses Worms 4', videoId: 'kDLbf0Iuv4M' },
                { position: 21, title: '21-Sniffers and Phishing Part 1', videoId: 'pdUSYzRzeAY' },
                { position: 22, title: '22-Sniffers and Phishing Part 2', videoId: 'saJKgo5bXcM' },
                { position: 23, title: '23-Wireless Hacking Part 1', videoId: 'haitQc64Mq8' },
                { position: 24, title: '24-Wireless Hacking Part 2', videoId: 'pSYUzVlCKfc' },
                { position: 25, title: '25-Hacking Web Servers Part 1', videoId: 'bMlhwZfCLXc' },
                { position: 26, title: '26-Hacking Web Servers Part 2', videoId: 'ZbuMTLtwcHo' },
                { position: 27, title: '27-Hacking Web Servers Part 3', videoId: 'SVa_NUBSe2A' },
                { position: 28, title: '28-Hacking Web Servers Part 4', videoId: 'fT1-1sFssE8' },
                { position: 29, title: '29-Hacking Web Servers Part 5', videoId: 'hG_gUl3OKTw' },
                { position: 30, title: '30-Windows and Linux Hacking Part 1', videoId: 'gaK8SQ4Pabk' },
                { position: 31, title: '31-Windows and Linux Hacking Part 2', videoId: 'zXzbe5Ay9Hc' },
                { position: 32, title: '32-Windows and Linux Hacking Part 3', videoId: 'v5u89HiG9Hg' }
            ]
        },

        // ========== SQL CRASH COURSE (Cyber Guy) ==========
        {
            id: 'cyberguy-sql',
            title: 'SQL Crash Course (Arabic)',
            titleAr: 'كورس SQL السريع',
            description: 'كورس SQL السريع بالعربي',
            descriptionEn: 'SQL crash course in Arabic',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSAhaQZzkR1uyNsMOezEChMA',
            channel: 'Cyber Guy',
            thumbnail: '0YAYnFOcgaA',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'SQL Crash Course Episode 1', videoId: '0YAYnFOcgaA' },
                { position: 2, title: 'SQL Crash Course Episode 2', videoId: 'OWm2GVif-zc' },
                { position: 3, title: 'SQL Crash Course Episode 3', videoId: 'kQ0yEVBEKuE' },
                { position: 4, title: 'SQL Crash Course Episode 4', videoId: 'LRYFPhAEYH4' },
                { position: 5, title: 'SQL Crash Course Episode 5', videoId: 'JfHttZwb0_o' }
            ]
        },

        // ========== EPT CRASH COURSE (Cyber Guy) ==========
        {
            id: 'cyberguy-ept',
            title: 'Elite Penetration Tester Crash Course',
            titleAr: 'كورس مختبر الاختراق المتقدم',
            description: 'كورس EPT السريع بالعربي - من الأساسيات',
            descriptionEn: 'Elite Penetration Tester crash course in Arabic',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLDRMxi70CdSCIsZPz_DzTT07e14Ke-xR4',
            channel: 'Cyber Guy',
            thumbnail: 'bDJNMZuz2sE',
            totalVideos: 14,
            videos: [
                { position: 1, title: 'EPT Crash Course | Intro', videoId: 'bDJNMZuz2sE' },
                { position: 2, title: 'What Is A Vulnerability', videoId: 'akPSCPQiHeM' },
                { position: 3, title: 'How Vulnerability Occurs', videoId: 'AnnVGMznusE' },
                { position: 4, title: 'Types Of Vulnerabilities', videoId: 'b3imOFI5wWs' },
                { position: 5, title: 'History of Vulnerabilities', videoId: '99rkzdA0p4Y' },
                { position: 6, title: 'Exploitation of Vulnerabilities', videoId: 'zQe7n1lqsd8' },
                { position: 7, title: 'Web Protocols Part 1', videoId: 'GApz2P9GDDA' },
                { position: 8, title: 'Web Protocols Part 2', videoId: 'wTNxzlE3np0' },
                { position: 9, title: 'Web Protocols Part 3', videoId: 'YQWpxbGo3BA' },
                { position: 10, title: 'Web Protocols Part 4', videoId: '1zhdH7sCyr0' },
                { position: 11, title: 'How HTTPS Works', videoId: '3wUHZXBhU7U' },
                { position: 12, title: 'HTML Intro', videoId: 'vR9QN4pyQVw' },
                { position: 13, title: 'HTML Part 2', videoId: 'iReULnFeZ9E' },
                { position: 14, title: 'HTML Part 3 & Intro to JS', videoId: 'ovy-DKi_06Q' }
            ]
        },

        // ========== WEB TUTORIAL (Cyber Guy) ==========
        {
            id: 'cyberguy-web-tutorial',
            title: 'Web Security Tutorials',
            titleAr: 'دروس أمن الويب العملية',
            description: 'دروس عملية في أمن الويب - تثبيت Labs والتدريب',
            descriptionEn: 'Practical web security tutorials - Lab installation and practice',
            category: 'web-security',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSDfN1Eyq7q-48o91Sz1_AFM',
            channel: 'Cyber Guy',
            thumbnail: 'lg6EPKU-4E0',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'HTB Registration CTF Walkthrough', videoId: 'lg6EPKU-4E0' },
                { position: 2, title: 'DVWA Practice Lab Installation', videoId: 'utkU54XVP-8' },
                { position: 3, title: 'bWAPP Practice Lab Installation', videoId: '08kge5Lg2bk' },
                { position: 4, title: 'XVWA Practice Lab Installation', videoId: 'd4Sm5uZBuGg' },
                { position: 5, title: 'KaliLinux Installation on VirtualBox', videoId: 'MjwaeCi2QrQ' }
            ]
        },

        // ========== COMPTIA A+ ==========
        {
            id: 'comptia-aplus',
            title: 'CompTIA A+ Course',
            titleAr: 'كورس CompTIA A+',
            description: 'دورة شاملة للتحضير لشهادة CompTIA A+ بالعربي',
            descriptionEn: 'Comprehensive CompTIA A+ certification preparation course in Arabic',
            category: 'certs',
            level: 'beginner',
            playlistId: 'PLH-n8YK76vIiDdOMRB-ylvns-_8Zl1euV',
            channel: 'Arabic IT',
            thumbnail: 'zIpF33NCgrA',
            totalVideos: 56,
            videos: [
                { position: 1, title: 'مقدمة وتعريف بشهادات CompTIA', videoId: 'zIpF33NCgrA' },
                { position: 2, title: 'كل ماتريد أن تعرفه عن شهادة A+', videoId: '3ewpchhw3nA' },
                { position: 3, title: '01-Introduction to Hardware', videoId: 'HCdzduik1ZE' },
                { position: 4, title: '02-Form Factor', videoId: 'GQFeSgssCAo' },
                { position: 5, title: '03-Power Supply', videoId: 'A9rExIbfyzs' },
                { position: 6, title: '04-Safety and Protection', videoId: '3ff7XXnZET0' },
                { position: 7, title: '05-Motherboard Part1', videoId: '5I2HMPNanTo' },
                { position: 8, title: '06-Motherboard Part2', videoId: '7psnHQXElyk' },
                { position: 9, title: '07-BIOS and UEFI', videoId: 'uUmFTIJ4sBk' },
                { position: 10, title: '08-CPU', videoId: 'HiMjKMOjAzA' },
                { position: 11, title: '09-RAM', videoId: 'hKDtYu-FUbY' },
                { position: 12, title: '10-Storage Devices', videoId: 'z4yqa1vBRAc' },
                { position: 13, title: '11-Disks & Partitions', videoId: 'zkMLzPCXLRo' },
                { position: 14, title: '12-Dynamic Disks & RAID', videoId: 'WYKNyiqGLlc' },
                { position: 15, title: '13-File System', videoId: '2gUwqcZk3JE' },
                { position: 16, title: '14-Disk Optimization', videoId: 'QKHaVQNrJqA' },
                { position: 17, title: '15-Installing Windows Part1', videoId: 'U_PSPVcCYi0' },
                { position: 18, title: '16-Install Windows Part2', videoId: 'dfZNx5xD644' },
                { position: 19, title: '17-Windows features', videoId: '-hzDwesStq0' },
                { position: 20, title: '18-Managing Files using Command Line', videoId: 'hcGn3zKwm98' },
                { position: 21, title: '19-System Management Part1', videoId: 'PFLg12OBlwc' },
                { position: 22, title: '20-System Management Part2', videoId: 'm_JIvFFghJg' },
                { position: 23, title: '21-System Protection', videoId: 'lP0byYKhbi0' },
                { position: 24, title: '22-Troubleshooting', videoId: 'Fx4aSN3sjKI' },
                { position: 25, title: '23-Troubleshooting Application', videoId: '53VvXupXASw' },
                { position: 26, title: '24-Troubleshooting Windows Startup 1', videoId: 'KNIzw0HftVg' },
                { position: 27, title: '25-Troubleshooting Windows Startup 2', videoId: 'QoVopdv0qds' },
                { position: 28, title: '26-Troubleshooting Windows Startup 3', videoId: 'bFgnUfr8Izg' },
                { position: 29, title: '27-Supporting IO Devices', videoId: 'Qna640T0fNE' },
                { position: 30, title: '28-Supporting Video Subsystems Part 1', videoId: 'Gornp-tO0uA' },
                { position: 31, title: '29-Supporting Video Subsystems Part 2', videoId: 'qIXqS421Meg' },
                { position: 32, title: '30-Networks Part 1', videoId: 'PsjE96NTb7k' },
                { position: 33, title: '31-Networks Part 2', videoId: 'P4kf3adHxa0' },
                { position: 34, title: '32-Networks Part 3', videoId: 'oVv12se6BmM' },
                { position: 35, title: '33-Networks Part 4', videoId: 'pAZcxzC2K-E' },
                { position: 36, title: '34-Networks Part 5', videoId: 'CU6RW6D6jKQ' },
                { position: 37, title: '35-Networks Part 6', videoId: 'Kg7rF5jnbV8' },
                { position: 38, title: '36-Network Hardware Part 1', videoId: 'Y_w1-dqax_c' },
                { position: 39, title: '37-Network Hardware Part 2', videoId: '7IVz45CH3zk' },
                { position: 40, title: '38-Network Hardware Part 3', videoId: 'Wey5FAfnzhw' },
                { position: 41, title: '39-Network Hardware Part 4', videoId: 'SGxVl_sA3G8' },
                { position: 42, title: '40-Network Resources Part 1', videoId: 'qxDnPx8ZZ98' },
                { position: 43, title: '41-Network Resources Part2', videoId: 'EePTbL7aTJA' },
                { position: 44, title: '42-Network Resources Part3', videoId: 'y21QBUx53I0' },
                { position: 45, title: '43-Network Resources Part4', videoId: 'M89n0wOOIPM' },
                { position: 46, title: '44-Cloud Computing', videoId: 'qMYz5Y8ibRI' },
                { position: 47, title: '45-Supporting Printers Part 1', videoId: 'K6QLJAqRFi0' },
                { position: 48, title: '46-Supporting Printers Part 2', videoId: 'LUmT3LVEzvI' },
                { position: 49, title: '47-Supporting Printers Part 3', videoId: 'gBst-BB830w' },
                { position: 50, title: '48-Security Strategies Part 1', videoId: 'D36k-l6zO0g' },
                { position: 51, title: '49-Security Strategies Part 2', videoId: 'jMnWP77Vu4I' },
                { position: 52, title: '50-Security Strategies Part 3', videoId: '0q2mFeS1oos' },
                { position: 53, title: '51-Security Strategies Part 4', videoId: 'jfNlOOqAON4' },
                { position: 54, title: '52-Security Strategies Part 5', videoId: '1jDekrHOMWg' },
                { position: 55, title: '53-Linux Basics Part 1', videoId: 'bFGU-D67zH4' },
                { position: 56, title: '54-Linux Part2', videoId: 'EBLBBpbwbzo' }
            ]
        },

        // ========== COMPTIA N+ ==========
        {
            id: 'comptia-networkplus',
            title: 'CompTIA Network+ Course',
            titleAr: 'كورس CompTIA Network+',
            description: 'دورة شاملة للتحضير لشهادة CompTIA Network+ بالعربي',
            descriptionEn: 'Comprehensive CompTIA Network+ certification preparation course in Arabic',
            category: 'certs',
            level: 'intermediate',
            playlistId: 'PLH-n8YK76vIiuIZoWvHL7AvtrDV7hR3He',
            channel: 'Arabic IT',
            thumbnail: 'RFK4Kc_aJYg',
            totalVideos: 36,
            videos: [
                { position: 1, title: 'كل ماتريد أن تعرفه عن شهادة Network+', videoId: 'RFK4Kc_aJYg' },
                { position: 2, title: '01-Intro to Networks', videoId: '8cAmDg65qyk' },
                { position: 3, title: '02-Networks Terms', videoId: '02Jo7gR9GnA' },
                { position: 4, title: '02-1-Lab تطبيق عملى', videoId: 'U5ETRBzGzQk' },
                { position: 5, title: '03-OSI Model Part 1', videoId: 'UV_T_744vRo' },
                { position: 6, title: '04-OSI Model Part2', videoId: 'jhpN6Uh7uEQ' },
                { position: 7, title: '04-1-OSI Model تطبيق عملى', videoId: 'ziHWjVhb-6A' },
                { position: 8, title: '05-TCP_IP Model Part 1', videoId: 'pb2hhd1fhAs' },
                { position: 9, title: '06-TCP IP Model Part2', videoId: 'IbqAVzYWKes' },
                { position: 10, title: '07-TCP|IP Exercises', videoId: 'GxtyySPBeaY' },
                { position: 11, title: '08-Network Cables part 1', videoId: 'ju58R4f4JBY' },
                { position: 12, title: '09-Network Cables part 2', videoId: 'lBn-9D_MqJU' },
                { position: 13, title: '10-Network Devices Part1', videoId: 'WeXFpleuRlc' },
                { position: 14, title: '11-Network Devices Part2', videoId: 'E3IbLs9hxiw' },
                { position: 15, title: '12-Ethernet', videoId: 'qKS4ZfKENew' },
                { position: 16, title: '13-IPv4 Addressing Part 1', videoId: 'Ah64EqEIZ9Y' },
                { position: 17, title: '14-IPv4 Addressing Part 2', videoId: '3w-mKSm3XbE' },
                { position: 18, title: '15-IPv4 Addressing Part 3', videoId: 'ZayMyB_iJT8' },
                { position: 19, title: '16-Subnetting', videoId: 'O2-HFicmk54' },
                { position: 20, title: '17-DHCP', videoId: 'K7qMOYFSzsY' },
                { position: 21, title: '18-DNS', videoId: 'aWfWS_WZvzQ' },
                { position: 22, title: '19-Routing Part 1', videoId: '8UIGUjvg6nQ' },
                { position: 23, title: '20-Routing Part 2', videoId: '8-mpgi203V0' },
                { position: 24, title: '20_2-Routing Lab', videoId: 'D_PoyqT9DAc' },
                { position: 25, title: '21-NAT', videoId: 'bR8OlNmnn54' },
                { position: 26, title: '22-IPv6', videoId: 'mdEM1FFRPng' },
                { position: 27, title: '23-Wireless Networking Part1', videoId: '4dHtrA5rluU' },
                { position: 28, title: '24-Wireless Architecture', videoId: 'jPxCHWFbDy8' },
                { position: 29, title: '25-Wireless Standards', videoId: 'Za4wGdwWHOA' },
                { position: 30, title: '26-Wireless Security', videoId: 'cdsHAUW6TZ8' },
                { position: 31, title: '27-Wi-Fi Implementation Part 1', videoId: 'dUh9gHyiIJ0' },
                { position: 32, title: '28-Wi-Fi Implementation Part 2', videoId: 'ww9Hykspj0E' },
                { position: 33, title: '29-IOT Techs', videoId: 'QeFb5e-saeU' },
                { position: 34, title: '30-Virtualization', videoId: 'DpO6DrLM3as' },
                { position: 35, title: '31-Cloud Computing', videoId: '_4YzjTwHPI4' },
                { position: 36, title: 'مقدمة وتعريف بشهادات CompTIA', videoId: 'zIpF33NCgrA' }
            ]
        },

        // ========== PYTHON SQLITE3 ==========
        {
            id: 'python-sqlite3',
            title: 'Python SQLite3 Database Course',
            titleAr: 'كورس قواعد البيانات بالبايثون',
            description: 'تعلم قواعد البيانات باستخدام Python و SQLite3',
            descriptionEn: 'Learn databases using Python and SQLite3',
            category: 'linux',
            level: 'beginner',
            playlistId: 'PLknwEmKsW8OveN7SrZN5QjwyXLBzUDkJB',
            channel: 'Arabic Python',
            thumbnail: 'Gtl35O5qU9U',
            totalVideos: 11,
            videos: [
                { position: 1, title: '0- مقدمة', videoId: 'Gtl35O5qU9U' },
                { position: 2, title: '1- انشاء جداول في قاعدة البيانات', videoId: 'x6bSaind4tw' },
                { position: 3, title: '2- ادخال صف واحد من البيانات', videoId: 'f38qQV5E8Cs' },
                { position: 4, title: '3- ادخال العديد من الصفوف', videoId: 'BZCzSZCDD8M' },
                { position: 5, title: '4- قراءة البيانات', videoId: 'Z4F0lx7lLiQ' },
                { position: 6, title: '5- fetchall - fetchmany - fetchone', videoId: 's3PF-pXY7Lc' },
                { position: 7, title: '6- LIMIT - ORDER BY', videoId: 'u_c1ghe4zjI' },
                { position: 8, title: '7- الشروط where', videoId: 'wd6YMBTpJfw' },
                { position: 9, title: '8- تعديل البيانات update', videoId: 'eTJPnlRhr0A' },
                { position: 10, title: '9- حذف البيانات delete and drop', videoId: 'a-uZrdW3s2k' },
                { position: 11, title: '10- PRIMARY KEY - AUTOINCREMENT', videoId: 'CAR_bTV3WG8' }
            ]
        },

        // ========== BURPSUITE CRASH COURSE (Cyber Guy) ==========
        {
            id: 'cyberguy-burpsuite',
            title: 'Burpsuite Crash Course',
            titleAr: 'كورس Burp Suite السريع',
            description: 'كورس Burp Suite السريع بالعربي',
            descriptionEn: 'Burp Suite crash course in Arabic',
            category: 'web-security',
            level: 'intermediate',
            playlistId: 'PLDRMxi70CdSBzjCKsC0clrioNmlAPvASK',
            channel: 'Cyber Guy',
            thumbnail: 'Q9xOyOdgNf0',
            totalVideos: 5,
            videos: [
                { position: 1, title: 'Burpsuite Crash Course | Part 1', videoId: 'Q9xOyOdgNf0' },
                { position: 2, title: 'Burpsuite Crash Course | Part 2', videoId: 'is_XmuY1l-I' },
                { position: 3, title: 'Burpsuite Crash Course | Part 3', videoId: 'N4T21HO3src' },
                { position: 4, title: 'Burpsuite Crash Course | Part 4', videoId: 'KDf8h76LaGs' },
                { position: 5, title: 'Burpsuite Crash Course | Part 5', videoId: 'BuIHNXFcTPg' }
            ]
        },

        // ========== BASIC CRYPTOGRAPHY (Cyber Guy) ==========
        {
            id: 'cyberguy-cryptography',
            title: 'Basic Cryptography (Arabic)',
            titleAr: 'أساسيات التشفير',
            description: 'دورة أساسيات التشفير بالعربي',
            descriptionEn: 'Basic cryptography course in Arabic',
            category: 'network',
            level: 'beginner',
            playlistId: 'PLDRMxi70CdSCjBdDL3LcTJD1F46Sjy_zy',
            channel: 'Cyber Guy',
            thumbnail: '9wgEO3_GxcQ',
            totalVideos: 4,
            videos: [
                { position: 1, title: 'Basic Cryptography | Hashing', videoId: '9wgEO3_GxcQ' },
                { position: 2, title: 'Basic Cryptography | Symmetric Encryption', videoId: '7a8AxImXGXQ' },
                { position: 3, title: 'Basic Cryptography | Asymmetric Encryption', videoId: 'pvN_sUviFwU' },
                { position: 4, title: 'Basic Cryptography | Encoding', videoId: 'R28nvK8kjOA' }
            ]
        }
    ]
};

// Helper function to get YouTube thumbnail URL
function getYouTubeThumbnail(videoId, quality) {
    quality = quality || 'hqdefault';
    return 'https://img.youtube.com/vi/' + videoId + '/' + quality + '.jpg';
}

// Helper function to get YouTube embed URL
function getYouTubeEmbed(videoId) {
    return 'https://www.youtube.com/embed/' + videoId;
}

// Helper function to get YouTube watch URL
function getYouTubeWatchUrl(videoId) {
    return 'https://www.youtube.com/watch?v=' + videoId;
}

// Helper function to get playlist URL
function getPlaylistUrl(playlistId) {
    return 'https://www.youtube.com/playlist?list=' + playlistId;
}

// Get playlists by category
function getPlaylistsByCategory(categoryId) {
    return youtubeCoursesData.playlists.filter(function (p) {
        return p.category === categoryId;
    });
}

// Get playlist by ID
function getPlaylistById(playlistId) {
    return youtubeCoursesData.playlists.find(function (p) {
        return p.id === playlistId;
    });
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { youtubeCoursesData, getYouTubeThumbnail, getYouTubeEmbed, getPlaylistsByCategory };
}

// ==================== ADDITIONAL PLACEHOLDER DATA ====================
// Found in functional-pages.js (pageVideos function)

const extraVideoCategories = [
    {
        name: 'Web Application Security', icon: 'fa-globe', videos: [
            { title: 'SQL Injection Masterclass', author: 'StudyHub', duration: '45:00', views: '12K' },
            { title: 'XSS for Beginners', author: 'StudyHub', duration: '30:00', views: '8.5K' },
            { title: 'IDOR Exploitation', author: 'StudyHub', duration: '25:00', views: '6.2K' }
        ]
    },
    {
        name: 'Network Security', icon: 'fa-network-wired', videos: [
            { title: 'Nmap Deep Dive', author: 'StudyHub', duration: '55:00', views: '15K' },
            { title: 'Wireshark Analysis', author: 'StudyHub', duration: '40:00', views: '9.8K' },
            { title: 'Metasploit Framework', author: 'StudyHub', duration: '60:00', views: '11K' }
        ]
    },
    {
        name: 'CTF Walkthroughs', icon: 'fa-flag', videos: [
            { title: 'HackTheBox - Easy Machine', author: 'StudyHub', duration: '35:00', views: '7.2K' },
            { title: 'TryHackMe - Web Series', author: 'StudyHub', duration: '28:00', views: '5.5K' },
            { title: 'PicoCTF Solutions', author: 'StudyHub', duration: '42:00', views: '8.1K' }
        ]
    }
];
