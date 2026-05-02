import {
  Shield, Target, Zap, Search, Cloud, Code, Monitor,
  Skull, Bug, Terminal, Lock, Database, Smartphone,
  Cpu, FileSearch, Users, Globe, BookOpen
} from 'lucide-react';

// ─── YouTube Playlist IDs mapped to tracks ───────────────────────────────────
// Each track references playlist IDs from youtube-data.js
// so the TrackDetail page can pull them without duplicating data.

export const learningPaths = [

  // ══════════════════════════════════════════════════════
  // BEGINNER
  // ══════════════════════════════════════════════════════
  {
    id: 'pre-security',
    title: 'Pre Security',
    titleAr: 'ما قبل الأمن السيبراني',
    description: 'The absolute foundation for any cyber security journey. Break the fear of the black screen.',
    descriptionAr: 'الأساس المطلق لأي رحلة في الأمن السيبراني. تخلص من الخوف من الشاشة السوداء.',
    level: 'beginner',
    duration: '20 Hours',
    modules: 5,
    students: 15000,
    icon: Shield,
    skills: ['Linux Basics', 'Network Basics', 'Windows', 'CLI'],
    certGoals: ['CompTIA A+', 'CompTIA Network+'],
    // content/Pre Security mdx files
    contentModules: [
      {
        id: 'intro-cyber',
        title: 'Intro to Cyber',
        titleAr: 'مقدمة في الأمن السيبراني',
        icon: 'Shield',
        lessons: [
          { title: 'Welcome to BreachLabs', file: 'Pre Security/Intro to Cyber/Welcome to BreachLabs.mdx', xp: 50 },
          { title: 'Lab Setup Guide',       file: 'Pre Security/Intro to Cyber/Lab Setup.mdx',            xp: 50 },
        ]
      },
      {
        id: 'linux-fundamentals',
        title: 'Linux Fundamentals',
        titleAr: 'أساسيات لينكس',
        icon: 'Terminal',
        lessons: [
          { title: 'Navigation & CLI',      file: 'linux/navigation.mdx',          xp: 75 },
          { title: 'Directory Structure',   file: 'linux/directory-structure.mdx', xp: 50 },
          { title: 'Permissions',           file: 'linux/permissions.mdx',         xp: 75 },
          { title: 'Processes',             file: 'linux/processes.mdx',           xp: 75 },
          { title: 'Text Manipulation',     file: 'linux/text-manipulation.mdx',   xp: 75 },
          { title: 'Linux Fundamentals 1',  file: 'Pre Security/Linux Fundamentals/Linux Fundamentals 1.mdx', xp: 100 },
          { title: 'Linux Fundamentals 2',  file: 'Pre Security/Linux Fundamentals/Linux Fundamentals 2.mdx', xp: 100 },
        ]
      },
      {
        id: 'network-basics',
        title: 'Network Basics',
        titleAr: 'أساسيات الشبكات',
        icon: 'Network',
        lessons: [
          { title: 'Intro to Networking',   file: 'networking/intro.mdx',          xp: 50 },
          { title: 'IP Addressing',         file: 'networking/ip-addressing.mdx',  xp: 75 },
          { title: 'OSI Model',             file: 'networking/osi-model.mdx',      xp: 75 },
          { title: 'Protocols',             file: 'networking/protocols.mdx',      xp: 75 },
          { title: 'Network Tools',         file: 'networking/tools.mdx',          xp: 75 },
          { title: 'OSI Model Deep Dive',   file: 'Network Fundamentals/OSI & TCP-IP/The OSI Model Deep Dive.mdx', xp: 100 },
          { title: 'TCP and UDP',           file: 'Network Fundamentals/Protocols/TCP and UDP.mdx',               xp: 100 },
          { title: 'ICMP and ARP',          file: 'Network Fundamentals/Protocols/ICMP and ARP.mdx',              xp: 75 },
          { title: 'OSI Model (Pre-Sec)',   file: 'Pre Security/Network Basics/OSI Model.mdx',                    xp: 75 },
          { title: 'TCP/IP Protocol',       file: 'Pre Security/Network Basics/TCP-IP Protocol.mdx',              xp: 75 },
        ]
      },
    ],
    // YouTube playlists from youtube-data.js that match this track
    youtubePlaylists: [
      { id: 'ple4ob7kyojitmiezjikq-kr4nlopndggq',  relevance: 'THM Pre Security — Linux, Networking, Windows (MajinSec)' },
      { id: 'ple4ob7kyojiu-aapo2mqvmyj1wxxf9lah',  relevance: 'THM Cyber Security 101 — مقدمة شاملة للأمن السيبراني (MajinSec)' },
      { id: 'ple4ob7kyojis19t0p3ju9ttlsf41yayen',  relevance: 'THM Linux Fundamentals — أساسيات Linux بالتطبيق (MajinSec)' },
      { id: 'ple4ob7kyojivmxgsv3mmarhykthnhy5ep',  relevance: 'THM Networking — OSI, TCP/IP, Protocols (MajinSec)' },
      { id: 'pldrmxi70cdsd48opjbsdzrt4l0gvwj2ig',  relevance: 'Linux Basics بالعربي — أوامر Linux من الصفر (Cyber Guy)' },
      { id: 'plllr6jkkdyk0cc3bm-3kfutfwigmlgct9',  relevance: 'Linux Administration بالعربي — إدارة الأنظمة (Information Technology)' },
      { id: 'plunk096q36ca-nlk1dj3c6gprchw1bsu0',  relevance: 'Routing & Switching بالعربي — أساسيات الشبكات (Huawei ICT Academy)' },
      { id: 'plky4bd7-03m8o1nb0j96osxzs0kcklgmo',  relevance: 'Security+ SY0-601 بالعربي — أساسيات الأمن السيبراني (Netriders)' },
      { id: 'plpe-livmiwm51wrkec00aujnn0cxn-pwl',  relevance: 'معسكر الأمن السيبراني — مقدمة شاملة للمبتدئين (Abdalla Hijjawe)' },
    ],
  },

  {
    id: 'programming-for-pen-testers',
    title: 'Programming for Penetration Testers',
    titleAr: 'البرمجة لمختبري الاختراق',
    description: 'Learn Python and Bash scripting to automate tasks, build custom tools, and supercharge your penetration testing workflow.',
    descriptionAr: 'تعلم البرمجة بـ Python وBash لأتمتة المهام وبناء أدوات مخصصة وتعزيز سير عمل اختبار الاختراق.',
    level: 'beginner',
    duration: '30 Hours',
    modules: 4,
    students: 0,
    icon: Code,
    skills: ['Python', 'Bash', 'Scripting', 'Tool Development'],
    certGoals: ['eJPT', 'OSCP'],
    contentModules: [
      {
        id: 'python-basics',
        title: 'Python for Hackers',
        titleAr: 'Python للهاكرز',
        icon: 'Code',
        lessons: [
          { title: 'Python Crash Course',        file: 'programming/python-crash-course.mdx',      xp: 75 },
          { title: 'File & Network I/O',          file: 'programming/python-file-network.mdx',      xp: 100 },
          { title: 'Building a Port Scanner',     file: 'programming/python-port-scanner.mdx',      xp: 125 },
        ]
      },
      {
        id: 'bash-scripting',
        title: 'Bash Scripting',
        titleAr: 'سكريبتات Bash',
        icon: 'Terminal',
        lessons: [
          { title: 'Bash Fundamentals',           file: 'programming/bash-fundamentals.mdx',        xp: 75 },
          { title: 'Automation Scripts',          file: 'programming/bash-automation.mdx',          xp: 100 },
        ]
      },
      {
        id: 'tool-development',
        title: 'Building Pentest Tools',
        titleAr: 'بناء أدوات الاختراق',
        icon: 'Cpu',
        lessons: [
          { title: 'Reverse Shell in Python',     file: 'programming/python-reverse-shell.mdx',     xp: 150 },
          { title: 'Web Scraper & Fuzzer',        file: 'programming/python-web-fuzzer.mdx',        xp: 150 },
          { title: 'Exploit Automation',          file: 'programming/python-exploit-automation.mdx',xp: 175 },
        ]
      },
      {
        id: 'regex-and-parsing',
        title: 'Regex & Data Parsing',
        titleAr: 'التعبيرات النمطية وتحليل البيانات',
        icon: 'Search',
        lessons: [
          { title: 'Regex for Pentesters',        file: 'programming/regex-pentesters.mdx',         xp: 100 },
          { title: 'Parsing Tool Output',         file: 'programming/parsing-tool-output.mdx',      xp: 100 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'plknwemksw8osg8dnisr--2wgyx7lpggee',  relevance: 'Python للمبتدئين — أساسيات Python من الصفر (Abdelrahman Gamal)' },
      { id: 'pl2zf-nedn4flmdu55wnv3iluoz8eai9a4',  relevance: 'Python كامل — 60 فيديو تغطي كل المفاهيم (HankTheTank)' },
      { id: 'pl5jgi-q5p8ihoumtsxnt0cv-lslg7eron',  relevance: 'أدوات Python في السايبر سكيورتي — تطبيقات عملية (محمد العداس)' },
      { id: 'pl5dzpxpukhpm0hmeffcfjgelawyty4lym',  relevance: 'OSCP+ 2025 — Bash Scripting, Netcat, PowerShell (MrLimbo)' },
      { id: 'plllr6jkkdyk12gna1q5sylk7yzjo7hg7s',  relevance: 'PowerShell for Penetration Testers — أتمتة الاختراق (Information Technology)' },
      { id: 'pldrmxi70cdsahaqzzkr1uynsmoezechma',  relevance: 'SQL Crash Course بالعربي — أساسيات قواعد البيانات (Cyber Guy)' },
      { id: 'pl2zf-nedn4fmzxaj2anipcy-u4z8ezp6w',  relevance: 'MySQL Database — قواعد البيانات للمبرمجين (HankTheTank)' },
      { id: 'pld92v1qxpopr6cll6f4sl2tdp4uzo9lnw',  relevance: 'JavaScript For Ethical Hackers — JS للهاكرز (The XSS Rat)' },
    ],
  },

  {
    id: 'web-fundamentals',
    title: 'Web Fundamentals',
    titleAr: 'أساسيات الويب',
    description: 'Understand how the web works, from HTTP requests to browser security mechanisms.',
    descriptionAr: 'افهم كيف يعمل الويب، من طلبات HTTP إلى آليات أمان المتصفح.',
    level: 'beginner',
    duration: '15 Hours',
    modules: 3,
    students: 8500,
    icon: Globe,
    skills: ['HTTP', 'HTML/CSS/JS', 'Browser Security', 'APIs'],
    certGoals: ['CompTIA Security+'],
    contentModules: [
      {
        id: 'http-protocol',
        title: 'HTTP Protocol',
        titleAr: 'بروتوكول HTTP',
        icon: 'Globe',
        lessons: [
          { title: 'How the Web Works',     file: 'web/how-web-works.mdx',                                    xp: 75 },
          { title: 'Requests & Headers',    file: 'Web Fundamentals/HTTP Protocol/Requests and Headers.mdx',  xp: 100 },
          { title: 'Cookies & Sessions',    file: 'Web Fundamentals/HTTP Protocol/Cookies and Sessions.mdx',  xp: 100 },
        ]
      },
      {
        id: 'web-tech',
        title: 'Web Technologies',
        titleAr: 'تقنيات الويب',
        icon: 'Code',
        lessons: [
          { title: 'DOM Manipulation',      file: 'Web Fundamentals/Web Tech/DOM Manipulation.mdx',           xp: 75 },
          { title: 'JavaScript for Hackers',file: 'Web Fundamentals/Web Tech/JavaScript for Hackers.mdx',     xp: 100 },
        ]
      },
      {
        id: 'web-security-intro',
        title: 'Web Security Intro',
        titleAr: 'مقدمة أمن الويب',
        icon: 'Shield',
        lessons: [
          { title: 'OWASP Overview',        file: 'web/owasp-overview.mdx',  xp: 75 },
          { title: 'IDOR Basics',           file: 'web/idor.mdx',            xp: 75 },
          { title: 'XSS Basics',            file: 'web/xss.mdx',             xp: 75 },
          { title: 'SQL Injection Basics',  file: 'web/sql-injection.mdx',   xp: 75 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'pldrmxi70cdscnfkdkygnhkzb0iq0qvj8d',  relevance: 'Web Technologies بالعربي — HTTP, HTML, CSS, APIs (Cyber Guy)' },
      { id: 'ple4ob7kyojith97v5xe22r40bi2wrryg6',   relevance: 'THM How The Web Works — DNS, HTTP, Cookies (MajinSec)' },
      { id: 'ple4ob7kyojisgrxiejn1qpkgw7uqzkexy',   relevance: 'THM Introduction to Web Hacking — OWASP, XSS, SQLi (MajinSec)' },
      { id: 'plknwemksw8outqudafrbiavidz5ui3vce',   relevance: 'JavaScript كامل بالعربي — أساسيات JS للمطورين (Abdelrahman Gamal)' },
      { id: 'plqnljoftspqu6zo0drayhftkkyfnjw1io',   relevance: 'HTTP بالتفصيل — كيف يعمل البروتوكول (Hussein Nasser)' },
      { id: 'plqm63j87r5p5xzr4evp-zpmkfqyt9wffr',  relevance: 'TryHackMe OWASP TOP 10 — أهم ثغرات الويب (Motasem Hamdan)' },
      { id: 'plehdb4yx2v-2r8iyqt4ute8zxduu8xukg',   relevance: 'Web Vulnerabilities — ثغرات الويب للمبتدئين (Beta3 Elcyber)' },
    ],
  },

  // ══════════════════════════════════════════════════════
  // INTERMEDIATE
  // ══════════════════════════════════════════════════════
  {
    id: 'jr-pentester',
    title: 'Jr Penetration Tester',
    titleAr: 'مختبر اختراق مبتدئ',
    description: 'Step into the world of ethical hacking. Scanning, enumeration, and exploitation.',
    descriptionAr: 'ادخل عالم الاختراق الأخلاقي. الفحص والتعداد والاستغلال.',
    level: 'intermediate',
    duration: '60 Hours',
    modules: 6,
    students: 12000,
    icon: Target,
    skills: ['Nmap', 'Metasploit', 'Privilege Escalation', 'Exploitation'],
    certGoals: ['CompTIA PenTest+', 'eJPT'],
    contentModules: [
      {
        id: 'pt-fundamentals',
        title: 'Penetration Testing Fundamentals',
        titleAr: 'أساسيات اختبار الاختراق',
        icon: 'BookOpen',
        lessons: [
          { title: 'Ethics & Rules of Engagement', file: 'penetration-testing-fundamentals/ethics-roe.mdx',   xp: 75 },
          { title: 'Legal Issues',                  file: 'penetration-testing-fundamentals/legal-issues.mdx', xp: 75 },
          { title: 'PT Lifecycle',                  file: 'penetration-testing-fundamentals/pt-lifecycle.mdx', xp: 100 },
          { title: 'Red vs Blue Teams',             file: 'penetration-testing-fundamentals/teams.mdx',        xp: 75 },
          { title: 'Ethics & Legal (Track)',        file: 'Penetration Tester/Fundamentals/Ethics & Legal Issues.mdx',    xp: 100 },
          { title: 'PT Methodologies',              file: 'Penetration Tester/Fundamentals/PT Methodologies.mdx',         xp: 100 },
          { title: 'Lab Setup Guide',               file: 'Penetration Tester/Fundamentals/Lab Setup Guide.mdx',          xp: 75 },
          { title: 'Reporting & Documentation',     file: 'Penetration Tester/Fundamentals/Reporting & Documentation.mdx',xp: 100 },
        ]
      },
      {
        id: 'recon',
        title: 'Reconnaissance & Enumeration',
        titleAr: 'الاستطلاع والتعداد',
        icon: 'Search',
        lessons: [
          { title: 'Passive Recon',         file: 'reconnaissance-and-enumeration/passive-recon.mdx',                    xp: 75 },
          { title: 'Active Recon',          file: 'reconnaissance-and-enumeration/active-recon.mdx',                     xp: 100 },
          { title: 'Service Enumeration',   file: 'reconnaissance-and-enumeration/service-enum.mdx',                     xp: 100 },
          { title: 'Web Enumeration',       file: 'reconnaissance-and-enumeration/web-enum.mdx',                         xp: 100 },
          { title: 'Active Recon (Nmap)',   file: 'Penetration Tester/Reconnaissance/Active Recon (Nmap).mdx',           xp: 125 },
          { title: 'Passive Recon (Track)', file: 'Penetration Tester/Reconnaissance/Passive Recon.mdx',                 xp: 100 },
          { title: 'DNS Enumeration',       file: 'Penetration Tester/Reconnaissance/DNS Enumeration.mdx',               xp: 100 },
          { title: 'OSINT Frameworks',      file: 'Penetration Tester/Reconnaissance/OSINT Frameworks.mdx',              xp: 125 },
        ]
      },
      {
        id: 'vuln-assessment',
        title: 'Vulnerability Assessment',
        titleAr: 'تقييم الثغرات',
        icon: 'FileSearch',
        lessons: [
          { title: 'Automated Scanning',    file: 'vulnerability-assessment/automated-scanning.mdx',                     xp: 100 },
          { title: 'CVSS Scoring',          file: 'vulnerability-assessment/cvss-scoring.mdx',                           xp: 75 },
          { title: 'Manual Validation',     file: 'vulnerability-assessment/manual-validation.mdx',                      xp: 100 },
          { title: 'Professional Reports',  file: 'vulnerability-assessment/professional-reports.mdx',                   xp: 100 },
          { title: 'Scanning Theory',       file: 'Penetration Tester/Vulnerability Assessment/Scanning Theory.mdx',     xp: 100 },
          { title: 'Nessus Essentials',     file: 'Penetration Tester/Vulnerability Assessment/Nessus Essentials.mdx',   xp: 125 },
          { title: 'CVSS Scoring (Track)',  file: 'Penetration Tester/Vulnerability Assessment/CVSS Scoring.mdx',        xp: 75 },
          { title: 'Manual Validation (T)', file: 'Penetration Tester/Vulnerability Assessment/Manual Validation.mdx',   xp: 100 },
        ]
      },
      {
        id: 'network-pentest',
        title: 'Network Penetration Testing',
        titleAr: 'اختبار اختراق الشبكات',
        icon: 'Network',
        lessons: [
          { title: 'Nmap Deep Dive',        file: 'network-sec/nmap.mdx',                                                xp: 125 },
          { title: 'Attacking Services',    file: 'network-sec/attacking-services.mdx',                                  xp: 125 },
          { title: 'Password Cracking',     file: 'network-sec/password-cracking.mdx',                                   xp: 100 },
          { title: 'Wireshark',             file: 'network-sec/wireshark.mdx',                                           xp: 100 },
          { title: 'Metasploit',            file: 'network-sec/metasploit.mdx',                                          xp: 125 },
          { title: 'Metasploit Deep Dive',  file: 'Penetration Tester/Network Penetration Testing/Metasploit Deep Dive.mdx', xp: 150 },
          { title: 'Privilege Escalation',  file: 'Penetration Tester/Network Penetration Testing/Privilege Escalation.mdx', xp: 150 },
          { title: 'Pivoting & Tunneling',  file: 'Penetration Tester/Network Penetration Testing/Pivoting & Tunneling.mdx', xp: 150 },
          { title: 'Active Directory',      file: 'Penetration Tester/Network Penetration Testing/Active Directory (Kerberoasting).mdx', xp: 175 },
        ]
      },
      {
        id: 'web-app-pentest',
        title: 'Web Application Pentesting',
        titleAr: 'اختبار اختراق تطبيقات الويب',
        icon: 'Bug',
        lessons: [
          { title: 'SQL Injection',         file: 'web-application-pentesting/sqli.mdx',                                 xp: 125 },
          { title: 'XSS',                   file: 'web-application-pentesting/xss.mdx',                                  xp: 125 },
          { title: 'IDOR',                  file: 'web-application-pentesting/idor.mdx',                                  xp: 100 },
          { title: 'Auth & Session Mgmt',   file: 'web-application-pentesting/auth-session-mgmt.mdx',                    xp: 125 },
          { title: 'SQL Injection (Track)', file: 'Penetration Tester/Web Application Pentesting/SQL Injection.mdx',     xp: 150 },
          { title: 'XSS (Track)',           file: 'Penetration Tester/Web Application Pentesting/Cross-Site Scripting.mdx', xp: 150 },
          { title: 'IDOR (Track)',          file: 'Penetration Tester/Web Application Pentesting/IDOR.mdx',               xp: 125 },
          { title: 'Broken Auth (Track)',   file: 'Penetration Tester/Web Application Pentesting/Broken Auth.mdx',        xp: 150 },
        ]
      },
      {
        id: 'post-exploit',
        title: 'Post Exploitation',
        titleAr: 'ما بعد الاستغلال',
        icon: 'Skull',
        lessons: [
          { title: 'Linux PrivEsc',         file: 'post-exploit/linux-privesc.mdx',    xp: 150 },
          { title: 'Windows PrivEsc',       file: 'post-exploit/windows-privesc.mdx',  xp: 150 },
          { title: 'Persistence',           file: 'post-exploit/persistence.mdx',      xp: 125 },
          { title: 'Pivoting',              file: 'post-exploit/pivoting.mdx',         xp: 125 },
          { title: 'Cleanup',               file: 'post-exploit/cleanup.mdx',          xp: 75  },
          { title: 'Kerberoasting',         file: 'network-pentesting/kerberoasting.mdx', xp: 175 },
          { title: 'Metasploit (NetPT)',    file: 'network-pentesting/metasploit.mdx',    xp: 125 },
          { title: 'Pivoting (NetPT)',      file: 'network-pentesting/pivoting.mdx',      xp: 125 },
          { title: 'PrivEsc (NetPT)',       file: 'network-pentesting/priv-esc.mdx',      xp: 150 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'ple4ob7kyojiv71hrqz6598tafl6jqjffo',  relevance: 'THM Jr Penetration Tester — المسار الكامل (MajinSec)' },
      { id: 'plqm63j87r5p4ywmhmzx1kbvg6yadqnp1w',  relevance: 'TryHackMe Jr Penetration Tester — Nmap, Metasploit, PrivEsc (Motasem Hamdan)' },
      { id: 'plmuadkgharvrczcqzjfdnltikz66u19xk',  relevance: 'دورة الاختراق الأخلاقي الكاملة — من الصفر للاحتراف (Coder-Web)' },
      { id: 'plmuadkgharvrtklvhf516lwkywsbxmqcq',  relevance: 'دورة فحص الأنظمة Nmap — الفحص والاستطلاع (Coder-Web)' },
      { id: 'plbf0hzazhtgpx4-jgz6wojoj4cijsv1ww',  relevance: 'Information Gathering — الاستطلاع والتعداد (HackerSploit)' },
      { id: 'plbf0hzazhtgm8v-3oekhvcm9xah3qddix',  relevance: 'Nmap — الفحص الشامل للشبكات (HackerSploit)' },
      { id: 'plbf0hzazhtgn31zptzbbk70bohtyt7hsm',  relevance: 'Metasploit — الاستغلال والـ Post Exploitation (HackerSploit)' },
      { id: 'pliwbr7sjooxgmojornpup-vt1ctwwp8qw',  relevance: 'Kali Linux Exploitation Tools — Metasploit, BeEF (SYS TECH)' },
      { id: 'plxfr7vyudv2vcthrrq7hc2h3dq4iw3m1n',  relevance: 'كورس PTS بالعربي — Penetration Testing Specialist (CTRL)' },
    ],
  },

  {
    id: 'soc-analyst-1',
    title: 'SOC Analyst Level 1',
    titleAr: 'محلل أمن (SOC) - المستوى 1',
    description: 'Start your career as a Security Analyst. Monitor, Detect, and Respond to threats.',
    descriptionAr: 'ابدأ مسيرتك كمحلل أمني. راقب واكتشف واستجب للتهديدات.',
    level: 'intermediate',
    duration: '40 Hours',
    modules: 5,
    students: 9500,
    icon: Monitor,
    skills: ['Splunk', 'Wireshark', 'Log Analysis', 'Incident Response'],
    certGoals: ['CompTIA Security+', 'CompTIA CySA+', 'Splunk Core Certified'],
    contentModules: [
      {
        id: 'soc-blue-team',
        title: 'Blue Team Fundamentals',
        titleAr: 'أساسيات الفريق الأزرق',
        icon: 'Shield',
        lessons: [
          { title: 'SIEM Introduction',         file: 'blue-team-soc/siem-introduction.mdx',         xp: 100 },
          { title: 'Log Analysis Basics',        file: 'blue-team-soc/log-analysis-basics.mdx',       xp: 100 },
          { title: 'IOCs and TTPs',              file: 'blue-team-soc/iocs-and-ttps.mdx',             xp: 125 },
          { title: 'MITRE ATT&CK Navigator',    file: 'blue-team-soc/mitre-attack-navigator.mdx',    xp: 125 },
          { title: 'Threat Feeds Integration',  file: 'blue-team-soc/threat-feeds-integration.mdx',  xp: 100 },
        ]
      },
      {
        id: 'incident-response',
        title: 'Incident Response',
        titleAr: 'الاستجابة للحوادث',
        icon: 'Zap',
        lessons: [
          { title: 'Incident Lifecycle',        file: 'blue-team-soc/incident-lifecycle.mdx',        xp: 125 },
          { title: 'Timeline Analysis',         file: 'blue-team-soc/timeline-analysis.mdx',         xp: 125 },
          { title: 'Disk Forensics Essentials', file: 'blue-team-soc/disk-forensics-essentials.mdx', xp: 150 },
          { title: 'Memory Forensics',          file: 'blue-team-soc/memory-forensics-volatility.mdx', xp: 175 },
        ]
      },
      {
        id: 'network-analysis',
        title: 'Network Traffic Analysis',
        titleAr: 'تحليل حركة الشبكة',
        icon: 'Network',
        lessons: [
          { title: 'Wireshark Intro',           file: 'Network Fundamentals/OSI & TCP-IP/Wireshark Intro.mdx', xp: 125 },
          { title: 'TCP and UDP',               file: 'Network Fundamentals/Protocols/TCP and UDP.mdx',        xp: 100 },
          { title: 'ICMP and ARP',              file: 'Network Fundamentals/Protocols/ICMP and ARP.mdx',       xp: 100 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'plky4bd7-03m8o1nb0j96osxzs0kcklgmo',  relevance: 'Security+ SY0-601 بالعربي — أساسيات الأمن الدفاعي (Netriders)' },
      { id: 'plzp8fyhy3ohjnblffzfcmbol42jd0hmrs',  relevance: 'Reversing 101 — تحليل البرمجيات الخبيثة (NullByte)' },
      { id: 'plneu5z2hm4uyil-361xcrpr-wv0ilgvt4',  relevance: 'Application Security & DevSecOps بالعربي — الأمن الدفاعي (AppecAcademy)' },
      { id: 'plbf0hzazhtgmg7fjvzoaaw-je3wymioqv',  relevance: 'Linux Security — تأمين أنظمة Linux (HackerSploit)' },
      { id: 'plunk096q36ca-nlk1dj3c6gprchw1bsu0',  relevance: 'Routing & Switching — تحليل حركة الشبكة (Huawei ICT Academy)' },
      { id: 'plibgq1hxeaqhzwuqlkresvtejjpqmldyn',  relevance: 'Introduction to Cryptography بالعربي — التشفير للمحللين (X-Vector)' },
      { id: 'ple4ob7kyojiuoxhhxfaswx0p4-nnq4xtb',  relevance: 'THM Cryptography — التشفير وتحليل الهجمات (MajinSec)' },
      { id: 'plpe-livmiwm51wrkec00aujnn0cxn-pwl',  relevance: 'معسكر الأمن السيبراني — Blue Team وتحليل التهديدات (Abdalla Hijjawe)' },
    ],
  },

  {
    id: 'web-penetration-testing',
    title: 'Web Penetration Testing',
    titleAr: 'اختبار اختراق تطبيقات الويب',
    description: 'Master web application hacking from the ground up. OWASP Top 10, Burp Suite, SQL injection, XSS, IDOR, and beyond.',
    descriptionAr: 'أتقن اختبار اختراق تطبيقات الويب من الصفر. OWASP Top 10 وBurp Suite وحقن SQL وXSS وIDOR والمزيد.',
    level: 'intermediate',
    duration: '40 Hours',
    modules: 5,
    students: 0,
    icon: Bug,
    skills: ['OWASP Top 10', 'Burp Suite', 'SQL Injection', 'XSS', 'IDOR'],
    certGoals: ['eWPT', 'BSCP', 'OSWA'],
    contentModules: [
      {
        id: 'web-recon',
        title: 'Web Reconnaissance',
        titleAr: 'استطلاع تطبيقات الويب',
        icon: 'Search',
        lessons: [
          { title: 'Burp Suite Fundamentals',     file: 'web-pentest/burp-suite-fundamentals.mdx',  xp: 100 },
          { title: 'Web App Fingerprinting',      file: 'web-pentest/web-fingerprinting.mdx',       xp: 75  },
          { title: 'Directory & File Fuzzing',    file: 'web-pentest/directory-fuzzing.mdx',        xp: 100 },
        ]
      },
      {
        id: 'injection-attacks',
        title: 'Injection Attacks',
        titleAr: 'هجمات الحقن',
        icon: 'Bug',
        lessons: [
          { title: 'SQL Injection Deep Dive',     file: 'web-pentest/sqli-deep-dive.mdx',           xp: 150 },
          { title: 'Command Injection',           file: 'web-pentest/command-injection.mdx',        xp: 125 },
          { title: 'Server-Side Template Injection', file: 'web-pentest/ssti.mdx',                  xp: 150 },
        ]
      },
      {
        id: 'client-side-attacks',
        title: 'Client-Side Attacks',
        titleAr: 'هجمات جانب العميل',
        icon: 'Globe',
        lessons: [
          { title: 'XSS Deep Dive',               file: 'web-pentest/xss-deep-dive.mdx',            xp: 125 },
          { title: 'CSRF Attacks',                file: 'web-pentest/csrf.mdx',                     xp: 100 },
          { title: 'Clickjacking',                file: 'web-pentest/clickjacking.mdx',             xp: 75  },
        ]
      },
      {
        id: 'access-control',
        title: 'Access Control & Auth',
        titleAr: 'التحكم في الوصول والمصادقة',
        icon: 'Lock',
        lessons: [
          { title: 'IDOR & Broken Access Control', file: 'web-pentest/idor-access-control.mdx',     xp: 125 },
          { title: 'JWT Attacks',                 file: 'web-pentest/jwt-attacks.mdx',              xp: 150 },
          { title: 'OAuth Vulnerabilities',       file: 'web-pentest/oauth-vulnerabilities.mdx',    xp: 150 },
        ]
      },
      {
        id: 'advanced-web',
        title: 'Advanced Web Attacks',
        titleAr: 'هجمات الويب المتقدمة',
        icon: 'Zap',
        lessons: [
          { title: 'SSRF Attacks',                file: 'web-pentest/ssrf.mdx',                     xp: 175 },
          { title: 'XXE Injection',               file: 'web-pentest/xxe.mdx',                      xp: 150 },
          { title: 'File Upload Vulnerabilities', file: 'web-pentest/file-upload.mdx',              xp: 175 },
          { title: 'File Inclusion (LFI/RFI)',    file: 'web-pentest/file-inclusion.mdx',           xp: 175 },
          { title: 'Web Service & API Attacks',   file: 'web-pentest/api-attacks.mdx',              xp: 175 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'pldrmxi70cdsbhodkny87kqqgusnl0asxg',  relevance: 'Web Apps Pentesting بالعربي — XSS, CSRF, SSRF, SQLi (Cyber Guy)' },
      { id: 'pldrmxi70cdsbzjcksc0clrionmlapvask',  relevance: 'Burp Suite Crash Course بالعربي — أساسيات Burp (Cyber Guy)' },
      { id: 'ple4ob7kyojiuoxhhxfaswx0p4-nnq4xtb',  relevance: 'THM BurpSuite — الاستخدام الاحترافي (MajinSec)' },
      { id: 'plx621demlusaa7ngen7ufvzyjihhnefv0',  relevance: 'Bug Bounty للمبتدئين — اكتشاف ثغرات المواقع (GenTiL Security)' },
      { id: 'plx621demlusbqhfsi88be2jfrwmhz6cfj',  relevance: 'SQL Injection من الصفر للاحتراف 2025 (GenTiL Security)' },
      { id: 'plx621demlusaep8x6tbt8h1wfee5uh-hi',  relevance: 'XSS — PortSwigger Labs بالعربي (GenTiL Security)' },
      { id: 'plv7coghxovhxvhpzil1dwtbiyual8bahj',  relevance: 'Web Application Penetration Testing — المسار الكامل (Ebrahem)' },
      { id: 'plogq8zjmuit9ay9ob0r3tgyserevwmej-',  relevance: 'eWPT — Web Penetration Testing Certification Course (Ahmed_Exploitz)' },
      { id: 'plbf0hzazhtgo3epgas718lvlsimiv9dsc',  relevance: 'Web App Penetration Testing Tutorials — OWASP Top 10 (HackerSploit)' },
      { id: 'pllkt--mcueiyukmyaakznszeu4lzywt-j',  relevance: 'Web Application Pentesting — المسار الكامل (The Cyber Mentor)' },
      { id: 'plrqwms8b1fmqqhetj5b-bszv8ket-lx-f',  relevance: 'Web Application Reconnaissance — الاستطلاع المتقدم (BePractical)' },
      { id: 'pl7mt2fdjakpfus1vt4aaqgajheukefapb',  relevance: 'Pro PHP Security — SQLi, XSS, CSRF, File Upload (Sec Theater)' },
      { id: 'plqm63j87r5p72tfwg3gaw7ntkmcaig9w-',  relevance: 'OWASP TOP 10 — HackTheBox Track (Motasem Hamdan)' },
    ],
  },

  // ══════════════════════════════════════════════════════
  // ADVANCED
  // ══════════════════════════════════════════════════════
  {
    id: 'professional-pentester',
    title: 'Professional Penetration Tester',
    titleAr: 'مختبر اختراق محترف',
    description: 'Master advanced exploitation, Active Directory attacks, and professional reporting.',
    descriptionAr: 'أتقن الاستغلال المتقدم وهجمات Active Directory والتقارير الاحترافية.',
    level: 'advanced',
    duration: '120 Hours',
    modules: 12,
    students: 6000,
    icon: Skull,
    skills: ['Active Directory', 'Buffer Overflow', 'C2 Frameworks', 'AV Evasion'],
    certGoals: ['OSCP', 'OSEP', 'CEH'],
    contentModules: [
      {
        id: 'advanced-topics',
        title: 'Advanced Topics',
        titleAr: 'المواضيع المتقدمة',
        icon: 'Zap',
        lessons: [
          { title: 'Buffer Overflows',      file: 'advanced-topics/buffer-overflows.mdx',                              xp: 200 },
          { title: 'C2 Frameworks',         file: 'advanced-topics/c2-frameworks.mdx',                                 xp: 200 },
          { title: 'Career Path & Certs',   file: 'advanced-topics/career-path.mdx',                                   xp: 100 },
          { title: 'Buffer Overflows (T)',  file: 'Penetration Tester/Advanced Topics & Career/Buffer Overflows.mdx',  xp: 225 },
          { title: 'C2 Frameworks (T)',     file: 'Penetration Tester/Advanced Topics & Career/C2 Frameworks.mdx',     xp: 225 },
          { title: 'Antivirus Evasion',     file: 'Penetration Tester/Advanced Topics & Career/Antivirus Evasion.mdx', xp: 225 },
          { title: 'Career Path (T)',       file: 'Penetration Tester/Advanced Topics & Career/Career Path & Certs.mdx', xp: 100 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'pl5dzpxpukhpm0hmeffcfjgelawyty4lym',  relevance: 'OSCP+ 2025 — التحضير الكامل: AD, PrivEsc, AV Evasion (MrLimbo)' },
      { id: 'plqm63j87r5p4mp4np-oa1klv6o22rdfex',  relevance: 'OSCP Course 2025 — 168 فيديو شامل (Motasem Hamdan)' },
      { id: 'plmuadkgharvrczcqzjfdnltikz66u19xk',  relevance: 'دورة الاختراق الأخلاقي الكاملة — من الصفر للـ OSCP (Coder-Web)' },
      { id: 'plbf0hzazhtgoepimcp15es6y-ar4m6ql3',  relevance: 'Penetration Testing Bootcamp — 106 فيديو شامل (HackerSploit)' },
      { id: 'plbf0hzazhtgmjslpmj73cydh9vcqxukcu',  relevance: 'Red Team Essentials — MITRE ATT&CK, AD, Persistence (HackerSploit)' },
      { id: 'plllr6jkkdyk12gna1q5sylk7yzjo7hg7s',  relevance: 'PowerShell for Penetration Testers — أتمتة الاختراق (Information Technology)' },
      { id: 'plhfrwillookos-fjcphdzd2icf2vorfwk',  relevance: 'Linux for Hackers — Linux المتقدم للاختراق (David Bombal)' },
      { id: 'plhfrwillookof1ru-tfanubvuwc87i-7z',  relevance: 'Hackers Arise — تقنيات الاختراق المتقدمة (David Bombal)' },
      { id: 'plibgq1hxeaqg5-j3l7dphyc1mfpdrrjrg',  relevance: 'Cryptography for Pentesters بالعربي — التشفير للمختبرين (X-Vector)' },
    ],
  },

  {
    id: 'cloud-security',
    title: 'Cloud Security Specialist',
    titleAr: 'متخصص أمن السحابة',
    description: 'Attack and defend AWS, Azure, and GCP environments.',
    descriptionAr: 'هاجم وادافع عن بيئات AWS وAzure وGCP.',
    level: 'advanced',
    duration: '45 Hours',
    modules: 5,
    students: 3200,
    icon: Cloud,
    skills: ['AWS IAM', 'S3 Security', 'Azure AD', 'GCP', 'Lambda'],
    certGoals: ['AWS Security Specialty', 'AZ-500', 'CCSP'],
    contentModules: [
      {
        id: 'cloud-attacks',
        title: 'Cloud Attack Techniques',
        titleAr: 'تقنيات هجوم السحابة',
        icon: 'Cloud',
        lessons: [
          { title: 'AWS IAM Misconfigs',        file: 'cloud-security/aws-iam-misconfigs.mdx',       xp: 175 },
          { title: 'S3 Bucket Exploitation',    file: 'cloud-security/s3-bucket-exploitation.mdx',   xp: 175 },
          { title: 'Azure AD Attacks',          file: 'cloud-security/azure-ad-attacks.mdx',         xp: 175 },
          { title: 'GCP Privilege Escalation',  file: 'cloud-security/gcp-privilege-escalation.mdx', xp: 175 },
          { title: 'Lambda Security',           file: 'cloud-security/lambda-security.mdx',          xp: 150 },
        ]
      },
    ],
    youtubePlaylists: [
      { id: 'plneu5z2hm4uyil-361xcrpr-wv0ilgvt4',  relevance: 'Application Security & DevSecOps بالعربي — Cloud Security (AppecAcademy)' },
      { id: 'plbf0hzazhtgmjslpmj73cydh9vcqxukcu',  relevance: 'Red Team Essentials — Cloud Attack Techniques (HackerSploit)' },
      { id: 'plky4bd7-03m8o1nb0j96osxzs0kcklgmo',  relevance: 'Security+ SY0-601 — Cloud Security Fundamentals (Netriders)' },
    ],
  },

  // ══════════════════════════════════════════════════════
  // EXPERT (locked)
  // ══════════════════════════════════════════════════════
  {
    id: 'exploit-development',
    title: 'Exploit Development',
    titleAr: 'تطوير الاستغلال',
    description: 'Write your own exploits. Buffer overflows, shellcode, and kernel exploitation.',
    descriptionAr: 'اكتب استغلالاتك الخاصة. Buffer overflows وShellcode واستغلال الكيرنل.',
    level: 'expert',
    duration: '80 Hours',
    modules: 8,
    students: 1200,
    icon: Cpu,
    isLocked: true,
    skills: ['Assembly', 'GDB', 'Shellcode', 'Kernel Exploits'],
    certGoals: ['OSED', 'GREM'],
    contentModules: [],
    youtubePlaylists: [],
  },

  {
    id: 'malware-analysis',
    title: 'Malware Analysis',
    titleAr: 'تحليل البرمجيات الخبيثة',
    description: 'Reverse engineer malware samples and understand attacker techniques.',
    descriptionAr: 'قم بهندسة عكسية لعينات البرمجيات الخبيثة وافهم تقنيات المهاجمين.',
    level: 'expert',
    duration: '60 Hours',
    modules: 6,
    students: 900,
    icon: FileSearch,
    isLocked: true,
    skills: ['IDA Pro', 'Ghidra', 'Dynamic Analysis', 'YARA'],
    certGoals: ['GREM', 'GCFE'],
    contentModules: [],
    youtubePlaylists: [],
  },
];
