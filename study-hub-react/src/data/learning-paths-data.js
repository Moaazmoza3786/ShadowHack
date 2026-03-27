import {
    Shield,
    Target,
    Zap,
    Search,
    Cloud,
    Code,
    Monitor,
    Skull,
    Bug,
    Terminal,
    Lock,
    Database,
    Smartphone,
    Cpu,
    FileSearch,
    Users,
    Globe
} from 'lucide-react';

// Career Learning Paths - Fully functional tracks
export const learningPaths = [
    // ==================== BEGINNER PATHS ====================
    {
        id: 'pre-security',
        title: 'Pre Security',
        titleAr: 'ما قبل الأمن السيبراني',
        description: 'The absolute foundation for any cyber security journey. Break the fear of the black screen.',
        level: 'beginner',
        duration: '20 Hours',
        modules: 5,
        students: 15000,
        icon: Shield,
        route: '/courses/linux-fundamentals',
        skills: ['Linux Basics', 'Network Basics', 'Windows', 'CLI'],
        courses: [
            { id: 'ps-intro', title: 'Intro to Cyber', completed: false },
            { id: 'ps-linux', title: 'Linux Fundamentals', completed: false },
            { id: 'ps-network', title: 'Network Basics', completed: false },
            { id: 'ps-windows', title: 'Windows Basics', completed: false },
            { id: 'ps-tools', title: 'Tools Intro', completed: false }
        ]
    },
    {
        id: 'web-fundamentals',
        title: 'Web Fundamentals',
        titleAr: 'أساسيات الويب',
        description: 'Understand how the web works, from HTTP requests to browser security mechanisms.',
        level: 'beginner',
        duration: '15 Hours',
        modules: 3,
        students: 8500,
        icon: Globe,
        route: '/courses/web-app-security',
        skills: ['HTTP', 'HTML/CSS/JS', 'Browser Security', 'APIs'],
        courses: [
            { id: 'wf-http', title: 'HTTP Protocol', completed: false },
            { id: 'wf-html', title: 'Web Tech', completed: false },
            { id: 'wf-security', title: 'Browser Security', completed: false }
        ]
    },

    // ==================== INTERMEDIATE PATHS ====================
    {
        id: 'jr-pentester',
        title: 'Jr Penetration Tester',
        titleAr: 'مختبر اختراق مبتدئ',
        description: 'Step into the world of ethical hacking. Scanning, enumeration, and exploitation.',
        level: 'intermediate',
        duration: '60 Hours',
        modules: 6,
        students: 12000,
        icon: Target,
        route: '/courses/network-pentest',
        skills: ['Nmap', 'Metasploit', 'Privilege Escalation', 'Exploitation'],
        courses: [
            { id: 'jpt-scan', title: 'Scanning & Enumeration', completed: false },
            { id: 'jpt-exp', title: 'Exploitation Basics', completed: false },
            { id: 'jpt-priv', title: 'Privilege Escalation', completed: false }
        ]
    },
    {
        id: 'soc-analyst-1',
        title: 'SOC Analyst Level 1',
        titleAr: 'محلل أمن (SOC) - المستوى 1',
        description: 'Start your career as a Security Analyst. Monitor, Detect, and Respond to threats.',
        level: 'intermediate',
        duration: '40 Hours',
        modules: 5,
        students: 9500,
        icon: Monitor,
        route: '/courses/soc-level-1',
        skills: ['Splunk', 'Wireshark', 'Log Analysis', 'Incident Response'],
        courses: [
            { id: 'soc-fund', title: 'SOC Fundamentals', completed: false },
            { id: 'soc-siem', title: 'SIEM Operations', completed: false },
            { id: 'soc-ir', title: 'Incident Response', completed: false }
        ]
    },
    {
        id: 'web-pentesting',
        title: 'Web Application Pentesting',
        titleAr: 'اختبار اختراق تطبيقات الويب',
        description: 'Find and exploit web vulnerabilities. OWASP Top 10, Injection, and XSS.',
        level: 'intermediate',
        duration: '60 Hours',
        modules: 8,
        students: 7800,
        icon: Bug,
        route: '/courses/web-pentesting',
        skills: ['SQLi', 'XSS', 'Auth Bypass', 'SSRF', 'Burp Suite'],
        courses: [
            { id: 'web-recon', title: 'Reconnaissance', completed: false },
            { id: 'web-inj', title: 'Injection Attacks', completed: false },
            { id: 'web-burp', title: 'Burp Suite Mastery', completed: false }
        ]
    },
    {
        id: 'python-hackers',
        title: 'Python for Hackers',
        titleAr: 'بايثون للهاكرز',
        description: 'Build your own hacking tools with Python. Automation and scripting for security.',
        level: 'intermediate',
        duration: '30 Hours',
        modules: 4,
        students: 11000,
        icon: Code,
        route: '/courses/python-hackers',
        skills: ['Python', 'Scripting', 'Automation', 'Tool Development'],
        courses: [
            { id: 'py-basics', title: 'Python Basics', completed: false },
            { id: 'py-net', title: 'Network Programming', completed: false },
            { id: 'py-tools', title: 'Building Tools', completed: false }
        ]
    },

    // ==================== ADVANCED PATHS ====================
    {
        id: 'professional-pentester',
        title: 'Professional Penetration Tester',
        titleAr: 'مختبر اختراق محترف',
        description: 'Master the art of ethical hacking from fundamentals to advanced exploitation.',
        level: 'advanced',
        duration: '120 Hours',
        modules: 12,
        students: 5400,
        icon: Skull,
        route: '/courses/antigravity-pentester',
        skills: ['Metasploit', 'Burp Suite', 'AD Hacking', 'PrivEsc', 'OSINT'],
        courses: [
            { id: 'pt-fund', title: 'Fundamentals', completed: false },
            { id: 'pt-recon', title: 'Reconnaissance', completed: false },
            { id: 'pt-vuln', title: 'Vulnerability Assessment', completed: false },
            { id: 'pt-web', title: 'Web Application Pentesting', completed: false },
            { id: 'pt-net', title: 'Network Penetration Testing', completed: false }
        ]
    },
    {
        id: 'red-team-operator',
        title: 'Red Team Operator',
        titleAr: 'مشغل الفريق الأحمر (Red Team)',
        description: 'Simulate advanced adversaries. C2, Lateral Movement, and OPSEC.',
        level: 'advanced',
        duration: '80 Hours',
        modules: 8,
        students: 1800,
        icon: Zap,
        route: '/courses/red-teaming',
        skills: ['C2 Frameworks', 'AV Evasion', 'OPSEC', 'Cobalt Strike'],
        courses: [
            { id: 'rt-c2', title: 'C2 Infrastructure', completed: false },
            { id: 'rt-evasion', title: 'AV/EDR Evasion', completed: false },
            { id: 'rt-ops', title: 'Red Team Operations', completed: false }
        ]
    },
    {
        id: 'bug-bounty-hunter',
        title: 'Bug Bounty Hunter',
        titleAr: 'صيد الثغرات',
        description: 'Master bug bounty hunting. Recon, exploitation, and professional reporting.',
        level: 'advanced',
        duration: '50 Hours',
        modules: 6,
        students: 6200,
        icon: Search,
        route: '/courses/bug-bounty-hunting',
        skills: ['Bug Bounty', 'Recon', 'Automation', 'Report Writing'],
        courses: [
            { id: 'bb-recon', title: 'Reconnaissance', completed: false },
            { id: 'bb-vuln', title: 'Vulnerability Discovery', completed: false },
            { id: 'bb-report', title: 'Report Writing', completed: false }
        ]
    },
    {
        id: 'cloud-security',
        title: 'Cloud Security Specialist',
        titleAr: 'أخصائي أمن سحابي',
        description: 'Secure AWS, Azure, and GCP environments. Auditing and Hardening.',
        level: 'advanced',
        duration: '45 Hours',
        modules: 5,
        students: 2100,
        icon: Cloud,
        route: '/courses/cloud-security',
        skills: ['AWS IAM', 'S3 Security', 'Azure AD', 'Cloud Pentest'],
        courses: [
            { id: 'cloud-aws', title: 'AWS Security Mastery', completed: false },
            { id: 'cloud-azure', title: 'Azure Security', completed: false },
            { id: 'cloud-gcp', title: 'GCP Security', completed: false }
        ]
    },
    {
        id: 'devsecops',
        title: 'DevSecOps Specialist',
        titleAr: 'أخصائي ديف سيك أوبس',
        description: 'Integrate security into the SDLC. CI/CD, Containers, and Kubernetes.',
        level: 'advanced',
        duration: '40 Hours',
        modules: 5,
        students: 1500,
        icon: Terminal,
        route: '/courses/devsecops',
        skills: ['Docker', 'Kubernetes', 'CI/CD Security', 'SCA', 'SAST'],
        courses: [
            { id: 'dso-docker', title: 'Container Security', completed: false },
            { id: 'dso-k8s', title: 'Kubernetes Security', completed: false },
            { id: 'dso-cicd', title: 'CI/CD Pipeline Security', completed: false }
        ]
    },

    // ==================== EXPERT PATHS ====================
    {
        id: 'offensive-pentesting',
        title: 'Offensive Pentesting',
        titleAr: 'اختبار الاختراق الهجومي',
        description: 'Advanced methodologies, focusing on real-world exploitation and Active Directory.',
        level: 'expert',
        duration: '100 Hours',
        modules: 10,
        students: 980,
        icon: Skull,
        route: '/paths/red',
        skills: ['Buffer Overflows', 'Active Directory', 'Exploit Development'],
        courses: [
            { id: 'op-bof', title: 'Buffer Overflows', completed: false },
            { id: 'op-ad', title: 'Active Directory Attacks', completed: false },
            { id: 'op-exp', title: 'Exploit Development', completed: false }
        ]
    },
    {
        id: 'soc-level-2',
        title: 'SOC Level 2',
        titleAr: 'محلل أمن (SOC) - المستوى 2',
        description: 'Advanced security operations: Threat Hunting and Malware Analysis.',
        level: 'expert',
        duration: '60 Hours',
        modules: 6,
        students: 650,
        icon: Monitor,
        route: '/paths/soc',
        skills: ['Threat Hunting', 'Malware Analysis', 'Forensics'],
        courses: [
            { id: 'soc2-hunt', title: 'Threat Hunting', completed: false },
            { id: 'soc2-mal', title: 'Malware Analysis', completed: false }
        ]
    },
    {
        id: 'exploit-development',
        title: 'Exploit Development',
        titleAr: 'تطوير الاستغلالات',
        description: 'The science of weaponizing vulnerabilities at the hardware and kernel level.',
        level: 'expert',
        duration: '80 Hours',
        modules: 8,
        students: 420,
        icon: Cpu,
        isLocked: true,
        skills: ['Shellcoding', 'Kernel Exploitation', 'Reverse Engineering'],
        courses: [
            { id: 'exp-shell', title: 'Shellcoding', completed: false },
            { id: 'exp-kernel', title: 'Kernel Exploitation', completed: false }
        ]
    },
    {
        id: 'digital-forensics',
        title: 'Digital Forensics',
        titleAr: 'التحقيق الجنائي الرقمي',
        description: 'Uncovering evidence, identifying artifacts, and reconstructing digital timelines.',
        level: 'expert',
        duration: '50 Hours',
        modules: 5,
        students: 780,
        icon: FileSearch,
        isLocked: true,
        skills: ['Disk Forensics', 'Memory Forensics', 'Timeline Analysis'],
        courses: [
            { id: 'for-disk', title: 'Disk Forensics', completed: false },
            { id: 'for-mem', title: 'Memory Forensics', completed: false }
        ]
    },
    {
        id: 'mobile-security',
        title: 'Mobile Security',
        titleAr: 'أمن الهواتف المحمولة',
        description: 'Hacking Android and iOS applications and bypass defenses.',
        level: 'expert',
        duration: '45 Hours',
        modules: 5,
        students: 560,
        icon: Smartphone,
        isLocked: true,
        skills: ['Android Security', 'iOS Security', 'Mobile Pentesting'],
        courses: [
            { id: 'mob-android', title: 'Android Security', completed: false },
            { id: 'mob-ios', title: 'iOS Security', completed: false }
        ]
    },
    {
        id: 'malware-analysis',
        title: 'Malware Analysis',
        titleAr: 'تحليل البرمجيات الخبيثة',
        description: 'Dissect malicious software to understand its behavior and origin.',
        level: 'expert',
        duration: '60 Hours',
        modules: 6,
        students: 890,
        icon: Bug,
        isLocked: true,
        skills: ['Static Analysis', 'Dynamic Analysis', 'Reverse Engineering'],
        courses: [
            { id: 'mal-basic', title: 'Basic Analysis', completed: false },
            { id: 'mal-adv', title: 'Advanced RE', completed: false }
        ]
    }
];
