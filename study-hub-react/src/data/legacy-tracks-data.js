/* legacy-tracks-data.js */

export const legacyTracks = [
    {
        id: 'pre-security',
        title: 'Pre Security',
        titleAr: 'ما قبل الأمن السيبراني',
        description: 'The absolute foundation for any cyber security journey. Break the fear of the black screen.',
        courses: [
            { id: 'ps-intro', title: 'Intro to Cyber', modules: 3 },
            { id: 'ps-linux', title: 'Linux Fundamentals', modules: 3 },
            { id: 'ps-network', title: 'Network Basics', modules: 3 },
            { id: 'ps-windows', title: 'Windows Basics', modules: 3 },
            { id: 'ps-tools', title: 'Tools Intro', modules: 3 }
        ]
    },
    {
        id: 'cyber-security-101',
        title: 'Cyber Security 101',
        titleAr: 'أساسيات الأمن السيبراني 101',
        description: 'Learn the core principles of security, attack vectors, and defense-in-depth.',
        courses: [
            { id: 'cs101-principles', title: 'Security Principles', modules: 3 },
            { id: 'cs101-vectors', title: 'Attack Vectors', modules: 2 }
        ]
    },
    {
        id: 'web-fundamentals',
        title: 'Web Fundamentals',
        titleAr: 'أساسيات الويب',
        description: 'Understand how the web works, from HTTP requests to browser security mechanisms.',
        courses: [
            { id: 'wf-http', title: 'HTTP Protocol', modules: 2 },
            { id: 'wf-html', title: 'Web Tech', modules: 2 },
            { id: 'wf-security', title: 'Browser Security', modules: 2 }
        ]
    },
    {
        id: 'linux-fundamentals',
        title: 'Linux Fundamentals',
        titleAr: 'أساسيات لينكس',
        description: 'Master the Linux command line, file systems, and user permissions.',
        courses: [
            { id: 'lf-cli', title: 'Command Line Basics', modules: 2 },
            { id: 'lf-perm', title: 'Permissions & Users', modules: 1 }
        ]
    },
    {
        id: 'network-fundamentals',
        title: 'Network Fundamentals',
        titleAr: 'أساسيات الشبكات',
        description: 'Protocols, packets, and addressing. The bedrock of communication security.',
        courses: [
            { id: 'nf-arch', title: 'Architecture (Pro)', modules: 1 },
            { id: 'nf-osi', title: 'OSI & TCP/IP', modules: 2 },
            { id: 'nf-proto', title: 'Protocols', modules: 2 },
            { id: 'nf-ip', title: 'Addressing', modules: 1 }
        ]
    },
    {
        id: 'jr-pentester',
        title: 'Jr Penetration Tester',
        titleAr: 'مختبر اختراق مبتدئ',
        description: 'Step into the world of ethical hacking. Scanning, enumeration, and exploitation.',
        courses: [
            { id: 'jpt-scan', title: 'Scanning & Enum', modules: 2 },
            { id: 'jpt-exp', title: 'Exploitation', modules: 2 },
            { id: 'jpt-priv', title: 'Privilege Escalation', modules: 2 }
        ]
    },
    {
        id: 'off-pentest',
        title: 'Offensive Pentesting',
        titleAr: 'اختبار الاختراق الهجومي',
        description: 'Advanced methodologies, focusing on real-world exploitation and Active Directory.',
        courses: [
            { id: 'op-bof', title: 'Buffer Overflows', modules: 1 },
            { id: 'op-ad', title: 'Active Directory', modules: 2 }
        ]
    },
    {
        id: 'soc-level-2',
        title: 'SOC Level 2',
        titleAr: 'محلل أمن (SOC) - المستوى 2',
        description: 'Advanced security operations: Threat Hunting and Malware Analysis.',
        courses: [
            { id: 'soc2-hunt', title: 'Threat Hunting', modules: 2 },
            { id: 'soc2-mal', title: 'Malware Analysis', modules: 2 }
        ]
    },
    {
        id: 'exploit-dev',
        title: 'Exploit Development',
        titleAr: 'تطوير الاستغلالات',
        description: 'The science of weaponizing vulnerabilities at the hardware and kernel level.',
        courses: [
            { id: 'exp-shell', title: 'Shellcoding', modules: 1 },
            { id: 'exp-kernel', title: 'Kernel Exploitation', modules: 1 }
        ]
    },
    {
        id: 'forensics-specialist',
        title: 'Digital Forensics',
        titleAr: 'التحقيق الجنائي الرقمي',
        description: 'Uncovering evidence, identifying artifacts, and reconstructing digital timelines.',
        courses: [
            { id: 'for-disk', title: 'Disk Forensics', modules: 1 },
            { id: 'for-mem', title: 'Memory Forensics', modules: 1 }
        ]
    },
    {
        id: 'mobile-hacking',
        title: 'Mobile Security',
        titleAr: 'أمن الهواتف المحمولة',
        description: 'Hacking Android and iOS applications and bypass defenses.',
        courses: [
            { id: 'mob-android', title: 'Android Security', modules: 2 },
            { id: 'mob-ios', title: 'iOS Security', modules: 1 }
        ]
    },
    {
        id: 'iot-security',
        title: 'IoT & Hardware Hacking',
        titleAr: 'أمن إنترنت الأشياء (IoT)',
        description: 'Hacking embedded devices, firmware, and radio protocols.',
        courses: [
            { id: 'iot-firm', title: 'Firmware Analysis', modules: 1 },
            { id: 'iot-sdr', title: 'Radio (SDR)', modules: 1 }
        ]
    },
    {
        id: 'malware-analysis',
        title: 'Malware Analysis',
        titleAr: 'تحليل البرمجيات الخبيثة',
        description: 'Dissect malicious software to understand its behavior and origin.',
        courses: [
            { id: 'mal-basic', title: 'Basic Analysis', modules: 1 },
            { id: 'mal-adv', title: 'Advanced RE', modules: 1 }
        ]
    },
    {
        id: 'grc-audit',
        title: 'GRC & Auditing',
        titleAr: 'الحوكمة والمخاطر والامتثال (GRC)',
        description: 'Governance, Risk management, and Compliance standards.',
        courses: [
            { id: 'grc-std', title: 'Standards (ISO/GDPR)', modules: 2 }
        ]
    }
];
