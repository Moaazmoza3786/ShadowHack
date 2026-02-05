import { Globe, Network, Microscope, Code, Terminal, Cpu, Shield, Zap, Wifi, Bot, Cloud, Bug, Server, Eye, Ghost, Search, BookOpen } from 'lucide-react';

export const TOPICS_DATA = {
    web: {
        title: 'Web Security',
        titleAr: 'أمن الويب',
        subtitle: 'Master modern web application vulnerabilities.',
        icon: Globe,
        color: '#ef4444',
        rooms: [
            { id: 'web-1', title: 'Introduction to Web Applications', desc: 'Understanding the client-server model and HTTP.', time: '45 min', points: 50, difficulty: 'Easy' },
            { id: 'web-2', title: 'Using Web Proxies', desc: 'Mastering Burp Suite and OWASP ZAP.', time: '60 min', points: 100, difficulty: 'Easy' },
            { id: 'web-3', title: 'Web Fuzzing', desc: 'Automating directory and parameter discovery.', time: '60 min', points: 100, difficulty: 'Medium' },
            { id: 'web-4', title: 'SQL Injection Fundamentals', desc: 'Classic SQLi, Auth Bypass, and UNION attacks.', time: '90 min', points: 150, difficulty: 'Medium' },
            { id: 'web-5', title: 'Blind SQL Injection', desc: 'Boolean-based and Time-based data extraction.', time: '120 min', points: 250, difficulty: 'Hard' },
            { id: 'web-7', title: 'SQLMap Essentials', desc: 'Automating database exploitation.', time: '60 min', points: 120, difficulty: 'Medium' },
            { id: 'web-9', title: 'Cross-Site Scripting (XSS)', desc: 'Stored, Reflected, and DOM-based XSS.', time: '60 min', points: 120, difficulty: 'Medium' },
            { id: 'web-10', title: 'Advanced XSS & CSRF', desc: 'Client-side attack chains and bypasses.', time: '90 min', points: 200, difficulty: 'Hard' },
            { id: 'web-11', title: 'Command Injections', desc: 'Executing OS commands via web apps.', time: '60 min', points: 180, difficulty: 'Medium' },
            { id: 'web-12', title: 'File Inclusion', desc: 'LFI and RFI vulnerabilities.', time: '45 min', points: 150, difficulty: 'Medium' },
            { id: 'web-13', title: 'File Upload Attacks', desc: 'Bypassing filters to achieve RCE.', time: '60 min', points: 200, difficulty: 'Hard' },
            { id: 'web-14', title: 'Server-side Attacks', desc: 'SSRF and SSTI deep dive.', time: '90 min', points: 300, difficulty: 'Hard' },
            { id: 'web-15', title: 'Deserialization Attacks', desc: 'Insecure deserialization in various languages.', time: '120 min', points: 300, difficulty: 'Hard' },
            { id: 'web-18', title: 'Broken Authentication', desc: 'Bypassing login and session controls.', time: '60 min', points: 200, difficulty: 'Medium' },
            { id: 'web-20', title: 'Attacking Ffuf', desc: 'High-speed web fuzzing mastery.', time: '45 min', points: 100, difficulty: 'Medium' }
        ]
    },
    network: {
        title: 'Network Security',
        titleAr: 'أمن الشبكات',
        subtitle: 'Understand protocols and infrastructure attacks.',
        icon: Network,
        color: '#3b82f6',
        rooms: [
            { id: 'net-101', title: 'Introduction to Networking', desc: 'OSI Model and TCP/IP deep dive.', time: '60 min', points: 100, difficulty: 'Easy' },
            { id: 'net-3', title: 'Network Enumeration with Nmap', desc: 'Advanced port scanning and scripts.', time: '90 min', points: 150, difficulty: 'Medium' },
            { id: 'net-4', title: 'Footprinting', desc: 'Infrastructure reconnaissance and mapping.', time: '60 min', points: 120, difficulty: 'Easy' },
            { id: 'net-5', title: 'DNS Enumeration with Python', desc: 'Writing custom tools for DNS discovery.', time: '90 min', points: 180, difficulty: 'Medium' },
            { id: 'net-7', title: 'OSINT: Corporate Recon', desc: 'Gathering intel from public sources.', time: '120 min', points: 250, difficulty: 'Hard' },
            { id: 'net-8', title: 'Attacking Common Services', desc: 'SSH, SMB, FTP, and RDP exploitation.', time: '90 min', points: 300, difficulty: 'Hard' }
        ]
    },
    ad: {
        title: 'Active Directory',
        titleAr: 'أكتيف دايركتوري',
        subtitle: 'Dominate the Windows Domain environment.',
        icon: Shield,
        color: '#a855f7',
        rooms: [
            { id: 'ad-1', title: 'Introduction to Active Directory', desc: 'Users, Groups, and GPOs.', time: '60 min', points: 100, difficulty: 'Easy' },
            { id: 'ad-2', title: 'AD Enumeration & Attacks', desc: 'Mapping the domain environment.', time: '120 min', points: 300, difficulty: 'Hard' },
            { id: 'ad-3', title: 'Active Directory PowerView', desc: 'Advanced internal enumeration.', time: '90 min', points: 200, difficulty: 'Medium' },
            { id: 'ad-4', title: 'Active Directory BloodHound', desc: 'Mapping attack paths to Domain Admin.', time: '90 min', points: 200, difficulty: 'Medium' },
            { id: 'ad-5', title: 'Kerberos Attacks', desc: 'Kerberoasting and AS-REP roasting.', time: '90 min', points: 250, difficulty: 'Hard' },
            { id: 'ad-6', title: 'Using CrackMapExec', desc: 'Post-exploitation automation.', time: '60 min', points: 150, difficulty: 'Medium' }
        ]
    },
    wifi: {
        title: 'Wi-Fi Security',
        titleAr: 'أمن الوايفاي',
        subtitle: 'Wireless protocol analysis and exploitation.',
        icon: Wifi,
        color: '#22c55e',
        rooms: [
            { id: 'wifi-1', title: 'Wi-Fi PT Basics', desc: 'Wireless 802.11 fundamentals.', time: '45 min', points: 50, difficulty: 'Easy' },
            { id: 'wifi-3', title: 'Attacking WPA2', desc: 'Exploiting the 4-way handshake.', time: '90 min', points: 200, difficulty: 'Medium' },
            { id: 'wifi-4', title: 'Attacking WPA3', desc: 'Bypassing the Dragonfly handshake.', time: '120 min', points: 350, difficulty: 'Hard' },
            { id: 'wifi-6', title: 'Evil Twin Attacks', desc: 'Deploying rogue access points.', time: '90 min', points: 250, difficulty: 'Hard' },
            { id: 'wifi-12', title: 'Wi-Fi Deauthentication', desc: 'Forcing clients off the network.', time: '30 min', points: 80, difficulty: 'Easy' }
        ]
    },
    ai: {
        title: 'AI Security',
        titleAr: 'أمن الذكاء الاصطناعي',
        subtitle: 'Red teaming LLMs and AI applications.',
        icon: Bot,
        color: '#f43f5e',
        rooms: [
            { id: 'ai-1', title: 'Intro to Red Teaming AI', desc: 'Understanding the AI attack surface.', time: '45 min', points: 100, difficulty: 'Easy' },
            { id: 'ai-3', title: 'Prompt Injection', desc: 'Bypassing guardrails via text.', time: '90 min', points: 250, difficulty: 'Medium' },
            { id: 'ai-4', title: 'LLM Output Attacks', desc: 'Manipulating model outputs.', time: '120 min', points: 300, difficulty: 'Hard' }
        ]
    },
    cloud: {
        title: 'Cloud Security',
        titleAr: 'الأمن السحابي',
        subtitle: 'AWS, Azure, and GCP penetration testing.',
        icon: Cloud,
        color: '#06b6d4',
        rooms: [
            { id: 'cloud-aws', title: 'AWS Security Mastery', desc: 'Securing AWS S3 and IAM.', time: '120 min', points: 300, difficulty: 'Medium' },
            { id: 'cloud-azure', title: 'Azure Security', desc: 'Azure AD and cloud-native services.', time: '90 min', points: 250, difficulty: 'Medium' }
        ]
    },
    forensics: {
        title: 'Digital Forensics',
        titleAr: 'التحقيق الجنائي الرقمي',
        subtitle: 'Investigate digital crime scenes and artifacts.',
        icon: Microscope,
        color: '#6366f1',
        rooms: [
            { id: 'forensics-1', title: 'Disk Imaging', desc: 'Acquisition and analysis of raw disks.', time: '90 min', points: 150, difficulty: 'Medium' },
            { id: 'forensics-2', title: 'Memory Forensics', desc: 'Volatilty 3: Finding malware in RAM.', time: '120 min', points: 300, difficulty: 'Hard' },
            { id: 'forensics-3', title: 'Log Investigation', desc: 'Finding intruders in Event Logs.', time: '60 min', points: 100, difficulty: 'Easy' },
            { id: 'forensics-4', title: 'Autopsy Basics', desc: 'GUI-based forensic analysis.', time: '45 min', points: 100, difficulty: 'Easy' }
        ]
    },
    linux: {
        title: 'Linux Security',
        titleAr: 'أمن لينكس',
        subtitle: 'Master the core of the hacker OS.',
        icon: Terminal,
        color: '#f59e0b',
        rooms: [
            { id: 'linux-1', title: 'Linux Basics', desc: 'Navigation, files, and users.', time: '45 min', points: 50, difficulty: 'Easy' },
            { id: 'linux-2', title: 'Privilege Escalation', desc: 'GTFOBins and SUID abuses.', time: '90 min', points: 200, difficulty: 'Medium' },
            { id: 'linux-3', title: 'Kernel Exploits', desc: 'DirtyCow and modern vulnerabilities.', time: '120 min', points: 350, difficulty: 'Hard' },
            { id: 'linux-4', title: 'Cron Persistence', desc: 'Scheduling malicious tasks.', time: '30 min', points: 80, difficulty: 'Easy' }
        ]
    },
    scripting: {
        title: 'Scripting & Automation',
        titleAr: 'البرمجة والأتمتة',
        subtitle: 'Automate your security workflow with code.',
        icon: Code,
        color: '#10b981',
        rooms: [
            { id: 'python-1', title: 'Python for Hackers', desc: 'Write your own scanners and C2s.', time: '120 min', points: 250, difficulty: 'Medium' },
            { id: 'bash-1', title: 'Bash Automation', desc: 'Chain commands for fast recon.', time: '60 min', points: 120, difficulty: 'Easy' },
            { id: 'ps-1', title: 'PowerShell Offensive', desc: 'Exploiting Windows via PS.', time: '90 min', points: 200, difficulty: 'Hard' }
        ]
    }
};
