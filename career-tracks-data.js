/* career-tracks-data.js - Comprehensive Career Track Data */

const CareerTracksData = {
    tracks: [
        // ==================== SOC ANALYST ====================
        {
            id: 'soc-analyst',
            title: 'SOC Analyst',
            titleAr: 'محلل SOC',
            icon: 'fa-user-shield',
            color: '#10b981',
            difficulty: 'Medium',
            duration: '12d',
            level: 'Entry-Level',
            salary: '$60,000 - $95,000',
            description: `The SOC Analyst Job Role Path is designed for aspiring Security Operations Center professionals who want to build expertise in monitoring, detecting, and responding to security threats. The course provides hands-on training in SIEM tools, log analysis, and incident triage. Students will gain practical experience with industry-standard tools and methodologies, learning how to identify security incidents, analyze alerts, and recommend effective countermeasures. By the end of this Path, participants will be equipped with the knowledge and skills required to work as a Tier 1 or Tier 2 SOC Analyst.`,
            pathIncludes: {
                modules: 8,
                interactiveSections: 32,
                assessments: 4,
                badge: true,
                cubes: 520
            },
            certifications: ['CompTIA Security+', 'CompTIA CySA+', 'Splunk Core Certified User'],
            skills: ['SIEM Operations', 'Log Analysis', 'Threat Detection', 'Incident Triage', 'Malware Analysis'],
            modules: [
                {
                    id: 'soc-fundamentals',
                    title: 'SOC Fundamentals',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Easy',
                    duration: '1d',
                    tier: 'Tier I',
                    description: 'Introduction to Security Operations Centers and the role of a SOC Analyst.',
                    rooms: [
                        { title: 'Introduction to SOC', points: 50 },
                        { title: 'SOC Analyst Workflow', points: 50 },
                        { title: 'Understanding Alerts and Events', points: 75 }
                    ]
                },
                {
                    id: 'networking-fundamentals',
                    title: 'Networking Fundamentals',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Easy',
                    duration: '2d',
                    tier: 'Tier I',
                    description: 'Master TCP/IP, DNS, HTTP, and network protocols essential for SOC work.',
                    rooms: [
                        { title: 'OSI Model Deep Dive', points: 75 },
                        { title: 'TCP/IP Fundamentals', points: 75 },
                        { title: 'DNS and DHCP', points: 50 },
                        { title: 'HTTP/HTTPS Traffic Analysis', points: 100 }
                    ]
                },
                {
                    id: 'siem-fundamentals',
                    title: 'SIEM Fundamentals',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    isNew: true,
                    description: 'Learn Security Information and Event Management systems and log analysis.',
                    rooms: [
                        { title: 'Introduction to SIEM', points: 50 },
                        { title: 'Splunk Basics', points: 100 },
                        { title: 'Writing SPL Queries', points: 100 },
                        { title: 'Creating Dashboards', points: 75 }
                    ]
                },
                {
                    id: 'threat-detection',
                    title: 'Threat Detection and Analysis',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Identify and analyze security threats using various detection techniques.',
                    rooms: [
                        { title: 'IOCs and IOAs', points: 75 },
                        { title: 'MITRE ATT&CK Framework', points: 100 },
                        { title: 'Threat Intelligence Platforms', points: 100 },
                        { title: 'Behavioral Analysis', points: 100 }
                    ]
                },
                {
                    id: 'incident-triage',
                    title: 'Incident Triage',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Learn to prioritize and categorize security incidents effectively.',
                    rooms: [
                        { title: 'Alert Prioritization', points: 75 },
                        { title: 'False Positive Identification', points: 100 },
                        { title: 'Escalation Procedures', points: 75 }
                    ]
                },
                {
                    id: 'malware-fundamentals',
                    title: 'Malware Fundamentals for SOC',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Understand malware types and basic analysis techniques.',
                    rooms: [
                        { title: 'Malware Types and Classification', points: 75 },
                        { title: 'Static Analysis Basics', points: 100 },
                        { title: 'Dynamic Analysis Sandbox', points: 100 }
                    ]
                },
                {
                    id: 'phishing-analysis-soc',
                    title: 'Phishing Analysis',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Easy',
                    duration: '1d',
                    tier: 'Tier I',
                    description: 'Analyze phishing emails and identify malicious indicators.',
                    rooms: [
                        { title: 'Email Header Analysis', points: 75 },
                        { title: 'URL and Attachment Analysis', points: 100 },
                        { title: 'Phishing Campaign Investigation', points: 100 }
                    ]
                },
                {
                    id: 'soc-capstone',
                    title: 'SOC Analyst Capstone',
                    type: 'assessment',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Put your skills to the test in a realistic SOC simulation.',
                    rooms: [
                        { title: 'SOC Simulation Day 1', points: 150 },
                        { title: 'SOC Simulation Day 2', points: 150 },
                        { title: 'Final Assessment', points: 200 }
                    ]
                }
            ]
        },

        // ==================== PENETRATION TESTER ====================
        {
            id: 'penetration-tester',
            title: 'Penetration Tester',
            titleAr: 'مختبر اختراق',
            icon: 'fa-bug',
            color: '#ef4444',
            difficulty: 'Hard',
            duration: '20d',
            level: 'Intermediate',
            salary: '$80,000 - $130,000',
            description: `The Penetration Tester Job Role Path is designed for professionals and aspiring security practitioners who want to build expertise in identifying and exploiting vulnerabilities in systems, networks, and applications. The course provides hands-on training in reconnaissance, exploitation, post-exploitation, and reporting. Students will gain practical experience with industry-standard tools like Nmap, Burp Suite, Metasploit, and custom scripts. By the end of this Path, participants will be equipped with the knowledge and skills required to perform authorized penetration tests and provide actionable recommendations.`,
            pathIncludes: {
                modules: 12,
                interactiveSections: 48,
                assessments: 5,
                badge: true,
                cubes: 840
            },
            certifications: ['OSCP', 'CEH', 'CompTIA PenTest+', 'GPEN'],
            skills: ['Network Penetration', 'Web Application Testing', 'Exploitation', 'Privilege Escalation', 'Report Writing'],
            modules: [
                {
                    id: 'pentest-fundamentals',
                    title: 'Penetration Testing Fundamentals',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Easy',
                    duration: '1d',
                    tier: 'Tier I',
                    description: 'Introduction to penetration testing methodology and ethics.',
                    rooms: [
                        { title: 'What is Penetration Testing?', points: 50 },
                        { title: 'Legal and Ethical Considerations', points: 50 },
                        { title: 'Pentest Methodology', points: 75 }
                    ]
                },
                {
                    id: 'recon-enumeration',
                    title: 'Reconnaissance and Enumeration',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Master information gathering and target enumeration techniques.',
                    rooms: [
                        { title: 'Passive Reconnaissance', points: 75 },
                        { title: 'Active Enumeration with Nmap', points: 100 },
                        { title: 'Service Enumeration', points: 100 },
                        { title: 'Web Enumeration', points: 100 }
                    ]
                },
                {
                    id: 'vulnerability-scanning',
                    title: 'Vulnerability Scanning',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Learn to identify vulnerabilities using automated scanning tools.',
                    rooms: [
                        { title: 'Nessus Fundamentals', points: 75 },
                        { title: 'OpenVAS Configuration', points: 75 },
                        { title: 'Vulnerability Prioritization', points: 100 }
                    ]
                },
                {
                    id: 'web-exploitation',
                    title: 'Web Application Exploitation',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    isNew: true,
                    description: 'Exploit common web vulnerabilities including SQLi, XSS, and more.',
                    rooms: [
                        { title: 'SQL Injection Deep Dive', points: 150 },
                        { title: 'Cross-Site Scripting (XSS)', points: 100 },
                        { title: 'Server-Side Request Forgery', points: 125 },
                        { title: 'Authentication Bypass', points: 125 },
                        { title: 'File Upload Vulnerabilities', points: 100 }
                    ]
                },
                {
                    id: 'network-exploitation',
                    title: 'Network Exploitation',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Exploit network services and protocols to gain access.',
                    rooms: [
                        { title: 'SMB Exploitation', points: 100 },
                        { title: 'SSH and FTP Attacks', points: 100 },
                        { title: 'SNMP Exploitation', points: 75 },
                        { title: 'Database Attacks', points: 100 }
                    ]
                },
                {
                    id: 'metasploit-mastery',
                    title: 'Metasploit Mastery',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Master the Metasploit Framework for exploitation and post-exploitation.',
                    rooms: [
                        { title: 'Metasploit Fundamentals', points: 75 },
                        { title: 'Exploitation with Metasploit', points: 100 },
                        { title: 'Meterpreter Deep Dive', points: 100 },
                        { title: 'Pivoting and Port Forwarding', points: 125 }
                    ]
                },
                {
                    id: 'linux-privesc',
                    title: 'Linux Privilege Escalation',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Escalate privileges on Linux systems using various techniques.',
                    rooms: [
                        { title: 'SUID/SGID Exploitation', points: 100 },
                        { title: 'Kernel Exploits', points: 125 },
                        { title: 'Sudo Misconfigurations', points: 100 },
                        { title: 'Cron Jobs and PATH Hijacking', points: 100 }
                    ]
                },
                {
                    id: 'windows-privesc',
                    title: 'Windows Privilege Escalation',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Escalate privileges on Windows systems using various techniques.',
                    rooms: [
                        { title: 'Token Impersonation', points: 100 },
                        { title: 'Service Exploitation', points: 125 },
                        { title: 'Registry and AlwaysInstallElevated', points: 100 },
                        { title: 'Windows Kernel Exploits', points: 125 }
                    ]
                },
                {
                    id: 'password-attacks',
                    title: 'Password Attacks',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Learn various password cracking and credential attack techniques.',
                    rooms: [
                        { title: 'Hash Cracking with Hashcat', points: 100 },
                        { title: 'Password Spraying', points: 75 },
                        { title: 'Credential Harvesting', points: 100 }
                    ]
                },
                {
                    id: 'ad-attacks',
                    title: 'Active Directory Attacks',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    description: 'Attack Active Directory environments using modern techniques.',
                    rooms: [
                        { title: 'AD Enumeration with BloodHound', points: 125 },
                        { title: 'Kerberoasting and AS-REP Roasting', points: 150 },
                        { title: 'Pass-the-Hash and Pass-the-Ticket', points: 150 },
                        { title: 'DCSync and Domain Admin', points: 175 }
                    ]
                },
                {
                    id: 'report-writing',
                    title: 'Penetration Test Reporting',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Easy',
                    duration: '1d',
                    tier: 'Tier I',
                    description: 'Write professional penetration test reports.',
                    rooms: [
                        { title: 'Report Structure and Format', points: 50 },
                        { title: 'Writing Executive Summaries', points: 75 },
                        { title: 'Technical Findings Documentation', points: 75 }
                    ]
                },
                {
                    id: 'pentest-capstone',
                    title: 'Pentest Capstone Challenge',
                    type: 'assessment',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    description: 'Complete a full penetration test on a realistic network.',
                    rooms: [
                        { title: 'External Network Assessment', points: 200 },
                        { title: 'Internal Network Pivot', points: 200 },
                        { title: 'Domain Compromise', points: 250 }
                    ]
                }
            ]
        },

        // ==================== SECURITY ENGINEER ====================
        {
            id: 'security-engineer',
            title: 'Security Engineer',
            titleAr: 'مهندس أمني',
            icon: 'fa-layer-group',
            color: '#3b82f6',
            difficulty: 'Hard',
            duration: '18d',
            level: 'Intermediate',
            salary: '$90,000 - $150,000',
            description: `The Security Engineer Job Role Path is designed for professionals who want to build expertise in designing, implementing, and maintaining secure systems and infrastructure. The course provides hands-on training in network security, cloud security, cryptography, and security architecture. Students will gain practical experience with firewalls, IDS/IPS, SIEM systems, and cloud security platforms. By the end of this Path, participants will be equipped with the knowledge and skills required to secure enterprise environments and ensure compliance with industry standards.`,
            pathIncludes: {
                modules: 10,
                interactiveSections: 40,
                assessments: 4,
                badge: true,
                cubes: 720
            },
            certifications: ['CISSP', 'AWS Security Specialty', 'Azure Security Engineer'],
            skills: ['Network Security', 'Cloud Security', 'Security Architecture', 'Cryptography', 'Compliance'],
            modules: [
                {
                    id: 'security-architecture',
                    title: 'Security Architecture Fundamentals',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Learn the principles of designing secure systems and architectures.',
                    rooms: [
                        { title: 'Defense in Depth', points: 75 },
                        { title: 'Zero Trust Architecture', points: 100 },
                        { title: 'Secure Network Design', points: 100 },
                        { title: 'Security Frameworks', points: 75 }
                    ]
                },
                {
                    id: 'network-security-eng',
                    title: 'Network Security Engineering',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Configure and manage network security devices.',
                    rooms: [
                        { title: 'Firewall Configuration', points: 100 },
                        { title: 'IDS/IPS Systems', points: 100 },
                        { title: 'VPN Implementation', points: 75 },
                        { title: 'Network Segmentation', points: 100 }
                    ]
                },
                {
                    id: 'cloud-security-eng',
                    title: 'Cloud Security',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    isNew: true,
                    description: 'Secure cloud environments across AWS, Azure, and GCP.',
                    rooms: [
                        { title: 'AWS Security Fundamentals', points: 100 },
                        { title: 'IAM and Access Control', points: 125 },
                        { title: 'Cloud Network Security', points: 100 },
                        { title: 'Container Security', points: 125 },
                        { title: 'Cloud Compliance', points: 75 }
                    ]
                },
                {
                    id: 'cryptography-eng',
                    title: 'Applied Cryptography',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Implement cryptographic solutions for data protection.',
                    rooms: [
                        { title: 'Encryption Algorithms', points: 100 },
                        { title: 'PKI and Certificates', points: 100 },
                        { title: 'Key Management', points: 100 },
                        { title: 'TLS/SSL Configuration', points: 75 }
                    ]
                },
                {
                    id: 'endpoint-security',
                    title: 'Endpoint Security',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Secure endpoints with EDR and hardening techniques.',
                    rooms: [
                        { title: 'EDR Solutions', points: 100 },
                        { title: 'System Hardening', points: 75 },
                        { title: 'Application Whitelisting', points: 75 }
                    ]
                },
                {
                    id: 'identity-access',
                    title: 'Identity and Access Management',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Implement secure identity and access management solutions.',
                    rooms: [
                        { title: 'Authentication Mechanisms', points: 75 },
                        { title: 'Multi-Factor Authentication', points: 75 },
                        { title: 'SSO and Federation', points: 100 },
                        { title: 'Privileged Access Management', points: 100 }
                    ]
                },
                {
                    id: 'devsecops',
                    title: 'DevSecOps',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Integrate security into CI/CD pipelines.',
                    rooms: [
                        { title: 'Secure SDLC', points: 75 },
                        { title: 'SAST and DAST', points: 100 },
                        { title: 'Container Security Scanning', points: 100 },
                        { title: 'Infrastructure as Code Security', points: 100 }
                    ]
                },
                {
                    id: 'compliance-grc',
                    title: 'Compliance and GRC',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Understand compliance frameworks and governance.',
                    rooms: [
                        { title: 'NIST Cybersecurity Framework', points: 75 },
                        { title: 'ISO 27001', points: 75 },
                        { title: 'PCI DSS Compliance', points: 75 }
                    ]
                },
                {
                    id: 'security-automation',
                    title: 'Security Automation',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Automate security tasks with Python and APIs.',
                    rooms: [
                        { title: 'Python for Security', points: 100 },
                        { title: 'SOAR Platforms', points: 100 },
                        { title: 'API Security Automation', points: 100 },
                        { title: 'Custom Security Tools', points: 125 }
                    ]
                },
                {
                    id: 'engineer-capstone',
                    title: 'Security Engineer Capstone',
                    type: 'assessment',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Design and implement a secure infrastructure.',
                    rooms: [
                        { title: 'Architecture Design', points: 150 },
                        { title: 'Implementation Challenge', points: 200 },
                        { title: 'Final Assessment', points: 150 }
                    ]
                }
            ]
        },

        // ==================== RED TEAMER ====================
        {
            id: 'red-teamer',
            title: 'Red Teamer',
            titleAr: 'عضو الفريق الأحمر',
            icon: 'fa-user-ninja',
            color: '#dc2626',
            difficulty: 'Expert',
            duration: '25d',
            level: 'Advanced',
            salary: '$100,000 - $180,000',
            description: `The Red Teamer Job Role Path is designed for advanced security professionals who want to master offensive security operations. The course provides comprehensive training in advanced adversary simulation, including initial access, persistence, lateral movement, command and control, and evasion techniques. Students will learn to emulate real-world threat actors and perform full-scope red team engagements. By the end of this Path, participants will be equipped with the skills to conduct sophisticated attacks and provide valuable insights to improve organizational security.`,
            pathIncludes: {
                modules: 14,
                interactiveSections: 56,
                assessments: 5,
                badge: true,
                cubes: 1200
            },
            certifications: ['OSCP', 'OSEP', 'CRTO', 'GXPN'],
            skills: ['Adversary Simulation', 'Evasion Techniques', 'C2 Frameworks', 'Social Engineering', 'Custom Tooling'],
            modules: [
                {
                    id: 'redteam-fundamentals',
                    title: 'Red Team Fundamentals',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '1d',
                    tier: 'Tier II',
                    description: 'Understanding red team operations and methodology.',
                    rooms: [
                        { title: 'Red Team vs Pentest', points: 50 },
                        { title: 'Red Team Methodology', points: 75 },
                        { title: 'Adversary Emulation', points: 100 }
                    ]
                },
                {
                    id: 'initial-access-rt',
                    title: 'Initial Access Techniques',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Master initial access techniques including phishing and exploitation.',
                    rooms: [
                        { title: 'Spear Phishing Campaigns', points: 125 },
                        { title: 'Weaponized Documents', points: 125 },
                        { title: 'Supply Chain Attacks', points: 150 },
                        { title: 'Drive-by Compromise', points: 100 }
                    ]
                },
                {
                    id: 'c2-frameworks',
                    title: 'Command and Control',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    isNew: true,
                    description: 'Deploy and operate C2 frameworks for red team engagements.',
                    rooms: [
                        { title: 'Cobalt Strike Basics', points: 150 },
                        { title: 'Havoc C2 Framework', points: 125 },
                        { title: 'Custom C2 Development', points: 175 },
                        { title: 'C2 Traffic Analysis', points: 100 }
                    ]
                },
                {
                    id: 'defense-evasion',
                    title: 'Defense Evasion',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Expert',
                    duration: '3d',
                    tier: 'Tier IV',
                    description: 'Bypass security controls and evade detection.',
                    rooms: [
                        { title: 'AV/EDR Evasion', points: 175 },
                        { title: 'AMSI Bypass Techniques', points: 150 },
                        { title: 'Payload Obfuscation', points: 150 },
                        { title: 'Living off the Land', points: 125 },
                        { title: 'Process Injection', points: 175 }
                    ]
                },
                {
                    id: 'persistence-techniques',
                    title: 'Persistence Techniques',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Establish persistence across Windows and Linux systems.',
                    rooms: [
                        { title: 'Registry Persistence', points: 100 },
                        { title: 'Scheduled Tasks and Services', points: 100 },
                        { title: 'DLL Hijacking', points: 125 },
                        { title: 'Rootkit Deployment', points: 150 }
                    ]
                },
                {
                    id: 'lateral-movement-rt',
                    title: 'Advanced Lateral Movement',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Move laterally through enterprise networks.',
                    rooms: [
                        { title: 'WMI and WinRM', points: 100 },
                        { title: 'PsExec and SMB', points: 100 },
                        { title: 'RDP Hijacking', points: 125 },
                        { title: 'DCOM Execution', points: 125 }
                    ]
                },
                {
                    id: 'ad-exploitation-rt',
                    title: 'Advanced AD Exploitation',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Expert',
                    duration: '3d',
                    tier: 'Tier IV',
                    description: 'Advanced attacks against Active Directory environments.',
                    rooms: [
                        { title: 'Unconstrained Delegation', points: 150 },
                        { title: 'Constrained Delegation', points: 150 },
                        { title: 'Resource-Based Delegation', points: 175 },
                        { title: 'AD CS Attacks', points: 200 },
                        { title: 'Golden Ticket Attacks', points: 175 }
                    ]
                },
                {
                    id: 'custom-tooling',
                    title: 'Custom Tooling Development',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Expert',
                    duration: '2d',
                    tier: 'Tier IV',
                    description: 'Develop custom tools for red team operations.',
                    rooms: [
                        { title: 'C# for Red Teamers', points: 150 },
                        { title: 'Go Offensive Development', points: 150 },
                        { title: 'Shellcode Development', points: 175 },
                        { title: 'Reflective DLL Injection', points: 175 }
                    ]
                },
                {
                    id: 'redteam-capstone',
                    title: 'Red Team Capstone',
                    type: 'assessment',
                    team: 'offensive',
                    difficulty: 'Expert',
                    duration: '5d',
                    tier: 'Tier IV',
                    description: 'Full-scope red team engagement simulation.',
                    rooms: [
                        { title: 'Initial Compromise', points: 200 },
                        { title: 'Network Domination', points: 250 },
                        { title: 'Objective Completion', points: 300 }
                    ]
                }
            ]
        },

        // ==================== INCIDENT RESPONDER ====================
        {
            id: 'incident-responder',
            title: 'Incident Responder',
            titleAr: 'مستجيب الحوادث',
            icon: 'fa-file-shield',
            color: '#6366f1',
            difficulty: 'Hard',
            duration: '16d',
            level: 'Intermediate',
            salary: '$85,000 - $140,000',
            description: `The Incident Responder Job Role Path is designed for security professionals who want to specialize in detecting, analyzing, and responding to security incidents. The course provides hands-on training in incident response methodology, digital forensics, malware analysis, and threat hunting. Students will learn to investigate breaches, contain threats, and recover systems using industry-standard tools and techniques. By the end of this Path, participants will be equipped with the skills to lead incident response efforts and minimize the impact of security incidents.`,
            pathIncludes: {
                modules: 10,
                interactiveSections: 40,
                assessments: 4,
                badge: true,
                cubes: 680
            },
            certifications: ['GCIH', 'GCFA', 'ECIH', 'CHFI'],
            skills: ['Incident Response', 'Digital Forensics', 'Malware Analysis', 'Threat Hunting', 'Memory Forensics'],
            modules: [
                {
                    id: 'ir-fundamentals',
                    title: 'Incident Response Fundamentals',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Easy',
                    duration: '1d',
                    tier: 'Tier I',
                    description: 'Introduction to incident response processes and procedures.',
                    rooms: [
                        { title: 'IR Lifecycle', points: 50 },
                        { title: 'IR Team Structure', points: 50 },
                        { title: 'Incident Classification', points: 75 }
                    ]
                },
                {
                    id: 'evidence-collection',
                    title: 'Evidence Collection and Preservation',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Collect and preserve digital evidence properly.',
                    rooms: [
                        { title: 'Chain of Custody', points: 75 },
                        { title: 'Disk Imaging', points: 100 },
                        { title: 'Memory Acquisition', points: 100 },
                        { title: 'Network Traffic Capture', points: 75 }
                    ]
                },
                {
                    id: 'windows-forensics',
                    title: 'Windows Forensics',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    isNew: true,
                    description: 'Analyze Windows systems for evidence of compromise.',
                    rooms: [
                        { title: 'Windows Artifacts', points: 100 },
                        { title: 'Registry Forensics', points: 125 },
                        { title: 'Event Log Analysis', points: 125 },
                        { title: 'Timeline Analysis', points: 100 },
                        { title: 'Browser Forensics', points: 75 }
                    ]
                },
                {
                    id: 'linux-forensics',
                    title: 'Linux Forensics',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Analyze Linux systems for evidence of compromise.',
                    rooms: [
                        { title: 'Linux Artifacts', points: 100 },
                        { title: 'Log Analysis', points: 100 },
                        { title: 'File System Analysis', points: 100 },
                        { title: 'Bash History and Cron', points: 75 }
                    ]
                },
                {
                    id: 'memory-forensics',
                    title: 'Memory Forensics',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Analyze memory dumps to detect malicious activity.',
                    rooms: [
                        { title: 'Volatility Fundamentals', points: 100 },
                        { title: 'Process Analysis', points: 125 },
                        { title: 'Network Connections', points: 100 },
                        { title: 'Detecting Injection', points: 125 }
                    ]
                },
                {
                    id: 'malware-analysis-ir',
                    title: 'Malware Analysis for IR',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Analyze malware to understand its capabilities and indicators.',
                    rooms: [
                        { title: 'Static Analysis Advanced', points: 100 },
                        { title: 'Dynamic Analysis', points: 125 },
                        { title: 'Behavioral Analysis', points: 100 },
                        { title: 'Extracting IOCs', points: 100 }
                    ]
                },
                {
                    id: 'threat-hunting',
                    title: 'Threat Hunting',
                    type: 'regular',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Proactively search for threats in your environment.',
                    rooms: [
                        { title: 'Hunting Methodology', points: 75 },
                        { title: 'Hypothesis-Driven Hunting', points: 100 },
                        { title: 'SIEM-Based Hunting', points: 100 },
                        { title: 'EDR Query Development', points: 125 }
                    ]
                },
                {
                    id: 'ir-capstone',
                    title: 'IR Capstone Challenge',
                    type: 'assessment',
                    team: 'defensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    description: 'Investigate a simulated breach from start to finish.',
                    rooms: [
                        { title: 'Breach Investigation', points: 200 },
                        { title: 'Root Cause Analysis', points: 175 },
                        { title: 'Final Report', points: 150 }
                    ]
                }
            ]
        },

        // ==================== BUG BOUNTY HUNTER ====================
        {
            id: 'bug-bounty-hunter',
            title: 'Bug Bounty Hunter',
            titleAr: 'صائد الثغرات',
            icon: 'fa-crosshairs',
            color: '#f59e0b',
            difficulty: 'Hard',
            duration: '14d',
            level: 'Intermediate',
            salary: 'Variable (Bounties)',
            description: 'The Bug Bounty Hunter path focuses on web application security and automated discovery. Learn to find critical vulnerabilities in real-world assets and report them for profit.',
            pathIncludes: {
                modules: 8,
                interactiveSections: 35,
                assessments: 3,
                badge: true,
                cubes: 600
            },
            certifications: ['eWPT', 'OSWE', 'Burp Suite Certified'],
            skills: ['Web Recon', 'Automated Scanning', 'Business Logic Errors', 'Reporting', 'API Hacking'],
            modules: [
                {
                    id: 'bb-recon',
                    title: 'Bounty Reconnaissance',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Medium',
                    duration: '2d',
                    tier: 'Tier II',
                    description: 'Advanced recon techniques for large scopes.',
                    rooms: [
                        { title: 'Subdomain Enumeration', points: 75 },
                        { title: 'Github Dorking', points: 75 },
                        { title: 'Asset Discovery', points: 100 }
                    ]
                },
                {
                    id: 'bb-web-vulns',
                    title: 'Common Bounty Vulns',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '3d',
                    tier: 'Tier III',
                    description: 'Focus on high-impact/low-hanging fruit.',
                    rooms: [
                        { title: 'IDOR in-depth', points: 125 },
                        { title: 'Race Conditions', points: 150 },
                        { title: 'OAuth Implementations', points: 125 }
                    ]
                },
                {
                    id: 'bb-capstone',
                    title: 'Bounty Capstone',
                    type: 'assessment',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '2d',
                    tier: 'Tier III',
                    description: 'Simulated bounty program challenge.',
                    rooms: [
                        { title: 'VDP Policy Review', points: 50 },
                        { title: 'Finding P1 Bug', points: 250 },
                        { title: 'Report Submission', points: 100 }
                    ]
                }
            ]
        },

        // ==================== WEB SECURITY ARCHITECTURE ====================
        {
            id: 'web-security-architecture',
            title: 'Web Security Architecture & Exploitation',
            titleAr: 'أمن تطبيقات الويب المعماري',
            icon: 'fa-shield-virus',
            color: '#8b5cf6',
            difficulty: 'Expert',
            duration: '6 Months',
            tier: 'Tier III',
            description: 'A complete journey from source code analysis to exploiting complex architectural flaws. Master Node.js, Advanced Data, and API Security.',
            descriptionAr: 'رحلة كاملة من فهم الكود المصدري إلى استغلال أعقد الثغرات المعمارية.',
            pathIncludes: {
                modules: 3,
                interactiveSections: 25,
                assessments: 3,
                cubes: 1000
            },
            certifications: ['OSWE', 'BSC', 'EWPTX'],
            skills: ['Source Code Review', 'Architecture Analysis', 'Exploit Chaining', 'Secure Coding'],
            modules: [
                {
                    id: 'course-nodejs-security',
                    title: 'Node.js & Express: From Logic to Runtime',
                    titleAr: 'أمن Node.js و Express',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '4 weeks',
                    tier: 'Tier III',
                    isNew: true,
                    rooms: [
                        { title: 'The Engine & Logic', points: 100 },
                        { title: 'JS Internals & Pollution', points: 150 },
                        { title: 'Auth & Session Engineering', points: 125 }
                    ]
                },
                {
                    id: 'course-advanced-data',
                    title: 'Advanced Data & Database Exploitation',
                    titleAr: 'استغلال قواعد البيانات المتقدم',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Hard',
                    duration: '4 weeks',
                    tier: 'Tier III',
                    isNew: true,
                    rooms: [
                        { title: 'SQL Injection Mastery', points: 150 },
                        { title: 'NoSQL & Polyglot', points: 125 },
                        { title: 'SSRF & Redis', points: 150 }
                    ]
                },
                {
                    id: 'course-modern-client-side',
                    title: 'Modern Client-Side & API Security',
                    titleAr: 'أمن الواجهات والأ API الحديثة',
                    type: 'regular',
                    team: 'offensive',
                    difficulty: 'Expert',
                    duration: '4 weeks',
                    tier: 'Tier III',
                    isNew: true,
                    rooms: [
                        { title: 'DOM & XSS Evolution', points: 125 },
                        { title: 'API Architecture', points: 150 },
                        { title: 'Race Conditions', points: 125 }
                    ]
                }
            ]
        }
    ],

    // Helper functions
    getTrackById(id) {
        return this.tracks.find(t => t.id === id) || null;
    },

    getAllTracks() {
        return this.tracks;
    },

    getTrackProgress(trackId) {
        const progressData = JSON.parse(localStorage.getItem('careerTrackProgress') || '{}');
        return progressData[trackId] || { completed: 0, total: 0 };
    },

    isTrackEnrolled(trackId) {
        const enrolled = JSON.parse(localStorage.getItem('enrolledCareerTracks') || '[]');
        return enrolled.includes(trackId);
    },

    enrollInTrack(trackId) {
        const enrolled = JSON.parse(localStorage.getItem('enrolledCareerTracks') || '[]');
        if (!enrolled.includes(trackId)) {
            enrolled.push(trackId);
            localStorage.setItem('enrolledCareerTracks', JSON.stringify(enrolled));
        }
    }
};

// Export
window.CareerTracksData = CareerTracksData;
console.log('Career Tracks Data loaded:', CareerTracksData.tracks.length, 'tracks');
