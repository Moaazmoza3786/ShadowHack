/* ============================================================
   UNIFIED LEARNING DATA - ShadowHack Platform
   Consolidated learning paths, units, rooms, and CTF challenges
   Phase 4.5: Full Professional Content
   ============================================================ */

const UnifiedLearningData = {
    // ==================== LEARNING PATHS (20 PATHS) ====================
    paths: [
        // --- FEATURED CAREER TRACKS (Starting with our flagship) ---
        {
            "id": "antigravity-pentester",
            "name": "Penetration Tester",
            "description": "Master the art of ethical hacking. From fundamentals to advanced exploitation techniques.",
            "icon": "fa-user-secret",
            "color": "#eab308",
            "difficulty": "career",
            "premium": true,
            "estimatedHours": 120,
            "totalRooms": 24,
            "type": "career",
            "units": [
                {
                    "id": "pt-fund",
                    "name": "Fundamentals",
                    "rooms": [
                        { "id": "pt-ethics", "title": "Ethics & Legal Issues", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Fundamentals/Ethics & Legal Issues.mdx", "points": 100 },
                        { "id": "pt-method", "title": "PT Methodologies", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Fundamentals/PT Methodologies.mdx", "points": 100 },
                        { "id": "pt-report", "title": "Reporting & Documentation", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Fundamentals/Reporting & Documentation.mdx", "points": 100 },
                        { "id": "pt-lab", "title": "Lab Setup Guide", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Fundamentals/Lab Setup Guide.mdx", "points": 100 }
                    ]
                },
                {
                    "id": "pt-recon",
                    "name": "Reconnaissance",
                    "rooms": [
                        { "id": "pt-passive", "title": "Passive Recon", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Reconnaissance/Passive Recon.mdx", "points": 100 },
                        { "id": "pt-active", "title": "Active Recon (Nmap)", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Reconnaissance/Active Recon (Nmap).mdx", "points": 100 },
                        { "id": "pt-dns", "title": "DNS Enumeration", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Reconnaissance/DNS Enumeration.mdx", "points": 100 },
                        { "id": "pt-osint", "title": "OSINT Frameworks", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Reconnaissance/OSINT Frameworks.mdx", "points": 100 }
                    ]
                },
                {
                    "id": "pt-vuln",
                    "name": "Vulnerability Assessment",
                    "rooms": [
                        { "id": "pt-scan-theory", "title": "Scanning Theory", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Vulnerability Assessment/Scanning Theory.mdx", "points": 100 },
                        { "id": "pt-nessus", "title": "Nessus Essentials", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Vulnerability Assessment/Nessus Essentials.mdx", "points": 100 },
                        { "id": "pt-manual", "title": "Manual Validation", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Vulnerability Assessment/Manual Validation.mdx", "points": 100 },
                        { "id": "pt-cvss", "title": "CVSS Scoring", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Vulnerability Assessment/CVSS Scoring.mdx", "points": 100 }
                    ]
                },
                {
                    "id": "pt-web",
                    "name": "Web Application Pentesting",
                    "rooms": [
                        { "id": "pt-sqli", "title": "SQL Injection", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Web Application Pentesting/SQL Injection.mdx", "points": 150 },
                        { "id": "pt-xss", "title": "Cross-Site Scripting", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Web Application Pentesting/Cross-Site Scripting.mdx", "points": 150 },
                        { "id": "pt-auth", "title": "Broken Auth", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Web Application Pentesting/Broken Auth.mdx", "points": 150 },
                        { "id": "pt-idor", "title": "IDOR", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Web Application Pentesting/IDOR.mdx", "points": 150 }
                    ]
                },
                {
                    "id": "pt-net",
                    "name": "Network Penetration Testing",
                    "rooms": [
                        { "id": "pt-privesc", "title": "Privilege Escalation", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Network Penetration Testing/Privilege Escalation.mdx", "points": 200 },
                        { "id": "pt-kerb", "title": "Active Directory (Kerberoasting)", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Network Penetration Testing/Active Directory (Kerberoasting).mdx", "points": 200 },
                        { "id": "pt-pivot", "title": "Pivoting & Tunneling", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Network Penetration Testing/Pivoting & Tunneling.mdx", "points": 200 },
                        { "id": "pt-msf", "title": "Metasploit Deep Dive", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Network Penetration Testing/Metasploit Deep Dive.mdx", "points": 150 }
                    ]
                },
                {
                    "id": "pt-adv",
                    "name": "Advanced Topics & Career",
                    "rooms": [
                        { "id": "pt-bof", "title": "Buffer Overflows", "difficulty": "insane", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Advanced Topics & Career/Buffer Overflows.mdx", "points": 300 },
                        { "id": "pt-av", "title": "Antivirus Evasion", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Advanced Topics & Career/Antivirus Evasion.mdx", "points": 250 },
                        { "id": "pt-c2", "title": "C2 Frameworks", "difficulty": "hard", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Advanced Topics & Career/C2 Frameworks.mdx", "points": 250 },
                        { "id": "pt-career", "title": "Career Path & Certs", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Penetration Tester/Advanced Topics & Career/Career Path & Certs.mdx", "points": 100 }
                    ]
                }
            ]
        },

        // --- EASY PATHS ---
        {
            "id": "pre-security",
            "name": "Pre Security",
            "description": "Foundation path for complete beginners. Break the fear of the black screen.",
            "icon": "fa-graduation-cap",
            "color": "#22c55e",
            "difficulty": "basic",
            "premium": false,
            "estimatedHours": 25,
            "totalRooms": 6,
            "type": "skill",
            "units": [
                {
                    "id": "ps-intro",
                    "name": "Intro to Cyber",
                    "rooms": [
                        { "id": "welcome", "title": "Welcome to BreachLabs", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Intro to Cyber/Welcome to BreachLabs.mdx" },
                        { "id": "careers", "title": "Cyber Careers", "difficulty": "easy", "type": "info" },
                        { "id": "setup", "title": "Lab Setup", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Intro to Cyber/Lab Setup.mdx" }
                    ]
                },
                {
                    "id": "ps-linux",
                    "name": "Linux Fundamentals",
                    "rooms": [
                        { "id": "linux-fund-1", "title": "Linux Fundamentals 1", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Linux Fundamentals/Linux Fundamentals 1.mdx", "machine_id": "penguin-ops" },
                        { "id": "linux-fund-2", "title": "Linux Fundamentals 2", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Linux Fundamentals/Linux Fundamentals 2.mdx", "machine_id": "penguin-ops" },
                        { "id": "linux-fund-3", "title": "Linux Fundamentals 3", "difficulty": "easy", "type": "lab", "machine_id": "penguin-ops" }
                    ]
                },
                {
                    "id": "ps-network",
                    "name": "Network Basics",
                    "rooms": [
                        { "id": "net-osi", "title": "OSI Model", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Network Basics/OSI Model.mdx" },
                        { "id": "net-tcp", "title": "TCP/IP Protocol", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Pre Security/Network Basics/TCP-IP Protocol.mdx", "machine_id": "netrunner-101" },
                        { "id": "net-dns", "title": "DNS & HTTP", "difficulty": "easy", "type": "lab", "machine_id": "netrunner-101" }
                    ]
                },
                {
                    "id": "ps-windows",
                    "name": "Windows Basics",
                    "rooms": [
                        { "id": "win-cmd", "title": "Windows CMD", "difficulty": "easy", "type": "lab", "machine_id": "blue-screen" },
                        { "id": "win-powershell", "title": "PowerShell Intro", "difficulty": "easy", "type": "lab", "machine_id": "blue-screen" },
                        { "id": "win-registry", "title": "Windows Registry", "difficulty": "easy", "type": "lab", "machine_id": "blue-screen" }
                    ]
                },
                {
                    "id": "ps-tools",
                    "name": "Tools Intro",
                    "rooms": [
                        { "id": "tool-kali", "title": "Kali Linux Overview", "difficulty": "easy", "type": "lab", "machine_id": "toolkit-zero" },
                        { "id": "tool-virtualbox", "title": "Virtualization", "difficulty": "easy", "type": "theory" },
                        { "id": "tool-recon", "title": "Recon Tools", "difficulty": "easy", "type": "lab", "machine_id": "toolkit-zero" }
                    ]
                }
            ]
        },
        {
            "id": "cyber-security-101",
            "name": "Cyber Security 101",
            "description": "Essential introduction to cyber security threats and principles.",
            "icon": "fa-shield-halved",
            "color": "#22c55e",
            "difficulty": "easy",
            "estimatedHours": 15,
            "type": "skill",
            "units": [
                {
                    "id": "cs101-principles",
                    "name": "Security Principles",
                    "rooms": [
                        { "id": "princ-cia", "title": "CIA Triad", "difficulty": "easy", "type": "theory" },
                        { "id": "princ-aaa", "title": "AAA Security", "difficulty": "easy", "type": "theory" },
                        { "id": "princ-defense", "title": "Defense in Depth", "difficulty": "easy", "type": "theory" }
                    ]
                },
                {
                    "id": "cs101-vectors",
                    "name": "Attack Vectors",
                    "rooms": [
                        { "id": "vec-phishing", "title": "Phishing Attacks", "difficulty": "easy", "type": "lab", "machine_id": "phish-pond" },
                        { "id": "vec-malware", "title": "Malware Types", "difficulty": "easy", "type": "lab", "machine_id": "phish-pond" }
                    ]
                }
            ]
        },
        {
            "id": "web-fundamentals",
            "name": "Web Fundamentals",
            "description": "Master the web. HTTP, HTML/JS, Cookies, and Browser Security.",
            "icon": "fa-globe",
            "color": "#22c55e",
            "difficulty": "easy",
            "estimatedHours": 20,
            "type": "skill",
            "units": [
                {
                    "id": "wf-http",
                    "name": "HTTP Protocol",
                    "rooms": [
                        { "id": "http-basics", "title": "Requests & Headers", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Web Fundamentals/HTTP Protocol/Requests and Headers.mdx", "machine_id": "packet-stream" },
                        { "id": "http-cookies", "title": "Cookies & Sessions", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Web Fundamentals/HTTP Protocol/Cookies and Sessions.mdx", "machine_id": "packet-stream" }
                    ]
                },
                {
                    "id": "wf-html",
                    "name": "Web Tech",
                    "rooms": [
                        { "id": "html-dom", "title": "DOM Manipulation", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Web Fundamentals/Web Tech/DOM Manipulation.mdx", "machine_id": "code-canvas" },
                        { "id": "html-js", "title": "JavaScript for Hackers", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Web Fundamentals/Web Tech/JavaScript for Hackers.mdx", "machine_id": "code-canvas" }
                    ]
                },
                {
                    "id": "wf-security",
                    "name": "Browser Security",
                    "rooms": [
                        { "id": "sec-sop", "title": "Same Origin Policy", "difficulty": "medium", "type": "lab", "machine_id": "browser-fort" },
                        { "id": "sec-devtools", "title": "DevTools Mastery", "difficulty": "easy", "type": "lab", "machine_id": "inspector-x" }
                    ]
                }
            ]
        },
        {
            "id": "linux-fundamentals",
            "name": "Linux Fundamentals",
            "description": "Master the Linux command line. Learn file navigation, permissions, and system administration.",
            "icon": "fa-linux",
            "color": "#22c55e",
            "difficulty": "easy",
            "estimatedHours": 18,
            "type": "skill",
            "units": [
                {
                    "id": "lf-cli",
                    "name": "Command Line Basics",
                    "rooms": [
                        {
                            "id": "cli-nav",
                            "title": "Navigation & Files",
                            "difficulty": "easy",
                            "type": "lab",
                            "machine_id": "linux-fundamentals",
                            "content": "<h3>File System Navigation</h3><p>In Linux, everything is a file. Use `ls` to list files and `cd` to change directories.</p><pre><code>$ ls -la\n$ cd /var/www/html\n$ pwd</code></pre><p><strong>Challenge:</strong> Navigate to `/tmp` and find the hidden file.</p>",
                            "tasks": [
                                {
                                    "title": "List files in current directory",
                                    "content": "Run `ls` command.",
                                    "questions": [
                                        {
                                            "id": "q1_base",
                                            "text": "What command lists files?",
                                            "answer": "ls",
                                            "points": 10,
                                            "hint": "It stands for LiSt.",
                                            "explanation": "The `ls` command is used to list directory contents. Adding flags like `-la` shows hidden files and details."
                                        }
                                    ]
                                },
                                {
                                    "title": "Change to /tmp directory",
                                    "content": "Run `cd /tmp`.",
                                    "questions": [
                                        {
                                            "id": "q2_base",
                                            "text": "What command changes directory?",
                                            "answer": "cd",
                                            "points": 10,
                                            "hint": "Change Directory",
                                            "explanation": "The `cd` (Change Directory) command is used to switch between folders. `cd /tmp` moves you to the temporary directory."
                                        }
                                    ]
                                },
                                {
                                    "title": "Read the flag file",
                                    "content": "Use `cat flag.txt`.",
                                    "questions": [
                                        {
                                            "id": "q3_base",
                                            "text": "What is the content of flag.txt?",
                                            "answer": "flag{linux_master}",
                                            "points": 20,
                                            "hint": "Use cat",
                                            "explanation": "**Full Solution:**\n1. Run `ls` to see the file.\n2. Run `cat flag.txt` to output its content.\n3. Copy the text starting with `flag{...}`."
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "id": "cli-grep",
                            "title": "Grep & Pipes",
                            "difficulty": "medium",
                            "type": "lab",
                            "machine_id": "linux-fundamentals",
                            "content": "<h3>Power of Pipes</h3><p>Combine commands using the pipe `|` operator. Use `grep` to search within output.</p><pre><code>$ cat access.log | grep '404'</code></pre>",
                            "tasks": [
                                { "title": "Find 'password' in config", "content": "Grep for 'password' in the config file." }
                            ]
                        }
                    ]
                },
                {
                    "id": "lf-perm",
                    "name": "Permissions & Users",
                    "rooms": [
                        {
                            "id": "perm-chmod",
                            "title": "Chmod & Chown",
                            "difficulty": "medium",
                            "type": "lab",
                            "machine_id": "linux-fundamentals",
                            "content": "<h3>Understanding Permissions</h3><p>Linux permissions are read (r), write (w), and execute (x).</p><pre><code>$ chmod +x script.sh\n$ chown user:group file.txt</code></pre>",
                            "tasks": [
                                { "title": "Make script executable", "content": "Use `chmod +x`." },
                                { "title": "Change file owner", "content": "Use `chown root file`." }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "network-fundamentals",
            "name": "Network Fundamentals",
            "description": "Understand how the internet works. Packets, Protocols, Subnetting, and Firewalls.",
            "icon": "fa-network-wired",
            "color": "#22c55e",
            "difficulty": "easy",
            "estimatedHours": 15,
            "type": "skill",
            "units": [
                {
                    "id": "nf-arch",
                    "name": "Architecture (Pro)",
                    "rooms": [
                        {
                            "id": "net-intro",
                            "title": "BreachLabs Core",
                            "difficulty": "hard",
                            "type": "network",
                            "description": "Infiltrate the core network. Pivot from the web server to the internal database.",
                            "points": 500,
                            "topology": {
                                "nodes": [
                                    { "id": "internet", "type": "internet", "label": "Internet", "x": 10, "y": 50, "icon": "fa-globe" },
                                    { "id": "firewall", "type": "firewall", "label": "WAF", "x": 30, "y": 50, "icon": "fa-shield-halved" },
                                    { "id": "web01", "type": "server", "label": "Web Server (DMZ)", "x": 50, "y": 50, "icon": "fa-server", "status": "compromised", "os": "linux", "ip": "10.10.10.5" },
                                    { "id": "db01", "type": "server", "label": "Database (Internal)", "x": 80, "y": 30, "icon": "fa-database", "status": "locked", "os": "windows", "ip": "172.16.5.10" },
                                    { "id": "ad01", "type": "server", "label": "Domain Controller", "x": 80, "y": 70, "icon": "fa-network-wired", "status": "locked", "os": "windows", "ip": "172.16.5.5" }
                                ],
                                "connections": [
                                    { "from": "internet", "to": "firewall" },
                                    { "from": "firewall", "to": "web01" },
                                    { "from": "web01", "to": "db01", "type": "dashed" },
                                    { "from": "web01", "to": "ad01", "type": "dashed" }
                                ]
                            }
                        }
                    ]
                },
                {
                    "id": "nf-osi",
                    "name": "OSI & TCP/IP",
                    "rooms": [
                        { "id": "osi-layers", "title": "The OSI Model Deep Dive", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Network Fundamentals/OSI & TCP-IP/The OSI Model Deep Dive.mdx" },
                        { "id": "osi-wireshark", "title": "Wireshark Intro", "difficulty": "easy", "type": "mdx", "mdxPath": "tracks/Network Fundamentals/OSI & TCP-IP/Wireshark Intro.mdx", "machine_id": "wireshark-bay" }
                    ]
                },
                {
                    "id": "nf-proto",
                    "name": "Protocols",
                    "rooms": [
                        { "id": "proto-tcp", "title": "TCP and UDP", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Network Fundamentals/Protocols/TCP and UDP.mdx", "machine_id": "protocol-arena" },
                        { "id": "proto-icmp", "title": "ICMP and ARP", "difficulty": "medium", "type": "mdx", "mdxPath": "tracks/Network Fundamentals/Protocols/ICMP and ARP.mdx", "machine_id": "protocol-arena" }
                    ]
                },
                {
                    "id": "nf-ip",
                    "name": "Addressing",
                    "rooms": [
                        { "id": "ip-subnet", "title": "Subnetting", "difficulty": "hard", "type": "lab", "machine_id": "subnet-master" }
                    ]
                },
                {
                    "id": "nf-dev",
                    "name": "Network Devices",
                    "rooms": [
                        { "id": "dev-firewall", "title": "Firewalls", "difficulty": "medium", "type": "lab", "machine_id": "bridge-control" }
                    ]
                }
            ]
        },
        {
            "id": "soc-level-1",
            "name": "SOC Level 1",
            "description": "Start your career as a Security Analyst. Monitor, Detect, and Respond.",
            "icon": "fa-user-shield",
            "color": "#22c55e",
            "difficulty": "medium",
            "estimatedHours": 40,
            "type": "career",
            "units": [
                {
                    "id": "soc-fund",
                    "name": "SOC Fundamentals",
                    "rooms": [
                        { "id": "soc-roles", "title": "SOC Structure", "difficulty": "easy", "type": "info" }
                    ]
                },
                {
                    "id": "soc-siem",
                    "name": "SIEM Basics",
                    "rooms": [
                        { "id": "siem-splunk", "title": "Splunk Intro", "difficulty": "medium", "type": "lab", "machine_id": "splunk-citadel" },
                        { "id": "siem-kql", "title": "KQL Basics", "difficulty": "medium", "type": "lab", "machine_id": "splunk-citadel" }
                    ]
                },
                {
                    "id": "soc-logs",
                    "name": "Log Analysis",
                    "rooms": [
                        { "id": "log-win", "title": "Windows Event Logs", "difficulty": "medium", "type": "lab", "machine_id": "log-hunter" },
                        { "id": "log-syslog", "title": "Syslog Analysis", "difficulty": "medium", "type": "lab", "machine_id": "log-hunter" }
                    ]
                },
                {
                    "id": "soc-ir",
                    "name": "Incident Response",
                    "rooms": [
                        { "id": "ir-process", "title": "IR Lifecycle", "difficulty": "easy", "type": "theory" },
                        { "id": "ir-practice", "title": "Incident Triage", "difficulty": "medium", "type": "lab", "machine_id": "incident-alpha" }
                    ]
                }
            ]
        },

        // --- MEDIUM PATHS ---
        {
            "id": "web-pentesting",
            "name": "Web Application Pentesting",
            "description": "Find and exploit web vulnerabilities. OWASP Top 10, Injection, and XSS.",
            "icon": "fa-bug-slash",
            "color": "#eab308",
            "difficulty": "intermediate",
            "estimatedHours": 60,
            "type": "career",
            "units": [
                {
                    "id": "web-recon",
                    "name": "Reconnaissance",
                    "rooms": [
                        { "id": "recon-sub", "title": "Subdomain Enum", "difficulty": "easy", "type": "lab", "machine_id": "recon-phantom" },
                        { "id": "recon-tech", "title": "Tech Stack ID", "difficulty": "easy", "type": "lab", "machine_id": "recon-phantom" }
                    ]
                },
                {
                    "id": "web-inj",
                    "name": "Injection Attacks",
                    "rooms": [
                        { "id": "inj-sql", "title": "SQL Injection", "difficulty": "hard", "type": "lab", "machine_id": "injection-nexus" },
                        { "id": "inj-cmd", "title": "Command Injection", "difficulty": "medium", "type": "lab", "machine_id": "injection-nexus" }
                    ]
                },
                {
                    "id": "web-xss",
                    "name": "XSS & Client Side",
                    "rooms": [
                        { "id": "xss-ref", "title": "Reflected XSS", "difficulty": "medium", "type": "lab", "machine_id": "xss-playground" },
                        { "id": "xss-store", "title": "Stored XSS", "difficulty": "medium", "type": "lab", "machine_id": "xss-playground" }
                    ]
                },
                {
                    "id": "web-auth",
                    "name": "Broken Authentication",
                    "rooms": [
                        { "id": "auth-brute", "title": "Brute Force", "difficulty": "medium", "type": "lab", "machine_id": "auth-breaker" },
                        { "id": "auth-jwt", "title": "JWT Attacks", "difficulty": "hard", "type": "lab", "machine_id": "auth-breaker" }
                    ]
                }
            ]
        },
        {
            "id": "jr-pentester",
            "name": "Jr Penetration Tester",
            "description": "Your first steps into ethical hacking. Methodology, Scanning, and Exploitation.",
            "icon": "fa-user-secret",
            "color": "#eab308",
            "difficulty": "intermediate",
            "estimatedHours": 50,
            "type": "career",
            "units": [
                {
                    "id": "jpt-scan",
                    "name": "Scanning & Enum",
                    "rooms": [
                        { "id": "scan-nmap", "title": "Nmap Mastery", "difficulty": "medium", "type": "lab", "machine_id": "scan-lab" },
                        { "id": "scan-vuln", "title": "Vuln Scanning", "difficulty": "easy", "type": "lab", "machine_id": "scan-lab" }
                    ]
                },
                {
                    "id": "jpt-exp",
                    "name": "Exploitation",
                    "rooms": [
                        { "id": "exp-meta", "title": "Metasploit", "difficulty": "medium", "type": "lab", "machine_id": "exploit-arena" },
                        { "id": "exp-manual", "title": "Manual Exploitation", "difficulty": "hard", "type": "lab", "machine_id": "exploit-arena" }
                    ]
                },
                {
                    "id": "jpt-priv",
                    "name": "Privilege Escalation",
                    "rooms": [
                        { "id": "priv-lin", "title": "Linux PrivEsc", "difficulty": "medium", "type": "lab", "machine_id": "privilege-tower" },
                        { "id": "priv-win", "title": "Windows PrivEsc", "difficulty": "medium", "type": "lab", "machine_id": "privilege-tower" }
                    ]
                }
            ]
        },

        // --- HARD PATHS ---
        {
            "id": "off-pentest",
            "name": "Offensive Pentesting",
            "description": "Advanced exploitation. Buffer Overflows, Active Directory, and Evasion.",
            "icon": "fa-dragon",
            "color": "#ef4444",
            "difficulty": "advanced",
            "estimatedHours": 85,
            "type": "career",
            "units": [
                {
                    "id": "op-bof",
                    "name": "Buffer Overflows",
                    "rooms": [
                        { "id": "bof-stack", "title": "Stack Overflow", "difficulty": "insane", "type": "lab", "machine_id": "overflow-abyss" }
                    ]
                },
                {
                    "id": "op-ad",
                    "name": "Active Directory",
                    "rooms": [
                        { "id": "ad-enum", "title": "AD Enumeration", "difficulty": "hard", "type": "lab", "machine_id": "domain-breach" },
                        { "id": "ad-kerb", "title": "Kerberoasting", "difficulty": "hard", "type": "lab", "machine_id": "domain-breach" }
                    ]
                }
            ]
        },
        {
            "id": "red-teaming",
            "name": "Red Teaming",
            "description": "Simulate advanced adversaries. C2, Lateral Movement, and OPSEC.",
            "icon": "fa-crosshairs",
            "color": "#ef4444",
            "difficulty": "advanced",
            "estimatedHours": 80,
            "type": "career",
            "units": [
                {
                    "id": "rt-c2",
                    "name": "C2 Infrastructure",
                    "rooms": [
                        { "id": "c2-setup", "title": "C2 Setup", "difficulty": "hard", "type": "lab", "machine_id": "command-center" }
                    ]
                },
                {
                    "id": "rt-evasion",
                    "name": "Defense Evasion",
                    "rooms": [
                        { "id": "ev-av", "title": "AV Evasion", "difficulty": "insane", "type": "lab", "machine_id": "shadow-evade" }
                    ]
                }
            ]
        },
        // --- SPECIALIST PATHS ---
        {
            "id": "soc-level-2",
            "name": "SOC Level 2",
            "description": "Senior Analyst skills. Threat Hunting, Malware Analysis, and Digital Forensics.",
            "icon": "fa-user-shield",
            "color": "#a855f7",
            "difficulty": "advanced",
            "estimatedHours": 60,
            "type": "career",
            "units": [
                { "id": "soc2-hunt", "name": "Threat Hunting", "rooms": [{ "id": "hunt-intro", "title": "Hunting Methodology", "difficulty": "medium", "type": "theory" }, { "id": "hunt-elastic", "title": "Elastic Hunting", "difficulty": "hard", "type": "lab", "machine_id": "elastic-stack" }] },
                { "id": "soc2-mal", "name": "Malware Analysis", "rooms": [{ "id": "mal-static", "title": "Static Analysis", "difficulty": "hard", "type": "lab", "machine_id": "checkmate" }, { "id": "mal-dynamic", "title": "Dynamic Analysis", "difficulty": "hard", "type": "lab", "machine_id": "checkmate" }] }
            ]
        },
        {
            "id": "cloud-security",
            "name": "Cloud Security Profile",
            "description": "Secure AWS, Azure, and GCP environments. Auditing and Hardening.",
            "icon": "fa-cloud",
            "color": "#3b82f6",
            "difficulty": "advanced",
            "estimatedHours": 45,
            "type": "career",
            "units": [
                { "id": "cloud-aws", "name": "AWS Security", "rooms": [{ "id": "aws-iam", "title": "IAM PrivEsc", "difficulty": "medium", "type": "lab", "machine_id": "cloud-goat" }, { "id": "aws-s3", "title": "S3 Buckets", "difficulty": "easy", "type": "lab", "machine_id": "cloud-goat" }] },
                { "id": "cloud-azure", "name": "Azure Security", "rooms": [{ "id": "az-ad", "title": "Azure AD", "difficulty": "hard", "type": "lab", "machine_id": "cloud-goat" }] }
            ]
        },
        {
            "id": "devsecops",
            "name": "DevSecOps",
            "description": "Integrate security into the SDLC. CI/CD, Containers, and Kubernetes.",
            "icon": "fa-infinity",
            "color": "#eab308",
            "difficulty": "advanced",
            "estimatedHours": 40,
            "type": "career",
            "units": [
                { "id": "dso-docker", "name": "Container Security", "rooms": [{ "id": "docker-esc", "title": "Docker Breakouts", "difficulty": "hard", "type": "lab", "machine_id": "docker-labs" }] },
                { "id": "dso-k8s", "name": "Kubernetes", "rooms": [{ "id": "k8s-attack", "title": "Attacking K8s", "difficulty": "insane", "type": "lab", "machine_id": "k8s-goat" }] }
            ]
        },
        {
            "id": "mobile-hacking",
            "name": "Mobile Application Security",
            "description": "Pentesting Android and iOS applications.",
            "icon": "fa-mobile-screen",
            "color": "#ef4444",
            "difficulty": "advanced",
            "estimatedHours": 35,
            "type": "career",
            "units": [
                { "id": "mob-android", "name": "Android", "rooms": [{ "id": "and-debug", "title": "ADB & Smali", "difficulty": "medium", "type": "lab", "machine_id": "android-lab" }, { "id": "and-re", "title": "APK Reversing", "difficulty": "hard", "type": "lab", "machine_id": "android-lab" }] },
                { "id": "mob-ios", "name": "iOS", "rooms": [{ "id": "ios-jail", "title": "Jailbreak Detection", "difficulty": "hard", "type": "theory" }] }
            ]
        },
        {
            "id": "iot-security",
            "name": "IoT & Hardware Hacking",
            "description": "Hacking embedded devices, firmware, and radio protocols.",
            "icon": "fa-microchip",
            "color": "#ef4444",
            "difficulty": "insane",
            "estimatedHours": 30,
            "type": "skill",
            "units": [
                { "id": "iot-firm", "name": "Firmware", "rooms": [{ "id": "firm-ext", "title": "Extraction", "difficulty": "medium", "type": "lab", "machine_id": "iot-lab" }] },
                { "id": "iot-sdr", "name": "Radio (SDR)", "rooms": [{ "id": "sdr-replay", "title": "Replay Attacks", "difficulty": "medium", "type": "theory" }] }
            ]
        },
        {
            "id": "malware-analysis",
            "name": "Malware Analysis",
            "description": "Dissect malicious software to understand its behavior.",
            "icon": "fa-virus",
            "color": "#ef4444",
            "difficulty": "advanced",
            "estimatedHours": 50,
            "type": "skill",
            "units": [
                { "id": "mal-basic", "name": "Basic Analysis", "rooms": [{ "id": "mal-strings", "title": "Strings & Packing", "difficulty": "medium", "type": "lab", "machine_id": "flare-vm" }] },
                { "id": "mal-adv", "name": "Advanced RE", "rooms": [{ "id": "mal-assembly", "title": "x86 Assembly", "difficulty": "hard", "type": "lab", "machine_id": "flare-vm" }] }
            ]
        },
        {
            "id": "security-engineer",
            "name": "Security Engineering",
            "description": "Building secure systems and networks.",
            "icon": "fa-helmet-safety",
            "color": "#3b82f6",
            "difficulty": "intermediate",
            "estimatedHours": 40,
            "type": "career",
            "units": [
                { "id": "eng-arch", "name": "Architecture", "rooms": [{ "id": "arch-zero", "title": "Zero Trust", "difficulty": "medium", "type": "theory" }] },
                { "id": "eng-harden", "name": "Hardening", "rooms": [{ "id": "hard-lin", "title": "Linux Hardening", "difficulty": "medium", "type": "lab", "machine_id": "bastion-host" }] }
            ]
        },
        {
            "id": "grc-audit",
            "name": "GRC & Auditing",
            "description": "Governance, Risk management, and Compliance standards.",
            "icon": "fa-scale-balanced",
            "color": "#64748b",
            "difficulty": "intermediate",
            "estimatedHours": 25,
            "type": "skill",
            "units": [
                { "id": "grc-std", "name": "Standards", "rooms": [{ "id": "std-iso", "title": "ISO 27001", "difficulty": "easy", "type": "theory" }, { "id": "std-gdpr", "title": "GDPR", "difficulty": "easy", "type": "theory" }] }
            ]
        },
        {
            "id": "forensics-specialist",
            "name": "Digital Forensics",
            "description": "Deep dive into dead-box forensics and artifact analysis.",
            "icon": "fa-magnifying-glass",
            "color": "#3b82f6",
            "difficulty": "advanced",
            "estimatedHours": 45,
            "type": "career",
            "units": [
                {
                    "id": "for-disk", "name": "Disk Forensics",
                    "rooms": [{ "id": "disk-ntfs", "title": "NTFS Artifacts", "difficulty": "medium", "type": "lab", "machine_id": "forensic-box" }]
                },
                {
                    "id": "for-mem", "name": "Memory Forensics",
                    "rooms": [{ "id": "mem-vol", "title": "Volatility Advanced", "difficulty": "hard", "type": "lab", "machine_id": "forensic-box" }]
                }
            ]
        },
        {
            "id": "exploit-dev",
            "name": "Exploit Development",
            "description": "Writing custom exploits for 0-day vulnerabilities.",
            "icon": "fa-bomb",
            "color": "#ef4444",
            "difficulty": "insane",
            "estimatedHours": 80,
            "type": "career",
            "units": [
                { "id": "exp-shell", "name": "Shellcoding", "rooms": [{ "id": "shell-win", "title": "Windows Shellcode", "difficulty": "insane", "type": "lab", "machine_id": "exploit-dev-vm" }] },
                { "id": "exp-kernel", "name": "Kernel Exploitation", "rooms": [{ "id": "kern-driver", "title": "Driver Exploitation", "difficulty": "insane", "type": "lab", "machine_id": "exploit-dev-vm" }] }
            ]
        }
    ],

    // ==================== COURSES (NEW LAYER) ====================
    courses: [
        {
            id: 'cyber-fundamentals',
            title: 'Cybersecurity Fundamentals',
            description: 'The ultimate starting point. Learn the core principles of security, networking, and operating systems.',
            difficulty: 'Beginner',
            icon: 'fa-shield-halved',
            modules: [
                { title: 'Intro to Cyber Security', rooms: new Array(3) },
                { title: 'Networking 101', rooms: new Array(4) },
                { title: 'Linux Basics', rooms: new Array(5) }
            ]
        },
        {
            id: 'adv-pentest',
            title: 'Advanced Penetration Testing',
            description: 'Master advanced network exploitation, evasion techniques, and post-exploitation tactics.',
            difficulty: 'Advanced',
            icon: 'fa-dragon',
            modules: [
                { title: 'Advanced Scanning', rooms: new Array(3) },
                { title: 'Evasion Techniques', rooms: new Array(4) },
                { title: 'Post-Exploitation', rooms: new Array(5) }
            ]
        },
        {
            id: 'ad-attacks',
            title: 'Active Directory Attacks',
            description: 'Dominate Windows environments. Learn Kerberoasting, Golden Tickets, and Forest Trust abuse.',
            difficulty: 'Advanced',
            icon: 'fa-sitemap',
            modules: [
                { title: 'AD Enumeration', rooms: new Array(3) },
                { title: 'Lateral Movement', rooms: new Array(4) },
                { title: 'Domain Dominance', rooms: new Array(3) }
            ]
        },
        {
            id: 'web-exploits',
            title: 'Web Application Exploitation',
            description: 'Deep dive into modern web vulnerabilities including Deserialization, SSTI, and OAuth abuse.',
            difficulty: 'Advanced',
            icon: 'fa-bug',
            modules: [
                { title: 'Injection Attacks', rooms: new Array(4) },
                { title: 'Broken Auth', rooms: new Array(3) },
                { title: 'Modern Vulnerabilities', rooms: new Array(4) }
            ]
        },
        {
            id: 'soc-eng-osint',
            title: 'Social Engineering & OSINT',
            description: 'The art of human hacking and Open Source Intelligence gathering mastery.',
            difficulty: 'Intermediate',
            icon: 'fa-user-secret',
            modules: [
                { title: 'OSINT Methodologies', rooms: new Array(3) },
                { title: 'Phishing Campaigns', rooms: new Array(3) },
                { title: 'Physical Security', rooms: new Array(2) }
            ]
        }
    ],

    // ==================== MODULES (15 MODULES) ====================
    modules: [
        // --- BLUE TEAM ---
        {
            "id": "blue-honeynet",
            "title": "Honeynet Collapse",
            "team": "blue",
            "difficulty": "medium",
            "estimatedTime": "4 hours",
            "rooms": [
                { "id": "honey-1", "title": "Memory Forensics", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "honeytrap-prime", "tasks": [{ "title": "Analyze Memory", "content": "Use Volatility to find the malware process." }] },
                { "id": "honey-2", "title": "Log Correlation", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "honeytrap-prime", "tasks": [{ "title": "Correlate Logs", "content": "Find the entry vector in auth.log." }] },
                { "id": "honey-3", "title": "Threat Intel", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "honeytrap-prime", "tasks": [{ "title": "IOC Extraction", "content": "Extract IP addresses and domains." }] }
            ],
            "description": "Analyze memory dumps and logs from a compromised honeynet.",
            "scenario": "A production honeynet has been compromised. Analyze dumps and logs to reconstruct the timeline.",
            "objectives": ["Memory forensics", "Log correlation", "Timeline reconstruction"],
            "machineId": "honeytrap-prime",
            "flags": 3,
            "icon": "fa-network-wired",
            "color": "#3b82f6"
        },
        {
            "id": "blue-frameworks",
            "title": "Cyber Defence Frameworks",
            "team": "blue",
            "difficulty": "easy",
            "estimatedTime": "3 hours",
            "rooms": [
                { "id": "fw-mitre", "title": "MITRE ATT&CK", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "framework-arena", "tasks": [{ "title": "Map Techniques", "content": "Map the observed behavior to ATT&CK ID." }] },
                { "id": "fw-killchain", "title": "Cyber Kill Chain", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "framework-arena", "tasks": [{ "title": "Identify Phase", "content": "Which phase is the attacker in?" }] },
                { "id": "fw-diamond", "title": "Diamond Model", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "framework-arena", "tasks": [{ "title": "Model Event", "content": "Create a Diamond Model for the event." }] }
            ],
            "description": "Learn MITRE ATT&CK, Kill Chain, and Diamond Model.",
            "scenario": "Standardize threat analysis using global frameworks.",
            "objectives": ["MITRE ATT&CK", "Kill Chain", "Diamond Model"],
            "machineId": "framework-arena",
            "flags": 3,
            "icon": "fa-shield-halved",
            "color": "#3b82f6"
        },
        {
            "id": "blue-siem",
            "title": "SIEM Mastery",
            "team": "blue",
            "difficulty": "medium",
            "estimatedTime": "6 hours",
            "rooms": [
                { "id": "siem-1", "title": "Data Ingestion", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "splunk-fortress", "tasks": [{ "title": "Ingest Logs", "content": "Configure inputs.conf to ingest logs." }] },
                { "id": "siem-2", "title": "SPL Queries", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "splunk-fortress", "tasks": [{ "title": "Write Queries", "content": "Search for failed login attempts > 10." }] },
                { "id": "siem-3", "title": "Alerting", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "splunk-fortress", "tasks": [{ "title": "Create Alert", "content": "Trigger an alert on brute force." }] }
            ],
            "description": "Configure and operate a SIEM platform.",
            "scenario": "Manage a Splunk instance, write rules, and detect threats.",
            "objectives": ["SPL Language", "Correlation Rules", "Dashboards"],
            "machineId": "splunk-fortress",
            "flags": 3,
            "icon": "fa-chart-line",
            "color": "#3b82f6"
        },
        {
            "id": "blue-ir",
            "title": "Incident Response Ops",
            "team": "blue",
            "difficulty": "hard",
            "estimatedTime": "8 hours",
            "rooms": [
                { "id": "ir-1", "title": "Containment", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "incident-omega", "tasks": [{ "title": "Isolate Host", "content": "Cut network access for the infected host." }] },
                { "id": "ir-2", "title": "Eradication", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "incident-omega", "tasks": [{ "title": "Remove Malware", "content": "Delete persistence keys and files." }] }
            ],
            "description": "Contain, eradicate, and recover from a live incident.",
            "scenario": "Ransomware outbreak! You have 2 hours to save the network.",
            "objectives": ["Containment", "Evidence Preservation", "Recovery"],
            "machineId": "incident-omega",
            "flags": 2,
            "icon": "fa-file-medical-alt",
            "color": "#3b82f6"
        },
        {
            "id": "blue-hunt",
            "title": "Threat Hunting Elite",
            "team": "blue",
            "difficulty": "hard",
            "estimatedTime": "6 hours",
            "rooms": [
                { "id": "hunt-1", "title": "Hypothesis", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "hunter-grounds", "tasks": [{ "title": "Form Hypothesis", "content": "Assume DNS tunneling is occurring." }] },
                { "id": "hunt-2", "title": "Hunting", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "hunter-grounds", "tasks": [{ "title": "Find Anomalies", "content": "Identify long DNS queries." }] }
            ],
            "description": "Proactively hunt for threats using hypothesis-driven techniques.",
            "scenario": "No alerts, but intelligence suggests an APT is present.",
            "objectives": ["Hunting Hypothesis", "Sigma Rules", "Behavioral Analysis"],
            "machineId": "hunter-grounds",
            "flags": 2,
            "icon": "fa-crosshairs",
            "color": "#3b82f6"
        },

        // --- RED TEAM ---
        {
            "id": "red-osint",
            "title": "OSINT Operations",
            "team": "red",
            "difficulty": "easy",
            "estimatedTime": "4 hours",
            "rooms": [
                { "id": "osint-1", "title": "Google Dorking", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "osint-target", "tasks": [{ "title": "Find Files", "content": "Locate confidential PDFs." }] },
                { "id": "osint-2", "title": "Social Media", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "osint-target", "tasks": [{ "title": "Employee Recon", "content": "Identify key personnel." }] }
            ],
            "description": "Gather intelligence using only public information.",
            "scenario": "Target 'TechSecure Corp' using passive reconnaissance.",
            "objectives": ["Google Dorking", "Social Media Intel", "Infrastructure Recon"],
            "machineId": "osint-target",
            "flags": 2,
            "icon": "fa-eye",
            "color": "#ef4444"
        },
        {
            "id": "red-access",
            "title": "Initial Access Tactics",
            "team": "red",
            "difficulty": "medium",
            "estimatedTime": "5 hours",
            "rooms": [
                { "id": "access-1", "title": "Phishing", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "breach-point", "tasks": [{ "title": "Craft Payload", "content": "Create a malicious Office macro." }] },
                { "id": "access-2", "title": "Exploit Public App", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "breach-point", "tasks": [{ "title": "CVE Exploit", "content": "Exploit the vulnerable web server." }] }
            ],
            "description": "Gain initial access to corporate networks.",
            "scenario": "Breach the perimeter of a secured organization.",
            "objectives": ["Phishing", "Macro Attacks", "Web Exploits"],
            "machineId": "breach-point",
            "flags": 2,
            "icon": "fa-door-open",
            "color": "#ef4444"
        },
        {
            "id": "red-post",
            "title": "Post-Exploitation",
            "team": "red",
            "difficulty": "hard",
            "estimatedTime": "6 hours",
            "rooms": [
                { "id": "post-1", "title": "Persistence", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "persist-domain", "tasks": [{ "title": "Registry Run Key", "content": "Add persistence via Registry." }] },
                { "id": "post-2", "title": "Cred Harvesting", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "persist-domain", "tasks": [{ "title": "Dump LSASS", "content": "Extract cleartext passwords." }] }
            ],
            "description": "Shell upgrade, persistence, and privilege escalation.",
            "scenario": "You're in. Now stay in and become God.",
            "objectives": ["Persistence", "Credential Dumping", "Lateral Movement"],
            "machineId": "persist-domain",
            "flags": 2,
            "icon": "fa-ghost",
            "color": "#ef4444"
        },
        {
            "id": "red-evasion",
            "title": "Evasion Techniques",
            "team": "red",
            "difficulty": "hard",
            "estimatedTime": "5 hours",
            "rooms": [
                { "id": "ev-1", "title": "AMSI Bypass", "difficulty": "insane", "type": "lab", "points": 200, "machine_id": "shadow-ops", "tasks": [{ "title": "Patch AMSI", "content": "Disable AMSI in PowerShell." }] },
                { "id": "ev-2", "title": "Obfuscation", "difficulty": "hard", "type": "lab", "points": 150, "machine_id": "shadow-ops", "tasks": [{ "title": "Obfuscate Payload", "content": "Bypass static signature detection." }] }
            ],
            "description": "Evade EDR and AV detection.",
            "scenario": "Bypass modern defenses to execute your payload.",
            "objectives": ["AMSI Bypass", "Obfuscation", "LOLBins"],
            "machineId": "shadow-ops",
            "flags": 2,
            "icon": "fa-mask",
            "color": "#ef4444"
        },
        {
            "id": "red-c2",
            "title": "C2 Infrastructure",
            "team": "red",
            "difficulty": "hard",
            "estimatedTime": "6 hours",
            "rooms": [
                { "id": "c2-1", "title": "Sliver Setup", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "command-hq", "tasks": [{ "title": "Install Sliver", "content": "Setup the C2 server." }] }
            ],
            "description": "Operate Command & Control infrastructure.",
            "scenario": "Manage compromised hosts via a C2 framework.",
            "objectives": ["C2 Deployment", "Listeners", "Profiles"],
            "machineId": "command-hq",
            "flags": 1,
            "icon": "fa-server",
            "color": "#ef4444"
        },

        // --- MIXED ---
        {
            "id": "mix-script",
            "title": "Scripting for Hackers",
            "team": "purple",
            "difficulty": "medium",
            "estimatedTime": "5 hours",
            "rooms": [
                { "id": "script-1", "title": "Python Basics", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "script-lab", "tasks": [{ "title": "Port Scanner", "content": "Write a simple port scanner." }] },
                { "id": "script-2", "title": "Bash Automation", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "script-lab", "tasks": [{ "title": "Recon Script", "content": "Automate subdomain enumeration." }] }
            ],
            "description": "Automate hacking tasks with Python and Bash.",
            "scenario": "Build your own tools for recon and exploitation.",
            "objectives": ["Python", "Bash", "Automation"],
            "machineId": "script-lab",
            "flags": 2,
            "icon": "fa-scroll",
            "color": "#a855f7"
        },
        {
            "id": "mix-traffic",
            "title": "Network Analysis",
            "team": "purple",
            "difficulty": "medium",
            "estimatedTime": "4 hours",
            "rooms": [
                { "id": "net-1", "title": "Wireshark Filters", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "packet-storm", "tasks": [{ "title": "Filter HTTP", "content": "Find the login credentials." }] }
            ],
            "description": "Analyze traffic to identify attacks.",
            "scenario": "Dig into PCAPs to find the needle in the haystack.",
            "objectives": ["Wireshark", "Protocol Analysis", "Forensics"],
            "machineId": "packet-storm",
            "flags": 1,
            "icon": "fa-wifi",
            "color": "#a855f7"
        },
        {
            "id": "ad-forest",
            "title": "AD Forest Security",
            "team": "red",
            "difficulty": "hard",
            "estimatedTime": "8 hours",
            "rooms": [
                { "id": "ad-trust", "title": "Trust Issues", "difficulty": "hard", "type": "lab", "points": 100, "machine_id": "forest-breach", "tasks": [{ "title": "enumerate-trusts", "content": "Map capabilities across trusts." }] }
            ],
            "description": "Attacking multi-domain forests.",
            "scenario": "Break out of a child domain to control the forest root.",
            "objectives": ["Forest Trusts", "Enterprise Admin", "SID History"],
            "machineId": "forest-breach",
            "flags": 2,
            "icon": "fa-sitemap",
            "color": "#ef4444"
        },
        {
            "id": "bug-bounty",
            "title": "Bug Bounty Hunting",
            "team": "purple",
            "difficulty": "medium",
            "estimatedTime": "10 hours",
            "rooms": [
                { "id": "bb-recon", "title": "Wide Scope Recon", "difficulty": "easy", "type": "lab", "points": 50, "machine_id": "bounty-target", "tasks": [{ "title": "Asset Discovery", "content": "Find all subdomains and assets." }] },
                { "id": "bb-vuln", "title": "Business Logic", "difficulty": "medium", "type": "lab", "points": 100, "machine_id": "bounty-target", "tasks": [{ "title": "Logic Flaw", "content": "Bypass payment logic." }] }
            ],
            "description": "Methodologies for bug bounty success.",
            "scenario": "Find bugs in a simulated program, earn points.",
            "objectives": ["Reconnaissance", "Logic Flaws", "Reporting"],
            "machineId": "bounty-target",
            "flags": 3,
            "icon": "fa-bug",
            "color": "#eab308"
        },
        // --- WI-FI SECURITY (12 Modules) ---
        { "id": "wifi-1", "title": "Wi-Fi Penetration Testing Basics", "difficulty": "easy", "machineId": "wifi-dojo", "flags": 3, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-1-r", "title": "Basics", "type": "lab" }] },
        { "id": "wifi-2", "title": "Wi-Fi Penetration Testing Tools", "difficulty": "medium", "machineId": "aircrack-lab", "flags": 4, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-2-r", "title": "Tools", "type": "lab" }] },
        { "id": "wifi-3", "title": "Attacking WPA/WPA2 Networks", "difficulty": "medium", "machineId": "wpa-breaker", "flags": 4, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-3-r", "title": "WPA2 Attack", "type": "lab" }] },
        { "id": "wifi-4", "title": "Attacking WPA3 Networks", "difficulty": "hard", "machineId": "wpa3-fortress", "flags": 3, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-4-r", "title": "WPA3 Attack", "type": "lab" }] },
        { "id": "wifi-5", "title": "Wi-Fi Password Cracking", "difficulty": "medium", "machineId": "crack-station", "flags": 5, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-5-r", "title": "Cracking", "type": "lab" }] },
        { "id": "wifi-6", "title": "Wi-Fi Evil Twin Attacks", "difficulty": "hard", "machineId": "evil-twin", "flags": 4, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-6-r", "title": "Evil Twin", "type": "lab" }] },
        { "id": "wifi-7", "title": "Bypassing Captive Portals", "difficulty": "medium", "machineId": "portal-bypass", "flags": 3, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-7-r", "title": "Captive Portal", "type": "lab" }] },
        { "id": "wifi-8", "title": "WEP Attacks", "difficulty": "easy", "machineId": "wep-legacy", "flags": 2, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-8-r", "title": "WEP Crack", "type": "lab" }] },
        { "id": "wifi-9", "title": "Attacking WPS", "difficulty": "medium", "machineId": "wps-exploit", "flags": 3, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-9-r", "title": "WPS Reaver", "type": "lab" }] },
        { "id": "wifi-10", "title": "Attacking Corporate Wi-Fi", "difficulty": "hard", "machineId": "corp-wireless", "flags": 5, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-10-r", "title": "Enterprise EAP", "type": "lab" }] },
        { "id": "wifi-11", "title": "Wireless Reconnaissance", "difficulty": "easy", "machineId": "signal-hunt", "flags": 3, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-11-r", "title": "Recon", "type": "lab" }] },
        { "id": "wifi-12", "title": "Wi-Fi Deauthentication", "difficulty": "medium", "machineId": "deauth-storm", "flags": 2, "category": "Wi-Fi Security", "rooms": [{ "id": "wifi-12-r", "title": "Deauth", "type": "lab" }] },

        // --- AI/LLM ATTACKS (4 Modules) ---
        { "id": "ai-1", "title": "Introduction to Red Teaming AI", "difficulty": "easy", "machineId": "ai-intro", "flags": 2, "category": "AI Security", "rooms": [{ "id": "ai-1-r", "title": "AI Intro", "type": "theory" }] },
        { "id": "ai-2", "title": "Attacking AI Applications", "difficulty": "medium", "machineId": "ai-attack-lab", "flags": 4, "category": "AI Security", "rooms": [{ "id": "ai-2-r", "title": "AI App Attack", "type": "lab" }] },
        { "id": "ai-3", "title": "Prompt Injection Attacks", "difficulty": "medium", "machineId": "prompt-inject", "flags": 5, "category": "AI Security", "rooms": [{ "id": "ai-3-r", "title": "Prompt Injection", "type": "lab" }] },
        { "id": "ai-4", "title": "LLM Output Attacks", "difficulty": "hard", "machineId": "llm-exploit", "flags": 4, "category": "AI Security", "rooms": [{ "id": "ai-4-r", "title": "Output Manipulation", "type": "lab" }] },

        // --- WEB EXPLOITATION (20 Modules) ---
        { "id": "web-1", "title": "Introduction to Web Applications", "difficulty": "easy", "machineId": "web-basics", "flags": 2, "category": "Web Exploitation", "rooms": [{ "id": "web-1-r", "title": "Web Basics", "type": "theory" }] },
        { "id": "web-2", "title": "Using Web Proxies", "difficulty": "easy", "machineId": "burp-academy", "flags": 3, "category": "Web Exploitation", "rooms": [{ "id": "web-2-r", "title": "Burp Suite", "type": "lab" }] },
        { "id": "web-3", "title": "Web Fuzzing", "difficulty": "medium", "machineId": "fuzz-factory", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-3-r", "title": "Fuzzing", "type": "lab" }] },
        {
            "id": "web-4",
            "title": "SQL Injection Fundamentals",
            "difficulty": "medium",
            "machineId": "sqli-bakery",
            "flags": 4,
            "category": "Web Exploitation",
            "description": "Learn how to bypass authentication and retrieve hidden data using SQL Injection.",
            "objectives": ["Authentication Bypass", "UNION Attacks", "Database Enumeration"],
            "rooms": [
                {
                    "id": "web-4-r",
                    "title": "SQLi 101",
                    "type": "lab",
                    "content": "<h3>What is SQL Injection?</h3><p>SQL Injection (SQLi) allows attackers to interfere with database queries.</p><h4>1. Authentication Bypass</h4><p>Use a payload to trick the login logic.</p><pre><code>' OR 1=1--</code></pre><h4>2. UNION Attacks</h4><p>Retrieve data from other tables using `UNION SELECT`.</p><pre><code>' UNION SELECT username, password FROM users--</code></pre>",
                    "tasks": [
                        { "title": "Bypass Login", "content": "Log in as admin without a password." },
                        { "title": "Find the secret version", "content": "Use UNION to find the DB version." }
                    ]
                }
            ]
        },
        { "id": "web-5", "title": "Blind SQL Injection", "difficulty": "hard", "machineId": "blind-sqli", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-5-r", "title": "Blind SQLi", "type": "lab" }] },
        { "id": "web-6", "title": "Advanced SQL Injections", "difficulty": "hard", "machineId": "sqli-master", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-6-r", "title": "Advanced SQLi", "type": "lab" }] },
        { "id": "web-7", "title": "SQLMap Essentials", "difficulty": "medium", "machineId": "sqlmap-lab", "flags": 3, "category": "Web Exploitation", "rooms": [{ "id": "web-7-r", "title": "SQLMap", "type": "lab" }] },
        { "id": "web-8", "title": "NoSQL Injection", "difficulty": "medium", "machineId": "nosql-attack", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-8-r", "title": "NoSQLi", "type": "lab" }] },
        { "id": "web-9", "title": "Cross-Site Scripting (XSS)", "difficulty": "medium", "machineId": "xss-arena", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-9-r", "title": "XSS Basics", "type": "lab" }] },
        { "id": "web-10", "title": "Advanced XSS & CSRF", "difficulty": "hard", "machineId": "xss-master", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-10-r", "title": "Advanced XSS", "type": "lab" }] },
        { "id": "web-11", "title": "Command Injections", "difficulty": "medium", "machineId": "cmd-inject", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-11-r", "title": "CMDi", "type": "lab" }] },
        { "id": "web-12", "title": "File Inclusion", "difficulty": "medium", "machineId": "lfi-rfi-lab", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-12-r", "title": "LFI/RFI", "type": "lab" }] },
        { "id": "web-13", "title": "File Upload Attacks", "difficulty": "medium", "machineId": "upload-arena", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-13-r", "title": "Uploads", "type": "lab" }] },
        { "id": "web-14", "title": "Server-side Attacks", "difficulty": "hard", "machineId": "ssrf-ssti", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-14-r", "title": "SSRF & SSTI", "type": "lab" }] },
        { "id": "web-15", "title": "Deserialization Attacks", "difficulty": "hard", "machineId": "deserialize", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-15-r", "title": "Insecure Deserialization", "type": "lab" }] },
        { "id": "web-16", "title": "HTTP/HTTPS Attacks", "difficulty": "medium", "machineId": "http-tricks", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-16-r", "title": "HTTP Smuggling", "type": "lab" }] },
        { "id": "web-17", "title": "Session Security", "difficulty": "medium", "machineId": "session-hijack", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-17-r", "title": "Session Mgmt", "type": "lab" }] },
        { "id": "web-18", "title": "Broken Authentication", "difficulty": "medium", "machineId": "auth-bypass", "flags": 4, "category": "Web Exploitation", "rooms": [{ "id": "web-18-r", "title": "Auth Attacks", "type": "lab" }] },
        { "id": "web-19", "title": "Modern Web Exploitation", "difficulty": "hard", "machineId": "modern-web", "flags": 5, "category": "Web Exploitation", "rooms": [{ "id": "web-19-r", "title": "Modern Tech", "type": "lab" }] },
        { "id": "web-20", "title": "Attacking Ffuf", "difficulty": "medium", "machineId": "ffuf-mastery", "flags": 3, "category": "Web Exploitation", "rooms": [{ "id": "web-20-r", "title": "Ffuf", "type": "lab" }] },

        // --- API & WEB SERVICES (4 Modules) ---
        { "id": "api-1", "title": "Web Service & API Attacks", "difficulty": "medium", "machineId": "api-attack", "flags": 4, "category": "API Security", "rooms": [{ "id": "api-1-r", "title": "API 101", "type": "lab" }] },
        { "id": "api-2", "title": "API Attacks", "difficulty": "medium", "machineId": "api-exploit", "flags": 5, "category": "API Security", "rooms": [{ "id": "api-2-r", "title": "Broken Object Level Auth", "type": "lab" }] },
        { "id": "api-3", "title": "Web Requests", "difficulty": "easy", "machineId": "http-requests", "flags": 2, "category": "API Security", "rooms": [{ "id": "api-3-r", "title": "Request Analysis", "type": "theory" }] },
        { "id": "api-4", "title": "Hacking WordPress", "difficulty": "medium", "machineId": "wp-pwned", "flags": 4, "category": "API Security", "rooms": [{ "id": "api-4-r", "title": "WPScan", "type": "lab" }] },

        // --- NETWORK & ENUMERATION (8 Modules) ---
        { "id": "net-101", "title": "Introduction to Networking", "difficulty": "easy", "machineId": "net-101", "flags": 2, "category": "Network", "rooms": [{ "id": "net-1-r", "title": "Net Basics", "type": "theory" }] },
        { "id": "net-2", "title": "Network Foundations", "difficulty": "easy", "machineId": "net-foundations", "flags": 3, "category": "Network", "rooms": [{ "id": "net-2-r", "title": "OSI Model", "type": "theory" }] },
        { "id": "net-3", "title": "Network Enumeration with Nmap", "difficulty": "medium", "machineId": "nmap-master", "flags": 4, "category": "Network", "rooms": [{ "id": "net-3-r", "title": "Nmap", "type": "lab" }] },
        { "id": "net-4", "title": "Footprinting", "difficulty": "medium", "machineId": "footprint-lab", "flags": 4, "category": "Network", "rooms": [{ "id": "net-4-r", "title": "Recon", "type": "lab" }] },
        { "id": "net-5", "title": "DNS Enumeration with Python", "difficulty": "medium", "machineId": "dns-enum", "flags": 3, "category": "Network", "rooms": [{ "id": "net-5-r", "title": "DNS", "type": "lab" }] },
        { "id": "net-6", "title": "Information Gathering - Web", "difficulty": "medium", "machineId": "recon-web", "flags": 4, "category": "Network", "rooms": [{ "id": "net-6-r", "title": "Web Recon", "type": "lab" }] },
        { "id": "net-7", "title": "OSINT: Corporate Recon", "difficulty": "medium", "machineId": "osint-corp", "flags": 4, "category": "Network", "rooms": [{ "id": "net-7-r", "title": "OSINT", "type": "lab" }] },
        { "id": "net-8", "title": "Attacking Common Services", "difficulty": "hard", "machineId": "service-pwner", "flags": 5, "category": "Network", "rooms": [{ "id": "net-8-r", "title": "Service Attacks", "type": "lab" }] },

        // --- ACTIVE DIRECTORY (8 Modules) ---
        { "id": "ad-1", "title": "Introduction to Active Directory", "difficulty": "easy", "machineId": "ad-101", "flags": 2, "category": "Active Directory", "rooms": [{ "id": "ad-1-r", "title": "AD Basics", "type": "theory" }] },
        { "id": "ad-2", "title": "Active Directory Enumeration & Attacks", "difficulty": "hard", "machineId": "ad-enum", "flags": 6, "category": "Active Directory", "rooms": [{ "id": "ad-2-r", "title": "Enum", "type": "lab" }] },
        { "id": "ad-3", "title": "Active Directory PowerView", "difficulty": "medium", "machineId": "powerview-lab", "flags": 4, "category": "Active Directory", "rooms": [{ "id": "ad-3-r", "title": "PowerView", "type": "lab" }] },
        { "id": "ad-4", "title": "Active Directory BloodHound", "difficulty": "medium", "machineId": "bloodhound-lab", "flags": 4, "category": "Active Directory", "rooms": [{ "id": "ad-4-r", "title": "BloodHound", "type": "lab" }] },
        { "id": "ad-5", "title": "Kerberos Attacks", "difficulty": "hard", "machineId": "kerberos-forge", "flags": 5, "category": "Active Directory", "rooms": [{ "id": "ad-5-r", "title": "Kerberos", "type": "lab" }] },
        { "id": "ad-6", "title": "Using CrackMapExec", "difficulty": "medium", "machineId": "cme-mastery", "flags": 4, "category": "Active Directory", "rooms": [{ "id": "ad-6-r", "title": "CME", "type": "lab" }] },
        { "id": "ad-7", "title": "Windows Attacks & Defense", "difficulty": "hard", "machineId": "win-attack", "flags": 5, "category": "Active Directory", "rooms": [{ "id": "ad-7-r", "title": "Defense", "type": "lab" }] },
        { "id": "ad-8", "title": "Attacking Enterprise", "difficulty": "hard", "machineId": "enterprise-pwned", "flags": 6, "category": "Active Directory", "rooms": [{ "id": "ad-8-r", "title": "Enterprise", "type": "lab" }] },

        // --- PRIVILEGE ESCALATION (4 Modules) ---
        { "id": "pe-1", "title": "Linux Privilege Escalation", "difficulty": "medium", "machineId": "linux-privesc", "flags": 5, "category": "PrivEsc", "rooms": [{ "id": "pe-1-r", "title": "Linux PE", "type": "lab" }] },
        { "id": "pe-2", "title": "Windows Privilege Escalation", "difficulty": "hard", "machineId": "win-privesc", "flags": 5, "category": "PrivEsc", "rooms": [{ "id": "pe-2-r", "title": "Windows PE", "type": "lab" }] },
        { "id": "pe-3", "title": "Shells & Payloads", "difficulty": "medium", "machineId": "shell-craft", "flags": 4, "category": "PrivEsc", "rooms": [{ "id": "pe-3-r", "title": "Shells", "type": "lab" }] },
        { "id": "pe-4", "title": "File Transfers", "difficulty": "easy", "machineId": "file-transfer", "flags": 3, "category": "PrivEsc", "rooms": [{ "id": "pe-4-r", "title": "Transfers", "type": "lab" }] },

        // --- SCRIPTING & TOOLS (10 Modules) ---
        { "id": "tool-1", "title": "Introduction to Python 3", "difficulty": "easy", "machineId": "python-101", "flags": 3, "category": "Scripting", "rooms": [{ "id": "tool-1-r", "title": "Python", "type": "lab" }] },
        { "id": "tool-2", "title": "Introduction to Bash Scripting", "difficulty": "easy", "machineId": "bash-basics", "flags": 3, "category": "Scripting", "rooms": [{ "id": "tool-2-r", "title": "Bash", "type": "lab" }] },
        { "id": "tool-3", "title": "Intro to Assembly Language", "difficulty": "hard", "machineId": "asm-intro", "flags": 4, "category": "Scripting", "rooms": [{ "id": "tool-3-r", "title": "Assembly", "type": "theory" }] },
        { "id": "tool-4", "title": "Using the Metasploit Framework", "difficulty": "medium", "machineId": "msf-mastery", "flags": 5, "category": "Tools", "rooms": [{ "id": "tool-4-r", "title": "Metasploit", "type": "lab" }] },
        { "id": "tool-5", "title": "Cracking Passwords with Hashcat", "difficulty": "medium", "machineId": "hashcat-lab", "flags": 4, "category": "Tools", "rooms": [{ "id": "tool-5-r", "title": "Hashcat", "type": "lab" }] },
        { "id": "tool-6", "title": "Login Brute Forcing", "difficulty": "medium", "machineId": "bruteforce-lab", "flags": 4, "category": "Tools", "rooms": [{ "id": "tool-6-r", "title": "Bruteforce", "type": "lab" }] },
        { "id": "tool-7", "title": "Password Attacks", "difficulty": "medium", "machineId": "password-lab", "flags": 5, "category": "Tools", "rooms": [{ "id": "tool-7-r", "title": "Passwords", "type": "lab" }] },
        { "id": "tool-8", "title": "Secure Coding 101: JavaScript", "difficulty": "easy", "machineId": "secure-js", "flags": 3, "category": "Scripting", "rooms": [{ "id": "tool-8-r", "title": "JS Security", "type": "lab" }] },
        { "id": "tool-9", "title": "Injection Attacks", "difficulty": "medium", "machineId": "inject-all", "flags": 4, "category": "Tools", "rooms": [{ "id": "tool-9-r", "title": "Injection", "type": "lab" }] },
        { "id": "tool-10", "title": "HTTP Attacks", "difficulty": "medium", "machineId": "http-attacks", "flags": 4, "category": "Tools", "rooms": [{ "id": "tool-10-r", "title": "HTTP", "type": "lab" }] },

        // --- BUG BOUNTY (3 Modules) ---
        { "id": "bb-1", "title": "Bug Bounty Hunting Process", "difficulty": "medium", "machineId": "bb-process", "flags": 3, "category": "Bug Bounty", "rooms": [{ "id": "bb-1-r", "title": "Process", "type": "theory" }] },
        { "id": "bb-2", "title": "Web Attacks", "difficulty": "medium", "machineId": "web-attacks-bb", "flags": 5, "category": "Bug Bounty", "rooms": [{ "id": "bb-2-r", "title": "Attacks", "type": "lab" }] },
        { "id": "bb-3", "title": "Attacking Authentication", "difficulty": "medium", "machineId": "auth-attacks", "flags": 4, "category": "Bug Bounty", "rooms": [{ "id": "bb-3-r", "title": "Auth", "type": "lab" }] },

        // --- OS FUNDAMENTALS (5 Modules) ---
        { "id": "os-1", "title": "Linux Fundamentals", "difficulty": "easy", "machineId": "linux-101", "flags": 3, "category": "OS", "rooms": [{ "id": "os-1-r", "title": "Linux", "type": "lab" }] },
        { "id": "os-2", "title": "Windows Fundamentals", "difficulty": "easy", "machineId": "win-101", "flags": 3, "category": "OS", "rooms": [{ "id": "os-2-r", "title": "Windows", "type": "lab" }] },
        { "id": "os-3", "title": "Introduction to Windows", "difficulty": "easy", "machineId": "win-intro", "flags": 2, "category": "OS", "rooms": [{ "id": "os-3-r", "title": "Intro", "type": "theory" }] },
        { "id": "os-4", "title": "MacOS Fundamentals", "difficulty": "easy", "machineId": "macos-101", "flags": 2, "category": "OS", "rooms": [{ "id": "os-4-r", "title": "MacOS", "type": "theory" }] },
        { "id": "os-5", "title": "Kali Linux Essentials", "difficulty": "easy", "machineId": "kali-101", "flags": 3, "category": "OS", "rooms": [{ "id": "os-5-r", "title": "Kali", "type": "lab" }] }
    ],

    roadmaps: [],

    // Helper Methods
    getPathById: function (id) { return this.paths.find(p => p.id === id); },

    getPathCourses: function (pathId) {
        const path = this.paths.find(p => p.id === pathId);
        return path ? (path.courses || path.units || []) : [];
    },

    getCourseById: function (courseId) {
        // Check top-level courses if they exist
        if (this.courses) {
            const course = this.courses.find(c => c.id === courseId);
            if (course) return course;
        }
        // Search in Paths units
        for (const path of this.paths) {
            if (path.units) {
                const unit = path.units.find(u => u.id === courseId);
                if (unit) return unit;
            }
        }
        return null;
    },

    getCourseModules: function (courseId) {
        const course = this.getCourseById(courseId);
        if (!course) return [];
        return course.rooms || course.modules || [];
    },

    getModuleById: function (id) {
        // 1. Search in global modules
        const mod = this.modules.find(m => m.id === id);
        if (mod) return mod;

        // 2. Search in Paths -> Units (Courses) -> Rooms (Modules)
        for (const path of this.paths) {
            if (path.units) {
                for (const unit of path.units) {
                    if (unit.rooms) {
                        const room = unit.rooms.find(r => r.id === id);
                        if (room) return room;
                    }
                }
            }
        }
        return null;
    },

    getRoadmapById: function (id) { return this.roadmaps.find(r => r.id === id); },

    // Helper to get room from any structure
    getRoomById: function (roomId) {
        // 0. Direct search in top-level rooms (new curriculum rooms)
        if (Array.isArray(this.rooms)) {
            const topRoom = this.rooms.find(r => r.id === roomId);
            if (topRoom) return { room: topRoom, context: { type: 'rooms' } };
        }

        // Search in Paths
        for (const path of this.paths) {
            if (path.units) {
                for (const unit of path.units) {
                    const room = unit.rooms.find(r => r.id === roomId);
                    if (room) return { room, context: { type: 'path', id: path.id, unit: unit.id } };
                }
            }
        }
        // Search in Modules
        for (const mod of this.modules) {
            if (mod.rooms) {
                const room = mod.rooms.find(r => r.id === roomId);
                if (room) return { room, context: { type: 'module', id: mod.id } };
            }
        }
        return null;
    }
};

// Export properly to window
if (typeof window !== 'undefined') {
    window.UnifiedLearningData = UnifiedLearningData;
    console.log('UnifiedLearningData loaded with ' + UnifiedLearningData.paths.length + ' paths and ' + UnifiedLearningData.modules.length + ' modules.');
}

// For CommonJS environments (if any)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UnifiedLearningData;
}
