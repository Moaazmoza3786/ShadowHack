/* ============================================================
   JOB SIMULATIONS DATA v2.0
   Scenarios, tickets, and validation logic for Role-Based Paths
   Now includes AI KNOWLEDGE BASES for Heuristic Analysis.
   ============================================================ */

window.JobSimData = {
    // === CAREER RANKS ===
    ranks: [
        { id: 1, title: 'Script Kiddie', minXP: 0 },
        { id: 2, title: 'Junior Analyst', minXP: 500 },
        { id: 3, title: 'Security Consultant', minXP: 2000 },
        { id: 4, title: 'Red Team Operator', minXP: 5000 },
        { id: 5, title: 'CISO', minXP: 15000 }
    ],

    // === ROLES & SCENARIOS ===
    roles: [
        {
            id: 'soc-analyst-1',
            title: 'SOC Analyst Level 1',
            icon: 'shield-halved',
            difficulty: 'Beginner',
            tier: 1,
            description: 'The first line of defense. Monitor SIEM logs, triage alerts, and escalate confirmed threats.',
            salary: '$70k - $90k',
            skills: ['SIEM Analysis', 'Phishing Triage', 'Incident Response'],
            aiPersona: {
                name: 'Sarah (Senior Analyst)',
                role: 'Mentor',
                tone: 'Professional but encouraging',
                systemPrompt: 'You are a Senior SOC Analyst mentoring a Junior. Guide them through the investigation without giving the answer directly. Use analogies.'
            },
            scenarios: [
                {
                    id: 'shift-1-phishing',
                    title: 'Incident 2024-001: CEO Impersonation',
                    description: 'High-priority alert: Finance department reported a suspiciously urgent email from the "CEO".',
                    difficulty: 'Easy',
                    xpOrder: 500,
                    aiKnowledge: {
                        keywords: ['header', 'received', 'origin', 'spoof', 'reply-to'],
                        antiPatterns: {
                            'reply': 'Never reply to a suspicious email. It confirms the mailbox is active.',
                            'ignore': 'CEO fraud causes massive financial loss. We cannot ignore this.',
                            'delete': 'Deleting destroys evidence. We need to analyze headers first.'
                        },
                        hints: [
                            'Start by looking at the "Received" headers from bottom to top.',
                            'The bottom-most IP is usually the true origin.',
                            'Compare the "From" address with the "Return-Path".'
                        ]
                    },
                    tasks: [
                        {
                            id: 't1',
                            title: 'Header Analysis',
                            prompt: 'Analyze the "Received" headers. What is the originating IP address?',
                            type: 'text',
                            validation: { regex: /^192\.168\.1\.105$/, hint: 'Look for the bottom-most "Received" hop.' },
                            points: 50
                        },
                        {
                            id: 't2',
                            title: 'Payload Analysis',
                            prompt: 'The attachment "Invoice.pdf.exe" uses a double extension. What is the real file type?',
                            type: 'select',
                            options: ['PDF', 'Windows Executable', 'Image', 'Text'],
                            validation: { match: 'Windows Executable', hint: 'Windows executes the extension after the last dot.' },
                            points: 50
                        },
                        {
                            id: 't3',
                            title: 'Containment',
                            prompt: 'What is the immediate action required?',
                            type: 'select',
                            options: ['Reply to sender', 'Block Sender IP on Gateway', 'Delete email from inbox only', 'Ignore'],
                            validation: { match: 'Block Sender IP on Gateway', hint: 'Stop the attack at the perimeter.' },
                            points: 100
                        }
                    ],
                    evidence: {
                        headers: `From: CEO <ceo@corp-internal.com> (Spoofed)\nReturn-Path: <attacker@evil-server.xyz>\nReceived: from unknown (192.168.1.105) by mail.corp.local`,
                        body: `URGENT: Wire $50,000 to vendor immediately. Attached is the invoice.\nFile: Invoice.pdf.exe`
                    }
                },
                {
                    id: 'shift-2-ransom',
                    title: 'Incident 2024-055: Ransomware Outbreak',
                    description: 'CRITICAL: Multiple endpoints encrypted. Lateral movement detected via SMB.',
                    difficulty: 'Hard',
                    xpOrder: 1000,
                    aiKnowledge: {
                        keywords: ['smb', '445', 'lateral', 'encrypt', 'isolate'],
                        antiPatterns: {
                            'firewall': 'Updating the external firewall wont stop internal lateral movement (SMB).',
                            'pay': 'We never negotiate with terrorists or pay ransoms.',
                            'reboot': 'Rebooting might destroy evidence in RAM or trigger encryption scripts.'
                        },
                        hints: [
                            'Check the SIEM logs for traffic on port 445 (SMB).',
                            'Identify the source of the infection.',
                            'Isolate the infected host from the network immediately.'
                        ]
                    },
                    tasks: [
                        {
                            id: 't1',
                            title: 'Identify Strain',
                            prompt: 'Encrypted files have extensions `.locked_by_troll`. What ransomware family matches this signature?',
                            type: 'text',
                            validation: { regex: /troll/i, hint: 'The extension usually names the variant.' },
                            points: 100
                        }
                    ],
                    evidence: {
                        logs: `SMB traffic surge from Workstation-05 to FileServer-01.\nFiles renamed to *.locked_by_troll`
                    }
                }
            ]
        },
        {
            id: 'bug-hunter-1',
            title: 'Bug Bounty Hunter',
            icon: 'bug',
            difficulty: 'Intermediate',
            tier: 2,
            description: 'Freelance security researcher. Find vulnerabilities in authorized targets and write professional reports.',
            salary: 'Performance Based',
            skills: ['Web Exploitation', 'Reconnaissance', 'Report Writing'],
            aiPersona: {
                name: 'Triager Bot',
                role: 'Triager',
                tone: 'Strict and technical',
                systemPrompt: 'You are a strict Bug Bounty Triager. Critique reports based on reproducibility and impact.'
            },
            scenarios: [
                {
                    id: 'bh-1-xss',
                    title: 'Program: MegaCorp - Stored XSS',
                    description: 'MegaCorp launched a new comments section. Can you pop a sweet alert?',
                    difficulty: 'Medium',
                    xpOrder: 750,
                    aiKnowledge: {
                        keywords: ['script', 'alert', 'payload', 'cookie', 'session', 'stored'],
                        antiPatterns: {
                            'self': 'Self-XSS is usually out of scope. Show how to victimize others.',
                            'scanner': 'Automated scanner output is not a valid report. Verify manually.'
                        },
                        hints: [
                            'The filter removes `<script>`, but what about `<img onerror=...>?',
                            'Stored XSS means the payload persists in the database.',
                            'Demonstrate impact by stealing a (mock) cookie.'
                        ]
                    },
                    tasks: [
                        {
                            id: 'xss1',
                            title: 'Exploit Crafting',
                            prompt: 'Submit a payload that bypasses the simple filter `<script>` removal.',
                            type: 'text',
                            validation: { regex: /<img|onload|onerror|iframe|body/i, hint: 'Try event handlers like onload or onerror.' },
                            points: 100
                        }
                    ],
                    evidence: {
                        source: `function sanitise(input) {\n  return input.replace('<script>', '');\n}`
                    }
                }
            ]
        },
        {
            id: 'malware-1',
            title: 'Malware Analyst',
            icon: 'biohazard',
            difficulty: 'Advanced',
            tier: 3,
            description: 'Reverse engineer suspicious binaries. Unpack code and extract IOCs.',
            salary: '$90k - $130k',
            skills: ['Assembly (x86)', 'Decompilation', 'Static Analysis'],
            aiPersona: {
                name: 'The Reverse Engineer',
                role: 'Expert',
                tone: 'Cryptic and precise',
                systemPrompt: 'You are an expert Malware Analyst. Give hints about assembly instructions and memory addresses.'
            },
            scenarios: [
                {
                    id: 'mal-1-dropper',
                    title: 'Sample Analysis: Ursnif Dropper',
                    description: 'A suspicious macro document dropped an EXE. Analyze the PE headers.',
                    difficulty: 'Hard',
                    xpOrder: 1200,
                    aiKnowledge: {
                        keywords: ['dll', 'import', 'export', 'kernel32', 'dynamic', 'load'],
                        antiPatterns: {
                            'open': 'Never open malware on your host machine. Use the sandbox.',
                            'string': 'Strings can be obfuscated. Don\'t rely on them alone.'
                        },
                        hints: [
                            'Look at the Import Address Table (IAT).',
                            'Which function allows loading code from other files?',
                            'It starts with "Load..."'
                        ]
                    },
                    tasks: [
                        {
                            id: 'm1',
                            title: 'Import Hashing',
                            prompt: 'What kernel32 function is being imported to dynamically load other libraries?',
                            type: 'text',
                            validation: { regex: /LoadLibrary/i, hint: 'It allows loading DLLs at runtime.' },
                            points: 150
                        }
                    ],
                    evidence: {
                        imports: `KERNEL32.DLL: LoadLibraryA, GetProcAddress, VirtualAlloc`
                    }
                }
            ]
        }
    ]
};
