/**
 * Unified CTF Data - Professional Capture The Flag Challenges
 * Phase 5 Implementation: Story-Driven Scenarios
 */

const CTFData = {
    "tier1": [ // Ground Zero
        {
            "id": "ctf-intern-mistake",
            "title": "The Intern's Mistake",
            "difficulty": "easy",
            "tier": 1,
            "points": 50,
            "category": "Web / Source Code",
            "description": "An intern forgot to scrub the notes. Can you find the secrets in the source?",
            "scenario": "A junior developer at 'TechCorp' just pushed a beta version of their landing page. Unfortunately, they didn't follow the security checklist and left developer comments containing sensitive access tokens. Your mission is to inspect the public face of the application and find what was meant to be hidden.",
            "objectives": ["Inspect Site Source Code", "Find HTML Comments", "Extract Access Token (Flag)"],
            "tags": ["Source Code", "Comments", "DevTools"],
            "flag": "AG{Y0u_F0und_7h3_C0mm3n7}",
            "machineId": "ctf-intern-mistake"
        },
        {
            "id": "ctf-leaky-bucket",
            "title": "The Leaky Bucket",
            "difficulty": "easy",
            "tier": 1,
            "points": 100,
            "category": "Web / Exposure",
            "description": "A disgruntled employee left more than just a resignation letter. Can you find the shadow backup?",
            "scenario": "Operative V was a senior sysadmin at Global Logistics Corp before being terminated for 'unprofessional conduct'. In a final act of silent rebellion, he moved a critical database backup to a publicly accessible web directory, betting that the company's automated scanners would miss it. Your objective is to perform a directory traversal or brute-force attack to locate this 'leaky bucket' and extract the sensitive flag within.",
            "objectives": ["Enumerate Web Directories", "Locate Guessable Backup Paths", "Extract and Decrypt Zip Archive", "Capture the flag"],
            "tags": ["Data Exposure", "Enumeration", "Fuzzing"],
            "flag": "AG{unsecure_backups_lead_to_leaks_2024}",
            "machineId": "ctf-leaky-bucket"
        },
        {
            "id": "ctf-hidden-sauce",
            "title": "Hidden Sauce",
            "difficulty": "easy",
            "tier": 1,
            "points": 50,
            "category": "Web / Warmup",
            "description": "A simple bakery website. Can you find the secret ingredient?",
            "scenario": "Welcome to the academy. Your first mission is to prove you can look where others don't. The target is a simple static site. Check the recipe notes.",
            "objectives": ["Inspect Source Code", "Find HTML Comments", "Locate flag.txt"],
            "tags": ["Elements", "DevTools"],
            "flag": "AG{s0urce_cod3_d1scov3ry}",
            "machineId": "warmup-1",
            "image": "./assets/ctf/ctf_hidden_sauce.png"
        },
        {
            "id": "ctf-base-jump",
            "title": "Base Jump",
            "difficulty": "easy",
            "tier": 1,
            "points": 50,
            "category": "Crypto / Warmup",
            "description": "Decode the transmission from the lunar base.",
            "scenario": "We intercepted a radio burst. It looks like standard encoding but the field team is stuck. Help them out.",
            "objectives": ["Identify Encoding", "Decode Base64", "Submit Flag"],
            "tags": ["Base64", "Decoding"],
            "flag": "AG{lunar_transm1ssion_dec0ded}",
            "machineId": "warmup-2",
            "image": "./assets/ctf/ctf_base_jump.png"
        }
    ],
    "tier2": [ // Escape Velocity
        {
            "id": "ctf-celestial-logbook",
            "title": "The Celestial Logbook",
            "difficulty": "medium",
            "tier": 2,
            "points": 350,
            "category": "Web / LFI",
            "description": "Navigate the desert observatory's archives and find the hidden encryption keys.",
            "scenario": "Deep within the hyper-arid Atacama desert, the 'Nova-1' Automated Observatory has been scanning the stars for decades. Its web portal allows researchers to view historical telescope alignment logs via a simple dynamic viewer. Intelligence suggests that a sensitive encryption key (the flag) is stored on the server's root directory. Can you use the log viewer to navigate out of the restricted directory and capture the celestial secret?",
            "objectives": ["Discover Log Viewing Endpoint", "Test for Directory Traversal", "Capture flag.txt from the Root Directory"],
            "tags": ["LFI", "Traversal", "PHP"],
            "flag": "AG{LFI_1n_th3_St4rs_8ce3}",
            "machineId": "ctf-celestial-logbook",
            "image": "./assets/ctf/ctf_celestial_logbook_v1_1768040045639.png"
        },
        {
            "id": "ctf-ghost-archive",
            "title": "The Ghost Archive",
            "difficulty": "medium",
            "tier": 2,
            "points": 300,
            "category": "Web / LFI",
            "description": "A legacy retrieval system with a pathing flaw. Can you ghost the files?",
            "scenario": "The old 'Systems Archive' at Orbital Systems is still online. It uses a dynamic file loader that trusts user-supplied paths. Our source says a high-value 'launch code' file exists on the server. Break the confinement and find the secret flag.",
            "objectives": ["Identify File Inclusion Point", "Perform Directory Traversal", "Locate secret_flag.txt"],
            "tags": ["LFI", "Traversal", "PHP"],
            "flag": "AG{LFI_Tr4v3rs4l_M4st3r_2026}",
            "machineId": "ctf-ghost-archive",
            "image": "./assets/ctf/ctf_ghost_archive_v1_1768039265501.png"
        },
        {
            "id": "ctf-login-limbo",
            "title": "Login Limbo",
            "difficulty": "medium",
            "tier": 2,
            "points": 250,
            "category": "Web / SQLi",
            "description": "An outdated portal guarded by a weak lock. Can you bypass the gate?",
            "scenario": "The employee entrance for 'Bank of Antigravity' relies on a legacy authentication system. The IT manager claims it's unhackable because 'nobody knows the admin password', but they failed to realize that the code itself is the vulnerability. Your task is to bypass the login form using a SQL injection payload and retrieve the flag from the administrative dashboard.",
            "objectives": ["Discover Authentication Vulnerability", "Bypass Login without Password", "Extract flag.txt from the Dashboard"],
            "tags": ["SQLi", "Auth Bypass", "SQLite"],
            "flag": "AG{SQL_Inj3ct10n_M4st3r}",
            "machineId": "ctf-login-limbo",
            "image": "./assets/ctf/ctf_login_limbo_v1_1768039019839.png"
        },
        {
            "id": "ctf-eternal-shadow",
            "title": "Eternal Shadow",
            "difficulty": "medium",
            "tier": 2,
            "points": 250,
            "category": "Network / CVE",
            "description": "An old Windows 7 machine is still running in the basement.",
            "scenario": "Shadow Corp forgot to deprovision an old HR server. It's vulnerable to a classic SMB exploit. Launch the attack and gain a shell.",
            "objectives": ["Nmap Scan", "Identify MS17-010", "Use Metasploit/Exploit Script", "Capture user.txt"],
            "tags": ["SMB", "CVE-2017-0144", "Windows"],
            "flag": "AG{3t3rn4l_r0cks_th3_syst3m}",
            "machineId": "eternal-blue-lab",
            "image": "./assets/ctf/ctf_eternal_shadow.png"
        }
    ],
    "tier3": [ // Orbit
        {
            "id": "ctf-ping-pong",
            "title": "Ping Pong",
            "difficulty": "hard",
            "tier": 3,
            "points": 500,
            "category": "Web / Command Injection",
            "description": "A diagnostic tool with a serious logic flaw. Can you break out of the script?",
            "scenario": "The internal systems monitor at 'TechCorp' allows admins to ping servers to verify uptime. However, the tool was built with a lack of input validation, trusting whatever string is passed to the shell. Your objective is to exploit this command injection vulnerability to read sensitive system files and capture the flag hidden in the root directory.",
            "objectives": ["Discover Command Injection Entry Point", "Bypass Basic Filters (if any)", "Execute Remote Commands", "Capture flag.txt from /root/"],
            "tags": ["RCE", "Command Injection", "Linux"],
            "flag": "AG{C0mm4nd_Inj3ct10n_1s_L3th4l}",
            "machineId": "ctf-ping-pong",
            "image": "./assets/ctf/ctf_ping_pong_v1_1768039176598.png"
        },
        {
            "id": "ctf-blind-fury",
            "title": "Blind Fury",
            "difficulty": "hard",
            "tier": 3,
            "points": 500,
            "category": "Web / SQLi",
            "description": "A secure-looking portal with a hidden blind SQLi vulnerability.",
            "scenario": "The 'SecureGate' portal claims to be unhackable. Our recon shows a time-based blind SQLi in the 'region' parameter. You'll need to write a script to extract the data.",
            "objectives": ["Manual SQLi Discovery", "Write Extraction Script (Python)", "Dump Database Schema", "Extract Admin Password"],
            "tags": ["Blind SQLi", "Python", "Automation"],
            "flag": "AG{bl1nd_sql_m4st3ry}",
            "machineId": "sql-pro-lab",
            "image": "./assets/ctf/ctf_blind_fury.png"
        },
        {
            "id": "ctf-docker-breakout",
            "title": "Container Escape",
            "difficulty": "hard",
            "tier": 3,
            "points": 600,
            "category": "Cloud / Docker",
            "description": "You are trapped in a container. Can you reach the host?",
            "scenario": "You've gained initial access to a microservice. However, it's heavily restricted. Find a way to exploit the Docker socket or a misconfigured volume to escape to the host system.",
            "objectives": ["Enumerate Container Env", "Discover Docker Socket", "Exploit Writable Volume", "Capture host_flag.txt"],
            "tags": ["Docker", "PrivEsc", "Cloud"],
            "flag": "AG{d0ck3r_3sc4p3_succ3ss}",
            "machineId": "docker-escape-lab",
            "image": "./assets/ctf/ctf_container_escape.png"
        }
    ],
    "tier4": [ // Deep Space
        {
            "id": "ctf-identity-paradox",
            "title": "The Identity Paradox",
            "difficulty": "hard",
            "tier": 4,
            "points": 750,
            "category": "Web / JWT",
            "description": "A communication link secured by a weak secret. Can you forge a high-level identity?",
            "scenario": "The orbital communication link uses JWT for officer authentication. While you have 'guest' access, the rockets are locked behind 'admin' privileges. The signature secret is a common English word. Crack the HMAC-SHA256 signature, forge an admin token, and seize control of the station.",
            "objectives": ["Capture JWT Authentication Token", "Crack Weak HMAC Secret", "Forge Identity Token with Admin Role"],
            "tags": ["JWT", "Auth Bypass", "Brute Force"],
            "flag": "AG{W34k_JWT_S3cr3ts_Cr4ck3d}",
            "machineId": "ctf-identity-paradox",
            "image": "./assets/ctf/ctf_identity_paradox_v1_1768039396600.png"
        },
        {
            "id": "ctf-black-box-protocol",
            "title": "Black Box Protocol",
            "difficulty": "insane",
            "tier": 4,
            "points": 1000,
            "category": "Pivoting / Malware",
            "description": "Signals from a rogue satellite. Pivot through the network and exploit the core.",
            "scenario": "Rogue hackers have seized an old satellite. Gain initial access, pivot to the internal network, and disable the mining operation. Beware of the watchdog reset.",
            "objectives": ["Exploit Web Entry", "Pivot to 10.10.x.x", "Bypass Local Firewall", "Reverse Engineer Protocol"],
            "tags": ["Satellite", "Reverse", "Insane"],
            "flag": "AG{s4t3llit3_r3cl4im3d}",
            "machineId": "satellite-control-lab",
            "image": "./assets/ctf/ctf_black_box_protocol.png"
        }
    ],
    "tier5": [ // Singularity
        {
            "id": "ctf-dark-matter-object",
            "title": "Dark Matter Object",
            "difficulty": "insane",
            "tier": 5,
            "points": 1500,
            "category": "Web / Deserialization",
            "description": "An unstable core processing raw serialized streams. Can you achieve total control?",
            "scenario": "The 'Dark Matter' engine runs on a legacy Python core that processes session data using the Pickett protocol. No authentication or validation is performed on the incoming streams. Your objective is to forge a malicious serialized object that, when processed by the core, executes remote commands to exfiltrate the hidden system flag.",
            "objectives": ["Analyze Session Serialization Format", "Develop Python RCE Payload", "Exfiltrate Environment Variables"],
            "tags": ["Deserialization", "RCE", "Pickle", "Python"],
            "flag": "AG{D3s3r1al1z4t10n_1s_D3adly_RCE}",
            "machineId": "ctf-dark-matter-object",
            "image": "./assets/ctf/ctf_dark_matter_object_v1_1768039493497.png"
        },
        {
            "id": "ctf-singularity-bank",
            "title": "Project Singularity",
            "difficulty": "legendary",
            "tier": 5,
            "points": 2500,
            "category": "Red Team Simulation",
            "description": "The ultimate test. Compromise the highly secure Central Bank.",
            "scenario": "A full-scale simulation of a modern financial institution. Antivirus, EDR, and Firewalls are live. You must develop a custom payload to bypass defenses and exfiltrate the root keys.",
            "objectives": ["Bypass EDR", "Develop FUD Malware", "Compromise Domain Controller", "Exfiltrate Root Keys"],
            "tags": ["Full Chain", "AI", "Simulation"],
            "flag": "AG{th3_s1ngul4r1ty_1s_h3r3_2026}",
            "machineId": "singularity-core-lab",
            "image": "./assets/ctf/ctf_singularity_v2_1768037996908.png"
        }
    ],

    // --- NEW CHALLENGES (Phase 6) ---
    "tier6": [ // Cloud & Advanced
        {
            "id": "ctf-s3-treasure",
            "title": "S3 Treasure Hunt",
            "difficulty": "medium",
            "tier": 2,
            "points": 300,
            "category": "Cloud / AWS",
            "description": "A startup left their backup bucket public. Time to dig for gold.",
            "scenario": "TechStartup Inc just went through a security audit. Too bad they forgot about their old dev environment. Find the exposed S3 bucket and extract the secret credentials.",
            "objectives": ["Enumerate S3 Buckets", "Access Public Objects", "Extract credentials.json"],
            "tags": ["AWS", "S3", "Cloud"],
            "flag": "BL{s3_buck3t_l00t_4cqu1r3d}",
            "machineId": "ctf-s3-treasure"
        },
        {
            "id": "ctf-lambda-backdoor",
            "title": "Lambda Backdoor",
            "difficulty": "hard",
            "tier": 3,
            "points": 600,
            "category": "Cloud / Serverless",
            "description": "An SSRF in a serverless function leads to credential theft.",
            "scenario": "The company's webhook processor has an SSRF vulnerability. Use it to query the metadata service and steal Lambda's IAM credentials, then pivot to access the secret flag stored in Secrets Manager.",
            "objectives": ["Discover SSRF", "Query Metadata Service", "Steal IAM Creds", "Access Secrets Manager"],
            "tags": ["AWS", "Lambda", "SSRF", "IAM"],
            "flag": "BL{l4mbd4_cr3ds_3xf1ltr4t3d}",
            "machineId": "ctf-lambda-backdoor"
        },
        {
            "id": "ctf-azure-consent",
            "title": "OAuth Consent Trap",
            "difficulty": "hard",
            "tier": 3,
            "points": 550,
            "category": "Cloud / Azure",
            "description": "A malicious OAuth application is harvesting corporate data.",
            "scenario": "You're investigating a phishing campaign targeting Azure AD users. The attacker has deployed a malicious OAuth app that requests excessive permissions. Analyze the app, understand the attack, and find the flag hidden in the compromised data.",
            "objectives": ["Analyze OAuth Flow", "Identify Malicious Scopes", "Extract Leaked Data"],
            "tags": ["Azure AD", "OAuth", "Phishing"],
            "flag": "BL{c0ns3nt_ph1sh1ng_d3t3ct3d}",
            "machineId": "ctf-azure-consent"
        },
        {
            "id": "ctf-memory-ghost",
            "title": "Memory Ghost",
            "difficulty": "hard",
            "tier": 3,
            "points": 650,
            "category": "Forensics / Memory",
            "description": "A memory dump from a compromised machine. Can you find the malware?",
            "scenario": "The IR team captured a memory image from an infected workstation. Using Volatility, analyze the dump to find the hidden malware process, extract the C2 server address, and discover the flag embedded in the malware's strings.",
            "objectives": ["Analyze Memory with Volatility", "Identify Suspicious Process", "Extract Malware Strings", "Find Hidden Flag"],
            "tags": ["Volatility", "Memory Forensics", "DFIR"],
            "flag": "BL{m3m0ry_f0r3ns1cs_m4st3r}",
            "machineId": "ctf-memory-ghost"
        },
        {
            "id": "ctf-log-hunter",
            "title": "Log Hunter",
            "difficulty": "medium",
            "tier": 2,
            "points": 350,
            "category": "Forensics / Log Analysis",
            "description": "400GB of logs. One indicator of compromise. Ready?",
            "scenario": "The SOC detected unusual activity but the alert was lost in the noise. Parse through Windows Event Logs to find the initial compromise - a PowerShell download cradle executed at 3 AM.",
            "objectives": ["Parse Event Logs", "Find Encoded PowerShell", "Decode the Payload", "Extract the Flag"],
            "tags": ["Windows Logs", "PowerShell", "SIEM"],
            "flag": "BL{l0g_4n4lys1s_pr0}",
            "machineId": "ctf-log-hunter"
        },
        {
            "id": "ctf-ssrf-internal",
            "title": "SSRF to Internal",
            "difficulty": "hard",
            "tier": 3,
            "points": 500,
            "category": "Web / SSRF",
            "description": "A PDF generator with a fatal flaw. Reach the internal admin panel.",
            "scenario": "The company's invoice generator accepts URLs to include as logos. However, it doesn't validate the target. Use this SSRF to access the internal admin panel at http://localhost:8080/admin and steal the flag.",
            "objectives": ["Identify SSRF Vector", "Bypass URL Filters", "Access Internal Panel", "Extract Flag"],
            "tags": ["SSRF", "Web", "Internal"],
            "flag": "BL{ssrf_1nt3rn4l_pwn3d}",
            "machineId": "ctf-ssrf-internal"
        },
        {
            "id": "ctf-xxe-exfil",
            "title": "XXE Exfiltration",
            "difficulty": "hard",
            "tier": 3,
            "points": 550,
            "category": "Web / XXE",
            "description": "An XML parser that trusts external entities. Time to exfiltrate.",
            "scenario": "The legacy document import feature parses XML without disabling external entities. Craft a malicious DTD to read /etc/passwd and exfiltrate it via out-of-band techniques to your controlled server.",
            "objectives": ["Craft XXE Payload", "Exfiltrate /etc/passwd", "Use OOB Technique", "Find Flag in /opt/secret"],
            "tags": ["XXE", "XML", "OOB"],
            "flag": "BL{xx3_00b_3xf1ltr4t10n}",
            "machineId": "ctf-xxe-exfil"
        },
        {
            "id": "ctf-race-condition",
            "title": "Race to the Bank",
            "difficulty": "hard",
            "tier": 3,
            "points": 600,
            "category": "Web / Race Condition",
            "description": "A coupon system with a timing vulnerability. Get infinite discounts.",
            "scenario": "The e-commerce platform's coupon redemption has a TOCTOU vulnerability. By sending multiple simultaneous requests, you can apply the same coupon multiple times before the 'used' flag is set.",
            "objectives": ["Identify Race Condition", "Craft Parallel Requests", "Exploit TOCTOU", "Get Flag from Admin"],
            "tags": ["Race Condition", "Concurrency", "Web"],
            "flag": "BL{r4c3_c0nd1t10n_w1nn3r}",
            "machineId": "ctf-race-condition"
        },
        {
            "id": "ctf-graphql-introspection",
            "title": "GraphQL Secrets",
            "difficulty": "medium",
            "tier": 2,
            "points": 400,
            "category": "API / GraphQL",
            "description": "A GraphQL API with introspection enabled. Map the schema and find the hidden data.",
            "scenario": "The startup's new API uses GraphQL but forgot to disable introspection in production. Query the schema, find the hidden 'internalNotes' field, and extract the flag from the CEO's user object.",
            "objectives": ["Query __schema", "Discover Hidden Fields", "Craft Data Query", "Extract Flag"],
            "tags": ["GraphQL", "API", "Introspection"],
            "flag": "BL{gr4phql_1ntr0sp3ct10n}",
            "machineId": "ctf-graphql-introspection"
        },
        {
            "id": "ctf-jwt-confusion",
            "title": "JWT Key Confusion",
            "difficulty": "insane",
            "tier": 4,
            "points": 800,
            "category": "Web / JWT",
            "description": "RS256 public key confusion attack. Forge admin tokens.",
            "scenario": "The API uses RS256 JWTs but exposes the public key. Due to misconfiguration, the server also accepts HS256 tokens. Use the algorithm confusion attack to sign your own admin token using the public key as the HMAC secret.",
            "objectives": ["Extract Public Key", "Understand Algorithm Confusion", "Forge HS256 Token", "Access Admin Endpoint"],
            "tags": ["JWT", "RS256", "HS256", "Crypto"],
            "flag": "BL{jwt_4lg0_c0nfus10n}",
            "machineId": "ctf-jwt-confusion"
        },
        {
            "id": "ctf-prototype-pollution",
            "title": "Prototype Pollution",
            "difficulty": "hard",
            "tier": 3,
            "points": 600,
            "category": "Web / JavaScript",
            "description": "Pollute the prototype chain to achieve RCE.",
            "scenario": "The Node.js API merges user input into configuration objects without sanitization. Use prototype pollution to inject malicious properties that enable remote code execution when the server renders templates.",
            "objectives": ["Find Merge Function", "Inject __proto__", "Achieve RCE via Template", "Read /flag.txt"],
            "tags": ["Prototype Pollution", "Node.js", "RCE"],
            "flag": "BL{pr0t0typ3_p0llut10n_rc3}",
            "machineId": "ctf-prototype-pollution"
        },
        {
            "id": "ctf-disk-forensics",
            "title": "Disk Detective",
            "difficulty": "medium",
            "tier": 2,
            "points": 400,
            "category": "Forensics / Disk",
            "description": "A disk image from a ransomware victim. Recover the deleted files.",
            "scenario": "The attacker deleted the original files after encryption. Using Autopsy and Sleuth Kit, recover the deleted documents from the disk image and find the flag hidden in a recovered PDF.",
            "objectives": ["Mount Disk Image", "Run Autopsy Analysis", "Recover Deleted Files", "Extract Flag from PDF"],
            "tags": ["Disk Forensics", "Autopsy", "Recovery"],
            "flag": "BL{d3l3t3d_f1l3s_r3c0v3r3d}",
            "machineId": "ctf-disk-forensics"
        }
    ]
};

// Map old keys to tiers for compatibility if needed, or flatten
const allChallenges = [
    ...CTFData.tier1,
    ...CTFData.tier2,
    ...CTFData.tier3,
    ...CTFData.tier4,
    ...CTFData.tier5,
    ...CTFData.tier6
];

if (typeof window !== 'undefined') {
    window.CTFData = CTFData;
    window.ctfChallengesData = allChallenges;
    window.getAllCTFChallenges = () => allChallenges;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CTFData, ctfChallengesData: allChallenges };
}

