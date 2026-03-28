/* ==================== MITRE ATT&CK MATRIX PRO 🎯📊 ==================== */
/* Comprehensive Skill Gap Analyzer for Red Teamers - Enhanced */

window.MitreMatrix = {
    // === COMPLETE ATT&CK DATA ===
    tactics: [
        {
            id: 'TA0043', name: 'Reconnaissance', color: '#3498db',
            techniques: [
                { id: 'T1595', name: 'Active Scanning', desc: 'Port scans, Vulnerability scans', tools: ['Nmap', 'Masscan'] },
                { id: 'T1595.001', name: 'Scanning IP Blocks', desc: 'Network range scanning', tools: ['Nmap', 'Zmap'] },
                { id: 'T1595.002', name: 'Vulnerability Scanning', desc: 'Nessus, OpenVAS', tools: ['Nessus', 'Nuclei'] },
                { id: 'T1592', name: 'Gather Victim Host Info', desc: 'OS, Services, Software', tools: ['Shodan', 'Censys'] },
                { id: 'T1592.001', name: 'Hardware', desc: 'Device fingerprinting', tools: ['Nmap OS'] },
                { id: 'T1592.002', name: 'Software', desc: 'Web tech detection', tools: ['Wappalyzer', 'WhatWeb'] },
                { id: 'T1589', name: 'Gather Victim Identity', desc: 'Emails, Users, Credentials', tools: ['theHarvester'] },
                { id: 'T1589.001', name: 'Credentials', desc: 'Credential stuffing lists', tools: ['Dehashed'] },
                { id: 'T1589.002', name: 'Email Addresses', desc: 'Email enumeration', tools: ['Hunter.io'] },
                { id: 'T1593', name: 'Search Open Sources', desc: 'OSINT, Social Media', tools: ['Maltego'] },
                { id: 'T1593.001', name: 'Social Media', desc: 'LinkedIn, Twitter recon', tools: ['Sherlock'] },
                { id: 'T1594', name: 'Search Victim Sites', desc: 'Website content analysis', tools: ['Burp'] }
            ]
        },
        {
            id: 'TA0042', name: 'Resource Development', color: '#9b59b6',
            techniques: [
                { id: 'T1583', name: 'Acquire Infrastructure', desc: 'C2 Servers, Domains', tools: ['AWS', 'Azure'] },
                { id: 'T1583.001', name: 'Domains', desc: 'Lookalike domains', tools: ['Namecheap'] },
                { id: 'T1583.003', name: 'VPS', desc: 'Virtual servers', tools: ['DigitalOcean'] },
                { id: 'T1584', name: 'Compromise Infrastructure', desc: 'Hijack servers', tools: ['Shodan'] },
                { id: 'T1587', name: 'Develop Capabilities', desc: 'Malware, Exploits', tools: ['msfvenom'] },
                { id: 'T1587.001', name: 'Malware', desc: 'Custom implants', tools: ['C2 Frameworks'] },
                { id: 'T1587.002', name: 'Code Signing Certs', desc: 'Signed malware', tools: ['OpenSSL'] },
                { id: 'T1585', name: 'Establish Accounts', desc: 'Social Media, Email', tools: ['ProtonMail'] },
                { id: 'T1586', name: 'Compromise Accounts', desc: 'Account takeover', tools: ['Credential stuffing'] }
            ]
        },
        {
            id: 'TA0001', name: 'Initial Access', color: '#e74c3c',
            techniques: [
                { id: 'T1566', name: 'Phishing', desc: 'Spear-phishing, Attachments', tools: ['Gophish', 'King Phisher'] },
                { id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'Malicious documents', tools: ['maldoc'] },
                { id: 'T1566.002', name: 'Spearphishing Link', desc: 'Credential harvesting', tools: ['Evilginx'] },
                { id: 'T1190', name: 'Exploit Public Apps', desc: 'Web App Vulns, RCE', tools: ['Nuclei', 'Burp'] },
                { id: 'T1133', name: 'External Remote Services', desc: 'VPN, RDP, SSH', tools: ['Hydra', 'Ncrack'] },
                { id: 'T1078', name: 'Valid Accounts', desc: 'Credential Stuffing', tools: ['Hydra'] },
                { id: 'T1078.001', name: 'Default Accounts', desc: 'Factory credentials', tools: ['DefaultCreds'] },
                { id: 'T1078.002', name: 'Domain Accounts', desc: 'AD credentials', tools: ['CrackMapExec'] },
                { id: 'T1189', name: 'Drive-by Compromise', desc: 'Browser exploitation', tools: ['BeEF'] },
                { id: 'T1195', name: 'Supply Chain Compromise', desc: 'Third-party software', tools: ['Dep-scan'] },
                { id: 'T1199', name: 'Trusted Relationship', desc: 'Partner compromise', tools: ['BloodHound'] }
            ]
        },
        {
            id: 'TA0002', name: 'Execution', color: '#f39c12',
            techniques: [
                { id: 'T1059', name: 'Command & Script', desc: 'PowerShell, Bash, Python', tools: ['PowerShell'] },
                { id: 'T1059.001', name: 'PowerShell', desc: 'PS scripts', tools: ['PowerShell ISE'] },
                { id: 'T1059.003', name: 'Windows Cmd', desc: 'CMD.exe', tools: ['cmd.exe'] },
                { id: 'T1059.004', name: 'Unix Shell', desc: 'Bash, sh, zsh', tools: ['Bash'] },
                { id: 'T1059.005', name: 'VBScript', desc: 'Visual Basic scripting', tools: ['cscript'] },
                { id: 'T1059.006', name: 'Python', desc: 'Python scripts', tools: ['Python'] },
                { id: 'T1059.007', name: 'JavaScript', desc: 'JS/JScript', tools: ['Node.js'] },
                { id: 'T1203', name: 'Exploitation for Execution', desc: 'Browser, Office', tools: ['msfconsole'] },
                { id: 'T1047', name: 'WMI', desc: 'Windows Management', tools: ['wmic'] },
                { id: 'T1053', name: 'Scheduled Task', desc: 'Cron, Task Scheduler', tools: ['schtasks'] },
                { id: 'T1053.002', name: 'At Jobs', desc: 'at command', tools: ['at'] },
                { id: 'T1053.003', name: 'Cron', desc: 'Linux cron', tools: ['crontab'] },
                { id: 'T1053.005', name: 'Scheduled Task', desc: 'Windows tasks', tools: ['schtasks'] },
                { id: 'T1204', name: 'User Execution', desc: 'Social engineering', tools: ['Phishing'] },
                { id: 'T1569', name: 'System Services', desc: 'Service execution', tools: ['sc.exe'] }
            ]
        },
        {
            id: 'TA0003', name: 'Persistence', color: '#1abc9c',
            techniques: [
                { id: 'T1547', name: 'Boot/Logon Autostart', desc: 'Registry, Startup', tools: ['Autoruns'] },
                { id: 'T1547.001', name: 'Registry Run Keys', desc: 'HKLM/HKCU Run', tools: ['reg.exe'] },
                { id: 'T1547.004', name: 'Winlogon Helper', desc: 'Winlogon DLLs', tools: ['regedit'] },
                { id: 'T1547.009', name: 'Shortcut Modification', desc: 'LNK files', tools: ['mklnk'] },
                { id: 'T1136', name: 'Create Account', desc: 'Backdoor Users', tools: ['net user'] },
                { id: 'T1136.001', name: 'Local Account', desc: 'Local user creation', tools: ['net user'] },
                { id: 'T1136.002', name: 'Domain Account', desc: 'AD user creation', tools: ['PowerView'] },
                { id: 'T1543', name: 'Create/Modify Service', desc: 'System Services', tools: ['sc.exe'] },
                { id: 'T1543.003', name: 'Windows Service', desc: 'Service creation', tools: ['sc create'] },
                { id: 'T1505', name: 'Server Software', desc: 'Web Shells', tools: ['weevely'] },
                { id: 'T1505.003', name: 'Web Shell', desc: 'PHP/ASPX shells', tools: ['weevely'] },
                { id: 'T1098', name: 'Account Manipulation', desc: 'Modify permissions', tools: ['net group'] },
                { id: 'T1053.005', name: 'Scheduled Task', desc: 'Persistence via tasks', tools: ['schtasks'] }
            ]
        },
        {
            id: 'TA0004', name: 'Privilege Escalation', color: '#9b59b6',
            techniques: [
                { id: 'T1068', name: 'Exploit for PrivEsc', desc: 'Kernel Exploits', tools: ['searchsploit'] },
                { id: 'T1055', name: 'Process Injection', desc: 'DLL, Shellcode injection', tools: ['Cobalt Strike'] },
                { id: 'T1055.001', name: 'DLL Injection', desc: 'LoadLibrary injection', tools: ['Inject.exe'] },
                { id: 'T1055.002', name: 'PE Injection', desc: 'Portable Executable', tools: ['msfvenom'] },
                { id: 'T1055.003', name: 'Thread Hijacking', desc: 'Thread execution hijack', tools: ['SuspendThread'] },
                { id: 'T1055.012', name: 'Process Hollowing', desc: 'Replace process memory', tools: ['ProcessGhost'] },
                { id: 'T1548', name: 'Abuse Elevation', desc: 'UAC Bypass, Sudo', tools: ['UACME'] },
                { id: 'T1548.001', name: 'Setuid/Setgid', desc: 'SUID binaries', tools: ['GTFOBins'] },
                { id: 'T1548.002', name: 'UAC Bypass', desc: 'Windows UAC', tools: ['UACME'] },
                { id: 'T1548.003', name: 'Sudo Caching', desc: 'Sudo tokens', tools: ['sudo -l'] },
                { id: 'T1134', name: 'Access Token Manipulation', desc: 'Token impersonation', tools: ['Incognito'] },
                { id: 'T1134.001', name: 'Token Impersonation', desc: 'Steal tokens', tools: ['Mimikatz'] },
                { id: 'T1574', name: 'Hijack Execution Flow', desc: 'DLL hijacking', tools: ['DLL Hijack'] }
            ]
        },
        {
            id: 'TA0005', name: 'Defense Evasion', color: '#34495e',
            techniques: [
                { id: 'T1070', name: 'Indicator Removal', desc: 'Log Deletion', tools: ['wevtutil'] },
                { id: 'T1070.001', name: 'Clear Windows Logs', desc: 'Event log clearing', tools: ['wevtutil'] },
                { id: 'T1070.003', name: 'Clear Command History', desc: 'Bash history', tools: ['history -c'] },
                { id: 'T1070.004', name: 'File Deletion', desc: 'Remove artifacts', tools: ['sdelete'] },
                { id: 'T1036', name: 'Masquerading', desc: 'Rename Files', tools: ['rename'] },
                { id: 'T1036.003', name: 'Rename System Utils', desc: 'Tool renaming', tools: ['copy'] },
                { id: 'T1036.005', name: 'Match Legitimate Name', desc: 'Lookalike names', tools: ['rename'] },
                { id: 'T1027', name: 'Obfuscated Files', desc: 'Encoding, Packing', tools: ['UPX', 'Themida'] },
                { id: 'T1027.002', name: 'Software Packing', desc: 'Binary packers', tools: ['UPX'] },
                { id: 'T1027.005', name: 'Indicator Removal', desc: 'String removal', tools: ['strip'] },
                { id: 'T1562', name: 'Impair Defenses', desc: 'Disable AV', tools: ['Defender Control'] },
                { id: 'T1562.001', name: 'Disable Security Tools', desc: 'Kill AV processes', tools: ['taskkill'] },
                { id: 'T1562.004', name: 'Disable Logging', desc: 'Audit policy', tools: ['auditpol'] },
                { id: 'T1140', name: 'Deobfuscate/Decode', desc: 'Runtime decryption', tools: ['base64'] },
                { id: 'T1218', name: 'System Binary Proxy', desc: 'LOLBins execution', tools: ['mshta', 'rundll32'] }
            ]
        },
        {
            id: 'TA0006', name: 'Credential Access', color: '#e74c3c',
            techniques: [
                { id: 'T1003', name: 'OS Credential Dumping', desc: 'Mimikatz, LSASS', tools: ['Mimikatz'] },
                { id: 'T1003.001', name: 'LSASS Memory', desc: 'LSASS dump', tools: ['Mimikatz'] },
                { id: 'T1003.002', name: 'SAM', desc: 'SAM database', tools: ['secretsdump'] },
                { id: 'T1003.003', name: 'NTDS', desc: 'AD database', tools: ['ntdsutil'] },
                { id: 'T1003.004', name: 'LSA Secrets', desc: 'Registry secrets', tools: ['secretsdump'] },
                { id: 'T1003.005', name: 'Cached Credentials', desc: 'Domain cache', tools: ['cachedump'] },
                { id: 'T1003.006', name: 'DCSync', desc: 'Replicate DC', tools: ['secretsdump'] },
                { id: 'T1110', name: 'Brute Force', desc: 'Password attacks', tools: ['Hydra'] },
                { id: 'T1110.001', name: 'Password Guessing', desc: 'Common passwords', tools: ['Hydra'] },
                { id: 'T1110.003', name: 'Password Spraying', desc: 'Single password', tools: ['Spray'] },
                { id: 'T1558', name: 'Steal Kerberos Tickets', desc: 'Ticket attacks', tools: ['Rubeus'] },
                { id: 'T1558.003', name: 'Kerberoasting', desc: 'SPN tickets', tools: ['GetUserSPNs'] },
                { id: 'T1558.004', name: 'AS-REP Roasting', desc: 'No preauth', tools: ['GetNPUsers'] },
                { id: 'T1552', name: 'Unsecured Credentials', desc: 'Files, Registry', tools: ['LaZagne'] },
                { id: 'T1552.001', name: 'Credentials in Files', desc: 'Config files', tools: ['grep'] },
                { id: 'T1555', name: 'Credentials from Password Stores', desc: 'Browser, vault', tools: ['LaZagne'] }
            ]
        },
        {
            id: 'TA0007', name: 'Discovery', color: '#3498db',
            techniques: [
                { id: 'T1087', name: 'Account Discovery', desc: 'User Enumeration', tools: ['net user'] },
                { id: 'T1087.001', name: 'Local Account', desc: 'Local users', tools: ['net user'] },
                { id: 'T1087.002', name: 'Domain Account', desc: 'AD users', tools: ['PowerView'] },
                { id: 'T1083', name: 'File/Dir Discovery', desc: 'List Files', tools: ['dir', 'ls'] },
                { id: 'T1046', name: 'Network Service Scan', desc: 'Port Scans', tools: ['Nmap'] },
                { id: 'T1018', name: 'Remote System Discovery', desc: 'Ping Sweep', tools: ['ping'] },
                { id: 'T1016', name: 'System Network Config', desc: 'IP config', tools: ['ipconfig'] },
                { id: 'T1049', name: 'System Network Connections', desc: 'Active connections', tools: ['netstat'] },
                { id: 'T1069', name: 'Permission Groups', desc: 'Group membership', tools: ['net group'] },
                { id: 'T1069.001', name: 'Local Groups', desc: 'Local groups', tools: ['net localgroup'] },
                { id: 'T1069.002', name: 'Domain Groups', desc: 'AD groups', tools: ['PowerView'] },
                { id: 'T1057', name: 'Process Discovery', desc: 'Running processes', tools: ['ps', 'tasklist'] },
                { id: 'T1012', name: 'Query Registry', desc: 'Registry values', tools: ['reg query'] },
                { id: 'T1082', name: 'System Information', desc: 'OS info', tools: ['systeminfo'] }
            ]
        },
        {
            id: 'TA0008', name: 'Lateral Movement', color: '#e67e22',
            techniques: [
                { id: 'T1021', name: 'Remote Services', desc: 'RDP, SSH, SMB', tools: ['xfreerdp'] },
                { id: 'T1021.001', name: 'RDP', desc: 'Remote Desktop', tools: ['xfreerdp'] },
                { id: 'T1021.002', name: 'SMB/Admin Shares', desc: 'Windows shares', tools: ['psexec'] },
                { id: 'T1021.003', name: 'DCOM', desc: 'Distributed COM', tools: ['dcomexec'] },
                { id: 'T1021.004', name: 'SSH', desc: 'Secure Shell', tools: ['ssh'] },
                { id: 'T1021.006', name: 'WinRM', desc: 'Windows Remote Mgmt', tools: ['evil-winrm'] },
                { id: 'T1550', name: 'Use Alternate Auth', desc: 'Pass-the-Hash', tools: ['pth-winexe'] },
                { id: 'T1550.002', name: 'Pass-the-Hash', desc: 'NTLM hash auth', tools: ['psexec.py'] },
                { id: 'T1550.003', name: 'Pass-the-Ticket', desc: 'Kerberos ticket', tools: ['Rubeus'] },
                { id: 'T1570', name: 'Lateral Tool Transfer', desc: 'Copy Tools', tools: ['scp', 'smbclient'] },
                { id: 'T1563', name: 'Remote Session Hijack', desc: 'Session Steal', tools: ['tscon'] },
                { id: 'T1534', name: 'Internal Spearphishing', desc: 'Internal phishing', tools: ['Outlook'] }
            ]
        },
        {
            id: 'TA0009', name: 'Collection', color: '#16a085',
            techniques: [
                { id: 'T1560', name: 'Archive Collected Data', desc: 'Zip, 7z', tools: ['7z', 'tar'] },
                { id: 'T1560.001', name: 'Archive via Utility', desc: '7z, WinRAR', tools: ['7z.exe'] },
                { id: 'T1005', name: 'Data from Local System', desc: 'File Grabbing', tools: ['copy'] },
                { id: 'T1114', name: 'Email Collection', desc: 'Outlook, PST', tools: ['MailSniper'] },
                { id: 'T1114.001', name: 'Local Email Collection', desc: 'PST files', tools: ['OutlookExport'] },
                { id: 'T1114.002', name: 'Remote Email Collection', desc: 'Exchange', tools: ['MailSniper'] },
                { id: 'T1113', name: 'Screen Capture', desc: 'Screenshots', tools: ['Import-Module'] },
                { id: 'T1115', name: 'Clipboard Data', desc: 'Clipboard contents', tools: ['Get-Clipboard'] },
                { id: 'T1056', name: 'Input Capture', desc: 'Keylogging', tools: ['Keylogger'] },
                { id: 'T1056.001', name: 'Keylogging', desc: 'Keystroke logging', tools: ['pynput'] },
                { id: 'T1039', name: 'Network Share Collection', desc: 'Share enumeration', tools: ['smbclient'] }
            ]
        },
        {
            id: 'TA0011', name: 'Command & Control', color: '#8e44ad',
            techniques: [
                { id: 'T1071', name: 'Application Layer Proto', desc: 'HTTP, DNS, HTTPS', tools: ['Cobalt Strike'] },
                { id: 'T1071.001', name: 'Web Protocols', desc: 'HTTP/HTTPS C2', tools: ['Covenant'] },
                { id: 'T1071.004', name: 'DNS', desc: 'DNS tunneling', tools: ['dnscat2'] },
                { id: 'T1132', name: 'Data Encoding', desc: 'Base64, XOR', tools: ['base64'] },
                { id: 'T1132.001', name: 'Standard Encoding', desc: 'Base64', tools: ['CyberChef'] },
                { id: 'T1573', name: 'Encrypted Channel', desc: 'TLS, Custom', tools: ['OpenSSL'] },
                { id: 'T1573.001', name: 'Symmetric Crypto', desc: 'AES encryption', tools: ['AES'] },
                { id: 'T1573.002', name: 'Asymmetric Crypto', desc: 'RSA encryption', tools: ['RSA'] },
                { id: 'T1090', name: 'Proxy', desc: 'Multi-hop, Tor', tools: ['proxychains'] },
                { id: 'T1090.001', name: 'Internal Proxy', desc: 'Pivot points', tools: ['chisel'] },
                { id: 'T1090.003', name: 'Multi-hop Proxy', desc: 'Multiple hops', tools: ['ligolo-ng'] },
                { id: 'T1095', name: 'Non-Application Layer', desc: 'Raw sockets', tools: ['ICMP tunnel'] },
                { id: 'T1102', name: 'Web Service', desc: 'C2 via web services', tools: ['Discord', 'Slack'] }
            ]
        },
        {
            id: 'TA0010', name: 'Exfiltration', color: '#c0392b',
            techniques: [
                { id: 'T1041', name: 'Exfil Over C2', desc: 'Via C2 Channel', tools: ['C2 Framework'] },
                { id: 'T1048', name: 'Exfil Over Alt Protocol', desc: 'DNS, ICMP', tools: ['dnscat2'] },
                { id: 'T1048.002', name: 'Exfil Over DNS', desc: 'DNS exfiltration', tools: ['DNSExfiltrator'] },
                { id: 'T1048.003', name: 'Exfil Over ICMP', desc: 'ICMP tunnel', tools: ['ICMP tunnel'] },
                { id: 'T1567', name: 'Exfil Over Web Service', desc: 'Cloud Storage', tools: ['rclone'] },
                { id: 'T1567.002', name: 'Exfil to Cloud', desc: 'Cloud storage', tools: ['Dropbox', 'MEGA'] },
                { id: 'T1020', name: 'Automated Exfiltration', desc: 'Scheduled Transfer', tools: ['cron'] },
                { id: 'T1030', name: 'Data Transfer Size Limits', desc: 'Chunked transfer', tools: ['split'] },
                { id: 'T1537', name: 'Transfer to Cloud Account', desc: 'Attacker cloud', tools: ['AWS CLI'] }
            ]
        },
        {
            id: 'TA0040', name: 'Impact', color: '#2c3e50',
            techniques: [
                { id: 'T1485', name: 'Data Destruction', desc: 'Wipe Data', tools: ['sdelete'] },
                { id: 'T1486', name: 'Data Encrypted for Impact', desc: 'Ransomware', tools: ['Custom crypto'] },
                { id: 'T1489', name: 'Service Stop', desc: 'Kill Processes', tools: ['net stop'] },
                { id: 'T1490', name: 'Inhibit System Recovery', desc: 'Delete backups', tools: ['vssadmin'] },
                { id: 'T1491', name: 'Defacement', desc: 'Web Defacement', tools: ['Custom'] },
                { id: 'T1491.001', name: 'Internal Defacement', desc: 'Internal sites', tools: ['Custom'] },
                { id: 'T1491.002', name: 'External Defacement', desc: 'Public sites', tools: ['Custom'] },
                { id: 'T1498', name: 'Network DoS', desc: 'DDoS attacks', tools: ['LOIC'] },
                { id: 'T1531', name: 'Account Access Removal', desc: 'Lock accounts', tools: ['net user'] },
                { id: 'T1529', name: 'System Shutdown', desc: 'Force reboot', tools: ['shutdown'] }
            ]
        }
    ],

    // === STATE ===
    learnedTechniques: [],
    selectedTactic: null,
    filterMode: 'all', // all, learned, unlearned

    // === AI RECOMMENDATIONS ===
    aiRecommendations: {
        'low': [
            { tactic: 'Reconnaissance', reason: 'Foundation of every attack - start here' },
            { tactic: 'Initial Access', reason: 'Learn entry point techniques next' }
        ],
        'medium': [
            { tactic: 'Execution', reason: 'Practice payload delivery' },
            { tactic: 'Privilege Escalation', reason: 'Essential for post-exploitation' }
        ],
        'high': [
            { tactic: 'Defense Evasion', reason: 'Advanced stealth techniques' },
            { tactic: 'Lateral Movement', reason: 'Critical for enterprise attacks' }
        ]
    },

    // === CERTIFICATION MAPPING ===
    certificationMap: {
        'eJPT': ['T1595', 'T1046', 'T1190', 'T1078', 'T1059', 'T1068', 'T1003', 'T1110', 'T1021'],
        'OSCP': ['T1595', 'T1190', 'T1059', 'T1068', 'T1548', 'T1574', 'T1003', 'T1110', 'T1558', 'T1021', 'T1550', 'T1070'],
        'OSEP': ['T1055', 'T1027', 'T1562', 'T1218', 'T1134', 'T1036', 'T1140', 'T1071', 'T1573'],
        'CRTO': ['T1566', 'T1059.001', 'T1055', 'T1134', 'T1558', 'T1550', 'T1003.006', 'T1071', 'T1090'],
        'PNPT': ['T1595', 'T1589', 'T1566', 'T1190', 'T1078', 'T1059', 'T1068', 'T1003', 'T1021', 'T1041']
    },

    // === RELATED LABS ===
    relatedLabs: {
        'T1190': { lab: 'Web Exploit Lab', tool: 'web-exploit-lab' },
        'T1059': { lab: 'Payload Factory', tool: 'payload-factory' },
        'T1068': { lab: 'PrivEsc Lab', tool: 'privesc-lab' },
        'T1548': { lab: 'PrivEsc Lab', tool: 'privesc-lab' },
        'T1003': { lab: 'Credential Attacks', tool: 'ad-lab' },
        'T1558': { lab: 'AD Lab - Kerberos', tool: 'ad-lab' },
        'T1550': { lab: 'AD Lab - PTH/PTT', tool: 'ad-lab' },
        'T1021': { lab: 'Lateral Movement', tool: 'lateral-movement' },
        'T1070': { lab: 'Stealth Lab', tool: 'stealth-lab' },
        'T1027': { lab: 'Stealth Lab', tool: 'stealth-lab' },
        'T1055': { lab: 'Stealth Lab', tool: 'stealth-lab' },
        'T1595': { lab: 'Recon Lab', tool: 'recon-lab' },
        'T1046': { lab: 'Recon Lab', tool: 'recon-lab' },
        'T1110': { lab: 'Command Reference', tool: 'command-reference' },
        'T1071': { lab: 'C2 Simulator', tool: 'c2-simulator' }
    },

    // === OSCP SPECIFIC CHECKLIST ===
    oscpChecklist: [
        { id: 'T1595', name: 'Nmap Scanning', required: true },
        { id: 'T1190', name: 'Web App Exploitation', required: true },
        { id: 'T1059', name: 'Shell Payloads', required: true },
        { id: 'T1068', name: 'Kernel Exploits', required: true },
        { id: 'T1548', name: 'SUID/UAC Bypass', required: true },
        { id: 'T1574', name: 'DLL Hijacking', required: true },
        { id: 'T1003', name: 'Credential Dumping', required: true },
        { id: 'T1550', name: 'Pass-the-Hash', required: true },
        { id: 'T1021', name: 'Lateral Movement', required: true }
    ],

    // === INIT ===
    init() {
        this.loadProgress();
    },

    loadProgress() {
        try {
            const saved = localStorage.getItem('mitre_progress_v2');
            this.learnedTechniques = saved ? JSON.parse(saved) : [];
        } catch (e) { this.learnedTechniques = []; }
    },

    saveProgress() {
        localStorage.setItem('mitre_progress_v2', JSON.stringify(this.learnedTechniques));
    },

    // === RENDER ===
    render() {
        const totalTechniques = this.tactics.reduce((acc, t) => acc + t.techniques.length, 0);
        const learnedCount = this.learnedTechniques.length;
        const progress = Math.round((learnedCount / totalTechniques) * 100);
        const level = progress < 30 ? 'Beginner' : progress < 60 ? 'Intermediate' : progress < 85 ? 'Advanced' : 'Expert';
        const levelColor = progress < 30 ? '#3498db' : progress < 60 ? '#f39c12' : progress < 85 ? '#9b59b6' : '#e74c3c';

        return `
        <style>${this.getStyles()}</style>
        <div class="mitre-app">
            <div class="mitre-header">
                <div class="header-left">
                    <h1><i class="fas fa-bullseye"></i> MITRE ATT&CK <span class="pro-badge">PRO</span></h1>
                    <p class="subtitle">Track your Red Team skills across the kill chain</p>
                </div>
                <div class="header-stats">
                    <div class="stat-box">
                        <span class="stat-val">${learnedCount}</span>
                        <span class="stat-label">Learned</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-val">${totalTechniques}</span>
                        <span class="stat-label">Total</span>
                    </div>
                    <div class="stat-box level-box" style="--level-color: ${levelColor}">
                        <span class="stat-val level-val">${level}</span>
                        <span class="stat-label">Skill Level</span>
                    </div>
                    <div class="stat-box progress-box">
                        <div class="progress-ring">
                            <svg viewBox="0 0 36 36">
                                <path class="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                                <path class="ring-fill" stroke-dasharray="${progress}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            </svg>
                            <span class="ring-text">${progress}%</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="mitre-filters">
                <button class="${this.filterMode === 'all' ? 'active' : ''}" onclick="MitreMatrix.setFilter('all')">
                    <i class="fas fa-th"></i> All
                </button>
                <button class="${this.filterMode === 'learned' ? 'active' : ''}" onclick="MitreMatrix.setFilter('learned')">
                    <i class="fas fa-check-circle"></i> Learned (${learnedCount})
                </button>
                <button class="${this.filterMode === 'unlearned' ? 'active' : ''}" onclick="MitreMatrix.setFilter('unlearned')">
                    <i class="fas fa-circle"></i> To Learn (${totalTechniques - learnedCount})
                </button>
                <span class="filter-divider"></span>
                <button class="cert-btn ${this.filterMode === 'eJPT' ? 'active' : ''}" onclick="MitreMatrix.setFilter('eJPT')">
                    <i class="fas fa-graduation-cap"></i> eJPT
                </button>
                <button class="cert-btn ${this.filterMode === 'OSCP' ? 'active' : ''}" onclick="MitreMatrix.setFilter('OSCP')">
                    <i class="fas fa-certificate"></i> OSCP
                </button>
                <button class="cert-btn ${this.filterMode === 'OSEP' ? 'active' : ''}" onclick="MitreMatrix.setFilter('OSEP')">
                    <i class="fas fa-user-secret"></i> OSEP
                </button>
                <button class="cert-btn ${this.filterMode === 'CRTO' ? 'active' : ''}" onclick="MitreMatrix.setFilter('CRTO')">
                    <i class="fas fa-skull"></i> CRTO
                </button>
                <button class="cert-btn ${this.filterMode === 'PNPT' ? 'active' : ''}" onclick="MitreMatrix.setFilter('PNPT')">
                    <i class="fas fa-flag"></i> PNPT
                </button>
            </div>

            <div class="mitre-matrix">
                ${this.tactics.map(tactic => this.renderTactic(tactic)).join('')}
            </div>
        </div>`;
    },

    renderTactic(tactic) {
        const learnedInTactic = tactic.techniques.filter(t => this.learnedTechniques.includes(t.id)).length;
        const tacticProgress = Math.round((learnedInTactic / tactic.techniques.length) * 100);

        let techniques = tactic.techniques;
        if (this.filterMode === 'learned') {
            techniques = techniques.filter(t => this.learnedTechniques.includes(t.id));
        } else if (this.filterMode === 'unlearned') {
            techniques = techniques.filter(t => !this.learnedTechniques.includes(t.id));
        } else if (this.certificationMap[this.filterMode]) {
            // Filter by certification
            const certTechniques = this.certificationMap[this.filterMode];
            techniques = techniques.filter(t => certTechniques.includes(t.id) || certTechniques.some(ct => t.id.startsWith(ct + '.')));
        }

        if (techniques.length === 0 && this.filterMode !== 'all') return '';

        return `
        <div class="tactic-column" style="--tactic-color: ${tactic.color}">
            <div class="tactic-header">
                <div class="tactic-name">${tactic.name}</div>
                <div class="tactic-progress">${learnedInTactic}/${tactic.techniques.length}</div>
                <div class="tactic-bar">
                    <div class="tactic-bar-fill" style="width: ${tacticProgress}%"></div>
                </div>
            </div>
            <div class="techniques-list">
                ${techniques.map(tech => this.renderTechnique(tech)).join('')}
            </div>
        </div>`;
    },

    renderTechnique(tech) {
        const isLearned = this.learnedTechniques.includes(tech.id);
        const isSubTechnique = tech.id.includes('.');

        return `
        <div class="technique-card ${isLearned ? 'learned' : ''} ${isSubTechnique ? 'sub-technique' : ''}" 
             onclick="MitreMatrix.toggleTechnique('${tech.id}')" title="${tech.desc}">
            <div class="tech-top">
                <div class="tech-id">${tech.id}</div>
                ${isLearned ? '<div class="check-mark"><i class="fas fa-check"></i></div>' : ''}
            </div>
            <div class="tech-name">${tech.name}</div>
            <div class="tech-tools">${tech.tools ? tech.tools.slice(0, 2).join(', ') : ''}</div>
        </div>`;
    },

    // === ACTIONS ===
    toggleTechnique(id) {
        if (this.learnedTechniques.includes(id)) {
            this.learnedTechniques = this.learnedTechniques.filter(t => t !== id);
        } else {
            this.learnedTechniques.push(id);
        }
        this.saveProgress();
        this.reRender();
    },

    setFilter(mode) {
        this.filterMode = mode;
        this.reRender();
    },

    reRender() {
        const app = document.querySelector('.mitre-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        .mitre-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Rajdhani', sans-serif; }
        
        .mitre-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-bottom: 20px; border-bottom: 2px solid rgba(255,255,255,0.1); flex-wrap: wrap; gap: 20px; }
        .header-left h1 { margin: 0; color: #fff; font-size: 1.8rem; display: flex; align-items: center; gap: 10px; }
        .pro-badge { background: linear-gradient(135deg, #e74c3c, #c0392b); font-size: 0.6rem; padding: 3px 8px; border-radius: 4px; }
        .subtitle { color: #888; margin: 5px 0 0; }
        
        .header-stats { display: flex; gap: 15px; flex-wrap: wrap; }
        .stat-box { background: rgba(255,255,255,0.05); padding: 15px 20px; border-radius: 10px; text-align: center; min-width: 80px; }
        .stat-val { display: block; font-size: 1.8rem; font-weight: bold; color: #fff; }
        .stat-label { font-size: 0.75rem; color: #888; text-transform: uppercase; }
        .level-box .stat-val { color: var(--level-color); font-size: 1rem; }
        
        .progress-ring { width: 70px; height: 70px; position: relative; }
        .progress-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .ring-bg { fill: none; stroke: rgba(255,255,255,0.1); stroke-width: 3; }
        .ring-fill { fill: none; stroke: #00ff88; stroke-width: 3; stroke-linecap: round; transition: stroke-dasharray 0.5s; }
        .ring-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1rem; font-weight: bold; color: #00ff88; }

        .mitre-filters { display: flex; gap: 10px; margin-bottom: 25px; flex-wrap: wrap; align-items: center; }
        .mitre-filters button { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #888; padding: 10px 20px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: 0.2s; }
        .mitre-filters button:hover { background: rgba(255,255,255,0.1); color: #fff; }
        .mitre-filters button.active { background: rgba(0,255,136,0.15); border-color: #00ff88; color: #00ff88; }
        .filter-divider { width: 2px; height: 30px; background: rgba(255,255,255,0.2); margin: 0 10px; }
        .cert-btn { padding: 8px 15px !important; font-size: 0.85rem; }
        .cert-btn.active { background: rgba(231,76,60,0.2) !important; border-color: #e74c3c !important; color: #e74c3c !important; }

        .mitre-matrix { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; }
        
        .tactic-column { background: rgba(0,0,0,0.3); border-radius: 12px; overflow: hidden; border: 1px solid rgba(255,255,255,0.05); }
        
        .tactic-header { background: linear-gradient(135deg, var(--tactic-color), color-mix(in srgb, var(--tactic-color) 70%, black)); padding: 15px; text-align: center; }
        .tactic-name { font-weight: bold; font-size: 0.85rem; color: #fff; text-transform: uppercase; letter-spacing: 1px; }
        .tactic-progress { font-size: 0.75rem; color: rgba(255,255,255,0.8); margin: 5px 0; }
        .tactic-bar { height: 4px; background: rgba(0,0,0,0.3); border-radius: 2px; margin-top: 8px; }
        .tactic-bar-fill { height: 100%; background: rgba(255,255,255,0.8); border-radius: 2px; transition: width 0.3s; }
        
        .techniques-list { padding: 10px; display: flex; flex-direction: column; gap: 6px; max-height: 400px; overflow-y: auto; }
        
        .technique-card { background: rgba(255,255,255,0.03); padding: 10px 12px; border-radius: 8px; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; }
        .technique-card:hover { background: rgba(255,255,255,0.08); transform: translateX(3px); }
        .technique-card.learned { background: rgba(0, 255, 136, 0.1); border-color: rgba(0,255,136,0.3); }
        .technique-card.learned .tech-name { color: #00ff88; }
        .technique-card.sub-technique { margin-left: 10px; padding: 8px 10px; }
        .technique-card.sub-technique .tech-name { font-size: 0.8rem; }
        
        .tech-top { display: flex; justify-content: space-between; align-items: center; }
        .tech-id { font-size: 0.65rem; color: #666; font-family: 'JetBrains Mono', monospace; }
        .tech-name { font-size: 0.85rem; color: #ccc; margin: 4px 0; }
        .tech-tools { font-size: 0.7rem; color: #555; }
        .check-mark { color: #00ff88; font-size: 0.8rem; }

        @media (max-width: 1200px) { .mitre-matrix { grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); } }
        @media (max-width: 768px) { .mitre-matrix { grid-template-columns: 1fr 1fr; } }
        `;
    }
};

function pageMitreMatrix() {
    MitreMatrix.init();
    return MitreMatrix.render();
}
