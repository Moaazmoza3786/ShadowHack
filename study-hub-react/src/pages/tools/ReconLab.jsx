import React, { useState, useEffect, useRef } from 'react';
import {
    Radar, Crosshair, Globe, Zap, Activity, Play
} from 'lucide-react';
import { io } from 'socket.io-client';
import { useAppContext } from '../../context/AppContext';
import { useToast } from '../../context/ToastContext';

const ReconLab = () => {
    const { apiUrl } = useAppContext();
    const { toast } = useToast();

    // --- STATE ---
    const [target, setTarget] = useState('scanme.nmap.org');
    const [activeTab, setActiveTab] = useState('portscan');
    const [isScanning, setIsScanning] = useState(false);
    const [socket, setSocket] = useState(null);
    const [outputBuffer, setOutputBuffer] = useState([]);

    const terminalRef = useRef(null);

    const addLog = (text) => {
        setOutputBuffer(prev => [...prev, text]);
    };

    // --- SOCKET CONNECTION ---
    useEffect(() => {
        const newSocket = io(apiUrl.replace('/api', '') + '/ws/tools', {
            transports: ['websocket']
        });

        newSocket.on('connect', () => {
            addLog('\u001b[1;32m⚡ TOOL ENGINE ONLINE ⚡\u001b[0m');
        });

        newSocket.on('tool_output', (data) => {
            const text = data.data || data;
            addLog(text);
            if (text.toLowerCase().includes('complete') || text.toLowerCase().includes('done')) {
                setIsScanning(false);
            }
        });

        const t = setTimeout(() => setSocket(newSocket), 0);

        return () => {
            clearTimeout(t);
            newSocket.disconnect();
        };
    }, [apiUrl]);

    // Auto-scroll terminal
    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [outputBuffer]);

    // --- DATA ---
    const tools = {
        subdomain: {
            icon: Globe, items: [
                { name: 'Subfinder', cmd: 'subfinder -d {DOMAIN}', desc: 'Fast passive subdomain enum' },
                { name: 'Ping', cmd: 'ping -c 4 {DOMAIN}', desc: 'Connectivity check' },
                { name: 'Dig', cmd: 'dig {DOMAIN} ANY +noall +answer', desc: 'DNS enumeration' }
            ]
        },
        portscan: {
            icon: Activity, items: [
                { name: 'Nmap Quick', cmd: 'nmap -F {IP}', desc: 'Fast 100 port scan' },
                { name: 'Nmap Version', cmd: 'nmap -sV -p 80,443 {IP}', desc: 'Service version detection' },
                { name: 'Nmap Full', cmd: 'nmap -p- -T4 {IP}', desc: 'Full port scan (Slow)' }
            ]
        },
        alive: {
            icon: Zap, items: [
                { name: 'HTTP Probe', cmd: 'httpx -u http://{DOMAIN} -title -status-code', desc: 'Check if web server is up' },
                { name: 'Whois', cmd: 'whois {DOMAIN}', desc: 'Domain registration info' }
            ]
        }
    };

    // --- ACTIONS ---
    const runTool = (cmdTemplate) => {
        if (!target) {
            toast('Please enter a target domain/IP', 'error');
            return;
        }

        // Sanitize check (basic)
        if (target.includes(';') || target.includes('&')) {
            addLog('\u001b[1;31m[!] Invalid target characters detected.\u001b[0m');
            return;
        }

        const cmd = cmdTemplate.replace(/{DOMAIN}/g, target).replace(/{IP}/g, target);

        setIsScanning(true);
        addLog(`\r\n\u001b[1;34mroot@kali:~# ${cmd}\u001b[0m`);

        if (socket) {
            socket.emit('execute_tool', { cmd });
        } else {
            addLog('\u001b[1;31m[!] Error: Socket not connected.\u001b[0m');
            setIsScanning(false);
        }
    };

    return (
        <div className="h-full flex flex-col p-6 max-w-[1800px] mx-auto overflow-hidden">
            {/* Header */}
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-500 flex items-center gap-3">
                        <Radar className="w-8 h-8 text-blue-400" />
                        Recon Lab <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded ml-2 border border-red-500/30">PRO</span>
                    </h1>
                    <p className="text-gray-400 text-sm">Professional Asset Intelligence Engine</p>
                </div>
                <div className="flex items-center gap-4 bg-gray-900/50 p-2 rounded-xl border border-white/10">
                    <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 rounded-lg border border-red-500/20">
                        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                        <span className="text-xs font-bold text-red-400">LIVE EXECUTION</span>
                    </div>
                    <Crosshair className="w-5 h-5 text-gray-400 ml-2" />
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="bg-transparent text-white font-mono outline-none w-64"
                        placeholder="Target Domain / IP"
                    />
                </div>
            </div>

            <div className="flex-1 flex gap-6 min-h-0">
                {/* Tools Sidebar */}
                <div className="w-64 shrink-0 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl overflow-hidden flex flex-col">
                    <div className="p-4 text-xs font-bold text-gray-500 uppercase tracking-widest bg-white/5">Toolkit</div>
                    <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-2">
                        {Object.keys(tools).map((key) => (
                            <div key={key} className="space-y-1">
                                <button
                                    onClick={() => setActiveTab(key)}
                                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-bold transition-all ${activeTab === key
                                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                                        : 'text-gray-400 hover:bg-white/5 hover:text-white'
                                        }`}
                                >
                                    {React.createElement(tools[key].icon, { className: "w-4 h-4" })}
                                    <span className="capitalize">{key}</span>
                                </button>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Main Action Area */}
                <div className="flex-1 flex flex-col gap-6">
                    {/* Active Tool Panel */}
                    <div className="bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl p-6 min-h-[200px]">
                        {tools[activeTab] && (
                            <div className="animate-fade-in">
                                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2 capitalize">
                                    {React.createElement(tools[activeTab].icon, { className: 'w-6 h-6 text-cyan-400' })}
                                    {activeTab} Modules
                                </h2>
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                    {tools[activeTab].items.map((tool, i) => (
                                        <div key={i} className="bg-black/40 border border-white/5 rounded-lg p-4 group hover:border-cyan-500/30 transition-all flex flex-col justify-between gap-3">
                                            <div>
                                                <div className="flex justify-between items-start mb-1">
                                                    <h3 className="font-bold text-white">{tool.name}</h3>
                                                </div>
                                                <p className="text-xs text-gray-500">{tool.desc}</p>
                                            </div>

                                            <div className="flex items-center gap-2 mt-2">
                                                <code className="hidden md:block flex-1 bg-black/60 px-2 py-1.5 rounded text-xs font-mono text-cyan-500/70 truncate border border-white/5">
                                                    {tool.cmd}
                                                </code>
                                                <button
                                                    onClick={() => runTool(tool.cmd)}
                                                    disabled={isScanning}
                                                    className="w-full md:w-auto px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold uppercase rounded-lg shadow-lg shadow-cyan-900/20 transition-all flex items-center justify-center gap-2"
                                                >
                                                    {isScanning ? <Activity className="w-3 h-3 animate-spin" /> : <Play size={12} fill="currentColor" />}
                                                    {isScanning ? 'Scanning...' : 'Run'}
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Terminal Output */}
                    <div className="flex-1 min-h-[400px] relative rounded-xl overflow-hidden border border-white/10 shadow-2xl bg-[#0a0a0a]">
                        <div className="absolute inset-0 p-4 font-mono text-sm overflow-y-auto custom-scrollbar">
                            {outputBuffer.map((line, i) => {
                                // Use split/join to avoid regex control character linting
                                const processedLine = line
                                    .split('\u001b[1;32m').join('<span class="text-green-400 font-bold">')
                                    .split('\u001b[1;31m').join('<span class="text-red-500 font-bold">')
                                    .split('\u001b[1;34m').join('<span class="text-blue-400 font-bold">')
                                    .split('\u001b[1;33m').join('<span class="text-yellow-400 font-bold">')
                                    .split('\u001b[0m').join('</span>');

                                return (
                                    <div key={i} className="whitespace-pre-wrap break-words leading-tight"
                                        dangerouslySetInnerHTML={{ __html: processedLine }}
                                    />
                                );
                            })}
                            <div ref={terminalRef} />
                        </div>

                        {/* Status Bar */}
                        <div className="absolute bottom-0 left-0 right-0 h-6 bg-white/5 border-t border-white/5 flex items-center justify-between px-3 text-[10px] text-gray-500 font-mono">
                            <span>STATUS: {socket ? 'CONNECTED' : 'DISCONNECTED'}</span>
                            <span>MODE: EXECUTION</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReconLab;
