import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Terminal, Globe, Activity, ShieldAlert,
    Wifi, HardDrive, FileCode, Lock,
    ChevronRight, Download, Skull
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';
import { useCyberRangeEvents, RANGE_EVENTS } from '../../utils/cyberRangeBus';
import { io } from 'socket.io-client';

// ... MOCK FS INTENTIONALY KEPT FOR GAMEPLAY FEEL ... (omitted for brevity in prompt match, but keeping in file)

const C2CommandCenter = () => {
    const { toast } = useToast();

    // STATE
    const [beacons, setBeacons] = useState([
        { id: 'HV-09', ip: '45.33.22.11', os: 'Windows 10', status: 'active', user: 'Admin', tier: 'high', x: 20, y: 30 },
        { id: 'XR-77', ip: '102.99.1.5', os: 'Ubuntu 20.04', status: 'active', user: 'root', tier: 'critical', x: 70, y: 60 },
        { id: 'OM-22', ip: '198.51.100.2', os: 'Server 2019', status: 'dormant', user: 'SYSTEM', tier: 'low', x: 80, y: 20 },
    ]);
    const [selectedAgentId, setSelectedAgentId] = useState(null);
    const [terminalHistory, setTerminalHistory] = useState([]);
    const [cwd, setCwd] = useState([]); // Array of dir names
    const [noiseLevel, setNoiseLevel] = useState(0);
    const [loot, setLoot] = useState([]);
    const terminalEndRef = useRef(null);
    const inputRef = useRef(null);

    // --- REAL EXECUTION ---
    const [socket, setSocket] = useState(null);
    // -----------------------

    // --- SOCKET INIT ---
    useEffect(() => {
        const newSocket = io('http://localhost:5000/ws/tools', { transports: ['websocket'] });
        newSocket.on('tool_output', (data) => {
            const text = data.data || data;
            logOut(text);
        });
        setSocket(newSocket);
        return () => newSocket.disconnect();
    }, []);
    // -------------------

    // KERNEL LOOP (Noise Decay)
    const MOCK_FS = {
        'HV-09': { // Windows Admin
            'Users': {
                'Admin': {
                    'Documents': {
                        'passwords.txt': 'root:toor\nadmin:Hunter2!',
                        'financials.xlsx': '[ENCRYPTED DATA]',
                        'project_chimera.pdf': 'CONFIDENTIAL BLUEPRINTS'
                    },
                    'Downloads': { 'mimikatz.exe': '[BINARY]' },
                    'Desktop': { 'creds.dump': 'DOMAIN\\Admin:5e884898da28047151d0e56f8dc62927' }
                }
            },
            'Windows': { 'System32': { 'cmd.exe': '[BIN]', 'calc.exe': '[BIN]' } }
        },
        'XR-77': { // Linux Server
            'home': {
                'user': {
                    '.ssh': { 'id_rsa': '-----BEGIN RSA PRIVATE KEY-----' },
                    'flag.txt': 'C2{R3D_T34M_0PS_M4ST3R}'
                }
            },
            'etc': { 'shadow': 'root:$6$...' },
            'var': { 'www': { 'html': { 'index.php': '<?php echo "Hello"; ?>' } } }
        },
        'OM-22': { // Dormant Server
            'C:': { 'Backup': { 'database.sql': 'INSERT INTO users...' } }
        }
    };

    const C2CommandCenter = () => {
        const { toast } = useToast();

        // STATE
        const [beacons, setBeacons] = useState([
            { id: 'HV-09', ip: '45.33.22.11', os: 'Windows 10', status: 'active', user: 'Admin', tier: 'high', x: 20, y: 30 },
            { id: 'XR-77', ip: '102.99.1.5', os: 'Ubuntu 20.04', status: 'active', user: 'root', tier: 'critical', x: 70, y: 60 },
            { id: 'OM-22', ip: '198.51.100.2', os: 'Server 2019', status: 'dormant', user: 'SYSTEM', tier: 'low', x: 80, y: 20 },
        ]);
        const [selectedAgentId, setSelectedAgentId] = useState(null);
        const [terminalHistory, setTerminalHistory] = useState([]);
        const [cwd, setCwd] = useState([]); // Array of dir names
        const [noiseLevel, setNoiseLevel] = useState(0);
        const [loot, setLoot] = useState([]);
        const terminalEndRef = useRef(null);
        const inputRef = useRef(null);

        // KERNEL LOOP (Noise Decay)
        useEffect(() => {
            const interval = setInterval(() => {
                setNoiseLevel(prev => Math.max(0, prev - 0.5));
            }, 1000);
            return () => clearInterval(interval);
        }, []);

        // --- REAL-TIME C2 INTEGRATION ---
        const realSessions = useCyberRangeEvents(RANGE_EVENTS.C2_BEACON);
        const capturedCreds = useCyberRangeEvents(RANGE_EVENTS.CREDENTIAL_CAPTURED);

        useEffect(() => {
            if (capturedCreds.length > 0) {
                const latest = capturedCreds[0]; // Get the newest event (since hook implementation prepends)
                // Check if we already processed this timestamp to avoid dupes? 
                // Actually, the hook returns a new array reference on change.
                // But if I just take [0] every render, I might re-process.
                // The hook updates only when new event comes.
                // But I should be careful.
                // Let's rely on the fact that useEffect runs when `capturedCreds` changes.
                // But `capturedCreds` is an array.
                // If I add to `loot`, I should check if it's already there?
                // Loot doesn't have IDs.
                // Let's rely on toast for feedback and just append.
                const credItem = {
                    name: `Creds: ${latest.payload.username}`,
                    agent: latest.payload.source || 'Phishing',
                    content: `User: ${latest.payload.username}\nPass: ${latest.payload.password}\nUrl: ${latest.payload.domain}`
                };
                setLoot(prev => [credItem, ...prev]);
                toast('CREDENTIALS CAPTURED FROM CYBER RANGE', 'success');
            }
        }, [capturedCreds]);

        useEffect(() => {
            if (realSessions.length > 0) {
                const newBeacons = realSessions.map(evt => ({
                    id: evt.payload.id,
                    ip: evt.payload.ip,
                    os: evt.payload.os,
                    status: 'active',
                    user: evt.payload.user,
                    tier: 'critical', // Real sessions are always critical
                    x: Math.floor(Math.random() * 80) + 10,
                    y: Math.floor(Math.random() * 80) + 10
                }));

                // Merge unique beacons
                setBeacons(prev => {
                    const combined = [...prev, ...newBeacons];
                    // Remove duplicates by ID
                    return Array.from(new Map(combined.map(item => [item.id, item])).values());
                });

                // Add to Mock FS so it's explorable
                newBeacons.forEach(b => {
                    if (!MOCK_FS[b.id]) {
                        MOCK_FS[b.id] = {
                            'home': { 'user': { 'flag.txt': 'REAL_SESSION_CAPTURED' } },
                            'captured_data': { 'creds.txt': `User: ${b.user}` }
                        };
                    }
                });
            }
        }, [realSessions]);
        // ----------------------------

        // AUTO SCROLL
        useEffect(() => {
            terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }, [terminalHistory]);

        // --- LOGIC: FS ---
        const resolvePath = (agentId, pathArr) => {
            if (!MOCK_FS[agentId]) return null;
            let current = MOCK_FS[agentId];
            for (const dir of pathArr) {
                if (current[dir]) current = current[dir];
                else return null;
            }
            return current;
        };

        const handleCommand = (cmd) => {
            if (!cmd.trim()) return;

            const args = cmd.trim().split(' ');
            const op = args[0].toLowerCase();
            const param = args[1];

            // LOG INPUT
            setTerminalHistory(prev => [...prev, { type: 'in', text: cmd, prompt: `${selectedAgentId || 'local'}# ` }]);

            if (!selectedAgentId && op !== 'help' && op !== 'list' && op !== 'use' && op !== 'clear') {
                logError('NO AGENT SELECTED. Use "list" then "use [ID]".');
                return;
            }

            const agent = beacons.find(b => b.id === selectedAgentId);
            if (selectedAgentId && agent.status === 'burned') {
                logError('AGENT IS BURNED. CONNECTION SEVERED.');
                return;
            }

            // COMMAND SWITCH
            switch (op) {
                case 'help':
                    logOut('AVAILABLE COMMANDS: list, use, ls, cd, cat, download, listener, ps, mimikatz, clear');
                    break;
                case 'clear':
                    setTerminalHistory([]);
                    break;
                case 'listener':
                    // Real Netcat Listener
                    if (socket) {
                        const port = param || '4444';
                        logSys(`STARTING LISTENER ON PORT ${port}...`);
                        socket.emit('execute_tool', { cmd: `nc -lvnp ${port}` });
                    }
                    break;
                case 'list':
                    logOut('ACTIVE BEACONS:\n' + beacons.map(b => `${b.id} [${b.ip}] - ${b.status.toUpperCase()}`).join('\n'));
                    break;
                case 'use':
                    const target = beacons.find(b => b.id === param);
                    if (target) {
                        setSelectedAgentId(target.id);
                        setCwd(target.id === 'XR-77' ? ['home', 'user'] : ['Users', 'Admin', 'Documents']); // Reset CWD base
                        logSys(`ATTACHED TO ${target.id} (${target.ip}). SECURE CHANNEL ESTABLISHED.`);
                    } else {
                        logError('AGENT NOT FOUND');
                    }
                    break;
                case 'ls':
                    const dir = resolvePath(selectedAgentId, cwd);
                    if (dir && typeof dir === 'object') {
                        const files = Object.keys(dir).map(k => typeof dir[k] === 'object' ? `DIR  ${k}/` : `FILE ${k}`).join('\n');
                        logOut(files);
                    } else {
                        logError('INVALID DIRECTORY STATE');
                    }
                    break;
                case 'cd':
                    if (param === '..') {
                        setCwd(prev => prev.length > 0 ? prev.slice(0, -1) : []);
                        logOut('Changed directory up.');
                    } else if (resolvePath(selectedAgentId, [...cwd, param])) {
                        setCwd(prev => [...prev, param]);
                        logOut(`Changed directory to ${param}`);
                    } else {
                        logError('DIRECTORY NOT FOUND');
                    }
                    break;
                case 'cat':
                    const fileContent = resolvePath(selectedAgentId, cwd)?.[param];
                    if (typeof fileContent === 'string') {
                        logOut(fileContent);
                    } else {
                        logError('FILE NOT FOUND OR IS A DIRECTORY');
                    }
                    break;
                case 'download':
                    const fileToLoot = resolvePath(selectedAgentId, cwd)?.[param];
                    if (typeof fileToLoot === 'string') {
                        logSys(`DOWNLOADING ${param}... 100%`);
                        setLoot(prev => [...prev, { name: param, agent: selectedAgentId, content: fileToLoot }]);
                        toast(`Exfiltrated ${param}`, 'success');
                        addNoise(10);
                    } else {
                        logError('FILE NOT FOUND');
                    }
                    break;
                case 'mimikatz':
                    logWarn('EXECUTING MIMIKATZ MODULE... (HIGH NOISE)');
                    setTimeout(() => {
                        logOut('Dumping Logic... SUCCESS\nAdministrator: 5e884898da28047151d0e56f8dc62927');
                        addNoise(50);
                    }, 1000);
                    break;
                default:
                    logError('UNKNOWN COMMAND');
            }
        };

        const addNoise = (amount) => {
            setNoiseLevel(prev => {
                const newVal = prev + amount;
                if (newVal >= 100) {
                    // Burn Agent logic
                    setBeacons(bs => bs.map(b => b.id === selectedAgentId ? { ...b, status: 'burned' } : b));
                    logError('ALERT: AGENT DETECTED AND BURNED! DISCONNECTING...');
                    setSelectedAgentId(null);
                    return 100;
                }
                return newVal;
            });
        };

        const logOut = (text) => setTerminalHistory(prev => [...prev, { type: 'out', text }]);
        const logError = (text) => setTerminalHistory(prev => [...prev, { type: 'error', text }]);
        const logSys = (text) => setTerminalHistory(prev => [...prev, { type: 'sys', text }]);
        const logWarn = (text) => setTerminalHistory(prev => [...prev, { type: 'warn', text }]);

        // --- RENDER ---
        return (
            <div className="min-h-screen bg-black text-green-500 font-mono p-4 flex flex-col md:flex-row gap-4 overflow-hidden relative">

                {/* BACKGROUND SIM */}
                <div className="absolute inset-0 pointer-events-none z-0 opacity-20 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]"></div>

                {/* LEFT: GRID AND AGENTS */}
                <div className="w-full md:w-1/3 flex flex-col gap-4 z-10">
                    {/* HEAD */}
                    <div className="p-4 border border-green-900 bg-black/80">
                        <h1 className="text-2xl font-bold tracking-widest text-green-600 mb-1">C2 COMMAND CENTER</h1>
                        <div className="flex justify-between text-xs text-green-800">
                            <span>OP: RED_STORM</span>
                            <span>STATUS: ONLINE</span>
                        </div>
                    </div>

                    {/* VISUALIZER */}
                    <div className="h-64 border border-green-900 bg-black/90 relative overflow-hidden flex items-center justify-center">
                        <div className="absolute inset-0 grid grid-cols-12 grid-rows-12 gap-1 opacity-10">
                            {[...Array(144)].map((_, i) => <div key={i} className="border border-green-500/20"></div>)}
                        </div>
                        {/* Beacons on Map */}
                        {beacons.map(b => (
                            <motion.div
                                key={b.id}
                                initial={{ scale: 0 }}
                                animate={{ scale: 1, opacity: b.status === 'burned' ? 0.3 : 1 }}
                                className={`absolute w-3 h-3 rounded-full cursor-pointer ${b.status === 'active' ? 'bg-green-500 shadow-[0_0_10px_#0f0]' :
                                    b.status === 'dormant' ? 'bg-yellow-600' : 'bg-red-900'
                                    }`}
                                style={{ top: `${b.y}%`, left: `${b.x}%` }}
                                onClick={() => setSelectedAgentId(b.id)}
                            />
                        ))}
                        <Globe size={120} className="text-green-900/30 animate-pulse" />
                    </div>

                    {/* AGENT LIST */}
                    <div className="flex-1 border border-green-900 bg-black/80 flex flex-col">
                        <div className="p-2 border-b border-green-900 bg-green-900/10 text-xs font-bold">ACTIVE BEACONS</div>
                        <div className="flex-1 overflow-y-auto p-2 space-y-1">
                            {beacons.map(b => (
                                <div
                                    key={b.id}
                                    onClick={() => setSelectedAgentId(b.id)}
                                    className={`p-2 border border-transparent hover:border-green-500/50 cursor-pointer flex justify-between items-center group transition-colors ${selectedAgentId === b.id ? 'bg-green-900/20 border-green-500' : ''}`}
                                >
                                    <div className="flex items-center gap-3">
                                        <div className={`w-2 h-2 rounded-full ${b.status === 'active' ? 'bg-green-500' : b.status === 'burned' ? 'bg-red-500' : 'bg-yellow-600'}`} />
                                        <div>
                                            <div className="font-bold text-sm text-green-400 group-hover:text-green-300">{b.id}</div>
                                            <div className="text-[10px] text-green-800 font-bold">{b.ip}</div>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-[10px] text-green-600">{b.os}</div>
                                        <div className="text-[10px] text-green-800">{b.user}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* RIGHT: TERMINAL & TOOLS */}
                <div className="w-full md:w-2/3 flex flex-col gap-4 z-10">

                    {/* TERMINAL */}
                    <div className="flex-1 border border-green-900 bg-black/90 flex flex-col font-mono text-sm shadow-lg shadow-green-900/10">
                        <div className="p-2 border-b border-green-900 bg-black flex justify-between items-center">
                            <span className="flex items-center gap-2"><Terminal size={14} /> /bin/sh</span>
                            <span className="text-xs text-green-800">Use 'help' for commands</span>
                        </div>
                        <div className="flex-1 p-4 overflow-y-auto font-mono" style={{ fontFamily: '"Fira Code", monospace' }}>
                            {terminalHistory.map((line, i) => (
                                <div key={i} className={`mb-1 break-all ${line.type === 'error' ? 'text-red-500' :
                                    line.type === 'sys' ? 'text-blue-400' :
                                        line.type === 'warn' ? 'text-yellow-500' :
                                            'text-green-400'
                                    }`}>
                                    {line.prompt && <span className="text-green-700 select-none mr-2">{line.prompt}</span>}
                                    {line.text}
                                </div>
                            ))}
                            <div ref={terminalEndRef} />
                        </div>
                        <div className="p-2 border-t border-green-900 bg-black flex">
                            <span className="text-green-600 mr-2 select-none">{selectedAgentId ? `${selectedAgentId}` : 'local'}#</span>
                            <input
                                ref={inputRef}
                                type="text"
                                className="flex-1 bg-transparent border-none outline-none text-green-400 placeholder-green-900"
                                autoFocus
                                placeholder="..."
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        handleCommand(e.currentTarget.value);
                                        e.currentTarget.value = '';
                                    }
                                }}
                            />
                        </div>
                    </div>

                    {/* BOTTOM PANELS */}
                    <div className="h-40 flex gap-4">
                        {/* NOISE METER */}
                        <div className="w-1/3 border border-green-900 bg-black/80 flex flex-col p-2">
                            <div className="text-xs font-bold text-red-500 flex items-center gap-2 mb-2"><Activity size={14} /> NOISE LEVEL</div>
                            <div className="flex-1 flex flex-col justify-end gap-1 relative">
                                <div className="absolute bottom-0 w-full bg-red-900/20 h-full transition-all duration-300" style={{ height: `${noiseLevel}%` }} />
                                <div className="absolute bottom-0 w-full text-center text-4xl font-bold text-red-900 opacity-50 z-0">{Math.round(noiseLevel)}%</div>
                            </div>
                        </div>

                        {/* LOOT BOX */}
                        <div className="flex-1 border border-green-900 bg-black/80 flex flex-col p-2">
                            <div className="text-xs font-bold text-yellow-500 flex items-center gap-2 mb-2 border-b border-green-900 pb-2"><HardDrive size={14} /> EXFILTRATED LOOT</div>
                            <div className="flex-1 overflow-y-auto space-y-1">
                                {loot.length === 0 && <div className="text-green-900 italic text-xs mt-4 text-center">No data exfiltrated yet...</div>}
                                {loot.map((item, i) => (
                                    <div key={i} className="flex justify-between items-center text-xs p-1 hover:bg-green-900/20 border border-transparent hover:border-green-800">
                                        <span className="text-green-300 truncate max-w-[150px]">{item.name}</span>
                                        <span className="text-[10px] text-green-700">{item.agent}</span>
                                        <Download size={12} className="text-green-600 cursor-pointer hover:text-green-300" />
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        );
    };

    export default C2CommandCenter;
