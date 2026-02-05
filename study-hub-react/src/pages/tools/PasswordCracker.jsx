import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Unlock, Search, List, Terminal, Shield,
    CheckCircle, AlertTriangle, Fingerprint,
    Copy, Download, RefreshCw, Database,
    Flame, Zap, Hash, FileKey, Globe, Play, Square, Wifi
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- DATABASE & LOGIC ---

const HASH_TYPES = [
    { name: 'MD5', length: 32, pattern: /^[a-f0-9]{32}$/i, example: '5f4dcc3b5aa765d61d8327deb882cf99', hashcat: 0, john: 'raw-md5' },
    { name: 'SHA-1', length: 40, pattern: /^[a-f0-9]{40}$/i, example: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', hashcat: 100, john: 'raw-sha1' },
    { name: 'SHA-256', length: 64, pattern: /^[a-f0-9]{64}$/i, example: '5e884898da28047d9167e5b32cc0bcea9b8d79165c7c6c4c7e4adef5e2a2bdcc', hashcat: 1400, john: 'raw-sha256' },
    { name: 'SHA-512', length: 128, pattern: /^[a-f0-9]{128}$/i, example: 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86', hashcat: 1700, john: 'raw-sha512' },
    { name: 'NTLM', length: 32, pattern: /^[a-f0-9]{32}$/i, example: 'a4f49c406510bdcab6824ee7c30fd852', hashcat: 1000, john: 'nt' },
    { name: 'bcrypt', length: 60, pattern: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, example: '$2b$12$EixZaYVK1fsbw1ZfbX3OXe.lFz7EIJLZnNJO4jqD9FKe3N6VZ3GKy', hashcat: 3200, john: 'bcrypt' },
    { name: 'MySQL5', length: 40, pattern: /^\*[A-F0-9]{40}$/i, example: '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19', hashcat: 300, john: 'mysql-sha1' },
    { name: 'SHA-512 (Unix)', length: 86, pattern: /^\$6\$/, example: '$6$rounds=5000$salt$hash', hashcat: 1800, john: 'sha512crypt' },
    { name: 'MD5 (Unix)', length: 34, pattern: /^\$1\$/, example: '$1$salt$hash', hashcat: 500, john: 'md5crypt' },
    { name: 'LM', length: 32, pattern: /^[a-f0-9]{32}$/i, example: 'aad3b435b51404eeaad3b435b51404ee', hashcat: 3000, john: 'lm' }
];

const CHALLENGES = [
    { id: 'md5-easy', name: 'MD5 Basics', difficulty: 'Easy', hash: '5f4dcc3b5aa765d61d8327deb882cf99', answer: 'password', points: 50 },
    { id: 'md5-med', name: 'Common Password', difficulty: 'Easy', hash: 'e10adc3949ba59abbe56e057f20f883e', answer: '123456', points: 50 },
    { id: 'sha1-1', name: 'SHA-1 Challenge', difficulty: 'Medium', hash: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', answer: 'password', points: 100 },
    { id: 'sha256-1', name: 'SHA-256 Cracker', difficulty: 'Medium', hash: '5e884898da28047d9167e5b32cc0bcea9b8d79165c7c6c4c7e4adef5e2a2bdcc', answer: 'password', points: 100 },
    { id: 'ntlm-1', name: 'Windows NTLM', difficulty: 'Hard', hash: 'a4f49c406510bdcab6824ee7c30fd852', answer: 'password', points: 200 }
];

const ROCKYOU_TOP_25 = [
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567',
    'dragon', '123123', 'baseball', 'iloveyou', 'trustno1', 'sunshine', 'master', 'welcome',
    'shadow', 'ashley', 'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1'
];

const PasswordCracker = () => {
    const [activeTab, setActiveTab] = useState('identifier');
    const { toast } = useToast();

    // --- STATE: Identifier ---
    const [hashInput, setHashInput] = useState('');
    const [identifiedHash, setIdentifiedHash] = useState(null);

    // --- STATE: Wordlist ---
    const [baseWords, setBaseWords] = useState('company\nname\nyear\nadmin');
    const [genOptions, setGenOptions] = useState({
        numbers: true,
        symbols: true,
        case: true,
        leet: false
    });
    const [generatedWordlist, setGeneratedWordlist] = useState('');

    // --- STATE: Challenges ---
    const [solvedChallenges, setSolvedChallenges] = useState([]);
    const [challengeInputs, setChallengeInputs] = useState({});

    // --- STATE: Online Attack (Hydra) ---
    const [hydraTarget, setHydraTarget] = useState('192.168.1.100');
    const [hydraService, setHydraService] = useState('ssh');
    const [hydraUser, setHydraUser] = useState('admin');
    const [hydraRunning, setHydraRunning] = useState(false);
    const [hydraLogs, setHydraLogs] = useState([]);
    const [hydraProgress, setHydraProgress] = useState(0);

    // --- INIT ---
    useEffect(() => {
        const saved = localStorage.getItem('password_solved');
        if (saved) setSolvedChallenges(JSON.parse(saved));
    }, []);

    // --- HANDLERS: Identifier ---
    const identifyHash = () => {
        if (!hashInput.trim()) {
            setIdentifiedHash(null);
            return;
        }

        const input = hashInput.trim();
        const matches = HASH_TYPES.filter(h => {
            if (h.pattern.test(input)) return true;
            if (input.length === h.length) return true;
            return false;
        });

        if (matches.length > 0) {
            setIdentifiedHash(matches);
            toast('Hash identified successfully', 'success');
        } else {
            setIdentifiedHash([{ name: 'Unknown / Custom Custom', length: input.length, hashcat: '?', john: '?' }]);
            toast('Unknown hash format', 'warning');
        }
    };

    // --- HANDLERS: Wordlist ---
    const generateWordlist = () => {
        const words = baseWords.split('\n').filter(w => w.trim());
        let result = [...words];

        if (genOptions.case) {
            const cased = [];
            words.forEach(w => {
                cased.push(w.toLowerCase());
                cased.push(w.toUpperCase());
                cased.push(w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
            });
            result = [...new Set([...result, ...cased])];
        }

        if (genOptions.leet) {
            const leet = result.map(w => w.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5'));
            result = [...new Set([...result, ...leet])];
        }

        if (genOptions.numbers) {
            const numbered = [];
            result.forEach(w => {
                for (let i = 0; i <= 9; i++) numbered.push(`${w}${i}`);
                numbered.push(`${w}123`);
                numbered.push(`${w}2024`);
                numbered.push(`${w}2025`);
                numbered.push(`${w}!`);
            });
            result = [...result, ...numbered];
        }

        if (genOptions.symbols) {
            const symbols = ['!', '@', '#', '$'];
            const symboled = [];
            result.forEach(w => symbols.forEach(s => symboled.push(`${w}${s}`)));
            result = [...result, ...symboled];
        }

        setGeneratedWordlist(result.join('\n'));
        toast(`Generated ${result.length} words`, 'success');
    };

    const downloadWordlist = () => {
        if (!generatedWordlist) return;
        const blob = new Blob([generatedWordlist], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'custom_wordlist.txt';
        a.click();
        URL.revokeObjectURL(url);
        toast('Wordlist downloaded', 'success');
    };

    // --- HANDLERS: Challenges ---
    const checkAnswer = (id) => {
        const challenge = CHALLENGES.find(c => c.id === id);
        const input = challengeInputs[id]?.trim();

        if (input && input.toLowerCase() === challenge.answer.toLowerCase()) {
            if (!solvedChallenges.includes(id)) {
                const newSolved = [...solvedChallenges, id];
                setSolvedChallenges(newSolved);
                localStorage.setItem('password_solved', JSON.stringify(newSolved));
                toast(`Cracked! +${challenge.points} pts`, 'success');
            }
        } else {
            toast('Incorrect password', 'error');
        }
    };

    // --- HANDLERS: Hydra ---
    const runHydra = async () => {
        if (hydraRunning) return;
        setHydraRunning(true);
        setHydraLogs([]);
        setHydraProgress(0);

        const passwords = ['123456', 'password', 'admin', 'root', 'toor', 'welcome', 'login', 'service', 'access', 'secret'];
        const targetPass = passwords[Math.floor(Math.random() * passwords.length)];

        let i = 0;
        const interval = setInterval(() => {
            if (i >= passwords.length) {
                clearInterval(interval);
                setHydraRunning(false);
                setHydraLogs(prev => [...prev, `[DATA] Attack finished. No valid credentials found.`]);
                return;
            }

            const attempt = passwords[i];
            const success = attempt === targetPass;

            setHydraLogs(prev => {
                const newLogs = [...prev, `[${hydraService.toUpperCase()}] Attempting ${hydraUser}:${attempt}... ${success ? 'SUCCESS' : 'FAILED'}`];
                if (newLogs.length > 8) newLogs.shift();
                return newLogs;
            });
            setHydraProgress(Math.round(((i + 1) / passwords.length) * 100));

            if (success) {
                clearInterval(interval);
                setStatus('cracked'); // Using local var for immediate effect logic if needed, but here just state
                setHydraRunning(false);
                toast(`CRACKED: ${hydraUser}:${attempt}`, 'success');
                setHydraLogs(prev => [...prev, `[SUCCESS] Valid credentials found: ${hydraUser}:${attempt}`]);
            }
            i++;
        }, 500);
    };

    const stopHydra = () => {
        // In a real app we'd clear interval ID reference, simplified here
        setHydraRunning(false);
        setHydraLogs(prev => [...prev, `[STOP] Attack aborted by user.`]);
    };

    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">
            {/* HERDER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
                <div className="space-y-2">
                    <h1 className="text-4xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500">
                        PASSWORD ANALYST PRO
                    </h1>
                    <p className="text-white/40 font-mono tracking-widest uppercase text-sm">
                        Advanced Hash Identification & Wordlist Engine
                    </p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 font-mono text-xs">
                        <span className="font-bold text-lg">{solvedChallenges.length}/{CHALLENGES.length}</span> CHALLENGES
                    </div>
                </div>
            </div>

            {/* NAVIGATION */}
            <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
                {[
                    { id: 'identifier', label: 'Hash Identifier', icon: Fingerprint },
                    { id: 'wordlist', label: 'Wordlist Generator', icon: List },
                    { id: 'hydra', label: 'Online Attack', icon: Globe },
                    { id: 'commands', label: 'Command Builder', icon: Terminal },
                    { id: 'challenges', label: 'Training Lab', icon: Zap }
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-6 py-3 rounded-xl font-bold uppercase tracking-wider text-sm transition-all whitespace-nowrap ${activeTab === tab.id
                            ? 'bg-red-500 text-white shadow-lg shadow-red-500/20'
                            : 'bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white'
                            }`}
                    >
                        <tab.icon size={16} />
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* CONTENT AREA */}
            <div className="min-h-[500px]">
                <AnimatePresence mode="wait">

                    {/* TAB: IDENTIFIER */}
                    {activeTab === 'identifier' && (
                        <motion.div
                            key="identifier"
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                        >
                            <div className="space-y-6">
                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                    <h3 className="text-xl font-bold flex items-center gap-2 text-red-400">
                                        <Search size={20} /> Hash Analyzer
                                    </h3>
                                    <textarea
                                        value={hashInput}
                                        onChange={(e) => setHashInput(e.target.value)}
                                        placeholder="Paste your hash here (e.g. 5f4dcc3b5aa765d61d8327deb882cf99)..."
                                        className="w-full h-32 bg-dark-900 border border-white/10 rounded-xl p-4 font-mono text-sm text-green-400 focus:outline-none focus:border-red-500/50 transition-colors resize-none"
                                    />
                                    <button
                                        onClick={identifyHash}
                                        className="w-full py-3 rounded-xl bg-gradient-to-r from-red-600 to-orange-600 font-bold uppercase tracking-widest hover:brightness-110 transition-all shadow-lg shadow-red-600/20"
                                    >
                                        Identify Hash
                                    </button>
                                </div>

                                {identifiedHash && (
                                    <div className="space-y-4 animate-slide-up">
                                        {identifiedHash.map((match, idx) => (
                                            <div key={idx} className="p-6 rounded-2xl bg-green-500/10 border border-green-500/20 relative overflow-hidden group">
                                                <div className="absolute top-0 right-0 p-4 opacity-20 group-hover:opacity-40 transition-opacity">
                                                    <CheckCircle size={64} className="text-green-500" />
                                                </div>
                                                <h4 className="text-2xl font-black text-green-400 mb-4">{match.name}</h4>
                                                <div className="grid grid-cols-2 gap-4 text-sm">
                                                    <div className="p-3 rounded-lg bg-black/20 border border-white/5">
                                                        <span className="block text-white/40 text-[10px] uppercase font-bold mb-1">Length</span>
                                                        <span className="font-mono text-white">{match.length} chars</span>
                                                    </div>
                                                    <div className="p-3 rounded-lg bg-black/20 border border-white/5">
                                                        <span className="block text-white/40 text-[10px] uppercase font-bold mb-1">Hashcat Mode</span>
                                                        <span className="font-mono text-yellow-400">-m {match.hashcat}</span>
                                                    </div>
                                                    <div className="p-3 rounded-lg bg-black/20 border border-white/5 col-span-2">
                                                        <span className="block text-white/40 text-[10px] uppercase font-bold mb-1">John the Ripper Format</span>
                                                        <span className="font-mono text-blue-400">--format={match.john}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div className="p-6 rounded-2xl bg-white/5 border border-white/10 h-fit">
                                <h3 className="text-xl font-bold flex items-center gap-2 text-white mb-6">
                                    <Database size={20} /> Hash Database
                                </h3>
                                <div className="space-y-2">
                                    {HASH_TYPES.slice(0, 8).map((h, i) => (
                                        <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors border border-transparent hover:border-white/10 cursor-help group">
                                            <div>
                                                <div className="font-bold text-sm text-gray-200 group-hover:text-red-400 transition-colors">{h.name}</div>
                                                <div className="text-[10px] font-mono text-white/40">{h.length} chars</div>
                                            </div>
                                            <div className="font-mono text-[10px] text-yellow-500/60 group-hover:text-yellow-500">
                                                -m {h.hashcat}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* TAB: WORDLIST */}
                    {activeTab === 'wordlist' && (
                        <motion.div
                            key="wordlist"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="grid grid-cols-1 lg:grid-cols-3 gap-8"
                        >
                            <div className="lg:col-span-1 space-y-6">
                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-6">
                                    <div className="space-y-2">
                                        <label className="text-sm font-bold text-gray-400 uppercase tracking-wide">Base Words</label>
                                        <textarea
                                            value={baseWords}
                                            onChange={(e) => setBaseWords(e.target.value)}
                                            className="w-full h-32 bg-dark-900 border border-white/10 rounded-xl p-4 font-mono text-sm focus:outline-none focus:border-red-500/50 resize-none"
                                            placeholder="Enter seed words..."
                                        />
                                    </div>

                                    <div className="space-y-3">
                                        <p className="text-sm font-bold text-gray-400 uppercase tracking-wide">Permutations</p>
                                        {[
                                            { id: 'numbers', label: 'Add Numbers (0-99, Years)', icon: Hash },
                                            { id: 'symbols', label: 'Add Symbols (!@#$)', icon: Flame },
                                            { id: 'case', label: 'Case Variants (Aa, aA)', icon: RefreshCw },
                                            { id: 'leet', label: 'Leet Speak (h4ck3r)', icon: Terminal },
                                        ].map(opt => (
                                            <button
                                                key={opt.id}
                                                onClick={() => setGenOptions({ ...genOptions, [opt.id]: !genOptions[opt.id] })}
                                                className={`flex items-center gap-3 w-full p-3 rounded-xl border transition-all ${genOptions[opt.id]
                                                    ? 'bg-red-500/10 border-red-500/50 text-red-400'
                                                    : 'bg-white/5 border-transparent text-gray-500 hover:bg-white/10'
                                                    }`}
                                            >
                                                <opt.icon size={16} />
                                                <span className="text-sm font-bold">{opt.label}</span>
                                                {genOptions[opt.id] && <CheckCircle size={14} className="ml-auto" />}
                                            </button>
                                        ))}
                                    </div>

                                    <button
                                        onClick={generateWordlist}
                                        className="w-full py-3 rounded-xl bg-white text-dark-900 font-black uppercase tracking-widest hover:scale-[1.02] transition-transform"
                                    >
                                        Generate List
                                    </button>
                                </div>
                            </div>

                            <div className="lg:col-span-2 space-y-6">
                                <div className="p-6 rounded-2xl bg-dark-800 border border-white/10 h-full flex flex-col">
                                    <div className="flex justify-between items-center mb-4">
                                        <h3 className="text-lg font-bold text-gray-200">Generated Output</h3>
                                        <div className="flex gap-2">
                                            <button onClick={() => { navigator.clipboard.writeText(generatedWordlist); toast('Copied!', 'success') }} className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors">
                                                <Copy size={18} />
                                            </button>
                                            <button onClick={downloadWordlist} className="p-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-400 transition-colors">
                                                <Download size={18} />
                                            </button>
                                        </div>
                                    </div>
                                    <textarea
                                        readOnly
                                        value={generatedWordlist}
                                        className="w-full flex-1 min-h-[400px] bg-black/30 border border-white/5 rounded-xl p-4 font-mono text-sm text-green-400/80 resize-none focus:outline-none"
                                        placeholder="Output will appear here..."
                                    />
                                    <div className="mt-4 text-right text-xs font-mono text-gray-500">
                                        Total Lines: {generatedWordlist ? generatedWordlist.split('\n').length : 0}
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* TAB: HYDRA (ONLINE ATTACK) */}
                    {activeTab === 'hydra' && (
                        <motion.div
                            key="hydra"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                        >
                            <div className="space-y-6">
                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-6">
                                    <h3 className="text-xl font-bold text-red-400 flex items-center gap-2">
                                        <Globe size={20} /> Network Brute Force
                                    </h3>

                                    <div className="space-y-4">
                                        <div className="space-y-2">
                                            <label className="text-xs uppercase text-gray-500 font-bold tracking-widest">Target IP</label>
                                            <input
                                                type="text"
                                                value={hydraTarget}
                                                onChange={e => setHydraTarget(e.target.value)}
                                                className="w-full bg-dark-900 border border-white/10 p-3 rounded-xl font-mono text-sm focus:border-red-500/50 outline-none"
                                            />
                                        </div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="space-y-2">
                                                <label className="text-xs uppercase text-gray-500 font-bold tracking-widest">Service</label>
                                                <select
                                                    value={hydraService}
                                                    onChange={e => setHydraService(e.target.value)}
                                                    className="w-full bg-dark-900 border border-white/10 p-3 rounded-xl font-mono text-sm focus:border-red-500/50 outline-none"
                                                >
                                                    <option value="ssh">SSH (22)</option>
                                                    <option value="ftp">FTP (21)</option>
                                                    <option value="http-post-form">HTTP POST</option>
                                                    <option value="rdp">RDP (3389)</option>
                                                </select>
                                            </div>
                                            <div className="space-y-2">
                                                <label className="text-xs uppercase text-gray-500 font-bold tracking-widest">Username</label>
                                                <input
                                                    type="text"
                                                    value={hydraUser}
                                                    onChange={e => setHydraUser(e.target.value)}
                                                    className="w-full bg-dark-900 border border-white/10 p-3 rounded-xl font-mono text-sm focus:border-red-500/50 outline-none"
                                                />
                                            </div>
                                        </div>

                                        <div className="p-4 bg-black/20 rounded-xl border border-white/5">
                                            <div className="flex justify-between text-xs text-gray-500 uppercase font-bold mb-2">
                                                <span>Wordlist</span>
                                                <span className="text-green-500">rockyou.txt (Top 1000)</span>
                                            </div>
                                            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                                                <div className="h-full bg-red-500 transition-all duration-300" style={{ width: `${hydraProgress}%` }} />
                                            </div>
                                        </div>

                                        <div className="flex gap-4">
                                            {!hydraRunning ? (
                                                <button
                                                    onClick={runHydra}
                                                    className="flex-1 py-3 bg-red-600 hover:bg-red-500 text-white rounded-xl font-bold uppercase tracking-widest transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Play size={18} /> Attack
                                                </button>
                                            ) : (
                                                <button
                                                    onClick={stopHydra}
                                                    className="flex-1 py-3 bg-white/10 hover:bg-white/20 text-white rounded-xl font-bold uppercase tracking-widest transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Square size={18} /> Stop
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-6">
                                <div className="h-full max-h-[400px] p-6 rounded-2xl bg-black border border-white/10 font-mono text-sm overflow-y-auto">
                                    <div className="text-gray-500 mb-2 border-b border-white/10 pb-2 flex justify-between">
                                        <span>ATTACK CONSOLE</span>
                                        {hydraRunning && <span className="text-red-500 animate-pulse">● LIVE</span>}
                                    </div>
                                    <div className="space-y-1">
                                        {hydraLogs.length === 0 && <span className="text-gray-700 italic">Ready to start session...</span>}
                                        {hydraLogs.map((log, i) => (
                                            <div key={i} className={`${log.includes('SUCCESS') ? 'text-green-400 font-bold' : log.includes('FAILED') ? 'text-red-400/60' : 'text-gray-400'}`}>
                                                {log}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* TAB: COMMANDS (Refactored for React) */}
                    {activeTab === 'commands' && ( // Added missing component
                        <motion.div
                            key="commands"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="space-y-8"
                        >
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                                    <h3 className="text-xl font-bold text-red-500 mb-6 flex items-center gap-2">
                                        <Flame size={24} /> Hashcat Cheatsheet
                                    </h3>
                                    <div className="space-y-4">
                                        {[
                                            { name: 'Dictionary Attack', cmd: 'hashcat -m 0 hash.txt wordlist.txt' },
                                            { name: 'Brute Force (Classic)', cmd: 'hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a?a?a' },
                                            { name: 'Rule-based Attack', cmd: 'hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule' },
                                            { name: 'Mask Attack (Known Prefix)', cmd: 'hashcat -a 3 -m 0 hash.txt Password?d?d?d' }
                                        ].map((item, i) => (
                                            <div key={i} className="group cursor-pointer" onClick={() => { navigator.clipboard.writeText(item.cmd); toast('Command copied', 'success') }}>
                                                <div className="text-xs font-bold text-gray-400 mb-1">{item.name}</div>
                                                <div className="p-3 rounded-lg bg-black/40 border border-white/5 font-mono text-sm text-yellow-500 group-hover:border-yellow-500/50 transition-colors">
                                                    {item.cmd}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                                    <h3 className="text-xl font-bold text-blue-500 mb-6 flex items-center gap-2">
                                        <FileKey size={24} /> John the Ripper
                                    </h3>
                                    <div className="space-y-4">
                                        {[
                                            { name: 'Auto Detect & Crack', cmd: 'john hash.txt' },
                                            { name: 'Wordlist Attack', cmd: 'john --wordlist=rockyou.txt hash.txt' },
                                            { name: 'Specific Format', cmd: 'john --format=raw-md5 hash.txt' },
                                            { name: 'Show Cracked Passwords', cmd: 'john --show hash.txt' }
                                        ].map((item, i) => (
                                            <div key={i} className="group cursor-pointer" onClick={() => { navigator.clipboard.writeText(item.cmd); toast('Command copied', 'success') }}>
                                                <div className="text-xs font-bold text-gray-400 mb-1">{item.name}</div>
                                                <div className="p-3 rounded-lg bg-black/40 border border-white/5 font-mono text-sm text-cyan-400 group-hover:border-cyan-400/50 transition-colors">
                                                    {item.cmd}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* TAB: CHALLENGES */}
                    {activeTab === 'challenges' && (
                        <motion.div
                            key="challenges"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                        >
                            {CHALLENGES.map(c => {
                                const isSolved = solvedChallenges.includes(c.id);
                                return (
                                    <div key={c.id} className={`p-6 rounded-2xl border transition-all ${isSolved ? 'bg-green-500/5 border-green-500/30' : 'bg-white/5 border-white/10'}`}>
                                        <div className="flex justify-between items-start mb-4">
                                            <div>
                                                <h4 className={`font-bold text-lg ${isSolved ? 'text-green-400' : 'text-white'}`}>{c.name}</h4>
                                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${c.difficulty === 'Easy' ? 'bg-green-500/20 text-green-400' :
                                                    c.difficulty === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                        'bg-red-500/20 text-red-400'
                                                    }`}>{c.difficulty}</span>
                                            </div>
                                            <div className="text-xs font-bold text-yellow-500">{c.points} PTS</div>
                                        </div>

                                        <div className="mb-6 p-3 rounded-lg bg-black/30 border border-white/5 relative group">
                                            <div className="font-mono text-xs text-gray-400 break-all">{c.hash}</div>
                                            <button
                                                onClick={() => { navigator.clipboard.writeText(c.hash); toast('Hash copied', 'success') }}
                                                className="absolute top-2 right-2 p-1 rounded hover:bg-white/10 text-gray-500 hover:text-white"
                                            >
                                                <Copy size={12} />
                                            </button>
                                        </div>

                                        {isSolved ? (
                                            <div className="p-3 rounded-xl bg-green-500/20 border border-green-500/30 flex items-center gap-3 text-green-400 font-bold justify-center">
                                                <Unlock size={18} /> CRACKED: {c.answer}
                                            </div>
                                        ) : (
                                            <div className="flex gap-2">
                                                <input
                                                    type="text"
                                                    placeholder="Enter password..."
                                                    value={challengeInputs[c.id] || ''}
                                                    onChange={(e) => setChallengeInputs({ ...challengeInputs, [c.id]: e.target.value })}
                                                    className="flex-1 bg-black/20 border border-white/10 rounded-lg px-3 py-2 text-sm focus:border-red-500/50 outline-none"
                                                />
                                                <button
                                                    onClick={() => checkAnswer(c.id)}
                                                    className="p-2 rounded-lg bg-red-500 hover:bg-red-600 text-white transition-colors"
                                                >
                                                    <Unlock size={18} />
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default PasswordCracker;
