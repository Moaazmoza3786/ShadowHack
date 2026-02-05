import React, { useState, useEffect } from 'react';
import { Search, Globe, ChevronLeft, ChevronRight, RotateCcw, Terminal as TerminalIcon, ShieldAlert, CheckCircle, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export const WebSimulator = ({ config }) => {
    const [url, setUrl] = useState(config.target || 'http://localhost:8080');
    const [view, setView] = useState('home'); // home, login, robots, secrets
    const [formData, setFormData] = useState({ user: '', pass: '' });
    const [message, setMessage] = useState('');
    const [history, setHistory] = useState([url]);
    const [isLoading, setIsLoading] = useState(false);

    const navigate = (newUrl) => {
        setIsLoading(true);
        setTimeout(() => {
            setIsLoading(false);
            setHistory([...history, newUrl]);
            setUrl(newUrl);
            if (newUrl.includes('/robots.txt')) setView('robots');
            else if (newUrl.includes('/login')) setView('login');
            else if (newUrl.includes('/flag.txt')) setView('secrets');
            else setView('home');
        }, 800);
    };

    const handleLogin = (e) => {
        e.preventDefault();
        // SQLi Logic
        if (formData.user.includes("' OR 1=1") || formData.user.includes("' OR '1'='1")) {
            setMessage({ type: 'success', text: 'AUTHENTICATION BYPASSED! Accessing Admin Dashboard...' });
            setTimeout(() => {
                setView('secrets');
                setUrl('http://admin-portal.local/dashboard');
            }, 1500);
        } else {
            setMessage({ type: 'error', text: 'Invalid credentials. Intrusion detection active.' });
        }
    };

    return (
        <div className="flex flex-col h-full bg-slate-50 text-gray-800 rounded-3xl overflow-hidden shadow-2xl font-sans">
            {/* Browser Controls */}
            <div className="flex flex-col bg-gray-100 border-b border-gray-200">
                <div className="flex items-center gap-4 px-6 py-4">
                    <div className="flex gap-2">
                        <button onClick={() => navigate(history[history.length - 2] || url)} className="p-2 hover:bg-gray-200 rounded-lg"><ChevronLeft size={16} /></button>
                        <button className="p-2 hover:bg-gray-200 rounded-lg"><ChevronRight size={16} /></button>
                        <button onClick={() => navigate(url)} className="p-2 hover:bg-gray-200 rounded-lg"><RotateCcw size={16} /></button>
                    </div>
                    <div className="flex-1 flex items-center gap-3 px-4 py-2 bg-white rounded-xl border border-gray-300 shadow-sm focus-within:ring-2 ring-blue-500/20 transition-all">
                        <Globe size={14} className="text-blue-500" />
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && navigate(url)}
                            className="flex-1 text-xs font-semibold focus:outline-none"
                        />
                    </div>
                </div>
                {isLoading && (
                    <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: '100%' }}
                        transition={{ duration: 0.8 }}
                        className="h-1 bg-blue-500"
                    />
                )}
            </div>

            {/* Viewport content based on view state */}
            <div className="flex-1 p-12 overflow-auto bg-white relative">
                {isLoading && (
                    <div className="absolute inset-0 bg-white/50 backdrop-blur-[2px] z-10 flex items-center justify-center">
                        <Activity className="animate-pulse text-blue-500" size={32} />
                    </div>
                )}
                {view === 'login' && (
                    <div className="max-w-md mx-auto space-y-8 py-10">
                        <div className="text-center space-y-2">
                            <ShieldAlert className="mx-auto text-blue-600" size={48} />
                            <h2 className="text-2xl font-bold text-gray-900 tracking-tight">Enterprise Authentication</h2>
                            <p className="text-sm text-gray-500 italic">SECURE_GATEWAY_v4.2</p>
                        </div>

                        <form onSubmit={handleLogin} className="space-y-4">
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-gray-400">Username / ID</label>
                                <input
                                    type="text"
                                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-sm focus:ring-2 ring-blue-500/20 outline-none"
                                    placeholder="operative_id"
                                    value={formData.user}
                                    onChange={(e) => setFormData({ ...formData, user: e.target.value })}
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-black uppercase text-gray-400">Secure Token</label>
                                <input
                                    type="password"
                                    className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-sm focus:ring-2 ring-blue-500/20 outline-none"
                                    placeholder="••••••••"
                                    value={formData.pass}
                                    onChange={(e) => setFormData({ ...formData, pass: e.target.value })}
                                />
                            </div>
                            {message && (
                                <div className={`p-4 rounded-xl text-xs font-bold flex items-center gap-3 ${message.type === 'success' ? 'bg-green-50 text-green-600' : 'bg-red-50 text-red-600'}`}>
                                    {message.type === 'success' ? <CheckCircle size={16} /> : <ShieldAlert size={16} />}
                                    {message.text}
                                </div>
                            )}
                            <button className="w-full py-4 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-bold text-sm shadow-lg transition-transform active:scale-95">
                                ACCESS_PORTAL
                            </button>
                        </form>
                    </div>
                )}

                {view === 'home' && (
                    <div className="space-y-8 animate-in fade-in duration-700">
                        <div className="h-40 bg-gradient-to-r from-blue-600 to-indigo-700 rounded-3xl p-8 flex items-end">
                            <h1 className="text-3xl font-black text-white italic">TechCorp_Intranet</h1>
                        </div>
                        <div className="grid grid-cols-2 gap-6">
                            {[1, 2, 3, 4].map(i => (
                                <div key={i} className="p-6 rounded-2xl border border-gray-100 bg-gray-50/50 space-y-3">
                                    <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center text-blue-600">
                                        <Search size={20} />
                                    </div>
                                    <div className="h-2 w-2/3 bg-gray-200 rounded" />
                                    <div className="h-2 w-1/2 bg-gray-100 rounded" />
                                </div>
                            ))}
                        </div>
                        <div className="text-center py-10 border-t border-gray-100">
                            <p className="text-xs text-gray-400 font-medium">© 2024 TechCorp Security Systems. All assets logged.</p>
                        </div>
                    </div>
                )}

                {view === 'robots' && (
                    <div className="font-mono text-sm leading-relaxed p-6 bg-slate-100 rounded-2xl border border-slate-200 shadow-inner">
                        <p className="text-slate-400 mb-4"># TechCorp Automated Bot Policy</p>
                        <p>User-agent: *</p>
                        <p>Disallow: /admin-backup-2024/</p>
                        <p>Disallow: /flag.txt</p>
                        <p>Disallow: /api/v2/tokens/</p>
                        <p className="text-blue-600 mt-4 cursor-pointer hover:underline" onClick={() => navigate('http://techcorp.local/flag.txt')}># View Restricted Logic</p>
                    </div>
                )}

                {view === 'secrets' && (
                    <div className="h-full flex flex-col items-center justify-center text-center space-y-6">
                        <div className="w-24 h-24 rounded-full bg-green-100 flex items-center justify-center text-green-600 shadow-[0_0_40px_rgba(34,197,94,0.2)]">
                            <CheckCircle size={48} />
                        </div>
                        <div className="space-y-2">
                            <h2 className="text-3xl font-black text-gray-900 tracking-tight italic">DATA_BREACH_SUCCESS</h2>
                            <p className="text-gray-500 text-sm">Target intercepted. Flag extracted from core memory.</p>
                        </div>
                        <div className="px-10 py-5 rounded-2xl bg-slate-900 text-green-400 font-mono text-lg shadow-2xl border-2 border-green-500/20">
                            AG{'{'}SQL_Inj3ct10n_M4st3r{'}'}
                        </div>
                        <button onClick={() => setView('home')} className="text-blue-600 text-xs font-bold uppercase tracking-widest hover:underline">
                            Return to Gateway
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export const TerminalSimulator = ({ config }) => {
    const [history, setHistory] = useState([
        { text: 'STUDY_HUB v3.04.1 (Neural Protocol)', type: 'system' },
        { text: 'Starting secure shell instance...', type: 'system' },
        { text: `Target_Node: ${config.target || 'local-host'}`, type: 'system' },
        { text: 'READY. Type "help" for a list of tactical commands.', type: 'system' }
    ]);
    const [input, setInput] = useState('');
    const [files, setFiles] = useState(['packed.exe', 'README.md', 'secret_notes.txt']);

    useEffect(() => {
        if (config.initialFiles) {
            setFiles(config.initialFiles.map(f => f.name));
        }
    }, [config.initialFiles]);

    const handleCommand = (cmd) => {
        const fullCmd = cmd.trim();
        const args = fullCmd.split(' ');
        const baseCmd = args[0].toLowerCase();

        let response = '';
        let type = 'output';

        switch (baseCmd) {
            case 'help':
                response = 'AVAILABLE_COMMANDS: ls, cat, upx, strings, clear, whoami, help, docker-compose';
                break;
            case 'whoami':
                response = 'operative@studyhub-red-cell';
                break;
            case 'ls':
                response = files.join('   ');
                break;
            case 'clear':
                setHistory([{ text: 'Terminal cleared.', type: 'system' }]);
                setInput('');
                return;
            case 'cat':
                if (args[1] === 'README.md') response = 'MISSION: Locate the hidden flag inside the packed binary. Use advanced analysis tools.';
                else if (args[1] === 'secret_notes.txt') response = 'Note to self: The UPX packer header was slightly modified but -d should still work.';
                else if (args[1] === 'flag.txt') response = 'AG{b0f_m4st3r_2024}';
                else if (args[1] === 'docker-compose.yml') response = 'version: "3"\nservices:\n  vulnerable-app:\n    privileged: true\n    volumes: ["/:/host"]';
                else response = `cat: ${args[1] || ''}: No such file or directory`;
                break;
            case 'upx':
                if (args[1] === '-d' && args[2] === 'packed.exe') {
                    setFiles([...files, 'unpacked.exe']);
                    response = 'Unpacked 1 file: packed.exe (24.1 KB -> 58.2 KB)';
                } else {
                    response = 'UPX Error: Missing parameters. Usage: upx -d <file>';
                }
                break;
            case 'strings':
                if (args[1] === 'unpacked.exe') {
                    response = 'EXTRACTING_STRINGS...\n/lib/ld-linux.so.2\nGLIBC_2.3.4\nFLAG: AG{UPX_Unp4ck1ng_S4v3s_Th3_D4y}\nhost_master_v1';
                } else if (args[1] === 'packed.exe') {
                    response = '(Binary is packed - unreadable junk data)';
                } else if (args[1] === 'bof') {
                    response = '... vulnerable_function ... main ... gets ... FLAG: AG{b0f_m4st3r_2024}';
                } else {
                    response = `strings: ${args[1] || ''}: No such file`;
                }
                break;
            case 'docker-compose':
                if (args[1] === 'up') {
                    response = 'Creating network "bridge"\nCreating volume "host_v" ... \nStarting container "vulnerable_app_1" ... success.\nFLAG: AG{d0ck3r_3sc4p3_succ3ss}';
                } else {
                    response = 'Usage: docker-compose [up|down|ps]';
                }
                break;
            default:
                response = `sh: command not found: ${baseCmd}`;
                type = 'error';
        }

        setHistory([...history, { text: `$ ${fullCmd}`, type: 'input' }, { text: response, type }]);
        setInput('');
    };

    return (
        <div className="flex flex-col h-full bg-[#050505] text-blue-400 font-mono text-sm leading-relaxed rounded-3xl overflow-hidden shadow-2xl border border-white/5 group relative">
            {/* CRT Effects Overlay */}
            <div className="absolute inset-0 pointer-events-none z-50 opacity-[0.03] overflow-hidden rounded-3xl">
                <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,118,0.06))] bg-[length:100%_2px,3px_100%] animate-flicker" />
                <div className="absolute inset-0 shadow-[inset_0_0_100px_rgba(0,0,0,0.5)]" />
            </div>

            <div className="flex items-center justify-between px-6 py-4 bg-white/5 border-b border-white/5 relative z-10">
                <div className="flex items-center gap-3">
                    <TerminalIcon size={16} className="text-blue-500 animate-pulse" />
                    <span className="text-[10px] font-black uppercase tracking-[0.2em] text-gray-500">Neural_Bridge_Active</span>
                </div>
                <div className="flex gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/30" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/30" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/30 shadow-[0_0_10px_rgba(34,197,94,0.3)]" />
                </div>
            </div>

            <div className="flex-1 p-8 overflow-auto space-y-1 scrollbar-hide relative z-10">
                <AnimatePresence>
                    {history.map((entry, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -5 }}
                            animate={{ opacity: 1, x: 0 }}
                            className={`
                                ${entry.type === 'system' ? 'text-gray-600 italic text-[11px]' : ''}
                                ${entry.type === 'input' ? 'text-white font-bold before:content-["_"]' : ''}
                                ${entry.type === 'error' ? 'text-red-500' : ''}
                                ${entry.type === 'output' ? 'text-blue-400 whitespace-pre-wrap' : ''}
                            `}
                        >
                            {entry.text}
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            <div className="px-8 py-5 bg-white/5 flex items-center gap-4 border-t border-white/5 relative z-10">
                <span className="text-blue-500 font-black">▶</span>
                <input
                    type="text"
                    value={input}
                    autoFocus
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleCommand(input)}
                    className="flex-1 bg-transparent border-none outline-none text-white focus:ring-0 placeholder:opacity-20"
                    placeholder="ENTER TACTICAL COMMAND..."
                />
            </div>

            <style dangerouslySetInnerHTML={{
                __html: `
                @keyframes flicker {
                    0% { opacity: 0.97; }
                    5% { opacity: 0.95; }
                    10% { opacity: 0.9; }
                    15% { opacity: 0.95; }
                    20% { opacity: 0.98; }
                    25% { opacity: 0.95; }
                    30% { opacity: 0.9; }
                    40% { opacity: 0.98; }
                    50% { opacity: 0.95; }
                    60% { opacity: 0.9; }
                    70% { opacity: 0.98; }
                    80% { opacity: 0.95; }
                    90% { opacity: 0.9; }
                    100% { opacity: 0.98; }
                }
                .animate-flicker {
                    animation: flicker 0.15s infinite;
                }
            `}} />
        </div>
    );
};
