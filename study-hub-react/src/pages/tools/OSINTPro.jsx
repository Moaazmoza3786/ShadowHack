import React, { useState } from 'react';
import {
    Globe, Search, Flag, Wrench,
    Network, User, Mail, MapPin,
    Database, Shield, Terminal, Copy,
    Sparkles, Info, Lightbulb, Trophy,
    ArrowRight, ExternalLink, Filter,
    Activity, Cpu, Key, Eye, Fingerprint,
    Zap, Share2, Box, Layers
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useToast } from '../../context/ToastContext';
import { useAppContext } from '../../context/AppContext';

const OSINTPro = () => {
    const { toast } = useToast();
    const { apiUrl } = useAppContext();
    const [activeTab, setActiveTab] = useState('intelligence'); // intelligence, domain, social, metadata
    const [target, setTarget] = useState('');
    const [logs, setLogs] = useState([
        { type: 'info', msg: 'OSINT Pro v3.0 Digital Intelligence System Initialized.', time: new Date().toLocaleTimeString() },
        { type: 'cmd', msg: 'Awaiting target specification for deep-dive analysis...', time: new Date().toLocaleTimeString() }
    ]);

    const [isSearching, setIsSearching] = useState(false);
    const [findings, setFindings] = useState([]);

    const addLog = (msg, type = 'info') => {
        setLogs(prev => [...prev, { type, msg, time: new Date().toLocaleTimeString() }].slice(-50));
    };

    const handleSearch = async () => {
        if (!target) return toast('Please enter a target domain', 'error');
        setIsSearching(true);
        addLog(`Initiating deep OSINT search on ${target}...`, 'cmd');

        try {
            const response = await fetch(`${apiUrl}/tools/osint`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, type: activeTab })
            });
            const data = await response.json();
            if (data.success) {
                setFindings(data.results.findings);
                addLog(`Intelligence gathering complete for ${target}.`, 'info');
                toast('Search results synchronized.', 'success');
            }
        } catch (error) {
            console.error("OSINT search failed:", error);
            addLog("Search failure: Connection refused or backend offline.", "warn");
        } finally {
            setIsSearching(false);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast('Command copied to ops clipboard!', 'success');
        addLog(`Copied: ${text.substring(0, 30)}...`, 'cmd');
    };

    // --- RENDERERS ---

    const renderIntelligence = () => (
        <div className="space-y-8">
            <div className="bg-dark-800 border border-white/10 rounded-[3rem] p-10 relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-12 opacity-5 scale-150 rotate-12 group-hover:rotate-0 transition-transform duration-1000">
                    <Shield size={200} className="text-emerald-500" />
                </div>

                <div className="relative z-10 space-y-6 max-w-2xl">
                    <div className="inline-flex items-center gap-3 px-4 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        <span className="text-[10px] font-black text-emerald-500 uppercase tracking-widest">Global Intel Relay: SYNCED</span>
                    </div>

                    <h2 className="text-5xl font-black italic tracking-tighter leading-none text-white">
                        DIGITAL <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">INTELLIGENCE HUB</span>
                    </h2>
                    <p className="text-gray-400 text-lg font-medium leading-relaxed">
                        Professional reconnaissance framework for domain mapping, identity tracing, and data correlation. Transition from simulation to real-world operational intelligence.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {[
                    { label: 'Active Targets', value: '0', icon: Target, color: 'text-emerald-500' },
                    { label: 'Identified Leaks', value: 'PRO-ENABLED', icon: AlertTriangle, color: 'text-amber-500' },
                    { label: 'Intel Confidence', value: 'High Fidelity', icon: Activity, color: 'text-cyan-500' }
                ].map((stat, i) => (
                    <div key={i} className="bg-dark-800/40 border border-white/5 p-6 rounded-3xl flex items-center justify-between group hover:border-emerald-500/30 transition-all">
                        <div className="space-y-1">
                            <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">{stat.label}</div>
                            <div className={`text-xl font-black italic uppercase italic tracking-tighter ${stat.color}`}>{stat.value}</div>
                        </div>
                        <div className={`p-3 rounded-2xl bg-white/5 group-hover:scale-110 transition-transform ${stat.color}`}>
                            <stat.icon size={24} />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );

    const renderDomain = () => (
        <div className="space-y-6">
            <div className="bg-dark-800 border border-white/10 rounded-3xl p-8">
                <h3 className="text-xl font-black italic text-white mb-6 uppercase tracking-tighter flex items-center gap-3">
                    <Globe className="text-emerald-500" /> Infrastructure Enumeration
                </h3>
                <div className="flex gap-4 mb-8">
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="Target Domain (e.g., target.com)"
                        className="flex-1 bg-black border border-white/10 rounded-2xl px-6 py-4 font-mono text-emerald-500 focus:border-emerald-500 outline-none transition-all"
                    />
                    <button
                        onClick={handleSearch}
                        disabled={isSearching}
                        className="px-8 py-4 bg-emerald-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter hover:scale-105 transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                    >
                        {isSearching ? <RefreshCw className="animate-spin" /> : 'GENERATE OPS PLAN'}
                    </button>
                </div>

                {findings.length > 0 && (
                    <div className="mb-8 p-6 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl">
                        <h4 className="text-xs font-black text-emerald-500 uppercase tracking-widest mb-4">Real-Time Intelligence Found</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {findings.map((f, i) => (
                                <div key={i} className="p-4 bg-black/40 rounded-xl border border-white/5">
                                    <div className="text-[10px] font-black text-gray-500 uppercase mb-2">{f.source} Finding</div>
                                    <pre className="text-[10px] font-mono text-emerald-400 overflow-x-auto">
                                        {JSON.stringify(f.data, null, 2)}
                                    </pre>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <div className="space-y-4">
                        <h4 className="text-xs font-black text-gray-500 uppercase tracking-widest px-2">Subdomain Discovery</h4>
                        {[
                            { tool: 'Subfinder', cmd: `subfinder -d ${target || 'target.com'} -silent`, desc: 'Fast subdomain enumeration tool.' },
                            { tool: 'Assetfinder', cmd: `assetfinder --subs-only ${target || 'target.com'}`, desc: 'Find domains and subdomains of a specific threshold.' },
                            { tool: 'Amass', cmd: `amass enum -passive -d ${target || 'target.com'}`, desc: 'In-depth attack surface mapping and asset discovery.' }
                        ].map((item, i) => (
                            <div key={i} className="p-4 bg-black/40 border border-white/5 rounded-2xl group hover:border-emerald-400/30 transition-all">
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-sm font-black text-white italic uppercase">{item.tool}</span>
                                    <button onClick={() => copyToClipboard(item.cmd)} className="p-1.5 opacity-0 group-hover:opacity-100 hover:bg-emerald-500/20 rounded transition-all">
                                        <Copy size={12} className="text-emerald-500" />
                                    </button>
                                </div>
                                <code className="text-[10px] text-emerald-500/70 block break-all mb-2">{item.cmd}</code>
                                <p className="text-[10px] text-gray-500 italic font-medium">{item.desc}</p>
                            </div>
                        ))}
                    </div>

                    <div className="space-y-4">
                        <h4 className="text-xs font-black text-gray-500 uppercase tracking-widest px-2">Network Interrogation</h4>
                        {[
                            { tool: 'Dig (DNS)', cmd: `dig +short ${target || 'target.com'} mx`, desc: 'Query DNS name servers for MX records.' },
                            { tool: 'Whois', cmd: `whois ${target || 'target.com'}`, desc: 'Look up domain ownership and registration info.' },
                            { tool: 'Shodan CLI', cmd: `shodan domain ${target || 'target.com'}`, desc: 'Interrogate Shodan for domain-related services.' }
                        ].map((item, i) => (
                            <div key={i} className="p-4 bg-black/40 border border-white/5 rounded-2xl group hover:border-cyan-400/30 transition-all">
                                <div className="flex justify-between items-start mb-2">
                                    <span className="text-sm font-black text-white italic uppercase">{item.tool}</span>
                                    <button onClick={() => copyToClipboard(item.cmd)} className="p-1.5 opacity-0 group-hover:opacity-100 hover:bg-cyan-500/20 rounded transition-all">
                                        <Copy size={12} className="text-cyan-500" />
                                    </button>
                                </div>
                                <code className="text-[10px] text-cyan-500/70 block break-all mb-2">{item.cmd}</code>
                                <p className="text-[10px] text-gray-500 italic font-medium">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );

    const renderSocial = () => (
        <div className="space-y-6">
            <div className="bg-dark-800 border border-white/10 rounded-3xl p-8">
                <h3 className="text-xl font-black italic text-white mb-2 uppercase tracking-tighter flex items-center gap-3">
                    <User className="text-cyan-500" /> Identity & Breach Intelligence
                </h3>
                <p className="text-sm text-gray-500 mb-8">Correlate usernames and emails against public leaks and social platforms.</p>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
                    <div className="space-y-6">
                        <div className="p-6 bg-black rounded-2xl border border-white/5 space-y-4">
                            <h4 className="text-[10px] font-black text-cyan-500 uppercase tracking-widest flex items-center gap-2">
                                <Search size={12} /> Username Correlation
                            </h4>
                            <div className="space-y-4">
                                <input
                                    type="text"
                                    placeholder="Username to track..."
                                    className="w-full bg-dark-900 border border-white/5 rounded-xl px-4 py-3 text-sm font-mono text-cyan-500 outline-none focus:border-cyan-500/50"
                                />
                                <div className="p-4 bg-cyan-500/5 border border-cyan-500/20 rounded-xl space-y-3">
                                    <div className="flex justify-between items-center group cursor-pointer" onClick={() => copyToClipboard('sherlock [username]')}>
                                        <span className="text-xs font-bold text-white uppercase italic">Sherlock Suite</span>
                                        <Copy size={12} className="text-gray-500 group-hover:text-cyan-500" />
                                    </div>
                                    <p className="text-[10px] text-gray-500 leading-relaxed">Runs username checks against 300+ platforms including Github, X, Reddit, and LinkedIn.</p>
                                </div>
                            </div>
                        </div>

                        <div className="p-6 bg-black rounded-2xl border border-white/5 space-y-4">
                            <h4 className="text-[10px] font-black text-amber-500 uppercase tracking-widest flex items-center gap-2">
                                <Mail size={12} /> Breach Interrogation
                            </h4>
                            <div className="space-y-3">
                                <div className="flex justify-between items-center p-3 bg-white/5 rounded-xl group cursor-pointer" onClick={() => copyToClipboard('holehe [email]')}>
                                    <div className="space-y-1">
                                        <div className="text-xs font-bold text-white">Holehe (Email OSINT)</div>
                                        <div className="text-[9px] text-gray-500">Check for registered accounts via password recovery flows.</div>
                                    </div>
                                    <Copy size={12} className="text-gray-500 group-hover:text-amber-500" />
                                </div>
                                <div className="flex justify-between items-center p-3 bg-white/5 rounded-xl group cursor-pointer hover:bg-amber-500/10 transition-all">
                                    <div className="space-y-1">
                                        <div className="text-xs font-bold text-white">DeHashed / HIBP API</div>
                                        <div className="text-[9px] text-gray-500">Direct breach repository query (Requires API Key).</div>
                                    </div>
                                    <ExternalLink size={12} className="text-gray-500" />
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="bg-dark-900/50 rounded-3xl p-8 border border-white/5 flex flex-col items-center justify-center text-center gap-6">
                        <div className="w-20 h-20 rounded-full bg-cyan-500/10 flex items-center justify-center text-cyan-500 border border-cyan-500/20 shadow-[0_0_30px_rgba(6,182,212,0.15)]">
                            <Fingerprint size={40} />
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-xl font-black text-white italic uppercase tracking-tighter">Person of Interest (POI) Dashboard</h4>
                            <p className="text-xs text-gray-500 font-medium max-w-xs uppercase tracking-widest leading-relaxed">Integrating dynamic link analysis and relationship mapping engine...</p>
                        </div>
                        <div className="grid grid-cols-2 gap-3 w-full max-w-xs">
                            <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                <div className="h-full bg-cyan-500 w-1/3 animate-pulse" />
                            </div>
                            <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                <div className="h-full bg-cyan-500 w-1/2 animate-pulse" />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderMetadata = () => (
        <div className="bg-dark-800 border border-white/10 rounded-3xl p-8 space-y-8">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="space-y-1">
                    <h3 className="text-xl font-black italic text-white uppercase tracking-tighter flex items-center gap-3">
                        <MapPin className="text-orange-500" /> Forensic Metadata Lab
                    </h3>
                    <p className="text-sm text-gray-500">Analyze images, documents, and video files for hidden GPS and software tags.</p>
                </div>
                <div className="bg-orange-500/10 border border-orange-500/20 px-4 py-2 rounded-xl flex items-center gap-3">
                    <Terminal size={16} className="text-orange-500" />
                    <code className="text-[10px] font-mono text-orange-400">exiftool -all= [file]</code>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="bg-black/40 border border-white/5 rounded-2xl p-8 flex flex-col items-center justify-center gap-6 border-dashed group hover:border-orange-500/30 transition-all cursor-pointer">
                    <div className="w-20 h-20 rounded-3xl bg-white/5 flex items-center justify-center text-orange-500 group-hover:scale-110 transition-transform duration-500 font-black">
                        <Share2 size={32} />
                    </div>
                    <div className="text-center space-y-2">
                        <h4 className="text-lg font-black text-white italic uppercase tracking-tighter">Target Upload Zone</h4>
                        <p className="text-[10px] text-gray-500 font-bold uppercase tracking-[0.2em]">Drag image for deep EXIF parsing</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">Extraction Recipes</h4>
                    {[
                        { label: 'GPS Coordinates', cmd: 'exiftool -gpslatitude -gpslongitude [file]', icon: MapPin },
                        { label: 'Camera Hardware', cmd: 'exiftool -make -model [file]', icon: Cpu },
                        { label: 'Software Fingerprint', cmd: 'exiftool -software -modifydate [file]', icon: Activity },
                        { label: 'Wipe All Metadata', cmd: 'exiftool -all= -overwrite_original [file]', icon: Eye }
                    ].map((recipe, i) => (
                        <div key={i} className="flex items-center gap-4 p-4 bg-black border border-white/5 rounded-2xl group hover:border-orange-500/20 transition-all cursor-pointer" onClick={() => copyToClipboard(recipe.cmd)}>
                            <div className="w-10 h-10 rounded-xl bg-orange-500/10 flex items-center justify-center text-orange-500">
                                <recipe.icon size={18} />
                            </div>
                            <div className="flex-1">
                                <div className="text-xs font-bold text-white uppercase italic">{recipe.label}</div>
                                <code className="text-[9px] text-orange-400 group-hover:text-orange-300 transition-colors uppercase font-mono">{recipe.cmd}</code>
                            </div>
                            <Copy size={12} className="text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );

    const renderDorks = () => (
        <div className="bg-dark-800 border border-white/10 rounded-3xl p-8 space-y-8">
            <div className="max-w-xl space-y-4">
                <h3 className="text-xl font-black italic text-white uppercase tracking-tighter flex items-center gap-3">
                    <Search className="text-yellow-500" /> Advanced Google Dorker
                </h3>
                <p className="text-sm text-gray-400">Custom queries for finding leaked data and administrative vulnerabilities.</p>
                <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="target-domain.com"
                    className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 font-mono text-yellow-500 focus:border-yellow-500 outline-none"
                />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[
                    { cat: 'Leaked Data', q: `site:${target || 'target.com'} filetype:pdf OR filetype:doc OR filetype:xls "confidential"` },
                    { cat: 'Exposed Config', q: `site:${target || 'target.com'} ext:env OR ext:config OR ext:swp` },
                    { cat: 'Admin Panels', q: `site:${target || 'target.com'} inurl:admin OR inurl:login OR inurl:setup` },
                    { cat: 'Directory Listing', q: `site:${target || 'target.com'} intitle:"index of"` },
                    { cat: 'Subdomains', q: `site:*.${target || 'target.com'} -www` },
                    { cat: 'API Keys', q: `site:github.com "${target || 'target.com'}" "api_key"` }
                ].map((dork, i) => (
                    <div key={i} className="p-5 bg-black/40 border border-white/5 rounded-2xl group hover:border-yellow-500/30 transition-all space-y-3">
                        <div className="flex items-center justify-between">
                            <span className="text-[10px] font-black text-yellow-500 uppercase tracking-widest">{dork.cat}</span>
                            <div className="flex gap-2">
                                <button onClick={() => copyToClipboard(dork.q)} className="p-1.5 hover:bg-yellow-500/20 rounded transition-all">
                                    <Copy size={12} className="text-yellow-500" />
                                </button>
                                <a href={`https://www.google.com/search?q=${encodeURIComponent(dork.q)}`} target="_blank" rel="noopener noreferrer" className="p-1.5 hover:bg-yellow-500/20 rounded transition-all">
                                    <ExternalLink size={12} className="text-yellow-500" />
                                </a>
                            </div>
                        </div>
                        <code className="text-[10px] text-white/40 block leading-relaxed break-all font-mono italic">{dork.q}</code>
                    </div>
                ))}
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* HERO BAR */}
            <div className="bg-dark-900 border border-white/10 rounded-full px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                        <Globe className="text-emerald-500" size={20} />
                        <h1 className="text-xl font-black italic tracking-tighter uppercase leading-none">
                            OSINT <span className="text-emerald-500">PRO</span>
                        </h1>
                    </div>
                    <div className="h-4 w-px bg-white/10 hidden md:block" />
                    <nav className="flex gap-4">
                        {[
                            { id: 'intelligence', label: 'Hub' },
                            { id: 'domain', label: 'Domain' },
                            { id: 'social', label: 'Social' },
                            { id: 'metadata', label: 'Metadata' },
                            { id: 'dorks', label: 'Dorks' }
                        ].map(t => (
                            <button
                                key={t.id}
                                onClick={() => setActiveTab(t.id)}
                                className={`text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === t.id ? 'text-emerald-500' : 'text-gray-500 hover:text-white'}`}
                            >
                                {t.label}
                            </button>
                        ))}
                    </nav>
                </div>

                <div className="hidden md:flex items-center gap-4">
                    <div className="text-right">
                        <div className="text-[8px] font-bold text-gray-500 uppercase tracking-widest">Active Operative</div>
                        <div className="text-[10px] font-black text-white italic uppercase">Session: AD-72-B9</div>
                    </div>
                    <div className="w-10 h-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500">
                        <User size={20} />
                    </div>
                </div>
            </div>

            {/* TAB CONTENT */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, scale: 0.98, y: 10 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 1.02, y: -10 }}
                    className="min-h-[600px]"
                >
                    {activeTab === 'intelligence' && renderIntelligence()}
                    {activeTab === 'domain' && renderDomain()}
                    {activeTab === 'social' && renderSocial()}
                    {activeTab === 'metadata' && renderMetadata()}
                    {activeTab === 'dorks' && renderDorks()}
                </motion.div>
            </AnimatePresence>

            {/* INTEL LOGS */}
            <div className="bg-dark-900/80 border border-white/5 rounded-3xl p-6 font-mono overflow-hidden">
                <div className="flex items-center gap-4 mb-4">
                    <div className="flex gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-red-500/20" />
                        <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20" />
                        <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/50" />
                    </div>
                    <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Digital Footprint Logs</span>
                </div>
                <div className="h-40 overflow-y-auto space-y-1.5 px-2 scrollbar-cyber">
                    {logs.map((log, i) => (
                        <div key={i} className="text-[10px] flex gap-4 border-b border-white/[0.02] pb-1 font-mono">
                            <span className="text-gray-600 shrink-0">[{log.time}]</span>
                            <span className={`${log.type === 'cmd' ? 'text-emerald-500' : log.type === 'warn' ? 'text-amber-500' : 'text-gray-400'}`}>
                                {log.type === 'cmd' ? '>> ' : ''}{log.msg}
                            </span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

const Target = ({ size, className }) => (
    <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
    >
        <circle cx="12" cy="12" r="10" />
        <circle cx="12" cy="12" r="6" />
        <circle cx="12" cy="12" r="2" />
    </svg>
);

const AlertTriangle = ({ size, className }) => (
    <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
    >
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
);

export default OSINTPro;
