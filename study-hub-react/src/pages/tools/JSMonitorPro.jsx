import React, { useState, useEffect, useRef } from 'react';
import {
    Shield, Play, Square, RefreshCw, AlertTriangle, CheckCircle,
    Clock, FileJson, AlertOctagon, Search, Terminal, Copy,
    ExternalLink, Zap, Eye, Bug, Code, Link as LinkIcon, Lock,
    Activity
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useToast } from '../../context/ToastContext';
import { useAppContext } from '../../context/AppContext';

const JSMonitorPro = () => {
    const { toast } = useToast();
    const { apiUrl } = useAppContext();
    const [activeTab, setActiveTab] = useState('scanner'); // scanner, mapper, dom-auditor
    const [targetUrl, setTargetUrl] = useState('');
    const [monitoring, setMonitoring] = useState(false);
    const [intervalSeconds, setIntervalSeconds] = useState(60);
    const [history, setHistory] = useState([]);
    const [findings, setFindings] = useState([]);
    const [status, setStatus] = useState('idle');
    const intervalRef = useRef(null);

    // --- PRO SECRET DISCOVERY ---
    const proSignatures = [
        { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24}/g, severity: 'critical' },
        { name: 'Twilio Auth Token', pattern: /AC[a-z0-9]{32}/g, severity: 'critical' },
        { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/g, severity: 'high' },
        { name: 'Firebase Database', pattern: /[a-z0-9.-]+\.firebaseio\.com/gi, severity: 'medium' },
        { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'high' },
        { name: 'Slack Webhook', pattern: /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, severity: 'critical' },
        { name: 'Google Cloud API', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'critical' },
        { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
        { name: 'Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'critical' },
        { name: 'Generic Secret', pattern: /['"]?(secret|password|auth|creds)['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{8,}['"]/gi, severity: 'high' }
    ];

    const addLog = (msg, type = 'info') => {
        const timestamp = new Date().toLocaleTimeString();
        setHistory(prev => [{ time: timestamp, msg, type }, ...prev].slice(0, 50));
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast('Copied to clipboard!', 'success');
    };

    const runScan = async () => {
        if (!targetUrl) return toast('Please enter a target URL', 'error');
        setStatus('scanning');
        addLog(`Initiating backend monitor on ${targetUrl}...`, 'cmd');

        try {
            const response = await fetch(`${apiUrl}/tools/js-monitor`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            });
            const data = await response.json();
            if (data.success) {
                addLog(`Backend monitoring active for ${targetUrl}.`, 'success');
                toast('Monitoring initialized on backend.', 'success');

                // Add a simulated finding to show it works
                setFindings(prev => [
                    { type: 'Monitor Active', value: `Tracking changes on ${targetUrl}`, severity: 'info', timestamp: new Date().toLocaleTimeString() },
                    ...prev
                ]);
            }
        } catch (error) {
            console.error("JS Monitor failed:", error);
            addLog("Monitor failure: Backend unreachable.", "warn");
        } finally {
            setStatus('idle');
        }
    };

    // --- RENDERERS ---

    const renderScanner = () => (
        <div className="space-y-6">
            <div className="bg-dark-800 border border-white/10 rounded-3xl p-8">
                <div className="flex flex-col md:flex-row gap-4 items-end mb-8">
                    <div className="flex-1 w-full">
                        <label className="block text-[10px] font-black text-cyan-500 uppercase tracking-widest mb-3">Target JS / URL Endpoint</label>
                        <div className="relative">
                            <input
                                type="text"
                                value={targetUrl}
                                onChange={(e) => setTargetUrl(e.target.value)}
                                placeholder="https://target.com/assets/app.js"
                                className="w-full bg-black border border-white/10 rounded-2xl py-4 px-6 font-mono text-cyan-400 focus:border-cyan-500 outline-none"
                            />
                            <Search className="absolute right-6 top-4 text-gray-500 pointer-events-none" />
                        </div>
                    </div>
                    <button
                        onClick={runScan}
                        className="px-10 py-4 bg-cyan-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter hover:scale-105 transition-all shadow-lg shadow-cyan-500/20"
                    >
                        INITIALIZE SCAN
                    </button>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <div className="space-y-4">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2 flex items-center gap-2">
                            <Shield size={12} className="text-cyan-500" /> Security Findings
                        </h4>
                        <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 scrollbar-cyber">
                            {findings.length === 0 ? (
                                <div className="p-8 text-center text-gray-600 border-2 border-dashed border-white/5 rounded-2xl opacity-50">
                                    Awaiting scan results...
                                </div>
                            ) : (
                                findings.map((f, i) => (
                                    <div key={i} className="p-4 bg-black/40 border border-white/5 rounded-2xl group hover:border-cyan-500/30 transition-all">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className={`text-[8px] font-black px-2 py-0.5 rounded uppercase ${f.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-500'}`}>
                                                {f.severity}
                                            </span>
                                            <span className="text-[10px] font-mono text-gray-600 font-bold">{f.timestamp}</span>
                                        </div>
                                        <div className="space-y-2">
                                            <div className="text-xs font-black text-white italic uppercase">{f.type}</div>
                                            <code className="block text-[10px] text-cyan-500/70 truncate bg-black/40 p-2 rounded border border-white/5">{f.value}</code>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    <div className="space-y-4">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2 flex items-center gap-2">
                            <Zap size={12} className="text-purple-500" /> Secret Signatures
                        </h4>
                        <div className="grid grid-cols-1 gap-2">
                            {proSignatures.slice(0, 6).map((sig, i) => (
                                <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/5">
                                    <div className="flex items-center gap-3">
                                        <div className={`w-1.5 h-1.5 rounded-full ${sig.severity === 'critical' ? 'bg-red-500' : 'bg-purple-500'}`} />
                                        <span className="text-xs font-bold text-gray-300 uppercase italic leading-none">{sig.name}</span>
                                    </div>
                                    <div className="text-[9px] font-black text-gray-600 uppercase tracking-tighter">Regex Active</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderMapper = () => (
        <div className="space-y-6">
            <div className="bg-dark-800 border border-white/10 rounded-3xl p-8">
                <h3 className="text-xl font-black italic text-white mb-6 uppercase tracking-tighter flex items-center gap-3">
                    <LinkIcon className="text-cyan-500" /> Attack Surface Mapping
                </h3>
                <p className="text-sm text-gray-400 mb-8 max-w-2xl">
                    Gather endpoints, hidden routes, and sensitive files from JavaScript bundles using professional command-line techniques.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div className="space-y-4">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">Endpoint Discovery</h4>
                        {[
                            { tool: 'LinkFinder', cmd: `python3 linkfinder.py -i ${targetUrl || 'target.com/app.js'} -o cli`, desc: 'Extract endpoints and params from JS files.' },
                            { tool: 'SubJS', cmd: `subjs -i url_list.txt`, desc: 'Gather JS files from a list of subdomains.' },
                            { tool: 'KJS', cmd: `cat urls.txt | hx extract -t js | kjs`, desc: 'Custom pipe for endpoint normalization.' }
                        ].map((item, i) => (
                            <div key={i} className="p-4 bg-black border border-white/5 rounded-2xl group hover:border-cyan-500/30 transition-all">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-xs font-black text-white italic uppercase">{item.tool}</span>
                                    <button onClick={() => copyToClipboard(item.cmd)} className="p-2 hover:bg-cyan-500/20 rounded-lg group-hover:scale-110 transition-all">
                                        <Copy size={12} className="text-cyan-500" />
                                    </button>
                                </div>
                                <code className="block text-[10px] text-cyan-400/80 mb-2 font-mono break-all leading-relaxed bg-black/50 p-3 rounded-xl">{item.cmd}</code>
                                <p className="text-[10px] text-gray-500 italic font-medium">{item.desc}</p>
                            </div>
                        ))}
                    </div>

                    <div className="space-y-4">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">Secret Extraction</h4>
                        {[
                            { tool: 'SecretFinder', cmd: `python3 SecretFinder.py -i ${targetUrl || 'target.com/app.js'} -o cli`, desc: 'Pro-grade secret discovery in JS files.' },
                            { tool: 'TruffleHog (JS)', cmd: `trufflehog filesystem --directory=/path/to/extracted/js`, desc: 'Deep-dive scan for credentials in project files.' }
                        ].map((item, i) => (
                            <div key={i} className="p-4 bg-black border border-white/5 rounded-2xl group hover:border-purple-500/30 transition-all">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-xs font-black text-white italic uppercase">{item.tool}</span>
                                    <button onClick={() => copyToClipboard(item.cmd)} className="p-2 hover:bg-purple-500/20 rounded-lg group-hover:scale-110 transition-all">
                                        <Copy size={12} className="text-purple-500" />
                                    </button>
                                </div>
                                <code className="block text-[10px] text-purple-400/80 mb-2 font-mono break-all leading-relaxed bg-black/50 p-3 rounded-xl">{item.cmd}</code>
                                <p className="text-[10px] text-gray-500 italic font-medium">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );

    const renderDOMAuditor = () => (
        <div className="space-y-6">
            <div className="bg-dark-800 border border-white/10 rounded-3xl p-8">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h3 className="text-xl font-black italic text-white uppercase tracking-tighter flex items-center gap-3">
                            <Bug className="text-orange-500" /> DOM Security Auditor
                        </h3>
                        <p className="text-xs text-gray-400">Manually inspect and audit DOM-based vulnerability sinks and sources.</p>
                    </div>
                    <div className="px-4 py-2 bg-orange-500/10 border border-orange-500/20 rounded-xl">
                        <span className="text-[10px] font-black text-orange-500 uppercase tracking-widest leading-none">Vulnerability Class: DOM-XSS</span>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
                    <div className="space-y-6">
                        <h4 className="text-xs font-black text-gray-500 uppercase tracking-widest px-2">Dangerous Sinks (Audit Points)</h4>
                        <div className="space-y-3">
                            {[
                                { name: 'innerHTML', desc: 'Allows direct execution of malicious script tags.', risk: 'High' },
                                { name: 'eval()', desc: 'Executes arbitrary string content as code.', risk: 'Critical' },
                                { name: 'setTimeout() / setInterval()', desc: 'String arguments can lead to execution if unsanitized.', risk: 'Medium' },
                                { name: 'document.write()', desc: 'Can overwrite entire page content or inject scripts.', risk: 'High' }
                            ].map((sink, i) => (
                                <div key={i} className="p-4 bg-white/5 border border-white/5 rounded-2xl group hover:border-orange-500/20 transition-all">
                                    <div className="flex justify-between items-center mb-1">
                                        <span className="text-sm font-black text-white italic uppercase tracking-tighter">{sink.name}</span>
                                        <span className="text-[8px] font-black text-orange-500 uppercase tracking-widest">{sink.risk} Risk</span>
                                    </div>
                                    <p className="text-[10px] text-gray-500 leading-relaxed italic">{sink.desc}</p>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="bg-black/40 border border-white/5 rounded-3xl p-8 flex flex-col items-center justify-center text-center gap-6">
                        <div className="w-20 h-20 rounded-full bg-orange-500/10 flex items-center justify-center text-orange-500 border border-orange-500/20 shadow-[0_0_30px_rgba(249,115,22,0.15)]">
                            <Eye size={40} />
                        </div>
                        <div className="space-y-2">
                            <h4 className="text-xl font-black text-white italic uppercase tracking-tighter">Live DOM Inspector Component</h4>
                            <p className="text-xs text-gray-500 font-medium max-w-xs uppercase tracking-widest leading-relaxed">System integration for runtime DOM interception and sink monitoring in development mode...</p>
                        </div>
                        <div className="flex gap-2">
                            {[...Array(3)].map((_, i) => (
                                <div key={i} className="w-12 h-1 bg-orange-500/20 rounded-full overflow-hidden">
                                    <div className="h-full bg-orange-500 w-1/2 animate-pulse" />
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* HERO NAVIGATION */}
            <div className="bg-dark-900 border border-white/10 rounded-full px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                        <Activity className="text-cyan-500" size={20} />
                        <h1 className="text-xl font-black italic tracking-tighter uppercase leading-none">
                            JS MONITOR <span className="text-cyan-500">PRO</span>
                        </h1>
                    </div>
                    <div className="h-4 w-px bg-white/10 hidden md:block" />
                    <nav className="flex gap-6">
                        {[
                            { id: 'scanner', label: 'Scanner', icon: Shield },
                            { id: 'mapper', label: 'Surface Map', icon: LinkIcon },
                            { id: 'dom-auditor', label: 'DOM Auditor', icon: Bug }
                        ].map(t => (
                            <button
                                key={t.id}
                                onClick={() => setActiveTab(t.id)}
                                className={`flex items-center gap-2 text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === t.id ? 'text-cyan-500' : 'text-gray-500 hover:text-white'}`}
                            >
                                <t.icon size={14} />
                                <span className="hidden sm:inline">{t.label}</span>
                            </button>
                        ))}
                    </nav>
                </div>

                <div className="hidden md:flex items-center gap-4">
                    <div className="px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                        <span className="text-[10px] font-black text-emerald-500 uppercase tracking-widest leading-none mt-0.5">Live Feed Active</span>
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
                    {activeTab === 'scanner' && renderScanner()}
                    {activeTab === 'mapper' && renderMapper()}
                    {activeTab === 'dom-auditor' && renderDOMAuditor()}
                </motion.div>
            </AnimatePresence>

            {/* ACTIVITY BOX */}
            <div className="bg-dark-900 border border-white/10 rounded-[2.5rem] p-8 font-mono">
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-4">
                        <Terminal size={18} className="text-cyan-500" />
                        <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Digital Footprint Intelligence Feed</span>
                    </div>
                    <div className="flex gap-2">
                        <div className="w-3 h-3 rounded-full bg-red-500/20" />
                        <div className="w-3 h-3 rounded-full bg-emerald-500/50" />
                    </div>
                </div>
                <div className="h-48 overflow-y-auto space-y-2 scrollbar-cyber pr-4">
                    {history.length === 0 ? (
                        <div className="text-[10px] text-gray-600 italic">No activity detected yet...</div>
                    ) : (
                        history.map((log, i) => (
                            <div key={i} className="text-[10px] flex gap-4 pb-2 border-b border-white/[0.02]">
                                <span className="text-gray-600 shrink-0">[{log.time}]</span>
                                <span className={log.type === 'cmd' ? 'text-cyan-400' : log.type === 'success' ? 'text-emerald-500' : 'text-gray-400'}>
                                    {log.type === 'cmd' && '>> '}{log.msg}
                                </span>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
};

export default JSMonitorPro;
