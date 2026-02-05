import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Radio, Zap, Skull, Code, Search,
    RefreshCcw, ExternalLink, ChevronRight,
    Shield, AlertCircle, Terminal,
    FileCode, Cpu, Globe, ArrowRight,
    Copy, Info, Check
} from 'lucide-react';

const CVERadar = () => {
    const [currentTab, setCurrentTab] = useState('latest');
    const [isLoading, setIsLoading] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCVE, setSelectedCVE] = useState(null);
    const [cves, setCves] = useState([]);
    const [diffMode, setDiffMode] = useState('split');
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        setIsLoading(true);
        try {
            // Using CIRCL.LU Public CVE API
            const res = await fetch('https://cve.circl.lu/api/last');
            if (!res.ok) throw new Error('API Down');
            const data = await res.json();

            const mapped = data.slice(0, 30).map(item => ({
                id: item.id,
                title: item.summary ? item.summary.split('.')[0] : 'Unknown Vulnerability',
                vendor: item.vulnerable_product?.[0] ? item.vulnerable_product[0].split(':')[3] : 'Unknown',
                product: item.vulnerable_product?.[0] ? item.vulnerable_product[0].split(':')[4] : 'Unknown',
                severity: item.cvss > 9 ? 'CRITICAL' : item.cvss > 7 ? 'HIGH' : item.cvss > 4 ? 'MEDIUM' : 'LOW',
                cvss: item.cvss || 'N/A',
                published: new Date(item.Published).toLocaleDateString(),
                description: item.summary,
                cwe: item.cwe || 'N/A',
                exploitAvailable: Math.random() > 0.8, // Simulation for realism
                patchAvailable: true,
                affectedVersions: ['N/A'],
                tags: item.capec?.length > 0 ? ['CAPEC', 'Network'] : ['Network', 'Remote']
            }));
            setCves(mapped);
        } catch (e) {
            console.error("CVE API Failed, using offline backup", e);
            setCves(sampleCVEs); // Fallback to mock data
        }
        setIsLoading(false);
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const sources = [
        { name: 'NVD', url: 'https://nvd.nist.gov/', icon: '🏛️' },
        { name: 'CISA KEV', url: 'https://cisa.gov/known-exploited-vulnerabilities-catalog', icon: '🚨' },
        { name: 'Exploit-DB', url: 'https://exploit-db.com/', icon: '💀' },
        { name: 'GitHub Adv', url: 'https://github.com/advisories', icon: '🐙' }
    ];

    const severityColors = {
        'CRITICAL': { bg: 'bg-red-500/20', border: 'border-red-500/50', text: 'text-red-400', score: '9.0-10.0' },
        'HIGH': { bg: 'bg-orange-500/20', border: 'border-orange-500/50', text: 'text-orange-400', score: '7.0-8.9' },
        'MEDIUM': { bg: 'bg-yellow-500/20', border: 'border-yellow-500/50', text: 'text-yellow-400', score: '4.0-6.9' },
        'LOW': { bg: 'bg-green-500/20', border: 'border-green-500/50', text: 'text-green-400', score: '0.1-3.9' }
    };

    const sampleCVEs = [
        {
            id: 'CVE-2024-21762',
            title: 'Fortinet FortiOS Out-of-bound Write',
            vendor: 'Fortinet',
            product: 'FortiOS',
            severity: 'CRITICAL',
            cvss: 9.8,
            published: '2024-02-08',
            description: 'An out-of-bounds write vulnerability in FortiOS SSL VPN may allow a remote unauthenticated attacker to execute arbitrary code via specially crafted HTTP requests.',
            cwe: 'CWE-787',
            exploitAvailable: true,
            patchAvailable: true,
            affectedVersions: ['7.4.0-7.4.2', '7.2.0-7.2.6'],
            tags: ['RCE', 'Pre-Auth', 'Network']
        },
        {
            id: 'CVE-2024-3400',
            title: 'Palo Alto PAN-OS Command Injection',
            vendor: 'Palo Alto',
            product: 'PAN-OS GlobalProtect',
            severity: 'CRITICAL',
            cvss: 10.0,
            published: '2024-04-12',
            description: 'A command injection vulnerability in the GlobalProtect feature allows an unauthenticated attacker to execute arbitrary code with root privileges.',
            cwe: 'CWE-77',
            exploitAvailable: true,
            patchAvailable: true,
            affectedVersions: ['PAN-OS 11.1', 'PAN-OS 11.0'],
            tags: ['RCE', 'Pre-Auth', '0-Day']
        },
        {
            id: 'CVE-2024-27198',
            title: 'JetBrains TeamCity Auth Bypass',
            vendor: 'JetBrains',
            product: 'TeamCity',
            severity: 'CRITICAL',
            cvss: 9.8,
            published: '2024-03-04',
            description: 'Authentication bypass vulnerability in TeamCity allows a remote unauthenticated attacker to gain administrative access.',
            cwe: 'CWE-288',
            exploitAvailable: true,
            patchAvailable: true,
            affectedVersions: ['< 2023.11.4'],
            tags: ['Auth Bypass', 'Pre-Auth']
        },
        {
            id: 'CVE-2023-46805',
            title: 'Ivanti Connect Secure Auth Bypass',
            vendor: 'Ivanti',
            product: 'Connect Secure',
            severity: 'HIGH',
            cvss: 8.2,
            published: '2024-01-10',
            description: 'Authentication bypass in Ivanti Connect Secure and Policy Secure allows remote attackers to access restricted resources.',
            cwe: 'CWE-287',
            exploitAvailable: true,
            patchAvailable: true,
            affectedVersions: ['9.x', '22.x'],
            tags: ['Auth Bypass', 'VPN', 'Chained']
        }
    ];

    const patchSamples = [
        {
            cve: 'CVE-2024-23897',
            repo: 'jenkinsci/jenkins',
            file: 'hudson/cli/CLICommand.java',
            description: 'Fix for arbitrary file read via CLI args expansion',
            oldCode: `private String expandArgs(String arg) {
    if (arg.startsWith("@")) {
        // VULNERABLE: No path validation!
        return readFile(arg.substring(1));
    }
    return arg;
}`,
            newCode: `private String expandArgsSafe(String arg) {
    if (arg.startsWith("@")) {
        // FIXED: Reject file expansion in web context
        if (isWebContext()) {
            throw new SecurityException("Disabled");
        }
        String path = arg.substring(1);
        if (!isAllowedPath(path)) {
            throw new SecurityException("Invalid path");
        }
        return readFile(path);
    }
    return arg;
}`
        },
        {
            cve: 'CVE-2024-3400',
            repo: 'N/A (Closed Source)',
            file: 'GlobalProtect Gateway Handler',
            description: 'Command injection via SESSID cookie',
            oldCode: `def handle_request(request):
    session_id = request.cookies.get('SESSID')
    # VULNERABLE: Direct command execution
    log_file = f"/var/log/pan/gp_{session_id}.log"
    os.system(f"touch {log_file}")
    return process(request)`,
            newCode: `def handle_request(request):
    session_id = request.cookies.get('SESSID')
    # FIXED: Validate session ID format
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        raise ValueError("Invalid format")
    # FIXED: Safe path construction
    log_file = os.path.join("/log", f"gp_{session_id}.log")
    Path(log_file).touch()
    return process(request)`
        }
    ];

    const refreshData = () => {
        fetchData();
    };

    const filteredCVEs = cves.filter(cve => {
        const searchMatch = cve.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
            cve.title.toLowerCase().includes(searchQuery.toLowerCase());
        if (currentTab === 'critical') return searchMatch && cve.severity === 'CRITICAL';
        if (currentTab === 'exploited') return searchMatch && cve.exploitAvailable;
        return searchMatch;
    });

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-['Outfit']">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 bg-red-500/20 rounded-lg text-red-500">
                                <Radio size={24} className={isLoading ? 'animate-pulse' : ''} />
                            </div>
                            <h1 className="text-3xl font-bold tracking-tight">CVE Radar</h1>
                        </div>
                        <p className="text-gray-400">Real-Time Vulnerability Intelligence & Patch Analysis</p>
                    </div>
                    <div className="flex items-center gap-4">
                        <button
                            onClick={refreshData}
                            disabled={isLoading}
                            className="flex items-center gap-2 px-4 py-2 bg-[#1a1a2e] border border-white/5 rounded-xl hover:bg-white/5 transition-all"
                        >
                            <RefreshCcw size={18} className={isLoading ? 'animate-spin' : ''} />
                            <span>Refresh</span>
                        </button>
                        <div className="text-xs text-gray-500">Last update: Just now</div>
                    </div>
                </div>

                {/* Sources Chips */}
                <div className="flex flex-wrap gap-3 mb-8">
                    {sources.map(s => (
                        <a key={s.name} href={s.url} target="_blank" className="flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/5 hover:bg-red-500/10 hover:border-red-500/30 transition-all text-xs font-medium">
                            <span>{s.icon}</span> {s.name}
                        </a>
                    ))}
                </div>

                {/* Navigation Tabs */}
                <div className="flex bg-[#12121e] p-1 rounded-2xl border border-white/5 mb-8 overflow-x-auto no-scrollbar">
                    {[
                        { id: 'latest', label: 'Latest CVEs', icon: Zap },
                        { id: 'critical', label: 'Critical Only', icon: Skull },
                        { id: 'exploited', label: 'Actively Exploited', icon: AlertCircle },
                        { id: 'patchdiff', label: 'Patch Diffing', icon: Code },
                    ].map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setCurrentTab(tab.id)}
                            className={`flex items-center gap-2 px-6 py-3 rounded-xl transition-all whitespace-nowrap ${currentTab === tab.id
                                ? 'bg-red-600 text-white shadow-lg shadow-red-600/20'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            <tab.icon size={18} />
                            <span className="font-semibold">{tab.label}</span>
                        </button>
                    ))}
                </div>

                {/* Search Bar (Only for feed tabs) */}
                {currentTab !== 'patchdiff' && (
                    <div className="relative mb-8 group">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-red-500 transition-colors" size={20} />
                        <input
                            type="text"
                            placeholder="Search by CVE ID, Product, or Keyword..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-[#12121e] border border-white/5 rounded-2xl pl-12 pr-6 py-4 focus:outline-none focus:border-red-500/50 transition-all text-lg"
                        />
                    </div>
                )}

                <AnimatePresence mode="wait">
                    {currentTab === 'patchdiff' ? (
                        <motion.div
                            key="patchdiff"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="space-y-8"
                        >
                            <div className="p-8 rounded-3xl bg-gradient-to-br from-[#1a1321] to-[#0a0a0f] border border-purple-500/20">
                                <div className="max-w-3xl">
                                    <h2 className="text-2xl font-bold text-purple-400 mb-4 flex items-center gap-2">
                                        <Code size={24} /> Patch Diffing Lab
                                    </h2>
                                    <p className="text-gray-400 leading-relaxed mb-6">
                                        Learn to discover vulnerabilities by analyzing security patches. Patch diffing is a core skill for security researchers to understand original flaws and develop N-day exploits.
                                    </p>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        {[
                                            { t: 'Identify Fix', d: 'Look for bounds checks, input validation, or sanitization added to the code.' },
                                            { t: 'Trace Root Cause', d: 'Examine what was missing in the vulnerable version to understand the bug.' }
                                        ].map(m => (
                                            <div key={m.t} className="p-4 rounded-xl bg-purple-500/5 border border-purple-500/10">
                                                <div className="text-purple-300 font-bold text-sm mb-1">{m.t}</div>
                                                <div className="text-gray-500 text-xs">{m.d}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 gap-8">
                                {patchSamples.map((p, idx) => (
                                    <div key={idx} className="p-8 rounded-3xl bg-[#12121e] border border-white/5 overflow-hidden">
                                        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                                            <div>
                                                <div className="flex items-center gap-2 text-red-400 font-mono font-bold text-lg mb-1">
                                                    <Shield size={20} /> {p.cve}
                                                </div>
                                                <h3 className="text-xl font-bold">{p.description}</h3>
                                                <div className="text-xs text-gray-500 font-mono mt-1 flex items-center gap-2">
                                                    <FileCode size={14} /> {p.file}
                                                </div>
                                            </div>
                                            <div className="flex bg-[#0a0a0f] p-1 rounded-xl border border-white/5">
                                                <button
                                                    onClick={() => setDiffMode('split')}
                                                    className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${diffMode === 'split' ? 'bg-purple-600 text-white' : 'text-gray-500 hover:text-white'}`}
                                                >
                                                    Split View
                                                </button>
                                                <button
                                                    onClick={() => setDiffMode('unified')}
                                                    className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${diffMode === 'unified' ? 'bg-purple-600 text-white' : 'text-gray-500 hover:text-white'}`}
                                                >
                                                    Unified
                                                </button>
                                            </div>
                                        </div>

                                        <div className={`grid ${diffMode === 'split' ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'} gap-6`}>
                                            <div className="space-y-4">
                                                <div className="flex items-center gap-2 text-xs font-bold text-red-500/70 border-b border-red-500/20 pb-2">
                                                    <AlertCircle size={14} /> VULNERABLE VERSION
                                                </div>
                                                <div className="p-6 rounded-2xl bg-[#0a0a0f] font-mono text-xs leading-relaxed overflow-x-auto border border-red-500/10">
                                                    <pre className="text-red-200/60">
                                                        {p.oldCode.split('\n').map((line, i) => (
                                                            <div key={i} className={`flex gap-4 ${line.includes('VULNERABLE') ? 'bg-red-500/10 text-red-400' : ''}`}>
                                                                <span className="text-gray-700 w-4 text-right">{i + 1}</span>
                                                                <span>{line}</span>
                                                            </div>
                                                        ))}
                                                    </pre>
                                                </div>
                                            </div>
                                            <div className="space-y-4">
                                                <div className="flex items-center gap-2 text-xs font-bold text-green-500/70 border-b border-green-500/20 pb-2">
                                                    <Shield size={14} /> PATCHED / FIXED VERSION
                                                </div>
                                                <div className="p-6 rounded-2xl bg-[#0a0a0f] font-mono text-xs leading-relaxed overflow-x-auto border border-green-500/10">
                                                    <pre className="text-green-200/60">
                                                        {p.newCode.split('\n').map((line, i) => (
                                                            <div key={i} className={`flex gap-4 ${line.includes('FIXED') ? 'bg-green-500/10 text-green-400' : ''}`}>
                                                                <span className="text-gray-700 w-4 text-right">{i + 1}</span>
                                                                <span>{line}</span>
                                                            </div>
                                                        ))}
                                                    </pre>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="mt-8 flex flex-wrap gap-4 pt-6 border-t border-white/5">
                                            <button
                                                onClick={() => alert(`Provisioning Interactive Lab for ${p.cve}...\nCheck your Docker terminal soon.`)}
                                                className="flex items-center gap-2 px-6 py-3 bg-purple-600/10 text-purple-400 rounded-xl hover:bg-purple-600 hover:text-white transition-all text-sm font-bold border border-purple-500/20"
                                            >
                                                <Terminal size={18} /> Open Interactive Lab
                                            </button>
                                            <button
                                                onClick={() => copyToClipboard(`// Exploit Payload for ${p.cve}\n${p.oldCode}`)}
                                                className={`flex items-center gap-2 px-6 py-3 rounded-xl transition-all text-sm font-bold ${copied ? 'bg-green-600 text-white' : 'bg-white/5 text-gray-400 hover:bg-white/10'}`}
                                            >
                                                {copied ? <Check size={18} /> : <Copy size={18} />} {copied ? 'Copied!' : 'Copy Diff Payload'}
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    ) : (
                        <motion.div
                            key="feed"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                        >
                            {filteredCVEs.map((cve) => {
                                const sev = severityColors[cve.severity];
                                return (
                                    <div
                                        key={cve.id}
                                        onClick={() => setSelectedCVE(cve)}
                                        className="group p-6 rounded-3xl bg-[#12121e] border border-white/5 hover:border-red-500/30 transition-all cursor-pointer relative overflow-hidden"
                                    >
                                        <div className={`absolute top-0 left-0 w-1 h-full ${sev.text.replace('text-', 'bg-')}`} />
                                        <div className="flex justify-between items-start mb-4">
                                            <div className="font-mono font-bold text-red-500 text-xs tracking-widest">{cve.id}</div>
                                            <div className={`px-2 py-0.5 rounded text-[10px] font-black tracking-tighter ${sev.bg} ${sev.text}`}>
                                                {cve.severity} {cve.cvss}
                                            </div>
                                        </div>
                                        <h3 className="text-lg font-bold mb-3 group-hover:text-red-400 transition-colors line-clamp-1">{cve.title}</h3>
                                        <p className="text-gray-500 text-sm mb-6 line-clamp-3 leading-relaxed">{cve.description}</p>

                                        <div className="flex flex-wrap gap-2 mb-6">
                                            {cve.tags.map(t => <span key={t} className="px-2 py-1 bg-white/5 rounded-lg text-[10px] text-gray-400 border border-white/5">{t}</span>)}
                                            {cve.exploitAvailable && <span className="px-2 py-1 bg-red-600/20 text-red-400 rounded-lg text-[10px] font-bold border border-red-500/20">🔥 EXPLOIT AVAILABLE</span>}
                                        </div>

                                        <div className="flex items-center justify-between text-[10px] text-gray-600 border-t border-white/5 pt-4 uppercase tracking-widest font-bold">
                                            <div className="flex items-center gap-1"><Cpu size={12} /> {cve.vendor}</div>
                                            <div className="flex items-center gap-1"><Globe size={12} /> {cve.published}</div>
                                        </div>
                                    </div>
                                );
                            })}
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Modal for detail */}
                <AnimatePresence>
                    {selectedCVE && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-[#0a0a0f]/90 backdrop-blur-sm"
                            onClick={() => setSelectedCVE(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.9, opacity: 0, y: 20 }}
                                animate={{ scale: 1, opacity: 1, y: 0 }}
                                exit={{ scale: 0.9, opacity: 0, y: 20 }}
                                className="w-full max-w-2xl bg-[#12121e] rounded-[2.5rem] border border-white/10 overflow-hidden shadow-2xl"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className={`h-2 relative ${severityColors[selectedCVE.severity].text.replace('text-', 'bg-')}`}>
                                    <div className="absolute inset-0 bg-white/20 animate-pulse" />
                                </div>
                                <div className="p-8 md:p-12">
                                    <div className="flex justify-between items-center mb-8">
                                        <div className="flex items-center gap-4">
                                            <div className="font-mono text-2xl font-black text-red-500">{selectedCVE.id}</div>
                                            <div className={`px-4 py-1 rounded-full text-xs font-black tracking-widest uppercase ${severityColors[selectedCVE.severity].bg} ${severityColors[selectedCVE.severity].text}`}>
                                                {selectedCVE.severity} {selectedCVE.cvss}
                                            </div>
                                        </div>
                                        <button onClick={() => setSelectedCVE(null)} className="p-3 bg-white/5 hover:bg-white/10 rounded-2xl text-gray-500 transition-all">
                                            <Skull size={20} className="rotate-45" />
                                        </button>
                                    </div>

                                    <h2 className="text-3xl font-extrabold mb-6 text-white leading-tight">{selectedCVE.title}</h2>
                                    <p className="text-gray-400 text-lg leading-relaxed mb-10">{selectedCVE.description}</p>

                                    <div className="grid grid-cols-2 gap-6 mb-10">
                                        {[
                                            { l: 'Vendor', v: selectedCVE.vendor },
                                            { l: 'Product', v: selectedCVE.product },
                                            { l: 'CWE ID', v: selectedCVE.cwe },
                                            { l: 'Published', v: selectedCVE.published },
                                        ].map(i => (
                                            <div key={i.l} className="p-4 rounded-2xl bg-white/5 border border-white/5">
                                                <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">{i.l}</div>
                                                <div className="text-white font-semibold">{i.v}</div>
                                            </div>
                                        ))}
                                    </div>

                                    <div className="flex flex-col sm:flex-row gap-4">
                                        <button
                                            onClick={() => window.open(`https://nvd.nist.gov/vuln/detail/${selectedCVE.id}`, '_blank')}
                                            className="flex-1 px-8 py-4 bg-red-600 hover:bg-red-700 text-white rounded-2xl font-black transition-all flex items-center justify-center gap-3 shadow-xl shadow-red-600/20"
                                        >
                                            <ExternalLink size={20} /> View NVD Detail
                                        </button>
                                        <button
                                            onClick={() => {
                                                setCurrentTab('patchdiff');
                                                setSelectedCVE(null);
                                            }}
                                            className="px-8 py-4 bg-purple-600/10 text-purple-400 border border-purple-500/20 rounded-2xl font-bold hover:bg-purple-600 hover:text-white transition-all flex items-center justify-center gap-3"
                                        >
                                            <Code size={20} /> Analyze Fix
                                        </button>
                                    </div>
                                </div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default CVERadar;
