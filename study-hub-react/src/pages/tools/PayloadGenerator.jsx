import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Bomb, Code, Hash, Fingerprint,
    Terminal, Shield, Zap, Search,
    Copy, Check, Info, AlertTriangle,
    FileCode, Database, Globe, RefreshCcw,
    Sparkles, Lock, Cpu
} from 'lucide-react';
import { useAppContext } from '../../context/AppContext';

const PayloadGenerator = () => {
    const { apiUrl } = useAppContext();
    const [activeCategory, setActiveCategory] = useState(null);
    const [payloads, setPayloads] = useState({});
    const [loading, setLoading] = useState(true);
    const [selectedPayload, setSelectedPayload] = useState(null);
    const [output, setOutput] = useState('');
    const [copied, setCopied] = useState(false);
    const [isMutating, setIsMutating] = useState(false);
    const [mutationTechnique, setMutationTechnique] = useState('obfuscation');

    // Configuration for placeholders
    const [config, setConfig] = useState({
        ATTACKER: '10.10.10.10',
        PORT: '4444',
        CMD: 'id',
        FILE: '/etc/passwd'
    });

    useEffect(() => {
        fetchPayloads();
    }, []);

    const fetchPayloads = async () => {
        try {
            const res = await fetch(`${apiUrl}/payloads`);
            const data = await res.json();
            if (data.success) {
                setPayloads(data.payloads);
                // Set first category as active by default
                const categories = Object.keys(data.payloads);
                if (categories.length > 0) setActiveCategory(categories[0]);
            }
        } catch (error) {
            console.error("Failed to fetch payloads:", error);
        } finally {
            setLoading(false);
        }
    };

    // Update output when selection or config changes
    useEffect(() => {
        if (selectedPayload) {
            let processed = selectedPayload.template;
            processed = processed.replace(/{ATTACKER}/g, config.ATTACKER);
            processed = processed.replace(/{PORT}/g, config.PORT);
            processed = processed.replace(/{CMD}/g, config.CMD);
            processed = processed.replace(/{FILE}/g, config.FILE);
            setOutput(processed);
        }
    }, [selectedPayload, config]);

    const handleCopy = () => {
        navigator.clipboard.writeText(output);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleMutate = async () => {
        if (!output) return;
        setIsMutating(true);
        try {
            const res = await fetch(`${apiUrl}/mutate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    payload: output,
                    technique: mutationTechnique
                })
            });
            const data = await res.json();
            if (data.success && data.result) {
                setOutput(data.result.mutation);
            }
        } catch (error) {
            console.error("Mutation failed:", error);
        } finally {
            setIsMutating(false);
        }
    };

    const categoryIcons = {
        xss: <Globe size={18} />,
        sqli: <Database size={18} />,
        rce: <Terminal size={18} />,
        lfi: <FileCode size={18} />,
        ssti: <Code size={18} />
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-['Outfit']">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="relative mb-8 p-8 rounded-3xl bg-[#12121e] border border-red-500/20 overflow-hidden">
                    <div className="absolute top-0 right-0 w-96 h-96 bg-red-500/5 blur-[100px] rounded-full -mr-20 -mt-20" />
                    <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="p-3 bg-red-500/10 rounded-xl text-red-500 border border-red-500/20">
                                    <Bomb size={32} />
                                </div>
                                <h1 className="text-4xl font-bold text-white tracking-tight">
                                    Payload Generator <span className="text-red-500">Pro</span>
                                </h1>
                            </div>
                            <p className="text-gray-400 text-lg max-w-2xl">
                                Advanced weaponization suite with AI-driven WAF evasion and massive payload library.
                            </p>
                        </div>
                        <div className="flex items-center gap-4">
                            <div className="px-4 py-2 bg-black/40 rounded-lg border border-white/10 flex items-center gap-2">
                                <Sparkles size={16} className="text-purple-400" />
                                <span className="text-sm font-mono text-gray-300">AI Engine: <span className="text-green-400">ONLINE</span></span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    {/* Sidebar / Categories */}
                    <div className="lg:col-span-3 space-y-4">
                        <div className="bg-[#12121e] rounded-2xl border border-white/5 p-4">
                            <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4 px-2">Vulnerability Type</h3>
                            <div className="space-y-1">
                                {loading ? (
                                    <div className="animate-pulse space-y-2">
                                        {[1, 2, 3, 4, 5].map(i => <div key={i} className="h-10 bg-white/5 rounded-lg" />)}
                                    </div>
                                ) : (
                                    Object.keys(payloads).map(cat => (
                                        <button
                                            key={cat}
                                            onClick={() => setActiveCategory(cat)}
                                            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all font-medium ${activeCategory === cat
                                                ? 'bg-red-600 text-white shadow-lg shadow-red-600/20'
                                                : 'text-gray-400 hover:bg-white/5 hover:text-white'
                                                }`}
                                        >
                                            {categoryIcons[cat] || <Zap size={18} />}
                                            <span className="uppercase tracking-wide text-sm">{cat}</span>
                                            <span className="ml-auto text-xs opacity-50 bg-black/20 px-2 py-0.5 rounded-full">
                                                {payloads[cat]?.length || 0}
                                            </span>
                                        </button>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Configuration Panel */}
                        <div className="bg-[#12121e] rounded-2xl border border-white/5 p-5 space-y-4">
                            <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest flex items-center gap-2">
                                <Cpu size={14} /> Configuration
                            </h3>

                            <div className="space-y-3">
                                <div>
                                    <label className="text-xs text-gray-500 font-mono mb-1 block">LHOST (Attacker)</label>
                                    <input
                                        type="text"
                                        value={config.ATTACKER}
                                        onChange={e => setConfig({ ...config, ATTACKER: e.target.value })}
                                        className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-3 py-2 text-sm text-green-400 font-mono focus:border-red-500/50 outline-none transition-colors"
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500 font-mono mb-1 block">LPORT</label>
                                    <input
                                        type="text"
                                        value={config.PORT}
                                        onChange={e => setConfig({ ...config, PORT: e.target.value })}
                                        className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-3 py-2 text-sm text-green-400 font-mono focus:border-red-500/50 outline-none transition-colors"
                                    />
                                </div>
                                {(activeCategory === 'rce' || activeCategory === 'cmd') && (
                                    <div>
                                        <label className="text-xs text-gray-500 font-mono mb-1 block">Command</label>
                                        <input
                                            type="text"
                                            value={config.CMD}
                                            onChange={e => setConfig({ ...config, CMD: e.target.value })}
                                            className="w-full bg-[#0a0a0f] border border-white/10 rounded-lg px-3 py-2 text-sm text-yellow-400 font-mono focus:border-red-500/50 outline-none transition-colors"
                                        />
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Main Content */}
                    <div className="lg:col-span-9 space-y-6">
                        {/* Payload Selector Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {activeCategory && payloads[activeCategory]?.map((p, i) => (
                                <button
                                    key={i}
                                    onClick={() => setSelectedPayload(p)}
                                    className={`text-left p-4 rounded-xl border transition-all relative group overflow-hidden ${selectedPayload === p
                                        ? 'bg-red-500/10 border-red-500/50 ring-1 ring-red-500/50'
                                        : 'bg-[#12121e] border-white/5 hover:border-white/20'
                                        }`}
                                >
                                    <div className="flex justify-between items-start mb-2">
                                        <span className="font-bold text-sm text-gray-200">{p.name}</span>
                                        {p.risk === 'Critical' && <AlertTriangle size={14} className="text-red-500" />}
                                    </div>
                                    <code className="text-xs text-gray-500 font-mono line-clamp-2 bg-black/30 p-1.5 rounded block">
                                        {p.template}
                                    </code>
                                    <div className={`absolute bottom-0 left-0 h-1 bg-red-500 transition-all duration-300 ${selectedPayload === p ? 'w-full' : 'w-0'}`} />
                                </button>
                            ))}
                        </div>

                        {/* Editor & Actions */}
                        <div className="bg-[#12121e] rounded-2xl border border-white/5 p-1">
                            {/* Toolbar */}
                            <div className="flex flex-wrap items-center justify-between gap-4 p-4 border-b border-white/5 bg-black/20 rounded-t-xl">
                                <div className="flex items-center gap-3">
                                    <Terminal size={18} className="text-gray-400" />
                                    <span className="text-sm font-bold text-gray-300">Payload Editor</span>
                                </div>
                                <div className="flex items-center gap-3">
                                    <select
                                        value={mutationTechnique}
                                        onChange={(e) => setMutationTechnique(e.target.value)}
                                        className="bg-[#0a0a0f] text-gray-400 text-xs py-1.5 px-3 rounded-lg border border-white/10 outline-none"
                                    >
                                        <option value="obfuscation">General Obfuscation</option>
                                        <option value="encoding">Encoding (URL/Hex)</option>
                                        <option value="polymorphic">Polymorphic</option>
                                        <option value="waf-bypass">WAF Bypass</option>
                                    </select>

                                    <button
                                        onClick={handleMutate}
                                        disabled={isMutating || !output}
                                        className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border transition-all ${isMutating
                                            ? 'bg-purple-900/20 text-purple-400 border-purple-500/20 cursor-wait'
                                            : 'bg-purple-600/10 text-purple-400 border-purple-500/30 hover:bg-purple-600 hover:text-white'
                                            }`}
                                    >
                                        {isMutating ? <RefreshCcw size={14} className="animate-spin" /> : <Sparkles size={14} />}
                                        {isMutating ? 'Thinking...' : 'AI Mutate'}
                                    </button>

                                    <button
                                        onClick={handleCopy}
                                        className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border transition-all ${copied
                                            ? 'bg-green-600/10 text-green-400 border-green-500/30'
                                            : 'bg-white/5 text-gray-300 border-white/10 hover:bg-white/10'
                                            }`}
                                    >
                                        {copied ? <Check size={14} /> : <Copy size={14} />}
                                        {copied ? 'Copied' : 'Copy'}
                                    </button>
                                </div>
                            </div>

                            {/* Editor Area */}
                            <div className="relative">
                                <textarea
                                    value={output}
                                    onChange={(e) => setOutput(e.target.value)}
                                    className="w-full h-64 bg-[#0a0a0f] text-red-400 font-mono text-sm p-6 resize-none focus:outline-none rounded-b-xl"
                                    spellCheck="false"
                                    placeholder="// Select a payload to begin..."
                                />
                                {activeCategory === 'rce' && config.ATTACKER === '10.10.10.10' && (
                                    <div className="absolute bottom-4 right-4 text-[10px] text-yellow-500/50 font-mono border border-yellow-500/20 px-2 py-1 rounded bg-yellow-500/5">
                                        ⚠ WARNING: Using default LHOST
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PayloadGenerator;
