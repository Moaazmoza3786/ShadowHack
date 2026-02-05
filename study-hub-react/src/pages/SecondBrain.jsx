import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Brain, Search, Code, Book,
    Flag, Terminal, Copy, ExternalLink,
    Hash, Tag, ChevronRight, Layers,
    Zap, AlertCircle, LayoutDashboard,
    Quote, Wand2, Info, CheckCircle2,
    Database, ShieldCheck, Cpu, Play,
    X, ArrowRight, Shield, Bug, Target,
    Settings, TrendingUp, AlertTriangle
} from 'lucide-react';
import SecondBrainData from '../data/second-brain-data';

const SecondBrain = () => {
    const { snippets: secondBrainSnippets, wiki: secondBrainWiki, playbooks: secondBrainPlaybooks } = SecondBrainData || { snippets: [], wiki: [], playbooks: [] };
    const [activeTab, setActiveTab] = useState('wiki'); // dashboard, wiki, snippets, playbooks
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedLanguage, setSelectedLanguage] = useState('All');
    const [viewingWikiItem, setViewingWikiItem] = useState(null);
    const [modalType, setModalType] = useState(null); // 'deepDive' or 'payloads'
    const [copiedId, setCopiedId] = useState(null);
    const [customizingPayload, setCustomizingPayload] = useState(null); // { payload: string, index: number }
    const [builderConfig, setBuilderConfig] = useState({});

    // Get unique languages for snippets
    const languages = ['All', ...new Set(secondBrainSnippets.map(s => s.lang))];

    const filteredSnippets = secondBrainSnippets.filter(s => {
        const matchesQuery = s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
            s.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
        const matchesLang = selectedLanguage === 'All' || s.lang === selectedLanguage;
        return matchesQuery && matchesLang;
    });

    const filteredWiki = secondBrainWiki.filter(w =>
        w.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        w.category.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const filteredPlaybooks = secondBrainPlaybooks.filter(pb =>
        pb.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        pb.description.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const copyToClipboard = (text, id) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    // Extract variables from payload template
    const extractVariables = (payload) => {
        const regex = /\[\[(\w+)\]\]/g;
        const matches = [...payload.matchAll(regex)];
        return [...new Set(matches.map(m => m[1]))];
    };

    // Build payload from template and config
    const buildPayload = (template, config) => {
        let built = template;
        Object.keys(config).forEach(key => {
            const regex = new RegExp(`\\[\\[${key}\\]\\]`, 'g');
            built = built.replace(regex, config[key] || `[[${key}]]`);
        });
        return built;
    };

    // Payload Builder Modal - ENHANCED PROFESSIONAL VERSION
    const PayloadBuilderModal = ({ payload, item, onClose }) => {
        const variables = extractVariables(payload);
        const [values, setValues] = useState({});
        const [builtPayload, setBuiltPayload] = useState(payload);
        const [activeEncodingTab, setActiveEncodingTab] = useState('raw');
        const [encodedPayloads, setEncodedPayloads] = useState({});
        const [selectedPreset, setSelectedPreset] = useState(null);
        const [obfuscationOptions, setObfuscationOptions] = useState({
            caseRandomization: false,
            commentInjection: false,
            nullByteInsertion: false,
            doubleEncoding: false
        });
        const [copyHistory, setCopyHistory] = useState([]);

        // Presets based on vulnerability type
        const getPresets = () => {
            const presets = {
                'wiki-1': [ // SQLi
                    { name: 'Basic Auth Bypass', values: { USER: 'admin', TABLE: 'users', COL1: 'username', COL2: 'password' } },
                    { name: 'MSSQL RCE', values: { CMD: 'whoami', OOB_DNS: 'attacker.com' } },
                    { name: 'Data Exfiltration', values: { TABLE: 'customers', COL1: 'email', COL2: 'credit_card' } }
                ],
                'wiki-2': [ // XSS
                    { name: 'Cookie Stealer', values: { MSG: 'XSS', HOOK_URL: 'https://hookb.in/xxxxx' } },
                    { name: 'Keylogger', values: { MSG: 'Logged', HOOK_URL: 'https://c2.attacker.com/log' } },
                    { name: 'Redirect Attack', values: { URL: 'https://evil.com/phish', MSG: 'Redirected' } }
                ],
                'wiki-3': [ // SSRF
                    { name: 'AWS Metadata', values: { IP: '169.254.169.254', PATH: 'latest/meta-data', PORT: '80' } },
                    { name: 'Internal Admin Panel', values: { IP: '127.0.0.1', PATH: 'admin', PORT: '8080' } },
                    { name: 'Redis Exploit', values: { IP: '127.0.0.1', PORT: '6379', PASS: 'redis123' } }
                ],
                'wiki-4': [ // RCE
                    { name: 'Linux Reverse Shell', values: { LHOST: '10.10.10.10', LPORT: '4444', CMD: 'whoami', FILE: '/etc/passwd' } },
                    { name: 'Windows Reverse Shell', values: { LHOST: '192.168.1.100', LPORT: '443', CMD: 'whoami' } },
                    { name: 'Web Shell Upload', values: { CMD: 'ls -la', FILE: '/var/www/html' } }
                ]
            };
            return presets[item.id] || [];
        };

        // Encoding functions
        const encodePayload = (text, type) => {
            switch (type) {
                case 'base64':
                    return btoa(text);
                case 'url':
                    return encodeURIComponent(text);
                case 'hex':
                    return text.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                case 'double-url':
                    return encodeURIComponent(encodeURIComponent(text));
                case 'html':
                    return text.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
                case 'unicode':
                    return text.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
                default:
                    return text;
            }
        };

        // Apply obfuscation
        const obfuscatePayload = (text) => {
            let result = text;

            if (obfuscationOptions.caseRandomization) {
                result = result.split('').map(c =>
                    Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()
                ).join('');
            }

            if (obfuscationOptions.commentInjection && item.id === 'wiki-1') {
                result = result.replace(/SELECT/gi, 'SEL/**/ECT').replace(/UNION/gi, 'UNI/**/ON');
            }

            if (obfuscationOptions.nullByteInsertion) {
                result = result.split('').join('%00');
            }

            return result;
        };

        useEffect(() => {
            // Initialize with defaults from builderConfig
            const defaults = {};
            if (item.builderConfig) {
                item.builderConfig.forEach(cfg => {
                    defaults[cfg.id] = cfg.placeholder || '';
                });
            }
            setValues(defaults);
        }, []);

        useEffect(() => {
            let built = buildPayload(payload, values);
            built = obfuscatePayload(built);
            setBuiltPayload(built);

            // Generate encoded versions
            const encoded = {
                raw: built,
                base64: encodePayload(built, 'base64'),
                url: encodePayload(built, 'url'),
                hex: encodePayload(built, 'hex'),
                'double-url': encodePayload(built, 'double-url'),
                html: encodePayload(built, 'html'),
                unicode: encodePayload(built, 'unicode')
            };
            setEncodedPayloads(encoded);
        }, [values, payload, obfuscationOptions]);

        const handleChange = (varName, value) => {
            setValues(prev => ({ ...prev, [varName]: value }));
        };

        const applyPreset = (preset) => {
            setValues(preset.values);
            setSelectedPreset(preset.name);
        };

        const handleCopy = (text, format) => {
            copyToClipboard(text, `builder-${format}`);
            setCopyHistory(prev => [{
                payload: text,
                format,
                timestamp: new Date().toLocaleTimeString()
            }, ...prev.slice(0, 4)]);
        };

        const exportAsFile = () => {
            const blob = new Blob([encodedPayloads[activeEncodingTab]], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${item.title.replace(/\s+/g, '_')}_payload_${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        };

        const getLabel = (varName) => {
            if (item.builderConfig) {
                const config = item.builderConfig.find(c => c.id === varName);
                if (config) return config.label;
            }
            return varName.replace(/_/g, ' ');
        };

        const getPlaceholder = (varName) => {
            if (item.builderConfig) {
                const config = item.builderConfig.find(c => c.id === varName);
                if (config) return config.placeholder;
            }
            return '';
        };

        return (
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-[200] flex items-center justify-center p-4 md:p-8"
            >
                <div
                    className="absolute inset-0 bg-black/95 backdrop-blur-2xl"
                    onClick={onClose}
                />

                <motion.div
                    initial={{ scale: 0.95, y: 20, opacity: 0 }}
                    animate={{ scale: 1, y: 0, opacity: 1 }}
                    exit={{ scale: 0.95, y: 20, opacity: 0 }}
                    className="relative w-full max-w-7xl max-h-[95vh] bg-[#0F0F17] border border-accent-500/30 rounded-[3rem] overflow-hidden flex flex-col shadow-[0_0_100px_rgba(239,68,68,0.3)]"
                >
                    {/* Header */}
                    <div className="p-8 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-accent-500/10 to-transparent">
                        <div className="flex items-center gap-6">
                            <div className="relative w-16 h-16 rounded-2xl bg-accent-500/20 flex items-center justify-center shadow-lg text-accent-500">
                                <Settings size={32} className="animate-pulse" />
                                <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-green-500 animate-pulse" />
                            </div>
                            <div>
                                <span className="text-[10px] font-black text-accent-500/60 uppercase tracking-widest block mb-1">
                                    Professional Builder v2.5 • Enterprise Edition
                                </span>
                                <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">
                                    Advanced Payload Arsenal
                                </h2>
                                <div className="flex items-center gap-3 mt-2">
                                    <span className="px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest bg-accent-500/10 text-accent-500">
                                        {item.title}
                                    </span>
                                    {selectedPreset && (
                                        <span className="px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest bg-primary-500/10 text-primary-500">
                                            Preset: {selectedPreset}
                                        </span>
                                    )}
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-3 rounded-full hover:bg-white/5 text-gray-500 hover:text-white transition-all"
                        >
                            <X size={24} />
                        </button>
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto scrollbar-cyber">
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 p-10">
                            {/* Left Column: Configuration */}
                            <div className="lg:col-span-2 space-y-8">
                                {/* Quick Presets */}
                                {getPresets().length > 0 && (
                                    <section>
                                        <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                            <Zap size={14} /> Quick Presets
                                        </h4>
                                        <div className="flex flex-wrap gap-3">
                                            {getPresets().map((preset, idx) => (
                                                <button
                                                    key={idx}
                                                    onClick={() => applyPreset(preset)}
                                                    className={`px-5 py-3 rounded-xl font-bold text-xs uppercase tracking-widest transition-all ${selectedPreset === preset.name
                                                        ? 'bg-primary-500 text-white shadow-lg'
                                                        : 'bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white border border-white/10'
                                                        }`}
                                                >
                                                    {preset.name}
                                                </button>
                                            ))}
                                        </div>
                                    </section>
                                )}

                                {/* Variable Configuration */}
                                <section>
                                    <h4 className="text-[10px] font-black text-accent-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                        <Target size={14} /> Variable Configuration
                                    </h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        {variables.map(varName => (
                                            <div key={varName} className="space-y-2">
                                                <label className="text-xs font-bold text-gray-400 uppercase tracking-widest flex items-center gap-2">
                                                    <Hash size={12} className="text-accent-500" />
                                                    {getLabel(varName)}
                                                </label>
                                                <input
                                                    type="text"
                                                    value={values[varName] || ''}
                                                    onChange={(e) => handleChange(varName, e.target.value)}
                                                    placeholder={getPlaceholder(varName)}
                                                    className="w-full bg-black/40 border border-white/10 rounded-xl py-3 px-4 text-white focus:outline-none focus:border-accent-500/50 transition-all font-mono text-sm"
                                                />
                                            </div>
                                        ))}
                                    </div>
                                </section>

                                {/* Obfuscation & WAF Bypass */}
                                <section className="p-6 rounded-2xl bg-red-500/5 border border-red-500/10">
                                    <h4 className="text-[10px] font-black text-red-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                        <Shield size={14} /> WAF Bypass Techniques
                                    </h4>
                                    <div className="grid grid-cols-2 gap-4">
                                        {Object.entries({
                                            caseRandomization: 'Case Randomization',
                                            commentInjection: 'Comment Injection',
                                            nullByteInsertion: 'Null Byte Insertion',
                                            doubleEncoding: 'Double Encoding'
                                        }).map(([key, label]) => (
                                            <label key={key} className="flex items-center gap-3 cursor-pointer group">
                                                <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${obfuscationOptions[key]
                                                    ? 'bg-red-500 border-red-500'
                                                    : 'border-white/20 group-hover:border-red-500/50'
                                                    }`}>
                                                    {obfuscationOptions[key] && <CheckCircle2 size={12} className="text-white" />}
                                                </div>
                                                <input
                                                    type="checkbox"
                                                    checked={obfuscationOptions[key]}
                                                    onChange={(e) => setObfuscationOptions(prev => ({
                                                        ...prev,
                                                        [key]: e.target.checked
                                                    }))}
                                                    className="hidden"
                                                />
                                                <span className="text-xs font-bold text-gray-400 group-hover:text-white transition-colors">
                                                    {label}
                                                </span>
                                            </label>
                                        ))}
                                    </div>
                                </section>
                            </div>

                            {/* Right Column: Preview & Export */}
                            <div className="space-y-8">
                                {/* Encoding Tabs */}
                                <section>
                                    <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                        <TrendingUp size={14} /> Export Format
                                    </h4>
                                    <div className="grid grid-cols-2 gap-2 mb-4">
                                        {['raw', 'base64', 'url', 'hex', 'double-url', 'html', 'unicode'].map(format => (
                                            <button
                                                key={format}
                                                onClick={() => setActiveEncodingTab(format)}
                                                className={`px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${activeEncodingTab === format
                                                    ? 'bg-primary-500 text-white'
                                                    : 'bg-white/5 text-gray-500 hover:bg-white/10'
                                                    }`}
                                            >
                                                {format}
                                            </button>
                                        ))}
                                    </div>

                                    {/* Preview Box */}
                                    <div className="relative group">
                                        <div className="absolute top-4 right-4 z-10 flex gap-2">
                                            <button
                                                onClick={() => handleCopy(encodedPayloads[activeEncodingTab], activeEncodingTab)}
                                                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-primary-500 text-white text-[10px] font-black uppercase tracking-widest hover:scale-105 transition-all shadow-lg"
                                            >
                                                {copiedId === `builder-${activeEncodingTab}` ? <CheckCircle2 size={12} /> : <Copy size={12} />}
                                                {copiedId === `builder-${activeEncodingTab}` ? 'COPIED' : 'COPY'}
                                            </button>
                                            <button
                                                onClick={exportAsFile}
                                                className="p-2 rounded-xl bg-accent-500/10 text-accent-500 hover:bg-accent-500 hover:text-white transition-all"
                                                title="Export as file"
                                            >
                                                <ArrowRight size={16} />
                                            </button>
                                        </div>
                                        <pre className="p-8 pt-16 rounded-2xl bg-black/60 border border-primary-500/20 font-mono text-xs text-primary-400 overflow-x-auto select-all whitespace-pre-wrap break-all min-h-[200px] max-h-[300px]">
                                            {encodedPayloads[activeEncodingTab] || builtPayload}
                                        </pre>
                                        <div className="absolute bottom-4 right-4 text-[8px] font-mono text-gray-600 uppercase">
                                            {(encodedPayloads[activeEncodingTab] || builtPayload).length} chars
                                        </div>
                                    </div>
                                </section>

                                {/* Copy History */}
                                {copyHistory.length > 0 && (
                                    <section>
                                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                            <Database size={14} /> Recent Copies
                                        </h4>
                                        <div className="space-y-2">
                                            {copyHistory.map((item, idx) => (
                                                <div key={idx} className="p-3 rounded-xl bg-white/[0.02] border border-white/5 flex items-center justify-between">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-2 h-2 rounded-full bg-green-500" />
                                                        <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                                                            {item.format}
                                                        </span>
                                                    </div>
                                                    <span className="text-[9px] font-mono text-gray-600">
                                                        {item.timestamp}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </section>
                                )}

                                {/* Pro Tips */}
                                <section className="p-6 rounded-2xl bg-accent-500/5 border border-accent-500/10">
                                    <div className="flex items-center gap-3 text-accent-500 mb-3">
                                        <Zap size={18} />
                                        <span className="text-xs font-black uppercase tracking-widest">Pro Tips</span>
                                    </div>
                                    <ul className="space-y-2 text-xs text-gray-400">
                                        <li className="flex items-start gap-2">
                                            <ChevronRight size={14} className="text-accent-500 mt-0.5 shrink-0" />
                                            <span>Use <strong>Base64</strong> for basic obfuscation</span>
                                        </li>
                                        <li className="flex items-start gap-2">
                                            <ChevronRight size={14} className="text-accent-500 mt-0.5 shrink-0" />
                                            <span>Try <strong>Double URL</strong> encoding to bypass filters</span>
                                        </li>
                                        <li className="flex items-start gap-2">
                                            <ChevronRight size={14} className="text-accent-500 mt-0.5 shrink-0" />
                                            <span>Enable <strong>Comment Injection</strong> for SQL WAF bypass</span>
                                        </li>
                                        <li className="flex items-start gap-2">
                                            <ChevronRight size={14} className="text-accent-500 mt-0.5 shrink-0" />
                                            <span>Test in controlled environments first</span>
                                        </li>
                                    </ul>
                                </section>
                            </div>
                        </div>
                    </div>

                    {/* Footer */}
                    <div className="p-8 border-t border-white/5 bg-white/[0.01] flex items-center justify-between">
                        <div className="flex items-center gap-6">
                            <div className="flex items-center gap-2 text-[10px] font-black text-gray-600 uppercase tracking-widest">
                                <Shield size={12} /> Payload Builder v2.5 Enterprise
                            </div>
                            <div className="flex items-center gap-2 text-[10px] font-mono text-gray-700">
                                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                {Object.keys(encodedPayloads).length} formats ready
                            </div>
                        </div>
                        <div className="flex items-center gap-4">
                            <button
                                onClick={() => {
                                    setValues({});
                                    setSelectedPreset(null);
                                    setObfuscationOptions({
                                        caseRandomization: false,
                                        commentInjection: false,
                                        nullByteInsertion: false,
                                        doubleEncoding: false
                                    });
                                }}
                                className="px-6 py-3 rounded-xl bg-white/5 border border-white/10 text-[10px] font-black text-gray-400 uppercase tracking-widest hover:bg-white/10 hover:text-white transition-all"
                            >
                                Reset All
                            </button>
                            <button
                                onClick={onClose}
                                className="px-8 py-3 rounded-xl bg-primary-500 text-white text-[10px] font-black uppercase tracking-widest hover:scale-105 transition-all shadow-lg"
                            >
                                Done
                            </button>
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        );
    };

    const WikiModal = ({ item, type, onClose }) => {
        if (!item) return null;

        return (
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-8"
            >
                {/* Backdrop */}
                <div
                    className="absolute inset-0 bg-black/90 backdrop-blur-xl"
                    onClick={onClose}
                />

                {/* Modal Content */}
                <motion.div
                    initial={{ scale: 0.9, y: 20, opacity: 0 }}
                    animate={{ scale: 1, y: 0, opacity: 1 }}
                    exit={{ scale: 0.9, y: 20, opacity: 0 }}
                    className="relative w-full max-w-5xl max-h-[90vh] bg-[#0F0F17] border border-white/10 rounded-[3rem] overflow-hidden flex flex-col shadow-[0_0_100px_rgba(0,0,0,0.5)]"
                >
                    {/* Header */}
                    <div className="p-8 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                        <div className="flex items-center gap-6">
                            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center shadow-lg ${type === 'deepDive' ? 'bg-primary-500/20 text-primary-500' : 'bg-accent-500/20 text-accent-500'}`}>
                                {type === 'deepDive' ? <ShieldCheck size={32} /> : <Zap size={32} />}
                            </div>
                            <div>
                                <div className="flex items-center gap-3 mb-1">
                                    <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">{item.category}</span>
                                    <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest ${item.severity === 'Critical' ? 'bg-red-500/10 text-red-500' : 'bg-orange-500/10 text-orange-500'}`}>
                                        {item.severity}
                                    </span>
                                </div>
                                <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">
                                    {type === 'deepDive' ? `Deep Dive: ${item.title}` : `Payload Generator: ${item.title}`}
                                </h2>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-3 rounded-full hover:bg-white/5 text-gray-500 hover:text-white transition-all"
                        >
                            <X size={24} />
                        </button>
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto p-10 scrollbar-cyber">
                        {type === 'deepDive' ? (
                            <div className="space-y-10">
                                {/* Intelligence Header with Metrics */}
                                <div className="grid grid-cols-4 gap-4 p-6 rounded-2xl bg-gradient-to-r from-primary-500/10 via-accent-500/5 to-primary-500/10 border border-white/10">
                                    {item.cvss && (
                                        <div className="text-center">
                                            <div className="text-3xl font-black text-red-500 mb-1">{item.cvss}</div>
                                            <div className="text-[8px] font-black text-gray-600 uppercase tracking-widest">CVSS Score</div>
                                        </div>
                                    )}
                                    {item.cwe && (
                                        <div className="text-center">
                                            <div className="text-lg font-black text-primary-500 mb-1">{item.cwe}</div>
                                            <div className="text-[8px] font-black text-gray-600 uppercase tracking-widest">CWE Reference</div>
                                        </div>
                                    )}
                                    {item.owasp && (
                                        <div className="text-center col-span-2">
                                            <div className="text-sm font-black text-accent-500 mb-1">{item.owasp}</div>
                                            <div className="text-[8px] font-black text-gray-600 uppercase tracking-widest">OWASP Top 10</div>
                                        </div>
                                    )}
                                </div>

                                {/* Description */}
                                <section>
                                    <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                        <Info size={14} /> Intelligence Overview
                                    </h4>
                                    <p className="text-gray-300 text-base leading-relaxed border-l-4 border-primary-500/30 pl-6 italic">
                                        {item.description}
                                    </p>
                                </section>

                                {/* Technical Details */}
                                {item.technicalDetails && (
                                    <section className="p-6 rounded-2xl bg-blue-500/5 border border-blue-500/10">
                                        <h4 className="text-[10px] font-black text-blue-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                            <Cpu size={14} /> Technical Mechanism
                                        </h4>
                                        <p className="text-sm text-gray-400 mb-6 leading-relaxed">
                                            {item.technicalDetails.mechanism}
                                        </p>

                                        {item.technicalDetails.commonVulnerablePoints && (
                                            <div>
                                                <h5 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Common Vulnerable Points:</h5>
                                                <div className="grid grid-cols-2 gap-3">
                                                    {item.technicalDetails.commonVulnerablePoints.map((point, i) => (
                                                        <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                            <ChevronRight size={12} className="text-blue-500 mt-0.5 shrink-0" />
                                                            <span>{point}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {item.technicalDetails.databaseSpecific && (
                                            <div className="mt-6 grid grid-cols-2 gap-4">
                                                {Object.entries(item.technicalDetails.databaseSpecific).map(([db, info]) => (
                                                    <div key={db} className="p-4 rounded-xl bg-black/20 border border-white/5">
                                                        <div className="text-[10px] font-black text-blue-400 uppercase tracking-widest mb-2">{db}</div>
                                                        <div className="text-xs text-gray-500">{info}</div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </section>
                                )}

                                {/* Impact Analysis */}
                                {item.impact && (
                                    <section className="p-6 rounded-2xl bg-red-500/5 border border-red-500/10">
                                        <h4 className="text-[10px] font-black text-red-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                            <AlertTriangle size={14} /> Impact Analysis (CIA Triad)
                                        </h4>
                                        <div className="space-y-4">
                                            {item.impact.confidentiality && (
                                                <div>
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <div className="w-2 h-2 rounded-full bg-red-500"></div>
                                                        <span className="text-xs font-black text-red-400 uppercase tracking-widest">Confidentiality</span>
                                                    </div>
                                                    <p className="text-sm text-gray-400 pl-4">{item.impact.confidentiality}</p>
                                                </div>
                                            )}
                                            {item.impact.integrity && (
                                                <div>
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                                                        <span className="text-xs font-black text-orange-400 uppercase tracking-widest">Integrity</span>
                                                    </div>
                                                    <p className="text-sm text-gray-400 pl-4">{item.impact.integrity}</p>
                                                </div>
                                            )}
                                            {item.impact.availability && (
                                                <div>
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
                                                        <span className="text-xs font-black text-yellow-400 uppercase tracking-widest">Availability</span>
                                                    </div>
                                                    <p className="text-sm text-gray-400 pl-4">{item.impact.availability}</p>
                                                </div>
                                            )}
                                            {item.impact.businessImpact && (
                                                <div className="mt-6 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <TrendingUp size={14} className="text-red-500" />
                                                        <span className="text-xs font-black text-red-400 uppercase tracking-widest">Business Impact</span>
                                                    </div>
                                                    <p className="text-sm text-gray-400">{item.impact.businessImpact}</p>
                                                </div>
                                            )}
                                        </div>
                                    </section>
                                )}

                                {/* Exploitation Techniques */}
                                {item.exploitation && (
                                    <section>
                                        <h4 className="text-[10px] font-black text-accent-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                            <Target size={14} /> Exploitation Methodology
                                        </h4>

                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            {item.exploitation.reconnaissance && (
                                                <div className="p-6 rounded-2xl bg-purple-500/5 border border-purple-500/10">
                                                    <h5 className="text-xs font-black text-purple-400 uppercase tracking-widest mb-4">🔍 Reconnaissance</h5>
                                                    <ul className="space-y-2">
                                                        {item.exploitation.reconnaissance.map((step, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <div className="w-1.5 h-1.5 rounded-full bg-purple-500 mt-1.5 shrink-0"></div>
                                                                <span>{step}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            {item.exploitation.techniques && (
                                                <div className="p-6 rounded-2xl bg-accent-500/5 border border-accent-500/10">
                                                    <h5 className="text-xs font-black text-accent-400 uppercase tracking-widest mb-4">⚔️ Core Techniques</h5>
                                                    <ul className="space-y-2">
                                                        {item.exploitation.techniques.map((tech, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <div className="w-1.5 h-1.5 rounded-full bg-accent-500 mt-1.5 shrink-0"></div>
                                                                <span>{tech}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            {item.exploitation.advanced && (
                                                <div className="p-6 rounded-2xl bg-primary-500/5 border border-primary-500/10">
                                                    <h5 className="text-xs font-black text-primary-400 uppercase tracking-widest mb-4">🚀 Advanced</h5>
                                                    <ul className="space-y-2">
                                                        {item.exploitation.advanced.map((adv, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <div className="w-1.5 h-1.5 rounded-full bg-primary-500 mt-1.5 shrink-0"></div>
                                                                <span>{adv}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    </section>
                                )}

                                {/* Attack Vectors & Tools Grid */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    {/* Attack Vectors */}
                                    <section>
                                        <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                            <Target size={14} /> Attack Vectors
                                        </h4>
                                        <div className="space-y-2">
                                            {item.vectors.map((v, i) => (
                                                <div key={i} className="group flex items-center justify-between p-4 rounded-xl bg-white/[0.03] border border-white/5 hover:border-primary-500/30 transition-all">
                                                    <span className="text-sm font-bold text-gray-400 group-hover:text-white">{v}</span>
                                                    <ChevronRight size={14} className="text-primary-500 opacity-0 group-hover:opacity-100 transition-all" />
                                                </div>
                                            ))}
                                        </div>
                                    </section>

                                    {/* Professional Toolset */}
                                    <section>
                                        <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4 flex items-center gap-2">
                                            <Cpu size={14} /> Professional Toolset
                                        </h4>
                                        <div className="flex flex-wrap gap-3">
                                            {item.tools.map((tool, i) => (
                                                <div key={i} className="px-5 py-3 rounded-xl bg-primary-500/5 border border-primary-500/10 text-xs font-black text-primary-500 uppercase tracking-widest">
                                                    {tool}
                                                </div>
                                            ))}
                                        </div>
                                    </section>
                                </div>

                                {/* Remediation Strategies */}
                                {item.remediation && (
                                    <section className="p-6 rounded-2xl bg-green-500/5 border border-green-500/10">
                                        <h4 className="text-[10px] font-black text-green-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                            <Shield size={14} /> Remediation Strategies
                                        </h4>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                                            {item.remediation.immediate && (
                                                <div>
                                                    <h5 className="text-xs font-black text-green-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                                                        <Zap size={12} /> Immediate Actions
                                                    </h5>
                                                    <ul className="space-y-2">
                                                        {item.remediation.immediate.map((action, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <CheckCircle2 size={12} className="text-green-500 mt-0.5 shrink-0" />
                                                                <span>{action}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            {item.remediation.longTerm && (
                                                <div>
                                                    <h5 className="text-xs font-black text-green-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                                                        <TrendingUp size={12} /> Long-term Solutions
                                                    </h5>
                                                    <ul className="space-y-2">
                                                        {item.remediation.longTerm.map((solution, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <CheckCircle2 size={12} className="text-green-500 mt-0.5 shrink-0" />
                                                                <span>{solution}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>

                                        {item.remediation.codeExample && (
                                            <div className="p-4 rounded-xl bg-black/40 border border-green-500/20">
                                                <h5 className="text-[10px] font-black text-green-400 uppercase tracking-widest mb-3">Code Example</h5>
                                                <pre className="text-xs text-gray-400 font-mono overflow-x-auto whitespace-pre-wrap">
                                                    {item.remediation.codeExample}
                                                </pre>
                                            </div>
                                        )}
                                    </section>
                                )}

                                {/* Testing Methodology */}
                                {item.testing && (
                                    <section className="p-6 rounded-2xl bg-cyan-500/5 border border-cyan-500/10">
                                        <h4 className="text-[10px] font-black text-cyan-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                            <Database size={14} /> Testing Methodology
                                        </h4>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            {item.testing.manual && (
                                                <div>
                                                    <h5 className="text-xs font-black text-cyan-400 uppercase tracking-widest mb-3">Manual Testing</h5>
                                                    <ul className="space-y-2">
                                                        {item.testing.manual.map((test, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <Hash size={12} className="text-cyan-500 mt-0.5 shrink-0" />
                                                                <span>{test}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}

                                            {item.testing.automated && (
                                                <div>
                                                    <h5 className="text-xs font-black text-cyan-400 uppercase tracking-widest mb-3">Automated Tools</h5>
                                                    <ul className="space-y-2">
                                                        {item.testing.automated.map((tool, i) => (
                                                            <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                                                                <Cpu size={12} className="text-cyan-500 mt-0.5 shrink-0" />
                                                                <span>{tool}</span>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>

                                        {item.testing.payload && (
                                            <div className="mt-4 p-4 rounded-xl bg-black/40 border border-cyan-500/20">
                                                <div className="flex items-center justify-between mb-2">
                                                    <h5 className="text-[10px] font-black text-cyan-400 uppercase tracking-widest">Quick Test Payload</h5>
                                                    <button
                                                        onClick={() => copyToClipboard(item.testing.payload, 'test-payload')}
                                                        className="px-3 py-1 rounded-lg bg-cyan-500/10 text-cyan-500 text-[9px] font-black uppercase tracking-widest hover:bg-cyan-500 hover:text-white transition-all"
                                                    >
                                                        {copiedId === 'test-payload' ? 'COPIED' : 'COPY'}
                                                    </button>
                                                </div>
                                                <pre className="text-xs text-cyan-400 font-mono select-all">
                                                    {item.testing.payload}
                                                </pre>
                                            </div>
                                        )}
                                    </section>
                                )}

                                {/* Bug Bounty Intel */}
                                <section>
                                    <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                                        <Bug size={14} /> Real-World Intel (Bug Bounty Reports)
                                    </h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        {item.reports.map((report, i) => (
                                            <a
                                                key={i}
                                                href={report.url}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="group p-6 rounded-2xl bg-accent-500/5 border border-accent-500/10 hover:border-accent-500/40 transition-all"
                                            >
                                                <div className="flex justify-between items-start mb-3">
                                                    <h5 className="text-white font-bold group-hover:text-accent-500 transition-colors uppercase text-sm flex-1">{report.title}</h5>
                                                    <ExternalLink size={14} className="text-accent-500 shrink-0 ml-2" />
                                                </div>
                                                <div className="flex items-center justify-between">
                                                    <div className="text-[10px] font-black text-accent-500/60 uppercase tracking-widest">
                                                        Bounty: {report.bounty}
                                                    </div>
                                                    {report.severity && (
                                                        <div className={`px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-widest ${report.severity === 'Critical' ? 'bg-red-500/20 text-red-500' : 'bg-orange-500/20 text-orange-500'
                                                            }`}>
                                                            {report.severity}
                                                        </div>
                                                    )}
                                                </div>
                                            </a>
                                        ))}
                                    </div>
                                </section>
                            </div>
                        ) : (
                            <div className="space-y-8">
                                <div className="p-6 rounded-2xl bg-accent-500/5 border border-accent-500/10 mb-8">
                                    <div className="flex items-center gap-3 text-accent-500 mb-2">
                                        <Zap size={18} />
                                        <span className="text-xs font-black uppercase tracking-widest">Tactical Tip</span>
                                    </div>
                                    <p className="text-sm text-gray-400 italic">
                                        Always ensure the target environment is within scope before executing complex payloads. Use URL encoding (where applicable) to bypass standard WAF filters.
                                    </p>
                                </div>

                                <div className="space-y-4">
                                    {item.payloads.map((p, i) => {
                                        const hasVariables = extractVariables(p).length > 0;
                                        return (
                                            <div key={i} className="group relative bg-black/40 border border-white/5 rounded-2xl p-6 hover:border-accent-500/30 transition-all">
                                                <div className="flex items-center justify-between mb-4">
                                                    <span className="text-[8px] font-black text-gray-600 uppercase tracking-[0.3em]">Attack String #{i + 1}</span>
                                                    <div className="flex items-center gap-3">
                                                        {hasVariables && (
                                                            <button
                                                                onClick={() => setCustomizingPayload({ payload: p, index: i, item })}
                                                                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-500/10 text-accent-500 text-[10px] font-black uppercase tracking-widest hover:bg-accent-500 hover:text-white transition-all shadow-lg"
                                                            >
                                                                <Settings size={12} />
                                                                CUSTOMIZE
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => copyToClipboard(p, `payload-${i}`)}
                                                            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-500/10 text-accent-500 text-[10px] font-black uppercase tracking-widest hover:bg-accent-500 hover:text-white transition-all shadow-lg"
                                                        >
                                                            {copiedId === `payload-${i}` ? <CheckCircle2 size={12} /> : <Copy size={12} />}
                                                            {copiedId === `payload-${i}` ? 'COPIED' : 'COPY'}
                                                        </button>
                                                    </div>
                                                </div>
                                                <pre className="font-mono text-sm text-accent-400 overflow-x-auto select-all whitespace-pre-wrap break-all">
                                                    {p}
                                                </pre>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="p-8 border-t border-white/5 bg-white/[0.01] flex items-center justify-between">
                        <div className="flex items-center gap-2 text-[10px] font-black text-gray-600 uppercase tracking-widest">
                            <Shield size={12} /> ShadowHack Defensive Protocol v3.0 Enabled
                        </div>
                        <button
                            onClick={onClose}
                            className="px-8 py-3 rounded-xl bg-white/5 border border-white/10 text-[10px] font-black text-white uppercase tracking-widest hover:bg-white/10 transition-all"
                        >
                            Return to Arsenal
                        </button>
                    </div>
                </motion.div>
            </motion.div>
        );
    };

    return (
        <div className="min-h-screen bg-[#0A0A0F] text-gray-300">
            {/* Modals */}
            <AnimatePresence>
                {(viewingWikiItem && modalType) && (
                    <WikiModal
                        item={viewingWikiItem}
                        type={modalType}
                        onClose={() => { setViewingWikiItem(null); setModalType(null); }}
                    />
                )}
                {customizingPayload && (
                    <PayloadBuilderModal
                        payload={customizingPayload.payload}
                        item={customizingPayload.item}
                        onClose={() => setCustomizingPayload(null)}
                    />
                )}
            </AnimatePresence>

            {/* --- TOP BAR --- */}
            <header className="sticky top-0 z-50 bg-[#0A0A12]/80 backdrop-blur-xl border-b border-white/5 px-8 py-4">
                <div className="max-w-[1600px] mx-auto flex items-center justify-between gap-8">
                    {/* Logo */}
                    <div className="flex items-center gap-4 shrink-0">
                        <div className="w-12 h-12 rounded-2xl bg-primary-500/20 flex items-center justify-center text-primary-500 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
                            <Brain size={28} />
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h1 className="text-xl font-black text-white italic tracking-tighter uppercase leading-none">
                                    Second Brain
                                </h1>
                                <span className="px-1.5 py-0.5 rounded-md bg-accent-500/20 text-accent-500 text-[8px] font-black uppercase tracking-widest">PRO</span>
                            </div>
                            <div className="mt-1">
                                <span className="text-[10px] text-gray-500 font-mono uppercase tracking-widest">Tactical Knowledge Graph</span>
                            </div>
                        </div>
                    </div>

                    {/* Search / AI Bar */}
                    <div className="flex-1 max-w-2xl relative group">
                        <div className="absolute inset-0 bg-primary-500/5 rounded-2xl blur-lg opacity-0 group-focus-within:opacity-100 transition-opacity" />
                        <div className="relative flex items-center">
                            <Search className="absolute left-5 text-gray-500 group-focus-within:text-primary-500 transition-colors" size={20} />
                            <input
                                type="text"
                                placeholder="Search knowledge or ask AI..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full bg-[#1A1A24] border border-white/5 rounded-2xl py-4 pl-14 pr-4 text-white focus:outline-none focus:border-primary-500/50 transition-all font-medium text-sm"
                            />
                            <div className="absolute right-5 text-[10px] text-gray-600 font-mono uppercase tracking-widest pointer-events-none hidden md:block">
                                Press Enter for AI Search
                            </div>
                        </div>
                    </div>

                    {/* Nav Buttons */}
                    <nav className="flex items-center gap-2 shrink-0">
                        {[
                            { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
                            { id: 'wiki', label: 'Wiki', icon: Database },
                            { id: 'snippets', label: 'Snippets', icon: Terminal },
                            { id: 'playbooks', label: 'Playbooks', icon: Book }
                        ].map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`flex items-center gap-2 px-5 py-3 rounded-xl font-bold text-xs uppercase tracking-widest transition-all ${activeTab === tab.id
                                    ? 'bg-primary-500 text-white shadow-[0_0_30px_rgba(239,68,68,0.25)]'
                                    : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
                                    }`}
                            >
                                <tab.icon size={16} />
                                <span className="hidden xl:inline">{tab.label}</span>
                            </button>
                        ))}
                    </nav>
                </div>
            </header>

            {/* --- MAIN CONTENT --- */}
            <main className="max-w-[1600px] mx-auto p-12">
                <AnimatePresence mode="wait">
                    {activeTab === 'wiki' && (
                        <motion.div
                            key="wiki"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="space-y-12"
                        >
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                                {filteredWiki.map(item => (
                                    <div key={item.id} className="group relative bg-[#13131C] border border-white/5 rounded-[2.5rem] p-8 hover:border-primary-500/30 transition-all duration-500 overflow-hidden">
                                        {/* Status Badge */}
                                        <div className="flex items-center justify-between mb-6">
                                            <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-red-500/10 border border-red-500/20">
                                                <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                                <span className="text-[10px] font-black text-red-500 uppercase tracking-widest">{item.severity}</span>
                                            </div>
                                            <span className="text-xs font-black text-white/20 uppercase tracking-[0.2em]">{item.category}</span>
                                        </div>

                                        {/* Content */}
                                        <div className="space-y-4 mb-8">
                                            <h3 className="text-2xl font-black text-white uppercase italic tracking-tighter group-hover:text-primary-500 transition-colors">
                                                {item.title}
                                            </h3>
                                            <p className="text-gray-500 text-sm leading-relaxed line-clamp-2 italic">
                                                {item.description}
                                            </p>
                                        </div>

                                        {/* Tags */}
                                        <div className="flex flex-wrap gap-2 mb-8">
                                            {item.vectors.map((tag, i) => (
                                                <span key={i} className="px-3 py-1 rounded-lg bg-white/5 border border-white/5 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                                                    {tag}
                                                </span>
                                            ))}
                                        </div>

                                        {/* Actions */}
                                        <div className="grid grid-cols-2 gap-4">
                                            <button
                                                onClick={() => { setViewingWikiItem(item); setModalType('deepDive'); }}
                                                className="flex items-center justify-center gap-2 py-4 rounded-2xl bg-primary-500/10 border border-primary-500/20 text-primary-500 font-black text-[10px] uppercase tracking-widest hover:bg-primary-500 hover:text-white transition-all"
                                            >
                                                <Layers size={14} />
                                                Deep Dive
                                            </button>
                                            <button
                                                onClick={() => { setViewingWikiItem(item); setModalType('payloads'); }}
                                                className="flex items-center justify-center gap-2 py-4 rounded-2xl bg-accent-500/10 border border-accent-500/20 text-accent-500 font-black text-[10px] uppercase tracking-widest hover:bg-accent-500 hover:text-white transition-all"
                                            >
                                                <Zap size={14} />
                                                Payloads
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'snippets' && (
                        <motion.div
                            key="snippets"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="space-y-8"
                        >
                            {/* Filter Chips */}
                            <div className="flex flex-wrap gap-3 pb-4 border-b border-white/5">
                                {languages.map(lang => (
                                    <button
                                        key={lang}
                                        onClick={() => setSelectedLanguage(lang)}
                                        className={`px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${selectedLanguage === lang
                                            ? 'bg-primary-500 text-white shadow-lg'
                                            : 'bg-white/5 text-gray-500 hover:bg-white/10 hover:text-gray-300'
                                            }`}
                                    >
                                        {lang}
                                    </button>
                                ))}
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                                {filteredSnippets.map(snip => (
                                    <div key={snip.id} className="bg-[#13131C] border border-white/5 rounded-[2rem] overflow-hidden group hover:border-primary-500/30 transition-all duration-500">
                                        <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
                                            <div className="flex items-center gap-4">
                                                <div className="w-10 h-10 rounded-xl bg-primary-500/10 border border-primary-500/20 flex items-center justify-center text-primary-500">
                                                    <Code size={20} />
                                                </div>
                                                <div>
                                                    <p className="text-[10px] font-black text-primary-500 uppercase tracking-widest leading-none mb-1">{snip.lang}</p>
                                                    <h3 className="text-lg font-black text-white italic tracking-tighter uppercase">{snip.title}</h3>
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => copyToClipboard(snip.code, snip.id)}
                                                className={`p-2 rounded-lg transition-all ${copiedId === snip.id ? 'text-green-500' : 'text-gray-600 hover:text-primary-500 hover:bg-primary-500/10'}`}
                                            >
                                                {copiedId === snip.id ? <CheckCircle2 size={16} /> : <Copy size={16} />}
                                            </button>
                                        </div>
                                        <div className="p-6 space-y-4">
                                            <div className="relative group/code">
                                                <div className="absolute top-4 right-4 z-10 opacity-0 group-hover/code:opacity-100 transition-opacity">
                                                    <button
                                                        onClick={() => copyToClipboard(snip.code, snip.id)}
                                                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-dark-900 border border-white/10 text-[8px] font-black text-white uppercase tracking-widest hover:border-primary-500/50"
                                                    >
                                                        {copiedId === snip.id ? <CheckCircle2 size={10} /> : <Copy size={10} />}
                                                        {copiedId === snip.id ? 'Copied' : 'Copy'}
                                                    </button>
                                                </div>
                                                <pre className="p-6 rounded-2xl bg-[#09090F] border border-white/5 font-mono text-xs text-primary-400 overflow-x-auto scrollbar-hide max-h-[200px]">
                                                    <code>{snip.code}</code>
                                                </pre>
                                            </div>
                                            <button className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-white/5 border border-white/5 text-[10px] font-black text-gray-500 uppercase tracking-widest hover:bg-white/10 hover:text-white transition-all">
                                                <Wand2 size={14} className="text-primary-500" />
                                                Explain Code
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'playbooks' && (
                        <motion.div
                            key="playbooks"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="space-y-12"
                        >
                            {/* Action Header */}
                            <div className="flex justify-end">
                                <button className="flex items-center gap-3 px-8 py-4 rounded-2xl bg-gradient-to-r from-primary-500 to-accent-500 text-white font-black text-sm uppercase tracking-widest shadow-[0_0_30px_rgba(239,68,68,0.2)] hover:scale-105 transition-all">
                                    <Brain size={20} />
                                    Generate Neural Playbook
                                </button>
                            </div>

                            <div className="space-y-8">
                                {filteredPlaybooks.map(pb => (
                                    <div key={pb.id} className="bg-[#13131C] border border-white/5 rounded-[2.5rem] p-10 group hover:border-accent-500/30 transition-all duration-500">
                                        <div className="flex items-center justify-between mb-10 pb-6 border-b border-white/5">
                                            <div className="flex items-center gap-6">
                                                <div className="w-16 h-16 rounded-2xl bg-accent-500/10 border border-accent-500/20 flex items-center justify-center text-accent-500">
                                                    <Book size={32} />
                                                </div>
                                                <div>
                                                    <h3 className="text-3xl font-black text-white italic uppercase tracking-tighter">
                                                        {pb.title}
                                                    </h3>
                                                    <p className="text-gray-500 text-sm mt-1">{pb.description}</p>
                                                </div>
                                            </div>
                                            <div className="px-4 py-2 rounded-full bg-white/5 text-[10px] font-black text-gray-500 uppercase tracking-widest">
                                                {pb.steps.length} Steps
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            {pb.steps.map((step, idx) => (
                                                <div key={step.id} className="flex items-center gap-6 p-5 rounded-2xl bg-white/[0.02] border border-white/5 hover:bg-white/5 transition-all cursor-pointer">
                                                    <div className="w-8 h-8 rounded-lg border-2 border-white/10 flex items-center justify-center group-hover:border-accent-500/50 transition-colors">
                                                        {step.checked ? <CheckCircle2 size={16} className="text-green-500" /> : <div className="w-3 h-3 rounded-sm border border-white/20" />}
                                                    </div>
                                                    <span className="text-lg font-bold text-gray-400 group-hover:text-white transition-colors">{step.label}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'dashboard' && (
                        <motion.div
                            key="dashboard"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="flex flex-col items-center justify-center min-h-[500px] text-center space-y-8"
                        >
                            <div className="w-32 h-32 rounded-[2.5rem] bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center text-white shadow-[0_0_50px_rgba(239,68,68,0.3)] neon-glow-primary">
                                <Brain size={64} />
                            </div>
                            <div className="space-y-4">
                                <h2 className="text-5xl font-black text-white italic uppercase tracking-tighter">Neural Library Sync Complete</h2>
                                <p className="text-gray-500 max-w-xl mx-auto text-lg leading-relaxed">
                                    Your second brain is online and fully synchronized. Browse methodology, code snippets, and tactical playbooks to enhance your clinical operations.
                                </p>
                            </div>
                            <div className="flex gap-6 pt-4">
                                <button
                                    onClick={() => setActiveTab('wiki')}
                                    className="px-10 py-5 rounded-2xl bg-white/5 border border-white/10 text-xs font-black uppercase tracking-widest hover:bg-white/10 transition-all"
                                >
                                    Explore Wiki
                                </button>
                                <button
                                    onClick={() => setActiveTab('snippets')}
                                    className="px-10 py-5 rounded-2xl bg-primary-500 text-white text-xs font-black uppercase tracking-widest shadow-xl hover:scale-105 transition-all"
                                >
                                    Access Arsenal
                                </button>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
};

export default SecondBrain;
