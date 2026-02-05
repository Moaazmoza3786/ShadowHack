import React, { useState } from 'react';
import {
    Plug, Search, Bug, Key, Network, Copy, Check,
    Terminal, Globe, Shield, Code, ChevronRight,
    Lock, Unlock, AlertTriangle, FileJson, Database
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const APISecurityLab = () => {
    const [activeTab, setActiveTab] = useState('discovery');
    const [copiedId, setCopiedId] = useState(null);
    const [jwtInput, setJwtInput] = useState('');
    const [jwtOutput, setJwtOutput] = useState(null);

    const copyToClipboard = (text, id) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const decodeJWT = () => {
        if (!jwtInput) return;
        try {
            const parts = jwtInput.split('.');
            if (parts.length !== 3) throw new Error('Invalid JWT format');
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            setJwtOutput({ header, payload, signature: parts[2] });
        } catch (e) {
            setJwtOutput({ error: e.message });
        }
    };

    const vulnerabilities = [
        {
            id: 'API1',
            name: 'Broken Object Level Authorization (BOLA)',
            desc: 'Access other users\' data by changing IDs',
            payloads: [
                { name: 'IDOR via ID', payload: '/api/users/{other_user_id}', method: 'GET' },
                { name: 'Parameter Pollution', payload: '/api/users?id=1&id=2', method: 'GET' }
            ],
            testing: ['Change user IDs in requests', 'Test UUID guessing/prediction']
        },
        {
            id: 'API2',
            name: 'Broken Authentication',
            desc: 'Authentication mechanism flaws',
            payloads: [
                { name: 'JWT None Algorithm', payload: '{"alg":"none","typ":"JWT"}', method: 'Header' },
                { name: 'Weak Token', payload: 'Authorization: Bearer admin', method: 'Header' }
            ],
            testing: ['Check JWT validation', 'Try password reset flaws']
        },
        {
            id: 'API3',
            name: 'Excessive Data Exposure',
            desc: 'API returns more data than needed',
            payloads: [
                { name: 'Full Object Return', payload: '/api/users/me', method: 'GET' },
                { name: 'GraphQL Introspection', payload: '{__schema{types{name}}}', method: 'POST' }
            ],
            testing: ['Analyze full API responses', 'Look for hidden fields']
        }
    ];

    const discoveryTools = [
        { name: 'Swagger/OpenAPI', cmd: '/swagger.json, /openapi.json', desc: 'API documentation' },
        { name: 'Kiterunner', cmd: 'kr scan https://target.com -w routes.kite', desc: 'Smart API discovery' },
        { name: 'Arjun', cmd: 'arjun -u https://target.com/api/search', desc: 'Parameter discovery' }
    ];

    return (
        <div className="max-w-7xl mx-auto space-y-12 animate-fade-in pb-20">
            {/* Header */}
            <header className="relative py-16 px-12 rounded-[3.5rem] bg-gradient-to-br from-indigo-900/40 to-dark-900 border border-indigo-500/20 overflow-hidden">
                <div className="absolute inset-0 bg-cyber-grid opacity-10" />
                <div className="relative z-10 flex flex-col md:flex-row items-center gap-12">
                    <div className="w-24 h-24 rounded-3xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-500 shadow-[0_0_30px_rgba(99,102,241,0.2)]">
                        <Plug size={48} />
                    </div>
                    <div>
                        <h1 className="text-5xl md:text-6xl font-black text-white italic tracking-tighter uppercase">
                            API <span className="text-indigo-500">HACK LAB</span>
                        </h1>
                        <p className="text-gray-400 mt-2 font-mono uppercase tracking-[0.2em] text-sm">Testing Platform for Modern APIs</p>
                    </div>
                </div>
            </header>

            {/* Navigation Tabs */}
            <div className="flex flex-wrap gap-4 p-2 rounded-3xl bg-dark-800/40 border border-white/5 w-fit">
                {[
                    { id: 'discovery', label: 'Discovery', icon: Search },
                    { id: 'vulns', label: 'Vulnerabilities', icon: Bug },
                    { id: 'jwt', label: 'JWT Audit', icon: Key },
                    { id: 'graphql', label: 'GraphQL', icon: Network }
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-3 px-8 py-3 rounded-2xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === tab.id ? 'bg-indigo-500 text-white shadow-lg' : 'text-gray-500 hover:text-white'}`}
                    >
                        <tab.icon size={16} />
                        {tab.label}
                    </button>
                ))}
            </div>

            <main className="min-h-[600px]">
                <AnimatePresence mode="wait">
                    {activeTab === 'discovery' && (
                        <motion.div
                            key="discovery"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                        >
                            <div className="space-y-8">
                                <section className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6">
                                    <h2 className="text-2xl font-black text-white italic uppercase flex items-center gap-3">
                                        <Globe className="text-indigo-500" /> Endpoint Discovery
                                    </h2>
                                    <div className="space-y-4">
                                        {discoveryTools.map((tool, idx) => (
                                            <div key={idx} className="p-6 rounded-2xl bg-black/40 border border-white/5 group hover:border-indigo-500/30 transition-all">
                                                <div className="flex justify-between items-start mb-4">
                                                    <h4 className="text-sm font-black text-white uppercase tracking-widest">{tool.name}</h4>
                                                    <span className="text-[10px] text-gray-500 font-mono">{tool.desc}</span>
                                                </div>
                                                <div className="flex gap-2">
                                                    <code className="flex-1 px-4 py-2 rounded-xl bg-indigo-500/5 border border-indigo-500/20 text-xs text-indigo-400 font-mono">{tool.cmd}</code>
                                                    <button
                                                        onClick={() => copyToClipboard(tool.cmd, `discovery-${idx}`)}
                                                        className="p-3 rounded-xl bg-white/5 border border-white/10 text-gray-500 hover:text-white"
                                                    >
                                                        {copiedId === `discovery-${idx}` ? <Check size={16} className="text-green-500" /> : <Copy size={16} />}
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </section>
                            </div>

                            <div className="space-y-8">
                                <section className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6">
                                    <h3 className="text-xs font-black text-gray-500 uppercase tracking-[0.2em]">Common API Paths</h3>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        {['/api/v1/users', '/api/v2/admin', '/swagger.json', '/graphql', '/api-docs', '/api/debug', '/api/health'].map(path => (
                                            <div key={path} className="flex justify-between items-center p-4 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 transition-all">
                                                <code className="text-[10px] text-yellow-500/80 font-mono">{path}</code>
                                                <button onClick={() => copyToClipboard(path, path)} className="text-gray-600 hover:text-indigo-400">
                                                    {copiedId === path ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                </section>
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'vulns' && (
                        <motion.div
                            key="vulns"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8"
                        >
                            {vulnerabilities.map(vuln => (
                                <div key={vuln.id} className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 hover:border-indigo-500/20 transition-all space-y-6">
                                    <div className="flex items-center gap-3">
                                        <div className="px-2 py-1 rounded bg-red-500/10 border border-red-500/20 text-[10px] font-black text-red-500">{vuln.id}</div>
                                        <h3 className="text-sm font-black text-white uppercase tracking-widest">{vuln.name}</h3>
                                    </div>
                                    <p className="text-xs text-gray-500 leading-relaxed font-medium">{vuln.desc}</p>

                                    <div className="space-y-4">
                                        <div className="text-[10px] font-black text-indigo-500 uppercase tracking-widest">Payloads</div>
                                        {vuln.payloads.map((p, i) => (
                                            <div key={i} className="group p-4 rounded-2xl bg-black/40 border border-white/5 space-y-2">
                                                <div className="flex justify-between">
                                                    <span className="text-[9px] font-black text-gray-600 uppercase italic">{p.name}</span>
                                                    <span className="text-[9px] px-1.5 bg-yellow-500/10 text-yellow-500 rounded font-bold uppercase tracking-widest">{p.method}</span>
                                                </div>
                                                <div className="flex gap-2">
                                                    <code className="flex-1 text-[10px] text-green-500/80 truncate font-mono">{p.payload}</code>
                                                    <button onClick={() => copyToClipboard(p.payload, `${vuln.id}-${i}`)} className="text-gray-700 hover:text-white transition-colors">
                                                        {copiedId === `${vuln.id}-${i}` ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </motion.div>
                    )}

                    {activeTab === 'jwt' && (
                        <motion.div
                            key="jwt"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="grid grid-cols-1 lg:grid-cols-2 gap-12"
                        >
                            <div className="space-y-8">
                                <section className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6">
                                    <h2 className="text-2xl font-black text-white italic uppercase flex items-center gap-3">
                                        <Key className="text-indigo-500" /> JWT Decoder
                                    </h2>
                                    <div className="space-y-4">
                                        <textarea
                                            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                            value={jwtInput}
                                            onChange={(e) => setJwtInput(e.target.value)}
                                            className="w-full h-40 p-6 rounded-3xl bg-black/40 border border-white/5 text-xs text-indigo-400 font-mono outline-none focus:border-indigo-500/50 transition-all resize-none shadow-inner"
                                        />
                                        <button
                                            onClick={decodeJWT}
                                            className="w-full py-4 rounded-[1.5rem] bg-indigo-500 text-white font-black uppercase tracking-widest italic text-xs hover:scale-[1.02] transition-all shadow-[0_10px_30px_rgba(99,102,241,0.3)] flex items-center justify-center gap-3"
                                        >
                                            <Unlock size={16} /> Decode Token
                                        </button>
                                    </div>
                                </section>

                                <div className="p-8 rounded-[2.5rem] bg-indigo-500/5 border border-indigo-500/10 space-y-6">
                                    <h3 className="text-xs font-black text-indigo-500 uppercase tracking-widest flex items-center gap-2">
                                        <Shield size={14} /> Critical JWT Attacks
                                    </h3>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        {[
                                            { name: 'None Alg', desc: 'Remove signature, set alg:none' },
                                            { name: 'Alg Confusion', desc: 'RS256 -> HS256 with PubKey' },
                                            { name: 'Kid Injection', desc: 'SQLi/Path traversal in kid' },
                                            { name: 'Weak Secret', desc: 'Brute force short HMAC keys' }
                                        ].map(attack => (
                                            <div key={attack.name} className="p-4 rounded-2xl bg-black/40 border border-white/5 group">
                                                <div className="text-[10px] font-black text-red-500 uppercase tracking-widest mb-1">{attack.name}</div>
                                                <p className="text-[10px] text-gray-600 font-medium leading-tight">{attack.desc}</p>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-8">
                                <AnimatePresence mode="wait">
                                    {jwtOutput ? (
                                        <motion.div
                                            key="output"
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            className="space-y-6"
                                        >
                                            {jwtOutput.error ? (
                                                <div className="p-8 rounded-[2.5rem] bg-red-500/10 border border-red-500/20 text-red-500 flex items-center gap-4">
                                                    <AlertTriangle size={36} />
                                                    <div className="text-sm font-black uppercase tracking-widest italic">{jwtOutput.error}</div>
                                                </div>
                                            ) : (
                                                <>
                                                    <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-4">
                                                        <div className="text-[10px] font-black text-red-500 uppercase tracking-widest flex items-center justify-between">
                                                            <span>Header</span>
                                                            <FileJson size={14} />
                                                        </div>
                                                        <pre className="text-[10px] text-indigo-400 font-mono bg-black/40 p-4 rounded-xl overflow-x-auto">
                                                            {JSON.stringify(jwtOutput.header, null, 2)}
                                                        </pre>
                                                    </div>
                                                    <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-4">
                                                        <div className="text-[10px] font-black text-purple-500 uppercase tracking-widest flex items-center justify-between">
                                                            <span>Payload</span>
                                                            <Database size={14} />
                                                        </div>
                                                        <pre className="text-[10px] text-indigo-400 font-mono bg-black/40 p-4 rounded-xl overflow-x-auto">
                                                            {JSON.stringify(jwtOutput.payload, null, 2)}
                                                        </pre>
                                                    </div>
                                                    <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-4">
                                                        <div className="text-[10px] font-black text-blue-500 uppercase tracking-widest flex items-center justify-between">
                                                            <span>Signature</span>
                                                            <Lock size={14} />
                                                        </div>
                                                        <div className="text-[10px] font-mono p-4 rounded-xl bg-black/40 text-gray-500 break-all leading-relaxed">
                                                            {jwtOutput.signature}
                                                        </div>
                                                    </div>
                                                </>
                                            )}
                                        </motion.div>
                                    ) : (
                                        <div className="h-full min-h-[400px] border-2 border-dashed border-white/5 rounded-[3.5rem] flex flex-col items-center justify-center text-center p-12 gap-6 opacity-30 grayscale group hover:opacity-50 transition-all">
                                            <div className="w-20 h-20 rounded-full bg-white/5 border border-white/10 flex items-center justify-center group-hover:scale-110 transition-transform">
                                                <Key size={40} />
                                            </div>
                                            <p className="text-sm font-bold uppercase tracking-widest text-gray-500">Decoded data will appear here</p>
                                        </div>
                                    )}
                                </AnimatePresence>
                            </div>
                        </motion.div>
                    )}

                    {activeTab === 'graphql' && (
                        <motion.div
                            key="graphql"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="space-y-12"
                        >
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                                {[
                                    { title: 'Full Schema', query: '{__schema{types{name,fields{name,args{name}}}}}' },
                                    { title: 'All Types', query: '{__schema{types{name}}}' },
                                    { title: 'Query Types', query: '{__schema{queryType{name,fields{name}}}}' },
                                    { title: 'Mutation Types', query: '{__schema{mutationType{name,fields{name}}}}' }
                                ].map((q, idx) => (
                                    <div key={idx} className="p-6 rounded-3xl bg-dark-800/40 border border-white/5 space-y-4">
                                        <h3 className="text-[10px] font-black text-white uppercase tracking-widest">{q.title}</h3>
                                        <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                                            <code className="text-[9px] text-green-500 font-mono block truncate">{q.query}</code>
                                        </div>
                                        <button
                                            onClick={() => copyToClipboard(q.query, `gq-${idx}`)}
                                            className="w-full py-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-[10px] font-black text-indigo-400 uppercase tracking-widest hover:bg-indigo-500 hover:text-white transition-all"
                                        >
                                            {copiedId === `gq-${idx}` ? 'Copied!' : 'Copy Query'}
                                        </button>
                                    </div>
                                ))}
                            </div>

                            <section className="p-10 rounded-[3.5rem] bg-dark-800/40 border border-white/5 space-y-8">
                                <div className="flex items-center gap-4">
                                    <Terminal className="text-indigo-500" />
                                    <h2 className="text-xl font-black text-white uppercase italic tracking-widest">GraphQL Attack Vectors</h2>
                                </div>
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                    {[
                                        { name: 'DoS via Deep Nesting', query: '{user{friends{friends{friends{friends{name}}}}}}', impact: 'Server Resource Exhaustion' },
                                        { name: 'Batching Attack', query: '[{query:"{me{id}}"}, {query:"{me{id}}"}]', impact: 'Bypassing Rate Limits' },
                                        { name: 'Field Suggestion enumeration', query: '{user{passwor}} // observe response', impact: 'Data Schema Leakage' },
                                        { name: 'Alias Overloading', query: '{u1:me{name},u2:me{name}}', impact: 'WAF Bypass' }
                                    ].map((a, i) => (
                                        <div key={i} className="flex gap-6 p-6 rounded-2xl bg-white/[0.02] border border-white/5">
                                            <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500 shrink-0 italic font-black">!</div>
                                            <div className="flex-1 space-y-2">
                                                <div className="flex justify-between items-center">
                                                    <span className="text-xs font-black text-white uppercase tracking-widest">{a.name}</span>
                                                    <span className="text-[8px] font-mono text-red-500/50 uppercase">{a.impact}</span>
                                                </div>
                                                <code className="block p-3 rounded-lg bg-black text-[10px] text-gray-500 font-mono truncate">{a.query}</code>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </section>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
};

export default APISecurityLab;
