import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Zap, Skull, Code, Search,
    RefreshCcw, ExternalLink, ChevronRight,
    Shield, Terminal, FileCode, Globe,
    Download, Target, AlertTriangle, Check
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';
import { useAppContext } from '../../context/AppContext';

const CVERadar = () => {
    const { toast } = useToast();
    const { apiUrl } = useAppContext();
    const [isLoading, setIsLoading] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [results, setResults] = useState([]);
    const [downloading, setDownloading] = useState(null);

    const performSearch = async () => {
        if (!searchQuery || searchQuery.length < 3) {
            return toast('Please enter at least 3 characters', 'warn');
        }

        setIsLoading(true);
        try {
            const res = await fetch(`${apiUrl}/tools/exploit-search`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: searchQuery })
            });
            const data = await res.json();

            if (data.success) {
                setResults(data.results);
                toast(`Found ${data.results.length} relevant exploits`, 'success');
            } else {
                setResults([]);
                toast(data.error || 'No results found', 'info');
            }
        } catch (e) {
            console.error("Search failed", e);
            toast('Failed to reach exploit database', 'error');
        } finally {
            setIsLoading(false);
        }
    };

    const handleDownload = async (exploit) => {
        const id = exploit['EDB-ID'];
        setDownloading(id);

        toast(`Downloading exploit ${id} to workspace...`, 'info');

        try {
            const res = await fetch(`${apiUrl}/tools/exploit-download`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ exploit_id: id })
            });
            const data = await res.json();

            if (data.success) {
                toast(`Exploit mirrored successfully!`, 'success');
                // Could ideally show where inside the UI or workspace
            } else {
                toast(data.error || "Download failed", 'error');
            }
        } catch (e) {
            console.error("Download failed", e);
            toast('Backend connection error', 'error');
        } finally {
            setDownloading(null);
        }
    };

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* HERO SECTION */}
            <div className="relative overflow-hidden rounded-[2.5rem] bg-dark-900 border border-white/10 p-12">
                <div className="relative z-10 flex flex-col md:flex-row justify-between items-center gap-12">
                    <div className="flex-1 space-y-6">
                        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-red-500/10 border border-red-500/20 text-red-500 text-[10px] font-black uppercase tracking-widest">
                            <Target size={14} /> Active Recon Engine
                        </div>
                        <h1 className="text-5xl md:text-6xl font-black italic uppercase tracking-tighter text-white leading-none">
                            CVE <span className="text-red-500">Hunter</span>
                        </h1>
                        <p className="text-lg text-gray-400 font-medium max-w-xl">
                            Instant access to Exploit-DB and NVD.
                            Find, analyze, and deploy scripts directly into your <span className="text-white font-bold">Codespace</span> with one click.
                        </p>

                        <div className="relative max-w-2xl group">
                            <Search className="absolute left-6 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-red-500 transition-colors" size={24} />
                            <input
                                type="text"
                                placeholder="Service, Version, or CVE (e.g. vsftpd 2.3.4)"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && performSearch()}
                                className="w-full bg-black/50 border-2 border-white/5 rounded-3xl py-6 pl-16 pr-40 text-xl font-mono text-red-400 focus:border-red-500/50 outline-none transition-all placeholder:text-gray-700 shadow-2xl"
                            />
                            <button
                                onClick={performSearch}
                                disabled={isLoading}
                                className="absolute right-3 top-1/2 -translate-y-1/2 bg-red-600 hover:bg-red-500 text-white px-8 py-4 rounded-2xl font-black uppercase italic tracking-tighter transition-all hover:scale-105 shadow-lg shadow-red-600/20 flex items-center gap-2 disabled:opacity-50"
                            >
                                {isLoading ? <RefreshCcw className="animate-spin" size={20} /> : <Zap size={20} />}
                                HUNT
                            </button>
                        </div>
                    </div>

                    <div className="hidden lg:block w-72 h-72 relative">
                        <div className="absolute inset-0 bg-red-500/10 rounded-full blur-[80px] animate-pulse" />
                        <div className="absolute inset-0 border-4 border-dashed border-red-500/20 rounded-full animate-spin-slow" />
                        <div className="absolute inset-4 border-2 border-red-500/40 rounded-full animate-reverse-spin-slow" />
                        <div className="absolute inset-0 flex items-center justify-center">
                            <Skull size={80} className="text-red-600 opacity-80" />
                        </div>
                    </div>
                </div>
            </div>

            {/* RESULTS SECTION */}
            <div className="space-y-4">
                <div className="flex items-center justify-between px-4">
                    <h2 className="text-xs font-black uppercase tracking-widest text-gray-500 flex items-center gap-2">
                        <Code size={14} className="text-red-500" /> Hunt Results
                        <span className="text-white bg-white/5 px-2 py-0.5 rounded ml-2">{results.length}</span>
                    </h2>
                    <div className="flex gap-4">
                        <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">Database: Exploit-DB</span>
                    </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                    <AnimatePresence>
                        {results.length > 0 ? (
                            results.map((item, idx) => (
                                <motion.div
                                    key={idx}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: idx * 0.05 }}
                                    className="p-6 bg-dark-900 border border-white/5 rounded-3xl group hover:border-red-500/30 transition-all hover:translate-x-2"
                                >
                                    <div className="flex flex-col md:flex-row justify-between items-center gap-6">
                                        <div className="flex-1 space-y-3">
                                            <div className="flex items-center gap-3 flex-wrap">
                                                <h3 className="text-xl font-black text-white group-hover:text-red-400 transition-colors uppercase tracking-tight italic">
                                                    {item['Title']}
                                                </h3>
                                                {item['Codes'] && (
                                                    <span className="px-3 py-1 bg-white/5 rounded-lg text-[10px] font-mono text-white/50 border border-white/5">
                                                        {item['Codes']}
                                                    </span>
                                                )}
                                                {item['Verified'] === '1' && (
                                                    <span className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 text-emerald-500 text-[10px] font-black uppercase rounded-lg">
                                                        <Check size={12} /> VERIFIED
                                                    </span>
                                                )}
                                            </div>

                                            <div className="flex flex-wrap items-center gap-6 text-[10px] font-black text-gray-500 uppercase tracking-widest font-mono">
                                                <div className="flex items-center gap-2">
                                                    <Shield size={12} className="text-red-500" />
                                                    ID: <span className="text-white">{item['EDB-ID']}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <FileCode size={12} className="text-cyan-500" />
                                                    TYPE: <span className="text-white">{item['Type']}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <Globe size={12} className="text-blue-500" />
                                                    PLATFORM: <span className="text-white">{item['Platform']}</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <AlertTriangle size={12} className="text-orange-500" />
                                                    DATE: <span className="text-white">{item['Date']}</span>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex gap-3 shrink-0">
                                            <button
                                                onClick={() => handleDownload(item)}
                                                disabled={downloading === item['EDB-ID']}
                                                className="h-14 flex items-center gap-3 px-8 bg-red-600/10 text-red-500 border-2 border-red-500/20 rounded-2xl hover:bg-red-600 hover:text-white transition-all font-black uppercase italic tracking-tighter disabled:opacity-50"
                                            >
                                                {downloading === item['EDB-ID'] ? (
                                                    <RefreshCcw className="animate-spin" size={20} />
                                                ) : (
                                                    <Download size={20} />
                                                )}
                                                DEPLOY EXPLOIT
                                            </button>

                                            <a
                                                href={`https://www.exploit-db.com/exploits/${item['EDB-ID']}`}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="w-14 h-14 flex items-center justify-center bg-white/5 text-gray-400 border border-white/10 rounded-2xl hover:bg-white/10 hover:text-white transition-all"
                                            >
                                                <ExternalLink size={20} />
                                            </a>
                                        </div>
                                    </div>
                                </motion.div>
                            ))
                        ) : (
                            !isLoading && (
                                <div className="p-20 bg-dark-900 border border-white/5 rounded-[3rem] text-center space-y-6">
                                    <div className="w-24 h-24 bg-white/5 rounded-full flex items-center justify-center mx-auto">
                                        <Skull size={48} className="text-gray-700" />
                                    </div>
                                    <div className="space-y-2">
                                        <h3 className="text-xl font-black text-white uppercase italic tracking-widest">No Targets Detected</h3>
                                        <p className="text-sm text-gray-500 max-w-xs mx-auto">
                                            The Recon Engine is awaiting coordinates. Enter a service or version to begin the hunt.
                                        </p>
                                    </div>
                                </div>
                            )
                        )}
                    </AnimatePresence>
                </div>
            </div>

            {/* Background Animations */}
            <div className="fixed inset-0 pointer-events-none overflow-hidden z-[-1] opacity-20">
                <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] bg-red-600 blur-[200px] rounded-full mix-blend-screen" />
                <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] bg-blue-900 blur-[200px] rounded-full mix-blend-screen" />
            </div>
        </div>
    );
};

export default CVERadar;
