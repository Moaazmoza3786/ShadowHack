import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Zap, Search, Shield, Activity, Globe,
    Server, RefreshCw, AlertCircle, CheckCircle,
    LayoutGrid, List, Plus, Trash2, Terminal,
    Database, Map, ExternalLink, ChevronRight,
    Filter, Clock, Play, Square, Pause,
    Layers, Cpu, Box, Target, Flag, Loader2
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

const StatusBadge = ({ status }) => {
    const colors = {
        200: 'bg-green-500/20 text-green-400 border-green-500/30',
        301: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
        302: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
        401: 'bg-purple-500/20 text-purple-400 border-purple-500/30 shadow-[0_0_10px_rgba(168,85,247,0.2)]',
        403: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
        404: 'bg-white/5 text-white/40 border-white/10',
        500: 'bg-red-500/20 text-red-400 border-red-500/30 animate-pulse'
    };

    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${colors[status] || colors[404]}`}>
            {status}
        </span>
    );
};

const FuzzingCockpit = () => {
    const { toast } = useToast();
    const [url, setUrl] = useState('');
    const [wordlist, setWordlist] = useState('common.txt');
    const [activeFilters, setActiveFilters] = useState([404]);
    const [taskId, setTaskId] = useState(null);
    const [status, setStatus] = useState('idle'); // idle, running, completed
    const [results, setResults] = useState([]);
    const [stats, setStats] = useState({ progress: 0, speed: 0, requests: 0, hits: 0 });
    const resultsEndRef = useRef(null);

    const WORDLISTS = [
        { name: 'Common Paths', file: 'common.txt' },
        { name: 'Big Directory', file: 'directory-list-2.3-big.txt' },
        { name: 'Admin Panels', file: 'admin-panels.txt' },
        { name: 'API Endpoints', file: 'api-routes.txt' },
        { name: 'Raft Medium', file: 'raft-medium-directories.txt' }
    ];

    const toggleFilter = (code) => {
        setActiveFilters(prev =>
            prev.includes(code) ? prev.filter(c => c !== code) : [...prev, code]
        );
    };

    const startFuzz = async () => {
        if (!url.includes('FUZZ')) return toast("URL must contain 'FUZZ' placeholder", "warning");

        setStatus('running');
        setResults([]);
        setStats({ progress: 0, speed: 0, requests: 0, hits: 0 });

        const activeProjectId = localStorage.getItem('activeProjectId');
        try {
            const res = await fetch('/api/tools/fuzz/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, wordlist, filters: activeFilters, project_id: activeProjectId })
            });
            const data = await res.json();
            if (data.success) {
                setTaskId(data.task_id);
                toast("Fuzzing Operation Launched", "success");
            } else {
                setStatus('idle');
                toast(data.error || "Failed to start", "error");
            }
        } catch (err) {
            setStatus('idle');
            toast("Connection error", "error");
        }
    };

    // Polling for status
    useEffect(() => {
        let interval;
        if (taskId && status === 'running') {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`/api/tools/fuzz/status/${taskId}`);
                    const resData = await res.json();
                    if (resData.success) {
                        const { data } = resData;
                        setResults(data.results || []);
                        setStats({
                            progress: data.progress,
                            speed: data.speed,
                            requests: data.total_requests,
                            hits: (data.results || []).length
                        });
                        if (data.status === 'completed' || data.status === 'failed') {
                            setStatus(data.status);
                            clearInterval(interval);
                            toast(data.status === 'completed' ? "Operation Complete" : "Operation Failed",
                                data.status === 'completed' ? "success" : "error");
                        }
                    }
                } catch (err) {
                    console.error("Polling error:", err);
                }
            }, 1000);
        }
        return () => clearInterval(interval);
    }, [taskId, status]);

    // Internal Scroll
    useEffect(() => {
        resultsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [results]);

    return (
        <div className="min-h-screen bg-dark-950 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER / HUD */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-white/10 pb-10">
                <div className="space-y-4">
                    <div className="flex items-center gap-4">
                        <div className="p-4 rounded-2xl bg-orange-500/20 text-orange-500 border border-orange-500/30 shadow-[0_0_20px_rgba(249,115,22,0.15)]">
                            <Target size={32} />
                        </div>
                        <div>
                            <h1 className="text-5xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-orange-400 via-red-500 to-orange-400 bg-[length:200%_auto] animate-gradient">
                                FUZZING COCKPIT
                            </h1>
                            <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-xs flex items-center gap-2">
                                <Zap size={12} className="text-orange-500" /> Automated Discovery System
                            </p>
                        </div>
                    </div>
                </div>

                {/* STATS HUD */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-dark-900/50 backdrop-blur-xl border border-white/10 p-5 rounded-[2rem]">
                    {[
                        { label: 'Progress', value: `${stats.progress}%`, icon: Activity, color: 'text-blue-400' },
                        { label: 'Speed', value: `${stats.speed} R/s`, icon: Cpu, color: 'text-orange-400' },
                        { label: 'Requests', value: stats.requests, icon: Server, color: 'text-purple-400' },
                        { label: 'Hits', value: stats.hits, icon: Flag, color: 'text-green-400' }
                    ].map((stat, i) => (
                        <div key={i} className="px-4 py-2 border-r last:border-none border-white/5 space-y-1 text-center md:text-left">
                            <div className="flex items-center gap-2 text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">
                                <stat.icon size={10} className={stat.color} /> {stat.label}
                            </div>
                            <div className={`text-xl font-black italic ${stat.color}`}>{stat.value}</div>
                        </div>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

                {/* LEFT: CONTROLS (4 cols) */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 space-y-8 shadow-2xl relative overflow-hidden">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-orange-500/5 blur-3xl rounded-full" />

                        <h3 className="text-xl font-black text-white italic flex items-center gap-3">
                            <Target size={22} className="text-orange-500" /> MISSION PARAMETERS
                        </h3>

                        {/* URL INPUT */}
                        <div className="space-y-3">
                            <label className="text-[10px] font-black text-white/30 uppercase tracking-widest ml-1">Target URL (with FUZZ)</label>
                            <div className="relative group">
                                <Globe size={18} className="absolute left-5 top-1/2 -translate-y-1/2 text-white/20 group-focus-within:text-orange-500 transition-colors" />
                                <input
                                    type="text"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder="http://example.com/FUZZ"
                                    className="w-full bg-dark-800 border border-white/5 rounded-2xl pl-12 pr-6 py-4 focus:outline-none focus:border-orange-500/50 transition-all font-mono text-sm"
                                />
                            </div>
                        </div>

                        {/* WORDLIST SELECTOR */}
                        <div className="space-y-3">
                            <label className="text-[10px] font-black text-white/30 uppercase tracking-widest ml-1">Tactical Wordlist</label>
                            <div className="grid grid-cols-1 gap-2">
                                {WORDLISTS.map(wl => (
                                    <button
                                        key={wl.file}
                                        onClick={() => setWordlist(wl.file)}
                                        className={`p-4 rounded-2xl flex items-center justify-between border transition-all ${wordlist === wl.file
                                            ? 'bg-orange-500/10 border-orange-500/40 text-orange-400'
                                            : 'bg-dark-800 border-white/5 text-white/40 hover:border-white/20'}`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <Database size={16} />
                                            <span className="text-xs font-bold">{wl.name}</span>
                                        </div>
                                        {wordlist === wl.file && <CheckCircle size={14} />}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* FILTERS */}
                        <div className="space-y-3">
                            <label className="text-[10px] font-black text-white/30 uppercase tracking-widest ml-1">Exclusion Filters (Hide Status)</label>
                            <div className="flex flex-wrap gap-2">
                                {[200, 301, 302, 401, 403, 404, 500].map(code => (
                                    <button
                                        key={code}
                                        onClick={() => toggleFilter(code)}
                                        className={`px-4 py-2 rounded-xl border text-[10px] font-black transition-all ${activeFilters.includes(code)
                                            ? 'bg-red-500/20 border-red-500/30 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.1)]'
                                            : 'bg-white/5 border-white/10 text-white/30'}`}
                                    >
                                        {code}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* ACTION BUTTON */}
                        <button
                            onClick={status === 'running' ? () => setStatus('idle') : startFuzz}
                            className={`w-full py-5 rounded-3xl font-black uppercase tracking-[0.3em] text-sm flex items-center justify-center gap-3 transition-all ${status === 'running'
                                ? 'bg-red-500/20 text-red-500 border border-red-500/40 hover:bg-red-500/30'
                                : 'bg-gradient-to-r from-orange-600 to-red-600 text-white shadow-xl shadow-orange-500/20 hover:scale-[1.02] active:scale-95'}`}
                        >
                            {status === 'running' ? (
                                <><Square size={20} fill="currentColor" /> Abort Operation</>
                            ) : (
                                <><Play size={20} fill="currentColor" /> Launch Mission</>
                            )}
                        </button>
                    </div>
                </div>

                {/* RIGHT: DASHBOARD (8 cols) */}
                <div className="lg:col-span-8 flex flex-col space-y-6">
                    <div className="flex-1 p-8 rounded-[3rem] bg-dark-900 border border-white/10 shadow-2xl flex flex-col min-h-[600px]">
                        <div className="flex justify-between items-center mb-8">
                            <h3 className="text-xl font-black text-white italic flex items-center gap-3">
                                <Activity size={22} className="text-blue-500" /> LIVE DISCOVERIES
                            </h3>
                            <div className="flex items-center gap-3 px-4 py-2 bg-white/5 rounded-full border border-white/5">
                                <span className={`w-2 h-2 rounded-full ${status === 'running' ? 'bg-green-500 animate-pulse' : 'bg-white/20'}`} />
                                <span className="text-[10px] font-mono text-white/40 uppercase tracking-widest">{status}</span>
                            </div>
                        </div>

                        {/* RESULTS TABLE */}
                        <div className="flex-1 overflow-hidden relative border border-white/5 rounded-3xl bg-black/20">
                            <div className="overflow-y-auto h-full scrollbar-hide p-4">
                                <table className="w-full text-left">
                                    <thead className="sticky top-0 bg-dark-900/90 backdrop-blur-md z-10 border-b border-white/10">
                                        <tr className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em]">
                                            <th className="px-6 py-4">Payload</th>
                                            <th className="px-6 py-4">Status</th>
                                            <th className="px-6 py-4">Size</th>
                                            <th className="px-6 py-4">Time</th>
                                            <th className="px-6 py-4">Identity</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        <AnimatePresence>
                                            {results.map((res, i) => (
                                                <motion.tr
                                                    key={res.id}
                                                    initial={{ opacity: 0, x: -10 }}
                                                    animate={{ opacity: 1, x: 0 }}
                                                    transition={{ duration: 0.2 }}
                                                    className="group hover:bg-white/5 transition-colors"
                                                >
                                                    <td className="px-6 py-4">
                                                        <span className="font-mono text-xs text-orange-400 font-bold tracking-tight">/{res.payload}</span>
                                                    </td>
                                                    <td className="px-6 py-4 text-center">
                                                        <StatusBadge status={res.status} />
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <span className="text-xs font-mono text-white/40">{res.size} B</span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <span className="text-xs font-mono text-white/40">{res.time}ms</span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className="flex items-center gap-2">
                                                            <div className="p-1.5 rounded-lg bg-white/5 text-white/20">
                                                                <ExternalLink size={12} />
                                                            </div>
                                                            <span className="text-[10px] text-white/20 font-mono truncate max-w-[120px]">{res.url}</span>
                                                        </div>
                                                    </td>
                                                </motion.tr>
                                            ))}
                                        </AnimatePresence>
                                        <div ref={resultsEndRef} />
                                    </tbody>
                                </table>

                                {results.length === 0 && status === 'idle' && (
                                    <div className="h-full flex flex-col items-center justify-center space-y-4 py-20 opacity-20">
                                        <Terminal size={48} />
                                        <p className="font-mono text-xs uppercase tracking-[0.3em]">Awaiting tactical command...</p>
                                    </div>
                                )}

                                {status === 'running' && results.length === 0 && (
                                    <div className="h-full flex flex-col items-center justify-center space-y-4 py-20">
                                        <Loader2 size={40} className="text-orange-500 animate-spin" />
                                        <p className="font-mono text-xs text-white/40 uppercase animate-pulse">Scanning targets...</p>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* PROGRESS BAR */}
                        <div className="mt-8 space-y-2">
                            <div className="flex justify-between text-[10px] font-black uppercase tracking-widest text-white/30 px-1">
                                <span>Operation Progress</span>
                                <span className="text-blue-400">{stats.progress}%</span>
                            </div>
                            <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden border border-white/10">
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${stats.progress}%` }}
                                    className="h-full bg-gradient-to-r from-blue-600 via-indigo-500 to-blue-600 bg-[length:200%_auto] animate-gradient"
                                />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default FuzzingCockpit;
