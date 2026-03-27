import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Flame, Zap, Shield, Search, Terminal,
    CheckCircle, AlertTriangle, Fingerprint,
    Copy, Download, RefreshCw, Database,
    Gauge, Activity, ArrowUpRight, Lock, Unlock,
    Upload, FileText, Settings, Play, Square
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- UI COMPONENTS ---

const Speedometer = ({ speed }) => {
    // speed is hashes/sec, let's normalize to a degree (0-180 or 270)
    const maxSpeed = 1000000;
    const normalized = Math.min(speed / maxSpeed, 1);
    const rotation = -135 + (normalized * 270);

    return (
        <div className="relative w-48 h-48 flex items-center justify-center">
            {/* Background Arc */}
            <svg className="absolute w-full h-full transform -rotate-90">
                <circle
                    cx="96" cy="96" r="80"
                    fill="none"
                    stroke="rgba(255,255,255,0.05)"
                    strokeWidth="12"
                    strokeDasharray="377"
                    strokeDashoffset="125"
                    strokeLinecap="round"
                />
                {/* Active Progress Arc */}
                <motion.circle
                    cx="96" cy="96" r="80"
                    fill="none"
                    stroke="url(#speed-gradient)"
                    strokeWidth="12"
                    strokeDasharray="377"
                    initial={{ strokeDashoffset: 377 }}
                    animate={{ strokeDashoffset: 377 - (normalized * 252) }}
                    transition={{ type: "spring", stiffness: 50 }}
                    strokeLinecap="round"
                />
                <defs>
                    <linearGradient id="speed-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#ef4444" />
                        <stop offset="100%" stopColor="#f97316" />
                    </linearGradient>
                </defs>
            </svg>

            {/* Needle */}
            <motion.div
                className="absolute w-1 h-24 bg-red-500 origin-bottom rounded-full"
                style={{ bottom: '50%', transformOrigin: 'bottom center' }}
                animate={{ rotate: rotation }}
                transition={{ type: "spring", stiffness: 60 }}
            />

            <div className="z-10 text-center">
                <div className="text-3xl font-black font-mono text-white leading-none">
                    {(speed / 1000).toFixed(1)}k
                </div>
                <div className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em] mt-1">
                    Hashes/sec
                </div>
            </div>
        </div>
    );
};

const RefineryProgress = ({ progress }) => {
    const segments = 20;
    const activeSegments = Math.floor((progress / 100) * segments);

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-end">
                <div className="space-y-1">
                    <span className="text-[10px] font-bold text-orange-500 uppercase tracking-widest">System Load</span>
                    <h4 className="text-xl font-black text-white italic">REFINERY INTENSITY</h4>
                </div>
                <div className="text-3xl font-black font-mono text-orange-400 italic">
                    {progress}%
                </div>
            </div>
            <div className="grid grid-cols-20 gap-1.5 h-8">
                {[...Array(segments)].map((_, i) => (
                    <motion.div
                        key={i}
                        initial={{ opacity: 0.1 }}
                        animate={{
                            opacity: i < activeSegments ? 1 : 0.1,
                            backgroundColor: i < activeSegments ? '#f97316' : '#ffffff',
                            boxShadow: i < activeSegments ? '0 0 15px #f97316' : 'none'
                        }}
                        className="rounded-sm"
                    />
                ))}
            </div>
        </div>
    );
};

const MatrixLogs = ({ logs }) => {
    const logRef = useRef(null);

    useEffect(() => {
        if (logRef.current) {
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }, [logs]);

    return (
        <div className="bg-black/80 border border-orange-500/20 rounded-2xl p-6 font-mono relative overflow-hidden h-[400px]">
            {/* Scanline Effect */}
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.03),rgba(0,255,0,0.01),rgba(0,0,255,0.03))] bg-[length:100%_4px,3px_100%] z-20" />

            <div ref={logRef} className="space-y-1.5 overflow-y-auto h-full scrollbar-thin scrollbar-thumb-orange-500/20 pr-4">
                {logs.map((log, i) => (
                    <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -5 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`text-sm ${log.includes('[!]') ? 'text-red-400 font-bold' :
                                log.includes('[+]') ? 'text-orange-400' :
                                    'text-white/60'
                            }`}
                    >
                        <span className="text-white/20 mr-2">[{new Date().toLocaleTimeString()}]</span>
                        {log}
                    </motion.div>
                ))}
                {logs.length === 0 && <div className="text-white/20 italic italic">Refinery offline. Awaiting input...</div>}
            </div>
        </div>
    );
};

// --- MAIN COMPONENT ---

const HashRefinery = () => {
    const { toast } = useToast();
    const [hashInput, setHashInput] = useState('');
    const [detectedMatches, setDetectedMatches] = useState([]);
    const [selectedWordlist, setSelectedWordlist] = useState('rockyou.txt');

    const [taskID, setTaskID] = useState(null);
    const [refineryData, setRefineryData] = useState(null);
    const [isCracking, setIsCracking] = useState(false);

    // --- AUTO-DETECTION ---
    useEffect(() => {
        if (hashInput.trim().length > 8) {
            const timer = setTimeout(async () => {
                try {
                    const res = await fetch('/api/tools/hash/detect', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ hash: hashInput })
                    });
                    const data = await res.json();
                    if (data.success) {
                        setDetectedMatches(data.matches);
                    }
                } catch (err) {
                    console.error("Detection failed:", err);
                }
            }, 500);
            return () => clearTimeout(timer);
        } else {
            setDetectedMatches([]);
        }
    }, [hashInput]);

    // --- POLLING ---
    useEffect(() => {
        let interval;
        if (isCracking && taskID) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch('/api/tools/crack/status', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ task_id: taskID })
                    });
                    const data = await res.json();
                    if (data.success) {
                        setRefineryData(data.data);
                        if (data.data.status === 'completed' || data.data.status === 'failed') {
                            setIsCracking(false);
                            if (data.data.status === 'completed') {
                                toast("Refining Successful!", "success");
                            } else {
                                toast("Refinery Failed", "error");
                            }
                        }
                    }
                } catch (err) {
                    setIsCracking(false);
                }
            }, 1000);
        }
        return () => clearInterval(interval);
    }, [isCracking, taskID]);

    const startRefinery = async () => {
        if (!hashInput.trim()) return toast("Hash input required", "warning");

        setIsCracking(true);
        setRefineryData(null);
        try {
            const res = await fetch('/api/tools/crack/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: hashInput, wordlist: selectedWordlist })
            });
            const data = await res.json();
            if (data.success) {
                setTaskID(data.task_id);
                toast("Refinery Initialized", "success");
            } else {
                setIsCracking(false);
                toast(data.error || "Failed to start", "error");
            }
        } catch (err) {
            setIsCracking(false);
            toast("Connection error", "error");
        }
    };

    const stopRefinery = () => {
        setIsCracking(false);
        // We could call a backend stop endpoint here if implemented
    };

    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-white/10 pb-10">
                <div className="space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="p-3 rounded-2xl bg-orange-500/20 border border-orange-500/30 text-orange-500 shadow-lg shadow-orange-500/10">
                            <Flame size={32} />
                        </div>
                        <div>
                            <h1 className="text-5xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-orange-400 via-red-500 to-orange-400 bg-[length:200%_auto] animate-gradient">
                                THE HASH REFINERY
                            </h1>
                            <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-xs flex items-center gap-2">
                                <Settings size={12} className="animate-spin-slow" /> Advanced Password Cracking Station
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <div className="px-6 py-4 rounded-3xl bg-dark-800 border border-white/10 flex items-center gap-4 shadow-xl shadow-black/50">
                        <div className="text-right">
                            <div className="text-[10px] font-bold text-white/30 uppercase tracking-widest">System Status</div>
                            <div className={`text-sm font-black italic ${isCracking ? 'text-orange-500' : 'text-green-500'}`}>
                                {isCracking ? 'REFINING ACTIVE' : 'REFINERY READY'}
                            </div>
                        </div>
                        <div className={`w-3 h-3 rounded-full ${isCracking ? 'bg-orange-500' : 'bg-green-500'} animate-pulse shadow-[0_0_10px_currentColor]`} />
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

                {/* LEFT: INPUT & DETECTION (4 cols) */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="p-8 rounded-[2.5rem] bg-dark-800 border border-white/10 space-y-6 shadow-2xl shadow-black/40">
                        <div className="space-y-4">
                            <h3 className="text-lg font-black text-white italic flex items-center gap-2">
                                <Database size={20} className="text-orange-500" /> REFINERY FEED
                            </h3>
                            <textarea
                                value={hashInput}
                                onChange={(e) => setHashInput(e.target.value)}
                                placeholder="DROP HASH OR SHADOW CONTENT HERE..."
                                className="w-full h-40 bg-dark-900 border border-white/5 rounded-3xl p-6 font-mono text-sm text-orange-400 focus:outline-none focus:border-orange-500/50 transition-all resize-none shadow-inner"
                            />

                            <div className="flex gap-2">
                                <button className="flex-1 py-3 bg-white/5 hover:bg-white/10 rounded-2xl border border-white/10 text-[10px] font-bold uppercase tracking-widest transition-all text-white/60 flex items-center justify-center gap-2">
                                    <Upload size={14} /> Upload Shadow
                                </button>
                                <button className="flex-1 py-3 bg-white/5 hover:bg-white/10 rounded-2xl border border-white/10 text-[10px] font-bold uppercase tracking-widest transition-all text-white/60 flex items-center justify-center gap-2">
                                    <FileText size={14} /> Load Wordlist
                                </button>
                            </div>
                        </div>

                        {/* Detection Results */}
                        <div className="space-y-4 pt-4 border-t border-white/5">
                            <h4 className="text-[10px] font-bold text-white/30 uppercase tracking-widest">Intelligence Matches</h4>
                            {detectedMatches.length > 0 ? (
                                <div className="grid grid-cols-1 gap-2">
                                    {detectedMatches.map((m, i) => (
                                        <motion.div
                                            key={i}
                                            initial={{ opacity: 0, x: -10 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            className="p-4 rounded-2xl bg-orange-500/5 border border-orange-500/20 flex justify-between items-center group cursor-pointer hover:bg-orange-500/10 transition-all"
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 rounded-lg bg-orange-500/10 text-orange-500">
                                                    <Fingerprint size={16} />
                                                </div>
                                                <span className="font-bold text-gray-200">{m.name}</span>
                                            </div>
                                            <div className="text-[10px] font-mono text-white/40">cat:{m.hashcat}</div>
                                        </motion.div>
                                    ))}
                                </div>
                            ) : (
                                <div className="p-6 rounded-2xl border border-dashed border-white/10 text-center text-white/20 text-xs italic italic">
                                    No hash detected...
                                </div>
                            )}
                        </div>

                        <div className="space-y-2">
                            <label className="text-[10px] font-bold text-white/30 uppercase tracking-widest px-2">Refining Strategy</label>
                            <select
                                value={selectedWordlist}
                                onChange={e => setSelectedWordlist(e.target.value)}
                                className="w-full bg-dark-900 border border-white/5 p-4 rounded-2xl font-bold text-sm text-gray-300 focus:outline-none focus:ring-2 ring-orange-500/20 transition-all cursor-pointer"
                            >
                                <option value="rockyou.txt">rockyou.txt (Ultimate)</option>
                                <option value="top10k.txt">Top 10k Passwords</option>
                                <option value="bruteforce">Brute Force (A-Z, 0-9)</option>
                                <option value="custom">Custom Refinery Wordlist</option>
                            </select>
                        </div>
                    </div>
                </div>

                {/* RIGHT: DASHBOARD & LOGS (8 cols) */}
                <div className="lg:col-span-8 space-y-8">

                    {/* TOP PANEL: SPEED & PROGRESS */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {/* Speedometer card */}
                        <div className="p-8 rounded-[2.5rem] bg-dark-800 border border-white/10 flex flex-col items-center justify-center shadow-2xl relative overflow-hidden group">
                            <div className="absolute top-0 right-0 p-8 text-white/5 group-hover:text-orange-500/10 transition-colors pointer-events-none">
                                <Gauge size={120} />
                            </div>
                            <Speedometer speed={refineryData?.speed || 0} />
                        </div>

                        {/* Progress card */}
                        <div className="p-8 rounded-[2.5rem] bg-dark-800 border border-white/10 flex flex-col justify-between shadow-2xl shadow-black/40">
                            <RefineryProgress progress={refineryData?.progress || 0} />

                            <div className="mt-8 flex gap-4">
                                {!isCracking ? (
                                    <button
                                        onClick={startRefinery}
                                        className="flex-1 py-4 bg-orange-500 hover:bg-orange-600 text-white rounded-2xl font-black uppercase tracking-[0.2em] shadow-lg shadow-orange-500/20 active:scale-95 transition-all flex items-center justify-center gap-3"
                                    >
                                        <Zap size={20} fill="currentColor" /> REFINING INITIALIZE
                                    </button>
                                ) : (
                                    <button
                                        onClick={stopRefinery}
                                        className="flex-1 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-2xl font-black uppercase tracking-[0.2em] active:scale-95 transition-all flex items-center justify-center gap-3"
                                    >
                                        <Square size={20} fill="currentColor" /> CEASE OPERATION
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* BOTTOM PANEL: LOGS & RESULT */}
                    <AnimatePresence mode="wait">
                        {refineryData?.status === 'completed' ? (
                            <motion.div
                                key="result"
                                initial={{ opacity: 0, scale: 0.95 }}
                                animate={{ opacity: 1, scale: 1 }}
                                className="p-10 rounded-[2.5rem] bg-green-500/10 border border-green-500/30 flex flex-col items-center justify-center text-center space-y-4 shadow-[0_0_50px_rgba(34,197,94,0.1)]"
                            >
                                <div className="p-4 rounded-3xl bg-green-500/20 text-green-400">
                                    <Unlock size={48} />
                                </div>
                                <h2 className="text-xl font-black text-green-400 uppercase tracking-widest">CRACKED SUCCESSFUL</h2>
                                <div className="text-6xl font-black font-mono text-white tracking-tighter drop-shadow-[0_0_15px_rgba(255,255,255,0.4)]">
                                    {refineryData.cracked_pass}
                                </div>
                                <button className="flex items-center gap-2 px-6 py-2 rounded-xl bg-green-500 text-dark-900 font-bold hover:scale-105 transition-all">
                                    <Copy size={16} /> COPY PASSWORD
                                </button>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="logs"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                            >
                                <MatrixLogs logs={refineryData?.logs || []} />
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default HashRefinery;
