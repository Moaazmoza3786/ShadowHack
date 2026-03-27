import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Shield, Search, Eye, Activity, Globe,
    Server, RefreshCw, AlertCircle, CheckCircle,
    LayoutGrid, List, Plus, Trash2, Terminal,
    Database, Map, ExternalLink, ChevronRight,
    Filter, Clock
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- UI COMPONENTS ---

const StatusBadge = ({ status }) => {
    const isNew = status === 'NEW';
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-widest ${isNew
            ? 'bg-green-500/20 text-green-400 border border-green-500/30 animate-pulse'
            : 'bg-white/5 text-white/40 border border-white/10'
            }`}>
            {status}
        </span>
    );
};

const MonitorLogs = ({ logs }) => {
    const logRef = useRef(null);
    useEffect(() => {
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, [logs]);

    return (
        <div className="bg-black/40 border border-blue-500/10 rounded-2xl p-4 font-mono h-[200px] overflow-hidden relative">
            <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.05)_50%)] bg-[length:100%_4px] z-10" />
            <div ref={logRef} className="h-full overflow-y-auto space-y-1 scrollbar-thin scrollbar-thumb-blue-500/20 pr-2">
                {logs.map((log, i) => (
                    <div key={i} className="text-[11px] flex gap-2">
                        <span className="text-white/20 whitespace-nowrap">{log.split('] ')[0]}]</span>
                        <span className={`${log.includes('[!]') ? 'text-blue-400 font-bold' :
                            log.includes('[+]') ? 'text-green-400' : 'text-white/50'
                            }`}>
                            {log.split('] ')[1]}
                        </span>
                    </div>
                ))}
                {logs.length === 0 && <div className="text-white/10 italic text-center pt-8">Awaiting initialization...</div>}
            </div>
        </div>
    );
};

const SubdomainMonitor = () => {
    const { toast } = useToast();
    const [domainInput, setDomainInput] = useState('');
    const [monitors, setMonitors] = useState({});
    const [selectedDomain, setSelectedDomain] = useState(null);
    const [inventory, setInventory] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [filter, setFilter] = useState('');

    // Fetch All Monitors
    const fetchMonitors = async () => {
        try {
            const res = await fetch('/api/tools/subdomain/status');
            const data = await res.json();
            if (data.success) setMonitors(data.monitors);
        } catch (err) {
            console.error("Failed to fetch monitors:", err);
        }
    };

    // Fetch Specific Domain Results
    const fetchResults = async (domain) => {
        setIsLoading(true);
        try {
            const res = await fetch(`/api/tools/subdomain/results/${domain}`);
            const data = await res.json();
            if (data.success) {
                setInventory(data.assets);
                setSelectedDomain(domain);
            }
        } catch (err) {
            toast("Failed to load inventory", "error");
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchMonitors();
        const interval = setInterval(fetchMonitors, 5000);
        return () => clearInterval(interval);
    }, []);

    const addMonitor = async () => {
        if (!domainInput.trim()) return toast("Enter a target domain", "warning");
        const activeProjectId = localStorage.getItem('activeProjectId');
        try {
            const res = await fetch('/api/tools/subdomain/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domainInput, project_id: activeProjectId })
            });
            const data = await res.json();
            if (data.success) {
                toast("Silent Monitor Activated", "success");
                setDomainInput('');
                fetchMonitors();
            } else {
                toast(data.message || "Failed to add", "error");
            }
        } catch (err) {
            toast("Connection error", "error");
        }
    };

    const filteredInventory = inventory.filter(s =>
        s.subdomain.toLowerCase().includes(filter.toLowerCase())
    );

    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-white/10 pb-10">
                <div className="space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="p-3 rounded-2xl bg-blue-500/20 border border-blue-500/30 text-blue-500 shadow-lg shadow-blue-500/10">
                            <Eye size={32} />
                        </div>
                        <div>
                            <h1 className="text-5xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-indigo-500 to-blue-400 bg-[length:200%_auto] animate-gradient">
                                SUBDOMAIN MONITOR
                            </h1>
                            <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-xs flex items-center gap-2">
                                <Clock size={12} /> Automated Active Surface Tracking
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <div className="relative group">
                        <input
                            type="text"
                            value={domainInput}
                            onChange={(e) => setDomainInput(e.target.value)}
                            placeholder="TARGET DOMAIN (e.g. google.com)"
                            className="bg-dark-800 border border-white/10 rounded-2xl px-6 py-4 w-72 focus:outline-none focus:border-blue-500/50 transition-all font-mono text-sm"
                        />
                        <button
                            onClick={addMonitor}
                            className="absolute right-2 top-2 bottom-2 px-4 bg-blue-500 hover:bg-blue-600 text-white rounded-xl shadow-lg shadow-blue-500/20 transition-all"
                        >
                            <Plus size={20} />
                        </button>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

                {/* LEFT: MONITOR LIST (4 cols) */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="p-8 rounded-[2.5rem] bg-dark-800 border border-white/10 space-y-6 shadow-2xl shadow-black/40">
                        <h3 className="text-lg font-black text-white italic flex items-center gap-2">
                            <Activity size={20} className="text-blue-500" /> ACTIVE MONITORS
                        </h3>

                        <div className="space-y-3">
                            {Object.entries(monitors).map(([domain, data]) => (
                                <motion.div
                                    key={domain}
                                    onClick={() => fetchResults(domain)}
                                    className={`p-5 rounded-3xl border transition-all cursor-pointer group ${selectedDomain === domain
                                        ? 'bg-blue-500/10 border-blue-500/40 shadow-lg shadow-blue-500/5'
                                        : 'bg-dark-900 border-white/5 hover:border-white/20'
                                        }`}
                                >
                                    <div className="flex justify-between items-start mb-3">
                                        <div className="space-y-1">
                                            <div className="font-black text-white flex items-center gap-2">
                                                {domain}
                                                <ChevronRight size={14} className="group-hover:translate-x-1 transition-transform" />
                                            </div>
                                            <div className="text-[10px] font-mono text-white/30 uppercase tracking-widest">
                                                Interval: {data.interval}h
                                            </div>
                                        </div>
                                        {data.new_assets_count > 0 && (
                                            <div className="bg-green-500 text-[10px] font-black px-2 py-0.5 rounded-full shadow-[0_0_10px_rgba(34,197,94,0.3)]">
                                                {data.new_assets_count} NEW
                                            </div>
                                        )}
                                    </div>

                                    <div className="space-y-3">
                                        <div className="flex justify-between text-[10px] font-bold">
                                            <span className="text-white/20 uppercase tracking-widest">Current Status</span>
                                            <span className="text-blue-400 uppercase">{data.status}</span>
                                        </div>
                                        <MonitorLogs logs={data.logs.slice(-5)} />
                                    </div>
                                </motion.div>
                            ))}
                            {Object.keys(monitors).length === 0 && (
                                <div className="text-center py-12 p-8 border border-dashed border-white/5 rounded-3xl">
                                    <Search size={32} className="mx-auto text-white/10 mb-4" />
                                    <p className="text-xs text-white/20 italic italic">No active monitors found... Start by adding a domain above.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* RIGHT: INVENTORY (8 cols) */}
                <div className="lg:col-span-8 space-y-6">
                    {selectedDomain ? (
                        <div className="space-y-6">
                            {/* Inventory Header */}
                            <div className="p-8 rounded-[2.5rem] bg-dark-800 border border-white/10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 shadow-2xl">
                                <div className="flex items-center gap-4">
                                    <div className="p-4 rounded-2xl bg-blue-500/10 text-blue-500">
                                        <Globe size={24} />
                                    </div>
                                    <div>
                                        <h2 className="text-2xl font-black text-white italic uppercase tracking-tight">{selectedDomain}</h2>
                                        <p className="text-[10px] font-mono text-white/30 tracking-[0.2em] uppercase mt-1">
                                            {inventory.length} Assets Identified
                                        </p>
                                    </div>
                                </div>

                                <div className="flex gap-4 w-full md:w-auto">
                                    <div className="relative flex-1 md:flex-none">
                                        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-white/20" />
                                        <input
                                            type="text"
                                            value={filter}
                                            onChange={e => setFilter(e.target.value)}
                                            placeholder="FILTER ASSETS..."
                                            className="bg-dark-900 border border-white/5 rounded-2xl pl-12 pr-6 py-3 w-full md:w-64 focus:outline-none focus:border-blue-500/30 transition-all text-xs font-mono"
                                        />
                                    </div>
                                    <button className="p-3 bg-white/5 hover:bg-white/10 rounded-2xl border border-white/10 transition-all text-white/60">
                                        <Filter size={20} />
                                    </button>
                                </div>
                            </div>

                            {/* Inventory Table */}
                            <div className="p-4 rounded-[2.5rem] bg-dark-800 border border-white/10 shadow-2xl overflow-hidden">
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left">
                                        <thead>
                                            <tr className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] border-b border-white/5">
                                                <th className="px-6 py-5">Subdomain</th>
                                                <th className="px-6 py-5">IP Address</th>
                                                <th className="px-6 py-5">Status</th>
                                                <th className="px-6 py-5">Last Detected</th>
                                                <th className="px-6 py-5">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/5">
                                            {filteredInventory.map((item, i) => (
                                                <motion.tr
                                                    key={i}
                                                    initial={{ opacity: 0, y: 10 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    transition={{ delay: i * 0.05 }}
                                                    className="group hover:bg-white/5 transition-colors"
                                                >
                                                    <td className="px-6 py-5">
                                                        <div className="flex items-center gap-3">
                                                            <div className="w-8 h-8 rounded-lg bg-blue-500/5 border border-blue-500/10 flex items-center justify-center text-blue-500">
                                                                <Server size={14} />
                                                            </div>
                                                            <span className="font-bold text-gray-200">{item.subdomain}</span>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-5 font-mono text-xs text-white/50">{item.ip}</td>
                                                    <td className="px-6 py-5">
                                                        <StatusBadge status={item.status} />
                                                    </td>
                                                    <td className="px-6 py-5 font-mono text-[10px] text-white/30">
                                                        {new Date(item.last_seen).toLocaleDateString()}
                                                    </td>
                                                    <td className="px-6 py-5">
                                                        <div className="flex gap-2">
                                                            <button className="p-2 bg-white/5 hover:bg-blue-500/20 text-white/40 hover:text-blue-400 rounded-lg transition-all">
                                                                <ExternalLink size={14} />
                                                            </button>
                                                            <button className="p-2 bg-white/5 hover:bg-blue-500/20 text-white/40 hover:text-blue-400 rounded-lg transition-all">
                                                                <Map size={14} />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </motion.tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                                {filteredInventory.length === 0 && (
                                    <div className="py-20 text-center">
                                        <div className="text-white/10 italic text-sm">No assets match your search...</div>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        <div className="h-[600px] flex flex-col items-center justify-center space-y-6 p-12 rounded-[3.5rem] border border-dashed border-white/5">
                            <div className="p-10 rounded-[3rem] bg-dark-800 border border-white/10 shadow-2xl relative">
                                <div className="absolute -inset-4 bg-blue-500/20 blur-2xl rounded-full opacity-50" />
                                <Shield size={100} className="text-blue-500 relative z-10" />
                            </div>
                            <div className="text-center space-y-2">
                                <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">Inventory Locked</h2>
                                <p className="text-white/20 font-mono text-xs uppercase tracking-widest max-w-sm mx-auto">
                                    Select an active monitor from the list to reveal infrastructure intelligence
                                </p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SubdomainMonitor;
