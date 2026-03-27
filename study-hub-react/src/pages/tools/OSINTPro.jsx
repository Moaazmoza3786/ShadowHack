import React, { useState, useEffect, useRef } from 'react';
import {
    Globe, Search, Shield, Terminal, Copy,
    Activity, Cpu, Eye, Fingerprint,
    Zap, Share2, Box, Layers, Target,
    AlertTriangle, RefreshCw, Network,
    Layout, Database, Mail, Map, Lock,
    ChevronRight, ExternalLink, Download
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ForceGraph2D from 'react-force-graph-2d';
import { useToast } from '../../context/ToastContext';
import { useAppContext } from '../../context/AppContext';

// --- SUB-COMPONENTS ---

const MatrixLogs = ({ logs, logEndRef }) => (
    <div className="bg-black/80 border border-emerald-500/20 rounded-2xl p-6 font-mono relative overflow-hidden h-[400px]">
        <div className="absolute top-0 left-0 w-full h-1 bg-emerald-500/30 animate-scanline" />
        <div className="flex items-center justify-between mb-4 border-b border-emerald-500/20 pb-2">
            <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-[10px] text-emerald-500 font-black uppercase tracking-widest">Live Intel Stream</span>
            </div>
            <span className="text-[10px] text-emerald-500/50 uppercase">Matrix Protocol v2.4</span>
        </div>
        <div className="overflow-y-auto h-[320px] scrollbar-none space-y-1">
            {logs.map((log, i) => (
                <div key={i} className="text-[11px] text-emerald-400 group flex gap-3">
                    <span className="text-emerald-900 font-bold">[{i.toString().padStart(3, '0')}]</span>
                    <span className="group-hover:text-white transition-colors">
                        {log.startsWith('[!]') ? <span className="text-red-500 font-bold">{log}</span> :
                            log.startsWith('[+]') ? <span className="text-cyan-400 font-bold">{log}</span> : log}
                    </span>
                </div>
            ))}
            <div ref={logEndRef} />
        </div>
    </div>
);

const IntelGraph = ({ harvestData }) => (
    <div className="bg-dark-900 border border-white/10 rounded-[2.5rem] p-4 h-[600px] relative overflow-hidden">
        <div className="absolute top-8 left-8 z-10 pointer-events-none">
            <h3 className="text-2xl font-black italic uppercase italic tracking-tighter text-white">Relationship <span className="text-cyan-500">Mapping</span></h3>
            <p className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Dynamic Link Analysis Engine</p>
        </div>

        {harvestData?.nodes?.length > 0 ? (
            <ForceGraph2D
                graphData={{ nodes: harvestData.nodes, links: harvestData.links }}
                nodeLabel="label"
                nodeAutoColorBy="group"
                linkDirectionalParticles={2}
                linkDirectionalParticleSpeed={d => d.value * 0.01}
                backgroundColor="rgba(0,0,0,0)"
                width={1000}
                height={550}
                nodeCanvasObject={(node, ctx, globalScale) => {
                    const label = node.label;
                    const fontSize = 12 / globalScale;
                    ctx.font = `${fontSize}px Inter`;
                    const textWidth = ctx.measureText(label).width;
                    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

                    ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                    ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = node.color;
                    ctx.fillText(label, node.x, node.y);
                }}
            />
        ) : (
            <div className="h-full flex flex-col items-center justify-center text-center space-y-4">
                <Network size={64} className="text-gray-800 animate-pulse" />
                <p className="text-gray-600 font-mono text-sm uppercase">Waiting for graph data...</p>
            </div>
        )}
    </div>
);

const ScoreWidget = ({ score }) => (
    <div className="bg-dark-900 border border-white/10 rounded-3xl p-8 flex flex-col items-center justify-center relative overflow-hidden">
        <div className="absolute -top-10 -right-10 w-40 h-40 bg-red-500/10 rounded-full blur-3xl" />
        <div className="relative z-10 text-center space-y-2">
            <div className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em]">Attack Surface Exposure</div>
            <div className={`text-7xl font-black italic tracking-tighter ${score > 70 ? 'text-red-500' : score > 30 ? 'text-orange-500' : 'text-emerald-500'}`}>
                {score}%
            </div>
            <div className="flex gap-1 justify-center">
                {[...Array(5)].map((_, i) => (
                    <div key={i} className={`w-8 h-1.5 rounded-full ${i < (score / 20) ? 'bg-red-500' : 'bg-white/5'}`} />
                ))}
            </div>
        </div>
    </div>
);

const OSINTPro = () => {
    const { toast } = useToast();
    const { apiUrl } = useAppContext();
    const [activeTab, setActiveTab] = useState('harvest'); // harvest, Graph, Analysis
    const [target, setTarget] = useState('');
    const [isHarvesting, setIsHarvesting] = useState(false);
    const [harvestData, setHarvestData] = useState(null);
    const [logs, setLogs] = useState([]);
    const logEndRef = useRef(null);

    // Matrix Log Auto-scroll
    useEffect(() => {
        logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    // Polling for harvest status
    useEffect(() => {
        let interval;
        if (isHarvesting && target) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`${apiUrl}/tools/harvest/status`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target })
                    });
                    const data = await res.json();
                    if (data.success) {
                        setLogs(data.data.logs || []);
                        setHarvestData(data.data.data);
                        if (data.data.status === 'completed' || data.data.status === 'failed') {
                            setIsHarvesting(false);
                            if (data.data.status === 'completed') {
                                toast('Intelligence Harvest Complete!', 'success');
                                setHarvestData(prev => ({ ...prev, score: data.data.score }));
                            } else {
                                toast('Harvest Operation Failed', 'error');
                            }
                        }
                    }
                } catch (err) {
                    console.error("Status check failed", err);
                }
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [isHarvesting, target, apiUrl, toast]);

    const startHarvest = async () => {
        if (!target) return toast('Target coordinates required', 'warn');
        setIsHarvesting(true);
        setLogs(["[*] Initializing ShadowHarvester Engine..."]);
        try {
            const res = await fetch(`${apiUrl}/tools/harvest/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });
            const data = await res.json();
            if (!data.success) {
                toast(data.error, 'error');
                setIsHarvesting(false);
            }
        } catch (err) {
            console.error("Harvest start failed", err);
            toast('Backend connection error', 'error');
            setIsHarvesting(false);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast('Copied to clipboard', 'success');
    };


    const renderHarvest = () => (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Control Panel */}
            <div className="lg:col-span-1 space-y-6">
                <div className="bg-dark-900 border border-white/10 rounded-3xl p-8 space-y-6">
                    <div className="flex items-center gap-3">
                        <div className="p-3 bg-emerald-500/10 rounded-2xl text-emerald-500">
                            <Target size={24} />
                        </div>
                        <h3 className="text-xl font-black italic uppercase text-white tracking-tighter">New Operation</h3>
                    </div>

                    <div className="space-y-4">
                        <div className="relative">
                            <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-emerald-500/50" size={18} />
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Target Domain (e.g., target.com)"
                                className="w-full bg-black border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-emerald-400 font-mono outline-none focus:border-emerald-500"
                            />
                        </div>
                        <button
                            onClick={startHarvest}
                            disabled={isHarvesting}
                            className="w-full bg-emerald-500 hover:bg-emerald-400 text-dark-900 py-4 rounded-2xl font-black uppercase italic tracking-tighter shadow-xl shadow-emerald-500/20 flex items-center justify-center gap-3 transition-all active:scale-95 disabled:opacity-50"
                        >
                            {isHarvesting ? <RefreshCw className="animate-spin" /> : <Zap size={20} />}
                            INITIALIZE HARVESTER
                        </button>
                    </div>
                </div>

                <MatrixLogs logs={logs} logEndRef={logEndRef} />
            </div>

            {/* Results Display */}
            <div className="lg:col-span-2 space-y-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <ScoreWidget score={harvestData?.score || 0} />
                    <div className="bg-dark-900 border border-white/10 rounded-3xl p-8 space-y-4">
                        <h4 className="text-xs font-black text-gray-500 uppercase tracking-widest flex items-center gap-2">
                            <Fingerprint size={14} className="text-cyan-500" /> Identity Leaks Found
                        </h4>
                        <div className="space-y-3">
                            {harvestData?.leaked_credentials?.slice(0, 3).map((leak, i) => (
                                <div key={i} className="flex justify-between items-center bg-black/40 p-3 rounded-xl border border-white/5">
                                    <div className="text-xs font-mono text-white/80">{leak.email}</div>
                                    <div className="px-2 py-0.5 bg-red-500/10 text-red-500 text-[8px] font-black uppercase rounded">{leak.source}</div>
                                </div>
                            )) || <div className="text-gray-700 text-xs italic">No data yet...</div>}
                        </div>
                    </div>
                </div>

                <div className="bg-dark-900 border border-white/10 rounded-[2.5rem] p-10">
                    <div className="flex items-center justify-between mb-8">
                        <h4 className="text-xl font-black italic uppercase text-white tracking-tighter flex items-center gap-3">
                            <Database className="text-orange-500" /> Harvested Intelligence
                        </h4>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {harvestData?.sensitive_files?.map((file, i) => (
                            <div key={i} className="p-6 bg-black border border-white/5 rounded-2xl group hover:border-orange-500/30 transition-all">
                                <div className="flex justify-between items-start mb-4">
                                    <div className="p-3 bg-white/5 rounded-xl text-orange-500">
                                        <Layers size={20} />
                                    </div>
                                    <button onClick={() => copyToClipboard(file.url)} className="p-2 bg-white/5 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity">
                                        <ExternalLink size={14} className="text-gray-500" />
                                    </button>
                                </div>
                                <div className="text-sm font-black text-white italic uppercase mb-1">{file.name}</div>
                                <div className="text-[10px] text-gray-500 font-mono truncate">{file.url}</div>
                                <div className="mt-4 pt-4 border-t border-white/5 flex gap-2 overflow-x-auto">
                                    {Object.entries(file.metadata || {}).map(([key, val], idx) => (
                                        <span key={idx} className="px-2 py-0.5 bg-white/5 rounded text-[8px] text-gray-500 uppercase font-black tracking-widest">
                                            {key}: {val}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )) || <div className="text-gray-800 italic">Initiate search to see results...</div>}
                    </div>
                </div>
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* HEADER */}
            <div className="bg-dark-900 border border-white/10 rounded-[2rem] px-10 py-6 flex flex-col md:flex-row items-center justify-between gap-6">
                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-emerald-500/20 rounded-lg text-emerald-500">
                            <Shield size={24} />
                        </div>
                        <h1 className="text-3xl font-black italic tracking-tighter uppercase leading-none text-white">
                            Shadow<span className="text-emerald-500">Harvester</span>
                        </h1>
                    </div>
                    <div className="h-4 w-px bg-white/10 hidden md:block" />
                    <nav className="flex gap-1.5 p-1 bg-black/40 rounded-xl">
                        {[
                            { id: 'harvest', label: 'Monitor', icon: Layout },
                            { id: 'Graph', label: 'Graph Map', icon: Network },
                            { id: 'Analysis', label: 'Analysis', icon: Fingerprint }
                        ].map(t => (
                            <button
                                key={t.id}
                                onClick={() => setActiveTab(t.id)}
                                className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all flex items-center gap-2 ${activeTab === t.id ? 'bg-emerald-500 text-dark-900' : 'text-gray-500 hover:text-white hover:bg-white/5'}`}
                            >
                                <t.icon size={14} /> {t.label}
                            </button>
                        ))}
                    </nav>
                </div>

                <div className="flex items-center gap-4">
                    <div className="text-right hidden sm:block font-mono">
                        <div className="text-[8px] font-bold text-gray-500 uppercase">Operational Status</div>
                        <div className="text-[10px] text-emerald-500 animate-pulse">SYSTEM_ACTIVE_[RELAY_OK]</div>
                    </div>
                </div>
            </div>

            {/* CONTENT */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="min-h-[600px]"
                >
                    {activeTab === 'harvest' && renderHarvest()}
                    {activeTab === 'Graph' && <IntelGraph harvestData={harvestData} />}
                    {activeTab === 'Analysis' && (
                        <div className="p-20 bg-dark-900 border border-white/10 rounded-[3rem] text-center space-y-6">
                            <Fingerprint size={64} className="mx-auto text-gray-800" />
                            <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter leading-none">Deep Analysis Engine</h3>
                            <p className="text-gray-500 max-w-sm mx-auto">This module performs recursive correlation across multiple ID databases. Results will populate here upon harvest completion.</p>
                        </div>
                    )}
                </motion.div>
            </AnimatePresence>

            {/* Matrix Rain Background Effect (Optional/Subtle) */}
            <div className="fixed inset-0 pointer-events-none z-[-1] opacity-[0.03]">
                <div className="absolute inset-0 bg-matrix-gradient" />
            </div>
        </div>
    );
};

export default OSINTPro;
