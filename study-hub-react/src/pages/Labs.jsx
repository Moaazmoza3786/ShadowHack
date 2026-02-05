import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAppContext } from '../context/AppContext';
import { machines } from '../data/machines';
import {
    Terminal as TerminalIcon,
    Cpu,
    Shield,
    Activity,
    Play,
    Power,
    Timer,
    Globe,
    Lock,
    Search,
    ChevronRight,
    Zap,
    AlertCircle,
    RotateCcw
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLabManager } from '../hooks/useLabManager';

const MachineCard = ({ machine }) => {
    const navigate = useNavigate();
    const {
        status,
        isLoading,
        connectionInfo,
        startLab,
        stopLab
    } = useLabManager(machine.id);

    const handleStart = () => {
        // startLab(); -> Moved to Workspace
        navigate(`/labs/workspace/${machine.id}`);
    };

    const handleStop = () => {
        stopLab();
    };

    return (
        <div className="group relative rounded-3xl bg-dark-800/40 border border-white/5 overflow-hidden hover:border-primary-500/30 transition-all duration-500 shadow-2xl">
            <div className="absolute inset-x-0 bottom-0 h-1 bg-primary-500/10 group-hover:bg-primary-500 transition-all duration-700 shadow-[0_0_15px_rgba(0,242,234,0.5)]" />
            <div className="p-8 space-y-6">
                <div className="flex items-start justify-between">
                    <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:scale-110 group-hover:border-primary-500/50 transition-all duration-500 backdrop-blur-sm shadow-xl">
                        <Cpu className="text-gray-500 group-hover:text-primary-500 transition-colors group-hover:drop-shadow-[0_0_8px_rgba(0,242,234,0.6)]" size={32} />
                    </div>
                    <div className="flex flex-col items-end">
                        <span className="px-2 py-1 rounded-md bg-dark-900 border border-white/10 text-[9px] font-black uppercase tracking-widest text-primary-500">
                            {machine.level}
                        </span>
                        <div className={`mt-2 flex items-center gap-2 px-2 py-0.5 rounded-full border text-[8px] font-black uppercase tracking-widest ${status === 'running' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
                            status === 'starting' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                                'bg-red-500/10 text-red-500 border-red-500/20'
                            }`}>
                            <div className={`w-1.5 h-1.5 rounded-full ${status === 'running' ? 'bg-green-500 animate-pulse' :
                                status === 'starting' ? 'bg-yellow-500 animate-spin' :
                                    'bg-red-500'
                                }`} />
                            {status === 'running' ? 'online' : status}
                        </div>
                    </div>
                </div>

                <div>
                    <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter leading-none mb-2">
                        {machine.name}
                    </h3>
                    <p className="text-xs text-gray-500 leading-relaxed min-h-[40px]">
                        {machine.desc}
                    </p>
                </div>

                <div className="grid grid-cols-2 gap-4 py-6 border-t border-b border-white/5">
                    <div className="flex flex-col">
                        <span className="text-[8px] font-black text-gray-600 uppercase tracking-widest mb-1">OS System</span>
                        <div className="flex items-center gap-2 text-xs font-bold text-gray-300">
                            <Shield size={14} className="text-primary-500" />
                            {machine.os}
                        </div>
                    </div>
                    <div className="flex flex-col">
                        <span className="text-[8px] font-black text-gray-600 uppercase tracking-widest mb-1">IP Address</span>
                        <div className="font-mono text-xs text-primary-500 font-bold tracking-wider">
                            {status === 'running' ? `${connectionInfo?.ip}:${connectionInfo?.port}` : '---.---.---.---'}
                        </div>
                    </div>
                </div>

                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="flex flex-col">
                            <span className="text-[10px] font-black text-white italic uppercase">{machine.points} XP</span>
                            <span className="text-[8px] font-black text-gray-600 uppercase tracking-widest">Reward</span>
                        </div>
                    </div>

                    <button
                        onClick={handleStart}
                        className="flex items-center gap-3 px-6 py-3 bg-primary-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter text-sm hover:bg-primary-400 transition-all shadow-lg shadow-primary-500/20 active:scale-95"
                    >
                        <Power size={18} />
                        Initiate
                    </button>
                </div>
            </div>

            {/* Hologram Effect on Start */}
            <AnimatePresence>
                {status === 'starting' && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 bg-primary-500/5 backdrop-blur-[2px] flex items-center justify-center flex-col gap-4"
                    >
                        <Activity className="text-primary-500 animate-pulse" size={48} />
                        <span className="text-xs font-black text-primary-500 uppercase tracking-[0.3em] animate-pulse">Establishing Neural Link...</span>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

const Labs = () => {
    const { t } = useAppContext();
    const [activeCategory, setActiveCategory] = useState('all');

    return (
        <div className="space-y-12 pb-20">
            {/* Hero Section */}
            <header className="relative py-20 px-12 rounded-[4rem] bg-dark-800 border border-white/5 overflow-hidden group">
                <div className="absolute inset-0 bg-cyber-grid opacity-10" />
                <div className="absolute -right-32 -top-32 w-[600px] h-[600px] bg-primary-500/5 blur-[120px] rounded-full group-hover:bg-primary-500/10 transition-all duration-1000" />

                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-12">
                    <div className="space-y-6 max-w-2xl">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20">
                            <Activity size={12} className="text-primary-500" />
                            <span className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Network Topology Map: LOADED</span>
                        </div>
                        <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-[0.8] glitch-text">
                            TARGET <span className="text-primary-500 text-glow">LABS</span>
                        </h1>
                        <p className="text-gray-400 text-xl font-medium leading-relaxed">
                            Deploy high-performance virtual machines and practice your offensive security tradecraft in a controlled, isolated network.
                        </p>

                        <div className="flex items-center gap-6 pt-4">
                            <div className="flex flex-col">
                                <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">Active VMs</span>
                                <span className="text-2xl font-black text-white italic tracking-tighter">12 / 64</span>
                            </div>
                            <div className="h-10 w-px bg-white/5" />
                            <div className="flex flex-col">
                                <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">Average Latency</span>
                                <span className="text-2xl font-black text-green-500 italic tracking-tighter">14 MS</span>
                            </div>
                        </div>
                    </div>

                    <div className="w-full md:w-80 p-8 rounded-[2.5rem] bg-white/5 border border-white/10 backdrop-blur-xl space-y-6">
                        <div className="flex items-center justify-between">
                            <h3 className="text-sm font-black text-white uppercase italic tracking-widest">VPN Access</h3>
                            <div className="px-2 py-0.5 rounded-md bg-green-500/10 border border-green-500/20 text-[8px] font-black text-green-500 uppercase tracking-widest">Connected</div>
                        </div>
                        <div className="space-y-4">
                            <div className="p-4 rounded-2xl bg-dark-900/50 border border-white/5">
                                <p className="text-[9px] font-black text-gray-600 uppercase tracking-widest mb-1">Assigned Tunnel</p>
                                <p className="text-xs font-mono text-primary-500 font-bold">tun0 (10.10.14.23)</p>
                            </div>
                            <button className="w-full py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-black text-white uppercase tracking-[0.2em] hover:bg-white/10 transition-all flex items-center justify-center gap-2">
                                <Zap size={14} className="text-yellow-500" />
                                DOWNLOAD OVPN
                            </button>
                        </div>
                    </div>
                </div>
            </header>

            {/* Filters */}
            <div className="flex flex-col lg:flex-row gap-8 items-center justify-between">
                <div className="flex items-center gap-3 overflow-x-auto pb-2 w-full lg:w-auto">
                    {['all', 'beginner', 'intermediate', 'hard', 'insane'].map(lvl => (
                        <button
                            key={lvl}
                            onClick={() => setActiveCategory(lvl)}
                            className={`
                                px-6 py-3 rounded-2xl border transition-all duration-300 font-bold uppercase tracking-widest text-[10px] whitespace-nowrap
                                ${activeCategory === lvl
                                    ? 'bg-primary-500 border-primary-500 text-dark-900'
                                    : 'bg-dark-800/40 border-white/5 text-gray-500 hover:text-white'}
                            `}
                        >
                            {lvl}
                        </button>
                    ))}
                </div>

                <div className="relative w-full lg:w-96 group">
                    <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-primary-500 transition-colors" size={18} />
                    <input
                        type="text"
                        placeholder="Search targets..."
                        className="w-full bg-dark-800/40 border border-white/5 rounded-2xl py-3.5 pl-14 pr-6 focus:outline-none focus:border-primary-500/50 transition-all text-gray-100 placeholder:text-gray-600 text-sm"
                    />
                </div>
            </div>

            {/* Machines Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-8">
                {machines.map(m => (
                    <MachineCard key={m.id} machine={m} />
                ))}
            </div>

            {/* Documentation / Info Overlay */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-8 pt-12">
                <div className="p-8 rounded-[2.5rem] bg-gradient-to-br from-white/5 to-transparent border border-white/5 space-y-4">
                    <AlertCircle className="text-yellow-500" size={32} />
                    <h3 className="text-xl font-black text-white italic tracking-tighter uppercase leading-none">Usage Policy</h3>
                    <p className="text-xs text-gray-500 leading-relaxed font-medium">Please do not perform DoS/DDoS attacks on internal targets. Any abuse of infrastructure will result in automatic ban.</p>
                </div>
                <div className="flex-1 xl:col-span-2 p-8 rounded-[2.5rem] bg-dark-800/60 border border-white/5 flex items-center justify-between group cursor-pointer hover:border-primary-500/20 transition-all">
                    <div className="flex items-center gap-8">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center neon-glow-primary shadow-[0_0_20px_rgba(0,242,234,0.4)]">
                            <Shield className="text-dark-900 fill-dark-900" size={24} />
                        </div>
                        <div>
                            <h3 className="text-2xl font-black text-white italic tracking-tighter uppercase leading-none mb-1">Lab Documentation</h3>
                            <p className="text-xs text-gray-500 font-bold uppercase tracking-widest">Learn how to configure your VPN and access targets</p>
                        </div>
                    </div>
                    <ChevronRight className="text-primary-500 group-hover:translate-x-2 transition-transform" />
                </div>
            </div>
        </div>
    );
};

export default Labs;
