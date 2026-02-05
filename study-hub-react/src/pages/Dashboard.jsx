import React from 'react';
import { useAppContext } from '../context/AppContext';
import { useMissionSystem } from '../hooks/useMissionSystem';
import {
    Zap,
    Shield,
    TrendingUp,
    ArrowUpRight,
    Activity,
    Target,
    Terminal as TerminalIcon,
    ChevronRight,
    DollarSign,
    Flame,
    Star,
    Cpu,
    Copy,
    Play,
    Square,
    ExternalLink,
    RefreshCw
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { CourseCard } from '../components/CourseCard';
import { courses } from '../data/courses';
import { motion, AnimatePresence } from 'framer-motion';
import { useLabManager } from '../hooks/useLabManager';
import { useToast } from '../context/ToastContext';
import CyberTerminal from '../components/CyberTerminal';

const StatCard = ({ label, value, icon: Icon, color, suffix = "" }) => (
    <div className="relative group overflow-hidden bg-dark-800/40 border border-white/5 rounded-[2rem] p-8 hover:border-white/10 transition-all duration-500">
        <div className={`absolute top-0 right-0 w-32 h-32 opacity-10 group-hover:opacity-20 blur-3xl rounded-full transition-opacity duration-500 ${color}`} />
        <div className="relative z-10 flex items-center justify-between pointer-events-none">
            <div>
                <p className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] mb-2">{label}</p>
                <div className="flex items-baseline gap-2">
                    <p className="text-4xl font-black text-white italic tracking-tighter uppercase">{value}</p>
                    <span className="text-xs font-bold text-gray-500 uppercase">{suffix}</span>
                </div>
            </div>
            <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border border-white/10 backdrop-blur-xl group-hover:scale-110 transition-transform duration-500`}>
                <Icon className={`${color.replace('bg-', 'text-')} w-7 h-7`} />
            </div>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/5 overflow-hidden">
            <motion.div
                initial={{ width: 0 }}
                animate={{ width: "65%" }}
                className={`h-full ${color}`}
            />
        </div>
    </div>
);

const DailyChallengeSection = () => {
    const { toast } = useToast();
    const challengeMachine = {
        id: 'dvwa', // Hardcoded for today, could be dynamic
        name: 'DVWA: SQL Injection Mastery',
        difficulty: 'Medium',
        reward: '500 XP',
        tags: ['SQLi', 'Web']
    };

    const { status, isLoading, connectionInfo, startLab, stopLab } = useLabManager(challengeMachine.id);

    return (
        <section className="relative group overflow-hidden bg-dark-800 border-2 border-primary-500/20 rounded-[3rem] p-12 shadow-2xl shadow-primary-500/10 mb-12">
            <div className="absolute inset-0 bg-cyber-grid opacity-10" />
            <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
                <div className="lg:col-span-7 space-y-6">
                    <div className="flex items-center gap-4">
                        <span className="px-4 py-1.5 rounded-full bg-primary-500 text-dark-900 text-[10px] font-black uppercase tracking-widest shadow-lg shadow-primary-500/20">
                            DAILY CHALLENGE
                        </span>
                        <div className="flex items-center gap-2">
                            <Activity size={14} className="text-primary-500" />
                            <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Rotates in 14h 22m</span>
                        </div>
                    </div>

                    <div className="space-y-4">
                        <h2 className="text-5xl font-black text-white italic tracking-tighter uppercase leading-[0.9]">
                            {challengeMachine.name}
                        </h2>
                        <div className="flex flex-wrap gap-3">
                            {challengeMachine.tags.map(tag => (
                                <span key={tag} className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-[10px] font-black text-primary-500/60 uppercase tracking-widest">
                                    {tag}
                                </span>
                            ))}
                            <span className="px-4 py-2 rounded-xl bg-orange-500/10 border border-orange-500/20 text-[10px] font-black text-orange-500 uppercase tracking-widest">
                                {challengeMachine.difficulty} Difficulty
                            </span>
                        </div>
                    </div>

                    <p className="text-gray-400 font-medium leading-relaxed max-w-xl">
                        Identify and exploit the SQL injection point to extract the target flag. Today's mission yields double Neural XP for first-time completion.
                    </p>

                    <div className="flex flex-wrap items-center gap-6 pt-4">
                        {status === 'running' ? (
                            <>
                                <button
                                    onClick={stopLab}
                                    className="px-8 py-4 bg-red-500/10 text-red-500 border border-red-500/20 rounded-2xl font-black uppercase italic tracking-tighter hover:bg-red-500/20 transition-all flex items-center gap-3"
                                >
                                    <Square size={18} fill="currentColor" />
                                    TERMINATE MACHINE
                                </button>
                                {connectionInfo && (
                                    <div className="px-6 py-4 bg-primary-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter shadow-xl shadow-primary-500/20 flex items-center gap-4">
                                        <span>IP: {connectionInfo.ip}:{connectionInfo.port}</span>
                                        <button onClick={() => { navigator.clipboard.writeText(`${connectionInfo.ip}:${connectionInfo.port}`); toast('URI Copied', 'success'); }}>
                                            <Copy size={16} />
                                        </button>
                                    </div>
                                )}
                            </>
                        ) : (
                            <button
                                onClick={startLab}
                                disabled={isLoading}
                                className="px-10 py-5 bg-primary-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter hover:scale-105 transition-all shadow-xl shadow-primary-500/30 flex items-center gap-3"
                            >
                                {isLoading ? <RefreshCw className="animate-spin" /> : <Play size={20} fill="currentColor" />}
                                {isLoading ? 'SYNCING...' : 'DEPOY TARGET MACHINE'}
                            </button>
                        )}
                        <div className="flex flex-col">
                            <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">Reward Portfolio</span>
                            <span className="text-xl font-black text-green-500 italic uppercase">+{challengeMachine.reward}</span>
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-5 hidden lg:flex items-center justify-center">
                    <div className="relative">
                        <div className="absolute inset-0 bg-primary-500/20 blur-3xl rounded-full animate-pulse" />
                        <div className="relative w-64 h-64 rounded-[3rem] bg-dark-900 border-2 border-white/10 flex items-center justify-center group-hover:scale-110 group-hover:border-primary-500/50 transition-all duration-700 overflow-hidden shadow-2xl">
                            <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                            <Target size={120} className="text-primary-500/20 absolute" />
                            <Cpu size={80} className="text-primary-500 animate-pulse" />
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
};

const Dashboard = () => {
    const { t, user } = useAppContext();
    const { state } = useMissionSystem();

    return (
        <div className="space-y-12">
            {/* Header / Hero */}
            <header className="relative py-12 px-12 rounded-[3rem] bg-gradient-to-br from-dark-800/80 to-dark-900 border border-white/5 overflow-hidden group">
                <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                <div className="absolute -right-20 -top-20 w-96 h-96 bg-primary-500/10 blur-[100px] rounded-full group-hover:bg-primary-500/20 transition-all duration-1000" />
                <div className="absolute -left-20 -bottom-20 w-96 h-96 bg-accent-500/10 blur-[100px] rounded-full group-hover:bg-accent-500/20 transition-all duration-1000" />

                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-8">
                    <div className="space-y-4">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20">
                            <Activity size={12} className="text-primary-500 animate-pulse" />
                            <span className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Neural Link Synchronized • High Fidelity</span>
                        </div>
                        <div className="flex flex-col gap-2">
                            <h1 className="text-4xl font-black italic tracking-tighter uppercase underline decoration-primary-500/50 underline-offset-8">
                                OPERATIONS CENTER
                            </h1>
                            <div className="flex items-center gap-3">
                                <span className="px-2 py-1 rounded-lg bg-primary-500/20 text-primary-500 border border-primary-500/30 text-[10px] font-bold animate-pulse">
                                    V2.0 PRO UNLOCKED
                                </span>
                                <span className="text-[10px] text-white/40 font-mono tracking-widest uppercase italic">
                                    Status: Active & Secure
                                </span>
                            </div>
                        </div>
                        <p className="text-gray-400 max-w-xl text-lg font-medium leading-relaxed">
                            {state.mission.active
                                ? `Active Operation: ${state.mission.id.toUpperCase()}. Neutralize all threats and extract sensitive assets.`
                                : "No active operations detected. Monitor the Darknet for new high-stakes contracts."
                            }
                        </p>
                    </div>

                    <div className="flex flex-col items-end gap-2">
                        <div className="p-1.5 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md flex items-center gap-6">
                            <div className="px-4 py-2 text-right">
                                <p className="text-[10px] font-black text-primary-500 uppercase tracking-widest leading-none mb-1">Operative Rank</p>
                                <div className="flex items-center gap-2 justify-end">
                                    <span className="text-xl font-black text-white italic">{user.rank}</span>
                                    <Shield size={16} className="text-accent-500" />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </header>

            {/* Stats Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
                <StatCard label="Total Credits" value={state.money} icon={DollarSign} color="bg-green-500" suffix="CR" />
                <StatCard label="Infiltration Heat" value={state.heat} icon={Flame} color="bg-red-500" suffix="%" />
                <StatCard label="Darknet Rep" value={state.reputation} icon={Star} color="bg-primary-500" suffix="REP" />
                <StatCard label="Neural XP" value={user.points} icon={Zap} color="bg-yellow-500" suffix="XP" />
            </div>

            {/* Daily Challenge Highlight */}
            <DailyChallengeSection />

            {/* Content Sections */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-12">
                <main className="xl:col-span-8 space-y-12">
                    <div className="flex items-center justify-between mb-8">
                        <div className="flex items-center gap-4">
                            <div className="w-1.5 h-10 bg-primary-500 rounded-full" />
                            <div>
                                <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">Strategic Paths</h2>
                                <p className="text-xs text-gray-500 uppercase font-black tracking-widest">Curated learning trajectories for your evolution</p>
                            </div>
                        </div>
                        <Link to="/courses" className="group flex items-center gap-2 text-xs font-black text-gray-500 hover:text-primary-500 transition-colors uppercase tracking-widest">
                            All Operations <ArrowUpRight size={14} className="group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform" />
                        </Link>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {courses.slice(0, 4).map((course, idx) => (
                            <motion.div
                                key={course.id}
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: idx * 0.1 }}
                            >
                                <CourseCard course={course} />
                            </motion.div>
                        ))}
                    </div>
                </main>

                <aside className="xl:col-span-4 space-y-12">
                    <div className="space-y-8">
                        <div className="flex items-center gap-4">
                            <div className="w-1.5 h-10 bg-accent-500 rounded-full" />
                            <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">Command Center</h2>
                        </div>

                        <div className="space-y-4">
                            <Link to="/tools" className="group relative block p-8 rounded-[2rem] bg-gradient-to-br from-cyan-500/20 to-transparent border border-cyan-500/20 hover:border-cyan-500/40 transition-all duration-500 overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 blur-3xl group-hover:bg-cyan-500/10 transition-colors" />
                                <div className="relative z-10 flex items-center justify-between">
                                    <div className="flex items-center gap-6">
                                        <div className="w-14 h-14 rounded-2xl bg-cyan-500 flex items-center justify-center text-white shadow-[0_0_20px_rgba(6,182,212,0.3)] group-hover:scale-110 transition-transform duration-500">
                                            <Cpu size={28} />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-black text-white uppercase italic tracking-tighter leading-none mb-1">Security Tools</h3>
                                            <p className="text-[10px] font-black text-cyan-500/60 uppercase tracking-widest">Penetration Testing Suite</p>
                                        </div>
                                    </div>
                                    <ChevronRight className="text-cyan-500 opacity-0 group-hover:opacity-100 transition-opacity translate-x-[-10px] group-hover:translate-x-0 group-hover:duration-500" />
                                </div>
                            </Link>

                            <Link to="/career-hub" className="group relative block p-8 rounded-[2rem] bg-gradient-to-br from-indigo-500/20 to-transparent border border-indigo-500/20 hover:border-indigo-500/40 transition-all duration-500 overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 blur-3xl group-hover:bg-indigo-500/10 transition-colors" />
                                <div className="relative z-10 flex items-center justify-between">
                                    <div className="flex items-center gap-6">
                                        <div className="w-14 h-14 rounded-2xl bg-indigo-500 flex items-center justify-center text-white shadow-[0_0_20px_rgba(99,102,241,0.3)] group-hover:scale-110 transition-transform duration-500">
                                            <Target size={28} />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-black text-white uppercase italic tracking-tighter leading-none mb-1">Career Pathways</h3>
                                            <p className="text-[10px] font-black text-indigo-500/60 uppercase tracking-widest">Job Ready Tracks</p>
                                        </div>
                                    </div>
                                    <ChevronRight className="text-indigo-500 opacity-0 group-hover:opacity-100 transition-opacity translate-x-[-10px] group-hover:translate-x-0 group-hover:duration-500" />
                                </div>
                            </Link>

                            <Link to="/second-brain" className="group relative block p-8 rounded-[2rem] bg-gradient-to-br from-primary-500/20 to-transparent border border-primary-500/20 hover:border-primary-500/40 transition-all duration-500 overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-primary-500/5 blur-3xl group-hover:bg-primary-500/10 transition-colors" />
                                <div className="relative z-10 flex items-center justify-between">
                                    <div className="flex items-center gap-6">
                                        <div className="w-14 h-14 rounded-2xl bg-primary-500 flex items-center justify-center text-white shadow-[0_0_20px_rgba(239,68,68,0.3)] group-hover:scale-110 transition-transform duration-500">
                                            <Cpu size={28} />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-black text-white uppercase italic tracking-tighter leading-none mb-1">Second Brain</h3>
                                            <p className="text-[10px] font-black text-primary-500/60 uppercase tracking-widest">Knowledge Base</p>
                                        </div>
                                    </div>
                                    <ChevronRight className="text-primary-500 opacity-0 group-hover:opacity-100 transition-opacity translate-x-[-10px] group-hover:translate-x-0 group-hover:duration-500" />
                                </div>
                            </Link>

                            <Link to="/ctf" className="group relative block p-8 rounded-[2rem] bg-gradient-to-br from-accent-500/20 to-transparent border border-accent-500/20 hover:border-accent-500/40 transition-all duration-500 overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-accent-500/5 blur-3xl group-hover:bg-accent-500/10 transition-colors" />
                                <div className="relative z-10 flex items-center justify-between">
                                    <div className="flex items-center gap-6">
                                        <div className="w-14 h-14 rounded-2xl bg-accent-500 flex items-center justify-center text-white shadow-[0_0_20px_rgba(255,0,85,0.3)] group-hover:scale-110 transition-transform duration-500">
                                            <Target size={28} />
                                        </div>
                                        <div>
                                            <h3 className="text-xl font-black text-white uppercase italic tracking-tighter leading-none mb-1">CTF Arena</h3>
                                            <p className="text-[10px] font-black text-accent-500/60 uppercase tracking-widest">Capture the flag</p>
                                        </div>
                                    </div>
                                    <ChevronRight className="text-accent-500 opacity-0 group-hover:opacity-100 transition-opacity translate-x-[-10px] group-hover:translate-x-0 group-hover:duration-500" />
                                </div>
                            </Link>
                        </div>
                    </div>

                    <div className="bg-dark-800/40 border border-white/5 rounded-[2rem] overflow-hidden">
                        <div className="p-8 border-b border-white/5 flex items-center justify-between">
                            <h3 className="text-sm font-black text-white uppercase italic tracking-widest">Active Uplink</h3>
                            <div className="flex items-center gap-1.5">
                                <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                                <span className="text-[8px] font-black text-white/40 uppercase">Connected</span>
                            </div>
                        </div>
                        <div className="p-2 space-y-1 h-[300px] overflow-hidden">
                            <CyberTerminal />
                        </div>
                    </div>
                </aside>
            </div>
        </div>
    );
};

export default Dashboard;
