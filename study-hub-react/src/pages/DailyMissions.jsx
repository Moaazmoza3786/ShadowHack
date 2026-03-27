
import React, { useState, useEffect } from 'react';
import {
    Target, CheckCircle, Clock, Zap, Gift,
    Calendar, TrendingUp, Award, Rocket, AlertCircle, RefreshCcw, Monitor, Terminal, Shield, ChevronRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppContext } from '../context/AppContext';
import './DailyMissions.css';

const DailyMissions = () => {
    const { language } = useAppContext();
    const [missions, setMissions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeCodespaces, setActiveCodespaces] = useState([]);
    const [isSyncing, setIsSyncing] = useState({});
    const [notification, setNotification] = useState(null);

    const toast = (message, type = 'info') => {
        setNotification({ message, type });
        setTimeout(() => setNotification(null), 3000);
    };

    const fetchCodespaces = async () => {
        try {
            const res = await fetch('/api/codespaces/active');
            const data = await res.json();
            if (data.success) {
                setActiveCodespaces(Object.entries(data.environments).map(([id, env]) => ({ id, ...env })));
            }
        } catch (err) {
            console.error(err);
        }
    };

    useEffect(() => {
        fetchMissions();
        fetchCodespaces();
        const interval = setInterval(fetchCodespaces, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchMissions = async () => {
        try {
            const res = await fetch('/api/missions/user/1');
            const data = await res.json();
            if (data.success) setMissions(data.missions);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const syncToCodespace = async (mission) => {
        if (activeCodespaces.length === 0) {
            toast("No active Codespace Bridge detected", "error");
            return;
        }

        setIsSyncing(prev => ({ ...prev, [mission.id]: true }));
        try {
            const res = await fetch('/api/codespaces/sync-mission', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    codespace_id: activeCodespaces[0].id,
                    mission_id: `daily_${mission.id}`
                })
            });
            const data = await res.json();
            if (data.success) {
                toast(`Mission ${mission.title} synced to tactical terminal!`, "success");
            } else {
                toast(data.message || "Synchronization failed", "error");
            }
        } catch (err) {
            toast("Bridge communication error", "error");
        } finally {
            setIsSyncing(prev => ({ ...prev, [mission.id]: false }));
        }
    };

    const getMissionTypeIcon = (type) => {
        switch (type) {
            case 'daily': return <Calendar size={14} />;
            case 'weekly': return <TrendingUp size={14} />;
            case 'event': return <Gift size={14} />;
            default: return <Target size={14} />;
        }
    };

    const getMissionTypeClass = (type) => {
        switch (type) {
            case 'daily': return 'type-daily';
            case 'weekly': return 'type-weekly';
            case 'event': return 'type-event';
            default: return '';
        }
    };

    return (
        <div className="min-h-screen bg-dark-900/50 p-8 space-y-12 relative overflow-hidden">
            {/* Background Effects */}
            <div className="absolute inset-0 bg-cyber-grid opacity-5 pointer-events-none" />

            {/* Notification Toast */}
            <AnimatePresence>
                {notification && (
                    <motion.div
                        initial={{ opacity: 0, y: -20, x: '-50%' }}
                        animate={{ opacity: 1, y: 0, x: '-50%' }}
                        exit={{ opacity: 0, y: -20, x: '-50%' }}
                        className={`fixed top-8 left-1/2 z-[200] px-6 py-3 rounded-2xl border backdrop-blur-md shadow-2xl flex items-center gap-3 ${notification.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' :
                            notification.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                                'bg-primary-500/10 border-primary-500/20 text-primary-500'
                            }`}
                    >
                        {notification.type === 'success' ? <Rocket size={18} /> : <AlertCircle size={18} />}
                        <span className="text-xs font-black uppercase tracking-widest">{notification.message}</span>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Header Section */}
            <header className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-8 p-10 rounded-[3rem] bg-gradient-to-br from-dark-800 to-dark-900 border border-white/5 shadow-2xl overflow-hidden">
                <div className="absolute inset-0 bg-primary-500/5 opacity-10" />
                <div className="relative space-y-4">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20">
                        <Terminal size={12} className="text-primary-500" />
                        <span className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Tactical Operations Hub</span>
                    </div>
                    <h1 className="text-6xl font-black text-white italic tracking-tighter uppercase leading-none">
                        Daily <span className="text-primary-500">Infiltrations</span>
                    </h1>
                    <p className="text-gray-400 font-medium max-w-lg">
                        Execute high-priority objectives. Synchronize with the Tactical Bridge for live environment access.
                    </p>
                </div>

                <div className="flex gap-4">
                    <div className="p-6 rounded-3xl bg-white/5 border border-white/10 backdrop-blur-md">
                        <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">Missions Active</p>
                        <p className="text-3xl font-black text-white italic">{missions.length}</p>
                    </div>
                    <div className="p-6 rounded-3xl bg-white/5 border border-white/10 backdrop-blur-md">
                        <p className="text-[10px] font-black text-primary-500 uppercase tracking-widest mb-1">Bridge Status</p>
                        <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${activeCodespaces.length > 0 ? 'bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]' : 'bg-red-500'}`} />
                            <p className="text-lg font-black text-white uppercase italic">{activeCodespaces.length > 0 ? 'Linked' : 'Offline'}</p>
                        </div>
                    </div>
                </div>
            </header>

            {/* Missions Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                {missions.map((mission, idx) => (
                    <motion.div
                        key={mission.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.1 }}
                        className={`group relative p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 transition-all duration-500 hover:border-primary-500/30 ${mission.is_completed ? 'opacity-80' : ''}`}
                    >
                        {/* Status Header */}
                        <div className="flex items-center justify-between mb-8">
                            <div className={`px-4 py-1.5 rounded-full border text-[9px] font-black uppercase tracking-widest flex items-center gap-2 ${mission.mission_type === 'daily' ? 'bg-primary-500/10 border-primary-500/20 text-primary-500' :
                                mission.mission_type === 'weekly' ? 'bg-purple-500/10 border-purple-500/20 text-purple-500' :
                                    'bg-yellow-500/10 border-yellow-500/20 text-yellow-500'
                                }`}>
                                {getMissionTypeIcon(mission.mission_type)}
                                {mission.mission_type}
                            </div>
                            {mission.is_completed && (
                                <div className="flex items-center gap-1.5 text-emerald-500 font-black text-[10px] uppercase tracking-widest">
                                    <CheckCircle size={14} />
                                    COMPLETED
                                </div>
                            )}
                        </div>

                        {/* Content */}
                        <div className="space-y-4 mb-8">
                            <h3 className="text-xl font-black text-white italic uppercase tracking-tighter group-hover:text-primary-500 transition-colors">
                                {mission.title}
                            </h3>
                            <p className="text-xs text-gray-500 leading-relaxed font-medium">
                                {mission.description}
                            </p>
                        </div>

                        {/* Progress */}
                        <div className="space-y-3 mb-8">
                            <div className="flex items-center justify-between text-[10px] font-black uppercase tracking-widest">
                                <span className="text-gray-500">Operation Progress</span>
                                <span className={`${mission.is_completed ? 'text-emerald-500' : 'text-white'} italic`}>
                                    {mission.user_progress} / {mission.objective_target}
                                </span>
                            </div>
                            <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${Math.min((mission.user_progress / mission.objective_target) * 100, 100)}%` }}
                                    className={`h-full rounded-full ${mission.is_completed ? 'bg-emerald-500' : 'bg-primary-500 shadow-[0_0_10px_#00f2ea]'}`}
                                />
                            </div>
                        </div>

                        {/* Footer Actions */}
                        <div className="flex items-center justify-between pt-6 border-t border-white/5">
                            <div className="flex items-center gap-2">
                                <Zap size={14} className="text-primary-500" />
                                <span className="text-[10px] font-black text-white italic">+{mission.xp_reward} XP</span>
                            </div>

                            {!mission.is_completed && (
                                <button
                                    onClick={() => syncToCodespace(mission)}
                                    disabled={isSyncing[mission.id]}
                                    className="flex items-center gap-2 px-5 py-2.5 bg-primary-500/10 border border-primary-500/20 text-primary-500 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-primary-500 hover:text-dark-900 transition-all group/btn"
                                >
                                    {isSyncing[mission.id] ? (
                                        <RefreshCcw size={14} className="animate-spin" />
                                    ) : (
                                        <Rocket size={14} className="group-hover/btn:translate-x-1 group-hover/btn:-translate-y-1 transition-transform" />
                                    )}
                                    {isSyncing[mission.id] ? 'SYNCING...' : 'INFILTRATE'}
                                </button>
                            )}
                        </div>
                    </motion.div>
                ))}

                {missions.length === 0 && !loading && (
                    <div className="col-span-full py-20 text-center space-y-4 opacity-40">
                        <Shield size={64} className="mx-auto text-gray-700" />
                        <p className="text-xs font-black uppercase tracking-[0.2em] text-gray-500">No active infiltrations assigned</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default DailyMissions;
