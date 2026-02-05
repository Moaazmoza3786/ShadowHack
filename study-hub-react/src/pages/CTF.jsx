import React, { useState } from 'react';
import { useAppContext } from '../context/AppContext';
import { ctfRooms, achievements } from '../data/ctf-rooms';
import {
    Flag,
    Target,
    Zap,
    Trophy,
    Shield,
    Timer,
    Search,
    Eye,
    Cpu,
    ChevronRight,
    Terminal as TerminalIcon,
    Flame,
    Lock
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';

const RoomCard = ({ room }) => {
    const { language } = useAppContext();

    return (
        <Link to={`/ctf/${room.id}`} className="group relative block rounded-3xl bg-dark-800/40 border border-white/5 overflow-hidden hover:border-accent-500/30 transition-all duration-500 shadow-2xl">
            <div className="p-8 space-y-6">
                <div className="flex items-start justify-between">
                    <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:scale-110 group-hover:border-accent-500/50 transition-all duration-500">
                        <Target className="text-gray-500 group-hover:text-accent-500 transition-colors" size={28} />
                    </div>
                    <div className="flex flex-col items-end">
                        <span className="text-[10px] font-black text-accent-500 uppercase tracking-widest">{room.difficulty}</span>
                        <div className="flex items-center gap-1 mt-1">
                            <Zap size={12} className="text-yellow-500 fill-yellow-500" />
                            <span className="text-sm font-black text-white italic">{room.points} PTS</span>
                        </div>
                    </div>
                </div>

                <div>
                    <h3 className="text-xl font-black text-white italic uppercase tracking-tighter leading-none mb-2 group-hover:text-accent-500 transition-colors">
                        {language === 'ar' ? room.title.ar : room.title.en}
                    </h3>
                    <p className="text-xs text-gray-500 line-clamp-2 leading-relaxed">
                        {language === 'ar' ? room.description.ar : room.description.en}
                    </p>
                </div>

                <div className="flex items-center gap-4 pt-6 border-t border-white/5 mt-auto">
                    <div className="flex items-center gap-2">
                        <Timer size={14} className="text-gray-500" />
                        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">{room.estimatedTime}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 ml-auto">
                        {room.tags.slice(0, 2).map(tag => (
                            <span key={tag} className="px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[8px] font-black text-gray-500 uppercase tracking-widest">#{tag}</span>
                        ))}
                    </div>
                </div>
            </div>

            <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/5">
                <div className="h-full bg-accent-500 w-0 group-hover:w-full transition-all duration-700 ease-out shadow-[0_0_10px_#ff0055]"></div>
            </div>
        </Link>
    );
};

const CTF = () => {
    const { t, user, liveFeed } = useAppContext();
    const [activeTab, setActiveTab] = useState('web');
    const [selectedLevel, setSelectedLevel] = useState('all');

    const categories = [
        { id: 'web', label: 'Web Exploit', icon: TerminalIcon },
        { id: 'crypto', label: 'Cryptography', icon: Lock },
        { id: 'pwn', label: 'Binary Pwn', icon: Flame },
        { id: 'cloud', label: 'Cloud Security', icon: Shield },
        { id: 'forensics', label: 'Digital Forensics', icon: Search },
        { id: 'redteam', label: 'Red Team', icon: Zap }
    ];

    const levels = [
        { id: 'all', label: 'All Levels', labelAr: 'كل المستويات' },
        { id: 'easy', label: 'Beginner', labelAr: 'مبتدئ' },
        { id: 'medium', label: 'Intermediate', labelAr: 'متوسط' },
        { id: 'hard', label: 'Advanced', labelAr: 'متقدم' }
    ];

    const filteredRooms = (ctfRooms[activeTab] || []).filter(room =>
        selectedLevel === 'all' || room.difficulty === selectedLevel
    );

    // Dynamic Stats Calculation
    const totalPossibleFlags = Object.values(ctfRooms).reduce((acc, cat) =>
        acc + (cat?.reduce((acc2, room) => acc2 + (room?.tasks?.length || 0), 0) || 0), 0
    );
    const solvedFlagsCount = user?.solvedCTFTasks?.length || 0;
    const worldProgress = Math.round((solvedFlagsCount / (totalPossibleFlags || 1)) * 100);

    return (
        <div className="space-y-12 pb-20">
            {/* Header / Stats Overlay */}
            <div className="relative p-12 rounded-[3.5rem] bg-gradient-to-br from-dark-800 to-dark-900 border border-white/5 overflow-hidden">
                <div className="absolute inset-0 bg-cyber-grid opacity-10" />
                <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-12">
                    <div className="space-y-6">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent-500/10 border border-accent-500/20">
                            <div className="w-1.5 h-1.5 rounded-full bg-accent-500 animate-ping" />
                            <span className="text-[10px] font-black text-accent-500 uppercase tracking-widest">Live Arena • Competition Active</span>
                        </div>
                        <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-none glitch-text">
                            Battleground
                        </h1>
                        <p className="text-xl text-gray-400 max-w-xl font-medium leading-relaxed">
                            {t('ميدان التدريب العملي. اختر هدفك، استغل الثغرات، واجمع الأعلام لرفع تصنيفك العالمي.', 'Elite practical training arena. Select your target, exploit vulnerabilities, and capture flags to rise in global ranking.')}
                        </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-6 rounded-3xl bg-white/5 border border-white/10 backdrop-blur-md">
                            <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">Total Flags</p>
                            <p className="text-2xl font-black text-white italic">{solvedFlagsCount} / {totalPossibleFlags}</p>
                        </div>
                        <div className="p-6 rounded-3xl bg-white/5 border border-white/10 backdrop-blur-md">
                            <p className="text-[10px] font-black text-accent-500 uppercase tracking-widest mb-1">XP Earned</p>
                            <p className="text-2xl font-black text-white italic">+{user.points}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Achievement Bar */}
            <div className="flex flex-wrap gap-6 items-center">
                <p className="text-xs font-black text-gray-500 uppercase tracking-[0.2em]">Rank Badges</p>
                <div className="flex gap-4">
                    {achievements.slice(0, 3).map(ach => (
                        <div key={ach.id} className="flex items-center gap-3 px-4 py-2 rounded-2xl bg-dark-800/40 border border-white/5 group hover:border-accent-500/20 transition-all cursor-help">
                            <div className="w-8 h-8 rounded-lg bg-accent-500/10 flex items-center justify-center text-accent-500 group-hover:scale-110 transition-transform">
                                <Trophy size={16} />
                            </div>
                            <span className="text-xs font-bold text-gray-300 uppercase tracking-widest">{ach.title.en}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Dashboard HUD */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* World Progress Bar */}
                <div className="p-6 rounded-[2.5rem] bg-dark-800/40 border border-white/5 backdrop-blur-md flex flex-col justify-center">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            < Shield className="text-accent-500" size={18} />
                            <span className="text-[10px] font-black text-accent-500 uppercase tracking-[0.2em]">World Bloodlust</span>
                        </div>
                        <span className="text-xl font-black text-white italic">{worldProgress}%</span>
                    </div>
                    <div className="relative h-2 bg-dark-900/60 rounded-full overflow-hidden border border-white/5">
                        <div
                            className="absolute inset-y-0 left-0 bg-gradient-to-r from-accent-500 to-red-600 rounded-full transition-all duration-1000 shadow-[0_0_15px_rgba(255,0,85,0.4)]"
                            style={{ width: `${worldProgress}%` }}
                        >
                            <div className="absolute inset-0 bg-white/10 animate-pulse" />
                        </div>
                    </div>
                    <p className="text-[9px] text-gray-500 mt-3 font-medium uppercase tracking-widest opacity-60">Global completion across all operatives</p>
                </div>

                {/* Live Feed Terminal */}
                <div className="p-6 rounded-[2.5rem] bg-dark-900/80 border border-accent-500/10 backdrop-blur-md font-mono relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-1 h-full bg-accent-500/20" />
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-1.5 h-1.5 rounded-full bg-accent-500 animate-ping" />
                        <span className="text-[10px] font-black text-cyan-400 uppercase tracking-[0.2em]">Live_Feed_Terminal</span>
                    </div>
                    <div className="space-y-2 h-24 overflow-hidden mask-fade-bottom">
                        {liveFeed.length > 0 ? liveFeed.map((feed, i) => (
                            <div key={i} className="flex items-center gap-2 text-[11px] text-gray-400 group-hover:translate-x-1 transition-transform" style={{ transitionDelay: `${i * 50}ms` }}>
                                <span className="text-cyan-500/50">│</span>
                                <span className="text-green-400/80 font-bold">{feed.user}</span>
                                <span className="opacity-40 text-[9px]">CAPTURED</span>
                                <span className="text-yellow-400/90">{`[${feed.challenge}]`}</span>
                            </div>
                        )) : (
                            <div className="h-full flex flex-col items-center justify-center space-y-2 opacity-20">
                                <Search size={20} className="text-cyan-500 animate-pulse" />
                                <span className="text-[9px] uppercase tracking-[0.3em] font-black italic">Monitoring Signal...</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Level Filter Pills */}
            <div className="flex flex-wrap gap-3 items-center">
                {levels.map(level => (
                    <button
                        key={level.id}
                        onClick={() => setSelectedLevel(level.id)}
                        className={`
                            px-6 py-3 rounded-full font-bold uppercase tracking-widest text-[10px] transition-all duration-300
                            ${selectedLevel === level.id
                                ? 'bg-accent-500 text-white shadow-[0_0_20px_rgba(255,0,85,0.3)]'
                                : 'bg-dark-800/40 border border-white/5 text-gray-500 hover:text-white hover:border-white/10'}
                        `}
                    >
                        {level.label}
                    </button>
                ))}
            </div>

            {/* Navigation Tabs */}
            <div className="flex flex-col lg:flex-row gap-8 items-start">
                <div className="w-full lg:w-64 space-y-2">
                    {categories.map(cat => (
                        <button
                            key={cat.id}
                            onClick={() => setActiveTab(cat.id)}
                            className={`
                                w-full flex items-center gap-4 px-6 py-4 rounded-2xl transition-all duration-300 font-bold uppercase tracking-widest text-[10px] text-left
                                ${activeTab === cat.id
                                    ? 'bg-accent-500 text-white shadow-[0_0_30px_rgba(255,0,85,0.2)]'
                                    : 'bg-dark-800/40 border border-white/5 text-gray-500 hover:text-white hover:border-white/10'}
                            `}
                        >
                            <cat.icon size={18} />
                            {cat.label}
                        </button>
                    ))}
                </div>

                {/* Rooms Grid */}
                <div className="flex-1">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={activeTab}
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -20 }}
                            transition={{ duration: 0.3 }}
                            className="grid grid-cols-1 md:grid-cols-2 gap-8"
                        >
                            {filteredRooms.length > 0 ? (
                                filteredRooms.map(room => (
                                    <RoomCard key={room.id} room={room} />
                                ))
                            ) : (
                                <div className="col-span-2 p-12 text-center">
                                    <p className="text-gray-500 text-sm font-bold uppercase tracking-widest">No challenges found for this level</p>
                                </div>
                            )}
                        </motion.div>
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default CTF;
