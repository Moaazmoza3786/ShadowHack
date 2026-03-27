import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
    Map,
    ChevronRight,
    Target,
    Shield,
    Zap,
    Lock,
    Users,
    Award,
    Clock,
    Star,
    BookOpen,
    Search,
    Filter
} from 'lucide-react';
import { learningPaths } from '../data/learning-paths-data';

const LearningTracks = () => {
    const navigate = useNavigate();
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedLevel, setSelectedLevel] = useState('all');

    const levels = [
        { id: 'all', label: 'All Paths', icon: Map },
        { id: 'beginner', label: 'Beginner', icon: Shield },
        { id: 'intermediate', label: 'Intermediate', icon: Target },
        { id: 'advanced', label: 'Advanced', icon: Zap },
    ];

    const filteredPaths = learningPaths.filter(path => {
        const title = path.title || '';
        const description = path.description || '';
        const matchesSearch = title.toLowerCase().includes(searchQuery.toLowerCase()) ||
            description.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesLevel = selectedLevel === 'all' || path.level === selectedLevel;
        return matchesSearch && matchesLevel;
    });

    const getLevelColor = (level) => {
        switch (level) {
            case 'beginner': return 'from-green-500 to-emerald-600';
            case 'intermediate': return 'from-yellow-500 to-orange-600';
            case 'advanced': return 'from-red-500 to-pink-600';
            case 'expert': return 'from-purple-500 to-violet-600';
            default: return 'from-primary-500 to-cyan-600';
        }
    };

    const getLevelBadge = (level) => {
        switch (level) {
            case 'beginner': return { text: 'ENTRY', color: 'text-green-400 border-green-400/30 bg-green-400/10' };
            case 'intermediate': return { text: 'SPECIALIST', color: 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10' };
            case 'advanced': return { text: 'ELITE', color: 'text-red-400 border-red-400/30 bg-red-400/10' };
            case 'expert': return { text: 'MASTER', color: 'text-purple-400 border-purple-400/30 bg-purple-400/10' };
            default: return { text: 'PATH', color: 'text-primary-400 border-primary-400/30 bg-primary-400/10' };
        }
    };

    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4">
                    <Map size={12} />
                    Career Pathways
                </div>
                <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-none glitch-text">
                    Learning <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-500 to-cyan-500">Tracks</span>
                </h1>
                <p className="mt-4 text-gray-400 italic font-medium max-w-xl">
                    Structured career paths designed to take you from zero to hero.
                    Each track is a complete journey with courses, labs, and certifications.
                </p>
            </div>

            {/* Search & Filter */}
            <div className="flex flex-col lg:flex-row gap-6">
                <div className="relative flex-1 group">
                    <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-primary-500 transition-colors" size={20} />
                    <input
                        type="text"
                        placeholder="Search paths by name or skill..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-dark-800/40 border border-white/5 rounded-3xl py-4 pl-14 pr-6 focus:outline-none focus:border-primary-500/50 focus:bg-dark-800/60 transition-all text-gray-100 placeholder:text-gray-600 font-medium"
                    />
                </div>

                <div className="flex flex-wrap items-center gap-3">
                    {levels.map((level) => (
                        <button
                            key={level.id}
                            onClick={() => setSelectedLevel(level.id)}
                            className={`
                                flex items-center gap-3 px-6 py-4 rounded-3xl border transition-all duration-300 font-bold uppercase tracking-widest text-[10px]
                                ${selectedLevel === level.id
                                    ? 'bg-primary-500 border-primary-500 text-dark-900 shadow-[0_0_20px_rgba(0,242,234,0.2)]'
                                    : 'bg-dark-800/40 border-white/5 text-gray-400 hover:border-white/10 hover:text-white'}
                            `}
                        >
                            <level.icon size={16} />
                            {level.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Paths Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                {filteredPaths.map((path, idx) => {
                    const badge = getLevelBadge(path.level);
                    return (
                        <motion.div
                            key={path.id}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.05 }}
                            onClick={() => navigate(path.route || `/paths/${path.id}`)}
                            className="group cursor-pointer p-8 rounded-[2rem] bg-dark-800/40 border border-white/5 hover:border-primary-500/30 transition-all duration-500 overflow-hidden relative"
                        >
                            {/* Background Gradient */}
                            <div className={`absolute inset-0 bg-gradient-to-br ${getLevelColor(path.level)} opacity-0 group-hover:opacity-5 transition-opacity duration-500`}></div>

                            {/* Icon Watermark */}
                            <div className="absolute top-0 right-0 p-6 opacity-[0.03] group-hover:opacity-[0.08] transition-opacity">
                                <path.icon size={120} />
                            </div>

                            <div className="relative z-10 flex flex-col h-full">
                                {/* Level Badge */}
                                <div className={`inline-flex self-start items-center gap-1.5 px-3 py-1 rounded-full border text-[9px] font-black uppercase tracking-[0.15em] mb-4 ${badge.color}`}>
                                    {badge.text}
                                </div>

                                {/* Title */}
                                <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter mb-2 group-hover:text-primary-500 transition-colors">
                                    {path.title}
                                </h3>

                                {/* Arabic Title */}
                                {path.titleAr && (
                                    <p className="text-sm text-gray-500 mb-4">{path.titleAr}</p>
                                )}

                                {/* Description */}
                                <p className="text-gray-400 text-sm mb-6 line-clamp-2">
                                    {path.description}
                                </p>

                                {/* Stats */}
                                <div className="flex items-center gap-4 text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-6">
                                    <span className="flex items-center gap-1.5">
                                        <Clock size={12} />
                                        {path.duration}
                                    </span>
                                    <span className="flex items-center gap-1.5">
                                        <BookOpen size={12} />
                                        {path.modules} Modules
                                    </span>
                                    {path.students && (
                                        <span className="flex items-center gap-1.5">
                                            <Users size={12} />
                                            {path.students.toLocaleString()}
                                        </span>
                                    )}
                                </div>

                                {/* Skills */}
                                <div className="flex flex-wrap gap-2 mb-6">
                                    {path.skills?.slice(0, 4).map((skill, i) => (
                                        <span key={i} className="px-2 py-1 text-[9px] font-bold uppercase tracking-wider bg-white/5 border border-white/10 rounded-lg text-gray-400">
                                            {skill}
                                        </span>
                                    ))}
                                </div>

                                {/* CTA */}
                                <button className="mt-auto w-full py-4 rounded-2xl bg-white/5 border border-white/10 text-white font-black uppercase tracking-widest text-[10px] hover:bg-primary-500 hover:text-dark-900 hover:border-primary-500 transition-all flex items-center justify-center gap-2 group/btn">
                                    {path.isLocked ? (
                                        <>
                                            <Lock size={14} />
                                            COMING SOON
                                        </>
                                    ) : (
                                        <>
                                            START PATH
                                            <ChevronRight size={14} className="group-hover/btn:translate-x-1 transition-transform" />
                                        </>
                                    )}
                                </button>
                            </div>
                        </motion.div>
                    );
                })}
            </div>

            {/* Empty State */}
            {filteredPaths.length === 0 && (
                <div className="flex flex-col items-center justify-center py-32 space-y-6 rounded-[3rem] border border-dashed border-white/10 bg-dark-800/20">
                    <div className="w-20 h-20 rounded-full bg-white/5 flex items-center justify-center text-gray-600">
                        <Search size={40} />
                    </div>
                    <div className="text-center">
                        <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter">No Paths Found</h3>
                        <p className="text-gray-500 mt-1 font-bold uppercase tracking-widest text-[10px]">Try adjusting your search filters</p>
                    </div>
                    <button
                        onClick={() => { setSearchQuery(''); setSelectedLevel('all'); }}
                        className="px-8 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-black text-white uppercase tracking-[0.2em] hover:bg-white/10 transition-all"
                    >
                        Reset Filters
                    </button>
                </div>
            )}
        </div>
    );
};

export default LearningTracks;
