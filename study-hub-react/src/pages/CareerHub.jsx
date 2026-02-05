import React from 'react';
import { motion } from 'framer-motion';
import {
    Briefcase, Target, Award, Clock,
    ChevronRight, Shield, Bug,
    Layers, Zap, BarChart3, TrendingUp
} from 'lucide-react';
import { careerTracks as careerData } from '../data/career-data';
import { youtubeCoursesData } from '../data/youtube-data';

const TrackIcon = ({ icon, className }) => {
    switch (icon) {
        case 'Shield': return <Shield className={className} />;
        case 'Bug': return <Bug className={className} />;
        case 'Layers': return <Layers className={className} />;
        default: return <Briefcase className={className} />;
    }
};

const CareerHub = () => {
    const careerTracks = careerData?.tracks || [];
    const youtubePlaylists = youtubeCoursesData?.playlists || [];

    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4">
                    <Target size={12} />
                    Job Readiness
                </div>
                <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-none glitch-text">
                    Career <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-500 to-indigo-500">Pathways</span>
                </h1>
                <p className="mt-4 text-gray-400 italic font-medium max-w-xl">
                    Structured curriculum designed to get you job-ready in specialized security roles.
                    Follow the path, master the skills, and secure your future.
                </p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {[
                    { label: 'Job Readiness', value: '94%', icon: TrendingUp },
                    { label: 'Active Learners', value: '1.2k', icon: Zap },
                    { label: 'Average Salary', value: '$85k+', icon: BarChart3 }
                ].map((stat, i) => (
                    <div key={i} className="p-6 rounded-3xl bg-dark-800/40 border border-white/5 backdrop-blur-sm relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-8 opacity-[0.03] group-hover:opacity-[0.05] transition-opacity">
                            <stat.icon size={80} />
                        </div>
                        <div className="text-gray-500 text-[10px] font-black uppercase tracking-widest mb-1">{stat.label}</div>
                        <div className="text-3xl font-black text-white italic tracking-tighter uppercase">{stat.value}</div>
                    </div>
                ))}
            </div>

            {/* Career Tracks Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {careerTracks.map((track, idx) => (
                    <motion.div
                        key={track.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.1 }}
                        className="group relative"
                    >
                        <div className="absolute -inset-0.5 bg-gradient-to-r from-primary-500/20 to-indigo-500/20 rounded-[2.5rem] blur opacity-0 group-hover:opacity-100 transition duration-500" />
                        <div className="relative p-8 rounded-[2rem] bg-dark-800/60 border border-white/5 backdrop-blur-md overflow-hidden flex flex-col h-full">
                            {/* Head */}
                            <div className="flex justify-between items-start mb-8">
                                <div className={`p-4 rounded-2xl bg-white/5 text-primary-500 shadow-[0_0_20px_rgba(239,68,68,0.1)]`}>
                                    <TrackIcon icon={track.icon} className="w-8 h-8" />
                                </div>
                                <div className="flex flex-col items-end">
                                    <div className="px-3 py-1 rounded-lg bg-black/40 border border-white/5 text-[10px] font-black text-indigo-400 uppercase tracking-widest mb-2">
                                        {track.level}
                                    </div>
                                    <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">
                                        {track.salary}
                                    </div>
                                </div>
                            </div>

                            <div className="flex-1">
                                <h3 className="text-3xl font-black text-white italic uppercase tracking-tighter mb-4 group-hover:text-primary-500 transition-colors">
                                    {track.title}
                                </h3>
                                <p className="text-gray-400 italic text-sm leading-relaxed mb-8">
                                    {track.description}
                                </p>

                                {/* Badges */}
                                <div className="flex flex-wrap gap-2 mb-8">
                                    {track.skills.map((skill, i) => (
                                        <span key={i} className="px-3 py-1 rounded-full bg-white/5 border border-white/5 text-[10px] font-bold text-gray-300 uppercase tracking-wider">
                                            {skill}
                                        </span>
                                    ))}
                                </div>

                                {/* NEURAL CONNECTIVITY: Recommended Courses */}
                                <div className="mb-8">
                                    <div className="text-[10px] font-black text-indigo-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                                        <Zap size={12} /> Recommended Training
                                    </div>
                                    <div className="space-y-2">
                                        {[
                                            // Auto-link logic: Find playlists matching track keywords
                                            ...youtubePlaylists.filter(p =>
                                                p.title.toLowerCase().includes(track.title.toLowerCase().split(' ')[0]) ||
                                                p.category === (track.id === 'soc-analyst' ? 'network' : 'web-security')
                                            ).slice(0, 2)
                                        ].map((course, i) => (
                                            <div key={i} className="flex items-center gap-3 p-2 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 transition-colors cursor-pointer">
                                                <div className="w-8 h-8 rounded-lg bg-black overflow-hidden shrink-0">
                                                    <img src={`https://img.youtube.com/vi/${course.thumbnail}/mqdefault.jpg`} className="w-full h-full object-cover opacity-70" />
                                                </div>
                                                <div className="min-w-0">
                                                    <div className="text-[10px] font-bold text-gray-300 truncate max-w-[150px]">{course.title}</div>
                                                    <div className="text-[8px] text-gray-500 uppercase tracking-wider">{course.totalVideos} Videos</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {/* Footer */}
                            <div className="pt-8 border-t border-white/5 flex items-center justify-between">
                                <div className="flex gap-6">
                                    <div className="flex items-center gap-2 text-gray-500">
                                        <Layers size={14} />
                                        <span className="text-[10px] font-black uppercase tracking-widest">{track.modules.length} Modules</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-gray-500">
                                        <Clock size={14} />
                                        <span className="text-[10px] font-black uppercase tracking-widest">{track.duration}</span>
                                    </div>
                                </div>
                                <button className="p-3 rounded-xl bg-primary-500 text-white shadow-[0_0_20px_rgba(239,68,68,0.3)] hover:scale-110 transition-transform">
                                    <ChevronRight size={20} />
                                </button>
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default CareerHub;
