import React from 'react';
import { Calendar, Star, Play, Users, Signal, Folder } from 'lucide-react';
import { motion } from 'framer-motion';

const DailyCTF = () => {
    // Picking a challenge based on current day
    const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
    const mockChallenge = {
        title: 'The Cookie Monster',
        description: 'Manipulate cookies to gain admin access. This lab tests your understanding of session management and cookie-based authentication flaws.',
        difficulty: 'Easy',
        category: 'Web',
        solves: 1242,
        points: 100
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-white p-8 pt-24 font-orbitron">
            <div className="max-w-6xl mx-auto space-y-12">
                <div className="text-center space-y-4">
                    <h1 className="text-5xl font-black tracking-tighter flex items-center justify-center gap-4 italic underline decoration-red-500/50 underline-offset-8">
                        <Calendar size={48} className="text-red-500" />
                        DAILY CHALLENGE
                    </h1>
                    <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">
                        {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
                    </p>
                </div>

                <motion.div
                    initial={{ scale: 0.95, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className="relative bg-gradient-to-br from-red-500/10 via-[#0d0d15] to-[#0a0a0f] border-2 border-red-500/30 rounded-3xl p-10 overflow-hidden group shadow-2xl shadow-red-500/5"
                >
                    <div className="absolute top-6 right-6 px-4 py-2 bg-red-500 text-black font-black text-xs rounded-full shadow-lg shadow-red-500/20 flex items-center gap-2">
                        <Star size={14} fill="black" />
                        FEATURED
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-12 items-center">
                        <div className="lg:col-span-2 space-y-6">
                            <h2 className="text-4xl font-black tracking-tight group-hover:text-red-400 transition-colors uppercase">{mockChallenge.title}</h2>
                            <p className="text-white/60 font-mono text-lg leading-relaxed">{mockChallenge.description}</p>

                            <div className="flex flex-wrap gap-8 py-4">
                                <div className="flex items-center gap-3 text-white/40">
                                    <Signal size={20} className="text-red-500" />
                                    <span className="font-mono text-sm uppercase">{mockChallenge.difficulty}</span>
                                </div>
                                <div className="flex items-center gap-3 text-white/40">
                                    <Folder size={20} className="text-red-500" />
                                    <span className="font-mono text-sm uppercase">{mockChallenge.category}</span>
                                </div>
                                <div className="flex items-center gap-3 text-white/40">
                                    <Users size={20} className="text-red-500" />
                                    <span className="font-mono text-sm uppercase">{mockChallenge.solves} solves</span>
                                </div>
                            </div>

                            <button className="px-10 py-5 bg-red-600 hover:bg-red-500 text-white font-black rounded-2xl shadow-xl shadow-red-600/20 transition-all hover:-translate-y-1 flex items-center gap-3 uppercase tracking-widest text-lg">
                                <Play size={20} fill="white" />
                                Start Challenge
                            </button>
                        </div>

                        <div className="bg-black/40 border border-white/10 rounded-3xl p-10 text-center space-y-2 backdrop-blur-md">
                            <div className="text-7xl font-black text-red-500 tracking-tighter">{mockChallenge.points}</div>
                            <div className="text-white/30 font-mono tracking-[0.5em] text-xs font-bold uppercase">Points</div>
                        </div>
                    </div>
                </motion.div>

                <div className="space-y-6">
                    <h3 className="text-2xl font-black tracking-tight text-white/80 border-b border-white/10 pb-4 uppercase">More Challenges</h3>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        {[1, 2, 3].map(i => (
                            <div key={i} className="bg-white/5 border border-white/10 rounded-2xl p-6 hover:border-red-500/30 transition-all cursor-pointer group">
                                <div className="flex justify-between items-start mb-4">
                                    <div className="font-black text-white group-hover:text-red-400 uppercase tracking-tight">Machine_{i}01</div>
                                    <div className="px-2 py-1 bg-red-500/10 text-red-500 text-[10px] font-bold rounded">100 PTS</div>
                                </div>
                                <p className="text-[11px] text-white/40 font-mono mb-4 leading-relaxed">Basic enumeration and privilege escalation in a simple Linux environment.</p>
                                <div className="flex gap-4">
                                    <span className="text-[9px] text-white/20 font-mono uppercase tracking-widest font-bold">Linux</span>
                                    <span className="text-[9px] text-white/20 font-mono uppercase tracking-widest font-bold underline decoration-red-500/50 underline-offset-4">Easy</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default DailyCTF;
