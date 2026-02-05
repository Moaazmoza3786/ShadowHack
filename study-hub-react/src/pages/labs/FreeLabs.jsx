import React from 'react';
import { FlaskConical, Clock, Star, Play, Signal, Map } from 'lucide-react';
import { motion } from 'framer-motion';

const FreeLabs = () => {
    const mockLabs = [
        { id: 1, title: 'Introduction to Web Hacking', description: 'Learn the basics of web penetration testing. Understand HTTP, cookies, and simple vulnerabilities.', difficulty: 'Easy', time: '45m', points: 50, category: 'Web' },
        { id: 2, title: 'Linux Fundamentals 101', description: 'Master the command line. Navigation, file manipulation, and permissions explained.', difficulty: 'Easy', time: '30m', points: 40, category: 'Nix' },
        { id: 3, title: 'Network Scanning with Nmap', description: 'Learn how to discover systems and services on a network using the industry standard tool.', difficulty: 'Easy', time: '60m', points: 60, category: 'Net' },
        { id: 4, title: 'Bypassing Logins', description: 'Explore authentication flaws and learn how to bypass poorly implemented login forms.', difficulty: 'Medium', time: '50m', points: 80, category: 'Web' },
    ];

    return (
        <div className="min-h-screen bg-[#0a0a1f] text-white p-8 pt-24 font-orbitron">
            <div className="max-w-6xl mx-auto space-y-12">
                <div className="text-center space-y-4">
                    <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-green-500/50 underline-offset-8">
                        <FlaskConical size={48} className="text-green-500" />
                        FREE LABS
                    </h1>
                    <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Hand-picked community content for beginners</p>
                    <div className="inline-block px-4 py-2 bg-green-500/20 border border-green-500/30 text-green-500 rounded-full text-xs font-black tracking-widest">
                        TOTAL: {mockLabs.length} LABS READY
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {mockLabs.map(lab => (
                        <motion.div
                            key={lab.id}
                            whileHover={{ y: -5 }}
                            className="bg-white/5 border border-white/10 rounded-3xl p-8 hover:border-green-500/30 transition-all cursor-pointer group flex flex-col justify-between"
                        >
                            <div className="space-y-4">
                                <div className="flex justify-between items-start">
                                    <h2 className="text-2xl font-black group-hover:text-green-400 transition-colors uppercase tracking-tight leading-tight">{lab.title}</h2>
                                    <div className="px-3 py-1 bg-green-500 text-black text-[10px] font-black rounded uppercase tracking-widest">Free</div>
                                </div>
                                <p className="text-sm text-white/50 font-mono leading-relaxed">{lab.description}</p>

                                <div className="flex flex-wrap gap-6 text-[10px] font-black text-white/30 tracking-widest uppercase">
                                    <div className="flex items-center gap-2">
                                        <Clock size={12} className="text-green-500" /> {lab.time}
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Star size={12} className="text-green-500" /> {lab.points} pts
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Signal size={12} className="text-green-500" /> {lab.difficulty}
                                    </div>
                                    <div className="flex items-center gap-2 underline decoration-green-500/50 underline-offset-4">
                                        <Map size={12} className="text-green-500" /> {lab.category}
                                    </div>
                                </div>
                            </div>

                            <button className="mt-8 w-full py-4 bg-green-600/10 hover:bg-green-600 text-green-500 hover:text-black font-black rounded-xl border-2 border-green-600/30 transition-all uppercase tracking-[0.2em] text-xs flex items-center justify-center gap-3">
                                <Play size={16} fill="currentColor" />
                                Start Training
                            </button>
                        </motion.div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default FreeLabs;
