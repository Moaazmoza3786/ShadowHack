import React from 'react';
import { Trophy, Star, Shield, Zap, Target, Award } from 'lucide-react';
import { motion } from 'framer-motion';

const Achievements = () => {
    const achievements = [
        { title: 'First Blood', desc: 'Complete your first room.', icon: Zap, color: 'text-primary-500', progress: 100 },
        { title: 'Bug Hunter', desc: 'Find 5 web vulnerabilities.', icon: Target, color: 'text-primary-500', progress: 60 },
        { title: 'Network Master', desc: 'Complete the Network Path.', icon: Shield, color: 'text-primary-500', progress: 20 },
        { title: 'Top 1% Agent', desc: 'Reach the global leaderboard.', icon: Trophy, color: 'text-primary-500', progress: 45 },
        { title: 'Script Kiddie No More', desc: 'Complete 10 scripting challenges.', icon: Award, color: 'text-primary-500', progress: 80 },
        { title: 'Full Spectrum', desc: 'Solve a challenge in every category.', icon: Star, color: 'text-primary-500', progress: 10 }
    ];

    return (
        <div className="max-w-6xl mx-auto space-y-16 animate-fade-in">
            <div className="text-center space-y-4">
                <div className="mx-auto w-24 h-24 bg-primary-500/20 rounded-full flex items-center justify-center border border-primary-500/30 mb-6 shadow-2xl shadow-primary-500/10">
                    <Trophy size={48} className="text-primary-500" />
                </div>
                <h1 className="text-5xl font-black tracking-tighter uppercase italic underline decoration-primary-500/50 underline-offset-8">Operative Merits</h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Validating tactical excellence in the field</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {achievements.map((ach, idx) => (
                    <motion.div
                        key={ach.title}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.1 }}
                        className="bg-dark-800/50 border border-white/5 rounded-3xl p-8 hover:border-primary-500/30 transition-all group backdrop-blur-sm relative overflow-hidden"
                    >
                        <div className="absolute top-0 right-0 w-24 h-24 bg-primary-500/5 rounded-full blur-2xl -mr-12 -mt-12 group-hover:bg-primary-500/10 transition-all" />

                        <div className="space-y-6 relative z-10 font-mono">
                            <div className="flex items-center gap-5">
                                <div className={`p-4 bg-white/5 rounded-2xl border border-white/5 group-hover:border-primary-500/20 group-hover:bg-primary-500/10 transition-all ${ach.color}`}>
                                    <ach.icon size={28} />
                                </div>
                                <div className="space-y-1">
                                    <h3 className="text-lg font-black uppercase tracking-tight group-hover:text-primary-400 transition-colors italic">{ach.title}</h3>
                                    <p className="text-[10px] text-white/30 uppercase tracking-[0.2em]">{ach.desc}</p>
                                </div>
                            </div>

                            <div className="space-y-3">
                                <div className="flex justify-between text-[10px] font-black text-white/20 uppercase tracking-[0.2em]">
                                    <span>Sync Progress</span>
                                    <span className="text-primary-500">{ach.progress}%</span>
                                </div>
                                <div className="h-1.5 bg-white/5 rounded-full overflow-hidden p-0.5 border border-white/5">
                                    <div
                                        className="h-full bg-primary-600 rounded-full transition-all duration-1000 shadow-[0_0_15px_rgba(var(--primary-rgb),0.5)]"
                                        style={{ width: `${ach.progress}%` }}
                                    />
                                </div>
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default Achievements;
