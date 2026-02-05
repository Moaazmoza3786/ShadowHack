import React from 'react';
import { Shield, Target, Laptop, Users, Clock } from 'lucide-react';
import { motion } from 'framer-motion';

const About = () => {
    return (
        <div className="max-w-4xl mx-auto space-y-16 animate-fade-in">
            <div className="text-center space-y-4">
                <motion.div
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className="mx-auto w-24 h-24 bg-primary-500/20 rounded-full flex items-center justify-center border border-primary-500/30 mb-6 shadow-2xl shadow-primary-500/10"
                >
                    <Shield size={48} className="text-primary-500" />
                </motion.div>
                <h1 className="text-6xl font-black tracking-tighter uppercase italic">Study<span className="text-primary-500">Hub</span></h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Next-Generation Offensive Operations Lab</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 font-mono">
                <div className="bg-dark-800/50 border border-white/5 p-8 rounded-3xl space-y-4 hover:border-primary-500/30 transition-all group">
                    <div className="flex items-center gap-4 text-primary-500 uppercase font-black tracking-widest text-xs group-hover:translate-x-1 transition-transform">
                        <Target size={20} /> Our Mission
                    </div>
                    <p className="text-sm text-white/50 leading-relaxed uppercase tracking-tight">
                        ShadowHack is dedicated to making high-tier cybersecurity education accessible to everyone. We believe in learning by doing, which is why we've built a platform with hands-on labs, real-world challenges, and structured learning paths that take you from beginner to expert.
                    </p>
                </div>

                <div className="bg-dark-800/50 border border-white/5 p-8 rounded-3xl space-y-4 hover:border-primary-500/30 transition-all group">
                    <div className="flex items-center gap-4 text-primary-500 uppercase font-black tracking-widest text-xs group-hover:translate-x-1 transition-transform">
                        <Laptop size={20} /> Operational Scope
                    </div>
                    <p className="text-sm text-white/50 leading-relaxed uppercase tracking-tight">
                        From web application security to network pentesting, from malware analysis to cloud security - our comprehensive curriculum covers all aspects of modern cybersecurity. Each path is designed by industry professionals and includes practical exercises that simulate real-world scenarios.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
                {[
                    { num: '50+', label: 'Learning Rooms', icon: Laptop },
                    { num: '100+', label: 'CTF Challenges', icon: Target },
                    { num: '10K+', label: 'Active Operatives', icon: Users },
                    { num: '24/7', label: 'Uptime Access', icon: Clock }
                ].map(stat => (
                    <div key={stat.label} className="bg-white/5 border border-white/5 p-6 rounded-2xl text-center space-y-2">
                        <div className="text-3xl font-black text-primary-500 tracking-tighter italic">{stat.num}</div>
                        <div className="text-[10px] text-white/20 font-bold uppercase tracking-widest">{stat.label}</div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default About;
