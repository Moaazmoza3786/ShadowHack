import React from 'react';
import { Crown, Lock, Clock, Star, Play, ShieldAlert, Cpu } from 'lucide-react';
import { motion } from 'framer-motion';

const ProLabs = () => {
    const premiumLabs = [
        { id: 'ad-forest', title: 'Enterprise AD Forest', desc: 'Compromise a multi-forest AD environment using BloodHound and Kerberoasting.', time: '12h', points: 1500, skills: ['AD', 'Mimikatz'] },
        { id: 'cloud-breach', title: 'AWS Cloud Breach', desc: 'Full-chain attack from SSRF to S3 exfiltration. Based on real-world breaches.', time: '8h', points: 1200, skills: ['AWS', 'IAM'] },
        { id: 'apt-sim', title: 'APT Simulation: Lazarus', desc: 'Emulate TTPs of state hackers. Malware analysis and lateral movement.', time: '24h', points: 2500, skills: ['Forensics', 'C2'] },
        { id: 'ics-scada', title: 'SCADA: Water Treatment', desc: 'Critical Infrastructure hacking. Modbus traffic and PLC logic exploitation.', time: '6h', points: 1000, skills: ['OT', 'Modbus'] },
    ];

    const isPremium = false; // Mock subscription state

    return (
        <div className="min-h-screen bg-[#0a0a1f] text-white p-8 pt-24 font-orbitron">
            <div className="max-w-6xl mx-auto space-y-12">
                <div className="text-center space-y-4">
                    <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-purple-500/50 underline-offset-8 uppercase">
                        <Crown size={48} className="text-purple-500" />
                        Pro Labs
                    </h1>
                    <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">The ultimate testing grounds for elite practitioners</p>
                </div>

                {!isPremium && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="bg-gradient-to-r from-purple-600 to-indigo-600 rounded-3xl p-10 text-center space-y-6 shadow-2xl shadow-purple-600/20"
                    >
                        <h2 className="text-3xl font-black tracking-tight flex items-center justify-center gap-4">
                            <Lock size={32} />
                            UPGRADE TO ACCESS PRO LABS
                        </h2>
                        <p className="text-white/80 font-mono font-bold max-w-2xl mx-auto text-sm leading-relaxed uppercase tracking-widest">
                            Get unlimited access to advanced network simulations, certification prep material, and our exclusive red team labs.
                        </p>
                        <button className="px-12 py-5 bg-white text-purple-600 font-black rounded-2xl shadow-xl transition-all hover:-translate-y-1 uppercase tracking-widest text-lg">
                            Go Premium Now
                        </button>
                    </motion.div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    {premiumLabs.map(lab => (
                        <div key={lab.id} className="relative group overflow-hidden rounded-3xl border border-white/10 bg-white/5 p-8 flex flex-col justify-between h-full hover:border-purple-500/30 transition-all">
                            {!isPremium && (
                                <div className="absolute inset-0 bg-black/60 backdrop-blur-md z-10 flex flex-col items-center justify-center p-8 text-center space-y-4">
                                    <Lock size={48} className="text-white/20" />
                                    <div className="text-[10px] font-black tracking-[0.5em] text-white/40 uppercase">Subscription Required</div>
                                </div>
                            )}

                            <div className="space-y-4 relative z-0">
                                <div className="flex justify-between items-start">
                                    <h3 className="text-2xl font-black group-hover:text-purple-400 transition-colors uppercase leading-tight tracking-tight">{lab.title}</h3>
                                    <div className="px-3 py-1 bg-purple-500 text-white text-[10px] font-black rounded uppercase tracking-widest">Pro</div>
                                </div>
                                <p className="text-sm text-white/40 font-mono leading-relaxed">{lab.desc}</p>

                                <div className="flex gap-4">
                                    {lab.skills.map(skill => (
                                        <span key={skill} className="px-3 py-1 bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[10px] font-bold rounded uppercase tracking-widest">{skill}</span>
                                    ))}
                                </div>

                                <div className="flex gap-8 pt-4">
                                    <div className="flex items-center gap-2 text-[10px] font-black text-white/20 uppercase tracking-widest">
                                        <Clock size={14} className="text-purple-500" /> {lab.time}
                                    </div>
                                    <div className="flex items-center gap-2 text-[10px] font-black text-white/20 uppercase tracking-widest">
                                        <Star size={14} className="text-purple-500" /> {lab.points} PTS
                                    </div>
                                </div>
                            </div>

                            <button
                                disabled={!isPremium}
                                className={`mt-8 w-full py-4 text-xs font-black rounded-xl transition-all uppercase tracking-[0.3em] flex items-center justify-center gap-3 relative z-0 ${isPremium ? 'bg-purple-600 text-white shadow-lg' : 'bg-white/5 text-white/20 border border-white/5 cursor-not-allowed'}`}
                            >
                                <Play size={16} fill="currentColor" />
                                Start Lab
                            </button>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ProLabs;
