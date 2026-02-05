import React from 'react';
import { Shield, Eye, Ambulance, Crosshair, Microscope, Bug, ShieldAlert, Play } from 'lucide-react';
import { motion } from 'framer-motion';

const BlueTeamPath = () => {
    const modules = [
        { title: 'Security Monitoring', desc: 'SIEM, log analysis, and detection.', icon: Eye, rooms: 5, progress: 0 },
        { title: 'Incident Response', desc: 'Containment, eradication, and recovery.', icon: Ambulance, rooms: 6, progress: 0 },
        { title: 'Threat Intelligence', desc: 'IOCs, TTPs, and threat hunting.', icon: Crosshair, rooms: 4, progress: 0 },
        { title: 'Forensics', desc: 'Disk, memory, and network forensics.', icon: Microscope, rooms: 7, progress: 0 },
        { title: 'Malware Analysis', desc: 'Static and dynamic binary analysis.', icon: Bug, rooms: 5, progress: 0 },
        { title: 'System Hardening', desc: 'OS and network security hardening.', icon: ShieldAlert, rooms: 4, progress: 0 }
    ];

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-fade-in font-mono">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gradient-to-br from-blue-500/10 via-dark-800 to-black border border-blue-500/20 rounded-[2.5rem] p-12 text-center space-y-8 relative overflow-hidden backdrop-blur-xl"
            >
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-blue-500 to-transparent" />
                <div className="mx-auto w-24 h-24 bg-blue-500/10 rounded-3xl flex items-center justify-center border border-blue-500/30 shadow-2xl shadow-blue-500/10">
                    <Shield size={48} className="text-blue-500" />
                </div>
                <div className="space-y-3">
                    <h1 className="text-5xl font-black tracking-tighter uppercase italic leading-none">Blue Team Operator</h1>
                    <p className="text-white/40 font-mono text-sm max-w-2xl mx-auto uppercase tracking-[0.2em] leading-relaxed">
                        Master defensive security. Learn to detect, respond to, and prevent cyber attacks to protect real-world organizations.
                    </p>
                </div>
                <div className="flex justify-center gap-16 pt-4">
                    <div className="text-center">
                        <div className="text-3xl font-black text-blue-500 italic">31</div>
                        <div className="text-[10px] text-white/20 font-bold uppercase tracking-[0.3em]">Rooms</div>
                    </div>
                    <div className="text-center">
                        <div className="text-3xl font-black text-blue-500 italic">35+</div>
                        <div className="text-[10px] text-white/20 font-bold uppercase tracking-[0.3em]">Hours</div>
                    </div>
                    <div className="text-center">
                        <div className="text-3xl font-black text-blue-500 italic">6</div>
                        <div className="text-[10px] text-white/20 font-bold uppercase tracking-[0.3em]">Modules</div>
                    </div>
                </div>
                <button className="px-12 py-5 bg-blue-600 hover:bg-blue-500 text-white font-black rounded-2xl transition-all hover:scale-105 uppercase tracking-[0.3em] text-xs flex items-center gap-3 mx-auto shadow-2xl shadow-blue-600/20 active:scale-95">
                    <Play size={16} fill="white" /> Initialize Path
                </button>
            </motion.div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {modules.map(module => (
                    <motion.div
                        key={module.title}
                        whileHover={{ y: -5 }}
                        className="bg-dark-800/50 border border-white/5 rounded-3xl p-8 hover:border-blue-500/30 transition-all group flex flex-col justify-between backdrop-blur-sm"
                    >
                        <div className="space-y-6">
                            <div className="flex items-center gap-5">
                                <div className="p-4 bg-blue-500/10 rounded-2xl text-blue-500 border border-blue-500/20 group-hover:scale-110 transition-transform">
                                    <module.icon size={24} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-black text-white group-hover:text-blue-400 transition-colors uppercase tracking-tight italic">{module.title}</h3>
                                    <span className="text-[10px] text-blue-500/60 font-black uppercase tracking-widest">{module.rooms} deployments</span>
                                </div>
                            </div>
                            <p className="text-xs text-white/40 leading-relaxed uppercase tracking-tight">{module.desc}</p>
                        </div>
                        <div className="mt-8 space-y-3">
                            <div className="flex justify-between text-[10px] font-black text-white/20 uppercase tracking-[0.2em]">
                                <span>Synchronization</span>
                                <span className="text-blue-500/60">{module.progress}%</span>
                            </div>
                            <div className="h-1.5 bg-white/5 rounded-full overflow-hidden p-0.5 border border-white/5">
                                <div className="h-full bg-blue-600 rounded-full shadow-[0_0_10px_rgba(37,99,235,0.5)]" style={{ width: `${module.progress}%` }} />
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default BlueTeamPath;
