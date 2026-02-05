import React from 'react';
import { Handshake, ShieldCheck, Globe, Cpu, Users, Mail } from 'lucide-react';
import { motion } from 'framer-motion';

const Partners = () => {
    const partners = [
        { name: 'OWASP', type: 'Community Partner', icon: ShieldCheck, color: 'text-primary-500' },
        { name: 'Hack The Box', type: 'Platform Partner', icon: Globe, color: 'text-primary-500' },
        { name: 'PortSwigger', type: 'Tools Partner', icon: Cpu, color: 'text-primary-500' },
        { name: 'OffSec', type: 'Certification Partner', icon: Users, color: 'text-primary-500' },
        { name: 'SANS Institute', type: 'Education Partner', icon: ShieldCheck, color: 'text-primary-500' },
        { name: 'EC-Council', type: 'Certification Partner', icon: Handshake, color: 'text-primary-500' }
    ];

    return (
        <div className="max-w-6xl mx-auto space-y-16 animate-fade-in">
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black tracking-tighter uppercase italic flex items-center justify-center gap-4 underline decoration-primary-500/50 underline-offset-8">
                    <Handshake size={48} className="text-primary-500" />
                    Strategic Alliances
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Forging the future of global cybersecurity operations</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {partners.map(p => (
                    <motion.div
                        key={p.name}
                        whileHover={{ y: -5 }}
                        className="bg-dark-800/50 border border-white/5 rounded-3xl p-10 text-center space-y-6 hover:border-primary-500/30 transition-all group backdrop-blur-sm"
                    >
                        <div className={`mx-auto w-20 h-20 bg-white/5 rounded-full flex items-center justify-center border border-white/5 group-hover:border-primary-500/20 group-hover:bg-primary-500/10 transition-all ${p.color}`}>
                            <p.icon size={32} />
                        </div>
                        <div className="space-y-1">
                            <h3 className="text-2xl font-black uppercase tracking-tight group-hover:text-primary-400 transition-colors italic">{p.name}</h3>
                            <p className="text-[10px] text-white/30 font-mono font-bold uppercase tracking-[0.2em]">{p.type}</p>
                        </div>
                    </motion.div>
                ))}
            </div>

            <div className="text-center pt-8">
                <button className="px-12 py-5 bg-primary-600 hover:bg-primary-500 text-dark-900 font-black rounded-2xl shadow-xl transition-all hover:scale-105 uppercase tracking-[0.3em] text-xs flex items-center gap-3 mx-auto active:scale-95">
                    <Mail size={16} fill="currentColor" /> Initialize Partnership
                </button>
            </div>
        </div>
    );
};

export default Partners;
