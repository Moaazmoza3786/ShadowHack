import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
    Shield,
    Lock,
    Key,
    Database,
    Code,
    Settings,
    Package,
    UserCheck,
    GitBranch,
    Activity,
    Award,
    BookOpen,
    Play,
    Globe
} from 'lucide-react';

import { owaspEducationData } from '../data/owasp-data';

const iconMap = {
    Lock,
    Key,
    Database,
    Code,
    Settings,
    Package,
    UserCheck,
    GitBranch,
    Activity,
    Globe
};


const OWASPRange = () => {
    const vulnerabilities = Object.values(owaspEducationData || {});

    const stats = [
        { icon: Package, label: '10 Modules', color: 'text-blue-500' },
        { icon: Activity, label: 'Live Simulation', color: 'text-blue-400' },
        { icon: Award, label: 'Pro Certification', color: 'text-blue-300' }
    ];

    return (
        <div className="min-h-screen space-y-12 pb-20">
            {/* Header Section */}
            <div className="text-center space-y-6">
                <div className="flex justify-center items-center gap-4">
                    <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center neon-glow-primary">
                        <Shield size={32} className="text-white" />
                    </div>
                    <h1 className="text-6xl font-black italic tracking-tighter uppercase leading-none">
                        OWASP <span className="text-red-500">Cyber Range</span>
                    </h1>
                </div>
                <p className="text-gray-400 font-medium tracking-wide uppercase text-sm">
                    Professional Vulnerability Assessment & Exploitation Simulation
                </p>

                {/* Stat Badges */}
                <div className="flex items-center justify-center gap-8 pt-4">
                    {stats.map((stat, idx) => {
                        const Icon = stat.icon;
                        return (
                            <div key={idx} className="flex items-center gap-2 group cursor-default">
                                <Icon size={16} className={`${stat.color} group-hover:scale-110 transition-transform`} />
                                <span className="text-[10px] font-black uppercase tracking-[0.2em] text-gray-500 group-hover:text-gray-300 transition-colors">
                                    {stat.label}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Grid Layout */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 px-4">
                {vulnerabilities.map((vuln, idx) => {
                    const Icon = iconMap[vuln.icon] || Shield;
                    return (
                        <motion.div
                            key={vuln.id}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.05 }}
                            className="group relative bg-dark-800/40 border border-white/5 rounded-2xl p-8 hover:border-primary-500/30 transition-all hover:shadow-[0_0_30px_rgba(239,68,68,0.05)]"
                        >
                            {/* Card Content */}
                            <div className="space-y-6">
                                <div className="flex items-start justify-between">
                                    <div className="w-14 h-14 rounded-xl bg-white/5 border border-white/5 flex items-center justify-center group-hover:scale-110 transition-transform duration-500">
                                        <Icon size={28} className="text-blue-500" />
                                    </div>
                                    <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981]" />
                                </div>

                                <div className="space-y-4">
                                    <h3 className="text-xl font-bold text-gray-100 group-hover:text-white transition-colors">
                                        {vuln.title}
                                    </h3>

                                    <div className={`inline-flex px-3 py-1 rounded-full text-[10px] font-black tracking-widest border ${vuln.difficulty === 'HARD' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                                        vuln.difficulty === 'MEDIUM' ? 'bg-orange-500/10 border-orange-500/20 text-orange-500' :
                                            'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                                        }`}>
                                        {vuln.difficulty}
                                    </div>
                                </div>

                                {/* Action Buttons */}
                                <div className="flex items-center gap-3 pt-4">
                                    <Link
                                        to={`/owasp-range/${vuln.id}/learn`}
                                        className="flex-1 h-10 flex items-center justify-center gap-2 rounded-lg bg-primary-600/20 border border-primary-500/30 text-white text-xs font-black uppercase tracking-widest hover:bg-primary-500 transition-all shadow-[0_0_15px_rgba(239,68,68,0.1)]"
                                    >
                                        <BookOpen size={14} />
                                        <span>Learn</span>
                                    </Link>
                                    <Link
                                        to={`/owasp-range/${vuln.id}/practice`}
                                        className="flex-1 h-10 flex items-center justify-center gap-2 rounded-lg bg-dark-900/50 border border-white/10 text-gray-300 text-xs font-black uppercase tracking-widest hover:bg-white/5 hover:text-white transition-all hover:border-white/20"
                                    >
                                        <Play size={14} />
                                        <span>Practice</span>
                                    </Link>
                                </div>
                            </div>
                        </motion.div>
                    );
                })}
            </div>
        </div>
    );
};

export default OWASPRange;

