import React from 'react';
import { motion } from 'framer-motion';
import { Info, Shield, Server, Terminal, Layers, Globe, Zap, Cpu } from 'lucide-react';

const ShadowHackSpecs = () => {
    const specs = [
        { label: 'Virtualization', value: 'KVM / Proxmox', icon: Server },
        { label: 'Network Isolation', value: 'VLAN / VXLAN', icon: Globe },
        { label: 'Lab Instances', value: 'Dynamic Docker Spawning', icon: Layers },
        { label: 'Security Layer', value: 'PFSense / Suricata', icon: Shield }
    ];

    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div className="relative">
                <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-primary-500/[0.02] rounded-full blur-[150px] pointer-events-none" />
                <div className="relative z-10">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4">
                        <Info size={12} />
                        Infrastructure Specs
                    </div>
                    <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-none glitch-text">
                        ShadowHack <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-500 to-accent-500">Specs</span>
                    </h1>
                    <p className="mt-4 text-gray-400 italic font-medium max-w-xl">
                        Operational specifications and technical architecture of the ShadowHack
                        infrastructure. Understanding the matrix is the first step to mastering it.
                    </p>
                </div>
            </div>

            {/* Hardware/Tech Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {specs.map((item, i) => (
                    <div key={i} className="p-8 rounded-3xl bg-dark-800/40 border border-white/5 backdrop-blur-sm group">
                        <div className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-primary-500 mb-6 group-hover:scale-110 transition-transform">
                            <item.icon size={24} />
                        </div>
                        <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-1">{item.label}</div>
                        <div className="text-lg font-black text-white italic uppercase tracking-tighter">{item.value}</div>
                    </div>
                ))}
            </div>

            {/* Detailed Briefing */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 p-10 rounded-[2.5rem] bg-dark-800/60 border border-white/5 backdrop-blur-md space-y-8 relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary-500 to-transparent opacity-50" />

                    <div className="space-y-4">
                        <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter flex items-center gap-3">
                            <Zap className="text-primary-500" />
                            Operational Overview
                        </h2>
                        <div className="prose prose-invert max-w-none text-gray-400 italic leading-relaxed space-y-4">
                            <p>
                                Welcome to ShadowHack, a high-fidelity offensive security playground. Our infrastructure is built for maximum isolation and performance, allowing operatives to deploy complex scenarios at the click of a button.
                            </p>
                            <p>
                                Every lab instance is sandboxed within its own micro-network, monitored by an automated judge system that verifies flag submissions in real-time. The environment emulates real-world enterprise architectures, including Active Directory forests, cloud-hybrid nodes, and legacy mainframe systems.
                            </p>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-8 border-t border-white/5">
                        <div className="space-y-4">
                            <h3 className="text-sm font-black text-primary-500 uppercase tracking-widest">Environment Protocols</h3>
                            <ul className="space-y-2">
                                {['Zero Trust Networking', 'Automated Reset Cycles', 'Ephemeral Storage', 'Encrypted Uplinks'].map((p, i) => (
                                    <li key={i} className="flex items-center gap-2 text-xs font-bold text-gray-400 italic">
                                        <div className="w-1 h-1 bg-primary-500 rounded-full" />
                                        {p}
                                    </li>
                                ))}
                            </ul>
                        </div>
                        <div className="space-y-4">
                            <h3 className="text-sm font-black text-primary-500 uppercase tracking-widest">Access Guidelines</h3>
                            <ul className="space-y-2">
                                {['Connect via Shadow-VPN', 'Observe ROI Limits', 'No Data Persistence', 'Authorized Use Only'].map((p, i) => (
                                    <li key={i} className="flex items-center gap-2 text-xs font-bold text-gray-400 italic">
                                        <div className="w-1 h-1 bg-primary-500 rounded-full" />
                                        {p}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>

                {/* System Status Sidebar */}
                <div className="space-y-6">
                    <div className="p-8 rounded-3xl bg-dark-800/40 border border-white/5 backdrop-blur-sm">
                        <h3 className="text-xs font-black text-white uppercase tracking-widest mb-6 flex items-center justify-between">
                            System Health
                            <span className="flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                                <span className="text-[8px] text-green-500">OPERATIONAL</span>
                            </span>
                        </h3>
                        <div className="space-y-4">
                            {[
                                { label: 'CPU Load', value: '42%' },
                                { label: 'Memory', value: '128GB / 512GB' },
                                { label: 'Active Sessions', value: '1,024' },
                                { label: 'Database Sync', value: '99.9%' }
                            ].map((stat, i) => (
                                <div key={i} className="space-y-1.5">
                                    <div className="flex justify-between text-[10px] font-black uppercase tracking-widest">
                                        <span className="text-gray-500">{stat.label}</span>
                                        <span className="text-gray-300">{stat.value}</span>
                                    </div>
                                    <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                        <div className="h-full bg-primary-500/50" style={{ width: stat.value === '1,024' ? '70%' : stat.value }} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="p-8 rounded-3xl bg-primary-500/10 border border-primary-500/20 backdrop-blur-sm relative overflow-hidden group">
                        <div className="relative z-10">
                            <h3 className="text-sm font-black text-white uppercase italic tracking-tighter mb-2">Need Direct Uplink?</h3>
                            <p className="text-[10px] text-gray-400 italic mb-4">Contact terminal support for priority infrastructure access.</p>
                            <button className="w-full py-3 bg-primary-500 text-white text-[10px] font-black uppercase tracking-widest rounded-xl hover:bg-primary-400 transition-colors shadow-lg">
                                Open Support Ticket
                            </button>
                        </div>
                        <Cpu size={80} className="absolute -right-6 -bottom-6 opacity-5 group-hover:scale-110 transition-transform duration-700" />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ShadowHackSpecs;
