import React from 'react';
import { Map, ArrowRight, Shield, Globe, Network, Clock, Box } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

const Campaigns = () => {
    const campaigns = [
        {
            id: 'red-team',
            title: 'Red Team Operator',
            desc: 'Full spectrum adversary simulation. Breach, pivot, and persist in enterprise networks.',
            icon: Shield,
            color: 'text-red-500',
            border: 'hover:border-red-500/40',
            bg: 'hover:bg-red-500/10',
            rooms: 33,
            time: '40h',
            link: '/paths/red-team'
        },
        {
            id: 'web-adversary',
            title: 'Web Adversary',
            desc: 'Master modern web exploitation. SQLi, XSS, SSRF, and advanced deserialization.',
            icon: Globe,
            color: 'text-orange-500',
            border: 'hover:border-orange-500/40',
            bg: 'hover:bg-orange-500/10',
            rooms: 45,
            time: '55h',
            link: '/topics/web'
        },
        {
            id: 'domain-dominance',
            title: 'Active Directory',
            desc: 'Compromise forests, Kerberos attacks, and domain dominance.',
            icon: Network,
            color: 'text-purple-500',
            border: 'hover:border-purple-500/40',
            bg: 'hover:bg-purple-500/10',
            rooms: 12,
            time: '20h',
            link: '/topics/ad'
        }
    ];

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-white p-8 pt-24 font-orbitron">
            <div className="max-w-6xl mx-auto space-y-12">
                <div className="text-center space-y-4">
                    <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-red-600/50 underline-offset-8 uppercase">
                        <Map size={48} className="text-red-600" />
                        Active Campaigns
                    </h1>
                    <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Targeted learning missions across the security landscape</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                    {campaigns.map(campaign => (
                        <Link
                            to={campaign.link}
                            key={campaign.id}
                            className={`group block p-8 rounded-3xl border border-white/10 bg-white/5 transition-all relative overflow-hidden h-full flex flex-col justify-between ${campaign.border} ${campaign.bg}`}
                        >
                            <div className="space-y-6">
                                <div className={`p-4 rounded-2xl bg-white/5 w-fit group-hover:scale-110 transition-transform ${campaign.color}`}>
                                    <campaign.icon size={36} />
                                </div>

                                <div className="space-y-2">
                                    <h3 className="text-2xl font-black tracking-tight uppercase group-hover:text-white transition-colors">{campaign.title}</h3>
                                    <p className="text-xs text-white/40 font-mono leading-relaxed">{campaign.desc}</p>
                                </div>

                                <div className="flex gap-6 text-[10px] font-black text-white/20 uppercase tracking-widest pt-4">
                                    <div className="flex items-center gap-2">
                                        <Box size={14} className={campaign.color} /> {campaign.rooms} Labs
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Clock size={14} className={campaign.color} /> {campaign.time}
                                    </div>
                                </div>
                            </div>

                            <div className="mt-8 flex items-center gap-2 text-[10px] font-black group-hover:gap-4 transition-all uppercase tracking-[0.2em] text-white/40 group-hover:text-white pt-6 border-t border-white/5">
                                Engage Campaign <ArrowRight size={14} />
                            </div>
                        </Link>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default Campaigns;
