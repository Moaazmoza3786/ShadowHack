import React from 'react';
import { 
    Github, 
    Twitter, 
    Linkedin, 
    Youtube, 
    Shield, 
    Terminal
} from 'lucide-react';
import { Link } from 'react-router-dom';

const Footer = () => {
    const currentYear = new Date().getFullYear();

    const footerLinks = [
        {
            title: "Operations",
            links: [
                { name: "Training Ground", path: "/learning-tracks" },
                { name: "CTF Arena", path: "/ctf" },
                { name: "Mission Control", path: "/dashboard" },
                { name: "Security Audit", path: "/tools" },
            ]
        },
        {
            title: "Knowledge",
            links: [
                { name: "Darknet Wiki", path: "/second-brain" },
                { name: "YouTube Academy", path: "/youtube-hub" },
                { name: "Neural Training", path: "/mentors" },
                { name: "API Uplink", path: "/api-docs" },
            ]
        },
        {
            title: "Collective",
            links: [
                { name: "Operative Roster", path: "/community" },
                { name: "Bounty Board", path: "/leaderboard" },
                { name: "Shadow Forum", path: "/forum" },
                { name: "Intel Feed", path: "/news" },
            ]
        }
    ];

    return (
        <footer className="mt-32 relative pt-20 pb-12 overflow-hidden border-t border-white/5">
            {/* Ambient background effects */}
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary-500/50 to-transparent" />
            <div className="absolute -bottom-24 left-1/2 -translate-x-1/2 w-[800px] h-[300px] bg-primary-500/5 blur-[120px] rounded-full" />
            
            <div className="max-w-[1440px] mx-auto px-8 md:px-12 relative z-10">
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 lg:gap-8 mb-20">
                    {/* Brand Section */}
                    <div className="lg:col-span-5 space-y-8">
                        <div className="flex items-center gap-4">
                            <div className="relative group">
                                <div className="absolute -inset-2 bg-primary-500 blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
                                <div className="relative w-14 h-14 rounded-2xl bg-dark-900 border border-white/10 flex items-center justify-center backdrop-blur-xl group-hover:border-primary-500/50 transition-all duration-500">
                                    <Shield size={28} className="text-primary-500" />
                                </div>
                            </div>
                            <div>
                                <h2 className="text-3xl font-black text-white italic tracking-tighter uppercase leading-none">ShadowHack</h2>
                                <p className="text-[10px] font-black text-white/30 tracking-[0.4em] uppercase mt-1">Core V3.0 // Active</p>
                            </div>
                        </div>
                        
                        <p className="max-w-md text-white/40 text-sm leading-relaxed italic">
                            The definitive neural interface for elite cyber-operatives. Master the digital domain through immersive simulation, real-time exploitation, and collective intelligence.
                        </p>

                        <div className="flex items-center gap-4">
                            {[
                                { Icon: Github, color: "hover:text-white" },
                                { Icon: Twitter, color: "hover:text-cyan-400" },
                                { Icon: Linkedin, color: "hover:text-blue-500" },
                                { Icon: Youtube, color: "hover:text-red-500" }
                            ].map((social, idx) => (
                                <a 
                                    key={idx} 
                                    href="#" 
                                    className={`w-12 h-12 rounded-xl bg-white/5 border border-white/5 flex items-center justify-center transition-all duration-300 ${social.color} hover:bg-white/10 hover:-translate-y-1`}
                                >
                                    <social.Icon size={18} />
                                </a>
                            ))}
                        </div>
                    </div>

                    {/* Navigation Columns */}
                    <div className="lg:col-span-7 grid grid-cols-2 md:grid-cols-3 gap-12">
                        {footerLinks.map((section, idx) => (
                            <div key={idx} className="space-y-6">
                                <h3 className="text-xs font-black text-white uppercase tracking-[0.2em] italic border-l-2 border-primary-500 pl-4">
                                    {section.title}
                                </h3>
                                <ul className="space-y-3">
                                    {section.links.map((link, lIdx) => (
                                        <li key={lIdx}>
                                            <Link 
                                                to={link.path} 
                                                className="text-xs font-medium text-white/40 hover:text-primary-500 hover:translate-x-1 transition-all inline-block"
                                            >
                                                {link.name}
                                            </Link>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Bottom Bar */}
                <div className="pt-12 border-t border-white/5 flex flex-col md:flex-row items-center justify-between gap-8">
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] font-black text-white/20 uppercase tracking-widest italic">&copy; {currentYear} ShadowHack Collective. All nodes secured.</span>
                    </div>

                    <div className="flex items-center gap-10">
                        <div className="flex items-center gap-4 text-white/20">
                             <div className="flex items-center gap-2">
                                <Terminal size={14} />
                                <span className="text-[10px] font-black uppercase tracking-[0.2em]">Terminal Link Ready</span>
                             </div>
                             <div className="w-1.5 h-1.5 rounded-full bg-primary-500" />
                             <span className="text-[10px] font-black uppercase tracking-[0.2em] italic">V3.14.9</span>
                        </div>
                        <div className="flex items-center gap-6">
                            <a href="#" className="text-[10px] font-black text-white/20 hover:text-white uppercase tracking-widest transition-colors">Privacy Policy</a>
                            <a href="#" className="text-[10px] font-black text-white/20 hover:text-white uppercase tracking-widest transition-colors">Neural TOS</a>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
