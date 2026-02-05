import React from 'react';
import {
    Wrench, Bomb, FileText, Hash, Shield,
    Network, Fingerprint, Lock, ArrowRight, Scroll,
    Radar, Bot, Crosshair, Code, Activity, Crown,
    Database, Microscope, Search, Globe, Library, Bug, Download
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

const ToolsHub = () => {
    const tools = [
        // Advanced Simulators
        { title: 'C2 Command Ctr', desc: 'Red Team Ops: Manage agents & exfiltrate loot.', icon: Network, color: 'text-red-500', link: '/tools/c2-red-ops' },
        { title: 'Cloud Security Pro', desc: 'AWS/Azure Professional auditing & IAM exploitation.', icon: Globe, color: 'text-blue-400', link: '/tools/cloud-security' },

        // Offensive & Exploitation
        { title: 'API Security', desc: 'Test OWASP API Top 10 vulnerabilities.', icon: Database, color: 'text-indigo-400', link: '/tools/api-security' },
        { title: 'Web Exploitation', desc: 'XSS, SQLi, and SSRF vulnerability lab.', icon: Bug, color: 'text-orange-400', link: '/tools/web-exploitation' },
        { title: 'JS Monitor Pro', desc: 'Advanced DOM, Endpoint & Secret analyzer.', icon: Activity, color: 'text-yellow-400', link: '/tools/js-monitor' },
        { title: 'Payload Gen', desc: 'Reverse shells and command injection payloads.', icon: Bomb, color: 'text-red-500', link: '/tools/payload-gen' },
        { title: 'Pass Cracker', desc: 'Offline & Online password attack suite.', icon: Lock, color: 'text-red-600', link: '/tools/password-cracker' },

        { title: 'AD Attack Lab', desc: 'Active Directory exploitation & AI planning.', icon: Network, color: 'text-blue-400', link: '/tools/ad-attack-lab' },
        { title: 'CVE Radar', desc: 'Real-time vulnerability feed & patch analysis.', icon: Radar, color: 'text-red-400', link: '/tools/cve-radar' },
        { title: 'CVE Museum', desc: 'Interactive archive of historical vulnerabilities.', icon: Library, color: 'text-blue-500', link: '/tools/cve-museum' },
        { title: 'Finding Reporter', desc: 'Professional security reporting & CVSS calc.', icon: FileText, color: 'text-cyan-400', link: '/tools/finding-reporter' },
        { title: 'OSINT Pro', desc: 'Open source intelligence & deep reconnaissance.', icon: Globe, color: 'text-emerald-400', link: '/tools/osint-lab' },
        { title: 'Recon Lab', desc: 'Active and passive infrastructure discovery.', icon: Search, color: 'text-blue-500', link: '/tools/recon-lab' },
        { title: 'Malware Sandbox', desc: 'Simulated static and behavioral analysis.', icon: Microscope, color: 'text-red-400', link: '/tools/malware-sandbox' },

        // Operations & Management
        { title: 'Target Manager', desc: 'Track assets, scope, and vulnerabilities.', icon: Crosshair, color: 'text-rose-500', link: '/tools/target-manager' },
        { title: 'Campaigns', desc: 'Manage engagement timelines and progress.', icon: Scroll, color: 'text-amber-500', link: '/tools/campaign-manager' },
        { title: 'Report Builder', desc: 'Generate professional pentest reports.', icon: FileText, color: 'text-blue-500', link: '/tools/report-builder' },
        { title: 'Encoder/Decoder', desc: 'B64, URL, and Hex conversion utility.', icon: Hash, color: 'text-purple-500', link: '/tools/encoder' },
        { title: 'Cheatsheets', desc: 'Quick reference for commands and syntax.', icon: Code, color: 'text-green-500', link: '/tools/cheatsheets', upcoming: true },

        // Knowledge & Utils
        { title: 'Crypto Forge', desc: 'Pro cryptography & file hashing suite.', icon: Lock, color: 'text-yellow-500', link: '/tools/crypto-lab' },
        { title: 'Stego Analyst', desc: 'Image & Text steganography toolkit.', icon: Eye, color: 'text-purple-500', link: '/tools/stego-lab' },
        { title: 'Hash Identifier', desc: 'Identify hash types and cracking formats.', icon: Fingerprint, color: 'text-indigo-500', link: '/tools/hash-identifier' },
        { title: 'Subnet Calc', desc: 'Calculate CIDR ranges and network masks.', icon: Network, color: 'text-cyan-500', link: '/tools/subnet-calc' },
        { title: 'XSS Payloads', desc: 'Cross-site scripting payload library.', icon: Bug, color: 'text-orange-500', link: '/tools/xss-payloads' },
        { title: 'SQLi Payloads', desc: 'SQL injection payload library.', icon: Database, color: 'text-blue-400', link: '/tools/sqli-payloads' },
        { title: 'File Transfer', desc: 'Red team file transfer cheatsheet.', icon: Download, color: 'text-emerald-400', link: '/tools/file-transfer' },
        { title: 'PrivEsc Pro', desc: 'Professional Win & Linux escalation mastery.', icon: Shield, color: 'text-yellow-500', link: '/tools/privesc-lab' },
        { title: 'Command Reference', desc: '200+ commands for pentests & CTFs.', icon: Code, color: 'text-green-400', link: '/tools/command-ref' },
        { title: 'MITRE ATT&CK', desc: 'Track your red team skills by technique.', icon: Shield, color: 'text-red-500', link: '/tools/mitre-attack' },
        { title: 'Social Eng Pro', desc: 'Phishing manager, AI pretexting, & target profiling.', icon: Fingerprint, color: 'text-purple-400', link: '/tools/social-eng' },
        { title: 'Persona Pro', desc: 'Sock-puppet manager & OpSec-safe identity vault.', icon: Fingerprint, color: 'text-pink-500', link: '/tools/persona-factory' },
    ];

    return (
        <div className="max-w-7xl mx-auto space-y-12 animate-fade-in">
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-indigo-500/50 underline-offset-8">
                    <Wrench size={48} className="text-indigo-500" />
                    TOOLS HUB
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Essential utilities for the modern operative</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {tools.map(tool => (
                    <Link
                        to={tool.upcoming ? '#' : tool.link}
                        key={tool.title}
                        className={`group block p-8 rounded-3xl border transition-all relative overflow-hidden ${tool.upcoming ? 'bg-white/5 border-white/5 cursor-not-allowed opacity-50' : 'bg-white/5 border-white/10 hover:border-indigo-500/30 hover:bg-white/10'}`}
                    >
                        {tool.upcoming && (
                            <div className="absolute top-4 right-4 text-[8px] font-black tracking-widest bg-white/10 px-2 py-1 rounded text-white/40">CALIBRATING...</div>
                        )}

                        <div className="space-y-6">
                            <div className={`p-4 rounded-2xl bg-white/5 w-fit group-hover:scale-110 transition-transform ${tool.color}`}>
                                <tool.icon size={32} />
                            </div>

                            <div className="space-y-2">
                                <h3 className="text-xl font-black tracking-tight uppercase group-hover:text-indigo-400 transition-colors">{tool.title}</h3>
                                <p className="text-xs text-white/40 font-mono leading-relaxed">{tool.desc}</p>
                            </div>

                            {!tool.upcoming && (
                                <div className="flex items-center gap-2 text-[10px] font-black text-indigo-500 uppercase tracking-[0.2em] group-hover:translate-x-2 transition-transform">
                                    Launch Tool <ArrowRight size={14} />
                                </div>
                            )}
                        </div>
                    </Link>
                ))}
            </div>
        </div>
    );
};

export default ToolsHub;



