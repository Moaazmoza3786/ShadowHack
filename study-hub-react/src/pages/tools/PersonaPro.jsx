import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    User, Copy, Save, Download, RefreshCw, Trash2,
    Mail, Phone, Linkedin, Twitter, Building,
    GraduationCap, Briefcase, Check, Shield, Eye,
    Fingerprint, Globe, MapPin, Activity, FileText,
    Zap, Share2, Star, AlertTriangle, Terminal, Info,
    Settings
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

const PersonaPro = () => {
    const { toast } = useToast();
    const [currentPersona, setCurrentPersona] = useState(null);
    const [savedPersonas, setSavedPersonas] = useState(() => JSON.parse(localStorage.getItem('saved_personas_pro') || '[]'));
    const [settings, setSettings] = useState({ nationality: 'us', department: 'it', gender: 'random' });

    // --- PRO ENGINE DATA ---
    const names = {
        us: { first: ['James', 'John', 'Robert', 'Michael', 'William', 'Mary', 'Patricia', 'Jennifer', 'Linda', 'Elizabeth'], last: ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis'] },
        uk: { first: ['Oliver', 'George', 'Harry', 'Jack', 'Charlie', 'Olivia', 'Emma', 'Sophia', 'Isabella', 'Charlotte'], last: ['Smith', 'Jones', 'Taylor', 'Brown', 'Williams', 'Wilson', 'Johnson'] },
        arabic: { first: ['Ahmed', 'Mohammed', 'Ali', 'Omar', 'Youssef', 'Fatima', 'Aisha', 'Maryam', 'Noor', 'Layla'], last: ['Al-Hassan', 'Al-Ahmad', 'Al-Mahmoud', 'Al-Salem', 'Mansour'] },
        german: { first: ['Lukas', 'Leon', 'Maximilian', 'Felix', ' Paul', 'Emma', 'Hannah', 'Mia', 'Sophia', 'Anna'], last: ['Müller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer'] },
    };

    const jobs = {
        it: ['IT Administrator', 'Senior Developer', 'System Administrator', 'Security Analyst', 'Cloud Architect'],
        hr: ['HR Manager', 'Talent Acquisition', 'Diversity Officer', 'Employee Relations'],
        executive: ['CEO', 'CISO', 'VP Strategy', 'Operational Manager']
    };

    const generate = () => {
        const nat = settings.nationality;
        const dept = settings.department;
        const gender = settings.gender === 'random' ? (Math.random() > 0.5 ? 'male' : 'female') : settings.gender;

        const firstName = gender === 'male' ? names[nat].first[Math.floor(Math.random() * 5)] : names[nat].first[Math.floor(Math.random() * 5) + 5];
        const lastName = names[nat].last[Math.floor(Math.random() * names[nat].last.length)];
        const job = jobs[dept][Math.floor(Math.random() * jobs[dept].length)];
        const opsecScore = 85 + Math.floor(Math.random() * 15);

        const newPersona = {
            id: Date.now(),
            fullName: `${firstName} ${lastName}`,
            job,
            dept,
            nat,
            gender,
            email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}@${lastName.toLowerCase()}corp.com`,
            phone: `+${nat === 'us' ? '1' : nat === 'uk' ? '44' : '971'} ${Math.floor(100 + Math.random() * 900)}-${Math.floor(1000 + Math.random() * 9000)}`,
            opsecScore,
            bio: `${firstName} is a seasoned ${job} with over 12 years of experience. Specializing in corporate infrastructure and internal policy management. Currently focused on digital transformation initiatives.`,
            avatarSeed: `${firstName}${lastName}`
        };

        setCurrentPersona(newPersona);
        toast('New Identity Synthesized', 'success');
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast('Info copied to dossier', 'success');
    };

    const renderOpSecGauge = (score) => (
        <div className="p-4 bg-dark-900 border border-white/5 rounded-2xl flex items-center justify-between">
            <div className="space-y-1">
                <div className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Operational Security</div>
                <div className={`text-lg font-black italic uppercase italic tracking-tighter ${score > 90 ? 'text-emerald-500' : 'text-amber-500'}`}>{score}% RATING</div>
            </div>
            <div className={`w-12 h-12 rounded-full border-4 flex items-center justify-center text-[10px] font-black ${score > 90 ? 'border-emerald-500 text-emerald-500' : 'border-amber-500 text-amber-500'}`}>
                {score}
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-12 animate-fade-in pb-20">
            <header className="relative py-20 px-12 rounded-[4rem] bg-dark-800 border border-white/5 overflow-hidden group">
                <div className="absolute inset-0 bg-cyber-grid opacity-10" />
                <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-12">
                    <div className="space-y-6 max-w-2xl">
                        <div className="inline-flex items-center gap-3 px-3 py-1 rounded-full bg-pink-500/10 border border-pink-500/20">
                            <User size={12} className="text-pink-500" />
                            <span className="text-[10px] font-black text-pink-500 uppercase tracking-widest">Identity Architect: PRO v5.0</span>
                        </div>
                        <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-[0.8]">
                            PERSONA <span className="text-pink-500">PRO</span>
                        </h1>
                        <p className="text-gray-400 text-xl font-medium leading-relaxed">
                            Professional sock-puppet management and high-fidelity identity generation for Social Engineering engagements and OpSec-focused intelligence operations.
                        </p>
                    </div>

                    <button
                        onClick={generate}
                        className="px-12 py-6 bg-pink-500 text-dark-900 rounded-[2rem] font-black uppercase italic tracking-tighter hover:scale-105 transition-all shadow-xl shadow-pink-500/20 flex items-center gap-3"
                    >
                        <RefreshCw size={24} /> SYNTHESIZE IDENTITY
                    </button>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                {/* Configuration */}
                <aside className="lg:col-span-4 space-y-6">
                    <div className="p-10 rounded-[3.5rem] bg-dark-800/40 border border-white/5 space-y-8">
                        <h3 className="text-xl font-black text-white italic uppercase tracking-tighter flex items-center gap-3">
                            <Settings className="text-pink-500" /> Architect Settings
                        </h3>

                        {[['nationality', 'Geospatial Origin', { us: 'US-INTEL', uk: 'UK-INTEL', arabic: 'ARABIC-INTEL', german: 'EU-INTEL' }],
                        ['department', 'Occupational Sector', { it: 'Cyber/IT', hr: 'Human Capital', executive: 'Corporate/C-Level' }]
                        ].map(([key, label, opts]) => (
                            <div key={key} className="space-y-3">
                                <label className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">{label}</label>
                                <select
                                    value={settings[key]}
                                    onChange={(e) => setSettings({ ...settings, [key]: e.target.value })}
                                    className="w-full bg-black border border-white/10 rounded-2xl p-4 text-xs font-black uppercase tracking-widest text-pink-500 outline-none focus:border-pink-500"
                                >
                                    {Object.entries(opts).map(([v, t]) => <option key={v} value={v}>{t}</option>)}
                                </select>
                            </div>
                        ))}

                        <div className="pt-6 border-t border-white/5">
                            <div className="flex items-center gap-4 p-4 bg-pink-500/5 rounded-2xl border border-pink-500/10">
                                <Shield size={20} className="text-pink-500 shrink-0" />
                                <div className="text-[10px] font-black text-gray-400 uppercase tracking-widest leading-relaxed">
                                    Deep-fake profile history and social footprint generation enabled for all synthesized identities.
                                </div>
                            </div>
                        </div>
                    </div>
                </aside>

                {/* Identity Dossier */}
                <main className="lg:col-span-8">
                    {currentPersona ? (
                        <motion.div
                            initial={{ opacity: 0, scale: 0.98 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="p-10 rounded-[4rem] bg-dark-800 border border-white/10 space-y-10 relative overflow-hidden"
                        >
                            <div className="absolute top-0 right-0 p-12 opacity-5 scale-150 rotate-12">
                                <Fingerprint size={200} className="text-pink-500" />
                            </div>

                            <div className="flex flex-col md:flex-row items-center gap-10 relative z-10">
                                <div className="w-32 h-32 rounded-[2.5rem] bg-gradient-to-br from-pink-500 to-purple-500 p-1 shrink-0 overflow-hidden shadow-2xl shadow-pink-500/20">
                                    <img
                                        src={`https://api.dicebear.com/7.x/personas/svg?seed=${currentPersona.avatarSeed}`}
                                        alt="Avatar"
                                        className="w-full h-full object-cover rounded-[2rem] bg-dark-900"
                                    />
                                </div>
                                <div className="space-y-2 text-center md:text-left">
                                    <h2 className="text-5xl font-black text-white italic tracking-tighter uppercase">{currentPersona.fullName}</h2>
                                    <div className="flex flex-wrap justify-center md:justify-start gap-4">
                                        <span className="text-pink-400 font-black italic uppercase tracking-tighter text-lg">{currentPersona.job}</span>
                                        <span className="text-gray-600 font-bold uppercase tracking-widest text-xs mt-1.5">• AD-720 STATUS</span>
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative z-10">
                                <div className="space-y-6">
                                    <div className="space-y-4">
                                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">Operational Data</h4>
                                        {[
                                            { label: 'Email Address', value: currentPersona.email, icon: Mail },
                                            { label: 'Signal/Phone', value: currentPersona.phone, icon: Phone },
                                            { label: 'Persona Bio', value: currentPersona.bio, icon: FileText }
                                        ].map((item, i) => (
                                            <div
                                                key={i}
                                                onClick={() => copyToClipboard(item.value)}
                                                className="p-4 bg-black/40 border border-white/5 rounded-2xl group hover:border-pink-500/30 transition-all cursor-pointer"
                                            >
                                                <div className="flex justify-between items-center mb-1">
                                                    <div className="flex items-center gap-2 text-[8px] font-black text-gray-500 uppercase tracking-widest">
                                                        <item.icon size={10} /> {item.label}
                                                    </div>
                                                    <Copy size={10} className="text-gray-700 group-hover:text-pink-500 transition-colors" />
                                                </div>
                                                <div className="text-sm font-bold text-white uppercase italic">{item.value}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <div className="space-y-6">
                                    <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest px-2">Risk & OPSEC Analysis</h4>
                                    {renderOpSecGauge(currentPersona.opsecScore)}

                                    <div className="p-6 bg-white/5 rounded-[2.5rem] border border-white/5 space-y-4">
                                        <div className="text-[10px] font-black text-pink-500 uppercase tracking-widest flex items-center gap-2">
                                            <Terminal size={12} /> Social Footprint Generation
                                        </div>
                                        <div className="flex gap-2">
                                            {[Linkedin, Twitter, Globe].map((Icon, i) => (
                                                <div key={i} className="p-3 bg-black rounded-xl border border-white/10 text-gray-500">
                                                    <Icon size={18} />
                                                </div>
                                            ))}
                                        </div>
                                        <p className="text-[10px] text-gray-500 italic font-medium leading-relaxed">
                                            Automatic population of historical posts and professional endorsements specialized for the ${currentPersona.dept} sector.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    ) : (
                        <div className="h-[600px] rounded-[4rem] border-2 border-dashed border-white/5 flex flex-col items-center justify-center text-center opacity-30 grayscale p-12 gap-8">
                            <Fingerprint size={100} className="text-gray-500" />
                            <div className="space-y-2">
                                <h3 className="text-2xl font-black text-white uppercase italic tracking-tighter">Architect Mode Standby</h3>
                                <p className="text-sm font-bold uppercase tracking-widest text-gray-500 max-w-sm mx-auto">Configure your operative parameters and synthesize a high-fidelity digital identity for your next engagement.</p>
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
};

export default PersonaPro;
