import React, { useState } from 'react';
import { User, Lock, Bell, Shield, CreditCard, Save } from 'lucide-react';
import { motion } from 'framer-motion';

const Settings = () => {
    const [activeTab, setActiveTab] = useState('profile');

    const tabs = [
        { id: 'profile', label: 'Profile', icon: User },
        { id: 'security', label: 'Security', icon: Lock },
        { id: 'notifications', label: 'Terminal Alerts', icon: Bell },
        { id: 'billing', label: 'Crypto Ledger', icon: CreditCard }
    ];

    return (
        <div className="max-w-5xl mx-auto space-y-12 animate-fade-in">
            <div className="flex flex-col md:flex-row gap-12">
                <div className="w-full md:w-64 space-y-2">
                    {tabs.map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`w-full flex items-center gap-4 px-6 py-4 rounded-2xl transition-all uppercase tracking-widest text-[10px] font-black border-2 ${activeTab === tab.id
                                    ? 'bg-primary-500/10 border-primary-500/50 text-primary-500 shadow-lg shadow-primary-500/5'
                                    : 'bg-white/5 border-transparent text-white/30 hover:bg-white/10'
                                }`}
                        >
                            <tab.icon size={16} />
                            {tab.label}
                        </button>
                    ))}
                </div>

                <div className="flex-1 bg-dark-800/50 border border-white/5 rounded-[2.5rem] p-10 space-y-10 relative overflow-hidden backdrop-blur-xl">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-primary-500/5 rounded-full blur-3xl -mr-16 -mt-16" />

                    {activeTab === 'profile' && (
                        <div className="space-y-8 animate-fade-in">
                            <h2 className="text-3xl font-black uppercase italic tracking-tighter text-white/90">Operative Identity</h2>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                <div className="space-y-3">
                                    <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.2em] ml-2">Codename</label>
                                    <input type="text" className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-4 text-white focus:border-primary-500/50 outline-none transition-all font-mono" placeholder="john_doe_99" />
                                </div>
                                <div className="space-y-3">
                                    <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.2em] ml-2">Communication Channel</label>
                                    <input type="email" className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-4 text-white focus:border-primary-500/50 outline-none transition-all font-mono" placeholder="john@ops.center" />
                                </div>
                            </div>
                            <div className="space-y-3">
                                <label className="text-[10px] font-black text-white/20 uppercase tracking-[0.2em] ml-2">Personnel Bio</label>
                                <textarea rows="4" className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-4 text-white focus:border-primary-500/50 outline-none transition-all font-mono" placeholder="Describe your operational background..." />
                            </div>
                        </div>
                    )}

                    {activeTab === 'security' && (
                        <div className="space-y-8 animate-fade-in">
                            <h2 className="text-3xl font-black uppercase italic tracking-tighter text-white/90">Defense Protocols</h2>
                            <div className="space-y-6">
                                <button className="w-full flex items-center justify-between p-6 bg-white/5 border border-white/5 rounded-2xl hover:border-primary-500/30 transition-all group">
                                    <div className="flex items-center gap-4">
                                        <Shield className="text-primary-500" />
                                        <div className="text-left">
                                            <div className="text-xs font-black uppercase text-white">2FA Authentication</div>
                                            <div className="text-[10px] text-white/30 uppercase tracking-widest">Add an extra layer of defense</div>
                                        </div>
                                    </div>
                                    <div className="text-primary-500 text-[10px] font-black uppercase tracking-widest">Enable</div>
                                </button>
                                <button className="w-full flex items-center justify-between p-6 bg-white/5 border border-white/5 rounded-2xl hover:border-primary-500/30 transition-all group">
                                    <div className="flex items-center gap-4">
                                        <Lock className="text-primary-500" />
                                        <div className="text-left">
                                            <div className="text-xs font-black uppercase text-white">Encryption Keys</div>
                                            <div className="text-[10px] text-white/30 uppercase tracking-widest">Manage your private RSA keys</div>
                                        </div>
                                    </div>
                                    <div className="text-primary-500 text-[10px] font-black uppercase tracking-widest">Manage</div>
                                </button>
                            </div>
                        </div>
                    )}

                    <div className="pt-10 border-t border-white/5">
                        <button className="px-10 py-4 bg-primary-600 hover:bg-primary-500 text-dark-900 font-black rounded-2xl transition-all hover:scale-105 uppercase tracking-[0.2em] text-xs flex items-center gap-3 active:scale-95 shadow-xl shadow-primary-600/10">
                            <Save size={16} /> Deploy Changes
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Settings;
