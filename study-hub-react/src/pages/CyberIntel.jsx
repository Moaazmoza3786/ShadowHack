import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Newspaper, ShieldAlert, FileText, Filter, Search,
    ExternalLink, Clock, RefreshCw, Share2, Bookmark,
    ArrowUpRight, Zap, Radio, Globe, Ghost
} from 'lucide-react';
import { useToast } from '../context/ToastContext';
import { useAppContext } from '../context/AppContext';

const CyberIntel = () => {
    const { apiUrl } = useAppContext();
    const API_BASE = apiUrl;

    const [activeTab, setActiveTab] = useState('news');
    const [intelData, setIntelData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [lastUpdated, setLastUpdated] = useState(null);
    const { showToast } = useToast();

    const tabs = [
        { id: 'news', label: 'Security News', icon: Newspaper, color: 'blue' },
        { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert, color: 'red' },
        { id: 'writeups', label: 'HTB & Community Writeups', icon: FileText, color: 'purple' }
    ];

    useEffect(() => {
        fetchIntel();
    }, [activeTab]);

    const fetchIntel = async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/intel/${activeTab}`);
            const data = await response.json();
            if (data.success) {
                setIntelData(data.items);
                setLastUpdated(data.last_updated);
            }
        } catch (error) {
            console.error('Failed to fetch intel:', error);
            showToast('Failed to sync with intelligence feeds', 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleRefresh = async () => {
        showToast('Syncing with global security feeds...', 'info');
        try {
            await fetch(`${API_BASE}/intel/refresh`, { method: 'POST' });
            await fetchIntel();
            showToast('Cyber Intel updated successfully', 'success');
        } catch (error) {
            showToast('Sync failed. Try again later.', 'error');
        }
    };

    const filteredData = intelData.filter(item =>
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.source.toLowerCase().includes(searchQuery.toLowerCase())
    );

    return (
        <div className="min-h-screen bg-dark-950 p-6 lg:p-10">
            {/* Header section */}
            <div className="max-w-7xl mx-auto space-y-12">
                <header className="flex flex-col lg:flex-row lg:items-end justify-between gap-8">
                    <div className="space-y-4">
                        <div className="flex items-center gap-3 text-pink-500 font-black tracking-widest uppercase text-sm">
                            <span className="relative flex h-3 w-3">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-pink-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-3 w-3 bg-pink-500"></span>
                            </span>
                            Live Intelligence Stream
                        </div>
                        <h1 className="text-5xl lg:text-7xl font-black text-white italic uppercase tracking-tighter leading-none">
                            Cyber <span className="text-outline-white text-transparent">Intel Hub</span>
                        </h1>
                        <p className="text-dark-300 max-w-2xl text-lg font-medium leading-relaxed">
                            Real-time synchronization with global security feeds, vulnerability databases,
                            and professional red team writeups.
                        </p>
                    </div>

                    <div className="flex items-center gap-4">
                        <button
                            onClick={handleRefresh}
                            className="bg-white/5 hover:bg-white/10 border border-white/10 px-6 py-4 rounded-2xl flex items-center gap-3 transition-all duration-300 group"
                        >
                            <RefreshCw className={`w-5 h-5 text-pink-500 ${loading ? 'animate-spin' : 'group-hover:rotate-180 transition-transform duration-500'}`} />
                            <span className="text-white font-bold uppercase tracking-wider text-xs">Sync Feeds</span>
                        </button>
                    </div>
                </header>

                {/* Main Content Area */}
                <div className="grid lg:grid-cols-12 gap-10">
                    {/* Navigation and Filters */}
                    <aside className="lg:col-span-3 space-y-8">
                        <div className="space-y-4">
                            <h3 className="text-xs font-black text-dark-400 uppercase tracking-[0.2em] px-2">Feed Categories</h3>
                            <nav className="space-y-2">
                                {tabs.map(tab => (
                                    <button
                                        key={tab.id}
                                        onClick={() => setActiveTab(tab.id)}
                                        className={`w-full flex items-center gap-4 px-6 py-4 rounded-2xl transition-all duration-300 group ${activeTab === tab.id
                                            ? 'bg-pink-500 text-white shadow-lg shadow-pink-500/20'
                                            : 'bg-dark-800/40 text-dark-300 hover:text-white border border-transparent hover:border-white/5'
                                            }`}
                                    >
                                        <tab.icon className={`w-5 h-5 ${activeTab === tab.id ? 'text-white' : 'text-pink-500/60 group-hover:text-pink-500'}`} />
                                        <span className="font-black uppercase tracking-tighter italic">{tab.label}</span>
                                    </button>
                                ))}
                            </nav>
                        </div>

                        <div className="p-8 rounded-[2rem] bg-gradient-to-br from-pink-500/10 to-transparent border border-pink-500/20 space-y-4">
                            <Zap className="w-8 h-8 text-pink-500" />
                            <h4 className="text-lg font-black text-white italic uppercase tracking-tighter">Pro Intelligence</h4>
                            <p className="text-dark-400 text-sm leading-relaxed">
                                Curated from HTB, TryHackMe, and top security researchers.
                            </p>
                        </div>
                    </aside>

                    {/* Feed Display */}
                    <main className="lg:col-span-9 space-y-8">
                        {/* Search Bar */}
                        <div className="relative group">
                            <Search className="absolute left-6 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400 group-focus-within:text-pink-500 transition-colors" />
                            <input
                                type="text"
                                placeholder="Filter intelligence stream..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full bg-dark-800/40 border border-white/5 rounded-2xl py-5 pl-16 pr-8 text-white focus:outline-none focus:ring-2 focus:ring-pink-500/50 transition-all placeholder:text-dark-500 uppercase font-bold text-sm"
                            />
                        </div>

                        {/* List of items */}
                        <div className="space-y-4">
                            <AnimatePresence mode='popLayout'>
                                {loading ? (
                                    <motion.div
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        exit={{ opacity: 0 }}
                                        className="flex flex-col items-center justify-center py-32 space-y-6"
                                    >
                                        <div className="relative h-20 w-20">
                                            <div className="absolute inset-0 border-4 border-pink-500/20 rounded-full"></div>
                                            <div className="absolute inset-0 border-4 border-t-pink-500 rounded-full animate-spin"></div>
                                        </div>
                                        <p className="text-pink-500 font-black uppercase tracking-widest text-sm animate-pulse">Decrypting Feed Stream...</p>
                                    </motion.div>
                                ) : filteredData.length > 0 ? (
                                    filteredData.map((item, idx) => (
                                        <motion.div
                                            key={item.id || idx}
                                            initial={{ opacity: 0, y: 20 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: idx * 0.05 }}
                                            className="group relative bg-dark-800/20 hover:bg-dark-800/40 border border-white/5 hover:border-pink-500/30 p-8 rounded-[2.5rem] transition-all duration-300"
                                        >
                                            <div className="flex flex-col md:flex-row gap-8">
                                                <div className="flex-1 space-y-4">
                                                    <div className="flex flex-wrap items-center gap-3">
                                                        <span className="bg-pink-500/10 text-pink-500 text-[10px] font-black uppercase tracking-[0.2em] px-3 py-1.5 rounded-full border border-pink-500/20">
                                                            {item.source}
                                                        </span>
                                                        <div className="flex items-center gap-2 text-dark-500 text-[10px] font-bold uppercase tracking-widest">
                                                            <Clock className="w-3 h-3 text-pink-500" />
                                                            {new Date(item.published).toLocaleDateString()}
                                                        </div>
                                                    </div>

                                                    <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter group-hover:text-pink-500 transition-colors leading-tight">
                                                        {item.title}
                                                    </h2>

                                                    <p className="text-dark-400 font-medium leading-relaxed line-clamp-2">
                                                        {item.summary.replace(/<[^>]*>?/gm, '')}
                                                    </p>
                                                </div>

                                                <div className="flex md:flex-col items-center justify-center gap-3">
                                                    <a
                                                        href={item.link}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="w-14 h-14 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-white hover:bg-pink-500 hover:border-pink-500 transition-all duration-300 group/btn"
                                                    >
                                                        <ArrowUpRight className="w-6 h-6 group-hover/btn:translate-x-0.5 group-hover/btn:-translate-y-0.5 transition-transform" />
                                                    </a>
                                                    <button className="w-14 h-14 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-dark-300 hover:text-pink-500 transition-all duration-300">
                                                        <Bookmark className="w-5 h-5" />
                                                    </button>
                                                </div>
                                            </div>
                                        </motion.div>
                                    ))
                                ) : (
                                    <div className="text-center py-32 bg-dark-800/20 border border-dashed border-white/5 rounded-[3rem] space-y-6">
                                        <Ghost className="w-16 h-16 text-dark-600 mx-auto" />
                                        <div className="space-y-2">
                                            <h3 className="text-xl font-black text-white italic uppercase tracking-tighter">Negative Results</h3>
                                            <p className="text-dark-500 font-medium">No intelligence items match your current filter parameters.</p>
                                        </div>
                                    </div>
                                )}
                            </AnimatePresence>
                        </div>
                    </main>
                </div>
            </div>
        </div>
    );
};

export default CyberIntel;
