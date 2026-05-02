import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, Search, ChevronDown, User, Shield, Terminal, Activity, Globe } from 'lucide-react';
import { navigationConfig } from '../data/navigation';
import { useAppContext } from '../context/AppContext';
import ThemeToggle from './ThemeToggle';

const Navbar = () => {
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [activeDropdown, setActiveDropdown] = useState(null);
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);
    const { language, toggleLanguage, setIsSearchOpen } = useAppContext();
    const location = useLocation();

    const t = (obj) => (language === 'ar' && obj.labelAr) ? obj.labelAr : obj.label;
    const tSubtitle = (item) => (language === 'ar' && item.subtitleAr) ? item.subtitleAr : item.subtitle;

    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    useEffect(() => {
        setMobileMenuOpen(false);
        setActiveDropdown(null);
    }, [location]);

    // Keep the mobile menu state sane across resizes, and prevent background scroll when open.
    useEffect(() => {
        const handleResize = () => {
            // Close the mobile drawer once we enter desktop breakpoint (xl and up).
            if (window.innerWidth >= 1280) {
                setMobileMenuOpen(false);
            }
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    useEffect(() => {
        if (!mobileMenuOpen) return;

        // Clear any hover-based menus and lock scroll while the drawer is open.
        setActiveDropdown(null);
        setIsProfileOpen(false);

        const prevOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        return () => {
            document.body.style.overflow = prevOverflow;
        };
    }, [mobileMenuOpen]);

    const isActivePath = (path) => location.pathname === path;

    return (
        <header className="fixed top-0 left-0 right-0 z-[100] px-4 sm:px-10 py-4">
            <nav className={`mx-auto max-w-7xl relative z-[110] transform-gpu transition-all duration-500 rounded-[2.5rem] border backdrop-blur-3xl overflow-visible ${
                scrolled 
                ? 'translate-y-0 bg-dark-950/80 border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)] py-2' 
                : 'translate-y-2 bg-white/5 border-white/5 py-4'
            }`}>
                <div className="px-4 sm:px-8 flex items-center justify-between gap-4 min-w-0">
                    {/* Brand Section */}
                    <Link to="/" className="flex items-center gap-3 sm:gap-4 group shrink-0" title="ShadowHack">
                        <div className="relative">
                            <div className="absolute inset-0 bg-primary-500 blur-lg opacity-20 group-hover:opacity-40 transition-opacity" />
                            <div className="w-11 h-11 rounded-2xl bg-dark-950 flex items-center justify-center relative z-10 shadow-lg group-hover:scale-110 transition-transform duration-500 border border-white/10 overflow-hidden">
                                <img src="/logo.png" alt="ShadowHack Pro" className="w-full h-full object-cover" />
                            </div>
                        </div>
                        <div className="hidden sm:block">
                            <h1 className="text-lg xl:text-xl font-black italic tracking-tighter leading-none flex items-center">
                                SHADOW<span className="text-primary-500 hover:text-accent-500 transition-colors">HACK</span> <span className="ml-2 text-[10px] bg-primary-500 text-dark-950 px-1.5 py-0.5 rounded font-black not-italic uppercase tracking-tighter">PRO</span>
                            </h1>
                            <div className="flex items-center gap-2 mt-1">
                                <div className="w-1.5 h-1.5 rounded-full bg-primary-500 animate-pulse shadow-[0_0_10px_rgba(var(--primary-rgb),0.5)]" />
                                <p className="text-[8px] text-white/40 font-black uppercase tracking-[0.3em]">Personal Security Workspace</p>
                            </div>
                        </div>
                    </Link>

                    {/* Desktop Navigation */}
                    <div className="hidden xl:flex items-center gap-1 bg-white/5 rounded-2xl p-1 border border-white/5 mx-2">
                        {navigationConfig.directLinks.map((link) => {
                            const Icon = link.icon;
                            const active = isActivePath(link.path);
                            return (
                                <Link
                                    key={link.id}
                                    to={link.path}
                                    className={`relative flex items-center gap-2 px-3 2xl:px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${
                                        active ? 'text-primary-500 bg-white/5' : 'text-white/50 hover:text-white hover:bg-white/5'
                                    }`}
                                >
                                    {active && (
                                        <motion.div 
                                            layoutId="nav-pill" 
                                            className="absolute inset-0 bg-primary-500/10 border border-primary-500/20 rounded-xl"
                                            transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
                                        />
                                    )}
                                    <Icon size={14} className="relative z-10" />
                                    <span className="relative z-10">{t(link)}</span>
                                </Link>
                            );
                        })}

                        <div className="w-px h-6 bg-white/10 mx-1" />

                        {Object.entries(navigationConfig.dropdowns).map(([key, dropdown], idx, array) => {
                            const Icon = dropdown.icon;
                            const active = activeDropdown === key;
                            const isLast = idx === array.length - 1;
                            
                            return (
                                <div
                                    key={key}
                                    className="relative flex items-center"
                                    onMouseEnter={() => setActiveDropdown(key)}
                                    onMouseLeave={() => setActiveDropdown(null)}
                                >
                                    <button className={`flex items-center gap-2 px-3 2xl:px-4 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${
                                        active ? 'text-primary-500 bg-white/5' : 'text-white/50 hover:text-white hover:bg-white/5'
                                    }`}>
                                        <Icon size={14} />
                                        <span>{t(dropdown)}</span>
                                        <ChevronDown size={10} className={`transition-transform duration-300 ${active ? 'rotate-180' : ''}`} />
                                    </button>

                                    {/* Mega Dropdown */}
                                    <AnimatePresence>
                                        {active && (
                                            <motion.div
                                                initial={{ opacity: 0, y: 15, scale: 0.95 }}
                                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                                exit={{ opacity: 0, y: 10, scale: 0.95 }}
                                                transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                                                className={`absolute top-full pt-4 z-[110] ${isLast ? 'right-0' : 'left-1/2 -translate-x-1/2'}`}
                                            >
                                                <div className="glass-card p-1 rounded-[3rem] border-white/10 shadow-[0_40px_100px_rgba(0,0,0,0.8)] min-w-[300px]" 
                                                    style={{ width: dropdown.layout === 'tabs' ? '850px' : dropdown.columns ? dropdown.columns.length * 280 + 'px' : '300px' }}>
                                                    {dropdown.layout === 'tabs' ? (
                                                        <TabbedDropdown dropdown={dropdown} t={t} tSubtitle={tSubtitle} language={language} />
                                                    ) : (
                                                        <div className="grid p-8 gap-8" style={{ gridTemplateColumns: `repeat(${dropdown.columns.length}, 1fr)` }}>
                                                            {dropdown.columns.map((column, colIdx) => (
                                                                <div key={colIdx} className="space-y-6">
                                                                    <div className="flex items-center gap-3 px-4">
                                                                        <div className="w-1 h-4 bg-primary-500 rounded-full" />
                                                                        <span className="text-[10px] font-black text-white/40 uppercase tracking-[0.3em]">
                                                                            {language === 'ar' ? column.titleAr : column.title}
                                                                        </span>
                                                                    </div>
                                                                    <div className="space-y-2">
                                                                        {column.items.map((item, itemIdx) => {
                                                                            const ItemIcon = item.icon;
                                                                            return (
                                                                                <Link
                                                                                    key={itemIdx}
                                                                                    to={item.path}
                                                                                    className="flex items-start gap-4 p-4 rounded-3xl hover:bg-white/5 border border-transparent hover:border-white/10 transition-all group"
                                                                                >
                                                                                    <div className="w-12 h-12 rounded-2xl bg-dark-950 flex items-center justify-center shrink-0 border border-white/5 group-hover:border-primary-500/30 transition-colors">
                                                                                        <ItemIcon size={18} className="text-primary-500" />
                                                                                    </div>
                                                                                    <div className="flex-1">
                                                                                        <h4 className="text-xs font-black text-white group-hover:text-primary-500 transition-colors uppercase italic leading-tight mb-1">{t(item)}</h4>
                                                                                        {item.subtitle && <p className="text-[10px] text-gray-500 line-clamp-1">{tSubtitle(item)}</p>}
                                                                                    </div>
                                                                                </Link>
                                                                            );
                                                                        })}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </div>
                            );
                        })}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 sm:gap-3 shrink-0">
                        <button 
                            onClick={() => setIsSearchOpen(true)}
                            className="w-10 h-10 flex items-center justify-center rounded-2xl bg-white/5 border border-white/5 hover:bg-white/10 transition-all text-white/60 hover:text-white"
                            title={language === 'ar' ? 'بحث سريع' : 'Quick Search'}
                        >
                            <Search size={18} />
                        </button>
                        
                        <div className="h-4 w-[1px] bg-white/10 mx-1" />

                        {/* Profile Dropdown */}
                        <div 
                            className="relative"
                            onMouseEnter={() => setIsProfileOpen(true)}
                            onMouseLeave={() => setIsProfileOpen(null)}
                        >
                            <button
                                className={`w-10 h-10 flex items-center justify-center rounded-2xl transition-all group ${
                                    isProfileOpen ? 'bg-primary-500/20 border-primary-500/40 text-primary-500' : 'bg-white/5 border-white/5 text-white/80 hover:bg-primary-500/10 hover:border-primary-500/20'
                                } border`}
                            >
                                <User size={18} className="group-hover:text-primary-500 transition-colors" />
                            </button>

                            <AnimatePresence>
                                {isProfileOpen && (
                                    <motion.div
                                        initial={{ opacity: 0, y: 10, scale: 0.95 }}
                                        animate={{ opacity: 1, y: 0, scale: 1 }}
                                        exit={{ opacity: 0, y: 10, scale: 0.95 }}
                                        transition={{ duration: 0.2 }}
                                        className="absolute top-full right-0 pt-4 z-[110]"
                                    >
                                        <div className="glass-card p-2 rounded-3xl border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)] min-w-[200px]">
                                            <div className="flex flex-col gap-1">
                                                <Link 
                                                    to="/profile"
                                                    className="flex items-center gap-3 p-3 rounded-2xl hover:bg-white/5 text-white/70 hover:text-primary-500 transition-all group"
                                                >
                                                    <div className="w-8 h-8 rounded-xl bg-primary-500/10 flex items-center justify-center text-primary-500">
                                                        <User size={14} />
                                                    </div>
                                                    <span className="text-[10px] font-black uppercase tracking-widest">{language === 'ar' ? 'الملف الشخصي' : 'Profile'}</span>
                                                </Link>

                                                <button
                                                    onClick={toggleLanguage}
                                                    className="flex items-center gap-3 p-3 rounded-2xl hover:bg-white/5 text-white/70 hover:text-primary-500 transition-all group w-full text-left"
                                                >
                                                    <div className="w-8 h-8 rounded-xl bg-accent-500/10 flex items-center justify-center text-accent-500">
                                                        <Globe size={14} />
                                                    </div>
                                                    <div className="flex flex-col">
                                                        <span className="text-[10px] font-black uppercase tracking-widest">{language === 'ar' ? 'اللغة' : 'Language'}</span>
                                                        <span className="text-[8px] text-white/30 uppercase">{language === 'ar' ? 'العربية' : 'English'}</span>
                                                    </div>
                                                </button>

                                                <div className="h-px bg-white/5 my-1 mx-2" />
                                                
                                                <div className="flex items-center justify-between p-3">
                                                    <span className="text-[9px] font-black text-white/20 uppercase tracking-widest">{language === 'ar' ? 'المظهر' : 'Theme'}</span>
                                                    <ThemeToggle />
                                                </div>
                                            </div>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>

                        <button
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                            className="xl:hidden w-10 h-10 flex items-center justify-center rounded-2xl bg-white/5 border border-white/5 text-white"
                        >
                            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
                        </button>
                    </div>
                </div>
            </nav>

            {/* Mobile Menu Backdrop */}
            <AnimatePresence>
                {mobileMenuOpen && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-dark-950/90 backdrop-blur-3xl z-[105] xl:hidden pr-6 pl-6 pt-32 pb-10 overflow-y-auto overscroll-contain"
                    >
                        <div className="max-w-md mx-auto space-y-8">
                            {/* Mobile Search */}
                            <div 
                                className="relative cursor-pointer"
                                onClick={() => {
                                    setIsSearchOpen(true);
                                    setMobileMenuOpen(false);
                                }}
                            >
                                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-white/40" size={18} />
                                <div className="w-full bg-white/5 border border-white/10 rounded-2xl py-4 pl-12 pr-4 text-xs font-black uppercase tracking-widest text-white/40">
                                    SEARCH OPERATIONS...
                                </div>
                            </div>

                            <div className="grid grid-cols-1 gap-4">
                                {navigationConfig.directLinks.map((link) => {
                                    const Icon = link.icon;
                                    return (
                                        <Link
                                            key={link.id}
                                            to={link.path}
                                            className="flex items-center gap-4 p-5 rounded-3xl bg-white/5 border border-white/5 hover:bg-white/10"
                                        >
                                            <div className="w-10 h-10 rounded-xl bg-primary-500/10 flex items-center justify-center text-primary-500">
                                                <Icon size={20} />
                                            </div>
                                            <span className="text-sm font-black uppercase tracking-widest italic">{t(link)}</span>
                                        </Link>
                                    );
                                })}
                            </div>

                            {/* Mobile Sections */}
                            {Object.entries(navigationConfig.dropdowns).map(([key, dropdown]) => (
                                <div key={key} className="space-y-4">
                                    <div className="flex items-center gap-3 px-4">
                                        <div className="w-1 h-4 bg-primary-500 rounded-full" />
                                        <span className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em]">{t(dropdown)}</span>
                                    </div>
                                    <div className="grid grid-cols-1 gap-2">
                                        {dropdown.layout === 'tabs' ? 
                                            dropdown.tabs.map(tab => (
                                                <div key={tab.id} className="space-y-2">
                                                    <div className="px-6 py-2">
                                                        <span className="text-[9px] font-black text-white/20 uppercase tracking-[0.2em]">{t(tab)}</span>
                                                    </div>
                                                    {tab.columns.map(col => col.items.map((item, i) => (
                                                        <MobileMenuItem key={i} item={item} t={t} tSubtitle={tSubtitle} />
                                                    )))}
                                                </div>
                                            )) :
                                            dropdown.columns.map(col => col.items.map((item, i) => (
                                                <MobileMenuItem key={i} item={item} t={t} tSubtitle={tSubtitle} />
                                            )))
                                        }
                                    </div>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </header>
    );
};

const MobileMenuItem = ({ item, t, tSubtitle }) => {
    const Icon = item.icon;
    return (
        <Link
            to={item.path}
            className="flex items-center gap-4 p-4 rounded-3xl bg-white/5 border border-white/5 hover:bg-white/10 transition-colors"
        >
            <div className="w-10 h-10 rounded-xl bg-dark-900 border border-white/10 flex items-center justify-center text-primary-500">
                <Icon size={18} />
            </div>
            <div className="flex-1">
                <div className="text-xs font-black uppercase italic text-white leading-tight">{t(item)}</div>
                {item.subtitle && <div className="text-[9px] text-gray-500 mt-1">{tSubtitle(item)}</div>}
            </div>
        </Link>
    );
};

const TabbedDropdown = ({ dropdown, t, tSubtitle, language }) => {
    const [activeTab, setActiveTab] = useState(dropdown.tabs[0].id);
    const activeTabData = dropdown.tabs.find(tab => tab.id === activeTab);

    return (
        <div className="flex h-[500px]">
            {/* Sidebar Tabs */}
            <div className="w-64 bg-dark-950/50 border-r border-white/5 p-6 flex flex-col gap-2">
                <div className="text-[9px] font-black text-white/20 uppercase tracking-[0.4em] mb-4 px-4">Categories</div>
                {dropdown.tabs.map((tab) => {
                    const TabIcon = tab.icon;
                    const active = activeTab === tab.id;
                    return (
                        <button
                            key={tab.id}
                            onMouseEnter={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-4 px-5 py-4 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${
                                active ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20' : 'text-white/40 hover:text-white hover:bg-white/5'
                            }`}
                        >
                            <TabIcon size={16} />
                            <span>{language === 'ar' ? tab.labelAr : tab.label}</span>
                        </button>
                    );
                })}
            </div>

            {/* Content Area */}
            <div className="flex-1 p-10 overflow-y-auto scrollbar-cyber">
                <AnimatePresence mode="wait">
                    <motion.div
                        key={activeTab}
                        initial={{ opacity: 0, x: 15 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        transition={{ duration: 0.3 }}
                    >
                        <div className="grid grid-cols-2 gap-10">
                            {activeTabData.columns.map((column, idx) => (
                                <div key={idx} className="space-y-6">
                                    <div className="flex items-center gap-3">
                                        <div className="w-1.5 h-1.5 bg-primary-500 rounded-full" />
                                        <p className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em]">
                                            {language === 'ar' ? column.titleAr : column.title}
                                        </p>
                                    </div>
                                    <div className="grid grid-cols-1 gap-2">
                                        {column.items.map((item, itemIdx) => {
                                            const ItemIcon = item.icon;
                                            return (
                                                <Link
                                                    key={itemIdx}
                                                    to={item.path}
                                                    className="flex items-start gap-5 p-4 rounded-3xl border border-transparent hover:bg-white/5 hover:border-white/10 transition-all group"
                                                >
                                                    <div className="w-12 h-12 rounded-2xl bg-dark-950 border border-white/5 flex items-center justify-center shrink-0 group-hover:border-primary-500/30 transition-colors">
                                                        <ItemIcon size={18} className="text-primary-500" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <h4 className="text-xs font-black text-white group-hover:text-primary-500 transition-colors uppercase italic leading-tight mb-1">{t(item)}</h4>
                                                        {item.subtitle && <p className="text-[10px] text-gray-500 line-clamp-2 leading-relaxed">{tSubtitle(item)}</p>}
                                                    </div>
                                                </Link>
                                            );
                                        })}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </AnimatePresence>
            </div>
        </div>
    );
};

export default Navbar;
