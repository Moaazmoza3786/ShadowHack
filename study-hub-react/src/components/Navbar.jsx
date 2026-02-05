import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, Search, ChevronDown, User } from 'lucide-react';
import { navigationConfig } from '../data/navigation';
import { useAppContext } from '../context/AppContext';

const Navbar = () => {
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
    const [activeDropdown, setActiveDropdown] = useState(null);
    const { language, toggleLanguage } = useAppContext();

    const location = useLocation();

    const t = (obj) => (language === 'ar' && obj.labelAr) ? obj.labelAr : obj.label;
    const tSubtitle = (item) => (language === 'ar' && item.subtitleAr) ? item.subtitleAr : item.subtitle;

    // Close mobile menu on route change
    useEffect(() => {
        setMobileMenuOpen(false);
        setActiveDropdown(null);
    }, [location]);

    // Close dropdowns when clicking outside
    useEffect(() => {
        const handleClick = () => setActiveDropdown(null);
        if (activeDropdown) {
            document.addEventListener('click', handleClick);
            return () => document.removeEventListener('click', handleClick);
        }
    }, [activeDropdown]);

    const isActivePath = (path) => location.pathname === path;

    return (
        <>
            {/* Main Navbar */}
            <nav className="fixed top-0 left-0 right-0 z-50 bg-dark-900 border-b border-white/5 backdrop-blur-xl">
                <div className="mx-auto px-6">
                    <div className="flex items-center justify-between h-16">
                        {/* Logo & Brand */}
                        <Link to="/" className="flex items-center gap-3 group">
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center neon-glow-primary">
                                <svg viewBox="0 0 100 100" className="w-6 h-6" fill="none">
                                    <path d="M50 5 L90 20 L90 50 Q90 80 50 95 Q10 80 10 50 L10 20 Z" fill="rgba(0,0,0,0.3)" stroke="currentColor" strokeWidth="6" />
                                    <rect x="42" y="45" width="16" height="12" rx="2" fill="currentColor" />
                                    <path d="M45 45 V40 Q45 35 50 35 Q55 35 55 40 V45" stroke="currentColor" strokeWidth="4" fill="none" />
                                </svg>
                            </div>
                            <div>
                                <h1 className="text-xl font-black italic tracking-tighter leading-none">
                                    STUDY<span className="text-primary-500">HUB</span>
                                </h1>
                                <div className="flex items-center gap-2">
                                    <p className="text-[8px] text-primary-500/60 font-mono uppercase tracking-[0.2em]">Offensive v3.0</p>
                                    <span className="text-[8px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-500 border border-amber-500/30 font-bold">v7.9.8-TUNNEL-SYNC</span>
                                </div>
                            </div>
                        </Link>

                        {/* Desktop Navigation */}
                        <div className="hidden lg:flex items-center gap-2">
                            {/* Direct Links */}
                            {navigationConfig.directLinks.map((link) => {
                                const Icon = link.icon;
                                return (
                                    <Link
                                        key={link.id}
                                        to={link.path}
                                        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold uppercase tracking-wide transition-all ${isActivePath(link.path)
                                            ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20'
                                            : 'text-gray-400 hover:bg-white/5 hover:text-gray-100'
                                            }`}
                                    >
                                        <Icon size={16} />
                                        <span>{t(link)}</span>
                                        {link.badge && (
                                            <span className="px-1.5 py-0.5 rounded bg-accent-500/20 text-accent-500 text-[8px] font-bold border border-accent-500/20">
                                                {link.badge}
                                            </span>
                                        )}
                                    </Link>
                                );
                            })}

                            {/* Dropdown Menus */}
                            {Object.entries(navigationConfig.dropdowns).map(([key, dropdown]) => {
                                const Icon = dropdown.icon;
                                return (
                                    <div
                                        key={key}
                                        className="relative"
                                        onMouseEnter={() => setActiveDropdown(key)}
                                        onMouseLeave={() => setActiveDropdown(null)}
                                    >
                                        {dropdown.path ? (
                                            <Link
                                                to={dropdown.path}
                                                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold uppercase tracking-wide text-gray-400 hover:bg-white/5 hover:text-gray-100 transition-all"
                                            >
                                                <Icon size={16} />
                                                <span>{language === 'ar' ? dropdown.labelAr : dropdown.label}</span>
                                                <ChevronDown size={12} className={`transition-transform ${activeDropdown === key ? 'rotate-180' : ''}`} />
                                            </Link>
                                        ) : (
                                            <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold uppercase tracking-wide text-gray-400 hover:bg-white/5 hover:text-gray-100 transition-all">
                                                <Icon size={16} />
                                                <span>{language === 'ar' ? dropdown.labelAr : dropdown.label}</span>
                                                <ChevronDown size={12} className={`transition-transform ${activeDropdown === key ? 'rotate-180' : ''}`} />
                                            </button>
                                        )}

                                        {/* Dropdown Content */}
                                        <AnimatePresence>
                                            {activeDropdown === key && (
                                                <motion.div
                                                    initial={{ opacity: 0, y: 10 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    exit={{ opacity: 0, y: 10 }}
                                                    transition={{ duration: 0.2 }}
                                                    className={`absolute top-full left-0 mt-2 bg-dark-800 border border-white/10 rounded-2xl shadow-2xl overflow-hidden z-[60] ${dropdown.layout === 'tabs' ? 'w-[800px]' : ''
                                                        }`}
                                                    style={{ width: dropdown.layout === 'tabs' ? '800px' : dropdown.columns ? dropdown.columns.length * 280 + 'px' : '280px' }}
                                                >
                                                    {dropdown.layout === 'tabs' ? (
                                                        <TabbedDropdown dropdown={dropdown} t={t} tSubtitle={tSubtitle} language={language} />
                                                    ) : (
                                                        <div className={`grid gap-4 p-6`} style={{ gridTemplateColumns: `repeat(${dropdown.columns.length}, 1fr)` }}>
                                                            {dropdown.columns.map((column, idx) => (
                                                                <div key={idx} className="space-y-3">
                                                                    <p className="text-[10px] font-bold text-primary-500 uppercase tracking-widest mb-4">
                                                                        {language === 'ar' ? column.titleAr : column.title}
                                                                    </p>
                                                                    {column.items.map((item, itemIdx) => {
                                                                        const ItemIcon = item.icon;
                                                                        return (
                                                                            <Link
                                                                                key={itemIdx}
                                                                                to={item.path}
                                                                                className="flex items-start gap-3 p-3 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 hover:border-primary-500/20 transition-all group"
                                                                            >
                                                                                <div className="w-10 h-10 rounded-lg bg-dark-900 border border-white/10 flex items-center justify-center shrink-0 group-hover:border-primary-500/30 transition-colors">
                                                                                    <ItemIcon size={18} className="text-primary-500" />
                                                                                </div>
                                                                                <div className="flex-1 min-w-0">
                                                                                    <div className="flex items-center gap-2">
                                                                                        <h4 className="text-sm font-bold text-white group-hover:text-primary-500 transition-colors">
                                                                                            {t(item)}
                                                                                        </h4>
                                                                                        {item.badge && (
                                                                                            <span className="px-1.5 py-0.5 rounded bg-accent-500/20 text-accent-500 text-[8px] font-bold border border-accent-500/20">
                                                                                                {item.badge}
                                                                                            </span>
                                                                                        )}
                                                                                    </div>
                                                                                    {item.subtitle && (
                                                                                        <p className="text-[10px] text-gray-500 mt-1 line-clamp-1">{tSubtitle(item)}</p>
                                                                                    )}
                                                                                </div>
                                                                            </Link>
                                                                        );
                                                                    })}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </motion.div>
                                            )}
                                        </AnimatePresence>
                                    </div>
                                );
                            })}
                        </div>

                        {/* Right Side */}
                        <div className="flex items-center gap-3">
                            <button className="hidden lg:flex w-9 h-9 items-center justify-center rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
                                <Search size={16} className="text-gray-400" />
                            </button>

                            {/* Language Toggle */}
                            <button
                                onClick={toggleLanguage}
                                className="hidden lg:flex px-3 h-9 items-center gap-2 rounded-lg bg-primary-500/10 border border-primary-500/20 text-primary-500 hover:bg-primary-500/20 transition-all group"
                                title={language === 'ar' ? 'English' : 'العربية'}
                            >
                                <span className="text-[10px] font-black uppercase tracking-widest">
                                    {language === 'ar' ? 'EN' : 'AR'}
                                </span>
                                <div className="w-[1px] h-3 bg-primary-500/30" />
                                <span className={`text-[10px] font-bold ${language === 'ar' ? 'font-sans' : 'font-arabic'}`}>
                                    {language === 'ar' ? 'English' : 'العربية'}
                                </span>
                            </button>

                            {/* Right Items */}
                            <div className="hidden lg:flex items-center gap-2">
                                {navigationConfig.rightItems.map((item) => {
                                    const Icon = item.icon;
                                    return (
                                        <Link
                                            key={item.id}
                                            to={item.path}
                                            className={`flex items-center justify-center w-9 h-9 rounded-lg transition-all ${isActivePath(item.path)
                                                ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20'
                                                : 'text-gray-400 hover:bg-white/5 hover:text-gray-100'
                                                }`}
                                            title={t(item)}
                                        >
                                            <Icon size={18} />
                                        </Link>
                                    );
                                })}
                            </div>

                            {/* User Profile Icon */}
                            <button className="hidden lg:flex w-9 h-9 items-center justify-center rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
                                <User size={18} className="text-gray-400" />
                            </button>

                            {/* Mobile Menu Toggle */}
                            <button
                                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                                className="lg:hidden w-9 h-9 flex items-center justify-center rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
                            >
                                {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Mobile Menu */}
            <AnimatePresence>
                {mobileMenuOpen && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="fixed top-16 left-0 right-0 z-40 bg-dark-900 border-b border-white/5 lg:hidden overflow-hidden"
                    >
                        <div className="max-h-[calc(100vh-4rem)] overflow-y-auto scrollbar-cyber p-6 space-y-4">
                            {/* Mobile Language Toggle */}
                            <button
                                onClick={toggleLanguage}
                                className="flex w-full items-center justify-between p-4 rounded-xl bg-primary-500/10 border border-primary-500/20 text-primary-500 mb-4"
                            >
                                <div className="flex items-center gap-3">
                                    <div className="w-8 h-8 rounded-lg bg-primary-500/20 flex items-center justify-center font-black text-[10px]">
                                        {language === 'ar' ? 'EN' : 'AR'}
                                    </div>
                                    <span className="font-bold text-sm uppercase tracking-wider">
                                        {language === 'ar' ? 'Switch to English' : 'تغيير للغة العربية'}
                                    </span>
                                </div>
                                <span className={`text-xs ${language === 'ar' ? 'font-sans' : 'font-arabic'}`}>
                                    {language === 'ar' ? 'English' : 'العربية'}
                                </span>
                            </button>
                            {/* Direct Links */}
                            {navigationConfig.directLinks.map((link) => {
                                const Icon = link.icon;
                                return (
                                    <Link
                                        key={link.id}
                                        to={link.path}
                                        className="flex items-center gap-3 p-3 rounded-xl bg-white/5 hover:bg-white/10 transition-colors"
                                    >
                                        <Icon size={20} className="text-primary-500" />
                                        <span className="font-semibold">{t(link)}</span>
                                        {link.badge && (
                                            <span className="ml-auto px-2 py-1 rounded bg-accent-500/20 text-accent-500 text-[10px] font-bold">
                                                {link.badge}
                                            </span>
                                        )}
                                    </Link>
                                );
                            })}

                            {/* Dropdowns as Sections */}
                            {Object.entries(navigationConfig.dropdowns).map(([key, dropdown]) => (
                                <div key={key} className="space-y-2">
                                    <p className="text-[10px] font-bold text-primary-500/60 uppercase tracking-widest pl-3 mb-2">
                                        {language === 'ar' ? dropdown.labelAr : dropdown.label}
                                    </p>

                                    {/* Handle Tabbed Layout for Mobile */}
                                    {dropdown.layout === 'tabs' ? (
                                        dropdown.tabs.map((tab, tabIdx) => (
                                            <div key={tabIdx} className="space-y-2">
                                                <p className="text-[8px] font-bold text-gray-600 uppercase tracking-[0.2em] pl-4 mt-4 mb-2 border-l border-white/5 ml-1">
                                                    {language === 'ar' ? tab.labelAr : tab.label}
                                                </p>
                                                {tab.columns.map((column, colIdx) =>
                                                    column.items.map((item, itemIdx) => (
                                                        <MobileMenuItem key={`${tabIdx}-${colIdx}-${itemIdx}`} item={item} t={t} tSubtitle={tSubtitle} />
                                                    ))
                                                )}
                                            </div>
                                        ))
                                    ) : (
                                        /* Handle Standard Column Layout for Mobile */
                                        dropdown.columns.map((column, colIdx) => (
                                            <div key={colIdx} className="space-y-2">
                                                {dropdown.columns.length > 1 && (
                                                    <p className="text-[8px] font-bold text-gray-600 uppercase tracking-[0.2em] pl-4 mt-2 mb-2 border-l border-white/5 ml-1">
                                                        {language === 'ar' ? column.titleAr : column.title}
                                                    </p>
                                                )}
                                                {column.items.map((item, itemIdx) => (
                                                    <MobileMenuItem key={`${colIdx}-${itemIdx}`} item={item} t={t} tSubtitle={tSubtitle} />
                                                ))}
                                            </div>
                                        ))
                                    )}
                                </div>
                            ))}

                            {/* Right Items */}
                            <div className="pt-4 border-t border-white/5 space-y-2">
                                {navigationConfig.rightItems.map((item) => {
                                    const Icon = item.icon;
                                    return (
                                        <Link
                                            key={item.id}
                                            to={item.path}
                                            className="flex items-center gap-3 p-3 rounded-xl bg-white/5 hover:bg-white/10 transition-colors"
                                        >
                                            <Icon size={20} className="text-primary-500" />
                                            <span className="font-semibold">{t(item)}</span>
                                        </Link>
                                    );
                                })}
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </>
    );
};

const MobileMenuItem = ({ item, t, tSubtitle }) => {
    const Icon = item.icon;
    return (
        <Link
            to={item.path}
            className="flex items-center gap-3 p-3 rounded-xl bg-white/5 hover:bg-white/10 transition-colors"
        >
            <Icon size={18} className="text-primary-500" />
            <div className="flex-1">
                <div className="font-semibold text-sm">{t(item)}</div>
                {item.subtitle && (
                    <div className="text-[10px] text-gray-500">{tSubtitle(item)}</div>
                )}
            </div>
            {item.badge && (
                <span className="px-2 py-1 rounded bg-accent-500/20 text-accent-500 text-[10px] font-bold">
                    {item.badge}
                </span>
            )}
        </Link>
    );
};

const TabbedDropdown = ({ dropdown, t, tSubtitle, language }) => {
    const [activeTab, setActiveTab] = useState(dropdown.tabs[0].id);
    const activeTabData = dropdown.tabs.find(tab => tab.id === activeTab);

    return (
        <div className="flex h-[400px]">
            {/* Sidebar Tabs */}
            <div className="w-56 bg-dark-900/50 border-r border-white/5 p-4 flex flex-col gap-1">
                {dropdown.tabs.map((tab) => {
                    const TabIcon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onMouseEnter={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all ${activeTab === tab.id
                                ? 'bg-primary-500/10 text-primary-500 border border-primary-500/20'
                                : 'text-gray-400 hover:bg-white/5 hover:text-gray-300'
                                }`}
                        >
                            <TabIcon size={18} />
                            <span>{language === 'ar' ? tab.labelAr : tab.label}</span>
                        </button>
                    );
                })}
            </div>

            {/* Content Area */}
            <div className="flex-1 p-8 overflow-y-auto scrollbar-cyber">
                <AnimatePresence mode="wait">
                    <motion.div
                        key={activeTab}
                        initial={{ opacity: 0, x: 10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        transition={{ duration: 0.2 }}
                        className="grid grid-cols-2 gap-8"
                    >
                        {activeTabData.columns.map((column, idx) => (
                            <div key={idx} className="space-y-4">
                                <p className="text-[10px] font-bold text-primary-500 uppercase tracking-widest border-b border-primary-500/10 pb-2 mb-4">
                                    {language === 'ar' ? column.titleAr : column.title}
                                </p>
                                <div className="space-y-2">
                                    {column.items.map((item, itemIdx) => {
                                        const ItemIcon = item.icon;
                                        return (
                                            <Link
                                                key={itemIdx}
                                                to={item.path}
                                                className="flex items-start gap-4 p-3 rounded-xl border border-transparent hover:bg-white/5 hover:border-white/10 transition-all group"
                                            >
                                                <div className="w-8 h-8 rounded-lg bg-dark-900 border border-white/10 flex items-center justify-center shrink-0 group-hover:border-primary-500/30 transition-colors">
                                                    <ItemIcon size={16} className="text-primary-500" />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <h4 className="text-sm font-bold text-white group-hover:text-primary-500 transition-colors">
                                                            {t(item)}
                                                        </h4>
                                                        {item.badge && (
                                                            <span className="px-1.5 py-0.5 rounded bg-accent-500/20 text-accent-500 text-[8px] font-bold border border-accent-500/20">
                                                                {item.badge}
                                                            </span>
                                                        )}
                                                    </div>
                                                    {item.subtitle && (
                                                        <p className="text-[10px] text-gray-500 mt-1 line-clamp-2 leading-relaxed italic opacity-60">
                                                            {tSubtitle(item)}
                                                        </p>
                                                    )}
                                                </div>
                                            </Link>
                                        );
                                    })}
                                </div>
                            </div>
                        ))}
                    </motion.div>
                </AnimatePresence>
            </div>
        </div>
    );
};

export default Navbar;
