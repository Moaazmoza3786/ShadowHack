import React from 'react';
import { useAppContext } from '../context/AppContext';
import Navbar from './Navbar';
import Footer from './Footer';
import GlobalSearch from './GlobalSearch';
import { Outlet } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

const MainLayout = () => {
    const { language } = useAppContext();

    return (
        <div className="min-h-screen bg-dark-950 text-gray-100 flex flex-col font-sans selection:bg-primary-500/30 selection:text-primary-500" dir={language === 'ar' ? 'rtl' : 'ltr'}>
            <div className="noise fixed inset-0 z-50 pointer-events-none opacity-20" />
            <div className="scanlines fixed inset-0 z-50 pointer-events-none opacity-20" />
            <div className="crt-overlay fixed inset-0 z-50 pointer-events-none opacity-20" />
            
            {/* Global Background Glows */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none -z-10">
                <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-primary-500/5 blur-[120px] rounded-full" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-accent-500/5 blur-[120px] rounded-full" />
            </div>

            <Navbar />
            <GlobalSearch />

            <main className="flex-1 pt-20 relative overflow-x-hidden">
                <div className="absolute inset-0 bg-cyber-grid pointer-events-none opacity-20 mask-fade-bottom" />
                
                <div className="relative z-10 max-w-[1800px] mx-auto px-4 sm:px-6 lg:px-12">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={window.location.pathname}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            transition={{ 
                                duration: 0.3, 
                                ease: [0.16, 1, 0.3, 1]
                            }}
                        >
                            <Outlet />
                        </motion.div>
                    </AnimatePresence>
                </div>
            </main>

            <Footer />
        </div>
    );
};

export default MainLayout;
