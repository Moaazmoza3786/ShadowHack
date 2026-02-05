import React from 'react';
import { useAppContext } from '../context/AppContext';
import Navbar from './Navbar';
import { motion, AnimatePresence } from 'framer-motion';

const MainLayout = ({ children }) => {
    const { language } = useAppContext();

    return (
        <div className="min-h-screen bg-dark-900 text-gray-100" dir={language === 'ar' ? 'rtl' : 'ltr'}>
            <div className="noise" />
            <div className="scanlines" />
            <div className="crt-overlay" />
            <Navbar />

            <main className="pt-16 min-h-screen overflow-y-auto scrollbar-cyber relative bg-dark-900/50">
                <div className="absolute inset-0 bg-cyber-grid pointer-events-none opacity-40" />
                <div className="relative z-10 max-w-[1600px] mx-auto p-8 lg:p-12">
                    <AnimatePresence mode="wait">
                        <motion.div
                            key={window.location.pathname}
                            initial={{ opacity: 0, scale: 0.99, y: 10 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 1.01, y: -10 }}
                            transition={{ duration: 0.4, ease: [0.23, 1, 0.32, 1] }}
                        >
                            {children}
                        </motion.div>
                    </AnimatePresence>
                </div>
            </main>
        </div>
    );
};

export default MainLayout;
