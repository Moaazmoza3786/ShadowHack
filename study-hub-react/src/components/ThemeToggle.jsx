import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { motion } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';

const ThemeToggle = () => {
    const { theme, toggleTheme } = useTheme();

    return (
        <motion.button
            onClick={toggleTheme}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.95 }}
            className="relative p-3 rounded-2xl bg-white/10 border border-white/20 hover:bg-white/20 transition-all duration-300 flex items-center justify-center"
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
            <motion.div
                initial={false}
                animate={{ rotate: theme === 'dark' ? 0 : 180 }}
                transition={{ duration: 0.3 }}
            >
                {theme === 'dark' ? (
                    <Moon className="w-5 h-5 text-yellow-400" />
                ) : (
                    <Sun className="w-5 h-5 text-yellow-500" />
                )}
            </motion.div>

            {/* Animated background indicator */}
            <motion.div
                className="absolute inset-0 rounded-2xl bg-primary-500/20 -z-10"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: [0, 1, 0], scale: 1 }}
                transition={{ duration: 0.6 }}
            />
        </motion.button>
    );
};

export default ThemeToggle;
