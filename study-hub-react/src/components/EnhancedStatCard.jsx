import React from 'react';
import { motion } from 'framer-motion';

const EnhancedStatCard = ({ label, value, icon: Icon, color, suffix = "", trend = null, description = "" }) => {
    // Parse color to get text and background variants
    const getColorClasses = (colorClass) => {
        const colorMap = {
            'bg-primary-500': { text: 'text-primary-500', light: 'bg-primary-500/10', border: 'border-primary-500/30' },
            'bg-green-500': { text: 'text-green-500', light: 'bg-green-500/10', border: 'border-green-500/30' },
            'bg-red-500': { text: 'text-red-500', light: 'bg-red-500/10', border: 'border-red-500/30' },
            'bg-yellow-500': { text: 'text-yellow-500', light: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
            'bg-accent-500': { text: 'text-accent-500', light: 'bg-accent-500/10', border: 'border-accent-500/30' },
        };
        return colorMap[colorClass] || colorMap['bg-primary-500'];
    };

    const colors = getColorClasses(color);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            whileHover={{ y: -10, borderColor: colors.border }}
            className={`relative group overflow-hidden ${colors.light} border border-white/5 rounded-3xl p-8 hover:border-white/10 transition-all duration-500 cursor-pointer`}
        >
            {/* Animated Gradient Background */}
            <motion.div
                className={`absolute top-0 right-0 w-40 h-40 opacity-20 group-hover:opacity-30 blur-3xl rounded-full transition-opacity duration-500 ${color}`}
                animate={{
                    scale: [1, 1.2, 1],
                }}
                transition={{ duration: 4, repeat: Infinity }}
            />

            {/* Content */}
            <div className="relative z-10">
                {/* Header with Icon */}
                <div className="flex items-start justify-between mb-6">
                    <div className="flex-1">
                        <p className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] mb-3">
                            {label}
                        </p>
                        <div className="flex items-baseline gap-3">
                            <motion.p
                                initial={{ opacity: 0, scale: 0.5 }}
                                animate={{ opacity: 1, scale: 1 }}
                                transition={{ duration: 0.6 }}
                                className={`text-4xl font-black text-white italic tracking-tighter uppercase ${colors.text}`}
                            >
                                {value}
                            </motion.p>
                            {suffix && (
                                <span className="text-xs font-bold text-gray-500 uppercase">{suffix}</span>
                            )}
                        </div>
                    </div>

                    {/* Icon Box */}
                    <motion.div
                        whileHover={{ scale: 1.15, rotate: 10 }}
                        className={`w-14 h-14 rounded-2xl flex items-center justify-center border border-white/10 backdrop-blur-xl ${colors.light} group-hover:border-white/30 transition-all`}
                    >
                        <Icon className={`w-7 h-7 ${colors.text}`} />
                    </motion.div>
                </div>

                {/* Trend Indicator */}
                {trend && (
                    <div className={`text-xs font-bold uppercase tracking-widest mb-3 ${trend.isPositive ? 'text-green-400' : 'text-red-400'}`}>
                        {trend.isPositive ? '↑' : '↓'} {trend.percentage}% from last week
                    </div>
                )}

                {/* Description */}
                {description && (
                    <p className="text-xs text-gray-400 mb-4">{description}</p>
                )}

                {/* Progress Bar */}
                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                    <motion.div
                        initial={{ width: '0%' }}
                        animate={{ width: '65%' }}
                        transition={{ duration: 1.5, ease: 'easeOut' }}
                        className={`h-full ${color} rounded-full`}
                    />
                </div>
            </div>

            {/* Hover Glow Effect */}
            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none">
                <div className={`absolute inset-0 ${color}/5 blur-xl`} />
            </div>
        </motion.div>
    );
};

export default EnhancedStatCard;
