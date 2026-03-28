import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Zap, Lock } from 'lucide-react';

const HeroSection = ({ userName = "Operative" }) => {
    const [text, setText] = useState('');
    const fullText = 'LEARN. PRACTICE. DOMINATE.';

    useEffect(() => {
        let index = 0;
        const timer = setInterval(() => {
            if (index < fullText.length) {
                setText(fullText.slice(0, index + 1));
                index++;
            } else {
                clearInterval(timer);
            }
        }, 100);
        return () => clearInterval(timer);
    }, []);

    return (
        <section className="relative overflow-hidden py-20 px-6">
            {/* Animated Background Elements */}
            <div className="absolute inset-0 -z-10">
                {/* Gradient Orbs */}
                <motion.div
                    className="absolute top-0 left-0 w-96 h-96 bg-primary-500/20 rounded-full blur-3xl"
                    animate={{
                        x: [0, 30, 0],
                        y: [0, 30, 0],
                    }}
                    transition={{ duration: 8, repeat: Infinity }}
                />
                <motion.div
                    className="absolute bottom-0 right-0 w-96 h-96 bg-accent-500/20 rounded-full blur-3xl"
                    animate={{
                        x: [0, -30, 0],
                        y: [0, -30, 0],
                    }}
                    transition={{ duration: 8, repeat: Infinity, delay: 0.5 }}
                />
                {/* Grid Pattern */}
                <div
                    className="absolute inset-0 opacity-10"
                    style={{
                        backgroundImage:
                            'linear-gradient(0deg, transparent 24%, rgba(51, 171, 255, 0.1) 25%, rgba(51, 171, 255, 0.1) 26%, transparent 27%, transparent 74%, rgba(51, 171, 255, 0.1) 75%, rgba(51, 171, 255, 0.1) 76%, transparent 77%, transparent), linear-gradient(90deg, transparent 24%, rgba(51, 171, 255, 0.1) 25%, rgba(51, 171, 255, 0.1) 26%, transparent 27%, transparent 74%, rgba(51, 171, 255, 0.1) 75%, rgba(51, 171, 255, 0.1) 76%, transparent 77%, transparent)',
                        backgroundSize: '50px 50px',
                    }}
                />
            </div>

            <div className="relative z-10 max-w-6xl mx-auto text-center">
                {/* Status Badge */}
                <motion.div
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6 }}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/30 mb-8"
                >
                    <div className="w-2 h-2 rounded-full bg-primary-500 animate-pulse" />
                    <span className="text-sm font-bold text-primary-500 uppercase tracking-widest">
                        System Online • Global Servers Active
                    </span>
                </motion.div>

                {/* Main Heading with Typing Effect */}
                <motion.h1
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.8 }}
                    className="text-6xl md:text-7xl font-black text-white mb-6 italic tracking-tighter uppercase"
                >
                    {text}
                    <motion.span
                        animate={{ opacity: [1, 0] }}
                        transition={{ duration: 0.8, repeat: Infinity }}
                        className="text-primary-500"
                    >
                        |
                    </motion.span>
                </motion.h1>

                {/* Subheading */}
                <motion.p
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.2 }}
                    className="text-xl md:text-2xl text-gray-300 mb-12 max-w-2xl mx-auto font-medium"
                >
                    The most advanced cybersecurity education platform for aspiring ethical hackers
                </motion.p>

                {/* Feature Pills */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.4 }}
                    className="flex flex-wrap justify-center gap-4 mb-12"
                >
                    {[
                        { icon: Shield, label: '40+ Security Tools' },
                        { icon: Zap, label: 'Real-Time Labs' },
                        { icon: Lock, label: 'Expert Guidance' },
                    ].map((feature, idx) => {
                        const Icon = feature.icon;
                        return (
                            <motion.div
                                key={idx}
                                whileHover={{ scale: 1.05 }}
                                className="px-6 py-3 rounded-full bg-white/5 border border-white/10 flex items-center gap-3 group hover:border-primary-500/50 transition-all"
                            >
                                <Icon className="w-5 h-5 text-primary-500 group-hover:scale-110 transition-transform" />
                                <span className="text-sm font-bold text-white uppercase tracking-widest">
                                    {feature.label}
                                </span>
                            </motion.div>
                        );
                    })}
                </motion.div>

                {/* Call-to-Action Buttons */}
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.6, delay: 0.6 }}
                    className="flex flex-col sm:flex-row gap-6 justify-center"
                >
                    <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        className="px-10 py-4 bg-primary-500 text-dark-900 rounded-2xl font-black uppercase italic tracking-tighter shadow-xl shadow-primary-500/30 hover:shadow-primary-500/50 transition-all"
                    >
                        Start Your Journey
                    </motion.button>
                    <motion.button
                        whileHover={{ scale: 1.05, borderColor: 'rgba(51, 171, 255, 0.5)' }}
                        whileTap={{ scale: 0.95 }}
                        className="px-10 py-4 bg-transparent border-2 border-white/20 text-white rounded-2xl font-black uppercase italic tracking-tighter hover:bg-white/5 transition-all"
                    >
                        View Courses
                    </motion.button>
                </motion.div>

                {/* User Stats Badges */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.8 }}
                    className="mt-16 grid grid-cols-3 gap-6 max-w-md mx-auto"
                >
                    {[
                        { label: '10K+', value: 'Active Users' },
                        { label: '100+', value: 'Challenges' },
                        { label: '50+', value: 'Expert Labs' },
                    ].map((stat, idx) => (
                        <div
                            key={idx}
                            className="p-4 rounded-xl bg-white/5 border border-white/10 text-center hover:border-primary-500/50 transition-all"
                        >
                            <div className="text-2xl font-black text-primary-500 mb-1">{stat.label}</div>
                            <div className="text-xs font-bold text-gray-400 uppercase tracking-widest">{stat.value}</div>
                        </div>
                    ))}
                </motion.div>
            </div>
        </section>
    );
};

export default HeroSection;
