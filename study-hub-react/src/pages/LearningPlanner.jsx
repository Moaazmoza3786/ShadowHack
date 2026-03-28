import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Brain, Zap, Target, Clock, CheckCircle, AlertCircle } from 'lucide-react';
import notificationService from '../services/notificationService';

/**
 * AI-Powered Learning Plans
 * Generates adaptive, personalized curricula using Groq AI
 */

const LearningPlanner = ({ userId = null }) => {
    const [learningPlan, setLearningPlan] = useState(null);
    const [loading, setLoading] = useState(false);
    const [selectedDifficulty, setSelectedDifficulty] = useState('intermediate');
    const [selectedDomain, setSelectedDomain] = useState('web-security');
    const [generatingPlan, setGeneratingPlan] = useState(false);

    const domains = [
        { id: 'web-security', name: 'Web Security', icon: '🌐', color: 'from-blue-500 to-cyan-500' },
        { id: 'networks', name: 'Networking', icon: '🔗', color: 'from-purple-500 to-pink-500' },
        { id: 'crypto', name: 'Cryptography', icon: '🔐', color: 'from-green-500 to-emerald-500' },
        { id: 'forensics', name: 'Forensics', icon: '🔬', color: 'from-orange-500 to-red-500' },
        { id: 'osint', name: 'OSINT', icon: '🔍', color: 'from-indigo-500 to-blue-500' },
        { id: 'exploit', name: 'Exploitation', icon: '💣', color: 'from-red-500 to-pink-500' },
    ];

    const difficulties = ['beginner', 'intermediate', 'advanced', 'expert'];

    /**
     * Generate AI-powered learning plan using Groq
     */
    const generatePlan = async () => {
        setGeneratingPlan(true);
        try {
            const response = await fetch('/api/ai/learning-plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: userId,
                    domain: selectedDomain,
                    difficulty: selectedDifficulty,
                    duration_weeks: 8,
                    learning_style: 'mixed', // Can be: visual, practical, reading
                }),
            });

            const data = await response.json();
            if (data.success) {
                setLearningPlan(data.plan);
                notificationService.notify(
                    'learning_plan',
                    '🧠 Learning Plan Generated',
                    `Your personalized ${selectedDifficulty} ${selectedDomain} plan is ready!`
                );
            }
        } catch (error) {
            console.error('Error generating plan:', error);
            notificationService.notify(
                'error',
                '❌ Error',
                'Failed to generate learning plan. Please try again.'
            );
        } finally {
            setGeneratingPlan(false);
        }
    };

    /**
     * Start a week of the learning plan
     */
    const startWeek = async (weekNumber) => {
        // Save progress and update learning plan
        try {
            await fetch(`/api/learning-plans/${learningPlan?.id}/week/${weekNumber}`, {
                method: 'POST',
            });
            notificationService.notify(
                'learning_progress',
                '📚 Week Started',
                `You've started Week ${weekNumber}. Let's learn!`
            );
        } catch (error) {
            console.error('Error starting week:', error);
        }
    };

    if (generatingPlan) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-dark-900">
                <motion.div
                    animate={{ scale: [1, 1.1, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="text-center"
                >
                    <Brain className="w-24 h-24 text-primary-500 mx-auto mb-4" />
                    <p className="text-xl font-black text-white uppercase tracking-widest">
                        AI is Generating Your Plan...
                    </p>
                    <p className="text-gray-400 mt-2">This may take a moment</p>
                </motion.div>
            </div>
        );
    }

    return (
        <div className="space-y-12 pb-12">
            {/* Header */}
            <div className="space-y-4">
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/20">
                    <Brain className="w-4 h-4 text-primary-500" />
                    <span className="text-sm font-bold text-primary-500 uppercase tracking-widest">
                        AI-Powered Learning
                    </span>
                </div>
                <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
                    Adaptive Learning Plans
                </h1>
                <p className="text-gray-400 text-lg max-w-2xl">
                    Let AI generate a personalized curriculum tailored to your goals and learning style
                </p>
            </div>

            {!learningPlan ? (
                // Plan Generator
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
                    {/* Domain Selection */}
                    <motion.div
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="space-y-6"
                    >
                        <h2 className="text-2xl font-black text-white uppercase italic">
                            Select Your Domain
                        </h2>
                        <div className="grid grid-cols-2 gap-4">
                            {domains.map(domain => (
                                <motion.button
                                    key={domain.id}
                                    whileHover={{ scale: 1.05 }}
                                    onClick={() => setSelectedDomain(domain.id)}
                                    className={`p-6 rounded-2xl transition-all ${selectedDomain === domain.id
                                        ? `bg-gradient-to-br ${domain.color} border-2 border-white`
                                        : 'bg-white/5 border border-white/10 hover:border-white/20'
                                        }`}
                                >
                                    <div className="text-3xl mb-2">{domain.icon}</div>
                                    <div className="font-bold text-sm">{domain.name}</div>
                                </motion.button>
                            ))}
                        </div>
                    </motion.div>

                    {/* Difficulty Selection */}
                    <motion.div
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="space-y-6"
                    >
                        <h2 className="text-2xl font-black text-white uppercase italic">
                            Choose Difficulty
                        </h2>
                        <div className="space-y-3">
                            {difficulties.map(diff => (
                                <motion.button
                                    key={diff}
                                    whileHover={{ x: 10 }}
                                    onClick={() => setSelectedDifficulty(diff)}
                                    className={`w-full p-4 rounded-xl transition-all text-left font-bold uppercase tracking-widest ${selectedDifficulty === diff
                                        ? 'bg-primary-500 text-dark-900 border-2 border-white'
                                        : 'bg-white/5 text-white border border-white/10 hover:border-primary-500/30'
                                        }`}
                                >
                                    <div className="flex items-center justify-between">
                                        <span>{diff.charAt(0).toUpperCase() + diff.slice(1)}</span>
                                        <span className="text-xs">
                                            {diff === 'beginner' && '0-20 hrs'}
                                            {diff === 'intermediate' && '20-40 hrs'}
                                            {diff === 'advanced' && '40-80 hrs'}
                                            {diff === 'expert' && '80+ hrs'}
                                        </span>
                                    </div>
                                </motion.button>
                            ))}
                        </div>

                        {/* Generate Button */}
                        <motion.button
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={generatePlan}
                            className="w-full mt-8 px-8 py-4 bg-gradient-to-r from-primary-500 to-accent-500 text-white rounded-2xl font-black uppercase italic tracking-tighter shadow-xl"
                        >
                            <Zap className="inline mr-2 w-5 h-5" />
                            Generate Plan with AI
                        </motion.button>
                    </motion.div>
                </div>
            ) : (
                // Rendered Learning Plan
                <div className="space-y-8">
                    {/* Plan Overview */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="grid grid-cols-1 md:grid-cols-4 gap-6"
                    >
                        {[
                            { icon: Target, label: 'Domain', value: selectedDomain },
                            { icon: Zap, label: 'Difficulty', value: selectedDifficulty },
                            { icon: Clock, label: 'Duration', value: '8 Weeks' },
                            { icon: CheckCircle, label: 'Modules', value: learningPlan?.weeks?.length || 8 },
                        ].map((stat, idx) => {
                            const Icon = stat.icon;
                            return (
                                <motion.div
                                    key={idx}
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: idx * 0.1 }}
                                    className="p-6 rounded-2xl bg-gradient-to-br from-white/10 to-white/5 border border-white/10 hover:border-primary-500/30 transition-all"
                                >
                                    <Icon className="w-8 h-8 text-primary-500 mb-3" />
                                    <p className="text-xs text-gray-400 uppercase tracking-widest mb-1">{stat.label}</p>
                                    <p className="text-xl font-black text-white capitalize">{stat.value}</p>
                                </motion.div>
                            );
                        })}
                    </motion.div>

                    {/* Weekly Breakdown */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-4"
                    >
                        <h2 className="text-2xl font-black text-white uppercase italic">8-Week Curriculum</h2>
                        {(learningPlan?.weeks || []).map((week, idx) => (
                            <motion.div
                                key={idx}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: idx * 0.05 }}
                                className="p-6 rounded-2xl bg-dark-800/50 border border-white/10 hover:border-primary-500/30 transition-all cursor-pointer group"
                            >
                                <div className="flex items-start justify-between mb-4">
                                    <div>
                                        <h3 className="text-lg font-black text-white mb-1 group-hover:text-primary-500 transition-colors">
                                            Week {idx + 1}: {week.title}
                                        </h3>
                                        <p className="text-sm text-gray-400">{week.summary}</p>
                                    </div>
                                    <motion.button
                                        whileHover={{ scale: 1.1 }}
                                        onClick={() => startWeek(idx + 1)}
                                        className="px-4 py-2 rounded-lg bg-primary-500 text-dark-900 font-bold text-sm uppercase group-hover:shadow-lg group-hover:shadow-primary-500/50 transition-all"
                                    >
                                        Start Week
                                    </motion.button>
                                </div>

                                {/* Topics */}
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                    {(week.topics || []).map((topic, topicIdx) => (
                                        <span
                                            key={topicIdx}
                                            className="px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-xs font-bold text-primary-500 uppercase"
                                        >
                                            {topic}
                                        </span>
                                    ))}
                                </div>

                                {/* Metrics */}
                                <div className="flex gap-4 mt-4 text-xs text-gray-400">
                                    <span>📚 {week.labs} labs</span>
                                    <span>⏱ {week.hours}h</span>
                                    <span>🎯 {week.xp_reward} XP</span>
                                </div>
                            </motion.div>
                        ))}
                    </motion.div>

                    {/* Difficulty Adaptive Note */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.5 }}
                        className="p-6 rounded-2xl bg-primary-500/10 border border-primary-500/20 flex gap-4"
                    >
                        <Brain className="w-6 h-6 text-primary-500 flex-shrink-0 mt-1" />
                        <div>
                            <h4 className="font-bold text-white mb-2">Adaptive Difficulty</h4>
                            <p className="text-sm text-gray-300">
                                This plan will automatically adjust its difficulty based on your performance. 
                                Struggling? We'll add more foundational labs. Excelling? Expect harder challenges!
                            </p>
                        </div>
                    </motion.div>

                    {/* Generate New Plan Button */}
                    <motion.button
                        whileHover={{ scale: 1.05 }}
                        onClick={() => setLearningPlan(null)}
                        className="w-full px-8 py-4 bg-white/5 text-white rounded-2xl font-black uppercase italic border border-white/10 hover:border-primary-500/30 transition-all"
                    >
                        Generate New Plan
                    </motion.button>
                </div>
            )}
        </div>
    );
};

export default LearningPlanner;
