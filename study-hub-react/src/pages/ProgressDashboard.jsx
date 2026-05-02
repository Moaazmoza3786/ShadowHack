import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { TrendingUp, Target, Award, Clock } from 'lucide-react';

// Custom Skill Radar Chart Component
const SkillRadar = ({ skills = [], size = 300 }) => {
    const angleSlice = (Math.PI * 2) / skills.length;
    const radius = size / 2.5;
    const center = size / 2;

    const getPoint = (index, value) => {
        const angle = angleSlice * index - Math.PI / 2;
        const x = center + radius * (value / 100) * Math.cos(angle);
        const y = center + radius * (value / 100) * Math.sin(angle);
        return { x, y };
    };

    // Create polygon points
    const radarPoints = skills.map((skill, idx) => {
        const point = getPoint(idx, skill.value);
        return `${point.x},${point.y}`;
    }).join(' ');

    // Grid lines
    const gridLevels = 5;
    const gridLines = Array.from({ length: gridLevels }, (_, i) => {
        const level = ((i + 1) / gridLevels) * 100;
        const points = skills.map((_, idx) => {
            const point = getPoint(idx, level);
            return `${point.x},${point.y}`;
        }).join(' ');
        return points;
    });

    return (
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
            {/* Grid */}
            {gridLines.map((points, i) => (
                <polygon
                    key={`grid-${i}`}
                    points={points}
                    fill="none"
                    stroke="rgba(255, 255, 255, 0.1)"
                    strokeWidth="1"
                />
            ))}

            {/* Axes */}
            {skills.map((_, idx) => {
                const endPoint = getPoint(idx, 100);
                return (
                    <line
                        key={`axis-${idx}`}
                        x1={center}
                        y1={center}
                        x2={endPoint.x}
                        y2={endPoint.y}
                        stroke="rgba(255, 255, 255, 0.1)"
                        strokeWidth="1"
                    />
                );
            })}

            {/* Data polygon */}
            <motion.polygon
                points={radarPoints}
                fill="rgba(51, 171, 255, 0.15)"
                stroke="rgba(51, 171, 255, 0.6)"
                strokeWidth="2"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.8 }}
            />

            {/* Data points */}
            {skills.map((skill, idx) => {
                const point = getPoint(idx, skill.value);
                return (
                    <g key={`point-${idx}`}>
                        <motion.circle
                            cx={point.x}
                            cy={point.y}
                            r="4"
                            fill="rgba(51, 171, 255, 1)"
                            initial={{ r: 0 }}
                            animate={{ r: 4 }}
                            transition={{ duration: 0.6, delay: idx * 0.1 }}
                        />
                    </g>
                );
            })}

            {/* Labels */}
            {skills.map((skill, idx) => {
                const labelPoint = getPoint(idx, 120);
                return (
                    <text
                        key={`label-${idx}`}
                        x={labelPoint.x}
                        y={labelPoint.y}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        fill="rgba(255, 255, 255, 0.7)"
                        fontSize="12"
                        fontWeight="bold"
                    >
                        {skill.name}
                    </text>
                );
            })}
        </svg>
    );
};

// Timeline Component
const TimelineView = ({ milestones = [] }) => {
    return (
        <div className="relative">
            {/* Vertical Line */}
            <div className="absolute left-8 top-0 bottom-0 w-1 bg-gradient-to-b from-primary-500/20 to-accent-500/20" />

            {/* Milestones */}
            <div className="space-y-8">
                {milestones.map((milestone, idx) => (
                    <motion.div
                        key={idx}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.5, delay: idx * 0.1 }}
                        className="flex items-start gap-6 relative"
                    >
                        {/* Timeline Dot */}
                        <div className="flex-shrink-0">
                            <motion.div
                                initial={{ scale: 0 }}
                                animate={{ scale: 1 }}
                                transition={{ duration: 0.4, delay: idx * 0.1 + 0.2 }}
                                className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-500/20 to-accent-500/20 border-2 border-primary-500 flex items-center justify-center flex-shrink-0"
                            >
                                <div className="w-8 h-8 rounded-full bg-primary-500/30 flex items-center justify-center">
                                    <Award className="w-4 h-4 text-primary-500" />
                                </div>
                            </motion.div>
                        </div>

                        {/* Content */}
                        <div className="flex-1 pt-2">
                            <h3 className="text-lg font-bold text-white mb-1">{milestone.title}</h3>
                            <p className="text-sm text-gray-400 mb-2">{milestone.description}</p>
                            <div className="flex items-center gap-4 text-xs">
                                <span className="px-2 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500">
                                    {milestone.date}
                                </span>
                                {milestone.xp && (
                                    <span className="text-green-400 font-bold">+{milestone.xp} XP</span>
                                )}
                            </div>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

// Progress Dashboard Page
const ProgressDashboard = ({ user = {} }) => {
    const [skills, setSkills] = useState([
        { name: 'Web Security', value: 78 },
        { name: 'Crypto', value: 65 },
        { name: 'Forensics', value: 82 },
        { name: 'Privilege Escalation', value: 72 },
        { name: 'Networking', value: 88 },
        { name: 'Reverse Engineering', value: 55 },
    ]);

    const [milestones] = useState([
        {
            title: 'Web Security Mastery',
            description: 'Completed all web security labs and CTF challenges',
            date: 'Mar 15, 2024',
            xp: 1500,
        },
        {
            title: 'First 10 Labs Completed',
            description: 'Milestone achievement unlocked',
            date: 'Mar 10, 2024',
            xp: 500,
        },
        {
            title: 'Account Created',
            description: 'Started your cybersecurity journey',
            date: 'Jan 01, 2024',
            xp: 100,
        },
    ]);

    const [pathProgress] = useState([
        { name: 'Red Team Path', completed: 65, total: 100 },
        { name: 'Blue Team Path', completed: 42, total: 100 },
        { name: 'CTF Master', completed: 81, total: 100 },
    ]);

    return (
        <div className="space-y-12 pb-12">
            {/* Header */}
            <div className="space-y-4">
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/20">
                    <TrendingUp className="w-4 h-4 text-primary-500" />
                    <span className="text-sm font-bold text-primary-500 uppercase tracking-widest">Progress Tracking</span>
                </div>
                <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
                    Your Learning Journey
                </h1>
                <p className="text-gray-400 text-lg max-w-2xl">
                    Track your skill development and celebrate every milestone on your cybersecurity learning path
                </p>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {[
                    { label: 'Labs Completed', value: '42', icon: Target, color: 'bg-primary-500' },
                    { label: 'Total XP', value: '12,850', icon: TrendingUp, color: 'bg-green-500' },
                    { label: 'Current Streak', value: '23 days', icon: Clock, color: 'bg-orange-500' },
                    { label: 'Achievements', value: '18', icon: Award, color: 'bg-accent-500' },
                ].map((stat, idx) => {
                    const Icon = stat.icon;
                    return (
                        <motion.div
                            key={idx}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.1 }}
                            className="p-6 rounded-3xl bg-white/5 border border-white/10 hover:border-white/20 transition-all"
                        >
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">{stat.label}</p>
                                    <p className="text-3xl font-black text-white">{stat.value}</p>
                                </div>
                                <div className={`w-12 h-12 rounded-2xl ${stat.color}/20 flex items-center justify-center border border-white/10`}>
                                    <Icon className={`w-6 h-6 ${stat.color.replace('bg-', 'text-')}`} />
                                </div>
                            </div>
                        </motion.div>
                    );
                })}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
                {/* Skill Radar Chart */}
                <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.6 }}
                    className="lg:col-span-1 flex flex-col items-center"
                >
                    <div className="rounded-3xl bg-gradient-to-br from-dark-800 to-dark-900 border border-white/10 p-8 w-full">
                        <h2 className="text-xl font-black text-white mb-6 text-center uppercase italic">Skill Proficiency</h2>
                        <SkillRadar skills={skills} size={280} />
                        <div className="mt-6 space-y-2 text-sm">
                            {skills.map((skill, idx) => (
                                <div key={idx} className="flex justify-between items-center">
                                    <span className="text-gray-400">{skill.name}</span>
                                    <span className="font-bold text-primary-500">{skill.value}%</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </motion.div>

                {/* Path Progress */}
                <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.6, delay: 0.2 }}
                    className="lg:col-span-2 space-y-6"
                >
                    <div className="rounded-3xl bg-gradient-to-br from-dark-800 to-dark-900 border border-white/10 p-8">
                        <h2 className="text-xl font-black text-white mb-8 uppercase italic">Career Path Progress</h2>

                        {pathProgress.map((path, idx) => (
                            <div key={idx} className="mb-8 last:mb-0">
                                <div className="flex justify-between items-center mb-3">
                                    <h3 className="font-bold text-white">{path.name}</h3>
                                    <span className="text-sm font-bold text-primary-500">{path.completed}%</span>
                                </div>

                                {/* Progress Bar */}
                                <div className="relative h-3 rounded-full bg-white/10 border border-white/5 overflow-hidden">
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${path.completed}%` }}
                                        transition={{ duration: 1.5, ease: 'easeOut', delay: idx * 0.2 }}
                                        className="h-full bg-gradient-to-r from-primary-500 to-accent-500 rounded-full"
                                    />
                                </div>

                                {/* Milestones */}
                                <div className="mt-2 flex gap-2 flex-wrap">
                                    {Array.from({ length: Math.ceil(path.total / 10) }).map((_, i) => (
                                        <div
                                            key={i}
                                            className={`w-2 h-2 rounded-full ${(i + 1) * 10 <= path.completed ? 'bg-primary-500' : 'bg-white/20'}`}
                                        />
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </motion.div>
            </div>

            {/* Timeline Section */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.4 }}
                className="rounded-3xl bg-gradient-to-br from-dark-800 to-dark-900 border border-white/10 p-8"
            >
                <h2 className="text-2xl font-black text-white mb-8 uppercase italic">Achievement Timeline</h2>
                <TimelineView milestones={milestones} />
            </motion.div>
        </div>
    );
};

export default ProgressDashboard;
