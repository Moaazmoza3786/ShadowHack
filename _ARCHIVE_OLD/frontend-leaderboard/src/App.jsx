import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Trophy,
    Flame,
    TrendingUp,
    TrendingDown,
    Target,
    User as UserIcon,
    Shield,
    Zap
} from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    Legend
} from 'recharts';

// Components
const FirstBloodTicker = ({ notification }) => {
    return (
        <div className="w-full bg-red-950/30 border-y border-red-500/50 py-2 overflow-hidden mb-6 relative">
            <div className="absolute inset-x-0 h-px bg-red-500 top-0 opacity-20" />
            <div className="absolute inset-x-0 h-px bg-red-500 bottom-0 opacity-20" />

            <AnimatePresence mode="wait">
                {notification && (
                    <motion.div
                        key={notification.timestamp}
                        initial={{ x: '100%' }}
                        animate={{ x: '-100%' }}
                        transition={{ duration: 15, ease: "linear" }}
                        className="whitespace-nowrap flex items-center gap-4 text-red-400 font-cyber font-bold italic uppercase tracking-widest text-sm"
                    >
                        <Shield className="w-4 h-4 fill-red-500 animate-pulse" />
                        {notification.message}
                        <Shield className="w-4 h-4 fill-red-500 animate-pulse" />
                    </motion.div>
                )}
            </AnimatePresence>

            {!notification && (
                <div className="text-gray-500 text-center font-cyber text-xs uppercase tracking-tighter opacity-50">
                    Waiting for system breaches...
                </div>
            )}
        </div>
    );
};

const ScoreProgressChart = ({ progression }) => {
    if (!progression || progression.length === 0) return null;

    // Flatten and format data for recharts
    // Each progression is { username, data: [{time, score}] }
    // We need to merge them by time
    const chartData = [];
    const timeLabels = new Set();
    progression.forEach(p => p.data.forEach(d => timeLabels.add(d.time)));

    const sortedTimes = Array.from(timeLabels).sort();

    sortedTimes.forEach(time => {
        const entry = { time: new Date(time).toLocaleTimeString() };
        progression.forEach(p => {
            const match = p.data.find(d => d.time === time);
            entry[p.username] = match ? match.score : null;
        });
        chartData.push(entry);
    });

    const colors = ['#22c55e', '#a855f7', '#06b6d4', '#eab308', '#ef4444'];

    return (
        <div className="w-full h-[250px] glass-panel rounded-xl p-4 mb-8 cyber-border">
            <h3 className="text-neon-cyan font-cyber text-sm mb-4 flex items-center gap-2">
                <TrendingUp className="w-4 h-4" /> TOP OPERATIVES XP PROGRESSION
            </h3>
            <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e1e2e" />
                    <XAxis
                        dataKey="time"
                        stroke="#475569"
                        fontSize={10}
                        tick={{ fill: '#475569' }}
                    />
                    <YAxis
                        stroke="#475569"
                        fontSize={10}
                        tick={{ fill: '#475569' }}
                    />
                    <Tooltip
                        contentStyle={{ backgroundColor: '#0a0a0f', borderColor: '#06b6d4', color: '#fff' }}
                        itemStyle={{ fontSize: '12px' }}
                    />
                    <Legend wrapperStyle={{ fontSize: '10px' }} />
                    {progression.map((p, idx) => (
                        <Line
                            key={p.username}
                            type="monotone"
                            dataKey={p.username}
                            stroke={colors[idx % colors.length]}
                            strokeWidth={2}
                            dot={false}
                            animationDuration={1500}
                        />
                    ))}
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
};

const LeaderboardRow = ({ user, index }) => {
    const isTop3 = index < 3;
    const rankColors = ["text-yellow-400", "text-slate-300", "text-amber-600"];

    return (
        <motion.tr
            layout
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.4, delay: index * 0.05 }}
            className={`group border-b border-gray-800/50 hover:bg-neon-cyan/5 transition-all duration-300 relative overflow-hidden`}
        >
            {/* Background highlight for active or on-fire users */}
            {user.streak_days > 3 && (
                <div className="absolute inset-0 bg-gradient-to-r from-orange-500/5 to-transparent pointer-events-none" />
            )}

            <td className="py-4 pl-4">
                <div className={`font-cyber italic text-xl ${isTop3 ? rankColors[index] : 'text-gray-500'}`}>
                    #{user.rank}
                </div>
            </td>

            <td className="py-4">
                <div className="relative inline-block">
                    {user.avatar_url ? (
                        <img src={user.avatar_url} className="w-10 h-10 rounded-full border border-neon-cyan/30" alt={user.username} />
                    ) : (
                        <div className="w-10 h-10 bg-gray-800 rounded-full flex items-center justify-center border border-gray-700">
                            <UserIcon className="w-6 h-6 text-gray-400" />
                        </div>
                    )}
                    {user.streak_days > 2 && (
                        <div className="absolute -top-1 -right-1">
                            <Flame className="w-4 h-4 text-orange-500 fill-orange-500 animate-bounce" />
                        </div>
                    )}
                </div>
            </td>

            <td className="py-4">
                <div className="flex flex-col">
                    <span className="font-bold text-gray-100 group-hover:text-neon-cyan transition-colors">
                        {user.username}
                    </span>
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-cyber">
                        {user.current_rank}
                    </span>
                </div>
            </td>

            <td className="py-4 text-center">
                <div className="flex flex-col items-center">
                    <span className="text-neon-green font-bold text-lg drop-shadow-[0_0_8px_rgba(34,197,94,0.4)]">
                        {user.xp_points}
                    </span>
                    <span className="text-[9px] text-gray-600 uppercase">XP UNITS</span>
                </div>
            </td>

            <td className="py-4 text-center">
                <div className="flex flex-col items-center">
                    <div className="flex items-center gap-1 text-neon-purple font-bold">
                        <Shield className="w-3 h-3" />
                        {user.solvedCount}
                    </div>
                    <span className="text-[9px] text-gray-600 uppercase">SYSTEMS PWNED</span>
                </div>
            </td>

            <td className="py-4 pr-4 text-right">
                {/* Mocking trend for visual effect */}
                {index % 3 === 0 ? (
                    <TrendingUp className="w-4 h-4 text-neon-green ml-auto" />
                ) : (
                    <div className="w-4 h-4 rounded-full border border-gray-800 ml-auto" />
                )}
            </td>
        </motion.tr>
    );
};

export default function App() {
    const [data, setData] = useState({ leaderboard: [], progression: [] });
    const [notification, setNotification] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Connect to Node.js server
        const socket = io('http://localhost:3001');

        socket.on('connect', () => {
            console.log('Connected to real-time hub');
            setLoading(false);
        });

        socket.on('leaderboard_update', (payload) => {
            console.log('Update received:', payload);
            setData({
                leaderboard: payload.leaderboard,
                progression: payload.progression
            });
        });

        socket.on('notification', (notif) => {
            setNotification(notif);
            // Clear notification after some time or when animation finishes
            setTimeout(() => setNotification(null), 15000);
        });

        return () => {
            socket.disconnect();
        };
    }, []);

    return (
        <div className="min-h-screen bg-cyber-black font-cairo text-gray-200 p-4 md:p-8 relative">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <header className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
                    <div>
                        <div className="text-neon-cyan font-cyber font-bold tracking-[0.2em] mb-2 flex items-center gap-2">
                            <Zap className="fill-neon-cyan w-4 h-4" /> SYSTEM STATE: LIVE
                        </div>
                        <h1 className="text-4xl md:text-6xl font-black font-cyber text-transparent bg-clip-text bg-gradient-to-r from-white via-white to-gray-500 glow-text">
                            ANTIGRAVITY<br />LEADERBOARD
                        </h1>
                    </div>

                    <div className="flex items-center gap-6 glass-panel px-6 py-4 rounded-xl border-l-4 border-neon-purple">
                        <div className="text-center">
                            <div className="text-2xl font-black text-neon-purple font-cyber">
                                {data.leaderboard.reduce((acc, u) => acc + u.solvedCount, 0)}
                            </div>
                            <div className="text-[10px] text-gray-500 uppercase font-cyber">Global Compromises</div>
                        </div>
                        <div className="w-px h-8 bg-gray-800" />
                        <div className="text-center">
                            <div className="text-2xl font-black text-neon-cyan font-cyber">
                                {data.leaderboard.length}
                            </div>
                            <div className="text-[10px] text-gray-500 uppercase font-cyber">Active Operatives</div>
                        </div>
                    </div>
                </header>

                {/* First Blood Ticker */}
                <FirstBloodTicker notification={notification} />

                {/* The Graph */}
                <ScoreProgressChart progression={data.progression} />

                {/* Main Grid */}
                <div className="w-full">
                    <div className="glass-panel rounded-xl overflow-hidden cyber-border">
                        <div className="p-4 border-b border-gray-800 bg-gray-900/50 flex items-center justify-between">
                            <div className="flex items-center gap-3 font-cyber text-sm tracking-widest text-gray-400">
                                <Shield className="w-4 h-4" /> RANKINGS DATABASE
                            </div>
                            <div className="flex gap-1">
                                {[1, 2, 3].map(i => <div key={i} className="w-2 h-2 rounded-full border border-gray-700" />)}
                            </div>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className="bg-gray-900/40 text-[10px] uppercase font-cyber text-gray-500 tracking-tighter">
                                        <th className="py-3 pl-4">Rank</th>
                                        <th className="py-3">Agent</th>
                                        <th className="py-3">Handle</th>
                                        <th className="py-3 text-center">XP Units</th>
                                        <th className="py-3 text-center">Solves</th>
                                        <th className="py-3 pr-4 text-right">Trend</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <AnimatePresence>
                                        {data.leaderboard.map((user, idx) => (
                                            <LeaderboardRow key={user.id} user={user} index={idx} />
                                        ))}
                                    </AnimatePresence>
                                </tbody>
                            </table>
                        </div>

                        {data.leaderboard.length === 0 && !loading && (
                            <div className="py-20 text-center">
                                <div className="text-gray-500 font-cyber animate-pulse">NO OPERATIVES DETECTED IN SECTOR</div>
                            </div>
                        )}

                        {loading && (
                            <div className="py-20 flex flex-col items-center justify-center gap-4">
                                <div className="w-12 h-12 border-2 border-neon-cyan border-t-transparent rounded-full animate-spin" />
                                <div className="text-neon-cyan font-cyber text-xs animate-pulse">ESTABLISHING UPLINK...</div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer info */}
                <footer className="mt-8 text-center text-gray-600 text-[10px] uppercase font-cyber tracking-[0.3em]">
                    &copy; BreachLabs Terminal // Neural Sync Enabled
                </footer>
            </div>

            {/* Background Decor */}
            <div className="fixed top-0 left-0 w-full h-full pointer-events-none -z-10 opacity-30">
                <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_-20%,#1a1a2e,transparent)]" />
                <div
                    className="absolute inset-0"
                    style={{ backgroundImage: 'radial-gradient(#1a1a2e 1px, transparent 1px)', backgroundSize: '40px 40px' }}
                />
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-neon-cyan to-transparent animate-scanline opacity-20" />
            </div>
        </div>
    );
}
