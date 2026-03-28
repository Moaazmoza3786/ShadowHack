import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Globe, Flame, Trophy, TrendingUp } from 'lucide-react';

/**
 * Global Leaderboards Component
 * Displays rankings across regions and time periods
 */

const GlobalLeaderboards = () => {
    const [leaderboard, setLeaderboard] = useState([]);
    const [region, setRegion] = useState('global');
    const [period, setPeriod] = useState('weekly');
    const [loading, setLoading] = useState(false);
    const [userRank, setUserRank] = useState(null);

    const regions = [
        { id: 'global', name: '🌍 Global', icon: Globe },
        { id: 'europe', name: '🇪🇺 Europe', icon: Globe },
        { id: 'americas', name: '🌎 Americas', icon: Globe },
        { id: 'asia', name: '🌏 Asia', icon: Globe },
        { id: 'middle-east', name: '🕌 Middle East', icon: Globe },
        { id: 'africa', name: '🌍 Africa', icon: Globe },
    ];

    const periods = [
        { id: 'weekly', name: 'Weekly', icon: '📅' },
        { id: 'monthly', name: 'Monthly', icon: '📊' },
        { id: 'alltime', name: 'All-Time', icon: '🏆' },
    ];

    useEffect(() => {
        fetchLeaderboard();
    }, [region, period]);

    const fetchLeaderboard = async () => {
        setLoading(true);
        try {
            const response = await fetch(
                `/api/leagues/global-${period}?limit=100`
            );
            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    setLeaderboard(data.rankings);
                    setUserRank(data.user_rank);
                }
            } else {
                // Use mock data for development
                setLeaderboard(generateMockData());
            }
        } catch (error) {
            console.error('Error fetching leaderboard:', error);
            // Use mock data as fallback
            setLeaderboard(generateMockData());
        } finally {
            setLoading(false);
        }
    };

    const generateMockData = () => {
        const names = ['AlexHacker', 'CyberNinja', 'SecurityPro', 'CodeMaster', 'EthicalHacker',
            'WhiteHatWizard', 'BugBountyKing', 'PentestPro', 'EncryptionGuru', 'NetworkNinja',
            'PayloadExpert', 'SplitSecond', 'ReverseEng', 'CryptoQueen', 'LogicBomb'];
        const countries = ['🇺🇸 USA', '🇬🇧 UK', '🇮🇳 India', '🇧🇷 Brazil', '🇨🇦 Canada', '🇩🇪 Germany', '🇯🇵 Japan', '🇸🇦 Saudi Arabia'];
        return Array.from({ length: 50 }, (_, i) => ({
            rank: i + 1,
            id: i + 1,
            username: names[i % names.length] + Math.floor(Math.random() * 1000),
            avatar_url: `https://api.dicebear.com/7.x/avataaars/svg?seed=${i}`,
            xp: Math.max(100, 5000 - i * 100 - Math.random() * 500),
            level: Math.ceil((i + 1) / 5),
            country: countries[Math.floor(Math.random() * countries.length)],
            labs_completed: Math.floor(Math.random() * 50) + 5
        }));
    };

    const getMedalEmoji = (rank) => {
        if (rank === 1) return '🥇';
        if (rank === 2) return '🥈';
        if (rank === 3) return '🥉';
        return `#${rank}`;
    };

    return (
        <div className="space-y-8 pb-12">
            {/* Header */}
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4"
            >
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/20">
                    <Trophy className="w-4 h-4 text-primary-500" />
                    <span className="text-sm font-bold text-primary-500 uppercase tracking-widest">
                        Competitive Rankings
                    </span>
                </div>
                <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
                    Global Leaderboards
                </h1>
                <p className="text-gray-400 text-lg max-w-2xl">
                    Compete globally and regionally. Earn your rank among top hackers worldwide.
                </p>
            </motion.div>

            {/* Your Rank Card */}
            {userRank && (
                <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="p-6 rounded-2xl bg-gradient-to-r from-primary-500/20 to-accent-500/20 border-2 border-primary-500/50"
                >
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm font-bold text-gray-400 uppercase tracking-widest mb-1">
                                Your Current Rank
                            </p>
                            <div className="flex items-center gap-4">
                                <span className="text-4xl font-black text-primary-500">
                                    #{userRank.rank}
                                </span>
                                <div>
                                    <p className="text-lg font-bold text-white">{userRank.xp} XP</p>
                                    <p className="text-xs text-gray-400">
                                        {userRank.region} • {period}
                                    </p>
                                </div>
                            </div>
                        </div>
                        <TrendingUp className="w-12 h-12 text-accent-500" />
                    </div>
                </motion.div>
            )}

            {/* Controls */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Region Selector */}
                <div className="space-y-3">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-widest">
                        Select Region
                    </h3>
                    <div className="grid grid-cols-2 gap-2">
                        {regions.map(r => (
                            <motion.button
                                key={r.id}
                                whileHover={{ scale: 1.05 }}
                                onClick={() => setRegion(r.id)}
                                className={`p-3 rounded-xl transition-all font-bold text-sm uppercase ${
                                    region === r.id
                                        ? 'bg-primary-500 text-dark-900 border-2 border-white'
                                        : 'bg-white/5 text-white border border-white/10 hover:border-primary-500/30'
                                }`}
                            >
                                {r.name}
                            </motion.button>
                        ))}
                    </div>
                </div>

                {/* Period Selector */}
                <div className="space-y-3">
                    <h3 className="text-sm font-bold text-gray-400 uppercase tracking-widest">
                        Time Period
                    </h3>
                    <div className="grid grid-cols-3 gap-2">
                        {periods.map(p => (
                            <motion.button
                                key={p.id}
                                whileHover={{ scale: 1.05 }}
                                onClick={() => setPeriod(p.id)}
                                className={`p-3 rounded-xl transition-all font-bold text-sm uppercase ${
                                    period === p.id
                                        ? 'bg-accent-500 text-white border-2 border-white'
                                        : 'bg-white/5 text-white border border-white/10 hover:border-accent-500/30'
                                }`}
                            >
                                {p.icon} {p.name}
                            </motion.button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Leaderboard Table */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-2xl bg-dark-800/50 border border-white/10 overflow-hidden"
            >
                {loading ? (
                    <div className="p-12 text-center">
                        <div className="inline-block w-12 h-12 border-4 border-primary-500/20 border-t-primary-500 rounded-full animate-spin" />
                        <p className="mt-4 text-gray-400">Loading rankings...</p>
                    </div>
                ) : leaderboard.length === 0 ? (
                    <div className="p-12 text-center text-gray-400">
                        No rankings available for this period
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="border-b border-white/10">
                                <tr className="bg-white/5">
                                    <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-widest">
                                        Rank
                                    </th>
                                    <th className="px-6 py-4 text-left text-xs font-bold text-gray-400 uppercase tracking-widest">
                                        Player
                                    </th>
                                    <th className="px-6 py-4 text-right text-xs font-bold text-gray-400 uppercase tracking-widest">
                                        XP
                                    </th>
                                    <th className="px-6 py-4 text-right text-xs font-bold text-gray-400 uppercase tracking-widest">
                                        Level
                                    </th>
                                    <th className="px-6 py-4 text-right text-xs font-bold text-gray-400 uppercase tracking-widest">
                                        Labs
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5">
                                {leaderboard.map((player, idx) => (
                                    <motion.tr
                                        key={player.id}
                                        initial={{ opacity: 0, x: -20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: idx * 0.05 }}
                                        className={`hover:bg-white/5 transition-colors ${
                                            idx === 0 ? 'bg-yellow-500/10' :
                                            idx === 1 ? 'bg-gray-400/10' :
                                            idx === 2 ? 'bg-orange-500/10' : ''
                                        }`}
                                    >
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-3">
                                                <span className="text-2xl">{getMedalEmoji(player.rank)}</span>
                                                <span className="text-sm font-bold text-gray-400">
                                                    #{player.rank}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-3">
                                                <img
                                                    src={player.avatar_url || '/default-avatar.png'}
                                                    alt={player.username}
                                                    className="w-10 h-10 rounded-full border border-white/10"
                                                />
                                                <div>
                                                    <p className="font-bold text-white">{player.username}</p>
                                                    <p className="text-xs text-gray-500">{player.country}</p>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <span className="font-bold text-primary-500 text-lg">
                                                {player.xp.toLocaleString()}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <span className="px-3 py-1 rounded-full bg-primary-500/20 border border-primary-500/30 text-sm font-bold text-primary-500">
                                                Lvl {player.level}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <div className="text-right">
                                                <p className="font-bold text-white">{player.labs_completed}</p>
                                                <p className="text-xs text-gray-500">completed</p>
                                            </div>
                                        </td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </motion.div>

            {/* Stats Footer */}
            <div className="grid grid-cols-3 gap-4">
                {[
                    { icon: '👥', label: 'Active Players', value: '10,582' },
                    { icon: '🌍', label: 'Countries', value: '142' },
                    { icon: '⚡', label: 'Total XP Earned', value: '5.2M' },
                ].map((stat, idx) => (
                    <motion.div
                        key={idx}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.1 }}
                        className="p-6 rounded-2xl bg-white/5 border border-white/10 text-center"
                    >
                        <div className="text-3xl mb-2">{stat.icon}</div>
                        <p className="text-sm text-gray-400 uppercase tracking-widest mb-1">
                            {stat.label}
                        </p>
                        <p className="text-2xl font-black text-white">{stat.value}</p>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default GlobalLeaderboards;
