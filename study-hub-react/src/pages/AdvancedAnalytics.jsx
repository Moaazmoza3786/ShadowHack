import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { BarChart3, TrendingUp, Clock, Zap, Calendar, Filter } from 'lucide-react';

/**
 * Advanced Analytics Dashboard
 * Detailed insights into learning progress, engagement, and performance
 */

const AdvancedAnalytics = () => {
  const [timeRange, setTimeRange] = useState('30d');
  const [selectedMetric, setSelectedMetric] = useState('xp');
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    generateChartData();
  }, [timeRange, selectedMetric]);

  const generateChartData = () => {
    const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 365;
    const data = [];
    
    for (let i = 0; i < days; i++) {
      const date = new Date();
      date.setDate(date.getDate() - (days - 1 - i));
      
      const value = selectedMetric === 'xp' 
        ? Math.floor(Math.random() * 300) + 100
        : selectedMetric === 'labs'
        ? Math.floor(Math.random() * 5) + 1
        : Math.floor(Math.random() * 2) + 1;
      
      data.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        value,
      });
    }
    setChartData(data);
  };

  const maxValue = Math.max(...chartData.map(d => d.value), 1);
  const avgValue = Math.round(chartData.reduce((sum, d) => sum + d.value, 0) / chartData.length);

  const metrics = [
    {
      id: 'xp',
      label: 'XP Earned',
      value: '12,450',
      change: '+15%',
      icon: '⭐',
      color: 'from-purple-500 to-pink-500',
    },
    {
      id: 'labs',
      label: 'Labs Completed',
      value: '42',
      change: '+8%',
      icon: '🔬',
      color: 'from-blue-500 to-cyan-500',
    },
    {
      id: 'time',
      label: 'Hours Spent',
      value: '156',
      change: '+12%',
      icon: '⏱️',
      color: 'from-green-500 to-emerald-500',
    },
    {
      id: 'streak',
      label: 'Day Streak',
      value: '18',
      change: '+2',
      icon: '🔥',
      color: 'from-red-500 to-orange-500',
    },
  ];

  const skillBreakdown = [
    { skill: 'Web Security', percentage: 92, xp: 3200 },
    { skill: 'Network Security', percentage: 78, xp: 2100 },
    { skill: 'Cryptography', percentage: 65, xp: 1800 },
    { skill: 'Reverse Engineering', percentage: 54, xp: 1500 },
    { skill: 'Cloud Security', percentage: 71, xp: 1850 },
  ];

  const learningPaths = [
    { name: 'CEH Preparation', progress: 65, labs_done: 18, labs_total: 28, estimated_completion: '12 days' },
    { name: 'OSCP Path', progress: 42, labs_done: 12, labs_total: 28, estimated_completion: '28 days' },
    { name: 'Bug Bounty Mastery', progress: 78, labs_done: 23, labs_total: 29, estimated_completion: '5 days' },
  ];

  const recentAchievements = [
    { emoji: '🥇', name: 'Speed Demon', description: 'Complete lab in under 5 minutes', date: '2 days ago' },
    { emoji: '🎯', name: 'Perfect Score', description: '100% on CTF Challenge', date: '5 days ago' },
    { emoji: '🔓', name: 'Exploit Master', description: 'Chain 5 exploits successfully', date: '1 week ago' },
  ];

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-4"
      >
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-cyan-500/10 border border-cyan-500/20">
          <BarChart3 className="w-4 h-4 text-cyan-500" />
          <span className="text-sm font-bold text-cyan-500 uppercase tracking-widest">
            Deep Insights
          </span>
        </div>
        <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
          Advanced Analytics
        </h1>
        <p className="text-gray-400 text-lg max-w-2xl">
          Comprehensive analysis of your learning journey, skill development, and performance trends.
        </p>
      </motion.div>

      {/* Time Range Selector */}
      <div className="flex gap-3">
        {['7d', '30d', '365d'].map(range => (
          <button
            key={range}
            onClick={() => setTimeRange(range)}
            className={`px-4 py-2 rounded-lg font-bold transition-all ${
              timeRange === range
                ? 'bg-cyan-500 text-black'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            }`}
          >
            {range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '1 Year'}
          </button>
        ))}
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((metric, idx) => (
          <motion.div
            key={metric.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            onClick={() => setSelectedMetric(metric.id)}
            className={`p-6 rounded-xl bg-gradient-to-br ${metric.color}/10 border-2 transition-all cursor-pointer ${
              selectedMetric === metric.id ? `border-${metric.color}/100` : 'border-gray-700/50 hover:border-gray-700/100'
            }`}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <p className="text-sm text-gray-400 mb-1">{metric.label}</p>
                <p className="text-3xl font-black text-white">{metric.value}</p>
              </div>
              <span className="text-3xl">{metric.icon}</span>
            </div>
            <p className="text-xs text-green-400 font-bold">{metric.change} this period</p>
          </motion.div>
        ))}
      </div>

      {/* Main Chart */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">
            {selectedMetric === 'xp' ? 'XP Earned Over Time' : 
             selectedMetric === 'labs' ? 'Labs Completed' : 
             'Streak Continuity'}
          </h2>
          <p className="text-sm text-gray-400">Average: {avgValue} per day</p>
        </div>

        {/* Chart */}
        <div className="flex items-end justify-between h-64 gap-1 p-4 bg-gray-900/50 rounded-lg border border-gray-700/50">
          {chartData.map((data, idx) => (
            <div key={idx} className="flex-1 flex flex-col items-center justify-end group">
              <div
                className="w-full bg-gradient-to-t from-cyan-500 to-purple-500 rounded-t transition-all group-hover:opacity-80"
                style={{ height: `${(data.value / maxValue) * 100}%` }}
                title={`${data.date}: ${data.value}`}
              />
              {chartData.length <= 7 && (
                <p className="text-xs text-gray-500 mt-2 text-center">{data.date}</p>
              )}
            </div>
          ))}
        </div>
      </motion.div>

      {/* Skills Breakdown */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50"
      >
        <h2 className="text-xl font-bold text-white mb-6">Skill Development</h2>
        <div className="space-y-4">
          {skillBreakdown.map((skill, idx) => (
            <div key={idx}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-bold text-white">{skill.skill}</p>
                <p className="text-xs text-cyan-400 font-bold">{skill.percentage}%</p>
              </div>
              <div className="h-3 bg-gray-900/50 rounded-full overflow-hidden border border-gray-700/50">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${skill.percentage}%` }}
                  transition={{ delay: 0.1, duration: 1 }}
                  className="h-full bg-gradient-to-r from-cyan-500 to-purple-500"
                />
              </div>
              <p className="text-xs text-gray-400 mt-1">{skill.xp} XP earned</p>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Learning Paths Progress */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50"
      >
        <h2 className="text-xl font-bold text-white mb-6">Learning Paths Progress</h2>
        <div className="space-y-6">
          {learningPaths.map((path, idx) => (
            <div key={idx} className="p-4 bg-gray-900/50 rounded-lg border border-gray-700/50">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold text-white">{path.name}</h3>
                <span className="text-sm text-cyan-400 font-bold">{path.progress}%</span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden mb-3">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${path.progress}%` }}
                  transition={{ delay: 0.2, duration: 1 }}
                  className="h-full bg-gradient-to-r from-cyan-500 to-purple-500"
                />
              </div>
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span>{path.labs_done}/{path.labs_total} labs completed</span>
                <span>⏱️ {path.estimated_completion}</span>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Recent Achievements */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50"
      >
        <h2 className="text-xl font-bold text-white mb-6">Recent Achievements</h2>
        <div className="space-y-3">
          {recentAchievements.map((achievement, idx) => (
            <div key={idx} className="flex items-center gap-4 p-4 bg-gray-900/50 rounded-lg border border-gray-700/50">
              <span className="text-3xl">{achievement.emoji}</span>
              <div className="flex-1">
                <p className="font-bold text-white">{achievement.name}</p>
                <p className="text-sm text-gray-400">{achievement.description}</p>
              </div>
              <p className="text-xs text-gray-500">{achievement.date}</p>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Performance Summary */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
        className="grid grid-cols-1 md:grid-cols-2 gap-4"
      >
        <div className="p-6 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30">
          <h3 className="font-bold text-white mb-2">Strengths</h3>
          <ul className="text-sm text-gray-300 space-y-1">
            <li>• Excellent in Web Security</li>
            <li>• Consistent daily engagement</li>
            <li>• Fast lab completion time</li>
          </ul>
        </div>
        <div className="p-6 rounded-xl bg-gradient-to-br from-yellow-500/20 to-orange-500/20 border border-yellow-500/30">
          <h3 className="font-bold text-white mb-2">Growth Areas</h3>
          <ul className="text-sm text-gray-300 space-y-1">
            <li>• Reverse Engineering: 54%</li>
            <li>• Advanced cryptography topics</li>
            <li>• Challenge time optimization</li>
          </ul>
        </div>
      </motion.div>
    </div>
  );
};

export default AdvancedAnalytics;
