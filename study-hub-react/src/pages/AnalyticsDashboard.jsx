
import React, { useState, useEffect } from 'react';
import {
    BarChart2, Activity, Target, Award, TrendingUp,
    Calendar, Zap, Clock, Trophy, CheckCircle
} from 'lucide-react';
import './AnalyticsDashboard.css';

const AnalyticsDashboard = () => {
    const [overview, setOverview] = useState(null);
    const [activity, setActivity] = useState({});
    const [xpHistory, setXpHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchAnalytics();
    }, []);

    const fetchAnalytics = async () => {
        try {
            // Replace 1 with actual user ID
            const [overviewRes, activityRes, xpRes] = await Promise.all([
                fetch('http://localhost:5000/api/analytics/user/1/overview'),
                fetch('http://localhost:5000/api/analytics/user/1/activity?days=90'),
                fetch('http://localhost:5000/api/analytics/user/1/xp-history?days=30')
            ]);

            const overviewData = await overviewRes.json();
            const activityData = await activityRes.json();
            const xpData = await xpRes.json();

            if (overviewData.success) setOverview(overviewData.overview);
            if (activityData.success) setActivity(activityData.activity);
            if (xpData.success) setXpHistory(xpData.xp_history);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const StatCard = ({ icon: Icon, label, value, subValue, color }) => (
        <div className="stat-card" style={{ borderColor: color }}>
            <div className="stat-icon" style={{ background: `${color}20`, color }}>
                <Icon size={24} />
            </div>
            <div className="stat-info">
                <span className="stat-value">{value}</span>
                <span className="stat-label">{label}</span>
                {subValue && <span className="stat-sub">{subValue}</span>}
            </div>
        </div>
    );

    if (loading) {
        return (
            <div className="analytics-container loading">
                <Activity size={48} className="spin" />
                <p>Loading analytics...</p>
            </div>
        );
    }

    return (
        <div className="analytics-container">
            {/* Header */}
            <header className="analytics-header">
                <BarChart2 size={28} className="header-icon" />
                <div>
                    <h1>PERFORMANCE <span className="highlight">ANALYTICS</span></h1>
                    <p>Track your progress. Measure your growth. Dominate.</p>
                </div>
            </header>

            {/* Overview Stats */}
            <section className="stats-grid">
                <StatCard
                    icon={Zap}
                    label="Total XP"
                    value={overview?.xp_total?.toLocaleString() || 0}
                    subValue={`Level ${overview?.level || 1}`}
                    color="var(--primary-color)"
                />
                <StatCard
                    icon={Target}
                    label="Labs Completed"
                    value={overview?.labs?.completed || 0}
                    subValue={`${overview?.labs?.success_rate || 0}% success rate`}
                    color="var(--secondary-color)"
                />
                <StatCard
                    icon={Clock}
                    label="Avg Solve Time"
                    value={`${overview?.labs?.avg_solve_time_minutes || 0} min`}
                    color="#ffd700"
                />
                <StatCard
                    icon={Trophy}
                    label="Achievements"
                    value={overview?.achievements_count || 0}
                    color="#ff6b6b"
                />
                <StatCard
                    icon={CheckCircle}
                    label="Modules Done"
                    value={overview?.learning?.modules_completed || 0}
                    color="#4ecdc4"
                />
                <StatCard
                    icon={Calendar}
                    label="Day Streak"
                    value={overview?.streak_days || 0}
                    subValue="Keep it going!"
                    color="#a855f7"
                />
            </section>

            {/* XP Progress Chart */}
            <section className="chart-section">
                <h2><TrendingUp size={20} /> XP Progress (Last 30 Days)</h2>
                <div className="xp-chart">
                    {xpHistory.length > 0 ? (
                        <div className="bar-chart">
                            {xpHistory.map((day, i) => (
                                <div key={i} className="bar-wrapper">
                                    <div
                                        className="bar"
                                        style={{ height: `${Math.min((day.xp / 200) * 100, 100)}%` }}
                                        title={`${day.date}: ${day.xp} XP`}
                                    />
                                    <span className="bar-label">{new Date(day.date).getDate()}</span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="empty-chart">
                            <Activity size={32} />
                            <p>No XP data yet. Start completing labs!</p>
                        </div>
                    )}
                </div>
            </section>

            {/* Activity Heatmap */}
            <section className="chart-section">
                <h2><Calendar size={20} /> Activity Heatmap (90 Days)</h2>
                <div className="heatmap">
                    {Object.keys(activity).length > 0 ? (
                        <div className="heatmap-grid">
                            {Object.entries(activity).map(([date, count]) => (
                                <div
                                    key={date}
                                    className="heatmap-cell"
                                    style={{
                                        opacity: Math.min(0.3 + (count * 0.2), 1)
                                    }}
                                    title={`${date}: ${count} activities`}
                                />
                            ))}
                        </div>
                    ) : (
                        <div className="empty-chart">
                            <Calendar size={32} />
                            <p>No activity recorded yet.</p>
                        </div>
                    )}
                </div>
            </section>

            {/* Rank Display */}
            <section className="rank-section">
                <Award size={48} className="rank-icon" />
                <div className="rank-info">
                    <span className="rank-label">Current Rank</span>
                    <span className="rank-title">{overview?.rank || 'Script Kiddie'}</span>
                </div>
            </section>
        </div>
    );
};

export default AnalyticsDashboard;
