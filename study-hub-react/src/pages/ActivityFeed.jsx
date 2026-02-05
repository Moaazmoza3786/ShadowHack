
import React, { useState, useEffect } from 'react';
import {
    Activity, Trophy, Users, Target, Zap, Code,
    Award, TrendingUp
} from 'lucide-react';
import './ActivityFeed.css';

const ActivityFeed = () => {
    const [activities, setActivities] = useState([]);
    const [filter, setFilter] = useState('all');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchActivities();
    }, []);

    const fetchActivities = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/activity/global?limit=50');
            const data = await res.json();
            if (data.success) setActivities(data.activities);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const getActivityIcon = (type) => {
        switch (type) {
            case 'lab_complete': return <Code size={18} />;
            case 'achievement': return <Trophy size={18} />;
            case 'level_up': return <TrendingUp size={18} />;
            case 'team_join': return <Users size={18} />;
            case 'mission_complete': return <Target size={18} />;
            default: return <Activity size={18} />;
        }
    };

    const getActivityColor = (type) => {
        switch (type) {
            case 'lab_complete': return 'var(--secondary-color)';
            case 'achievement': return '#ffd700';
            case 'level_up': return 'var(--primary-color)';
            case 'team_join': return '#a855f7';
            case 'mission_complete': return '#ff6b6b';
            default: return 'var(--text-secondary)';
        }
    };

    const getTimeAgo = (dateStr) => {
        const date = new Date(dateStr);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);

        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    };

    const filteredActivities = filter === 'all'
        ? activities
        : activities.filter(a => a.activity_type === filter);

    return (
        <div className="feed-container">
            <header className="feed-header">
                <Activity size={28} className="header-icon" />
                <div>
                    <h1>ACTIVITY <span className="highlight">FEED</span></h1>
                    <p>See what the community is achieving.</p>
                </div>
            </header>

            <div className="feed-filters">
                {[
                    { key: 'all', label: 'All Activity' },
                    { key: 'lab_complete', label: 'Labs' },
                    { key: 'achievement', label: 'Achievements' },
                    { key: 'level_up', label: 'Level Ups' },
                    { key: 'team_join', label: 'Teams' }
                ].map(f => (
                    <button
                        key={f.key}
                        className={`filter-btn ${filter === f.key ? 'active' : ''}`}
                        onClick={() => setFilter(f.key)}
                    >
                        {f.label}
                    </button>
                ))}
            </div>

            <div className="feed-timeline">
                {filteredActivities.map(activity => (
                    <div key={activity.id} className="activity-item">
                        <div
                            className="activity-icon"
                            style={{ background: `${getActivityColor(activity.activity_type)}20`, color: getActivityColor(activity.activity_type) }}
                        >
                            {getActivityIcon(activity.activity_type)}
                        </div>
                        <div className="activity-content">
                            <div className="activity-header">
                                <img
                                    src={activity.avatar_url || `https://api.dicebear.com/7.x/cyber/svg?seed=${activity.username}`}
                                    alt=""
                                    className="user-avatar"
                                />
                                <span className="username">{activity.username || 'Anonymous'}</span>
                                <span className="activity-time">{getTimeAgo(activity.created_at)}</span>
                            </div>
                            <p className="activity-text">{activity.content}</p>
                        </div>
                    </div>
                ))}

                {filteredActivities.length === 0 && !loading && (
                    <div className="empty-state">
                        <Activity size={48} />
                        <p>No activity to show</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ActivityFeed;
