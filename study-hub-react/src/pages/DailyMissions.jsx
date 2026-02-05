
import React, { useState, useEffect } from 'react';
import {
    Target, CheckCircle, Clock, Zap, Gift,
    Calendar, TrendingUp, Award
} from 'lucide-react';
import './DailyMissions.css';

const DailyMissions = () => {
    const [missions, setMissions] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchMissions();
    }, []);

    const fetchMissions = async () => {
        try {
            // Replace 1 with actual user ID from context
            const res = await fetch('http://localhost:5000/api/missions/user/1');
            const data = await res.json();
            if (data.success) setMissions(data.missions);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const getMissionTypeIcon = (type) => {
        switch (type) {
            case 'daily': return <Calendar size={14} />;
            case 'weekly': return <TrendingUp size={14} />;
            case 'event': return <Gift size={14} />;
            default: return <Target size={14} />;
        }
    };

    const getMissionTypeClass = (type) => {
        switch (type) {
            case 'daily': return 'type-daily';
            case 'weekly': return 'type-weekly';
            case 'event': return 'type-event';
            default: return '';
        }
    };

    return (
        <div className="missions-container">
            <header className="missions-header">
                <Target size={28} className="header-icon" />
                <div>
                    <h1>DAILY <span className="highlight">MISSIONS</span></h1>
                    <p>Complete objectives. Earn rewards. Level up.</p>
                </div>
            </header>

            <div className="missions-grid">
                {missions.map(mission => (
                    <div
                        key={mission.id}
                        className={`mission-card ${mission.is_completed ? 'completed' : ''}`}
                    >
                        <div className="mission-type">
                            <span className={`type-badge ${getMissionTypeClass(mission.mission_type)}`}>
                                {getMissionTypeIcon(mission.mission_type)}
                                {mission.mission_type.toUpperCase()}
                            </span>
                            {mission.is_completed && (
                                <CheckCircle size={20} className="completed-icon" />
                            )}
                        </div>

                        <h3>{mission.title}</h3>
                        <p className="mission-desc">{mission.description}</p>

                        <div className="progress-section">
                            <div className="progress-bar">
                                <div
                                    className="progress-fill"
                                    style={{ width: `${Math.min((mission.user_progress / mission.objective_target) * 100, 100)}%` }}
                                />
                            </div>
                            <span className="progress-text">
                                {mission.user_progress} / {mission.objective_target}
                            </span>
                        </div>

                        <div className="mission-reward">
                            <Zap size={16} />
                            <span>+{mission.xp_reward} XP</span>
                        </div>

                        {mission.expires_at && (
                            <div className="mission-expiry">
                                <Clock size={14} />
                                <span>Expires: {new Date(mission.expires_at).toLocaleDateString()}</span>
                            </div>
                        )}
                    </div>
                ))}

                {missions.length === 0 && !loading && (
                    <div className="empty-state">
                        <Award size={48} />
                        <p>No active missions. Check back soon!</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default DailyMissions;
