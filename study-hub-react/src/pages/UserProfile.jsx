
import React, { useState, useEffect } from 'react';
import {
    User, Trophy, Target, Zap, Calendar, MapPin,
    Globe, Edit2, Shield, Settings, Award, Code,
    TrendingUp, Star
} from 'lucide-react';
import './UserProfile.css';

const UserProfile = ({ userId = 1 }) => {
    const [profile, setProfile] = useState(null);
    const [isEditing, setIsEditing] = useState(false);
    const [editData, setEditData] = useState({});
    const [activeTab, setActiveTab] = useState('overview');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchProfile();
    }, [userId]);

    const fetchProfile = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/profile/${userId}`);
            const data = await res.json();
            if (data.success) {
                setProfile(data.profile);
                setEditData({
                    username: data.profile.username,
                    bio: data.profile.bio || '',
                    location: data.profile.location || '',
                    website: data.profile.website || ''
                });
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        try {
            await fetch(`http://localhost:5000/api/profile/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(editData)
            });
            fetchProfile();
            setIsEditing(false);
        } catch (err) {
            console.error(err);
        }
    };

    const getRankColor = (rank) => {
        const colors = {
            'Script Kiddie': '#888',
            'Hacker': '#00ff9d',
            'Elite Hacker': '#00f3ff',
            'Master': '#ffd700',
            'Legend': '#ff00ff'
        };
        return colors[rank] || '#00ff9d';
    };

    if (loading || !profile) {
        return (
            <div className="profile-container loading">
                <User size={48} className="spin" />
                <p>Loading profile...</p>
            </div>
        );
    }

    return (
        <div className="profile-container">
            {/* Header Section */}
            <div className="profile-header">
                <div className="avatar-section">
                    <img
                        src={profile.avatar_url || `https://api.dicebear.com/7.x/cyber/svg?seed=${profile.username}`}
                        alt={profile.username}
                        className="profile-avatar"
                    />
                    <div className="level-badge">LVL {profile.stats.level}</div>
                </div>

                <div className="profile-info">
                    <div className="name-section">
                        {isEditing ? (
                            <input
                                type="text"
                                value={editData.username}
                                onChange={e => setEditData({ ...editData, username: e.target.value })}
                                className="edit-input"
                            />
                        ) : (
                            <h1>{profile.username}</h1>
                        )}
                        <span
                            className="rank-badge"
                            style={{ background: `${getRankColor(profile.stats.rank)}20`, color: getRankColor(profile.stats.rank) }}
                        >
                            {profile.stats.rank}
                        </span>
                    </div>

                    {isEditing ? (
                        <textarea
                            value={editData.bio}
                            onChange={e => setEditData({ ...editData, bio: e.target.value })}
                            placeholder="Write your bio..."
                            className="edit-textarea"
                        />
                    ) : (
                        <p className="bio">{profile.bio || 'No bio yet'}</p>
                    )}

                    <div className="profile-meta">
                        {(isEditing || profile.location) && (
                            <span>
                                <MapPin size={14} />
                                {isEditing ? (
                                    <input
                                        type="text"
                                        value={editData.location}
                                        onChange={e => setEditData({ ...editData, location: e.target.value })}
                                        placeholder="Location"
                                        className="edit-input-small"
                                    />
                                ) : profile.location}
                            </span>
                        )}
                        {(isEditing || profile.website) && (
                            <span>
                                <Globe size={14} />
                                {isEditing ? (
                                    <input
                                        type="text"
                                        value={editData.website}
                                        onChange={e => setEditData({ ...editData, website: e.target.value })}
                                        placeholder="Website"
                                        className="edit-input-small"
                                    />
                                ) : (
                                    <a href={profile.website} target="_blank" rel="noopener noreferrer">
                                        {profile.website}
                                    </a>
                                )}
                            </span>
                        )}
                        <span>
                            <Calendar size={14} />
                            Joined {new Date(profile.created_at).toLocaleDateString()}
                        </span>
                    </div>
                </div>

                <div className="profile-actions">
                    {isEditing ? (
                        <>
                            <button className="save-btn" onClick={handleSave}>Save</button>
                            <button className="cancel-btn" onClick={() => setIsEditing(false)}>Cancel</button>
                        </>
                    ) : (
                        <button className="edit-btn" onClick={() => setIsEditing(true)}>
                            <Edit2 size={16} />
                            Edit Profile
                        </button>
                    )}
                </div>
            </div>

            {/* Stats Cards */}
            <div className="stats-grid">
                <div className="stat-card">
                    <Zap size={24} className="stat-icon xp" />
                    <div className="stat-value">{profile.stats.xp.toLocaleString()}</div>
                    <div className="stat-label">Total XP</div>
                </div>
                <div className="stat-card">
                    <Code size={24} className="stat-icon labs" />
                    <div className="stat-value">{profile.stats.labs_completed}</div>
                    <div className="stat-label">Labs Completed</div>
                </div>
                <div className="stat-card">
                    <Trophy size={24} className="stat-icon achievements" />
                    <div className="stat-value">{profile.stats.achievements_count}</div>
                    <div className="stat-label">Achievements</div>
                </div>
                <div className="stat-card">
                    <TrendingUp size={24} className="stat-icon streak" />
                    <div className="stat-value">{profile.stats.streak_days}</div>
                    <div className="stat-label">Day Streak</div>
                </div>
            </div>

            {/* Team Display */}
            {profile.team && (
                <div className="team-card">
                    <Shield size={20} />
                    <span className="team-tag">[{profile.team.tag}]</span>
                    <span className="team-name">{profile.team.name}</span>
                    <span className="team-role">{profile.team.role}</span>
                </div>
            )}

            {/* Tabs */}
            <div className="profile-tabs">
                {[
                    { key: 'overview', label: 'Overview', icon: User },
                    { key: 'achievements', label: 'Achievements', icon: Award },
                    { key: 'settings', label: 'Settings', icon: Settings }
                ].map(tab => (
                    <button
                        key={tab.key}
                        className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab.key)}
                    >
                        <tab.icon size={16} />
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <div className="tab-content">
                {activeTab === 'achievements' && (
                    <div className="achievements-grid">
                        {profile.achievements.map((ach, i) => (
                            <div key={i} className="achievement-card">
                                <div className="achievement-icon">
                                    <Star size={24} />
                                </div>
                                <div className="achievement-info">
                                    <h4>{ach.name || 'Achievement'}</h4>
                                    <span>Earned {new Date(ach.earned_at).toLocaleDateString()}</span>
                                </div>
                            </div>
                        ))}
                        {profile.achievements.length === 0 && (
                            <p className="empty-text">No achievements yet. Start completing labs!</p>
                        )}
                    </div>
                )}

                {activeTab === 'settings' && (
                    <div className="settings-section">
                        <p className="settings-note">Visit the Settings page for full options.</p>
                    </div>
                )}

                {activeTab === 'overview' && (
                    <div className="overview-section">
                        <p>Complete more labs and challenges to build your profile!</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default UserProfile;
