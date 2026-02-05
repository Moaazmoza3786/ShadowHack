
import React, { useState, useEffect } from 'react';
import {
    Users, Crown, Plus, Search, Shield, Zap,
    Trophy, TrendingUp, UserPlus, LogOut, Copy
} from 'lucide-react';
import './TeamsHub.css';

const TeamsHub = () => {
    const [teams, setTeams] = useState([]);
    const [leaderboard, setLeaderboard] = useState([]);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [newTeam, setNewTeam] = useState({ name: '', tag: '', description: '' });
    const [activeTab, setActiveTab] = useState('browse');

    useEffect(() => {
        fetchTeams();
        fetchLeaderboard();
    }, []);

    const fetchTeams = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/teams/');
            const data = await res.json();
            if (data.success) setTeams(data.teams);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchLeaderboard = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/teams/leaderboard');
            const data = await res.json();
            if (data.success) setLeaderboard(data.leaderboard);
        } catch (err) {
            console.error(err);
        }
    };

    const createTeam = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/teams/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ...newTeam, user_id: 1 }) // Replace with actual user
            });
            const data = await res.json();
            if (data.success) {
                setShowCreateModal(false);
                fetchTeams();
                fetchLeaderboard();
            }
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="teams-container">
            {/* Header */}
            <header className="teams-header">
                <div className="header-content">
                    <Users size={32} className="header-icon" />
                    <div>
                        <h1>SQUAD <span className="highlight">HQ</span></h1>
                        <p>Form alliances. Dominate challenges. Conquer together.</p>
                    </div>
                </div>
                <button className="create-btn" onClick={() => setShowCreateModal(true)}>
                    <Plus size={18} />
                    CREATE SQUAD
                </button>
            </header>

            {/* Tabs */}
            <div className="tabs">
                <button
                    className={`tab ${activeTab === 'browse' ? 'active' : ''}`}
                    onClick={() => setActiveTab('browse')}
                >
                    <Search size={16} />
                    Browse Squads
                </button>
                <button
                    className={`tab ${activeTab === 'leaderboard' ? 'active' : ''}`}
                    onClick={() => setActiveTab('leaderboard')}
                >
                    <Trophy size={16} />
                    Leaderboard
                </button>
            </div>

            {/* Content */}
            <main className="teams-content">
                {activeTab === 'browse' && (
                    <div className="teams-grid">
                        {teams.map(team => (
                            <div key={team.id} className="team-card">
                                <div className="team-header">
                                    <div className="team-avatar">
                                        <Shield size={24} />
                                    </div>
                                    <div className="team-info">
                                        <h3>[{team.tag}] {team.name}</h3>
                                        <span className="member-count">
                                            <Users size={14} /> {team.member_count} members
                                        </span>
                                    </div>
                                </div>
                                <div className="team-stats">
                                    <div className="stat">
                                        <Zap size={14} />
                                        <span>{team.total_xp.toLocaleString()} XP</span>
                                    </div>
                                    <div className="stat">
                                        <TrendingUp size={14} />
                                        <span>{team.wins}W / {team.losses}L</span>
                                    </div>
                                </div>
                                <button className="join-btn">
                                    <UserPlus size={16} />
                                    Join Squad
                                </button>
                            </div>
                        ))}
                        {teams.length === 0 && (
                            <div className="empty-state">
                                <Users size={48} />
                                <p>No squads found. Be the first to create one!</p>
                            </div>
                        )}
                    </div>
                )}

                {activeTab === 'leaderboard' && (
                    <div className="leaderboard">
                        <table>
                            <thead>
                                <tr>
                                    <th>Rank</th>
                                    <th>Squad</th>
                                    <th>XP</th>
                                    <th>W/L</th>
                                </tr>
                            </thead>
                            <tbody>
                                {leaderboard.map((team, i) => (
                                    <tr key={team.id} className={i < 3 ? `top-${i + 1}` : ''}>
                                        <td className="rank">
                                            {i === 0 && <Crown size={16} className="gold" />}
                                            {i === 1 && <Crown size={16} className="silver" />}
                                            {i === 2 && <Crown size={16} className="bronze" />}
                                            {i >= 3 && <span>#{i + 1}</span>}
                                        </td>
                                        <td className="team-name">[{team.tag}] {team.name}</td>
                                        <td className="xp">{team.total_xp.toLocaleString()}</td>
                                        <td className="wl">{team.wins}/{team.losses}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </main>

            {/* Create Modal */}
            {showCreateModal && (
                <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <h2><Plus size={20} /> Create New Squad</h2>
                        <div className="form-group">
                            <label>Squad Name</label>
                            <input
                                type="text"
                                placeholder="e.g., Shadow Legion"
                                value={newTeam.name}
                                onChange={(e) => setNewTeam({ ...newTeam, name: e.target.value })}
                            />
                        </div>
                        <div className="form-group">
                            <label>Tag (3-5 chars)</label>
                            <input
                                type="text"
                                placeholder="e.g., SHK"
                                maxLength={5}
                                value={newTeam.tag}
                                onChange={(e) => setNewTeam({ ...newTeam, tag: e.target.value.toUpperCase() })}
                            />
                        </div>
                        <div className="form-group">
                            <label>Description</label>
                            <textarea
                                placeholder="Tell others about your squad..."
                                value={newTeam.description}
                                onChange={(e) => setNewTeam({ ...newTeam, description: e.target.value })}
                            />
                        </div>
                        <div className="modal-actions">
                            <button className="cancel-btn" onClick={() => setShowCreateModal(false)}>Cancel</button>
                            <button className="submit-btn" onClick={createTeam}>Create Squad</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default TeamsHub;
