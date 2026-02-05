
import React, { useState, useEffect } from 'react';
import { Shield, Users, Activity, Ban, CheckCircle, Search, AlertTriangle, FileText } from 'lucide-react';
import './AdminDashboard.css';

const AdminDashboard = () => {
    const [activeTab, setActiveTab] = useState('users'); // users, logs, stats
    const [stats, setStats] = useState(null);
    const [users, setUsers] = useState([]);
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    // Fetch Stats
    useEffect(() => {
        fetchStats();
    }, []);

    // Fetch Users or Logs based on tab
    useEffect(() => {
        if (activeTab === 'users') fetchUsers();
        if (activeTab === 'logs') fetchLogs();
    }, [activeTab, searchTerm]);

    const fetchStats = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/admin/stats');
            const data = await res.json();
            if (data.success) setStats(data.stats);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchUsers = async () => {
        setLoading(true);
        try {
            const res = await fetch(`http://localhost:5000/api/admin/users?q=${searchTerm}`);
            const data = await res.json();
            if (data.success) setUsers(data.users);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const fetchLogs = async () => {
        setLoading(true);
        try {
            const res = await fetch('http://localhost:5000/api/admin/logs');
            const data = await res.json();
            if (data.success) setLogs(data.logs);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const toggleBan = async (userId) => {
        if (!window.confirm('Are you sure you want to ban/unban this user?')) return;
        try {
            const res = await fetch(`http://localhost:5000/api/admin/users/${userId}/ban`, { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                fetchUsers(); // Refresh list
                alert(data.message);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const changeRole = async (userId, newRole) => {
        try {
            const res = await fetch(`http://localhost:5000/api/admin/users/${userId}/role`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: newRole })
            });
            const data = await res.json();
            if (data.success) {
                fetchUsers();
            }
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="admin-dashboard">
            <header className="admin-header">
                <div className="header-title">
                    <Shield size={32} className="admin-icon" />
                    <h1>SYSTEM <span className="highlight">ADMINISTRATION</span></h1>
                </div>
                <div className="system-status">
                    <div className="status-indicator online"></div>
                    <span>SYSTEM ONLINE</span>
                </div>
            </header>

            {/* Stats Cards */}
            {stats && (
                <div className="admin-stats-grid">
                    <div className="stat-card">
                        <Users size={24} />
                        <div className="stat-info">
                            <h3>Total Users</h3>
                            <p>{stats.total_users}</p>
                        </div>
                    </div>
                    <div className="stat-card warning">
                        <Ban size={24} />
                        <div className="stat-info">
                            <h3>Banned Users</h3>
                            <p>{stats.banned_users}</p>
                        </div>
                    </div>
                    <div className="stat-card success">
                        <Shield size={24} />
                        <div className="stat-info">
                            <h3>Admins</h3>
                            <p>{stats.admins}</p>
                        </div>
                    </div>
                    <div className="stat-card info">
                        <Activity size={24} />
                        <div className="stat-info">
                            <h3>Active Today</h3>
                            <p>{stats.active_today}</p>
                        </div>
                    </div>
                </div>
            )}

            {/* Tabs */}
            <div className="admin-tabs">
                <button
                    className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
                    onClick={() => setActiveTab('users')}
                >
                    <Users size={18} /> User Management
                </button>
                <button
                    className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
                    onClick={() => setActiveTab('logs')}
                >
                    <FileText size={18} /> System Logs
                </button>
            </div>

            {/* Content Area */}
            <div className="admin-content">
                {activeTab === 'users' && (
                    <div className="users-manager">
                        <div className="table-controls">
                            <div className="search-box">
                                <Search size={18} />
                                <input
                                    type="text"
                                    placeholder="Search users..."
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                />
                            </div>
                        </div>

                        <div className="data-table-wrapper">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>User</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                        <th>Joined</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {loading ? (
                                        <tr><td colSpan="6" className="text-center">Loading...</td></tr>
                                    ) : users.map(user => (
                                        <tr key={user.id} className={user.is_banned ? 'banned-row' : ''}>
                                            <td>
                                                <div className="user-cell">
                                                    <span className="username">{user.username}</span>
                                                </div>
                                            </td>
                                            <td>{user.email}</td>
                                            <td>
                                                <select
                                                    value={user.role}
                                                    onChange={(e) => changeRole(user.id, e.target.value)}
                                                    className={`role-select role-${user.role}`}
                                                >
                                                    <option value="user">User</option>
                                                    <option value="moderator">Moderator</option>
                                                    <option value="admin">Admin</option>
                                                </select>
                                            </td>
                                            <td>
                                                {user.is_banned ? (
                                                    <span className="status-badge banned">BANNED</span>
                                                ) : (
                                                    <span className="status-badge active">ACTIVE</span>
                                                )}
                                            </td>
                                            <td>{new Date(user.joined).toLocaleDateString()}</td>
                                            <td>
                                                <button
                                                    className={`action-btn ${user.is_banned ? 'unban' : 'ban'}`}
                                                    onClick={() => toggleBan(user.id)}
                                                >
                                                    {user.is_banned ? 'Unban' : 'Ban'}
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {activeTab === 'logs' && (
                    <div className="logs-viewer">
                        {loading ? (
                            <div className="loading">Loading logs...</div>
                        ) : logs.length > 0 ? (
                            <div className="logs-list">
                                {logs.map(log => (
                                    <div key={log.id} className="log-entry">
                                        <span className="log-time">{new Date(log.created_at).toLocaleString()}</span>
                                        <span className={`log-type type-${log.activity_type}`}>{log.activity_type}</span>
                                        <span className="log-user">{log.username}</span>
                                        <span className="log-content">{log.content}</span>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="empty-state">No system logs found.</div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminDashboard;
