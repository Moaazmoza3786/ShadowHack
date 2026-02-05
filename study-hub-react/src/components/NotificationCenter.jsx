
import React, { useState, useEffect, useRef } from 'react';
import {
    Bell, Check, CheckCheck, X, Settings,
    Trophy, Users, Target, Zap, MessageSquare
} from 'lucide-react';
import './NotificationCenter.css';

const NotificationCenter = ({ userId = 1 }) => {
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef(null);

    useEffect(() => {
        fetchNotifications();
        // Poll for new notifications every 30 seconds
        const interval = setInterval(fetchNotifications, 30000);
        return () => clearInterval(interval);
    }, [userId]);

    useEffect(() => {
        const handleClickOutside = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const fetchNotifications = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/notifications/user/${userId}`);
            const data = await res.json();
            if (data.success) {
                setNotifications(data.notifications);
                setUnreadCount(data.unread_count);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const markAsRead = async (id) => {
        try {
            await fetch(`http://localhost:5000/api/notifications/${id}/read`, { method: 'POST' });
            setNotifications(prev =>
                prev.map(n => n.id === id ? { ...n, is_read: true } : n)
            );
            setUnreadCount(prev => Math.max(0, prev - 1));
        } catch (err) {
            console.error(err);
        }
    };

    const markAllRead = async () => {
        try {
            await fetch(`http://localhost:5000/api/notifications/user/${userId}/read-all`, { method: 'POST' });
            setNotifications(prev => prev.map(n => ({ ...n, is_read: true })));
            setUnreadCount(0);
        } catch (err) {
            console.error(err);
        }
    };

    const getIcon = (category) => {
        switch (category) {
            case 'achievement': return <Trophy size={18} />;
            case 'social': return <Users size={18} />;
            case 'mission': return <Target size={18} />;
            case 'xp': return <Zap size={18} />;
            default: return <MessageSquare size={18} />;
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

    return (
        <div className="notification-center" ref={dropdownRef}>
            <button
                className={`notification-trigger ${unreadCount > 0 ? 'has-unread' : ''}`}
                onClick={() => setIsOpen(!isOpen)}
            >
                <Bell size={20} />
                {unreadCount > 0 && (
                    <span className="notification-badge">{unreadCount > 9 ? '9+' : unreadCount}</span>
                )}
            </button>

            {isOpen && (
                <div className="notification-dropdown">
                    <header className="notification-header">
                        <h3>Notifications</h3>
                        <div className="header-actions">
                            {unreadCount > 0 && (
                                <button onClick={markAllRead} title="Mark all as read">
                                    <CheckCheck size={16} />
                                </button>
                            )}
                            <button title="Settings">
                                <Settings size={16} />
                            </button>
                        </div>
                    </header>

                    <div className="notification-list">
                        {notifications.length === 0 ? (
                            <div className="empty-state">
                                <Bell size={32} />
                                <p>No notifications yet</p>
                            </div>
                        ) : (
                            notifications.map(notif => (
                                <div
                                    key={notif.id}
                                    className={`notification-item ${!notif.is_read ? 'unread' : ''} type-${notif.type}`}
                                    onClick={() => !notif.is_read && markAsRead(notif.id)}
                                >
                                    <div className="notification-icon">
                                        {getIcon(notif.category)}
                                    </div>
                                    <div className="notification-content">
                                        <h4>{notif.title}</h4>
                                        {notif.message && <p>{notif.message}</p>}
                                        <span className="notification-time">{getTimeAgo(notif.created_at)}</span>
                                    </div>
                                    {!notif.is_read && (
                                        <button className="mark-read-btn" onClick={() => markAsRead(notif.id)}>
                                            <Check size={14} />
                                        </button>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default NotificationCenter;
