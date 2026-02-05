
import React, { useState, useEffect } from 'react';
import {
    Settings, Bell, Lock, Palette, Globe, Shield,
    Eye, EyeOff, Save, Check, X
} from 'lucide-react';
import './SettingsPanel.css';

const SettingsPanel = ({ userId = 1 }) => {
    const [settings, setSettings] = useState(null);
    const [saving, setSaving] = useState(false);
    const [saved, setSaved] = useState(false);
    const [activeSection, setActiveSection] = useState('notifications');

    useEffect(() => {
        fetchSettings();
    }, [userId]);

    const fetchSettings = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/profile/${userId}/settings`);
            const data = await res.json();
            if (data.success) setSettings(data.settings);
        } catch (err) {
            console.error(err);
        }
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            await fetch(`http://localhost:5000/api/profile/${userId}/settings`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            setSaved(true);
            setTimeout(() => setSaved(false), 2000);
        } catch (err) {
            console.error(err);
        } finally {
            setSaving(false);
        }
    };

    const updateSetting = (category, key, value) => {
        setSettings(prev => ({
            ...prev,
            [category]: {
                ...prev[category],
                [key]: value
            }
        }));
    };

    const Toggle = ({ value, onChange, label }) => (
        <div className="setting-row">
            <span className="setting-label">{label}</span>
            <button
                className={`toggle-switch ${value ? 'active' : ''}`}
                onClick={() => onChange(!value)}
            >
                <div className="toggle-thumb" />
            </button>
        </div>
    );

    if (!settings) {
        return (
            <div className="settings-container loading">
                <Settings size={48} className="spin" />
                <p>Loading settings...</p>
            </div>
        );
    }

    return (
        <div className="settings-container">
            <header className="settings-header">
                <Settings size={28} className="header-icon" />
                <div>
                    <h1>ACCOUNT <span className="highlight">SETTINGS</span></h1>
                    <p>Manage your preferences and privacy.</p>
                </div>
            </header>

            <div className="settings-layout">
                {/* Sidebar */}
                <nav className="settings-nav">
                    {[
                        { key: 'notifications', icon: Bell, label: 'Notifications' },
                        { key: 'privacy', icon: Shield, label: 'Privacy' },
                        { key: 'appearance', icon: Palette, label: 'Appearance' },
                        { key: 'security', icon: Lock, label: 'Security' }
                    ].map(item => (
                        <button
                            key={item.key}
                            className={`nav-item ${activeSection === item.key ? 'active' : ''}`}
                            onClick={() => setActiveSection(item.key)}
                        >
                            <item.icon size={18} />
                            {item.label}
                        </button>
                    ))}
                </nav>

                {/* Content */}
                <div className="settings-content">
                    {activeSection === 'notifications' && (
                        <section className="settings-section">
                            <h2><Bell size={20} /> Notification Preferences</h2>
                            <Toggle
                                value={settings.notifications.email_notifications}
                                onChange={v => updateSetting('notifications', 'email_notifications', v)}
                                label="Email Notifications"
                            />
                            <Toggle
                                value={settings.notifications.push_notifications}
                                onChange={v => updateSetting('notifications', 'push_notifications', v)}
                                label="Push Notifications"
                            />
                            <Toggle
                                value={settings.notifications.achievement_alerts}
                                onChange={v => updateSetting('notifications', 'achievement_alerts', v)}
                                label="Achievement Alerts"
                            />
                            <Toggle
                                value={settings.notifications.team_updates}
                                onChange={v => updateSetting('notifications', 'team_updates', v)}
                                label="Team Updates"
                            />
                        </section>
                    )}

                    {activeSection === 'privacy' && (
                        <section className="settings-section">
                            <h2><Shield size={20} /> Privacy Settings</h2>
                            <Toggle
                                value={settings.privacy.profile_public}
                                onChange={v => updateSetting('privacy', 'profile_public', v)}
                                label="Public Profile"
                            />
                            <Toggle
                                value={settings.privacy.show_activity}
                                onChange={v => updateSetting('privacy', 'show_activity', v)}
                                label="Show Activity Feed"
                            />
                            <Toggle
                                value={settings.privacy.show_stats}
                                onChange={v => updateSetting('privacy', 'show_stats', v)}
                                label="Show Stats on Profile"
                            />
                        </section>
                    )}

                    {activeSection === 'appearance' && (
                        <section className="settings-section">
                            <h2><Palette size={20} /> Appearance</h2>
                            <div className="setting-row">
                                <span className="setting-label">Theme</span>
                                <select
                                    value={settings.appearance.theme}
                                    onChange={e => updateSetting('appearance', 'theme', e.target.value)}
                                    className="setting-select"
                                >
                                    <option value="dark">Dark Mode</option>
                                    <option value="light">Light Mode</option>
                                    <option value="cyber">Cyberpunk</option>
                                </select>
                            </div>
                            <div className="setting-row">
                                <span className="setting-label">Language</span>
                                <select
                                    value={settings.appearance.language}
                                    onChange={e => updateSetting('appearance', 'language', e.target.value)}
                                    className="setting-select"
                                >
                                    <option value="en">English</option>
                                    <option value="ar">العربية</option>
                                </select>
                            </div>
                        </section>
                    )}

                    {activeSection === 'security' && (
                        <section className="settings-section">
                            <h2><Lock size={20} /> Security</h2>
                            <div className="security-option">
                                <h4>Change Password</h4>
                                <p>Update your password regularly for better security.</p>
                                <button className="action-btn">Change Password</button>
                            </div>
                            <div className="security-option">
                                <h4>Two-Factor Authentication</h4>
                                <p>Add an extra layer of security to your account.</p>
                                <button className="action-btn">Enable 2FA</button>
                            </div>
                        </section>
                    )}

                    <button
                        className={`save-settings-btn ${saved ? 'saved' : ''}`}
                        onClick={handleSave}
                        disabled={saving}
                    >
                        {saved ? (
                            <>
                                <Check size={18} />
                                Saved!
                            </>
                        ) : (
                            <>
                                <Save size={18} />
                                {saving ? 'Saving...' : 'Save Changes'}
                            </>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default SettingsPanel;
