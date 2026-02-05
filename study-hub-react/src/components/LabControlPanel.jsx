
import React, { useState, useEffect } from 'react';
import { Play, Square, RefreshCw, Terminal, Clock, Wifi } from 'lucide-react';
import './LabControlPanel.css';

const LabControlPanel = ({ labId, userId = 1, onStatusChange }) => {
    const [status, setStatus] = useState('stopped'); // stopped, building, running
    const [connection, setConnection] = useState(null);
    const [loading, setLoading] = useState(false);
    const [timeLeft, setTimeLeft] = useState(null);

    useEffect(() => {
        checkStatus();
        const interval = setInterval(checkStatus, 5000);
        return () => clearInterval(interval);
    }, [labId]);

    const checkStatus = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/labs/${labId}/status?user_id=${userId}`);
            const data = await res.json();
            if (data.success && data.status) {
                setStatus(data.status.state);
                if (data.status.ip) {
                    setConnection(data.status);
                }
                if (onStatusChange) onStatusChange(data.status.state);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const handleStart = async () => {
        setLoading(true);
        setStatus('building');
        try {
            const res = await fetch(`http://localhost:5000/api/labs/${labId}/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });
            const data = await res.json();
            if (data.success) {
                checkStatus(); // Immediate check
            } else {
                alert('Failed to start lab: ' + data.error);
                setStatus('stopped');
            }
        } catch (err) {
            console.error(err);
            setStatus('stopped');
        } finally {
            setLoading(false);
        }
    };

    const handleStop = async () => {
        if (!window.confirm('Are you sure you want to stop this lab? Progress will be lost.')) return;
        setLoading(true);
        try {
            await fetch(`http://localhost:5000/api/labs/${labId}/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });
            setStatus('stopped');
            setConnection(null);
            if (onStatusChange) onStatusChange('stopped');
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="lab-control-panel">
            <div className="status-section">
                <div className={`status-indicator ${status}`}>
                    <div className="dot"></div>
                    <span>{status.toUpperCase()}</span>
                </div>

                {status === 'running' && connection && (
                    <div className="connection-info">
                        <div className="info-item">
                            <span className="label">TARGET IP:</span>
                            <span className="value">{connection.ip}</span>
                        </div>
                        {connection.expiry && (
                            <div className="info-item">
                                <Clock size={14} />
                                <span className="value">
                                    {Math.round((new Date(connection.expiry) - new Date()) / 60000)}m left
                                </span>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <div className="control-actions">
                {status === 'stopped' && (
                    <button
                        className="control-btn start"
                        onClick={handleStart}
                        disabled={loading}
                    >
                        {loading ? <RefreshCw className="spin" size={18} /> : <Play size={18} />}
                        <span>START MACHINE</span>
                    </button>
                )}

                {status === 'running' && (
                    <>
                        <button className="control-btn terminal">
                            <Terminal size={18} />
                            <span>WEB TERMINAL</span>
                        </button>
                        <button
                            className="control-btn stop"
                            onClick={handleStop}
                            disabled={loading}
                        >
                            <Square size={18} />
                            <span>STOP</span>
                        </button>
                    </>
                )}

                {status === 'building' && (
                    <div className="building-loader">
                        <RefreshCw className="spin" size={20} />
                        <span>Provisioning Environment...</span>
                    </div>
                )}
            </div>

            <div className="vpn-status">
                <Wifi size={16} className={status === 'running' ? 'connected' : ''} />
                <span>VPN: {status === 'running' ? 'Connected' : 'Disconnected'}</span>
            </div>
        </div>
    );
};

export default LabControlPanel;
