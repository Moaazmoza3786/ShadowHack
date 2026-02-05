
import React, { useState, useEffect } from 'react';
import {
    Terminal, Shield, Zap, Search, Activity,
    Cpu, Target, AlertTriangle, ChevronRight, Play, CheckCircle
} from 'lucide-react';
import './CyberOpsDashboard.css';

const CyberOpsDashboard = () => {
    const [target, setTarget] = useState('');
    const [activeTasks, setActiveTasks] = useState([]);
    const [taskOutput, setTaskOutput] = useState('');
    const [aiAnalysis, setAiAnalysis] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    const startScan = async () => {
        if (!target) return;
        setIsScanning(true);
        try {
            const res = await fetch('http://localhost:5000/api/automation/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, type: 'nmap', args: '-sV' })
            });
            const data = await res.json();
            if (data.success) {
                pollTaskStatus(data.task_id);
            }
        } catch (err) {
            console.error(err);
            setIsScanning(false);
        }
    };

    const pollTaskStatus = async (taskId) => {
        const interval = setInterval(async () => {
            try {
                const res = await fetch(`http://localhost:5000/api/automation/tasks/${taskId}`);
                const data = await res.json();
                if (data.status === 'completed') {
                    clearInterval(interval);
                    setTaskOutput(data.output);
                    setIsScanning(false);
                    analyzeResult(data.output);
                } else if (data.status === 'failed' || data.status === 'error') {
                    clearInterval(interval);
                    setIsScanning(false);
                }
            } catch (err) {
                clearInterval(interval);
                setIsScanning(false);
            }
        }, 2000);
    };

    const analyzeResult = async (output) => {
        setIsAnalyzing(true);
        try {
            const res = await fetch('http://localhost:5000/api/automation/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ output })
            });
            const data = await res.json();
            if (data.success) {
                setAiAnalysis(data.analysis);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setIsAnalyzing(false);
        }
    };

    return (
        <div className="cyber-ops-container">
            {/* Header */}
            <header className="ops-header">
                <div className="status-badge live">
                    <Activity size={14} className="pulse" />
                    SYSTEM_LIVE
                </div>
                <h1>CyberOps <span className="highlight">Command Center</span></h1>
                <div className="ops-meta">
                    <span>OPERATOR: Moaaz</span>
                    <span className="divider">|</span>
                    <span>TIER: Professional</span>
                </div>
            </header>

            <div className="ops-grid">
                {/* Left Column: Target & Scan */}
                <div className="ops-panel target-panel">
                    <div className="panel-header">
                        <Target size={18} />
                        <h2>Target Acquisition</h2>
                    </div>
                    <div className="panel-body">
                        <div className="input-group">
                            <input
                                type="text"
                                placeholder="Target IP / Domain (e.g., 10.10.11.200)"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                            />
                            <button
                                className={`scan-btn ${isScanning ? 'loading' : ''}`}
                                onClick={startScan}
                                disabled={isScanning || !target}
                            >
                                {isScanning ? <Activity className="spin" /> : <Play size={18} />}
                                {isScanning ? 'SCANNING...' : 'START_SCAN'}
                            </button>
                        </div>

                        <div className="scan-options">
                            <label><input type="checkbox" defaultChecked /> Stealth Mode</label>
                            <label><input type="checkbox" defaultChecked /> Service Detection</label>
                            <label><input type="checkbox" /> OS Fingerprinting</label>
                        </div>
                    </div>

                    <div className="terminal-window">
                        <div className="terminal-header">
                            <Terminal size={14} />
                            <span>CMD_OUTPUT_LOG</span>
                        </div>
                        <pre className="terminal-content">
                            {taskOutput || "Waiting for task execution..."}
                            {isScanning && "\n[+] Initializing Nmap engine...\n[+] Parallel DNS resolution...\n[+] Scanning 1000 ports..."}
                        </pre>
                    </div>
                </div>

                {/* Right Column: AI Red Team Analysis */}
                <div className="ops-panel ai-panel">
                    <div className="panel-header">
                        <Cpu size={18} className="ai-accent" />
                        <h2>AI Red Team Analysis</h2>
                        {isAnalyzing && <Zap size={14} className="spin ai-accent" />}
                    </div>
                    <div className="panel-body">
                        {!aiAnalysis && !isAnalyzing && (
                            <div className="empty-state">
                                <AlertTriangle size={32} />
                                <p>No active scan data to analyze.</p>
                            </div>
                        )}

                        {isAnalyzing && (
                            <div className="analysis-loading">
                                <div className="progress-bar-container">
                                    <div className="progress-bar-fill"></div>
                                </div>
                                <p>AI Engine extracting vulnerabilities...</p>
                            </div>
                        )}

                        {aiAnalysis && (
                            <div className="analysis-results">
                                <section className="analysis-section critical">
                                    <h3><Shield size={16} /> Critical Findings</h3>
                                    <ul>
                                        {aiAnalysis.critical_findings?.map((f, i) => (
                                            <li key={i}>{f}</li>
                                        ))}
                                    </ul>
                                </section>

                                <section className="analysis-section exploits">
                                    <h3><Zap size={16} /> Suggested Exploits</h3>
                                    {aiAnalysis.suggested_exploits?.map((ex, i) => (
                                        <div key={i} className="exploit-card">
                                            <span className="exploit-name">{ex}</span>
                                            <button className="copy-btn">PREPARE_PAYLOAD</button>
                                        </div>
                                    ))}
                                </section>

                                <section className="analysis-section next-steps">
                                    <h3><ChevronRight size={16} /> Next Strategic Steps</h3>
                                    <ul>
                                        {aiAnalysis.next_steps?.map((step, i) => (
                                            <li key={i}>{step}</li>
                                        ))}
                                    </ul>
                                </section>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CyberOpsDashboard;
