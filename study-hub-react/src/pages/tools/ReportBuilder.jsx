
import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { FileText, Save, Download, Plus, Trash2, Mic, AlertTriangle, CheckCircle2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import './ReportBuilder.css';

const ReportBuilder = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();

    // Initial State
    const [report, setReport] = useState({
        title: 'New Assessment Report',
        lab_id: searchParams.get('lab_id') || '',
        executive_summary: '',
        status: 'draft',
        findings: []
    });

    const [activeTab, setActiveTab] = useState('editor'); // editor, preview
    const [selectedFindingIndex, setSelectedFindingIndex] = useState(null);
    const [loading, setLoading] = useState(false);
    const [saved, setSaved] = useState(false);

    // Finding Templates
    const templates = {
        sqli: {
            title: 'SQL Injection in Login Parameter',
            severity: 'High',
            description: 'The application is vulnerable to SQL Injection via the `username` parameter...',
            remediation: 'Use parameterized queries (Prepared Statements)...'
        },
        xss: {
            title: 'Reflected Cross-Site Scripting (XSS)',
            severity: 'Medium',
            description: 'Reflected XSS occurs when an application receives data in an HTTP request...',
            remediation: 'Sanitize all user input and use Content Security Policy (CSP)...'
        }
    };

    const addFinding = (templateKey = null) => {
        const template = templateKey ? templates[templateKey] : {
            title: 'New Finding',
            severity: 'Low',
            description: '',
            remediation: '',
            evidence: ''
        };

        setReport(prev => ({
            ...prev,
            findings: [...prev.findings, template]
        }));
        setSelectedFindingIndex(report.findings.length); // Select the new one
    };

    const updateFinding = (index, field, value) => {
        const updatedFindings = [...report.findings];
        updatedFindings[index] = { ...updatedFindings[index], [field]: value };
        setReport(prev => ({ ...prev, findings: updatedFindings }));
        setSaved(false);
    };

    const removeFinding = (index) => {
        const updatedFindings = report.findings.filter((_, i) => i !== index);
        setReport(prev => ({ ...prev, findings: updatedFindings }));
        setSelectedFindingIndex(null);
        setSaved(false);
    };

    const handleSave = async () => {
        setLoading(true);
        try {
            // In real app, POST to /api/reports/create or PUT /api/reports/:id
            await new Promise(resolve => setTimeout(resolve, 1000)); // Mock API delay
            setSaved(true);
            setTimeout(() => setSaved(false), 2000);
        } catch (err) {
            console.error('Failed to save report', err);
        } finally {
            setLoading(false);
        }
    };

    const handleExport = () => {
        alert("Generating PDF... (Simulation)");
        // window.open(`${apiUrl}/reports/${report.id}/export`, '_blank');
    };

    return (
        <div className="report-builder-container">
            <header className="report-header">
                <div className="header-left">
                    <div className="icon-wrapper">
                        <FileText size={20} />
                    </div>
                    <div>
                        <input
                            type="text"
                            className="report-title-input"
                            value={report.title}
                            onChange={(e) => setReport({ ...report, title: e.target.value })}
                        />
                        <div className="report-meta">
                            <span>Status: {report.status.toUpperCase()}</span>
                            <span>•</span>
                            <span>{new Date().toLocaleDateString()}</span>
                        </div>
                    </div>
                </div>

                <div className="header-actions">
                    <button className="btn-secondary" onClick={handleSave} disabled={loading}>
                        {saved ? <CheckCircle2 size={16} /> : <Save size={16} />}
                        {saved ? 'Saved' : 'Save Draft'}
                    </button>
                    <button className="btn-primary" onClick={handleExport}>
                        <Download size={16} /> Export PDF
                    </button>
                </div>
            </header>

            <div className="report-workspace">
                {/* Left Sidebar: Outline */}
                <aside className="report-sidebar">
                    <h3>Report Outline</h3>
                    <div
                        className={`outline-item ${selectedFindingIndex === null ? 'active' : ''}`}
                        onClick={() => setSelectedFindingIndex(null)}
                    >
                        <span>Executive Summary</span>
                    </div>

                    <div className="findings-list">
                        <div className="findings-header">
                            <h4>Findings</h4>
                            <button className="icon-btn" onClick={() => addFinding()}><Plus size={14} /></button>
                        </div>
                        {report.findings.map((finding, idx) => (
                            <div
                                key={idx}
                                className={`outline-item ${selectedFindingIndex === idx ? 'active' : ''} severity-${finding.severity.toLowerCase()}`}
                                onClick={() => setSelectedFindingIndex(idx)}
                            >
                                <span className="truncate">{finding.title}</span>
                                <button className="delete-btn" onClick={(e) => { e.stopPropagation(); removeFinding(idx); }}>
                                    <Trash2 size={12} />
                                </button>
                            </div>
                        ))}
                    </div>

                    <div className="templates-section">
                        <h4>Quick Add</h4>
                        <div className="template-chips">
                            <button onClick={() => addFinding('sqli')}>SQLi</button>
                            <button onClick={() => addFinding('xss')}>XSS</button>
                        </div>
                    </div>
                </aside>

                {/* Main Editor Area */}
                <main className="report-editor">
                    {selectedFindingIndex === null ? (
                        <div className="editor-section">
                            <h2>Executive Summary</h2>
                            <p className="helper-text">High-level overview of the assessment for management.</p>
                            <textarea
                                className="full-editor"
                                value={report.executive_summary}
                                onChange={(e) => setReport({ ...report, executive_summary: e.target.value })}
                                placeholder="The assessment revealed several critical vulnerabilities..."
                            />
                        </div>
                    ) : (
                        <div className="finding-editor">
                            <div className="finding-header-inputs">
                                <input
                                    className="input-title"
                                    value={report.findings[selectedFindingIndex].title}
                                    onChange={(e) => updateFinding(selectedFindingIndex, 'title', e.target.value)}
                                    placeholder="Finding Title"
                                />
                                <select
                                    className={`input-severity severity-${report.findings[selectedFindingIndex].severity.toLowerCase()}`}
                                    value={report.findings[selectedFindingIndex].severity}
                                    onChange={(e) => updateFinding(selectedFindingIndex, 'severity', e.target.value)}
                                >
                                    <option value="Critical">Critical</option>
                                    <option value="High">High</option>
                                    <option value="Medium">Medium</option>
                                    <option value="Low">Low</option>
                                    <option value="Info">Info</option>
                                </select>
                            </div>

                            <div className="markdown-split">
                                <div className="split-pane">
                                    <label>Description (Markdown)</label>
                                    <textarea
                                        value={report.findings[selectedFindingIndex].description}
                                        onChange={(e) => updateFinding(selectedFindingIndex, 'description', e.target.value)}
                                        placeholder="Describe the vulnerability..."
                                    />
                                </div>
                                <div className="split-pane">
                                    <label>Remediation</label>
                                    <textarea
                                        value={report.findings[selectedFindingIndex].remediation}
                                        onChange={(e) => updateFinding(selectedFindingIndex, 'remediation', e.target.value)}
                                        placeholder="How to fix..."
                                    />
                                </div>
                            </div>

                            <div className="evidence-section">
                                <label>Evidence / Proof of Concept</label>
                                <textarea
                                    className="code-font"
                                    value={report.findings[selectedFindingIndex].evidence}
                                    onChange={(e) => updateFinding(selectedFindingIndex, 'evidence', e.target.value)}
                                    placeholder="Paste HTTP logs, screenshots (base64) or code snippets..."
                                />
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
};

export default ReportBuilder;
