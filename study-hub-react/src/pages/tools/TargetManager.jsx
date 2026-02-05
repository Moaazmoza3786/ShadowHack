import React, { useState, useEffect } from 'react';
import {
    Target, Globe, Crosshair, ListTodo, Bug, StickyNote, Bot,
    Plus, Trash2, Edit2, ExternalLink, CheckSquare, Square,
    ChevronDown, ChevronRight, Search, Shield, Key, Lock, Server,
    Download, Upload
} from 'lucide-react';

const TargetManager = () => {
    // --- STATE ---
    const [activeTab, setActiveTab] = useState('programs');
    const [targets, setTargets] = useState([]);
    const [findings, setFindings] = useState([]);
    const [notes, setNotes] = useState('');
    const [methodologyProgress, setMethodologyProgress] = useState({});

    // AI State
    const [selectedAiTarget, setSelectedAiTarget] = useState('');
    const [aiAnalysis, setAiAnalysis] = useState(null);

    // Initial Load
    useEffect(() => {
        const load = (key, setter, def) => {
            try {
                const item = localStorage.getItem(key);
                if (item) setter(JSON.parse(item));
                else setter(def);
            } catch (e) {
                console.error(`Error loading ${key}`, e);
                setter(def);
            }
        };
        load('bb_targets', setTargets, []);
        load('bb_findings', setFindings, []);
        load('bb_notes', setNotes, '');
        load('bb_methodology', setMethodologyProgress, {});
    }, []);

    // Save Effects
    useEffect(() => localStorage.setItem('bb_targets', JSON.stringify(targets)), [targets]);
    useEffect(() => localStorage.setItem('bb_findings', JSON.stringify(findings)), [findings]);
    useEffect(() => localStorage.setItem('bb_notes', JSON.stringify(notes)), [notes]);
    useEffect(() => localStorage.setItem('bb_methodology', JSON.stringify(methodologyProgress)), [methodologyProgress]);

    // --- DATA ---
    const programs = [
        { name: 'HackerOne', url: 'https://hackerone.com/directory/programs', type: 'Platform', icon: '🔴' },
        { name: 'Bugcrowd', url: 'https://bugcrowd.com/programs', type: 'Platform', icon: '🟠' },
        { name: 'Intigriti', url: 'https://intigriti.com/programs', type: 'Platform', icon: '🟢' },
        { name: 'YesWeHack', url: 'https://yeswehack.com/programs', type: 'Platform', icon: '🔵' },
        { name: 'Google VRP', url: 'https://bughunters.google.com/', type: 'Direct', icon: '🟡' },
        { name: 'Meta', url: 'https://facebook.com/whitehat', type: 'Direct', icon: '🔵' },
    ];

    const methodology = {
        recon: {
            title: 'Reconnaissance', icon: Search, color: 'text-blue-400',
            tasks: [
                { id: 'r1', text: 'Subdomain enumeration (subfinder, amass)' },
                { id: 'r2', text: 'Port scanning (nmap, masscan)' },
                { id: 'r3', text: 'Technology fingerprinting' },
                { id: 'r4', text: 'Content discovery (ffuf, gobuster)' },
                { id: 'r5', text: 'JavaScript analysis' },
                { id: 'r6', text: 'Wayback URLs collection' },
                { id: 'r7', text: 'Parameter discovery' },
                { id: 'r8', text: 'GitHub/GitLab dorking' }
            ]
        },
        auth: {
            title: 'Authentication', icon: Key, color: 'text-yellow-400',
            tasks: [
                { id: 'a1', text: 'Test login bypass' },
                { id: 'a2', text: 'Password reset flaws' },
                { id: 'a3', text: 'Session management' },
                { id: 'a4', text: 'JWT vulnerabilities' },
                { id: 'a5', text: 'OAuth/SSO issues' },
                { id: 'a6', text: '2FA bypass' }
            ]
        },
        authz: {
            title: 'Authorization', icon: Lock, color: 'text-purple-400',
            tasks: [
                { id: 'z1', text: 'IDOR testing' },
                { id: 'z2', text: 'Privilege escalation' },
                { id: 'z3', text: 'Access control bypass' },
                { id: 'z4', text: 'Role manipulation' }
            ]
        },
        injection: {
            title: 'Injection', icon: Bug, color: 'text-red-400',
            tasks: [
                { id: 'i1', text: 'XSS (Reflected, Stored, DOM)' },
                { id: 'i2', text: 'SQL Injection' },
                { id: 'i3', text: 'NoSQL Injection' },
                { id: 'i4', text: 'Command Injection' },
                { id: 'i5', text: 'SSTI/Template Injection' }
            ]
        },
        server: {
            title: 'Server-Side', icon: Server, color: 'text-green-400',
            tasks: [
                { id: 's1', text: 'SSRF testing' },
                { id: 's2', text: 'XXE/XML attacks' },
                { id: 's3', text: 'File upload vulnerabilities' },
                { id: 's4', text: 'Path traversal' },
                { id: 's5', text: 'Deserialization' }
            ]
        }
    };

    // --- ACTIONS ---
    const addTarget = () => {
        const name = prompt('Target Name:');
        if (!name) return;
        const scope = prompt('Scope (domains, IPs):') || '';
        setTargets(prev => [...prev, {
            name,
            scope,
            status: 'active',
            date: new Date().toLocaleDateString(),
            findings: 0
        }]);
    };

    const deleteTarget = (index) => {
        if (window.confirm('Delete this target?')) {
            setTargets(prev => prev.filter((_, i) => i !== index));
        }
    };

    const toggleTask = (taskId) => {
        setMethodologyProgress(prev => ({
            ...prev,
            [taskId]: !prev[taskId]
        }));
    };

    const getPhaseProgress = (phase) => {
        const total = phase.tasks.length;
        const done = phase.tasks.filter(t => methodologyProgress[t.id]).length;
        return Math.round((done / total) * 100);
    };

    const addFinding = () => {
        const title = prompt('Vulnerability Title:');
        if (!title) return;
        setFindings(prev => [...prev, {
            title,
            target: prompt('Target:') || '',
            severity: prompt('Severity (Critical/High/Medium/Low):') || 'Medium',
            description: prompt('Description:') || '',
            status: 'reported',
            date: new Date().toLocaleDateString()
        }]);
    };

    const runAIAnalysis = (targetName) => {
        setSelectedAiTarget(targetName);
        if (!targetName) return setAiAnalysis(null);

        const target = targets.find(t => t.name === targetName);
        if (!target) return;

        // Logic from legacy script
        const scope = target.scope.toLowerCase();
        const suggestions = [];
        if (scope.includes('*')) suggestions.push({ text: 'Wildcard Scope: Use Subfinder & Amass for broad subdomain enumeration.', icon: Globe });
        if (scope.includes('api')) suggestions.push({ text: 'API Detected: Focus on IDOR, mass assignment, and fuzzing endpoints.', icon: Server });
        if (scope.includes('admin') || scope.includes('internal')) suggestions.push({ text: 'High Value: Prioritize Access Control checks and Auth bypass.', icon: Lock });
        if (suggestions.length === 0) suggestions.push({ text: 'Standard Scope: Begin with automated recon and technology fingerprinting.', icon: Search });

        // Dorks
        const domain = targetName.replace(/\s+/g, '').toLowerCase() + '.com'; // Naive
        const dorks = [
            { title: 'Public Docs', query: `site:${domain} ext:doc | ext:pdf` },
            { title: 'Config Files', query: `site:${domain} ext:xml | ext:conf | ext:env` },
            { title: 'Login Pages', query: `site:${domain} inurl:login` }
        ];

        setAiAnalysis({ suggestions, dorks });
    };

    const handleExport = () => {
        const data = {
            targets,
            findings,
            notes,
            methodology: methodologyProgress,
            date: new Date().toISOString()
        };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `target-manager-backup-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
    };

    const handleImport = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const data = JSON.parse(event.target.result);
                if (window.confirm('This will overwrite current data. Continue?')) {
                    if (data.targets) setTargets(data.targets);
                    if (data.findings) setFindings(data.findings);
                    if (data.notes) setNotes(data.notes);
                    if (data.methodology) setMethodologyProgress(data.methodology);
                    alert('Import successful!');
                }
            } catch (err) {
                alert('Invalid backup file');
            }
        };
        reader.readAsText(file);
    };

    return (
        <div className="h-full flex flex-col p-6 max-w-7xl mx-auto space-y-6">
            {/* Header */}
            <div className="flex justify-between items-start">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-green-600 mb-2 flex items-center gap-3">
                        <Target className="w-8 h-8 text-emerald-500" />
                        Target Manager
                        <span className="text-xs bg-emerald-500 text-black px-2 py-1 rounded font-bold">AI ENABLED</span>
                    </h1>
                    <p className="text-gray-400">
                        Smart Target Management & Methodology Tracker
                    </p>
                </div>
                <div className="flex gap-2">
                    <button onClick={handleExport} className="px-3 py-1 bg-gray-800 border border-white/10 rounded-lg text-xs font-bold text-gray-300 hover:text-white hover:border-emerald-500 transition-all flex items-center gap-2">
                        <Download className="w-3 h-3" /> Export Data
                    </button>
                    <label className="px-3 py-1 bg-gray-800 border border-white/10 rounded-lg text-xs font-bold text-gray-300 hover:text-white hover:border-emerald-500 transition-all flex items-center gap-2 cursor-pointer">
                        <Upload className="w-3 h-3" /> Import Data
                        <input type="file" onChange={handleImport} className="hidden" accept=".json" />
                    </label>
                </div>
            </div>

            {/* Navigation */}
            <div className="flex flex-wrap gap-2 border-b border-white/10 pb-1">
                {[
                    { id: 'programs', icon: Globe, label: 'Programs' },
                    { id: 'targets', icon: Crosshair, label: 'My Targets' },
                    { id: 'ai', icon: Bot, label: 'AI Assistant', highlight: true },
                    { id: 'methodology', icon: ListTodo, label: 'Methodology' },
                    { id: 'findings', icon: Bug, label: 'Findings' },
                    { id: 'notes', icon: StickyNote, label: 'Notes' }
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-t-lg transition-all ${activeTab === tab.id
                            ? 'bg-emerald-500/10 text-emerald-400 border-b-2 border-emerald-500'
                            : 'text-gray-400 hover:text-white hover:bg-white/5'
                            } ${tab.highlight ? 'text-emerald-400' : ''}`}
                    >
                        <tab.icon className="w-4 h-4" />
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Content Area */}
            <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar pr-2 animate-fadeIn">

                {/* PROGRAMS */}
                {activeTab === 'programs' && (
                    <div className="space-y-6">
                        <h2 className="text-xl font-bold text-white flex items-center gap-2">
                            <Globe className="w-5 h-5 text-emerald-400" /> Bug Bounty Platforms
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {programs.map((p, i) => (
                                <a
                                    key={i} href={p.url} target="_blank" rel="noopener noreferrer"
                                    className="bg-gray-900/50 border border-white/10 rounded-xl p-4 flex items-center gap-3 hover:bg-emerald-500/5 hover:border-emerald-500/30 transition-all group"
                                >
                                    <span className="text-2xl">{p.icon}</span>
                                    <div className="flex-1">
                                        <h4 className="font-bold text-white group-hover:text-emerald-400 transition-colors">{p.name}</h4>
                                        <span className="text-xs text-gray-400">{p.type}</span>
                                    </div>
                                    <ExternalLink className="w-4 h-4 text-gray-600 group-hover:text-emerald-500" />
                                </a>
                            ))}
                        </div>
                    </div>
                )}

                {/* TARGETS */}
                {activeTab === 'targets' && (
                    <div className="space-y-6">
                        <div className="flex justify-between items-center">
                            <h2 className="text-xl font-bold text-white flex items-center gap-2">
                                <Crosshair className="w-5 h-5 text-emerald-400" /> My Targets
                            </h2>
                            <button
                                onClick={addTarget}
                                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg flex items-center gap-2 transition-colors font-bold text-sm"
                            >
                                <Plus className="w-4 h-4" /> Add Target
                            </button>
                        </div>
                        {targets.length === 0 ? (
                            <div className="text-center py-20 text-gray-500 bg-gray-900/30 rounded-xl border border-dashed border-white/10">
                                <Crosshair className="w-12 h-12 mx-auto mb-3 opacity-20" />
                                <p>No targets tracked yet.</p>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {targets.map((t, i) => (
                                    <div key={i} className="bg-gray-900/50 border border-white/10 rounded-xl p-6 relative group hover:border-white/20 transition-all">
                                        <div className="flex justify-between items-start mb-4">
                                            <h3 className="font-bold text-lg text-white">{t.name}</h3>
                                            <span className={`text-xs px-2 py-1 rounded capitalize ${t.status === 'active' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-300'
                                                }`}>
                                                {t.status}
                                            </span>
                                        </div>
                                        <p className="text-sm text-gray-400 mb-4 font-mono">{t.scope}</p>
                                        <div className="flex justify-between items-center text-xs text-gray-500 border-t border-white/5 pt-4">
                                            <span>Added: {t.date}</span>
                                            <div className="flex gap-2">
                                                <button className="hover:text-white transition-colors"><Edit2 className="w-3 h-3" /></button>
                                                <button onClick={() => deleteTarget(i)} className="hover:text-red-400 transition-colors"><Trash2 className="w-3 h-3" /></button>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}

                {/* AI ASSISTANT */}
                {activeTab === 'ai' && (
                    <div className="space-y-6">
                        <div className="bg-gray-900/50 border border-emerald-500/20 rounded-xl p-6">
                            <h3 className="font-bold text-emerald-400 flex items-center gap-2 mb-4">
                                <Bot className="w-5 h-5" /> Target Intelligence
                            </h3>
                            <div className="max-w-md mb-6">
                                <label className="text-xs text-gray-500 mb-1 block">SELECT TARGET</label>
                                <select
                                    className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-white outline-none focus:border-emerald-500"
                                    value={selectedAiTarget}
                                    onChange={(e) => runAIAnalysis(e.target.value)}
                                    onClick={() => !selectedAiTarget && targets.length > 0 && runAIAnalysis(targets[0].name)} // Auto-select first if empty on click
                                >
                                    <option value="">-- Select Target --</option>
                                    {targets.map(t => <option key={t.name} value={t.name}>{t.name}</option>)}
                                </select>
                            </div>

                            {aiAnalysis ? (
                                <div className="space-y-6 animate-fadeIn">
                                    <div className="bg-black/30 rounded-xl p-4 border border-white/5">
                                        <h4 className="font-bold text-white mb-3">Scope Insights</h4>
                                        <div className="space-y-3">
                                            {aiAnalysis.suggestions.map((s, i) => (
                                                <div key={i} className="flex gap-3 text-sm text-gray-300">
                                                    <s.icon className="w-5 h-5 text-emerald-500 shrink-0" />
                                                    <p>{s.text}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="bg-black/30 rounded-xl p-4 border border-white/5">
                                        <h4 className="font-bold text-white mb-3 flex items-center gap-2">
                                            <Search className="w-4 h-4 text-emerald-500" /> Generated Dorks
                                        </h4>
                                        <div className="space-y-2">
                                            {aiAnalysis.dorks.map((d, i) => (
                                                <div key={i} className="group flex flex-col bg-gray-900/50 p-2 rounded border border-white/5 hover:border-emerald-500/30 transition-colors">
                                                    <span className="text-xs text-gray-500 font-bold mb-1">{d.title}</span>
                                                    <code className="text-emerald-400/90 font-mono text-xs break-all selection:bg-emerald-500/30">
                                                        {d.query}
                                                    </code>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="text-center text-gray-500 py-10">
                                    <Bot className="w-10 h-10 mx-auto mb-2 opacity-20" />
                                    <p>Select a target to run AI analysis.</p>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* METHODOLOGY */}
                {activeTab === 'methodology' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                        {Object.entries(methodology).map(([key, phase]) => (
                            <div key={key} className="bg-gray-900/50 border border-white/10 rounded-xl p-4 flex flex-col">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className={`p-2 rounded bg-white/5 ${phase.color}`}>
                                        <phase.icon className="w-5 h-5" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-white">{phase.title}</h3>
                                        <div className="w-full bg-gray-800 h-1 mt-1 rounded-full overflow-hidden">
                                            <div
                                                className="bg-emerald-500 h-full transition-all duration-500"
                                                style={{ width: `${getPhaseProgress(phase)}%` }}
                                            />
                                        </div>
                                    </div>
                                    <span className="text-xs font-bold text-emerald-400">{getPhaseProgress(phase)}%</span>
                                </div>

                                <div className="space-y-2 flex-1">
                                    {phase.tasks.map(task => (
                                        <div
                                            key={task.id}
                                            onClick={() => toggleTask(task.id)}
                                            className="flex items-start gap-3 p-2 rounded hover:bg-white/5 cursor-pointer group transition-colors"
                                        >
                                            <div className={`mt-0.5 ${methodologyProgress[task.id] ? 'text-emerald-500' : 'text-gray-600 group-hover:text-gray-400'}`}>
                                                {methodologyProgress[task.id] ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
                                            </div>
                                            <span className={`text-sm ${methodologyProgress[task.id] ? 'text-gray-500 line-through' : 'text-gray-300'}`}>
                                                {task.text}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* FINDINGS */}
                {activeTab === 'findings' && (
                    <div className="space-y-6">
                        <div className="flex justify-between items-center">
                            <h2 className="text-xl font-bold text-white flex items-center gap-2">
                                <Bug className="w-5 h-5 text-red-500" /> Vulnerabilities Found
                            </h2>
                            <button
                                onClick={addFinding}
                                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg flex items-center gap-2 transition-colors font-bold text-sm"
                            >
                                <Plus className="w-4 h-4" /> Report New
                            </button>
                        </div>

                        {findings.length === 0 ? (
                            <div className="text-center py-20 text-gray-500 bg-gray-900/30 rounded-xl border border-dashed border-white/10">
                                <Bug className="w-12 h-12 mx-auto mb-3 opacity-20" />
                                <p>No findings recorded yet. Happy hunting!</p>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {findings.map((f, i) => (
                                    <div key={i} className="bg-gray-900/50 border border-white/10 border-l-4 rounded-xl p-5 hover:border-white/20 transition-all"
                                        style={{ borderLeftColor: f.severity === 'Critical' ? '#ef4444' : f.severity === 'High' ? '#f97316' : '#eab308' }}>
                                        <div className="flex justify-between items-start mb-2">
                                            <span className="font-bold text-white">{f.title}</span>
                                            <span className="text-xs font-mono px-2 py-0.5 bg-white/5 rounded text-gray-300">{f.severity}</span>
                                        </div>
                                        <p className="text-xs text-emerald-400 mb-2 font-mono">{f.target}</p>
                                        <p className="text-sm text-gray-400 mb-4 line-clamp-2">{f.description}</p>
                                        <div className="flex justify-between items-end border-t border-white/5 pt-3">
                                            <span className="text-xs text-gray-600">{f.date}</span>
                                            <button onClick={() => {
                                                setFindings(prev => prev.filter((_, idx) => idx !== i));
                                            }} className="text-gray-600 hover:text-red-400 transition-colors">
                                                <Trash2 className="w-3 h-3" />
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}

                {/* NOTES */}
                {activeTab === 'notes' && (
                    <div className="h-full flex flex-col">
                        <textarea
                            className="flex-1 w-full bg-gray-900/50 border border-white/10 rounded-xl p-6 text-white outline-none focus:border-emerald-500/50 resize-none font-mono text-sm leading-relaxed"
                            placeholder="Scratchpad for your thoughts..."
                            value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                        />
                    </div>
                )}
            </div>
        </div>
    );
};

export default TargetManager;
