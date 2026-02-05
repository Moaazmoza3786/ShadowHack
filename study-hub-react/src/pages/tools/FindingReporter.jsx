import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    FileText, PlusCircle, FolderOpen, Calculator, Book,
    Save, Download, Trash2, Link,
    AlertTriangle, CheckCircle, ChevronRight,
    Clipboard, Bug, Shield
} from 'lucide-react';

const FindingReporter = () => {
    const [currentTab, setCurrentTab] = useState('new');
    const [findings, setFindings] = useState(() => {
        return JSON.parse(localStorage.getItem('pro_findings') || '[]');
    });
    const [selectedFinding, setSelectedFinding] = useState(null);
    const [cvssValues, setCvssValues] = useState({});
    const [cvssResult, setCvssResult] = useState({ score: 0, severity: 'None', vector: '' });

    // CVSS 3.1 Metrics Configuration
    const cvssMetrics = {
        AV: {
            label: 'Attack Vector',
            options: [
                { value: 'N', label: 'Network', score: 0.85, desc: 'Remotely exploitable' },
                { value: 'A', label: 'Adjacent', score: 0.62, desc: 'Same network segment' },
                { value: 'L', label: 'Local', score: 0.55, desc: 'Local access required' },
                { value: 'P', label: 'Physical', score: 0.20, desc: 'Physical access required' }
            ]
        },
        AC: {
            label: 'Attack Complexity',
            options: [
                { value: 'L', label: 'Low', score: 0.77, desc: 'No special conditions' },
                { value: 'H', label: 'High', score: 0.44, desc: 'Specialized conditions' }
            ]
        },
        PR: {
            label: 'Privileges Required',
            options: [
                { value: 'N', label: 'None', score: 0.85, desc: 'No authentication' },
                { value: 'L', label: 'Low', score: 0.62, desc: 'Basic user' },
                { value: 'H', label: 'High', score: 0.27, desc: 'Admin/elevated' }
            ]
        },
        UI: {
            label: 'User Interaction',
            options: [
                { value: 'N', label: 'None', score: 0.85, desc: 'No user action' },
                { value: 'R', label: 'Required', score: 0.62, desc: 'User action needed' }
            ]
        },
        S: {
            label: 'Scope',
            options: [
                { value: 'U', label: 'Unchanged', desc: 'Impact limited to component' },
                { value: 'C', label: 'Changed', desc: 'Can impact other components' }
            ]
        },
        C: {
            label: 'Confidentiality',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No disclosure' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Some data exposed' },
                { value: 'H', label: 'High', score: 0.56, desc: 'All data exposed' }
            ]
        },
        I: {
            label: 'Integrity',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No modification' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Some data modifiable' },
                { value: 'H', label: 'High', score: 0.56, desc: 'All data modifiable' }
            ]
        },
        A: {
            label: 'Availability',
            options: [
                { value: 'N', label: 'None', score: 0, desc: 'No impact' },
                { value: 'L', label: 'Low', score: 0.22, desc: 'Partial disruption' },
                { value: 'H', label: 'High', score: 0.56, desc: 'Complete disruption' }
            ]
        }
    };

    const vulnTypes = [
        'SQL Injection', 'Cross-Site Scripting (XSS)', 'Server-Side Request Forgery (SSRF)',
        'Insecure Direct Object Reference (IDOR)', 'Authentication Bypass', 'Broken Access Control',
        'Remote Code Execution (RCE)', 'Local File Inclusion (LFI)', 'XML External Entity (XXE)',
        'Cross-Site Request Forgery (CSRF)', 'Information Disclosure', 'Business Logic Flaw',
        'Subdomain Takeover', 'Open Redirect', 'Command Injection', 'Privilege Escalation',
        'Insecure Deserialization', 'Server-Side Template Injection (SSTI)', 'Race Condition', 'Other'
    ];

    const businessImpacts = {
        'Critical': [
            'Complete compromise of customer data affecting millions of users',
            'Full access to financial systems and ability to perform unauthorized transactions',
            'Complete system takeover allowing attackers to control all infrastructure',
            'Regulatory violations (GDPR, PCI-DSS) with potential fines exceeding $10M'
        ],
        'High': [
            'Unauthorized access to sensitive customer PII (names, addresses, SSN)',
            'Ability to impersonate any user including administrators',
            'Access to internal systems and confidential business documents',
            'Potential reputational damage affecting customer trust'
        ],
        'Medium': [
            'Limited access to user data without critical information',
            'Ability to perform actions on behalf of users with their session',
            'Information disclosure of internal infrastructure details',
            'Service disruption affecting subset of users'
        ],
        'Low': [
            'Minor information disclosure (software versions, paths)',
            'Low-impact denial of service affecting single sessions',
            'Security misconfiguration without direct exploitation path',
            'Verbose error messages revealing technical details'
        ]
    };

    useEffect(() => {
        localStorage.setItem('pro_findings', JSON.stringify(findings));
    }, [findings]);

    const calculateCVSS = () => {
        const v = cvssValues;
        const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        const allSet = requiredMetrics.every(m => v[m]);

        if (!allSet) return;

        const getScore = (metric, val) => {
            const opt = cvssMetrics[metric].options.find(o => o.value === val);
            return opt?.score || 0;
        };

        const C = getScore('C', v.C);
        const I = getScore('I', v.I);
        const A = getScore('A', v.A);
        const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));

        let impact;
        if (v.S === 'U') {
            impact = 6.42 * ISS;
        } else {
            impact = 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
        }

        const AV = getScore('AV', v.AV);
        const AC = getScore('AC', v.AC);
        let PR = getScore('PR', v.PR);

        if (v.S === 'C') {
            if (v.PR === 'L') PR = 0.68;
            if (v.PR === 'H') PR = 0.50;
        }

        const UI = getScore('UI', v.UI);
        const exploitability = 8.22 * AV * AC * PR * UI;

        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else if (v.S === 'U') {
            baseScore = Math.min(impact + exploitability, 10);
        } else {
            baseScore = Math.min(1.08 * (impact + exploitability), 10);
        }

        baseScore = Math.ceil(baseScore * 10) / 10;

        let severity;
        if (baseScore === 0) severity = 'None';
        else if (baseScore < 4) severity = 'Low';
        else if (baseScore < 7) severity = 'Medium';
        else if (baseScore < 9) severity = 'High';
        else severity = 'Critical';

        const vector = `CVSS: 3.1 / AV:${v.AV} /AC:${v.AC}/PR:${v.PR} /UI:${v.UI}/S:${v.S} /C:${v.C}/I:${v.I}/A:${v.A}`;
        setCvssResult({ score: baseScore, severity, vector });
    };

    const handleMetricChange = (metric, value) => {
        const newValues = { ...cvssValues, [metric]: value };
        setCvssValues(newValues);
    };

    useEffect(() => {
        calculateCVSS();
    }, [cvssValues]);

    const saveFinding = (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const newFinding = {
            id: Date.now(),
            title: formData.get('title'),
            type: formData.get('type'),
            asset: formData.get('asset'),
            description: formData.get('description'),
            steps: formData.get('steps'),
            poc: formData.get('poc'),
            cvss: cvssResult.score,
            severity: cvssResult.severity,
            vector: cvssResult.vector,
            impact: formData.get('impact'),
            remediation: formData.get('remediation'),
            date: new Date().toLocaleDateString()
        };

        if (!newFinding.title || !newFinding.type) {
            alert("Please fill in the required fields");
            return;
        }

        setFindings([...findings, newFinding]);
        setCurrentTab('reports');
        alert("Finding saved successfully!");
    };

    const deleteFinding = (id) => {
        if (confirm("Delete this finding?")) {
            setFindings(findings.filter(f => f.id !== id));
        }
    };

    const exportToMarkdown = (f) => {
        const report = `# ${f.title}\n\n` +
            `**Severity:** ${f.severity} (${f.cvss})\n` +
            `**Vector:** \`${f.vector}\`\n` +
            `**Type:** ${f.type}\n` +
            `**Asset:** ${f.asset}\n\n` +
            `## Description\n${f.description}\n\n` +
            `## Steps to Reproduce\n${f.steps}\n\n` +
            `## Proof of Concept\n\`\`\`\n${f.poc}\n\`\`\`\n\n` +
            `## Business Impact\n${f.impact}\n\n` +
            `## Remediation\n${f.remediation}\n\n` +
            `--- \n*Generated by StudyHub Finding Reporter*`;

        const blob = new Blob([report], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${f.title.replace(/\s+/g, '_')}_Report.md`;
        a.click();
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-['Outfit']">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="relative mb-12 p-8 rounded-2xl bg-gradient-to-br from-[#12121e] to-[#0a0a0f] border border-blue-500/20 overflow-hidden">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 blur-[80px] rounded-full -mr-32 -mt-32" />
                    <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="p-2 bg-blue-500/20 rounded-lg text-blue-400">
                                    <FileText size={24} />
                                </div>
                                <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-400">
                                    Finding Reporter
                                </h1>
                            </div>
                            <p className="text-gray-400 text-lg">Professional Security Report Writing & CVSS Calculator</p>
                        </div>
                        <div className="flex bg-[#1a1a2e] p-1 rounded-xl border border-white/5">
                            {[
                                { id: 'new', label: 'New Finding', icon: PlusCircle },
                                { id: 'reports', label: 'My Reports', icon: FolderOpen },
                                { id: 'cvss', label: 'CVSS Calc', icon: Calculator },
                                { id: 'templates', label: 'Templates', icon: Book },
                            ].map((tab) => (
                                <button
                                    key={tab.id}
                                    onClick={() => setCurrentTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${currentTab === tab.id
                                        ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
                                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                                        }`}
                                >
                                    <tab.icon size={18} />
                                    <span className="hidden sm:inline">{tab.label}</span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <AnimatePresence mode="wait">
                    {currentTab === 'new' && (
                        <motion.div
                            key="new"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                        >
                            <form onSubmit={saveFinding} className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                <div className="lg:col-span-2 space-y-6">
                                    {/* Basic Info */}
                                    <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5 space-y-4">
                                        <h3 className="text-lg font-semibold flex items-center gap-2 text-blue-400 mb-4">
                                            <Bug size={20} /> Basic Information
                                        </h3>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium text-gray-400">Finding Title *</label>
                                                <input
                                                    name="title"
                                                    required
                                                    className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50"
                                                    placeholder="e.g., Stored XSS in Bio Field"
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium text-gray-400">Vulnerability Type *</label>
                                                <select
                                                    name="type"
                                                    required
                                                    className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50"
                                                >
                                                    <option value="">Select type...</option>
                                                    {vulnTypes.map(t => <option key={t} value={t}>{t}</option>)}
                                                </select>
                                            </div>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Affected Asset *</label>
                                            <input
                                                name="asset"
                                                required
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50"
                                                placeholder="e.g., https://api.example.com/v1/user"
                                            />
                                        </div>
                                    </div>

                                    {/* Technical Details */}
                                    <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5 space-y-4">
                                        <h3 className="text-lg font-semibold flex items-center gap-2 text-cyan-400 mb-4">
                                            <Shield size={20} /> Technical Details
                                        </h3>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Description</label>
                                            <textarea
                                                name="description"
                                                rows={4}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50 resize-none"
                                                placeholder="Detailed technical description..."
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Steps to Reproduce</label>
                                            <textarea
                                                name="steps"
                                                rows={4}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50 resize-none font-mono text-sm"
                                                placeholder="1. Login as user...&#10;2. Navigate to...&#10;3. Inject payload..."
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Proof of Concept (PoC)</label>
                                            <textarea
                                                name="poc"
                                                rows={3}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-blue-500/50 resize-none font-mono text-sm"
                                                placeholder="<script>alert(1)</script>"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-6">
                                    {/* CVSS Preview (Stickied in sidebar) */}
                                    <div className="p-6 rounded-2xl bg-[#12121e] border border-blue-500/20 overflow-hidden sticky top-8">
                                        <div className="absolute top-0 right-0 p-2 opacity-10">
                                            <Calculator size={80} />
                                        </div>
                                        <h3 className="text-lg font-semibold mb-6">CVSS Score</h3>
                                        <div className="flex flex-col items-center justify-center py-4 space-y-2">
                                            <div className={`text-6xl font-bold ${cvssResult.score >= 9 ? 'text-red-500' :
                                                cvssResult.score >= 7 ? 'text-orange-500' :
                                                    cvssResult.score >= 4 ? 'text-yellow-500' :
                                                        cvssResult.score > 0 ? 'text-green-500' : 'text-gray-500'
                                                }`}>
                                                {cvssResult.score.toFixed(1)}
                                            </div>
                                            <div className={`px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${cvssResult.score >= 9 ? 'bg-red-500/20 text-red-400' :
                                                cvssResult.score >= 7 ? 'bg-orange-500/20 text-orange-400' :
                                                    cvssResult.score >= 4 ? 'bg-yellow-500/20 text-yellow-400' :
                                                        cvssResult.score > 0 ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                                                }`}>
                                                {cvssResult.severity}
                                            </div>
                                        </div>
                                        <p className="text-[10px] font-mono text-gray-500 text-center mt-4 truncate">
                                            {cvssResult.vector || 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_'}
                                        </p>
                                        <button
                                            type="button"
                                            onClick={() => setCurrentTab('cvss')}
                                            className="w-full mt-6 py-3 px-4 rounded-xl bg-blue-600/10 text-blue-400 border border-blue-500/20 hover:bg-blue-600 hover:text-white transition-all text-sm font-medium flex items-center justify-center gap-2"
                                        >
                                            <Calculator size={16} /> Open Calculator
                                        </button>
                                    </div>

                                    <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5 space-y-4">
                                        <h3 className="text-lg font-semibold mb-4">Business & Fix</h3>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Impact</label>
                                            <textarea
                                                name="impact"
                                                rows={3}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500/50 text-sm"
                                                placeholder="Risk to business..."
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-medium text-gray-400">Remediation</label>
                                            <textarea
                                                name="remediation"
                                                rows={3}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-3 py-2 focus:outline-none focus:border-blue-500/50 text-sm"
                                                placeholder="How to fix..."
                                            />
                                        </div>
                                        <div className="pt-4 flex flex-col gap-3">
                                            <button
                                                type="submit"
                                                className="w-full bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-xl font-bold shadow-lg shadow-blue-600/20 transition-all flex items-center justify-center gap-2"
                                            >
                                                <Save size={20} /> Save Finding
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </form>
                        </motion.div>
                    )}

                    {currentTab === 'reports' && (
                        <motion.div
                            key="reports"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="space-y-6"
                        >
                            {findings.length === 0 ? (
                                <div className="text-center py-24 bg-[#12121e] rounded-3xl border border-dashed border-white/10">
                                    <div className="flex justify-center mb-6 text-gray-600">
                                        <FolderOpen size={64} />
                                    </div>
                                    <h3 className="text-xl font-bold mb-2">No findings saved yet</h3>
                                    <p className="text-gray-400 mb-8">Start documenting your security discoveries.</p>
                                    <button
                                        onClick={() => setCurrentTab('new')}
                                        className="px-8 py-3 bg-blue-600 hover:bg-blue-700 rounded-xl font-bold transition-all"
                                    >
                                        Create Your First Report
                                    </button>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    {findings.map((f) => (
                                        <div key={f.id} className="group p-6 rounded-2xl bg-[#12121e] border border-white/5 hover:border-blue-500/30 transition-all relative overflow-hidden">
                                            <div className={`absolute top-0 right-0 w-2 h-full ${f.severity === 'Critical' ? 'bg-red-500' :
                                                f.severity === 'High' ? 'bg-orange-500' :
                                                    f.severity === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
                                                }`} />

                                            <div className="flex justify-between items-start mb-4">
                                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${f.severity === 'Critical' ? 'bg-red-500/20 text-red-500' :
                                                    f.severity === 'High' ? 'bg-orange-500/20 text-orange-500' :
                                                        f.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-green-500/20 text-green-500'
                                                    }`}>
                                                    {f.severity}
                                                </span>
                                                <span className="text-xs text-gray-500 font-mono">{f.date}</span>
                                            </div>
                                            <h4 className="text-lg font-bold mb-2 line-clamp-1">{f.title}</h4>
                                            <div className="flex items-center gap-2 text-xs text-gray-400 mb-6">
                                                <Link size={12} />
                                                <span className="truncate">{f.asset}</span>
                                            </div>

                                            <div className="flex gap-2 border-t border-white/5 pt-4">
                                                <button
                                                    onClick={() => setSelectedFinding(f)}
                                                    className="flex-1 py-2 rounded-lg bg-white/5 hover:bg-blue-600/20 text-blue-400 hover:text-blue-300 transition-all text-xs font-bold"
                                                >
                                                    View Details
                                                </button>
                                                <button
                                                    onClick={() => exportToMarkdown(f)}
                                                    className="p-2 rounded-lg bg-white/5 hover:bg-green-600/20 text-green-400 hover:text-green-300 transition-all"
                                                >
                                                    <Download size={16} />
                                                </button>
                                                <button
                                                    onClick={() => deleteFinding(f.id)}
                                                    className="p-2 rounded-lg bg-white/5 hover:bg-red-600/20 text-red-400 hover:text-red-300 transition-all"
                                                >
                                                    <Trash2 size={16} />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </motion.div>
                    )}

                    {currentTab === 'cvss' && (
                        <motion.div
                            key="cvss"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="grid grid-cols-1 lg:grid-cols-12 gap-8"
                        >
                            <div className="lg:col-span-8 space-y-6">
                                {Object.entries(cvssMetrics).map(([key, metric]) => (
                                    <div key={key} className="p-6 rounded-2xl bg-[#12121e] border border-white/5">
                                        <div className="flex justify-between items-center mb-4">
                                            <h4 className="text-lg font-semibold">{metric.label}</h4>
                                            <div className="px-2 py-1 bg-white/5 rounded text-[10px] font-mono text-gray-500">Metric ID: {key}</div>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                                            {metric.options.map((opt) => (
                                                <button
                                                    key={opt.value}
                                                    onClick={() => handleMetricChange(key, opt.value)}
                                                    className={`p-3 rounded-xl border text-left transition-all ${cvssValues[key] === opt.value
                                                        ? 'bg-blue-600 border-blue-500 text-white shadow-lg shadow-blue-600/20'
                                                        : 'bg-[#0a0a0f] border-white/10 text-gray-400 hover:border-white/30'
                                                        }`}
                                                >
                                                    <div className="text-sm font-bold">{opt.label}</div>
                                                    <div className="text-[10px] opacity-60 leading-tight mt-1">{opt.desc}</div>
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div className="lg:col-span-4 lg:sticky lg:top-8 h-fit space-y-6">
                                <div className="p-8 rounded-3xl bg-gradient-to-br from-blue-600 to-cyan-600 text-white shadow-2xl shadow-blue-500/20">
                                    <h3 className="text-xl font-bold mb-8">Score Summary</h3>
                                    <div className="flex flex-col items-center py-6">
                                        <div className="text-8xl font-black mb-2">{cvssResult.score.toFixed(1)}</div>
                                        <div className="px-6 py-2 bg-white/20 backdrop-blur-md rounded-full font-bold uppercase tracking-widest text-sm">
                                            {cvssResult.severity}
                                        </div>
                                    </div>
                                    <div className="mt-8 p-4 bg-black/20 rounded-2xl border border-white/10">
                                        <div className="text-[10px] font-bold text-blue-200 uppercase mb-2">Vector String</div>
                                        <div className="font-mono text-xs break-all leading-relaxed opacity-80">
                                            {cvssResult.vector || 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_'}
                                        </div>
                                        <button
                                            onClick={() => {
                                                navigator.clipboard.writeText(cvssResult.vector);
                                                alert("Vector copied!");
                                            }}
                                            className="mt-4 w-full py-2 rounded-xl bg-white/10 hover:bg-white/20 transition-all text-[10px] font-bold uppercase tracking-widest flex items-center justify-center gap-2"
                                        >
                                            <Clipboard size={12} /> Copy Vector
                                        </button>
                                    </div>
                                </div>

                                <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5">
                                    <h4 className="text-sm font-bold text-gray-400 uppercase mb-4 tracking-widest">Severity Guide</h4>
                                    <div className="space-y-3">
                                        {[
                                            { l: 'Critical', r: '9.0 - 10.0', c: 'bg-red-500' },
                                            { l: 'High', r: '7.0 - 8.9', c: 'bg-orange-500' },
                                            { l: 'Medium', r: '4.0 - 6.9', d: 'bg-yellow-500' },
                                            { l: 'Low', r: '0.1 - 3.9', d: 'bg-green-500' },
                                        ].map(s => (
                                            <div key={s.l} className="flex items-center justify-between text-xs">
                                                <div className="flex items-center gap-2">
                                                    <div className={`w-2 h-2 rounded-full ${s.c || s.d}`} />
                                                    <span className="font-medium text-gray-300">{s.l}</span>
                                                </div>
                                                <span className="text-gray-500 font-mono">{s.r}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {currentTab === 'templates' && (
                        <motion.div
                            key="templates"
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 1.05 }}
                            className="grid grid-cols-1 md:grid-cols-2 gap-8"
                        >
                            <div className="space-y-6">
                                <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5">
                                    <h4 className="text-lg font-bold mb-4 flex items-center gap-2">
                                        <CheckCircle size={20} className="text-blue-400" /> Executive Summary Template
                                    </h4>
                                    <pre className="p-4 bg-black/40 rounded-xl text-gray-400 text-xs overflow-x-auto leading-relaxed border border-white/5 h-48 scrollbar-thin">
                                        {`During the security assessment of [TARGET], [X] vulnerabilities were identified:
- [X] Critical
- [X] High  
- [X] Medium
- [X] Low

The most severe finding was [TITLE], which could allow an attacker to [IMPACT].

Immediate remediation is recommended for all Critical and High severity findings.`}
                                    </pre>
                                    <button
                                        onClick={() => {
                                            const text = `During the security assessment of [TARGET], [X] vulnerabilities were identified:\n- [X] Critical\n- [X] High\n- [X] Medium\n- [X] Low\n\nThe most severe finding was [TITLE], which could allow an attacker to [IMPACT].\n\nImmediate remediation is recommended for all Critical and High severity findings.`;
                                            navigator.clipboard.writeText(text);
                                            alert("Copied!");
                                        }}
                                        className="mt-4 w-full py-2 bg-blue-600/10 text-blue-400 rounded-lg text-xs font-bold hover:bg-blue-600 hover:text-white transition-all"
                                    >
                                        Copy Template
                                    </button>
                                </div>

                                <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5">
                                    <h4 className="text-lg font-bold mb-4 flex items-center gap-2">
                                        <AlertTriangle size={20} className="text-orange-400" /> Impact Examples
                                    </h4>
                                    <div className="space-y-4">
                                        {Object.entries(businessImpacts).map(([sev, items]) => (
                                            <details key={sev} className="group transition-all">
                                                <summary className="flex items-center justify-between cursor-pointer p-3 rounded-lg bg-white/5 hover:bg-white/10 font-bold text-sm">
                                                    {sev} Severity
                                                    <ChevronRight size={16} className="group-open:rotate-90 transition-transform" />
                                                </summary>
                                                <ul className="pl-6 pr-3 py-3 space-y-2 text-xs text-gray-400 border-l border-white/5 mt-1">
                                                    {items.map((i, idx) => (
                                                        <li key={idx} className="flex gap-2">
                                                            <span className="text-blue-500 opacity-50">•</span> {i}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </details>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="p-6 rounded-2xl bg-[#12121e] border border-white/5 h-fit">
                                <h4 className="text-lg font-bold mb-4">Detailed Vulnerability Schema</h4>
                                <div className="space-y-4 p-4 bg-black/40 rounded-xl border border-white/5 font-mono text-xs text-gray-400">
                                    <div className="text-blue-400">## [FINDING TITLE]</div>
                                    <div>**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]</div>
                                    <div>**CVSS Score:** [X.X] ([CVSS VECTOR])</div>
                                    <div className="mt-4 text-cyan-400">### Description</div>
                                    <div>[Technical description of the vulnerability]</div>
                                    <div className="mt-4 text-cyan-400">### Steps to Reproduce</div>
                                    <div>1. [Step 1]</div>
                                    <div>2. [Step 2]</div>
                                    <div className="mt-4 text-cyan-400">### Proof of Concept</div>
                                    <div className="p-2 bg-white/5 rounded border border-white/10 text-gray-500">
                                        \`\`\`<br />
                                        [Payload or command string]<br />
                                        \`\`\`
                                    </div>
                                    <div className="mt-4 text-cyan-400">### Remediation</div>
                                    <div>[Recommended fix or mitigation]</div>
                                </div>
                                <button
                                    onClick={() => {
                                        const text = `## [FINDING TITLE]\n\n**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]\n**CVSS Score:** [X.X] ([CVSS VECTOR])\n\n### Description\n[Technical description...]\n\n### Steps to Reproduce\n1. [Step 1]\n2. [Step 2]\n\n### Proof of Concept\n\`\`\`\n[Payload...]\n\`\`\`\n\n### Remediation\n[Recommended fix...]`;
                                        navigator.clipboard.writeText(text);
                                        alert("Copied!");
                                    }}
                                    className="mt-6 w-full py-4 bg-white/5 hover:bg-white/10 rounded-xl font-bold transition-all flex items-center justify-center gap-2"
                                >
                                    <Clipboard size={18} /> Copy Full Schema
                                </button>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Modal for Details */}
                <AnimatePresence>
                    {selectedFinding && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-[#0a0a0f]/90 backdrop-blur-sm"
                            onClick={() => setSelectedFinding(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.9, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.9, opacity: 0 }}
                                className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-[#12121e] rounded-3xl border border-white/10 p-8 shadow-2xl scrollbar-thin"
                                onClick={e => e.stopPropagation()}
                            >
                                <div className="flex justify-between items-start mb-6">
                                    <div>
                                        <h2 className="text-2xl font-bold mb-2">{selectedFinding.title}</h2>
                                        <div className="flex items-center gap-3">
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${selectedFinding.severity === 'Critical' ? 'bg-red-500/20 text-red-500' :
                                                selectedFinding.severity === 'High' ? 'bg-orange-500/20 text-orange-500' :
                                                    selectedFinding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500' : 'bg-green-500/20 text-green-500'
                                                }`}>
                                                {selectedFinding.severity}
                                            </span>
                                            <span className="text-gray-500 text-xs font-mono">CVSS: {selectedFinding.cvss}</span>
                                        </div>
                                    </div>
                                    <button onClick={() => setSelectedFinding(null)} className="p-2 hover:bg-white/5 rounded-full text-gray-500">
                                        <Trash2 size={24} className="rotate-45" />
                                    </button>
                                </div>

                                <div className="space-y-8">
                                    <div className="p-4 rounded-xl bg-black/20 border border-white/5">
                                        <div className="text-[10px] font-bold text-gray-500 uppercase mb-1">Asset</div>
                                        <div className="text-blue-400 truncate">{selectedFinding.asset}</div>
                                    </div>

                                    <section>
                                        <h4 className="text-sm font-bold text-blue-400 mb-2 uppercase tracking-widest">Description</h4>
                                        <p className="text-gray-400 text-sm leading-relaxed whitespace-pre-wrap">{selectedFinding.description}</p>
                                    </section>

                                    <section>
                                        <h4 className="text-sm font-bold text-cyan-400 mb-2 uppercase tracking-widest">Steps to Reproduce</h4>
                                        <div className="p-4 bg-black/40 rounded-xl border border-white/5 font-mono text-xs text-gray-400 whitespace-pre-wrap leading-relaxed">
                                            {selectedFinding.steps}
                                        </div>
                                    </section>

                                    {selectedFinding.poc && (
                                        <section>
                                            <h4 className="text-sm font-bold text-purple-400 mb-2 uppercase tracking-widest">Proof of Concept</h4>
                                            <div className="p-4 bg-black/40 rounded-xl border border-purple-500/20 font-mono text-xs text-purple-300 whitespace-pre-wrap leading-relaxed">
                                                {selectedFinding.poc}
                                            </div>
                                        </section>
                                    )}

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <section>
                                            <h4 className="text-sm font-bold text-orange-400 mb-2 uppercase tracking-widest">Business Impact</h4>
                                            <p className="text-gray-400 text-xs leading-relaxed">{selectedFinding.impact}</p>
                                        </section>
                                        <section>
                                            <h4 className="text-sm font-bold text-green-400 mb-2 uppercase tracking-widest">Remediation</h4>
                                            <p className="text-gray-400 text-xs leading-relaxed">{selectedFinding.remediation}</p>
                                        </section>
                                    </div>
                                </div>

                                <div className="mt-12 flex gap-4">
                                    <button
                                        onClick={() => exportToMarkdown(selectedFinding)}
                                        className="flex-1 bg-green-600 hover:bg-green-700 text-white py-4 rounded-xl font-bold transition-all flex items-center justify-center gap-2"
                                    >
                                        <Download size={20} /> Export Markdown
                                    </button>
                                </div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default FindingReporter;
