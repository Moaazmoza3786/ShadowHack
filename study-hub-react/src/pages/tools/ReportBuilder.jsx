import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { FileText, Download, BookOpen, AlertCircle, CheckCircle2, Calculator } from 'lucide-react';

const ReportBuilder = () => {
    const [activeTab, setActiveTab] = useState('builder');
    const [report, setReport] = useState({
        title: '',
        severity: 'Medium',
        description: '',
        steps: '',
        impact: ''
    });
    const [preview, setPreview] = useState(false);

    // CVSS State
    const [cvss, setCvss] = useState({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N'
    });

    const cvssConfig = {
        AV: { label: 'Attack Vector', options: { N: { label: 'Network', val: 0.85 }, A: { label: 'Adjacent', val: 0.62 }, L: { label: 'Local', val: 0.55 }, P: { label: 'Physical', val: 0.2 } } },
        AC: { label: 'Attack Complexity', options: { L: { label: 'Low', val: 0.77 }, H: { label: 'High', val: 0.44 } } },
        PR: { label: 'Privileges Required', options: { N: { label: 'None', val: 0.85 }, L: { label: 'Low', val: 0.62 }, H: { label: 'High', val: 0.27 } } },
        UI: { label: 'User Interaction', options: { N: { label: 'None', val: 0.85 }, R: { label: 'Required', val: 0.62 } } },
        S: { label: 'Scope', options: { U: { label: 'Unchanged', val: 6.42 }, C: { label: 'Changed', val: 7.52 } } },
        C: { label: 'Confidentiality', options: { N: { label: 'None', val: 0 }, L: { label: 'Low', val: 0.22 }, H: { label: 'High', val: 0.56 } } },
        I: { label: 'Integrity', options: { N: { label: 'None', val: 0 }, L: { label: 'Low', val: 0.22 }, H: { label: 'High', val: 0.56 } } },
        A: { label: 'Availability', options: { N: { label: 'None', val: 0 }, L: { label: 'Low', val: 0.22 }, H: { label: 'High', val: 0.56 } } },
    };

    const calculateCvss = () => {
        // Simplified Logic for Demo (Not exact 3.1 spec but close approximation for UI)
        // See https://www.first.org/cvss/v3.0/specification-document#CVSS-v3-0-Equations
        // Implementing actual spec logic briefly:

        try {
            const iscBase = 1 - ((1 - cvssConfig.C.options[cvss.C].val) * (1 - cvssConfig.I.options[cvss.I].val) * (1 - cvssConfig.A.options[cvss.A].val));
            const impact = cvss.S === 'U' ? 6.42 * iscBase : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

            if (impact <= 0) return 0;

            const exploitability = 8.22 * cvssConfig.AV.options[cvss.AV].val * cvssConfig.AC.options[cvss.AC].val *
                (cvss.S === 'U' ? cvssConfig.PR.options[cvss.PR].val : (cvss.PR === 'N' ? 0.85 : (cvss.PR === 'L' ? 0.68 : 0.50))) * // PR logic changes if Scope changed
                cvssConfig.UI.options[cvss.UI].val;

            let score = 0;
            if (cvss.S === 'U') score = Math.min(10, impact + exploitability);
            else score = Math.min(10, 1.08 * (impact + exploitability));

            return Math.ceil(score * 10) / 10;
        } catch (e) { return 0; }
    };

    const generateMD = () => {
        const markdown = `# ${report.title || 'Untitled vulnerability'}

**Severity:** ${report.severity}

## Description
${report.description || 'No description provided.'}

## Steps to Reproduce
${report.steps || 'No steps provided.'}

## Impact
${report.impact || 'No impact analysis provided.'}

## Remediation
Apply input validation and output encoding.
`;
        const blob = new Blob([markdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.title.toLowerCase().replace(/\s+/g, '-') || 'report'}.md`;
        a.click();
    };

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-fade-in">
            <div className="text-center space-y-4">
                <div className="inline-block p-4 bg-blue-500/20 rounded-2xl border border-blue-500/30">
                    <FileText size={48} className="text-blue-500" />
                </div>
                <h1 className="text-4xl font-bold tracking-tighter uppercase font-orbitron">Report Center</h1>
                <p className="text-white/50">Generate professional vulnerability reports or learn best practices.</p>
            </div>

            <div className="flex space-x-2 border-b border-white/10 pb-4">
                <button
                    onClick={() => setActiveTab('builder')}
                    className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${activeTab === 'builder' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-white/40 hover:text-white/60'}`}
                >
                    Report Builder
                </button>
                <button
                    onClick={() => setActiveTab('guide')}
                    className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${activeTab === 'guide' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-white/40 hover:text-white/60'}`}
                >
                    Writing Guide
                </button>
                <button
                    onClick={() => setActiveTab('cvss')}
                    className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${activeTab === 'cvss' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-white/40 hover:text-white/60'}`}
                >
                    CVSS Calculator
                </button>
            </div>

            {activeTab === 'builder' ? (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-white/5 border border-white/10 rounded-2xl p-6 space-y-6"
                >
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="md:col-span-2 space-y-2">
                            <label className="text-xs uppercase text-white/30 font-bold">Vulnerability Title</label>
                            <input
                                type="text"
                                value={report.title}
                                onChange={(e) => setReport({ ...report, title: e.target.value })}
                                className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-blue-400 focus:outline-none focus:border-blue-500/50"
                                placeholder="e.g. Stored XSS on Profile Page"
                            />
                        </div>
                        <div className="space-y-2">
                            <label className="text-xs uppercase text-white/30 font-bold">Severity</label>
                            <select
                                value={report.severity}
                                onChange={(e) => setReport({ ...report, severity: e.target.value })}
                                className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-blue-400 focus:outline-none focus:border-blue-500/50"
                            >
                                <option>Critical</option>
                                <option>High</option>
                                <option>Medium</option>
                                <option>Low</option>
                                <option>Info</option>
                            </select>
                        </div>
                    </div>

                    <div className="space-y-2">
                        <label className="text-xs uppercase text-white/30 font-bold">Description</label>
                        <textarea
                            value={report.description}
                            onChange={(e) => setReport({ ...report, description: e.target.value })}
                            className="w-full h-32 bg-black/40 border border-white/10 rounded-lg p-3 text-blue-400 focus:outline-none focus:border-blue-500/50 resize-none"
                            placeholder="Technical details of the flaw..."
                        />
                    </div>

                    <div className="space-y-2">
                        <label className="text-xs uppercase text-white/30 font-bold">Steps to Reproduce</label>
                        <textarea
                            value={report.steps}
                            onChange={(e) => setReport({ ...report, steps: e.target.value })}
                            className="w-full h-32 bg-black/40 border border-white/10 rounded-lg p-3 text-blue-400 focus:outline-none focus:border-blue-500/50 resize-none"
                            placeholder="1. Navigate to...&#10;2. Inject payload..."
                        />
                    </div>

                    <div className="space-y-2">
                        <label className="text-xs uppercase text-white/30 font-bold">Impact</label>
                        <input
                            type="text"
                            value={report.impact}
                            onChange={(e) => setReport({ ...report, impact: e.target.value })}
                            className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-blue-400 focus:outline-none focus:border-blue-500/50"
                            placeholder="What can an attacker achieve?"
                        />
                    </div>

                    <button
                        onClick={generateMD}
                        className="w-full py-4 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl flex items-center justify-center space-x-2 transition-all"
                    >
                        <Download size={18} />
                        <span>GENERATE MARKDOWN REPORT</span>
                    </button>
                </motion.div>
            ) : activeTab === 'cvss' ? (
                <div className="bg-white/5 border border-white/10 rounded-2xl p-6 space-y-8 animate-fadeIn">
                    <div className="text-center">
                        <div className="inline-block p-4 rounded-full bg-black/40 border-4 border-white/10 mb-4 h-32 w-32 flex items-center justify-center">
                            <div className={`text-4xl font-extrabold ${calculateCvss() >= 9.0 ? 'text-red-500' :
                                calculateCvss() >= 7.0 ? 'text-orange-500' :
                                    calculateCvss() >= 4.0 ? 'text-yellow-500' : 'text-green-500'
                                }`}>
                                {calculateCvss()}
                            </div>
                        </div>
                        <h2 className="text-xl font-bold text-white mb-2">CVSS v3.1 Base Score</h2>
                        <code className="bg-black/50 px-3 py-1 rounded text-xs font-mono text-gray-400">
                            CVSS:3.1/AV:{cvss.AV}/AC:{cvss.AC}/PR:{cvss.PR}/UI:{cvss.UI}/S:{cvss.S}/C:{cvss.C}/I:{cvss.I}/A:{cvss.A}
                        </code>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        {Object.keys(cvssConfig).map(metric => (
                            <div key={metric} className="space-y-2">
                                <label className="text-xs uppercase font-bold text-gray-500 block mb-2">{cvssConfig[metric].label}</label>
                                <div className="space-y-1">
                                    {Object.entries(cvssConfig[metric].options).map(([key, value]) => (
                                        <button
                                            key={key}
                                            onClick={() => setCvss({ ...cvss, [metric]: key })}
                                            className={`w-full text-left px-3 py-2 rounded text-xs font-bold transition-all border ${cvss[metric] === key
                                                ? 'bg-blue-500/20 text-blue-400 border-blue-500/50'
                                                : 'bg-black/20 text-gray-500 border-transparent hover:bg-white/5'
                                                }`}
                                        >
                                            {key} - {value.label}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-6"
                >
                    <div className="bg-white/5 border border-white/10 p-6 rounded-2xl space-y-4">
                        <h3 className="flex items-center space-x-2 text-blue-400 font-bold">
                            <AlertCircle size={20} />
                            <span>Evidence Collection</span>
                        </h3>
                        <ul className="space-y-2 text-sm text-white/60">
                            <li>• Take high-quality screenshots</li>
                            <li>• Include full URLs in the frame</li>
                            <li>• Save full Request/Response pairs</li>
                            <li>• Copy cURL commands for reproduction</li>
                        </ul>
                    </div>
                    <div className="bg-white/5 border border-white/10 p-6 rounded-2xl space-y-4">
                        <h3 className="flex items-center space-x-2 text-green-400 font-bold">
                            <BookOpen size={20} />
                            <span>Writing Structure</span>
                        </h3>
                        <ul className="space-y-2 text-sm text-white/60">
                            <li>• Summary for executives</li>
                            <li>• Technical description</li>
                            <li>• Exact reproduction steps</li>
                            <li>• Business impact analysis</li>
                        </ul>
                    </div>
                </motion.div>
            )}
        </div>
    );
};

export default ReportBuilder;
