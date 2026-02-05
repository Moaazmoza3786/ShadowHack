import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Rocket, GitBranch, Search, Key, Box, Shield,
    Cloud, CheckCircle, XCircle, Play, RotateCcw,
    Terminal, FileText, Download, Copy, AlertTriangle,
    Server, Code, Settings
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- SIMULATOR DATA ---
const PIPELINE_STEPS = [
    { id: 'git', name: 'Source', icon: GitBranch },
    { id: 'sast', name: 'SAST', icon: Search },
    { id: 'secret', name: 'Secrets', icon: Key },
    { id: 'build', name: 'Build', icon: Box },
    { id: 'container', name: 'Image Scan', icon: Shield },
    { id: 'dast', name: 'DAST', icon: Server },
    { id: 'deploy', name: 'Deploy', icon: Cloud }
];

// --- GENERATOR TEMPLATES ---
const CI_TEMPLATES = {
    github: {
        name: 'GitHub Actions',
        header: `name: Secure Pipeline
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3`,
        sast: {
            semgrep: `
      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit`,
            sonar: `
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master`
        },
        secret: {
            gitleaks: `
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2`
        },
        dast: {
            zap: `
  dast:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.example.com'`
        }
    },
    gitlab: {
        name: 'GitLab CI',
        header: `stages:
  - test
  - security
  - build
  - deploy

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml`,
        sast: {
            semgrep: `
semgrep-sast:
  stage: security
  image: returntocorp/semgrep
  script: semgrep ci`,
        },
        secret: {
            trufflehog: `
trufflehog:
  stage: security
  image: trufflehog/trufflehog
  script: trufflehog filesystem .`
        },
        dast: {
            zap: `
zap-dast:
  stage: security
  image: owasp/zap2docker-stable
  script: zap-baseline.py -t https://staging.example.com`
        }
    }
};

const DevSecOpsLab = () => {
    const { toast } = useToast();
    const [activeTab, setActiveTab] = useState('simulator');

    // SIMULATOR STATE
    const [pipelineStatus, setPipelineStatus] = useState('idle'); // idle, running, success, failed
    const [currentStepIndex, setCurrentStepIndex] = useState(-1);
    const [logs, setLogs] = useState([{ time: new Date().toLocaleTimeString(), msg: 'Ready to initialize pipeline...' }]);
    const [findings, setFindings] = useState([]);
    const logsEndRef = useRef(null);

    // GENERATOR STATE
    const [platform, setPlatform] = useState('github');
    const [configOpts, setConfigOpts] = useState({
        sast: true,
        secret: true,
        dast: false,
        container: false
    });

    // --- LOGIC: SIMULATOR ---
    const addLog = (msg, type = 'info') => {
        setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg, type }]);
    };

    const scrollToBottom = () => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [logs]);

    const runPipeline = async () => {
        if (pipelineStatus === 'running') return;

        setPipelineStatus('running');
        setCurrentStepIndex(-1);
        setFindings([]);
        setLogs([{ time: new Date().toLocaleTimeString(), msg: 'Initializing secure pipeline...', type: 'info' }]);

        for (let i = 0; i < PIPELINE_STEPS.length; i++) {
            setCurrentStepIndex(i);
            const step = PIPELINE_STEPS[i];
            addLog(`Starting Stage: ${step.name}...`, 'info');

            await new Promise(r => setTimeout(r, 1500)); // Simulate work

            // Simulation Logic
            if (step.id === 'sast' && Math.random() > 0.7) {
                const fail = Math.random() > 0.5;
                addLog(`SAST: Found ${fail ? 'CRITICAL' : 'Medium'} vulnerability in auth.js`, fail ? 'error' : 'warning');
                setFindings(prev => [...prev, { stage: 'SAST', severity: fail ? 'Critical' : 'Medium', msg: 'SQL Injection pattern detected', file: 'src/auth.js:42' }]);
                if (fail) {
                    setPipelineStatus('failed');
                    addLog('Pipeline Halted: Critical Security Gate Failed', 'error');
                    return;
                }
            }

            if (step.id === 'secret' && Math.random() > 0.8) {
                addLog('SECRETS: Hardcoded AWS Key detected!', 'error');
                setFindings(prev => [...prev, { stage: 'Secrets', severity: 'Critical', msg: 'AWS Access Key exposed', file: 'config/aws.yml' }]);
                setPipelineStatus('failed');
                addLog('Pipeline Halted: Secret Detection Failed', 'error');
                return;
            }

            addLog(`Stage ${step.name} Completed Successfully`, 'success');
        }

        setPipelineStatus('success');
        addLog('DEPLOYMENT SUCCESSFUL: Application is live', 'success');
    };

    // --- LOGIC: GENERATOR ---
    const generateConfig = () => {
        const tmpl = CI_TEMPLATES[platform];
        let content = tmpl.header;

        if (configOpts.sast) {
            content += tmpl.sast.semgrep || tmpl.sast.sonar || '';
        }
        if (configOpts.secret) {
            content += tmpl.secret.gitleaks || tmpl.secret.trufflehog || '';
        }
        if (configOpts.dast) {
            content += tmpl.dast.zap || '';
        }

        return content;
    };

    // --- RENDER ---
    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
                <div className="space-y-2">
                    <h1 className="text-4xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-cyan-500">
                        SECURE PIPELINE ARCHITECT
                    </h1>
                    <p className="text-white/40 font-mono tracking-widest uppercase text-sm">
                        DevSecOps Simulator & CI/CD Generator
                    </p>
                </div>
                <div className="flex gap-4">
                    <button
                        onClick={() => setActiveTab('simulator')}
                        className={`px-4 py-2 rounded-lg font-bold transition-all ${activeTab === 'simulator' ? 'bg-blue-600 text-white' : 'bg-white/5 text-gray-400'}`}
                    >
                        <i className="fas fa-play mr-2"></i> SIMULATOR
                    </button>
                    <button
                        onClick={() => setActiveTab('generator')}
                        className={`px-4 py-2 rounded-lg font-bold transition-all ${activeTab === 'generator' ? 'bg-cyan-600 text-white' : 'bg-white/5 text-gray-400'}`}
                    >
                        <i className="fas fa-code mr-2"></i> CONFIG GENERATOR
                    </button>
                </div>
            </div>

            <AnimatePresence mode="wait">

                {/* TAB: SIMULATOR */}
                {activeTab === 'simulator' && (
                    <motion.div
                        key="simulator"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="grid grid-cols-1 lg:grid-cols-3 gap-8"
                    >
                        {/* LEFT: VISUALIZER */}
                        <div className="lg:col-span-2 space-y-6">
                            <div className="p-8 rounded-2xl bg-white/5 border border-white/10 relative overflow-hidden min-h-[300px] flex items-center justify-center">
                                {/* Pipeline Line */}
                                <div className="absolute top-1/2 left-10 right-10 h-1 bg-white/10 -translate-y-1/2 z-0" />

                                <div className="flex justify-between w-full relative z-10 px-4">
                                    {PIPELINE_STEPS.map((step, idx) => {
                                        let status = 'pending';
                                        if (currentStepIndex > idx) status = 'completed';
                                        if (currentStepIndex === idx) status = pipelineStatus === 'failed' ? 'failed' : 'running';
                                        if (currentStepIndex === idx && pipelineStatus === 'failed') status = 'failed';
                                        if (pipelineStatus === 'success') status = 'completed'; // Override for full success

                                        return (
                                            <div key={step.id} className="flex flex-col items-center gap-3">
                                                <div className={`w-14 h-14 rounded-full flex items-center justify-center border-2 transition-all duration-500 ${status === 'completed' ? 'bg-green-500/20 border-green-500 text-green-500 shadow-[0_0_20px_rgba(34,197,94,0.3)]' :
                                                        status === 'running' ? 'bg-blue-500/20 border-blue-500 text-blue-500 shadow-[0_0_20px_rgba(59,130,246,0.5)] animate-pulse' :
                                                            status === 'failed' ? 'bg-red-500/20 border-red-500 text-red-500 shadow-[0_0_20px_rgba(239,68,68,0.5)]' :
                                                                'bg-black/40 border-white/10 text-gray-600'
                                                    }`}>
                                                    {status === 'completed' ? <CheckCircle size={24} /> :
                                                        status === 'failed' ? <XCircle size={24} /> :
                                                            <step.icon size={24} />}
                                                </div>
                                                <span className={`text-xs font-bold uppercase tracking-wider ${status === 'completed' ? 'text-green-500' :
                                                        status === 'running' ? 'text-blue-500' :
                                                            status === 'failed' ? 'text-red-500' : 'text-gray-600'
                                                    }`}>{step.name}</span>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <button
                                    onClick={runPipeline}
                                    disabled={pipelineStatus === 'running'}
                                    className="py-4 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 font-bold uppercase tracking-widest hover:brightness-110 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                >
                                    <Play size={20} /> Trigger Pipeline
                                </button>
                                <div className="p-4 rounded-xl bg-white/5 border border-white/10 flex items-center justify-between">
                                    <span className="text-gray-400 font-bold uppercase text-xs">Status</span>
                                    <span className={`font-mono font-bold px-3 py-1 rounded ${pipelineStatus === 'success' ? 'bg-green-500/20 text-green-400' :
                                            pipelineStatus === 'failed' ? 'bg-red-500/20 text-red-400' :
                                                pipelineStatus === 'running' ? 'bg-blue-500/20 text-blue-400' :
                                                    'bg-white/10 text-gray-500'
                                        }`}>{pipelineStatus.toUpperCase()}</span>
                                </div>
                            </div>

                            {/* FINDINGS REPORT */}
                            {findings.length > 0 && (
                                <div className="p-6 rounded-2xl bg-red-500/5 border border-red-500/20 animate-slide-up">
                                    <h3 className="text-lg font-bold text-red-400 mb-4 flex items-center gap-2"><AlertTriangle /> Security Findings</h3>
                                    <div className="space-y-3 max-h-[200px] overflow-y-auto pr-2 scrollbar-cyber">
                                        {findings.map((f, i) => (
                                            <div key={i} className="p-3 bg-black/40 rounded-lg border-l-4 border-red-500 flex justify-between items-start">
                                                <div>
                                                    <div className="font-bold text-red-300 text-sm">{f.msg}</div>
                                                    <div className="text-xs text-red-400/60 font-mono mt-1">{f.file}</div>
                                                </div>
                                                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-[10px] font-bold uppercase rounded">{f.severity}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* RIGHT: TERMINAL */}
                        <div className="bg-black/80 rounded-2xl border border-white/10 p-4 font-mono text-xs flex flex-col h-[500px] shadow-2xl">
                            <div className="flex items-center gap-2 text-gray-500 mb-2 pb-2 border-b border-white/10">
                                <Terminal size={14} /> Console Output
                            </div>
                            <div className="flex-1 overflow-y-auto scrollbar-cyber space-y-1">
                                {logs.map((log, i) => (
                                    <div key={i} className={`flex gap-2 ${log.type === 'error' ? 'text-red-400' :
                                            log.type === 'success' ? 'text-green-400' :
                                                'text-blue-300'
                                        }`}>
                                        <span className="opacity-30">[{log.time}]</span>
                                        <span>{log.msg}</span>
                                    </div>
                                ))}
                                <div ref={logsEndRef} />
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* TAB: GENERATOR */}
                {activeTab === 'generator' && (
                    <motion.div
                        key="generator"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="grid grid-cols-1 md:grid-cols-2 gap-8"
                    >
                        <div className="space-y-6">
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-6">
                                <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
                                    <Settings size={20} /> Configuration
                                </h3>

                                <div>
                                    <label className="text-xs font-bold text-gray-500 uppercase mb-2 block">CI Platform</label>
                                    <div className="flex gap-2">
                                        {['github', 'gitlab'].map(p => (
                                            <button
                                                key={p}
                                                onClick={() => setPlatform(p)}
                                                className={`flex-1 py-3 rounded-xl border font-bold capitalize transition-all ${platform === p
                                                        ? 'bg-cyan-600/20 border-cyan-600 text-cyan-400'
                                                        : 'bg-black/20 border-white/10 text-gray-500 hover:border-white/30'
                                                    }`}
                                            >
                                                {p}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                <div className="space-y-3">
                                    <label className="text-xs font-bold text-gray-500 uppercase block">Security Gates</label>
                                    {[
                                        { id: 'sast', label: 'SAST Scanning (Semgrep/Sonar)' },
                                        { id: 'secret', label: 'Secret Detection (TruffleHog)' },
                                        { id: 'dast', label: 'DAST Analysis (OWASP ZAP)' },
                                        { id: 'container', label: 'Container Security (Trivy)' }
                                    ].map(opt => (
                                        <button
                                            key={opt.id}
                                            onClick={() => setConfigOpts(prev => ({ ...prev, [opt.id]: !prev[opt.id] }))}
                                            className={`w-full p-4 rounded-xl border flex items-center justify-between transition-all ${configOpts[opt.id]
                                                    ? 'bg-green-500/10 border-green-500/50 text-green-400'
                                                    : 'bg-black/20 border-white/10 text-gray-500'
                                                }`}
                                        >
                                            <span className="font-bold text-sm">{opt.label}</span>
                                            {configOpts[opt.id] && <CheckCircle size={16} />}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="space-y-2 h-full flex flex-col">
                            <div className="flex justify-between items-center">
                                <label className="text-xs font-bold text-gray-500 uppercase ml-2">Generated YAML</label>
                                <div className="flex gap-2">
                                    <button onClick={() => { navigator.clipboard.writeText(generateConfig()); toast('Config copied!', 'success') }} className="p-2 bg-white/5 hover:bg-white/10 rounded-lg text-gray-400 hover:text-white">
                                        <Copy size={16} />
                                    </button>
                                    <button className="p-2 bg-cyan-600/20 hover:bg-cyan-600/30 rounded-lg text-cyan-400">
                                        <Download size={16} />
                                    </button>
                                </div>
                            </div>
                            <div className="flex-1 bg-black/40 border border-white/10 rounded-2xl p-4 font-mono text-sm text-blue-300 relative group overflow-hidden shadow-inner">
                                <textarea
                                    readOnly
                                    value={generateConfig()}
                                    className="w-full h-full bg-transparent resize-none outline-none"
                                />
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default DevSecOpsLab;
