import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Terminal, Globe, Code, ChevronLeft, Shield, AlertCircle,
    CheckCircle2, Zap, RefreshCw, Play, Lock, Unlock,
    HelpCircle, Flag, ChevronRight, Eye, EyeOff
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const OWASPPractice = ({ vuln }) => {
    const navigate = useNavigate();
    const terminalRef = useRef(null);

    const [terminalLines, setTerminalLines] = useState([]);
    const [terminalInput, setTerminalInput] = useState('');
    const [currentStage, setCurrentStage] = useState(0);
    const [completedStages, setCompletedStages] = useState([]);
    const [hintsUsed, setHintsUsed] = useState({});
    const [showHint, setShowHint] = useState({});
    const [flagInput, setFlagInput] = useState('');
    const [flagStatus, setFlagStatus] = useState(null); // null | 'correct' | 'wrong'
    const [isSuccess, setIsSuccess] = useState(false);
    const [isSimulating, setIsSimulating] = useState(false);

    const stages = vuln.simulation.stages || [];
    const totalStages = stages.length;

    useEffect(() => {
        document.body.style.overflow = 'hidden';
        return () => { document.body.style.overflow = 'unset'; };
    }, []);

    useEffect(() => {
        const timer = setTimeout(() => {
            addLines([
                `┌──(kali@cyber-range)-[~/owasp/${vuln.id}]`,
                `└─$ echo "Target: ${vuln.simulation.targetSite}"`,
                `Target: ${vuln.simulation.targetSite}`,
                `┌──(kali@cyber-range)-[~/owasp/${vuln.id}]`,
                `└─$ # Stage 1: ${stages[0]?.title || 'Recon'} — ${stages[0]?.description || ''}`,
                `└─$ # Type 'hint' for a hint, 'run' to simulate the attack, 'flag <FLAG>' to submit`
            ]);
        }, 400);
        return () => clearTimeout(timer);
    }, [vuln]);

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [terminalLines]);

    const addLines = (lines) => {
        setTerminalLines(prev => [...prev, ...lines]);
    };

    const handleTerminalCommand = (e) => {
        if (e.key !== 'Enter' || !terminalInput.trim()) return;
        const cmd = terminalInput.trim();
        setTerminalInput('');

        addLines([`┌──(kali@cyber-range)-[~/owasp/${vuln.id}]`, `└─$ ${cmd}`]);

        if (cmd === 'hint') {
            const stage = stages[currentStage];
            if (stage) {
                setHintsUsed(p => ({ ...p, [currentStage]: true }));
                addLines([`[HINT] ${stage.hint}`]);
            }
        } else if (cmd === 'run' || cmd === 'exploit') {
            runSimulation();
        } else if (cmd.startsWith('flag ')) {
            const submitted = cmd.replace('flag ', '').trim();
            checkFlag(submitted);
        } else if (cmd === 'clear') {
            setTerminalLines([]);
        } else if (cmd === 'stages') {
            stages.forEach((s, i) => {
                const done = completedStages.includes(i);
                addLines([`  [${done ? '✓' : i === currentStage ? '→' : ' '}] Stage ${s.id}: ${s.title} — ${s.description}`]);
            });
        } else if (cmd === 'help') {
            addLines([
                '  run / exploit  — Simulate the attack for current stage',
                '  hint           — Show hint for current stage',
                '  stages         — List all stages and progress',
                '  flag <FLAG>    — Submit the capture flag',
                '  clear          — Clear terminal',
            ]);
        } else {
            addLines([`bash: ${cmd}: command not found`, `Try 'help' for available commands`]);
        }
    };

    const runSimulation = () => {
        if (isSimulating) return;
        setIsSimulating(true);

        const logs = vuln.simulation.terminalLogs || [];
        const stageLog = logs.slice(
            Math.floor((currentStage / totalStages) * logs.length),
            Math.floor(((currentStage + 1) / totalStages) * logs.length) + 2
        );

        let i = 0;
        const interval = setInterval(() => {
            if (i < stageLog.length) {
                addLines([stageLog[i]]);
                i++;
            } else {
                clearInterval(interval);
                setIsSimulating(false);
                const newCompleted = [...completedStages, currentStage];
                setCompletedStages(newCompleted);
                addLines([
                    `[✓] Stage ${currentStage + 1} complete: ${stages[currentStage]?.title}`,
                    currentStage + 1 < totalStages
                        ? `[→] Next: Stage ${currentStage + 2} — ${stages[currentStage + 1]?.title}`
                        : `[★] All stages complete! Submit the flag to finish.`
                ]);
                if (currentStage + 1 < totalStages) {
                    setCurrentStage(prev => prev + 1);
                }
            }
        }, 350);
    };

    const checkFlag = (submitted) => {
        if (submitted === vuln.simulation.flag) {
            setFlagStatus('correct');
            addLines([`[★] FLAG ACCEPTED: ${submitted}`, `[✓] Mission Complete! +${vuln.xpReward || 100} XP`]);
            setTimeout(() => setIsSuccess(true), 800);
        } else {
            setFlagStatus('wrong');
            addLines([`[✗] Incorrect flag. Keep trying.`]);
            setTimeout(() => setFlagStatus(null), 2000);
        }
    };

    const progressPct = totalStages > 0 ? (completedStages.length / totalStages) * 100 : 0;

    return (
        <div className="fixed inset-0 z-[2000] bg-[#050505] flex flex-col overflow-hidden">
            {/* Top Bar */}
            <div className="h-14 border-b border-white/10 bg-dark-950 px-6 flex items-center justify-between flex-shrink-0">
                <div className="flex items-center gap-4">
                    <button onClick={() => navigate(`/owasp-range/${vuln.id}/learn`)}
                        className="p-2 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white transition-all">
                        <ChevronLeft size={18} />
                    </button>
                    <div className="h-5 w-px bg-white/10" />
                    <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-lg bg-red-500/20 flex items-center justify-center">
                            <Shield size={14} className="text-red-500" />
                        </div>
                        <span className="text-xs font-black text-white italic uppercase tracking-tighter">
                            {vuln.title} <span className="text-gray-600 mx-1">/</span>
                            <span className="text-gray-400">Practice</span>
                        </span>
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_6px_#10b981] ml-1" />
                    </div>
                </div>

                {/* Progress */}
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Progress</span>
                        <div className="w-32 h-1.5 bg-white/5 rounded-full overflow-hidden">
                            <motion.div className="h-full bg-primary-500 rounded-full"
                                animate={{ width: `${progressPct}%` }} transition={{ duration: 0.5 }} />
                        </div>
                        <span className="text-[10px] font-black text-gray-400">{completedStages.length}/{totalStages}</span>
                    </div>
                    <div className="px-2 py-1 rounded-lg bg-orange-500/10 border border-orange-500/20 text-[10px] font-black text-orange-500 uppercase tracking-widest">
                        {vuln.difficulty}
                    </div>
                </div>
            </div>

            {/* Main Layout */}
            <div className="flex-1 flex overflow-hidden">

                {/* Left: Mission Panel */}
                <div className="w-72 border-r border-white/10 bg-dark-900/30 flex flex-col overflow-y-auto scrollbar-none flex-shrink-0">
                    {/* Stages */}
                    <div className="p-4 border-b border-white/5">
                        <div className="flex items-center gap-2 mb-3">
                            <Flag size={14} className="text-primary-500" />
                            <span className="text-[10px] font-black uppercase tracking-widest text-primary-500">Stages</span>
                        </div>
                        <div className="space-y-2">
                            {stages.map((stage, i) => {
                                const done = completedStages.includes(i);
                                const active = i === currentStage;
                                return (
                                    <div key={i} className={`p-3 rounded-xl border transition-all ${
                                        done ? 'bg-emerald-500/10 border-emerald-500/20' :
                                        active ? 'bg-primary-500/10 border-primary-500/30' :
                                        'bg-white/3 border-white/5 opacity-50'
                                    }`}>
                                        <div className="flex items-center gap-2 mb-1">
                                            <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 ${
                                                done ? 'bg-emerald-500' : active ? 'bg-primary-500' : 'bg-white/10'
                                            }`}>
                                                {done ? <CheckCircle2 size={12} className="text-white" /> :
                                                 active ? <ChevronRight size={12} className="text-white" /> :
                                                 <Lock size={10} className="text-gray-500" />}
                                            </div>
                                            <span className={`text-[10px] font-black uppercase tracking-widest ${
                                                done ? 'text-emerald-400' : active ? 'text-white' : 'text-gray-600'
                                            }`}>{stage.title}</span>
                                        </div>
                                        <p className="text-[10px] text-gray-500 italic pl-7 leading-relaxed">{stage.description}</p>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Hints */}
                    <div className="p-4 border-b border-white/5">
                        <div className="flex items-center gap-2 mb-3">
                            <HelpCircle size={14} className="text-yellow-500" />
                            <span className="text-[10px] font-black uppercase tracking-widest text-yellow-500">Hints</span>
                        </div>
                        {stages.map((stage, i) => (
                            <div key={i} className="mb-2">
                                <button onClick={() => {
                                    setShowHint(p => ({ ...p, [i]: !p[i] }));
                                    setHintsUsed(p => ({ ...p, [i]: true }));
                                }}
                                    className="w-full flex items-center justify-between p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-all text-[10px] font-black text-gray-400 uppercase tracking-widest">
                                    <span>Stage {i + 1} Hint</span>
                                    {showHint[i] ? <EyeOff size={12} /> : <Eye size={12} />}
                                </button>
                                <AnimatePresence>
                                    {showHint[i] && (
                                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            className="overflow-hidden">
                                            <p className="text-[10px] text-yellow-400/80 italic p-2 leading-relaxed">{stage.hint}</p>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        ))}
                    </div>

                    {/* Mission Info */}
                    <div className="p-4 space-y-3">
                        <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                            <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest mb-1">Target</div>
                            <div className="text-[10px] font-mono text-gray-300 break-all">{vuln.simulation.targetSite}</div>
                        </div>
                        <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                            <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest mb-1">Severity</div>
                            <div className="text-xs font-bold text-red-400">{vuln.severity} (CVSS {vuln.cvss})</div>
                        </div>
                        <div className="p-3 rounded-xl bg-white/5 border border-white/5">
                            <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest mb-1">Defense</div>
                            <div className="text-[10px] text-blue-400/80 italic leading-relaxed">{vuln.defense}</div>
                        </div>
                    </div>
                </div>

                {/* Center: Terminal */}
                <div className="flex-1 flex flex-col min-w-0 bg-[#080808]">
                    {/* Terminal Header */}
                    <div className="h-8 bg-dark-900 px-4 flex items-center justify-between border-b border-white/5 flex-shrink-0">
                        <div className="flex items-center gap-2">
                            <Terminal size={12} className="text-emerald-500" />
                            <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                                kali@cyber-range: ~/owasp/{vuln.id}
                            </span>
                        </div>
                        <div className="flex items-center gap-3">
                            <button onClick={runSimulation} disabled={isSimulating}
                                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-primary-600/20 border border-primary-500/30 text-primary-400 text-[10px] font-black uppercase tracking-widest hover:bg-primary-500/30 transition-all disabled:opacity-40">
                                {isSimulating ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} className="fill-current" />}
                                {isSimulating ? 'Running...' : 'Run Stage'}
                            </button>
                        </div>
                    </div>

                    {/* Terminal Output */}
                    <div ref={terminalRef}
                        className="flex-1 p-4 font-mono text-[11px] leading-relaxed overflow-y-auto scrollbar-cyber bg-[#0a0a0a]">
                        {terminalLines.map((line, i) => (
                            <div key={i} className={
                                line.includes('[✓]') || line.includes('SUCCESS') ? 'text-emerald-400 font-bold' :
                                line.includes('[✗]') || line.includes('ALERT') || line.includes('⚠️') ? 'text-red-400' :
                                line.includes('[★]') ? 'text-yellow-400 font-bold' :
                                line.includes('[→]') || line.includes('[HINT]') ? 'text-blue-400' :
                                line.includes('FOUND') || line.includes('EXPLOIT') || line.includes('CRACK') ? 'text-orange-400' :
                                line.startsWith('┌') || line.startsWith('└') ? 'text-emerald-500' :
                                'text-gray-400'
                            }>{line}</div>
                        ))}
                        <div className="flex items-center gap-2 mt-1">
                            <span className="text-emerald-500 font-bold">└─$</span>
                            <input value={terminalInput}
                                onChange={e => setTerminalInput(e.target.value)}
                                onKeyDown={handleTerminalCommand}
                                className="flex-1 bg-transparent text-white outline-none font-mono text-[11px] caret-emerald-500"
                                placeholder="Type 'help' for commands..."
                                autoFocus />
                        </div>
                    </div>
                </div>

                {/* Right: Code Editor */}
                <div className="w-[420px] border-l border-white/10 bg-black flex flex-col flex-shrink-0">
                    <div className="h-10 bg-dark-900 px-4 flex items-center justify-between border-b border-white/5 flex-shrink-0">
                        <div className="flex items-center gap-2">
                            <Code size={14} className="text-primary-500" />
                            <span className="text-[10px] font-black uppercase tracking-widest text-white italic">Vulnerable Code</span>
                        </div>
                    </div>

                    <div className="flex-1 p-4 font-mono text-[11px] leading-relaxed bg-[#0d1117] overflow-auto scrollbar-cyber">
                        <div className="flex gap-3 text-gray-600 mb-4 select-none border-b border-white/5 pb-3">
                            <span className="text-primary-500 font-bold border-b-2 border-primary-500 pb-1 text-[10px] uppercase tracking-widest">vulnerable.js</span>
                            <span className="hover:text-gray-400 cursor-pointer text-[10px] uppercase tracking-widest pb-1">server.config</span>
                        </div>
                        <pre className="text-gray-400">
                            {vuln.simulation.vulnerableCode.split('\n').map((line, i) => (
                                <div key={i} className="flex gap-3 group hover:bg-white/[0.02] rounded px-1">
                                    <span className="w-6 text-gray-700 text-right select-none flex-shrink-0">{i + 1}</span>
                                    <span className={
                                        line.includes('⚠️') || line.includes('VULNERABLE') ? 'text-red-400 italic' :
                                        line.startsWith('//') || line.startsWith('#') ? 'text-gray-600 italic' :
                                        'text-gray-300'
                                    }>{line}</span>
                                </div>
                            ))}
                        </pre>
                    </div>

                    {/* Flag Submission */}
                    <div className="p-4 border-t border-white/10 bg-dark-950 space-y-3">
                        <div className="flex items-center gap-2 mb-1">
                            <Flag size={12} className="text-yellow-500" />
                            <span className="text-[10px] font-black uppercase tracking-widest text-yellow-500">Submit Flag</span>
                        </div>
                        <div className="flex gap-2">
                            <input value={flagInput}
                                onChange={e => setFlagInput(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && checkFlag(flagInput)}
                                placeholder="FLAG{...}"
                                className={`flex-1 h-10 bg-white/5 border rounded-xl px-3 font-mono text-xs text-white outline-none transition-all ${
                                    flagStatus === 'correct' ? 'border-emerald-500/50 bg-emerald-500/10' :
                                    flagStatus === 'wrong' ? 'border-red-500/50 bg-red-500/10' :
                                    'border-white/10 focus:border-primary-500/50'
                                }`} />
                            <button onClick={() => checkFlag(flagInput)}
                                className="h-10 px-4 rounded-xl bg-yellow-500/20 border border-yellow-500/30 text-yellow-400 text-[10px] font-black uppercase tracking-widest hover:bg-yellow-500/30 transition-all">
                                Submit
                            </button>
                        </div>
                        {flagStatus === 'wrong' && (
                            <p className="text-[10px] text-red-400 italic">Incorrect flag. Keep investigating.</p>
                        )}
                    </div>
                </div>
            </div>

            {/* Success Overlay */}
            <AnimatePresence>
                {isSuccess && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        className="fixed inset-0 z-[100] bg-black/85 backdrop-blur-md flex items-center justify-center">
                        <motion.div initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }}
                            className="text-center space-y-6 max-w-md p-10 rounded-3xl bg-dark-900 border border-emerald-500/30 shadow-[0_0_60px_rgba(16,185,129,0.15)]">
                            <div className="w-20 h-20 rounded-full bg-emerald-500 flex items-center justify-center mx-auto shadow-[0_0_30px_rgba(16,185,129,0.5)]">
                                <CheckCircle2 size={40} className="text-white" />
                            </div>
                            <div className="space-y-2">
                                <div className="text-[10px] font-black text-emerald-500 uppercase tracking-[0.3em]">Mission Complete</div>
                                <h3 className="text-3xl font-black text-white italic uppercase tracking-tighter">{vuln.title}</h3>
                                <p className="text-gray-400 italic text-sm">
                                    You successfully exploited and remediated the vulnerability.
                                </p>
                            </div>
                            <div className="flex items-center justify-center gap-4 py-2">
                                <div className="text-center">
                                    <div className="text-2xl font-black text-yellow-400">+{vuln.xpReward || 100}</div>
                                    <div className="text-[9px] text-gray-500 uppercase tracking-widest">XP Earned</div>
                                </div>
                                <div className="w-px h-10 bg-white/10" />
                                <div className="text-center">
                                    <div className="text-2xl font-black text-blue-400">{hintsUsed ? Object.keys(hintsUsed).length : 0}</div>
                                    <div className="text-[9px] text-gray-500 uppercase tracking-widest">Hints Used</div>
                                </div>
                                <div className="w-px h-10 bg-white/10" />
                                <div className="text-center">
                                    <div className="text-2xl font-black text-emerald-400">{totalStages}</div>
                                    <div className="text-[9px] text-gray-500 uppercase tracking-widest">Stages Done</div>
                                </div>
                            </div>
                            <div className="flex flex-col gap-3">
                                <button onClick={() => navigate('/owasp-range')}
                                    className="w-full h-12 rounded-xl bg-white text-black font-black uppercase tracking-widest text-xs hover:bg-gray-200 transition-all">
                                    Return to Range
                                </button>
                                <button onClick={() => setIsSuccess(false)}
                                    className="w-full h-12 rounded-xl bg-white/5 text-gray-400 font-black uppercase tracking-widest text-xs hover:bg-white/10 transition-all">
                                    Review Environment
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default OWASPPractice;
