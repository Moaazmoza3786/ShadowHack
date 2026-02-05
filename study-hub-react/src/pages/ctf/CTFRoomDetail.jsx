import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAppContext } from '../../context/AppContext';
import { ctfRooms } from '../../data/ctf-rooms';
import {
    Flag,
    Terminal,
    Shield,
    Trophy,
    ChevronLeft,
    Play,
    AlertCircle,
    CheckCircle2,
    Lock,
    Command,
    ChevronRight,
    Search,
    Zap,
    RotateCcw,
    Activity,
    Clock,
    Fingerprint,
    Database
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { WebSimulator, TerminalSimulator } from './labs/LabComponents';
import { useLabManager } from '../../hooks/useLabManager';

const GlitchText = ({ children, className = "" }) => (
    <div className={`relative inline-block ${className}`}>
        <span className="relative z-10">{children}</span>
        <span className="absolute top-0 left-0 -z-10 text-red-500 opacity-50 animate-glitch-1 clip-path-glitch">{children}</span>
        <span className="absolute top-0 left-0 -z-10 text-blue-500 opacity-50 animate-glitch-2 clip-path-glitch">{children}</span>
    </div>
);

const BOOT_LINES = [
    "> INITIALIZING NEURAL BRIDGE...",
    "> LOADING KERNEL MODULES (v8.2.4)...",
    "> ESTABLISHING VPN TUNNEL...",
    "> MOUNTING VIRTUAL FILESYSTEM...",
    "> BYPASSING FIREWALL (LEVEL-4)...",
    "> HANDSHAKE SUCCESSFUL.",
    "> TARGET ACQUIRED: 10.10.X.X",
    "> SESSION READY."
];

const BootSequence = ({ onComplete }) => {
    const [lines, setLines] = useState([]);

    useEffect(() => {
        let i = 0;
        const interval = setInterval(() => {
            if (i < BOOT_LINES.length) {
                setLines(prev => [...prev, BOOT_LINES[i]]);
                i++;
            } else {
                clearInterval(interval);
                setTimeout(onComplete, 1000);
            }
        }, 300);
        return () => clearInterval(interval);
    }, [onComplete]);

    return (
        <div className="absolute inset-0 bg-black z-[100] flex flex-col p-12 font-mono text-[10px] space-y-2 overflow-hidden">
            <div className="flex items-center gap-4 border-b border-white/10 pb-4 mb-4">
                <div className="w-3 h-3 rounded-full bg-accent-500 animate-pulse" />
                <span className="text-accent-500 font-black tracking-widest">BOOT SEQUENCE</span>
            </div>
            {lines.map((line, idx) => (
                <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={line?.includes('SUCCESS') || line?.includes('READY') ? 'text-green-500' : 'text-gray-500'}
                >
                    {line}
                </motion.div>
            ))}
            <div className="absolute bottom-12 right-12 scale-150">
                <RotateCcw className="animate-spin text-accent-500/20" size={48} />
            </div>
        </div>
    );
};

const DataCascade = () => {
    const chars = "0123456789ABCDEFHIJKLMNOPQRSTUVWXYZ%$#@!&*";
    const [cols, setCols] = useState([]);

    useEffect(() => {
        const newCols = Array.from({ length: 40 }).map(() => ({
            id: Math.random(),
            chars: Array.from({ length: 20 }).map(() => chars[Math.floor(Math.random() * chars.length)]),
            left: `${Math.floor(Math.random() * 100)}%`,
            delay: Math.random() * 2,
            duration: 1 + Math.random() * 2
        }));
        setCols(newCols);
    }, []);

    return (
        <div className="fixed inset-0 pointer-events-none z-[1000] overflow-hidden opacity-40">
            {cols.map(col => (
                <div
                    key={col.id}
                    className="absolute top-0 flex flex-col font-mono text-green-500 text-[10px]"
                    style={{
                        left: col.left,
                        animation: `code-drop ${col.duration}s linear infinite`,
                        animationDelay: `${col.delay}s`
                    }}
                >
                    {col.chars.map((char, i) => (
                        <span key={i} className={i === col.chars.length - 1 ? "text-white shadow-[0_0_10px_#fff]" : ""}>
                            {char}
                        </span>
                    ))}
                </div>
            ))}
        </div>
    );
};

const CTFRoomDetail = () => {
    const { roomId } = useParams();
    const { language, user, solveCTFTask, unlockHint } = useAppContext();
    const [room, setRoom] = useState(null);
    const [answers, setAnswers] = useState({});
    const [showWriteup, setShowWriteup] = useState(false);

    // Real Lab Manager Hook
    const {
        status,
        isLoading,
        connectionInfo,
        startLab,
        stopLab,
        terminalOutput: labLogs
    } = useLabManager(roomId);

    const isMachineRunning = status === 'running';
    const isStarting = status === 'starting' || isLoading;
    const machineIP = connectionInfo?.ip || null;
    const machinePort = connectionInfo?.port || null;
    const [timeLeft, setTimeLeft] = useState(3600);
    const [showBootSequence, setShowBootSequence] = useState(false);
    const [logs, setLogs] = useState([]);

    // Sync progress from global user state
    const solvedTasks = user.solvedCTFTasks
        .filter(id => id.startsWith(`${roomId}-`))
        .map(id => parseInt(id.split('-').pop()));

    const isRoomCaptured = room?.tasks.every(t => solvedTasks.includes(t.id));

    const totalPoints = room?.tasks
        .filter(t => solvedTasks.includes(t.id))
        .reduce((sum, t) => sum + t.points, 0) || 0;

    // Machine Timer & Logs
    useEffect(() => {
        let timer;
        let logInterval;

        if (isMachineRunning) {
            timer = setInterval(() => {
                setTimeLeft(prev => (prev > 0 ? prev - 1 : 0));
            }, 1000);

            const possibleLogs = [
                'Incoming connection from 10.10.x.x',
                'HTTP GET /robots.txt 200',
                'System: Auth failure for user "admin"',
                'Network: Port scan detected on 80, 443',
                'Kernel: CPU spikes detected (Load: 0.85)',
                'Log: cron job executed successfully',
                'Secure: Firewall rule triggered (DROPPED)',
                'Storage: SSD health check passed (100%)'
            ];

            logInterval = setInterval(() => {
                const randomLog = possibleLogs[Math.floor(Math.random() * possibleLogs.length)];
                setLogs(prev => [
                    { time: new Date().toLocaleTimeString(), text: randomLog },
                    ...prev.slice(0, 5)
                ]);
            }, 5000);
        } else {
            setTimeLeft(3600);
            setLogs([]);
        }

        return () => {
            clearInterval(timer);
            clearInterval(logInterval);
        };
    }, [isMachineRunning]);

    const formatTime = (seconds) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
    };

    useEffect(() => {
        let foundRoom = null;
        Object.values(ctfRooms).forEach(categoryRooms => {
            const match = categoryRooms.find(r => r.id === roomId);
            if (match) foundRoom = match;
        });
        setRoom(foundRoom);
    }, [roomId]);

    const [submissionStatus, setSubmissionStatus] = useState({}); // { taskId: 'success' | 'error' }

    const handleAnswerSubmit = (taskId) => {
        const task = room.tasks.find(t => t.id === taskId);
        const userAnswer = answers[taskId]?.toLowerCase().trim();
        const correctAnswer = task.answer?.toLowerCase().trim();

        if (userAnswer === correctAnswer) {
            const roomTitle = language === 'ar' ? room.title.ar : room.title.en;
            solveCTFTask(room.id, task, roomTitle);
            setSubmissionStatus(prev => ({ ...prev, [taskId]: 'success' }));
            setTimeout(() => {
                setSubmissionStatus(prev => {
                    const next = { ...prev };
                    delete next[taskId];
                    return next;
                });
            }, 3000);
        } else {
            setSubmissionStatus(prev => ({ ...prev, [taskId]: 'error' }));
            setTimeout(() => {
                setSubmissionStatus(prev => {
                    const next = { ...prev };
                    delete next[taskId];
                    return next;
                });
            }, 2000);
        }
    };

    const toggleMachine = () => {
        if (isMachineRunning) {
            stopLab();
        } else {
            setShowBootSequence(true);
            // The handleBootComplete will trigger startLab
        }
    };

    const handleBootComplete = () => {
        setShowBootSequence(false);
        startLab();
    };

    if (!room) {
        return (
            <div className="min-h-[60vh] flex flex-col items-center justify-center space-y-6">
                <div className="w-20 h-20 rounded-full bg-red-500/10 flex items-center justify-center text-red-500 animate-pulse">
                    <AlertCircle size={40} />
                </div>
                <h2 className="text-2xl font-black text-white uppercase italic tracking-widest">
                    {language === 'ar' ? 'التحدي غير موجود' : 'Challenge Not Found'}
                </h2>
                <Link to="/ctf" className="px-8 py-3 rounded-full bg-white/5 border border-white/10 text-gray-400 hover:text-white transition-all text-xs font-bold uppercase tracking-widest">
                    {language === 'ar' ? 'العودة للميدان' : 'Back to Arena'}
                </Link>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto space-y-12 pb-32 relative">
            <div className="fixed inset-0 pointer-events-none z-[9999] opacity-[0.03] animate-noise bg-[url('https://grainy-gradients.vercel.app/noise.svg')]" />
            {Object.values(submissionStatus).includes('success') && <DataCascade />}

            {/* Navigation Header */}
            <div className="flex items-center justify-between">
                <Link to="/ctf" className="flex items-center gap-2 text-gray-500 hover:text-accent-500 transition-colors group">
                    <ChevronLeft size={20} className="group-hover:-translate-x-1 transition-transform" />
                    <span className="text-[10px] font-black uppercase tracking-widest text-white">Back to Arena</span>
                </Link>
                <div className="flex items-center gap-6">
                    <div className="px-4 py-2 rounded-xl bg-dark-800/40 border border-white/5 flex items-center gap-3">
                        <Trophy className="text-yellow-500" size={16} />
                        <span className="text-xs font-black text-white italic">{totalPoints} / {room.points} PTS</span>
                    </div>
                </div>
            </div>

            {/* Room Hero */}
            <div className="relative p-12 md:p-16 rounded-[3.5rem] bg-gradient-to-br from-dark-800 to-dark-900 border border-white/5 overflow-hidden">
                <div className="absolute inset-0 bg-cyber-grid opacity-10" />
                <div className="relative z-10 flex flex-col md:flex-row gap-12 items-center">
                    <div className="w-40 h-40 rounded-[2.5rem] bg-accent-500/10 border border-accent-500/20 flex items-center justify-center text-accent-500 shadow-[0_0_50px_rgba(255,0,85,0.1)]">
                        <Terminal size={64} />
                    </div>
                    <div className="flex-1 text-center md:text-left space-y-4">
                        <div className="flex flex-wrap justify-center md:justify-start gap-4">
                            <span className="px-3 py-1 rounded-full bg-accent-500/10 border border-accent-500/20 text-[10px] font-black text-accent-500 uppercase tracking-widest">
                                {room.difficulty}
                            </span>
                            <span className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-black text-gray-500 uppercase tracking-widest">
                                {room.estimatedTime}
                            </span>
                            {machineIP && (
                                <>
                                    <span className="px-4 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-[10px] font-black text-green-500 animate-pulse uppercase tracking-[0.2em]">
                                        {machineIP}:{machinePort}
                                    </span>
                                    <span className="px-4 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-[10px] font-black text-cyan-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                        <RotateCcw size={10} className="animate-spin" />
                                        {formatTime(timeLeft)}
                                    </span>
                                </>
                            )}
                        </div>
                        <h1 className="text-5xl md:text-7xl font-black text-white italic uppercase tracking-tighter leading-none">
                            <GlitchText>{language === 'ar' ? room.title.ar : room.title.en}</GlitchText>
                        </h1>
                        <p className="text-gray-400 text-sm md:text-base font-medium max-w-2xl leading-relaxed">
                            {language === 'ar' ? room.description.ar : room.description.en}
                        </p>

                        <div className="pt-4">
                            {room.labConfig ? (
                                <button
                                    onClick={toggleMachine}
                                    disabled={isStarting}
                                    className={`px-10 py-5 rounded-3xl font-black uppercase tracking-[0.2em] italic text-xs transition-all flex items-center gap-4 ${isMachineRunning
                                        ? 'bg-red-500/20 border border-red-500/30 text-red-500 hover:bg-red-500/30'
                                        : 'bg-accent-500 text-white shadow-[0_20px_40px_rgba(255,0,85,0.3)] hover:scale-105'
                                        } ${isStarting ? 'opacity-50 cursor-wait' : ''}`}
                                >
                                    {isStarting ? (
                                        <RotateCcw className="animate-spin" size={18} />
                                    ) : isMachineRunning ? (
                                        <AlertCircle size={18} />
                                    ) : (
                                        <Play size={18} fill="currentColor" />
                                    )}
                                    {isStarting ? 'Allocating Resources...' : isMachineRunning ? 'Terminate Machine' : 'Start Machine'}
                                </button>
                            ) : (
                                <div className="flex items-center gap-3 py-2">
                                    <div className="w-2 h-2 rounded-full bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]" />
                                    <span className="text-[10px] font-black uppercase tracking-widest text-cyan-500/80">
                                        {language === 'ar' ? 'تحدي بيانات ثابتة: لا يتطلب تشغيل آلة' : 'Static Data Challenge: No Deployment Required'}
                                    </span>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
                <div className="lg:col-span-2 space-y-12">
                    <section className="space-y-6">
                        <div className="flex items-center gap-3">
                            <Command className="text-accent-500" size={20} />
                            <h2 className="text-xl font-black text-white uppercase italic tracking-widest">The Scenario</h2>
                        </div>
                        <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 leading-relaxed text-gray-300">
                            {language === 'ar'
                                ? (room.scenario?.ar || room.description.ar)
                                : (room.scenario?.en || room.description.en)}
                        </div>
                    </section>

                    {room.intel && (
                        <section className="space-y-6">
                            <div className="flex items-center gap-3">
                                <Fingerprint className="text-accent-500" size={20} />
                                <h2 className="text-xl font-black text-white uppercase italic tracking-widest">Tactical Intel</h2>
                            </div>
                            <div className="relative group overflow-hidden rounded-[2.5rem] bg-black border border-accent-500/20 shadow-[0_0_30px_rgba(255,0,85,0.05)]">
                                <div className="absolute inset-0 bg-cyber-grid opacity-5 group-hover:opacity-10 transition-opacity" />
                                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-accent-500/40 to-transparent" />

                                <div className="relative p-8 flex flex-col md:flex-row gap-8 items-start">
                                    <div className="w-16 h-16 rounded-2xl bg-accent-500/10 border border-accent-500/20 flex items-center justify-center text-accent-500 shrink-0">
                                        <Database size={32} />
                                    </div>
                                    <div className="flex-1 space-y-4">
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                                <span className="text-[10px] font-black uppercase tracking-[0.2em] text-accent-500">DECRYPTED TRANSMISSION</span>
                                            </div>
                                            <span className="text-[8px] font-mono text-gray-700">SIGNAL_STRENGTH: 100%</span>
                                        </div>
                                        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/5 font-mono">
                                            <p className="text-xl md:text-2xl font-black text-white selection:bg-accent-500 selection:text-white leading-relaxed tracking-tight">
                                                {language === 'ar' ? room.intel.ar : room.intel.en}
                                            </p>
                                        </div>
                                        <div className="flex items-center gap-4 text-[8px] font-black uppercase tracking-[0.2em] text-gray-700">
                                            <span>Origin: Unknown</span>
                                            <span>Format: RAW_HEX</span>
                                            <span>Security: Cleared</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </section>
                    )}

                    {room.labConfig && (
                        <section className="space-y-6">
                            <div className="flex items-center gap-3">
                                <Terminal className="text-accent-500" size={20} />
                                <h2 className="text-xl font-black text-white uppercase italic tracking-widest">Lab Terminal</h2>
                            </div>

                            {!isMachineRunning ? (
                                <div className="aspect-video rounded-[3rem] bg-dark-800/50 border-2 border-dashed border-white/5 flex flex-col items-center justify-center text-center p-12 gap-4 relative overflow-hidden group">
                                    {showBootSequence && <BootSequence onComplete={handleBootComplete} />}

                                    {/* Matrix-like data stream background */}
                                    <div className="absolute inset-0 opacity-[0.03] pointer-events-none font-mono text-[8px] flex flex-wrap gap-2 p-4 overflow-hidden leading-none select-none">
                                        {Array.from({ length: 200 }).map((_, i) => (
                                            <span key={i} className="animate-pulse" style={{ animationDelay: `${i * 0.1}s` }}>
                                                {Math.random() > 0.5 ? '1' : '0'}
                                            </span>
                                        ))}
                                    </div>

                                    <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center text-gray-600 relative z-10 group-hover:scale-110 transition-transform duration-500">
                                        <Zap size={32} />
                                    </div>
                                    <div className="relative z-10">
                                        <h3 className="text-lg font-black text-white uppercase tracking-widest italic">Machine Offline</h3>
                                        <p className="text-xs text-gray-500 max-w-xs mt-2 font-medium">Click "Start Machine" above to deploy your personal target instance and start hacking.</p>
                                    </div>
                                </div>
                            ) : (
                                <div className="aspect-video rounded-[2.5rem] bg-black border border-white/10 overflow-hidden relative shadow-2xl">
                                    {room.labConfig.type === 'web' ? (
                                        <WebSimulator config={{ ...room.labConfig, target: machineIP }} />
                                    ) : (
                                        <TerminalSimulator config={{ ...room.labConfig, target: machineIP }} />
                                    )}
                                </div>
                            )}

                            <style dangerouslySetInnerHTML={{
                                __html: `
                                @keyframes shake {
                                    0%, 100% { transform: translateX(0); }
                                    25% { transform: translateX(-5px); }
                                    75% { transform: translateX(5px); }
                                }
                                .animate-shake {
                                    animation: shake 0.2s ease-in-out infinite;
                                }
                                @keyframes glitch-1 {
                                    0% { transform: translate(2px, 2px); }
                                    20% { transform: translate(-2px, -2px); }
                                    40% { transform: translate(-2px, 2px); }
                                    60% { transform: translate(2px, -2px); }
                                    80% { transform: translate(2px, 2px); }
                                    100% { transform: translate(0); }
                                }
                                @keyframes glitch-2 {
                                    0% { transform: translate(-2px, -2px); }
                                    20% { transform: translate(2px, 2px); }
                                    40% { transform: translate(2px, -2px); }
                                    60% { transform: translate(-2px, 2px); }
                                    80% { transform: translate(-2px, -2px); }
                                    100% { transform: translate(0); }
                                }
                                .animate-glitch-1 { animation: glitch-1 0.2s skew(10deg) infinite; }
                                .animate-glitch-2 { animation: glitch-2 0.3s skew(-10deg) infinite; }
                                .clip-path-glitch {
                                    clip-path: polygon(0 0, 100% 0, 100% 33%, 0 33%, 0 66%, 100% 66%, 100% 100%, 0 100%);
                                }
                                @keyframes code-drop {
                                    0% { transform: translateY(-100%); opacity: 0; }
                                    10% { opacity: 1; }
                                    90% { opacity: 1; }
                                    100% { transform: translateY(100vh); opacity: 0; }
                                }
                                @keyframes noise {
                                    0%, 100% { transform: translate(0,0); }
                                    10% { transform: translate(-5%,-5%); }
                                    20% { transform: translate(-10%,5%); }
                                    30% { transform: translate(5%,-10%); }
                                    40% { transform: translate(-5%,15%); }
                                    50% { transform: translate(-10%,5%); }
                                    60% { transform: translate(15%,0); }
                                    70% { transform: translate(0,10%); }
                                    80% { transform: translate(-15%,0); }
                                    90% { transform: translate(10%,5%); }
                                }
                                .animate-noise {
                                    animation: noise 0.2s infinite;
                                }
                            `}} />
                        </section>
                    )}

                    <section className="space-y-6">
                        <div className="flex items-center gap-3">
                            <Flag className="text-accent-500" size={20} />
                            <h2 className="text-xl font-black text-white uppercase italic tracking-widest">Objectives</h2>
                        </div>
                        <div className="space-y-4">
                            {room.tasks.map((task, idx) => {
                                const isSolved = solvedTasks.includes(task.id);
                                return (
                                    <motion.div
                                        key={task.id}
                                        initial={{ opacity: 0, y: 20 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        transition={{ delay: idx * 0.1 }}
                                        className={`p-8 rounded-[2.5rem] bg-dark-800/40 border transition-all duration-500 ${isSolved ? 'border-green-500/30' : 'border-white/5'}`}
                                    >
                                        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                                            <div className="flex items-center gap-4">
                                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center border font-black italic ${isSolved ? 'bg-green-500/20 border-green-500/30 text-green-500' : 'bg-white/5 border-white/10 text-gray-500'}`}>
                                                    {isSolved ? <CheckCircle2 size={20} /> : idx + 1}
                                                </div>
                                                <div>
                                                    <h3 className="text-sm font-black text-white uppercase tracking-widest italic leading-tight">
                                                        {language === 'ar' ? task.question.ar : task.question.en}
                                                    </h3>
                                                    <p className="text-[10px] font-black text-accent-500 uppercase tracking-[0.2em] mt-1">{task.points} PTS</p>
                                                </div>
                                            </div>
                                            {!isSolved && task.answer && (
                                                <div className="flex gap-3 w-full md:w-auto relative">
                                                    <input
                                                        type="text"
                                                        placeholder="FLAG{...}"
                                                        value={answers[task.id] || ''}
                                                        onChange={(e) => setAnswers(prev => ({ ...prev, [task.id]: e.target.value }))}
                                                        onKeyDown={(e) => e.key === 'Enter' && handleAnswerSubmit(task.id)}
                                                        className={`flex-1 md:w-64 px-6 py-3 rounded-xl bg-black/40 border text-xs font-mono text-white placeholder:text-gray-700 outline-none transition-all ${submissionStatus[task.id] === 'success' ? 'border-green-500 ring-2 ring-green-500/20' :
                                                            submissionStatus[task.id] === 'error' ? 'border-red-500 ring-2 ring-red-500/20 animate-shake' :
                                                                'border-white/10 focus:border-accent-500/50'
                                                            }`}
                                                    />
                                                    <button
                                                        onClick={() => handleAnswerSubmit(task.id)}
                                                        disabled={submissionStatus[task.id] === 'success'}
                                                        className={`px-6 py-3 rounded-xl font-black uppercase italic text-[10px] tracking-widest transition-all shadow-lg ${submissionStatus[task.id] === 'success' ? 'bg-green-500 text-white' :
                                                            'bg-accent-500 text-white hover:scale-105 active:scale-95 shadow-accent-500/20'
                                                            }`}
                                                    >
                                                        {submissionStatus[task.id] === 'success' ? <CheckCircle2 size={16} /> : 'Submit'}
                                                    </button>

                                                    {submissionStatus[task.id] === 'success' && (
                                                        <motion.div
                                                            initial={{ opacity: 0, scale: 0.5 }}
                                                            animate={{ opacity: 1, scale: 1.2 }}
                                                            className="absolute -top-12 left-1/2 -translate-x-1/2 bg-green-500 text-white px-4 py-2 rounded-full text-[10px] font-black uppercase tracking-widest shadow-2xl z-20 whitespace-nowrap"
                                                        >
                                                            SIGNAL CAPTURED! +{task.points} PTS
                                                        </motion.div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    </motion.div>
                                );
                            })}
                        </div>
                    </section>

                    {room.writeup && (
                        <section className="space-y-6">
                            <div className="flex items-center gap-3">
                                <Zap className="text-accent-500" size={20} />
                                <h2 className="text-xl font-black text-white uppercase italic tracking-widest">Debriefing</h2>
                            </div>
                            {!isRoomCaptured ? (
                                <div className="p-12 rounded-[2.5rem] bg-dark-800/40 border border-white/5 flex flex-col items-center justify-center text-center space-y-4 filter blur-sm select-none pointer-events-none">
                                    <Lock size={48} className="text-gray-500" />
                                    <p className="text-xs font-black uppercase tracking-widest text-gray-500">Decrypt all flags to unlock debriefing</p>
                                </div>
                            ) : (
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    className="p-8 rounded-[2.5rem] bg-accent-500/5 border border-accent-500/20 leading-relaxed text-gray-300 font-medium"
                                >
                                    {language === 'ar' ? room.writeup.ar : room.writeup.en}
                                </motion.div>
                            )}
                        </section>
                    )}
                </div>

                <div className="space-y-8">
                    {room.hints && (
                        <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6">
                            <div className="flex items-center gap-3">
                                <Zap className="text-yellow-500" size={18} />
                                <h3 className="text-xs font-black text-white uppercase tracking-widest">Tactical Hints</h3>
                            </div>
                            <div className="space-y-4">
                                {room.hints.map((hint, i) => {
                                    const hintId = `${room.id}-${i}`;
                                    const isUnlocked = user.unlockedHints.includes(hintId);
                                    return (
                                        <div key={i} className="space-y-3">
                                            {!isUnlocked ? (
                                                <button
                                                    onClick={() => unlockHint(room.id, i, hint.cost)}
                                                    className="w-full p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-yellow-500/30 transition-all text-left flex items-center justify-between group"
                                                >
                                                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Unlock Intel</span>
                                                    <span className="text-[10px] font-black text-yellow-500 italic">-{hint.cost} PTS</span>
                                                </button>
                                            ) : (
                                                <div className="p-4 rounded-2xl bg-yellow-500/5 border border-yellow-500/10 text-xs text-yellow-500/80 leading-relaxed">
                                                    {language === 'ar' ? hint.text.ar : hint.text.en}
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {room.labConfig && (
                        <div className="p-8 rounded-[2.5rem] bg-accent-500/5 border border-accent-500/10 space-y-6">
                            <div className="flex items-center gap-3">
                                <Shield className="text-accent-500" size={18} />
                                <h3 className="text-xs font-black text-white uppercase tracking-widest">Room Matrix</h3>
                            </div>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center text-[10px] uppercase tracking-widest font-black">
                                    <span className="text-gray-500">Stability</span>
                                    <span className="text-green-500">99.8%</span>
                                </div>
                                <div className="w-full h-1.5 bg-dark-900 rounded-full overflow-hidden border border-white/5">
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: '99.8%' }}
                                        className="h-full bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]"
                                    />
                                </div>
                            </div>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center text-[10px] uppercase tracking-widest font-black">
                                    <span className="text-gray-500">Signal Strength</span>
                                    <span className="text-blue-500">{isMachineRunning ? 'Excellent' : 'Offline'}</span>
                                </div>
                                <div className="flex gap-1.5">
                                    {[1, 2, 3, 4, 5].map(i => (
                                        <div key={i} className={`h-4 w-1.5 rounded-sm ${isMachineRunning && i <= 4 ? 'bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.3)]' : 'bg-white/5'}`} />
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {isMachineRunning && (
                        <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6 overflow-hidden">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <Activity className="text-accent-500" size={18} />
                                    <h3 className="text-xs font-black text-white uppercase tracking-widest">Instance Logs</h3>
                                </div>
                                <div className="w-2 h-2 rounded-full bg-green-500 animate-ping" />
                            </div>
                            <div className="space-y-3 font-mono">
                                <AnimatePresence initial={false}>
                                    {labLogs.map((log, i) => (
                                        <motion.div
                                            key={i}
                                            initial={{ opacity: 0, x: -10 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            exit={{ opacity: 0, scale: 0.9 }}
                                            className="text-[10px] space-y-1"
                                        >
                                            <p className="text-gray-400 break-words leading-tight">{log}</p>
                                        </motion.div>
                                    ))}
                                </AnimatePresence>
                                {labLogs.length === 0 && (
                                    <p className="text-[10px] text-gray-700 italic">Listening for system events...</p>
                                )}
                            </div>
                        </div>
                    )}

                    <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 space-y-6">
                        <div className="flex items-center gap-3">
                            <Lock className="text-gray-500" size={18} />
                            <h3 className="text-xs font-black text-white uppercase tracking-widest">Tags</h3>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {room.tags.map(tag => (
                                <span key={tag} className="px-3 py-1.5 rounded-xl bg-white/5 border border-white/5 text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                                    #{tag}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CTFRoomDetail;
