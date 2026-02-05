import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Terminal,
    Globe,
    Code,
    ChevronLeft,
    Shield,
    AlertCircle,
    CheckCircle2,
    Zap,
    Maximize2,
    RefreshCw,
    Play
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const OWASPPractice = ({ vuln }) => {
    const navigate = useNavigate();
    const [terminalLines, setTerminalLines] = useState([]);
    const [isDeploying, setIsDeploying] = useState(false);
    const [isSuccess, setIsSuccess] = useState(false);

    useEffect(() => {
        // Init terminal logs
        const timer = setTimeout(() => {
            setTerminalLines(vuln.simulation.terminalLogs);
        }, 500);
        return () => clearTimeout(timer);
    }, [vuln]);

    const handleDeploy = () => {
        setIsDeploying(true);
        setTimeout(() => {
            setIsDeploying(false);
            setIsSuccess(true);
            setTerminalLines(prev => [
                ...prev,
                `[${new Date().toLocaleTimeString()}] SUCCESS: Patch applied successfully.`,
                `[${new Date().toLocaleTimeString()}] LOCKDOWN: Environment secured.`
            ]);
        }, 2000);
    };

    return (
        <div className="fixed inset-0 z-50 bg-[#050505] flex flex-col overflow-hidden animate-in fade-in duration-700">
            {/* Simulation Top Bar */}
            <div className="h-16 border-b border-white/10 bg-dark-950 px-6 flex items-center justify-between">
                <div className="flex items-center gap-6">
                    <button
                        onClick={() => navigate(`/owasp-range/${vuln.id}/learn`)}
                        className="p-2 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white transition-all"
                    >
                        <ChevronLeft size={20} />
                    </button>
                    <div className="h-6 w-px bg-white/10" />
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
                            <Shield size={16} className="text-red-500" />
                        </div>
                        <div>
                            <h2 className="text-sm font-black text-white italic uppercase tracking-tighter">
                                OWASP Range <span className="text-gray-500 mx-2">/</span> {vuln.title}
                            </h2>
                            <div className="flex items-center gap-2">
                                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Active Simulation Environment</span>
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]" />
                            </div>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <div className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] font-black text-gray-400 uppercase tracking-widest">
                        Module: {vuln.id.toUpperCase()}
                    </div>
                    <div className="px-3 py-1 rounded-full bg-orange-500/10 border border-orange-500/20 text-[10px] font-black text-orange-500 uppercase tracking-widest">
                        Difficulty: {vuln.difficulty}
                    </div>
                </div>
            </div>

            {/* Main Workbench Layout */}
            <div className="flex-1 flex overflow-hidden">

                {/* Left Panel: Mission Dossier */}
                <div className="w-80 border-r border-white/10 bg-dark-900/30 p-6 flex flex-col gap-6 overflow-y-auto scrollbar-none">
                    <div className="space-y-4">
                        <div className="flex items-center gap-2 text-primary-500">
                            <AlertCircle size={16} />
                            <span className="text-xs font-black uppercase tracking-widest italic">Mission Dossier</span>
                        </div>
                        <div className="space-y-4">
                            <div className="p-4 rounded-xl bg-white/5 border border-white/5 space-y-1">
                                <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Target Type</div>
                                <div className="text-sm font-bold text-white">{vuln.type}</div>
                            </div>
                            <div className="p-4 rounded-xl bg-white/5 border border-white/5 space-y-1">
                                <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Severity</div>
                                <div className="text-sm font-bold text-red-500">{vuln.severity} (CVSS {vuln.cvss})</div>
                            </div>
                        </div>
                    </div>

                    <div className="space-y-3">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Objective</h4>
                        <p className="text-xs italic text-gray-400 leading-relaxed">
                            {vuln.objective}
                        </p>
                    </div>

                    <div className="space-y-3">
                        <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Defense Strategy</h4>
                        <p className="text-xs italic text-blue-400/80 leading-relaxed">
                            {vuln.defense}
                        </p>
                    </div>

                    <div className="mt-auto p-4 rounded-xl bg-primary-500/5 border border-primary-500/10 flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-primary-500/20 flex items-center justify-center">
                            <Zap size={16} className="text-primary-500" />
                        </div>
                        <div>
                            <div className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Status</div>
                            <div className="text-xs font-bold text-white uppercase italic">In Progress</div>
                        </div>
                    </div>
                </div>

                {/* Center Panel: Interaction Layer */}
                <div className="flex-1 flex flex-col min-w-0 bg-[#080808]">
                    {/* Top: Kali Terminal */}
                    <div className="h-2/5 border-b border-white/10 flex flex-col bg-black">
                        <div className="h-8 bg-dark-900 px-4 flex items-center justify-between border-b border-white/5">
                            <div className="flex items-center gap-2">
                                <Terminal size={12} className="text-emerald-500" />
                                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">kali@cyber-range: ~</span>
                            </div>
                            <div className="flex gap-1.5">
                                <div className="w-2.5 h-2.5 rounded-full bg-white/5" />
                                <div className="w-2.5 h-2.5 rounded-full bg-white/5" />
                            </div>
                        </div>
                        <div className="flex-1 p-4 font-mono text-[11px] leading-relaxed overflow-y-auto scrollbar-cyber">
                            {terminalLines.map((line, i) => (
                                <div key={i} className={`
                                    ${line.includes('ALERT') ? 'text-red-400' :
                                        line.includes('SUCCESS') ? 'text-emerald-400 font-bold' :
                                            line.includes('SCAN') || line.includes('INTEL') ? 'text-blue-400' : 'text-gray-400'}
                                `}>
                                    {line}
                                </div>
                            ))}
                            <div className="flex items-center gap-2 mt-2">
                                <span className="text-emerald-500 font-bold">➜</span>
                                <span className="text-white animate-pulse">_</span>
                            </div>
                        </div>
                    </div>

                    {/* Bottom: Browser Simulator */}
                    <div className="flex-1 flex flex-col">
                        <div className="h-10 bg-dark-900 border-b border-white/5 px-4 flex items-center gap-4">
                            <div className="flex gap-2">
                                <div className="w-3 h-3 rounded-full bg-white/5" />
                                <div className="w-3 h-3 rounded-full bg-white/5" />
                            </div>
                            <div className="flex-1 max-w-lg h-7 bg-black rounded-lg border border-white/10 px-3 flex items-center gap-2">
                                <Globe size={12} className="text-gray-600" />
                                <span className="text-[10px] text-gray-500 font-mono truncate">{vuln.simulation.targetSite}</span>
                            </div>
                            <RefreshCw size={12} className="text-gray-600" />
                        </div>
                        <div className="flex-1 bg-white flex items-center justify-center relative overflow-hidden">
                            <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]" />
                            <div className="text-center space-y-4 p-8">
                                <div className="w-20 h-20 rounded-2xl bg-gray-100 flex items-center justify-center mx-auto shadow-sm">
                                    <Globe size={40} className="text-gray-300" />
                                </div>
                                <h3 className="text-lg font-bold text-gray-800 uppercase tracking-tight italic">Target Application Preview</h3>
                                <p className="text-sm text-gray-500 italic max-w-xs mx-auto">
                                    The vulnerable endpoint has been quarantined for simulation. Perform inspection via the terminal above.
                                </p>
                                <div className="inline-flex px-4 py-2 bg-red-500/10 text-red-600 rounded-lg text-[10px] font-black uppercase tracking-widest border border-red-500/20">
                                    Quarantined Environment
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Right Panel: Secure Editor */}
                <div className="w-[450px] border-l border-white/10 bg-black flex flex-col">
                    <div className="h-12 bg-dark-900 px-6 flex items-center justify-between border-b border-white/5">
                        <div className="flex items-center gap-2">
                            <Code size={16} className="text-primary-500" />
                            <span className="text-xs font-black uppercase tracking-widest italic text-white">Secure Code Editor</span>
                        </div>
                        <Maximize2 size={14} className="text-gray-600" />
                    </div>

                    <div className="flex-1 p-6 font-mono text-xs leading-relaxed bg-[#0d1117] overflow-auto scrollbar-cyber">
                        <div className="flex gap-4 text-gray-600 mb-4 select-none">
                            <span className="text-primary-500 font-bold border-b-2 border-primary-500 pb-1 uppercase tracking-widest">vulnerable.js</span>
                            <span className="hover:text-gray-400 cursor-pointer uppercase tracking-widest pb-1">server.config</span>
                            <span className="hover:text-gray-400 cursor-pointer uppercase tracking-widest pb-1">auth.middleware</span>
                        </div>
                        <pre className="text-gray-400">
                            {vuln.simulation.vulnerableCode.split('\n').map((line, i) => (
                                <div key={i} className="flex gap-4 group">
                                    <span className="w-6 text-gray-700 text-right">{i + 1}</span>
                                    <span className={line.includes('backdoor') || line.includes('⚠️') ? 'text-red-400 italic' : ''}>
                                        {line}
                                    </span>
                                </div>
                            ))}
                        </pre>
                    </div>

                    <div className="p-6 border-t border-white/10 bg-dark-950">
                        <button
                            onClick={handleDeploy}
                            disabled={isDeploying || isSuccess}
                            className={`w-full h-14 rounded-xl flex items-center justify-center gap-3 font-black uppercase tracking-[0.2em] transition-all
                                ${isSuccess ? 'bg-emerald-500 text-white' :
                                    isDeploying ? 'bg-primary-500/20 text-primary-500 cursor-wait' :
                                        'bg-white text-black hover:bg-gray-200'}`}
                        >
                            {isSuccess ? (
                                <><CheckCircle2 size={18} /> Patch Deployed</>
                            ) : isDeploying ? (
                                <><RefreshCw size={18} className="animate-spin" /> Deploying Patch...</>
                            ) : (
                                <><Play size={18} className="fill-current" /> Deploy Security Patch</>
                            )}
                        </button>
                    </div>
                </div>

            </div>

            {/* Success Overlay */}
            <AnimatePresence>
                {isSuccess && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="fixed inset-0 z-[100] bg-black/80 backdrop-blur-md flex items-center justify-center"
                    >
                        <motion.div
                            initial={{ scale: 0.9, y: 20 }}
                            animate={{ scale: 1, y: 0 }}
                            className="text-center space-y-6 max-w-md p-10 rounded-3xl bg-dark-900 border border-emerald-500/30 shadow-[0_0_50px_rgba(16,185,129,0.1)]"
                        >
                            <div className="w-20 h-20 rounded-full bg-emerald-500 flex items-center justify-center mx-auto shadow-[0_0_20px_rgba(16,185,129,0.4)]">
                                <CheckCircle2 size={40} className="text-white" />
                            </div>
                            <div className="space-y-2">
                                <h3 className="text-3xl font-black text-white italic uppercase tracking-tighter">Mission Success</h3>
                                <p className="text-gray-400 italic font-medium">
                                    You have successfully identified and remediated the <span className="text-white">{vuln.title}</span> vulnerability.
                                </p>
                            </div>
                            <div className="flex flex-col gap-3">
                                <button
                                    onClick={() => navigate('/owasp-range')}
                                    className="w-full h-12 rounded-xl bg-white text-black font-black uppercase tracking-widest text-xs hover:bg-gray-200"
                                >
                                    Claim XP & Return to Range
                                </button>
                                <button
                                    onClick={() => setIsSuccess(false)}
                                    className="w-full h-12 rounded-xl bg-white/5 text-gray-400 font-black uppercase tracking-widest text-xs hover:bg-white/10"
                                >
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
