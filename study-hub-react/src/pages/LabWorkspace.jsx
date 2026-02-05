import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { machines } from '../data/machines';
import CyberTerminal from '../components/CyberTerminal';
import { useAppContext } from '../context/AppContext';
import {
    ArrowLeft,
    Terminal as TerminalIcon,
    BookOpen,
    Shield,
    Cpu,
    CheckCircle2,
    Copy,
    Server
} from 'lucide-react';
import LabControlPanel from '../components/LabControlPanel';

const LabWorkspace = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const machine = machines.find(m => m.id === id);
    const { user, solveCTFTask } = useAppContext();

    // Flag Submission State
    const [userFlag, setUserFlag] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [feedback, setFeedback] = useState({ message: '', type: '' });
    const [labStatus, setLabStatus] = useState('stopped');

    // Check if machine is already solved via AppContext
    const isSolved = user.solvedCTFTasks?.includes(`${id}-user`) || user.solvedCTFTasks?.includes(id);

    if (!machine) {
        return <div className="p-12 text-center text-white">Machine not found</div>;
    }

    const handleSubmitFlag = async () => {
        if (!userFlag.trim()) return;

        setIsSubmitting(true);
        setFeedback({ message: 'Verifying with Neural Link...', type: 'info' });

        try {
            // Use the consolidated backend verify endpoint
            const response = await fetch(`${apiUrl}/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    machine_id: id,
                    flag: userFlag
                })
            });

            const data = await response.json();

            if (data.valid) {
                setFeedback({ message: data.message, type: 'success' });
                // Reward XP and register solve in AppContext
                solveCTFTask(id, { id: 'user', points: machine.points || 100 }, machine.name);
            } else {
                setFeedback({ message: data.message, type: 'error' });
            }
        } catch (err) {
            setFeedback({ message: 'Connection to verification node failed.', type: 'error' });
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="h-screen bg-[#0a0a0a] flex flex-col overflow-hidden">
            {/* Top Bar for Workspace */}
            <header className="h-14 bg-dark-900 border-b border-white/5 flex items-center justify-between px-6 z-20 shadow-xl">
                <div className="flex items-center gap-4">
                    <button
                        onClick={() => navigate('/labs')}
                        className="p-2 hover:bg-white/5 rounded-lg text-gray-400 hover:text-white transition-colors"
                    >
                        <ArrowLeft size={18} />
                    </button>
                    <div className="flex items-center gap-2">
                        <Cpu size={16} className="text-primary-500" />
                        <h1 className="text-sm font-black text-white uppercase tracking-widest">{machine.name}</h1>
                        {isSolved && (
                            <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-green-500/10 border border-green-500/20 text-[10px] font-bold text-green-500 uppercase">
                                <CheckCircle2 size={10} /> SOLVED
                            </span>
                        )}
                        <span className="px-2 py-0.5 rounded bg-primary-500/10 border border-primary-500/20 text-[10px] font-bold text-primary-500 uppercase">
                            {machine.level}
                        </span>
                    </div>
                </div>

                <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-dark-800 border border-white/5">
                        <Server size={14} className="text-green-500" />
                        <span className="text-xs font-mono text-white">{machine.ip}</span>
                        <button
                            onClick={() => navigator.clipboard.writeText(machine.ip)}
                            className="p-1 hover:bg-white/10 rounded text-gray-500 hover:text-white transition-colors"
                        >
                            <Copy size={12} />
                        </button>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                        <span className="text-[10px] font-bold text-green-500 uppercase tracking-widest">System Active</span>
                    </div>
                </div>
            </header>

            {/* Split View */}
            <div className="flex-1 flex overflow-hidden">
                {/* Left Panel - Guide & Controls */}
                <div className="col-span-4 bg-[#0a0a0a] border-r border-white/5 flex flex-col overflow-hidden">
                    <div className="p-6 overflow-y-auto custom-scrollbar">
                        <LabControlPanel
                            labId={id}
                            userId={user?.id || 1}
                            onStatusChange={setLabStatus}
                        />

                        {/* Objectives */}
                        <div className="space-y-4">
                            <h2 className="flex items-center gap-2 text-sm font-black text-gray-400 uppercase tracking-widest">
                                <BookOpen size={16} />
                                Mission Objectives
                            </h2>
                            <div className="p-4 rounded-xl bg-white/5 border border-white/5 text-gray-300 text-sm leading-relaxed">
                                {machine.desc}
                            </div>
                        </div>

                        {/* Tasks Section */}
                        <div className="space-y-4">
                            <h2 className="flex items-center gap-2 text-sm font-black text-gray-400 uppercase tracking-widest">
                                <Activity size={16} />
                                Tasks
                            </h2>

                            <div className="space-y-3">
                                <div className="p-4 rounded-xl bg-dark-900 border border-white/5 space-y-3">
                                    <div className="flex justify-between items-start">
                                        <p className="text-sm font-bold text-white">1. Connect to the VPN</p>
                                        <CheckCircle2 size={16} className="text-green-500" />
                                    </div>
                                    <p className="text-xs text-gray-500">Ensure you have downloaded your OpenVPN configuration file and connected successfully.</p>
                                </div>

                                <div className="p-4 rounded-xl bg-dark-900 border border-white/5 space-y-3">
                                    <div className="flex justify-between items-start">
                                        <p className="text-sm font-bold text-white">2. Scan the Target</p>
                                        <div className="w-4 h-4 rounded-full border border-gray-600" />
                                    </div>
                                    <p className="text-xs text-gray-500">Use Nmap to identify open ports and services on {machine.ip}.</p>
                                    <div className="p-2 rounded bg-black/50 border border-white/5 font-mono text-xs text-green-500">
                                        nmap -sC -sV {machine.ip}
                                    </div>
                                </div>

                                <div className="p-4 rounded-xl bg-dark-900 border border-white/5 space-y-3">
                                    <div className="flex justify-between items-start">
                                        <p className="text-sm font-bold text-white">3. User Flag</p>
                                        {isSolved ? (
                                            <CheckCircle2 size={16} className="text-green-500" />
                                        ) : (
                                            <div className="w-4 h-4 rounded-full border border-gray-600" />
                                        )}
                                    </div>
                                    <input
                                        type="text"
                                        value={userFlag}
                                        onChange={(e) => setUserFlag(e.target.value)}
                                        disabled={isSolved || isSubmitting}
                                        placeholder="Enter flag format: SH{...}"
                                        className="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 focus:outline-none transition-colors font-mono disabled:opacity-50"
                                    />

                                    {feedback.message && (
                                        <p className={`text-[10px] font-bold uppercase ${feedback.type === 'success' ? 'text-green-500' :
                                            feedback.type === 'error' ? 'text-red-500' : 'text-primary-500'
                                            }`}>
                                            {feedback.message}
                                        </p>
                                    )}

                                    {!isSolved && (
                                        <button
                                            onClick={handleSubmitFlag}
                                            disabled={isSubmitting || !userFlag}
                                            className="w-full py-2 bg-primary-500/10 border border-primary-500/20 text-primary-500 rounded-lg text-xs font-bold uppercase hover:bg-primary-500 hover:text-black transition-all disabled:opacity-20"
                                        >
                                            {isSubmitting ? 'Verifying...' : 'Submit Flag'}
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Right Panel: Terminal */}
                <div className="flex-1 bg-[#0a0a0a] relative flex flex-col">
                    <div className="absolute top-4 right-4 z-10">
                        <span className="px-2 py-1 bg-white/10 rounded text-[10px] text-gray-400 uppercase font-mono tracking-widest border border-white/5">
                            Codespace: Active
                        </span>
                    </div>

                    {/* The Terminal sits here filling the space */}
                    <div className="flex-1 p-2">
                        <CyberTerminal
                            initialHeight="100%"
                            title={`ROOT@CODESPACE [${machine.name}]`}
                            isConnected={labStatus === 'running'}
                            labId={id}
                            userId={user?.id || 1}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LabWorkspace;
