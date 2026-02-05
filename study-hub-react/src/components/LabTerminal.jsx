import React, { useState } from 'react';
import { Terminal as TerminalIcon, Play, Square, RefreshCcw, Wifi, ShieldCheck } from 'lucide-react';

const LabTerminal = ({ lesson }) => {
    const [status, setStatus] = useState('offline'); // offline, starting, online
    const [output, setOutput] = useState([]);

    const startMachine = () => {
        setStatus('starting');
        setOutput(['[+] Powering on machine...', '[+] Initializing kernel...', '[+] Setting up network interfaces...']);

        setTimeout(() => {
            setStatus('online');
            setOutput(prev => [...prev, '[+] Machine is ONLINE', '[+] Target IP: 10.10.12.34', 'root@study-hub:~# ']);
        }, 3000);
    };

    const stopMachine = () => {
        setStatus('offline');
        setOutput([]);
    };

    return (
        <div className="bg-dark-900 border border-dark-600 rounded-2xl overflow-hidden flex flex-col h-[600px] shadow-2xl">
            <div className="p-4 bg-dark-800 border-b border-dark-600 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-primary-600/10 rounded-lg flex items-center justify-center">
                        <TerminalIcon className="w-5 h-5 text-primary-500" />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-white">Interactive Terminal</h3>
                        <div className="flex items-center gap-1.5 mt-0.5">
                            <div className={`w-2 h-2 rounded-full ${status === 'online' ? 'bg-accent-500 animate-pulse' : status === 'starting' ? 'bg-yellow-500 animate-bounce' : 'bg-red-500'}`} />
                            <span className="text-[10px] uppercase font-bold text-gray-500 tracking-wider font-mono">
                                {status}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    {status === 'offline' ? (
                        <button
                            onClick={startMachine}
                            className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white text-xs font-bold rounded-lg transition-all"
                        >
                            <Play className="w-3.5 h-3.5 fill-current" />
                            Start Machine
                        </button>
                    ) : (
                        <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-accent-500 bg-accent-500/10 px-2 py-1 rounded border border-accent-500/20">10.10.12.34</span>
                            <button
                                onClick={stopMachine}
                                className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-500/10 rounded-lg transition-all"
                            >
                                <Square className="w-4 h-4 fill-current" />
                            </button>
                        </div>
                    )}
                </div>
            </div>

            <div className="flex-1 bg-[#0c0c0d] p-6 font-mono text-sm overflow-y-auto scrollbar-thin scrollbar-thumb-dark-600">
                {output.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-center space-y-4">
                        <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center">
                            <Wifi className="w-8 h-8 text-gray-700" />
                        </div>
                        <div>
                            <p className="text-gray-500">Terminal is waiting for connection.</p>
                            <p className="text-[10px] text-gray-700 uppercase mt-1">Status: No active session</p>
                        </div>
                    </div>
                ) : (
                    <div className="space-y-1">
                        {output.map((line, i) => (
                            <div key={i} className={line.startsWith('[+]') ? 'text-accent-500' : 'text-gray-300'}>
                                {line}
                            </div>
                        ))}
                        {status === 'online' && (
                            <div className="inline-flex gap-2">
                                <span className="text-primary-500">root@study-hub</span>
                                <span className="text-gray-500">:</span>
                                <span className="text-blue-400">~</span>
                                <span className="text-gray-500">#</span>
                                <span className="w-2 h-5 bg-primary-500 animate-caret-blink" />
                            </div>
                        )}
                    </div>
                )}
            </div>

            <div className="p-4 bg-dark-800 border-t border-dark-600 flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 text-gray-400">
                        <ShieldCheck className="w-4 h-4" />
                        <span className="text-xs antialiased uppercase tracking-wide">VPN: Connected</span>
                    </div>
                </div>
                <button className="p-2 text-gray-500 hover:text-white transition-colors">
                    <RefreshCcw className="w-4 h-4" />
                </button>
            </div>
        </div>
    );
};

export default LabTerminal;
