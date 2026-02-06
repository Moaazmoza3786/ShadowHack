import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { Play, Shield, Activity, RefreshCw, Terminal } from 'lucide-react';

const AttackChains = () => {
    const [socket, setSocket] = useState(null);
    const [chains, setChains] = useState({});
    const [target, setTarget] = useState('scanme.nmap.org');
    const [activeChain, setActiveChain] = useState(null);
    const [logs, setLogs] = useState([]);
    const terminalRef = useRef(null);

    useEffect(() => {
        const newSocket = io('http://localhost:5000/ws/tools', {
            transports: ['websocket']
        });

        newSocket.on('connect', () => {
            newSocket.emit('get_chains');
        });

        newSocket.on('chains_list', (data) => {
            setChains(data);
        });

        newSocket.on('chain_output', (data) => {
            setLogs(prev => [...prev, data.data || data]);
        });

        setSocket(newSocket);
        return () => newSocket.disconnect();
    }, []);

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [logs]);

    const runChain = (id) => {
        if (!target) return;
        setLogs([]);
        setActiveChain(id);
        socket.emit('execute_chain', { id, target });
    };

    return (
        <div className="h-full flex flex-col p-6 max-w-[1800px] mx-auto text-gray-100 font-['Outfit']">
            {/* Header */}
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-500 to-orange-500 flex items-center gap-3">
                        <Activity className="w-8 h-8 text-red-500" />
                        Automated Attack Chains
                    </h1>
                    <p className="text-gray-500 text-sm mt-1">Multi-stage autonomous offensive workflows.</p>
                </div>
                <div className="flex items-center gap-4 bg-gray-900/50 p-2 rounded-xl border border-white/10">
                    <span className="text-xs font-bold text-gray-500 px-2">TARGET SCPE</span>
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-white font-mono text-sm outline-none focus:border-red-500/50 w-64"
                        placeholder="Target IP/Domain"
                    />
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-0">
                {/* Chains List */}
                <div className="space-y-4">
                    {Object.entries(chains).map(([id, chain]) => (
                        <div
                            key={id}
                            className={`p-6 rounded-2xl border transition-all cursor-pointer group ${activeChain === id
                                    ? 'bg-red-500/10 border-red-500/50 shadow-lg shadow-red-900/20'
                                    : 'bg-[#12121e] border-white/5 hover:border-red-500/30'
                                }`}
                            onClick={() => setActiveChain(id)}
                        >
                            <div className="flex justify-between items-start mb-4">
                                <div className="p-3 bg-black/40 rounded-xl">
                                    <Shield className={`w-6 h-6 ${activeChain === id ? 'text-red-400' : 'text-gray-400'}`} />
                                </div>
                                {activeChain === id && <span className="text-[10px] font-bold bg-red-500 text-white px-2 py-1 rounded animate-pulse">ACTIVE</span>}
                            </div>
                            <h3 className="text-lg font-bold mb-2">{chain.name}</h3>
                            <p className="text-sm text-gray-400 mb-6">{chain.description}</p>
                            <button
                                onClick={(e) => { e.stopPropagation(); runChain(id); }}
                                className="w-full py-3 bg-white/5 hover:bg-red-600 hover:text-white rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-2 group-hover:bg-red-600/20 group-hover:text-red-400"
                            >
                                <Play size={16} fill="currentColor" /> Execute Chain
                            </button>
                        </div>
                    ))}

                    {Object.keys(chains).length === 0 && (
                        <div className="text-center p-8 text-gray-500">
                            <RefreshCw className="w-8 h-8 mx-auto mb-4 animate-spin opacity-50" />
                            Loading Chains...
                        </div>
                    )}
                </div>

                {/* Live Execution Output */}
                <div className="lg:col-span-2 bg-[#0a0a0f] rounded-2xl border border-white/10 overflow-hidden flex flex-col relative shadow-2xl">
                    <div className="bg-white/5 px-4 py-2 border-b border-white/5 flex justify-between items-center">
                        <div className="flex items-center gap-2">
                            <Terminal size={14} className="text-gray-400" />
                            <span className="text-xs font-bold text-gray-400 uppercase">Kill Chain Terminal</span>
                        </div>
                        <div className="flex gap-1.5">
                            <div className="w-2.5 h-2.5 rounded-full bg-red-500/20 border border-red-500/50" />
                            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
                            <div className="w-2.5 h-2.5 rounded-full bg-green-500/20 border border-green-500/50" />
                        </div>
                    </div>

                    <div
                        ref={terminalRef}
                        className="flex-1 p-6 font-mono text-xs overflow-y-auto custom-scrollbar space-y-1"
                    >
                        {logs.length === 0 && (
                            <div className="h-full flex flex-col items-center justify-center text-gray-600 opacity-50">
                                <Activity size={48} className="mb-4" />
                                <p>Ready to execute kill chain...</p>
                            </div>
                        )}
                        {logs.map((log, i) => (
                            <div key={i} className="whitespace-pre-wrap break-all leading-relaxed text-gray-300">
                                {log}
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AttackChains;
