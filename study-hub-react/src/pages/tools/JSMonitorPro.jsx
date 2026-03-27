import React, { useState } from 'react';
import {
    Shield, Search, FileCode, Lock, Globe,
    ChevronRight, ChevronDown, ExternalLink,
    AlertTriangle, Zap, Terminal, Download,
    Eye, Database
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useToast } from '../../context/ToastContext';
import { useAppContext } from '../../context/AppContext';

const JSMonitorPro = () => {
    const { toast } = useToast();
    const { apiUrl } = useAppContext();
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [selectedFile, setSelectedFile] = useState(null);

    const runDeepScan = async () => {
        if (!targetUrl) return toast('Please enter a target URL', 'error');
        setIsScanning(true);
        setScanResults(null);
        setSelectedFile(null);

        try {
            const response = await fetch(`${apiUrl}/tools/js-mine`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            });
            const data = await response.json();

            if (data.success) {
                setScanResults(data.data);
                toast(`Scan complete! Found ${data.data.total_secrets} secrets.`, 'success');
                if (data.data.files.length > 0) {
                    setSelectedFile(data.data.files[0]);
                }
            } else {
                toast(data.error || 'Scan failed', 'error');
            }
        } catch (error) {
            console.error("Scan error:", error);
            toast('Failed to connect to backend', 'error');
        } finally {
            setIsScanning(false);
        }
    };

    const getSeverityColor = (severity) => {
        if (severity === 'Critical') return 'text-red-500 bg-red-500/10 border-red-500/20';
        if (severity === 'High') return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
        return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
    };

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20 animate-fade-in relative min-h-screen">

            {/* HERADER */}
            <div className="flex flex-col md:flex-row justify-between items-end gap-6 border-b border-white/10 pb-6">
                <div className="space-y-2">
                    <h1 className="text-3xl md:text-4xl font-black italic uppercase tracking-tighter text-white flex items-center gap-3">
                        <Database className="text-cyan-500" size={32} />
                        Deep-JS <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600">Miner</span>
                    </h1>
                    <p className="text-gray-400 font-medium max-w-xl">
                        Advanced static analysis engine for JavaScript assets.
                        Uncover hardcoded secrets, hidden API endpoints, and potential logic flaws.
                    </p>
                </div>

                <div className="flex gap-4">
                    <div className="bg-dark-800 px-4 py-2 rounded-xl border border-white/5 flex flex-col items-center">
                        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Files</span>
                        <span className="text-xl font-black text-white">{scanResults?.files?.length || 0}</span>
                    </div>
                    <div className="bg-dark-800 px-4 py-2 rounded-xl border border-white/5 flex flex-col items-center">
                        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Secrets</span>
                        <span className="text-xl font-black text-red-500">{scanResults?.total_secrets || 0}</span>
                    </div>
                    <div className="bg-dark-800 px-4 py-2 rounded-xl border border-white/5 flex flex-col items-center">
                        <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Endpoints</span>
                        <span className="text-xl font-black text-cyan-500">{scanResults?.total_endpoints || 0}</span>
                    </div>
                </div>
            </div>

            {/* INPUT SECTION */}
            <div className="bg-dark-800/50 border border-white/10 rounded-2xl p-6 backdrop-blur-sm">
                <div className="flex flex-col md:flex-row gap-4">
                    <div className="flex-1 relative">
                        <Search className="absolute left-4 top-4 text-gray-500" size={20} />
                        <input
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            placeholder="https://target.com"
                            className="w-full bg-black/50 border border-white/10 rounded-xl py-3.5 pl-12 pr-4 text-cyan-400 font-mono focus:border-cyan-500/50 outline-none transition-all"
                        />
                    </div>
                    <button
                        onClick={runDeepScan}
                        disabled={isScanning}
                        className={`px-8 py-3.5 rounded-xl font-black uppercase tracking-widest text-sm flex items-center gap-2 transition-all ${isScanning
                                ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                                : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-[0_0_20px_rgba(8,145,178,0.3)] hover:shadow-[0_0_30px_rgba(8,145,178,0.5)]'
                            }`}
                    >
                        {isScanning ? (
                            <>
                                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                                Mining...
                            </>
                        ) : (
                            <>
                                <Zap size={18} />
                                Start Mining
                            </>
                        )}
                    </button>
                </div>
            </div>

            {/* MAIN CONTENT AREA */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">

                {/* LEFT: FILE TREE */}
                <div className="lg:col-span-1 bg-dark-900 border border-white/10 rounded-2xl overflow-hidden flex flex-col">
                    <div className="p-4 border-b border-white/5 bg-white/5 flex justify-between items-center">
                        <h3 className="text-xs font-black uppercase tracking-widest text-gray-400">Target Assets</h3>
                        <span className="text-[10px] font-mono text-cyan-500 bg-cyan-500/10 px-2 py-0.5 rounded">
                            {scanResults ? scanResults.target : 'Waiting...'}
                        </span>
                    </div>

                    <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-thin scrollbar-thumb-white/10 hover:scrollbar-thumb-cyan-500/50">
                        {scanResults?.files?.map((file, idx) => (
                            <button
                                key={idx}
                                onClick={() => setSelectedFile(file)}
                                className={`w-full text-left p-3 rounded-xl border transition-all group relative overflow-hidden ${selectedFile === file
                                        ? 'bg-cyan-500/10 border-cyan-500/30'
                                        : 'bg-black/20 border-white/5 hover:bg-white/5'
                                    }`}
                            >
                                <div className="flex items-center gap-3 relative z-10">
                                    <FileCode size={18} className={selectedFile === file ? 'text-cyan-400' : 'text-gray-500'} />
                                    <div className="flex-1 min-w-0">
                                        <div className={`text-sm font-bold truncate ${selectedFile === file ? 'text-white' : 'text-gray-400 group-hover:text-gray-300'}`}>
                                            {file.name}
                                        </div>
                                        <div className="flex items-center gap-2 mt-1">
                                            {file.secrets.length > 0 && (
                                                <span className="text-[10px] font-bold text-red-400 bg-red-400/10 px-1.5 rounded flex items-center gap-1">
                                                    <Lock size={8} /> {file.secrets.length}
                                                </span>
                                            )}
                                            {file.endpoints.length > 0 && (
                                                <span className="text-[10px] font-bold text-blue-400 bg-blue-400/10 px-1.5 rounded flex items-center gap-1">
                                                    <Globe size={8} /> {file.endpoints.length}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    {selectedFile === file && <ChevronRight size={16} className="text-cyan-500" />}
                                </div>
                            </button>
                        ))}

                        {!scanResults && (
                            <div className="text-center py-20 text-gray-600">
                                <Search size={40} className="mx-auto mb-4 opacity-20" />
                                <p className="text-xs uppercase tracking-widest font-bold">No data mined yet</p>
                            </div>
                        )}
                    </div>
                </div>

                {/* RIGHT: DETAILS VIEW */}
                <div className="lg:col-span-2 bg-dark-900 border border-white/10 rounded-2xl flex flex-col overflow-hidden">
                    {selectedFile ? (
                        <>
                            {/* File Header */}
                            <div className="p-4 border-b border-white/5 bg-white/5 flex justify-between items-center">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 bg-cyan-500/20 rounded-lg">
                                        <FileCode size={20} className="text-cyan-500" />
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-bold text-white">{selectedFile.name}</h3>
                                        <a href={selectedFile.url} target="_blank" rel="noreferrer" className="text-xs text-gray-500 hover:text-cyan-400 flex items-center gap-1 transition-colors">
                                            {selectedFile.url} <ExternalLink size={10} />
                                        </a>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <button className="p-2 hover:bg-white/10 rounded-lg transition-colors text-gray-400 hover:text-white" title="Download Report">
                                        <Download size={18} />
                                    </button>
                                </div>
                            </div>

                            {/* Content Tabs/Sections */}
                            <div className="flex-1 overflow-y-auto p-6 space-y-8 scrollbar-thin">

                                {/* SECRETS */}
                                <div className="space-y-4">
                                    <h4 className="text-xs font-black uppercase tracking-widest text-red-500 flex items-center gap-2">
                                        <Lock size={14} /> Potential Secrets Found ({selectedFile.secrets.length})
                                    </h4>

                                    {selectedFile.secrets.length > 0 ? (
                                        <div className="grid gap-3">
                                            {selectedFile.secrets.map((secret, i) => (
                                                <div key={i} className={`p-4 rounded-xl border ${getSeverityColor(secret.severity)} bg-opacity-5 relative group`}>
                                                    <div className="flex justify-between items-start mb-1">
                                                        <span className="text-[10px] font-black uppercase">{secret.type}</span>
                                                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-black/20">{secret.severity}</span>
                                                    </div>
                                                    <code className="text-xs font-mono block mt-1 break-all bg-black/30 p-2 rounded selectable">
                                                        {secret.value}
                                                    </code>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="p-4 rounded-xl border border-dashed border-white/10 text-center text-gray-500 text-xs italic">
                                            No hardcoded secrets found in this file. Good security practice!
                                        </div>
                                    )}
                                </div>

                                {/* ENDPOINTS */}
                                <div className="space-y-4">
                                    <h4 className="text-xs font-black uppercase tracking-widest text-blue-500 flex items-center gap-2">
                                        <Globe size={14} /> Discovered Endpoints ({selectedFile.endpoints.length})
                                    </h4>

                                    {selectedFile.endpoints.length > 0 ? (
                                        <div className="bg-black/30 border border-white/5 rounded-xl overflow-hidden">
                                            {selectedFile.endpoints.map((ep, i) => (
                                                <div key={i} className="px-4 py-3 border-b border-white/5 last:border-0 hover:bg-white/5 transition-colors flex justify-between items-center group">
                                                    <code className="text-xs text-gray-300 font-mono">{ep}</code>
                                                    <span className="text-[10px] text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity">Endpoint</span>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="p-4 rounded-xl border border-dashed border-white/10 text-center text-gray-500 text-xs italic">
                                            No endpoints patterns detected.
                                        </div>
                                    )}
                                </div>

                            </div>
                        </>
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center text-center p-8 space-y-4 opacity-50">
                            <div className="w-20 h-20 bg-cyan-500/10 rounded-full flex items-center justify-center animate-pulse">
                                <Terminal size={40} className="text-cyan-500" />
                            </div>
                            <div>
                                <h3 className="text-lg font-bold text-white">Select a File</h3>
                                <p className="text-sm text-gray-400">Choose a JavaScript file from the left to analyze findings.</p>
                            </div>
                        </div>
                    )}
                </div>

            </div>

            {/* Background Decorations */}
            <div className="absolute top-20 left-10 w-64 h-64 bg-cyan-500/10 blur-[100px] pointer-events-none rounded-full mix-blend-screen" />
            <div className="absolute bottom-10 right-10 w-64 h-64 bg-blue-600/10 blur-[100px] pointer-events-none rounded-full mix-blend-screen" />

        </div>
    );
};

export default JSMonitorPro;
