import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Map, Search, Globe, Network, Cpu,
    Layers, Activity, Shield, Info, Maximize2,
    ZoomIn, ZoomOut, RefreshCw, Share2, Download,
    Database, Box, Filter, Terminal, Zap
} from 'lucide-react';
import ForceGraph2D from 'react-force-graph-2d';
import { useToast } from '../../context/ToastContext';

const VisualMapper = () => {
    const { toast } = useToast();
    const [domainInput, setDomainInput] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [graphData, setGraphData] = useState({ nodes: [], links: [] });
    const [selectedNode, setSelectedNode] = useState(null);
    const [hoverNode, setHoverNode] = useState(null);
    const [scanStatus, setScanStatus] = useState('idle'); // idle, scanning, completed
    const graphRef = useRef();

    // Node colors by type
    const NODE_COLORS = {
        domain: '#3b82f6',    // Blue
        subdomain: '#60a5fa', // Light Blue
        ip: '#ef4444',       // Red
        tech: '#f59e0b'      // Amber
    };

    const startScan = async () => {
        if (!domainInput.trim()) return toast("Domain required", "warning");

        setIsScanning(true);
        setScanStatus('scanning');
        setGraphData({ nodes: [], links: [] });
        setSelectedNode(null);

        const activeProjectId = localStorage.getItem('activeProjectId');
        try {
            const res = await fetch('/api/tools/visual/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domainInput, project_id: activeProjectId })
            });
            const data = await res.json();
            if (data.success) {
                toast("Mapping Engine Initialized", "success");
                startPolling(domainInput);
            } else {
                setIsScanning(false);
                setScanStatus('failed');
                toast(data.error || "Scan failed", "error");
            }
        } catch (err) {
            setIsScanning(false);
            setScanStatus('failed');
            toast("Connection error", "error");
        }
    };

    const startPolling = (domain) => {
        const interval = setInterval(async () => {
            try {
                const res = await fetch(`/api/tools/visual/data/${domain}`);
                const resData = await res.json();
                if (resData.success && resData.data.status === 'completed') {
                    setGraphData(resData.data);
                    setIsScanning(false);
                    setScanStatus('completed');
                    toast("Graph Rendering Complete", "success");
                    clearInterval(interval);
                }
            } catch (err) {
                console.error("Polling error:", err);
            }
        }, 2000);
    };

    // Zoom handlers
    const handleZoomIn = () => graphRef.current.zoom(graphRef.current.zoom() * 1.2, 400);
    const handleZoomOut = () => graphRef.current.zoom(graphRef.current.zoom() * 0.8, 400);
    const handleReset = () => graphRef.current.zoomToFit(400);

    return (
        <div className="h-screen bg-dark-950 text-gray-100 flex flex-col overflow-hidden">
            {/* OVERLAY: HEADER */}
            <div className="absolute top-0 left-0 right-0 z-50 p-6 pointer-events-none">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                    <div className="flex items-center gap-4 bg-dark-900/80 backdrop-blur-xl border border-white/10 p-4 rounded-3xl pointer-events-auto">
                        <div className="p-3 rounded-2xl bg-blue-500/20 text-blue-500">
                            <Map size={32} />
                        </div>
                        <div>
                            <h1 className="text-4xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-500">
                                VISUAL MAPPER
                            </h1>
                            <p className="text-[10px] font-mono tracking-[0.3em] uppercase text-white/40 flex items-center gap-2">
                                <Network size={12} /> Infrastructure Intelligence Node
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-3 bg-dark-900/80 backdrop-blur-xl border border-white/10 p-3 rounded-2xl pointer-events-auto">
                        <input
                            type="text"
                            value={domainInput}
                            onChange={(e) => setDomainInput(e.target.value)}
                            placeholder="TARGET DOMAIN (e.g. apple.com)"
                            className="bg-transparent border-none focus:outline-none px-4 w-64 font-mono text-sm"
                        />
                        <button
                            onClick={startScan}
                            disabled={isScanning}
                            className={`p-3 rounded-xl transition-all ${isScanning ? 'bg-blue-500/20 text-blue-500 animate-pulse' : 'bg-blue-500 hover:bg-blue-600 text-white shadow-lg shadow-blue-500/20'}`}
                        >
                            {isScanning ? <RefreshCw className="animate-spin" size={20} /> : <Zap size={20} />}
                        </button>
                    </div>
                </div>
            </div>

            {/* OVERLAY: NODE DETAILS (Left Side) */}
            <AnimatePresence>
                {selectedNode && (
                    <motion.div
                        initial={{ x: -300, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        exit={{ x: -300, opacity: 0 }}
                        className="absolute left-8 top-32 bottom-32 w-80 z-40 bg-dark-900/90 backdrop-blur-2xl border border-white/10 rounded-[2.5rem] p-8 space-y-8 shadow-2xl overflow-y-auto scrollbar-hide"
                    >
                        <div className="flex justify-between items-start">
                            <div className={`p-3 rounded-2xl bg-white/5 ${NODE_COLORS[selectedNode.type]}`}>
                                {selectedNode.type === 'domain' && <Globe size={24} />}
                                {selectedNode.type === 'ip' && <Cpu size={24} />}
                                {selectedNode.type === 'tech' && <Layers size={24} />}
                                {selectedNode.type === 'subdomain' && <Box size={24} />}
                            </div>
                            <button onClick={() => setSelectedNode(null)} className="text-white/20 hover:text-white transition-colors">
                                <Maximize2 size={18} />
                            </button>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <h3 className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em] mb-1">Target Identity</h3>
                                <p className="text-xl font-black text-white break-all italic">{selectedNode.label}</p>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded-full text-[8px] font-black uppercase tracking-widest bg-white/5 border border-white/10`}>
                                    {selectedNode.type}
                                </span>
                                <span className="text-[10px] text-white/20 font-mono">ID: {selectedNode.id}</span>
                            </div>
                        </div>

                        <div className="space-y-4 pt-4 border-t border-white/5">
                            <h4 className="text-[10px] font-bold text-white/30 uppercase tracking-widest">Metadata</h4>
                            <div className="space-y-3">
                                <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-1">
                                    <div className="text-[10px] text-white/40 uppercase">Last Detected</div>
                                    <div className="text-sm font-mono text-gray-300">{new Date().toLocaleTimeString()}</div>
                                </div>
                                <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-1">
                                    <div className="text-[10px] text-white/40 uppercase">Confidence Score</div>
                                    <div className="text-lg font-black text-blue-400">98%</div>
                                </div>
                            </div>
                        </div>

                        <button className="w-full py-4 bg-blue-500 text-white rounded-2xl font-black uppercase tracking-widest text-xs hover:bg-blue-600 transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20">
                            <ExternalLink size={14} /> Full Deep-Scan
                        </button>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* OVERLAY: CONTROLS (Bottom Center) */}
            <div className="absolute bottom-10 left-1/2 -translate-x-1/2 z-50 flex gap-4 p-3 bg-dark-900/60 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl">
                <button onClick={handleZoomIn} className="p-2 hover:bg-white/5 rounded-lg text-white/60 transition-all"><ZoomIn size={18} /></button>
                <button onClick={handleZoomOut} className="p-2 hover:bg-white/5 rounded-lg text-white/60 transition-all"><ZoomOut size={18} /></button>
                <button onClick={handleReset} className="p-2 hover:bg-white/5 rounded-lg text-white/60 transition-all"><Maximize2 size={18} /></button>
                <div className="w-px bg-white/10 h-6 mx-1" />
                <button className="p-2 hover:bg-white/5 rounded-lg text-white/60 transition-all"><Download size={18} /></button>
                <button className="p-2 hover:bg-white/5 rounded-lg text-white/60 transition-all"><Share2 size={18} /></button>
            </div>

            {/* OVERLAY: LEGEND (Bottom Right) */}
            <div className="absolute bottom-10 right-10 z-50 p-6 bg-dark-900/80 backdrop-blur-xl border border-white/10 rounded-3xl space-y-4 shadow-2xl">
                <h4 className="text-[8px] font-black text-white/20 uppercase tracking-[0.3em]">Map Legend</h4>
                <div className="grid grid-cols-2 gap-4">
                    {Object.entries(NODE_COLORS).map(([type, color]) => (
                        <div key={type} className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }} />
                            <span className="text-[10px] font-bold text-white/60 uppercase">{type}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* THE GRAPH RENDERING */}
            <div className="flex-1 cursor-grab active:cursor-grabbing">
                <ForceGraph2D
                    ref={graphRef}
                    graphData={graphData}
                    nodeRelSize={6}
                    nodeColor={node => NODE_COLORS[node.type] || '#ffffff'}
                    nodeLabel={node => node.label}
                    linkColor={() => 'rgba(255,255,255,0.08)'}
                    linkDirectionalParticles={1}
                    linkDirectionalParticleSpeed={0.005}
                    linkDirectionalParticleWidth={2}
                    linkDirectionalParticleColor={() => '#3b82f6'}
                    backgroundColor="transparent"
                    onNodeClick={node => setSelectedNode(node)}
                    onNodeHover={node => setHoverNode(node)}
                    nodeCanvasObject={(node, ctx, globalScale) => {
                        const label = node.label;
                        const fontSize = 12 / globalScale;
                        ctx.font = `${fontSize}px Inter, system-ui`;
                        const textWidth = ctx.measureText(label).width;
                        const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

                        // Draw Node Circle
                        ctx.beginPath();
                        ctx.arc(node.x, node.y, 4, 0, 2 * Math.PI, false);
                        ctx.fillStyle = NODE_COLORS[node.type] || '#ffffff';
                        ctx.fill();

                        // Add Glow
                        ctx.shadowColor = ctx.fillStyle;
                        ctx.shadowBlur = 10;

                        // Draw Label
                        if (globalScale > 2 || node === selectedNode || node === hoverNode) {
                            ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                            ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2 - 8, ...bckgDimensions);
                            ctx.textAlign = 'center';
                            ctx.textBaseline = 'middle';
                            ctx.fillStyle = '#fff';
                            ctx.fillText(label, node.x, node.y - 8);
                        }
                    }}
                />
            </div>
        </div>
    );
};

export default VisualMapper;
