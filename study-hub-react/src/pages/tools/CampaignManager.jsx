import React, { useState, useRef, useEffect } from 'react';
import {
    Crown, Sparkles, Network, Plus, Save, FolderOpen, FileUp, Trash2,
    Search, DoorOpen, Key, ArrowUp, Move, Anchor, CloudUpload, Bot,
    X, Link as LinkIcon, AlertCircle, ChevronDown, ChevronRight, Check
} from 'lucide-react';

const CampaignManager = () => {
    // --- STATE ---
    const [blocks, setBlocks] = useState([]);
    const [connections, setConnections] = useState([]);
    const [selectedBlockId, setSelectedBlockId] = useState(null);
    const [connectModeSource, setConnectModeSource] = useState(null);
    const [scenarioName, setScenarioName] = useState('New Campaign');
    const [draggedItem, setDraggedItem] = useState(null);
    const canvasRef = useRef(null);
    const [showSaveSuccess, setShowSaveSuccess] = useState(false);

    // --- PERSISTENCE ---
    useEffect(() => {
        const savedCampaign = localStorage.getItem('campaign_autosave');
        if (savedCampaign) {
            try {
                const data = JSON.parse(savedCampaign);
                setBlocks(data.blocks || []);
                setConnections(data.connections || []);
                setScenarioName(data.name || 'Restored Campaign');
            } catch (e) {
                console.error("Failed to restore campaign", e);
            }
        }
    }, []);

    const saveCampaign = () => {
        const data = {
            name: scenarioName,
            blocks,
            connections,
            date: new Date().toISOString()
        };
        localStorage.setItem('campaign_autosave', JSON.stringify(data));
        setShowSaveSuccess(true);
        setTimeout(() => setShowSaveSuccess(false), 2000);
    };

    // --- DATA ---
    const blockLibrary = {
        recon: {
            category: 'Reconnaissance', icon: Search, color: '#3b82f6', blocks: [
                { id: 'nmap', name: 'Nmap Scan', desc: 'Port scanning and service detection', mitre: 'T1046' },
                { id: 'gobuster', name: 'Gobuster', desc: 'Directory and file enumeration', mitre: 'T1083' },
                { id: 'nikto', name: 'Nikto', desc: 'Web vulnerability scanner', mitre: 'T1595' },
                { id: 'osint', name: 'OSINT', desc: 'Open source intelligence gathering', mitre: 'T1593' },
            ]
        },
        initial: {
            category: 'Initial Access', icon: DoorOpen, color: '#ef4444', blocks: [
                { id: 'phishing', name: 'Phishing', desc: 'Social engineering attack', mitre: 'T1566' },
                { id: 'exploit_public', name: 'Public Exploit', desc: 'Known vulnerability exploitation', mitre: 'T1190' },
                { id: 'webshell', name: 'Web Shell', desc: 'Upload malicious web shell', mitre: 'T1505.003' },
                { id: 'sqli', name: 'SQL Injection', desc: 'Database manipulation attack', mitre: 'T1190' },
            ]
        },
        creds: {
            category: 'Credential Access', icon: Key, color: '#f59e0b', blocks: [
                { id: 'brute_force', name: 'Brute Force', desc: 'Password cracking attack', mitre: 'T1110' },
                { id: 'cred_dump', name: 'Credential Dump', desc: 'Extract credentials from memory', mitre: 'T1003' },
                { id: 'mimikatz', name: 'Mimikatz', desc: 'Windows credential extraction', mitre: 'T1003.001' },
            ]
        },
        privesc: {
            category: 'Privilege Escalation', icon: ArrowUp, color: '#8b5cf6', blocks: [
                { id: 'suid', name: 'SUID Exploit', desc: 'Abuse SUID binaries', mitre: 'T1548.001' },
                { id: 'kernel', name: 'Kernel Exploit', desc: 'Exploit kernel vulnerabilities', mitre: 'T1068' },
                { id: 'sudo', name: 'Sudo Abuse', desc: 'Misconfigured sudo permissions', mitre: 'T1548.003' },
            ]
        },
        lateral: {
            category: 'Lateral Movement', icon: Move, color: '#10b981', blocks: [
                { id: 'pth', name: 'Pass-the-Hash', desc: 'Authenticate with NTLM hash', mitre: 'T1550.002' },
                { id: 'psexec', name: 'PSExec', desc: 'Remote command execution', mitre: 'T1569.002' },
                { id: 'ssh_pivot', name: 'SSH Pivot', desc: 'Pivot through SSH tunnel', mitre: 'T1021.004' },
            ]
        },
        persist: {
            category: 'Persistence', icon: Anchor, color: '#ec4899', blocks: [
                { id: 'backdoor', name: 'Backdoor', desc: 'Install persistent backdoor', mitre: 'T1505' },
                { id: 'scheduled', name: 'Scheduled Task', desc: 'Create scheduled task/cron', mitre: 'T1053' },
            ]
        },
        exfil: {
            category: 'Exfiltration', icon: CloudUpload, color: '#06b6d4', blocks: [
                { id: 'data_collect', name: 'Data Collection', desc: 'Gather sensitive data', mitre: 'T1005' },
                { id: 'exfil_http', name: 'HTTP Exfil', desc: 'Exfiltrate over HTTP/S', mitre: 'T1048.002' },
            ]
        }
    };

    const aiSuggestionsMap = {
        'nmap': ['gobuster', 'nikto', 'default_creds'],
        'gobuster': ['sqli', 'webshell'],
        'sqli': ['webshell', 'cred_dump'],
        'webshell': ['suid', 'kernel', 'sudo'],
        'phishing': ['mimikatz', 'cred_dump'],
        'brute_force': ['ssh_pivot', 'psexec'],
        'cred_dump': ['pth', 'psexec'],
        'mimikatz': ['pth', 'token'],
        'suid': ['backdoor', 'ssh_key'],
        'pth': ['psexec', 'wmi'],
        'backdoor': ['data_collect'],
        'data_collect': ['exfil_http']
    };

    // --- ACTIONS ---
    const handleDragStart = (e, category, blockId) => {
        setDraggedItem({ category, blockId });
    };

    const handleDrop = (e) => {
        e.preventDefault();
        const rect = canvasRef.current.getBoundingClientRect();
        const x = e.clientX - rect.left - 75; // Center offset
        const y = e.clientY - rect.top - 30;

        if (draggedItem) {
            addBlock(draggedItem.category, draggedItem.blockId, x, y);
            setDraggedItem(null);
        }
    };

    const addBlock = (category, blockId, x, y) => {
        const template = blockLibrary[category].blocks.find(b => b.id === blockId);
        const newBlock = {
            uid: Date.now(),
            ...template,
            category,
            x: Math.max(0, x),
            y: Math.max(0, y),
            color: blockLibrary[category].color,
            icon: blockLibrary[category].icon
        };
        setBlocks(prev => [...prev, newBlock]);

        // Auto-connect hint
        if (blocks.length > 0) {
            // Optional: Connect to last block? (Legacy did this in AI add, not manual drop)
        }
    };

    const startConnection = (uid) => {
        if (connectModeSource === null) {
            setConnectModeSource(uid);
        } else {
            if (connectModeSource !== uid) {
                // Prevent duplicate connections
                if (!connections.find(c => c.from === connectModeSource && c.to === uid)) {
                    setConnections(prev => [...prev, { from: connectModeSource, to: uid }]);
                }
            }
            setConnectModeSource(null);
        }
    };

    const deleteBlock = (uid, e) => {
        e.stopPropagation();
        setBlocks(prev => prev.filter(b => b.uid !== uid));
        setConnections(prev => prev.filter(c => c.from !== uid && c.to !== uid));
        if (selectedBlockId === uid) setSelectedBlockId(null);
    };

    // Block Dragging in Canvas
    const [movingBlock, setMovingBlock] = useState(null);

    const handleCanvasMouseDown = (e, uid) => {
        if (e.target.closest('button')) return; // Ignore button clicks
        const block = blocks.find(b => b.uid === uid);
        setMovingBlock({
            uid,
            offsetX: e.clientX - block.x,
            offsetY: e.clientY - block.y
        });
        setSelectedBlockId(uid);
    };

    const handleCanvasMouseMove = (e) => {
        if (movingBlock) {
            setBlocks(prev => prev.map(b =>
                b.uid === movingBlock.uid
                    ? { ...b, x: e.clientX - movingBlock.offsetX, y: e.clientY - movingBlock.offsetY }
                    : b
            ));
        }
    };

    const handleCanvasMouseUp = () => {
        setMovingBlock(null);
    };

    // AI Suggestions
    const getSuggestions = () => {
        if (blocks.length === 0) return [];
        const lastBlock = blocks[blocks.length - 1]; // Naive "last"
        const suggestIds = aiSuggestionsMap[lastBlock.id] || [];

        // Flatten library to find blocks
        const allBlocks = Object.values(blockLibrary).flatMap(cat =>
            cat.blocks.map(b => ({ ...b, catKey: Object.keys(blockLibrary).find(k => blockLibrary[k] === cat) }))
        );

        return suggestIds.map(id => allBlocks.find(b => b.id === id)).filter(Boolean);
    };

    const addSuggestion = (suggestion) => {
        const lastBlock = blocks[blocks.length - 1];
        const x = lastBlock ? lastBlock.x + 200 : 50;
        const y = lastBlock ? lastBlock.y : 50;

        const template = blockLibrary[suggestion.catKey].blocks.find(b => b.id === suggestion.id);
        const newUid = Date.now();
        const newBlock = {
            uid: newUid,
            ...template,
            category: suggestion.catKey,
            x, y,
            color: blockLibrary[suggestion.catKey].color,
            icon: blockLibrary[suggestion.catKey].icon
        };

        setBlocks(prev => [...prev, newBlock]);
        if (lastBlock) {
            setConnections(prev => [...prev, { from: lastBlock.uid, to: newUid }]);
        }
    };

    const selectedBlock = blocks.find(b => b.uid === selectedBlockId);

    // --- RENDER ---
    return (
        <div
            className="h-full flex flex-col p-4 max-w-[1600px] mx-auto overflow-hidden"
            onMouseMove={handleCanvasMouseMove}
            onMouseUp={handleCanvasMouseUp}
        >
            {/* Header */}
            <div className="flex justify-between items-center mb-4 bg-gray-900/80 backdrop-blur-sm p-4 rounded-xl border border-white/10">
                <div className="flex items-center gap-3">
                    <Crown className="w-8 h-8 text-cyan-400" />
                    <div>
                        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                            Attack Campaign <span className="text-cyan-400">Manager Pro</span>
                        </h1>
                        <p className="text-xs text-gray-400">Red Team Operations & Planning</p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <input
                        type="text"
                        value={scenarioName}
                        onChange={(e) => setScenarioName(e.target.value)}
                        className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-white outline-none focus:border-cyan-400"
                    />
                    <button className="p-2 bg-gradient-to-r from-purple-600 to-blue-600 rounded-lg text-white hover:opacity-90 transition-opacity">
                        <Sparkles className="w-5 h-5" />
                    </button>
                    <button
                        onClick={saveCampaign}
                        className={`p-2 rounded-lg text-white border border-white/10 transition-all ${showSaveSuccess ? 'bg-green-500/20 text-green-400 border-green-500/50' : 'bg-gray-800 text-gray-300 hover:text-white'
                            }`}
                    >
                        {showSaveSuccess ? <Check className="w-5 h-5" /> : <Save className="w-5 h-5" />}
                    </button>
                    <button
                        onClick={() => {
                            if (window.confirm('Clear canvas?')) {
                                setBlocks([]);
                                setConnections([]);
                                setScenarioName('New Campaign');
                            }
                        }}
                        className="p-2 bg-red-500/10 rounded-lg text-red-400 hover:bg-red-500/20 border border-red-500/20"
                    >
                        <Trash2 className="w-5 h-5" />
                    </button>
                </div>
            </div>

            <div className="flex-1 flex gap-4 min-h-0">

                {/* Left: Library */}
                <div className="w-64 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl overflow-y-auto custom-scrollbar flex flex-col">
                    <div className="p-4 border-b border-white/5">
                        <h3 className="font-bold text-gray-300 flex items-center gap-2">
                            <FolderOpen className="w-4 h-4" /> Attack Blocks
                        </h3>
                    </div>
                    <div className="p-2 space-y-2">
                        {Object.entries(blockLibrary).map(([key, cat]) => (
                            <LibraryCategory key={key} catKey={key} category={cat} onDragStart={handleDragStart} />
                        ))}
                    </div>
                </div>

                {/* Center: Canvas */}
                <div
                    ref={canvasRef}
                    className="flex-1 bg-black/40 border border-white/10 rounded-xl relative overflow-hidden bg-grid-pattern cursor-crosshair"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={handleDrop}
                >
                    <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
                        <defs>
                            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                                <polygon points="0 0, 10 3.5, 0 7" fill="#00ff88" />
                            </marker>
                        </defs>
                        {connections.map((conn, i) => {
                            const from = blocks.find(b => b.uid === conn.from);
                            const to = blocks.find(b => b.uid === conn.to);
                            if (!from || !to) return null;
                            return (
                                <line
                                    key={i}
                                    x1={from.x + 90} y1={from.y + 35} // Adjust for block center
                                    x2={to.x + 90} y2={to.y + 35}
                                    stroke="#00ff88"
                                    strokeWidth="2"
                                    markerEnd="url(#arrowhead)"
                                    opacity="0.6"
                                />
                            );
                        })}
                        {connectModeSource && (() => {
                            // Optional: Draw line to mouse cursor (requires tracking mouse in canvas state not just dragging)
                            return null;
                        })()}
                    </svg>

                    {blocks.map(block => (
                        <div
                            key={block.uid}
                            style={{
                                left: block.x,
                                top: block.y,
                                borderLeftColor: block.color,
                                '--block-color': block.color
                            }}
                            className={`absolute w-[180px] bg-gray-900 border-l-4 rounded-lg shadow-lg p-3 select-none transition-shadow group
                                ${selectedBlockId === block.uid ? 'ring-2 ring-white/50 shadow-cyan-500/20' : 'border-white/10'}
                                ${connectModeSource === block.uid ? 'ring-2 ring-green-500 animate-pulse' : ''}
                            `}
                            onMouseDown={(e) => handleCanvasMouseDown(e, block.uid)}
                        >
                            <div className="flex items-center gap-2 mb-2">
                                <span style={{ color: block.color }}><block.icon className="w-4 h-4" /></span>
                                <span className="font-bold text-sm text-white truncate">{block.name}</span>
                            </div>
                            <div className="text-[10px] text-gray-500 font-mono mb-2">{block.mitre}</div>

                            <div className="flex justify-end gap-1 opacity-100 transition-opacity">
                                <button
                                    onClick={() => startConnection(block.uid)}
                                    className={`p-1 rounded hover:bg-white/10 ${connectModeSource === block.uid ? 'text-green-400' : 'text-gray-400'}`}
                                >
                                    <LinkIcon className="w-3 h-3" />
                                </button>
                                <button
                                    onClick={(e) => deleteBlock(block.uid, e)}
                                    className="p-1 rounded hover:bg-red-500/20 text-gray-400 hover:text-red-400"
                                >
                                    <Trash2 className="w-3 h-3" />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Right: Details & AI */}
                <div className="w-72 flex flex-col gap-4">
                    {/* AI Suggestions */}
                    <div className="bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl p-4 flex-none min-h-[200px]">
                        <h3 className="font-bold text-cyan-400 flex items-center gap-2 mb-3">
                            <Bot className="w-4 h-4" /> AI Suggestions
                        </h3>
                        <div className="space-y-2">
                            {getSuggestions().length > 0 ? (
                                getSuggestions().map((s, i) => (
                                    <div
                                        key={i}
                                        onClick={() => addSuggestion(s)}
                                        className="flex items-center gap-2 p-2 bg-black/40 border border-white/5 rounded-lg cursor-pointer hover:border-cyan-500/50 transition-colors group"
                                    >
                                        <Plus className="w-3 h-3 text-cyan-500" />
                                        <span className="text-sm text-gray-300 group-hover:text-white">{s.name}</span>
                                    </div>
                                ))
                            ) : (
                                <p className="text-xs text-gray-500 italic">Add a block to the canvas to receive next-step recommendations from the AI Architect.</p>
                            )}
                        </div>
                    </div>

                    {/* Block Details */}
                    <div className="flex-1 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl p-4 overflow-y-auto">
                        <h3 className="font-bold text-gray-300 flex items-center gap-2 mb-3">
                            <AlertCircle className="w-4 h-4" /> Details
                        </h3>
                        {selectedBlock ? (
                            <div className="space-y-4 animate-fadeIn">
                                <div className="p-3 rounded-lg bg-black/20 border border-t-2 border-white/5" style={{ borderTopColor: selectedBlock.color }}>
                                    <h4 className="font-bold text-white text-lg">{selectedBlock.name}</h4>
                                    <span className="text-xs px-2 py-0.5 rounded bg-white/10 text-gray-300 font-mono mt-1 inline-block">
                                        {selectedBlock.mitre}
                                    </span>
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500 uppercase font-bold">Description</label>
                                    <p className="text-sm text-gray-300 mt-1">{selectedBlock.desc}</p>
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500 uppercase font-bold">Notes</label>
                                    <textarea
                                        className="w-full h-32 bg-black/40 border border-white/10 rounded-lg p-2 text-sm text-white mt-1 outline-none focus:border-cyan-500/50 resize-none"
                                        placeholder="Add mission notes..."
                                    />
                                </div>
                            </div>
                        ) : (
                            <div className="text-center text-gray-500 py-10">
                                <p>Select a block to view details</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

// Helper Component for Library
const LibraryCategory = ({ catKey, category, onDragStart }) => {
    const [open, setOpen] = useState(false);

    return (
        <div className="select-none">
            <div
                onClick={() => setOpen(!open)}
                className="flex items-center gap-2 p-2 rounded-lg cursor-pointer hover:bg-white/5 transition-colors"
            >
                {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                <category.icon className="w-4 h-4" style={{ color: category.color }} />
                <span className="font-bold text-sm text-gray-300">{category.category}</span>
            </div>

            {open && (
                <div className="ml-6 space-y-1 mt-1 border-l border-white/5 pl-2">
                    {category.blocks.map(block => (
                        <div
                            key={block.id}
                            draggable
                            onDragStart={(e) => onDragStart(e, catKey, block.id)}
                            className="p-2 bg-black/20 border border-white/5 rounded hover:border-white/20 cursor-grab active:cursor-grabbing text-xs text-gray-400 hover:text-white transition-colors"
                        >
                            {block.name}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default CampaignManager;
