import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Briefcase, Plus, Target, Activity, Clock,
    ChevronRight, Database, FileText, Download,
    Trash2, ExternalLink, Shield, Globe, Zap,
    Layers, Search, AlertCircle, CheckCircle,
    Flag, Terminal, Box, Rocket
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

const ProjectTracker = () => {
    const { toast } = useToast();
    const [projects, setProjects] = useState([]);
    const [activeProjectId, setActiveProjectId] = useState(localStorage.getItem('activeProjectId'));
    const [selectedProject, setSelectedProject] = useState(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [newProject, setNewProject] = useState({ name: '', target: '', objective: '' });
    const [isLoading, setIsLoading] = useState(false);

    // Fetch All Projects
    const fetchProjects = async () => {
        try {
            const res = await fetch('/api/projects/list');
            const data = await res.json();
            if (data.success) {
                setProjects(data.projects);
                // If we have an active ID, sync it
                if (activeProjectId) {
                    const active = data.projects.find(p => p.id === activeProjectId);
                    if (active) setSelectedProject(active);
                }
            }
        } catch (err) {
            console.error("Failed to fetch projects:", err);
        }
    };

    useEffect(() => {
        fetchProjects();
    }, []);

    const handleCreateProject = async () => {
        if (!newProject.name || !newProject.target) return toast("Name and Target required", "warning");
        try {
            const res = await fetch('/api/projects/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newProject)
            });
            const data = await res.json();
            if (data.success) {
                toast("Workspace Initialized", "success");
                setShowCreateModal(false);
                setNewProject({ name: '', target: '', objective: '' });
                fetchProjects();
            }
        } catch (err) {
            toast("Connection Error", "error");
        }
    };

    const setActiveProject = (project) => {
        const id = project.id;
        setActiveProjectId(id);
        setSelectedProject(project);
        localStorage.setItem('activeProjectId', id);
        toast(`Project '${project.name}' is now ACTIVE`, "success");
    };

    const clearActiveProject = () => {
        setActiveProjectId(null);
        setSelectedProject(null);
        localStorage.removeItem('activeProjectId');
        toast("Mission Context Cleared", "info");
    };

    const generateReport = async (projectId) => {
        try {
            const res = await fetch(`/api/projects/report/${projectId}`);
            const data = await res.json();
            if (data.success) {
                // For now, simulate a download
                const element = document.createElement("a");
                const file = new Blob([data.report], { type: 'text/plain' });
                element.href = URL.createObjectURL(file);
                element.download = `TACTICAL_REPORT_${projectId}.md`;
                document.body.appendChild(element);
                element.click();
                toast("Tactical Report Generated", "success");
            }
        } catch (err) {
            toast("Report generation failed", "error");
        }
    };

    return (
        <div className="min-h-screen bg-dark-950 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-white/10 pb-10">
                <div className="space-y-4">
                    <div className="flex items-center gap-4">
                        <div className="p-4 rounded-2xl bg-indigo-500/20 text-indigo-500 border border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)]">
                            <Briefcase size={32} />
                        </div>
                        <div>
                            <h1 className="text-5xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-500 to-indigo-400 bg-[length:200%_auto] animate-gradient">
                                PROJECT TRACKER
                            </h1>
                            <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-xs flex items-center gap-2">
                                <Shield size={12} className="text-indigo-500" /> Operational Mission Control Hub
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex gap-4">
                    {activeProjectId && (
                        <button
                            onClick={clearActiveProject}
                            className="px-6 py-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all text-white/40"
                        >
                            Deactivate Mission
                        </button>
                    )}
                    <button
                        onClick={() => setShowCreateModal(true)}
                        className="px-8 py-4 bg-indigo-500 hover:bg-indigo-600 text-white rounded-2xl shadow-xl shadow-indigo-500/20 transition-all font-black uppercase tracking-widest flex items-center gap-2"
                    >
                        <Plus size={20} /> New Workspace
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

                {/* LEFT: WORKSPACE LIST (4 cols) */}
                <div className="lg:col-span-4 space-y-6">
                    <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 space-y-6 shadow-2xl relative overflow-hidden">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 blur-3xl rounded-full" />

                        <h3 className="text-xl font-black text-white italic flex items-center gap-3">
                            <Layers size={22} className="text-indigo-500" /> ACTIVE MISSIONS
                        </h3>

                        <div className="space-y-3 max-h-[600px] overflow-y-auto scrollbar-hide pr-2">
                            {projects.map(proj => (
                                <motion.div
                                    key={proj.id}
                                    onClick={() => setSelectedProject(proj)}
                                    className={`p-5 rounded-3xl border transition-all cursor-pointer group relative ${selectedProject?.id === proj.id
                                        ? 'bg-indigo-500/10 border-indigo-500/40 shadow-lg'
                                        : 'bg-dark-800 border-white/5 hover:border-white/20'}`}
                                >
                                    {activeProjectId === proj.id && (
                                        <div className="absolute top-4 right-4 flex items-center gap-1.5 px-2 py-0.5 bg-green-500/20 border border-green-500/30 rounded-full">
                                            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                                            <span className="text-[8px] font-black text-green-400 uppercase tracking-widest">Active</span>
                                        </div>
                                    )}
                                    <div className="space-y-1">
                                        <div className="font-black text-white flex items-center gap-2">
                                            {proj.name}
                                            <ChevronRight size={14} className="group-hover:translate-x-1 transition-transform text-white/20" />
                                        </div>
                                        <div className="text-[10px] font-mono text-white/30 uppercase tracking-widest flex items-center gap-2">
                                            <Globe size={10} /> {proj.target}
                                        </div>
                                    </div>
                                    <div className="mt-4 flex gap-2">
                                        <div className="px-2 py-1 bg-white/5 rounded-lg text-[8px] font-bold text-white/20 uppercase">
                                            Hits: {proj.data.fuzzing.length + proj.data.subdomains.length}
                                        </div>
                                        <div className="px-2 py-1 bg-white/5 rounded-lg text-[8px] font-bold text-white/20 uppercase">
                                            {new Date(proj.created_at).toLocaleDateString()}
                                        </div>
                                    </div>
                                </motion.div>
                            ))}
                            {projects.length === 0 && (
                                <div className="text-center py-20 border border-dashed border-white/5 rounded-[2rem] space-y-4">
                                    <Box size={40} className="mx-auto text-white/10" />
                                    <p className="text-xs text-white/20 font-mono uppercase tracking-widest italic">No missions found...</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* RIGHT: INTELLIGENCE HUB (8 cols) */}
                <div className="lg:col-span-8 flex flex-col space-y-6">
                    {selectedProject ? (
                        <div className="space-y-6">
                            {/* Project Header */}
                            <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 shadow-2xl relative overflow-hidden">
                                <div className="absolute -top-24 -left-24 w-64 h-64 bg-indigo-500/10 blur-[100px] rounded-full" />

                                <div className="flex items-center gap-6 relative z-10">
                                    <div className="p-5 rounded-[2rem] bg-indigo-500/10 text-indigo-500 border border-indigo-500/20">
                                        <Flag size={32} />
                                    </div>
                                    <div className="space-y-1">
                                        <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">{selectedProject.name}</h2>
                                        <div className="flex items-center gap-4">
                                            <p className="text-[10px] font-mono text-white/40 tracking-[0.2em] uppercase flex items-center gap-2">
                                                <Target size={12} /> {selectedProject.target}
                                            </p>
                                            <span className="text-white/10">|</span>
                                            <p className="text-[10px] font-mono text-white/40 tracking-[0.2em] uppercase flex items-center gap-2">
                                                <Clock size={12} /> Established {new Date(selectedProject.created_at).toLocaleDateString()}
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                <div className="flex gap-3 relative z-10">
                                    {activeProjectId !== selectedProject.id && (
                                        <button
                                            onClick={() => setActiveProject(selectedProject)}
                                            className="px-6 py-4 bg-green-500 hover:bg-green-600 text-white rounded-2xl shadow-xl shadow-green-500/20 transition-all font-black uppercase tracking-widest flex items-center gap-2 text-xs"
                                        >
                                            <Rocket size={16} /> Deploy Active Status
                                        </button>
                                    )}
                                    <button
                                        onClick={() => generateReport(selectedProject.id)}
                                        className="p-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl text-white/60 transition-all"
                                        title="Generate Tactical Report"
                                    >
                                        <FileText size={20} />
                                    </button>
                                </div>
                            </div>

                            {/* Aggregated Intelligence Tabs */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {/* Subdomains Card */}
                                <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 space-y-6 shadow-2xl border-t-blue-500/30">
                                    <div className="flex justify-between items-center">
                                        <h4 className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em] flex items-center gap-2">
                                            <Globe size={14} className="text-blue-500" /> Infrastructure
                                        </h4>
                                        <span className="text-xl font-black italic text-blue-400">{selectedProject.data.subdomains.length}</span>
                                    </div>
                                    <div className="space-y-2 max-h-48 overflow-y-auto pr-2 scrollbar-hide">
                                        {selectedProject.data.subdomains.map((sub, i) => (
                                            <div key={i} className="p-3 bg-white/5 rounded-xl text-[11px] font-mono text-white/60 border border-white/5 flex justify-between items-center">
                                                {sub}
                                                <ExternalLink size={10} className="text-white/20" />
                                            </div>
                                        ))}
                                        {selectedProject.data.subdomains.length === 0 && <p className="text-center py-6 text-[10px] text-white/20 italic italic">No passive discovery data...</p>}
                                    </div>
                                </div>

                                {/* Fuzzing Card */}
                                <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 space-y-6 shadow-2xl border-t-orange-500/30">
                                    <div className="flex justify-between items-center">
                                        <h4 className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em] flex items-center gap-2">
                                            <Zap size={14} className="text-orange-500" /> Tactical Fuzzing
                                        </h4>
                                        <span className="text-xl font-black italic text-orange-400">{selectedProject.data.fuzzing.length}</span>
                                    </div>
                                    <div className="space-y-2 max-h-48 overflow-y-auto pr-2 scrollbar-hide">
                                        {selectedProject.data.fuzzing.map((hit, i) => (
                                            <div key={i} className="p-3 bg-white/5 rounded-xl text-[11px] font-mono text-white/60 border border-white/5 flex justify-between items-center">
                                                <span className="text-orange-500 font-bold">/{hit.payload}</span>
                                                <span className="px-2 py-0.5 bg-white/5 rounded text-[8px] font-black">{hit.status}</span>
                                            </div>
                                        ))}
                                        {selectedProject.data.fuzzing.length === 0 && <p className="text-center py-6 text-[10px] text-white/20 italic italic">No tactical hits logged...</p>}
                                    </div>
                                </div>
                            </div>

                            {/* Objective & Findings */}
                            <div className="p-8 rounded-[2.5rem] bg-dark-900 border border-white/10 space-y-6 shadow-2xl">
                                <h4 className="text-[10px] font-black text-white/30 uppercase tracking-[0.3em] flex items-center gap-2">
                                    <Flag size={14} className="text-indigo-500" /> Operational Objectives
                                </h4>
                                <div className="p-6 rounded-2xl bg-black/40 border border-white/5 font-mono text-xs text-white/60 leading-relaxed italic">
                                    {selectedProject.objective || "No specific mission objective defined for this workspace."}
                                </div>
                                <div className="pt-4 flex gap-4">
                                    <button className="flex-1 py-4 bg-white/5 hover:bg-indigo-500/20 text-white/40 hover:text-indigo-400 border border-white/10 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all">
                                        Log New Finding
                                    </button>
                                    <button className="flex-1 py-4 bg-white/5 hover:bg-indigo-500/20 text-white/40 hover:text-indigo-400 border border-white/10 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all">
                                        View All Artifacts
                                    </button>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-[700px] flex flex-col items-center justify-center space-y-8 p-12 rounded-[4rem] border border-dashed border-white/5 bg-dark-900/20 backdrop-blur-sm relative overflow-hidden">
                            {/* Background Glitches */}
                            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-indigo-500/5 blur-[120px] rounded-full pointer-events-none" />

                            <div className="p-12 rounded-[3.5rem] bg-dark-900 border border-white/10 shadow-2xl relative">
                                <div className="absolute -inset-6 bg-indigo-500/20 blur-3xl rounded-full opacity-30 animate-pulse" />
                                <Rocket size={120} className="text-indigo-500 relative z-10" />
                            </div>

                            <div className="text-center space-y-4 max-w-sm mx-auto relative z-10">
                                <h2 className="text-4xl font-black text-white italic uppercase tracking-tighter">Mission Locked</h2>
                                <p className="text-white/20 font-mono text-xs uppercase tracking-widest leading-loose">
                                    Select a tactical workspace from the left to engage mission intelligence and aggregate operational discovery.
                                </p>
                            </div>

                            <button
                                onClick={() => setShowCreateModal(true)}
                                className="px-10 py-5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-3xl text-sm font-black uppercase tracking-[0.2em] transition-all text-indigo-400"
                            >
                                Initialize New Mission
                            </button>
                        </div>
                    )}
                </div>
            </div>

            {/* CREATE PROJECT MODAL */}
            <AnimatePresence>
                {showCreateModal && (
                    <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 backdrop-blur-md bg-black/60">
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            className="bg-dark-900 border border-white/10 rounded-[3rem] p-10 w-full max-w-lg shadow-[0_0_100px_rgba(99,102,241,0.2)] space-y-8"
                        >
                            <div className="space-y-2">
                                <h3 className="text-3xl font-black italic text-white uppercase tracking-tighter">Initialize Mission</h3>
                                <p className="text-xs text-white/30 font-mono uppercase tracking-widest">Setup a new tactical workspace for discovery</p>
                            </div>

                            <div className="space-y-6">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-white/20 uppercase tracking-widest ml-1">Mission Name</label>
                                    <input
                                        type="text"
                                        value={newProject.name}
                                        onChange={e => setNewProject({ ...newProject, name: e.target.value })}
                                        placeholder="e.g. OPERATION_NIGHTHAWK"
                                        className="w-full bg-dark-800 border border-white/5 rounded-2xl px-6 py-4 focus:outline-none focus:border-indigo-500/50 transition-all font-mono text-sm"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-white/20 uppercase tracking-widest ml-1">Primary Target</label>
                                    <input
                                        type="text"
                                        value={newProject.target}
                                        onChange={e => setNewProject({ ...newProject, target: e.target.value })}
                                        placeholder="e.g. htb.target.com"
                                        className="w-full bg-dark-800 border border-white/5 rounded-2xl px-6 py-4 focus:outline-none focus:border-indigo-500/50 transition-all font-mono text-sm"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-white/20 uppercase tracking-widest ml-1">Tactical Objective (Optional)</label>
                                    <textarea
                                        value={newProject.objective}
                                        onChange={e => setNewProject({ ...newProject, objective: e.target.value })}
                                        placeholder="Outline your goal..."
                                        className="w-full bg-dark-800 border border-white/5 rounded-2xl px-6 py-4 focus:outline-none focus:border-indigo-500/50 transition-all font-mono text-xs h-32 resize-none"
                                    />
                                </div>
                            </div>

                            <div className="flex gap-4 pt-4">
                                <button
                                    onClick={() => setShowCreateModal(false)}
                                    className="flex-1 py-5 bg-white/5 hover:bg-white/10 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all text-white/40"
                                >
                                    Cancel Mission
                                </button>
                                <button
                                    onClick={handleCreateProject}
                                    className="flex-[2] py-5 bg-indigo-500 hover:bg-indigo-600 text-white rounded-2xl shadow-xl shadow-indigo-500/20 transition-all font-black uppercase tracking-widest text-xs"
                                >
                                    Begin Engagement
                                </button>
                            </div>
                        </motion.div>
                    </div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default ProjectTracker;
