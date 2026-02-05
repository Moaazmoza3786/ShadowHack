import React from 'react';
import { motion } from 'framer-motion';
import {
    ChevronLeft,
    Shield,
    AlertCircle,
    Terminal,
    CheckCircle2,
    Play,
    Info,
    ArrowRight
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

const OWASPLearn = ({ vuln }) => {
    const navigate = useNavigate();

    return (
        <div className="space-y-8 pb-12">
            {/* Header / Breadcrumbs */}
            <div className="flex items-center justify-between">
                <button
                    onClick={() => navigate('/owasp-range')}
                    className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors group"
                >
                    <ChevronLeft size={20} className="group-hover:-translate-x-1 transition-transform" />
                    <span className="text-xs font-black uppercase tracking-widest">Back to Modules</span>
                </button>

                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
                        <AlertCircle size={14} className="text-red-500" />
                        <span className="text-[10px] font-black uppercase tracking-widest text-red-500">
                            Severity: {vuln.severity}
                        </span>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
                        <Shield size={14} className="text-blue-500" />
                        <span className="text-[10px] font-black uppercase tracking-widest text-blue-500">
                            CVSS: {vuln.cvss}
                        </span>
                    </div>
                </div>
            </div>

            {/* Title Section */}
            <div>
                <h1 className="text-5xl font-black text-white italic uppercase tracking-tighter">
                    {vuln.title}
                </h1>
                <p className="mt-2 text-gray-400 font-medium tracking-wide">
                    {vuln.type} • Documentation & Remediation Case Study
                </p>
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Left: Theory */}
                <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="bg-dark-800/40 border border-white/5 rounded-3xl p-8 space-y-8"
                >
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-blue-500/20 flex items-center justify-center">
                            <Info size={20} className="text-blue-500" />
                        </div>
                        <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">Theory</h2>
                    </div>

                    <div
                        className="prose prose-invert max-w-none text-gray-400 prose-headings:text-white prose-p:italic prose-li:italic prose-strong:text-blue-400"
                        dangerouslySetInnerHTML={{ __html: vuln.theory }}
                    />

                    <div className="p-6 rounded-2xl bg-blue-500/5 border border-blue-500/10 space-y-3">
                        <h4 className="text-xs font-black uppercase tracking-widest text-blue-500">Objective</h4>
                        <p className="text-sm italic text-blue-100/70">{vuln.objective}</p>
                    </div>

                    <div className="pt-6 border-t border-white/5">
                        <Link
                            to={`/owasp-range/${vuln.id}/practice`}
                            className="group w-full h-16 rounded-2xl bg-primary-600 text-white flex items-center justify-between px-8 hover:bg-primary-500 transition-all shadow-[0_0_30px_rgba(239,68,68,0.2)]"
                        >
                            <div className="flex items-center gap-4">
                                <Play size={20} className="fill-current" />
                                <div className="text-left">
                                    <div className="text-[10px] font-black uppercase tracking-[0.2em] opacity-80">Ready to Practice?</div>
                                    <div className="text-xl font-black italic uppercase tracking-tighter">Start Simulation</div>
                                </div>
                            </div>
                            <ArrowRight size={24} className="group-hover:translate-x-2 transition-transform" />
                        </Link>
                    </div>
                </motion.div>

                {/* Right: Code Remediation */}
                <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="bg-black/40 border border-white/5 rounded-3xl overflow-hidden flex flex-col"
                >
                    <div className="p-6 border-b border-white/5 flex items-center justify-between bg-dark-900/50">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                                <CheckCircle2 size={20} className="text-emerald-500" />
                            </div>
                            <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">Remediation</h2>
                        </div>
                        <div className="flex gap-1.5">
                            <div className="w-2 h-2 rounded-full bg-red-500/20" />
                            <div className="w-2 h-2 rounded-full bg-orange-500/20" />
                            <div className="w-2 h-2 rounded-full bg-emerald-500/20" />
                        </div>
                    </div>

                    <div className="flex-1 p-8 font-mono text-sm overflow-auto scrollbar-cyber bg-[#0d1117]">
                        <pre className="text-gray-300 leading-relaxed">
                            {vuln.codeFix.split('\n').map((line, i) => (
                                <div key={i} className="flex gap-6 group">
                                    <span className="w-8 text-gray-600 text-right select-none">{i + 1}</span>
                                    <span className={
                                        line.includes('// VULNERABLE') ? 'text-red-400 font-bold' :
                                            line.includes('// SECURE') ? 'text-emerald-400 font-bold' :
                                                line.startsWith('//') ? 'text-gray-500 italic' :
                                                    'text-gray-300'
                                    }>
                                        {line}
                                    </span>
                                </div>
                            ))}
                        </pre>
                    </div>
                </motion.div>
            </div>
        </div>
    );
};

export default OWASPLearn;
