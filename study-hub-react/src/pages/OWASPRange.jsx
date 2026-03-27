import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
    Shield,
    Lock,
    Key,
    Database,
    Code,
    Settings,
    Package,
    UserCheck,
    GitBranch,
    Activity,
    Award,
    BookOpen,
    Play,
    Globe,
    Rocket,
    AlertCircle,
    RefreshCcw,
    Monitor,
    Zap
} from 'lucide-react';
import { AnimatePresence } from 'framer-motion';

import { owaspEducationData } from '../data/owasp-data';

const iconMap = {
    Lock,
    Key,
    Database,
    Code,
    Settings,
    Package,
    UserCheck,
    GitBranch,
    Activity,
    Globe
};


const OWASPRange = () => {
    const vulnerabilities = Object.values(owaspEducationData || {});
    const [activeCodespaces, setActiveCodespaces] = React.useState([]);
    const [isDeploying, setIsDeploying] = React.useState({});
    const [notification, setNotification] = React.useState(null);

    const toast = (message, type = 'info') => {
        setNotification({ message, type });
        setTimeout(() => setNotification(null), 3000);
    };

    const fetchCodespaces = async () => {
        try {
            const res = await fetch('/api/codespaces/active');
            const data = await res.json();
            if (data.success) {
                setActiveCodespaces(Object.entries(data.environments).map(([id, env]) => ({ id, ...env })));
            }
        } catch (err) {
            console.error("Failed to fetch codespaces:", err);
        }
    };

    React.useEffect(() => {
        fetchCodespaces();
        const interval = setInterval(fetchCodespaces, 10000);
        return () => clearInterval(interval);
    }, []);

    const deployMission = async (vulnId) => {
        if (activeCodespaces.length === 0) {
            toast("No active Codespace Bridge found", "error");
            return;
        }

        setIsDeploying(prev => ({ ...prev, [vulnId]: true }));
        try {
            const res = await fetch('/api/codespaces/deploy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    codespace_id: activeCodespaces[0].id,
                    artifact: {
                        name: `OWASP-${vulnId}-Mission`,
                        type: 'mission_hub',
                        content: `Initiating OWASP Tactical Mission: ${vulnId}\nTargeting environment...`
                    }
                })
            });
            const data = await res.json();
            if (data.success) {
                toast(`Tactical Hub for ${vulnId} deployed!`, "success");
            } else {
                toast(data.error || "Deployment failed", "error");
            }
        } catch (err) {
            toast("Connection to bridge failed", "error");
        } finally {
            setIsDeploying(prev => ({ ...prev, [vulnId]: false }));
        }
    };

    const stats = [
        { icon: Package, label: '10 Modules', color: 'text-blue-500' },
        { icon: Activity, label: 'Live Simulation', color: 'text-blue-400' },
        { icon: Award, label: 'Pro Certification', color: 'text-blue-300' }
    ];

    return (
        <div className="min-h-screen space-y-12 pb-20 relative">
            {/* Notification Toast */}
            <AnimatePresence>
                {notification && (
                    <motion.div
                        initial={{ opacity: 0, y: -20, x: '-50%' }}
                        animate={{ opacity: 1, y: 0, x: '-50%' }}
                        exit={{ opacity: 0, y: -20, x: '-50%' }}
                        className={`fixed top-8 left-1/2 z-[200] px-6 py-3 rounded-2xl border backdrop-blur-md shadow-2xl flex items-center gap-3 ${notification.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-500' :
                                notification.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                                    'bg-primary-500/10 border-primary-500/20 text-primary-500'
                            }`}
                    >
                        {notification.type === 'success' ? <Rocket size={18} /> : <AlertCircle size={18} />}
                        <span className="text-xs font-black uppercase tracking-widest">{notification.message}</span>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Header Section */}
            <div className="text-center space-y-6">
                <div className="flex justify-center items-center gap-4">
                    <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center neon-glow-primary">
                        <Shield size={32} className="text-white" />
                    </div>
                    <h1 className="text-6xl font-black italic tracking-tighter uppercase leading-none">
                        OWASP <span className="text-red-500">Cyber Range</span>
                    </h1>
                </div>
                <p className="text-gray-400 font-medium tracking-wide uppercase text-sm">
                    Professional Vulnerability Assessment & Exploitation Simulation
                </p>

                {/* Stat Badges */}
                <div className="flex items-center justify-center gap-8 pt-4">
                    {stats.map((stat, idx) => {
                        const Icon = stat.icon;
                        return (
                            <div key={idx} className="flex items-center gap-2 group cursor-default">
                                <Icon size={16} className={`${stat.color} group-hover:scale-110 transition-transform`} />
                                <span className="text-[10px] font-black uppercase tracking-[0.2em] text-gray-500 group-hover:text-gray-300 transition-colors">
                                    {stat.label}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Grid Layout */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 px-4">
                {vulnerabilities.map((vuln, idx) => {
                    const Icon = iconMap[vuln.icon] || Shield;
                    return (
                        <motion.div
                            key={vuln.id}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.05 }}
                            className="group relative bg-dark-800/40 border border-white/5 rounded-2xl p-8 hover:border-primary-500/30 transition-all hover:shadow-[0_0_30px_rgba(239,68,68,0.05)]"
                        >
                            {/* Card Content */}
                            <div className="space-y-6">
                                <div className="flex items-start justify-between">
                                    <div className="w-14 h-14 rounded-xl bg-white/5 border border-white/5 flex items-center justify-center group-hover:scale-110 transition-transform duration-500">
                                        <Icon size={28} className="text-blue-500" />
                                    </div>
                                    <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981]" />
                                </div>

                                <div className="space-y-4">
                                    <h3 className="text-xl font-bold text-gray-100 group-hover:text-white transition-colors">
                                        {vuln.title}
                                    </h3>

                                    <div className={`inline-flex px-3 py-1 rounded-full text-[10px] font-black tracking-widest border ${vuln.difficulty === 'HARD' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                                        vuln.difficulty === 'MEDIUM' ? 'bg-orange-500/10 border-orange-500/20 text-orange-500' :
                                            'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                                        }`}>
                                        {vuln.difficulty}
                                    </div>
                                    <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/5 border border-white/10">
                                        <Monitor size={10} className="text-gray-500" />
                                        <span className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Codespace Ready</span>
                                    </div>
                                </div>

                                {/* Action Buttons */}
                                <div className="space-y-3 pt-4">
                                    <div className="flex items-center gap-3">
                                        <Link
                                            to={`/owasp-range/${vuln.id}/learn`}
                                            className="flex-1 h-10 flex items-center justify-center gap-2 rounded-lg bg-primary-600/20 border border-primary-500/30 text-white text-xs font-black uppercase tracking-widest hover:bg-primary-500 transition-all shadow-[0_0_15px_rgba(239,68,68,0.1)]"
                                        >
                                            <BookOpen size={14} />
                                            <span>Learn</span>
                                        </Link>
                                        <Link
                                            to={`/owasp-range/${vuln.id}/practice`}
                                            className="flex-1 h-10 flex items-center justify-center gap-2 rounded-lg bg-dark-900/50 border border-white/10 text-gray-300 text-xs font-black uppercase tracking-widest hover:bg-white/5 hover:text-white transition-all hover:border-white/20"
                                        >
                                            <Play size={14} />
                                            <span>Practice</span>
                                        </Link>
                                    </div>
                                    <button
                                        onClick={() => deployMission(vuln.id)}
                                        disabled={isDeploying[vuln.id]}
                                        className="w-full h-11 flex items-center justify-center gap-3 rounded-xl bg-white/5 border border-white/10 text-gray-400 text-[10px] font-black uppercase tracking-[0.2em] hover:bg-emerald-500/10 hover:border-emerald-500/30 hover:text-emerald-500 transition-all group/btn"
                                    >
                                        {isDeploying[vuln.id] ? (
                                            <RefreshCcw size={16} className="animate-spin" />
                                        ) : (
                                            <Zap size={16} className="group-hover/btn:scale-125 transition-transform" />
                                        )}
                                        {isDeploying[vuln.id] ? 'Deploying...' : 'Initiate Tactical Lab'}
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    );
                })}
            </div>
        </div>
    );
};

export default OWASPRange;

