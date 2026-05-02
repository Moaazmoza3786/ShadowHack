import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppContext } from '../context/AppContext';
import OpenRouterAI from '../services/openrouterAI';
import { 
  Brain, 
  Target, 
  ChevronRight, 
  Loader, 
  RefreshCw,
  Sparkles,
  Zap,
  BookOpen,
  FlaskConical,
  Wrench,
  Trophy,
  CheckCircle2
} from 'lucide-react';

const typeIcons = {
  course: BookOpen,
  lab: FlaskConical,
  tool: Wrench,
  challenge: Trophy
};

const typeColors = {
  course: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
  lab: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  tool: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  challenge: 'text-purple-400 bg-purple-500/10 border-purple-500/20'
};

export default function SmartRecommendations() {
  const { user } = useAppContext();
  const [roadmap, setRoadmap] = useState(null);
  const [fallbackText, setFallbackText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [completedSteps, setCompletedSteps] = useState([]);
  const hasFetched = useRef(false); // Prevent React Strict Mode double-call

  const fetchRecommendations = async () => {
    setLoading(true);
    setError('');
    try {
      const apiKey = import.meta.env.VITE_OPENROUTER_API_KEY || 'local';
      
      const ai = new OpenRouterAI(apiKey);
      const data = await ai.getStructuredRoadmap({
        points: user.points,
        level: user.level,
        completedModules: user.completedModules?.join(', ') || 'General Foundation'
      });
      
      if (data.steps && data.steps.length > 0) {
        setRoadmap(data.steps);
        setFallbackText('');
      } else {
        setFallbackText(data.raw || '');
        setRoadmap(null);
      }
    } catch (err) {
      console.error('Rec Error:', err);
      setError('Neural Link Offline');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Guard against React Strict Mode double-invocation
    if (hasFetched.current) return;
    hasFetched.current = true;
    fetchRecommendations();
  }, []);

  const toggleStep = (idx) => {
    setCompletedSteps(prev => 
      prev.includes(idx) ? prev.filter(i => i !== idx) : [...prev, idx]
    );
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative group bg-white/[0.02] backdrop-blur-xl border border-white/5 rounded-[2.5rem] p-8 hover:border-primary-500/20 transition-all duration-700 overflow-hidden"
    >
      <div className="relative z-10 flex flex-col h-full">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-primary-500/10 border border-primary-500/20 flex items-center justify-center">
              <Brain className="text-primary-500 animate-pulse" size={24} />
            </div>
            <div>
              <h3 className="text-lg font-black text-white italic uppercase tracking-tighter leading-none">Neural Roadmap</h3>
              <p className="text-[10px] font-black text-white/30 tracking-widest uppercase mt-1">AI-Powered Learning Path</p>
            </div>
          </div>
          <button 
            onClick={fetchRecommendations}
            disabled={loading}
            className="p-2 hover:bg-white/5 rounded-xl text-white/40 hover:text-primary-500 transition-colors"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 min-h-[200px]">
          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div 
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center py-12 gap-4"
              >
                <div className="relative">
                  <Loader className="animate-spin text-primary-500" size={32} />
                  <Sparkles className="absolute inset-0 m-auto text-primary-500/30" size={14} />
                </div>
                <span className="text-[10px] font-black uppercase tracking-[0.3em] text-white/20">Mapping Neural Path...</span>
              </motion.div>
            ) : error ? (
              <motion.div
                key="error"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-12 gap-3 text-red-400"
              >
                <Zap size={24} />
                <span className="text-xs font-bold">{error}</span>
                <button onClick={fetchRecommendations} className="text-[10px] uppercase tracking-widest text-white/40 hover:text-white transition-colors">
                  Retry Connection
                </button>
              </motion.div>
            ) : roadmap && roadmap.length > 0 ? (
              <motion.div 
                key="roadmap"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-3"
              >
                {roadmap.map((step, idx) => {
                  const TypeIcon = typeIcons[step.type] || Target;
                  const colorClass = typeColors[step.type] || typeColors.course;
                  const isCompleted = completedSteps.includes(idx);
                  
                  return (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      onClick={() => toggleStep(idx)}
                      className={`flex items-start gap-4 p-4 rounded-2xl border cursor-pointer transition-all duration-300 ${
                        isCompleted 
                          ? 'bg-emerald-500/5 border-emerald-500/20 opacity-60' 
                          : 'bg-white/[0.02] border-white/5 hover:bg-white/[0.04] hover:border-white/10'
                      }`}
                    >
                      {/* Step number / check */}
                      <div className="flex flex-col items-center gap-1 pt-0.5">
                        {isCompleted ? (
                          <CheckCircle2 size={18} className="text-emerald-500" />
                        ) : (
                          <div className="w-5 h-5 rounded-full border border-white/20 flex items-center justify-center text-[10px] font-black text-white/40">
                            {idx + 1}
                          </div>
                        )}
                        {idx < roadmap.length - 1 && (
                          <div className="w-px h-6 bg-white/10" />
                        )}
                      </div>

                      {/* Icon */}
                      <div className={`w-9 h-9 rounded-xl border flex items-center justify-center shrink-0 ${colorClass}`}>
                        <TypeIcon size={16} />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <h4 className={`text-sm font-bold leading-tight ${isCompleted ? 'line-through text-white/40' : 'text-white'}`}>
                          {step.title}
                        </h4>
                        <p className="text-[11px] text-white/40 mt-1 leading-relaxed">
                          {step.description}
                        </p>
                        <span className={`text-[9px] font-black uppercase tracking-widest mt-1.5 inline-block ${colorClass.split(' ')[0]}`}>
                          {step.type}
                        </span>
                      </div>
                    </motion.div>
                  );
                })}
              </motion.div>
            ) : fallbackText ? (
              <motion.div 
                key="fallback"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-4"
              >
                <div className="flex items-center gap-2">
                  <Target size={14} className="text-primary-500" />
                  <span className="text-[10px] font-bold text-primary-500 uppercase tracking-widest">Priority Objective</span>
                </div>
                <div className="text-sm text-slate-200 leading-relaxed font-medium italic whitespace-pre-wrap">
                  {fallbackText}
                </div>
              </motion.div>
            ) : (
              <div className="flex items-center justify-center py-12 text-white/20 italic text-sm">
                No active neural patterns detected.
              </div>
            )}
          </AnimatePresence>
        </div>

        {/* Progress bar */}
        {roadmap && roadmap.length > 0 && (
          <div className="mt-6 pt-4 border-t border-white/5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[9px] font-black text-white/20 uppercase tracking-widest">Progress</span>
              <span className="text-[9px] font-black text-primary-500 uppercase tracking-widest">
                {completedSteps.length}/{roadmap.length}
              </span>
            </div>
            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: `${(completedSteps.length / roadmap.length) * 100}%` }}
                transition={{ duration: 0.5, ease: "easeOut" }}
                className="h-full rounded-full bg-primary-500 shadow-[0_0_10px_rgba(239,68,68,0.4)]"
              />
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}
