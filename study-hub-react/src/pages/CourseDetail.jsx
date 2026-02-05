import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAppContext } from '../context/AppContext';
import { courses } from '../data/courses';
import {
    Play,
    BookOpen,
    Clock,
    Users,
    Star,
    CheckCircle2,
    ChevronRight,
    Lock,
    Award,
    Shield,
    Terminal as TerminalIcon,
    ArrowLeft,
    Share2,
    Heart,
    Copy
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLabManager } from '../hooks/useLabManager';
import { useToast } from '../context/ToastContext';

const CourseDetail = () => {
    const { id } = useParams();
    const { t, language } = useAppContext();
    const [activeTab, setActiveTab] = useState('curriculum'); // curriculum, overview, reviews
    const { toast } = useToast();
    const [selectedLesson, setSelectedLesson] = useState(null);

    // Lab Manager Integration
    const {
        status: labStatus,
        isLoading: isLabLoading,
        connectionInfo,
        startLab,
        stopLab,
        terminalOutput
    } = useLabManager(selectedLesson?.machineId);

    const course = courses.find(c => c.id === id);

    if (!course) {
        return (
            <div className="flex flex-col items-center justify-center py-32 text-center">
                <h1 className="text-4xl font-black text-white italic tracking-tighter uppercase mb-4">Course Not Found</h1>
                <Link to="/courses" className="text-primary-500 font-bold uppercase tracking-widest hover:underline flex items-center gap-2">
                    <ArrowLeft size={16} /> Back to Archive
                </Link>
            </div>
        );
    }

    return (
        <div className="space-y-12 pb-20">
            {/* Breadcrumbs & Actions */}
            <div className="flex items-center justify-between">
                <Link to="/courses" className="flex items-center gap-2 text-gray-500 hover:text-white transition-colors text-xs font-black uppercase tracking-widest">
                    <ArrowLeft size={16} /> Archive / {course.level}
                </Link>
                <div className="flex items-center gap-4">
                    <button className="p-3 bg-white/5 border border-white/10 rounded-2xl text-gray-400 hover:text-white hover:border-white/20 transition-all">
                        <Heart size={18} />
                    </button>
                    <button className="p-3 bg-white/5 border border-white/10 rounded-2xl text-gray-400 hover:text-white hover:border-white/20 transition-all">
                        <Share2 size={18} />
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-12">
                {/* Main Content */}
                <div className="xl:col-span-8 space-y-12">
                    <section className="space-y-6">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-widest">
                            <Shield size={12} /> Verified Operation
                        </div>
                        <h1 className="text-6xl font-black text-white italic tracking-tighter uppercase leading-[0.9]">
                            {language === 'ar' ? course.titleAr : course.title}
                        </h1>
                        <p className="text-xl text-gray-400 font-medium leading-relaxed max-w-3xl">
                            {language === 'ar' ? course.description : course.descriptionEn}
                        </p>

                        <div className="flex flex-wrap items-center gap-8 py-6 border-t border-b border-white/5">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-primary-500">
                                    <Star size={18} />
                                </div>
                                <div className="flex flex-col">
                                    <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">Rating</span>
                                    <span className="text-lg font-black text-white italic">{course.rating} / 5.0</span>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-primary-500">
                                    <Users size={18} />
                                </div>
                                <div className="flex flex-col">
                                    <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">Students</span>
                                    <span className="text-lg font-black text-white italic">{course.students.toLocaleString()}</span>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-primary-500">
                                    <Clock size={18} />
                                </div>
                                <div className="flex flex-col">
                                    <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">Intensity</span>
                                    <span className="text-lg font-black text-white italic">{course.duration}</span>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* Tabs */}
                    <div className="space-y-8">
                        <div className="flex items-center gap-8 border-b border-white/5 pb-px">
                            {['Curriculum', 'Overview', 'Reviews'].map((tab) => (
                                <button
                                    key={tab}
                                    onClick={() => setActiveTab(tab.toLowerCase())}
                                    className={`
                                        pb-4 px-2 text-xs font-black uppercase tracking-widest transition-all relative
                                        ${activeTab === tab.toLowerCase() ? 'text-primary-500' : 'text-gray-500 hover:text-gray-300'}
                                    `}
                                >
                                    {tab}
                                    {activeTab === tab.toLowerCase() && (
                                        <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-1 bg-primary-500 shadow-[0_0_10px_#00f2ea]" />
                                    )}
                                </button>
                            ))}
                        </div>

                        <AnimatePresence mode="wait">
                            {activeTab === 'curriculum' && (
                                <motion.div
                                    key="curriculum"
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -10 }}
                                    className="space-y-4"
                                >
                                    {course.modules.map((module, idx) => (
                                        <div key={module.id} className="group rounded-[2rem] bg-dark-800/40 border border-white/5 overflow-hidden hover:border-white/10 transition-all duration-300">
                                            <div className="p-8 flex items-center justify-between">
                                                <div className="flex items-center gap-6">
                                                    <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-gray-500 font-black italic">
                                                        {idx + 1 < 10 ? `0${idx + 1}` : idx + 1}
                                                    </div>
                                                    <div>
                                                        <h3 className="text-xl font-black text-white italic uppercase tracking-tighter leading-none mb-1 group-hover:text-primary-500 transition-colors">
                                                            {language === 'ar' ? module.titleAr : module.title}
                                                        </h3>
                                                        <p className="text-[10px] font-black text-gray-600 uppercase tracking-widest">{module.lessons.length} Lessons • {module.duration}</p>
                                                    </div>
                                                </div>
                                                <ChevronRight className="text-gray-600 group-hover:text-primary-500 group-hover:translate-x-1 transition-all" />
                                            </div>

                                            <div className="px-8 pb-8 space-y-3">
                                                {module.lessons.map((lesson) => (
                                                    <div key={lesson.id} className="space-y-4">
                                                        <div
                                                            onClick={() => setSelectedLesson(selectedLesson?.id === lesson.id ? null : lesson)}
                                                            className={`flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/5 hover:bg-white/10 transition-colors cursor-pointer group/lesson ${selectedLesson?.id === lesson.id ? 'border-primary-500/50 bg-white/10' : ''}`}
                                                        >
                                                            <div className="flex items-center gap-4">
                                                                <div className="w-8 h-8 rounded-lg bg-dark-900 flex items-center justify-center text-gray-500 group-hover/lesson:text-primary-500 transition-colors">
                                                                    {lesson.type === 'lab' ? <TerminalIcon size={14} /> : <Play size={14} fill="currentColor" />}
                                                                </div>
                                                                <span className="text-xs font-bold text-gray-300">{language === 'ar' ? lesson.titleAr : lesson.title}</span>
                                                            </div>
                                                            <div className="flex items-center gap-4">
                                                                {lesson.type === 'lab' && <span className="text-[8px] font-black px-2 py-0.5 rounded bg-primary-500/20 text-primary-500 uppercase">Lab</span>}
                                                                <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">{lesson.duration || '15m'}</span>
                                                            </div>
                                                        </div>

                                                        {/* Expanded Lesson Content */}
                                                        <AnimatePresence>
                                                            {selectedLesson?.id === lesson.id && (
                                                                <motion.div
                                                                    initial={{ height: 0, opacity: 0 }}
                                                                    animate={{ height: 'auto', opacity: 1 }}
                                                                    exit={{ height: 0, opacity: 0 }}
                                                                    className="overflow-hidden bg-black/40 rounded-2xl p-6 space-y-6 border border-white/5"
                                                                >
                                                                    <p className="text-sm text-gray-400 leading-relaxed italic">
                                                                        {lesson.content}
                                                                    </p>

                                                                    {lesson.type === 'lab' && (
                                                                        <div className="space-y-6">
                                                                            <div className="flex items-center justify-between p-4 bg-dark-800 rounded-xl border border-white/10">
                                                                                <div className="flex items-center gap-4">
                                                                                    <div className={`w-3 h-3 rounded-full ${labStatus === 'running' ? 'bg-green-500' : 'bg-gray-600'}`} />
                                                                                    <div>
                                                                                        <div className="text-[10px] font-black text-gray-500 uppercase tracking-widest leading-none mb-1">Status</div>
                                                                                        <div className="text-xs font-black text-white italic uppercase tracking-tighter">{labStatus === 'running' ? 'Active' : 'Offline'}</div>
                                                                                    </div>
                                                                                </div>
                                                                                <button
                                                                                    onClick={labStatus === 'running' ? stopLab : startLab}
                                                                                    disabled={isLabLoading}
                                                                                    className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${labStatus === 'running' ? 'bg-red-500/10 text-red-500 border border-red-500/20' : 'bg-primary-500 text-dark-900 shadow-lg shadow-primary-500/20'}`}
                                                                                >
                                                                                    {isLabLoading ? 'Connecting...' : (labStatus === 'running' ? 'Stop Machine' : 'Spawn Machine')}
                                                                                </button>
                                                                            </div>

                                                                            {labStatus === 'running' && connectionInfo && (
                                                                                <div className="p-4 bg-primary-500/5 border border-primary-500/20 rounded-xl space-y-2">
                                                                                    <div className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Instance URI</div>
                                                                                    <code className="text-sm font-mono text-white break-all flex items-center justify-between">
                                                                                        {connectionInfo.ip}:{connectionInfo.port}
                                                                                        <button onClick={() => { navigator.clipboard.writeText(`${connectionInfo.ip}:${connectionInfo.port}`); toast('URI Copied', 'success'); }} className="p-1 hover:bg-primary-500/10 rounded">
                                                                                            <Copy size={12} className="text-primary-500" />
                                                                                        </button>
                                                                                    </code>
                                                                                </div>
                                                                            )}

                                                                            {lesson.tasks && (
                                                                                <div className="space-y-4">
                                                                                    <h4 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.2em] px-2 flex items-center gap-2">
                                                                                        <CheckCircle2 size={12} className="text-primary-500" /> Operational Objectives
                                                                                    </h4>
                                                                                    <div className="space-y-2">
                                                                                        {lesson.tasks.map(task => (
                                                                                            <div key={task.id} className="flex items-center gap-3 p-4 bg-white/5 rounded-xl border border-white/5 hover:bg-white/10 transition-colors">
                                                                                                <input type="checkbox" className="w-4 h-4 rounded border-white/10 bg-dark-900 text-primary-500 focus:ring-primary-500" />
                                                                                                <span className="text-xs text-gray-300 font-medium">{task.text}</span>
                                                                                            </div>
                                                                                        ))}
                                                                                    </div>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    )}
                                                                </motion.div>
                                                            )}
                                                        </AnimatePresence>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </motion.div>
                            )}

                            {activeTab === 'overview' && (
                                <motion.div
                                    key="overview"
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: -10 }}
                                    className="space-y-12"
                                >
                                    <section className="space-y-6">
                                        <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter">Mission Objectives</h3>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            {course.whatYouWillLearn.map((objective, i) => (
                                                <div key={i} className="flex items-center gap-4 p-4 rounded-2xl bg-white/5 border border-white/5">
                                                    <CheckCircle2 className="text-primary-500 shrink-0" size={20} />
                                                    <span className="text-sm font-medium text-gray-300">{objective}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </section>

                                    <section className="space-y-6">
                                        <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter">Prerequisites</h3>
                                        <div className="flex flex-wrap gap-3">
                                            {course.skills.map((skill, i) => (
                                                <span key={i} className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-gray-400 uppercase tracking-widest">
                                                    {skill}
                                                </span>
                                            ))}
                                        </div>
                                    </section>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>

                {/* Sidebar Card */}
                <div className="xl:col-span-4">
                    <div className="sticky top-32 space-y-8">
                        <div className="rounded-[3rem] bg-dark-800 border-2 border-primary-500/20 shadow-2xl shadow-primary-500/10 overflow-hidden group">
                            <div className="h-64 relative bg-dark-900 flex items-center justify-center overflow-hidden">
                                <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                                <div className="relative z-10 w-24 h-24 rounded-[2rem] bg-white/5 border border-white/10 flex items-center justify-center text-primary-500 group-hover:scale-110 group-hover:border-primary-500 transition-all duration-700">
                                    <TerminalIcon size={48} />
                                </div>
                                <div className="absolute top-6 left-6 px-3 py-1 rounded-full bg-primary-500 text-dark-900 text-[10px] font-black uppercase tracking-widest shadow-lg shadow-primary-500/20">
                                    MISSION READY
                                </div>
                            </div>

                            <div className="p-10 space-y-8">
                                <div className="flex items-end justify-between">
                                    <div className="space-y-1">
                                        <p className="text-[11px] font-black text-gray-500 uppercase tracking-[0.2em] leading-none">Tuition Cost</p>
                                        <p className="text-4xl font-black text-white italic tracking-tighter uppercase">{course.price}</p>
                                    </div>
                                    <div className="flex items-center gap-1 px-3 py-1 rounded-lg bg-green-500/10 text-green-500 border border-green-500/20 text-[10px] font-black uppercase tracking-widest">
                                        Lifetime Access
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <button className="w-full py-5 bg-primary-500 text-dark-900 text-lg font-black uppercase italic tracking-tighter rounded-3xl hover:bg-primary-400 transition-all shadow-xl shadow-primary-500/20 active:scale-95 flex items-center justify-center gap-3">
                                        <Play size={20} fill="currentColor" />
                                        Initialize Mission
                                    </button>
                                    <button className="w-full py-5 text-gray-400 text-sm font-black uppercase tracking-widest rounded-3xl border border-white/5 hover:bg-white/5 transition-all">
                                        Enroll with Enterprise
                                    </button>
                                </div>

                                <div className="space-y-4 pt-4 border-t border-white/5">
                                    <p className="text-[10px] font-black text-gray-600 uppercase tracking-widest mb-6">Course Includes:</p>
                                    <div className="space-y-4">
                                        <div className="flex items-center gap-4 text-xs font-bold text-gray-400">
                                            <div className="w-1.5 h-1.5 rounded-full bg-primary-500" />
                                            Specialized Certificate of Completion
                                        </div>
                                        <div className="flex items-center gap-4 text-xs font-bold text-gray-400">
                                            <div className="w-1.5 h-1.5 rounded-full bg-primary-500" />
                                            Advanced Attack Infrastructure Access
                                        </div>
                                        <div className="flex items-center gap-4 text-xs font-bold text-gray-400">
                                            <div className="w-1.5 h-1.5 rounded-full bg-primary-500" />
                                            Live Cloud Sandbox Labs
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="p-8 rounded-[2.5rem] bg-dark-800/40 border border-white/5 flex items-center gap-6">
                            <div className="w-12 h-12 rounded-2xl bg-accent-500/10 flex items-center justify-center text-accent-500">
                                <Award size={24} />
                            </div>
                            <div>
                                <h4 className="text-sm font-black text-white uppercase italic tracking-widest leading-none mb-1">Elite Instructor</h4>
                                <p className="text-xs text-gray-500 font-bold uppercase tracking-widest">{course.instructor}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CourseDetail;
