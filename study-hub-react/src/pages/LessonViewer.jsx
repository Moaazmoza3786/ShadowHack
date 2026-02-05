import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useAppContext } from '../context/AppContext';
import { courses } from '../data/courses';
import {
    Play,
    CheckCircle2,
    ArrowLeft,
    ArrowRight,
    Terminal as TerminalIcon,
    Menu,
    X,
    MessageSquare,
    Settings,
    Shield,
    Award,
    Maximize2,
    Volume2,
    BookOpen
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';

const LessonViewer = () => {
    const { courseId, lessonId } = useParams();
    const navigate = useNavigate();
    const { t, language } = useAppContext();
    const [sidebarOpen, setSidebarOpen] = useState(true);

    const course = courses.find(c => c.id === courseId);
    if (!course) return <div>Course not found</div>;

    const allLessons = course.modules.flatMap(m => m.lessons);
    const currentLessonIndex = allLessons.findIndex(l => l.id === lessonId);
    const currentLesson = allLessons[currentLessonIndex];

    const nextLesson = allLessons[currentLessonIndex + 1];
    const prevLesson = allLessons[currentLessonIndex - 1];

    if (!currentLesson) return <div>Lesson not found</div>;

    return (
        <div className="flex h-screen bg-dark-900 overflow-hidden fixed inset-0 z-[60]">
            {/* Sidebar - Course Index */}
            <AnimatePresence mode="wait">
                {sidebarOpen && (
                    <motion.aside
                        initial={{ x: -300, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        exit={{ x: -300, opacity: 0 }}
                        className="w-80 h-full bg-dark-800 border-r border-white/5 flex flex-col z-10"
                    >
                        <div className="p-6 border-b border-white/5 flex items-center justify-between">
                            <h2 className="text-sm font-black text-white italic uppercase tracking-widest">Operation Index</h2>
                            <button onClick={() => setSidebarOpen(false)} className="text-gray-500 hover:text-white">
                                <X size={20} />
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto scrollbar-cyber p-4 space-y-8">
                            {course.modules.map((module, mIdx) => (
                                <div key={module.id} className="space-y-3">
                                    <p className="px-2 text-[10px] font-black text-gray-500 uppercase tracking-widest">
                                        Phase {mIdx + 1}: {language === 'ar' ? module.titleAr : module.title}
                                    </p>
                                    <div className="space-y-1">
                                        {module.lessons.map((lesson) => (
                                            <Link
                                                key={lesson.id}
                                                to={`/course/${course.id}/lesson/${lesson.id}`}
                                                className={`
                                                    w-full flex items-center gap-3 p-3 rounded-xl transition-all border
                                                    ${lesson.id === lessonId
                                                        ? 'bg-primary-500/10 border-primary-500/20 text-primary-500'
                                                        : 'border-transparent text-gray-400 hover:bg-white/5 hover:text-gray-100'}
                                                `}
                                            >
                                                <div className={`w-1.5 h-1.5 rounded-full ${lesson.id === lessonId ? 'bg-primary-500 shadow-[0_0_8px_#00f2ea]' : 'bg-gray-700'}`} />
                                                <span className="text-[11px] font-bold uppercase tracking-tight line-clamp-1">
                                                    {language === 'ar' ? lesson.titleAr : lesson.title}
                                                </span>
                                            </Link>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>

                        <div className="p-4 border-t border-white/5">
                            <div className="p-4 rounded-2xl bg-dark-900 border border-white/5">
                                <p className="text-[9px] font-black text-gray-600 uppercase tracking-widest mb-2">Completion Status</p>
                                <div className="h-1 bg-white/5 rounded-full overflow-hidden mb-2">
                                    <div className="h-full bg-primary-500 w-1/3 shadow-[0_0_10px_#00f2ea]"></div>
                                </div>
                                <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest leading-none">33% SECURED</p>
                            </div>
                        </div>
                    </motion.aside>
                )}
            </AnimatePresence>

            {/* Main Content Area */}
            <main className="flex-1 flex flex-col min-w-0 bg-cyber-grid">
                {/* Header */}
                <header className="h-16 bg-dark-800/80 backdrop-blur-xl border-b border-white/5 flex items-center justify-between px-8 relative z-20">
                    <div className="flex items-center gap-4">
                        {!sidebarOpen && (
                            <button onClick={() => setSidebarOpen(true)} className="p-2 text-gray-400 hover:text-white transition-colors">
                                <Menu size={20} />
                            </button>
                        )}
                        <div className="flex flex-col">
                            <div className="flex items-center gap-2">
                                <Shield size={12} className="text-primary-500" />
                                <span className="text-[10px] font-black text-primary-500 uppercase tracking-[0.2em]">Secure Node 0x77</span>
                            </div>
                            <h1 className="text-xs font-black text-white italic uppercase tracking-widest leading-none">
                                {language === 'ar' ? currentLesson.titleAr : currentLesson.title}
                            </h1>
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        <Link to={`/course/${course.id}`} className="px-4 py-2 text-[10px] font-black text-gray-500 hover:text-white uppercase tracking-widest transition-colors flex items-center gap-2">
                            <X size={14} /> Exit Mission
                        </Link>
                    </div>
                </header>

                {/* Content Scroller */}
                <div className="flex-1 overflow-y-auto scrollbar-cyber p-8 lg:p-12">
                    <div className="max-w-4xl mx-auto space-y-12 pb-32">
                        {/* Video / Visual Placeholder */}
                        <div className="aspect-video rounded-[2.5rem] bg-dark-800 border border-white/5 overflow-hidden relative group shadow-2xl">
                            <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                            <div className="absolute inset-0 flex items-center justify-center">
                                <div className="w-20 h-20 rounded-full bg-primary-500/10 border border-primary-500/20 flex items-center justify-center text-primary-500 group-hover:scale-110 group-hover:bg-primary-500 group-hover:text-dark-900 transition-all duration-500 cursor-pointer shadow-lg shadow-primary-500/10">
                                    <Play size={32} fill="currentColor" />
                                </div>
                            </div>
                            <div className="absolute bottom-6 left-6 right-6 flex items-center justify-between opacity-0 group-hover:opacity-100 transition-opacity">
                                <div className="flex items-center gap-4 text-gray-400">
                                    <Volume2 size={18} />
                                    <div className="h-1 w-32 bg-white/10 rounded-full overflow-hidden">
                                        <div className="h-full bg-primary-500 w-3/4"></div>
                                    </div>
                                </div>
                                <Maximize2 size={18} className="text-gray-400" />
                            </div>
                        </div>

                        {/* Text Content */}
                        <article className="prose prose-invert prose-cyber max-w-none">
                            <ReactMarkdown className="text-gray-300 font-medium leading-[2]">
                                {currentLesson.content || 'Decrypting module data...'}
                            </ReactMarkdown>
                        </article>

                        {/* Completion Card */}
                        <div className="p-10 rounded-[3rem] bg-gradient-to-br from-primary-500/10 to-transparent border border-primary-500/20 flex flex-col md:flex-row md:items-center justify-between gap-8 relative overflow-hidden group">
                            <div className="relative z-10 flex items-center gap-6">
                                <div className="w-16 h-16 rounded-[1.5rem] bg-primary-500 flex items-center justify-center text-dark-900 shadow-xl shadow-primary-500/20">
                                    <Award size={32} />
                                </div>
                                <div className="space-y-1">
                                    <h3 className="text-2xl font-black text-white italic tracking-tighter uppercase leading-none">PHASE COMPLETE?</h3>
                                    <p className="text-[10px] font-black text-primary-500 uppercase tracking-widest">Seal this operation and gain 50 XP</p>
                                </div>
                            </div>
                            <button className="relative z-10 px-10 py-4 bg-primary-500 text-dark-900 text-sm font-black uppercase italic tracking-tighter rounded-2xl hover:bg-primary-400 hover:scale-105 transition-all shadow-xl shadow-primary-500/20 active:scale-95">
                                Secure Checkpoint
                            </button>
                            <div className="absolute -right-8 -bottom-8 opacity-5 group-hover:scale-110 transition-transform duration-700">
                                <Shield size={120} />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Footer Navigation */}
                <footer className="h-20 bg-dark-900/80 backdrop-blur-xl border-t border-white/5 flex items-center justify-center px-12 relative z-20">
                    <div className="max-w-4xl w-full flex items-center justify-between">
                        <button
                            disabled={!prevLesson}
                            onClick={() => navigate(`/course/${course.id}/lesson/${prevLesson.id}`)}
                            className="flex items-center gap-3 text-xs font-black text-gray-500 hover:text-white uppercase tracking-widest transition-colors disabled:opacity-20"
                        >
                            <ArrowLeft size={16} /> Previous Link
                        </button>

                        <div className="hidden lg:flex items-center gap-8 px-6 py-2 bg-white/5 border border-white/5 rounded-2xl">
                            <div className="flex flex-col items-center">
                                <span className="text-[8px] font-black text-gray-600 uppercase tracking-widest">Active Lesson</span>
                                <span className="text-[10px] font-black text-white italic">{currentLessonIndex + 1} / {allLessons.length}</span>
                            </div>
                            <div className="h-6 w-px bg-white/5" />
                            <button className="text-gray-500 hover:text-white transition-colors">
                                <MessageSquare size={18} />
                            </button>
                            <button className="text-gray-500 hover:text-white transition-colors">
                                <Settings size={18} />
                            </button>
                        </div>

                        <button
                            disabled={!nextLesson}
                            onClick={() => navigate(`/course/${course.id}/lesson/${nextLesson.id}`)}
                            className="flex items-center gap-3 text-xs font-black text-primary-500 hover:text-white hover:bg-primary-500/10 px-6 py-3 border border-primary-500/20 rounded-2xl uppercase tracking-widest transition-all disabled:opacity-20 translate-middle"
                        >
                            Proceed to Next <ArrowRight size={16} />
                        </button>
                    </div>
                </footer>
            </main>
        </div>
    );
};

export default LessonViewer;
