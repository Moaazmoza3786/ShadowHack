import React from 'react';
import { BookOpen, Users, Clock, Star, ArrowRight, ShieldCheck, Zap, Activity } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAppContext } from '../context/AppContext';
import { Link } from 'react-router-dom';

export const CourseCard = ({ course }) => {
    const { language } = useAppContext();

    return (
        <Link to={`/course/${course.id}`} className="block h-full group">
            <motion.div
                whileHover={{ y: -10 }}
                transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                className="relative bg-white/[0.03] backdrop-blur-3xl border border-white/5 rounded-[2.5rem] overflow-hidden flex flex-col h-full hover:border-primary-500/30 hover:bg-white/[0.05] transition-all duration-700 shadow-2xl group-hover:shadow-primary-500/10"
            >
                {/* Visual Header */}
                <div className="h-48 relative overflow-hidden shrink-0 bg-dark-950/50 border-b border-white/5">
                    <div className="absolute inset-0 bg-cyber-grid opacity-20" />
                    <div className={`absolute inset-0 bg-gradient-to-br from-primary-500/10 to-transparent group-hover:opacity-100 transition-opacity duration-700`} />
                    
                    {/* Animated Glow */}
                    <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary-500 blur-3xl opacity-0 group-hover:opacity-20 transition-opacity duration-700 rounded-full" />

                    <div className="absolute inset-0 flex items-center justify-center">
                        <div className="relative group-hover:scale-110 transition-transform duration-700 px-8 py-8">
                            <div className="absolute inset-0 bg-primary-500 blur-3xl opacity-10 group-hover:opacity-40 transition-opacity" />
                            <div className="relative w-20 h-20 rounded-3xl bg-dark-900/80 border border-white/10 flex items-center justify-center backdrop-blur-xl group-hover:border-primary-500/50 transition-all shadow-2xl">
                                <BookOpen size={40} className="text-gray-400 group-hover:text-primary-500 transition-colors duration-500" />
                            </div>
                        </div>
                    </div>

                    {/* Meta Badges */}
                    <div className="absolute top-6 left-6 flex items-center gap-2">
                        <div className="px-3 py-1 rounded-full bg-dark-950/80 border border-white/10 backdrop-blur-md flex items-center gap-2">
                            <div className="w-1.5 h-1.5 rounded-full bg-primary-500 animate-pulse" />
                            <span className="text-[10px] font-black text-white/60 tracking-widest uppercase italic">{course.level}</span>
                        </div>
                    </div>

                    {/* Price Tag */}
                    <div className="absolute bottom-6 left-6">
                        <div className="px-4 py-1.5 rounded-2xl bg-primary-500 text-dark-900 text-[10px] font-black tracking-widest uppercase italic shadow-lg shadow-primary-500/20">
                            {course.price === 'مجاني' ? 'Auth Access' : course.price}
                        </div>
                    </div>
                </div>

                {/* Body Content */}
                <div className="p-8 flex flex-col flex-1 relative overflow-hidden">
                    {/* Background Detail */}
                    <div className="absolute -bottom-8 -right-8 w-32 h-32 text-primary-500/5 rotate-12 pointer-events-none">
                        <Activity size={128} />
                    </div>

                    <div className="mb-6">
                        <div className="flex items-center gap-2 mb-3">
                            <span className="text-[9px] font-black text-primary-500 uppercase tracking-[0.3em] italic">Operation Module</span>
                            <div className="h-[1px] flex-1 bg-primary-500/20" />
                        </div>
                        <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter leading-none mb-3 group-hover:text-primary-500 transition-colors duration-500">
                            {language === 'ar' ? course.titleAr : course.title}
                        </h3>
                        <p className="text-xs text-white/40 font-medium leading-relaxed line-clamp-2">
                            {language === 'ar' ? course.description : course.descriptionEn}
                        </p>
                    </div>

                    {/* Data Points */}
                    <div className="grid grid-cols-2 gap-4 py-6 border-t border-b border-white/5 mb-8">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-xl bg-white/5 flex items-center justify-center border border-white/5">
                                <Users size={14} className="text-primary-500" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[8px] font-black text-white/20 uppercase tracking-widest leading-none mb-1">Operatives</span>
                                <span className="text-[10px] font-black text-white/60 uppercase">{course.students}</span>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-xl bg-white/5 flex items-center justify-center border border-white/5">
                                <Clock size={14} className="text-primary-500" />
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[8px] font-black text-white/20 uppercase tracking-widest leading-none mb-1">Duration</span>
                                <span className="text-[10px] font-black text-white/60 uppercase">{course.duration}</span>
                            </div>
                        </div>
                    </div>

                    {/* Footer Action */}
                    <div className="mt-auto flex items-center justify-between group/action">
                        <div className="flex items-center gap-1">
                            {[1, 2, 3, 4, 5].map(i => (
                                <Star key={i} size={10} className={i <= Math.floor(course.rating) ? "text-yellow-500 fill-yellow-500" : "text-white/10"} />
                            ))}
                            <span className="text-[10px] font-black text-white/30 ml-2 italic">{course.rating}</span>
                        </div>
                        
                        <div className="relative">
                            <div className="absolute -inset-2 bg-primary-500 blur-lg opacity-0 group-hover/action:opacity-20 transition-opacity duration-500" />
                            <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-white relative z-10 group-hover/action:bg-primary-500 group-hover/action:text-dark-900 transition-all duration-500 shadow-xl">
                                <ArrowRight size={20} className="group-hover/action:translate-x-1 transition-transform" />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Bottom Bar Detail */}
                <div className="h-1 w-full bg-white/5">
                    <motion.div 
                        initial={{ width: 0 }}
                        whileInView={{ width: '100%' }}
                        transition={{ duration: 1, ease: 'easeOut' }}
                        className="h-full bg-primary-500 opacity-60 shadow-[0_0_10px_currentColor]"
                    />
                </div>
            </motion.div>
        </Link>
    );
};

export default CourseCard;
