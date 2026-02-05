import React from 'react';
import { BookOpen, Users, Clock, Star, ArrowRight, ShieldCheck, Zap } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAppContext } from '../context/AppContext';
import { Link } from 'react-router-dom';

export const CourseCard = ({ course }) => {
    const { t, language } = useAppContext();

    return (
        <Link to={`/course/${course.id}`} className="block h-full group">
            <motion.div
                whileHover={{ y: -5 }}
                className="relative bg-dark-800/40 backdrop-blur-md border border-white/5 rounded-3xl overflow-hidden flex flex-col h-full hover:border-primary-500/30 transition-all duration-500 shadow-2xl"
            >
                {/* Decorative Elements */}
                <div className="absolute top-0 right-0 w-32 h-32 bg-primary-500/5 blur-3xl rounded-full -mr-16 -mt-16 group-hover:bg-primary-500/10 transition-colors"></div>

                {/* Thumbnail Area */}
                <div className="h-44 relative overflow-hidden shrink-0 bg-dark-900/50">
                    <div className="absolute inset-0 bg-gradient-to-br from-primary-500/10 to-transparent mix-blend-overlay"></div>
                    <div className="absolute inset-0 flex items-center justify-center">
                        <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:scale-110 group-hover:border-primary-500/50 transition-all duration-500 backdrop-blur-sm">
                            <BookOpen size={32} className="text-gray-500 group-hover:text-primary-500 transition-colors" />
                        </div>
                    </div>

                    {/* Badge */}
                    <div className="absolute top-4 left-4">
                        <span className="px-2 py-1 rounded-md bg-dark-900/80 border border-white/10 text-[9px] font-black uppercase tracking-widest text-primary-500 backdrop-blur-md">
                            {course.level}
                        </span>
                    </div>

                    {/* Progress Blur */}
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/5">
                        <div className="h-full bg-primary-500 w-0 group-hover:w-full transition-all duration-1000 ease-out shadow-[0_0_10px_#00f2ea]"></div>
                    </div>
                </div>

                {/* Content Area */}
                <div className="p-6 flex flex-col flex-1">
                    <div className="mb-4">
                        <h3 className="text-lg font-black text-gray-100 italic uppercase tracking-tight leading-tight group-hover:text-white transition-colors mb-2">
                            {language === 'ar' ? course.titleAr : course.title}
                        </h3>
                        <p className="text-xs text-gray-500 line-clamp-2 leading-relaxed">
                            {language === 'ar' ? course.description : course.descriptionEn}
                        </p>
                    </div>

                    <div className="flex items-center gap-4 py-4 border-t border-b border-white/5 mb-6">
                        <div className="flex items-center gap-1.5">
                            <Users size={14} className="text-primary-500/70" />
                            <span className="text-[10px] font-bold text-gray-400">{course.students}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <Clock size={14} className="text-primary-500/70" />
                            <span className="text-[10px] font-bold text-gray-400">{course.duration}</span>
                        </div>
                        <div className="flex items-center gap-1.5 ml-auto">
                            <Star size={14} className="text-yellow-500/70" />
                            <span className="text-[10px] font-bold text-gray-400">{course.rating}</span>
                        </div>
                    </div>

                    <div className="mt-auto flex items-center justify-between">
                        <div className="flex flex-col">
                            <span className="text-[8px] font-black text-gray-600 uppercase tracking-widest leading-none mb-1">Tuition</span>
                            <span className="text-sm font-black italic text-white uppercase tracking-tighter">{course.price === 'مجاني' ? 'Free Access' : course.price}</span>
                        </div>
                        <div className="flex items-center gap-2 group/btn">
                            <span className="text-[10px] font-black text-primary-500 uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-all -translate-x-2 group-hover:translate-x-0">Deploy</span>
                            <div className="w-10 h-10 rounded-xl bg-primary-500 flex items-center justify-center text-dark-900 shadow-lg shadow-primary-500/20 group-hover:shadow-primary-500/40 transition-all">
                                <ArrowRight size={18} />
                            </div>
                        </div>
                    </div>
                </div>
            </motion.div>
        </Link>
    );
};

export default CourseCard;
