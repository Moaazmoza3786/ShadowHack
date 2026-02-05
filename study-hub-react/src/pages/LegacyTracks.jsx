import React from 'react';
import { motion } from 'framer-motion';
import { History, Archive, ChevronRight, FileCode, BookOpen } from 'lucide-react';
import { legacyTracks } from '../data/legacy-tracks-data';

const LegacyTracks = () => {
    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700">
            {/* Header */}
            <div>
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-gray-500/10 border border-gray-500/20 text-gray-500 text-[10px] font-black uppercase tracking-[0.2em] mb-4">
                    <History size={12} />
                    Historical Archive
                </div>
                <h1 className="text-7xl font-black text-white italic tracking-tighter uppercase leading-none glitch-text">
                    Legacy <span className="text-transparent bg-clip-text bg-gradient-to-r from-gray-500 to-gray-700">Tracks</span>
                </h1>
                <p className="mt-4 text-gray-400 italic font-medium max-w-xl">
                    Access older learning paths and archived training material.
                    These tracks contain foundational knowledge that remains relevant to this day.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {legacyTracks.map((track, idx) => (
                    <motion.div
                        key={track.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: idx * 0.1 }}
                        className="group p-8 rounded-[2rem] bg-dark-800/40 border border-white/5 hover:border-white/10 transition-all duration-500 overflow-hidden relative"
                    >
                        <div className="absolute top-0 right-0 p-8 opacity-[0.02] group-hover:opacity-[0.05] transition-opacity">
                            <Archive size={120} />
                        </div>

                        <div className="relative z-10 flex flex-col h-full">
                            <h3 className="text-3xl font-black text-white italic uppercase tracking-tighter mb-4 group-hover:text-primary-500 transition-colors">
                                {track.title}
                            </h3>
                            <p className="text-gray-500 italic text-sm mb-8">
                                {track.description}
                            </p>

                            <div className="space-y-3 flex-1">
                                {track.courses.map((course, i) => (
                                    <div key={i} className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/5 group/item hover:bg-white/10 transition-colors">
                                        <div className="flex items-center gap-3">
                                            <FileCode size={16} className="text-gray-500 group-hover/item:text-primary-500 transition-colors" />
                                            <span className="text-xs font-bold text-gray-300 uppercase tracking-widest">{course.title}</span>
                                        </div>
                                        <span className="text-[10px] font-black text-gray-600 uppercase tracking-widest">{course.modules} Modules</span>
                                    </div>
                                ))}
                            </div>

                            <button className="mt-8 w-full py-4 rounded-2xl bg-white/5 border border-white/10 text-white font-black uppercase tracking-widest text-[10px] hover:bg-primary-500 hover:text-white hover:border-primary-500 transition-all flex items-center justify-center gap-2 group/btn">
                                Access Archive
                                <ChevronRight size={14} className="group-hover/btn:translate-x-1 transition-transform" />
                            </button>
                        </div>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default LegacyTracks;
