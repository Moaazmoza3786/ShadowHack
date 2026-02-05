import React from 'react';
import { motion } from 'framer-motion';
import { Clock, Star, Signal, ArrowLeft } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import { TOPICS_DATA } from '../../data/topics';

const TopicPage = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const config = TOPICS_DATA[id];

    if (!config) {
        return (
            <div className="flex flex-col items-center justify-center py-20">
                <h1 className="text-2xl font-bold text-white mb-4">Topic Not Found</h1>
                <button onClick={() => navigate('/courses')} className="text-primary-500 hover:underline">Return to Courses</button>
            </div>
        );
    }

    return (
        <div className="max-w-6xl mx-auto space-y-12 animate-fade-in">
            <button
                onClick={() => navigate(-1)}
                className="flex items-center gap-2 text-white/30 hover:text-white transition-colors text-xs font-bold uppercase tracking-widest"
            >
                <ArrowLeft size={14} /> Back
            </button>

            <div className="text-center space-y-4">
                <div className="mx-auto w-20 h-20 bg-white/5 rounded-full flex items-center justify-center border border-white/5 mb-6 shadow-2xl" style={{ color: config.color, boxShadow: `0 0 30px ${config.color}20` }}>
                    <config.icon size={40} />
                </div>
                <h1 className="text-5xl font-black tracking-tighter uppercase italic">{config.title}</h1>
                <p className="text-white/40 font-mono tracking-[0.2em] uppercase text-sm">{config.subtitle}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 font-mono">
                {config.rooms.map(room => (
                    <motion.div
                        key={room.title}
                        whileHover={{ y: -5 }}
                        className="bg-dark-800/50 border border-white/5 rounded-3xl p-6 hover:border-white/20 transition-all cursor-pointer group flex flex-col justify-between"
                        style={{ borderLeft: `4px solid ${config.color}` }}
                    >
                        <div className="space-y-4">
                            <h3 className="text-xl font-black group-hover:text-white transition-colors uppercase leading-tight tracking-tight">{room.title}</h3>
                            <p className="text-[11px] text-white/40 leading-relaxed line-clamp-3">{room.desc}</p>

                            <div className="flex flex-wrap gap-4 pt-2">
                                <div className="flex items-center gap-1.5 text-[9px] font-bold text-white/20 uppercase tracking-widest">
                                    <Clock size={12} style={{ color: config.color }} /> {room.time}
                                </div>
                                <div className="flex items-center gap-1.5 text-[9px] font-bold text-white/20 uppercase tracking-widest">
                                    <Star size={12} style={{ color: config.color }} /> {room.points} pts
                                </div>
                                <div className="flex items-center gap-1.5 text-[9px] font-bold text-white/20 uppercase tracking-widest">
                                    <Signal size={12} style={{ color: config.color }} /> {room.difficulty}
                                </div>
                            </div>
                        </div>

                        <button className="mt-6 w-full py-3 bg-white/5 group-hover:bg-white/10 text-white/40 group-hover:text-white font-black rounded-xl border border-white/5 transition-all uppercase tracking-widest text-[10px]">
                            Enter Room
                        </button>
                    </motion.div>
                ))}
            </div>
        </div>
    );
};

export default TopicPage;
