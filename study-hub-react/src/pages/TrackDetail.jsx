import React, { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronLeft, BookOpen, Play, CheckCircle2, Lock,
  Youtube, Clock, Zap, Trophy, ChevronDown, ChevronRight,
  Shield, Target, Star, Users, Award, ExternalLink
} from 'lucide-react';import { learningPaths } from '../data/learning-paths-data';
import { youtubeCoursesData } from '../data/youtube-data';
import { useAppContext } from '../context/AppContext';
import LessonViewer from '../components/LessonViewer';

// ─── helpers ─────────────────────────────────────────────────────────────────
const LEVEL_STYLES = {
  beginner:     { badge: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400', bar: 'bg-emerald-500' },
  intermediate: { badge: 'bg-yellow-500/10  border-yellow-500/20  text-yellow-400',  bar: 'bg-yellow-500'  },
  advanced:     { badge: 'bg-red-500/10     border-red-500/20     text-red-400',     bar: 'bg-red-500'     },
  expert:       { badge: 'bg-purple-500/10  border-purple-500/20  text-purple-400',  bar: 'bg-purple-500'  },
};

// ─── Module Accordion ────────────────────────────────────────────────────────
function ModuleAccordion({ mod, index, completedLessons, onLessonClick, isAr }) {
  const [open, setOpen] = useState(index === 0);
  const done = mod.lessons.filter(l => completedLessons.includes(l.file)).length;
  const pct  = mod.lessons.length ? Math.round((done / mod.lessons.length) * 100) : 0;

  return (
    <div className={`rounded-2xl border overflow-hidden transition-all ${open ? 'border-white/10' : 'border-white/5'}`}>
      <button onClick={() => setOpen(p => !p)}
        className="w-full flex items-center justify-between p-5 bg-dark-800/40 hover:bg-dark-800/60 transition-all text-left">
        <div className="flex items-center gap-4">
          <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 text-xs font-black
            ${pct === 100 ? 'bg-emerald-500 text-white' : 'bg-white/5 text-gray-400'}`}>
            {pct === 100 ? <CheckCircle2 size={16} /> : index + 1}
          </div>
          <div>
            <p className="text-sm font-black text-white uppercase tracking-tight">
              {isAr && mod.titleAr ? mod.titleAr : mod.title}
            </p>
            <p className="text-[10px] text-gray-500 mt-0.5">
              {mod.lessons.length} {isAr ? 'درس' : 'lessons'} · {done}/{mod.lessons.length} {isAr ? 'مكتمل' : 'done'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* progress bar */}
          <div className="w-20 h-1.5 bg-white/5 rounded-full overflow-hidden hidden sm:block">
            <motion.div className="h-full bg-primary-500 rounded-full"
              animate={{ width: `${pct}%` }} transition={{ duration: 0.5 }} />
          </div>
          {open ? <ChevronDown size={16} className="text-gray-400" /> : <ChevronRight size={16} className="text-gray-600" />}
        </div>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }} className="overflow-hidden">
            <div className="divide-y divide-white/5">
              {mod.lessons.map((lesson, li) => {
                const isDone = completedLessons.includes(lesson.file);
                return (
                  <button key={li} onClick={() => onLessonClick(lesson)}
                    className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.03] transition-all text-left group">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 border transition-all
                      ${isDone ? 'bg-emerald-500 border-emerald-500' : 'border-white/10 group-hover:border-primary-500/50'}`}>
                      {isDone
                        ? <CheckCircle2 size={12} className="text-white" />
                        : <span className="text-[9px] text-gray-600 font-black">{li + 1}</span>}
                    </div>
                    <span className={`text-xs flex-1 transition-colors ${isDone ? 'text-gray-500 line-through' : 'text-gray-300 group-hover:text-white'}`}>
                      {lesson.title}
                    </span>
                    <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      <span className="text-[9px] font-black text-yellow-500">+{lesson.xp} XP</span>
                      <Play size={12} className="text-primary-500 fill-current" />
                    </div>
                  </button>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── YouTube Playlist Card ────────────────────────────────────────────────────
function PlaylistCard({ playlistId, relevance }) {
  const playlist = youtubeCoursesData.playlists.find(
    p => p.id === playlistId || p.playlistId?.toLowerCase() === playlistId?.toLowerCase()
  );
  if (!playlist) return null;

  return (
    <a href={`https://www.youtube.com/playlist?list=${playlist.playlistId}`}
      target="_blank" rel="noopener noreferrer"
      className="flex items-start gap-4 p-4 rounded-2xl bg-dark-800/40 border border-white/5
        hover:border-red-500/20 hover:bg-red-500/5 transition-all group">
      <img src={playlist.thumbnail} alt={playlist.title}
        className="w-20 h-14 rounded-xl object-cover flex-shrink-0 group-hover:scale-105 transition-transform" />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-black text-white line-clamp-2 group-hover:text-red-400 transition-colors">
          {playlist.title}
        </p>
        <p className="text-[10px] text-gray-500 mt-1">{playlist.channel} · {playlist.totalVideos} videos · {playlist.duration}</p>
        <p className="text-[10px] text-gray-600 italic mt-1 line-clamp-1">{relevance}</p>
      </div>
      <ExternalLink size={14} className="text-gray-600 group-hover:text-red-400 flex-shrink-0 mt-1 transition-colors" />
    </a>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
const TrackDetail = () => {
  const { trackId } = useParams();
  const navigate    = useNavigate();
  const { language, user, updateProgress, addXP } = useAppContext();
  const isAr = language === 'ar';

  const track = learningPaths.find(p => p.id === trackId);
  const [activeTab, setActiveTab]       = useState('curriculum');

  // Load user's custom playlist selections from wizard (fallback to track defaults)
  const userPlaylists = useMemo(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('track_playlists') || '{}');
      const ids = saved[trackId];
      if (ids && ids.length > 0) {
        return ids.map(id => {
          const pl = youtubeCoursesData.playlists.find(p => p.id === id);
          return pl ? { id, relevance: pl.channel } : null;
        }).filter(Boolean);
      }
    } catch {}
    return track?.youtubePlaylists || [];
  }, [trackId, track]);
  const [completedLessons, setCompleted] = useState(() => {
    try { return JSON.parse(localStorage.getItem(`track_${trackId}_done`) || '[]'); }
    catch { return []; }
  });
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [viewerOpen, setViewerOpen]         = useState(false);

  useEffect(() => {
    localStorage.setItem(`track_${trackId}_done`, JSON.stringify(completedLessons));
  }, [completedLessons, trackId]);

  if (!track) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-4">
          <p className="text-white font-black text-2xl uppercase italic">Track Not Found</p>
          <button onClick={() => navigate('/learning-tracks')}
            className="px-6 py-2 bg-primary-600 text-white rounded-xl text-xs font-black uppercase tracking-widest hover:bg-primary-500 transition-all">
            Back to Tracks
          </button>
        </div>
      </div>
    );
  }

  const totalLessons    = track.contentModules.reduce((s, m) => s + m.lessons.length, 0);
  const totalXP         = track.contentModules.reduce((s, m) => s + m.lessons.reduce((ss, l) => ss + l.xp, 0), 0);
  const doneCount       = completedLessons.length;
  const progressPct     = totalLessons ? Math.round((doneCount / totalLessons) * 100) : 0;
  const lvl             = LEVEL_STYLES[track.level] || LEVEL_STYLES.beginner;

  const handleLessonClick = (lesson) => {
    setSelectedLesson(lesson);
    setViewerOpen(true);
  };

  const handleLessonComplete = (lesson) => {
    if (!completedLessons.includes(lesson.file)) {
      setCompleted(p => [...p, lesson.file]);
      addXP(lesson.xp);
    }
  };

  const TABS = isAr
    ? ['المنهج', 'كورسات يوتيوب', 'الشهادات']
    : ['Curriculum', 'YouTube Courses', 'Certifications'];

  return (
    <div className="space-y-8 pb-16">
      {/* Lesson Viewer Overlay */}
      <AnimatePresence>
        {viewerOpen && selectedLesson && (
          <LessonViewer
            lesson={selectedLesson}
            onClose={() => setViewerOpen(false)}
            onComplete={() => handleLessonComplete(selectedLesson)}
            isCompleted={completedLessons.includes(selectedLesson.file)}
          />
        )}
      </AnimatePresence>
      {/* Back */}
      <button onClick={() => navigate('/learning-tracks')}
        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors group">
        <ChevronLeft size={18} className="group-hover:-translate-x-1 transition-transform" />
        <span className="text-xs font-black uppercase tracking-widest">
          {isAr ? 'العودة للمسارات' : 'Back to Tracks'}
        </span>
      </button>

      {/* Hero */}
      <div className="relative bg-dark-800/40 border border-white/5 rounded-3xl p-8 overflow-hidden">
        <div className="absolute inset-0 bg-cyber-grid opacity-10 pointer-events-none" />
        <div className="relative flex flex-col lg:flex-row gap-8">
          {/* Left */}
          <div className="flex-1 space-y-4">
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest border ${lvl.badge}`}>
                {track.level}
              </span>
              {track.isLocked && (
                <span className="flex items-center gap-1 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest bg-gray-500/10 border border-gray-500/20 text-gray-400">
                  <Lock size={10} /> {isAr ? 'قريباً' : 'Coming Soon'}
                </span>
              )}
            </div>
            <h1 className="text-4xl lg:text-5xl font-black text-white italic uppercase tracking-tighter">
              {isAr && track.titleAr ? track.titleAr : track.title}
            </h1>
            <p className="text-gray-400 leading-relaxed max-w-2xl">
              {isAr && track.descriptionAr ? track.descriptionAr : track.description}
            </p>
            {/* Skills */}
            <div className="flex flex-wrap gap-2">
              {track.skills.map(s => (
                <span key={s} className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-[10px] font-black text-gray-400 uppercase tracking-widest">
                  {s}
                </span>
              ))}
            </div>
          </div>

          {/* Stats */}
          <div className="lg:w-72 space-y-4">
            {/* Progress */}
            <div className="p-5 rounded-2xl bg-dark-900/60 border border-white/5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">
                  {isAr ? 'التقدم' : 'Progress'}
                </span>
                <span className="text-sm font-black text-white">{progressPct}%</span>
              </div>
              <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <motion.div className={`h-full rounded-full ${lvl.bar}`}
                  animate={{ width: `${progressPct}%` }} transition={{ duration: 0.6 }} />
              </div>
              <p className="text-[10px] text-gray-500">{doneCount}/{totalLessons} {isAr ? 'درس مكتمل' : 'lessons done'}</p>
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { icon: Clock,  val: track.duration,          label: isAr ? 'المدة' : 'Duration' },
                { icon: BookOpen, val: `${totalLessons}`,     label: isAr ? 'درس' : 'Lessons' },
                { icon: Zap,    val: `${totalXP} XP`,         label: isAr ? 'نقاط' : 'Total XP' },
                { icon: Users,  val: track.students.toLocaleString(), label: isAr ? 'طالب' : 'Students' },
              ].map(({ icon: Icon, val, label }) => (
                <div key={label} className="p-3 rounded-xl bg-dark-900/60 border border-white/5 text-center">
                  <Icon size={14} className="text-primary-500 mx-auto mb-1" />
                  <p className="text-sm font-black text-white">{val}</p>
                  <p className="text-[9px] text-gray-500 uppercase tracking-widest">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 p-1 bg-dark-900/60 border border-white/5 rounded-2xl w-fit">
        {TABS.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(['curriculum','youtube','certs'][i])}
            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
              activeTab === ['curriculum','youtube','certs'][i]
                ? 'bg-primary-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                : 'text-gray-500 hover:text-gray-300'
            }`}>
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div key={activeTab}
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }}>

          {/* CURRICULUM */}
          {activeTab === 'curriculum' && (
            <div className="space-y-3">
              {track.contentModules.length === 0 ? (
                <div className="p-12 rounded-2xl border border-white/5 bg-dark-800/20 text-center">
                  <Lock size={32} className="text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-500 font-black uppercase tracking-widest text-sm">
                    {isAr ? 'المحتوى قيد الإعداد' : 'Content Coming Soon'}
                  </p>
                </div>
              ) : (
                track.contentModules.map((mod, i) => (
                  <ModuleAccordion key={mod.id} mod={mod} index={i}
                    completedLessons={completedLessons}
                    onLessonClick={handleLessonClick}
                    isAr={isAr} />
                ))
              )}
            </div>
          )}

          {/* YOUTUBE */}
          {activeTab === 'youtube' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-xs text-gray-500 italic">
                  {isAr
                    ? 'كورسات يوتيوب المختارة لهذا المسار — تفتح في يوتيوب مباشرة'
                    : 'Your selected YouTube playlists for this track'}
                </p>
                <button onClick={() => navigate('/playlist-wizard')}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-black uppercase tracking-widest hover:bg-red-500/20 transition-all">
                  <Youtube size={11} />
                  {isAr ? 'تعديل' : 'Edit'}
                </button>
              </div>
              {userPlaylists.length === 0 ? (
                <div className="p-12 rounded-2xl border border-white/5 bg-dark-800/20 text-center space-y-3">
                  <Youtube size={32} className="text-gray-600 mx-auto" />
                  <p className="text-gray-500 text-sm">{isAr ? 'لم تختر كورسات بعد' : 'No playlists selected yet'}</p>
                  <button onClick={() => navigate('/playlist-wizard')}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-black uppercase tracking-widest hover:bg-red-500/20 transition-all">
                    <Youtube size={12} />
                    {isAr ? 'اختر الكورسات' : 'Select Playlists'}
                  </button>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {userPlaylists.map(({ id, relevance }) => (
                    <PlaylistCard key={id} playlistId={id} relevance={relevance} />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* CERTS */}
          {activeTab === 'certs' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {(track.certGoals || []).map(cert => (
                <div key={cert} className="p-6 rounded-2xl bg-dark-800/40 border border-white/5 hover:border-yellow-500/20 transition-all space-y-3">
                  <div className="w-12 h-12 rounded-xl bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center">
                    <Trophy size={22} className="text-yellow-500" />
                  </div>
                  <p className="text-base font-black text-white">{cert}</p>
                  <p className="text-xs text-gray-500 italic">
                    {isAr ? 'هذا المسار يُعدّك للحصول على هذه الشهادة' : 'This track prepares you for this certification'}
                  </p>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};

export default TrackDetail;
