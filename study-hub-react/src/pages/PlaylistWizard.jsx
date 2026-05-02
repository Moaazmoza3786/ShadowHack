import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import {
  ChevronRight, ChevronLeft, Check, Youtube,
  ExternalLink, Search, Trophy, CheckCircle2,
  Filter, X, Play
} from 'lucide-react';
import { learningPaths } from '../data/learning-paths-data';
import { youtubeCoursesData } from '../data/youtube-data';
import { useAppContext } from '../context/AppContext';

// ─── helpers ─────────────────────────────────────────────────────────────────
const LEVEL_COLORS = {
  beginner:     'from-emerald-500 to-green-600',
  intermediate: 'from-yellow-500 to-orange-500',
  advanced:     'from-red-500 to-pink-600',
  expert:       'from-purple-500 to-violet-600',
};
const LEVEL_BADGE = {
  beginner:     'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  intermediate: 'bg-yellow-500/10  border-yellow-500/20  text-yellow-400',
  advanced:     'bg-red-500/10     border-red-500/20     text-red-400',
  expert:       'bg-purple-500/10  border-purple-500/20  text-purple-400',
};

// ─── Single Playlist Card ─────────────────────────────────────────────────────
function PlaylistCard({ pl, selected, onToggle }) {
  return (
    <motion.button
      onClick={onToggle}
      whileTap={{ scale: 0.98 }}
      className={`w-full flex items-start gap-3 p-3 rounded-xl border text-left transition-all ${
        selected
          ? 'bg-primary-500/10 border-primary-500/40 shadow-[0_0_12px_rgba(239,68,68,0.1)]'
          : 'bg-dark-800/40 border-white/5 hover:border-white/15'
      }`}
    >
      {/* Checkbox */}
      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-0.5 transition-all ${
        selected ? 'bg-primary-500 border-primary-500' : 'border-white/20'
      }`}>
        {selected && <Check size={10} className="text-white" strokeWidth={3} />}
      </div>

      {/* Thumbnail */}
      <img src={pl.thumbnail} alt={pl.title}
        className="w-16 h-11 rounded-lg object-cover flex-shrink-0" />

      {/* Info */}
      <div className="flex-1 min-w-0">
        <p className={`text-[11px] font-bold line-clamp-2 leading-tight transition-colors ${selected ? 'text-white' : 'text-gray-300'}`}>
          {pl.title}
        </p>
        <p className="text-[9px] text-gray-500 mt-0.5">
          {pl.channel} · {pl.totalVideos} videos · {pl.duration}
        </p>
      </div>
    </motion.button>
  );
}

// ─── Track Step ───────────────────────────────────────────────────────────────
function TrackStep({ track, selections, onToggle, isAr }) {
  const Icon = track.icon;
  const allPlaylists = youtubeCoursesData.playlists;
  const categories   = youtubeCoursesData.categories;

  const [search, setSearch]     = useState('');
  const [activecat, setActivecat] = useState('all');

  const filtered = useMemo(() => {
    return allPlaylists.filter(pl => {
      const matchCat = activecat === 'all' || pl.category === activecat;
      const q = search.toLowerCase();
      const matchSearch = !q ||
        pl.title.toLowerCase().includes(q) ||
        (pl.titleAr || '').toLowerCase().includes(q) ||
        pl.channel.toLowerCase().includes(q);
      return matchCat && matchSearch;
    });
  }, [search, activecat, allPlaylists]);

  const selected = selections[track.id] || [];

  return (
    <div className="space-y-4">
      {/* Track Header */}
      <div className={`flex items-start gap-4 p-5 rounded-2xl bg-gradient-to-br ${LEVEL_COLORS[track.level]}/10 border border-white/10`}>
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${LEVEL_COLORS[track.level]} flex items-center justify-center flex-shrink-0`}>
          <Icon size={22} className="text-white" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest border ${LEVEL_BADGE[track.level]}`}>
              {track.level}
            </span>
            <span className="text-[10px] text-gray-500">{track.duration}</span>
          </div>
          <h2 className="text-xl font-black text-white italic uppercase tracking-tighter">
            {isAr && track.titleAr ? track.titleAr : track.title}
          </h2>
          <p className="text-xs text-gray-400 mt-1 leading-relaxed line-clamp-2">
            {isAr && track.descriptionAr ? track.descriptionAr : track.description}
          </p>
        </div>
        {selected.length > 0 && (
          <div className="flex-shrink-0 px-2.5 py-1 rounded-full bg-primary-500/20 border border-primary-500/30 text-[10px] font-black text-primary-400">
            {selected.length} ✓
          </div>
        )}
      </div>

      {/* Search + Filter */}
      <div className="space-y-2">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={isAr ? 'ابحث في الكورسات...' : 'Search playlists...'}
            className="w-full bg-dark-800/60 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-xs text-white outline-none focus:border-primary-500/50 placeholder:text-gray-600"
          />
          {search && (
            <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
              <X size={12} />
            </button>
          )}
        </div>

        {/* Category tabs */}
        <div className="flex gap-1.5 overflow-x-auto pb-1 scrollbar-none">
          <button
            onClick={() => setActivecat('all')}
            className={`px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest flex-shrink-0 transition-all ${
              activecat === 'all' ? 'bg-white/10 text-white border border-white/20' : 'text-gray-500 hover:text-gray-300'
            }`}>
            {isAr ? 'الكل' : 'All'} ({allPlaylists.length})
          </button>
          {categories.map(cat => {
            const count = allPlaylists.filter(p => p.category === cat.id).length;
            return (
              <button key={cat.id}
                onClick={() => setActivecat(cat.id)}
                className={`px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest flex-shrink-0 transition-all ${
                  activecat === cat.id ? 'bg-white/10 text-white border border-white/20' : 'text-gray-500 hover:text-gray-300'
                }`}>
                {isAr ? cat.nameAr : cat.name} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Results count */}
      <p className="text-[10px] text-gray-600">
        {filtered.length} {isAr ? 'كورس' : 'playlists'}
        {selected.length > 0 && <span className="text-primary-400 ml-2">· {selected.length} {isAr ? 'مختار' : 'selected'}</span>}
      </p>

      {/* Playlist Grid */}
      <div className="space-y-2 max-h-[50vh] overflow-y-auto scrollbar-cyber pr-1">
        {filtered.length === 0 ? (
          <div className="py-8 text-center text-gray-600 text-xs italic">
            {isAr ? 'لا توجد نتائج' : 'No results found'}
          </div>
        ) : (
          filtered.map(pl => (
            <PlaylistCard
              key={pl.id}
              pl={pl}
              selected={selected.includes(pl.id)}
              onToggle={() => onToggle(track.id, pl.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

// ─── Summary Step ─────────────────────────────────────────────────────────────
function SummaryStep({ tracks, selections, isAr }) {
  const totalSelected = Object.values(selections).flat().length;

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <div className="w-16 h-16 rounded-full bg-emerald-500 flex items-center justify-center mx-auto shadow-[0_0_30px_rgba(16,185,129,0.4)]">
          <Trophy size={30} className="text-white" />
        </div>
        <h2 className="text-3xl font-black text-white italic uppercase tracking-tighter">
          {isAr ? 'خطتك جاهزة!' : 'Your Plan is Ready!'}
        </h2>
        <p className="text-gray-400 text-sm">
          {isAr
            ? `اخترت ${totalSelected} كورس عبر ${tracks.length} مسار`
            : `${totalSelected} courses selected across ${tracks.length} tracks`}
        </p>
      </div>

      <div className="space-y-4">
        {tracks.map(track => {
          const selected = selections[track.id] || [];
          const Icon = track.icon;
          return (
            <div key={track.id} className="p-4 rounded-2xl bg-dark-800/40 border border-white/5 space-y-3">
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-xl bg-gradient-to-br ${LEVEL_COLORS[track.level]} flex items-center justify-center flex-shrink-0`}>
                  <Icon size={14} className="text-white" />
                </div>
                <div className="flex-1">
                  <p className="text-xs font-black text-white uppercase tracking-tight">
                    {isAr && track.titleAr ? track.titleAr : track.title}
                  </p>
                  <p className="text-[9px] text-gray-500">
                    {selected.length} {isAr ? 'كورس مختار' : 'courses selected'}
                  </p>
                </div>
              </div>
              {selected.length > 0 && (
                <div className="space-y-1.5 pl-11">
                  {selected.map(id => {
                    const pl = youtubeCoursesData.playlists.find(p => p.id === id);
                    if (!pl) return null;
                    return (
                      <a key={id}
                        href={`https://www.youtube.com/playlist?list=${pl.playlistId}`}
                        target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-2 text-[10px] text-gray-400 hover:text-red-400 transition-colors group">
                        <Youtube size={10} className="text-red-500 flex-shrink-0" />
                        <span className="line-clamp-1 group-hover:underline">{pl.title}</span>
                        <ExternalLink size={9} className="opacity-0 group-hover:opacity-100 flex-shrink-0 ml-auto" />
                      </a>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main Wizard ──────────────────────────────────────────────────────────────
const PlaylistWizard = () => {
  const navigate = useNavigate();
  const { language } = useAppContext();
  const isAr = language === 'ar';

  const tracks = learningPaths.filter(p => !p.isLocked);
  const totalSteps = tracks.length + 1;

  const [step, setStep]             = useState(0);
  const [direction, setDirection]   = useState(1);
  const [selections, setSelections] = useState(() => {
    try { return JSON.parse(localStorage.getItem('wizard_selections') || '{}'); }
    catch { return {}; }
  });

  // Persist selections
  useEffect(() => {
    localStorage.setItem('wizard_selections', JSON.stringify(selections));
    // Also update the track's youtubePlaylists in learning-paths-data at runtime
    // (stored separately so TrackDetail can read them)
    localStorage.setItem('track_playlists', JSON.stringify(selections));
  }, [selections]);

  const togglePlaylist = (trackId, playlistId) => {
    setSelections(prev => {
      const current = prev[trackId] || [];
      const updated = current.includes(playlistId)
        ? current.filter(id => id !== playlistId)
        : [...current, playlistId];
      return { ...prev, [trackId]: updated };
    });
  };

  const goNext = () => { setDirection(1);  setStep(s => Math.min(s + 1, totalSteps - 1)); };
  const goPrev = () => { setDirection(-1); setStep(s => Math.max(s - 1, 0)); };

  const isSummary    = step === tracks.length;
  const currentTrack = !isSummary ? tracks[step] : null;
  const progress     = (step / (totalSteps - 1)) * 100;

  return (
    <div className="min-h-screen bg-dark-950 flex flex-col overflow-hidden">
      {/* Top Bar */}
      <div className="h-14 border-b border-white/10 px-6 flex items-center justify-between flex-shrink-0">
        <button onClick={() => navigate('/learning-tracks')}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors group">
          <ChevronLeft size={18} className="group-hover:-translate-x-1 transition-transform" />
          <span className="text-xs font-black uppercase tracking-widest">
            {isAr ? 'العودة' : 'Back'}
          </span>
        </button>
        <div className="text-center">
          <p className="text-[10px] font-black text-gray-500 uppercase tracking-widest">
            {isSummary
              ? (isAr ? 'الملخص النهائي' : 'Final Summary')
              : `${isAr ? 'المسار' : 'Track'} ${step + 1} / ${tracks.length}`}
          </p>
        </div>
        <div className="w-16" />
      </div>

      {/* Progress Bar */}
      <div className="h-0.5 bg-white/5 flex-shrink-0">
        <motion.div className="h-full bg-gradient-to-r from-primary-500 to-cyan-500"
          animate={{ width: `${progress}%` }} transition={{ duration: 0.4 }} />
      </div>

      {/* Step Dots */}
      <div className="flex items-center gap-1.5 px-6 py-3 overflow-x-auto scrollbar-none flex-shrink-0 border-b border-white/5">
        {tracks.map((t, i) => {
          const done   = i < step;
          const active = i === step && !isSummary;
          const Icon   = t.icon;
          const count  = (selections[t.id] || []).length;
          return (
            <button key={t.id}
              onClick={() => { setDirection(i > step ? 1 : -1); setStep(i); }}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border transition-all text-[9px] font-black uppercase tracking-widest flex-shrink-0 ${
                active ? 'bg-primary-500/20 border-primary-500/50 text-white' :
                done   ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                         'bg-white/3 border-white/5 text-gray-600 hover:border-white/15 hover:text-gray-400'
              }`}>
              {done ? <CheckCircle2 size={9} /> : <Icon size={9} />}
              <span className="hidden md:inline">{t.title}</span>
              {count > 0 && <span className="bg-primary-500/30 text-primary-300 px-1 rounded-full">{count}</span>}
            </button>
          );
        })}
        <button onClick={() => { setDirection(1); setStep(tracks.length); }}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border transition-all text-[9px] font-black uppercase tracking-widest flex-shrink-0 ${
            isSummary ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' : 'bg-white/3 border-white/5 text-gray-600'
          }`}>
          <Trophy size={9} />
          <span className="hidden md:inline">{isAr ? 'الملخص' : 'Summary'}</span>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-2xl mx-auto px-4 py-5">
          <AnimatePresence mode="wait" custom={direction}>
            <motion.div key={step}
              custom={direction}
              initial={{ opacity: 0, x: direction * 30 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: direction * -30 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}>
              {isSummary ? (
                <SummaryStep tracks={tracks} selections={selections} isAr={isAr} />
              ) : (
                <TrackStep
                  track={currentTrack}
                  selections={selections}
                  onToggle={togglePlaylist}
                  isAr={isAr}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>

      {/* Bottom Nav */}
      <div className="border-t border-white/10 px-6 py-4 flex items-center justify-between flex-shrink-0 bg-dark-950">
        <button onClick={goPrev} disabled={step === 0}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-gray-400 text-xs font-black uppercase tracking-widest hover:bg-white/10 hover:text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed">
          <ChevronLeft size={14} />
          {isAr ? 'السابق' : 'Prev'}
        </button>

        {!isSummary && (
          <span className="text-[10px] text-gray-600 italic">
            {(selections[currentTrack?.id] || []).length > 0
              ? `${(selections[currentTrack?.id] || []).length} ${isAr ? 'مختار' : 'selected'}`
              : (isAr ? 'يمكنك التخطي' : 'Skip if you want')}
          </span>
        )}

        {isSummary ? (
          <button onClick={() => navigate('/learning-tracks')}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-emerald-500 text-white text-xs font-black uppercase tracking-widest hover:bg-emerald-400 transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)]">
            <CheckCircle2 size={14} />
            {isAr ? 'ابدأ التعلم' : 'Start Learning'}
          </button>
        ) : (
          <button onClick={goNext}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-primary-600 text-white text-xs font-black uppercase tracking-widest hover:bg-primary-500 transition-all shadow-[0_0_20px_rgba(239,68,68,0.2)]">
            {step === tracks.length - 1
              ? (isAr ? 'عرض الملخص' : 'View Summary')
              : (isAr ? 'التالي' : 'Next')}
            <ChevronRight size={14} />
          </button>
        )}
      </div>
    </div>
  );
};

export default PlaylistWizard;
