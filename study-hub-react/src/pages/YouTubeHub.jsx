import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Youtube, Search, PlayCircle, Clock,
    ChevronRight, ArrowLeft, Globe, Shield,
    Terminal, Code, Flag, Eye, Heart, ShieldAlert,
    Cloud, Network, Mic, Layers, ExternalLink,
    Video, Users, BookOpen, Star
} from 'lucide-react';
import { youtubeCoursesData } from '../data/youtube-data';
import { fetchPlaylistMetadata, fetchPlaylistVideos, formatDuration } from '../services/youtube-service';

const CategoryIcon = ({ icon, className }) => {
    switch (icon) {
        case 'Globe': return <Globe className={className} />;
        case 'Shield': return <Shield className={className} />;
        case 'Terminal': return <Terminal className={className} />;
        case 'Code': return <Code className={className} />;
        case 'Flag': return <Flag className={className} />;
        case 'Eye': return <Eye className={className} />;
        case 'Heart': return <Heart className={className} />;
        case 'ShieldAlert': return <ShieldAlert className={className} />;
        case 'Cloud': return <Cloud className={className} />;
        case 'Network': return <Network className={className} />;
        case 'Mic': return <Mic className={className} />;
        case 'Layers': return <Layers className={className} />;
        default: return <Globe className={className} />;
    }
};

const YouTubeHub = () => {
    const { categories: youtubeCategories, playlists: youtubePlaylists } = youtubeCoursesData || { categories: [], playlists: [] };
    const [selectedCategory, setSelectedCategory] = useState('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedPlaylist, setSelectedPlaylist] = useState(null);
    const [playlistMetadata, setPlaylistMetadata] = useState(null);
    const [playlistVideos, setPlaylistVideos] = useState([]);
    const [activeVideo, setActiveVideo] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [favorites, setFavorites] = useState(() => {
        const saved = localStorage.getItem('yt_favorites');
        return saved ? JSON.parse(saved) : [];
    });

    const toggleFavorite = (e, id) => {
        e.stopPropagation();
        const newFavorites = favorites.includes(id)
            ? favorites.filter(fav => fav !== id)
            : [...favorites, id];
        setFavorites(newFavorites);
        localStorage.setItem('yt_favorites', JSON.stringify(newFavorites));
    };

    useEffect(() => {
        if (selectedPlaylist) {
            loadPlaylistData(selectedPlaylist.playlistId || selectedPlaylist.id);
        }
    }, [selectedPlaylist]);

    const loadPlaylistData = async (id) => {
        setIsLoading(true);
        // Use provided videos if available, otherwise fetch
        if (selectedPlaylist.videos && selectedPlaylist.videos.length > 1) {
            setPlaylistVideos(selectedPlaylist.videos);
            setActiveVideo(selectedPlaylist.videos[0]);
        } else {
            const videos = await fetchPlaylistVideos(id);
            setPlaylistVideos(videos);
            if (videos.length > 0) setActiveVideo(videos[0]);
        }

        const meta = await fetchPlaylistMetadata(id);
        if (meta) setPlaylistMetadata(meta);
        setIsLoading(false);
    };

    const filteredPlaylists = youtubePlaylists.filter(playlist => {
        const matchesCategory = selectedCategory === 'all' ||
            (selectedCategory === 'favorites' ? favorites.includes(playlist.id) : playlist.category === selectedCategory);

        const query = searchQuery.toLowerCase();
        const matchesSearch =
            playlist.title.toLowerCase().includes(query) ||
            playlist.titleAr?.toLowerCase().includes(query) ||
            playlist.description?.toLowerCase().includes(query) ||
            playlist.channel?.toLowerCase().includes(query);

        return matchesCategory && matchesSearch;
    });

    // Playlist Content View (Split Layout)
    if (selectedPlaylist) {
        return (
            <div className="min-h-screen bg-dark-950 space-y-8 animate-in fade-in duration-500 pb-20">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <button
                        onClick={() => setSelectedPlaylist(null)}
                        className="flex items-center gap-2 text-gray-400 hover:text-white transition-all group px-4 py-2 rounded-xl bg-white/5 border border-white/5 hover:border-white/10"
                    >
                        <ArrowLeft size={18} className="group-hover:-translate-x-1 transition-transform" />
                        <span className="font-bold uppercase tracking-widest text-[10px]">Back to Hub</span>
                    </button>

                    <div className="flex items-center gap-3">
                        <a
                            href={`https://www.youtube.com/playlist?list=${selectedPlaylist.playlistId}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/5 hover:border-primary-500/30 text-gray-400 hover:text-white transition-all"
                        >
                            <ExternalLink size={16} />
                            <span className="font-bold uppercase tracking-widest text-[10px]">Open on YouTube</span>
                        </a>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    {/* Left: Video Player */}
                    <div className="lg:col-span-8 space-y-6">
                        <div className="relative aspect-video rounded-[2rem] overflow-hidden border border-white/5 shadow-2xl bg-black group">
                            {activeVideo ? (
                                <iframe
                                    src={`https://www.youtube.com/embed/${activeVideo.videoId}?autoplay=1`}
                                    className="absolute inset-0 w-full h-full"
                                    allow="autoplay; encrypted-media"
                                    allowFullScreen
                                    title="YouTube Video Player"
                                />
                            ) : (
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <div className="animate-pulse flex flex-col items-center gap-4">
                                        <Youtube size={48} className="text-gray-800" />
                                        <p className="text-gray-600 font-bold uppercase tracking-widest text-xs">Loading Channel...</p>
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="p-8 rounded-[2rem] bg-dark-800/40 border border-white/5 backdrop-blur-xl">
                            <div className="flex items-center gap-4 mb-6">
                                <div className="w-12 h-12 rounded-2xl bg-primary-500/20 flex items-center justify-center">
                                    <Youtube size={24} className="text-primary-500" />
                                </div>
                                <div>
                                    <h1 className="text-2xl font-black text-white uppercase tracking-tighter">
                                        {activeVideo?.title || selectedPlaylist.title}
                                    </h1>
                                    <p className="text-primary-500 font-bold uppercase tracking-widest text-[10px]">
                                        {playlistMetadata?.channelTitle || selectedPlaylist.channel}
                                    </p>
                                </div>
                            </div>
                            <p className="text-gray-400 leading-relaxed font-medium">
                                {selectedPlaylist.description}
                            </p>
                        </div>
                    </div>

                    {/* Right: Playlist Sidebar */}
                    <div className="lg:col-span-4 space-y-4">
                        <div className="p-6 rounded-[2rem] bg-dark-800/40 border border-white/5 backdrop-blur-xl h-[calc(100vh-280px)] overflow-hidden flex flex-col">
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
                                    <PlayCircle size={18} className="text-primary-500" />
                                    Playlist
                                </h2>
                                <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest bg-white/5 px-2 py-1 rounded-lg">
                                    {playlistVideos.length} Videos
                                </span>
                            </div>

                            <div className="flex-1 overflow-y-auto scrollbar-cyber space-y-3 pr-2">
                                {isLoading ? (
                                    Array(6).fill(0).map((_, i) => (
                                        <div key={i} className="h-16 rounded-2xl bg-white/5 animate-pulse" />
                                    ))
                                ) : (
                                    playlistVideos.map((video, index) => (
                                        <button
                                            key={index}
                                            onClick={() => setActiveVideo(video)}
                                            className={`w-full group p-4 rounded-2xl border transition-all duration-300 flex gap-4 items-center text-left ${activeVideo?.videoId === video.videoId
                                                ? 'bg-primary-500/10 border-primary-500/30'
                                                : 'bg-white/5 border-white/5 hover:border-white/10 hover:bg-white/10'
                                                }`}
                                        >
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-black text-[10px] ${activeVideo?.videoId === video.videoId ? 'bg-primary-500 text-white' : 'bg-dark-900 text-gray-500'
                                                }`}>
                                                {video.position}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <h4 className={`text-xs font-bold truncate ${activeVideo?.videoId === video.videoId ? 'text-white' : 'text-gray-400 group-hover:text-gray-200'
                                                    }`}>
                                                    {video.title}
                                                </h4>
                                            </div>
                                        </button>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-12 animate-in fade-in slide-in-from-bottom-4 duration-700 pb-20">
            {/* Header Section */}
            <div className="relative pt-8">
                <div className="absolute -top-24 -left-24 w-[30rem] h-[30rem] bg-primary-500/5 rounded-full blur-[120px] pointer-events-none" />

                <div className="flex flex-col items-center text-center space-y-6">
                    <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-[0.3em] shadow-[0_0_20px_rgba(239,68,68,0.1)]">
                        FREE EDUCATION PLATFORM
                    </div>

                    <h1 className="text-8xl font-black text-white italic tracking-tighter uppercase leading-none">
                        YouTube <span className="text-transparent bg-clip-text bg-gradient-to-br from-primary-500 to-accent-600">Hub</span>
                    </h1>

                    {/* Stats Bar */}
                    <div className="flex flex-wrap justify-center gap-8 py-4">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-primary-500">
                                <Video size={18} />
                            </div>
                            <div className="text-left">
                                <div className="text-xl font-black text-white leading-none tracking-tight">{youtubePlaylists.length}</div>
                                <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mt-1">Playlists</div>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-accent-500">
                                <Users size={18} />
                            </div>
                            <div className="text-left">
                                <div className="text-xl font-black text-white leading-none tracking-tight">2157+</div>
                                <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mt-1">Videos</div>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-emerald-500">
                                <Layers size={18} />
                            </div>
                            <div className="text-left">
                                <div className="text-xl font-black text-white leading-none tracking-tight">{youtubeCategories.length}</div>
                                <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mt-1">Hubs</div>
                            </div>
                        </div>
                    </div>

                    {/* Centered Search Bar */}
                    <div className="relative w-full max-w-2xl group mt-4">
                        <Search className="absolute left-6 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-primary-500 transition-colors" size={20} />
                        <input
                            type="text"
                            placeholder="Search among 109+ premium security playlists..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-dark-800/60 border border-white/10 rounded-[2rem] py-6 pl-16 pr-8 text-white focus:outline-none focus:border-primary-500/50 transition-all font-medium text-sm tracking-wide placeholder:text-gray-600 backdrop-blur-xl shadow-2xl"
                        />
                    </div>

                    {/* Pill Filters */}
                    <div className="flex flex-wrap justify-center gap-2 pt-4">
                        <button
                            onClick={() => setSelectedCategory('all')}
                            className={`px-6 py-2.5 rounded-full font-black uppercase tracking-widest text-[9px] transition-all duration-300 border ${selectedCategory === 'all'
                                ? 'bg-white text-black border-white shadow-[0_0_20px_rgba(255,255,255,0.2)] scale-105'
                                : 'bg-white/5 text-gray-400 border-white/5 hover:border-white/20 hover:text-white'
                                }`}
                        >
                            All Categories
                        </button>
                        {youtubeCategories.map(cat => (
                            <button
                                key={cat.id}
                                onClick={() => setSelectedCategory(cat.id)}
                                className={`px-5 py-2.5 rounded-full font-black uppercase tracking-widest text-[9px] transition-all duration-300 border flex items-center gap-2 ${selectedCategory === cat.id
                                    ? 'bg-primary-500 text-white border-primary-500 shadow-[0_0_20px_rgba(239,68,68,0.3)] scale-105'
                                    : 'bg-white/5 text-gray-400 border-white/5 hover:border-white/20 hover:text-white'
                                    }`}
                            >
                                <CategoryIcon icon={cat.icon} className="w-3.5 h-3.5" />
                                {cat.name}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Playlists Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-8">
                <AnimatePresence mode="popLayout">
                    {filteredPlaylists.map((playlist, idx) => (
                        <motion.div
                            key={playlist.id}
                            layout
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.9 }}
                            transition={{ duration: 0.4, delay: idx * 0.05 }}
                            onClick={() => setSelectedPlaylist(playlist)}
                            className="group relative"
                        >
                            <div className="relative rounded-[2.5rem] bg-dark-800/40 border border-white/5 overflow-hidden transition-all duration-500 hover:border-primary-500/30 hover:shadow-[0_20px_50px_rgba(0,0,0,0.5)] group-hover:-translate-y-2">
                                {/* Thumbnail Wrapper */}
                                <div className="relative aspect-video overflow-hidden">
                                    <img
                                        src={playlist.thumbnail?.startsWith('http')
                                            ? playlist.thumbnail
                                            : `https://img.youtube.com/vi/${playlist.thumbnail}/maxresdefault.jpg`}
                                        alt={playlist.title}
                                        className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110 opacity-70 group-hover:opacity-100"
                                    />
                                    <div className="absolute inset-0 bg-gradient-to-t from-dark-900 via-transparent to-transparent opacity-60" />

                                    {/* Category Tag */}
                                    <div className="absolute top-5 left-5 px-3 py-1 rounded-full bg-black/40 backdrop-blur-md border border-white/10 text-[8px] font-black text-white uppercase tracking-[0.2em]">
                                        {playlist.category.replace('-', ' ')}
                                    </div>

                                    {/* Favorite Button */}
                                    <button
                                        onClick={(e) => toggleFavorite(e, playlist.id)}
                                        className={`absolute top-5 right-5 w-8 h-8 rounded-full flex items-center justify-center transition-all ${favorites.includes(playlist.id)
                                            ? 'bg-primary-500 text-white'
                                            : 'bg-black/40 backdrop-blur-md border border-white/10 text-white/40 hover:text-white'
                                            }`}
                                    >
                                        <Heart size={14} fill={favorites.includes(playlist.id) ? "currentColor" : "none"} />
                                    </button>

                                    {/* Play Counter overlay */}
                                    <div className="absolute bottom-5 right-5 px-2.5 py-1 rounded-lg bg-black/60 backdrop-blur-md border border-white/5 flex items-center gap-1.5 shadow-xl">
                                        <PlayCircle size={12} className="text-primary-500" />
                                        <span className="text-[10px] font-black text-white uppercase tracking-widest">{playlist.totalVideos} Videos</span>
                                    </div>
                                </div>

                                {/* Content */}
                                <div className="p-8 space-y-4">
                                    <div className="flex items-center gap-2">
                                        <div className="w-5 h-5 rounded-full bg-red-600/20 flex items-center justify-center">
                                            <Youtube size={10} className="text-red-500" />
                                        </div>
                                        <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest truncate">{playlist.channel || 'System Tech'}</span>
                                    </div>

                                    <h3 className="text-lg font-black text-white leading-tight uppercase tracking-tighter italic group-hover:text-primary-500 transition-colors line-clamp-2">
                                        {playlist.title}
                                    </h3>

                                    <div className="flex items-center justify-between pt-2">
                                        <div className="flex items-center gap-1.5 text-gray-500 font-bold uppercase tracking-widest text-[9px]">
                                            <Clock size={12} />
                                            {playlist.duration === 'Calculated'
                                                ? `${Math.floor(playlist.totalVideos * 15 / 60)}h ${(playlist.totalVideos * 15) % 60}m`
                                                : (playlist.duration || '3h+')}
                                        </div>
                                        <div className="flex items-center gap-1 text-primary-500 font-black uppercase text-[9px] tracking-widest opacity-0 group-hover:opacity-100 transition-all translate-x-4 group-hover:translate-x-0">
                                            Watch Now <ChevronRight size={14} />
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            {/* Empty State */}
            {filteredPlaylists.length === 0 && (
                <div className="flex flex-col items-center justify-center py-32 text-center">
                    <div className="w-20 h-20 rounded-full bg-white/5 flex items-center justify-center text-gray-600 mb-6">
                        <Search size={40} />
                    </div>
                    <h3 className="text-2xl font-black text-white italic uppercase tracking-widest">No playlists found</h3>
                    <p className="text-gray-500 mt-2 font-medium">Try adjusting your search or filters to find what you're looking for.</p>
                </div>
            )}
        </div>
    );
};

export default YouTubeHub;
