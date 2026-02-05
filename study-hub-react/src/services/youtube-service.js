const API_KEY = import.meta.env.VITE_YOUTUBE_API_KEY;
const BASE_URL = 'https://www.googleapis.com/youtube/v3';

const CACHE_KEY_PREFIX = 'yt_cache_';
const CACHE_DURATION = 1000 * 60 * 60 * 24; // 24 hours

const getCache = (key) => {
    const cached = localStorage.getItem(CACHE_KEY_PREFIX + key);
    if (!cached) return null;
    const { data, timestamp } = JSON.parse(cached);
    if (Date.now() - timestamp > CACHE_DURATION) {
        localStorage.removeItem(CACHE_KEY_PREFIX + key);
        return null;
    }
    return data;
};

const setCache = (key, data) => {
    localStorage.setItem(CACHE_KEY_PREFIX + key, JSON.stringify({
        data,
        timestamp: Date.now()
    }));
};

export const fetchPlaylistMetadata = async (playlistId) => {
    const cached = getCache(`meta_${playlistId}`);
    if (cached) return cached;

    try {
        const response = await fetch(
            `${BASE_URL}/playlists?part=snippet,contentDetails&id=${playlistId}&key=${API_KEY}`
        );
        const data = await response.json();
        if (data.items && data.items.length > 0) {
            const metadata = {
                title: data.items[0].snippet.title,
                description: data.items[0].snippet.description,
                thumbnail: data.items[0].snippet.thumbnails.maxresdefault?.url || data.items[0].snippet.thumbnails.high?.url,
                totalVideos: data.items[0].contentDetails.itemCount,
                channelTitle: data.items[0].snippet.channelTitle,
            };
            setCache(`meta_${playlistId}`, metadata);
            return metadata;
        }
        return null;
    } catch (error) {
        console.error('Error fetching playlist metadata:', error);
        return null;
    }
};

export const fetchPlaylistVideos = async (playlistId) => {
    const cached = getCache(`videos_${playlistId}`);
    if (cached) return cached;

    try {
        const response = await fetch(
            `${BASE_URL}/playlistItems?part=snippet,contentDetails&maxResults=50&playlistId=${playlistId}&key=${API_KEY}`
        );
        const data = await response.json();
        if (data.items) {
            const videos = data.items.map(item => ({
                position: item.snippet.position + 1,
                title: item.snippet.title,
                videoId: item.contentDetails.videoId,
                thumbnail: item.snippet.thumbnails.medium?.url,
            }));
            setCache(`videos_${playlistId}`, videos);
            return videos;
        }
        return [];
    } catch (error) {
        console.error('Error fetching playlist videos:', error);
        return [];
    }
};

export const formatDuration = (seconds) => {
    if (!seconds) return '0m';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
};
