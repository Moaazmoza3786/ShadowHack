/* ============================================================
   YOUTUBE COURSES MODULE
   Free community education integration.
   ============================================================ */

window.YouTubeCoursesData = [
    // --- RED TEAM ---
    {
        id: 'PLXBdizAnWgrgPHJju1I37t1W8a4J63I2g', // Example ID (Placeholder) -> Zero to Hero
        title: 'Zero to Hero Pentesting',
        channel: 'The Cyber Mentor',
        category: 'Red Team',
        hours: '12h',
        image: 'https://i.ytimg.com/vi/WnNCNP_t5tE/maxresdefault.jpg'
    },
    {
        id: 'PL69866E3d231A9F76', // Placeholder
        title: 'Metasploit Tutorials',
        channel: 'HackerSploit',
        category: 'Red Team',
        hours: '8h',
        image: 'https://i.ytimg.com/vi/8lR27db8aQI/maxresdefault.jpg'
    },
    {
        id: 'PLBf0hzazHTGMdM4-8WJ8C8J9Qo_4-5-6', // Placeholder
        title: 'Red Team Operations',
        channel: 'IppSec',
        category: 'Red Team',
        hours: '15h',
        image: 'https://i.ytimg.com/vi/1-2-3-4/maxresdefault.jpg'
    },

    // --- BLUE TEAM ---
    {
        id: 'PL23F7E7C4-SOC', // Placeholder
        title: 'SOC Analyst Guide',
        channel: 'BlackPerl',
        category: 'Blue Team',
        hours: '6h',
        image: 'https://i.ytimg.com/vi/soc-intro/maxresdefault.jpg'
    },
    {
        id: 'PLForensics101', // Placeholder
        title: 'Digital Forensics 101',
        channel: '13Cubed',
        category: 'Blue Team',
        hours: '10h',
        image: 'https://i.ytimg.com/vi/forensics/maxresdefault.jpg'
    },

    // --- NETWORKING & TOOLS ---
    {
        id: 'PLNetworkingChuck', // Placeholder
        title: 'CCNA Course',
        channel: 'NetworkChuck',
        category: 'Networking',
        hours: '14h',
        image: 'https://i.ytimg.com/vi/ccna-1/maxresdefault.jpg'
    },
    {
        id: 'PLPythonForHackers', // Placeholder
        title: 'Python for Hackers',
        channel: 'NetworkChuck',
        category: 'Programming',
        hours: '5h',
        image: 'https://i.ytimg.com/vi/python-1/maxresdefault.jpg'
    },
    {
        id: 'PLBurpSuite', // Placeholder
        title: 'Burp Suite Masterclass',
        channel: 'Rana Khalil',
        category: 'Tools',
        hours: '9h',
        image: 'https://i.ytimg.com/vi/burp-1/maxresdefault.jpg'
    }
];

// Global state for filtering
let currentYtCategory = 'All';

// ============== LocalStorage Utilities ==============
const YT_FAVORITES_KEY = 'yt_hub_favorites';
const YT_PROGRESS_KEY = 'yt_hub_progress';

window.getYtFavorites = function () {
    try {
        return JSON.parse(localStorage.getItem(YT_FAVORITES_KEY) || '[]');
    } catch { return []; }
};

window.toggleYtFavorite = function (playlistId, event) {
    if (event) event.stopPropagation();
    let favs = window.getYtFavorites();
    if (favs.includes(playlistId)) {
        favs = favs.filter(id => id !== playlistId);
    } else {
        favs.push(playlistId);
    }
    localStorage.setItem(YT_FAVORITES_KEY, JSON.stringify(favs));

    // Update UI
    const btn = document.querySelector(`[data-fav-id="${playlistId}"]`);
    if (btn) {
        const icon = btn.querySelector('i');
        if (favs.includes(playlistId)) {
            icon.className = 'fas fa-heart';
            btn.classList.add('text-danger');
        } else {
            icon.className = 'far fa-heart';
            btn.classList.remove('text-danger');
        }
    }

    // Re-filter if on favorites view
    if (currentYtCategory === 'Favorites') {
        window.filterYoutube();
    }
};

window.getYtProgress = function () {
    try {
        return JSON.parse(localStorage.getItem(YT_PROGRESS_KEY) || '{}');
    } catch { return {}; }
};

window.markVideoWatched = function (playlistId, videoId) {
    let progress = window.getYtProgress();
    if (!progress[playlistId]) progress[playlistId] = [];
    if (!progress[playlistId].includes(videoId)) {
        progress[playlistId].push(videoId);
        localStorage.setItem(YT_PROGRESS_KEY, JSON.stringify(progress));
    }
    return progress[playlistId].length;
};

window.getPlaylistProgress = function (playlistId, totalVideos) {
    const progress = window.getYtProgress();
    const watched = progress[playlistId] ? progress[playlistId].length : 0;
    return totalVideos > 0 ? Math.round((watched / totalVideos) * 100) : 0;
};

// ============== Filter Functions ==============
window.setYtFilter = function (cat, btn) {
    currentYtCategory = cat;
    document.querySelectorAll('.yt-filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    window.filterYoutube();
};

window.filterYoutube = function () {
    const searchEl = document.getElementById('yt-search');
    const query = searchEl ? searchEl.value.toLowerCase() : '';
    const cards = document.querySelectorAll('.yt-card-col');
    const favorites = window.getYtFavorites();
    let visibleCount = 0;

    cards.forEach(card => {
        const title = (card.dataset.title || '').toLowerCase();
        const channel = (card.dataset.channel || '').toLowerCase();
        const category = card.dataset.category || 'General';
        const playlistId = card.dataset.id;

        const matchesSearch = title.includes(query) || channel.includes(query);
        let matchesCat = currentYtCategory === 'All' || category === currentYtCategory;

        // Special case for Favorites filter
        if (currentYtCategory === 'Favorites') {
            matchesCat = favorites.includes(playlistId);
        }

        if (matchesSearch && matchesCat) {
            card.style.display = 'block';
            visibleCount++;
        } else {
            card.style.display = 'none';
        }
    });

    const noRes = document.getElementById('no-results');
    if (noRes) noRes.className = visibleCount === 0 ? 'text-center py-5 d-block' : 'text-center py-5 d-none';
};

// Main Playlist View (Grid) - PREMIUM DESIGN
function pageYoutubeCourses() {
    const playlists = (window.YouTubeDataGen && window.YouTubeDataGen.length > 0)
        ? window.YouTubeDataGen
        : window.YouTubeCoursesData;

    const categories = ['All', 'Favorites', 'TryHackMe', 'Red Team', 'Blue Team', 'Web Security', 'Cloud', 'Networking', 'Programming', 'Tools', 'Podcast', 'General'];

    // Category color mapping
    const catColors = {
        'All': '#6c757d',
        'Favorites': '#ff4757',
        'TryHackMe': '#C12C1F', // THM Brand Red
        'Red Team': '#dc3545',
        'Blue Team': '#0d6efd',
        'Web Security': '#20c997',
        'Cloud': '#17a2b8',
        'Networking': '#198754',
        'Programming': '#6f42c1',
        'Tools': '#fd7e14',
        'Podcast': '#e83e8c',
        'General': '#6c757d'
    };

    const totalPlaylists = playlists.length;
    const totalVideos = playlists.reduce((acc, p) => acc + (parseInt(p.videoCount) || 0), 0);

    return `
    <style>
        .yt-hub-hero {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            position: relative;
            overflow: hidden;
        }
        .yt-hub-hero::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,0,0,0.1) 0%, transparent 50%);
            animation: pulse-glow 8s ease-in-out infinite;
        }
        @keyframes pulse-glow {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.2); opacity: 0.8; }
        }
        .yt-glass-card {
            background: rgba(30, 30, 40, 0.8);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .yt-glass-card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 20px 40px rgba(0,0,0,0.4), 0 0 30px rgba(255,0,0,0.1);
            border-color: rgba(255,0,0,0.3);
        }
        .yt-card-thumb {
            position: relative;
            height: 200px;
            overflow: hidden;
            border-radius: 16px 16px 0 0;
        }
        .yt-card-thumb img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.5s ease;
        }
        .yt-glass-card:hover .yt-card-thumb img {
            transform: scale(1.1);
        }
        .yt-card-thumb::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 60%;
            background: linear-gradient(to top, rgba(0,0,0,0.8), transparent);
        }
        .yt-cat-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .yt-play-overlay {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) scale(0.8);
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 10;
        }
        .yt-glass-card:hover .yt-play-overlay {
            transform: translate(-50%, -50%) scale(1);
            opacity: 1;
        }
        .yt-filter-btn.active {
            background: linear-gradient(135deg, #ff0000, #cc0000) !important;
            border-color: #ff0000 !important;
            color: white !important;
        }
        .yt-search-box {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 50px;
            transition: all 0.3s ease;
        }
        .yt-search-box:focus-within {
            border-color: rgba(255,0,0,0.5);
            box-shadow: 0 0 20px rgba(255,0,0,0.2);
        }
    </style>

    <div class="container-fluid p-0">
        <!-- Hero Section -->
        <div class="yt-hub-hero text-center py-5 px-3" style="min-height: 400px;">
            <div class="position-relative" style="z-index: 2;">
                <!-- Badge -->
                <div class="d-inline-flex align-items-center gap-2 px-4 py-2 rounded-pill mb-4" 
                     style="background: rgba(255,0,0,0.15); border: 1px solid rgba(255,0,0,0.3);">
                    <i class="fab fa-youtube text-danger"></i>
                    <span class="text-danger fw-bold">FREE EDUCATION PLATFORM</span>
                </div>

                <!-- Title -->
                <h1 class="display-2 fw-bold text-white mb-3" style="text-shadow: 0 0 40px rgba(255,0,0,0.3);">
                    YouTube <span style="background: linear-gradient(135deg, #ff0000, #ff6b6b); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Hub</span>
                </h1>
                
                <p class="text-secondary fs-5 mb-4 mx-auto" style="max-width: 600px;">
                    Access the world's best cybersecurity content. Curated playlists from elite educators, streamed directly to you.
                </p>

                <!-- Stats -->
                <div class="d-flex justify-content-center gap-5 mb-5">
                    <div class="text-center">
                        <div class="display-6 fw-bold text-white">${totalPlaylists}</div>
                        <div class="text-secondary small text-uppercase">Playlists</div>
                    </div>
                    <div class="text-center">
                        <div class="display-6 fw-bold text-white">${totalVideos}+</div>
                        <div class="text-secondary small text-uppercase">Videos</div>
                    </div>
                    <div class="text-center">
                        <div class="display-6 fw-bold text-white">${categories.length - 1}</div>
                        <div class="text-secondary small text-uppercase">Categories</div>
                    </div>
                </div>

                <!-- Search -->
                <div class="mx-auto mb-4" style="max-width: 600px;">
                    <div class="yt-search-box d-flex align-items-center px-4 py-3">
                        <i class="fas fa-search text-secondary me-3"></i>
                        <input type="text" id="yt-search" class="form-control bg-transparent border-0 text-white shadow-none" 
                               placeholder="Search playlists, channels, topics..." onkeyup="filterYoutube()">
                    </div>
                </div>

                <!-- Filter Buttons -->
                <div class="d-flex justify-content-center gap-2 flex-wrap">
                    ${categories.map(cat => `
                        <button class="btn btn-sm rounded-pill px-4 py-2 yt-filter-btn ${cat === 'All' ? 'active' : ''}" 
                                style="border: 1px solid ${catColors[cat]}; color: ${catColors[cat]}; transition: all 0.3s;"
                                onclick="setYtFilter('${cat}', this)">
                            ${cat}
                        </button>
                    `).join('')}
                </div>
            </div>
        </div>

        <!-- Grid Section -->
        <div class="container py-5">
            <div class="row g-4" id="yt-grid">
                ${playlists.map(pl => renderYoutubeCard(pl, catColors)).join('')}
            </div>
            
            <div id="no-results" class="text-center py-5 d-none">
                <i class="fas fa-satellite-dish fa-4x text-secondary mb-4" style="opacity: 0.5;"></i>
                <h4 class="text-white-50">No playlists found</h4>
                <p class="text-muted">Try different search terms or filters</p>
            </div>
        </div>
    </div>
    `;
}

function renderYoutubeCard(pl, catColors = {}) {
    const catColor = catColors[pl.category] || '#6c757d';
    const favorites = window.getYtFavorites ? window.getYtFavorites() : [];
    const isFav = favorites.includes(pl.id);
    const progress = window.getPlaylistProgress ? window.getPlaylistProgress(pl.id, pl.videoCount || 0) : 0;

    return `
    <div class="col-md-6 col-lg-4 col-xl-3 yt-card-col" 
         data-category="${pl.category}" 
         data-title="${pl.title}" 
         data-channel="${pl.channel}"
         data-id="${pl.id}">
         
        <div class="yt-glass-card h-100" onclick="loadPage('youtube-player', '${pl.id}')" style="cursor: pointer;">
            <!-- Thumbnail -->
            <div class="yt-card-thumb">
                <img src="${pl.image}" alt="${pl.title}" 
                     onerror="this.src='assets/images/placeholder_course.jpg'">
                
                <!-- Play Overlay -->
                <div class="yt-play-overlay">
                    <div class="rounded-circle d-flex align-items-center justify-content-center" 
                         style="width: 70px; height: 70px; background: rgba(255,0,0,0.9); box-shadow: 0 0 30px rgba(255,0,0,0.5);">
                        <i class="fas fa-play text-white fs-4" style="margin-left: 4px;"></i>
                    </div>
                </div>
                
                <!-- Favorite Button -->
                <button class="position-absolute top-0 end-0 m-2 btn btn-sm rounded-circle ${isFav ? 'text-danger' : 'text-white'}" 
                        style="width: 36px; height: 36px; background: rgba(0,0,0,0.6); backdrop-filter: blur(5px); z-index: 10; border: none;"
                        data-fav-id="${pl.id}"
                        onclick="toggleYtFavorite('${pl.id}', event)">
                    <i class="${isFav ? 'fas' : 'far'} fa-heart"></i>
                </button>
                
                <!-- Video Count Badge -->
                <div class="position-absolute bottom-0 end-0 m-2 px-3 py-1 rounded-pill" 
                     style="background: rgba(0,0,0,0.8); backdrop-filter: blur(10px); z-index: 5;">
                    <i class="fas fa-play-circle text-danger me-1"></i>
                    <span class="text-white fw-bold small">${pl.videoCount || '?'}</span>
                </div>
                
                <!-- Category Badge -->
                <div class="position-absolute top-0 start-0 m-2 yt-cat-badge" 
                     style="background: ${catColor}; z-index: 5;">
                    ${pl.category}
                </div>
                
                <!-- Progress Bar -->
                ${progress > 0 ? `
                <div class="position-absolute bottom-0 start-0 end-0" style="height: 4px; background: rgba(0,0,0,0.5); z-index: 5;">
                    <div style="width: ${progress}%; height: 100%; background: linear-gradient(90deg, #ff0000, #ff6b6b);"></div>
                </div>
                ` : ''}
            </div>
            
            <!-- Body -->
            <div class="p-4">
                <!-- Channel -->
                <div class="d-flex align-items-center mb-2">
                    <i class="fab fa-youtube text-danger me-2"></i>
                    <span class="text-secondary small text-uppercase fw-bold" style="letter-spacing: 0.5px;">
                        ${pl.channel}
                    </span>
                </div>
                
                <!-- Title -->
                <h5 class="text-white fw-bold mb-3" style="line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">
                    ${pl.title}
                </h5>
                
                <!-- Footer -->
                <div class="d-flex justify-content-between align-items-center pt-3" style="border-top: 1px solid rgba(255,255,255,0.1);">
                    <span class="text-secondary small">
                        ${progress > 0 ? `<i class="fas fa-check-circle text-success me-1"></i> ${progress}%` : `<i class="fas fa-clock me-1"></i> ${pl.videoCount ? Math.ceil(pl.videoCount * 15 / 60) + 'h+' : 'N/A'}`}
                    </span>
                    <span class="text-danger fw-bold small">
                        ${progress > 0 ? 'Continue' : 'Watch Now'} <i class="fas fa-arrow-right ms-1"></i>
                    </span>
                </div>
            </div>
        </div>
    </div>
    `;
}

// Premium Player UI with Sidebar - YouTube Style
function pageYoutubePlayer(id) {
    const playlists = (window.YouTubeDataGen && window.YouTubeDataGen.length > 0)
        ? window.YouTubeDataGen
        : window.YouTubeCoursesData;

    const pl = playlists.find(p => p.id === id);
    if (!pl) return `<div class="d-flex align-items-center justify-content-center h-100 text-white"><h3>Playlist not found</h3></div>`;

    const videos = pl.videos || [];
    const firstVid = videos.length > 0 ? videos[0].videoId : null;
    const initialSrc = firstVid
        ? `https://www.youtube.com/embed/${firstVid}?rel=0`
        : `https://www.youtube.com/embed/videoseries?list=${pl.id}`;

    return `
    <style>
        .yt-watch-page {
            background: #0f0f0f;
            min-height: 100vh;
            padding: 24px;
        }
        .yt-video-container {
            position: relative;
            width: 100%;
            padding-bottom: 56.25%; /* 16:9 */
            background: #000;
            border-radius: 12px;
            overflow: hidden;
        }
        .yt-video-container iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
        }
        .yt-playlist-panel {
            background: #1a1a1a;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            max-height: 600px;
            display: flex;
            flex-direction: column;
        }
        .yt-playlist-header {
            padding: 16px;
            background: linear-gradient(135deg, rgba(255,0,0,0.15), rgba(255,0,0,0.05));
            border-bottom: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px 12px 0 0;
        }
        .yt-playlist-items {
            flex: 1;
            overflow-y: auto;
            max-height: 480px;
        }
        .yt-video-item {
            display: flex;
            gap: 12px;
            padding: 12px 16px;
            background: transparent;
            border: none;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            transition: background 0.2s;
            cursor: pointer;
            width: 100%;
            text-align: left;
        }
        .yt-video-item:hover {
            background: rgba(255,255,255,0.05);
        }
        .yt-video-item.active {
            background: rgba(255,0,0,0.1);
            border-left: 3px solid #ff0000;
        }
        .yt-video-num {
            min-width: 28px;
            height: 28px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
            color: #aaa;
        }
        .yt-back-btn {
            background: rgba(255,255,255,0.1);
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background 0.2s;
        }
        .yt-back-btn:hover {
            background: rgba(255,255,255,0.2);
        }
    </style>

    <div class="yt-watch-page">
        <!-- Header -->
        <div class="d-flex align-items-center gap-3 mb-4">
            <button class="yt-back-btn" onclick="loadPage('youtube-courses')">
                <i class="fas fa-arrow-left me-2"></i> Back to Hub
            </button>
            <a href="https://www.youtube.com/playlist?list=${pl.id}" target="_blank" 
               class="btn btn-sm btn-outline-danger rounded-pill px-3 ms-auto">
                <i class="fab fa-youtube me-2"></i> Open on YouTube
            </a>
        </div>

        <!-- Main Layout -->
        <div class="row g-4">
            <!-- Video Column -->
            <div class="col-lg-8">
                <!-- Video Player -->
                <div class="yt-video-container mb-3">
                    <iframe id="yt-main-frame" 
                            src="${initialSrc}" 
                            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" 
                            allowfullscreen></iframe>
                </div>
                
                <!-- Video Info -->
                <div class="p-3 rounded-3" style="background: #1a1a1a;">
                    <h5 class="text-white fw-bold mb-2">${pl.title}</h5>
                    <div class="d-flex align-items-center gap-2">
                        <i class="fab fa-youtube text-danger"></i>
                        <span class="text-secondary">${pl.channel}</span>
                        <span class="text-secondary">•</span>
                        <span class="text-secondary">${videos.length} videos</span>
                    </div>
                </div>
            </div>

            <!-- Playlist Column -->
            <div class="col-lg-4">
                <div class="yt-playlist-panel">
                    <!-- Playlist Header -->
                    <div class="yt-playlist-header">
                        <h6 class="text-white fw-bold mb-1">
                            <i class="fas fa-list-ul text-danger me-2"></i> Playlist
                        </h6>
                        <small class="text-secondary">${videos.length} videos • ${pl.channel}</small>
                    </div>
                    
                    <!-- Playlist Items -->
                    <div class="yt-playlist-items">
                        ${videos.length > 0 ? videos.map((v, i) => {
        const watched = window.getYtProgress && window.getYtProgress()[id] && window.getYtProgress()[id].includes(v.videoId);
        return `
                            <button class="yt-video-item ${i === 0 ? 'active' : ''}"
                                    onclick="changeYtVideo('${id}', '${v.videoId}', this)">
                                <div class="yt-video-num ${watched ? 'text-success' : ''}">
                                    ${watched ? '<i class="fas fa-check"></i>' : (i + 1)}
                                </div>
                                <div class="flex-grow-1">
                                    <div class="text-white small fw-semibold mb-1" style="line-height: 1.3;">
                                        ${v.title.length > 60 ? v.title.substring(0, 60) + '...' : v.title}
                                    </div>
                                    <small class="${watched ? 'text-success' : 'text-secondary'}">
                                        ${watched ? '<i class="fas fa-check-circle me-1"></i>Watched' : '<i class="fas fa-play me-1"></i>Video'}
                                    </small>
                                </div>
                            </button>
                        `}).join('') : `
                            <div class="p-4 text-center">
                                <i class="fas fa-video-slash fa-2x text-secondary mb-3"></i>
                                <p class="text-muted small mb-0">Video list unavailable.<br>Playing in playlist mode.</p>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        </div>
    </div>
    `;
}

// Global video change function
window.changeYtVideo = function (playlistId, vidId, btn) {
    const frame = document.getElementById('yt-main-frame');
    if (frame) frame.src = 'https://www.youtube.com/embed/' + vidId + '?autoplay=1&rel=0';

    // Mark as watched
    if (window.markVideoWatched) {
        window.markVideoWatched(playlistId, vidId);
    }

    // Update button to show watched
    if (btn) {
        const numBox = btn.querySelector('.yt-video-num');
        if (numBox) {
            numBox.className = 'yt-video-num text-success';
            numBox.innerHTML = '<i class="fas fa-check"></i>';
        }
        const statusText = btn.querySelector('span[style*="0.75rem"]');
        if (statusText) {
            statusText.innerHTML = '<i class="fas fa-check-circle text-success me-1"></i> Watched';
        }
    }

    // Active state
    document.querySelectorAll('.yt-video-item').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
};

window.pageYoutubeCourses = pageYoutubeCourses;
window.pageYoutubePlayer = pageYoutubePlayer;
