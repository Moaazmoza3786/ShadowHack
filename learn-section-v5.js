/* learn-section-v5.js */
/* Professional Learn Section Implementation V5.0 - Ultra Compact & Clean */

/* --- Data Aggregation Helper --- */
/* --- Data Aggregation Helper --- */
function getIntegratedLearnDataV5() {
    const data = window.UnifiedLearningData || {};

    // 1. Paths
    const paths = (data.paths || []).map(p => ({
        id: p.id, title: p.name, type: 'Career Path', difficulty: p.difficulty ? (p.difficulty.charAt(0).toUpperCase() + p.difficulty.slice(1)) : 'Beginner',
        status: p.premium ? 'Pro' : 'Free', xp: (p.totalRooms || 5) * 100,
        icon: p.icon || 'fa-map-signs', color: p.color || '#22c55e', description: p.description,
        hours: p.estimatedHours, rooms: p.totalRooms
    }));

    // 2. Modules
    const modules = (data.modules || []).map(m => ({
        id: m.id, title: m.title, type: 'Module', difficulty: m.difficulty.charAt(0).toUpperCase() + m.difficulty.slice(1),
        status: 'Not Started', xp: m.rooms.reduce((sum, r) => sum + (r.points || 0), 0), icon: m.icon || 'fa-cube',
        color: m.color || '#3b82f6', description: m.description, team: m.team
    }));

    // 3. Walkthroughs (CTF Rooms)
    let walkthroughs = [];
    if (window.ctfRooms) {
        Object.keys(window.ctfRooms).forEach(category => {
            window.ctfRooms[category].forEach(room => {
                walkthroughs.push({
                    id: room.id, title: room.title.en, type: category.toUpperCase(), difficulty: room.difficulty.charAt(0).toUpperCase() + room.difficulty.slice(1),
                    status: 'Free', icon: getIconForCategory(category), color: getColorForCategory(category), points: room.points, tags: room.tags
                });
            });
        });
    }

    const networks = []; // Removed

    // Apply Smart Icons
    paths.forEach(p => { if (!p.icon || p.icon.startsWith('fa-')) p.icon = getSmartIconV5(p.title, 'path'); });
    modules.forEach(m => { if (!m.icon || m.icon === 'fa-cube') m.icon = getSmartIconV5(m.title); });
    walkthroughs.forEach(w => { if (!w.icon || w.icon === 'fa-cube') w.icon = getSmartIconV5(w.title, w.type); });

    return { paths, modules, walkthroughs, networks };
}

function getSmartIconV5(title, type = '') {
    const t = title.toLowerCase() + ' ' + type.toLowerCase();
    const p = 'assets/images/3d-icons/';
    if (t.includes('pre security') || t.includes('intro')) return p + 'icon_security_3d_1765817313667.png';
    if (t.includes('web') || t.includes('bug bounty')) return p + 'icon_web_3d_1765817117593.png';
    if (t.includes('linux')) return p + 'icon_linux_3d_1765817009790.png';
    if (t.includes('network')) return p + 'icon_network_3d_1765817211308.png';
    if (t.includes('soc')) return p + 'icon_soc_3d_1765820038104.png';
    if (t.includes('pentest') || t.includes('e-jpt') || t.includes('junior')) return p + 'icon_pentest_3d_1765819812403.png';
    if (t.includes('red team') || t.includes('offensive')) return p + 'icon_redteam_3d_1765819904532.png';
    if (t.includes('malware')) return p + 'icon_malware_3d_1765820129321.png';
    if (t.includes('python') || t.includes('scripting')) return p + 'icon_scripting_3d_1765819420953.png';
    if (t.includes('phishing')) return p + 'icon_osint_3d_1765819003909.png';
    if (t.includes('forensics')) return p + 'icon_forensics_3d_1765922362347.png';
    if (t.includes('cryptography')) return p + 'icon_crypto_3d_1765922333633.png';
    if (t.includes('active directory')) return p + 'icon_ad_forest_3d_1765819581743.png';
    if (type === 'path') return p + 'icon_learning_path_3d_1765922272083.png';
    return p + 'icon_security_3d_1765817313667.png';
}

function getIconForCategory(cat) { const map = { web: 'fa-globe', crypto: 'fa-key', forensics: 'fa-magnifying-glass', osint: 'fa-eye', network: 'fa-network-wired', reversing: 'fa-microchip', pwn: 'fa-bomb' }; return map[cat] || 'fa-cube'; }
function getColorForCategory(cat) { const map = { web: '#3b82f6', crypto: '#eab308', forensics: '#a855f7', osint: '#ef4444', network: '#22c55e', reversing: '#f97316', pwn: '#ec4899' }; return map[cat] || '#64748b'; }

/* --- Premium Cyber Styles V5 (Ultra Compact) --- */
function getLearnStylesV5() {
    return `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;700&display=swap');

        :root {
            --cyber-bg: #050510;
            --card-bg: #11131f; /* Darker, flatter */
            --border-color: rgba(255, 255, 255, 0.12);
            --neon-blue: #00f3ff;
            --neon-green: #00ff9d;
            --neon-purple: #bc13fe;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
        }

        .learn-container {
            font-family: 'Outfit', sans-serif !important;
            background: var(--cyber-bg);
            min-height: 100vh;
            color: var(--text-main);
            padding-bottom: 60px;
        }

        /* --- V5 Card Design (Ultra Compact) --- */
        .path-card-v5 {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px; /* Tighter radius */
            overflow: hidden;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            display: flex;
            flex-direction: column;
            height: 100%;
            padding: 0; /* Internal padding only */
        }

        .path-card-v5:hover {
            transform: translateY(-4px);
            border-color: var(--glow-color, var(--neon-blue));
            box-shadow: 0 4px 20px -5px rgba(0, 0, 0, 0.4);
        }

        /* Top Bar: Minimal */
        .v5-top-bar {
            padding: 10px 14px;
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            background: rgba(255,255,255,0.01);
            height: 40px;
        }

        .v5-badge {
            font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            padding: 3px 8px; border-radius: 4px;
            background: rgba(255,255,255,0.08); color: #ccc;
        }
        .v5-badge.pro { background: var(--neon-purple); color: #fff; }

        /* Content Body */
        .v5-body {
            padding: 16px;
            display: flex; flex-direction: column; align-items: center; text-align: center;
            flex-grow: 1;
        }

        /* Icon: Smallest yet visible */
        .v5-icon-container {
            width: 60px; height: 60px; /* Ultra Compact */
            margin-bottom: 12px;
            transition: transform 0.3s ease;
        }
        .path-card-v5:hover .v5-icon-container { transform: scale(1.1); }
        
        .v5-icon-img {
            width: 100%; height: 100%; object-fit: contain;
            filter: drop-shadow(0 5px 15px rgba(0,0,0,0.3));
        }

        .v5-title {
            font-size: 1.1rem; font-weight: 700; color: #fff; margin-bottom: 6px;
            line-height: 1.25;
            display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
            height: 2.5rem; /* Fixed height for alignment */
        }
        .v5-desc {
            font-size: 0.8rem; color: var(--text-muted); line-height: 1.4; margin-bottom: 12px;
            display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
            height: 2.3rem;
            opacity: 0.8;
        }

        /* Stats Row - Compact */
        .v5-stats-row {
            display: flex; justify-content: center; gap: 15px;
            width: 100%;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .v5-stat { font-size: 0.75rem; color: #94a3b8; display: flex; align-items: center; gap: 5px; }
        .v5-stat i { color: var(--glow-color, var(--neon-blue)); font-size: 0.8rem; }

        /* Footer */
        .v5-footer {
            padding: 10px 14px;
            background: rgba(0,0,0,0.25);
            border-top: 1px solid rgba(255,255,255,0.05);
            display: flex; justify-content: space-between; align-items: center;
            height: 44px;
        }

        .v5-progress-wrap { flex-grow: 1; margin-right: 12px; }
        .v5-prog-track { height: 3px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden; }
        .v5-prog-fill { height: 100%; background: var(--glow-color, var(--neon-blue)); border-radius: 2px; }

        .v5-btn {
            width: 28px; height: 28px; border-radius: 6px;
            background: rgba(255,255,255,0.05); color: #fff;
            display: flex; align-items: center; justify-content: center;
            border: 1px solid rgba(255,255,255,0.1);
            font-size: 0.8rem;
        }
        .path-card-v5:hover .v5-btn {
            background: var(--glow-color, var(--neon-blue)); color: #000; border-color: transparent;
        }

        /* Helpers */
        .theme-blue { --glow-color: var(--neon-blue); }
        .theme-green { --glow-color: var(--neon-green); }
        .theme-red { --glow-color: var(--neon-red); }
        .theme-purple { --glow-color: var(--neon-purple); }
        .theme-orange { --glow-color: var(--neon-orange); }

        /* Grid - Tighter */
        .grid-3 { 
            display: grid; 
            /* Min 240px is very compact */
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); 
            gap: 20px; 
        }

        .fade-in { animation: fadeIn 0.4s ease-out forwards; opacity: 0; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        .learn-hero { margin-bottom: 30px !important; padding: 30px !important; border-radius: 20px !important; }
        .cyber-input { background: #0f111a !important; border: 1px solid rgba(255,255,255,0.1) !important; padding: 10px 15px !important; font-size: 0.9rem !important; }
    </style>
    `;
}

function renderPathCard(path) {
    const iconSrc = getSmartIconV5(path.title, 'path');

    // Determine Theme
    let theme = 'theme-blue';
    if (path.title.includes('Pre') || path.title.includes('Intro')) theme = 'theme-green';
    else if (path.title.includes('Red')) theme = 'theme-red';
    else if (path.title.includes('SOC') || path.title.includes('Blue')) theme = 'theme-purple';
    else if (path.title.includes('Forensics')) theme = 'theme-orange';

    const isPro = path.status === 'Pro' || path.status === 'VIP';
    let progress = Math.floor(Math.random() * 30);

    return `
    <div class="path-card-v5 ${theme}" onclick="loadPage('path-roadmap:${path.id}')" onmousemove="updateCardEffect(event, this)">
        <div class="v5-top-bar">
            <span class="v5-badge ${isPro ? 'pro' : ''}">${isPro ? 'PRO' : 'FREE'}</span>
            <span style="font-size:0.7rem; color:#64748b;"><i class="fas fa-users"></i> 2.4k</span>
        </div>

        <div class="v5-body">
            <div class="v5-icon-container">
                <img src="${iconSrc}" class="v5-icon-img" alt="${path.title}" onerror="this.src='assets/images/3d-icons/icon_security_3d_1765817313667.png'">
            </div>
            
            <h3 class="v5-title">${path.title}</h3>
            <p class="v5-desc">${path.description ? path.description.substring(0, 50) + '...' : 'Start your journey.'}</p>
            
            <div class="v5-stats-row">
                <span class="v5-stat"><i class="fas fa-layer-group"></i> ${path.difficulty}</span>
                <span class="v5-stat"><i class="fas fa-clock"></i> ${path.hours || 40}h</span>
                <span class="v5-stat"><i class="fas fa-flask"></i> ${path.rooms || 10}</span>
            </div>
        </div>
        
        <div class="v5-footer">
            <div class="v5-progress-wrap">
                <div class="d-flex justify-content-between mb-1" style="font-size:0.65rem; color:#94a3b8;">
                    <span>PROGRESS</span><span>${progress}%</span>
                </div>
                <div class="v5-prog-track"><div class="v5-prog-fill" style="width: ${progress}%;"></div></div>
            </div>
            <div class="v5-btn"><i class="fas fa-arrow-right"></i></div>
        </div>
    </div>
    `;
}

function renderModuleCard(mod) {
    // Reuse V5 style for consistency
    const iconSrc = getSmartIconV5(mod.title, 'module');
    return `
    <div class="path-card-v5 theme-blue" onclick="openModuleDetails('${mod.id}')">
         <div class="v5-top-bar">
            <span class="v5-badge">${mod.difficulty}</span>
            <span style="font-size:0.7rem; color:#64748b;">XP ${mod.xp || 100}</span>
        </div>
        <div class="v5-body">
             <div class="v5-icon-container">
                <img src="${iconSrc}" class="v5-icon-img" alt="${mod.title}">
            </div>
            <h3 class="v5-title">${mod.title}</h3>
            <p class="v5-desc">${mod.description || 'Module description...'}</p>
        </div>
        <div class="v5-footer">
             <span style="font-size:0.7rem; color:#94a3b8;">START MODULE</span>
             <div class="v5-btn"><i class="fas fa-play"></i></div>
        </div>
    </div>
    `;
}
function renderWalkthroughCard(wt) {
    return `<div class="path-card-v5 theme-purple"><div class="v5-body"><h3 class="v5-title">${wt.title}</h3></div></div>`;
}
function renderNetworkCard(n) { return ''; }

/* --- V5 Main Page --- */
/* --- V5 Main Page --- */
function pageLearningPathsV5() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStylesV5()}
        
        <div class="d-flex justify-content-between align-items-center mb-4 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0" style="padding: 8px 20px; font-size:0.9rem;">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة', 'Back')}
            </button>
        </div>

        <div class="learn-hero mb-4 fade-in delay-1" style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1);">
            <div class="row align-items-center">
                <div class="col-lg-8">
                    <span class="v5-badge pro mb-2 d-inline-block">PREMIUM CURRICULUM</span>
                    <h1 class="display-5 fw-bold text-white mb-2">
                        ${txt('مسارات التعلم', 'Learning Paths')} <span style="font-size:1rem; color:var(--neon-green); vertical-align: super;">V5.0</span>
                    </h1>
                    <p class="text-muted mb-3" style="max-width:600px;">${txt('مسارات احترافية مصممة لنقلك من المبتدئ إلى الخبير.', 'Professional paths designed to take you from beginner to expert.')}</p>
                    
                    <!-- Integrated Search -->
                    <div class="d-flex gap-2">
                        <input type="text" id="path-search" onkeyup="filterPaths()" placeholder="Search paths..." class="form-control cyber-input" style="max-width: 300px;">
                        <select id="path-diff" onchange="filterPaths()" class="form-select cyber-input" style="max-width: 150px;">
                            <option value="All">Level</option>
                            <option value="Beginner">Beginner</option>
                            <option value="Advanced">Advanced</option>
                        </select>
                    </div>
                </div>
                 <div class="col-lg-4 text-center">
                    <img src="assets/images/3d-icons/icon_learning_path_3d_1765922272083.png" style="width: 180px; filter: drop-shadow(0 0 30px rgba(0,0,0,0.5));">
                </div>
            </div>
        </div>
        
        <div class="grid-3 fade-in delay-2" id="paths-grid">
            ${getIntegratedLearnDataV5().paths.map(renderPathCard).join('')}
        </div>
    </div>
    `;
}

/* Re-expose V2/V3 legacy functions just in case, but redirect logic */
window.pageLearnV2 = pageLearningPathsV5;
window.pageLearningPathsV2 = pageLearningPathsV5;
window.pageLearn = pageLearningPathsV5;
window.pageLearningPathsPro = pageLearningPathsV5;

/* Mouse Effect */
function updateCardEffect(e, card) {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    card.style.setProperty('--mouse-x', `${x}px`);
    card.style.setProperty('--mouse-y', `${y}px`);
}
window.updateCardEffect = updateCardEffect;
window.renderPathCard = renderPathCard;
window.getIntegratedLearnDataV5 = getIntegratedLearnDataV5;
window.getLearnStylesV5 = getLearnStylesV5;
window.pageLearningPathsV5 = pageLearningPathsV5;

/* Export others needed for index */
window.pageModules = function () { return '<div class="text-white p-5">Modules V5 Loading...</div>'; };
