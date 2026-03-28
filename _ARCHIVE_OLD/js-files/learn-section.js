/* learn-section.js */
/* Professional Learn Section Implementation V3.0 - Cyber Future Theme */

/* --- Data Aggregation Helper --- */
function getIntegratedLearnData() {
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

    // 4. Networks
    // 4. Networks - REMOVED
    const networks = [];

    // Apply Smart Icons
    paths.forEach(p => { if (!p.icon || p.icon.startsWith('fa-')) p.icon = getSmartIcon(p.title, 'path'); });
    modules.forEach(m => { if (!m.icon || m.icon === 'fa-cube') m.icon = getSmartIcon(m.title); });
    walkthroughs.forEach(w => { if (!w.icon || w.icon === 'fa-cube') w.icon = getSmartIcon(w.title, w.type); });

    return { paths, modules, walkthroughs, networks };
}

function getSmartIcon(title, type = '') {
    const t = title.toLowerCase() + ' ' + type.toLowerCase();
    const p = 'assets/images/3d-icons/';

    // --- Paths & Careers ---
    if (t.includes('pre security') || t.includes('intro')) return p + 'icon_security_3d_1765817313667.png';
    if (t.includes('junior') || t.includes('jr')) return p + 'icon_pentest_3d_1765819812403.png'; // Need generic pentest icon
    if (t.includes('web') || t.includes('bug bounty')) return p + 'icon_web_3d_1765817117593.png';
    if (t.includes('offensive') || t.includes('red team')) return p + 'icon_redteam_3d_1765819904532.png'; // Need red team icon
    if (t.includes('soc') || t.includes('blue')) return p + 'icon_soc_3d_1765820038104.png';
    if (t.includes('malware')) return p + 'icon_malware_3d_1765820129321.png';

    // --- Blue Team Modules ---
    if (t.includes('honey')) return p + 'icon_honeynet_3d_1765818484701.png';
    if (t.includes('framework') || t.includes('mitre') || t.includes('diamond')) return p + 'icon_frameworks_3d_1765818576549.png';
    if (t.includes('siem') || t.includes('splunk') || t.includes('log')) return p + 'icon_siem_3d_1765818657470.png';
    if (t.includes('incident') || t.includes('response') || t.includes('ir ') || t.includes('triage')) return p + 'icon_ir_3d_1765818771664.png';
    if (t.includes('hunt') || t.includes('threat')) return p + 'icon_hunt_3d_1765818898436.png';

    // --- Red Team Modules ---
    if (t.includes('osint') || t.includes('recon') || t.includes('google')) return p + 'icon_osint_3d_1765819003909.png';
    if (t.includes('phishing') || t.includes('access') || t.includes('initial')) return p + 'icon_access_3d_1765819070867.png';
    if (t.includes('post') || t.includes('persistence') || t.includes('credential')) return p + 'icon_post_3d_1765819141827.png';
    if (t.includes('evasion') || t.includes('obfuscation') || t.includes('bypass') || t.includes('amsi')) return p + 'icon_evasion_3d_1765819229136.png';
    if (t.includes('c2') || t.includes('command') || t.includes('sliver')) return p + 'icon_c2_3d_1765819311043.png';

    // --- Specialist ---
    if (t.includes('script') || t.includes('python') || t.includes('bash')) return p + 'icon_scripting_3d_1765819420953.png';
    if (t.includes('traffic') || t.includes('wireshark') || t.includes('packet') || t.includes('network')) return p + 'icon_traffic_3d_1765819502216.png';
    if (t.includes('forest') || t.includes('active directory') || t.includes('ad ')) return p + 'icon_ad_forest_3d_1765819581743.png';
    if (t.includes('exploit') || t.includes('overflow') || t.includes('kernel')) return p + 'icon_exploit_dev_3d_1765819716830.png';

    // --- Technical ---
    if (t.includes('linux')) return p + 'icon_linux_3d_1765817009790.png';
    if (t.includes('docker') || t.includes('container')) return p + 'icon_docker_3d_1765820250100.png';
    if (t.includes('android') || t.includes('mobile')) return p + 'icon_mobile_3d_1765820315800.png';

    // Fallback based on type
    if (type.includes('path')) return p + 'icon_path_3d_1765820400200.png';

    return p + 'icon_security_3d_1765817313667.png';
}

function getIconForCategory(cat) {
    const map = { web: 'fa-globe', crypto: 'fa-key', forensics: 'fa-magnifying-glass', osint: 'fa-eye', network: 'fa-network-wired', reversing: 'fa-microchip', pwn: 'fa-bomb' };
    return map[cat] || 'fa-cube';
}
function getColorForCategory(cat) {
    const map = { web: '#3b82f6', crypto: '#eab308', forensics: '#a855f7', osint: '#ef4444', network: '#22c55e', reversing: '#f97316', pwn: '#ec4899' };
    return map[cat] || '#64748b';
}

/* --- Premium Cyber Styles V4 (Compact & Clean) --- */
function getLearnStyles() {
    return `
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;700&display=swap');

        :root {
            --cyber-bg: #050510;
            --card-bg: #0f111a;
            --border-color: rgba(255, 255, 255, 0.1);
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

        /* --- V4 Card Design (Compact) --- */
        .path-card-v4 {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            display: flex;
            flex-direction: column;
            height: 100%;
            /* Cleaner shadow */
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        .path-card-v4:hover {
            transform: translateY(-5px);
            border-color: var(--glow-color, var(--neon-blue));
            box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.3), 0 0 15px -3px var(--glow-color, var(--neon-blue));
        }

        /* Top Bar: Badge & Stats */
        .v4-top-bar {
            padding: 12px 16px;
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            background: rgba(255,255,255,0.02);
        }

        .v4-badge {
            font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            padding: 4px 10px; border-radius: 6px;
            background: rgba(255,255,255,0.1); color: #fff;
        }
        .v4-badge.pro { background: var(--neon-purple); color: #fff; box-shadow: 0 0 10px rgba(188, 19, 254, 0.4); }
        .v4-users { font-size: 0.75rem; color: var(--text-muted); display: flex; align-items: center; gap: 5px; }

        /* Content Body */
        .v4-body {
            padding: 20px;
            display: flex; flex-direction: column; align-items: center; text-align: center;
            flex-grow: 1;
        }

        /* Icon: Compact & Clean */
        .v4-icon-container {
            width: 80px; height: 80px; /* Smaller */
            margin-bottom: 15px;
            position: relative;
            transition: transform 0.3s ease;
        }
        .path-card-v4:hover .v4-icon-container { transform: scale(1.1); }
        
        .v4-icon-img {
            width: 100%; height: 100%; object-fit: contain;
            filter: drop-shadow(0 10px 20px rgba(0,0,0,0.3));
        }

        .v4-title {
            font-size: 1.25rem; font-weight: 600; color: #fff; margin-bottom: 8px;
            line-height: 1.3;
        }
        .v4-desc {
            font-size: 0.85rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 20px;
            display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
        }

        /* Stats Row */
        .v4-stats-row {
            display: flex; justify-content: center; gap: 20px;
            width: 100%;
            padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .v4-stat { font-size: 0.85rem; color: #cbd5e1; display: flex; align-items: center; gap: 6px; }
        .v4-stat i { color: var(--glow-color, var(--neon-blue)); font-size: 0.9rem; }

        /* Footer: Progress & Action */
        .v4-footer {
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            border-top: 1px solid rgba(255,255,255,0.05);
            display: flex; justify-content: space-between; align-items: center;
        }

        .v4-progress-wrap { flex-grow: 1; margin-right: 15px; }
        .v4-prog-label { font-size: 0.7rem; color: var(--text-muted); display: flex; justify-content: space-between; margin-bottom: 4px; }
        .v4-prog-track { height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden; }
        .v4-prog-fill { height: 100%; background: var(--glow-color, var(--neon-blue)); border-radius: 2px; }

        .v4-btn {
            width: 32px; height: 32px; border-radius: 8px;
            background: rgba(255,255,255,0.05); color: #fff;
            display: flex; align-items: center; justify-content: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.2s;
        }
        .path-card-v4:hover .v4-btn {
            background: var(--glow-color, var(--neon-blue)); color: #000; border-color: transparent;
        }

        /* Helpers */
        .theme-blue { --glow-color: var(--neon-blue); }
        .theme-green { --glow-color: var(--neon-green); }
        .theme-red { --glow-color: var(--neon-red); }
        .theme-purple { --glow-color: var(--neon-purple); }
        .theme-orange { --glow-color: var(--neon-orange); }

        /* Grid */
        .grid-3 { 
            display: grid; 
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); 
            gap: 24px; 
        }

        .fade-in { animation: fadeIn 0.5s ease-out forwards; opacity: 0; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Search Bar & Hero adjustments for V4 */
        .learn-hero { margin-bottom: 40px !important; padding: 40px !important; }
        .cyber-input { background: #0f111a !important; border: 1px solid rgba(255,255,255,0.1) !important; }
    </style>
    `;
}

/* --- Main Learn Page (Hub) --- */
function pageLearn() {
    const data = getIntegratedLearnData();
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="learn-hero fade-in">
            <div class="learn-hero-text">
                <h1>${txt('أكاديمية الأمن السيبراني', 'CYBER SECURITY ACADEMY')}</h1>
                <p>${txt('منصة تعليمية متكاملة تأخذك من الصفر إلى الاحتراف. استكشف مساراتنا المتقدمة وابدأ رحلتك الآن.', 'An integrated learning platform taking you from zero to hero. Explore our advanced paths and start your journey now.')}</p>
                <div style="display: flex; gap: 20px; flex-wrap: wrap;">

                    <button onclick="loadPage('modules')" class="cyber-btn">
                        <i class="fas fa-layer-group"></i> ${txt('الموديولات', 'Modules')}
                    </button>
                    <button onclick="loadPage('socsimulator')" class="cyber-btn" style="border-color: var(--neon-blue); box-shadow: 0 0 15px rgba(0, 243, 255, 0.2);">
                        <i class="fas fa-shield-halved"></i> ${txt('محاكي SOC', 'SOC Direct')}
                    </button>
                </div>
            </div>
            <div class="learn-hero-3d-icon">
                <i class="fas fa-fingerprint"></i>
            </div>
        </div>

        <!-- Latest Paths Preview -->
        <div class="section-header fade-in delay-1">
            <h2><i class="fas fa-road" style="color: var(--neon-purple);"></i> ${txt('مسارات مميزة', 'Featured Paths')}</h2>
            <a href="#" onclick="loadPage('learningpaths')" class="view-all-link">${txt('عرض الكل', 'View All')} <i class="fas fa-arrow-right"></i></a>
        </div>
        <div class="grid-3 fade-in delay-1">
            ${data.paths.slice(0, 3).map(renderPathCard).join('')}
        </div>

        <!-- Latest Modules Preview -->
        <div class="section-header fade-in delay-2">
            <h2><i class="fas fa-cubes" style="color: var(--neon-green);"></i> ${txt('أحدث الموديولات', 'Latest Modules')}</h2>
            <a href="#" onclick="loadPage('modules')" class="view-all-link">${txt('عرض الكل', 'View All')} <i class="fas fa-arrow-right"></i></a>
        </div>
        <div class="grid-3 fade-in delay-2">
            ${data.modules.slice(0, 3).map(renderModuleCard).join('')}
        </div>

        <!-- Networks Preview - REMOVED -->
    </div>
    `;
}
/* --- Modules Page (Pro) --- */
function pageModulesPro() {
    const data = getIntegratedLearnData();
    const modules = data.modules;

    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
            <div class="filter-bar" style="background: rgba(0,0,0,0.3); padding: 5px; border-radius: 30px; border: 1px solid rgba(255,255,255,0.1);">
                <button class="filter-btn active" style="background: var(--neon-blue); color: #000; border-radius: 20px; padding: 5px 20px; border: none; font-weight: bold;">ALL</button>
                <button class="filter-btn" style="background: transparent; color: #fff; padding: 5px 20px; border: none;">WEB</button>
                <button class="filter-btn" style="background: transparent; color: #fff; padding: 5px 20px; border: none;">NETWORK</button>
                <button class="filter-btn" style="background: transparent; color: #fff; padding: 5px 20px; border: none;">DEFENSE</button>
            </div>
        </div>

        <div class="learn-hero mb-5 fade-in delay-1" style="padding: 50px; border-radius: 24px; background: linear-gradient(135deg, rgba(168, 85, 247, 0.1) 0%, rgba(10, 10, 16, 0.8) 100%); border: 1px solid rgba(168, 85, 247, 0.2);">
            <div class="row align-items-center">
                <div class="col-lg-7">
                    <span class="cyber-badge mb-3 d-inline-block" style="border-color: #a855f7; color: #a855f7;"><i class="fas fa-cubes me-2"></i> TRAINING LIBRARY</span>
                    <h1 class="display-4 fw-bold text-white mb-4" style="text-shadow: 0 0 30px rgba(168, 85, 247, 0.3);">
                        ${txt('مكتبة الوحدات التدريبية', 'Module Library')}
                    </h1>
                    <p class="lead text-light opacity-75 mb-4" style="max-width: 600px; line-height: 1.8;">
                        ${txt('تصفح مئات الوحدات التدريبية المتخصصة في مختلف مجالات الأمن السيبراني. صقل مهاراتك وحدة تلو الأخرى.', 'Browse hundreds of specialized training modules across various cybersecurity domains. Hone your skills one unit at a time.')}
                    </p>
                    <div class="d-flex gap-3">
                         <div class="stat-pill" style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); padding: 10px 20px; border-radius: 12px; color: #fff;">
                            <span class="fw-bold" style="color: #a855f7;">${modules.length}</span> Modules
                        </div>
                        <div class="stat-pill" style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); padding: 10px 20px; border-radius: 12px; color: #fff;">
                            <span class="fw-bold" style="color: #a855f7;">New</span> Content Weekly
                        </div>
                    </div>
                </div>
                <div class="col-lg-5 text-center position-relative">
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 300px; height: 300px; background: #a855f7; filter: blur(100px); opacity: 0.2; border-radius: 50%;"></div>
                    <img src="assets/images/3d-icons/icon_modules_3d_1765922303520.png" alt="Modules" style="position: relative; width: 320px; animation: float 5s ease-in-out infinite; filter: drop-shadow(0 0 40px rgba(168, 85, 247, 0.4));">
                </div>
            </div>
        </div>

        <h3 class="section-title fade-in delay-2"><i class="fas fa-layer-group text-primary me-2"></i> ${txt('جميع الوحدات', 'All Modules')}</h3>
        
        <div class="grid-3 fade-in delay-3">
            ${modules.map(mod => renderModuleCardPro(mod)).join('')}
        </div>
        
        <div class="text-center mt-5 mb-5">
            <button class="cyber-btn btn-outline">
                ${txt('تحميل المزيد', 'Load More')}
            </button>
        </div>
    </div>
    `;
}

function pageLearningPathsV2() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="learn-hero mb-5 fade-in delay-1" style="padding: 50px; border-radius: 24px;">
            <div class="row align-items-center">
                <div class="col-lg-7">
                    <span class="cyber-badge text-warning border-warning mb-3 d-inline-block"><i class="fas fa-star me-2"></i> PREMIUM CURRICULUM</span>
                    <h1 class="display-4 fw-bold text-white mb-3" style="text-shadow: 0 0 30px rgba(0,243,255,0.3);">${txt('مسارات التعلم الاحترافية', 'Professional Learning Paths')}</h1>
                    <p class="fs-5 text-muted mb-4" style="line-height: 1.8;">${txt('اختر مسارك المهني وابدأ رحلة احتراف الأمن السيبراني مع محتوى مصمم بدقة من قبل خبراء الصناعة.', 'Choose your career path and start your cybersecurity mastery journey with accurately designed content by industry experts.')}</p>
                    
                    <div class="d-flex gap-3 mt-4">
                        <div class="d-flex align-items-center text-white-50"><i class="fas fa-check-circle text-success me-2"></i> ${txt('شهادات معتمدة', 'Certified')}</div>
                        <div class="d-flex align-items-center text-white-50"><i class="fas fa-check-circle text-success me-2"></i> ${txt('تدريب عملي 100%', '100% Hands-on')}</div>
                        <div class="d-flex align-items-center text-white-50"><i class="fas fa-check-circle text-success me-2"></i> ${txt('تحديث مستمر', 'Always Updated')}</div>
                    </div>
                </div>
                <div class="col-lg-5 text-center position-relative">
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 300px; height: 300px; background: var(--neon-blue); opacity: 0.15; filter: blur(100px); border-radius: 50%;"></div>
                    <img src="assets/images/3d-icons/icon_learning_path_3d_1765922272083.png" alt="Learning Paths" style="position: relative; width: 280px; filter: drop-shadow(0 0 40px rgba(0,0,0,0.5)); animation: float-pulse 5s infinite ease-in-out;">
                </div>
            </div>
            
            <!-- Filter Bar -->
            <div class="d-flex justify-content-between align-items-center mt-5 pt-4 border-top border-secondary" style="border-color: rgba(255,255,255,0.08)!important;">
                 <h4 class="text-white m-0"><i class="fas fa-layer-group me-2 text-primary"></i> ${txt('استكشف المسارات', 'Explore Paths')}</h4>
                 <div class="d-flex gap-3">
                    <div class="position-relative">
                        <i class="fas fa-search position-absolute text-muted" style="top: 12px; left: 15px;"></i>
                        <input type="text" id="path-search" onkeyup="filterPaths()" placeholder="${txt('بحث...', 'Search...')}" class="form-control cyber-input" style="width: 250px; padding-left: 40px !important;">
                    </div>
                    <select id="path-diff" onchange="filterPaths()" class="form-select cyber-input" style="width: 160px;">
                        <option value="All">${txt('الكل', 'All Levels')}</option>
                        <option value="Beginner">Beginner</option>
                        <option value="Intermediate">Intermediate</option>
                        <option value="Advanced">Advanced</option>
                    </select>
                </div>
            </div>
        </div>
        
        <div class="grid-3 fade-in delay-2" id="paths-grid">
            ${getIntegratedLearnData().paths.map(renderPathCard).join('')}
        </div>
    </div>
    `;
}

/* --- Modules Page --- */
function pageModules() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="d-flex justify-content-between align-items-end mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <div>
                <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-cubes text-success me-3"></i> ${txt('الموديولات', 'Modules')}</h2>
                <p class="text-muted fs-5 mb-0">${txt('تصفح مكتبة ضخمة من الدروس العملية', 'Browse a huge library of practical hands-on lessons')}</p>
            </div>
            <div class="d-flex gap-3">
                <input type="text" id="mod-search" onkeyup="filterModules()" placeholder="${txt('بحث...', 'Search...')}" class="form-control cyber-input" style="width: 300px;">
                <select id="mod-diff" onchange="filterModules()" class="form-select cyber-input" style="width: 180px;">
                    <option value="All">${txt('All Difficulties', 'All Difficulties')}</option>
                    <option value="Easy">Easy</option>
                    <option value="Medium">Medium</option>
                    <option value="Hard">Hard</option>
                </select>
            </div>
        </div>
        
        <div class="grid-3 fade-in delay-2" id="modules-grid">
            ${getIntegratedLearnData().modules.map(renderModuleCard).join('')}
        </div>
    </div>
    `;
}

/* --- Walkthroughs Page --- */
function pageWalkthroughs() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="d-flex flex-wrap justify-content-between align-items-end mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <div>
                <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-play text-primary me-3"></i> ${txt('الشروحات', 'Walkthroughs')}</h2>
                <p class="text-muted fs-5 mb-0">${txt('شروحات مفصلة لحل التحديات والآلات', 'Detailed walkthroughs for CTFs and Machines')}</p>
            </div>
            <div class="d-flex gap-3 flex-wrap">
                <input type="text" id="wt-search" onkeyup="filterWalkthroughs()" placeholder="${txt('بحث...', 'Search...')}" class="form-control cyber-input" style="width: 250px;">
                <select id="wt-diff" onchange="filterWalkthroughs()" class="form-select cyber-input" style="width: 150px;">
                    <option value="All">${txt('Difficulty', 'Difficulty')}</option>
                    <option value="Easy">Easy</option>
                    <option value="Medium">Medium</option>
                    <option value="Hard">Hard</option>
                </select>
            </div>
        </div>

        <div class="grid-3 fade-in delay-2" id="walkthroughs-grid">
            ${getIntegratedLearnData().walkthroughs.map(renderWalkthroughCard).join('')}
        </div>
    </div>
    `;
}

/* --- Networks Page --- */
function pageNetworks() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-network-wired text-info me-3"></i> ${txt('الشبكات', 'Networks')}</h2>
            <p class="text-muted fs-5">${txt('بيئات شبكية كاملة ومجهزة للاختراق المتقدم', 'Full network environments ready for advanced exploitation')}</p>
        </div>

        <div class="grid-3 fade-in delay-2">
            ${getIntegratedLearnData().networks.map(renderNetworkCard).join('')}
        </div>
    </div>
    `;
}

/* --- Path Viewer (Detail Page) --- */
window.pagePathViewer = function (pathId) {
    if (pathId && pathId.startsWith('unit-viewer:')) {
        pathId = pathId.split(':')[1];
    }

    const data = getIntegratedLearnData();
    const path = data.paths.find(p => p.id === pathId);

    // Fetch original object to get 'units'
    let units = [];
    if (window.UnifiedLearningData && window.UnifiedLearningData.paths) {
        const originalPath = window.UnifiedLearningData.paths.find(p => p.id === pathId);
        if (originalPath && originalPath.units) {
            units = originalPath.units;
        }
    }

    if (!path) return `<div class="learn-container text-center pt-5"><h2>${txt('المسار غير موجود', 'Path not found')}</h2><button onclick="loadPage('learningpaths')" class="cyber-btn mt-3">Back</button></div>`;

    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-4 fade-in">
            <button onclick="loadPage('learningpaths')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-left ms-2"></i> ${txt('كل المسارات', 'All Paths')}
            </button>
        </div>

        <!-- Path Hero -->
        <div class="row align-items-center mb-5 fade-in delay-1">
            <div class="col-lg-8">
                <span class="cyber-badge mb-3 d-inline-block" style="border-color: ${path.color}">${path.type}</span>
                <h1 class="display-3 fw-bold text-white mb-3">${path.title}</h1>
                <p class="fs-5 text-muted mb-4">${path.description || 'Master this domain with our comprehensive curriculum.'}</p>
                
                <div class="d-flex gap-4 mb-4 text-white-50">
                    <div><i class="fas fa-bolt text-warning me-2"></i> ${path.difficulty}</div>
                    <div><i class="fas fa-clock text-info me-2"></i> ${path.estimatedHours || path.hours || 0} hrs</div>
                    <div><i class="fas fa-trophy text-success me-2"></i> ${path.xp} XP</div>
                </div>

                <div class="cyber-progress-container mb-2" style="max-width: 500px;">
                     <div class="cyber-progress-bar" style="width: 0%;"></div>
                </div>
                <small class="text-muted">0% Complete</small>
            </div>
            <div class="col-lg-4 text-center">
                 <div class="card-icon-3d" style="font-size: 8rem; color: ${path.color};">
                    <i class="fas ${path.icon.replace('assets/images/3d-icons/', '').includes('/') ? 'fa-map' : path.icon.replace('fa-', 'fa-')}"></i>
                 </div>
            </div>
        </div>

        <!-- Syllabus -->
        <div class="section-header fade-in delay-2">
            <h2><i class="fas fa-list-check" style="color: var(--neon-blue);"></i> ${txt('المنهج الدراسي', 'Syllabus')}</h2>
        </div>

        <div class="d-flex flex-column gap-4 fade-in delay-2" style="max-width: 1000px;">
            ${units.length > 0 ? units.map((unit, uIndex) => `
            <div class="cyber-unit-block">
                <h3 class="text-white mb-3" style="border-left: 4px solid var(--neon-purple); padding-left: 15px;">
                    <span class="text-muted fs-6 d-block mb-1">UNIT ${uIndex + 1}</span>
                    ${unit.name}
                </h3>
                
                <div class="d-flex flex-column gap-2">
                    ${unit.rooms ? unit.rooms.map((room, rIndex) => `
                    <div class="cyber-card p-3 d-flex align-items-center" style="min-height: auto; cursor: pointer; border-left: 0; border-right:0; border-top:0; border-radius: 8px; background: rgba(255,255,255,0.02);" onclick="loadPage('room-viewer:${room.id}')">
                        <div class="me-3 text-muted">${uIndex + 1}.${rIndex + 1}</div>
                        <div class="flex-grow-1">
                            <h5 class="mb-0 text-white" style="font-size: 1rem;">${room.title}</h5>
                        </div>
                        <div class="text-end">
                            <span class="cyber-badge bg-transparent" style="border: 1px solid rgba(255,255,255,0.1); font-size: 0.7rem;">${room.type || 'Task'}</span>
                            <span class="cyber-badge bg-transparent text-warning border-0"><i class="fas fa-bolt"></i> ${room.difficulty}</span>
                        </div>
                         <div class="ms-3">
                             <i class="fas fa-chevron-right text-muted"></i>
                        </div>
                    </div>
                    `).join('') : '<div class="text-muted mp-3">No content in this unit.</div>'}
                </div>
            </div>
            `).join('') : '<div class="text-center p-5 text-muted">No syllabus content available.</div>'}
        </div>

    </div>
    `;
}



/* --- Enhanced Module Viewer --- */
window.pageEnhancedModuleViewer = function (moduleId) {
    if (moduleId && moduleId.startsWith('cyber-module:')) {
        moduleId = moduleId.split(':')[1];
    }

    const data = getIntegratedLearnData();
    const mod = data.modules.find(m => m.id === moduleId);

    if (!mod) return `<div class="learn-container text-center pt-5"><h2>${txt('الموديول غير موجود', 'Module not found')}</h2><button onclick="loadPage('modules')" class="cyber-btn mt-3">Back</button></div>`;

    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-4 fade-in">
            <button onclick="loadPage('modules')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-left ms-2"></i> ${txt('كل الموديولات', 'All Modules')}
            </button>
        </div>

        <!-- Module Hero -->
        <div class="row align-items-center mb-5 fade-in delay-1">
            <div class="col-lg-8">
                <span class="cyber-badge mb-3 d-inline-block" style="border-color: ${mod.color || '#00f3ff'}">MODULE</span>
                <h1 class="display-3 fw-bold text-white mb-3">${mod.title}</h1>
                <p class="fs-5 text-muted mb-4">${mod.description || mod.category || 'Advance your skills with this hands-on module.'}</p>
                
                <div class="d-flex gap-4 mb-4 text-white-50">
                    <div><i class="fas fa-bolt text-warning me-2"></i> ${mod.difficulty}</div>
                    <div><i class="fas fa-flag text-danger me-2"></i> ${mod.flags || 2} Flags</div>
                    <div><i class="fas fa-trophy text-success me-2"></i> ${mod.xp || 100} XP</div>
                </div>
                
                <button onclick="loadPage('room-viewer:${mod.rooms && mod.rooms[0] ? mod.rooms[0].id : ''}')" class="cyber-btn pulse-btn">
                    <i class="fas fa-play"></i> ${txt('ابدأ الآن', 'Start Now')}
                </button>
            </div>
            <div class="col-lg-4 text-center">
                 <div class="card-icon-3d" style="font-size: 8rem; color: ${mod.color || '#00f3ff'};">
                    <i class="fas ${mod.icon.replace('assets/images/3d-icons/', '').includes('/') ? 'fa-cube' : mod.icon.replace('fa-', 'fa-')}"></i>
                 </div>
            </div>
        </div>

        <!-- Module Content (Rooms) -->
        <div class="section-header fade-in delay-2">
            <h2><i class="fas fa-tasks" style="color: var(--neon-green);"></i> ${txt('المهام', 'Tasks & Labs')}</h2>
        </div>

        <div class="d-flex flex-column gap-3 fade-in delay-2" style="max-width: 800px;">
            ${mod.rooms ? mod.rooms.map((room, index) => `
            <div class="cyber-card p-3 d-flex align-items-center" onclick="loadPage('room-viewer:${room.id}')" style="min-height: auto; cursor: pointer;">
                <div class="me-4 text-center">
                    <div class="cyber-badge border-0 bg-dark">${index + 1}</div>
                </div>
                <div class="flex-grow-1">
                    <h4 class="mb-1 text-white">${room.title}</h4>
                    <span class="badge bg-dark border border-secondary">${room.type}</span>
                </div>
                <div class="ms-3">
                     <i class="fas fa-chevron-right text-muted"></i>
                </div>
            </div>
            `).join('') : '<div class="text-muted">No rooms available.</div>'}
        </div>

    </div>
    `;
}

/* --- Open Module Details Helper --- */
window.openModuleDetails = function (moduleId) {
    loadPage('cyber-module:' + moduleId);
}

/* --- Filter Logic --- */
window.filterPaths = function () {
    const searchEl = document.getElementById('path-search');
    const diffEl = document.getElementById('path-diff');
    if (!searchEl || !diffEl) return;

    const search = searchEl.value.toLowerCase();
    const diff = diffEl.value;
    const data = getIntegratedLearnData().paths;

    const filtered = data.filter(p => {
        const matchSearch = p.title.toLowerCase().includes(search);
        const matchDiff = diff === 'All' || p.difficulty === diff;
        return matchSearch && matchDiff;
    });

    const grid = document.getElementById('paths-grid');
    if (grid) grid.innerHTML = filtered.length > 0 ? filtered.map(renderPathCard).join('') : `<div class="col-12 text-center text-muted p-5"><h4>${txt('لا توجد نتائج', 'No results found')}</h4></div>`;
}

window.filterModules = function () {
    const searchEl = document.getElementById('mod-search');
    const diffEl = document.getElementById('mod-diff');
    if (!searchEl || !diffEl) return;

    const search = searchEl.value.toLowerCase();
    const diff = diffEl.value;
    const data = getIntegratedLearnData().modules;

    const filtered = data.filter(m => {
        const matchSearch = m.title.toLowerCase().includes(search);
        const matchDiff = diff === 'All' || m.difficulty === diff;
        return matchSearch && matchDiff;
    });

    const grid = document.getElementById('modules-grid');
    if (grid) grid.innerHTML = filtered.length > 0 ? filtered.map(renderModuleCard).join('') : `<div class="col-12 text-center text-muted p-5"><h4>${txt('لا توجد نتائج', 'No results found')}</h4></div>`;
}

window.filterWalkthroughs = function () {
    const searchEl = document.getElementById('wt-search');
    const diffEl = document.getElementById('wt-diff');
    if (!searchEl) return;

    const search = searchEl.value.toLowerCase();
    const diff = diffEl.value;
    const data = getIntegratedLearnData().walkthroughs;

    const filtered = data.filter(w => {
        const matchSearch = w.title.toLowerCase().includes(search);
        const matchDiff = diff === 'All' || w.difficulty === diff;
        return matchSearch && matchDiff;
    });

    const grid = document.getElementById('walkthroughs-grid');
    if (grid) grid.innerHTML = filtered.length > 0 ? filtered.map(renderWalkthroughCard).join('') : `<div class="col-12 text-center text-muted p-5"><h4>${txt('لا توجد نتائج', 'No results found')}</h4></div>`;
}

/* --- Helper: Get 3D Icon for Category/Title --- */
function getSmartIcon3D(type, title) {
    const t = (title || '').toLowerCase();
    const basePath = 'assets/images/3d-icons/';

    // --- 0. Specific Path Matches (User Requested) ---
    if (t.includes('cyber security 101') || t.includes('intro')) return basePath + 'icon_cybersec_101_3d_1765924747485.png';
    if (t.includes('web fundamentals')) return basePath + 'icon_web_fund_3d_1765924768472.png';
    if (t.includes('linux fundamentals')) return basePath + 'icon_linux_fund_3d_1765924787847.png';
    if (t.includes('network fundamentals')) return basePath + 'icon_network_fund_3d_1765924824670.png';
    if (t.includes('soc level 1')) return basePath + 'icon_soc_level1_3d_1765924843102.png';
    if (t.includes('web application pentesting')) return basePath + 'icon_web_pentest_3d_1765924859618.png';
    if (t.includes('jr penetration tester') || t.includes('junior')) return basePath + 'icon_jr_pentester_3d_1765924888421.png';
    if (t.includes('offensive pentesting')) return basePath + 'icon_offensive_pentest_3d_1765924906299.png';
    if (t.includes('red teaming')) return basePath + 'icon_red_teaming_generated_3d.png';
    if (t.includes('exploit development')) return basePath + 'icon_exploit_dev_generated_3d.png';

    // --- 1. Keyword Matching (Prioritized) ---
    /* Foundations & Pre-Sec */
    if (t.includes('pre security')) return basePath + 'icon_presec_3d_1765922821198.png';

    /* Core Domains */
    if (t.includes('web')) return basePath + 'icon_web_3d_1765817117593.png';
    if (t.includes('linux')) return basePath + 'icon_linux_3d_1765817009790.png';
    if (t.includes('network')) return basePath + 'icon_network_3d_1765817211308.png';
    if (t.includes('cloud')) return basePath + 'icon_cloud_sec_3d_1765922640275.png';
    if (t.includes('mobile') || t.includes('android') || t.includes('ios')) return basePath + 'icon_mobile_sec_3d_1765922679704.png';
    if (t.includes('iot') || t.includes('hardware') || t.includes('firmware')) return basePath + 'icon_iot_3d_1765922711003.png';

    /* Engineer & Architect */
    if (t.includes('engineer') || t.includes('architecture')) return basePath + 'icon_sec_eng_3d_1765923606392.png';

    /* Blue Team / SOC */
    if (t.includes('soc level 2') || t.includes('threat hunting') || t.includes('hunting')) return basePath + 'icon_hunt_3d_1765818898436.png';
    if (t.includes('soc') || t.includes('siem') || t.includes('splunk') || t.includes('log')) return basePath + 'icon_siem_3d_1765818657470.png';
    if (t.includes('incident') || t.includes('response')) return basePath + 'icon_ir_3d_1765818771664.png';
    if (t.includes('forensics') || t.includes('disk') || t.includes('memory')) return basePath + 'icon_forensics_3d_1765922362347.png';
    if (t.includes('grc') || t.includes('audit') || t.includes('compliance')) return basePath + 'icon_grc_3d_1765922791960.png';
    if (t.includes('blue') || t.includes('defens')) return basePath + 'icon_security_3d_1765817313667.png';
    if (t.includes('honeynet') || t.includes('honey')) return basePath + 'icon_honeynet_3d_1765818484701.png';

    /* Red Team / Offensive */
    if (t.includes('hacker') || t.includes('pentest')) return basePath + 'icon_access_3d_1765819070867.png';
    if (t.includes('offensive') || t.includes('red team') || t.includes('adversary')) return basePath + 'icon_c2_3d_1765819311043.png';
    if (t.includes('exploitation') || t.includes('exploit') || t.includes('buffer') || t.includes('development')) return basePath + 'icon_exploit_dev_3d_1765819716830.png';
    if (t.includes('metasploit') || t.includes('framework')) return basePath + 'icon_frameworks_3d_1765818576549.png';
    if (t.includes('evasion') || t.includes('bypass') || t.includes('amsi')) return basePath + 'icon_evasion_3d_1765819229136.png';
    if (t.includes('privilege') || t.includes('persistence') || t.includes('post')) return basePath + 'icon_post_3d_1765819141827.png';
    if (t.includes('phishing') || t.includes('osint') || t.includes('recon')) return basePath + 'icon_osint_3d_1765819003909.png';
    if (t.includes('malware') || t.includes('virus')) return basePath + 'icon_malware_3d_1765923577789.png';
    if (t.includes('bug bounty')) return basePath + 'icon_bug_bounty_3d_1765819664727.png';
    if (t.includes('crypto')) return basePath + 'icon_crypto_3d_1765922333633.png';

    /* DevOps */
    if (t.includes('devsecops') || t.includes('container') || t.includes('docker')) return basePath + 'icon_devsecops_3d_1765922752494.png';

    /* --- 2. Fallbacks based on Type --- */
    if (type === 'path') {
        return basePath + 'icon_learning_path_3d_1765922272083.png';
    }

    // Default Module
    return basePath + 'icon_modules_3d_1765922303520.png';
}

/* --- Theme Helper (Enhanced) --- */
function getPathTheme(title) {
    const t = (title || '').toLowerCase();

    // Red Team / Offensive (Red)
    if (t.includes('red') || t.includes('offensive') || t.includes('penetration') || t.includes('pentest') || t.includes('exploit') ||
        t.includes('سبر') || t.includes('هجوم') || t.includes('احمر') || t.includes('أحمر') || t.includes('اختراق')) {
        return 'theme-red';
    }

    // Blue Team / Defensive (Blue)
    if (t.includes('blue') || t.includes('defens') || t.includes('soc') || t.includes('threat') || t.includes('hunting') || t.includes('response') ||
        t.includes('أزرق') || t.includes('ازرق') || t.includes('دفاع') || t.includes('استجابة') || t.includes('تحقيق')) {
        return 'theme-blue';
    }

    // Web / App Sec (Orange)
    if (t.includes('web') || t.includes('bug') || t.includes('mobile') || t.includes('app') ||
        t.includes('ويب') || t.includes('تطبيقات') || t.includes('ثغرات')) {
        return 'theme-orange';
    }

    // Fundamentals / Pre-Security (Green)
    if (t.includes('intro') || t.includes('fundamental') || t.includes('pre') || t.includes('linux') || t.includes('network') ||
        t.includes('مقدمة') || t.includes('أساسيات') || t.includes('اساسيات') || t.includes('شبكات')) {
        return 'theme-green';
    }

    // Default / Advanced (Purple)
    return 'theme-purple';
}







/* --- Module Theme Helper --- */
function getModuleTheme(title) {
    // Reuse logic from Paths for consistency, but maintain separation for future flexibility
    return getPathTheme(title);
}

function renderPathCard(path) {
    const iconSrc = getSmartIcon(path.title, 'path');

    // Determine Theme based on content keywords
    let theme = 'theme-blue';
    if (path.title.includes('Pre') || path.title.includes('Intro')) theme = 'theme-green';
    else if (path.title.includes('Web') || path.title.includes('Bounty')) theme = 'theme-blue';
    else if (path.title.includes('Red') || path.title.includes('Offensive') || path.title.includes('Pentesting')) theme = 'theme-red';
    else if (path.title.includes('SOC') || path.title.includes('Blue')) theme = 'theme-purple';
    else if (path.title.includes('Forensics')) theme = 'theme-orange';

    const isPro = path.status === 'Pro' || path.status === 'VIP';
    let progress = Math.floor(Math.random() * 30);

    return `
    <div class="path-card-v4 ${theme}" onclick="loadPage('path-viewer:${path.id}')" onmousemove="updateCardEffect(event, this)">
        <div class="v4-top-bar">
            <span class="v4-badge ${isPro ? 'pro' : ''}">${isPro ? 'PRO' : 'FREE'}</span>
            <div class="v4-users"><i class="fas fa-users"></i> ${(Math.random() * 5 + 1).toFixed(1)}k</div>
        </div>

        <div class="v4-body">
            <div class="v4-icon-container">
                <img src="${iconSrc}" class="v4-icon-img" alt="${path.title}" onerror="this.src='assets/images/3d-icons/icon_security_3d_1765817313667.png'">
            </div>
            
            <h3 class="v4-title">${path.title}</h3>
            <p class="v4-desc">${path.description ? path.description.substring(0, 60) + '...' : 'Start learning now.'}</p>
            
            <div class="v4-stats-row">
                <span class="v4-stat"><i class="fas fa-layer-group"></i> ${path.difficulty}</span>
                <span class="v4-stat"><i class="fas fa-clock"></i> ${path.hours || 40}h</span>
                <span class="v4-stat"><i class="fas fa-flask"></i> ${path.rooms || 12} Labs</span>
            </div>
        </div>
        
        <div class="v4-footer">
            <div class="v4-progress-wrap">
                <div class="v4-prog-label"><span>Progress</span> <span>${progress}%</span></div>
                <div class="v4-prog-track"><div class="v4-prog-fill" style="width: ${progress}%;"></div></div>
            </div>
            <div class="v4-btn"><i class="fas fa-arrow-right"></i></div>
        </div>
    </div>
    `;
}

function renderModuleCardPro(module) {
    const iconSrc = getSmartIcon(module.title, 'module');
    const themeClass = getModuleTheme(module.title);
    // Use module.xp or estimate points based on difficulty if not available
    const points = module.xp || (module.difficulty === 'Easy' ? 100 : module.difficulty === 'Medium' ? 250 : 500);

    return `
    <div class="path-card-pro ${themeClass}" onclick="loadPage('module-viewer:global/${module.id}')" onmousemove="updateCardEffect(event, this)">
        <div class="path-card-header">
            <span class="path-badge free">
                <i class="fas fa-cube me-1"></i> MODULE
            </span>
             <span class="path-badge" style="background: rgba(255,255,255,0.05); color: #94a3b8;">
                ${module.difficulty}
            </span>
        </div>
        
        <div class="path-card-body">
            <div class="path-icon-wrapper">
                <div style="position: absolute; width: 80px; height: 80px; background: var(--neon-blue); filter: blur(40px); opacity: 0.2; border-radius: 50%;"></div>
                <img src="${iconSrc}" class="path-icon-img" style="width: 70px; height: 70px;" alt="${module.title}">
            </div>
            
            <h3 class="path-title" style="font-size: 1.1rem;">${module.title}</h3>
            <p class="path-desc" style="font-size: 0.85rem;">${module.description ? module.description.substring(0, 70) + '...' : 'Enhance your skills with this specialized module.'}</p>
            
            <div class="path-stats-grid" style="grid-template-columns: 1fr 1fr;">
                 <div class="p-stat">
                    <span class="p-stat-val text-white" style="text-shadow: 0 0 10px var(--glow-color);">${points}</span>
                    <span class="p-stat-label">XP Points</span>
                </div>
                 <div class="p-stat">
                    <span class="p-stat-val text-white">${module.team || 'General'}</span>
                    <span class="p-stat-label">Category</span>
                </div>
            </div>
        </div>
        
        <div class="path-card-footer">
            <div style="width: 100%; display: flex; justify-content: space-between; align-items: center;">
                 <span style="font-size: 0.8rem; color: var(--neon-blue); letter-spacing: 1px;">START MODULE</span>
                 <div class="btn-path-action" style="width: 32px; height: 32px;">
                    <i class="fas fa-play" style="font-size: 0.8rem;"></i>
                </div>
            </div>
        </div>
    </div>`;
}


function renderModuleCard(mod) {
    const iconSrc = getSmartIcon(mod.title, 'module');

    // Determine gradient based on difficulty if not explicit
    let glowColor = mod.color;
    if (!glowColor) {
        switch (mod.difficulty) {
            case 'easy': glowColor = 'var(--neon-green)'; break;
            case 'medium': glowColor = '#ffb300'; break;
            case 'hard': glowColor = '#ff003c'; break;
            case 'insane': glowColor = 'var(--neon-purple)'; break;
            default: glowColor = 'var(--neon-blue)';
        }
    }

    const xpPoints = mod.xp || (mod.flags ? mod.flags * 50 : 100);

    return `
    <div class="module-card" onclick="openModuleDetails('${mod.id}')" style="--card-glow: ${glowColor}">
        <div class="module-icon-wrapper">
             <div class="module-icon-glow"></div>
             <img src="${iconSrc}" class="module-icon-img" alt="${mod.title}">
        </div>
        
        <div class="module-content">
            <div class="module-header">
                <span class="difficulty-badge ${mod.difficulty}">${txt(mod.difficulty, mod.difficulty)}</span>
                ${mod.flags ? `<span class="flags-badge"><i class="fas fa-flag"></i> ${mod.flags}</span>` : ''}
            </div>
            
            <h3>${mod.title}</h3>
            <p>${mod.description ? mod.description.substring(0, 80) + '...' : txt('انقر للتفاصيل', 'Click for details')}</p>
            
            <div class="module-footer">
                <div class="xp-tag"><i class="fas fa-bolt"></i> ${xpPoints} XP</div>
                <div class="arrow-icon"><i class="fas fa-arrow-right"></i></div>
            </div>
        </div>
    </div>
    `;
}

function renderWalkthroughCard(wt) {
    const isImg = wt.icon.includes('/');
    const iconHtml = isImg
        ? `<img src="${wt.icon}" class="card-icon-img" alt="${wt.title}" style="width:100px; height:100px;">`
        : `<div class="card-icon-3d" style="color: ${wt.color}; font-size: 2.5rem;"><i class="fas ${wt.icon}"></i></div>`;

    return `
    <div class="cyber-card">
        <div class="d-flex justify-content-between align-items-start mb-4">
            ${iconHtml}
            <span class="cyber-badge">${wt.status}</span>
        </div>
        <h3>${wt.title}</h3>
        <div class="d-flex gap-2 mb-3">
             <span class="cyber-badge" style="color: #fff; border-color: ${wt.color}">${wt.type}</span>
             <span class="cyber-badge">${wt.difficulty}</span>
        </div>
        <button class="cyber-btn mt-3 w-100 justify-content-center" style="font-size: 0.9rem; padding: 10px;" onclick="viewSolution('${wt.id}')">${txt('مشاهدة الحل', 'View Solution')}</button>
    </div>
    `;
}

function renderNetworkCard(net) {
    const iconPath = 'assets/images/3d-icons/icon_network_3d_1765817211308.png';
    return `
    <div class="cyber-card" style="border-top: 2px solid ${net.color};">
        <div class="d-flex justify-content-center mb-4">
             <img src="${iconPath}" class="card-icon-img" alt="${net.title}">
        </div>
        <h3>${net.title}</h3>
        <p class="mb-3 text-white"><span class="fw-bold fs-5" style="color: ${net.color}">${net.servers}</span> Servers Available</p>
        <div class="d-flex gap-2 mb-4">
            <span class="cyber-badge bg-danger text-white border-0">${net.difficulty}</span>
            <span class="cyber-badge bg-warning text-dark border-0">${net.status}</span>
        </div>
        <button id="btn-start-${net.id}" class="cyber-btn w-100 justify-content-center" style="border-color: ${net.color};" onclick="startLabNetwork('${net.id}')">${txt('ابدأ الشبكة', 'Start Network')}</button>
    </div>
    `;
}

// ==========================================================================
// MODULE INTERACTIONS (Start Network / View Solution / Details)
// ==========================================================================

window.startLabNetwork = async function (moduleId) {
    const btn = document.getElementById(`btn-start-${moduleId}`);
    if (btn && btn.disabled) return;

    let originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Spawning...';
        btn.disabled = true;
    }

    try {
        let module = null;
        if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
            module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
        }
        const machineId = module ? (module.machineId || module.id) : moduleId;

        console.log(`Starting Lab: ${machineId} (Module: ${moduleId})`);
        const response = await fetch('http://localhost:5000/api/labs/spawn', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: 1, lab_id: machineId })
        });
        const data = await response.json();

        if (data.success) {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check"></i> Running';
                btn.classList.add('btn-success');
            }
            let msg = `Network Started!\n\nTarget IP: ${data.container_ip || '127.0.0.1'}\nMachine: ${data.lab_name}`;
            if (data.container_port && data.container_port != 80) msg += `\nPort: ${data.container_port}`;
            setTimeout(() => {
                alert(msg);
                setTimeout(() => {
                    if (btn) {
                        btn.innerHTML = '<i class="fas fa-network-wired"></i> Restart Network';
                        btn.disabled = false;
                        btn.classList.remove('btn-success');
                    }
                }, 10000);
            }, 500);
        } else {
            throw new Error(data.error || "Failed to spawn lab");
        }
    } catch (error) {
        console.error("Lab Spawn Error:", error);
        if (btn) {
            btn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error';
            btn.classList.add('btn-danger');
        }
        alert(`Failed to start network: ${error.message}`);
        setTimeout(() => {
            if (btn) {
                btn.innerHTML = originalText;
                btn.disabled = false;
                btn.classList.remove('btn-danger');
            }
        }, 3000);
    }
};

window.viewSolution = function (moduleId) {
    let module = null;
    if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
        module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
    }
    if (!module && window.ctfRooms) {
        for (const cat of Object.keys(window.ctfRooms)) {
            const found = window.ctfRooms[cat].find(r => r.id === moduleId);
            if (found) {
                module = found;
                if (!module.title && module.title) module.title = module.title.en;
                break;
            }
        }
    }
    if (!module) {
        module = { title: 'Walkthrough Solution', rooms: [{ title: 'Task 1', content: 'Follow the instructions in the room PDF.' }, { title: 'Flag', content: 'The flag is located in /root/flag.txt' }] };
    }

    let solutionHtml = '';
    if (module.rooms && module.rooms.length > 0) {
        solutionHtml += '<div class="solution-steps">';
        module.rooms.forEach((room, index) => {
            solutionHtml += `
                <div class="solution-step mb-4">
                    <h5 class="text-cyber-blue" style="border-bottom: 1px solid rgba(0,243,255,0.2); padding-bottom: 5px;">Step ${index + 1}: ${room.title}</h5>
                    <div class="p-3 border border-dark rounded bg-dark-glass" style="background: rgba(0,0,0,0.3);">
                        <p class="mb-2 text-white">${room.content || (room.description || 'Complete the task objectives.')}</p>
                        ${room.tasks ? room.tasks.map(t => `<div class="text-muted"><i class="fas fa-check-circle text-success me-2"></i>${t.title}</div>`).join('') : ''}
                    </div>
                </div>
            `;
        });
        solutionHtml += '</div>';
    } else if (module.tasks && module.tasks.length > 0) {
        solutionHtml += '<div class="solution-steps">';
        module.tasks.forEach((task, index) => {
            solutionHtml += `
                <div class="solution-step mb-4">
                    <h5 class="text-cyber-blue" style="border-bottom: 1px solid rgba(0,243,255,0.2); padding-bottom: 5px;">Task ${index + 1}: ${task.title}</h5>
                    <div class="p-3 border border-dark rounded bg-dark-glass" style="background: rgba(0,0,0,0.3);">
                        <p class="mb-2 text-white">${task.content || 'Solve this challenge.'}</p>
                        ${task.question ? `<div class="text-info mt-2"><i class="fas fa-question-circle me-2"></i>${task.question}</div>` : ''}
                        ${task.answer ? `<div class="text-success mt-2 font-monospace"><i class="fas fa-key me-2"></i>${task.answer}</div>` : ''}
                    </div>
                </div>
            `;
        });
        solutionHtml += '</div>';
    } else {
        solutionHtml = `<div class="text-center p-4"><p class="text-muted">No specific solution steps available.</p>${module.description ? `<p>${module.description}</p>` : ''}</div>`;
    }

    const existingModal = document.getElementById('solution-modal');
    if (existingModal) existingModal.remove();

    const modalHtml = `
        <div class="modal fade" id="solution-modal" tabindex="-1" aria-hidden="true" style="z-index: 10000;">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content bg-cyber-dark text-white border-0" style="background: #0f172a; border: 1px solid var(--neon-blue) !important; box-shadow: 0 0 40px rgba(0, 243, 255, 0.2);">
                    <div class="modal-header border-bottom border-dark" style="border-color: rgba(255,255,255,0.1) !important;">
                        <h5 class="modal-title font-monospace text-cyber-primary" style="color: var(--neon-blue);"><i class="fas fa-unlock-alt me-2"></i>SOLUTION :: ${module.title || 'Unknown'}</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close" style="filter: invert(1);"></button>
                    </div>
                    <div class="modal-body custom-scrollbar" style="max-height: 70vh; overflow-y: auto; padding: 2rem;">${solutionHtml}</div>
                    <div class="modal-footer border-top border-dark" style="border-color: rgba(255,255,255,0.1) !important;">
                        <button type="button" class="cyber-btn" data-bs-dismiss="modal" style="padding: 8px 20px;">Close Terminal</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    try {
        const modalEl = document.getElementById('solution-modal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    } catch (e) {
        console.error("Bootstrap Modal Error:", e);
        $('#solution-modal').modal('show');
    }
};

window.openModuleDetails = function (moduleId) {
    let module = null;
    if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
        module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
    }
    if (!module && window.ctfRooms) {
        for (const cat of Object.keys(window.ctfRooms)) {
            const found = window.ctfRooms[cat].find(r => r.id === moduleId);
            if (found) { module = found; break; }
        }
    }
    if (!module) return;

    const container = document.querySelector('.learn-container');
    if (!container) return;

    const iconHtml = (module.icon && module.icon.includes('/'))
        ? `<img src="${module.icon}" class="sidebar-icon-img" alt="${module.title}">`
        : `<i class="${module.icon} fa-3x text-cyber-primary"></i>`;

    const initialContent = `
        <div class="p-5 text-center">
            <div class="mb-4">${iconHtml}</div>
            <h1 class="text-white mb-3 fw-bold">${module.title || module.name}</h1>
            <p class="text-muted fs-5 mb-5" style="max-width: 600px; margin: 0 auto;">${module.description || 'Welcome to this module. Select a unit from the left to begin.'}</p>
        </div>
    `;

    // A simpler logic for details would be loading the RoomViewer if it's a single room module.
    // For now, retaining the previous "Unit Viewer" concept is out of scope for this specific file unless defined elsewhere.
    // We'll just alert for now or try to load a unit viewer.
    // Use `loadPage('unit-viewer:...')` if applicable.

    // For "Modules" in UnifiedData, they have "rooms".
    // We can show a modal with the rooms list to jump into.

    // Quick implementation of a specific module view:
    // Re-rendering the pageLearn as a "Module View"

    alert("Opening module details: " + module.title);
};


function getSmartIcon(title, type = '') {
    const t = title.toLowerCase() + ' ' + type.toLowerCase();
    const p = 'assets/images/3d-icons/';

    // --- Blue Team ---
    if (t.includes('honey')) return p + 'icon_honeynet_3d_1765818484701.png';
    if (t.includes('framework') || t.includes('mitre') || t.includes('diamond')) return p + 'icon_frameworks_3d_1765818576549.png';
    if (t.includes('siem') || t.includes('splunk') || t.includes('log')) return p + 'icon_siem_3d_1765818657470.png';
    if (t.includes('incident') || t.includes('response') || t.includes('ir ') || t.includes('triage')) return p + 'icon_ir_3d_1765818771664.png';
    if (t.includes('hunt') || t.includes('threat')) return p + 'icon_hunt_3d_1765818898436.png';

    // --- Red Team ---
    if (t.includes('osint') || t.includes('recon') || t.includes('google')) return p + 'icon_osint_3d_1765819003909.png';
    if (t.includes('phishing') || t.includes('access') || t.includes('initial')) return p + 'icon_access_3d_1765819070867.png';
    if (t.includes('post') || t.includes('persistence') || t.includes('credential')) return p + 'icon_post_3d_1765819141827.png';
    if (t.includes('evasion') || t.includes('obfuscation') || t.includes('bypass') || t.includes('amsi')) return p + 'icon_evasion_3d_1765819229136.png';
    if (t.includes('c2') || t.includes('command') || t.includes('sliver')) return p + 'icon_c2_3d_1765819311043.png';

    // --- Specialist ---
    if (t.includes('script') || t.includes('python') || t.includes('bash')) return p + 'icon_scripting_3d_1765819420953.png';
    if (t.includes('traffic') || t.includes('wireshark') || t.includes('packet') || t.includes('network')) return p + 'icon_traffic_3d_1765819502216.png';
    if (t.includes('forest') || t.includes('active directory') || t.includes('ad ')) return p + 'icon_ad_forest_3d_1765819581743.png';
    if (t.includes('bounty') || t.includes('bug')) return p + 'icon_bug_bounty_3d_1765819664727.png';
    if (t.includes('exploit') || t.includes('overflow') || t.includes('kernel')) return p + 'icon_exploit_dev_3d_1765819716830.png';

    // --- Fallbacks ---
    if (t.includes('linux')) return p + 'icon_linux_3d_1765817009790.png';
    if (t.includes('web')) return p + 'icon_web_3d_1765817117593.png';
    if (t.includes('security') || t.includes('secure')) return p + 'icon_security_3d_1765817313667.png';

    return p + 'icon_security_3d_1765817313667.png';
}

function getIconForCategory(cat) {
    const map = { web: 'fa-globe', crypto: 'fa-key', forensics: 'fa-magnifying-glass', osint: 'fa-eye', network: 'fa-network-wired', reversing: 'fa-microchip', pwn: 'fa-bomb' };
    return map[cat] || 'fa-cube';
}
function getColorForCategory(cat) {
    const map = { web: '#3b82f6', crypto: '#eab308', forensics: '#a855f7', osint: '#ef4444', network: '#22c55e', reversing: '#f97316', pwn: '#ec4899' };
    return map[cat] || '#64748b';
}

/* --- Premium Cyber Styles --- */
function getLearnStyles() {
    return `
    <style>
        :root {
            --cyber-bg: #0a0b1e;
            --cyber-glass: rgba(255, 255, 255, 0.03);
            --cyber-border: rgba(255, 255, 255, 0.08);
            --neon-green: #00ff9d;
            --neon-blue: #00f3ff;
            --card-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }

        .learn-container { 
            padding: 40px; 
            background-color: var(--cyber-bg);
            background-image: 
                linear-gradient(rgba(0, 243, 255, 0.03) 1px, transparent 1px), 
                linear-gradient(90deg, rgba(0, 243, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            min-height: 100vh; 
            color: #ecf0f1; 
            font-family: 'Cairo', sans-serif; 
            position: relative;
        }

        /* Ambient Glow */
        .learn-container::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle at 50% 10%, rgba(0, 243, 255, 0.05), transparent 60%);
            pointer-events: none;
            z-index: 0;
        }

        /* --- Hero Section --- */
        .learn-hero {
            display: flex; align-items: center; justify-content: space-between;
            background: rgba(13, 16, 33, 0.7);
            backdrop-filter: blur(20px);
            border: 1px solid var(--cyber-border);
            border-radius: 30px; 
            padding: 60px; margin-bottom: 50px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5), inset 0 0 0 1px rgba(255,255,255,0.05);
            position: relative; overflow: hidden;
            z-index: 1;
        }
        
        .learn-hero h1 { 
            font-size: 4rem; font-weight: 800; margin-bottom: 20px; letter-spacing: -1px;
            background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%); 
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
            filter: drop-shadow(0 0 30px rgba(165, 180, 252, 0.3));
        }
        .learn-hero p { 
            font-size: 1.25rem; color: #94a3b8; line-height: 1.8; margin-bottom: 40px; max-width: 600px;
        }

        /* 3D Fingerprint Icon */
        .learn-hero-3d-icon {
            font-size: 14rem; 
            color: var(--neon-green);
            filter: drop-shadow(0 0 50px rgba(0, 255, 157, 0.2));
            animation: float-pulse 6s ease-in-out infinite;
            z-index: 1; position: relative;
        }
        .learn-hero-3d-icon::after {
            content: ''; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            width: 140%; height: 2px;
            background: var(--neon-green); box-shadow: 0 0 15px var(--neon-green);
            animation: scanline 4s linear infinite;
        }
        @keyframes float-pulse { 0%, 100% { transform: translateY(0) scale(1); } 50% { transform: translateY(-15px) scale(1.02); } }
        @keyframes scanline { 0% { top: 0%; opacity: 0; } 15% { opacity: 1; } 85% { opacity: 1; } 100% { top: 100%; opacity: 0; } }

        /* --- Buttons --- */
        .cyber-btn {
            background: linear-gradient(145deg, rgba(255,255,255,0.05), rgba(255,255,255,0.01));
            color: #fff; 
            border: 1px solid var(--cyber-border);
            padding: 14px 35px; border-radius: 12px; 
            font-weight: 600; font-size: 1.05rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: inline-flex; align-items: center; gap: 12px; cursor: pointer; text-decoration: none;
            position: relative; overflow: hidden;
        }
        .cyber-btn::before {
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            transform: translateX(-100%); transition: 0.5s;
        }
        .cyber-btn:hover::before { transform: translateX(100%); }
        .cyber-btn:hover { 
            background: rgba(255,255,255,0.1); 
            border-color: var(--neon-green); 
            box-shadow: 0 0 20px rgba(0, 255, 157, 0.2); 
            color: #fff;
            transform: translateY(-2px);
        }
        .back-btn { 
            background: transparent; border: 1px solid var(--cyber-border); color: #94a3b8; 
            padding: 10px 25px; margin-bottom: 30px; 
        }
        .back-btn:hover { border-color: var(--neon-blue); color: var(--neon-blue); box-shadow: 0 0 15px rgba(0, 243, 255, 0.2); }

        /* --- Cyber Cards --- */
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; z-index: 1; }
        
        .section-header { 
            display: flex; align-items: center; justify-content: space-between; 
            margin-bottom: 40px; margin-top: 60px; border-bottom: 1px solid var(--cyber-border); padding-bottom: 20px;
        }
        .section-header h2 { font-size: 2.2rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 15px; }
        .view-all-link { 
            color: var(--neon-blue); font-weight: 600; text-decoration: none; letter-spacing: 0.5px; transition: 0.3s; 
            display: flex; align-items: center; gap: 8px;
        }
        .view-all-link:hover { color: #fff; text-shadow: 0 0 10px var(--neon-blue); transform: translateX(-5px); }

        .cyber-card {
            background: var(--cyber-glass);
            backdrop-filter: blur(15px);
            border: 1px solid var(--cyber-border);
            border-radius: 16px;
            padding: 20px;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: hidden;
            cursor: pointer;
            box-shadow: var(--card-shadow);
        }
        .cyber-card::before {
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 100%);
            opacity: 0; transition: 0.4s;
        }
        .cyber-card:hover {
            transform: translateY(-10px) scale(1.02);
            border-color: var(--neon-green);
            box-shadow: 0 20px 40px rgba(0,0,0,0.6), 0 0 20px rgba(0, 255, 157, 0.1);
        }
        .cyber-card:hover::before { opacity: 1; }

        /* Smart 3D Icon Image Style */
        .card-icon-img {
            width: 140px; height: 140px;
            object-fit: contain;
            margin-bottom: 25px;
            filter: drop-shadow(0 15px 30px rgba(0,0,0,0.6));
            transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            transform: perspective(1000px) rotateY(-15deg) translateZ(0);
        }
        .cyber-card:hover .card-icon-img {
            transform: perspective(1000px) rotateY(10deg) translateZ(30px) scale(1.15);
            filter: drop-shadow(0 25px 40px rgba(0, 255, 157, 0.4));
        }

        .card-icon-3d {
            font-size: 3rem; margin-bottom: 20px; display: inline-block;
            filter: drop-shadow(0 15px 25px rgba(0,0,0,0.5));
            transform: perspective(800px) rotateY(-15deg) translateZ(0);
            transition: all 0.5s ease;
        }
        .cyber-card:hover .card-icon-3d {
            transform: perspective(800px) rotateY(10deg) translateZ(20px) scale(1.1);
            filter: drop-shadow(0 20px 30px rgba(0, 255, 157, 0.3));
        }

        .cyber-card h3 { font-size: 1.25rem; font-weight: 700; color: #fff; margin-bottom: 10px; z-index: 2; position: relative; }
        .cyber-card p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; z-index: 2; position: relative; }

        .cyber-badge {
            background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
            color: #ccc; padding: 5px 12px; border-radius: 8px; font-size: 0.8rem; letter-spacing: 0.5px;
        }
        
        /* Stats Row */
        .card-stats { 
            display: flex; justify-content: space-between; margin-top: 25px; pt-3; 
            border-top: 1px solid rgba(255,255,255,0.05); 
        }
        .stat-item { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; color: #cbd5e1; }

        /* Animation */
        .fade-in { animation: fadeIn 0.6s ease-out forwards; opacity: 0; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        
        /* Input Styles */
        .cyber-input {
            background: rgba(13, 16, 33, 0.8) !important;
            border: 1px solid var(--cyber-border) !important;
            color: #fff !important;
            border-radius: 12px !important;
            padding: 12px 20px !important;
            box-shadow: none !important;
            transition: 0.3s !important;
        }
        .cyber-input:focus { border-color: var(--neon-blue) !important; box-shadow: 0 0 15px rgba(0, 243, 255, 0.1) !important; }
    </style>
    `;
}

/* --- Main Learn Page (Hub) --- */
function pageLearnV2() {
    const data = getIntegratedLearnData();
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="learn-hero fade-in">
            <div class="learn-hero-text">
                <h1>${txt('أكاديمية الأمن السيبراني', 'CYBER SECURITY ACADEMY')} <span style="font-size:1rem; color:var(--neon-green); vertical-align: super;">V4.0</span></h1>
                <p>${txt('منصة تعليمية متكاملة تأخذك من الصفر إلى الاحتراف. استكشف مساراتنا المتقدمة وابدأ رحلتك الآن.', 'An integrated learning platform taking you from zero to hero. Explore our advanced paths and start your journey now.')}</p>
                <div style="display: flex; gap: 20px; flex-wrap: wrap;">

                    <button onclick="loadPage('modules')" class="cyber-btn">
                        <i class="fas fa-cubes"></i> ${txt('الموديولات', 'Modules')}
                    </button>
                </div>
            </div>
            <div class="learn-hero-3d-icon">
                <i class="fas fa-fingerprint"></i>
            </div>
        </div>

        <!-- Latest Modules Preview -->
        <div class="section-header fade-in delay-1">
            <h2><i class="fas fa-cubes" style="color: var(--neon-green);"></i> ${txt('أحدث الموديولات', 'Latest Modules')}</h2>
            <a href="#" onclick="loadPage('modules')" class="view-all-link">${txt('عرض الكل', 'View All')} <i class="fas fa-arrow-right"></i></a>
        </div>
        <div class="grid-3 fade-in delay-1">
            ${data.modules.slice(0, 3).map(renderModuleCard).join('')}
        </div>

        <!-- Networks Preview -->
        <div class="section-header fade-in delay-2">
            <h2><i class="fas fa-network-wired" style="color: var(--neon-blue);"></i> ${txt('الشبكات', 'Networks')}</h2>
            <a href="#" onclick="loadPage('networks')" class="view-all-link">${txt('عرض الكل', 'View All')} <i class="fas fa-arrow-right"></i></a>
        </div>
        <div class="grid-3 fade-in delay-2">
            ${data.networks.map(renderNetworkCard).join('')}
        </div>
    </div>
    `;
}

/* --- Modules Page --- */
function pageModules() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}
        
        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="d-flex justify-content-between align-items-end mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <div>
                <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-cubes text-success me-3"></i> ${txt('الموديولات', 'Modules')}</h2>
                <p class="text-muted fs-5 mb-0">${txt('تصفح مكتبة ضخمة من الدروس العملية', 'Browse a huge library of practical hands-on lessons')}</p>
            </div>
            <div class="d-flex gap-3">
                <input type="text" id="mod-search" onkeyup="filterModules()" placeholder="${txt('بحث...', 'Search...')}" class="form-control cyber-input" style="width: 300px;">
                <select id="mod-diff" onchange="filterModules()" class="form-select cyber-input" style="width: 180px;">
                    <option value="All">${txt('All Difficulties', 'All Difficulties')}</option>
                    <option value="Easy">Easy</option>
                    <option value="Medium">Medium</option>
                    <option value="Hard">Hard</option>
                    <option value="Insane">Insane</option>
                </select>
            </div>
        </div>
        
        <div class="grid-3 fade-in delay-2" id="modules-grid">
            ${getIntegratedLearnData().modules.map(renderModuleCard).join('')}
        </div>
    </div>
    `;
}

/* --- Walkthroughs Page --- */
function pageWalkthroughs() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="d-flex flex-wrap justify-content-between align-items-end mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <div>
                <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-play text-primary me-3"></i> ${txt('الشروحات', 'Walkthroughs')}</h2>
                <p class="text-muted fs-5 mb-0">${txt('شروحات مفصلة لحل التحديات والآلات', 'Detailed walkthroughs for CTFs and Machines')}</p>
            </div>
            <div class="d-flex gap-3 flex-wrap">
                <input type="text" id="wt-search" onkeyup="filterWalkthroughs()" placeholder="${txt('بحث...', 'Search...')}" class="form-control cyber-input" style="width: 250px;">
                <select id="wt-diff" onchange="filterWalkthroughs()" class="form-select cyber-input" style="width: 150px;">
                    <option value="All">${txt('Difficulty', 'Difficulty')}</option>
                    <option value="Easy">Easy</option>
                    <option value="Medium">Medium</option>
                    <option value="Hard">Hard</option>
                </select>
            </div>
        </div>

        <div class="grid-3 fade-in delay-2" id="walkthroughs-grid">
            ${getIntegratedLearnData().walkthroughs.map(renderWalkthroughCard).join('')}
        </div>
    </div>
    `;
}

/* --- Networks Page --- */
function pageNetworks() {
    return `
    <div class="container-fluid learn-container">
        ${getLearnStyles()}

        <div class="d-flex justify-content-between align-items-center mb-5 fade-in">
            <button onclick="loadPage('learn')" class="cyber-btn back-btn mb-0">
                <i class="fas fa-arrow-right ms-2"></i> ${txt('العودة للرئيسية', 'Back to Hub')}
            </button>
        </div>

        <div class="mb-5 fade-in delay-1 border-bottom border-secondary pb-4" style="border-color: rgba(255,255,255,0.05)!important;">
            <h2 class="display-4 fw-bold mb-2 text-white"><i class="fas fa-network-wired text-info me-3"></i> ${txt('الشبكات', 'Networks')}</h2>
            <p class="text-muted fs-5">${txt('بيئات شبكية كاملة ومجهزة للاختراق المتقدم', 'Full network environments ready for advanced exploitation')}</p>
        </div>

        <div class="grid-3 fade-in delay-2">
            ${getIntegratedLearnData().networks.map(renderNetworkCard).join('')}
        </div>
    </div>
    `;
}


/* --- Filter Logic --- */
window.filterModules = function () {
    const searchEl = document.getElementById('mod-search');
    const diffEl = document.getElementById('mod-diff');
    if (!searchEl || !diffEl) return;

    const search = searchEl.value.toLowerCase();
    const diff = diffEl.value;
    const data = getIntegratedLearnData().modules;

    const filtered = data.filter(m => {
        const matchSearch = m.title.toLowerCase().includes(search);
        const matchDiff = diff === 'All' || m.difficulty === diff;
        return matchSearch && matchDiff;
    });

    const grid = document.getElementById('modules-grid');
    if (grid) {
        if (filtered.length > 0) {
            grid.innerHTML = filtered.map(renderModuleCard).join('');
        } else {
            grid.innerHTML = `<div class="col-12 text-center text-muted p-5"><h4>${txt('لا توجد نتائج', 'No results found')}</h4></div>`;
        }
    }
}

window.filterWalkthroughs = function () {
    const searchEl = document.getElementById('wt-search');
    const diffEl = document.getElementById('wt-diff');
    if (!searchEl) return;

    const search = searchEl.value.toLowerCase();
    const diff = diffEl.value;
    const data = getIntegratedLearnData().walkthroughs;

    const filtered = data.filter(w => {
        const matchSearch = w.title.toLowerCase().includes(search);
        const matchDiff = diff === 'All' || w.difficulty === diff;
        return matchSearch && matchDiff;
    });

    const grid = document.getElementById('walkthroughs-grid');
    if (grid) {
        if (filtered.length > 0) {
            grid.innerHTML = filtered.map(renderWalkthroughCard).join('');
        } else {
            grid.innerHTML = `<div class="col-12 text-center text-muted p-5"><h4>${txt('لا توجد نتائج', 'No results found')}</h4></div>`;
        }
    }
}

/* --- Render Helpers for Cyber Theme --- */
function renderModuleCard(mod) {
    // Check if icon is an image path (contains slash)
    const isImg = mod.icon.includes('/');
    const iconHtml = isImg
        ? `<img src="${mod.icon}" class="card-icon-img" alt="${mod.title}">`
        : `<div class="card-icon-3d" style="color: ${mod.color};"><i class="fab ${mod.icon.replace('fa-', 'fa-')} fas ${mod.icon}"></i></div>`;

    return `
    <div class="cyber-card" onclick="openModuleDetails('${mod.id}')">
        <div class="d-flex justify-content-center mb-4">
            ${iconHtml}
        </div>
        <div class="d-flex justify-content-between align-items-center mb-2">
             <span class="cyber-badge" style="border-color: ${mod.status === 'Completed' ? '#2ecc71' : 'rgba(255,255,255,0.1)'}">${mod.status}</span>
        </div>
        <h3>${mod.title}</h3>
        <p>${mod.description ? mod.description.substring(0, 80) + '...' : ''}</p>
        
        <div class="card-stats">
            <div class="stat-item"><i class="fas fa-bolt text-warning"></i> ${mod.difficulty}</div>
            <div class="stat-item"><i class="fas fa-star text-warning"></i> ${mod.xp} XP</div>
        </div>
    </div>
    `;
}

function renderWalkthroughCard(wt) {
    // Check if icon is an image path (contains slash) - Walkthroughs also get smart images now
    const isImg = wt.icon.includes('/');
    const iconHtml = isImg
        ? `<img src="${wt.icon}" class="card-icon-img" alt="${wt.title}" style="width:100px; height:100px;">`
        : `<div class="card-icon-3d" style="color: ${wt.color}; font-size: 2.5rem;"><i class="fas ${wt.icon}"></i></div>`;

    return `
    <div class="cyber-card">
        <div class="d-flex justify-content-between align-items-start mb-4">
            ${iconHtml}
            <span class="cyber-badge">${wt.status}</span>
        </div>
        <h3>${wt.title}</h3>
        <div class="d-flex gap-2 mb-3">
             <span class="cyber-badge" style="color: #fff; border-color: ${wt.color}">${wt.type}</span>
             <span class="cyber-badge">${wt.difficulty}</span>
        </div>
        <button class="cyber-btn mt-3 w-100 justify-content-center" style="font-size: 0.9rem; padding: 10px;" onclick="viewSolution('${wt.id}')">${txt('مشاهدة الحل', 'View Solution')}</button>
    </div>
    `;
}

function renderNetworkCard(net) {
    // Networks use 3D network icon always
    const iconPath = 'assets/images/3d-icons/icon_network_3d_1765817211308.png';
    return `
    <div class="cyber-card" style="border-top: 2px solid ${net.color};">
        <div class="d-flex justify-content-center mb-4">
             <img src="${iconPath}" class="card-icon-img" alt="${net.title}">
        </div>
        <h3>${net.title}</h3>
        <p class="mb-3 text-white"><span class="fw-bold fs-5" style="color: ${net.color}">${net.servers}</span> Servers Available</p>
        <div class="d-flex gap-2 mb-4">
            <span class="cyber-badge bg-danger text-white border-0">${net.difficulty}</span>
            <span class="cyber-badge bg-warning text-dark border-0">${net.status}</span>
        </div>
        <button id="btn-start-${net.id}" class="cyber-btn w-100 justify-content-center" style="border-color: ${net.color};" onclick="startLabNetwork('${net.id}')">${txt('ابدأ الشبكة', 'Start Network')}</button>
    </div>
    `;
}

// ==========================================================================
// MODULE INTERACTIONS (Start Network / View Solution)
// ==========================================================================

window.startLabNetwork = async function (moduleId) {
    const btn = document.getElementById(`btn-start-${moduleId}`);
    if (btn && btn.disabled) return; // Prevent double clicks

    // Visual Loading State
    let originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Spawning...';
        btn.disabled = true;
    }

    try {
        // 1. Find Module/Network Data
        // Look in networks first for instant match, or modules
        let module = null;
        // Check UnifiedLearningData if accessible
        if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
            module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
        }

        // If not found in modules, it might be a network ID passed directly
        const machineId = module ? (module.machineId || module.id) : moduleId;

        console.log(`Starting Lab: ${machineId} (Module: ${moduleId})`);

        // 2. Call Backend API
        // Use relative URL for portability or configured base
        const response = await fetch('http://localhost:5000/api/labs/spawn', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: 1, // TODO: Get actual user ID from auth context
                lab_id: machineId
            })
        });

        const data = await response.json();

        if (data.success) {
            // Success State
            if (btn) {
                btn.innerHTML = '<i class="fas fa-check"></i> Running';
                btn.classList.add('btn-success');
                // btn.style.borderColor = '#2ecc71'; // Optional overrides
            }

            // Show notification
            let msg = `Network Started!\n\nTarget IP: ${data.container_ip || '127.0.0.1'}\nMachine: ${data.lab_name}`;
            if (data.container_port && data.container_port != 80) msg += `\nPort: ${data.container_port}`;

            // Allow time for user to see "Running"
            setTimeout(() => {
                alert(msg);

                // Revert button logic can vary - maybe stay running?
                // For now, let's keep it "Running" until page refresh or manual stop (not implemented yet)
                // But to allow re-spawn attempts if something fails:
                setTimeout(() => {
                    if (btn) {
                        btn.innerHTML = '<i class="fas fa-network-wired"></i> Restart Network';
                        btn.disabled = false;
                        btn.classList.remove('btn-success');
                    }
                }, 10000);
            }, 500);

        } else {
            throw new Error(data.error || "Failed to spawn lab");
        }

    } catch (error) {
        console.error("Lab Spawn Error:", error);
        if (btn) {
            btn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error';
            btn.classList.add('btn-danger');
        }
        alert(`Failed to start network: ${error.message}`);

        setTimeout(() => {
            if (btn) {
                btn.innerHTML = originalText;
                btn.disabled = false;
                btn.classList.remove('btn-danger');
            }
        }, 3000);
    }
};

window.viewSolution = function (moduleId) {
    // 1. Find Module Data
    let module = null;

    // Check UnifiedLearningData Modules
    if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
        module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
    }

    // Check CTF Rooms (Walkthroughs)
    if (!module && window.ctfRooms) {
        for (const cat of Object.keys(window.ctfRooms)) {
            const found = window.ctfRooms[cat].find(r => r.id === moduleId);
            if (found) {
                module = found;
                if (!module.title && module.title) module.title = module.title.en; // Handle multilingual title structure if exists
                break;
            }
        }
    }

    // Fallback Mock Data
    if (!module) {
        module = {
            title: 'Walkthrough Solution',
            rooms: [
                { title: 'Task 1', content: 'Follow the instructions in the room PDF.' },
                { title: 'Flag', content: 'The flag is located in /root/flag.txt' }
            ]
        };
    }

    // 2. Build Solution Content
    // normalized to use 'rooms' or 'tasks' or just 'description'
    let solutionHtml = '';

    // Check for nested rooms (Modules)
    if (module.rooms && module.rooms.length > 0) {
        solutionHtml += '<div class="solution-steps">';
        module.rooms.forEach((room, index) => {
            solutionHtml += `
                <div class="solution-step mb-4">
                    <h5 class="text-cyber-blue" style="border-bottom: 1px solid rgba(0,243,255,0.2); padding-bottom: 5px;">Step ${index + 1}: ${room.title}</h5>
                    <div class="p-3 border border-dark rounded bg-dark-glass" style="background: rgba(0,0,0,0.3);">
                        <p class="mb-2 text-white">${room.content || (room.description || 'Complete the task objectives.')}</p>
                        ${room.tasks ? room.tasks.map(t => `<div class="text-muted"><i class="fas fa-check-circle text-success me-2"></i>${t.title}</div>`).join('') : ''}
                    </div>
                </div>
            `;
        });
        solutionHtml += '</div>';
    }
    // Check for direct tasks (CTF Rooms)
    else if (module.tasks && module.tasks.length > 0) {
        solutionHtml += '<div class="solution-steps">';
        module.tasks.forEach((task, index) => {
            solutionHtml += `
                <div class="solution-step mb-4">
                    <h5 class="text-cyber-blue" style="border-bottom: 1px solid rgba(0,243,255,0.2); padding-bottom: 5px;">Task ${index + 1}: ${task.title}</h5>
                    <div class="p-3 border border-dark rounded bg-dark-glass" style="background: rgba(0,0,0,0.3);">
                        <p class="mb-2 text-white">${task.content || 'Solve this challenge.'}</p>
                        ${task.question ? `<div class="text-info mt-2"><i class="fas fa-question-circle me-2"></i>${task.question}</div>` : ''}
                        ${task.answer ? `<div class="text-success mt-2 font-monospace"><i class="fas fa-key me-2"></i>${task.answer}</div>` : ''}
                    </div>
                </div>
            `;
        });
        solutionHtml += '</div>';
    }
    else {
        solutionHtml = `<div class="text-center p-4">
            <p class="text-muted">No specific solution steps available.</p>
            ${module.description ? `<p>${module.description}</p>` : ''}
        </div>`;
    }

    // 3. Create/Show Modal
    const existingModal = document.getElementById('solution-modal');
    if (existingModal) existingModal.remove();

    const modalHtml = `
        <div class="modal fade" id="solution-modal" tabindex="-1" aria-hidden="true" style="z-index: 10000;">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content bg-cyber-dark text-white border-0" style="
                    background: #0f172a; 
                    border: 1px solid var(--neon-blue) !important; 
                    box-shadow: 0 0 40px rgba(0, 243, 255, 0.2);">
                    
                    <div class="modal-header border-bottom border-dark" style="border-color: rgba(255,255,255,0.1) !important;">
                        <h5 class="modal-title font-monospace text-cyber-primary" style="color: var(--neon-blue);">
                            <i class="fas fa-unlock-alt me-2"></i>SOLUTION :: ${module.title || 'Unknown'}
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close" style="filter: invert(1);"></button>
                    </div>
                    
                    <div class="modal-body custom-scrollbar" style="max-height: 70vh; overflow-y: auto; padding: 2rem;">
                        ${solutionHtml}
                    </div>
                    
                    <div class="modal-footer border-top border-dark" style="border-color: rgba(255,255,255,0.1) !important;">
                        <button type="button" class="cyber-btn" data-bs-dismiss="modal" style="padding: 8px 20px;">Close Terminal</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // Initialize Bootstrap Modal
    try {
        const modalEl = document.getElementById('solution-modal');
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    } catch (e) {
        console.error("Bootstrap Modal Error:", e);
        // Fallback for older bootstrap or missing JS
        $('#solution-modal').modal('show');
    }
};

// ==========================================================================
// MODULE INTERACTIONS
// ==========================================================================

// ==========================================================================
// MODULE INTERACTIONS (Split-Pane Cyber Dashboard)
// ==========================================================================

window.openModuleDetails = function (moduleId) {
    // 1. Find Data (Same logic)
    let module = null;
    if (window.UnifiedLearningData && window.UnifiedLearningData.modules) {
        module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
    }
    if (!module && window.ctfRooms) {
        for (const cat of Object.keys(window.ctfRooms)) {
            const found = window.ctfRooms[cat].find(r => r.id === moduleId);
            if (found) { module = found; break; }
        }
    }
    if (!module) return;

    // 2. Render Split-Pane View
    const container = document.querySelector('.learn-container');
    if (!container) return;

    const iconHtml = (module.icon && module.icon.includes('/'))
        ? `<img src="${module.icon}" class="sidebar-icon-img" alt="${module.title}">`
        : `<i class="${module.icon} fa-3x text-cyber-primary"></i>`;

    // Default to displaying description if no room selected yet
    const initialContent = `
        <div class="p-5 text-center">
            <div class="mb-4">${iconHtml}</div>
            <h1 class="text-white mb-3 fw-bold">${module.title || module.name}</h1>
            <p class="text-muted fs-5 mb-5" style="max-width: 600px; margin: 0 auto;">${module.description || 'Welcome to this module. Select a unit from the left to begin.'}</p>
            <div class="d-flex justify-content-center gap-4">
                <div class="stat-box p-3 border border-dark rounded bg-dark-glass">
                    <h3 class="text-white m-0">${module.difficulty || 'Easy'}</h3>
                    <small class="text-muted">DIFFICULTY</small>
                </div>
                <div class="stat-box p-3 border border-dark rounded bg-dark-glass">
                    <h3 class="text-white m-0">${module.xp || 100}</h3>
                    <small class="text-muted">XP POINTS</small>
                </div>
            </div>
        </div>
    `;

    const dashboardHtml = `
    <div class="module-dashboard fade-in h-100 d-flex flex-column">
        <!-- Dashboard Header -->
        <div class="d-flex justify-content-between align-items-center mb-0 p-3 border-bottom border-dark" style="background: rgba(15, 15, 20, 0.95);">
            <div class="d-flex align-items-center gap-3">
                <button onclick="loadPage('learn')" class="cyber-btn back-btn m-0 py-2 px-3" style="font-size: 0.9rem;">
                    <i class="fas fa-arrow-left me-2"></i> ${txt('العودة', 'Back')}
                </button>
                <div class="vr bg-secondary mx-2"></div>
                <h4 class="m-0 text-white font-monospace">${module.title || module.name}</h4>
            </div>
            <div id="lab-status-mini" class="d-flex align-items-center gap-3">
                 <span class="text-muted small"><i class="fas fa-microchip me-1"></i> STATUS: <span class="text-danger">OFFLINE</span></span>
            </div>
        </div>

        <div class="row g-0 flex-grow-1" style="height: calc(100vh - 80px);">
            <!-- Left Sidebar (Syllabus & Lab) -->
            <div class="col-lg-3 border-end border-dark bg-dark-glass d-flex flex-column" style="background: rgba(10, 11, 15, 0.9);">
                
                <!-- Lab Control Card -->
                <div class="p-3 border-bottom border-dark">
                    <div class="cyber-card p-3 mb-0" style="background: rgba(0,0,0,0.2);">
                        <div class="d-flex align-items-center justify-content-between mb-2">
                             <h6 class="m-0 text-cyber-primary text-uppercase font-monospace text-truncate" title="${module.machineId || 'lab'}">LAB: ${module.machineId || 'GENERIC'}</h6>
                             <i class="fas fa-network-wired text-muted"></i>
                        </div>
                        <button id="btn-dashboard-start" onclick="startLabDashboard('${module.id}')" class="cyber-btn w-100 justify-content-center py-2" style="font-size: 0.9rem; border-color: var(--neon-green);">
                            <i class="fas fa-power-off"></i> ${txt('تشغيل المعمل', 'Start Lab')}
                        </button>
                    </div>
                </div>

                <!-- Syllabus List -->
                <div class="flex-grow-1 overflow-auto custom-scrollbar p-3">
                    <h6 class="text-muted text-uppercase mb-3 ps-2" style="font-size: 0.75rem; letter-spacing: 1px;">Syllabus</h6>
                    ${renderSyllabusItems(module)}
                </div>
            </div>

            <!-- Main Content Area -->
            <div class="col-lg-9 bg-cyber-dark position-relative overflow-hidden">
                <div id="content-viewer" class="h-100 w-100 overflow-auto custom-scrollbar p-5" style="background: radial-gradient(circle at 50% 50%, #1a1a2e 0%, #0f172a 100%);">
                    ${initialContent}
                </div>
            </div>
        </div>
    </div>
    <style>
        .module-dashboard { position: fixed; top: 0; left: 0; width: 100%; height: 100vh; z-index: 1000; background: var(--cyber-bg); }
        .sidebar-icon-img { width: 80px; height: 80px; object-fit: contain; filter: drop-shadow(0 0 10px rgba(0,243,255,0.3)); }
        .syllabus-link {
            display: flex; align-items: center; gap: 10px;
            padding: 12px 15px;
            border-radius: 8px;
            color: #94a3b8;
            transition: all 0.2s;
            cursor: pointer;
            border: 1px solid transparent;
        }
        .syllabus-link:hover, .syllabus-link.active {
            background: rgba(0, 243, 255, 0.05);
            color: #fff;
            border-color: rgba(0, 243, 255, 0.2);
        }
        .syllabus-link.active i.status-icon { color: var(--neon-green); text-shadow: 0 0 10px var(--neon-green); }
        code { color: #f97316; background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 4px; font-family: monospace; }
        pre { background: #0f172a; border: 1px solid rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0; overflow-x: auto; }
        .tasks-container .task-card { transition: transform 0.2s; }
        .tasks-container .task-card:hover { transform: translateY(-2px); border-color: var(--neon-blue) !important; }
    </style>
    `;

    container.innerHTML = dashboardHtml;
    window.scrollTo(0, 0);
};

function renderSyllabusItems(module) {
    let html = '';
    // Handle nested structure (units -> rooms) logic from data structure
    let items = [];
    if (module.units) {
        // Flatten units for sidebar
        module.units.forEach(u => {
            items = items.concat(u.rooms.map(r => ({ ...r, unitName: u.name })));
        });
    } else {
        items = module.rooms || module.tasks || [];
    }

    if (items.length === 0) return '<div class="text-muted small ps-2">No units found.</div>';

    items.forEach((item, i) => {
        html += `
            <div class="syllabus-link mb-2" onclick="loadRoomContent('${module.id}', '${item.id}', this)">
                <i class="fas fa-circle status-icon" style="font-size: 0.5rem; color: #475569;"></i>
                <div style="flex:1;">
                    <div class="fw-bold" style="font-size: 0.95rem;">${item.title}</div>
                    <div class="small opacity-50 text-truncate">${item.type || 'Lab'}</div>
                </div>
            </div>
        `;
    });
    return html;
}

window.loadRoomContent = function (moduleId, roomId, element) {
    // UI Active State
    document.querySelectorAll('.syllabus-link').forEach(el => el.classList.remove('active'));
    if (element) element.classList.add('active');

    // Find Module & Room Data
    let module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
    if (!module && window.ctfRooms) {
        for (const cat of Object.keys(window.ctfRooms)) {
            const found = window.ctfRooms[cat].find(r => r.id === moduleId);
            if (found) { module = found; break; }
        }
    }

    // Search for room in units or direct list
    let item = null;
    if (module.units) {
        for (const unit of module.units) {
            const result = unit.rooms.find(r => r.id === roomId);
            if (result) { item = result; break; }
        }
    } else {
        const items = module.rooms || module.tasks || [];
        item = items.find(r => r.id === roomId);
    }

    if (!item) return;

    // Render Content
    const contentHtml = `
        <div class="animate__animated animate__fadeIn">
            <h2 class="text-white mb-4 pb-2 border-bottom border-secondary">${item.title}</h2>
            
            <div class="content-body text-light mb-5" style="font-size: 1.1rem; line-height: 1.8;">
                ${item.content || item.description || '<p>No specific content provided for this unit yet.</p>'}
            </div>

            <!-- Tasks Section -->
            ${item.tasks && item.tasks.length > 0 ? `
                <h4 class="text-cyber-primary mb-4"><i class="fas fa-tasks me-2"></i>Tasks to Complete</h4>
                <div class="tasks-container">
                    ${item.tasks.map((t, idx) => `
                        <div class="task-card p-4 mb-3 rounded bg-dark border border-secondary" style="background: rgba(0,0,0,0.2) !important;">
                            <h5 class="mb-3 text-white"><span class="badge bg-secondary me-2">#${idx + 1}</span> ${t.title}</h5>
                            <p class="text-muted mb-3">${t.content}</p>
                            ${t.question ? `
                                <div class="input-group mb-2">
                                    <span class="input-group-text bg-dark border-secondary text-info"><i class="fas fa-question"></i></span>
                                    <input type="text" class="form-control bg-transparent border-secondary text-white" placeholder="Answer format: flag{...}">
                                    <button class="btn btn-outline-success">Submit</button>
                                </div>
                            ` : `<button class="btn btn-sm btn-success"><i class="fas fa-check me-2"></i>Mark Complete</button>`}
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        </div>
    `;

    document.getElementById('content-viewer').innerHTML = contentHtml;
};

// New Start Lab Wrapper for Dashboard
window.startLabDashboard = async function (moduleId) {
    const btn = document.getElementById('btn-dashboard-start');
    const statusEl = document.getElementById('lab-status-mini');

    if (btn) {
        btn.innerHTML = '<i class="fas fa-sync fa-spin"></i> Spawning...';
        btn.disabled = true;
    }

    try {
        // Find module logic (reused from startLabNetwork but with UI updates for dashboard)
        let module = window.UnifiedLearningData.modules.find(m => m.id === moduleId);
        // Fallback search
        if (!module && window.ctfRooms) {
            for (const cat of Object.keys(window.ctfRooms)) {
                const found = window.ctfRooms[cat].find(r => r.id === moduleId);
                if (found) { module = found; break; }
            }
        }

        const machineId = module ? (module.machineId || module.id) : moduleId;

        const response = await fetch('http://localhost:5000/api/labs/spawn', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: 1, lab_id: machineId })
        });

        const data = await response.json();

        if (data.success) {
            if (btn) {
                btn.innerHTML = '<i class="fas fa-stop"></i> Stop Lab'; // Placeholder logic
                btn.classList.replace('btn-outline-success', 'btn-outline-danger');
                btn.disabled = false;
            }
            if (statusEl) {
                statusEl.innerHTML = `
                    <span class="text-success small fw-bold"><i class="fas fa-circle me-1"></i> ONLINE</span>
                    <span class="badge bg-dark border border-success font-monospace ms-2">${data.container_ip}</span>
                `;
            }
            alert(`Lab Started!\nIP: ${data.container_ip}\nUse the terminal to connect.`);
        } else {
            throw new Error(data.error);
        }
    } catch (e) {
        console.error(e);
        alert('Failed to start lab: ' + e.message);
        if (btn) {
            btn.innerHTML = '<i class="fas fa-power-off"></i> Start Lab';
            btn.disabled = false;
        }
    }
};

// Ensure functions are global
// function removed
window.getLearnStyles = getLearnStyles;
