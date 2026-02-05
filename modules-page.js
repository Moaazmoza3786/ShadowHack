// ==================== ENHANCED MODULES PAGE - HTB Academy Style ====================

function pageModulesEnhanced() {
    const data = window.UnifiedLearningData || {};
    const modules = data.modules || [];
    const paths = data.paths || [];

    // Get all modules from paths as well for richer data
    const allModules = [...modules];

    // Add modules from paths if not already present
    paths.forEach(path => {
        path.units?.forEach(unit => {
            unit.rooms?.forEach(room => {
                if (!allModules.find(m => m.id === room.id)) {
                    allModules.push({
                        id: room.id || `room-${Math.random().toString(36).substr(2, 9)}`,
                        title: room.name || room.title || 'Untitled',
                        description: room.description || '',
                        difficulty: room.difficulty || 'easy',
                        tier: room.tier || 'regular',
                        type: room.type || 'general',
                        icon: room.icon || path.icon || 'fa-cube',
                        color: room.color || path.color || '#3b82f6',
                        image: room.image || null,
                        isPremium: room.isPremium || false,
                        estimatedTime: room.estimatedTime || '1 hour',
                        pathName: path.name
                    });
                }
            });
        });
    });

    // Use modules from data directly
    const finalModules = allModules;

    return `
        <div class="modules-page-htb">
            <style>
                /* ============ HTB ACADEMY STYLE MODULES PAGE ============ */
                .modules-page-htb {
                    min-height: 100vh;
                    background: linear-gradient(180deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
                    padding: 30px 40px;
                    font-family: 'Inter', 'Segoe UI', sans-serif;
                }
                
                /* Page Header */
                .htb-modules-header {
                    margin-bottom: 35px;
                }
                .htb-modules-header h1 {
                    font-size: 2.8rem;
                    font-weight: 800;
                    color: #fff;
                    margin-bottom: 30px;
                    letter-spacing: -0.5px;
                }
                
                /* Tab Switcher */
                .htb-tabs {
                    display: flex;
                    gap: 0;
                    margin-bottom: 30px;
                    background: rgba(255,255,255,0.05);
                    border-radius: 10px;
                    padding: 4px;
                    width: fit-content;
                }
                .htb-tab {
                    padding: 12px 24px;
                    font-size: 14px;
                    font-weight: 600;
                    color: rgba(255,255,255,0.6);
                    cursor: pointer;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    border: none;
                    background: transparent;
                }
                .htb-tab:hover {
                    color: #fff;
                }
                .htb-tab.active {
                    background: rgba(255,255,255,0.1);
                    color: #fff;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                }
                
                /* Filter Bar */
                .htb-filter-bar {
                    display: flex;
                    gap: 12px;
                    margin-bottom: 35px;
                    flex-wrap: wrap;
                    align-items: center;
                }
                .htb-filter-dropdown {
                    position: relative;
                }
                .htb-filter-dropdown select {
                    appearance: none;
                    padding: 12px 40px 12px 18px;
                    background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.12);
                    border-radius: 10px;
                    color: rgba(255,255,255,0.8);
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                    min-width: 140px;
                    transition: all 0.3s ease;
                }
                .htb-filter-dropdown select:hover {
                    border-color: rgba(255,255,255,0.25);
                    background: rgba(255,255,255,0.08);
                }
                .htb-filter-dropdown select:focus {
                    outline: none;
                    border-color: #9fef00;
                    box-shadow: 0 0 0 3px rgba(159, 239, 0, 0.1);
                }
                .htb-filter-dropdown select option {
                    background: #1a1f2e;
                    color: #fff;
                    padding: 10px;
                }
                .htb-filter-dropdown::after {
                    content: '\\f078';
                    font-family: 'Font Awesome 6 Free';
                    font-weight: 900;
                    position: absolute;
                    right: 14px;
                    top: 50%;
                    transform: translateY(-50%);
                    color: rgba(255,255,255,0.4);
                    font-size: 10px;
                    pointer-events: none;
                }
                
                .htb-view-toggle {
                    margin-left: auto;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    color: rgba(255,255,255,0.5);
                    font-size: 13px;
                }
                .htb-view-toggle span {
                    color: #9fef00;
                    font-weight: 600;
                }
                
                /* Section Title */
                .htb-section-title {
                    font-size: 1.3rem;
                    font-weight: 700;
                    color: #fff;
                    margin-bottom: 25px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .htb-section-title::before {
                    content: '';
                    width: 4px;
                    height: 24px;
                    background: linear-gradient(180deg, #9fef00, #22c55e);
                    border-radius: 2px;
                }
                
                /* Modules Grid */
                .htb-modules-grid {
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 25px;
                }
                @media (max-width: 1400px) {
                    .htb-modules-grid { grid-template-columns: repeat(3, 1fr); }
                }
                @media (max-width: 1000px) {
                    .htb-modules-grid { grid-template-columns: repeat(2, 1fr); }
                }
                @media (max-width: 650px) {
                    .htb-modules-grid { grid-template-columns: 1fr; }
                }
                
                /* Module Card - HTB Style */
                .htb-module-card {
                    background: linear-gradient(165deg, #1e2a3a 0%, #141d2b 100%);
                    border-radius: 16px;
                    overflow: hidden;
                    cursor: pointer;
                    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                    border: 1px solid rgba(255,255,255,0.06);
                    position: relative;
                }
                .htb-module-card:hover {
                    transform: translateY(-8px) scale(1.02);
                    border-color: rgba(159, 239, 0, 0.3);
                    box-shadow: 
                        0 20px 50px rgba(0,0,0,0.4),
                        0 0 40px rgba(159, 239, 0, 0.08),
                        inset 0 1px 0 rgba(255,255,255,0.05);
                }
                
                /* Progress Badge */
                .htb-progress-badge {
                    position: absolute;
                    top: 12px;
                    right: 12px;
                    padding: 6px 14px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #fff;
                    font-size: 11px;
                    font-weight: 700;
                    border-radius: 6px;
                    z-index: 10;
                    box-shadow: 0 4px 15px rgba(34, 197, 94, 0.4);
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                /* Card Image Area */
                .htb-card-image {
                    height: 160px;
                    background: linear-gradient(135deg, #1a2332 0%, #0f172a 100%);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    position: relative;
                    overflow: hidden;
                }
                .htb-card-image::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: radial-gradient(circle at 30% 30%, rgba(159, 239, 0, 0.08) 0%, transparent 50%);
                }
                .htb-card-image::after {
                    content: '';
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    right: 0;
                    height: 60px;
                    background: linear-gradient(to top, #141d2b, transparent);
                }
                
                /* Module Icon/Visual */
                .htb-module-visual {
                    position: relative;
                    z-index: 5;
                }
                .htb-module-visual i {
                    font-size: 64px;
                    background: linear-gradient(135deg, #fff 20%, rgba(255,255,255,0.6) 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    filter: drop-shadow(0 4px 20px rgba(0,0,0,0.3));
                    transition: all 0.4s ease;
                }
                .htb-module-card:hover .htb-module-visual i {
                    transform: scale(1.1) rotate(5deg);
                    filter: drop-shadow(0 8px 30px rgba(159, 239, 0, 0.2));
                }
                
                /* Floating Decorations */
                .htb-card-decoration {
                    position: absolute;
                    border-radius: 50%;
                    opacity: 0.6;
                    animation: float 4s ease-in-out infinite;
                }
                .htb-card-decoration.d1 {
                    width: 12px;
                    height: 12px;
                    background: #a855f7;
                    top: 20%;
                    left: 15%;
                    animation-delay: 0s;
                }
                .htb-card-decoration.d2 {
                    width: 8px;
                    height: 8px;
                    background: #22d3ee;
                    top: 30%;
                    right: 20%;
                    animation-delay: 1s;
                }
                .htb-card-decoration.d3 {
                    width: 10px;
                    height: 10px;
                    background: #9fef00;
                    bottom: 35%;
                    left: 25%;
                    animation-delay: 2s;
                }
                @keyframes float {
                    0%, 100% { transform: translateY(0) scale(1); opacity: 0.6; }
                    50% { transform: translateY(-8px) scale(1.2); opacity: 1; }
                }
                
                /* Card Content */
                .htb-card-content {
                    padding: 18px 20px 20px;
                }
                
                /* Tags Row */
                .htb-card-tags {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 12px;
                    flex-wrap: wrap;
                }
                .htb-tag {
                    display: inline-flex;
                    align-items: center;
                    gap: 5px;
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 10px;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .htb-tag.tier-regular {
                    background: rgba(34, 197, 94, 0.15);
                    color: #22c55e;
                }
                .htb-tag.tier-premium {
                    background: rgba(245, 158, 11, 0.15);
                    color: #f59e0b;
                }
                .htb-tag.type-general {
                    background: rgba(59, 130, 246, 0.15);
                    color: #60a5fa;
                }
                .htb-tag.type-offensive {
                    background: rgba(239, 68, 68, 0.15);
                    color: #f87171;
                }
                .htb-tag.type-defensive {
                    background: rgba(168, 85, 247, 0.15);
                    color: #c084fc;
                }
                .htb-tag i {
                    font-size: 9px;
                }
                
                /* Module Title */
                .htb-card-title {
                    font-size: 1rem;
                    font-weight: 700;
                    color: #fff;
                    margin: 0;
                    line-height: 1.4;
                    transition: color 0.3s ease;
                }
                .htb-module-card:hover .htb-card-title {
                    color: #9fef00;
                }
                
                /* Progress Bar (for in-progress modules) */
                .htb-progress-bar-container {
                    margin-top: 14px;
                    background: rgba(255,255,255,0.08);
                    border-radius: 6px;
                    height: 6px;
                    overflow: hidden;
                }
                .htb-progress-bar {
                    height: 100%;
                    background: linear-gradient(90deg, #9fef00, #22c55e);
                    border-radius: 6px;
                    transition: width 0.5s ease;
                    box-shadow: 0 0 10px rgba(159, 239, 0, 0.5);
                }
                
                /* Difficulty Badge */
                .htb-difficulty {
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    padding: 5px 12px;
                    border-radius: 6px;
                    font-size: 10px;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-top: 12px;
                }
                .htb-difficulty i { font-size: 10px; }
                .htb-difficulty.easy {
                    background: rgba(34,197,94,0.12);
                    color: #22c55e;
                    border: 1px solid rgba(34,197,94,0.25);
                }
                .htb-difficulty.medium {
                    background: rgba(245,158,11,0.12);
                    color: #f59e0b;
                    border: 1px solid rgba(245,158,11,0.25);
                }
                .htb-difficulty.hard {
                    background: rgba(239,68,68,0.12);
                    color: #ef4444;
                    border: 1px solid rgba(239,68,68,0.25);
                }
                .htb-difficulty.insane {
                    background: rgba(139, 92, 246, 0.12);
                    color: #a78bfa;
                    border: 1px solid rgba(139, 92, 246, 0.25);
                }
                
                /* Empty State */
                .htb-empty-state {
                    text-align: center;
                    padding: 80px 40px;
                    color: rgba(255,255,255,0.5);
                }
                .htb-empty-state i {
                    font-size: 64px;
                    margin-bottom: 20px;
                    color: rgba(255,255,255,0.2);
                }
                .htb-empty-state h3 {
                    font-size: 1.5rem;
                    color: #fff;
                    margin-bottom: 10px;
                }
                
                /* Responsive Filter */
                @media (max-width: 900px) {
                    .modules-page-htb { padding: 20px; }
                    .htb-modules-header h1 { font-size: 2rem; }
                    .htb-filter-bar { gap: 8px; }
                    .htb-filter-dropdown select { min-width: 110px; padding: 10px 30px 10px 12px; font-size: 12px; }
                    .htb-view-toggle { display: none; }
                }
            </style>
            
            <!-- Header -->
            <div class="htb-modules-header">
                <h1>Modules</h1>
                
                <!-- Tab Switcher -->
                <div class="htb-tabs">
                    <button class="htb-tab active" onclick="switchModulesTab('all')">All Modules</button>
                    <button class="htb-tab" onclick="switchModulesTab('favourites')">Favourite Modules</button>
                </div>
            </div>
            
            <!-- Filter Bar -->
            <div class="htb-filter-bar">
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-category" onchange="filterHTBModules()">
                        <option value="">Categories</option>
                        <option value="web">Web</option>
                        <option value="network">Network</option>
                        <option value="linux">Linux</option>
                        <option value="windows">Windows</option>
                        <option value="crypto">Cryptography</option>
                        <option value="forensics">Forensics</option>
                    </select>
                </div>
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-difficulty" onchange="filterHTBModules()">
                        <option value="">Difficulty</option>
                        <option value="easy">Easy</option>
                        <option value="medium">Medium</option>
                        <option value="hard">Hard</option>
                        <option value="insane">Insane</option>
                    </select>
                </div>
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-tier" onchange="filterHTBModules()">
                        <option value="">Tiers</option>
                        <option value="regular">Regular</option>
                        <option value="premium">Premium</option>
                    </select>
                </div>
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-type" onchange="filterHTBModules()">
                        <option value="">Type</option>
                        <option value="general">General</option>
                        <option value="offensive">Offensive</option>
                        <option value="defensive">Defensive</option>
                    </select>
                </div>
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-state" onchange="filterHTBModules()">
                        <option value="">State</option>
                        <option value="active">Active</option>
                        <option value="retired">Retired</option>
                    </select>
                </div>
                <div class="htb-filter-dropdown">
                    <select id="htb-filter-status" onchange="filterHTBModules()">
                        <option value="">Status</option>
                        <option value="not-started">Not Started</option>
                        <option value="in-progress">In Progress</option>
                        <option value="completed">Completed</option>
                    </select>
                </div>
                
                <div class="htb-view-toggle">
                    View By: <span>Default</span> <i class="fas fa-chevron-down" style="font-size: 10px;"></i>
                </div>
            </div>
            
            <!-- Section Title -->
            <h2 class="htb-section-title">All Modules</h2>
            
            <div class="htb-modules-grid" id="htb-modules-grid">
                ${finalModules.map(mod => {
        const progress = mod.progress || 0;
        const hasProgress = progress > 0 && progress < 100;
        const isCompleted = progress >= 100;
        const difficulty = (mod.difficulty || 'easy').toLowerCase();
        const tier = (mod.tier || 'regular').toLowerCase();
        const type = (mod.type || 'general').toLowerCase();

        return `
                        <div class="htb-module-card" 
                             data-difficulty="${difficulty}"
                             data-tier="${tier}"
                             data-type="${type}"
                             data-title="${(mod.title || '').toLowerCase()}"
                             data-status="${isCompleted ? 'completed' : (hasProgress ? 'in-progress' : 'not-started')}"
                             onclick="openModule('${mod.id}')">
                            
                            ${hasProgress ? '<div class="htb-progress-badge">In Progress</div>' : ''}
                            ${isCompleted ? '<div class="htb-progress-badge" style="background: linear-gradient(135deg, #3b82f6, #1d4ed8);">Completed</div>' : ''}
                            
                            <div class="htb-card-image" style="background: linear-gradient(135deg, ${mod.color || '#3b82f6'}22 0%, #0f172a 100%);">
                                <div class="htb-card-decoration d1"></div>
                                <div class="htb-card-decoration d2"></div>
                                <div class="htb-card-decoration d3"></div>
                                <div class="htb-module-visual">
                                    <i class="fa-solid ${mod.icon || 'fa-cube'}"></i>
                                </div>
                            </div>
                            
                            <div class="htb-card-content">
                                <div class="htb-card-tags">
                                    <span class="htb-tag tier-${tier}">
                                        <i class="fas ${tier === 'premium' ? 'fa-crown' : 'fa-check-circle'}"></i>
                                        ${tier}
                                    </span>
                                    <span class="htb-tag type-${type}">
                                        <i class="fas ${type === 'offensive' ? 'fa-crosshairs' : (type === 'defensive' ? 'fa-shield-alt' : 'fa-book')}"></i>
                                        ${type}
                                    </span>
                                </div>
                                
                                <h3 class="htb-card-title">${mod.title}</h3>
                                
                                ${hasProgress ? `
                                    <div class="htb-progress-bar-container">
                                        <div class="htb-progress-bar" style="width: ${progress}%;"></div>
                                    </div>
                                ` : `
                                    <div class="htb-difficulty ${difficulty}">
                                        <i class="fas fa-signal"></i>
                                        ${difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
                                    </div>
                                `}
                            </div>
                        </div>
                    `;
    }).join('')}
            </div>
        </div>
    `;
}

// Tab switching function
function switchModulesTab(tab) {
    const tabs = document.querySelectorAll('.htb-tab');
    tabs.forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');

    const sectionTitle = document.querySelector('.htb-section-title');
    if (sectionTitle) {
        sectionTitle.textContent = tab === 'favourites' ? 'Favourite Modules' : 'All Modules';
    }

    // Filter modules based on tab
    const cards = document.querySelectorAll('.htb-module-card');
    if (tab === 'favourites') {
        // Get favourites from localStorage
        const favourites = JSON.parse(localStorage.getItem('module_favourites') || '[]');
        cards.forEach(card => {
            const moduleId = card.getAttribute('onclick')?.match(/openModule\('([^']+)'\)/)?.[1];
            card.style.display = favourites.includes(moduleId) ? '' : 'none';
        });
    } else {
        cards.forEach(card => card.style.display = '');
    }
}

// Filter function
function filterHTBModules() {
    const category = document.getElementById('htb-filter-category')?.value || '';
    const difficulty = document.getElementById('htb-filter-difficulty')?.value || '';
    const tier = document.getElementById('htb-filter-tier')?.value || '';
    const type = document.getElementById('htb-filter-type')?.value || '';
    const state = document.getElementById('htb-filter-state')?.value || '';
    const status = document.getElementById('htb-filter-status')?.value || '';

    const cards = document.querySelectorAll('.htb-module-card');

    cards.forEach(card => {
        const cardDifficulty = card.dataset.difficulty || '';
        const cardTier = card.dataset.tier || '';
        const cardType = card.dataset.type || '';
        const cardStatus = card.dataset.status || '';
        const cardTitle = card.dataset.title || '';

        // Category matching (check if title contains category)
        const matchesCategory = !category || cardTitle.includes(category);
        const matchesDifficulty = !difficulty || cardDifficulty === difficulty;
        const matchesTier = !tier || cardTier === tier;
        const matchesType = !type || cardType === type;
        const matchesStatus = !status || cardStatus === status;

        if (matchesCategory && matchesDifficulty && matchesTier && matchesType && matchesStatus) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}

// Make functions globally available
window.pageModulesEnhanced = pageModulesEnhanced;
window.switchModulesTab = switchModulesTab;
window.filterHTBModules = filterHTBModules;
