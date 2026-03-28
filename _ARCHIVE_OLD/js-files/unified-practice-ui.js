/* ============================================================
   PRACTICE UI - Professional CTF Challenges Arena
   Uses CTFData from unified-ctf-data.js
   ============================================================ */

// ==================== PRACTICE PAGE ====================
function pagePractice() {
    // Use CTFData if available
    const ctfCategories = typeof CTFData !== 'undefined' ? Object.keys(CTFData) : [];
    const progress = typeof getCTFProgress === 'function' ? getCTFProgress() : { solved: 0, total: 0, percentage: 0, earnedPoints: 0 };

    const categoryInfo = {
        web: { name: 'Web Exploitation', icon: 'fa-globe', color: '#3b82f6' },
        crypto: { name: 'Cryptography', icon: 'fa-key', color: '#8b5cf6' },
        forensics: { name: 'Digital Forensics', icon: 'fa-magnifying-glass', color: '#06b6d4' },
        osint: { name: 'OSINT', icon: 'fa-user-secret', color: '#f59e0b' },
        network: { name: 'Network', icon: 'fa-network-wired', color: '#14b8a6' },
        reverse: { name: 'Reverse Engineering', icon: 'fa-microchip', color: '#ec4899' }
    };

    return `
        <div class="ctf-arena-page">
            <style>
                .ctf-arena-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #0f0c29 100%);
                    padding: 0;
                }
                
                /* Hero Section */
                .ctf-hero {
                    padding: 60px 40px;
                    text-align: center;
                    background: linear-gradient(135deg, rgba(239,68,68,0.1), rgba(139,92,246,0.05));
                    border-bottom: 1px solid rgba(255,255,255,0.05);
                    position: relative;
                    overflow: hidden;
                }
                .ctf-hero::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4z' fill='%23ef4444' fill-opacity='0.03'/%3E%3C/svg%3E");
                }
                .ctf-hero-content { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; }
                .ctf-hero-title {
                    font-size: 3.5rem;
                    font-weight: 800;
                    font-family: 'Orbitron', sans-serif;
                    background: linear-gradient(135deg, #ef4444, #f97316, #ef4444);
                    background-size: 200% auto;
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    animation: gradient-shift 3s ease infinite;
                    margin-bottom: 15px;
                }
                @keyframes gradient-shift {
                    0% { background-position: 0% center; }
                    100% { background-position: 200% center; }
                }
                .ctf-hero-subtitle { color: rgba(255,255,255,0.6); font-size: 1.2rem; margin-bottom: 30px; }
                
                /* Stats Bar */
                .ctf-stats-bar {
                    display: flex;
                    justify-content: center;
                    gap: 40px;
                    flex-wrap: wrap;
                }
                .ctf-stat {
                    text-align: center;
                    padding: 20px 30px;
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 16px;
                    min-width: 140px;
                }
                .ctf-stat-value {
                    font-size: 2rem;
                    font-weight: 700;
                    color: #ef4444;
                    font-family: 'Orbitron', sans-serif;
                }
                .ctf-stat-label {
                    color: rgba(255,255,255,0.5);
                    font-size: 0.85rem;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-top: 5px;
                }
                
                /* Main Container */
                .ctf-container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }
                
                /* Category Tabs */
                .ctf-category-tabs {
                    display: flex;
                    gap: 10px;
                    flex-wrap: wrap;
                    margin-bottom: 40px;
                    padding: 10px;
                    background: rgba(0,0,0,0.2);
                    border-radius: 16px;
                }
                .ctf-category-tab {
                    padding: 12px 24px;
                    background: transparent;
                    border: 1px solid transparent;
                    border-radius: 10px;
                    color: rgba(255,255,255,0.6);
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .ctf-category-tab:hover {
                    background: rgba(255,255,255,0.05);
                    color: #fff;
                }
                .ctf-category-tab.active {
                    background: var(--cat-color, #ef4444);
                    color: #fff;
                    border-color: var(--cat-color, #ef4444);
                }
                .ctf-category-tab .count {
                    background: rgba(255,255,255,0.2);
                    padding: 2px 8px;
                    border-radius: 10px;
                    font-size: 12px;
                }
                
                /* Challenges Grid */
                .ctf-challenges-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
                    gap: 25px;
                }
                
                /* Challenge Card */
                .ctf-challenge-card {
                    background: rgba(255,255,255,0.02);
                    border: 1px solid rgba(255,255,255,0.06);
                    border-radius: 20px;
                    padding: 25px;
                    transition: all 0.4s ease;
                    cursor: pointer;
                    position: relative;
                    overflow: hidden;
                }
                .ctf-challenge-card::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0;
                    width: 4px; height: 100%;
                    background: var(--cat-color, #ef4444);
                    opacity: 0;
                    transition: opacity 0.3s;
                }
                .ctf-challenge-card:hover {
                    transform: translateY(-5px);
                    border-color: var(--cat-color, #ef4444);
                    box-shadow: 0 15px 40px rgba(0,0,0,0.3), 0 0 30px var(--cat-glow, rgba(239,68,68,0.1));
                }
                .ctf-challenge-card:hover::before { opacity: 1; }
                .ctf-challenge-card.solved {
                    border-color: #22c55e;
                    background: rgba(34,197,94,0.05);
                }
                .ctf-challenge-card.solved::before { background: #22c55e; opacity: 1; }
                
                .ctf-card-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 15px;
                }
                .ctf-card-title {
                    font-size: 1.2rem;
                    font-weight: 700;
                    color: #fff;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .ctf-card-title .solved-check {
                    color: #22c55e;
                    font-size: 0.9rem;
                }
                .ctf-card-points {
                    background: linear-gradient(135deg, var(--cat-color, #ef4444), var(--cat-dark, #dc2626));
                    padding: 6px 14px;
                    border-radius: 20px;
                    font-size: 13px;
                    font-weight: 700;
                    color: #fff;
                }
                
                .ctf-card-desc {
                    color: rgba(255,255,255,0.6);
                    font-size: 14px;
                    line-height: 1.6;
                    margin-bottom: 15px;
                    display: -webkit-box;
                    -webkit-line-clamp: 2;
                    -webkit-box-orient: vertical;
                    overflow: hidden;
                }
                
                .ctf-card-meta {
                    display: flex;
                    gap: 12px;
                    flex-wrap: wrap;
                }
                .ctf-card-badge {
                    padding: 4px 12px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                }
                .ctf-badge-easy { background: rgba(34,197,94,0.15); color: #22c55e; }
                .ctf-badge-medium { background: rgba(245,158,11,0.15); color: #f59e0b; }
                .ctf-badge-hard { background: rgba(239,68,68,0.15); color: #ef4444; }
                
                @media (max-width: 768px) {
                    .ctf-hero-title { font-size: 2rem; }
                    .ctf-challenges-grid { grid-template-columns: 1fr; }
                    .ctf-stats-bar { gap: 15px; }
                    .ctf-stat { min-width: 100px; padding: 15px; }
                }
            </style>
            
            <!-- Hero Section -->
            <div class="ctf-hero">
                <div class="ctf-hero-content">
                    <h1 class="ctf-hero-title">
                        <i class="fa-solid fa-flag" style="margin-right: 15px;"></i>
                        CTF Practice Arena
                    </h1>
                    <p class="ctf-hero-subtitle">Master cybersecurity through hands-on Capture The Flag challenges</p>
                    
                    <div class="ctf-stats-bar">
                        <div class="ctf-stat">
                            <div class="ctf-stat-value">${progress.solved}</div>
                            <div class="ctf-stat-label">Solved</div>
                        </div>
                        <div class="ctf-stat">
                            <div class="ctf-stat-value">${progress.total}</div>
                            <div class="ctf-stat-label">Total</div>
                        </div>
                        <div class="ctf-stat">
                            <div class="ctf-stat-value">${progress.earnedPoints || 0}</div>
                            <div class="ctf-stat-label">Points</div>
                        </div>
                        <div class="ctf-stat">
                            <div class="ctf-stat-value">${progress.percentage}%</div>
                            <div class="ctf-stat-label">Progress</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="ctf-container">
                <!-- Category Tabs -->
                <div class="ctf-category-tabs">
                    <button class="ctf-category-tab active" style="--cat-color: #ef4444;" onclick="filterCTFCategory('all')" id="ctf-tab-all">
                        <i class="fa-solid fa-layer-group"></i> All
                        <span class="count">${progress.total}</span>
                    </button>
                    ${ctfCategories.map(cat => {
        const info = categoryInfo[cat] || { name: cat, icon: 'fa-puzzle-piece', color: '#888' };
        const count = CTFData[cat]?.length || 0;
        return `
                            <button class="ctf-category-tab" style="--cat-color: ${info.color};" 
                                    onclick="filterCTFCategory('${cat}')" id="ctf-tab-${cat}">
                                <i class="fa-solid ${info.icon}"></i> ${info.name}
                                <span class="count">${count}</span>
                            </button>
                        `;
    }).join('')}
                </div>
                
                <!-- Challenges Grid -->
                <div class="ctf-challenges-grid" id="ctf-challenges-container">
                    ${renderAllCTFChallenges()}
                </div>
            </div>
        </div>
    `;
}

// Render all CTF challenges
function renderAllCTFChallenges(categoryFilter = 'all') {
    if (typeof CTFData === 'undefined') {
        return '<p style="color: #888; text-align: center; padding: 40px;">No CTF challenges available.</p>';
    }

    const categoryInfo = {
        web: { color: '#3b82f6', dark: '#2563eb', glow: 'rgba(59,130,246,0.2)' },
        crypto: { color: '#8b5cf6', dark: '#7c3aed', glow: 'rgba(139,92,246,0.2)' },
        forensics: { color: '#06b6d4', dark: '#0891b2', glow: 'rgba(6,182,212,0.2)' },
        osint: { color: '#f59e0b', dark: '#d97706', glow: 'rgba(245,158,11,0.2)' },
        network: { color: '#14b8a6', dark: '#0d9488', glow: 'rgba(20,184,166,0.2)' },
        reverse: { color: '#ec4899', dark: '#db2777', glow: 'rgba(236,72,153,0.2)' }
    };

    let allChallenges = [];
    Object.entries(CTFData).forEach(([cat, challenges]) => {
        if (categoryFilter === 'all' || categoryFilter === cat) {
            allChallenges = allChallenges.concat(challenges.map(c => ({ ...c, category: cat })));
        }
    });

    if (allChallenges.length === 0) {
        return '<p style="color: #888; text-align: center; padding: 40px;">No challenges found.</p>';
    }

    return allChallenges.map(c => {
        const catInfo = categoryInfo[c.category] || { color: '#888', dark: '#666', glow: 'rgba(136,136,136,0.2)' };
        const solved = typeof isCTFSolved === 'function' && isCTFSolved(c.id);
        const diffClass = c.difficulty === 'easy' ? 'ctf-badge-easy' :
            c.difficulty === 'medium' ? 'ctf-badge-medium' : 'ctf-badge-hard';

        return `
            <div class="ctf-challenge-card ${solved ? 'solved' : ''}"
                 style="--cat-color: ${catInfo.color}; --cat-dark: ${catInfo.dark}; --cat-glow: ${catInfo.glow};"
                 onclick="openCTFChallenge('${c.id}')">
                <div class="ctf-card-header">
                    <div class="ctf-card-title">
                        ${c.title}
                        ${solved ? '<i class="fa-solid fa-circle-check solved-check"></i>' : ''}
                    </div>
                    <div class="ctf-card-points">${c.points} pts</div>
                </div>
                <div class="ctf-card-desc">${c.description}</div>
                <div class="ctf-card-meta">
                    <span class="ctf-card-badge ${diffClass}">${c.difficulty.toUpperCase()}</span>
                    <span class="ctf-card-badge" style="background: ${catInfo.color}20; color: ${catInfo.color};">
                        ${c.category.toUpperCase()}
                    </span>
                </div>
            </div>
        `;
    }).join('');
}

// Filter by category
function filterCTFCategory(category) {
    // Update tabs
    document.querySelectorAll('.ctf-category-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('ctf-tab-' + category)?.classList.add('active');

    // Re-render challenges
    const container = document.getElementById('ctf-challenges-container');
    if (container) {
        container.innerHTML = renderAllCTFChallenges(category);
    }
}

// Open challenge detail view - Redirects to Room Viewer for unified experience
function openCTFChallenge(challengeId) {
    // Check if challenge exists in the new flattened data
    const allChallenges = typeof getAllCTFChallenges === 'function' ? getAllCTFChallenges() : (typeof ctfChallengesData !== 'undefined' ? ctfChallengesData : []);
    const challenge = allChallenges.find(c => c.id === challengeId);

    if (!challenge) {
        console.error('Challenge not found:', challengeId);
        // Fallback try to find in CTFData direct object if flattened array fails
        let found = null;
        if (typeof CTFData !== 'undefined') {
            Object.values(CTFData).forEach(list => {
                const c = list.find(x => x.id === challengeId);
                if (c) found = c;
            });
        }

        if (!found) {
            console.error('Challenge truly not found (fallback):', challengeId);
            if (typeof showToast === 'function') showToast('Error: Challenge data not found', 'error');
            return;
        }
    }

    // Redirect to Room Viewer
    if (typeof loadPage === 'function') {
        loadPage('room-viewer', challengeId);
    } else {
        console.error('loadPage function not found');
    }
}

// Custom rendering logic removed in favor of unified Room Viewer
// See openCTFChallenge above which now calls loadPage('room-viewer', id)

// Submit flag
function submitCTFFlag(challengeId) {
    const input = document.getElementById('ctf-flag-input');
    const resultDiv = document.getElementById('ctf-result');
    const flag = input?.value?.trim();

    if (!flag) {
        resultDiv.className = 'ctf-cv-result error';
        resultDiv.innerHTML = '<i class="fa-solid fa-xmark"></i> Please enter a flag';
        return;
    }

    const result = typeof checkCTFFlag === 'function' ? checkCTFFlag(challengeId, flag) : { success: false };

    if (result.success) {
        resultDiv.className = 'ctf-cv-result success';
        resultDiv.innerHTML = `<i class="fa-solid fa-check"></i> Correct! You earned ${result.points} points! 🎉`;

        // Add XP if available
        if (typeof LeaguesAPI !== 'undefined' && typeof AuthState !== 'undefined' && AuthState.isLoggedIn()) {
            LeaguesAPI.addXP(result.points).catch(() => { });
        }

        if (typeof showNotification === 'function') {
            showNotification(`+${result.points} XP - Flag correct!`, 'success');
        }

        // Reload after delay
        setTimeout(() => openCTFChallenge(challengeId), 2000);
    } else {
        resultDiv.className = 'ctf-cv-result error';
        resultDiv.innerHTML = '<i class="fa-solid fa-xmark"></i> Incorrect flag. Try again!';
    }
}

// Hint system
function isHintUnlocked(challengeId, hintIndex) {
    const unlocked = JSON.parse(localStorage.getItem('ctf_hints_unlocked') || '{}');
    return unlocked[`${challengeId}_${hintIndex}`] === true;
}

function unlockCTFHint(challengeId, hintIndex) {
    const challenge = typeof getCTFChallenge === 'function' ? getCTFChallenge(challengeId) : null;
    if (!challenge) return;

    const hint = challenge.hints?.[hintIndex];
    if (!hint) return;

    if (confirm(`Unlock this hint for ${hint.cost} points?`)) {
        const unlocked = JSON.parse(localStorage.getItem('ctf_hints_unlocked') || '{}');
        unlocked[`${challengeId}_${hintIndex}`] = true;
        localStorage.setItem('ctf_hints_unlocked', JSON.stringify(unlocked));

        // Refresh the challenge view
        openCTFChallenge(challengeId);
    }
}

// Make functions globally available
window.pagePractice = pagePractice;
window.filterCTFCategory = filterCTFCategory;
window.openCTFChallenge = openCTFChallenge;
window.submitCTFFlag = submitCTFFlag;
window.unlockCTFHint = unlockCTFHint;
window.renderAllCTFChallenges = renderAllCTFChallenges;

console.log('✅ Practice Arena UI loaded');
