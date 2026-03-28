/* ==================== ACHIEVEMENTS FEATURE ==================== */
/* Gamification with badges and milestones */

// ============== Achievement Definitions ==============
const ACHIEVEMENTS = [
    {
        id: 'first-blood',
        name: 'First Blood',
        icon: '🔓',
        description: 'Solve your first CTF challenge',
        criteria: (progress) => progress.ctfSolved >= 1,
        points: 50,
        rarity: 'common'
    },
    {
        id: 'sharpshooter',
        name: 'Sharpshooter',
        icon: '🎯',
        description: 'Solve 5 CTF challenges',
        criteria: (progress) => progress.ctfSolved >= 5,
        points: 100,
        rarity: 'uncommon'
    },
    {
        id: 'ctf-master',
        name: 'CTF Master',
        icon: '👑',
        description: 'Solve 15 CTF challenges',
        criteria: (progress) => progress.ctfSolved >= 15,
        points: 250,
        rarity: 'rare'
    },
    {
        id: 'binge-watcher',
        name: 'Binge Watcher',
        icon: '📺',
        description: 'Watch 10 videos',
        criteria: (progress) => progress.videosWatched >= 10,
        points: 75,
        rarity: 'common'
    },
    {
        id: 'scholar',
        name: 'Scholar',
        icon: '🎓',
        description: 'Complete 50 videos',
        criteria: (progress) => progress.videosWatched >= 50,
        points: 200,
        rarity: 'rare'
    },
    {
        id: 'collector',
        name: 'Collector',
        icon: '⭐',
        description: 'Add 5 playlists to favorites',
        criteria: (progress) => progress.favorites >= 5,
        points: 50,
        rarity: 'common'
    },
    {
        id: 'on-fire',
        name: 'On Fire',
        icon: '🔥',
        description: 'Maintain a 3-day streak',
        criteria: (progress) => progress.streak >= 3,
        points: 100,
        rarity: 'uncommon'
    },
    {
        id: 'dedicated',
        name: 'Dedicated',
        icon: '💪',
        description: 'Maintain a 7-day streak',
        criteria: (progress) => progress.streak >= 7,
        points: 200,
        rarity: 'rare'
    },
    {
        id: 'champion',
        name: 'Champion',
        icon: '🏆',
        description: 'Earn 1000+ total points',
        criteria: (progress) => progress.totalPoints >= 1000,
        points: 300,
        rarity: 'legendary'
    },
    {
        id: 'note-taker',
        name: 'Note Taker',
        icon: '📝',
        description: 'Create your first note',
        criteria: (progress) => progress.notesCount >= 1,
        points: 25,
        rarity: 'common'
    },
    {
        id: 'explorer',
        name: 'Explorer',
        icon: '🧭',
        description: 'Visit all main sections',
        criteria: (progress) => progress.sectionsVisited >= 5,
        points: 50,
        rarity: 'common'
    }
];

// ============== Progress Tracking ==============
const ACHIEVEMENTS_KEY = 'study_hub_achievements';
const ACHIEVEMENTS_UNLOCKED_KEY = 'study_hub_achievements_unlocked';

function getAchievementProgress() {
    // Gather progress from various sources
    const ctfProgress = typeof getCTFProgress === 'function' ? getCTFProgress() : { points: 0, solved: [] };
    const ytProgress = typeof window.getYtProgress === 'function' ? window.getYtProgress() : {};
    const favorites = typeof window.getYtFavorites === 'function' ? window.getYtFavorites() : [];
    const notes = JSON.parse(localStorage.getItem('study_hub_notes') || '[]');

    // Count videos watched
    let videosWatched = 0;
    Object.values(ytProgress).forEach(playlist => {
        videosWatched += (playlist || []).length;
    });

    return {
        ctfSolved: ctfProgress.solved ? ctfProgress.solved.length : 0,
        totalPoints: ctfProgress.points || 0,
        videosWatched: videosWatched,
        favorites: favorites.length,
        streak: parseInt(localStorage.getItem('study_hub_streak') || '0'),
        notesCount: notes.length,
        sectionsVisited: parseInt(localStorage.getItem('study_hub_sections_visited') || '0')
    };
}

function getUnlockedAchievements() {
    try {
        return JSON.parse(localStorage.getItem(ACHIEVEMENTS_UNLOCKED_KEY) || '[]');
    } catch { return []; }
}

function unlockAchievement(achievementId) {
    const unlocked = getUnlockedAchievements();
    if (!unlocked.includes(achievementId)) {
        unlocked.push(achievementId);
        localStorage.setItem(ACHIEVEMENTS_UNLOCKED_KEY, JSON.stringify(unlocked));

        // Show notification
        const achievement = ACHIEVEMENTS.find(a => a.id === achievementId);
        if (achievement) {
            showAchievementNotification(achievement);
        }
    }
}

function checkAndUnlockAchievements() {
    const progress = getAchievementProgress();
    const unlocked = getUnlockedAchievements();

    ACHIEVEMENTS.forEach(achievement => {
        if (!unlocked.includes(achievement.id) && achievement.criteria(progress)) {
            unlockAchievement(achievement.id);
        }
    });
}

// ============== Notification ==============
function showAchievementNotification(achievement) {
    const rarityColors = {
        common: '#6c757d',
        uncommon: '#28a745',
        rare: '#0d6efd',
        legendary: '#ffd700'
    };

    const notification = document.createElement('div');
    notification.className = 'achievement-notification';
    notification.innerHTML = `
        <div class="achievement-popup" style="border-color: ${rarityColors[achievement.rarity]}">
            <div class="achievement-icon">${achievement.icon}</div>
            <div class="achievement-info">
                <div class="achievement-title">Achievement Unlocked!</div>
                <div class="achievement-name">${achievement.name}</div>
                <div class="achievement-points">+${achievement.points} pts</div>
            </div>
        </div>
    `;

    // Add styles if not already present
    if (!document.getElementById('achievement-notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'achievement-notification-styles';
        styles.textContent = `
            .achievement-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 99999;
                animation: slideInRight 0.5s ease, fadeOut 0.5s ease 3s forwards;
            }
            .achievement-popup {
                background: rgba(20, 20, 30, 0.95);
                backdrop-filter: blur(20px);
                border-radius: 16px;
                border: 2px solid #ffd700;
                padding: 16px 24px;
                display: flex;
                align-items: center;
                gap: 16px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            }
            .achievement-icon {
                font-size: 2.5rem;
            }
            .achievement-info {
                color: white;
            }
            .achievement-title {
                font-size: 0.75rem;
                color: #888;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .achievement-name {
                font-size: 1.1rem;
                font-weight: 700;
            }
            .achievement-points {
                color: #ffd700;
                font-weight: 600;
            }
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes fadeOut {
                to { opacity: 0; transform: translateX(100%); }
            }
        `;
        document.head.appendChild(styles);
    }

    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 4000);
}

// ============== Achievements Page ==============
function pageAchievements() {
    const progress = getAchievementProgress();
    const unlocked = getUnlockedAchievements();
    const totalAchievements = ACHIEVEMENTS.length;
    const unlockedCount = unlocked.length;
    const totalPossiblePoints = ACHIEVEMENTS.reduce((sum, a) => sum + a.points, 0);
    const earnedPoints = ACHIEVEMENTS.filter(a => unlocked.includes(a.id)).reduce((sum, a) => sum + a.points, 0);

    const rarityColors = {
        common: { bg: 'rgba(108,117,125,0.2)', border: '#6c757d', text: '#adb5bd' },
        uncommon: { bg: 'rgba(40,167,69,0.2)', border: '#28a745', text: '#28a745' },
        rare: { bg: 'rgba(13,110,253,0.2)', border: '#0d6efd', text: '#0d6efd' },
        legendary: { bg: 'rgba(255,215,0,0.2)', border: '#ffd700', text: '#ffd700' }
    };

    return `
    <style>
        .achievements-page {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            min-height: 100vh;
            padding: 30px;
        }
        .ach-header {
            text-align: center;
            margin-bottom: 40px;
        }
        .ach-header h1 {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffd700, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .ach-stats {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 30px 0;
        }
        .ach-stat {
            text-align: center;
        }
        .ach-stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: #ffd700;
        }
        .ach-stat-label {
            color: #888;
            font-size: 0.9rem;
        }
        .ach-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .ach-card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 24px;
            border: 2px solid rgba(255,255,255,0.1);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        .ach-card.unlocked {
            border-color: var(--ach-color);
            background: var(--ach-bg);
        }
        .ach-card.locked {
            opacity: 0.5;
            filter: grayscale(1);
        }
        .ach-card:hover {
            transform: translateY(-5px);
        }
        .ach-icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        .ach-name {
            font-size: 1.2rem;
            font-weight: 700;
            color: white;
            margin-bottom: 5px;
        }
        .ach-desc {
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 15px;
        }
        .ach-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .ach-rarity {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        .ach-points {
            font-weight: 700;
            color: #ffd700;
        }
        .ach-unlocked-badge {
            position: absolute;
            top: 15px;
            right: 15px;
            background: #28a745;
            color: white;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
        }
    </style>

    <div class="achievements-page">
        <div class="ach-header">
            <h1><i class="fas fa-medal me-3"></i>Achievements</h1>
            <p class="text-secondary">Complete challenges to unlock badges</p>
        </div>

        <div class="ach-stats">
            <div class="ach-stat">
                <div class="ach-stat-value">${unlockedCount}/${totalAchievements}</div>
                <div class="ach-stat-label">Unlocked</div>
            </div>
            <div class="ach-stat">
                <div class="ach-stat-value">${earnedPoints}</div>
                <div class="ach-stat-label">Points Earned</div>
            </div>
            <div class="ach-stat">
                <div class="ach-stat-value">${Math.round((unlockedCount / totalAchievements) * 100)}%</div>
                <div class="ach-stat-label">Completion</div>
            </div>
        </div>

        <div class="ach-grid">
            ${ACHIEVEMENTS.map(ach => {
        const isUnlocked = unlocked.includes(ach.id);
        const colors = rarityColors[ach.rarity];
        return `
                    <div class="ach-card ${isUnlocked ? 'unlocked' : 'locked'}" 
                         style="--ach-color: ${colors.border}; --ach-bg: ${colors.bg};">
                        ${isUnlocked ? '<div class="ach-unlocked-badge"><i class="fas fa-check me-1"></i>UNLOCKED</div>' : ''}
                        <div class="ach-icon">${ach.icon}</div>
                        <div class="ach-name">${ach.name}</div>
                        <div class="ach-desc">${ach.description}</div>
                        <div class="ach-footer">
                            <span class="ach-rarity" style="color: ${colors.text}">${ach.rarity}</span>
                            <span class="ach-points">+${ach.points} pts</span>
                        </div>
                    </div>
                `;
    }).join('')}
        </div>
    </div>
    `;
}

// ============== Auto-check on page load ==============
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(checkAndUnlockAchievements, 2000);
});

// ============== Exports ==============
window.pageAchievements = pageAchievements;
window.checkAndUnlockAchievements = checkAndUnlockAchievements;
window.ACHIEVEMENTS = ACHIEVEMENTS;
