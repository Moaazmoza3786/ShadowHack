/* ==================== DAILY CHALLENGE FEATURE ==================== */
/* Fresh challenge every day with streak tracking */

// ============== LocalStorage ==============
const DAILY_KEY = 'study_hub_daily_challenge';
const STREAK_KEY = 'study_hub_streak';

function getDailyData() {
    try {
        return JSON.parse(localStorage.getItem(DAILY_KEY) || '{}');
    } catch { return {}; }
}

function saveDailyData(data) {
    localStorage.setItem(DAILY_KEY, JSON.stringify(data));
}

function getStreak() {
    return parseInt(localStorage.getItem(STREAK_KEY) || '0');
}

function updateStreak(completed) {
    const data = getDailyData();
    const today = getTodayString();
    const yesterday = getYesterdayString();

    if (completed) {
        if (data.lastCompleted === yesterday) {
            // Continue streak
            const newStreak = getStreak() + 1;
            localStorage.setItem(STREAK_KEY, newStreak.toString());
        } else if (data.lastCompleted !== today) {
            // Reset streak (missed a day)
            localStorage.setItem(STREAK_KEY, '1');
        }
        data.lastCompleted = today;
        saveDailyData(data);
    }
}

function getTodayString() {
    return new Date().toISOString().split('T')[0];
}

function getYesterdayString() {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    return d.toISOString().split('T')[0];
}

// ============== Daily Challenge Selection ==============
function getDailyChallenge() {
    const allChallenges = typeof getAllCTFChallenges === 'function'
        ? getAllCTFChallenges()
        : (typeof ctfChallengesData !== 'undefined' ? ctfChallengesData : []);

    if (allChallenges.length === 0) return null;

    // Use date as seed for consistent daily selection
    const today = getTodayString();
    const seed = today.split('-').reduce((a, b) => a + parseInt(b), 0);
    const index = seed % allChallenges.length;

    return allChallenges[index];
}

function isDailyChallengeCompleted() {
    const data = getDailyData();
    const today = getTodayString();
    return data.completedToday === today;
}

function completeDailyChallenge() {
    const data = getDailyData();
    const today = getTodayString();

    // access specific challenge points if possible, otherwise default 100
    const challenge = getDailyChallenge();
    const points = challenge ? (challenge.points || 100) : 100;

    data.completedToday = today;
    saveDailyData(data);
    updateStreak(true);

    // Award XP if Gamification system is available
    if (window.GamificationDashboard && typeof window.GamificationDashboard.addXP === 'function') {
        window.GamificationDashboard.addXP(points + 50, 'Daily Challenge'); // Bonus 50 for daily

        // Check for streak badges
        const streak = getStreak();
        if (streak >= 7) window.GamificationDashboard.awardBadge('streak-7');
        if (streak >= 30) window.GamificationDashboard.awardBadge('streak-30');
    }
}

// ============== Daily Challenge Card (for Home Page) ==============
function getDailyChallengeCard() {
    const challenge = getDailyChallenge();
    const isCompleted = isDailyChallengeCompleted();
    const streak = getStreak();

    if (!challenge) {
        return `<div class="daily-challenge-card empty">No challenges available</div>`;
    }

    const diffColors = {
        'easy': '#28a745',
        'medium': '#ffc107',
        'hard': '#dc3545',
        'insane': '#6f42c1'
    };
    const diffColor = diffColors[challenge.difficulty?.toLowerCase()] || '#6c757d';

    return `
    <style>
        .daily-card {
            background: linear-gradient(135deg, rgba(255,193,7,0.15), rgba(255,107,107,0.15));
            border: 2px solid rgba(255,193,7,0.3);
            border-radius: 20px;
            padding: 24px;
            position: relative;
            overflow: hidden;
        }
        .daily-card::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle, rgba(255,193,7,0.1) 0%, transparent 70%);
            animation: dailyPulse 3s ease infinite;
        }
        @keyframes dailyPulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.2); opacity: 0.8; }
        }
        .daily-badge {
            position: absolute;
            top: 15px;
            right: 15px;
            background: linear-gradient(135deg, #ffd700, #ff6b6b);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 700;
            color: #000;
            text-transform: uppercase;
        }
        .daily-icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        .daily-title {
            font-size: 1.3rem;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
        }
        .daily-meta {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .daily-meta-item {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.85rem;
            color: #aaa;
        }
        .daily-streak {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,107,0,0.2);
            padding: 8px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .daily-streak-num {
            font-size: 1.5rem;
            font-weight: 800;
            color: #ff6b00;
        }
        .daily-streak-label {
            font-size: 0.8rem;
            color: #aaa;
        }
        .daily-btn {
            width: 100%;
            padding: 14px;
            border-radius: 12px;
            font-weight: 700;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            z-index: 2;
        }
        .daily-btn-start {
            background: linear-gradient(135deg, #ffc107, #ff6b6b);
            color: #000;
        }
        .daily-btn-completed {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
        }
        .daily-btn:hover {
            transform: translateY(-2px);
        }
    </style>
    
    <div class="daily-card">
        <span class="daily-badge"><i class="fas fa-calendar-day me-1"></i>Daily</span>
        
        <div class="daily-icon">🎯</div>
        
        <div class="daily-title">${challenge.title}</div>
        
        <div class="daily-meta">
            <span class="daily-meta-item">
                <span style="color: ${diffColor}; font-weight: 600;">${challenge.difficulty || 'Medium'}</span>
            </span>
            <span class="daily-meta-item">
                <i class="fas fa-star text-warning"></i> ${challenge.points} pts
            </span>
            <span class="daily-meta-item">
                <i class="fas fa-tag"></i> ${challenge.category || 'Challenge'}
            </span>
        </div>
        
        ${streak > 0 ? `
        <div class="daily-streak">
            <i class="fas fa-fire" style="color: #ff6b00; font-size: 1.5rem;"></i>
            <div>
                <div class="daily-streak-num">${streak}</div>
                <div class="daily-streak-label">day streak</div>
            </div>
        </div>
        ` : ''}
        
        ${isCompleted ? `
            <button class="daily-btn daily-btn-completed" disabled>
                <i class="fas fa-check-circle me-2"></i>Completed Today!
            </button>
        ` : `
            <button class="daily-btn daily-btn-start" onclick="loadPage('ctf-challenge', '${challenge.id}')">
                <i class="fas fa-play me-2"></i>Start Challenge
            </button>
        `}
    </div>
    `;
}

// ============== Daily Challenge Page ==============
function pageDailyChallenge() {
    const challenge = getDailyChallenge();
    const isCompleted = isDailyChallengeCompleted();
    const streak = getStreak();

    if (!challenge) {
        return `
        <div class="d-flex align-items-center justify-content-center" style="min-height: 80vh;">
            <div class="text-center">
                <i class="fas fa-calendar-times fa-4x text-secondary mb-4"></i>
                <h3 class="text-white">No Daily Challenge Available</h3>
                <p class="text-muted">Check back tomorrow!</p>
            </div>
        </div>
        `;
    }

    const diffColors = {
        'easy': '#28a745',
        'medium': '#ffc107',
        'hard': '#dc3545',
        'insane': '#6f42c1'
    };
    const diffColor = diffColors[challenge.difficulty?.toLowerCase()] || '#6c757d';

    return `
    <style>
        .daily-page {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            min-height: 100vh;
            padding: 30px;
        }
        .daily-header {
            text-align: center;
            margin-bottom: 40px;
        }
        .daily-header h1 {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffc107, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .daily-main-card {
            background: rgba(255,255,255,0.03);
            border-radius: 24px;
            padding: 40px;
            max-width: 700px;
            margin: 0 auto;
            border: 2px solid rgba(255,193,7,0.2);
        }
        .daily-challenge-title {
            font-size: 2rem;
            font-weight: 700;
            color: white;
            margin-bottom: 15px;
            text-align: center;
        }
        .daily-challenge-desc {
            color: #aaa;
            text-align: center;
            margin-bottom: 30px;
            line-height: 1.6;
        }
        .daily-stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .daily-stat {
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
        }
        .daily-stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffc107;
        }
        .daily-stat-label {
            font-size: 0.8rem;
            color: #888;
            margin-top: 5px;
        }
        .daily-action-btn {
            width: 100%;
            padding: 18px;
            border-radius: 14px;
            font-size: 1.1rem;
            font-weight: 700;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
        }
        .daily-action-btn.start {
            background: linear-gradient(135deg, #ffc107, #ff6b6b);
            color: #000;
        }
        .daily-action-btn.completed {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
        }
        .daily-action-btn:hover:not(:disabled) {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(255,193,7,0.3);
        }
    </style>

    <div class="daily-page">
        <div class="daily-header">
            <h1><i class="fas fa-calendar-star me-3"></i>Daily Challenge</h1>
            <p class="text-secondary">A new challenge awaits you every day</p>
        </div>

        <div class="daily-main-card">
            <div class="text-center mb-4">
                <span class="badge" style="background: linear-gradient(135deg, #ffc107, #ff6b6b); color: #000; padding: 8px 20px; font-size: 0.9rem;">
                    <i class="fas fa-calendar-day me-1"></i> Today's Challenge
                </span>
            </div>
            
            <h2 class="daily-challenge-title">${challenge.title}</h2>
            <p class="daily-challenge-desc">${challenge.description}</p>
            
            <div class="daily-stats-grid">
                <div class="daily-stat">
                    <div class="daily-stat-value" style="color: ${diffColor};">${challenge.difficulty || 'Medium'}</div>
                    <div class="daily-stat-label">Difficulty</div>
                </div>
                <div class="daily-stat">
                    <div class="daily-stat-value">${challenge.points}</div>
                    <div class="daily-stat-label">Points</div>
                </div>
                <div class="daily-stat">
                    <div class="daily-stat-value">${streak} 🔥</div>
                    <div class="daily-stat-label">Day Streak</div>
                </div>
            </div>
            
            ${challenge.objectives && challenge.objectives.length > 0 ? `
            <div class="mb-4">
                <h6 class="text-white mb-3"><i class="fas fa-tasks me-2"></i>Objectives</h6>
                <ul class="text-secondary">
                    ${challenge.objectives.map(obj => `<li>${obj}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
            
            ${isCompleted ? `
                <button class="daily-action-btn completed" disabled>
                    <i class="fas fa-check-circle me-2"></i>Challenge Completed!
                </button>
                <p class="text-center text-success mt-3"><i class="fas fa-clock me-1"></i>Come back tomorrow for a new challenge</p>
            ` : `
                <button class="daily-action-btn start" onclick="loadPage('ctf-challenge', '${challenge.id}')">
                    <i class="fas fa-play me-2"></i>Start Today's Challenge
                </button>
            `}
        </div>
    </div>
    `;
}

// ============== Hook into CTF completion ==============
// Override or extend the CTF solve function to track daily completion
const originalSolveCTF = window.solveCTF;
if (originalSolveCTF) {
    window.solveCTF = function (challengeId, points) {
        const result = originalSolveCTF(challengeId, points);

        // Check if this was the daily challenge
        const daily = getDailyChallenge();
        if (daily && daily.id === challengeId) {
            completeDailyChallenge();
        }

        return result;
    };
}

// ============== Exports ==============
window.pageDailyChallenge = pageDailyChallenge;
window.getDailyChallengeCard = getDailyChallengeCard;
window.getDailyChallenge = getDailyChallenge;
window.isDailyChallengeCompleted = isDailyChallengeCompleted;
window.getStreak = getStreak;
