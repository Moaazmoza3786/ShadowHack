// ==================== GAMIFICATION SYSTEM ====================

const gamification = {
    // Configuration
    config: {
        levels: [
            { level: 1, name: 'Neural Initiate', minXP: 0 },
            { level: 2, name: 'Data Scavenger', minXP: 100 },
            { level: 3, name: 'Logic Weaver', minXP: 300 },
            { level: 4, name: 'Pattern Breaker', minXP: 600 },
            { level: 5, name: 'System Architect', minXP: 1000 },
            { level: 6, name: 'Ghost in the Shell', minXP: 1500 },
            { level: 7, name: 'Neural Commander', minXP: 2200 },
            { level: 8, name: 'Quantum Auditor', minXP: 3000 },
            { level: 9, name: 'AI Overlord', minXP: 4000 },
            { level: 10, name: 'Digital Singularity', minXP: 5500 }
        ],
        xpValues: {
            challenge_easy: 50,
            challenge_medium: 100,
            challenge_hard: 200,
            read_article: 15,
            use_tool: 25,
            daily_login: 50,
            quiz_pass: 100,
            ai_gen_card: 30,
            ai_brain_sync: 50
        },
        achievements: [
            { id: 'first_blood', title: 'First Resonance', desc: 'Execute your first challenge scenario', icon: 'fa-droplet', xp: 50 },
            { id: 'tool_master', title: 'Arsenal Expert', desc: 'Deploy 5 distinct specialized tools', icon: 'fa-toolbox', xp: 100 },
            { id: 'ai_fusion', title: 'Neural Fusion', desc: 'Generate flashcards using Pulse AI', icon: 'fa-brain-circuit', xp: 150 },
            { id: 'streak_master', title: 'Consistency Pulse', desc: 'Maintain a 7-day synchronization streak', icon: 'fa-fire-flame-curved', xp: 200 },
            { id: 'quiz_whiz', title: 'Cerebral Master', desc: 'Achieve 3 perfect quiz scores', icon: 'fa-microchip', xp: 150 },
            { id: 'brain_power', title: 'Omniscience', desc: 'Sync 20+ items to Second Brain', icon: 'fa-atom', xp: 300 }
        ]
    },

    // State
    state: {
        xp: 0,
        level: 1,
        rank: 'Neural Initiate',
        achievements: [],
        streak: 0,
        lastLogin: null,
        toolsUsed: [],
        challengesCompleted: []
    },

    // Initialization
    init() {
        this.loadState();
        this.checkDailyLogin();
        this.injectStyles();
        this.updateUI();
    },

    injectStyles() {
        if (!document.getElementById('gamification-styles')) {
            const style = document.createElement('style');
            style.id = 'gamification-styles';
            style.textContent = this.getStyles();
            document.head.appendChild(style);
        }
    },

    // Load/Save State
    loadState() {
        const saved = localStorage.getItem('studyHub_gamification');
        if (saved) {
            try {
                this.state = { ...this.state, ...JSON.parse(saved) };
            } catch (e) {
                console.error('Gamification Load Error:', e);
            }
            // Fix: Sync level with XP on load to prevent premature modals
            this.syncLevelSilent();
        }
    },

    syncLevelSilent() {
        // Calculate correct level based on XP without showing modal
        const correctLevel = this.config.levels.slice().reverse().find(l => this.state.xp >= l.minXP);
        if (correctLevel && correctLevel.level > this.state.level) {
            console.log(`[Gamification] Silent Level Sync: ${this.state.level} -> ${correctLevel.level}`);
            this.state.level = correctLevel.level;
            this.state.rank = correctLevel.name;
            // We don't save immediately here to avoid write loops, state will trigger save on next action
            // But we should update UI
            this.updateUI();
        }
    },

    saveState() {
        localStorage.setItem('studyHub_gamification', JSON.stringify(this.state));
        this.updateUI();
    },

    // Core Logic
    addXP(amount, reason) {
        this.state.xp += amount;
        this.checkLevelUp();
        this.saveState();
        this.showNotification(`+${amount} XP: ${reason}`, 'xp');
    },

    checkLevelUp() {
        const currentLevel = this.state.level;
        const nextLevel = this.config.levels.slice().reverse().find(l => this.state.xp >= l.minXP);

        if (nextLevel && nextLevel.level > currentLevel) {
            this.state.level = nextLevel.level;
            this.state.rank = nextLevel.name;
            this.showLevelUpModal(nextLevel);
        }
    },

    unlockAchievement(id) {
        if (this.state.achievements.includes(id)) return;

        const achievement = this.config.achievements.find(a => a.id === id);
        if (achievement) {
            this.state.achievements.push(id);
            this.addXP(achievement.xp, `Achievement Unlocked: ${achievement.title}`);
            this.showAchievementModal(achievement);
            this.saveState();
        }
    },

    checkDailyLogin() {
        const today = new Date().toDateString();
        if (this.state.lastLogin !== today) {
            if (this.state.lastLogin === new Date(Date.now() - 86400000).toDateString()) {
                this.state.streak++;
            } else {
                this.state.streak = 1;
            }
            this.state.lastLogin = today;
            this.addXP(this.config.xpValues.daily_login, 'Daily Login Pulse');

            if (this.state.streak === 7) this.unlockAchievement('streak_master');
            this.saveState();
        }
    },

    trackToolUsage(toolName) {
        if (!this.state.toolsUsed.includes(toolName)) {
            this.state.toolsUsed.push(toolName);
            this.addXP(this.config.xpValues.use_tool, `Used tool: ${toolName}`);

            if (this.state.toolsUsed.length >= 5) this.unlockAchievement('tool_master');
            this.saveState();
        }
    },

    // UI Helpers
    showNotification(message, type = 'info') {
        const container = document.getElementById('gm-notif-container') || this.createNotifContainer();
        const notif = document.createElement('div');
        notif.className = `gm-notif gm-notif-${type}`;
        notif.innerHTML = `
            <div class="gm-notif-icon">
                <i class="fa-solid ${type === 'xp' ? 'fa-bolt-lightning' : 'fa-trophy'}"></i>
            </div>
            <div class="gm-notif-content">
                ${message}
            </div>
        `;
        container.appendChild(notif);
        setTimeout(() => {
            notif.classList.add('out');
            setTimeout(() => notif.remove(), 400);
        }, 4000);
    },

    createNotifContainer() {
        const div = document.createElement('div');
        div.id = 'gm-notif-container';
        document.body.appendChild(div);
        return div;
    },

    showLevelUpModal(level) {
        const modal = document.createElement('div');
        modal.className = 'gm-modal-overlay';
        modal.innerHTML = `
            <div class="gm-modal-content level-up-glow">
                <i class="fa-solid fa-angles-up level-icon"></i>
                <h2>NEURAL ASCENSION</h2>
                <p>You have evolved into</p>
                <h1 class="rank-name">${level.name}</h1>
                <div class="level-badge">Lvl ${level.level}</div>
                <button onclick="this.parentElement.parentElement.remove()" class="gm-close-btn">Synchronize</button>
            </div>
        `;
        document.body.appendChild(modal);
    },

    showAchievementModal(achievement) {
        this.showNotification(`🏆 Achievement Unlocked: ${achievement.title}`, 'achievement');
    },

    updateUI() {
        const xpDisplay = document.getElementById('user-xp');
        const levelDisplay = document.getElementById('user-level');
        const streakDisplay = document.getElementById('user-streak');

        if (xpDisplay) xpDisplay.innerText = `${this.state.xp} XP`;
        if (levelDisplay) levelDisplay.innerText = `Lvl ${this.state.level}`;
        if (streakDisplay) streakDisplay.innerText = `${this.state.streak}`;

        this.renderPlayerCard();
    },

    renderPlayerCard() {
        const container = document.getElementById('player-card-container');
        if (!container) return;

        const nextLevel = this.config.levels.find(l => l.level === this.state.level + 1);
        const nextLevelXp = nextLevel ? nextLevel.minXP : this.state.xp * 1.5;
        const prevLevelXp = this.config.levels.find(l => l.level === this.state.level)?.minXP || 0;

        const range = nextLevelXp - prevLevelXp;
        const currentInLevel = this.state.xp - prevLevelXp;
        const progress = Math.min(100, Math.round((currentInLevel / range) * 100));

        container.innerHTML = `
            <div class="gm-player-card">
                <div class="gm-card-top">
                    <div class="gm-rank-info">
                        <span class="gm-rank-label">${this.state.rank}</span>
                        <span class="gm-level-badge">LEVEL ${this.state.level}</span>
                    </div>
                    <div class="gm-streak-display">
                        <i class="fa-solid fa-fire"></i> ${this.state.streak}
                    </div>
                </div>
                
                <div class="gm-progress-wrapper">
                    <div class="gm-progress-label">
                        <span>NEURAL PROGRESS</span>
                        <span>${progress}%</span>
                    </div>
                    <div class="gm-progress-track">
                        <div class="gm-progress-fill" style="width: ${progress}%"></div>
                    </div>
                    <div class="gm-xp-meta">
                        <span>${this.state.xp} XP</span>
                        <span>NEXT: ${nextLevelXp}</span>
                    </div>
                </div>

                <div class="gm-achievements-mini">
                    ${this.state.achievements.slice(-4).map(id => {
            const a = this.config.achievements.find(acc => acc.id === id);
            return `<i class="fa-solid ${a?.icon || 'fa-medal'}" title="${a?.title}"></i>`;
        }).join('')}
                </div>
            </div>
        `;
    },

    getStyles() {
        return `
            #gm-notif-container { position: fixed; bottom: 30px; right: 30px; z-index: 10000; display: flex; flex-direction: column; gap: 10px; }
            .gm-notif { 
                background: rgba(22, 20, 33, 0.8); backdrop-filter: blur(15px); border: 1px solid rgba(255,255,255,0.1);
                border-radius: 16px; padding: 15px 25px; color: #fff; display: flex; align-items: center; gap: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.4); animation: gmSlideIn 0.4s cubic-bezier(0.17, 0.67, 0.83, 0.67) forwards;
            }
            .gm-notif.out { animation: gmSlideOut 0.4s forwards; }
            .gm-notif-icon { width: 35px; height: 35px; border-radius: 10px; display: flex; align-items: center; justify-content: center; background: rgba(130, 115, 221, 0.2); color: #8273DD; }
            .gm-notif-achievement .gm-notif-icon { background: rgba(245, 158, 11, 0.2); color: #F59E0B; }
            
            .gm-modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(10px); z-index: 20000; display: flex; align-items: center; justify-content: center; }
            .gm-modal-content { 
                background: #111019; border: 1px solid rgba(130, 115, 221, 0.3); border-radius: 32px;
                padding: 60px; text-align: center; max-width: 500px; position: relative;
            }
            .level-up-glow { box-shadow: 0 0 100px rgba(130, 115, 221, 0.2); }
            .level-icon { font-size: 4rem; color: #8273DD; margin-bottom: 20px; text-shadow: 0 0 20px rgba(130, 115, 221, 0.5); }
            .rank-name { font-weight: 800; font-size: 2.5rem; margin: 10px 0; background: linear-gradient(135deg, #fff, #8273DD); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
            .level-badge { display: inline-block; padding: 8px 25px; background: #8273DD; border-radius: 100px; font-weight: 800; margin-top: 20px; }
            .gm-close-btn { margin-top: 40px; width: 100%; padding: 15px; border-radius: 14px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #fff; cursor: pointer; font-weight: 700; transition: 0.3s; }
            .gm-close-btn:hover { background: #8273DD; border-color: #8273DD; }
            
            .gm-player-card { 
                background: rgba(22, 20, 33, 0.4); border: 1px solid rgba(255,255,255,0.08); 
                border-radius: 20px; padding: 20px; font-family: 'Outfit', sans-serif;
            }
            .gm-card-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
            .gm-rank-label { display: block; font-weight: 800; color: #8273DD; text-transform: uppercase; letter-spacing: 1px; font-size: 0.85rem; }
            .gm-level-badge { font-weight: 700; font-size: 0.7rem; color: #9CA3AF; }
            .gm-streak-display { background: rgba(245, 158, 11, 0.1); color: #F59E0B; padding: 4px 12px; border-radius: 8px; font-weight: 800; font-size: 0.8rem; }
            
            .gm-progress-wrapper { margin-bottom: 15px; }
            .gm-progress-label { display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 800; color: #6B7280; margin-bottom: 6px; }
            .gm-progress-track { height: 6px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden; }
            .gm-progress-fill { height: 100%; background: linear-gradient(90deg, #8273DD, #4f46e5); box-shadow: 0 0 10px rgba(130, 115, 221, 0.4); border-radius: 10px; transition: width 1s ease-out; }
            .gm-xp-meta { display: flex; justify-content: space-between; font-size: 0.65rem; color: #4B5563; font-weight: 600; margin-top: 5px; }
            
            .gm-achievements-mini { display: flex; gap: 8px; color: #4B5563; font-size: 0.9rem; }
            .gm-achievements-mini i { transition: 0.3s; }
            .gm-achievements-mini i:hover { color: #F59E0B; transform: scale(1.2); }

            @keyframes gmSlideIn { from { transform: translateX(50px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
            @keyframes gmSlideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(50px); opacity: 0; } }
        `;
    }
};

if (typeof window !== 'undefined') {
    window.gamification = gamification;
    document.addEventListener('DOMContentLoaded', () => gamification.init());
}

// Initialize on load
// Initialize on load
// document.addEventListener('DOMContentLoaded', () => {
// gamification.init();
// });

// Export for usage in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = gamification;
}
