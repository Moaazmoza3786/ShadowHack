/* ============================================================
   REAL-TIME SCOREBOARD - BreachLabs
   Global and monthly leaderboard with live updates
   ============================================================ */

const Scoreboard = {
    currentTab: 'global',
    updateInterval: null,

    // Data State
    state: {
        global: [],
        monthly: [],
        league: null,
        user: null
    },

    // Initialize
    async init() {
        this.injectStyles();
        await this.fetchData();
        this.render();
    },

    // Fetch Data from Backend
    async fetchData() {
        try {
            // Fetch Global Leaderboard (mock league_id=3 for Gold/Global)
            const globalRes = await fetch('http://localhost:5000/api/leagues/3/leaderboard');
            const globalData = await globalRes.json();

            if (globalData.success) {
                this.state.global = globalData.leaderboard.map(entry => ({
                    rank: entry.rank,
                    username: entry.user.username,
                    avatar: entry.user.avatar_url || '👤',
                    country: '🌍', // Default
                    points: entry.xp,
                    level: globalData.league.name,
                    streak: 0 // Not in this endpoint yet
                }));
                this.state.league = globalData.league;
            }

            // Fetch Current User Stats (Only if logged in)
            const token = localStorage.getItem('auth_token');
            if (token) {
                try {
                    const userRes = await fetch('http://localhost:5000/api/leagues/current', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    if (userRes.ok) {
                        const userData = await userRes.json();
                        if (userData.success) {
                            this.state.user = userData;
                        }
                    }
                } catch (err) {
                    console.warn("Failed to fetch user stats", err);
                }
            }

        } catch (e) {
            console.error("Scoreboard API Error:", e);
            // Fallback to empty if failed
        }
    },



    // Inject CSS
    injectStyles() {
        if (document.getElementById('scoreboard-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'scoreboard-styles';
        styles.textContent = `
            /* Scoreboard Container */
            .scoreboard-container {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border-radius: 20px;
                padding: 24px;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            }

            .scoreboard-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
            }

            .scoreboard-title {
                display: flex;
                align-items: center;
                gap: 12px;
                color: #fff;
                font-size: 1.5rem;
                font-weight: 700;
            }

            .scoreboard-title i {
                color: #f59e0b;
            }

            .live-badge {
                display: flex;
                align-items: center;
                gap: 6px;
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .live-dot {
                width: 8px;
                height: 8px;
                background: #ef4444;
                border-radius: 50%;
                animation: pulse-dot 1.5s infinite;
            }

            @keyframes pulse-dot {
                0%, 100% { opacity: 1; transform: scale(1); }
                50% { opacity: 0.7; transform: scale(1.2); }
            }

            /* Tabs */
            .scoreboard-tabs {
                display: flex;
                gap: 8px;
                margin-bottom: 20px;
                padding: 4px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
            }

            .scoreboard-tab {
                flex: 1;
                padding: 12px 20px;
                background: transparent;
                border: none;
                border-radius: 8px;
                color: #94a3b8;
                font-size: 0.9rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }

            .scoreboard-tab:hover {
                color: #fff;
            }

            .scoreboard-tab.active {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #fff;
            }

            /* Leaderboard Table */
            .leaderboard-table {
                width: 100%;
                border-collapse: separate;
                border-spacing: 0 8px;
            }

            .leaderboard-header {
                color: #64748b;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .leaderboard-header th {
                padding: 8px 16px;
                text-align: left;
                font-weight: 600;
            }

            .leaderboard-row {
                background: rgba(255, 255, 255, 0.05);
                transition: all 0.3s ease;
            }

            .leaderboard-row:hover {
                background: rgba(255, 255, 255, 0.1);
                transform: translateX(4px);
            }

            .leaderboard-row td {
                padding: 16px;
            }

            .leaderboard-row td:first-child {
                border-radius: 12px 0 0 12px;
            }

            .leaderboard-row td:last-child {
                border-radius: 0 12px 12px 0;
            }

            /* Top 3 special styling */
            .leaderboard-row.gold {
                background: linear-gradient(90deg, rgba(251, 191, 36, 0.2) 0%, rgba(255, 255, 255, 0.05) 100%);
            }

            .leaderboard-row.silver {
                background: linear-gradient(90deg, rgba(148, 163, 184, 0.2) 0%, rgba(255, 255, 255, 0.05) 100%);
            }

            .leaderboard-row.bronze {
                background: linear-gradient(90deg, rgba(217, 119, 6, 0.2) 0%, rgba(255, 255, 255, 0.05) 100%);
            }

            /* Rank Badge */
            .rank-badge {
                width: 36px;
                height: 36px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 10px;
                font-weight: 700;
                font-size: 1rem;
            }

            .rank-badge.rank-1 {
                background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
                color: #1e1e2e;
            }

            .rank-badge.rank-2 {
                background: linear-gradient(135deg, #94a3b8 0%, #64748b 100%);
                color: #1e1e2e;
            }

            .rank-badge.rank-3 {
                background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
                color: #fff;
            }

            .rank-badge.rank-other {
                background: rgba(255, 255, 255, 0.1);
                color: #94a3b8;
            }

            /* User Info */
            .user-cell {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .user-avatar {
                width: 44px;
                height: 44px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5rem;
                background: rgba(102, 126, 234, 0.2);
                border-radius: 12px;
            }

            .user-name {
                color: #fff;
                font-weight: 600;
                font-size: 1rem;
            }

            .user-level {
                color: #94a3b8;
                font-size: 0.75rem;
            }

            /* Points */
            .points-cell {
                color: #22c55e;
                font-weight: 700;
                font-size: 1.1rem;
                font-family: 'JetBrains Mono', monospace;
            }

            /* Streak */
            .streak-cell {
                display: flex;
                align-items: center;
                gap: 6px;
                color: #f59e0b;
                font-weight: 600;
            }

            /* Country */
            .country-cell {
                font-size: 1.5rem;
            }

            /* Your Rank Section */
            .your-rank-section {
                margin-top: 16px;
                padding: 16px;
                background: linear-gradient(90deg, rgba(102, 126, 234, 0.2) 0%, transparent 100%);
                border-radius: 12px;
                border: 1px dashed rgba(102, 126, 234, 0.3);
            }

            .your-rank-title {
                color: #94a3b8;
                font-size: 0.75rem;
                text-transform: uppercase;
                margin-bottom: 12px;
            }

            /* Stats Row */
            .stats-row {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
                margin-bottom: 24px;
            }

            .stat-card {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 16px;
                text-align: center;
            }

            .stat-value {
                color: #fff;
                font-size: 1.5rem;
                font-weight: 700;
            }

            .stat-label {
                color: #94a3b8;
                font-size: 0.75rem;
                text-transform: uppercase;
                margin-top: 4px;
            }
        `;
        document.head.appendChild(styles);
    },

    render(containerId = 'scoreboard-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Use fetched data, default to empty list if not ready
        const data = this.state.global.length ? this.state.global : [];

        container.innerHTML = `
            <div class="scoreboard-container">
                <div class="scoreboard-header">
                    <div class="scoreboard-title">
                        <i class="fa-solid fa-trophy"></i>
                        Leaderboard
                    </div>
                    <div class="live-badge">
                        <span class="live-dot"></span>
                        Live
                    </div>
                </div>

                ${this.renderStats()}

                <div class="scoreboard-tabs">
                    <button class="scoreboard-tab ${this.currentTab === 'global' ? 'active' : ''}" 
                            onclick="Scoreboard.switchTab('global')">
                        <i class="fa-solid fa-globe"></i>
                        All Time
                    </button>
                    <button class="scoreboard-tab ${this.currentTab === 'monthly' ? 'active' : ''}"
                            onclick="Scoreboard.switchTab('monthly')">
                        <i class="fa-solid fa-calendar"></i>
                        This Month
                    </button>
                </div>

                <table class="leaderboard-table">
                    <thead class="leaderboard-header">
                        <tr>
                            <th>Rank</th>
                            <th>Hacker</th>
                            <th></th>
                            <th>Points</th>
                            <th>Streak</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.map(user => this.renderRow(user)).join('')}
                    </tbody>
                </table>

                ${this.renderYourRank()}
            </div>
        `;
    },

    // Render stats
    renderStats() {
        const totalUsers = 12584;
        const activeToday = 847;
        const roomsCompleted = 45621;
        const flagsCaptured = 128540;

        return `
            <div class="stats-row">
                <div class="stat-card">
                    <div class="stat-value">${this.formatNumber(totalUsers)}</div>
                    <div class="stat-label">Total Hackers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${this.formatNumber(activeToday)}</div>
                    <div class="stat-label">Active Today</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${this.formatNumber(roomsCompleted)}</div>
                    <div class="stat-label">Rooms Completed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${this.formatNumber(flagsCaptured)}</div>
                    <div class="stat-label">Flags Captured</div>
                </div>
            </div>
        `;
    },

    // Render leaderboard row
    renderRow(user) {
        const rankClass = user.rank <= 3 ? ['', 'gold', 'silver', 'bronze'][user.rank] : '';
        const badgeClass = user.rank <= 3 ? `rank-${user.rank}` : 'rank-other';

        return `
            <tr class="leaderboard-row ${rankClass}">
                <td>
                    <div class="rank-badge ${badgeClass}">${user.rank}</div>
                </td>
                <td>
                    <div class="user-cell">
                        <div class="user-avatar">${user.avatar}</div>
                        <div>
                            <div class="user-name">${user.username}</div>
                            <div class="user-level">${user.level}</div>
                        </div>
                    </div>
                </td>
                <td class="country-cell">${user.country}</td>
                <td class="points-cell">${this.formatNumber(user.points)} XP</td>
                <td>
                    <div class="streak-cell">
                        <i class="fa-solid fa-fire"></i>
                        ${user.streak} days
                    </div>
                </td>
            </tr>
        `;
    },

    // Render your rank section
    renderYourRank() {
        // Get user's actual rank (from localStorage or session)
        const userPoints = parseInt(localStorage.getItem('userPoints') || '0');
        const userName = this.getUserName();

        return `
            <div class="your-rank-section">
                <div class="your-rank-title">Your Position</div>
                <table class="leaderboard-table" style="margin: 0;">
                    <tbody>
                        <tr class="leaderboard-row" style="background: rgba(102, 126, 234, 0.1);">
                            <td>
                                <div class="rank-badge rank-other">#?</div>
                            </td>
                            <td>
                                <div class="user-cell">
                                    <div class="user-avatar">👤</div>
                                    <div>
                                        <div class="user-name">${userName}</div>
                                        <div class="user-level">You</div>
                                    </div>
                                </div>
                            </td>
                            <td class="country-cell">🌍</td>
                            <td class="points-cell">${this.formatNumber(userPoints)} XP</td>
                            <td>
                                <div class="streak-cell">
                                    <i class="fa-solid fa-fire"></i>
                                    ${this.getUserStreak()} days
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        `;
    },

    // Switch tab
    switchTab(tab) {
        this.currentTab = tab;
        this.render();
    },

    // Format number with commas
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    // Get username
    getUserName() {
        try {
            const user = JSON.parse(sessionStorage.getItem('auth_user') || '{}');
            return user.username || user.name || 'You';
        } catch {
            return 'You';
        }
    },

    // Get user streak
    getUserStreak() {
        try {
            const progress = JSON.parse(localStorage.getItem('studyhub_progress') || '{}');
            return progress.user?.streak || 0;
        } catch {
            return 0;
        }
    },

    // Start auto-refresh
    startAutoRefresh(interval = 30000) {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        this.updateInterval = setInterval(() => this.render(), interval);
    },

    // Stop auto-refresh
    stopAutoRefresh() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }
};

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    Scoreboard.init();
});

// Export globally
window.Scoreboard = Scoreboard;
