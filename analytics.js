// ==================== ANALYTICS SYSTEM ====================
// Complete analytics tracking and visualization system

// Analytics Data Structure
const analyticsManager = {
    // Initialize analytics data
    init() {
        if (!localStorage.getItem('userAnalytics')) {
            const defaultData = {
                totalChallenges: 0,
                completedChallenges: 0,
                totalPoints: 0,
                currentStreak: 0,
                longestStreak: 0,
                lastActivityDate: null,
                skillLevels: {
                    web: 0,
                    crypto: 0,
                    forensics: 0,
                    osint: 0,
                    network: 0
                },
                categoryStats: {
                    web: { completed: 0, total: 0, points: 0, avgTime: 0 },
                    crypto: { completed: 0, total: 0, points: 0, avgTime: 0 },
                    forensics: { completed: 0, total: 0, points: 0, avgTime: 0 },
                    osint: { completed: 0, total: 0, points: 0, avgTime: 0 },
                    network: { completed: 0, total: 0, points: 0, avgTime: 0 }
                },
                timeSpent: {}, // {challengeId: minutes}
                completionHistory: [], // [{date, challengeId, category, points, time}]
                activityCalendar: {}, // {date: count}
                achievements: []
            };
            localStorage.setItem('userAnalytics', JSON.stringify(defaultData));
        }
    },

    // Get analytics data
    getData() {
        this.init();
        return JSON.parse(localStorage.getItem('userAnalytics'));
    },

    // Save analytics data
    saveData(data) {
        localStorage.setItem('userAnalytics', JSON.stringify(data));
    },

    // Update analytics when challenge is completed
    updateOnCompletion(challengeId, category, points, timeSpent) {
        const data = this.getData();
        const today = new Date().toISOString().split('T')[0];

        // Update basic stats
        data.completedChallenges++;
        data.totalPoints += points;

        // Update category stats
        if (data.categoryStats[category]) {
            data.categoryStats[category].completed++;
            data.categoryStats[category].points += points;

            // Update average time
            const prevAvg = data.categoryStats[category].avgTime;
            const count = data.categoryStats[category].completed;
            data.categoryStats[category].avgTime = ((prevAvg * (count - 1)) + timeSpent) / count;
        }

        // Update skill levels (0-100 scale)
        data.skillLevels[category] = Math.min(100, data.skillLevels[category] + (points / 10));

        // Update time spent
        data.timeSpent[challengeId] = timeSpent;

        // Add to completion history
        data.completionHistory.push({
            date: today,
            challengeId,
            category,
            points,
            time: timeSpent,
            timestamp: Date.now()
        });

        // Update activity calendar
        data.activityCalendar[today] = (data.activityCalendar[today] || 0) + 1;

        // Update streak
        this.updateStreak(data, today);

        // Check for achievements
        this.checkAchievements(data);

        this.saveData(data);
    },

    // Update streak
    updateStreak(data, today) {
        const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

        if (data.lastActivityDate === yesterday || data.lastActivityDate === today) {
            if (data.lastActivityDate !== today) {
                data.currentStreak++;
            }
        } else if (data.lastActivityDate !== today) {
            data.currentStreak = 1;
        }

        data.longestStreak = Math.max(data.longestStreak, data.currentStreak);
        data.lastActivityDate = today;
    },

    // Check and award achievements
    checkAchievements(data) {
        const achievements = [
            { id: 'first_blood', name: 'First Blood', condition: () => data.completedChallenges === 1, icon: 'fa-flag' },
            { id: 'beginner', name: 'Beginner', condition: () => data.completedChallenges >= 5, icon: 'fa-seedling' },
            { id: 'intermediate', name: 'Intermediate', condition: () => data.completedChallenges >= 20, icon: 'fa-fire' },
            { id: 'expert', name: 'Expert', condition: () => data.completedChallenges >= 50, icon: 'fa-crown' },
            { id: 'streak_7', name: '7 Day Streak', condition: () => data.currentStreak >= 7, icon: 'fa-calendar-check' },
            { id: 'streak_30', name: '30 Day Streak', condition: () => data.currentStreak >= 30, icon: 'fa-fire-flame-curved' },
            { id: 'point_hunter', name: 'Point Hunter', condition: () => data.totalPoints >= 1000, icon: 'fa-trophy' },
            { id: 'web_master', name: 'Web Master', condition: () => data.skillLevels.web >= 80, icon: 'fa-globe' },
            { id: 'crypto_expert', name: 'Crypto Expert', condition: () => data.skillLevels.crypto >= 80, icon: 'fa-key' }
        ];

        achievements.forEach(achievement => {
            if (achievement.condition() && !data.achievements.includes(achievement.id)) {
                data.achievements.push(achievement.id);
                this.showAchievementNotification(achievement);
            }
        });
    },

    // Show achievement notification
    showAchievementNotification(achievement) {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = 'achievement-toast';
        toast.innerHTML = `
      <div class="achievement-content">
        <i class="fa-solid ${achievement.icon} achievement-icon"></i>
        <div>
          <strong>Achievement Unlocked!</strong>
          <p>${achievement.name}</p>
        </div>
      </div>
    `;
        document.body.appendChild(toast);

        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    // Get weaknesses (categories with low completion rate)
    getWeaknesses() {
        const data = this.getData();
        const weaknesses = [];

        Object.entries(data.categoryStats).forEach(([category, stats]) => {
            if (stats.total > 0) {
                const completionRate = (stats.completed / stats.total) * 100;
                if (completionRate < 50) {
                    weaknesses.push({ category, completionRate, ...stats });
                }
            }
        });

        return weaknesses.sort((a, b) => a.completionRate - b.completionRate);
    },

    // Get strengths (categories with high completion rate)
    getStrengths() {
        const data = this.getData();
        const strengths = [];

        Object.entries(data.categoryStats).forEach(([category, stats]) => {
            if (stats.total > 0) {
                const completionRate = (stats.completed / stats.total) * 100;
                if (completionRate >= 70) {
                    strengths.push({ category, completionRate, ...stats });
                }
            }
        });

        return strengths.sort((a, b) => b.completionRate - a.completionRate);
    },

    // Get recent activity (last 7 days)
    getRecentActivity() {
        const data = this.getData();
        const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);

        return data.completionHistory
            .filter(item => item.timestamp >= sevenDaysAgo)
            .sort((a, b) => b.timestamp - a.timestamp);
    },

    // Calculate level based on total points
    getLevel() {
        const data = this.getData();
        const points = data.totalPoints;

        if (points < 100) return { level: 1, name: 'Newbie', next: 100 };
        if (points < 500) return { level: 2, name: 'Beginner', next: 500 };
        if (points < 1000) return { level: 3, name: 'Intermediate', next: 1000 };
        if (points < 2500) return { level: 4, name: 'Advanced', next: 2500 };
        if (points < 5000) return { level: 5, name: 'Expert', next: 5000 };
        return { level: 6, name: 'Elite Hacker', next: null };
    },

    // Get progress to next level
    getLevelProgress() {
        const data = this.getData();
        const levelInfo = this.getLevel();

        if (!levelInfo.next) return 100;

        const prevLevelPoints = [0, 100, 500, 1000, 2500, 5000][levelInfo.level - 1];
        const pointsInLevel = data.totalPoints - prevLevelPoints;
        const pointsNeeded = levelInfo.next - prevLevelPoints;

        return Math.round((pointsInLevel / pointsNeeded) * 100);
    },

    // Reset analytics (for testing)
    reset() {
        localStorage.removeItem('userAnalytics');
        this.init();
    }
};

// Initialize on load
analyticsManager.init();

// Export for global use
window.analyticsManager = analyticsManager;
