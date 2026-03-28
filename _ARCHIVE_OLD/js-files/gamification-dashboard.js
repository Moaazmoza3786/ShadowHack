/**
 * Study Hub - Gamification Dashboard System
 * Complete User Dashboard with XP, Ranks, Streaks, Skills Radar, Activity Heatmap
 */

const GamificationDashboard = {
    config: {
        xpPerCorrectAnswer: 10,
        xpPerFlag: 50,
        xpPerRootFlag: 100,
        xpPerRoomComplete: 100,
        firstBloodMultiplier: 2,
        ranks: [
            { name: 'Noob', nameAr: 'مبتدئ', minXP: 0, color: '#6b7280', icon: '👶' },
            { name: 'Script Kiddie', nameAr: 'سكربت كيدي', minXP: 500, color: '#22c55e', icon: '📜' },
            { name: 'Hacker', nameAr: 'هاكر', minXP: 2000, color: '#3b82f6', icon: '💻' },
            { name: 'Pro Pwn3r', nameAr: 'برو بونر', minXP: 5000, color: '#a855f7', icon: '🔥' },
            { name: 'Elite', nameAr: 'نخبة', minXP: 10000, color: '#f59e0b', icon: '⚡' },
            { name: 'BreachLabs Elite', nameAr: 'نخبة BreachLabs', minXP: 25000, color: '#ef4444', icon: '👑' }
        ],
        skills: ['Linux', 'Web', 'Network', 'PrivEsc', 'Forensics', 'Windows'],
        badges: [
            { id: 'streak-7', name: 'Week Warrior', nameAr: 'محارب الأسبوع', icon: '🔥' },
            { id: 'streak-30', name: 'Streak Master', nameAr: 'سيد السلسلة', icon: '🏆' },
            { id: 'bug-hunter', name: 'Bug Hunter', nameAr: 'صائد الثغرات', icon: '🐛' },
            { id: 'owl', name: 'Night Owl', nameAr: 'بومة الليل', icon: '🦉' },
            { id: 'speed-demon', name: 'Speed Demon', nameAr: 'شيطان السرعة', icon: '⚡' },
            { id: 'first-blood', name: 'First Blood', nameAr: 'الدم الأول', icon: '🩸' },
            { id: 'root-access', name: 'The Root Access', nameAr: 'وصول الروت', icon: '👑' },
            { id: 'completionist', name: 'Completionist', nameAr: 'المُتمم', icon: '✅' }
        ]
    },

    userData: null,

    init() {
        this.loadUserData();
        this.checkStreak();
    },

    loadUserData() {
        // Try to sync with global progress system if available
        if (typeof getComprehensiveStats === 'function') {
            const stats = getComprehensiveStats();

            // Get local gamification specific data (like activity heatmap history which might not be in global stats yet)
            const localData = JSON.parse(localStorage.getItem('gamificationData') || '{}');

            this.userData = {
                xp: stats.xp,
                level: stats.level,
                streak: stats.streak,

                // Keep these local for now as they are specific to this dashboard's visualizations
                skills: localData.skills || { Linux: 0, Web: 0, Network: 0, PrivEsc: 0, Forensics: 0, Windows: 0 },
                badges: localData.badges || [], // TODO: Sync with global badges
                activityLog: localData.activityLog || [],
                roomsCompleted: localData.roomsCompleted || [],
                lastRoom: localData.lastRoom || null,
                streakFreezes: localData.streakFreezes || 0,
                lastActivity: localData.lastActivity || new Date().toISOString(),
                globalRank: localData.globalRank || 1337
            };
        } else {
            const defaultData = {
                xp: 0, level: 1, streak: 0, lastActivity: null, streakFreezes: 0,
                skills: { Linux: 0, Web: 0, Network: 0, PrivEsc: 0, Forensics: 0, Windows: 0 },
                badges: [], activityLog: [], roomsCompleted: [], lastRoom: null, globalRank: 99999
            };
            this.userData = JSON.parse(localStorage.getItem('gamificationData') || JSON.stringify(defaultData));
        }
    },

    saveUserData() {
        localStorage.setItem('gamificationData', JSON.stringify(this.userData));
    },

    addXP(amount, category = null, isFirstBlood = false) {
        const multiplier = isFirstBlood ? this.config.firstBloodMultiplier : 1;
        const xpGained = amount * multiplier;
        this.userData.xp += xpGained;
        if (category && this.userData.skills[category] !== undefined) {
            this.userData.skills[category] += Math.floor(xpGained / 5);
        }
        this.userData.level = this.calculateLevel(this.userData.xp);
        this.logActivity('xp', xpGained);
        this.updateStreak();
        this.checkBadges();
        this.saveUserData();
        this.showXPPopup(xpGained, isFirstBlood);
        return xpGained;
    },

    calculateLevel(xp) {
        return Math.floor(Math.sqrt(xp / 100)) + 1;
    },

    getXPForNextLevel() {
        const currentLevel = this.userData.level;
        const nextLevelXP = Math.pow(currentLevel, 2) * 100;
        const currentLevelXP = Math.pow(currentLevel - 1, 2) * 100;
        const progressXP = this.userData.xp - currentLevelXP;
        const neededXP = nextLevelXP - currentLevelXP;
        return { current: progressXP, needed: neededXP, percent: (progressXP / neededXP) * 100 };
    },

    getCurrentRank() {
        const xp = this.userData.xp;
        let currentRank = this.config.ranks[0];
        for (const rank of this.config.ranks) {
            if (xp >= rank.minXP) currentRank = rank;
        }
        return currentRank;
    },

    updateStreak() {
        const now = new Date();
        const today = now.toDateString();
        const lastActivity = this.userData.lastActivity;
        if (!lastActivity) {
            this.userData.streak = 1;
        } else {
            const lastDate = new Date(lastActivity).toDateString();
            const yesterday = new Date(now - 86400000).toDateString();
            if (lastDate === today) { /* Already active today */ }
            else if (lastDate === yesterday) { this.userData.streak += 1; }
            else {
                if (this.userData.streakFreezes > 0) this.userData.streakFreezes -= 1;
                else this.userData.streak = 1;
            }
        }
        this.userData.lastActivity = now.toISOString();
        this.saveUserData();
    },

    checkStreak() {
        const now = new Date();
        const lastActivity = this.userData.lastActivity;
        if (!lastActivity) return;
        const lastDate = new Date(lastActivity);
        const hoursSinceActivity = (now - lastDate) / (1000 * 60 * 60);
        if (hoursSinceActivity > 24 && this.userData.streakFreezes === 0) {
            this.userData.streak = 0;
            this.saveUserData();
        }
        if (hoursSinceActivity >= 22 && hoursSinceActivity < 24) {
            this.showStreakWarning();
        }
    },

    showStreakWarning() {
        const warning = document.createElement('div');
        warning.className = 'streak-warning-banner';
        warning.innerHTML = '<div class="sw-content"><i class="fa-solid fa-fire"></i><span>شعلتك ستنطفئ! حل سؤالاً الآن!</span><button onclick="loadPage(\'practice\');this.parentElement.parentElement.remove();">حل الآن</button></div>';
        warning.style.cssText = 'position:fixed;bottom:30px;left:50%;transform:translateX(-50%);z-index:9999;';
        document.body.appendChild(warning);
        setTimeout(() => warning.remove(), 10000);
    },

    checkBadges() {
        const data = this.userData;
        if (data.streak >= 7 && !data.badges.includes('streak-7')) this.awardBadge('streak-7');
        if (data.streak >= 30 && !data.badges.includes('streak-30')) this.awardBadge('streak-30');
        if (data.roomsCompleted.length >= 10 && !data.badges.includes('completionist')) this.awardBadge('completionist');
    },

    awardBadge(badgeId) {
        const badge = this.config.badges.find(b => b.id === badgeId);
        if (!badge || this.userData.badges.includes(badgeId)) return;
        this.userData.badges.push(badgeId);
        this.saveUserData();
        this.showBadgePopup(badge);
    },

    showBadgePopup(badge) {
        const popup = document.createElement('div');
        popup.innerHTML = '<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#1a1a2e;border:2px solid #f59e0b;border-radius:20px;padding:40px;text-align:center;z-index:99999;"><div style="font-size:80px;">' + badge.icon + '</div><h3 style="color:#f59e0b;">وسام جديد!</h3><p style="color:#fff;">' + badge.nameAr + '</p></div>';
        document.body.appendChild(popup);
        setTimeout(() => popup.remove(), 4000);
    },

    logActivity(type, value) {
        const today = new Date().toDateString();
        const existing = this.userData.activityLog.find(a => a.date === today);
        if (existing) { existing.count += 1; existing.xp += value; }
        else { this.userData.activityLog.push({ date: today, count: 1, xp: value }); }
        if (this.userData.activityLog.length > 365) this.userData.activityLog.shift();
        this.saveUserData();
    },

    showXPPopup(amount, isFirstBlood) {
        const popup = document.createElement('div');
        popup.style.cssText = 'position:fixed;top:100px;right:30px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#000;padding:15px 25px;border-radius:12px;font-weight:800;font-size:18px;z-index:9999;animation:slideIn 0.3s;';
        popup.innerHTML = '<i class="fa-solid fa-bolt"></i> +' + amount + ' XP' + (isFirstBlood ? ' <span style="background:#ef4444;color:#fff;padding:3px 8px;border-radius:5px;font-size:12px;">FIRST BLOOD!</span>' : '');
        document.body.appendChild(popup);
        setTimeout(() => popup.remove(), 2500);
    },

    getUserName() {
        return localStorage.getItem('userName') || 'Hacker';
    },

    renderDashboard() {
        const lang = document.documentElement.lang === 'ar' ? 'ar' : 'en';
        const data = this.userData;
        const rank = this.getCurrentRank();
        const levelProgress = this.getXPForNextLevel();
        const userName = this.getUserName();

        return '<style>' + this.getStyles() + '</style>' +
            '<div class="gm-dashboard">' +
            // Status Bar
            '<div class="gm-status-bar">' +
            '<div class="status-item level"><div class="level-circle"><span class="level-num">' + data.level + '</span><svg class="level-ring" viewBox="0 0 36 36"><circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="3"/><circle cx="18" cy="18" r="16" fill="none" stroke="#22c55e" stroke-width="3" stroke-dasharray="' + levelProgress.percent + ', 100" transform="rotate(-90 18 18)"/></svg></div><div class="status-info"><span class="status-label">Level</span><span class="status-value">' + data.xp.toLocaleString() + ' XP</span></div></div>' +
            '<div class="status-item streak ' + (data.streak > 0 ? 'active' : '') + '"><div class="streak-fire">🔥</div><div class="status-info"><span class="status-label">Streak</span><span class="status-value">' + data.streak + ' ' + (lang === 'ar' ? 'يوم' : 'Days') + '</span></div></div>' +
            '<div class="status-item rank"><div class="rank-icon">' + rank.icon + '</div><div class="status-info"><span class="status-label">' + (lang === 'ar' ? rank.nameAr : rank.name) + '</span><span class="status-value">#' + data.globalRank.toLocaleString() + '</span></div></div>' +
            '</div>' +
            // Hero Section
            '<div class="gm-hero"><div class="hero-welcome"><h1>' + (lang === 'ar' ? 'مرحباً بعودتك' : 'Welcome back') + ', <span>' + userName + '</span>!</h1><p>' + (lang === 'ar' ? 'استمر من حيث توقفت' : 'Continue where you left off') + '</p></div>' + this.renderResumeCard(lang) + '</div>' +

            // Daily Challenge Section (New)
            (window.getDailyChallengeCard ? '<div class="mb-4">' + window.getDailyChallengeCard() + '</div>' : '') +

            // Widgets
            '<div class="gm-widgets">' +
            '<div class="gm-widget skills-widget"><h3><i class="fa-solid fa-crosshairs"></i> ' + (lang === 'ar' ? 'مصفوفة المهارات' : 'Skills Matrix') + '</h3><div class="skills-chart"><canvas id="skills-radar-chart"></canvas></div></div>' +
            '<div class="gm-widget activity-widget"><h3><i class="fa-solid fa-calendar-days"></i> ' + (lang === 'ar' ? 'خريطة النشاط' : 'Activity Heatmap') + '</h3><div class="activity-heatmap">' + this.renderActivityHeatmap() + '</div><div class="heatmap-legend"><span>' + (lang === 'ar' ? 'أقل' : 'Less') + '</span><div class="legend-boxes"><div class="lb" style="background:#1a1a2e"></div><div class="lb" style="background:#166534"></div><div class="lb" style="background:#22c55e"></div><div class="lb" style="background:#4ade80"></div><div class="lb" style="background:#86efac"></div></div><span>' + (lang === 'ar' ? 'أكثر' : 'More') + '</span></div></div>' +
            '<div class="gm-widget leaderboard-widget"><h3><i class="fa-solid fa-ranking-star"></i> ' + (lang === 'ar' ? 'المتصدرون' : 'Leaderboard') + '</h3><div class="mini-leaderboard">' + this.renderMiniLeaderboard() + '</div><a href="#" onclick="loadPage(\'leaderboard\')" class="widget-link">' + (lang === 'ar' ? 'عرض الكل' : 'View All') + ' <i class="fa-solid fa-arrow-right"></i></a></div>' +
            '<div class="gm-widget badges-widget"><h3><i class="fa-solid fa-medal"></i> ' + (lang === 'ar' ? 'الأوسمة' : 'Badges') + '</h3><div class="badges-grid">' + this.renderBadges() + '</div></div>' +
            '</div>' +
            // Quick Actions
            '<div class="gm-quick-actions">' +
            '<button onclick="loadPage(\'practice\')" class="quick-action-btn primary"><i class="fa-solid fa-flag"></i> ' + (lang === 'ar' ? 'حل تحدي' : 'Solve Challenge') + '</button>' +
            '<button onclick="loadPage(\'learn\')" class="quick-action-btn"><i class="fa-solid fa-book"></i> ' + (lang === 'ar' ? 'تعلم جديد' : 'Learn New') + '</button>' +
            '<button onclick="loadPage(\'leaderboard\')" class="quick-action-btn"><i class="fa-solid fa-trophy"></i> ' + (lang === 'ar' ? 'المتصدرون' : 'Leaderboards') + '</button>' +
            '</div>' +
            '</div>';
    },

    renderResumeCard(lang) {
        const lastRoom = this.userData.lastRoom;
        if (!lastRoom) {
            return '<div class="resume-card empty"><i class="fa-solid fa-rocket"></i><h3>' + (lang === 'ar' ? 'ابدأ رحلتك!' : 'Start Your Journey!') + '</h3><p>' + (lang === 'ar' ? 'لم تبدأ أي مسار بعد' : 'You have not started any path yet') + '</p><button onclick="loadPage(\'learn\')" class="resume-btn">' + (lang === 'ar' ? 'ابدأ الآن' : 'Start Now') + '</button></div>';
        }
        return '<div class="resume-card"><div class="resume-path-icon" style="background:' + (lastRoom.color || '#22c55e') + '"><i class="fa-solid ' + (lastRoom.icon || 'fa-shield-halved') + '"></i></div><div class="resume-info"><span class="resume-path">' + (lastRoom.pathName || 'Jr Penetration Tester') + '</span><h3>' + (lastRoom.roomName || 'Current Room') + '</h3><div class="resume-progress"><div class="progress-bar"><div class="progress-fill" style="width:' + (lastRoom.progress || 0) + '%"></div></div><span>' + (lastRoom.progress || 0) + '%</span></div></div><button onclick="loadPage(\'room-viewer\',\'' + lastRoom.roomId + '\')" class="resume-btn"><i class="fa-solid fa-play"></i> ' + (lang === 'ar' ? 'استمر' : 'Continue') + '</button></div>';
    },

    renderActivityHeatmap() {
        const activityLog = this.userData.activityLog;
        const today = new Date();
        let html = '<div class="heatmap-grid">';
        for (let i = 364; i >= 0; i--) {
            const date = new Date(today - i * 86400000);
            const dateStr = date.toDateString();
            const activity = activityLog.find(a => a.date === dateStr);
            const count = activity ? activity.count : 0;
            let level = 0;
            if (count >= 10) level = 4;
            else if (count >= 5) level = 3;
            else if (count >= 2) level = 2;
            else if (count >= 1) level = 1;
            html += '<div class="heatmap-cell level-' + level + '" title="' + dateStr + ': ' + count + '"></div>';
        }
        return html + '</div>';
    },

    renderMiniLeaderboard() {
        const leaders = [
            { rank: 1, name: 'D4rkW@ve', xp: 45230, avatar: '🥇' },
            { rank: 2, name: 'CyberShadow', xp: 38120, avatar: '🥈' },
            { rank: 3, name: 'NullByte', xp: 35890, avatar: '🥉' },
            { rank: 4, name: 'ZeroDay', xp: 32100, avatar: '4️⃣' },
            { rank: 5, name: 'PhantomX', xp: 28750, avatar: '5️⃣' }
        ];
        return leaders.map(l => '<div class="leaderboard-item' + (l.rank <= 3 ? ' top-' + l.rank : '') + '"><span class="lb-rank">' + l.avatar + '</span><span class="lb-name">' + l.name + '</span><span class="lb-xp">' + l.xp.toLocaleString() + ' XP</span></div>').join('');
    },

    renderBadges() {
        const earnedBadges = this.userData.badges;
        return this.config.badges.map(badge => {
            const earned = earnedBadges.includes(badge.id);
            return '<div class="badge-item ' + (earned ? 'earned' : 'locked') + '"><span class="badge-icon">' + badge.icon + '</span><span class="badge-name">' + badge.nameAr + '</span></div>';
        }).join('');
    },

    initSkillsRadar() {
        const canvas = document.getElementById('skills-radar-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const skills = this.userData.skills;
        const labels = Object.keys(skills);
        const values = Object.values(skills);
        const maxValue = Math.max(...values, 100);
        canvas.width = 300; canvas.height = 300;
        const centerX = 150, centerY = 150, radius = 100;
        for (let layer = 5; layer >= 1; layer--) {
            const layerRadius = (radius * layer) / 5;
            ctx.beginPath();
            for (let i = 0; i < 6; i++) {
                const angle = (Math.PI * 2 * i) / 6 - Math.PI / 2;
                const x = centerX + layerRadius * Math.cos(angle);
                const y = centerY + layerRadius * Math.sin(angle);
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            }
            ctx.closePath();
            ctx.strokeStyle = 'rgba(34,197,94,0.1)';
            ctx.stroke();
        }
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
            const angle = (Math.PI * 2 * i) / 6 - Math.PI / 2;
            const value = values[i] / maxValue;
            const x = centerX + radius * value * Math.cos(angle);
            const y = centerY + radius * value * Math.sin(angle);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.closePath();
        ctx.fillStyle = 'rgba(34,197,94,0.3)';
        ctx.fill();
        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.fillStyle = '#fff';
        ctx.font = '12px Cairo';
        ctx.textAlign = 'center';
        for (let i = 0; i < 6; i++) {
            const angle = (Math.PI * 2 * i) / 6 - Math.PI / 2;
            const x = centerX + (radius + 20) * Math.cos(angle);
            const y = centerY + (radius + 20) * Math.sin(angle);
            ctx.fillText(labels[i], x, y + 4);
        }
    },

    getStyles() {
        return `
            .gm-dashboard { padding: 30px; max-width: 1400px; margin: 0 auto; color: var(--text-primary, #fff); }
            .gm-status-bar { display: flex; justify-content: center; gap: 40px; padding: 25px; background: var(--bg-secondary, rgba(30,41,59,0.8)); border-radius: 20px; border: 1px solid var(--border-color, rgba(34,197,94,0.2)); margin-bottom: 30px; }
            .status-item { display: flex; align-items: center; gap: 15px; }
            .level-circle { position: relative; width: 60px; height: 60px; }
            .level-num { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 24px; font-weight: 800; color: #22c55e; font-family: Orbitron, sans-serif; }
            .level-ring { width: 100%; height: 100%; }
            .status-info { display: flex; flex-direction: column; }
            .status-label { font-size: 12px; color: var(--text-muted, #94a3b8); text-transform: uppercase; letter-spacing: 1px; }
            .status-value { font-size: 18px; font-weight: 700; color: var(--text-primary, #fff); }
            .streak-fire { font-size: 40px; filter: grayscale(1); transition: filter 0.3s; }
            .streak.active .streak-fire { filter: none; animation: fire-pulse 1s infinite; }
            @keyframes fire-pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
            .rank-icon { font-size: 40px; }
            
            .gm-hero { background: var(--bg-card, rgba(34,197,94,0.1)); border-radius: 20px; padding: 30px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; gap: 30px; flex-wrap: wrap; border: 1px solid var(--border-color, rgba(255,255,255,0.1)); }
            .hero-welcome h1 { font-size: 32px; color: var(--text-primary, #fff); margin: 0; }
            .hero-welcome h1 span { color: #22c55e; }
            .hero-welcome p { color: var(--text-muted, #94a3b8); margin: 5px 0 0; }
            
            .resume-card { display: flex; align-items: center; gap: 20px; background: var(--bg-secondary, rgba(0,0,0,0.3)); padding: 20px 30px; border-radius: 15px; border: 1px solid var(--border-color, rgba(255,255,255,0.1)); }
            .resume-card.empty { flex-direction: column; text-align: center; padding: 40px; }
            .resume-card.empty i { font-size: 50px; color: #22c55e; }
            .resume-path-icon { width: 60px; height: 60px; border-radius: 15px; display: flex; align-items: center; justify-content: center; font-size: 28px; color: #000; }
            .resume-info { flex: 1; }
            .resume-path { font-size: 12px; color: var(--text-muted, #94a3b8); text-transform: uppercase; }
            .resume-info h3 { color: var(--text-primary, #fff); margin: 5px 0; font-size: 18px; }
            .resume-progress { display: flex; align-items: center; gap: 10px; }
            .progress-bar { width: 150px; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; }
            .progress-fill { height: 100%; background: linear-gradient(90deg, #22c55e, #4ade80); border-radius: 4px; }
            .resume-progress span { color: #22c55e; font-weight: 600; }
            .resume-btn { padding: 15px 30px; background: linear-gradient(135deg, #22c55e, #16a34a); border: none; border-radius: 12px; color: #000; font-weight: 700; font-size: 16px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: all 0.3s; }
            .resume-btn:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(34,197,94,0.4); }
            
            .gm-widgets { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 25px; margin-bottom: 30px; }
            .gm-widget { background: var(--bg-card, rgba(30,41,59,0.8)); border-radius: 20px; padding: 25px; border: 1px solid var(--border-color, rgba(255,255,255,0.1)); }
            .gm-widget h3 { color: var(--text-primary, #fff); margin: 0 0 20px; font-size: 16px; display: flex; align-items: center; gap: 10px; }
            .gm-widget h3 i { color: #22c55e; }
            .skills-chart { display: flex; justify-content: center; }
            
            .heatmap-grid { display: grid; grid-template-columns: repeat(52, 1fr); grid-template-rows: repeat(7, 1fr); gap: 3px; grid-auto-flow: column; }
            .heatmap-cell { width: 12px; height: 12px; border-radius: 2px; background: var(--bg-hover, #1a1a2e); }
            .heatmap-cell.level-1 { background: #166534; }
            .heatmap-cell.level-2 { background: #22c55e; }
            .heatmap-cell.level-3 { background: #4ade80; }
            .heatmap-cell.level-4 { background: #86efac; }
            
            .heatmap-legend { display: flex; justify-content: flex-end; align-items: center; gap: 8px; margin-top: 15px; font-size: 11px; color: var(--text-muted, #64748b); }
            .legend-boxes { display: flex; gap: 4px; }
            .lb { width: 12px; height: 12px; border-radius: 2px; }
            
            .mini-leaderboard { display: flex; flex-direction: column; gap: 10px; }
            .leaderboard-item { display: flex; align-items: center; padding: 12px 15px; background: var(--bg-secondary, rgba(255,255,255,0.05)); border-radius: 10px; transition: all 0.2s; }
            .leaderboard-item:hover { background: var(--bg-hover, rgba(34,197,94,0.1)); }
            .leaderboard-item.top-1 { border-left: 3px solid #ffd700; }
            .leaderboard-item.top-2 { border-left: 3px solid #c0c0c0; }
            .leaderboard-item.top-3 { border-left: 3px solid #cd7f32; }
            .lb-rank { font-size: 20px; margin-right: 15px; }
            .lb-name { flex: 1; color: var(--text-primary, #fff); font-weight: 600; }
            .lb-xp { color: #22c55e; font-family: JetBrains Mono, monospace; font-size: 13px; }
            
            .widget-link { display: block; text-align: center; color: #3b82f6; text-decoration: none; margin-top: 15px; font-size: 13px; }
            
            .badges-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }
            .badge-item { display: flex; flex-direction: column; align-items: center; padding: 15px 10px; background: var(--bg-secondary, rgba(255,255,255,0.05)); border-radius: 12px; transition: all 0.3s; }
            .badge-item.locked { filter: grayscale(1); opacity: 0.5; }
            .badge-item.earned { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); }
            .badge-icon { font-size: 28px; margin-bottom: 8px; }
            .badge-name { font-size: 11px; color: var(--text-muted, #94a3b8); text-align: center; }
            
            .gm-quick-actions { display: flex; justify-content: center; gap: 15px; flex-wrap: wrap; }
            .quick-action-btn { padding: 15px 30px; background: var(--bg-secondary, rgba(255,255,255,0.08)); border: 1px solid var(--border-color, rgba(255,255,255,0.1)); border-radius: 12px; color: var(--text-primary, #fff); font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: all 0.3s; }
            .quick-action-btn:hover { background: rgba(34,197,94,0.1); border-color: #22c55e; }
            .quick-action-btn.primary { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; border: none; }
            
            @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
            @media (max-width: 768px) {
                .gm-status-bar { flex-direction: column; gap: 20px; }
                .gm-hero { flex-direction: column; text-align: center; }
                .resume-card { flex-direction: column; }
                .badges-grid { grid-template-columns: repeat(2, 1fr); }
            }
        `;
    }
};

function pageDashboard() {
    GamificationDashboard.loadUserData(); // Sync data before rendering
    setTimeout(() => GamificationDashboard.initSkillsRadar(), 100);
    return GamificationDashboard.renderDashboard();
}

document.addEventListener('DOMContentLoaded', () => GamificationDashboard.init());

// ==================== NEW PAGE EXPORTS ====================

function pageLeaderboard() {
    const lang = document.documentElement.lang === 'ar' ? 'ar' : 'en';
    const leaders = [
        { rank: 1, name: 'D4rkW@ve', xp: 45230, avatar: '🥇', level: 42, badge: 'Cyber Legend' },
        { rank: 2, name: 'CyberShadow', xp: 38120, avatar: '🥈', level: 38, badge: 'Elite' },
        { rank: 3, name: 'NullByte', xp: 35890, avatar: '🥉', level: 35, badge: 'Elite' },
        { rank: 4, name: 'ZeroDay', xp: 32100, avatar: '4️⃣', level: 31, badge: 'Pro Pwn3r' },
        { rank: 5, name: 'PhantomX', xp: 28750, avatar: '5️⃣', level: 28, badge: 'Pro Pwn3r' },
        { rank: 6, name: 'MrRobot', xp: 25400, avatar: '🤖', level: 25, badge: 'Hacker' },
        { rank: 7, name: 'NetRunner', xp: 22100, avatar: '🌐', level: 22, badge: 'Hacker' },
        { rank: 8, name: 'ByteMaster', xp: 18900, avatar: '💾', level: 19, badge: 'Script Kiddie' },
        { rank: 9, name: 'You', xp: GamificationDashboard.userData ? GamificationDashboard.userData.xp : 0, avatar: '👤', level: GamificationDashboard.userData ? GamificationDashboard.userData.level : 1, badge: 'Current Rank', highlight: true },
        { rank: 10, name: 'Newbie', xp: 1200, avatar: '👶', level: 2, badge: 'Noob' }
    ].sort((a, b) => b.xp - a.xp);

    // Re-rank after sort in case user moved up
    leaders.forEach((l, i) => l.rank = i + 1);

    return `
    <div class="container mt-5">
        <h1 class="text-center text-white mb-5 display-4 fw-bold"><i class="fas fa-trophy text-warning"></i> ${lang === 'ar' ? 'لوحة المتصدرين' : 'Global Leaderboard'}</h1>
        
        <div class="cyber-card p-4 mx-auto" style="max-width: 800px; background: rgba(30,41,59,0.9);">
            <div class="d-flex justify-content-between text-muted mb-3 px-3">
                <span>RANK</span>
                <span>HACKER</span>
                <span>LEVEL</span>
                <span>XP</span>
            </div>
            
            ${leaders.map(l => `
                <div class="d-flex align-items-center p-3 mb-2 rounded ${l.highlight ? 'border border-success bg-success bg-opacity-10' : 'bg-dark bg-opacity-50'}" 
                     style="transition: transform 0.2s;">
                    <div class="fw-bold fs-4 text-center" style="width: 50px; color: ${l.rank <= 3 ? '#fbbf24' : '#9ca3af'}">#${l.rank}</div>
                    <div class="ms-3 d-flex align-items-center flex-grow-1">
                        <span class="fs-4 me-3">${l.avatar}</span>
                        <div>
                            <div class="fw-bold text-white">${l.name}</div>
                            <small class="text-muted">${l.badge}</small>
                        </div>
                    </div>
                    <div class="text-center text-info fw-bold" style="width: 80px;">Lvl ${l.level}</div>
                    <div class="text-end fw-bold text-success font-monospace" style="width: 100px;">${l.xp.toLocaleString()}</div>
                </div>
            `).join('')}
        </div>
    </div>`;
}

function pageAchievements() {
    const lang = document.documentElement.lang === 'ar' ? 'ar' : 'en';
    const badges = GamificationDashboard.config.badges;
    const earned = GamificationDashboard.userData ? GamificationDashboard.userData.badges : [];

    return `
    <div class="container mt-5">
        <h1 class="text-center text-white mb-5 display-4 fw-bold"><i class="fas fa-medal text-info"></i> ${lang === 'ar' ? 'الإنجازات والأوسمة' : 'Achievements & Badges'}</h1>
        
        <div class="row g-4 justify-content-center">
            ${badges.map(b => {
        const isEarned = earned.includes(b.id);
        return `
                <div class="col-md-3 col-sm-6">
                    <div class="cyber-card h-100 p-4 text-center ${isEarned ? 'border-warning' : 'border-secondary opacity-50'}" 
                         style="background: ${isEarned ? 'rgba(245, 158, 11, 0.1)' : 'rgba(0,0,0,0.3)'}">
                        <div class="display-1 mb-3">${b.icon}</div>
                        <h4 class="text-white mb-2">${lang === 'ar' ? b.nameAr : b.name}</h4>
                        ${isEarned
                ? `<span class="badge bg-warning text-dark">UNLOCKED</span>`
                : `<span class="badge bg-secondary"><i class="fas fa-lock"></i> LOCKED</span>`}
                    </div>
                </div>`;
    }).join('')}
        </div>
    </div>`;
}

// function pageDailyChallenge() removed to use the implementation from daily-challenge.js

window.GamificationDashboard = GamificationDashboard;
window.pageDashboard = pageDashboard;
window.pageLeaderboard = pageLeaderboard;
window.pageAchievements = pageAchievements;
// window.pageDailyChallenge = pageDailyChallenge; // Removed to avoid conflict

