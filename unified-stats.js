/* ==================== UNIFIED STATS AGGREGATOR 📊 ==================== */
/* Multi-Platform Progress Tracker: HTB, THM, PortSwigger */

window.UnifiedStats = {
    state: {
        tab: 'overview',
        htb: { connected: false, token: '', data: null },
        thm: { connected: false, username: '', data: null },
        portswigger: { connected: false, email: '', data: null },
        activities: []
    },

    // Platform configs
    platforms: {
        htb: { name: 'Hack The Box', icon: '🟩', color: '#9fef00', url: 'https://hackthebox.com' },
        thm: { name: 'TryHackMe', icon: '🔴', color: '#ef4444', url: 'https://tryhackme.com' },
        portswigger: { name: 'PortSwigger', icon: '🟠', color: '#ff6b35', url: 'https://portswigger.net' }
    },

    // Demo data (replace with real API calls)
    demoData: {
        htb: {
            username: 'h4ck3r_pr0',
            rank: 'Hacker',
            points: 4250,
            globalRank: 1542,
            ownership: { user: 45, system: 38 },
            machines: [
                { name: 'Keeper', difficulty: 'Easy', date: '2024-01-02', points: 20 },
                { name: 'Codify', difficulty: 'Easy', date: '2024-01-01', points: 20 },
                { name: 'Devvortex', difficulty: 'Easy', date: '2023-12-28', points: 20 },
                { name: 'Cybermonday', difficulty: 'Hard', date: '2023-12-25', points: 40 }
            ],
            challenges: 28,
            proLabs: ['Offshore', 'RastaLabs']
        },
        thm: {
            username: 'cyber_ninja',
            rank: '0x8 [Hacker]',
            points: 12450,
            globalRank: 8234,
            streak: 45,
            badges: 23,
            rooms: [
                { name: 'Buffer Overflow Prep', difficulty: 'Medium', date: '2024-01-03', completed: true },
                { name: 'AD Basics', difficulty: 'Easy', date: '2024-01-02', completed: true },
                { name: 'Web Fundamentals', difficulty: 'Easy', date: '2023-12-30', completed: true }
            ],
            paths: { completed: 4, total: 8 },
            achievements: ['Advent of Cyber 2023', '7 Day Streak', 'First Blood']
        },
        portswigger: {
            username: 'websec_master',
            level: 'Apprentice',
            labsSolved: 85,
            totalLabs: 250,
            topics: [
                { name: 'SQL Injection', solved: 12, total: 18 },
                { name: 'XSS', solved: 10, total: 15 },
                { name: 'CSRF', solved: 8, total: 8 },
                { name: 'SSRF', solved: 5, total: 7 },
                { name: 'XXE', solved: 6, total: 9 },
                { name: 'Access Control', solved: 13, total: 13 }
            ],
            recentLabs: [
                { name: 'Blind SQL injection with conditional responses', date: '2024-01-03' },
                { name: 'DOM XSS using web messages', date: '2024-01-02' }
            ]
        }
    },

    render() {
        const s = this.state;
        return `
        <div class="usa fade-in">
            <div class="usa-h">
                <h1>📊 Unified Stats Aggregator</h1>
                <p>All your security training progress in one place</p>
            </div>
            <div class="usa-tabs">
                <button class="${s.tab === 'overview' ? 'act' : ''}" onclick="UnifiedStats.tab('overview')">📈 Overview</button>
                <button class="${s.tab === 'platforms' ? 'act' : ''}" onclick="UnifiedStats.tab('platforms')">🔗 Platforms</button>
                <button class="${s.tab === 'activity' ? 'act' : ''}" onclick="UnifiedStats.tab('activity')">📋 Activity</button>
                <button class="${s.tab === 'settings' ? 'act' : ''}" onclick="UnifiedStats.tab('settings')">⚙️ Settings</button>
            </div>
            <div class="usa-body">${this.renderTab()}</div>
        </div>
        <style>
        .usa{min-height:100vh;background:linear-gradient(135deg,#0a0a12,#1a1a2e);color:#e0e0e0;padding:20px;font-family:system-ui}
        .usa-h h1{margin:0;color:#8b5cf6;font-size:1.8rem}.usa-h p{color:#888;margin:5px 0 20px}
        .usa-tabs{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}.usa-tabs button{padding:12px 24px;background:rgba(255,255,255,.05);border:1px solid #333;border-radius:8px;color:#888;cursor:pointer}
        .usa-tabs button:hover{border-color:#8b5cf6;color:#8b5cf6}.usa-tabs button.act{background:#8b5cf6;color:#fff;border-color:#8b5cf6}
        .usa-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:25px}
        .stat-card{background:rgba(0,0,0,.4);padding:25px;border-radius:12px;text-align:center;border-left:4px solid}
        .stat-card h2{margin:0;font-size:2.5rem}.stat-card p{margin:5px 0 0;color:#888}
        .stat-card.htb{border-color:#9fef00}.stat-card.thm{border-color:#ef4444}.stat-card.portswigger{border-color:#ff6b35}
        .stat-card h2.htb{color:#9fef00}.stat-card h2.thm{color:#ef4444}.stat-card h2.portswigger{color:#ff6b35}
        .platform-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px}
        .platform-card{background:rgba(0,0,0,.4);border-radius:12px;overflow:hidden}
        .platform-header{padding:20px;display:flex;align-items:center;gap:15px}
        .platform-icon{font-size:2.5rem}.platform-info h3{margin:0;color:#fff}.platform-info p{margin:5px 0 0;color:#888}
        .platform-stats{padding:20px;display:grid;grid-template-columns:repeat(3,1fr);gap:15px;background:rgba(0,0,0,.2)}
        .p-stat{text-align:center}.p-stat-val{font-size:1.5rem;font-weight:bold;display:block}.p-stat-lbl{font-size:.8rem;color:#888}
        .platform-machines{padding:20px}
        .platform-machines h4{margin:0 0 15px;color:#888}
        .machine-list{display:flex;flex-direction:column;gap:8px}
        .machine-item{display:flex;justify-content:space-between;align-items:center;padding:10px;background:#0a0a12;border-radius:8px}
        .machine-name{color:#fff}.machine-diff{padding:2px 8px;border-radius:4px;font-size:.75rem}
        .machine-diff.Easy{background:rgba(34,197,94,.2);color:#22c55e}.machine-diff.Medium{background:rgba(245,158,11,.2);color:#f59e0b}.machine-diff.Hard{background:rgba(239,68,68,.2);color:#ef4444}
        .machine-date{color:#666;font-size:.85rem}
        .chart-container{background:rgba(0,0,0,.4);padding:25px;border-radius:12px;margin-bottom:20px}
        .chart-container h3{margin:0 0 20px;color:#8b5cf6}
        .bar-chart{display:flex;align-items:flex-end;height:200px;gap:30px;justify-content:center}
        .bar-group{display:flex;flex-direction:column;align-items:center;gap:10px}
        .bar{width:60px;border-radius:8px 8px 0 0;transition:.3s}.bar:hover{opacity:.8}
        .bar-label{color:#888;font-size:.85rem}
        .progress-section{margin-bottom:20px}
        .progress-section h4{margin:0 0 15px;color:#fff}
        .progress-bars{display:flex;flex-direction:column;gap:12px}
        .progress-row{display:flex;align-items:center;gap:15px}
        .progress-name{width:120px;color:#888;font-size:.9rem}
        .progress-bar{flex:1;height:8px;background:#333;border-radius:4px;overflow:hidden}
        .progress-fill{height:100%;border-radius:4px;transition:.3s}
        .progress-pct{width:50px;text-align:right;color:#fff;font-size:.9rem}
        .activity-list{display:flex;flex-direction:column;gap:10px}
        .activity-item{display:flex;align-items:center;gap:15px;padding:15px;background:rgba(0,0,0,.4);border-radius:10px}
        .activity-icon{font-size:1.5rem}.activity-info{flex:1}
        .activity-info h4{margin:0;color:#fff}.activity-info p{margin:5px 0 0;color:#888;font-size:.9rem}
        .activity-meta{text-align:right}.activity-platform{font-size:.8rem;padding:3px 8px;border-radius:4px}.activity-date{color:#666;font-size:.8rem;margin-top:5px}
        .settings-section{background:rgba(0,0,0,.4);padding:25px;border-radius:12px;margin-bottom:20px}
        .settings-section h3{margin:0 0 20px;color:#8b5cf6}
        .api-input{display:flex;gap:10px;margin-bottom:15px}
        .api-input input{flex:1;padding:12px;background:#0a0a12;border:1px solid #333;border-radius:8px;color:#fff}
        .api-input button{padding:12px 20px;border-radius:8px;cursor:pointer;border:none}
        .btn-connect{background:#22c55e;color:#fff}.btn-disconnect{background:#ef4444;color:#fff}
        .connected-badge{display:inline-flex;align-items:center;gap:8px;padding:8px 15px;background:rgba(34,197,94,.2);border-radius:8px;color:#22c55e;margin-bottom:15px}
        .total-card{background:linear-gradient(135deg,#8b5cf6,#6366f1);padding:30px;border-radius:16px;text-align:center;margin-bottom:25px}
        .total-card h2{margin:0;font-size:3.5rem;color:#fff}.total-card p{margin:10px 0 0;color:rgba(255,255,255,.8)}
        .rank-badges{display:flex;justify-content:center;gap:20px;margin-top:20px;flex-wrap:wrap}
        .rank-badge{padding:10px 20px;background:rgba(255,255,255,.1);border-radius:8px;text-align:center}
        .rank-badge .platform{font-size:.8rem;color:rgba(255,255,255,.7)}.rank-badge .rank{font-weight:bold;color:#fff}
        @media(max-width:900px){.usa-grid{grid-template-columns:1fr}.platform-grid{grid-template-columns:1fr}}
        </style>`;
    },

    renderTab() {
        switch (this.state.tab) {
            case 'overview': return this.renderOverview();
            case 'platforms': return this.renderPlatforms();
            case 'activity': return this.renderActivity();
            case 'settings': return this.renderSettings();
        }
    },

    renderOverview() {
        const htb = this.demoData.htb;
        const thm = this.demoData.thm;
        const ps = this.demoData.portswigger;
        const totalPoints = htb.points + thm.points;
        const totalMachines = htb.ownership.user + htb.ownership.system + thm.rooms.length + ps.labsSolved;

        return `
            <div class="total-card">
                <h2>${totalPoints.toLocaleString()}</h2>
                <p>Combined Points (HTB + THM)</p>
                <div class="rank-badges">
                    <div class="rank-badge"><div class="platform">🟩 HTB</div><div class="rank">${htb.rank}</div></div>
                    <div class="rank-badge"><div class="platform">🔴 THM</div><div class="rank">${thm.rank}</div></div>
                    <div class="rank-badge"><div class="platform">🟠 PortSwigger</div><div class="rank">${ps.level}</div></div>
                </div>
            </div>
            
            <div class="usa-grid">
                <div class="stat-card htb"><h2 class="htb">${htb.points}</h2><p>HTB Points</p></div>
                <div class="stat-card thm"><h2 class="thm">${thm.points}</h2><p>THM Points</p></div>
                <div class="stat-card portswigger"><h2 class="portswigger">${ps.labsSolved}</h2><p>PortSwigger Labs</p></div>
            </div>

            <div class="chart-container">
                <h3>📊 Progress Comparison</h3>
                <div class="bar-chart">
                    <div class="bar-group">
                        <div class="bar" style="height:${htb.ownership.user * 2}px;background:#9fef00"></div>
                        <div class="bar-label">HTB<br>Machines</div>
                    </div>
                    <div class="bar-group">
                        <div class="bar" style="height:${thm.rooms.length * 20}px;background:#ef4444"></div>
                        <div class="bar-label">THM<br>Rooms</div>
                    </div>
                    <div class="bar-group">
                        <div class="bar" style="height:${ps.labsSolved}px;background:#ff6b35"></div>
                        <div class="bar-label">PS<br>Labs</div>
                    </div>
                    <div class="bar-group">
                        <div class="bar" style="height:${htb.challenges * 3}px;background:#22c55e"></div>
                        <div class="bar-label">HTB<br>Challenges</div>
                    </div>
                    <div class="bar-group">
                        <div class="bar" style="height:${thm.badges * 4}px;background:#f59e0b"></div>
                        <div class="bar-label">THM<br>Badges</div>
                    </div>
                </div>
            </div>

            <div class="progress-section">
                <h4>🎯 PortSwigger Topics Progress</h4>
                <div class="progress-bars">
                    ${ps.topics.map(t => `
                        <div class="progress-row">
                            <span class="progress-name">${t.name}</span>
                            <div class="progress-bar"><div class="progress-fill" style="width:${(t.solved / t.total) * 100}%;background:#ff6b35"></div></div>
                            <span class="progress-pct">${t.solved}/${t.total}</span>
                        </div>
                    `).join('')}
                </div>
            </div>

            <div class="platform-machines">
                <h4>🖥️ Recent Machines & Labs (All Platforms)</h4>
                <div class="machine-list">
                    ${[...htb.machines.map(m => ({ ...m, platform: 'htb' })),
            ...thm.rooms.map(r => ({ name: r.name, difficulty: r.difficulty, date: r.date, platform: 'thm' })),
            ...ps.recentLabs.map(l => ({ name: l.name, difficulty: 'Lab', date: l.date, platform: 'portswigger' }))]
                .sort((a, b) => new Date(b.date) - new Date(a.date))
                .slice(0, 8)
                .map(m => `
                        <div class="machine-item">
                            <span class="machine-name">${this.platforms[m.platform].icon} ${m.name}</span>
                            <span class="machine-diff ${m.difficulty}">${m.difficulty}</span>
                            <span class="machine-date">${m.date}</span>
                        </div>
                    `).join('')}
                </div>
            </div>`;
    },

    renderPlatforms() {
        const htb = this.demoData.htb;
        const thm = this.demoData.thm;
        const ps = this.demoData.portswigger;

        return `
            <div class="platform-grid">
                <div class="platform-card" style="border-top:4px solid #9fef00">
                    <div class="platform-header">
                        <div class="platform-icon">🟩</div>
                        <div class="platform-info">
                            <h3>Hack The Box</h3>
                            <p>@${htb.username} • ${htb.rank}</p>
                        </div>
                    </div>
                    <div class="platform-stats">
                        <div class="p-stat"><span class="p-stat-val" style="color:#9fef00">${htb.points}</span><span class="p-stat-lbl">Points</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#9fef00">#${htb.globalRank}</span><span class="p-stat-lbl">Global Rank</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#9fef00">${htb.ownership.user}</span><span class="p-stat-lbl">User Owns</span></div>
                    </div>
                    <div class="platform-machines">
                        <h4>Recent Machines</h4>
                        <div class="machine-list">
                            ${htb.machines.slice(0, 3).map(m => `
                                <div class="machine-item">
                                    <span class="machine-name">${m.name}</span>
                                    <span class="machine-diff ${m.difficulty}">${m.difficulty}</span>
                                    <span class="machine-date">+${m.points}pts</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>

                <div class="platform-card" style="border-top:4px solid #ef4444">
                    <div class="platform-header">
                        <div class="platform-icon">🔴</div>
                        <div class="platform-info">
                            <h3>TryHackMe</h3>
                            <p>@${thm.username} • ${thm.rank}</p>
                        </div>
                    </div>
                    <div class="platform-stats">
                        <div class="p-stat"><span class="p-stat-val" style="color:#ef4444">${thm.points}</span><span class="p-stat-lbl">Points</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#ef4444">🔥${thm.streak}</span><span class="p-stat-lbl">Day Streak</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#ef4444">${thm.badges}</span><span class="p-stat-lbl">Badges</span></div>
                    </div>
                    <div class="platform-machines">
                        <h4>Recent Rooms</h4>
                        <div class="machine-list">
                            ${thm.rooms.slice(0, 3).map(r => `
                                <div class="machine-item">
                                    <span class="machine-name">${r.name}</span>
                                    <span class="machine-diff ${r.difficulty}">${r.difficulty}</span>
                                    <span class="machine-date">${r.completed ? '✅' : '⏳'}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>

                <div class="platform-card" style="border-top:4px solid #ff6b35">
                    <div class="platform-header">
                        <div class="platform-icon">🟠</div>
                        <div class="platform-info">
                            <h3>PortSwigger Academy</h3>
                            <p>${ps.level} • ${ps.labsSolved}/${ps.totalLabs} Labs</p>
                        </div>
                    </div>
                    <div class="platform-stats">
                        <div class="p-stat"><span class="p-stat-val" style="color:#ff6b35">${ps.labsSolved}</span><span class="p-stat-lbl">Labs Solved</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#ff6b35">${Math.round((ps.labsSolved / ps.totalLabs) * 100)}%</span><span class="p-stat-lbl">Completion</span></div>
                        <div class="p-stat"><span class="p-stat-val" style="color:#ff6b35">${ps.topics.filter(t => t.solved === t.total).length}</span><span class="p-stat-lbl">Mastered</span></div>
                    </div>
                    <div class="platform-machines">
                        <h4>Topic Progress</h4>
                        <div class="progress-bars" style="padding:0">
                            ${ps.topics.slice(0, 4).map(t => `
                                <div class="progress-row">
                                    <span class="progress-name" style="width:100px">${t.name}</span>
                                    <div class="progress-bar"><div class="progress-fill" style="width:${(t.solved / t.total) * 100}%;background:#ff6b35"></div></div>
                                    <span class="progress-pct">${t.solved}/${t.total}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>`;
    },

    renderActivity() {
        const activities = [
            { icon: '🟩', name: 'Pwned Keeper', desc: 'User and Root flags captured', platform: 'htb', color: '#9fef00', date: '2h ago' },
            { icon: '🔴', name: 'Completed Buffer Overflow Prep', desc: 'All tasks completed', platform: 'thm', color: '#ef4444', date: '5h ago' },
            { icon: '🟠', name: 'Solved Blind SQL with conditionals', desc: 'SQL Injection lab completed', platform: 'portswigger', color: '#ff6b35', date: '1d ago' },
            { icon: '🟩', name: 'Ranked up to Hacker', desc: 'New rank achieved!', platform: 'htb', color: '#9fef00', date: '2d ago' },
            { icon: '🔴', name: 'Earned 7 Day Streak badge', desc: 'Consistency reward', platform: 'thm', color: '#ef4444', date: '3d ago' },
            { icon: '🟠', name: 'Mastered CSRF topic', desc: 'All 8 labs completed', platform: 'portswigger', color: '#ff6b35', date: '4d ago' },
            { icon: '🟩', name: 'First blooded Cybermonday', desc: 'First to solve!', platform: 'htb', color: '#9fef00', date: '1w ago' }
        ];

        return `
            <h3 style="color:#8b5cf6;margin:0 0 20px">📋 Recent Activity</h3>
            <div class="activity-list">
                ${activities.map(a => `
                    <div class="activity-item">
                        <div class="activity-icon">${a.icon}</div>
                        <div class="activity-info">
                            <h4>${a.name}</h4>
                            <p>${a.desc}</p>
                        </div>
                        <div class="activity-meta">
                            <span class="activity-platform" style="background:${a.color}22;color:${a.color}">${this.platforms[a.platform].name}</span>
                            <div class="activity-date">${a.date}</div>
                        </div>
                    </div>
                `).join('')}
            </div>`;
    },

    renderSettings() {
        const s = this.state;
        return `
            <div class="settings-section">
                <h3>🟩 Hack The Box</h3>
                ${s.htb.connected ? `<div class="connected-badge">✅ Connected as ${this.demoData.htb.username}</div>` : ''}
                <div class="api-input">
                    <input type="password" id="htb-token" placeholder="Enter HTB API Token (from account settings)">
                    <button class="btn-connect" onclick="UnifiedStats.connect('htb')">Connect</button>
                </div>
                <p style="color:#888;font-size:.85rem">Get your token from: HTB → Account Settings → App Tokens</p>
            </div>

            <div class="settings-section">
                <h3>🔴 TryHackMe</h3>
                ${s.thm.connected ? `<div class="connected-badge">✅ Connected as ${this.demoData.thm.username}</div>` : ''}
                <div class="api-input">
                    <input type="text" id="thm-username" placeholder="Enter your TryHackMe username">
                    <button class="btn-connect" onclick="UnifiedStats.connect('thm')">Connect</button>
                </div>
                <p style="color:#888;font-size:.85rem">THM public API uses username for public profiles</p>
            </div>

            <div class="settings-section">
                <h3>🟠 PortSwigger Academy</h3>
                ${s.portswigger.connected ? `<div class="connected-badge">✅ Connected</div>` : ''}
                <div class="api-input">
                    <input type="email" id="ps-email" placeholder="Enter PortSwigger email">
                    <button class="btn-connect" onclick="UnifiedStats.connect('portswigger')">Connect</button>
                </div>
                <p style="color:#888;font-size:.85rem">Note: PortSwigger doesn't have public API - uses manual entry</p>
            </div>

            <div class="settings-section">
                <h3>🔄 Actions</h3>
                <div style="display:flex;gap:10px;flex-wrap:wrap">
                    <button class="btn-connect" onclick="UnifiedStats.refresh()">🔄 Refresh All</button>
                    <button class="btn-connect" style="background:#f59e0b" onclick="UnifiedStats.exportStats()">📊 Export Stats</button>
                    <button class="btn-disconnect" onclick="UnifiedStats.demo()">📥 Load Demo Data</button>
                </div>
            </div>`;
    },

    connect(platform) {
        // In real implementation, this would make API calls
        this.state[platform].connected = true;
        alert(`✅ ${this.platforms[platform].name} connected!\n\n(Demo mode - using sample data)`);
        this.rr();
    },

    refresh() { alert('🔄 Refreshing stats from all platforms...\n\n(Demo mode - data is simulated)'); },

    exportStats() {
        const htb = this.demoData.htb;
        const thm = this.demoData.thm;
        const ps = this.demoData.portswigger;
        const report = `# Unified Security Training Stats\n\n## Summary\n- **Total Points:** ${htb.points + thm.points}\n- **Total Machines/Labs:** ${htb.ownership.user + thm.rooms.length + ps.labsSolved}\n\n## Hack The Box\n- Username: ${htb.username}\n- Rank: ${htb.rank}\n- Points: ${htb.points}\n- Machines: ${htb.ownership.user} user / ${htb.ownership.system} system\n\n## TryHackMe\n- Username: ${thm.username}\n- Rank: ${thm.rank}\n- Points: ${thm.points}\n- Streak: ${thm.streak} days\n\n## PortSwigger\n- Level: ${ps.level}\n- Labs: ${ps.labsSolved}/${ps.totalLabs}`;
        const blob = new Blob([report], { type: 'text/markdown' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'security_stats.md'; a.click();
    },

    demo() { this.state.htb.connected = true; this.state.thm.connected = true; this.state.portswigger.connected = true; alert('📥 Demo data loaded!'); this.rr(); },
    tab(t) { this.state.tab = t; this.rr(); },
    rr() { const app = document.querySelector('.usa'); if (app) app.outerHTML = this.render(); }
};

function pageUnifiedStats() { return UnifiedStats.render(); }
