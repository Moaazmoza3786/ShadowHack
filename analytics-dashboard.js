/* ==================== ANALYTICS DASHBOARD 📊 ==================== */

window.Analytics = {
    // --- STATE ---
    logs: [],
    skills: {
        'Web Exploitation': 0,
        'Cryptography': 0,
        'Reverse Engineering': 0,
        'Forensics': 0,
        'Pwn/Binary': 0,
        'Networking': 0
    },

    init() {
        this.loadLogs();
        this.calculateSkills();
    },

    loadLogs() {
        const saved = localStorage.getItem('ctf_analytics_logs');
        if (saved) {
            this.logs = JSON.parse(saved);
        } else {
            // Seed Data
            this.logs = [
                { id: 1, name: 'Basic SQLi', category: 'Web Exploitation', time: 15, lesson: 'Always check inputs', date: '2025-01-01' },
                { id: 2, name: 'Caesar Cipher', category: 'Cryptography', time: 5, lesson: 'Shift ciphers are weak', date: '2025-01-02' }
            ];
            this.saveLogs();
        }
    },

    saveLogs() {
        localStorage.setItem('ctf_analytics_logs', JSON.stringify(this.logs));
    },

    calculateSkills() {
        // Simple logic: Each log adds 10 points to category score
        // Reset
        Object.keys(this.skills).forEach(k => this.skills[k] = 0);

        this.logs.forEach(log => {
            if (this.skills[log.category] !== undefined) {
                this.skills[log.category] += 10;
            }
        });
    },

    // --- RENDER ---
    render() {
        this.init();
        return `
            <div class="analytics-container fade-in">
                <div class="analytics-header">
                    <h1><i class="fas fa-chart-line"></i> Performance Analytics</h1>
                    <p>Track your growth, analyze your weaknesses.</p>
                </div>

                <div class="analytics-grid">
                    <!-- SKILL GRAPH -->
                    <div class="analytics-card skills-card">
                        <h3><i class="fas fa-brain"></i> Skill Matrix</h3>
                        <div class="skills-chart">
                            ${Object.keys(this.skills).map(skill => {
            const val = this.skills[skill];
            const percent = Math.min(val, 100); // Max 100 for bar
            return `
                                    <div class="skill-row">
                                        <div class="skill-label">${skill}</div>
                                        <div class="skill-bar-bg">
                                            <div class="skill-bar-fill" style="width: ${percent}%; background: ${this.getColor(skill)}"></div>
                                        </div>
                                        <div class="skill-val">${val} XP</div>
                                    </div>
                                `;
        }).join('')}
                        </div>
                    </div>

                    <!-- LOG FORM -->
                    <div class="analytics-card form-card">
                        <h3><i class="fas fa-plus-circle"></i> Log Completed CTF</h3>
                        <div class="form-group">
                            <input type="text" id="log-name" placeholder="Challenge Name">
                        </div>
                        <div class="form-group">
                            <select id="log-cat">
                                <option>Web Exploitation</option>
                                <option>Cryptography</option>
                                <option>Reverse Engineering</option>
                                <option>Forensics</option>
                                <option>Pwn/Binary</option>
                                <option>Networking</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <input type="number" id="log-time" placeholder="Time Taken (Minutes)">
                        </div>
                        <div class="form-group">
                            <textarea id="log-lesson" placeholder="What is the key lesson? (e.g., 'Forgot to check robots.txt')"></textarea>
                        </div>
                        <button class="btn-log" onclick="Analytics.addLog()">Log Activity</button>
                    </div>
                </div>

                <!-- RECENT LOGS -->
                <div class="analytics-card logs-card" style="margin-top:20px;">
                    <h3><i class="fas fa-history"></i> Recent Activity</h3>
                    <table class="logs-table">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Challenge</th>
                                <th>Category</th>
                                <th>Time</th>
                                <th>Lesson Learned</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.logs.slice().reverse().map(log => `
                                <tr>
                                    <td>${log.date}</td>
                                    <td><strong>${log.name}</strong></td>
                                    <td><span class="cat-badge ${log.category.split(' ')[0].toLowerCase()}">${log.category}</span></td>
                                    <td>${log.time}m</td>
                                    <td>${log.lesson}</td>
                                    <td><button class="btn-del" onclick="Analytics.deleteLog(${log.id})"><i class="fas fa-trash"></i></button></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    addLog() {
        const name = document.getElementById('log-name').value;
        const cat = document.getElementById('log-cat').value;
        const time = document.getElementById('log-time').value;
        const lesson = document.getElementById('log-lesson').value;

        if (!name || !time) return alert('Please fill required fields');

        const newLog = {
            id: Date.now(),
            name, category: cat, time, lesson: lesson || 'No notes.',
            date: new Date().toISOString().split('T')[0]
        };

        this.logs.push(newLog);
        this.saveLogs();

        // Refresh
        document.querySelector('.app-content').innerHTML = this.render();
    },

    deleteLog(id) {
        if (!confirm('Remove this entry?')) return;
        this.logs = this.logs.filter(l => l.id !== id);
        this.saveLogs();
        document.querySelector('.app-content').innerHTML = this.render();
    },

    getColor(skill) {
        const colors = {
            'Web Exploitation': '#f43f5e',
            'Cryptography': '#8b5cf6',
            'Reverse Engineering': '#10b981',
            'Forensics': '#3b82f6',
            'Pwn/Binary': '#f59e0b',
            'Networking': '#06b6d4'
        };
        return colors[skill] || '#ccc';
    },

    getStyles() {
        return `
        <style>
            .analytics-container { padding: 40px; max-width: 1200px; margin: 0 auto; color: #fff; }
            .analytics-header { text-align: center; margin-bottom: 40px; }
            .analytics-header h1 { font-size: 2.5rem; margin-bottom: 10px; background: linear-gradient(135deg, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
            
            .analytics-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
            @media (max-width: 768px) { .analytics-grid { grid-template-columns: 1fr; } }

            .analytics-card { background: #1e1e2e; padding: 25px; border-radius: 16px; border: 1px solid rgba(255,255,255,0.05); box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
            .analytics-card h3 { margin-top: 0; margin-bottom: 20px; color: #a5b4fc; font-size: 1.2rem; display: flex; align-items: center; gap: 10px; }

            /* SKILLS CHART */
            .skill-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px; }
            .skill-label { width: 140px; font-size: 0.9rem; color: #cbd5e1; }
            .skill-bar-bg { flex: 1; height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; margin: 0 15px; overflow: hidden; }
            .skill-bar-fill { height: 100%; border-radius: 4px; transition: width 1s ease-out; }
            .skill-val { width: 50px; text-align: right; font-weight: bold; color: #fff; font-size: 0.9rem; }

            /* FORM */
            .form-group { margin-bottom: 15px; }
            input, select, textarea { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 8px; outline: none; font-family: inherit; }
            input:focus, select:focus, textarea:focus { border-color: #6366f1; }
            .btn-log { width: 100%; padding: 12px; background: #6366f1; color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; transition: 0.2s; }
            .btn-log:hover { background: #4f46e5; }

            /* TABLE */
            .logs-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            .logs-table th { text-align: left; padding: 15px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 0.9rem; }
            .logs-table td { padding: 15px; border-bottom: 1px solid #1e293b; color: #e2e8f0; font-size: 0.95rem; }
            .cat-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; background: #334155; }
            .cat-badge.web { background: rgba(244, 63, 94, 0.2); color: #f43f5e; }
            .cat-badge.cryptography { background: rgba(139, 92, 246, 0.2); color: #8b5cf6; }
            .btn-del { background: none; border: none; color: #475569; cursor: pointer; }
            .btn-del:hover { color: #f43f5e; }
        </style>
        `;
    }
};

function pageAnalytics() {
    return Analytics.render();
}
