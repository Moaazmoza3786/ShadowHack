/* ==================== DAILY DRILL (TECHNICAL TRAINING) ==================== */

window.DailyDrill = {
    // --- STATE ---
    currentQuestion: null,
    streak: 0,
    lastPlayed: null,

    // --- DATA ---
    questions: [
        { id: 1, type: 'port', q: 'What is the default port for SSH?', a: '22', options: ['21', '22', '23', '443'] },
        { id: 2, type: 'port', q: 'What is the default port for RDP?', a: '3389', options: ['3306', '3389', '8080', '5900'] },
        { id: 3, type: 'vuln', q: 'Which vulnerability allows an attacker to execute arbitrary SQL commands?', a: 'SQL Injection', options: ['XSS', 'CSRF', 'SQL Injection', 'IDOR'] },
        { id: 4, type: 'cmd', q: 'Which Nmap flag enables OS detection?', a: '-O', options: ['-sV', '-O', '-A', '-p-'] },
        { id: 5, type: 'code', q: 'Identify the vuln: `eval(user_input)`', a: 'RCE', options: ['XSS', 'RCE', 'LFI', 'SQLi'] },
        { id: 6, type: 'port', q: 'Default port for MySQL?', a: '3306', options: ['1433', '3306', '5432', '27017'] },
        { id: 7, type: 'vuln', q: 'What does XSS stand for?', a: 'Cross-Site Scripting', options: ['Extra Secure Sockets', 'Cross-Site Scripting', 'XML Style Sheets', 'Xenon Server Security'] },
        { id: 8, type: 'tool', q: 'Which tool is best for intercepting web traffic?', a: 'Burp Suite', options: ['Nmap', 'Burp Suite', 'Wireshark', 'Metasploit'] }
    ],

    // --- INIT ---
    init() {
        this.loadState();
    },

    loadState() {
        const saved = localStorage.getItem('daily_drill_state');
        if (saved) {
            const data = JSON.parse(saved);
            this.streak = data.streak || 0;
            this.lastPlayed = data.lastPlayed;
        }
    },

    saveState() {
        localStorage.setItem('daily_drill_state', JSON.stringify({
            streak: this.streak,
            lastPlayed: this.lastPlayed
        }));
    },

    getDailyQuestion() {
        // Simple seeded random based on date to ensure same question for everyone per day
        const day = new Date().toISOString().split('T')[0];
        if (this.lastPlayed === day) return null; // Already played

        const seed = day.split('-').reduce((a, b) => a + parseInt(b), 0);
        const index = seed % this.questions.length;
        return this.questions[index];
    },

    // --- RENDER ---
    render() {
        const today = new Date().toISOString().split('T')[0];
        const q = this.getDailyQuestion();

        if (this.lastPlayed === today) {
            return this.renderCompleted();
        }

        this.currentQuestion = q;

        return `
            <div class="drill-container fade-in">
                <div class="drill-card">
                    <div class="drill-header">
                        <div class="drill-badge">DAILY DRILL 🎯</div>
                        <div class="drill-streak">🔥 ${this.streak} Day Streak</div>
                    </div>
                    
                    <div class="drill-content">
                        <div class="question-box">
                            <h3>${q.q}</h3>
                            ${q.type === 'code' ? '<p class="text-muted text-sm">Analyze the code snippet carefully.</p>' : ''}
                        </div>
                        
                        <div class="options-grid">
                            ${q.options.map(opt => `
                                <button class="drill-opt-btn" onclick="DailyDrill.checkAnswer('${opt}')">
                                    ${opt}
                                </button>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderCompleted() {
        return `
            <div class="drill-container fade-in">
                <div class="drill-card completed">
                    <div class="drill-icon"><i class="fas fa-check-circle"></i></div>
                    <h2>Drill Completed!</h2>
                    <p>Good job keeping your skills sharp.</p>
                    <div class="drill-streak large">🔥 ${this.streak}</div>
                    <p class="text-muted">Come back tomorrow for a new question.</p>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    // --- LOGIC ---
    checkAnswer(ans) {
        if (!this.currentQuestion) return;

        if (ans === this.currentQuestion.a) {
            // Correct
            this.streak++;
            this.lastPlayed = new Date().toISOString().split('T')[0];
            this.saveState();

            // Show Success UI
            document.querySelector('.drill-container').innerHTML = this.renderCompleted();
            this.playSound('success');

            // Gamification Hook (if exists)
            if (window.addXP) window.addXP(50);

        } else {
            // Wrong
            this.streak = 0; // Reset streak? Or just allow retry? Let's be harsh for "Drill".
            this.lastPlayed = new Date().toISOString().split('T')[0]; // Mark as played but failed?
            // Actually, let's just show error and let them retry for learning, but maybe reset streak.
            alert('Incorrect! Streak Reset. Try again.');
            this.saveState();
            this.render(); // Re-render to update streak UI
        }
    },

    playSound(type) {
        // Placeholder
    },

    getStyles() {
        return `
        <style>
            .drill-container {
                display: flex; justify-content: center; align-items: center;
                min-height: 80vh; padding: 20px;
                background: radial-gradient(circle at center, #1a1a2e 0%, #000 100%);
            }
            .drill-card {
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 20px;
                padding: 40px;
                max-width: 600px;
                width: 100%;
                box-shadow: 0 20px 50px rgba(0,0,0,0.5);
                text-align: center;
            }
            .drill-card.completed { border-color: #00ff88; background: rgba(0, 255, 136, 0.05); }
            
            .drill-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
            .drill-badge { font-family: 'Rajdhani', sans-serif; font-weight: 800; color: #fff; background: #6366f1; padding: 5px 15px; border-radius: 20px; letter-spacing: 1px; }
            .drill-streak { color: #ff9f43; font-weight: bold; font-size: 1.1rem; }
            .drill-streak.large { font-size: 3rem; margin: 20px 0; }
            
            .question-box h3 { color: #fff; font-size: 1.5rem; margin-bottom: 30px; line-height: 1.4; }
            
            .options-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
            .drill-opt-btn {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
                color: #fff;
                padding: 15px;
                border-radius: 12px;
                font-size: 1rem;
                cursor: pointer;
                transition: 0.2s;
            }
            .drill-opt-btn:hover { background: rgba(99, 102, 241, 0.2); border-color: #6366f1; transform: translateY(-2px); }
            
            .drill-icon { font-size: 4rem; color: #00ff88; margin-bottom: 20px; animation: popIn 0.5s cubic-bezier(0.68, -0.55, 0.27, 1.55); }
            
            @keyframes popIn { 0% { transform: scale(0); } 70% { transform: scale(1.2); } 100% { transform: scale(1); } }
            @keyframes fade-in { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            .fade-in { animation: fade-in 0.5s ease-out; }
        </style>
        `;
    }
};

// Global Page Function
function pageDailyDrill() {
    DailyDrill.init();
    return DailyDrill.render();
}
