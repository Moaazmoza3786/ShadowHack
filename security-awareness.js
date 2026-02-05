/* ==================== SECURITY AWARENESS TRAINING PORTAL 🎓 ==================== */
/* Interactive Phishing Simulation & Compliance Tracking Suite */

window.SecurityAwareness = {
    state: {
        activeTab: 'inbox',
        stats: {
            reported: 0,
            clicked: 0,
            quizScore: 0,
            compliance: 65
        },
        emails: [
            { id: 1, sender: 'IT Support <support@megacorp.net>', subject: 'Urgent: Password Reset Required', body: 'We detected unusual activity on your account. Please reset your password immediately at http://megacorp-auth.xyz/reset', isPhish: true, status: 'unread' },
            { id: 2, sender: 'HR <hr@megacorp.local>', subject: 'Updated Q4 Benefits', body: 'Please review the attached PDF for your updated Q4 healthcare benefits.', isPhish: false, status: 'unread' },
            { id: 3, sender: 'Amazon <no-reply@amazon-shipping.net>', subject: 'Your package is delayed', body: 'Your order #88219 is delayed. Track your shipment here: http://bit.ly/track-my-package-secure', isPhish: true, status: 'unread' }
        ],
        quiz: [
            { q: "What is the primary goal of Spear Phishing?", options: ["Targeting a specific individual/organization", "Sending emails to millions of random people", "Attacking a web server", "Encrypting files for ransom"], correct: 0 },
            { q: "Which of these is a sign of a phishing email?", options: ["Generic greeting", "Sense of urgency", "Suspicious links", "All of the above"], correct: 3 }
        ],
        currentQuestion: 0,
        quizComplete: false
    },

    init() {
        this.renderAll();
    },

    render() {
        return `
        <div class="awareness-app fade-in">
            <div class="awareness-header">
                <div class="header-info">
                    <h1><i class="fas fa-graduation-cap"></i> Cyber Awareness Hub</h1>
                    <p>Employee Security Training & Phishing Simulation Portal</p>
                </div>
                <div class="header-stats">
                    <div class="stat-box">
                        <span class="stat-label">Compliance</span>
                        <span class="stat-val">${this.state.stats.compliance}%</span>
                    </div>
                </div>
            </div>

            <div class="awareness-tabs">
                <button class="a-tab ${this.state.activeTab === 'inbox' ? 'active' : ''}" onclick="SecurityAwareness.switchTab('inbox')"><i class="fas fa-envelope"></i> Phish Simulation</button>
                <button class="a-tab ${this.state.activeTab === 'quiz' ? 'active' : ''}" onclick="SecurityAwareness.switchTab('quiz')"><i class="fas fa-tasks"></i> Training Quiz</button>
                <button class="a-tab ${this.state.activeTab === 'stats' ? 'active' : ''}" onclick="SecurityAwareness.switchTab('stats')"><i class="fas fa-chart-line"></i> My Progress</button>
            </div>

            <div class="awareness-main">
                ${this.renderContent()}
            </div>
        </div>
        ${this.getStyles()}`;
    },

    renderContent() {
        switch (this.state.activeTab) {
            case 'inbox': return this.renderInbox();
            case 'quiz': return this.renderQuiz();
            case 'stats': return this.renderStats();
            default: return this.renderInbox();
        }
    },

    renderInbox() {
        return `
            <div class="inbox-view fade-in">
                <div class="inbox-container">
                    <div class="inbox-sidebar">
                        <div class="sidebar-item active"><i class="fas fa-inbox"></i> Inbox (${this.state.emails.filter(e => e.status === 'unread').length})</div>
                        <div class="sidebar-item"><i class="fas fa-flag"></i> Reported</div>
                    </div>
                    <div class="email-list">
                        ${this.state.emails.map(e => `
                            <div class="email-item ${e.status}" onclick="SecurityAwareness.viewEmail(${e.id})">
                                <div class="e-sender">${e.sender}</div>
                                <div class="e-subject">${e.subject}</div>
                                <div class="e-actions">
                                    <button class="btn-report" onclick="event.stopPropagation(); SecurityAwareness.reportPhish(${e.id})"><i class="fas fa-shield-alt"></i> Report Phish</button>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderQuiz() {
        if (this.state.quizComplete) {
            return `
                <div class="quiz-complete fade-in">
                    <i class="fas fa-check-circle"></i>
                    <h2>Training Module Complete!</h2>
                    <p>Your Score: ${this.state.stats.quizScore}/${this.state.quiz.length}</p>
                    <button class="btn-primary" onclick="SecurityAwareness.resetQuiz()">Retake Quiz</button>
                </div>
            `;
        }
        const q = this.state.quiz[this.state.currentQuestion];
        return `
            <div class="quiz-view fade-in">
                <div class="quiz-card">
                    <div class="q-header">Question ${this.state.currentQuestion + 1} of ${this.state.quiz.length}</div>
                    <div class="q-text">${q.q}</div>
                    <div class="q-options">
                        ${q.options.map((o, idx) => `
                            <button class="opt-btn" onclick="SecurityAwareness.answerQuiz(${idx})">${o}</button>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderStats() {
        return `
            <div class="stats-view fade-in">
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Emails Reported</h3>
                        <div class="big-num">${this.state.stats.reported}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Simulated "Clicks"</h3>
                        <div class="big-num warning">${this.state.stats.clicked}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Quiz Performance</h3>
                        <div class="big-num">${this.state.stats.quizScore}/${this.state.quiz.length}</div>
                    </div>
                </div>
                <div class="compliance-row">
                    <h3>Overall Compliance Status</h3>
                    <div class="progress-container">
                        <div class="progress-bar" style="width: ${this.state.stats.compliance}%"></div>
                    </div>
                    <p>${this.state.stats.compliance}% - Target: 90%</p>
                </div>
            </div>
        `;
    },

    switchTab(tab) {
        this.state.activeTab = tab;
        this.renderAll();
    },

    viewEmail(id) {
        const e = this.state.emails.find(e => e.id === id);
        if (e && e.isPhish) {
            if (confirm(`EMAIL CONTENT:\n\nFrom: ${e.sender}\nSubject: ${e.subject}\n\n${e.body}\n\n[Click here to perform action]`)) {
                this.state.stats.clicked++;
                this.state.stats.compliance -= 5;
                alert("ALARM: You clicked a simulated phishing link! This has been logged for training purposes.");
            }
        } else {
            alert(`From: ${e.sender}\n\n${e.body}`);
        }
        e.status = 'read';
        this.renderAll();
    },

    reportPhish(id) {
        const e = this.state.emails.find(e => e.id === id);
        if (e.isPhish) {
            this.state.stats.reported++;
            this.state.stats.compliance += 10;
            alert("Excellent! You identified and reported a phishing attempt. +10 Compliance score.");
        } else {
            alert("This was a legitimate email. Be careful not to report real business communications!");
        }
        this.state.emails = this.state.emails.filter(email => email.id !== id);
        this.renderAll();
    },

    answerQuiz(idx) {
        const q = this.state.quiz[this.state.currentQuestion];
        if (idx === q.correct) {
            this.state.stats.quizScore++;
        }
        if (this.state.currentQuestion < this.state.quiz.length - 1) {
            this.state.currentQuestion++;
        } else {
            this.state.quizComplete = true;
            this.state.stats.compliance += 15;
        }
        this.renderAll();
    },

    resetQuiz() {
        this.state.currentQuestion = 0;
        this.state.quizComplete = false;
        this.state.stats.quizScore = 0;
        this.renderAll();
    },

    renderAll() {
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .awareness-app { padding: 40px; color: #e0e0e0; font-family: 'Inter', sans-serif; background: #0f111a; min-height: 100%; box-sizing: border-box; }
            .awareness-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; border-bottom: 1px solid #1c1c26; padding-bottom: 25px; }
            .header-info h1 { margin: 0; font-size: 2rem; color: #fff; display: flex; align-items: center; gap: 15px; }
            .header-info p { margin: 5px 0 0; color: #6366f1; font-weight: 500; }
            
            .stat-box { background: #161925; padding: 15px 25px; border-radius: 12px; border: 1px solid #2d2d3a; text-align: center; }
            .stat-label { display: block; font-size: 0.75rem; text-transform: uppercase; color: #555; font-weight: 800; margin-bottom: 5px; }
            .stat-val { font-size: 1.5rem; font-weight: 900; color: #6366f1; }

            .awareness-tabs { display: flex; gap: 15px; margin-bottom: 30px; }
            .a-tab { background: #161925; border: 1px solid #2d2d3a; color: #888; padding: 12px 25px; border-radius: 8px; cursor: pointer; transition: 0.3s; font-weight: 600; }
            .a-tab.active { background: #6366f1; color: #fff; border-color: #6366f1; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3); }

            .inbox-container { display: grid; grid-template-columns: 250px 1fr; gap: 20px; background: #161925; border-radius: 20px; border: 1px solid #2d2d3a; overflow: hidden; min-height: 500px; }
            .inbox-sidebar { padding: 20px; background: rgba(0,0,0,0.2); border-right: 1px solid #2d2d3a; }
            .sidebar-item { padding: 12px 15px; border-radius: 8px; margin-bottom: 10px; cursor: pointer; color: #888; display: flex; align-items: center; gap: 12px; font-weight: 600; }
            .sidebar-item.active { background: #6366f1; color: #fff; }

            .email-item { padding: 20px; border-bottom: 1px solid #1c1c26; cursor: pointer; transition: 0.2s; position: relative; }
            .email-item:hover { background: rgba(255,255,255,0.02); }
            .email-item.unread { border-left: 4px solid #6366f1; background: rgba(99, 102, 241, 0.05); }
            .e-sender { font-weight: 700; color: #fff; font-size: 0.95rem; margin-bottom: 5px; }
            .e-subject { color: #888; font-size: 0.9rem; }
            .e-actions { position: absolute; right: 20px; top: 50%; transform: translateY(-50%); }
            .btn-report { background: #ef4444; color: #fff; border: none; padding: 6px 15px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer; opacity: 0; transition: 0.2s; }
            .email-item:hover .btn-report { opacity: 1; }

            .quiz-card { max-width: 600px; margin: 0 auto; background: #161925; padding: 40px; border-radius: 20px; border: 1px solid #2d2d3a; text-align: center; }
            .q-header { font-size: 0.75rem; color: #555; text-transform: uppercase; margin-bottom: 20px; font-weight: 800; }
            .q-text { font-size: 1.3rem; color: #fff; font-weight: 700; margin-bottom: 30px; line-height: 1.4; }
            .q-options { display: grid; gap: 15px; }
            .opt-btn { background: #0b0c14; border: 1px solid #2d2d3a; color: #e0e0e0; padding: 15px; border-radius: 12px; cursor: pointer; transition: 0.3s; font-weight: 600; font-size: 1rem; }
            .opt-btn:hover { background: #6366f1; color: #fff; border-color: #6366f1; }

            .quiz-complete { text-align: center; padding: 60px 0; }
            .quiz-complete i { font-size: 4rem; color: #22c55e; margin-bottom: 25px; }

            .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }
            .stat-card { background: #161925; padding: 30px; border-radius: 20px; border: 1px solid #2d2d3a; text-align: center; }
            .stat-card h3 { font-size: 0.8rem; color: #555; text-transform: uppercase; margin-bottom: 15px; }
            .big-num { font-size: 3rem; font-weight: 900; color: #fff; }
            .big-num.warning { color: #ef4444; }

            .compliance-row { background: #161925; padding: 30px; border-radius: 20px; border: 1px solid #2d2d3a; }
            .progress-container { height: 12px; background: #0b0c14; border-radius: 6px; overflow: hidden; margin: 15px 0; }
            .progress-bar { height: 100%; background: linear-gradient(90deg, #6366f1, #a855f7); transition: 1s; }
            
            .btn-primary { background: #6366f1; color: #fff; border: none; padding: 12px 30px; border-radius: 10px; font-weight: 700; cursor: pointer; margin-top: 20px; }
        </style>`;
    }
};

function pageSecurityAwareness() {
    SecurityAwareness.init();
    return SecurityAwareness.render();
}
