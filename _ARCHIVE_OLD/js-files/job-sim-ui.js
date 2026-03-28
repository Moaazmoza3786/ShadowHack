/* ============================================================
   CYBER CAREER CENTER (JOB SIM UI) v2.0
   The central hub for all professional role-playing paths.
   Now powered by HEURISTIC AI ENGINE.
   ============================================================ */

window.JobSimUI = {
    currentRole: null,
    currentScenario: null,
    progress: {},
    userXP: 0,
    userRank: null,
    // Track hint usage per task to give progressive help
    hintState: {},

    init() {
        this.progress = JSON.parse(localStorage.getItem('job_sim_progress') || '{}');
        this.calculateXP();
    },

    calculateXP() {
        let xp = 0;
        window.JobSimData.roles.forEach(role => {
            role.scenarios.forEach(scen => {
                scen.tasks.forEach(task => {
                    if (this.progress[`${scen.id}_${task.id}`]) {
                        xp += task.points;
                    }
                });
            });
        });
        this.userXP = xp;
        this.updateRank();
    },

    updateRank() {
        const ranks = window.JobSimData.ranks;
        this.userRank = ranks.slice().reverse().find(r => this.userXP >= r.minXP) || ranks[0];
    },

    getNextRank() {
        const ranks = window.JobSimData.ranks;
        return ranks.find(r => r.minXP > this.userXP) || { title: 'Max Level', minXP: this.userXP };
    },

    // --- DASHBOARD: CAREER HUB ---
    renderDashboard() {
        this.init();
        const nextRank = this.getNextRank();
        const xpPercent = Math.min(100, Math.max(0, ((this.userXP - this.userRank.minXP) / (nextRank.minXP - this.userRank.minXP)) * 100));

        return `
            <div class="career-hub-container fade-in">
                <style>
                    /* HUB STYLES */
                    .career-hub-container {
                        padding: 40px;
                        color: #e2e8f0;
                        font-family: 'Outfit', sans-serif;
                        max-width: 1600px;
                        margin: 0 auto;
                        min-height: 100vh;
                        background: radial-gradient(circle at top right, #1e293b 0%, #0f172a 100%);
                    }
                    
                    /* HEADER SECTION */
                    .hub-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-end;
                        margin-bottom: 50px;
                        border-bottom: 1px solid #334155;
                        padding-bottom: 30px;
                    }
                    .hub-title h1 {
                        font-family: 'Orbitron', sans-serif;
                        font-size: 3.5rem;
                        background: linear-gradient(to right, #38bdf8, #818cf8);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        margin: 0;
                        letter-spacing: -2px;
                    }
                    .hub-title p {
                        font-size: 1.2rem;
                        color: #94a3b8;
                        margin-top: 10px;
                    }

                    /* PROFILE WIDGET */
                    .profile-card {
                        background: rgba(30, 41, 59, 0.5);
                        backdrop-filter: blur(10px);
                        border: 1px solid #334155;
                        padding: 25px;
                        border-radius: 20px;
                        width: 350px;
                        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                    }
                    .rank-badge {
                        display: inline-block;
                        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                        color: #fff;
                        padding: 5px 12px;
                        border-radius: 20px;
                        font-weight: 700;
                        font-size: 0.8rem;
                        margin-bottom: 10px;
                        box-shadow: 0 4px 10px rgba(245, 158, 11, 0.3);
                    }
                    .xp-bar-container {
                        height: 10px;
                        background: #334155;
                        border-radius: 5px;
                        margin: 15px 0 5px;
                        overflow: hidden;
                    }
                    .xp-bar-fill {
                        height: 100%;
                        background: #38bdf8;
                        width: ${xpPercent}%;
                        transition: width 1s ease;
                    }
                    .xp-text {
                        font-size: 0.85rem;
                        color: #94a3b8;
                        display: flex;
                        justify-content: space-between;
                    }

                    /* AI COACH WIDGET */
                    .ai-coach-widget {
                        background: linear-gradient(145deg, #1e1e2e, #161625);
                        border: 1px solid #6366f1;
                        border-radius: 20px;
                        padding: 25px;
                        margin-bottom: 40px;
                        display: flex;
                        gap: 20px;
                        align-items: center;
                        position: relative;
                        overflow: hidden;
                    }
                    .ai-coach-widget::before {
                        content: '';
                        position: absolute;
                        top: 0; left: 0; width: 5px; height: 100%;
                        background: #6366f1;
                    }
                    .coach-avatar {
                        font-size: 3rem;
                        color: #6366f1;
                        animation: pulse 2s infinite;
                    }
                    .coach-content h3 { margin: 0 0 5px 0; color: #fff; }
                    .coach-content p { margin: 0; color: #cbd5e1; font-style: italic; }

                    /* CAREER GRID */
                    .career-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                        gap: 30px;
                    }
                    .career-card {
                        background: #1e293b;
                        border: 1px solid #334155;
                        border-radius: 24px;
                        overflow: hidden;
                        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                        position: relative;
                    }
                    .career-card:hover {
                        transform: translateY(-8px);
                        border-color: #38bdf8;
                        box-shadow: 0 20px 40px rgba(56, 189, 248, 0.15);
                    }
                    .card-banner {
                        height: 120px;
                        background: linear-gradient(to right, #0f172a, #334155);
                        position: relative;
                        padding: 20px;
                    }
                    .role-icon-lg {
                        position: absolute;
                        bottom: -30px;
                        left: 30px;
                        width: 70px;
                        height: 70px;
                        background: #0f172a;
                        border: 3px solid #38bdf8;
                        border-radius: 16px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 2rem;
                        color: #38bdf8;
                        z-index: 2;
                    }
                    .tier-badge {
                        position: absolute;
                        top: 20px;
                        right: 20px;
                        background: rgba(0,0,0,0.4);
                        backdrop-filter: blur(4px);
                        padding: 5px 12px;
                        border-radius: 8px;
                        border: 1px solid rgba(255,255,255,0.1);
                        font-size: 0.8rem;
                        color: #cbd5e1;
                    }
                    .card-body {
                        padding: 45px 30px 30px;
                    }
                    .card-body h2 { margin: 0 0 10px; font-size: 1.8rem; }
                    .card-stats {
                        display: flex;
                        gap: 15px;
                        margin-bottom: 20px;
                        font-size: 0.9rem;
                        color: #94a3b8;
                    }
                    .card-stats i { color: #38bdf8; margin-right: 5px; }
                    .start-btn {
                        width: 100%;
                        padding: 14px;
                        background: #38bdf8;
                        color: #0f172a;
                        border: none;
                        border-radius: 12px;
                        font-weight: 700;
                        font-size: 1rem;
                        cursor: pointer;
                        transition: 0.2s;
                    }
                    .start-btn:hover {
                        background: #7dd3fc;
                        box-shadow: 0 0 20px rgba(56, 189, 248, 0.4);
                    }

                    @keyframes pulse { 0% { opacity: 0.7; } 50% { opacity: 1; } 100% { opacity: 0.7; } }
                </style>

                <div class="hub-header">
                    <div class="hub-title">
                        <h1>CYBER CAREER CENTER</h1>
                        <p>Build your professional profile through realistic job simulations.</p>
                    </div>
                    <div class="profile-card">
                        <div class="rank-badge"><i class="fa-solid fa-crown"></i> ${this.userRank.title}</div>
                        <h2 style="margin:0; font-size:1.4rem;">${localStorage.getItem('username') || 'Guest User'}</h2>
                        <div class="xp-bar-container">
                            <div class="xp-bar-fill"></div>
                        </div>
                        <div class="xp-text">
                            <span>${this.userXP} XP</span>
                            <span>Next: ${nextRank.minXP} XP</span>
                        </div>
                    </div>
                </div>

                <div class="ai-coach-widget">
                    <div class="coach-avatar"><i class="fa-solid fa-robot"></i></div>
                    <div class="coach-content">
                        <h3>AI Career Coach Analysis</h3>
                        <p id="coach-tip">${this.getCoachTip()}</p>
                    </div>
                </div>

                <div class="career-grid">
                    ${window.JobSimData.roles.map(role => `
                        <div class="career-card">
                            <div class="card-banner">
                                <div class="tier-badge">TIER ${role.tier}</div>
                            </div>
                            <div class="role-icon-lg">
                                <i class="fa-solid fa-${role.icon}"></i>
                            </div>
                            <div class="card-body">
                                <h2>${role.title}</h2>
                                <div class="card-stats">
                                    <span><i class="fa-solid fa-money-bill-wave"></i> ${role.salary}</span>
                                    <span><i class="fa-solid fa-briefcase"></i> ${role.difficulty}</span>
                                </div>
                                <p style="color:#94a3b8; line-height:1.6; margin-bottom:20px;">${role.description}</p>
                                <div style="display:flex; gap:5px; flex-wrap:wrap; margin-bottom:25px;">
                                    ${role.skills.map(s => `<span style="background:#334155; padding:4px 10px; border-radius:6px; font-size:0.8rem; color:#cbd5e1;">${s}</span>`).join('')}
                                </div>
                                <button class="start-btn" onclick="JobSimUI.startShift('${role.id}')">
                                    Start Career Path <i class="fa-solid fa-arrow-right" style="margin-left:5px;"></i>
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    getCoachTip() {
        if (this.userXP === 0) return "Welcome, Rookie! I recommend starting with the **SOC Analyst** track to build fundamental defensive skills. The market demand for SOC analysts is high.";
        if (this.userXP < 2000) return "Great progress! You're gaining traction. Try the **Bug Bounty** simulations next to understand the attacker's mindset regarding web vulnerabilities.";
        return "Impressive portfolio. You are ready for **Advanced Malware Analysis**. This is the simulated big leagues—expect no hand-holding.";
    },

    // --- WORKSPACE: TASK RUNNER ---
    startShift(roleId) {
        this.currentRole = window.JobSimData.roles.find(r => r.id === roleId);
        this.currentScenario = this.currentRole.scenarios[0];

        // Initialize Heuristic Engine Context
        if (window.HeuristicEngine) {
            window.HeuristicEngine.setContext(this.currentRole, this.currentScenario);
        }

        // Render unified workspace
        this.renderWorkspace();
    },

    renderWorkspace(activeTaskId = null) {
        if (!activeTaskId) activeTaskId = this.currentScenario.tasks[0].id; // Default to first task
        const activeTask = this.currentScenario.tasks.find(t => t.id === activeTaskId);
        const container = document.getElementById('content');

        // Styles
        const html = `
             <div class="job-sim-container fade-in">
                <style>
                    /* WORKSPACE STYLES */
                    .workspace-grid {
                        display: grid;
                        grid-template-columns: 320px 1fr;
                        gap: 25px;
                        height: 85vh;
                        margin-top: 20px;
                    }
                    .sidebar {
                        background: #1e293b;
                        border-radius: 16px;
                        border: 1px solid #334155;
                        display: flex;
                        flex-direction: column;
                        overflow: hidden;
                    }
                    .sidebar-header {
                        padding: 20px;
                        background: #0f172a;
                        border-bottom: 1px solid #334155;
                    }
                    .task-list {
                        flex: 1;
                        overflow-y: auto;
                        padding: 15px;
                    }
                    .task-item {
                        padding: 15px;
                        border-radius: 10px;
                        background: #334155;
                        margin-bottom: 10px;
                        cursor: pointer;
                        border-left: 4px solid transparent;
                        transition: 0.2s;
                    }
                    .task-item.active { background: #475569; border-left-color: #38bdf8; }
                    .task-item.done { opacity: 0.6; text-decoration: line-through; border-left-color: #22c55e; }
                    
                    .main-console {
                        background: #0f172a;
                        border-radius: 16px;
                        border: 1px solid #334155;
                        display: flex;
                        flex-direction: column;
                        overflow: hidden;
                        position: relative;
                    }
                    .console-header {
                        padding: 20px;
                        border-bottom: 1px solid #334155;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        background: #1e293b;
                    }
                    .console-body {
                        flex: 1;
                        padding: 40px;
                        overflow-y: auto;
                        font-family: 'JetBrains Mono', monospace;
                    }
                    .evidence-viewer {
                        background: #000;
                        color: #4ade80;
                        padding: 20px;
                        border-radius: 8px;
                        margin: 20px 0;
                        border: 1px solid #334155;
                        white-space: pre-wrap;
                        font-size: 0.9rem;
                    }
                    .interaction-area {
                        margin-top: 30px;
                        background: #1e293b;
                        padding: 20px;
                        border-radius: 12px;
                        border: 1px solid #334155;
                    }
                    .sim-input {
                        width: 100%;
                        background: #0f172a;
                        border: 1px solid #475569;
                        color: #fff;
                        padding: 15px;
                        border-radius: 8px;
                        font-family: inherit;
                        margin-bottom: 15px;
                    }
                    .sim-btn {
                        background: #38bdf8; color: #000;
                        padding: 10px 25px; border-radius: 8px; border: none; font-weight: bold; cursor: pointer;
                    }
                    
                    /* AI CHAT BUBBLE */
                    .ai-response-box {
                        margin-top: 20px;
                        background: rgba(99, 102, 241, 0.1);
                        border-left: 4px solid #6366f1;
                        padding: 15px;
                        border-radius: 8px;
                        color: #cbd5e1;
                        animation: slideIn 0.3s ease;
                    }
                    .ai-response-header {
                        display: flex; align-items: center; gap: 10px; margin-bottom: 10px; color: #818cf8; font-weight: bold;
                    }
                    .ai-tag { font-size: 0.75rem; background: rgba(99, 102, 241, 0.2); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(99, 102, 241, 0.4); }
                    @keyframes slideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
                </style>    

                <div style="display: flex; align-items: center; gap: 20px;">
                    <button onclick="JobSimUI.backToDashboard()" style="background:none; border:none; color:#94a3b8; cursor:pointer; font-size:1.1rem;">
                        <i class="fa-solid fa-arrow-left"></i> Exit Shift
                    </button>
                    <div>
                        <h2 style="margin:0; color:#fff;">${this.currentScenario.title}</h2>
                        <span style="color:#94a3b8; font-size:0.9rem;"><i class="fa-solid fa-building"></i> ${this.currentRole.title} | ${this.currentRole.difficulty}</span>
                    </div>
                </div>

                <div class="workspace-grid">
                    <!-- SIDEBAR -->
                    <div class="sidebar">
                        <div class="sidebar-header">
                            <h4 style="margin:0; color:#fff;">SHIFT TASKS</h4>
                            <div style="height:5px; background:#334155; margin-top:10px; border-radius:3px;">
                                <div style="height:100%; width:${this.calculateProgress()}%; background:#22c55e;"></div>
                            </div>
                        </div>
                        <div class="task-list">
                            ${this.currentScenario.tasks.map(t => `
                                <div class="task-item ${t.id === activeTaskId ? 'active' : ''} ${this.isTaskDone(t.id) ? 'done' : ''}"
                                     onclick="JobSimUI.renderWorkspace('${t.id}')">
                                    <div style="font-weight:700;">${t.title}</div>
                                    <div style="font-size:0.8rem; color:#cbd5e1;">${t.points} XP</div>
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <!-- CONSOLE -->
                    <div class="main-console">
                        <div class="console-header">
                            <h3 style="margin:0; color:#fff;"><i class="fa-solid fa-terminal"></i> Terminal / View</h3>
                            <button onclick="JobSimUI.askSeniorAnalyst('${activeTask.id}')" style="background:#6366f1; color:#fff; border:none; padding:8px 15px; border-radius:6px; font-weight:bold; cursor:pointer; transition:0.2s;">
                                <i class="fa-solid fa-headset"></i> Ask Senior Analyst
                            </button>
                        </div>
                        <div class="console-body">
                            <p style="color:#e2e8f0; font-size:1.1rem; margin-top:0;">${activeTask.prompt}</p>
                            
                            <!-- DYNAMIC EVIDENCE -->
                            ${this.renderEvidence(activeTask)}

                            <!-- INTERACTION -->
                            <div class="interaction-area">
                                ${this.renderInput(activeTask)}
                                <button class="sim-btn" onclick="JobSimUI.submitTask('${activeTask.id}')">Submit Findings</button>
                                <div id="feedback-${activeTask.id}" style="margin-top:15px; min-height:20px;"></div>
                                <div id="ai-mentor-${activeTask.id}" style="display:none;"></div>
                            </div>
                        </div>
                    </div>
                </div>
             </div>
        `;
        container.innerHTML = html;
        window.scrollTo(0, 0);
    },

    backToDashboard() {
        document.getElementById('content').innerHTML = this.renderDashboard();
    },

    // --- HELPERS ---
    calculateProgress() {
        if (!this.currentScenario) return 0;
        const total = this.currentScenario.tasks.length;
        const done = this.currentScenario.tasks.filter(t => this.isTaskDone(t.id)).length;
        return (done / total) * 100;
    },

    isTaskDone(taskId) {
        if (!this.currentScenario) return false;
        return this.progress[`${this.currentScenario.id}_${taskId}`] === true;
    },

    renderEvidence(task) {
        // Simple mapping for now, can be complex logic later
        const ev = this.currentScenario.evidence;
        let content = '';
        if (ev.headers) content += `[EMAIL HEADERS]\n${ev.headers}\n\n`;
        if (ev.body) content += `[EMAIL BODY]\n${ev.body}\n\n`;
        if (ev.logs) content += `[SYSTEM LOGS]\n${ev.logs}\n\n`;
        if (ev.terminal) content += `[TERMINAL OUTPUT]\n${ev.terminal}\n\n`;
        if (ev.hexView) content += `[HEX DUMP]\n${ev.hexView}\n\n`;
        if (ev.imports) content += `[PE IMPORTS]\n${ev.imports}\n\n`;
        if (ev.source) content += `[SOURCE CODE]\n${ev.source}\n\n`;
        if (ev.apiDocs) content += `[API DOCS]\n${ev.apiDocs}\n\n`;
        if (!content) content = 'No automated evidence. Use manual tools if provided.';

        return `<div class="evidence-viewer">${content}</div>`;
    },

    renderInput(task) {
        if (task.type === 'select') {
            return `
                <select id="input-${task.id}" class="sim-input">
                    <option value="">-- Select --</option>
                    ${task.options.map(o => `<option value="${o}">${o}</option>`).join('')}
                </select>`;
        }
        return `<input type="text" id="input-${task.id}" class="sim-input" placeholder="Enter findings here...">`;
    },

    async submitTask(taskId) {
        const inputEl = document.getElementById(`input-${taskId}`);
        const input = inputEl.value.trim();
        const task = this.currentScenario.tasks.find(t => t.id === taskId);
        const feedbackEl = document.getElementById(`feedback-${taskId}`);

        let isValid = false;
        if (task.validation.regex) isValid = task.validation.regex.test(input);
        else if (task.validation.match) isValid = input.toLowerCase() === task.validation.match.toLowerCase();

        if (isValid) {
            feedbackEl.innerHTML = `<span style="color:#4ade80"><i class="fa-solid fa-check-circle"></i> Correct! +${task.points} XP</span>`;

            // Update State
            this.progress[`${this.currentScenario.id}_${taskId}`] = true;
            localStorage.setItem('job_sim_progress', JSON.stringify(this.progress));

            // Visual success
            inputEl.style.borderColor = '#4ade80';

            // Check for Shift Complete
            if (this.calculateProgress() === 100) {
                setTimeout(() => {
                    alert('SHIFT COMPLETED! You successfully finished this scenario.');
                    this.backToDashboard();
                }, 1500);
            } else {
                // Auto next
                setTimeout(() => {
                    const idx = this.currentScenario.tasks.findIndex(t => t.id === taskId);
                    if (this.currentScenario.tasks[idx + 1]) this.renderWorkspace(this.currentScenario.tasks[idx + 1].id);
                }, 1000);
            }
        } else {
            // --- HEURISTIC ENGINE ANALYSIS ---
            let aiFeedback = null;
            if (window.HeuristicEngine) {
                // Check specifically for anti-patterns in the wrong answer
                const analysis = await window.HeuristicEngine.analyze(input, 'text');
                if (analysis.type === 'warning') {
                    aiFeedback = analysis.message;
                }
            }

            const helpMsg = aiFeedback
                ? `<strong><i class="fa-solid fa-triangle-exclamation"></i> Teaching Moment:</strong> ${aiFeedback}`
                : `Incorrect. Hint: ${task.validation.hint}`;

            feedbackEl.innerHTML = `<span style="color:#f87171">${helpMsg}</span>`;
            inputEl.style.borderColor = '#f87171';
        }
    },

    async askSeniorAnalyst(taskId) {
        const box = document.getElementById(`ai-mentor-${taskId}`);
        const task = this.currentScenario.tasks.find(t => t.id === taskId);
        const persona = this.currentRole.aiPersona;

        box.style.display = 'block';
        box.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Consulting Senior Analyst...';

        try {
            // Simulate API delay
            setTimeout(async () => {
                let response = "";

                if (window.HeuristicEngine) {
                    const insight = await window.HeuristicEngine.analyze(`help with task ${task.title}`, 'text');
                    response = insight.message;
                } else {
                    response = task.validation.hint;
                }

                box.innerHTML = `
                    <div class="ai-response-box">
                        <div class="ai-response-header">
                            <i class="fa-solid fa-user-astronaut"></i> ${persona.name} <span class="ai-tag">AI MENTOR</span>
                        </div>
                        <div>"${response}"</div>
                    </div>
                `;
            }, 800);
        } catch (e) {
            box.innerText = 'System Offline.';
        }
    }
};
