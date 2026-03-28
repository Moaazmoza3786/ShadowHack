/* ============================================================
   ROOM VIEWER SYSTEM V2.0
   Features: Split-Screen, Docker Integration, Terminal Support
   ============================================================ */

window.roomViewer = {
  // --- STATE ---
  currentRoomId: null,
  machineActive: false,
  machineTimer: null,
  machineIP: null,
  machineTimeLeft: 3600, // 1 hour
  containerId: null,
  currentRoomData: null, // Store active room data

  // --- INITIALIZATION ---
  loadRoom(roomId) {
    try {
      console.log('RoomViewer: Loading room...', roomId);
      this.currentRoomId = roomId;

      // Reset State
      this.machineActive = false;
      this.machineIP = null;
      document.getElementById('machine-status-bar')?.remove();

      if (!window.UnifiedLearningData) {
        throw new Error('UnifiedLearningData is not loaded.');
      }

      // 1. Get Room Data
      let room = null;
      let module = null;

      // Check Unified Data (Phase 3)
      const data = window.UnifiedLearningData.getRoomById(roomId);
      if (data && data.room) {
        room = data.room;
        module = data.module;
      }
      // Fallback to Legacy/CTF checks...
      else if (typeof roomsData !== 'undefined' && roomsData[roomId]) {
        room = roomsData[roomId];
      } else if (typeof ctfChallengesData !== 'undefined' && ctfChallengesData[roomId]) {
        room = this.normalizeCTF(ctfChallengesData[roomId]);
      }

      if (!room) {
        console.error('Room not found:', roomId);
        return this.renderErrorState(roomId);
      }

      this.currentRoomData = room; // Persist for machine logic

      // 2. Start Machine Check (Async)
      this.checkActiveMachine();

      // 3. Render
      return this.renderLayout(room, module);

    } catch (err) {
      console.error('RoomViewer Error:', err);
      return `<div class="p-5 text-center text-danger">
        <h2>Error Loading Lab</h2>
        <p>${err.message}</p>
        <pre class="text-start bg-dark p-3 mt-3 border border-danger text-light">${err.stack}</pre>
      </div>`;
    }
  },

  // Ensure task HTML stays rendered even if other scripts touch the DOM
  hydrateTaskContent() {
    const room = this.currentRoomData;
    if (!room || !room.tasks) return;

    room.tasks.forEach(task => {
      const collapse = document.getElementById(`collapse${task.id}`);
      if (!collapse) return;

      // Initial paint
      const box = collapse.querySelector('.task-content-box');
      if (box) this.renderTaskIntoShadow(box, task);

      // Repaint on accordion open
      collapse.addEventListener('show.bs.collapse', () => {
        const b = collapse.querySelector('.task-content-box');
        if (b) this.renderTaskIntoShadow(b, task);
      });

      // MutationObserver to restore content if any script clears it
      if (!task._contentObserver) {
        const target = collapse.querySelector('.task-content-box');
        if (target) {
          const observer = new MutationObserver((mutations) => {
            const host = target.querySelector('.bl-shadow-host');
            const hasContent = host && host.shadowRoot && host.shadowRoot.innerHTML.trim().length > 0;
            if (!hasContent) this.renderTaskIntoShadow(target, task);
          });
          observer.observe(target, { childList: true, subtree: true });
          task._contentObserver = observer;
        }
      }
    });

    // Guard: re-assert content a few times in case other scripts wipe it
    this.ensureTaskContentIntegrity();
    // Aggressive guard: keep repainting via rAF for a few seconds
    this.aggressiveContentGuard();
  },

  aggressiveContentGuard() {
    const room = this.currentRoomData;
    if (!room || !room.tasks) return;

    let frames = 0;
    const maxFrames = 300; // ~5 seconds at 60fps
    const tick = () => {
      frames++;
      room.tasks.forEach(task => {
        const box = document.querySelector(`#collapse${task.id} .task-content-box`);
        if (!box) return;
        const host = box.querySelector('.bl-shadow-host');
        const hasContent = host && host.shadowRoot && host.shadowRoot.innerHTML.trim().length > 0;
        if (!hasContent) this.renderTaskIntoShadow(box, task);
      });
      if (frames < maxFrames) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  },

  ensureTaskContentIntegrity() {
    const room = this.currentRoomData;
    if (!room || !room.tasks) return;

    let attempts = 0;
    const maxAttempts = 12; // ~6s if interval 500ms
    const timer = setInterval(() => {
      attempts += 1;
      room.tasks.forEach(task => {
        const box = document.querySelector(`#collapse${task.id} .task-content-box`);
        if (!box) return;
        const host = box.querySelector('.bl-shadow-host');
        const hasContent = host && host.shadowRoot && host.shadowRoot.innerHTML.trim().length > 0;
        if (!hasContent) this.renderTaskIntoShadow(box, task);
      });
      if (attempts >= maxAttempts) clearInterval(timer);
    }, 500);
  },

  renderTaskIntoShadow(box, task) {
    const host = box.querySelector('.bl-shadow-host');
    if (!host) return;
    const shadow = host.shadowRoot || host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `<style>:host{color:inherit;font-family:inherit;} p{margin:0 0 1em;} pre{background:#111;padding:12px;border-radius:8px;border:1px solid #333;overflow:auto;}</style>${this.getCachedTaskContent(task)}`;
  },

  _findCTFRoom(roomId) {
    if (typeof ctfChallengesData !== 'undefined') {
      const ctf = ctfChallengesData.find(c => c.id === roomId);
      if (ctf) return this.normalizeCTF(ctf);
    }
    if (typeof CTFData !== 'undefined') {
      for (const list of Object.values(CTFData)) {
        const ctf = list.find(c => c.id === roomId);
        if (ctf) return this.normalizeCTF(ctf);
      }
    }
    return null;
  },

  renderErrorState(roomId) {
    return `
            <div class="d-flex flex-column align-items-center justify-content-center h-100 text-white">
                <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                <h3>Room Not Found</h3>
                <p>Could not locate logic for ID: <code>${roomId}</code></p>
                <button class="btn btn-outline-light" onclick="loadPage('home')">Return Home</button>
            </div>
        `;
  },

  // Render task content with graceful fallback (HTML-first, then Markdown)
  renderTaskContentSafe(task = {}) {
    try {
      const raw = task.content || task.body || '';

      // If content already contains HTML tags, prefer direct rendering
      const seemsHTML = /<\w+[^>]*>/.test(raw);

      if (seemsHTML) {
        return raw;
      }

      if (typeof marked !== 'undefined' && typeof marked.parse === 'function') {
        // Ensure GFM enabled and IDs disabled to avoid collisions
        if (marked.setOptions) {
          marked.setOptions({ gfm: true, breaks: true, mangle: false, headerIds: false });
        }

        let html = marked.parse(raw || '*(No content provided)*');
        if (!html || !html.trim()) html = raw; // fallback to raw if parsing empty
        return html;
      }

      return `<pre>${raw || 'No Content'}</pre>`;
    } catch (e) {
      return `<div style="color:red">Marked Error: ${e.message}</div><pre>${task.content || ''}</pre>`;
    }
  },

  // Cache rendered task content to avoid it being lost by other scripts/animations
  getCachedTaskContent(task = {}) {
    if (task._renderedContent) return task._renderedContent;
    task._renderedContent = this.renderTaskContentSafe(task);
    return task._renderedContent;
  },

  // --- LAYOUT RENDERING ---
  renderLayout(room) {
    return `
          <div class="cyber-room-container fade-in">
            <!-- Room Header -->
            <div class="room-header-cyber">
              <div class="d-flex align-items-center">
                <button class="btn btn-sm btn-outline-secondary me-3" style="border-color: #333; color: #888;" onclick="loadPage('${room.isCTF ? 'practice' : 'learn'}')">
                  <i class="fa-solid fa-arrow-left"></i>
                </button>
                <div class="room-title-box">
                    <h5 class="m-0 room-title-text">${room.title}</h5>
                    <small class="room-id-badge">${room.id}</small>
                </div>
              </div>
              
              <div class="d-flex align-items-center gap-2">
                <!-- VPN Content -->
                <button class="btn btn-sm btn-outline-info d-none d-md-block" style="border-color: var(--neon-cyan); color: var(--neon-cyan);" onclick="roomViewer.downloadVPN()" title="VPN Config">
                  <i class="fa-solid fa-shield-halved"></i> <span class="d-none d-lg-inline">VPN</span>
                </button>
                
                <div id="machine-status" class="d-flex align-items-center">
                  ${this.getMachineStatusHTML()}
                </div>
                
                <button class="btn btn-glitch-v2 ${this.machineActive ? 'btn-terminate' : 'btn-active'}" 
                        style="--btn-color: ${this.machineActive ? '#ef4444' : '#22c55e'}; height: 38px;"
                        id="btn-start-machine" onclick="roomViewer.toggleMachine()">
                  <i class="fa-solid fa-power-off"></i> ${this.machineActive ? 'TERMINATE' : 'DEPLOY SYSTEM'}
                </button>
              </div>
            </div>
    
            ${room.topology ? this.renderTopologyMap(room.topology) : ''}
            
            ${!room.topology ? `
            <!-- Machine Control Bar (Conditional) -->
            <div id="machine-control-bar" class="machine-control-bar" style="display: ${this.machineActive ? 'flex' : 'none'} !important; background: #111; border-bottom: 1px solid #333;">
              <div class="d-flex align-items-center gap-3">
                <div class="target-ip-box" style="background: rgba(0, 243, 255, 0.05); border: 1px solid var(--neon-cyan);">
                  <span class="text-info small" style="color: var(--neon-cyan) !important;">TARGET:</span>
                  <span id="target-ip-display" class="target-ip-text font-monospace" style="color: #fff;">${this.machineIP || 'Loading...'}</span>
                  <button class="btn btn-sm btn-link py-0 px-2 text-white-50" onclick="roomViewer.copyIP()">
                    <i class="fa-solid fa-copy"></i>
                  </button>
                </div>
                <div class="d-flex align-items-center gap-2">
                  <i class="fa-solid fa-clock text-warning"></i>
                  <span id="control-bar-timer" class="font-monospace text-warning header-font">--:--</span>
                </div>
              </div>
              
              <div class="d-flex align-items-center gap-2">
                <button class="btn btn-sm btn-outline-success" style="border-color: #22c55e; color: #22c55e;" id="btn-add-time" onclick="roomViewer.addTime()">
                  <i class="fa-solid fa-plus"></i> +1h
                </button>
                <button class="btn btn-sm btn-outline-warning" style="border-color: #f59e0b; color: #f59e0b;" id="btn-reset-machine" onclick="roomViewer.resetMachine()">
                  <i class="fa-solid fa-rotate"></i> Reset
                </button>
              </div>
            </div>
    
            <!-- Split Content Area -->
            <div class="room-split-container" id="room-split-container">
              
              <!-- LEFT PANEL: TASKS -->
              <div class="task-panel-cyber" id="left-panel" style="width: ${this.getSavedPanelWidth()};">
                 <div class="p-4">
                    ${this.renderTasks(room)}
                 </div>
              </div>
    
              <!-- RESIZER -->
              <div class="resizer-cyber" id="panel-resizer"></div>
    
              <!-- RIGHT PANEL: CONTENT/MACHINE -->
              <div class="right-panel-cyber" id="right-panel">
                <div id="machine-view" class="w-100 h-100 d-flex align-items-center justify-content-center">
                  ${this.getRightPanelContent(room)}
                </div>
              </div>
            </div>
            ` : ''}
          </div>
          <script>
            // Re-hydrate task content after DOM insertion & on accordion open (prevents empty panels)
            setTimeout(() => { try { window.roomViewer && window.roomViewer.hydrateTaskContent(); } catch (e) { console.error(e); } }, 50);
          </script>
        `;
  },

  // --- TASK RENDERING ---
  renderTasks(room) {
    // Safety check for empty room components
    if (!room || !room.tasks) {
      return `<div class="p-4 text-center text-secondary">
                  <i class="fas fa-exclamation-circle fa-2x mb-3"></i>
                  <p>No mission data available.</p>
                </div>`;
    }

    // Calculate Progress
    const totalQuestions = room.tasks.reduce((acc, t) => acc + (t.questions ? t.questions.length : 0), 0);
    const solvedQuestions = room.tasks.reduce((acc, t) => {
      return acc + (t.questions ? t.questions.filter(q => this.isQuestionSolved(q.id)).length : 0);
    }, 0);
    const progressPercent = totalQuestions > 0 ? Math.round((solvedQuestions / totalQuestions) * 100) : 0;

    return `
          <!-- Progress Card -->
          <div class="cyber-panel p-3 mb-4" style="border-width: 1px;">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h6 class="m-0 text-white font-monospace"><i class="fa-solid fa-clipboard-check me-2" style="color:var(--neon-green)"></i>MISSION PROGRESS</h6>
              <span class="badge" style="background:rgba(34,197,94,0.1); color:var(--neon-green)">${solvedQuestions}/${totalQuestions} FLAGGED</span>
            </div>
            <div class="progress" style="height: 6px; background: rgba(255,255,255,0.05);">
              <div class="progress-bar" style="width: ${progressPercent}%; background: var(--neon-green); box-shadow: 0 0 10px var(--neon-green);"></div>
            </div>
            <div class="d-flex justify-content-between mt-2 small font-monospace">
              <span class="text-white-50"><i class="fa-solid fa-bolt me-1 text-warning"></i>${room.difficulty || 'Normal'}</span>
              <span class="text-white-50"><i class="fa-solid fa-hourglass-half me-1"></i>${room.estimatedTime || 'N/A'}</span>
            </div>
          </div>
    
          <!-- Tasks Accordion -->
          <div class="accordion task-accordion-cyber" id="tasksAccordion">
            ${room.tasks.map((task, index) => {
      const isTaskSolved = task.questions && task.questions.length > 0 && task.questions.every(q => this.isQuestionSolved(q.id));
      return `
              <div class="accordion-item">
                <h2 class="accordion-header" id="heading${task.id}">
                  <button class="accordion-button ${index === 0 ? '' : 'collapsed'} ${isTaskSolved ? 'solved' : ''}" 
                          type="button" 
                          data-bs-toggle="collapse" 
                          data-bs-target="#collapse${task.id}">
                    <div class="d-flex align-items-center w-100">
                      <div class="task-circle-cyber ${isTaskSolved ? 'completed' : ''}">
                        ${isTaskSolved ? '<i class="fa-solid fa-check"></i>' : index + 1}
                      </div>
                      <div class="flex-grow-1">
                        <div class="fw-bold">${task.title}</div>
                      </div>
                      <i class="fa-solid fa-chevron-down ms-2"></i>
                    </div>
                  </button>
                </h2>
                <div id="collapse${task.id}" class="accordion-collapse collapse ${index === 0 ? 'show' : ''}" data-bs-parent="#tasksAccordion">
                  <div class="task-body-cyber prose">
                        <div class="task-content-box ai-tutor-enabled">
                            <div class="bl-shadow-host" data-task-id="${task.id}"></div>
                        </div>
                    <div class="task-questions mt-4">
                      <h6 class="fw-bold mb-3" style="color:var(--neon-cyan); letter-spacing:1px;"><i class="fa-solid fa-terminal me-2"></i>OBJECTIVES</h6>
                      ${task.questions ? task.questions.map((q, qIndex) => this.renderQuestion(q, qIndex)).join('') : '<p class="text-muted">No questions.</p>'}
                    </div>
                  </div>
                </div>
              </div>
            `}).join('')}
          </div>
        `;
  },

  renderQuestion(q, qIndex) {
    const isSolved = this.isQuestionSolved(q.id);
    return `
          <div class="cyber-question-box ${isSolved ? 'solved' : ''}">
            <p class="mb-2 fw-semibold text-white font-monospace">${q.text}</p>
            
            ${q.hint ? `
                <div class="mb-2 d-flex gap-2">
                    <button class="btn btn-sm btn-link text-warning p-0 text-decoration-none font-monospace small" 
                            type="button" data-bs-toggle="collapse" data-bs-target="#hint-${q.id}">
                        <i class="fa-regular fa-lightbulb"></i> ACCESS INTEL
                    </button>
                    <button class="btn btn-sm btn-link text-info p-0 text-decoration-none font-monospace small" 
                            onclick="AISecurityAssistant.askForHint('${this.currentRoomId}', 'What should I do here? Question: ${q.text.replace(/'/g, "\\'")}')">
                        <i class="fa-solid fa-robot"></i> INTERROGATE GRAVITY
                    </button>
                    <div class="collapse w-100" id="hint-${q.id}">
                        <div class="p-2 mt-1 bg-black border border-warning border-opacity-25 rounded text-warning small font-monospace">
                            [INTEL]: ${q.hint}
                        </div>
                    </div>
                </div>
            ` : `
                <div class="mb-2">
                    <button class="btn btn-sm btn-link text-info p-0 text-decoration-none font-monospace small" 
                            onclick="AISecurityAssistant.askForHint('${this.currentRoomId}', 'What should I do here? Question: ${q.text.replace(/'/g, "\\'")}')">
                        <i class="fa-solid fa-robot"></i> INTERROGATE GRAVITY
                    </button>
                </div>
            `}

            <div class="cyber-input-group">
                <input type="text" class="cyber-input" 
                       id="input-${q.id}" placeholder="flag{...}" 
                       ${isSolved ? 'disabled value="' + q.answer + '"' : ''}>
                <button class="btn btn-glitch-v2 ${isSolved ? 'btn-success' : 'btn-primary'}" 
                        style="--btn-color: ${isSolved ? '#22c55e' : '#00f3ff'}; height: 38px; min-width: 100px;"
                        onclick="roomViewer.submitAnswer('${q.id}', '${q.answer}', ${q.points})"
                        ${isSolved ? 'disabled' : ''}>
                    ${isSolved ? 'CAPTURED' : 'SUBMIT'}
                </button>
            </div>
            ${isSolved ? '<small class="text-success mt-1 d-block font-monospace"><i class="fa-solid fa-check-circle"></i> Flag verified</small>' : ''}
          </div>
        `;
  },

  // --- ANSWER LOGIC ---
  submitAnswer(qId, correctAnswer, points) {
    const input = document.getElementById(`input-${qId}`);
    const val = input.value.trim();

    if (val === correctAnswer) {
      this.markQuestionSolved(qId);

      // UI Feedback
      input.disabled = true;
      input.classList.add('is-valid');
      const btn = input.nextElementSibling;
      btn.className = 'btn btn-success';
      btn.innerHTML = '<i class="fa-solid fa-check"></i>';
      btn.disabled = true;

      // Optional XP
      if (typeof gamification !== 'undefined') gamification.addXP(points || 10, 'Flag Captured');

      // Sound
      this.playSuccessSound();

    } else {
      input.classList.add('is-invalid');
      if (typeof showToast === 'function') showToast('Incorrect Flag', 'danger');
      setTimeout(() => input.classList.remove('is-invalid'), 1500);
    }
  },

  isQuestionSolved(qId) {
    const solved = JSON.parse(localStorage.getItem('solved_questions') || '[]');
    return solved.includes(qId);
  },

  markQuestionSolved(qId) {
    const solved = JSON.parse(localStorage.getItem('solved_questions') || '[]');
    if (!solved.includes(qId)) {
      solved.push(qId);
      localStorage.setItem('solved_questions', JSON.stringify(solved));
    }
  },

  playSuccessSound() {
    try {
      const audio = new Audio('https://assets.mixkit.co/active_storage/sfx/2000/2000-preview.mp3');
      audio.volume = 0.3;
      audio.play();
    } catch (e) { }
  },

  // --- MACHINE / DOCKER LOGIC ---
  // --- MACHINE / DOCKER LOGIC ---
  toggleMachine() {
    // Safety: If active but IP is invalid, treat as stopped
    const isValid = this.machineIP && this.machineIP.includes('.');

    if (this.machineActive && !isValid) {
      console.log('RoomViewer: Resetting invalid machine state...');
      this.stopMachine(); // Clean reset
      setTimeout(() => this.startMachine(), 500); // Restart
      return;
    }

    if (this.machineActive) {
      if (confirm("Terminate active machine?")) this.stopMachine();
    } else {
      this.startMachine();
    }
  },

  async startMachine() {
    // ... existing start logic ...
    const btn = document.getElementById('btn-start-machine');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Init...'; }

    // Mock call -> Replace with real backend
    const userId = 1;
    const labId = this.currentRoomId;

    try {
      // Real Backend Call
      const res = await fetch(`http://localhost:5000/api/labs/spawn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, lab_id: labId, image_name: 'breachlabs/base' })
      });
      const data = await res.json();

      if (data.success) {
        this.activateMachineState(data);
        if (typeof showToast === 'function') showToast('Machine Deployed!', 'success');
      } else {
        throw new Error(data.error);
      }
    } catch (e) {
      console.error(e);
      if (confirm("Backend unreachable. Start Simulation Mode?")) {
        this.activeSimulationMode();
      } else {
        this.resetUI();
      }
    }
  },

  activeSimulationMode() {
    // Use target_ip from room data, or fallback to a random lab IP
    const fallbackIP = `10.10.${Math.floor(Math.random() * 255)}.55`;
    const finalIP = (this.currentRoomData && this.currentRoomData.target_ip) ? this.currentRoomData.target_ip : fallbackIP;

    this.activateMachineState({
      ip: finalIP,
      connection_string: finalIP,
      timeout_minutes: 60
    });
  },

  activateMachineState(data) {
    this.machineActive = true;
    this.machineIP = data.ip;
    this.machineTimeLeft = (data.timeout_minutes || 60) * 60;

    this.updateMachineUI();
    this.startTimer();
    this.loadRightPanelContent();

    // Show Bar
    const bar = document.getElementById('machine-control-bar');
    if (bar) bar.style.display = 'flex';

    // Init Resizer once DOM is ready
    setTimeout(() => this.initResizer(), 500);
  },

  async checkActiveMachine() {
    try {
      const res = await fetch(`http://localhost:5000/api/labs/status/1`); // User 1
      const data = await res.json();

      if (data.status === 'running') {
        // Validate IP from backend
        if (data.ip) {
          this.activateMachineState(data);
        } else {
          // Backend has invalid IP? Stop it.
          this.stopMachine();
        }
      }
    } catch (e) {
      // Logic to check localStorage
      const saved = JSON.parse(localStorage.getItem('active_machine_' + this.currentRoomId));
      if (saved && saved.active) {
        const now = Date.now();
        if (now < saved.expiresAt) {
          this.machineActive = true;
          this.machineIP = saved.ip;
          this.machineTimeLeft = Math.floor((saved.expiresAt - now) / 1000);
          this.updateMachineUI();
          this.startTimer();
          this.loadRightPanelContent();
        } else {
          localStorage.removeItem('active_machine_' + this.currentRoomId);
        }
      }
    }
  },

  async stopMachine() {
    const btn = document.getElementById('btn-start-machine');
    if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Stopping...';

    try {
      await fetch(`http://localhost:5000/api/labs/kill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: 1 })
      });
    } catch (e) { }

    this.machineActive = false;
    this.machineIP = null;
    if (this.machineTimer) clearInterval(this.machineTimer);

    this.updateMachineUI();
    document.getElementById('machine-control-bar').style.display = 'none';
    this.loadRightPanelContent(); // Reset to default
  },

  startTimer() {
    if (this.machineTimer) clearInterval(this.machineTimer);
    this.machineTimer = setInterval(() => {
      if (this.machineTimeLeft > 0) {
        this.machineTimeLeft--;
        this.updateTimerDisplay();
      } else {
        this.stopMachine();
      }
    }, 1000);
  },

  updateTimerDisplay() {
    const m = Math.floor(this.machineTimeLeft / 60);
    const s = this.machineTimeLeft % 60;
    const str = `${m}:${s.toString().padStart(2, '0')}`;

    const el = document.getElementById('control-bar-timer');
    if (el) el.innerText = str;

    const el2 = document.getElementById('machine-timer');
    if (el2) el2.innerText = str;
  },

  updateMachineUI() {
    const btn = document.getElementById('btn-start-machine');
    const ipDisplay = document.getElementById('target-ip-display');

    if (this.machineActive) {
      if (btn) {
        btn.className = 'btn btn-sm btn-danger';
        btn.innerHTML = '<i class="fa-solid fa-power-off"></i> Terminate';
        btn.disabled = false;
      }
      if (ipDisplay) ipDisplay.innerText = this.machineIP;
    } else {
      if (btn) {
        btn.className = 'btn btn-sm btn-success';
        btn.innerHTML = '<i class="fa-solid fa-power-off"></i> Start Machine';
        btn.disabled = false;
      }
    }
  },

  // --- UTILITIES ---
  initResizer() {
    const resizer = document.getElementById('panel-resizer');
    const leftPanel = document.getElementById('left-panel');
    const container = document.getElementById('room-split-container');

    if (!resizer || !leftPanel || !container) return;

    let x = 0;
    let w = 0;

    const mouseDown = (e) => {
      x = e.clientX;
      w = parseInt(window.getComputedStyle(leftPanel).width, 10);
      document.addEventListener('mousemove', mouseMove);
      document.addEventListener('mouseup', mouseUp);
      resizer.classList.add('resizing');
    };

    const mouseMove = (e) => {
      const dx = e.clientX - x;
      const newW = ((w + dx) * 100) / container.getBoundingClientRect().width;
      if (newW > 20 && newW < 80) leftPanel.style.width = `${newW}%`;
    };

    const mouseUp = () => {
      document.removeEventListener('mousemove', mouseMove);
      document.removeEventListener('mouseup', mouseUp);
      resizer.classList.remove('resizing');
      localStorage.setItem('room_panel_width', leftPanel.style.width);
    };

    resizer.addEventListener('mousedown', mouseDown);
  },

  getSavedPanelWidth() {
    return localStorage.getItem('room_panel_width') || '40%';
  },

  // --- LAYOUT HELPERS ---
  getMachineStatusHTML() {
    if (this.machineActive) {
      return `
            <div class="machine-status-cyber animate__animated animate__fadeIn">
                <div class="d-flex align-items-center gap-2">
                    <div class="status-indicator online"></div>
                    <span style="color:var(--neon-green)">ONLINE</span>
                </div>
                <div style="width:1px; height:15px; background:#444;"></div>
                <span class="text-info font-monospace small" style="text-shadow:0 0 5px var(--neon-cyan)">${this.machineIP}</span>
                <div style="width:1px; height:15px; background:#444;"></div>
                <div class="d-flex align-items-center">
                    <i class="fa-solid fa-clock text-warning me-2"></i>
                    <span id="machine-timer" class="machine-timer-cyber small">
                        ${Math.floor(this.machineTimeLeft / 60)}:${(this.machineTimeLeft % 60).toString().padStart(2, '0')}
                    </span>
                </div>
            </div>
          `;
    }
    return `
        <div class="machine-status-cyber opacity-50">
            <div class="status-indicator bg-danger"></div>
            <span class="text-secondary ms-2">SYSTEM OFFLINE</span>
        </div>
    `;
  },

  async checkActiveMachine() {
    try {
      // Assume user_id=1 for now
      const res = await fetch('http://localhost:5000/api/labs/status?user_id=1');
      const data = await res.json();
      if (data.success && data.active && data.lab) {
        // Restore state
        this.activateMachineState({
          ip: data.lab.ip,
          timeout_minutes: 60 // Should calc remaining from expires_at
        });
      }
    } catch (e) {
      console.log('Backend offline or no active machine');
    }
  },

  // --- VIEW TOGGLE ---
  viewMode: 'web', // 'web' or 'terminal'

  toggleView(mode) {
    this.viewMode = mode;
    this.loadRightPanelContent();
  },

  getRightPanelContent(room) {
    if (!this.machineActive) {
      return `
                <div class="offline-frame-cyber">
                    <i class="fas fa-server offline-glitch-icon mb-4"></i>
                    <h4 class="text-white font-monospace" style="letter-spacing: 2px;">SYSTEM_OFFLINE</h4>
                    <p class="text-secondary font-monospace">Deploy machine to establish uplink.</p>
                </div>
            `;
    }

    // Header Controls
    const header = `
        <div class="p-2 d-flex align-items-center justify-content-between" style="background: #080808; border-bottom: 1px solid #333;">
            <div class="d-flex align-items-center gap-2">
                <span class="badge bg-success me-2 animate__animated animate__pulse animate__infinite">LIVE</span>
                <small class="text-info font-monospace">${this.machineIP}::22</small>
            </div>
            <div class="btn-group btn-group-sm">
                <button class="btn btn-sm btn-outline-secondary ${this.viewMode === 'web' ? 'active' : ''}" 
                        style="${this.viewMode === 'web' ? 'background:#222; color:var(--neon-cyan); border-color:#444;' : 'border-color:#333; color:#666;'}"
                        onclick="roomViewer.toggleView('web')">
                    <i class="fas fa-globe me-1"></i> WEB
                </button>
                <button class="btn btn-sm btn-outline-secondary ${this.viewMode === 'terminal' ? 'active' : ''}" 
                        style="${this.viewMode === 'terminal' ? 'background:#222; color:var(--neon-cyan); border-color:#444;' : 'border-color:#333; color:#666;'}"
                        onclick="roomViewer.toggleView('terminal')">
                    <i class="fas fa-terminal me-1"></i> TERMINAL
                </button>
            </div>
            <div class="d-flex gap-2">
                ${this.viewMode === 'web' ? `
                <button class="btn btn-xs btn-outline-secondary" style="border-color:#333; color:#888;" onclick="document.getElementById('web-lab-frame').src += ''" title="Refresh">
                    <i class="fas fa-sync"></i>
                </button>
                ` : ''}
                <button class="btn btn-xs btn-outline-secondary" style="border-color:#333; color:#888;" onclick="window.open('http://${this.machineIP}', '_blank')" title="Open New Tab">
                    <i class="fas fa-external-link-alt"></i>
                </button>
            </div>
        </div>
    `;

    // Active Content
    let content = '';

    if (this.viewMode === 'web') {
      // Validate IP - if it's the default placeholder or unreachable, show placeholder
      const isValidIP = this.machineIP && this.machineIP.includes('.');

      if (!this.machineActive || !isValidIP) {
        content = `
            <div class="flex-grow-1 bg-black d-flex flex-column align-items-center justify-content-center text-center p-5">
                <i class="fas fa-satellite-dish fa-4x text-muted mb-3 fa-spin" style="animation-duration: 5s;"></i>
                <h4 class="text-white-50 font-monospace">ESTABLISHING LINK...</h4>
                <p class="text-muted small font-monospace" style="max-width: 400px;">Waiting for packet acknowledgment from ${this.machineIP || 'Host'}...</p>
                <button class="btn btn-success mt-4 cyber-btn" onclick="roomViewer.toggleMachine()" style="box-shadow: 0 0 15px var(--neon-green);">
                    <i class="fas fa-power-off"></i> FORCE RESTART
                </button>
            </div>
          `;
      } else {
        content = `
            <div class="flex-grow-1 bg-black position-relative">
                 <iframe id="web-lab-frame" src="http://${this.machineIP}" class="w-100 h-100 border-0" title="Lab Interface" onerror="this.srcdoc='<div class=\\'text-center p-5\\'><h3>Connection Failed</h3><p>Ensure the machine is fully booted.</p></div>'"></iframe>
                 <div class="position-absolute top-50 start-50 translate-middle text-center" style="z-index: 0; pointer-events: none;">
                    <i class="fas fa-circle-notch fa-spin text-muted fa-2x"></i>
                    <p class="text-muted small mt-2">Connecting to ${this.machineIP}...</p>
                 </div>
            </div>
        `;
      }
    } else {
      // Trigger Terminal Init
      setTimeout(() => {
        this.initTerminal('terminal-container');
      }, 100);

      content = `
            <div class="flex-grow-1 bg-black position-relative split-right" style="overflow: hidden;">
                <div id="terminal-container" class="w-100 h-100"></div>
            </div>
        `;
    }

    return `
            <div class="w-100 h-100 bg-black d-flex flex-column">
                ${header}
                ${content}
            </div>
        `;
  },

  // --- TERMINAL SYSTEM ---
  term: null,
  fitAddon: null,
  commandBuffer: '',

  initTerminal(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clean up previous instance
    if (this.term) {
      this.term.dispose();
      this.term = null;
    }

    // Initialize xterm.js
    this.term = new Terminal({
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", monospace',
      fontSize: 14,
      theme: {
        background: '#0a0a0f',
        foreground: '#00f3ff',
        cursor: '#00f3ff',
        selection: 'rgba(0, 243, 255, 0.3)'
      }
    });

    // Load Fit Addon
    if (typeof FitAddon !== 'undefined') {
      this.fitAddon = new FitAddon.FitAddon();
      this.term.loadAddon(this.fitAddon);
    }

    this.term.open(container);
    if (this.fitAddon) this.fitAddon.fit();

    // Welcome Message
    this.term.writeln('\x1b[1;32m[*] SECURE SHELL UPLINK ESTABLISHED\x1b[0m');
    this.term.writeln('Connected to: ' + (this.machineIP || 'UNKNOWN_HOST'));
    this.term.writeln('Type "help" for available commands.\n');
    this.term.write('\r\n\x1b[1;36mroot@breachlabs:~#\x1b[0m ');

    // Handle Resize
    window.addEventListener('resize', () => {
      if (this.fitAddon) this.fitAddon.fit();
    });

    // Handle Input
    this.term.onData(e => {
      this.handleTerminalInput(e);
    });

    this.commandBuffer = '';
  },

  handleTerminalInput(data) {
    const ord = data.charCodeAt(0);

    // Enter Key
    if (ord === 13) {
      this.term.write('\r\n');
      this.processCommand(this.commandBuffer);
      this.commandBuffer = '';
    }
    // Backspace
    else if (ord === 127) {
      if (this.commandBuffer.length > 0) {
        this.commandBuffer = this.commandBuffer.slice(0, -1);
        this.term.write('\b \b');
      }
    }
    // Normal Check
    else if (ord >= 32 && ord <= 126) {
      this.commandBuffer += data;
      this.term.write(data);
    }
  },

  async processCommand(cmd) {
    cmd = cmd.trim();
    if (!cmd) {
      this.prompt();
      return;
    }

    const parts = cmd.split(' ');
    const main = parts[0].toLowerCase();

    // Client-side Commands
    if (main === 'clear') {
      this.term.clear();
      this.prompt();
      return;
    }
    if (main === 'help') {
      this.term.writeln('\r\nAvailable Commands:');
      this.term.writeln('  \x1b[33mhelp\x1b[0m     - Show this help menu');
      this.term.writeln('  \x1b[33mclear\x1b[0m    - Clear terminal screen');
      this.term.writeln('  \x1b[33mping\x1b[0m     - Test connectivity');
      this.term.writeln('  \x1b[33msubmit\x1b[0m   - Submit a captured flag');
      this.term.writeln('  \x1b[33mnmap\x1b[0m     - Network exploration tool');
      this.term.writeln('  \x1b[33mcurl\x1b[0m     - Transfer data from or to a server');
      this.prompt();
      return;
    }
    if (main === 'submit') {
      const flag = parts[1];
      if (!flag) {
        this.term.writeln('\r\x1b[31mUsage: submit <flag>\x1b[0m');
      } else {
        await this.submitFlagFromTerm(flag);
      }
      this.prompt();
      return;
    }

    // Server-side Execution
    this.term.writeln(''); // New line for output
    try {
      const res = await fetch('http://localhost:5000/api/labs/shell', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 1, // Default user
          command: cmd
        })
      });

      const data = await res.json();
      if (data.success) {
        // Fix newlines for xterm
        const output = data.output.replace(/\n/g, '\r\n');
        this.term.write(output);
      } else {
        this.term.writeln(`\x1b[31mError: ${data.error}\x1b[0m`);
      }
    } catch (e) {
      this.term.writeln(`\x1b[31mConnection Fail: ${e.message}\x1b[0m`);
    }

    this.prompt();
  },

  prompt() {
    this.term.write('\r\n\x1b[1;36mroot@breachlabs:~#\x1b[0m ');
  },

  async submitFlagFromTerm(flag) {
    // Mock finding the question ID... in reality we might need to know which question
    // For now, let's just use the check_flag endpoint which checks against the LAB flag
    try {
      const res = await fetch('http://localhost:5000/api/flag/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 1,
          lab_id: this.currentRoomId,
          flag: flag
        })
      });
      const data = await res.json();
      if (data.correct) {
        this.term.writeln(`\x1b[1;32m[+] CORRECT! Flag Accepted.\x1b[0m`);
        this.term.writeln(`\x1b[1;32m[+] Points Earned: ${data.points_earned}\x1b[0m`);
        // Play sound
        this.playSuccessSound();
        // Refresh tasks UI if possible
        const qId = `flag-${this.currentRoomId}-0`; // Best guess or need loop
        this.markQuestionSolved(qId);
        this.renderLayout(this.currentRoomData); // naive refresh
      } else {
        this.term.writeln(`\x1b[1;31m[-] WRONG FLAG. Try harder.\x1b[0m`);
      }
    } catch (e) {
      this.term.writeln(`\x1b[31mError submitting flag: ${e.message}\x1b[0m`);
    }
  },

  async downloadVPN() {
    try {
      const res = await fetch('http://localhost:5000/api/vpn/config?user_id=1');
      const data = await res.json();

      if (data.success) {
        const element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(data.config_text));
        element.setAttribute('download', data.filename);
        element.style.display = 'none';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);

        if (typeof showToast === 'function') showToast('OpenVPN Configuration Downloaded', 'success');
      } else {
        alert('Error fetching VPN config.');
      }
    } catch (e) {
      console.error(e);
      alert('Failed to connect to backend.');
    }
  },

  copyIP() {
    if (this.machineIP) navigator.clipboard.writeText(this.machineIP);
  },

  addTime() {
    this.machineTimeLeft += 3600;
    this.updateTimerDisplay();
  },

  resetMachine() {
    this.stopMachine().then(() => setTimeout(() => this.startMachine(), 500));
  },

  loadRightPanelContent() {
    const panel = document.getElementById('right-panel');
    if (panel) {
      panel.innerHTML = `<div id="machine-view" class="w-100 h-100 d-flex align-items-center justify-content-center">
                  ${this.getRightPanelContent(window.UnifiedLearningData?.getRoomById(this.currentRoomId)?.room || {})}
                </div>`;
    }
  },

  // --- HELPER FOR CTF ---
  normalizeCTF(ctf) {
    return {
      isCTF: true,
      id: ctf.id,
      title: ctf.title,
      description: ctf.description,
      difficulty: ctf.difficulty,
      estimatedTime: ctf.estimatedTime || '60 min',
      tasks: [{
        id: 'task-1',
        title: 'Challenge',
        content: ctf.description,
        questions: ctf.flags ? ctf.flags.map((f, i) => ({
          id: `flag-${ctf.id}-${i}`, text: f.title || 'Flag', answer: f.flag, points: 10
        })) : [{ id: 'flag-1', text: 'Flag', answer: ctf.flag || 'test', points: 10 }]
      }]
    };
  },

  resetUI() {
    const btn = document.getElementById('btn-start-machine');
    if (btn) { btn.disabled = false; btn.innerHTML = 'Start Machine'; }
  }
};
