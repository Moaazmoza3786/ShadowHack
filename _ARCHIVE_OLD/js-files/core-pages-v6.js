/* ============================================================
   BREACHLABS V6 - CORE PAGES SYSTEM
   Includes: Dashboard, Profile, Settings
   Theme: HackingHub Replica (Dark/Purple/Glass)
   ============================================================ */

/* --- DASHBOARD V6 --- */
function pageDashboardV6() {
    const user = getUserDataV6(); // Helper to safely get user data

    // --- LOGIC: Last Active Room ---
    const lastRoomId = localStorage.getItem('lastActiveRoomId');
    const lastRoomTitle = localStorage.getItem('lastActiveRoomTitle') || 'Introduction to Cybersecurity';
    const resumeAction = lastRoomId ? `loadPage('room-viewer', '${lastRoomId}')` : `loadPage('learn')`;

    // --- LOGIC: Heatmap Generation ---
    // Generate 52 columns (weeks) x 7 rows (days) of random activity
    setTimeout(() => {
        const heatmap = document.getElementById('v6-heatmap');
        if (heatmap) {
            let html = '';
            for (let i = 0; i < 52; i++) {
                html += '<div class="heatmap-col">';
                for (let j = 0; j < 7; j++) {
                    const level = Math.random() > 0.7 ? Math.floor(Math.random() * 4) + 1 : 0; // 0-4 intensity
                    const color = level === 0 ? 'rgba(255,255,255,0.05)' :
                        level === 1 ? 'rgba(130, 115, 221, 0.3)' :
                            level === 2 ? 'rgba(130, 115, 221, 0.5)' :
                                level === 3 ? 'rgba(130, 115, 221, 0.7)' : '#8273DD';
                    html += `<div class="heatmap-cell" style="background: ${color};" title="Activity Level: ${level}"></div>`;
                }
                html += '</div>';
            }
            heatmap.innerHTML = html;
        }
    }, 100);

    return `
    ${getCoreStylesV6()}
    <div class="v6-page-container fade-in">
        <!-- HERO SECTION -->
        <div class="v6-hero-welcome">
            <div>
                <h1 class="hero-title">Welcome back, <span class="text-purple">${user.displayName}</span></h1>
                <p class="hero-subtitle">Ready to continue your hacking journey?</p>
            </div>
            <button class="v6-btn-primary large" onclick="${resumeAction}">
                <i class="fas fa-play"></i> Resume Learning
            </button>
        </div>
        
        <div class="v6-dashboard-grid fadeIn">
            <!-- Left Column: Stats & Progress -->
            <div class="v6-col-main">
                <div class="v6-section-header">
                    <h3><i class="fas fa-chart-line"></i> ${txt('مسارك الحالي', 'Your Trajectory')}</h3>
                </div>
                
                <!-- Active Path Card -->
                <div class="v6-card active-path-card" onclick="loadPage('learn')">
                    <div class="path-icon-large"><i class="fas fa-user-secret"></i></div>
                    <div class="path-info">
                        <span class="v6-badge purple">CURRENT PATH</span>
                        <h2>Junior Penetration Tester</h2>
                        <div class="v6-progress-wrapper">
                            <div class="v6-progress-bar"><div class="v6-progress-fill" style="width: 35%"></div></div>
                            <span class="v6-progress-text">35% COMPLETE</span>
                        </div>
                    </div>
                    <div class="path-arrow"><i class="fas fa-chevron-right"></i></div>
                </div>

                <!-- Activity Heatmap -->
                <div class="v6-card mt-4">
                     <div class="v6-card-header">
                        <h4>${txt('سجل النشاط', 'Activity Log')}</h4>
                        <span class="text-muted text-sm">365 Days</span>
                     </div>
                     <div class="v6-heatmap-container" id="v6-heatmap">
                        <!-- Populated by JS -->
                     </div>
                </div>
            </div>

            <!-- Right Column: Quick Actions & Leaderboard -->
            <div class="v6-col-side">
                 <div class="v6-card compact-card mb-3">
                    <div class="v6-stat-big">
                        <span class="value">${user.streak}</span>
                        <span class="label">DAY STREAK 🔥</span>
                    </div>
                 </div>

                 <div class="v6-card compact-card mb-3">
                    <div class="v6-stat-big">
                        <span class="value text-success">${user.xp.toLocaleString()}</span>
                        <span class="label">TOTAL XP ⚡</span>
                    </div>
                 </div>

                 <div class="v6-section-header mt-4">
                    <h3><i class="fas fa-bolt"></i> ${txt('إجراءات سريعة', 'Quick Actions')}</h3>
                 </div>
                 
                 <div class="v6-quick-grid">
                    <button class="v6-btn-action" onclick="loadPage('practice')">
                        <i class="fas fa-terminal"></i>
                        <span>Start Lab</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('ctf-arena')">
                        <i class="fas fa-flag"></i>
                        <span>CTF Arena</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('public-profile')">
                        <i class="fas fa-id-badge"></i>
                        <span>My Profile</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('settings')">
                        <i class="fas fa-cog"></i>
                        <span>Settings</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('exfiltration-lab')">
                        <i class="fas fa-satellite-dish"></i>
                        <span>Exfil Lab</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('infra-monitor')">
                        <i class="fas fa-globe-americas"></i>
                        <span>Infra Monitor</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('osint-monitor')">
                        <i class="fas fa-satellite"></i>
                        <span>Target Intel</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('cloud-lab')">
                        <i class="fas fa-cloud"></i>
                        <span>Cloud Lab Pro</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('vuln-manager')">
                        <i class="fas fa-shield-virus"></i>
                        <span>Vuln Manager</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('malware-sandbox')">
                        <i class="fas fa-microscope"></i>
                        <span>Malware Lab</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('ad-lab-pro')">
                        <i class="fas fa-network-wired"></i>
                        <span>AD Lab Pro</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('zero-trust')">
                        <i class="fas fa-fingerprint"></i>
                        <span>Zero Trust</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('devsecops')">
                        <i class="fas fa-rocket"></i>
                        <span>DevSecOps</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('ir-playbook')">
                        <i class="fas fa-book-medical"></i>
                        <span>Incident Ops</span>
                    </button>
                    <button class="v6-btn-action" onclick="loadPage('security-awareness')">
                        <i class="fas fa-graduation-cap"></i>
                        <span>Training</span>
                    </button>
                 </div>
            </div>
        </div>
    </div>
  `;
}

/* --- PROFILE V6 --- */
function pageProfileV6(username) {
    const user = getUserDataV6(); // Simplified for now, would fetch by username
    // const isMe = !username || username === user.username;

    return `
      ${getCoreStylesV6()}
      <div class="v6-page-container fade-in">
          <!-- Profile Hero -->
          <div class="v6-profile-hero">
              <div class="v6-profile-avatar">
                  <img src="assets/avatar_placeholder.png" onerror="this.src='https://ui-avatars.com/api/?name=${user.username}&background=8273DD&color=fff&size=128'" alt="Avatar">
                  <div class="v6-rank-badge ${user.rank.toLowerCase().replace(' ', '-')}">${user.rank}</div>
              </div>
              <div class="v6-profile-info">
                  <h1>${user.displayName || user.username} <i class="fas fa-check-circle text-primary text-sm" title="Verified"></i></h1>
                  <p class="v6-username">@${user.username} • Joined Jan 2024</p>
                  <div class="v6-profile-stats-row">
                      <div class="stat"><i class="fas fa-bolt text-warning"></i> <b>${user.xp.toLocaleString()}</b> XP</div>
                      <div class="stat"><i class="fas fa-trophy text-danger"></i> <b>${user.rank}</b> Rank</div>
                      <div class="stat"><i class="fas fa-flag text-success"></i> <b>${user.labsSolved}</b> PWNED</div>
                  </div>
              </div>
              <div class="v6-profile-actions">
                   <button class="v6-btn-outline"><i class="fas fa-share-alt"></i> Share</button>
                   <button class="v6-btn-primary"><i class="fas fa-envelope"></i> Message</button>
              </div>
          </div>

          <div class="v6-dashboard-grid mt-4">
              <!-- Left: Badges -->
              <div class="v6-col-main">
                  <div class="v6-section-header">
                      <h3><i class="fas fa-medal"></i> ${txt('الأوسمة', 'Badges')}</h3>
                  </div>
                  <div class="v6-badges-grid">
                      ${getV6Badges(user.badges)}
                  </div>
                  
                  <div class="v6-section-header mt-5">
                      <h3><i class="fas fa-certificate"></i> ${txt('الشهادات', 'Certificates')}</h3>
                  </div>
                  <div class="v6-card">
                      <div class="v6-empty-state">
                          <i class="fas fa-graduation-cap"></i>
                          <p>Complete a Career Path to earn certificates.</p>
                      </div>
                  </div>
              </div>

              <!-- Right: Skills Radar (Placeholder for now) -->
               <div class="v6-col-side">
                  <div class="v6-card">
                      <div class="v6-card-header"><h4>Skill Matrix</h4></div>
                      <div class="p-4 text-center">
                          <!-- Simplified visual for radar chart -->
                          <div class="v6-radar-placeholder">
                               <div class="radar-axis"></div>
                               <div class="radar-shape"></div>
                               <span class="radar-label top">WEB</span>
                               <span class="radar-label right">NET</span>
                               <span class="radar-label bottom">OS</span>
                               <span class="radar-label left">CODE</span>
                          </div>
                      </div>
                  </div>
               </div>
          </div>
      </div>
    `;
}

/* --- SETTINGS V6 --- */
/* --- SETTINGS V6 --- */
function pageSettingsV6() {
    setTimeout(() => {
        // Initialize Avatar
        const currentAvatar = localStorage.getItem('userAvatar') || 'assets/avatar.png';
        const avatarImg = document.getElementById('settings-avatar-preview');
        if (avatarImg) avatarImg.src = currentAvatar;
    }, 100);

    window.switchSettingsTab = (tabId, element) => {
        document.querySelectorAll('.v6-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.v6-tab-content').forEach(c => c.classList.remove('active'));

        element.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    };

    window.saveSettings = () => {
        const name = document.getElementById('setting-name').value;
        localStorage.setItem('username', name);
        showToast('Settings saved successfully!');
    };

    window.selectAvatar = (url) => {
        localStorage.setItem('userAvatar', url);
        document.getElementById('settings-avatar-preview').src = url;
        showToast('Avatar updated!');
    };

    window.clearAllData = () => {
        if (confirm('Are you sure? This will delete all progress, notes, and achievements.')) {
            localStorage.clear();
            location.reload();
        }
    };

    return `
      ${getCoreStylesV6()}
      <style>
        .settings-layout-v2 { display: grid; grid-template-columns: 250px 1fr; gap: 30px; min-height: 600px; }
        .settings-sidebar { background: rgba(255,255,255,0.02); border-right: 1px solid var(--v6-border); padding: 20px; border-radius: 16px; }
        .v6-tab-btn {
            display: flex; align-items: center; gap: 10px; width: 100%; padding: 15px 20px;
            background: transparent; border: none; color: var(--v6-text-muted);
            text-align: left; cursor: pointer; transition: 0.3s; border-radius: 12px; margin-bottom: 5px;
            font-family: 'Outfit', sans-serif; font-size: 1rem;
        }
        .v6-tab-btn:hover { background: rgba(255,255,255,0.05); color: #fff; }
        .v6-tab-btn.active { background: rgba(130, 115, 221, 0.1); color: var(--v6-purple); border: 1px solid rgba(130, 115, 221, 0.2); }
        .v6-tab-btn i { width: 24px; }
        
        .settings-content-area { background: rgba(255,255,255,0.01); border-radius: 16px; padding: 30px; border: 1px solid var(--v6-border); }
        .v6-tab-content { display: none; animation: fadeIn 0.3s ease; }
        .v6-tab-content.active { display: block; }
        
        .avatar-section { display: flex; align-items: center; gap: 20px; margin-bottom: 30px; pading-bottom: 30px; border-bottom: 1px solid var(--v6-border); }
        .avatar-preview { width: 80px; height: 80px; border-radius: 50%; object-fit: cover; border: 2px solid var(--v6-purple); }
        .avatar-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(60px, 1fr)); gap: 10px; margin-top: 15px; }
        .avatar-option { width: 60px; height: 60px; border-radius: 50%; cursor: pointer; border: 2px solid transparent; transition: 0.2s; }
        .avatar-option:hover { border-color: var(--v6-green); transform: scale(1.1); }
        
        .form-group-v2 { margin-bottom: 20px; }
        .form-group-v2 label { display: block; margin-bottom: 8px; color: var(--v6-text-muted); font-size: 0.9rem; }
        .input-v2 { 
            width: 100%; padding: 12px 15px; background: rgba(0,0,0,0.3); border: 1px solid var(--v6-border);
            border-radius: 8px; color: #fff; font-family: 'Outfit', sans-serif; transition: 0.3s;
        }
        .input-v2:focus { border-color: var(--v6-purple); outline: none; box-shadow: 0 0 0 3px rgba(130,115,221,0.1); }
        
        .btn-save { background: var(--v6-purple); color: #fff; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
        .btn-danger-outline { background: transparent; border: 1px solid #ef4444; color: #ef4444; padding: 10px 20px; border-radius: 8px; cursor: pointer; }
        .btn-danger-outline:hover { background: #ef4444; color: #fff; }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      </style>

      <div class="v6-page-container fade-in">
          <div class="v6-hero-welcome" style="padding: 20px 40px; margin-bottom: 20px;">
            <div>
              <h1 class="hero-title">Settings</h1>
              <p class="hero-subtitle">Manage your account and preferences</p>
            </div>
          </div>

          <div class="settings-layout-v2">
              <!-- Sidebar -->
              <div class="settings-sidebar">
                  <button class="v6-tab-btn active" onclick="switchSettingsTab('tab-profile', this)">
                      <i class="fas fa-user-astronaut"></i> Profile
                  </button>
                  <button class="v6-tab-btn" onclick="switchSettingsTab('tab-appearance', this)">
                      <i class="fas fa-palette"></i> Appearance
                  </button>
                  <button class="v6-tab-btn" onclick="switchSettingsTab('tab-data', this)">
                      <i class="fas fa-database"></i> Data & Privacy
                  </button>
                  <button class="v6-tab-btn" onclick="switchSettingsTab('tab-about', this)">
                      <i class="fas fa-info-circle"></i> About
                  </button>
              </div>

              <!-- Content -->
              <div class="settings-content-area">
                  
                  <!-- TAB: PROFILE -->
                  <div id="tab-profile" class="v6-tab-content active">
                      <div class="avatar-section">
                          <img src="" id="settings-avatar-preview" class="avatar-preview">
                          <div>
                              <h3>Profile Picture</h3>
                              <p class="text-muted">Select an avatar from the gallery</p>
                          </div>
                      </div>
                      
                      <div class="form-group-v2">
                          <label>Choose Avatar</label>
                          <div class="avatar-grid">
                              <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=Felix" class="avatar-option" onclick="selectAvatar(this.src)">
                              <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=Aneka" class="avatar-option" onclick="selectAvatar(this.src)">
                              <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=Bob" class="avatar-option" onclick="selectAvatar(this.src)">
                              <img src="https://api.dicebear.com/7.x/bottts/svg?seed=Cyber" class="avatar-option" onclick="selectAvatar(this.src)">
                              <img src="https://api.dicebear.com/7.x/bottts/svg?seed=Tech" class="avatar-option" onclick="selectAvatar(this.src)">
                          </div>
                      </div>

                      <div class="form-group-v2">
                          <label>Display Name</label>
                          <input type="text" id="setting-name" class="input-v2" value="${localStorage.getItem('username') || 'User'}">
                      </div>
                      
                      <div class="form-group-v2">
                          <label>Email Address</label>
                          <input type="email" class="input-v2" value="user@breachlabs.local" readonly style="opacity: 0.6; cursor: not-allowed;">
                          <small class="text-muted">Email cannot be changed in demo mode.</small>
                      </div>
                      
                      <button class="btn-save" onclick="saveSettings()">Save Changes</button>
                  </div>

                  <!-- TAB: APPEARANCE -->
                  <div id="tab-appearance" class="v6-tab-content">
                      <h3>Theme Settings</h3>
                      <p class="text-muted mb-4">Customize the look and feel of the platform.</p>
                      
                      <div class="v6-toggle-row">
                          <div class="info">
                              <h4>Cyberpunk Mode</h4>
                              <p>Enable enhanced neon visual effects.</p>
                          </div>
                          <label class="v6-switch">
                              <input type="checkbox" checked disabled>
                              <span class="slider round"></span>
                          </label>
                      </div>
                      
                      <div class="v6-toggle-row">
                          <div class="info">
                              <h4>Reduced Motion</h4>
                              <p>Disable heavy animations for performance.</p>
                          </div>
                          <label class="v6-switch">
                              <input type="checkbox" onchange="document.body.classList.toggle('reduce-motion')">
                              <span class="slider round"></span>
                          </label>
                      </div>
                  </div>

                  <!-- TAB: DATA -->
                  <div id="tab-data" class="v6-tab-content">
                      <h3 class="text-danger">Danger Zone</h3>
                      <p class="text-muted mb-4">Manage your data and progress.</p>
                      
                      <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 20px; border-radius: 12px;">
                          <h4>Reset Progress</h4>
                          <p class="mb-3">This will permanently delete all your CTF progress, badges, notes, and local data.</p>
                          <button class="btn-danger-outline" onclick="clearAllData()">
                              <i class="fas fa-trash"></i> Reset Everything
                          </button>
                      </div>
                  </div>

                  <!-- TAB: ABOUT -->
                  <div id="tab-about" class="v6-tab-content">
                      <div class="text-center p-4">
                          <img src="assets/logo.png" style="width: 80px; margin-bottom: 20px; opacity: 0.8;" onerror="this.src='https://via.placeholder.com/80?text=BL'">
                          <h2>BreachLabs v3.5</h2>
                          <p class="text-muted">The Ultimate Ethical Hacking Platform</p>
                          <hr style="border-color: var(--v6-border); margin: 30px 0;">
                          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; text-align: left;">
                              <div>
                                  <h5 class="text-purple">Credits</h5>
                                  <ul style="list-style: none; padding: 0; color: #888; font-size: 0.9rem;">
                                      <li>Core Engine: v6.2.1</li>
                                      <li>CTF Module: v3.0</li>
                                      <li>UI System: Cyberpunk UI</li>
                                  </ul>
                              </div>
                              <div>
                                  <h5 class="text-green">Status</h5>
                                  <ul style="list-style: none; padding: 0; color: #888; font-size: 0.9rem;">
                                      <li>System: <span class="text-green">Operational</span></li>
                                      <li>Database: <span class="text-green">Connected</span></li>
                                      <li>Labs: <span class="text-green">Online</span></li>
                                  </ul>
                              </div>
                          </div>
                      </div>
                  </div>

              </div>
          </div>
      </div>
    `;
}

function getCoreStylesV6() {
    return `
    <style>
        /* CORE VARIABLES (Shared with Learn V6) */
        :root {
            --v6-bg: #0d0b14;
            --v6-card: rgba(22, 20, 33, 0.7);
            --v6-border: rgba(255, 255, 255, 0.1);
            --v6-purple: #8273DD;
            --v6-purple-glow: rgba(130, 115, 221, 0.4);
            --v6-green: #10B981;
            --v6-red: #EF4444;
            --v6-text: #ffffff;
            --v6-text-muted: #9CA3AF;
            --v6-glass: blur(12px) saturate(180%);
        }

        .v6-page-container {
            max-width: 1400px; margin: 0 auto; padding: 40px 20px;
            color: var(--v6-text); font-family: 'Outfit', sans-serif;
            min-height: 100vh;
        }

        /* --- HERO --- */
        .v6-hero-welcome {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 40px; padding: 40px;
            background: linear-gradient(135deg, rgba(130, 115, 221, 0.1) 0%, transparent 100%);
            border: 1px solid var(--v6-border); border-radius: 24px;
            position: relative; overflow: hidden;
        }
        .hero-title { font-size: 2.5rem; font-weight: 800; margin: 0 0 10px 0; }
        .hero-subtitle { font-size: 1.1rem; color: var(--v6-text-muted); }
        .text-purple { color: var(--v6-purple); }

        /* --- LAYOUT GRID --- */
        .v6-dashboard-grid {
            display: grid; grid-template-columns: 2fr 1fr; gap: 30px;
        }
        @media (max-width: 900px) { .v6-dashboard-grid { grid-template-columns: 1fr; } }

        /* --- CARDS --- */
        .v6-card {
            background: var(--v6-card); border: 1px solid var(--v6-border);
            border-radius: 16px; padding: 25px; margin-bottom: 25px;
            transition: transform 0.2s;
        }
        .v6-card:hover { border-color: rgba(130, 115, 221, 0.3); }
        .v6-section-header h3 { font-size: 1.2rem; font-weight: 600; margin-bottom: 20px; color: var(--v6-text); }
        .compact-card { padding: 20px; margin-bottom: 15px; }

        /* --- ACTIVE PATH CARD --- */
        .active-path-card {
            display: flex; align-items: center; gap: 25px; cursor: pointer;
            background: linear-gradient(90deg, #1A1829 0%, #161421 100%);
        }
        .active-path-card:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .path-icon-large {
            width: 80px; height: 80px; background: rgba(130, 115, 221, 0.1);
            border-radius: 16px; display: flex; align-items: center; justify-content: center;
            font-size: 2rem; color: var(--v6-purple);
        }
        .path-info { flex: 1; }
        .path-info h2 { font-size: 1.5rem; margin: 8px 0; }
        .v6-badge { padding: 4px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
        .v6-badge.purple { background: rgba(130, 115, 221, 0.2); color: var(--v6-purple); }

        .v6-progress-wrapper { display: flex; align-items: center; gap: 15px; margin-top: 10px; }
        .v6-progress-bar { flex: 1; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; }
        .v6-progress-fill { height: 100%; background: var(--v6-purple); border-radius: 3px; }
        .v6-progress-text { font-size: 0.8rem; font-weight: 700; color: var(--v6-text-muted); }

        /* --- HEATMAP --- */
        .v6-heatmap-container { display: flex; gap: 4px; overflow-x: auto; padding-bottom: 10px; }
        .heatmap-col { display: flex; flex-direction: column; gap: 4px; }
        .heatmap-cell { width: 12px; height: 12px; border-radius: 2px; }
        .heatmap-cell.empty { background: rgba(255,255,255,0.05); }
        .heatmap-cell.low { background: #064E3B; }
        .heatmap-cell.med { background: #059669; }
        .heatmap-cell.high { background: #10B981; }

        /* --- SIDEBAR STATS --- */
        .v6-stat-big { text-align: center; }
        .v6-stat-big .value { display: block; font-size: 2rem; font-weight: 800; color: #fff; }
        .v6-stat-big .label { font-size: 0.8rem; font-weight: 700; color: var(--v6-text-muted); letter-spacing: 1px; }

        /* --- BUTTONS --- */
        .v6-quick-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .v6-btn-action {
            background: rgba(255,255,255,0.05); border: 1px solid var(--v6-border);
            padding: 15px; border-radius: 12px; color: #fff; cursor: pointer;
            display: flex; flex-direction: column; align-items: center; gap: 10px;
            transition: all 0.2s;
        }
        .v6-btn-action:hover { background: var(--v6-purple); border-color: var(--v6-purple); }
        .v6-btn-action i { font-size: 1.5rem; }

        /* --- PROFILE --- */
        .v6-profile-hero {
            background: linear-gradient(180deg, rgba(130, 115, 221, 0.1) 0%, transparent 100%);
            border: 1px solid var(--v6-border); border-radius: 24px; padding: 40px;
            display: flex; align-items: center; gap: 40px;
        }
        .v6-profile-avatar { position: relative; width: 140px; height: 140px; }
        .v6-profile-avatar img { width: 100%; height: 100%; border-radius: 50%; border: 4px solid var(--v6-card); box-shadow: 0 0 20px rgba(130, 115, 221, 0.4); }
        .v6-rank-badge {
            position: absolute; bottom: 0; right: 0; 
            background: var(--v6-purple); color: #fff; 
            padding: 5px 15px; border-radius: 20px; font-weight: 700; font-size: 0.8rem;
            border: 3px solid var(--v6-card);
        }
        .v6-profile-stats-row { display: flex; gap: 30px; margin-top: 15px; font-size: 1.1rem; }
        .v6-profile-actions { margin-left: auto; display: flex; gap: 15px; }

        .v6-btn-primary { background: var(--v6-purple); color: #fff; border: none; padding: 10px 25px; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .v6-btn-outline { background: transparent; border: 1px solid var(--v6-border); color: #fff; padding: 10px 25px; border-radius: 8px; font-weight: 600; cursor: pointer; }

        /* --- BADGES --- */
        .v6-badges-grid { display: flex; flex-wrap: wrap; gap: 15px; }
        .v6-badge-item {
            text-align: center; width: 100px;
        }
        .badge-hex {
            width: 60px; height: 60px; margin: 0 auto 10px;
            display: flex; align-items: center; justify-content: center;
            border: 2px solid #ccc; border-radius: 50%; /* Hexagon fallback */
            font-size: 1.5rem; background: rgba(255,255,255,0.05);
        }

        /* --- SETTINGS --- */
        .v6-settings-layout { display: flex; gap: 40px; }
        .v6-settings-sidebar { width: 250px; display: flex; flex-direction: column; gap: 10px; border-right: 1px solid var(--v6-border); padding-right: 20px; }
        .v6-settings-sidebar a { padding: 12px; border-radius: 8px; text-decoration: none; color: var(--v6-text-muted); display: flex; align-items: center; gap: 10px; }
        .v6-settings-sidebar a.active, .v6-settings-sidebar a:hover { background: rgba(255,255,255,0.05); color: #fff; }
        .v6-settings-content { flex: 1; max-width: 600px; }
        
        .v6-form-group { margin-bottom: 20px; }
        .v6-form-group label { display: block; margin-bottom: 8px; color: var(--v6-text-muted); font-size: 0.9rem; }
        .v6-input { width: 100%; padding: 12px; background: rgba(0,0,0,0.2); border: 1px solid var(--v6-border); border-radius: 8px; color: #fff; }
        
        .v6-toggle-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-bottom: 25px; border-bottom: 1px solid var(--v6-border); }
        .v6-switch { position: relative; display: inline-block; width: 50px; height: 26px; }
        .v6-switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #333; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--v6-purple); }
        input:checked + .slider:before { transform: translateX(24px); }

        .v6-btn-danger { background: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; padding: 10px 20px; border-radius: 8px; cursor: pointer; }
    </style>
    `;
}


/* --- HELPER FUNCTIONS --- */

function getUserDataV6() {
    // Determine Greeting Time
    const hour = new Date().getHours();
    let greeting = 'Good Evening';
    if (hour < 12) greeting = 'Good Morning';
    else if (hour < 18) greeting = 'Good Afternoon';

    return {
        username: localStorage.getItem('username') || 'Guest',
        displayName: localStorage.getItem('username') || 'Guest',
        greeting: greeting,
        xp: parseInt(localStorage.getItem('userPoints') || '0'),
        rank: 'Script Kiddie', // simplified
        streak: parseInt(localStorage.getItem('streakDays') || '0'),
        labsSolved: parseInt(localStorage.getItem('labsCompleted') || '0'),
        badges: ['first-blood', 'intro'] // dummy
    };
}

function getV6Hero(user) {
    return `
    <div class="v6-hero-welcome">
        <div>
            <h1 class="hero-title">${user.greeting}, <span class="text-purple">${user.username}</span>.</h1>
            <p class="hero-subtitle">Ready to breach? You have <b>3 pending labs</b> in your queue.</p>
        </div>
        <div class="v6-hero-graphic">
             <!-- Abstract decorative graphic -->
             <div class="graphic-circle"></div>
             <i class="fas fa-terminal graphic-icon"></i>
        </div>
    </div>
    `;
}

function getV6Badges(badges) {
    // Mockup badges
    const allBadges = [
        { id: 'first-blood', icon: 'droplet', color: '#EF4444', title: 'First Blood' },
        { id: 'intro', icon: 'door-open', color: '#10B981', title: 'Welcome' },
        { id: 'hacker', icon: 'user-secret', color: '#8273DD', title: 'Hacker' }
    ];

    return allBadges.map(b => `
        <div class="v6-badge-item">
            <div class="badge-hex" style="border-color: ${b.color}">
                <i class="fas fa-${b.icon}" style="color: ${b.color}"></i>
            </div>
            <span>${b.title}</span>
        </div>
    `).join('');
}

// Generate render function for Heatmap on load
setTimeout(() => {
    const heatmap = document.getElementById('v6-heatmap');
    if (heatmap) {
        let html = '';
        for (let i = 0; i < 52; i++) {
            html += `<div class="heatmap-col">`;
            for (let j = 0; j < 7; j++) {
                const active = Math.random() > 0.7; // Random data
                const intensity = active ? Math.ceil(Math.random() * 3) : 0;
                let colorClass = 'empty';
                if (intensity === 1) colorClass = 'low';
                if (intensity === 2) colorClass = 'med';
                if (intensity === 3) colorClass = 'high';

                html += `<div class="heatmap-cell ${colorClass}"></div>`;
            }
            html += `</div>`;
        }
        heatmap.innerHTML = html;
    }
}, 500); // Delayed init
