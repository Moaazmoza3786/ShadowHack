// ==================== PLATFORM PAGES ====================
// Hub Dashboard, Domain View, Path Roadmap, Module Learning, CTF Arena

/* ========== DOMAINS SELECTION PAGE ========== */
function pageDomains() {
  return `
    <div class="domains-page">
      <style>
        .domains-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 50%, #16213e 100%); color: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px 20px; }
        .domains-header { text-align: center; margin-bottom: 60px; }
        .domains-title { font-size: 3rem; font-weight: 800; background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 15px; }
        .domains-subtitle { color: rgba(255,255,255,0.7); font-size: 1.2rem; }
        
        .domains-choices { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 40px; max-width: 1000px; width: 100%; }
        
        .domain-choice { background: rgba(255,255,255,0.03); border: 3px solid rgba(255,255,255,0.1); border-radius: 30px; padding: 50px 40px; cursor: pointer; transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); position: relative; overflow: hidden; text-align: center; }
        .domain-choice::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 5px; }
        .domain-choice.red-team::before { background: linear-gradient(90deg, #ef4444, #dc2626); }
        .domain-choice.blue-team::before { background: linear-gradient(90deg, #3b82f6, #1d4ed8); }
        
        .domain-choice:hover { transform: translateY(-15px) scale(1.02); border-color: rgba(255,255,255,0.3); }
        .domain-choice.red-team:hover { box-shadow: 0 30px 80px rgba(239,68,68,0.4); }
        .domain-choice.blue-team:hover { box-shadow: 0 30px 80px rgba(59,130,246,0.4); }
        
        .domain-emoji { font-size: 6rem; margin-bottom: 25px; filter: drop-shadow(0 10px 30px rgba(0,0,0,0.3)); }
        .domain-name { font-size: 2.2rem; font-weight: 800; margin-bottom: 10px; }
        .domain-choice.red-team .domain-name { color: #ef4444; }
        .domain-choice.blue-team .domain-name { color: #3b82f6; }
        .domain-subtitle-text { color: rgba(255,255,255,0.6); font-size: 1.1rem; margin-bottom: 20px; }
        .domain-desc { color: rgba(255,255,255,0.5); font-size: 0.95rem; line-height: 1.7; margin-bottom: 25px; }
        
        .domain-stats { display: flex; justify-content: center; gap: 30px; margin-bottom: 25px; }
        .domain-stat { text-align: center; }
        .domain-stat-value { font-size: 1.8rem; font-weight: 700; color: #667eea; }
        .domain-stat-label { color: rgba(255,255,255,0.5); font-size: 0.8rem; }
        
        .domain-cta { background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05)); padding: 12px 30px; border-radius: 25px; display: inline-flex; align-items: center; gap: 10px; font-weight: 600; transition: all 0.3s; }
        .domain-choice.red-team .domain-cta { color: #ef4444; }
        .domain-choice.blue-team .domain-cta { color: #3b82f6; }
        .domain-choice:hover .domain-cta { background: rgba(255,255,255,0.15); }
      </style>
      
      <div class="domains-header">
        <h1 class="domains-title">📚 ${txt('اختر مجالك', 'Choose Your Domain')}</h1>
        <p class="domains-subtitle">${txt('ابدأ رحلتك في الأمن السيبراني', 'Start your cybersecurity journey')}</p>
      </div>
      
      <div class="domains-choices">
        <div class="domain-choice red-team" onclick="loadPage('red-team')">
          <div class="domain-emoji">🔴</div>
          <div class="domain-name">${txt('الفريق الأحمر', 'Red Team')}</div>
          <div class="domain-subtitle-text">${txt('الأمن الهجومي', 'Offensive Security')}</div>
          <div class="domain-desc">${txt('تعلم كيف تفكر مثل المهاجمين. اختبار الاختراق، استغلال الثغرات، والعمليات الهجومية.', 'Learn to think like attackers. Penetration testing, exploitation, and offensive operations.')}</div>
          <div class="domain-stats">
            <div class="domain-stat">
              <div class="domain-stat-value">6</div>
              <div class="domain-stat-label">${txt('مسارات', 'Paths')}</div>
            </div>
            <div class="domain-stat">
              <div class="domain-stat-value">40+</div>
              <div class="domain-stat-label">${txt('وحدة', 'Modules')}</div>
            </div>
          </div>
          <div class="domain-cta">${txt('استكشف المسارات', 'Explore Paths')} <i class="fas fa-arrow-right"></i></div>
        </div>
        
        <div class="domain-choice blue-team" onclick="loadPage('blue-team')">
          <div class="domain-emoji">🔵</div>
          <div class="domain-name">${txt('الفريق الأزرق', 'Blue Team')}</div>
          <div class="domain-subtitle-text">${txt('الأمن الدفاعي', 'Defensive Security')}</div>
          <div class="domain-desc">${txt('تعلم كيف تحمي الأنظمة. تحليل SOC، التحليل الجنائي، الاستجابة للحوادث.', 'Learn to protect systems. SOC analysis, forensics, incident response.')}</div>
          <div class="domain-stats">
            <div class="domain-stat">
              <div class="domain-stat-value">6</div>
              <div class="domain-stat-label">${txt('مسارات', 'Paths')}</div>
            </div>
            <div class="domain-stat">
              <div class="domain-stat-value">35+</div>
              <div class="domain-stat-label">${txt('وحدة', 'Modules')}</div>
            </div>
          </div>
          <div class="domain-cta">${txt('استكشف المسارات', 'Explore Paths')} <i class="fas fa-arrow-right"></i></div>
        </div>
      </div>
    </div>
  `;
}

/* ========== PUBLIC PROFILE PAGE ========== */
function pagePublicProfile(username) {

  // Fetch profile data on load
  setTimeout(() => {
    loadPublicProfile(username);
  }, 100);

  return `
    <div class="public-profile-page">
      <style>
        .public-profile-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 50%, #16213e 100%); color: #fff; padding: 40px 20px; }
        .profile-container { max-width: 900px; margin: 0 auto; }
        
        /* Profile Header */
        .profile-header { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px; text-align: center; margin-bottom: 30px; }
        .profile-avatar { width: 120px; height: 120px; border-radius: 50%; background: linear-gradient(135deg, #667eea, #764ba2); display: flex; align-items: center; justify-content: center; font-size: 3rem; margin: 0 auto 20px; box-shadow: 0 10px 40px rgba(102,126,234,0.3); }
        .profile-name { font-size: 2rem; font-weight: 700; margin-bottom: 5px; }
        .profile-username { color: rgba(255,255,255,0.5); font-size: 1rem; margin-bottom: 20px; }
        .profile-rank { display: inline-flex; align-items: center; gap: 10px; background: rgba(255,255,255,0.1); padding: 10px 25px; border-radius: 30px; font-weight: 600; }
        .profile-rank-icon { font-size: 1.5rem; }
        
        /* Stats Row */
        .profile-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }
        .profile-stat { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 20px; text-align: center; }
        .profile-stat-value { font-size: 1.8rem; font-weight: 700; color: #667eea; }
        .profile-stat-label { font-size: 0.8rem; color: rgba(255,255,255,0.5); margin-top: 5px; }
        
        /* Share Buttons */
        .profile-share { display: flex; justify-content: center; gap: 15px; margin-top: 25px; }
        .share-btn { display: flex; align-items: center; gap: 8px; padding: 12px 25px; border-radius: 10px; font-weight: 600; cursor: pointer; transition: all 0.3s; border: none; font-size: 0.95rem; }
        .share-btn.linkedin { background: #0077b5; color: #fff; }
        .share-btn.twitter { background: #1da1f2; color: #fff; }
        .share-btn:hover { transform: translateY(-3px); box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
        
        /* Badges Section */
        .profile-section { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 30px; margin-bottom: 25px; }
        .profile-section-title { font-size: 1.3rem; font-weight: 600; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        .badges-grid { display: flex; flex-wrap: wrap; gap: 15px; }
        .badge-item { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 15px 20px; display: flex; align-items: center; gap: 12px; }
        .badge-icon { font-size: 1.8rem; }
        .badge-info h4 { margin: 0 0 3px; font-size: 0.95rem; }
        .badge-info p { margin: 0; font-size: 0.75rem; color: rgba(255,255,255,0.5); }
        
        /* Certificates */
        .certs-list { display: grid; gap: 15px; }
        .cert-item { background: linear-gradient(135deg, rgba(255,215,0,0.1), rgba(255,215,0,0.05)); border: 1px solid rgba(255,215,0,0.2); border-radius: 12px; padding: 20px; display: flex; align-items: center; gap: 15px; }
        .cert-icon { font-size: 2rem; color: #ffd700; }
        .cert-info h4 { margin: 0 0 5px; font-weight: 600; }
        .cert-info p { margin: 0; font-size: 0.8rem; color: rgba(255,255,255,0.5); }
        
        /* Heatmap */
        .profile-heatmap { margin-top: 20px; }
        
        /* Loading */
        .profile-loading { text-align: center; padding: 60px; }
        .profile-loading-spinner { width: 50px; height: 50px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #667eea; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        @media (max-width: 768px) {
          .profile-stats { grid-template-columns: repeat(2, 1fr); }
          .profile-share { flex-direction: column; }
        }
      </style>
      
      <div class="profile-container">
        <div id="profile-content">
          <div class="profile-loading">
            <div class="profile-loading-spinner"></div>
            <p>Loading profile...</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Load public profile data
async function loadPublicProfile(username) {
  const container = document.getElementById('profile-content');
  if (!container) return;

  try {
    // Try to fetch from API, fallback to localStorage for demo
    let profileData;
    try {
      const response = await fetch(`http://localhost:5000/api/profile/${username}`);
      profileData = await response.json();
    } catch {
      // Fallback to localStorage data for demo
      profileData = {
        success: true,
        user: {
          username: username,
          displayName: localStorage.getItem('username') || username,
          points: parseInt(localStorage.getItem('userPoints') || '0'),
          level: Math.floor(parseInt(localStorage.getItem('userPoints') || '0') / 500) + 1,
          rank: 'Cyber Warrior',
          labsSolved: parseInt(localStorage.getItem('labsCompleted') || '0'),
          streak: parseInt(localStorage.getItem('streakDays') || '0'),
          joinDate: '2024-01-15',
          badges: [
            { icon: '🔥', name: 'Week Warrior', desc: '7-day streak' },
            { icon: '🧪', name: 'Lab Rat', desc: '10 labs completed' },
            { icon: '🎯', name: 'First Blood', desc: 'First lab solved' }
          ],
          certificates: [
            { name: 'Web Security Fundamentals', date: '2024-01-20' }
          ]
        }
      };
    }

    if (!profileData.success) {
      container.innerHTML = `<div class="profile-header"><h2>Profile not found</h2></div>`;
      return;
    }

    const user = profileData.user;
    const shareUrl = encodeURIComponent(window.location.href);
    const shareText = encodeURIComponent(`Check out my cybersecurity profile on Study Hub! 🔐 Level ${user.level} | ${user.points} Points`);

    container.innerHTML = `
      <!-- Profile Header -->
      <div class="profile-header">
        <div class="profile-avatar">👨‍💻</div>
        <div class="profile-name">${user.displayName || user.username}</div>
        <div class="profile-username">@${user.username}</div>
        <div class="profile-rank">
          <span class="profile-rank-icon">🎖️</span>
          <span>${user.rank}</span>
        </div>
        
        <div class="profile-stats">
          <div class="profile-stat">
            <div class="profile-stat-value">${user.points?.toLocaleString() || 0}</div>
            <div class="profile-stat-label">Points</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value">${user.level || 1}</div>
            <div class="profile-stat-label">Level</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value">${user.labsSolved || 0}</div>
            <div class="profile-stat-label">Labs Solved</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value">🔥 ${user.streak || 0}</div>
            <div class="profile-stat-label">Day Streak</div>
          </div>
        </div>
        
        <div class="profile-share">
          <button class="share-btn linkedin" onclick="window.open('https://www.linkedin.com/sharing/share-offsite/?url=${shareUrl}', '_blank')">
            <i class="fab fa-linkedin"></i> Share on LinkedIn
          </button>
          <button class="share-btn twitter" onclick="window.open('https://twitter.com/intent/tweet?text=${shareText}&url=${shareUrl}', '_blank')">
            <i class="fab fa-twitter"></i> Share on Twitter
          </button>
        </div>
      </div>
      
      <!-- Badges -->
      <div class="profile-section">
        <div class="profile-section-title"><i class="fas fa-medal"></i> Badges & Achievements</div>
        <div class="badges-grid">
          ${(user.badges || []).map(b => `
            <div class="badge-item">
              <div class="badge-icon">${b.icon}</div>
              <div class="badge-info">
                <h4>${b.name}</h4>
                <p>${b.desc}</p>
              </div>
            </div>
          `).join('') || '<p style="color: rgba(255,255,255,0.5);">No badges yet</p>'}
        </div>
      </div>
      
      <!-- Certificates -->
      <div class="profile-section">
        <div class="profile-section-title"><i class="fas fa-certificate"></i> Certificates</div>
        <div class="certs-list">
          ${(user.certificates || []).map(c => `
            <div class="cert-item">
              <div class="cert-icon">🎓</div>
              <div class="cert-info">
                <h4>${c.name}</h4>
                <p>Issued: ${c.date}</p>
              </div>
            </div>
          `).join('') || '<p style="color: rgba(255,255,255,0.5);">No certificates yet</p>'}
        </div>
      </div>
    `;
  } catch (error) {
    console.error('Error loading profile:', error);
    container.innerHTML = `<div class="profile-header"><h2>Error loading profile</h2><p>${error.message}</p></div>`;
  }
}

/* ========== HUB DASHBOARD ========== */

function pageHub() {
  // Get user stats from localStorage
  const userPoints = parseInt(localStorage.getItem('userPoints') || '0');
  const userRank = getUserRank ? getUserRank(userPoints) : { name: 'Script Kiddie', color: '#94a3b8' };
  const nextRankInfo = getNextRank ? getNextRank(userPoints) : { rank: null, pointsNeeded: 500 };
  const labsCompleted = parseInt(localStorage.getItem('labsCompleted') || '0');
  const streak = parseInt(localStorage.getItem('streakDays') || '0');

  // Get paths progress
  const pathProgress = JSON.parse(localStorage.getItem('pathProgress') || '{}');

  // Initialize heatmap after render
  setTimeout(() => {
    renderActivityHeatmap();
  }, 100);

  return `
    <div class="hub-page">
      <style>
        .hub-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 50%, #16213e 100%); color: #fff; padding: 0; }
        .hub-hero { padding: 60px 40px; background: linear-gradient(135deg, rgba(102,126,234,0.2) 0%, rgba(118,75,162,0.2) 100%); border-bottom: 1px solid rgba(255,255,255,0.1); text-align: center; position: relative; overflow: hidden; }
        .hub-hero::before { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(102,126,234,0.1) 0%, transparent 50%); animation: pulse 15s ease-in-out infinite; }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
        .hub-title { font-size: 3rem; font-weight: 800; background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; position: relative; }
        .hub-subtitle { font-size: 1.2rem; color: rgba(255,255,255,0.7); margin-bottom: 30px; }
        
        /* Stats Cards */
        .hub-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 40px; max-width: 1400px; margin: 0 auto; }
        .stat-card { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 25px; text-align: center; transition: all 0.3s; }
        .stat-card:hover { transform: translateY(-5px); border-color: rgba(102,126,234,0.5); box-shadow: 0 20px 40px rgba(102,126,234,0.2); }
        .stat-icon { font-size: 2.5rem; margin-bottom: 15px; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #667eea; }
        .stat-label { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 5px; }
        
        /* Streak Fire Animation */
        .stat-card.streak-card { position: relative; overflow: hidden; }
        .stat-card.streak-card.active { border-color: rgba(239, 68, 68, 0.5); box-shadow: 0 0 30px rgba(239, 68, 68, 0.3); }
        .stat-card.streak-card .stat-icon { animation: fireGlow 1.5s ease-in-out infinite; }
        .stat-card.streak-card .stat-value { background: linear-gradient(135deg, #f97316, #ef4444, #dc2626); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        @keyframes fireGlow { 0%, 100% { text-shadow: 0 0 10px rgba(249, 115, 22, 0.5), 0 0 20px rgba(239, 68, 68, 0.3); transform: scale(1); } 50% { text-shadow: 0 0 20px rgba(249, 115, 22, 0.8), 0 0 40px rgba(239, 68, 68, 0.5); transform: scale(1.1); } }
        .streak-flames { position: absolute; bottom: 0; left: 50%; transform: translateX(-50%); font-size: 3rem; opacity: 0.15; animation: flicker 0.5s ease-in-out infinite alternate; }
        @keyframes flicker { from { opacity: 0.1; } to { opacity: 0.2; } }
        
        /* Rank Progress */
        .rank-section { padding: 0 40px 40px; max-width: 1400px; margin: 0 auto; }
        .rank-card { background: linear-gradient(135deg, rgba(102,126,234,0.2) 0%, rgba(118,75,162,0.2) 100%); border-radius: 20px; padding: 30px; display: flex; align-items: center; gap: 30px; flex-wrap: wrap; }
        .rank-badge { width: 100px; height: 100px; border-radius: 50%; background: linear-gradient(135deg, ${userRank.color} 0%, ${userRank.color}88 100%); display: flex; align-items: center; justify-content: center; font-size: 2.5rem; box-shadow: 0 10px 30px ${userRank.color}44; }
        .rank-info { flex: 1; min-width: 200px; }
        .rank-name { font-size: 1.8rem; font-weight: 700; color: ${userRank.color}; }
        .rank-points { color: rgba(255,255,255,0.7); margin: 5px 0 15px; }
        .rank-progress { height: 10px; background: rgba(255,255,255,0.1); border-radius: 10px; overflow: hidden; }
        .rank-progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); border-radius: 10px; transition: width 0.5s; }
        .rank-next { color: rgba(255,255,255,0.5); font-size: 0.85rem; margin-top: 10px; }
        
        /* Activity Heatmap */
        .heatmap-section { padding: 0 40px 40px; max-width: 1400px; margin: 0 auto; }
        .heatmap-card { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 30px; }
        .heatmap-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .heatmap-title { font-size: 1.3rem; font-weight: 600; display: flex; align-items: center; gap: 10px; }
        .heatmap-legend { display: flex; align-items: center; gap: 8px; font-size: 0.8rem; color: rgba(255,255,255,0.5); }
        .heatmap-legend-item { width: 12px; height: 12px; border-radius: 2px; }
        .heatmap-container { overflow-x: auto; }
        .heatmap-grid { display: grid; grid-template-columns: repeat(53, 12px); grid-template-rows: repeat(7, 12px); gap: 3px; }
        .heatmap-day { width: 12px; height: 12px; border-radius: 2px; background: rgba(255,255,255,0.05); cursor: pointer; transition: all 0.2s; position: relative; }
        .heatmap-day:hover { transform: scale(1.5); z-index: 10; }
        .heatmap-day.level-1 { background: #0e4429; }
        .heatmap-day.level-2 { background: #006d32; }
        .heatmap-day.level-3 { background: #26a641; }
        .heatmap-day.level-4 { background: #39d353; }
        .heatmap-tooltip { position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: #1f2937; color: #fff; padding: 5px 10px; border-radius: 6px; font-size: 0.75rem; white-space: nowrap; opacity: 0; pointer-events: none; transition: opacity 0.2s; z-index: 100; }
        .heatmap-day:hover .heatmap-tooltip { opacity: 1; }
        .heatmap-months { display: flex; gap: 3px; margin-bottom: 5px; font-size: 0.7rem; color: rgba(255,255,255,0.4); }
        .heatmap-months span { width: calc(12px * 4 + 3px * 3); }
        .heatmap-stats { display: flex; gap: 30px; margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1); }
        .heatmap-stat { text-align: center; }
        .heatmap-stat-value { font-size: 1.5rem; font-weight: 700; color: #39d353; }
        .heatmap-stat-label { font-size: 0.8rem; color: rgba(255,255,255,0.5); }
        
        /* Domains Section */
        .domains-section { padding: 40px; max-width: 1400px; margin: 0 auto; }
        .section-title { font-size: 1.8rem; font-weight: 700; margin-bottom: 30px; display: flex; align-items: center; gap: 15px; }
        .domains-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; }
        .domain-card { background: rgba(255,255,255,0.03); border: 2px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 35px; cursor: pointer; transition: all 0.4s; position: relative; overflow: hidden; }
        .domain-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; }
        .domain-card.red-team::before { background: linear-gradient(90deg, #ef4444, #dc2626); }
        .domain-card.blue-team::before { background: linear-gradient(90deg, #3b82f6, #1d4ed8); }
        .domain-card:hover { transform: translateY(-8px); border-color: rgba(255,255,255,0.3); }
        .domain-card.red-team:hover { box-shadow: 0 20px 60px rgba(239,68,68,0.3); }
        .domain-card.blue-team:hover { box-shadow: 0 20px 60px rgba(59,130,246,0.3); }
        .domain-emoji { font-size: 4rem; margin-bottom: 20px; }
        .domain-name { font-size: 1.8rem; font-weight: 700; margin-bottom: 5px; }
        .domain-subtitle { color: rgba(255,255,255,0.6); margin-bottom: 15px; }
        .domain-desc { color: rgba(255,255,255,0.5); font-size: 0.95rem; line-height: 1.6; margin-bottom: 20px; }
        .domain-paths { display: flex; flex-wrap: wrap; gap: 8px; }
        .domain-path-tag { background: rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; color: rgba(255,255,255,0.7); }
        
        /* Quick Actions */
        .actions-section { padding: 0 40px 60px; max-width: 1400px; margin: 0 auto; }
        .actions-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .action-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; display: flex; align-items: center; gap: 20px; cursor: pointer; transition: all 0.3s; }
        .action-card:hover { background: rgba(255,255,255,0.1); transform: translateX(5px); }
        .action-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; }
        .action-icon.purple { background: linear-gradient(135deg, #667eea, #764ba2); }
        .action-icon.red { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .action-icon.green { background: linear-gradient(135deg, #10b981, #059669); }
        .action-icon.orange { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .action-text h4 { margin: 0 0 5px; font-size: 1.1rem; }
        .action-text p { margin: 0; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
      </style>
      
      <!-- Hero -->
      <div class="hub-hero">
        <h1 class="hub-title">🎯 ${txt('مركز التعلم', 'The Learning Hub')}</h1>
        <p class="hub-subtitle">${txt('منصتك الشاملة لتعلم الأمن السيبراني', 'Your Complete Cybersecurity Learning Platform')}</p>
      </div>
      
      <!-- Stats -->
      <div class="hub-stats">
        <div class="stat-card">
          <div class="stat-icon">⚡</div>
          <div class="stat-value">${userPoints.toLocaleString()}</div>
          <div class="stat-label">${txt('النقاط', 'Points')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">🧪</div>
          <div class="stat-value">${labsCompleted}</div>
          <div class="stat-label">${txt('مختبرات مكتملة', 'Labs Completed')}</div>
        </div>
        <div class="stat-card streak-card ${streak >= 3 ? 'active' : ''}">
          <div class="streak-flames">🔥🔥🔥</div>
          <div class="stat-icon">🔥</div>
          <div class="stat-value">${streak}</div>
          <div class="stat-label">${txt('أيام متتالية', 'Day Streak')}</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon">🏆</div>
          <div class="stat-value">${Object.keys(pathProgress).length}</div>
          <div class="stat-label">${txt('مسارات نشطة', 'Active Paths')}</div>
        </div>
      </div>
      
      <!-- Rank -->
      <div class="rank-section">
        <div class="rank-card">
          <div class="rank-badge">🎖️</div>
          <div class="rank-info">
            <div class="rank-name">${userRank.name}</div>
            <div class="rank-points">${userPoints.toLocaleString()} ${txt('نقطة', 'points')}</div>
            <div class="rank-progress">
              <div class="rank-progress-fill" style="width: ${nextRankInfo.rank ? Math.min(100, (userPoints / nextRankInfo.rank.minPoints) * 100) : 100}%"></div>
            </div>
            ${nextRankInfo.rank ? `<div class="rank-next">${nextRankInfo.pointsNeeded.toLocaleString()} ${txt('نقطة للوصول إلى', 'points to reach')} ${nextRankInfo.rank.name}</div>` : ''}
          </div>
        </div>
      </div>
      
      <!-- Activity Heatmap -->
      <div class="heatmap-section">
        <div class="heatmap-card">
          <div class="heatmap-header">
            <div class="heatmap-title">
              <i class="fas fa-chart-line"></i> ${txt('نشاطك خلال السنة', 'Your Activity This Year')}
            </div>
            <div class="heatmap-legend">
              ${txt('أقل', 'Less')}
              <div class="heatmap-legend-item" style="background: rgba(255,255,255,0.05);"></div>
              <div class="heatmap-legend-item" style="background: #0e4429;"></div>
              <div class="heatmap-legend-item" style="background: #006d32;"></div>
              <div class="heatmap-legend-item" style="background: #26a641;"></div>
              <div class="heatmap-legend-item" style="background: #39d353;"></div>
              ${txt('أكثر', 'More')}
            </div>
          </div>
          <div class="heatmap-container">
            <div class="heatmap-months" id="heatmap-months"></div>
            <div class="heatmap-grid" id="activity-heatmap"></div>
          </div>
          <div class="heatmap-stats">
            <div class="heatmap-stat">
              <div class="heatmap-stat-value" id="total-contributions">0</div>
              <div class="heatmap-stat-label">${txt('نشاط هذا العام', 'contributions this year')}</div>
            </div>
            <div class="heatmap-stat">
              <div class="heatmap-stat-value" id="longest-streak">0</div>
              <div class="heatmap-stat-label">${txt('أطول سلسلة', 'longest streak')}</div>
            </div>
            <div class="heatmap-stat">
              <div class="heatmap-stat-value" id="current-streak">${streak}</div>
              <div class="heatmap-stat-label">${txt('السلسلة الحالية', 'current streak')}</div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Domains -->
      <div class="domains-section">
        <h2 class="section-title"><i class="fas fa-sitemap"></i> ${txt('اختر مجالك', 'Choose Your Domain')}</h2>
        <div class="domains-grid">
          <div class="domain-card red-team" onclick="loadPage('red-team')">
            <div class="domain-emoji">🔴</div>
            <div class="domain-name">${txt('الفريق الأحمر', 'Red Team')}</div>
            <div class="domain-subtitle">${txt('الأمن الهجومي', 'Offensive Security')}</div>
            <div class="domain-desc">${txt('أتقن تقنيات الاختراق واختبار الاختراق واستغلال الثغرات', 'Master hacking techniques, penetration testing, and vulnerability exploitation')}</div>
            <div class="domain-paths">
              <span class="domain-path-tag">Web Pentesting</span>
              <span class="domain-path-tag">Network Hacking</span>
              <span class="domain-path-tag">Exploit Dev</span>
              <span class="domain-path-tag">+3 more</span>
            </div>
          </div>
          <div class="domain-card blue-team" onclick="loadPage('blue-team')">
            <div class="domain-emoji">🔵</div>
            <div class="domain-name">${txt('الفريق الأزرق', 'Blue Team')}</div>
            <div class="domain-subtitle">${txt('الأمن الدفاعي', 'Defensive Security')}</div>
            <div class="domain-desc">${txt('تعلم الدفاع والتحليل الجنائي والاستجابة للحوادث', 'Learn defense, forensics, and incident response')}</div>
            <div class="domain-paths">
              <span class="domain-path-tag">SOC Analyst</span>
              <span class="domain-path-tag">Digital Forensics</span>
              <span class="domain-path-tag">Malware Analysis</span>
              <span class="domain-path-tag">+3 more</span>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Quick Actions -->
      <div class="actions-section">
        <h2 class="section-title"><i class="fas fa-bolt"></i> ${txt('إجراءات سريعة', 'Quick Actions')}</h2>
        <div class="actions-grid">
          <div class="action-card" onclick="loadPage('lab-paths')">
            <div class="action-icon purple"><i class="fas fa-flask"></i></div>
            <div class="action-text">
              <h4>${txt('مختبرات الاختراق', 'Hacking Labs')}</h4>
              <p>${txt('ابدأ تحدي عملي الآن', 'Start a hands-on challenge now')}</p>
            </div>
          </div>
          <div class="action-card" onclick="loadPage('practice')" style="border-left: 3px solid #22c55e;">
            <div class="action-icon" style="background: linear-gradient(135deg, #22c55e, #16a34a);"><i class="fas fa-door-open"></i></div>
            <div class="action-text">
              <h4>${txt('الغرف التفاعلية', 'Interactive Rooms')}</h4>
              <p>${txt('تعلم عملياً على طريقة TryHackMe', 'Learn TryHackMe style')}</p>
            </div>
          </div>
          <div class="action-card" onclick="loadPage('ctf-arena')">
            <div class="action-icon red"><i class="fas fa-flag"></i></div>
            <div class="action-text">
              <h4>${txt('ساحة CTF', 'CTF Arena')}</h4>
              <p>${txt('تنافس وتحدى نفسك', 'Compete and challenge yourself')}</p>
            </div>
          </div>
          <div class="action-card" onclick="loadPage('toolshub')" style="border-left: 3px solid #a855f7;">
            <div class="action-icon" style="background: linear-gradient(135deg, #a855f7, #9333ea);"><i class="fas fa-toolbox"></i></div>
            <div class="action-text">
              <h4>${txt('مركز الأدوات', 'Tools Center')}</h4>
              <p>${txt('Reverse Shell, Hash ID, XSS', 'Reverse Shell, Hash ID, XSS')}</p>
            </div>
          </div>
          <div class="action-card" onclick="loadPage('courses')">
            <div class="action-icon green"><i class="fas fa-graduation-cap"></i></div>
            <div class="action-text">
              <h4>${txt('الكورسات', 'Courses')}</h4>
              <p>${txt('تعلم من الخبراء', 'Learn from experts')}</p>
            </div>
          </div>
          <div class="action-card" onclick="loadPage('leaderboard')">
            <div class="action-icon orange"><i class="fas fa-trophy"></i></div>
            <div class="action-text">
              <h4>${txt('المتصدرين', 'Leaderboard')}</h4>
              <p>${txt('شاهد ترتيبك', 'See your ranking')}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Render Activity Heatmap
function renderActivityHeatmap() {
  const heatmapContainer = document.getElementById('activity-heatmap');
  const monthsContainer = document.getElementById('heatmap-months');
  if (!heatmapContainer) return;

  // Get activity data from localStorage
  const activityData = JSON.parse(localStorage.getItem('dailyActivity') || '{}');

  // Generate last 365 days
  const today = new Date();
  const days = [];
  let totalContributions = 0;
  let currentStreak = 0;
  let longestStreak = 0;
  let tempStreak = 0;

  for (let i = 364; i >= 0; i--) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    const count = activityData[dateStr] || 0;

    totalContributions += count;

    if (count > 0) {
      tempStreak++;
      if (tempStreak > longestStreak) longestStreak = tempStreak;
      if (i === 0) currentStreak = tempStreak;
    } else {
      tempStreak = 0;
    }

    days.push({ date: dateStr, count, dayOfWeek: date.getDay() });
  }

  // Render days
  let html = '';
  days.forEach(day => {
    let level = 0;
    if (day.count >= 1) level = 1;
    if (day.count >= 3) level = 2;
    if (day.count >= 5) level = 3;
    if (day.count >= 8) level = 4;

    const dateFormatted = new Date(day.date).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric'
    });

    html += `<div class="heatmap-day level-${level}" data-date="${day.date}">
      <div class="heatmap-tooltip">${day.count} activities on ${dateFormatted}</div>
    </div>`;
  });
  heatmapContainer.innerHTML = html;

  // Update stats
  const totalEl = document.getElementById('total-contributions');
  const longestEl = document.getElementById('longest-streak');
  if (totalEl) totalEl.textContent = totalContributions;
  if (longestEl) longestEl.textContent = longestStreak;

  // Render months
  if (monthsContainer) {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    let monthHtml = '';
    const startMonth = new Date(today);
    startMonth.setDate(startMonth.getDate() - 364);
    for (let i = 0; i < 12; i++) {
      const monthDate = new Date(startMonth);
      monthDate.setMonth(monthDate.getMonth() + i);
      monthHtml += `<span>${months[monthDate.getMonth()]}</span>`;
    }
    monthsContainer.innerHTML = monthHtml;
  }
}



/* ========== DOMAIN VIEW ========== */
function pageDomainView(domainId) {
  const domain = getDomainById ? getDomainById(domainId) : null;
  if (!domain) {
    return `<div class="container mt-5"><div class="alert alert-danger">Domain not found</div></div>`;
  }

  const paths = getPathsByDomain ? getPathsByDomain(domainId) : [];
  const isRedTeam = domainId === 'red-team';
  const primaryColor = isRedTeam ? '#ef4444' : '#3b82f6';
  const secondaryColor = isRedTeam ? '#dc2626' : '#1d4ed8';
  const glowColor = isRedTeam ? 'rgba(239,68,68,0.3)' : 'rgba(59,130,246,0.3)';

  return `
    <div class="domain-view-page">
      <style>
        .domain-view-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 100%); color: #fff; padding-bottom: 80px; }
        
        /* Hero Header */
        .domain-hero { padding: 80px 40px; background: linear-gradient(135deg, ${primaryColor}15 0%, transparent 50%, ${secondaryColor}10 100%); position: relative; overflow: hidden; text-align: center; }
        .domain-hero::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, ${primaryColor}, ${secondaryColor}); }
        .domain-hero::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 200px; background: linear-gradient(to top, #0f0c29, transparent); pointer-events: none; }
        .hero-glow { position: absolute; width: 600px; height: 600px; border-radius: 50%; background: radial-gradient(circle, ${glowColor} 0%, transparent 70%); top: -200px; left: 50%; transform: translateX(-50%); animation: pulse-glow 4s ease-in-out infinite; }
        @keyframes pulse-glow { 0%, 100% { opacity: 0.5; transform: translateX(-50%) scale(1); } 50% { opacity: 0.8; transform: translateX(-50%) scale(1.1); } }
        
        .domain-emoji { font-size: 5rem; margin-bottom: 20px; filter: drop-shadow(0 0 30px ${glowColor}); position: relative; z-index: 1; }
        .domain-title { font-size: 3rem; font-weight: 800; color: ${primaryColor}; margin-bottom: 15px; position: relative; z-index: 1; text-shadow: 0 0 40px ${glowColor}; }
        .domain-subtitle { color: rgba(255,255,255,0.7); font-size: 1.2rem; max-width: 600px; margin: 0 auto; position: relative; z-index: 1; }
        
        /* Stats Bar */
        .domain-stats-bar { display: flex; justify-content: center; gap: 50px; margin-top: 40px; position: relative; z-index: 1; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: 800; color: ${primaryColor}; }
        .stat-label { color: rgba(255,255,255,0.5); font-size: 0.9rem; margin-top: 5px; }
        
        /* Paths Grid */
        .paths-section { padding: 60px 40px; max-width: 1400px; margin: 0 auto; }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .section-title { font-size: 1.8rem; font-weight: 700; display: flex; align-items: center; gap: 15px; }
        .section-title i { color: ${primaryColor}; }
        
        .paths-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 30px; }
        
        /* Professional Path Card */
        .pro-path-card { background: linear-gradient(145deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; overflow: hidden; cursor: pointer; transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); position: relative; }
        .pro-path-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, ${primaryColor}, ${secondaryColor}); transform: scaleX(0); transition: transform 0.4s ease; transform-origin: left; }
        .pro-path-card:hover { transform: translateY(-10px); border-color: ${primaryColor}44; box-shadow: 0 25px 60px ${glowColor}; }
        .pro-path-card:hover::before { transform: scaleX(1); }
        
        /* Card Header */
        .card-header-pro { padding: 25px; display: flex; align-items: flex-start; gap: 20px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .path-icon-pro { width: 70px; height: 70px; border-radius: 16px; background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor}); display: flex; align-items: center; justify-content: center; font-size: 1.8rem; color: #fff; flex-shrink: 0; box-shadow: 0 10px 30px ${glowColor}; }
        .path-title-section { flex: 1; }
        .path-name-pro { font-size: 1.4rem; font-weight: 700; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
        .path-desc-pro { color: rgba(255,255,255,0.6); font-size: 0.9rem; line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
        
        /* Difficulty & Cert Badge */
        .path-badges { display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
        .badge-difficulty { padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-beginner { background: linear-gradient(135deg, #22c55e22, #22c55e11); color: #22c55e; border: 1px solid #22c55e44; }
        .badge-intermediate { background: linear-gradient(135deg, #f59e0b22, #f59e0b11); color: #f59e0b; border: 1px solid #f59e0b44; }
        .badge-advanced { background: linear-gradient(135deg, #ef444422, #ef444411); color: #ef4444; border: 1px solid #ef444444; }
        .badge-cert { padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; background: linear-gradient(135deg, ${primaryColor}22, ${primaryColor}11); color: ${primaryColor}; border: 1px solid ${primaryColor}44; display: flex; align-items: center; gap: 5px; }
        
        /* Card Body */
        .card-body-pro { padding: 25px; }
        
        /* Stats Row */
        .path-stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
        .path-stat { background: rgba(255,255,255,0.03); border-radius: 12px; padding: 15px; text-align: center; border: 1px solid rgba(255,255,255,0.05); }
        .path-stat-icon { font-size: 1.2rem; color: ${primaryColor}; margin-bottom: 8px; }
        .path-stat-value { font-size: 1.3rem; font-weight: 700; color: #fff; }
        .path-stat-label { font-size: 0.75rem; color: rgba(255,255,255,0.5); margin-top: 3px; }
        
        /* Progress Bar */
        .path-progress-section { margin-bottom: 20px; }
        .progress-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .progress-label { font-size: 0.8rem; color: rgba(255,255,255,0.6); }
        .progress-value { font-size: 0.8rem; font-weight: 600; color: ${primaryColor}; }
        .progress-bar-pro { height: 6px; background: rgba(255,255,255,0.1); border-radius: 6px; overflow: hidden; }
        .progress-fill-pro { height: 100%; background: linear-gradient(90deg, ${primaryColor}, ${secondaryColor}); border-radius: 6px; transition: width 0.5s ease; }
        
        /* Modules Preview */
        .modules-preview { display: flex; flex-wrap: wrap; gap: 8px; }
        .module-chip { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 20px; font-size: 0.75rem; color: rgba(255,255,255,0.7); transition: all 0.3s; }
        .pro-path-card:hover .module-chip { border-color: ${primaryColor}33; }
        
        /* Card Footer */
        .card-footer-pro { padding: 20px 25px; background: rgba(0,0,0,0.2); display: flex; justify-content: space-between; align-items: center; }
        .start-path-btn { background: linear-gradient(135deg, ${primaryColor}, ${secondaryColor}); border: none; padding: 12px 25px; border-radius: 12px; color: #fff; font-weight: 600; font-size: 0.9rem; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: all 0.3s; }
        .start-path-btn:hover { transform: scale(1.05); box-shadow: 0 10px 30px ${glowColor}; }
        .path-users { display: flex; align-items: center; gap: 8px; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
        
        /* Responsive */
        @media (max-width: 768px) {
          .paths-grid { grid-template-columns: 1fr; }
          .domain-hero { padding: 50px 20px; }
          .domain-title { font-size: 2rem; }
          .domain-stats-bar { gap: 30px; flex-wrap: wrap; }
        }
      </style>
      
      <!-- Hero Header -->
      <div class="domain-hero">
        <div class="hero-glow"></div>
        <div class="domain-emoji">${domain.emoji}</div>
        <h1 class="domain-title">${currentLang === 'ar' ? domain.nameAr : domain.name}</h1>
        <p class="domain-subtitle">${currentLang === 'ar' ? domain.descriptionAr : domain.description}</p>
        
        <div class="domain-stats-bar">
          <div class="stat-item">
            <div class="stat-number">${paths.length}</div>
            <div class="stat-label">${txt('مسارات متاحة', 'Available Paths')}</div>
          </div>
          <div class="stat-item">
            <div class="stat-number">${paths.reduce((sum, p) => sum + (p.modules?.length || 0), 0)}+</div>
            <div class="stat-label">${txt('وحدة تعليمية', 'Learning Modules')}</div>
          </div>
          <div class="stat-item">
            <div class="stat-number">${paths.reduce((sum, p) => sum + (p.estimatedHours || 0), 0)}h</div>
            <div class="stat-label">${txt('ساعات تعلم', 'Learning Hours')}</div>
          </div>
        </div>
      </div>
      
      <!-- Paths Section -->
      <div class="paths-section">
        <div class="section-header">
          <h2 class="section-title"><i class="fas fa-road"></i> ${txt('المسارات التخصصية', 'Career Paths')}</h2>
        </div>
        
        <div class="paths-grid">
          ${paths.map((path, index) => {
    const progress = Math.floor(Math.random() * 30); // Simulated progress
    const users = Math.floor(Math.random() * 500) + 100; // Simulated users
    return `
              <div class="pro-path-card" onclick="loadPage('path-roadmap', '${path.id}')">
                <!-- Card Header -->
                <div class="card-header-pro">
                  <div class="path-icon-pro"><i class="fas ${path.icon}"></i></div>
                  <div class="path-title-section">
                    <h3 class="path-name-pro">${currentLang === 'ar' ? path.nameAr : path.name}</h3>
                    <p class="path-desc-pro">${currentLang === 'ar' ? path.descriptionAr : path.description}</p>
                    <div class="path-badges">
                      <span class="badge-difficulty badge-${path.difficulty}">${path.difficulty}</span>
                      ${path.certification ? `<span class="badge-cert"><i class="fas fa-certificate"></i> ${path.certification}</span>` : ''}
                    </div>
                  </div>
                </div>
                
                <!-- Card Body -->
                <div class="card-body-pro">
                  <!-- Stats -->
                  <div class="path-stats-row">
                    <div class="path-stat">
                      <div class="path-stat-icon"><i class="fas fa-clock"></i></div>
                      <div class="path-stat-value">${path.estimatedHours}h</div>
                      <div class="path-stat-label">${txt('المدة', 'Duration')}</div>
                    </div>
                    <div class="path-stat">
                      <div class="path-stat-icon"><i class="fas fa-layer-group"></i></div>
                      <div class="path-stat-value">${path.modules?.length || 0}</div>
                      <div class="path-stat-label">${txt('وحدات', 'Modules')}</div>
                    </div>
                    <div class="path-stat">
                      <div class="path-stat-icon"><i class="fas fa-flask"></i></div>
                      <div class="path-stat-value">${(path.modules?.length || 0) * 2}</div>
                      <div class="path-stat-label">${txt('مختبرات', 'Labs')}</div>
                    </div>
                  </div>
                  
                  <!-- Progress -->
                  <div class="path-progress-section">
                    <div class="progress-header">
                      <span class="progress-label">${txt('تقدمك', 'Your Progress')}</span>
                      <span class="progress-value">${progress}%</span>
                    </div>
                    <div class="progress-bar-pro">
                      <div class="progress-fill-pro" style="width: ${progress}%"></div>
                    </div>
                  </div>
                  
                  <!-- Modules Preview -->
                  <div class="modules-preview">
                    ${(path.modules || []).slice(0, 3).map(m => `<span class="module-chip">${currentLang === 'ar' ? m.nameAr : m.name}</span>`).join('')}
                    ${(path.modules?.length || 0) > 3 ? `<span class="module-chip">+${path.modules.length - 3}</span>` : ''}
                  </div>
                </div>
                
                <!-- Card Footer -->
                <div class="card-footer-pro">
                  <button class="start-path-btn">
                    ${progress > 0 ? txt('استمر', 'Continue') : txt('ابدأ الآن', 'Start Now')} <i class="fas fa-arrow-right"></i>
                  </button>
                  <div class="path-users">
                    <i class="fas fa-users"></i> ${users} ${txt('متعلم', 'learners')}
                  </div>
                </div>
              </div>
            `;
  }).join('')}
        </div>
      </div>
    </div>
  `;
}

/* ========== PATH ROADMAP ========== */
function pagePathRoadmap(pathId) {
  console.log('DEBUG: pagePathRoadmap called', pathId);
  try {
    if (typeof getPathById !== 'function' && typeof UnifiedLearningData !== 'undefined') {
      // Fallback if getPathById isn't global
      var path = UnifiedLearningData.getPathById(pathId);
    } else {
      var path = typeof getPathById === 'function' ? getPathById(pathId) : null;
    }
  } catch (e) {
    console.error('Error fetching path:', e);
    return `<div class="container mt-5"><div class="alert alert-danger">Error loading path data: ${e.message}</div></div>`;
  }

  if (!path) {
    return `<div class="container mt-5"><div class="alert alert-danger">Path not found</div></div>`;
  }

  const progress = JSON.parse(localStorage.getItem('moduleProgress') || '{}');
  const completedModules = Object.keys(progress).filter(k => k.startsWith(pathId) && progress[k].completed).length;
  const progressPercent = path.modules?.length ? Math.round((completedModules / path.modules.length) * 100) : 0;

  return `
    <div class="roadmap-page">
      <style>
        .roadmap-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 100%); color: #fff; padding-bottom: 60px; }
        .roadmap-header { padding: 40px; background: rgba(102,126,234,0.1); border-bottom: 1px solid rgba(255,255,255,0.1); }
        .back-btn { color: rgba(255,255,255,0.7); text-decoration: none; display: inline-flex; align-items: center; gap: 8px; margin-bottom: 20px; transition: color 0.3s; }
        .back-btn:hover { color: #667eea; }
        .path-title { font-size: 2rem; font-weight: 700; margin-bottom: 10px; display: flex; align-items: center; gap: 15px; }
        .path-title i { color: ${path.color || '#667eea'}; }
        .progress-bar-container { background: rgba(255,255,255,0.1); border-radius: 10px; height: 12px; margin-top: 20px; overflow: hidden; }
        .progress-bar-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); border-radius: 10px; transition: width 0.5s; }
        .progress-text { margin-top: 10px; color: rgba(255,255,255,0.6); font-size: 0.9rem; }
        
        .roadmap-container { padding: 40px; max-width: 900px; margin: 0 auto; }
        .roadmap-timeline { position: relative; padding-left: 50px; }
        .roadmap-timeline::before { content: ''; position: absolute; left: 20px; top: 0; bottom: 0; width: 4px; background: linear-gradient(180deg, #667eea 0%, #764ba2 50%, #667eea44 100%); border-radius: 4px; }
        
        .module-node { position: relative; margin-bottom: 30px; }
        .module-number { position: absolute; left: -50px; top: 0; width: 40px; height: 40px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.1rem; border: 3px solid #1a1a2e; z-index: 1; }
        .module-number.completed { background: linear-gradient(135deg, #22c55e, #16a34a); }
        .module-number.locked { background: rgba(255,255,255,0.2); }
        
        .module-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; margin-left: 20px; cursor: pointer; transition: all 0.3s; }
        .module-card:hover { background: rgba(255,255,255,0.1); border-color: rgba(102,126,234,0.5); transform: translateX(10px); }
        .module-card.completed { border-color: #22c55e44; }
        .module-card.locked { opacity: 0.5; cursor: not-allowed; }
        .module-name { font-size: 1.2rem; font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
        .module-name .status-icon { font-size: 1rem; }
        .module-status { display: flex; gap: 15px; margin-top: 15px; flex-wrap: wrap; }
        .status-item { display: flex; align-items: center; gap: 6px; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
        .status-item.done { color: #22c55e; }
      </style>
      
      <div class="roadmap-header">
        <a href="javascript:void(0)" onclick="loadPage('${path.domainId}')" class="back-btn">
          <i class="fas fa-arrow-left"></i> ${txt('رجوع', 'Back')}
        </a>
        <h1 class="path-title"><i class="fas ${path.icon}"></i> ${currentLang === 'ar' ? path.nameAr : path.name}</h1>
        <p style="color: rgba(255,255,255,0.6); max-width: 600px;">${currentLang === 'ar' ? path.descriptionAr : path.description}</p>
        <div class="progress-bar-container">
          <div class="progress-bar-fill" style="width: ${progressPercent}%"></div>
        </div>
        <div class="progress-text">${progressPercent}% ${txt('مكتمل', 'Complete')} • ${completedModules}/${path.modules?.length || 0} ${txt('وحدات', 'modules')}</div>
      </div>
      
      <div class="roadmap-container">
        <div class="roadmap-timeline">
          ${(path.modules || []).map((module, index) => {
    const moduleKey = `${pathId}_${module.id}`;
    const moduleProgress = progress[moduleKey] || {};
    const isCompleted = moduleProgress.completed;
    const isLocked = index > 0 && !progress[`${pathId}_${path.modules[index - 1].id}`]?.completed;

    return `
              <div class="module-node">
                <div class="module-number ${isCompleted ? 'completed' : isLocked ? 'locked' : ''}">${index + 1}</div>
                <div class="module-card ${isCompleted ? 'completed' : isLocked ? 'locked' : ''}" 
                     onclick="${isLocked ? '' : `loadPage('module-learning', '${pathId}/${module.id}')`}">
                  <div class="module-name">
                    ${currentLang === 'ar' ? module.nameAr : module.name}
                    ${isCompleted ? '<span class="status-icon" style="color:#22c55e">✓</span>' : isLocked ? '<span class="status-icon">🔒</span>' : ''}
                  </div>
                  <div class="module-status">
                    <span class="status-item ${moduleProgress.contentDone ? 'done' : ''}">
                      <i class="fas fa-book"></i> ${txt('المحتوى', 'Content')}
                    </span>
                    <span class="status-item ${moduleProgress.quizDone ? 'done' : ''}">
                      <i class="fas fa-question-circle"></i> ${txt('الكويز', 'Quiz')}
                    </span>
                    <span class="status-item ${moduleProgress.labDone ? 'done' : ''}">
                      <i class="fas fa-flask"></i> ${txt('اللاب', 'Lab')}
                    </span>
                  </div>
                </div>
              </div>
            `;
  }).join('')}
        </div>
      </div>
    </div>
  `;
}

/* ========== MODULE LEARNING ========== */
function pageModuleLearning(params) {
  const [pathId, moduleId] = params.split('/');
  const path = getPathById ? getPathById(pathId) : null;
  const module = path?.modules?.find(m => m.id === moduleId);

  if (!path || !module) {
    return `<div class="container mt-5"><div class="alert alert-danger">Module not found</div></div>`;
  }

  // Store module data for quiz functionality
  window.currentModuleData = module;
  window.currentPathId = pathId;
  window.currentModuleId = moduleId;

  return `
    <div class="module-learning-page">
      <style>
        .module-learning-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 100%); color: #fff; }
        
        /* Header */
        .module-header { padding: 40px; background: linear-gradient(135deg, rgba(102,126,234,0.15) 0%, rgba(118,75,162,0.15) 100%); border-bottom: 1px solid rgba(255,255,255,0.1); }
        .breadcrumb { display: flex; align-items: center; gap: 10px; color: rgba(255,255,255,0.5); margin-bottom: 15px; font-size: 0.9rem; }
        .breadcrumb a { color: #667eea; text-decoration: none; transition: color 0.3s; }
        .breadcrumb a:hover { color: #764ba2; }
        .module-title { font-size: 2rem; font-weight: 700; margin-bottom: 10px; }
        .module-desc { color: rgba(255,255,255,0.7); max-width: 700px; }
        
        /* Meta Info */
        .module-meta { display: flex; gap: 25px; margin-top: 20px; flex-wrap: wrap; }
        .meta-item { display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 8px 15px; border-radius: 20px; font-size: 0.85rem; }
        .meta-item i { color: #667eea; }
        
        /* Tabs */
        .module-tabs { display: flex; gap: 5px; padding: 20px 40px 0; background: rgba(0,0,0,0.3); overflow-x: auto; }
        .module-tab { padding: 14px 28px; background: transparent; border: none; color: rgba(255,255,255,0.5); cursor: pointer; border-radius: 12px 12px 0 0; transition: all 0.3s; font-size: 1rem; font-weight: 500; white-space: nowrap; display: flex; align-items: center; gap: 8px; }
        .module-tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
        .module-tab.active { background: linear-gradient(135deg, #1a1a2e, #16213e); color: #667eea; }
        
        /* Content Area */
        .module-content-area { padding: 40px; max-width: 1000px; margin: 0 auto; }
        .content-section { display: none; animation: fadeIn 0.3s ease; }
        .content-section.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Content Card */
        .content-card { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; padding: 30px; margin-bottom: 25px; }
        .content-card h3 { margin-bottom: 20px; color: #667eea; font-size: 1.3rem; display: flex; align-items: center; gap: 12px; }
        .content-card h3 i { font-size: 1.1rem; }
        .content-card p { color: rgba(255,255,255,0.75); line-height: 1.8; margin-bottom: 15px; }
        
        /* Objectives */
        .objectives-list { list-style: none; padding: 0; }
        .objectives-list li { padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; gap: 12px; color: rgba(255,255,255,0.8); }
        .objectives-list li:last-child { border-bottom: none; }
        .objectives-list li i { color: #22c55e; font-size: 0.9rem; }
        
        /* Tools */
        .tools-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 15px; }
        .tool-badge { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(102,126,234,0.1)); border: 1px solid rgba(102,126,234,0.3); padding: 8px 16px; border-radius: 20px; font-size: 0.85rem; color: #667eea; font-weight: 500; }
        
        /* Code Commands */
        .command-box { background: #0f0f23; border: 1px solid rgba(102,126,234,0.2); border-radius: 12px; padding: 20px; margin: 15px 0; font-family: 'Fira Code', monospace; }
        .command-header { color: rgba(255,255,255,0.5); font-size: 0.8rem; margin-bottom: 10px; }
        .command-code { color: #00f2ea; font-size: 0.95rem; word-break: break-all; }
        .command-desc { color: rgba(255,255,255,0.6); font-size: 0.85rem; margin-top: 10px; }
        
        /* Quiz */
        .quiz-question { margin-bottom: 30px; }
        .quiz-question-text { font-size: 1.1rem; color: #fff; margin-bottom: 20px; font-weight: 500; }
        .quiz-options { display: flex; flex-direction: column; gap: 12px; }
        .quiz-option { background: rgba(255,255,255,0.03); border: 2px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 16px 20px; cursor: pointer; transition: all 0.3s; display: flex; align-items: center; gap: 15px; }
        .quiz-option:hover { border-color: rgba(102,126,234,0.5); background: rgba(102,126,234,0.05); }
        .quiz-option.selected { border-color: #667eea; background: rgba(102,126,234,0.1); }
        .quiz-option.correct { border-color: #22c55e; background: rgba(34,197,94,0.15); }
        .quiz-option.wrong { border-color: #ef4444; background: rgba(239,68,68,0.15); }
        .option-letter { width: 32px; height: 32px; border-radius: 50%; background: rgba(255,255,255,0.1); display: flex; align-items: center; justify-content: center; font-weight: 600; flex-shrink: 0; }
        .quiz-explanation { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); border-radius: 12px; padding: 15px 20px; margin-top: 15px; color: #22c55e; display: none; }
        
        /* Lab */
        .lab-card { background: linear-gradient(135deg, rgba(102,126,234,0.1), rgba(118,75,162,0.1)); border: 2px solid rgba(102,126,234,0.2); border-radius: 24px; padding: 40px; text-align: center; }
        .lab-icon { font-size: 4rem; margin-bottom: 20px; }
        .lab-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 10px; }
        .lab-difficulty { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; margin-bottom: 20px; }
        .lab-difficulty.easy { background: rgba(34,197,94,0.2); color: #22c55e; }
        .lab-difficulty.medium { background: rgba(245,158,11,0.2); color: #f59e0b; }
        .lab-difficulty.hard { background: rgba(239,68,68,0.2); color: #ef4444; }
        .lab-desc { color: rgba(255,255,255,0.7); margin-bottom: 25px; max-width: 500px; margin-left: auto; margin-right: auto; }
        .lab-stats { display: flex; justify-content: center; gap: 40px; margin-bottom: 30px; }
        .lab-stat { text-align: center; }
        .lab-stat-value { font-size: 1.5rem; font-weight: 700; color: #667eea; }
        .lab-stat-label { font-size: 0.85rem; color: rgba(255,255,255,0.5); }
        .start-lab-btn { background: linear-gradient(135deg, #667eea, #764ba2); border: none; padding: 16px 45px; border-radius: 14px; color: #fff; font-size: 1.1rem; font-weight: 600; cursor: pointer; transition: all 0.3s; display: inline-flex; align-items: center; gap: 10px; }
        .start-lab-btn:hover { transform: translateY(-3px); box-shadow: 0 15px 40px rgba(102,126,234,0.4); }
        
        /* Hints */
        .hints-section { margin-top: 30px; text-align: left; }
        .hint-item { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.2); border-radius: 12px; padding: 15px 20px; margin-bottom: 10px; color: #f59e0b; cursor: pointer; display: flex; align-items: center; gap: 12px; }
        .hint-content { display: none; color: rgba(255,255,255,0.8); margin-top: 10px; }
        
        /* Complete Button */
        .complete-btn { background: linear-gradient(135deg, #22c55e, #16a34a); border: none; padding: 14px 35px; border-radius: 12px; color: #fff; font-weight: 600; cursor: pointer; margin-top: 25px; display: inline-flex; align-items: center; gap: 10px; transition: all 0.3s; }
        .complete-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(34,197,94,0.3); }
      </style>
      
      <!-- Header -->
      <div class="module-header">
        <div class="breadcrumb">
          <a href="javascript:void(0)" onclick="loadPage('${path.domainId}')">${currentLang === 'ar' ? path.nameAr : path.name}</a>
          <i class="fas fa-chevron-right"></i>
          <a href="javascript:void(0)" onclick="loadPage('path-roadmap', '${pathId}')">${txt('خريطة المسار', 'Path Roadmap')}</a>
          <i class="fas fa-chevron-right"></i>
          <span>${currentLang === 'ar' ? module.nameAr : module.name}</span>
        </div>
        <h1 class="module-title">${currentLang === 'ar' ? module.nameAr : module.name}</h1>
        <p class="module-desc">${currentLang === 'ar' ? (module.descriptionAr || module.description) : module.description}</p>
        
        <div class="module-meta">
          <div class="meta-item"><i class="fas fa-clock"></i> ${module.estimatedMinutes || 60} ${txt('دقيقة', 'minutes')}</div>
          <div class="meta-item"><i class="fas fa-star"></i> ${module.lab?.points || 100} ${txt('نقطة', 'points')}</div>
          <div class="meta-item"><i class="fas fa-signal"></i> ${module.lab?.difficulty || 'medium'}</div>
        </div>
      </div>
      
      <!-- Tabs -->
      <div class="module-tabs">
        <button class="module-tab active" onclick="showModuleTab('content')"><i class="fas fa-book"></i> ${txt('المحتوى', 'Content')}</button>
        <button class="module-tab" onclick="showModuleTab('quiz')"><i class="fas fa-clipboard-question"></i> ${txt('الكويز', 'Quiz')}</button>
        <button class="module-tab" onclick="showModuleTab('lab')"><i class="fas fa-flask"></i> ${txt('المختبر', 'Lab')}</button>
      </div>
      
      <!-- Content Area -->
      <div class="module-content-area">
        <!-- Content Tab -->
        <div id="content-tab" class="content-section active">
          <!-- Objectives -->
          ${module.objectives ? `
          <div class="content-card">
            <h3><i class="fas fa-bullseye"></i> ${txt('أهداف التعلم', 'Learning Objectives')}</h3>
            <ul class="objectives-list">
              ${(currentLang === 'ar' ? module.objectivesAr : module.objectives).map(obj => `
                <li><i class="fas fa-check-circle"></i> ${obj}</li>
              `).join('')}
            </ul>
          </div>
          ` : ''}
          
          <!-- Tools -->
          ${module.tools ? `
          <div class="content-card">
            <h3><i class="fas fa-wrench"></i> ${txt('الأدوات المستخدمة', 'Tools Used')}</h3>
            <div class="tools-grid">
              ${module.tools.map(tool => `<span class="tool-badge">${tool}</span>`).join('')}
            </div>
          </div>
          ` : ''}
          
          <!-- Content Sections -->
          ${module.content?.sections ? module.content.sections.map(section => `
          <div class="content-card">
            <h3><i class="fas fa-book-open"></i> ${currentLang === 'ar' ? section.titleAr : section.title}</h3>
            <p>${currentLang === 'ar' ? section.contentAr : section.content}</p>
          </div>
          `).join('') : ''}
          
          <!-- Commands -->
          ${module.content?.commands ? `
          <div class="content-card">
            <h3><i class="fas fa-terminal"></i> ${txt('أوامر مفيدة', 'Useful Commands')}</h3>
            ${module.content.commands.map(cmd => `
            <div class="command-box">
              <div class="command-header">${cmd.tool}</div>
              <div class="command-code">${cmd.command}</div>
              <div class="command-desc">${cmd.description}</div>
            </div>
            `).join('')}
          </div>
          ` : ''}
          
          <button class="complete-btn" onclick="markContentComplete('${pathId}', '${moduleId}')">
            <i class="fas fa-check"></i> ${txt('إتمام المحتوى', 'Mark Content Complete')}
          </button>
        </div>
        
        <!-- Quiz Tab -->
        <div id="quiz-tab" class="content-section">
          <div class="content-card">
            <h3><i class="fas fa-clipboard-question"></i> ${txt('اختبار الوحدة', 'Module Quiz')}</h3>
            <p>${txt('أجب على الأسئلة التالية لاختبار فهمك للمحتوى', 'Answer the following questions to test your understanding')}</p>
          </div>
          
          <div id="quiz-questions">
            ${module.quiz?.questions ? module.quiz.questions.map((q, qIndex) => `
            <div class="content-card quiz-question" data-question="${qIndex}">
              <div class="quiz-question-text">${qIndex + 1}. ${currentLang === 'ar' ? q.questionAr : q.question}</div>
              <div class="quiz-options">
                ${q.options.map((opt, optIndex) => `
                <div class="quiz-option" data-question="${qIndex}" data-option="${optIndex}" onclick="selectQuizOption(${qIndex}, ${optIndex}, ${q.correct})">
                  <span class="option-letter">${String.fromCharCode(65 + optIndex)}</span>
                  <span>${opt}</span>
                </div>
                `).join('')}
              </div>
              <div class="quiz-explanation" id="explanation-${qIndex}">${q.explanation}</div>
            </div>
            `).join('') : `<div class="content-card"><p>${txt('لا توجد أسئلة متاحة لهذه الوحدة', 'No quiz questions available for this module')}</p></div>`}
          </div>
          
          <button class="complete-btn" onclick="submitQuiz('${pathId}', '${moduleId}')" style="background: linear-gradient(135deg, #667eea, #764ba2);">
            <i class="fas fa-paper-plane"></i> ${txt('إرسال الإجابات', 'Submit Answers')}
          </button>
        </div>
        
        <!-- Lab Tab -->
        <div id="lab-tab" class="content-section">
          ${module.lab ? `
          <div class="lab-card">
            <div class="lab-icon">🧪</div>
            <h2 class="lab-title">${currentLang === 'ar' ? module.lab.titleAr : module.lab.title}</h2>
            <span class="lab-difficulty ${module.lab.difficulty}">${module.lab.difficulty.toUpperCase()}</span>
            <p class="lab-desc">${currentLang === 'ar' ? module.lab.descriptionAr : module.lab.description}</p>
            
            <div class="lab-stats">
              <div class="lab-stat">
                <div class="lab-stat-value">${module.lab.points}</div>
                <div class="lab-stat-label">${txt('نقطة', 'Points')}</div>
              </div>
              <div class="lab-stat">
                <div class="lab-stat-value">${module.lab.estimatedTime}</div>
                <div class="lab-stat-label">${txt('دقيقة', 'Minutes')}</div>
              </div>
            </div>
            
            <button class="start-lab-btn" onclick="startModuleLab('${pathId}', '${moduleId}')">
              <i class="fas fa-play"></i> ${txt('بدء المختبر', 'Start Lab')}
            </button>
            
            ${module.lab.hints ? `
            <div class="hints-section">
              <h4 style="margin-bottom: 15px; color: #f59e0b;"><i class="fas fa-lightbulb"></i> ${txt('تلميحات', 'Hints')}</h4>
              ${module.lab.hints.map((hint, i) => `
              <div class="hint-item" onclick="this.querySelector('.hint-content').style.display = this.querySelector('.hint-content').style.display === 'block' ? 'none' : 'block'">
                <i class="fas fa-key"></i>
                <span>${txt('تلميح', 'Hint')} ${i + 1}</span>
                <div class="hint-content">${hint}</div>
              </div>
              `).join('')}
            </div>
            ` : ''}
          </div>
          ` : `<div class="content-card"><p>${txt('لا يوجد مختبر متاح لهذه الوحدة', 'No lab available for this module')}</p></div>`}
        </div>
      </div>
    </div>
  `;
}

// Tab switching for module learning
window.showModuleTab = function (tabId) {
  document.querySelectorAll('.module-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
  document.querySelector(`[onclick="showModuleTab('${tabId}')"]`).classList.add('active');
  document.getElementById(`${tabId}-tab`).classList.add('active');
};

// Mark content complete
window.markContentComplete = function (pathId, moduleId) {
  const progress = JSON.parse(localStorage.getItem('moduleProgress') || '{}');
  const key = `${pathId}_${moduleId}`;
  progress[key] = progress[key] || {};
  progress[key].contentDone = true;
  localStorage.setItem('moduleProgress', JSON.stringify(progress));
  showToast(txt('تم إتمام المحتوى!', 'Content marked as complete!'), 'success');
};

// Start module lab
window.startModuleLab = function (pathId, moduleId) {
  showToast(txt('جاري تحميل المختبر...', 'Loading lab...'), 'info');
  // In production, this would call the backend to start a Docker container
};

// Quiz answer tracking
window.quizAnswers = {};

// Select quiz option
window.selectQuizOption = function (questionIndex, optionIndex, correctAnswer) {
  // Store the answer
  window.quizAnswers[questionIndex] = optionIndex;

  // Update visual selection
  const options = document.querySelectorAll(`[data-question="${questionIndex}"]`);
  options.forEach(opt => {
    if (opt.classList.contains('quiz-option')) {
      opt.classList.remove('selected');
    }
  });

  const selectedOption = document.querySelector(`.quiz-option[data-question="${questionIndex}"][data-option="${optionIndex}"]`);
  if (selectedOption) {
    selectedOption.classList.add('selected');
  }
};

// Submit quiz
window.submitQuiz = function (pathId, moduleId) {
  const module = window.currentModuleData;
  if (!module || !module.quiz || !module.quiz.questions) {
    showToast(txt('لا توجد أسئلة للتقييم', 'No questions to evaluate'), 'error');
    return;
  }

  let correctCount = 0;
  const questions = module.quiz.questions;

  questions.forEach((q, index) => {
    const userAnswer = window.quizAnswers[index];
    const options = document.querySelectorAll(`.quiz-option[data-question="${index}"]`);
    const explanationEl = document.getElementById(`explanation-${index}`);

    options.forEach((opt, optIndex) => {
      opt.classList.remove('selected', 'correct', 'wrong');

      if (optIndex === q.correct) {
        opt.classList.add('correct');
      } else if (userAnswer === optIndex) {
        opt.classList.add('wrong');
      }
    });

    if (userAnswer === q.correct) {
      correctCount++;
    }

    // Show explanation
    if (explanationEl) {
      explanationEl.style.display = 'block';
    }
  });

  const score = Math.round((correctCount / questions.length) * 100);
  const passed = score >= (module.quiz.passingScore || 70);

  // Save progress
  const progress = JSON.parse(localStorage.getItem('moduleProgress') || '{}');
  const key = `${pathId}_${moduleId}`;
  progress[key] = progress[key] || {};
  progress[key].quizScore = score;
  progress[key].quizDone = passed;
  localStorage.setItem('moduleProgress', JSON.stringify(progress));

  // Award points if passed
  if (passed) {
    const currentPoints = parseInt(localStorage.getItem('userPoints') || '0');
    const pointsEarned = Math.round((module.lab?.points || 100) * 0.3); // 30% of lab points for quiz
    localStorage.setItem('userPoints', currentPoints + pointsEarned);

    showToast(`🎉 ${txt('نجحت!', 'You passed!')} ${score}% - +${pointsEarned} ${txt('نقطة', 'points')}`, 'success');
  } else {
    showToast(`${txt('حاول مرة أخرى', 'Try again')} - ${score}% (${txt('مطلوب', 'Required')}: ${module.quiz.passingScore || 70}%)`, 'error');
  }

  // Reset answers for retry
  window.quizAnswers = {};
};


/* ========== CTF ARENA ========== */
function pageCTFArena() {
  return `
    <div class="ctf-arena-page">
      <style>
        .ctf-arena-page { min-height: 100vh; background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 100%); color: #fff; padding-bottom: 60px; }
        .arena-hero { padding: 80px 40px; text-align: center; background: linear-gradient(135deg, rgba(239,68,68,0.15) 0%, rgba(59,130,246,0.15) 100%); border-bottom: 1px solid rgba(255,255,255,0.1); position: relative; overflow: hidden; }
        .arena-hero::before { content: '🏆'; position: absolute; font-size: 20rem; opacity: 0.03; top: 50%; left: 50%; transform: translate(-50%, -50%); }
        .arena-title { font-size: 3rem; font-weight: 800; background: linear-gradient(135deg, #ef4444 0%, #f59e0b 50%, #3b82f6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 15px; }
        .arena-subtitle { color: rgba(255,255,255,0.7); font-size: 1.2rem; }
        
        .arena-modes { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 30px; padding: 50px 40px; max-width: 1400px; margin: 0 auto; }
        .mode-card { background: rgba(255,255,255,0.05); border: 2px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.4s; position: relative; overflow: hidden; }
        .mode-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; }
        .mode-card.jeopardy::before { background: linear-gradient(90deg, #667eea, #764ba2); }
        .mode-card.seasonal::before { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .mode-card.attack-defense::before { background: linear-gradient(90deg, #ef4444, #3b82f6); }
        .mode-card:hover { transform: translateY(-10px); border-color: rgba(255,255,255,0.3); }
        .mode-icon { font-size: 4rem; margin-bottom: 20px; }
        .mode-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 10px; }
        .mode-desc { color: rgba(255,255,255,0.6); margin-bottom: 20px; line-height: 1.6; }
        .mode-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; }
        .badge-active { background: #22c55e33; color: #22c55e; }
        .badge-soon { background: #f59e0b33; color: #f59e0b; }
        
        .categories-section { padding: 40px; max-width: 1400px; margin: 0 auto; }
        .section-title { font-size: 1.8rem; margin-bottom: 30px; }
        .categories-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .category-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; text-align: center; cursor: pointer; transition: all 0.3s; }
        .category-card:hover { background: rgba(255,255,255,0.1); transform: scale(1.05); }
        .category-icon { font-size: 2.5rem; margin-bottom: 15px; }
        .category-name { font-weight: 600; margin-bottom: 5px; }
        .category-count { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
      </style>
      
      <div class="arena-hero">
        <h1 class="arena-title">🏆 ${txt('ساحة CTF', 'CTF Arena')}</h1>
        <p class="arena-subtitle">${txt('تحدى نفسك وتنافس مع الآخرين في مسابقات الأمن السيبراني', 'Challenge yourself and compete with others in cybersecurity competitions')}</p>
      </div>
      
      <div class="arena-modes">
        <div class="mode-card jeopardy" onclick="loadPage('ctf')">
          <div class="mode-icon">🎯</div>
          <div class="mode-title">${txt('تحديات Jeopardy', 'Jeopardy Challenges')}</div>
          <div class="mode-desc">${txt('تحديات منفصلة في فئات مختلفة - اختر ما يناسبك', 'Standalone challenges in different categories - choose what suits you')}</div>
          <span class="mode-badge badge-active">${txt('متاح الآن', 'Available Now')}</span>
        </div>
        
        <div class="mode-card seasonal" onclick="loadPage('leaderboard')">
          <div class="mode-icon">📅</div>
          <div class="mode-title">${txt('الدوري الموسمي', 'Seasonal League')}</div>
          <div class="mode-desc">${txt('دوري شهري بلوحة متصدرين يتم تصفيرها كل شهر', 'Monthly league with leaderboard reset every month')}</div>
          <span class="mode-badge badge-active">${txt('الموسم الأول', 'Season 1')}</span>
        </div>
        
        <div class="mode-card attack-defense">
          <div class="mode-icon">⚔️</div>
          <div class="mode-title">${txt('هجوم ودفاع', 'Attack-Defense')}</div>
          <div class="mode-desc">${txt('فرق تهاجم وتدافع في الوقت الحقيقي', 'Teams attack and defend in real-time')}</div>
          <span class="mode-badge badge-soon">${txt('قريباً', 'Coming Soon')}</span>
        </div>
      </div>
      
      <div class="categories-section">
        <h2 class="section-title"><i class="fas fa-th-large"></i> ${txt('فئات التحديات', 'Challenge Categories')}</h2>
        <div class="categories-grid">
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">🌐</div>
            <div class="category-name">Web</div>
            <div class="category-count">15 ${txt('تحدي', 'challenges')}</div>
          </div>
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">🔐</div>
            <div class="category-name">Crypto</div>
            <div class="category-count">12 ${txt('تحدي', 'challenges')}</div>
          </div>
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">💾</div>
            <div class="category-name">Pwn</div>
            <div class="category-count">8 ${txt('تحدي', 'challenges')}</div>
          </div>
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">🔍</div>
            <div class="category-name">Forensics</div>
            <div class="category-count">10 ${txt('تحدي', 'challenges')}</div>
          </div>
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">🔄</div>
            <div class="category-name">Reverse</div>
            <div class="category-count">7 ${txt('تحدي', 'challenges')}</div>
          </div>
          <div class="category-card" onclick="loadPage('ctf')">
            <div class="category-icon">🧩</div>
            <div class="category-name">Misc</div>
            <div class="category-count">9 ${txt('تحدي', 'challenges')}</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Toast notification helper
window.showToast = window.showToast || function (message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast-notification toast-${type}`;
  toast.innerHTML = message;
  toast.style.cssText = `
    position: fixed; bottom: 20px; right: 20px; padding: 15px 25px; border-radius: 10px; 
    background: ${type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#667eea'}; 
    color: white; font-weight: 500; z-index: 10000; animation: slideIn 0.3s ease;
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
};


// ========== LOGIN PAGE ========== */
function pageLogin() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="auth-container">
        <style>
            .auth-container {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
                padding: 20px;
            }
            
            .auth-card {
                width: 100%;
                max-width: 420px;
                background: rgba(26, 26, 46, 0.9);
                border: 1px solid rgba(0, 255, 136, 0.2);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5),
                            0 0 40px rgba(0, 255, 136, 0.1);
            }
            
            .auth-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .auth-logo {
                font-size: 3rem;
                margin-bottom: 15px;
            }
            
            .auth-title {
                font-size: 1.8rem;
                font-weight: 700;
                color: #fff;
                margin-bottom: 8px;
            }
            
            .auth-subtitle {
                color: rgba(255, 255, 255, 0.6);
                font-size: 0.9rem;
            }
            
            .auth-form {
                display: flex;
                flex-direction: column;
                gap: 20px;
            }
            
            .auth-input-group {
                position: relative;
            }
            
            .auth-input-group i {
                position: absolute;
                left: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: rgba(255, 255, 255, 0.4);
            }
            
            .auth-input {
                width: 100%;
                padding: 14px 14px 14px 45px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                color: #fff;
                font-size: 1rem;
                transition: all 0.3s;
            }
            
            .auth-input:focus {
                outline: none;
                border-color: #00ff88;
                box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
            }
            
            .auth-input::placeholder {
                color: rgba(255, 255, 255, 0.4);
            }
            
            .auth-btn {
                padding: 14px;
                background: linear-gradient(135deg, #00ff88, #00cc6a);
                border: none;
                border-radius: 10px;
                color: #0a0a0f;
                font-size: 1rem;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .auth-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3);
            }
            
            .auth-btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none;
            }
            
            .auth-divider {
                display: flex;
                align-items: center;
                gap: 15px;
                margin: 20px 0;
                color: rgba(255, 255, 255, 0.4);
                font-size: 0.85rem;
            }
            
            .auth-divider::before,
            .auth-divider::after {
                content: '';
                flex: 1;
                height: 1px;
                background: rgba(255, 255, 255, 0.1);
            }
            
            .auth-switch {
                text-align: center;
                color: rgba(255, 255, 255, 0.6);
            }
            
            .auth-switch a {
                color: #00ff88;
                text-decoration: none;
                font-weight: 600;
            }
            
            .auth-switch a:hover {
                text-decoration: underline;
            }
            
            .auth-error {
                padding: 12px;
                background: rgba(239, 68, 68, 0.2);
                border: 1px solid rgba(239, 68, 68, 0.5);
                border-radius: 8px;
                color: #ff6b6b;
                font-size: 0.9rem;
                display: none;
            }
            
            .auth-error.show {
                display: block;
            }
            
            .auth-back {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: rgba(255, 255, 255, 0.6);
                text-decoration: none;
                font-size: 0.9rem;
                margin-bottom: 20px;
            }
            
            .auth-back:hover {
                color: #00ff88;
            }
        </style>
        
        <div class="auth-card">
            <a href="#" onclick="loadPage('home')" class="auth-back">
                <i class="fa-solid fa-arrow-left"></i>
                ${isArabic ? 'العودة للرئيسية' : 'Back to Home'}
            </a>
            
            <div class="auth-header">
                <div class="auth-logo">🔐</div>
                <h1 class="auth-title">${isArabic ? 'تسجيل الدخول' : 'Welcome Back'}</h1>
                <p class="auth-subtitle">${isArabic ? 'أدخل بياناتك للمتابعة' : 'Enter your credentials to continue'}</p>
            </div>
            
            <form class="auth-form" id="login-form" onsubmit="handleLogin(event)">
                <div class="auth-error" id="login-error"></div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-envelope"></i>
                    <input type="email" class="auth-input" id="login-email" 
                           placeholder="${isArabic ? 'البريد الإلكتروني' : 'Email'}" required>
                </div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" class="auth-input" id="login-password" 
                           placeholder="${isArabic ? 'كلمة المرور' : 'Password'}" required>
                </div>
                
                <div style="text-align: right; margin-top: -5px;">
                    <a href="#" onclick="loadPage('forgot-password')" style="color: #00ff88; font-size: 0.85rem; text-decoration: none;">
                        ${isArabic ? 'نسيت كلمة المرور؟' : 'Forgot password?'}
                    </a>
                </div>
                
                <button type="submit" class="auth-btn" id="login-btn">
                    <span id="login-btn-text">${isArabic ? 'دخول' : 'Login'}</span>
                </button>
            </form>
            
            <div class="auth-divider">${isArabic ? 'أو' : 'OR'}</div>
            
            <p class="auth-switch">
                ${isArabic ? 'ليس لديك حساب؟' : "Don't have an account?"} 
                <a href="#" onclick="loadPage('register')">${isArabic ? 'سجل الآن' : 'Sign up'}</a>
            </p>
        </div>
    </div>
    `;
}

// Handle login form submission
window.handleLogin = async function (event) {
  event.preventDefault();

  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');
  const btnText = document.getElementById('login-btn-text');
  const btn = document.getElementById('login-btn');

  // Show loading
  btn.disabled = true;
  btnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  errorEl.classList.remove('show');

  try {
    const result = await AuthAPI.login(email, password);

    if (result.success) {
      showToast(result.message || txt('تم تسجيل الدخول بنجاح!', 'Login successful!'), 'success');
      setTimeout(() => window.location.reload(), 500);
    } else {
      errorEl.textContent = result.error || txt('فشل تسجيل الدخول', 'Login failed');
      errorEl.classList.add('show');
    }
  } catch (error) {
    errorEl.textContent = txt('حدث خطأ في الاتصال', 'Connection error');
    errorEl.classList.add('show');
  }

  btn.disabled = false;
  btnText.textContent = txt('دخول', 'Login');
};


// ========== REGISTER PAGE ========== */
function pageRegister() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="auth-container">
        <style>
            .auth-container {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
                padding: 20px;
            }
            
            .auth-card {
                width: 100%;
                max-width: 420px;
                background: rgba(26, 26, 46, 0.9);
                border: 1px solid rgba(0, 255, 136, 0.2);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5),
                            0 0 40px rgba(0, 255, 136, 0.1);
            }
            
            .auth-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .auth-logo {
                font-size: 3rem;
                margin-bottom: 15px;
            }
            
            .auth-title {
                font-size: 1.8rem;
                font-weight: 700;
                color: #fff;
                margin-bottom: 8px;
            }
            
            .auth-subtitle {
                color: rgba(255, 255, 255, 0.6);
                font-size: 0.9rem;
            }
            
            .auth-form {
                display: flex;
                flex-direction: column;
                gap: 15px;
            }
            
            .auth-input-group {
                position: relative;
            }
            
            .auth-input-group i {
                position: absolute;
                left: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: rgba(255, 255, 255, 0.4);
            }
            
            .auth-input {
                width: 100%;
                padding: 14px 14px 14px 45px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                color: #fff;
                font-size: 1rem;
                transition: all 0.3s;
            }
            
            .auth-input:focus {
                outline: none;
                border-color: #00ff88;
                box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
            }
            
            .auth-input::placeholder {
                color: rgba(255, 255, 255, 0.4);
            }
            
            .auth-btn {
                padding: 14px;
                background: linear-gradient(135deg, #00ff88, #00cc6a);
                border: none;
                border-radius: 10px;
                color: #0a0a0f;
                font-size: 1rem;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-top: 10px;
            }
            
            .auth-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3);
            }
            
            .auth-btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none;
            }
            
            .auth-row {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }
            
            .auth-divider {
                display: flex;
                align-items: center;
                gap: 15px;
                margin: 15px 0;
                color: rgba(255, 255, 255, 0.4);
                font-size: 0.85rem;
            }
            
            .auth-divider::before,
            .auth-divider::after {
                content: '';
                flex: 1;
                height: 1px;
                background: rgba(255, 255, 255, 0.1);
            }
            
            .auth-switch {
                text-align: center;
                color: rgba(255, 255, 255, 0.6);
            }
            
            .auth-switch a {
                color: #00ff88;
                text-decoration: none;
                font-weight: 600;
            }
            
            .auth-switch a:hover {
                text-decoration: underline;
            }
            
            .auth-error {
                padding: 12px;
                background: rgba(239, 68, 68, 0.2);
                border: 1px solid rgba(239, 68, 68, 0.5);
                border-radius: 8px;
                color: #ff6b6b;
                font-size: 0.9rem;
                display: none;
            }
            
            .auth-error.show {
                display: block;
            }
            
            .auth-back {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: rgba(255, 255, 255, 0.6);
                text-decoration: none;
                font-size: 0.9rem;
                margin-bottom: 20px;
            }
            
            .auth-back:hover {
                color: #00ff88;
            }
            
            .password-hint {
                font-size: 0.75rem;
                color: rgba(255, 255, 255, 0.4);
                margin-top: -10px;
                padding-left: 5px;
            }
        </style>
        
        <div class="auth-card">
            <a href="#" onclick="loadPage('hub')" class="auth-back">
                <i class="fa-solid fa-arrow-left"></i>
                ${isArabic ? 'العودة للرئيسية' : 'Back to Home'}
            </a>
            
            <div class="auth-header">
                <div class="auth-logo">🚀</div>
                <h1 class="auth-title">${isArabic ? 'إنشاء حساب' : 'Create Account'}</h1>
                <p class="auth-subtitle">${isArabic ? 'ابدأ رحلتك في الأمن السيبراني' : 'Start your cybersecurity journey'}</p>
            </div>
            
            <form class="auth-form" id="register-form" onsubmit="handleRegister(event)">
                <div class="auth-error" id="register-error"></div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-user"></i>
                    <input type="text" class="auth-input" id="register-username" 
                           placeholder="${isArabic ? 'اسم المستخدم' : 'Username'}" required minlength="3">
                </div>
                
                <div class="auth-row">
                    <div class="auth-input-group">
                        <i class="fa-solid fa-id-card"></i>
                        <input type="text" class="auth-input" id="register-firstname" 
                               placeholder="${isArabic ? 'الاسم الأول' : 'First Name'}">
                    </div>
                    <div class="auth-input-group">
                        <i class="fa-solid fa-id-card"></i>
                        <input type="text" class="auth-input" id="register-lastname" 
                               placeholder="${isArabic ? 'الاسم الأخير' : 'Last Name'}">
                    </div>
                </div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-envelope"></i>
                    <input type="email" class="auth-input" id="register-email" 
                           placeholder="${isArabic ? 'البريد الإلكتروني' : 'Email'}" required>
                </div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" class="auth-input" id="register-password" 
                           placeholder="${isArabic ? 'كلمة المرور' : 'Password'}" required minlength="8">
                </div>
                <p class="password-hint">${isArabic ? '8 أحرف على الأقل، حرف ورقم' : 'Min 8 chars, include letter & number'}</p>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" class="auth-input" id="register-confirm" 
                           placeholder="${isArabic ? 'تأكيد كلمة المرور' : 'Confirm Password'}" required>
                </div>
                
                <button type="submit" class="auth-btn" id="register-btn">
                    <span id="register-btn-text">${isArabic ? 'إنشاء الحساب' : 'Create Account'}</span>
                </button>
            </form>
            
            <div class="auth-divider">${isArabic ? 'أو' : 'OR'}</div>
            
            <p class="auth-switch">
                ${isArabic ? 'لديك حساب بالفعل؟' : 'Already have an account?'} 
                <a href="#" onclick="loadPage('login')">${isArabic ? 'سجل دخول' : 'Login'}</a>
            </p>
        </div>
    </div>
    `;
}

// Handle register form submission
window.handleRegister = async function (event) {
  event.preventDefault();

  const username = document.getElementById('register-username').value.trim();
  const firstName = document.getElementById('register-firstname').value.trim();
  const lastName = document.getElementById('register-lastname').value.trim();
  const email = document.getElementById('register-email').value.trim();
  const password = document.getElementById('register-password').value;
  const confirm = document.getElementById('register-confirm').value;
  const errorEl = document.getElementById('register-error');
  const btnText = document.getElementById('register-btn-text');
  const btn = document.getElementById('register-btn');

  // Validate passwords match
  if (password !== confirm) {
    errorEl.textContent = txt('كلمتا المرور غير متطابقتين', 'Passwords do not match');
    errorEl.classList.add('show');
    return;
  }

  // Show loading
  btn.disabled = true;
  btnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  errorEl.classList.remove('show');

  try {
    const result = await AuthAPI.register(username, email, password, firstName, lastName);

    if (result.success) {
      showToast(result.message || txt('تم إنشاء الحساب بنجاح!', 'Account created!'), 'success');
      setTimeout(() => window.location.reload(), 500);
    } else {
      errorEl.textContent = result.error || txt('فشل إنشاء الحساب', 'Registration failed');
      errorEl.classList.add('show');
    }
  } catch (error) {
    errorEl.textContent = txt('حدث خطأ في الاتصال', 'Connection error');
    errorEl.classList.add('show');
  }

  btn.disabled = false;
  btnText.textContent = txt('إنشاء الحساب', 'Create Account');
};

/* ========== USER PROFILE PAGE ========== */
function pageProfile() {
  const isLoggedIn = typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn();
  const user = isLoggedIn && AuthState.user ? AuthState.user : null;
  const username = user ? user.username : 'Guest';
  const avatarUrl = user && user.avatar_url
    ? user.avatar_url
    : `https://ui-avatars.com/api/?name=${username}&background=22c55e&color=000&size=200`;

  // Get real stats
  const stats = (typeof getComprehensiveStats === 'function') ? getComprehensiveStats() : {
    xp: 0, level: 1, rank: 'Noob', streak: 0, badges: 0,
    modules: { completed: 0 }, ctfs: { completed: 0 }
  };

  const level = stats.level;
  const xp = stats.xp;
  const streak = stats.streak;
  const rank = stats.rank;
  const badgesCount = stats.badges;
  const completedRoomsCount = stats.modules.completed;
  const globalRank = 'N/A'; // Mock for now

  // Rank colors
  const rankColors = {
    'Noob': '#b0b0b0',
    'Script Kiddie': '#22c55e',
    'Hacker': '#3b82f6',
    'Pro Hacker': '#a855f7',
    'Elite Hacker': '#f59e0b',
    'Guru': '#f97316',
    'Omniscient': '#ef4444',
    'Master': '#000000',
    'Legend': '#00bfff',
    'God Mode': '#ff00ff'
  };
  const rankColor = rankColors[rank] || '#b0b0b0';
  const rankCode = `[LVL ${level}]`;

  // Badges HTML
  const earnedBadges = (typeof getEarnedBadges === 'function') ? getEarnedBadges() : [];
  let badgesHTML = '';
  if (earnedBadges.length === 0) {
    badgesHTML = '<div class="empty-msg"><i class="fa-solid fa-award"></i><p>No badges yet</p></div>';
  } else {
    badgesHTML = earnedBadges.map(b => `
          <div class="badge-item">
            <div class="badge-icon"><i class="${b.icon || 'fa-solid fa-shield-halved'}"></i></div>
            <div class="badge-name">${b.name}</div>
          </div>
      `).join('');
  }

  // Certificates HTML
  const earnedCerts = (typeof getCertificates === 'function') ? getCertificates() : [];
  let certsHTML = '';
  if (earnedCerts.length === 0) {
    certsHTML = '<div class="empty-msg"><i class="fa-solid fa-certificate"></i><p>No certificates yet</p></div>';
  } else {
    certsHTML = earnedCerts.map(c => `
          <div class="room-mini">
            <h4>${c.name}</h4>
            <p>${c.date}</p>
            <span class="completed-tag" style="background: rgba(255,215,0,0.15); color: #ffd700;">🏆 Certificate</span>
          </div>
      `).join('');
  }

  // Completed Rooms HTML (Extract from Progress)
  // We'll iterate through paths and find completed modules
  let roomsHTML = '';
  const fullProgress = (typeof getProgress === 'function') ? getProgress() : {};
  let completedModulesList = [];

  if (fullProgress.paths) {
    Object.keys(fullProgress.paths).forEach(pathId => {
      const path = fullProgress.paths[pathId];
      if (path.modules) {
        Object.keys(path.modules).forEach(modId => {
          if (path.modules[modId].completed) {
            completedModulesList.push({
              name: modId.replace(/-/g, ' ').toUpperCase(), // Simple formatting
              category: pathId.replace(/-/g, ' '),
              date: path.modules[modId].completedAt
            });
          }
        });
      }
    });
  }

  if (completedModulesList.length === 0) {
    roomsHTML = '<div class="empty-msg"><i class="fa-solid fa-door-open"></i><p>No completed rooms yet</p></div>';
  } else {
    roomsHTML = completedModulesList.slice(0, 12).map(m => `
          <div class="room-mini">
            <h4>${m.name}</h4>
            <p>${m.category}</p>
            <span class="completed-tag">✓ Completed</span>
          </div>
      `).join('');
  }

  return `
    <div class="profile-page-v2">
      <style>
        .profile-page-v2 { min-height: 100vh; background: var(--bg-body, #0a0a0f); color: var(--text-primary, #fff); }
        .profile-hero { position: relative; height: 200px; background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460); }
        .profile-hero::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 80px; background: linear-gradient(transparent, var(--bg-body, #0a0a0f)); }
        .profile-header-content { position: relative; max-width: 1100px; margin: -60px auto 0; padding: 0 20px; display: flex; gap: 25px; align-items: flex-start; }
        .profile-avatar-lg { width: 130px; height: 130px; border-radius: 50%; border: 4px solid ${rankColor}; box-shadow: 0 0 25px ${rankColor}66; object-fit: cover; }
        .profile-info { flex: 1; padding-top: 40px; }
        .profile-username { font-size: 1.8rem; font-weight: 700; color: var(--text-primary, #fff); margin: 0 0 8px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .rank-badge { font-family: monospace; font-size: 0.85rem; color: ${rankColor}; background: ${rankColor}15; padding: 4px 12px; border-radius: 6px; border: 1px solid ${rankColor}44; }
        .profile-country { color: var(--text-secondary, rgba(255,255,255,0.6)); font-size: 0.95rem; margin-bottom: 12px; }
        .profile-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        .p-btn { padding: 10px 18px; border-radius: 8px; font-size: 0.9rem; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--border-color, rgba(255,255,255,0.1)); background: var(--bg-secondary, rgba(255,255,255,0.05)); color: var(--text-primary, #fff); }
        .p-btn:hover { background: var(--bg-hover, rgba(255,255,255,0.1)); transform: translateY(-2px); }
        
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; max-width: 1100px; margin: 35px auto; padding: 0 20px; }
        .stat-card { background: var(--bg-card, rgba(255,255,255,0.02)); border: 1px solid var(--border-color, rgba(255,255,255,0.06)); border-radius: 14px; padding: 22px; text-align: center; transition: all 0.3s; }
        .stat-card:hover { transform: translateY(-4px); border-color: rgba(34,197,94,0.3); }
        .stat-card i { font-size: 1.4rem; color: #22c55e; margin-bottom: 10px; }
        .stat-val { font-size: 1.6rem; font-weight: 700; color: var(--text-primary, #fff); }
        .stat-lbl { font-size: 0.8rem; color: var(--text-muted, rgba(255,255,255,0.5)); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
        
        .tabs-container { max-width: 1100px; margin: 35px auto; padding: 0 20px; }
        .tabs-nav { display: flex; gap: 4px; background: var(--bg-secondary, rgba(255,255,255,0.03)); padding: 4px; border-radius: 10px; margin-bottom: 20px; }
        .tab-btn { flex: 1; padding: 12px; border-radius: 8px; background: transparent; border: none; color: var(--text-secondary, rgba(255,255,255,0.6)); font-size: 0.9rem; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .tab-btn:hover { color: var(--text-primary, #fff); background: var(--bg-hover, rgba(255,255,255,0.05)); }
        .tab-btn.active { background: #22c55e; color: #000; }
        .tab-panel { display: none; } .tab-panel.active { display: block; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        .rooms-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 15px; }
        .room-mini { background: var(--bg-card, rgba(255,255,255,0.02)); border: 1px solid var(--border-color, rgba(255,255,255,0.06)); border-radius: 10px; padding: 18px; }
        .room-mini h4 { color: var(--text-primary, #fff); margin: 0 0 6px; font-size: 0.95rem; }
        .room-mini p { color: var(--text-muted, rgba(255,255,255,0.5)); font-size: 0.8rem; margin: 0; }
        .completed-tag { display: inline-block; margin-top: 10px; padding: 4px 10px; background: rgba(34,197,94,0.15); color: #22c55e; font-size: 0.75rem; border-radius: 4px; }
        
        .badges-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 15px; }
        .badge-item { background: var(--bg-card, rgba(255,255,255,0.02)); border: 1px solid var(--border-color, rgba(255,255,255,0.06)); border-radius: 10px; padding: 20px 12px; text-align: center; }
        .badge-item:hover { border-color: rgba(255,215,0,0.3); }
        .badge-icon { width: 50px; height: 50px; background: linear-gradient(135deg, #ffd700, #ff8c00); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; font-size: 1.3rem; color: #fff; text-shadow: 0 2px 4px rgba(0,0,0,0.3); }
        .badge-name { color: var(--text-primary, #fff); font-size: 0.85rem; font-weight: 500; }
        
        .empty-msg { text-align: center; padding: 50px; color: var(--text-muted, rgba(255,255,255,0.4)); }
        .empty-msg i { font-size: 2.5rem; margin-bottom: 12px; opacity: 0.3; }
        
        @media (max-width: 768px) { 
          .profile-header-content { flex-direction: column; align-items: center; text-align: center; }
          .profile-info { padding-top: 15px; }
          .stats-grid { grid-template-columns: repeat(2, 1fr); }
          .tabs-nav { flex-wrap: wrap; } .tab-btn { flex: 1 1 45%; }
        }
      </style>
      
      <div class="profile-hero"></div>
      
      <div class="profile-header-content">
        <img class="profile-avatar-lg" src="${avatarUrl}" alt="${username}">
        <div class="profile-info">
          <h1 class="profile-username">
            ${username} 
            <span class="rank-badge" style="color: ${rankColor}; border-color: ${rankColor}; background: ${rankColor}10;">
                ${rankCode} ${rank.toUpperCase()}
            </span>
          </h1>
          <p class="profile-country"><i class="fa-solid fa-globe"></i> Global</p>
          <div class="profile-actions">
            <button class="p-btn" onclick="loadPage('account')"><i class="fa-solid fa-pen"></i> Edit Profile</button>
            <button class="p-btn" onclick="copyBadgeId()"><i class="fa-solid fa-id-badge"></i> Badge ID</button>
          </div>
        </div>
      </div>
      
      <div class="stats-grid">
        <div class="stat-card"><i class="fa-solid fa-trophy"></i><div class="stat-val">${globalRank}</div><div class="stat-lbl">Rank</div></div>
        <div class="stat-card"><i class="fa-solid fa-medal"></i><div class="stat-val">${badgesCount}</div><div class="stat-lbl">Badges</div></div>
        <div class="stat-card"><i class="fa-solid fa-fire"></i><div class="stat-val">${streak}</div><div class="stat-lbl">Streak</div></div>
        <div class="stat-card"><i class="fa-solid fa-door-open"></i><div class="stat-val">${completedRoomsCount}</div><div class="stat-lbl">Rooms</div></div>
      </div>
      
      <div class="tabs-container">
        <div class="tabs-nav">
          <button class="tab-btn active" onclick="showProfileTab('rooms',this)"><i class="fa-solid fa-door-open"></i> Rooms</button>
          <button class="tab-btn" onclick="showProfileTab('certs',this)"><i class="fa-solid fa-certificate"></i> Certificates</button>
          <button class="tab-btn" onclick="showProfileTab('skills',this)"><i class="fa-solid fa-chart-simple"></i> Skills</button>
          <button class="tab-btn" onclick="showProfileTab('badges',this)"><i class="fa-solid fa-award"></i> Badges</button>
        </div>
        
        <div id="tab-rooms" class="tab-panel active">
          <div class="rooms-grid">
            ${roomsHTML}
          </div>
        </div>
        
        <div id="tab-certs" class="tab-panel">
          <div class="rooms-grid">
            ${certsHTML}
          </div>
        </div>
        
        <div id="tab-skills" class="tab-panel">
          <div class="empty-msg"><i class="fa-solid fa-chart-radar"></i><p>Skills matrix coming soon</p></div>
        </div>
        
        <div id="tab-badges" class="tab-panel">
            <div class="badges-grid">
                ${badgesHTML}
            </div>
        </div>
      </div>
    </div>
  `;
}

function showProfileTab(tabId, btn) {
  document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + tabId).classList.add('active');
}

function copyBadgeId() {
  const id = 'SH-' + Math.random().toString(36).substr(2, 9).toUpperCase();
  navigator.clipboard.writeText(id);
  if (typeof showToast !== 'undefined') showToast('Copied: ' + id, 'success');
}

/* ========== ACCOUNT MANAGEMENT PAGE ========== */
function pageAccount() {
  const isLoggedIn = typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn();
  const user = isLoggedIn && AuthState.user ? AuthState.user : null;
  const username = user ? user.username : 'Guest';
  const email = user ? user.email : '';
  const avatarUrl = user && user.avatar_url
    ? user.avatar_url
    : `https://ui-avatars.com/api/?name=${username}&background=22c55e&color=000&size=200`;

  return `
    <div class="account-page">
      <style>
        .account-page { min-height: 100vh; background: #0a0a0f; display: flex; }
        
        .account-sidebar {
          width: 260px;
          background: rgba(255,255,255,0.02);
          border-right: 1px solid rgba(255,255,255,0.06);
          padding: 30px 0;
          position: sticky;
          top: 0;
          height: 100vh;
        }
        
        .sidebar-header {
          padding: 0 20px 25px;
          border-bottom: 1px solid rgba(255,255,255,0.06);
          margin-bottom: 20px;
        }
        
        .sidebar-header h2 {
          color: #fff;
          font-size: 1.2rem;
          margin: 0;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        
        .sidebar-nav {
          list-style: none;
          padding: 0;
          margin: 0;
        }
        
        .sidebar-item {
          padding: 14px 25px;
          color: rgba(255,255,255,0.6);
          cursor: pointer;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          gap: 12px;
          font-size: 0.95rem;
          border-left: 3px solid transparent;
        }
        
        .sidebar-item:hover {
          background: rgba(255,255,255,0.03);
          color: #fff;
        }
        
        .sidebar-item.active {
          background: rgba(34, 197, 94, 0.1);
          color: #22c55e;
          border-left-color: #22c55e;
        }
        
        .sidebar-item i {
          width: 20px;
          text-align: center;
        }
        
        .account-main {
          flex: 1;
          padding: 40px;
          max-width: 900px;
        }
        
        .account-section {
          display: none;
          animation: fadeIn 0.3s;
        }
        
        .account-section.active {
          display: block;
        }
        
        .section-title {
          font-size: 1.5rem;
          color: #fff;
          margin: 0 0 8px;
          font-weight: 600;
        }
        
        .section-desc {
          color: rgba(255,255,255,0.5);
          margin-bottom: 30px;
        }
        
        .form-card {
          background: rgba(255,255,255,0.02);
          border: 1px solid rgba(255,255,255,0.06);
          border-radius: 14px;
          padding: 25px;
          margin-bottom: 20px;
        }
        
        .form-card h3 {
          color: #fff;
          font-size: 1rem;
          margin: 0 0 20px;
          padding-bottom: 15px;
          border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        
        .form-group {
          margin-bottom: 20px;
        }
        
        .form-group label {
          display: block;
          color: rgba(255,255,255,0.7);
          font-size: 0.9rem;
          margin-bottom: 8px;
        }
        
        .form-group input {
          width: 100%;
          padding: 12px 16px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 8px;
          color: #fff;
          font-size: 0.95rem;
          transition: all 0.2s;
        }
        
        .form-group input:focus {
          outline: none;
          border-color: #22c55e;
          background: rgba(34, 197, 94, 0.05);
        }
        
        .form-group input:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        
        .avatar-upload {
          display: flex;
          align-items: center;
          gap: 20px;
        }
        
        .avatar-preview {
          width: 80px;
          height: 80px;
          border-radius: 50%;
          border: 3px solid #22c55e;
          object-fit: cover;
        }
        
        .upload-btn {
          padding: 10px 20px;
          background: rgba(255,255,255,0.05);
          border: 1px dashed rgba(255,255,255,0.2);
          border-radius: 8px;
          color: rgba(255,255,255,0.7);
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .upload-btn:hover {
          border-color: #22c55e;
          color: #22c55e;
        }
        
        .save-btn {
          padding: 12px 30px;
          background: #22c55e;
          border: none;
          border-radius: 8px;
          color: #000;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .save-btn:hover {
          background: #16a34a;
          transform: translateY(-2px);
        }
        
        /* Danger Zone */
        .danger-zone {
          background: rgba(239, 68, 68, 0.05);
          border: 1px solid rgba(239, 68, 68, 0.2);
          border-radius: 14px;
          padding: 25px;
          margin-top: 30px;
        }
        
        .danger-zone h3 {
          color: #ef4444;
          margin: 0 0 15px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        
        .danger-zone p {
          color: rgba(255,255,255,0.6);
          margin-bottom: 20px;
          font-size: 0.9rem;
        }
        
        .danger-btn {
          padding: 10px 20px;
          background: transparent;
          border: 1px solid #ef4444;
          border-radius: 8px;
          color: #ef4444;
          cursor: pointer;
          transition: all 0.2s;
          margin-right: 10px;
        }
        
        .danger-btn:hover {
          background: #ef4444;
          color: #fff;
        }
        
        @media (max-width: 768px) {
          .account-page { flex-direction: column; }
          .account-sidebar { width: 100%; height: auto; position: relative; }
          .sidebar-nav { display: flex; overflow-x: auto; padding: 0 10px; }
          .sidebar-item { flex-shrink: 0; border-left: none; border-bottom: 3px solid transparent; }
          .sidebar-item.active { border-bottom-color: #22c55e; border-left: none; }
        }
      </style>
      
      <!-- Sidebar -->
      <div class="account-sidebar">
        <div class="sidebar-header">
          <h2><i class="fa-solid fa-gear"></i> Account</h2>
        </div>
        <ul class="sidebar-nav">
          <li class="sidebar-item active" onclick="showAccountSection('profile', this)">
            <i class="fa-solid fa-user"></i> Profile
          </li>
          <li class="sidebar-item" onclick="showAccountSection('account', this)">
            <i class="fa-solid fa-shield-halved"></i> Account
          </li>
          <li class="sidebar-item" onclick="showAccountSection('notifications', this)">
            <i class="fa-solid fa-bell"></i> Notifications
          </li>
          <li class="sidebar-item" onclick="showAccountSection('billing', this)">
            <i class="fa-solid fa-credit-card"></i> Billing
          </li>
          <li class="sidebar-item" onclick="showAccountSection('api', this)">
            <i class="fa-solid fa-key"></i> API / VPN
          </li>
        </ul>
      </div>
      
      <!-- Main Content -->
      <div class="account-main">
        
        <!-- Profile Section -->
        <div id="section-profile" class="account-section active">
          <h1 class="section-title">Profile Settings</h1>
          <p class="section-desc">Update your personal information and avatar</p>
          
          <div class="form-card">
            <h3>Avatar</h3>
            <div class="avatar-upload">
              <img class="avatar-preview" id="acc-avatar-preview" src="${avatarUrl}" alt="${username}">
              <div>
                <input type="file" id="acc-avatar-input" accept="image/*" style="display:none;" onchange="previewAvatar(this)">
                <button class="upload-btn" onclick="document.getElementById('acc-avatar-input').click()">
                  <i class="fa-solid fa-upload"></i> Upload New
                </button>
                <p style="color:rgba(255,255,255,0.4);font-size:0.8rem;margin-top:8px;">JPG or PNG, max 2MB</p>
              </div>
            </div>
          </div>
          
          <div class="form-card">
            <h3>Basic Info</h3>
            <div class="form-group">
              <label>Display Name</label>
              <input type="text" id="acc-display-name" value="${user?.first_name || username}" placeholder="Your display name">
            </div>
            <div class="form-group">
              <label>Bio</label>
              <input type="text" id="acc-bio" value="${user?.bio || ''}" placeholder="Tell us about yourself...">
            </div>
            <div class="form-group">
              <label>Country</label>
              <input type="text" id="acc-country" value="${user?.country || 'Egypt'}" placeholder="Your country">
            </div>
          </div>
          
          <div class="form-card">
            <h3>Social Links</h3>
            <div class="form-group">
              <label><i class="fa-brands fa-twitter"></i> Twitter</label>
              <input type="text" id="acc-twitter" value="${user?.twitter || ''}" placeholder="@username">
            </div>
            <div class="form-group">
              <label><i class="fa-brands fa-github"></i> GitHub</label>
              <input type="text" id="acc-github" value="${user?.github || ''}" placeholder="github.com/username">
            </div>
            <div class="form-group">
              <label><i class="fa-brands fa-linkedin"></i> LinkedIn</label>
              <input type="text" id="acc-linkedin" value="${user?.linkedin || ''}" placeholder="linkedin.com/in/username">
            </div>
          </div>
          
          <button class="save-btn" id="acc-save-profile" onclick="saveProfileChanges()">
            <i class="fa-solid fa-check"></i> Save Changes
          </button>
        </div>
        
        <!-- Account Section -->
        <div id="section-account" class="account-section">
          <h1 class="section-title">Account Settings</h1>
          <p class="section-desc">Manage your account credentials and security</p>
          
          <div class="form-card">
            <h3>Username</h3>
            <div class="form-group">
              <label>Current Username</label>
              <input type="text" value="${username}" disabled>
              <p style="color:rgba(255,255,255,0.4);font-size:0.8rem;margin-top:8px;">Contact support to change username</p>
            </div>
          </div>
          
          <div class="form-card">
            <h3>Email</h3>
            <div class="form-group">
              <label>Email Address</label>
              <input type="email" id="acc-email" value="${email}" placeholder="your@email.com">
            </div>
            <button class="save-btn" onclick="updateEmail()">
              <i class="fa-solid fa-envelope"></i> Update Email
            </button>
          </div>
          
          <div class="form-card">
            <h3>Change Password</h3>
            <div class="form-group">
              <label>Current Password</label>
              <input type="password" id="acc-current-password" placeholder="••••••••">
            </div>
            <div class="form-group">
              <label>New Password</label>
              <input type="password" id="acc-new-password" placeholder="••••••••">
            </div>
            <div class="form-group">
              <label>Confirm New Password</label>
              <input type="password" id="acc-confirm-password" placeholder="••••••••">
            </div>
            <button class="save-btn" onclick="changePassword()">
              <i class="fa-solid fa-key"></i> Update Password
            </button>
          </div>
          
          <!-- Danger Zone -->
          <div class="danger-zone">
            <h3><i class="fa-solid fa-triangle-exclamation"></i> Danger Zone</h3>
            <p>These actions are irreversible. Please be careful.</p>
            <button class="danger-btn" onclick="resetAllProgress()">
              <i class="fa-solid fa-arrow-rotate-left"></i> Reset Progress
            </button>
            <button class="danger-btn" onclick="deleteAccountConfirm()">
              <i class="fa-solid fa-trash"></i> Delete Account
            </button>
          </div>
        </div>
        
        <!-- Notifications Section -->
        <div id="section-notifications" class="account-section">
          <h1 class="section-title">Notifications</h1>
          <p class="section-desc">Manage your email and push notification preferences</p>
          <div class="form-card">
            <h3>Email Notifications</h3>
            <p style="color:rgba(255,255,255,0.5);">Coming soon...</p>
          </div>
        </div>
        
        <!-- Billing Section -->
        <div id="section-billing" class="account-section">
          <h1 class="section-title">Billing</h1>
          <p class="section-desc">Manage your subscription and payment methods</p>
          <div class="form-card">
            <h3>Current Plan</h3>
            <p style="color:#22c55e;font-size:1.2rem;font-weight:600;">Free Plan</p>
            <button class="save-btn" onclick="loadPage('subscribe')" style="margin-top:15px;">
              <i class="fa-solid fa-crown"></i> Upgrade to Premium
            </button>
          </div>
        </div>
        
        <!-- API / VPN Section -->
        <div id="section-api" class="account-section">
          <h1 class="section-title">API / VPN</h1>
          <p class="section-desc">Access your API keys and VPN configuration files</p>
          <div class="form-card">
            <h3>API Key</h3>
            <div class="form-group">
              <input type="text" id="acc-api-key" value="shub_${user?.id ? user.id.toString(36) : 'guest'}_${Date.now().toString(36)}" readonly>
            </div>
            <button class="save-btn" onclick="copyApiKey()">
              <i class="fa-solid fa-copy"></i> Copy Key
            </button>
            <button class="save-btn" style="margin-left:10px;background:#f59e0b;" onclick="regenerateApiKey()">
              <i class="fa-solid fa-refresh"></i> Regenerate
            </button>
          </div>
          <div class="form-card">
            <h3>VPN Configuration</h3>
            <p style="color:rgba(255,255,255,0.5);margin-bottom:15px;">Download your OpenVPN configuration file</p>
            <button class="save-btn" onclick="downloadVpnConfig()">
              <i class="fa-solid fa-download"></i> Download .ovpn
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function showAccountSection(sectionId, btn) {
  document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
  document.querySelectorAll('.account-section').forEach(s => s.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('section-' + sectionId).classList.add('active');
}

// ========== ACCOUNT PAGE HANDLER FUNCTIONS ==========

// Preview avatar before upload
function previewAvatar(input) {
  if (input.files && input.files[0]) {
    const reader = new FileReader();
    reader.onload = function (e) {
      document.getElementById('acc-avatar-preview').src = e.target.result;
    };
    reader.readAsDataURL(input.files[0]);
  }
}

// Save profile changes
async function saveProfileChanges() {
  // Check if logged in
  if (typeof AuthState === 'undefined' || !AuthState.isLoggedIn()) {
    showToast('Please login to save changes', 'error');
    return;
  }

  const btn = document.getElementById('acc-save-profile');
  const originalText = btn.innerHTML;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
  btn.disabled = true;

  try {
    // Backend only supports: first_name, last_name, bio, avatar_url
    const profileData = {
      first_name: document.getElementById('acc-display-name')?.value || '',
      bio: document.getElementById('acc-bio')?.value || ''
    };

    const result = await AuthAPI.updateProfile(profileData);

    if (result.success) {
      // Save extra fields to localStorage (not in backend)
      const extraData = {
        country: document.getElementById('acc-country')?.value || '',
        twitter: document.getElementById('acc-twitter')?.value || '',
        github: document.getElementById('acc-github')?.value || '',
        linkedin: document.getElementById('acc-linkedin')?.value || ''
      };
      localStorage.setItem('userProfileExtra', JSON.stringify(extraData));

      showToast('Profile updated successfully!', 'success');
    } else {
      showToast(result.error || 'Failed to update profile', 'error');
    }
  } catch (error) {
    console.error('Profile save error:', error);
    showToast('Connection error. Please check that backend is running.', 'error');
  }

  btn.innerHTML = originalText;
  btn.disabled = false;
}

// Update email
async function updateEmail() {
  const newEmail = document.getElementById('acc-email')?.value;
  if (!newEmail) {
    showToast('Please enter an email address', 'error');
    return;
  }

  try {
    const result = await AuthAPI.updateProfile({ email: newEmail });
    if (result.success) {
      showToast('Email updated successfully!', 'success');
    } else {
      showToast(result.error || 'Failed to update email', 'error');
    }
  } catch (error) {
    showToast('Connection error. Please try again.', 'error');
  }
}

// Change password
async function changePassword() {
  const currentPassword = document.getElementById('acc-current-password')?.value;
  const newPassword = document.getElementById('acc-new-password')?.value;
  const confirmPassword = document.getElementById('acc-confirm-password')?.value;

  if (!currentPassword || !newPassword || !confirmPassword) {
    showToast('Please fill in all password fields', 'error');
    return;
  }

  if (newPassword !== confirmPassword) {
    showToast('New passwords do not match', 'error');
    return;
  }

  if (newPassword.length < 8) {
    showToast('Password must be at least 8 characters', 'error');
    return;
  }

  try {
    const result = await AuthAPI.changePassword(currentPassword, newPassword);
    if (result.success) {
      showToast('Password changed successfully!', 'success');
      document.getElementById('acc-current-password').value = '';
      document.getElementById('acc-new-password').value = '';
      document.getElementById('acc-confirm-password').value = '';
    } else {
      showToast(result.error || 'Failed to change password', 'error');
    }
  } catch (error) {
    showToast('Connection error. Please try again.', 'error');
  }
}

// Reset all progress
function resetAllProgress() {
  if (!confirm('Are you sure you want to reset ALL your learning progress? This cannot be undone!')) {
    return;
  }

  // Clear all progress-related localStorage items
  const keysToDelete = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && (
      key.startsWith('path_progress_') ||
      key.startsWith('roadmap_progress_') ||
      key.startsWith('module_progress_') ||
      key.startsWith('moduleTask_') ||
      key.startsWith('room_task_') ||
      key.startsWith('completed_')
    )) {
      keysToDelete.push(key);
    }
  }

  keysToDelete.forEach(key => localStorage.removeItem(key));
  showToast(`Progress reset! Cleared ${keysToDelete.length} items.`, 'warning');
}

// Delete account confirmation
function deleteAccountConfirm() {
  const confirmText = prompt('Type "DELETE" to permanently delete your account:');
  if (confirmText !== 'DELETE') {
    showToast('Account deletion cancelled', 'info');
    return;
  }

  // For now, just log out since we don't have a backend delete endpoint
  showToast('Account deletion requested. You will be logged out.', 'warning');
  setTimeout(() => {
    if (typeof AuthAPI !== 'undefined') {
      AuthAPI.logout();
    }
  }, 2000);
}

// Copy API key
function copyApiKey() {
  const apiKeyInput = document.getElementById('acc-api-key');
  if (apiKeyInput) {
    navigator.clipboard.writeText(apiKeyInput.value);
    showToast('API key copied to clipboard!', 'success');
  }
}

// Regenerate API key
function regenerateApiKey() {
  const newKey = 'shub_' + Math.random().toString(36).substr(2, 12) + '_' + Date.now().toString(36);
  const apiKeyInput = document.getElementById('acc-api-key');
  if (apiKeyInput) {
    apiKeyInput.value = newKey;
    showToast('New API key generated!', 'success');
  }
}

// Download VPN config
function downloadVpnConfig() {
  const user = AuthState?.user;
  const username = user?.username || 'user';

  const vpnConfig = `client
dev tun
proto udp
remote vpn.studyhub.local 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert ${username}.crt
key ${username}.key
cipher AES-256-CBC
auth SHA256
verb 3
# Generated for: ${username}
# Date: ${new Date().toISOString()}
`;

  const blob = new Blob([vpnConfig], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `studyhub-${username}.ovpn`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast('VPN config downloaded!', 'success');
}

window.pageAccount = pageAccount;
window.showAccountSection = showAccountSection;
window.previewAvatar = previewAvatar;
window.saveProfileChanges = saveProfileChanges;
window.updateEmail = updateEmail;
window.changePassword = changePassword;
window.resetAllProgress = resetAllProgress;
window.deleteAccountConfirm = deleteAccountConfirm;
window.copyApiKey = copyApiKey;
window.regenerateApiKey = regenerateApiKey;
window.downloadVpnConfig = downloadVpnConfig;


/* ========== SETTINGS PAGE ========== */
function pageSettings() {
  const isArabic = document.documentElement.lang === 'ar';
  const username = localStorage.getItem('username') || 'Guest';
  const userBio = localStorage.getItem('userBio') || '';
  const currentTheme = localStorage.getItem('theme') || 'dark';

  return `
    <div style="min-height:100vh;background:linear-gradient(135deg,#0f0c29,#1a1a3e,#0f0c29);padding:40px 20px;">
      <div style="max-width:800px;margin:0 auto;">
        
        <!-- Header -->
        <div style="text-align:center;margin-bottom:50px;">
          <h1 style="font-size:2.5rem;font-weight:800;color:#fff;font-family:'Orbitron',sans-serif;">
            <i class="fas fa-cog" style="color:#22c55e;"></i>
            ${isArabic ? 'الإعدادات' : 'Settings'}
          </h1>
          <p style="color:rgba(255,255,255,0.6);">${isArabic ? 'خصص تجربتك' : 'Customize your experience'}</p>
        </div>
        
        <!-- Profile Section -->
        <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:30px;margin-bottom:25px;">
          <h3 style="color:#22c55e;margin-bottom:25px;display:flex;align-items:center;gap:10px;">
            <i class="fas fa-user"></i>
            ${isArabic ? 'الملف الشخصي' : 'Profile'}
          </h3>
          
          <div style="display:flex;align-items:center;gap:20px;margin-bottom:25px;">
            <div style="width:80px;height:80px;background:linear-gradient(135deg,#22c55e,#16a34a);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;box-shadow:0 0 30px rgba(34,197,94,0.4);">
              ${username.charAt(0).toUpperCase()}
            </div>
            <div>
              <div style="color:#fff;font-size:1.3rem;font-weight:700;">${username}</div>
              <div style="color:rgba(255,255,255,0.5);font-size:14px;">${isArabic ? 'متعلم' : 'Learner'}</div>
            </div>
          </div>
          
          <div style="margin-bottom:20px;">
            <label style="display:block;color:rgba(255,255,255,0.7);margin-bottom:8px;font-size:14px;">
              ${isArabic ? 'اسم المستخدم' : 'Username'}
            </label>
            <input type="text" id="settings-username" value="${username}" style="width:100%;padding:14px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.2);border-radius:12px;color:#fff;font-size:16px;" readonly>
          </div>
          
          <div>
            <label style="display:block;color:rgba(255,255,255,0.7);margin-bottom:8px;font-size:14px;">
              ${isArabic ? 'النبذة التعريفية' : 'Bio'}
            </label>
            <textarea id="settings-bio" rows="3" style="width:100%;padding:14px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.2);border-radius:12px;color:#fff;font-size:16px;resize:none;">${userBio}</textarea>
          </div>
        </div>
        
        <!-- Appearance Section -->
        <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:30px;margin-bottom:25px;">
          <h3 style="color:#a855f7;margin-bottom:25px;display:flex;align-items:center;gap:10px;">
            <i class="fas fa-palette"></i>
            ${isArabic ? 'المظهر' : 'Appearance'}
          </h3>
          
          <div style="display:flex;justify-content:space-between;align-items:center;padding:15px 0;">
            <div>
              <div style="color:#fff;font-weight:600;">${isArabic ? 'اللغة' : 'Language'}</div>
              <div style="color:rgba(255,255,255,0.5);font-size:13px;">${isArabic ? 'اختر لغة الواجهة' : 'Select interface language'}</div>
            </div>
            <div style="display:flex;gap:10px;">
              <button onclick="if(document.documentElement.lang !== 'ar') toggleLang()" style="padding:10px 20px;border-radius:10px;border:none;cursor:pointer;font-weight:600;${isArabic ? 'background:#22c55e;color:#000;' : 'background:rgba(255,255,255,0.1);color:#fff;'}">العربية</button>
              <button onclick="if(document.documentElement.lang !== 'en') toggleLang()" style="padding:10px 20px;border-radius:10px;border:none;cursor:pointer;font-weight:600;${!isArabic ? 'background:#22c55e;color:#000;' : 'background:rgba(255,255,255,0.1);color:#fff;'}">English</button>
            </div>
          </div>
        </div>
        
        <!-- Security Section -->
        <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:30px;margin-bottom:25px;">
          <h3 style="color:#f59e0b;margin-bottom:25px;display:flex;align-items:center;gap:10px;">
            <i class="fas fa-shield-alt"></i>
            ${isArabic ? 'الأمان' : 'Security'}
          </h3>
          
          <div style="margin-bottom:20px;">
            <label style="display:block;color:rgba(255,255,255,0.7);margin-bottom:8px;font-size:14px;">
              ${isArabic ? 'كلمة المرور الجديدة' : 'New Password'}
            </label>
            <input type="password" id="settings-new-password" placeholder="${isArabic ? '••••••••' : '••••••••'}" style="width:100%;padding:14px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.2);border-radius:12px;color:#fff;font-size:16px;">
          </div>
          
          <div>
            <label style="display:block;color:rgba(255,255,255,0.7);margin-bottom:8px;font-size:14px;">
              ${isArabic ? 'تأكيد كلمة المرور' : 'Confirm Password'}
            </label>
            <input type="password" id="settings-confirm-password" placeholder="${isArabic ? '••••••••' : '••••••••'}" style="width:100%;padding:14px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.2);border-radius:12px;color:#fff;font-size:16px;">
          </div>
        </div>
        
        <!-- Action Buttons -->
        <div style="display:flex;gap:15px;flex-wrap:wrap;">
          <button onclick="saveSettings()" style="flex:1;min-width:200px;padding:16px;background:linear-gradient(135deg,#22c55e,#16a34a);border:none;border-radius:14px;color:#000;font-weight:700;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:10px;">
            <i class="fas fa-save"></i>
            ${isArabic ? 'حفظ التغييرات' : 'Save Changes'}
          </button>
          
          <button onclick="if(confirm('${isArabic ? 'هل تريد تسجيل الخروج؟' : 'Are you sure you want to logout?'}')) { if(typeof AuthAPI !== 'undefined') AuthAPI.logout(); else { localStorage.clear(); sessionStorage.clear(); location.reload(); } }" style="flex:1;min-width:200px;padding:16px;background:linear-gradient(135deg,#ef4444,#dc2626);border:none;border-radius:14px;color:#fff;font-weight:700;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:10px;">
            <i class="fas fa-sign-out-alt"></i>
            ${isArabic ? 'تسجيل الخروج' : 'Logout'}
          </button>
        </div>
        
      </div>
    </div>
  `;
}

// Save settings helper
function saveSettings() {
  const bio = document.getElementById('settings-bio')?.value || '';
  localStorage.setItem('userBio', bio);

  const newPass = document.getElementById('settings-new-password')?.value;
  const confirmPass = document.getElementById('settings-confirm-password')?.value;

  if (newPass && newPass !== confirmPass) {
    alert(document.documentElement.lang === 'ar' ? 'كلمات المرور غير متطابقة' : 'Passwords do not match');
    return;
  }

  if (typeof showNotification === 'function') {
    showNotification(document.documentElement.lang === 'ar' ? 'تم حفظ الإعدادات!' : 'Settings saved!', 'success');
  } else {
    alert(document.documentElement.lang === 'ar' ? 'تم حفظ الإعدادات!' : 'Settings saved!');
  }
}

/* ========== CERTIFICATES PAGE ========== */
function pageCertificates() {
  // Fetch certificates on page load
  setTimeout(() => {
    loadUserCertificates();
  }, 100);

  return `
    <div class="certs-page">
        <style>
            .certs-page { padding: 60px 20px; max-width: 1200px; margin: 0 auto; color: #fff; min-height: 80vh; }
            .certs-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
            .certs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 30px; margin-top: 40px; }
            .cert-card { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 2px solid #ffd700; padding: 25px; border-radius: 15px; position: relative; cursor: pointer; transition: all 0.3s; box-shadow: 0 10px 40px rgba(255, 215, 0, 0.1); }
            .cert-card:hover { transform: translateY(-8px); box-shadow: 0 20px 60px rgba(255, 215, 0, 0.2); }
            .cert-badge { position: absolute; top: -15px; right: 20px; background: linear-gradient(135deg, #ffd700, #ffA500); color: #000; padding: 8px 15px; border-radius: 20px; font-weight: 700; font-size: 0.8rem; }
            .cert-icon { font-size: 3.5rem; color: #ffd700; margin-bottom: 15px; text-align: center; text-shadow: 0 0 30px rgba(255, 215, 0, 0.5); }
            .cert-title { font-weight: 700; font-size: 1.3rem; margin-bottom: 8px; color: #fff; text-align: center; }
            .cert-title-ar { font-size: 1rem; color: rgba(255,255,255,0.7); text-align: center; margin-bottom: 15px; }
            .cert-meta { display: flex; justify-content: space-between; margin-bottom: 20px; padding: 10px 0; border-top: 1px solid rgba(255,255,255,0.1); border-bottom: 1px solid rgba(255,255,255,0.1); }
            .cert-meta-item { text-align: center; }
            .cert-meta-label { font-size: 0.7rem; color: rgba(255,255,255,0.5); text-transform: uppercase; }
            .cert-meta-value { font-size: 0.95rem; color: #ffd700; font-weight: 600; }
            .cert-actions { display: flex; gap: 10px; }
            .cert-btn { flex: 1; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.3s; display: flex; align-items: center; justify-content: center; gap: 8px; }
            .cert-btn-download { background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; }
            .cert-btn-download:hover { transform: scale(1.02); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
            .cert-btn-verify { background: transparent; border: 1px solid rgba(255,255,255,0.3); color: #fff; }
            .cert-btn-verify:hover { background: rgba(255,255,255,0.1); }
            .empty-state { text-align: center; padding: 80px 40px; background: rgba(255,255,255,0.02); border-radius: 20px; border: 1px dashed rgba(255,255,255,0.1); }
            .empty-icon { font-size: 5rem; margin-bottom: 20px; opacity: 0.3; }
            .empty-title { font-size: 1.5rem; margin-bottom: 10px; color: rgba(255,255,255,0.7); }
            .empty-text { color: rgba(255,255,255,0.4); margin-bottom: 25px; }
            .loading-state { text-align: center; padding: 60px; }
            .loading-spinner { width: 50px; height: 50px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #ffd700; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
            @keyframes spin { to { transform: rotate(360deg); } }
        </style>
        
        <div class="certs-header">
            <h1>🎓 ${txt('شهاداتي', 'My Certificates')}</h1>
        </div>
        
        <div id="certs-container" class="certs-grid">
            <div class="loading-state">
                <div class="loading-spinner"></div>
                <p>${txt('جاري التحميل...', 'Loading certificates...')}</p>
            </div>
        </div>
    </div>
    `;
}

// Load user certificates from API
async function loadUserCertificates() {
  const container = document.getElementById('certs-container');
  if (!container) return;

  const user = JSON.parse(sessionStorage.getItem('auth_user') || '{}');
  const userId = user.id || 1;

  try {
    const response = await fetch(`http://localhost:5000/api/certificate/user/${userId}`);
    const data = await response.json();

    if (data.success && data.certificates && data.certificates.length > 0) {
      container.innerHTML = data.certificates.map(cert => `
        <div class="cert-card">
          <div class="cert-badge">✓ VERIFIED</div>
          <div class="cert-icon"><i class="fas fa-award"></i></div>
          <div class="cert-title">${cert.path_name || 'Certificate'}</div>
          ${cert.path_name_ar ? `<div class="cert-title-ar">${cert.path_name_ar}</div>` : ''}
          <div class="cert-meta">
            <div class="cert-meta-item">
              <div class="cert-meta-label">Issued</div>
              <div class="cert-meta-value">${new Date(cert.issued_at).toLocaleDateString()}</div>
            </div>
            <div class="cert-meta-item">
              <div class="cert-meta-label">Score</div>
              <div class="cert-meta-value">${cert.final_score || 100}%</div>
            </div>
            <div class="cert-meta-item">
              <div class="cert-meta-label">Code</div>
              <div class="cert-meta-value">${cert.verify_code.slice(-8)}</div>
            </div>
          </div>
          <div class="cert-actions">
            <button class="cert-btn cert-btn-download" onclick="downloadCertificate('${cert.verify_code}')">
              <i class="fas fa-download"></i> Download PDF
            </button>
            <button class="cert-btn cert-btn-verify" onclick="verifyCertificate('${cert.verify_code}')">
              <i class="fas fa-qrcode"></i>
            </button>
          </div>
        </div>
      `).join('');
    } else {
      container.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="empty-icon">📜</div>
          <div class="empty-title">No Certificates Yet</div>
          <div class="empty-text">Complete a learning path to earn your first certificate</div>
          <button class="cert-btn cert-btn-download" onclick="loadPage('domains')" style="display: inline-flex; width: auto; padding: 15px 30px;">
            <i class="fas fa-rocket"></i> Start Learning
          </button>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading certificates:', error);
    container.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-icon">⚠️</div>
        <div class="empty-title">Loading Error</div>
        <div class="empty-text">${error.message}</div>
      </div>
    `;
  }
}

// Download certificate PDF
function downloadCertificate(code) {
  const downloadUrl = `http://localhost:5000/api/certificate/download/${code}`;
  window.open(downloadUrl, '_blank');
  if (typeof showToast === 'function') {
    showToast('Downloading certificate...', 'info');
  }
}

// Verify certificate (show QR modal)
function verifyCertificate(code) {
  const verifyUrl = `https://studyhub.com/verify/${code}`;
  if (typeof showToast === 'function') {
    showToast(`Verify URL: ${verifyUrl}`, 'info');
  }
  // Copy to clipboard
  navigator.clipboard.writeText(verifyUrl).then(() => {
    if (typeof showToast === 'function') {
      showToast('Verify URL copied!', 'success');
    }
  });
}


/* ========== LEADERBOARD PAGE ========== */
function pageLeaderboard() {
  return `
      < div class= "leaderboard-page" >
         <style>
            .leaderboard-page { padding: 60px 20px; max-width: 1000px; margin: 0 auto; color: #fff; }
            .lb-table { width: 100%; border-collapse: collapse; margin-top: 30px; background: rgba(255,255,255,0.05); border-radius: 15px; overflow: hidden; }
            .lb-table th { background: rgba(102,126,234,0.2); padding: 20px; text-align: left; font-weight: 600; color: #667eea; }
            .lb-table td { padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.05); }
            .lb-rank { font-weight: 700; width: 60px; text-align: center; }
            .lb-user { display: flex; align-items: center; gap: 10px; font-weight: 500; }
            .lb-avatar { width: 35px; height: 35px; border-radius: 50%; background: #333; display: flex; align-items: center; justify-content: center; }
            .lb-points { font-weight: 700; color: #22c55e; text-align: right; }
            
            .rank-1 .lb-rank { color: #ffd700; font-size: 1.2rem; }
            .rank-2 .lb-rank { color: #c0c0c0; font-size: 1.2rem; }
            .rank-3 .lb-rank { color: #cd7f32; font-size: 1.2rem; }
         </style>
         
         <h1>🏆 ${txt('لوحة المتصدرين', 'Leaderboard')}</h1>
         <p>${txt('أفضل 10 متسللين هذا الأسبوع', 'Top 10 hackers this week')}</p>
         
         <table class="lb-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>${txt('المستخدم', 'User')}</th>
                    <th>Rank</th>
                    <th style="text-align:right">${txt('النقاط', 'Points')}</th>
                </tr>
            </thead>
            <tbody>
                <tr class="rank-1">
                    <td class="lb-rank">1</td>
                    <td class="lb-user"><div class="lb-avatar">👾</div> CyberNinja</td>
                    <td>Elite Hacker</td>
                    <td class="lb-points">15,420</td>
                </tr>
                <tr class="rank-2">
                    <td class="lb-rank">2</td>
                    <td class="lb-user"><div class="lb-avatar">🐱</div> MrRobot</td>
                    <td>Senior Pentester</td>
                    <td class="lb-points">12,150</td>
                </tr>
                 <tr class="rank-3">
                    <td class="lb-rank">3</td>
                    <td class="lb-user"><div class="lb-avatar">🦊</div> ZeroDay</td>
                    <td>Security Analyst</td>
                    <td class="lb-points">9,800</td>
                </tr>
                 <tr>
                    <td class="lb-rank">4</td>
                    <td class="lb-user"><div class="lb-avatar">👨‍💻</div> ${localStorage.getItem('username') || 'You'}</td>
                    <td>Script Kiddie</td>
                    <td class="lb-points">${localStorage.getItem('userPoints') || 0}</td>
                </tr>
            </tbody>
         </table>
    </div >
      `;
}

/* ========== FORGOT PASSWORD PAGE ========== */
function pageForgotPassword() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="auth-container">
        <style>
            .auth-container {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
                padding: 20px;
            }
            .auth-card {
                width: 100%;
                max-width: 420px;
                background: rgba(26, 26, 46, 0.9);
                border: 1px solid rgba(0, 255, 136, 0.2);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            }
            .auth-header { text-align: center; margin-bottom: 30px; }
            .auth-logo { font-size: 3rem; margin-bottom: 15px; }
            .auth-title { font-size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 8px; }
            .auth-subtitle { color: rgba(255, 255, 255, 0.6); font-size: 0.9rem; }
            .auth-form { display: flex; flex-direction: column; gap: 15px; }
            .auth-input-group { position: relative; }
            .auth-input-group i { position: absolute; left: 15px; top: 50%; transform: translateY(-50%); color: rgba(255, 255, 255, 0.4); }
            .auth-input { width: 100%; padding: 14px 14px 14px 45px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; color: #fff; font-size: 1rem; transition: all 0.3s; }
            .auth-input:focus { outline: none; border-color: #00ff88; box-shadow: 0 0 20px rgba(0, 255, 136, 0.2); }
            .auth-btn { padding: 14px; background: linear-gradient(135deg, #00ff88, #00cc6a); border: none; border-radius: 10px; color: #0a0a0f; font-size: 1rem; font-weight: 700; cursor: pointer; transition: all 0.3s; text-transform: uppercase; letter-spacing: 1px; margin-top: 10px; }
            .auth-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3); }
            .auth-btn:disabled { opacity: 0.5; cursor: not-allowed; }
            .auth-back { display: inline-flex; align-items: center; gap: 8px; color: rgba(255, 255, 255, 0.6); text-decoration: none; font-size: 0.9rem; margin-bottom: 20px; }
            .auth-back:hover { color: #00ff88; }
            .auth-error, .auth-success { padding: 12px; border-radius: 8px; font-size: 0.9rem; display: none; }
            .auth-error { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #ff6b6b; }
            .auth-success { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.5); color: #22c55e; }
            .auth-error.show, .auth-success.show { display: block; }
            .auth-switch { text-align: center; color: rgba(255, 255, 255, 0.6); margin-top: 20px; }
            .auth-switch a { color: #00ff88; text-decoration: none; font-weight: 600; }
        </style>
        
        <div class="auth-card">
            <a href="#" onclick="loadPage('login')" class="auth-back">
                <i class="fa-solid fa-arrow-left"></i>
                ${isArabic ? 'العودة لتسجيل الدخول' : 'Back to Login'}
            </a>
            
            <div class="auth-header">
                <div class="auth-logo">🔑</div>
                <h1 class="auth-title">${isArabic ? 'استعادة كلمة المرور' : 'Reset Password'}</h1>
                <p class="auth-subtitle">${isArabic ? 'أدخل بريدك الإلكتروني وسنرسل لك رابط إعادة التعيين' : 'Enter your email and we\'ll send you a reset link'}</p>
            </div>
            
            <form class="auth-form" id="forgot-form" onsubmit="handleForgotPassword(event)">
                <div class="auth-error" id="forgot-error"></div>
                <div class="auth-success" id="forgot-success"></div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-envelope"></i>
                    <input type="email" class="auth-input" id="forgot-email" 
                           placeholder="${isArabic ? 'البريد الإلكتروني' : 'Email'}" required>
                </div>
                
                <button type="submit" class="auth-btn" id="forgot-btn">
                    <span id="forgot-btn-text">${isArabic ? 'إرسال رابط الاستعادة' : 'Send Reset Link'}</span>
                </button>
            </form>
            
            <p class="auth-switch">
                ${isArabic ? 'تذكرت كلمة المرور؟' : 'Remember your password?'} 
                <a href="#" onclick="loadPage('login')">${isArabic ? 'سجل دخول' : 'Login'}</a>
            </p>
        </div>
    </div>
    `;
}

// Handle forgot password form
window.handleForgotPassword = async function (event) {
  event.preventDefault();

  const email = document.getElementById('forgot-email').value.trim();
  const errorEl = document.getElementById('forgot-error');
  const successEl = document.getElementById('forgot-success');
  const btnText = document.getElementById('forgot-btn-text');
  const btn = document.getElementById('forgot-btn');
  const isArabic = document.documentElement.lang === 'ar';

  btn.disabled = true;
  btnText.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  errorEl.classList.remove('show');
  successEl.classList.remove('show');

  try {
    // Call API to send reset email
    const response = await fetch('http://localhost:5000/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await response.json();

    if (data.success) {
      successEl.textContent = isArabic
        ? 'تم إرسال رابط إعادة التعيين إلى بريدك الإلكتروني!'
        : 'Password reset link has been sent to your email!';
      successEl.classList.add('show');
      document.getElementById('forgot-email').value = '';
    } else {
      errorEl.textContent = data.error || (isArabic ? 'حدث خطأ' : 'An error occurred');
      errorEl.classList.add('show');
    }
  } catch (error) {
    // For demo: show success anyway
    successEl.textContent = isArabic
      ? 'إذا كان البريد مسجلاً، سيصلك رابط إعادة التعيين خلال دقائق.'
      : 'If that email is registered, you\'ll receive a reset link shortly.';
    successEl.classList.add('show');
  }

  btn.disabled = false;
  btnText.textContent = isArabic ? 'إرسال رابط الاستعادة' : 'Send Reset Link';
};

/* ========== RESET PASSWORD PAGE ========== */
function pageResetPassword() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="auth-container">
        <style>
            .auth-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%); padding: 20px; }
            .auth-card { width: 100%; max-width: 420px; background: rgba(26, 26, 46, 0.9); border: 1px solid rgba(0, 255, 136, 0.2); border-radius: 20px; padding: 40px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5); }
            .auth-header { text-align: center; margin-bottom: 30px; }
            .auth-logo { font-size: 3rem; margin-bottom: 15px; }
            .auth-title { font-size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 8px; }
            .auth-subtitle { color: rgba(255, 255, 255, 0.6); font-size: 0.9rem; }
            .auth-form { display: flex; flex-direction: column; gap: 15px; }
            .auth-input-group { position: relative; }
            .auth-input-group i { position: absolute; left: 15px; top: 50%; transform: translateY(-50%); color: rgba(255, 255, 255, 0.4); }
            .auth-input { width: 100%; padding: 14px 14px 14px 45px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; color: #fff; font-size: 1rem; }
            .auth-input:focus { outline: none; border-color: #00ff88; }
            .auth-btn { padding: 14px; background: linear-gradient(135deg, #00ff88, #00cc6a); border: none; border-radius: 10px; color: #0a0a0f; font-size: 1rem; font-weight: 700; cursor: pointer; text-transform: uppercase; margin-top: 10px; }
            .auth-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3); }
            .auth-error, .auth-success { padding: 12px; border-radius: 8px; font-size: 0.9rem; display: none; }
            .auth-error { background: rgba(239, 68, 68, 0.2); color: #ff6b6b; }
            .auth-success { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
            .auth-error.show, .auth-success.show { display: block; }
        </style>
        
        <div class="auth-card">
            <div class="auth-header">
                <div class="auth-logo">🔒</div>
                <h1 class="auth-title">${isArabic ? 'كلمة مرور جديدة' : 'New Password'}</h1>
                <p class="auth-subtitle">${isArabic ? 'أدخل كلمة المرور الجديدة' : 'Enter your new password'}</p>
            </div>
            
            <form class="auth-form" id="reset-form" onsubmit="handleResetPassword(event)">
                <div class="auth-error" id="reset-error"></div>
                <div class="auth-success" id="reset-success"></div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" class="auth-input" id="reset-password" 
                           placeholder="${isArabic ? 'كلمة المرور الجديدة' : 'New Password'}" required minlength="8">
                </div>
                
                <div class="auth-input-group">
                    <i class="fa-solid fa-lock"></i>
                    <input type="password" class="auth-input" id="reset-confirm" 
                           placeholder="${isArabic ? 'تأكيد كلمة المرور' : 'Confirm Password'}" required>
                </div>
                
                <button type="submit" class="auth-btn" id="reset-btn">
                    <span id="reset-btn-text">${isArabic ? 'تغيير كلمة المرور' : 'Reset Password'}</span>
                </button>
            </form>
        </div>
    </div>
    `;
}

// Handle reset password form
window.handleResetPassword = async function (event) {
  event.preventDefault();

  const password = document.getElementById('reset-password').value;
  const confirm = document.getElementById('reset-confirm').value;
  const errorEl = document.getElementById('reset-error');
  const successEl = document.getElementById('reset-success');
  const isArabic = document.documentElement.lang === 'ar';

  if (password !== confirm) {
    errorEl.textContent = isArabic ? 'كلمتا المرور غير متطابقتين' : 'Passwords do not match';
    errorEl.classList.add('show');
    return;
  }

  successEl.textContent = isArabic ? 'تم تغيير كلمة المرور بنجاح!' : 'Password changed successfully!';
  successEl.classList.add('show');
  errorEl.classList.remove('show');

  setTimeout(() => loadPage('login'), 2000);
};

// Export new pages
window.pageForgotPassword = pageForgotPassword;
window.pageResetPassword = pageResetPassword;

/* ========== SUBSCRIPTION PAGE ========== */
function pageSubscribe() {
  // If SubscriptionSystem is not loaded, show unavailable
  if (typeof SubscriptionSystem === 'undefined') {
    return '<div style="padding:50px;text-align:center;"><h2>Subscription System Loading...</h2></div>';
  }

  const tiers = SubscriptionSystem.tiers;

  return `
        <div class="subscription-page">
            <style>
                .subscription-page { min-height: 100vh; background: #0a0a0f; padding: 60px 20px; }
                .pricing-container { max-width: 1200px; margin: 0 auto; }
                .pricing-container h1 { font-size: 3rem; font-weight: 800; color: #fff; margin-bottom: 10px; }
                .pricing-container p { color: rgba(255,255,255,0.6); font-size: 1.2rem; margin-bottom: 40px; }
                
                .pricing-grid {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                  gap: 30px;
                }
                
                .pricing-card {
                  background: rgba(255, 255, 255, 0.03);
                  border: 1px solid rgba(255, 255, 255, 0.1);
                  border-radius: 20px;
                  padding: 40px;
                  position: relative;
                  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                
                .pricing-card:hover {
                  transform: translateY(-10px);
                  border-color: var(--card-color, rgba(255, 255, 255, 0.2));
                  box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                }
                
                .pricing-card.popular {
                  border-color: #22c55e;
                  background: linear-gradient(180deg, rgba(34, 197, 94, 0.05) 0%, rgba(255,255,255,0.02) 100%);
                }
                
                .popular-badge {
                  position: absolute;
                  top: -15px;
                  left: 50%;
                  transform: translateX(-50%);
                  background: linear-gradient(135deg, #22c55e, #16a34a);
                  color: #fff;
                  padding: 8px 24px;
                  border-radius: 20px;
                  font-size: 14px;
                  font-weight: 700;
                  text-transform: uppercase;
                  letter-spacing: 1px;
                  box-shadow: 0 5px 15px rgba(34, 197, 94, 0.4);
                }
                
                .pricing-icon {
                  width: 60px;
                  height: 60px;
                  border-radius: 16px;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  font-size: 28px;
                  margin-bottom: 25px;
                }
                
                .pricing-name { font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 8px; }
                
                .pricing-price { margin-bottom: 30px; }
                .pricing-amount { font-size: 42px; font-weight: 800; color: #fff; }
                .pricing-period { color: rgba(255, 255, 255, 0.5); font-size: 16px; }
                
                .pricing-features { list-style: none; padding: 0; margin: 0 0 30px 0; }
                .pricing-features li { display: flex; align-items: center; gap: 12px; padding: 12px 0; color: rgba(255, 255, 255, 0.8); font-size: 15px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
                .pricing-features li:last-child { border-bottom: none; }
                .pricing-features li i { font-size: 16px; min-width: 20px; }
                .pricing-features li i.fa-check { color: #22c55e; }
                .pricing-features li i.fa-xmark { color: #ef4444; opacity: 0.5; }
                .pricing-features li.disabled { color: rgba(255, 255, 255, 0.3); }
                
                .pricing-btn {
                  width: 100%;
                  padding: 16px 24px;
                  border-radius: 12px;
                  font-size: 16px;
                  font-weight: 700;
                  cursor: pointer;
                  transition: all 0.3s;
                  text-transform: uppercase;
                  letter-spacing: 1px;
                }
                
                .pricing-btn.primary { background: linear-gradient(135deg, #22c55e, #16a34a); color: #fff; border: none; }
                .pricing-btn.primary:hover { transform: scale(1.02); box-shadow: 0 10px 30px rgba(34, 197, 94, 0.4); }
                .pricing-btn.secondary { background: transparent; color: #fff; border: 2px solid rgba(255, 255, 255, 0.2); }
                .pricing-btn.secondary:hover { border-color: rgba(255, 255, 255, 0.4); background: rgba(255, 255, 255, 0.05); }
            </style>
            
            <div class="pricing-container">
                <div class="text-center mb-5">
                   <h1>Upgrade Your Arsenal</h1>
                   <p>Unlock professional tools, unlimited labs, and premium paths</p>
                </div>
                
                <div class="pricing-grid">
                  ${Object.entries(tiers).map(([key, tier]) => `
                    <div class="pricing-card ${tier.popular ? 'popular' : ''}" style="--card-color: ${tier.color}">
                      ${tier.popular ? '<div class="popular-badge">Most Popular</div>' : ''}
                      
                      <div class="pricing-icon" style="background: ${tier.color}20; color: ${tier.color}">
                        <i class="fas ${tier.icon}"></i>
                      </div>
                      
                      <div class="pricing-name">${tier.name}</div>
                      
                      <div class="pricing-price">
                        <span class="pricing-amount">
                          ${typeof tier.priceMonthly === 'number' ? '$' + tier.priceMonthly : tier.priceMonthly}
                        </span>
                        ${typeof tier.priceMonthly === 'number' ? '<span class="pricing-period">/month</span>' : ''}
                      </div>
                      
                      <ul class="pricing-features">
                        ${tier.features.map(f => `
                          <li class="${!f.included ? 'disabled' : ''}">
                            <i class="fas ${f.included ? 'fa-check' : 'fa-xmark'}"></i>
                            ${f.text}
                          </li>
                        `).join('')}
                      </ul>
                      
                      <button class="pricing-btn ${key === 'premium' ? 'primary' : 'secondary'}"
                        onclick="SubscriptionSystem.handleUpgrade('${key}')">
                        ${key === 'free' ? 'Current Plan' : key === 'enterprise' ? 'Contact Sales' : 'Upgrade Now'}
                      </button>
                    </div>
                  `).join('')}
                </div>
            </div>
        </div>
    `;
}
window.pageSubscribe = pageSubscribe;
