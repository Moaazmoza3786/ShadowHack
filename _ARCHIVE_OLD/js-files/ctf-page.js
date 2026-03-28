/* ==================== CTF CHALLENGES PAGE ==================== */
/* High-Fidelity Design Re-implementation */

function pageCTF() {
  const challenges = typeof getAllCTFChallenges === 'function' ? getAllCTFChallenges() : [];

  // Group by tier
  const tiers = {
    1: challenges.filter(c => c.tier === 1),
    2: challenges.filter(c => c.tier === 2),
    3: challenges.filter(c => c.tier === 3),
    4: challenges.filter(c => c.tier === 4),
    5: challenges.filter(c => c.tier === 5)
  };

  const tierNames = {
    1: 'Ground Zero',
    2: 'Escape Velocity',
    3: 'Orbit',
    4: 'Deep Space',
    5: 'Singularity'
  };

  return `
    <div class="ctf-page fade-in">
      <div class="ctf-header">
        <h1 class="ctf-title" style="font-family: 'Orbitron', sans-serif; letter-spacing: 4px;">CTF GALAXY</h1>
        <p class="ctf-subtitle">Progress through the tiers. Capture flags to ascend.</p>
      </div>

      <div class="ctf-galaxy-container">
        <div class="scanline"></div>
        <div class="ctf-galaxy-map">
          ${[5, 4, 3, 2, 1].map(t => `
            <div class="tier-hub-wrapper tier-${t}-wrapper">
              
              <!-- THE CENTRAL HUB -->
              <div class="tier-hub-node tier-${t}">
                 <div class="hub-glitch-circle"></div>
                 <div class="hub-content">
                    <span class="hub-lvl">LVL ${t}</span>
                    <span class="hub-name">${tierNames[t]}</span>
                 </div>
              </div>

              <!-- SATELLITE CHALLENGES -->
              <div class="satellites-grid">
                ${tiers[t].map(ctf => `
                  <div class="satellite-node tier-${t}" onclick="loadPage('ctf-challenge', '${ctf.id}')">
                    <div class="satellite-icon"><i class="${getCategoryIconClass(ctf.category)}"></i></div>
                    <div class="satellite-info">
                      <div class="sat-title">${ctf.title}</div>
                      <div class="sat-meta">${ctf.points} PTS</div>
                    </div>
                  </div>
                `).join('')}
              </div>

            </div>
          `).join('')}
        </div>
      </div>

      <!-- SIDE DASHBOARD -->
      <div class="ctf-side-dash">
        <div class="bloodlust-container">
          <div style="font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; color: #ef4444;">
            <i class="fas fa-skull"></i> WORLD BLOODLUST: 45%
          </div>
          <div class="blood-bar"><div class="blood-fill"></div></div>
        </div>

        <div class="live-feed-v2">
          <div style="font-family: 'Orbitron', sans-serif; font-size: 0.7rem; color: var(--neon-cyan); margin-bottom: 10px;">
            LIVE_FEED_TERMINAL
          </div>
          <div class="feed-item-v2">Operative_X captured [Hidden Sauce]</div>
          <div class="feed-item-v2">Rogue_One captured [Base Jump]</div>
          <div class="feed-item-v2">Ghost_User captured [Eternal Shadow]</div>
        </div>
      </div>
    </div>
  `;
}

/**
 * Challenge Detail Page (The Room)
 */
function pageCTFChallenge(id) {
  const challenges = typeof getAllCTFChallenges === 'function' ? getAllCTFChallenges() : [];
  const ctf = challenges.find(c => c.id === id);

  if (!ctf) {
    return `<div class="p-5 text-center"><h2>Challenge not found.</h2><button class="btn btn-primary" onclick="loadPage('ctf')">Back to Galaxy</button></div>`;
  }

  // Get image based on ID
  const images = {
    'ctf-hidden-sauce': 'https://i.ibb.co/hR0Z0zY/ctf-hidden-sauce.png', // Placeholder or generated
    'ctf-base-jump': 'https://i.ibb.co/6P0S0nY/ctf-base-jump.png',
    'ctf-eternal-shadow': 'https://i.ibb.co/0n0S0nY/ctf-eternal-shadow.png'
  };

  const coverImg = images[id] || 'https://via.placeholder.com/800x400/0a0a1a/00f3ff?text=' + encodeURIComponent(ctf.title);

  return `
    <div class="ctf-room-container fade-in">
      <div class="ctf-room-header" style="background-image: linear-gradient(to bottom, rgba(5,5,15,0.7), #05050f), url('${coverImg}');">
        <div class="ctf-room-header-content">
          <div class="d-flex align-items-center mb-3">
             <button class="btn-back-cyber mr-3" onclick="loadPage('ctf')"><i class="fas fa-arrow-left"></i></button>
             <span class="badge badge-tier-${ctf.tier}">TIER ${ctf.tier}</span>
          </div>
          <h1 class="ctf-room-title">${ctf.title}</h1>
          <div class="ctf-room-meta">
            <span><i class="fas fa-tag"></i> ${ctf.category}</span>
            <span><i class="fas fa-tachometer-alt"></i> ${ctf.difficulty}</span>
            <span><i class="fas fa-trophy"></i> ${ctf.points} PTS</span>
          </div>
        </div>
      </div>

      <div class="ctf-room-grid">
        <!-- LEFT: Content -->
        <div class="ctf-room-main">
          <div class="ctf-glass-panel mb-4">
             <h3><i class="fas fa-book-dead"></i> Briefing</h3>
             <p class="ctf-scenario-text">${ctf.scenario || ctf.description}</p>
          </div>

          <div class="ctf-glass-panel">
             <h3><i class="fas fa-tasks"></i> Objectives</h3>
             <ul class="ctf-obj-list">
               ${(ctf.objectives || []).map(obj => `
                 <li><i class="far fa-circle"></i> ${obj}</li>
               `).join('')}
             </ul>
          </div>
        </div>

        <!-- RIGHT: Terminal/Tools -->
        <div class="ctf-room-side">
          <div class="ctf-glass-panel machine-status-panel text-center mb-4">
            <div id="machine-control-ui">
              <div class="machine-icon-glow"><i class="fas fa-microchip"></i></div>
              <p class="mb-3 text-muted">A private instance is required for this challenge.</p>
              <button class="btn-spawn-cyber" id="spawn-btn" onclick="spawnMachine('${ctf.machineId}')">
                <i class="fas fa-rocket"></i> SPAWN MACHINE
              </button>
            </div>
            <div id="machine-active-ui" style="display:none;">
              <div class="active-ip-box">
                <span class="ip-label">TARGET IP</span>
                <span class="ip-value" id="active-ip">10.10.231.42</span>
              </div>
              <div class="machine-timer"><i class="fas fa-clock"></i> <span id="machine-time">59:59</span></div>
              <button class="btn btn-outline-danger btn-sm mt-3" onclick="terminateMachine()">TERMINATE</button>
            </div>
          </div>

          <div class="ctf-glass-panel">
            <h3><i class="fas fa-flag"></i> Submission</h3>
            <div class="flag-input-group">
              <input type="text" id="flag-input" placeholder="AG{...}" class="cyber-input">
              <button class="btn-submit-flag" onclick="submitFlag('${ctf.id}')">SUBMIT</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function spawnMachine(labId) {
  const btn = document.getElementById('spawn-btn');
  if (!btn) return;

  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PROVISIONING...';
  btn.disabled = true;

  try {
    const currentUser = JSON.parse(localStorage.getItem('currentUser') || '{"id": 1}');
    const userId = currentUser.id || 1;

    const response = await fetch('/api/labs/spawn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        lab_id: labId
      })
    });

    const result = await response.json();

    if (result.success) {
      document.getElementById('machine-control-ui').style.display = 'none';
      document.getElementById('machine-active-ui').style.display = 'block';

      const ip = result.connection_string || result.ip;
      document.getElementById('active-ip').innerText = ip;

      if (result.expires_at) {
        startMachineTimer(result.expires_at);
      }

      showToast(result.message || 'Machine deployed successfully!', 'success');
    } else {
      showToast(result.error || 'Failed to spawn machine.', 'error');
      btn.innerHTML = '<i class="fas fa-rocket"></i> SPAWN MACHINE';
      btn.disabled = false;
    }
  } catch (err) {
    console.warn('Spawn Error:', err);
    showToast('Backend unreachable. Simulation active.', 'warning');

    setTimeout(() => {
      document.getElementById('machine-control-ui').style.display = 'none';
      document.getElementById('machine-active-ui').style.display = 'block';
      document.getElementById('active-ip').innerText = `10.10.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
    }, 2000);
  }
}

async function terminateMachine() {
  try {
    const currentUser = JSON.parse(localStorage.getItem('currentUser') || '{"id": 1}');
    const userId = currentUser.id || 1;

    const response = await fetch('/api/labs/kill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId })
    });

    const result = await response.json();
    if (result.success) {
      document.getElementById('machine-control-ui').style.display = 'block';
      document.getElementById('machine-active-ui').style.display = 'none';
      const btn = document.getElementById('spawn-btn');
      if (btn) {
        btn.innerHTML = '<i class="fas fa-rocket"></i> SPAWN MACHINE';
        btn.disabled = false;
      }
      showToast('Machine terminated.', 'info');
    }
  } catch (err) {
    showToast('Failed to terminate machine.', 'error');
  }
}

function startMachineTimer(expiresAt) {
  const timerElem = document.getElementById('machine-time');
  if (!timerElem) return;

  const expiry = new Date(expiresAt).getTime();

  const interval = setInterval(() => {
    const now = new Date().getTime();
    const distance = expiry - now;

    if (distance < 0) {
      clearInterval(interval);
      timerElem.innerText = "EXPIRED";
      terminateMachine();
      return;
    }

    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((distance % (1000 * 60)) / 1000);
    timerElem.innerText = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
  }, 1000);
}

function submitFlag(id) {
  const input = document.getElementById('flag-input');
  const flag = input?.value?.trim();
  if (!flag) return;

  // Use the global flag validator route if available
  fetch('/api/submit-flag', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: id, flag: flag })
  })
    .then(res => res.json())
    .then(result => {
      if (result.success) {
        showToast('FLAG CAPTURED! Points awarded.', 'success');
        input.style.borderColor = 'var(--neon-green)';

        // Update local storage if needed or refresh
        setTimeout(() => {
          loadPage('ctf'); // Back to galaxy
        }, 1500);
      } else {
        showToast(result.error || 'Invalid flag.', 'error');
        input.classList.add('shake');
        setTimeout(() => input.classList.remove('shake'), 500);
      }
    })
    .catch(err => {
      // Fallback logic for offline mode
      const challenges = typeof getAllCTFChallenges === 'function' ? getAllCTFChallenges() : [];
      const ctf = challenges.find(c => c.id === id);
      if (ctf && flag === ctf.flag) {
        showToast('FLAG CAPTURED! (Offline Mode)', 'success');
        input.style.borderColor = 'var(--neon-green)';
      } else {
        showToast('Invalid flag.', 'error');
        input.classList.add('shake');
        setTimeout(() => input.classList.remove('shake'), 500);
      }
    });
}

function getCategoryIconClass(cat) {
  cat = cat?.toLowerCase() || '';
  if (cat.includes('web')) return 'fas fa-globe';
  if (cat.includes('crypto')) return 'fas fa-lock';
  if (cat.includes('network')) return 'fas fa-server';
  if (cat.includes('pwn')) return 'fas fa-bug';
  if (cat.includes('red team')) return 'fas fa-shield-alt';
  return 'fas fa-flag';
}


// Helper to render cards
function renderCTFCards(challenges) {
  if (!challenges || challenges.length === 0) {
    return `<div class="col-12 text-center text-muted py-5"><h3>No challenges found.</h3></div>`;
  }

  return challenges.map(ctf => {
    // Check if solved
    const isSolved = typeof isCTFSolved === 'function' ? isCTFSolved(ctf.id) : false;

    const diffClass = (ctf.difficulty || 'medium').toLowerCase();
    const icon = getCategoryIcon(ctf.category);

    return `
      <div class="ctf-card" onclick="loadPage('ctf-challenge', '${ctf.id}')">
        <div class="ctf-card-header">
          <div class="ctf-icon-wrapper">${icon}</div>
          <div class="ctf-points-badge">${ctf.points} PTS</div>
        </div>
        
        <div class="ctf-card-body">
          <div class="ctf-card-title">${ctf.title}</div>
          <div class="ctf-card-desc">${ctf.description.substring(0, 100)}${ctf.description.length > 100 ? '...' : ''}</div>
          
          <div class="ctf-tags">
            <span class="ctf-tag">${ctf.category || 'Challenge'}</span>
            ${ctf.tags ? ctf.tags.slice(0, 2).map(t => `<span class="ctf-tag">${t}</span>`).join('') : ''}
          </div>
        </div>
        
        <div class="ctf-card-footer">
          <div class="difficulty-indicator">
            <span class="dot ${diffClass}"></span>
            <span style="text-transform: capitalize;">${ctf.difficulty || 'Medium'}</span>
          </div>
          
          <div class="status-text ${isSolved ? 'solved' : 'start'}">
            ${isSolved ? '<i class="fas fa-check-circle"></i> Solved' : 'Start <i class="fas fa-arrow-right"></i>'}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function getCategoryIcon(category) {
  const map = {
    'web': '<i class="fas fa-globe"></i>',
    'crypto': '<i class="fas fa-lock"></i>',
    'forensics': '<i class="fas fa-search"></i>',
    'pwn': '<i class="fas fa-bug"></i>',
    'reverse': '<i class="fas fa-sync"></i>',
    'misc': '<i class="fas fa-puzzle-piece"></i>',
    'osint': '<i class="fas fa-user-secret"></i>'
  };
  return map[category?.toLowerCase()] || '<i class="fas fa-flag"></i>';
}

// Filter Logic
function filterCTFs(category, btn) {
  // Update active button
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const container = document.getElementById('ctf-grid-container');
  if (!container) return;

  // Use unified data getter
  let filtered = [];
  if (typeof getAllCTFChallenges === 'function') {
    const all = getAllCTFChallenges();
    filtered = category === 'all' ? all : all.filter(c => (c.category || '').toLowerCase() === category);
  } else if (typeof ctfChallengesData !== 'undefined') {
    filtered = category === 'all' ? ctfChallengesData : ctfChallengesData.filter(c => (c.category || '').toLowerCase() === category);
  }

  container.innerHTML = renderCTFCards(filtered);
}

// Export
window.pageCTF = pageCTF;
window.pageCTFChallenge = pageCTFChallenge;
window.spawnMachine = spawnMachine;
window.submitFlag = submitFlag;
window.filterCTFs = filterCTFs;

