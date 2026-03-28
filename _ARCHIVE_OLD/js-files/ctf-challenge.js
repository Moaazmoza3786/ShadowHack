/* ==================== CTF CHALLENGE VIEWER ==================== */
/* Professional CTF Experience with Flag Submission & Progress Tracking */

// ============== LocalStorage Utilities ==============
const CTF_PROGRESS_KEY = 'study_hub_ctf_progress';
const CTF_HINTS_KEY = 'study_hub_ctf_hints';

// Labs that require backend spawning (Docker)
const MACHINE_LABS = [
    'kerberoasting', 'bloodhound', 'zerologon',
    'gpo-abuse', 'golden-ticket', 'llmnr-poisoning'
];

function getCTFProgress() {
    try {
        return JSON.parse(localStorage.getItem(CTF_PROGRESS_KEY) || '{"solved": [], "points": 0}');
    } catch { return { solved: [], points: 0 }; }
}

function saveCTFProgress(progress) {
    localStorage.setItem(CTF_PROGRESS_KEY, JSON.stringify(progress));
}

function isCTFSolved(challengeId) {
    return getCTFProgress().solved.includes(challengeId);
}

function solveCTF(challengeId, points) {
    const progress = getCTFProgress();
    if (!progress.solved.includes(challengeId)) {
        progress.solved.push(challengeId);
        progress.points += points;
        saveCTFProgress(progress);
    }
    return progress;
}

function getUsedHints(challengeId) {
    try {
        const hints = JSON.parse(localStorage.getItem(CTF_HINTS_KEY) || '{}');
        return hints[challengeId] || [];
    } catch { return []; }
}

function useHint(challengeId, hintIndex) {
    try {
        const hints = JSON.parse(localStorage.getItem(CTF_HINTS_KEY) || '{}');
        if (!hints[challengeId]) hints[challengeId] = [];
        if (!hints[challengeId].includes(hintIndex)) {
            hints[challengeId].push(hintIndex);
            localStorage.setItem(CTF_HINTS_KEY, JSON.stringify(hints));
        }
        return hints[challengeId];
    } catch { return []; }
}

// ============== CTF Challenge Viewer Page ==============
function pageCTFChallenge(challengeId) {
    // Find challenge in data
    const allChallenges = typeof getAllCTFChallenges === 'function'
        ? getAllCTFChallenges()
        : (typeof ctfChallengesData !== 'undefined' ? ctfChallengesData : []);

    const challenge = allChallenges.find(c => c.id === challengeId);

    if (!challenge) {
        return `
        <div class="d-flex align-items-center justify-content-center" style="min-height: 80vh;">
            <div class="text-center">
                <i class="fas fa-flag fa-4x text-secondary mb-4"></i>
                <h3 class="text-white">Challenge Not Found</h3>
                <p class="text-muted">The requested challenge doesn't exist.</p>
                <button class="btn btn-outline-danger" onclick="loadPage('ctf')">
                    <i class="fas fa-arrow-left me-2"></i> Back to CTF Arena
                </button>
            </div>
        </div>
        `;
    }

    const isSolved = isCTFSolved(challengeId);
    const usedHints = getUsedHints(challengeId);
    const diffColors = {
        'easy': '#28a745',
        'medium': '#ffc107',
        'hard': '#dc3545',
        'insane': '#6f42c1'
    };
    const diffColor = diffColors[challenge.difficulty?.toLowerCase()] || '#6c757d';

    // Generate hints HTML
    const hints = challenge.hints || [
        "Think about common injection patterns",
        "Check the source code for clues",
        "Try special characters in input fields"
    ];

    // Comprehensive CTF app path mapping
    const appPathMapping = {
        // === WEB EXPLOITATION ===
        'web-darkweb-bakery': 'ctf-apps/sqli-practice/index.html',
        'web-crypto-exchange': 'ctf-apps/jwt-practice/index.html',
        'web-hospital-portal': 'ctf-apps/ssrf-practice/index.html',
        'web-graphql-galaxy': 'ctf-apps/idor-practice/index.html',
        'web-social-spider': 'ctf-apps/xss-practice/index.html',
        'web-upload-arena': 'ctf-apps/file-upload-practice/index.html',

        // === PRIVILEGE ESCALATION ===
        'priv-linux-fortress': 'ctf-apps/lfi-practice/index.html',
        'priv-windows-citadel': 'ctf-apps/rce-practice/index.html',
        'priv-kernel-panic': 'ctf-apps/rce-practice/index.html',
        'priv-docker-escape': 'ctf-apps/rce-practice/index.html',
        'priv-sudo-slayer': 'ctf-apps/lfi-practice/index.html',
        'priv-service-hunter': 'ctf-apps/rce-practice/index.html',

        // === ACTIVE DIRECTORY ===
        'ad-bloodhound-hunt': 'ctf-apps/network-lab/index.html',
        'ad-pass-the-world': 'ctf-apps/hash-cracker/index.html',
        'ad-gpo-takeover': 'ctf-apps/network-lab/index.html',

        // === MISC/CRYPTO/FORENSICS ===
        'misc-crypto-1': 'ctf-apps/crypto-lab/index.html',
        'misc-forensics-1': 'ctf-apps/forensics-lab/index.html',
        'misc-osint-1': 'ctf-apps/osint-lab/index.html',

        // === AVAILABLE APPS BY FOLDER NAME ===
        'sqli-practice': 'ctf-apps/sqli-practice/index.html',
        'sqli-edu': 'ctf-apps/sqli-edu/index.html',
        'sqli-union': 'ctf-apps/sqli-union/index.html',
        'sql-injection': 'ctf-apps/sql-injection/index.html',
        'xss-practice': 'ctf-apps/xss-practice/index.html',
        'xss-edu': 'ctf-apps/xss-edu/index.html',
        'xss-reflected': 'ctf-apps/xss-reflected/index.html',
        'ssrf-practice': 'ctf-apps/ssrf-practice/index.html',
        'ssrf-basic': 'ctf-apps/ssrf-basic/index.html',
        'ssrf-cloud': 'ctf-apps/ssrf-cloud/index.html',
        'idor-practice': 'ctf-apps/idor-practice/index.html',
        'idor-edu': 'ctf-apps/idor-edu/index.html',
        'jwt-practice': 'ctf-apps/jwt-practice/index.html',
        'lfi-practice': 'ctf-apps/lfi-practice/index.html',
        'rce-practice': 'ctf-apps/rce-practice/index.html',
        'xxe-practice': 'ctf-apps/xxe-practice/index.html',
        'file-upload-practice': 'ctf-apps/file-upload-practice/index.html',
        'crypto-lab': 'ctf-apps/crypto-lab/index.html',
        'forensics-lab': 'ctf-apps/forensics-lab/index.html',
        'network-lab': 'ctf-apps/network-lab/index.html',
        'osint-lab': 'ctf-apps/osint-lab/index.html',
        'hash-cracker': 'ctf-apps/hash-cracker/index.html',
        'weak-password': 'ctf-apps/weak-password/index.html',
        'weak-crypto': 'ctf-apps/weak-crypto/index.html',
        'default-creds': 'ctf-apps/default-creds/index.html',
        'directory-listing': 'ctf-apps/directory-listing/index.html',
        'exposed-secrets': 'ctf-apps/exposed-secrets/index.html',
        'hidden-text': 'ctf-apps/hidden-text/index.html',
        'log-injection': 'ctf-apps/log-injection/index.html',
        'logic-flaw': 'ctf-apps/logic-flaw/index.html',
        'session-fixation': 'ctf-apps/session-fixation/index.html',
        'unsigned-code': 'ctf-apps/unsigned-code/index.html'
    };

    // Smart app path resolution
    let appPath = appPathMapping[challengeId] || appPathMapping[challenge.machineId];

    if (!appPath) {
        // Try category-based matching
        const catLower = (challenge.category || '').toLowerCase();
        const tags = (challenge.tags || []).map(t => t.toLowerCase()).join(' ');
        const combined = `${catLower} ${tags}`;

        if (combined.includes('sql') || combined.includes('sqli')) appPath = 'ctf-apps/sqli-practice/index.html';
        else if (combined.includes('xss') || combined.includes('cross-site')) appPath = 'ctf-apps/xss-practice/index.html';
        else if (combined.includes('ssrf') || combined.includes('server-side')) appPath = 'ctf-apps/ssrf-practice/index.html';
        else if (combined.includes('idor') || combined.includes('insecure direct')) appPath = 'ctf-apps/idor-practice/index.html';
        else if (combined.includes('jwt') || combined.includes('api')) appPath = 'ctf-apps/jwt-practice/index.html';
        else if (combined.includes('lfi') || combined.includes('local file')) appPath = 'ctf-apps/lfi-practice/index.html';
        else if (combined.includes('rce') || combined.includes('command')) appPath = 'ctf-apps/rce-practice/index.html';
        else if (combined.includes('upload') || combined.includes('file upload')) appPath = 'ctf-apps/file-upload-practice/index.html';
        else if (combined.includes('crypto') || combined.includes('encryption')) appPath = 'ctf-apps/crypto-lab/index.html';
        else if (combined.includes('forensic') || combined.includes('memory')) appPath = 'ctf-apps/forensics-lab/index.html';
        else if (combined.includes('osint') || combined.includes('recon')) appPath = 'ctf-apps/osint-lab/index.html';
        else if (combined.includes('network') || combined.includes('bloodhound')) appPath = 'ctf-apps/network-lab/index.html';
        else if (combined.includes('hash') || combined.includes('password')) appPath = 'ctf-apps/hash-cracker/index.html';
        else if (combined.includes('web') || combined.includes('graphql')) appPath = 'ctf-apps/xss-practice/index.html';
        else if (combined.includes('linux') || combined.includes('priv')) appPath = 'ctf-apps/lfi-practice/index.html';
        else if (combined.includes('windows') || combined.includes('service')) appPath = 'ctf-apps/rce-practice/index.html';
        else appPath = 'ctf-apps/sqli-practice/index.html'; // Ultimate fallback
    }

    return `
    <style>
        .ctf-challenge-page {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            min-height: 100vh;
            padding: 24px;
        }
        .ctf-header-card {
            background: rgba(30, 30, 40, 0.9);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
            padding: 24px;
        }
        .ctf-diff-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 1px;
        }
        .ctf-points-badge {
            background: linear-gradient(135deg, #ff6b6b, #dc3545);
            padding: 8px 20px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 1.1rem;
        }
        .ctf-app-container {
            background: #000;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            overflow: hidden;
            min-height: 500px;
        }
        .ctf-app-container iframe {
            width: 100%;
            height: 500px;
            border: none;
        }
        .ctf-sidebar {
            background: rgba(25, 25, 35, 0.95);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .ctf-objective {
            padding: 12px 16px;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            margin-bottom: 8px;
            border-left: 3px solid #dc3545;
        }
        .ctf-hint-btn {
            background: rgba(255,193,7,0.1);
            border: 1px solid rgba(255,193,7,0.3);
            color: #ffc107;
            padding: 10px 16px;
            border-radius: 8px;
            width: 100%;
            text-align: left;
            transition: all 0.2s;
        }
        .ctf-hint-btn:hover:not(:disabled) {
            background: rgba(255,193,7,0.2);
        }
        .ctf-hint-btn.revealed {
            background: rgba(255,193,7,0.05);
            border-color: rgba(255,193,7,0.2);
        }
        .ctf-flag-input {
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 16px 20px;
            color: white;
            font-family: 'Courier New', monospace;
            font-size: 1.1rem;
        }
        .ctf-flag-input:focus {
            border-color: #dc3545;
            box-shadow: 0 0 20px rgba(220,53,69,0.3);
            outline: none;
        }
        .ctf-submit-btn {
            background: linear-gradient(135deg, #dc3545, #c82333);
            border: none;
            padding: 16px 32px;
            border-radius: 12px;
            font-weight: 600;
            transition: all 0.2s;
        }
        .ctf-submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(220,53,69,0.3);
        }
        .ctf-solved-banner {
            background: linear-gradient(135deg, rgba(40,167,69,0.2), rgba(40,167,69,0.1));
            border: 1px solid rgba(40,167,69,0.3);
            border-radius: 12px;
            padding: 20px;
        }
    </style>

    <div class="ctf-challenge-page">
        <!-- Header -->
        <div class="d-flex align-items-center gap-3 mb-4">
            <button class="btn btn-sm px-3 py-2" style="background: rgba(255,255,255,0.1); border: none; color: white;" 
                    onclick="loadPage('ctf')">
                <i class="fas fa-arrow-left me-2"></i> CTF Arena
            </button>
            <div class="ms-auto d-flex gap-2">
                <span class="ctf-diff-badge" style="background: ${diffColor}20; color: ${diffColor}; border: 1px solid ${diffColor};">
                    ${challenge.difficulty || 'Medium'}
                </span>
                <span class="ctf-points-badge text-white">
                    <i class="fas fa-star me-1"></i> ${challenge.points} PTS
                </span>
            </div>
        </div>

        <!-- Main Content -->
        <div class="row g-4">
            <!-- Left Column - App -->
            <div class="col-lg-8">
                <!-- Challenge Info Card -->
                <div class="ctf-header-card mb-4">
                    <div class="d-flex align-items-start justify-content-between mb-3">
                        <div>
                            <span class="badge bg-danger bg-opacity-25 text-danger mb-2">${challenge.category || 'Challenge'}</span>
                            <h2 class="text-white fw-bold mb-2">${challenge.title}</h2>
                            <p class="text-secondary mb-0">${challenge.description}</p>
                        </div>
                        ${isSolved ? '<span class="badge bg-success fs-6 p-2"><i class="fas fa-check-circle me-1"></i> SOLVED</span>' : ''}
                    </div>
                    
                    ${challenge.scenario ? `
                    <div class="p-3 rounded-3 mt-3" style="background: rgba(220,53,69,0.1); border: 1px solid rgba(220,53,69,0.2);">
                        <small class="text-danger fw-bold"><i class="fas fa-scroll me-2"></i>SCENARIO</small>
                        <p class="text-secondary mb-0 mt-2">${challenge.scenario}</p>
                    </div>
                    ` : ''}
                </div>

                <!-- App Container OR Machine Spawner -->
                <div class="ctf-app-container">
                    ${MACHINE_LABS.includes(challengeId) ? `
                        <div class="d-flex flex-column align-items-center justify-content-center h-100 p-5 text-center">
                            <i class="fas fa-server fa-5x text-secondary mb-4"></i>
                            <h3 class="text-white">Target Machine Required</h3>
                            <p class="text-muted mb-4">This challenge runs on a dedicated Docker container.</p>
                            
                            <div id="machine-controls">
                                <button class="btn btn-danger btn-lg px-5 hover-scale" onclick="spawnLab('${challengeId}')">
                                    <i class="fas fa-power-off me-2"></i> Start Machine
                                </button>
                            </div>

                            <div id="machine-info" class="mt-4 w-100" style="display: none;">
                                <div class="card bg-dark border-success">
                                    <div class="card-body">
                                        <h5 class="card-title text-success"><i class="fas fa-check-circle me-2"></i>Machine Active</h5>
                                        <div class="d-flex justify-content-around mt-3">
                                            <div>
                                                <small class="text-muted d-block">IP Address</small>
                                                <span class="fs-4 font-monospace text-white" id="lab-ip">10.10.10.5</span>
                                            </div>
                                            <div>
                                                <small class="text-muted d-block">Port</small>
                                                <span class="fs-4 font-monospace text-white" id="lab-port">3389</span>
                                            </div>
                                            <div>
                                                <small class="text-muted d-block">Expires In</small>
                                                <span class="fs-4 font-monospace text-warning" id="lab-timer">02:00:00</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ` : `
                        <iframe src="${appPath}" id="ctf-app-frame"></iframe>
                    `}
                </div>
                
                <!-- Open in New Tab -->
                <div class="mt-3 text-center">
                    <a href="${appPath}" target="_blank" class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-external-link-alt me-2"></i> Open Challenge in New Tab
                    </a>
                </div>
            </div>

            <!-- Right Column - Sidebar -->
            <div class="col-lg-4">
                <!-- Flag Submission -->
                <div class="ctf-sidebar p-4 mb-4">
                    <h5 class="text-white fw-bold mb-3">
                        <i class="fas fa-flag text-danger me-2"></i> Submit Flag
                    </h5>
                    
                    ${isSolved ? `
                    <div class="ctf-solved-banner text-center">
                        <i class="fas fa-trophy fa-3x text-success mb-3"></i>
                        <h5 class="text-success fw-bold">Challenge Completed!</h5>
                        <p class="text-muted mb-0">You earned ${challenge.points} points</p>
                    </div>
                    ` : `
                    <div class="mb-3">
                        <input type="text" id="flag-input" class="ctf-flag-input w-100" 
                               placeholder="FLAG{...}" autocomplete="off">
                    </div>
                    <button class="ctf-submit-btn w-100 text-white" onclick="submitCTFFlag('${challengeId}')">
                        <i class="fas fa-paper-plane me-2"></i> Submit Flag
                    </button>
                    <div id="flag-result" class="mt-3"></div>
                    `}
                </div>

                <!-- Objectives -->
                ${challenge.objectives && challenge.objectives.length > 0 ? `
                <div class="ctf-sidebar p-4 mb-4">
                    <h5 class="text-white fw-bold mb-3">
                        <i class="fas fa-tasks text-info me-2"></i> Objectives
                    </h5>
                    ${challenge.objectives.map((obj, i) => `
                        <div class="ctf-objective">
                            <span class="text-muted me-2">${i + 1}.</span>
                            <span class="text-white">${obj}</span>
                        </div>
                    `).join('')}
                </div>
                ` : ''}

                <!-- Hints -->
                <div class="ctf-sidebar p-4 mb-4">
                    <h5 class="text-white fw-bold mb-3">
                        <i class="fas fa-lightbulb text-warning me-2"></i> Hints
                        <small class="text-muted ms-2">(-50 pts each)</small>
                    </h5>
                    ${hints.map((hint, i) => {
        const isRevealed = usedHints.includes(i);
        return `
                        <button class="ctf-hint-btn mb-2 ${isRevealed ? 'revealed' : ''}" 
                                onclick="revealCTFHint('${challengeId}', ${i}, '${hint.replace(/'/g, "\\'")}')"
                                ${isRevealed ? '' : ''}>
                            <i class="fas ${isRevealed ? 'fa-eye' : 'fa-lock'} me-2"></i>
                            <span id="hint-text-${i}">${isRevealed ? hint : `Hint ${i + 1} (Click to reveal)`}</span>
                        </button>
                    `}).join('')}
                </div>

                <!-- Tags -->
                ${challenge.tags && challenge.tags.length > 0 ? `
                <div class="ctf-sidebar p-4">
                    <h5 class="text-white fw-bold mb-3">
                        <i class="fas fa-tags text-secondary me-2"></i> Tags
                    </h5>
                    <div class="d-flex flex-wrap gap-2">
                        ${challenge.tags.map(tag => `
                            <span class="badge" style="background: rgba(255,255,255,0.1); color: #aaa;">${tag}</span>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        </div>
    </div>
    `;
}

// ============== Flag Submission ==============
window.submitCTFFlag = function (challengeId) {
    const input = document.getElementById('flag-input');
    const result = document.getElementById('flag-result');
    if (!input || !result) return;

    const submittedFlag = input.value.trim();

    // Find challenge
    const allChallenges = typeof getAllCTFChallenges === 'function'
        ? getAllCTFChallenges()
        : (typeof ctfChallengesData !== 'undefined' ? ctfChallengesData : []);
    const challenge = allChallenges.find(c => c.id === challengeId);

    if (!challenge) {
        result.innerHTML = '<div class="alert alert-danger">Challenge not found</div>';
        return;
    }

    // Normalize flags for comparison (case-insensitive, trim whitespace)
    const correctFlag = (challenge.flag || '').trim().toLowerCase();
    const userFlag = submittedFlag.toLowerCase();

    if (userFlag === correctFlag) {
        // Correct!
        const usedHints = getUsedHints(challengeId);
        const hintPenalty = usedHints.length * 50;
        const finalPoints = Math.max(0, challenge.points - hintPenalty);

        solveCTF(challengeId, finalPoints);

        result.innerHTML = `
            <div class="ctf-solved-banner text-center animate__animated animate__bounceIn">
                <i class="fas fa-trophy fa-3x text-success mb-3"></i>
                <h5 class="text-success fw-bold">Correct Flag!</h5>
                <p class="text-white mb-1">+${finalPoints} points</p>
                ${hintPenalty > 0 ? `<small class="text-muted">(-${hintPenalty} hint penalty)</small>` : ''}
            </div>
        `;

        // Disable input
        input.disabled = true;
        input.value = submittedFlag;

        // Show confetti effect if available
        if (typeof confetti === 'function') {
            confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
        }
    } else {
        // Wrong
        result.innerHTML = `
            <div class="alert alert-danger d-flex align-items-center">
                <i class="fas fa-times-circle me-2"></i> Incorrect flag. Try again!
            </div>
        `;
        input.classList.add('animate__animated', 'animate__shakeX');
        setTimeout(() => input.classList.remove('animate__animated', 'animate__shakeX'), 500);
    }
};

// ============== Hint System ==============
window.revealCTFHint = function (challengeId, hintIndex, hintText) {
    const usedHints = getUsedHints(challengeId);

    if (usedHints.includes(hintIndex)) {
        // Already revealed
        return;
    }

    // Confirm hint usage
    if (!confirm(`Reveal this hint? You'll lose 50 points if you solve this challenge.`)) {
        return;
    }

    // Use hint
    useHint(challengeId, hintIndex);

    // Update UI
    const btn = document.querySelector(`#hint-text-${hintIndex}`).closest('button');
    const textSpan = document.getElementById(`hint-text-${hintIndex}`);

    if (btn) {
        btn.classList.add('revealed');
        btn.querySelector('i').className = 'fas fa-eye me-2';
    }
    if (textSpan) {
        textSpan.textContent = hintText;
    }
    if (textSpan) {
        textSpan.textContent = hintText;
    }
};

// ============== Lab Spawning Logic ==============
window.spawnLab = async function (challengeId) {
    const controls = document.getElementById('machine-controls');
    const info = document.getElementById('machine-info');
    const btn = controls.querySelector('button');

    // UI Loading State
    const originalBtn = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-circle-notch fa-spin me-2"></i> Spawning...';
    btn.disabled = true;

    try {
        // Find challenge data to get image name if needed (optional)
        // For now, backend maps ID to Image

        // Simulating API call if backend offline (graceful)
        let response;
        try {
            response = await fetch('/api/labs/spawn', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: 1, // Default User
                    lab_id: challengeId
                })
            });
        } catch (e) {
            console.warn("Backend unreachable, simulating...");
            // Simulate for demo
            await new Promise(r => setTimeout(r, 2000));
            response = {
                ok: true, json: async () => ({
                    success: true,
                    ip: '10.10.14.55',
                    port: 3389,
                    timeout_minutes: 120,
                    message: 'Simulation Mode'
                })
            };
        }

        const data = await response.json();

        if (data.success) {
            controls.style.display = 'none';
            info.style.display = 'block';

            document.getElementById('lab-ip').textContent = data.ip;
            document.getElementById('lab-port').textContent = data.port || 'Default';

            // Start Timer (Simple frontend visual)
            let duration = (data.timeout_minutes || 120) * 60;
            const timerEl = document.getElementById('lab-timer');
            setInterval(() => {
                duration--;
                const h = Math.floor(duration / 3600);
                const m = Math.floor((duration % 3600) / 60);
                const s = duration % 60;
                timerEl.textContent = `${h}:${m < 10 ? '0' + m : m}:${s < 10 ? '0' + s : s}`;
            }, 1000);

        } else {
            alert('Failed to spawn lab: ' + (data.error || data.message));
            btn.innerHTML = originalBtn;
            btn.disabled = false;
        }

    } catch (err) {
        console.error(err);
        alert('Connection Failed. Ensure Backend is running.');
        btn.innerHTML = originalBtn;
        btn.disabled = false;
    }
};

// ============== Exports ==============
window.pageCTFChallenge = pageCTFChallenge;
window.getCTFProgress = getCTFProgress;
window.isCTFSolved = isCTFSolved;
