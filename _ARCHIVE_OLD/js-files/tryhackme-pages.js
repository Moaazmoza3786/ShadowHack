/* ============================================================
   TRYHACKME-STYLE PAGES
   SOC Simulator, Threat Hunting, KOTH, Leagues
   ============================================================ */

// Placeholder page function
function pagePlaceholder(title, subtitle) {
    return `
        <div class="placeholder-page">
            <style>
                .placeholder-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    flex-direction: column;
                    text-align: center;
                    padding: 40px;
                }
                .placeholder-icon {
                    font-size: 80px;
                    color: #22c55e;
                    margin-bottom: 30px;
                    animation: float 3s ease-in-out infinite;
                }
                @keyframes float {
                    0%, 100% { transform: translateY(0); }
                    50% { transform: translateY(-15px); }
                }
                .placeholder-title {
                    font-size: 3rem;
                    font-weight: 800;
                    color: #fff;
                    margin-bottom: 15px;
                    font-family: 'Orbitron', sans-serif;
                }
                .placeholder-subtitle {
                    font-size: 1.3rem;
                    color: rgba(255,255,255,0.6);
                    margin-bottom: 30px;
                }
                .placeholder-badge {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                    padding: 10px 25px;
                    border-radius: 30px;
                    font-weight: 700;
                    font-size: 14px;
                }
            </style>
            <i class="fa-solid fa-hammer placeholder-icon"></i>
            <h1 class="placeholder-title">${title}</h1>
            <p class="placeholder-subtitle">${subtitle}</p>
            <span class="placeholder-badge">Coming Soon</span>
        </div>
    `;
}

// SOC Simulator Page
function pageSOCSimulatorLegacy() {
    return `
        <div class="soc-simulator-page">
            <style>
                .soc-simulator-page {
                    min-height: 100vh;
                    background: #0a0a0f;
                    font-family: 'JetBrains Mono', monospace;
                }
                .soc-header {
                    background: linear-gradient(90deg, #1a1a2e 0%, #16213e 100%);
                    padding: 20px 30px;
                    border-bottom: 2px solid #22c55e;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .soc-title {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }
                .soc-title h1 {
                    color: #22c55e;
                    font-size: 1.5rem;
                    font-family: 'Orbitron', sans-serif;
                }
                .soc-status {
                    display: flex;
                    gap: 20px;
                }
                .status-box {
                    text-align: center;
                    padding: 10px 20px;
                    background: rgba(34, 197, 94, 0.1);
                    border-radius: 8px;
                }
                .status-value { font-size: 1.5rem; color: #22c55e; font-weight: 700; }
                .status-label { font-size: 10px; color: rgba(255,255,255,0.5); text-transform: uppercase; }
                
                .soc-main {
                    display: grid;
                    grid-template-columns: 1fr 400px;
                    height: calc(100vh - 80px);
                }
                .alerts-panel {
                    border-right: 1px solid rgba(34, 197, 94, 0.2);
                    overflow-y: auto;
                }
                .alerts-header {
                    padding: 15px 20px;
                    background: rgba(0,0,0,0.3);
                    border-bottom: 1px solid rgba(34, 197, 94, 0.2);
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .alerts-header h3 { color: #fff; font-size: 14px; }
                .alert-count { color: #22c55e; font-weight: 700; }
                
                .alert-item {
                    padding: 15px 20px;
                    border-bottom: 1px solid rgba(255,255,255,0.05);
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .alert-item:hover {
                    background: rgba(34, 197, 94, 0.05);
                }
                .alert-item.critical { border-left: 3px solid #ef4444; }
                .alert-item.high { border-left: 3px solid #f59e0b; }
                .alert-item.medium { border-left: 3px solid #3b82f6; }
                .alert-item.low { border-left: 3px solid #22c55e; }
                
                .alert-time { font-size: 11px; color: rgba(255,255,255,0.4); }
                .alert-source { font-size: 13px; color: #22c55e; margin: 5px 0; font-weight: 600; }
                .alert-message { font-size: 12px; color: rgba(255,255,255,0.7); }
                
                .detail-panel {
                    padding: 20px;
                    background: rgba(0,0,0,0.2);
                }
                .detail-header { color: #fff; margin-bottom: 20px; }
                .detail-section {
                    background: rgba(255,255,255,0.02);
                    border-radius: 8px;
                    padding: 15px;
                    margin-bottom: 15px;
                }
                .detail-section h4 { color: #22c55e; font-size: 12px; margin-bottom: 10px; text-transform: uppercase; }
                .detail-log {
                    background: #000;
                    padding: 15px;
                    border-radius: 6px;
                    font-size: 11px;
                    color: #22c55e;
                    overflow-x: auto;
                    white-space: pre-wrap;
                }
                
                .verdict-buttons {
                    display: flex;
                    gap: 15px;
                    margin-top: 20px;
                }
                .verdict-btn {
                    flex: 1;
                    padding: 15px;
                    border: none;
                    border-radius: 10px;
                    font-weight: 700;
                    cursor: pointer;
                    font-size: 14px;
                    transition: all 0.3s;
                }
                .verdict-btn.true-positive {
                    background: #ef4444;
                    color: #fff;
                }
                .verdict-btn.false-positive {
                    background: #22c55e;
                    color: #000;
                }
            </style>
            
            <div class="soc-header">
                <div class="soc-title">
                    <i class="fa-solid fa-desktop" style="font-size: 24px; color: #22c55e;"></i>
                    <h1>SOC Simulator</h1>
                </div>
                <div class="soc-status">
                    <div class="status-box">
                        <div class="status-value">15</div>
                        <div class="status-label">Pending</div>
                    </div>
                    <div class="status-box">
                        <div class="status-value">85%</div>
                        <div class="status-label">Accuracy</div>
                    </div>
                    <div class="status-box">
                        <div class="status-value">128</div>
                        <div class="status-label">Triaged</div>
                    </div>
                </div>
            </div>
            
            <div class="soc-main">
                <div class="alerts-panel">
                    <div class="alerts-header">
                        <h3>Alert Queue</h3>
                        <span class="alert-count">15 Alerts</span>
                    </div>
                    
                    <div class="alert-item critical">
                        <div class="alert-time">2 min ago</div>
                        <div class="alert-source">Windows Security</div>
                        <div class="alert-message">Multiple failed login attempts detected from 192.168.1.105</div>
                    </div>
                    <div class="alert-item high">
                        <div class="alert-time">5 min ago</div>
                        <div class="alert-source">Firewall</div>
                        <div class="alert-message">Outbound connection to known C2 server blocked</div>
                    </div>
                    <div class="alert-item medium">
                        <div class="alert-time">12 min ago</div>
                        <div class="alert-source">Antivirus</div>
                        <div class="alert-message">Suspicious PowerShell execution detected</div>
                    </div>
                    <div class="alert-item low">
                        <div class="alert-time">18 min ago</div>
                        <div class="alert-source">IDS</div>
                        <div class="alert-message">Port scan detected from internal host</div>
                    </div>
                </div>
                
                <div class="detail-panel">
                    <h3 class="detail-header">Alert Details</h3>
                    
                    <div class="detail-section">
                        <h4>Source Information</h4>
                        <p style="color: rgba(255,255,255,0.7); font-size: 13px;">
                            Source IP: 192.168.1.105<br>
                            Hostname: WORKSTATION-07<br>
                            User: jsmith
                        </p>
                    </div>
                    
                    <div class="detail-section">
                        <h4>Raw Log</h4>
                        <div class="detail-log">[2024-01-15 14:32:15] EventID: 4625
Account: Administrator
Source IP: 192.168.1.105
Failure Reason: Bad Password
Logon Type: 10 (RemoteInteractive)</div>
                    </div>
                    
                    <div class="verdict-buttons">
                        <button class="verdict-btn true-positive">
                            <i class="fa-solid fa-exclamation-triangle"></i> True Positive
                        </button>
                        <button class="verdict-btn false-positive">
                            <i class="fa-solid fa-check"></i> False Positive
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// King of the Hill Page
function pageKOTH() {
    return `
        <div class="koth-page">
            <style>
                .koth-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    padding: 30px;
                }
                .koth-container { max-width: 1400px; margin: 0 auto; }
                .koth-header {
                    text-align: center;
                    margin-bottom: 40px;
                }
                .koth-title {
                    font-size: 3rem;
                    font-weight: 800;
                    color: #fff;
                    font-family: 'Orbitron', sans-serif;
                    margin-bottom: 10px;
                }
                .koth-title i { color: #f59e0b; margin-right: 15px; }
                .koth-subtitle { color: rgba(255,255,255,0.6); font-size: 1.1rem; }
                
                .koth-lobbies {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                    gap: 25px;
                }
                
                .lobby-card {
                    background: rgba(255,255,255,0.03);
                    border: 2px solid rgba(245, 158, 11, 0.3);
                    border-radius: 20px;
                    padding: 25px;
                    transition: all 0.4s;
                    cursor: pointer;
                }
                .lobby-card:hover {
                    border-color: #f59e0b;
                    transform: translateY(-5px);
                    box-shadow: 0 20px 40px rgba(245, 158, 11, 0.2);
                }
                .lobby-card.active { border-color: #22c55e; }
                
                .lobby-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 20px;
                }
                .lobby-name { font-size: 1.4rem; font-weight: 700; color: #fff; }
                .lobby-status {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    font-size: 13px;
                    padding: 6px 14px;
                    border-radius: 20px;
                }
                .lobby-status.live {
                    background: rgba(34, 197, 94, 0.2);
                    color: #22c55e;
                }
                .lobby-status.waiting {
                    background: rgba(245, 158, 11, 0.2);
                    color: #f59e0b;
                }
                .status-dot {
                    width: 8px; height: 8px;
                    border-radius: 50%;
                    background: currentColor;
                    animation: blink 1.5s infinite;
                }
                @keyframes blink {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.3; }
                }
                
                .lobby-machine {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    padding: 15px;
                    background: rgba(0,0,0,0.2);
                    border-radius: 12px;
                    margin-bottom: 20px;
                }
                .machine-os {
                    width: 50px; height: 50px;
                    border-radius: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 24px;
                }
                .machine-os.linux { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
                .machine-os.windows { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
                .machine-info { flex: 1; }
                .machine-name { color: #fff; font-weight: 600; }
                .machine-ip { color: rgba(255,255,255,0.4); font-size: 13px; font-family: monospace; }
                
                .lobby-king {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 12px;
                    background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(245, 158, 11, 0.05));
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
                .king-crown { font-size: 24px; color: #f59e0b; }
                .king-name { color: #fff; font-weight: 600; flex: 1; }
                .king-time { color: #f59e0b; font-size: 14px; font-family: monospace; }
                
                .lobby-players {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 20px;
                }
                .player-avatar {
                    width: 35px; height: 35px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 14px;
                    color: #000;
                    font-weight: 700;
                }
                .players-more {
                    background: rgba(255,255,255,0.1);
                    color: rgba(255,255,255,0.7);
                }
                
                .join-btn {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #f59e0b, #d97706);
                    border: none;
                    border-radius: 12px;
                    color: #000;
                    font-weight: 700;
                    font-size: 15px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
            </style>
            
            <div class="koth-container">
                <div class="koth-header">
                    <h1 class="koth-title">
                        <i class="fa-solid fa-crown"></i>
                        King of the Hill
                    </h1>
                    <p class="koth-subtitle">Compete in real-time. Attack, defend, and claim the throne!</p>
                </div>
                
                <div class="koth-lobbies">
                    <div class="lobby-card active">
                        <div class="lobby-header">
                            <span class="lobby-name">Battle Arena #1</span>
                            <span class="lobby-status live">
                                <span class="status-dot"></span> LIVE
                            </span>
                        </div>
                        <div class="lobby-machine">
                            <div class="machine-os linux">
                                <i class="fab fa-linux"></i>
                            </div>
                            <div class="machine-info">
                                <div class="machine-name">CyberFortress</div>
                                <div class="machine-ip">10.10.10.45</div>
                            </div>
                        </div>
                        <div class="lobby-king">
                            <i class="fa-solid fa-crown king-crown"></i>
                            <span class="king-name">H4ck3rX</span>
                            <span class="king-time">15:42</span>
                        </div>
                        <div class="lobby-players">
                            <div class="player-avatar">JD</div>
                            <div class="player-avatar">SK</div>
                            <div class="player-avatar">MR</div>
                            <div class="player-avatar players-more">+4</div>
                        </div>
                        <button class="join-btn">
                            <i class="fa-solid fa-gamepad"></i> Join Battle
                        </button>
                    </div>
                    
                    <div class="lobby-card">
                        <div class="lobby-header">
                            <span class="lobby-name">Battle Arena #2</span>
                            <span class="lobby-status waiting">
                                <span class="status-dot"></span> Waiting
                            </span>
                        </div>
                        <div class="lobby-machine">
                            <div class="machine-os windows">
                                <i class="fab fa-windows"></i>
                            </div>
                            <div class="machine-info">
                                <div class="machine-name">DomainController</div>
                                <div class="machine-ip">10.10.10.100</div>
                            </div>
                        </div>
                        <div class="lobby-king">
                            <i class="fa-solid fa-hourglass-half king-crown" style="color: rgba(255,255,255,0.3);"></i>
                            <span class="king-name" style="color: rgba(255,255,255,0.5);">Waiting for first king...</span>
                        </div>
                        <div class="lobby-players">
                            <div class="player-avatar">AS</div>
                            <div class="player-avatar">BT</div>
                        </div>
                        <button class="join-btn">
                            <i class="fa-solid fa-gamepad"></i> Join Battle
                        </button>
                    </div>
                    
                    <div class="lobby-card">
                        <div class="lobby-header">
                            <span class="lobby-name">Beginner Arena</span>
                            <span class="lobby-status live">
                                <span class="status-dot"></span> LIVE
                            </span>
                        </div>
                        <div class="lobby-machine">
                            <div class="machine-os linux">
                                <i class="fab fa-linux"></i>
                            </div>
                            <div class="machine-info">
                                <div class="machine-name">Starter Box</div>
                                <div class="machine-ip">10.10.10.5</div>
                            </div>
                        </div>
                        <div class="lobby-king">
                            <i class="fa-solid fa-crown king-crown"></i>
                            <span class="king-name">NewbieKing</span>
                            <span class="king-time">03:21</span>
                        </div>
                        <div class="lobby-players">
                            <div class="player-avatar">AA</div>
                            <div class="player-avatar">BB</div>
                            <div class="player-avatar">CC</div>
                        </div>
                        <button class="join-btn">
                            <i class="fa-solid fa-gamepad"></i> Join Battle
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Leagues Page - Weekly Competitive Leaderboard (API-Integrated)
function pageLeagues() {
    // Trigger async data loading
    setTimeout(loadLeaguesData, 0);

    // Return loading shell immediately
    return `
        <div class="leagues-page" id="leagues-container">
            <style>
                .leagues-page {
                    min-height: 100vh;
                    background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 50%, #0f0f23 100%);
                }
                
                /* Loading State */
                .leagues-loading {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    min-height: 60vh;
                    color: #fff;
                }
                .leagues-loading .spinner {
                    width: 60px;
                    height: 60px;
                    border: 4px solid rgba(34, 197, 94, 0.2);
                    border-top-color: #22c55e;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin { to { transform: rotate(360deg); } }
                .leagues-loading p {
                    font-size: 1.2rem;
                    color: rgba(255,255,255,0.6);
                }
                
                /* Header Section */
                .leagues-header {
                    background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #0d1b2a 100%);
                    padding: 60px 30px;
                    text-align: center;
                    border-bottom: 2px solid rgba(34, 197, 94, 0.3);
                }
                
                /* Hexagon Badge Row */
                .badges-row {
                    display: flex;
                    justify-content: center;
                    gap: 25px;
                    margin-bottom: 40px;
                    flex-wrap: wrap;
                }
                
                .hex-badge {
                    width: 80px;
                    height: 92px;
                    position: relative;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                
                .hex-badge::before {
                    content: '';
                    position: absolute;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
                    clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
                    border: 2px solid rgba(255,255,255,0.2);
                    transition: all 0.3s;
                }
                
                .hex-badge.unlocked::before {
                    background: var(--badge-color);
                    box-shadow: 0 0 30px var(--badge-color);
                }
                
                .hex-badge.current::before {
                    animation: pulse-glow 2s ease-in-out infinite;
                }
                
                @keyframes pulse-glow {
                    0%, 100% { box-shadow: 0 0 20px var(--badge-color); }
                    50% { box-shadow: 0 0 40px var(--badge-color), 0 0 60px var(--badge-color); }
                }
                
                .hex-badge.locked::before {
                    background: rgba(50, 50, 70, 0.5);
                    filter: grayscale(100%);
                }
                
                .hex-badge i {
                    font-size: 28px;
                    color: #fff;
                    z-index: 1;
                    margin-bottom: 5px;
                }
                
                .hex-badge.locked i {
                    color: rgba(255,255,255,0.3);
                }
                
                .hex-badge-name {
                    font-size: 11px;
                    color: rgba(255,255,255,0.7);
                    margin-top: 8px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                
                .hex-badge.locked .hex-badge-name {
                    color: rgba(255,255,255,0.3);
                }
                
                /* League Title */
                .league-title {
                    font-size: 3.5rem;
                    font-weight: 800;
                    color: #fff;
                    font-family: 'Orbitron', sans-serif;
                    margin-bottom: 15px;
                }
                
                .league-subtitle {
                    font-size: 1.2rem;
                    color: rgba(255,255,255,0.6);
                    margin-bottom: 30px;
                }
                
                .league-buttons {
                    display: flex;
                    gap: 15px;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                
                .league-btn {
                    padding: 14px 30px;
                    border-radius: 12px;
                    font-weight: 700;
                    font-size: 15px;
                    cursor: pointer;
                    border: none;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    transition: all 0.3s;
                }
                
                .league-btn.primary {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                }
                
                .league-btn.primary:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 10px 30px rgba(34, 197, 94, 0.4);
                }
                
                .league-btn.secondary {
                    background: rgba(255,255,255,0.1);
                    color: #fff;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                
                .league-btn.secondary:hover {
                    background: rgba(255,255,255,0.15);
                }
                
                .league-btn:disabled {
                    opacity: 0.5;
                    cursor: not-allowed;
                }
                
                /* User Stats */
                .user-stats {
                    display: flex;
                    gap: 30px;
                    justify-content: center;
                    margin-top: 25px;
                }
                .stat-item {
                    text-align: center;
                }
                .stat-value {
                    font-size: 2rem;
                    font-weight: 800;
                    color: #22c55e;
                    font-family: 'JetBrains Mono', monospace;
                }
                .stat-label {
                    font-size: 0.9rem;
                    color: rgba(255,255,255,0.5);
                    text-transform: uppercase;
                }
                
                /* Leaderboard Section */
                .leaderboard-section {
                    max-width: 900px;
                    margin: 0 auto;
                    padding: 40px 20px;
                }
                
                .leaderboard-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 25px;
                }
                
                .leaderboard-title {
                    font-size: 1.8rem;
                    font-weight: 700;
                    color: #fff;
                    font-family: 'Orbitron', sans-serif;
                }
                
                .week-timer {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    background: rgba(245, 158, 11, 0.1);
                    padding: 10px 20px;
                    border-radius: 30px;
                    color: #f59e0b;
                    font-weight: 600;
                }
                
                /* Leaderboard Table */
                .leaderboard-table {
                    background: rgba(255,255,255,0.02);
                    border-radius: 16px;
                    overflow: hidden;
                    border: 1px solid rgba(255,255,255,0.05);
                }
                
                .leaderboard-row {
                    display: grid;
                    grid-template-columns: 60px 1fr 100px;
                    align-items: center;
                    padding: 18px 25px;
                    border-bottom: 1px solid rgba(255,255,255,0.05);
                    transition: all 0.2s;
                }
                
                .leaderboard-row:hover {
                    background: rgba(255,255,255,0.03);
                }
                
                .leaderboard-row.promotion-zone {
                    background: linear-gradient(90deg, rgba(34, 197, 94, 0.15), transparent);
                    border-left: 4px solid #22c55e;
                }
                
                .leaderboard-row.demotion-zone {
                    background: linear-gradient(90deg, rgba(239, 68, 68, 0.15), transparent);
                    border-left: 4px solid #ef4444;
                }
                
                .leaderboard-row.current-user {
                    background: rgba(59, 130, 246, 0.15);
                    border-left: 4px solid #3b82f6;
                }
                
                .rank-col {
                    font-size: 1.3rem;
                    font-weight: 800;
                    color: rgba(255,255,255,0.8);
                }
                
                .rank-col.top-3 {
                    color: #22c55e;
                }
                
                .user-col {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }
                
                .user-avatar {
                    width: 45px;
                    height: 45px;
                    border-radius: 12px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: 700;
                    color: #000;
                    font-size: 14px;
                }
                
                .user-name {
                    font-weight: 600;
                    color: #fff;
                    font-size: 15px;
                }
                
                .xp-col {
                    text-align: right;
                    font-weight: 700;
                    color: #22c55e;
                    font-size: 15px;
                    font-family: 'JetBrains Mono', monospace;
                }
                
                /* Zone Labels */
                .zone-label {
                    padding: 10px 25px;
                    font-size: 12px;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                }
                
                .zone-label.promotion {
                    background: rgba(34, 197, 94, 0.2);
                    color: #22c55e;
                    border-bottom: 1px solid rgba(34, 197, 94, 0.3);
                }
                
                .zone-label.demotion {
                    background: rgba(239, 68, 68, 0.2);
                    color: #ef4444;
                    border-top: 1px solid rgba(239, 68, 68, 0.3);
                }
                
                /* Empty State */
                .empty-leaderboard {
                    text-align: center;
                    padding: 60px 20px;
                    color: rgba(255,255,255,0.5);
                }
                .empty-leaderboard i {
                    font-size: 4rem;
                    margin-bottom: 20px;
                    color: rgba(255,255,255,0.2);
                }
                
                /* Modal */
                .leagues-modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.8);
                    z-index: 1000;
                    justify-content: center;
                    align-items: center;
                    backdrop-filter: blur(5px);
                }
                
                .leagues-modal.active {
                    display: flex;
                }
                
                .modal-content {
                    background: linear-gradient(135deg, #1a1a2e, #16213e);
                    border-radius: 20px;
                    padding: 40px;
                    max-width: 500px;
                    width: 90%;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .modal-title {
                    font-size: 1.8rem;
                    font-weight: 700;
                    color: #fff;
                    margin-bottom: 25px;
                    font-family: 'Orbitron', sans-serif;
                }
                
                .modal-text {
                    color: rgba(255,255,255,0.7);
                    line-height: 1.8;
                    margin-bottom: 20px;
                }
                
                .modal-text strong {
                    color: #22c55e;
                }
                
                .modal-close {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                    border: none;
                    padding: 14px 40px;
                    border-radius: 12px;
                    font-weight: 700;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 20px;
                }
            </style>
            
            <div class="leagues-loading">
                <div class="spinner"></div>
                <p>Loading leagues...</p>
            </div>
        </div>
    `;
}

// Async function to load leagues data
async function loadLeaguesData() {
    const container = document.getElementById('leagues-container');
    if (!container) return;

    try {
        // Fetch all required data
        const [allLeaguesRes, currentRes] = await Promise.all([
            LeaguesAPI.getAll(),
            AuthState.isLoggedIn() ? LeaguesAPI.getCurrent() : Promise.resolve({ success: false })
        ]);

        // Default leagues if API fails
        const defaultLeagues = [
            { id: 1, name: 'Bronze', icon: 'fa-medal', color: '#cd7f32', order_index: 1 },
            { id: 2, name: 'Silver', icon: 'fa-medal', color: '#c0c0c0', order_index: 2 },
            { id: 3, name: 'Gold', icon: 'fa-medal', color: '#ffd700', order_index: 3 },
            { id: 4, name: 'Platinum', icon: 'fa-gem', color: '#e5e4e2', order_index: 4 },
            { id: 5, name: 'Diamond', icon: 'fa-gem', color: '#b9f2ff', order_index: 5 },
            { id: 6, name: 'Master', icon: 'fa-crown', color: '#9b59b6', order_index: 6 },
            { id: 7, name: 'Grandmaster', icon: 'fa-crown', color: '#e74c3c', order_index: 7 }
        ];

        const leagues = allLeaguesRes.success ? allLeaguesRes.leagues : defaultLeagues;
        const currentLeague = currentRes.success && currentRes.league ? currentRes.league : leagues[0];
        const participation = currentRes.participation || null;
        const weeklyXP = currentRes.weekly_xp || 0;
        const weekRemaining = currentRes.week_remaining || { days: 5, hours: 12 };

        // Fetch leaderboard for current league
        const leaderboardRes = await LeaguesAPI.getLeaderboard(currentLeague.id);
        const leaderboard = leaderboardRes.success ? leaderboardRes.leaderboard : [];
        const zones = leaderboardRes.zones || { promotion_cutoff: 3, demotion_cutoff: 8 };

        // Render the page
        container.innerHTML = renderLeaguesContent(leagues, currentLeague, participation, weeklyXP, weekRemaining, leaderboard, zones);

    } catch (error) {
        console.error('Failed to load leagues data:', error);
        container.innerHTML = `
            <div class="leagues-loading">
                <i class="fa-solid fa-exclamation-triangle" style="font-size: 3rem; color: #ef4444; margin-bottom: 20px;"></i>
                <p style="color: #ef4444;">Failed to load leagues data</p>
                <button class="league-btn primary" onclick="loadPage('leagues')" style="margin-top: 20px;">
                    <i class="fa-solid fa-refresh"></i> Retry
                </button>
            </div>
        `;
    }
}

// Render leagues content
function renderLeaguesContent(leagues, currentLeague, participation, weeklyXP, weekRemaining, leaderboard, zones) {
    const isLoggedIn = AuthState.isLoggedIn();
    const hasJoined = !!participation;
    const currentUserId = AuthState.getUserId();

    return `
        <div class="leagues-header">
            <div class="badges-row">
                ${leagues.map(league => {
        const isCurrent = league.id === currentLeague.id;
        const isUnlocked = league.order_index <= currentLeague.order_index;
        return `
                        <div class="hex-badge ${isUnlocked ? 'unlocked' : 'locked'} ${isCurrent ? 'current' : ''}" 
                             style="--badge-color: ${league.color};"
                             onclick="viewLeagueLeaderboard(${league.id})">
                            <i class="fa-solid ${league.icon || 'fa-medal'}"></i>
                            <span class="hex-badge-name">${league.name}</span>
                        </div>
                    `;
    }).join('')}
            </div>
            
            <h1 class="league-title" style="text-shadow: 0 0 30px ${currentLeague.color};">
                ${currentLeague.name} League
            </h1>
            <p class="league-subtitle">
                ${hasJoined ? 'You\'re competing this week! Earn XP to climb the ranks.' : 'Join the weekly competition to compete for promotions!'}
            </p>
            
            ${isLoggedIn ? `
                <div class="user-stats">
                    <div class="stat-item">
                        <div class="stat-value">${weeklyXP.toLocaleString()}</div>
                        <div class="stat-label">Weekly XP</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">#${participation?.rank || '-'}</div>
                        <div class="stat-label">Current Rank</div>
                    </div>
                </div>
            ` : ''}
            
            <div class="league-buttons">
                ${!isLoggedIn ? `
                    <button class="league-btn primary" onclick="loadPage('login')">
                        <i class="fa-solid fa-sign-in-alt"></i> Login to Compete
                    </button>
                ` : !hasJoined ? `
                    <button class="league-btn primary" onclick="joinLeague()">
                        <i class="fa-solid fa-trophy"></i> Join This Week's League
                    </button>
                ` : `
                    <button class="league-btn primary" onclick="loadPage('learn')">
                        <i class="fa-solid fa-play"></i> Earn More XP
                    </button>
                `}
                <button class="league-btn secondary" onclick="document.getElementById('howLeaguesModal').classList.add('active')">
                    <i class="fa-solid fa-circle-info"></i> How Leagues Work
                </button>
            </div>
        </div>
        
        <div class="leaderboard-section">
            <div class="leaderboard-header">
                <h2 class="leaderboard-title">
                    <i class="fa-solid fa-trophy" style="color: #f59e0b; margin-right: 10px;"></i>
                    Weekly Leaderboard
                </h2>
                <div class="week-timer">
                    <i class="fa-solid fa-clock"></i>
                    <span>${weekRemaining.days}d ${weekRemaining.hours}h remaining</span>
                </div>
            </div>
            
            <div class="leaderboard-table">
                ${leaderboard.length > 0 ? `
                    <div class="zone-label promotion">
                        <i class="fa-solid fa-arrow-up"></i> Promotion Zone - Top ${zones.promotion_cutoff} advance
                    </div>
                    
                    ${leaderboard.map((entry, index) => {
        let zoneClass = '';
        if (index < zones.promotion_cutoff) zoneClass = 'promotion-zone';
        else if (index >= zones.demotion_cutoff - 1 && zones.demotion_cutoff > 0) zoneClass = 'demotion-zone';

        const isCurrentUser = entry.user?.id === currentUserId;
        if (isCurrentUser) zoneClass += ' current-user';

        const avatar = entry.user?.username?.substring(0, 2).toUpperCase() || '??';

        return `
                            <div class="leaderboard-row ${zoneClass}">
                                <div class="rank-col ${index < 3 ? 'top-3' : ''}">#${entry.rank}</div>
                                <div class="user-col">
                                    <div class="user-avatar">${avatar}</div>
                                    <div class="user-name">${entry.user?.username || 'Unknown'}${isCurrentUser ? ' (You)' : ''}</div>
                                </div>
                                <div class="xp-col">${entry.xp?.toLocaleString() || 0} XP</div>
                            </div>
                        `;
    }).join('')}
                    
                    ${zones.demotion_cutoff > 0 ? `
                        <div class="zone-label demotion">
                            <i class="fa-solid fa-arrow-down"></i> Demotion Zone - Bottom players drop
                        </div>
                    ` : ''}
                ` : `
                    <div class="empty-leaderboard">
                        <i class="fa-solid fa-users-slash"></i>
                        <p>No participants yet this week.<br>Be the first to join!</p>
                    </div>
                `}
            </div>
        </div>
        
        <!-- How Leagues Work Modal -->
        <div id="howLeaguesModal" class="leagues-modal" onclick="if(event.target === this) this.classList.remove('active')">
            <div class="modal-content">
                <h2 class="modal-title">
                    <i class="fa-solid fa-trophy" style="color: #f59e0b;"></i> How Leagues Work
                </h2>
                <p class="modal-text">
                    <strong>Earn XP</strong> by completing rooms and challenges throughout the week.
                </p>
                <p class="modal-text">
                    <strong>Top 10%</strong> of players in your league get <strong>promoted</strong> to the next tier.
                </p>
                <p class="modal-text">
                    <strong>Bottom 10%</strong> get <strong>demoted</strong> to the previous tier.
                </p>
                <p class="modal-text">
                    Leagues reset every <strong>Sunday at midnight</strong>. Join to compete and climb the ranks!
                </p>
                <button class="modal-close" onclick="document.getElementById('howLeaguesModal').classList.remove('active')">
                    Got it!
                </button>
            </div>
        </div>
    `;
}

// Join league function
async function joinLeague() {
    if (!AuthState.isLoggedIn()) {
        showNotification('Please login to join a league', 'warning');
        loadPage('login');
        return;
    }

    const result = await LeaguesAPI.join();

    if (result.success) {
        showNotification('🎉 You\'ve joined this week\'s league!', 'success');
        loadPage('leagues'); // Refresh page
    } else {
        showNotification(result.error || 'Failed to join league', 'error');
    }
}

// View specific league leaderboard
async function viewLeagueLeaderboard(leagueId) {
    // For now, just reload the page - could be enhanced to switch leagues
    console.log('Viewing league:', leagueId);
}

// Make functions globally available
window.loadLeaguesData = loadLeaguesData;
window.joinLeague = joinLeague;
window.viewLeagueLeaderboard = viewLeagueLeaderboard;

// Premium Subscription Page
function pageSubscribe() {
    return `
        <div class="subscribe-page">
            <style>
                .subscribe-page {
                    min-height: 100vh;
                    background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%);
                    padding: 60px 20px;
                }
                
                .subscribe-container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                
                .subscribe-header {
                    text-align: center;
                    margin-bottom: 60px;
                }
                
                .subscribe-title {
                    font-size: 3rem;
                    font-weight: 800;
                    color: #fff;
                    font-family: 'Orbitron', sans-serif;
                    margin-bottom: 15px;
                }
                
                .subscribe-title span {
                    background: linear-gradient(135deg, #22c55e, #3b82f6);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                }
                
                .subscribe-subtitle {
                    font-size: 1.2rem;
                    color: rgba(255,255,255,0.6);
                }
                
                /* Pricing Cards */
                .pricing-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                    gap: 30px;
                    margin-bottom: 50px;
                }
                
                .pricing-card {
                    background: rgba(255,255,255,0.02);
                    border: 2px solid rgba(255,255,255,0.1);
                    border-radius: 24px;
                    padding: 40px;
                    position: relative;
                    transition: all 0.4s;
                }
                
                .pricing-card:hover {
                    transform: translateY(-10px);
                    border-color: rgba(34, 197, 94, 0.5);
                    box-shadow: 0 30px 60px rgba(0,0,0,0.3);
                }
                
                .pricing-card.featured {
                    background: linear-gradient(135deg, rgba(34, 197, 94, 0.1), rgba(59, 130, 246, 0.1));
                    border-color: #22c55e;
                    transform: scale(1.05);
                }
                
                .pricing-card.featured:hover {
                    transform: scale(1.05) translateY(-10px);
                }
                
                .best-value-badge {
                    position: absolute;
                    top: -15px;
                    left: 50%;
                    transform: translateX(-50%);
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                    padding: 8px 25px;
                    border-radius: 30px;
                    font-weight: 700;
                    font-size: 13px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                
                .plan-name {
                    font-size: 1.5rem;
                    font-weight: 700;
                    color: #fff;
                    margin-bottom: 10px;
                }
                
                .plan-price {
                    margin-bottom: 25px;
                }
                
                .price-amount {
                    font-size: 3.5rem;
                    font-weight: 800;
                    color: #22c55e;
                    font-family: 'Orbitron', sans-serif;
                }
                
                .price-period {
                    font-size: 1rem;
                    color: rgba(255,255,255,0.5);
                }
                
                .plan-description {
                    color: rgba(255,255,255,0.6);
                    margin-bottom: 30px;
                    font-size: 14px;
                }
                
                .features-list {
                    list-style: none;
                    padding: 0;
                    margin-bottom: 30px;
                }
                
                .features-list li {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 12px 0;
                    color: rgba(255,255,255,0.8);
                    font-size: 14px;
                    border-bottom: 1px solid rgba(255,255,255,0.05);
                }
                
                .features-list li i.included {
                    color: #22c55e;
                    font-size: 16px;
                }
                
                .features-list li i.not-included {
                    color: rgba(255,255,255,0.2);
                    font-size: 16px;
                }
                
                .features-list li.disabled {
                    color: rgba(255,255,255,0.3);
                }
                
                .subscribe-btn {
                    width: 100%;
                    padding: 16px;
                    border-radius: 14px;
                    font-weight: 700;
                    font-size: 16px;
                    cursor: pointer;
                    border: none;
                    transition: all 0.3s;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
                
                .subscribe-btn.primary {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                }
                
                .subscribe-btn.primary:hover {
                    box-shadow: 0 15px 40px rgba(34, 197, 94, 0.4);
                    transform: translateY(-2px);
                }
                
                .subscribe-btn.secondary {
                    background: rgba(255,255,255,0.1);
                    color: #fff;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                
                .subscribe-btn.secondary:hover {
                    background: rgba(255,255,255,0.15);
                }
                
                /* Payment Modal */
                .payment-modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.9);
                    z-index: 1000;
                    justify-content: center;
                    align-items: center;
                    backdrop-filter: blur(10px);
                }
                
                .payment-modal.active {
                    display: flex;
                }
                
                .payment-content {
                    background: linear-gradient(135deg, #1a1a2e, #16213e);
                    border-radius: 24px;
                    padding: 50px;
                    max-width: 450px;
                    width: 90%;
                    border: 1px solid rgba(255,255,255,0.1);
                    position: relative;
                }
                
                .payment-close {
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    background: none;
                    border: none;
                    color: rgba(255,255,255,0.5);
                    font-size: 24px;
                    cursor: pointer;
                }
                
                .payment-title {
                    font-size: 1.8rem;
                    font-weight: 700;
                    color: #fff;
                    margin-bottom: 10px;
                    font-family: 'Orbitron', sans-serif;
                }
                
                .payment-plan-info {
                    color: #22c55e;
                    font-weight: 600;
                    margin-bottom: 30px;
                }
                
                .form-group {
                    margin-bottom: 20px;
                }
                
                .form-label {
                    display: block;
                    color: rgba(255,255,255,0.7);
                    font-size: 13px;
                    margin-bottom: 8px;
                    font-weight: 600;
                }
                
                .form-input {
                    width: 100%;
                    padding: 14px 18px;
                    background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 12px;
                    color: #fff;
                    font-size: 15px;
                    transition: all 0.3s;
                }
                
                .form-input:focus {
                    outline: none;
                    border-color: #22c55e;
                    box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.2);
                }
                
                .form-row {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                }
                
                .payment-submit {
                    width: 100%;
                    padding: 18px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border: none;
                    border-radius: 14px;
                    color: #000;
                    font-weight: 700;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                    transition: all 0.3s;
                }
                
                .payment-submit:hover {
                    box-shadow: 0 15px 40px rgba(34, 197, 94, 0.4);
                    transform: translateY(-2px);
                }
                
                .secure-badge {
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                    color: rgba(255,255,255,0.4);
                    font-size: 12px;
                    margin-top: 20px;
                }
                
                /* Confetti Animation */
                .confetti-container {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    pointer-events: none;
                    z-index: 2000;
                }
                
                .confetti-container.active {
                    display: block;
                }
                
                .confetti {
                    position: absolute;
                    width: 10px;
                    height: 10px;
                    animation: confetti-fall 3s ease-out forwards;
                }
                
                @keyframes confetti-fall {
                    0% {
                        transform: translateY(-100px) rotate(0deg);
                        opacity: 1;
                    }
                    100% {
                        transform: translateY(100vh) rotate(720deg);
                        opacity: 0;
                    }
                }
                
                /* Success Modal */
                .success-modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.9);
                    z-index: 1500;
                    justify-content: center;
                    align-items: center;
                }
                
                .success-modal.active {
                    display: flex;
                }
                
                .success-content {
                    text-align: center;
                    color: #fff;
                }
                
                .success-icon {
                    font-size: 80px;
                    color: #22c55e;
                    margin-bottom: 25px;
                    animation: bounce-in 0.6s ease;
                }
                
                @keyframes bounce-in {
                    0% { transform: scale(0); }
                    50% { transform: scale(1.2); }
                    100% { transform: scale(1); }
                }
                
                .success-title {
                    font-size: 2.5rem;
                    font-weight: 800;
                    margin-bottom: 15px;
                    font-family: 'Orbitron', sans-serif;
                }
                
                .success-text {
                    color: rgba(255,255,255,0.7);
                    font-size: 1.1rem;
                    margin-bottom: 30px;
                }
                
                .success-btn {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    color: #000;
                    border: none;
                    padding: 16px 50px;
                    border-radius: 14px;
                    font-weight: 700;
                    font-size: 16px;
                    cursor: pointer;
                }
            </style>
            
            <div class="subscribe-container">
                <div class="subscribe-header">
                    <h1 class="subscribe-title">Unlock <span>Premium</span></h1>
                    <p class="subscribe-subtitle">Get unlimited access to all rooms, faster VPN, and exclusive content</p>
                </div>
                
                <div class="pricing-grid">
                    <!-- Free Plan -->
                    <div class="pricing-card">
                        <div class="plan-name">Free</div>
                        <div class="plan-price">
                            <span class="price-amount">$0</span>
                            <span class="price-period">/forever</span>
                        </div>
                        <p class="plan-description">Perfect for getting started with cybersecurity</p>
                        <ul class="features-list">
                            <li><i class="fa-solid fa-check included"></i> Access to free rooms</li>
                            <li><i class="fa-solid fa-check included"></i> Basic learning paths</li>
                            <li><i class="fa-solid fa-check included"></i> Community support</li>
                            <li class="disabled"><i class="fa-solid fa-xmark not-included"></i> Premium rooms</li>
                            <li class="disabled"><i class="fa-solid fa-xmark not-included"></i> Private networks</li>
                            <li class="disabled"><i class="fa-solid fa-xmark not-included"></i> Priority VPN</li>
                        </ul>
                        <button class="subscribe-btn secondary">
                            <i class="fa-solid fa-check"></i> Current Plan
                        </button>
                    </div>
                    
                    <!-- Monthly Plan -->
                    <div class="pricing-card">
                        <div class="plan-name">Monthly</div>
                        <div class="plan-price">
                            <span class="price-amount">$9.99</span>
                            <span class="price-period">/month</span>
                        </div>
                        <p class="plan-description">Full access with monthly flexibility</p>
                        <ul class="features-list">
                            <li><i class="fa-solid fa-check included"></i> All free features</li>
                            <li><i class="fa-solid fa-check included"></i> All premium rooms</li>
                            <li><i class="fa-solid fa-check included"></i> Private networks</li>
                            <li><i class="fa-solid fa-check included"></i> Priority VPN access</li>
                            <li><i class="fa-solid fa-check included"></i> Downloadable certificates</li>
                            <li><i class="fa-solid fa-check included"></i> Cancel anytime</li>
                        </ul>
                        <button class="subscribe-btn primary" onclick="openPaymentModal('Monthly', '$9.99/month')">
                            <i class="fa-solid fa-crown"></i> Go Premium
                        </button>
                    </div>
                    
                    <!-- Annual Plan -->
                    <div class="pricing-card featured">
                        <div class="best-value-badge">Best Value - Save 33%</div>
                        <div class="plan-name">Annual</div>
                        <div class="plan-price">
                            <span class="price-amount">$79.99</span>
                            <span class="price-period">/year</span>
                        </div>
                        <p class="plan-description">Best value for serious learners</p>
                        <ul class="features-list">
                            <li><i class="fa-solid fa-check included"></i> All monthly features</li>
                            <li><i class="fa-solid fa-check included"></i> Exclusive boot camps</li>
                            <li><i class="fa-solid fa-check included"></i> Early access to new rooms</li>
                            <li><i class="fa-solid fa-check included"></i> 1-on-1 mentor sessions</li>
                            <li><i class="fa-solid fa-check included"></i> Priority support</li>
                            <li><i class="fa-solid fa-check included"></i> 2 months free!</li>
                        </ul>
                        <button class="subscribe-btn primary" onclick="openPaymentModal('Annual', '$79.99/year')">
                            <i class="fa-solid fa-rocket"></i> Go Premium
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Payment Modal -->
            <div id="paymentModal" class="payment-modal" onclick="if(event.target === this) closePaymentModal()">
                <div class="payment-content">
                    <button class="payment-close" onclick="closePaymentModal()">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                    <h2 class="payment-title">Complete Payment</h2>
                    <p class="payment-plan-info" id="selectedPlanInfo">Annual Plan - $79.99/year</p>
                    
                    <form onsubmit="processPayment(event)">
                        <div class="form-group">
                            <label class="form-label">Card Number</label>
                            <input type="text" class="form-input" placeholder="4242 4242 4242 4242" maxlength="19" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Cardholder Name</label>
                            <input type="text" class="form-input" placeholder="John Doe" required>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Expiry Date</label>
                                <input type="text" class="form-input" placeholder="MM/YY" maxlength="5" required>
                            </div>
                            <div class="form-group">
                                <label class="form-label">CVC</label>
                                <input type="text" class="form-input" placeholder="123" maxlength="4" required>
                            </div>
                        </div>
                        <button type="submit" class="payment-submit">
                            <i class="fa-solid fa-lock"></i> Complete Payment
                        </button>
                    </form>
                    
                    <div class="secure-badge">
                        <i class="fa-solid fa-shield-halved"></i>
                        <span>Secure payment - This is a demo payment form</span>
                    </div>
                </div>
            </div>
            
            <!-- Success Modal -->
            <div id="successModal" class="success-modal">
                <div class="success-content">
                    <i class="fa-solid fa-circle-check success-icon"></i>
                    <h2 class="success-title">Welcome to Premium!</h2>
                    <p class="success-text">Your subscription is now active. Enjoy unlimited access!</p>
                    <button class="success-btn" onclick="redirectToDashboard()">
                        <i class="fa-solid fa-rocket"></i> Go to Dashboard
                    </button>
                </div>
            </div>
            
            <!-- Confetti Container -->
            <div id="confettiContainer" class="confetti-container"></div>
        </div>
        
        <script>
            let selectedTier = 'monthly'; // Track selected tier
            
            function openPaymentModal(plan, price) {
                // Map plan names to tier values
                selectedTier = plan.toLowerCase() === 'annual' ? 'annual' : 'monthly';
                document.getElementById('selectedPlanInfo').textContent = plan + ' Plan - ' + price;
                document.getElementById('paymentModal').classList.add('active');
            }
            
            function closePaymentModal() {
                document.getElementById('paymentModal').classList.remove('active');
            }
            
            async function processPayment(e) {
                e.preventDefault();
                
                // Get card number for last 4 digits (mock)
                const cardInput = document.querySelector('.payment-content input[type="text"]');
                const cardLastFour = cardInput ? cardInput.value.slice(-4) : '****';
                
                closePaymentModal();
                
                // Try to call backend API if available
                if (typeof SubscriptionAPI !== 'undefined' && typeof AuthState !== 'undefined' && AuthState.isLoggedIn()) {
                    try {
                        const result = await SubscriptionAPI.subscribe(selectedTier, cardLastFour);
                        if (result.success) {
                            // Store subscription data
                            localStorage.setItem('userSubscription', JSON.stringify({
                                tier: result.tier,
                                expires_at: result.expires_at,
                                transaction_id: result.transaction_id
                            }));
                            
                            // Show confetti and success
                            createConfetti();
                            setTimeout(() => {
                                document.getElementById('successModal').classList.add('active');
                            }, 500);
                            return;
                        } else {
                            // API error - show toast and fall back to mock
                            if (typeof showToast === 'function') {
                                showToast(result.error || 'Payment failed', 'error');
                            }
                        }
                    } catch (error) {
                        console.error('Subscription API error:', error);
                    }
                }
                
                // Fall back to mock payment (for demo/when not logged in)
                createConfetti();
                
                setTimeout(() => {
                    document.getElementById('successModal').classList.add('active');
                }, 500);
                
                // Store mock subscription in localStorage
                const expiryDays = selectedTier === 'annual' ? 365 : 30;
                localStorage.setItem('userSubscription', JSON.stringify({
                    tier: selectedTier,
                    expires_at: new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString()
                }));
            }
            
            function createConfetti() {
                const container = document.getElementById('confettiContainer');
                container.classList.add('active');
                container.innerHTML = '';
                
                const colors = ['#22c55e', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];
                
                for (let i = 0; i < 100; i++) {
                    const confetti = document.createElement('div');
                    confetti.className = 'confetti';
                    confetti.style.left = Math.random() * 100 + '%';
                    confetti.style.background = colors[Math.floor(Math.random() * colors.length)];
                    confetti.style.animationDelay = Math.random() * 2 + 's';
                    confetti.style.animationDuration = (2 + Math.random() * 2) + 's';
                    container.appendChild(confetti);
                }
                
                setTimeout(() => {
                    container.classList.remove('active');
                }, 5000);
            }
            
            function redirectToDashboard() {
                document.getElementById('successModal').classList.remove('active');
                if (typeof loadPage === 'function') {
                    loadPage('dashboard');
                } else {
                    window.location.hash = '#dashboard';
                }
            }
        </script>
    `;
}

// Make functions globally available

// Career Tracks Page
function pageCareers() {
    return `
        <div class="career-hub-page">
            <style>
                .career-hub-page {
                    min-height: 100vh;
                    background: #f9fafb; /* Light background as per screenshot */
                    font-family: 'Inter', sans-serif;
                }
                
                /* Hero Section */
                .career-hero {
                    background: #0f172a;
                    padding: 80px 20px;
                    text-align: center;
                    color: #fff;
                    position: relative;
                    overflow: hidden;
                }
                .career-hero::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background: radial-gradient(circle at 50% 50%, rgba(34, 197, 94, 0.15), transparent 70%);
                    pointer-events: none;
                }
                .career-hero h1 {
                    font-size: 3rem;
                    font-weight: 700;
                    margin-bottom: 20px;
                }
                .career-hero h1::after {
                    content: '';
                    display: block;
                    width: 60px;
                    height: 4px;
                    background: #84cc16; /* Lime/Green underline */
                    margin: 15px auto 0;
                    border-radius: 2px;
                }
                .career-hero p {
                    font-size: 1.2rem;
                    color: #94a3b8;
                    max-width: 800px;
                    margin: 0 auto;
                }
                
                /* Quiz CTA Section */
                .career-quiz-section {
                    text-align: center;
                    padding: 60px 20px;
                    background: #fff;
                }
                .career-quiz-section h2 {
                    font-size: 1.8rem;
                    color: #1e293b;
                    margin-bottom: 10px;
                    font-weight: 700;
                }
                .career-quiz-section p {
                    color: #64748b;
                    font-size: 1rem;
                }
                .career-quiz-section a {
                    color: #3b82f6;
                    text-decoration: none;
                    font-weight: 600;
                }
                .career-quiz-section a:hover { text-decoration: underline; }
                .quiz-indicator {
                    width: 40px;
                    height: 4px;
                    background: #84cc16;
                    margin: 20px auto 0;
                    border-radius: 2px;
                }
                
                /* Cards Grid */
                .career-cards-container {
                    max-width: 1200px;
                    margin: -40px auto 80px; /* Pull up or just margin */
                    margin-top: 0;
                    padding: 20px;
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                    gap: 30px;
                    background: #fff; /* Container bg matches section */
                }
                
                .career-card {
                    background: #fff;
                    border: 1px solid #e2e8f0;
                    border-radius: 12px;
                    padding: 40px 30px;
                    text-align: center;
                    transition: all 0.3s ease;
                    cursor: pointer;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                }
                
                .career-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 20px 40px rgba(0,0,0,0.05);
                    border-color: #cbd5e1;
                }
                
                .career-illustration {
                    height: 160px;
                    margin-bottom: 25px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .career-illustration img {
                    max-height: 100%;
                    max-width: 100%;
                    object-fit: contain;
                }
                
                /* Fallback icons if no image */
                .career-icon-placeholder {
                    font-size: 80px;
                    margin-bottom: 20px;
                }
                .career-icon-placeholder.analyst { color: #10b981; }
                .career-icon-placeholder.pentester { color: #ef4444; }
                .career-icon-placeholder.engineer { color: #3b82f6; }
                .career-icon-placeholder.redteam { color: #dc2626; }
                .career-icon-placeholder.responder { color: #6366f1; }

                .career-card h3 {
                    font-size: 1.25rem;
                    font-weight: 700;
                    color: #1e293b;
                    margin-bottom: 15px;
                }
                
                .career-card p {
                    color: #64748b;
                    font-size: 0.95rem;
                    line-height: 1.6;
                }

                /* Responsive */
                @media (max-width: 768px) {
                    .career-hero h1 { font-size: 2rem; }
                    .career-cards-container { grid-template-columns: 1fr; }
                }
            </style>
            
            <!-- Hero -->
            <div class="career-hero">
                <h1>Career Tracks</h1>
                <p>From Entry-Level to Expert, the BreachLabs Career Tracks has you covered every step of the way.</p>
            </div>
            
            <!-- Quiz CTA -->
            <div class="career-quiz-section">
                <h2>Which career is right for you?</h2>
                <p>Not sure? Take our <a href="#" onclick="alert('Quiz coming soon!'); return false;">career quiz</a> to find out.</p>
                <div class="quiz-indicator"></div>
            </div>
            
            <!-- Cards Grid -->
            <div class="career-cards-container">
                <!-- Card 1: Security Analyst -->
                <div class="career-card" onclick="loadPage('career-track', {id: 'soc-analyst'})">
                    <div class="career-illustration">
                        <i class="fa-solid fa-user-shield career-icon-placeholder analyst"></i>
                    </div>
                    <h3>SOC Analyst</h3>
                    <p>Get on the fast track to becoming a successful Security Operations Center Analyst.</p>
                </div>
                
                <!-- Card 2: Penetration Tester -->
                <div class="career-card" onclick="loadPage('career-track', {id: 'penetration-tester'})">
                    <div class="career-illustration">
                        <i class="fa-solid fa-bug career-icon-placeholder pentester"></i>
                    </div>
                    <h3>Penetration Tester</h3>
                    <p>Level up and forge your path to victory as a Penetration Tester.</p>
                </div>
                
                <!-- Card 3: Security Engineer -->
                <div class="career-card" onclick="loadPage('career-track', {id: 'security-engineer'})">
                    <div class="career-illustration">
                        <i class="fa-solid fa-layer-group career-icon-placeholder engineer"></i>
                    </div>
                    <h3>Security Engineer</h3>
                    <p>Navigate your journey to becoming a world-class Security Engineer.</p>
                </div>

                <!-- Card 4: Red Teamer -->
                <div class="career-card" onclick="loadPage('career-track', {id: 'red-teamer'})">
                    <div class="career-illustration">
                        <i class="fa-solid fa-user-ninja career-icon-placeholder redteam"></i>
                    </div>
                    <h3>Red Teamer</h3>
                    <p>Master Offensive Security by learning how to become a Red Teamer.</p>
                </div>
                
                <!-- Card 5: Incident Responder -->
                <div class="career-card" onclick="loadPage('career-track', {id: 'incident-responder'})">
                    <div class="career-illustration">
                        <i class="fa-solid fa-file-shield career-icon-placeholder responder"></i>
                    </div>
                    <h3>Incident Responder</h3>
                    <p>Step into the frontline of cybersecurity and master the skills to become an effective incident responder.</p>
                </div>
            </div>
        </div>
    `;
}

window.pagePlaceholder = pagePlaceholder;
window.pageSOCSimulator = pageSOCSimulator;
window.pageKOTH = pageKOTH;
window.pageLeagues = pageLeagues;
window.pageSubscribe = pageSubscribe;
window.pageCareers = pageCareers;
