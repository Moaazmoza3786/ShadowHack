/* ============================================================
   KOTH - King of the Hill
   Study Hub Platform - Attack & Defense Competition
   ============================================================ */

function pageKOTH() {
    // Mock Active Machines
    const machines = [
        { name: 'Bastion-01', ip: '10.10.245.1', status: 'Contested', owner: 'R00tKiller', time: '12m 30s' },
        { name: 'Database-PROD', ip: '10.10.245.5', status: 'Secure', owner: 'BlueTeam_Alpha', time: '45m 00s' },
        { name: 'Web-Front', ip: '10.10.245.10', status: 'Compromised', owner: 'AnonUser', time: '2m 10s' }
    ];

    // Mock Leaderboard
    const topPlayers = [
        { rank: 1, name: 'CyberNinja', score: 12500, team: 'Red' },
        { rank: 2, name: 'SecOps_Dave', score: 11200, team: 'Blue' },
        { rank: 3, name: 'Hack3rOne', score: 9800, team: 'Red' }
    ];

    return `
        <div class="koth-container fade-in">
            <!-- Hero Section -->
            <div class="koth-hero">
                <div class="koth-overlay"></div>
                <div class="position-relative z-1 text-center py-5">
                    <h1 class="display-3 fw-bold text-white mb-3" style="font-family: 'Orbitron', sans-serif; text-shadow: 0 0 20px #eab308;">
                        KING OF THE HILL
                    </h1>
                    <p class="h4 text-warning mb-4">ATTACK. DEFEND. DOMINATE.</p>
                    <div class="d-flex justify-content-center gap-3">
                        <button class="btn btn-warning btn-lg fw-bold px-5 py-3 shadow-lg">
                            <i class="fa-solid fa-gamepad me-2"></i> JOIN QUEUE
                        </button>
                        <button class="btn btn-outline-light btn-lg px-5 py-3">
                            <i class="fa-solid fa-book-open me-2"></i> RULES
                        </button>
                    </div>
                </div>
            </div>

            <div class="row g-4 mt-2">
                <!-- Live Arena Status -->
                <div class="col-lg-8">
                    <div class="card bg-dark border-gold h-100">
                        <div class="card-header bg-transparent border-gold d-flex justify-content-between align-items-center">
                            <h4 class="text-white mb-0"><i class="fa-solid fa-server me-2 text-warning"></i>Live Arena</h4>
                            <span class="badge bg-danger animate-pulse">LIVE</span>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-dark table-hover mb-0">
                                    <thead>
                                        <tr>
                                            <th class="text-secondary">MACHINE</th>
                                            <th class="text-secondary">IP ADDRESS</th>
                                            <th class="text-secondary">STATUS</th>
                                            <th class="text-secondary">CURRENT KING</th>
                                            <th class="text-secondary">HOLD TIME</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${machines.map(m => `
                                            <tr>
                                                <td class="fw-bold text-white">${m.name}</td>
                                                <td class="font-monospace text-muted">${m.ip}</td>
                                                <td><span class="badge bg-${getKothColor(m.status)}">${m.status}</span></td>
                                                <td class="text-warning"><i class="fa-solid fa-crown me-1"></i> ${m.owner}</td>
                                                <td class="font-monospace">${m.time}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Top Players -->
                <div class="col-lg-4">
                    <div class="card bg-dark border-gold h-100">
                        <div class="card-header bg-transparent border-gold">
                            <h4 class="text-white mb-0"><i class="fa-solid fa-trophy me-2 text-warning"></i>Leaderboard</h4>
                        </div>
                        <div class="card-body p-0">
                            <div class="list-group list-group-flush">
                                ${topPlayers.map(p => `
                                    <div class="list-group-item bg-transparent border-secondary d-flex align-items-center p-3">
                                        <div class="rank-circle bg-dark border border-warning text-warning me-3">
                                            ${p.rank}
                                        </div>
                                        <div class="flex-grow-1">
                                            <h6 class="text-white mb-0">${p.name}</h6>
                                            <span class="badge bg-${p.team === 'Red' ? 'danger' : 'primary'} small">${p.team} Team</span>
                                        </div>
                                        <span class="fw-bold text-warning">${p.score} pts</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <style>
                .koth-container { max-width: 1400px; margin: 0 auto; padding: 20px; }
                .koth-hero {
                    background: linear-gradient(45deg, #000 0%, #332600 100%);
                    border-bottom: 4px solid #eab308;
                    border-radius: 12px;
                    overflow: hidden;
                    position: relative;
                }
                .border-gold { border-color: #eab308 !important; }
                .text-warning { color: #eab308 !important; }
                .btn-warning { background-color: #eab308; border-color: #eab308; color: #000; }
                
                .rank-circle {
                    width: 32px; height: 32px;
                    display: flex; align-items: center; justify-content: center;
                    border-radius: 50%;
                    font-weight: bold;
                }
                
                .animate-pulse {
                    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { opacity: 1; }
                    50% { opacity: .5; }
                }
            </style>
        </div>
    `;
}

function getKothColor(status) {
    if (status === 'Contested') return 'warning';
    if (status === 'Secure') return 'success';
    return 'danger';
}

window.pageKOTH = pageKOTH;
