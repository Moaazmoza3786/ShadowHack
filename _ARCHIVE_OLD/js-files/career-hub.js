/* ============================================================
   CAREER HUB UI
   Displays available career tracks (Red, Blue, SOC, etc.)
   ============================================================ */

function pageCareers() {
    // Ensure tracks data is loaded
    const tracks = (typeof CareerTracksData !== 'undefined' && CareerTracksData.tracks)
        ? CareerTracksData.tracks
        : [];

    return `
    <div class="career-hub-page fade-in">
        <style>
            .career-hub-page {
                padding: 40px;
                max-width: 1400px;
                margin: 0 auto;
                color: #fff;
            }
            .hub-header {
                text-align: center;
                margin-bottom: 60px;
            }
            .hub-header h1 {
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 15px;
            }
            .hub-header p {
                font-size: 1.2rem;
                color: #94a3b8;
                max-width: 600px;
                margin: 0 auto;
            }
            
            .career-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 30px;
            }

            .career-card {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 16px;
                overflow: hidden;
                transition: transform 0.3s, box-shadow 0.3s;
                position: relative;
                display: flex;
                flex-direction: column;
            }
            .career-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                border-color: #6366f1;
            }

            .card-banner {
                height: 140px;
                background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
            }
            .card-icon {
                font-size: 4rem;
                color: rgba(255,255,255,0.1);
                position: absolute;
                right: 20px;
                bottom: -20px;
                transform: rotate(-15deg);
            }
            .track-icon-main {
                width: 80px;
                height: 80px;
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2.5rem;
                color: #fff;
                box-shadow: 0 10px 20px rgba(0,0,0,0.2);
                z-index: 10;
            }

            .card-body {
                padding: 30px;
                flex: 1;
                display: flex;
                flex-direction: column;
            }
            .card-title {
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 10px;
                color: #f8fafc;
            }
            .card-desc {
                color: #94a3b8;
                font-size: 0.95rem;
                line-height: 1.6;
                margin-bottom: 25px;
                flex: 1;
            }

            .card-stats {
                display: flex;
                gap: 20px;
                margin-bottom: 25px;
                font-size: 0.9rem;
                color: #cbd5e1;
            }
            .stat-item { display: flex; align-items: center; gap: 8px; }
            .stat-item i { color: #818cf8; }

            .card-btn {
                width: 100%;
                padding: 15px;
                background: #4f46e5;
                color: #fff;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s;
                text-align: center;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .card-btn:hover { background: #4338ca; }
            
            .difficulty-badge {
                position: absolute;
                top: 15px;
                right: 15px;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 700;
                text-transform: uppercase;
                background: rgba(0,0,0,0.4);
                backdrop-filter: blur(5px);
            }
            .diff-beginner { color: #4ade80; border: 1px solid #4ade80; }
            .diff-intermediate { color: #facc15; border: 1px solid #facc15; }
            .diff-advanced { color: #f87171; border: 1px solid #f87171; }

            /* Grid Layout for specific cards if needed */
        </style>

        <div class="hub-header">
            <h1>Career Pathways</h1>
            <p>Select a specialized career track to begin your journey. Follow a structured curriculum designed to get you job-ready.</p>
        </div>

        <div class="career-grid">
            ${tracks.map(track => {
        const diffClass = track.difficulty === 'Beginner' ? 'diff-beginner' :
            track.difficulty === 'Intermediate' ? 'diff-intermediate' : 'diff-advanced';

        // Helper to get font awesome icon based on track ID
        let icon = 'fa-road';
        if (track.id.includes('soc')) icon = 'fa-shield-halved';
        if (track.id.includes('pen')) icon = 'fa-user-secret';
        if (track.id.includes('red')) icon = 'fa-dragon';
        if (track.id.includes('bug')) icon = 'fa-bug';
        if (track.id.includes('eng')) icon = 'fa-hard-hat';

        return `
                <div class="career-card" onclick="loadPage('career-track', {id: '${track.id}'})">
                    <div class="card-banner">
                        <div class="difficulty-badge ${diffClass}">${track.difficulty}</div>
                        <i class="fas ${icon} card-icon"></i>
                        <div class="track-icon-main">
                            <i class="fas ${icon}"></i>
                        </div>
                    </div>
                    <div class="card-body">
                        <h3 class="card-title">${track.title}</h3>
                        <p class="card-desc">${track.description || 'Master the skills needed for this role through hands-on labs and guided coursework.'}</p>
                        
                        <div class="card-stats">
                            <div class="stat-item"><i class="fas fa-layer-group"></i> ${track.modules ? track.modules.length : 8} Modules</div>
                            <div class="stat-item"><i class="fas fa-clock"></i> ${track.duration || '40h'}</div>
                        </div>

                        <button class="card-btn">
                            View Career Path <i class="fas fa-arrow-right" style="margin-left:8px"></i>
                        </button>
                    </div>
                </div>
                `;
    }).join('')}
        </div>
    </div>
    `;
}

// Global aliases to ensure all app.js routes work
window.pageCareers = pageCareers;
window.pageCareer = pageCareers;
