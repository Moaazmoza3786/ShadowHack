/* ==================== PASSWORD CRACKING LAB 🔓💥 ==================== */
/* Hash Analysis, Wordlist Generation & Password Security */

window.PasswordLab = {
    // --- STATE ---
    currentTab: 'identifier',
    hashInput: '',
    identifiedHash: null,

    // --- HASH TYPES DATABASE ---
    hashTypes: [
        { name: 'MD5', length: 32, pattern: /^[a-f0-9]{32}$/i, example: '5f4dcc3b5aa765d61d8327deb882cf99', hashcat: 0, john: 'raw-md5' },
        { name: 'SHA-1', length: 40, pattern: /^[a-f0-9]{40}$/i, example: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', hashcat: 100, john: 'raw-sha1' },
        { name: 'SHA-256', length: 64, pattern: /^[a-f0-9]{64}$/i, example: '5e884898da28047d9167e5b32cc0bcea9b8d79165c7c6c4c7e4adef5e2a2bdcc', hashcat: 1400, john: 'raw-sha256' },
        { name: 'SHA-512', length: 128, pattern: /^[a-f0-9]{128}$/i, example: 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86', hashcat: 1700, john: 'raw-sha512' },
        { name: 'NTLM', length: 32, pattern: /^[a-f0-9]{32}$/i, example: 'a4f49c406510bdcab6824ee7c30fd852', hashcat: 1000, john: 'nt' },
        { name: 'bcrypt', length: 60, pattern: /^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$/, example: '$2b$12$EixZaYVK1fsbw1ZfbX3OXe.lFz7EIJLZnNJO4jqD9FKe3N6VZ3GKy', hashcat: 3200, john: 'bcrypt' },
        { name: 'MySQL5', length: 40, pattern: /^\*[A-F0-9]{40}$/i, example: '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19', hashcat: 300, john: 'mysql-sha1' },
        { name: 'SHA-512 (Unix)', length: 86, pattern: /^\$6\$/, example: '$6$rounds=5000$salt$hash', hashcat: 1800, john: 'sha512crypt' },
        { name: 'MD5 (Unix)', length: 34, pattern: /^\$1\$/, example: '$1$salt$hash', hashcat: 500, john: 'md5crypt' },
        { name: 'LM', length: 32, pattern: /^[a-f0-9]{32}$/i, example: 'aad3b435b51404eeaad3b435b51404ee', hashcat: 3000, john: 'lm' }
    ],

    // --- COMMON PASSWORDS (for demo) ---
    rockyouTop: [
        '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567',
        'dragon', '123123', 'baseball', 'iloveyou', 'trustno1', 'sunshine', 'master', 'welcome',
        'shadow', 'ashley', 'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1'
    ],

    // --- CHALLENGES ---
    challenges: [
        { id: 'md5-easy', name: 'MD5 Basics', difficulty: 'Easy', hash: '5f4dcc3b5aa765d61d8327deb882cf99', answer: 'password', points: 50 },
        { id: 'md5-med', name: 'Common Password', difficulty: 'Easy', hash: 'e10adc3949ba59abbe56e057f20f883e', answer: '123456', points: 50 },
        { id: 'sha1-1', name: 'SHA-1 Challenge', difficulty: 'Medium', hash: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8', answer: 'password', points: 100 },
        { id: 'sha256-1', name: 'SHA-256 Cracker', difficulty: 'Medium', hash: '5e884898da28047d9167e5b32cc0bcea9b8d79165c7c6c4c7e4adef5e2a2bdcc', answer: 'password', points: 100 },
        { id: 'ntlm-1', name: 'Windows NTLM', difficulty: 'Hard', hash: 'a4f49c406510bdcab6824ee7c30fd852', answer: 'password', points: 200 }
    ],

    solvedChallenges: JSON.parse(localStorage.getItem('password_solved') || '[]'),

    // --- RENDER ---
    render() {
        return `
            <div class="password-app fade-in">
                <div class="password-header">
                    <div class="header-left">
                        <h1><i class="fas fa-unlock-alt"></i> Password Cracking Lab</h1>
                        <p class="subtitle">Hash Analysis & Password Security</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat"><span class="val">${this.solvedChallenges.length}/${this.challenges.length}</span><span class="label">Cracked</span></div>
                    </div>
                </div>

                <div class="password-tabs">
                    <div class="tab ${this.currentTab === 'identifier' ? 'active' : ''}" onclick="PasswordLab.switchTab('identifier')">
                        <i class="fas fa-search"></i> Hash Identifier
                    </div>
                    <div class="tab ${this.currentTab === 'challenges' ? 'active' : ''}" onclick="PasswordLab.switchTab('challenges')">
                        <i class="fas fa-flag"></i> Challenges
                    </div>
                    <div class="tab ${this.currentTab === 'wordlist' ? 'active' : ''}" onclick="PasswordLab.switchTab('wordlist')">
                        <i class="fas fa-list"></i> Wordlist Gen
                    </div>
                    <div class="tab ${this.currentTab === 'commands' ? 'active' : ''}" onclick="PasswordLab.switchTab('commands')">
                        <i class="fas fa-terminal"></i> Commands
                    </div>
                </div>

                <div class="password-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'identifier': return this.renderIdentifier();
            case 'challenges': return this.renderChallenges();
            case 'wordlist': return this.renderWordlist();
            case 'commands': return this.renderCommands();
            default: return '';
        }
    },

    renderIdentifier() {
        return `
            <div class="identifier-section">
                <div class="id-input-area">
                    <h2><i class="fas fa-fingerprint"></i> Hash Identifier</h2>
                    <p>Paste a hash to identify its type</p>
                    <textarea id="hash-input" placeholder="Paste your hash here...">${this.hashInput}</textarea>
                    <button onclick="PasswordLab.identifyHash()"><i class="fas fa-search"></i> Identify</button>
                </div>

                ${this.identifiedHash ? `
                    <div class="id-result">
                        <h3><i class="fas fa-check-circle"></i> Possible Hash Types</h3>
                        <div class="hash-matches">
                            ${this.identifiedHash.map(h => `
                                <div class="hash-match">
                                    <div class="match-name">${h.name}</div>
                                    <div class="match-info">
                                        <span>Length: ${h.length}</span>
                                        <span>Hashcat: -m ${h.hashcat}</span>
                                        <span>John: --format=${h.john}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}

                <div class="hash-reference">
                    <h3><i class="fas fa-book"></i> Hash Reference</h3>
                    <table>
                        <thead><tr><th>Type</th><th>Length</th><th>Example</th><th>Hashcat</th></tr></thead>
                        <tbody>
                            ${this.hashTypes.slice(0, 6).map(h => `
                                <tr>
                                    <td>${h.name}</td>
                                    <td>${h.length}</td>
                                    <td><code>${h.example.substring(0, 24)}...</code></td>
                                    <td>-m ${h.hashcat}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    },

    renderChallenges() {
        return `
            <div class="challenges-section">
                <h2><i class="fas fa-flag"></i> Cracking Challenges</h2>
                <div class="challenges-grid">
                    ${this.challenges.map(c => {
            const solved = this.solvedChallenges.includes(c.id);
            return `
                            <div class="challenge-card ${solved ? 'solved' : ''}">
                                <div class="card-header">
                                    <h4>${c.name}</h4>
                                    <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                                </div>
                                <div class="card-hash">
                                    <code>${c.hash}</code>
                                    <button onclick="navigator.clipboard.writeText('${c.hash}')"><i class="fas fa-copy"></i></button>
                                </div>
                                ${solved ? `
                                    <div class="solved-badge"><i class="fas fa-check"></i> Cracked: ${c.answer}</div>
                                ` : `
                                    <div class="answer-input">
                                        <input type="text" id="ans-${c.id}" placeholder="Enter password...">
                                        <button onclick="PasswordLab.checkAnswer('${c.id}')"><i class="fas fa-unlock"></i></button>
                                    </div>
                                `}
                                <div class="card-points">${c.points} pts</div>
                            </div>
                        `;
        }).join('')}
                </div>
            </div>
        `;
    },

    renderWordlist() {
        return `
            <div class="wordlist-section">
                <h2><i class="fas fa-list"></i> Wordlist Generator</h2>
                
                <div class="gen-form">
                    <div class="form-row">
                        <label>Base Words (one per line)</label>
                        <textarea id="base-words" placeholder="company
name
year"></textarea>
                    </div>
                    <div class="form-options">
                        <label><input type="checkbox" id="opt-numbers" checked> Add numbers (1-999)</label>
                        <label><input type="checkbox" id="opt-symbols" checked> Add symbols (!@#$)</label>
                        <label><input type="checkbox" id="opt-case" checked> Case variations</label>
                        <label><input type="checkbox" id="opt-leet"> Leet speak (a→4, e→3)</label>
                    </div>
                    <button onclick="PasswordLab.generateWordlist()"><i class="fas fa-magic"></i> Generate</button>
                </div>

                <div class="wordlist-output">
                    <div class="output-header">
                        <span id="word-count">0 words</span>
                        <button onclick="PasswordLab.copyWordlist()"><i class="fas fa-copy"></i> Copy</button>
                        <button onclick="PasswordLab.downloadWordlist()"><i class="fas fa-download"></i> Download</button>
                    </div>
                    <textarea id="wordlist-result" readonly placeholder="Generated wordlist will appear here..."></textarea>
                </div>

                <div class="rockyou-preview">
                    <h3><i class="fas fa-fire"></i> RockYou Top 25</h3>
                    <div class="rockyou-list">
                        ${this.rockyouTop.map((w, i) => `<span class="rock-word">${i + 1}. ${w}</span>`).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderCommands() {
        return `
            <div class="commands-section">
                <h2><i class="fas fa-terminal"></i> Cracking Commands</h2>
                
                <div class="cmd-group">
                    <h3>Hashcat</h3>
                    <div class="cmd-item">
                        <span class="cmd-desc">Dictionary Attack</span>
                        <code>hashcat -m 0 hash.txt wordlist.txt</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Brute Force (8 chars)</span>
                        <code>hashcat -m 0 hash.txt -a 3 ?a?a?a?a?a?a?a?a</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Rules Attack</span>
                        <code>hashcat -m 0 hash.txt wordlist.txt -r rules/best64.rule</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Show Cracked</span>
                        <code>hashcat -m 0 hash.txt --show</code>
                    </div>
                </div>

                <div class="cmd-group">
                    <h3>John the Ripper</h3>
                    <div class="cmd-item">
                        <span class="cmd-desc">Auto Detect</span>
                        <code>john hash.txt</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Wordlist Mode</span>
                        <code>john --wordlist=rockyou.txt hash.txt</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Specific Format</span>
                        <code>john --format=raw-md5 hash.txt</code>
                    </div>
                    <div class="cmd-item">
                        <span class="cmd-desc">Show Cracked</span>
                        <code>john --show hash.txt</code>
                    </div>
                </div>

                <div class="cmd-group">
                    <h3>Online Resources</h3>
                    <div class="resources-list">
                        <a href="https://crackstation.net" target="_blank">CrackStation</a>
                        <a href="https://hashes.com" target="_blank">Hashes.com</a>
                        <a href="https://md5decrypt.net" target="_blank">MD5Decrypt</a>
                    </div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    identifyHash() {
        const input = document.getElementById('hash-input').value.trim();
        this.hashInput = input;

        if (!input) {
            this.identifiedHash = null;
            this.reRender();
            return;
        }

        const matches = this.hashTypes.filter(h => {
            if (h.pattern.test(input)) return true;
            if (input.length === h.length) return true;
            return false;
        });

        this.identifiedHash = matches.length > 0 ? matches : [{ name: 'Unknown', length: input.length, hashcat: '?', john: '?' }];
        this.reRender();
    },

    checkAnswer(id) {
        const challenge = this.challenges.find(c => c.id === id);
        const input = document.getElementById(`ans-${id}`).value.trim();

        if (input.toLowerCase() === challenge.answer.toLowerCase()) {
            if (!this.solvedChallenges.includes(id)) {
                this.solvedChallenges.push(id);
                localStorage.setItem('password_solved', JSON.stringify(this.solvedChallenges));
            }
            this.showNotification('🔓 Cracked! +' + challenge.points + ' pts', 'success');
            this.reRender();
        } else {
            this.showNotification('❌ Wrong password!', 'error');
        }
    },

    generateWordlist() {
        const baseWords = document.getElementById('base-words').value.split('\n').filter(w => w.trim());
        const addNumbers = document.getElementById('opt-numbers').checked;
        const addSymbols = document.getElementById('opt-symbols').checked;
        const caseVar = document.getElementById('opt-case').checked;
        const leetSpeak = document.getElementById('opt-leet').checked;

        let words = [...baseWords];

        if (caseVar) {
            const cased = [];
            words.forEach(w => {
                cased.push(w.toLowerCase());
                cased.push(w.toUpperCase());
                cased.push(w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
            });
            words = [...new Set([...words, ...cased])];
        }

        if (leetSpeak) {
            const leet = words.map(w => w.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5'));
            words = [...new Set([...words, ...leet])];
        }

        if (addNumbers) {
            const numbered = [];
            words.forEach(w => {
                for (let i = 0; i <= 99; i++) numbered.push(w + i);
                numbered.push(w + '123');
                numbered.push(w + '2024');
                numbered.push(w + '2023');
            });
            words = [...words, ...numbered];
        }

        if (addSymbols) {
            const symbols = ['!', '@', '#', '$', '!@#'];
            const symboled = [];
            words.forEach(w => symbols.forEach(s => symboled.push(w + s)));
            words = [...words, ...symboled];
        }

        document.getElementById('wordlist-result').value = words.join('\n');
        document.getElementById('word-count').textContent = words.length + ' words';
    },

    copyWordlist() {
        const text = document.getElementById('wordlist-result').value;
        navigator.clipboard.writeText(text);
        this.showNotification('Copied to clipboard!', 'success');
    },

    downloadWordlist() {
        const text = document.getElementById('wordlist-result').value;
        const blob = new Blob([text], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'wordlist.txt';
        a.click();
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `pass-notif ${type}`;
        n.innerHTML = msg;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    },

    reRender() {
        const app = document.querySelector('.password-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .password-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            .password-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .password-header h1 { margin: 0; color: #e74c3c; font-size: 1.8rem; }
            .password-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(231,76,60,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #e74c3c; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            .password-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #e74c3c; color: #fff; }

            /* IDENTIFIER */
            .identifier-section { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; }
            .id-input-area h2 { color: #e74c3c; margin: 0 0 10px; }
            .id-input-area p { color: #888; margin: 0 0 15px; }
            .id-input-area textarea { width: 100%; height: 80px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; padding: 12px; color: #00ff88; font-family: monospace; margin-bottom: 10px; }
            .id-input-area button { padding: 10px 20px; background: #e74c3c; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .id-result { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .id-result h3 { color: #2ecc71; margin: 0 0 15px; }
            .hash-match { background: rgba(46,204,113,0.1); padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 3px solid #2ecc71; }
            .match-name { font-weight: bold; color: #fff; margin-bottom: 8px; }
            .match-info span { display: inline-block; background: rgba(0,0,0,0.3); padding: 3px 10px; border-radius: 5px; margin-right: 8px; font-size: 0.8rem; color: #888; }

            .hash-reference { grid-column: 1 / -1; }
            .hash-reference h3 { color: #e74c3c; margin: 0 0 15px; }
            .hash-reference table { width: 100%; background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; }
            .hash-reference th, .hash-reference td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #222; }
            .hash-reference th { background: rgba(231,76,60,0.2); color: #e74c3c; }
            .hash-reference code { color: #888; font-size: 0.8rem; }

            /* CHALLENGES */
            .challenges-section h2 { color: #e74c3c; margin: 0 0 20px; }
            .challenges-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
            .challenge-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; position: relative; }
            .challenge-card.solved { border: 1px solid #2ecc71; }
            .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .card-header h4 { margin: 0; color: #fff; }
            .diff { padding: 3px 10px; border-radius: 10px; font-size: 0.7rem; font-weight: bold; }
            .diff.easy { background: #2ecc71; color: #000; }
            .diff.medium { background: #f39c12; color: #000; }
            .diff.hard { background: #e74c3c; color: #fff; }
            .card-hash { background: #0a0a12; padding: 12px; border-radius: 8px; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
            .card-hash code { flex: 1; color: #f39c12; font-size: 0.75rem; word-break: break-all; }
            .card-hash button { background: transparent; border: none; color: #666; cursor: pointer; }
            .solved-badge { background: #2ecc71; padding: 10px; border-radius: 8px; text-align: center; color: #fff; }
            .answer-input { display: flex; gap: 8px; }
            .answer-input input { flex: 1; padding: 10px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .answer-input button { padding: 10px 15px; background: #e74c3c; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .card-points { position: absolute; top: 15px; right: 15px; color: #ffd700; font-size: 0.8rem; }

            /* WORDLIST */
            .wordlist-section h2 { color: #e74c3c; margin: 0 0 20px; }
            .gen-form { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
            .form-row { margin-bottom: 15px; }
            .form-row label { display: block; color: #888; margin-bottom: 5px; }
            .form-row textarea { width: 100%; height: 80px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; padding: 12px; color: #fff; }
            .form-options { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 15px; }
            .form-options label { color: #aaa; font-size: 0.9rem; cursor: pointer; }
            .gen-form > button { padding: 12px 25px; background: #e74c3c; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

            .wordlist-output { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
            .output-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .output-header span { color: #888; }
            .output-header button { background: #333; border: none; padding: 8px 15px; border-radius: 5px; color: #fff; cursor: pointer; margin-left: 10px; }
            #wordlist-result { width: 100%; height: 150px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; padding: 12px; color: #00ff88; font-family: monospace; }

            .rockyou-preview h3 { color: #f39c12; margin: 0 0 15px; }
            .rockyou-list { display: flex; flex-wrap: wrap; gap: 10px; }
            .rock-word { background: rgba(243,156,18,0.1); padding: 5px 12px; border-radius: 15px; font-size: 0.85rem; color: #f39c12; }

            /* COMMANDS */
            .commands-section h2 { color: #e74c3c; margin: 0 0 20px; }
            .cmd-group { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
            .cmd-group h3 { color: #e74c3c; margin: 0 0 15px; font-size: 1.1rem; }
            .cmd-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #0a0a12; border-radius: 8px; margin-bottom: 10px; }
            .cmd-desc { color: #888; font-size: 0.9rem; }
            .cmd-item code { color: #2ecc71; font-family: monospace; font-size: 0.85rem; }
            .resources-list { display: flex; gap: 15px; }
            .resources-list a { background: rgba(231,76,60,0.2); color: #e74c3c; padding: 10px 20px; border-radius: 20px; text-decoration: none; }
            .resources-list a:hover { background: #e74c3c; color: #fff; }

            .pass-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 9999; animation: slideIn 0.3s ease; }
            .pass-notif.success { background: #2ecc71; color: #fff; }
            .pass-notif.error { background: #e74c3c; color: #fff; }
            @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

            @media (max-width: 900px) { .identifier-section { grid-template-columns: 1fr; } }
        </style>
        `;
    }
};

function pagePasswordLab() {
    return PasswordLab.render();
}
