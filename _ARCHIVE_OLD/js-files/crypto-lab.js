/* ==================== CRYPTOGRAPHY CHALLENGES LAB 🔐🧩 ==================== */
/* Cipher Puzzles, Hash Cracking & Cryptanalysis */

window.CryptoLab = {
    // --- STATE ---
    currentTab: 'challenges',
    selectedChallenge: null,
    userAnswer: '',
    solvedChallenges: JSON.parse(localStorage.getItem('crypto_solved') || '[]'),

    // --- CHALLENGES DATA ---
    challenges: [
        // EASY
        {
            id: 'caesar-1',
            name: 'Caesar Shift',
            difficulty: 'Easy',
            points: 50,
            category: 'Classical',
            description: 'Decrypt this Caesar cipher with shift of 3',
            ciphertext: 'WKLV LV D VHFUHW PHVVDJH',
            hint: 'Julius Caesar used this cipher. Try shifting each letter back by 3.',
            answer: 'THIS IS A SECRET MESSAGE'
        },
        {
            id: 'rot13-1',
            name: 'ROT13 Decoder',
            difficulty: 'Easy',
            points: 50,
            category: 'Classical',
            description: 'Decode this ROT13 encoded message',
            ciphertext: 'URYYB UNPXRE JBEYQ',
            hint: 'ROT13 shifts by 13. Fun fact: Applying it twice gives you the original!',
            answer: 'HELLO HACKER WORLD'
        },
        {
            id: 'base64-1',
            name: 'Base64 Secret',
            difficulty: 'Easy',
            points: 50,
            category: 'Encoding',
            description: 'Decode this Base64 encoded flag',
            ciphertext: 'QnJlYWNoTGFic3tCYXNlNjRfSXNfTm90X0VuY3J5cHRpb259',
            hint: 'Base64 uses A-Z, a-z, 0-9, +, and /',
            answer: 'BreachLabs{Base64_Is_Not_Encryption}'
        },
        // MEDIUM
        {
            id: 'vigenere-1',
            name: 'Vigenère Cipher',
            difficulty: 'Medium',
            points: 100,
            category: 'Classical',
            description: 'Decrypt using key: "HACK"',
            ciphertext: 'OPWMB ITNLB RWPMB',
            hint: 'Each letter in the key shifts the corresponding plaintext letter.',
            answer: 'HELLO CYBER WORLD'
        },
        {
            id: 'xor-1',
            name: 'XOR Challenge',
            difficulty: 'Medium',
            points: 100,
            category: 'Modern',
            description: 'XOR the hex bytes with key 0x42',
            ciphertext: '0x00 0x22 0x21 0x23 0x27 0x2B',
            hint: 'XOR is reversible: A ⊕ B ⊕ B = A',
            answer: 'BREACH'
        },
        {
            id: 'hash-1',
            name: 'Hash Cracker',
            difficulty: 'Medium',
            points: 100,
            category: 'Hashing',
            description: 'Crack this MD5 hash (common password)',
            ciphertext: '5f4dcc3b5aa765d61d8327deb882cf99',
            hint: 'This is one of the most common passwords in the world.',
            answer: 'password'
        },
        // HARD
        {
            id: 'aes-1',
            name: 'AES Puzzle',
            difficulty: 'Hard',
            points: 200,
            category: 'Modern',
            description: 'Find the key from the ciphertext pattern',
            ciphertext: 'U2FsdGVkX1+vupppZ...',
            hint: 'AES operates on 128-bit blocks. The key might be in the metadata.',
            answer: 'AES256_MASTER_KEY'
        },
        {
            id: 'rsa-1',
            name: 'RSA Baby',
            difficulty: 'Hard',
            points: 200,
            category: 'Asymmetric',
            description: 'Given n=77, e=7, c=10. Find m.',
            ciphertext: 'n=77, e=7, c=10',
            hint: 'n = p * q where p and q are primes. Here n = 7 * 11.',
            answer: '32'
        }
    ],

    // --- TOOLS DATA ---
    tools: [
        {
            name: 'Caesar Cipher',
            icon: 'fa-rotate',
            description: 'Shift letters by N positions',
            action: 'caesar'
        },
        {
            name: 'Base64',
            icon: 'fa-code',
            description: 'Encode/Decode Base64',
            action: 'base64'
        },
        {
            name: 'XOR',
            icon: 'fa-xmarks-lines',
            description: 'XOR with key',
            action: 'xor'
        },
        {
            name: 'MD5/SHA Hash',
            icon: 'fa-fingerprint',
            description: 'Generate hashes',
            action: 'hash'
        },
        {
            name: 'ROT13',
            icon: 'fa-repeat',
            description: 'ROT13 transform',
            action: 'rot13'
        },
        {
            name: 'Hex Converter',
            icon: 'fa-hashtag',
            description: 'Hex ↔ ASCII',
            action: 'hex'
        }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="crypto-app fade-in">
                <!-- HEADER -->
                <div class="crypto-header">
                    <div class="header-left">
                        <h1><i class="fas fa-lock-open"></i> Cryptography Lab</h1>
                        <p class="subtitle">Cipher Puzzles & Cryptanalysis Challenges</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat">
                            <span class="val">${this.solvedChallenges.length}</span>
                            <span class="label">Solved</span>
                        </div>
                        <div class="stat">
                            <span class="val">${this.getTotalPoints()}</span>
                            <span class="label">Points</span>
                        </div>
                    </div>
                </div>

                <!-- TABS -->
                <div class="crypto-tabs">
                    <div class="tab ${this.currentTab === 'challenges' ? 'active' : ''}" onclick="CryptoLab.switchTab('challenges')">
                        <i class="fas fa-puzzle-piece"></i> Challenges
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="CryptoLab.switchTab('tools')">
                        <i class="fas fa-tools"></i> Crypto Tools
                    </div>
                    <div class="tab ${this.currentTab === 'learn' ? 'active' : ''}" onclick="CryptoLab.switchTab('learn')">
                        <i class="fas fa-book"></i> Learn
                    </div>
                </div>

                <!-- CONTENT -->
                <div class="crypto-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'challenges': return this.renderChallenges();
            case 'tools': return this.renderTools();
            case 'learn': return this.renderLearn();
            default: return '';
        }
    },

    renderChallenges() {
        const easy = this.challenges.filter(c => c.difficulty === 'Easy');
        const medium = this.challenges.filter(c => c.difficulty === 'Medium');
        const hard = this.challenges.filter(c => c.difficulty === 'Hard');

        return `
            <div class="challenges-container">
                <div class="challenge-list">
                    <div class="difficulty-section">
                        <h3><span class="diff-badge easy">Easy</span> ${easy.length} Challenges</h3>
                        ${easy.map(c => this.renderChallengeCard(c)).join('')}
                    </div>
                    <div class="difficulty-section">
                        <h3><span class="diff-badge medium">Medium</span> ${medium.length} Challenges</h3>
                        ${medium.map(c => this.renderChallengeCard(c)).join('')}
                    </div>
                    <div class="difficulty-section">
                        <h3><span class="diff-badge hard">Hard</span> ${hard.length} Challenges</h3>
                        ${hard.map(c => this.renderChallengeCard(c)).join('')}
                    </div>
                </div>
                ${this.selectedChallenge ? this.renderChallengeDetail() : `
                    <div class="no-selection">
                        <i class="fas fa-hand-pointer"></i>
                        <p>Select a challenge to begin</p>
                    </div>
                `}
            </div>
        `;
    },

    renderChallengeCard(c) {
        const solved = this.solvedChallenges.includes(c.id);
        return `
            <div class="challenge-card ${solved ? 'solved' : ''} ${this.selectedChallenge === c.id ? 'active' : ''}" onclick="CryptoLab.selectChallenge('${c.id}')">
                <div class="card-icon">
                    ${solved ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-lock"></i>'}
                </div>
                <div class="card-info">
                    <span class="card-name">${c.name}</span>
                    <span class="card-category">${c.category}</span>
                </div>
                <div class="card-points">${c.points} pts</div>
            </div>
        `;
    },

    renderChallengeDetail() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        if (!c) return '';
        const solved = this.solvedChallenges.includes(c.id);

        return `
            <div class="challenge-detail">
                <div class="detail-header">
                    <h2>${c.name}</h2>
                    <div class="detail-meta">
                        <span class="diff-badge ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                        <span class="cat-badge">${c.category}</span>
                        <span class="pts-badge">${c.points} pts</span>
                    </div>
                </div>
                <p class="detail-desc">${c.description}</p>
                
                <div class="cipher-box">
                    <div class="cipher-label">Ciphertext</div>
                    <code class="cipher-text">${c.ciphertext}</code>
                    <button class="copy-btn" onclick="navigator.clipboard.writeText('${c.ciphertext}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>

                <div class="hint-box" onclick="this.classList.toggle('revealed')">
                    <div class="hint-label"><i class="fas fa-lightbulb"></i> Click to reveal hint</div>
                    <div class="hint-text">${c.hint}</div>
                </div>

                ${solved ? `
                    <div class="solved-banner">
                        <i class="fas fa-trophy"></i> Challenge Solved!
                    </div>
                ` : `
                    <div class="answer-box">
                        <input type="text" id="answer-input" placeholder="Enter your answer..." value="${this.userAnswer}" onkeyup="CryptoLab.userAnswer = this.value; if(event.key === 'Enter') CryptoLab.submitAnswer()">
                        <button onclick="CryptoLab.submitAnswer()">
                            <i class="fas fa-flag"></i> Submit
                        </button>
                    </div>
                `}
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-container">
                <div class="tools-grid">
                    ${this.tools.map(t => `
                        <div class="tool-card" onclick="CryptoLab.openTool('${t.action}')">
                            <i class="fas ${t.icon}"></i>
                            <h4>${t.name}</h4>
                            <p>${t.description}</p>
                        </div>
                    `).join('')}
                </div>
                <div class="tool-workspace">
                    <h3><i class="fas fa-flask"></i> Workspace</h3>
                    <div class="workspace-row">
                        <label>Input</label>
                        <textarea id="crypto-input" placeholder="Enter text to process..."></textarea>
                    </div>
                    <div class="workspace-controls">
                        <select id="crypto-operation">
                            <option value="caesar">Caesar (Shift 3)</option>
                            <option value="rot13">ROT13</option>
                            <option value="base64-enc">Base64 Encode</option>
                            <option value="base64-dec">Base64 Decode</option>
                            <option value="hex-enc">Text to Hex</option>
                            <option value="hex-dec">Hex to Text</option>
                        </select>
                        <button onclick="CryptoLab.processInput()">
                            <i class="fas fa-play"></i> Process
                        </button>
                    </div>
                    <div class="workspace-row">
                        <label>Output</label>
                        <textarea id="crypto-output" readonly placeholder="Result will appear here..."></textarea>
                    </div>
                </div>
            </div>
        `;
    },

    renderLearn() {
        return `
            <div class="learn-container">
                <div class="learn-card">
                    <h3><i class="fas fa-history"></i> Classical Ciphers</h3>
                    <p>Ancient encryption methods like Caesar, Vigenère, and substitution ciphers.</p>
                    <ul>
                        <li><strong>Caesar Cipher:</strong> Shifts each letter by a fixed amount</li>
                        <li><strong>Vigenère:</strong> Uses a keyword for polyalphabetic substitution</li>
                        <li><strong>Atbash:</strong> Reverses the alphabet (A↔Z, B↔Y...)</li>
                    </ul>
                </div>
                <div class="learn-card">
                    <h3><i class="fas fa-microchip"></i> Modern Encryption</h3>
                    <p>Symmetric and asymmetric algorithms used in today's security.</p>
                    <ul>
                        <li><strong>AES:</strong> Advanced Encryption Standard (128/256-bit blocks)</li>
                        <li><strong>RSA:</strong> Public-key cryptography using prime factorization</li>
                        <li><strong>XOR:</strong> Bitwise operation fundamental to many ciphers</li>
                    </ul>
                </div>
                <div class="learn-card">
                    <h3><i class="fas fa-fingerprint"></i> Hashing</h3>
                    <p>One-way functions for integrity and password storage.</p>
                    <ul>
                        <li><strong>MD5:</strong> 128-bit hash (deprecated, vulnerable)</li>
                        <li><strong>SHA-256:</strong> Secure 256-bit hash from SHA-2 family</li>
                        <li><strong>bcrypt:</strong> Adaptive hashing for passwords</li>
                    </ul>
                </div>
                <div class="learn-card">
                    <h3><i class="fas fa-code"></i> Encoding vs Encryption</h3>
                    <p>Encoding (Base64, Hex) is NOT encryption - it's reversible without a key!</p>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    selectChallenge(id) {
        this.selectedChallenge = id;
        this.userAnswer = '';
        this.reRender();
    },

    submitAnswer() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        if (!c) return;

        if (this.userAnswer.trim().toUpperCase() === c.answer.toUpperCase()) {
            if (!this.solvedChallenges.includes(c.id)) {
                this.solvedChallenges.push(c.id);
                localStorage.setItem('crypto_solved', JSON.stringify(this.solvedChallenges));
            }
            this.showNotification('🎉 Correct! +' + c.points + ' points', 'success');
        } else {
            this.showNotification('❌ Incorrect. Try again!', 'error');
        }
        this.reRender();
    },

    processInput() {
        const input = document.getElementById('crypto-input').value;
        const op = document.getElementById('crypto-operation').value;
        let output = '';

        switch (op) {
            case 'caesar':
                output = this.caesarShift(input, 3);
                break;
            case 'rot13':
                output = this.rot13(input);
                break;
            case 'base64-enc':
                output = btoa(input);
                break;
            case 'base64-dec':
                try { output = atob(input); } catch { output = 'Invalid Base64'; }
                break;
            case 'hex-enc':
                output = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                break;
            case 'hex-dec':
                output = input.replace(/\s/g, '').match(/.{2}/g)?.map(h => String.fromCharCode(parseInt(h, 16))).join('') || '';
                break;
        }
        document.getElementById('crypto-output').value = output;
    },

    caesarShift(text, shift) {
        return text.toUpperCase().split('').map(c => {
            if (c >= 'A' && c <= 'Z') {
                return String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26) + 65);
            }
            return c;
        }).join('');
    },

    rot13(text) {
        return this.caesarShift(text, 13);
    },

    openTool(action) {
        document.getElementById('crypto-operation').value = action === 'caesar' ? 'caesar' :
            action === 'base64' ? 'base64-enc' :
                action === 'rot13' ? 'rot13' :
                    action === 'hex' ? 'hex-enc' : 'caesar';
    },

    getTotalPoints() {
        return this.challenges.filter(c => this.solvedChallenges.includes(c.id))
            .reduce((sum, c) => sum + c.points, 0);
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `crypto-notif ${type}`;
        n.innerHTML = msg;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    },

    reRender() {
        const app = document.querySelector('.crypto-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .crypto-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            /* HEADER */
            .crypto-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .crypto-header h1 { margin: 0; color: #ffd700; font-size: 1.8rem; }
            .crypto-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats { display: flex; gap: 20px; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(255,215,0,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #ffd700; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            /* TABS */
            .crypto-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #ffd700; color: #000; }

            /* CHALLENGES */
            .challenges-container { display: grid; grid-template-columns: 350px 1fr; gap: 25px; }
            .challenge-list { max-height: 70vh; overflow-y: auto; }
            .difficulty-section { margin-bottom: 25px; }
            .difficulty-section h3 { color: #888; margin: 0 0 10px; font-size: 0.9rem; }
            
            .diff-badge { padding: 3px 10px; border-radius: 10px; font-size: 0.75rem; font-weight: bold; margin-right: 8px; }
            .diff-badge.easy { background: #2ecc71; color: #000; }
            .diff-badge.medium { background: #f39c12; color: #000; }
            .diff-badge.hard { background: #e74c3c; color: #fff; }

            .challenge-card { display: flex; align-items: center; gap: 12px; padding: 15px; background: rgba(255,255,255,0.03); border-radius: 10px; cursor: pointer; margin-bottom: 10px; transition: 0.2s; border: 1px solid transparent; }
            .challenge-card:hover { background: rgba(255,255,255,0.08); transform: translateX(5px); }
            .challenge-card.active { border-color: #ffd700; background: rgba(255,215,0,0.1); }
            .challenge-card.solved .card-icon { color: #2ecc71; }
            .card-icon { font-size: 1.2rem; color: #888; width: 30px; }
            .card-info { flex: 1; }
            .card-name { display: block; color: #fff; font-weight: 500; }
            .card-category { color: #666; font-size: 0.8rem; }
            .card-points { color: #ffd700; font-weight: bold; }

            .no-selection { text-align: center; padding: 80px; color: #555; }
            .no-selection i { font-size: 3rem; margin-bottom: 15px; }

            /* CHALLENGE DETAIL */
            .challenge-detail { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .detail-header h2 { margin: 0 0 10px; color: #fff; }
            .detail-meta { display: flex; gap: 10px; margin-bottom: 15px; }
            .cat-badge { background: rgba(102, 126, 234, 0.3); color: #667eea; padding: 3px 10px; border-radius: 10px; font-size: 0.75rem; }
            .pts-badge { background: rgba(255,215,0,0.2); color: #ffd700; padding: 3px 10px; border-radius: 10px; font-size: 0.75rem; }
            .detail-desc { color: #aaa; margin-bottom: 20px; }

            .cipher-box { background: #0a0a12; padding: 20px; border-radius: 10px; position: relative; margin-bottom: 15px; }
            .cipher-label { color: #ffd700; font-size: 0.8rem; margin-bottom: 10px; }
            .cipher-text { display: block; color: #00ff88; font-family: monospace; font-size: 1.1rem; word-break: break-all; }
            .copy-btn { position: absolute; top: 10px; right: 10px; background: transparent; border: none; color: #666; cursor: pointer; }
            .copy-btn:hover { color: #ffd700; }

            .hint-box { background: rgba(255,215,0,0.1); padding: 15px; border-radius: 10px; cursor: pointer; margin-bottom: 20px; }
            .hint-label { color: #ffd700; }
            .hint-text { display: none; color: #aaa; margin-top: 10px; }
            .hint-box.revealed .hint-text { display: block; }

            .solved-banner { background: linear-gradient(90deg, #2ecc71, #27ae60); padding: 15px; border-radius: 10px; text-align: center; color: #fff; font-weight: bold; }

            .answer-box { display: flex; gap: 10px; }
            .answer-box input { flex: 1; padding: 12px 15px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 1rem; }
            .answer-box button { padding: 12px 25px; background: #ffd700; border: none; border-radius: 8px; color: #000; font-weight: bold; cursor: pointer; }
            .answer-box button:hover { background: #ffed4a; }

            /* TOOLS */
            .tools-container { display: grid; grid-template-columns: 300px 1fr; gap: 25px; }
            .tools-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
            .tool-card { background: rgba(255,255,255,0.03); padding: 20px; border-radius: 12px; text-align: center; cursor: pointer; transition: 0.2s; border: 1px solid transparent; }
            .tool-card:hover { border-color: #ffd700; background: rgba(255,215,0,0.1); transform: translateY(-3px); }
            .tool-card i { font-size: 2rem; color: #ffd700; margin-bottom: 10px; }
            .tool-card h4 { margin: 0 0 5px; color: #fff; }
            .tool-card p { margin: 0; color: #666; font-size: 0.85rem; }

            .tool-workspace { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .tool-workspace h3 { color: #ffd700; margin: 0 0 20px; }
            .workspace-row { margin-bottom: 15px; }
            .workspace-row label { display: block; color: #888; margin-bottom: 5px; }
            .workspace-row textarea { width: 100%; height: 100px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; padding: 12px; color: #00ff88; font-family: monospace; resize: vertical; }
            .workspace-controls { display: flex; gap: 10px; margin-bottom: 15px; }
            .workspace-controls select { flex: 1; padding: 10px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .workspace-controls button { padding: 10px 20px; background: #ffd700; border: none; border-radius: 8px; color: #000; font-weight: bold; cursor: pointer; }

            /* LEARN */
            .learn-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .learn-card { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .learn-card h3 { color: #ffd700; margin: 0 0 15px; }
            .learn-card p { color: #aaa; margin-bottom: 15px; }
            .learn-card ul { margin: 0; padding-left: 20px; color: #888; }
            .learn-card li { margin-bottom: 8px; }
            .learn-card strong { color: #00ff88; }

            /* NOTIFICATION */
            .crypto-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 9999; animation: slideIn 0.3s ease; }
            .crypto-notif.success { background: #2ecc71; color: #fff; }
            .crypto-notif.error { background: #e74c3c; color: #fff; }
            @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

            @media (max-width: 1024px) {
                .challenges-container, .tools-container { grid-template-columns: 1fr; }
            }
        </style>
        `;
    }
};

function pageCryptoLab() {
    return CryptoLab.render();
}
