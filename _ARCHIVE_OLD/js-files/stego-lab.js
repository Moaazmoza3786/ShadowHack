/* ==================== STEGANOGRAPHY LAB 🖼️🕵️ ==================== */
/* Hidden Data Analysis & Extraction */

window.StegoLab = {
    // --- STATE ---
    currentTab: 'challenges',
    selectedChallenge: null,
    solvedChallenges: JSON.parse(localStorage.getItem('stego_solved') || '[]'),

    // --- CHALLENGES DATA ---
    challenges: [
        {
            id: 'lsb-1',
            name: 'Hidden in Plain Sight',
            difficulty: 'Easy',
            points: 50,
            category: 'LSB',
            description: 'Extract the hidden message from the image using LSB technique.',
            image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgZmlsbD0iIzMzMyIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmaWxsPSIjMDBmZjg4IiBmb250LXNpemU9IjE2IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkeT0iLjNlbSI+U3RlZ28gSW1hZ2U8L3RleHQ+PC9zdmc+',
            hint: 'Look at the least significant bit of each pixel. The flag is hidden in the red channel.',
            answer: 'HIDDEN_FLAG'
        },
        {
            id: 'strings-1',
            name: 'Metadata Secrets',
            difficulty: 'Easy',
            points: 50,
            category: 'Metadata',
            description: 'Check the image metadata (EXIF) for hidden information.',
            image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgZmlsbD0iIzQ0NCIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmaWxsPSIjZmY4ODAwIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkeT0iLjNlbSI+Q2hlY2sgTWV0YWRhdGE8L3RleHQ+PC9zdmc+',
            hint: 'Use exiftool or strings command. The flag might be in the Comment field.',
            answer: 'METADATA_SECRET'
        },
        {
            id: 'audio-1',
            name: 'Spectrogram Message',
            difficulty: 'Medium',
            points: 100,
            category: 'Audio',
            description: 'Analyze the audio spectrogram to find the hidden image.',
            image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgZmlsbD0iIzIyMiIvPjx0ZXh0IHg9IjUwJSIgeT0iNDUlIiBmaWxsPSIjMDBjY2ZmIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5BdWRpbyBTcGVjdHJvZ3JhbTwvdGV4dD48dGV4dCB4PSI1MCUiIHk9IjU1JSIgZmlsbD0iIzg4OCIgZm9udC1zaXplPSIxMCIgdGV4dC1hbmNob3I9Im1pZGRsZSI+VXNlIEF1ZGFjaXR5PC90ZXh0Pjwvc3ZnPg==',
            hint: 'Open in Audacity and view the spectrogram. The message appears visually.',
            answer: 'SPECTROGRAM_FLAG'
        },
        {
            id: 'zip-1',
            name: 'File Inception',
            difficulty: 'Medium',
            points: 100,
            category: 'Polyglot',
            description: 'This image is also a ZIP file. Extract the hidden content.',
            image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgZmlsbD0iIzE1MTUyMCIvPjx0ZXh0IHg9IjUwJSIgeT0iNDUlIiBmaWxsPSIjZmY0NDU1IiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5Qb2x5Z2xvdCBGaWxlPC90ZXh0Pjx0ZXh0IHg9IjUwJSIgeT0iNTUlIiBmaWxsPSIjNjY2IiBmb250LXNpemU9IjEwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5JbWFnZSArIFpJUDwvdGV4dD48L3N2Zz4=',
            hint: 'Try renaming the file to .zip and extracting it.',
            answer: 'POLYGLOT_FILE'
        },
        {
            id: 'whitespace-1',
            name: 'Invisible Text',
            difficulty: 'Hard',
            points: 200,
            category: 'Whitespace',
            description: 'There are hidden characters in this text. Find them.',
            image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgZmlsbD0iI2ZmZiIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmaWxsPSIjMDAwIiBmb250LXNpemU9IjEyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkeT0iLjNlbSI+V2hpdGVzcGFjZSBIaWRlczwvdGV4dD48L3N2Zz4=',
            hint: 'Look for zero-width characters or tab/space patterns (Snow cipher).',
            answer: 'WHITESPACE_SECRET'
        }
    ],

    // --- TOOLS DATA ---
    tools: [
        { name: 'Strings Extractor', icon: 'fa-font', description: 'Find readable strings in files' },
        { name: 'Hex Editor', icon: 'fa-code', description: 'View raw hex bytes' },
        { name: 'LSB Analyzer', icon: 'fa-eye', description: 'Extract least significant bits' },
        { name: 'EXIF Viewer', icon: 'fa-info-circle', description: 'Read image metadata' },
        { name: 'Binwalk Sim', icon: 'fa-file-archive', description: 'Find embedded files' },
        { name: 'QR Decoder', icon: 'fa-qrcode', description: 'Decode QR codes' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="stego-app fade-in">
                <!-- HEADER -->
                <div class="stego-header">
                    <div class="header-left">
                        <h1><i class="fas fa-eye-slash"></i> Steganography Lab</h1>
                        <p class="subtitle">Hidden Data Analysis & Extraction</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat">
                            <span class="val">${this.solvedChallenges.length}/${this.challenges.length}</span>
                            <span class="label">Solved</span>
                        </div>
                        <div class="stat">
                            <span class="val">${this.getTotalPoints()}</span>
                            <span class="label">Points</span>
                        </div>
                    </div>
                </div>

                <!-- TABS -->
                <div class="stego-tabs">
                    <div class="tab ${this.currentTab === 'challenges' ? 'active' : ''}" onclick="StegoLab.switchTab('challenges')">
                        <i class="fas fa-puzzle-piece"></i> Challenges
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="StegoLab.switchTab('tools')">
                        <i class="fas fa-tools"></i> Analysis Tools
                    </div>
                    <div class="tab ${this.currentTab === 'encoder' ? 'active' : ''}" onclick="StegoLab.switchTab('encoder')">
                        <i class="fas fa-lock"></i> Encode Data
                    </div>
                </div>

                <!-- CONTENT -->
                <div class="stego-content">
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
            case 'encoder': return this.renderEncoder();
            default: return '';
        }
    },

    renderChallenges() {
        return `
            <div class="challenges-grid">
                ${this.challenges.map(c => {
            const solved = this.solvedChallenges.includes(c.id);
            return `
                        <div class="stego-card ${solved ? 'solved' : ''}" onclick="StegoLab.openChallenge('${c.id}')">
                            <div class="card-image">
                                <img src="${c.image}" alt="${c.name}">
                                ${solved ? '<div class="solved-badge"><i class="fas fa-check"></i></div>' : ''}
                            </div>
                            <div class="card-body">
                                <h3>${c.name}</h3>
                                <div class="card-meta">
                                    <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                                    <span class="cat">${c.category}</span>
                                    <span class="pts">${c.points} pts</span>
                                </div>
                                <p>${c.description}</p>
                            </div>
                        </div>
                    `;
        }).join('')}
            </div>
            ${this.selectedChallenge ? this.renderChallengeModal() : ''}
        `;
    },

    renderChallengeModal() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        if (!c) return '';
        const solved = this.solvedChallenges.includes(c.id);

        return `
            <div class="modal-overlay" onclick="StegoLab.closeChallenge()">
                <div class="challenge-modal" onclick="event.stopPropagation()">
                    <button class="close-btn" onclick="StegoLab.closeChallenge()"><i class="fas fa-times"></i></button>
                    <div class="modal-image">
                        <img src="${c.image}" alt="${c.name}">
                    </div>
                    <div class="modal-content">
                        <h2>${c.name}</h2>
                        <div class="modal-meta">
                            <span class="diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                            <span class="cat">${c.category}</span>
                            <span class="pts">${c.points} pts</span>
                        </div>
                        <p class="modal-desc">${c.description}</p>
                        
                        <div class="hint-box" onclick="this.classList.toggle('revealed')">
                            <span class="hint-label"><i class="fas fa-lightbulb"></i> Hint (click to reveal)</span>
                            <span class="hint-text">${c.hint}</span>
                        </div>

                        ${solved ? `
                            <div class="solved-banner"><i class="fas fa-trophy"></i> Solved!</div>
                        ` : `
                            <div class="answer-form">
                                <input type="text" id="stego-answer" placeholder="Enter the flag...">
                                <button onclick="StegoLab.submitAnswer()"><i class="fas fa-flag"></i> Submit</button>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-section">
                <div class="tools-grid">
                    ${this.tools.map(t => `
                        <div class="tool-card">
                            <i class="fas ${t.icon}"></i>
                            <h4>${t.name}</h4>
                            <p>${t.description}</p>
                        </div>
                    `).join('')}
                </div>
                <div class="analysis-workspace">
                    <h3><i class="fas fa-search"></i> File Analysis</h3>
                    <div class="upload-zone" onclick="document.getElementById('stego-upload').click()">
                        <i class="fas fa-cloud-upload-alt"></i>
                        <p>Drop file or click to upload</p>
                        <input type="file" id="stego-upload" style="display:none" onchange="StegoLab.analyzeFile(event)">
                    </div>
                    <div class="analysis-results" id="stego-results">
                        <div class="placeholder">Upload a file to begin analysis</div>
                    </div>
                </div>
            </div>
        `;
    },

    renderEncoder() {
        return `
            <div class="encoder-section">
                <h3><i class="fas fa-lock"></i> Hide Data in Text</h3>
                <p class="encoder-desc">Encode secret messages using zero-width characters</p>
                
                <div class="encoder-form">
                    <div class="form-row">
                        <label>Cover Text (visible)</label>
                        <textarea id="cover-text" placeholder="Enter the visible text...">This looks like a normal message</textarea>
                    </div>
                    <div class="form-row">
                        <label>Secret Message</label>
                        <input type="text" id="secret-msg" placeholder="Hidden message...">
                    </div>
                    <button class="encode-btn" onclick="StegoLab.encodeMessage()">
                        <i class="fas fa-magic"></i> Encode
                    </button>
                </div>

                <div class="form-row">
                    <label>Result (copy this)</label>
                    <textarea id="encoded-result" readonly placeholder="Encoded text will appear here..."></textarea>
                    <button class="copy-btn" onclick="StegoLab.copyResult()"><i class="fas fa-copy"></i> Copy</button>
                </div>

                <hr>

                <h3><i class="fas fa-unlock"></i> Decode Hidden Data</h3>
                <div class="form-row">
                    <label>Paste Encoded Text</label>
                    <textarea id="decode-input" placeholder="Paste text with hidden message..."></textarea>
                </div>
                <button class="decode-btn" onclick="StegoLab.decodeMessage()">
                    <i class="fas fa-search"></i> Decode
                </button>
                <div class="decode-result" id="decode-result"></div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    openChallenge(id) {
        this.selectedChallenge = id;
        this.reRender();
    },

    closeChallenge() {
        this.selectedChallenge = null;
        this.reRender();
    },

    submitAnswer() {
        const c = this.challenges.find(ch => ch.id === this.selectedChallenge);
        const answer = document.getElementById('stego-answer').value.trim();

        if (answer.toUpperCase() === c.answer.toUpperCase()) {
            if (!this.solvedChallenges.includes(c.id)) {
                this.solvedChallenges.push(c.id);
                localStorage.setItem('stego_solved', JSON.stringify(this.solvedChallenges));
            }
            this.showNotification('🎉 Correct! +' + c.points + ' points', 'success');
            this.reRender();
        } else {
            this.showNotification('❌ Incorrect. Try again!', 'error');
        }
    },

    analyzeFile(event) {
        const file = event.target.files[0];
        if (!file) return;

        const results = document.getElementById('stego-results');
        results.innerHTML = `
            <div class="result-item"><strong>Filename:</strong> ${file.name}</div>
            <div class="result-item"><strong>Type:</strong> ${file.type || 'Unknown'}</div>
            <div class="result-item"><strong>Size:</strong> ${(file.size / 1024).toFixed(2)} KB</div>
            <hr>
            <div class="result-item"><strong>Simulated Analysis:</strong></div>
            <div class="result-item">• No obvious strings found</div>
            <div class="result-item">• File header appears normal</div>
            <div class="result-item">• Run binwalk for embedded files</div>
            <div class="result-item">• Try LSB extraction tools</div>
        `;
    },

    encodeMessage() {
        const cover = document.getElementById('cover-text').value;
        const secret = document.getElementById('secret-msg').value;

        // Simple zero-width encoding simulation
        const zwc = secret.split('').map(c => {
            const bin = c.charCodeAt(0).toString(2).padStart(8, '0');
            return bin.split('').map(b => b === '0' ? '\u200B' : '\u200C').join('');
        }).join('\u200D');

        document.getElementById('encoded-result').value = cover + zwc;
    },

    decodeMessage() {
        const input = document.getElementById('decode-input').value;
        const zwChars = input.match(/[\u200B\u200C\u200D]/g);

        if (!zwChars || zwChars.length === 0) {
            document.getElementById('decode-result').innerHTML = '<span class="no-data">No hidden data found</span>';
            return;
        }

        // Decode simulation
        const chunks = input.split('\u200D').filter(c => c.match(/[\u200B\u200C]/));
        let decoded = '';
        chunks.forEach(chunk => {
            const bin = chunk.split('').map(c => c === '\u200B' ? '0' : '1').join('');
            decoded += String.fromCharCode(parseInt(bin, 2));
        });

        document.getElementById('decode-result').innerHTML = `<span class="found-data">Found: <code>${decoded || 'Encoded pattern detected'}</code></span>`;
    },

    copyResult() {
        const text = document.getElementById('encoded-result').value;
        navigator.clipboard.writeText(text);
        this.showNotification('Copied to clipboard!', 'success');
    },

    getTotalPoints() {
        return this.challenges.filter(c => this.solvedChallenges.includes(c.id))
            .reduce((sum, c) => sum + c.points, 0);
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `stego-notif ${type}`;
        n.innerHTML = msg;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 3000);
    },

    reRender() {
        const app = document.querySelector('.stego-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .stego-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            .stego-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .stego-header h1 { margin: 0; color: #a855f7; font-size: 1.8rem; }
            .stego-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats { display: flex; gap: 20px; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(168,85,247,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #a855f7; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            .stego-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #a855f7; color: #fff; }

            /* CHALLENGES GRID */
            .challenges-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
            .stego-card { background: rgba(0,0,0,0.3); border-radius: 15px; overflow: hidden; cursor: pointer; transition: 0.3s; border: 1px solid transparent; }
            .stego-card:hover { transform: translateY(-5px); border-color: #a855f7; }
            .stego-card.solved { border-color: #2ecc71; }
            .card-image { position: relative; height: 150px; background: #222; display: flex; align-items: center; justify-content: center; }
            .card-image img { max-width: 100%; max-height: 100%; }
            .solved-badge { position: absolute; top: 10px; right: 10px; background: #2ecc71; color: #fff; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
            .card-body { padding: 15px; }
            .card-body h3 { margin: 0 0 10px; color: #fff; }
            .card-meta { display: flex; gap: 8px; margin-bottom: 10px; }
            .card-meta span { padding: 3px 10px; border-radius: 10px; font-size: 0.7rem; }
            .diff { font-weight: bold; }
            .diff.easy { background: #2ecc71; color: #000; }
            .diff.medium { background: #f39c12; color: #000; }
            .diff.hard { background: #e74c3c; color: #fff; }
            .cat { background: rgba(168,85,247,0.3); color: #a855f7; }
            .pts { background: rgba(255,215,0,0.2); color: #ffd700; }
            .card-body p { margin: 0; color: #888; font-size: 0.85rem; }

            /* MODAL */
            .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; display: flex; align-items: center; justify-content: center; }
            .challenge-modal { background: #1a1a2e; border-radius: 20px; max-width: 600px; width: 90%; position: relative; overflow: hidden; }
            .close-btn { position: absolute; top: 15px; right: 15px; background: rgba(255,255,255,0.1); border: none; color: #fff; width: 35px; height: 35px; border-radius: 50%; cursor: pointer; z-index: 10; }
            .modal-image { height: 200px; background: #222; display: flex; align-items: center; justify-content: center; }
            .modal-image img { max-width: 100%; max-height: 100%; }
            .modal-content { padding: 25px; }
            .modal-content h2 { margin: 0 0 10px; color: #fff; }
            .modal-meta { display: flex; gap: 10px; margin-bottom: 15px; }
            .modal-desc { color: #aaa; margin-bottom: 20px; }
            
            .hint-box { background: rgba(168,85,247,0.1); padding: 12px 15px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; }
            .hint-label { color: #a855f7; }
            .hint-text { display: none; color: #aaa; margin-top: 8px; }
            .hint-box.revealed .hint-text { display: block; }

            .solved-banner { background: #2ecc71; padding: 15px; border-radius: 10px; text-align: center; color: #fff; font-weight: bold; }
            .answer-form { display: flex; gap: 10px; }
            .answer-form input { flex: 1; padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .answer-form button { padding: 12px 20px; background: #a855f7; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

            /* TOOLS */
            .tools-section { display: grid; grid-template-columns: 300px 1fr; gap: 25px; }
            .tools-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
            .tool-card { background: rgba(255,255,255,0.03); padding: 15px; border-radius: 10px; text-align: center; border: 1px solid transparent; transition: 0.2s; cursor: pointer; }
            .tool-card:hover { border-color: #a855f7; }
            .tool-card i { font-size: 1.8rem; color: #a855f7; margin-bottom: 8px; }
            .tool-card h4 { margin: 0 0 5px; color: #fff; font-size: 0.9rem; }
            .tool-card p { margin: 0; color: #666; font-size: 0.75rem; }

            .analysis-workspace { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 15px; }
            .analysis-workspace h3 { color: #a855f7; margin: 0 0 15px; }
            .upload-zone { border: 2px dashed #444; padding: 40px; text-align: center; border-radius: 10px; cursor: pointer; transition: 0.2s; }
            .upload-zone:hover { border-color: #a855f7; }
            .upload-zone i { font-size: 2rem; color: #a855f7; margin-bottom: 10px; }
            .analysis-results { margin-top: 15px; padding: 15px; background: #0a0a12; border-radius: 8px; font-family: monospace; font-size: 0.85rem; }
            .result-item { padding: 5px 0; color: #aaa; }
            .placeholder { color: #555; text-align: center; }

            /* ENCODER */
            .encoder-section { max-width: 700px; margin: 0 auto; }
            .encoder-section h3 { color: #a855f7; margin: 0 0 10px; }
            .encoder-desc { color: #888; margin-bottom: 20px; }
            .form-row { margin-bottom: 15px; position: relative; }
            .form-row label { display: block; color: #888; margin-bottom: 5px; }
            .form-row textarea, .form-row input { width: 100%; padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .form-row textarea { height: 80px; resize: vertical; }
            .encode-btn, .decode-btn { padding: 12px 25px; background: #a855f7; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; margin-bottom: 20px; }
            .copy-btn { position: absolute; top: 30px; right: 10px; background: transparent; border: none; color: #a855f7; cursor: pointer; }
            .decode-result { padding: 15px; background: rgba(0,0,0,0.3); border-radius: 8px; margin-top: 10px; }
            .no-data { color: #888; }
            .found-data { color: #2ecc71; }
            .found-data code { background: rgba(46,204,113,0.2); padding: 3px 8px; border-radius: 5px; }

            hr { border: none; border-top: 1px solid #333; margin: 30px 0; }

            .stego-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 9999; animation: slideIn 0.3s ease; }
            .stego-notif.success { background: #2ecc71; color: #fff; }
            .stego-notif.error { background: #e74c3c; color: #fff; }
            @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

            @media (max-width: 900px) {
                .tools-section { grid-template-columns: 1fr; }
            }
        </style>
        `;
    }
};

function pageStegoLab() {
    return StegoLab.render();
}
