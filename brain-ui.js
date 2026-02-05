/* ============================================================
   THE SECOND BRAIN - UI CONTROLLER
   Handles Dashboard, Wiki, Snippets, and Playbooks rendering
   ============================================================ */

window.BrainUI = {
    currentView: 'dashboard',
    searchTimeout: null,

    init() {
        console.log("BrainUI Initialized");
    },

    renderPage() {
        return `
            <div class="brain-v6-app fade-in">
                ${this.renderHeader()}
                <div id="brain-content-area" class="brain-content-v6">
                    ${this.renderContent()}
                </div>
            </div>
            ${this.renderModals()}
            ${this.getV6Styles()}
        `;
    },

    renderHeader() {
        return `
            <div class="brain-header-v6">
                <div class="header-branding">
                    <div class="branding-icon"><i class="fa-solid fa-brain"></i></div>
                    <div>
                        <h1>Second Brain <small class="pro-tag">PRO</small></h1>
                        <p>Knowledge Graph & Advanced Arsenal</p>
                    </div>
                </div>
                
                <div class="header-search-v6">
                    <div class="search-input-wrapper">
                        <i class="fa-solid fa-sparkles ai-icon"></i>
                        <input type="text" id="brain-ai-search" placeholder="Search knowledge or ask AI..." onkeyup="BrainUI.handleSearch(event)">
                        <div class="search-hint">Press Enter for AI Search</div>
                    </div>
                </div>

                <div class="header-nav-v6">
                    <button class="${this.currentView === 'dashboard' ? 'active' : ''}" onclick="BrainUI.switchView('dashboard')">
                        <i class="fa-solid fa-grid-2"></i> <span>Dashboard</span>
                    </button>
                    <button class="${this.currentView === 'wiki' ? 'active' : ''}" onclick="BrainUI.switchView('wiki')">
                        <i class="fa-solid fa-network-wired"></i> <span>Wiki</span>
                    </button>
                    <button class="${this.currentView === 'snippets' ? 'active' : ''}" onclick="BrainUI.switchView('snippets')">
                        <i class="fa-solid fa-terminal"></i> <span>Snippets</span>
                    </button>
                    <button class="${this.currentView === 'playbooks' ? 'active' : ''}" onclick="BrainUI.switchView('playbooks')">
                        <i class="fa-solid fa-list-check"></i> <span>Playbooks</span>
                    </button>
                </div>
            </div>
        `;
    },

    renderContent() {
        switch (this.currentView) {
            case 'dashboard': return this.renderDashboard();
            case 'wiki': return this.renderWiki();
            case 'snippets': return this.renderSnippets();
            case 'playbooks': return this.renderPlaybooks();
            default: return this.renderDashboard();
        }
    },

    renderDashboard() {
        return `
            <div class="dashboard-v6-grid">
                <div class="brain-v6-card welcome-card">
                    <h2><i class="fa-solid fa-layer-group"></i> Command Center</h2>
                    <p>Welcome to your advanced security operations center. Your neural network is active.</p>
                    <div class="welcome-stats">
                        <div class="stat-pill"><i class="fa-solid fa-code"></i> ${window.SecondBrainData.snippets.length} Snippets</div>
                        <div class="stat-pill"><i class="fa-solid fa-book"></i> ${window.SecondBrainData.wiki.length} Exploits</div>
                        <div class="stat-pill"><i class="fa-solid fa-list-check"></i> ${window.SecondBrainData.playbooks.length} Playbooks</div>
                    </div>
                </div>
                <div class="brain-v6-card action-card" onclick="BrainUI.switchView('playbooks')">
                    <i class="fa-solid fa-chess-knight"></i>
                    <h3>Strategy Engine</h3>
                    <p>Design custom attack chains and methodologies.</p>
                </div>
            </div>
        `;
    },

    renderWiki() {
        const data = window.SecondBrainData.wiki;
        return `
            <div class="wiki-grid-v6 fade-in">
                ${data.map(item => `
                    <div class="wiki-v6-card" id="wiki-${item.id}">
                        <div class="card-header">
                            <span class="severity-badge ${item.severity.toLowerCase()}">${item.severity}</span>
                            <h3>${item.title}</h3>
                        </div>
                        <p class="desc">${item.description}</p>
                        <div class="tag-row">
                            ${item.vectors.map(v => `<span class="tag">${v}</span>`).join('')}
                        </div>
                        <div class="wiki-actions">
                            <button class="ai-expand-btn" onclick="BrainUI.expandWikiWithAI('${item.title}', '${item.id}')">
                                <i class="fa-solid fa-microchip"></i> Deep Dive
                            </button>
                            <button class="ai-payloads-btn" onclick="BrainUI.showPayloads('${item.title}')">
                                <i class="fa-solid fa-bomb"></i> Generate Payloads
                            </button>
                        </div>
                        <div id="ai-res-${item.id}" class="ai-response-box"></div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderSnippets() {
        const data = window.SecondBrainData.snippets;
        const languages = [...new Set(data.map(s => s.lang))];

        return `
            <div class="snippets-v6-container fade-in">
                <div class="snippets-controls">
                    <div class="filter-group">
                        <button class="filter-chip active" onclick="BrainUI.filterSnippets('all', event)">All</button>
                        ${languages.map(l => `<button class="filter-chip" onclick="BrainUI.filterSnippets('${l}', event)">${l}</button>`).join('')}
                    </div>
                </div>

                <div class="snippets-grid-v6" id="snippets-grid">
                    ${data.map(s => `
                        <div class="snippet-v6-card lang-${s.lang}" data-lang="${s.lang}" data-title="${s.title.toLowerCase()}">
                            <div class="snippet-header">
                                <div class="lang-icon"><i class="fa-solid fa-code"></i></div>
                                <div class="title-group">
                                    <span class="lang-tag">${s.lang}</span>
                                    <h4>${s.title}</h4>
                                </div>
                                <button class="copy-v6" onclick="BrainUI.copySnippet(this, \`${btoa(s.code)}\`)"><i class="fa-solid fa-copy"></i></button>
                            </div>
                            <pre class="code-v6"><code class="language-${s.lang}">${s.code.replace(/</g, '&lt;')}</code></pre>
                            <div class="snippet-footer-v6">
                                <button class="ai-button-tiny" onclick="BrainUI.explainSnippet('${s.title}', \`${btoa(s.code)}\`)">
                                    <i class="fa-solid fa-wand-magic-sparkles"></i> Explain
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            
        `;
    },

    filterSnippets(lang, event) {
        document.querySelectorAll('.filter-chip').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        const cards = document.querySelectorAll('.snippet-v6-card');
        cards.forEach(card => {
            if (lang === 'all' || card.dataset.lang === lang) card.style.display = 'block';
            else card.style.display = 'none';
        });
    },

    async explainSnippet(title, b64code) {
        const code = atob(b64code);
        const modalId = 'ai-explain-' + Date.now();
        const modal = document.createElement('div');
        modal.className = 'ai-generation-overlay';
        modal.id = modalId;
        modal.innerHTML = `
            <div class="ai-gen-modal" style="text-align: left; max-width: 600px;">
                <i class="fa-solid fa-microchip" style="font-size: 2rem; display: block; text-align: center; margin-bottom: 20px;"></i>
                <h3 style="text-align: center; margin-bottom: 20px;">Analyzing ${title}...</h3>
                <div class="ai-gen-progress"></div>
            </div>
        `;
        document.body.appendChild(modal);

        try {
            const res = await fetch('http://localhost:5000/api/ai/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code, language: 'auto' })
            });
            const data = await res.json();
            if (data.success) {
                const result = data.analysis;
                let formattedHtml = '';
                if (typeof result === 'string') {
                    formattedHtml = result;
                } else {
                    formattedHtml = `
                    <div class="ai-deep-dive">
                        <h4><i class="fa-solid fa-align-left"></i> Summary</h4>
                        <p>${result.summary || 'No summary provided.'}</p>
                        <hr>
                        <h4><i class="fa-solid fa-lightbulb"></i> Explanation</h4>
                        <p>${result.explanation || 'No explanation provided.'}</p>
                        <hr>
                        <h4><i class="fa-solid fa-shield-halved"></i> Security Risk: <span class="${(result.security_risk || 'unknown').toLowerCase()}">${result.security_risk}</span></h4>
                        <hr>
                        <h4><i class="fa-solid fa-code"></i> Usage Example</h4>
                        <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto;"><code>${result.usage_example || ''}</code></pre>
                    </div>
                `;
                }

                const modalContent = modal.querySelector('.ai-gen-modal');
                modalContent.className = 'ai-gen-modal success';
                modalContent.style.maxWidth = '600px';
                modalContent.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3 style="margin: 0; color: #10B981;"><i class="fa-solid fa-check-circle"></i> Analysis Complete</h3>
                    <button class="btn-pro" style="padding: 5px 15px; font-size: 12px; background: #333;" onclick="document.getElementById('${modalId}').remove()">Close</button>
                </div>
                <div style="max-height: 500px; overflow-y: auto; text-align: left;">${formattedHtml}</div>
            `;
            } else {
                throw new Error(data.error || 'Optimization failed');
            }
        } catch (e) {
            const modalContent = modal.querySelector('.ai-gen-modal');
            modalContent.className = 'ai-gen-modal error';
            modalContent.innerHTML = `
                <h3>Analysis Failed</h3>
                <p>${e.message}</p>
                <button class="btn-pro" onclick="document.getElementById('${modalId}').remove()">Close</button>
            `;
        }
    },

    renderPlaybooks() {
        const data = window.SecondBrainData.playbooks;
        return `
            <div class="playbook-v6-container fade-in">
                <div class="playbook-actions">
                    <button class="btn-pro" onclick="BrainUI.showPlaybookMaker()">
                        <i class="fa-solid fa-plus"></i> Generate Neural Playbook
                    </button>
                </div>
                <div class="playbook-grid-v6">
                    ${data.map(pb => `
                        <div class="pb-v6-card">
                            <div class="pb-v6-header">
                                <h3>${pb.title}</h3>
                                <span class="pb-count">${pb.steps.length} Steps</span>
                            </div>
                            <div class="pb-steps">
                                ${pb.steps.map(step => `
                                    <div class="pb-step ${step.checked ? 'completed' : ''}">
                                        <div class="step-check"><i class="fa-solid fa-check"></i></div>
                                        <span>${step.label}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    switchView(view) {
        this.currentView = view;
        const main = document.getElementById('content');
        if (main) main.innerHTML = this.renderPage();
    },

    handleSearch(e) {
        const query = e.target.value;
        if (e.key === 'Enter' && query.length > 2) {
            this.runAISearch(query);
        }
    },

    async runAISearch(query) {
        const searchInput = document.getElementById('brain-ai-search');
        searchInput.classList.add('loading-ai');

        try {
            const dataset = [
                ...window.SecondBrainData.wiki.map(item => ({ id: item.id, title: item.title, description: item.description })),
                ...window.SecondBrainData.snippets.map(s => ({ id: s.id, title: s.title, tags: s.tags.join(' ') }))
            ];

            const res = await fetch('http://localhost:5000/api/ai/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query, dataset: dataset })
            });
            const data = await res.json();

            if (data.success && data.results.length > 0) {
                alert(`AI found ${data.results.length} relevant matches. Navigating to first match...`);
                const firstId = data.results[0];
                if (firstId.startsWith('wiki')) this.switchView('wiki');
                else this.switchView('snippets');
            } else {
                alert("AI could not find exact semantic matches. Try a broader term.");
            }
        } catch (err) {
            console.error(err);
        } finally {
            searchInput.classList.remove('loading-ai');
        }
    },

    async expandWikiWithAI(topic, id) {
        const box = document.getElementById(`ai-res-${id}`);
        box.innerHTML = '<div class="ai-loader"><div class="spinner"></div> Synthesizing Deep-Dive Content...</div>';
        box.classList.add('open');

        try {
            const res = await fetch('http://localhost:5000/api/ai/wiki', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ topic: topic })
            });
            const data = await res.json();
            if (data.success) {
                const c = data.content;

                const formatContent = (content) => {
                    if (!content) return 'None provided.';
                    if (typeof content === 'string') return content;
                    if (Array.isArray(content)) return `<ul>${content.map(i => `<li>${i}</li>`).join('')}</ul>`;
                    if (typeof content === 'object') {
                        return `<ul>${Object.entries(content).map(([k, v]) => `<li><strong>${k}:</strong> ${v}</li>`).join('')}</ul>`;
                    }
                    return String(content);
                };

                const riskHtml = formatContent(c.risk);
                const remediationHtml = formatContent(c.remediation);

                box.innerHTML = `
                <div class="ai-deep-dive fade-in">
                    <h4><i class="fa-solid fa-fingerprint"></i> Technical Analysis</h4>
                    <p>${c.desc}</p>
                    <hr>
                    <h4><i class="fa-solid fa-triangle-exclamation"></i> Attack Vectors & Risks</h4>
                    <div style="font-size: 13px; color: #cbd5e1; line-height: 1.6;">${riskHtml}</div>
                    <hr>
                    <h4><i class="fa-solid fa-shield-virus"></i> Mitigation Strategies</h4>
                    <div style="font-size: 13px; color: #cbd5e1; line-height: 1.6;">${remediationHtml}</div>
                </div>
            `;
            } else {
                throw new Error(data.error || 'Synthesis successful but returned invalid data structure.');
            }

        } catch (e) {
            console.error('Wiki AI Error:', e);
            box.innerHTML = `<p class="error">Neural link severed: ${e.message}</p>`;
        }
    },

    async showPayloads(topic) {
        // Create Modal with Loading State
        const modal = document.createElement('div');
        modal.className = 'ai-generation-overlay';
        modal.innerHTML = `
            <div class="ai-gen-modal" style="max-width: 900px; width: 95%; height: 85vh; display: flex; flex-direction: column;">
                <div style="flex-shrink: 0; text-align: center; padding: 20px;">
                    <i class="fa-solid fa-bomb fa-spin" style="color: #ef4444; font-size: 2em; margin-bottom: 15px;"></i>
                    <h3>Fabricating Payload Arsenal</h3>
                    <p>Compiling 20+ weaponized vectors for: <strong>${topic}</strong></p>
                    <div class="ai-gen-progress"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        try {
            const res = await fetch('http://localhost:5000/api/ai/payloads', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ topic: topic })
            });
            const data = await res.json();

            if (data.success && data.payloads) {
                // Store payloads globally for filtering
                window.lastPayloads = data.payloads;

                const modalContent = modal.querySelector('.ai-gen-modal');
                modalContent.className = 'ai-gen-modal success';
                modalContent.style.textAlign = 'left';

                // Inject the Dashboard Interface for Payloads
                modalContent.innerHTML = `
                    <!-- Header -->
                    <div style="flex-shrink: 0; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <h3 style="margin: 0; color: #ef4444; font-size: 1.4em;"><i class="fa-solid fa-crosshairs"></i> Payload Arsenal</h3>
                            <span style="font-size: 12px; color: #94a3b8;">${data.payloads.length} vectors generated for ${topic}</span>
                        </div>
                        <button class="btn-pro" style="background: #333; padding: 5px 15px;" onclick="document.querySelector('.ai-generation-overlay').remove()">Esc</button>
                    </div>

                    <!-- Search & Filter Controls -->
                    <div style="flex-shrink: 0; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap;">
                        <input type="text" id="payload-search" placeholder="Search payloads (e.g., 'polyglot', 'iframe')..." 
                               style="background: rgba(0,0,0,0.3); border: 1px solid #334155; color: #fff; padding: 10px 15px; border-radius: 6px; flex-grow: 1; outline: none;"
                               onkeyup="BrainUI.filterPayloads()">
                        
                        <div class="filter-group" style="display: flex; gap: 5px;">
                            <button class="filter-btn active" onclick="BrainUI.setPayloadFilter('All', this)">All</button>
                            <button class="filter-btn" onclick="BrainUI.setPayloadFilter('Bypass', this)">Bypass</button>
                            <button class="filter-btn" onclick="BrainUI.setPayloadFilter('Obfuscated', this)">Obfuscated</button>
                            <button class="filter-btn" onclick="BrainUI.setPayloadFilter('Polyglot', this)">Polyglot</button>
                            <button class="filter-btn" onclick="BrainUI.setPayloadFilter('One-Liner', this)">One-Liner</button>
                        </div>
                    </div>

                    <!-- Payload List Container -->
                    <div id="payload-list" style="flex-grow: 1; overflow-y: auto; padding-right: 5px;">
                        <!-- Content rendered by BrainUI.filterPayloads() -->
                    </div>
                `;

                // Initial Render
                setTimeout(() => BrainUI.filterPayloads('All'), 100);

            } else {
                throw new Error(data.error || 'Payload generation failed.');
            }
        } catch (e) {
            const modalContent = modal.querySelector('.ai-gen-modal');
            modalContent.className = 'ai-gen-modal error';
            modalContent.innerHTML = `
                <h3>Generation Failed</h3>
                <p>${e.message}</p>
                <button class="btn-pro" onclick="document.querySelector('.ai-generation-overlay').remove()">Close</button>
            `;
        }
    },

    // Payload Filter Logic
    currentFilter: 'All',

    setPayloadFilter(category, btn) {
        this.currentFilter = category;

        // Update button styles
        document.querySelectorAll('.filter-btn').forEach(b => {
            b.style.background = 'rgba(255,255,255,0.05)';
            b.style.color = '#94a3b8';
            b.style.border = '1px solid transparent';
        });
        btn.style.background = 'rgba(239, 68, 68, 0.2)';
        btn.style.color = '#ef4444';
        btn.style.border = '1px solid rgba(239, 68, 68, 0.5)';

        this.filterPayloads();
    },

    filterPayloads() {
        const query = document.getElementById('payload-search') ? document.getElementById('payload-search').value.toLowerCase() : '';
        const listContainer = document.getElementById('payload-list');
        if (!listContainer || !window.lastPayloads) return;

        const filtered = window.lastPayloads.filter(p => {
            const matchesSearch = p.payload.toLowerCase().includes(query) || p.description.toLowerCase().includes(query) || (p.category && p.category.toLowerCase().includes(query));
            const matchesCategory = this.currentFilter === 'All' || (p.category && p.category === this.currentFilter);
            return matchesSearch && matchesCategory;
        });

        if (filtered.length === 0) {
            listContainer.innerHTML = `<div style="text-align: center; color: #64748b; padding: 40px;">No payloads match your criteria.</div>`;
            return;
        }

        listContainer.innerHTML = filtered.map(p => `
            <div class="payload-item fade-in" style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px; margin-bottom: 10px; border-left: 3px solid ${this.getCategoryColor(p.category)}; position: relative;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 10px; color: ${this.getCategoryColor(p.category)}; font-weight: 700; text-transform: uppercase; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${p.category || 'GENERAL'}</span>
                    <button class="copy-v6-mini" onclick="BrainUI.copySnippet(this, \`${btoa(p.payload)}\`)" title="Copy Payload"><i class="fa-solid fa-copy"></i></button>
                </div>
                <code style="display: block; font-family: 'JetBrains Mono', monospace; color: #e2e8f0; font-size: 0.9em; margin-bottom: 6px; word-break: break-all; background: rgba(0,0,0,0.2); padding: 8px; border-radius: 4px;">${p.payload.replace(/</g, '&lt;')}</code>
                <p style="font-size: 12px; color: #94a3b8; margin: 0; line-height: 1.4;"><i class="fa-solid fa-circle-info" style="font-size: 10px; margin-right: 5px;"></i>${p.description}</p>
            </div>
        `).join('');
    },

    getCategoryColor(cat) {
        const map = {
            'Basic': '#3b82f6', // Blue
            'Bypass': '#ef4444', // Red
            'Obfuscated': '#a855f7', // Purple
            'Polyglot': '#f59e0b', // Amber
            'One-Liner': '#10b981' // Green
        };
        return map[cat] || '#64748b'; // Default Slate
    },

    copySnippet(btn, b64) {
        const code = atob(b64);
        navigator.clipboard.writeText(code);
        const originalIcon = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check" style="color: #10b981;"></i>';
        setTimeout(() => btn.innerHTML = originalIcon, 1500);
    },

    renderModals() {
        return `<div id="brain-modals"></div>`;
    },

    getV6Styles() {
        return `
        <style>
            .brain-v6-app { padding: 30px; color: #fff; font-family: 'Outfit', sans-serif; max-width: 1400px; margin: 0 auto; }

            /* Header V6 */
            .brain-header-v6 {
                display: flex; justify-content: space-between; align-items: center;
                background: rgba(22, 20, 33, 0.7); border: 1px solid rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(12px) saturate(180%); padding: 20px 30px;
                border-radius: 20px; margin-bottom: 30px;
            }
            .header-branding { display: flex; align-items: center; gap: 15px; }
            .branding-icon { width: 50px; height: 50px; background: rgba(130, 115, 221, 0.2); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: #8273DD; border: 1px solid rgba(130, 115, 221, 0.3); }
            .header-branding h1 { margin: 0; font-size: 1.25rem; font-weight: 800; display: flex; flex-direction: column; }
            .pro-tag { font-size: 10px; background: #8273DD; color: #fff; padding: 2px 6px; border-radius: 4px; display: inline-block; width: fit-content; margin-left: 10px; }
            .header-branding p { margin: 0; font-size: 12px; color: #9CA3AF; }

            .search-input-wrapper { position: relative; width: 400px; }
            .search-input-wrapper input { width: 100%; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); padding: 12px 15px 12px 40px; border-radius: 12px; color: #fff; font-family: 'JetBrains Mono'; transition: 0.3s; }
            .search-input-wrapper input:focus { border-color: #8273DD; box-shadow: 0 0 15px rgba(130, 115, 221, 0.2); outline: none; }
            .ai-icon { position: absolute; left: 15px; top: 50%; transform: translateY(-50%); color: #8273DD; }
            .search-hint { position: absolute; right: 10px; bottom: -20px; font-size: 10px; color: #555; }

            .header-nav-v6 { display: flex; gap: 8px; }
            .header-nav-v6 button {
                background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1);
                height: 45px; padding: 0 20px; border-radius: 12px; color: #9CA3AF;
                cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 10px; font-weight: 600; font-family: 'Outfit', sans-serif;
            }
            .header-nav-v6 button:hover, .header-nav-v6 button.active { background: #8273DD; color: #fff; border-color: #8273DD; transform: translateY(-2px); }

            /* Cards V6 */
            .brain-v6-card { background: rgba(22, 20, 33, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); padding: 30px; border-radius: 20px; transition: 0.3s; }
            .dashboard-v6-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 30px; }
            .welcome-card h2 { margin: 0 0 15px 0; font-size: 2rem; }
            .welcome-stats { display: flex; gap: 10px; margin-top: 20px; }
            .stat-pill { background: rgba(130, 115, 221, 0.1); border: 1px solid rgba(130, 115, 221, 0.2); padding: 8px 15px; border-radius: 20px; font-size: 12px; color: #8273DD; font-weight: 700; }

            .action-card { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; cursor: pointer; border: 1px dashed rgba(130, 115, 221, 0.5); }
            .action-card:hover { background: rgba(130, 115, 221, 0.1); border-style: solid; }
            .action-card i { font-size: 3rem; color: #8273DD; margin-bottom: 15px; }

            /* Wiki V6 */
            .wiki-grid-v6 { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
            .wiki-v6-card { background: rgba(30, 30, 46, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); padding: 25px; border-radius: 16px; position: relative; overflow: hidden; }
            .wiki-v6-card .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .severity-badge { font-size: 10px; font-weight: 800; padding: 4px 10px; border-radius: 5px; text-transform: uppercase; }
            .severity-badge.critical { background: rgba(239, 68, 68, 0.1); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.2); }
            .tag-row { display: flex; flex-wrap: wrap; gap: 5px; margin: 15px 0; }
            .tag { font-size: 11px; background: rgba(255, 255, 255, 0.05); padding: 4px 10px; border-radius: 6px; color: #9CA3AF; border: 1px solid rgba(255, 255, 255, 0.05); }

            .ai-expand-btn { width: 100%; background: linear-gradient(90deg, #6366f1, #8273DD); border: none; padding: 12px; border-radius: 10px; color: #fff; font-weight: 700; cursor: pointer; margin-top: 10px; transition: 0.3s; display: flex; justify-content: center; align-items: center; gap: 8px; }
            .ai-expand-btn:hover { box-shadow: 0 0 20px rgba(130, 115, 221, 0.4); }

            .ai-payloads-btn { width: 100%; background: linear-gradient(90deg, #EF4444, #b91c1c); border: none; padding: 12px; border-radius: 10px; color: #fff; font-weight: 700; cursor: pointer; margin-top: 10px; transition: 0.3s; display: flex; justify-content: center; align-items: center; gap: 8px; }
            .ai-payloads-btn:hover { box-shadow: 0 0 20px rgba(239, 68, 68, 0.4); }

            .wiki-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 15px; }

            .ai-response-box { max-height: 0; overflow: hidden; transition: 0.5s ease-out; background: rgba(0, 0, 0, 0.2); border-radius: 10px; margin-top: 0; }
            .ai-response-box.open { max-height: 500px; padding: 20px; margin-top: 15px; border: 1px solid rgba(130, 115, 221, 0.2); overflow-y: auto; }
            .ai-loader { display: flex; align-items: center; gap: 10px; color: #8273DD; font-size: 13px; }
            .spinner { width: 15px; height: 15px; border: 2px solid #8273DD; border-top-color: transparent; border-radius: 50%; animation: rot 1s infinite linear; }
            @keyframes rot { to { transform: rotate(360deg); } }

            .ai-deep-dive h4 { font-size: 14px; margin: 15px 0 5px 0; color: #8273DD; display: flex; align-items: center; gap: 8px; }
            .ai-deep-dive p { font-size: 13px; color: #cbd5e1; line-height: 1.5; margin: 0; }
            .ai-deep-dive hr { border: 0; border-top: 1px solid rgba(255, 255, 255, 0.05); margin: 10px 0; }

            /* Playbooks V6 */
            .pb-v6-card { background: rgba(22, 20, 33, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); padding: 25px; border-radius: 20px; margin-bottom: 20px; }
            .pb-v6-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .pb-count { font-size: 11px; background: rgba(130, 115, 221, 0.2); color: #8273DD; padding: 4px 10px; border-radius: 20px; font-weight: 800; }
            .pb-steps { display: flex; flex-direction: column; gap: 10px; }
            .pb-step { display: flex; align-items: center; gap: 15px; background: rgba(0, 0, 0, 0.2); padding: 12px 15px; border-radius: 12px; font-size: 14px; border: 1px solid transparent; transition: 0.2s; }
            .pb-step.completed { opacity: 0.5; border-color: #10B981; }
            .step-check { width: 20px; height: 20px; border: 2px solid #555; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 10px; color: transparent; }
            .pb-step.completed .step-check { background: #10B981; border-color: #10B981; color: #fff; }

            .btn-pro { background: #8273DD; color: #fff; border: none; padding: 12px 25px; border-radius: 12px; font-weight: 700; cursor: pointer; transition: 0.3s; }
            .playbook-actions { margin-bottom: 30px; display: flex; justify-content: flex-end; }

            .snippets-controls { margin-bottom: 25px; overflow-x: auto; padding-bottom: 5px; }
            .filter-group { display: flex; gap: 10px; }
            .filter-chip { background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); padding: 6px 14px; border-radius: 20px; color: #9CA3AF; cursor: pointer; transition: 0.2s; font-size: 12px; }
            .filter-chip.active, .filter-chip:hover { background: #8273DD; color: #fff; border-color: #8273DD; }
            
            .snippets-grid-v6 { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }
            .snippet-v6-card { background: rgba(30, 30, 46, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; overflow: hidden; transition: 0.3s; display: flex; flex-direction: column; }
            .snippet-v6-card:hover { transform: translateY(-3px); box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5); border-color: rgba(130, 115, 221, 0.3); }

            /* Language Borders */
            .snippet-v6-card.lang-python { border-left: 3px solid #3776ab; }
            .snippet-v6-card.lang-bash { border-left: 3px solid #4ade80; }
            .snippet-v6-card.lang-powershell { border-left: 3px solid #0078d4; }
            .snippet-v6-card.lang-sql { border-left: 3px solid #e34c26; }
            .snippet-v6-card.lang-javascript { border-left: 3px solid #f0db4f; }
            .snippet-v6-card.lang-c { border-left: 3px solid #555555; }
            .snippet-v6-card.lang-cpp { border-left: 3px solid #00599c; }
            .snippet-v6-card.lang-php { border-left: 3px solid #4F5D95; }

            .snippet-header { display: flex; align-items: center; gap: 12px; padding: 15px 20px; background: rgba(0, 0, 0, 0.2); border-bottom: 1px solid rgba(255, 255, 255, 0.05); }
            .lang-icon { width: 30px; height: 30px; background: rgba(255, 255, 255, 0.05); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 12px; color: #8273DD; }
            .title-group { flex: 1; }
            .title-group h4 { margin: 0; font-size: 14px; color: #e2e8f0; font-weight: 600; }
            .lang-tag { font-size: 9px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 2px; }
            
            .copy-v6 { background: none; border: none; color: #555; cursor: pointer; transition: 0.2s; }
            .copy-v6:hover { color: #fff; transform: scale(1.1); }
            
            .code-v6 { padding: 20px; margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 11px; line-height: 1.6; color: #e2e8f0; overflow-x: auto; background: rgba(0, 0, 0, 0.3); height: 100%; flex-grow: 1; }
            
            .snippet-footer-v6 { padding: 12px 20px; background: rgba(0, 0, 0, 0.2); border-top: 1px solid rgba(255, 255, 255, 0.05); display: flex; justify-content: space-between; align-items: center; }
            
            .ai-button-tiny { background: transparent; border: 1px solid rgba(130, 115, 221, 0.3); color: #8273DD; font-size: 11px; padding: 6px 12px; border-radius: 6px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; gap: 6px; }
            .ai-button-tiny:hover { background: rgba(130, 115, 221, 0.1); }
            
            .ai-gen-cards-mini { display: none; }

            .ai-generation-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 9999; }
            .ai-gen-modal { background: #161421; border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 24px; text-align: center; max-width: 400px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); border-top: 4px solid #8273DD; }
            .ai-gen-modal i { font-size: 3rem; color: #8273DD; margin-bottom: 20px; }
            .ai-gen-modal.success { border-top-color: #10B981; }
            .ai-gen-modal.success i { color: #10B981; }
            .ai-gen-modal.error { border-top-color: #ef4444; }
            .ai-gen-modal.error i { color: #ef4444; }
            
            .ai-gen-progress { height: 4px; background: rgba(130, 115, 221, 0.1); border-radius: 2px; overflow: hidden; position: relative; margin-top: 20px; }
            .ai-gen-progress::after { content: ''; position: absolute; left: -50%; top: 0; height: 100%; width: 50%; background: #8273DD; animation: slide-progress 2s infinite linear; }
            @keyframes slide-progress { to { left: 100%; } }

            .loading-ai { animation: pulse-ai 1.5s infinite; }
            @keyframes pulse-ai { 0% { border-color: #8273DD; } 50% { border-color: #6366f1; box-shadow: 0 0 20px rgba(130, 115, 221, 0.4); } 100% { border-color: #8273DD; } }
        </style>`;
    }
};
