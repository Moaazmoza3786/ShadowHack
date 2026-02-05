/* ==================== JS CHANGE MONITOR 🔍📡 ==================== */
/* Bug Bounty JavaScript Change Detection with AI Analysis */

window.JSMonitor = {
    // === STATE ===
    targets: [],
    checkInterval: 6 * 60 * 60 * 1000, // 6 hours in ms
    lastCheck: null,
    alerts: [],
    isMonitoring: false,
    currentTab: 'targets',

    // === PATTERNS TO DETECT ===
    sensitivePatterns: [
        { name: 'API Key', pattern: /['"]?api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/gi, severity: 'critical' },
        { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
        { name: 'AWS Secret', pattern: /['"]?aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9\/+=]{40}['"]/gi, severity: 'critical' },
        { name: 'Private Key', pattern: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g, severity: 'critical' },
        { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, severity: 'high' },
        { name: 'Bearer Token', pattern: /['"]?bearer['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-\.]+['"]/gi, severity: 'high' },
        { name: 'Authorization Header', pattern: /['"]?authorization['"]?\s*[:=]\s*['"][^'"]+['"]/gi, severity: 'high' },
        { name: 'Password', pattern: /['"]?password['"]?\s*[:=]\s*['"][^'"]{6,}['"]/gi, severity: 'high' },
        { name: 'Secret', pattern: /['"]?secret['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi, severity: 'high' },
        { name: 'Database URL', pattern: /(mongodb|mysql|postgres|redis):\/\/[^\s'"]+/gi, severity: 'critical' },
        { name: 'Firebase Config', pattern: /firebaseConfig\s*=\s*\{[^}]+\}/g, severity: 'high' },
        { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
        { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24}/g, severity: 'critical' },
        { name: 'GitHub Token', pattern: /ghp_[0-9a-zA-Z]{36}/g, severity: 'critical' },
        { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z-]+/g, severity: 'high' },
        { name: 'New Endpoint', pattern: /['"]\/api\/[a-zA-Z0-9\/_-]+['"]/g, severity: 'medium' },
        { name: 'Internal URL', pattern: /['"]https?:\/\/(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.)/gi, severity: 'medium' },
        { name: 'Admin Path', pattern: /['"]\/admin[a-zA-Z0-9\/_-]*['"]/gi, severity: 'medium' },
        { name: 'Debug Mode', pattern: /debug\s*[:=]\s*true/gi, severity: 'medium' },
        { name: 'Source Map', pattern: /\/\/# sourceMappingURL=/g, severity: 'low' }
    ],

    // === INIT ===
    init() {
        this.loadTargets();
        this.loadAlerts();
        this.startMonitoring();
    },

    loadTargets() {
        try {
            const saved = localStorage.getItem('js_monitor_targets');
            this.targets = saved ? JSON.parse(saved) : [];
        } catch (e) { this.targets = []; }
    },

    saveTargets() {
        localStorage.setItem('js_monitor_targets', JSON.stringify(this.targets));
    },

    loadAlerts() {
        try {
            const saved = localStorage.getItem('js_monitor_alerts');
            this.alerts = saved ? JSON.parse(saved) : [];
        } catch (e) { this.alerts = []; }
    },

    saveAlerts() {
        localStorage.setItem('js_monitor_alerts', JSON.stringify(this.alerts.slice(0, 100))); // Keep last 100
    },

    // === TARGET MANAGEMENT ===
    addTarget(url, name = '') {
        if (!url || !url.endsWith('.js')) {
            this.showNotification('❌ Invalid URL. Must be a .js file', 'error');
            return;
        }

        if (this.targets.find(t => t.url === url)) {
            this.showNotification('⚠️ Target already exists', 'warning');
            return;
        }

        const target = {
            id: Date.now().toString(),
            url: url,
            name: name || this.extractName(url),
            addedAt: new Date().toISOString(),
            lastChecked: null,
            lastHash: null,
            lastContent: null,
            status: 'pending',
            changeCount: 0
        };

        this.targets.push(target);
        this.saveTargets();
        this.checkTarget(target.id);
        this.reRender();
        this.showNotification('✅ Target added successfully', 'success');
    },

    removeTarget(id) {
        this.targets = this.targets.filter(t => t.id !== id);
        this.saveTargets();
        this.reRender();
    },

    extractName(url) {
        try {
            const parts = url.split('/');
            const filename = parts[parts.length - 1].split('?')[0];
            const domain = new URL(url).hostname;
            return `${domain} - ${filename}`;
        } catch (e) {
            return url.substring(0, 50);
        }
    },

    // === MONITORING ===
    startMonitoring() {
        if (this.isMonitoring) return;
        this.isMonitoring = true;

        // Check every 6 hours
        setInterval(() => this.checkAllTargets(), this.checkInterval);

        // Initial check if last check was more than 6 hours ago
        const lastCheck = localStorage.getItem('js_monitor_last_check');
        if (!lastCheck || Date.now() - parseInt(lastCheck) > this.checkInterval) {
            this.checkAllTargets();
        }
    },

    async checkAllTargets() {
        console.log('🔍 JS Monitor: Checking all targets...');
        localStorage.setItem('js_monitor_last_check', Date.now().toString());

        for (const target of this.targets) {
            await this.checkTarget(target.id);
            await new Promise(r => setTimeout(r, 1000)); // Rate limiting
        }

        this.reRender();
    },

    async checkTarget(id) {
        const target = this.targets.find(t => t.id === id);
        if (!target) return;

        target.status = 'checking';
        this.reRender();

        try {
            // Use CORS proxy or backend
            const response = await this.fetchWithProxy(target.url);
            const content = await response.text();
            const hash = await this.hashContent(content);

            target.lastChecked = new Date().toISOString();

            if (target.lastHash && target.lastHash !== hash) {
                // CHANGE DETECTED!
                target.changeCount++;
                target.status = 'changed';

                const diff = this.generateDiff(target.lastContent || '', content);
                const analysis = this.analyzeChanges(content, target.lastContent || '');

                const alert = {
                    id: Date.now().toString(),
                    targetId: target.id,
                    targetName: target.name,
                    targetUrl: target.url,
                    detectedAt: new Date().toISOString(),
                    diff: diff,
                    analysis: analysis,
                    newFindings: analysis.findings,
                    read: false
                };

                this.alerts.unshift(alert);
                this.saveAlerts();
                this.showChangeNotification(alert);
            } else {
                target.status = 'ok';
            }

            target.lastHash = hash;
            target.lastContent = content;
            this.saveTargets();

        } catch (error) {
            console.error('Error checking target:', target.url, error);
            target.status = 'error';
            target.lastError = error.message;
        }

        this.reRender();
    },

    async fetchWithProxy(url) {
        // Try multiple CORS proxies
        const proxies = [
            `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
            `https://corsproxy.io/?${encodeURIComponent(url)}`,
            url // Direct fetch as fallback
        ];

        for (const proxyUrl of proxies) {
            try {
                const response = await fetch(proxyUrl, {
                    method: 'GET',
                    headers: { 'Accept': 'application/javascript, text/javascript, */*' }
                });
                if (response.ok) return response;
            } catch (e) { continue; }
        }
        throw new Error('Failed to fetch from all proxies');
    },

    async hashContent(content) {
        const encoder = new TextEncoder();
        const data = encoder.encode(content);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    // === DIFF GENERATION ===
    generateDiff(oldContent, newContent) {
        const oldLines = oldContent.split('\n');
        const newLines = newContent.split('\n');
        const diff = [];

        let i = 0, j = 0;
        while (i < oldLines.length || j < newLines.length) {
            if (i >= oldLines.length) {
                diff.push({ type: 'added', line: j + 1, content: newLines[j] });
                j++;
            } else if (j >= newLines.length) {
                diff.push({ type: 'removed', line: i + 1, content: oldLines[i] });
                i++;
            } else if (oldLines[i] === newLines[j]) {
                i++; j++;
            } else {
                // Simple diff - mark as removed then added
                diff.push({ type: 'removed', line: i + 1, content: oldLines[i] });
                diff.push({ type: 'added', line: j + 1, content: newLines[j] });
                i++; j++;
            }
        }

        return diff.slice(0, 200); // Limit diff size
    },

    // === AI ANALYSIS ===
    analyzeChanges(newContent, oldContent) {
        const findings = [];
        const newLines = newContent.split('\n');
        const oldLines = oldContent.split('\n');
        const addedLines = newLines.filter(l => !oldLines.includes(l));

        // Check for sensitive patterns in new content
        for (const pattern of this.sensitivePatterns) {
            const matches = newContent.match(pattern.pattern) || [];
            const oldMatches = oldContent.match(pattern.pattern) || [];

            // Find new matches not in old content
            const newMatches = matches.filter(m => !oldMatches.includes(m));

            for (const match of newMatches) {
                findings.push({
                    type: pattern.name,
                    severity: pattern.severity,
                    value: this.maskSensitive(match),
                    raw: match,
                    context: this.findContext(newContent, match)
                });
            }
        }

        // AI-like summary
        const summary = this.generateAISummary(findings, addedLines.length);

        return {
            findings: findings,
            summary: summary,
            addedLinesCount: addedLines.length,
            riskLevel: this.calculateRiskLevel(findings)
        };
    },

    maskSensitive(value) {
        if (value.length > 20) {
            return value.substring(0, 10) + '****' + value.substring(value.length - 6);
        }
        return value.substring(0, 4) + '****';
    },

    findContext(content, match) {
        const index = content.indexOf(match);
        if (index === -1) return '';
        const start = Math.max(0, index - 50);
        const end = Math.min(content.length, index + match.length + 50);
        return '...' + content.substring(start, end).replace(/\n/g, ' ') + '...';
    },

    generateAISummary(findings, addedLines) {
        if (findings.length === 0) {
            return `📦 Minor update detected (${addedLines} new lines). No sensitive data found.`;
        }

        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;

        if (criticalCount > 0) {
            return `🚨 CRITICAL: ${criticalCount} critical exposures found! Potential API keys or secrets leaked. Investigate immediately!`;
        }

        if (highCount > 0) {
            return `⚠️ HIGH PRIORITY: ${highCount} high-severity items detected. New endpoints or tokens may be exposed.`;
        }

        return `📋 ${findings.length} items of interest found. New endpoints or debug info detected.`;
    },

    calculateRiskLevel(findings) {
        if (findings.some(f => f.severity === 'critical')) return 'critical';
        if (findings.some(f => f.severity === 'high')) return 'high';
        if (findings.some(f => f.severity === 'medium')) return 'medium';
        if (findings.length > 0) return 'low';
        return 'none';
    },

    // === NOTIFICATIONS ===
    showNotification(message, type = 'info') {
        const notif = document.createElement('div');
        notif.className = `jsm-notif jsm-notif-${type}`;
        notif.innerHTML = message;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 3000);
    },

    showChangeNotification(alert) {
        // Browser notification
        if (Notification.permission === 'granted') {
            new Notification('🔍 JS Change Detected!', {
                body: `${alert.targetName}: ${alert.analysis.summary}`,
                icon: '🔍'
            });
        }

        // In-app notification
        this.showNotification(`🔔 Change detected in ${alert.targetName}!`, 'warning');
    },

    requestNotificationPermission() {
        if ('Notification' in window) {
            Notification.requestPermission();
        }
    },

    // === RENDER ===
    render() {
        const unreadAlerts = this.alerts.filter(a => !a.read).length;

        return `
        <style>${this.getStyles()}</style>
        <div class="jsm-app fade-in">
            <div class="jsm-header">
                <div class="header-left">
                    <h1><i class="fas fa-radar"></i> JS Change Monitor <span class="pro-badge">PRO</span></h1>
                    <p class="subtitle">Bug Bounty JavaScript Intelligence • AI-Powered Analysis</p>
                </div>
                <div class="header-right">
                    <button class="btn-refresh" onclick="JSMonitor.checkAllTargets()">
                        <i class="fas fa-sync-alt"></i> Check Now
                    </button>
                    <button class="btn-notif" onclick="JSMonitor.requestNotificationPermission()">
                        <i class="fas fa-bell"></i> Enable Notifications
                    </button>
                </div>
            </div>

            <div class="jsm-stats">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-crosshairs"></i></div>
                    <div class="stat-info">
                        <span class="stat-val">${this.targets.length}</span>
                        <span class="stat-label">Targets</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon alert-icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="stat-info">
                        <span class="stat-val">${unreadAlerts}</span>
                        <span class="stat-label">New Alerts</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-exchange-alt"></i></div>
                    <div class="stat-info">
                        <span class="stat-val">${this.targets.reduce((sum, t) => sum + t.changeCount, 0)}</span>
                        <span class="stat-label">Changes Detected</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-clock"></i></div>
                    <div class="stat-info">
                        <span class="stat-val">6h</span>
                        <span class="stat-label">Check Interval</span>
                    </div>
                </div>
            </div>

            <div class="jsm-tabs">
                <div class="tab ${this.currentTab === 'targets' ? 'active' : ''}" onclick="JSMonitor.switchTab('targets')">
                    <i class="fas fa-crosshairs"></i> Targets (${this.targets.length})
                </div>
                <div class="tab ${this.currentTab === 'alerts' ? 'active' : ''}" onclick="JSMonitor.switchTab('alerts')">
                    <i class="fas fa-bell"></i> Alerts ${unreadAlerts > 0 ? `<span class="badge">${unreadAlerts}</span>` : ''}
                </div>
                <div class="tab ${this.currentTab === 'analyze' ? 'active' : ''}" onclick="JSMonitor.switchTab('analyze')">
                    <i class="fas fa-brain"></i> AI Analyze
                </div>
            </div>

            <div class="jsm-content">
                ${this.renderTabContent()}
            </div>
        </div>`;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'targets': return this.renderTargets();
            case 'alerts': return this.renderAlerts();
            case 'analyze': return this.renderAnalyze();
            default: return '';
        }
    },

    renderTargets() {
        return `
        <div class="targets-section">
            <div class="add-target">
                <h3><i class="fas fa-plus-circle"></i> Add JavaScript Target</h3>
                <div class="add-form">
                    <input type="text" id="jsm-url" placeholder="https://example.com/static/main.js" />
                    <input type="text" id="jsm-name" placeholder="Target Name (optional)" />
                    <button onclick="JSMonitor.addTarget(document.getElementById('jsm-url').value, document.getElementById('jsm-name').value)">
                        <i class="fas fa-plus"></i> Add Target
                    </button>
                </div>
                <p class="tip">💡 Add JavaScript files from your Bug Bounty targets. The monitor will track changes every 6 hours.</p>
            </div>

            <div class="targets-list">
                ${this.targets.length === 0 ? '<div class="empty-state"><i class="fas fa-crosshairs"></i><p>No targets yet. Add a JavaScript URL to start monitoring.</p></div>' : ''}
                ${this.targets.map(t => this.renderTarget(t)).join('')}
            </div>
        </div>`;
    },

    renderTarget(target) {
        const statusColors = { ok: '#22c55e', changed: '#f59e0b', error: '#ef4444', pending: '#6b7280', checking: '#3b82f6' };
        const statusIcons = { ok: 'check-circle', changed: 'exclamation-circle', error: 'times-circle', pending: 'clock', checking: 'spinner fa-spin' };

        return `
        <div class="target-card">
            <div class="target-status" style="background: ${statusColors[target.status]}">
                <i class="fas fa-${statusIcons[target.status]}"></i>
            </div>
            <div class="target-info">
                <div class="target-name">${target.name}</div>
                <div class="target-url">${target.url}</div>
                <div class="target-meta">
                    <span><i class="fas fa-clock"></i> Last checked: ${target.lastChecked ? new Date(target.lastChecked).toLocaleString() : 'Never'}</span>
                    <span><i class="fas fa-exchange-alt"></i> Changes: ${target.changeCount}</span>
                </div>
            </div>
            <div class="target-actions">
                <button onclick="JSMonitor.checkTarget('${target.id}')" title="Check Now">
                    <i class="fas fa-sync-alt"></i>
                </button>
                <button onclick="JSMonitor.analyzeTarget('${target.id}')" title="Deep Analyze">
                    <i class="fas fa-brain"></i>
                </button>
                <button class="btn-danger" onclick="JSMonitor.removeTarget('${target.id}')" title="Remove">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>`;
    },

    renderAlerts() {
        return `
        <div class="alerts-section">
            <div class="alerts-header">
                <h3><i class="fas fa-bell"></i> Change Alerts</h3>
                <button onclick="JSMonitor.markAllRead()"><i class="fas fa-check-double"></i> Mark All Read</button>
            </div>
            ${this.alerts.length === 0 ? '<div class="empty-state"><i class="fas fa-bell-slash"></i><p>No alerts yet. Changes will appear here when detected.</p></div>' : ''}
            <div class="alerts-list">
                ${this.alerts.map(a => this.renderAlert(a)).join('')}
            </div>
        </div>`;
    },

    renderAlert(alert) {
        const riskColors = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#65a30d', none: '#22c55e' };

        return `
        <div class="alert-card ${alert.read ? 'read' : 'unread'}" onclick="JSMonitor.viewAlert('${alert.id}')">
            <div class="alert-risk" style="background: ${riskColors[alert.analysis?.riskLevel || 'none']}">
                ${(alert.analysis?.riskLevel || 'none').toUpperCase()}
            </div>
            <div class="alert-info">
                <div class="alert-title">${alert.targetName}</div>
                <div class="alert-summary">${alert.analysis?.summary || 'Changes detected'}</div>
                <div class="alert-meta">
                    <span><i class="fas fa-clock"></i> ${new Date(alert.detectedAt).toLocaleString()}</span>
                    <span><i class="fas fa-bug"></i> ${alert.newFindings?.length || 0} findings</span>
                </div>
            </div>
            <div class="alert-actions">
                <button onclick="event.stopPropagation(); JSMonitor.showDiff('${alert.id}')">
                    <i class="fas fa-code"></i> View Diff
                </button>
            </div>
        </div>`;
    },

    renderAnalyze() {
        return `
        <div class="analyze-section">
            <h3><i class="fas fa-brain"></i> AI-Powered JavaScript Analysis</h3>
            <p class="section-desc">Paste any JavaScript content to analyze for sensitive data, API endpoints, and security issues.</p>

            <div class="analyze-form">
                <textarea id="jsm-analyze-content" placeholder="Paste JavaScript content here to analyze..."></textarea>
                <button onclick="JSMonitor.analyzeContent()">
                    <i class="fas fa-search"></i> Analyze with AI
                </button>
            </div>

            <div id="jsm-analyze-results"></div>

            <div class="pattern-reference">
                <h4><i class="fas fa-list"></i> Detection Patterns</h4>
                <div class="patterns-grid">
                    ${this.sensitivePatterns.map(p => `
                        <div class="pattern-item severity-${p.severity}">
                            <span class="pattern-name">${p.name}</span>
                            <span class="pattern-severity">${p.severity.toUpperCase()}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>`;
    },

    // === ACTIONS ===
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    markAllRead() {
        this.alerts.forEach(a => a.read = true);
        this.saveAlerts();
        this.reRender();
    },

    viewAlert(id) {
        const alert = this.alerts.find(a => a.id === id);
        if (alert) {
            alert.read = true;
            this.saveAlerts();
            this.showAlertDetails(alert);
        }
    },

    showDiff(alertId) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (!alert || !alert.diff) return;

        const diffHtml = alert.diff.map(d => `
            <div class="diff-line ${d.type}">
                <span class="line-num">${d.line}</span>
                <span class="line-sign">${d.type === 'added' ? '+' : '-'}</span>
                <span class="line-content">${this.escapeHtml(d.content)}</span>
            </div>
        `).join('');

        this.showModal('Code Diff', `<div class="diff-view">${diffHtml}</div>`);
    },

    showAlertDetails(alert) {
        const findingsHtml = (alert.newFindings || []).map(f => `
            <div class="finding-item severity-${f.severity}">
                <div class="finding-header">
                    <span class="finding-type">${f.type}</span>
                    <span class="finding-severity">${f.severity.toUpperCase()}</span>
                </div>
                <code class="finding-value">${this.escapeHtml(f.value)}</code>
                <div class="finding-context">${this.escapeHtml(f.context)}</div>
            </div>
        `).join('') || '<p>No sensitive findings.</p>';

        this.showModal('Alert Details', `
            <h4>${alert.targetName}</h4>
            <p><strong>URL:</strong> ${alert.targetUrl}</p>
            <p><strong>Detected:</strong> ${new Date(alert.detectedAt).toLocaleString()}</p>
            <h5>AI Summary</h5>
            <p class="ai-summary">${alert.analysis?.summary || 'No summary'}</p>
            <h5>Findings (${alert.newFindings?.length || 0})</h5>
            <div class="findings-list">${findingsHtml}</div>
        `);
    },

    showModal(title, content) {
        const modal = document.createElement('div');
        modal.className = 'jsm-modal-overlay';
        modal.innerHTML = `
            <div class="jsm-modal">
                <div class="jsm-modal-header">
                    <h3>${title}</h3>
                    <button onclick="this.closest('.jsm-modal-overlay').remove()"><i class="fas fa-times"></i></button>
                </div>
                <div class="jsm-modal-body">${content}</div>
            </div>
        `;
        document.body.appendChild(modal);
    },

    analyzeContent() {
        const content = document.getElementById('jsm-analyze-content')?.value || '';
        if (!content.trim()) {
            this.showNotification('⚠️ Please paste some JavaScript content', 'warning');
            return;
        }

        const analysis = this.analyzeChanges(content, '');
        const resultsDiv = document.getElementById('jsm-analyze-results');

        const findingsHtml = analysis.findings.map(f => `
            <div class="finding-item severity-${f.severity}">
                <div class="finding-header">
                    <span class="finding-type">${f.type}</span>
                    <span class="finding-severity">${f.severity.toUpperCase()}</span>
                </div>
                <code class="finding-value">${this.escapeHtml(f.value)}</code>
                <div class="finding-context">${this.escapeHtml(f.context)}</div>
            </div>
        `).join('');

        resultsDiv.innerHTML = `
            <div class="analyze-results">
                <h4><i class="fas fa-robot"></i> AI Analysis Results</h4>
                <div class="ai-summary-box">${analysis.summary}</div>
                <div class="risk-badge risk-${analysis.riskLevel}">Risk Level: ${analysis.riskLevel.toUpperCase()}</div>
                <h5>Findings (${analysis.findings.length})</h5>
                ${analysis.findings.length > 0 ? findingsHtml : '<p class="no-findings">✅ No sensitive data detected.</p>'}
            </div>
        `;
    },

    async analyzeTarget(id) {
        const target = this.targets.find(t => t.id === id);
        if (!target || !target.lastContent) {
            this.showNotification('⚠️ No content available. Check the target first.', 'warning');
            return;
        }

        const analysis = this.analyzeChanges(target.lastContent, '');
        this.showModal('Deep Analysis: ' + target.name, `
            <div class="ai-summary-box">${analysis.summary}</div>
            <div class="risk-badge risk-${analysis.riskLevel}">Risk Level: ${analysis.riskLevel.toUpperCase()}</div>
            <h5>All Findings (${analysis.findings.length})</h5>
            ${analysis.findings.map(f => `
                <div class="finding-item severity-${f.severity}">
                    <div class="finding-header">
                        <span class="finding-type">${f.type}</span>
                        <span class="finding-severity">${f.severity.toUpperCase()}</span>
                    </div>
                    <code class="finding-value">${this.escapeHtml(f.value)}</code>
                </div>
            `).join('') || '<p>No findings.</p>'}
        `);
    },

    escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    },

    reRender() {
        const app = document.querySelector('.jsm-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        .jsm-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }

        .jsm-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .jsm-header h1 { margin: 0; color: #00d4ff; font-size: 1.8rem; display: flex; align-items: center; gap: 10px; }
        .pro-badge { background: linear-gradient(135deg, #00d4ff, #0066cc); font-size: 0.6rem; padding: 3px 10px; border-radius: 4px; color: #000; }
        .subtitle { color: #888; margin: 5px 0 0; }
        .header-right { display: flex; gap: 10px; }
        .btn-refresh, .btn-notif { padding: 10px 20px; background: rgba(0, 212, 255, 0.15); border: 1px solid #00d4ff; border-radius: 8px; color: #00d4ff; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: 0.2s; }
        .btn-refresh:hover, .btn-notif:hover { background: rgba(0, 212, 255, 0.3); }

        .jsm-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: rgba(0,0,0,0.4); padding: 20px; border-radius: 12px; display: flex; align-items: center; gap: 15px; border: 1px solid rgba(255,255,255,0.05); }
        .stat-icon { width: 50px; height: 50px; background: rgba(0, 212, 255, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.3rem; color: #00d4ff; }
        .alert-icon { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
        .stat-val { font-size: 1.8rem; font-weight: bold; color: #fff; display: block; }
        .stat-label { color: #888; font-size: 0.85rem; }

        .jsm-tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 12px 20px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; cursor: pointer; color: #888; display: flex; align-items: center; gap: 8px; transition: 0.2s; }
        .tab:hover { color: #fff; background: rgba(255,255,255,0.1); }
        .tab.active { background: #00d4ff; color: #000; border-color: #00d4ff; }
        .badge { background: #ef4444; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; margin-left: 5px; }

        .add-target { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; margin-bottom: 25px; }
        .add-target h3 { margin: 0 0 15px; color: #00d4ff; }
        .add-form { display: flex; gap: 10px; flex-wrap: wrap; }
        .add-form input { flex: 1; min-width: 200px; padding: 12px 15px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 1rem; }
        .add-form input:focus { border-color: #00d4ff; outline: none; }
        .add-form button { padding: 12px 25px; background: #00d4ff; border: none; border-radius: 8px; color: #000; font-weight: bold; cursor: pointer; display: flex; align-items: center; gap: 8px; }
        .add-form button:hover { background: #00a8cc; }
        .tip { color: #888; font-size: 0.85rem; margin: 15px 0 0; }

        .targets-list { display: flex; flex-direction: column; gap: 12px; }
        .target-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; display: flex; align-items: center; gap: 20px; border: 1px solid rgba(255,255,255,0.05); transition: 0.2s; }
        .target-card:hover { border-color: #00d4ff; transform: translateX(5px); }
        .target-status { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #fff; }
        .target-info { flex: 1; }
        .target-name { color: #fff; font-weight: bold; font-size: 1.1rem; margin-bottom: 5px; }
        .target-url { color: #00d4ff; font-size: 0.85rem; word-break: break-all; }
        .target-meta { margin-top: 10px; color: #666; font-size: 0.8rem; display: flex; gap: 20px; }
        .target-meta span { display: flex; align-items: center; gap: 5px; }
        .target-actions { display: flex; gap: 8px; }
        .target-actions button { width: 36px; height: 36px; border: none; border-radius: 8px; background: rgba(255,255,255,0.1); color: #888; cursor: pointer; transition: 0.2s; }
        .target-actions button:hover { background: #00d4ff; color: #000; }
        .target-actions .btn-danger:hover { background: #ef4444; color: #fff; }

        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state i { font-size: 3rem; margin-bottom: 15px; display: block; }

        .alerts-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .alerts-header h3 { margin: 0; color: #f59e0b; }
        .alerts-header button { padding: 8px 15px; background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; border-radius: 8px; color: #f59e0b; cursor: pointer; }
        .alerts-list { display: flex; flex-direction: column; gap: 12px; }
        .alert-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; display: flex; align-items: center; gap: 20px; cursor: pointer; border: 1px solid rgba(255,255,255,0.05); transition: 0.2s; }
        .alert-card.unread { border-left: 4px solid #f59e0b; }
        .alert-card:hover { border-color: #f59e0b; }
        .alert-risk { padding: 8px 12px; border-radius: 8px; color: #fff; font-size: 0.7rem; font-weight: bold; }
        .alert-info { flex: 1; }
        .alert-title { color: #fff; font-weight: bold; }
        .alert-summary { color: #888; font-size: 0.9rem; margin: 5px 0; }
        .alert-meta { color: #666; font-size: 0.8rem; display: flex; gap: 15px; }
        .alert-actions button { padding: 8px 15px; background: rgba(255,255,255,0.1); border: none; border-radius: 8px; color: #888; cursor: pointer; }

        .analyze-section { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
        .analyze-section h3 { margin: 0 0 10px; color: #a855f7; }
        .section-desc { color: #888; margin: 0 0 20px; }
        .analyze-form textarea { width: 100%; height: 150px; background: #0a0a12; border: 1px solid #333; border-radius: 10px; padding: 15px; color: #fff; font-family: monospace; resize: vertical; margin-bottom: 15px; }
        .analyze-form button { padding: 12px 25px; background: #a855f7; border: none; border-radius: 8px; color: #fff; font-weight: bold; cursor: pointer; }

        .analyze-results { margin-top: 25px; padding: 20px; background: rgba(168, 85, 247, 0.1); border-radius: 12px; border: 1px solid rgba(168, 85, 247, 0.3); }
        .ai-summary-box { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin: 10px 0; }
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; font-size: 0.85rem; }
        .risk-critical { background: rgba(220, 38, 38, 0.2); color: #dc2626; }
        .risk-high { background: rgba(234, 88, 12, 0.2); color: #ea580c; }
        .risk-medium { background: rgba(202, 138, 4, 0.2); color: #ca8a04; }
        .risk-low { background: rgba(101, 163, 13, 0.2); color: #65a30d; }
        .risk-none { background: rgba(34, 197, 94, 0.2); color: #22c55e; }

        .finding-item { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 4px solid #888; }
        .finding-item.severity-critical { border-color: #dc2626; }
        .finding-item.severity-high { border-color: #ea580c; }
        .finding-item.severity-medium { border-color: #ca8a04; }
        .finding-item.severity-low { border-color: #65a30d; }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .finding-type { color: #fff; font-weight: bold; }
        .finding-severity { font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; background: rgba(255,255,255,0.1); }
        .finding-value { display: block; background: #0a0a12; padding: 10px; border-radius: 6px; margin: 10px 0; word-break: break-all; color: #22c55e; }
        .finding-context { color: #666; font-size: 0.85rem; }

        .patterns-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-top: 15px; }
        .pattern-item { background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 8px; display: flex; justify-content: space-between; border-left: 3px solid #888; }
        .pattern-item.severity-critical { border-color: #dc2626; }
        .pattern-item.severity-high { border-color: #ea580c; }
        .pattern-item.severity-medium { border-color: #ca8a04; }
        .pattern-item.severity-low { border-color: #65a30d; }
        .pattern-severity { font-size: 0.65rem; padding: 2px 6px; background: rgba(255,255,255,0.1); border-radius: 3px; }

        .jsm-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 10000; }
        .jsm-modal { background: #1a1a2e; border-radius: 15px; max-width: 800px; width: 90%; max-height: 80vh; overflow: hidden; }
        .jsm-modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px; border-bottom: 1px solid #333; }
        .jsm-modal-header h3 { margin: 0; color: #00d4ff; }
        .jsm-modal-header button { background: none; border: none; color: #888; font-size: 1.2rem; cursor: pointer; }
        .jsm-modal-body { padding: 20px; max-height: 60vh; overflow-y: auto; }

        .diff-view { font-family: monospace; font-size: 0.85rem; }
        .diff-line { padding: 3px 10px; display: flex; gap: 10px; }
        .diff-line.added { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .diff-line.removed { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .line-num { color: #666; min-width: 40px; }
        .line-sign { font-weight: bold; min-width: 15px; }

        .jsm-notif { position: fixed; top: 80px; right: 20px; padding: 15px 25px; border-radius: 10px; z-index: 10001; animation: slideIn 0.3s; }
        .jsm-notif-success { background: linear-gradient(135deg, #22c55e, #16a34a); color: #fff; }
        .jsm-notif-error { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; }
        .jsm-notif-warning { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; }
        @keyframes slideIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        @media (max-width: 768px) {
            .target-card { flex-direction: column; align-items: stretch; }
            .target-actions { justify-content: flex-end; }
            .alert-card { flex-direction: column; align-items: stretch; }
        }
        `;
    }
};

function pageJSMonitor() {
    JSMonitor.init();
    return JSMonitor.render();
}
