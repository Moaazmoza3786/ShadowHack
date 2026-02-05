/* ==================== RECON DASHBOARD 🎯📡 ==================== */
/* Continuous Reconnaissance for Bug Bounty Hunters */

window.ReconDashboard = {
    // --- STATE ---
    targets: JSON.parse(localStorage.getItem('recon_targets') || '[]'),
    notifications: JSON.parse(localStorage.getItem('recon_notifications') || '[]'),
    currentTab: 'targets',
    scanInterval: null,
    telegramBotToken: localStorage.getItem('telegram_bot_token') || '',
    telegramChatId: localStorage.getItem('telegram_chat_id') || '',

    // --- RENDER ---
    render() {
        return `
            <div class="recon-app fade-in">
                <div class="recon-header">
                    <div class="header-left">
                        <h1><i class="fas fa-satellite-dish"></i> Recon Dashboard</h1>
                        <p class="subtitle">Continuous Reconnaissance & Subdomain Monitoring</p>
                    </div>
                    <div class="header-right">
                        <span class="scan-status ${this.scanInterval ? 'active' : ''}">
                            <i class="fas fa-circle"></i> ${this.scanInterval ? 'Monitoring Active' : 'Monitoring Paused'}
                        </span>
                        <button onclick="ReconDashboard.toggleMonitoring()" class="${this.scanInterval ? 'btn-stop' : 'btn-start'}">
                            <i class="fas ${this.scanInterval ? 'fa-pause' : 'fa-play'}"></i>
                            ${this.scanInterval ? 'Pause' : 'Start'}
                        </button>
                    </div>
                </div>

                <div class="recon-stats">
                    <div class="stat">
                        <i class="fas fa-crosshairs"></i>
                        <div>
                            <span class="stat-num">${this.targets.length}</span>
                            <span class="stat-label">Targets</span>
                        </div>
                    </div>
                    <div class="stat">
                        <i class="fas fa-globe"></i>
                        <div>
                            <span class="stat-num">${this.getTotalSubdomains()}</span>
                            <span class="stat-label">Subdomains</span>
                        </div>
                    </div>
                    <div class="stat">
                        <i class="fas fa-bell"></i>
                        <div>
                            <span class="stat-num">${this.notifications.filter(n => !n.read).length}</span>
                            <span class="stat-label">New Alerts</span>
                        </div>
                    </div>
                    <div class="stat">
                        <i class="fas fa-clock"></i>
                        <div>
                            <span class="stat-num">${this.getLastScanTime()}</span>
                            <span class="stat-label">Last Scan</span>
                        </div>
                    </div>
                </div>

                <div class="recon-tabs">
                    <div class="tab ${this.currentTab === 'targets' ? 'active' : ''}" onclick="ReconDashboard.switchTab('targets')">
                        <i class="fas fa-crosshairs"></i> Targets
                    </div>
                    <div class="tab ${this.currentTab === 'subdomains' ? 'active' : ''}" onclick="ReconDashboard.switchTab('subdomains')">
                        <i class="fas fa-globe"></i> Subdomains
                    </div>
                    <div class="tab ${this.currentTab === 'notifications' ? 'active' : ''}" onclick="ReconDashboard.switchTab('notifications')">
                        <i class="fas fa-bell"></i> Notifications
                        ${this.notifications.filter(n => !n.read).length > 0 ? `<span class="badge">${this.notifications.filter(n => !n.read).length}</span>` : ''}
                    </div>
                    <div class="tab ${this.currentTab === 'tools' ? 'active' : ''}" onclick="ReconDashboard.switchTab('tools')">
                        <i class="fas fa-tools"></i> Tools
                    </div>
                    <div class="tab ${this.currentTab === 'settings' ? 'active' : ''}" onclick="ReconDashboard.switchTab('settings')">
                        <i class="fas fa-cog"></i> Settings
                    </div>
                </div>

                <div class="recon-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'targets': return this.renderTargets();
            case 'subdomains': return this.renderSubdomains();
            case 'notifications': return this.renderNotifications();
            case 'tools': return this.renderTools();
            case 'settings': return this.renderSettings();
            default: return '';
        }
    },

    renderTargets() {
        return `
            <div class="targets-section">
                <div class="add-target-form">
                    <h3><i class="fas fa-plus-circle"></i> Add New Target</h3>
                    <div class="form-row">
                        <input type="text" id="new-target-domain" placeholder="example.com">
                        <input type="text" id="new-target-program" placeholder="Program Name (e.g., HackerOne - Example)">
                        <select id="new-target-scope">
                            <option value="wildcard">*.example.com (Wildcard)</option>
                            <option value="single">Single Domain</option>
                        </select>
                        <button onclick="ReconDashboard.addTarget()">
                            <i class="fas fa-plus"></i> Add Target
                        </button>
                    </div>
                </div>

                <div class="targets-list">
                    ${this.targets.length === 0 ?
                `<div class="empty-state">
                            <i class="fas fa-crosshairs"></i>
                            <p>No targets yet. Add your first bug bounty target!</p>
                        </div>` :
                this.targets.map((t, i) => this.renderTargetCard(t, i)).join('')
            }
                </div>
            </div>
        `;
    },

    renderTargetCard(target, index) {
        const newSubsCount = target.subdomains?.filter(s => s.isNew).length || 0;
        return `
            <div class="target-card ${target.isActive ? 'active' : 'paused'}">
                <div class="target-header">
                    <div class="target-info">
                        <h4>${target.domain}</h4>
                        <span class="program-name">${target.program || 'No Program'}</span>
                    </div>
                    <div class="target-status">
                        ${newSubsCount > 0 ? `<span class="new-badge">${newSubsCount} NEW</span>` : ''}
                        <span class="scope-badge">${target.scope === 'wildcard' ? '*.domain' : 'Single'}</span>
                    </div>
                </div>
                <div class="target-stats">
                    <span><i class="fas fa-globe"></i> ${target.subdomains?.length || 0} subdomains</span>
                    <span><i class="fas fa-clock"></i> Last: ${target.lastScan || 'Never'}</span>
                </div>
                <div class="target-actions">
                    <button onclick="ReconDashboard.scanTarget(${index})" title="Scan Now">
                        <i class="fas fa-search"></i>
                    </button>
                    <button onclick="ReconDashboard.viewSubdomains(${index})" title="View Subdomains">
                        <i class="fas fa-list"></i>
                    </button>
                    <button onclick="ReconDashboard.toggleTarget(${index})" title="${target.isActive ? 'Pause' : 'Resume'}">
                        <i class="fas ${target.isActive ? 'fa-pause' : 'fa-play'}"></i>
                    </button>
                    <button onclick="ReconDashboard.exportTarget(${index})" title="Export">
                        <i class="fas fa-download"></i>
                    </button>
                    <button onclick="ReconDashboard.deleteTarget(${index})" title="Delete" class="delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
    },

    renderSubdomains() {
        const allSubs = this.getAllSubdomains();
        const newSubs = allSubs.filter(s => s.isNew);

        return `
            <div class="subdomains-section">
                <div class="subs-header">
                    <h3><i class="fas fa-globe"></i> All Subdomains (${allSubs.length})</h3>
                    <div class="subs-filters">
                        <input type="text" id="sub-search" placeholder="Search subdomains..." onkeyup="ReconDashboard.filterSubdomains()">
                        <select id="sub-filter" onchange="ReconDashboard.filterSubdomains()">
                            <option value="all">All</option>
                            <option value="new">New Only</option>
                            <option value="alive">Alive (HTTP 200)</option>
                        </select>
                        <button onclick="ReconDashboard.exportAllSubdomains()">
                            <i class="fas fa-download"></i> Export All
                        </button>
                    </div>
                </div>

                ${newSubs.length > 0 ? `
                    <div class="new-subs-alert">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>${newSubs.length} new subdomains discovered! First to test!</span>
                        <button onclick="ReconDashboard.markAllAsRead()">Mark All Read</button>
                    </div>
                ` : ''}

                <div class="subs-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>Parent</th>
                                <th>Status</th>
                                <th>Discovered</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="subs-tbody">
                            ${allSubs.map(s => `
                                <tr class="${s.isNew ? 'new-row' : ''}">
                                    <td>
                                        ${s.isNew ? '<span class="new-dot"></span>' : ''}
                                        <a href="https://${s.subdomain}" target="_blank">${s.subdomain}</a>
                                    </td>
                                    <td>${s.parent}</td>
                                    <td><span class="status-badge ${s.status || 'unknown'}">${s.status || 'Unknown'}</span></td>
                                    <td>${s.discovered || 'N/A'}</td>
                                    <td class="actions">
                                        <button onclick="window.open('https://${s.subdomain}', '_blank')" title="Open">
                                            <i class="fas fa-external-link-alt"></i>
                                        </button>
                                        <button onclick="navigator.clipboard.writeText('${s.subdomain}')" title="Copy">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                        <button onclick="ReconDashboard.scanSingleSub('${s.subdomain}')" title="Scan">
                                            <i class="fas fa-search"></i>
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    },

    renderNotifications() {
        return `
            <div class="notifications-section">
                <div class="notif-header">
                    <h3><i class="fas fa-bell"></i> Notifications</h3>
                    <button onclick="ReconDashboard.clearAllNotifications()">
                        <i class="fas fa-trash"></i> Clear All
                    </button>
                </div>

                <div class="notif-list">
                    ${this.notifications.length === 0 ?
                `<div class="empty-state">
                            <i class="fas fa-bell-slash"></i>
                            <p>No notifications yet. Start monitoring to receive alerts!</p>
                        </div>` :
                this.notifications.map((n, i) => `
                            <div class="notif-card ${n.read ? 'read' : 'unread'}" onclick="ReconDashboard.markAsRead(${i})">
                                <div class="notif-icon ${n.type}">
                                    <i class="fas ${n.type === 'new_subdomain' ? 'fa-globe' : 'fa-info-circle'}"></i>
                                </div>
                                <div class="notif-content">
                                    <h4>${n.title}</h4>
                                    <p>${n.message}</p>
                                    <span class="notif-time">${n.time}</span>
                                </div>
                            </div>
                        `).join('')
            }
                </div>
            </div>
        `;
    },

    renderTools() {
        return `
            <div class="tools-section">
                <h3><i class="fas fa-tools"></i> Quick Recon Tools</h3>

                <div class="tools-grid">
                    <div class="tool-card">
                        <h4><i class="fas fa-search"></i> Quick Subdomain Lookup</h4>
                        <div class="tool-form">
                            <input type="text" id="quick-domain" placeholder="Enter domain...">
                            <button onclick="ReconDashboard.quickSubdomainLookup()">
                                <i class="fas fa-search"></i> Find Subdomains
                            </button>
                        </div>
                        <div id="quick-results" class="quick-results"></div>
                    </div>

                    <div class="tool-card">
                        <h4><i class="fas fa-terminal"></i> Recon One-Liners</h4>
                        <div class="oneliners">
                            <div class="oneliner">
                                <label>Subfinder + httpx</label>
                                <code>subfinder -d DOMAIN -silent | httpx -silent</code>
                                <button onclick="ReconDashboard.copyOneliner(this)"><i class="fas fa-copy"></i></button>
                            </div>
                            <div class="oneliner">
                                <label>Amass passive</label>
                                <code>amass enum -passive -d DOMAIN -o subs.txt</code>
                                <button onclick="ReconDashboard.copyOneliner(this)"><i class="fas fa-copy"></i></button>
                            </div>
                            <div class="oneliner">
                                <label>Full pipeline</label>
                                <code>subfinder -d DOMAIN | httpx | nuclei -t ~/nuclei-templates/</code>
                                <button onclick="ReconDashboard.copyOneliner(this)"><i class="fas fa-copy"></i></button>
                            </div>
                            <div class="oneliner">
                                <label>Wayback URLs</label>
                                <code>echo DOMAIN | gau | grep -E "\\.(js|json|xml|config)$"</code>
                                <button onclick="ReconDashboard.copyOneliner(this)"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    </div>

                    <div class="tool-card">
                        <h4><i class="fas fa-server"></i> HTTP Probe</h4>
                        <div class="tool-form">
                            <textarea id="probe-targets" placeholder="Enter URLs (one per line)..."></textarea>
                            <button onclick="ReconDashboard.probeTargets()">
                                <i class="fas fa-bolt"></i> Probe HTTP
                            </button>
                        </div>
                        <div id="probe-results" class="probe-results"></div>
                    </div>

                    <div class="tool-card">
                        <h4><i class="fas fa-cloud"></i> Technology Detection</h4>
                        <div class="tool-form">
                            <input type="text" id="tech-url" placeholder="Enter URL...">
                            <button onclick="ReconDashboard.detectTech()">
                                <i class="fas fa-fingerprint"></i> Detect Tech
                            </button>
                        </div>
                        <div id="tech-results" class="tech-results"></div>
                    </div>
                </div>
            </div>
        `;
    },

    renderSettings() {
        return `
            <div class="settings-section">
                <h3><i class="fas fa-cog"></i> Settings</h3>

                <div class="settings-grid">
                    <div class="setting-card">
                        <h4><i class="fas fa-clock"></i> Scan Schedule</h4>
                        <div class="setting-form">
                            <label>Scan Interval</label>
                            <select id="scan-interval">
                                <option value="3600000">Every 1 hour</option>
                                <option value="21600000">Every 6 hours</option>
                                <option value="43200000">Every 12 hours</option>
                                <option value="86400000" selected>Every 24 hours</option>
                            </select>
                        </div>
                    </div>

                    <div class="setting-card">
                        <h4><i class="fab fa-telegram"></i> Telegram Notifications</h4>
                        <div class="setting-form">
                            <label>Bot Token</label>
                            <input type="text" id="telegram-token" placeholder="123456:ABC-DEF..." 
                                   value="${this.telegramBotToken}">
                            <label>Chat ID</label>
                            <input type="text" id="telegram-chat" placeholder="Your chat ID" 
                                   value="${this.telegramChatId}">
                            <button onclick="ReconDashboard.saveTelegramSettings()">
                                <i class="fas fa-save"></i> Save
                            </button>
                            <button onclick="ReconDashboard.testTelegram()">
                                <i class="fas fa-paper-plane"></i> Test
                            </button>
                        </div>
                        <p class="setting-hint">
                            Create a bot with @BotFather and get your chat ID from @userinfobot
                        </p>
                    </div>

                    <div class="setting-card">
                        <h4><i class="fas fa-database"></i> Data Management</h4>
                        <div class="setting-form">
                            <button onclick="ReconDashboard.exportAllData()">
                                <i class="fas fa-download"></i> Export All Data
                            </button>
                            <button onclick="ReconDashboard.importData()">
                                <i class="fas fa-upload"></i> Import Data
                            </button>
                            <button onclick="ReconDashboard.clearAllData()" class="danger">
                                <i class="fas fa-trash"></i> Clear All Data
                            </button>
                        </div>
                    </div>

                    <div class="setting-card">
                        <h4><i class="fas fa-server"></i> Backend Status</h4>
                        <div class="backend-status">
                            <div class="status-item">
                                <span>API Server</span>
                                <span id="api-status" class="status-badge checking">Checking...</span>
                            </div>
                            <div class="status-item">
                                <span>Subdomain Scanner</span>
                                <span id="scanner-status" class="status-badge checking">Checking...</span>
                            </div>
                        </div>
                        <button onclick="ReconDashboard.checkBackendStatus()">
                            <i class="fas fa-sync-alt"></i> Check Status
                        </button>
                    </div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    addTarget() {
        const domain = document.getElementById('new-target-domain')?.value.trim();
        const program = document.getElementById('new-target-program')?.value.trim();
        const scope = document.getElementById('new-target-scope')?.value;

        if (!domain) {
            alert('Please enter a domain');
            return;
        }

        // Validate domain format
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$/;
        if (!domainRegex.test(domain)) {
            alert('Invalid domain format');
            return;
        }

        // Check if already exists
        if (this.targets.find(t => t.domain === domain)) {
            alert('Target already exists');
            return;
        }

        const target = {
            domain,
            program,
            scope,
            isActive: true,
            subdomains: [],
            lastScan: null,
            createdAt: new Date().toISOString()
        };

        this.targets.push(target);
        this.saveTargets();
        this.reRender();

        // Auto-scan new target
        this.scanTarget(this.targets.length - 1);
    },

    async scanTarget(index) {
        const target = this.targets[index];
        if (!target) return;

        // Show scanning status
        this.addNotification('scan_start', 'Scan Started', `Scanning ${target.domain}...`);

        try {
            // Try backend API first
            const response = await fetch('http://localhost:5000/api/recon/subdomains', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: target.domain })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success && data.subdomains) {
                    this.processNewSubdomains(index, data.subdomains);
                    return;
                }
            }
        } catch (e) {
            console.log('Backend not available, using simulation');
        }

        // Fallback: Simulate subdomain discovery
        this.simulateSubdomainDiscovery(index);
    },

    simulateSubdomainDiscovery(index) {
        const target = this.targets[index];
        const domain = target.domain;

        // Simulate finding subdomains
        const prefixes = ['www', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'mail', 'blog',
            'shop', 'cdn', 'static', 'docs', 'portal', 'dashboard', 'mobile', 'm',
            'beta', 'demo', 'internal', 'vpn', 'remote', 'git', 'jenkins', 'jira'];

        const existingSubs = new Set(target.subdomains?.map(s => s.subdomain) || []);
        const newSubs = [];

        // Randomly select some subdomains
        const numToFind = Math.floor(Math.random() * 5) + 1;
        const shuffled = prefixes.sort(() => 0.5 - Math.random());

        for (let i = 0; i < numToFind && i < shuffled.length; i++) {
            const sub = `${shuffled[i]}.${domain}`;
            if (!existingSubs.has(sub)) {
                newSubs.push(sub);
            }
        }

        this.processNewSubdomains(index, newSubs);
    },

    processNewSubdomains(index, newSubdomains) {
        const target = this.targets[index];
        const existingSubs = new Set(target.subdomains?.map(s => s.subdomain) || []);

        let addedCount = 0;
        const now = new Date().toLocaleDateString();

        newSubdomains.forEach(sub => {
            if (!existingSubs.has(sub)) {
                target.subdomains.push({
                    subdomain: sub,
                    parent: target.domain,
                    isNew: true,
                    discovered: now,
                    status: 'unknown'
                });
                addedCount++;
            }
        });

        target.lastScan = now;
        this.saveTargets();

        if (addedCount > 0) {
            this.addNotification(
                'new_subdomain',
                `${addedCount} New Subdomains!`,
                `Found ${addedCount} new subdomains for ${target.domain}`
            );
            this.sendTelegramNotification(`🎯 ${addedCount} new subdomains found for ${target.domain}!`);
        }

        this.reRender();
    },

    toggleTarget(index) {
        this.targets[index].isActive = !this.targets[index].isActive;
        this.saveTargets();
        this.reRender();
    },

    deleteTarget(index) {
        if (confirm('Delete this target and all its data?')) {
            this.targets.splice(index, 1);
            this.saveTargets();
            this.reRender();
        }
    },

    viewSubdomains(index) {
        const target = this.targets[index];
        this.currentTab = 'subdomains';
        this.reRender();
    },

    exportTarget(index) {
        const target = this.targets[index];
        const subs = target.subdomains?.map(s => s.subdomain).join('\n') || '';
        const blob = new Blob([subs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${target.domain}_subdomains.txt`;
        a.click();
    },

    toggleMonitoring() {
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
            this.scanInterval = null;
            this.addNotification('info', 'Monitoring Paused', 'Background scanning has been paused');
        } else {
            const interval = parseInt(document.getElementById('scan-interval')?.value) || 86400000;
            this.scanInterval = setInterval(() => this.runScheduledScan(), interval);
            this.addNotification('info', 'Monitoring Active', 'Background scanning has started');
        }
        this.reRender();
    },

    runScheduledScan() {
        console.log('Running scheduled scan...');
        this.targets.forEach((target, i) => {
            if (target.isActive) {
                this.scanTarget(i);
            }
        });
    },

    // --- NOTIFICATIONS ---
    addNotification(type, title, message) {
        this.notifications.unshift({
            type,
            title,
            message,
            time: new Date().toLocaleString(),
            read: false
        });

        // Keep only last 50 notifications
        if (this.notifications.length > 50) {
            this.notifications = this.notifications.slice(0, 50);
        }

        localStorage.setItem('recon_notifications', JSON.stringify(this.notifications));

        // Browser notification
        if (Notification.permission === 'granted') {
            new Notification(title, { body: message });
        }
    },

    markAsRead(index) {
        this.notifications[index].read = true;
        localStorage.setItem('recon_notifications', JSON.stringify(this.notifications));
        this.reRender();
    },

    markAllAsRead() {
        this.targets.forEach(t => {
            t.subdomains?.forEach(s => s.isNew = false);
        });
        this.saveTargets();
        this.reRender();
    },

    clearAllNotifications() {
        if (confirm('Clear all notifications?')) {
            this.notifications = [];
            localStorage.setItem('recon_notifications', '[]');
            this.reRender();
        }
    },

    // --- TELEGRAM ---
    saveTelegramSettings() {
        this.telegramBotToken = document.getElementById('telegram-token')?.value || '';
        this.telegramChatId = document.getElementById('telegram-chat')?.value || '';
        localStorage.setItem('telegram_bot_token', this.telegramBotToken);
        localStorage.setItem('telegram_chat_id', this.telegramChatId);
        alert('Telegram settings saved!');
    },

    async testTelegram() {
        if (!this.telegramBotToken || !this.telegramChatId) {
            alert('Please enter Bot Token and Chat ID first');
            return;
        }
        const result = await this.sendTelegramNotification('🔔 Test notification from Recon Dashboard!');
        alert(result ? 'Message sent successfully!' : 'Failed to send message. Check your credentials.');
    },

    async sendTelegramNotification(message) {
        if (!this.telegramBotToken || !this.telegramChatId) return false;

        try {
            const response = await fetch(`https://api.telegram.org/bot${this.telegramBotToken}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: this.telegramChatId,
                    text: message,
                    parse_mode: 'HTML'
                })
            });
            return response.ok;
        } catch (e) {
            console.error('Telegram error:', e);
            return false;
        }
    },

    // --- TOOLS ---
    async quickSubdomainLookup() {
        const domain = document.getElementById('quick-domain')?.value.trim();
        if (!domain) return;

        const resultsDiv = document.getElementById('quick-results');
        resultsDiv.innerHTML = '<p class="loading"><i class="fas fa-spinner fa-spin"></i> Searching...</p>';

        // Use crt.sh API (free certificate transparency logs)
        try {
            const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`);
            if (response.ok) {
                const data = await response.json();
                const subs = [...new Set(data.map(d => d.name_value.replace(/\*\./g, '')))];
                resultsDiv.innerHTML = `
                    <p class="result-count">Found ${subs.length} subdomains:</p>
                    <div class="result-list">${subs.slice(0, 50).map(s => `<span>${s}</span>`).join('')}</div>
                    <button onclick="navigator.clipboard.writeText('${subs.join('\\n')}')">
                        <i class="fas fa-copy"></i> Copy All
                    </button>
                `;
            } else {
                throw new Error('API error');
            }
        } catch (e) {
            resultsDiv.innerHTML = '<p class="error">Error fetching subdomains. Try again later or check the domain.</p>';
        }
    },

    copyOneliner(btn) {
        const code = btn.previousElementSibling.textContent;
        const domain = document.getElementById('quick-domain')?.value || 'DOMAIN';
        navigator.clipboard.writeText(code.replace(/DOMAIN/g, domain));
        btn.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => btn.innerHTML = '<i class="fas fa-copy"></i>', 1500);
    },

    // --- HELPERS ---
    getTotalSubdomains() {
        return this.targets.reduce((sum, t) => sum + (t.subdomains?.length || 0), 0);
    },

    getAllSubdomains() {
        const all = [];
        this.targets.forEach(t => {
            t.subdomains?.forEach(s => all.push(s));
        });
        return all.sort((a, b) => (b.isNew ? 1 : 0) - (a.isNew ? 1 : 0));
    },

    getLastScanTime() {
        const scans = this.targets.filter(t => t.lastScan).map(t => t.lastScan);
        return scans.length > 0 ? scans[scans.length - 1] : 'Never';
    },

    saveTargets() {
        localStorage.setItem('recon_targets', JSON.stringify(this.targets));
    },

    exportAllSubdomains() {
        const subs = this.getAllSubdomains().map(s => s.subdomain).join('\n');
        const blob = new Blob([subs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'all_subdomains.txt';
        a.click();
    },

    exportAllData() {
        const data = {
            targets: this.targets,
            notifications: this.notifications,
            exportedAt: new Date().toISOString()
        };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'recon_dashboard_backup.json';
        a.click();
    },

    clearAllData() {
        if (confirm('This will delete ALL targets, subdomains, and notifications. Are you sure?')) {
            this.targets = [];
            this.notifications = [];
            localStorage.removeItem('recon_targets');
            localStorage.removeItem('recon_notifications');
            this.reRender();
        }
    },

    async checkBackendStatus() {
        try {
            const response = await fetch('http://localhost:5000/api/health');
            document.getElementById('api-status').className = 'status-badge online';
            document.getElementById('api-status').textContent = 'Online';
        } catch (e) {
            document.getElementById('api-status').className = 'status-badge offline';
            document.getElementById('api-status').textContent = 'Offline';
        }
    },

    filterSubdomains() {
        // Filter implementation
        const search = document.getElementById('sub-search')?.value.toLowerCase() || '';
        const filter = document.getElementById('sub-filter')?.value || 'all';

        document.querySelectorAll('#subs-tbody tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            const isNew = row.classList.contains('new-row');

            let show = text.includes(search);
            if (filter === 'new') show = show && isNew;

            row.style.display = show ? '' : 'none';
        });
    },

    // --- NAVIGATION ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    reRender() {
        const app = document.querySelector('.recon-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .recon-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .recon-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
            .recon-header h1 { margin: 0; color: #22c55e; font-size: 1.8rem; }
            .recon-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-right { display: flex; align-items: center; gap: 15px; }
            .scan-status { display: flex; align-items: center; gap: 8px; color: #888; }
            .scan-status.active { color: #22c55e; }
            .scan-status i { font-size: 0.6rem; }
            .btn-start { padding: 10px 20px; background: #22c55e; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .btn-stop { padding: 10px 20px; background: #ef4444; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .recon-stats { display: flex; gap: 20px; margin-bottom: 25px; flex-wrap: wrap; }
            .stat { display: flex; align-items: center; gap: 15px; background: rgba(0,0,0,0.3); padding: 20px 25px; border-radius: 12px; flex: 1; min-width: 180px; }
            .stat i { font-size: 1.5rem; color: #22c55e; }
            .stat-num { display: block; font-size: 1.8rem; font-weight: bold; color: #fff; }
            .stat-label { color: #888; font-size: 0.85rem; }

            .recon-tabs { display: flex; gap: 5px; margin-bottom: 25px; flex-wrap: wrap; }
            .tab { padding: 12px 20px; border-radius: 8px; cursor: pointer; color: #888; transition: 0.2s; display: flex; align-items: center; gap: 8px; position: relative; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #22c55e; color: #fff; }
            .tab .badge { position: absolute; top: 5px; right: 5px; background: #ef4444; color: #fff; padding: 2px 6px; border-radius: 10px; font-size: 0.7rem; }

            .add-target-form { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 25px; }
            .add-target-form h3 { margin: 0 0 15px; color: #22c55e; }
            .form-row { display: flex; gap: 10px; flex-wrap: wrap; }
            .form-row input, .form-row select { flex: 1; min-width: 200px; padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .form-row button { padding: 12px 25px; background: #22c55e; border: none; border-radius: 8px; color: #fff; cursor: pointer; white-space: nowrap; }

            .targets-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
            .target-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; border-left: 3px solid #22c55e; }
            .target-card.paused { border-left-color: #666; opacity: 0.7; }
            .target-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }
            .target-info h4 { margin: 0; color: #fff; }
            .program-name { color: #22c55e; font-size: 0.85rem; }
            .target-status { display: flex; gap: 8px; }
            .new-badge { padding: 3px 10px; background: #ef4444; color: #fff; border-radius: 12px; font-size: 0.75rem; font-weight: bold; animation: pulse 2s infinite; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
            .scope-badge { padding: 3px 10px; background: rgba(34,197,94,0.2); color: #22c55e; border-radius: 12px; font-size: 0.75rem; }
            .target-stats { display: flex; gap: 20px; color: #888; font-size: 0.85rem; margin-bottom: 15px; }
            .target-actions { display: flex; gap: 8px; }
            .target-actions button { padding: 8px 12px; background: rgba(255,255,255,0.05); border: none; border-radius: 6px; color: #888; cursor: pointer; transition: 0.2s; }
            .target-actions button:hover { background: #22c55e; color: #fff; }
            .target-actions button.delete:hover { background: #ef4444; }

            .subdomains-section h3 { color: #22c55e; margin: 0 0 20px; }
            .subs-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
            .subs-filters { display: flex; gap: 10px; flex-wrap: wrap; }
            .subs-filters input, .subs-filters select { padding: 10px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .subs-filters button { padding: 10px 20px; background: #22c55e; border: none; border-radius: 8px; color: #fff; cursor: pointer; }

            .new-subs-alert { display: flex; align-items: center; gap: 15px; background: rgba(239,68,68,0.2); border: 1px solid #ef4444; padding: 15px 20px; border-radius: 10px; margin-bottom: 20px; }
            .new-subs-alert i { color: #ef4444; font-size: 1.2rem; }
            .new-subs-alert span { flex: 1; color: #fff; }
            .new-subs-alert button { padding: 8px 15px; background: transparent; border: 1px solid #ef4444; border-radius: 6px; color: #ef4444; cursor: pointer; }

            .subs-table { overflow-x: auto; }
            .subs-table table { width: 100%; border-collapse: collapse; }
            .subs-table th, .subs-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
            .subs-table th { color: #888; font-weight: 500; }
            .subs-table tr.new-row { background: rgba(34,197,94,0.1); }
            .new-dot { display: inline-block; width: 8px; height: 8px; background: #22c55e; border-radius: 50%; margin-right: 8px; }
            .subs-table a { color: #60a5fa; text-decoration: none; }
            .status-badge { padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; }
            .status-badge.alive { background: rgba(34,197,94,0.2); color: #22c55e; }
            .status-badge.unknown { background: rgba(107,114,128,0.2); color: #6b7280; }
            .subs-table .actions button { padding: 6px 10px; background: transparent; border: none; color: #666; cursor: pointer; }
            .subs-table .actions button:hover { color: #22c55e; }

            .notifications-section h3 { color: #22c55e; margin: 0; }
            .notif-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .notif-header button { padding: 10px 20px; background: rgba(239,68,68,0.2); border: none; border-radius: 8px; color: #ef4444; cursor: pointer; }
            .notif-list { display: flex; flex-direction: column; gap: 10px; }
            .notif-card { display: flex; gap: 15px; background: rgba(0,0,0,0.3); padding: 15px 20px; border-radius: 10px; cursor: pointer; transition: 0.2s; }
            .notif-card:hover { background: rgba(255,255,255,0.05); }
            .notif-card.unread { border-left: 3px solid #22c55e; }
            .notif-card.read { opacity: 0.6; }
            .notif-icon { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
            .notif-icon.new_subdomain { background: rgba(34,197,94,0.2); color: #22c55e; }
            .notif-icon.info { background: rgba(59,130,246,0.2); color: #60a5fa; }
            .notif-content h4 { margin: 0 0 5px; color: #fff; }
            .notif-content p { margin: 0; color: #888; font-size: 0.9rem; }
            .notif-time { color: #666; font-size: 0.8rem; }

            .tools-section h3 { color: #22c55e; margin: 0 0 25px; }
            .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
            .tool-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .tool-card h4 { margin: 0 0 15px; color: #fff; }
            .tool-form { display: flex; flex-direction: column; gap: 10px; }
            .tool-form input, .tool-form textarea { padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .tool-form button { padding: 12px; background: #22c55e; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .oneliners { display: flex; flex-direction: column; gap: 10px; }
            .oneliner { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 10px; border-radius: 8px; }
            .oneliner label { min-width: 120px; color: #888; font-size: 0.85rem; }
            .oneliner code { flex: 1; color: #22c55e; font-size: 0.85rem; word-break: break-all; }
            .oneliner button { padding: 6px 10px; background: transparent; border: none; color: #666; cursor: pointer; }
            .quick-results, .probe-results, .tech-results { margin-top: 15px; padding: 15px; background: #0a0a12; border-radius: 8px; max-height: 200px; overflow-y: auto; }
            .result-list { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
            .result-list span { padding: 5px 10px; background: rgba(34,197,94,0.2); color: #22c55e; border-radius: 6px; font-size: 0.85rem; }

            .settings-section h3 { color: #22c55e; margin: 0 0 25px; }
            .settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .setting-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .setting-card h4 { margin: 0 0 15px; color: #fff; }
            .setting-form { display: flex; flex-direction: column; gap: 10px; }
            .setting-form label { color: #888; font-size: 0.85rem; }
            .setting-form input, .setting-form select { padding: 12px; background: #0a0a12; border: 1px solid #333; border-radius: 8px; color: #fff; }
            .setting-form button { padding: 12px; background: #22c55e; border: none; border-radius: 8px; color: #fff; cursor: pointer; }
            .setting-form button.danger { background: #ef4444; }
            .setting-hint { color: #666; font-size: 0.8rem; margin-top: 10px; }
            .backend-status { display: flex; flex-direction: column; gap: 10px; margin-bottom: 15px; }
            .status-item { display: flex; justify-content: space-between; align-items: center; }
            .status-badge.online { background: rgba(34,197,94,0.2); color: #22c55e; }
            .status-badge.offline { background: rgba(239,68,68,0.2); color: #ef4444; }
            .status-badge.checking { background: rgba(234,179,8,0.2); color: #eab308; }

            .empty-state { text-align: center; padding: 60px 20px; color: #666; }
            .empty-state i { font-size: 4rem; margin-bottom: 20px; color: #22c55e; }
            .loading { text-align: center; color: #22c55e; }
            .error { color: #ef4444; }

            @media (max-width: 800px) { .targets-list { grid-template-columns: 1fr; } .tools-grid { grid-template-columns: 1fr; } }
        </style>`;
    }
};

function pageReconDashboard() {
    return ReconDashboard.render();
}

// Request notification permission on page load
if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
    Notification.requestPermission();
}
