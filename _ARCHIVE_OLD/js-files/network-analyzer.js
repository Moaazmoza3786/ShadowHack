/* ==================== NETWORK PACKET ANALYZER 📡🔍 ==================== */
/* Wireshark-style Packet Analysis Simulator */

window.NetworkAnalyzer = {
    // --- STATE ---
    currentTab: 'capture',
    selectedPacket: null,
    filterQuery: '',

    // --- SIMULATED PACKET DATA ---
    packets: [
        { id: 1, time: '0.000000', src: '192.168.1.100', dst: '93.184.216.34', protocol: 'TCP', length: 74, info: '55432 → 443 [SYN] Seq=0', flags: 'SYN' },
        { id: 2, time: '0.025432', src: '93.184.216.34', dst: '192.168.1.100', protocol: 'TCP', length: 74, info: '443 → 55432 [SYN, ACK] Seq=0 Ack=1', flags: 'SYN,ACK' },
        { id: 3, time: '0.025512', src: '192.168.1.100', dst: '93.184.216.34', protocol: 'TCP', length: 66, info: '55432 → 443 [ACK] Seq=1 Ack=1', flags: 'ACK' },
        { id: 4, time: '0.026100', src: '192.168.1.100', dst: '93.184.216.34', protocol: 'TLSv1.3', length: 571, info: 'Client Hello', flags: '' },
        { id: 5, time: '0.052345', src: '93.184.216.34', dst: '192.168.1.100', protocol: 'TLSv1.3', length: 2867, info: 'Server Hello, Certificate', flags: '' },
        { id: 6, time: '0.053100', src: '192.168.1.100', dst: '93.184.216.34', protocol: 'TLSv1.3', length: 126, info: 'Client Key Exchange', flags: '' },
        { id: 7, time: '0.080234', src: '192.168.1.100', dst: '93.184.216.34', protocol: 'HTTP', length: 345, info: 'GET /api/users HTTP/1.1', flags: '', suspicious: false },
        { id: 8, time: '0.120567', src: '93.184.216.34', dst: '192.168.1.100', protocol: 'HTTP', length: 1420, info: '200 OK (application/json)', flags: '' },

        // Suspicious Traffic
        { id: 9, time: '1.234567', src: '192.168.1.100', dst: '10.0.0.50', protocol: 'TCP', length: 66, info: '12345 → 4444 [SYN] - Suspicious Port', flags: 'SYN', suspicious: true, alert: 'Potential Reverse Shell' },
        { id: 10, time: '1.256789', src: '10.0.0.50', dst: '192.168.1.100', protocol: 'TCP', length: 66, info: '4444 → 12345 [SYN, ACK]', flags: 'SYN,ACK', suspicious: true },
        { id: 11, time: '1.300000', src: '192.168.1.100', dst: '10.0.0.50', protocol: 'TCP', length: 150, info: 'Encrypted C2 Traffic', flags: '', suspicious: true, alert: 'Possible C2 Communication' },

        // DNS
        { id: 12, time: '2.100000', src: '192.168.1.100', dst: '8.8.8.8', protocol: 'DNS', length: 74, info: 'Standard query A evil-c2.com', flags: '', suspicious: true, alert: 'Suspicious DNS Query' },
        { id: 13, time: '2.150000', src: '8.8.8.8', dst: '192.168.1.100', protocol: 'DNS', length: 90, info: 'Standard query response A 10.0.0.50', flags: '', suspicious: true },

        // Port Scan Detection
        { id: 14, time: '3.000000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 22 [SYN]', flags: 'SYN', suspicious: true, alert: 'Port Scan Detected' },
        { id: 15, time: '3.001000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 23 [SYN]', flags: 'SYN', suspicious: true },
        { id: 16, time: '3.002000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 80 [SYN]', flags: 'SYN', suspicious: true },
        { id: 17, time: '3.003000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 443 [SYN]', flags: 'SYN', suspicious: true },
        { id: 18, time: '3.004000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 445 [SYN]', flags: 'SYN', suspicious: true },
        { id: 19, time: '3.005000', src: '10.0.0.200', dst: '192.168.1.100', protocol: 'TCP', length: 60, info: '→ 3389 [SYN]', flags: 'SYN', suspicious: true },

        // SQL Injection in HTTP
        { id: 20, time: '4.500000', src: '10.0.0.200', dst: '192.168.1.50', protocol: 'HTTP', length: 450, info: "GET /search?q=' OR 1=1-- HTTP/1.1", flags: '', suspicious: true, alert: 'SQL Injection Attempt' }
    ],

    // --- ALERTS ---
    alerts: [
        { severity: 'HIGH', type: 'Port Scan', source: '10.0.0.200', count: 6, time: '3.000000' },
        { severity: 'CRITICAL', type: 'Reverse Shell', source: '192.168.1.100', target: '10.0.0.50:4444', time: '1.234567' },
        { severity: 'MEDIUM', type: 'Suspicious DNS', domain: 'evil-c2.com', time: '2.100000' },
        { severity: 'CRITICAL', type: 'SQL Injection', source: '10.0.0.200', target: '/search', time: '4.500000' }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="network-app fade-in">
                <!-- HEADER -->
                <div class="network-header">
                    <div class="header-left">
                        <h1><i class="fas fa-network-wired"></i> Network Packet Analyzer</h1>
                        <p class="subtitle">Wireshark-style Traffic Analysis</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat"><span class="val">${this.packets.length}</span><span class="label">Packets</span></div>
                        <div class="stat"><span class="val">${this.alerts.length}</span><span class="label">Alerts</span></div>
                    </div>
                </div>

                <!-- TABS -->
                <div class="network-tabs">
                    <div class="tab ${this.currentTab === 'capture' ? 'active' : ''}" onclick="NetworkAnalyzer.switchTab('capture')">
                        <i class="fas fa-list"></i> Packet List
                    </div>
                    <div class="tab ${this.currentTab === 'alerts' ? 'active' : ''}" onclick="NetworkAnalyzer.switchTab('alerts')">
                        <i class="fas fa-exclamation-triangle"></i> Alerts
                    </div>
                    <div class="tab ${this.currentTab === 'stats' ? 'active' : ''}" onclick="NetworkAnalyzer.switchTab('stats')">
                        <i class="fas fa-chart-bar"></i> Statistics
                    </div>
                </div>

                <!-- FILTER -->
                <div class="filter-bar">
                    <i class="fas fa-filter"></i>
                    <input type="text" id="packet-filter" placeholder="ip.addr == 192.168.1.100 || tcp.port == 443" value="${this.filterQuery}" onkeyup="NetworkAnalyzer.applyFilter(this.value)">
                    <button onclick="NetworkAnalyzer.clearFilter()">Clear</button>
                </div>

                <!-- CONTENT -->
                <div class="network-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'capture': return this.renderPacketList();
            case 'alerts': return this.renderAlerts();
            case 'stats': return this.renderStats();
            default: return '';
        }
    },

    renderPacketList() {
        const filtered = this.getFilteredPackets();
        return `
            <div class="packet-view">
                <div class="packet-list">
                    <table>
                        <thead>
                            <tr>
                                <th>No.</th>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Length</th>
                                <th>Info</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered.map(p => `
                                <tr class="${p.suspicious ? 'suspicious' : ''} ${this.selectedPacket === p.id ? 'selected' : ''} protocol-${p.protocol.toLowerCase().replace('.', '')}" onclick="NetworkAnalyzer.selectPacket(${p.id})">
                                    <td>${p.id}</td>
                                    <td>${p.time}</td>
                                    <td>${p.src}</td>
                                    <td>${p.dst}</td>
                                    <td><span class="protocol-badge">${p.protocol}</span></td>
                                    <td>${p.length}</td>
                                    <td class="info-cell">
                                        ${p.alert ? `<i class="fas fa-exclamation-triangle alert-icon"></i>` : ''}
                                        ${this.escapeHtml(p.info)}
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ${this.selectedPacket ? this.renderPacketDetails() : ''}
            </div>
        `;
    },

    renderPacketDetails() {
        const p = this.packets.find(pkt => pkt.id === this.selectedPacket);
        if (!p) return '';

        return `
            <div class="packet-details">
                <div class="details-header">
                    <h3><i class="fas fa-info-circle"></i> Packet Details</h3>
                    <button onclick="NetworkAnalyzer.closeDetails()"><i class="fas fa-times"></i></button>
                </div>
                <div class="details-tree">
                    <div class="tree-node">
                        <div class="node-header" onclick="NetworkAnalyzer.toggleNode(this)">
                            <i class="fas fa-chevron-down"></i> Frame ${p.id}: ${p.length} bytes on wire
                        </div>
                        <div class="node-content">
                            <div>Arrival Time: ${p.time}</div>
                            <div>Frame Length: ${p.length} bytes</div>
                        </div>
                    </div>
                    <div class="tree-node">
                        <div class="node-header" onclick="NetworkAnalyzer.toggleNode(this)">
                            <i class="fas fa-chevron-down"></i> Ethernet II
                        </div>
                        <div class="node-content">
                            <div>Src: aa:bb:cc:dd:ee:ff</div>
                            <div>Dst: 11:22:33:44:55:66</div>
                        </div>
                    </div>
                    <div class="tree-node">
                        <div class="node-header" onclick="NetworkAnalyzer.toggleNode(this)">
                            <i class="fas fa-chevron-down"></i> Internet Protocol Version 4
                        </div>
                        <div class="node-content">
                            <div>Src: ${p.src}</div>
                            <div>Dst: ${p.dst}</div>
                            <div>TTL: 64</div>
                        </div>
                    </div>
                    <div class="tree-node">
                        <div class="node-header" onclick="NetworkAnalyzer.toggleNode(this)">
                            <i class="fas fa-chevron-down"></i> ${p.protocol}
                        </div>
                        <div class="node-content">
                            <div>Info: ${this.escapeHtml(p.info)}</div>
                            ${p.flags ? `<div>Flags: ${p.flags}</div>` : ''}
                        </div>
                    </div>
                </div>
                <div class="hex-dump">
                    <h4>Hex Dump</h4>
                    <pre>0000   ${this.generateHexDump()}</pre>
                </div>
            </div>
        `;
    },

    renderAlerts() {
        return `
            <div class="alerts-container">
                <div class="alerts-grid">
                    ${this.alerts.map(a => `
                        <div class="alert-card severity-${a.severity.toLowerCase()}">
                            <div class="alert-icon">
                                ${a.severity === 'CRITICAL' ? '<i class="fas fa-skull-crossbones"></i>' :
                a.severity === 'HIGH' ? '<i class="fas fa-exclamation-triangle"></i>' :
                    '<i class="fas fa-info-circle"></i>'}
                            </div>
                            <div class="alert-content">
                                <div class="alert-type">${a.type}</div>
                                <div class="alert-details">
                                    ${a.source ? `<span>Source: ${a.source}</span>` : ''}
                                    ${a.target ? `<span>Target: ${a.target}</span>` : ''}
                                    ${a.domain ? `<span>Domain: ${a.domain}</span>` : ''}
                                    ${a.count ? `<span>Count: ${a.count}</span>` : ''}
                                </div>
                                <div class="alert-time">@ ${a.time}</div>
                            </div>
                            <div class="alert-severity">${a.severity}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderStats() {
        const protocols = {};
        this.packets.forEach(p => {
            protocols[p.protocol] = (protocols[p.protocol] || 0) + 1;
        });

        return `
            <div class="stats-container">
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3><i class="fas fa-layer-group"></i> Protocol Distribution</h3>
                        <div class="protocol-bars">
                            ${Object.entries(protocols).map(([proto, count]) => {
            const pct = Math.round((count / this.packets.length) * 100);
            return `
                                    <div class="proto-bar">
                                        <span class="proto-name">${proto}</span>
                                        <div class="bar-bg">
                                            <div class="bar-fill" style="width: ${pct}%"></div>
                                        </div>
                                        <span class="proto-count">${count} (${pct}%)</span>
                                    </div>
                                `;
        }).join('')}
                        </div>
                    </div>
                    <div class="stat-card">
                        <h3><i class="fas fa-globe"></i> Top Talkers</h3>
                        <table class="talkers-table">
                            <tr><td>192.168.1.100</td><td>12 packets</td></tr>
                            <tr><td>10.0.0.200</td><td>7 packets</td></tr>
                            <tr><td>93.184.216.34</td><td>4 packets</td></tr>
                            <tr><td>10.0.0.50</td><td>3 packets</td></tr>
                        </table>
                    </div>
                    <div class="stat-card">
                        <h3><i class="fas fa-shield-alt"></i> Security Summary</h3>
                        <div class="security-stats">
                            <div class="sec-stat critical"><span>2</span> Critical</div>
                            <div class="sec-stat high"><span>1</span> High</div>
                            <div class="sec-stat medium"><span>1</span> Medium</div>
                            <div class="sec-stat info"><span>${this.packets.filter(p => p.suspicious).length}</span> Suspicious Packets</div>
                        </div>
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

    selectPacket(id) {
        this.selectedPacket = id;
        this.reRender();
    },

    closeDetails() {
        this.selectedPacket = null;
        this.reRender();
    },

    applyFilter(query) {
        this.filterQuery = query;
        this.reRender();
    },

    clearFilter() {
        this.filterQuery = '';
        document.getElementById('packet-filter').value = '';
        this.reRender();
    },

    getFilteredPackets() {
        if (!this.filterQuery) return this.packets;
        const q = this.filterQuery.toLowerCase();
        return this.packets.filter(p =>
            p.src.includes(q) ||
            p.dst.includes(q) ||
            p.protocol.toLowerCase().includes(q) ||
            p.info.toLowerCase().includes(q)
        );
    },

    toggleNode(el) {
        const content = el.nextElementSibling;
        content.style.display = content.style.display === 'none' ? 'block' : 'none';
        const icon = el.querySelector('i');
        icon.className = content.style.display === 'none' ? 'fas fa-chevron-right' : 'fas fa-chevron-down';
    },

    generateHexDump() {
        let hex = '';
        const bytes = 'aa bb cc dd ee ff 11 22 33 44 55 66 08 00 45 00';
        hex += bytes + '\n';
        hex += '0010   00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 64 5d b8\n';
        hex += '0020   d8 22 d8 68 01 bb e4 f0 30 0a 00 00 00 00 a0 02';
        return hex;
    },

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },

    reRender() {
        const app = document.querySelector('.network-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .network-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a28 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            /* HEADER */
            .network-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .network-header h1 { margin: 0; color: #00bcd4; font-size: 1.8rem; }
            .network-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats { display: flex; gap: 20px; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(0,188,212,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #00bcd4; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            /* TABS */
            .network-tabs { display: flex; gap: 5px; margin-bottom: 15px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #00bcd4; color: #000; }

            /* FILTER */
            .filter-bar { display: flex; align-items: center; gap: 10px; background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 8px; margin-bottom: 15px; }
            .filter-bar i { color: #00bcd4; }
            .filter-bar input { flex: 1; background: transparent; border: none; color: #fff; font-size: 0.95rem; outline: none; font-family: monospace; }
            .filter-bar button { background: rgba(255,255,255,0.1); border: none; padding: 8px 15px; border-radius: 5px; color: #888; cursor: pointer; }
            .filter-bar button:hover { background: rgba(255,255,255,0.2); color: #fff; }

            /* PACKET LIST */
            .packet-view { display: grid; grid-template-columns: 1fr 350px; gap: 15px; }
            .packet-list { background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; }
            .packet-list table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
            .packet-list th { background: rgba(0,188,212,0.2); color: #00bcd4; padding: 10px 8px; text-align: left; font-weight: 500; position: sticky; top: 0; }
            .packet-list td { padding: 8px; border-bottom: 1px solid #222; }
            .packet-list tbody tr { cursor: pointer; transition: 0.1s; }
            .packet-list tbody tr:hover { background: rgba(255,255,255,0.05); }
            .packet-list tr.selected { background: rgba(0,188,212,0.2) !important; }
            .packet-list tr.suspicious { background: rgba(255, 71, 87, 0.1); }
            .packet-list tr.suspicious:hover { background: rgba(255, 71, 87, 0.2); }

            .protocol-badge { padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: bold; }
            .protocol-tcp .protocol-badge { background: rgba(52, 152, 219, 0.3); color: #3498db; }
            .protocol-http .protocol-badge { background: rgba(46, 204, 113, 0.3); color: #2ecc71; }
            .protocol-dns .protocol-badge { background: rgba(155, 89, 182, 0.3); color: #9b59b6; }
            .protocol-tlsv13 .protocol-badge { background: rgba(241, 196, 15, 0.3); color: #f1c40f; }
            
            .info-cell { font-family: monospace; font-size: 0.8rem; }
            .alert-icon { color: #ff4757; margin-right: 5px; }

            /* PACKET DETAILS */
            .packet-details { background: rgba(0,0,0,0.4); border-radius: 10px; padding: 15px; max-height: 600px; overflow-y: auto; }
            .details-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
            .details-header h3 { margin: 0; color: #00bcd4; }
            .details-header button { background: transparent; border: none; color: #888; cursor: pointer; font-size: 1.2rem; }

            .tree-node { margin-bottom: 10px; }
            .node-header { padding: 8px 10px; background: rgba(255,255,255,0.05); border-radius: 5px; cursor: pointer; display: flex; align-items: center; gap: 8px; }
            .node-header:hover { background: rgba(255,255,255,0.1); }
            .node-content { padding: 8px 10px 8px 30px; font-family: monospace; font-size: 0.85rem; color: #888; }
            .node-content div { padding: 3px 0; }

            .hex-dump { margin-top: 15px; }
            .hex-dump h4 { margin: 0 0 10px; color: #888; }
            .hex-dump pre { background: #0a0a0f; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.8rem; color: #00bcd4; overflow-x: auto; }

            /* ALERTS */
            .alerts-grid { display: grid; gap: 15px; }
            .alert-card { display: flex; align-items: center; gap: 15px; padding: 20px; background: rgba(0,0,0,0.3); border-radius: 10px; border-left: 4px solid; }
            .alert-card.severity-critical { border-color: #c0392b; }
            .alert-card.severity-high { border-color: #e74c3c; }
            .alert-card.severity-medium { border-color: #f39c12; }
            .alert-icon { width: 50px; height: 50px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; }
            .severity-critical .alert-icon { background: rgba(192,57,43,0.3); color: #e74c3c; }
            .severity-high .alert-icon { background: rgba(231,76,60,0.3); color: #e74c3c; }
            .severity-medium .alert-icon { background: rgba(243,156,18,0.3); color: #f39c12; }
            .alert-content { flex: 1; }
            .alert-type { font-weight: bold; font-size: 1.1rem; color: #fff; }
            .alert-details { color: #888; font-size: 0.9rem; margin: 5px 0; }
            .alert-details span { margin-right: 15px; }
            .alert-time { font-size: 0.8rem; color: #666; }
            .alert-severity { padding: 5px 12px; border-radius: 15px; font-size: 0.75rem; font-weight: bold; }
            .severity-critical .alert-severity { background: #c0392b; color: #fff; }
            .severity-high .alert-severity { background: #e74c3c; color: #fff; }
            .severity-medium .alert-severity { background: #f39c12; color: #000; }

            /* STATS */
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .stat-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; }
            .stat-card h3 { margin: 0 0 20px; color: #00bcd4; font-size: 1rem; }

            .proto-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
            .proto-name { width: 80px; font-size: 0.85rem; }
            .bar-bg { flex: 1; height: 20px; background: rgba(255,255,255,0.1); border-radius: 10px; overflow: hidden; }
            .bar-fill { height: 100%; background: linear-gradient(90deg, #00bcd4, #00ff88); border-radius: 10px; }
            .proto-count { font-size: 0.8rem; color: #888; width: 70px; text-align: right; }

            .talkers-table { width: 100%; }
            .talkers-table td { padding: 10px; border-bottom: 1px solid #222; }
            .talkers-table td:last-child { text-align: right; color: #00bcd4; }

            .security-stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
            .sec-stat { padding: 15px; border-radius: 8px; text-align: center; }
            .sec-stat span { display: block; font-size: 1.5rem; font-weight: bold; }
            .sec-stat.critical { background: rgba(192,57,43,0.2); color: #e74c3c; }
            .sec-stat.high { background: rgba(231,76,60,0.2); color: #e74c3c; }
            .sec-stat.medium { background: rgba(243,156,18,0.2); color: #f39c12; }
            .sec-stat.info { background: rgba(52,152,219,0.2); color: #3498db; }

            @media (max-width: 1024px) {
                .packet-view { grid-template-columns: 1fr; }
            }
        </style>
        `;
    }
};

function pageNetworkAnalyzer() {
    return NetworkAnalyzer.render();
}
