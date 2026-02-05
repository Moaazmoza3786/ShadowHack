/* ============================================================
   CONTENT FILLER - MISSING PAGES IMPLEMENTATION
   ============================================================ */

const ContentFiller = {
    renderTopicPage(topic) {
        const topics = {
            'web': { title: 'Web Hacking', icon: 'fa-globe', desc: 'Master OWASP Top 10, Injection, and XSS.' },
            'network': { title: 'Network Security', icon: 'fa-network-wired', desc: 'Nmap, Wireshark, and Protocol Analysis.' },
            'forensics': { title: 'Digital Forensics', icon: 'fa-search', desc: 'Analyze artifacts, memory dumps, and malware.' },
            'linux': { title: 'Linux Privilege Escalation', icon: 'fa-linux', desc: 'Bash scripting, Cron jobs, and SUID binaries.' },
            'scripting': { title: 'Python & Bash', icon: 'fa-code', desc: 'Automate your attacks with custom scripts.' }
        };
        const t = topics[topic] || { title: 'Unknown Topic', icon: 'fa-question', desc: '' };

        return `
            <div class="container fade-in">
                <div class="text-center mb-5">
                    <h1 class="display-4"><i class="fa-solid ${t.icon} text-primary"></i> ${t.title}</h1>
                    <p class="lead text-muted">${t.desc}</p>
                </div>
                
                <div class="row g-4">
                    <!-- Placeholder Content Cards -->
                    ${this.renderModuleCard('Module 1: Fundamentals', 'Completed')}
                    ${this.renderModuleCard('Module 2: Advanced Techniques', 'Locked')}
                    ${this.renderModuleCard('Module 3: Real World Scenarios', 'Locked')}
                </div>
            </div>
        `;
    },

    renderModuleCard(title, status) {
        return `
            <div class="col-md-4">
                <div class="card bg-darker border-0 h-100">
                    <div class="card-body text-center p-4">
                        <div class="mb-3">
                            <i class="fa-solid fa-cube fa-3x ${status === 'Locked' ? 'text-secondary' : 'text-success'}"></i>
                        </div>
                        <h3>${title}</h3>
                        <p class="text-muted">Deep dive into core concepts.</p>
                        <button class="btn btn-outline-primary" ${status === 'Locked' ? 'disabled' : ''}>
                            ${status === 'Locked' ? '<i class="fa-solid fa-lock"></i> Locked' : '<i class="fa-solid fa-play"></i> Start'}
                        </button>
                    </div>
                </div>
            </div>
        `;
    },

    renderLabsPage(type) {
        return `
            <div class="container fade-in">
                <h1><i class="fa-solid fa-flask"></i> ${type} Labs</h1>
                <p>Practice your skills in safe, isolated environments.</p>
                
                <div class="alert alert-info">
                    <i class="fa-solid fa-info-circle"></i> Use the <strong>Live Lab & Sandbox</strong> for interactive Docker containers.
                </div>

                <div class="row">
                    ${[1, 2, 3, 4, 5, 6].map(i => `
                        <div class="col-md-3 mb-4">
                            <div class="card cyber-card">
                                <div class="card-body">
                                    <h5>Lab Machine #${i}</h5>
                                    <span class="badge ${type === 'Pro' ? 'bg-warning text-dark' : 'bg-success'}">${type}</span>
                                    <p class="small text-muted mt-2">OS: Linux • Diff: Medium</p>
                                    <button class="btn btn-sm btn-primary w-100">Deploy</button>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderCheatsheets() {
        return `
            <div class="container fade-in">
                <h1><i class="fa-solid fa-scroll"></i> Cheatsheets</h1>
                <div class="list-group">
                    <a href="#" class="list-group-item list-group-item-action bg-dark text-light">
                        <div class="d-flex w-100 justify-content-between">
                            <h5 class="mb-1">Reverse Shells</h5>
                            <small>Updated 2 days ago</small>
                        </div>
                        <p class="mb-1">Common one-liners for Bash, Python, PHP.</p>
                    </a>
                    <a href="#" class="list-group-item list-group-item-action bg-dark text-light">
                        <div class="d-flex w-100 justify-content-between">
                            <h5 class="mb-1">Nmap Quick Reference</h5>
                            <small>Updated 1 week ago</small>
                        </div>
                        <p class="mb-1">Essential scanning flags and scripts.</p>
                    </a>
                    <a href="#" class="list-group-item list-group-item-action bg-dark text-light">
                        <div class="d-flex w-100 justify-content-between">
                            <h5 class="mb-1">Privilege Escalation Checklist</h5>
                            <small>Updated 3 days ago</small>
                        </div>
                        <p class="mb-1">Linux & Windows enumeration steps.</p>
                    </a>
                </div>
            </div>
        `;
    }
};

// Expose globally
window.pageTopicWeb = () => ContentFiller.renderTopicPage('web');
window.pageTopicNetwork = () => ContentFiller.renderTopicPage('network');
window.pageTopicForensics = () => ContentFiller.renderTopicPage('forensics');
window.pageTopicLinux = () => ContentFiller.renderTopicPage('linux');
window.pageTopicScripting = () => ContentFiller.renderTopicPage('scripting');

window.pageFreeLabs = () => ContentFiller.renderLabsPage('Free');
window.pageProLabs = () => ContentFiller.renderLabsPage('Pro');

window.pageCheatsheets = () => ContentFiller.renderCheatsheets();
window.pageDocs = () => '<h2>Documentation</h2><p>Platform documentation is currently being written.</p>';
window.pageVerify = () => '<h2>Certificate Verification</h2><p>Enter your certificate ID to verify authenticity.</p>';
