/* ==================== SOCIAL ENGINEERING LAB 🎭🪤 ==================== */
/* Phishing Analysis, Pretexting & Security Awareness */

window.SocialEngLab = {
    // --- STATE ---
    currentTab: 'phishing',
    selectedScenario: null,
    userChoices: {},
    score: parseInt(localStorage.getItem('social_score') || '0'),

    // --- PHISHING EMAILS ---
    phishingEmails: [
        {
            id: 'phish-1',
            subject: 'Urgent: Your Account Will Be Suspended',
            from: 'security@amaz0n-support.com',
            fromDisplay: 'Amazon Support',
            body: `Dear Valued Customer,

We have detected suspicious activity on your Amazon account. Your account will be suspended within 24 hours unless you verify your identity.

Click here to verify your account immediately: http://amaz0n-secure-login.com/verify

Best regards,
Amazon Security Team`,
            redFlags: ['Fake domain (amaz0n)', 'Urgency tactics', 'Suspicious link', 'Generic greeting'],
            isPhishing: true,
            difficulty: 'Easy'
        },
        {
            id: 'phish-2',
            subject: 'Invoice #INV-2024-0892 Payment Required',
            from: 'accounting@legitcompany.com',
            fromDisplay: 'Accounting Department',
            body: `Hi,

Please find attached the invoice for last month's services. Payment is due within 7 days.

Amount: $4,299.00
Due Date: January 15, 2024

[Download Invoice.pdf.exe]

Thanks,
Accounting`,
            redFlags: ['.exe disguised as PDF', 'Unexpected invoice', 'Vague sender', 'Pressure to pay'],
            isPhishing: true,
            difficulty: 'Medium'
        },
        {
            id: 'legit-1',
            subject: 'Your Monthly Statement is Ready',
            from: 'noreply@bank.com',
            fromDisplay: 'Bank of America',
            body: `Dear John,

Your monthly statement for December 2023 is now available in your online banking portal.

Log in to your account at www.bankofamerica.com to view your statement.

Thank you for banking with us.

Bank of America`,
            redFlags: [],
            isPhishing: false,
            difficulty: 'Easy'
        },
        {
            id: 'phish-3',
            subject: 'RE: Meeting Tomorrow - Updated Link',
            from: 'ceo@company-internal.net',
            fromDisplay: 'John Smith (CEO)',
            body: `Hey,

Sorry for the confusion earlier. Here's the new meeting link for tomorrow:

https://zoom-meeting-join.com/room/8372918

Please be on time, we have important things to discuss.

- John

Sent from my iPhone`,
            redFlags: ['Spoofed CEO', 'External domain pretending to be internal', 'Fake Zoom link', 'Vague urgency'],
            isPhishing: true,
            difficulty: 'Hard'
        },
        {
            id: 'phish-4',
            subject: 'Password Reset Request',
            from: 'no-reply@micros0ft-security.com',
            fromDisplay: 'Microsoft Account',
            body: `Someone requested a password reset for your Microsoft account.

If this was you, click the link below:
http://micros0ft-password-reset.com/reset?token=abc123

If you did not request this, secure your account immediately!

Microsoft Security Team`,
            redFlags: ['Fake Microsoft domain', 'Zero in micros0ft', 'Suspicious reset link', 'Fear tactics'],
            isPhishing: true,
            difficulty: 'Easy'
        }
    ],

    // --- PRETEXTING SCENARIOS ---
    pretextingScenarios: [
        {
            id: 'pretext-1',
            title: 'The IT Support Call',
            description: 'You receive a call from someone claiming to be from IT support. They say there is a virus on your computer and they need your password to fix it remotely.',
            options: [
                { text: 'Give them your password to fix the issue', correct: false, feedback: '❌ Never share your password! Legitimate IT support never asks for passwords.' },
                { text: 'Ask for their employee ID and call IT back', correct: true, feedback: '✅ Correct! Always verify identity through official channels.' },
                { text: 'Let them remote into your computer', correct: false, feedback: '❌ Never allow unknown remote access. This is a classic scam.' }
            ]
        },
        {
            id: 'pretext-2',
            title: 'The Tailgating Attempt',
            description: 'A person in a delivery uniform is waiting at the secure door without a badge. They ask you to hold the door for them because their hands are full.',
            options: [
                { text: 'Hold the door open for them', correct: false, feedback: '❌ This is tailgating. Attackers use social pressure to gain access.' },
                { text: 'Politely ask them to use their badge or call reception', correct: true, feedback: '✅ Correct! Everyone must use their own credentials to enter.' },
                { text: 'Ignore them and walk in', correct: false, feedback: '❌ You should actively prevent tailgating, not just ignore it.' }
            ]
        },
        {
            id: 'pretext-3',
            title: 'The USB Drop',
            description: 'You find a USB drive in the parking lot labeled "Salary Data 2024". What do you do?',
            options: [
                { text: 'Plug it into your work computer to see what is on it', correct: false, feedback: '❌ This is a USB drop attack! The drive could contain malware.' },
                { text: 'Take it to IT security without plugging it in', correct: true, feedback: '✅ Correct! Report suspicious devices to security.' },
                { text: 'Throw it away', correct: false, feedback: '⚠️ While not the worst option, IT should analyze it for threats.' }
            ]
        },
        {
            id: 'pretext-4',
            title: 'The Urgent Email from Boss',
            description: 'You receive an email from your CEO asking you to urgently buy gift cards and send the codes. They claim to be in a meeting and need them immediately.',
            options: [
                { text: 'Buy the gift cards immediately', correct: false, feedback: '❌ This is CEO fraud! Verify through another channel.' },
                { text: 'Call your CEO directly to verify', correct: true, feedback: '✅ Correct! Always verify unusual requests through a different communication channel.' },
                { text: 'Reply to the email asking for more details', correct: false, feedback: '❌ The attacker controls the email. Use a separate channel to verify.' }
            ]
        }
    ],

    // --- RENDER ---
    render() {
        return `
            <div class="social-app fade-in">
                <div class="social-header">
                    <div class="header-left">
                        <h1><i class="fas fa-theater-masks"></i> Social Engineering Lab</h1>
                        <p class="subtitle">Phishing Analysis & Security Awareness</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat"><span class="val">${this.score}</span><span class="label">Points</span></div>
                    </div>
                </div>

                <div class="social-tabs">
                    <div class="tab ${this.currentTab === 'phishing' ? 'active' : ''}" onclick="SocialEngLab.switchTab('phishing')">
                        <i class="fas fa-fish"></i> Phishing Detection
                    </div>
                    <div class="tab ${this.currentTab === 'pretexting' ? 'active' : ''}" onclick="SocialEngLab.switchTab('pretexting')">
                        <i class="fas fa-user-secret"></i> Pretexting Scenarios
                    </div>
                    <div class="tab ${this.currentTab === 'awareness' ? 'active' : ''}" onclick="SocialEngLab.switchTab('awareness')">
                        <i class="fas fa-graduation-cap"></i> Awareness Training
                    </div>
                </div>

                <div class="social-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'phishing': return this.renderPhishing();
            case 'pretexting': return this.renderPretexting();
            case 'awareness': return this.renderAwareness();
            default: return '';
        }
    },

    renderPhishing() {
        return `
            <div class="phishing-section">
                <h2><i class="fas fa-envelope"></i> Email Inbox</h2>
                <p class="section-desc">Analyze each email and identify if it's a phishing attempt</p>
                
                <div class="inbox">
                    ${this.phishingEmails.map(e => `
                        <div class="email-item ${this.selectedScenario === e.id ? 'selected' : ''}" onclick="SocialEngLab.selectEmail('${e.id}')">
                            <div class="email-sender">${e.fromDisplay}</div>
                            <div class="email-subject">${e.subject}</div>
                            <span class="diff ${e.difficulty.toLowerCase()}">${e.difficulty}</span>
                        </div>
                    `).join('')}
                </div>

                ${this.selectedScenario ? this.renderEmailDetail() : `
                    <div class="email-placeholder"><i class="fas fa-inbox"></i><p>Select an email to analyze</p></div>
                `}
            </div>
        `;
    },

    renderEmailDetail() {
        const e = this.phishingEmails.find(em => em.id === this.selectedScenario);
        if (!e) return '';
        const answered = this.userChoices[e.id] !== undefined;

        return `
            <div class="email-detail">
                <div class="email-header">
                    <div class="email-from"><strong>From:</strong> ${e.from} <span class="display-name">(${e.fromDisplay})</span></div>
                    <div class="email-subj"><strong>Subject:</strong> ${e.subject}</div>
                </div>
                <div class="email-body"><pre>${e.body}</pre></div>

                ${answered ? `
                    <div class="email-result ${this.userChoices[e.id] === e.isPhishing ? 'correct' : 'wrong'}">
                        <h4>${this.userChoices[e.id] === e.isPhishing ? '✅ Correct!' : '❌ Incorrect!'}</h4>
                        <p>This email is <strong>${e.isPhishing ? 'PHISHING' : 'LEGITIMATE'}</strong></p>
                        ${e.isPhishing ? `
                            <div class="red-flags">
                                <h5>🚩 Red Flags:</h5>
                                <ul>${e.redFlags.map(f => `<li>${f}</li>`).join('')}</ul>
                            </div>
                        ` : ''}
                    </div>
                ` : `
                    <div class="email-actions">
                        <button class="btn-safe" onclick="SocialEngLab.answerPhishing('${e.id}', false)">
                            <i class="fas fa-check-circle"></i> Legitimate
                        </button>
                        <button class="btn-phish" onclick="SocialEngLab.answerPhishing('${e.id}', true)">
                            <i class="fas fa-exclamation-triangle"></i> Phishing
                        </button>
                    </div>
                `}
            </div>
        `;
    },

    renderPretexting() {
        return `
            <div class="pretexting-section">
                <h2><i class="fas fa-user-secret"></i> Pretexting Scenarios</h2>
                <p class="section-desc">Choose the correct response to each social engineering scenario</p>

                <div class="scenarios-grid">
                    ${this.pretextingScenarios.map(s => `
                        <div class="scenario-card">
                            <h3>${s.title}</h3>
                            <p>${s.description}</p>
                            <div class="options">
                                ${s.options.map((opt, i) => `
                                    <button class="option-btn ${this.userChoices[s.id] === i ? (opt.correct ? 'correct' : 'wrong') : ''}" 
                                            onclick="SocialEngLab.answerPretext('${s.id}', ${i})"
                                            ${this.userChoices[s.id] !== undefined ? 'disabled' : ''}>
                                        ${opt.text}
                                    </button>
                                `).join('')}
                            </div>
                            ${this.userChoices[s.id] !== undefined ? `
                                <div class="feedback">${s.options[this.userChoices[s.id]].feedback}</div>
                            ` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderAwareness() {
        return `
            <div class="awareness-section">
                <h2><i class="fas fa-graduation-cap"></i> Security Awareness Training</h2>

                <div class="training-grid">
                    <div class="training-card">
                        <i class="fas fa-fish"></i>
                        <h3>Phishing Prevention</h3>
                        <ul>
                            <li>Check sender's actual email address</li>
                            <li>Hover over links before clicking</li>
                            <li>Look for spelling/grammar errors</li>
                            <li>Be suspicious of urgency tactics</li>
                            <li>Verify requests through official channels</li>
                        </ul>
                    </div>
                    <div class="training-card">
                        <i class="fas fa-phone-alt"></i>
                        <h3>Vishing Defense</h3>
                        <ul>
                            <li>Never share passwords over the phone</li>
                            <li>Call back using official numbers</li>
                            <li>Be wary of unsolicited calls</li>
                            <li>Ask for caller verification</li>
                            <li>Report suspicious calls to IT</li>
                        </ul>
                    </div>
                    <div class="training-card">
                        <i class="fas fa-door-open"></i>
                        <h3>Physical Security</h3>
                        <ul>
                            <li>Always badge in yourself</li>
                            <li>Don't hold doors for strangers</li>
                            <li>Challenge unfamiliar faces</li>
                            <li>Secure sensitive documents</li>
                            <li>Lock your computer when away</li>
                        </ul>
                    </div>
                    <div class="training-card">
                        <i class="fas fa-usb"></i>
                        <h3>USB Security</h3>
                        <ul>
                            <li>Never plug in unknown USB devices</li>
                            <li>Report found drives to IT</li>
                            <li>Use only company-approved drives</li>
                            <li>Encrypt sensitive data</li>
                            <li>Disable autorun features</li>
                        </ul>
                    </div>
                </div>

                <div class="attack-types">
                    <h3><i class="fas fa-skull-crossbones"></i> Common Attack Types</h3>
                    <div class="attack-grid">
                        <div class="attack"><strong>Phishing</strong> - Fraudulent emails/messages</div>
                        <div class="attack"><strong>Spear Phishing</strong> - Targeted phishing</div>
                        <div class="attack"><strong>Whaling</strong> - Executive-targeted attacks</div>
                        <div class="attack"><strong>Vishing</strong> - Voice phishing</div>
                        <div class="attack"><strong>Smishing</strong> - SMS phishing</div>
                        <div class="attack"><strong>Pretexting</strong> - Fabricated scenarios</div>
                        <div class="attack"><strong>Baiting</strong> - Malware-laden lures</div>
                        <div class="attack"><strong>Tailgating</strong> - Physical access following</div>
                    </div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.selectedScenario = null;
        this.reRender();
    },

    selectEmail(id) {
        this.selectedScenario = id;
        this.reRender();
    },

    answerPhishing(id, userSaysPhishing) {
        const email = this.phishingEmails.find(e => e.id === id);
        this.userChoices[id] = userSaysPhishing;
        if (userSaysPhishing === email.isPhishing) {
            this.score += 50;
            localStorage.setItem('social_score', this.score);
        }
        this.reRender();
    },

    answerPretext(id, optionIndex) {
        const scenario = this.pretextingScenarios.find(s => s.id === id);
        this.userChoices[id] = optionIndex;
        if (scenario.options[optionIndex].correct) {
            this.score += 100;
            localStorage.setItem('social_score', this.score);
        }
        this.reRender();
    },

    reRender() {
        const app = document.querySelector('.social-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `
        <style>
            .social-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            
            .social-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .social-header h1 { margin: 0; color: #9b59b6; font-size: 1.8rem; }
            .social-header .subtitle { color: #888; margin: 5px 0 0; }
            .header-stats .stat { text-align: center; padding: 10px 20px; background: rgba(155,89,182,0.1); border-radius: 10px; }
            .header-stats .val { display: block; font-size: 1.5rem; font-weight: bold; color: #9b59b6; }
            .header-stats .label { font-size: 0.8rem; color: #888; }

            .social-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #9b59b6; color: #fff; }

            /* PHISHING */
            .phishing-section { display: grid; grid-template-columns: 350px 1fr; gap: 25px; }
            .phishing-section h2 { grid-column: 1/-1; color: #9b59b6; margin: 0 0 5px; }
            .section-desc { grid-column: 1/-1; color: #888; margin: 0 0 15px; }
            
            .inbox { background: rgba(0,0,0,0.3); border-radius: 12px; overflow: hidden; }
            .email-item { display: flex; align-items: center; gap: 15px; padding: 15px; border-bottom: 1px solid #222; cursor: pointer; transition: 0.2s; }
            .email-item:hover { background: rgba(255,255,255,0.05); }
            .email-item.selected { background: rgba(155,89,182,0.2); border-left: 3px solid #9b59b6; }
            .email-sender { width: 120px; font-weight: bold; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .email-subject { flex: 1; color: #aaa; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .diff { padding: 3px 8px; border-radius: 10px; font-size: 0.7rem; font-weight: bold; }
            .diff.easy { background: #2ecc71; color: #000; }
            .diff.medium { background: #f39c12; color: #000; }
            .diff.hard { background: #e74c3c; color: #fff; }

            .email-placeholder { text-align: center; padding: 80px; color: #555; }
            .email-placeholder i { font-size: 3rem; margin-bottom: 15px; display: block; }

            .email-detail { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 12px; }
            .email-header { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #333; }
            .email-from { margin-bottom: 5px; color: #aaa; }
            .display-name { color: #666; }
            .email-subj { color: #fff; font-size: 1.1rem; }
            .email-body { background: #0a0a12; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
            .email-body pre { margin: 0; white-space: pre-wrap; color: #ccc; font-family: inherit; }

            .email-actions { display: flex; gap: 15px; }
            .btn-safe, .btn-phish { flex: 1; padding: 15px; border: none; border-radius: 10px; font-size: 1rem; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px; }
            .btn-safe { background: #2ecc71; color: #fff; }
            .btn-phish { background: #e74c3c; color: #fff; }

            .email-result { padding: 20px; border-radius: 10px; }
            .email-result.correct { background: rgba(46,204,113,0.2); border: 1px solid #2ecc71; }
            .email-result.wrong { background: rgba(231,76,60,0.2); border: 1px solid #e74c3c; }
            .email-result h4 { margin: 0 0 10px; }
            .red-flags h5 { color: #e74c3c; margin: 15px 0 10px; }
            .red-flags ul { margin: 0; padding-left: 20px; color: #aaa; }
            .red-flags li { margin: 5px 0; }

            /* PRETEXTING */
            .pretexting-section h2 { color: #9b59b6; margin: 0 0 5px; }
            .scenarios-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin-top: 20px; }
            .scenario-card { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .scenario-card h3 { color: #9b59b6; margin: 0 0 15px; }
            .scenario-card > p { color: #aaa; margin: 0 0 20px; }
            .options { display: flex; flex-direction: column; gap: 10px; }
            .option-btn { padding: 12px 15px; background: rgba(255,255,255,0.05); border: 1px solid #333; border-radius: 8px; color: #fff; text-align: left; cursor: pointer; transition: 0.2s; }
            .option-btn:hover:not(:disabled) { background: rgba(255,255,255,0.1); }
            .option-btn.correct { background: rgba(46,204,113,0.3); border-color: #2ecc71; }
            .option-btn.wrong { background: rgba(231,76,60,0.3); border-color: #e74c3c; }
            .option-btn:disabled { cursor: default; opacity: 0.7; }
            .feedback { margin-top: 15px; padding: 12px; background: rgba(155,89,182,0.1); border-radius: 8px; color: #aaa; }

            /* AWARENESS */
            .awareness-section h2 { color: #9b59b6; margin: 0 0 20px; }
            .training-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .training-card { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .training-card i { font-size: 2.5rem; color: #9b59b6; margin-bottom: 15px; }
            .training-card h3 { margin: 0 0 15px; color: #fff; }
            .training-card ul { margin: 0; padding-left: 20px; color: #888; }
            .training-card li { margin: 8px 0; }

            .attack-types h3 { color: #e74c3c; margin: 0 0 15px; }
            .attack-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
            .attack { background: rgba(231,76,60,0.1); padding: 12px 15px; border-radius: 8px; color: #aaa; }
            .attack strong { color: #e74c3c; }

            @media (max-width: 900px) { .phishing-section { grid-template-columns: 1fr; } }
        </style>
        `;
    }
};

function pageSocialEngLab() {
    return SocialEngLab.render();
}
