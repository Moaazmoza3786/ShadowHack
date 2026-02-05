/**
 * Study Hub - Celebration & Certificate System
 * Victory pop-ups, confetti, certificates, and social sharing
 */

const CelebrationSystem = {
    // Configuration
    config: {
        confettiDuration: 5000,
        xpReward: 1000,
        badgeName: 'The Root Access',
        certificateName: 'PT1 Certification'
    },

    // Initialize
    init() {
        this.injectStyles();
    },

    // Generate unique certificate code
    generateCertCode(pathId) {
        const prefix = pathId.toUpperCase().substring(0, 3);
        const random = Math.random().toString(36).substring(2, 6).toUpperCase();
        const num = Math.floor(Math.random() * 9000) + 1000;
        return `AG-${prefix}-${num}-${random}`;
    },

    // Launch confetti explosion
    launchConfetti() {
        const colors = ['#22c55e', '#3b82f6', '#f59e0b', '#ef4444', '#a855f7', '#ec4899'];
        const confettiContainer = document.createElement('div');
        confettiContainer.id = 'confetti-container';
        confettiContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 99999;
            overflow: hidden;
        `;
        document.body.appendChild(confettiContainer);

        // Create confetti pieces
        for (let i = 0; i < 150; i++) {
            setTimeout(() => {
                const confetti = document.createElement('div');
                const color = colors[Math.floor(Math.random() * colors.length)];
                const size = Math.random() * 10 + 5;
                const x = Math.random() * 100;
                const rotation = Math.random() * 360;
                const duration = Math.random() * 2 + 3;

                confetti.style.cssText = `
                    position: absolute;
                    top: -20px;
                    left: ${x}%;
                    width: ${size}px;
                    height: ${size}px;
                    background: ${color};
                    transform: rotate(${rotation}deg);
                    animation: confetti-fall ${duration}s ease-out forwards;
                `;
                confettiContainer.appendChild(confetti);
            }, i * 20);
        }

        // Remove after animation
        setTimeout(() => {
            confettiContainer.remove();
        }, this.config.confettiDuration);
    },

    // Show Victory Pop-up
    showVictoryPopup(options = {}) {
        const {
            userName = 'المستخدم',
            pathName = 'Jr Penetration Tester',
            pathId = 'pt1',
            xpReward = this.config.xpReward,
            badgeName = this.config.badgeName,
            certificateName = this.config.certificateName,
            targetName = 'Gravity Finance'
        } = options;

        const certCode = this.generateCertCode(pathId);
        const certUrl = `https://studyhub.io/verify/${certCode}`;

        // Launch confetti
        this.launchConfetti();

        // Play victory sound
        this.playVictorySound();

        // Create popup
        const popup = document.createElement('div');
        popup.id = 'victory-popup-overlay';
        popup.innerHTML = `
            <div class="victory-popup">
                <div class="victory-glow"></div>
                
                <div class="victory-header">
                    <div class="victory-icon">🎉</div>
                    <h1 class="victory-title">تم اختراق النظام بنجاح!</h1>
                    <h2 class="victory-subtitle">System Compromised!</h2>
                </div>

                <div class="victory-body">
                    <p class="victory-message">
                        عمل رائع يا <strong>${userName}</strong>! لقد أثبت مهارتك واخترقت خادم 
                        <span class="highlight">'${targetName}'</span> بالكامل. 
                        أنت لم تعثر على الثغرة فحسب، بل قمت باستغلالها وتصعيد صلاحياتك للوصول إلى الـ Root.
                    </p>
                    <p class="victory-completion">
                        لقد أنهيت مسار <strong>${pathName}</strong> رسمياً! 🏆
                    </p>
                </div>

                <div class="victory-rewards">
                    <h3><i class="fa-solid fa-gift"></i> الجوائز</h3>
                    <div class="rewards-grid">
                        <div class="reward-item">
                            <div class="reward-icon xp">
                                <i class="fa-solid fa-bolt"></i>
                            </div>
                            <div class="reward-info">
                                <span class="reward-value">+${xpReward} XP</span>
                                <span class="reward-label">تمت إضافتها لرصيدك</span>
                            </div>
                        </div>
                        <div class="reward-item">
                            <div class="reward-icon badge">
                                <i class="fa-solid fa-medal"></i>
                            </div>
                            <div class="reward-info">
                                <span class="reward-value">${badgeName}</span>
                                <span class="reward-label">Badge Unlocked</span>
                            </div>
                        </div>
                        <div class="reward-item">
                            <div class="reward-icon cert">
                                <i class="fa-solid fa-certificate"></i>
                            </div>
                            <div class="reward-info">
                                <span class="reward-value">${certificateName}</span>
                                <span class="reward-label">أصبحت جاهزة</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="victory-actions">
                    <button class="victory-btn primary" onclick="CelebrationSystem.showCertificate('${pathId}', '${userName}', '${certCode}')">
                        <i class="fa-solid fa-scroll"></i> عرض شهادتي
                    </button>
                    <button class="victory-btn secondary" onclick="CelebrationSystem.shareOnLinkedIn('${pathName}', '${certUrl}')">
                        <i class="fa-brands fa-linkedin"></i> شارك على LinkedIn
                    </button>
                </div>

                <button class="victory-close" onclick="document.getElementById('victory-popup-overlay').remove()">
                    <i class="fa-solid fa-times"></i>
                </button>
            </div>
        `;

        document.body.appendChild(popup);

        // Add XP to user
        this.addXP(xpReward);

        // Store certificate in localStorage
        this.storeCertificate(pathId, certCode, userName);
    },

    // Show Certificate
    showCertificate(pathId, userName, certCode) {
        const currentDate = new Date().toLocaleDateString('ar-EG', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });

        const skills = [
            'Linux Systems & Command Line',
            'Web Application Security (OWASP Top 10)',
            'Network Scanning & Enumeration (Nmap)',
            'Vulnerability Exploitation (Metasploit)',
            'Privilege Escalation Techniques',
            'Professional Reporting'
        ];

        const certModal = document.createElement('div');
        certModal.id = 'certificate-modal-overlay';
        certModal.innerHTML = `
            <div class="certificate-modal">
                <div class="certificate-frame">
                    <div class="certificate-border"></div>
                    
                    <div class="certificate-header">
                        <div class="cert-logo">
                            <i class="fa-solid fa-shield-halved"></i>
                        </div>
                        <div class="cert-platform">STUDY HUB</div>
                        <h2>شهادة إتمام مسار</h2>
                        <h3>Certificate of Completion</h3>
                    </div>

                    <div class="certificate-body">
                        <h1 class="cert-title">Junior Penetration Tester</h1>
                        <div class="cert-badge">PT1</div>
                        
                        <p class="cert-recipient">
                            تشهد منصة <strong>Study Hub</strong> بأن
                        </p>
                        <h2 class="cert-name">${userName}</h2>
                        <p class="cert-text">
                            قد أتم بنجاح المنهج العملي والنظري لمسار اختبار الاختراق المبتدئ،
                            واجتاز الاختبار النهائي (Capstone Challenge) بنسبة نجاح <strong>100%</strong>
                        </p>

                        <div class="cert-skills">
                            <h4><i class="fa-solid fa-check-double"></i> المهارات المكتسبة:</h4>
                            <ul>
                                ${skills.map(s => `<li><i class="fa-solid fa-check"></i> ${s}</li>`).join('')}
                            </ul>
                        </div>
                    </div>

                    <div class="certificate-footer">
                        <div class="cert-date">
                            <span class="label">تاريخ الإصدار</span>
                            <span class="value">${currentDate}</span>
                        </div>
                        <div class="cert-signature">
                            <div class="signature-line"></div>
                            <span>المدير الأكاديمي</span>
                        </div>
                        <div class="cert-verify">
                            <span class="label">كود التحقق</span>
                            <span class="value code">${certCode}</span>
                            <a href="/verify/${certCode}" class="verify-link">
                                <i class="fa-solid fa-external-link"></i> تحقق
                            </a>
                        </div>
                    </div>

                    <div class="cert-watermark">ANTIGRAVITY</div>
                </div>

                <div class="certificate-actions">
                    <button class="cert-action-btn" onclick="CelebrationSystem.downloadCertificate('${certCode}')">
                        <i class="fa-solid fa-download"></i> تحميل PDF
                    </button>
                    <button class="cert-action-btn" onclick="CelebrationSystem.shareOnLinkedIn('Junior Penetration Tester', 'https://studyhub.io/verify/${certCode}')">
                        <i class="fa-brands fa-linkedin"></i> مشاركة
                    </button>
                    <button class="cert-action-btn close" onclick="document.getElementById('certificate-modal-overlay').remove()">
                        <i class="fa-solid fa-times"></i> إغلاق
                    </button>
                </div>
            </div>
        `;

        // Remove victory popup if exists
        const victoryPopup = document.getElementById('victory-popup-overlay');
        if (victoryPopup) victoryPopup.remove();

        document.body.appendChild(certModal);
    },

    // Share on LinkedIn
    shareOnLinkedIn(pathName, certUrl) {
        const text = encodeURIComponent(
            `فخور جداً بحصولي اليوم على شهادة ${pathName} من منصة Study Hub! 🚀\n\n` +
            `كانت رحلة ممتعة تعلمت فيها كيفية فحص الشبكات، واكتشاف ثغرات الويب (SQLi, XSS)، ` +
            `واستخدام أدوات مثل Burp Suite و Metasploit، واختتمتها باختبار اختراق عملي (CTF) كامل.\n\n` +
            `يمكنكم التحقق من شهادتي هنا: ${certUrl}\n\n` +
            `#CyberSecurity #PenetrationTesting #StudyHub #Learning #Infosec`
        );

        const linkedInUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(certUrl)}&text=${text}`;
        window.open(linkedInUrl, '_blank', 'width=600,height=500');
    },

    // Download Certificate as PDF
    async downloadCertificate(certCode) {
        // Try API first, fallback to print
        try {
            const response = await fetch(`/api/certificate/download/${certCode}`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `StudyHub_Certificate_${certCode}.pdf`;
                a.click();
                window.URL.revokeObjectURL(url);
                return;
            }
        } catch (e) {
            console.log('Using print fallback');
        }

        // Fallback: Open print dialog
        const certFrame = document.querySelector('.certificate-frame');
        if (certFrame) {
            const printWindow = window.open('', '_blank');
            printWindow.document.write(`
                <html>
                <head>
                    <title>Certificate - ${certCode}</title>
                    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
                    <style>
                        body { margin: 0; padding: 20px; direction: rtl; font-family: 'Cairo', sans-serif; }
                        ${document.getElementById('celebration-styles').textContent}
                    </style>
                </head>
                <body>${certFrame.outerHTML}</body>
                </html>
            `);
            printWindow.document.close();
            printWindow.print();
        }
    },

    // Add XP
    addXP(amount) {
        let userXP = parseInt(localStorage.getItem('userXP') || '0');
        userXP += amount;
        localStorage.setItem('userXP', userXP);

        // Update UI if exists
        const xpDisplay = document.querySelector('.hud-xp-value');
        if (xpDisplay) {
            xpDisplay.textContent = userXP.toLocaleString();
        }
    },

    // Store Certificate
    storeCertificate(pathId, certCode, userName) {
        const certs = JSON.parse(localStorage.getItem('userCertificates') || '[]');
        certs.push({
            pathId,
            certCode,
            userName,
            earnedAt: new Date().toISOString()
        });
        localStorage.setItem('userCertificates', JSON.stringify(certs));
    },

    // Play victory sound
    playVictorySound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const notes = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6

            notes.forEach((freq, i) => {
                setTimeout(() => {
                    const oscillator = audioContext.createOscillator();
                    const gainNode = audioContext.createGain();
                    oscillator.connect(gainNode);
                    gainNode.connect(audioContext.destination);
                    oscillator.frequency.value = freq;
                    oscillator.type = 'sine';
                    gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
                    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
                    oscillator.start(audioContext.currentTime);
                    oscillator.stop(audioContext.currentTime + 0.3);
                }, i * 100);
            });
        } catch (e) {
            console.log('Sound not supported');
        }
    },

    // Inject Styles
    injectStyles() {
        if (document.getElementById('celebration-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'celebration-styles';
        styles.textContent = `
            /* Confetti Animation */
            @keyframes confetti-fall {
                0% { transform: translateY(0) rotate(0deg); opacity: 1; }
                100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
            }

            /* Victory Popup Overlay */
            #victory-popup-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.9);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 99998;
                animation: fadeIn 0.3s ease;
            }

            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            /* Victory Popup */
            .victory-popup {
                position: relative;
                background: linear-gradient(180deg, #1a1a2e 0%, #0f0f1a 100%);
                border: 2px solid #22c55e;
                border-radius: 24px;
                padding: 40px;
                max-width: 600px;
                width: 90%;
                text-align: center;
                animation: popIn 0.5s cubic-bezier(0.18, 0.89, 0.32, 1.28);
                box-shadow: 0 0 100px rgba(34, 197, 94, 0.3);
            }

            @keyframes popIn {
                0% { transform: scale(0.5); opacity: 0; }
                100% { transform: scale(1); opacity: 1; }
            }

            .victory-glow {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 300px;
                height: 300px;
                background: radial-gradient(circle, rgba(34, 197, 94, 0.3) 0%, transparent 70%);
                pointer-events: none;
            }

            .victory-header {
                margin-bottom: 30px;
            }

            .victory-icon {
                font-size: 80px;
                animation: bounce 1s ease infinite;
            }

            @keyframes bounce {
                0%, 100% { transform: translateY(0); }
                50% { transform: translateY(-10px); }
            }

            .victory-title {
                font-size: 32px;
                color: #22c55e;
                margin: 10px 0 5px;
                font-weight: 800;
                text-shadow: 0 0 30px rgba(34, 197, 94, 0.5);
            }

            .victory-subtitle {
                font-size: 20px;
                color: #94a3b8;
                font-weight: 600;
            }

            .victory-body {
                margin-bottom: 30px;
            }

            .victory-message {
                color: rgba(255, 255, 255, 0.85);
                font-size: 16px;
                line-height: 1.8;
            }

            .victory-message .highlight {
                color: #f59e0b;
                font-weight: 700;
            }

            .victory-completion {
                color: #22c55e;
                font-size: 18px;
                font-weight: 700;
                margin-top: 15px;
            }

            /* Rewards */
            .victory-rewards h3 {
                color: #fff;
                font-size: 18px;
                margin-bottom: 20px;
            }

            .victory-rewards h3 i {
                color: #f59e0b;
                margin-left: 8px;
            }

            .rewards-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
            }

            .reward-item {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 15px;
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }

            .reward-icon {
                width: 50px;
                height: 50px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 20px;
            }

            .reward-icon.xp { background: linear-gradient(135deg, #22c55e, #16a34a); color: #000; }
            .reward-icon.badge { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; }
            .reward-icon.cert { background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff; }

            .reward-info {
                text-align: center;
            }

            .reward-value {
                display: block;
                color: #fff;
                font-weight: 700;
                font-size: 14px;
            }

            .reward-label {
                font-size: 11px;
                color: #94a3b8;
            }

            /* Actions */
            .victory-actions {
                display: flex;
                gap: 15px;
                justify-content: center;
                margin-top: 30px;
            }

            .victory-btn {
                padding: 15px 30px;
                border-radius: 12px;
                font-size: 16px;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                gap: 10px;
                border: none;
            }

            .victory-btn.primary {
                background: linear-gradient(135deg, #22c55e, #16a34a);
                color: #000;
                box-shadow: 0 0 30px rgba(34, 197, 94, 0.4);
            }

            .victory-btn.primary:hover {
                transform: translateY(-3px);
                box-shadow: 0 0 50px rgba(34, 197, 94, 0.6);
            }

            .victory-btn.secondary {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
                border: 2px solid #3b82f6;
            }

            .victory-btn.secondary:hover {
                background: rgba(59, 130, 246, 0.3);
            }

            .victory-close {
                position: absolute;
                top: 15px;
                right: 15px;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.1);
                border: none;
                color: #fff;
                cursor: pointer;
                transition: all 0.3s;
            }

            .victory-close:hover {
                background: rgba(239, 68, 68, 0.3);
                color: #ef4444;
            }

            /* Certificate Modal */
            #certificate-modal-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.95);
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                z-index: 99999;
                padding: 20px;
                overflow-y: auto;
            }

            .certificate-modal {
                max-width: 900px;
                width: 100%;
            }

            .certificate-frame {
                background: linear-gradient(180deg, #1a1a2e 0%, #0a0a14 100%);
                border: 3px solid #22c55e;
                border-radius: 20px;
                padding: 50px;
                position: relative;
                overflow: hidden;
            }

            .certificate-border {
                position: absolute;
                top: 10px;
                left: 10px;
                right: 10px;
                bottom: 10px;
                border: 2px dashed rgba(34, 197, 94, 0.3);
                border-radius: 15px;
                pointer-events: none;
            }

            .certificate-header {
                text-align: center;
                margin-bottom: 30px;
            }

            .cert-logo {
                width: 80px;
                height: 80px;
                margin: 0 auto 15px;
                background: linear-gradient(135deg, #22c55e, #16a34a);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 40px;
                color: #000;
                box-shadow: 0 0 40px rgba(34, 197, 94, 0.5);
            }

            .cert-platform {
                font-family: 'Orbitron', sans-serif;
                font-size: 24px;
                font-weight: 800;
                color: #22c55e;
                letter-spacing: 5px;
                margin-bottom: 10px;
            }

            .certificate-header h2 {
                color: #fff;
                font-size: 20px;
                margin: 5px 0;
            }

            .certificate-header h3 {
                color: #94a3b8;
                font-size: 14px;
                font-weight: 400;
            }

            .certificate-body {
                text-align: center;
                padding: 30px 0;
            }

            .cert-title {
                font-size: 42px;
                color: #fff;
                font-weight: 800;
                margin: 0;
                text-shadow: 0 0 30px rgba(255, 255, 255, 0.2);
            }

            .cert-badge {
                display: inline-block;
                background: linear-gradient(135deg, #f59e0b, #d97706);
                color: #000;
                padding: 8px 25px;
                border-radius: 30px;
                font-weight: 800;
                font-size: 18px;
                margin: 15px 0;
            }

            .cert-recipient {
                color: #94a3b8;
                font-size: 16px;
                margin: 20px 0 5px;
            }

            .cert-name {
                font-size: 36px;
                color: #22c55e;
                font-weight: 800;
                margin: 10px 0;
                font-family: 'Cairo', sans-serif;
            }

            .cert-text {
                color: rgba(255, 255, 255, 0.8);
                font-size: 15px;
                line-height: 1.8;
                max-width: 600px;
                margin: 20px auto;
            }

            .cert-skills {
                background: rgba(34, 197, 94, 0.1);
                border-radius: 15px;
                padding: 20px;
                margin: 30px 0;
                text-align: right;
            }

            .cert-skills h4 {
                color: #22c55e;
                margin: 0 0 15px;
            }

            .cert-skills ul {
                list-style: none;
                padding: 0;
                margin: 0;
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 10px;
            }

            .cert-skills li {
                color: rgba(255, 255, 255, 0.85);
                font-size: 13px;
            }

            .cert-skills li i {
                color: #22c55e;
                margin-left: 8px;
            }

            .certificate-footer {
                display: flex;
                justify-content: space-between;
                align-items: flex-end;
                padding-top: 30px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                margin-top: 30px;
            }

            .cert-date, .cert-verify {
                text-align: center;
            }

            .cert-signature {
                text-align: center;
            }

            .signature-line {
                width: 150px;
                border-bottom: 2px solid #22c55e;
                margin-bottom: 8px;
            }

            .certificate-footer .label {
                display: block;
                color: #64748b;
                font-size: 11px;
                margin-bottom: 5px;
            }

            .certificate-footer .value {
                color: #fff;
                font-size: 14px;
                font-weight: 600;
            }

            .certificate-footer .code {
                font-family: 'JetBrains Mono', monospace;
                color: #22c55e;
            }

            .verify-link {
                display: inline-block;
                color: #3b82f6;
                font-size: 12px;
                margin-top: 5px;
                text-decoration: none;
            }

            .cert-watermark {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%) rotate(-45deg);
                font-size: 120px;
                font-weight: 900;
                color: rgba(34, 197, 94, 0.03);
                pointer-events: none;
                font-family: 'Orbitron', sans-serif;
            }

            .certificate-actions {
                display: flex;
                justify-content: center;
                gap: 15px;
                margin-top: 30px;
            }

            .cert-action-btn {
                padding: 12px 25px;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                color: #fff;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                gap: 8px;
            }

            .cert-action-btn:hover {
                background: rgba(34, 197, 94, 0.2);
                border-color: #22c55e;
            }

            .cert-action-btn.close {
                background: rgba(239, 68, 68, 0.2);
                border-color: rgba(239, 68, 68, 0.3);
            }

            .cert-action-btn.close:hover {
                background: rgba(239, 68, 68, 0.3);
            }

            /* Responsive */
            @media (max-width: 768px) {
                .victory-popup { padding: 25px; }
                .victory-title { font-size: 24px; }
                .rewards-grid { grid-template-columns: 1fr; }
                .victory-actions { flex-direction: column; }
                .certificate-frame { padding: 25px; }
                .cert-title { font-size: 28px; }
                .cert-name { font-size: 24px; }
                .cert-skills ul { grid-template-columns: 1fr; }
                .certificate-footer { flex-direction: column; gap: 20px; }
            }
        `;

        document.head.appendChild(styles);
    }
};

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    CelebrationSystem.init();
});

// Global function for triggering celebration
function triggerVictoryCelebration(options) {
    CelebrationSystem.showVictoryPopup(options);
}

// Export
window.CelebrationSystem = CelebrationSystem;
window.triggerVictoryCelebration = triggerVictoryCelebration;
