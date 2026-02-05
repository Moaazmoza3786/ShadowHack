/* ============================================================
   SHADOWHACK - HOME PAGE
   Professional landing page matching the cyber theme
   ============================================================ */

function pageHome() {
    const isArabic = document.documentElement.lang === 'ar';

    return `
    <div class="home-page">
        <!-- Hero Section V2 -->
        <section class="hero-v2">
            <div class="cyber-grid-bg"></div>
            <div id="particles-js" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; pointer-events: none;"></div>

            <div class="hero-v2-content slide-in-left">
                <div class="hero-badge mb-4">
                     <span class="pulse-dot"></span>
                     ${isArabic ? 'منصة التدريب السيبراني المتقدمة' : 'Advanced Cyber Training Platform'}
                </div>
                
                <h1>
                    <span class="glitch" data-text="ELITE">ELITE</span> <br>
                    <span class="text-gradient">RED TEAM OPS</span>
                </h1>
                
                <p>
                    ${isArabic
            ? 'احترف عمليات الفريق الأحمر والاختراق المتقدم. تخصص في Active Directory، تطوير البرمجيات الخبيثة، ومحاكاة الهجمات الواقعية.'
            : 'Master Red Team Operations and Advanced Adversary Emulation. Specialize in Active Directory, Malware Dev, and C2 Infrastructure.'}
                </p>
                
                <div class="d-flex gap-3 mt-4">
                    <button onclick="loadPage('courses')" class="btn-glitch-v2">
                        ${isArabic ? 'ابدأ الآن' : 'Start Hacking'}
                    </button>
                    <button onclick="loadPage('practice')" class="cyber-btn secondary-glass">
                         ${isArabic ? 'المختبرات' : 'Explore Labs'}
                    </button>
                </div>
                
                <div class="hero-subtitle mt-5">
                    <span class="text-primary">>_</span> <span id="typing-text" class="ms-2"></span><span class="cursor-blink">|</span>
                </div>
            </div>

            <!-- Holographic Visual (Preserved) -->
            <div class="hero-visual fade-in-up">
                <div class="holo-container">
                    <div class="holo-core">
                         <svg viewBox="0 0 100 100" fill="none">
                              <path d="M50 5 L90 20 L90 50 Q90 80 50 95 Q10 80 10 50 L10 20 Z" fill="rgba(0, 0, 0, 0.5)" stroke="#00ff88" stroke-width="4" />
                              <rect x="42" y="45" width="16" height="12" rx="2" fill="#00ff88" />
                              <path d="M45 45 V40 Q45 35 50 35 Q55 35 55 40 V45" stroke="#00ff88" stroke-width="3" fill="none" />
                         </svg>
                    </div>
                    <div class="holo-surface"></div>
                    <div class="holo-ring ring-1"></div>
                    <div class="holo-ring ring-2"></div>
                    <div class="holo-ring ring-3"></div>
                    <div class="holo-scanner"></div>
                    
                    <div class="floating-icons">
                        <div class="f-icon i1"><i class="fas fa-shield-halved"></i></div>
                        <div class="f-icon i2"><i class="fas fa-terminal"></i></div>
                        <div class="f-icon i3"><i class="fas fa-code"></i></div>
                        <div class="f-icon i4"><i class="fas fa-network-wired"></i></div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Stats Section -->
            <div class="container mb-5">
               <div class="cyber-panel p-4 d-flex justify-content-around align-items-center text-center">
                  <div class="stat-item">
                     <div class="stat-value text-primary font-orbitron fs-2">50+</div>
                     <div class="stat-label text-muted small">MODULES</div>
                  </div>
                  <div class="vr bg-secondary opacity-25" style="height: 40px;"></div>
                  <div class="stat-item">
                     <div class="stat-value text-primary font-orbitron fs-2">100+</div>
                     <div class="stat-label text-muted small">LABS</div>
                  </div>
                  <div class="vr bg-secondary opacity-25" style="height: 40px;"></div>
                  <div class="stat-item">
                     <div class="stat-value text-primary font-orbitron fs-2">CTF</div>
                     <div class="stat-label text-muted small">CHALLENGES</div>
                  </div>
               </div>
            </div>

        <!-- Features Grid V2 -->
        <section class="container py-5">
            <div class="section-header text-center mb-5">
                <h2 class="section-title font-orbitron">${isArabic ? 'مجالات التدريب' : 'TRAINING OPERATIONS'}</h2>
                <div class="section-line mx-auto bg-primary" style="width: 50px; height: 3px;"></div>
            </div>
            
            <div class="category-grid">
               ${[
            { icon: 'fa-layer-group', title: 'Modular Learning', color: '#00ff88', desc: 'Focused modules on specific topics.', action: "loadPage('learn')" },
            { icon: 'fa-server', title: 'Cloud Labs', color: '#00ccff', desc: 'Instant access to Kali Linux & Docker labs.', action: "loadPage('labs')" },
            { icon: 'fa-flag', title: 'CTF Arena', color: '#ff0055', desc: 'Test your skills in Capture The Flag events.', action: "loadPage('ctf')" },
            { icon: 'fa-graduation-cap', title: 'Professional Courses', color: '#ffbb00', desc: 'Structured specialized courses.', action: "loadPage('courses')" }
        ].map(f => `
                  <div class="category-card" onclick="${f.action}" style="cursor: pointer;">
                      <div class="category-icon" style="color: ${f.color}">
                          <i class="fas ${f.icon}"></i>
                      </div>
                      <h3 class="text-white mb-2 font-orbitron">${f.title}</h3>
                      <p class="text-muted small mb-0">${f.desc}</p>
                  </div>
               `).join('')}
            </div>
        </section>

        <!-- Featured Paths Section -->
        <section class="paths-section container">
             <div class="section-header">
                <h2 class="section-title fade-in-up">${isArabic ? 'مسارات التعلم' : 'Featured Paths'}</h2>
                <div class="section-line fade-in-up"></div>
             </div>
             
         <div class="paths-grid animate-stagger">
                 ${[
            { title: 'Red Teaming', icon: 'fa-user-secret', color: '#ff5f56', desc: 'Offensive Security & Pentesting', progress: 0, id: 'red-team-path' },
            { title: 'Exploit Dev', icon: 'fa-bug', color: '#ff8f00', desc: 'Buffer Overflows & Shellcoding', progress: 0, id: 'exploit-development-path' },
            { title: 'Web Adversary', icon: 'fa-spider', color: '#ff2e2e', desc: 'Advanced Web Attacks', progress: 0, id: 'bug-bounty-path' },
            { title: 'Web Architecture', icon: 'fa-cubes', color: '#00d4ff', desc: 'Secure Design & Exploitation', progress: 0, id: 'web-security-architecture-path' }
        ].map((p, i) => `
                     <div class="path-card hover-lift card-animate animate-item" onclick="loadPage('path-roadmap', '${p.id || 'skill-tree'}')" style="animation-delay: ${i * 0.2}s">
                        <div class="path-icon-wrapper" style="border-color: ${p.color}">
                            <div class="path-icon" style="color: ${p.color}"><i class="fas ${p.icon}"></i></div>
                        </div>
                        <div class="path-info">
                            <h3>${p.title}</h3>
                            <p>${p.desc}</p>
                            <div class="path-progress-container">
                                <div class="path-progress-bar" style="width: ${p.progress}%; background: ${p.color}"></div>
                            </div>
                            <span class="path-status" style="color: ${p.color}">Start Path <i class="fas fa-arrow-right"></i></span>
                        </div>
                     </div>
                  `).join('')}
             </div>
        </section>
        
        <!-- Script to Init -->
        <script>
            setTimeout(() => {
                if(typeof initHomePage === 'function') initHomePage();
            }, 100);
        </script>
    </div>
    `;
}

// Initialize Home Page Animations
function initHomePage() {
    // 1. Typing Effect
    const typingText = document.getElementById('typing-text');
    if (typingText) {
        const words = ["ACTIVE DIRECTORY ATTACKS", "MALWARE DEVELOPMENT", "C2 INFRASTRUCTURE", "ADVANCED EVASION", "PHYSICAL INTRUSION"];
        let wordIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typeSpeed = 100;

        function type() {
            const currentWord = words[wordIndex];
            if (isDeleting) {
                typingText.textContent = currentWord.substring(0, charIndex - 1);
                charIndex--;
                typeSpeed = 50;
            } else {
                typingText.textContent = currentWord.substring(0, charIndex + 1);
                charIndex++;
                typeSpeed = 100;
            }

            if (!isDeleting && charIndex === currentWord.length) {
                isDeleting = true;
                typeSpeed = 2000; // Pause at end
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                wordIndex = (wordIndex + 1) % words.length;
                typeSpeed = 500;
            }

            setTimeout(type, typeSpeed);
        }
        type();
    }

    // 2. 3D Tilt Effect
    const heroVisual = document.querySelector('.hero-visual');
    if (heroVisual) {
        document.addEventListener('mousemove', (e) => {
            const { clientX, clientY } = e;
            const x = (window.innerWidth / 2 - clientX) / 50;
            const y = (window.innerHeight / 2 - clientY) / 50;
            heroVisual.style.transform = `rotateY(${x}deg) rotateX(${y}deg)`;
        });
    }

    // 3. Stats Counter
    const stats = document.querySelectorAll('.stat-value');
    stats.forEach(stat => {
        const target = parseInt(stat.innerText);
        if (isNaN(target)) return;
        let current = 0;
        const increment = target / 50;
        const updateCount = () => {
            if (current < target) {
                current += increment;
                stat.innerText = Math.ceil(current) + '+';
                setTimeout(updateCount, 40);
            } else {
                stat.innerText = target + '+';
            }
        };
        updateCount();
    });
}
