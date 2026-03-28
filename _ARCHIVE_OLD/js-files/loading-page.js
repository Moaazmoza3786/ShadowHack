/* ============================================================
   BREACHLABS - ULTIMATE HACKING LOADING PAGE
   Theme: Matrix Rain + Security Clearance
   ============================================================ */

const LoadingPage = {
  show(message = 'ESTABLISHING SECURE CONNECTION...') {
    this.hide();

    // Fonts
    const isArabic = document.documentElement.lang === 'ar';
    const fontMono = "'Share Tech Mono', 'Consolas', monospace";
    const fontPrimary = isArabic ? "'Cairo', sans-serif" : "'Orbitron', sans-serif";

    // Create Overlay
    const overlay = document.createElement('div');
    overlay.id = 'breachlabs-loader';
    overlay.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
        
        #breachlabs-loader {
          position: fixed; top: 0; left: 0; width: 100%; height: 100%;
          background: #000; z-index: 999999;
          overflow: hidden;
          font-family: ${fontMono};
          display: flex; flex-direction: column; justify-content: center; align-items: center;
          color: #00ff88;
        }

        /* --- MATRIX BACKGROUND --- */
        #matrix-canvas {
            position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            opacity: 0.15; z-index: 0; pointer-events: none;
        }

        /* --- VIGNETTE & SCANLINES --- */
        .crt-overlay {
            position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle, transparent 50%, #000 150%);
            background-size: 100% 2px;
            pointer-events: none; z-index: 1;
        }
        .crt-overlay::after {
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%);
            background-size: 100% 4px;
        }

        /* --- MAIN CONTENT CONTAINER --- */
        .loader-interface {
            position: relative; z-index: 10;
            display: flex; flex-direction: column; align-items: center;
            width: 100%; max-width: 600px;
            padding: 40px;
            background: rgba(0, 10, 0, 0.6);
            border: 1px solid rgba(0, 255, 136, 0.2);
            border-radius: 4px;
            backdrop-filter: blur(5px);
            box-shadow: 0 0 50px rgba(0, 0, 0, 0.8);
            clip-path: polygon(
                0 0, 100% 0, 100% calc(100% - 20px), calc(100% - 20px) 100%, 
                20px 100%, 0 calc(100% - 20px)
            );
        }

        /* --- LOGO / LOCK --- */
        .security-lock {
            width: 100px; height: 100px; margin-bottom: 30px;
            position: relative;
            display: flex; align-items: center; justify-content: center;
        }
        .lock-ring {
            position: absolute; width: 100%; height: 100%;
            border: 2px dashed #00ff88; border-radius: 50%;
            animation: spinLock 10s linear infinite;
        }
        .lock-ring-2 {
            position: absolute; width: 80%; height: 80%;
            border: 2px solid rgba(0, 255, 136, 0.3); border-radius: 50%;
            border-top-color: #00ff88;
            animation: spinLock 2s linear infinite reverse;
        }
        .lock-icon {
            font-size: 40px; color: #00ff88;
            filter: drop-shadow(0 0 10px #00ff88);
            animation: pulseIcon 1s infinite alternate;
        }

        /* --- TYPOGRAPHY --- */
        .boot-title {
            font-family: ${fontPrimary};
            font-size: 2.5rem; color: #fff; margin: 0;
            letter-spacing: 5px; font-weight: 800;
            text-shadow: 0 0 15px rgba(0, 255, 136, 0.5);
            margin-bottom: 5px;
        }
        .boot-subtitle {
            font-size: 0.9rem; color: #00ff88; letter-spacing: 2px;
            margin-bottom: 40px; opacity: 0.8;
            text-transform: uppercase;
        }

        /* --- PROGRESS BAR --- */
        .hack-progress-container {
            width: 100%; height: 6px;
            background: rgba(0, 255, 136, 0.1);
            position: relative; margin-bottom: 15px;
            overflow: hidden;
        }
        .hack-progress-bar {
            position: absolute; top: 0; left: 0; height: 100%; width: 0%;
            background: #00ff88;
            box-shadow: 0 0 15px #00ff88;
            animation: loadHack 3s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }

        /* --- TERMINAL LOGS --- */
        .terminal-log {
            width: 100%; height: 60px;
            font-size: 12px; color: rgba(0, 255, 136, 0.7);
            overflow: hidden; text-align: left;
            border-top: 1px solid rgba(0, 255, 136, 0.1);
            padding-top: 10px;
            display: flex; flex-direction: column; justify-content: flex-end;
        }
        .log-line { margin-bottom: 2px; white-space: nowrap; }

        /* --- ANIMATIONS --- */
        @keyframes spinLock { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes pulseIcon { 0% { opacity: 0.5; transform: scale(0.9); } 100% { opacity: 1; transform: scale(1.1); } }
        @keyframes loadHack { 0% { width: 0%; } 20% { width: 10%; } 40% { width: 45%; } 60% { width: 60%; } 100% { width: 100%; } }
      </style>

      <canvas id="matrix-canvas"></canvas>
      <div class="crt-overlay"></div>

      <div class="loader-interface">
          <div class="security-lock">
              <div class="lock-ring"></div>
              <div class="lock-ring-2"></div>
              <div class="lock-icon">
                   <svg viewBox="0 0 100 100" fill="none" width="50" height="50">
                        <path d="M50 5 L90 20 L90 50 Q90 80 50 95 Q10 80 10 50 L10 20 Z" fill="rgba(0, 255, 136, 0.2)" stroke="#00ff88" stroke-width="4" />
                        <rect x="42" y="45" width="16" height="12" rx="2" fill="#00ff88" />
                        <path d="M45 45 V40 Q45 35 50 35 Q55 35 55 40 V45" stroke="#00ff88" stroke-width="3" fill="none" />
                   </svg>
              </div>
          </div>

          <h1 class="boot-title">BREACHLABS</h1>
          <div class="boot-subtitle">SECURE ENVIRONMENT LOADER v4.0</div>

          <div class="hack-progress-container">
              <div class="hack-progress-bar"></div>
          </div>
          
          <div class="terminal-log" id="term-log">
               <div class="log-line">> INITIALIZING DAEMON...</div>
               <div class="log-line">> BYPASSING FIREWALL... [SUCCESS]</div>
               <div class="log-line">> DECRYPTING USER DATA...</div>
          </div>
      </div>
    `;

    document.body.appendChild(overlay);
    this.startMatrix();
    this.startLogSequence(message);

    // Auto-remove fallback
    setTimeout(() => {
      if (document.getElementById('breachlabs-loader')) {
        // this.hide(); 
      }
    }, 4500); // Slightly shorter
  },

  startMatrix() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン";
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = [];

    for (let x = 0; x < columns; x++) drops[x] = 1;

    // Draw loop
    const draw = () => {
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)"; // Trail effect
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = "#0F0"; // Green text
      ctx.font = fontSize + "px monospace";

      for (let i = 0; i < drops.length; i++) {
        const text = chars.charAt(Math.floor(Math.random() * chars.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975)
          drops[i] = 0;

        drops[i]++;
      }
      this.matrixInterval = requestAnimationFrame(draw);
    };

    draw();

    // Handle Resize
    window.addEventListener('resize', () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    });
  },

  startLogSequence(message) {
    const logs = [
      "> ESTABLISHING NEURAL LINK...",
      "> VERIFYING ENCRYPTION KEYS...",
      "> MOUNTING VIRTUAL FILESYSTEM...",
      "> LOADING LAB ENVIRONMENT...",
      "> " + message.toUpperCase()
    ];
    const container = document.getElementById('term-log');
    let i = 0;

    const interval = setInterval(() => {
      if (i >= logs.length) {
        clearInterval(interval);
        return;
      }
      const div = document.createElement('div');
      div.className = 'log-line';
      div.textContent = logs[i];
      container.appendChild(div);
      // Keep only last 3 lines
      while (container.children.length > 3) container.removeChild(container.firstChild);
      i++;
    }, 600);

    this.logInterval = interval;
  },

  hide() {
    const loader = document.getElementById('breachlabs-loader');
    if (loader) {
      if (this.matrixInterval) cancelAnimationFrame(this.matrixInterval);
      if (this.logInterval) clearInterval(this.logInterval);

      loader.style.transition = 'opacity 0.5s ease';
      loader.style.opacity = '0';
      setTimeout(() => loader.remove(), 500);
    }
  }
};
