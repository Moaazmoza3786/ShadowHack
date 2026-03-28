/* ============================================================
   BREACHLABS V6 - CORE LOADING SYSTEM
   Theme: Glassmorphism + Cyber Data Stream (HackingHub Style)
   ============================================================ */

const LoadingPageV6 = {
  show(message = 'INITIALIZING ENVIRONMENT...') {
    console.log('Legacy loading screen disabled.');
    // Legacy loader code removed to prevent double loading screens.
  },

  startTypewriter(message) {
    const textEl = document.getElementById('v6-status-text');
    if (!textEl) return;

    // Messages sequence
    const messages = [
      "CONNECTING TO NEURAL NET...",
      "DECRYPTING USER PROFILE...",
      "LOADING ASSETS...",
      message
    ];

    let msgIndex = 0;

    const showNext = () => {
      if (msgIndex >= messages.length) return;
      textEl.textContent = messages[msgIndex];
      msgIndex++;
      setTimeout(showNext, 600);
    };

    showNext();
  },

  hide() {
    const loader = document.getElementById('breachlabs-loader-v6');
    if (loader) {
      loader.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      loader.style.opacity = '0';
      loader.style.transform = 'scale(1.1)'; // Zoom out effect
      setTimeout(() => loader.remove(), 500);
    }
  }
};

// Export to window
window.LoadingPageV6 = LoadingPageV6;
