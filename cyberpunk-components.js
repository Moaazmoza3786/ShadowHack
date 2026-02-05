/* ============================================================
   STUDY HUB - FINAL NAVBAR (Clean Structure)
   Dashboard, Learn, Practice, Compete, Courses
   ============================================================ */

const MegaNavbar = {
  // Direct Links (no dropdown) - In order: Home only
  directLinks: [
    {
      id: 'home',
      title: { en: 'Home', ar: 'الرئيسية' },
      icon: 'fa-house',
      page: 'home'
    },
    {
      id: 'second-brain',
      title: { en: 'Second Brain', ar: 'العقل الثاني' },
      icon: 'fa-brain',
      page: 'second-brain'
    }
  ],

  // Dropdown Menus: My Tools, Learn, Practice, Compete
  menus: {
    mytools: {
      title: { en: 'My Tools', ar: 'أدواتي' },
      icon: 'fa-toolbox',
      layout: 'tabs',
      columns: [
        {
          title: { en: 'Offensive & Recon', ar: 'هجوم واستطلاع' },
          items: [
            {
              icon: 'fa-bomb',
              label: { en: 'Attack & Payload', ar: 'الهجوم والبايلود' },
              subtitle: { en: 'Generation & Exploitation', ar: 'توليد واستغلال' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-bread-slice', iconColor: 'orange', label: { en: 'Payload Bakery', ar: 'مصنع البايلود' }, subtitle: { en: 'Shell Factory', ar: 'مصنع الشلات' }, page: 'payload-bakery' },
                { icon: 'fa-terminal', iconColor: 'lime', label: { en: 'Reverse Shell Gen', ar: 'شل عكسي' }, subtitle: { en: 'One-liners', ar: 'سطر واحد' }, page: 'revshell-gen' },
                { icon: 'fa-spider', iconColor: 'red', label: { en: 'Web Exploitation', ar: 'استغلال الويب' }, subtitle: { en: 'XSS, SQLi', ar: 'هجمات الويب' }, page: 'web-exploit-lab' },
                { icon: 'fa-plug', iconColor: 'violet', label: { en: 'API Hacking Lab', ar: 'اختراق API' }, subtitle: { en: 'REST/GraphQL', ar: 'فحص API' }, page: 'api-hack-lab' },
                { icon: 'fa-shield-alt', iconColor: 'red', label: { en: 'EDR Arena', ar: 'حلبة EDR' }, subtitle: { en: 'Evasion & Payload', ar: 'تخطي الحماية' }, page: 'edr-arena', badge: 'AI' },
                { icon: 'fa-building', iconColor: 'blue', label: { en: 'AD Attack Lab', ar: 'مختبر AD' }, subtitle: { en: 'Active Directory', ar: 'أكتيف دايركتوري' }, page: 'ad-lab', badge: 'AI' },
                { icon: 'fa-chess-king', iconColor: 'gold', label: { en: 'Campaign Manager', ar: 'إدارة الحملات' }, subtitle: { en: 'Red Team Ops', ar: 'عمليات حمراء' }, page: 'attack-builder', badge: 'AI' }
              ]
            },
            {
              icon: 'fa-binoculars',
              label: { en: 'Reconnaissance', ar: 'الاستطلاع' },
              subtitle: { en: 'Info Gathering', ar: 'جمع المعلومات' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-crosshairs', iconColor: 'cyan', label: { en: 'Recon Lab', ar: 'مختبر الاستطلاع' }, subtitle: { en: 'Commands', ar: 'أوامر' }, page: 'recon-lab' },
                { icon: 'fa-satellite-dish', iconColor: 'green', label: { en: 'Recon Dashboard', ar: 'لوحة الاستطلاع' }, subtitle: { en: 'Monitoring', ar: 'مراقبة' }, page: 'recon-dashboard' },
                { icon: 'fa-radar', iconColor: 'blue', label: { en: 'JS Monitor', ar: 'مراقب JS' }, subtitle: { en: 'Changes', ar: 'تغييرات' }, page: 'js-monitor' },
                { icon: 'fa-bullseye', iconColor: 'gold', label: { en: 'Target Manager', ar: 'إدارة الأهداف' }, subtitle: { en: 'Bug Bounty', ar: 'باغ باونتي' }, page: 'bugbounty-dash' }
              ]
            }
          ]
        },
        {
          title: { en: 'Analysis & Intel', ar: 'تحليل ومعلومات' },
          items: [
            {
              icon: 'fa-microscope',
              label: { en: 'Analysis Tools', ar: 'أدوات التحليل' },
              subtitle: { en: 'Forensics & Malware', ar: 'تحليل وجرائم' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-biohazard', iconColor: 'red', label: { en: 'Malware Lab', ar: 'مختبر الخبيثة' }, subtitle: { en: 'Analysis', ar: 'تحليل' }, page: 'malware-lab' },
                { icon: 'fa-network-wired', iconColor: 'cyan', label: { en: 'Network Analyzer', ar: 'محلل الشبكات' }, subtitle: { en: 'PCAP', ar: 'تحليل حزم' }, page: 'network-analyzer' },
                { icon: 'fa-search-plus', iconColor: 'blue', label: { en: 'Forensics Lab', ar: 'تحقيق جنائي' }, subtitle: { en: 'Investigation', ar: 'تحقيق' }, page: 'forensics-lab' },
                { icon: 'fa-globe', iconColor: 'green', label: { en: 'OSINT Lab', ar: 'مختبر OSINT' }, subtitle: { en: 'Open Source', ar: 'مصادر مفتوحة' }, page: 'osint-lab' },
                { icon: 'fa-eye-slash', iconColor: 'purple', label: { en: 'Stego Lab', ar: 'مختبر الإخفاء' }, subtitle: { en: 'Steganography', ar: 'إخفاء' }, page: 'stego-lab' }
              ]
            },
            {
              icon: 'fa-chart-pie',
              label: { en: 'Reporting & Intel', ar: 'تقارير ومعلومات' },
              subtitle: { en: 'Vuln Mgmt', ar: 'إدارة الثغرات' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-file-medical-alt', iconColor: 'blue', label: { en: 'Finding Reporter', ar: 'كتابة التقارير' }, subtitle: { en: 'Generate', ar: 'توليد' }, page: 'finding-reporter' },
                { icon: 'fa-microscope', iconColor: 'green', label: { en: 'Code Review', ar: 'مراجعة الكود' }, subtitle: { en: 'Audit', ar: 'تدقيق' }, page: 'code-review' },
                { icon: 'fa-satellite', iconColor: 'red', label: { en: 'CVE Radar', ar: 'رادار CVE' }, subtitle: { en: 'Tracking', ar: 'تتبع' }, page: 'cve-watch' },
                { icon: 'fa-landmark', iconColor: 'gold', label: { en: 'CVE Museum', ar: 'متحف CVE' }, subtitle: { en: 'History', ar: 'تاريخ' }, page: 'cve-museum' },
                { icon: 'fa-chart-line', iconColor: 'purple', label: { en: 'Unified Stats', ar: 'الإحصائيات' }, subtitle: { en: 'Track All', ar: 'تتبع الكل' }, page: 'unified-stats' }
              ]
            }
          ]
        },
        {
          title: { en: 'Knowledge & Utils', ar: 'معرفة وأدوات' },
          items: [
            {
              icon: 'fa-book-dead',
              label: { en: 'Reference', ar: 'المراجع' },
              subtitle: { en: 'Cheatsheets', ar: 'أوراق الغش' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-scroll', iconColor: 'gold', label: { en: 'Command Reference', ar: 'مرجع الأوامر' }, subtitle: { en: 'All Commands', ar: 'كل الأوامر' }, page: 'command-ref' },
                { icon: 'fa-crown', iconColor: 'purple', label: { en: 'PrivEsc Lab', ar: 'تصعيد الصلاحيات' }, subtitle: { en: 'Elevate', ar: 'رفع الصلاحيات' }, page: 'privesc-lab' },
                { icon: 'fa-sitemap', iconColor: 'red', label: { en: 'MITRE ATT&CK', ar: 'مصفوفة MITRE' }, subtitle: { en: 'Framework', ar: 'إطار العمل' }, page: 'mitre-matrix' }
              ]
            },
            {
              icon: 'fa-lock',
              label: { en: 'Encoding & Crypto', ar: 'التشفير' },
              subtitle: { en: 'Data Protection', ar: 'حماية البيانات' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-code', iconColor: 'cyan', label: { en: 'Encoder Tool', ar: 'أداة التشفير' }, subtitle: { en: 'Decode/Encode', ar: 'فك وترميز' }, page: 'encoder-tool' },
                { icon: 'fa-unlock-alt', iconColor: 'red', label: { en: 'Password Lab', ar: 'كسر الباسورد' }, subtitle: { en: 'Cracking', ar: 'كسر' }, page: 'password-lab' }
              ]
            },
            {
              icon: 'fa-user-secret',
              label: { en: 'Social Engineering', ar: 'هندسة اجتماعية' },
              subtitle: { en: 'Human Element', ar: 'العنصر البشري' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-id-card', iconColor: 'pink', label: { en: 'Persona Factory', ar: 'مصنع الهويات' }, subtitle: { en: 'Fake ID', ar: 'هوية مزيفة' }, page: 'persona-factory' }
              ]
            }
          ]
        }
      ]
    },
    learn: {
      title: { en: 'Learn', ar: 'تعلم' },
      icon: 'fa-graduation-cap',
      columns: [
        {
          title: { en: 'Academy', ar: 'الأكاديمية' },
          items: [
            {
              icon: 'fa-road',
              label: { en: 'Learning Paths', ar: 'مسارات التعلم' },
              subtitle: { en: 'Structured learning', ar: 'تعلم منظم' },
              type: 'dropdown',
              direction: 'left',
              subItems: [
                {
                  icon: 'fa-rocket',
                  iconColor: 'cyan',
                  label: { en: 'BreachLabs Specs', ar: 'تخصصات BreachLabs' },
                  subtitle: { en: 'Premium Paths', ar: 'مسارات متميزة' },
                  click: "loadPage('learning-paths'); setTimeout(() => document.getElementById('antigravity-specializations').scrollIntoView({behavior:'smooth'}), 300)"
                },
                {
                  icon: 'fa-history',
                  iconColor: 'orange',
                  label: { en: 'Legacy Tracks', ar: 'المسارات الكلاسيكية' },
                  subtitle: { en: 'Career Career', ar: 'مسارات مهنية' },
                  click: "loadPage('learning-paths'); setTimeout(() => document.getElementById('legacy-tracks').scrollIntoView({behavior:'smooth'}), 300)"
                },
                {
                  icon: 'fa-user-tie',
                  iconColor: 'gold',
                  label: { en: 'Career Hub', ar: 'مركز المهن' },
                  subtitle: { en: 'Job Readiness', ar: 'الجاهزية للوظيفة' },
                  page: 'careers',
                  badge: 'NEW'
                },
                {
                  icon: 'fa-list',
                  iconColor: 'white',
                  label: { en: 'View All Paths', ar: 'عرض الكل' },
                  subtitle: { en: 'Browse All', ar: 'تصفح الكل' },
                  click: "loadPage('learning-paths')"
                }
              ]
            },
            {
              icon: 'fa-book',
              label: { en: 'Courses', ar: 'الدورات' },
              subtitle: { en: 'Professional Courses', ar: 'دورات احترافية' },
              page: 'courses'
            },
            {
              icon: 'fa-cubes',
              label: { en: 'Modules', ar: 'الوحدات' },
              subtitle: { en: 'Browse all modules', ar: 'تصفح جميع الوحدات' },
              page: 'modules'
            },
            {
              icon: 'fa-youtube',
              iconColor: 'red',
              label: { en: 'YouTube Hub', ar: 'منصة يوتيوب' },
              subtitle: { en: 'Free Community Education', ar: 'تعليم مجاني' },
              page: 'youtube-courses',
              badge: 'FREE'
            },
            {
              icon: 'fa-brain',
              iconColor: 'violet',
              label: { en: 'SRS Flashcards', ar: 'بطاقات الذاكرة' },
              subtitle: { en: 'Spaced Repetition', ar: 'المراجعة المتباعدة' },
              page: 'srs-flashcards',
              badge: 'NEW'
            }
          ]
        },
        {
          title: { en: 'Simulation Paths', ar: 'مسارات المحاكاة' },
          items: [
            {
              icon: 'fa-vr-cardboard',
              label: { en: 'Job Simulations', ar: 'محاكاة وظيفية' },
              subtitle: { en: 'Career Training', ar: 'تدريب مهني' },
              type: 'dropdown',
              subItems: [
                { icon: 'fa-bug', iconColor: 'lime', label: { en: 'Bug Bounty Sim', ar: 'صائد الجوائز' }, subtitle: { en: 'HackerOne Style', ar: 'محاكي HackerOne' }, page: 'bug-bounty-sim', badge: 'NEW' },
                { icon: 'fa-crosshairs', iconColor: 'white', label: { en: 'Bug Bounty Hub', ar: 'مركز صيد الثغرات' }, subtitle: { en: 'Target Recon', ar: 'استطلاع الأهداف' }, page: 'bug-bounty' },
                { icon: 'fa-building', iconColor: 'cyan', label: { en: 'All Simulations', ar: 'جميع المحاكاة' }, subtitle: { en: 'Browse all', ar: 'تصفح الكل' }, page: 'sim-paths' }
              ]
            },
            {
              icon: 'fa-shield-virus',
              iconColor: 'pink',
              label: { en: 'OWASP Range', ar: 'مختبر OWASP' },
              subtitle: { en: 'AppSec Training', ar: 'تدريب أمان' },
              page: 'owaspsimulator',
              badge: 'LAB'
            }
          ]
        }
      ]
    },
    practice: {
      title: { en: 'Practice', ar: 'تدريب' },
      icon: 'fa-flask',
      columns: [
        {
          title: { en: 'Challenges', ar: 'تحديات' },
          items: [
            {
              icon: 'fa-flag',
              label: { en: 'CTF Challenges', ar: 'تحديات CTF' },
              subtitle: { en: 'Reinforce your learning', ar: 'عزز تعلمك' },
              page: 'practice'
            },
            {
              icon: 'fa-calendar-day',
              iconColor: 'orange',
              label: { en: 'Daily Challenge', ar: 'تحدي يومي' },
              subtitle: { en: 'New challenge every day', ar: 'تحدي جديد كل يوم' },
              page: 'daily-ctf',
              badge: 'NEW'
            },
            {
              icon: 'fa-clock-rotate-left',
              label: { en: 'Past Events', ar: 'الأحداث السابقة' },
              subtitle: { en: 'CTF archive & writeups', ar: 'أرشيف CTF' },
              page: 'past-ctf'
            }
          ]
        },
        {
          title: { en: 'Simulators', ar: 'المحاكاة' },
          items: [
            {
              icon: 'fa-gamepad',
              label: { en: 'Red Simulators', ar: 'محاكاة الهجوم' },
              subtitle: { en: 'Adversary & Evasion', ar: 'محاكاة وتخفي' },
              type: 'dropdown',
              direction: 'left',
              subItems: [
                { icon: 'fa-skull', iconColor: 'purple', label: { en: 'C2 Simulator', ar: 'محاكي C2' }, subtitle: { en: 'Adversary Ops', ar: 'عمليات' }, page: 'c2simulator' },
                { icon: 'fa-ghost', iconColor: 'gray', label: { en: 'Stealth Lab', ar: 'مختبر التخفي' }, subtitle: { en: 'Evasion', ar: 'تخفي' }, page: 'stealth-lab' },
                { icon: 'fa-project-diagram', iconColor: 'green', label: { en: 'Lateral Move', ar: 'حركة جانبية' }, subtitle: { en: 'Pivoting', ar: 'تنقل' }, page: 'lateral-movement' }
              ]
            },
            {
              icon: 'fa-shield-alt',
              label: { en: 'Blue Simulators', ar: 'محاكاة الدفاع' },
              subtitle: { en: 'SOC & Defense', ar: 'SOC ودفاع' },
              type: 'dropdown',
              direction: 'left',
              subItems: [
                { icon: 'fa-radar', iconColor: 'blue', label: { en: 'SOC Simulator', ar: 'محاكي SOC' }, subtitle: { en: 'Operations', ar: 'عمليات' }, page: 'soc-simulator' },
                { icon: 'fa-crosshairs', iconColor: 'red', label: { en: 'Threat Hunting', ar: 'صيد التهديدات' }, subtitle: { en: 'Hunting', ar: 'صيد' }, page: 'threat-hunting' },
                { icon: 'fa-flask', iconColor: 'cyan', label: { en: 'Live Sandbox', ar: 'المختبر الحي' }, subtitle: { en: 'Docker', ar: 'Docker' }, page: 'sandbox' }
              ]
            },
            {
              icon: 'fa-vial',
              label: { en: 'Training Labs', ar: 'مختبرات التدريب' },
              subtitle: { en: 'Practice Scenarios', ar: 'سيناريوهات' },
              type: 'dropdown',
              direction: 'left',
              subItems: [
                { icon: 'fa-bug', iconColor: 'lime', label: { en: 'Bug Bounty Sim', ar: 'محاكي الصيد' }, subtitle: { en: 'Simulation', ar: 'محاكاة' }, page: 'bug-bounty-sim' },
                { icon: 'fa-theater-masks', iconColor: 'purple', label: { en: 'Social Eng Lab', ar: 'مختبر التصيد' }, subtitle: { en: 'Phishing', ar: 'تصيد' }, page: 'social-eng-lab' },
                { icon: 'fa-key', iconColor: 'gold', label: { en: 'Crypto Lab', ar: 'مختبر التشفير' }, subtitle: { en: 'Challenges', ar: 'تحديات' }, page: 'crypto-lab' }
              ]
            }
          ]
        }
      ]
    },
    compete: {
      title: { en: 'Compete', ar: 'تنافس' },
      icon: 'fa-trophy',
      columns: [
        {
          title: { en: 'Leagues', ar: 'الدوريات' },
          items: [
            {
              icon: 'fa-flag-checkered',
              label: { en: 'Leaderboard', ar: 'لائحة المتصدرين' },
              subtitle: { en: 'Top hackers', ar: 'أفضل الهاكرز' },
              page: 'leagues'
            },
            {
              icon: 'fa-crown',
              label: { en: 'King of the Hill', ar: 'ملك التل' },
              subtitle: { en: 'Attack & Defend', ar: 'هجوم ودفاع' },
              page: 'koth',
              badge: 'LIVE'
            }
          ]
        }
      ]
    }
  },

  // State
  mobileOpen: false,

  // Initialize
  init() {
    this.injectStyles();
    // Start legacy loop just in case
    setInterval(() => this.checkVPNStatus(), 30000);
    this.bindEvents();
  },

  // Render Method
  render() {
    const container = document.createElement('div');
    container.id = 'mega-navbar-container';

    const lang = document.documentElement.lang || 'en';
    const t = (obj) => obj[lang] || obj['en'];
    const isAuth = typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn();
    const user = isAuth ? AuthState.getUser() : null;

    container.innerHTML = `
      <style>
        :root {
          --nav-bg: #08080c; /* Solid Opaque */
          --nav-border: 1px solid rgba(255, 255, 255, 0.08);
          --nav-text: #fff;
          --nav-accent: #00ff88;
          --nav-hover: rgba(255, 255, 255, 0.05);
        }
        .mega-navbar {
          position: fixed; top: 0; left: 0; width: 100%; height: 64px;
          background: var(--nav-bg); backdrop-filter: blur(20px);
          border-bottom: var(--nav-border); z-index: 9000;
          display: flex; align-items: center; justify-content: space-between;
          padding: 0 30px; font-family: 'Rajdhani', sans-serif;
          box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }
        .mega-nav-left, .mega-nav-right { display: flex; align-items: center; gap: 25px; }
        
        /* Logo */
        .mega-logo { display: flex; align-items: center; gap: 12px; cursor: pointer; transition: transform 0.3s; }
        .mega-logo:hover { transform: scale(1.02); }
        .mega-logo-icon { 
            width: 36px; height: 36px; 
            background: linear-gradient(135deg, var(--nav-accent), #00cc6a);
            border-radius: 8px; display: flex; align-items: center; justify-content: center;
            color: #000; font-size: 18px; box-shadow: 0 0 15px rgba(0,255,136,0.3);
        }
        .mega-logo-text { font-family: 'Orbitron', sans-serif; font-weight: 800; font-size: 1.4rem; letter-spacing: 1px; color: #fff; }
        .mega-logo-text span { color: var(--nav-accent); }
        
        /* Links */
        .mega-link { color: rgba(255,255,255,0.75); text-decoration: none; font-weight: 600; font-size: 1rem; transition: all 0.3s; display: flex; align-items: center; gap: 8px; padding: 8px 14px; border-radius: 8px; cursor: pointer; position: relative; overflow: hidden; }
        .mega-link:hover, .mega-link.active { color: #fff; background: var(--nav-hover); }
        .mega-link i { font-size: 0.95rem; color: var(--nav-accent); opacity: 0.8; transition: 0.3s; }
        .mega-link:hover i { opacity: 1; transform: scale(1.1); }
        
        /* Dropdowns */
        .mega-dropdown { position: relative; height: 64px; display: flex; align-items: center; }
        .mega-dropdown-content {
          position: absolute; top: 100%; left: -20px;
          background: #0f0f16 !important; /* Force Opaque */
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 16px; padding: 25px;
          display: grid; gap: 20px;
          opacity: 0; visibility: hidden; transform: translateY(15px) scale(0.98);
          transition: opacity 0.2s ease, transform 0.2s ease, visibility 0s linear 0.2s; /* Delay closing */
          box-shadow: 0 30px 80px rgba(0,0,0,0.9);
          z-index: 9100;
        }
        /* Bridge for Main Dropdown */
        .mega-dropdown-content::before {
            content: ''; position: absolute; top: -15px; left: 0; width: 100%; height: 20px;
        }
        
        .mega-dropdown:hover .mega-dropdown-content { 
            opacity: 1; visibility: visible; transform: translateY(0) scale(1); 
            transition-delay: 0s; /* Instant Open */
        }
        
        .dropdown-col-title { color: var(--nav-accent); font-weight: 700; margin-bottom: 18px; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1.5px; opacity: 0.9; }
        .dropdown-item { display: flex; align-items: flex-start; gap: 15px; padding: 12px; border-radius: 10px; text-decoration: none; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; background: rgba(20,20,30,0.5); }
        .dropdown-item:hover { background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); transform: translateX(5px); }
        .dropdown-icon { width: 40px; height: 40px; background: rgba(255,255,255,0.05); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 1.1rem; border: 1px solid rgba(255,255,255,0.05); }
        .dropdown-text h4 { color: #fff; font-size: 1rem; margin: 0; font-weight: 600; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        .dropdown-text p { color: rgba(255,255,255,0.7); font-size: 0.8rem; margin: 4px 0 0 0; line-height: 1.4; }
        
        /* Nested Dropdown */
        .nested-dropdown { position: relative; } /* Ensure the item is relative for positioning */
        .nested-dropdown-content {
            position: absolute; left: 100%; top: -10px; width: 280px;
            background: #0f0f16 !important;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px; padding: 15px;
            display: flex; flex-direction: column; gap: 8px;
            opacity: 0; visibility: hidden; transform: translateX(-10px);
            transition: opacity 0.2s ease, transform 0.2s ease, visibility 0s linear 0.2s; /* Delay closing */
            box-shadow: 0 10px 40px rgba(0,0,0,0.8);
            z-index: 9200;
        }
        /* Bridge for Nested Dropdown */
        .nested-dropdown-content::before {
            content: ''; position: absolute; right: 100%; top: 0; width: 30px; height: 100%; /* Side bridge */
        }

        .nested-dropdown:hover .nested-dropdown-content { 
            opacity: 1; visibility: visible; transform: translateX(0); 
            transition-delay: 0s; /* Instant Open */
        }
        
        /* RTL Support for Nested */
        :root[lang="ar"] .nested-dropdown-content { left: auto; right: 100%; transform: translateX(10px); }
        :root[lang="ar"] .nested-dropdown:hover .nested-dropdown-content { transform: translateX(0); }

        /* Left-Opening Nested Dropdown (For Right-Side Columns) */
        .nested-dropdown.nested-left .nested-dropdown-content {
            left: auto; right: 100%;
            border-right: 1px solid rgba(255,255,255,0.1); border-left: none; /* Adjust border visual */
            margin-right: -5px; /* Slight overlap fix */
        }
        .nested-dropdown.nested-left .nested-dropdown-content::before {
            right: -20px; left: auto;
        }

        
        /* User Dropdown */
        .user-dropdown { position: relative; }
        .user-trigger { 
            display: flex; align-items: center; gap: 12px; 
            padding: 5px 12px 5px 5px; border-radius: 50px; 
            background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
            cursor: pointer; transition: all 0.3s;
        }
        .user-trigger:hover, .user-trigger.active { background: rgba(255,255,255,0.1); border-color: var(--nav-accent); }
        .user-avatar { width: 38px; height: 38px; border-radius: 50%; object-fit: cover; border: 2px solid var(--nav-accent); }
        .user-name { font-weight: 600; font-size: 0.95rem; color: #fff; padding-right: 5px; }

        .user-menu {
            position: absolute; top: 120%; right: 0; width: 220px;
            background: #13131f; border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px; padding: 10px;
            opacity: 0; visibility: hidden; transform: translateY(10px);
            transition: all 0.2s ease;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }
        .user-menu.show { opacity: 1; visibility: visible; transform: translateY(0); }
        .user-menu-item { 
            display: flex; align-items: center; gap: 10px; 
            padding: 12px 15px; border-radius: 8px; color: rgba(255,255,255,0.8);
            text-decoration: none; font-size: 0.95rem; transition: all 0.2s;
        }
        .user-menu-item:hover { background: rgba(0, 255, 136, 0.1); color: var(--nav-accent); }
        .user-menu-item i { width: 20px; text-align: center; }
        .user-divider { height: 1px; background: rgba(255,255,255,0.1); margin: 8px 0; }

        /* Mobile Menu */
        .mega-mobile-menu {
            position: fixed; top: 64px; left: 0; width: 100%;
            background: var(--nav-bg); backdrop-filter: blur(20px);
            padding: 20px; display: flex; flex-direction: column; gap: 15px;
            transform: translateY(-150%); opacity: 0; visibility: hidden;
            transition: all 0.3s ease; z-index: 900;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            max-height: calc(100vh - 64px); overflow-y: auto;
        }
        .mega-mobile-menu.open { transform: translateY(0); opacity: 1; visibility: visible; }
        
        .mega-mobile-link {
            color: #fff; text-decoration: none; font-size: 1.1rem;
            padding: 10px; border-radius: 8px; font-weight: 600;
            display: flex; align-items: center; gap: 12px;
            transition: all 0.2s;
        }
        .mega-mobile-link:hover { background: rgba(255,255,255,0.05); color: var(--nav-accent); }
        
        .mega-auth-btn { padding: 12px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; display: flex; align-items: center; gap: 8px; }
        .mega-auth-btn.login { background: var(--nav-accent); color: #000; }

        /* Mobile Toggle */
        .mobile-toggle { display: none; font-size: 1.5rem; color: #fff; background: none; border: none; cursor: pointer; }
        
        @media (max-width: 992px) {
            .mega-nav-left > .mega-link, .mega-dropdown { display: none; }
            .mobile-toggle { display: block; }
            .mega-navbar { padding: 0 20px; }
            .user-name { display: none; }
        }

        /* TABBED LAYOUT STYLES */
        .mega-dropdown-tabs {
            position: absolute; top: 100%; left: -20px; width: 900px !important;
            background: #0f0f16 !important;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px; padding: 0; /* No padding on container */
            display: flex; /* Sidebar layout */
            opacity: 0; visibility: hidden; transform: translateY(15px) scale(0.98);
            transition: opacity 0.2s ease, transform 0.2s ease, visibility 0s linear 0.2s;
            box-shadow: 0 30px 80px rgba(0,0,0,0.9);
            z-index: 9100;
            overflow: hidden;
        }
        /* Bridge for Tabbed Dropdown */
        .mega-dropdown-tabs::before {
            content: ''; position: absolute; top: -15px; left: 0; width: 100%; height: 20px;
        }

        .mega-dropdown:hover .mega-dropdown-tabs {
            opacity: 1; visibility: visible; transform: translateY(0) scale(1);
            transition-delay: 0s;
        }

        /* Sidebar Side */
        .mega-tab-sidebar {
            width: 260px;
            background: rgba(0,0,0,0.3);
            border-right: 1px solid rgba(255,255,255,0.05);
            display: flex; flex-direction: column;
            padding: 15px;
        }
        .mega-tab-item {
            display: flex; align-items: center; gap: 12px;
            padding: 14px 18px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            color: rgba(255,255,255,0.7);
            font-size: 0.95rem;
            font-weight: 600;
        }
        .mega-tab-item:hover, .mega-tab-item.active {
            background: rgba(0, 255, 136, 0.1);
            color: #fff;
        }
        .mega-tab-item i { width: 24px; text-align: center; font-size: 1.1rem; }
        .mega-tab-item.active i { color: var(--nav-accent); }
        .mega-tab-item.active { border-left: 3px solid var(--nav-accent); }

        /* Content Side */
        .mega-tab-content-area {
            flex: 1;
            padding: 25px;
            background: rgba(255,255,255,0.01);
            position: relative;
        }
        .mega-tab-pane {
            display: none;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            animation: fadeIn 0.3s ease;
        }
        .mega-tab-pane.active { display: grid; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
      </style>

      <nav class="mega-navbar">
        <div class="mega-nav-left">
          <div class="mega-logo" onclick="loadPage('home')">
            <!-- High-End Circular Logo -->
            <div class="mega-logo-icon" style="
                width: 48px; height: 48px; 
                background: rgba(0,0,0,0.5); 
                border-radius: 50%; /* Circle */
                display: flex; align-items: center; justify-content: center;
                position: relative;
                box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
                border: 1px solid rgba(0, 255, 136, 0.2);
            ">
                <!-- Spinning Ring -->
                <div style="
                    position: absolute; top: -2px; left: -2px; right: -2px; bottom: -2px;
                    border-radius: 50%;
                    border: 2px solid transparent;
                    border-top-color: var(--nav-accent);
                    border-right-color: var(--nav-accent);
                    animation: spinLogo 3s linear infinite;
                "></div>
                
                <!-- The Logo SVG -->
                <svg viewBox="0 0 100 100" fill="none" style="width: 70%; height: 70%; filter: drop-shadow(0 0 5px rgba(0,255,136,0.8));">
                    <path d="M50 5 L90 20 L90 50 Q90 80 50 95 Q10 80 10 50 L10 20 Z" fill="rgba(0, 255, 136, 0.2)" stroke="#00ff88" stroke-width="6" />
                    <rect x="42" y="45" width="16" height="12" rx="2" fill="#00ff88" />
                    <path d="M45 45 V40 Q45 35 50 35 Q55 35 55 40 V45" stroke="#00ff88" stroke-width="4" fill="none" />
                </svg>
            </div>
            
            <style>
                @keyframes spinLogo { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
            <div class="mega-logo-text">BREACH<span>LABS</span></div>
          </div>
          
          <!-- Direct Links -->
          ${this.directLinks.map(link => `
            <a class="mega-link" onclick="loadPage('${link.page}')">
                <i class="fa-solid ${link.icon}"></i> ${t(link.title)}
            </a>
          `).join('')}

          <!-- Dropdowns -->
          ${Object.entries(this.menus).map(([key, menu]) => `
            <div class="mega-dropdown">
                <div class="mega-link">
                    <i class="fa-solid ${menu.icon}"></i> ${t(menu.title)} <i class="fa-solid fa-chevron-down" style="font-size: 0.7rem; margin-left: 5px; opacity: 0.5;"></i>
                </div>
                
                ${menu.layout === 'tabs' ? `
                    <!-- TABBED LAYOUT -->
                    <div class="mega-dropdown-tabs">
                        <!-- Sidebar -->
                        <div class="mega-tab-sidebar">
                            ${menu.columns.map((col, idx) => `
                                <div class="mega-tab-item ${idx === 0 ? 'active' : ''}" onmouseenter="MegaNavbar.switchTab('${key}', ${idx})">
                                    <i class="fa-solid ${col.icon || 'fa-folder'}"></i>
                                    <span>${t(col.title)}</span>
                                </div>
                            `).join('')}
                        </div>

                        <!-- Content Area -->
                        <div class="mega-tab-content-area" id="tab-content-${key}">
                            ${menu.columns.map((col, idx) => `
                                <div class="mega-tab-pane ${idx === 0 ? 'active' : ''}" id="tab-${key}-${idx}">
                                    ${col.items.map(item => {
      if (item.type === 'dropdown' && item.subItems) {
        return `
                                            <!-- Group Header with items -->
                                            <div style="grid-column: span 1;">
                                                <div class="dropdown-item nested-dropdown" style="background: rgba(255,255,255,0.03); border:none; cursor:default;">
                                                    <div class="dropdown-icon" style="color: ${item.iconColor || 'white'}; background: transparent; border: 2px solid rgba(255,255,255,0.1);"><i class="fa-solid ${item.icon}"></i></div>
                                                    <div class="dropdown-text">
                                                        <h4 style="color: var(--nav-accent);">${t(item.label)}</h4>
                                                        <p>${t(item.subtitle)}</p>
                                                    </div>
                                                </div>
                                                <div style="margin-top: 10px; padding-left: 15px; border-left: 2px solid rgba(255,255,255,0.05); margin-left: 20px;">
                                                    ${item.subItems.map(sub => `
                                                        <a class="dropdown-item" onclick="${sub.click ? sub.click : `loadPage('${sub.page || '#'}')`}" style="background: transparent; border: none; padding: 8px; margin-bottom: 5px;">
                                                            <div class="dropdown-icon" style="width: 28px; height: 28px; font-size: 0.8rem; color: ${sub.iconColor || 'white'}"><i class="fa-solid ${sub.icon}"></i></div>
                                                            <div class="dropdown-text">
                                                                <h4 style="font-size: 0.9rem;">${t(sub.label)} ${sub.badge ? `<span class="badge bg-danger" style="font-size: 0.5rem">${sub.badge}</span>` : ''}</h4>
                                                            </div>
                                                        </a>
                                                    `).join('')}
                                                </div>
                                            </div>
                                        `;
      } else {
        return `
                                            <a class="dropdown-item" onclick="${item.click ? item.click : `loadPage('${item.page || '#'}')`}">
                                                <div class="dropdown-icon" style="color: ${item.iconColor || 'white'}"><i class="fa-solid ${item.icon}"></i></div>
                                                <div class="dropdown-text">
                                                    <h4>${t(item.label)} ${item.badge ? `<span class="badge bg-danger" style="font-size: 0.6rem">${item.badge}</span>` : ''}</h4>
                                                    <p>${t(item.subtitle)}</p>
                                                </div>
                                            </a>
                                          `;
      }
    }).join('')}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : `
                    <!-- STANDARD GRID LAYOUT -->
                    <div class="mega-dropdown-content" style="width: ${menu.columns?.length ? menu.columns.length * 320 : 650}px; grid-template-columns: repeat(${menu.columns?.length || 2}, 1fr);">
                        ${menu.columns.map(col => `
                            <div class="dropdown-col">
                                <div class="dropdown-col-title">${t(col.title)}</div>
                                ${col.items.map(item => {
      if (item.type === 'dropdown' && item.subItems) {
        return `
                                        <div class="dropdown-item nested-dropdown ${item.direction === 'left' ? 'nested-left' : ''}">
                                            <div class="dropdown-icon" style="color: ${item.iconColor || 'white'}"><i class="fa-solid ${item.icon}"></i></div>
                                            <div class="dropdown-text" style="flex: 1;">
                                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                                    <h4>${t(item.label)}</h4>
                                                    <i class="fa-solid fa-${item.direction === 'left' ? 'chevron-left' : 'chevron-right'}" style="font-size: 0.7rem; opacity: 0.5;"></i>
                                                </div>
                                                <p>${t(item.subtitle)}</p>
                                            </div>
                                            
                                            <!-- Nested Content -->
                                            <div class="nested-dropdown-content">
                                                ${item.subItems.map(sub => `
                                                    <a class="dropdown-item" onclick="${sub.click ? sub.click : `loadPage('${sub.page || '#'}')`}">
                                                        <div class="dropdown-icon" style="width: 32px; height: 32px; font-size: 0.9rem; color: ${sub.iconColor || 'white'}"><i class="fa-solid ${sub.icon}"></i></div>
                                                        <div class="dropdown-text">
                                                            <h4 style="font-size: 0.95rem;">${t(sub.label)} ${sub.badge ? `<span class="badge bg-danger" style="font-size: 0.5rem">${sub.badge}</span>` : ''}</h4>
                                                        </div>
                                                    </a>
                                                `).join('')}
                                            </div>
                                        </div>
                                        `;
      } else {
        return `
                                        <a class="dropdown-item" onclick="${item.click ? item.click : `loadPage('${item.page || '#'}')`}">
                                            <div class="dropdown-icon" style="color: ${item.iconColor || 'white'}"><i class="fa-solid ${item.icon}"></i></div>
                                            <div class="dropdown-text">
                                                <h4>${t(item.label)} ${item.badge ? `<span class="badge bg-danger" style="font-size: 0.6rem">${item.badge}</span>` : ''}</h4>
                                                <p>${t(item.subtitle)}</p>
                                            </div>
                                        </a>
                                        `;
      }
    }).join('')}
                            </div>
                        `).join('')}
                    </div>
                `}
            </div>
          `).join('')}
        </div>

        <div class="mega-nav-right">
            <!-- Search -->
            <div class="search-trigger" onclick="MegaNavbar.toggleSearch()" style="cursor: pointer; padding: 10px; border-radius: 50%; background: rgba(255,255,255,0.05); transition: 0.3s;" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                <i class="fa-solid fa-search"></i>
            </div>
            
            <!-- Auth Buttons -->
            ${!isAuth ? `
                <button class="btn btn-sm btn-outline-light" onclick="loadPage('login')">Login</button>
                <button class="btn btn-sm btn-primary" style="background: var(--nav-accent); color: #000; border: none; font-weight: 700; border-radius: 6px; padding: 6px 16px;" onclick="loadPage('register')">Join</button>
            ` : `
                <div class="user-dropdown">
                    <div class="user-trigger" onclick="MegaNavbar.toggleUserMenu(event)">
                        <img src="${user.avatar || 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + user.username}" class="user-avatar">
                        <span class="user-name">${user.username}</span>
                        <i class="fa-solid fa-chevron-down" style="font-size: 0.8rem; margin-right: 5px;"></i>
                    </div>
                    <div class="user-menu" id="user-menu-dropdown">
                        <a class="user-menu-item" onclick="loadPage('profile')">
                            <i class="fa-solid fa-user"></i> Profile
                        </a>
                        <a class="user-menu-item" onclick="loadPage('dashboard')">
                            <i class="fa-solid fa-chart-line"></i> Dashboard
                        </a>
                        <a class="user-menu-item" onclick="loadPage('settings')">
                            <i class="fa-solid fa-gear"></i> Settings
                        </a>
                         <div class="user-divider"></div>
                        <a class="user-menu-item" onclick="Auth.logout()" style="color: #ef4444;">
                            <i class="fa-solid fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>
            `}
            
            <button class="mobile-toggle" onclick="MegaNavbar.toggleMobile()">
                <i class="fa-solid fa-bars"></i>
            </button>
        </div>
      </nav>

      <!-- Mobile Menu -->
      <div id="mega-mobile-menu" class="mega-mobile-menu">
        ${this.directLinks.map(link => `
            <a class="mega-mobile-link" onclick="loadPage('${link.page}'); MegaNavbar.toggleMobile();">
                <i class="fa-solid ${link.icon}"></i> ${t(link.title)}
            </a>
        `).join('')}
        
        <!-- Mobile Compete/Practice Links simplified -->
        <a class="mega-mobile-link" onclick="loadPage('practice'); MegaNavbar.toggleMobile();">
            <i class="fa-solid fa-flask"></i> Practice
        </a>
        <div style="border-top: 1px solid rgba(255,255,255,0.1); margin: 10px 0;"></div>

    ${(() => {
        const isLoggedIn = typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn();
        if (isLoggedIn) {
          return `
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
              <a class="mega-mobile-link" onclick="loadPage('profile'); MegaNavbar.toggleMobile();">
                <i class="fa-solid fa-user"></i> ${document.documentElement.lang === 'ar' ? 'الملف الشخصي' : 'Profile'}
              </a>
              <a class="mega-mobile-link" onclick="loadPage('settings'); MegaNavbar.toggleMobile();">
                <i class="fa-solid fa-gear"></i> ${document.documentElement.lang === 'ar' ? 'الإعدادات' : 'Settings'}
              </a>
            </div>`;
        } else {
          return `
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
               <button class="mega-auth-btn login w-100 justify-content-center mb-3" onclick="loadPage('login'); MegaNavbar.toggleMobile();">
                <i class="fa-solid fa-sign-in-alt"></i> ${document.documentElement.lang === 'ar' ? 'تسجيل الدخول' : 'Login'}
              </button>
            </div>`;
        }
      })()}
      </div >
  `;

    // Insert if not exists
    if (!document.getElementById('mega-navbar-container')) {
      document.body.insertBefore(container, document.body.firstChild);
    }

    // Add body padding
    document.body.style.paddingTop = '70px';
  },

  // Bind events
  bindEvents() {
    // Close menus when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.mega-navbar-item')) {
        document.querySelectorAll('.mega-navbar-trigger').forEach(t => t.classList.remove('active'));
      }
    });

    // Check VPN on load
    this.checkVPNStatus();
  },

  // Check VPN Status
  async checkVPNStatus() {
    const statusEl = document.querySelector('.vpn-status'); // If we have one in UI
    try {
      if (typeof ApiClient !== 'undefined') {
        // Mock check or real if API exists
        // Real implementation if needed
      }
    } catch (e) {
      // silent
    }
  },

  // Toggle User Menu
  toggleUserMenu(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('user-menu-dropdown');
    const trigger = document.querySelector('.user-trigger');

    // Close other menus
    const mobileMenu = document.getElementById('mega-mobile-menu');
    if (mobileMenu) mobileMenu.classList.remove('open');

    if (menu) {
      menu.classList.toggle('show');
      if (trigger) trigger.classList.toggle('active');
    }
  },

  // Toggle mobile menu
  toggleMobile() {
    this.mobileOpen = !this.mobileOpen;
    const menu = document.getElementById('mega-mobile-menu');
    const icon = document.querySelector('.mobile-toggle i'); // Use querySelector to find the icon inside button

    // Close user menu
    const userMenu = document.getElementById('user-menu-dropdown');
    if (userMenu) userMenu.classList.remove('show');

    if (menu) {
      if (this.mobileOpen) {
        menu.classList.add('open');
        if (icon) icon.className = 'fa-solid fa-xmark';
      } else {
        menu.classList.remove('open');
        if (icon) icon.className = 'fa-solid fa-bars';
      }
    }
  },

  // Switch Tab
  switchTab(menuKey, colIdx) {
    const container = document.getElementById(`tab-content-${menuKey}`);
    if (!container) return;

    // Update sidebar active state
    const items = container.previousElementSibling.querySelectorAll('.mega-tab-item');
    items.forEach((item, i) => {
      if (i === colIdx) item.classList.add('active');
      else item.classList.remove('active');
    });

    // Update content panels
    const panels = container.querySelectorAll('.mega-tab-pane');
    panels.forEach((panel, i) => {
      if (i === colIdx) panel.classList.add('active');
      else panel.classList.remove('active');
    });
  },

  // Toggle search dropdown
  toggleSearch() {
    // Implementation for search dropdown if UI exists
    // For now we just implement logic if the UI elements are added later
  },

  // Inject Styles (Legacy support)
  injectStyles() {
    // Empty as we use inline styles in render()
  }
};

// ==================== THEME TOGGLE ====================

function toggleTheme() {
  const html = document.documentElement;
  const currentTheme = html.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  applyTheme(newTheme);
  localStorage.setItem('theme', newTheme);
}

function applyTheme(theme) {
  const html = document.documentElement;
  html.setAttribute('data-theme', theme);
  if (theme === 'dark') {
    document.body.classList.add('dark-mode');
  } else {
    document.body.classList.remove('dark-mode');
  }
}

// Initialize Theme
document.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('theme') || 'dark'; // Default to dark for Cyberpunk
  applyTheme(savedTheme);
});

// ==================== EXPORTS & INIT ====================

function renderCyberNavbar() {
  return MegaNavbar.render();
}

function refreshCyberNavbar() {
  const navbarContainer = document.getElementById('mega-navbar-container');
  // Just Re-render if container exists
  if (navbarContainer) {
    // Clear old
    navbarContainer.remove();
    MegaNavbar.render();
  } else {
    MegaNavbar.render();
  }
}

// Export functions
window.toggleTheme = toggleTheme;
window.MegaNavbar = MegaNavbar;
window.renderCyberNavbar = renderCyberNavbar;
window.refreshCyberNavbar = refreshCyberNavbar;

// Refresh navbar on auth state change
window.addEventListener('authStateChanged', (event) => {
  console.log('Auth state changed:', event.detail);
  refreshCyberNavbar();
});
