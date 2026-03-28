/* ============================================================
   SHADOWHACK - ADDITIONAL PAGES
   Missing navbar pages - Professional implementations
   ============================================================ */

// ==================== CAREER PATH PAGES ====================

function pagePathRedTeam() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="career-path-page" style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <!-- Hero Section -->
      <div style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); border-radius: 20px; padding: 60px 40px; margin-bottom: 40px; position: relative; overflow: hidden;">
        <div style="position: absolute; top: -50px; right: -50px; width: 200px; height: 200px; background: rgba(255,255,255,0.1); border-radius: 50%;"></div>
        <div style="position: relative; z-index: 1;">
          <div style="font-size: 14px; color: rgba(255,255,255,0.8); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 2px;">
            <i class="fas fa-crosshairs"></i> ${isArabic ? 'مسار وظيفي' : 'Career Path'}
          </div>
          <h1 style="font-size: 3rem; color: #fff; margin-bottom: 20px; font-family: 'Orbitron', sans-serif;">
            ${isArabic ? 'الفريق الأحمر' : 'Red Team Operator'}
          </h1>
          <p style="color: rgba(255,255,255,0.9); font-size: 18px; max-width: 600px; line-height: 1.8;">
            ${isArabic
      ? 'تعلم كيف تفكر كمهاجم. اختبر دفاعات المنظمات واكتشف الثغرات قبل أن يفعل المخترقون الحقيقيون.'
      : 'Learn to think like an attacker. Test organizational defenses and find vulnerabilities before real hackers do.'}
          </p>
          <div style="margin-top: 30px; display: flex; gap: 20px; flex-wrap: wrap;">
            <div style="background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px;">
              <div style="color: rgba(255,255,255,0.7); font-size: 12px;">${isArabic ? 'المدة المتوقعة' : 'Expected Duration'}</div>
              <div style="color: #fff; font-size: 20px; font-weight: 700;">6-8 ${isArabic ? 'أشهر' : 'Months'}</div>
            </div>
            <div style="background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px;">
              <div style="color: rgba(255,255,255,0.7); font-size: 12px;">${isArabic ? 'متوسط الراتب' : 'Avg Salary'}</div>
              <div style="color: #fff; font-size: 20px; font-weight: 700;">$95,000/yr</div>
            </div>
            <div style="background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px;">
              <div style="color: rgba(255,255,255,0.7); font-size: 12px;">${isArabic ? 'المستوى' : 'Level'}</div>
              <div style="color: #fff; font-size: 20px; font-weight: 700;">${isArabic ? 'متوسط-متقدم' : 'Intermediate+'}</div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Skills Grid -->
      <h2 style="color: #fff; margin-bottom: 25px;"><i class="fas fa-tasks" style="color: #dc2626;"></i> ${isArabic ? 'المهارات المطلوبة' : 'Skills You Will Learn'}</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 40px;">
        ${[
      { icon: 'fa-network-wired', title: isArabic ? 'فحص الشبكات' : 'Network Enumeration', desc: isArabic ? 'Nmap, Masscan, Service Discovery' : 'Nmap, Masscan, Service Discovery' },
      { icon: 'fa-globe', title: isArabic ? 'اختراق الويب' : 'Web Exploitation', desc: 'SQLi, XSS, SSRF, RCE' },
      { icon: 'fa-windows', title: isArabic ? 'هجمات Active Directory' : 'Active Directory Attacks', desc: 'Kerberoasting, Pass-the-Hash, DCSync' },
      { icon: 'fa-user-secret', title: isArabic ? 'تصعيد الصلاحيات' : 'Privilege Escalation', desc: 'Linux & Windows PrivEsc' },
      { icon: 'fa-ghost', title: isArabic ? 'التخفي والمراوغة' : 'Evasion & Stealth', desc: 'AV Bypass, C2 Frameworks' },
      { icon: 'fa-file-code', title: isArabic ? 'كتابة التقارير' : 'Report Writing', desc: isArabic ? 'توثيق النتائج والتوصيات' : 'Documenting findings & recommendations' }
    ].map(skill => `
          <div style="background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); border-radius: 16px; padding: 24px;">
            <i class="fas ${skill.icon}" style="font-size: 28px; color: #dc2626; margin-bottom: 15px;"></i>
            <h4 style="color: #fff; margin-bottom: 8px;">${skill.title}</h4>
            <p style="color: rgba(255,255,255,0.6); font-size: 14px;">${skill.desc}</p>
          </div>
        `).join('')}
      </div>
      
      <!-- CTA -->
      <div style="text-align: center; padding: 40px; background: rgba(220, 38, 38, 0.1); border-radius: 20px;">
        <h3 style="color: #fff; margin-bottom: 20px;">${isArabic ? 'جاهز للبدء؟' : 'Ready to Start?'}</h3>
        <button onclick="loadPage('learningpaths')" style="padding: 15px 40px; background: #dc2626; color: #fff; border: none; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer;">
          <i class="fas fa-play"></i> ${isArabic ? 'ابدأ المسار' : 'Start This Path'}
        </button>
      </div>
    </div>
  `;
}

function pagePathBlueTeam() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="career-path-page" style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); border-radius: 20px; padding: 60px 40px; margin-bottom: 40px;">
        <div style="font-size: 14px; color: rgba(255,255,255,0.8); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 2px;">
          <i class="fas fa-shield-halved"></i> ${isArabic ? 'مسار وظيفي' : 'Career Path'}
        </div>
        <h1 style="font-size: 3rem; color: #fff; margin-bottom: 20px; font-family: 'Orbitron', sans-serif;">
          ${isArabic ? 'الفريق الأزرق' : 'Blue Team Defender'}
        </h1>
        <p style="color: rgba(255,255,255,0.9); font-size: 18px; max-width: 600px;">
          ${isArabic
      ? 'احمِ المنظمات من التهديدات السيبرانية. تعلم الكشف والاستجابة للحوادث.'
      : 'Protect organizations from cyber threats. Learn detection and incident response.'}
        </p>
        <div style="margin-top: 30px; display: flex; gap: 20px; flex-wrap: wrap;">
          <div style="background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px;">
            <div style="color: rgba(255,255,255,0.7); font-size: 12px;">${isArabic ? 'متوسط الراتب' : 'Avg Salary'}</div>
            <div style="color: #fff; font-size: 20px; font-weight: 700;">$85,000/yr</div>
          </div>
        </div>
      </div>
      
      <h2 style="color: #fff; margin-bottom: 25px;"><i class="fas fa-tasks" style="color: #2563eb;"></i> ${isArabic ? 'المهارات' : 'Skills'}</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px;">
        ${['SIEM & Log Analysis', 'Threat Hunting', 'Incident Response', 'Malware Analysis', 'Security Hardening', 'Forensics'].map(skill => `
          <div style="background: rgba(37, 99, 235, 0.1); border: 1px solid rgba(37, 99, 235, 0.3); border-radius: 16px; padding: 24px;">
            <h4 style="color: #fff;">${skill}</h4>
          </div>
        `).join('')}
      </div>
      
      <div style="text-align: center; padding: 40px; margin-top: 40px;">
        <button onclick="loadPage('learningpaths')" style="padding: 15px 40px; background: #2563eb; color: #fff; border: none; border-radius: 12px; font-size: 18px; cursor: pointer;">
          <i class="fas fa-play"></i> ${isArabic ? 'ابدأ المسار' : 'Start This Path'}
        </button>
      </div>
    </div>
  `;
}

function pagePathSoc() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div class="career-path-page" style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%); border-radius: 20px; padding: 60px 40px; margin-bottom: 40px;">
        <h1 style="font-size: 3rem; color: #fff; font-family: 'Orbitron', sans-serif;">
          ${isArabic ? 'محلل SOC' : 'SOC Analyst'}
        </h1>
        <p style="color: rgba(255,255,255,0.9); font-size: 18px; max-width: 600px; margin-top: 20px;">
          ${isArabic
      ? 'راقب التهديدات على مدار الساعة. كن خط الدفاع الأول ضد الهجمات.'
      : 'Monitor threats 24/7. Be the first line of defense against attacks.'}
        </p>
        <div style="margin-top: 20px; background: rgba(0,0,0,0.3); padding: 15px 25px; border-radius: 12px; display: inline-block;">
          <span style="color: #fff; font-size: 20px; font-weight: 700;">$70,000 - $95,000/yr</span>
        </div>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px;">
        ${['Tier 1: Alert Triage', 'Tier 2: Incident Analysis', 'Tier 3: Threat Hunting'].map((tier, i) => `
          <div style="background: rgba(124, 58, 237, 0.1); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 16px; padding: 30px; text-align: center;">
            <div style="width: 60px; height: 60px; background: #7c3aed; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 24px; color: #fff;">${i + 1}</div>
            <h4 style="color: #fff;">${tier}</h4>
          </div>
        `).join('')}
      </div>
      
      <div style="text-align: center; padding: 40px; margin-top: 40px;">
        <button onclick="loadPage('learningpaths')" style="padding: 15px 40px; background: #7c3aed; color: #fff; border: none; border-radius: 12px; font-size: 18px; cursor: pointer;">
          ${isArabic ? 'ابدأ المسار' : 'Start This Path'}
        </button>
      </div>
    </div>
  `;
}

// ==================== TOPIC PAGES ====================

function pageTopicWeb() {
  return pageTopicTemplate('web', 'fa-globe', '#f59e0b',
    { en: 'Web Security', ar: 'أمان الويب' },
    { en: 'Master web application security testing and exploitation techniques.', ar: 'أتقن اختبار أمان تطبيقات الويب وتقنيات الاستغلال.' },
    ['OWASP Top 10', 'SQL Injection', 'XSS & CSRF', 'Authentication Bypass', 'API Security', 'Session Hijacking']
  );
}

function pageTopicNetwork() {
  return pageTopicTemplate('network', 'fa-network-wired', '#06b6d4',
    { en: 'Network Security', ar: 'أمان الشبكات' },
    { en: 'Learn to secure and attack network infrastructure.', ar: 'تعلم تأمين ومهاجمة البنية التحتية للشبكات.' },
    ['TCP/IP Fundamentals', 'Port Scanning', 'Packet Analysis', 'Man-in-the-Middle', 'WiFi Hacking', 'Firewall Evasion']
  );
}

function pageTopicForensics() {
  return pageTopicTemplate('forensics', 'fa-magnifying-glass', '#8b5cf6',
    { en: 'Digital Forensics', ar: 'التحقيق الرقمي' },
    { en: 'Investigate cyber crimes and analyze digital evidence.', ar: 'حقق في الجرائم السيبرانية وحلل الأدلة الرقمية.' },
    ['Disk Forensics', 'Memory Analysis', 'Log Analysis', 'Malware Forensics', 'Mobile Forensics', 'Chain of Custody']
  );
}

function pageTopicScripting() {
  return pageTopicTemplate('scripting', 'fa-code', '#22c55e',
    { en: 'Scripting & Coding', ar: 'البرمجة والسكريبتات' },
    { en: 'Automate tasks and build security tools.', ar: 'أتمتة المهام وبناء أدوات الأمان.' },
    ['Python for Hackers', 'Bash Scripting', 'PowerShell', 'Custom Exploits', 'Tool Development', 'API Scripting']
  );
}

function pageTopicLinux() {
  return pageTopicTemplate('linux', 'fa-linux', '#ea580c',
    { en: 'Linux Fundamentals', ar: 'أساسيات لينكس' },
    { en: 'Master the Linux command line and system administration.', ar: 'أتقن سطر أوامر لينكس وإدارة النظام.' },
    ['Command Line Basics', 'File Permissions', 'User Management', 'Process Control', 'Network Config', 'Shell Scripting']
  );
}

function pageTopicTemplate(id, icon, color, title, desc, skills) {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, ${color}20, ${color}10); border: 1px solid ${color}40; border-radius: 20px; padding: 50px; margin-bottom: 40px;">
        <i class="fas ${icon}" style="font-size: 48px; color: ${color}; margin-bottom: 20px;"></i>
        <h1 style="font-size: 2.5rem; color: #fff; margin-bottom: 15px;">${title[isArabic ? 'ar' : 'en']}</h1>
        <p style="color: rgba(255,255,255,0.7); font-size: 18px;">${desc[isArabic ? 'ar' : 'en']}</p>
      </div>
      
      <h2 style="color: #fff; margin-bottom: 20px;">${isArabic ? 'المواضيع' : 'Topics Covered'}</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 40px;">
        ${skills.map(s => `
          <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; text-align: center;">
            <span style="color: #fff;">${s}</span>
          </div>
        `).join('')}
      </div>
      
      <button onclick="loadPage('practice')" style="padding: 15px 40px; background: ${color}; color: #fff; border: none; border-radius: 12px; font-size: 16px; cursor: pointer;">
        ${isArabic ? 'تصفح الغرف' : 'Browse Rooms'}
      </button>
    </div>
  `;
}

// ==================== CHEATSHEETS PAGE ====================

function pageCheatsheets() {
  const isArabic = document.documentElement.lang === 'ar';

  const sheets = [
    { icon: 'fa-linux', title: 'Linux Commands', color: '#f59e0b', items: 40 },
    { icon: 'fa-network-wired', title: 'Nmap Cheatsheet', color: '#22c55e', items: 35 },
    { icon: 'fa-database', title: 'SQL Injection', color: '#ef4444', items: 50 },
    { icon: 'fa-terminal', title: 'Reverse Shells', color: '#a855f7', items: 25 },
    { icon: 'fa-globe', title: 'XSS Payloads', color: '#f59e0b', items: 30 },
    { icon: 'fa-windows', title: 'Windows PrivEsc', color: '#3b82f6', items: 45 },
    { icon: 'fa-python', title: 'Python Quick Ref', color: '#22c55e', items: 60 },
    { icon: 'fa-shield-halved', title: 'Metasploit', color: '#dc2626', items: 40 }
  ];

  return `
    <div style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <h1 style="color: #fff; font-size: 2.5rem; margin-bottom: 10px;">
        <i class="fas fa-file-lines" style="color: #22c55e;"></i> ${isArabic ? 'الملخصات السريعة' : 'Cheat Sheets'}
      </h1>
      <p style="color: rgba(255,255,255,0.6); margin-bottom: 40px;">${isArabic ? 'مرجع سريع لأهم الأوامر والتقنيات' : 'Quick reference for essential commands and techniques'}</p>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px;">
        ${sheets.map(s => `
          <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; cursor: pointer; transition: all 0.3s;" onmouseover="this.style.borderColor='${s.color}'" onmouseout="this.style.borderColor='rgba(255,255,255,0.1)'">
            <i class="fas ${s.icon}" style="font-size: 32px; color: ${s.color}; margin-bottom: 15px;"></i>
            <h3 style="color: #fff; margin-bottom: 10px;">${s.title}</h3>
            <p style="color: rgba(255,255,255,0.5); font-size: 14px;">${s.items} ${isArabic ? 'أمر/تقنية' : 'commands/techniques'}</p>
            <button style="margin-top: 15px; padding: 8px 20px; background: ${s.color}20; color: ${s.color}; border: 1px solid ${s.color}40; border-radius: 8px; cursor: pointer;">
              ${isArabic ? 'عرض' : 'View'}
            </button>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ==================== CERTIFICATE VERIFY PAGE ====================

function pageVerify() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div style="padding: 40px; max-width: 600px; margin: 0 auto; text-align: center;">
      <div style="width: 100px; height: 100px; background: linear-gradient(135deg, #22c55e, #16a34a); border-radius: 50%; margin: 0 auto 30px; display: flex; align-items: center; justify-content: center;">
        <i class="fas fa-certificate" style="font-size: 48px; color: #fff;"></i>
      </div>
      
      <h1 style="color: #fff; margin-bottom: 10px;">${isArabic ? 'التحقق من الشهادة' : 'Verify Certificate'}</h1>
      <p style="color: rgba(255,255,255,0.6); margin-bottom: 40px;">${isArabic ? 'أدخل رقم الشهادة للتحقق من صحتها' : 'Enter certificate ID to verify authenticity'}</p>
      
      <div style="background: rgba(255,255,255,0.05); padding: 40px; border-radius: 20px;">
        <input type="text" id="cert-id" placeholder="${isArabic ? 'رقم الشهادة (مثال: SH-2024-XXXXX)' : 'Certificate ID (e.g., SH-2024-XXXXX)'}" 
          style="width: 100%; padding: 16px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; font-size: 16px; text-align: center; margin-bottom: 20px;">
        
        <button onclick="verifyCertificate()" style="width: 100%; padding: 16px; background: #22c55e; color: #000; border: none; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer;">
          <i class="fas fa-search"></i> ${isArabic ? 'تحقق الآن' : 'Verify Now'}
        </button>
      </div>
      
      <div id="verify-result" style="margin-top: 30px;"></div>
    </div>
  `;
}

// ==================== ABOUT PAGE ====================

function pageAbout() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div style="padding: 40px; max-width: 900px; margin: 0 auto;">
      <div style="text-align: center; margin-bottom: 50px;">
        <h1 style="color: #fff; font-size: 3rem; margin-bottom: 20px;">${isArabic ? 'من نحن' : 'About BreachLabs'}</h1>
        <p style="color: rgba(255,255,255,0.7); font-size: 18px; line-height: 1.8;">
          ${isArabic
      ? 'BreachLabs هي منصة تعليمية مجانية ومفتوحة المصدر لتعلم الأمن السيبراني واختبار الاختراق بطريقة عملية وتفاعلية.'
      : 'BreachLabs is a free, open-source educational platform for learning cybersecurity and penetration testing through hands-on practice.'}
        </p>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-bottom: 50px;">
        ${[
      { icon: 'fa-graduation-cap', num: '50+', label: isArabic ? 'غرفة تعليمية' : 'Learning Rooms' },
      { icon: 'fa-flask', num: '100+', label: isArabic ? 'تحدي عملي' : 'Hands-on Labs' },
      { icon: 'fa-users', num: '10K+', label: isArabic ? 'متعلم' : 'Learners' }
    ].map(s => `
          <div style="text-align: center; padding: 30px; background: rgba(34, 197, 94, 0.1); border-radius: 20px;">
            <i class="fas ${s.icon}" style="font-size: 40px; color: #22c55e; margin-bottom: 15px;"></i>
            <div style="font-size: 36px; color: #fff; font-weight: 700;">${s.num}</div>
            <div style="color: rgba(255,255,255,0.6);">${s.label}</div>
          </div>
        `).join('')}
      </div>
      
      <div style="background: rgba(255,255,255,0.05); padding: 40px; border-radius: 20px; text-align: center;">
        <h3 style="color: #fff; margin-bottom: 20px;">${isArabic ? 'تواصل معنا' : 'Get in Touch'}</h3>
        <div style="display: flex; justify-content: center; gap: 20px;">
          <a href="#" style="width: 50px; height: 50px; background: #5865F2; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 24px;"><i class="fab fa-discord"></i></a>
          <a href="#" style="width: 50px; height: 50px; background: #333; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 24px;"><i class="fab fa-github"></i></a>
          <a href="#" style="width: 50px; height: 50px; background: #1DA1F2; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 24px;"><i class="fab fa-twitter"></i></a>
        </div>
      </div>
    </div>
  `;
}

// ==================== DISCUSSIONS PAGE ====================

function pageDiscussions() {
  const isArabic = document.documentElement.lang === 'ar';

  const topics = [
    { title: 'Help with SQL Injection lab', author: 'HackerX', replies: 12, time: '2h ago' },
    { title: 'Best resources for OSCP prep?', author: 'CyberNinja', replies: 24, time: '5h ago' },
    { title: 'How to bypass WAF?', author: 'PenTester01', replies: 8, time: '1d ago' },
    { title: 'Linux privilege escalation tips', author: 'RootKing', replies: 31, time: '2d ago' }
  ];

  return `
    <div style="padding: 40px; max-width: 900px; margin: 0 auto;">
      <h1 style="color: #fff; margin-bottom: 30px;"><i class="fas fa-comments" style="color: #22c55e;"></i> ${isArabic ? 'المناقشات' : 'Discussions'}</h1>
      
      <button style="margin-bottom: 30px; padding: 12px 24px; background: #22c55e; color: #000; border: none; border-radius: 10px; font-weight: 600; cursor: pointer;">
        <i class="fas fa-plus"></i> ${isArabic ? 'موضوع جديد' : 'New Topic'}
      </button>
      
      <div style="display: flex; flex-direction: column; gap: 15px;">
        ${topics.map(t => `
          <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; display: flex; justify-content: space-between; align-items: center; cursor: pointer;" onmouseover="this.style.background='rgba(34,197,94,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
            <div>
              <h4 style="color: #fff; margin-bottom: 5px;">${t.title}</h4>
              <span style="color: rgba(255,255,255,0.5); font-size: 14px;">by ${t.author} • ${t.time}</span>
            </div>
            <div style="background: rgba(34,197,94,0.2); padding: 8px 16px; border-radius: 20px; color: #22c55e;">
              <i class="fas fa-comment"></i> ${t.replies}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ==================== DAILY CTF PAGE ====================

function pageDailyCtf() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div style="padding: 40px; max-width: 800px; margin: 0 auto; text-align: center;">
      <div style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); border-radius: 20px; padding: 50px; margin-bottom: 40px;">
        <i class="fas fa-calendar-day" style="font-size: 60px; color: #fff; margin-bottom: 20px;"></i>
        <h1 style="color: #fff; font-size: 2.5rem; margin-bottom: 10px;">${isArabic ? 'تحدي اليوم' : "Today's Challenge"}</h1>
        <p style="color: rgba(255,255,255,0.9);">${isArabic ? 'تحدي جديد كل يوم!' : 'A new challenge every day!'}</p>
      </div>
      
      <div style="background: rgba(255,255,255,0.05); padding: 40px; border-radius: 20px; margin-bottom: 30px;">
        <div style="color: #f59e0b; font-size: 14px; margin-bottom: 10px;">DECEMBER 8, 2024</div>
        <h2 style="color: #fff; font-size: 1.8rem; margin-bottom: 15px;">SQL Injection Challenge</h2>
        <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">${isArabic ? 'اكتشف واستغل ثغرة SQL في موقع المتجر' : 'Find and exploit SQL vulnerability in the shop website'}</p>
        
        <div style="display: flex; justify-content: center; gap: 30px; margin-bottom: 30px;">
          <div><span style="color: #f59e0b; font-size: 24px; font-weight: 700;">500</span><br><span style="color: rgba(255,255,255,0.5); font-size: 14px;">${isArabic ? 'نقاط' : 'Points'}</span></div>
          <div><span style="color: #22c55e; font-size: 24px; font-weight: 700;">142</span><br><span style="color: rgba(255,255,255,0.5); font-size: 14px;">${isArabic ? 'أكملوه' : 'Solves'}</span></div>
        </div>
        
        <button style="padding: 15px 50px; background: #f59e0b; color: #000; border: none; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer;">
          ${isArabic ? 'ابدأ التحدي' : 'Start Challenge'}
        </button>
      </div>
      
      <p style="color: rgba(255,255,255,0.5);">${isArabic ? 'التحدي القادم خلال' : 'Next challenge in'}: <span style="color: #f59e0b;">14:32:18</span></p>
    </div>
  `;
}

// ==================== OLD LEAGUES PAGE (DEPRECATED - Use pageLeagues from tryhackme-pages.js) ====================

function pageLeaguesOld() {
  const isArabic = document.documentElement.lang === 'ar';

  return `
    <div style="padding: 40px; max-width: 1000px; margin: 0 auto;">
      <h1 style="color: #fff; text-align: center; margin-bottom: 40px;">
        <i class="fas fa-medal" style="color: #f59e0b;"></i> ${isArabic ? 'الدوريات' : 'CTF Leagues'}
      </h1>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px;">
        ${[
      { name: 'Bronze League', color: '#cd7f32', players: '1.2K', req: '0-1000 pts' },
      { name: 'Silver League', color: '#c0c0c0', players: '800', req: '1000-5000 pts' },
      { name: 'Gold League', color: '#ffd700', players: '300', req: '5000-15000 pts' },
      { name: 'Platinum League', color: '#e5e4e2', players: '50', req: '15000+ pts' }
    ].map(l => `
          <div style="background: ${l.color}15; border: 2px solid ${l.color}40; border-radius: 20px; padding: 30px; text-align: center;">
            <i class="fas fa-trophy" style="font-size: 48px; color: ${l.color}; margin-bottom: 20px;"></i>
            <h3 style="color: #fff; margin-bottom: 10px;">${l.name}</h3>
            <p style="color: rgba(255,255,255,0.5);">${l.req}</p>
            <p style="color: ${l.color}; margin-top: 15px;">${l.players} players</p>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ==================== FREE/PRO LABS ====================

function pageFreeLabs() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <h1 style="color: #22c55e; margin-bottom: 30px;"><i class="fas fa-gift"></i> ${isArabic ? 'المعامل المجانية' : 'Free Labs'}</h1>
      <p style="color: rgba(255,255,255,0.6); margin-bottom: 40px;">${isArabic ? 'ابدأ تعلم الأمن السيبراني مجاناً' : 'Start learning cybersecurity for free'}</p>
      <button onclick="loadPage('practice')" style="padding: 15px 30px; background: #22c55e; color: #000; border: none; border-radius: 12px; font-size: 16px; cursor: pointer;">
        ${isArabic ? 'تصفح الغرف المجانية' : 'Browse Free Rooms'}
      </button>
    </div>
  `;
}

function pageProLabs() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #a855f7, #9333ea); padding: 50px; border-radius: 20px; text-align: center;">
        <i class="fas fa-star" style="font-size: 60px; color: #fff; margin-bottom: 20px;"></i>
        <h1 style="color: #fff; margin-bottom: 20px;">${isArabic ? 'سيناريوهات PRO' : 'PRO Scenarios'}</h1>
        <p style="color: rgba(255,255,255,0.9); margin-bottom: 30px;">${isArabic ? 'سيناريوهات متقدمة تحاكي بيئات العمل الحقيقية' : 'Advanced scenarios simulating real-world environments'}</p>
        <button style="padding: 15px 40px; background: #fff; color: #9333ea; border: none; border-radius: 12px; font-size: 18px; font-weight: 600; cursor: pointer;">
          ${isArabic ? 'ترقية للـ PRO' : 'Upgrade to PRO'}
        </button>
      </div>
    </div>
  `;
}

// ==================== OTHER PAGES ====================

function pagePartners() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 900px; margin: 0 auto; text-align: center;">
      <h1 style="color: #fff; margin-bottom: 40px;"><i class="fas fa-handshake" style="color: #22c55e;"></i> ${isArabic ? 'شركاؤنا' : 'Our Partners'}</h1>
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 30px;">
        ${['Partner 1', 'Partner 2', 'Partner 3', 'Partner 4'].map(p => `
          <div style="background: rgba(255,255,255,0.05); padding: 40px; border-radius: 16px;">
            <div style="width: 80px; height: 80px; background: rgba(255,255,255,0.1); border-radius: 50%; margin: 0 auto;"></div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function pageDocs() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 900px; margin: 0 auto;">
      <h1 style="color: #fff; margin-bottom: 30px;"><i class="fas fa-book-open" style="color: #22c55e;"></i> ${isArabic ? 'التوثيق' : 'Documentation'}</h1>
      <div style="display: grid; gap: 15px;">
        ${['Getting Started', 'How to Use Labs', 'Account Settings', 'API Reference', 'FAQ'].map(d => `
          <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; cursor: pointer;" onmouseover="this.style.background='rgba(34,197,94,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
            <i class="fas fa-file-alt" style="color: #22c55e; margin-right: 15px;"></i>
            <span style="color: #fff;">${d}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function pageVideos() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 1200px; margin: 0 auto;">
      <h1 style="color: #fff; margin-bottom: 30px;"><i class="fas fa-video" style="color: #ef4444;"></i> ${isArabic ? 'فيديوهات تعليمية' : 'Video Tutorials'}</h1>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
        ${['Intro to Hacking', 'Web App Pentesting', 'Linux for Hackers', 'CTF Walkthrough'].map(v => `
          <div style="background: rgba(255,255,255,0.05); border-radius: 16px; overflow: hidden;">
            <div style="height: 180px; background: linear-gradient(135deg, #1a1a2e, #16213e); display: flex; align-items: center; justify-content: center;">
              <i class="fas fa-play-circle" style="font-size: 48px; color: rgba(255,255,255,0.3);"></i>
            </div>
            <div style="padding: 15px;"><h4 style="color: #fff;">${v}</h4></div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function pagePastCtf() {
  const isArabic = document.documentElement.lang === 'ar';
  return `
    <div style="padding: 40px; max-width: 900px; margin: 0 auto;">
      <h1 style="color: #fff; margin-bottom: 30px;"><i class="fas fa-flag-checkered" style="color: #f59e0b;"></i> ${isArabic ? 'تحديات سابقة' : 'Past CTF Challenges'}</h1>
      <div style="display: grid; gap: 15px;">
        ${[
      { name: 'November 2024 CTF', teams: 45, winner: 'Team Alpha' },
      { name: 'October 2024 CTF', teams: 38, winner: 'CyberHunters' },
      { name: 'September 2024 CTF', teams: 52, winner: 'RedTeam Pro' }
    ].map(c => `
          <div style="background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <h4 style="color: #fff;">${c.name}</h4>
              <span style="color: rgba(255,255,255,0.5);">${c.teams} teams participated</span>
            </div>
            <div style="color: #f59e0b;"><i class="fas fa-trophy"></i> ${c.winner}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}
