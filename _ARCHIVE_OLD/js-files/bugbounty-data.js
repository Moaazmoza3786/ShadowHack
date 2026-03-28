// ==================== BUG BOUNTY DATA ====================
// بيانات قسم Bug Bounty

const bugBountyData = {
    // Methodology Guide
    methodology: {
        title: 'منهجية صيد الثغرات',
        titleEn: 'Bug Bounty Methodology',
        phases: [
            {
                id: 'recon',
                title: 'الاستطلاع',
                titleEn: 'Reconnaissance',
                icon: 'binoculars',
                color: '#667eea',
                steps: [
                    { title: 'تعداد النطاقات الفرعية', titleEn: 'Subdomain Enumeration', tools: ['Subfinder', 'Amass', 'Assetfinder'], description: 'اكتشاف جميع النطاقات الفرعية للهدف' },
                    { title: 'فحص الحالة', titleEn: 'Probing', tools: ['httpx', 'httprobe'], description: 'التحقق من النطاقات النشطة' },
                    { title: 'فحص المنافذ', titleEn: 'Port Scanning', tools: ['Nmap', 'Masscan'], description: 'اكتشاف الخدمات المفتوحة' },
                    { title: 'تحليل التقنيات', titleEn: 'Technology Detection', tools: ['Wappalyzer', 'WhatWeb'], description: 'تحديد التقنيات المستخدمة' }
                ]
            },
            {
                id: 'discovery',
                title: 'الاكتشاف',
                titleEn: 'Discovery',
                icon: 'search',
                color: '#f093fb',
                steps: [
                    { title: 'اكتشاف المحتوى', titleEn: 'Content Discovery', tools: ['Gobuster', 'ffuf', 'dirsearch'], description: 'البحث عن الملفات والمجلدات المخفية' },
                    { title: 'تحليل JavaScript', titleEn: 'JS Analysis', tools: ['LinkFinder', 'JSFinder'], description: 'استخراج Endpoints من ملفات JS' },
                    { title: 'فحص الأرشيف', titleEn: 'Wayback Analysis', tools: ['waybackurls', 'gau'], description: 'البحث في أرشيف الإنترنت' },
                    { title: 'Google Dorking', titleEn: 'Google Dorking', tools: ['Google', 'DorkSearch'], description: 'استخدام محركات البحث' }
                ]
            },
            {
                id: 'testing',
                title: 'الاختبار',
                titleEn: 'Testing',
                icon: 'flask',
                color: '#38ef7d',
                steps: [
                    { title: 'اختبار المصادقة', titleEn: 'Authentication Testing', tools: ['Burp Suite'], description: 'فحص نظام تسجيل الدخول' },
                    { title: 'اختبار التفويض', titleEn: 'Authorization Testing', tools: ['Autorize'], description: 'فحص صلاحيات الوصول' },
                    { title: 'اختبار الحقن', titleEn: 'Injection Testing', tools: ['SQLMap', 'Burp'], description: 'البحث عن ثغرات الحقن' },
                    { title: 'اختبار XSS', titleEn: 'XSS Testing', tools: ['XSStrike', 'Dalfox'], description: 'البحث عن Cross-Site Scripting' }
                ]
            },
            {
                id: 'exploit',
                title: 'الاستغلال',
                titleEn: 'Exploitation',
                icon: 'bug',
                color: '#eb3349',
                steps: [
                    { title: 'إثبات الثغرة', titleEn: 'Proof of Concept', tools: ['Burp Suite', 'Python'], description: 'إنشاء PoC للثغرة' },
                    { title: 'تقييم الخطورة', titleEn: 'Impact Assessment', tools: ['CVSS Calculator'], description: 'تحديد مستوى الخطورة' },
                    { title: 'توثيق الخطوات', titleEn: 'Documentation', tools: ['Markdown'], description: 'توثيق خطوات الاستغلال' }
                ]
            },
            {
                id: 'report',
                title: 'التقرير',
                titleEn: 'Reporting',
                icon: 'file-alt',
                color: '#764ba2',
                steps: [
                    { title: 'كتابة التقرير', titleEn: 'Write Report', tools: ['Markdown', 'HackerOne'], description: 'كتابة تقرير احترافي' },
                    { title: 'إضافة Screenshots', titleEn: 'Add Screenshots', tools: ['Greenshot'], description: 'توثيق بالصور' },
                    { title: 'تقديم التقرير', titleEn: 'Submit Report', tools: ['Platform'], description: 'إرسال للبرنامج' }
                ]
            }
        ]
    },

    // Report Templates
    reportTemplates: [
        {
            id: 'sqli-report',
            title: 'تقرير SQL Injection',
            severity: 'Critical',
            template: `## Summary
SQL Injection vulnerability in [endpoint]

## Vulnerability Details
- **Endpoint:** 
- **Parameter:** 
- **Type:** 

## Steps to Reproduce
1. Navigate to [URL]
2. Insert payload: \`' OR 1=1--\`
3. Observe [result]

## Impact
- Database access
- Data exfiltration
- Authentication bypass

## Remediation
Use parameterized queries/prepared statements.

## References
- OWASP SQL Injection
- CWE-89`
        },
        {
            id: 'xss-report',
            title: 'تقرير XSS',
            severity: 'High',
            template: `## Summary
Cross-Site Scripting (XSS) in [endpoint]

## Vulnerability Details
- **Endpoint:** 
- **Parameter:** 
- **Type:** Reflected/Stored/DOM

## Steps to Reproduce
1. Navigate to [URL]
2. Insert payload: \`<script>alert(1)</script>\`
3. Observe JavaScript execution

## Impact
- Session hijacking
- Cookie theft
- Phishing

## Remediation
Implement output encoding and CSP.`
        },
        {
            id: 'idor-report',
            title: 'تقرير IDOR',
            severity: 'High',
            template: `## Summary
Insecure Direct Object Reference in [endpoint]

## Vulnerability Details
- **Endpoint:** 
- **Parameter:** 

## Steps to Reproduce
1. Login as User A
2. Access /api/users/123
3. Change to /api/users/124
4. Access User B's data

## Impact
- Unauthorized data access
- Privacy violation

## Remediation
Implement proper authorization checks.`
        },
        {
            id: 'ssrf-report',
            title: 'تقرير SSRF',
            severity: 'Critical',
            template: `## Summary
Server-Side Request Forgery in [endpoint]

## Vulnerability Details
- **Endpoint:** 
- **Parameter:** 

## Steps to Reproduce
1. Intercept request
2. Modify URL to: http://169.254.169.254/
3. Access cloud metadata

## Impact
- Internal network access
- Cloud credential theft
- RCE potential

## Remediation
Implement URL allowlist validation.`
        }
    ],

    // Bug Bounty Programs
    programs: [
        { name: 'HackerOne', url: 'https://hackerone.com', type: 'Platform', bountyRange: '$100 - $100,000+', description: 'أكبر منصة Bug Bounty' },
        { name: 'Bugcrowd', url: 'https://bugcrowd.com', type: 'Platform', bountyRange: '$50 - $50,000+', description: 'منصة شهيرة للثغرات' },
        { name: 'Intigriti', url: 'https://intigriti.com', type: 'Platform', bountyRange: '€50 - €50,000+', description: 'منصة أوروبية' },
        { name: 'Google VRP', url: 'https://bughunters.google.com', type: 'Direct', bountyRange: '$100 - $31,337+', description: 'برنامج جوجل' },
        { name: 'Microsoft MSRC', url: 'https://msrc.microsoft.com', type: 'Direct', bountyRange: '$500 - $100,000+', description: 'برنامج مايكروسوفت' },
        { name: 'Facebook', url: 'https://facebook.com/whitehat', type: 'Direct', bountyRange: '$500 - $50,000+', description: 'برنامج فيسبوك' },
        { name: 'Apple Security', url: 'https://security.apple.com', type: 'Direct', bountyRange: '$5,000 - $1,000,000+', description: 'برنامج أبل' },
        { name: 'GitHub', url: 'https://bounty.github.com', type: 'Direct', bountyRange: '$617 - $30,000+', description: 'برنامج جيت هاب' }
    ],

    // Tips for Beginners
    tips: [
        { icon: 'target', title: 'ابدأ بالأهداف الصغيرة', description: 'اختر برامج للمبتدئين أولاً' },
        { icon: 'book', title: 'تعلم باستمرار', description: 'اقرأ التقارير المكشوفة' },
        { icon: 'users', title: 'انضم للمجتمع', description: 'شارك في Discord و Twitter' },
        { icon: 'clock', title: 'الصبر مفتاح', description: 'لا تستسلم بسرعة' },
        { icon: 'tools', title: 'أتقن أدواتك', description: 'تعلم Burp Suite جيداً' },
        { icon: 'pencil', title: 'وثق كل شيء', description: 'احتفظ بملاحظاتك' }
    ],

    // Common Vulnerabilities Quick Reference
    vulnRef: [
        { name: 'SQL Injection', severity: 'Critical', cvss: '9.8', cwe: 'CWE-89' },
        { name: 'XSS', severity: 'High', cvss: '6.1-8.2', cwe: 'CWE-79' },
        { name: 'CSRF', severity: 'Medium', cvss: '4.3-6.5', cwe: 'CWE-352' },
        { name: 'IDOR', severity: 'High', cvss: '6.5-8.6', cwe: 'CWE-639' },
        { name: 'SSRF', severity: 'Critical', cvss: '9.1', cwe: 'CWE-918' },
        { name: 'XXE', severity: 'High', cvss: '7.5', cwe: 'CWE-611' },
        { name: 'RCE', severity: 'Critical', cvss: '9.8-10', cwe: 'CWE-94' },
        { name: 'File Upload', severity: 'High', cvss: '7.2-9.8', cwe: 'CWE-434' }
    ]
};

// Career Path Data
const careerData = {
    roles: [
        {
            id: 'pentester',
            title: 'Penetration Tester',
            titleAr: 'مختبر اختراق',
            salary: '$70,000 - $130,000',
            demand: 'High',
            description: 'اختبار أمان الأنظمة والتطبيقات',
            skills: ['Web Security', 'Network Security', 'Scripting', 'Report Writing'],
            certs: ['OSCP', 'CEH', 'eJPT', 'PNPT']
        },
        {
            id: 'security-analyst',
            title: 'Security Analyst',
            titleAr: 'محلل أمني',
            salary: '$60,000 - $100,000',
            demand: 'Very High',
            description: 'مراقبة وتحليل التهديدات الأمنية',
            skills: ['SIEM', 'Threat Analysis', 'Incident Response', 'Log Analysis'],
            certs: ['Security+', 'CySA+', 'GCIH']
        },
        {
            id: 'bug-hunter',
            title: 'Bug Bounty Hunter',
            titleAr: 'صائد ثغرات',
            salary: '$50,000 - $500,000+',
            demand: 'Flexible',
            description: 'البحث عن ثغرات في البرامج المختلفة',
            skills: ['Web Security', 'Recon', 'Persistence', 'Report Writing'],
            certs: ['OSCP', 'BSCP', 'eWPT']
        },
        {
            id: 'security-engineer',
            title: 'Security Engineer',
            titleAr: 'مهندس أمني',
            salary: '$100,000 - $180,000',
            demand: 'High',
            description: 'تصميم وتنفيذ الحلول الأمنية',
            skills: ['Cloud Security', 'DevSecOps', 'Architecture', 'Automation'],
            certs: ['CISSP', 'AWS Security', 'Azure Security']
        },
        {
            id: 'red-team',
            title: 'Red Team Operator',
            titleAr: 'مشغل الفريق الأحمر',
            salary: '$120,000 - $200,000',
            demand: 'High',
            description: 'محاكاة هجمات متقدمة على المؤسسات',
            skills: ['Advanced Exploitation', 'C2 Frameworks', 'Evasion', 'Social Engineering'],
            certs: ['OSCP', 'CRTO', 'GPEN']
        },
        {
            id: 'malware-analyst',
            title: 'Malware Analyst',
            titleAr: 'محلل برمجيات خبيثة',
            salary: '$80,000 - $140,000',
            demand: 'Medium',
            description: 'تحليل وفهم البرمجيات الخبيثة',
            skills: ['Reverse Engineering', 'Assembly', 'Debugging', 'Sandbox Analysis'],
            certs: ['GREM', 'CREA', 'eCMAP']
        }
    ],

    certifications: [
        { id: 'oscp', name: 'OSCP', fullName: 'Offensive Security Certified Professional', provider: 'OffSec', price: '$1,599+', difficulty: 'Hard', duration: '90 days', recommended: true },
        { id: 'ceh', name: 'CEH', fullName: 'Certified Ethical Hacker', provider: 'EC-Council', price: '$950+', difficulty: 'Medium', duration: 'Self-paced', recommended: true },
        { id: 'ejpt', name: 'eJPT', fullName: 'eLearnSecurity Junior Penetration Tester', provider: 'INE', price: '$249', difficulty: 'Easy', duration: '35 hours', recommended: true },
        { id: 'secplus', name: 'Security+', fullName: 'CompTIA Security+', provider: 'CompTIA', price: '$392', difficulty: 'Easy', duration: 'Self-paced', recommended: true },
        { id: 'cissp', name: 'CISSP', fullName: 'Certified Information Systems Security Professional', provider: 'ISC2', price: '$749', difficulty: 'Hard', duration: 'Self-paced', recommended: false },
        { id: 'pnpt', name: 'PNPT', fullName: 'Practical Network Penetration Tester', provider: 'TCM', price: '$399', difficulty: 'Medium', duration: '30 hours', recommended: true },
        { id: 'bscp', name: 'BSCP', fullName: 'Burp Suite Certified Practitioner', provider: 'PortSwigger', price: '$99', difficulty: 'Medium', duration: 'Self-paced', recommended: true }
    ],

    roadmap: [
        { level: 1, title: 'المبتدئ', titleEn: 'Beginner', duration: '3-6 months', focus: ['Linux Basics', 'Networking', 'Programming Fundamentals'], certs: ['Security+', 'eJPT'] },
        { level: 2, title: 'المتوسط', titleEn: 'Intermediate', duration: '6-12 months', focus: ['Web Security', 'Pentesting Tools', 'CTF Challenges'], certs: ['CEH', 'PNPT'] },
        { level: 3, title: 'المتقدم', titleEn: 'Advanced', duration: '1-2 years', focus: ['Advanced Exploitation', 'Red Teaming', 'Bug Bounty'], certs: ['OSCP', 'BSCP'] },
        { level: 4, title: 'الخبير', titleEn: 'Expert', duration: '2+ years', focus: ['Specialization', 'Research', 'Leadership'], certs: ['OSWE', 'CRTO', 'CISSP'] }
    ]
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { bugBountyData, careerData };
}
