// ==================== SHADOWHACK AI CHATBOT - PREMIUM EDITION ====================
// Powered by OpenAI GPT - Advanced Cybersecurity Assistant

// OpenAI API Configuration
// SECURITY WARNING: Never hardcode API keys in client-side code!
const AI_CONFIG = {
  apiKeys: [
    'sk-YOUR-OPENAI-API-KEY-HERE'
  ],
  currentKeyIndex: 0,
  model: 'gpt-3.5-turbo',
  baseUrl: 'https://api.openai.com/v1/chat/completions'
};

// Get next API key (rotation for rate limiting)
function getNextApiKey() {
  const key = AI_CONFIG.apiKeys[AI_CONFIG.currentKeyIndex];
  AI_CONFIG.currentKeyIndex = (AI_CONFIG.currentKeyIndex + 1) % AI_CONFIG.apiKeys.length;
  return key;
}

const SYSTEM_PROMPT = `أنت "ShadowHack AI"، مساعد ذكاء اصطناعي متخصص في الأمن السيبراني واختبار الاختراق وصيد الثغرات.

قدراتك:
- شرح ثغرات OWASP Top 10 بالتفصيل
- المساعدة في حل تحديات CTF
- كتابة تقارير Bug Bounty احترافية
- شرح أدوات مثل Burp Suite, Nmap, SQLMap
- تحليل الأكواد واكتشاف الثغرات
- شرح مفاهيم الشبكات والبروتوكولات
- المساعدة في التنقل داخل منصة ShadowHack

قواعد:
- استخدم العربية إذا كتب المستخدم بالعربية، والإنجليزية إذا كتب بالإنجليزية
- قدم أمثلة عملية مع الأكواد
- استخدم تنسيق Markdown للردود
- كن مختصراً ومفيداً`;

let chatHistory = [];
let conversationHistory = []; // For OpenAI format
let isMinimized = false;
let soundEnabled = true;

// Send message to OpenAI API
async function sendMessage() {
  const input = document.getElementById('chatbot-input');
  const message = input.value.trim();
  if (!message) return;

  // Check for navigation commands first
  const navResponse = handleNavigationCommand(message);
  if (navResponse) {
    addMessageToUI(message, 'user');
    addMessageToUI(navResponse, 'bot');
    input.value = '';
    return;
  }

  // Add user message to UI
  addMessageToUI(message, 'user');
  input.value = '';
  input.style.height = 'auto';

  // Show typing indicator
  showTypingIndicator();

  // Add to conversation history
  conversationHistory.push({ role: 'user', content: message });

  try {
    const apiKey = getNextApiKey();

    // Check if API key is set
    if (apiKey === 'sk-YOUR-OPENAI-API-KEY-HERE') {
      hideTypingIndicator();
      addMessageToUI('⚠️ يرجى إضافة مفتاح OpenAI API الخاص بك في ملف ai-chatbot.js\n\nPlease add your OpenAI API key in the ai-chatbot.js file', 'bot');
      return;
    }

    const response = await fetch(AI_CONFIG.baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: AI_CONFIG.model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          ...conversationHistory.slice(-10) // Keep last 10 messages for context
        ],
        max_tokens: 1000,
        temperature: 0.7
      })
    });

    hideTypingIndicator();

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      if (response.status === 401) {
        addMessageToUI('❌ مفتاح API غير صالح. يرجى التحقق من المفتاح.\n\nInvalid API key. Please check your key.', 'bot');
      } else if (response.status === 429) {
        addMessageToUI('⏳ تم تجاوز حد الطلبات. يرجى الانتظار قليلاً.\n\nRate limit exceeded. Please wait a moment.', 'bot');
      } else {
        addMessageToUI(`❌ خطأ في الاتصال: ${errorData.error?.message || response.statusText}`, 'bot');
      }
      return;
    }

    const data = await response.json();
    const aiResponse = data.choices[0]?.message?.content || 'عذراً، لم أتمكن من الرد.';

    // Add to conversation history
    conversationHistory.push({ role: 'assistant', content: aiResponse });

    // Add to UI
    addMessageToUI(aiResponse, 'bot');

    // Save chat history
    chatHistory.push({ role: 'user', parts: [{ text: message }] });
    chatHistory.push({ role: 'model', parts: [{ text: aiResponse }] });
    saveChatHistory();

    // Play notification sound
    if (soundEnabled) playNotificationSound();

  } catch (error) {
    hideTypingIndicator();
    console.error('Chat error:', error);
    addMessageToUI('❌ حدث خطأ في الاتصال. تأكد من اتصالك بالإنترنت.\n\nConnection error. Please check your internet.', 'bot');
  }
}

// Send quick message from suggestions
function sendQuickMessage(message) {
  document.getElementById('chatbot-input').value = message;
  sendMessage();
}

// Add message to chat UI
function addMessageToUI(text, sender) {
  const messagesContainer = document.getElementById('chatbot-messages');
  const welcomeMessage = messagesContainer.querySelector('.welcome-message');
  if (welcomeMessage) welcomeMessage.remove();

  const time = new Date().toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });

  // Format markdown-like content
  let formattedText = text
    .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\n/g, '<br>');

  const messageHTML = `
        <div class="chat-message ${sender}">
            <div class="message-avatar">
                <i class="fas fa-${sender === 'user' ? 'user' : 'robot'}"></i>
            </div>
            <div class="message-content">
                ${formattedText}
                <div class="message-time">${time}</div>
            </div>
        </div>
    `;

  messagesContainer.insertAdjacentHTML('beforeend', messageHTML);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Show typing indicator
function showTypingIndicator() {
  const messagesContainer = document.getElementById('chatbot-messages');
  const typingHTML = `
        <div class="chat-message bot" id="typing-indicator">
            <div class="message-avatar"><i class="fas fa-robot"></i></div>
            <div class="typing-indicator">
                <span></span><span></span><span></span>
            </div>
        </div>
    `;
  messagesContainer.insertAdjacentHTML('beforeend', typingHTML);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Hide typing indicator
function hideTypingIndicator() {
  const indicator = document.getElementById('typing-indicator');
  if (indicator) indicator.remove();
}

// Clear chat
function clearChat() {
  document.getElementById('chatbot-messages').innerHTML = `
        <div class="welcome-message">
            <div class="welcome-avatar"><i class="fas fa-robot"></i></div>
            <h3>مرحباً بك! 👋</h3>
            <p>أنا <strong>ShadowHack AI</strong>، مساعدك الذكي في عالم الأمن السيبراني</p>
            <div class="capabilities">
                <div class="capability"><i class="fas fa-bug"></i> تحليل الثغرات</div>
                <div class="capability"><i class="fas fa-file-alt"></i> كتابة التقارير</div>
                <div class="capability"><i class="fas fa-flag"></i> حل CTF</div>
                <div class="capability"><i class="fas fa-tools"></i> شرح الأدوات</div>
            </div>
        </div>
    `;
  chatHistory = [];
  conversationHistory = [];
  localStorage.removeItem('shadowhack_chat_history');
}





function initChatbot() {
  const chatbotHTML = `
    <button id="chatbot-toggle" class="chatbot-toggle" onclick="toggleChatbot()">
      <i class="fas fa-robot"></i>
      <span class="notification-dot" id="notif-dot" style="display:none;"></span>
    </button>
    
    <div id="chatbot-window" class="chatbot-window">
      <div class="chatbot-header">
        <div class="chatbot-branding">
          <div class="ai-avatar pulse"><i class="fas fa-robot"></i></div>
          <div class="chatbot-info">
            <span class="chatbot-name">ShadowHack AI</span>
            <span class="chatbot-status"><span class="status-dot"></span> متصل</span>
          </div>
        </div>
        <div class="chatbot-controls">
          <button onclick="toggleSound()" title="الصوت" id="sound-btn"><i class="fas fa-volume-up"></i></button>
          <button onclick="exportChat()" title="تصدير"><i class="fas fa-download"></i></button>
          <button onclick="clearChat()" title="مسح"><i class="fas fa-trash-alt"></i></button>
          <button onclick="minimizeChatbot()" title="تصغير"><i class="fas fa-minus"></i></button>
          <button onclick="toggleChatbot()" title="إغلاق"><i class="fas fa-times"></i></button>
        </div>
      </div>

      <div class="chatbot-tabs">
        <button class="tab-btn active" onclick="switchTab('chat')"><i class="fas fa-comments"></i> المحادثة</button>
        <button class="tab-btn" onclick="switchTab('tools')"><i class="fas fa-magic"></i> أدوات</button>
        <button class="tab-btn" onclick="switchTab('history')"><i class="fas fa-history"></i> السجل</button>
      </div>

      <div id="tab-chat" class="tab-content active">
        <div id="chatbot-messages" class="chatbot-messages">
          <div class="welcome-message">
            <div class="welcome-avatar"><i class="fas fa-robot"></i></div>
            <h3>مرحباً بك! 👋</h3>
            <p>أنا <strong>ShadowHack AI</strong>، مساعدك الذكي في عالم الأمن السيبراني</p>
            <div class="capabilities">
              <div class="capability"><i class="fas fa-bug"></i> تحليل الثغرات</div>
              <div class="capability"><i class="fas fa-file-alt"></i> كتابة التقارير</div>
              <div class="capability"><i class="fas fa-flag"></i> حل CTF</div>
              <div class="capability"><i class="fas fa-tools"></i> شرح الأدوات</div>
            </div>
          </div>
        </div>

        <div class="suggested-prompts" id="suggested-prompts">
          <span class="prompts-label">اقتراحات:</span>
          <div class="prompts-scroll">
            <button onclick="sendQuickMessage('اشرح لي SQL Injection')">💉 SQL Injection</button>
            <button onclick="sendQuickMessage('كيف أكتب تقرير Bug Bounty؟')">📝 كتابة تقرير</button>
            <button onclick="sendQuickMessage('ما هي أدوات الـ Recon؟')">🔍 أدوات Recon</button>
            <button onclick="sendQuickMessage('اشرح XSS بالتفصيل')">⚡ XSS</button>
          </div>
        </div>

        <div class="chatbot-input-area">
          <div class="chatbot-input">
            <textarea id="chatbot-input" placeholder="اكتب رسالتك..." onkeydown="handleKeyDown(event)" rows="1"></textarea>
            <button onclick="sendMessage()" class="send-btn" id="send-btn"><i class="fas fa-paper-plane"></i></button>
          </div>
        </div>
      </div>

      <div id="tab-tools" class="tab-content">
        <div class="tools-grid">
          <div class="tool-card" onclick="generateReportTemplate()"><i class="fas fa-file-code"></i><span>مولد التقارير</span></div>
          <div class="tool-card" onclick="explainVulnerability()"><i class="fas fa-bug"></i><span>شرح الثغرات</span></div>
          <div class="tool-card" onclick="generatePayload()"><i class="fas fa-code"></i><span>مولد Payloads</span></div>
          <div class="tool-card" onclick="ctfHelper()"><i class="fas fa-flag"></i><span>مساعد CTF</span></div>
          <div class="tool-card" onclick="toolsGuide()"><i class="fas fa-toolbox"></i><span>دليل الأدوات</span></div>
          <div class="tool-card" onclick="methodologyGuide()"><i class="fas fa-list-ol"></i><span>المنهجية</span></div>
        </div>
      </div>

      <div id="tab-history" class="tab-content">
        <div class="history-list" id="history-list">
          <div class="empty-history"><i class="fas fa-inbox"></i><p>لا توجد محادثات محفوظة</p></div>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', chatbotHTML);
  addChatbotStyles();
  loadChatHistory();

  const textarea = document.getElementById('chatbot-input');
  textarea.addEventListener('input', function () {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
  });
}

function addChatbotStyles() {
  const styles = document.createElement('style');
  styles.textContent = `
    .chatbot-toggle{
        position:fixed; bottom:30px; left:30px;
        width:70px; height:70px;
        border-radius:50%;
        background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
        color:#fff;
        border:4px solid rgba(255,255,255,0.2);
        font-size:1.8rem;
        cursor:pointer;
        box-shadow:0 10px 40px rgba(102,126,234,0.5), 0 0 0 0 rgba(102,126,234,0.5);
        z-index:9998;
        transition:all .4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        display:flex; align-items:center; justify-content:center;
        animation:toggleBounceIn 1s;
    }
    .chatbot-toggle:hover{
        transform:scale(1.1) rotate(10deg);
        box-shadow:0 15px 50px rgba(102,126,234,0.7);
        border-color:rgba(255,255,255,0.6);
    }
    .chatbot-toggle.active{
        background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);
        transform:rotate(180deg);
        box-shadow:0 10px 40px rgba(245,87,108,0.5);
    }
    @keyframes toggleBounceIn{
        0%{transform:scale(0);opacity:0}
        60%{transform:scale(1.1);opacity:1}
        100%{transform:scale(1)}
    }
    .notification-dot{position:absolute;top:5px;right:5px;width:12px;height:12px;background:#ff4757;border-radius:50%;animation:pulse 1s infinite}
    .chatbot-window{position:fixed;bottom:110px;left:30px;width:400px;height:550px;background:rgba(255,255,255,0.98);backdrop-filter:blur(20px);border-radius:20px;box-shadow:0 25px 80px rgba(0,0,0,0.15);z-index:9999;display:none;flex-direction:column;overflow:hidden;border:1px solid rgba(255,255,255,0.3)}
    .chatbot-window.open{display:flex;animation:slideUp .4s ease}
    .chatbot-window.minimized{height:60px}
    .chatbot-window.minimized .chatbot-tabs,.chatbot-window.minimized .tab-content{display:none}
    @keyframes slideUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
    @keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.2)}}
    .chatbot-header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:12px 15px;display:flex;justify-content:space-between;align-items:center}
    .chatbot-branding{display:flex;align-items:center;gap:10px}
    .ai-avatar{width:40px;height:40px;background:rgba(255,255,255,0.2);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.1rem}
    .ai-avatar.pulse{animation:avatarPulse 2s infinite}
    @keyframes avatarPulse{0%,100%{box-shadow:0 0 0 0 rgba(255,255,255,0.4)}50%{box-shadow:0 0 0 10px rgba(255,255,255,0)}}
    .chatbot-info{display:flex;flex-direction:column}
    .chatbot-name{font-weight:700;font-size:1rem}
    .chatbot-status{font-size:.7rem;opacity:.9;display:flex;align-items:center;gap:5px}
    .status-dot{width:8px;height:8px;background:#2ecc71;border-radius:50%}
    .chatbot-controls{display:flex;gap:3px}
    .chatbot-controls button{background:rgba(255,255,255,0.15);border:none;color:#fff;width:30px;height:30px;border-radius:6px;cursor:pointer;transition:all .2s}
    .chatbot-controls button:hover{background:rgba(255,255,255,0.3)}
    .chatbot-tabs{display:flex;background:#f8f9fa;border-bottom:1px solid #e9ecef}
    .tab-btn{flex:1;padding:10px;border:none;background:none;cursor:pointer;font-size:.8rem;color:#666;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:5px}
    .tab-btn.active{color:#667eea;background:#fff;border-bottom:2px solid #667eea}
    .tab-content{display:none;flex:1;flex-direction:column;overflow:hidden}
    .tab-content.active{display:flex}
    .chatbot-messages{flex:1;overflow-y:auto;padding:15px;background:linear-gradient(180deg,#f8f9fa 0%,#fff 100%)}
    .welcome-message{text-align:center;padding:25px 15px}
    .welcome-avatar{width:70px;height:70px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 15px;font-size:1.8rem;color:#fff;animation:float 3s ease-in-out infinite}
    @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
    .welcome-message h3{margin:0 0 8px;color:#333;font-size:1.2rem}
    .welcome-message p{color:#666;margin:0 0 15px;font-size:.9rem}
    .capabilities{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
    .capability{background:linear-gradient(135deg,#667eea15 0%,#764ba215 100%);padding:8px 12px;border-radius:10px;font-size:.8rem;color:#667eea;display:flex;align-items:center;gap:6px}
    .chat-message{display:flex;gap:10px;margin-bottom:15px;animation:messageIn .3s ease}
    @keyframes messageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    .chat-message.user{flex-direction:row-reverse}
    .message-avatar{width:35px;height:35px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.85rem}
    .chat-message.bot .message-avatar{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}
    .chat-message.user .message-avatar{background:linear-gradient(135deg,#11998e,#38ef7d);color:#fff}
    .message-content{max-width:80%;padding:12px 15px;border-radius:15px;font-size:.9rem;line-height:1.5}
    .chat-message.bot .message-content{background:#fff;border:1px solid #e9ecef;border-radius:15px 15px 15px 4px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
    .chat-message.user .message-content{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border-radius:15px 15px 4px 15px}
    .message-content pre{background:#1e1e2e;color:#cdd6f4;padding:10px;border-radius:8px;overflow-x:auto;font-size:.8rem;margin:8px 0}
    .message-content code{background:rgba(102,126,234,0.1);padding:2px 5px;border-radius:4px;font-family:'Fira Code',monospace;font-size:.85em}
    .message-time{font-size:.65rem;color:#999;margin-top:4px}
    .suggested-prompts{padding:10px 12px;background:#fff;border-top:1px solid #e9ecef}
    .prompts-label{font-size:.7rem;color:#999;margin-bottom:6px;display:block}
    .prompts-scroll{display:flex;gap:6px;overflow-x:auto;padding-bottom:5px}
    .prompts-scroll button{flex-shrink:0;padding:6px 12px;border:1px solid #e9ecef;background:#fff;border-radius:15px;font-size:.75rem;cursor:pointer;transition:all .2s;white-space:nowrap}
    .prompts-scroll button:hover{background:#667eea;color:#fff;border-color:#667eea}
    .chatbot-input-area{padding:12px;background:#fff;border-top:1px solid #e9ecef}
    .chatbot-input{display:flex;gap:8px;align-items:flex-end}
    .chatbot-input textarea{flex:1;padding:10px 15px;border:2px solid #e9ecef;border-radius:20px;font-size:.9rem;resize:none;max-height:100px;font-family:inherit;transition:all .2s}
    .chatbot-input textarea:focus{outline:none;border-color:#667eea}
    .send-btn{width:45px;height:45px;border-radius:50%;border:none;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center}
    .send-btn:hover{transform:scale(1.1)}
    .send-btn:disabled{opacity:.5;cursor:not-allowed}
    .tools-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;padding:15px;overflow-y:auto}
    .tool-card{background:#fff;border:1px solid #e9ecef;border-radius:12px;padding:15px;cursor:pointer;transition:all .3s;text-align:center}
    .tool-card:hover{border-color:#667eea;transform:translateY(-2px);box-shadow:0 8px 25px rgba(102,126,234,0.15)}
    .tool-card i{font-size:1.5rem;color:#667eea;margin-bottom:8px}
    .tool-card span{display:block;font-weight:600;color:#333;font-size:.85rem}
    .history-list{padding:15px;overflow-y:auto}
    .empty-history{text-align:center;padding:30px;color:#999}
    .empty-history i{font-size:2.5rem;margin-bottom:10px;opacity:.5}
    .history-item{background:#fff;border:1px solid #e9ecef;border-radius:10px;padding:12px;margin-bottom:8px;cursor:pointer;transition:all .2s}
    .history-item:hover{border-color:#667eea}
    .typing-indicator{display:flex;gap:5px;padding:10px 15px}
    .typing-indicator span{width:10px;height:10px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:50%;animation:typing 1.4s infinite}
    .typing-indicator span:nth-child(2){animation-delay:.2s}
    .typing-indicator span:nth-child(3){animation-delay:.4s}
    @keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-10px)}}
    @media (max-width:480px){.chatbot-window{width:calc(100% - 20px);left:10px;bottom:100px;height:70vh}.chatbot-toggle{width:55px;height:55px;bottom:20px;left:20px}}
  `;
  document.head.appendChild(styles);
}

function toggleChatbot() {
  const win = document.getElementById('chatbot-window');
  const toggle = document.getElementById('chatbot-toggle');
  win.classList.toggle('open');
  toggle.classList.toggle('active');
  document.getElementById('notif-dot').style.display = 'none';
}

function minimizeChatbot() {
  document.getElementById('chatbot-window').classList.toggle('minimized');
  isMinimized = !isMinimized;
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));

  // Find the correct tab button by its onclick attribute or use first matching
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    if (btn.getAttribute('onclick')?.includes(tabName)) {
      btn.classList.add('active');
    }
  });

  document.getElementById('tab-' + tabName).classList.add('active');
}

function handleKeyDown(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
}

function handleNavigationCommand(message) {
  const lowerMsg = message.toLowerCase();
  const navMappings = {
    'الرئيسية': 'home', 'home': 'home', 'كورسات': 'courses', 'courses': 'courses',
    'غرف': 'rooms', 'rooms': 'rooms', 'صيد الثغرات': 'bugbounty', 'bug bounty': 'bugbounty',
    'أدوات': 'toolshub', 'tools': 'toolshub', 'لوحة التحكم': 'dashboard', 'dashboard': 'dashboard',
    'ctf': 'ctf', 'تحديات': 'ctf', 'ملاحظات': 'notes', 'notes': 'notes', 'اعدادات': 'settings', 'settings': 'settings'
  };

  if (lowerMsg.includes('خذني') || lowerMsg.includes('اذهب') || lowerMsg.includes('افتح') || lowerMsg.includes('go to') || lowerMsg.includes('open')) {
    for (const [key, page] of Object.entries(navMappings)) {
      if (lowerMsg.includes(key)) {
        window.location.hash = page;
        return `جاري الانتقال إلى ${key}... 🚀`;
      }
    }
  }
  return null;
}

function saveChatHistory() {
  if (chatHistory.length > 0) {
    localStorage.setItem('shadowhack_chat_history', JSON.stringify({ timestamp: Date.now(), messages: chatHistory.slice(-20) }));
    updateHistoryTab();
  }
}

function loadChatHistory() {
  const saved = localStorage.getItem('shadowhack_chat_history');
  if (saved) {
    const data = JSON.parse(saved);
    chatHistory = data.messages || [];
    updateHistoryTab();
  }
}

function updateHistoryTab() {
  const historyList = document.getElementById('history-list');
  const userMessages = chatHistory.filter(m => m.role === 'user');
  if (userMessages.length === 0) {
    historyList.innerHTML = '<div class="empty-history"><i class="fas fa-inbox"></i><p>لا توجد محادثات محفوظة</p></div>';
    return;
  }
  historyList.innerHTML = userMessages.slice(-5).map((msg, i) => '<div class="history-item" onclick="sendQuickMessage(\'' + msg.parts[0].text.replace(/'/g, "\\'").substring(0, 50) + '\')"><strong>رسالة ' + (i + 1) + '</strong><p style="font-size:.8rem;color:#666;margin:0">' + msg.parts[0].text.substring(0, 40) + '...</p></div>').join('');
}

function exportChat() {
  if (chatHistory.length === 0) { addMessageToUI('❌ لا توجد محادثات', 'bot'); return; }
  let text = '# ShadowHack AI Chat\n\n';
  chatHistory.forEach(msg => { text += (msg.role === 'user' ? '👤 المستخدم' : '🤖 AI') + ':\n' + msg.parts[0].text + '\n\n---\n\n'; });
  const blob = new Blob([text], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'shadowhack-chat.md';
  a.click();
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  document.getElementById('sound-btn').innerHTML = '<i class="fas fa-volume-' + (soundEnabled ? 'up' : 'mute') + '"></i>';
}

function playNotificationSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = 800;
    gain.gain.value = 0.1;
    osc.start();
    osc.stop(ctx.currentTime + 0.1);
  } catch (e) { }
}

function generateReportTemplate() { switchTab('chat'); sendQuickMessage('ساعدني في كتابة تقرير Bug Bounty احترافي'); }
function explainVulnerability() { switchTab('chat'); sendQuickMessage('اشرح لي ثغرة SQL Injection بالتفصيل'); }
function generatePayload() { switchTab('chat'); sendQuickMessage('اعطني payloads لاختبار XSS'); }
function ctfHelper() { switchTab('chat'); sendQuickMessage('كيف أحل تحديات CTF؟'); }
function toolsGuide() { switchTab('chat'); sendQuickMessage('ما هي أهم أدوات اختبار الاختراق؟'); }
function methodologyGuide() { switchTab('chat'); sendQuickMessage('ما هي منهجية اختبار الاختراق؟'); }

document.addEventListener('DOMContentLoaded', function () {
  setTimeout(initChatbot, 800);
});
