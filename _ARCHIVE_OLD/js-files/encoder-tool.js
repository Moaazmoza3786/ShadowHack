/* ==================== CYBER CHEF STATION v1.0 🍳 ==================== */
/* Advanced Smart Encoder/Decoder with AI Analysis & Recipe Pipelines */

const CyberChefStation = {
  isOpen: false,
  history: [],
  pipeline: [], // Active recipe pipeline

  // === CORE LOGIC ===

  // 1. Smart Detection System
  detectType(input) {
    if (!input) return null;
    const trimmed = input.trim();

    // JWT
    if (/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(trimmed)) return 'JWT';

    // ASP.NET ViewState (Starts with /wEP...)
    if (trimmed.startsWith('/wEP')) return 'ViewState';

    // Hex (Simple heuristic: even length, hex chars)
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length > 4) return 'Hex';

    // Base64 (Basic heuristic)
    if (/^[A-Za-z0-9+/]*={0,2}$/.test(trimmed) && trimmed.length > 8) return 'Base64';

    // URL Encoded
    if (trimmed.includes('%') && trimmed.match(/%[0-9A-Fa-f]{2}/)) return 'URL';

    return 'Raw';
  },

  // 2. AI Explainer (Simulated)
  async explainData(input) {
    const type = this.detectType(input);
    return new Promise(resolve => {
      setTimeout(() => {
        let explanation = "";
        switch (type) {
          case 'JWT':
            explanation = "This is a **JSON Web Token (JWT)**. It consists of three parts: Header, Payload, and Signature. It is commonly used for stateless authentication (Bearer tokens).";
            break;
          case 'ViewState':
            explanation = "This appears to be an **ASP.NET ViewState**. It contains the state of UI controls on a webpage. If not encrypted (MAC enabled only), it can be decoded to reveal sensitive server-side structure.";
            break;
          case 'Hex':
            explanation = "This is a **Hexadecimal String**. It's a raw byte representation. Common in binary files, encryption keys, or shellcode.";
            break;
          case 'Base64':
            explanation = "This is **Base64 Encoded Data**. It's used to represent binary data in an ASCII string format. decode it to see the underlying content.";
            break;
          default:
            explanation = "This looks like raw text or an unknown format. Try using the 'Magic' button to auto-detect nested encodings.";
        }
        resolve({ type, explanation });
      }, 800);
    });
  },

  // 3. Operations Library
  ops: {
    'To Base64': (i) => btoa(i),
    'From Base64': (i) => atob(i),
    'To Hex': (i) => Array.from(i).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
    'From Hex': (i) => i.replace(/\s/g, '').match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join(''),
    'URL Encode': (i) => encodeURIComponent(i),
    'URL Decode': (i) => decodeURIComponent(i),
    'ROT13': (i) => i.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)),
    'Reverse': (i) => i.split('').reverse().join(''),
    'XOR 42': (i) => Array.from(i).map(c => String.fromCharCode(c.charCodeAt(0) ^ 42)).join('')
  },

  // === UI RENDERING ===

  open() {
    this.isOpen = true;
    this.render();
  },

  close() {
    this.isOpen = false;
    document.getElementById('cyber-chef-modal')?.remove();
  },

  render() {
    const existing = document.getElementById('cyber-chef-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'cyber-chef-modal';
    modal.innerHTML = `
            <style>
                #cyber-chef-modal {
                    position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 10000;
                    display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px);
                    font-family: 'JetBrains Mono', monospace;
                }
                .chef-container {
                    width: 90%; max-width: 1200px; height: 85vh;
                    background: #1e1e2e; border: 1px solid #4f46e5; border-radius: 16px;
                    display: grid; grid-template-columns: 250px 1fr 300px; grid-template-rows: 60px 1fr;
                    overflow: hidden; box-shadow: 0 0 50px rgba(79, 70, 229, 0.2);
                }
                /* Header */
                .chef-header {
                    grid-column: 1 / -1; background: #2d2d3e; border-bottom: 1px solid #43435c;
                    display: flex; align-items: center; justify-content: space-between; padding: 0 25px;
                }
                .chef-title { font-size: 1.2rem; font-weight: 700; color: #fff; display: flex; gap: 10px; align-items: center; }
                .chef-title i { color: #facc15; }
                
                /* Sidebar: Operations */
                .chef-sidebar { background: #181824; border-right: 1px solid #43435c; padding: 15px; overflow-y: auto; }
                .op-category { color: #818cf8; font-weight: bold; margin: 15px 0 5px; font-size: 0.8rem; text-transform: uppercase; }
                .op-btn {
                    display: block; width: 100%; text-align: left; padding: 8px 12px;
                    margin-bottom: 5px; background: #2d2d3e; color: #cbd5e1; border: none; border-radius: 6px;
                    cursor: pointer; transition: 0.2s; font-size: 0.9rem;
                }
                .op-btn:hover { background: #4f46e5; color: #fff; transform: translateX(5px); }
                
                /* Main: Recipe & Output */
                .chef-main { display: flex; flex-direction: column; padding: 20px; gap: 20px; background: #1e1e2e; }
                .recipe-area { background: #2d2d3e; border-radius: 12px; padding: 15px; min-height: 100px; border: 1px dashed #6366f1; }
                .io-area { flex: 1; display: grid; grid-template-rows: 1fr 1fr; gap: 20px; }
                .io-box { display: flex; flex-direction: column; gap: 10px; position: relative; }
                .io-header { display: flex; justify-content: space-between; color: #94a3b8; font-size: 0.85rem; font-weight: bold; }
                textarea.chef-text {
                    flex: 1; background: #13131c; border: 1px solid #43435c; border-radius: 8px;
                    color: #a5b4fc; padding: 15px; font-family: inherit; resize: none;
                }
                textarea.chef-text:focus { outline: none; border-color: #6366f1; }
                
                /* Right: Inspector */
                .chef-inspector { background: #181824; border-left: 1px solid #43435c; padding: 20px; overflow-y: auto; }
                .inspector-card { background: #2d2d3e; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
                .inspector-title { color: #facc15; font-weight: bold; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
                
                /* specialized decoders */
                .jwt-part { word-break: break-all; margin-bottom: 5px; padding: 5px; border-radius: 4px; font-size: 0.8rem; }
                .jwt-header { color: #fb7185; background: rgba(251, 113, 133, 0.1); }
                .jwt-payload { color: #c084fc; background: rgba(192, 132, 252, 0.1); }
                .jwt-sig { color: #60a5fa; background: rgba(96, 165, 250, 0.1); }

                .badge { padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; font-weight: bold; }
                .badge-jwt { background: #ec4899; color: black; }
                .badge-viewstate { background: #22c55e; color: black; }

                /* Magic Wand Animation */
                .magic-wand { position: absolute; right: 10px; top: 35px; color: #facc15; cursor: pointer; animation: float 2s infinite; }
                @keyframes float { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }

            </style>

            <div class="chef-container">
                <!-- HEADER -->
                <div class="chef-header">
                    <div class="chef-title"><i class="fas fa-cookie-bite"></i> Cyber Chef Station</div>
                    <div>
                        <button onclick="CyberChefStation.close()" style="background:none; border:none; color:#fff; cursor:pointer;"><i class="fas fa-times fa-lg"></i></button>
                    </div>
                </div>

                <!-- OPERATIONS -->
                <div class="chef-sidebar">
                    <div class="op-category">Data Format</div>
                    <button class="op-btn" onclick="CyberChefStation.addOp('To Base64')">To Base64</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('From Base64')">From Base64</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('To Hex')">To Hex</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('From Hex')">From Hex</button>
                    
                    <div class="op-category">Web</div>
                    <button class="op-btn" onclick="CyberChefStation.addOp('URL Encode')">URL Encode</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('URL Decode')">URL Decode</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('JWT Decode')">JWT Decode</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('ViewState Parse')">ViewState Parse</button>

                    <div class="op-category">Crypto / Lo-Fi</div>
                    <button class="op-btn" onclick="CyberChefStation.addOp('ROT13')">ROT13</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('XOR 42')">XOR (Key: 42)</button>
                    <button class="op-btn" onclick="CyberChefStation.addOp('Reverse')">Reverse String</button>
                </div>

                <!-- MAIN -->
                <div class="chef-main">
                    <!-- PIPELINE -->
                    <div class="recipe-area" id="recipe-list">
                        <span style="color:#64748b; font-size:0.9rem; font-style:italic;">Draft your recipe... Select operations from the left.</span>
                    </div>

                    <!-- IO -->
                    <div class="io-area">
                        <div class="io-box">
                            <div class="io-header">
                                <span><i class="fas fa-sign-in-alt"></i> INPUT</span>
                                <button onclick="CyberChefStation.clear()" style="background:none; border:none; color:#ef4444; cursor:pointer;">Clear</button>
                            </div>
                            <textarea id="chef-input" class="chef-text" placeholder="Paste data here..." oninput="CyberChefStation.bake()"></textarea>
                            <div class="magic-wand" onclick="CyberChefStation.autoMagic()" title="AI Auto-Detect"><i class="fas fa-magic"></i></div>
                        </div>
                        <div class="io-box">
                            <div class="io-header">
                                <span><i class="fas fa-sign-out-alt"></i> OUTPUT</span>
                                <button onclick="CyberChefStation.copy()" style="background:none; border:none; color:#4ade80; cursor:pointer;">Copy</button>
                            </div>
                            <textarea id="chef-output" class="chef-text" readonly placeholder="Result..."></textarea>
                        </div>
                    </div>
                </div>

                <!-- INSPECTOR -->
                <div class="chef-inspector" id="chef-inspector">
                    <div class="inspector-card">
                        <div class="inspector-title"><i class="fas fa-robot"></i> AI Inspector</div>
                        <div id="ai-explanation" style="color:#d1d5db; font-size:0.9rem;">Type something to get AI insights...</div>
                    </div>
                    <!-- Dynamic Specialized Views (JWT, etc) will go here -->
                </div>
            </div>
        `;
    document.body.appendChild(modal);
  },

  // === LOGIC ===

  addOp(opName) {
    // specialized decoders are handled separately or as ops
    if (opName === 'JWT Decode' || opName === 'ViewState Parse') {
      this.runSpecial(opName);
      return;
    }

    this.pipeline.push(opName);
    this.renderRecipe();
    this.bake();
  },

  removeOp(index) {
    this.pipeline.splice(index, 1);
    this.renderRecipe();
    this.bake();
  },

  renderRecipe() {
    const div = document.getElementById('recipe-list');
    if (this.pipeline.length === 0) {
      div.innerHTML = '<span style="color:#64748b; font-size:0.9rem; font-style:italic;">Draft your recipe... Select operations from the left.</span>';
      return;
    }

    div.innerHTML = this.pipeline.map((op, i) => `
            <span style="display:inline-block; background:#4f46e5; color:#fff; padding:5px 12px; border-radius:20px; font-size:0.85rem; margin-right:5px; margin-bottom:5px;">
                ${op} <i class="fas fa-times" style="cursor:pointer; margin-left:5px;" onclick="CyberChefStation.removeOp(${i})"></i>
            </span>
        `).join('');
  },

  bake() {
    let data = document.getElementById('chef-input').value;

    // 1. Run Pipeline
    try {
      for (const op of this.pipeline) {
        if (this.ops[op]) {
          data = this.ops[op](data);
        }
      }
    } catch (e) {
      data = `[Error in ${op}]: ${e.message}`;
    }

    document.getElementById('chef-output').value = data;

    // 2. Trigger AI Explain (Debounced in production, simple here)
    this.updateAI(data);
  },

  async updateAI(data) {
    const aiDiv = document.getElementById('ai-explanation');
    const inspector = document.getElementById('chef-inspector');

    // Clear previous special views
    const existingDetails = document.querySelectorAll('.dynamic-detail');
    existingDetails.forEach(e => e.remove());

    // Basic AI Text
    if (!data) {
      aiDiv.innerHTML = "Waiting for data...";
      return;
    }

    aiDiv.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Analyzing...';

    const insights = await this.explainData(data);
    aiDiv.innerHTML = insights.explanation;

    // Special views based on type detection
    if (insights.type === 'JWT') {
      this.renderJWTView(data);
    } else if (insights.type === 'ViewState') {
      this.renderViewStateView(data);
    }
  },

  // Specialized Decoders Logic

  runSpecial(op) {
    // Setup initial input for special cases
    const input = document.getElementById('chef-input').value;
    if (!input) return;

    if (op === 'JWT Decode') {
      // Just trigger the view, no need to transform text in pipeline if we just want to inspect
      this.renderJWTView(input);
    }
  },

  renderJWTView(token) {
    const inspector = document.getElementById('chef-inspector');
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return;

      const header = JSON.stringify(JSON.parse(atob(parts[0])), null, 2);
      const payload = JSON.stringify(JSON.parse(atob(parts[1])), null, 2);

      const div = document.createElement('div');
      div.className = 'inspector-card dynamic-detail';
      div.innerHTML = `
                <div class="inspector-title"><span class="badge badge-jwt">JWT</span> Token Breakdown</div>
                <div class="jwt-part jwt-header">${header}</div>
                <div class="jwt-part jwt-payload">${payload}</div>
                <div class="jwt-part jwt-sig">Signature: ${parts[2].substring(0, 10)}...</div>
            `;
      inspector.appendChild(div);
    } catch (e) { console.log('Not a valid JWT for view'); }
  },

  renderViewStateView(vs) {
    const inspector = document.getElementById('chef-inspector');
    const div = document.createElement('div');
    div.className = 'inspector-card dynamic-detail';
    div.innerHTML = `
            <div class="inspector-title"><span class="badge badge-viewstate">ASP.NET</span> ViewState</div>
            <div style="font-size:0.8rem; color:#cbd5e1; word-break:break-all;">
                <strong>Decoded Preview:</strong><br>
                ${atob(vs).substring(0, 200).replace(/[^\x20-\x7E]/g, '.')}...
            </div>
            <div style="margin-top:10px; font-size:0.75rem; color:#ef4444;">
                <i class="fas fa-lock"></i> Encryption: Likely AES (if MAC validation enabled).
            </div>
        `;
    inspector.appendChild(div);
  },

  autoMagic() {
    const input = document.getElementById('chef-input').value;
    const type = this.detectType(input);

    // Auto-suggest operations
    if (type === 'Base64') {
      this.addOp('From Base64');
    } else if (type === 'URL') {
      this.addOp('URL Decode');
    } else if (type === 'Hex') {
      this.addOp('From Hex');
    } else {
      alert(`AI Suggestion: Detected format is '${type}'. No specific decoding pipeline required or available.`);
    }
  },

  clear() {
    document.getElementById('chef-input').value = '';
    this.pipeline = [];
    this.renderRecipe();
    this.bake();
  },

  copy() {
    navigator.clipboard.writeText(document.getElementById('chef-output').value);
    alert('Copied output!');
  }
};

// Global Entry
window.openEncoderTool = () => CyberChefStation.open();

// App.js Router Compatibility
window.pageEncoderTool = () => {
  // Determine if we should auto-open (UX choice: yes, if navigating to the page)
  setTimeout(() => CyberChefStation.open(), 100);

  return `
        <div style="height:80vh; display:flex; flex-direction:column; align-items:center; justify-content:center; color:#fff;">
            <div style="font-size:3rem; margin-bottom:20px;">🍳</div>
            <h2>Cyber Chef Station</h2>
            <p style="color:#94a3b8; margin-bottom:30px;">Advanced Encoding & Analysis Pipeline</p>
            <button onclick="CyberChefStation.open()" 
                style="background:#4f46e5; color:white; border:none; padding:12px 24px; border-radius:8px; font-weight:bold; cursor:pointer; font-size:1.1rem; box-shadow:0 0 20px rgba(79, 70, 229, 0.4);">
                <i class="fas fa-external-link-alt"></i> Open Station
            </button>
            <p style="margin-top:20px; font-size:0.9rem; opacity:0.7;">(The station opens in an overlay)</p>
        </div>
    `;
};
