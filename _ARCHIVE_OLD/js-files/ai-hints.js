// ==================== AI HINT SYSTEM ====================

const aiHints = {
    state: {
        isOpen: false,
        currentContext: 'global', // 'global', 'recon', 'challenge-id', etc.
        messageHistory: []
    },

    init() {
        // this.createUI(); // Disabled to prevent duplicate chatbot
        // this.attachEvents(); // Disabled - method doesn't exist
        // Check context on page load
        this.updateContext(currentPage);
    },

    updateContext(contextId) {
        this.state.currentContext = hintsData[contextId] ? contextId : 'global';
        // If it's a challenge page, we might want to pass the specific challenge ID
        // This logic can be enhanced based on how challenges are loaded
    },

    getHint(level = 1) {
        const contextHints = hintsData[this.state.currentContext] || hintsData['global'];

        // Simple logic: get a random hint or specific level for challenges
        let hint;
        if (Array.isArray(contextHints)) {
            // It's a list of hints (page context)
            hint = contextHints[Math.floor(Math.random() * contextHints.length)];
        } else {
            // It's structured (challenge context not fully implemented in data structure above for all cases, assuming array for simplicity or specific structure)
            // For now, let's assume the array structure in hints-data.js
            hint = contextHints[Math.floor(Math.random() * contextHints.length)];
        }

        if (!hint) return "I'm analyzing the current page... No specific hints yet, but keep trying!";

        // Check cost
        if (hint.cost > 0) {
            if (confirm(`This hint costs ${hint.cost} XP. Do you want to proceed?`)) {
                // Deduct XP (assuming gamification is global)
                if (typeof gamification !== 'undefined') {
                    gamification.addXP(-hint.cost, 'Used AI Hint');
                }
            } else {
                return "Hint cancelled.";
            }
        }

        return hint.text;
    },

    createUI() {
        // Floating Button
        const btn = document.createElement('button');
        btn.id = 'ai-hint-btn';
        btn.className = 'btn btn-primary rounded-circle shadow-lg';
        btn.style.cssText = 'position: fixed; bottom: 30px; right: 30px; width: 60px; height: 60px; z-index: 1000; font-size: 24px;';
        btn.innerHTML = '<i class="fa-solid fa-robot"></i>';
        btn.onclick = () => this.toggleChat();
        document.body.appendChild(btn);

        // Chat Window
        const chat = document.createElement('div');
        chat.id = 'ai-chat-window';
        chat.className = 'card shadow-lg';
        chat.style.cssText = 'position: fixed; bottom: 100px; right: 30px; width: 350px; height: 500px; z-index: 1000; display: none; flex-direction: column;';
        chat.innerHTML = `
      <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="fa-solid fa-robot me-2"></i>AI Assistant</h5>
        <button type="button" class="btn-close btn-close-white" onclick="aiHints.toggleChat()"></button>
      </div>
      <div class="card-body" id="ai-chat-body" style="overflow-y: auto; flex-grow: 1; background: #f8f9fa;">
        <div class="d-flex mb-3">
          <div class="bg-primary text-white p-3 rounded-3" style="max-width: 80%;">
            Hello! I'm your AI assistant. I can help you with hints and tips. Just ask! 🤖
          </div>
        </div>
      </div>
      <div class="card-footer bg-white">
        <div class="d-grid gap-2">
          <button class="btn btn-outline-primary btn-sm" onclick="aiHints.ask('general')">💡 General Tip</button>
          <button class="btn btn-outline-warning btn-sm" onclick="aiHints.ask('specific')">🔑 Specific Hint (Costs XP)</button>
          <button class="btn btn-outline-danger btn-sm" onclick="aiHints.ask('solution')">🔓 Show Solution (High Cost)</button>
        </div>
      </div>
    `;
        document.body.appendChild(chat);
    },

    toggleChat() {
        const chat = document.getElementById('ai-chat-window');
        this.state.isOpen = !this.state.isOpen;
        chat.style.display = this.state.isOpen ? 'flex' : 'none';
        if (this.state.isOpen) {
            this.updateContext(currentPage); // Update context when opening
        }
    },

    ask(type) {
        const chatBody = document.getElementById('ai-chat-body');

        // User message
        const userMsg = document.createElement('div');
        userMsg.className = 'd-flex justify-content-end mb-3';
        userMsg.innerHTML = `<div class="bg-light border p-3 rounded-3" style="max-width: 80%;">I need a ${type} hint.</div>`;
        chatBody.appendChild(userMsg);

        // AI thinking
        const thinkingMsg = document.createElement('div');
        thinkingMsg.className = 'd-flex mb-3';
        thinkingMsg.innerHTML = `<div class="bg-primary text-white p-3 rounded-3" style="max-width: 80%;"><i class="fa-solid fa-circle-notch fa-spin"></i> Thinking...</div>`;
        chatBody.appendChild(thinkingMsg);
        chatBody.scrollTop = chatBody.scrollHeight;

        // Simulate delay
        setTimeout(() => {
            thinkingMsg.remove();

            // Get hint logic
            let responseText = "";
            const contextHints = hintsData[this.state.currentContext] || hintsData['global'];

            // Find appropriate hint based on type (simplified logic)
            let hint;
            if (type === 'general') {
                hint = contextHints.find(h => h.cost === 0) || contextHints[0];
            } else if (type === 'specific') {
                hint = contextHints.find(h => h.cost > 0 && h.cost <= 20) || contextHints[1] || contextHints[0];
            } else {
                hint = contextHints.find(h => h.cost > 20) || contextHints[contextHints.length - 1];
            }

            if (hint) {
                // Check cost
                if (hint.cost > 0) {
                    if (typeof gamification !== 'undefined') {
                        gamification.addXP(-hint.cost, `Used ${type} hint`);
                        responseText = `(Spent ${hint.cost} XP) <br> ${hint.text}`;
                    } else {
                        responseText = hint.text;
                    }
                } else {
                    responseText = hint.text;
                }
            } else {
                responseText = "I don't have a specific hint for this right now. Keep exploring!";
            }

            const aiMsg = document.createElement('div');
            aiMsg.className = 'd-flex mb-3';
            aiMsg.innerHTML = `<div class="bg-primary text-white p-3 rounded-3" style="max-width: 80%;">${responseText}</div>`;
            chatBody.appendChild(aiMsg);
            chatBody.scrollTop = chatBody.scrollHeight;

        }, 1000);
    }
};

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Wait a bit for other scripts to load
    setTimeout(() => aiHints.init(), 1000);
});
