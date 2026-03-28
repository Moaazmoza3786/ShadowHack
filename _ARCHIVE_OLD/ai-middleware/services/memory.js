
const memory = new Map();

/**
 * Memory Service for Gravity AI
 * Stores conversation history by sessionId
 */
const MemoryService = {
    getHistory(sessionId) {
        if (!memory.has(sessionId)) {
            memory.set(sessionId, []);
        }
        return memory.get(sessionId);
    },

    addMessage(sessionId, role, content) {
        const history = this.getHistory(sessionId);
        history.push({ role, content });

        // Limit history to last 10 messages to save tokens/context window
        if (history.length > 10) {
            history.shift();
        }
    },

    clear(sessionId) {
        memory.delete(sessionId);
    }
};

module.exports = MemoryService;
