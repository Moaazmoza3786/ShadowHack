
const express = require('express');
const axios = require('axios');
const MemoryService = require('../services/memory');
const router = express.Router();

// AI Service URL (Docker internal network or local)
const OLLAMA_URL = process.env.OLLAMA_URL || "http://antigravity_llm:11434/api/generate";

/**
 * MOCK DATABASE ACCESS
 * In a real scenario, this would fetch from MongoDB/SQL
 */
const getLabWriteup = async (labId) => {
    const mockLabs = {
        "lab01": "The vulnerability is a simple SQL Injection on the login form. The payload is ' OR 1=1 --. The flag is FLAG{sql_basics}.",
        "lab02": "This lab requires exploiting a Path Traversal. Use ../../../etc/passwd to read the flag in /var/www/flag.txt.",
        "pwn_01": "Buffer overflow in the 'name' field. Overwrite EIP with the address of the win() function at 0x080484b6."
    };
    return mockLabs[labId] || "Generic security lab about identification and exploitation.";
};

// @route   POST /api/ai/hint
// @desc    Get a vague AI hint for a specific lab
router.post('/hint', async (req, res) => {
    const { labId, userQuestion } = req.body;

    if (!labId) {
        return res.status(400).json({ error: "labId is required." });
    }

    try {
        // 1. Fetch the solution/writeup for context
        const solution = await getLabWriteup(labId);

        // 2. System Prompt: Programming the AI Mentor "Gravity"
        const systemPrompt = `
            You are 'Gravity', the expert CTF Mentor for the BreachLabs Platform.
            Your goal is to guide students WITHOUT giving the answer.
            
            Current Lab Solution: ${solution}
            
            Rules:
            - Never reveal the flag or the exact final payload.
            - Be vague but encouraging.
            - Speak technically.
            - If the user is way off, correct their direction.
        `;

        // 3. Request to Ollama
        const response = await axios.post(OLLAMA_URL, {
            model: "llama3",
            prompt: `${systemPrompt}\nUser Question: ${userQuestion || "I'm stuck, help me."}\nGravity's Hint:`,
            stream: false
        });

        res.json({
            labId,
            hint: response.data.response,
            model: "llama3"
        });

    } catch (error) {
        console.error("AI Middleware Error:", error.message);
        res.status(500).json({
            error: "Failed to connect to AI Brain.",
            details: error.message
        });
    }
});

// @route   POST /api/ai/ask
// @desc    General security chat with context and multi-turn memory
router.post('/ask', async (req, res) => {
    const { userMessage, context, stream, sessionId } = req.body;
    const sId = sessionId || 'default';

    // 1. Get history and add current user message
    const history = MemoryService.getHistory(sId);
    MemoryService.addMessage(sId, 'user', userMessage);

    // 2. Construct prompt with history
    const historyText = history.map(m => `${m.role === 'user' ? 'User' : 'Gravity'}: ${m.content}`).join('\n');

    const systemPrompt = `
        You are 'Gravity', the expert AI Security Mentor for BreachLabs Academy.
        Context: ${JSON.stringify(context)}
        Rules: Be technical, helpful, and concise. Use markdown.
        
        Recent Conversation:
        ${historyText}
    `;

    try {
        if (stream) {
            // Set headers for SSE
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');

            const response = await axios.post(OLLAMA_URL, {
                model: "llama3",
                prompt: `${systemPrompt}\nUser: ${userMessage}\nGravity:`,
                stream: true
            }, { responseType: 'stream' });

            let fullAssistantResponse = '';
            response.data.on('data', chunk => {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const json = JSON.parse(line);
                        if (json.response) {
                            res.write(json.response);
                            fullAssistantResponse += json.response;
                        }
                        if (json.done) {
                            // Add assistant response to memory when done
                            MemoryService.addMessage(sId, 'assistant', fullAssistantResponse);
                            res.end();
                        }
                    } catch (e) {
                        // Not a full JSON yet
                    }
                }
            });
        } else {
            const response = await axios.post(OLLAMA_URL, {
                model: "llama3",
                prompt: `${systemPrompt}\nUser: ${userMessage}\nGravity:`,
                stream: false
            });
            const reply = response.data.response;
            MemoryService.addMessage(sId, 'assistant', reply);
            res.json({ reply });
        }
    } catch (error) {
        console.error("AI Ask Error:", error.message);
        res.status(500).json({ error: "Brain connection failed." });
    }
});

// @route   POST /api/ai/clear
// @desc    Clear session memory
router.post('/clear', (req, res) => {
    const { sessionId } = req.body;
    if (sessionId) {
        MemoryService.clear(sessionId);
    }
    res.json({ success: true });
});

module.exports = router;
