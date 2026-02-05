
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const aiRoutes = require('./routes/ai');

const app = express();
const PORT = process.env.PORT || 5005;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/ai', aiRoutes);

// Health Check
app.get('/health', (req, res) => {
    res.json({ status: 'online', engine: 'Ollama-Llama3', timestamp: new Date() });
});

app.listen(PORT, () => {
    console.log(`🚀 Gravity AI Middleware running on http://localhost:${PORT}`);
    console.log(`🔗 Targeting Ollama at: ${process.env.OLLAMA_URL || "http://antigravity_llm:11434"}`);
});
