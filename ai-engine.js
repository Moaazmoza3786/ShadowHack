/* ============================================================
   HEURISTIC AI ENGINE v1.0
   Shared Intelligence Layer for Job Simulations.
   Analyses user intent against scenario knowledge bases.
   ============================================================ */

class HeuristicEngine {
    constructor() {
        this.context = {
            role: null,
            scenario: null,
            history: []
        };
    }

    setContext(role, scenario) {
        this.context.role = role;
        this.context.scenario = scenario;
        this.context.history = []; // Reset conversation history
    }

    /**
     * Main analysis entry point
     * @param {string} query User's input or selected action
     * @param {string} type 'text' (chat) or 'action' (button click)
     */
    async analyze(query, type = 'text') {
        const scenario = this.context.scenario;
        if (!scenario || !scenario.aiKnowledge) {
            return this.fallbackResponse();
        }

        // 1. Check Anti-Patterns (Immediate Feedback on mistakes)
        const antiPattern = this.detectAntiPattern(query, scenario.aiKnowledge.antiPatterns);
        if (antiPattern) {
            return {
                type: 'warning',
                confidence: 90,
                message: antiPattern,
                tone: 'caution'
            };
        }

        // 2. Keyword Matching (Relevance Check)
        const relevance = this.calculateRelevance(query, scenario.aiKnowledge.keywords);

        // 3. Construct Response based on Scenario Context
        if (relevance > 0.3) {
            return this.generateInsight(query, scenario);
        } else {
            return {
                type: 'info',
                confidence: 20,
                message: "This doesn't seem relevant to the current incident. Let's focus on the evidence we have.",
                tone: 'neutral'
            };
        }
    }

    detectAntiPattern(query, antiPatterns) {
        if (!antiPatterns) return null;
        const lowerQuery = query.toLowerCase();

        for (const [trigger, warning] of Object.entries(antiPatterns)) {
            if (lowerQuery.includes(trigger.toLowerCase())) {
                return warning;
            }
        }
        return null; // No anti-pattern found
    }

    calculateRelevance(query, keywords) {
        if (!keywords || keywords.length === 0) return 1; // Assume relevant if no keywords defined

        const lowerQuery = query.toLowerCase();
        let matches = 0;

        keywords.forEach(kw => {
            if (lowerQuery.includes(kw.toLowerCase())) matches++;
        });

        return matches / keywords.length; // Normalized score 0-1
    }

    generateInsight(query, scenario) {
        // In a real LLM, this would generate text. 
        // Here we select the most relevant hint or insight from the knowledge base.

        // Simulated "Thinking"
        const hints = scenario.aiKnowledge.hints || [];
        const randomHint = hints[Math.floor(Math.random() * hints.length)];

        return {
            type: 'insight',
            confidence: 85,
            message: `Based on your query "${query}", I suggest: ${randomHint}`,
            tone: 'helpful'
        };
    }

    fallbackResponse() {
        return {
            type: 'neutral',
            confidence: 0,
            message: "I'm standing by for your instructions. Review the ticket details.",
            tone: 'neutral'
        };
    }
}

// Export global instance
window.HeuristicEngine = new HeuristicEngine();
