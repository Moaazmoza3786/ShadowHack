/**
 * AI Service for ShadowHack Study Hub
 * Integrates with OpenRouter API using the MiniMax M2.5 model
 */

const OPENROUTER_API_KEY = import.meta.env.VITE_OPENROUTER_API_KEY;
const MODEL_ID = "minimax/minimax-m2.5:free";
const API_URL = "https://openrouter.ai/api/v1/chat/completions";

export const aiService = {
    /**
     * Sends a message to the AI and returns the response
     * @param {string} prompt - The user's input
     * @param {string} language - 'ar' or 'en' for context
     * @returns {Promise<string>} - The AI response
     */
    async getChatResponse(prompt, language = 'en') {
        if (!OPENROUTER_API_KEY) {
            console.error("OpenRouter API Key is missing!");
            return language === 'ar' 
                ? "خطأ: مفتاح API غير موجود. يرجى تكوين الإعدادات." 
                : "Error: API Key is missing. Please configure settings.";
        }

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
                    "HTTP-Referer": window.location.origin, // Required by OpenRouter
                    "X-Title": "ShadowHack Study Hub", // Optional but good practice
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    model: MODEL_ID,
                    messages: [
                        {
                            role: "system",
                            content: language === 'ar'
                                ? "أنت مساعد أمني ذكي في ShadowHack، خبير في الأمن السيبراني واختبار الاختراق. ساعد الطلاب في تعلم مفاهيم الأمن السيبراني وحل التحديات بأسلوب احترافي ومشجع."
                                : "You are a Security AI Assistant at ShadowHack, an expert in cybersecurity and penetration testing. Help students learn cybersecurity concepts and solve challenges in a professional and encouraging manner."
                        },
                        {
                            role: "user",
                            content: prompt
                        }
                    ]
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error?.message || "Failed to fetch from AI Service");
            }

            const data = await response.json();
            return data.choices[0].message.content;
        } catch (error) {
            console.error("AI Service Error:", error);
            return language === 'ar'
                ? "عذراً، حدث خطأ أثناء الاتصال بالنواة العصبية. يرجى المحاولة لاحقاً."
                : "Sorry, an error occurred while connecting to the neural core. Please try again later.";
        }
    }
};
