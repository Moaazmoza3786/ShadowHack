import React, { useState, useRef, useEffect } from 'react';
import { useAppContext } from '../context/AppContext';
import { Bot, X, Send, Link as LinkIcon, Code, BookOpen, ShieldAlert, Search, Crown, Bug, Sparkles, HelpCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useMissionSystem } from '../hooks/useMissionSystem';

const AIAssistant = () => {
    const { t, language } = useAppContext();
    const [isOpen, setIsOpen] = useState(false);
    const [input, setInput] = useState('');
    const [messages, setMessages] = useState([
        { role: 'assistant', content: language === 'ar' ? 'مرحباً! أنا مساعدك الأمني الذكي. كيف يمكنني مساعدتك اليوم؟' : 'Hello! I am your AI Security Assistant. How can I help you today?' }
    ]);
    const [isLoading, setIsLoading] = useState(false);
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages]);

    const quickActions = [
        { label: t('تحليل URL', 'Analyze URL'), icon: LinkIcon, prompt: 'Analyze this URL for vulnerabilities: ' },
        { label: t('توليد Payload', 'Gen Payload'), icon: Code, prompt: 'Generate a payload for: ' },
        { label: t('شرح ثغرة', 'Explain Vuln'), icon: BookOpen, prompt: 'Explain this vulnerability: ' },
        { label: t('تخطي WAF', 'Bypass WAF'), icon: ShieldAlert, prompt: 'How to bypass WAF for: ' },
    ];

    const handleSend = async (text = input) => {
        if (!text.trim()) return;

        const newMessages = [...messages, { role: 'user', content: text }];
        setMessages(newMessages);
        setInput('');
        setIsLoading(true);

        try {
            // Context-aware responses based on mission
            let response = '';
            const activeMission = state.mission.active ? state.mission.id : null;

            if (text.toLowerCase().includes('hint') && activeMission) {
                response = language === 'ar'
                    ? `تلميح لمهمة ${activeMission}: حاول استخدام nmap لفحص المنافذ المفتوحة أولاً.`
                    : `Hint for mission ${activeMission}: Try using 'nmap' to scan for open ports first.`;
            } else {
                // Simulated AI Response for now - can be connected to real backend
                response = language === 'ar'
                    ? `لقد استلمت طلبك بخصوص "${text}". جاري تحليل البيانات الأمنية...`
                    : `Received your request regarding "${text}". Analyzing security data...`;
            }

            setTimeout(() => {
                setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: response
                }]);
                setIsLoading(false);
            }, 1000);
        } catch (error) {
            setMessages(prev => [...prev, { role: 'assistant', content: 'Connection to Brain-Core failed.' }]);
            setIsLoading(false);
        }
    };

    return (
        <div className="fixed bottom-6 right-6 z-[100] flex flex-col items-end">
            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ opacity: 0, y: 20, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 20, scale: 0.95 }}
                        className="mb-4 w-[400px] max-h-[600px] bg-dark-800 border border-primary-500/30 rounded-3xl overflow-hidden shadow-2xl flex flex-col backdrop-blur-xl"
                    >
                        <header className="p-4 bg-primary-600 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center">
                                    <Bot className="text-white w-5 h-5" />
                                </div>
                                <span className="font-bold text-white uppercase tracking-wider text-sm">Security AI Assistant</span>
                            </div>
                            <button onClick={() => setIsOpen(false)} className="text-white/70 hover:text-white transition-colors">
                                <X className="w-5 h-5" />
                            </button>
                        </header>

                        <div className="p-2 bg-dark-700/50 flex gap-2 overflow-x-auto scrollbar-none border-b border-white/5">
                            {quickActions.map((action, idx) => (
                                <button
                                    key={idx}
                                    onClick={() => handleSend(action.prompt)}
                                    className="whitespace-nowrap px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/5 rounded-full text-[10px] font-bold text-primary-400 flex items-center gap-1.5 transition-all"
                                >
                                    <action.icon className="w-3 h-3" />
                                    {action.label}
                                </button>
                            ))}
                        </div>

                        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 min-h-[300px]">
                            {messages.map((msg, idx) => (
                                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                    <div className={`max-w-[85%] p-3 rounded-2xl text-sm ${msg.role === 'user'
                                        ? 'bg-primary-600 text-white rounded-tr-none'
                                        : 'bg-white/5 text-gray-300 rounded-tl-none border border-white/5'
                                        }`}>
                                        {msg.content}
                                    </div>
                                </div>
                            ))}
                            {isLoading && (
                                <div className="flex justify-start">
                                    <div className="bg-white/5 p-3 rounded-2xl rounded-tl-none border border-white/5 flex gap-1">
                                        <div className="w-1.5 h-1.5 bg-primary-500 rounded-full animate-bounce" />
                                        <div className="w-1.5 h-1.5 bg-primary-500 rounded-full animate-bounce [animation-delay:0.2s]" />
                                        <div className="w-1.5 h-1.5 bg-primary-500 rounded-full animate-bounce [animation-delay:0.4s]" />
                                    </div>
                                </div>
                            )}
                        </div>

                        <form
                            onSubmit={(e) => { e.preventDefault(); handleSend(); }}
                            className="p-4 bg-dark-900/50 border-t border-white/5 flex gap-2"
                        >
                            <input
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder={t('اسأل عن أي شيء أمني...', 'Ask about anything security...')}
                                className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm focus:outline-none focus:border-primary-500 transition-colors"
                            />
                            <button className="p-2 bg-primary-600 text-white rounded-xl hover:bg-primary-500 transition-all">
                                <Send className="w-5 h-5" />
                            </button>
                        </form>
                    </motion.div>
                )}
            </AnimatePresence>

            <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setIsOpen(!isOpen)}
                className="w-14 h-14 bg-gradient-to-tr from-primary-600 to-primary-400 rounded-full flex items-center justify-center shadow-2xl shadow-primary-600/40 border border-white/20 relative"
            >
                <Bot className="text-white w-7 h-7" />
                {!isOpen && (
                    <span className="absolute -top-1 -right-1 w-5 h-5 bg-accent-500 text-white text-[10px] font-black rounded-full flex items-center justify-center animate-pulse">
                        AI
                    </span>
                )}
            </motion.button>
        </div>
    );
};

export default AIAssistant;
