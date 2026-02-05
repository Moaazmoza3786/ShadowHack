import React, { createContext, useContext, useState, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X, Check, AlertTriangle, Info } from 'lucide-react';

const ToastContext = createContext();

export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);

    const toast = useCallback((message, type = 'info', duration = 3000) => {
        const id = Date.now() + Math.random();
        setToasts(prev => [...prev, { id, message, type }]);

        setTimeout(() => {
            setToasts(prev => prev.filter(t => t.id !== id));
        }, duration);
    }, []);

    const removeToast = (id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    };

    return (
        <ToastContext.Provider value={{ toast }}>
            {children}
            <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
                <AnimatePresence>
                    {toasts.map(t => (
                        <motion.div
                            key={t.id}
                            initial={{ opacity: 0, x: 50, scale: 0.9 }}
                            animate={{ opacity: 1, x: 0, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.9, transition: { duration: 0.2 } }}
                            className={`pointer-events-auto min-w-[300px] max-w-sm p-4 rounded-lg border shadow-lg backdrop-blur-md flex items-center gap-3 ${t.type === 'success' ? 'bg-emerald-950/90 border-emerald-500/50 text-emerald-200' :
                                    t.type === 'error' ? 'bg-red-950/90 border-red-500/50 text-red-200' :
                                        t.type === 'warning' ? 'bg-amber-950/90 border-amber-500/50 text-amber-200' :
                                            'bg-slate-900/90 border-slate-700 text-slate-200'
                                }`}
                        >
                            <div className={`p-1 rounded-full ${t.type === 'success' ? 'bg-emerald-500/20' :
                                    t.type === 'error' ? 'bg-red-500/20' :
                                        t.type === 'warning' ? 'bg-amber-500/20' : 'bg-slate-700'
                                }`}>
                                {t.type === 'success' && <Check size={16} />}
                                {t.type === 'error' && <X size={16} />}
                                {t.type === 'warning' && <AlertTriangle size={16} />}
                                {t.type === 'info' && <Info size={16} />}
                            </div>
                            <div className="flex-1 text-sm font-medium">{t.message}</div>
                            <button onClick={() => removeToast(t.id)} className="opacity-50 hover:opacity-100 transition-opacity">
                                <X size={14} />
                            </button>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>
        </ToastContext.Provider>
    );
};

export const useToast = () => {
    const context = useContext(ToastContext);
    if (!context) throw new Error('useToast must be used within a ToastProvider');
    return context;
};
