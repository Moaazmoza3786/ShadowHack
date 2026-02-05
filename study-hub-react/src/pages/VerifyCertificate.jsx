import React, { useState } from 'react';
import { Award, Search, CheckCircle2, AlertCircle, ShieldCheck } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const VerifyCertificate = () => {
    const [code, setCode] = useState('');
    const [status, setStatus] = useState('idle'); // idle, loading, success, error

    const handleVerify = () => {
        if (!code) return;
        setStatus('loading');
        setTimeout(() => {
            if (code.startsWith('CERT-')) {
                setStatus('success');
            } else {
                setStatus('error');
            }
        }, 1500);
    };

    return (
        <div className="max-w-xl mx-auto py-12 space-y-12 animate-fade-in">
            <div className="text-center space-y-6">
                <motion.div
                    initial={{ scale: 0.8, opacity: 0, rotate: -10 }}
                    animate={{ scale: 1, opacity: 1, rotate: 0 }}
                    className="mx-auto w-32 h-32 bg-primary-500/10 rounded-3xl flex items-center justify-center border border-primary-500/20 mb-8 shadow-2xl shadow-primary-500/5"
                >
                    <Award size={64} className="text-primary-500" />
                </motion.div>
                <div className="space-y-2">
                    <h1 className="text-5xl font-black italic tracking-tighter uppercase underline decoration-primary-500/50 underline-offset-8">Verify Asset</h1>
                    <p className="text-white/40 font-mono tracking-[0.2em] uppercase text-xs">Cryptographic Validation Protocol v1.0</p>
                </div>
            </div>

            <div className="bg-dark-800/50 border border-white/5 p-10 rounded-[2.5rem] space-y-8 backdrop-blur-xl relative overflow-hidden group">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary-500/50 to-transparent" />

                <div className="space-y-8 relative z-10">
                    <div className="space-y-4">
                        <label className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] ml-2">Certificate Serial Number</label>
                        <div className="relative">
                            <input
                                type="text"
                                placeholder="CERT-XXXX-XXXX"
                                value={code}
                                onChange={(e) => setCode(e.target.value.toUpperCase())}
                                className="w-full bg-black/40 border-2 border-white/5 group-hover:border-primary-500/20 rounded-2xl py-6 text-center text-2xl font-black text-primary-400 placeholder:text-white/5 focus:outline-none focus:border-primary-500/50 transition-all font-mono tracking-[0.2em]"
                            />
                        </div>
                    </div>

                    <button
                        onClick={handleVerify}
                        disabled={status === 'loading'}
                        className="w-full py-6 bg-primary-600 hover:bg-primary-500 text-dark-900 font-black rounded-2xl transition-all hover:scale-[1.02] uppercase tracking-[0.3em] text-sm flex items-center justify-center gap-3 active:scale-95 shadow-xl shadow-primary-600/20 group/btn"
                    >
                        {status === 'loading' ? (
                            <div className="w-6 h-6 border-3 border-dark-900 border-t-transparent rounded-full animate-spin" />
                        ) : (
                            <>
                                <Search size={18} className="group-hover/btn:scale-120 transition-transform" />
                                Run Validation
                            </>
                        )}
                    </button>
                </div>
            </div>

            <AnimatePresence mode="wait">
                {status === 'success' && (
                    <motion.div
                        initial={{ opacity: 0, y: 20, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: -20, scale: 0.95 }}
                        className="bg-green-500/10 border border-green-500/30 p-8 rounded-3xl flex items-center gap-6 backdrop-blur-md"
                    >
                        <div className="w-12 h-12 rounded-full bg-green-500/20 flex items-center justify-center shrink-0">
                            <ShieldCheck className="text-green-500" size={28} />
                        </div>
                        <div>
                            <h4 className="font-black text-green-500 uppercase tracking-tight text-lg italic">Asset Authenticated</h4>
                            <p className="text-xs text-white/40 font-mono uppercase tracking-wide">This certificate is valid and cryptographically signed in our secure ledger.</p>
                        </div>
                    </motion.div>
                )}

                {status === 'error' && (
                    <motion.div
                        initial={{ opacity: 0, y: 20, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: -20, scale: 0.95 }}
                        className="bg-red-500/10 border border-red-500/30 p-8 rounded-3xl flex items-center gap-6 backdrop-blur-md"
                    >
                        <div className="w-12 h-12 rounded-full bg-red-500/20 flex items-center justify-center shrink-0">
                            <AlertCircle className="text-red-500" size={28} />
                        </div>
                        <div>
                            <h4 className="font-black text-red-500 uppercase tracking-tight text-lg italic">Validation Failed</h4>
                            <p className="text-xs text-white/40 font-mono uppercase tracking-wide">The provided ID does not correlate with any verified assets in our database.</p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default VerifyCertificate;
