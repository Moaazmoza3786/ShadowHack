import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Fingerprint, Search, Copy, Check, AlertCircle, Shield, ArrowRight, Hash, Info } from 'lucide-react';

const HashIdentifier = () => {
    const [hashInput, setHashInput] = useState('');
    const [results, setResults] = useState([]);
    const [copied, setCopied] = useState(false);

    const hashPatterns = [
        { regex: /^[a-f0-9]{32}$/i, types: [{ name: 'MD5', mode: '0', confidence: 'High' }, { name: 'NTLM', mode: '1000', confidence: 'Medium' }, { name: 'LM', mode: '3000', confidence: 'Low' }] },
        { regex: /^[a-f0-9]{40}$/i, types: [{ name: 'SHA-1', mode: '100', confidence: 'High' }, { name: 'RIPEMD-160', mode: '6000', confidence: 'Low' }] },
        { regex: /^[a-f0-9]{64}$/i, types: [{ name: 'SHA-256', mode: '1400', confidence: 'High' }, { name: 'SHA3-256', mode: '17400', confidence: 'Medium' }, { name: 'Keccak-256', mode: '17800', confidence: 'Low' }] },
        { regex: /^[a-f0-9]{96}$/i, types: [{ name: 'SHA-384', mode: '10800', confidence: 'High' }] },
        { regex: /^[a-f0-9]{128}$/i, types: [{ name: 'SHA-512', mode: '1700', confidence: 'High' }, { name: 'SHA3-512', mode: '17600', confidence: 'Medium' }, { name: 'Whirlpool', mode: '6100', confidence: 'Low' }] },
        { regex: /^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/, types: [{ name: 'MD5 Crypt (Unix)', mode: '500', confidence: 'High' }] },
        { regex: /^\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$/, types: [{ name: 'Bcrypt', mode: '3200', confidence: 'High' }] },
        { regex: /^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$/, types: [{ name: 'SHA-256 Crypt', mode: '7400', confidence: 'High' }] },
        { regex: /^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$/, types: [{ name: 'SHA-512 Crypt', mode: '1800', confidence: 'High' }] },
        { regex: /^\*[A-F0-9]{40}$/i, types: [{ name: 'MySQL 4.1+', mode: '300', confidence: 'High' }] },
        { regex: /^[a-f0-9]{16}$/i, types: [{ name: 'MySQL (Old)', mode: '200', confidence: 'Medium' }, { name: 'DES', mode: '1500', confidence: 'Low' }] },
        { regex: /^[a-f0-9]{56}$/i, types: [{ name: 'SHA-224', mode: '1300', confidence: 'High' }] },
        { regex: /^pbkdf2_sha256\$/, types: [{ name: 'Django PBKDF2-SHA256', mode: '10000', confidence: 'High' }] },
        { regex: /^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/i, types: [{ name: 'Django SHA-1', mode: '124', confidence: 'High' }] },
        { regex: /^[a-f0-9]{32}:[a-zA-Z0-9]+$/i, types: [{ name: 'Joomla MD5', mode: '11', confidence: 'High' }] },
        { regex: /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/, types: [{ name: 'JWT Token', mode: '16500', confidence: 'High' }] },
        { regex: /^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/, types: [{ name: 'Apache MD5', mode: '1600', confidence: 'High' }] },
        { regex: /^[a-f0-9]{48}$/i, types: [{ name: 'Haval-192', mode: 6008, confidence: 'Low' }] },
    ];

    const identifyHash = (input) => {
        const trimmed = input.trim();
        if (!trimmed) {
            setResults([]);
            return;
        }

        const matches = [];
        for (const pattern of hashPatterns) {
            if (pattern.regex.test(trimmed)) {
                pattern.types.forEach(type => matches.push(type));
            }
        }

        if (matches.length === 0) {
            setResults([{ name: 'Unknown', mode: 'N/A', confidence: 'None', length: trimmed.length }]);
        } else {
            setResults(matches.sort((a, b) => {
                const order = { High: 0, Medium: 1, Low: 2 };
                return order[a.confidence] - order[b.confidence];
            }));
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const getConfidenceColor = (confidence) => {
        switch (confidence) {
            case 'High': return 'text-green-400 bg-green-500/10 border-green-500/30';
            case 'Medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
            case 'Low': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
            default: return 'text-red-400 bg-red-500/10 border-red-500/30';
        }
    };

    return (
        <div className="max-w-4xl mx-auto space-y-12 animate-fade-in">
            {/* Header */}
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-purple-500/50 underline-offset-8">
                    <Fingerprint size={48} className="text-purple-500" />
                    HASH IDENTIFIER
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">Detect hash types & find hashcat modes</p>
            </div>

            {/* Input Section */}
            <div className="p-8 rounded-3xl bg-white/5 border border-white/10 space-y-6">
                <div className="flex items-center gap-4">
                    <Search size={20} className="text-purple-400" />
                    <input
                        type="text"
                        value={hashInput}
                        onChange={(e) => {
                            setHashInput(e.target.value);
                            identifyHash(e.target.value);
                        }}
                        placeholder="Paste hash here... (e.g., 5d41402abc4b2a76b9719d911017c592)"
                        className="flex-1 bg-transparent border-none outline-none text-white placeholder:text-white/30 font-mono text-lg"
                    />
                    {hashInput && (
                        <button onClick={() => { setHashInput(''); setResults([]); }} className="text-white/30 hover:text-white/60">
                            Clear
                        </button>
                    )}
                </div>
                {hashInput && (
                    <div className="flex items-center gap-4 text-xs text-white/40 font-mono border-t border-white/5 pt-4">
                        <span>Length: {hashInput.trim().length}</span>
                        <span>Charset: {/^[a-f0-9]+$/i.test(hashInput.trim()) ? 'Hex' : 'Mixed'}</span>
                    </div>
                )}
            </div>

            {/* Results */}
            <AnimatePresence>
                {results.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        className="space-y-4"
                    >
                        <h2 className="text-lg font-black text-white/60 flex items-center gap-2">
                            <Hash size={18} /> POSSIBLE HASH TYPES
                        </h2>

                        {results[0]?.name === 'Unknown' ? (
                            <div className="p-8 rounded-3xl bg-red-500/5 border border-red-500/20 text-center space-y-4">
                                <AlertCircle size={48} className="mx-auto text-red-400" />
                                <h3 className="text-xl font-bold text-red-400">Unknown Hash Format</h3>
                                <p className="text-white/40 text-sm">
                                    Could not identify this hash. Length: {results[0].length} characters.
                                </p>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {results.map((result, idx) => (
                                    <motion.div
                                        key={idx}
                                        initial={{ opacity: 0, x: -20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: idx * 0.05 }}
                                        className={`p-6 rounded-2xl border flex items-center justify-between ${getConfidenceColor(result.confidence)}`}
                                    >
                                        <div className="flex items-center gap-4">
                                            <div className="p-3 rounded-xl bg-white/5">
                                                <Shield size={24} />
                                            </div>
                                            <div>
                                                <div className="text-lg font-black flex items-center gap-3">
                                                    {result.name}
                                                    {idx === 0 && (
                                                        <span className="text-[10px] bg-green-500 text-black px-2 py-0.5 rounded-full font-bold">
                                                            MOST LIKELY
                                                        </span>
                                                    )}
                                                </div>
                                                <div className="text-xs opacity-60">Confidence: {result.confidence}</div>
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-4">
                                            <div className="text-right">
                                                <div className="text-xs text-white/40">Hashcat Mode</div>
                                                <div className="font-mono font-bold text-lg">-m {result.mode}</div>
                                            </div>
                                            <button
                                                onClick={() => copyToClipboard(`hashcat -m ${result.mode} hash.txt wordlist.txt`)}
                                                className="p-3 rounded-xl bg-white/10 hover:bg-white/20 transition-all"
                                            >
                                                {copied ? <Check size={18} className="text-green-400" /> : <Copy size={18} />}
                                            </button>
                                        </div>
                                    </motion.div>
                                ))}
                            </div>
                        )}

                        {/* Pro Tips */}
                        <div className="p-6 rounded-2xl bg-purple-500/5 border border-purple-500/20 space-y-4 mt-8">
                            <h3 className="text-sm font-black text-purple-400 flex items-center gap-2">
                                <Info size={16} /> CRACKING TIPS
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-white/60 font-mono">
                                <div>
                                    <strong className="text-white/80">Hashcat:</strong>
                                    <pre className="mt-1 p-3 bg-black/50 rounded-lg overflow-x-auto">hashcat -m {results[0]?.mode || '0'} hash.txt rockyou.txt</pre>
                                </div>
                                <div>
                                    <strong className="text-white/80">John the Ripper:</strong>
                                    <pre className="mt-1 p-3 bg-black/50 rounded-lg overflow-x-auto">john --wordlist=rockyou.txt hash.txt</pre>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Empty State */}
            {!hashInput && (
                <div className="text-center py-16 space-y-6">
                    <Fingerprint size={64} className="mx-auto text-white/10" />
                    <p className="text-white/30 text-sm">Paste a hash above to identify its type</p>
                    <div className="flex flex-wrap justify-center gap-2 text-xs">
                        {['MD5', 'SHA-1', 'SHA-256', 'Bcrypt', 'NTLM', 'MySQL'].map(type => (
                            <span key={type} className="px-3 py-1 rounded-full bg-white/5 text-white/40">{type}</span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default HashIdentifier;
