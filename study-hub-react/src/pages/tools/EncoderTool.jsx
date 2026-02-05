import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Hash, Code, RefreshCw, Copy, Check } from 'lucide-react';

const EncoderTool = () => {
    const [input, setInput] = useState('');
    const [output, setOutput] = useState('');
    const [mode, setMode] = useState('b64-enc');
    const [key, setKey] = useState('KEY');
    const [copied, setCopied] = useState(false);

    const process = (val, currentMode, currentKey) => {
        try {
            switch (currentMode) {
                case 'b64-enc': setOutput(btoa(val)); break;
                case 'b64-dec': setOutput(atob(val)); break;
                case 'url-enc': setOutput(encodeURIComponent(val)); break;
                case 'url-dec': setOutput(decodeURIComponent(val)); break;
                case 'html-enc': setOutput(val.replace(/[\u00A0-\u9999<>&]/g, i => '&#' + i.charCodeAt(0) + ';')); break;
                case 'html-dec': setOutput(val.replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec))); break;
                case 'rot13': setOutput(val.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26))); break;
                case 'xor':
                    let res = '';
                    for (let i = 0; i < val.length; i++) {
                        res += String.fromCharCode(val.charCodeAt(i) ^ currentKey.charCodeAt(i % currentKey.length));
                    }
                    setOutput(btoa(res)); // Output as Base64 for readability
                    break;
                case 'xor-dec':
                    let decoded = atob(val);
                    let resDec = '';
                    for (let i = 0; i < decoded.length; i++) {
                        resDec += String.fromCharCode(decoded.charCodeAt(i) ^ currentKey.charCodeAt(i % currentKey.length));
                    }
                    setOutput(resDec);
                    break;
                case 'hex-enc':
                    let hex = '';
                    for (let i = 0; i < val.length; i++) hex += val.charCodeAt(i).toString(16).padStart(2, '0');
                    setOutput(hex);
                    break;
                case 'hex-dec':
                    let str = '';
                    for (let i = 0; i < val.length; i += 2) str += String.fromCharCode(parseInt(val.substr(i, 2), 16));
                    setOutput(str);
                    break;
                default: break;
            }
        } catch (e) {
            setOutput('ERROR: Invalid Input');
        }
    };

    const handleInput = (e) => {
        setInput(e.target.value);
        process(e.target.value, mode, key);
    };

    const handleKeyChange = (e) => {
        setKey(e.target.value);
        process(input, mode, e.target.value);
    };

    const handleModeChange = (newMode) => {
        setMode(newMode);
        process(input, newMode, key);
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(output);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-fade-in">
            <div className="text-center space-y-4">
                <div className="inline-block p-4 bg-purple-500/20 rounded-2xl border border-purple-500/30">
                    <Hash size={48} className="text-purple-500" />
                </div>
                <h1 className="text-4xl font-bold tracking-tighter uppercase font-orbitron">Encoder // Decoder</h1>
                <p className="text-white/50">Multi-format encoding utility for security researchers.</p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {[
                    { id: 'b64-enc', name: 'Base64 Enc' },
                    { id: 'b64-dec', name: 'Base64 Dec' },
                    { id: 'url-enc', name: 'URL Enc' },
                    { id: 'url-dec', name: 'URL Dec' },
                    { id: 'hex-enc', name: 'Hex Enc' },
                    { id: 'hex-dec', name: 'Hex Dec' },
                    { id: 'html-enc', name: 'HTML Enc' },
                    { id: 'html-dec', name: 'HTML Dec' },
                    { id: 'rot13', name: 'ROT13' },
                    { id: 'xor', name: 'XOR Enc' },
                    { id: 'xor-dec', name: 'XOR Dec' },
                ].map(btn => (
                    <button
                        key={btn.id}
                        onClick={() => handleModeChange(btn.id)}
                        className={`py-2 px-4 rounded-lg text-[10px] font-bold tracking-widest uppercase transition-all border ${mode === btn.id ? 'bg-purple-600 border-purple-400 text-white shadow-lg shadow-purple-500/20' : 'text-white/40 border-white/10 hover:border-white/20'}`}
                    >
                        {btn.name}
                    </button>
                ))}
            </div>

            {(mode === 'xor' || mode === 'xor-dec') && (
                <div className="space-y-2 animate-fade-in">
                    <label className="text-xs uppercase text-white/30 font-bold tracking-widest">XOR Key</label>
                    <input
                        type="text"
                        value={key}
                        onChange={handleKeyChange}
                        className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-purple-400 focus:outline-none focus:border-purple-500/50 font-mono text-sm"
                        placeholder="Enter encryption key..."
                    />
                </div>
            )}

            <div className="space-y-6">
                <div className="space-y-2">
                    <label className="text-xs uppercase text-white/30 font-bold tracking-widest">Input String</label>
                    <textarea
                        value={input}
                        onChange={handleInput}
                        className="w-full h-32 bg-black/40 border border-white/10 rounded-xl p-4 text-purple-400 focus:outline-none focus:border-purple-500/50 resize-none font-mono text-sm"
                        placeholder="Enter text to process..."
                    />
                </div>

                <div className="relative space-y-2">
                    <label className="text-xs uppercase text-white/30 font-bold tracking-widest">Output String</label>
                    <div className="relative">
                        <textarea
                            value={output}
                            readOnly
                            className="w-full h-32 bg-purple-500/5 border border-purple-500/20 rounded-xl p-4 text-white resize-none font-mono text-sm"
                        />
                        <button
                            onClick={handleCopy}
                            className="absolute top-4 right-4 p-2 bg-black/40 hover:bg-black/60 rounded-lg text-white/50 hover:text-white transition-all border border-white/10"
                        >
                            {copied ? <Check size={16} className="text-green-500" /> : <Copy size={16} />}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default EncoderTool;
