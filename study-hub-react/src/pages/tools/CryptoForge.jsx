import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Lock, Unlock, RefreshCw, Hash, FileCode,
    Shield, Key, Database, Play, AlertTriangle,
    CheckCircle, Copy, ArrowRightLeft, BookOpen
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- CHALLENGES DATA ---
const CHALLENGES = [
    // EASY
    {
        id: 'caesar-1',
        name: 'Caesar Shift',
        difficulty: 'Easy',
        points: 50,
        category: 'Classical',
        description: 'Decrypt this Caesar cipher with shift of 3',
        ciphertext: 'WKLV LV D VHFUHW PHVVDJH',
        hint: 'Julius Caesar used this cipher. Try shifting each letter back by 3.',
        answer: 'THIS IS A SECRET MESSAGE'
    },
    {
        id: 'rot13-1',
        name: 'ROT13 Decoder',
        difficulty: 'Easy',
        points: 50,
        category: 'Classical',
        description: 'Decode this ROT13 encoded message',
        ciphertext: 'URYYB UNPXRE JBEYQ',
        hint: 'ROT13 shifts by 13. Fun fact: Applying it twice gives you the original!',
        answer: 'HELLO HACKER WORLD'
    },
    {
        id: 'base64-1',
        name: 'Base64 Secret',
        difficulty: 'Easy',
        points: 50,
        category: 'Encoding',
        description: 'Decode this Base64 encoded flag',
        ciphertext: 'QnJlYWNoTGFic3tCYXNlNjRfSXNfTm90X0VuY3J5cHRpb259',
        hint: 'Base64 uses A-Z, a-z, 0-9, +, and /',
        answer: 'ShadowHack{Base64_Is_Not_Encryption}'
    },
    // MEDIUM
    {
        id: 'vigenere-1',
        name: 'Vigenère Cipher',
        difficulty: 'Medium',
        points: 100,
        category: 'Classical',
        description: 'Decrypt using key: "HACK"',
        ciphertext: 'OPWMB ITNLB RWPMB',
        hint: 'Each letter in the key shifts the corresponding plaintext letter.',
        answer: 'HELLO CYBER WORLD'
    },
    {
        id: 'xor-1',
        name: 'XOR Challenge',
        difficulty: 'Medium',
        points: 100,
        category: 'Modern',
        description: 'XOR the hex bytes with key 0x42',
        ciphertext: '0x00 0x22 0x21 0x23 0x27 0x2B',
        hint: 'XOR is reversible: A ⊕ B ⊕ B = A',
        answer: 'BREACH'
    },
    {
        id: 'hash-1',
        name: 'Hash Cracker',
        difficulty: 'Medium',
        points: 100,
        category: 'Hashing',
        description: 'Crack this MD5 hash (common password)',
        ciphertext: '5f4dcc3b5aa765d61d8327deb882cf99',
        hint: 'This is one of the most common passwords in the world.',
        answer: 'password'
    },
    // HARD
    {
        id: 'aes-1',
        name: 'AES Puzzle',
        difficulty: 'Hard',
        points: 200,
        category: 'Modern',
        description: 'Find the key from the ciphertext pattern',
        ciphertext: 'U2FsdGVkX1+vupppZ...',
        hint: 'AES operates on 128-bit blocks. The key might be in the metadata.',
        answer: 'AES256_MASTER_KEY'
    },
    {
        id: 'rsa-1',
        name: 'RSA Baby',
        difficulty: 'Hard',
        points: 200,
        category: 'Asymmetric',
        description: 'Given n=77, e=7, c=10. Find m.',
        ciphertext: 'n=77, e=7, c=10',
        hint: 'n = p * q where p and q are primes. Here n = 7 * 11.',
        answer: '32'
    }
];

// --- UTILS ---
const caesarCipher = (str, shift) => {
    return str.replace(/[A-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26) + 65))
        .replace(/[a-z]/g, c => String.fromCharCode(((c.charCodeAt(0) - 97 + shift) % 26) + 97));
};

const xorCipher = (text, key) => {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
};

// Simplified SHA256 implementation for demo (in production use real library)
const sha256 = async (message) => {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

const CryptoForge = () => {
    const { toast } = useToast();
    const [activeTab, setActiveTab] = useState('challenges');

    // CHALLENGES STATE
    const [solvedChallenges, setSolvedChallenges] = useState([]);
    const [selectedChallengeId, setSelectedChallengeId] = useState(null);
    const [answerInput, setAnswerInput] = useState('');
    const [showHint, setShowHint] = useState(false);

    // WORKBENCH STATE
    const [inputText, setInputText] = useState('');
    const [outputText, setOutputText] = useState('');
    const [operation, setOperation] = useState('base64Enc');
    const [customKey, setCustomKey] = useState('');
    const [hmacAlgo, setHmacAlgo] = useState('SHA-256');

    // FILE HASHING STATE
    const [fileHashResult, setFileHashResult] = useState(null);
    const [isHashing, setIsHashing] = useState(false);

    // RSA STATE
    const [rsaKeys, setRsaKeys] = useState({ public: '', private: '' });
    const [rsaGenerating, setRsaGenerating] = useState(false);
    const [rsaKeySize, setRsaKeySize] = useState(2048);

    useEffect(() => {
        const saved = localStorage.getItem('crypto_solved');
        if (saved) setSolvedChallenges(JSON.parse(saved));
    }, []);

    // --- UTILS ---
    const calculateFileHash = async (file, algo) => {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest(algo, buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const handleFileDrop = async (e) => {
        e.preventDefault();
        const file = e.dataTransfer?.files[0] || e.target.files[0];
        if (!file) return;

        setIsHashing(true);
        try {
            const md5 = await calculateFileHash(file, 'SHA-1'); // Browser doesn't support MD5 natively via subtle crypto easily without lib, using SHA-1 as fallback info or just SHA-256
            // Note: Native MD5 is not in crypto.subtle. We will use SHA-1, SHA-256, SHA-384, SHA-512.
            const s1 = await calculateFileHash(file, 'SHA-1');
            const s256 = await calculateFileHash(file, 'SHA-256');
            const s512 = await calculateFileHash(file, 'SHA-512');

            setFileHashResult({
                name: file.name,
                size: file.size,
                sha1: s1,
                sha256: s256,
                sha512: s512
            });
            toast('File hashed successfully', 'success');
        } catch (err) {
            toast('Hashing failed: ' + err.message, 'error');
        }
        setIsHashing(false);
    };

    const generateRSA = async () => {
        setRsaGenerating(true);
        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: rsaKeySize,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );

            const exportedPublic = await crypto.subtle.exportKey("spki", keyPair.publicKey);
            const exportedPrivate = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

            const toPem = (buffer, type) => {
                const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
                const str = b64.match(/.{1,64}/g).join('\n');
                return `-----BEGIN ${type} KEY-----\n${str}\n-----END ${type} KEY-----`;
            };

            setRsaKeys({
                public: toPem(exportedPublic, 'PUBLIC'),
                private: toPem(exportedPrivate, 'PRIVATE')
            });
            toast('RSA Keypair Generated', 'success');
        } catch (e) {
            toast('RSA Gen Error: ' + e.message, 'error');
        }
        setRsaGenerating(false);
    };

    const handleProcess = async () => {
        if (!inputText) return;
        let res = '';

        try {
            switch (operation) {
                case 'base64Enc': res = btoa(inputText); break;
                case 'base64Dec': res = atob(inputText); break;
                case 'hexEnc': res = Array.from(inputText).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' '); break;
                case 'hexDec': res = inputText.replace(/\s/g, '').match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || ''; break;
                case 'rot13': res = caesarCipher(inputText, 13); break;
                case 'caesar': res = caesarCipher(inputText, parseInt(customKey) || 3); break;
                case 'urlEnc': res = encodeURIComponent(inputText); break;
                case 'urlDec': res = decodeURIComponent(inputText); break;
                case 'sha256': res = await sha256(inputText); break;
                case 'xor': res = xorCipher(inputText, customKey || '42'); break;
                case 'reverse': res = inputText.split('').reverse().join(''); break;
                case 'hmac':
                    const enc = new TextEncoder();
                    const key = await crypto.subtle.importKey("raw", enc.encode(customKey || 'secret'), { name: "HMAC", hash: hmacAlgo }, false, ["sign"]);
                    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(inputText));
                    res = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
                    break;
                default: res = inputText;
            }
            setOutputText(res);
        } catch (e) {
            setOutputText('Error: ' + e.message);
        }
    };

    const handleChallengeSubmit = () => {
        const challenge = CHALLENGES.find(c => c.id === selectedChallengeId);
        if (!challenge) return;

        if (answerInput.trim().toUpperCase() === challenge.answer.toUpperCase()) {
            if (!solvedChallenges.includes(challenge.id)) {
                const newSolved = [...solvedChallenges, challenge.id];
                setSolvedChallenges(newSolved);
                localStorage.setItem('crypto_solved', JSON.stringify(newSolved));
                toast(`Correct! +${challenge.points} pts`, 'success');
            } else {
                toast('Correct!', 'success');
            }
        } else {
            toast('Incorrect answer', 'error');
        }
    };

    const selectedChallenge = CHALLENGES.find(c => c.id === selectedChallengeId);

    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
                <div className="space-y-2">
                    <h1 className="text-4xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-yellow-500 to-amber-500">
                        CRYPTO FORGE
                    </h1>
                    <p className="text-white/40 font-mono tracking-widest uppercase text-sm">
                        Pro Cryptography & Analysis Suite
                    </p>
                </div>
                <div className="flex gap-4">
                    <div className="px-4 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 font-mono text-xs">
                        <span className="font-bold text-lg">{solvedChallenges.length}</span> SOLVED
                    </div>
                    <div className="px-4 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 font-mono text-xs">
                        <span className="font-bold text-lg">
                            {CHALLENGES.filter(c => solvedChallenges.includes(c.id)).reduce((a, b) => a + b.points, 0)}
                        </span> PTS
                    </div>
                </div>
            </div>

            {/* NAV */}
            <div className="flex gap-2 p-1 bg-white/5 rounded-xl w-fit overflow-x-auto">
                {[
                    { id: 'challenges', label: 'Challenges', icon: Shield },
                    { id: 'workbench', label: 'Workbench', icon: RefreshCw },
                    { id: 'filehash', label: 'File Hasher', icon: FileCode },
                    { id: 'rsa', label: 'RSA Lab', icon: Key },
                    { id: 'learn', label: 'Reference', icon: BookOpen },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-6 py-2 rounded-lg font-bold uppercase text-sm transition-all whitespace-nowrap ${activeTab === tab.id
                            ? 'bg-yellow-500 text-black shadow-lg shadow-yellow-500/20'
                            : 'text-gray-400 hover:text-white hover:bg-white/5'
                            }`}
                    >
                        <tab.icon size={16} /> {tab.label}
                    </button>
                ))}
            </div>

            {/* CONTENT */}
            <AnimatePresence mode="wait">

                {/* TAB: CHALLENGES */}
                {activeTab === 'challenges' && (
                    <motion.div
                        key="challenges"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 10 }}
                        className="grid grid-cols-1 lg:grid-cols-3 gap-6"
                    >
                        {/* LIST */}
                        <div className="lg:col-span-1 space-y-4 max-h-[70vh] overflow-y-auto pr-2 scrollbar-cyber">
                            {['Easy', 'Medium', 'Hard'].map(diff => (
                                <div key={diff} className="space-y-2">
                                    <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest px-2">{diff}</h3>
                                    {CHALLENGES.filter(c => c.difficulty === diff).map(c => (
                                        <div
                                            key={c.id}
                                            onClick={() => { setSelectedChallengeId(c.id); setShowHint(false); setAnswerInput(''); }}
                                            className={`p-4 rounded-xl border cursor-pointer transition-all group ${selectedChallengeId === c.id
                                                ? 'bg-yellow-500/10 border-yellow-500 text-white'
                                                : 'bg-white/5 border-transparent hover:bg-white/10 hover:border-white/10'
                                                }`}
                                        >
                                            <div className="flex justify-between items-center mb-1">
                                                <span className="font-bold">{c.name}</span>
                                                {solvedChallenges.includes(c.id) && <CheckCircle size={14} className="text-green-500" />}
                                            </div>
                                            <div className="flex justify-between text-xs opacity-60">
                                                <span>{c.category}</span>
                                                <span className="font-mono text-yellow-500">{c.points} pts</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ))}
                        </div>

                        {/* DETAIL */}
                        <div className="lg:col-span-2">
                            {selectedChallenge ? (
                                <div className="p-8 rounded-2xl bg-white/5 border border-white/10 h-full flex flex-col">
                                    <div className="mb-6 pb-6 border-b border-white/10">
                                        <div className="flex items-center gap-3 mb-2">
                                            <h2 className="text-2xl font-black text-white">{selectedChallenge.name}</h2>
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${selectedChallenge.difficulty === 'Easy' ? 'bg-green-500/20 text-green-400' :
                                                selectedChallenge.difficulty === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                    'bg-red-500/20 text-red-500'
                                                }`}>{selectedChallenge.difficulty}</span>
                                        </div>
                                        <p className="text-gray-400">{selectedChallenge.description}</p>
                                    </div>

                                    <div className="space-y-6 flex-1">
                                        <div className="space-y-2">
                                            <label className="text-xs font-bold text-yellow-500 uppercase tracking-widest">Ciphertext</label>
                                            <div className="p-4 rounded-xl bg-black/40 border border-white/5 font-mono text-green-400 break-all relative group">
                                                {selectedChallenge.ciphertext}
                                                <button
                                                    onClick={() => { navigator.clipboard.writeText(selectedChallenge.ciphertext); toast('Copied', 'success') }}
                                                    className="absolute top-2 right-2 p-1.5 rounded hover:bg-white/10 text-gray-500 hover:text-white"
                                                >
                                                    <Copy size={16} />
                                                </button>
                                            </div>
                                        </div>

                                        <div className="p-4 rounded-xl bg-blue-500/5 border border-blue-500/10 cursor-pointer hover:bg-blue-500/10 transition-colors"
                                            onClick={() => setShowHint(!showHint)}>
                                            <div className="flex items-center gap-2 text-blue-400 font-bold mb-1">
                                                <AlertTriangle size={16} /> Encryption Hint
                                            </div>
                                            {showHint ? (
                                                <p className="text-sm text-blue-200 animate-slide-down">{selectedChallenge.hint}</p>
                                            ) : (
                                                <p className="text-xs text-blue-400/50 uppercase tracking-widest">Click to reveal hint</p>
                                            )}
                                        </div>
                                    </div>

                                    <div className="mt-8 pt-6 border-t border-white/10">
                                        {solvedChallenges.includes(selectedChallenge.id) ? (
                                            <div className="p-4 rounded-xl bg-green-500/20 text-green-400 font-black text-center flex items-center justify-center gap-2">
                                                <CheckCircle /> CHALLENGE SOLVED
                                            </div>
                                        ) : (
                                            <div className="flex gap-4">
                                                <input
                                                    type="text"
                                                    value={answerInput}
                                                    onChange={(e) => setAnswerInput(e.target.value)}
                                                    placeholder="Enter decrypted plaintext..."
                                                    className="flex-1 bg-black/20 border border-white/10 rounded-xl px-4 py-3 focus:border-yellow-500/50 outline-none"
                                                    onKeyDown={(e) => e.key === 'Enter' && handleChallengeSubmit()}
                                                />
                                                <button
                                                    onClick={handleChallengeSubmit}
                                                    className="px-8 font-bold bg-yellow-500 text-black rounded-xl hover:bg-yellow-400 transition-colors"
                                                >
                                                    SUBMIT
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-gray-600 border border-white/5 rounded-2xl">
                                    <Lock size={48} className="mb-4 opacity-20" />
                                    <p>Select a challenge to begin decoding</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* TAB: WORKBENCH */}
                {activeTab === 'workbench' && (
                    <motion.div
                        key="workbench"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 1.05 }}
                        className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                    >
                        <div className="space-y-6">
                            <div className="space-y-2">
                                <label className="text-xs font-bold text-gray-500 uppercase ml-2">Input</label>
                                <textarea
                                    value={inputText}
                                    onChange={(e) => setInputText(e.target.value)}
                                    className="w-full h-64 bg-black/20 border border-white/10 rounded-2xl p-4 font-mono text-sm resize-none focus:outline-none focus:border-yellow-500/50 placeholder:text-gray-700"
                                    placeholder="Enter text to analyze..."
                                />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase ml-2">Operation</label>
                                    <select
                                        value={operation}
                                        onChange={(e) => setOperation(e.target.value)}
                                        className="w-full bg-white/5 border border-white/10 rounded-xl p-3 text-white outline-none"
                                    >
                                        <option value="base64Enc">Base64 Encode</option>
                                        <option value="base64Dec">Base64 Decode</option>
                                        <option value="hexEnc">Text to Hex</option>
                                        <option value="hexDec">Hex to Text</option>
                                        <option value="urlEnc">URL Encode</option>
                                        <option value="urlDec">URL Decode</option>
                                        <option value="rot13">ROT13</option>
                                        <option value="caesar">Caesar Shift</option>
                                        <option value="xor">XOR Cipher</option>
                                        <option value="reverse">Reverse String</option>
                                        <option value="sha256">SHA-256 Hash</option>
                                        <option value="hmac">HMAC (Sign)</option>
                                    </select>
                                </div>

                                {['caesar', 'xor', 'hmac'].includes(operation) && (
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-gray-500 uppercase ml-2">Key / Shift</label>
                                        <input
                                            type="text"
                                            value={customKey}
                                            onChange={(e) => setCustomKey(e.target.value)}
                                            placeholder={operation === 'caesar' ? 'Shift amount (e.g. 3)' : 'Secret Key'}
                                            className="w-full bg-white/5 border border-white/10 rounded-xl p-3 text-white outline-none"
                                        />
                                    </div>
                                )}

                                {operation === 'hmac' && (
                                    <div className="col-span-2 space-y-2">
                                        <label className="text-xs font-bold text-gray-500 uppercase ml-2">Algorithm</label>
                                        <select
                                            value={hmacAlgo}
                                            onChange={e => setHmacAlgo(e.target.value)}
                                            className="w-full bg-white/5 border border-white/10 rounded-xl p-3 text-white outline-none"
                                        >
                                            <option value="SHA-1">SHA-1</option>
                                            <option value="SHA-256">SHA-256</option>
                                            <option value="SHA-384">SHA-384</option>
                                            <option value="SHA-512">SHA-512</option>
                                        </select>
                                    </div>
                                )}
                            </div>

                            <button
                                onClick={handleProcess}
                                className="w-full py-4 rounded-xl bg-gradient-to-r from-yellow-600 to-amber-600 font-black uppercase tracking-widest text-white shadow-lg shadow-amber-600/20 hover:scale-[1.02] transition-transform"
                            >
                                Process Data
                            </button>
                        </div>

                        <div className="space-y-2 h-full flex flex-col">
                            <label className="text-xs font-bold text-gray-500 uppercase ml-2">Output</label>
                            <div className="flex-1 bg-black/40 border border-white/10 rounded-2xl p-4 font-mono text-green-400 text-sm relative group overflow-hidden">
                                <div className="overflow-y-auto h-full pr-2 scrollbar-cyber break-all whitespace-pre-wrap">
                                    {outputText || '// Result will appear here...'}
                                </div>
                                {outputText && (
                                    <button
                                        onClick={() => { navigator.clipboard.writeText(outputText); toast('Copied result', 'success') }}
                                        className="absolute top-4 right-4 p-2 rounded-lg bg-white/10 hover:bg-white/20 text-white transition-opacity opacity-0 group-hover:opacity-100"
                                    >
                                        <Copy size={16} />
                                    </button>
                                )}
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* TAB: FILE HASHING */}
                {activeTab === 'filehash' && (
                    <motion.div
                        key="filehash"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 1.05 }}
                        className="grid grid-cols-1 gap-8"
                    >
                        <div
                            onDrop={handleFileDrop}
                            onDragOver={e => e.preventDefault()}
                            className="border-2 border-dashed border-white/20 rounded-2xl p-12 text-center hover:border-yellow-500/50 hover:bg-yellow-500/5 transition-all cursor-pointer relative"
                        >
                            <input
                                type="file"
                                onChange={(e) => handleFileDrop({ target: { files: e.target.files }, preventDefault: () => { } })}
                                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                            />
                            <div className="flex flex-col items-center gap-4 pointer-events-none">
                                <FileCode size={48} className="text-yellow-500/50" />
                                <div>
                                    <h3 className="text-xl font-bold text-white">Drag & Drop File Here</h3>
                                    <p className="text-gray-500">Computes SHA-1, SHA-256, and SHA-512 client-side.</p>
                                </div>
                            </div>
                        </div>

                        {isHashing && <div className="text-center text-yellow-500 animate-pulse font-mono">Computing hashes...</div>}

                        {fileHashResult && (
                            <div className="space-y-4 animate-slide-up">
                                <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                    <h3 className="flex items-center gap-2 font-bold text-lg text-white">
                                        <CheckCircle size={20} className="text-green-500" /> {fileHashResult.name}
                                    </h3>
                                    <p className="text-xs text-gray-500 font-mono">{(fileHashResult.size / 1024).toFixed(2)} KB</p>

                                    {[
                                        { label: 'SHA-1', val: fileHashResult.sha1 },
                                        { label: 'SHA-256', val: fileHashResult.sha256 },
                                        { label: 'SHA-512', val: fileHashResult.sha512 },
                                    ].map(h => (
                                        <div key={h.label} className="space-y-1">
                                            <label className="text-xs font-bold text-gray-500 uppercase">{h.label}</label>
                                            <div className="flex bg-black/30 border border-white/5 rounded-lg overflow-hidden">
                                                <div className="flex-1 p-3 font-mono text-sm text-yellow-500 truncate">{h.val}</div>
                                                <button
                                                    onClick={() => { navigator.clipboard.writeText(h.val); toast('Copied', 'success') }}
                                                    className="px-4 hover:bg-white/10 text-gray-400"
                                                >
                                                    <Copy size={14} />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </motion.div>
                )}

                {/* TAB: RSA LAB */}
                {activeTab === 'rsa' && (
                    <motion.div
                        key="rsa"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 1.05 }}
                        className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                    >
                        <div className="space-y-6">
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                <h3 className="text-xl font-bold flex items-center gap-2 text-white"><Key size={20} /> Key Generation</h3>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase">Key Size</label>
                                    <select
                                        value={rsaKeySize}
                                        onChange={e => setRsaKeySize(parseInt(e.target.value))}
                                        className="w-full bg-black/20 border border-white/10 rounded-xl p-3 outline-none"
                                    >
                                        <option value={1024}>1024 bit (Fast, Insecure)</option>
                                        <option value={2048}>2048 bit (Standard)</option>
                                        <option value={4096}>4096 bit (Paranoid)</option>
                                    </select>
                                </div>
                                <button
                                    onClick={generateRSA}
                                    disabled={rsaGenerating}
                                    className="w-full py-3 bg-yellow-600 rounded-xl font-bold uppercase hover:bg-yellow-500 transition-colors disabled:opacity-50"
                                >
                                    {rsaGenerating ? 'Generating Keys...' : 'Generate Keypair'}
                                </button>
                            </div>
                        </div>

                        <div className="space-y-6">
                            <div className="space-y-4">
                                <div>
                                    <label className="text-xs font-bold text-gray-500 uppercase">Public Key (share this)</label>
                                    <textarea
                                        readOnly
                                        value={rsaKeys.public}
                                        className="w-full h-32 bg-black/30 border border-white/10 rounded-xl p-3 font-mono text-[10px] text-green-400 resize-none outline-none"
                                    />
                                </div>
                                <div className="relative">
                                    <label className="text-xs font-bold text-red-500 uppercase">Private Key (DANGER: KEEP SECRET)</label>
                                    <textarea
                                        readOnly
                                        value={rsaKeys.private}
                                        className="w-full h-32 bg-red-900/10 border border-red-500/20 rounded-xl p-3 font-mono text-[10px] text-red-400 resize-none outline-none blur-sm hover:blur-none transition-all focus:blur-none"
                                    />
                                    <div className="absolute top-8 right-4 text-red-500/40 pointer-events-none text-xs uppercase font-bold">Hover to Reveal</div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* TAB: LEARN */}
                {activeTab === 'learn' && (
                    <motion.div
                        key="learn"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
                    >
                        {[
                            { title: 'Classical Ciphers', icon: BookOpen, desc: 'Ancient encryption methods like Caesar, Vigenère, and substitution ciphers. These operated on letters and were often broken by frequency analysis.' },
                            { title: 'Modern Encryption', icon: Shield, desc: 'Advanced algorithms like AES (Symmetric) and RSA (Asymmetric). These operate on bits and rely on complex mathematical problems.' },
                            { title: 'Hashing', icon: Hash, desc: 'One-way mathematical functions (MD5, SHA-256) used for data integrity and password storage. They cannot be decrypted, only cracked.' },
                            { title: 'Encoding', icon: FileCode, desc: 'Encoding (Base64, Hex) is NOT encryption. It is used to represent data in a safe format for transmission, and is easily reversible.' },
                            { title: 'XOR Operations', icon: ArrowRightLeft, desc: 'The exclusive OR operation is fundamental to modern cryptography. It is reversible: (A ⊕ B) ⊕ B = A.' },
                            { title: 'Key Exchange', icon: Key, desc: 'Protocols like Diffie-Hellman allow two parties to establish a shared secret over an insecure channel.' }
                        ].map((item, i) => (
                            <div key={i} className="p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-yellow-500/30 transition-colors">
                                <item.icon size={32} className="text-yellow-500 mb-4" />
                                <h3 className="text-xl font-bold text-white mb-2">{item.title}</h3>
                                <p className="text-sm text-gray-400 leading-relaxed">{item.desc}</p>
                            </div>
                        ))}
                    </motion.div>
                )}

            </AnimatePresence>
        </div>
    );
};

export default CryptoForge;
