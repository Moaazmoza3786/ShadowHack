import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Eye, EyeOff, Image as ImageIcon, FileText,
    Upload, Download, Search, AlertCircle,
    CheckCircle, Lock, Unlock, Zap, Layers,
    Maximize2, Grid, FileCode, Edit3
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

// --- CHALLENGES ---
const CHALLENGES = [
    {
        id: 'lsb-1',
        name: 'Hidden in Plain Sight',
        difficulty: 'Easy',
        points: 50,
        category: 'LSB',
        description: 'Extract the hidden message from the image using LSB technique.',
        hint: 'Look at the least significant bit of each pixel. The flag is hidden in the red channel.',
        answer: 'HIDDEN_FLAG' // Simplified for React demo
    },
    {
        id: 'strings-1',
        name: 'Metadata Secrets',
        difficulty: 'Easy',
        points: 50,
        category: 'Metadata',
        description: 'Check the image metadata (EXIF) for hidden information.',
        hint: 'Use exiftool or strings command. The flag might be in the Comment field.',
        answer: 'METADATA_SECRET'
    },
    {
        id: 'whitespace-1',
        name: 'Invisible Text',
        difficulty: 'Hard',
        points: 200,
        category: 'Whitespace',
        description: 'There are hidden characters in this text. Find them.',
        hint: 'Look for zero-width characters or tab/space patterns (Snow cipher).',
        answer: 'WHITESPACE_SECRET'
    }
];

const StegoAnalyst = () => {
    const { toast } = useToast();
    const [activeTab, setActiveTab] = useState('analyze');

    // IMAGE STATE
    const [selectedImage, setSelectedImage] = useState(null);
    const [imagePreview, setImagePreview] = useState(null);
    const canvasRef = useRef(null);

    // TEXT STEGO STATE
    const [coverText, setCoverText] = useState('This looks like a normal message.');
    const [secretMessage, setSecretMessage] = useState('');
    const [encodedResult, setEncodedResult] = useState('');
    const [decodeInput, setDecodeInput] = useState('');
    const [decodedResult, setDecodedResult] = useState(null);

    // LSB STATE
    const [lsbSecret, setLsbSecret] = useState('');
    const [lsbEncodedImage, setLsbEncodedImage] = useState(null);
    const [lsbDecodedText, setLsbDecodedText] = useState('');

    // ANALYSIS STATE
    const [analysisResult, setAnalysisResult] = useState(null);
    const [hexDump, setHexDump] = useState('');

    // CHALLENGE STATE
    const [solvedChallenges, setSolvedChallenges] = useState([]);

    useEffect(() => {
        const saved = localStorage.getItem('stego_solved');
        if (saved) setSolvedChallenges(JSON.parse(saved));
    }, []);

    // --- UTILS: ZERO WIDTH ---
    const encodeZeroWidth = () => {
        if (!secretMessage) return;
        const binary = secretMessage.split('').map(char =>
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');

        const hidden = binary.split('').map(bit =>
            bit === '1' ? '\u200B' : '\u200C'
        ).join(''); // 200B (Zero Width Space) = 1, 200C (Zero Width Non-Joiner) = 0

        setEncodedResult(coverText + hidden + '\u200D'); // 200D as Terminator
        toast('Message encoded invisibly!', 'success');
    };

    const decodeZeroWidth = () => {
        if (!decodeInput) return;
        const hiddenPart = decodeInput.match(/[\u200B\u200C]+/g);

        if (!hiddenPart) {
            setDecodedResult('No hidden Zero-Width data found.');
            return;
        }

        const binary = hiddenPart[0].split('').map(char =>
            char === '\u200B' ? '1' : '0'
        ).join('');

        let text = '';
        for (let i = 0; i < binary.length; i += 8) {
            text += String.fromCharCode(parseInt(binary.substr(i, 8), 2));
        }
        setDecodedResult(text);
        toast('Hidden message extracted!', 'success');
    };

    // --- UTILS: IMAGE LSB ---
    const handleLsbEncode = () => {
        if (!selectedImage || !lsbSecret) {
            toast('Please select an image and enter a secret message', 'error');
            return;
        }

        const img = new Image();
        img.src = imagePreview;
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const data = imgData.data;

            // Prepare secret binary + terminator (null char)
            const binarySecret = (lsbSecret + '\0').split('').map(char =>
                char.charCodeAt(0).toString(2).padStart(8, '0')
            ).join('');

            if (binarySecret.length > data.length / 4) { // 1 bit per pixel channel (r,g,b, not a) is enough usually, but lets be safe. actually 1 bit per byte roughly.
                // data includes RGBA. We modify RGB. 
                // Capacity: (Width * Height * 3) bits
                toast('Message too long for this image!', 'error');
                return;
            }

            let bitIdx = 0;
            for (let i = 0; i < data.length; i += 4) {
                if (bitIdx >= binarySecret.length) break;

                // Modify R, G, B channels
                for (let j = 0; j < 3; j++) {
                    if (bitIdx >= binarySecret.length) break;
                    // Clear LSB and set new bit
                    data[i + j] = (data[i + j] & ~1) | parseInt(binarySecret[bitIdx]);
                    bitIdx++;
                }
            }

            ctx.putImageData(imgData, 0, 0);
            setLsbEncodedImage(canvas.toDataURL('image/png'));
            toast('LSB Encoding Complete', 'success');
        };
    };

    const handleLsbDecode = () => {
        if (!selectedImage) {
            toast('Please select an image to decode', 'error');
            return;
        }

        const img = new Image();
        img.src = imagePreview; // In real usage, this would be the uploaded encoded image
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const data = imgData.data;

            let binary = '';
            let charPrototype = '';

            // Extract bits
            for (let i = 0; i < data.length; i += 4) {
                for (let j = 0; j < 3; j++) {
                    binary += (data[i + j] & 1).toString();
                }
            }

            // Convert to chars until null terminator
            let result = '';
            for (let i = 0; i < binary.length; i += 8) {
                const byte = binary.substr(i, 8);
                if (byte.length < 8) break;
                const charCode = parseInt(byte, 2);
                if (charCode === 0) break; // Terminator
                result += String.fromCharCode(charCode);
                // Safety break for huge images/noise
                if (result.length > 1000) break;
            }

            setLsbDecodedText(result);
            if (result) toast('LSB Data Extracted', 'success');
            else toast('No LSB data found (or failed to decode)', 'warning');
        };
    };


    // --- UTILS: ANALYSIS ---
    const handleImageUpload = (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
            setImagePreview(event.target.result);
            setSelectedImage(file);
            // Reset LSB states
            setLsbEncodedImage(null);
            setLsbDecodedText('');

            setAnalysisResult({
                name: file.name,
                type: file.type,
                size: (file.size / 1024).toFixed(2) + ' KB',
                lastModified: new Date(file.lastModified).toLocaleString()
            });

            // Auto-generate Hex Dump (first 200 bytes)
            const hexReader = new FileReader();
            hexReader.onload = (e) => {
                const buffer = new Uint8Array(e.target.result);
                let hex = '';
                for (let i = 0; i < Math.min(buffer.length, 500); i++) {
                    hex += buffer[i].toString(16).padStart(2, '0') + ' ';
                }
                setHexDump(hex);
            };
            hexReader.readAsArrayBuffer(file);
        };
        reader.readAsDataURL(file);
    };

    // --- RENDER ---
    return (
        <div className="min-h-screen bg-dark-900 text-gray-100 p-6 space-y-8 animate-fade-in pb-24">

            {/* HEADER */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-white/10 pb-6">
                <div className="space-y-2">
                    <h1 className="text-4xl font-black italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-r from-purple-500 to-indigo-500">
                        STEGO ANALYST
                    </h1>
                    <p className="text-white/40 font-mono tracking-widest uppercase text-sm">
                        Hidden Data Extraction & Injection Suite
                    </p>
                </div>
                <div className="flex gap-4">
                    <div className="px-4 py-2 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 font-mono text-xs">
                        TOOLS ACTIVE
                    </div>
                </div>
            </div>

            {/* NAV */}
            <div className="flex gap-2 p-1 bg-white/5 rounded-xl w-fit overflow-x-auto">
                {[
                    { id: 'analyze', label: 'File Analysis', icon: Search },
                    { id: 'lsb', label: 'LSB Studio', icon: Layers }, // New LSB Tab
                    { id: 'text', label: 'Hidden Text', icon: FileText },
                    { id: 'challenges', label: 'Training Lab', icon: Zap },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-6 py-2 rounded-lg font-bold uppercase text-sm transition-all whitespace-nowrap ${activeTab === tab.id
                            ? 'bg-purple-500 text-white shadow-lg shadow-purple-500/20'
                            : 'text-gray-400 hover:text-white hover:bg-white/5'
                            }`}
                    >
                        <tab.icon size={16} /> {tab.label}
                    </button>
                ))}
            </div>

            <AnimatePresence mode="wait">

                {/* TAB: ANALYSIS */}
                {activeTab === 'analyze' && (
                    <motion.div
                        key="analyze"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                    >
                        <div className="space-y-6">
                            <div className="p-8 rounded-2xl bg-white/5 border border-dashed border-white/20 hover:border-purple-500 text-center transition-colors cursor-pointer relative"
                                onClick={() => document.getElementById('file-upload').click()}>
                                <input type="file" id="file-upload" className="hidden" onChange={handleImageUpload} accept="image/*" />
                                <div className="space-y-4">
                                    <div className="w-16 h-16 rounded-full bg-purple-500/10 flex items-center justify-center mx-auto text-purple-400">
                                        <Upload size={32} />
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-white text-lg">Upload Media for Analysis</h3>
                                        <p className="text-sm text-gray-500">Supports PNG, JPG, BMP (Max 5MB)</p>
                                    </div>
                                </div>
                            </div>

                            {imagePreview && (
                                <div className="p-4 rounded-2xl bg-black/40 border border-white/5">
                                    <img src={imagePreview} alt="Analysis Target" className="max-h-[400px] mx-auto rounded-lg" />
                                </div>
                            )}
                        </div>

                        <div className="space-y-6">
                            {analysisResult ? (
                                <>
                                    <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                            <ImageIcon size={20} className="text-pink-500" /> Basic Metadata
                                        </h3>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="p-3 rounded-lg bg-black/20">
                                                <span className="text-[10px] uppercase font-bold text-gray-500">Filename</span>
                                                <div className="font-mono text-sm text-white truncate">{analysisResult.name}</div>
                                            </div>
                                            <div className="p-3 rounded-lg bg-black/20">
                                                <span className="text-[10px] uppercase font-bold text-gray-500">Size</span>
                                                <div className="font-mono text-sm text-yellow-400">{analysisResult.size}</div>
                                            </div>
                                            <div className="p-3 rounded-lg bg-black/20">
                                                <span className="text-[10px] uppercase font-bold text-gray-500">MIME Type</span>
                                                <div className="font-mono text-sm text-blue-400">{analysisResult.type}</div>
                                            </div>
                                            <div className="p-3 rounded-lg bg-black/20">
                                                <span className="text-[10px] uppercase font-bold text-gray-500">Modified</span>
                                                <div className="font-mono text-sm text-gray-300 text-[10px]">{analysisResult.lastModified}</div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="p-6 rounded-2xl bg-white/5 border border-white/10 flex-1 flex flex-col min-h-[300px]">
                                        <div className="flex justify-between items-center mb-4">
                                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                                <FileCode size={20} className="text-green-500" /> Hex Dump (Header)
                                            </h3>
                                        </div>
                                        <div className="flex-1 bg-black/50 rounded-xl p-4 font-mono text-xs text-green-500/80 overflow-y-auto max-h-[300px] break-all border border-white/5 scrollbar-cyber">
                                            {hexDump}
                                        </div>
                                    </div>
                                </>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-gray-600 border border-white/5 rounded-2xl bg-white/5 p-8">
                                    <Search size={48} className="mb-4 opacity-20" />
                                    <p>Select a file to extract metadata and view hex structure</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* TAB: LSB STUDIO */}
                {activeTab === 'lsb' && (
                    <motion.div
                        key="lsb"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="grid grid-cols-1 lg:grid-cols-2 gap-8"
                    >
                        <div className="space-y-6">
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                <h3 className="text-xl font-bold text-purple-400 flex items-center gap-2">
                                    <Edit3 size={20} /> Inject Data (Encode)
                                </h3>

                                {!selectedImage ? (
                                    <div className="text-sm text-gray-500 italic p-4 border border-dashed border-white/10 rounded-xl">
                                        Please upload an image in the "File Analysis" tab first.
                                    </div>
                                ) : (
                                    <>
                                        <div>
                                            <label className="text-xs font-bold text-gray-500 uppercase">Secret Message</label>
                                            <textarea
                                                value={lsbSecret}
                                                onChange={e => setLsbSecret(e.target.value)}
                                                className="w-full h-24 bg-black/20 border border-white/10 rounded-xl p-3 resize-none focus:outline-none focus:border-purple-500/50"
                                                placeholder="Enter text to hide inside image..."
                                            />
                                        </div>
                                        <button
                                            onClick={handleLsbEncode}
                                            className="w-full py-3 bg-purple-600 rounded-xl font-bold uppercase hover:bg-purple-500 hover:scale-[1.02] transition-all shadow-lg shadow-purple-600/20"
                                        >
                                            Embed Message
                                        </button>
                                    </>
                                )}
                            </div>

                            {lsbEncodedImage && (
                                <div className="p-6 rounded-2xl bg-purple-900/10 border border-purple-500/30 space-y-4 animate-scale-in">
                                    <h3 className="text-lg font-bold text-white">Encoded Image Ready</h3>
                                    <img src={lsbEncodedImage} alt="Stego Result" className="rounded-lg shadow-lg border border-white/10" />
                                    <a
                                        href={lsbEncodedImage}
                                        download="stego_result.png"
                                        className="block w-full py-3 bg-white/10 text-center rounded-xl font-bold uppercase hover:bg-white/20 transition-colors"
                                    >
                                        <Download size={16} className="inline mr-2" /> Download Image
                                    </a>
                                </div>
                            )}
                        </div>

                        <div className="space-y-6">
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                                <h3 className="text-xl font-bold text-green-400 flex items-center gap-2">
                                    <Unlock size={20} /> Extract Data (Decode)
                                </h3>
                                <p className="text-sm text-gray-400">Attempts to extract LSB hidden data from the currently loaded image.</p>

                                {!selectedImage && (
                                    <div className="text-sm text-gray-500 italic p-4 border border-dashed border-white/10 rounded-xl">
                                        No image loaded. Upload a steganographic image in "File Analysis".
                                    </div>
                                )}

                                <button
                                    onClick={handleLsbDecode}
                                    disabled={!selectedImage}
                                    className="w-full py-3 bg-green-600 rounded-xl font-bold uppercase hover:bg-green-500 disabled:opacity-50 transition-colors"
                                >
                                    Scan for Hidden Data
                                </button>
                            </div>

                            {lsbDecodedText && (
                                <div className="p-6 rounded-2xl bg-green-900/10 border border-green-500/30 space-y-2 animate-slide-up">
                                    <label className="text-xs font-bold text-green-500 uppercase">Extracted Message</label>
                                    <div className="p-4 bg-black/40 rounded-xl font-mono text-green-400 break-all border border-green-500/20">
                                        {lsbDecodedText}
                                    </div>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* TAB: TEXT STEGO */}
                {activeTab === 'text' && (
                    <motion.div
                        key="text"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="grid grid-cols-1 md:grid-cols-2 gap-8"
                    >
                        {/* ENCODER */}
                        <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-6">
                            <h3 className="text-xl font-bold text-blue-400 flex items-center gap-2">
                                <Lock size={20} /> Text Encoder (ZWCI)
                            </h3>
                            <p className="text-sm text-gray-400">Uses Zero-Width Characters to hide invisible messages inside normal text.</p>

                            <div className="space-y-4">
                                <div>
                                    <label className="text-xs font-bold text-gray-500 uppercase">Cover Text (Public)</label>
                                    <input
                                        type="text"
                                        value={coverText}
                                        onChange={(e) => setCoverText(e.target.value)}
                                        className="w-full bg-black/20 border border-white/10 rounded-xl p-3 mt-1 focus:border-blue-500/50 outline-none text-white"
                                    />
                                </div>
                                <div>
                                    <label className="text-xs font-bold text-gray-500 uppercase">Secret Message</label>
                                    <input
                                        type="text"
                                        value={secretMessage}
                                        onChange={(e) => setSecretMessage(e.target.value)}
                                        className="w-full bg-black/20 border border-white/10 rounded-xl p-3 mt-1 focus:border-red-500/50 outline-none text-red-300"
                                        placeholder="Top Secret..."
                                    />
                                </div>
                                <button
                                    onClick={encodeZeroWidth}
                                    className="w-full py-3 bg-blue-600 rounded-xl font-bold uppercase hover:bg-blue-500 transition-colors"
                                >
                                    Hide Message
                                </button>
                            </div>

                            {encodedResult && (
                                <div className="mt-4 p-4 bg-green-900/10 border border-green-500/30 rounded-xl">
                                    <div className="flex justify-between items-center mb-2">
                                        <span className="text-xs font-bold text-green-500 uppercase">Result (Contains Hidden Data)</span>
                                        <button onClick={() => { navigator.clipboard.writeText(encodedResult); toast('Copied!', 'success') }} className="p-1 hover:text-white text-gray-400">
                                            <Copy size={14} />
                                        </button>
                                    </div>
                                    <div className="font-mono text-white bg-black/20 p-2 rounded break-all">
                                        {encodedResult}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* DECODER */}
                        <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-6">
                            <h3 className="text-xl font-bold text-green-400 flex items-center gap-2">
                                <Unlock size={20} /> Text Decoder
                            </h3>
                            <p className="text-sm text-gray-400">Paste seemingly normal text to reveal hidden zero-width messages.</p>

                            <div>
                                <label className="text-xs font-bold text-gray-500 uppercase">Suspicious Text</label>
                                <textarea
                                    value={decodeInput}
                                    onChange={(e) => setDecodeInput(e.target.value)}
                                    className="w-full h-32 bg-black/20 border border-white/10 rounded-xl p-3 mt-1 focus:border-green-500/50 outline-none text-white resize-none"
                                    placeholder="Paste text here..."
                                />
                            </div>
                            <button
                                onClick={decodeZeroWidth}
                                className="w-full py-3 bg-green-600 rounded-xl font-bold uppercase hover:bg-green-500 transition-colors"
                            >
                                Extract Hidden Data
                            </button>

                            {decodedResult && (
                                <div className="mt-4 p-4 bg-yellow-900/10 border border-yellow-500/30 rounded-xl animate-scale-in">
                                    <span className="text-xs font-bold text-yellow-500 uppercase block mb-2">Extracted Message</span>
                                    <div className="font-mono text-xl text-yellow-400 font-bold">
                                        {decodedResult}
                                    </div>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* TAB: CHALLENGES */}
                {activeTab === 'challenges' && (
                    <motion.div
                        key="challenges"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="space-y-6"
                    >
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {CHALLENGES.map(c => (
                                <div key={c.id} className="p-6 rounded-2xl bg-white/5 border border-white/10 relative group hover:border-purple-500/50 transition-colors">
                                    <h3 className="font-bold text-white text-lg mb-2">{c.name}</h3>
                                    <div className="flex gap-2 mb-4">
                                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-white/10 text-gray-300">{c.category}</span>
                                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-yellow-500/20 text-yellow-400">{c.points} PTS</span>
                                    </div>
                                    <p className="text-sm text-gray-400 mb-6">{c.description}</p>

                                    <div className="p-3 bg-black/30 rounded-lg text-xs text-gray-500 italic mb-4">
                                        <AlertCircle size={12} className="inline mr-1" /> Hint: {c.hint}
                                    </div>

                                    {solvedChallenges.includes(c.id) ? (
                                        <div className="absolute top-4 right-4 text-green-500">
                                            <CheckCircle size={24} />
                                        </div>
                                    ) : (
                                        <button className="w-full py-2 rounded-lg bg-purple-600/20 text-purple-400 hover:bg-purple-600 hover:text-white transition-all text-sm font-bold uppercase">
                                            Start Challenge
                                        </button>
                                    )}
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default StegoAnalyst;
