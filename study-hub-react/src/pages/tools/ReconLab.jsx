import React, { useState, useEffect, useRef } from 'react';
import {
    Radar, Search, Crosshair, Terminal, Network, List, Book,
    Zap, Globe, Server, AlertTriangle, FileText, Play, Copy,
    Bot, Activity, Shield, Hash, Cloud, Database,
    Bug, Link, FileCode, CheckSquare
} from 'lucide-react';

const ReconLab = () => {
    // --- STATE ---
    const [target, setTarget] = useState('example.com');
    const [activeTab, setActiveTab] = useState('subdomain');
    const [terminalOutput, setTerminalOutput] = useState([]);
    const [isScanning, setIsScanning] = useState(false);
    const [aiAnalysis, setAiAnalysis] = useState(null);
    const [realMode, setRealMode] = useState(false);
    const terminalEndRef = useRef(null);

    // --- DATA ---
    const tools = {
        subdomain: {
            icon: Globe, items: [
                { name: 'Subfinder', cmd: 'subfinder -d {DOMAIN} -all -o subdomains.txt', desc: 'Fast passive subdomain enum' },
                { name: 'Amass', cmd: 'amass enum -passive -d {DOMAIN} -o amass.txt', desc: 'In-depth discovery' },
                { name: 'Assetfinder', cmd: 'assetfinder --subs-only {DOMAIN} | tee assetfinder.txt', desc: 'Quick subdomain finding' },
                { name: 'Findomain', cmd: 'findomain -t {DOMAIN} -o', desc: 'Cross-platform enum' }
            ]
        },
        portscan: {
            icon: Activity, items: [
                { name: 'Nmap Quick', cmd: 'nmap -sC -sV -T4 {IP} -oA quick', desc: 'Quick version scan' },
                { name: 'Nmap Full TCP', cmd: 'nmap -p- -T4 {IP} -oA full_tcp', desc: 'All 65535 TCP ports' },
                { name: 'Masscan', cmd: 'masscan -p1-65535 {IP} --rate=1000 -oL masscan.txt', desc: 'Ultra-fast scanning' },
                { name: 'Rustscan', cmd: 'rustscan -a {IP} -- -sC -sV', desc: 'Fast port discovery' }
            ]
        },
        alive: {
            icon: Zap, items: [
                { name: 'httpx', cmd: 'cat subdomains.txt | httpx -silent -threads 100 -o alive.txt', desc: 'Fast URL prober' },
                { name: 'httprobe', cmd: 'cat subdomains.txt | httprobe -c 50 > alive.txt', desc: 'HTTP/HTTPS prober' },
                { name: 'Aquatone', cmd: 'cat alive.txt | aquatone -out aquatone/', desc: 'Visual recon' }
            ]
        },
        urls: {
            icon: Link, items: [
                { name: 'Waybackurls', cmd: 'echo {DOMAIN} | waybackurls | tee wayback.txt', desc: 'Archive URL fetch' },
                { name: 'GAU', cmd: 'echo {DOMAIN} | gau --threads 5 | tee gau.txt', desc: 'Get all URLs' },
                { name: 'Katana', cmd: 'katana -u {DOMAIN} -d 3 -o katana.txt', desc: 'Next-gen crawler' },
                { name: 'ParamSpider', cmd: 'python paramspider.py -d {DOMAIN}', desc: 'Parameter discovery' }
            ]
        },
        vulnscan: {
            icon: Bug, items: [
                { name: 'Nuclei Critical', cmd: 'nuclei -l alive.txt -s critical,high -o critical.txt', desc: 'High severity templates' },
                { name: 'Nuclei CVEs', cmd: 'nuclei -l alive.txt -t cves/ -o cve.txt', desc: 'CVE check' },
                { name: 'Nikto', cmd: 'nikto -h https://{DOMAIN} -o nikto.txt', desc: 'Web server scanner' },
                { name: 'Dalfox', cmd: 'dalfox file params.txt -o xss.txt', desc: 'XSS scanner' }
            ]
        },
        fuzzing: {
            icon: FileText, items: [
                { name: 'FFUF Dir', cmd: 'ffuf -u https://{DOMAIN}/FUZZ -w wordlist.txt -mc 200', desc: 'Directory brute' },
                { name: 'Gobuster', cmd: 'gobuster dir -u https://{DOMAIN} -w wordlist.txt -t 50', desc: 'Directory brute' },
                { name: 'FFUF VHost', cmd: "ffuf -u https://{DOMAIN} -H 'Host: FUZZ.{DOMAIN}' -w vhosts.txt", desc: 'VHost discovery' }
            ]
        },
        js: {
            icon: FileCode, items: [
                { name: 'GetJS', cmd: 'echo https://{DOMAIN} | getJS --complete', desc: 'Extract JS files' },
                { name: 'LinkFinder', cmd: 'python linkfinder.py -i https://{DOMAIN} -d', desc: 'Find links in JS' },
                { name: 'SecretFinder', cmd: 'python SecretFinder.py -i https://{DOMAIN}/app.js -o cli', desc: 'Secrets in JS' }
            ]
        },
        cloud: {
            icon: Cloud, items: [
                { name: 'S3Scanner', cmd: 'python s3scanner.py sites.txt', desc: 'S3 bucket finder' },
                { name: 'CloudEnum', cmd: 'python cloudenum.py -k {DOMAIN}', desc: 'Multi-cloud enum' }
            ]
        }
    };

    // Reference Data (Nmap, Nuclei, Wordlists, OneLiners)
    const referenceTools = {
        nmap: {
            title: 'Nmap Scripts', items: [
                { name: 'SMB Enum', cmd: 'nmap --script smb-enum-shares -p 445 {IP}' },
                { name: 'HTTP Vuln', cmd: 'nmap --script "http-vuln-*" -p 80,443 {IP}' },
                { name: 'Vulnerability', cmd: 'nmap --script vuln {IP}' }
            ]
        },
        nuclei: {
            title: 'Nuclei Templates', items: [
                { name: 'Log4Shell', cmd: 'nuclei -t cves/2021/CVE-2021-44228.yaml -u {DOMAIN}' },
                { name: 'Spring4Shell', cmd: 'nuclei -t cves/2022/CVE-2022-22965.yaml -u {DOMAIN}' },
                { name: 'Exposed Panels', cmd: 'nuclei -t exposed-panels/ -u {DOMAIN}' }
            ]
        },
        wordlists: {
            title: 'Wordlists', items: [
                { name: 'Dir Medium', cmd: '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt' },
                { name: 'Subdomains', cmd: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt' },
                { name: 'RockYou', cmd: '/usr/share/wordlists/rockyou.txt' }
            ]
        },
        oneliners: {
            title: 'One-Liners', items: [
                { name: 'Quick Recon', cmd: 'echo {DOMAIN} | subfinder -silent | httpx -silent -tech-detect' },
                { name: 'XSS Hunt', cmd: "echo {DOMAIN} | gau | grep '=' | dalfox pipe" },
                { name: 'Open Redirect', cmd: "waybackurls {DOMAIN} | grep -E '(url=|redirect=|next=)'" }
            ]
        }
    };

    const methodology = [
        'Scope Definition: Define target scope, ranges, and rules.',
        'Subdomain Enumeration: Passive (Subfinder) & Active (Brute force).',
        'Port Scanning: Identification of open ports and services.',
        'Service Enumeration: Deep dive into specific services (HTTP, SMB).',
        'Content Discovery: Directory fuzzing and URL gathering.',
        'Vulnerability Scanning: Automated checks (Nuclei) and manual testing.',
        'Manual Exploitation: Business logic, IDOR, Auth bypass.'
    ];



    // --- ACTIONS ---
    // --- REAL WORLD API ACTIONS ---
    const runRealScan = async () => {
        if (!target) return;
        setIsScanning(true);
        setTerminalOutput(prev => [...prev, `root@kali:~# Starting REAL scan on ${target}...`]);

        try {
            // 1. Subdomain Enum via CRT.SH
            setTerminalOutput(prev => [...prev, `[+] Querying crt.sh for certificates...`]);
            const res = await fetch(`https://crt.sh/?q=${target}&output=json`);
            if (!res.ok) throw new Error('CRT.SH API failed');
            const data = await res.json();

            const subdomains = [...new Set(data.map(entry => entry.name_value.split('\n')).flat())];
            setTerminalOutput(prev => [...prev, `[+] Found ${subdomains.length} real subdomains:`]);
            subdomains.slice(0, 5).forEach(sub => setTerminalOutput(prev => [...prev, `    > ${sub}`]));
            if (subdomains.length > 5) setTerminalOutput(prev => [...prev, `    ...and ${subdomains.length - 5} more.`]);

            // 2. IP Geolocation (if target is IP or resolved)
            // Note: In client-side browser, we might have CORS issues with some APIs.
            // Using a simple no-cors check or assuming a backend proxy would be better for some.
            // For now, we stick to CRT.SH as it often allows CORS or we handle error gracefully.

            setAiAnalysis({
                critical: [`${subdomains.length} exposed subdomains found via Certificate Transparency.`],
                info: [`Target: ${target}`, `First 5 subdomains: ${subdomains.slice(0, 5).join(', ')}`]
            });

        } catch (e) {
            setTerminalOutput(prev => [...prev, `[!] Error during real scan: ${e.message}`, `[!] Falling back to simulation...`]);
            // Fallback?
        }

        setIsScanning(false);
    };
    // ------------------------------

    const runTerminalCmd = (cmdTemplate) => {
        if (isScanning) return;

        if (realMode && (activeTab === 'subdomain' || activeTab === 'alive')) {
            runRealScan();
            return;
        }

        const cmd = cmdTemplate.replace('{DOMAIN}', target).replace('{IP}', target); // Simple Replace

        setIsScanning(true);
        setTerminalOutput(prev => [...prev, `root@kali:~# ${cmd}`]);

        const steps = [
            'Initializing scan modules...',
            `Resolving target ${target}...`,
            '[+] Target is up (latency: 24ms)',
            'Enumerating assets...',
            'Found: admin.' + target + ' (Status: 200)',
            'Found: dev.' + target + ' (Status: 403)',
            'Found: api.' + target + ' (Status: 200)',
            'Analyzing results...',
            '[!] Potential vulnerability detected on api.' + target,
            'Scan completed successfully.'
        ];

        let i = 0;
        const interval = setInterval(() => {
            if (i >= steps.length) {
                clearInterval(interval);
                setIsScanning(false);
                setTerminalOutput(prev => [...prev, '', 'root@kali:~# ']);
                analyzeResults();
            } else {
                setTerminalOutput(prev => [...prev, steps[i++]]);
            }
        }, 600);
    };

    const analyzeResults = () => {
        // Simulate AI Analysis
        setAiAnalysis({
            critical: [`Possible IDOR on api.${target}/v1/user/123`, `Exposed .env file on dev.${target}`],
            info: [`Technology: Nginx 1.18.0, React`, `3 Subdomains Discovered`]
        });
    };

    const copyToClipboard = (text) => {
        const cmd = text.replace('{DOMAIN}', target).replace('{IP}', target);
        navigator.clipboard.writeText(cmd);
    };

    useEffect(() => {
        if (terminalEndRef.current) {
            terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [terminalOutput]);

    return (
        <div className="h-full flex flex-col p-6 max-w-[1800px] mx-auto overflow-hidden">
            {/* Header */}
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-500 flex items-center gap-3">
                        <Radar className="w-8 h-8 text-blue-400" />
                        Recon Lab <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded ml-2 border border-blue-500/30">V2.0</span>
                    </h1>
                    <p className="text-gray-400 text-sm">Automated Reconnaissance & Asset Intelligence</p>
                </div>
                <div className="flex items-center gap-4 bg-gray-900/50 p-2 rounded-xl border border-white/10">
                    <button
                        onClick={() => setRealMode(!realMode)}
                        className={`px-3 py-1 rounded-lg text-xs font-black uppercase tracking-widest transition-all ${realMode ? 'bg-red-500 text-white animate-pulse' : 'bg-gray-700 text-gray-400'}`}
                    >
                        {realMode ? 'LIVE MODE' : 'SIMULATION'}
                    </button>
                    <Crosshair className="w-5 h-5 text-red-400 ml-2" />
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="bg-transparent text-white font-mono outline-none w-64"
                        placeholder="Target Domain / IP"
                    />
                </div>
            </div>

            <div className="flex-1 flex gap-6 min-h-0">
                {/* Sidebar Navigation */}
                <div className="w-64 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl overflow-y-auto custom-scrollbar flex flex-col">
                    <div className="p-4 text-xs font-bold text-gray-500 uppercase tracking-widest">Tool Categories</div>
                    {Object.entries(tools).map(([key, cat]) => (
                        <button
                            key={key}
                            onClick={() => setActiveTab(key)}
                            className={`flex items-center gap-3 px-4 py-3 text-sm font-bold transition-all border-l-2 ${activeTab === key
                                ? 'border-cyan-400 bg-white/5 text-cyan-400'
                                : 'border-transparent text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            <cat.icon className="w-4 h-4" />
                            <span className="capitalize">{key}</span>
                        </button>
                    ))}
                    <div className="my-2 border-t border-white/5 mx-4"></div>
                    <div className="p-4 text-xs font-bold text-gray-500 uppercase tracking-widest">Reference</div>
                    {Object.keys(referenceTools).map(key => (
                        <button
                            key={key}
                            onClick={() => setActiveTab(key)}
                            className={`flex items-center gap-3 px-4 py-3 text-sm font-bold transition-all border-l-2 ${activeTab === key
                                ? 'border-purple-400 bg-white/5 text-purple-400'
                                : 'border-transparent text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            <Book className="w-4 h-4" />
                            <span className="capitalize">{key}</span>
                        </button>
                    ))}
                    <button
                        onClick={() => setActiveTab('methodology')}
                        className={`flex items-center gap-3 px-4 py-3 text-sm font-bold transition-all border-l-2 ${activeTab === 'methodology'
                            ? 'border-green-400 bg-white/5 text-green-400'
                            : 'border-transparent text-gray-400 hover:text-white hover:bg-white/5'
                            }`}
                    >
                        <List className="w-4 h-4" />
                        <span>Methodology</span>
                    </button>
                    <button
                        onClick={() => setActiveTab('graph')}
                        className={`flex items-center gap-3 px-4 py-3 text-sm font-bold transition-all border-l-2 ${activeTab === 'graph'
                            ? 'border-orange-400 bg-white/5 text-orange-400'
                            : 'border-transparent text-gray-400 hover:text-white hover:bg-white/5'
                            }`}
                    >
                        <Network className="w-4 h-4" />
                        <span>Asset Graph</span>
                    </button>
                </div>

                {/* Main Content */}
                <div className="flex-1 flex flex-col gap-6">
                    {/* Tool View */}
                    <div className="flex-1 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl p-6 overflow-y-auto custom-scrollbar">
                        {tools[activeTab] && (
                            <div className="animate-fadeIn">
                                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2 capitalize">
                                    {React.createElement(tools[activeTab].icon, { className: 'w-6 h-6 text-cyan-400' })}
                                    {activeTab} Tools
                                </h2>
                                <div className="grid grid-cols-1 gap-4">
                                    {tools[activeTab].items.map((tool, i) => (
                                        <div key={i} className="bg-black/40 border border-white/5 rounded-lg p-4 group hover:border-cyan-500/30 transition-all">
                                            <div className="flex justify-between items-center mb-2">
                                                <h3 className="font-bold text-white">{tool.name}</h3>
                                                <span className="text-xs text-gray-500">{tool.desc}</span>
                                            </div>
                                            <div className="flex gap-2">
                                                <code className="flex-1 bg-black/60 p-3 rounded text-sm font-mono text-cyan-500/90 break-all border border-transparent group-hover:border-cyan-500/10">
                                                    {tool.cmd.replace('{DOMAIN}', target).replace('{IP}', target)}
                                                </code>
                                                <button
                                                    onClick={() => copyToClipboard(tool.cmd)}
                                                    className="p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-400 hover:text-white transition-colors"
                                                    title="Copy Command"
                                                >
                                                    <Copy className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={() => runTerminalCmd(tool.cmd)}
                                                    className="p-3 bg-cyan-600/20 hover:bg-cyan-600/40 border border-cyan-500/30 rounded-lg text-cyan-400 transition-colors"
                                                    title="Run in Terminal"
                                                >
                                                    <Play className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Reference Tools View */}
                        {referenceTools[activeTab] && (
                            <div className="animate-fadeIn">
                                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                                    <Book className="w-6 h-6 text-purple-400" />
                                    {referenceTools[activeTab].title}
                                </h2>
                                <div className="grid grid-cols-1 gap-4">
                                    {referenceTools[activeTab].items.map((item, i) => (
                                        <div key={i} className="flex items-center gap-4 bg-black/40 border border-white/5 rounded-lg p-3 group hover:border-purple-500/30 transition-all">
                                            <div className="w-32 shrink-0 font-bold text-sm text-gray-300">{item.name}</div>
                                            <code className="flex-1 text-xs font-mono text-purple-300 break-all">{item.cmd.replace('{DOMAIN}', target)}</code>
                                            <button
                                                onClick={() => copyToClipboard(item.cmd)}
                                                className="p-2 text-gray-500 hover:text-white transition-colors"
                                            >
                                                <Copy className="w-4 h-4" />
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Methodology View */}
                        {activeTab === 'methodology' && (
                            <div className="animate-fadeIn space-y-4">
                                <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                                    <List className="w-6 h-6 text-green-400" /> Recon Methodology
                                </h2>
                                {methodology.map((step, i) => (
                                    <div key={i} className="flex items-center gap-4 p-4 bg-black/40 border border-white/5 rounded-lg">
                                        <div className="w-8 h-8 rounded-full bg-green-500/20 text-green-400 flex items-center justify-center font-bold font-mono">
                                            {i + 1}
                                        </div>
                                        <p className="text-gray-300">{step}</p>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Graph View */}
                        {activeTab === 'graph' && (
                            <div className="animate-fadeIn h-full flex flex-col items-center justify-center text-center p-10 bg-black/40 border border-white/5 rounded-xl border-dashed">
                                <Network className="w-24 h-24 text-orange-400 opacity-20 mb-6" />
                                <h3 className="text-2xl font-bold text-white mb-2">Asset Graph Visualization</h3>
                                <p className="text-gray-400 max-w-md">
                                    Visualize the relationships between subdomains, IPs, and technologies.
                                    (Run a scan to populate the graph).
                                </p>
                            </div>
                        )}
                    </div>

                    {/* Terminal & Output Panel */}
                    <div className="h-[350px] flex gap-6">
                        {/* Terminal */}
                        <div className="flex-[2] bg-black/80 border border-white/10 rounded-xl flex flex-col font-mono text-sm overflow-hidden shadow-2xl">
                            <div className="bg-gray-800/80 px-4 py-2 flex justify-between items-center border-b border-white/5">
                                <span className="flex items-center gap-2 text-gray-400 text-xs">
                                    <Terminal className="w-3 h-3" /> bash - 80x24
                                </span>
                                <div className="flex gap-2">
                                    <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                                    <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                                    <div className="w-3 h-3 rounded-full bg-green-500/50"></div>
                                </div>
                            </div>
                            <div className="flex-1 p-4 overflow-y-auto custom-scrollbar text-gray-300 space-y-1">
                                {terminalOutput.length === 0 && <div className="text-gray-600">Ready for commands...</div>}
                                {terminalOutput.map((line, i) => (
                                    <div key={i} className={line.startsWith('root') ? 'text-green-400 font-bold' : ''}>{line}</div>
                                ))}
                                <div ref={terminalEndRef} />
                            </div>
                        </div>

                        {/* AI Analysis */}
                        <div className="flex-1 bg-gray-900/50 backdrop-blur-sm border border-white/10 rounded-xl p-4 flex flex-col">
                            <h3 className="font-bold text-purple-400 flex items-center gap-2 mb-4">
                                <Bot className="w-4 h-4" /> Analysis
                            </h3>
                            <div className="flex-1 overflow-y-auto custom-scrollbar">
                                {aiAnalysis ? (
                                    <div className="space-y-4 animate-fadeIn">
                                        <div>
                                            <h4 className="text-xs font-bold text-red-400 uppercase mb-2">Critical Issues</h4>
                                            <ul className="list-disc pl-4 space-y-1">
                                                {aiAnalysis.critical.map((issue, i) => (
                                                    <li key={i} className="text-xs text-gray-300">{issue}</li>
                                                ))}
                                            </ul>
                                        </div>
                                        <div>
                                            <h4 className="text-xs font-bold text-blue-400 uppercase mb-2">Info</h4>
                                            <ul className="list-disc pl-4 space-y-1">
                                                {aiAnalysis.info.map((info, i) => (
                                                    <li key={i} className="text-xs text-gray-400">{info}</li>
                                                ))}
                                            </ul>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="h-full flex flex-col items-center justify-center text-center text-gray-500 opacity-50">
                                        <Bot className="w-12 h-12 mb-2" />
                                        <p className="text-xs">Run a scan to generate AI insights</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReconLab;
