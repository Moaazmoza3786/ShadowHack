import React, { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Target, Filter, Award, CheckCircle, Circle, BarChart3, Search } from 'lucide-react';

const MitreAttack = () => {
    const [learnedTechniques, setLearnedTechniques] = useState(() => {
        const saved = localStorage.getItem('mitre_progress_v2');
        return saved ? JSON.parse(saved) : [];
    });
    const [filterMode, setFilterMode] = useState('all');
    const [selectedTactic, setSelectedTactic] = useState(null);

    const tactics = [
        {
            id: 'TA0043', name: 'Reconnaissance', color: '#3498db', techniques: [
                { id: 'T1595', name: 'Active Scanning', tools: ['Nmap', 'Masscan'] },
                { id: 'T1592', name: 'Gather Victim Host Info', tools: ['Shodan', 'Censys'] },
                { id: 'T1589', name: 'Gather Victim Identity', tools: ['theHarvester'] },
                { id: 'T1593', name: 'Search Open Sources', tools: ['Maltego'] },
            ]
        },
        {
            id: 'TA0042', name: 'Resource Development', color: '#9b59b6', techniques: [
                { id: 'T1583', name: 'Acquire Infrastructure', tools: ['AWS', 'Azure'] },
                { id: 'T1587', name: 'Develop Capabilities', tools: ['msfvenom'] },
                { id: 'T1585', name: 'Establish Accounts', tools: ['ProtonMail'] },
            ]
        },
        {
            id: 'TA0001', name: 'Initial Access', color: '#e74c3c', techniques: [
                { id: 'T1566', name: 'Phishing', tools: ['Gophish', 'King Phisher'] },
                { id: 'T1190', name: 'Exploit Public Apps', tools: ['Nuclei', 'Burp'] },
                { id: 'T1133', name: 'External Remote Services', tools: ['Hydra'] },
                { id: 'T1078', name: 'Valid Accounts', tools: ['CrackMapExec'] },
            ]
        },
        {
            id: 'TA0002', name: 'Execution', color: '#f39c12', techniques: [
                { id: 'T1059', name: 'Command & Script', tools: ['PowerShell'] },
                { id: 'T1203', name: 'Exploitation for Execution', tools: ['msfconsole'] },
                { id: 'T1047', name: 'WMI', tools: ['wmic'] },
                { id: 'T1053', name: 'Scheduled Task', tools: ['schtasks'] },
            ]
        },
        {
            id: 'TA0003', name: 'Persistence', color: '#1abc9c', techniques: [
                { id: 'T1547', name: 'Boot/Logon Autostart', tools: ['Autoruns'] },
                { id: 'T1136', name: 'Create Account', tools: ['net user'] },
                { id: 'T1543', name: 'Create/Modify Service', tools: ['sc.exe'] },
                { id: 'T1505', name: 'Server Software (Web Shell)', tools: ['weevely'] },
            ]
        },
        {
            id: 'TA0004', name: 'Privilege Escalation', color: '#9b59b6', techniques: [
                { id: 'T1068', name: 'Exploit for PrivEsc', tools: ['searchsploit'] },
                { id: 'T1055', name: 'Process Injection', tools: ['Cobalt Strike'] },
                { id: 'T1548', name: 'Abuse Elevation', tools: ['UACME'] },
                { id: 'T1134', name: 'Access Token Manipulation', tools: ['Mimikatz'] },
            ]
        },
        {
            id: 'TA0005', name: 'Defense Evasion', color: '#34495e', techniques: [
                { id: 'T1070', name: 'Indicator Removal', tools: ['wevtutil'] },
                { id: 'T1036', name: 'Masquerading', tools: ['rename'] },
                { id: 'T1027', name: 'Obfuscated Files', tools: ['UPX'] },
                { id: 'T1562', name: 'Impair Defenses', tools: ['Defender Control'] },
            ]
        },
        {
            id: 'TA0006', name: 'Credential Access', color: '#e74c3c', techniques: [
                { id: 'T1003', name: 'OS Credential Dumping', tools: ['Mimikatz'] },
                { id: 'T1110', name: 'Brute Force', tools: ['Hydra'] },
                { id: 'T1558', name: 'Steal Kerberos Tickets', tools: ['Rubeus'] },
                { id: 'T1552', name: 'Unsecured Credentials', tools: ['LaZagne'] },
            ]
        },
        {
            id: 'TA0007', name: 'Discovery', color: '#3498db', techniques: [
                { id: 'T1087', name: 'Account Discovery', tools: ['net user'] },
                { id: 'T1083', name: 'File/Dir Discovery', tools: ['dir', 'ls'] },
                { id: 'T1046', name: 'Network Service Scan', tools: ['Nmap'] },
                { id: 'T1057', name: 'Process Discovery', tools: ['ps', 'tasklist'] },
            ]
        },
        {
            id: 'TA0008', name: 'Lateral Movement', color: '#e67e22', techniques: [
                { id: 'T1021', name: 'Remote Services', tools: ['psexec', 'xfreerdp'] },
                { id: 'T1550', name: 'Use Alternate Auth', tools: ['pth-winexe'] },
                { id: 'T1570', name: 'Lateral Tool Transfer', tools: ['scp'] },
            ]
        },
        {
            id: 'TA0009', name: 'Collection', color: '#16a085', techniques: [
                { id: 'T1560', name: 'Archive Collected Data', tools: ['7z', 'tar'] },
                { id: 'T1005', name: 'Data from Local System', tools: ['copy'] },
                { id: 'T1113', name: 'Screen Capture', tools: ['screenshot'] },
            ]
        },
        {
            id: 'TA0011', name: 'Command & Control', color: '#8e44ad', techniques: [
                { id: 'T1071', name: 'Application Layer Proto', tools: ['Cobalt Strike'] },
                { id: 'T1573', name: 'Encrypted Channel', tools: ['OpenSSL'] },
                { id: 'T1090', name: 'Proxy', tools: ['proxychains', 'chisel'] },
            ]
        },
        {
            id: 'TA0010', name: 'Exfiltration', color: '#c0392b', techniques: [
                { id: 'T1041', name: 'Exfil Over C2', tools: ['C2 Framework'] },
                { id: 'T1048', name: 'Exfil Over Alt Protocol', tools: ['dnscat2'] },
                { id: 'T1567', name: 'Exfil Over Web Service', tools: ['rclone'] },
            ]
        },
        {
            id: 'TA0040', name: 'Impact', color: '#2c3e50', techniques: [
                { id: 'T1485', name: 'Data Destruction', tools: ['sdelete'] },
                { id: 'T1486', name: 'Data Encrypted for Impact', tools: ['Ransomware'] },
                { id: 'T1489', name: 'Service Stop', tools: ['net stop'] },
            ]
        },
    ];

    const certMap = {
        eJPT: ['T1595', 'T1046', 'T1190', 'T1078', 'T1059', 'T1068', 'T1003', 'T1110', 'T1021'],
        OSCP: ['T1595', 'T1190', 'T1059', 'T1068', 'T1548', 'T1003', 'T1110', 'T1558', 'T1021', 'T1550', 'T1070'],
        OSEP: ['T1055', 'T1027', 'T1562', 'T1134', 'T1036', 'T1071', 'T1573'],
        CRTO: ['T1566', 'T1059', 'T1055', 'T1134', 'T1558', 'T1550', 'T1071', 'T1090'],
    };

    const totalTechniques = tactics.reduce((acc, t) => acc + t.techniques.length, 0);
    const learnedCount = learnedTechniques.length;
    const progress = Math.round((learnedCount / totalTechniques) * 100);
    const level = progress < 30 ? 'Beginner' : progress < 60 ? 'Intermediate' : progress < 85 ? 'Advanced' : 'Expert';

    const [searchTerm, setSearchTerm] = useState('');

    const toggleTechnique = (id) => {
        const updated = learnedTechniques.includes(id) ? learnedTechniques.filter(t => t !== id) : [...learnedTechniques, id];
        setLearnedTechniques(updated);
        localStorage.setItem('mitre_progress_v2', JSON.stringify(updated));
    };

    const getFilteredTechniques = (techniques) => {
        let filtered = techniques;
        if (filterMode === 'learned') filtered = techniques.filter(t => learnedTechniques.includes(t.id));
        if (filterMode === 'unlearned') filtered = techniques.filter(t => !learnedTechniques.includes(t.id));
        if (certMap[filterMode]) filtered = techniques.filter(t => certMap[filterMode].includes(t.id));

        if (searchTerm) {
            const lower = searchTerm.toLowerCase();
            filtered = filtered.filter(t => t.id.toLowerCase().includes(lower) || t.name.toLowerCase().includes(lower) || t.tools?.some(tool => tool.toLowerCase().includes(lower)));
        }

        return filtered;
    };

    return (
        <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)', color: '#e0e0e0', padding: 24, fontFamily: 'Rajdhani, sans-serif' }}>
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
                <div>
                    <h1 style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '1.8rem', color: '#fff', margin: 0 }}>
                        <Target size={32} /> MITRE ATT&CK <span style={{ background: 'linear-gradient(135deg, #e74c3c, #c0392b)', fontSize: '0.6rem', padding: '3px 8px', borderRadius: 4, color: '#fff' }}>PRO</span>
                    </h1>
                    <p style={{ color: '#888', margin: '8px 0 0' }}>Track your Red Team skills across the kill chain</p>
                </div>
                <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                    <div style={{ textAlign: 'center', padding: '12px 20px', background: 'rgba(255,255,255,0.05)', borderRadius: 10 }}>
                        <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#fff' }}>{learnedCount}</div>
                        <div style={{ fontSize: '0.75rem', color: '#888' }}>LEARNED</div>
                    </div>
                    <div style={{ textAlign: 'center', padding: '12px 20px', background: 'rgba(255,255,255,0.05)', borderRadius: 10 }}>
                        <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#00ff88' }}>{progress}%</div>
                        <div style={{ fontSize: '0.75rem', color: '#888' }}>{level}</div>
                    </div>
                </div>
            </motion.div>

            {/* Search */}
            <div style={{ marginBottom: 24 }}>
                <div style={{ position: 'relative', maxWidth: 400 }}>
                    <Search size={18} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#666' }} />
                    <input
                        type="text"
                        placeholder="Search technique ID, name, or tool (e.g. Cobalt Strike)..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{
                            width: '100%',
                            padding: '12px 12px 12px 40px',
                            background: 'rgba(255,255,255,0.05)',
                            border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: 8,
                            color: '#fff',
                            outline: 'none',
                            fontFamily: 'inherit'
                        }}
                    />
                </div>
            </div>

            {/* Filters */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 24, flexWrap: 'wrap' }}>
                {['all', 'learned', 'unlearned'].map(f => (
                    <button key={f} onClick={() => setFilterMode(f)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', background: filterMode === f ? 'rgba(0,255,136,0.15)' : 'rgba(255,255,255,0.05)', border: `1px solid ${filterMode === f ? '#00ff88' : 'rgba(255,255,255,0.1)'}`, borderRadius: 8, color: filterMode === f ? '#00ff88' : '#888', cursor: 'pointer', textTransform: 'capitalize' }}>
                        {f === 'all' ? <BarChart3 size={16} /> : f === 'learned' ? <CheckCircle size={16} /> : <Circle size={16} />} {f}
                    </button>
                ))}
                <div style={{ width: 2, height: 30, background: 'rgba(255,255,255,0.2)', margin: '0 8px' }} />
                {Object.keys(certMap).map(cert => (
                    <button key={cert} onClick={() => setFilterMode(cert)} style={{ padding: '8px 14px', background: filterMode === cert ? 'rgba(231,76,60,0.2)' : 'rgba(255,255,255,0.05)', border: `1px solid ${filterMode === cert ? '#e74c3c' : 'rgba(255,255,255,0.1)'}`, borderRadius: 8, color: filterMode === cert ? '#e74c3c' : '#888', cursor: 'pointer', fontSize: '0.85rem' }}>
                        <Award size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} /> {cert}
                    </button>
                ))}
            </div>

            {/* Matrix */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 16 }}>
                {tactics.map((tactic, ti) => {
                    const filteredTech = getFilteredTechniques(tactic.techniques);
                    const learnedInTactic = tactic.techniques.filter(t => learnedTechniques.includes(t.id)).length;
                    const tacticProgress = Math.round((learnedInTactic / tactic.techniques.length) * 100);
                    if (filteredTech.length === 0 && filterMode !== 'all') return null;
                    return (
                        <motion.div key={tactic.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: ti * 0.05 }} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 12, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div style={{ background: `linear-gradient(135deg, ${tactic.color}, ${tactic.color}99)`, padding: 16, textAlign: 'center' }}>
                                <div style={{ fontWeight: 'bold', fontSize: '0.85rem', color: '#fff', textTransform: 'uppercase', letterSpacing: 1 }}>{tactic.name}</div>
                                <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.8)', margin: '4px 0' }}>{learnedInTactic}/{tactic.techniques.length}</div>
                                <div style={{ height: 4, background: 'rgba(0,0,0,0.3)', borderRadius: 2, marginTop: 8 }}>
                                    <div style={{ height: '100%', width: `${tacticProgress}%`, background: 'rgba(255,255,255,0.8)', borderRadius: 2 }} />
                                </div>
                            </div>
                            <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 300, overflowY: 'auto' }}>
                                {filteredTech.map(tech => {
                                    const isLearned = learnedTechniques.includes(tech.id);
                                    return (
                                        <div key={tech.id} onClick={() => toggleTechnique(tech.id)} style={{ background: isLearned ? 'rgba(0,255,136,0.1)' : 'rgba(255,255,255,0.03)', padding: '10px 12px', borderRadius: 8, cursor: 'pointer', border: isLearned ? '1px solid rgba(0,255,136,0.3)' : '1px solid transparent', transition: 'all 0.2s' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <span style={{ fontSize: '0.65rem', color: '#666', fontFamily: 'JetBrains Mono, monospace' }}>{tech.id}</span>
                                                {isLearned && <CheckCircle size={14} color="#00ff88" />}
                                            </div>
                                            <div style={{ fontSize: '0.85rem', color: isLearned ? '#00ff88' : '#ccc', margin: '4px 0' }}>{tech.name}</div>
                                            <div style={{ fontSize: '0.7rem', color: '#555' }}>{tech.tools?.slice(0, 2).join(', ')}</div>
                                        </div>
                                    );
                                })}
                            </div>
                        </motion.div>
                    );
                })}
            </div>
        </div>
    );
};

export default MitreAttack;
