import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Cloud, Server, Shield, Database,
    Lock, Unlock, AlertTriangle, Terminal,
    Play, RotateCcw, FileJson, Check, ExternalLink,
    Code, Search, Activity, Cpu, Globe, Key,
    Info, BookOpen, Fingerprint, Zap
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';

const CloudSecurityPro = () => {
    const { toast } = useToast();
    const [activeTab, setActiveTab] = useState('aws'); // aws, azure, library, imds
    const [activeSubTab, setActiveSubTab] = useState('iam'); // iam, s3, lambda (for AWS)

    // --- SHARED STATE ---
    const [terminalOutput, setTerminalOutput] = useState([
        { type: 'info', content: 'Cloud Security Pro v2.5 Initialized...' },
        { type: 'info', content: 'Ready for professional cloud auditing.' }
    ]);

    const addToTerminal = (content, type = 'cmd') => {
        setTerminalOutput(prev => [...prev, { type, content, timestamp: new Date().toLocaleTimeString() }].slice(-50));
    };

    // --- AWS: IAM PRIVESC STATE ---
    const [iamPolicy, setIamPolicy] = useState(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "ec2:RunInstances"
      ],
      "Resource": "*"
    }
  ]
}`);
    const [iamFindings, setIamFindings] = useState(null);

    // --- AWS: S3 HUNTER STATE ---
    const [s3Target, setS3Target] = useState('');
    const [s3Results, setS3Results] = useState([]);
    const [isScanning, setIsScanning] = useState(false);

    // --- AZURE STATE ---
    const [azureSubTab, setAzureSubTab] = useState('entra'); // entra, identity

    // === LOGIC: AWS IAM AUDIT ===
    const auditIAMPolicy = () => {
        try {
            const policy = JSON.parse(iamPolicy);
            const findings = [];
            const statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];

            const privEscPatterns = [
                {
                    actions: ['iam:PassRole', 'ec2:RunInstances'],
                    risk: 'CRITICAL',
                    title: 'Direct PrivEsc: EC2 PassRole',
                    desc: 'Allows an attacker to create an EC2 instance with a high-privilege role attached and then access that role from the instance.'
                },
                {
                    actions: ['iam:CreateAccessKey'],
                    risk: 'HIGH',
                    title: 'Persistence: Access Key Creation',
                    desc: 'Allows creating new permanent credentials for any user.'
                },
                {
                    actions: ['lambda:UpdateFunctionCode'],
                    risk: 'HIGH',
                    title: 'PrivEsc: Lambda Code Injection',
                    desc: 'Allows modifying existing Lambda functions to execute malicious code with the function\'s role.'
                },
                {
                    actions: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
                    risk: 'CRITICAL',
                    title: 'Backdoor: Role Trust Policy Update',
                    desc: 'Allows an attacker to modify who can assume a role, potentially granting themselves access.'
                }
            ];

            statements.forEach(st => {
                if (st.Effect === 'Allow') {
                    const actions = Array.isArray(st.Action) ? st.Action : [st.Action];

                    privEscPatterns.forEach(pattern => {
                        const matches = pattern.actions.every(pAct =>
                            actions.some(a => a === pAct || a === '*' || (a.includes('*') && pAct.startsWith(a.split('*')[0])))
                        );
                        if (matches) {
                            findings.push(pattern);
                        }
                    });

                    if (actions.includes('*')) {
                        findings.push({
                            risk: 'CRITICAL',
                            title: 'Full Admin Access',
                            desc: 'Wildcard Action allows all operations in the cloud environment.'
                        });
                    }
                }
            });

            setIamFindings(findings);
            addToTerminal(`IAM Audit complete. Found ${findings.length} critical issues.`, 'warn');
            toast(findings.length > 0 ? 'Attack vectors identified!' : 'No major issues found.', findings.length > 0 ? 'warning' : 'success');
        } catch (e) {
            toast('Invalid JSON format', 'error');
        }
    };

    // === LOGIC: S3 HUNTER ===
    const runS3ProHunter = () => {
        if (!s3Target) return toast('Enter target name', 'error');
        setIsScanning(true);
        setS3Results([]);
        addToTerminal(`Initiating Pro-S3 Enumeration for: ${s3Target}`);

        const suffixes = ['', '-prod', '-dev', '-public', '-backup', '-assets', '-logs', '-sql', '-internal', '-staging'];
        let idx = 0;

        const interval = setInterval(() => {
            if (idx >= suffixes.length) {
                clearInterval(interval);
                setIsScanning(false);
                addToTerminal('S3 Hunter Finished.', 'success');
                return;
            }
            const bucketName = `${s3Target}${suffixes[idx]}`;
            const url = `https://${bucketName}.s3.amazonaws.com`;

            // Simulation of "Real" check (usually requires proxy or CLI)
            // In Pro tool, we show the command used to verify
            setS3Results(prev => [...prev, { name: bucketName, url, status: 'PROBE' }]);
            idx++;
        }, 300);
    };

    // --- RENDERERS ---

    const renderAWS = () => (
        <div className="space-y-6">
            <div className="flex gap-4 border-b border-white/5 pb-4">
                {['iam', 's3', 'imds'].map(s => (
                    <button
                        key={s}
                        onClick={() => setActiveSubTab(s)}
                        className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${activeSubTab === s ? 'bg-primary-500/10 text-primary-500' : 'text-gray-500 hover:text-white'}`}
                    >
                        {s.toUpperCase()} Operations
                    </button>
                ))}
            </div>

            {activeSubTab === 'iam' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="bg-dark-800 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-bold flex items-center gap-2">
                                <Shield className="text-primary-500" /> IAM PrivEsc Analyst
                            </h3>
                            <button onClick={auditIAMPolicy} className="px-4 py-2 bg-primary-500 text-white rounded-lg text-xs font-bold hover:bg-primary-400 transition-colors">
                                RUN ANALYSIS
                            </button>
                        </div>
                        <textarea
                            value={iamPolicy}
                            onChange={(e) => setIamPolicy(e.target.value)}
                            className="w-full h-[400px] bg-black border border-white/5 rounded-xl p-4 font-mono text-sm text-yellow-500 focus:border-primary-500/50 outline-none resize-none"
                            spellCheck="false"
                        />
                    </div>
                    <div className="bg-dark-800 border border-white/10 rounded-2xl p-6 overflow-y-auto max-h-[500px]">
                        <h3 className="text-lg font-bold mb-4">Risk Assessment</h3>
                        {!iamFindings ? (
                            <div className="flex flex-col items-center justify-center h-full text-gray-500 italic">
                                <Search size={48} className="mb-4 opacity-20" />
                                Paste policy and click Run
                            </div>
                        ) : iamFindings.length === 0 ? (
                            <div className="text-emerald-500 font-bold flex flex-col items-center justify-center h-full">
                                <Check size={48} className="mb-4" />
                                Clean Policy Detected
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {iamFindings.map((f, i) => (
                                    <motion.div
                                        initial={{ opacity: 0, y: 10 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        key={i}
                                        className={`p-4 rounded-xl border ${f.risk === 'CRITICAL' ? 'border-red-500/30 bg-red-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm font-black uppercase text-white">{f.title}</span>
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${f.risk === 'CRITICAL' ? 'bg-red-500 text-white' : 'bg-amber-500 text-black'}`}>
                                                {f.risk}
                                            </span>
                                        </div>
                                        <p className="text-xs text-gray-400 leading-relaxed">{f.desc}</p>
                                    </motion.div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {activeSubTab === 's3' && (
                <div className="bg-dark-800 border border-white/10 rounded-2xl p-6">
                    <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                        <Database className="text-primary-500" /> S3 Pro Hunter
                    </h3>
                    <div className="flex gap-4 mb-6">
                        <input
                            type="text"
                            value={s3Target}
                            onChange={(e) => setS3Target(e.target.value)}
                            className="flex-1 bg-black border border-white/10 rounded-xl px-4 py-3 font-mono text-sm focus:border-primary-500 outline-none"
                            placeholder="Target Brand (e.g. acme-corp)"
                        />
                        <button
                            onClick={runS3ProHunter}
                            disabled={isScanning}
                            className={`px-6 py-3 bg-primary-500 text-white rounded-xl font-bold flex items-center gap-2 hover:bg-primary-400 transition-all ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                            {isScanning ? 'HUNTING...' : <><Search size={18} /> START HUNTER</>}
                        </button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {s3Results.map((r, i) => (
                            <div key={i} className="p-4 bg-black/40 border border-white/5 rounded-xl hover:border-primary-500/30 transition-all group">
                                <div className="text-xs font-mono text-gray-500 mb-2 truncate">{r.name}</div>
                                <div className="flex items-center justify-between">
                                    <code className="text-[10px] text-primary-500/70">aws s3 ls s3://{r.name}</code>
                                    <button
                                        onClick={() => {
                                            navigator.clipboard.writeText(`aws s3 ls s3://${r.name} --no-sign-request`);
                                            toast('Command copied!', 'success');
                                        }}
                                        className="p-1 hover:bg-primary-500/20 rounded transition-colors"
                                    >
                                        <ExternalLink size={12} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {activeSubTab === 'imds' && (
                <div className="bg-dark-800 border border-white/10 rounded-2xl p-8">
                    <div className="max-w-3xl mx-auto space-y-8">
                        <div className="text-center space-y-2">
                            <h3 className="text-2xl font-black italic text-red-500">IMDSv2 EXPLOITATION FLOW</h3>
                            <p className="text-sm text-gray-500">Bypassing Session Tokens in Modern Cloud Environments</p>
                        </div>

                        <div className="space-y-4">
                            {[
                                { step: '1', title: 'Token Acquisition', cmd: `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")`, desc: 'The first step is to obtain a temporary session token from the Metadata Service.' },
                                { step: '2', title: 'Metadata Enumeration', cmd: `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/`, desc: 'Use the token to list available IAM roles attached to the instance.' },
                                { step: '3', title: 'Credential Extraction', cmd: `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE_NAME]`, desc: 'Dump the temporary AccessKeyId, SecretAccessKey, and SessionToken.' }
                            ].map((item, idx) => (
                                <div key={idx} className="relative pl-12 border-l border-white/5 py-4 group">
                                    <div className="absolute left-0 top-1/2 -translate-x-1/2 -translate-y-1/2 w-8 h-8 rounded-full bg-dark-900 border border-red-500/50 flex items-center justify-center text-red-500 font-bold text-sm shadow-[0_0_15px_rgba(239,68,68,0.3)]">
                                        {item.step}
                                    </div>
                                    <div className="space-y-2">
                                        <h4 className="font-bold text-white uppercase tracking-wider">{item.title}</h4>
                                        <div className="bg-black rounded-lg p-3 relative group">
                                            <code className="text-xs text-red-400 block break-all">{item.cmd}</code>
                                            <button
                                                onClick={() => {
                                                    navigator.clipboard.writeText(item.cmd);
                                                    toast('Step command copied!', 'success');
                                                }}
                                                className="absolute right-2 top-2 p-1.5 opacity-0 group-hover:opacity-100 bg-white/5 rounded transition-all"
                                            >
                                                <RotateCcw size={12} className="rotate-90" />
                                            </button>
                                        </div>
                                        <p className="text-[10px] text-gray-500 italic">{item.desc}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );

    const renderAzure = () => (
        <div className="space-y-6">
            <div className="flex gap-4 border-b border-white/5 pb-4">
                {['entra', 'identity', 'storage'].map(s => (
                    <button
                        key={s}
                        onClick={() => setAzureSubTab(s)}
                        className={`px-4 py-2 rounded-lg text-sm font-bold transition-all ${azureSubTab === s ? 'bg-cyan-500/10 text-cyan-500' : 'text-gray-500 hover:text-white'}`}
                    >
                        {s.toUpperCase()} Security
                    </button>
                ))}
            </div>

            {azureSubTab === 'entra' && (
                <div className="bg-dark-800 border border-white/10 rounded-2xl p-6">
                    <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Fingerprint className="text-cyan-500" /> Entra ID (Azure AD) Recon
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-4">
                            <p className="text-sm text-gray-400">Essential commands for enumerating Azure AD environments during internal assessments.</p>
                            <div className="space-y-2">
                                {[
                                    { label: 'List All Users', cmd: 'az ad user list --query "[].{Name:displayName, UPN:userPrincipalName}"' },
                                    { label: 'List High-Priv Groups', cmd: 'az ad group list --display-name "Admin" --query "[].displayName"' },
                                    { label: 'Current Account Info', cmd: 'az account show --output json' }
                                ].map((c, i) => (
                                    <div key={i} className="p-3 bg-black/40 border border-white/5 rounded-xl hover:border-cyan-500/30 transition-all">
                                        <div className="text-[10px] font-bold text-cyan-500 uppercase mb-1">{c.label}</div>
                                        <code className="text-xs text-white/50">{c.cmd}</code>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <div className="bg-black/60 rounded-xl p-6 border border-white/5">
                            <h4 className="text-xs font-black uppercase text-white/40 mb-4 tracking-widest">Azure PrivEsc Vectors</h4>
                            <div className="space-y-3">
                                <div className="p-3 bg-cyan-500/5 border-l-2 border-cyan-500 rounded-r-lg">
                                    <p className="text-xs font-bold text-cyan-400 underline mb-1">Owner on Service Principal</p>
                                    <p className="text-[10px] text-gray-500">Check for users with Owner/Contributor rights on Service Principals. They can create new credentials for the SP.</p>
                                </div>
                                <div className="p-3 bg-amber-500/5 border-l-2 border-amber-500 rounded-r-lg">
                                    <p className="text-xs font-bold text-amber-400 underline mb-1">Global Admin via Password Reset</p>
                                    <p className="text-[10px] text-gray-500">Users with Password Administrator role can reset passwords of some accounts, potentially leading to GA.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Additional Azure tabs would go here */}
            {azureSubTab !== 'entra' && (
                <div className="h-64 flex flex-col items-center justify-center text-gray-500 border-2 border-dashed border-white/5 rounded-2xl">
                    <Zap size={32} className="mb-2 opacity-20" />
                    <p className="text-xs font-mono uppercase tracking-widest">Integrating {azureSubTab.toUpperCase()} Pro Module...</p>
                </div>
            )}
        </div>
    );

    const renderLibrary = () => (
        <div className="bg-dark-800 border border-white/10 rounded-2xl p-6">
            <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <BookOpen className="text-emerald-500" /> Operations Command Library
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[
                    {
                        cat: 'S3 Recon', items: [
                            { label: 'List Objects', cmd: 'aws s3 ls s3://[bucket]' },
                            { label: 'Recursively Copy', cmd: 'aws s3 cp s3://[bucket] . --recursive' }
                        ]
                    },
                    {
                        cat: 'EC2 Access', items: [
                            { label: 'Describe Instances', cmd: 'aws ec2 describe-instances' },
                            { label: 'Get User Data', cmd: 'aws ec2 describe-instance-attribute --instance-id [ID] --attribute userData' }
                        ]
                    },
                    {
                        cat: 'IAM & Secrets', items: [
                            { label: 'Get Secret Value', cmd: 'aws secretsmanager get-secret-value --secret-id [ID]' },
                            { label: 'List Policies', cmd: 'aws iam list-attached-user-policies --user-name [Name]' }
                        ]
                    }
                ].map((group, idx) => (
                    <div key={idx} className="space-y-4">
                        <h4 className="text-xs font-black text-gray-500 uppercase tracking-widest border-b border-white/5 pb-2">{group.cat}</h4>
                        {group.items.map((item, i) => (
                            <div key={i} className="p-3 bg-black border border-white/5 rounded-xl hover:border-emerald-500/30 transition-all cursor-pointer"
                                onClick={() => {
                                    navigator.clipboard.writeText(item.cmd);
                                    toast('Command copied!', 'success');
                                }}>
                                <div className="text-[10px] font-bold text-emerald-500 mb-1">{item.label}</div>
                                <code className="text-[10px] text-white/40 block leading-tight">{item.cmd}</code>
                            </div>
                        ))}
                    </div>
                ))}
            </div>
        </div>
    );

    return (
        <div className="max-w-7xl mx-auto space-y-8 animate-fade-in pb-20">
            {/* HERO */}
            <div className="relative overflow-hidden rounded-[3rem] bg-gradient-to-br from-dark-800 via-dark-900 to-black border border-white/10 p-12">
                <div className="absolute top-0 right-0 p-8 opacity-10">
                    <Cloud size={240} className="text-primary-500" />
                </div>

                <div className="relative z-10 space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-widest animate-pulse">
                            Professional Tier v2.5
                        </div>
                        <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]" />
                        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Systems Active</span>
                    </div>

                    <h1 className="text-6xl font-black italic tracking-tighter leading-none">
                        CLOUD <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary-500 to-accent-500">SECURITY PRO</span>
                    </h1>
                    <p className="text-gray-400 max-w-xl text-lg font-medium leading-relaxed">
                        Multicloud auditing & offensive operations toolkit. Hardened for real-world assessments and junior operative field training.
                    </p>
                </div>
            </div>

            {/* MAIN NAVIGATION */}
            <div className="flex flex-wrap gap-3 justify-center">
                {[
                    { id: 'aws', label: 'AWS Operations', icon: Cloud, color: 'text-orange-500' },
                    { id: 'azure', label: 'Azure Core', icon: Cpu, color: 'text-cyan-500' },
                    { id: 'library', label: 'Command Library', icon: BookOpen, color: 'text-emerald-500' },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-3 px-8 py-4 rounded-2xl font-black uppercase tracking-tighter transition-all ${activeTab === tab.id
                            ? 'bg-primary-500 text-white shadow-[0_0_30px_rgba(var(--primary-rgb),0.3)] scale-105'
                            : 'bg-dark-800 text-gray-500 hover:text-white border border-white/5'}`}
                    >
                        <tab.icon size={20} />
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* CONTENT AREA */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="min-h-[600px]"
                >
                    {activeTab === 'aws' && renderAWS()}
                    {activeTab === 'azure' && renderAzure()}
                    {activeTab === 'library' && renderLibrary()}
                </motion.div>
            </AnimatePresence>

            {/* SYSTEM LOGS (TERMINAL) */}
            <div className="bg-dark-900 border border-white/5 rounded-3xl p-6 font-mono overflow-hidden">
                <div className="flex items-center justify-between mb-4 px-2">
                    <div className="flex items-center gap-4">
                        <div className="flex gap-1.5">
                            <div className="w-3 h-3 rounded-full bg-red-500/20" />
                            <div className="w-3 h-3 rounded-full bg-amber-500/20" />
                            <div className="w-3 h-3 rounded-full bg-emerald-500/50" />
                        </div>
                        <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Operation Logs</span>
                    </div>
                </div>
                <div className="h-48 overflow-y-auto space-y-1 px-2 scrollbar-cyber">
                    {terminalOutput.map((log, i) => (
                        <div key={i} className="text-xs flex gap-4">
                            <span className="text-gray-600 shrink-0">[{log.timestamp || 'SYSTEM'}]</span>
                            <span className={`${log.type === 'warn' ? 'text-amber-500' : log.type === 'success' ? 'text-emerald-500' : 'text-gray-400'}`}>
                                {log.content}
                            </span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default CloudSecurityPro;
