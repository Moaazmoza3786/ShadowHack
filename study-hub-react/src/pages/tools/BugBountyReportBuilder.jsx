import React, { useState, useRef } from "react";
import { 
  Bug, 
  Shield, 
  Search, 
  Activity, 
  FileText, 
  Terminal, 
  Copy, 
  Download, 
  Zap, 
  Plus, 
  Trash2, 
  ChevronRight, 
  ChevronLeft,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
  Code
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const SEVERITY_CONFIG = {
  Critical: { color: "text-red-500", border: "border-red-500/30", bg: "bg-red-500/10", icon: "💀", cvss: "9.0-10.0" },
  High:     { color: "text-orange-500", border: "border-orange-500/30", bg: "bg-orange-500/10", icon: "🔴", cvss: "7.0-8.9" },
  Medium:   { color: "text-yellow-500", border: "border-yellow-500/30", bg: "bg-yellow-500/10", icon: "🟡", cvss: "4.0-6.9" },
  Low:      { color: "text-blue-500", border: "border-blue-500/30", bg: "bg-blue-500/10", icon: "🔵", cvss: "0.1-3.9" },
  Info:     { color: "text-gray-400", border: "border-gray-400/30", bg: "bg-gray-400/10", icon: "⚪", cvss: "0.0" },
};

const VULN_TEMPLATES = [
  {
    type: "SQL Injection (Error-based)",
    title: "Error-based SQL Injection on [Endpoint]",
    description: "The application fails to properly sanitize the [Parameter] parameter in the [Endpoint] endpoint. By injecting a single quote or specific SQL syntax, the database returns detailed error messages containing schema information.",
    impact: "An attacker can exfiltrate the entire database schema, user credentials, and sensitive business data. In some configurations, this could lead to Remote Code Execution (RCE) via `xp_cmdshell` or `INTO OUTFILE`.",
    mitigation: "1. Use parameterized queries (Prepared Statements) for all database interactions.\n2. Implement a Web Application Firewall (WAF) to detect common SQL injection patterns.\n3. Disable detailed database error messages in production environments.",
    steps: "1. Navigate to [URL].\n2. Locate the search field or parameter '[Parameter]'.\n3. Input a payload like `' OR 1=1--` or `' UNION SELECT 1,2,3--`.\n4. Observe the database error or unauthorized data returned in the response.",
  },
  {
    type: "Stored XSS",
    title: "Stored Cross-Site Scripting (XSS) in [Feature]",
    description: "The [Feature] (e.g., user profile, comments) allows users to save data that is later rendered to other users without proper HTML encoding. An attacker can store a malicious script that executes in the context of any user viewing the page.",
    impact: "Attackers can perform session hijacking by stealing `sessionID` cookies, redirect users to malicious sites, or perform actions on behalf of the victim (CSRF-like impact).",
    mitigation: "1. Apply context-aware output encoding (e.g., HTML entity encoding) before rendering user-supplied data.\n2. Implement a strict Content Security Policy (CSP) to block inline scripts.\n3. Use libraries like DOMPurify to sanitize HTML if rendering is required.",
    steps: "1. Login to the application.\n2. Go to the [Feature] section.\n3. Submit the following payload in the [Field]: `<script>alert(document.cookie)</script>`.\n4. View the page as a different user and observe the script execution.",
  },
  {
    type: "IDOR",
    title: "Insecure Direct Object Reference (IDOR) on [Endpoint]",
    description: "The application relies on a user-provided identifier (e.g., `user_id` or `order_id`) to access records but fails to verify if the requesting user has the authority to access that specific resource.",
    impact: "Unauthorized access to sensitive data (PII), including other users' profiles, invoices, or private messages. In some cases, this leads to unauthorized modification or deletion of data.",
    mitigation: "1. Implement server-side authorization checks for every request that accesses a resource by ID.\n2. Use non-sequential, unpredictable identifiers like UUIDs (though authorization is still required).\n3. Maintain a session-based mapping of authorized resource IDs.",
    steps: "1. Authenticate as User A and view your own data at `/api/v1/user/101`.\n2. Intercept the request and change the ID to `102` (User B's ID).\n3. Observe that User B's private information is returned in the response.",
  },
  {
    type: "SSRF",
    title: "Server-Side Request Forgery (SSRF) via [Parameter]",
    description: "The application accepts a URL from the user and fetches its content without proper validation. This allows an attacker to force the server to make requests to internal services, local loopback (127.0.0.1), or cloud metadata endpoints.",
    impact: "Attackers can steal cloud environment credentials (e.g., AWS IAM roles via `169.254.169.254`), scan the internal network, or exploit internal-only services (like Redis or Memcached).",
    mitigation: "1. Use an allowlist for permitted domains and protocols (e.g., only `https://trusted.com`).\n2. Validate that the resolved IP address is not a private or loopback address.\n3. Run the fetching service in a restricted network segment (DMZ) with no access to internal assets.",
    steps: "1. Locate the feature that fetches external content (e.g., 'Import from URL').\n2. Provide the following payload: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.\n3. Observe the server returning internal metadata or cloud credentials.",
  }
];

const EMPTY_FINDING = {
  title: "", vuln_type: "", severity: "High", target_url: "",
  parameter: "", description: "", steps: "", impact: "",
  poc: "", mitigation: "", cvss_score: "",
};

export default function BugBountyReportBuilder() {
  const [step, setStep] = useState(0); // 0=meta, 1=findings, 2=preview
  const [meta, setMeta] = useState({
    program_name: "", company: "", researcher: "", date: new Date().toISOString().split("T")[0],
    scope: "", platform: "HackerOne",
  });
  const [findings, setFindings] = useState([{ ...EMPTY_FINDING, id: 1 }]);
  const [activeFinding, setActiveFinding] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingField, setLoadingField] = useState("");
  const [report, setReport] = useState(null);
  const [copied, setCopied] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);

  const updateMeta = (k, v) => setMeta(p => ({ ...p, [k]: v }));
  const updateFinding = (idx, k, v) => setFindings(p => p.map((f, i) => i === idx ? { ...f, [k]: v } : f));

  const addFinding = () => {
    setFindings(p => [...p, { ...EMPTY_FINDING, id: p.length + 1 }]);
    setActiveFinding(findings.length);
  };

  const removeFinding = (idx) => {
    if (findings.length === 1) return;
    setFindings(p => p.filter((_, i) => i !== idx));
    setActiveFinding(Math.max(0, activeFinding - 1));
  };

  const applyTemplate = (template) => {
    const f = findings[activeFinding];
    updateFinding(activeFinding, "vuln_type", template.type);
    updateFinding(activeFinding, "title", template.title);
    updateFinding(activeFinding, "description", template.description);
    updateFinding(activeFinding, "impact", template.impact);
    updateFinding(activeFinding, "mitigation", template.mitigation);
    updateFinding(activeFinding, "steps", template.steps);
    setShowTemplates(false);
  };

  const aiEnhanceField = async (idx, field) => {
    const f = findings[idx];
    if (!f.vuln_type || !f.severity) return;
    setLoadingField(`${idx}-${field}`);

    const prompts = {
      description: `Write a professional bug bounty report description for: ${f.vuln_type} (${f.severity}) on ${f.target_url || "web application"}. 2-3 clear paragraphs. Technical but readable.`,
      impact: `Write the business/security impact for a ${f.severity} ${f.vuln_type} vulnerability. Be specific about what an attacker could achieve. 2-3 sentences.`,
      mitigation: `Write specific, actionable mitigation/remediation steps for ${f.vuln_type}. Include code examples if relevant. 3-5 bullet points.`,
      steps: `Write clear reproduction steps for ${f.vuln_type} on ${f.target_url || "the application"}. Format as numbered steps. Be specific.`,
    };

    try {
      // Logic for AI call (currently placeholder for project integration)
      // In a real scenario, this would call your backend or a designated AI hook
      setTimeout(() => {
        const dummyText = `[AI GENERATED] This is a professional enhancement for ${field} regarding ${f.vuln_type}. It details the technical nuances and ensures compliance with standard reporting security guidelines.`;
        updateFinding(idx, field, dummyText);
        setLoadingField("");
      }, 1500);
    } catch (e) { 
      console.error(e); 
      setLoadingField("");
    }
  };

  const generateFullReport = () => {
    setLoading(true);
    
    // Simulate generation delay
    setTimeout(() => {
      let md = `# Bug Bounty Report - ${meta.program_name}\n\n`;
      md += `**Date:** ${meta.date}  \n`;
      md += `**Researcher:** ${meta.researcher}  \n`;
      md += `**Platform:** ${meta.platform}  \n`;
      md += `**Target/Scope:** ${meta.scope}  \n\n`;
      
      md += `## Executive Summary\n`;
      md += `This report details ${findings.length} security vulnerability/ies discovered in ${meta.company}. \n\n`;
      
      md += `| Finding | Severity | Type | CVSS |\n`;
      md += `|---------|----------|------|------|\n`;
      findings.forEach(f => {
        md += `| ${f.title || f.vuln_type} | ${f.severity} | ${f.vuln_type} | ${f.cvss_score || "N/A"} |\n`;
      });
      md += `\n---\n\n`;
      
      findings.forEach((f, i) => {
        md += `## Finding #${i + 1}: ${f.title || f.vuln_type}\n\n`;
        md += `### Details\n`;
        md += `- **Severity:** ${f.severity}\n`;
        md += `- **Type:** ${f.vuln_type}\n`;
        md += `- **Target:** ${f.target_url}\n`;
        if(f.parameter) md += `- **Parameter:** \`${f.parameter}\`\n`;
        md += `- **CVSS:** ${f.cvss_score || "N/A"}\n\n`;
        
        md += `### Description\n${f.description || "No description provided."}\n\n`;
        md += `### Steps to Reproduce\n${f.steps || "No steps provided."}\n\n`;
        md += `### Impact\n${f.impact || "No impact details provided."}\n\n`;
        md += `### PoC\n\`\`\`\n${f.poc || "No PoC provided."}\n\`\`\`\n\n`;
        md += `### Mitigation\n${f.mitigation || "No mitigation steps provided."}\n\n`;
        md += `---\n\n`;
      });
      
      md += `\n*Report generated via ShadowHack Report Builder*`;
      
      setReport(md);
      setStep(2);
      setLoading(false);
    }, 1200);
  };

  const copyReport = () => {
    navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="min-h-screen bg-dark-950 text-gray-300 font-mono selection:bg-primary-500/30">
      {/* HUD Background Decorations */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-[0.03]" 
           style={{ backgroundImage: "linear-gradient(#ff4560 1px,transparent 1px),linear-gradient(90deg,#ff4560 1px,transparent 1px)", backgroundSize: "60px 60px" }} />
      
      <div className="relative z-10 max-w-6xl mx-auto px-6 py-12">
        
        {/* Header Section */}
        <header className="text-center mb-12">
            <motion.div 
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-500 text-[10px] font-black uppercase tracking-[0.3em] mb-4"
            >
                <Terminal size={12} /> Operative Utility v4.2
            </motion.div>
            <h1 className="text-5xl font-black italic tracking-tighter text-white mb-2">
                REPORT<span className="text-primary-500">_BUILDER</span>
            </h1>
            <p className="text-gray-500 text-sm max-w-md mx-auto">
                Generate professional, compliant bug bounty reports for HackerOne, Bugcrowd, and internal pentests.
            </p>
        </header>

        {/* Navigation Breadcrumbs */}
        <div className="flex items-center justify-center gap-2 mb-10 overflow-hidden">
            {[
                { id: 0, label: "Program Meta", icon: Info },
                { id: 1, label: "Vulnerability Data", icon: Bug },
                { id: 2, label: "Final Report", icon: FileText }
            ].map((s, idx) => (
                <React.Fragment key={s.id}>
                    <button 
                        onClick={() => s.id < step && setStep(s.id)}
                        className={`flex items-center gap-3 px-6 py-3 rounded-xl border transition-all ${
                            step === s.id 
                            ? 'bg-primary-500/10 border-primary-500/30 text-primary-500' 
                            : step > s.id 
                            ? 'bg-white/5 border-white/5 text-white/50 hover:bg-white/10' 
                            : 'opacity-30 cursor-not-allowed text-white/30 border-transparent'
                        }`}
                    >
                        <s.icon size={16} />
                        <span className="text-xs font-black uppercase tracking-widest">{s.label}</span>
                    </button>
                    {idx < 2 && <ChevronRight size={14} className="text-white/10" />}
                </React.Fragment>
            ))}
        </div>

        {/* Step Content */}
        <div className="relative min-h-[600px]">
            <AnimatePresence mode="wait">
                {/* STEP 0: META DATA */}
                {step === 0 && (
                    <motion.div 
                        key="step0"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        className="grid grid-cols-1 lg:grid-cols-3 gap-8"
                    >
                        <div className="lg:col-span-2 space-y-6 bg-dark-900/50 border border-white/5 rounded-3xl p-8 backdrop-blur-xl">
                            <div className="flex items-center gap-2 text-primary-500 mb-4">
                                <Zap size={18} fill="currentColor" />
                                <h2 className="text-lg font-black uppercase tracking-widest">Global Report Config</h2>
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Program Name</label>
                                    <input 
                                        type="text" 
                                        value={meta.program_name} 
                                        onChange={(e) => updateMeta("program_name", e.target.value)}
                                        placeholder="e.g. Acme Public BBP"
                                        className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Company / Target</label>
                                    <input 
                                        type="text" 
                                        value={meta.company} 
                                        onChange={(e) => updateMeta("company", e.target.value)}
                                        placeholder="e.g. Acme Inc."
                                        className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Your Handle</label>
                                    <input 
                                        type="text" 
                                        value={meta.researcher} 
                                        onChange={(e) => updateMeta("researcher", e.target.value)}
                                        placeholder="e.g. h4x0r_01"
                                        className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Platform</label>
                                    <select 
                                        value={meta.platform} 
                                        onChange={(e) => updateMeta("platform", e.target.value)}
                                        className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all appearance-none"
                                    >
                                        {["HackerOne", "Bugcrowd", "Intigriti", "Synack", "YesWeHack", "Private/Direct"].map(p => (
                                            <option key={p} value={p}>{p}</option>
                                        ))}
                                    </select>
                                </div>
                                <div className="md:col-span-2 space-y-2">
                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Scope / Wildcard</label>
                                    <input 
                                        type="text" 
                                        value={meta.scope} 
                                        onChange={(e) => updateMeta("scope", e.target.value)}
                                        placeholder="e.g. *.acme.com, static.acme.net/v2"
                                        className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                    />
                                </div>
                            </div>

                            <div className="pt-6 flex justify-end">
                                <button 
                                    onClick={() => setStep(1)}
                                    disabled={!meta.program_name || !meta.researcher}
                                    className="flex items-center gap-3 px-8 py-4 bg-primary-500 hover:bg-primary-600 disabled:opacity-30 disabled:cursor-not-allowed text-white rounded-2xl font-black uppercase tracking-widest transition-all shadow-lg shadow-primary-500/20"
                                >
                                    Proceed to Findings <ChevronRight size={18} />
                                </button>
                            </div>
                        </div>

                        <div className="space-y-6">
                            <div className="bg-primary-500/5 border border-primary-500/10 rounded-3xl p-6">
                                <h3 className="text-sm font-black text-primary-500 uppercase mb-3 flex items-center gap-2">
                                    <Activity size={16} /> Guidelines
                                </h3>
                                <ul className="space-y-4 text-xs text-gray-400">
                                    <li className="flex gap-3 tracking-tighter">
                                        <div className="w-1 h-1 rounded-full bg-primary-500 mt-1.5 shrink-0" />
                                        Clear and concise descriptions help triage teams evaluate your report faster.
                                    </li>
                                    <li className="flex gap-3 tracking-tighter">
                                        <div className="w-1 h-1 rounded-full bg-primary-500 mt-1.5 shrink-0" />
                                        Always include impactful business scenarios, not just technical PoCs.
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* STEP 1: FINDINGS */}
                {step === 1 && (
                    <motion.div 
                        key="step1"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        className="space-y-6"
                    >
                        {/* Finding Tabs & Stats */}
                        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                            <div className="flex overflow-x-auto pb-2 gap-2 max-w-full no-scrollbar">
                                {findings.map((f, i) => {
                                    const cfg = SEVERITY_CONFIG[f.severity];
                                    return (
                                        <button 
                                            key={i} 
                                            onClick={() => setActiveFinding(i)}
                                            className={`flex items-center gap-3 px-5 py-3 rounded-2xl border transition-all shrink-0 ${
                                                activeFinding === i 
                                                ? `${cfg.bg} ${cfg.border} ${cfg.color}` 
                                                : "bg-white/5 border-white/5 text-gray-500 hover:bg-white/10"
                                            }`}
                                        >
                                            <span>{cfg.icon}</span>
                                            <span className="text-[10px] font-bold uppercase tracking-widest">
                                                {f.title ? (f.title.length > 15 ? f.title.substring(0, 15) + "..." : f.title) : `Finding ${i + 1}`}
                                            </span>
                                            {findings.length > 1 && (
                                                <div 
                                                    onClick={(e) => { e.stopPropagation(); removeFinding(i); }}
                                                    className="p-1 hover:bg-black/20 rounded-md"
                                                >
                                                    <Trash2 size={12} />
                                                </div>
                                            )}
                                        </button>
                                    );
                                })}
                                <button 
                                    onClick={addFinding}
                                    className="px-5 py-3 rounded-2xl border border-dashed border-white/10 text-gray-500 hover:border-primary-500/30 hover:text-primary-500 transition-all flex items-center gap-2 shrink-0"
                                >
                                    <Plus size={14} /> <span className="text-[10px] font-bold uppercase tracking-widest">New</span>
                                </button>
                            </div>

                            <div className="hidden lg:flex items-center gap-4 bg-white/5 border border-white/10 px-4 py-2 rounded-2xl">
                                {Object.keys(SEVERITY_CONFIG).filter(s => severityCounts[s]).map(s => (
                                    <div key={s} className="flex items-center gap-1.5">
                                        <div className={`w-1.5 h-1.5 rounded-full ${SEVERITY_CONFIG[s].color.replace('text-', 'bg-')}`} />
                                        <span className="text-[10px] font-bold">{severityCounts[s]}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Active Finding Form */}
                        <div className="bg-dark-900/50 border border-white/5 rounded-[2rem] p-8 backdrop-blur-xl relative overflow-hidden">
                            
                            {/* Template Overlay */}
                            <AnimatePresence>
                                {showTemplates && (
                                    <motion.div 
                                        initial={{ opacity: 0, scale: 0.95 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        exit={{ opacity: 0, scale: 0.95 }}
                                        className="absolute inset-0 z-50 bg-dark-950/90 backdrop-blur-md p-8 flex flex-col"
                                    >
                                        <div className="flex items-center justify-between mb-8">
                                            <h3 className="text-xl font-black italic tracking-tight text-white uppercase">Vulnerability Templates</h3>
                                            <button onClick={() => setShowTemplates(false)} className="text-gray-500 hover:text-white"><Plus className="rotate-45" /></button>
                                        </div>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 overflow-y-auto pr-2 custom-scrollbar">
                                            {VULN_TEMPLATES.map((t, idx) => (
                                                <button 
                                                    key={idx} 
                                                    onClick={() => applyTemplate(t)}
                                                    className="text-left bg-white/5 border border-white/5 hover:border-primary-500/30 p-6 rounded-2xl transition-all group"
                                                >
                                                    <h4 className="text-primary-500 font-bold mb-1 text-sm group-hover:translate-x-1 transition-transform">{t.type}</h4>
                                                    <p className="text-[10px] text-gray-500 line-clamp-2 leading-relaxed">{t.description}</p>
                                                </button>
                                            ))}
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            <div className="flex flex-col lg:flex-row gap-10">
                                <div className="flex-1 space-y-6">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${SEVERITY_CONFIG[findings[activeFinding].severity].bg}`}>
                                                <Bug size={16} className={SEVERITY_CONFIG[findings[activeFinding].severity].color} />
                                            </div>
                                            <h3 className="font-black text-white uppercase tracking-widest italic">Finding Detail</h3>
                                        </div>
                                        <button 
                                            onClick={() => setShowTemplates(true)}
                                            className="text-[10px] font-bold text-primary-500 bg-primary-500/10 border border-primary-500/20 px-3 py-1.5 rounded-lg hover:bg-primary-500/20 transition-all flex items-center gap-2"
                                        >
                                            <Zap size={10} fill="currentColor" /> USAR TEMPLATE
                                        </button>
                                    </div>

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="md:col-span-2 space-y-2">
                                            <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Finding Title</label>
                                            <input 
                                                value={findings[activeFinding].title} 
                                                onChange={(e) => updateFinding(activeFinding, "title", e.target.value)}
                                                placeholder="Descriptive vulnerability title"
                                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                            />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Severity</label>
                                            <select 
                                                value={findings[activeFinding].severity} 
                                                onChange={(e) => updateFinding(activeFinding, "severity", e.target.value)}
                                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all appearance-none"
                                            >
                                                {Object.keys(SEVERITY_CONFIG).map(s => <option key={s} value={s}>{s}</option>)}
                                            </select>
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">CVSS Score</label>
                                            <input 
                                                value={findings[activeFinding].cvss_score} 
                                                onChange={(e) => updateFinding(activeFinding, "cvss_score", e.target.value)}
                                                placeholder="e.g. 7.5"
                                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                            />
                                        </div>
                                        <div className="md:col-span-2 space-y-2">
                                            <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">Vulnerable Endpoint / Path</label>
                                            <input 
                                                value={findings[activeFinding].target_url} 
                                                onChange={(e) => updateFinding(activeFinding, "target_url", e.target.value)}
                                                placeholder="https://app.com/api/v1/auth"
                                                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all"
                                            />
                                        </div>
                                    </div>
                                    
                                    {/* Text Areas Section with AI Enhancers */}
                                    <div className="space-y-6 pt-4 border-t border-white/5">
                                        {[
                                            { key: "description", label: "Technical Description", rows: 4 },
                                            { key: "steps",       label: "Steps to Reproduce", rows: 4 },
                                            { key: "impact",      label: "Security Impact", rows: 3 },
                                            { key: "mitigation",  label: "Recommended Remediation", rows: 3 },
                                            { key: "poc",         label: "Proof of Concept / Payload", rows: 3, isCode: true },
                                        ].map((field) => (
                                            <div key={field.key} className="space-y-2 group">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest ml-1">{field.label}</label>
                                                    <button 
                                                        onClick={() => aiEnhanceField(activeFinding, field.key)}
                                                        disabled={loadingField === `${activeFinding}-${field.key}`}
                                                        className="text-[9px] font-bold text-primary-500/60 hover:text-primary-500 flex items-center gap-1.5 transition-colors disabled:opacity-30"
                                                    >
                                                        {loadingField === `${activeFinding}-${field.key}` ? (
                                                            <div className="w-2 h-2 border border-primary-500 border-t-transparent animate-spin rounded-full" />
                                                        ) : <Zap size={10} />}
                                                        {loadingField === `${activeFinding}-${field.key}` ? 'ENHANCING...' : 'AI ENHANCE'}
                                                    </button>
                                                </div>
                                                <textarea 
                                                    rows={field.rows}
                                                    value={findings[activeFinding][field.key]}
                                                    onChange={(e) => updateFinding(activeFinding, field.key, e.target.value)}
                                                    className={`w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:border-primary-500/50 outline-none transition-all resize-none text-sm leading-relaxed ${field.isCode ? 'font-mono bg-dark-950/50' : ''}`}
                                                    placeholder={`Enter ${field.label.toLowerCase()}...`}
                                                />
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="mt-12 flex justify-end gap-4 border-t border-white/5 pt-8">
                                <button 
                                    onClick={() => setStep(0)}
                                    className="px-6 py-3 bg-white/5 border border-white/5 hover:bg-white/10 text-white rounded-2xl font-black uppercase tracking-widest transition-all"
                                >
                                    Go Back
                                </button>
                                <button 
                                    onClick={generateFullReport}
                                    disabled={loading}
                                    className="flex items-center gap-3 px-10 py-4 bg-gradient-to-r from-primary-600 to-accent-600 hover:from-primary-500 hover:to-accent-500 disabled:opacity-30 disabled:cursor-not-allowed text-white rounded-2xl font-black uppercase tracking-widest transition-all shadow-xl shadow-primary-500/20"
                                >
                                    {loading ? (
                                        <div className="w-5 h-5 border-2 border-white/30 border-t-white animate-spin rounded-full" />
                                    ) : <FileText size={18} />}
                                    {loading ? 'CALCULATING ATTACK CHAINS...' : 'GENERATE FULL REPORT'}
                                </button>
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* STEP 2: PREVIEW */}
                {step === 2 && report && (
                    <motion.div 
                        key="step2"
                        initial={{ opacity: 0, scale: 0.98 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.98 }}
                        className="space-y-6 max-w-4xl mx-auto"
                    >
                        {/* Control Bar */}
                        <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-dark-900/50 border border-white/5 p-4 rounded-[1.5rem] backdrop-blur-xl">
                            <div className="flex items-center gap-4">
                                <div className="p-3 bg-green-500/10 rounded-xl text-green-500">
                                    <CheckCircle2 size={24} />
                                </div>
                                <div>
                                    <h3 className="text-white font-bold uppercase tracking-tight italic leading-tight">Generation Complete</h3>
                                    <p className="text-[10px] text-gray-500 font-mono tracking-widest uppercase mt-0.5">Professional Grade MD Prepared</p>
                                </div>
                            </div>
                            
                            <div className="flex items-center gap-2">
                                <button 
                                    onClick={() => setStep(1)}
                                    className="px-4 py-2 hover:bg-white/5 text-gray-400 font-bold text-[10px] uppercase tracking-widest transition-all"
                                >
                                    Modify Findings
                                </button>
                                <button 
                                    onClick={copyReport}
                                    className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-black text-[10px] uppercase tracking-widest transition-all border ${
                                        copied 
                                        ? "bg-green-500/10 border-green-500/30 text-green-500" 
                                        : "bg-primary-500/10 border-primary-500/30 text-primary-500 hover:bg-primary-500/20"
                                    }`}
                                >
                                    {copied ? <CheckCircle2 size={12} /> : <Copy size={12} />}
                                    {copied ? 'Copied' : 'Copy MD'}
                                </button>
                                <button 
                                    onClick={() => {
                                        const blob = new Blob([report], { type: "text/markdown" });
                                        const a = document.createElement("a");
                                        a.href = URL.createObjectURL(blob);
                                        a.download = `bug-bounty-report-${meta.program_name.replace(/\s+/g, "-").toLowerCase() || "report"}.md`;
                                        a.click();
                                    }}
                                    className="flex items-center gap-2 px-5 py-2.5 bg-primary-500 text-white rounded-xl font-black text-[10px] uppercase tracking-widest transition-all hover:bg-primary-600 shadow-lg shadow-primary-500/20"
                                >
                                    <Download size={12} /> Save Report
                                </button>
                            </div>
                        </div>

                        {/* Report Container */}
                        <div className="bg-[#050a0e] border border-white/5 rounded-[2rem] overflow-hidden relative shadow-2xl">
                            <div className="absolute top-0 w-full h-1 bg-gradient-to-r from-primary-500 via-accent-500 to-primary-500 opacity-50" />
                            
                            <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <FileText size={18} className="text-gray-500" />
                                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">{meta.program_name}</span>
                                </div>
                                <div className="flex gap-1">
                                    <div className="w-2 h-2 rounded-full bg-red-500/20 border border-red-500/30" />
                                    <div className="w-2 h-2 rounded-full bg-yellow-500/20 border border-yellow-500/30" />
                                    <div className="w-2 h-2 rounded-full bg-green-500/20 border border-green-500/30" />
                                </div>
                            </div>

                            <div className="p-12 h-[600px] overflow-y-auto custom-scrollbar font-sans">
                                <pre className="whitespace-pre-wrap font-mono text-sm text-gray-400 leading-relaxed selection:bg-primary-500/20">
                                    {report}
                                </pre>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>

      </div>
    </div>
  );
}
