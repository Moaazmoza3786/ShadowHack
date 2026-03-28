import { useState, useRef } from "react";

const SEVERITY_CONFIG = {
  Critical: { color: "#ff4560", bg: "rgba(255,69,96,0.12)", icon: "💀", cvss: "9.0-10.0" },
  High:     { color: "#ff7c3a", bg: "rgba(255,124,58,0.12)", icon: "🔴", cvss: "7.0-8.9" },
  Medium:   { color: "#ffb800", bg: "rgba(255,184,0,0.12)",  icon: "🟡", cvss: "4.0-6.9" },
  Low:      { color: "#00b4d8", bg: "rgba(0,180,216,0.12)",  icon: "🔵", cvss: "0.1-3.9" },
  Info:     { color: "#8b949e", bg: "rgba(139,148,158,0.12)",icon: "⚪", cvss: "0.0" },
};

const VULN_TYPES = [
  "SQL Injection", "XSS (Reflected)", "XSS (Stored)", "XSS (DOM)",
  "IDOR", "SSRF", "CSRF", "XXE", "RCE", "LFI/RFI",
  "Broken Authentication", "Broken Access Control", "Sensitive Data Exposure",
  "Security Misconfiguration", "Insecure Deserialization", "JWT Vulnerability",
  "Open Redirect", "CORS Misconfiguration", "Business Logic Flaw", "Other",
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
  const reportRef = useRef(null);

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
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 800,
          messages: [{ role: "user", content: prompts[field] }],
        }),
      });
      const data = await res.json();
      const text = data.content?.[0]?.text || "";
      updateFinding(idx, field, text);
    } catch (e) { console.error(e); }
    setLoadingField("");
  };

  const generateFullReport = async () => {
    setLoading(true);
    const prompt = `Generate a professional bug bounty report in markdown format.

Program: ${meta.program_name}
Company: ${meta.company}
Researcher: ${meta.researcher}
Date: ${meta.date}
Platform: ${meta.platform}

Findings:
${findings.map((f, i) => `
Finding ${i + 1}: ${f.title || f.vuln_type}
- Severity: ${f.severity}
- Type: ${f.vuln_type}
- URL: ${f.target_url}
- Description: ${f.description}
- Steps: ${f.steps}
- Impact: ${f.impact}
- Mitigation: ${f.mitigation}
- CVSS: ${f.cvss_score}
`).join("\n")}

Generate a complete, professional markdown report with:
1. Executive Summary
2. Vulnerability Details for each finding (with proper formatting)
3. Risk Matrix table
4. Conclusion & Recommendations

Use professional language. Make it ready to submit.`;

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 4000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await res.json();
      setReport(data.content?.[0]?.text || "");
      setStep(2);
    } catch (e) { console.error(e); }
    setLoading(false);
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

  const css = `
    * { box-sizing: border-box; }
    input, textarea, select {
      background: rgba(0,0,0,0.4) !important;
      border: 1px solid rgba(255,255,255,0.1) !important;
      color: #c9d1d9 !important;
      border-radius: 6px !important;
      padding: 10px 14px !important;
      font-family: 'Courier New', monospace !important;
      font-size: 13px !important;
      width: 100% !important;
      outline: none !important;
      resize: vertical !important;
      transition: border-color 0.2s !important;
    }
    input:focus, textarea:focus, select:focus {
      border-color: rgba(255,69,96,0.5) !important;
    }
    select option { background: #0d1117; color: #c9d1d9; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes blink { 0%,100%{opacity:1}50%{opacity:0} }
    ::-webkit-scrollbar { width: 5px; }
    ::-webkit-scrollbar-track { background: #0a0a0a; }
    ::-webkit-scrollbar-thumb { background: rgba(255,69,96,0.2); border-radius: 3px; }
  `;

  const AIBtn = ({ onClick, loading: l }) => (
    <button onClick={onClick} disabled={!!l} style={{
      background: l ? "rgba(255,69,96,0.05)" : "rgba(255,69,96,0.12)",
      border: "1px solid rgba(255,69,96,0.3)", color: l ? "#666" : "#ff4560",
      borderRadius: 5, padding: "5px 12px", fontSize: 11, cursor: l ? "not-allowed" : "pointer",
      fontFamily: "'Courier New', monospace", letterSpacing: 1, display: "flex", alignItems: "center", gap: 6,
      whiteSpace: "nowrap",
    }}>
      {l ? <span style={{ display: "inline-block", width: 10, height: 10, border: "1px solid #ff4560", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.6s linear infinite" }} /> : "⚡"}
      {l ? "AI..." : "AI Enhance"}
    </button>
  );

  return (
    <div style={{ minHeight: "100vh", background: "#050a0e", color: "#c9d1d9", fontFamily: "'Courier New', monospace" }}>
      <style>{css}</style>

      {/* Grid BG */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: "linear-gradient(rgba(255,69,96,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,69,96,0.025) 1px,transparent 1px)", backgroundSize: "44px 44px" }} />

      <div style={{ position: "relative", zIndex: 1, maxWidth: 920, margin: "0 auto", padding: "40px 20px" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ fontSize: 11, letterSpacing: 6, color: "#ff4560", marginBottom: 10, opacity: 0.7 }}>
            BREACHLABS // BUG BOUNTY REPORT BUILDER
          </div>
          <h1 style={{
            fontSize: "clamp(22px,4vw,40px)", fontWeight: 900, margin: 0,
            background: "linear-gradient(135deg,#ff4560,#ffb800,#ff4560)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>REPORT_BUILDER.exe</h1>
          <p style={{ color: "#8b949e", marginTop: 8, fontSize: 13 }}>
            Professional bug bounty reports • AI-enhanced • Ready to submit
          </p>
        </div>

        {/* Step Tabs */}
        <div style={{ display: "flex", gap: 4, marginBottom: 28, background: "rgba(0,0,0,0.3)", borderRadius: 8, padding: 4 }}>
          {[["📋 Program Info", 0], ["🐛 Findings", 1], ["📄 Report Preview", 2]].map(([label, s]) => (
            <button key={s} onClick={() => s < 2 && setStep(s)} style={{
              flex: 1, padding: "10px 0", borderRadius: 6, border: "none", cursor: s < 2 ? "pointer" : "default",
              background: step === s ? "rgba(255,69,96,0.15)" : "transparent",
              color: step === s ? "#ff4560" : "#8b949e", fontSize: 13,
              fontFamily: "'Courier New', monospace", fontWeight: step === s ? 700 : 400,
              borderBottom: step === s ? "2px solid #ff4560" : "2px solid transparent",
              transition: "all 0.2s",
            }}>{label}</button>
          ))}
        </div>

        {/* STEP 0: Program Meta */}
        {step === 0 && (
          <div style={{ background: "rgba(13,17,23,0.9)", border: "1px solid rgba(255,69,96,0.2)", borderRadius: 10, padding: 28 }}>
            <div style={{ fontSize: 11, color: "#ff4560", letterSpacing: 3, marginBottom: 20 }}>◈ PROGRAM INFORMATION</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[
                { key: "program_name", label: "Program Name", placeholder: "e.g. Acme Corp Bug Bounty" },
                { key: "company",      label: "Company / Target", placeholder: "e.g. Acme Corporation" },
                { key: "researcher",   label: "Your Handle", placeholder: "e.g. h4x0r_m0z4" },
                { key: "date",         label: "Report Date", type: "date" },
              ].map(({ key, label, placeholder, type }) => (
                <div key={key}>
                  <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>{label.toUpperCase()}</div>
                  <input type={type || "text"} value={meta[key]} placeholder={placeholder}
                    onChange={e => updateMeta(key, e.target.value)} />
                </div>
              ))}
              <div>
                <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>PLATFORM</div>
                <select value={meta.platform} onChange={e => updateMeta("platform", e.target.value)}>
                  {["HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Synack", "Direct"].map(p => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>SCOPE / DOMAIN</div>
                <input value={meta.scope} placeholder="e.g. *.acme.com" onChange={e => updateMeta("scope", e.target.value)} />
              </div>
            </div>
            <div style={{ marginTop: 24, textAlign: "right" }}>
              <button onClick={() => setStep(1)} disabled={!meta.program_name || !meta.researcher} style={{
                background: "rgba(255,69,96,0.15)", border: "1px solid rgba(255,69,96,0.4)",
                color: "#ff4560", borderRadius: 6, padding: "12px 28px", fontSize: 13,
                cursor: !meta.program_name || !meta.researcher ? "not-allowed" : "pointer",
                fontFamily: "'Courier New', monospace", fontWeight: 700, letterSpacing: 1,
                opacity: !meta.program_name || !meta.researcher ? 0.5 : 1,
              }}>ADD FINDINGS →</button>
            </div>
          </div>
        )}

        {/* STEP 1: Findings */}
        {step === 1 && (
          <div>
            {/* Severity Summary */}
            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => (
                <div key={sev} style={{
                  background: cfg.bg, border: `1px solid ${cfg.color}44`,
                  borderRadius: 6, padding: "6px 14px", fontSize: 12, color: cfg.color,
                }}>
                  {cfg.icon} {sev}: <strong>{severityCounts[sev] || 0}</strong>
                </div>
              ))}
              <div style={{ marginLeft: "auto", fontSize: 12, color: "#8b949e", padding: "6px 0" }}>
                Total: {findings.length} finding{findings.length !== 1 ? "s" : ""}
              </div>
            </div>

            {/* Finding Tabs */}
            <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
              {findings.map((f, i) => {
                const sev = SEVERITY_CONFIG[f.severity];
                return (
                  <button key={i} onClick={() => setActiveFinding(i)} style={{
                    background: activeFinding === i ? sev.bg : "rgba(0,0,0,0.3)",
                    border: `1px solid ${activeFinding === i ? sev.color + "66" : "rgba(255,255,255,0.08)"}`,
                    color: activeFinding === i ? sev.color : "#8b949e",
                    borderRadius: 6, padding: "7px 14px", fontSize: 12, cursor: "pointer",
                    fontFamily: "'Courier New', monospace", transition: "all 0.2s",
                  }}>
                    {sev.icon} {f.title || f.vuln_type || `Finding ${i + 1}`}
                  </button>
                );
              })}
              <button onClick={addFinding} style={{
                background: "rgba(0,255,157,0.08)", border: "1px solid rgba(0,255,157,0.2)",
                color: "#00ff9d", borderRadius: 6, padding: "7px 14px", fontSize: 12,
                cursor: "pointer", fontFamily: "'Courier New', monospace",
              }}>+ Add Finding</button>
            </div>

            {/* Active Finding Form */}
            {findings[activeFinding] && (() => {
              const f = findings[activeFinding];
              const sev = SEVERITY_CONFIG[f.severity];
              const lf = (field) => loadingField === `${activeFinding}-${field}`;
              return (
                <div style={{ background: "rgba(13,17,23,0.9)", border: `1px solid ${sev.color}33`, borderRadius: 10, padding: 24 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                    <div style={{ fontSize: 11, color: sev.color, letterSpacing: 3 }}>
                      {sev.icon} FINDING {activeFinding + 1} — {f.severity.toUpperCase()}
                    </div>
                    {findings.length > 1 && (
                      <button onClick={() => removeFinding(activeFinding)} style={{
                        background: "rgba(255,69,96,0.08)", border: "1px solid rgba(255,69,96,0.2)",
                        color: "#ff4560", borderRadius: 4, padding: "4px 10px", fontSize: 11,
                        cursor: "pointer", fontFamily: "'Courier New', monospace",
                      }}>✕ Remove</button>
                    )}
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>TITLE</div>
                      <input value={f.title} placeholder="Short descriptive title"
                        onChange={e => updateFinding(activeFinding, "title", e.target.value)} />
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>VULNERABILITY TYPE</div>
                      <select value={f.vuln_type} onChange={e => updateFinding(activeFinding, "vuln_type", e.target.value)}>
                        <option value="">Select type...</option>
                        {VULN_TYPES.map(t => <option key={t}>{t}</option>)}
                      </select>
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>SEVERITY</div>
                      <select value={f.severity} onChange={e => updateFinding(activeFinding, "severity", e.target.value)}>
                        {Object.keys(SEVERITY_CONFIG).map(s => <option key={s}>{s}</option>)}
                      </select>
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>CVSS SCORE</div>
                      <input value={f.cvss_score} placeholder={`e.g. ${sev.cvss}`}
                        onChange={e => updateFinding(activeFinding, "cvss_score", e.target.value)} />
                    </div>
                    <div style={{ gridColumn: "1/-1" }}>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>TARGET URL</div>
                      <input value={f.target_url} placeholder="https://target.com/vulnerable/endpoint"
                        onChange={e => updateFinding(activeFinding, "target_url", e.target.value)} />
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>PARAMETER / ENDPOINT</div>
                      <input value={f.parameter} placeholder="e.g. id, user_id, search"
                        onChange={e => updateFinding(activeFinding, "parameter", e.target.value)} />
                    </div>
                    <div>
                      <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 6 }}>PROOF OF CONCEPT</div>
                      <input value={f.poc} placeholder="URL, payload, or screenshot ref"
                        onChange={e => updateFinding(activeFinding, "poc", e.target.value)} />
                    </div>
                  </div>

                  {/* AI-enhanced textareas */}
                  {[
                    { key: "description", label: "DESCRIPTION", placeholder: "Describe the vulnerability...", rows: 5 },
                    { key: "steps",       label: "STEPS TO REPRODUCE", placeholder: "1. Go to...\n2. Enter...", rows: 5 },
                    { key: "impact",      label: "IMPACT", placeholder: "What can an attacker achieve?", rows: 3 },
                    { key: "mitigation",  label: "MITIGATION / FIX", placeholder: "How to fix this vulnerability...", rows: 4 },
                  ].map(({ key, label, placeholder, rows }) => (
                    <div key={key} style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2 }}>{label}</div>
                        <AIBtn loading={lf(key)} onClick={() => aiEnhanceField(activeFinding, key)} />
                      </div>
                      <textarea rows={rows} value={f[key]} placeholder={placeholder}
                        onChange={e => updateFinding(activeFinding, key, e.target.value)} />
                    </div>
                  ))}
                </div>
              );
            })()}

            {/* Generate Button */}
            <div style={{ marginTop: 20, display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button onClick={() => setStep(0)} style={{
                background: "none", border: "1px solid rgba(255,255,255,0.1)",
                color: "#8b949e", borderRadius: 6, padding: "12px 20px", fontSize: 13,
                cursor: "pointer", fontFamily: "'Courier New', monospace",
              }}>← Back</button>
              <button onClick={generateFullReport} disabled={loading} style={{
                background: loading ? "rgba(255,69,96,0.05)" : "rgba(255,69,96,0.15)",
                border: "1px solid rgba(255,69,96,0.4)", color: loading ? "#666" : "#ff4560",
                borderRadius: 6, padding: "12px 28px", fontSize: 13, fontWeight: 700,
                cursor: loading ? "not-allowed" : "pointer", fontFamily: "'Courier New', monospace",
                letterSpacing: 1, display: "flex", alignItems: "center", gap: 8,
              }}>
                {loading ? (
                  <><span style={{ display: "inline-block", width: 14, height: 14, border: "2px solid #ff4560", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} /> GENERATING...</>
                ) : "⚡ GENERATE FULL REPORT"}
              </button>
            </div>
          </div>
        )}

        {/* STEP 2: Report Preview */}
        {step === 2 && report && (
          <div>
            {/* Action Bar */}
            <div style={{ display: "flex", gap: 10, marginBottom: 16, justifyContent: "flex-end", flexWrap: "wrap" }}>
              <button onClick={() => setStep(1)} style={{
                background: "none", border: "1px solid rgba(255,255,255,0.1)",
                color: "#8b949e", borderRadius: 6, padding: "9px 18px", fontSize: 12,
                cursor: "pointer", fontFamily: "'Courier New', monospace",
              }}>← Edit Findings</button>
              <button onClick={copyReport} style={{
                background: copied ? "rgba(0,255,157,0.12)" : "rgba(0,180,216,0.12)",
                border: `1px solid ${copied ? "rgba(0,255,157,0.4)" : "rgba(0,180,216,0.3)"}`,
                color: copied ? "#00ff9d" : "#00b4d8",
                borderRadius: 6, padding: "9px 18px", fontSize: 12,
                cursor: "pointer", fontFamily: "'Courier New', monospace",
              }}>
                {copied ? "✓ COPIED!" : "📋 COPY MARKDOWN"}
              </button>
              <button onClick={() => {
                const blob = new Blob([report], { type: "text/markdown" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob);
                a.download = `bug-bounty-report-${meta.program_name.replace(/\s+/g, "-").toLowerCase() || "report"}.md`;
                a.click();
              }} style={{
                background: "rgba(255,69,96,0.12)", border: "1px solid rgba(255,69,96,0.35)",
                color: "#ff4560", borderRadius: 6, padding: "9px 18px", fontSize: 12,
                cursor: "pointer", fontFamily: "'Courier New', monospace",
              }}>⬇ DOWNLOAD .MD</button>
            </div>

            {/* Report */}
            <div ref={reportRef} style={{
              background: "#0a0f14", border: "1px solid rgba(255,69,96,0.2)",
              borderRadius: 10, overflow: "hidden",
            }}>
              <div style={{
                background: "rgba(255,69,96,0.07)", padding: "12px 20px",
                borderBottom: "1px solid rgba(255,69,96,0.15)",
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}>
                <span style={{ color: "#ff4560", fontSize: 12, letterSpacing: 2 }}>
                  📄 {meta.program_name} — BUG BOUNTY REPORT
                </span>
                <span style={{ color: "#8b949e", fontSize: 11 }}>
                  {findings.length} finding{findings.length !== 1 ? "s" : ""} • {meta.date}
                </span>
              </div>
              <pre style={{
                padding: 28, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word",
                fontSize: 13, lineHeight: 1.8, color: "#c9d1d9", maxHeight: "70vh",
                overflowY: "auto", fontFamily: "'Courier New', monospace",
              }}>{report}</pre>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
