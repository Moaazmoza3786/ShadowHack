import { useState, useRef, useEffect } from "react";

// ─── THEME ───────────────────────────────────────────────────────────────────
const T = {
  bg: "#050a0e", card: "rgba(13,17,23,0.95)", border: "rgba(255,255,255,0.07)",
  accent: "#00ff9d", red: "#ff4560", yellow: "#ffb800", blue: "#00b4d8", purple: "#a855f7",
  muted: "#8b949e", text: "#c9d1d9",
  font: "'Courier New', monospace",
};

// ─── TOOLS CONFIG ─────────────────────────────────────────────────────────────
const TOOLS = [
  { id: "payload",   icon: "⚡", label: "Payload Generator", color: "#ff4560", desc: "AI-generated attack payloads" },
  { id: "subdomain", icon: "🌐", label: "Subdomain Monitor",  color: "#00b4d8", desc: "Recon & enumeration assistant" },
  { id: "osint",     icon: "🔍", label: "OSINT Pro",          color: "#a855f7", desc: "Footprint any target" },
  { id: "fuzzing",   icon: "💥", label: "Fuzzing Cockpit",    color: "#ffb800", desc: "Smart fuzzing strategies" },
  { id: "hash",      icon: "🔐", label: "Hash Refinery",      color: "#00ff9d", desc: "Identify, crack & analyze" },
  { id: "encoder",   icon: "🔄", label: "Encoder Tool",       color: "#fb923c", desc: "Encode / decode everything" },
];

// ─── SHARED COMPONENTS ────────────────────────────────────────────────────────
const GlowCard = ({ children, color = T.accent, style = {} }) => (
  <div style={{
    background: T.card, border: `1px solid ${color}22`,
    borderRadius: 10, overflow: "hidden", ...style,
  }}>{children}</div>
);

const CardHeader = ({ color, icon, title, subtitle }) => (
  <div style={{
    background: `${color}0d`, borderBottom: `1px solid ${color}22`,
    padding: "14px 20px", display: "flex", alignItems: "center", gap: 12,
  }}>
    <span style={{ fontSize: 20 }}>{icon}</span>
    <div>
      <div style={{ color, fontWeight: 700, fontSize: 15, letterSpacing: 0.5 }}>{title}</div>
      {subtitle && <div style={{ color: T.muted, fontSize: 11, marginTop: 1 }}>{subtitle}</div>}
    </div>
  </div>
);

const Input = ({ label, value, onChange, placeholder, type = "text" }) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 10, color: T.muted, letterSpacing: 2, marginBottom: 5 }}>{label}</div>}
    <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{
        width: "100%", background: "rgba(0,0,0,0.5)", border: `1px solid ${T.border}`,
        borderRadius: 6, padding: "9px 13px", color: T.text, fontSize: 13,
        fontFamily: T.font, outline: "none", boxSizing: "border-box",
        transition: "border-color 0.2s",
      }}
      onFocus={e => e.target.style.borderColor = "rgba(0,255,157,0.4)"}
      onBlur={e => e.target.style.borderColor = T.border}
    />
  </div>
);

const Select = ({ label, value, onChange, options }) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 10, color: T.muted, letterSpacing: 2, marginBottom: 5 }}>{label}</div>}
    <select value={value} onChange={e => onChange(e.target.value)} style={{
      width: "100%", background: "#0a0f14", border: `1px solid ${T.border}`,
      borderRadius: 6, padding: "9px 13px", color: T.text, fontSize: 13,
      fontFamily: T.font, outline: "none", boxSizing: "border-box",
    }}>
      {options.map(o => <option key={o.value ?? o} value={o.value ?? o}>{o.label ?? o}</option>)}
    </select>
  </div>
);

const RunBtn = ({ onClick, loading, color, label = "RUN" }) => (
  <button onClick={onClick} disabled={loading} style={{
    width: "100%", padding: "12px 0", borderRadius: 7, border: `1px solid ${color}55`,
    background: loading ? `${color}08` : `${color}18`,
    color: loading ? T.muted : color, fontWeight: 700, fontSize: 13,
    letterSpacing: 2, cursor: loading ? "not-allowed" : "pointer",
    fontFamily: T.font, transition: "all 0.2s", display: "flex",
    alignItems: "center", justifyContent: "center", gap: 8,
  }}>
    {loading
      ? <><Spinner color={color} /> PROCESSING...</>
      : <>{label}</>}
  </button>
);

const Spinner = ({ color }) => (
  <span style={{
    width: 13, height: 13, border: `2px solid ${color}44`,
    borderTopColor: color, borderRadius: "50%",
    display: "inline-block", animation: "spin 0.6s linear infinite",
  }} />
);

const OutputBox = ({ content, color, label = "OUTPUT" }) => (
  <div style={{ marginTop: 14 }}>
    <div style={{ fontSize: 10, color, letterSpacing: 2, marginBottom: 6 }}>◈ {label}</div>
    <div style={{
      background: "#020609", border: `1px solid ${color}22`, borderRadius: 8,
      padding: 16, maxHeight: 340, overflowY: "auto",
      fontFamily: T.font, fontSize: 12.5, lineHeight: 1.8, color: T.text,
      whiteSpace: "pre-wrap", wordBreak: "break-word",
    }}>{content}</div>
  </div>
);

const GuidePanel = ({ tips, color }) => (
  <GlowCard color={color} style={{ marginTop: 16 }}>
    <div style={{ padding: "12px 16px", borderBottom: `1px solid ${color}15` }}>
      <span style={{ fontSize: 10, color, letterSpacing: 2 }}>💡 LIVE GUIDE</span>
    </div>
    <div style={{ padding: "14px 16px" }}>
      {tips.map((tip, i) => (
        <div key={i} style={{ display: "flex", gap: 10, marginBottom: i < tips.length - 1 ? 10 : 0 }}>
          <span style={{ color, flexShrink: 0, fontSize: 12 }}>▸</span>
          <span style={{ fontSize: 12, color: T.muted, lineHeight: 1.6 }}>{tip}</span>
        </div>
      ))}
    </div>
  </GlowCard>
);

const WhyBox = ({ text, color }) => (
  text ? (
    <div style={{
      marginTop: 12, padding: "12px 16px", borderRadius: 8,
      background: `${color}07`, border: `1px solid ${color}20`,
    }}>
      <div style={{ fontSize: 10, color, letterSpacing: 2, marginBottom: 6 }}>🧠 WHY THIS WORKS</div>
      <div style={{ fontSize: 12, color: T.muted, lineHeight: 1.7 }}>{text}</div>
    </div>
  ) : null
);

// ─── AI CALL ──────────────────────────────────────────────────────────────────
async function callAI(prompt, onChunk) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1800,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  const data = await res.json();
  const text = data.content?.[0]?.text || "";
  onChunk(text);
  return text;
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 1 — PAYLOAD GENERATOR
// ════════════════════════════════════════════════════════════════════════════════
function PayloadGenerator() {
  const C = T.red;
  const [vulnType, setVulnType] = useState("XSS");
  const [context, setContext] = useState("HTML attribute");
  const [wafBypass, setWafBypass] = useState("none");
  const [target, setTarget] = useState("");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  const VULN_TYPES = ["XSS", "SQL Injection", "SSTI", "SSRF", "XXE", "LFI", "CSRF", "Command Injection", "IDOR", "Path Traversal", "JWT Attack", "CRLF Injection"];
  const CONTEXTS = ["HTML attribute", "JavaScript context", "URL parameter", "JSON body", "XML input", "HTTP header", "Cookie value", "GraphQL query"];
  const WAFBYPASS = ["none", "Cloudflare", "ModSecurity", "AWS WAF", "Akamai", "Imperva"];

  const generate = async () => {
    if (loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are an expert penetration tester. Generate real, working attack payloads.

Task: Generate 8-12 ${vulnType} payloads for context: "${context}"
Target context: ${target || "generic web application"}
WAF bypass needed: ${wafBypass}

Format your response EXACTLY like this:

## PAYLOADS
\`\`\`
[payload 1]
[payload 2]
... (one per line)
\`\`\`

## USAGE NOTES
Brief notes on when to use each variation.

## WHY_THIS_WORKS
[One paragraph explaining the technical reason these payloads work in this specific context]

Be technical, accurate, and practical. These are for authorized testing only.`;

    try {
      const text = await callAI(prompt, t => {
        const payloadSection = t.split("## WHY_THIS_WORKS")[0];
        setOutput(payloadSection);
      });
      const whyMatch = text.match(/## WHY_THIS_WORKS\n([\s\S]*)/);
      if (whyMatch) setWhy(whyMatch[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      {/* Left: Config */}
      <GlowCard color={C}>
        <CardHeader color={C} icon="⚡" title="Payload Generator" subtitle="AI-crafted attack payloads" />
        <div style={{ padding: 20 }}>
          <Select label="VULNERABILITY TYPE" value={vulnType} onChange={setVulnType} options={VULN_TYPES} />
          <Select label="INJECTION CONTEXT" value={context} onChange={setContext} options={CONTEXTS} />
          <Select label="WAF BYPASS" value={wafBypass} onChange={setWafBypass} options={WAFBYPASS} />
          <Input label="TARGET DESCRIPTION (optional)" value={target} onChange={setTarget} placeholder="e.g. login form, search bar, REST API" />
          <RunBtn onClick={generate} loading={loading} color={C} label="⚡ GENERATE PAYLOADS" />
          {output && <OutputBox content={output} color={C} label="GENERATED PAYLOADS" />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      {/* Right: Guide */}
      <div>
        <GuidePanel color={C} tips={[
          `اختار الـ Vulnerability Type الصح بناءً على السلوك اللي شايفه في الـ response.`,
          `الـ Context مهم جداً — XSS في HTML attribute مختلف عن XSS في JavaScript context.`,
          `لو في WAF، ابدأ بـ none الأول وشوف إيه اللي بيتبلوك، بعدين اختار الـ WAF المناسب.`,
          `جرب كل payload واحد واحد وراقب الـ response — حتى لو مفيش output ظاهر.`,
          `استخدم Burp Suite عشان تشوف الـ raw request/response مع كل payload.`,
        ]} />

        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>📚 QUICK REFERENCE</div>
            {[
              { type: "XSS Reflected", sign: "Input يرجع في الـ page بدون encode" },
              { type: "XSS Stored", sign: "Input يتحفظ ويرجع لكل user" },
              { type: "SQLi", sign: "Error message أو تغيير في السلوك" },
              { type: "SSTI", sign: "Template syntax زي {{7*7}}" },
              { type: "SSRF", sign: "Server بيعمل request لـ URL تحدده" },
            ].map(({ type, sign }) => (
              <div key={type} style={{ marginBottom: 8, padding: "8px 10px", background: "rgba(0,0,0,0.3)", borderRadius: 6 }}>
                <div style={{ color: C, fontSize: 12, fontWeight: 700 }}>{type}</div>
                <div style={{ color: T.muted, fontSize: 11, marginTop: 2 }}>علامة: {sign}</div>
              </div>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 2 — SUBDOMAIN MONITOR
// ════════════════════════════════════════════════════════════════════════════════
function SubdomainMonitor() {
  const C = T.blue;
  const [domain, setDomain] = useState("");
  const [strategy, setStrategy] = useState("passive");
  const [scope, setScope] = useState("full");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!domain || loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are an expert bug bounty recon specialist. Help enumerate subdomains for: ${domain}

Strategy: ${strategy} reconnaissance
Scope: ${scope}

Provide:

## RECON PLAN
Step-by-step recon plan with actual commands for: amass, subfinder, assetfinder, dnsx, httpx, shodan

## WORDLIST SUGGESTIONS
Top 20 likely subdomains to try for this domain based on common patterns (dev, staging, api, admin, etc.)

## PASSIVE SOURCES
List of OSINT sources to check (crt.sh, virustotal, etc.) with exact URLs for ${domain}

## INTERESTING TARGETS
What types of subdomains are highest-value bug bounty targets and why

## WHY_THIS_WORKS
Why passive recon is important before active scanning

## NEXT_STEPS
What to do after finding subdomains (port scan, tech fingerprint, etc.)`;

    try {
      const text = await callAI(prompt, t => {
        setOutput(t.split("## WHY_THIS_WORKS")[0]);
      });
      const m = text.match(/## WHY_THIS_WORKS\n([\s\S]*?)(?=## NEXT_STEPS|$)/);
      if (m) setWhy(m[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <GlowCard color={C}>
        <CardHeader color={C} icon="🌐" title="Subdomain Monitor" subtitle="Recon & enumeration assistant" />
        <div style={{ padding: 20 }}>
          <Input label="TARGET DOMAIN" value={domain} onChange={setDomain} placeholder="example.com (بدون https://)" />
          <Select label="RECON STRATEGY" value={strategy} onChange={setStrategy} options={[
            { value: "passive", label: "Passive (OSINT only - safe)" },
            { value: "active", label: "Active (DNS brute force)" },
            { value: "hybrid", label: "Hybrid (passive + light active)" },
          ]} />
          <Select label="SCOPE" value={scope} onChange={setScope} options={[
            { value: "full", label: "Full scope" },
            { value: "wildcard", label: "Wildcard (*.domain.com)" },
            { value: "specific", label: "Specific subdomain level" },
          ]} />
          <RunBtn onClick={run} loading={loading} color={C} label="🌐 START RECON" />
          {output && <OutputBox content={output} color={C} label="RECON PLAN & RESULTS" />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      <div>
        <GuidePanel color={C} tips={[
          `ابدأ دايماً بـ Passive recon — محتاجش permission وبيديك حاجات كتير.`,
          `crt.sh هو أهم مصدر — ابحث عن %.${domain || "target.com"} تلاقي كل الـ SSL certs.`,
          `الـ subdomains اللي على S3 أو Cloudfront ممكن تكون vulnerable لـ takeover.`,
          `بعد ما تجمع الـ subdomains، شغّل httpx عشان تعرف مين شغّال فعلاً.`,
          `فتش على الـ dev, staging, test subdomains — غالباً أقل security.`,
        ]} />
        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>🛠 TOOL COMMANDS</div>
            {[
              { tool: "subfinder", cmd: `subfinder -d ${domain || "target.com"} -o subs.txt` },
              { tool: "amass", cmd: `amass enum -passive -d ${domain || "target.com"}` },
              { tool: "httpx", cmd: `cat subs.txt | httpx -status-code -tech-detect` },
              { tool: "dnsx", cmd: `cat subs.txt | dnsx -a -resp` },
            ].map(({ tool, cmd }) => (
              <div key={tool} style={{ marginBottom: 8 }}>
                <div style={{ color: C, fontSize: 11, marginBottom: 3 }}>{tool}</div>
                <div style={{ background: "#020609", border: `1px solid ${C}15`, borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#00ff9d" }}>
                  $ {cmd}
                </div>
              </div>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 3 — OSINT PRO
// ════════════════════════════════════════════════════════════════════════════════
function OSINTPro() {
  const C = T.purple;
  const [targetType, setTargetType] = useState("domain");
  const [targetValue, setTargetValue] = useState("");
  const [goal, setGoal] = useState("recon");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!targetValue || loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are an OSINT expert for bug bounty and penetration testing. 

Target Type: ${targetType}
Target: ${targetValue}
Goal: ${goal}

Create a comprehensive OSINT investigation plan:

## IMMEDIATE ACTIONS
First 5 things to do RIGHT NOW (with exact URLs/commands)

## DATA SOURCES
Categorized list of sources to check:
- Public records
- Social media
- Technical databases (Shodan, Censys, etc.)
- Code repositories
- Breach databases

## GOOGLE DORKS
10 specific Google dorks for: ${targetValue}
Format: site:${targetValue} [dork here]

## FINDINGS TEMPLATE
What to document and how to organize findings

## WHY_THIS_WORKS
Why OSINT is crucial before any active testing

Make everything specific to: ${targetValue}`;

    try {
      const text = await callAI(prompt, t => {
        setOutput(t.split("## WHY_THIS_WORKS")[0]);
      });
      const m = text.match(/## WHY_THIS_WORKS\n([\s\S]*)/);
      if (m) setWhy(m[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <GlowCard color={C}>
        <CardHeader color={C} icon="🔍" title="OSINT Pro" subtitle="Open-source intelligence gathering" />
        <div style={{ padding: 20 }}>
          <Select label="TARGET TYPE" value={targetType} onChange={setTargetType} options={[
            { value: "domain", label: "Domain / Website" },
            { value: "company", label: "Company / Organization" },
            { value: "email", label: "Email Address" },
            { value: "ip", label: "IP Address" },
            { value: "username", label: "Username / Handle" },
          ]} />
          <Input label="TARGET VALUE" value={targetValue} onChange={setTargetValue}
            placeholder={targetType === "domain" ? "example.com" : targetType === "email" ? "user@example.com" : "Enter target..."} />
          <Select label="INVESTIGATION GOAL" value={goal} onChange={setGoal} options={[
            { value: "recon", label: "Bug Bounty Recon" },
            { value: "footprint", label: "Full Digital Footprint" },
            { value: "tech", label: "Technology Stack Discovery" },
            { value: "employees", label: "Employee & Contact Discovery" },
            { value: "vulns", label: "Vulnerability Discovery" },
          ]} />
          <RunBtn onClick={run} loading={loading} color={C} label="🔍 INVESTIGATE" />
          {output && <OutputBox content={output} color={C} label="OSINT REPORT" />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      <div>
        <GuidePanel color={C} tips={[
          `ابدأ بالـ domain الأساسي وبعدين اتفرع — registrant info → email → company → employees.`,
          `Google Dorks قوية جداً — site:target.com filetype:pdf بتلاقي documents مهمة.`,
          `Shodan وCensys بيكشفوا الـ infrastructure — ports, services, certificates.`,
          `GitHub search عن الـ domain ممكن تلاقي leaked API keys أو credentials.`,
          `LinkedIn بيكشف الـ employees والـ tech stack من job descriptions.`,
        ]} />
        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>🌐 QUICK LINKS</div>
            {[
              { name: "crt.sh", url: `https://crt.sh/?q=%.${targetValue || "target.com"}`, desc: "SSL certificates" },
              { name: "Shodan", url: `https://www.shodan.io/search?query=${targetValue || "target.com"}`, desc: "Internet devices" },
              { name: "VirusTotal", url: `https://virustotal.com/gui/domain/${targetValue || "target.com"}`, desc: "Subdomains & IPs" },
              { name: "GitHub", url: `https://github.com/search?q=${targetValue || "target.com"}`, desc: "Code leaks" },
              { name: "Wayback", url: `https://web.archive.org/web/*/${targetValue || "target.com"}`, desc: "Historical pages" },
            ].map(({ name, url, desc }) => (
              <a key={name} href={url} target="_blank" rel="noreferrer" style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "8px 10px", background: "rgba(0,0,0,0.3)", borderRadius: 6,
                marginBottom: 6, textDecoration: "none", transition: "background 0.2s",
              }}>
                <div>
                  <div style={{ color: C, fontSize: 12, fontWeight: 700 }}>{name}</div>
                  <div style={{ color: T.muted, fontSize: 10 }}>{desc}</div>
                </div>
                <span style={{ color: T.muted, fontSize: 14 }}>↗</span>
              </a>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 4 — FUZZING COCKPIT
// ════════════════════════════════════════════════════════════════════════════════
function FuzzingCockpit() {
  const C = T.yellow;
  const [endpoint, setEndpoint] = useState("");
  const [fuzzTarget, setFuzzTarget] = useState("parameters");
  const [technique, setTechnique] = useState("smart");
  const [context, setContext] = useState("");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are an expert web application fuzzer and bug bounty hunter.

Endpoint: ${endpoint || "https://target.com/api/endpoint"}
Fuzzing target: ${fuzzTarget}
Technique: ${technique}
Context: ${context || "REST API endpoint"}

Generate a complete fuzzing strategy:

## FFUF COMMANDS
3-5 ready-to-run ffuf commands with explanations

## WORDLISTS
Best wordlists to use (from SecLists) with paths

## CUSTOM PAYLOADS
20 custom payloads specific to ${fuzzTarget} fuzzing

## RESPONSE ANALYSIS
What responses to look for (status codes, sizes, timing)

## AUTOMATION SCRIPT
A bash one-liner or short script to automate this fuzzing

## WHY_THIS_WORKS
Technical explanation of why fuzzing finds vulnerabilities others miss

Keep everything practical and immediately usable.`;

    try {
      const text = await callAI(prompt, t => {
        setOutput(t.split("## WHY_THIS_WORKS")[0]);
      });
      const m = text.match(/## WHY_THIS_WORKS\n([\s\S]*)/);
      if (m) setWhy(m[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <GlowCard color={C}>
        <CardHeader color={C} icon="💥" title="Fuzzing Cockpit" subtitle="Smart fuzzing strategies & commands" />
        <div style={{ padding: 20 }}>
          <Input label="TARGET ENDPOINT" value={endpoint} onChange={setEndpoint} placeholder="https://api.target.com/v1/user/FUZZ" />
          <Select label="WHAT TO FUZZ" value={fuzzTarget} onChange={setFuzzTarget} options={[
            { value: "parameters", label: "Parameters / Query strings" },
            { value: "paths", label: "Paths & directories" },
            { value: "headers", label: "HTTP Headers" },
            { value: "subdomains", label: "Subdomains (vhost)" },
            { value: "files", label: "Hidden files & extensions" },
            { value: "json_keys", label: "JSON body keys" },
          ]} />
          <Select label="TECHNIQUE" value={technique} onChange={setTechnique} options={[
            { value: "smart", label: "Smart (AI-guided)" },
            { value: "bruteforce", label: "Brute force" },
            { value: "targeted", label: "Targeted (based on tech stack)" },
            { value: "recursive", label: "Recursive directory" },
          ]} />
          <Input label="TECH STACK / CONTEXT (optional)" value={context} onChange={setContext} placeholder="e.g. Laravel, Node.js, PHP, Django" />
          <RunBtn onClick={run} loading={loading} color={C} label="💥 BUILD STRATEGY" />
          {output && <OutputBox content={output} color={C} label="FUZZING PLAN" />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      <div>
        <GuidePanel color={C} tips={[
          `حط FUZZ في المكان اللي عايز تفزّه في الـ URL — ffuf بيستخدمه تلقائياً.`,
          `راقب الـ response size مش بس الـ status code — responses مختلفة الحجم مهمة.`,
          `استخدم -fc لـ filter الـ status codes اللي مش مهمة زي -fc 404,403.`,
          `SecLists هو أحسن مصدر للـ wordlists — اتأكد إنه installed.`,
          `ابدأ بـ wordlist صغيرة وبعدين وسّع — عشان ما تكونش aggressive.`,
        ]} />
        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>⚡ QUICK FFUF TEMPLATES</div>
            {[
              { label: "Directory fuzzing", cmd: `ffuf -w wordlist.txt -u ${endpoint || "https://target.com"}/FUZZ` },
              { label: "Parameter fuzzing", cmd: `ffuf -w params.txt -u ${endpoint || "https://target.com"}?FUZZ=test` },
              { label: "VHost fuzzing", cmd: `ffuf -w subdomains.txt -H "Host: FUZZ.target.com" -u https://target.com` },
            ].map(({ label, cmd }) => (
              <div key={label} style={{ marginBottom: 10 }}>
                <div style={{ color: C, fontSize: 11, marginBottom: 4 }}>{label}</div>
                <div style={{ background: "#020609", borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#00ff9d", wordBreak: "break-all" }}>
                  $ {cmd}
                </div>
              </div>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 5 — HASH REFINERY
// ════════════════════════════════════════════════════════════════════════════════
function HashRefinery() {
  const C = T.accent;
  const [hash, setHash] = useState("");
  const [mode, setMode] = useState("identify");
  const [plaintext, setPlaintext] = useState("");
  const [algorithm, setAlgorithm] = useState("md5");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  // Client-side hash generation
  const generateHash = async () => {
    if (!plaintext) return;
    setLoading(true);
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(plaintext);
      const algoMap = { sha256: "SHA-256", sha512: "SHA-512", sha1: "SHA-1" };
      if (algoMap[algorithm]) {
        const hashBuffer = await crypto.subtle.digest(algoMap[algorithm], data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
        setOutput(`Algorithm: ${algorithm.toUpperCase()}\nPlaintext: ${plaintext}\nHash: ${hashHex}\n\nNote: MD5 requires server-side computation.`);
      } else {
        setOutput(`MD5 requires server-side computation.\nPlaintext: ${plaintext}\nUse: echo -n "${plaintext}" | md5sum`);
      }
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  const analyzeHash = async () => {
    if (!hash || loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are a hash analysis expert.

Analyze this hash: ${hash}

## IDENTIFICATION
Identify the most likely hash type(s) based on length and character set.
Format: Hash type | Length | Likelihood | hashcat mode

## HASHCAT COMMANDS
Ready-to-run hashcat commands:
- Dictionary attack with rockyou.txt
- Rule-based attack
- Brute force (if feasible)

## JOHN THE RIPPER
Equivalent john commands

## ONLINE RESOURCES
Best online crackers to try first (hashes.com, crackstation.net, etc.)

## CRACKING STRATEGY
Step-by-step strategy: what to try first, second, third

## WHY_THIS_WORKS
Why different hash types have different security levels

Be specific with hashcat -m numbers.`;

    try {
      const text = await callAI(prompt, t => {
        setOutput(t.split("## WHY_THIS_WORKS")[0]);
      });
      const m = text.match(/## WHY_THIS_WORKS\n([\s\S]*)/);
      if (m) setWhy(m[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <GlowCard color={C}>
        <CardHeader color={C} icon="🔐" title="Hash Refinery" subtitle="Identify, analyze & crack hashes" />
        <div style={{ padding: 20 }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
            {[{ id: "identify", label: "Identify & Crack" }, { id: "generate", label: "Generate Hash" }].map(m => (
              <button key={m.id} onClick={() => setMode(m.id)} style={{
                flex: 1, padding: "8px 0", borderRadius: 6, border: `1px solid ${mode === m.id ? C + "66" : T.border}`,
                background: mode === m.id ? `${C}12` : "transparent",
                color: mode === m.id ? C : T.muted, fontSize: 12, cursor: "pointer",
                fontFamily: T.font, transition: "all 0.2s",
              }}>{m.label}</button>
            ))}
          </div>

          {mode === "identify" ? (
            <>
              <Input label="PASTE HASH" value={hash} onChange={setHash} placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99" />
              <RunBtn onClick={analyzeHash} loading={loading} color={C} label="🔐 ANALYZE HASH" />
            </>
          ) : (
            <>
              <Input label="PLAINTEXT" value={plaintext} onChange={setPlaintext} placeholder="Text to hash" />
              <Select label="ALGORITHM" value={algorithm} onChange={setAlgorithm} options={[
                { value: "sha256", label: "SHA-256" },
                { value: "sha512", label: "SHA-512" },
                { value: "sha1", label: "SHA-1" },
                { value: "md5", label: "MD5 (terminal)" },
              ]} />
              <RunBtn onClick={generateHash} loading={loading} color={C} label="🔐 GENERATE" />
            </>
          )}

          {output && <OutputBox content={output} color={C} label={mode === "identify" ? "ANALYSIS & CRACK GUIDE" : "GENERATED HASH"} />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      <div>
        <GuidePanel color={C} tips={[
          `اعرف الـ hash type الأول — طول الـ hash بيكشف كتير (32=MD5, 40=SHA1, 64=SHA256).`,
          `جرب الـ online crackers الأول زي crackstation.net — بيكسروا MD5/SHA1 في ثواني.`,
          `rockyou.txt هو أحسن wordlist للبداية — فيه 14 مليون password شائع.`,
          `hashcat أسرع بكتير من john لو عندك GPU — استخدمه لو الـ hash مش بيتكسر.`,
          `لو الـ hash فيه salt، محتاج تعرف الـ salt الأول عشان تكسره.`,
        ]} />
        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>📊 HASH CHEAT SHEET</div>
            {[
              { hash: "MD5", len: 32, mode: "0", color: "#ff4560" },
              { hash: "SHA-1", len: 40, mode: "100", color: "#ffb800" },
              { hash: "SHA-256", len: 64, mode: "1400", color: "#00b4d8" },
              { hash: "bcrypt", len: "60", mode: "3200", color: "#a855f7" },
              { hash: "NTLM", len: 32, mode: "1000", color: "#00ff9d" },
            ].map(({ hash: h, len, mode: m, color }) => (
              <div key={h} style={{ display: "flex", justifyContent: "space-between", padding: "7px 10px", background: "rgba(0,0,0,0.3)", borderRadius: 5, marginBottom: 5 }}>
                <span style={{ color, fontSize: 12, fontWeight: 700 }}>{h}</span>
                <span style={{ color: T.muted, fontSize: 11 }}>len:{len} | -m {m}</span>
              </div>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// TOOL 6 — ENCODER TOOL
// ════════════════════════════════════════════════════════════════════════════════
function EncoderTool() {
  const C = "#fb923c";
  const [input, setInput] = useState("");
  const [operation, setOperation] = useState("encode");
  const [format, setFormat] = useState("base64");
  const [aiMode, setAiMode] = useState(false);
  const [aiContext, setAiContext] = useState("bypass WAF");
  const [output, setOutput] = useState("");
  const [why, setWhy] = useState("");
  const [loading, setLoading] = useState(false);

  const encodeLocal = () => {
    if (!input) return;
    try {
      let result = "";
      const text = input;
      switch (format) {
        case "base64": result = operation === "encode" ? btoa(text) : atob(text); break;
        case "url": result = operation === "encode" ? encodeURIComponent(text) : decodeURIComponent(text); break;
        case "url_full": result = operation === "encode" ? encodeURIComponent(text).replace(/%../g, m => m.toLowerCase()) : decodeURIComponent(text); break;
        case "html": result = operation === "encode"
          ? text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")
          : text.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#39;/g,"'"); break;
        case "hex": result = operation === "encode"
          ? Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2,"0")).join("")
          : text.match(/.{2}/g)?.map(h => String.fromCharCode(parseInt(h,16))).join("") || ""; break;
        case "unicode": result = operation === "encode"
          ? Array.from(text).map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4,"0")}`).join("")
          : text.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16))); break;
        case "binary": result = operation === "encode"
          ? Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8,"0")).join(" ")
          : text.split(" ").map(b => String.fromCharCode(parseInt(b,2))).join(""); break;
        case "rot13": result = text.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)); break;
        default: result = text;
      }
      setOutput(result);
    } catch (e) { setOutput("Error: " + e.message); }
  };

  const aiEncode = async () => {
    if (!input || loading) return;
    setLoading(true); setOutput(""); setWhy("");
    const prompt = `You are a security expert specializing in encoding techniques for penetration testing.

Input payload: ${input}
Goal: ${aiContext}

Generate multiple encoded versions to ${aiContext}:

## ENCODED VARIANTS
Generate 8-10 different encoded versions using combinations:
- Double encoding
- Mixed case
- Unicode escapes
- HTML entities
- URL encoding variants
- Null byte injection
- Comment injection
- Whitespace variations

## USE CASES
When to use each variant

## BYPASS TECHNIQUE
Technical explanation of how encoding bypasses filters

## WHY_THIS_WORKS
Why encoding/obfuscation helps bypass security controls`;

    try {
      const text = await callAI(prompt, t => {
        setOutput(t.split("## WHY_THIS_WORKS")[0]);
      });
      const m = text.match(/## WHY_THIS_WORKS\n([\s\S]*)/);
      if (m) setWhy(m[1].trim());
    } catch (e) { setOutput("Error: " + e.message); }
    setLoading(false);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <GlowCard color={C}>
        <CardHeader color={C} icon="🔄" title="Encoder Tool" subtitle="Encode, decode & obfuscate" />
        <div style={{ padding: 20 }}>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 10, color: T.muted, letterSpacing: 2, marginBottom: 5 }}>INPUT</div>
            <textarea value={input} onChange={e => setInput(e.target.value)} rows={4}
              placeholder="Enter text, payload, or data to encode/decode..."
              style={{
                width: "100%", background: "rgba(0,0,0,0.5)", border: `1px solid ${T.border}`,
                borderRadius: 6, padding: "9px 13px", color: T.text, fontSize: 13,
                fontFamily: T.font, outline: "none", boxSizing: "border-box", resize: "vertical",
              }} />
          </div>

          <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
            {[{ v: "encode", l: "ENCODE" }, { v: "decode", l: "DECODE" }].map(({ v, l }) => (
              <button key={v} onClick={() => setOperation(v)} style={{
                flex: 1, padding: "8px 0", borderRadius: 6, border: `1px solid ${operation === v ? C + "66" : T.border}`,
                background: operation === v ? `${C}12` : "transparent",
                color: operation === v ? C : T.muted, fontSize: 12, cursor: "pointer", fontFamily: T.font,
              }}>{l}</button>
            ))}
          </div>

          <Select label="FORMAT" value={format} onChange={setFormat} options={[
            { value: "base64", label: "Base64" },
            { value: "url", label: "URL Encoding" },
            { value: "url_full", label: "URL Encoding (full)" },
            { value: "html", label: "HTML Entities" },
            { value: "hex", label: "Hex" },
            { value: "unicode", label: "Unicode (\\uXXXX)" },
            { value: "binary", label: "Binary" },
            { value: "rot13", label: "ROT13" },
          ]} />

          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <button onClick={encodeLocal} style={{
              flex: 1, padding: "10px 0", borderRadius: 6, border: `1px solid ${C}44`,
              background: `${C}12`, color: C, fontSize: 12, cursor: "pointer", fontFamily: T.font, fontWeight: 700,
            }}>{operation === "encode" ? "⚡ ENCODE" : "⚡ DECODE"}</button>
            <button onClick={() => { setAiMode(!aiMode); }} style={{
              padding: "10px 14px", borderRadius: 6, border: `1px solid ${T.purple}44`,
              background: aiMode ? `${T.purple}15` : "transparent",
              color: aiMode ? T.purple : T.muted, fontSize: 12, cursor: "pointer", fontFamily: T.font,
            }}>🤖 AI</button>
          </div>

          {aiMode && (
            <>
              <Select label="AI GOAL" value={aiContext} onChange={setAiContext} options={[
                { value: "bypass WAF", label: "WAF Bypass" },
                { value: "bypass XSS filters", label: "XSS Filter Bypass" },
                { value: "bypass SQL filters", label: "SQLi Filter Bypass" },
                { value: "obfuscate payload", label: "Payload Obfuscation" },
              ]} />
              <RunBtn onClick={aiEncode} loading={loading} color={T.purple} label="🤖 AI ENCODE" />
            </>
          )}

          {output && <OutputBox content={output} color={C} label="OUTPUT" />}
          {why && <WhyBox text={why} color={C} />}
        </div>
      </GlowCard>

      <div>
        <GuidePanel color={C} tips={[
          `Double encoding مفيد لما الـ WAF بيـdecode مرة واحدة بس — %253C = < بعد decode مرتين.`,
          `HTML entities بتشتغل في contexts مختلفة — &#60; و &lt; كلاهم يساوي <.`,
          `Unicode encoding قوية جداً مع XSS — \u003cscript\u003e بيشتغل في بعض السياقات.`,
          `لو Base64 بيتفلتر، جرب Base64 بدون = في الآخر أو بـ URL-safe characters.`,
          `الـ AI mode بيولد variants متعددة — جرب كل واحد وشوف أيهم بيعدي الفلتر.`,
        ]} />
        <GlowCard color={C} style={{ marginTop: 16 }}>
          <div style={{ padding: 16 }}>
            <div style={{ fontSize: 10, color: C, letterSpacing: 2, marginBottom: 12 }}>🎯 BYPASS CHEATSHEET</div>
            {[
              { label: "< in HTML", variants: ["&lt;", "&#60;", "&#x3c;", "%3C", "\\u003c"] },
              { label: "' in SQL", variants: ["%27", "&#39;", "\\'", "''"] },
              { label: "Space bypass", variants: ["%20", "+", "/**/", "%09", "%0a"] },
            ].map(({ label, variants }) => (
              <div key={label} style={{ marginBottom: 10 }}>
                <div style={{ color: C, fontSize: 11, marginBottom: 4 }}>{label}</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {variants.map(v => (
                    <span key={v} onClick={() => setInput(v)} style={{
                      background: "rgba(0,0,0,0.4)", border: `1px solid ${C}22`,
                      color: T.text, borderRadius: 4, padding: "3px 7px", fontSize: 11,
                      cursor: "pointer",
                    }}>{v}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </GlowCard>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN TOOLS HUB
// ════════════════════════════════════════════════════════════════════════════════
export default function ToolsHub() {
  const [active, setActive] = useState("payload");
  const [glitch, setGlitch] = useState(false);

  useEffect(() => {
    const iv = setInterval(() => setGlitch(g => !g), 5000);
    return () => clearInterval(iv);
  }, []);

  const COMPONENTS = {
    payload: <PayloadGenerator />,
    subdomain: <SubdomainMonitor />,
    osint: <OSINTPro />,
    fuzzing: <FuzzingCockpit />,
    hash: <HashRefinery />,
    encoder: <EncoderTool />,
  };

  const activeTool = TOOLS.find(t => t.id === active);

  return (
    <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: T.font }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.4} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: #0a0a0a; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,157,0.2); border-radius: 3px; }
      `}</style>

      {/* Grid bg */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: "linear-gradient(rgba(0,255,157,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,157,0.02) 1px,transparent 1px)", backgroundSize: "48px 48px" }} />

      <div style={{ position: "relative", zIndex: 1 }}>
        {/* Header */}
        <div style={{
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          background: "rgba(5,10,14,0.97)", backdropFilter: "blur(10px)",
          padding: "16px 28px", display: "flex", alignItems: "center", justifyContent: "space-between",
          position: "sticky", top: 0, zIndex: 100,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 8, background: `${activeTool?.color}18`,
              border: `1px solid ${activeTool?.color}44`, display: "flex", alignItems: "center",
              justifyContent: "center", fontSize: 18, transition: "all 0.3s",
            }}>{activeTool?.icon}</div>
            <div>
              <div style={{
                fontWeight: 900, fontSize: 18, letterSpacing: -0.5,
                background: `linear-gradient(90deg, ${activeTool?.color}, ${T.text})`,
                WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
                filter: glitch ? "blur(0.3px)" : "none", transition: "filter 0.1s",
              }}>BREACHLABS TOOLS</div>
              <div style={{ fontSize: 10, color: T.muted, letterSpacing: 3 }}>AI-POWERED SECURITY TOOLKIT</div>
            </div>
          </div>
          <div style={{ fontSize: 11, color: T.muted, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: T.accent, display: "inline-block", animation: "pulse 2s infinite" }} />
            AI ENGINE ONLINE
          </div>
        </div>

        <div style={{ display: "flex", minHeight: "calc(100vh - 69px)" }}>
          {/* Sidebar */}
          <div style={{
            width: 220, flexShrink: 0, borderRight: "1px solid rgba(255,255,255,0.05)",
            background: "rgba(8,12,16,0.8)", padding: "20px 12px",
            position: "sticky", top: 69, height: "calc(100vh - 69px)", overflowY: "auto",
          }}>
            <div style={{ fontSize: 9, color: T.muted, letterSpacing: 3, marginBottom: 14, paddingLeft: 8 }}>
              TOOLS ({TOOLS.length})
            </div>
            {TOOLS.map(tool => (
              <button key={tool.id} onClick={() => setActive(tool.id)} style={{
                width: "100%", textAlign: "left", padding: "10px 12px", borderRadius: 8,
                border: `1px solid ${active === tool.id ? tool.color + "44" : "transparent"}`,
                background: active === tool.id ? `${tool.color}0e` : "transparent",
                cursor: "pointer", marginBottom: 4, transition: "all 0.2s",
                display: "flex", alignItems: "center", gap: 10, fontFamily: T.font,
              }}
                onMouseEnter={e => { if (active !== tool.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
                onMouseLeave={e => { if (active !== tool.id) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ fontSize: 16 }}>{tool.icon}</span>
                <div>
                  <div style={{ fontSize: 12, color: active === tool.id ? tool.color : T.text, fontWeight: active === tool.id ? 700 : 400 }}>
                    {tool.label}
                  </div>
                  <div style={{ fontSize: 10, color: T.muted, marginTop: 1 }}>{tool.desc}</div>
                </div>
              </button>
            ))}

            {/* Sidebar Footer */}
            <div style={{ marginTop: 24, padding: "12px", background: "rgba(0,255,157,0.04)", border: "1px solid rgba(0,255,157,0.1)", borderRadius: 8 }}>
              <div style={{ fontSize: 10, color: T.accent, marginBottom: 6 }}>⚠ AUTHORIZED USE ONLY</div>
              <div style={{ fontSize: 10, color: T.muted, lineHeight: 1.6 }}>
                Use only on systems you own or have written permission to test.
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div style={{ flex: 1, padding: "24px 28px", overflowY: "auto" }}>
            {/* Tool Header */}
            <div style={{ marginBottom: 20, paddingBottom: 16, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                <span style={{ fontSize: 22 }}>{activeTool?.icon}</span>
                <h2 style={{ margin: 0, fontSize: 20, color: activeTool?.color, fontWeight: 900 }}>{activeTool?.label}</h2>
              </div>
              <div style={{ fontSize: 12, color: T.muted }}>{activeTool?.desc} • AI-enhanced • Real-time guidance</div>
            </div>

            {/* Active Tool */}
            {COMPONENTS[active]}
          </div>
        </div>
      </div>
    </div>
  );
}
