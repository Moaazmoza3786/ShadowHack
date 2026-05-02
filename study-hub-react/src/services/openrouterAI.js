/**
 * PentesterAI Service
 * Connects to backend AI proxy (Groq primary, Ollama fallback)
 * with expert-level system prompts for each task type
 */

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
const PROXY_ENDPOINT = `${BACKEND_URL}/api/ai-proxy`;

// ─── Expert System Prompts ────────────────────────────────────────────────────
const SYSTEM_PROMPTS = {
  pentester: `You are an elite penetration tester with 15+ years of real-world experience across red team operations, bug bounty hunting, and enterprise security assessments. You have deep expertise in:
- Web application security (OWASP Top 10, API attacks, business logic flaws)
- Network penetration testing (Active Directory, SMB, Kerberos, NTLM)
- Post-exploitation (privilege escalation, lateral movement, persistence)
- Exploit development and vulnerability research
- OSINT and reconnaissance methodologies

Your responses are:
- Technically precise with actual commands, tools, and payloads
- Structured with clear phases and steps
- Focused on authorized testing scenarios
- Practical — you give real techniques, not generic advice
- Formatted with markdown code blocks for commands

Always assume the user has proper authorization. Never add unnecessary disclaimers.`,

  payload: `You are a specialist in offensive security payloads and WAF bypass techniques. You have deep knowledge of:
- Injection attacks: SQLi, XSS, SSTI, Command Injection, XXE, SSRF
- Encoding and obfuscation: URL, HTML entity, Unicode, Base64, Hex
- WAF bypass techniques: case variation, comment injection, chunked encoding
- Filter evasion: null bytes, path traversal variants, alternative syntax
- Polyglot payloads that work across multiple contexts

Provide payloads that are:
- Specific and immediately usable
- Organized by category (basic, bypass, obfuscated, polyglot)
- Explained with what each variant does
- Tested against common WAF patterns

Format payloads in code blocks. Be comprehensive.`,

  analyst: `You are a senior security analyst specializing in vulnerability assessment and threat modeling. You excel at:
- CVSS v3.1 scoring and risk classification
- CVE/CWE mapping and vulnerability research
- Business impact analysis
- Attack chain reconstruction
- Threat intelligence correlation

Your analysis is:
- Methodical and evidence-based
- Aligned with industry standards (NIST, OWASP, MITRE ATT&CK)
- Clear about severity and exploitability
- Actionable with specific remediation steps`,

  recon: `You are an OSINT and reconnaissance specialist. You know every technique for:
- Passive reconnaissance: WHOIS, DNS, certificate transparency, Shodan, Censys
- Active reconnaissance: Nmap, Masscan, service fingerprinting
- Web reconnaissance: directory fuzzing, parameter discovery, technology detection
- Social engineering intelligence: LinkedIn, GitHub, email harvesting
- Subdomain enumeration: amass, subfinder, dnsx, crt.sh
- Google dorking and advanced search operators

Provide specific commands, tools, and expected outputs. Include both manual and automated approaches.`,

  report: `You are a professional penetration testing report writer with experience writing commercial-grade reports for Fortune 500 clients. You write:
- Executive summaries that communicate risk to non-technical stakeholders
- Technical findings with CVSS scores, CWE references, and reproduction steps
- Clear remediation guidance with code examples
- Professional language that holds up to legal scrutiny

Structure every finding with: Title, Severity, CVSS Score, Description, Proof of Concept, Impact, Remediation, References.`,

  code: `You are a senior application security engineer specializing in secure code review. You identify:
- Injection vulnerabilities (SQLi, XSS, Command Injection, SSTI)
- Authentication and authorization flaws
- Cryptographic weaknesses (weak algorithms, improper key management)
- Insecure deserialization
- Race conditions and TOCTOU vulnerabilities
- Information disclosure and error handling issues
- OWASP Top 10 and CWE Top 25 issues

For each finding: explain the vulnerability, show the vulnerable code, provide the secure version, and give the CWE reference.`,

  general: `You are an expert cybersecurity professional and penetration tester. Provide accurate, technical, and actionable security guidance. Use markdown formatting with code blocks for commands and payloads.`
};

// ─── Cache ────────────────────────────────────────────────────────────────────
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

function getCache(key) {
  try {
    const cached = localStorage.getItem(`phai_${key}`);
    if (!cached) return null;
    const { data, ts } = JSON.parse(cached);
    if (Date.now() - ts < CACHE_TTL) return data;
    localStorage.removeItem(`phai_${key}`);
  } catch { /* ignore */ }
  return null;
}

function setCache(key, data) {
  try {
    localStorage.setItem(`phai_${key}`, JSON.stringify({ data, ts: Date.now() }));
  } catch { /* ignore quota */ }
}

function hashStr(str) {
  let h = 0;
  for (let i = 0; i < Math.min(str.length, 200); i++) {
    h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  }
  return 'h' + Math.abs(h).toString(36);
}

// ─── Core query function ──────────────────────────────────────────────────────
async function query(systemPrompt, userPrompt, opts = {}) {
  const { temperature = 0.7, maxTokens = 4096, useCache = true, provider } = opts;

  const cacheKey = hashStr((provider || '') + systemPrompt.slice(0, 50) + userPrompt);
  if (useCache) {
    const cached = getCache(cacheKey);
    if (cached) return cached;
  }

  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt }
  ];

  // Get preferred provider from localStorage (set by user in UI)
  const preferredProvider = provider || localStorage.getItem('ai_provider') || 'auto';

  try {
    const resp = await fetch(`${PROXY_ENDPOINT}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages,
        temperature,
        max_tokens: maxTokens,
        provider: preferredProvider,
      }),
      signal: AbortSignal.timeout(180000) // 3 min for local models
    });

    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(`Backend error ${resp.status}: ${err}`);
    }

    const data = await resp.json();
    const result = data.content;
    if (useCache) setCache(cacheKey, result);
    return result;

  } catch (err) {
    // If backend is completely down, try Ollama directly
    if (err.name === 'TypeError' || err.message.includes('fetch')) {
      return queryOllamaDirect(systemPrompt, userPrompt, temperature, maxTokens);
    }
    throw err;
  }
}

// ─── Direct Ollama fallback ───────────────────────────────────────────────────
async function queryOllamaDirect(systemPrompt, userPrompt, temperature = 0.7, maxTokens = 4096) {
  const resp = await fetch('http://localhost:11434/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'qwen2.5-coder:7b',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature,
      max_tokens: maxTokens,
    }),
    signal: AbortSignal.timeout(120000)
  });

  if (!resp.ok) throw new Error(`Ollama error: ${resp.status}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content || '';
}

// ─── Streaming query ──────────────────────────────────────────────────────────
async function* queryStream(systemPrompt, userPrompt, opts = {}) {
  const { temperature = 0.7, maxTokens = 4096 } = opts;

  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt }
  ];

  try {
    const resp = await fetch(`${PROXY_ENDPOINT}/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages, temperature, max_tokens: maxTokens }),
      signal: AbortSignal.timeout(120000)
    });

    if (!resp.ok) throw new Error(`Stream error: ${resp.status}`);

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') return;
        try {
          const parsed = JSON.parse(data);
          if (parsed.chunk) yield parsed.chunk;
          if (parsed.error) throw new Error(parsed.error);
        } catch { /* skip malformed */ }
      }
    }
  } catch (err) {
    // Fallback: get full response and yield it
    const full = await queryOllamaDirect(systemPrompt, userPrompt, temperature, maxTokens);
    yield full;
  }
}

// ─── PentesterAI class ────────────────────────────────────────────────────────
class OpenRouterAI {
  constructor(apiKey = 'local') {
    this.apiKey = apiKey;
    // Keep these for backward compat
    this.endpoint = `${PROXY_ENDPOINT}/chat`;
    this.model = 'groq/llama-3.3-70b-versatile';
  }

  // ── Target Analysis ──────────────────────────────────────────────────────
  async analyzeTarget(target, targetType = 'web application') {
    const prompt = `Perform a comprehensive penetration testing analysis for this target:

TARGET: ${target}
TYPE: ${targetType}

Provide a structured attack plan:

## 1. Reconnaissance Phase
- Passive recon commands (WHOIS, DNS, crt.sh, Shodan)
- Active recon commands (Nmap, service detection)
- Technology fingerprinting approach

## 2. Attack Surface Mapping
- Identified entry points and attack vectors
- Specific OWASP/CWE issues to investigate for this target type
- API endpoints and hidden functionality to discover

## 3. Exploitation Strategy
- Priority vulnerabilities to test (ranked by impact)
- Specific tools and commands for each vector
- Payload types to try

## 4. Post-Exploitation
- Privilege escalation paths
- Lateral movement opportunities
- Data exfiltration approach

## 5. Tools & Commands
Provide exact commands ready to run.`;

    return query(SYSTEM_PROMPTS.pentester, prompt, { temperature: 0.6 });
  }

  // ── Payload Generation ───────────────────────────────────────────────────
  async generatePayload(vulnType, targetInfo, encodingType = 'raw') {
    const prompt = `Generate a comprehensive payload set for: **${vulnType}**

TARGET CONTEXT: ${targetInfo}
ENCODING: ${encodingType}

Provide:

## Basic Payloads
\`\`\`
[5-10 fundamental payloads]
\`\`\`

## WAF Bypass Variants
\`\`\`
[Obfuscated, encoded, case-varied versions]
\`\`\`

## Advanced / Polyglot
\`\`\`
[Context-breaking, multi-vector payloads]
\`\`\`

## Delivery Method
How to inject and trigger each payload type.

## Detection Evasion
Specific techniques to avoid WAF/IDS detection.`;

    return query(SYSTEM_PROMPTS.payload, prompt, { temperature: 0.5, useCache: false });
  }

  // ── Traffic Analysis ─────────────────────────────────────────────────────
  async analyzeTraffic(trafficData, protocol = 'HTTP') {
    const prompt = `Analyze this ${protocol} traffic for security vulnerabilities:

\`\`\`
${trafficData}
\`\`\`

Identify:
1. **Credentials & Tokens** — API keys, session tokens, passwords in plaintext
2. **Injection Points** — Parameters vulnerable to SQLi, XSS, Command Injection
3. **Authentication Flaws** — Weak tokens, missing validation, session issues
4. **Information Disclosure** — Server headers, error messages, internal paths
5. **Business Logic** — Exploitable workflows, IDOR opportunities
6. **Next Steps** — Specific attacks to attempt based on findings`;

    return query(SYSTEM_PROMPTS.analyst, prompt, { temperature: 0.3 });
  }

  // ── Bug Report Generation ────────────────────────────────────────────────
  async generateBugReport(finding, severity = 'High', impact = '') {
    const prompt = `Write a professional bug bounty report for this finding:

**FINDING:** ${finding}
**SEVERITY:** ${severity}
**IMPACT:** ${impact}

Structure:
# [Vulnerability Title]

**Severity:** ${severity}
**CVSS v3.1 Score:** [Calculate and explain]
**CWE:** [Relevant CWE ID and name]

## Summary
[2-3 sentence executive summary]

## Vulnerability Description
[Technical explanation of the vulnerability]

## Steps to Reproduce
1. [Step by step]
2. ...

## Proof of Concept
\`\`\`
[Request/payload/code]
\`\`\`

## Impact
[Business and technical impact]

## Remediation
[Specific fix with code example if applicable]

## References
[CVE, OWASP, CWE links]`;

    return query(SYSTEM_PROMPTS.report, prompt, { temperature: 0.4 });
  }

  // ── Exploitation Suggestions ─────────────────────────────────────────────
  async suggestExploitation(vulnDesc, targetType = 'web') {
    const prompt = `I found this vulnerability in a ${targetType} application:

${vulnDesc}

Provide a complete exploitation guide:

## Exploitation Approach
Step-by-step attack methodology

## Tools Required
Specific tools with installation commands

## Proof of Concept
Working exploit code/commands

## Advanced Techniques
- WAF bypass methods
- Filter evasion
- Chaining with other vulnerabilities

## Impact Demonstration
How to prove maximum impact for the report

## Detection Avoidance
How to stay under the radar during testing`;

    return query(SYSTEM_PROMPTS.pentester, prompt, { temperature: 0.6 });
  }

  // ── Code Analysis ────────────────────────────────────────────────────────
  async analyzeCode(code, language = 'javascript') {
    const prompt = `Perform a security audit of this ${language} code:

\`\`\`${language}
${code}
\`\`\`

For each vulnerability found:

### [Vulnerability Name] — [Severity: Critical/High/Medium/Low]
**CWE:** [CWE-XXX]
**Location:** [Line/function]
**Issue:** [What's wrong]
**Vulnerable Code:**
\`\`\`${language}
[The problematic snippet]
\`\`\`
**Secure Version:**
\`\`\`${language}
[Fixed code]
\`\`\`
**Exploitation:** [How an attacker would exploit this]`;

    return query(SYSTEM_PROMPTS.code, prompt, { temperature: 0.3 });
  }

  // ── OSINT Guidance ───────────────────────────────────────────────────────
  async getOSINTGuidance(target, targetType = 'domain') {
    const prompt = `Create a complete OSINT reconnaissance plan for: **${target}** (${targetType})

## Passive Reconnaissance
\`\`\`bash
# WHOIS, DNS, Certificate Transparency
[Exact commands]
\`\`\`

## Subdomain Enumeration
\`\`\`bash
[amass, subfinder, dnsx commands]
\`\`\`

## Technology Fingerprinting
\`\`\`bash
[whatweb, wappalyzer, shodan commands]
\`\`\`

## Email & Employee Discovery
[theHarvester, LinkedIn, Hunter.io approach]

## GitHub & Code Leaks
\`\`\`bash
[trufflehog, gitleaks, GitHub dork queries]
\`\`\`

## Google Dorks
\`\`\`
[10+ specific dorks for this target]
\`\`\`

## Shodan/Censys Queries
\`\`\`
[Specific queries]
\`\`\`

## Expected Findings
What you're likely to discover and how to use it.`;

    return query(SYSTEM_PROMPTS.recon, prompt, { temperature: 0.5 });
  }

  // ── Security Checklist ───────────────────────────────────────────────────
  async generateSecurityChecklist(appType = 'web application', scope = '') {
    const prompt = `Generate a comprehensive penetration testing checklist for: **${appType}**
${scope ? `\nScope: ${scope}` : ''}

Format as a detailed checklist with checkboxes, organized by phase:

## Phase 1: Reconnaissance
- [ ] [Specific test with tool/command]
...

## Phase 2: Scanning & Enumeration
...

## Phase 3: Vulnerability Assessment
...

## Phase 4: Exploitation
...

## Phase 5: Post-Exploitation
...

## Phase 6: Reporting
...

Include specific tools, commands, and success criteria for each item.`;

    return query(SYSTEM_PROMPTS.pentester, prompt, { temperature: 0.5 });
  }

  // ── Workflow Recommendation ──────────────────────────────────────────────
  async recommendWorkflow(goal, targetInfo = '') {
    const prompt = `Design a penetration testing workflow for this objective:

**GOAL:** ${goal}
${targetInfo ? `**TARGET:** ${targetInfo}` : ''}

Provide:

## Attack Path
Visual representation of the attack chain

## Phase Breakdown
| Phase | Duration | Tools | Objective |
|-------|----------|-------|-----------|
[Fill in]

## Step-by-Step Execution
1. [Detailed step with commands]
...

## Decision Points
- If X → do Y
- If blocked → try Z

## Success Criteria
How to know you've achieved the objective

## Common Pitfalls
What to avoid and why`;

    return query(SYSTEM_PROMPTS.pentester, prompt, { temperature: 0.6 });
  }

  // ── Smart Recommendations ────────────────────────────────────────────────
  async getSmartRecommendations(userData) {
    const prompt = `Based on this cybersecurity student's progress, suggest the most critical next steps:

USER DATA:
- XP: ${userData.points || 0}
- Level: ${userData.level || 1}
- Completed: ${userData.completedModules || 'General Foundation'}
- Current Path: ${userData.currentPath || 'Pentesting'}

Provide:
1. "Neural Target": The most important next lab or course to take.
2. "Strategic Rationale": Why this is important for their current progress.
3. "Technical Roadmap": 3 specific skills to master next.
4. "Resource Suggestion": specific tool or methodology to study.

Keep it tactical and encouraging.`;

    return query(SYSTEM_PROMPTS.general, prompt, { temperature: 0.7 });
  }

  // ── Enhance Finding ──────────────────────────────────────────────────────
  async enhanceFinding(findingTitle, context = '') {
    const prompt = `Enhance this security finding into a professional report segment:

FINDING: ${findingTitle}
CONTEXT: ${context}

Provide:
1. **TITLE:** Professional descriptive title
2. **SEVERITY:** Recommended severity with CVSS justification
3. **DESCRIPTION:** Deep technical explanation (2-3 paragraphs)
4. **REPRODUCTION:** 5-7 clear steps
5. **REMEDIATION:** Specific fix with secure code example

Use professional Markdown formatting.`;

    return query(SYSTEM_PROMPTS.report, prompt, { temperature: 0.4 });
  }

  // ── Structured Roadmap ───────────────────────────────────────────────────
  async getStructuredRoadmap(userData) {
    const prompt = `Based on this cybersecurity student's progress, create a structured learning roadmap.

USER DATA:
- XP: ${userData.points || 0}
- Level: ${userData.level || 1}
- Completed: ${userData.completedModules || 'General Foundation'}

Return EXACTLY 4 steps in this format (plain text, one per line):
STEP1_TITLE: [short title]
STEP1_DESC: [one sentence description]
STEP1_TYPE: [course/lab/tool/challenge]
STEP2_TITLE: [short title]
STEP2_DESC: [one sentence description]
STEP2_TYPE: [course/lab/tool/challenge]
STEP3_TITLE: [short title]
STEP3_DESC: [one sentence description]
STEP3_TYPE: [course/lab/tool/challenge]
STEP4_TITLE: [short title]
STEP4_DESC: [one sentence description]
STEP4_TYPE: [course/lab/tool/challenge]`;

    const raw = await query(SYSTEM_PROMPTS.general, prompt, { temperature: 0.6 });

    const steps = [];
    for (let i = 1; i <= 4; i++) {
      const titleMatch = raw.match(new RegExp(`STEP${i}_TITLE:\\s*(.+)`));
      const descMatch = raw.match(new RegExp(`STEP${i}_DESC:\\s*(.+)`));
      const typeMatch = raw.match(new RegExp(`STEP${i}_TYPE:\\s*(.+)`));
      if (titleMatch) {
        steps.push({
          title: titleMatch[1].trim(),
          description: descMatch ? descMatch[1].trim() : '',
          type: typeMatch ? typeMatch[1].trim().toLowerCase() : 'course'
        });
      }
    }

    return { raw, steps };
  }

  // ── Report Content ───────────────────────────────────────────────────────
  async generateReportContent(findings) {
    const list = findings.map((f, i) =>
      `Finding ${i + 1}: ${f.title} (${f.severity})\n${f.description || ''}\nRemediation: ${f.remediation || ''}`
    ).join('\n\n');

    const prompt = `Create a professional executive summary for a penetration test report:\n\n${list}\n\nProvide:\n1. Executive Summary (2 paragraphs)\n2. Risk Overview\n3. Key Recommendations\n\nFormat in Markdown.`;

    return query(SYSTEM_PROMPTS.report, prompt, { temperature: 0.4 });
  }

  // ── Streaming chat ───────────────────────────────────────────────────────
  async *streamChat(userMessage, role = 'pentester') {
    const systemPrompt = SYSTEM_PROMPTS[role] || SYSTEM_PROMPTS.general;
    yield* queryStream(systemPrompt, userMessage);
  }

  // ── Status check ─────────────────────────────────────────────────────────
  async checkStatus() {
    try {
      const resp = await fetch(`${PROXY_ENDPOINT}/status`, { signal: AbortSignal.timeout(5000) });
      if (!resp.ok) return { available: false, provider: 'none' };
      const data = await resp.json();
      return { available: data.primary !== 'none', ...data };
    } catch {
      return { available: false, provider: 'none' };
    }
  }

  // ── Set preferred provider ────────────────────────────────────────────────
  setProvider(provider) {
    // "local" | "cloud" | "auto"
    localStorage.setItem('ai_provider', provider);
  }

  getProvider() {
    return localStorage.getItem('ai_provider') || 'auto';
  }

  // ── List available Ollama models ──────────────────────────────────────────
  async getModels() {
    try {
      const resp = await fetch(`${PROXY_ENDPOINT}/models`, { signal: AbortSignal.timeout(5000) });
      if (!resp.ok) return { ollama_models: [], groq_models: [] };
      return await resp.json();
    } catch {
      return { ollama_models: [], groq_models: [] };
    }
  }

  // ── Backward compat stubs ────────────────────────────────────────────────
  async validateKey() { return (await this.checkStatus()).available; }
  async getUsageStats() { return this.checkStatus(); }
}

export default OpenRouterAI;
