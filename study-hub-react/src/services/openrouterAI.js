/**
 * OpenRouter AI Integration Service
 * Provides AI-powered penetration testing assistance using MiniMax M2.5
 * 
 * SECURITY: API key should be in .env file, NEVER hardcoded
 */

import axios from 'axios';

class OpenRouterAI {
  constructor(apiKey) {
    if (!apiKey) {
      throw new Error('OpenRouter API key is required. Set REACT_APP_OPENROUTER_KEY in .env');
    }
    
    this.apiKey = apiKey;
    this.baseURL = 'https://openrouter.ai/api/v1';
    this.model = 'minimax/minimax-text-01';
    this.client = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'https://study-hub3.vercel.app',
        'X-Title': 'ShadowHack Pentester AI'
      }
    });
  }

  /**
   * Analyze a target for vulnerabilities and attack vectors
   */
  async analyzeTarget(targetUrl, targetType = 'web application') {
    const prompt = `You are an expert penetration tester. Analyze this ${targetType} for potential vulnerabilities and attack vectors:

TARGET: ${targetUrl}

Provide:
1. Reconnaissance approach (tools and commands to use)
2. Common vulnerability patterns to check for this target type
3. Specific OWASP/CWE issues to investigate
4. Exploitation techniques (legal, authorized testing only)
5. Expected findings and POC creation approach
6. Tools you recommend (burp, zap, custom scripts, etc)
7. Timeline and methodology

Be practical and actionable.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Generate custom payloads for exploitation
   */
  async generatePayload(vulnerabilityType, targetInfo, encodingType = 'url-encoded') {
    const prompt = `Generate effective payloads for ${vulnerabilityType} vulnerability testing:

VULNERABILITY TYPE: ${vulnerabilityType}
TARGET INFO: ${targetInfo}
DESIRED ENCODING: ${encodingType}

Provide:
1. Base payload
2. Variations and alternatives
3. Encoding methods (${encodingType}, HTML entity, Unicode, etc)
4. WAF bypass techniques
5. Detection evasion methods
6. Delivery and execution methods
7. Detection avoidance tips

Important: Payloads are for authorized testing only on targets with permission.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Analyze captured network traffic
   */
  async analyzeTraffic(trafficData, protocol = 'HTTP') {
    const prompt = `Analyze this ${protocol} traffic capture for security insights:

TRAFFIC DATA:
${trafficData}

Identify and explain:
1. Authentication tokens, API keys, credentials
2. Hidden API endpoints and parameters
3. Injection points and attack surfaces
4. Session handling mechanisms
5. Security headers (or lack thereof)
6. Potential CSRF, XXE, or other vulnerabilities
7. Data exposure risks
8. Recommendations for next steps

Be specific and technical.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Generate a professional bug report
   */
  async generateBugReport(finding, severity, impact, targetProgram = '') {
    const prompt = `Help me write a professional bug bounty report:

FINDING: ${finding}
SEVERITY: ${severity}
BUSINESS IMPACT: ${impact}
${targetProgram ? `TARGET PROGRAM: ${targetProgram}` : ''}

Create a comprehensive bug report with:
1. Executive Summary (2-3 sentences)
2. Vulnerability Description (technical details)
3. Step-by-Step Reproduction Instructions
4. Proof of Concept (if applicable)
5. Impact Analysis (business and technical)
6. Affected Assets/Functionality
7. Remediation Recommendations
8. CVSS v3.1 Score Calculation
9. Timeline of Responsible Disclosure
10. References and Tools Used

Format it professionally for bug bounty submission.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Recommend exploitation approach for a vulnerability
   */
  async suggestExploitation(vulnerabilityDescription, targetType = 'web') {
    const prompt = `I discovered this vulnerability in a ${targetType} application:

${vulnerabilityDescription}

For authorized testing, suggest:
1. Most effective exploitation approach
2. Tools to use (manual, automated, custom)
3. Step-by-step attack plan
4. Expected results and validation
5. Advanced techniques to try
6. How to create a POC
7. How to document the finding
8. Defense mechanisms to bypass (WAF, rate limiting, etc)

Focus on practical, real-world scenarios.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Analyze source code for vulnerabilities
   */
  async analyzeCode(codeSnippet, language = 'javascript') {
    const prompt = `Security audit of ${language} code:

\`\`\`${language}
${codeSnippet}
\`\`\`

Analyze for:
1. Code injection vulnerabilities
2. Authentication/Authorization flaws
3. Cryptography weaknesses
4. Input validation issues
5. Error handling problems
6. Information disclosure
7. OWASP Top 10 issues
8. CWE classifications
9. Exploitation techniques
10. Remediation code

Provide secure code examples.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Get OSINT guidance for target
   */
  async getOSINTGuidance(target, targetType = 'domain') {
    const prompt = `OSINT strategy for ${targetType}: ${target}

Provide a complete reconnaissance plan:
1. Information to gather
2. Free tools and commands to use
3. Step-by-step enumeration approach
4. Subdomain discovery methods
5. Email and user discovery
6. Technology fingerprinting
7. Social engineering opportunities
8. Data breach databases to check
9. GitHub/Public repo searches
10. Expected findings and analysis

Include actual commands and tools.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Generate security testing checklist
   */
  async generateSecurityChecklist(appType = 'web application', scope = '') {
    const prompt = `Generate a comprehensive security testing checklist for a ${appType}:

${scope ? `ADDITIONAL SCOPE: ${scope}` : ''}

Create a detailed checklist covering:
1. Reconnaissance phase
2. Scanning and enumeration
3. Vulnerability testing
4. Authentication testing
5. Session management testing
6. Authorization testing
7. Business logic testing
8. Data validation testing
9. Cryptography testing
10. Configuration review
11. Post-exploitation steps
12. Documentation and reporting

Include specific tests, tools, and success criteria.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Get workflow recommendations
   */
  async recommendWorkflow(goal, targetInfo = '') {
    const prompt = `Penetration testing workflow recommendation:

GOAL: ${goal}
${targetInfo ? `TARGET INFO: ${targetInfo}` : ''}

Recommend:
1. Optimal testing sequence
2. Tools in order of use
3. Time estimates per phase
4. Risk assessment
5. Resource requirements
6. Expected outcomes
7. Success criteria
8. Common pitfalls to avoid

Make it practical and achievable.`;

    return this._query(prompt, 'technical');
  }

  /**
   * Private method to query OpenRouter API
   */
  async _query(prompt, type = 'general', temperature = 0.7) {
    try {
      const response = await this.client.post('/chat/completions', {
        model: this.model,
        messages: [
          {
            role: 'system',
            content: `You are an expert penetration tester, bug bounty hunter, and cybersecurity researcher with 15+ years of experience. 
            
You provide practical, detailed, and actionable guidance for authorized security testing. 
- Be technical and specific
- Include actual commands and tools
- Provide step-by-step instructions
- Suggest multiple approaches
- Mention tools and resources
- Always emphasize responsible disclosure and legal authorization

CRITICAL: All advice is for authorized testing only. Users must have explicit permission.`
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: temperature,
        max_tokens: 2000,
        top_p: 0.95
      });

      if (response.data && response.data.choices && response.data.choices[0]) {
        return response.data.choices[0].message.content;
      } else {
        throw new Error('Invalid response format from OpenRouter');
      }
    } catch (error) {
      console.error('OpenRouter AI Error:', error);
      
      if (error.response?.status === 401) {
        throw new Error('Invalid OpenRouter API key. Check .env file.');
      } else if (error.response?.status === 429) {
        throw new Error('Rate limit exceeded. Wait before trying again.');
      } else if (error.response?.status === 400) {
        throw new Error('Invalid request. Check your input.');
      }
      
      throw new Error(`AI Error: ${error.message}`);
    }
  }

  /**
   * Get usage statistics
   */
  async getUsageStats() {
    try {
      const response = await this.client.get('/auth/key');
      return response.data;
    } catch (error) {
      console.error('Failed to get usage stats:', error);
      return null;
    }
  }

  /**
   * Validate API key
   */
  async validateKey() {
    try {
      const response = await this.client.post('/chat/completions', {
        model: this.model,
        messages: [
          {
            role: 'user',
            content: 'Respond with just the word: OK'
          }
        ],
        max_tokens: 10
      });
      return response.data?.choices?.[0]?.message?.content === 'OK';
    } catch (error) {
      return false;
    }
  }
}

export default OpenRouterAI;
