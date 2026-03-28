// ==================== AI HINTS DATA ====================

const hintsData = {
    // Global / General Hints
    'global': [
        { text: "💡 Did you know? You can use the 'Tools' section to encode/decode strings quickly.", cost: 0 },
        { text: "💡 Stuck? Try breaking the problem into smaller steps.", cost: 0 },
        { text: "💡 Always check the source code (Ctrl+U) for hidden comments.", cost: 0 }
    ],

    // Page-Specific Hints
    'recon': [
        { text: "For recon, start with passive information gathering before active scanning.", cost: 0 },
        { text: "Use 'Amass' to find subdomains that aren't linked directly.", cost: 10 },
        { text: "Don't forget to check for 'robots.txt' and 'sitemap.xml'.", cost: 20 }
    ],
    'scan': [
        { text: "Nmap '-sC' runs default scripts which can find common vulnerabilities.", cost: 0 },
        { text: "Use '-p-' to scan all 65535 ports, not just the top 1000.", cost: 10 },
        { text: "FFUF is great for directory busting. Use a good wordlist like 'common.txt'.", cost: 20 }
    ],
    'vulns': [
        { text: "OWASP Top 10 is your bible. Master these vulnerabilities first.", cost: 0 },
        { text: "For XSS, always test if your input is reflected back in the response.", cost: 10 },
        { text: "SQL Injection often happens when user input is concatenated directly into queries.", cost: 10 }
    ],

    // Challenge-Specific Hints (mapped by challenge ID)
    'sql-injection-basic': [
        { level: 1, cost: 0, text: "The query likely looks like: SELECT * FROM users WHERE user='...' AND pass='...'" },
        { level: 2, cost: 20, text: "Try to manipulate the query to make the condition always true (OR 1=1)." },
        { level: 3, cost: 50, text: "Use a comment character (# or --) to ignore the rest of the query. Payload: admin' --" }
    ],
    'xss-reflected': [
        { level: 1, cost: 0, text: "Whatever you type in the search box appears on the page." },
        { level: 2, cost: 20, text: "Try injecting HTML tags like <h1>test</h1> to see if they render." },
        { level: 3, cost: 50, text: "Inject a script tag to execute JavaScript. Payload: <script>alert(1)</script>" }
    ],
    'idor-user-profile': [
        { level: 1, cost: 0, text: "Look at the URL parameters. Do you see an ID?" },
        { level: 2, cost: 20, text: "What happens if you change the ID to another number?" },
        { level: 3, cost: 50, text: "Change 'id=101' to 'id=1' to potentially access the admin profile." }
    ]
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = hintsData;
}
