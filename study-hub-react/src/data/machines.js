export const machines = [
    {
        id: 'apollo-01',
        name: 'APOLLO-01',
        os: 'Linux / Ubuntu',
        level: 'Beginner',
        points: 200,
        desc: 'Information gathering and basic exploitation of a misconfigured web server.',
        ip: '10.129.2.14',
        scenario: 'corporate_web',
        briefing: 'TechCorp internal staging server. Reports indicate a legacy PHP version and unpatched directory traversal.'
    },
    {
        id: 'zeus-frame',
        name: 'ZEUS-FRAME',
        os: 'Windows Server',
        level: 'Intermediate',
        points: 500,
        desc: 'Advanced Active Directory exploitation and lateral movement.',
        ip: '10.129.2.55',
        scenario: 'active_directory',
        briefing: 'Central domain controller for GlobalLogistics. Target high-value service accounts and look for Kerberoasting opportunities.'
    },
    {
        id: 'cronos',
        name: 'CRONOS',
        os: 'Linux / Debian',
        level: 'Hard',
        points: 800,
        desc: 'Exploiting complex binary vulnerabilities and root privilege escalation.',
        ip: '10.129.2.99',
        scenario: 'research_lab',
        briefing: 'Restricted research hub. Protected by EDR and customized kernel modules. Requires buffer overflow chained with local privilege escalation.'
    },
    {
        id: 'dvwa',
        name: 'DVWA',
        os: 'Linux / Docker',
        level: 'Beginner',
        points: 300,
        desc: 'Damn Vulnerable Web App - Practice SQLi, Bruteforce, and Command Injection.',
        ip: '127.0.0.1',
        scenario: 'training',
        briefing: 'Standardized vulnerable application for honing web exploitation fundamentals.'
    }
];
