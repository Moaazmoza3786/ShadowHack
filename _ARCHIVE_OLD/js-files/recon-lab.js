/* ==================== RECON AUTOMATION LAB v2.0 🔍🎯 ==================== */
/* Bug Bounty & Pentest Reconnaissance - Enhanced for Certifications */

window.ReconLab = {
    // --- STATE ---
    currentTab: 'subdomain',
    targetDomain: '',
    targetIP: '',

    // === NEW: V2 STATE ===
    terminal: { output: [], isRunning: false, processId: null },
    graph: { nodes: [] },

    // TERMINAL SIMULATION
    runTerminal(cmd) {
        if (this.terminal.isRunning) return;
        this.terminal.isRunning = true;
        this.terminal.output = [`<span class="term-prompt">root@kali:~#</span> ${cmd}`];
        this.renderTerminal();

        const outputs = [
            'Starting process...', 'Resolving target...', 'Initiating scan modules...',
            '[+] Target is up (lat: 23ms)', '[+] Enumerating subdomains...',
            'Found: admin.target.com (200 OK)', 'Found: dev.target.com (403 Forbidden)',
            'Found: api.target.com (200 OK)', '[+] Port scan starting...',
            'Discovered open port 80/tcp (http)', 'Discovered open port 443/tcp (https)',
            'Discovered open port 22/tcp (ssh)', '[*] Service detection performing...',
            '80/tcp: Apache/2.4.41 (Ubuntu)', '443/tcp: nginx/1.18.0',
            '[+] Vulnerability scan initiated...', '[!] Potential CVE-2021-41773 detected on port 80',
            'Scan completed in 4.23s'
        ];

        let i = 0;
        this.terminal.processId = setInterval(() => {
            if (i >= outputs.length) {
                this.terminal.isRunning = false;
                this.terminal.output.push('<span class="term-success">Done.</span>\n<span class="term-prompt">root@kali:~#</span>');
                clearInterval(this.terminal.processId);
                this.updateGraph();
            } else {
                this.terminal.output.push(outputs[i++]);
            }
            this.renderTerminal();
        }, 600);
    },

    renderTerminal() {
        const term = document.getElementById('recon-term-out');
        if (term) {
            term.innerHTML = this.terminal.output.join('\n');
            term.scrollTop = term.scrollHeight;
        }
    },

    // AI ANALYST
    analyzeResults() {
        if (this.terminal.output.length < 5) return alert('Run a scan first!');
        const panel = document.getElementById('ai-analysis-panel');
        panel.innerHTML = '<div class="ai-loading"><i class="fas fa-spinner fa-spin"></i> Analyzing...</div>';

        setTimeout(() => {
            panel.innerHTML = `
                <div class="ai-result fade-in">
                    <h4><i class="fas fa-robot"></i> AI Strategic Insight</h4>
                    <ul class="ai-list">
                        <li><span class="tag-crit">CRITICAL</span> <strong>Apache Path Traversal</strong>: Port 80 is vulnerable to CVE-2021-41773. Attempt to read <code>/etc/passwd</code>.</li>
                        <li><span class="tag-med">MEDIUM</span> <strong>Dev Subdomain</strong>: <code>dev.target.com</code> returned 403, try bypasses.</li>
                        <li><span class="tag-low">INFO</span> <strong>SSH Exposed</strong>: Check for weak credentials.</li>
                    </ul>
                    <div class="ai-action"><strong>Recommended Command:</strong><code>curl -v --path-as-is http://${this.targetDomain}/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd</code></div>
                </div>`;
        }, 2000);
    },

    // ASSET GRAPH
    updateGraph() {
        const graph = document.getElementById('asset-graph');
        if (!graph) return;
        graph.innerHTML = `
            <div class="node-root"><i class="fas fa-globe"></i> ${this.targetDomain}</div>
            <div class="node-branch"></div>
            <div class="node-leaf" style="left:20%"><i class="fas fa-server"></i> www</div>
            <div class="node-leaf" style="left:50%"><i class="fas fa-server"></i> api</div>
            <div class="node-leaf node-vuln" style="left:80%"><i class="fas fa-bomb"></i> admin</div>
        `;
    },

    renderGraphTab() {
        return `
            <div class="graph-container">
                <h3><i class="fas fa-sitemap"></i> Attack Surface Map</h3>
                <div id="asset-graph" class="asset-graph-viz"><div class="graph-placeholder">Run a scan to generate the asset map.</div></div>
            </div>`;
    },
    tools: {
        subdomain: [
            { name: 'Subfinder', cmd: 'subfinder -d {DOMAIN} -all -o subdomains.txt', desc: 'Fast passive subdomain enum', category: 'Passive' },
            { name: 'Amass Passive', cmd: 'amass enum -passive -d {DOMAIN} -o amass.txt', desc: 'In-depth discovery', category: 'Passive' },
            { name: 'Amass Active', cmd: 'amass enum -active -d {DOMAIN} -brute -o amass_active.txt', desc: 'Active brute force', category: 'Active' },
            { name: 'Assetfinder', cmd: 'assetfinder --subs-only {DOMAIN} | tee assetfinder.txt', desc: 'Quick subdomain finding', category: 'Passive' },
            { name: 'Findomain', cmd: 'findomain -t {DOMAIN} -o', desc: 'Cross-platform enum', category: 'Passive' },
            { name: 'Sublist3r', cmd: 'python sublist3r.py -d {DOMAIN} -o sublist3r.txt', desc: 'Python subdomain enum', category: 'Passive' },
            { name: 'crt.sh', cmd: 'curl -s "https://crt.sh/?q=%25.{DOMAIN}&output=json" | jq -r ".[].name_value" | sort -u', desc: 'Certificate transparency', category: 'Passive' },
            { name: 'Shodan', cmd: 'shodan search hostname:{DOMAIN}', desc: 'Shodan subdomain search', category: 'Passive' },
            { name: 'Censys', cmd: 'censys search "{DOMAIN}"', desc: 'Censys certificate search', category: 'Passive' },
            { name: 'GitHub Dorking', cmd: 'site:github.com "{DOMAIN}"', desc: 'GitHub secrets search', category: 'OSINT' },
            { name: 'DNSRecon', cmd: 'dnsrecon -d {DOMAIN} -t std', desc: 'DNS enumeration', category: 'Active' },
            { name: 'Fierce', cmd: 'fierce --domain {DOMAIN}', desc: 'DNS reconnaissance', category: 'Active' },
            { name: 'Knockpy', cmd: 'knockpy {DOMAIN}', desc: 'Subdomain scan', category: 'Active' },
            { name: 'Bruteforce', cmd: 'gobuster dns -d {DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50', desc: 'DNS brute force', category: 'Active' },
            { name: 'Merge & Dedupe', cmd: 'cat *.txt | sort -u > all_subdomains.txt', desc: 'Combine results', category: 'Utility' }
        ],
        portscan: [
            { name: 'Nmap Quick', cmd: 'nmap -sC -sV -T4 {IP} -oA quick', desc: 'Quick version scan', category: 'Basic' },
            { name: 'Nmap Full TCP', cmd: 'nmap -p- -T4 {IP} -oA full_tcp', desc: 'All 65535 TCP ports', category: 'Full' },
            { name: 'Nmap Service', cmd: 'nmap -sV -sC -p- {IP} -oA services', desc: 'Service detection', category: 'Full' },
            { name: 'Nmap UDP Top', cmd: 'sudo nmap -sU --top-ports 100 {IP} -oA udp', desc: 'UDP top 100 ports', category: 'UDP' },
            { name: 'Nmap Vuln', cmd: 'nmap --script vuln {IP} -oA vuln_scan', desc: 'Vulnerability scripts', category: 'Vuln' },
            { name: 'Nmap SMB', cmd: 'nmap --script smb-enum-* -p 139,445 {IP}', desc: 'SMB enumeration', category: 'SMB' },
            { name: 'Nmap HTTP', cmd: 'nmap --script http-* -p 80,443,8080 {IP}', desc: 'HTTP scripts', category: 'Web' },
            { name: 'Rustscan', cmd: 'rustscan -a {IP} -- -sC -sV', desc: 'Fast port discovery', category: 'Fast' },
            { name: 'Masscan Fast', cmd: 'masscan -p1-65535 {IP} --rate=1000 -oL masscan.txt', desc: 'Ultra-fast scanning', category: 'Fast' },
            { name: 'Nmap Stealth', cmd: 'nmap -sS -T2 -f {IP}', desc: 'Stealth SYN scan', category: 'Stealth' },
            { name: 'Nmap OS Detect', cmd: 'sudo nmap -O {IP}', desc: 'OS detection', category: 'OS' },
            { name: 'Nmap Ping Sweep', cmd: 'nmap -sn 192.168.1.0/24', desc: 'Network discovery', category: 'Discovery' }
        ],
        alive: [
            { name: 'httpx', cmd: 'cat subdomains.txt | httpx -silent -threads 100 -o alive.txt', desc: 'Fast URL prober', category: 'HTTP' },
            { name: 'httprobe', cmd: 'cat subdomains.txt | httprobe -c 50 > alive.txt', desc: 'HTTP/HTTPS prober', category: 'HTTP' },
            { name: 'httpx Full', cmd: 'httpx -l subdomains.txt -title -status-code -tech-detect -o httpx_full.txt', desc: 'Full info', category: 'HTTP' },
            { name: 'Masscan Quick', cmd: 'masscan -p80,443,8080,8443 -iL ips.txt --rate 10000 -oL masscan.txt', desc: 'Fast port scanner', category: 'Ports' },
            { name: 'Resolve DNS', cmd: 'cat subdomains.txt | dnsx -silent -a -resp-only -o resolved.txt', desc: 'DNS resolution', category: 'DNS' },
            { name: 'Gowitness', cmd: 'gowitness file -f alive.txt -P screenshots/', desc: 'Screenshot websites', category: 'Visual' },
            { name: 'Aquatone', cmd: 'cat alive.txt | aquatone -out aquatone/', desc: 'Visual recon', category: 'Visual' },
            { name: 'EyeWitness', cmd: 'python EyeWitness.py -f alive.txt --web', desc: 'Web screenshots', category: 'Visual' }
        ],
        urls: [
            { name: 'Waybackurls', cmd: 'echo {DOMAIN} | waybackurls | tee wayback.txt', desc: 'Archive URL fetch', category: 'Archive' },
            { name: 'GAU', cmd: 'echo {DOMAIN} | gau --threads 5 | tee gau.txt', desc: 'Get all URLs', category: 'Archive' },
            { name: 'Hakrawler', cmd: 'echo {DOMAIN} | hakrawler -d 3 | tee hakrawler.txt', desc: 'Fast web crawler', category: 'Crawler' },
            { name: 'Katana', cmd: 'katana -u {DOMAIN} -d 3 -o katana.txt', desc: 'Next-gen crawler', category: 'Crawler' },
            { name: 'ParamSpider', cmd: 'python paramspider.py -d {DOMAIN}', desc: 'Parameter discovery', category: 'Params' },
            { name: 'LinkFinder', cmd: 'python linkfinder.py -i https://{DOMAIN} -o cli', desc: 'JS endpoint extraction', category: 'JS' },
            { name: 'Filter Params', cmd: "grep '=' urls.txt | sort -u > params.txt", desc: 'Extract params', category: 'Filter' },
            { name: 'Filter JS', cmd: "grep -E '\\.js(\\?|$)' urls.txt > js_files.txt", desc: 'Extract JS files', category: 'Filter' },
            { name: 'URO', cmd: 'cat urls.txt | uro > cleaned_urls.txt', desc: 'Dedupe URLs', category: 'Filter' }
        ],
        vulnscan: [
            { name: 'Nuclei All', cmd: 'nuclei -l alive.txt -t ~/nuclei-templates/ -o nuclei.txt', desc: 'All templates', category: 'All' },
            { name: 'Nuclei Critical', cmd: 'nuclei -l alive.txt -s critical,high -o critical.txt', desc: 'High severity', category: 'Severe' },
            { name: 'Nuclei CVE', cmd: 'nuclei -l alive.txt -t cves/ -o cve.txt', desc: 'CVE check', category: 'CVE' },
            { name: 'Nuclei Exposed', cmd: 'nuclei -l alive.txt -t exposed-panels/ -o exposed.txt', desc: 'Exposed panels', category: 'Panels' },
            { name: 'Nuclei Misconfig', cmd: 'nuclei -l alive.txt -t misconfiguration/ -o misconfig.txt', desc: 'Misconfigurations', category: 'Config' },
            { name: 'Nikto', cmd: 'nikto -h https://{DOMAIN} -o nikto.txt', desc: 'Web server scanner', category: 'Web' },
            { name: 'Dalfox XSS', cmd: 'dalfox file params.txt -o xss.txt', desc: 'XSS testing', category: 'XSS' },
            { name: 'SQLMap', cmd: 'sqlmap -m params.txt --batch --random-agent', desc: 'SQL injection', category: 'SQLi' },
            { name: 'Corsy CORS', cmd: 'python corsy.py -i alive.txt', desc: 'CORS misconfig', category: 'CORS' },
            { name: 'CRLFuzz', cmd: 'crlfuzz -l alive.txt -o crlf.txt', desc: 'CRLF injection', category: 'CRLF' },
            { name: 'Smuggler', cmd: 'python smuggler.py -u https://{DOMAIN}', desc: 'HTTP smuggling', category: 'Smuggle' }
        ],
        fuzzing: [
            { name: 'FFUF Directory', cmd: "ffuf -u https://{DOMAIN}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302,403", desc: 'Directory brute', category: 'Dir' },
            { name: 'Gobuster Dir', cmd: 'gobuster dir -u https://{DOMAIN} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50', desc: 'Directory brute', category: 'Dir' },
            { name: 'Feroxbuster', cmd: 'feroxbuster -u https://{DOMAIN} -w wordlist.txt -d 2 -t 100', desc: 'Recursive content', category: 'Dir' },
            { name: 'FFUF Subdomain', cmd: "ffuf -u https://FUZZ.{DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200", desc: 'Subdomain brute', category: 'DNS' },
            { name: 'FFUF VHost', cmd: "ffuf -u https://{DOMAIN} -H 'Host: FUZZ.{DOMAIN}' -w vhosts.txt -mc 200", desc: 'Virtual host', category: 'VHost' },
            { name: 'FFUF Params', cmd: "ffuf -u 'https://{DOMAIN}?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt", desc: 'Parameter fuzz', category: 'Params' },
            { name: 'Wfuzz', cmd: 'wfuzz -c -w wordlist.txt --hc 404 https://{DOMAIN}/FUZZ', desc: 'Flexible fuzzer', category: 'General' },
            { name: 'Dirsearch', cmd: 'dirsearch -u https://{DOMAIN} -e php,asp,aspx,jsp -t 50', desc: 'Dir/file brute', category: 'Dir' }
        ],
        js: [
            { name: 'GetJS', cmd: 'echo https://{DOMAIN} | getJS --complete', desc: 'Extract JS files', category: 'Extract' },
            { name: 'JSFinder', cmd: 'python JSFinder.py -u https://{DOMAIN}', desc: 'JS endpoint finder', category: 'Endpoints' },
            { name: 'SecretFinder', cmd: 'python SecretFinder.py -i https://{DOMAIN}/app.js -o cli', desc: 'Secrets in JS', category: 'Secrets' },
            { name: 'LinkFinder', cmd: 'python linkfinder.py -i https://{DOMAIN} -d', desc: 'Find links in JS', category: 'Endpoints' },
            { name: 'Retire.js', cmd: 'retire --jspath /path/to/js/', desc: 'Vulnerable JS libs', category: 'Vuln' },
            { name: 'JSluice', cmd: 'cat js_files.txt | jsluice urls', desc: 'Extract URLs from JS', category: 'Extract' },
            { name: 'Mantra', cmd: 'mantra -u https://{DOMAIN}', desc: 'API key finder', category: 'Secrets' }
        ],
        cloud: [
            { name: 'S3Scanner', cmd: 'python s3scanner.py sites.txt', desc: 'S3 bucket finder', category: 'AWS' },
            { name: 'CloudEnum', cmd: 'python cloudenum.py -k {DOMAIN}', desc: 'Multi-cloud enum', category: 'All' },
            { name: 'GrayhatWarfare', cmd: 'Search: site:grayhatwarfare.com {DOMAIN}', desc: 'Open bucket search', category: 'Search' },
            { name: 'AWS S3 Brute', cmd: "for i in $(cat keywords.txt); do curl -s 'https://$i.s3.amazonaws.com' | grep -q 'ListBucket' && echo $i; done", desc: 'S3 enum script', category: 'AWS' },
            { name: 'Azure Blob', cmd: "ffuf -u 'https://FUZZ.blob.core.windows.net/{DOMAIN}' -w wordlist.txt", desc: 'Azure storage', category: 'Azure' },
            { name: 'GCP Bucket', cmd: 'gcpbucketbrute -k {DOMAIN} -w wordlist.txt', desc: 'GCP buckets', category: 'GCP' }
        ]
    },

    // --- NMAP SCRIPTS REFERENCE ---
    nmapScripts: {
        smb: [
            { name: 'smb-enum-shares', cmd: 'nmap --script smb-enum-shares -p 445 {IP}', desc: 'List SMB shares' },
            { name: 'smb-enum-users', cmd: 'nmap --script smb-enum-users -p 445 {IP}', desc: 'Enumerate users' },
            { name: 'smb-os-discovery', cmd: 'nmap --script smb-os-discovery -p 445 {IP}', desc: 'OS detection via SMB' },
            { name: 'smb-vuln-ms17-010', cmd: 'nmap --script smb-vuln-ms17-010 -p 445 {IP}', desc: 'EternalBlue check' },
            { name: 'smb-vuln-ms08-067', cmd: 'nmap --script smb-vuln-ms08-067 -p 445 {IP}', desc: 'Conficker check' }
        ],
        web: [
            { name: 'http-enum', cmd: 'nmap --script http-enum -p 80,443 {IP}', desc: 'HTTP enumeration' },
            { name: 'http-vuln-*', cmd: 'nmap --script "http-vuln-*" -p 80,443 {IP}', desc: 'HTTP vulns' },
            { name: 'http-headers', cmd: 'nmap --script http-headers -p 80,443 {IP}', desc: 'HTTP headers' },
            { name: 'http-methods', cmd: 'nmap --script http-methods -p 80,443 {IP}', desc: 'Allowed methods' },
            { name: 'http-robots.txt', cmd: 'nmap --script http-robots.txt -p 80,443 {IP}', desc: 'Robots.txt' }
        ],
        ftp: [
            { name: 'ftp-anon', cmd: 'nmap --script ftp-anon -p 21 {IP}', desc: 'Anonymous FTP' },
            { name: 'ftp-brute', cmd: 'nmap --script ftp-brute -p 21 {IP}', desc: 'FTP brute force' },
            { name: 'ftp-vuln-cve2010-4221', cmd: 'nmap --script ftp-vuln-cve2010-4221 -p 21 {IP}', desc: 'ProFTPD vuln' }
        ],
        ssh: [
            { name: 'ssh-brute', cmd: 'nmap --script ssh-brute -p 22 {IP}', desc: 'SSH brute force' },
            { name: 'ssh2-enum-algos', cmd: 'nmap --script ssh2-enum-algos -p 22 {IP}', desc: 'SSH algorithms' },
            { name: 'ssh-auth-methods', cmd: 'nmap --script ssh-auth-methods -p 22 {IP}', desc: 'Auth methods' }
        ],
        ldap: [
            { name: 'ldap-search', cmd: 'nmap --script ldap-search -p 389 {IP}', desc: 'LDAP search' },
            { name: 'ldap-rootdse', cmd: 'nmap --script ldap-rootdse -p 389 {IP}', desc: 'Root DSE' }
        ],
        dns: [
            { name: 'dns-zone-transfer', cmd: 'nmap --script dns-zone-transfer -p 53 {IP}', desc: 'Zone transfer' },
            { name: 'dns-brute', cmd: 'nmap --script dns-brute {DOMAIN}', desc: 'DNS brute force' }
        ]
    },

    // --- WORDLISTS REFERENCE ---
    wordlists: {
        directories: [
            { name: 'directory-list-2.3-medium', path: '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt', size: '220k entries' },
            { name: 'raft-medium-directories', path: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt', size: '30k entries' },
            { name: 'common.txt', path: '/usr/share/wordlists/dirb/common.txt', size: '4.6k entries' },
            { name: 'big.txt', path: '/usr/share/wordlists/dirb/big.txt', size: '20.5k entries' }
        ],
        subdomains: [
            { name: 'subdomains-top1million-5000', path: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', size: '5k entries' },
            { name: 'subdomains-top1million-110000', path: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', size: '110k entries' },
            { name: 'dns-Jhaddix.txt', path: '/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt', size: '2.2M entries' }
        ],
        passwords: [
            { name: 'rockyou.txt', path: '/usr/share/wordlists/rockyou.txt', size: '14M passwords' },
            { name: 'common-passwords', path: '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt', size: '10k entries' },
            { name: 'darkweb2017-top10000', path: '/usr/share/seclists/Passwords/darkweb2017-top10000.txt', size: '10k entries' }
        ],
        usernames: [
            { name: 'top-usernames-shortlist', path: '/usr/share/seclists/Usernames/top-usernames-shortlist.txt', size: '17 entries' },
            { name: 'xato-net-10-million-usernames', path: '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt', size: '8.3M entries' }
        ],
        lfi: [
            { name: 'LFI-Jhaddix.txt', path: '/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt', size: '929 entries' },
            { name: 'LFI-gracefulsecurity-linux', path: '/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt', size: '257 entries' }
        ]
    },

    // --- NUCLEI TEMPLATES REFERENCE ---
    nucleiTemplates: {
        cves: [
            { name: 'CVE-2021-44228', cmd: 'nuclei -t cves/2021/CVE-2021-44228.yaml -u {DOMAIN}', desc: 'Log4Shell RCE', severity: 'critical' },
            { name: 'CVE-2022-22965', cmd: 'nuclei -t cves/2022/CVE-2022-22965.yaml -u {DOMAIN}', desc: 'Spring4Shell', severity: 'critical' },
            { name: 'CVE-2021-26855', cmd: 'nuclei -t cves/2021/CVE-2021-26855.yaml -u {DOMAIN}', desc: 'ProxyLogon', severity: 'critical' },
            { name: 'CVE-2021-34473', cmd: 'nuclei -t cves/2021/CVE-2021-34473.yaml -u {DOMAIN}', desc: 'ProxyShell', severity: 'critical' },
            { name: 'CVE-2023-22515', cmd: 'nuclei -t cves/2023/CVE-2023-22515.yaml -u {DOMAIN}', desc: 'Confluence Auth Bypass', severity: 'critical' },
            { name: 'CVE-2023-46747', cmd: 'nuclei -t cves/2023/CVE-2023-46747.yaml -u {DOMAIN}', desc: 'F5 BIG-IP RCE', severity: 'critical' },
            { name: 'CVE-2023-27997', cmd: 'nuclei -t cves/2023/CVE-2023-27997.yaml -u {DOMAIN}', desc: 'FortiGate RCE', severity: 'critical' },
            { name: 'CVE-2024-21762', cmd: 'nuclei -t cves/2024/CVE-2024-21762.yaml -u {DOMAIN}', desc: 'FortiOS RCE', severity: 'critical' }
        ],
        exposedPanels: [
            { name: 'Admin Panels', cmd: 'nuclei -t exposed-panels/ -u {DOMAIN}', desc: 'Find exposed admin panels', severity: 'medium' },
            { name: 'Jenkins', cmd: 'nuclei -t exposed-panels/jenkins-dashboard.yaml -u {DOMAIN}', desc: 'Jenkins dashboard', severity: 'high' },
            { name: 'Grafana', cmd: 'nuclei -t exposed-panels/grafana-detect.yaml -u {DOMAIN}', desc: 'Grafana detect', severity: 'medium' },
            { name: 'Kibana', cmd: 'nuclei -t exposed-panels/kibana-detect.yaml -u {DOMAIN}', desc: 'Kibana panel', severity: 'medium' },
            { name: 'phpMyAdmin', cmd: 'nuclei -t exposed-panels/phpmyadmin-panel.yaml -u {DOMAIN}', desc: 'phpMyAdmin panel', severity: 'high' },
            { name: 'Webmin', cmd: 'nuclei -t exposed-panels/webmin-panel.yaml -u {DOMAIN}', desc: 'Webmin panel', severity: 'high' },
            { name: 'cPanel', cmd: 'nuclei -t exposed-panels/cpanel-detect.yaml -u {DOMAIN}', desc: 'cPanel detect', severity: 'medium' },
            { name: 'Tomcat Manager', cmd: 'nuclei -t exposed-panels/tomcat-manager.yaml -u {DOMAIN}', desc: 'Tomcat manager', severity: 'high' }
        ],
        misconfigs: [
            { name: 'All Misconfigs', cmd: 'nuclei -t misconfiguration/ -u {DOMAIN}', desc: 'All misconfiguration checks', severity: 'varies' },
            { name: 'CORS Misconfig', cmd: 'nuclei -t misconfiguration/cors-misconfig.yaml -u {DOMAIN}', desc: 'CORS issues', severity: 'medium' },
            { name: 'Directory Listing', cmd: 'nuclei -t misconfiguration/directory-listing.yaml -u {DOMAIN}', desc: 'Open directories', severity: 'low' },
            { name: 'HTTP Headers', cmd: 'nuclei -t misconfiguration/http-missing-security-headers.yaml -u {DOMAIN}', desc: 'Missing headers', severity: 'info' },
            { name: 'Git Exposed', cmd: 'nuclei -t exposures/configs/git-config.yaml -u {DOMAIN}', desc: '.git exposure', severity: 'high' },
            { name: 'Env File', cmd: 'nuclei -t exposures/configs/laravel-env.yaml -u {DOMAIN}', desc: '.env exposure', severity: 'high' },
            { name: 'Debug Mode', cmd: 'nuclei -t misconfiguration/laravel-debug-mode.yaml -u {DOMAIN}', desc: 'Debug enabled', severity: 'medium' },
            { name: 'Swagger UI', cmd: 'nuclei -t exposures/apis/swagger-ui.yaml -u {DOMAIN}', desc: 'Swagger docs', severity: 'low' }
        ],
        defaultCreds: [
            { name: 'Default Logins', cmd: 'nuclei -t default-logins/ -u {DOMAIN}', desc: 'Default credentials', severity: 'high' },
            { name: 'Tomcat Default', cmd: 'nuclei -t default-logins/tomcat-manager-default.yaml -u {DOMAIN}', desc: 'Tomcat defaults', severity: 'critical' },
            { name: 'Grafana Default', cmd: 'nuclei -t default-logins/grafana-default-login.yaml -u {DOMAIN}', desc: 'Grafana admin:admin', severity: 'high' },
            { name: 'Jenkins Default', cmd: 'nuclei -t default-logins/jenkins-default-login.yaml -u {DOMAIN}', desc: 'Jenkins defaults', severity: 'high' }
        ],
        technologies: [
            { name: 'Tech Detect', cmd: 'nuclei -t technologies/ -u {DOMAIN}', desc: 'Technology detection', severity: 'info' },
            { name: 'WordPress', cmd: 'nuclei -t technologies/wordpress-detect.yaml -u {DOMAIN}', desc: 'WordPress detect', severity: 'info' },
            { name: 'Joomla', cmd: 'nuclei -t technologies/joomla-detect.yaml -u {DOMAIN}', desc: 'Joomla detect', severity: 'info' },
            { name: 'Drupal', cmd: 'nuclei -t technologies/drupal-detect.yaml -u {DOMAIN}', desc: 'Drupal detect', severity: 'info' }
        ],
        fuzzing: [
            { name: 'XSS Fuzzing', cmd: 'nuclei -t fuzzing/xss.yaml -u {DOMAIN}', desc: 'XSS payloads', severity: 'high' },
            { name: 'SQLi Fuzzing', cmd: 'nuclei -t fuzzing/sqli.yaml -u {DOMAIN}', desc: 'SQLi payloads', severity: 'high' },
            { name: 'LFI Fuzzing', cmd: 'nuclei -t fuzzing/lfi.yaml -u {DOMAIN}', desc: 'LFI payloads', severity: 'high' },
            { name: 'SSTI Fuzzing', cmd: 'nuclei -t fuzzing/ssti.yaml -u {DOMAIN}', desc: 'SSTI payloads', severity: 'high' }
        ],
        workflows: [
            { name: 'Critical Severity', cmd: 'nuclei -l alive.txt -s critical -o critical.txt', desc: 'Critical only', severity: 'critical' },
            { name: 'High + Critical', cmd: 'nuclei -l alive.txt -s critical,high -o high_crit.txt', desc: 'High severity+', severity: 'high' },
            { name: 'New Templates', cmd: 'nuclei -l alive.txt -nt -o new.txt', desc: 'Recently added templates', severity: 'varies' },
            { name: 'Automatic Scan', cmd: 'nuclei -l alive.txt -as -o auto.txt', desc: 'Auto template selection', severity: 'varies' }
        ]
    },

    // --- ONE-LINERS ---
    oneLiners: [
        { name: 'Full Subdomain Enum', cmd: `subfinder -d {DOMAIN} -silent | httpx -silent | nuclei -t ~/nuclei-templates/`, category: 'Recon' },
        { name: 'Quick Recon', cmd: `echo {DOMAIN} | subfinder -silent | httpx -silent -title -status-code -tech-detect`, category: 'Recon' },
        { name: 'Find Subdomains + Alive', cmd: `subfinder -d {DOMAIN} -all -silent | sort -u | httpx -silent -o alive.txt`, category: 'Recon' },
        { name: 'Param Mining', cmd: `echo {DOMAIN} | waybackurls | grep '?' | uro | qsreplace 'FUZZ'`, category: 'Params' },
        { name: 'XSS Hunt', cmd: `echo {DOMAIN} | gau | grep '=' | dalfox pipe -o xss.txt`, category: 'XSS' },
        { name: 'Open Redirect', cmd: `waybackurls {DOMAIN} | grep -E '(url=|redirect=|next=|rurl=)'`, category: 'Redirect' },
        { name: 'Sensitive Files', cmd: `ffuf -u https://{DOMAIN}/FUZZ -w /path/to/sensitive-files.txt -mc 200`, category: 'Files' },
        { name: 'SSRF Endpoints', cmd: `gau {DOMAIN} | grep -E '(url=|file=|path=|src=|load=)'`, category: 'SSRF' },
        { name: 'JS Secrets', cmd: `echo {DOMAIN} | gau | grep '\\.js$' | httpx -silent | xargs -I% bash -c 'curl -s % | grep -Eo "(api|key|secret|token)[^\\s]*"'`, category: 'Secrets' },
        { name: 'Fast Port Scan', cmd: `rustscan -a {IP} -- -sC -sV | tee rustcan_output.txt`, category: 'Ports' },
        { name: 'SQLi Test', cmd: `cat params.txt | gf sqli | sqlmap -m - --batch`, category: 'SQLi' },
        { name: 'LFI Test', cmd: `cat params.txt | gf lfi | qsreplace '/etc/passwd' | httpx -mc 200 -mr 'root:'`, category: 'LFI' }
    ],

    // --- METHODOLOGY ---
    methodology: [
        { phase: 'Scope Definition', tasks: ['Define target scope', 'Identify in-scope domains/IPs', 'Read program rules', 'Note out-of-scope items', 'Set up note-taking'] },
        { phase: 'Subdomain Enumeration', tasks: ['Passive: Subfinder, Amass, crt.sh', 'Active: DNS brute force', 'Permutation: dnsgen, altdns', 'Combine & deduplicate results', 'Resolve to IPs'] },
        { phase: 'Port Scanning', tasks: ['Quick scan: nmap -sC -sV', 'Full TCP: nmap -p-', 'UDP scan: nmap -sU', 'Service fingerprinting', 'OS detection'] },
        { phase: 'Service Enumeration', tasks: ['Web: HTTP headers, tech detect', 'SMB: shares, users', 'FTP: anonymous access', 'SSH: version, auth methods', 'Database ports'] },
        { phase: 'Content Discovery', tasks: ['Directory fuzzing: ffuf, gobuster', 'Wayback URLs: gau, waybackurls', 'JS files analysis', 'Parameter discovery', 'API endpoint hunting'] },
        { phase: 'Vulnerability Scanning', tasks: ['Nuclei templates', 'XSS: dalfox', 'SQLi: sqlmap', 'SSRF endpoints', 'CORS misconfig', 'Open redirects'] },
        { phase: 'Manual Testing', tasks: ['Authentication bypass', 'IDOR testing', 'Business logic flaws', 'Race conditions', 'File upload bypass'] }
    ],

    // --- RENDER ---
    // --- RENDER ---
    render() {
        return `
            <div class="recon-app fade-in">
                <div class="recon-header">
                    <div class="h-left">
                        <h1><i class="fas fa-satellite-dish"></i> Recon Lab <span class="v2-badge">V2.0</span></h1>
                        <p class="subtitle">Automated reconnaissance & Intelligent Analysis</p>
                    </div>
                    <div class="h-right">
                         <div class="target-box">
                            <i class="fas fa-crosshairs"></i>
                            <input type="text" id="target-domain" value="${this.targetDomain}" onchange="ReconLab.updateTarget()" placeholder="Target Domain">
                        </div>
                    </div>
                </div>

                <div class="recon-layout">
                    <!-- LEFT: TOOLS NAV -->
                    <div class="recon-sidebar">
                        ${Object.keys(this.tools).map(cat => `
                            <div class="nav-item ${this.currentTab === cat ? 'active' : ''}" onclick="ReconLab.switchTab('${cat}')">
                                <i class="fas fa-${this.getTabIcon(cat)}"></i>
                                ${cat.charAt(0).toUpperCase() + cat.slice(1)}
                            </div>
                        `).join('')}
                        <div class="nav-sep"></div>
                        <div class="nav-item ${this.currentTab === 'graph' ? 'active' : ''}" onclick="ReconLab.switchTab('graph')">
                            <i class="fas fa-project-diagram"></i> Asset Graph
                        </div>
                        <div class="nav-item ${this.currentTab === 'nmap' ? 'active' : ''}" onclick="ReconLab.switchTab('nmap')">
                            <i class="fas fa-radar"></i> Nmap Scripts
                        </div>
                        <div class="nav-item ${this.currentTab === 'nuclei' ? 'active' : ''}" onclick="ReconLab.switchTab('nuclei')">
                            <i class="fas fa-atom"></i> Nuclei Templates
                        </div>
                        <div class="nav-item ${this.currentTab === 'wordlists' ? 'active' : ''}" onclick="ReconLab.switchTab('wordlists')">
                            <i class="fas fa-book"></i> Wordlists
                        </div>
                        <div class="nav-item ${this.currentTab === 'oneliners' ? 'active' : ''}" onclick="ReconLab.switchTab('oneliners')">
                            <i class="fas fa-magic"></i> One-Liners
                        </div>
                        <div class="nav-item ${this.currentTab === 'methodology' ? 'active' : ''}" onclick="ReconLab.switchTab('methodology')">
                            <i class="fas fa-tasks"></i> Methodology
                        </div>
                    </div>

                    <!-- CENTER: CONTENT -->
                    <div class="recon-main">
                        ${this.currentTab === 'graph' ? this.renderGraphTab() : this.renderTabContent()}
                    </div>

                    <!-- RIGHT: TERMINAL & AI -->
                    <div class="recon-panel">
                        <div class="term-window">
                            <div class="term-header"><i class="fas fa-terminal"></i> Live Terminal</div>
                            <pre id="recon-term-out" class="term-body">${this.terminal.output.length ? this.terminal.output.join('\n') : '<span class="term-muted">Ready to execute...</span>'}</pre>
                            <div class="term-controls">
                                <button onclick="ReconLab.terminal.output=[];ReconLab.renderTerminal()">Clear</button>
                                <button class="btn-run" onclick="ReconLab.runTerminal('nmap -sC -sV ${this.targetDomain}')">Run Full Scan</button>
                            </div>
                        </div>

                        <div class="ai-box">
                            <button class="btn-ai-analyze" onclick="ReconLab.analyzeResults()">
                                <i class="fas fa-brain"></i> Analyze Findings
                            </button>
                            <div id="ai-analysis-panel"></div>
                        </div>
                    </div>
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    getTabIcon(cat) {
        const icons = { subdomain: 'sitemap', portscan: 'search-location', alive: 'heartbeat', urls: 'link', vulnscan: 'bug', fuzzing: 'random', js: 'code', cloud: 'cloud' };
        return icons[cat] || 'tools';
    },

    renderTabContent() {
        if (this.currentTab === 'oneliners') return this.renderOneLiners();
        if (this.currentTab === 'methodology') return this.renderMethodology();
        if (this.currentTab === 'nmap') return this.renderNmapScripts();
        if (this.currentTab === 'wordlists') return this.renderWordlists();
        if (this.currentTab === 'nuclei') return this.renderNucleiTemplates();
        return this.renderTools();
    },

    renderTools() {
        const tools = this.tools[this.currentTab] || [];
        const categories = [...new Set(tools.map(t => t.category))];

        return `
            <div class="tools-section">
                ${categories.map(cat => `
                    <div class="category-section">
                        <h3><i class="fas fa-folder-open"></i> ${cat}</h3>
                        <div class="tools-grid">
                            ${tools.filter(t => t.category === cat).map(t => `
                                <div class="tool-card">
                                    <div class="tool-header">
                                        <span class="tool-name">${t.name}</span>
                                        <span class="tool-desc">${t.desc}</span>
                                    </div>
                                    <div class="tool-cmd">
                                        <code>${this.formatCmd(t.cmd)}</code>
                                        <button onclick="ReconLab.copyCmd('${t.cmd.replace(/'/g, "\\'")}')" title="Copy">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderNmapScripts() {
        return `
            <div class="nmap-section">
                <h3><i class="fas fa-radar"></i> Nmap NSE Scripts Reference</h3>
                <p class="section-desc">Common Nmap scripts for service enumeration and vulnerability detection</p>
                
                ${Object.entries(this.nmapScripts).map(([cat, scripts]) => `
                    <div class="nmap-category">
                        <h4><i class="fas fa-${cat === 'smb' ? 'folder' : cat === 'web' ? 'globe' : cat === 'ftp' ? 'file' : cat === 'ssh' ? 'key' : 'database'}"></i> ${cat.toUpperCase()}</h4>
                        <div class="tools-grid">
                            ${scripts.map(s => `
                                <div class="tool-card nmap-card">
                                    <div class="tool-header">
                                        <span class="tool-name">${s.name}</span>
                                        <span class="tool-desc">${s.desc}</span>
                                    </div>
                                    <div class="tool-cmd">
                                        <code>${this.formatCmd(s.cmd)}</code>
                                        <button onclick="ReconLab.copyCmd('${s.cmd.replace(/'/g, "\\'")}')" title="Copy">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderWordlists() {
        return `
            <div class="wordlists-section">
                <h3><i class="fas fa-book"></i> Wordlists Reference (SecLists)</h3>
                <p class="section-desc">Common wordlists for directory bruteforcing, subdomain enumeration, and password cracking</p>
                
                ${Object.entries(this.wordlists).map(([cat, lists]) => `
                    <div class="wordlist-category">
                        <h4><i class="fas fa-folder"></i> ${cat.charAt(0).toUpperCase() + cat.slice(1)}</h4>
                        <div class="wordlist-grid">
                            ${lists.map(w => `
                                <div class="wordlist-card">
                                    <div class="wordlist-name">${w.name}</div>
                                    <div class="wordlist-path">
                                        <code>${w.path}</code>
                                        <button onclick="navigator.clipboard.writeText('${w.path}')" title="Copy path">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                    <div class="wordlist-size"><i class="fas fa-database"></i> ${w.size}</div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderNucleiTemplates() {
        const severityColors = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a', info: '#2563eb', varies: '#7c3aed' };
        const categoryIcons = { cves: 'shield-virus', exposedPanels: 'door-open', misconfigs: 'cog', defaultCreds: 'key', technologies: 'microchip', fuzzing: 'bolt', workflows: 'project-diagram' };

        return `
            <div class="nuclei-section">
                <h3><i class="fas fa-atom"></i> Nuclei Templates Reference</h3>
                <p class="section-desc">Projectdiscovery Nuclei templates for automated vulnerability scanning - essential for OSCP/Bug Bounty</p>
                
                <div class="nuclei-install">
                    <h4><i class="fas fa-download"></i> Quick Install</h4>
                    <div class="install-cmds">
                        <div class="install-cmd">
                            <code>go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</code>
                            <button onclick="navigator.clipboard.writeText('go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')"><i class="fas fa-copy"></i></button>
                        </div>
                        <div class="install-cmd">
                            <code>nuclei -update-templates</code>
                            <button onclick="navigator.clipboard.writeText('nuclei -update-templates')"><i class="fas fa-copy"></i></button>
                        </div>
                    </div>
                </div>
                
                ${Object.entries(this.nucleiTemplates).map(([cat, templates]) => `
                    <div class="nuclei-category">
                        <h4><i class="fas fa-${categoryIcons[cat] || 'folder'}"></i> ${cat.replace(/([A-Z])/g, ' $1').trim()}</h4>
                        <div class="tools-grid">
                            ${templates.map(t => `
                                <div class="tool-card nuclei-card">
                                    <div class="tool-header">
                                        <span class="tool-name">${t.name}</span>
                                        <span class="severity-badge" style="background: ${severityColors[t.severity] || severityColors.info}20; color: ${severityColors[t.severity] || severityColors.info}; border: 1px solid ${severityColors[t.severity] || severityColors.info}">${t.severity.toUpperCase()}</span>
                                    </div>
                                    <div class="tool-desc">${t.desc}</div>
                                    <div class="tool-cmd">
                                        <code>${this.formatCmd(t.cmd)}</code>
                                        <button onclick="ReconLab.copyCmd('${t.cmd.replace(/'/g, "\\\\'")}')" title="Copy">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderOneLiners() {
        const categories = [...new Set(this.oneLiners.map(o => o.category))];
        return `
            <div class="oneliners-section">
                <h3><i class="fas fa-magic"></i> Powerful One-Liners</h3>
                ${categories.map(cat => `
                    <h4 class="oneliner-cat"><i class="fas fa-terminal"></i> ${cat}</h4>
                    <div class="oneliners-grid">
                        ${this.oneLiners.filter(o => o.category === cat).map(o => `
                            <div class="oneliner-card">
                                <div class="oneliner-name">${o.name}</div>
                                <div class="oneliner-cmd">
                                    <code>${this.formatCmd(o.cmd)}</code>
                                    <button onclick="ReconLab.copyCmd(\`${o.cmd.replace(/`/g, '\\`')}\`)" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderMethodology() {
        return `
            <div class="methodology-section">
                <h3><i class="fas fa-sitemap"></i> Pentest Recon Methodology</h3>
                <p class="section-desc">Step-by-step reconnaissance process for Bug Bounty & Penetration Testing</p>
                <div class="methodology-timeline">
                    ${this.methodology.map((m, i) => `
                        <div class="method-phase">
                            <div class="phase-number">${i + 1}</div>
                            <div class="phase-content">
                                <h4>${m.phase}</h4>
                                <ul>
                                    ${m.tasks.map(t => `<li><i class="fas fa-check-circle"></i> ${t}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.reRender();
    },

    updateTarget() {
        this.targetDomain = document.getElementById('target-domain').value.trim() || 'example.com';
        this.reRender();
    },

    updateIP() {
        this.targetIP = document.getElementById('target-ip').value.trim() || '10.10.10.10';
        this.reRender();
    },

    formatCmd(cmd) {
        return this.escapeHtml(cmd.replace(/{DOMAIN}/g, this.targetDomain || 'example.com').replace(/{IP}/g, this.targetIP || '10.10.10.10'));
    },

    copyCmd(cmd) {
        const formatted = cmd.replace(/{DOMAIN}/g, this.targetDomain || 'example.com').replace(/{IP}/g, this.targetIP || '10.10.10.10');
        navigator.clipboard.writeText(formatted);
        this.showNotification('Copied!', 'success');
    },

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },

    showNotification(msg, type) {
        const n = document.createElement('div');
        n.className = `recon-notif ${type}`;
        n.innerHTML = `<i class="fas fa-check"></i> ${msg}`;
        document.body.appendChild(n);
        setTimeout(() => n.remove(), 2000);
    },

    reRender() {
        const app = document.querySelector('.recon-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .recon-app { height: calc(100vh - 60px); display: flex; flex-direction: column; background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; overflow: hidden; }
            .recon-header { height: 60px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; padding: 0 20px; background: #161b22; }
            .h-left h1 { font-size: 1.2rem; margin: 0; color: #fff; display: flex; align-items: center; gap: 10px; }
            .v2-badge { background: #238636; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; }
            .subtitle { font-size: 0.8rem; color: #8b949e; margin: 0; }
            
            .target-box { background: #0d1117; border: 1px solid #30363d; padding: 5px 10px; border-radius: 6px; display: flex; align-items: center; gap: 8px; }
            .target-box input { background: transparent; border: none; color: #fff; outline: none; font-family: monospace; width: 200px; }
            
            .recon-layout { flex: 1; display: flex; overflow: hidden; }
            
            .recon-sidebar { width: 220px; background: #0d1117; border-right: 1px solid #30363d; display: flex; flex-direction: column; padding: 10px 0; overflow-y: auto; }
            .nav-item { padding: 10px 20px; cursor: pointer; color: #8b949e; display: flex; align-items: center; gap: 10px; transition: 0.2s; }
            .nav-item:hover, .nav-item.active { background: #161b22; color: #58a6ff; border-left: 3px solid #58a6ff; }
            .nav-sep { height: 1px; background: #21262d; margin: 10px 20px; }
            
            .recon-main { flex: 1; padding: 20px; overflow-y: auto; position: relative; }
            
            /* Enhanced Tool Cards for V2 */
            .tool-card, .wordlist-card, .nuclei-card, .oneliner-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 10px; }
            .tool-name { color: #58a6ff; font-weight: bold; }
            .tool-desc { color: #8b949e; font-size: 0.9rem; margin: 5px 0; }
            .tool-cmd, .install-cmd, .wordlist-path, .oneliner-cmd { background: #0d1117; padding: 8px; border-radius: 4px; border: 1px solid #30363d; display: flex; align-items: center; gap: 10px; margin-top: 8px; }
            .tool-cmd code, .install-cmd code, .wordlist-path code, .oneliner-cmd code { color: #a5d6ff; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; flex: 1; word-break: break-all; }
            .tool-cmd button, .install-cmd button, .wordlist-path button, .oneliner-cmd button { background: none; border: none; color: #8b949e; cursor: pointer; }
            .tool-cmd button:hover { color: #fff; }

            .recon-panel { width: 350px; background: #161b22; border-left: 1px solid #30363d; display: flex; flex-direction: column; padding: 15px; gap: 20px; }
            .term-window { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; flex: 1; display: flex; flex-direction: column; overflow: hidden; }
            .term-header { background: #21262d; padding: 8px 12px; font-size: 0.8rem; color: #8b949e; border-bottom: 1px solid #30363d; }
            .term-body { flex: 1; padding: 10px; margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; overflow-y: auto; color: #c9d1d9; white-space: pre-wrap; line-height: 1.4; }
            .term-prompt { color: #f78166; }
            .term-success { color: #3fb950; }
            .term-muted { color: #484f58; font-style: italic; }
            .term-controls { padding: 10px; border-top: 1px solid #30363d; display: flex; justify-content: flex-end; gap: 10px; }
            .term-controls button { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }
            .term-controls .btn-run { background: #1f6feb; border-color: #1f6feb; color: white; }
            
            .ai-box { border-top: 1px solid #30363d; padding-top: 20px; }
            .btn-ai-analyze { width: 100%; padding: 10px; background: linear-gradient(135deg, #a371f7, #6366f1); border: none; border-radius: 6px; color: white; font-weight: bold; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 15px; transition: 0.2s; }
            .btn-ai-analyze:hover { opacity: 0.9; }
            .ai-result { background: rgba(56, 139, 253, 0.1); border: 1px solid rgba(56, 139, 253, 0.4); border-radius: 6px; padding: 15px; font-size: 0.9rem; }
            .ai-result h4 { color: #79c0ff; margin: 0 0 10px; font-size: 1rem; }
            .ai-list { padding-left: 20px; margin: 10px 0; }
            .ai-list li { margin-bottom: 8px; }
            .tag-crit { background: rgba(248, 81, 73, 0.2); color: #ff7b72; padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }
            .tag-med { background: rgba(210, 153, 34, 0.2); color: #d29922; padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }
            .tag-low { background: rgba(56, 139, 253, 0.2); color: #79c0ff; padding: 1px 4px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }
            .ai-action code { display: block; background: #0d1117; padding: 8px; margin-top: 5px; border-radius: 4px; color: #a5d6ff; border: 1px solid #30363d; word-break: break-all; }
            
            .asset-graph-viz { height: 400px; background: #0d1117; border: 1px dashed #30363d; border-radius: 6px; position: relative; display: flex; align-items: center; justify-content: center; }
            .graph-placeholder { color: #484f58; }
            .node-root, .node-leaf { position: absolute; background: #1f6feb; color: white; padding: 8px 15px; border-radius: 20px; font-size: 0.9rem; font-weight: bold; box-shadow: 0 0 10px rgba(31, 111, 235, 0.4); z-index: 2; top: 20%; left: 50%; transform: translateX(-50%); }
            .node-leaf { top: 60%; background: #238636; font-size: 0.8rem; padding: 6px 12px; }
            .node-vuln { background: #d29922; }
            .node-branch { position: absolute; width: 2px; height: 40%; background: #30363d; top: 25%; left: 50%; z-index: 1; }
            .node-branch::before, .node-branch::after { content: ''; position: absolute; bottom: 0; width: 100px; height: 2px; background: #30363d; left: -100px; }
            .node-branch::after { left: auto; right: -100px; }
            
            @media (max-width: 900px) { .recon-layout { flex-direction: column; overflow-y: auto; } .recon-sidebar, .recon-panel { width: 100%; height: auto; } }
        </style>`;
    },
};

function pageReconLab() {
    return ReconLab.render();
}
