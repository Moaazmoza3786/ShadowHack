/* ============================================================
   THREAT HUNTING - Advanced Adversary Detection v2.0
   ShadowHack Platform - Interactive Threat Hunting Training
   ============================================================ */

window.ThreatHunting = {
    // --- STATE ---
    currentTab: 'campaigns',
    selectedCampaign: null,
    selectedHypothesis: null,
    queryLanguage: 'splunk',

    // --- HUNTING CAMPAIGNS ---
    campaigns: [
        {
            id: 'hunt-001',
            title: 'APT29 Beaconing Activity',
            status: 'Active',
            level: 'Advanced',
            tactic: 'Command and Control',
            mitre: 'T1071.001',
            description: 'Investigate potential C2 traffic over HTTPS appearing to mimic legitimate AWS interaction.',
            progress: 30,
            iocs: ['suspicious-aws.azureedge.net', '185.147.32.x', 'svchot.exe'],
            dataNeeded: ['DNS Logs', 'Proxy Logs', 'EDR Telemetry']
        },
        {
            id: 'hunt-002',
            title: 'Suspicious PowerShell Execution',
            status: 'New',
            level: 'Intermediate',
            tactic: 'Execution',
            mitre: 'T1059.001',
            description: 'Detect obfuscated PowerShell scripts launched by office applications.',
            progress: 0,
            iocs: ['FromBase64String', 'Invoke-Expression', '-enc'],
            dataNeeded: ['Windows Event Logs', 'Script Block Logging', 'EDR']
        },
        {
            id: 'hunt-003',
            title: 'Lateral Movement via SMB',
            status: 'Completed',
            level: 'Hard',
            tactic: 'Lateral Movement',
            mitre: 'T1021.002',
            description: 'Identify PsExec-like behavior moving between workstations in the Finance subnet.',
            progress: 100,
            iocs: ['ADMIN$', 'PSEXESVC.exe', 'named pipe \\\\pipe\\svcctl'],
            dataNeeded: ['Windows Security Logs', 'SMB Logs', 'Zeek']
        },
        {
            id: 'hunt-004',
            title: 'Living off the Land (LOLBins)',
            status: 'Active',
            level: 'Intermediate',
            tactic: 'Defense Evasion',
            mitre: 'T1218',
            description: 'Detect abuse of legitimate Windows binaries for malicious purposes.',
            progress: 45,
            iocs: ['mshta.exe', 'regsvr32.exe', 'certutil -urlcache'],
            dataNeeded: ['Sysmon', 'EDR Process Logs', 'Command Line Auditing']
        },
        {
            id: 'hunt-005',
            title: 'Credential Dumping Detection',
            status: 'New',
            level: 'Advanced',
            tactic: 'Credential Access',
            mitre: 'T1003.001',
            description: 'Hunt for LSASS access patterns consistent with credential harvesting tools.',
            progress: 0,
            iocs: ['lsass.exe access', 'mimikatz', 'procdump.exe'],
            dataNeeded: ['Sysmon EventID 10', 'EDR Memory Access', 'Windows Security 4656']
        },
        {
            id: 'hunt-006',
            title: 'Kerberoasting Attack',
            status: 'Active',
            level: 'Hard',
            tactic: 'Credential Access',
            mitre: 'T1558.003',
            description: 'Detect TGS requests for service accounts with weak encryption.',
            progress: 60,
            iocs: ['Event 4769', 'RC4 encryption', 'Service Principal Names'],
            dataNeeded: ['Windows Security Logs', 'DC Logs', 'BloodHound']
        },
        {
            id: 'hunt-007',
            title: 'Data Exfiltration over DNS',
            status: 'New',
            level: 'Advanced',
            tactic: 'Exfiltration',
            mitre: 'T1048.003',
            description: 'Identify DNS tunneling and data exfiltration via DNS queries.',
            progress: 0,
            iocs: ['Long DNS queries', 'High entropy subdomains', 'TXT record abuse'],
            dataNeeded: ['DNS Query Logs', 'Zeek DNS', 'Passive DNS']
        },
        {
            id: 'hunt-008',
            title: 'Persistence via Scheduled Tasks',
            status: 'Active',
            level: 'Intermediate',
            tactic: 'Persistence',
            mitre: 'T1053.005',
            description: 'Hunt for malicious scheduled tasks created for persistence.',
            progress: 25,
            iocs: ['schtasks.exe', 'at.exe', 'TaskCache registry'],
            dataNeeded: ['Windows Task Scheduler Logs', 'Sysmon', 'Registry']
        }
    ],

    // --- HUNTING HYPOTHESES ---
    hypotheses: [
        {
            id: 'hyp-001',
            title: 'Adversary Using Encoded PowerShell',
            category: 'Execution',
            mitre: 'T1059.001',
            description: 'Attackers use Base64-encoded PowerShell commands to evade detection.',
            splunkQuery: `index=windows sourcetype=WinEventLog:Security EventCode=4688
| search CommandLine="*powershell*" (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*FromBase64String*")
| table _time ComputerName User CommandLine
| sort -_time`,
            kqlQuery: `DeviceProcessEvents
| where ProcessName == "powershell.exe"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc`,
            elasticQuery: `process.name: "powershell.exe" AND process.command_line: (*-enc* OR *FromBase64String* OR *-encodedcommand*)`,
            indicators: ['Base64 strings > 100 chars', 'Hidden window', 'No profile flag']
        },
        {
            id: 'hyp-002',
            title: 'LSASS Memory Access for Credential Theft',
            category: 'Credential Access',
            mitre: 'T1003.001',
            description: 'Adversaries access LSASS process memory to extract credentials.',
            splunkQuery: `index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT match(SourceImage, "^C:\\\\Windows\\\\System32\\\\.*")
| table _time Computer SourceImage TargetImage GrantedAccess
| sort -_time`,
            kqlQuery: `DeviceEvents
| where ActionType == "ProcessAccess" 
| where TargetProcessName == "lsass.exe"
| where InitiatingProcessFolderPath !startswith @"C:\\Windows\\System32"
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessName
| sort by Timestamp desc`,
            elasticQuery: `event.code: 10 AND process.target.name: "lsass.exe" AND NOT process.executable: "C:\\\\Windows\\\\System32\\\\*"`,
            indicators: ['Non-system process accessing LSASS', 'PROCESS_VM_READ access', 'Unsigned binaries']
        },
        {
            id: 'hyp-003',
            title: 'Unusual Parent-Child Process Relationships',
            category: 'Execution',
            mitre: 'T1059',
            description: 'Detecting anomalous process spawning patterns indicates malicious activity.',
            splunkQuery: `index=sysmon EventCode=1 
| where (ParentImage="*WINWORD.EXE*" OR ParentImage="*EXCEL.EXE*" OR ParentImage="*POWERPNT.EXE*")
| where (Image="*cmd.exe*" OR Image="*powershell.exe*" OR Image="*wscript.exe*" OR Image="*mshta.exe*")
| table _time Computer ParentImage Image CommandLine User`,
            kqlQuery: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
            elasticQuery: `process.parent.name: (WINWORD.EXE OR EXCEL.EXE) AND process.name: (cmd.exe OR powershell.exe OR wscript.exe)`,
            indicators: ['Office spawning shell', 'Macro execution', 'Script interpreters']
        },
        {
            id: 'hyp-004',
            title: 'DNS Tunneling Detection',
            category: 'Exfiltration',
            mitre: 'T1048.003',
            description: 'Data exfiltration through DNS queries using encoded subdomains.',
            splunkQuery: `index=dns
| eval subdomain_length=len(mvindex(split(query,"."),0))
| where subdomain_length > 50
| stats count by query src_ip
| where count > 10
| sort -count`,
            kqlQuery: `DeviceNetworkEvents
| where RemotePort == 53
| extend subdomain = tostring(split(RemoteUrl, ".")[0])
| where strlen(subdomain) > 50
| summarize count() by RemoteUrl, DeviceName
| where count_ > 10`,
            elasticQuery: `destination.port: 53 AND dns.question.name.length: >50`,
            indicators: ['Long subdomain', 'High query frequency', 'TXT records', 'Entropy > 3.5']
        },
        {
            id: 'hyp-005',
            title: 'Kerberoasting Service Ticket Requests',
            category: 'Credential Access',
            mitre: 'T1558.003',
            description: 'Mass TGS requests indicate Kerberoasting attack.',
            splunkQuery: `index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| where Service_Name!="krbtgt" AND Service_Name!="$*"
| stats count by Account_Name Service_Name Client_Address
| where count > 5
| sort -count`,
            kqlQuery: `SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize RequestCount = count() by AccountName, ServiceName, IpAddress
| where RequestCount > 5`,
            elasticQuery: `event.code: 4769 AND winlog.event_data.TicketEncryptionType: 0x17 AND NOT winlog.event_data.ServiceName: *$`,
            indicators: ['RC4 encryption', 'Multiple service tickets', 'Non-machine accounts']
        },
        {
            id: 'hyp-006',
            title: 'Scheduled Task Persistence',
            category: 'Persistence',
            mitre: 'T1053.005',
            description: 'Attackers create scheduled tasks for persistence.',
            splunkQuery: `index=sysmon (EventCode=1 Image="*schtasks.exe*" CommandLine="*/create*")
| table _time Computer User CommandLine
| sort -_time`,
            kqlQuery: `DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc`,
            elasticQuery: `process.name: "schtasks.exe" AND process.command_line: *create*`,
            indicators: ['schtasks /create', 'at.exe usage', 'COM object tasks']
        },
        {
            id: 'hyp-007',
            title: 'LOLBin Abuse - Certutil',
            category: 'Defense Evasion',
            mitre: 'T1218',
            description: 'Certutil used to download files or decode payloads.',
            splunkQuery: `index=sysmon EventCode=1 Image="*certutil.exe*"
| where (CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-encode*")
| table _time Computer User CommandLine`,
            kqlQuery: `DeviceProcessEvents
| where FileName == "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-decode", "-encode", "-ping")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
            elasticQuery: `process.name: "certutil.exe" AND process.command_line: (*-urlcache* OR *-decode* OR *-ping*)`,
            indicators: ['URL download', 'Base64 decode', 'Remote file fetch']
        },
        {
            id: 'hyp-008',
            title: 'DCSync Attack Detection',
            category: 'Credential Access',
            mitre: 'T1003.006',
            description: 'Replication of AD directory data from non-DC systems.',
            splunkQuery: `index=wineventlog EventCode=4662 Access_Mask=0x100
| where ObjectType="*domain-dns*" OR ObjectType="*19195a5b-6da0-11d0-afd3-00c04fd930c9*"
| where NOT SubjectUserName="*$"
| stats count by SubjectUserName SubjectDomainName ObjectName`,
            kqlQuery: `SecurityEvent
| where EventID == 4662 
| where AccessMask == "0x100"
| where ObjectType contains "Replicating" or Properties contains "1131f6"
| project TimeGenerated, Account, Activity`,
            elasticQuery: `event.code: 4662 AND winlog.event_data.AccessMask: 0x100 AND winlog.event_data.Properties: *1131f6*`,
            indicators: ['DS-Replication-Get-Changes', 'Non-DC source', 'Directory replication']
        }
    ],

    // --- DATA SOURCES ---
    dataSources: [
        { name: 'Splunk SIEM', icon: 'chart-pie', status: 'connected', logsPerDay: '2.5M' },
        { name: 'CrowdStrike EDR', icon: 'shield-halved', status: 'connected', logsPerDay: '850K' },
        { name: 'Microsoft Defender', icon: 'shield-virus', status: 'connected', logsPerDay: '1.2M' },
        { name: 'Zeek Network', icon: 'network-wired', status: 'connected', logsPerDay: '5.1M' },
        { name: 'Windows Event Logs', icon: 'windows', status: 'connected', logsPerDay: '3.8M' },
        { name: 'Sysmon', icon: 'eye', status: 'connected', logsPerDay: '1.5M' },
        { name: 'DNS Logs', icon: 'globe', status: 'connected', logsPerDay: '10M' },
        { name: 'Firewall Logs', icon: 'fire', status: 'connected', logsPerDay: '500K' }
    ],

    // --- RENDER ---
    render() {
        const container = document.getElementById('hunt-app');
        if (!container) return;

        container.innerHTML = `
            ${this.getStyles()}
            <div class="hunt-container fade-in">
                <!-- Header -->
                <div class="hunt-header">
                    <div>
                        <h1 class="text-white mb-2"><i class="fa-solid fa-crosshairs text-danger me-3"></i>Threat Hunting Operations</h1>
                        <p class="text-secondary mb-0">Proactively search for adversaries that evaded automated defenses</p>
                    </div>
                    <div class="mt-3 mt-md-0">
                        <button class="btn btn-danger"><i class="fa-solid fa-plus me-2"></i>New Hunt</button>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="hunt-tabs mb-4">
                    ${['campaigns', 'hypotheses', 'queries', 'datasources'].map(tab => `
                        <button class="hunt-tab ${this.currentTab === tab ? 'active' : ''}" onclick="window.ThreatHunting.switchTab('${tab}')">
                            <i class="fa-solid fa-${tab === 'campaigns' ? 'radar' : tab === 'hypotheses' ? 'lightbulb' : tab === 'queries' ? 'code' : 'database'} me-2"></i>
                            ${tab.charAt(0).toUpperCase() + tab.slice(1)}
                        </button>
                    `).join('')}
                </div>

                <!-- Dashboard Stats -->
                <div class="row g-4 mb-4">
                    <div class="col-md-3">
                        <div class="hunt-stat-card border-danger">
                            <h3 class="display-6 fw-bold text-white">${this.campaigns.filter(c => c.status === 'Active').length}</h3>
                            <span class="text-danger small">Active Hunts</span>
                            <i class="fa-solid fa-radar stat-icon text-danger"></i>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="hunt-stat-card border-warning">
                            <h3 class="display-6 fw-bold text-white">${this.campaigns.filter(c => c.status === 'New').length}</h3>
                            <span class="text-warning small">Pending</span>
                            <i class="fa-solid fa-clock stat-icon text-warning"></i>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="hunt-stat-card border-success">
                            <h3 class="display-6 fw-bold text-white">${this.campaigns.filter(c => c.status === 'Completed').length}</h3>
                            <span class="text-success small">Completed</span>
                            <i class="fa-solid fa-check-circle stat-icon text-success"></i>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="hunt-stat-card border-info">
                            <h3 class="display-6 fw-bold text-white">${this.hypotheses.length}</h3>
                            <span class="text-info small">Hypotheses</span>
                            <i class="fa-solid fa-lightbulb stat-icon text-info"></i>
                        </div>
                    </div>
                </div>

                <!-- Tab Content -->
                ${this.renderTabContent()}
            </div>
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'campaigns': return this.renderCampaigns();
            case 'hypotheses': return this.renderHypotheses();
            case 'queries': return this.renderQueries();
            case 'datasources': return this.renderDataSources();
            default: return '';
        }
    },

    renderCampaigns() {
        return `
            <div class="card bg-dark border-secondary">
                <div class="card-header border-secondary bg-transparent py-3">
                    <h5 class="text-white mb-0"><i class="fa-solid fa-list me-2"></i>Active Hunting Campaigns</h5>
                </div>
                <div class="card-body p-0">
                    <div class="list-group list-group-flush">
                        ${this.campaigns.map(c => `
                            <div class="list-group-item bg-transparent border-secondary p-4 hunt-item">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div class="flex-grow-1">
                                        <div class="d-flex align-items-center mb-2 flex-wrap gap-2">
                                            <span class="badge bg-${this.getStatusColor(c.status)}">${c.status}</span>
                                            <span class="badge bg-dark border border-secondary">${c.mitre}</span>
                                            <h5 class="text-white mb-0 ms-2">${c.title}</h5>
                                        </div>
                                        <p class="text-secondary mb-2">${c.description}</p>
                                        <div class="d-flex align-items-center gap-3 text-muted small flex-wrap">
                                            <span><i class="fa-solid fa-chess-knight me-1"></i> ${c.tactic}</span>
                                            <span><i class="fa-solid fa-layer-group me-1"></i> ${c.level}</span>
                                            <span><i class="fa-solid fa-database me-1"></i> ${c.dataNeeded.length} sources</span>
                                        </div>
                                        <div class="mt-2">
                                            ${c.iocs.slice(0, 3).map(ioc => `<code class="me-2 small">${ioc}</code>`).join('')}
                                        </div>
                                    </div>
                                    <div class="text-end ms-4" style="min-width: 150px;">
                                        <div class="progress bg-secondary bg-opacity-25" style="height: 6px;">
                                            <div class="progress-bar bg-${this.getStatusColor(c.status)}" style="width: ${c.progress}%"></div>
                                        </div>
                                        <span class="d-block mt-2 small text-muted">${c.progress}% Complete</span>
                                        <button class="btn btn-sm btn-outline-${this.getStatusColor(c.status)} mt-3 w-100">
                                            <i class="fa-solid fa-microscope me-2"></i>Investigate
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderHypotheses() {
        return `
            <div class="row g-4">
                ${this.hypotheses.map(h => `
                    <div class="col-md-6">
                        <div class="card bg-dark border-secondary h-100 hypothesis-card" onclick="window.ThreatHunting.selectHypothesis('${h.id}')">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-3">
                                    <div>
                                        <span class="badge bg-primary mb-2">${h.category}</span>
                                        <span class="badge bg-dark border border-secondary mb-2 ms-1">${h.mitre}</span>
                                        <h5 class="text-white">${h.title}</h5>
                                    </div>
                                    <i class="fa-solid fa-lightbulb text-warning fa-lg"></i>
                                </div>
                                <p class="text-secondary small">${h.description}</p>
                                <div class="mt-3">
                                    <span class="text-muted small"><i class="fa-solid fa-search me-1"></i>Indicators:</span>
                                    <div class="mt-1">
                                        ${h.indicators.map(i => `<span class="badge bg-dark border border-secondary me-1 mb-1">${i}</span>`).join('')}
                                    </div>
                                </div>
                            </div>
                            <div class="card-footer bg-transparent border-secondary">
                                <button class="btn btn-sm btn-outline-primary w-100">
                                    <i class="fa-solid fa-code me-2"></i>View Queries
                                </button>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
            
            ${this.selectedHypothesis ? this.renderHypothesisDetail() : ''}
        `;
    },

    renderHypothesisDetail() {
        const h = this.hypotheses.find(x => x.id === this.selectedHypothesis);
        if (!h) return '';

        return `
            <div class="modal show d-block" style="background: rgba(0,0,0,0.8);" onclick="window.ThreatHunting.closeHypothesis(event)">
                <div class="modal-dialog modal-xl modal-dialog-centered" onclick="event.stopPropagation()">
                    <div class="modal-content bg-dark border-secondary">
                        <div class="modal-header border-secondary">
                            <h5 class="modal-title text-white">
                                <i class="fa-solid fa-lightbulb text-warning me-2"></i>${h.title}
                            </h5>
                            <button class="btn-close btn-close-white" onclick="window.ThreatHunting.closeHypothesis()"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-4">
                                <span class="badge bg-primary">${h.category}</span>
                                <span class="badge bg-danger ms-2">${h.mitre}</span>
                            </div>
                            <p class="text-secondary">${h.description}</p>
                            
                            <!-- Query Language Selector -->
                            <div class="btn-group mb-3" role="group">
                                <button class="btn btn-sm ${this.queryLanguage === 'splunk' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('splunk')">Splunk SPL</button>
                                <button class="btn btn-sm ${this.queryLanguage === 'kql' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('kql')">KQL (Sentinel)</button>
                                <button class="btn btn-sm ${this.queryLanguage === 'elastic' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('elastic')">Elastic</button>
                            </div>
                            
                            <div class="query-block">
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <span class="text-success small"><i class="fa-solid fa-code me-1"></i>Detection Query</span>
                                    <button class="btn btn-sm btn-outline-success" onclick="navigator.clipboard.writeText(\`${this.queryLanguage === 'splunk' ? h.splunkQuery : this.queryLanguage === 'kql' ? h.kqlQuery : h.elasticQuery}\`)">
                                        <i class="fa-solid fa-copy me-1"></i>Copy
                                    </button>
                                </div>
                                <pre class="bg-black p-3 rounded text-success small mb-0"><code>${this.queryLanguage === 'splunk' ? h.splunkQuery : this.queryLanguage === 'kql' ? h.kqlQuery : h.elasticQuery}</code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderQueries() {
        return `
            <div class="card bg-dark border-secondary mb-4">
                <div class="card-header border-secondary bg-transparent d-flex justify-content-between align-items-center">
                    <h5 class="text-white mb-0"><i class="fa-solid fa-code me-2"></i>Query Library</h5>
                    <div class="btn-group" role="group">
                        <button class="btn btn-sm ${this.queryLanguage === 'splunk' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('splunk')">Splunk</button>
                        <button class="btn btn-sm ${this.queryLanguage === 'kql' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('kql')">KQL</button>
                        <button class="btn btn-sm ${this.queryLanguage === 'elastic' ? 'btn-primary' : 'btn-outline-secondary'}" onclick="window.ThreatHunting.setQueryLang('elastic')">Elastic</button>
                    </div>
                </div>
                <div class="card-body p-0">
                    <div class="list-group list-group-flush">
                        ${this.hypotheses.map(h => `
                            <div class="list-group-item bg-transparent border-secondary p-3">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <div>
                                        <span class="badge bg-primary me-2">${h.category}</span>
                                        <span class="badge bg-dark border border-secondary">${h.mitre}</span>
                                        <strong class="text-white ms-2">${h.title}</strong>
                                    </div>
                                    <button class="btn btn-sm btn-outline-success" onclick="navigator.clipboard.writeText(\`${this.queryLanguage === 'splunk' ? h.splunkQuery.replace(/`/g, '\\`') : this.queryLanguage === 'kql' ? h.kqlQuery.replace(/`/g, '\\`') : h.elasticQuery.replace(/`/g, '\\`')}\`)">
                                        <i class="fa-solid fa-copy"></i>
                                    </button>
                                </div>
                                <pre class="bg-black p-2 rounded text-success small mb-0" style="max-height: 100px; overflow: auto;"><code>${this.queryLanguage === 'splunk' ? h.splunkQuery : this.queryLanguage === 'kql' ? h.kqlQuery : h.elasticQuery}</code></pre>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderDataSources() {
        const totalLogs = this.dataSources.reduce((sum, ds) => {
            const num = parseFloat(ds.logsPerDay.replace(/[^0-9.]/g, ''));
            const mult = ds.logsPerDay.includes('M') ? 1000000 : ds.logsPerDay.includes('K') ? 1000 : 1;
            return sum + (num * mult);
        }, 0);

        return `
            <div class="row g-4 mb-4">
                <div class="col-md-4">
                    <div class="card bg-dark border-success h-100">
                        <div class="card-body text-center">
                            <i class="fa-solid fa-database fa-3x text-success mb-3"></i>
                            <h3 class="text-white">${this.dataSources.filter(d => d.status === 'connected').length}/${this.dataSources.length}</h3>
                            <p class="text-muted mb-0">Sources Connected</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-dark border-info h-100">
                        <div class="card-body text-center">
                            <i class="fa-solid fa-chart-line fa-3x text-info mb-3"></i>
                            <h3 class="text-white">${(totalLogs / 1000000).toFixed(1)}M</h3>
                            <p class="text-muted mb-0">Logs/Day</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-dark border-warning h-100">
                        <div class="card-body text-center">
                            <i class="fa-solid fa-clock fa-3x text-warning mb-3"></i>
                            <h3 class="text-white">90 Days</h3>
                            <p class="text-muted mb-0">Retention</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row g-4">
                ${this.dataSources.map(ds => `
                    <div class="col-md-3">
                        <div class="card bg-dark border-secondary h-100">
                            <div class="card-body text-center">
                                <i class="fa-${ds.icon === 'windows' ? 'brands' : 'solid'} fa-${ds.icon} fa-2x text-primary mb-3"></i>
                                <h6 class="text-white">${ds.name}</h6>
                                <span class="badge bg-success mb-2">Connected</span>
                                <p class="text-muted small mb-0">${ds.logsPerDay}/day</p>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.render();
    },

    selectHypothesis(id) {
        this.selectedHypothesis = id;
        this.render();
    },

    closeHypothesis(event) {
        if (event && event.target !== event.currentTarget) return;
        this.selectedHypothesis = null;
        this.render();
    },

    setQueryLang(lang) {
        this.queryLanguage = lang;
        this.render();
    },

    getStatusColor(status) {
        if (status === 'Active') return 'danger';
        if (status === 'New') return 'warning';
        if (status === 'Completed') return 'success';
        return 'secondary';
    },

    getStyles() {
        return `<style>
            .hunt-container { max-width: 1400px; margin: 0 auto; padding: 20px; }
            .hunt-header { 
                display: flex; justify-content: space-between; align-items: center; 
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                padding: 30px; border-radius: 12px; margin-bottom: 30px; 
                border-bottom: 3px solid #dc3545;
                box-shadow: 0 10px 40px rgba(220,53,69,0.2);
            }
            .hunt-tabs {
                display: flex; gap: 10px; flex-wrap: wrap;
            }
            .hunt-tab {
                background: #1a1a2e; border: 1px solid #333; color: #888;
                padding: 12px 24px; border-radius: 8px; cursor: pointer;
                transition: all 0.3s ease;
            }
            .hunt-tab:hover { border-color: #dc3545; color: #fff; }
            .hunt-tab.active { 
                background: linear-gradient(135deg, #dc3545, #c82333);
                border-color: #dc3545; color: #fff;
            }
            .hunt-stat-card {
                background: linear-gradient(135deg, #1a1a2e, #16213e);
                padding: 25px; border-radius: 12px; border-left: 4px solid;
                position: relative; overflow: hidden;
            }
            .hunt-stat-card .stat-icon {
                position: absolute; right: 20px; top: 50%; transform: translateY(-50%);
                font-size: 2.5rem; opacity: 0.2;
            }
            .hunt-item { transition: all 0.3s ease; }
            .hunt-item:hover { background: rgba(220,53,69,0.1) !important; }
            .hypothesis-card { cursor: pointer; transition: all 0.3s ease; }
            .hypothesis-card:hover { 
                transform: translateY(-5px); 
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                border-color: #ffc107 !important;
            }
            .query-block {
                background: #0a0a15; border: 1px solid #333;
                padding: 15px; border-radius: 8px;
            }
            .fade-in { animation: fadeIn 0.5s ease; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        </style>`;
    }
};

function pageThreatHunting() {
    setTimeout(() => window.ThreatHunting.render(), 0);
    return `<div id="hunt-app"></div>`;
}

// Global Export
window.pageThreatHunting = pageThreatHunting;
