const express = require('express');
const app = express();
app.use(express.json());

const HTML = `
<!DOCTYPE html>
<html>
<head>
    <title>THE SINGULARITY - ROOT</title>
    <style>
        body { background: #000; color: #ff00ff; font-family: 'Orbitron', sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; }
        .glitch { font-size: 3em; font-weight: bold; text-transform: uppercase; position: relative; text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; animation: glitch 725ms infinite; }
        @keyframes glitch {
            0% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; }
            15% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; }
            16% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff, -0.05em -0.05em 0 #fffc00; }
            49% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff, -0.05em -0.05em 0 #fffc00; }
            50% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff, 0 -0.04em 0 #fffc00; }
            99% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff, 0 -0.04em 0 #fffc00; }
            100% { text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.04em 0 #fc00ff, -0.04em -0.03em 0 #fffc00; }
        }
        .console { background: #111; border: 1px solid #ff00ff; padding: 20px; width: 80%; border-radius: 5px; box-shadow: 0 0 30px #ff00ff44; margin-top: 20px; font-family: 'Courier New', monospace; font-size: 0.8em; }
        .input-line { display: flex; align-items: center; margin-top: 10px; }
        input { background: transparent; border: none; color: #ff00ff; flex-grow: 1; outline: none; caret-color: #ff00ff; }
        .success { color: #00ff00; }
    </style>
</head>
<body>
    <div class="glitch">PROJECT SINGULARITY</div>
    <div id="status" style="margin-top: 10px; color: #555;">[LEVEL 5 - LEGENDARY]</div>
    <div class="console" id="console">
        <div>[SYSTEM] INITIALIZING CORE OVERRIDE...</div>
        <div>[SYSTEM] WARNING: HIGH RADIATION DATA DETECTED.</div>
        <div>[USER] IDENTIFICATION REQUIRED. PROVIDE ROOT PASSPHRASE.</div>
        <div id="history"></div>
        <div class="input-line">
            <span>root@singularity:~# </span>
            <input type="text" id="cmd" autofocus onkeydown="handle(event)">
        </div>
    </div>

    <script>
        function handle(e) {
            if (e.key === 'Enter') {
                const cmd = e.target.value.trim();
                const history = document.getElementById('history');
                const line = document.createElement('div');
                line.innerHTML = '<span>root@singularity:~# </span>' + cmd;
                history.appendChild(line);
                e.target.value = '';

                fetch('/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                }).then(r => r.json()).then(data => {
                    const response = document.createElement('div');
                    if (data.success) {
                        response.innerHTML = '<span class="success">' + data.output + '</span>';
                    } else {
                        response.innerText = data.output || 'Command failed.';
                    }
                    history.appendChild(response);
                    document.getElementById('console').scrollTop = document.getElementById('console').scrollHeight;
                });
            }
        }
    </script>
</body>
</html>
`;

app.get('/', (req, res) => res.send(HTML));

app.post('/execute', (req, res) => {
    const { command } = req.body;
    if (command === "HELP") {
        return res.json({ success: true, output: "Available vectors: OVERRIDE, DECRYPT, EXFILTRATE" });
    }
    if (command === "OVERRIDE") {
        return res.json({ success: true, output: "Bypassing biometric firewall... OK. Accessing Singularity Vault." });
    }
    if (command === "DECRYPT") {
        return res.json({ success: true, output: "Cracking final layer... [||||||||||] 100%. Data decrypted." });
    }
    if (command === "EXFILTRATE") {
        return res.json({ success: true, output: "TRANSFERENCE COMPLETE. FLAG DETECTED: AG{th3_s1ngul4r1ty_1s_h3r3_2026}" });
    }
    res.json({ success: false, output: `bash: ${command}: command not found. Try 'HELP'.` });
});

app.listen(80, () => console.log('Singularity active on port 80'));
