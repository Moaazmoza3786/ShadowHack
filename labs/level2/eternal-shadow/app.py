from flask import Flask, request, render_template_string
import time

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Metasploit Pro - Simulated Console</title>
    <style>
        body { background: #1a1a1a; color: #eee; font-family: 'Consolas', monospace; padding: 20px; }
        #console { background: #000; border: 1px solid #444; padding: 20px; height: 500px; overflow-y: auto; white-space: pre-wrap; margin-bottom: 20px; }
        input { background: #000; border: none; color: #0f0; width: 80%; font-family: inherit; font-size: 1em; outline: none; }
        .prompt { color: #f00; }
        .success { color: #0f0; }
        .warning { color: #ff0; }
    </style>
</head>
<body>
    <div id="console">{{ history|safe }}</div>
    <form method="POST">
        <span class="prompt">msf6 > </span><input name="command" autofocus>
    </form>
</body>
</html>
"""

history = "[*] Starting Metasploit Framework Console...\\n[*] MSFv6.2.1-dev\\n"

@app.route('/', methods=['GET', 'POST'])
def index():
    global history
    if request.method == 'POST':
        cmd = request.form.get('command', '').strip()
        history += f'<span class="prompt">msf6 > </span>{cmd}\\n'
        
        if cmd == "help":
            history += "Available commands: help, use, show, set, run, exit\\n"
        elif cmd.startswith("use exploit/windows/smb/ms17_010_eternalblue"):
            history += "[*] Using configured payload windows/x64/meterpreter/reverse_tcp\\n"
            history += '<span class="prompt">msf6 exploit(ms17_010_eternalblue) > </span>\\n'
        elif "ms17_010" in cmd and "run" in cmd:
            history += "[*] Started reverse TCP handler on 0.0.0.0:4444 \\n"
            history += "[*] 10.10.10.100:445 - Target OS: Windows 7 Professional 7601 Service Pack 1 x64\\n"
            history += "[+] 10.10.10.100:445 - Target is vulnerable!\\n"
            history += "[*] 10.10.10.100:445 - Sending exploit...\\n"
            history += "[+] 10.10.10.100:445 - ETERNALBLUE Exploit successful!\\n"
            history += "[*] Meterpreter session 1 opened (10.10.10.1:4444 -> 10.10.10.100:49158)\\n"
            history += "<span class='success'>meterpreter > </span>\\n"
        elif "cat flag.txt" in cmd or "type flag.txt" in cmd:
            history += "AG{3t3rn4l_r0cks_th3_syst3m}\\n"
        else:
            history += f"[-] Unknown command: {cmd}\\n"
            
    return render_template_string(HTML_TEMPLATE, history=history)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
