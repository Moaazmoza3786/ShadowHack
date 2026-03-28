from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Restricted Core - Shell</title>
    <style>
        body { background: #0c0c0c; color: #33ff33; font-family: 'Consolas', monospace; padding: 20px; }
        #console { background: #000; border: 1px solid #333; padding: 15px; height: 500px; overflow-y: auto; white-space: pre-wrap; font-size: 0.9em; line-height: 1.4; box-shadow: 0 0 10px #00ff0011; }
        form { margin-top: 10px; display: flex; }
        .prompt { color: #f00; margin-right: 10px; }
        input { background: #000; border: none; color: #33ff33; flex-grow: 1; font-family: inherit; font-size: 1em; outline: none; }
        .info { color: #0088ff; }
        .success { color: #ffff00; font-weight: bold; }
    </style>
</head>
<body>
    <div style="margin-bottom: 20px;">
        <span class="info">[SATELLITE-OS v4.2] Restricted Environment</span> | User: worker_01 | Node: NODE-771
    </div>
    <div id="console">{{ history|safe }}</div>
    <form method="POST">
        <span class="prompt">worker_01@node771:~$</span><input name="command" autofocus autocomplete="off">
    </form>
</body>
</html>
"""

history = """Welcome to the node shell.
Type 'help' for available commands.
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    global history
    if request.method == 'POST':
        cmd = request.form.get('command', '').strip()
        history += f'<span class="prompt">worker_01@node771:~$</span> {cmd}\n'
        
        if cmd == "help":
            history += "Available commands: ls, cat, whoami, docker, help\n"
        elif cmd == "ls":
            history += "archive/  app/  logs/  docker.sock\n"
        elif cmd == "ls -la":
            history += "total 24\ndrwxr-xr-x 1 worker worker 4096 Jan 10 10:25 .\ndrwxr-xr-x 1 root   root   4096 Jan 10 10:25 ..\ndrwxr-xr-x 2 worker worker 4096 Jan 10 10:25 app\nsrw-rw---- 1 root   docker    0 Jan 10 10:25 docker.sock\n"
        elif cmd == "whoami":
            history += "worker_01\n"
        elif cmd == "docker images":
            history += "REPOSITORY          TAG       IMAGE ID       CREATED       SIZE\nsatellite-core      latest    a1b2c3d4e5f6   2 hours ago   128MB\nalpine              latest    c8b2c3d4e5f6   4 weeks ago   5MB\n"
        elif "docker run" in cmd and "-v /:/" in cmd:
            history += "[*] Mounting host filesystem...\n[*] Bypassing container isolation...\n[*] Accessing host secret store...\n"
            history += "<span class='success'>[+] HOST ACCESS GRANTED. FLAG FOUND: AG{d0ck3r_3sc4p3_succ3ss}</span>\n"
        elif cmd.startswith("docker"):
            history += "Docker is installed. You have access to the docker.sock. Find a way to reach the host.\n"
        elif cmd.startswith("cat"):
            history += "Permission denied: access restricted to local files only.\n"
        else:
            history += f"bash: {cmd}: command not found\n"
            
    return render_template_string(HTML_TEMPLATE, history=history)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
