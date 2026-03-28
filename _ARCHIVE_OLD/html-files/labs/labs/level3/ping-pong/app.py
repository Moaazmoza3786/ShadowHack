import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/')
def index():
    host = request.args.get('host')
    if host:
        result = os.popen(f"ping -c 1 {host}").read()
        return f"<pre>{result}</pre>"
    return "<h1>Network Tools</h1><form><input name='host'><button>Ping</button></form>"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
