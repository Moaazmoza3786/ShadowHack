from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "online",
        "system": "SATELLITE-CONTROL-BRAVO",
        "message": "Authentication required. Provide 'X-Satellite-Token' in headers.",
        "hint": "The token is a combination of the current year and the secret project name: 'GALAXIA'."
    })

@app.route('/api/v1/status', methods=['POST'])
def status():
    token = request.headers.get('X-Satellite-Token')
    if token == "2026-GALAXIA":
        return jsonify({
            "access": "granted",
            "message": "Welcome, Commander.",
            "data": "The core systems are now responsive. Execute 'UNLOCK' to proceed."
        })
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/v1/unlock', methods=['PUT'])
def unlock():
    token = request.headers.get('X-Satellite-Token')
    command = request.json.get('command')
    if token == "2026-GALAXIA" and command == "UNLOCK":
        return jsonify({
            "success": True,
            "flag": "AG{s4t3llit3_r3cl4im3d}",
            "logs": "Satellite control restored. rogue-01 disconnected."
        })
    return jsonify({"error": "Invalid command or token"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
