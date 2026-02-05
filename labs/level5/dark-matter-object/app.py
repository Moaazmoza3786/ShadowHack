import base64, pickle
from flask import Flask, request, make_response
app = Flask(__name__)
class User:
    def __init__(self, username): self.username = username
@app.route('/')
def home():
    cookie = request.cookies.get('session')
    if not cookie:
        user_obj = User("Explorer")
        serialized = base64.b64encode(pickle.dumps(user_obj)).decode()
        resp = make_response("<h1>Welcome, Explorer!</h1>")
        resp.set_cookie('session', serialized)
        return resp
    try:
        user_data = base64.b64decode(cookie)
        user_obj = pickle.loads(user_data)
        return f"<h1>Welcome back, {user_obj.username}!</h1>"
    except Exception as e: return f"Error: {e}"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
