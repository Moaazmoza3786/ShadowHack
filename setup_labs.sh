#!/bin/bash

# ShadowHack CTF Lab Structure Generator
# This script sets up the 5 levels of CTF challenges with Dockerfiles, Source Code, and Metadata.

echo "🚀 Generating ShadowHack CTF Lab Structure..."

# Level 1: Ground Zero
mkdir -p labs/level1/intern-mistake
mkdir -p labs/level1/leaky-bucket

# 1.1 The Intern's Mistake
cat <<EOF > labs/level1/intern-mistake/Dockerfile
FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 80
EOF

cat <<EOF > labs/level1/intern-mistake/index.html
<!DOCTYPE html>
<html>
<head><title>Beta Portal</title></head>
<body>
    <h1>Welcome to the internal beta portal.</h1>
    <p>This page is under construction. Please check back later.</p>
    <!-- DEV NOTE: Temporary admin access token: AG{Y0u_F0und_7h3_C0mm3n7} -->
</body>
</html>
EOF

cat <<EOF > labs/level1/intern-mistake/metadata.json
{
  "id": "ctf-intern-mistake",
  "name": "The Intern's Mistake",
  "description": "An intern forgot to scrub the notes. Can you find the secrets in the source?",
  "difficulty": "easy",
  "tier": 1,
  "port": 80,
  "category": "Web / Source Code",
  "flag": "AG{Y0u_F0und_7h3_C0mm3n7}"
}
EOF

# 1.2 The Leaky Bucket
mkdir -p labs/level1/leaky-bucket/dev_backups
cat <<EOF > labs/level1/leaky-bucket/Dockerfile
FROM php:7.4-apache
RUN apt-get update && apt-get install -y zip
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
EOF

cat <<EOF > labs/level1/leaky-bucket/index.php
<?php
echo "<h1>Welcome to Global Logistics Corp</h1>";
echo "<p>System Status: Online</p>";
// DEV NOTE: Backups moved to /dev_backups/ for safety.
?>
EOF

echo "AG{unsecure_backups_lead_to_leaks_2024}" > labs/level1/leaky-bucket/dev_backups/flag.txt
# (In a real scenario we'd zip it, but for simplicity of script creation we'll just put the file)

cat <<EOF > labs/level1/leaky-bucket/metadata.json
{
  "id": "ctf-leaky-bucket",
  "name": "The Leaky Bucket",
  "description": "A disgruntled employee left more than just a resignation letter. Can you find the shadow backup?",
  "difficulty": "easy",
  "tier": 1,
  "port": 80,
  "category": "Web / Exposure",
  "flag": "AG{unsecure_backups_lead_to_leaks_2024}"
}
EOF

# Level 2: Escape Velocity
mkdir -p labs/level2/login-limbo
mkdir -p labs/level2/ghost-archive/src

# 2.1 Login Limbo
cat <<EOF > labs/level2/login-limbo/Dockerfile
FROM php:7.4-apache
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev
RUN docker-php-ext-install pdo pdo_sqlite
COPY index.php /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
EOF

cat <<EOF > labs/level2/login-limbo/index.php
<?php
\$db = new PDO('sqlite::memory:');
\$db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, flag TEXT)");
\$db->exec("INSERT INTO users (username, password, flag) VALUES ('admin', 'super_secret_p@ss_2026', 'AG{SQL_Inj3ct10n_M4st3r}')");

if (\$_SERVER['REQUEST_METHOD'] === 'POST') {
    \$user = \$_POST['username'];
    \$pass = \$_POST['password'];
    \$query = "SELECT * FROM users WHERE username = '\$user' AND password = '\$pass'";
    \$result = \$db->query(\$query);
    if (\$result && \$result->fetch()) {
        echo "<h1>Logged in as Admin!</h1><p>Flag: AG{SQL_Inj3ct10n_M4st3r}</p>";
        exit;
    } else {
        echo "<p style='color:red;'>Login Failed!</p>";
    }
}
?>
<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <button type="submit">Login</button>
</form>
EOF

cat <<EOF > labs/level2/login-limbo/metadata.json
{
  "id": "ctf-login-limbo",
  "name": "Login Limbo",
  "description": "An outdated portal guarded by a weak lock. Can you bypass the gate?",
  "difficulty": "medium",
  "tier": 2,
  "port": 80,
  "category": "Web / SQLi",
  "flag": "AG{SQL_Inj3ct10n_M4st3r}"
}
EOF

# 2.2 The Ghost Archive
cat <<EOF > labs/level2/ghost-archive/Dockerfile
FROM php:7.4-apache
COPY src/ /var/www/html/
RUN echo "AG{LFI_Tr4v3rs4l_M4st3r_2026}" > /etc/secret_flag.txt
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
EOF

cat <<EOF > labs/level2/ghost-archive/src/index.php
<?php
\$file = \$_GET['doc'] ?? 'welcome.txt';
if (\$file) {
    include(\$file);
}
?>
<hr>
<ul>
    <li><a href="?doc=welcome.txt">Welcome</a></li>
    <li><a href="?doc=policy.txt">Policy</a></li>
    <li><a href="?doc=credits.txt">Credits</a></li>
</ul>
EOF

echo "Welcome to the Ghost Archive." > labs/level2/ghost-archive/src/welcome.txt
echo "Our policy is strictly digital." > labs/level2/ghost-archive/src/policy.txt
echo "Built by the Ancients." > labs/level2/ghost-archive/src/credits.txt

cat <<EOF > labs/level2/ghost-archive/metadata.json
{
  "id": "ctf-ghost-archive",
  "name": "The Ghost Archive",
  "description": "A legacy retrieval system with a pathing flaw. Can you ghost the files?",
  "difficulty": "medium",
  "tier": 2,
  "port": 80,
  "category": "Web / LFI",
  "flag": "AG{LFI_Tr4v3rs4l_M4st3r_2026}"
}
EOF

# Level 3: Orbit
mkdir -p labs/level3/ping-pong

cat <<EOF > labs/level3/ping-pong/Dockerfile
FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
RUN echo "AG{C0mm4nd_Inj3ct10n_1s_L3th4l}" > /root/flag.txt
EXPOSE 5000
CMD ["python", "app.py"]
EOF

cat <<EOF > labs/level3/ping-pong/app.py
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
EOF

cat <<EOF > labs/level3/ping-pong/metadata.json
{
  "id": "ctf-ping-pong",
  "name": "Ping Pong",
  "description": "A diagnostic tool with a serious logic flaw. Can you break out of the script?",
  "difficulty": "hard",
  "tier": 3,
  "port": 5000,
  "category": "Web / Command Injection",
  "flag": "AG{C0mm4nd_Inj3ct10n_1s_L3th4l}"
}
EOF

# Level 4: Deep Space
mkdir -p labs/level4/identity-paradox

cat <<EOF > labs/level4/identity-paradox/Dockerfile
FROM node:14-alpine
WORKDIR /app
COPY package.json .
RUN npm install express jsonwebtoken cookie-parser body-parser
COPY server.js .
ENV FLAG="AG{W34k_JWT_S3cr3ts_Cr4ck3d}"
EXPOSE 3000
CMD ["node", "server.js"]
EOF

cat <<EOF > labs/level4/identity-paradox/package.json
{
  "name": "identity-paradox",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "jsonwebtoken": "^8.5.1",
    "cookie-parser": "^1.4.5",
    "body-parser": "^1.19.0"
  }
}
EOF

cat <<EOF > labs/level4/identity-paradox/server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());
const SECRET_KEY = 'moonbase'; 
app.get('/', (req, res) => {
    const token = req.cookies.auth;
    if (!token) {
        const guestToken = jwt.sign({ username: 'guest', role: 'guest' }, SECRET_KEY);
        res.cookie('auth', guestToken);
        return res.send('<h1>Welcome Guest. Status: Access Denied.</h1>');
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        if (decoded.role === 'admin') {
            return res.send(\`<h1>ADMIN ACCESS GRANTED!</h1><p>Flag: \${process.env.FLAG}</p>\`);
        } else {
            return res.send(\`<h1>Welcome \${decoded.username}.</h1><p>Role: \${decoded.role}</p><p>Status: Access Denied.</p>\`);
        }
    } catch (e) { res.send('Invalid Token'); }
});
app.listen(3000, () => console.log('Server running on port 3000'));
EOF

cat <<EOF > labs/level4/identity-paradox/metadata.json
{
  "id": "ctf-identity-paradox",
  "name": "The Identity Paradox",
  "description": "A communication link secured by a weak secret. Can you forge a high-level identity?",
  "difficulty": "hard",
  "tier": 4,
  "port": 3000,
  "category": "Web / JWT",
  "flag": "AG{W34k_JWT_S3cr3ts_Cr4ck3d}"
}
EOF

# Level 5: Singularity
mkdir -p labs/level5/dark-matter-object

cat <<EOF > labs/level5/dark-matter-object/Dockerfile
FROM python:3.9-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
ENV FLAG="AG{D3s3r1al1z4t10n_1s_D3adly_RCE}"
EXPOSE 5000
CMD ["python", "app.py"]
EOF

cat <<EOF > labs/level5/dark-matter-object/app.py
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
EOF

cat <<EOF > labs/level5/dark-matter-object/metadata.json
{
  "id": "ctf-dark-matter-object",
  "name": "Dark Matter Object",
  "description": "An unstable core processing raw serialized streams. Can you achieve total control?",
  "difficulty": "insane",
  "tier": 5,
  "port": 5000,
  "category": "Web / Deserialization",
  "flag": "AG{D3s3r1al1z4t10n_1s_D3adly_RCE}"
}
EOF

echo "✅ Lab structure successfully generated in /labs folder!"
