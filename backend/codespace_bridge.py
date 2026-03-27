#!/usr/bin/env python3
"""
Study Hub Codespace Bridge
Automatically connects the Codespace environment to the Study Hub API.
"""
import os
import json
import requests
import time
from datetime import datetime

API_URL = os.environ.get('STUDYHUB_API_URL', 'http://localhost:5000/api')
CODESPACE_NAME = os.environ.get('CODESPACE_NAME', 'local')
USER_ID = os.environ.get('STUDYHUB_USER_ID', 'anon')

def register_environment():
    """Register this codespace with the central backend"""
    print(f"🚀 Registering Codespace [{CODESPACE_NAME}] with Study Hub API...")
    try:
        response = requests.post(f"{API_URL}/codespaces/register", json={
            "codespace_id": CODESPACE_NAME,
            "user_id": USER_ID,
            "status": "ready",
            "tools": ["nmap", "metasploit", "nikto", "gobuster", "searchsploit"],
            "timestamp": datetime.now().isoformat()
        }, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return False

def pull_commands():
    """Poll for new commands from the Study Hub API"""
    try:
        response = requests.get(f"{API_URL}/codespaces/commands/{CODESPACE_NAME}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            for cmd in data.get('commands', []):
                handle_command(cmd)
    except Exception as e:
        pass

def handle_command(cmd):
    """Process a single command from the backend"""
    ctype = cmd.get('type')
    if ctype == 'deploy':
        artifact = cmd.get('payload', {})
        name = artifact.get('name', 'exploit_code.txt')
        content = artifact.get('content', '')
        
        # Save to missions/ directory
        os.makedirs('missions', exist_ok=True)
        filepath = os.path.join('missions', name)
        
        with open(filepath, 'w') as f:
            f.write(content)
            
        print(f"📥 [DEPLOYED] Received artifact: {name} -> {filepath}")

if __name__ == "__main__":
    print("--- Study Hub Codespace Bridge ---")
    if register_environment():
        print("✅ Connection Established. Monitoring for tactical deployments...")
        while True:
            pull_commands()
            time.sleep(5) # Poll every 5 seconds
    else:
        print("❌ Could not connect to Study Hub API. Please check your network or API_URL.")
        time.sleep(30)
