#!/usr/bin/env python3
"""
Study Hub Codespace Bridge
Automatically connects the Codespace environment to the Study Hub API.
"""
import os
import json
import requests
import time

API_URL = os.environ.get('STUDYHUB_API_URL', 'http://localhost:5000/api')
CODESPACE_NAME = os.environ.get('CODESPACE_NAME', 'local')
USER_ID = os.environ.get('STUDYHUB_USER_ID')

def register_environment():
    """Register this codespace with the central backend"""
    print(f"🚀 Registering Codespace [{CODESPACE_NAME}] with Study Hub API...")
    try:
        response = requests.post(f"{API_URL}/codespaces/register", json={
            "codespace_id": CODESPACE_NAME,
            "user_id": USER_ID,
            "status": "ready",
            "tools": ["nmap", "metasploit", "nikto", "gobuster"]
        }, timeout=5)
        if response.status_code == 200:
            print("✅ Registration successful.")
        else:
            print(f"⚠️ Registration returned status: {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to connect to API: {e}")

if __name__ == "__main__":
    if not USER_ID:
        print("⚠️ STUDYHUB_USER_ID not set. Running in anonymous mode.")
    register_environment()
    # Keep alive or perform health checks
    while True:
        time.sleep(60)
