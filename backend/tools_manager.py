"""
Tools Manager - The Power Behind Pro Tools 🛠️
Provides backend logic for OSINT search, JS Monitoring, and advanced Obfuscation.
"""

import requests
import json
import logging
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ToolsManager')

import subprocess
import shlex

class ToolExecutor:
    """
    Handles secure execution of external tools.
    """
    ALLOWED_TOOLS = {
        'nmap': '/usr/bin/nmap',
        'subfinder': '/usr/bin/subfinder', # Assumes installed
        'httpx': '/usr/bin/httpx',
        'ping': '/bin/ping',
        'whois': '/usr/bin/whois',
        'dig': '/usr/bin/dig',
        'curl': '/usr/bin/curl',
        'sqlmap': '/usr/bin/sqlmap',
        'nikto': '/usr/bin/nikto',
        'gobuster': '/usr/bin/gobuster',
        'hydra': '/usr/bin/hydra',
        'john': '/usr/sbin/john',
        'aws': '/usr/bin/aws',
        'cat': '/bin/cat', # Useful for reading local files (careful!)
        'ls': '/bin/ls'
    }

    def validate_command(self, cmd_str):
        """
        Validates if the command is allowed and safe.
        Returns (is_valid, reason/sanitized_cmd_list)
        """
        try:
            parts = shlex.split(cmd_str)
            if not parts:
                return False, "Empty command"
            
            base_cmd = parts[0]
            if base_cmd not in self.ALLOWED_TOOLS:
                return False, f"Tool '{base_cmd}' is not allowed via this interface."
            
            # Prevent chaining or redirection (basic check)
            if any(c in cmd_str for c in [';', '|', '>', '<', '&', '$', '`']):
                 return False, "Shell operators are not allowed."

            return True, parts
        except Exception as e:
            return False, str(e)

    def execute_tool(self, cmd_str, output_callback):
        """
        Executes a tool and streams output to callback.
        """
        is_valid, result = self.validate_command(cmd_str)
        if not is_valid:
            output_callback(f"\x1b[1;31m[!] Error: {result}\x1b[0m\r\n")
            return

        cmd_parts = result
        tool_name = cmd_parts[0]
        
        # Check if tool is installed
        import shutil
        if not shutil.which(tool_name):
             output_callback(f"\x1b[1;33m[!] Tool '{tool_name}' not found. Installing...\x1b[0m\r\n")
             # In a real scenario, we might auto-install or warn.
             # For now, let's warn.
             output_callback(f"\x1b[1;31m[!] Error: '{tool_name}' is not installed in the environment.\x1b[0m\r\n")
             return

        try:
            process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1, # Line buffered
                universal_newlines=True
            )

            for line in process.stdout:
                output_callback(line)

            process.wait()
            if process.returncode == 0:
                output_callback("\x1b[1;32m[+] Execution completed successfully.\x1b[0m\r\n")
            else:
                output_callback(f"\x1b[1;31m[!] Tool exited with code {process.returncode}.\x1b[0m\r\n")

        except Exception as e:
            output_callback(f"\x1b[1;31m[!] Execution failed: {str(e)}\x1b[0m\r\n")


class ToolsManager:
    """
    Backend logic for professional security tools.
    """
    
    def __init__(self):
        self.monitored_targets = {}  # {url: {last_content: str, last_check: datetime}}
        self._osint_cache = {}

    # --- OSINT PRO ENGINE ---
    def osint_search(self, target: str, search_type: str = "all") -> Dict[str, Any]:
        """
        Perform deep OSINT search on a domain or IP.
        (Simulated for now, with structure for real API integration)
        """
        logger.info(f"🔍 OSINT Search on: {target} (Type: {search_type})")
        
        # Simulate API delay
        time.sleep(1.5)
        
        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": []
        }

        # Mock Data based on real OSINT patterns
        if "." in target: # Domain
            results["findings"].append({
                "source": "DNS",
                "data": {
                    "A": "192.168.1.50",
                    "MX": ["mail.target.com"],
                    "TXT": ["v=spf1 include:_spf.google.com ~all"]
                }
            })
            results["findings"].append({
                "source": "Whois",
                "data": {
                    "registrar": "NameCheap",
                    "creation_date": "2020-01-15",
                    "owner": "Redacted for Privacy"
                }
            })
        
        results["findings"].append({
            "source": "ThreatIntelligence",
            "data": {
                "malicious_score": 15,
                "known_vulnerabilities": ["CVE-2023-1234", "CVE-2021-44228"]
            }
        })

        return {"success": True, "results": results}

    # --- JS MONITOR PRO ---
    def add_js_monitor(self, url: str) -> Dict[str, Any]:
        """Add a URL to the JS monitoring list"""
        if url in self.monitored_targets:
            return {"success": False, "message": "Already monitoring this target"}
            
        self.monitored_targets[url] = {
            "last_check": datetime.utcnow().isoformat(),
            "status": "monitoring",
            "changes": 0
        }
        
        logger.info(f"👁️ Started monitoring JS on: {url}")
        return {"success": True, "message": f"Now monitoring {url}"}

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get status of all monitored targets"""
        return {"success": True, "targets": self.monitored_targets}

    # --- PAYLOAD GENERATOR PRO ---
    def obfuscate_payload(self, payload: str, method: str = "advanced_xor") -> Dict[str, Any]:
        """
        Advanced backend-powered obfuscation.
        """
        logger.info(f"🛡️ Obfuscating payload using {method}")
        
        if method == "advanced_xor":
            # Real XOR logic here
            key = 0x55
            obfuscated = "".join([chr(ord(c) ^ key) for c in payload])
            wrapper = f"python3 -c \"print(''.join([chr(ord(c)^0x55) for c in '{obfuscated}']))\""
            return {"success": True, "payload": wrapper, "method": method}
            
        return {"success": False, "error": "Unknown obfuscation method"}

# ==================== FLASK ROUTES ====================

def register_tools_routes(app):
    from flask import request, jsonify
    tools = ToolsManager()

    @app.route('/api/tools/osint', methods=['POST'])
    def do_osint():
        data = request.json
        target = data.get('target')
        search_type = data.get('type', 'all')
        
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'}), 400
            
        result = tools.osint_search(target, search_type)
        return jsonify(result)

    @app.route('/api/tools/js-monitor', methods=['POST', 'GET'])
    def js_monitor():
        if request.method == 'POST':
            data = request.json
            url = data.get('url')
            return jsonify(tools.add_js_monitor(url))
        else:
            return jsonify(tools.get_monitoring_status())

    @app.route('/api/tools/obfuscate', methods=['POST'])
    def obfuscate():
        data = request.json
        payload = data.get('payload')
        method = data.get('method', 'advanced_xor')
        
        if not payload:
            return jsonify({'success': False, 'error': 'No payload provided'}), 400
            
        return jsonify(tools.obfuscate_payload(payload, method))

    logger.info("✓ Pro Tools API routes registered")
