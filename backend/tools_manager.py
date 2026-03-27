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
import re
from urllib.parse import urljoin, urlparse

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
        'az': '/usr/bin/az',
        'nc': '/bin/nc',
        'theHarvester': '/usr/bin/theHarvester',
        'sherlock': '/usr/bin/sherlock',
        'cat': '/bin/cat', # Useful for reading local files (careful!)
        'ls': '/bin/ls',
        'searchsploit': '/usr/bin/searchsploit'
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
        self.harvest_results = {}  # {target: {status: str, logs: [], data: {}, score: 0}}
        self.crack_results = {}    # {task_id: {status: str, logs: [], progress: 0, speed: 0, cracked_pass: str}}
        self.subdomain_monitors = {} # {domain: {status: str, interval: int, last_run: str, logs: []}}
        self.subdomain_inventory = {} # {domain: [subdomains]}
        self.visual_maps = {}      # {domain: {nodes: [], links: [], status: str}}
        self.fuzz_results = {}     # {task_id: {status: str, results: [], total_requests: int, speed: int}}
        self.projects = {}         # {project_id: {name: str, target: str, data: {}, created_at: str}}
        self.codespace_commands = {} # {codespace_id: [commands]}
        self.active_missions = {}    # {mission_id: mission_data}
        self.campaigns = self._initialize_campaigns()

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


    # --- SHADOWHARVESTER OSINT ENGINE ---
    def start_harvest(self, target: str) -> Dict[str, Any]:
        """
        Starts an asynchronous harvesting task for a target.
        """
        if target in self.harvest_results and self.harvest_results[target]['status'] == 'running':
            return {"success": False, "error": "Harvest already in progress for this target"}
            
        self.harvest_results[target] = {
            "status": "running",
            "start_time": datetime.utcnow().isoformat(),
            "logs": ["[*] Initializing ShadowHarvester Engine...", f"[*] Target set to: {target}"],
            "data": {
                "nodes": [{"id": target, "group": 1, "label": target}],
                "links": [],
                "employees": [],
                "leaked_credentials": [],
                "sensitive_files": []
            },
            "score": 0
        }
        
        # Start background thread
        thread = threading.Thread(target=self._harvest_task, args=(target,))
        thread.daemon = True
        thread.start()
        
        return {"success": True, "message": "Harvesting started in background"}

    def get_harvest_status(self, target: str) -> Dict[str, Any]:
        """Returns the current status and logs for a harvest."""
        return {"success": True, "data": self.harvest_results.get(target, {"status": "not_found"})}

    def _add_harvest_log(self, target: str, msg: str):
        if target in self.harvest_results:
            self.harvest_results[target]['logs'].append(msg)
            logger.info(f"[SH-{target}] {msg}")

    def _harvest_task(self, target: str):
        """Worker thread for OSINT harvesting"""
        try:
            # 1. Google Dorking
            self._add_harvest_log(target, "[+] Initiating Advanced Google Dorking...")
            dorks = [
                f'site:{target} filetype:pdf OR filetype:doc',
                f'site:{target} "password" OR "config"',
                f'site:github.com "{target}" api_key'
            ]
            
            time.sleep(2) # Simulate network delay
            self._add_harvest_log(target, "[+] Found 12 sensitive file candidates.")
            
            # Mock results for visualization
            self.harvest_results[target]['data']['sensitive_files'] = [
                {"name": "employee_handbook_2024.pdf", "url": f"http://{target}/files/handbook.pdf", "metadata": {"author": "HR-Dept", "tool": "Acrobat 9.0"}},
                {"name": "config_backup.bak", "url": f"http://{target}/backup/config.bak", "metadata": {"status": "critical"}}
            ]
            
            # 2. DeHashed / Leak Analysis (Mocked)
            self._add_harvest_log(target, "[+] Querying Breach Repositories...")
            time.sleep(3)
            
            leaks = [
                {"email": f"admin@{target}", "source": "LinkedIn-2016", "hash": "8f3..."},
                {"email": f"ceo@{target}", "source": "Canva-Leak", "pass": "Qwerty123!"},
                {"email": f"dev@{target}", "source": "Github-Public", "type": "SSH Key"}
            ]
            self.harvest_results[target]['data']['leaked_credentials'] = leaks
            
            # Update Graph Nodes
            data = self.harvest_results[target]['data']
            for leak in leaks:
                email = leak['email']
                data['nodes'].append({"id": email, "group": 2, "label": email})
                data['links'].append({"source": target, "target": email, "value": 2})
                
                # Add source node
                src = leak['source']
                if not any(n['id'] == src for n in data['nodes']):
                    data['nodes'].append({"id": src, "group": 3, "label": src})
                data['links'].append({"source": email, "target": src, "value": 1})

            # 3. Attack Surface Score Calculation
            self._add_harvest_log(target, "[+] Calculating Attack Surface Score...")
            exposure_score = len(leaks) * 15 + len(data['sensitive_files']) * 10
            self.harvest_results[target]['score'] = min(exposure_score, 100)
            
            self._add_harvest_log(target, f"[!] Harvest Complete. Score: {self.harvest_results[target]['score']}/100")
            self.harvest_results[target]['status'] = 'completed'
            
        except Exception as e:
            self._add_harvest_log(target, f"[!] EXCEPTION: {str(e)}")
            self.harvest_results[target]['status'] = 'failed'


    # --- EXPLOIT DATABASE ENGINE ---
    def search_exploits(self, query: str) -> Dict[str, Any]:
        """
        Searches Exploit-DB using searchsploit logic.
        """
        if not query or len(query) < 3:
            return {"success": False, "error": "Query too short"}

        clean_query = shlex.quote(query)
        # searchsploit -j <query>
        cmd = ["searchsploit", "-j", query] # subprocess receives list, so no need to quote if using list but searchsploit might need loose args
        
        # ACTUALLY, searchsploit -j output is a bit messy sometimes. 
        # But let's try standard way.
        
        try:
            # We use shlex split just to be safe if we were using shell=True, but here we use list
            # But query might have spaces.
            cmd = ['searchsploit', '-j'] + query.split()
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                # Fallback: maybe no results found
                return {"success": True, "results": [], "message": "No results found"}
                
            data = json.loads(stdout)
            return {"success": True, "results": data.get("RESULTS_EXPLOIT", [])}
            
        except Exception as e:
            logger.error(f"Exploit search error: {e}")
            return {"success": False, "error": str(e)}

    def mirror_exploit(self, exploit_id: str, workspace_path: str = "./downloads") -> Dict[str, Any]:
        """
        Downloads (mirrors) an exploit by ID to the workspace.
        """
        import os
        if not os.path.exists(workspace_path):
            os.makedirs(workspace_path)
            
        # cmd: searchsploit -m <id>
        cmd = ['searchsploit', '-m', exploit_id]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=workspace_path
            )
            stdout, stderr = process.communicate()
            
            # success check
            if process.returncode == 0:
                return {
                    "success": True, 
                    "message": stdout, 
                    "location": os.path.abspath(workspace_path)
                }
            else:
                return {"success": False, "error": stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- LIVE CVE INTELLIGENCE ---
    def search_live_cve(self, query: str) -> Dict[str, Any]:
        """
        Queries real-time CVE data from CIRCL.lu API.
        """
        if not query or len(query) < 3:
            return {"success": False, "error": "Search query too short"}
            
        try:
            # CIRCL CVE API (Public)
            url = f"https://cve.circl.lu/api/search/{query}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Format for frontend
                results = []
                for item in data.get('results', [])[:20]: # Limit to top 20
                    results.append({
                        "id": item.get('id'),
                        "summary": item.get('summary'),
                        "cvss": item.get('cvss'),
                        "published": item.get('Published'),
                        "last_modified": item.get('Modified'),
                        "references": item.get('references', [])
                    })
                return {"success": True, "results": results}
            else:
                return {"success": False, "error": f"API returned status {response.status_code}"}
        except Exception as e:
            logger.error(f"Live CVE search error: {e}")
            return {"success": False, "error": "Connection to CVE database failed"}

    def deploy_to_codespace(self, codespace_id: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Queues an artifact for deployment to a specific Codespace.
        artifact: {name: str, content: str, type: str}
        """
        if codespace_id not in self.codespace_commands:
            self.codespace_commands[codespace_id] = []
            
        self.codespace_commands[codespace_id].append({
            "type": "deploy",
            "timestamp": datetime.now().isoformat(),
            "payload": artifact
        })
        
        logger.info(f"[*] Artifact '{artifact['name']}' queued for Codespace [{codespace_id}]")
        return {"success": True, "message": f"Deployment queued for {artifact['name']}"}

    def get_codespace_commands(self, codespace_id: str) -> List[Dict[str, Any]]:
        """Retrieve and clear command queue for a codespace"""
        if codespace_id in self.codespace_commands:
            cmds = self.codespace_commands[codespace_id]
            self.codespace_commands[codespace_id] = []
            return cmds
        return []

    def _initialize_campaigns(self) -> Dict[str, Any]:
        """Load tactical campaigns and scenarios."""
        return {
            "techcorp_breach": {
                "id": "techcorp_breach",
                "title": "Operation: TechCorp Breach",
                "difficulty": "Hard",
                "stages": [
                    {"id": "ctf-intern-mistake", "order": 1},
                    {"id": "ctf-login-limbo", "order": 2},
                    {"id": "ctf-ghost-archive", "order": 3},
                    {"id": "ctf-dark-matter-object", "order": 4}
                ],
                "reward_xp": 5000,
                "badge": "Shadow Operative"
            },
            "cloud_assault": {
                "id": "cloud_assault",
                "title": "Project: Cloud Assault",
                "difficulty": "Intermediate",
                "stages": [
                    {"id": "ctf-s3-treasure", "order": 1},
                    {"id": "ctf-lambda-backdoor", "order": 2},
                    {"id": "ctf-ssrf-internal", "order": 3}
                ],
                "reward_xp": 3000,
                "badge": "Cloud Striker"
            }
        }

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        return list(self.campaigns.values())

    def sync_mission_to_codespace(self, codespace_id: str, mission_id: str) -> Dict[str, Any]:
        """Prepare and deploy tactical artifacts for a specific mission."""
        # Mock mission payloads for demonstration
        payloads = {
            "ctf-intern-mistake": {
                "files": [
                    {"name": "intel/target_brief.txt", "content": "Target: intern-landing-page.studyhub.local\nLook for development comments."},
                    {"name": "tools/harvester.py", "content": "#!/usr/bin/env python3\nprint('Gathering info...')"}
                ]
            },
            "ctf-login-limbo": {
                "files": [
                    {"name": "payloads/sqli_wordlist.txt", "content": "' OR 1=1 --\nadmin'--\n' UNION SELECT NULL--"},
                    {"name": "intel/db_schema.md", "content": "# Target Schema\n- users (id, username, password, role)"}
                ]
            },
            "ctf-dark-matter-object": {
                "files": [
                    {"name": "exploits/pickle_payload.py", "content": "import pickle, base64, os\n# Redacted exploitation logic"},
                    {"name": "tools/monitor.sh", "content": "#!/bin/bash\ntail -f /var/log/syslog"}
                ]
            }
        }

        mission_payload = payloads.get(mission_id)
        if not mission_payload:
            return {"success": False, "error": f"Mission {mission_id} payload not found"}

        for file_info in mission_payload['files']:
            self.deploy_to_codespace(codespace_id, {
                "name": file_info["name"],
                "content": file_info["content"],
                "type": "mission_artifact"
            })

        return {
            "success": True, 
            "message": f"Mission {mission_id} tactical artifacts synced successfully",
            "artifact_count": len(mission_payload['files'])
        }

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


    # --- DEEP-JS MINER ---
    def scan_javascript(self, target_url: str) -> Dict[str, Any]:
        """
        Deep scans a target URL for JavaScript files and extracts secrets/endpoints.
        """
        results = {
            "target": target_url,
            "files": [],
            "total_secrets": 0,
            "total_endpoints": 0
        }

        try:
            # 1. Fetch Main Page
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(target_url, headers=headers, timeout=10, verify=False)
            html_content = response.text

            # 2. Extract JS Links
            # Simple regex for <script src="...">
            script_pattern = r'<script[^>]+src=["\'](.*?)["\']'
            js_links = re.findall(script_pattern, html_content)

            # Normalize URLs
            normalized_links = set()
            for link in js_links:
                full_url = urljoin(target_url, link)
                normalized_links.add(full_url)

            # 3. Analyze Each File
            for js_url in normalized_links:
                file_analysis = {
                    "name": js_url.split('/')[-1] or "script.js",
                    "url": js_url,
                    "secrets": [],
                    "endpoints": []
                }

                try:
                    js_resp = requests.get(js_url, headers=headers, timeout=10, verify=False)
                    js_code = js_resp.text

                    # -- Secret Regex Patterns --
                    secret_patterns = {
                        "Google API": r'AIza[0-9A-Za-z\-_]{35}',
                        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
                        "AWS Secret": r'[0-9a-zA-Z/+]{40}', # High false positive risk, handled carefully? Keeping simple for now. 
                        # Using safer context for generic secrets:
                        "Generic Secret/Key": r'(?:key|secret|token|password|auth)[a-z0-9_.\-]*\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']',
                        "JWT Token": r'eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+',
                        "Firebase": r'[a-z0-9.-]+\.firebaseio\.com',
                        "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
                    }

                    for name, pattern in secret_patterns.items():
                        matches = re.finditer(pattern, js_code, re.IGNORECASE)
                        for match in matches:
                            val = match.group(0)
                            # Basic filtering to avoid common false positives (like simple words)
                            if len(val) > 8: 
                                file_analysis["secrets"].append({
                                    "type": name,
                                    "value": val[:5] + "..." + val[-5:] if len(val) > 15 else val, # Mask slightly for display but keep identifiable
                                    "full_value": val, 
                                    "severity": "High" if "AWS" in name or "Private" in name else "Medium"
                                })

                    # -- Endpoint Regex Pattern --
                    # Looks for strings starting with / that resemble paths, e.g., "/api/v1/user"
                    # Ref: https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py (Simplified)
                    endpoint_pattern = r'(?:"|\')(((?:/|[a-zA-Z0-9-_]+\?)[a-zA-Z0-9_?=&/\-%]+))(?:"|\')'
                    
                    endpoint_matches = re.finditer(endpoint_pattern, js_code)
                    found_eps = set()
                    for match in endpoint_matches:
                        ep = match.group(1)
                        if len(ep) > 2 and not ep.startswith('//') and ' ' not in ep:
                             found_eps.add(ep)
                    
                    file_analysis["endpoints"] = list(found_eps)

                    # Update Counts
                    results["total_secrets"] += len(file_analysis["secrets"])
                    results["total_endpoints"] += len(file_analysis["endpoints"])
                    
                    results["files"].append(file_analysis)

                except Exception as e:
                    logger.error(f"Error scanning JS file {js_url}: {e}")
                    file_analysis["error"] = str(e)
                    results["files"].append(file_analysis)

            return {"success": True, "data": results}

        except Exception as e:
            logger.error(f"Deep-JS Miner failed: {e}")
            return {"success": False, "error": str(e)}


    # --- THE HASH REFINERY ENGINE ---
    def detect_hash_type(self, hash_value: str) -> Dict[str, Any]:
        """Detects hash type based on length and patterns."""
        hash_value = hash_value.strip()
        patterns = [
            {"name": "MD5", "regex": r"^[a-f0-9]{32}$", "hashcat": 0, "john": "raw-md5"},
            {"name": "SHA-1", "regex": r"^[a-f0-9]{40}$", "hashcat": 100, "john": "raw-sha1"},
            {"name": "SHA-256", "regex": r"^[a-f0-9]{64}$", "hashcat": 1400, "john": "raw-sha256"},
            {"name": "NTLM", "regex": r"^[a-f0-9]{32}$", "hashcat": 1000, "john": "nt"},
            {"name": "bcrypt", "regex": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "hashcat": 3200, "john": "bcrypt"}
        ]
        
        matches = []
        for p in patterns:
            if re.match(p["regex"], hash_value, re.IGNORECASE):
                matches.append(p)
        
        return {"success": True, "matches": matches if matches else [{"name": "Unknown", "hashcat": -1, "john": "unknown"}]}

    def start_crack(self, hash_value: str, hash_type: str = "auto", wordlist: str = "rockyou.txt") -> Dict[str, Any]:
        """Starts an asynchronous cracking task."""
        import uuid
        task_id = str(uuid.uuid4())[:8]
        
        self.crack_results[task_id] = {
            "status": "running",
            "hash": hash_value,
            "type": hash_type,
            "wordlist": wordlist,
            "progress": 0,
            "speed": 0,
            "logs": ["[*] Initializing Hash Refinery Engine...", f"[*] Input: {hash_value[:10]}..."],
            "cracked_pass": None,
            "start_time": datetime.utcnow().isoformat()
        }
        
        thread = threading.Thread(target=self._crack_task, args=(task_id, hash_value, wordlist))
        thread.daemon = True
        thread.start()
        
        return {"success": True, "task_id": task_id}

    def get_crack_status(self, task_id: str) -> Dict[str, Any]:
        """Returns the current status of a cracking task."""
        return {"success": True, "data": self.crack_results.get(task_id, {"status": "not_found"})}

    def _add_crack_log(self, task_id: str, msg: str):
        if task_id in self.crack_results:
            self.crack_results[task_id]['logs'].append(msg)

    def _crack_task(self, task_id: str, hash_value: str, wordlist: str):
        """Worker thread for password cracking simulation."""
        try:
            # 1. Initialization
            self._add_crack_log(task_id, f"[+] Loading refinery patterns for {wordlist}...")
            time.sleep(1)
            
            # 2. Simulated Cracking Loop
            total_steps = 10
            base_speed = 450000 # hashes/sec
            
            for i in range(1, total_steps + 1):
                if task_id not in self.crack_results: break # Task was cleared
                
                progress = i * 10
                speed = base_speed + (i * 15000) # Fluctuate speed
                
                self.crack_results[task_id]['progress'] = progress
                self.crack_results[task_id]['speed'] = speed
                
                if i == 3:
                    self._add_crack_log(task_id, "[*] Wordlist half-way mark reached. Adjusting entropy...")
                if i == 7:
                    self._add_crack_log(task_id, "[*] Analyzing hash salt components...")

                time.sleep(1) # Simulated delay per step
                
            # 3. Completion / Success
            # Mock success for common hashes
            demo_hashes = {
                "5f4dcc3b5aa765d61d8327deb882cf99": "password",
                "e10adc3949ba59abbe56e057f20f883e": "123456",
                "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password"
            }
            
            cracked = demo_hashes.get(hash_value.strip(), "cracked_pass_123")
            
            self.crack_results[task_id]['cracked_pass'] = cracked
            self.crack_results[task_id]['progress'] = 100
            self.crack_results[task_id]['status'] = "completed"
            self._add_crack_log(task_id, f"[!] REFINING SUCCESSFUL: Password found!")
            self._add_crack_log(task_id, f"[!] Result: {cracked}")
            
        except Exception as e:
            self._add_crack_log(task_id, f"[!] REFINERY FAILURE: {str(e)}")
            self.crack_results[task_id]['status'] = "failed"

    # --- SUBDOMAIN MONITOR (THE SILENT OBSERVER) ---
    def start_subdomain_monitor(self, domain: str, project_id: str = None) -> Dict[str, Any]:
        """
        Starts automated monitoring for a domain.
        """
        if domain in self.subdomain_monitors:
            return {"success": False, "message": "Monitoring already active for this domain"}
            
        self.subdomain_monitors[domain] = {
            "status": "active",
            "interval": 24, # hours
            "last_run": datetime.now().isoformat(),
            "logs": [f"[*] Monitoring initialized for {domain}"],
            "project_id": project_id
        }
        
        self.subdomain_inventory[domain] = []
        
        # Start immediate scan
        thread = threading.Thread(target=self._subdomain_monitor_worker, args=(domain, project_id))
        thread.daemon = True
        thread.start()
        
        return {"success": True, "message": f"Observation mission started for {domain}"}

    def _subdomain_monitor_worker(self, domain: str, project_id: str = None):
        """
        Background worker for subdomain enumeration and diffing.
        """
        try:
            # 1. Simulate Enumeration (Aggregate from Subfinder, Amass, etc.)
            self.subdomain_monitors[domain]['logs'].append("[+] Running high-precision enumeration...")
            time.sleep(2)
            
            # Simulated results
            potential_subs = [f"www.{domain}", f"api.{domain}", f"dev.{domain}", f"staging.{domain}", f"vpn.{domain}", f"mail.{domain}"]
            
            # 2. Differential Analysis
            current_inv = self.subdomain_inventory.get(domain, [])
            new_assets = []
            
            for sub in potential_subs:
                if sub not in [s['name'] for s in current_inv]:
                    asset = {
                        "name": sub,
                        "ip": f"104.26.{random.randint(0,255)}.{random.randint(1,254)}",
                        "detected_at": datetime.now().isoformat(),
                        "is_new": True
                    }
                    new_assets.append(asset)
                    current_inv.append(asset)
                    
                    # Log to project if available
                    if project_id:
                        self.log_to_project(project_id, 'subdomains', sub)
            
            self.subdomain_inventory[domain] = current_inv
            self.subdomain_monitors[domain]['logs'].append(f"[!] Cycle complete. Found {len(new_assets)} new assets.")
            self.subdomain_monitors[domain]['last_run'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Subdomain monitor error: {e}")
            if domain in self.subdomain_monitors:
                self.subdomain_monitors[domain]['status'] = "failed"

    def get_all_monitors(self) -> Dict[str, Any]:
        return {"success": True, "monitors": self.subdomain_monitors}

    def get_subdomain_results(self, domain: str) -> Dict[str, Any]:
        return {"success": True, "inventory": self.subdomain_inventory.get(domain, [])}

    # --- VISUAL MAPPER ENGINE ---
    def start_visual_map(self, domain: str, project_id: str = None) -> Dict[str, Any]:
        """
        Starts a background scan to map the domain infrastructure.
        """
        if not domain:
            return {"success": False, "error": "Domain is required"}
            
        self.visual_maps[domain] = {
            "status": "scanning",
            "nodes": [],
            "links": [],
            "last_updated": datetime.now().isoformat(),
            "project_id": project_id
        }
        
        thread = threading.Thread(target=self._visual_map_worker, args=(domain, project_id))
        thread.daemon = True
        thread.start()
        
        return {"success": True, "message": f"Visual mapping started for {domain}"}

    def _visual_map_worker(self, domain: str, project_id: str = None):
        """
        Background worker for infrastructure mapping.
        """
        try:
            # 1. Resolve domain to IP (Simulated)
            base_ip = f"104.26.{random.randint(0,255)}.{random.randint(1,254)}"
            
            nodes = [
                {"id": domain, "label": domain, "type": "domain", "group": 1},
                {"id": base_ip, "label": base_ip, "type": "ip", "group": 2}
            ]
            links = [{"source": domain, "target": base_ip}]
            
            # 2. Simulate Technology Fingerprinting (WhatWeb)
            techs = ["Cloudflare", "Nginx", "React", "HSTS", "WAF"]
            for tech in techs:
                tech_id = f"tech_{tech}"
                nodes.append({"id": tech_id, "label": tech, "type": "tech", "group": 3})
                links.append({"source": base_ip, "target": tech_id})
                
            # 3. Add some subdomains (Simulated)
            subs = ["api", "dev", "staging", "blog"]
            for sub in subs:
                sub_domain = f"{sub}.{domain}"
                sub_ip = f"104.26.{random.randint(0,255)}.{random.randint(1,254)}"
                
                nodes.append({"id": sub_domain, "label": sub_domain, "type": "subdomain", "group": 4})
                nodes.append({"id": sub_ip, "label": sub_ip, "type": "ip", "group": 2})
                
                links.append({"source": domain, "target": sub_domain})
                links.append({"source": sub_domain, "target": sub_ip})
                
                # Tech for subdomains
                nodes.append({"id": f"{sub}_tech", "label": "Node.js" if sub=="api" else "Apache", "type": "tech", "group": 3})
                links.append({"source": sub_ip, "target": f"{sub}_tech"})

            time.sleep(3) # Mapping time
            
            self.visual_maps[domain]["nodes"] = nodes
            self.visual_maps[domain]["links"] = links
            self.visual_maps[domain]["status"] = "completed"
            self.visual_maps[domain]["last_updated"] = datetime.now().isoformat()
            
            if project_id:
                self.log_to_project(project_id, 'visual_maps', self.visual_maps[domain])
            
        except Exception as e:
            logger.error(f"Visual map error: {e}")
            if domain in self.visual_maps:
                self.visual_maps[domain]["status"] = "failed"

    def get_visual_map(self, domain: str) -> Dict[str, Any]:
        """
        Returns the graph data for a domain.
        """
        return {"success": True, "data": self.visual_maps.get(domain, {})}

    # --- FUZZING COCKPIT ENGINE ---
    def start_fuzz(self, url: str, wordlist: str = "common.txt", filters: List[int] = [404], project_id: str = None) -> Dict[str, Any]:
        """
        Starts a high-speed fuzzing operation.
        """
        if "FUZZ" not in url:
            return {"success": False, "error": "URL must contain the placeholder 'FUZZ'"}
            
        task_id = f"fuzz_{int(time.time())}"
        self.fuzz_results[task_id] = {
            "status": "running",
            "url": url,
            "wordlist": wordlist,
            "filters": filters,
            "results": [],
            "total_requests": 0,
            "speed": 0,
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "project_id": project_id
        }
        
        thread = threading.Thread(target=self._fuzz_worker, args=(task_id, url, wordlist, filters, project_id))
        thread.daemon = True
        thread.start()
        
        return {"success": True, "task_id": task_id}

    def _fuzz_worker(self, task_id: str, url: str, wordlist: str, filters: List[int], project_id: str = None):
        """
        Background worker for high-speed fuzzing simulation.
        """
        try:
            # Simulated payloads based on common wordlists
            payloads = ["admin", "login", "config", "backup", "db", "api", "v1", "test", "dev", "staging", ".env", ".git"]
            total = len(payloads)
            
            for i, payload in enumerate(payloads):
                if task_id not in self.fuzz_results or self.fuzz_results[task_id]['status'] != 'running':
                    break
                    
                target_url = url.replace("FUZZ", payload)
                
                # Simulated status codes
                status_code = random.choice([200, 301, 302, 401, 403, 404, 500])
                
                # Check filters
                if status_code not in filters:
                    hit = {
                        "id": i,
                        "payload": payload,
                        "status": status_code,
                        "size": random.randint(100, 5000),
                        "time": random.randint(10, 200),
                        "url": target_url
                    }
                    self.fuzz_results[task_id]['results'].append(hit)
                    if project_id:
                        self.log_to_project(project_id, 'fuzzing', hit)
                
                # Update stats
                self.fuzz_results[task_id]['total_requests'] += 1
                self.fuzz_results[task_id]['progress'] = int(((i + 1) / total) * 100)
                self.fuzz_results[task_id]['speed'] = random.randint(50, 150) # Requests/sec
                
                time.sleep(0.5) # Simulate processing time
                
            if task_id in self.fuzz_results:
                self.fuzz_results[task_id]['status'] = "completed"
                
        except Exception as e:
            logger.error(f"Fuzzing worker error: {e}")
            if task_id in self.fuzz_results:
                self.fuzz_results[task_id]['status'] = "failed"

    def get_fuzz_status(self, task_id: str) -> Dict[str, Any]:
        """
        Returns the current progress and results of a fuzzing task.
        """
        return {"success": True, "data": self.fuzz_results.get(task_id, {})}

    # --- PROJECT TRACKER (THE JOKER) ENGINE ---
    def create_project(self, name: str, target: str, objective: str = "") -> Dict[str, Any]:
        """
        Creates a new tactical workspace.
        """
        project_id = f"proj_{int(time.time())}"
        self.projects[project_id] = {
            "id": project_id,
            "name": name,
            "target": target,
            "objective": objective,
            "created_at": datetime.now().isoformat(),
            "data": {
                "subdomains": [],
                "fuzzing": [],
                "visual_maps": [],
                "findings": []
            }
        }
        return {"success": True, "project_id": project_id, "message": f"Project '{name}' initialized."}

    def get_projects(self) -> Dict[str, Any]:
        """
        Lists all available workspaces.
        """
        return {"success": True, "projects": list(self.projects.values())}

    def get_project_data(self, project_id: str) -> Dict[str, Any]:
        """
        Returns all intelligence gathered for a specific project.
        """
        return {"success": True, "data": self.projects.get(project_id, {})}

    def log_to_project(self, project_id: str, category: str, item: Any):
        """
        Internal helper to correlate tool results with a project.
        """
        if project_id in self.projects:
            if category in self.projects[project_id]['data']:
                self.projects[project_id]['data'][category].append(item)
                return True
        return False

    def generate_project_report(self, project_id: str) -> Dict[str, Any]:
        """
        Compiles a tactical briefing for the mission.
        """
        if project_id not in self.projects:
            return {"success": False, "error": "Project not found"}
            
        proj = self.projects[project_id]
        report = f"# TACTICAL MISSION REPORT: {proj['name']}\n"
        report += f"**Target:** {proj['target']}\n"
        report += f"**Objective:** {proj['objective']}\n"
        report += f"**Created:** {proj['created_at']}\n\n"
        
        report += "## 1. INFRASTRUCTURE & DISCOVERY\n"
        report += f"- Subdomains Identified: {len(proj['data']['subdomains'])}\n"
        for sub in proj['data']['subdomains'][:10]:
            report += f"  - {sub}\n"
            
        report += "\n## 2. FUZZING & ATTACK SURFACE\n"
        report += f"- Significant Hits: {len(proj['data']['fuzzing'])}\n"
        for hit in proj['data']['fuzzing'][:10]:
            report += f"  - [/{hit.get('payload')}] (Status: {hit.get('status')})\n"
            
        report += "\n## 3. MANUAL FINDINGS\n"
        if not proj['data']['findings']:
            report += "- No manual findings logged yet.\n"
        else:
            for f in proj['data']['findings']:
                report += f"- **{f['title']}**: {f['desc']}\n"
                
        return {"success": True, "report": report}


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

    @app.route('/api/tools/harvest/start', methods=['POST'])
    def harvest_start():
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'}), 400
        return jsonify(tools.start_harvest(target))

    @app.route('/api/tools/harvest/status', methods=['POST'])
    def harvest_status():
        data = request.json
        target = data.get('target')
        if not target:
            return jsonify({'success': False, 'error': 'No target specified'}), 400
        return jsonify(tools.get_harvest_status(target))

    @app.route('/api/tools/hash/detect', methods=['POST'])
    def hash_detect():
        data = request.json
        hash_val = data.get('hash')
        if not hash_val:
            return jsonify({'success': False, 'error': 'No hash provided'}), 400
        return jsonify(tools.detect_hash_type(hash_val))

    @app.route('/api/tools/crack/start', methods=['POST'])
    def crack_start():
        data = request.json
        hash_val = data.get('hash')
        wordlist = data.get('wordlist', 'rockyou.txt')
        if not hash_val:
            return jsonify({'success': False, 'error': 'No hash provided'}), 400
        return jsonify(tools.start_crack(hash_val, wordlist=wordlist))

        return jsonify(tools.get_crack_status(task_id))

    @app.route('/api/tools/subdomain/add', methods=['POST'])
    def subdomain_add():
        data = request.json
        domain = data.get('domain')
        project_id = data.get('project_id')
        if not domain:
            return jsonify({'success': False, 'error': 'No domain specified'}), 400
        return jsonify(tools.start_subdomain_monitor(domain, project_id))

    @app.route('/api/tools/subdomain/status', methods=['GET'])
    def subdomain_status_all():
        return jsonify(tools.get_all_monitors())

    @app.route('/api/tools/subdomain/results/<domain>', methods=['GET'])
    def subdomain_results(domain):
        return jsonify(tools.get_subdomain_results(domain))

    @app.route('/api/tools/visual/start', methods=['POST'])
    def visual_start():
        data = request.json
        domain = data.get('domain')
        project_id = data.get('project_id')
        return jsonify(tools.start_visual_map(domain, project_id))

    @app.route('/api/tools/visual/data/<domain>', methods=['GET'])
    def visual_data(domain):
        return jsonify(tools.get_visual_map(domain))

    @app.route('/api/tools/fuzz/start', methods=['POST'])
    def fuzz_start():
        data = request.json
        url = data.get('url')
        wordlist = data.get('wordlist', 'common.txt')
        filters = data.get('filters', [404])
        project_id = data.get('project_id')
        return jsonify(tools.start_fuzz(url, wordlist, filters, project_id))

    @app.route('/api/tools/fuzz/status/<task_id>', methods=['GET'])
    def fuzz_status(task_id):
        return jsonify(tools.get_fuzz_status(task_id))

    @app.route('/api/projects/create', methods=['POST'])
    def project_create():
        data = request.json
        name = data.get('name')
        target = data.get('target')
        objective = data.get('objective', '')
        if not name or not target:
            return jsonify({'success': False, 'error': 'Name and Target are required'}), 400
        return jsonify(tools.create_project(name, target, objective))

    @app.route('/api/projects/list', methods=['GET'])
    def project_list():
        return jsonify(tools.get_projects())

    @app.route('/api/projects/data/<project_id>', methods=['GET'])
    def project_data(project_id):
        return jsonify(tools.get_project_data(project_id))

    @app.route('/api/projects/report/<project_id>', methods=['GET'])
    def project_report(project_id):
        return jsonify(tools.generate_project_report(project_id))

    @app.route('/api/projects/log', methods=['POST'])
    def project_log():
        data = request.json
        project_id = data.get('project_id')
        category = data.get('category')
        item = data.get('item')
        if tools.log_to_project(project_id, category, item):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Project not found or invalid category'}), 400

    logger.info("✓ Pro Tools API routes registered")
