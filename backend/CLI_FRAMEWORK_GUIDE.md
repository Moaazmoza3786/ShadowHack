# 🔥 SHADOWHACK ELITE CLI FRAMEWORK - COMPLETE GUIDE

## Overview

The ShadowHack Elite CLI Framework is a **professional-grade command-line penetration testing tool** designed for advanced security professionals. It provides:

- **Plugin Ecosystem**: Extensible architecture for custom tools
- **Workflow Engine**: Automated penetration testing workflows
- **Tool Orchestration**: Unified interface for multiple security tools
- **Real-time Integration**: Synchronize findings across tools
- **Professional Reporting**: Auto-generate comprehensive reports

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture](#architecture)
3. [CLI Commands](#cli-commands)
4. [Plugin Development](#plugin-development)
5. [Workflow Execution](#workflow-execution)
6. [API Integration](#api-integration)
7. [Advanced Features](#advanced-features)
8. [Best Practices](#best-practices)

---

## Quick Start

### Installation

```bash
# Clone or download the framework
cd backend

# Install required dependencies
pip install -r requirements.txt

# Optional dependencies
pip install pyyaml colorama click requests
```

### Basic Usage

```bash
# List available tools
python cli_pentester_framework.py list-tools

# List loaded plugins
python cli_pentester_framework.py list-plugins

# Run a workflow
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m sequential

# Generate report
python cli_pentester_framework.py generate-report report.json -f json
```

---

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     ShadowHack Elite CLI                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  CLI Interface Layer                      │  │
│  │  • Argument Parsing                                       │  │
│  │  • Command Dispatch                                       │  │
│  │  • Output Formatting                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Workflow Engine                              │  │
│  │  • Sequential Execution                                   │  │
│  │  • Parallel Execution                                     │  │
│  │  • Interactive Mode                                       │  │
│  │  • Dependency Resolution                                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────┬──────────────────────────────────────┐  │
│  │  Plugin Manager     │       Tool Manager                    │  │
│  │  • Load Plugins     │  • Register Tools                     │  │
│  │  • Execute Plugins  │  • Execute Tools                      │  │
│  │  • Manage Hooks     │  • Capture Output                     │  │
│  └─────────────────────┴──────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │            Report & Finding Management                    │  │
│  │  • Finding Storage                                        │  │
│  │  • Report Generation (JSON/HTML)                          │  │
│  │  • Export & Sharing                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

                            ↓

    ┌──────────────────────────────────────────┐
    │      External Tools & Plugins            │
    ├──────────────────────────────────────────┤
    │  • Nmap       • Burp Suite               │
    │  • Metasploit • OWASP ZAP                │
    │  • Custom     • Third-party              │
    └──────────────────────────────────────────┘
```

### Class Hierarchy

- **Plugin**: Abstract base class for all plugins
- **ToolManager**: Manages external tool registration and execution
- **PluginManager**: Manages plugin lifecycle
- **WorkflowEngine**: Orchestrates penetration testing workflows
- **ReportGenerator**: Creates professional reports
- **ShadowHackCLI**: Main CLI application
- **Logger**: Advanced logging system with colored output

---

## CLI Commands

### 1. run-workflow

Execute a penetration testing workflow.

```bash
python cli_pentester_framework.py run-workflow <workflow_file> [options]
```

**Options:**
- `-m, --mode`: Execution mode (sequential/parallel/interactive)
- `--dry-run`: Perform dry run without actual execution

**Example:**
```bash
# Run web app test workflow sequentially
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m sequential

# Interactive mode with user confirmation
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m interactive

# Dry run to preview
python cli_pentester_framework.py run-workflow pentester_workflows.yaml --dry-run
```

### 2. list-tools

List all registered tools.

```bash
python cli_pentester_framework.py list-tools
```

**Output:**
```
Available Tools:
  • nmap - 7.93
  • curl - 7.x
  • python - 3.x
```

### 3. list-plugins

List all loaded plugins with capabilities.

```bash
python cli_pentester_framework.py list-plugins
```

**Output:**
```
Loaded Plugins:
  • NetworkRecon v1.0.0
    - host_discovery
    - port_scanning
    - service_enumeration
  • WebVulnScanner v1.0.0
    - web_scanning
    - sql_injection_detection
```

### 4. generate-report

Generate a penetration testing report.

```bash
python cli_pentester_framework.py generate-report <output_file> [options]
```

**Options:**
- `-f, --format`: Report format (json/html)

**Example:**
```bash
# Generate JSON report
python cli_pentester_framework.py generate-report report.json -f json

# Generate HTML report
python cli_pentester_framework.py generate-report report.html -f html
```

---

## Plugin Development

### Creating a Custom Plugin

```python
from cli_pentester_framework import Plugin, Finding, SeverityLevel
from typing import Dict, List, Any

class MyCustomPlugin(Plugin):
    """Custom security plugin"""
    
    def __init__(self):
        super().__init__("MyCustomPlugin", version="1.0.0")
        self.metadata = {
            "author": "Your Name",
            "description": "What your plugin does",
            "category": "reconnaissance",  # or other category
            "tags": ["tag1", "tag2"]
        }
    
    def initialize(self):
        """Initialize the plugin"""
        self.enabled = True
        print(f"[*] Initializing {self.name} plugin...")
    
    def validate(self) -> bool:
        """Validate plugin dependencies"""
        # Check if required tools are available
        import subprocess
        try:
            result = subprocess.run(
                ["tool-name", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_capabilities(self) -> List[str]:
        """Return list of capabilities"""
        return [
            "capability1",
            "capability2",
            "capability3"
        ]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the plugin"""
        target = kwargs.get("target")
        
        # Your implementation here
        findings = []
        
        return {
            "success": True,
            "target": target,
            "findings": findings
        }
```

### Installing a Plugin

1. Create your plugin file in the `plugins/` directory
2. Plugin is automatically loaded on startup

```bash
# Create plugin file
cp my_plugin.py plugins/my_plugin.py

# Verify loading
python cli_pentester_framework.py list-plugins
```

### Plugin Hooks

Plugins can register hooks for various events:

```python
from cli_pentester_framework import PluginManager

pm = PluginManager()

# Register hooks
pm.register_hook("before_execution", my_callback)
pm.register_hook("after_execution", my_callback)
pm.register_hook("on_finding", my_callback)
pm.register_hook("on_error", my_callback)
```

---

## Workflow Execution

### Workflow File Format (YAML)

```yaml
name: "My Penetration Test"
version: "1.0"
description: "Comprehensive security assessment"
target_type: "web"

steps:
  - name: "Step Name"
    tool: "tool-name"
    args: ["--arg1", "value1", "${TARGET}"]
    description: "What this step does"
    depends_on: []  # Other steps this depends on
    timeout: 300
    critical: true  # Fail entire workflow if this fails
    parallel: true  # Can run in parallel with other steps
    capture_output: true
```

### Execution Modes

#### 1. Sequential Mode
Steps execute one after another.

```bash
python cli_pentester_framework.py run-workflow workflow.yaml -m sequential
```

**Use Case:** When steps depend on previous results.

#### 2. Parallel Mode
Independent steps execute simultaneously.

```bash
python cli_pentester_framework.py run-workflow workflow.yaml -m parallel
```

**Use Case:** Speed up testing when steps are independent.

#### 3. Interactive Mode
User confirms each step before execution.

```bash
python cli_pentester_framework.py run-workflow workflow.yaml -m interactive
```

**Use Case:** Manual testing with user control.

### Workflow Variables

```yaml
steps:
  - name: "Scan Target"
    tool: "nmap"
    args: ["-sV", "${TARGET}"]  # Replaced with actual target
    env:
      TIMEOUT: "${TIMEOUT}"
      SCAN_TYPE: "${SCAN_TYPE}"
```

Environment variables can be set:

```bash
export TARGET="example.com"
export TIMEOUT="600"
export SCAN_TYPE="full"
```

---

## API Integration

### Flask Integration

```python
from flask import Flask
from cli_integration import register_cli_routes

app = Flask(__name__)

# Register CLI routes
register_cli_routes(app)

app.run(debug=True)
```

### REST API Endpoints

#### Start Workflow
```
POST /api/cli/workflows/start
Content-Type: application/json

{
  "workflow_file": "pentester_workflows.yaml",
  "mode": "sequential",
  "dry_run": false
}
```

#### Check Workflow Status
```
GET /api/cli/workflows/{workflow_id}/status
```

#### List Active Workflows
```
GET /api/cli/workflows
```

#### Execute Plugin
```
POST /api/cli/plugins/{plugin_name}/execute
Content-Type: application/json

{
  "args": {
    "target": "example.com",
    "scan_type": "full"
  }
}
```

#### Add Finding
```
POST /api/cli/findings
Content-Type: application/json

{
  "title": "SQL Injection",
  "severity": "critical",
  "description": "Finding description",
  "location": "Parameter: id",
  "remediation": "Use parameterized queries",
  "cvss_score": 9.8
}
```

#### Get All Findings
```
GET /api/cli/findings
```

#### Generate Report
```
POST /api/cli/reports/generate
Content-Type: application/json

{
  "format": "json"
}
```

---

## Advanced Features

### 1. Custom Tool Integration

```python
from cli_pentester_framework import ToolConfig, ToolManager

tm = ToolManager()

# Register custom tool
tool_config = ToolConfig(
    name="burp",
    version="2024.1",
    path="/path/to/burpsuite",
    args=["--headless"],
    timeout=3600,
    required=True,
    parallel=False
)

tm.register_tool(tool_config)

# Execute tool
result = tm.execute_tool("burp", ["--target", "example.com"])
```

### 2. Finding Management

```python
from cli_pentester_framework import Finding, SeverityLevel

finding = Finding(
    title="Cross-Site Scripting",
    severity=SeverityLevel.HIGH,
    description="XSS vulnerability in search parameter",
    location="/search.php?q=",
    remediation="Use output encoding",
    evidence='<img src=x onerror="alert(1)">',
    impact="Session hijacking, data theft",
    cvss_score=6.1
)

workflow_engine.add_finding(finding)
```

### 3. Real-time Monitoring

```python
# Subscribe to workflow updates
from cli_integration import workflow_monitor

def on_workflow_update(message):
    print(f"Update: {message}")

workflow_monitor.subscribe("workflow_id", on_workflow_update)
```

### 4. Advanced Reporting

```python
# Generate multiple report formats
cli.generate_report("report.json", "json")
cli.generate_report("report.html", "html")

# Access findings programmatically
findings = workflow_engine.findings
for finding in findings:
    print(f"{finding.title} ({finding.severity.value})")
```

---

## Best Practices

### 1. Workflow Design

✅ **Good:**
```yaml
steps:
  # Phase 1: Reconnaissance
  - name: "Discovery"
    critical: true
  - name: "Enumeration"
    depends_on: ["Discovery"]
  
  # Phase 2: Scanning (can be parallel)
  - name: "Port Scan"
    parallel: true
  - name: "Service Scan"
    parallel: true
```

❌ **Avoid:**
```yaml
steps:
  - name: "Everything"
    timeout: 99999  # Too long
    critical: true  # Everything critical?
```

### 2. Plugin Development

✅ **Good:**
- Validate dependencies in `validate()`
- Clear error messages
- Return structured data
- Document capabilities

❌ **Avoid:**
- Hardcoded paths
- Silent failures
- Unstructured output
- No timeout limits

### 3. Error Handling

```python
try:
    result = workflow_engine.execute_workflow(steps)
except Exception as e:
    logger.error(f"Workflow failed: {str(e)}")
    # Handle gracefully
```

### 4. Tool Integration

```python
# Set environment variables
config = ToolConfig(
    name="tool",
    env={
        "PROXY": "http://proxy:8080",
        "TIMEOUT": "300"
    }
)

# Use timeouts
result = tool_manager.execute_tool("tool", args, timeout=300)
```

### 5. Reporting

```python
# Always include metadata
metadata = {
    "target": "example.com",
    "engagement_type": "web-app",
    "tester": "Security Team",
    "engagement_dates": "2024-03-01 to 2024-03-15"
}

cli.generate_report("report.html", "html", metadata)
```

---

## Examples

### Example 1: Quick Web App Test

```bash
# Run web application test
python cli_pentester_framework.py run-workflow pentester_workflows.yaml \
  -m sequential \
  --dry-run

# If dry run looks good, execute
python cli_pentester_framework.py run-workflow pentester_workflows.yaml \
  -m sequential
```

### Example 2: Network Penetration Test

```bash
# Load plugins
python cli_pentester_framework.py list-plugins

# Execute network workflow
python cli_pentester_framework.py run-workflow network_test.yaml \
  -m parallel

# View findings
curl http://localhost:5000/api/cli/findings

# Generate report
curl -X POST http://localhost:5000/api/cli/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

### Example 3: Custom Plugin Execution

```python
import sys
sys.path.insert(0, 'backend')

from cli_pentester_framework import ShadowHackCLI

cli = ShadowHackCLI()

# Load plugin
cli.plugin_manager.load_plugin('plugins/my_plugin.py')

# Execute plugin
result = cli.plugin_manager.execute_plugin(
    "MyPlugin",
    target="example.com",
    scan_type="aggressive"
)

print(result)
```

---

## Troubleshooting

### Issue: "Plugin validation failed"
**Solution:** Ensure required tools are installed and in PATH.

### Issue: "Tool not found"
**Solution:** Register tool with correct path before use.

### Issue: "Workflow timeout"
**Solution:** Increase timeout in workflow step or tool config.

### Issue: "No findings"
**Solution:** Check if detection is working; review tool output.

---

## Support & Community

For issues, features, or contributions:
- Check existing workflows in `pentester_workflows.yaml`
- Review plugin examples in `plugins_collection.py`
- Refer to API integration in `cli_integration.py`

---

## License & Attribution

ShadowHack Elite CLI Framework
Part of the ShadowHack Penetration Testing Platform

---

**Status:** ✅ Production Ready

**Last Updated:** 2024-03-29

**Version:** 1.0.0
