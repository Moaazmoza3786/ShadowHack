# 🚀 SHADOWHACK ELITE CLI - INTEGRATION & DEPLOYMENT GUIDE

## Complete Integration with ShadowHack Backend

This guide explains how to fully integrate the CLI framework with the ShadowHack Flask backend, create a powerful pentesting toolkit, and extend it with custom tools and plugins.

---

## 📋 Table of Contents

1. [Integration Overview](#integration-overview)
2. [Setup & Installation](#setup--installation)
3. [Backend Integration](#backend-integration)
4. [CLI Command Examples](#cli-command-examples)
5. [Workflow Scenarios](#workflow-scenarios)
6. [Plugin Ecosystem](#plugin-ecosystem)
7. [Advanced Integration](#advanced-integration)
8. [Deployment](#deployment)

---

## Integration Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   ShadowHack Platform                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  React Frontend  │         │  Flask Backend   │         │
│  │  (Web UI)        │         │  (REST API)      │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
│           │                            │                    │
│           └────────────┬───────────────┘                    │
│                        │                                    │
│          ┌─────────────▼──────────────┐                    │
│          │   CLI Integration Layer    │                    │
│          │  (cli_integration.py)      │                    │
│          └─────────────┬──────────────┘                    │
│                        │                                    │
│          ┌─────────────▼──────────────┐                    │
│          │  ShadowHack Elite CLI      │                    │
│          │  - Workflow Engine         │                    │
│          │  - Plugin Manager          │                    │
│          │  - Tool Manager            │                    │
│          │  - Report Generator        │                    │
│          └─────────────┬──────────────┘                    │
│                        │                                    │
│          ┌─────────────▼──────────────────────────┐        │
│          │  External Tools & Plugins              │        │
│          │  - Nmap, Burp, ZAP, Metasploit        │        │
│          │  - Custom Security Tools               │        │
│          │  - Community Plugins                   │        │
│          └──────────────────────────────────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Setup & Installation

### Step 1: Prerequisites

```bash
# Ensure Python 3.8+ is installed
python --version

# Clone/navigate to project
cd C:\Users\mmoza\Desktop\Study-hub3
cd backend
```

### Step 2: Install Dependencies

```bash
# Install CLI framework dependencies
pip install -r cli_requirements.txt

# Install core ShadowHack dependencies
pip install -r requirements.txt
```

### Step 3: Verify Installation

```bash
# Test CLI framework
python cli_pentester_framework.py list-tools

# Expected output:
# Available Tools:
#   • nmap - 7.93
#   • curl - 7.x
#   • python - 3.x
```

---

## Backend Integration

### Step 1: Update Flask App

Modify `main.py` to include CLI routes:

```python
# In backend/main.py

from cli_integration import register_cli_routes

# After app initialization
app = Flask(__name__)

# ... existing app setup ...

# Register CLI routes
register_cli_routes(app)

# ... rest of routes ...
```

### Step 2: Create CLI Endpoints

The CLI integration automatically provides these endpoints:

```
GET  /api/cli/health                    # Health check
GET  /api/cli/tools                     # List tools
GET  /api/cli/plugins                   # List plugins
POST /api/cli/workflows/start            # Start workflow
GET  /api/cli/workflows/<id>/status     # Check workflow status
GET  /api/cli/workflows                 # List workflows
POST /api/cli/plugins/<name>/execute    # Execute plugin
GET  /api/cli/findings                  # Get findings
POST /api/cli/findings                  # Add finding
POST /api/cli/reports/generate          # Generate report
GET  /api/cli/reports/<filename>        # Download report
GET  /api/cli/status                    # Overall CLI status
```

### Step 3: Frontend Integration (React)

Create a new page in React to interact with CLI:

```typescript
// study-hub-react/src/pages/CLIPentester.tsx

import React, { useState } from 'react';
import axios from 'axios';

export function CLIPentester() {
  const [workflowId, setWorkflowId] = useState('');
  const [status, setStatus] = useState('');

  const startWorkflow = async (workflowFile: string) => {
    const response = await axios.post('/api/cli/workflows/start', {
      workflow_file: workflowFile,
      mode: 'sequential',
      dry_run: false
    });
    
    setWorkflowId(response.data.workflow_id);
  };

  const checkStatus = async () => {
    const response = await axios.get(`/api/cli/workflows/${workflowId}/status`);
    setStatus(JSON.stringify(response.data, null, 2));
  };

  return (
    <div className="cli-pentester">
      <h1>🔥 ShadowHack Elite CLI</h1>
      
      <div className="workflow-section">
        <h2>Start Workflow</h2>
        <button onClick={() => startWorkflow('pentester_workflows.yaml')}>
          Start Web App Test
        </button>
        <p>Workflow ID: {workflowId}</p>
      </div>

      <div className="status-section">
        <h2>Workflow Status</h2>
        <button onClick={checkStatus}>Check Status</button>
        <pre>{status}</pre>
      </div>
    </div>
  );
}
```

---

## CLI Command Examples

### Basic Commands

```bash
# 1. List all available tools
python cli_pentester_framework.py list-tools

# 2. List all loaded plugins
python cli_pentester_framework.py list-plugins

# 3. Perform dry run (preview without execution)
python cli_pentester_framework.py run-workflow pentester_workflows.yaml --dry-run

# 4. Run workflow sequentially
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m sequential

# 5. Run workflow in parallel (faster)
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m parallel

# 6. Interactive mode (confirm each step)
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m interactive
```

### Advanced Commands

```bash
# Generate JSON report
python cli_pentester_framework.py generate-report report.json -f json

# Generate HTML report
python cli_pentester_framework.py generate-report report.html -f html

# Run custom workflow
python cli_pentester_framework.py run-workflow custom_workflow.yaml

# Execute with environment variables
export TARGET="target.com"
export TIMEOUT="600"
python cli_pentester_framework.py run-workflow workflow.yaml
```

---

## Workflow Scenarios

### Scenario 1: Quick Web Application Test

**Command:**
```bash
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m sequential
```

**What it does:**
1. Reconnaissance (subdomain discovery, tech stack)
2. Scanning (port scan, content discovery)
3. Enumeration (fingerprinting, API discovery)
4. Vulnerability assessment (SQL injection, XSS, auth testing)
5. Exploitation (POC creation)
6. Reporting (generate report)

**Expected output:**
```
[2024-03-29 10:15:32] [SUCCESS] Loaded workflow: pentester_workflows.yaml
[2024-03-29 10:15:33] [INFO] Starting workflow execution (sequential mode)
[2024-03-29 10:15:33] [INFO] Step: Reconnaissance - Subdomain Discovery
[2024-03-29 10:15:45] [SUCCESS] Completed: Reconnaissance - Subdomain Discovery
[2024-03-29 10:15:45] [INFO] Step: Reconnaissance - Technology Stack Analysis
... (more steps) ...
[2024-03-29 10:25:12] [SUCCESS] Completed: Reporting - Generate Finding Report
[2024-03-29 10:25:13] [INFO] Workflow completed
```

### Scenario 2: Network Penetration Test

**Command:**
```bash
export NETWORK_RANGE="192.168.1.0/24"
python cli_pentester_framework.py run-workflow pentester_workflows.yaml -m parallel
```

**What it does:**
- Network discovery
- Port scanning (all hosts)
- Service enumeration
- Active Directory enumeration
- Password spraying
- Lateral movement testing
- Privilege escalation

### Scenario 3: Mobile App Testing

```bash
export APK_FILE="/path/to/app.apk"
export DEVICE_ID="device123"
python cli_pentester_framework.py run-workflow pentester_workflows.yaml
```

---

## Plugin Ecosystem

### Creating Custom Plugins

#### Plugin 1: Custom Vulnerability Scanner

```python
# plugins/custom_vuln_scanner.py

from cli_pentester_framework import Plugin
from typing import Dict, List, Any

class CustomVulnScanner(Plugin):
    def __init__(self):
        super().__init__("CustomVulnScanner", "1.0.0")
    
    def initialize(self):
        self.enabled = True
    
    def validate(self) -> bool:
        return True
    
    def get_capabilities(self) -> List[str]:
        return ["custom_vulnerability_detection"]
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        target = kwargs.get("target")
        
        # Your custom scanning logic here
        findings = [
            {
                "title": "Custom Finding",
                "severity": "high",
                "description": "..."
            }
        ]
        
        return {
            "success": True,
            "findings": findings
        }
```

#### Plugin 2: Intelligence Gathering

```python
# plugins/intelligence_gatherer.py

class IntelligenceGatherer(Plugin):
    def __init__(self):
        super().__init__("IntelligenceGatherer", "1.0.0")
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        domain = kwargs.get("domain")
        
        # Gather intelligence
        intel = {
            "dns_records": self._get_dns(domain),
            "whois": self._get_whois(domain),
            "subdomains": self._enumerate_subdomains(domain),
            "emails": self._find_emails(domain),
            "technologies": self._detect_tech(domain)
        }
        
        return {"success": True, "intelligence": intel}
```

---

## Advanced Integration

### 1. Web UI Workflow Builder

Create a visual workflow builder in React:

```typescript
// Create workflows through UI
const createWorkflow = async (steps: WorkflowStep[]) => {
  // Convert to YAML
  const yaml = convertStepsToYAML(steps);
  
  // Save locally
  downloadYAML(yaml, `workflow_${Date.now()}.yaml`);
};
```

### 2. Real-time Progress Monitoring

```python
# WebSocket support for real-time updates
from flask_socketio import emit

@socketio.on('workflow_status')
def on_workflow_status(data):
    workflow_id = data['workflow_id']
    status = cli_service.get_workflow_status(workflow_id)
    emit('workflow_update', status, broadcast=True)
```

### 3. Integration with External Tools

```python
# Register Burp Suite
burp_config = ToolConfig(
    name="burp",
    version="2024.1",
    path="C:\\Program Files\\Burp\\burpsuite_pro.jar",
    args=["--headless"],
    timeout=3600
)

tool_manager.register_tool(burp_config)
```

### 4. Automated Reporting Pipeline

```python
# Auto-generate and send reports
def automated_reporting():
    # Generate report
    report_file = cli.generate_report("report.html", "html")
    
    # Send to client
    send_report_email(report_file, client_email)
    
    # Archive findings
    archive_findings(cli.workflow_engine.findings)
```

---

## Deployment

### Production Setup

1. **Install in production environment:**
```bash
pip install -r cli_requirements.txt --no-cache-dir
```

2. **Configure environment variables:**
```bash
# .env
CLI_PLUGINS_DIR=/opt/shadowhack/plugins
CLI_WORKFLOWS_DIR=/opt/shadowhack/workflows
CLI_REPORTS_DIR=/opt/shadowhack/reports
```

3. **Run with Gunicorn:**
```bash
gunicorn --workers 4 --threads 2 \
  --worker-class gthread \
  --bind 0.0.0.0:5000 \
  wsgi:app
```

4. **Docker deployment:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY cli_requirements.txt .
RUN pip install -r cli_requirements.txt

COPY backend/ .

CMD ["python", "cli_pentester_framework.py"]
```

### Monitoring

```bash
# Check CLI service health
curl http://localhost:5000/api/cli/health

# Monitor active workflows
curl http://localhost:5000/api/cli/status

# View findings
curl http://localhost:5000/api/cli/findings
```

---

## Performance Optimization

### 1. Parallel Execution

```yaml
# Use parallel mode for independent steps
steps:
  - name: "Port Scan"
    parallel: true
  - name: "Service Detection"
    parallel: true
```

### 2. Workflow Caching

```python
# Cache tool outputs
if tool_output_cached(tool_name, args):
    result = load_cached_output(tool_name, args)
else:
    result = execute_tool(tool_name, args)
    cache_output(tool_name, args, result)
```

### 3. Resource Management

```python
# Configure timeouts
tool_config = ToolConfig(
    timeout=300,  # 5 minutes
    max_output_size=50*1024*1024  # 50MB
)
```

---

## Troubleshooting

### Issue: Tools not found
```bash
# Ensure tools are in PATH or specify full path in config
which nmap
echo $PATH
```

### Issue: Plugin loading fails
```bash
# Check plugin syntax
python -m py_compile plugins/my_plugin.py

# Enable debug logging
export DEBUG=1
python cli_pentester_framework.py list-plugins
```

### Issue: Workflow timeout
```bash
# Increase timeout for specific steps
steps:
  - name: "Long-running scan"
    timeout: 1800  # 30 minutes
```

---

## Best Practices

✅ **Do:**
- Use workflows for complex scenarios
- Enable parallel execution when possible
- Validate plugins before production
- Monitor resource usage
- Regular backups of findings

❌ **Don't:**
- Run multiple workflows on same host simultaneously
- Use insecure tool paths
- Hardcode sensitive data
- Ignore tool errors
- Skip reporting phase

---

## Next Steps

1. **Test the CLI framework** with provided workflows
2. **Create custom plugins** for your specific needs
3. **Integrate with React frontend** for visual workflow builder
4. **Deploy to production** with proper monitoring
5. **Build community plugins** and share

---

## Support

For issues or questions:
1. Check CLI_FRAMEWORK_GUIDE.md for detailed docs
2. Review example plugins in plugins_collection.py
3. Check workflow examples in pentester_workflows.yaml
4. Enable debug logging for troubleshooting

---

**Status:** ✅ Ready for Production

**Version:** 1.0.0

**Last Updated:** 2024-03-29

---

🚀 **You now have a professional-grade penetration testing CLI framework integrated with ShadowHack!**
