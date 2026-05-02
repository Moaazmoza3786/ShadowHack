#!/usr/bin/env python3
"""
ShadowHack Elite CLI Integration Module
Integrates the CLI framework with the Flask backend
"""

from flask import Blueprint, request, jsonify, send_file
from functools import wraps
import asyncio
import json
import os
from datetime import datetime
from pathlib import Path

# Import CLI framework components
try:
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from cli_pentester_framework import (
        ShadowHackCLI, WorkflowEngine, ToolManager, PluginManager,
        ExecutionMode, Finding, SeverityLevel, WorkflowStep, Logger
    )
except ImportError as e:
    print(f"Warning: Could not import CLI components: {e}")


# Create Blueprint
cli_bp = Blueprint('cli', __name__, url_prefix='/api/cli')


class CLIService:
    """Service for managing CLI operations through API"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CLIService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.cli = ShadowHackCLI()
        self.logger = Logger("CLIService")
        self.active_workflows = {}
        self.workflow_results = {}
        self._initialized = True
    
    def start_workflow(self, workflow_file: str, mode: str = "sequential",
                      dry_run: bool = False) -> dict:
        """Start a workflow execution"""
        try:
            workflow_id = self._generate_workflow_id()
            
            steps = self.cli.workflow_engine.load_workflow(workflow_file)
            if not steps:
                return {
                    "success": False,
                    "error": "No steps loaded from workflow"
                }
            
            # Store active workflow
            self.active_workflows[workflow_id] = {
                "file": workflow_file,
                "mode": mode,
                "dry_run": dry_run,
                "steps": len(steps),
                "started_at": datetime.now().isoformat(),
                "status": "running"
            }
            
            # Execute workflow in background
            execution_mode = ExecutionMode[mode.upper()]
            asyncio.create_task(
                self._execute_workflow_async(
                    workflow_id, steps, execution_mode, dry_run
                )
            )
            
            return {
                "success": True,
                "workflow_id": workflow_id,
                "message": "Workflow started"
            }
        
        except Exception as e:
            self.logger.error(f"Failed to start workflow: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _execute_workflow_async(self, workflow_id: str, steps: list,
                                     mode: ExecutionMode, dry_run: bool):
        """Execute workflow asynchronously"""
        try:
            results = await self.cli.workflow_engine.execute_workflow(
                steps, mode, dry_run
            )
            
            self.workflow_results[workflow_id] = results
            self.active_workflows[workflow_id]["status"] = "completed"
            self.active_workflows[workflow_id]["completed_at"] = datetime.now().isoformat()
            
            self.logger.success(f"Workflow {workflow_id} completed")
        
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {str(e)}")
            self.active_workflows[workflow_id]["status"] = "failed"
            self.active_workflows[workflow_id]["error"] = str(e)
    
    def get_workflow_status(self, workflow_id: str) -> dict:
        """Get workflow status"""
        if workflow_id not in self.active_workflows:
            return {"error": "Workflow not found"}
        
        status = self.active_workflows[workflow_id]
        results = self.workflow_results.get(workflow_id, {})
        
        return {
            "workflow_id": workflow_id,
            "status": status["status"],
            "started_at": status.get("started_at"),
            "completed_at": status.get("completed_at"),
            "results": results
        }
    
    def list_workflows(self) -> list:
        """List all workflows"""
        return [
            {
                "workflow_id": wid,
                "status": wdata["status"],
                "file": wdata["file"]
            }
            for wid, wdata in self.active_workflows.items()
        ]
    
    def get_tools(self) -> dict:
        """Get available tools"""
        return self.cli.tool_manager.list_tools()
    
    def get_plugins(self) -> dict:
        """Get loaded plugins"""
        return self.cli.plugin_manager.list_plugins()
    
    def execute_plugin(self, plugin_name: str, **kwargs) -> dict:
        """Execute a plugin"""
        try:
            result = self.cli.plugin_manager.execute_plugin(plugin_name, **kwargs)
            return {
                "success": True,
                "plugin": plugin_name,
                "result": result
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def add_finding(self, finding_data: dict) -> dict:
        """Add a finding"""
        try:
            finding = Finding(
                title=finding_data["title"],
                severity=SeverityLevel[finding_data["severity"].upper()],
                description=finding_data["description"],
                location=finding_data["location"],
                remediation=finding_data["remediation"],
                evidence=finding_data.get("evidence", ""),
                impact=finding_data.get("impact", ""),
                cvss_score=finding_data.get("cvss_score", 0.0)
            )
            
            self.cli.workflow_engine.add_finding(finding)
            
            return {
                "success": True,
                "finding": finding_data,
                "total_findings": len(self.cli.workflow_engine.findings)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_findings(self) -> list:
        """Get all findings"""
        from dataclasses import asdict
        return [asdict(f) for f in self.cli.workflow_engine.findings]
    
    def generate_report(self, format_type: str = "json") -> dict:
        """Generate report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"report_{timestamp}.{format_type}"
            
            metadata = {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(self.cli.workflow_engine.findings),
                "workflows_executed": len(self.workflow_results)
            }
            
            self.cli.generate_report(output_file, format_type, metadata)
            
            return {
                "success": True,
                "report_file": output_file,
                "format": format_type
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_workflow_id(self) -> str:
        """Generate unique workflow ID"""
        import uuid
        return f"wf_{uuid.uuid4().hex[:8]}"


# Initialize service
cli_service = CLIService()


# ═══════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@cli_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ShadowHack Elite CLI",
        "timestamp": datetime.now().isoformat()
    })


@cli_bp.route('/tools', methods=['GET'])
def list_tools():
    """Get available tools"""
    try:
        tools = cli_service.get_tools()
        return jsonify({
            "success": True,
            "tools": tools,
            "count": len(tools)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/plugins', methods=['GET'])
def list_plugins():
    """Get loaded plugins"""
    try:
        plugins = cli_service.get_plugins()
        return jsonify({
            "success": True,
            "plugins": plugins,
            "count": len(plugins)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/workflows/start', methods=['POST'])
def start_workflow():
    """Start a workflow execution"""
    try:
        data = request.get_json()
        workflow_file = data.get("workflow_file")
        mode = data.get("mode", "sequential")
        dry_run = data.get("dry_run", False)
        
        if not workflow_file:
            return jsonify({"error": "workflow_file is required"}), 400
        
        result = cli_service.start_workflow(workflow_file, mode, dry_run)
        
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/workflows/<workflow_id>/status', methods=['GET'])
def get_workflow_status(workflow_id):
    """Get workflow status"""
    try:
        status = cli_service.get_workflow_status(workflow_id)
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@cli_bp.route('/workflows', methods=['GET'])
def list_workflows():
    """List all workflows"""
    try:
        workflows = cli_service.list_workflows()
        return jsonify({
            "success": True,
            "workflows": workflows,
            "count": len(workflows)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@cli_bp.route('/plugins/<plugin_name>/execute', methods=['POST'])
def execute_plugin(plugin_name):
    """Execute a plugin"""
    try:
        data = request.get_json()
        kwargs = data.get("args", {})
        
        result = cli_service.execute_plugin(plugin_name, **kwargs)
        
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/findings', methods=['GET'])
def get_findings():
    """Get all findings"""
    try:
        findings = cli_service.get_findings()
        return jsonify({
            "success": True,
            "findings": findings,
            "count": len(findings)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@cli_bp.route('/findings', methods=['POST'])
def add_finding():
    """Add a finding"""
    try:
        data = request.get_json()
        result = cli_service.add_finding(data)
        
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/reports/generate', methods=['POST'])
def generate_report():
    """Generate report"""
    try:
        data = request.get_json()
        format_type = data.get("format", "json")
        
        result = cli_service.generate_report(format_type)
        
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@cli_bp.route('/reports/<filename>', methods=['GET'])
def download_report(filename):
    """Download generated report"""
    try:
        file_path = Path(filename)
        
        if not file_path.exists():
            return jsonify({"error": "Report not found"}), 404
        
        return send_file(
            str(file_path),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@cli_bp.route('/status', methods=['GET'])
def get_cli_status():
    """Get overall CLI status"""
    try:
        return jsonify({
            "success": True,
            "status": "operational",
            "tools_available": len(cli_service.get_tools()),
            "plugins_loaded": len(cli_service.get_plugins()),
            "active_workflows": len(cli_service.active_workflows),
            "total_findings": len(cli_service.get_findings()),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET SUPPORT (for real-time updates)
# ═══════════════════════════════════════════════════════════════════════════

class WorkflowMonitor:
    """Monitor workflow execution in real-time"""
    
    def __init__(self):
        self.subscribers = {}
    
    def subscribe(self, workflow_id: str, callback):
        """Subscribe to workflow updates"""
        if workflow_id not in self.subscribers:
            self.subscribers[workflow_id] = []
        self.subscribers[workflow_id].append(callback)
    
    def notify(self, workflow_id: str, message: dict):
        """Notify subscribers of updates"""
        if workflow_id in self.subscribers:
            for callback in self.subscribers[workflow_id]:
                try:
                    callback(message)
                except Exception as e:
                    print(f"Error notifying subscriber: {e}")


workflow_monitor = WorkflowMonitor()


def register_cli_routes(app):
    """Register CLI routes with Flask app"""
    app.register_blueprint(cli_bp)
    print("[*] ShadowHack Elite CLI routes registered")


if __name__ == "__main__":
    # Test the service
    service = CLIService()
    
    print("╔════════════════════════════════════════════════╗")
    print("║   ShadowHack Elite CLI Service - Test Mode   ║")
    print("╚════════════════════════════════════════════════╝")
    
    # Test tool listing
    print("\n[*] Available Tools:")
    tools = service.get_tools()
    for tool_name, tool_info in tools.items():
        print(f"    • {tool_name}: {tool_info}")
    
    # Test plugin listing
    print("\n[*] Loaded Plugins:")
    plugins = service.get_plugins()
    for plugin_name, plugin_info in plugins.items():
        print(f"    • {plugin_name}: {plugin_info}")
    
    print("\n[+] CLI Service is operational!")
