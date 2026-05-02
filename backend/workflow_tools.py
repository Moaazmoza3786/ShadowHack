"""
AI-powered tool simulations for the Workflow Engine.
These functions use Ollama to generate realistic security scan results.
"""

import json
import logging
from typing import Dict, Any, List
from ai_manager import get_ai_manager

logger = logging.getLogger(__name__)

def generate_ai_step_result(action: str, inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a realistic security tool output using Ollama.
    """
    ai_manager = get_ai_manager()
    if not ai_manager:
        return {"error": "AI Manager not initialized"}

    # Construct a specific prompt based on the action
    target = inputs.get("target") or inputs.get("url") or inputs.get("domain") or inputs.get("network") or "unknown target"
    
    system_prompt = f"""You are an automated security scanner simulating the output of '{action}'.
The target is: {target}.
Generate a realistic, professional, and technically detailed output in text format that looks like it came from the real tool.
Do not include any chat-like pleasantries. Just the tool output.
If possible, include some interesting but safe findings (open ports, versions, potential misconfigurations).
"""

    user_prompt = f"Generate output for action: {action} with inputs: {json.dumps(inputs)}"
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    try:
        # Call Ollama via AI Manager
        # We use a lower temperature for more consistent "tool-like" output
        result_text = ai_manager._call_ai(messages, temperature=0.3, timeout=90)
        
        if not result_text:
            return {"error": f"AI failed to generate output for {action}"}

        return {
            "status": "success",
            "output": result_text,
            "action_executed": action,
            "target": target
        }
    except Exception as e:
        logger.error(f"AI tool execution failed for {action}: {e}")
        return {"error": str(e)}

def get_ai_workflow_tools() -> Dict[str, Any]:
    """
    Returns a mapping of tool names to their AI-powered execution functions.
    The keys match the 'action' field in WorkflowStep.
    """
    # Common actions from workflow_templates.py
    actions = [
        "nmap_scan", "subdomain_enum", "burp_crawl", "nikto_scan", 
        "sqlmap_test", "generate_report", "ping_sweep", "nmap_ports",
        "service_enum", "os_detect", "setup_mobile_env", "extract_app",
        "static_analysis_mobile", "dynamic_analysis_mobile", "test_mobile_api",
        "analyze_storage", "validate_cloud_creds", "cloud_inventory",
        "iam_audit", "cloud_network_check", "cloud_storage_audit",
        "verify_encryption", "quick_nmap", "quick_web_scan", "quick_report"
    ]

    # Map all defined actions to the generic AI generator
    tool_registry = {
        action: generate_ai_step_result
        for action in actions
    }
    
    return tool_registry
