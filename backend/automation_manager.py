
import subprocess
import threading
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AutomationManager")

class AutomationManager:
    """Handles execution of security tools and automation workflows"""
    
    def __init__(self):
        self.active_tasks = {}
        self.task_history = []
        
    def run_nmap_scan(self, target: str, arguments: str = "-F") -> Dict[str, Any]:
        """Execute an Nmap scan asynchronously"""
        task_id = f"nmap_{datetime.utcnow().timestamp()}"
        
        def execute():
            try:
                self.active_tasks[task_id] = {"status": "running", "start_time": datetime.utcnow().isoformat()}
                # Use nmap if available, otherwise simulate
                cmd = ["nmap"] + arguments.split() + [target]
                
                logger.info(f"🚀 Starting Nmap task {task_id}: {' '.join(cmd)}")
                
                # In a real environment, we'd check if nmap is installed
                try:
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    stdout, stderr = process.communicate(timeout=300)
                    
                    if process.returncode == 0:
                        self.active_tasks[task_id].update({
                            "status": "completed",
                            "output": stdout,
                            "end_time": datetime.utcnow().isoformat()
                        })
                    else:
                        self.active_tasks[task_id].update({
                            "status": "failed",
                            "error": stderr,
                            "end_time": datetime.utcnow().isoformat()
                        })
                except FileNotFoundError:
                    # Simulation mode if nmap not found
                    logger.warning("Nmap not found, simulating output")
                    simulation = f"Nmap scan report for {target}\nHost is up.\nNot shown: 98 closed ports\nPORT   STATE SERVICE\n80/tcp  open  http\n22/tcp  open  ssh"
                    self.active_tasks[task_id].update({
                        "status": "completed",
                        "output": simulation,
                        "end_time": datetime.utcnow().isoformat(),
                        "simulated": True
                    })
            except Exception as e:
                logger.error(f"Error in Nmap task: {e}")
                self.active_tasks[task_id] = {"status": "error", "error": str(e)}

        thread = threading.Thread(target=execute)
        thread.start()
        
        return {"success": True, "task_id": task_id, "message": "Nmap scan started"}

    def analyze_scan_with_ai(self, scan_output: str) -> Dict[str, Any]:
        """Use AI to analyze scan results and suggest red teaming tactics"""
        try:
            from ai_manager import get_groq_client
            client = get_groq_client()
            if not client:
                return {"success": False, "error": "AI client not initialized"}
            
            prompt = f"""
            Analyze the following Nmap scan output and suggest potential Red Teaming tactics (exploitation, lateral movement, or persistence).
            Output should be a JSON object with 'critical_findings', 'suggested_exploits', and 'next_steps'.
            
            Scan Output:
            {scan_output}
            """
            
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama3-70b-8192",
                response_format={"type": "json_object"}
            )
            
            return {"success": True, "analysis": json.loads(response.choices[0].message.content)}
        except Exception as e:
            logger.error(f"AI Analysis error: {e}")
            return {"success": False, "error": str(e)}

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Retrieve status and output of a specific task"""
        return self.active_tasks.get(task_id, {"success": False, "error": "Task not found"})

    def list_active_tasks(self) -> List[Dict[str, Any]]:
        """List all currently running tasks"""
        return [{"id": tid, "status": info["status"]} for tid, info in self.active_tasks.items() if info["status"] == "running"]

# Global Instance
automation_manager = AutomationManager()

def get_automation_manager():
    return automation_manager
