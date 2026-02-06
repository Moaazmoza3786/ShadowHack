import time
import threading
from tools_manager import ToolExecutor

class KillChainManager:
    def __init__(self):
        self.executor = ToolExecutor()
        self.chains = {
            'quick_recon': {
                'name': 'Quick Web Recon',
                'description': 'Ping -> Nmap Fast -> Nikto',
                'steps': [
                    {'tool': 'ping', 'cmd': 'ping -c 3 {target}', 'ignore_fail': True},
                    {'tool': 'nmap', 'cmd': 'nmap -F {target}', 'capture_output': True},
                    # Smart Step: Only run Nikto if port 80/443 found
                    {'tool': 'nikto', 'cmd': 'nikto -h http://{target} -Tuning x', 'condition': 'port_80_open'}
                ]
            },
            'full_server_audit': {
                'name': 'Full Server Audit',
                'description': 'Nmap Version -> Nikto (If Web) -> Gobuster (If Web)',
                'steps': [
                    {'tool': 'nmap', 'cmd': 'nmap -sV -p 80,443 {target}', 'capture_output': True},
                    {'tool': 'nikto', 'cmd': 'nikto -h http://{target}', 'condition': 'port_80_open'},
                    {'tool': 'gobuster', 'cmd': 'gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50', 'condition': 'port_80_open'}
                ]
            },
             'subdomain_hunt': {
                'name': 'Subdomain Hunt',
                'description': 'Subfinder -> Httpx -> Nmap',
                'steps': [
                     {'tool': 'theHarvester', 'cmd': 'theHarvester -d {target} -b google'},
                     {'tool': 'nmap', 'cmd': 'nmap -F {target}'}
                ]
            }
        }

    def get_chains(self):
        return {k: {'name': v['name'], 'description': v['description']} for k, v in self.chains.items()}

    def execute_chain(self, chain_id, target, emit_callback):
        if chain_id not in self.chains:
            emit_callback(f"[!] Chain {chain_id} not found.")
            return

        chain = self.chains[chain_id]
        emit_callback(f"[*] Starting Smart Kill Chain: {chain['name']}")
        emit_callback(f"[*] Target: {target}")
        emit_callback("="*50)

        context = {} # Store potential shared state

        def run_steps():
            for i, step in enumerate(chain['steps']):
                tool_name = step['tool']
                original_cmd = step['cmd']
                
                # Check conditions
                if 'condition' in step:
                    cond = step['condition']
                    should_run = False
                    if cond == 'port_80_open':
                        # Check context from previous nmap
                        prev_output = context.get('last_output', '')
                        if '80/tcp' in prev_output or '443/tcp' in prev_output or 'http' in prev_output or 'https' in prev_output:
                            should_run = True
                            emit_callback(f"\n[*] Condition Met: Web ports detected. Proceeding with {tool_name}.")
                        else:
                             emit_callback(f"\n[*] Condition Failed: Web ports NOT detected. Skipping {tool_name}.")
                    
                    if not should_run:
                        continue

                cmd = original_cmd.replace('{target}', target)
                
                emit_callback(f"\n[+] Step {i+1}/{len(chain['steps'])}: Executing {tool_name}...")
                emit_callback(f"[>] Command: {cmd}")
                emit_callback("-"*30)
                
                # We want to capture output for our logic, but also stream it.
                step_output = []
                
                def stream_and_capture(line):
                    emit_callback(line)
                    if step.get('capture_output'):
                        step_output.append(line)

                self.executor.execute_tool(cmd, stream_and_capture)
                
                if step.get('capture_output'):
                    context['last_output'] = "".join(step_output)
                
                time.sleep(1)
            
            emit_callback("\n" + "="*50)
            emit_callback("[*] Smart Chain Execution Complete.")

        threading.Thread(target=run_steps, daemon=True).start()
