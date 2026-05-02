"""
Example Plugin Template
This is a basic plugin template showing how to create plugins for ShadowHack
"""

from plugin_system import BasePlugin, PluginMetadata, PluginCapability
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class ExampleNetworkPlugin(BasePlugin):
    """
    Example Network Reconnaissance Plugin
    Demonstrates plugin structure and capabilities
    """
    
    def __init__(self):
        metadata = PluginMetadata(
            id="example-network-recon",
            name="Example Network Reconnaissance",
            version="1.0.0",
            author="ShadowHack Team",
            description="Basic network reconnaissance plugin template",
            license="MIT",
            homepage="https://shadowhack.io",
            repository="https://github.com/shadowhack/example-plugin",
            keywords=["network", "recon", "example"],
            capabilities=[
                PluginCapability(
                    name="scan_network",
                    description="Scan network for active hosts",
                    inputs={
                        "target": "str (CIDR notation)",
                        "port_range": "str (optional, e.g., 1-1000)"
                    },
                    outputs={
                        "active_hosts": "List[str]",
                        "scan_time": "float"
                    }
                ),
                PluginCapability(
                    name="enumerate_services",
                    description="Enumerate services on a host",
                    inputs={
                        "host": "str (IP address)",
                        "ports": "List[int] (optional)"
                    },
                    outputs={
                        "services": "Dict[int, str]",
                        "vulnerabilities": "List[str]"
                    }
                )
            ],
            dependencies={},
            minimum_app_version="1.0.0"
        )
        
        super().__init__(metadata)
    
    def initialize(self):
        """Initialize the plugin"""
        logger.info(f"Initializing {self.metadata.name}")
        
        # Example: Register hooks
        self.register_hook('after_load', self._on_loaded)
        self.register_hook('before_execution', self._before_execution)
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute plugin with given parameters"""
        capability = kwargs.get('capability', 'scan_network')
        
        if capability == 'scan_network':
            return self._scan_network(kwargs)
        elif capability == 'enumerate_services':
            return self._enumerate_services(kwargs)
        else:
            raise ValueError(f"Unknown capability: {capability}")
    
    def validate(self) -> bool:
        """Validate plugin integrity"""
        # Check required settings
        required_settings = ['tool_path']
        
        for setting in required_settings:
            if not self.get_setting(setting):
                logger.warning(f"Missing setting: {setting}")
                return False
        
        return True
    
    def get_capabilities(self):
        """Get list of capabilities"""
        return self.metadata.capabilities
    
    # ====================================================================
    # Plugin Methods
    # ====================================================================
    
    def _on_loaded(self):
        """Called after plugin is loaded"""
        logger.info(f"Plugin loaded: {self.metadata.name}")
    
    def _before_execution(self, params):
        """Called before plugin execution"""
        logger.debug(f"Executing with params: {params}")
    
    def _scan_network(self, params: Dict) -> Dict[str, Any]:
        """Scan network for active hosts"""
        target = params.get('target')
        port_range = params.get('port_range', '1-65535')
        
        if not target:
            raise ValueError("Missing 'target' parameter")
        
        # Simulate network scan
        logger.info(f"Scanning network: {target}")
        
        # In real implementation, this would use actual tools
        active_hosts = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.5",
            "192.168.1.10"
        ]
        
        return {
            'success': True,
            'active_hosts': active_hosts,
            'target': target,
            'port_range': port_range,
            'scan_time': 5.23,
            'host_count': len(active_hosts)
        }
    
    def _enumerate_services(self, params: Dict) -> Dict[str, Any]:
        """Enumerate services on a host"""
        host = params.get('host')
        ports = params.get('ports', [22, 80, 443, 3306])
        
        if not host:
            raise ValueError("Missing 'host' parameter")
        
        # Simulate service enumeration
        logger.info(f"Enumerating services on {host}")
        
        services = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL"
        }
        
        found_services = {p: services.get(p, f"Unknown({p})") for p in ports}
        
        return {
            'success': True,
            'host': host,
            'services': found_services,
            'vulnerabilities': [
                "SSH version outdated",
                "HTTP headers missing security flags"
            ],
            'port_count': len(found_services)
        }

# ====================================================================
# Factory Function (Required)
# ====================================================================

def create_plugin():
    """Factory function to create plugin instance"""
    return ExampleNetworkPlugin()

# For direct instantiation
if __name__ == "__main__":
    plugin = ExampleNetworkPlugin()
    plugin.initialize()
    
    # Example usage
    result = plugin.execute(
        capability='scan_network',
        target='192.168.0.0/24'
    )
    print(result)
