"""
Plugin System Core Architecture
Provides plugin management, loading, and execution
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import json
import importlib.util
import sys
import logging
from pathlib import Path
import hashlib
import semver

logger = logging.getLogger(__name__)

# ============================================================================
# Plugin Metadata & Configuration
# ============================================================================

@dataclass
class PluginCapability:
    """A capability/feature provided by a plugin"""
    name: str
    description: str
    inputs: Dict[str, str] = field(default_factory=dict)  # param_name -> type
    outputs: Dict[str, str] = field(default_factory=dict)  # result_name -> type

@dataclass
class PluginMetadata:
    """Plugin metadata and information"""
    id: str
    name: str
    version: str
    author: str
    description: str
    license: str = "MIT"
    homepage: str = ""
    repository: str = ""
    keywords: List[str] = field(default_factory=list)
    capabilities: List[PluginCapability] = field(default_factory=list)
    dependencies: Dict[str, str] = field(default_factory=dict)  # plugin_id -> version
    minimum_app_version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return asdict(self)

@dataclass
class PluginConfig:
    """Plugin configuration"""
    plugin_id: str
    enabled: bool = True
    settings: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

# ============================================================================
# Base Plugin Class
# ============================================================================

class BasePlugin(ABC):
    """
    Abstract base class for all plugins
    All plugins must inherit from this class
    """
    
    def __init__(self, metadata: PluginMetadata):
        self.metadata = metadata
        self.config: Optional[PluginConfig] = None
        self.enabled = True
        self.hooks: Dict[str, List[Callable]] = {
            'before_load': [],
            'after_load': [],
            'before_execution': [],
            'after_execution': [],
            'on_error': [],
            'before_unload': [],
        }
    
    @abstractmethod
    def initialize(self):
        """Initialize the plugin"""
        pass
    
    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the plugin with given parameters"""
        pass
    
    @abstractmethod
    def validate(self) -> bool:
        """Validate plugin integrity and health"""
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[PluginCapability]:
        """Get list of capabilities provided by plugin"""
        pass
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register a hook callback"""
        if hook_name in self.hooks:
            self.hooks[hook_name].append(callback)
    
    def trigger_hook(self, hook_name: str, *args, **kwargs):
        """Trigger all callbacks for a hook"""
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook error in {self.metadata.name}: {str(e)}")
    
    def get_setting(self, key: str, default=None):
        """Get a configuration setting"""
        if self.config:
            return self.config.settings.get(key, default)
        return default
    
    def set_setting(self, key: str, value: Any):
        """Set a configuration setting"""
        if self.config:
            self.config.settings[key] = value
            self.config.updated_at = datetime.now().isoformat()
    
    def get_info(self) -> Dict:
        """Get plugin information"""
        return {
            'metadata': self.metadata.to_dict(),
            'enabled': self.enabled,
            'capabilities': [asdict(c) for c in self.metadata.capabilities],
            'config': asdict(self.config) if self.config else None,
        }

# ============================================================================
# Plugin Manager
# ============================================================================

class PluginManager:
    """Manages plugin lifecycle, loading, and execution"""
    
    def __init__(self, plugins_dir: str = "./plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, BasePlugin] = {}
        self.configs: Dict[str, PluginConfig] = {}
        self.marketplace: List[Dict] = []  # Available plugins in marketplace
        self.ensure_plugins_dir()
    
    def ensure_plugins_dir(self):
        """Ensure plugins directory exists"""
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
    
    def load_plugin(self, plugin_path: str) -> BasePlugin:
        """
        Load a plugin from a Python file
        
        Args:
            plugin_path: Path to plugin file or directory
        
        Returns:
            Loaded plugin instance
        """
        plugin_path = Path(plugin_path)
        
        if plugin_path.is_dir():
            # Load from __init__.py
            plugin_file = plugin_path / "__init__.py"
        else:
            plugin_file = plugin_path
        
        if not plugin_file.exists():
            raise FileNotFoundError(f"Plugin file not found: {plugin_file}")
        
        # Load module dynamically
        spec = importlib.util.spec_from_file_location(
            plugin_file.stem, 
            plugin_file
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        
        # Find plugin class (should inherit from BasePlugin)
        plugin_class = None
        for item_name in dir(module):
            item = getattr(module, item_name)
            if isinstance(item, type) and issubclass(item, BasePlugin) and item != BasePlugin:
                plugin_class = item
                break
        
        if not plugin_class:
            raise ValueError(f"No BasePlugin subclass found in {plugin_file}")
        
        # Instantiate and initialize
        plugin = plugin_class()
        plugin.initialize()
        plugin.trigger_hook('after_load')
        
        # Register plugin
        self.plugins[plugin.metadata.id] = plugin
        logger.info(f"✓ Plugin loaded: {plugin.metadata.name} v{plugin.metadata.version}")
        
        return plugin
    
    def load_all_plugins(self):
        """Load all plugins from plugins directory"""
        if not self.plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return
        
        for plugin_path in self.plugins_dir.iterdir():
            if plugin_path.is_dir() or plugin_path.suffix == '.py':
                try:
                    self.load_plugin(plugin_path)
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_path}: {str(e)}")
    
    def register_plugin(self, plugin: BasePlugin, config: Optional[PluginConfig] = None):
        """Register a plugin"""
        self.plugins[plugin.metadata.id] = plugin
        
        if config:
            self.configs[plugin.metadata.id] = config
            plugin.config = config
        else:
            # Create default config
            config = PluginConfig(plugin_id=plugin.metadata.id)
            self.configs[plugin.metadata.id] = config
            plugin.config = config
        
        logger.info(f"✓ Plugin registered: {plugin.metadata.name}")
    
    def unload_plugin(self, plugin_id: str):
        """Unload a plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        plugin = self.plugins[plugin_id]
        plugin.trigger_hook('before_unload')
        
        del self.plugins[plugin_id]
        logger.info(f"✓ Plugin unloaded: {plugin.metadata.name}")
    
    def enable_plugin(self, plugin_id: str):
        """Enable a plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        self.plugins[plugin_id].enabled = True
        if plugin_id in self.configs:
            self.configs[plugin_id].enabled = True
        
        logger.info(f"✓ Plugin enabled: {plugin_id}")
    
    def disable_plugin(self, plugin_id: str):
        """Disable a plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        self.plugins[plugin_id].enabled = False
        if plugin_id in self.configs:
            self.configs[plugin_id].enabled = False
        
        logger.info(f"✓ Plugin disabled: {plugin_id}")
    
    def execute_plugin(self, plugin_id: str, **kwargs) -> Dict[str, Any]:
        """Execute a plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        plugin = self.plugins[plugin_id]
        
        if not plugin.enabled:
            raise RuntimeError(f"Plugin is disabled: {plugin_id}")
        
        try:
            plugin.trigger_hook('before_execution', kwargs)
            result = plugin.execute(**kwargs)
            plugin.trigger_hook('after_execution', result)
            return result
        except Exception as e:
            plugin.trigger_hook('on_error', e)
            logger.error(f"Plugin execution error ({plugin_id}): {str(e)}")
            raise
    
    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """Get a plugin by ID"""
        return self.plugins.get(plugin_id)
    
    def list_plugins(self, enabled_only: bool = False) -> List[Dict]:
        """List all plugins"""
        plugins_list = []
        for plugin_id, plugin in self.plugins.items():
            if enabled_only and not plugin.enabled:
                continue
            
            plugins_list.append({
                'id': plugin_id,
                'name': plugin.metadata.name,
                'version': plugin.metadata.version,
                'author': plugin.metadata.author,
                'description': plugin.metadata.description,
                'enabled': plugin.enabled,
                'capabilities': [asdict(c) for c in plugin.metadata.capabilities],
            })
        
        return plugins_list
    
    def get_plugin_info(self, plugin_id: str) -> Dict:
        """Get detailed plugin information"""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        return plugin.get_info()
    
    def update_plugin_config(self, plugin_id: str, settings: Dict[str, Any]):
        """Update plugin configuration"""
        if plugin_id not in self.configs:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        config = self.configs[plugin_id]
        config.settings.update(settings)
        config.updated_at = datetime.now().isoformat()
        
        # Update plugin config
        if plugin_id in self.plugins:
            self.plugins[plugin_id].config = config
        
        logger.info(f"✓ Plugin config updated: {plugin_id}")
    
    def validate_plugin(self, plugin_id: str) -> bool:
        """Validate a plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        return self.plugins[plugin_id].validate()
    
    def validate_all_plugins(self) -> Dict[str, bool]:
        """Validate all plugins"""
        results = {}
        for plugin_id, plugin in self.plugins.items():
            try:
                results[plugin_id] = plugin.validate()
            except Exception as e:
                logger.error(f"Validation error for {plugin_id}: {str(e)}")
                results[plugin_id] = False
        
        return results
    
    def add_to_marketplace(self, plugin_info: Dict):
        """Add plugin to marketplace"""
        self.marketplace.append({
            **plugin_info,
            'added_at': datetime.now().isoformat()
        })
    
    def list_marketplace(self, category: Optional[str] = None) -> List[Dict]:
        """List plugins in marketplace"""
        if category:
            return [p for p in self.marketplace if p.get('category') == category]
        return self.marketplace
    
    def search_marketplace(self, query: str) -> List[Dict]:
        """Search marketplace plugins"""
        query_lower = query.lower()
        results = []
        
        for plugin in self.marketplace:
            if (query_lower in plugin.get('name', '').lower() or
                query_lower in plugin.get('description', '').lower() or
                query_lower in ' '.join(plugin.get('keywords', [])).lower()):
                results.append(plugin)
        
        return results

# ============================================================================
# Global Plugin Manager Instance
# ============================================================================

_plugin_manager: Optional[PluginManager] = None

def get_plugin_manager(plugins_dir: str = "./plugins") -> PluginManager:
    """Get or create global plugin manager"""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager(plugins_dir)
    return _plugin_manager
