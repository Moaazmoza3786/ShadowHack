"""
Plugin Marketplace & Store API
RESTful API for plugin management, installation, and configuration
"""

from flask import Blueprint, request, jsonify, send_file
from flask_socketio import emit, join_room, leave_room
import asyncio
import json
import logging
from typing import Optional
from datetime import datetime
from pathlib import Path
import zipfile
import shutil
import requests

from plugin_system import (
    get_plugin_manager,
    BasePlugin,
    PluginMetadata,
    PluginCapability,
    PluginConfig
)

logger = logging.getLogger(__name__)

plugin_bp = Blueprint('plugins', __name__, url_prefix='/api/plugins')

# ============================================================================
# REST API Endpoints
# ============================================================================

@plugin_bp.route('/health', methods=['GET'])
def plugin_health():
    """Check plugin system health"""
    try:
        manager = get_plugin_manager()
        validation_results = manager.validate_all_plugins()
        
        valid_count = sum(1 for v in validation_results.values() if v)
        total_count = len(validation_results)
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'plugins_loaded': len(manager.plugins),
            'plugins_valid': valid_count,
            'plugins_total': total_count,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/list', methods=['GET'])
def list_plugins():
    """List all loaded plugins"""
    try:
        manager = get_plugin_manager()
        enabled_only = request.args.get('enabled', 'false').lower() == 'true'
        
        plugins = manager.list_plugins(enabled_only=enabled_only)
        
        return jsonify({
            'success': True,
            'plugins': plugins,
            'count': len(plugins),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"List plugins error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/info', methods=['GET'])
def get_plugin_info(plugin_id):
    """Get detailed plugin information"""
    try:
        manager = get_plugin_manager()
        info = manager.get_plugin_info(plugin_id)
        
        return jsonify({
            'success': True,
            'plugin': info,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Get plugin info error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 404

@plugin_bp.route('/<plugin_id>/execute', methods=['POST'])
def execute_plugin(plugin_id):
    """Execute a plugin with given parameters"""
    try:
        data = request.get_json() or {}
        params = data.get('params', {})
        
        manager = get_plugin_manager()
        result = manager.execute_plugin(plugin_id, **params)
        
        return jsonify({
            'success': True,
            'plugin_id': plugin_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Execute plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/enable', methods=['POST'])
def enable_plugin(plugin_id):
    """Enable a plugin"""
    try:
        manager = get_plugin_manager()
        manager.enable_plugin(plugin_id)
        
        return jsonify({
            'success': True,
            'message': f'Plugin enabled: {plugin_id}',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Enable plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/disable', methods=['POST'])
def disable_plugin(plugin_id):
    """Disable a plugin"""
    try:
        manager = get_plugin_manager()
        manager.disable_plugin(plugin_id)
        
        return jsonify({
            'success': True,
            'message': f'Plugin disabled: {plugin_id}',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Disable plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/unload', methods=['POST'])
def unload_plugin(plugin_id):
    """Unload a plugin"""
    try:
        manager = get_plugin_manager()
        manager.unload_plugin(plugin_id)
        
        return jsonify({
            'success': True,
            'message': f'Plugin unloaded: {plugin_id}',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Unload plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/config', methods=['GET'])
def get_plugin_config(plugin_id):
    """Get plugin configuration"""
    try:
        manager = get_plugin_manager()
        plugin = manager.get_plugin(plugin_id)
        
        if not plugin or not plugin.config:
            return jsonify({
                'success': False,
                'error': 'Plugin or config not found'
            }), 404
        
        return jsonify({
            'success': True,
            'config': {
                'enabled': plugin.config.enabled,
                'settings': plugin.config.settings
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Get config error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/config', methods=['PUT'])
def update_plugin_config(plugin_id):
    """Update plugin configuration"""
    try:
        data = request.get_json() or {}
        settings = data.get('settings', {})
        
        manager = get_plugin_manager()
        manager.update_plugin_config(plugin_id, settings)
        
        return jsonify({
            'success': True,
            'message': f'Config updated: {plugin_id}',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Update config error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/validate', methods=['GET'])
def validate_plugin(plugin_id):
    """Validate a plugin"""
    try:
        manager = get_plugin_manager()
        is_valid = manager.validate_plugin(plugin_id)
        
        return jsonify({
            'success': True,
            'plugin_id': plugin_id,
            'valid': is_valid,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Validate plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# Marketplace Endpoints
# ============================================================================

@plugin_bp.route('/marketplace/list', methods=['GET'])
def list_marketplace():
    """List plugins in marketplace"""
    try:
        manager = get_plugin_manager()
        category = request.args.get('category')
        
        plugins = manager.list_marketplace(category=category)
        
        return jsonify({
            'success': True,
            'plugins': plugins,
            'count': len(plugins),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"List marketplace error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/marketplace/search', methods=['GET'])
def search_marketplace():
    """Search marketplace plugins"""
    try:
        query = request.args.get('q', '')
        
        if not query:
            return jsonify({
                'success': False,
                'error': 'Search query required'
            }), 400
        
        manager = get_plugin_manager()
        results = manager.search_marketplace(query)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Search marketplace error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/marketplace/install', methods=['POST'])
def install_plugin():
    """Install a plugin from marketplace"""
    try:
        data = request.get_json() or {}
        plugin_url = data.get('url')
        plugin_id = data.get('plugin_id')
        
        if not plugin_url or not plugin_id:
            return jsonify({
                'success': False,
                'error': 'Missing url or plugin_id'
            }), 400
        
        # Download plugin
        response = requests.get(plugin_url, timeout=30)
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'error': 'Failed to download plugin'
            }), 400
        
        # Extract and install
        manager = get_plugin_manager()
        plugins_dir = manager.plugins_dir / plugin_id
        
        # Create zip file and extract
        zip_path = manager.plugins_dir / f"{plugin_id}.zip"
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        # Extract
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(plugins_dir)
        
        # Clean up zip
        zip_path.unlink()
        
        # Load plugin
        manager.load_plugin(plugins_dir)
        
        return jsonify({
            'success': True,
            'message': f'Plugin installed: {plugin_id}',
            'plugin_id': plugin_id,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Install plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@plugin_bp.route('/<plugin_id>/uninstall', methods=['POST'])
def uninstall_plugin(plugin_id):
    """Uninstall a plugin"""
    try:
        manager = get_plugin_manager()
        
        # Unload plugin
        manager.unload_plugin(plugin_id)
        
        # Remove plugin directory
        plugin_dir = manager.plugins_dir / plugin_id
        if plugin_dir.exists():
            shutil.rmtree(plugin_dir)
        
        return jsonify({
            'success': True,
            'message': f'Plugin uninstalled: {plugin_id}',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Uninstall plugin error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# WebSocket Events
# ============================================================================

from main import socketio

@socketio.on('plugins:list', namespace='/plugins')
def handle_list_plugins():
    """Get list of plugins"""
    try:
        manager = get_plugin_manager()
        plugins = manager.list_plugins()
        
        emit('plugins:list_response', {
            'success': True,
            'plugins': plugins,
            'count': len(plugins)
        })
    except Exception as e:
        logger.error(f"List plugins error: {str(e)}")
        emit('error', {'message': str(e)})

@socketio.on('plugins:execute', namespace='/plugins')
def handle_execute_plugin(data):
    """Execute a plugin"""
    try:
        plugin_id = data.get('plugin_id')
        params = data.get('params', {})
        
        manager = get_plugin_manager()
        result = manager.execute_plugin(plugin_id, **params)
        
        emit('plugins:execution_complete', {
            'success': True,
            'plugin_id': plugin_id,
            'result': result
        })
    except Exception as e:
        logger.error(f"Execute plugin error: {str(e)}")
        emit('error', {'message': str(e)})

@socketio.on('plugins:status', namespace='/plugins')
def handle_plugin_status():
    """Get plugin system status"""
    try:
        manager = get_plugin_manager()
        validation_results = manager.validate_all_plugins()
        
        emit('plugins:status_update', {
            'plugins_loaded': len(manager.plugins),
            'plugins_valid': sum(1 for v in validation_results.values() if v),
            'validation_results': validation_results
        })
    except Exception as e:
        logger.error(f"Status error: {str(e)}")
        emit('error', {'message': str(e)})
