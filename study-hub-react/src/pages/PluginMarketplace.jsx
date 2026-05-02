/**
 * Plugin Marketplace
 * Browse, search, install, and manage plugins
 */

import React, { useState, useEffect } from 'react';
import {
  Zap,
  Search,
  Download,
  Settings,
  Trash2,
  ChevronDown,
  Star,
  AlertCircle,
  Loader,
} from 'lucide-react';
import axios from 'axios';

const PluginMarketplace = () => {
  const [activeTab, setActiveTab] = useState('marketplace');
  const [plugins, setPlugins] = useState([]);
  const [installed, setInstalled] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPlugin, setSelectedPlugin] = useState(null);
  const [expandedPlugin, setExpandedPlugin] = useState(null);

  // Load plugins on mount
  useEffect(() => {
    loadPlugins();
    loadInstalledPlugins();
  }, [activeTab]);

  const loadPlugins = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/plugins/marketplace/list');
      if (response.data.success) {
        setPlugins(response.data.plugins);
      }
    } catch (error) {
      console.error('Error loading plugins:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadInstalledPlugins = async () => {
    try {
      const response = await axios.get('/api/plugins/list');
      if (response.data.success) {
        setInstalled(response.data.plugins);
      }
    } catch (error) {
      console.error('Error loading installed plugins:', error);
    }
  };

  const searchPlugins = async (query) => {
    if (!query.trim()) {
      loadPlugins();
      return;
    }

    setLoading(true);
    try {
      const response = await axios.get('/api/plugins/marketplace/search', {
        params: { q: query },
      });
      if (response.data.success) {
        setPlugins(response.data.results);
      }
    } catch (error) {
      console.error('Error searching plugins:', error);
    } finally {
      setLoading(false);
    }
  };

  const installPlugin = async (plugin) => {
    setLoading(true);
    try {
      const response = await axios.post('/api/plugins/marketplace/install', {
        plugin_id: plugin.id,
        url: plugin.download_url,
      });

      if (response.data.success) {
        alert(`✅ Plugin installed: ${plugin.name}`);
        loadInstalledPlugins();
        setActiveTab('installed');
      }
    } catch (error) {
      alert(`❌ Installation failed: ${error.response?.data?.error || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const uninstallPlugin = async (pluginId) => {
    if (!confirm('Are you sure you want to uninstall this plugin?')) return;

    setLoading(true);
    try {
      const response = await axios.post(`/api/plugins/${pluginId}/uninstall`);

      if (response.data.success) {
        alert('Plugin uninstalled successfully');
        loadInstalledPlugins();
      }
    } catch (error) {
      alert(`❌ Uninstall failed: ${error.response?.data?.error || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const enablePlugin = async (pluginId) => {
    try {
      const response = await axios.post(`/api/plugins/${pluginId}/enable`);
      if (response.data.success) {
        loadInstalledPlugins();
      }
    } catch (error) {
      alert(`Error: ${error.response?.data?.error || error.message}`);
    }
  };

  const disablePlugin = async (pluginId) => {
    try {
      const response = await axios.post(`/api/plugins/${pluginId}/disable`);
      if (response.data.success) {
        loadInstalledPlugins();
      }
    } catch (error) {
      alert(`Error: ${error.response?.data?.error || error.message}`);
    }
  };

  const PluginCard = ({ plugin, isInstalled = false }) => {
    const isExpanded = expandedPlugin === plugin.id;

    return (
      <div
        key={plugin.id}
        className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden hover:border-cyan-500 transition"
      >
        <div className="p-4">
          <div className="flex justify-between items-start mb-3">
            <div className="flex-1">
              <h3 className="text-lg font-bold text-cyan-300">{plugin.name}</h3>
              <p className="text-sm text-slate-400">{plugin.author}</p>
            </div>
            <div className="flex items-center gap-1">
              {[...Array(5)].map((_, i) => (
                <Star
                  key={i}
                  className={`w-4 h-4 ${
                    i < (plugin.rating || 0)
                      ? 'fill-yellow-400 text-yellow-400'
                      : 'text-slate-600'
                  }`}
                />
              ))}
            </div>
          </div>

          <p className="text-sm text-slate-300 mb-3">{plugin.description}</p>

          <div className="flex flex-wrap gap-2 mb-4">
            {plugin.keywords?.map((keyword) => (
              <span
                key={keyword}
                className="text-xs bg-slate-700 text-cyan-300 px-2 py-1 rounded"
              >
                {keyword}
              </span>
            ))}
          </div>

          <div className="flex justify-between items-center text-sm text-slate-400 mb-4">
            <span>v{plugin.version}</span>
            <span>{plugin.downloads || 0} downloads</span>
          </div>

          {/* Expanded Details */}
          {isExpanded && (
            <div className="bg-slate-700 rounded p-3 mb-4 border border-slate-600">
              <div className="space-y-3">
                {plugin.capabilities && plugin.capabilities.length > 0 && (
                  <div>
                    <h4 className="text-cyan-300 font-semibold mb-2">Capabilities</h4>
                    <div className="space-y-2">
                      {plugin.capabilities.map((cap, idx) => (
                        <div key={idx} className="text-sm text-slate-300">
                          <span className="text-cyan-400">• {cap.name}</span>
                          <p className="text-xs text-slate-400 ml-4">{cap.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {plugin.settings && (
                  <div>
                    <h4 className="text-cyan-300 font-semibold mb-2">Configuration</h4>
                    <div className="text-sm text-slate-300 space-y-1">
                      {Object.entries(plugin.settings).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-slate-400">{key}:</span>
                          <span className="text-cyan-300">{JSON.stringify(value)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2">
            {isInstalled ? (
              <>
                <button
                  onClick={() => setExpandedPlugin(isExpanded ? null : plugin.id)}
                  className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2 rounded text-sm flex items-center justify-center gap-2 transition"
                >
                  <ChevronDown
                    className={`w-4 h-4 transition ${
                      isExpanded ? 'rotate-180' : ''
                    }`}
                  />
                  Details
                </button>

                {plugin.enabled ? (
                  <button
                    onClick={() => disablePlugin(plugin.id)}
                    className="flex-1 bg-yellow-600 hover:bg-yellow-700 text-white py-2 rounded text-sm transition"
                  >
                    Disable
                  </button>
                ) : (
                  <button
                    onClick={() => enablePlugin(plugin.id)}
                    className="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded text-sm transition"
                  >
                    Enable
                  </button>
                )}

                <button
                  onClick={() => uninstallPlugin(plugin.id)}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm transition"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => setExpandedPlugin(isExpanded ? null : plugin.id)}
                  className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2 rounded text-sm flex items-center justify-center gap-2 transition"
                >
                  <ChevronDown
                    className={`w-4 h-4 transition ${
                      isExpanded ? 'rotate-180' : ''
                    }`}
                  />
                  Details
                </button>

                <button
                  onClick={() => installPlugin(plugin)}
                  disabled={loading}
                  className="flex-1 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white py-2 rounded text-sm flex items-center justify-center gap-2 transition"
                >
                  {loading ? (
                    <Loader className="w-4 h-4 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  Install
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <div className="bg-linear-to-r from-cyan-900 to-blue-900 border-b border-cyan-500 p-6">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl font-bold text-cyan-300 flex items-center gap-3 mb-2">
            <Zap className="w-10 h-10" />
            Plugin Marketplace
          </h1>
          <p className="text-cyan-200">
            Discover, install, and manage plugins for ShadowHack Elite
          </p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6">
        {/* Tabs */}
        <div className="flex gap-4 mb-6 border-b border-slate-700">
          {[
            { id: 'marketplace', label: '🏪 Marketplace' },
            { id: 'installed', label: '✅ Installed' },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => {
                setActiveTab(id);
                setSearchQuery('');
              }}
              className={`px-4 py-2 font-semibold transition ${
                activeTab === id
                  ? 'border-b-2 border-cyan-500 text-cyan-300'
                  : 'text-slate-400 hover:text-cyan-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Search Bar */}
        {activeTab === 'marketplace' && (
          <div className="mb-6 flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-3 w-5 h-5 text-slate-500" />
              <input
                type="text"
                placeholder="Search plugins..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  searchPlugins(e.target.value);
                }}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        )}

        {/* Content */}
        {loading && activeTab === 'marketplace' ? (
          <div className="flex items-center justify-center h-96">
            <Loader className="w-12 h-12 animate-spin text-cyan-400" />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {activeTab === 'marketplace' && plugins.length > 0
              ? plugins.map((plugin) => (
                  <PluginCard key={plugin.id} plugin={plugin} isInstalled={false} />
                ))
              : activeTab === 'installed' && installed.length > 0
                ? installed.map((plugin) => (
                    <PluginCard key={plugin.id} plugin={plugin} isInstalled={true} />
                  ))
                : null}
          </div>
        )}

        {/* Empty State */}
        {!loading && plugins.length === 0 && activeTab === 'marketplace' && (
          <div className="text-center py-12">
            <AlertCircle className="w-12 h-12 mx-auto mb-4 text-slate-500" />
            <p className="text-slate-400">
              {searchQuery ? 'No plugins found' : 'No plugins available in marketplace'}
            </p>
          </div>
        )}

        {installed.length === 0 && activeTab === 'installed' && (
          <div className="text-center py-12">
            <Zap className="w-12 h-12 mx-auto mb-4 text-slate-500" />
            <p className="text-slate-400">No plugins installed yet</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default PluginMarketplace;
