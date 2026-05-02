/**
 * AI Recommendations Page
 * Get intelligent tool and strategy recommendations
 */

import React, { useState } from 'react';
import { Zap, Loader, AlertCircle, Target, Lightbulb } from 'lucide-react';
import axios from 'axios';

const AIRecommendations = () => {
  const [activeTab, setActiveTab] = useState('tools');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  // Tools Recommendation Form
  const [toolsForm, setToolsForm] = useState({
    target_type: 'web_app',
    os_type: '',
    services: '',
    skill_level: 'intermediate',
  });

  // Attack Roadmap Form
  const [roadmapForm, setRoadmapForm] = useState({
    target_info: '',
    goals: '',
  });

  // Remediation Form
  const [remediationForm, setRemediationForm] = useState({
    vulnerability_type: '',
    severity: 'medium',
    affected_component: '',
  });

  // Learning Path Form
  const [learningForm, setLearningForm] = useState({
    current_skills: '',
    target_skills: '',
    available_time: '3 months',
  });

  const getToolRecommendations = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/recommendations/tools', {
        target_type: toolsForm.target_type,
        os_type: toolsForm.os_type || undefined,
        services: toolsForm.services
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        skill_level: toolsForm.skill_level,
      });

      setResults(response.data);
    } catch (error) {
      setResults({
        success: false,
        error: error.response?.data?.error || error.message,
      });
    } finally {
      setLoading(false);
    }
  };

  const getAttackRoadmap = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/recommendations/attack-roadmap', {
        target_info: roadmapForm.target_info,
        goals: roadmapForm.goals
          .split(',')
          .map((g) => g.trim())
          .filter(Boolean),
      });

      setResults(response.data);
    } catch (error) {
      setResults({
        success: false,
        error: error.response?.data?.error || error.message,
      });
    } finally {
      setLoading(false);
    }
  };

  const getRemediationRecommendations = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/recommendations/remediation', {
        vulnerability_type: remediationForm.vulnerability_type,
        severity: remediationForm.severity,
        affected_component: remediationForm.affected_component,
      });

      setResults(response.data);
    } catch (error) {
      setResults({
        success: false,
        error: error.response?.data?.error || error.message,
      });
    } finally {
      setLoading(false);
    }
  };

  const getLearningPath = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/recommendations/learning-path', {
        current_skills: learningForm.current_skills
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        target_skills: learningForm.target_skills
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        available_time: learningForm.available_time,
      });

      setResults(response.data);
    } catch (error) {
      setResults({
        success: false,
        error: error.response?.data?.error || error.message,
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-linear-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <div className="bg-linear-to-r from-cyan-900 to-blue-900 border-b border-cyan-500 p-6">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-4xl font-bold text-cyan-300 flex items-center gap-3 mb-2">
            <Lightbulb className="w-10 h-10" />
            Smart Recommendations
          </h1>
          <p className="text-cyan-200">AI-powered recommendations for tools, strategies, and learning paths</p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6">
        {/* Tabs */}
        <div className="flex gap-4 mb-6 border-b border-slate-700">
          {[
            { id: 'tools', label: '🛠️ Tools', icon: Target },
            { id: 'roadmap', label: '🗺️ Attack Roadmap', icon: Zap },
            { id: 'remediation', label: '🔧 Remediation', icon: AlertCircle },
            { id: 'learning', label: '📚 Learning Path', icon: Lightbulb },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => {
                setActiveTab(id);
                setResults(null);
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

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Input Panel */}
          <div className="lg:col-span-1">
            <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 sticky top-6">
              <h2 className="text-cyan-400 font-bold mb-4">Configuration</h2>

              {/* Tools Tab */}
              {activeTab === 'tools' && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-300">Target Type</label>
                    <select
                      value={toolsForm.target_type}
                      onChange={(e) =>
                        setToolsForm({ ...toolsForm, target_type: e.target.value })
                      }
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    >
                      <option value="web_app">Web Application</option>
                      <option value="network">Network</option>
                      <option value="mobile">Mobile</option>
                      <option value="api">API</option>
                      <option value="cloud">Cloud</option>
                      <option value="wifi">WiFi</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">OS Type (optional)</label>
                    <input
                      type="text"
                      value={toolsForm.os_type}
                      onChange={(e) =>
                        setToolsForm({ ...toolsForm, os_type: e.target.value })
                      }
                      placeholder="Windows, Linux, macOS"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Services (comma-separated)</label>
                    <input
                      type="text"
                      value={toolsForm.services}
                      onChange={(e) =>
                        setToolsForm({ ...toolsForm, services: e.target.value })
                      }
                      placeholder="Apache, PHP, MySQL"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Skill Level</label>
                    <select
                      value={toolsForm.skill_level}
                      onChange={(e) =>
                        setToolsForm({ ...toolsForm, skill_level: e.target.value })
                      }
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    >
                      <option value="beginner">Beginner</option>
                      <option value="intermediate">Intermediate</option>
                      <option value="advanced">Advanced</option>
                    </select>
                  </div>

                  <button
                    onClick={getToolRecommendations}
                    disabled={loading}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white py-2 rounded font-semibold transition flex items-center justify-center gap-2"
                  >
                    {loading && <Loader className="w-4 h-4 animate-spin" />}
                    Get Recommendations
                  </button>
                </div>
              )}

              {/* Attack Roadmap Tab */}
              {activeTab === 'roadmap' && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-300">Target Information</label>
                    <textarea
                      value={roadmapForm.target_info}
                      onChange={(e) =>
                        setRoadmapForm({ ...roadmapForm, target_info: e.target.value })
                      }
                      placeholder="Describe the target..."
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1 h-20"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Goals (comma-separated)</label>
                    <input
                      type="text"
                      value={roadmapForm.goals}
                      onChange={(e) =>
                        setRoadmapForm({ ...roadmapForm, goals: e.target.value })
                      }
                      placeholder="Data extraction, privilege escalation"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <button
                    onClick={getAttackRoadmap}
                    disabled={loading || !roadmapForm.target_info}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white py-2 rounded font-semibold transition flex items-center justify-center gap-2"
                  >
                    {loading && <Loader className="w-4 h-4 animate-spin" />}
                    Generate Roadmap
                  </button>
                </div>
              )}

              {/* Remediation Tab */}
              {activeTab === 'remediation' && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-300">Vulnerability Type</label>
                    <input
                      type="text"
                      value={remediationForm.vulnerability_type}
                      onChange={(e) =>
                        setRemediationForm({
                          ...remediationForm,
                          vulnerability_type: e.target.value,
                        })
                      }
                      placeholder="SQL Injection, XSS, etc."
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Severity</label>
                    <select
                      value={remediationForm.severity}
                      onChange={(e) =>
                        setRemediationForm({
                          ...remediationForm,
                          severity: e.target.value,
                        })
                      }
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Affected Component</label>
                    <input
                      type="text"
                      value={remediationForm.affected_component}
                      onChange={(e) =>
                        setRemediationForm({
                          ...remediationForm,
                          affected_component: e.target.value,
                        })
                      }
                      placeholder="Login form, database, etc."
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <button
                    onClick={getRemediationRecommendations}
                    disabled={loading || !remediationForm.vulnerability_type}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white py-2 rounded font-semibold transition flex items-center justify-center gap-2"
                  >
                    {loading && <Loader className="w-4 h-4 animate-spin" />}
                    Get Remediation
                  </button>
                </div>
              )}

              {/* Learning Path Tab */}
              {activeTab === 'learning' && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-300">Current Skills (comma-separated)</label>
                    <input
                      type="text"
                      value={learningForm.current_skills}
                      onChange={(e) =>
                        setLearningForm({
                          ...learningForm,
                          current_skills: e.target.value,
                        })
                      }
                      placeholder="Networking, Linux basics"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Target Skills (comma-separated)</label>
                    <input
                      type="text"
                      value={learningForm.target_skills}
                      onChange={(e) =>
                        setLearningForm({
                          ...learningForm,
                          target_skills: e.target.value,
                        })
                      }
                      placeholder="Web penetration testing, exploitation"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <div>
                    <label className="text-sm text-slate-300">Available Time</label>
                    <input
                      type="text"
                      value={learningForm.available_time}
                      onChange={(e) =>
                        setLearningForm({
                          ...learningForm,
                          available_time: e.target.value,
                        })
                      }
                      placeholder="3 months"
                      className="w-full bg-slate-700 border border-slate-600 rounded px-3 py-2 text-white text-sm mt-1"
                    />
                  </div>

                  <button
                    onClick={getLearningPath}
                    disabled={loading || !learningForm.target_skills}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white py-2 rounded font-semibold transition flex items-center justify-center gap-2"
                  >
                    {loading && <Loader className="w-4 h-4 animate-spin" />}
                    Generate Path
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-3">
            {loading ? (
              <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 flex items-center justify-center h-96">
                <div className="text-center">
                  <Loader className="w-12 h-12 animate-spin mx-auto mb-4 text-cyan-400" />
                  <p className="text-slate-300">Generating AI recommendations...</p>
                </div>
              </div>
            ) : results ? (
              <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
                {results.success ? (
                  <div className="space-y-4">
                    {results.recommendations && (
                      <div>
                        <h3 className="text-xl font-bold text-cyan-300 mb-4">Recommended Tools</h3>
                        <div className="grid grid-cols-1 gap-3">
                          {results.recommendations.map((tool, idx) => (
                            <div
                              key={idx}
                              className="bg-slate-700 border border-slate-600 rounded p-4 hover:border-cyan-500 transition"
                            >
                              <div className="flex justify-between items-start mb-2">
                                <h4 className="text-cyan-300 font-bold">{tool.name}</h4>
                                <span className="text-xs bg-cyan-600 text-white px-2 py-1 rounded">
                                  {tool.category}
                                </span>
                              </div>
                              <p className="text-slate-300 text-sm mb-2">{tool.purpose}</p>
                              <div className="flex gap-2">
                                <a
                                  href={tool.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-cyan-400 hover:text-cyan-300 text-sm"
                                >
                                  Visit Website →
                                </a>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {results.ai_strategy && (
                      <div>
                        <h3 className="text-xl font-bold text-cyan-300 mb-4">AI Strategy</h3>
                        <div className="bg-slate-700 rounded p-4 border border-slate-600">
                          <p className="text-slate-300 whitespace-pre-wrap text-sm">
                            {results.ai_strategy}
                          </p>
                        </div>
                      </div>
                    )}

                    {results.roadmap && (
                      <div>
                        <h3 className="text-xl font-bold text-cyan-300 mb-4">Attack Roadmap</h3>
                        <div className="bg-slate-700 rounded p-4 border border-slate-600">
                          <p className="text-slate-300 whitespace-pre-wrap text-sm">
                            {results.roadmap}
                          </p>
                        </div>
                      </div>
                    )}

                    {results.recommendations && (
                      <div>
                        <h3 className="text-xl font-bold text-cyan-300 mb-4">Recommendations</h3>
                        <div className="bg-slate-700 rounded p-4 border border-slate-600">
                          <p className="text-slate-300 whitespace-pre-wrap text-sm">
                            {results.recommendations}
                          </p>
                        </div>
                      </div>
                    )}

                    {results.learning_path && (
                      <div>
                        <h3 className="text-xl font-bold text-cyan-300 mb-4">Learning Path</h3>
                        <div className="bg-slate-700 rounded p-4 border border-slate-600">
                          <p className="text-slate-300 whitespace-pre-wrap text-sm">
                            {results.learning_path}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center gap-3 text-red-400">
                    <AlertCircle className="w-6 h-6" />
                    <p>{results.error}</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 text-center text-slate-400">
                <Lightbulb className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>Configure options and click a button to get recommendations</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIRecommendations;
