/**
 * Phase 4: Workflow Templates & Execution UI
 * Browse, execute, and manage workflow templates
 */

import React, { useState, useEffect } from 'react';
import './WorkflowTemplates.css';

const WorkflowTemplates = () => {
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [category, setCategory] = useState('all');
  const [difficulty, setDifficulty] = useState('all');
  const [executionModal, setExecutionModal] = useState(false);
  const [inputValues, setInputValues] = useState({});
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load templates on mount
  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (category !== 'all') params.append('category', category);
      if (difficulty !== 'all') params.append('difficulty', difficulty);

      const response = await fetch(`/api/workflows/templates?${params}`);
      if (!response.ok) throw new Error('Failed to load templates');

      const data = await response.json();
      setTemplates(data.templates || []);
    } catch (err) {
      setError(err.message);
      console.error('Error loading templates:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTemplates();
  }, [category, difficulty]);

  const handleExecuteTemplate = (template) => {
    setSelectedTemplate(template);
    
    // Initialize input values
    const initialValues = {};
    template.inputs?.forEach(input => {
      initialValues[input.name] = input.default || '';
    });
    setInputValues(initialValues);
    
    setExecutionModal(true);
  };

  const handleInputChange = (inputName, value) => {
    setInputValues(prev => ({
      ...prev,
      [inputName]: value
    }));
  };

  const executeWorkflow = async () => {
    if (!selectedTemplate) return;

    try {
      setExecuting(true);
      setError(null);

      const response = await fetch('/api/workflows/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          template_id: selectedTemplate.id,
          inputs: inputValues
        })
      });

      if (!response.ok) throw new Error('Execution failed');

      const data = await response.json();
      setExecutionResult(data);
      
      // Start polling for status updates
      pollExecutionStatus(data.execution_id);
    } catch (err) {
      setError(err.message);
      console.error('Execution error:', err);
    } finally {
      setExecuting(false);
    }
  };

  const pollExecutionStatus = async (executionId) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/workflows/execution/${executionId}`);
        if (!response.ok) throw new Error('Status check failed');

        const data = await response.json();
        setExecutionResult({ execution: data });

        // Stop polling when workflow completes
        if (data.status !== 'running' && data.status !== 'pending') {
          clearInterval(pollInterval);
        }
      } catch (err) {
        console.error('Status check error:', err);
        clearInterval(pollInterval);
      }
    }, 2000);
  };

  const closeExecutionModal = () => {
    setExecutionModal(false);
    setSelectedTemplate(null);
    setInputValues({});
    setExecutionResult(null);
  };

  const getDifficultyColor = (difficulty) => {
    switch (difficulty) {
      case 'beginner':
        return 'text-green-400';
      case 'intermediate':
        return 'text-yellow-400';
      case 'advanced':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  const getCategoryEmoji = (category) => {
    const emojis = {
      web: '🌐',
      network: '🌍',
      mobile: '📱',
      cloud: '☁️',
      general: '⚡'
    };
    return emojis[category] || '🎯';
  };

  return (
    <div className="workflow-templates-container">
      <div className="templates-header">
        <h1>🚀 Workflow Templates</h1>
        <p>Pre-built penetration testing workflows for rapid security assessments</p>
      </div>

      {/* Filters */}
      <div className="templates-filters">
        <div className="filter-group">
          <label>Category:</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="all">All Categories</option>
            <option value="web">Web</option>
            <option value="network">Network</option>
            <option value="mobile">Mobile</option>
            <option value="cloud">Cloud</option>
            <option value="general">General</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Difficulty:</label>
          <select value={difficulty} onChange={(e) => setDifficulty(e.target.value)}>
            <option value="all">All Levels</option>
            <option value="beginner">Beginner</option>
            <option value="intermediate">Intermediate</option>
            <option value="advanced">Advanced</option>
          </select>
        </div>
      </div>

      {/* Templates Grid */}
      <div className="templates-grid">
        {loading ? (
          <div className="loading-spinner">Loading templates...</div>
        ) : error ? (
          <div className="error-message">{error}</div>
        ) : templates.length === 0 ? (
          <div className="no-templates">No templates found</div>
        ) : (
          templates.map(template => (
            <div key={template.id} className="template-card">
              <div className="template-header">
                <span className="template-icon">{getCategoryEmoji(template.category)}</span>
                <h3>{template.name}</h3>
              </div>

              <p className="template-description">{template.description}</p>

              <div className="template-metadata">
                <span className={`difficulty ${getDifficultyColor(template.difficulty)}`}>
                  {template.difficulty.toUpperCase()}
                </span>
                <span className="category">{template.category}</span>
                {template.estimated_time && (
                  <span className="time">⏱️ {template.estimated_time}min</span>
                )}
              </div>

              {template.tags && template.tags.length > 0 && (
                <div className="template-tags">
                  {template.tags.map(tag => (
                    <span key={tag} className="tag">{tag}</span>
                  ))}
                </div>
              )}

              {template.best_practices && template.best_practices.length > 0 && (
                <div className="best-practices">
                  <strong>Best Practices:</strong>
                  <ul>
                    {template.best_practices.slice(0, 2).map((practice, idx) => (
                      <li key={idx}>{practice}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="template-actions">
                <button 
                  className="btn-primary"
                  onClick={() => handleExecuteTemplate(template)}
                >
                  Execute Workflow
                </button>
                <button className="btn-secondary">
                  View Details
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Execution Modal */}
      {executionModal && selectedTemplate && (
        <div className="modal-overlay">
          <div className="modal-content execution-modal">
            <div className="modal-header">
              <h2>Execute: {selectedTemplate.name}</h2>
              <button className="close-btn" onClick={closeExecutionModal}>×</button>
            </div>

            {!executionResult ? (
              <>
                <div className="modal-body">
                  <p className="template-description">{selectedTemplate.description}</p>

                  {selectedTemplate.inputs && selectedTemplate.inputs.length > 0 && (
                    <div className="inputs-section">
                      <h3>Workflow Inputs</h3>
                      {selectedTemplate.inputs.map(input => (
                        <div key={input.name} className="input-group">
                          <label>
                            {input.name}
                            {input.required && <span className="required">*</span>}
                          </label>
                          <p className="input-description">{input.description}</p>

                          {input.type === 'select' ? (
                            <select
                              value={inputValues[input.name] || ''}
                              onChange={(e) => handleInputChange(input.name, e.target.value)}
                            >
                              <option value="">-- Select {input.name} --</option>
                              {input.options?.map(opt => (
                                <option key={opt} value={opt}>{opt}</option>
                              ))}
                            </select>
                          ) : input.type === 'boolean' ? (
                            <div className="boolean-input">
                              <label className="checkbox">
                                <input
                                  type="checkbox"
                                  checked={inputValues[input.name] || false}
                                  onChange={(e) => handleInputChange(input.name, e.target.checked)}
                                />
                                Enable
                              </label>
                            </div>
                          ) : (
                            <input
                              type={input.type === 'number' ? 'number' : 'text'}
                              value={inputValues[input.name] || ''}
                              placeholder={input.default ? `Default: ${input.default}` : ''}
                              onChange={(e) => handleInputChange(input.name, e.target.value)}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {selectedTemplate.steps && (
                    <div className="workflow-steps-preview">
                      <h3>Workflow Steps ({selectedTemplate.steps.length})</h3>
                      <div className="steps-list">
                        {selectedTemplate.steps.map((step, idx) => (
                          <div key={step.id} className="step-item">
                            <span className="step-number">{idx + 1}</span>
                            <div className="step-info">
                              <strong>{step.name}</strong>
                              <p>{step.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="modal-footer">
                  <button 
                    className="btn-secondary" 
                    onClick={closeExecutionModal}
                  >
                    Cancel
                  </button>
                  <button 
                    className="btn-primary" 
                    onClick={executeWorkflow}
                    disabled={executing}
                  >
                    {executing ? 'Executing...' : 'Execute Now'}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="modal-body execution-result">
                  <h3>Execution Status</h3>
                  <div className="execution-info">
                    <div className="info-row">
                      <span>Execution ID:</span>
                      <code>{executionResult.execution_id}</code>
                    </div>
                    <div className="info-row">
                      <span>Status:</span>
                      <span className={`status ${executionResult.execution?.status || 'pending'}`}>
                        {(executionResult.execution?.status || 'pending').toUpperCase()}
                      </span>
                    </div>
                    <div className="info-row">
                      <span>Progress:</span>
                      <div className="progress-bar">
                        <div 
                          className="progress-fill"
                          style={{width: `${(executionResult.execution?.progress || 0) * 100}%`}}
                        ></div>
                      </div>
                      <span>{Math.round((executionResult.execution?.progress || 0) * 100)}%</span>
                    </div>

                    {executionResult.execution?.current_step && (
                      <div className="info-row">
                        <span>Current Step:</span>
                        <span>{executionResult.execution.current_step}</span>
                      </div>
                    )}

                    {executionResult.execution?.completed_steps?.length > 0 && (
                      <div className="info-row">
                        <span>Completed Steps:</span>
                        <span>{executionResult.execution.completed_steps.length}</span>
                      </div>
                    )}
                  </div>

                  {executionResult.execution?.status === 'completed' && (
                    <div className="execution-complete">
                      <h4>✅ Workflow Completed Successfully!</h4>
                      {executionResult.execution?.results && (
                        <div className="ai-results-container">
                          {Object.entries(executionResult.execution.results).map(([stepId, result]) => (
                            <div key={stepId} className="ai-step-result">
                              <h5 className="step-title">🤖 Output: {stepId}</h5>
                              {result.error ? (
                                <div className="step-error">❌ Error: {result.error}</div>
                              ) : (
                                <pre className="step-output">
                                  {typeof result.output === 'string' 
                                    ? result.output 
                                    : JSON.stringify(result.output || result, null, 2)}
                                </pre>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {executionResult.execution?.status === 'failed' && (
                    <div className="execution-failed">
                      <h4>❌ Workflow Failed</h4>
                      {executionResult.execution?.errors && (
                        <div className="errors-list">
                          {executionResult.execution.errors.map((err, idx) => (
                            <div key={idx} className="error-item">
                              <strong>{err.step || 'Workflow'}:</strong>
                              <p>{err.error}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <div className="modal-footer">
                  <button 
                    className="btn-secondary" 
                    onClick={closeExecutionModal}
                  >
                    {executionResult.execution?.status === 'running' ? 'Monitor in Background' : 'Close'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default WorkflowTemplates;
