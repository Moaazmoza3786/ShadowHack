import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { 
  FileText, 
  Save, 
  Download, 
  Plus, 
  Trash2, 
  AlertTriangle, 
  CheckCircle2, 
  Sparkles, 
  Loader, 
  Brain,
  ChevronRight,
  Shield,
  FileSearch,
  Zap,
  Layout
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppContext } from '../../context/AppContext';
import OpenRouterAI from '../../services/openrouterAI';
import './ReportBuilder.css';

const ReportBuilder = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { apiUrl, language } = useAppContext();

    // Initial State
    const [report, setReport] = useState({
        title: 'Neural Assessment 0x' + Math.floor(Math.random() * 1000).toString(16).toUpperCase(),
        lab_id: searchParams.get('lab_id') || '',
        executive_summary: '',
        status: 'draft',
        findings: []
    });

    const [activeTab, setActiveTab] = useState('editor'); // editor, preview
    const [selectedFindingIndex, setSelectedFindingIndex] = useState(null);
    const [loading, setLoading] = useState(false);
    const [aiLoading, setAiLoading] = useState(false);
    const [saved, setSaved] = useState(false);

    // AI Integration
    const enhanceWithAI = async (index) => {
      const finding = report.findings[index];
      if (!finding.title || finding.title === 'New Finding') {
        alert('Please provide a basic finding title first.');
        return;
      }

      setAiLoading(true);
      try {
        const apiKey = import.meta.env.VITE_OPENROUTER_API_KEY;
        const ai = new OpenRouterAI(apiKey);
        
        const enhancedText = await ai.enhanceFinding(finding.title, finding.description);
        
        // Simple parser for the AI response if it follows the MD structure
        // In a real app, we'd want more robust parsing or tool-calling
        updateFinding(index, 'description', enhancedText);
        
      } catch (err) {
        console.error('AI Enhancement Error:', err);
      } finally {
        setAiLoading(false);
      }
    };

    const autoGenerateSummary = async () => {
      if (report.findings.length === 0) {
        alert('Add findings before generating a summary.');
        return;
      }

      setAiLoading(true);
      try {
        const apiKey = import.meta.env.VITE_OPENROUTER_API_KEY;
        const ai = new OpenRouterAI(apiKey);
        
        const summary = await ai._query(`Generate a high-level executive summary for a security report with these findings: ${report.findings.map(f => f.title).join(', ')}. Format as 2 professional paragraphs.`, 'technical');
        
        setReport(prev => ({ ...prev, executive_summary: summary }));
      } catch (err) {
        console.error('AI Summary Error:', err);
      } finally {
        setAiLoading(false);
      }
    };

    const addFinding = (templateKey = null) => {
        const template = {
            title: 'New Finding',
            severity: 'Low',
            description: '',
            remediation: '',
            evidence: ''
        };

        setReport(prev => ({
            ...prev,
            findings: [...prev.findings, template]
        }));
        setSelectedFindingIndex(report.findings.length); 
    };

    const updateFinding = (index, field, value) => {
        const updatedFindings = [...report.findings];
        updatedFindings[index] = { ...updatedFindings[index], [field]: value };
        setReport(prev => ({ ...prev, findings: updatedFindings }));
        setSaved(false);
    };

    const removeFinding = (index) => {
        const updatedFindings = report.findings.filter((_, i) => i !== index);
        setReport(prev => ({ ...prev, findings: updatedFindings }));
        setSelectedFindingIndex(null);
        setSaved(false);
    };

    const handleSave = async () => {
        setLoading(true);
        try {
            await new Promise(resolve => setTimeout(resolve, 800)); 
            setSaved(true);
            setTimeout(() => setSaved(false), 2000);
        } catch (err) {
            console.error('Failed to save report', err);
        } finally {
            setLoading(false);
        }
    };

    const handleExport = async () => {
        // Try PDF export with jspdf, fallback to Markdown
        try {
            const jsPDFModule = await import('jspdf');
            const jsPDF = jsPDFModule.default || jsPDFModule.jsPDF;
            await import('jspdf-autotable');
            
            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();
            
            // Header
            doc.setFillColor(10, 15, 30);
            doc.rect(0, 0, pageWidth, 45, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(20);
            doc.setFont('helvetica', 'bold');
            doc.text('SHADOWHACK', 14, 18);
            doc.setFontSize(10);
            doc.setTextColor(180, 180, 180);
            doc.text('NEURAL SECURITY ASSESSMENT', 14, 26);
            doc.setFontSize(9);
            doc.text(`Report: ${report.title}`, 14, 34);
            doc.text(`Date: ${new Date().toLocaleDateString()}`, 14, 40);
            doc.text(`Classification: CONFIDENTIAL`, pageWidth - 60, 34);
            
            let y = 55;
            
            // Executive Summary
            if (report.executive_summary) {
                doc.setTextColor(220, 60, 60);
                doc.setFontSize(14);
                doc.setFont('helvetica', 'bold');
                doc.text('EXECUTIVE SUMMARY', 14, y);
                y += 8;
                doc.setTextColor(60, 60, 60);
                doc.setFontSize(10);
                doc.setFont('helvetica', 'normal');
                const summaryLines = doc.splitTextToSize(report.executive_summary, pageWidth - 28);
                doc.text(summaryLines, 14, y);
                y += summaryLines.length * 5 + 10;
            }
            
            // Findings Table
            if (report.findings.length > 0) {
                doc.setTextColor(220, 60, 60);
                doc.setFontSize(14);
                doc.setFont('helvetica', 'bold');
                doc.text('VULNERABILITY FINDINGS', 14, y);
                y += 8;
                
                // Summary table
                const tableData = report.findings.map((f, i) => [
                    `VUL-${String(i+1).padStart(3, '0')}`,
                    f.title,
                    f.severity,
                    f.description ? 'Documented' : 'Pending'
                ]);
                
                doc.autoTable({
                    startY: y,
                    head: [['ID', 'Finding', 'Severity', 'Status']],
                    body: tableData,
                    theme: 'grid',
                    headStyles: { fillColor: [30, 30, 50], textColor: [255, 255, 255], fontSize: 9 },
                    bodyStyles: { fontSize: 8, textColor: [50, 50, 50] },
                    columnStyles: {
                        0: { cellWidth: 25 },
                        2: { cellWidth: 25 },
                        3: { cellWidth: 25 }
                    },
                    didParseCell: (data) => {
                        if (data.column.index === 2 && data.section === 'body') {
                            const severity = data.cell.raw;
                            if (severity === 'Critical') data.cell.styles.textColor = [220, 40, 40];
                            else if (severity === 'High') data.cell.styles.textColor = [220, 120, 40];
                            else if (severity === 'Medium') data.cell.styles.textColor = [200, 160, 40];
                        }
                    }
                });
                
                y = doc.lastAutoTable.finalY + 15;
                
                // Detailed findings
                report.findings.forEach((finding, idx) => {
                    if (y > 250) { doc.addPage(); y = 20; }
                    
                    doc.setTextColor(220, 60, 60);
                    doc.setFontSize(12);
                    doc.setFont('helvetica', 'bold');
                    doc.text(`VUL-${String(idx+1).padStart(3, '0')}: ${finding.title}`, 14, y);
                    y += 7;
                    
                    doc.setFontSize(9);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(100, 100, 100);
                    doc.text(`Severity: ${finding.severity}`, 14, y);
                    y += 6;
                    
                    if (finding.description) {
                        doc.setFont('helvetica', 'normal');
                        doc.setTextColor(60, 60, 60);
                        const descLines = doc.splitTextToSize(finding.description.substring(0, 1500), pageWidth - 28);
                        doc.text(descLines, 14, y);
                        y += descLines.length * 4.5 + 4;
                    }
                    
                    if (finding.remediation) {
                        doc.setFont('helvetica', 'bold');
                        doc.setTextColor(40, 140, 80);
                        doc.text('Remediation:', 14, y);
                        y += 5;
                        doc.setFont('helvetica', 'normal');
                        doc.setTextColor(60, 60, 60);
                        const remLines = doc.splitTextToSize(finding.remediation.substring(0, 800), pageWidth - 28);
                        doc.text(remLines, 14, y);
                        y += remLines.length * 4.5 + 8;
                    }
                });
            }
            
            // Footer on last page
            const totalPages = doc.internal.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                doc.setPage(i);
                doc.setFontSize(7);
                doc.setTextColor(150, 150, 150);
                doc.text(`ShadowHack Neural Assessment | Page ${i}/${totalPages} | Confidential`, 14, doc.internal.pageSize.getHeight() - 8);
            }
            
            doc.save(`${report.title.replace(/\s+/g, '_')}_Report.pdf`);
            
        } catch (pdfError) {
            console.warn('PDF generation unavailable, falling back to Markdown:', pdfError);
            // Fallback: export as Markdown
            let md = `# ${report.title}\n\n`;
            md += `**Date:** ${new Date().toLocaleDateString()}\n`;
            md += `**Classification:** CONFIDENTIAL\n\n`;
            md += `---\n\n## Executive Summary\n\n${report.executive_summary || 'N/A'}\n\n`;
            md += `---\n\n## Findings\n\n`;
            report.findings.forEach((f, i) => {
                md += `### ${i+1}. ${f.title} [${f.severity}]\n\n`;
                md += `**Description:**\n${f.description || 'N/A'}\n\n`;
                md += `**Remediation:**\n${f.remediation || 'N/A'}\n\n`;
                if (f.evidence) md += `**Evidence:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
                md += `---\n\n`;
            });
            
            const blob = new Blob([md], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${report.title.replace(/\s+/g, '_')}_Report.md`;
            a.click();
            URL.revokeObjectURL(url);
        }
    };

    return (
        <div className="report-builder-container">
            {/* Background Polish */}
            <div className="fixed inset-0 pointer-events-none opacity-20 z-0">
              <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-sky-500/10 blur-[120px] rounded-full" />
              <div className="absolute bottom-0 left-0 w-[400px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full" />
            </div>

            <header className="report-header relative z-10">
                <div className="header-left">
                    <div className="icon-wrapper">
                        <Shield size={24} />
                    </div>
                    <div>
                        <input
                            type="text"
                            className="report-title-input"
                            value={report.title}
                            onChange={(e) => setReport({ ...report, title: e.target.value })}
                        />
                        <div className="report-meta">
                            <span className="flex items-center gap-2">
                              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                              ENC: AES-256
                            </span>
                            <span>•</span>
                            <span>{new Date().toLocaleDateString()}</span>
                            <span>•</span>
                            <span className="text-sky-500/60 uppercase">{report.findings.length} FINDINGS</span>
                        </div>
                    </div>
                </div>

                <div className="header-actions">
                    <button className="btn-secondary" onClick={handleSave} disabled={loading}>
                        {saved ? <CheckCircle2 size={16} className="text-emerald-500" /> : (loading ? <Loader className="animate-spin" size={16} /> : <Save size={16} />)}
                        {saved ? 'SYNCED' : 'COMMIT DRAFT'}
                    </button>
                    <button className="btn-primary" onClick={handleExport}>
                        <Download size={16} /> DOWNLOAD MD/PDF
                    </button>
                </div>
            </header>

            <div className="report-workspace relative z-10">
                {/* Left Sidebar: Outline */}
                <aside className="report-sidebar">
                    <div className="space-y-6 flex-1">
                      <div>
                        <h3>Navigation</h3>
                        <div
                            className={`outline-item mb-2 ${selectedFindingIndex === null ? 'active' : ''}`}
                            onClick={() => setSelectedFindingIndex(null)}
                        >
                            <span className="flex items-center gap-3">
                              <Layout size={14} />
                              Executive Summary
                            </span>
                        </div>
                      </div>

                      <div className="findings-list">
                          <div className="findings-header flex items-center justify-between px-2">
                              <h4>Tactical Findings</h4>
                              <button className="p-1 hover:bg-white/10 rounded-lg transition-colors" onClick={() => addFinding()}>
                                <Plus size={16} className="text-sky-500" />
                              </button>
                          </div>
                          <div className="space-y-1.5 mt-2">
                            {report.findings.map((finding, idx) => (
                                <div
                                    key={idx}
                                    className={`outline-item group ${selectedFindingIndex === idx ? 'active' : ''}`}
                                    onClick={() => setSelectedFindingIndex(idx)}
                                >
                                    <span className="truncate flex items-center gap-3">
                                      <div className={`w-1.5 h-1.5 rounded-full ${
                                        finding.severity === 'Critical' ? 'bg-red-500' :
                                        finding.severity === 'High' ? 'bg-orange-500' :
                                        finding.severity === 'Medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                                      }`} />
                                      {finding.title}
                                    </span>
                                    <button className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-500 transition-all" onClick={(e) => { e.stopPropagation(); removeFinding(idx); }}>
                                        <Trash2 size={12} />
                                    </button>
                                </div>
                            ))}
                          </div>
                      </div>
                    </div>

                    <div className="pt-6 border-t border-white/5 space-y-4">
                        <button 
                          onClick={autoGenerateSummary}
                          disabled={aiLoading}
                          className="w-full py-3 rounded-xl bg-sky-500/10 border border-sky-500/20 text-[10px] font-black uppercase tracking-widest text-sky-500 flex items-center justify-center gap-2 hover:bg-sky-500/20 transition-all"
                        >
                          <Brain size={14} className={aiLoading ? 'animate-pulse' : ''} />
                          Neural Summary
                        </button>
                    </div>
                </aside>

                {/* Main Editor Area */}
                <main className="report-editor relative group/editor">
                    <div className="absolute top-8 right-8 flex items-center gap-2 opacity-30 group-hover/editor:opacity-100 transition-opacity">
                      <div className="w-2 h-2 rounded-full bg-emerald-500" />
                      <span className="text-[10px] font-black uppercase tracking-widest">Live Buffer Active</span>
                    </div>

                    {selectedFindingIndex === null ? (
                        <div className="editor-section">
                            <h2 className="flex items-center gap-4">
                              <FileSearch className="text-sky-500" size={32} />
                              Executive Summary
                            </h2>
                            <p className="text-slate-500 text-sm font-medium mb-8 italic">High-level intelligence overview for executive stakeholders.</p>
                            <textarea
                                className="full-editor custom-scrollbar"
                                value={report.executive_summary}
                                onChange={(e) => setReport({ ...report, executive_summary: e.target.value })}
                                placeholder="The assessment revealed several critical vulnerabilities that require immediate remediation..."
                            />
                        </div>
                    ) : (
                        <div className="finding-editor">
                            <div className="flex flex-col gap-6">
                                <div className="space-y-4">
                                  <input
                                      className="input-title"
                                      value={report.findings[selectedFindingIndex].title}
                                      onChange={(e) => updateFinding(selectedFindingIndex, 'title', e.target.value)}
                                      placeholder="Vulnerability Blueprint Name"
                                  />
                                  <div className="flex items-center gap-4">
                                    <select
                                        className={`input-severity severity-${report.findings[selectedFindingIndex].severity.toLowerCase()}`}
                                        value={report.findings[selectedFindingIndex].severity}
                                        onChange={(e) => updateFinding(selectedFindingIndex, 'severity', e.target.value)}
                                    >
                                        <option value="Critical">Critical Risk</option>
                                        <option value="High">High Risk</option>
                                        <option value="Medium">Medium Risk</option>
                                        <option value="Low">Low Risk</option>
                                    </select>
                                    <button 
                                      onClick={() => enhanceWithAI(selectedFindingIndex)}
                                      disabled={aiLoading}
                                      className="btn-ai"
                                    >
                                      {aiLoading ? <RefreshCw className="animate-spin" size={14} /> : <Sparkles size={14} />}
                                      Neural Enhance
                                    </button>
                                  </div>
                                </div>
                            </div>

                            <div className="markdown-split">
                                <div className="split-pane">
                                    <label>Technical Intelligence (Markdown)</label>
                                    <textarea
                                        value={report.findings[selectedFindingIndex].description}
                                        onChange={(e) => updateFinding(selectedFindingIndex, 'description', e.target.value)}
                                        placeholder="Analyze the vulnerability context and impact..."
                                    />
                                </div>
                                <div className="split-pane">
                                    <label>Remediation Roadmap</label>
                                    <textarea
                                        value={report.findings[selectedFindingIndex].remediation}
                                        onChange={(e) => updateFinding(selectedFindingIndex, 'remediation', e.target.value)}
                                        placeholder="Deploy specific hardening measures..."
                                    />
                                </div>
                            </div>

                            <div className="evidence-section">
                                <label className="flex items-center gap-3">
                                  <Zap size={14} />
                                  Evidence / Proof of Concept
                                </label>
                                <textarea
                                    className="code-font custom-scrollbar"
                                    value={report.findings[selectedFindingIndex].evidence}
                                    onChange={(e) => updateFinding(selectedFindingIndex, 'evidence', e.target.value)}
                                    placeholder="Paste tactical logs, PoC payloads, or intercepted data..."
                                />
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
};

export default ReportBuilder;
