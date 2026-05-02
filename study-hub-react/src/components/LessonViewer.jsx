import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, CheckCircle2, AlertCircle, Info, Lightbulb, Terminal, HelpCircle, ChevronDown } from 'lucide-react';
import { loadLesson } from '../utils/contentLoader';

// ─── Custom MDX Component Renderers ──────────────────────────────────────────

function InfoBox({ type = 'info', children }) {
  const styles = {
    info:      { bg: 'bg-blue-500/10',    border: 'border-blue-500/20',    icon: Info,         color: 'text-blue-400'    },
    warning:   { bg: 'bg-orange-500/10',  border: 'border-orange-500/20',  icon: AlertCircle,  color: 'text-orange-400'  },
    important: { bg: 'bg-red-500/10',     border: 'border-red-500/20',     icon: AlertCircle,  color: 'text-red-400'     },
    tip:       { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: Lightbulb,    color: 'text-emerald-400' },
  };
  const s = styles[type] || styles.info;
  const Icon = s.icon;
  return (
    <div className={`flex gap-3 p-4 rounded-xl border ${s.bg} ${s.border} my-4`}>
      <Icon size={16} className={`${s.color} flex-shrink-0 mt-0.5`} />
      <p className={`text-sm ${s.color} leading-relaxed`}>{children}</p>
    </div>
  );
}

function TerminalWindow({ title = 'Terminal', command, output }) {
  return (
    <div className="rounded-xl overflow-hidden border border-white/10 my-4 font-mono text-sm">
      <div className="bg-dark-900 px-4 py-2 flex items-center gap-2 border-b border-white/5">
        <Terminal size={12} className="text-emerald-500" />
        <span className="text-[10px] text-gray-500 uppercase tracking-widest">{title}</span>
      </div>
      <div className="bg-[#0a0a0a] p-4 space-y-1">
        {command && <div className="flex gap-2"><span className="text-emerald-500">$</span><span className="text-gray-300">{command}</span></div>}
        {output  && <div className="text-gray-500 pl-4">{output}</div>}
      </div>
    </div>
  );
}

function QuizBlock({ question, answer, hint }) {
  const [revealed, setRevealed] = useState(false);
  const [input, setInput]       = useState('');
  const [correct, setCorrect]   = useState(null);

  const check = () => {
    setCorrect(input.trim().toLowerCase() === answer.trim().toLowerCase());
    setRevealed(true);
  };

  return (
    <div className="my-4 p-4 rounded-xl bg-purple-500/5 border border-purple-500/15 space-y-3">
      <div className="flex items-start gap-2">
        <HelpCircle size={14} className="text-purple-400 flex-shrink-0 mt-0.5" />
        <p className="text-sm font-bold text-white">{question}</p>
      </div>
      {!revealed ? (
        <div className="flex gap-2">
          <input value={input} onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && check()}
            placeholder="Your answer..."
            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-purple-500/50" />
          <button onClick={check}
            className="px-4 py-2 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 text-xs font-black uppercase tracking-widest hover:bg-purple-500/30 transition-all">
            Check
          </button>
        </div>
      ) : (
        <div className={`flex items-center gap-2 p-3 rounded-lg ${correct ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'}`}>
          {correct
            ? <CheckCircle2 size={14} className="text-emerald-400" />
            : <AlertCircle  size={14} className="text-red-400" />}
          <span className={`text-xs font-bold ${correct ? 'text-emerald-400' : 'text-red-400'}`}>
            {correct ? 'Correct!' : `Answer: ${answer}`}
          </span>
          {hint && !correct && <span className="text-xs text-gray-500 italic ml-2">Hint: {hint}</span>}
        </div>
      )}
    </div>
  );
}

// ─── MDX-like Parser ──────────────────────────────────────────────────────────
// Parses the raw mdx text into renderable React elements

function parseMDX(raw) {
  // Strip frontmatter
  const content = raw.replace(/^---[\s\S]*?---\n/, '').trim();
  const lines   = content.split('\n');
  const elements = [];
  let i = 0;
  let codeBlock = null;
  let codeLines = [];

  while (i < lines.length) {
    const line = lines[i];

    // Code block start
    if (line.startsWith('```')) {
      if (codeBlock === null) {
        codeBlock = line.slice(3).trim() || 'text';
        codeLines = [];
      } else {
        elements.push({ type: 'code', lang: codeBlock, content: codeLines.join('\n') });
        codeBlock = null;
        codeLines = [];
      }
      i++; continue;
    }
    if (codeBlock !== null) { codeLines.push(line); i++; continue; }

    // Custom components — single line
    const infoMatch  = line.match(/<InfoBox\s+type="([^"]+)">(.*?)<\/InfoBox>/);
    const termMatch  = line.match(/<TerminalWindow\s+title="([^"]*)"(?:\s+command="([^"]*)")?(?:\s+output="([^"]*)")?/);
    const quizMatch  = line.match(/<Quiz\s+question="([^"]+)"\s+answer="([^"]+)"(?:\s+hint="([^"]*)")?/);

    if (infoMatch)  { elements.push({ type: 'infobox',  boxType: infoMatch[1],  text: infoMatch[2] }); i++; continue; }
    if (termMatch)  { elements.push({ type: 'terminal', title: termMatch[1], command: termMatch[2], output: termMatch[3] }); i++; continue; }
    if (quizMatch)  { elements.push({ type: 'quiz',     question: quizMatch[1], answer: quizMatch[2], hint: quizMatch[3] }); i++; continue; }

    // Multi-line InfoBox
    if (line.startsWith('<InfoBox')) {
      const typeM = line.match(/type="([^"]+)"/);
      const texts = [];
      i++;
      while (i < lines.length && !lines[i].includes('</InfoBox>')) { texts.push(lines[i]); i++; }
      elements.push({ type: 'infobox', boxType: typeM?.[1] || 'info', text: texts.join(' ') });
      if (i < lines.length && lines[i].includes('</InfoBox>')) i++;
      continue;
    }

    // Headings
    if (line.startsWith('### ')) { elements.push({ type: 'h3', text: line.slice(4) }); i++; continue; }
    if (line.startsWith('## '))  { elements.push({ type: 'h2', text: line.slice(3) }); i++; continue; }
    if (line.startsWith('# '))   { elements.push({ type: 'h1', text: line.slice(2) }); i++; continue; }

    // Table
    if (line.startsWith('|')) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith('|')) {
        if (!lines[i].match(/^\|[-: |]+\|$/)) rows.push(lines[i]);
        i++;
      }
      elements.push({ type: 'table', rows });
      continue;
    }

    // Ordered list
    if (/^\d+\.\s/.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) { items.push(lines[i].replace(/^\d+\.\s/, '')); i++; }
      elements.push({ type: 'ol', items });
      continue;
    }

    // Unordered list
    if (line.startsWith('- ') || line.startsWith('* ')) {
      const items = [];
      while (i < lines.length && (lines[i].startsWith('- ') || lines[i].startsWith('* '))) {
        items.push(lines[i].slice(2));
        i++;
      }
      elements.push({ type: 'ul', items });
      continue;
    }

    // Blockquote
    if (line.startsWith('> ')) { elements.push({ type: 'blockquote', text: line.slice(2) }); i++; continue; }

    // Empty line
    if (line.trim() === '') { i++; continue; }

    // Paragraph
    const paraLines = [];
    while (i < lines.length && lines[i].trim() !== '' && !lines[i].startsWith('#') && !lines[i].startsWith('```') && !lines[i].startsWith('|') && !lines[i].startsWith('<') && !/^\d+\.\s/.test(lines[i]) && !lines[i].startsWith('- ') && !lines[i].startsWith('> ')) {
      paraLines.push(lines[i]);
      i++;
    }
    if (paraLines.length) elements.push({ type: 'p', text: paraLines.join(' ') });
  }

  return elements;
}

// Inline markdown: **bold**, `code`, *italic*
function renderInline(text) {
  if (!text) return null;
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} className="text-white font-bold">{part.slice(2, -2)}</strong>;
    if (part.startsWith('`') && part.endsWith('`'))
      return <code key={i} className="px-1.5 py-0.5 rounded bg-white/10 text-emerald-400 font-mono text-[0.85em]">{part.slice(1, -1)}</code>;
    if (part.startsWith('*') && part.endsWith('*'))
      return <em key={i} className="italic text-gray-300">{part.slice(1, -1)}</em>;
    return part;
  });
}

function renderElement(el, idx) {
  switch (el.type) {
    case 'h1': return <h1 key={idx} className="text-3xl font-black text-white italic uppercase tracking-tighter mt-8 mb-4">{renderInline(el.text)}</h1>;
    case 'h2': return <h2 key={idx} className="text-xl font-black text-white uppercase tracking-tight mt-6 mb-3 pb-2 border-b border-white/5">{renderInline(el.text)}</h2>;
    case 'h3': return <h3 key={idx} className="text-base font-black text-primary-400 uppercase tracking-tight mt-5 mb-2">{renderInline(el.text)}</h3>;
    case 'p':  return <p  key={idx} className="text-gray-400 leading-relaxed mb-3 text-sm">{renderInline(el.text)}</p>;
    case 'blockquote': return (
      <blockquote key={idx} className="border-l-2 border-primary-500/50 pl-4 my-3 italic text-gray-500 text-sm">{renderInline(el.text)}</blockquote>
    );
    case 'ul': return (
      <ul key={idx} className="space-y-1.5 mb-4 ml-2">
        {el.items.map((item, i) => (
          <li key={i} className="flex items-start gap-2 text-sm text-gray-400">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-500 flex-shrink-0 mt-2" />
            <span>{renderInline(item)}</span>
          </li>
        ))}
      </ul>
    );
    case 'ol': return (
      <ol key={idx} className="space-y-1.5 mb-4 ml-2">
        {el.items.map((item, i) => (
          <li key={i} className="flex items-start gap-3 text-sm text-gray-400">
            <span className="w-5 h-5 rounded-full bg-primary-500/20 border border-primary-500/30 text-primary-400 text-[10px] font-black flex items-center justify-center flex-shrink-0 mt-0.5">{i+1}</span>
            <span>{renderInline(item)}</span>
          </li>
        ))}
      </ol>
    );
    case 'code': return (
      <div key={idx} className="rounded-xl overflow-hidden border border-white/10 my-4">
        <div className="bg-dark-900 px-4 py-2 flex items-center gap-2 border-b border-white/5">
          <span className="text-[10px] text-gray-500 font-mono uppercase tracking-widest">{el.lang}</span>
        </div>
        <pre className="bg-[#0d1117] p-4 overflow-x-auto text-xs font-mono text-gray-300 leading-relaxed">
          {el.content.split('\n').map((line, i) => (
            <div key={i} className="flex gap-4">
              <span className="w-6 text-gray-700 text-right select-none flex-shrink-0">{i+1}</span>
              <span className={line.startsWith('--') || line.startsWith('#') ? 'text-gray-600 italic' : 'text-gray-300'}>{line}</span>
            </div>
          ))}
        </pre>
      </div>
    );
    case 'table': return (
      <div key={idx} className="overflow-x-auto my-4 rounded-xl border border-white/10">
        <table className="w-full text-xs">
          {el.rows.map((row, ri) => {
            const cells = row.split('|').filter(c => c.trim());
            return (
              <tr key={ri} className={ri === 0 ? 'bg-dark-900 border-b border-white/10' : 'border-b border-white/5 hover:bg-white/[0.02]'}>
                {cells.map((cell, ci) => ri === 0
                  ? <th key={ci} className="px-4 py-2 text-left font-black text-gray-400 uppercase tracking-widest">{cell.trim()}</th>
                  : <td key={ci} className="px-4 py-2 text-gray-400 font-mono">{renderInline(cell.trim())}</td>
                )}
              </tr>
            );
          })}
        </table>
      </div>
    );
    case 'infobox':  return <InfoBox  key={idx} type={el.boxType}>{el.text}</InfoBox>;
    case 'terminal': return <TerminalWindow key={idx} title={el.title} command={el.command} output={el.output} />;
    case 'quiz':     return <QuizBlock key={idx} question={el.question} answer={el.answer} hint={el.hint} />;
    default: return null;
  }
}

// ─── Main LessonViewer Component ─────────────────────────────────────────────
const LessonViewer = ({ lesson, onClose, onComplete, isCompleted }) => {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [elements, setElements] = useState([]);

  useEffect(() => {
    if (!lesson) return;
    setLoading(true);
    setContent('');
    setElements([]);

    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), 5000)
    );

    Promise.race([loadLesson(lesson.file), timeout])
      .then(raw => {
        if (raw) {
          setContent(raw);
          setElements(parseMDX(raw));
        } else {
          const fallback = `# ${lesson.title}\n\nContent coming soon.`;
          setContent(fallback);
          setElements(parseMDX(fallback));
        }
        setLoading(false);
      })
      .catch(() => {
        const fallback = `# ${lesson.title}\n\nContent coming soon.`;
        setContent(fallback);
        setElements(parseMDX(fallback));
        setLoading(false);
      });
  }, [lesson]);

  if (!lesson) return null;

  return (
    <motion.div
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 40 }}
      className="fixed inset-y-0 right-0 w-full max-w-2xl bg-dark-950 border-l border-white/10 z-[300] flex flex-col shadow-2xl"
    >
      {/* Header */}
      <div className="h-14 px-6 flex items-center justify-between border-b border-white/10 flex-shrink-0">
        <div className="flex items-center gap-3">
          {isCompleted && <CheckCircle2 size={16} className="text-emerald-500" />}
          <span className="text-sm font-black text-white uppercase tracking-tight truncate max-w-xs">{lesson.title}</span>
        </div>
        <div className="flex items-center gap-3">
          {!isCompleted && (
            <button onClick={onComplete}
              className="flex items-center gap-2 px-4 py-1.5 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-[10px] font-black uppercase tracking-widest hover:bg-emerald-500/30 transition-all">
              <CheckCircle2 size={12} />
              Mark Done (+{lesson.xp} XP)
            </button>
          )}
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-white/5 text-gray-400 hover:text-white transition-all">
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6 scrollbar-cyber">
        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-8 h-8 border-2 border-primary-500/20 border-t-primary-500 rounded-full animate-spin" />
          </div>
        ) : (
          <div className="max-w-none">
            {elements.map((el, i) => renderElement(el, i))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="h-14 px-6 flex items-center justify-between border-t border-white/10 flex-shrink-0">
        <span className="text-[10px] text-gray-600 font-mono">{lesson.file}</span>
        {isCompleted && (
          <span className="flex items-center gap-1.5 text-[10px] font-black text-emerald-500 uppercase tracking-widest">
            <CheckCircle2 size={12} /> Completed
          </span>
        )}
      </div>
    </motion.div>
  );
};

export default LessonViewer;
