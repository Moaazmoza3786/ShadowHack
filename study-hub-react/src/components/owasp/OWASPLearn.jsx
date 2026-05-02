import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    ChevronLeft, Shield, AlertCircle, CheckCircle2,
    Play, Info, ArrowRight, BookOpen, Swords,
    Trophy, Clock, Zap, ExternalLink, Code2, Target,
    ChevronDown, ChevronRight as ChevronRightIcon, BookMarked, ShieldAlert, Wrench, HelpCircle
} from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAppContext } from '../../context/AppContext';

// ─── Theory HTML → Visual Sections Parser ───────────────────────────────────
const SECTION_ICONS = {
    'what': { icon: HelpCircle, color: 'blue' },
    'how': { icon: ShieldAlert, color: 'orange' },
    'testing': { icon: Target, color: 'purple' },
    'prevention': { icon: Wrench, color: 'emerald' },
    'types': { icon: BookMarked, color: 'cyan' },
    'default': { icon: Info, color: 'blue' },
};

const COLOR_MAP = {
    blue:    { bg: 'bg-blue-500/10',    border: 'border-blue-500/20',    text: 'text-blue-400',    icon: 'text-blue-500',    dot: 'bg-blue-500'    },
    orange:  { bg: 'bg-orange-500/10',  border: 'border-orange-500/20',  text: 'text-orange-400',  icon: 'text-orange-500',  dot: 'bg-orange-500'  },
    purple:  { bg: 'bg-purple-500/10',  border: 'border-purple-500/20',  text: 'text-purple-400',  icon: 'text-purple-500',  dot: 'bg-purple-500'  },
    emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400', icon: 'text-emerald-500', dot: 'bg-emerald-500' },
    cyan:    { bg: 'bg-cyan-500/10',    border: 'border-cyan-500/20',    text: 'text-cyan-400',    icon: 'text-cyan-500',    dot: 'bg-cyan-500'    },
};

function parseTheoryHTML(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(`<div>${html}</div>`, 'text/html');
    const root = doc.querySelector('div');
    const sections = [];
    let current = null;

    root.childNodes.forEach(node => {
        if (node.nodeName === 'H3') {
            if (current) sections.push(current);
            const title = node.textContent.trim();
            const key = title.toLowerCase();
            const match = Object.keys(SECTION_ICONS).find(k => key.includes(k)) || 'default';
            current = { title, iconKey: match, items: [], paragraphs: [] };
        } else if (node.nodeName === 'UL' && current) {
            node.querySelectorAll('li').forEach(li => {
                // preserve <strong> inside li
                current.items.push(li.innerHTML.trim());
            });
        } else if (node.nodeName === 'P' && current) {
            current.paragraphs.push(node.innerHTML.trim());
        }
    });
    if (current) sections.push(current);
    return sections;
}

function TheorySection({ section, index, isOpen, onToggle }) {
    const { icon: Icon, color } = SECTION_ICONS[section.iconKey] || SECTION_ICONS.default;
    const c = COLOR_MAP[color] || COLOR_MAP.blue;

    return (
        <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.08 }}
            className={`rounded-2xl border overflow-hidden transition-all ${isOpen ? `${c.border} ${c.bg}` : 'border-white/5 bg-white/[0.02] hover:border-white/10'}`}
        >
            {/* Section Header — clickable */}
            <button onClick={onToggle} className="w-full flex items-center justify-between p-5 text-left group">
                <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${isOpen ? c.bg : 'bg-white/5'} border ${isOpen ? c.border : 'border-white/5'}`}>
                        <Icon size={16} className={isOpen ? c.icon : 'text-gray-500'} />
                    </div>
                    <span className={`text-sm font-black uppercase tracking-tight transition-colors ${isOpen ? 'text-white' : 'text-gray-400 group-hover:text-gray-200'}`}>
                        {section.title}
                    </span>
                </div>
                <div className={`w-6 h-6 rounded-lg flex items-center justify-center transition-all ${isOpen ? c.bg : 'bg-white/5'}`}>
                    {isOpen
                        ? <ChevronDown size={14} className={c.icon} />
                        : <ChevronRightIcon size={14} className="text-gray-600" />}
                </div>
            </button>

            {/* Section Body */}
            <AnimatePresence initial={false}>
                {isOpen && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
                        className="overflow-hidden"
                    >
                        <div className="px-5 pb-5 space-y-4">
                            {/* Paragraphs */}
                            {section.paragraphs.map((p, i) => (
                                <p key={i}
                                    className="text-sm text-gray-400 leading-relaxed"
                                    dangerouslySetInnerHTML={{ __html: p }} />
                            ))}

                            {/* List Items */}
                            {section.items.length > 0 && (
                                <ul className="space-y-2.5">
                                    {section.items.map((item, i) => (
                                        <li key={i} className="flex items-start gap-3">
                                            <span className={`w-1.5 h-1.5 rounded-full mt-2 flex-shrink-0 ${c.dot}`} />
                                            <span
                                                className="text-sm text-gray-400 leading-relaxed [&_strong]:font-bold [&_strong]:text-white"
                                                dangerouslySetInnerHTML={{ __html: item }} />
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    );
}

const OWASPLearn = ({ vuln }) => {
    const navigate = useNavigate();
    const { language } = useAppContext();
    const isAr = language === 'ar';

    const [activeTab, setActiveTab] = useState(0);
    const [quizAnswers, setQuizAnswers] = useState({});
    const [quizSubmitted, setQuizSubmitted] = useState(false);
    const [openSections, setOpenSections] = useState({ 0: true });

    // pick Arabic or English content
    const theoryHTML  = isAr && vuln.theory_ar  ? vuln.theory_ar  : vuln.theory;
    const objectiveText = isAr && vuln.objective_ar ? vuln.objective_ar : vuln.objective;
    const defenseText   = isAr && vuln.defense_ar   ? vuln.defense_ar   : vuln.defense;
    const descText      = isAr && vuln.description_ar ? vuln.description_ar : vuln.description;

    const theorySections = React.useMemo(() => parseTheoryHTML(theoryHTML || ''), [theoryHTML]);

    const TABS = isAr
        ? ['النظرية', 'أساليب الهجوم', 'حالات حقيقية', 'الإصلاح', 'اختبار المعرفة']
        : ['Theory', 'Attack Vectors', 'Real-World Cases', 'Remediation', 'Quiz'];

    const toggleSection = (i) => setOpenSections(p => ({ ...p, [i]: !p[i] }));

    const quizScore = quizSubmitted
        ? vuln.quiz.filter((q, i) => quizAnswers[i] === q.answer).length
        : 0;

    const handleQuizSubmit = () => {
        if (Object.keys(quizAnswers).length === vuln.quiz.length) setQuizSubmitted(true);
    };

    return (
        <div className="space-y-6 pb-12">
            {/* Header */}
            <div className="flex items-center justify-between">
                <button onClick={() => navigate('/owasp-range')}
                    className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors group">
                    <ChevronLeft size={20} className="group-hover:-translate-x-1 transition-transform" />
                    <span className="text-xs font-black uppercase tracking-widest">
                        {isAr ? 'العودة للقائمة' : 'Back to Range'}
                    </span>
                </button>
                <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
                        <AlertCircle size={14} className="text-red-500" />
                        <span className="text-[10px] font-black uppercase tracking-widest text-red-500">CVSS: {vuln.cvss}</span>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
                        <Clock size={14} className="text-blue-500" />
                        <span className="text-[10px] font-black uppercase tracking-widest text-blue-500">{vuln.readTime || '8 min'}</span>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                        <Zap size={14} className="text-yellow-500" />
                        <span className="text-[10px] font-black uppercase tracking-widest text-yellow-500">+{vuln.xpReward || 100} XP</span>
                    </div>
                </div>
            </div>

            {/* Title */}
            <div className="space-y-1">
                <div className="flex items-center gap-3">
                    <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary-500">{vuln.type}</span>
                    <span className="text-gray-600">•</span>
                    <span className={`text-[10px] font-black uppercase tracking-widest ${
                        vuln.difficulty === 'HARD' ? 'text-red-500' :
                        vuln.difficulty === 'MEDIUM' ? 'text-orange-500' : 'text-emerald-500'
                    }`}>{vuln.difficulty}</span>
                </div>
                <h1 className="text-5xl font-black text-white italic uppercase tracking-tighter">{vuln.title}</h1>
                <p className="text-gray-400 font-medium">{descText}</p>
            </div>

            {/* Tabs */}
            <div className="flex items-center gap-1 p-1 bg-dark-900/60 border border-white/5 rounded-2xl w-fit">
                {TABS.map((tab, i) => (
                    <button key={tab} onClick={() => setActiveTab(i)}
                        className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                            activeTab === i
                                ? 'bg-primary-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                                : 'text-gray-500 hover:text-gray-300'
                        }`}>
                        {tab}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <AnimatePresence mode="wait">
                <motion.div key={activeTab}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}>

                    {/* THEORY TAB */}
                    {activeTab === 0 && (
                        <div className="space-y-3">
                            {/* Quick Stats Bar */}
                            <div className="grid grid-cols-3 gap-3 mb-2">
                                <div className="bg-dark-800/40 border border-white/5 rounded-2xl p-4 flex items-center gap-3">
                                    <div className="w-9 h-9 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center flex-shrink-0">
                                        <AlertCircle size={16} className="text-red-500" />
                                    </div>
                                    <div>
                                        <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest">Severity</div>
                                        <div className="text-sm font-black text-white">{vuln.severity}</div>
                                    </div>
                                </div>
                                <div className="bg-dark-800/40 border border-white/5 rounded-2xl p-4 flex items-center gap-3">
                                    <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                                        <Shield size={16} className="text-blue-500" />
                                    </div>
                                    <div>
                                        <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest">CVSS Score</div>
                                        <div className="text-sm font-black text-white">{vuln.cvss} / 10</div>
                                    </div>
                                </div>
                                <div className="bg-dark-800/40 border border-white/5 rounded-2xl p-4 flex items-center gap-3">
                                    <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center flex-shrink-0">
                                        <BookOpen size={16} className="text-purple-500" />
                                    </div>
                                    <div>
                                        <div className="text-[9px] font-black text-gray-500 uppercase tracking-widest">Type</div>
                                        <div className="text-sm font-black text-white">{vuln.type}</div>
                                    </div>
                                </div>
                            </div>

                            {/* Accordion Sections */}
                            {theorySections.map((section, i) => (
                                <TheorySection
                                    key={i}
                                    section={section}
                                    index={i}
                                    isOpen={!!openSections[i]}
                                    onToggle={() => toggleSection(i)}
                                />
                            ))}

                            {/* Mission Objective */}
                            <div className="p-5 rounded-2xl bg-blue-500/5 border border-blue-500/15 flex items-start gap-4 mt-2">
                                <div className="w-9 h-9 rounded-xl bg-blue-500/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                                    <Target size={16} className="text-blue-500" />
                                </div>
                                <div>
                                    <div className="text-[10px] font-black uppercase tracking-[0.2em] text-blue-500 mb-1">
                                        {isAr ? 'هدف المهمة' : 'Mission Objective'}
                                    </div>
                                    <p className="text-sm text-blue-100/70 leading-relaxed italic">{objectiveText}</p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ATTACK VECTORS TAB */}
                    {activeTab === 1 && (
                        <div className="space-y-4">
                            <div className="flex items-center gap-3 mb-2">
                                <div className="w-10 h-10 rounded-xl bg-red-500/20 flex items-center justify-center">
                                    <Swords size={20} className="text-red-500" />
                                </div>
                                <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">
                            {isAr ? 'أساليب الهجوم' : 'Attack Vectors'}
                        </h2>
                            </div>
                            {(vuln.attackVectors || []).map((vec, i) => (
                                <motion.div key={i}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: i * 0.07 }}
                                    className="bg-dark-800/40 border border-white/5 rounded-2xl p-6 hover:border-red-500/20 transition-all group">
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <span className="text-sm font-black text-white uppercase tracking-tight">{vec.name}</span>
                                                <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest border ${
                                                    vec.severity === 'Critical' ? 'bg-red-500/10 border-red-500/20 text-red-500' :
                                                    vec.severity === 'High' ? 'bg-orange-500/10 border-orange-500/20 text-orange-500' :
                                                    'bg-yellow-500/10 border-yellow-500/20 text-yellow-500'
                                                }`}>{vec.severity}</span>
                                            </div>
                                            <p className="text-sm text-gray-400 italic">{vec.description}</p>
                                        </div>
                                        <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                                            <Swords size={14} className="text-red-500" />
                                        </div>
                                    </div>
                                </motion.div>
                            ))}
                        </div>
                    )}

                    {/* REAL-WORLD CASES TAB */}
                    {activeTab === 2 && (
                        <div className="space-y-4">
                            <div className="flex items-center gap-3 mb-2">
                                <div className="w-10 h-10 rounded-xl bg-orange-500/20 flex items-center justify-center">
                                    <ExternalLink size={20} className="text-orange-500" />
                                </div>
                                <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">
                            {isAr ? 'حالات حقيقية' : 'Real-World Cases'}
                        </h2>
                            </div>
                            {(vuln.realWorldCases || []).map((c, i) => (
                                <motion.div key={i}
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: i * 0.1 }}
                                    className="bg-dark-800/40 border border-white/5 rounded-2xl p-6 hover:border-orange-500/20 transition-all">
                                    <div className="flex items-start gap-4">
                                        <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center flex-shrink-0 mt-1">
                                            <span className="text-orange-500 font-black text-sm">{i + 1}</span>
                                        </div>
                                        <div className="flex-1">
                                            <h3 className="text-base font-black text-white mb-1">{c.title}</h3>
                                            <p className="text-sm text-gray-400 italic mb-3">{c.impact}</p>
                                            {c.cve !== 'N/A' && (
                                                <span className="px-2 py-1 rounded-lg bg-red-500/10 border border-red-500/20 text-[10px] font-black text-red-400 uppercase tracking-widest">
                                                    {c.cve}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                </motion.div>
                            ))}
                        </div>
                    )}

                    {/* REMEDIATION TAB */}
                    {activeTab === 3 && (
                        <div className="bg-black/40 border border-white/5 rounded-3xl overflow-hidden">
                            <div className="p-6 border-b border-white/5 flex items-center justify-between bg-dark-900/50">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                                        <CheckCircle2 size={20} className="text-emerald-500" />
                                    </div>
                                    <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">
                            {isAr ? 'الكود الآمن' : 'Secure Code'}
                        </h2>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Code2 size={14} className="text-gray-500" />
                                    <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">Remediation Pattern</span>
                                </div>
                            </div>
                            <div className="p-8 font-mono text-sm overflow-auto bg-[#0d1117] max-h-[500px]">
                                <pre className="text-gray-300 leading-relaxed">
                                    {vuln.codeFix.split('\n').map((line, i) => (
                                        <div key={i} className="flex gap-6 group hover:bg-white/[0.02] rounded px-1">
                                            <span className="w-8 text-gray-600 text-right select-none flex-shrink-0">{i + 1}</span>
                                            <span className={
                                                line.includes('// VULNERABLE') ? 'text-red-400 font-bold' :
                                                line.includes('// SECURE') ? 'text-emerald-400 font-bold' :
                                                line.startsWith('//') || line.startsWith('#') ? 'text-gray-500 italic' :
                                                line.includes('⚠️') ? 'text-red-400' :
                                                'text-gray-300'
                                            }>{line}</span>
                                        </div>
                                    ))}
                                </pre>
                            </div>
                            <div className="p-4 bg-emerald-500/5 border-t border-emerald-500/10">
                                <p className="text-xs text-emerald-400/70 italic font-medium">
                                    {isAr ? 'الدفاع: ' : 'Defense: '}{defenseText}
                                </p>
                            </div>
                        </div>
                    )}

                    {/* QUIZ TAB */}
                    {activeTab === 4 && (
                        <div className="space-y-6">
                            <div className="flex items-center gap-3 mb-2">
                                <div className="w-10 h-10 rounded-xl bg-yellow-500/20 flex items-center justify-center">
                                    <Trophy size={20} className="text-yellow-500" />
                                </div>
                                <h2 className="text-2xl font-black text-white italic uppercase tracking-tighter">
                            {isAr ? 'اختبار المعرفة' : 'Knowledge Check'}
                        </h2>
                            </div>

                            {quizSubmitted && (
                                <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
                                    className={`p-6 rounded-2xl border ${quizScore === vuln.quiz.length
                                        ? 'bg-emerald-500/10 border-emerald-500/30'
                                        : 'bg-orange-500/10 border-orange-500/30'}`}>
                                    <div className="flex items-center gap-3">
                                        {quizScore === vuln.quiz.length
                                            ? <CheckCircle2 size={24} className="text-emerald-500" />
                                            : <AlertCircle size={24} className="text-orange-500" />}
                                        <div>
                                            <p className="font-black text-white uppercase tracking-tight">
                                                Score: {quizScore}/{vuln.quiz.length}
                                            </p>
                                            <p className="text-xs text-gray-400 italic">
                                                {quizScore === vuln.quiz.length
                                                    ? (isAr ? 'ممتاز! أنت جاهز للتطبيق.' : 'Perfect! Ready for Practice.')
                                                    : (isAr ? 'راجع الإجابات الخاطئة وحاول مجدداً.' : 'Review the wrong answers and try again.')}
                                            </p>
                                        </div>
                                    </div>
                                </motion.div>
                            )}

                            {vuln.quiz.map((q, qi) => (
                                <div key={qi} className="bg-dark-800/40 border border-white/5 rounded-2xl p-6 space-y-4">
                                    <p className="text-sm font-bold text-white">
                                        <span className="text-primary-500 mr-2">Q{qi + 1}.</span>{q.q}
                                    </p>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                        {q.options.map((opt, oi) => {
                                            const isSelected = quizAnswers[qi] === oi;
                                            const isCorrect = quizSubmitted && oi === q.answer;
                                            const isWrong = quizSubmitted && isSelected && oi !== q.answer;
                                            return (
                                                <button key={oi}
                                                    disabled={quizSubmitted}
                                                    onClick={() => !quizSubmitted && setQuizAnswers(p => ({ ...p, [qi]: oi }))}
                                                    className={`p-3 rounded-xl border text-left text-xs font-bold transition-all ${
                                                        isCorrect ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400' :
                                                        isWrong ? 'bg-red-500/20 border-red-500/50 text-red-400' :
                                                        isSelected ? 'bg-primary-500/20 border-primary-500/50 text-white' :
                                                        'bg-white/5 border-white/10 text-gray-400 hover:border-white/20 hover:text-white'
                                                    }`}>
                                                    <span className="text-gray-500 mr-2">{String.fromCharCode(65 + oi)}.</span>
                                                    {opt}
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                            ))}

                            {!quizSubmitted && (
                                <button onClick={handleQuizSubmit}
                                    disabled={Object.keys(quizAnswers).length < vuln.quiz.length}
                                    className="w-full h-12 rounded-xl bg-primary-600 text-white font-black uppercase tracking-widest text-xs hover:bg-primary-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed">
                                    {isAr ? 'إرسال الإجابات' : 'Submit Answers'}
                                </button>
                            )}
                        </div>
                    )}
                </motion.div>
            </AnimatePresence>

            {/* CTA to Practice */}
            <Link to={`/owasp-range/${vuln.id}/practice`}
                className="group w-full h-16 rounded-2xl bg-primary-600 text-white flex items-center justify-between px-8 hover:bg-primary-500 transition-all shadow-[0_0_30px_rgba(239,68,68,0.2)]">
                <div className="flex items-center gap-4">
                    <Play size={20} className="fill-current" />
                    <div className="text-left">
                        <div className="text-[10px] font-black uppercase tracking-[0.2em] opacity-80">
                            {isAr ? 'النظرية اكتملت — حان وقت الاختراق' : 'Theory Complete — Time to Hack'}
                        </div>
                        <div className="text-xl font-black italic uppercase tracking-tighter">
                            {isAr ? 'ابدأ المحاكاة' : 'Start Simulation'}
                        </div>
                    </div>
                </div>
                <ArrowRight size={24} className="group-hover:translate-x-2 transition-transform" />
            </Link>
        </div>
    );
};

export default OWASPLearn;
