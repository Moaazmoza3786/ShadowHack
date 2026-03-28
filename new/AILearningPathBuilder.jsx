import { useState, useEffect } from "react";

const GOALS = [
  { id: "pentester", label: "Penetration Tester", icon: "⚔️", color: "#ff4560" },
  { id: "bugbounty", label: "Bug Bounty Hunter", icon: "🎯", color: "#ffb800" },
  { id: "blueteam", label: "Blue Team / SOC", icon: "🛡️", color: "#00b4d8" },
  { id: "malware", label: "Malware Analyst", icon: "🦠", color: "#a855f7" },
  { id: "cloudSec", label: "Cloud Security", icon: "☁️", color: "#00ff9d" },
  { id: "osint", label: "OSINT Specialist", icon: "🔍", color: "#fb923c" },
];

const LEVELS = [
  { id: "absolute", label: "مبتدئ تماماً", desc: "لا خبرة سابقة", icon: "◌" },
  { id: "beginner", label: "مبتدئ", desc: "أساسيات الشبكات والـ Linux", icon: "◔" },
  { id: "intermediate", label: "متوسط", desc: "جربت CTFs وأدوات أساسية", icon: "◑" },
  { id: "advanced", label: "متقدم", desc: "خبرة عملية وشهادات", icon: "◕" },
];

const TIME_OPTIONS = [
  { id: "1h", label: "ساعة/يوم", weeks: 52 },
  { id: "2h", label: "ساعتين/يوم", weeks: 26 },
  { id: "4h", label: "4 ساعات/يوم", weeks: 16 },
  { id: "8h", label: "Full-time", weeks: 10 },
];

export default function AILearningPathBuilder() {
  const [step, setStep] = useState(0); // 0=goal, 1=level, 2=time, 3=generating, 4=result
  const [goal, setGoal] = useState(null);
  const [level, setLevel] = useState(null);
  const [time, setTime] = useState(null);
  const [path, setPath] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expandedPhase, setExpandedPhase] = useState(0);
  const [completedItems, setCompletedItems] = useState(new Set());
  const [termLines, setTermLines] = useState([]);
  const [glitch, setGlitch] = useState(false);
  const [xp, setXp] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => setGlitch(g => !g), 4000);
    return () => clearInterval(iv);
  }, []);

  const addLine = (txt, delay = 0) =>
    setTimeout(() => setTermLines(p => [...p, txt]), delay);

  const generatePath = async () => {
    setStep(3);
    setLoading(true);
    setTermLines([]);
    addLine(`> Analyzing profile: ${GOALS.find(g => g.id === goal)?.label}`, 0);
    addLine(`> Current level: ${LEVELS.find(l => l.id === level)?.label}`, 300);
    addLine(`> Available time: ${TIME_OPTIONS.find(t => t.id === time)?.label}`, 600);
    addLine(`> Running AI path optimizer...`, 1000);
    addLine(`> Mapping skill dependencies...`, 1500);
    addLine(`> Calculating milestones...`, 2000);
    addLine(`> Building resource database...`, 2500);

    const goalLabel = GOALS.find(g => g.id === goal)?.label;
    const levelLabel = LEVELS.find(l => l.id === level)?.label;
    const timeLabel = TIME_OPTIONS.find(t => t.id === time)?.label;
    const weeks = TIME_OPTIONS.find(t => t.id === time)?.weeks;

    const prompt = `You are an expert cybersecurity career coach. Create a detailed, personalized learning path.

Goal: ${goalLabel}
Current Level: ${levelLabel}  
Time Available: ${timeLabel}
Total Duration: ~${weeks} weeks

Return ONLY valid JSON:
{
  "title": "Path title",
  "tagline": "One motivational line",
  "total_weeks": ${weeks},
  "total_xp": 5000,
  "phases": [
    {
      "id": 1,
      "title": "Phase title",
      "duration": "X weeks",
      "xp": 1000,
      "color": "#hexcolor",
      "description": "What you'll master in this phase",
      "topics": [
        {
          "name": "Topic name",
          "type": "course|lab|practice|cert",
          "duration": "X hours",
          "description": "Brief description",
          "free_resource": "Specific free resource name/URL",
          "xp": 100
        }
      ],
      "milestone": "What you can do after this phase",
      "project": "Hands-on project to build"
    }
  ],
  "certifications": [
    { "name": "Cert name", "timing": "After phase X", "cost": "$XXX or Free", "priority": "Must/Recommended/Optional" }
  ],
  "daily_routine": {
    "morning": "30min task",
    "main": "Main study block",
    "evening": "Practice/review task"
  },
  "success_metrics": ["metric1", "metric2", "metric3"],
  "job_titles": ["Job Title 1", "Job Title 2", "Job Title 3"]
}

Create exactly 4 phases. Make it realistic, actionable, and specific to ${goalLabel}. Include real free resources like TryHackMe, HackTheBox, YouTube channels, GitHub repos.`;

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 4000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await res.json();
      const text = data.content?.[0]?.text || "";
      const match = text.match(/\{[\s\S]*\}/);
      if (match) {
        const parsed = JSON.parse(match[0]);
        addLine(`> Path generated! ${parsed.phases.length} phases • ${parsed.total_weeks} weeks`, 0);
        addLine(`> Loading your personalized roadmap...`, 400);
        setTimeout(() => { setPath(parsed); setStep(4); setLoading(false); }, 800);
      }
    } catch (e) {
      addLine(`> ERROR: ${e.message}`, 0);
      setLoading(false);
    }
  };

  const toggleItem = (key) => {
    setCompletedItems(prev => {
      const next = new Set(prev);
      if (next.has(key)) { next.delete(key); setXp(x => Math.max(0, x - 100)); }
      else { next.add(key); setXp(x => x + 100); }
      return next;
    });
  };

  const goalCfg = GOALS.find(g => g.id === goal);

  const S = {
    page: {
      minHeight: "100vh", background: "#050a0e", color: "#c9d1d9",
      fontFamily: "'Courier New', monospace", position: "relative", overflow: "hidden",
    },
    grid: {
      position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
      backgroundImage: "linear-gradient(rgba(0,180,216,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,180,216,0.03) 1px,transparent 1px)",
      backgroundSize: "50px 50px",
    },
    scan: {
      position: "fixed", inset: 0, pointerEvents: "none", zIndex: 1,
      background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,180,216,0.012) 2px,rgba(0,180,216,0.012) 4px)",
    },
    wrap: { position: "relative", zIndex: 2, maxWidth: 900, margin: "0 auto", padding: "40px 20px" },
  };

  const typeColors = { course: "#00b4d8", lab: "#ff4560", practice: "#ffb800", cert: "#a855f7" };
  const typeIcons = { course: "📚", lab: "⚗️", practice: "🎯", cert: "🏆" };

  return (
    <div style={S.page}>
      <div style={S.grid} /><div style={S.scan} />
      <div style={S.wrap}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ fontSize: 11, letterSpacing: 6, color: "#00b4d8", marginBottom: 12, opacity: 0.7 }}>
            BREACHLABS // AI PATH BUILDER v1.0
          </div>
          <h1 style={{
            fontSize: "clamp(24px,5vw,44px)", fontWeight: 900, margin: 0, letterSpacing: -1,
            background: "linear-gradient(135deg,#00b4d8 0%,#00ff9d 50%,#a855f7 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            filter: glitch ? "blur(0.5px)" : "none", transition: "filter 0.1s",
          }}>LEARNING_PATH.ai</h1>
          <p style={{ color: "#8b949e", marginTop: 8, fontSize: 14 }}>
            مسار تعلم مخصص بالكامل ليك • AI-powered • مجاناً
          </p>
          {xp > 0 && (
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              background: "rgba(0,180,216,0.1)", border: "1px solid rgba(0,180,216,0.3)",
              borderRadius: 4, padding: "6px 16px", marginTop: 12, fontSize: 13,
            }}>
              <span style={{ color: "#00b4d8" }}>⚡</span>
              <span style={{ color: "#00b4d8", fontWeight: 700 }}>{xp} XP</span>
            </div>
          )}
        </div>

        {/* Step 0: Choose Goal */}
        {step === 0 && (
          <div>
            <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 3, marginBottom: 20, textAlign: "center" }}>
              STEP 1/3 — إيه هدفك؟
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))", gap: 12 }}>
              {GOALS.map(g => (
                <button key={g.id} onClick={() => { setGoal(g.id); setStep(1); }} style={{
                  background: "rgba(13,17,23,0.9)", border: `1px solid rgba(255,255,255,0.08)`,
                  borderRadius: 10, padding: "20px", cursor: "pointer", textAlign: "left",
                  transition: "all 0.25s", fontFamily: "'Courier New', monospace",
                  ":hover": { borderColor: g.color },
                }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = g.color; e.currentTarget.style.background = `rgba(13,17,23,1)`; e.currentTarget.style.transform = "translateY(-2px)"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; e.currentTarget.style.background = "rgba(13,17,23,0.9)"; e.currentTarget.style.transform = "none"; }}
                >
                  <div style={{ fontSize: 28, marginBottom: 10 }}>{g.icon}</div>
                  <div style={{ color: g.color, fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{g.label}</div>
                  <div style={{ color: "#8b949e", fontSize: 12 }}>اضغط لاختيار هذا المسار</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 1: Choose Level */}
        {step === 1 && (
          <div>
            <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 3, marginBottom: 8, textAlign: "center" }}>
              STEP 2/3 — مستواك الحالي؟
            </div>
            <div style={{ textAlign: "center", marginBottom: 24 }}>
              <span style={{ color: goalCfg?.color, fontSize: 14 }}>{goalCfg?.icon} {goalCfg?.label}</span>
              <span style={{ color: "#8b949e", fontSize: 14 }}> ← هدفك</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 12, marginBottom: 24 }}>
              {LEVELS.map(l => (
                <button key={l.id} onClick={() => { setLevel(l.id); setStep(2); }} style={{
                  background: "rgba(13,17,23,0.9)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 10, padding: "20px 16px", cursor: "pointer", textAlign: "center",
                  transition: "all 0.25s", fontFamily: "'Courier New', monospace",
                }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = "#00b4d8"; e.currentTarget.style.transform = "translateY(-2px)"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; e.currentTarget.style.transform = "none"; }}
                >
                  <div style={{ fontSize: 32, color: "#00b4d8", marginBottom: 8 }}>{l.icon}</div>
                  <div style={{ color: "#fff", fontWeight: 700, marginBottom: 4 }}>{l.label}</div>
                  <div style={{ color: "#8b949e", fontSize: 12 }}>{l.desc}</div>
                </button>
              ))}
            </div>
            <button onClick={() => setStep(0)} style={{
              background: "none", border: "1px solid rgba(255,255,255,0.1)", color: "#8b949e",
              borderRadius: 6, padding: "8px 20px", cursor: "pointer", fontSize: 13,
              fontFamily: "'Courier New', monospace",
            }}>← رجوع</button>
          </div>
        )}

        {/* Step 2: Choose Time */}
        {step === 2 && (
          <div>
            <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 3, marginBottom: 8, textAlign: "center" }}>
              STEP 3/3 — قد إيه وقتك في اليوم؟
            </div>
            <div style={{ textAlign: "center", marginBottom: 24, display: "flex", justifyContent: "center", gap: 16, flexWrap: "wrap" }}>
              <span style={{ color: goalCfg?.color, fontSize: 13 }}>{goalCfg?.icon} {goalCfg?.label}</span>
              <span style={{ color: "#4a5568" }}>•</span>
              <span style={{ color: "#00b4d8", fontSize: 13 }}>{LEVELS.find(l => l.id === level)?.label}</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 12, marginBottom: 24 }}>
              {TIME_OPTIONS.map(t => (
                <button key={t.id} onClick={() => { setTime(t.id); generatePath(); }} style={{
                  background: "rgba(13,17,23,0.9)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 10, padding: "24px 16px", cursor: "pointer", textAlign: "center",
                  transition: "all 0.25s", fontFamily: "'Courier New', monospace",
                }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = "#00ff9d"; e.currentTarget.style.transform = "translateY(-2px)"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; e.currentTarget.style.transform = "none"; }}
                >
                  <div style={{ color: "#00ff9d", fontSize: 22, fontWeight: 900, marginBottom: 6 }}>{t.label}</div>
                  <div style={{ color: "#8b949e", fontSize: 12 }}>~{t.weeks} أسبوع للإتمام</div>
                </button>
              ))}
            </div>
            <button onClick={() => setStep(1)} style={{
              background: "none", border: "1px solid rgba(255,255,255,0.1)", color: "#8b949e",
              borderRadius: 6, padding: "8px 20px", cursor: "pointer", fontSize: 13,
              fontFamily: "'Courier New', monospace",
            }}>← رجوع</button>
          </div>
        )}

        {/* Step 3: Generating */}
        {step === 3 && (
          <div style={{
            background: "rgba(13,17,23,0.9)", border: "1px solid rgba(0,180,216,0.2)",
            borderRadius: 10, overflow: "hidden",
          }}>
            <div style={{
              background: "rgba(0,180,216,0.05)", padding: "12px 20px",
              borderBottom: "1px solid rgba(0,180,216,0.15)",
              fontSize: 11, color: "#00b4d8", letterSpacing: 2,
            }}>⚙ AI PATH OPTIMIZER — RUNNING</div>
            <div style={{ padding: 24, minHeight: 200 }}>
              {termLines.map((l, i) => (
                <div key={i} style={{ color: "#00b4d8", fontSize: 13, marginBottom: 6, opacity: 0.9 }}>{l}</div>
              ))}
              <div style={{ color: "#00b4d8", animation: "blink 1s infinite" }}>█</div>
            </div>
            <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
          </div>
        )}

        {/* Step 4: Result */}
        {step === 4 && path && (
          <div>
            {/* Path Header */}
            <div style={{
              background: "linear-gradient(135deg,rgba(0,180,216,0.08),rgba(168,85,247,0.08))",
              border: `1px solid ${goalCfg?.color}33`, borderRadius: 12, padding: 28, marginBottom: 24,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 11, color: goalCfg?.color, letterSpacing: 3, marginBottom: 8 }}>
                    {goalCfg?.icon} YOUR PERSONALIZED ROADMAP
                  </div>
                  <h2 style={{ margin: "0 0 6px", fontSize: 26, color: "#fff" }}>{path.title}</h2>
                  <p style={{ margin: "0 0 16px", color: goalCfg?.color, fontStyle: "italic", fontSize: 14 }}>{path.tagline}</p>
                  <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                    {[
                      { label: "المدة", val: `${path.total_weeks} أسبوع` },
                      { label: "الـ XP", val: `${path.total_xp} XP` },
                      { label: "المراحل", val: `${path.phases?.length} phases` },
                    ].map(({ label, val }) => (
                      <div key={label} style={{
                        background: "rgba(0,0,0,0.3)", borderRadius: 6, padding: "8px 14px",
                        fontSize: 13,
                      }}>
                        <span style={{ color: "#8b949e" }}>{label}: </span>
                        <span style={{ color: "#fff", fontWeight: 700 }}>{val}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Job Titles */}
                {path.job_titles && (
                  <div style={{ minWidth: 180 }}>
                    <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 8 }}>وظايف هتقدر تشتغلها:</div>
                    {path.job_titles.map(j => (
                      <div key={j} style={{
                        background: "rgba(0,255,157,0.05)", border: "1px solid rgba(0,255,157,0.15)",
                        borderRadius: 4, padding: "5px 10px", fontSize: 12, color: "#00ff9d", marginBottom: 5,
                      }}>▸ {j}</div>
                    ))}
                  </div>
                )}
              </div>

              {/* Progress Bar */}
              <div style={{ marginTop: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, fontSize: 12 }}>
                  <span style={{ color: "#8b949e" }}>OVERALL PROGRESS</span>
                  <span style={{ color: "#00ff9d" }}>{completedItems.size} items completed</span>
                </div>
                <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 4, height: 8 }}>
                  <div style={{
                    width: `${Math.min(100, (completedItems.size / (path.phases?.reduce((a, p) => a + p.topics?.length, 0) || 1)) * 100)}%`,
                    height: "100%", borderRadius: 4,
                    background: `linear-gradient(90deg, ${goalCfg?.color}, #00ff9d)`,
                    transition: "width 0.5s ease",
                  }} />
                </div>
              </div>
            </div>

            {/* Phases */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 3, marginBottom: 16 }}>◈ LEARNING PHASES</div>
              {path.phases?.map((phase, pi) => (
                <div key={pi} style={{
                  background: "rgba(13,17,23,0.9)", border: `1px solid ${expandedPhase === pi ? (phase.color || "#00b4d8") + "55" : "rgba(255,255,255,0.08)"}`,
                  borderRadius: 10, marginBottom: 12, overflow: "hidden", transition: "border-color 0.3s",
                }}>
                  {/* Phase Header */}
                  <button onClick={() => setExpandedPhase(expandedPhase === pi ? -1 : pi)} style={{
                    width: "100%", background: expandedPhase === pi ? `rgba(${phase.color ? phase.color.slice(1).match(/.{2}/g).map(h => parseInt(h, 16)).join(",") : "0,180,216"},0.08)` : "transparent",
                    border: "none", padding: "16px 20px", cursor: "pointer", textAlign: "left",
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    fontFamily: "'Courier New', monospace", transition: "background 0.2s",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                      <div style={{
                        width: 36, height: 36, borderRadius: "50%", border: `2px solid ${phase.color || "#00b4d8"}`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        color: phase.color || "#00b4d8", fontWeight: 900, fontSize: 14, flexShrink: 0,
                      }}>{pi + 1}</div>
                      <div>
                        <div style={{ color: "#fff", fontWeight: 700, fontSize: 15 }}>{phase.title}</div>
                        <div style={{ color: "#8b949e", fontSize: 12, marginTop: 2 }}>
                          {phase.duration} • {phase.topics?.length} topics • {phase.xp} XP
                        </div>
                      </div>
                    </div>
                    <span style={{ color: phase.color || "#00b4d8", fontSize: 18 }}>
                      {expandedPhase === pi ? "−" : "+"}
                    </span>
                  </button>

                  {/* Phase Content */}
                  {expandedPhase === pi && (
                    <div style={{ padding: "0 20px 20px", borderTop: `1px solid rgba(255,255,255,0.05)` }}>
                      <p style={{ color: "#8b949e", fontSize: 13, lineHeight: 1.7, margin: "16px 0" }}>
                        {phase.description}
                      </p>

                      {/* Topics */}
                      <div style={{ marginBottom: 16 }}>
                        {phase.topics?.map((topic, ti) => {
                          const key = `${pi}-${ti}`;
                          const done = completedItems.has(key);
                          return (
                            <div key={ti} onClick={() => toggleItem(key)} style={{
                              display: "flex", gap: 12, padding: "12px", borderRadius: 8, marginBottom: 8,
                              background: done ? "rgba(0,255,157,0.05)" : "rgba(0,0,0,0.3)",
                              border: `1px solid ${done ? "rgba(0,255,157,0.2)" : "rgba(255,255,255,0.06)"}`,
                              cursor: "pointer", transition: "all 0.2s", alignItems: "flex-start",
                            }}>
                              <div style={{
                                width: 22, height: 22, borderRadius: 4, flexShrink: 0, marginTop: 1,
                                background: done ? "#00ff9d" : "rgba(255,255,255,0.05)",
                                border: `1px solid ${done ? "#00ff9d" : "rgba(255,255,255,0.2)"}`,
                                display: "flex", alignItems: "center", justifyContent: "center",
                                fontSize: 12, color: done ? "#000" : "transparent",
                              }}>✓</div>
                              <div style={{ flex: 1 }}>
                                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4, flexWrap: "wrap" }}>
                                  <span style={{ color: done ? "#00ff9d" : "#c9d1d9", fontWeight: 600, fontSize: 14 }}>
                                    {typeIcons[topic.type]} {topic.name}
                                  </span>
                                  <span style={{
                                    background: `${typeColors[topic.type]}22`, border: `1px solid ${typeColors[topic.type]}44`,
                                    color: typeColors[topic.type], borderRadius: 4, padding: "1px 8px", fontSize: 10, letterSpacing: 1,
                                  }}>{topic.type?.toUpperCase()}</span>
                                  <span style={{ color: "#8b949e", fontSize: 11 }}>⏱ {topic.duration}</span>
                                  <span style={{ color: "#ffb800", fontSize: 11 }}>+{topic.xp} XP</span>
                                </div>
                                <div style={{ color: "#8b949e", fontSize: 12, marginBottom: 4 }}>{topic.description}</div>
                                {topic.free_resource && (
                                  <div style={{ color: "#00b4d8", fontSize: 11 }}>
                                    🔗 {topic.free_resource}
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* Milestone & Project */}
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                        <div style={{
                          background: "rgba(0,255,157,0.05)", border: "1px solid rgba(0,255,157,0.15)",
                          borderRadius: 8, padding: 14,
                        }}>
                          <div style={{ fontSize: 11, color: "#00ff9d", letterSpacing: 2, marginBottom: 6 }}>🏁 MILESTONE</div>
                          <div style={{ fontSize: 13, color: "#c9d1d9", lineHeight: 1.6 }}>{phase.milestone}</div>
                        </div>
                        <div style={{
                          background: "rgba(168,85,247,0.05)", border: "1px solid rgba(168,85,247,0.15)",
                          borderRadius: 8, padding: 14,
                        }}>
                          <div style={{ fontSize: 11, color: "#a855f7", letterSpacing: 2, marginBottom: 6 }}>🛠 PROJECT</div>
                          <div style={{ fontSize: 13, color: "#c9d1d9", lineHeight: 1.6 }}>{phase.project}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Certifications */}
            {path.certifications && (
              <div style={{
                background: "rgba(13,17,23,0.9)", border: "1px solid rgba(255,184,0,0.2)",
                borderRadius: 10, padding: 20, marginBottom: 24,
              }}>
                <div style={{ fontSize: 11, color: "#ffb800", letterSpacing: 2, marginBottom: 16 }}>🏆 CERTIFICATIONS ROADMAP</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 10 }}>
                  {path.certifications.map((cert, i) => (
                    <div key={i} style={{
                      background: "rgba(255,184,0,0.04)", border: "1px solid rgba(255,184,0,0.15)",
                      borderRadius: 8, padding: 14,
                    }}>
                      <div style={{ color: "#ffb800", fontWeight: 700, fontSize: 14, marginBottom: 6 }}>{cert.name}</div>
                      <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 4 }}>⏰ {cert.timing}</div>
                      <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 6 }}>💰 {cert.cost}</div>
                      <div style={{
                        fontSize: 11, padding: "2px 8px", borderRadius: 4, display: "inline-block",
                        background: cert.priority === "Must" ? "rgba(255,69,96,0.15)" : cert.priority === "Recommended" ? "rgba(0,180,216,0.15)" : "rgba(255,255,255,0.05)",
                        color: cert.priority === "Must" ? "#ff4560" : cert.priority === "Recommended" ? "#00b4d8" : "#8b949e",
                        border: `1px solid ${cert.priority === "Must" ? "rgba(255,69,96,0.3)" : cert.priority === "Recommended" ? "rgba(0,180,216,0.3)" : "rgba(255,255,255,0.1)"}`,
                      }}>{cert.priority}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Daily Routine */}
            {path.daily_routine && (
              <div style={{
                background: "rgba(13,17,23,0.9)", border: "1px solid rgba(0,180,216,0.2)",
                borderRadius: 10, padding: 20, marginBottom: 24,
              }}>
                <div style={{ fontSize: 11, color: "#00b4d8", letterSpacing: 2, marginBottom: 16 }}>📅 DAILY ROUTINE</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
                  {[
                    { label: "🌅 الصبح", val: path.daily_routine.morning, color: "#ffb800" },
                    { label: "⚡ الدراسة", val: path.daily_routine.main, color: "#00b4d8" },
                    { label: "🌙 المساء", val: path.daily_routine.evening, color: "#a855f7" },
                  ].map(({ label, val, color }) => (
                    <div key={label} style={{
                      background: `${color}0a`, border: `1px solid ${color}22`,
                      borderRadius: 8, padding: 14, textAlign: "center",
                    }}>
                      <div style={{ fontSize: 13, color, fontWeight: 700, marginBottom: 6 }}>{label}</div>
                      <div style={{ fontSize: 12, color: "#8b949e", lineHeight: 1.6 }}>{val}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Reset Button */}
            <div style={{ textAlign: "center" }}>
              <button onClick={() => { setStep(0); setPath(null); setGoal(null); setLevel(null); setTime(null); setCompletedItems(new Set()); setXp(0); }} style={{
                background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)",
                color: "#8b949e", borderRadius: 6, padding: "10px 24px",
                cursor: "pointer", fontSize: 13, fontFamily: "'Courier New', monospace",
              }}>
                ↺ إنشاء مسار جديد
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
