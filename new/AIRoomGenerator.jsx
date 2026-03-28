import { useState, useEffect, useRef } from "react";

const DIFFICULTY_CONFIG = {
  Beginner: { color: "#00ff9d", icon: "◈", xp: 100 },
  Intermediate: { color: "#ffb800", icon: "◉", xp: 250 },
  Advanced: { color: "#ff4560", icon: "⬡", xp: 500 },
};

const TOPIC_PRESETS = [
  "SQL Injection", "XSS Attacks", "Buffer Overflow", "SSRF",
  "IDOR Vulnerabilities", "JWT Attacks", "DNS Enumeration",
  "Active Directory Attacks", "Privilege Escalation Linux",
  "OWASP Top 10", "Metasploit Basics", "Burp Suite Pro",
];

export default function AIRoomGenerator() {
  const [topic, setTopic] = useState("");
  const [difficulty, setDifficulty] = useState("Intermediate");
  const [room, setRoom] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTask, setActiveTask] = useState(0);
  const [completedTasks, setCompletedTasks] = useState(new Set());
  const [showHint, setShowHint] = useState({});
  const [quizAnswers, setQuizAnswers] = useState({});
  const [quizResults, setQuizResults] = useState({});
  const [xp, setXp] = useState(0);
  const [glitchText, setGlitchText] = useState(false);
  const [terminalLines, setTerminalLines] = useState([]);
  const terminalRef = useRef(null);

  useEffect(() => {
    const interval = setInterval(() => setGlitchText(g => !g), 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const addTerminalLine = (line, delay = 0) => {
    setTimeout(() => {
      setTerminalLines(prev => [...prev, line]);
    }, delay);
  };

  const generateRoom = async () => {
    if (!topic.trim()) return;
    setLoading(true);
    setRoom(null);
    setCompletedTasks(new Set());
    setShowHint({});
    setQuizAnswers({});
    setQuizResults({});
    setActiveTask(0);
    setTerminalLines([]);

    addTerminalLine(`> Initializing AI Room Generator...`, 0);
    addTerminalLine(`> Target: ${topic}`, 200);
    addTerminalLine(`> Difficulty: ${difficulty}`, 400);
    addTerminalLine(`> Scanning knowledge base...`, 700);
    addTerminalLine(`> Building attack scenarios...`, 1200);
    addTerminalLine(`> Generating interactive tasks...`, 1700);
    addTerminalLine(`> Crafting quiz challenges...`, 2200);

    const prompt = `You are an expert cybersecurity educator. Generate a detailed, high-quality learning room about "${topic}" at ${difficulty} level.

Return ONLY valid JSON with this exact structure:
{
  "title": "Room title (creative, hacker-style)",
  "subtitle": "One line mission briefing",
  "description": "3-4 sentences explaining what the student will learn",
  "objectives": ["objective 1", "objective 2", "objective 3", "objective 4"],
  "tasks": [
    {
      "id": 1,
      "title": "Task title",
      "content": "Detailed explanation with markdown-style formatting. Include code examples using backticks, explain concepts deeply. At least 200 words.",
      "command_example": "actual terminal command or code example",
      "hint": "A helpful hint that guides without giving away the answer"
    }
  ],
  "quiz": [
    {
      "id": 1,
      "question": "Question text",
      "options": ["A) option", "B) option", "C) option", "D) option"],
      "correct": 0,
      "explanation": "Why this answer is correct"
    }
  ],
  "flags": ["FLAG{example_flag_1}", "FLAG{example_flag_2}"],
  "tools": ["tool1", "tool2", "tool3"],
  "references": ["Reference 1", "Reference 2"]
}

Generate exactly 4 tasks and 4 quiz questions. Make content deep, technical, and educational. For ${difficulty} level.`;

    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 4000,
          messages: [{ role: "user", content: prompt }],
        }),
      });

      const data = await response.json();
      const text = data.content?.[0]?.text || "";
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        addTerminalLine(`> Room generated successfully!`, 0);
        addTerminalLine(`> [${parsed.tasks.length} tasks] [${parsed.quiz.length} questions] [${parsed.flags.length} flags]`, 200);
        addTerminalLine(`> Loading room interface...`, 500);
        setTimeout(() => {
          setRoom(parsed);
          setLoading(false);
        }, 800);
      }
    } catch (err) {
      addTerminalLine(`> ERROR: ${err.message}`, 0);
      setLoading(false);
    }
  };

  const completeTask = (taskId) => {
    if (!completedTasks.has(taskId)) {
      setCompletedTasks(prev => new Set([...prev, taskId]));
      const earned = DIFFICULTY_CONFIG[difficulty].xp / 4;
      setXp(prev => prev + earned);
    }
  };

  const submitQuiz = (qId, answerIdx) => {
    const q = room.quiz[qId];
    const correct = answerIdx === q.correct;
    setQuizResults(prev => ({ ...prev, [qId]: { correct, explanation: q.explanation } }));
    if (correct) setXp(prev => prev + 50);
  };

  const diffCfg = DIFFICULTY_CONFIG[difficulty];

  return (
    <div style={{
      minHeight: "100vh",
      background: "#050a0e",
      color: "#c9d1d9",
      fontFamily: "'Courier New', monospace",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Scanline effect */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 1,
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,157,0.015) 2px, rgba(0,255,157,0.015) 4px)",
      }} />

      {/* Grid background */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: "linear-gradient(rgba(0,255,157,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,157,0.03) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
      }} />

      <div style={{ position: "relative", zIndex: 2, maxWidth: 960, margin: "0 auto", padding: "40px 20px" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ fontSize: 11, letterSpacing: 6, color: "#00ff9d", marginBottom: 12, opacity: 0.7 }}>
            BREACHLABS // AI ROOM GENERATOR v2.0
          </div>
          <h1 style={{
            fontSize: "clamp(28px, 5vw, 48px)",
            fontWeight: 900,
            margin: 0,
            letterSpacing: -1,
            background: "linear-gradient(135deg, #00ff9d 0%, #00b4d8 50%, #7c3aed 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            filter: glitchText ? "blur(1px)" : "none",
            transition: "filter 0.1s",
          }}>
            ROOM_GENERATOR.exe
          </h1>
          <p style={{ color: "#8b949e", marginTop: 8, fontSize: 14 }}>
            AI-powered cybersecurity rooms • TryHackMe style • Infinite content
          </p>

          {xp > 0 && (
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              background: "rgba(0,255,157,0.1)", border: "1px solid rgba(0,255,157,0.3)",
              borderRadius: 4, padding: "6px 16px", marginTop: 12, fontSize: 13,
            }}>
              <span style={{ color: "#00ff9d" }}>⚡</span>
              <span style={{ color: "#00ff9d", fontWeight: 700 }}>{xp} XP</span>
              <span style={{ color: "#8b949e" }}>earned this session</span>
            </div>
          )}
        </div>

        {/* Generator Panel */}
        <div style={{
          background: "rgba(13,17,23,0.9)",
          border: "1px solid rgba(0,255,157,0.2)",
          borderRadius: 8,
          padding: 28,
          marginBottom: 32,
          backdropFilter: "blur(10px)",
        }}>
          <div style={{ fontSize: 11, color: "#00ff9d", letterSpacing: 3, marginBottom: 20, opacity: 0.7 }}>
            ◈ CONFIGURE ROOM
          </div>

          {/* Topic Presets */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 10, letterSpacing: 2 }}>QUICK SELECT:</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {TOPIC_PRESETS.map(t => (
                <button key={t} onClick={() => setTopic(t)} style={{
                  background: topic === t ? "rgba(0,255,157,0.15)" : "rgba(255,255,255,0.03)",
                  border: `1px solid ${topic === t ? "rgba(0,255,157,0.5)" : "rgba(255,255,255,0.1)"}`,
                  color: topic === t ? "#00ff9d" : "#8b949e",
                  borderRadius: 4, padding: "5px 12px", fontSize: 12,
                  cursor: "pointer", transition: "all 0.2s",
                }}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Custom Topic */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 8, letterSpacing: 2 }}>OR TYPE CUSTOM TOPIC:</div>
            <input
              value={topic}
              onChange={e => setTopic(e.target.value)}
              onKeyDown={e => e.key === "Enter" && generateRoom()}
              placeholder="e.g. Kerberoasting, Log4Shell, CSRF..."
              style={{
                width: "100%", background: "rgba(0,0,0,0.4)",
                border: "1px solid rgba(0,255,157,0.3)", borderRadius: 6,
                padding: "12px 16px", color: "#c9d1d9", fontSize: 14,
                outline: "none", boxSizing: "border-box",
                fontFamily: "'Courier New', monospace",
              }}
            />
          </div>

          {/* Difficulty */}
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 10, letterSpacing: 2 }}>DIFFICULTY:</div>
            <div style={{ display: "flex", gap: 10 }}>
              {Object.entries(DIFFICULTY_CONFIG).map(([d, cfg]) => (
                <button key={d} onClick={() => setDifficulty(d)} style={{
                  flex: 1, padding: "10px 0", borderRadius: 6, cursor: "pointer",
                  background: difficulty === d ? `rgba(${d === "Beginner" ? "0,255,157" : d === "Intermediate" ? "255,184,0" : "255,69,96"},0.15)` : "rgba(255,255,255,0.03)",
                  border: `1px solid ${difficulty === d ? cfg.color : "rgba(255,255,255,0.1)"}`,
                  color: difficulty === d ? cfg.color : "#8b949e",
                  fontSize: 13, fontFamily: "'Courier New', monospace",
                  transition: "all 0.2s",
                }}>
                  {cfg.icon} {d}
                  <div style={{ fontSize: 10, opacity: 0.7, marginTop: 2 }}>{cfg.xp} XP</div>
                </button>
              ))}
            </div>
          </div>

          {/* Generate Button */}
          <button onClick={generateRoom} disabled={loading || !topic.trim()} style={{
            width: "100%", padding: "14px 0", borderRadius: 6,
            background: loading || !topic.trim() ? "rgba(0,255,157,0.05)" : "linear-gradient(135deg, rgba(0,255,157,0.2) 0%, rgba(0,180,216,0.2) 100%)",
            border: `1px solid ${loading || !topic.trim() ? "rgba(0,255,157,0.1)" : "rgba(0,255,157,0.5)"}`,
            color: loading || !topic.trim() ? "#4a5568" : "#00ff9d",
            fontSize: 14, fontWeight: 700, letterSpacing: 3,
            cursor: loading || !topic.trim() ? "not-allowed" : "pointer",
            fontFamily: "'Courier New', monospace",
            transition: "all 0.3s",
          }}>
            {loading ? "⚙ GENERATING ROOM..." : "⚡ GENERATE ROOM"}
          </button>
        </div>

        {/* Terminal Output */}
        {(loading || terminalLines.length > 0) && (
          <div style={{
            background: "#0a0a0a", border: "1px solid rgba(0,255,157,0.15)",
            borderRadius: 8, marginBottom: 32, overflow: "hidden",
          }}>
            <div style={{
              background: "rgba(0,255,157,0.05)", padding: "8px 16px",
              borderBottom: "1px solid rgba(0,255,157,0.1)",
              fontSize: 11, color: "#00ff9d", letterSpacing: 2,
            }}>
              ● TERMINAL OUTPUT
            </div>
            <div ref={terminalRef} style={{
              padding: 20, maxHeight: 200, overflowY: "auto", fontSize: 13,
            }}>
              {terminalLines.map((line, i) => (
                <div key={i} style={{ color: "#00ff9d", marginBottom: 4, opacity: 0.85 }}>
                  {line}
                </div>
              ))}
              {loading && <div style={{ color: "#00ff9d", animation: "pulse 1s infinite" }}>█</div>}
            </div>
          </div>
        )}

        {/* Room Content */}
        {room && (
          <div>
            {/* Room Header */}
            <div style={{
              background: "linear-gradient(135deg, rgba(0,255,157,0.08) 0%, rgba(124,58,237,0.08) 100%)",
              border: "1px solid rgba(0,255,157,0.25)", borderRadius: 12,
              padding: 32, marginBottom: 24,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, color: diffCfg.color, letterSpacing: 3, marginBottom: 8 }}>
                    {diffCfg.icon} {difficulty.toUpperCase()} ROOM • {diffCfg.xp} XP
                  </div>
                  <h2 style={{ margin: "0 0 8px", fontSize: 28, color: "#fff", letterSpacing: -0.5 }}>
                    {room.title}
                  </h2>
                  <p style={{ margin: "0 0 16px", color: "#00ff9d", fontStyle: "italic", fontSize: 14 }}>
                    {room.subtitle}
                  </p>
                  <p style={{ margin: 0, color: "#8b949e", lineHeight: 1.7, fontSize: 14 }}>
                    {room.description}
                  </p>
                </div>
                <div style={{ minWidth: 160 }}>
                  <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 8 }}>TOOLS NEEDED:</div>
                  {room.tools?.map(t => (
                    <div key={t} style={{
                      background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 4, padding: "4px 10px", fontSize: 12, color: "#c9d1d9",
                      marginBottom: 4, display: "inline-block", marginRight: 6,
                    }}>{t}</div>
                  ))}
                </div>
              </div>

              {/* Objectives */}
              <div style={{ marginTop: 24, padding: 16, background: "rgba(0,0,0,0.3)", borderRadius: 8 }}>
                <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 12 }}>OBJECTIVES:</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 8 }}>
                  {room.objectives?.map((obj, i) => (
                    <div key={i} style={{ display: "flex", gap: 8, fontSize: 13, color: "#c9d1d9" }}>
                      <span style={{ color: "#00ff9d", flexShrink: 0 }}>▸</span>
                      <span>{obj}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Progress */}
              <div style={{ marginTop: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, fontSize: 12 }}>
                  <span style={{ color: "#8b949e" }}>ROOM PROGRESS</span>
                  <span style={{ color: "#00ff9d" }}>{completedTasks.size}/{room.tasks.length} tasks</span>
                </div>
                <div style={{ background: "rgba(0,0,0,0.4)", borderRadius: 4, height: 6 }}>
                  <div style={{
                    width: `${(completedTasks.size / room.tasks.length) * 100}%`,
                    height: "100%", borderRadius: 4,
                    background: "linear-gradient(90deg, #00ff9d, #00b4d8)",
                    transition: "width 0.5s ease",
                  }} />
                </div>
              </div>
            </div>

            {/* Tasks */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 3, marginBottom: 16 }}>◈ TASKS</div>
              <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
                {room.tasks.map((t, i) => (
                  <button key={i} onClick={() => setActiveTask(i)} style={{
                    padding: "8px 16px", borderRadius: 6, cursor: "pointer", fontSize: 13,
                    background: activeTask === i ? "rgba(0,255,157,0.15)" : completedTasks.has(i) ? "rgba(0,255,157,0.05)" : "rgba(255,255,255,0.03)",
                    border: `1px solid ${activeTask === i ? "rgba(0,255,157,0.5)" : completedTasks.has(i) ? "rgba(0,255,157,0.2)" : "rgba(255,255,255,0.1)"}`,
                    color: activeTask === i ? "#00ff9d" : completedTasks.has(i) ? "#00ff9d" : "#8b949e",
                    fontFamily: "'Courier New', monospace",
                    transition: "all 0.2s",
                  }}>
                    {completedTasks.has(i) ? "✓" : `[${i + 1}]`} {t.title}
                  </button>
                ))}
              </div>

              {/* Active Task */}
              {room.tasks[activeTask] && (() => {
                const task = room.tasks[activeTask];
                return (
                  <div style={{
                    background: "rgba(13,17,23,0.9)", border: "1px solid rgba(0,255,157,0.2)",
                    borderRadius: 10, overflow: "hidden",
                  }}>
                    <div style={{
                      background: "rgba(0,255,157,0.05)", padding: "14px 20px",
                      borderBottom: "1px solid rgba(0,255,157,0.1)",
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                    }}>
                      <span style={{ color: "#00ff9d", fontWeight: 700 }}>Task {activeTask + 1}: {task.title}</span>
                      {completedTasks.has(activeTask) && (
                        <span style={{ color: "#00ff9d", fontSize: 12 }}>✓ COMPLETED</span>
                      )}
                    </div>
                    <div style={{ padding: 24 }}>
                      <div style={{ lineHeight: 1.8, fontSize: 14, color: "#c9d1d9", marginBottom: 20, whiteSpace: "pre-wrap" }}>
                        {task.content}
                      </div>

                      {/* Command Example */}
                      {task.command_example && (
                        <div style={{ marginBottom: 20 }}>
                          <div style={{ fontSize: 11, color: "#8b949e", letterSpacing: 2, marginBottom: 8 }}>EXAMPLE:</div>
                          <div style={{
                            background: "#0a0a0a", border: "1px solid rgba(0,255,157,0.15)",
                            borderRadius: 6, padding: 16, fontFamily: "'Courier New', monospace",
                            fontSize: 13, color: "#00ff9d", overflowX: "auto",
                          }}>
                            <span style={{ color: "#666", userSelect: "none" }}>$ </span>
                            {task.command_example}
                          </div>
                        </div>
                      )}

                      {/* Hint */}
                      <div style={{ marginBottom: 20 }}>
                        <button onClick={() => setShowHint(p => ({ ...p, [activeTask]: !p[activeTask] }))} style={{
                          background: "rgba(255,184,0,0.08)", border: "1px solid rgba(255,184,0,0.2)",
                          color: "#ffb800", borderRadius: 6, padding: "8px 16px", fontSize: 12,
                          cursor: "pointer", fontFamily: "'Courier New', monospace", letterSpacing: 1,
                        }}>
                          💡 {showHint[activeTask] ? "HIDE HINT" : "SHOW HINT"}
                        </button>
                        {showHint[activeTask] && (
                          <div style={{
                            marginTop: 10, padding: 14,
                            background: "rgba(255,184,0,0.05)", border: "1px solid rgba(255,184,0,0.15)",
                            borderRadius: 6, fontSize: 13, color: "#ffb800", lineHeight: 1.6,
                          }}>
                            {task.hint}
                          </div>
                        )}
                      </div>

                      {/* Navigation */}
                      <div style={{ display: "flex", gap: 10, justifyContent: "space-between" }}>
                        <button onClick={() => setActiveTask(Math.max(0, activeTask - 1))} disabled={activeTask === 0} style={{
                          padding: "10px 20px", borderRadius: 6, cursor: activeTask === 0 ? "not-allowed" : "pointer",
                          background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)",
                          color: activeTask === 0 ? "#4a5568" : "#8b949e", fontSize: 13,
                          fontFamily: "'Courier New', monospace",
                        }}>← PREV</button>

                        <button onClick={() => { completeTask(activeTask); if (activeTask < room.tasks.length - 1) setActiveTask(activeTask + 1); }} style={{
                          padding: "10px 24px", borderRadius: 6, cursor: "pointer",
                          background: completedTasks.has(activeTask) ? "rgba(0,255,157,0.05)" : "rgba(0,255,157,0.15)",
                          border: `1px solid ${completedTasks.has(activeTask) ? "rgba(0,255,157,0.2)" : "rgba(0,255,157,0.4)"}`,
                          color: "#00ff9d", fontSize: 13, fontWeight: 700,
                          fontFamily: "'Courier New', monospace",
                        }}>
                          {completedTasks.has(activeTask) ? "✓ DONE" : "COMPLETE TASK ▸"}
                        </button>

                        <button onClick={() => setActiveTask(Math.min(room.tasks.length - 1, activeTask + 1))} disabled={activeTask === room.tasks.length - 1} style={{
                          padding: "10px 20px", borderRadius: 6, cursor: activeTask === room.tasks.length - 1 ? "not-allowed" : "pointer",
                          background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.1)",
                          color: activeTask === room.tasks.length - 1 ? "#4a5568" : "#8b949e", fontSize: 13,
                          fontFamily: "'Courier New', monospace",
                        }}>NEXT →</button>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Quiz Section */}
            <div style={{
              background: "rgba(13,17,23,0.9)", border: "1px solid rgba(124,58,237,0.3)",
              borderRadius: 10, overflow: "hidden", marginBottom: 24,
            }}>
              <div style={{
                background: "rgba(124,58,237,0.08)", padding: "14px 20px",
                borderBottom: "1px solid rgba(124,58,237,0.2)",
              }}>
                <span style={{ color: "#a855f7", fontWeight: 700, letterSpacing: 1 }}>⬡ KNOWLEDGE CHECK</span>
                <span style={{ color: "#8b949e", fontSize: 12, marginLeft: 12 }}>
                  {Object.keys(quizResults).length}/{room.quiz.length} answered • +50 XP per correct
                </span>
              </div>
              <div style={{ padding: 24 }}>
                {room.quiz.map((q, qi) => (
                  <div key={qi} style={{ marginBottom: qi < room.quiz.length - 1 ? 28 : 0 }}>
                    <div style={{ fontSize: 14, color: "#c9d1d9", marginBottom: 14, fontWeight: 600 }}>
                      <span style={{ color: "#a855f7" }}>Q{qi + 1}.</span> {q.question}
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                      {q.options.map((opt, oi) => {
                        const result = quizResults[qi];
                        const isSelected = quizAnswers[qi] === oi;
                        const isCorrect = oi === q.correct;
                        let bg = "rgba(255,255,255,0.03)", border = "rgba(255,255,255,0.1)", color = "#8b949e";
                        if (result) {
                          if (isCorrect) { bg = "rgba(0,255,157,0.1)"; border = "rgba(0,255,157,0.4)"; color = "#00ff9d"; }
                          else if (isSelected) { bg = "rgba(255,69,96,0.1)"; border = "rgba(255,69,96,0.4)"; color = "#ff4560"; }
                        } else if (isSelected) { bg = "rgba(124,58,237,0.15)"; border = "rgba(124,58,237,0.4)"; color = "#a855f7"; }
                        return (
                          <button key={oi} onClick={() => {
                            if (!quizResults[qi]) {
                              setQuizAnswers(p => ({ ...p, [qi]: oi }));
                              submitQuiz(qi, oi);
                            }
                          }} style={{
                            background: bg, border: `1px solid ${border}`,
                            borderRadius: 6, padding: "10px 14px", textAlign: "left",
                            cursor: quizResults[qi] ? "default" : "pointer",
                            color, fontSize: 13, lineHeight: 1.4,
                            fontFamily: "'Courier New', monospace",
                            transition: "all 0.2s",
                          }}>{opt}</button>
                        );
                      })}
                    </div>
                    {quizResults[qi] && (
                      <div style={{
                        marginTop: 10, padding: 12,
                        background: quizResults[qi].correct ? "rgba(0,255,157,0.05)" : "rgba(255,69,96,0.05)",
                        border: `1px solid ${quizResults[qi].correct ? "rgba(0,255,157,0.2)" : "rgba(255,69,96,0.2)"}`,
                        borderRadius: 6, fontSize: 12,
                        color: quizResults[qi].correct ? "#00ff9d" : "#ff6b6b",
                      }}>
                        {quizResults[qi].correct ? "✓ Correct! " : "✗ Incorrect. "}
                        {quizResults[qi].explanation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Flags */}
            {room.flags && (
              <div style={{
                background: "rgba(13,17,23,0.9)", border: "1px solid rgba(255,184,0,0.2)",
                borderRadius: 8, padding: 20,
              }}>
                <div style={{ fontSize: 11, color: "#ffb800", letterSpacing: 2, marginBottom: 12 }}>◈ CHALLENGE FLAGS</div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  {room.flags.map((flag, i) => (
                    <div key={i} style={{
                      background: "rgba(255,184,0,0.05)", border: "1px solid rgba(255,184,0,0.2)",
                      borderRadius: 6, padding: "8px 16px", fontSize: 13,
                      color: "#ffb800", fontFamily: "'Courier New', monospace",
                    }}>{flag}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <style>{`
          @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
          button:hover { opacity: 0.9; }
          ::-webkit-scrollbar { width: 6px; } 
          ::-webkit-scrollbar-track { background: #0a0a0a; }
          ::-webkit-scrollbar-thumb { background: rgba(0,255,157,0.2); border-radius: 3px; }
        `}</style>
      </div>
    </div>
  );
}
