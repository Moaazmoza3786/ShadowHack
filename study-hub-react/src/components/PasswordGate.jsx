import React, { useState, useEffect, useRef } from "react";
import "./PasswordGate.css";

const PasswordGate = ({ onAccessGranted }) => {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [glitchText, setGlitchText] = useState("SHADOWHACK");
  const [terminalLines, setTerminalLines] = useState([]);
  // Stable fake IP generated once per session (not re-rolled on every render)
  const fakeIpRef = useRef(
    `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
  );
  const sessionIdRef = useRef(Date.now().toString(36).toUpperCase());

  // Glitch effect for title
  useEffect(() => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*";
    const original = "SHADOWHACK";
    let interval;

    const glitch = () => {
      let result = "";
      for (let i = 0; i < original.length; i++) {
        if (Math.random() > 0.7) {
          result += chars[Math.floor(Math.random() * chars.length)];
        } else {
          result += original[i];
        }
      }
      setGlitchText(result);
    };

    interval = setInterval(glitch, 100);
    setTimeout(() => {
      clearInterval(interval);
      setGlitchText(original);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // Terminal boot sequence
  useEffect(() => {
    const bootSequence = [
      "> Initializing secure connection...",
      "> Bypassing firewall protocols...",
      "> Establishing encrypted tunnel...",
      "> Loading dark web interface...",
      "> ACCESS TERMINAL READY",
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < bootSequence.length) {
        setTerminalLines((prev) => [...prev, bootSequence[i]]);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 400);

    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    // Simulate hacking animation delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    try {
      const res = await fetch("/api/auth/verify-access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: password }),
      });

      // Guard against non-JSON responses (e.g. backend offline)
      const text = await res.text();
      if (!text.trim().startsWith("{")) {
        throw new Error("Backend is unreachable. Please start the server.");
      }
      const data = JSON.parse(text);

      if (data.success) {
        setTerminalLines((prev) => [
          ...prev,
          "> ACCESS GRANTED",
          "> Welcome, Operator...",
        ]);
        localStorage.setItem("shadowhack_access", "granted");
        await new Promise((resolve) => setTimeout(resolve, 1000));
        onAccessGranted();
      } else {
        setTerminalLines((prev) => [
          ...prev,
          "> ACCESS DENIED",
          "> Invalid credentials detected",
        ]);
        setError("ACCESS DENIED - Invalid Code");
        setLoading(false);
      }
    } catch (err) {
      setTerminalLines((prev) => [...prev, `> ERROR: ${err.message}`]);
      setError(`CONNECTION ERROR - ${err.message}`);
      setLoading(false);
    }
  };

  return (
    <div className="password-gate">
      <div className="gate-background">
        <div className="matrix-rain"></div>
        <div className="scanline"></div>
      </div>

      <div className="gate-container">
        <div className="gate-header">
          <div className="skull-icon">💀</div>
          <h1 className="glitch-title" data-text={glitchText}>
            {glitchText}
          </h1>
          <p className="gate-subtitle">RESTRICTED ACCESS TERMINAL</p>
        </div>

        <div className="terminal-window">
          <div className="terminal-header">
            <span className="terminal-dot red"></span>
            <span className="terminal-dot yellow"></span>
            <span className="terminal-dot green"></span>
            <span className="terminal-title">root@shadowhack:~</span>
          </div>
          <div className="terminal-body">
            {terminalLines.map((line, i) => (
              <div
                key={i}
                className={`terminal-line ${line?.includes && line.includes("DENIED") ? "error" : line?.includes && line.includes("GRANTED") ? "success" : ""}`}
              >
                {line || ""}
              </div>
            ))}
            <div className="terminal-cursor">_</div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="gate-form">
          <input
            type="text"
            name="username"
            autoComplete="username"
            style={{ display: "none" }}
            aria-hidden="true"
          />
          <div className="input-wrapper">
            <span className="input-icon">🔑</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter Access Code..."
              className="gate-input"
              autoFocus
              autoComplete="new-password"
              disabled={loading}
            />
          </div>

          {error && <div className="gate-error">{error}</div>}

          <button type="submit" className="gate-button" disabled={loading}>
            {loading ? (
              <span className="loading-text">
                <span className="spinner"></span>
                AUTHENTICATING...
              </span>
            ) : (
              <>
                <span className="button-icon">⚡</span>
                INITIALIZE ACCESS
              </>
            )}
          </button>
        </form>

        <div className="gate-footer">
          <p>⚠️ Unauthorized access will be traced and reported</p>
          <p className="ip-display">
            Your IP: {fakeIpRef.current} | Session: {sessionIdRef.current}
          </p>
        </div>
      </div>
    </div>
  );
};

export default PasswordGate;
