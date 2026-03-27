import React, { createContext, useContext, useState, useEffect } from "react";
import { calculateLevel, getRankTitle, LEVELS } from "../utils/levelUtils";

const AppContext = createContext();

const DEFAULT_API_URL = "/api";

export const AppProvider = ({ children }) => {
  const [apiUrl, setApiUrl] = useState(DEFAULT_API_URL);

  useEffect(() => {
    const loadConfig = async () => {
      try {
        const res = await fetch("/config.json");
        const text = await res.text();

        // Safety check: is it actually JSON?
        if (res.ok && text.trim().startsWith("{")) {
          const config = JSON.parse(text);
          if (config.apiUrl) {
            console.log("🚀 Dynamic API URL Loaded:", config.apiUrl);
            setApiUrl(config.apiUrl);
            return;
          }
        }
        throw new Error(
          `Invalid config response: ${res.status} ${text.substring(0, 50)}...`,
        );
      } catch (err) {
        console.warn(
          "Using default API URL (dynamic config failed):",
          err.message,
        );
        setApiUrl(DEFAULT_API_URL);
      }
    };
    loadConfig();
  }, []);
  const [user, setUser] = useState(() => {
    const defaultUser = {
      name: "Student",
      points: 0,
      level: 1,
      rank: "Neural Initiate",
      completedLessons: [],
      achievements: [],
      streak: 1,
      solvedCTFTasks: [],
      solveHistory: [],
      unlockedHints: [],
    };
    try {
      const saved = localStorage.getItem("user");
      if (saved) {
        const parsed = JSON.parse(saved);
        return { ...defaultUser, ...parsed };
      }
      return defaultUser;
    } catch (e) {
      console.error("Error parsing user from localStorage:", e);
      return defaultUser;
    }
  });

  const [language, setLanguage] = useState(() => {
    return localStorage.getItem("language") || "ar";
  });

  // Simulated "Global" Live Feed (User's latest + some preset ones)
  const [liveFeed, setLiveFeed] = useState([]);

  useEffect(() => {
    localStorage.setItem("user", JSON.stringify(user));
  }, [user]);

  useEffect(() => {
    localStorage.setItem("language", language);
    // Update document direction
    document.documentElement.dir = language === "ar" ? "rtl" : "ltr";
    document.documentElement.lang = language;
  }, [language]);

  const t = (ar, en) => (language === "ar" ? ar : en);

  const toggleLanguage = () =>
    setLanguage((prev) => (prev === "ar" ? "en" : "ar"));

  const addXP = (amount) => {
    setUser((prev) => {
      const newPoints = prev.points + amount;
      const newLevel = calculateLevel(newPoints);
      const newRank = getRankTitle(newLevel);
      return {
        ...prev,
        points: newPoints,
        level: newLevel,
        rank: newRank,
      };
    });
  };

  const unlockHint = (roomId, taskIdx, hintCost) => {
    const hintId = `${roomId}-${taskIdx}`;
    if ((user.unlockedHints || []).includes(hintId)) return true;
    if (user.points < hintCost) return false;

    setUser((prev) => ({
      ...prev,
      points: prev.points - hintCost,
      unlockedHints: [...(prev.unlockedHints || []), hintId],
    }));
    return true;
  };

  const solveCTFTask = (roomId, task, roomTitle) => {
    const globalTaskId = `${roomId}-${task.id}`;
    if ((user.solvedCTFTasks || []).includes(globalTaskId)) return false;

    setUser((prev) => ({
      ...prev,
      solvedCTFTasks: [...(prev.solvedCTFTasks || []), globalTaskId],
      solveHistory: [
        { user: prev.name, challenge: roomTitle, time: Date.now() },
        ...(prev.solveHistory || []),
      ].slice(0, 10),
    }));

    setLiveFeed((prev) =>
      [
        { user: user.name, challenge: roomTitle, time: Date.now() },
        ...prev,
      ].slice(0, 5),
    );

    addXP(task.points);
    return true;
  };

  const updateProgress = (lessonId) => {
    if ((user.completedLessons || []).includes(lessonId)) return;

    setUser((prev) => ({
      ...prev,
      completedLessons: [...(prev.completedLessons || []), lessonId],
    }));
    addXP(50); // standard XP per lesson
  };

  const unlockAchievement = (id, title) => {
    if (user.achievements.some((a) => a.id === id)) return;
    setUser((prev) => ({
      ...prev,
      achievements: [
        ...prev.achievements,
        { id, title, date: new Date().toLocaleDateString() },
      ],
    }));
    addXP(100);
  };

  return (
    <AppContext.Provider
      value={{
        user,
        setUser,
        language,
        setLanguage,
        t,
        toggleLanguage,
        updateProgress,
        addXP,
        unlockAchievement,
        solveCTFTask,
        unlockHint,
        liveFeed,
        LEVELS,
        apiUrl,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAppContext = () => useContext(AppContext);
