import React, { createContext, useContext, useState, useEffect } from 'react';
import { supabase, isSupabaseConfigured } from '../lib/supabase';

const AppContext = createContext();

export const DEFAULT_API_URL = '/api';

const LEVELS = [
    { level: 1, name: 'Neural Initiate', minXP: 0 },
    { level: 2, name: 'Data Scavenger', minXP: 100 },
    { level: 3, name: 'Logic Weaver', minXP: 300 },
    { level: 4, name: 'Pattern Breaker', minXP: 600 },
    { level: 5, name: 'System Architect', minXP: 1000 },
    { level: 6, name: 'Ghost in the Shell', minXP: 1500 },
    { level: 7, name: 'Neural Commander', minXP: 2200 },
    { level: 8, name: 'Quantum Auditor', minXP: 3000 },
    { level: 9, name: 'AI Overlord', minXP: 4000 },
    { level: 10, name: 'Digital Singularity', minXP: 5500 }
];

export const AppProvider = ({ children }) => {
    const [apiUrl, setApiUrl] = useState(DEFAULT_API_URL);

    useEffect(() => {
        const loadConfig = async () => {
            try {
                const res = await fetch('/config.json');
                const text = await res.text();

                // Safety check: is it actually JSON?
                if (res.ok && text.trim().startsWith('{')) {
                    const config = JSON.parse(text);
                    if (config.apiUrl) {
                        console.log("🚀 Dynamic API URL Loaded:", config.apiUrl);
                        setApiUrl(config.apiUrl);
                        return;
                    }
                }
                throw new Error(`Invalid config response: ${res.status} ${text.substring(0, 50)}...`);
            } catch (err) {
                console.warn("Using default API URL (dynamic config failed):", err.message);
                setApiUrl(DEFAULT_API_URL);
            }
        };
        loadConfig();
    }, []);
    const [user, setUser] = useState(() => {
        const defaultUser = {
            name: 'Student',
            points: 0,
            level: 1,
            rank: 'Neural Initiate',
            completedLessons: [],
            achievements: [],
            streak: 1,
            solvedCTFTasks: [],
            solveHistory: [],
            unlockedHints: []
        };
        try {
            const saved = localStorage.getItem('user');
            if (saved) {
                const parsed = JSON.parse(saved);
                return { ...defaultUser, ...parsed };
            }
            return defaultUser;
        } catch (e) {
            console.error('Error parsing user from localStorage:', e);
            return defaultUser;
        }
    });

    const [language, setLanguage] = useState(() => {
        return localStorage.getItem('language') || 'ar';
    });

    // Simulated "Global" Live Feed (User's latest + some preset ones)
    const [liveFeed, setLiveFeed] = useState([]);

    useEffect(() => {
        if (isSupabaseConfigured()) {
            console.log("Initialize Supabase Auth Listener");
            const { data: authListener } = supabase.auth.onAuthStateChange(async (event, session) => {
                if (session?.user) {
                    console.log("Supabase User Connected:", session.user.email);
                    // Here we would fetch the full profile from the 'profiles' table
                    // setUser(prev => ({ ...prev, email: session.user.email, id: session.user.id }));
                }
            });
            return () => {
                authListener.subscription.unsubscribe();
            };
        }
    }, []);

    useEffect(() => {
        localStorage.setItem('user', JSON.stringify(user));
    }, [user]);

    useEffect(() => {
        localStorage.setItem('language', language);
        // Update document direction
        document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = language;
    }, [language]);


    const t = (ar, en) => language === 'ar' ? ar : en;

    const toggleLanguage = () => setLanguage(prev => prev === 'ar' ? 'en' : 'ar');

    const addXP = (amount) => {
        setUser(prev => {
            const newPoints = prev.points + amount;
            const newLevel = LEVELS.slice().reverse().find(l => newPoints >= l.minXP) || LEVELS[0];

            return {
                ...prev,
                points: newPoints,
                level: newLevel.level,
                rank: newLevel.name
            };
        });
    };

    const unlockHint = (roomId, taskIdx, hintCost) => {
        const hintId = `${roomId}-${taskIdx}`;
        if (user.unlockedHints.includes(hintId)) return true;
        if (user.points < hintCost) return false;

        setUser(prev => ({
            ...prev,
            points: prev.points - hintCost,
            unlockedHints: [...prev.unlockedHints, hintId]
        }));
        return true;
    };

    const solveCTFTask = (roomId, task, roomTitle) => {
        const globalTaskId = `${roomId}-${task.id}`;
        if (user.solvedCTFTasks.includes(globalTaskId)) return false;

        setUser(prev => ({
            ...prev,
            solvedCTFTasks: [...prev.solvedCTFTasks, globalTaskId],
            solveHistory: [{ user: prev.name, challenge: roomTitle, time: Date.now() }, ...prev.solveHistory].slice(0, 10)
        }));

        setLiveFeed(prev => [
            { user: user.name, challenge: roomTitle, time: Date.now() },
            ...prev
        ].slice(0, 5));

        addXP(task.points);
        return true;
    };

    const updateProgress = (lessonId) => {
        if (user.completedLessons.includes(lessonId)) return;

        setUser(prev => ({
            ...prev,
            completedLessons: [...prev.completedLessons, lessonId]
        }));
        addXP(50); // standard XP per lesson
    };

    const unlockAchievement = (id, title) => {
        if (user.achievements.some(a => a.id === id)) return;
        setUser(prev => ({
            ...prev,
            achievements: [...prev.achievements, { id, title, date: new Date().toLocaleDateString() }]
        }));
        addXP(100);
    };

    return (
        <AppContext.Provider value={{
            user, setUser,
            language, setLanguage,
            t, toggleLanguage,
            updateProgress, addXP,
            unlockAchievement,
            solveCTFTask,
            unlockHint,
            liveFeed,
            LEVELS,
            apiUrl
        }}>
            {children}
        </AppContext.Provider>
    );
};

export const useAppContext = () => useContext(AppContext);
