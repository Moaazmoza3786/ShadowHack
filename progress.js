// ==================== PROGRESS TRACKING SYSTEM ====================
// نظام تتبع تقدم المستخدم

// Global helper to check if user is logged in
function isUserLoggedInGlobal() {
    // Check AuthState first
    if (typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn()) {
        return true;
    }
    // Check EnrollmentSystem
    if (typeof EnrollmentSystem !== 'undefined' && EnrollmentSystem.checkUserLoggedIn) {
        return EnrollmentSystem.checkUserLoggedIn();
    }
    // Fallback to localStorage/sessionStorage
    if (localStorage.getItem('isLoggedIn') === 'true' ||
        sessionStorage.getItem('isLoggedIn') === 'true') {
        return true;
    }
    // Check for user object
    try {
        const user = JSON.parse(sessionStorage.getItem('user') || localStorage.getItem('user') || '{}');
        if (user && (user.id || user.email || user.username)) {
            return true;
        }
    } catch (e) { }
    return false;
}

// Export globally
window.isUserLoggedInGlobal = isUserLoggedInGlobal;

// Initialize progress data structure
function initializeProgress() {
    if (!localStorage.getItem('studyhub_progress')) {
        const initialProgress = {
            user: {
                totalPoints: 0,
                level: 1,
                streak: 0,
                lastActive: Date.now(),
                joinDate: Date.now()
            },
            courses: {},
            modules: {},
            lessons: {},
            challenges: {},
            achievements: [],
            stats: {
                completedCourses: 0,
                completedModules: 0,
                completedLessons: 0,
                completedChallenges: 0,
                totalTimeSpent: 0
            }
        };
        localStorage.setItem('studyhub_progress', JSON.stringify(initialProgress));
    }
}

// Get all progress data (returns empty if not logged in)
function getProgress() {
    // If not logged in, return empty progress
    if (!isUserLoggedInGlobal()) {
        return {
            user: {
                totalPoints: 0,
                level: 1,
                streak: 0,
                lastActive: null,
                joinDate: null
            },
            courses: {},
            modules: {},
            lessons: {},
            challenges: {},
            achievements: [],
            stats: {
                completedCourses: 0,
                completedModules: 0,
                completedLessons: 0,
                completedChallenges: 0,
                totalTimeSpent: 0
            }
        };
    }
    initializeProgress();
    return JSON.parse(localStorage.getItem('studyhub_progress'));
}

// Save progress data
function saveProgress(progressData) {
    localStorage.setItem('studyhub_progress', JSON.stringify(progressData));
}

// Mark lesson as complete
function completeLesson(courseId, moduleId, lessonId) {
    // Must be logged in to save lesson progress
    if (!isUserLoggedInGlobal()) {
        if (typeof showToast === 'function') {
            showToast('Please log in to save your progress', 'warning');
        }
        return false;
    }

    const progress = getProgress();
    const key = `${courseId}-${moduleId}-${lessonId}`;

    if (!progress.lessons[key]) {
        progress.lessons[key] = {
            completed: true,
            completedAt: Date.now(),
            timeSpent: 0
        };

        // Add points
        progress.user.totalPoints += 50;
        progress.stats.completedLessons++;

        // Check if module is complete
        checkModuleCompletion(courseId, moduleId, progress);

        saveProgress(progress);
        updateStreak(progress);

        return true;
    }
    return false;
}

// Check if module is complete
function checkModuleCompletion(courseId, moduleId, progress) {
    const course = courses.find(c => c.id === courseId);
    if (!course) return;

    const module = course.modules.find(m => m.id === moduleId);
    if (!module) return;

    const allLessonsComplete = module.lessons.every(lesson => {
        const key = `${courseId}-${moduleId}-${lesson.id}`;
        return progress.lessons[key]?.completed;
    });

    if (allLessonsComplete) {
        const moduleKey = `${courseId}-${moduleId}`;
        if (!progress.modules[moduleKey]) {
            progress.modules[moduleKey] = {
                completed: true,
                completedAt: Date.now(),
                quizScore: null
            };
            progress.user.totalPoints += 100;
            progress.stats.completedModules++;

            // Check if course is complete
            checkCourseCompletion(courseId, progress);
        }
    }
}

// Check if course is complete
function checkCourseCompletion(courseId, progress) {
    const course = courses.find(c => c.id === courseId);
    if (!course) return;

    const allModulesComplete = course.modules.every(module => {
        const key = `${courseId}-${module.id}`;
        return progress.modules[key]?.completed;
    });

    if (allModulesComplete && !progress.courses[courseId]) {
        progress.courses[courseId] = {
            completed: true,
            completedAt: Date.now(),
            certificateIssued: course.certificate
        };
        progress.user.totalPoints += 500;
        progress.stats.completedCourses++;

        // Award achievement
        addAchievement('course_complete', `أكملت كورس ${course.titleAr}`, progress);
    }
}

// Save quiz score
function saveQuizScore(courseId, moduleId, score, totalQuestions) {
    const progress = getProgress();
    const moduleKey = `${courseId}-${moduleId}`;

    if (progress.modules[moduleKey]) {
        progress.modules[moduleKey].quizScore = {
            score: score,
            total: totalQuestions,
            percentage: (score / totalQuestions) * 100,
            passed: (score / totalQuestions) >= 0.7,
            completedAt: Date.now()
        };

        if ((score / totalQuestions) >= 0.7) {
            progress.user.totalPoints += 75;
        }

        saveProgress(progress);
    }
}

// Calculate course progress percentage
function getCourseProgress(courseId) {
    // If not logged in, always return 0
    if (!isUserLoggedInGlobal()) return 0;

    const progress = getProgress();
    const course = courses.find(c => c.id === courseId);

    if (!course) return 0;

    let totalLessons = 0;
    let completedLessons = 0;

    course.modules.forEach(module => {
        totalLessons += module.lessons.length;
        module.lessons.forEach(lesson => {
            const key = `${courseId}-${module.id}-${lesson.id}`;
            if (progress.lessons[key]?.completed) {
                completedLessons++;
            }
        });
    });

    return totalLessons > 0 ? Math.round((completedLessons / totalLessons) * 100) : 0;
}

// Get module progress
function getModuleProgress(courseId, moduleId) {
    // If not logged in, always return 0
    if (!isUserLoggedInGlobal()) return 0;

    const progress = getProgress();
    const course = courses.find(c => c.id === courseId);

    if (!course) return 0;

    const module = course.modules.find(m => m.id === moduleId);
    if (!module) return 0;

    const completedLessons = module.lessons.filter(lesson => {
        const key = `${courseId}-${moduleId}-${lesson.id}`;
        return progress.lessons[key]?.completed;
    }).length;

    return Math.round((completedLessons / module.lessons.length) * 100);
}

// Check if lesson is completed
function isLessonCompleted(courseId, moduleId, lessonId) {
    // If not logged in, always return false
    if (!isUserLoggedInGlobal()) return false;

    const progress = getProgress();
    const key = `${courseId}-${moduleId}-${lessonId}`;
    return progress.lessons[key]?.completed || false;
}

// Update streak
function updateStreak(progress) {
    const now = Date.now();
    const lastActive = progress.user.lastActive;
    const dayInMs = 24 * 60 * 60 * 1000;

    if (now - lastActive < dayInMs) {
        // Same day, no change
        return;
    } else if (now - lastActive < 2 * dayInMs) {
        // Next day, increment streak
        progress.user.streak++;
        if (progress.user.streak >= 7) {
            addAchievement('streak_7', 'حافظت على streak لمدة 7 أيام!', progress);
        }
    } else {
        // Streak broken
        progress.user.streak = 1;
    }

    progress.user.lastActive = now;
    saveProgress(progress);
}

// Add achievement
function addAchievement(id, title, progress) {
    if (!progress.achievements.find(a => a.id === id)) {
        progress.achievements.push({
            id: id,
            title: title,
            unlockedAt: Date.now()
        });
        progress.user.totalPoints += 100;
    }
}

// Get user stats
function getUserStats() {
    // If not logged in, return empty stats
    if (!isUserLoggedInGlobal()) {
        return {
            totalPoints: 0,
            level: 1,
            streak: 0,
            completedCourses: 0,
            completedModules: 0,
            completedLessons: 0,
            completedChallenges: 0,
            achievements: 0,
            joinDate: null
        };
    }

    const progress = getProgress();
    return {
        totalPoints: progress.user.totalPoints,
        level: calculateLevel(progress.user.totalPoints),
        streak: progress.user.streak,
        completedCourses: progress.stats.completedCourses,
        completedModules: progress.stats.completedModules,
        completedLessons: progress.stats.completedLessons,
        completedChallenges: progress.stats.completedChallenges,
        achievements: progress.achievements.length,
        joinDate: progress.user.joinDate
    };
}

// Calculate level from points
function calculateLevel(points) {
    if (points < 500) return 1;
    if (points < 2000) return 2;
    if (points < 5000) return 3;
    if (points < 10000) return 4;
    return 5;
}

// Get level name
function getLevelName(level) {
    const levels = {
        1: { ar: 'مبتدئ', en: 'Newbie' },
        2: { ar: 'متعلم', en: 'Learner' },
        3: { ar: 'ممارس', en: 'Practitioner' },
        4: { ar: 'خبير', en: 'Expert' },
        5: { ar: 'محترف', en: 'Master' }
    };
    return levels[level] || levels[1];
}

// Get next level info
function getNextLevelInfo(points) {
    const thresholds = [0, 500, 2000, 5000, 10000];
    const currentLevel = calculateLevel(points);

    if (currentLevel >= 5) {
        return {
            nextLevel: 5,
            pointsNeeded: 0,
            progress: 100
        };
    }

    const nextThreshold = thresholds[currentLevel];
    const currentThreshold = thresholds[currentLevel - 1];

    return {
        nextLevel: currentLevel + 1,
        pointsNeeded: nextThreshold - points,
        progress: Math.round(((points - currentThreshold) / (nextThreshold - currentThreshold)) * 100)
    };
}

// Complete challenge
function completeChallenge(challengeId, points) {
    // Must be logged in to save challenge progress
    if (!isUserLoggedInGlobal()) {
        if (typeof showToast === 'function') {
            showToast('Please log in to save your progress', 'warning');
        }
        return false;
    }

    const progress = getProgress();

    if (!progress.challenges[challengeId]) {
        progress.challenges[challengeId] = {
            completed: true,
            completedAt: Date.now(),
            points: points
        };

        progress.user.totalPoints += points;
        progress.stats.completedChallenges++;

        saveProgress(progress);
        updateStreak(progress);

        return true;
    }
    return false;
}

// Get recent activity
function getRecentActivity(limit = 10) {
    const progress = getProgress();
    const activities = [];

    // Collect all completed items
    Object.entries(progress.lessons).forEach(([key, data]) => {
        activities.push({
            type: 'lesson',
            key: key,
            timestamp: data.completedAt
        });
    });

    Object.entries(progress.modules).forEach(([key, data]) => {
        activities.push({
            type: 'module',
            key: key,
            timestamp: data.completedAt
        });
    });

    Object.entries(progress.courses).forEach(([key, data]) => {
        activities.push({
            type: 'course',
            key: key,
            timestamp: data.completedAt
        });
    });

    // Sort by timestamp and limit
    return activities
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, limit);
}

// Reset progress (for testing)
function resetProgress() {
    if (confirm('هل أنت متأكد من إعادة تعيين كل التقدم؟')) {
        localStorage.removeItem('studyhub_progress');
        initializeProgress();
        location.reload();
    }
}

// Initialize on load
initializeProgress();

// ==================== ENHANCED PROGRESS TRACKING ====================

// Track Path progress
function trackPathProgress(pathId, action = 'view') {
    if (!isUserLoggedInGlobal()) return;

    const progress = getProgress();
    if (!progress.paths) progress.paths = {};

    if (!progress.paths[pathId]) {
        progress.paths[pathId] = {
            enrolled: false,
            startedAt: null,
            completedAt: null,
            unitsCompleted: 0,
            lastActivity: Date.now()
        };
    }

    if (action === 'enroll') {
        progress.paths[pathId].enrolled = true;
        progress.paths[pathId].startedAt = Date.now();
        progress.user.totalPoints += 10;
    } else if (action === 'complete_unit') {
        progress.paths[pathId].unitsCompleted++;
        progress.paths[pathId].lastActivity = Date.now();
        progress.user.totalPoints += 100;
    } else if (action === 'complete') {
        progress.paths[pathId].completedAt = Date.now();
        progress.user.totalPoints += 500;
        progress.stats.completedPaths = (progress.stats.completedPaths || 0) + 1;
    }

    saveProgress(progress);
    return progress.paths[pathId];
}

// Get Path progress percentage
function getPathProgressPercent(pathId, totalUnits) {
    if (!isUserLoggedInGlobal()) return 0;

    const progress = getProgress();
    if (!progress.paths || !progress.paths[pathId]) return 0;

    const pathData = progress.paths[pathId];
    return Math.round((pathData.unitsCompleted / totalUnits) * 100);
}

// Track CTF/Challenge progress
function trackCTFProgress(ctfId, action = 'start', flagValue = null) {
    if (!isUserLoggedInGlobal()) return;

    const progress = getProgress();
    if (!progress.ctfs) progress.ctfs = {};

    if (!progress.ctfs[ctfId]) {
        progress.ctfs[ctfId] = {
            startedAt: null,
            completedAt: null,
            flagsCaptured: [],
            attempts: 0,
            points: 0
        };
    }

    if (action === 'start') {
        progress.ctfs[ctfId].startedAt = Date.now();
    } else if (action === 'flag') {
        if (flagValue && !progress.ctfs[ctfId].flagsCaptured.includes(flagValue)) {
            progress.ctfs[ctfId].flagsCaptured.push(flagValue);
            progress.ctfs[ctfId].points += 50;
            progress.user.totalPoints += 50;
        }
    } else if (action === 'attempt') {
        progress.ctfs[ctfId].attempts++;
    } else if (action === 'complete') {
        progress.ctfs[ctfId].completedAt = Date.now();
        progress.user.totalPoints += 200;
        progress.stats.completedChallenges++;
    }

    saveProgress(progress);
    return progress.ctfs[ctfId];
}

// Track Badge earned
function earnBadge(badgeId, badgeName, badgeDescription) {
    if (!isUserLoggedInGlobal()) return false;

    const progress = getProgress();
    if (!progress.badges) progress.badges = [];

    if (!progress.badges.find(b => b.id === badgeId)) {
        progress.badges.push({
            id: badgeId,
            name: badgeName,
            description: badgeDescription,
            earnedAt: Date.now()
        });
        progress.user.totalPoints += 100;
        saveProgress(progress);

        // Show notification
        showBadgeNotification(badgeName);
        return true;
    }
    return false;
}

// Show badge notification
function showBadgeNotification(badgeName) {
    const notification = document.createElement('div');
    notification.innerHTML = `
        <style>
            .badge-notification {
                position: fixed;
                top: 100px;
                right: 30px;
                background: linear-gradient(135deg, #22c55e, #16a34a);
                color: #fff;
                padding: 20px 30px;
                border-radius: 16px;
                z-index: 99999;
                animation: badgeSlideIn 0.5s ease, badgeSlideOut 0.5s ease 3.5s;
                display: flex;
                align-items: center;
                gap: 15px;
                box-shadow: 0 10px 40px rgba(34, 197, 94, 0.4);
            }
            
            @keyframes badgeSlideIn {
                from { transform: translateX(150%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            
            @keyframes badgeSlideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(150%); opacity: 0; }
            }
            
            .badge-notification i {
                font-size: 32px;
            }
            
            .badge-notification-text h4 {
                margin: 0 0 5px 0;
                font-size: 14px;
                opacity: 0.9;
            }
            
            .badge-notification-text p {
                margin: 0;
                font-size: 18px;
                font-weight: 700;
            }
        </style>
        <i class="fas fa-medal"></i>
        <div class="badge-notification-text">
            <h4>🎉 Badge Earned!</h4>
            <p>${badgeName}</p>
        </div>
    `;
    notification.className = 'badge-notification';
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 4000);
}

// Unlock Certificate
function unlockCertificate(certId, certName, pathId) {
    if (!isUserLoggedInGlobal()) return false;

    const progress = getProgress();
    if (!progress.certificates) progress.certificates = [];

    if (!progress.certificates.find(c => c.id === certId)) {
        progress.certificates.push({
            id: certId,
            name: certName,
            pathId: pathId,
            unlockedAt: Date.now(),
            verified: true
        });
        progress.user.totalPoints += 250;
        saveProgress(progress);
        return true;
    }
    return false;
}

// Get all earned badges
function getEarnedBadges() {
    if (!isUserLoggedInGlobal()) return [];
    const progress = getProgress();
    return progress.badges || [];
}

// Get all certificates
function getCertificates() {
    if (!isUserLoggedInGlobal()) return [];
    const progress = getProgress();
    return progress.certificates || [];
}

// Get comprehensive user stats
function getComprehensiveStats() {
    if (!isUserLoggedInGlobal()) {
        return {
            xp: 0,
            level: 1,
            rank: 'Noob',
            streak: 0,
            paths: { enrolled: 0, completed: 0 },
            modules: { started: 0, completed: 0 },
            ctfs: { attempted: 0, completed: 0, flags: 0 },
            badges: 0,
            certificates: 0,
            hoursLearned: 0
        };
    }

    const progress = getProgress();
    const pathsData = progress.paths || {};
    const ctfsData = progress.ctfs || {};

    const enrolledPaths = Object.values(pathsData).filter(p => p.enrolled).length;
    const completedPaths = Object.values(pathsData).filter(p => p.completedAt).length;
    const attemptedCTFs = Object.keys(ctfsData).length;
    const completedCTFs = Object.values(ctfsData).filter(c => c.completedAt).length;
    const totalFlags = Object.values(ctfsData).reduce((sum, c) => sum + (c.flagsCaptured?.length || 0), 0);

    // Calculate rank based on XP
    const xp = progress.user.totalPoints || 0;
    let rank = 'Noob';
    if (xp >= 100000) rank = 'God Mode';
    else if (xp >= 75000) rank = 'Legend';
    else if (xp >= 50000) rank = 'Master';
    else if (xp >= 35000) rank = 'Omniscient';
    else if (xp >= 20000) rank = 'Guru';
    else if (xp >= 10000) rank = 'Elite Hacker';
    else if (xp >= 5000) rank = 'Pro Hacker';
    else if (xp >= 2000) rank = 'Hacker';
    else if (xp >= 500) rank = 'Script Kiddie';

    return {
        xp: xp,
        level: calculateLevel(xp),
        rank: rank,
        streak: progress.user.streak || 0,
        paths: { enrolled: enrolledPaths, completed: completedPaths },
        modules: { started: progress.stats.completedModules || 0, completed: progress.stats.completedModules || 0 },
        ctfs: { attempted: attemptedCTFs, completed: completedCTFs, flags: totalFlags },
        badges: (progress.badges || []).length,
        certificates: (progress.certificates || []).length,
        hoursLearned: Math.round((progress.stats.totalTimeSpent || 0) / 3600)
    };
}

// Export all functions globally
window.trackPathProgress = trackPathProgress;
window.getPathProgressPercent = getPathProgressPercent;
window.trackCTFProgress = trackCTFProgress;
window.earnBadge = earnBadge;
window.unlockCertificate = unlockCertificate;
window.getEarnedBadges = getEarnedBadges;
window.getCertificates = getCertificates;
window.getComprehensiveStats = getComprehensiveStats;

