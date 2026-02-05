/* ==================== LEADERBOARD FEATURE ==================== */
/* User rankings based on CTF points and progress */
/* This file now serves as a mount point for the React-based Antigravity Leaderboard */

// ============== Leaderboard Data ==============
// In a real app, this would come from a backend API
// For now, we simulate with localStorage + demo users

const DEMO_USERS = [
    { id: 'user-1', name: 'CyberNinja', avatar: '🥷', points: 2450, ctfSolved: 18, streak: 12 },
    { id: 'user-2', name: 'HackerElite', avatar: '💀', points: 2100, ctfSolved: 15, streak: 8 },
    { id: 'user-3', name: 'SecMaster', avatar: '🛡️', points: 1850, ctfSolved: 14, streak: 5 },
    { id: 'user-4', name: 'ByteHunter', avatar: '🎯', points: 1600, ctfSolved: 12, streak: 7 },
    { id: 'user-5', name: 'CodeBreaker', avatar: '🔓', points: 1400, ctfSolved: 10, streak: 3 },
    { id: 'user-6', name: 'NetRunner', avatar: '🌐', points: 1200, ctfSolved: 9, streak: 4 },
    { id: 'user-7', name: 'CryptoKing', avatar: '👑', points: 1050, ctfSolved: 8, streak: 2 },
    { id: 'user-8', name: 'BugSlayer', avatar: '🐛', points: 900, ctfSolved: 7, streak: 1 },
    { id: 'user-9', name: 'RootAccess', avatar: '💻', points: 750, ctfSolved: 6, streak: 0 },
    { id: 'user-10', name: 'ZeroDay', avatar: '⚡', points: 600, ctfSolved: 5, streak: 0 }
];

function getLeaderboardData() {
    // Get current user data from localStorage
    const ctfProgress = typeof getCTFProgress === 'function' ? getCTFProgress() : { points: 0, solved: [] };
    const userName = localStorage.getItem('study_hub_username') || 'You';

    const currentUser = {
        id: 'current-user',
        name: userName,
        avatar: '🧑‍💻',
        points: ctfProgress.points || 0,
        ctfSolved: ctfProgress.solved ? ctfProgress.solved.length : 0,
        streak: parseInt(localStorage.getItem('study_hub_streak') || '0'),
        isCurrentUser: true
    };

    // Combine with demo users and sort
    const allUsers = [...DEMO_USERS, currentUser];
    allUsers.sort((a, b) => b.points - a.points);

    // Add rank
    allUsers.forEach((user, index) => {
        user.rank = index + 1;
    });

    return allUsers;
}

// ============== Leaderboard Page ==============
function pageLeaderboard() {
    return `
    <div id="leaderboard-root" class="min-h-screen bg-[#0a0a0f]" style="min-height: 100vh;">
        <!-- React Antigravity Leaderboard will mount here -->
        <div class="flex items-center justify-center p-20">
            <div class="text-neon-cyan animate-pulse font-cyber tracking-widest">
                INITIALIZING NEURAL LINK...
            </div>
        </div>
    </div>
    `;
}

// ============== Exports ==============
window.pageLeaderboard = pageLeaderboard;
window.getLeaderboardData = getLeaderboardData;
