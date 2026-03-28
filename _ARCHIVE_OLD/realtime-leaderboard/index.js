const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Paths
const DB_PATH = path.join(__dirname, '..', 'backend', 'studyhub.db');
const db = new Database(DB_PATH, { verbose: console.log });

// Cache for leaderboard data
let lastLeaderboard = [];

/**
 * Fetch top 50 users sorted by XP
 */
function getLeaderboardData() {
    const query = `
        SELECT id, username, xp_points, avatar_url, current_rank, streak_days
        FROM users
        ORDER BY xp_points DESC
        LIMIT 50
    `;
    const users = db.prepare(query).all();

    // Add rank and solve count (mocked for now, or queried)
    return users.map((user, index) => {
        // Query solve count
        const solveQuery = `SELECT COUNT(*) as solved FROM lab_submissions WHERE user_id = ? AND is_correct = 1`;
        const solveCount = db.prepare(solveQuery).get(user.id);

        return {
            ...user,
            rank: index + 1,
            solvedCount: solveCount ? solveCount.solved : 0
        };
    });
}

/**
 * Fetch score progression for top 5 users
 */
function getScoreProgression() {
    const top5Query = `SELECT id, username FROM users ORDER BY xp_points DESC LIMIT 5`;
    const top5 = db.prepare(top5Query).all();

    const progression = top5.map(user => {
        const historyQuery = `
            SELECT attempt_time, xp_awarded 
            FROM lab_submissions 
            WHERE user_id = ? AND is_correct = 1
            ORDER BY attempt_time ASC
        `;
        const history = db.prepare(historyQuery).all(user.id);

        let cumulativeXP = 0;
        const data = history.map(h => {
            cumulativeXP += h.xp_awarded;
            return {
                time: h.attempt_time,
                score: cumulativeXP
            };
        });

        return {
            username: user.username,
            data: data
        };
    });

    return progression;
}

/**
 * Broadcast update to all clients
 */
function broadcastUpdate() {
    console.log('Broadcasting leaderboard update...');
    const leaderboard = getLeaderboardData();
    const progression = getScoreProgression();

    io.emit('leaderboard_update', {
        leaderboard,
        progression,
        timestamp: new Date().toISOString()
    });
}

// Socket.io connection
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Send initial data
    socket.emit('leaderboard_update', {
        leaderboard: getLeaderboardData(),
        progression: getScoreProgression(),
        timestamp: new Date().toISOString()
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Internal endpoint for Flask to trigger updates
app.post('/api/trigger-update', (req, res) => {
    const { lab_id, user_id, username, lab_title } = req.body;

    // Check for First Blood
    const solveCountQuery = `SELECT COUNT(*) as solves FROM lab_submissions WHERE lab_id = ? AND is_correct = 1`;
    const solveCountResult = db.prepare(solveCountQuery).get(lab_id);

    if (solveCountResult && solveCountResult.solves === 1) {
        console.log(`FIRST BLOOD detected: ${username} on ${lab_title}`);
        io.emit('notification', {
            type: 'first_blood',
            message: `🩸 FIRST BLOOD: ${username} just pwned ${lab_title}!`,
            user: username,
            lab: lab_title,
            timestamp: new Date().toISOString()
        });
    }

    broadcastUpdate();
    res.json({ success: true });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`Real-time Leaderboard Server running on port ${PORT}`);
});
