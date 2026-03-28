import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Play, RotateCcw, Trophy, Zap, Target, Clock } from 'lucide-react';

/**
 * Mini-Games Component
 * Gamified security challenges: CTF, Code Challenges, Exploit Games
 */

const MiniGames = () => {
  const [activeGame, setActiveGame] = useState(null);
  const [gameState, setGameState] = useState('menu'); // menu, playing, results
  const [score, setScore] = useState(0);
  const [timeLeft, setTimeLeft] = useState(0);

  const games = [
    {
      id: 'ctf',
      name: 'Capture The Flag',
      emoji: '🚩',
      description: 'Find vulnerabilities and capture flags',
      difficulty: 'Intermediate',
      xp_reward: 500,
      modes: [
        { name: 'SQL Injection Hunt', duration: 300 },
        { name: 'XSS Challenge', duration: 300 },
        { name: 'CORS Bypass', duration: 300 },
      ],
    },
    {
      id: 'exploit',
      name: 'Exploit Simulator',
      emoji: '💣',
      description: 'Chain exploits to gain system access',
      difficulty: 'Advanced',
      xp_reward: 750,
      modes: [
        { name: 'Buffer Overflow', duration: 600 },
        { name: 'Privilege Escalation', duration: 480 },
        { name: 'RCE Chain', duration: 600 },
      ],
    },
    {
      id: 'code',
      name: 'Code Challenge',
      emoji: '⚙️',
      description: 'Solve security coding problems in real-time',
      difficulty: 'All Levels',
      xp_reward: 300,
      modes: [
        { name: 'Crypto Crash', duration: 180 },
        { name: 'Input Validation', duration: 240 },
        { name: 'Secure Coding', duration: 300 },
      ],
    },
    {
      id: 'defuse',
      name: 'Malware Defuser',
      emoji: '🔴',
      description: 'Disable malware before it spreads',
      difficulty: 'Hard',
      xp_reward: 600,
      modes: [
        { name: 'Ransomware Race', duration: 240 },
        { name: 'Botnet Shutdown', duration: 300 },
        { name: 'Worm Containment', duration: 280 },
      ],
    },
    {
      id: 'network',
      name: 'Network Forensics',
      emoji: '🔍',
      description: 'Analyze traffic and identify threats',
      difficulty: 'Intermediate',
      xp_reward: 450,
      modes: [
        { name: 'Packet Analysis', duration: 300 },
        { name: 'DDoS Detection', duration: 240 },
        { name: 'Man-in-the-Middle', duration: 360 },
      ],
    },
    {
      id: 'cipher',
      name: 'Cipher Breaker',
      emoji: '🔐',
      description: 'Decode encrypted messages against time',
      difficulty: 'Beginner',
      xp_reward: 250,
      modes: [
        { name: 'Caesar Cipher', duration: 120 },
        { name: 'Substitution', duration: 180 },
        { name: 'ROT13 Marathon', duration: 150 },
      ],
    },
  ];

  useEffect(() => {
    if (gameState === 'playing' && timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
      return () => clearTimeout(timer);
    } else if (timeLeft === 0 && gameState === 'playing') {
      setGameState('results');
    }
  }, [timeLeft, gameState]);

  const startGame = (game, mode) => {
    setActiveGame({ game, mode });
    setTimeLeft(mode.duration);
    setScore(0);
    setGameState('playing');
  };

  const endGame = () => {
    setGameState('results');
  };

  const resetGame = () => {
    setGameState('menu');
    setActiveGame(null);
    setScore(0);
    setTimeLeft(0);
  };

  // Game Menu
  if (gameState === 'menu') {
    return (
      <div className="space-y-8 pb-12">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-4"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-purple-500/10 border border-purple-500/20">
            <Zap className="w-4 h-4 text-purple-500" />
            <span className="text-sm font-bold text-purple-500 uppercase tracking-widest">
              Rapid Challenges
            </span>
          </div>
          <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
            Mini-Games
          </h1>
          <p className="text-gray-400 text-lg max-w-2xl">
            Quick gamified security challenges. Master exploits, solve puzzles, and climb the leaderboards.
          </p>
        </motion.div>

        {/* Games Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {games.map((game, idx) => (
            <GameCard key={game.id} game={game} index={idx} onSelect={(game) => setActiveGame(game)} />
          ))}
        </div>

        {/* Leaderboard Teaser */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="p-6 rounded-xl bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30"
        >
          <div className="flex items-center gap-4 mb-4">
            <Trophy className="w-6 h-6 text-purple-500" />
            <h3 className="text-xl font-bold text-white">Mini-Game Leaderboards</h3>
          </div>
          <p className="text-gray-300 mb-4">
            Compete on daily/weekly leaderboards for each game mode. Top performers earn exclusive badges and bonus XP.
          </p>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center">
              <p className="text-sm text-gray-400 mb-1">Daily Winner</p>
              <p className="text-lg font-bold text-purple-400">+100 XP</p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-400 mb-1">Weekly Top 10</p>
              <p className="text-lg font-bold text-pink-400">+500 XP</p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-400 mb-1">Perfect Run</p>
              <p className="text-lg font-bold text-yellow-400">Badge</p>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  // Game Playing
  if (gameState === 'playing' && activeGame) {
    return <GamePlayScreen game={activeGame.game} mode={activeGame.mode} timeLeft={timeLeft} score={score} setScore={setScore} onEnd={endGame} />;
  }

  // Game Results
  if (gameState === 'results' && activeGame) {
    return (
      <GameResultsScreen
        game={activeGame.game}
        mode={activeGame.mode}
        finalScore={score}
        onPlayAgain={() => startGame(activeGame.game, activeGame.mode)}
        onBackToMenu={resetGame}
      />
    );
  }
};

const GameCard = ({ game, index, onSelect }) => {
  const [hoveredModes, setHoveredModes] = React.useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
      onMouseEnter={() => setHoveredModes(true)}
      onMouseLeave={() => setHoveredModes(false)}
      className="group relative p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 hover:border-purple-500/50 transition-all cursor-pointer"
    >
      {/* Difficulty Badge */}
      <div className="absolute top-4 right-4 px-3 py-1 rounded-full bg-purple-500/20 border border-purple-500/30">
        <span className="text-xs font-bold text-purple-400">{game.difficulty}</span>
      </div>

      {/* Icon */}
      <div className="text-5xl mb-4">{game.emoji}</div>

      {/* Title & Description */}
      <h3 className="text-lg font-bold text-white mb-2">{game.name}</h3>
      <p className="text-sm text-gray-400 mb-4">{game.description}</p>

      {/* Reward */}
      <div className="mb-4 p-3 rounded-lg bg-gray-900/50 border border-purple-500/20">
        <p className="text-xs text-gray-400 mb-1">Max XP Reward</p>
        <p className="text-xl font-bold text-purple-400">⭐ {game.xp_reward}</p>
      </div>

      {/* Modes List (Hover) */}
      {hoveredModes && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="absolute inset-0 p-6 rounded-xl bg-gray-900/95 border border-purple-500/50 backdrop-blur-sm flex flex-col"
        >
          <p className="text-sm font-bold text-purple-400 mb-3">Select Mode:</p>
          <div className="space-y-2 flex-1">
            {game.modes.map((mode, idx) => (
              <button
                key={idx}
                onClick={() => onSelect({ game, mode })}
                className="w-full p-2 rounded-lg bg-purple-500/20 hover:bg-purple-500/40 border border-purple-500/30 text-white text-sm font-bold transition-all text-left"
              >
                {mode.name}
                <span className="float-right text-xs text-purple-300">
                  {mode.duration}s
                </span>
              </button>
            ))}
          </div>
        </motion.div>
      )}

      {/* Play Button */}
      <button
        onClick={() => setHoveredModes(!hoveredModes)}
        className="w-full px-4 py-2 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white font-bold rounded-lg transition-all flex items-center justify-center gap-2"
      >
        <Play className="w-4 h-4" />
        Select Mode
      </button>
    </motion.div>
  );
};

const GamePlayScreen = ({ game, mode, timeLeft, score, setScore, onEnd }) => {
  const [challenges, setChallenges] = React.useState(generateChallenges(5));
  const [currentIdx, setCurrentIdx] = React.useState(0);

  const current = challenges[currentIdx];

  const handleAnswer = (correct) => {
    if (correct) {
      setScore(score + 100);
      if (currentIdx < challenges.length - 1) {
        setCurrentIdx(currentIdx + 1);
      } else {
        onEnd();
      }
    }
  };

  return (
    <div className="fixed inset-0 bg-gradient-to-b from-gray-900 via-gray-900 to-black z-50 flex flex-col p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex-1">
          <p className="text-sm text-gray-400 mb-1">{game.name} - {mode.name}</p>
          <p className="text-2xl font-bold text-white">Score: {score}</p>
        </div>
        <div className="text-right">
          <div className="flex items-center gap-2 justify-end mb-2">
            <Clock className="w-5 h-5 text-red-500" />
            <span className="text-2xl font-bold text-red-500">{timeLeft}s</span>
          </div>
          <p className="text-sm text-gray-400">Challenge {currentIdx + 1}/{challenges.length}</p>
        </div>
      </div>

      {/* Challenge Display */}
      <motion.div
        key={currentIdx}
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="flex-1 flex flex-col items-center justify-center space-y-6"
      >
        <div className="text-6xl">{game.emoji}</div>
        <h2 className="text-3xl font-bold text-white text-center max-w-2xl">
          {current.question}
        </h2>

        {/* Answers */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 w-full max-w-2xl">
          {current.answers.map((answer, idx) => (
            <button
              key={idx}
              onClick={() => handleAnswer(answer.correct)}
              className="p-6 rounded-xl bg-gradient-to-r from-gray-800 to-gray-900 hover:from-purple-600 hover:to-pink-600 border border-gray-700 hover:border-purple-500 text-white font-bold text-lg transition-all hover:scale-105"
            >
              {answer.text}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Progress Bar */}
      <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden mb-6">
        <motion.div
          initial={{ width: '0%' }}
          animate={{ width: `${((currentIdx + 1) / challenges.length) * 100}%` }}
          className="h-full bg-gradient-to-r from-purple-500 to-pink-500"
        />
      </div>
    </div>
  );
};

const GameResultsScreen = ({ game, mode, finalScore, onPlayAgain, onBackToMenu }) => {
  const xpEarned = Math.floor((finalScore / 500) * game.xp_reward);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="space-y-8 pb-12"
    >
      {/* Results Card */}
      <div className="p-8 rounded-2xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border-2 border-purple-500/50 text-center">
        <div className="text-6xl mb-6">🎊</div>
        <h1 className="text-4xl font-black text-white mb-4">Game Complete!</h1>

        {/* Score */}
        <div className="mb-8">
          <p className="text-gray-300 mb-2">Final Score</p>
          <p className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">
            {finalScore}
          </p>
        </div>

        {/* XP Earned */}
        <div className="p-6 rounded-xl bg-gray-900/50 border border-purple-500/30 mb-8">
          <p className="text-sm text-gray-400 mb-2">Experience Points Earned</p>
          <p className="text-3xl font-bold text-purple-400">
            +{xpEarned} XP
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="p-4 rounded-lg bg-gray-800/50">
            <p className="text-xs text-gray-400">Game</p>
            <p className="text-sm font-bold text-white mt-1">{game.name}</p>
          </div>
          <div className="p-4 rounded-lg bg-gray-800/50">
            <p className="text-xs text-gray-400">Mode</p>
            <p className="text-sm font-bold text-white mt-1">{mode.name}</p>
          </div>
          <div className="p-4 rounded-lg bg-gray-800/50">
            <p className="text-xs text-gray-400">Difficulty</p>
            <p className="text-sm font-bold text-white mt-1">{game.difficulty}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-4 flex-col md:flex-row">
          <button
            onClick={onPlayAgain}
            className="flex-1 px-6 py-3 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 text-white font-bold rounded-lg transition-all flex items-center justify-center gap-2"
          >
            <RotateCcw className="w-5 h-5" />
            Play Again
          </button>
          <button
            onClick={onBackToMenu}
            className="flex-1 px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-bold rounded-lg transition-all"
          >
            Back to Menu
          </button>
        </div>
      </div>
    </motion.div>
  );
};

function generateChallenges(count) {
  const questionTypes = [
    {
      question: 'Which HTTP method is vulnerable to cache poisoning?',
      answers: [
        { text: 'GET', correct: false },
        { text: 'POST', correct: true },
        { text: 'DELETE', correct: false },
        { text: 'PUT', correct: false },
      ],
    },
    {
      question: 'What does CSRF protect against?',
      answers: [
        { text: 'Cross-Site Request Forgery', correct: true },
        { text: 'Content Security Framework', correct: false },
        { text: 'Cross-Source Resource Format', correct: false },
        { text: 'Cryptographic Secure Random', correct: false },
      ],
    },
    {
      question: 'Which hash function is considered broken?',
      answers: [
        { text: 'SHA-256', correct: false },
        { text: 'MD5', correct: true },
        { text: 'SHA-3', correct: false },
        { text: 'BLAKE2', correct: false },
      ],
    },
    {
      question: 'What is the default SSH port?',
      answers: [
        { text: '80', correct: false },
        { text: '443', correct: false },
        { text: '22', correct: true },
        { text: '3306', correct: false },
      ],
    },
    {
      question: 'Which encryption is symmetric?',
      answers: [
        { text: 'RSA', correct: false },
        { text: 'AES', correct: true },
        { text: 'ECDSA', correct: false },
        { text: 'Diffie-Hellman', correct: false },
      ],
    },
  ];

  return questionTypes.slice(0, count);
}

export default MiniGames;
