"""
Mini-Games & Gamified Challenges API Routes
Handles game scoring, leaderboards, achievements
"""

from flask import Blueprint, jsonify, request
from functools import wraps
import jwt
import os
from datetime import datetime, timedelta

from models import db, User

games_bp = Blueprint('games', __name__, url_prefix='/api/games')


def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            secret_key = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
            data = jwt.decode(token, secret_key, algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


# ==================== GAME DEFINITIONS ====================

GAMES_CONFIG = {
    'ctf': {
        'name': 'Capture The Flag',
        'xp_reward': 500,
        'difficulty': 'intermediate',
        'modes': ['SQL Injection Hunt', 'XSS Challenge', 'CORS Bypass'],
    },
    'exploit': {
        'name': 'Exploit Simulator',
        'xp_reward': 750,
        'difficulty': 'advanced',
        'modes': ['Buffer Overflow', 'Privilege Escalation', 'RCE Chain'],
    },
    'code': {
        'name': 'Code Challenge',
        'xp_reward': 300,
        'difficulty': 'all_levels',
        'modes': ['Crypto Crash', 'Input Validation', 'Secure Coding'],
    },
    'defuse': {
        'name': 'Malware Defuser',
        'xp_reward': 600,
        'difficulty': 'hard',
        'modes': ['Ransomware Race', 'Botnet Shutdown', 'Worm Containment'],
    },
    'network': {
        'name': 'Network Forensics',
        'xp_reward': 450,
        'difficulty': 'intermediate',
        'modes': ['Packet Analysis', 'DDoS Detection', 'Man-in-the-Middle'],
    },
    'cipher': {
        'name': 'Cipher Breaker',
        'xp_reward': 250,
        'difficulty': 'beginner',
        'modes': ['Caesar Cipher', 'Substitution', 'ROT13 Marathon'],
    },
}


# ==================== GAME ENDPOINTS ====================

@games_bp.route('/available', methods=['GET'])
def get_available_games():
    """Get all available mini-games"""
    games = []
    for game_id, config in GAMES_CONFIG.items():
        games.append({
            'id': game_id,
            'name': config['name'],
            'xp_reward': config['xp_reward'],
            'difficulty': config['difficulty'],
            'modes': config['modes'],
        })
    
    return jsonify({
        'success': True,
        'games': games,
        'total': len(games)
    })


@games_bp.route('/play/<game_id>/<mode>', methods=['POST'])
@token_required
def submit_game_score(current_user, game_id, mode):
    """Submit game score"""
    data = request.get_json()
    score = data.get('score', 0)
    time_taken = data.get('time_taken', 0)
    
    if game_id not in GAMES_CONFIG:
        return jsonify({'error': 'Game not found'}), 404
    
    game_config = GAMES_CONFIG[game_id]
    
    # Calculate XP earned (scale by score percentage: 0-100%)
    xp_percentage = min(100, (score / 500) * 100)
    xp_earned = int((xp_percentage / 100) * game_config['xp_reward'])
    
    # Update user stats
    current_user.xp_points += xp_earned
    
    # Increment level every 1000 XP
    current_user.level = (current_user.xp_points // 1000) + 1
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Game completed! +{xp_earned} XP',
        'xp_earned': xp_earned,
        'score': score,
        'time_taken': time_taken,
        'total_xp': current_user.xp_points,
        'level': current_user.level
    })


# ==================== LEADERBOARDS ====================

@games_bp.route('/leaderboards/<game_id>/<period>', methods=['GET'])
def get_game_leaderboard(game_id, period='weekly'):
    """Get leaderboard for a specific game"""
    limit = request.args.get('limit', 50, type=int)
    
    if game_id not in GAMES_CONFIG:
        return jsonify({'error': 'Game not found'}), 404
    
    # Mock leaderboard data
    leaderboard = []
    base_users = [
        {'username': 'CyberNinja', 'xp': 5420},
        {'username': 'HackerElite', 'xp': 4980},
        {'username': 'SecurityPro', 'xp': 4750},
        {'username': 'EthicalGhost', 'xp': 4320},
        {'username': 'ShadowWalker', 'xp': 4150},
    ]
    
    for idx, user in enumerate(base_users):
        leaderboard.append({
            'rank': idx + 1,
            'username': user['username'],
            'xp': user['xp'],
            'avatar_url': f"https://api.dicebear.com/7.x/avataaars/svg?seed={user['username']}",
            'badges': ['⭐'] * ((5 - idx) // 2),
        })
    
    return jsonify({
        'success': True,
        'game': game_id,
        'period': period,
        'leaderboard': leaderboard[:limit],
        'total_players': len(leaderboard)
    })


@games_bp.route('/leaderboards/<game_id>/<period>/my-rank', methods=['GET'])
@token_required
def get_user_game_rank(current_user, game_id, period='weekly'):
    """Get user's rank in a specific game"""
    if game_id not in GAMES_CONFIG:
        return jsonify({'error': 'Game not found'}), 404
    
    # Mock rank data
    return jsonify({
        'success': True,
        'game': game_id,
        'period': period,
        'rank': 142,
        'xp': current_user.xp_points,
        'percentile': 85,
    })


# ==================== ACHIEVEMENTS ====================

@games_bp.route('/achievements', methods=['GET'])
@token_required
def get_user_achievements(current_user):
    """Get user's achievements"""
    achievements = [
        {
            'id': 'first_game',
            'name': 'Game Starter',
            'description': 'Complete your first mini-game',
            'icon': '🎮',
            'unlocked': True,
            'unlocked_at': '2024-01-15',
        },
        {
            'id': 'speed_runner',
            'name': 'Speed Runner',
            'description': 'Complete a game in under 30 seconds',
            'icon': '⚡',
            'unlocked': False,
            'unlocked_at': None,
        },
        {
            'id': 'perfect_score',
            'name': 'Perfect Score',
            'description': 'Get 100% on a challenge',
            'icon': '💯',
            'unlocked': True,
            'unlocked_at': '2024-01-20',
        },
        {
            'id': 'streak_warrior',
            'name': 'Streak Warrior',
            'description': 'Play games for 7 consecutive days',
            'icon': '🔥',
            'unlocked': False,
            'unlocked_at': None,
        },
        {
            'id': 'game_master',
            'name': 'Game Master',
            'description': 'Top 10 in 3 different games',
            'icon': '👑',
            'unlocked': False,
            'unlocked_at': None,
        },
        {
            'id': 'challenge_champion',
            'name': 'Challenge Champion',
            'description': 'Win weekly leaderboard in any game',
            'icon': '🏆',
            'unlocked': False,
            'unlocked_at': None,
        },
    ]
    
    unlocked = sum(1 for a in achievements if a['unlocked'])
    
    return jsonify({
        'success': True,
        'achievements': achievements,
        'unlocked': unlocked,
        'total': len(achievements),
    })


# ==================== STATISTICS ====================

@games_bp.route('/stats/<game_id>', methods=['GET'])
@token_required
def get_game_stats(current_user, game_id):
    """Get user's statistics for a specific game"""
    if game_id not in GAMES_CONFIG:
        return jsonify({'error': 'Game not found'}), 404
    
    game_config = GAMES_CONFIG[game_id]
    
    stats = {
        'game_id': game_id,
        'game_name': game_config['name'],
        'times_played': 12,
        'avg_score': 385,
        'best_score': 489,
        'total_xp_earned': 4200,
        'best_time': 125,
        'mode_stats': {
            mode: {
                'plays': 4,
                'avg_score': 350 + (i * 20),
                'personal_best': 450 + (i * 20),
            }
            for i, mode in enumerate(game_config['modes'])
        }
    }
    
    return jsonify({
        'success': True,
        'stats': stats
    })


@games_bp.route('/all-stats', methods=['GET'])
@token_required
def get_all_game_stats(current_user):
    """Get user's overall game statistics"""
    total_games_played = 0
    total_xp_earned = 0
    total_time = 0
    
    # Aggregate stats across all games
    game_stats = []
    for game_id, config in GAMES_CONFIG.items():
        game_stats.append({
            'game_id': game_id,
            'game_name': config['name'],
            'plays': 5 + (hash(game_id) % 10),
            'xp_earned': (5 + (hash(game_id) % 10)) * 300,
            'best_score': 400 + (hash(game_id) % 100),
        })
        total_games_played += game_stats[-1]['plays']
        total_xp_earned += game_stats[-1]['xp_earned']
    
    return jsonify({
        'success': True,
        'total_games_played': total_games_played,
        'total_xp_earned': total_xp_earned,
        'avg_score': 380,
        'game_stats': sorted(game_stats, key=lambda x: x['xp_earned'], reverse=True)
    })


@games_bp.route('/daily-challenge', methods=['GET'])
def get_daily_challenge():
    """Get today's daily challenge"""
    game_ids = list(GAMES_CONFIG.keys())
    game_id = game_ids[hash(str(datetime.utcnow().date())) % len(game_ids)]
    game_config = GAMES_CONFIG[game_id]
    
    return jsonify({
        'success': True,
        'game_id': game_id,
        'game_name': game_config['name'],
        'difficulty': game_config['difficulty'],
        'bonus_xp': 150,
        'description': f'Play {game_config["name"]} today for +150 XP bonus!',
        'expires_at': (datetime.utcnow() + timedelta(days=1)).isoformat(),
    })
