"""
Mini-Games & Gamified Challenges API Routes
Handles game scoring, leaderboards, achievements
Powered by Groq AI for dynamic challenge generation
"""

from flask import Blueprint, jsonify, request
from functools import wraps
import jwt
import os
import logging
from datetime import datetime, timedelta

from models import db, User

logger = logging.getLogger(__name__)

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


# ==================== GROQ-POWERED AI CHALLENGES ====================

@games_bp.route('/<game_id>/ai-challenge', methods=['GET'])
def get_ai_challenge(game_id):
    """
    Get AI-generated challenge for a game
    Uses Groq qwen3-32b for dynamic content generation
    Query params:
    - difficulty: beginner, intermediate, advanced, hard, expert
    """
    try:
        from games_engine import games_engine
        
        difficulty = request.args.get('difficulty', 'intermediate')
        
        challenge_data = games_engine.get_game_challenge(game_id, difficulty)
        
        return jsonify({
            'success': True,
            'challenge': challenge_data
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating AI challenge: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@games_bp.route('/<game_id>/ai-challenge/<int:challenge_id>/submit', methods=['POST'])
@token_required
def submit_ai_challenge(current_user, game_id, challenge_id):
    """
    Submit answer to AI-generated challenge
    Calculates dynamic XP based on difficulty, score, and time
    """
    try:
        from games_engine import games_engine
        
        data = request.json
        score = data.get('score', 0)
        max_score = data.get('max_score', 1000)
        time_spent = data.get('time_spent_seconds')
        difficulty = data.get('difficulty', 'intermediate')
        
        # Calculate XP
        xp_calculation = games_engine.calculate_dynamic_xp(
            game_id=game_id,
            difficulty=difficulty,
            score=score,
            max_score=max_score,
            time_spent_seconds=time_spent
        )
        
        xp_earned = xp_calculation['total_xp']
        
        # Award XP to user
        current_user.xp_points += xp_earned
        current_user.level = max(1, int(0.1 * (current_user.xp_points ** 0.5)))
        
        # Update weekly XP for leaderboards
        current_user.weekly_xp += xp_earned
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'xp_earned': xp_earned,
            'xp_calculation': xp_calculation,
            'user_level': current_user.level,
            'total_xp': current_user.xp_points,
            'challenge_id': challenge_id
        }), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting AI challenge: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@games_bp.route('/daily-ai-challenge', methods=['GET'])
def get_daily_ai_challenge():
    """
    Get today's featured AI-generated challenge
    Provides bonus XP for completion
    Changes every 24 hours
    """
    try:
        from games_engine import games_engine
        
        daily_challenge = games_engine.generate_daily_challenge()
        
        return jsonify(daily_challenge), 200
    
    except Exception as e:
        logger.error(f"Error generating daily AI challenge: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@games_bp.route('/<game_id>/ai-difficulty-recommendations', methods=['GET'])
@token_required
def get_difficulty_recommendations(current_user, game_id):
    """
    Get personalized difficulty recommendation for a game
    Based on user's historical performance and XP level
    """
    try:
        user_xp = current_user.xp_points
        
        # Determine difficulty based on XP
        if user_xp < 1000:
            recommended = 'beginner'
            explanation = 'Start with basic challenges to learn the fundamentals'
        elif user_xp < 10000:
            recommended = 'intermediate'
            explanation = 'You\'re ready for moderate difficulty challenges'
        elif user_xp < 50000:
            recommended = 'advanced'
            explanation = 'Challenge yourself with advanced scenarios'
        elif user_xp < 100000:
            recommended = 'hard'
            explanation = 'Master-level challenges for elite hunters'
        else:
            recommended = 'expert'
            explanation = 'Ultimate difficulty - only for the most skilled'
        
        return jsonify({
            'success': True,
            'game_id': game_id,
            'recommended_difficulty': recommended,
            'explanation': explanation,
            'user_xp': user_xp,
            'user_level': current_user.level,
            'difficulty_ladder': ['beginner', 'intermediate', 'advanced', 'hard', 'expert']
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting recommendations: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@games_bp.route('/ai-hint/<game_id>/<topic>', methods=['GET'])
def get_ai_hint(game_id, topic):
    """
    Get AI-generated hint for a challenge topic
    Helps students without giving away the answer
    """
    try:
        from learning_manager import learning_manager
        
        difficulty = request.args.get('difficulty', 'intermediate')
        context = request.args.get('context')
        
        hint = learning_manager.generate_learning_hints(
            topic=f'{game_id}: {topic}',
            difficulty=difficulty,
            context=context
        )
        
        return jsonify({
            'success': True,
            'game_id': game_id,
            'topic': topic,
            'hint': hint,
            'difficulty': difficulty
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating hint: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
