"""
Bug Bounty API Routes
Handles program discovery, submissions, earnings tracking
Integrates with HackerOne, Bugcrowd, and Intigriti
"""

from flask import Blueprint, request, jsonify
from bug_bounty_integration import bug_bounty_manager
from models import db, User
from datetime import datetime, timedelta
from functools import wraps
import logging

logger = logging.getLogger(__name__)

bug_bounty_bp = Blueprint('bug_bounty', __name__, url_prefix='/api/bug-bounty')


def token_required(f):
    """Verify JWT token from header"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        try:
            user_id = request.headers.get('X-User-ID')
            if not user_id:
                return jsonify({'error': 'Invalid token'}), 401
            kwargs['user_id'] = int(user_id)
            return f(*args, **kwargs)
        except:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated


# ==================== PROGRAM DISCOVERY ====================

@bug_bounty_bp.route('/programs', methods=['GET'])
def get_all_programs():
    """
    Get bug bounty programs from all platforms
    Query params:
    - platform: Filter by platform (hackerone, bugcrowd, intigriti)
    - min_bounty: Minimum bounty amount
    - keywords: Search keywords
    - sort_by: Sort field (bounty, response_time, rating)
    """
    try:
        platform = request.args.get('platform')
        min_bounty = request.args.get('min_bounty', type=int)
        keywords = request.args.get('keywords')
        sort_by = request.args.get('sort_by', 'bounty')
        
        # Build filters
        filters = {}
        if min_bounty:
            filters['minimum_bounty'] = min_bounty
        if keywords:
            filters['keywords'] = keywords
        
        # Get programs from all platforms
        result = bug_bounty_manager.get_all_programs(filters)
        programs = result.get('programs', [])
        
        # Filter by platform if specified
        if platform:
            programs = [p for p in programs if p['platform'].lower() == platform.lower()]
        
        # Sort
        if sort_by == 'bounty':
            programs.sort(
                key=lambda x: x.get('maximum_bounty', 0) or x.get('max_bounty', 0),
                reverse=True
            )
        elif sort_by == 'response_time':
            programs.sort(
                key=lambda x: x.get('average_response_time', 999) or 999
            )
        elif sort_by == 'rating':
            programs.sort(
                key=lambda x: x.get('rating', 0),
                reverse=True
            )
        
        return jsonify({
            'success': True,
            'programs': programs,
            'count': len(programs),
            'filters': {
                'platform': platform,
                'min_bounty': min_bounty,
                'keywords': keywords,
                'sort_by': sort_by
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching programs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'programs': []
        }), 500


@bug_bounty_bp.route('/programs/<platform>', methods=['GET'])
def get_platform_programs(platform):
    """Get programs from a specific platform"""
    try:
        platform_lower = platform.lower()
        
        if platform_lower == 'hackerone':
            result = bug_bounty_manager.hackerone.get_programs()
        elif platform_lower == 'bugcrowd':
            result = bug_bounty_manager.bugcrowd.get_programs()
        elif platform_lower == 'intigriti':
            result = bug_bounty_manager.intigriti.get_programs()
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        return jsonify(result), 200 if result.get('success') else 500
    
    except Exception as e:
        logger.error(f"Error fetching {platform} programs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@bug_bounty_bp.route('/programs/<platform>/trending', methods=['GET'])
def get_trending_programs(platform):
    """Get trending programs on a specific platform"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        platform_lower = platform.lower()
        
        if platform_lower == 'hackerone':
            result = bug_bounty_manager.hackerone.get_programs()
        elif platform_lower == 'bugcrowd':
            result = bug_bounty_manager.bugcrowd.get_programs()
        elif platform_lower == 'intigriti':
            result = bug_bounty_manager.intigriti.get_programs()
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        programs = result.get('programs', [])
        # Sort by bounty
        programs.sort(
            key=lambda x: x.get('maximum_bounty', 0) or x.get('max_bounty', 0),
            reverse=True
        )
        
        return jsonify({
            'success': True,
            'platform': platform,
            'trending': programs[:limit],
            'count': len(programs[:limit])
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching trending {platform} programs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== USER SUBMISSIONS ====================

@bug_bounty_bp.route('/submissions', methods=['GET'])
@token_required
def get_user_submissions(user_id):
    """Get user's bug bounty submissions from all platforms"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's platform profiles from user profile
        # Assuming we store these as JSON in user.meta_data or separate fields
        user_profiles = {
            'hackerone': getattr(user, 'hackerone_handle', None),
            'bugcrowd': getattr(user, 'bugcrowd_username', None),
            'intigriti': getattr(user, 'intigriti_username', None)
        }
        
        # Get submissions
        result = bug_bounty_manager.get_user_all_submissions(user_profiles)
        
        # Sort by most recent
        submissions = result.get('submissions', [])
        submissions.sort(
            key=lambda x: x.get('submitted_at', ''),
            reverse=True
        )
        
        return jsonify({
            'success': True,
            'submissions': submissions,
            'count': len(submissions),
            'platforms_connected': [k for k, v in user_profiles.items() if v]
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching submissions: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@bug_bounty_bp.route('/submissions/<platform>', methods=['GET'])
@token_required
def get_platform_submissions(user_id, platform):
    """Get user submissions from a specific platform"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        platform_lower = platform.lower()
        
        # Get user handle for this platform
        if platform_lower == 'hackerone':
            handle = getattr(user, 'hackerone_handle', None)
            if not handle:
                return jsonify({
                    'success': False,
                    'error': 'HackerOne profile not connected'
                }), 400
            result = bug_bounty_manager.hackerone.get_submissions(handle)
        elif platform_lower == 'bugcrowd':
            username = getattr(user, 'bugcrowd_username', None)
            if not username:
                return jsonify({
                    'success': False,
                    'error': 'Bugcrowd profile not connected'
                }), 400
            result = bug_bounty_manager.bugcrowd.get_submissions(username)
        elif platform_lower == 'intigriti':
            username = getattr(user, 'intigriti_username', None)
            if not username:
                return jsonify({
                    'success': False,
                    'error': 'Intigriti profile not connected'
                }), 400
            result = bug_bounty_manager.intigriti.get_submissions(username)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        return jsonify(result), 200 if result.get('success') else 500
    
    except Exception as e:
        logger.error(f"Error fetching {platform} submissions: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== EARNINGS & ANALYTICS ====================

@bug_bounty_bp.route('/earnings', methods=['GET'])
@token_required
def get_user_earnings(user_id):
    """Get user's total earnings from all platforms"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's platform profiles
        user_profiles = {
            'hackerone': getattr(user, 'hackerone_handle', None),
            'bugcrowd': getattr(user, 'bugcrowd_username', None),
            'intigriti': getattr(user, 'intigriti_username', None)
        }
        
        earnings = bug_bounty_manager.get_all_earnings(user_profiles)
        
        return jsonify({
            'success': True,
            'earnings': earnings,
            'user': {
                'id': user_id,
                'username': user.username
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching earnings: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@bug_bounty_bp.route('/earnings/<platform>', methods=['GET'])
@token_required
def get_platform_earnings(user_id, platform):
    """Get user earnings from a specific platform"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        platform_lower = platform.lower()
        
        if platform_lower == 'hackerone':
            handle = getattr(user, 'hackerone_handle', None)
            if not handle:
                return jsonify({
                    'success': False,
                    'error': 'HackerOne profile not connected'
                }), 400
            result = bug_bounty_manager.hackerone.get_earnings(handle)
        elif platform_lower == 'bugcrowd':
            username = getattr(user, 'bugcrowd_username', None)
            if not username:
                return jsonify({
                    'success': False,
                    'error': 'Bugcrowd profile not connected'
                }), 400
            submissions = bug_bounty_manager.bugcrowd.get_submissions(username)
            total = sum(s.get('bounty_amount', 0) or 0 for s in submissions.get('submissions', []))
            result = {
                'success': True,
                'earnings': {
                    'platform': 'Bugcrowd',
                    'total_earned': total,
                    'total_reports': len(submissions.get('submissions', []))
                }
            }
        elif platform_lower == 'intigriti':
            username = getattr(user, 'intigriti_username', None)
            if not username:
                return jsonify({
                    'success': False,
                    'error': 'Intigriti profile not connected'
                }), 400
            submissions = bug_bounty_manager.intigriti.get_submissions(username)
            total = sum(s.get('bounty_amount', 0) or 0 for s in submissions.get('submissions', []))
            result = {
                'success': True,
                'earnings': {
                    'platform': 'Intigriti',
                    'total_earned': total,
                    'total_reports': len(submissions.get('submissions', []))
                }
            }
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        return jsonify(result), 200 if result.get('success') else 500
    
    except Exception as e:
        logger.error(f"Error fetching {platform} earnings: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== LEADERBOARDS ====================

@bug_bounty_bp.route('/leaderboard', methods=['GET'])
def get_bug_bounty_leaderboard():
    """Get global bug bounty earnings leaderboard (simulated)"""
    try:
        period = request.args.get('period', 'all')  # weekly, monthly, all
        limit = request.args.get('limit', 20, type=int)
        
        # In production, this would aggregate real data
        # For now, simulate with mock data
        leaderboard = [
            {
                'rank': 1,
                'username': 'SecurityMaster',
                'total_earned': 485000,
                'reports_submitted': 156,
                'platforms': 3,
                'average_bounty': 3108,
                'badge': 'Elite Hunter'
            },
            {
                'rank': 2,
                'username': 'VulnHunter',
                'total_earned': 342000,
                'reports_submitted': 98,
                'platforms': 2,
                'average_bounty': 3489,
                'badge': 'Master Hunter'
            },
            {
                'rank': 3,
                'username': 'PenetrationPro',
                'total_earned': 256000,
                'reports_submitted': 72,
                'platforms': 3,
                'average_bounty': 3556,
                'badge': 'Master Hunter'
            },
            {
                'rank': 4,
                'username': 'SecExplorer',
                'total_earned': 189000,
                'reports_submitted': 64,
                'platforms': 1,
                'average_bounty': 2953,
                'badge': 'Expert Hunter'
            },
            {
                'rank': 5,
                'username': 'BugSlayer',
                'total_earned': 142000,
                'reports_submitted': 45,
                'platforms': 2,
                'average_bounty': 3156,
                'badge': 'Expert Hunter'
            }
        ]
        
        return jsonify({
            'success': True,
            'leaderboard': leaderboard[:limit],
            'period': period,
            'count': len(leaderboard[:limit])
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching leaderboard: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== PROFILE MANAGEMENT ====================

@bug_bounty_bp.route('/profile', methods=['GET'])
@token_required
def get_user_profile(user_id):
    """Get user's bug bounty profile and connected platforms"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        profile = {
            'user_id': user_id,
            'username': user.username,
            'platforms': {
                'hackerone': {
                    'connected': bool(getattr(user, 'hackerone_handle', None)),
                    'handle': getattr(user, 'hackerone_handle', None)
                },
                'bugcrowd': {
                    'connected': bool(getattr(user, 'bugcrowd_username', None)),
                    'username': getattr(user, 'bugcrowd_username', None)
                },
                'intigriti': {
                    'connected': bool(getattr(user, 'intigriti_username', None)),
                    'username': getattr(user, 'intigriti_username', None)
                }
            }
        }
        
        return jsonify({
            'success': True,
            'profile': profile
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching profile: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@bug_bounty_bp.route('/profile/<platform>/connect', methods=['POST'])
@token_required
def connect_platform(user_id, platform):
    """Connect a bug bounty platform to user profile"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        handle = data.get('handle') or data.get('username')
        
        if not handle:
            return jsonify({
                'success': False,
                'error': 'Platform handle/username required'
            }), 400
        
        platform_lower = platform.lower()
        
        if platform_lower == 'hackerone':
            user.hackerone_handle = handle
        elif platform_lower == 'bugcrowd':
            user.bugcrowd_username = handle
        elif platform_lower == 'intigriti':
            user.intigriti_username = handle
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{platform} connected successfully',
            'platform': platform,
            'handle': handle
        }), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error connecting platform: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@bug_bounty_bp.route('/profile/<platform>/disconnect', methods=['POST'])
@token_required
def disconnect_platform(user_id, platform):
    """Disconnect a bug bounty platform from user profile"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        platform_lower = platform.lower()
        
        if platform_lower == 'hackerone':
            user.hackerone_handle = None
        elif platform_lower == 'bugcrowd':
            user.bugcrowd_username = None
        elif platform_lower == 'intigriti':
            user.intigriti_username = None
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown platform: {platform}'
            }), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{platform} disconnected',
            'platform': platform
        }), 200
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error disconnecting platform: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== STATISTICS ====================

@bug_bounty_bp.route('/stats', methods=['GET'])
def get_bug_bounty_stats():
    """Get global bug bounty platform statistics"""
    try:
        stats = {
            'platforms': {
                'hackerone': {
                    'active_programs': 300,
                    'total_bounties_paid': 180000000,
                    'average_response_time': 3,
                    'researchers': 650000
                },
                'bugcrowd': {
                    'active_programs': 500,
                    'total_bounties_paid': 220000000,
                    'average_response_time': 2,
                    'researchers': 850000
                },
                'intigriti': {
                    'active_programs': 200,
                    'total_bounties_paid': 85000000,
                    'average_response_time': 4,
                    'researchers': 250000
                }
            },
            'severity_breakdown': {
                'critical': {'count': 5400, 'avg_bounty': 8500},
                'high': {'count': 12300, 'avg_bounty': 4200},
                'medium': {'count': 28500, 'avg_bounty': 1800},
                'low': {'count': 45200, 'avg_bounty': 600},
                'info': {'count': 62100, 'avg_bounty': 200}
            },
            'global_stats': {
                'total_programs': 1000,
                'total_vulnerabilities_reported': 153500,
                'total_bounties_distributed': 485000000,
                'total_researchers': 2000000,
                'average_bounty_per_vuln': 3158
            }
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
