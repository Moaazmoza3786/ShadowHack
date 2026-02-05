"""
Analytics Routes for ShadowHack Platform
Phase 9: Advanced Analytics & Skill Certification
"""

from flask import Blueprint, request, jsonify
from models import db, User, LabSubmission, UserProgress, UserAchievement, Quiz, QuizAttempt
from datetime import datetime, timedelta
from sqlalchemy import func

analytics_bp = Blueprint('analytics', __name__, url_prefix='/api/analytics')


@analytics_bp.route('/user/<int:user_id>/overview', methods=['GET'])
def get_user_overview(user_id):
    """Get comprehensive user analytics overview"""
    user = User.query.get_or_404(user_id)
    
    # Lab stats
    total_labs = LabSubmission.query.filter_by(user_id=user_id).count()
    completed_labs = LabSubmission.query.filter_by(user_id=user_id, is_correct=True).count()
    
    # Calculate average solve time
    avg_solve_time = db.session.query(
        func.avg(LabSubmission.time_to_solve_seconds)
    ).filter_by(user_id=user_id, is_correct=True).scalar() or 0
    
    # Achievements
    achievements_count = UserAchievement.query.filter_by(user_id=user_id).count()
    
    # Learning progress
    modules_completed = UserProgress.query.filter_by(user_id=user_id, is_completed=True).count()
    
    # Quiz stats
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user_id).count()
    quiz_passed = QuizAttempt.query.filter_by(user_id=user_id, passed=True).count()
    
    return jsonify({
        'success': True,
        'overview': {
            'xp_total': user.xp_points,
            'level': user.level,
            'rank': user.current_rank,
            'streak_days': user.streak_days,
            'labs': {
                'total_attempts': total_labs,
                'completed': completed_labs,
                'success_rate': round((completed_labs / total_labs * 100) if total_labs > 0 else 0, 1),
                'avg_solve_time_minutes': round(avg_solve_time / 60, 1) if avg_solve_time else 0
            },
            'learning': {
                'modules_completed': modules_completed,
                'quizzes_attempted': quiz_attempts,
                'quizzes_passed': quiz_passed
            },
            'achievements_count': achievements_count
        }
    })


@analytics_bp.route('/user/<int:user_id>/activity', methods=['GET'])
def get_user_activity(user_id):
    """Get user activity heatmap data (last 90 days)"""
    days = int(request.args.get('days', 90))
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get lab activity by day
    lab_activity = db.session.query(
        func.date(LabSubmission.attempt_time).label('date'),
        func.count(LabSubmission.id).label('count')
    ).filter(
        LabSubmission.user_id == user_id,
        LabSubmission.attempt_time >= start_date
    ).group_by(func.date(LabSubmission.attempt_time)).all()
    
    # Format for heatmap
    activity_map = {str(a.date): a.count for a in lab_activity}
    
    return jsonify({
        'success': True,
        'activity': activity_map,
        'period_days': days
    })


@analytics_bp.route('/user/<int:user_id>/skills', methods=['GET'])
def get_user_skills(user_id):
    """Get user skill breakdown by category"""
    # Aggregate XP by domain/category from completed labs
    skill_data = db.session.query(
        LabSubmission.lab_id,
        func.count(LabSubmission.id).label('attempts'),
        func.sum(db.case((LabSubmission.is_correct == True, 1), else_=0)).label('wins')
    ).filter_by(user_id=user_id).group_by(LabSubmission.lab_id).all()
    
    # Map to skill categories (simplified)
    categories = {
        'web': {'name': 'Web Exploitation', 'xp': 0, 'completed': 0},
        'network': {'name': 'Network Security', 'xp': 0, 'completed': 0},
        'crypto': {'name': 'Cryptography', 'xp': 0, 'completed': 0},
        'forensics': {'name': 'Digital Forensics', 'xp': 0, 'completed': 0},
        'reverse': {'name': 'Reverse Engineering', 'xp': 0, 'completed': 0},
        'pwn': {'name': 'Binary Exploitation', 'xp': 0, 'completed': 0}
    }
    
    # TODO: Map lab_ids to categories based on Lab model
    # For now, return sample structure
    
    return jsonify({
        'success': True,
        'skills': list(categories.values())
    })


@analytics_bp.route('/user/<int:user_id>/xp-history', methods=['GET'])
def get_xp_history(user_id):
    """Get XP earned over time"""
    days = int(request.args.get('days', 30))
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get XP gains from lab completions
    xp_data = db.session.query(
        func.date(LabSubmission.attempt_time).label('date'),
        func.sum(50).label('xp')  # Assuming 50 XP per correct lab
    ).filter(
        LabSubmission.user_id == user_id,
        LabSubmission.is_correct == True,
        LabSubmission.attempt_time >= start_date
    ).group_by(func.date(LabSubmission.attempt_time)).all()
    
    history = [{'date': str(x.date), 'xp': x.xp} for x in xp_data]
    
    return jsonify({
        'success': True,
        'xp_history': history,
        'period_days': days
    })


@analytics_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    """Get global leaderboard"""
    limit = int(request.args.get('limit', 25))
    period = request.args.get('period', 'all')  # all, weekly, monthly
    
    query = User.query.filter(User.is_active == True)
    
    if period == 'weekly':
        query = query.order_by(User.weekly_xp.desc())
    else:
        query = query.order_by(User.xp_points.desc())
    
    users = query.limit(limit).all()
    
    leaderboard = [{
        'rank': i + 1,
        'user_id': u.id,
        'username': u.username,
        'avatar_url': u.avatar_url,
        'xp': u.weekly_xp if period == 'weekly' else u.xp_points,
        'level': u.level,
        'rank_title': u.current_rank
    } for i, u in enumerate(users)]
    
    return jsonify({
        'success': True,
        'leaderboard': leaderboard,
        'period': period
    })


def register_analytics_routes(app):
    """Register analytics blueprint"""
    app.register_blueprint(analytics_bp)
    print("✓ Analytics API routes registered")
