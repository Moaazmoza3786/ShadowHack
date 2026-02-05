"""
Profile Routes for ShadowHack Platform
Phase 11: User Profile & Settings System
"""

from flask import Blueprint, request, jsonify
from models import db, User, UserAchievement, Achievement, LabSubmission, Team, TeamMember
from datetime import datetime
from sqlalchemy import func
import hashlib

profile_bp = Blueprint('profile', __name__, url_prefix='/api/profile')


@profile_bp.route('/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    """Get user profile with stats"""
    user = User.query.get_or_404(user_id)
    
    # Get achievements
    achievements = UserAchievement.query.filter_by(user_id=user_id).all()
    
    # Get lab stats
    lab_stats = db.session.query(
        func.count(LabSubmission.id).label('total'),
        func.sum(db.case((LabSubmission.is_correct == True, 1), else_=0)).label('completed')
    ).filter_by(user_id=user_id).first()
    
    # Get team membership
    team_member = TeamMember.query.filter_by(user_id=user_id).first()
    team_info = None
    if team_member:
        team = Team.query.get(team_member.team_id)
        if team:
            team_info = {
                'id': team.id,
                'name': team.name,
                'tag': team.tag,
                'role': team_member.role
            }
    
    return jsonify({
        'success': True,
        'profile': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'avatar_url': user.avatar_url,
            'bio': getattr(user, 'bio', None),
            'location': getattr(user, 'location', None),
            'website': getattr(user, 'website', None),
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'stats': {
                'xp': user.xp_points,
                'level': user.level,
                'rank': user.current_rank,
                'streak_days': user.streak_days,
                'labs_attempted': lab_stats.total or 0,
                'labs_completed': lab_stats.completed or 0,
                'achievements_count': len(achievements)
            },
            'team': team_info,
            'achievements': [{
                'id': a.achievement.id if a.achievement else None,
                'name': a.achievement.name if a.achievement else None,
                'icon': a.achievement.icon if a.achievement else None,
                'earned_at': a.earned_at.isoformat() if a.earned_at else None
            } for a in achievements[:10]]  # Latest 10
        }
    })


@profile_bp.route('/<int:user_id>', methods=['PUT'])
def update_profile(user_id):
    """Update user profile"""
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # Updatable fields
    if 'username' in data:
        # Check uniqueness
        existing = User.query.filter_by(username=data['username']).first()
        if existing and existing.id != user_id:
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        user.username = data['username']
    
    if 'bio' in data:
        user.bio = data['bio'][:500] if data['bio'] else None
    
    if 'location' in data:
        user.location = data['location'][:100] if data['location'] else None
    
    if 'website' in data:
        user.website = data['website'][:200] if data['website'] else None
    
    if 'avatar_url' in data:
        user.avatar_url = data['avatar_url']
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Profile updated'})


@profile_bp.route('/<int:user_id>/settings', methods=['GET'])
def get_settings(user_id):
    """Get user settings/preferences"""
    user = User.query.get_or_404(user_id)
    
    # Default settings structure
    settings = {
        'notifications': {
            'email_notifications': getattr(user, 'email_notifications', True),
            'push_notifications': getattr(user, 'push_notifications', True),
            'achievement_alerts': True,
            'team_updates': True
        },
        'privacy': {
            'profile_public': getattr(user, 'profile_public', True),
            'show_activity': getattr(user, 'show_activity', True),
            'show_stats': True
        },
        'appearance': {
            'theme': getattr(user, 'theme', 'dark'),
            'language': 'en'
        }
    }
    
    return jsonify({'success': True, 'settings': settings})


@profile_bp.route('/<int:user_id>/settings', methods=['PUT'])
def update_settings(user_id):
    """Update user settings"""
    user = User.query.get_or_404(user_id)
    data = request.json
    
    # Update notification settings
    if 'notifications' in data:
        notif = data['notifications']
        if 'email_notifications' in notif:
            user.email_notifications = notif['email_notifications']
        if 'push_notifications' in notif:
            user.push_notifications = notif['push_notifications']
    
    # Update privacy settings
    if 'privacy' in data:
        priv = data['privacy']
        if 'profile_public' in priv:
            user.profile_public = priv['profile_public']
        if 'show_activity' in priv:
            user.show_activity = priv['show_activity']
    
    # Update appearance
    if 'appearance' in data:
        if 'theme' in data['appearance']:
            user.theme = data['appearance']['theme']
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Settings updated'})


@profile_bp.route('/<int:user_id>/password', methods=['PUT'])
def change_password(user_id):
    """Change user password"""
    user = User.query.get_or_404(user_id)
    data = request.json
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not all([current_password, new_password]):
        return jsonify({'success': False, 'error': 'Both passwords required'}), 400
    
    # Verify current password
    if not user.check_password(current_password):
        return jsonify({'success': False, 'error': 'Current password incorrect'}), 401
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})


def register_profile_routes(app):
    """Register profile blueprint"""
    app.register_blueprint(profile_bp)
    print("✓ Profile & Settings routes registered")
