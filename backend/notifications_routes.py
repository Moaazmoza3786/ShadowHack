"""
Notification Routes for ShadowHack Platform
Phase 10: Real-time notifications and activity feed
"""

from flask import Blueprint, request, jsonify
from models import db, Notification, ActivityFeed, User
from datetime import datetime

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')
activity_bp = Blueprint('activity', __name__, url_prefix='/api/activity')


# ==================== NOTIFICATION ROUTES ====================

@notifications_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user_notifications(user_id):
    """Get all notifications for a user"""
    unread_only = request.args.get('unread', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 50))
    
    query = Notification.query.filter_by(user_id=user_id)
    if unread_only:
        query = query.filter_by(is_read=False)
    
    notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()
    unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    
    return jsonify({
        'success': True,
        'notifications': [n.to_dict() for n in notifications],
        'unread_count': unread_count
    })


@notifications_bp.route('/<int:notification_id>/read', methods=['POST'])
def mark_as_read(notification_id):
    """Mark a notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    notification.is_read = True
    notification.read_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})


@notifications_bp.route('/user/<int:user_id>/read-all', methods=['POST'])
def mark_all_read(user_id):
    """Mark all notifications as read"""
    Notification.query.filter_by(user_id=user_id, is_read=False).update({
        'is_read': True,
        'read_at': datetime.utcnow()
    })
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'All notifications marked as read'})


@notifications_bp.route('/send', methods=['POST'])
def send_notification():
    """Send a notification to a user (internal/admin use)"""
    data = request.json
    user_id = data.get('user_id')
    title = data.get('title')
    message = data.get('message')
    
    if not all([user_id, title]):
        return jsonify({'success': False, 'error': 'user_id and title required'}), 400
    
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        icon=data.get('icon', 'bell'),
        notification_type=data.get('type', 'info'),
        category=data.get('category', 'system'),
        action_url=data.get('action_url'),
        action_label=data.get('action_label')
    )
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'success': True, 'notification': notification.to_dict()})


@notifications_bp.route('/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    """Delete a notification"""
    notification = Notification.query.get_or_404(notification_id)
    db.session.delete(notification)
    db.session.commit()
    
    return jsonify({'success': True})


# ==================== ACTIVITY FEED ROUTES ====================

@activity_bp.route('/global', methods=['GET'])
def get_global_feed():
    """Get global activity feed"""
    limit = int(request.args.get('limit', 30))
    
    activities = ActivityFeed.query.filter_by(is_public=True)\
        .order_by(ActivityFeed.created_at.desc())\
        .limit(limit).all()
    
    return jsonify({
        'success': True,
        'activities': [a.to_dict() for a in activities]
    })


@activity_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user_activity(user_id):
    """Get activity feed for a specific user"""
    limit = int(request.args.get('limit', 20))
    
    activities = ActivityFeed.query.filter_by(user_id=user_id)\
        .order_by(ActivityFeed.created_at.desc())\
        .limit(limit).all()
    
    return jsonify({
        'success': True,
        'activities': [a.to_dict() for a in activities]
    })


@activity_bp.route('/log', methods=['POST'])
def log_activity():
    """Log a new activity (internal use)"""
    data = request.json
    user_id = data.get('user_id')
    activity_type = data.get('activity_type')
    content = data.get('content')
    
    if not all([user_id, activity_type]):
        return jsonify({'success': False, 'error': 'user_id and activity_type required'}), 400
    
    activity = ActivityFeed(
        user_id=user_id,
        activity_type=activity_type,
        content=content,
        related_id=data.get('related_id'),
        related_type=data.get('related_type'),
        is_public=data.get('is_public', True)
    )
    db.session.add(activity)
    db.session.commit()
    
    return jsonify({'success': True, 'activity': activity.to_dict()})


def register_notification_routes(app):
    """Register notification and activity blueprints"""
    app.register_blueprint(notifications_bp)
    app.register_blueprint(activity_bp)
    print("✓ Notification & Activity routes registered")
