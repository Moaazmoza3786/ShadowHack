"""
Admin Routes for ShadowHack Platform
Phase 14: System Administration & Logs
"""

from flask import Blueprint, request, jsonify
from models import db, User, ActivityFeed
from sqlalchemy import desc

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# Decorator placeholder (in real app, verify properly)
def admin_required(f):
    """Decorator to require admin role"""
    # In a real implementation, you would check current_user.role == 'admin'
    # For this demo, we assume the frontend sends a 'X-Admin-Token' or similar, 
    # OR we just rely on the simulated generic user being admin for now.
    return f

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats():
    """Get system overview stats"""
    user_count = User.query.count()
    active_today = ActivityFeed.query.count() # Mock proxy
    banned_users = User.query.filter_by(is_banned=True).count()
    admins = User.query.filter_by(role='admin').count()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_users': user_count,
            'active_today': active_today, # Mock
            'banned_users': banned_users,
            'admins': admins,
            'server_status': 'Healthy',
            'uptime': '99.9%'
        }
    })

@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    """List all users with filtering"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    query = request.args.get('q', '').lower()
    
    users_query = User.query
    if query:
        users_query = users_query.filter(User.username.ilike(f'%{query}%'))
        
    pagination = users_query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    users_list = []
    for u in pagination.items:
        users_list.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'is_banned': u.is_banned,
            'joined': u.created_at.isoformat()
        })
        
    return jsonify({
        'success': True,
        'users': users_list,
        'total': pagination.total,
        'pages': pagination.pages
    })

@admin_bp.route('/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def toggle_ban(user_id):
    """Ban or Unban a user"""
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return jsonify({'success': False, 'error': 'Cannot ban an admin'}), 403
        
    user.is_banned = not user.is_banned
    db.session.commit()
    
    action = "Banned" if user.is_banned else "Unbanned"
    return jsonify({'success': True, 'message': f'User {user.username} has been {action}'})

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_role(user_id):
    """Update user role (promote/demote)"""
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    if new_role not in ['user', 'moderator', 'admin']:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
    user.role = new_role
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.username} is now {new_role}'})

@admin_bp.route('/logs', methods=['GET'])
@admin_required
def get_logs():
    """Get system logs (using ActivityFeed as proxy for now)"""
    logs = ActivityFeed.query.order_by(ActivityFeed.created_at.desc()).limit(50).all()
    
    return jsonify({
        'success': True,
        'logs': [l.to_dict() for l in logs]
    })


def register_admin_routes(app):
    """Register admin blueprint"""
    app.register_blueprint(admin_bp)
    print("✓ Admin routes registered")
