"""
Chat Routes for ShadowHack Platform
Phase 13: Real-time Chat & Messaging
"""

from flask import Blueprint, request, jsonify
from models import db, ChatMessage, User, Team, TeamMember
from datetime import datetime
from sqlalchemy import or_, and_

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')

@chat_bp.route('/history/team/<int:team_id>', methods=['GET'])
def get_team_chat(team_id):
    """Get chat history for a team channel"""
    # In real app: Check if current user is member of team
    messages = ChatMessage.query.filter_by(team_id=team_id)\
        .order_by(ChatMessage.created_at.asc())\
        .limit(100).all()
        
    return jsonify({
        'success': True,
        'messages': [m.to_dict() for m in messages]
    })

@chat_bp.route('/history/dm/<int:user1_id>/<int:user2_id>', methods=['GET'])
def get_dm_history(user1_id, user2_id):
    """Get direct message history between two users"""
    messages = ChatMessage.query.filter(
        or_(
            and_(ChatMessage.sender_id == user1_id, ChatMessage.recipient_id == user2_id),
            and_(ChatMessage.sender_id == user2_id, ChatMessage.recipient_id == user1_id)
        )
    ).order_by(ChatMessage.created_at.asc()).limit(100).all()
    
    return jsonify({
        'success': True,
        'messages': [m.to_dict() for m in messages]
    })

@chat_bp.route('/send', methods=['POST'])
def send_message():
    """Send a new message"""
    data = request.json
    sender_id = data.get('sender_id')
    content = data.get('content')
    
    if not sender_id or not content:
        return jsonify({'success': False, 'error': 'Missing data'}), 400
        
    msg = ChatMessage(
        sender_id=sender_id,
        content=content,
        message_type=data.get('type', 'text')
    )
    
    # Route to Team or DM
    if data.get('team_id'):
        msg.team_id = data.get('team_id')
    elif data.get('recipient_id'):
        msg.recipient_id = data.get('recipient_id')
    else:
        return jsonify({'success': False, 'error': 'No target specified'}), 400
        
    db.session.add(msg)
    db.session.commit()
    
    return jsonify({'success': True, 'message': msg.to_dict()})

@chat_bp.route('/contacts/<int:user_id>', methods=['GET'])
def get_contacts(user_id):
    """Get list of recent DMs and Team Channels"""
    # 1. Get Teams
    memberships = TeamMember.query.filter_by(user_id=user_id).all()
    teams = []
    for m in memberships:
        team = Team.query.get(m.team_id)
        if team:
            teams.append({
                'id': team.id,
                'name': team.name,
                'type': 'team',
                'avatar': None, # Could add team icon
                'unread': 0
            })
            
    # 2. Get Recent DMs (Simplified: just get all other users for now or mock recent)
    # Ideally: SELECT DISTINCT user from messages WHERE sender=me OR recipient=me
    other_users = User.query.filter(User.id != user_id).limit(10).all()
    dms = []
    for u in other_users:
        dms.append({
            'id': u.id,
            'name': u.username,
            'type': 'dm',
            'avatar': u.avatar_url,
            'status': 'online', # Mock status
            'unread': 0
        })
        
    return jsonify({
        'success': True,
        'channels': teams,
        'direct_messages': dms
    })


def register_chat_routes(app):
    """Register chat blueprint"""
    app.register_blueprint(chat_bp)
    print("✓ Chat routes registered")
