"""
Search & Bookmark Routes for ShadowHack Platform
Phase 12: Search & Bookmarking System
"""

from flask import Blueprint, request, jsonify
from models import db, Bookmark, User, Team, LabSubmission # Assuming Lab model exists or simulating
from datetime import datetime
from sqlalchemy import or_

search_bp = Blueprint('search', __name__, url_prefix='/api/search')

# ==================== SEARCH ROUTES ====================

@search_bp.route('/global', methods=['GET'])
def global_search():
    """Global search across Users, Teams, and Static Content"""
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify({'success': True, 'results': []})
    
    results = []
    
    # 1. Search Users
    users = User.query.filter(User.username.ilike(f'%{query}%')).limit(5).all()
    for user in users:
        results.append({
            'type': 'user',
            'title': user.username,
            'subtitle': f'Level {user.level} {user.current_rank}',
            'link': f'/profile',  # In real app: /profile/{user.id}
            'icon': 'user'
        })
        
    # 2. Search Teams
    teams = Team.query.filter(
        or_(Team.name.ilike(f'%{query}%'), Team.tag.ilike(f'%{query}%'))
    ).limit(5).all()
    for team in teams:
        results.append({
            'type': 'team',
            'title': team.name,
            'subtitle': f'[{team.tag}] {team.xp_points} XP',
            'link': '/teams',
            'icon': 'users'
        })
    
    # 3. Static Content (Simulated for Labs/Tools as they might not be in DB yet or are hardcoded)
    # in a real scenario, we would query the Lab/Course models
    static_content = [
        {'title': 'Nmap Network Scanning', 'type': 'lab', 'desc': 'Learn network discovery', 'link': '/cyber-ops', 'tags': ['nmap', 'network', 'scan']},
        {'title': 'Metasploit Framework', 'type': 'tool', 'desc': 'Exploitation framework', 'link': '/tools/metasploit', 'tags': ['exploit', 'msf']},
        {'title': 'Web Fundamentals', 'type': 'course', 'desc': 'Basics of web security', 'link': '/paths/web', 'tags': ['web', 'http', 'xss']},
        {'title': 'CyberOps Dashboard', 'type': 'feature', 'desc': 'Command center', 'link': '/cyber-ops', 'tags': ['dashboard', 'ops']},
        {'title': 'Skill Assessment', 'type': 'feature', 'desc': 'Test your skills', 'link': '/assessments', 'tags': ['quiz', 'test']},
    ]
    
    for item in static_content:
        if query.lower() in item['title'].lower() or \
           query.lower() in item['desc'].lower() or \
           any(query.lower() in tag for tag in item['tags']):
            results.append({
                'type': item['type'],
                'title': item['title'],
                'subtitle': item['desc'],
                'link': item['link'],
                'icon': 'code' if item['type'] == 'lab' else 'tool'
            })
            
    return jsonify({'success': True, 'results': results[:20]})


# ==================== BOOKMARK ROUTES ====================

@search_bp.route('/bookmarks/<int:user_id>', methods=['GET'])
def get_bookmarks(user_id):
    """Get user bookmarks"""
    bookmarks = Bookmark.query.filter_by(user_id=user_id).order_by(Bookmark.created_at.desc()).all()
    return jsonify({'success': True, 'bookmarks': [b.to_dict() for b in bookmarks]})

@search_bp.route('/bookmarks', methods=['POST'])
def add_bookmark():
    """Add a new bookmark"""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'success': False, 'error': 'User ID required'}), 400
        
    bookmark = Bookmark(
        user_id=user_id,
        item_type=data.get('type', 'link'),
        item_id=data.get('id', 0),
        title=data.get('title'),
        description=data.get('description'),
        path=data.get('path')
    )
    
    db.session.add(bookmark)
    db.session.commit()
    return jsonify({'success': True, 'bookmark': bookmark.to_dict()})

@search_bp.route('/bookmarks/<int:bookmark_id>', methods=['DELETE'])
def remove_bookmark(bookmark_id):
    """Remove a bookmark"""
    bookmark = Bookmark.query.get_or_404(bookmark_id)
    db.session.delete(bookmark)
    db.session.commit()
    return jsonify({'success': True})


def register_search_routes(app):
    """Register search blueprint"""
    app.register_blueprint(search_bp)
    print("✓ Search & Bookmark routes registered")
