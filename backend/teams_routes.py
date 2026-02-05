"""
Team and Mission Routes for ShadowHack Platform
Phase 8: Collaborative play and gamified missions
"""

from flask import Blueprint, request, jsonify
from models import db, Team, TeamMember, Mission, UserMissionProgress, User
from datetime import datetime
import secrets

teams_bp = Blueprint('teams', __name__, url_prefix='/api/teams')
missions_bp = Blueprint('missions', __name__, url_prefix='/api/missions')


# ==================== TEAM ROUTES ====================

@teams_bp.route('/', methods=['GET'])
def list_teams():
    """List all public teams"""
    teams = Team.query.filter_by(is_public=True).order_by(Team.total_xp.desc()).limit(50).all()
    return jsonify({'success': True, 'teams': [t.to_dict() for t in teams]})


@teams_bp.route('/', methods=['POST'])
def create_team():
    """Create a new team"""
    data = request.json
    user_id = data.get('user_id')
    name = data.get('name')
    tag = data.get('tag')
    
    if not all([user_id, name, tag]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    # Check if user exists
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    # Check if team name or tag already exists
    if Team.query.filter_by(name=name).first():
        return jsonify({'success': False, 'error': 'Team name already taken'}), 400
    if Team.query.filter_by(tag=tag).first():
        return jsonify({'success': False, 'error': 'Team tag already taken'}), 400
    
    team = Team(
        name=name,
        tag=tag,
        description=data.get('description', ''),
        owner_id=user_id,
        invite_code=secrets.token_urlsafe(8)
    )
    db.session.add(team)
    db.session.flush()
    
    # Add owner as first member
    member = TeamMember(team_id=team.id, user_id=user_id, role='owner')
    db.session.add(member)
    db.session.commit()
    
    return jsonify({'success': True, 'team': team.to_dict()}), 201


@teams_bp.route('/<int:team_id>', methods=['GET'])
def get_team(team_id):
    """Get team details"""
    team = Team.query.get_or_404(team_id)
    members = [{'user_id': m.user_id, 'role': m.role, 'contribution_xp': m.contribution_xp, 'username': m.user.username} for m in team.members]
    result = team.to_dict()
    result['members'] = members
    return jsonify({'success': True, 'team': result})


@teams_bp.route('/<int:team_id>/join', methods=['POST'])
def join_team(team_id):
    """Join a team via invite code or public join"""
    data = request.json
    user_id = data.get('user_id')
    invite_code = data.get('invite_code')
    
    team = Team.query.get_or_404(team_id)
    
    # Check if already a member
    if TeamMember.query.filter_by(team_id=team_id, user_id=user_id).first():
        return jsonify({'success': False, 'error': 'Already a member'}), 400
    
    # Public team or valid invite code
    if not team.is_public and team.invite_code != invite_code:
        return jsonify({'success': False, 'error': 'Invalid invite code'}), 403
    
    member = TeamMember(team_id=team_id, user_id=user_id, role='member')
    db.session.add(member)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Joined team {team.name}'})


@teams_bp.route('/<int:team_id>/leave', methods=['POST'])
def leave_team(team_id):
    """Leave a team"""
    data = request.json
    user_id = data.get('user_id')
    
    member = TeamMember.query.filter_by(team_id=team_id, user_id=user_id).first()
    if not member:
        return jsonify({'success': False, 'error': 'Not a member'}), 404
    
    if member.role == 'owner':
        return jsonify({'success': False, 'error': 'Owner cannot leave. Transfer ownership first.'}), 400
    
    db.session.delete(member)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Left team'})


@teams_bp.route('/leaderboard', methods=['GET'])
def team_leaderboard():
    """Get team leaderboard"""
    teams = Team.query.order_by(Team.total_xp.desc()).limit(20).all()
    return jsonify({'success': True, 'leaderboard': [
        {'rank': i+1, **t.to_dict()} for i, t in enumerate(teams)
    ]})


# ==================== MISSION ROUTES ====================

@missions_bp.route('/active', methods=['GET'])
def get_active_missions():
    """Get all active missions"""
    now = datetime.utcnow()
    missions = Mission.query.filter(
        Mission.is_active == True,
        Mission.starts_at <= now,
        (Mission.expires_at == None) | (Mission.expires_at > now)
    ).all()
    return jsonify({'success': True, 'missions': [m.to_dict() for m in missions]})


@missions_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user_missions(user_id):
    """Get missions with user progress"""
    now = datetime.utcnow()
    missions = Mission.query.filter(
        Mission.is_active == True,
        Mission.starts_at <= now,
        (Mission.expires_at == None) | (Mission.expires_at > now)
    ).all()
    
    result = []
    for mission in missions:
        progress = UserMissionProgress.query.filter_by(user_id=user_id, mission_id=mission.id).first()
        mission_data = mission.to_dict()
        mission_data['user_progress'] = progress.current_progress if progress else 0
        mission_data['is_completed'] = progress.is_completed if progress else False
        result.append(mission_data)
    
    return jsonify({'success': True, 'missions': result})


@missions_bp.route('/progress', methods=['POST'])
def update_mission_progress():
    """Update user progress on a mission"""
    data = request.json
    user_id = data.get('user_id')
    mission_id = data.get('mission_id')
    increment = data.get('increment', 1)
    
    mission = Mission.query.get_or_404(mission_id)
    progress = UserMissionProgress.query.filter_by(user_id=user_id, mission_id=mission_id).first()
    
    if not progress:
        progress = UserMissionProgress(user_id=user_id, mission_id=mission_id, current_progress=0)
        db.session.add(progress)
    
    if progress.is_completed:
        return jsonify({'success': True, 'message': 'Mission already completed'})
    
    progress.current_progress += increment
    
    # Check if completed
    if progress.current_progress >= mission.objective_target:
        progress.is_completed = True
        progress.completed_at = datetime.utcnow()
        
        # Award XP
        user = User.query.get(user_id)
        if user:
            user.add_xp(mission.xp_reward)
    
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'progress': progress.current_progress, 
        'target': mission.objective_target,
        'is_completed': progress.is_completed
    })


def register_team_routes(app):
    """Register team and mission blueprints"""
    app.register_blueprint(teams_bp)
    app.register_blueprint(missions_bp)
    print("✓ Team & Mission API routes registered")
