"""
Docker Routes for ShadowHack Platform
Phase 15: Docker Labs Integration
"""

from flask import Blueprint, request, jsonify
from models import db, Lab, User
from docker_lab_manager import DockerLabManager
import threading

docker_bp = Blueprint('docker', __name__, url_prefix='/api/labs')

# Initialize Lab Manager
lab_manager = DockerLabManager()

@docker_bp.route('/<int:lab_id>/start', methods=['POST'])
def start_lab(lab_id):
    """Start a Docker lab container"""
    lab = Lab.query.get_or_404(lab_id)
    user_id = request.json.get('user_id') # In real app, get from session
    
    if not lab.docker_image_id:
        return jsonify({'success': False, 'error': 'No Docker configuration for this lab'}), 400
        
    result = lab_manager.spawn_lab(
        user_id=user_id,
        lab_id=lab_id,
        image_name=lab.docker_image_id,
        duration_minutes=lab.time_limit_minutes
    )
    
    if result:
        return jsonify({
            'success': True,
            'connection': result
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to start lab container'}), 500

@docker_bp.route('/<int:lab_id>/stop', methods=['POST'])
def stop_lab(lab_id):
    """Stop a running lab container"""
    user_id = request.json.get('user_id')
    
    success = lab_manager.destroy_lab(user_id, lab_id)
    
    return jsonify({
        'success': success,
        'message': 'Lab terminated' if success else 'Failed to stop lab (or not running)'
    })

@docker_bp.route('/<int:lab_id>/status', methods=['GET'])
def check_status(lab_id):
    """Check lab status for user"""
    user_id = request.args.get('user_id', type=int)
    
    status = lab_manager.get_lab_status(user_id, lab_id)
    
    return jsonify({
        'success': True,
        'status': status
    })

@docker_bp.route('/<int:lab_id>/submit', methods=['POST'])
def submit_flag(lab_id):
    """Submit a flag for validation"""
    lab = Lab.query.get_or_404(lab_id)
    submitted_flag = request.json.get('flag')
    user_id = request.json.get('user_id')
    
    if lab.verify_flag(submitted_flag):
        # Update user progress, XP, etc. (Simplified)
        return jsonify({
            'success': True, 
            'message': 'Flag captured!', 
            'xp_earned': lab.xp_reward
        })
    else:
        return jsonify({'success': False, 'message': 'Incorrect flag'}), 200


def register_docker_routes(app):
    """Register docker blueprint"""
    app.register_blueprint(docker_bp)
    print("✓ Docker Lab routes registered")
