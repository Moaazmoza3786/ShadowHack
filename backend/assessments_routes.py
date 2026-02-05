"""
Skill Assessment Routes for ShadowHack Platform
Phase 9: Skill testing and certification
"""

from flask import Blueprint, request, jsonify
from models import db, User, UserAchievement, Achievement
from datetime import datetime
import secrets
import hashlib

assessments_bp = Blueprint('assessments', __name__, url_prefix='/api/assessments')

# Define skill assessments
ASSESSMENTS = {
    'web_exploitation': {
        'name': 'Web Exploitation',
        'questions': [
            {'id': 1, 'question': 'What HTTP header prevents clickjacking?', 'options': ['X-Frame-Options', 'Content-Type', 'Authorization', 'Cache-Control'], 'answer': 0},
            {'id': 2, 'question': 'Which attack exploits improper input validation in SQL queries?', 'options': ['XSS', 'CSRF', 'SQL Injection', 'SSRF'], 'answer': 2},
            {'id': 3, 'question': 'What does CORS stand for?', 'options': ['Cross-Origin Resource Sharing', 'Common Origin Response Standard', 'Cross-Object Request Sequence', 'Central Origin Response Schema'], 'answer': 0},
            {'id': 4, 'question': 'Which HTTP method is typically used for CSRF attacks?', 'options': ['GET', 'POST', 'OPTIONS', 'HEAD'], 'answer': 1},
            {'id': 5, 'question': 'What is the primary defense against XSS?', 'options': ['Encryption', 'Input validation and output encoding', 'Rate limiting', 'SSL/TLS'], 'answer': 1}
        ],
        'passing_score': 4,
        'xp_reward': 150,
        'badge_id': 'web_certified'
    },
    'network_security': {
        'name': 'Network Security',
        'questions': [
            {'id': 1, 'question': 'What port does HTTPS typically use?', 'options': ['80', '443', '22', '21'], 'answer': 1},
            {'id': 2, 'question': 'Which protocol is used for secure shell access?', 'options': ['Telnet', 'FTP', 'SSH', 'RDP'], 'answer': 2},
            {'id': 3, 'question': 'What does ARP stand for?', 'options': ['Address Resolution Protocol', 'Advanced Routing Protocol', 'Application Response Protocol', 'Authenticated Request Protocol'], 'answer': 0},
            {'id': 4, 'question': 'Which attack floods a target with traffic?', 'options': ['Phishing', 'DDoS', 'SQL Injection', 'Man-in-the-Middle'], 'answer': 1},
            {'id': 5, 'question': 'What layer of the OSI model does TCP operate on?', 'options': ['Network', 'Data Link', 'Transport', 'Application'], 'answer': 2}
        ],
        'passing_score': 4,
        'xp_reward': 150,
        'badge_id': 'network_certified'
    },
    'cryptography': {
        'name': 'Cryptography',
        'questions': [
            {'id': 1, 'question': 'Which is an asymmetric encryption algorithm?', 'options': ['AES', 'DES', 'RSA', '3DES'], 'answer': 2},
            {'id': 2, 'question': 'What is the output size of SHA-256?', 'options': ['128 bits', '256 bits', '512 bits', '1024 bits'], 'answer': 1},
            {'id': 3, 'question': 'What cryptographic concept ensures message integrity?', 'options': ['Encryption', 'Hashing', 'Obfuscation', 'Salting'], 'answer': 1},
            {'id': 4, 'question': 'Which is NOT a block cipher mode?', 'options': ['ECB', 'CBC', 'CTR', 'DSA'], 'answer': 3},
            {'id': 5, 'question': 'What protects against rainbow table attacks?', 'options': ['Longer passwords', 'Password salting', 'Symmetric encryption', 'Digital signatures'], 'answer': 1}
        ],
        'passing_score': 4,
        'xp_reward': 150,
        'badge_id': 'crypto_certified'
    }
}


@assessments_bp.route('/available', methods=['GET'])
def get_available_assessments():
    """Get list of available skill assessments"""
    assessments = [{
        'id': key,
        'name': data['name'],
        'question_count': len(data['questions']),
        'passing_score': data['passing_score'],
        'xp_reward': data['xp_reward']
    } for key, data in ASSESSMENTS.items()]
    
    return jsonify({'success': True, 'assessments': assessments})


@assessments_bp.route('/<assessment_id>/start', methods=['POST'])
def start_assessment(assessment_id):
    """Start an assessment session"""
    if assessment_id not in ASSESSMENTS:
        return jsonify({'success': False, 'error': 'Assessment not found'}), 404
    
    assessment = ASSESSMENTS[assessment_id]
    
    # Generate session token
    session_token = secrets.token_urlsafe(16)
    
    # Return questions without answers
    questions = [{
        'id': q['id'],
        'question': q['question'],
        'options': q['options']
    } for q in assessment['questions']]
    
    return jsonify({
        'success': True,
        'session_token': session_token,
        'assessment_name': assessment['name'],
        'questions': questions,
        'time_limit_minutes': 10
    })


@assessments_bp.route('/<assessment_id>/submit', methods=['POST'])
def submit_assessment(assessment_id):
    """Submit assessment answers and get results"""
    if assessment_id not in ASSESSMENTS:
        return jsonify({'success': False, 'error': 'Assessment not found'}), 404
    
    data = request.json
    user_id = data.get('user_id')
    answers = data.get('answers', {})  # {question_id: selected_index}
    
    assessment = ASSESSMENTS[assessment_id]
    
    # Grade the assessment
    correct = 0
    results = []
    for q in assessment['questions']:
        user_answer = answers.get(str(q['id']))
        is_correct = user_answer == q['answer']
        if is_correct:
            correct += 1
        results.append({
            'question_id': q['id'],
            'correct': is_correct,
            'correct_answer': q['answer']
        })
    
    passed = correct >= assessment['passing_score']
    score_percent = round((correct / len(assessment['questions'])) * 100)
    
    # Award XP and badge if passed
    if passed and user_id:
        user = User.query.get(user_id)
        if user:
            user.add_xp(assessment['xp_reward'])
            db.session.commit()
    
    return jsonify({
        'success': True,
        'passed': passed,
        'score': correct,
        'total': len(assessment['questions']),
        'score_percent': score_percent,
        'passing_score': assessment['passing_score'],
        'xp_awarded': assessment['xp_reward'] if passed else 0,
        'results': results
    })


def register_assessment_routes(app):
    """Register assessment blueprint"""
    app.register_blueprint(assessments_bp)
    print("✓ Skill Assessment routes registered")
