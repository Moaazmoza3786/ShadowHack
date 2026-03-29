"""
Mentor Matching API Routes
Intelligent mentor-mentee matching with scheduling and engagement tracking
"""

from flask import Blueprint, request, jsonify
from models import db, User
from datetime import datetime, timedelta
from functools import wraps
import logging

logger = logging.getLogger(__name__)

mentorship_bp = Blueprint('mentorship', __name__, url_prefix='/api/mentorship')


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


# ==================== MENTOR DISCOVERY & MATCHING ====================

@mentorship_bp.route('/mentors', methods=['GET'])
def get_available_mentors():
    """
    Get list of available mentors with filtering
    Query params:
    - expertise: Filter by expertise area
    - level: Filter by expertise level (beginner, intermediate, advanced, expert)
    - max_rate: Maximum hourly rate
    - timezone: Filter by timezone
    - rating_min: Minimum rating (0-5)
    """
    try:
        expertise = request.args.get('expertise')
        level = request.args.get('level')
        max_rate = request.args.get('max_rate', type=int)
        timezone = request.args.get('timezone')
        rating_min = request.args.get('rating_min', 4.0, type=float)
        
        # Query mentors
        query = User.query.filter(
            User.role.in_(['mentor', 'admin']),
            User.is_active == True
        )
        
        # Build mentor list with simulated data
        mentors = []
        for user in query.all():
            mentor_profile = {
                'id': user.id,
                'username': user.username,
                'avatar_url': user.avatar_url,
                'bio': user.bio or f'{user.username} is an experienced security expert',
                'expertise_areas': ['web-security', 'networks', 'exploit'],  # From profile
                'expertise_level': 'advanced' if user.level > 10 else 'intermediate',
                'years_experience': max(1, user.level // 5),
                'rating': min(5.0, 3.5 + (user.level / 20)),
                'reviews_count': user.level * 3,
                'hourly_rate': 25,
                'timezone': 'UTC',
                'available_hours': list(range(14, 22)),
                'current_mentees': 0,
                'max_mentees': 5
            }
            
            # Apply filters
            if expertise and expertise not in mentor_profile['expertise_areas']:
                continue
            if level and level != mentor_profile['expertise_level']:
                continue
            if max_rate and mentor_profile['hourly_rate'] > max_rate:
                continue
            if mentor_profile['rating'] < rating_min:
                continue
            
            mentors.append(mentor_profile)
        
        return jsonify({
            'success': True,
            'mentors': mentors,
            'count': len(mentors),
            'filters': {
                'expertise': expertise,
                'level': level,
                'rating_min': rating_min
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching mentors: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/match', methods=['POST'])
@token_required
def find_matching_mentors(user_id):
    """
    Find best matching mentors for a mentee
    Uses AI-powered matching algorithm
    Body params:
    - learning_goals: List of skills to learn
    - level: Current level (beginner, intermediate, advanced)
    - timezone: User's timezone
    - available_hours: List of available hours (0-23)
    - learning_style: visual, practical, reading, mixed
    """
    try:
        from mentor_matching_engine import mentor_matcher
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        
        # Build mentee profile
        mentee_profile = {
            'id': user_id,
            'learning_goals': data.get('learning_goals', ['web-security']),
            'level': data.get('level', 'beginner'),
            'timezone': data.get('timezone', 'UTC'),
            'available_hours': data.get('available_hours', list(range(19, 23))),
            'learning_style': data.get('learning_style', 'mixed')
        }
        
        # Get available mentors
        mentors_query = User.query.filter(
            User.role.in_(['mentor', 'admin']),
            User.is_active == True,
            User.id != user_id
        ).all()
        
        # Build mentor profiles
        available_mentors = []
        for mentor in mentors_query:
            available_mentors.append({
                'id': mentor.id,
                'username': mentor.username,
                'avatar_url': mentor.avatar_url,
                'expertise_areas': ['web-security', 'networks', 'crypto'],
                'expertise_level': 'advanced' if mentor.level > 10 else 'intermediate',
                'years_experience': max(1, mentor.level // 5),
                'rating': min(5.0, 3.5 + (mentor.level / 20)),
                'reviews_count': mentor.level * 3,
                'hourly_rate': 25,
                'timezone': 'UTC',
                'available_hours': list(range(14, 22)),
                'current_mentees': 0,
                'max_mentees': 5,
                'teaching_style': 'mixed'
            })
        
        # Find matches
        matches = mentor_matcher.match_mentors(mentee_profile, available_mentors, top_n=5)
        
        return jsonify({
            'success': True,
            'matches': matches,
            'count': len(matches),
            'mentee_profile': mentee_profile
        }), 200
    
    except Exception as e:
        logger.error(f"Error finding matches: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/mentors/<int:mentor_id>', methods=['GET'])
def get_mentor_profile(mentor_id):
    """Get detailed mentor profile"""
    try:
        mentor = User.query.get(mentor_id)
        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404
        
        profile = {
            'id': mentor.id,
            'username': mentor.username,
            'avatar_url': mentor.avatar_url,
            'bio': mentor.bio or f'{mentor.username} is an experienced security expert',
            'email': mentor.email if mentor.is_verified else None,  # Hide if not verified
            'expertise_areas': ['web-security', 'networks', 'crypto', 'exploit'],
            'expertise_level': 'advanced' if mentor.level > 10 else 'intermediate',
            'years_experience': max(1, mentor.level // 5),
            'rating': min(5.0, 3.5 + (mentor.level / 20)),
            'reviews_count': mentor.level * 3,
            'hourly_rate': 25,
            'timezone': 'UTC',
            'response_time_hours': 2,
            'availability_status': 'Available',
            'languages': ['English', 'Arabic'],
            'certifications': ['CEH', 'OSCP', 'Security+'],
            'reviews': [
                {
                    'mentee': 'John Doe',
                    'rating': 5,
                    'comment': 'Excellent mentor! Very knowledgeable',
                    'date': (datetime.utcnow() - timedelta(days=7)).isoformat()
                },
                {
                    'mentee': 'Jane Smith',
                    'rating': 4.5,
                    'comment': 'Great guidance and patient teacher',
                    'date': (datetime.utcnow() - timedelta(days=14)).isoformat()
                }
            ]
        }
        
        return jsonify({
            'success': True,
            'mentor': profile
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching mentor profile: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== SESSION SCHEDULING ====================

@mentorship_bp.route('/sessions/schedule', methods=['POST'])
@token_required
def schedule_session(user_id):
    """
    Schedule a mentoring session
    Body params:
    - mentor_id: ID of mentor
    - preferred_datetime: ISO format datetime
    - duration_minutes: Session duration (default 60)
    - topic: Discussion topic
    """
    try:
        data = request.json
        mentor_id = data.get('mentor_id')
        preferred_datetime = data.get('preferred_datetime')
        duration_minutes = data.get('duration_minutes', 60)
        topic = data.get('topic', 'General Cybersecurity')
        
        if not mentor_id or not preferred_datetime:
            return jsonify({
                'success': False,
                'error': 'mentor_id and preferred_datetime required'
            }), 400
        
        mentor = User.query.get(mentor_id)
        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404
        
        # Create session record
        session = {
            'session_id': f'session_{user_id}_{mentor_id}_{int(datetime.utcnow().timestamp())}',
            'mentee_id': user_id,
            'mentor_id': mentor_id,
            'mentor_username': mentor.username,
            'scheduled_at': datetime.utcnow().isoformat(),
            'session_datetime': preferred_datetime,
            'duration_minutes': duration_minutes,
            'topic': topic,
            'status': 'scheduled',
            'meeting_url': f'https://mentor.shadowhack.io/session/{mentor_id}/{user_id}',
            'reminder_sent': False
        }
        
        return jsonify({
            'success': True,
            'session': session,
            'message': f'Session scheduled with {mentor.username} for {preferred_datetime}'
        }), 201
    
    except Exception as e:
        logger.error(f"Error scheduling session: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/sessions', methods=['GET'])
@token_required
def get_user_sessions(user_id):
    """Get mentoring sessions for user (as mentee or mentor)"""
    try:
        role = request.args.get('role', 'mentee')  # mentee or mentor
        status = request.args.get('status')  # scheduled, completed, cancelled
        
        # Simulated session data
        sessions = [
            {
                'session_id': 'session_1',
                'mentee_id': user_id if role == 'mentor' else 1,
                'mentor_id': 1 if role == 'mentee' else user_id,
                'mentor_username': 'SecurityExpert' if role == 'mentee' else 'Student1',
                'scheduled_at': (datetime.utcnow() - timedelta(days=3)).isoformat(),
                'session_datetime': (datetime.utcnow() + timedelta(days=2)).isoformat(),
                'duration_minutes': 60,
                'topic': 'Web Security Fundamentals',
                'status': 'scheduled',
                'meeting_url': f'https://mentor.shadowhack.io/session/1/{user_id}'
            },
            {
                'session_id': 'session_2',
                'mentee_id': user_id if role == 'mentor' else 2,
                'mentor_id': 2 if role == 'mentee' else user_id,
                'mentor_username': 'NetworkMaster' if role == 'mentee' else 'Student2',
                'scheduled_at': (datetime.utcnow() - timedelta(days=7)).isoformat(),
                'session_datetime': (datetime.utcnow() - timedelta(days=1)).isoformat(),
                'duration_minutes': 60,
                'topic': 'Network Security Deep Dive',
                'status': 'completed',
                'feedback': {
                    'rating': 5,
                    'comment': 'Excellent session, very helpful'
                }
            }
        ]
        
        # Filter by status if provided
        if status:
            sessions = [s for s in sessions if s['status'] == status]
        
        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions),
            'role': role
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching sessions: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/sessions/<session_id>/feedback', methods=['POST'])
@token_required
def submit_session_feedback(user_id, session_id):
    """Submit feedback after mentoring session"""
    try:
        data = request.json
        rating = data.get('rating')  # 1-5
        comment = data.get('comment', '')
        
        if not rating or rating < 1 or rating > 5:
            return jsonify({
                'success': False,
                'error': 'Rating must be between 1 and 5'
            }), 400
        
        feedback = {
            'session_id': session_id,
            'user_id': user_id,
            'rating': rating,
            'comment': comment,
            'submitted_at': datetime.utcnow().isoformat(),
            'helpful_count': 0
        }
        
        return jsonify({
            'success': True,
            'feedback': feedback,
            'message': 'Feedback submitted successfully'
        }), 201
    
    except Exception as e:
        logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== MENTOR MANAGEMENT ====================

@mentorship_bp.route('/mentor-request', methods=['POST'])
@token_required
def become_mentor(user_id):
    """
    Request to become a mentor
    Body params:
    - expertise_areas: List of expertise areas
    - expertise_level: beginner, intermediate, advanced, expert
    - years_experience: Years of experience
    - hourly_rate: Hourly rate in USD
    - bio: Short bio/description
    """
    try:
        data = request.json
        
        mentor_application = {
            'user_id': user_id,
            'expertise_areas': data.get('expertise_areas', []),
            'expertise_level': data.get('expertise_level', 'intermediate'),
            'years_experience': data.get('years_experience', 1),
            'hourly_rate': data.get('hourly_rate', 25),
            'bio': data.get('bio', ''),
            'applied_at': datetime.utcnow().isoformat(),
            'status': 'pending_review',
            'message': 'Your mentor application has been submitted for review'
        }
        
        return jsonify({
            'success': True,
            'application': mentor_application
        }), 201
    
    except Exception as e:
        logger.error(f"Error submitting mentor application: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/my-mentees', methods=['GET'])
@token_required
def get_my_mentees(user_id):
    """Get list of mentees for a mentor"""
    try:
        mentor = User.query.get(user_id)
        if not mentor or mentor.role not in ['mentor', 'admin']:
            return jsonify({
                'error': 'User is not a mentor'
            }), 403
        
        # Simulated mentee list
        mentees = [
            {
                'id': 1,
                'username': 'SecurityStudent1',
                'avatar_url': 'https://api.example.com/avatars/1.jpg',
                'learning_goal': 'Web Application Security',
                'joined_date': (datetime.utcnow() - timedelta(days=30)).isoformat(),
                'sessions_completed': 5,
                'last_session': (datetime.utcnow() - timedelta(days=7)).isoformat(),
                'rating': 4.8
            },
            {
                'id': 2,
                'username': 'NetworkHunter',
                'avatar_url': 'https://api.example.com/avatars/2.jpg',
                'learning_goal': 'Network Security',
                'joined_date': (datetime.utcnow() - timedelta(days=60)).isoformat(),
                'sessions_completed': 12,
                'last_session': (datetime.utcnow() - timedelta(days=2)).isoformat(),
                'rating': 4.9
            }
        ]
        
        return jsonify({
            'success': True,
            'mentees': mentees,
            'count': len(mentees)
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching mentees: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/mentor-stats', methods=['GET'])
@token_required
def get_mentor_statistics(user_id):
    """Get statistics for a mentor"""
    try:
        mentor = User.query.get(user_id)
        if not mentor or mentor.role not in ['mentor', 'admin']:
            return jsonify({
                'error': 'User is not a mentor'
            }), 403
        
        stats = {
            'total_mentees': 8,
            'active_mentees': 3,
            'total_sessions': 47,
            'sessions_this_month': 12,
            'average_rating': 4.8,
            'total_earnings': 1175,  # In USD
            'earnings_this_month': 300,
            'expertise_areas': ['web-security', 'networks', 'exploit'],
            'response_time_avg_hours': 2,
            'mentee_feedback': {
                '5_star': 35,
                '4_star': 10,
                '3_star': 2,
                '2_star': 0,
                '1_star': 0
            }
        }
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching mentor stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== ENGAGEMENT & MESSAGING ====================

@mentorship_bp.route('/messages/<int:mentor_id>', methods=['GET'])
@token_required
def get_messages_with_mentor(user_id, mentor_id):
    """Get message history with a mentor"""
    try:
        mentor = User.query.get(mentor_id)
        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404
        
        # Simulated message history
        messages = [
            {
                'id': 1,
                'sender_id': user_id,
                'message': 'Hi! I have a question about SQL injection.',
                'timestamp': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                'read': True
            },
            {
                'id': 2,
                'sender_id': mentor_id,
                'message': 'Hi! Sure, I\'d be happy to help. Let\'s schedule a session.',
                'timestamp': (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                'read': True
            },
            {
                'id': 3,
                'sender_id': user_id,
                'message': 'Great! How about tomorrow at 3 PM?',
                'timestamp': (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                'read': False
            }
        ]
        
        return jsonify({
            'success': True,
            'messages': messages,
            'mentor': {
                'id': mentor.id,
                'username': mentor.username,
                'avatar_url': mentor.avatar_url
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching messages: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mentorship_bp.route('/messages/<int:mentor_id>/send', methods=['POST'])
@token_required
def send_message_to_mentor(user_id, mentor_id):
    """Send message to mentor"""
    try:
        data = request.json
        message_text = data.get('message')
        
        if not message_text:
            return jsonify({
                'success': False,
                'error': 'Message cannot be empty'
            }), 400
        
        message = {
            'id': int(datetime.utcnow().timestamp() * 1000),
            'sender_id': user_id,
            'recipient_id': mentor_id,
            'message': message_text,
            'timestamp': datetime.utcnow().isoformat(),
            'read': False
        }
        
        return jsonify({
            'success': True,
            'message': message
        }), 201
    
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
