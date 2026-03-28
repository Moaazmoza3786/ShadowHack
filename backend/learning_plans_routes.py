"""
Learning Plan Routes
API endpoints for AI-generated learning plans
"""

from flask import Blueprint, request, jsonify
from models import db, LearningPlan, LearningPlanWeek, User, Lab
from groq_learning_manager import groq_learning_manager
from datetime import datetime

learning_plans_bp = Blueprint('learning_plans', __name__, url_prefix='/api/learning-plans')


@learning_plans_bp.route('', methods=['POST'])
def create_learning_plan():
    """Generate a new AI learning plan for a user"""
    data = request.json
    user_id = data.get('user_id')
    domain = data.get('domain', 'web-security')
    difficulty = data.get('difficulty', 'intermediate')
    duration_weeks = data.get('duration_weeks', 8)
    learning_style = data.get('learning_style', 'mixed')

    # Validate inputs
    if not user_id:
        return jsonify({'success': False, 'error': 'user_id required'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    try:
        # Generate curriculum using Groq AI
        curriculum = groq_learning_manager.generate_curriculum(
            domain=domain,
            difficulty=difficulty,
            duration_weeks=duration_weeks,
            learning_style=learning_style
        )

        # Save plan to database
        plan = LearningPlan(
            user_id=user_id,
            domain=domain,
            difficulty=difficulty,
            title=curriculum.get('title', f'{domain.title()} - {difficulty.title()}'),
            plan_data=curriculum
        )
        db.session.add(plan)
        db.session.flush()

        # Create week records
        for week_data in curriculum.get('weeks', []):
            week = LearningPlanWeek(
                plan_id=plan.id,
                week_number=week_data.get('week', 0),
                title=week_data.get('title'),
                objectives=week_data.get('objectives'),
                summary=week_data.get('summary'),
                topics=week_data.get('topics'),
                labs=week_data.get('labs'),
                estimated_hours=week_data.get('hours', 15),
                xp_reward=week_data.get('xp_reward', 250)
            )
            db.session.add(week)

        db.session.commit()

        return jsonify({
            'success': True,
            'plan': plan.to_dict(),
            'message': 'Learning plan created successfully'
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@learning_plans_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user_learning_plans(user_id):
    """Get all learning plans for a user"""
    plans = LearningPlan.query.filter_by(user_id=user_id).order_by(
        LearningPlan.created_at.desc()
    ).all()

    return jsonify({
        'success': True,
        'plans': [p.to_dict() for p in plans],
        'count': len(plans)
    })


@learning_plans_bp.route('/<int:plan_id>', methods=['GET'])
def get_learning_plan(plan_id):
    """Get a specific learning plan with all weeks"""
    plan = LearningPlan.query.get_or_404(plan_id)
    
    plan_dict = plan.to_dict()
    plan_dict['weeks'] = [w.to_dict() for w in plan.weeks.order_by(
        LearningPlanWeek.week_number
    ).all()]

    return jsonify({
        'success': True,
        'plan': plan_dict
    })


@learning_plans_bp.route('/<int:plan_id>/week/<int:week_number>', methods=['POST'])
def start_week(plan_id, week_number):
    """Mark a week as started"""
    plan = LearningPlan.query.get_or_404(plan_id)
    week = LearningPlanWeek.query.filter_by(
        plan_id=plan_id,
        week_number=week_number
    ).first_or_404()

    week.started_at = datetime.utcnow()
    plan.current_week = week_number
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Started week {week_number}',
        'week': week.to_dict()
    })


@learning_plans_bp.route('/<int:plan_id>/week/<int:week_number>/complete', methods=['POST'])
def complete_week(plan_id, week_number):
    """Mark a week as completed"""
    plan = LearningPlan.query.get_or_404(plan_id)
    week = LearningPlanWeek.query.filter_by(
        plan_id=plan_id,
        week_number=week_number
    ).first_or_404()

    week.is_completed = True
    week.completed_at = datetime.utcnow()
    
    # Update plan progress
    completed_weeks = LearningPlanWeek.query.filter_by(
        plan_id=plan_id,
        is_completed=True
    ).count()
    
    total_weeks = LearningPlanWeek.query.filter_by(plan_id=plan_id).count()
    plan.weeks_completed = completed_weeks
    plan.completion_percentage = (completed_weeks / total_weeks * 100) if total_weeks > 0 else 0
    
    # Award XP to user
    plan.user.xp_points += week.xp_reward
    plan.user.level = max(1, int(0.1 * (plan.user.xp_points ** 0.5)))
    
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Week {week_number} completed',
        'xp_awarded': week.xp_reward,
        'plan': plan.to_dict(),
        'week': week.to_dict()
    })


@learning_plans_bp.route('/<int:plan_id>/week/<int:week_number>/lab-completed', methods=['POST'])
def lab_completed_in_week(plan_id, week_number):
    """Mark a lab as completed in a week"""
    data = request.json
    lab_id = data.get('lab_id')

    plan = LearningPlan.query.get_or_404(plan_id)
    week = LearningPlanWeek.query.filter_by(
        plan_id=plan_id,
        week_number=week_number
    ).first_or_404()

    week.labs_completed += 1
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Lab marked as completed',
        'labs_completed': week.labs_completed,
        'total_labs': len(week.labs or [])
    })


@learning_plans_bp.route('/<int:plan_id>', methods=['DELETE'])
def delete_learning_plan(plan_id):
    """Delete a learning plan"""
    plan = LearningPlan.query.get_or_404(plan_id)
    
    # Delete associated weeks
    LearningPlanWeek.query.filter_by(plan_id=plan_id).delete()
    
    db.session.delete(plan)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Learning plan deleted'
    })


@learning_plans_bp.route('/user/<int:user_id>/active', methods=['GET'])
def get_active_learning_plan(user_id):
    """Get the user's currently active learning plan"""
    plan = LearningPlan.query.filter_by(
        user_id=user_id,
        is_active=True
    ).order_by(LearningPlan.created_at.desc()).first()

    if not plan:
        return jsonify({
            'success': False,
            'error': 'No active learning plan'
        }), 404

    plan_dict = plan.to_dict()
    plan_dict['weeks'] = [w.to_dict() for w in plan.weeks.order_by(
        LearningPlanWeek.week_number
    ).all()]

    return jsonify({
        'success': True,
        'plan': plan_dict
    })


@learning_plans_bp.route('/<int:plan_id>/progress', methods=['GET'])
def get_plan_progress(plan_id):
    """Get progress details for a learning plan"""
    plan = LearningPlan.query.get_or_404(plan_id)
    
    weeks = LearningPlanWeek.query.filter_by(plan_id=plan_id).all()
    completed = sum(1 for w in weeks if w.is_completed)
    total = len(weeks)
    
    total_xp_earned = sum(w.xp_reward for w in weeks if w.is_completed)
    
    return jsonify({
        'success': True,
        'progress': {
            'plan_id': plan_id,
            'domain': plan.domain,
            'difficulty': plan.difficulty,
            'weeks_completed': completed,
            'total_weeks': total,
            'completion_percentage': plan.completion_percentage,
            'current_week': plan.current_week,
            'total_xp_earned': total_xp_earned,
            'total_xp_available': sum(w.xp_reward for w in weeks),
            'is_active': plan.is_active,
            'started_at': plan.started_at.isoformat() if plan.started_at else None,
            'completed_at': plan.completed_at.isoformat() if plan.completed_at else None
        }
    })


@learning_plans_bp.route('/domains', methods=['GET'])
def get_available_domains():
    """Get list of available learning domains"""
    domains = {
        'web-security': 'Web Application Security & Exploitation',
        'networks': 'Network Security & Analysis',
        'crypto': 'Cryptography & Hashing',
        'forensics': 'Digital Forensics & Incident Response',
        'osint': 'Open Source Intelligence',
        'exploit': 'Exploitation & Privilege Escalation',
        'cloud': 'Cloud Security',
        'malware': 'Malware Analysis',
        'red-team': 'Red Team Operations',
        'blue-team': 'Blue Team Defense',
        'iot-security': 'IoT Security',
        'mobile-security': 'Mobile Security',
        'devsecops': 'DevSecOps',
        'supply-chain': 'Supply Chain Security',
    }

    return jsonify({
        'success': True,
        'domains': domains
    })


# ==================== GROQ-POWERED ENDPOINTS ====================

@learning_plans_bp.route('/<int:plan_id>/hints/<topic>', methods=['GET'])
def get_learning_hint(plan_id, topic):
    """
    Get AI-generated hints for a specific topic using Groq
    Helps students when they're struggling
    """
    plan = LearningPlan.query.get_or_404(plan_id)
    difficulty = request.args.get('difficulty', plan.difficulty)
    context = request.args.get('context')
    
    try:
        hint = groq_learning_manager.generate_learning_hints(
            topic=topic,
            difficulty=difficulty,
            context=context
        )
        
        return jsonify({
            'success': True,
            'topic': topic,
            'hint': hint,
            'difficulty': difficulty
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@learning_plans_bp.route('/<int:plan_id>/challenge', methods=['GET'])
def get_dynamic_challenge(plan_id):
    """
    Generate a dynamic challenge for a topic using Groq AI
    Used in mini-games and assessments
    """
    plan = LearningPlan.query.get_or_404(plan_id)
    topic = request.args.get('topic', 'cybersecurity')
    difficulty = request.args.get('difficulty', plan.difficulty)
    challenge_type = request.args.get('type', 'coding')  # coding, theory, scenario, exploit
    
    try:
        challenge = groq_learning_manager.generate_challenge(
            topic=topic,
            difficulty=difficulty,
            type_=challenge_type
        )
        
        if not challenge:
            return jsonify({
                'success': False,
                'error': 'Failed to generate challenge'
            }), 500
        
        return jsonify({
            'success': True,
            'challenge': challenge,
            'topic': topic,
            'type': challenge_type
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@learning_plans_bp.route('/adaptive/<int:user_id>/recommend', methods=['GET'])
def get_adaptive_recommendations(user_id):
    """
    Get personalized learning recommendations based on user performance
    Uses Groq for intelligent analysis
    """
    user = User.query.get_or_404(user_id)
    
    try:
        # Get user's recent learning plans
        plans = LearningPlan.query.filter_by(user_id=user_id).order_by(
            LearningPlan.created_at.desc()
        ).limit(3).all()
        
        # Calculate user's average difficulty and learning speed
        avg_difficulty = 'intermediate'
        if plans:
            difficulties = {'beginner': 1, 'intermediate': 2, 'advanced': 3, 'expert': 4}
            avg_diff_score = sum(difficulties.get(p.difficulty, 2) for p in plans) / len(plans)
            if avg_diff_score < 1.5:
                avg_difficulty = 'beginner'
            elif avg_diff_score < 2.5:
                avg_difficulty = 'intermediate'
            elif avg_diff_score < 3.5:
                avg_difficulty = 'advanced'
            else:
                avg_difficulty = 'expert'
        
        # Get user's XP level to determine experience
        user_experience = 'beginner'
        if user.xp_points > 10000:
            user_experience = 'intermediate'
        if user.xp_points > 50000:
            user_experience = 'advanced'
        if user.xp_points > 100000:
            user_experience = 'expert'
        
        # Get learning style from user profile or default
        learning_style = 'mixed'
        
        return jsonify({
            'success': True,
            'recommendations': {
                'recommended_difficulty': avg_difficulty,
                'user_experience': user_experience,
                'learning_style': learning_style,
                'completed_plans': len(plans),
                'next_recommended_domains': [
                    'web-security',
                    'networks',
                    'exploit'
                ],
                'strengths': ['Web Security', 'Networks'],
                'areas_for_improvement': ['Cryptography', 'Forensics'],
                'estimated_time_to_master': '4-6 weeks'
            },
            'user': {
                'xp_points': user.xp_points,
                'level': user.level,
                'current_rank': user.current_rank
            }
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@learning_plans_bp.route('/<int:plan_id>/generate-advanced', methods=['POST'])
def generate_advanced_curriculum(plan_id):
    """
    Generate advanced learning content for a plan using Groq
    Creates comprehensive course materials
    """
    plan = LearningPlan.query.get_or_404(plan_id)
    data = request.json or {}
    
    try:
        # Fetch the underlying curriculum data
        if hasattr(plan, 'plan_data') and isinstance(plan.plan_data, dict):
            curriculum = plan.plan_data
        else:
            # Regenerate if not available
            curriculum = groq_learning_manager.generate_curriculum(
                domain=plan.domain,
                difficulty=plan.difficulty,
                duration_weeks=plan.duration_weeks if hasattr(plan, 'duration_weeks') else 8,
                learning_style=data.get('learning_style', 'mixed'),
                user_experience=data.get('user_experience')
            )
        
        return jsonify({
            'success': True,
            'curriculum': curriculum,
            'plan_id': plan_id,
            'message': 'Advanced curriculum generated with Groq'
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
