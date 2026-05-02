"""
Recommendation Engine Backend
Analyzes user behavior and generates personalized content recommendations
"""

from flask import Blueprint, request, jsonify
from models import db, User, LabSubmission, Quiz, UserProgress, Lab, Course
from datetime import datetime, timedelta
from sqlalchemy import func
import math

recommendations_bp = Blueprint('recommendations', __name__, url_prefix='/api/recommendations')


class RecommendationEngine:
    """ML-based recommendation system for personalized content"""

    @staticmethod
    def analyze_user_profile(user_id):
        """Analyze user's learning profile"""
        user = User.query.get(user_id)
        if not user:
            return None

        # Get completed labs
        completed_labs = LabSubmission.query.filter_by(user_id=user_id, correct=True).all()
        failed_labs = LabSubmission.query.filter_by(user_id=user_id, correct=False).all()

        # Get quiz attempts
        quiz_attempts = Quiz.query.filter_by(user_id=user_id).all()

        # Calculate stats
        avg_completion_time = 0
        if completed_labs:
            times = [
                (s.completed_at - s.created_at).total_seconds()
                for s in completed_labs
                if s.completed_at
            ]
            avg_completion_time = sum(times) / len(times) if times else 0

        # Identify preferred categories
        category_scores = {}
        for lab_sub in completed_labs:
            lab = Lab.query.get(lab_sub.lab_id)
            if lab:
                category = lab.category
                category_scores[category] = category_scores.get(category, 0) + 10

        for lab_sub in failed_labs:
            lab = Lab.query.get(lab_sub.lab_id)
            if lab:
                category = lab.category
                category_scores[category] = category_scores.get(category, 0) - 3

        preferred_categories = sorted(
            category_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # Calculate engagement score
        engagement_score = min(
            100,
            len(completed_labs) * 5 + user.points / 100
        )

        profile = {
            'user_id': user_id,
            'level': user.level,
            'total_xp': user.points,
            'completed_labs': len(completed_labs),
            'failed_attempts': len(failed_labs),
            'avg_completion_time': avg_completion_time,
            'preferred_categories': [cat[0] for cat in preferred_categories],
            'engagement_score': engagement_score,
            'streak_days': user.daily_streak or 0,
        }

        return profile

    @staticmethod
    def identify_skill_gaps(user_id):
        """Identify areas where user needs improvement"""
        user = User.query.get(user_id)
        failed_labs = LabSubmission.query.filter_by(
            user_id=user_id,
            correct=False
        ).all()

        skill_gaps = {}
        for failure in failed_labs:
            lab = Lab.query.get(failure.lab_id)
            if lab:
                category = lab.category
                difficulty = lab.difficulty
                key = f"{category}_{difficulty}"
                skill_gaps[key] = skill_gaps.get(key, 0) + 1

        # Sort by frequency (most problematic areas first)
        sorted_gaps = sorted(
            skill_gaps.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {
                'skill': gap[0],
                'gap_score': gap[1],
                'recommendation_type': 'skill_improvement'
            }
            for gap in sorted_gaps[:5]
        ]

    @staticmethod
    def get_recommended_labs(user_id, limit=10):
        """Get recommended labs based on user profile"""
        profile = RecommendationEngine.analyze_user_profile(user_id)
        if not profile:
            return []

        skill_gaps = RecommendationEngine.identify_skill_gaps(user_id)

        # Find labs matching user's weak areas
        recommendations = []

        # 1. Labs to fill skill gaps
        for gap in skill_gaps:
            gap_parts = gap['skill'].split('_')
            if len(gap_parts) == 2:
                category, difficulty = gap_parts
                # Find medium difficulty labs in this category
                labs = Lab.query.filter(
                    Lab.category == category,
                    Lab.difficulty.in_(['Easy', 'Medium']),
                    Lab.id.notin_([
                        s.lab_id for s in LabSubmission.query.filter_by(
                            user_id=user_id
                        ).all()
                    ])
                ).limit(3).all()
                recommendations.extend(labs)

        # 2. Next difficulty progression
        next_difficulty = 'Medium' if profile['level'] < 3 else 'Hard'
        progression_labs = Lab.query.filter(
            Lab.difficulty == next_difficulty,
            Lab.category.in_(profile['preferred_categories']),
            Lab.id.notin_([
                s.lab_id for s in LabSubmission.query.filter_by(
                    user_id=user_id
                ).all()
            ])
        ).limit(3).all()
        recommendations.extend(progression_labs)

        # 3. Popular labs
        popular_labs = db.session.query(Lab).join(
            LabSubmission
        ).group_by(Lab.id).order_by(
            func.count(LabSubmission.id).desc()
        ).limit(3).all()
        recommendations.extend(popular_labs)

        # Remove duplicates
        seen = set()
        unique_recommendations = []
        for lab in recommendations:
            if lab.id not in seen:
                seen.add(lab.id)
                unique_recommendations.append({
                    'id': lab.id,
                    'name': lab.name,
                    'category': lab.category,
                    'difficulty': lab.difficulty,
                    'xp_reward': lab.xp_reward or 100,
                    'description': lab.description,
                    'reason': 'Based on your learning profile'
                })

        return unique_recommendations[:limit]

    @staticmethod
    def get_recommended_courses(user_id, limit=10):
        """Get recommended courses"""
        profile = RecommendationEngine.analyze_user_profile(user_id)
        if not profile:
            return []

        courses = Course.query.filter(
            Course.category.in_(profile['preferred_categories'])
        ).limit(limit).all()

        return [
            {
                'id': course.id,
                'name': course.name,
                'category': course.category,
                'description': course.description,
                'estimated_hours': course.estimated_hours or 10,
                'reason': 'Matches your interests'
            }
            for course in courses
        ]

    @staticmethod
    def get_personalized_learning_path(user_id):
        """Generate a personalized learning path"""
        profile = RecommendationEngine.analyze_user_profile(user_id)
        if not profile:
            return None

        path_labs = RecommendationEngine.get_recommended_labs(user_id, limit=20)

        return {
            'user_id': user_id,
            'profile': profile,
            'recommended_labs': path_labs,
            'estimated_duration_days': len(path_labs) * 3,  # Assume 3 days per lab
            'difficulty_progression': [
                'Easy', 'Easy', 'Medium', 'Medium', 'Medium',
                'Hard', 'Hard', 'Insane'
            ][:len(path_labs)],
            'generated_at': datetime.utcnow().isoformat()
        }


# Routes

@recommendations_bp.route('/user/<int:user_id>', methods=['GET'])
def get_user_recommendations(user_id):
    """Get personalized recommendations for a user"""
    limit = request.args.get('limit', 10, type=int)

    try:
        recommendations = RecommendationEngine.get_recommended_labs(user_id, limit)
        return jsonify({
            'success': True,
            'recommendations': recommendations
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@recommendations_bp.route('/user/<int:user_id>/profile', methods=['GET'])
def get_user_profile(user_id):
    """Get user's analyzed profile"""
    try:
        profile = RecommendationEngine.analyze_user_profile(user_id)
        return jsonify({
            'success': True,
            'profile': profile
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@recommendations_bp.route('/user/<int:user_id>/path', methods=['GET'])
def get_learning_path(user_id):
    """Get personalized learning path"""
    try:
        path = RecommendationEngine.get_personalized_learning_path(user_id)
        return jsonify({
            'success': True,
            'path': path
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@recommendations_bp.route('/user/<int:user_id>/courses', methods=['GET'])
def get_course_recommendations(user_id):
    """Get recommended courses"""
    limit = request.args.get('limit', 10, type=int)

    try:
        courses = RecommendationEngine.get_recommended_courses(user_id, limit)
        return jsonify({
            'success': True,
            'courses': courses
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@recommendations_bp.route('/user/<int:user_id>/gaps', methods=['GET'])
def get_skill_gaps(user_id):
    """Identify skill gaps for improvement"""
    try:
        gaps = RecommendationEngine.identify_skill_gaps(user_id)
        return jsonify({
            'success': True,
            'skill_gaps': gaps
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
