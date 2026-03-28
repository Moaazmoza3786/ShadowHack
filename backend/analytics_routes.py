"""
Analytics Routes for ShadowHack Platform
Phase 9: Advanced Analytics & Skill Certification
"""

import logging
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request  # type: ignore

from models import (
    CareerPath,
    Domain,
    Lab,
    LabSubmission,
    Module,
    QuizAttempt,
    User,
    UserAchievement,
    UserProgress,
    db,
)
from sqlalchemy import func  # type: ignore


logger = logging.getLogger(__name__)

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


@analytics_bp.route("/user/<int:user_id>/overview", methods=["GET"])
def get_user_overview(user_id):
    """Get comprehensive user analytics overview"""
    user = User.query.get_or_404(user_id)

    # Lab stats
    total_labs = LabSubmission.query.filter_by(user_id=user_id).count()
    completed_labs = LabSubmission.query.filter_by(
        user_id=user_id, is_correct=True
    ).count()

    # Calculate average solve time
    avg_solve_time = (
        db.session.query(func.avg(LabSubmission.time_to_solve_seconds))
        .filter_by(user_id=user_id, is_correct=True)
        .scalar()
        or 0
    )

    # Achievements
    achievements_count = UserAchievement.query.filter_by(user_id=user_id).count()

    # Learning progress
    modules_completed = UserProgress.query.filter_by(
        user_id=user_id, is_completed=True
    ).count()

    # Quiz stats
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user_id).count()
    quiz_passed = QuizAttempt.query.filter_by(user_id=user_id, passed=True).count()

    return jsonify(
        {
            "success": True,
            "overview": {
                "xp_total": user.xp_points,
                "level": user.level,
                "rank": user.current_rank,
                "streak_days": user.streak_days,
                "labs": {
                    "total_attempts": total_labs,
                    "completed": completed_labs,
                    "success_rate": round(
                        (completed_labs / total_labs * 100) if total_labs > 0 else 0, 1
                    ),
                    "avg_solve_time_minutes": round(avg_solve_time / 60, 1)
                    if avg_solve_time
                    else 0,
                },
                "learning": {
                    "modules_completed": modules_completed,
                    "quizzes_attempted": quiz_attempts,
                    "quizzes_passed": quiz_passed,
                },
                "achievements_count": achievements_count,
            },
        }
    )


@analytics_bp.route("/user/<int:user_id>/activity", methods=["GET"])
def get_user_activity(user_id):
    """Get user activity heatmap data (last 90 days)"""
    days = int(request.args.get("days", 90))
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get lab activity by day
    lab_activity = (
        db.session.query(
            func.date(LabSubmission.attempt_time).label("date"),
            func.count(LabSubmission.id).label("count"),
        )
        .filter(
            LabSubmission.user_id == user_id, LabSubmission.attempt_time >= start_date
        )
        .group_by(func.date(LabSubmission.attempt_time))
        .all()
    )

    # Format for heatmap
    activity_map = {str(a.date): a.count for a in lab_activity}

    return jsonify({"success": True, "activity": activity_map, "period_days": days})


@analytics_bp.route("/user/<int:user_id>/skills", methods=["GET"])
def get_user_skills(user_id):
    """Get user skill breakdown by domain category via DB join.

    Joins: LabSubmission -> Lab -> Module -> CareerPath -> Domain
    so that each solved lab is attributed to its parent domain (Red Team,
    Blue Team, CTF Arena, etc.).
    """
    try:
        # Join all the way up to Domain to get the category name
        rows = (
            db.session.query(
                Domain.name.label("domain_name"),
                Domain.color.label("domain_color"),
                Domain.icon.label("domain_icon"),
                func.count(LabSubmission.id).label("attempts"),
                func.sum(db.case((LabSubmission.is_correct == True, 1), else_=0)).label(
                    "solved"
                ),
                func.sum(
                    db.case((LabSubmission.is_correct == True, Lab.xp_reward), else_=0)
                ).label("xp_earned"),
            )
            .join(Lab, LabSubmission.lab_id == Lab.id)
            .join(Module, Lab.module_id == Module.id)
            .join(CareerPath, Module.career_path_id == CareerPath.id)
            .join(Domain, CareerPath.domain_id == Domain.id)
            .filter(LabSubmission.user_id == user_id)
            .group_by(Domain.id, Domain.name, Domain.color, Domain.icon)
            .all()
        )

        skills = [
            {
                "name": row.domain_name,
                "color": row.domain_color,
                "icon": row.domain_icon,
                "attempts": row.attempts,
                "completed": int(row.solved or 0),
                "xp": int(row.xp_earned or 0),
                "success_rate": round(
                    (int(row.solved or 0) / row.attempts * 100)
                    if row.attempts > 0
                    else 0,
                    1,
                ),
            }
            for row in rows
        ]

        # If the user has no submissions yet, return all domains with zero stats
        if not skills:
            all_domains = (
                Domain.query.filter_by(is_active=True)
                .order_by(Domain.order_index)
                .all()
            )
            skills = [
                {
                    "name": d.name,
                    "color": d.color,
                    "icon": d.icon,
                    "attempts": 0,
                    "completed": 0,
                    "xp": 0,
                    "success_rate": 0.0,
                }
                for d in all_domains
            ]

        return jsonify({"success": True, "skills": skills})

    except Exception as e:
        logger.error("Error fetching skills for user %s: %s", user_id, e, exc_info=True)
        return jsonify({"success": False, "error": "Could not load skill data."}), 500


@analytics_bp.route("/user/<int:user_id>/xp-history", methods=["GET"])
def get_xp_history(user_id):
    """Get XP earned over time"""
    days = int(request.args.get("days", 30))
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get XP gains from lab completions
    xp_data = (
        db.session.query(
            func.date(LabSubmission.attempt_time).label("date"),
            func.sum(50).label("xp"),  # Assuming 50 XP per correct lab
        )
        .filter(
            LabSubmission.user_id == user_id,
            LabSubmission.is_correct == True,
            LabSubmission.attempt_time >= start_date,
        )
        .group_by(func.date(LabSubmission.attempt_time))
        .all()
    )

    history = [{"date": str(x.date), "xp": x.xp} for x in xp_data]

    return jsonify({"success": True, "xp_history": history, "period_days": days})


@analytics_bp.route("/leaderboard", methods=["GET"])
def get_leaderboard():
    """Get global leaderboard"""
    limit = int(request.args.get("limit", 25))
    period = request.args.get("period", "all")  # all, weekly, monthly

    query = User.query.filter(User.is_active == True)

    if period == "weekly":
        query = query.order_by(User.weekly_xp.desc())
    else:
        query = query.order_by(User.xp_points.desc())

    users = query.limit(limit).all()

    leaderboard = [
        {
            "rank": i + 1,
            "user_id": u.id,
            "username": u.username,
            "avatar_url": u.avatar_url,
            "xp": u.weekly_xp if period == "weekly" else u.xp_points,
            "level": u.level,
            "rank_title": u.current_rank,
        }
        for i, u in enumerate(users)
    ]

    return jsonify({"success": True, "leaderboard": leaderboard, "period": period})


# ==================== ADVANCED ML-POWERED ANALYTICS ====================

@analytics_bp.route("/user/<int:user_id>/skill-analysis", methods=["GET"])
def get_skill_analysis(user_id):
    """Get advanced skill analysis with gaps and strengths"""
    try:
        from advanced_analytics_engine import analytics_engine
        import numpy as np
        
        user = User.query.get_or_404(user_id)
        
        # Build user progress data
        user_progress = {
            'web-security_labs_completed': LabSubmission.query.filter_by(user_id=user_id).count(),
            'web-security_hours': 40,
        }
        
        # Get peer data
        peer_profiles = []
        for p in User.query.limit(100).all():
            if p.id != user_id:
                peer_profiles.append({
                    'id': p.id,
                    'username': p.username,
                    'xp_points': p.xp_points,
                    'level': p.level,
                    'labs_completed': LabSubmission.query.filter_by(user_id=p.id).count()
                })
        
        user_profile = {
            'id': user_id,
            'xp_points': user.xp_points,
            'level': user.level,
        }
        
        report = analytics_engine.generate_comprehensive_report(
            user_profile=user_profile,
            user_progress=user_progress,
            peer_profiles=peer_profiles
        )
        
        return jsonify({
            'success': True,
            'analysis': report
        }), 200
    
    except Exception as e:
        logger.error(f"Error in skill analysis: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@analytics_bp.route("/user/<int:user_id>/learning-prediction", methods=["GET"])
def get_learning_prediction(user_id):
    """Get predictive learning curve"""
    try:
        from advanced_analytics_engine import PredictiveLearningModel
        
        user = User.query.get_or_404(user_id)
        model = PredictiveLearningModel()
        
        domains = ['web-security', 'networks', 'crypto', 'forensics']
        predictions = {}
        
        current_level_score = user.level * 10
        
        for domain in domains:
            time_to_competency = model.predict_time_to_competency(
                current_score=min(current_level_score, 80),
                domain=domain
            )
            
            completion_pred = model.predict_completion_date(10, time_to_competency)
            success_prob = model.predict_success_rate({
                'streak_days': user.streak_days or 0,
                'weekly_xp': user.weekly_xp or 0,
                'level': user.level
            })
            
            predictions[domain] = {
                'hours_to_competency': time_to_competency,
                'estimated_completion': completion_pred,
                'success_probability': round(success_prob * 100, 1),
                'recommended_pace': model.recommend_learning_pace({'level': user.level}, 10)
            }
        
        return jsonify({
            'success': True,
            'predictions': predictions,
            'current_level': user.level
        }), 200
    
    except Exception as e:
        logger.error(f"Error in learning prediction: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@analytics_bp.route("/user/<int:user_id>/peer-comparison", methods=["GET"])
def get_peer_comparison(user_id):
    """Compare user to peers"""
    try:
        from advanced_analytics_engine import PeerComparison
        
        user = User.query.get_or_404(user_id)
        comparison = PeerComparison()
        
        peer_profiles = []
        for u in User.query.all():
            if u.id != user_id:
                peer_profiles.append({
                    'id': u.id,
                    'username': u.username,
                    'xp_points': u.xp_points,
                    'level': u.level,
                    'labs_completed': LabSubmission.query.filter_by(user_id=u.id).count()
                })
        
        user_profile = {
            'id': user_id,
            'username': user.username,
            'xp_points': user.xp_points,
            'level': user.level,
            'labs_completed': LabSubmission.query.filter_by(user_id=user_id).count()
        }
        
        peer_comparison_data = comparison.compare_to_peers(user_profile, peer_profiles)
        similar_peers = comparison.identify_learning_style_peers(user_profile, peer_profiles)
        
        return jsonify({
            'success': True,
            'comparison': peer_comparison_data,
            'similar_peers': similar_peers
        }), 200
    
    except Exception as e:
        logger.error(f"Error in peer comparison: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@analytics_bp.route("/leaderboard/stats", methods=["GET"])
def get_leaderboard_statistics():
    """Get leaderboard statistics"""
    try:
        import numpy as np
        from collections import Counter
        
        all_users = User.query.all()
        xp_points = [u.xp_points for u in all_users]
        levels = [u.level for u in all_users]
        
        if not xp_points:
            return jsonify({'success': False, 'error': 'No users'}), 404
        
        level_distribution = Counter(levels)
        
        stats = {
            'total_users': len(all_users),
            'xp_statistics': {
                'mean': int(sum(xp_points) / len(xp_points)),
                'median': int(np.median(xp_points)),
                'max': max(xp_points),
                'min': min(xp_points),
                'total_distributed': sum(xp_points)
            },
            'level_distribution': dict(level_distribution),
            'activity': {
                'active_users': sum(1 for u in all_users if u.weekly_xp > 100),
                'average_weekly_xp': int(sum(u.weekly_xp or 0 for u in all_users) / len(all_users))
            }
        }
        
        return jsonify({'success': True, 'statistics': stats}), 200
    
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


def register_analytics_routes(app):
    """Register analytics blueprint"""
    app.register_blueprint(analytics_bp)
    print("[OK] Analytics API routes registered")
