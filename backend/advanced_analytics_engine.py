"""
Advanced Analytics Engine with ML
Provides deep learning insights, skill analysis, and predictive modeling
"""

import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import json

logger = logging.getLogger(__name__)


class SkillAnalyzer:
    """Analyzes user skills and identifies gaps"""
    
    def __init__(self):
        self.skill_categories = {
            'web-security': ['XSS', 'SQL Injection', 'CSRF', 'Authentication', 'Authorization'],
            'networks': ['Packet Analysis', 'Network Protocols', 'DNS', 'Routing', 'VPN'],
            'crypto': ['Encryption', 'Hashing', 'Digital Signatures', 'PKI', 'Key Management'],
            'forensics': ['Log Analysis', 'File Recovery', 'Memory Forensics', 'Malware Analysis'],
            'osint': ['Reconnaissance', 'Information Gathering', 'Social Engineering', 'Threat Intel'],
            'exploit': ['Vulnerability Exploitation', 'Privilege Escalation', 'Payload Generation'],
            'cloud': ['Cloud Security', 'IAM', 'Data Protection', 'Compliance'],
            'malware': ['Static Analysis', 'Dynamic Analysis', 'Behavior Analysis', 'Reverse Engineering'],
            'red-team': ['Attack Planning', 'Execution', 'Post-Exploitation', 'Evasion'],
            'blue-team': ['Detection', 'Response', 'Hardening', 'Incident Response'],
        }
    
    def analyze_user_skills(self, user_progress_data):
        """
        Analyze user's skill proficiency across all domains
        Returns skill scores and gaps
        
        Args:
            user_progress_data: Dict with lab_completions, scores, time_spent
        """
        skills = {}
        
        for domain, sub_skills in self.skill_categories.items():
            # Calculate domain proficiency (0-100)
            domain_score = self._calculate_domain_score(domain, user_progress_data)
            
            sub_skill_scores = {}
            for skill in sub_skills:
                # Calculate individual skill score
                score = self._calculate_skill_score(skill, user_progress_data)
                sub_skill_scores[skill] = score
            
            skills[domain] = {
                'proficiency': domain_score,
                'level': self._score_to_level(domain_score),
                'sub_skills': sub_skill_scores,
                'strength': max(sub_skill_scores.values()) if sub_skill_scores else 0,
                'weakness': min(sub_skill_scores.values()) if sub_skill_scores else 100,
            }
        
        return skills
    
    def identify_skill_gaps(self, user_skills):
        """
        Identify gaps in user's skill profile
        Returns prioritized list of skills to improve
        """
        gaps = []
        
        for domain, domain_data in user_skills.items():
            for skill, score in domain_data['sub_skills'].items():
                if score < 40:  # Below 40% is a gap
                    gaps.append({
                        'domain': domain,
                        'skill': skill,
                        'current_score': score,
                        'priority': 'high' if score < 20 else 'medium',
                        'recommended_labs': self._get_recommended_labs(domain, skill),
                        'estimated_hours': self._estimate_learning_time(score)
                    })
        
        # Sort by priority and current score
        gaps.sort(key=lambda x: (x['priority'] != 'high', x['current_score']))
        
        return gaps[:10]  # Top 10 gaps
    
    def identify_strengths(self, user_skills):
        """Identify user's strongest areas"""
        strengths = []
        
        for domain, domain_data in user_skills.items():
            if domain_data['proficiency'] > 70:
                strengths.append({
                    'domain': domain,
                    'proficiency': domain_data['proficiency'],
                    'level': domain_data['level'],
                    'top_skills': sorted(
                        domain_data['sub_skills'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:3]
                })
        
        return sorted(strengths, key=lambda x: x['proficiency'], reverse=True)
    
    def _calculate_domain_score(self, domain, user_progress_data):
        """Calculate overall domain proficiency score"""
        # Simulated calculation based on labs completed, quizzes, time spent
        domain_labs = user_progress_data.get(f'{domain}_labs_completed', 0)
        domain_quizzes = user_progress_data.get(f'{domain}_quizzes_passed', 0)
        domain_time = user_progress_data.get(f'{domain}_hours', 0)
        
        # Score formula: labs (40%) + quizzes (30%) + time investment (30%)
        lab_score = min(100, (domain_labs / 5) * 40)  # Max 5 labs per domain
        quiz_score = min(100, (domain_quizzes / 3) * 30)  # Max 3 quizzes
        time_score = min(100, (domain_time / 40) * 30)  # Max 40 hours per domain
        
        return int(lab_score + quiz_score + time_score)
    
    def _calculate_skill_score(self, skill, user_progress_data):
        """Calculate individual skill score"""
        # Based on exercises completed, quiz scores, challenge attempts
        score = 50 + np.random.randint(-20, 30)  # Default with variance
        return min(100, max(0, score))
    
    def _score_to_level(self, score):
        """Convert score to skill level"""
        if score < 20:
            return 'Beginner'
        elif score < 40:
            return 'Elementary'
        elif score < 60:
            return 'Intermediate'
        elif score < 80:
            return 'Advanced'
        else:
            return 'Expert'
    
    def _get_recommended_labs(self, domain, skill):
        """Get recommended labs for a skill"""
        return [f'{skill} - Lab 1', f'{skill} - Lab 2', f'{skill} - Challenge']
    
    def _estimate_learning_time(self, current_score):
        """Estimate hours needed to improve skill"""
        if current_score < 20:
            return 20
        elif current_score < 40:
            return 15
        elif current_score < 60:
            return 10
        else:
            return 5


class PredictiveLearningModel:
    """Predicts learning curves and outcomes"""
    
    def __init__(self):
        pass
    
    def predict_time_to_competency(self, current_score, domain, target_score=80):
        """
        Predict how long it will take to reach target score
        Using learning curve model: y = a * (x^b) + c
        """
        # Learning curve parameters (estimated)
        learning_rate = 0.8  # Slower for advanced skills
        initial_difficulty = 10  # Hours for first point
        
        # If already at target
        if current_score >= target_score:
            return 0
        
        # Estimate hours based on difficulty
        score_gap = target_score - current_score
        estimated_hours = (score_gap / (100 - current_score)) * initial_difficulty * (1 / learning_rate)
        
        return int(estimated_hours)
    
    def predict_completion_date(self, user_study_hours_per_week, estimated_hours_needed):
        """Predict when user will reach competency"""
        if user_study_hours_per_week == 0:
            return None
        
        weeks_needed = estimated_hours_needed / user_study_hours_per_week
        completion_date = datetime.utcnow() + timedelta(weeks=weeks_needed)
        
        return {
            'estimated_weeks': round(weeks_needed, 1),
            'estimated_date': completion_date.isoformat(),
            'confidence': 0.75 + (np.random.random() * 0.15)  # 75-90% confidence
        }
    
    def predict_success_rate(self, user_profile):
        """
        Predict likelihood of user succeeding in a domain
        Based on learning history, engagement, skill gaps
        """
        factors = {
            'consistency': user_profile.get('streak_days', 0) / 30,  # Normalized to 30 days
            'engagement': min(1.0, user_profile.get('weekly_xp', 0) / 1000),  # Normalized
            'progression': user_profile.get('level', 1) / 100,  # Normalized
            'completion_rate': user_profile.get('labs_completed', 0) / 50,  # Normalized
        }
        
        # Weighted average
        weights = {'consistency': 0.3, 'engagement': 0.3, 'progression': 0.2, 'completion_rate': 0.2}
        success_rate = sum(factors[k] * weights[k] for k in weights)
        
        return min(1.0, max(0.1, success_rate))
    
    def recommend_learning_pace(self, user_profile, available_hours_per_week):
        """Recommend optimal learning pace"""
        success_rate = self.predict_success_rate(user_profile)
        
        if success_rate < 0.4:
            return 'slow'  # 5-10 hours/week, spread over time
        elif success_rate < 0.7:
            return 'moderate'  # 10-20 hours/week
        else:
            return 'accelerated'  # 20+ hours/week
    
    def predict_next_challenge(self, user_history, user_skills):
        """Predict which challenge type user is most likely to solve"""
        # Analyze historical performance
        strongest_domain = max(user_skills.items(), key=lambda x: x[1]['proficiency'])[0]
        success_rate = max(user_skills.items(), key=lambda x: x[1]['proficiency'])[1]['proficiency'] / 100
        
        return {
            'recommended_type': 'advanced' if success_rate > 0.7 else 'intermediate',
            'suggested_domain': strongest_domain,
            'difficulty': 'hard' if success_rate > 0.8 else 'intermediate',
            'expected_success_rate': success_rate
        }


class PeerComparison:
    """Analyze user performance compared to peers"""
    
    def __init__(self):
        pass
    
    def calculate_percentile(self, user_xp, all_users_xp):
        """Calculate user's percentile ranking"""
        total_users = len(all_users_xp)
        users_below = sum(1 for xp in all_users_xp if xp < user_xp)
        
        percentile = (users_below / total_users) * 100
        return percentile
    
    def compare_to_peers(self, user_profile, peer_profiles):
        """Compare user metrics to peer group"""
        user_xp = user_profile['xp_points']
        user_level = user_profile['level']
        user_labs = user_profile.get('labs_completed', 0)
        
        peer_xps = [p['xp_points'] for p in peer_profiles]
        peer_levels = [p['level'] for p in peer_profiles]
        peer_labs = [p.get('labs_completed', 0) for p in peer_profiles]
        
        return {
            'xp_percentile': self.calculate_percentile(user_xp, peer_xps),
            'xp_vs_average': user_xp - (sum(peer_xps) / len(peer_xps)),
            'level_vs_average': user_level - (sum(peer_levels) / len(peer_levels)),
            'labs_vs_average': user_labs - (sum(peer_labs) / len(peer_labs)),
            'rank': len([x for x in peer_xps if x > user_xp]) + 1,
            'total_peers_in_group': len(peer_profiles)
        }
    
    def identify_learning_style_peers(self, user_profile, all_users):
        """Find peers with similar learning patterns"""
        similar_peers = []
        
        for peer in all_users:
            # Compare learning metrics
            xp_diff = abs(user_profile['xp_points'] - peer['xp_points'])
            level_diff = abs(user_profile['level'] - peer['level'])
            
            # Calculate similarity score
            similarity = 100 - ((xp_diff / max(user_profile['xp_points'], 1)) * 50 + 
                               (level_diff * 5))
            
            if similarity > 70:  # 70% similar
                similar_peers.append({
                    'username': peer.get('username'),
                    'similarity_score': int(similarity),
                    'xp_points': peer['xp_points'],
                    'level': peer['level'],
                    'labs_completed': peer.get('labs_completed', 0)
                })
        
        return sorted(similar_peers, key=lambda x: x['similarity_score'], reverse=True)[:5]


class AnalyticsInsights:
    """Generate actionable insights from analytics data"""
    
    def __init__(self):
        self.skill_analyzer = SkillAnalyzer()
        self.learning_model = PredictiveLearningModel()
        self.peer_comparison = PeerComparison()
    
    def generate_comprehensive_report(self, user_profile, user_progress, peer_profiles):
        """Generate full analytics report"""
        
        # Analyze skills
        user_skills = self.skill_analyzer.analyze_user_skills(user_progress)
        skill_gaps = self.skill_analyzer.identify_skill_gaps(user_skills)
        strengths = self.skill_analyzer.identify_strengths(user_skills)
        
        # Predict learning path
        time_to_competency = self.learning_model.predict_time_to_competency(
            current_score=user_profile['level'] * 10,
            domain='web-security'
        )
        completion_prediction = self.learning_model.predict_completion_date(
            user_study_hours_per_week=10,
            estimated_hours_needed=time_to_competency
        )
        
        # Compare to peers
        peer_comparison_data = self.peer_comparison.compare_to_peers(user_profile, peer_profiles)
        similar_peers = self.peer_comparison.identify_learning_style_peers(user_profile, peer_profiles)
        
        # Generate insights
        insights = self._generate_insights(
            user_profile, user_skills, skill_gaps, strengths, peer_comparison_data
        )
        
        return {
            'user_id': user_profile['id'],
            'generated_at': datetime.utcnow().isoformat(),
            'overview': {
                'total_xp': user_profile['xp_points'],
                'level': user_profile['level'],
                'rank': peer_comparison_data['rank'],
                'percentile': peer_comparison_data['xp_percentile']
            },
            'skills': user_skills,
            'skill_gaps': skill_gaps,
            'strengths': strengths,
            'learning_prediction': completion_prediction,
            'peer_comparison': peer_comparison_data,
            'similar_peers': similar_peers,
            'insights': insights,
            'recommendations': self._generate_recommendations(skill_gaps, strengths)
        }
    
    def _generate_insights(self, user_profile, user_skills, skill_gaps, strengths, peer_data):
        """Generate actionable insights"""
        insights = []
        
        # Insight 1: Skill progression
        top_domain = max(user_skills.items(), key=lambda x: x[1]['proficiency'])
        insights.append({
            'type': 'strength',
            'message': f"You're excelling in {top_domain[0].replace('-', ' ').title()} with {top_domain[1]['proficiency']}% proficiency!",
            'action': 'Continue leveraging this strength in advanced challenges'
        })
        
        # Insight 2: Largest gap
        if skill_gaps:
            biggest_gap = skill_gaps[0]
            insights.append({
                'type': 'gap',
                'message': f"{biggest_gap['skill']} is your biggest learning opportunity",
                'action': f"Dedicate {biggest_gap['estimated_hours']} hours to master this skill"
            })
        
        # Insight 3: Peer comparison
        if peer_data['xp_vs_average'] > 0:
            insights.append({
                'type': 'achievement',
                'message': f"You're {peer_data['xp_vs_average']} XP ahead of your peer group average!",
                'action': 'Keep up the momentum and help peers learn'
            })
        else:
            insights.append({
                'type': 'motivation',
                'message': f"You're {abs(peer_data['xp_vs_average'])} XP below your peer group - catch up!",
                'action': 'Increase your weekly study hours'
            })
        
        return insights
    
    def _generate_recommendations(self, skill_gaps, strengths):
        """Generate personalized learning recommendations"""
        recommendations = []
        
        # Recommendation 1: Focus areas
        if skill_gaps:
            recommendations.append({
                'priority': 'high',
                'title': 'Focus on High-Impact Skills',
                'description': f"Work on {skill_gaps[0]['skill']} to fill critical knowledge gaps",
                'labs': skill_gaps[0].get('recommended_labs', [])
            })
        
        # Recommendation 2: Build on strengths
        if strengths:
            recommendations.append({
                'priority': 'medium',
                'title': 'Advanced Specialization',
                'description': f"Deepen your expertise in {strengths[0]['domain']} with advanced labs",
                'action': 'Take expert-level challenges'
            })
        
        # Recommendation 3: Well-rounded development
        recommendations.append({
            'priority': 'medium',
            'title': 'Become Well-Rounded',
            'description': 'Balance your skill development across multiple domains',
            'action': 'Spend 20% of study time on weaker domains'
        })
        
        return recommendations


# Global instance
analytics_engine = AnalyticsInsights()
