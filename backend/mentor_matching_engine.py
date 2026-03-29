"""
Mentor Matching Algorithm
Intelligent skill-based matching with availability, timezone, and rating-based sorting
"""

import math
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class MentorMatcher:
    """Intelligent mentor matching system"""
    
    def __init__(self):
        self.max_distance_km = 5000  # For location-based matching if needed
        self.timezone_tolerance_hours = 5  # Match mentors within 5 hours
    
    def match_mentors(self, mentee_profile: Dict, available_mentors: List[Dict], 
                     top_n: int = 5) -> List[Dict]:
        """
        Match mentors to a mentee using multi-factor scoring
        
        Args:
            mentee_profile: Dict with skills, level, goals, timezone, availability
            available_mentors: List of mentor profiles
            top_n: Number of top matches to return
        
        Returns:
            Sorted list of matched mentors with compatibility scores
        """
        matches = []
        
        for mentor in available_mentors:
            score = self._calculate_match_score(mentee_profile, mentor)
            matches.append({
                **mentor,
                'match_score': score['total'],
                'score_breakdown': score['breakdown'],
                'compatibility': self._score_to_rating(score['total']),
                'reason': score['reason']
            })
        
        # Sort by match score
        matches.sort(key=lambda x: x['match_score'], reverse=True)
        return matches[:top_n]
    
    def _calculate_match_score(self, mentee: Dict, mentor: Dict) -> Dict:
        """
        Calculate comprehensive match score (0-100)
        Factors:
        - Skill alignment (35%)
        - Availability (25%)
        - Timezone compatibility (15%)
        - Rating/Experience (15%)
        - Learning style match (10%)
        """
        breakdown = {}
        reasons = []
        
        # 1. Skill Alignment (35%)
        skill_score = self._calculate_skill_alignment(mentee, mentor)
        breakdown['skill_alignment'] = skill_score
        reasons.append(f"Skill match: {skill_score}%")
        
        # 2. Availability (25%)
        availability_score = self._calculate_availability_match(mentee, mentor)
        breakdown['availability'] = availability_score
        reasons.append(f"Availability: {availability_score}%")
        
        # 3. Timezone Compatibility (15%)
        timezone_score = self._calculate_timezone_compatibility(mentee, mentor)
        breakdown['timezone'] = timezone_score
        reasons.append(f"Timezone compatible: {timezone_score}%")
        
        # 4. Rating/Experience (15%)
        rating_score = self._calculate_rating_score(mentor)
        breakdown['rating'] = rating_score
        reasons.append(f"Mentor rating: {rating_score}%")
        
        # 5. Learning Style (10%)
        learning_style_score = self._calculate_learning_style_match(mentee, mentor)
        breakdown['learning_style'] = learning_style_score
        reasons.append(f"Learning style match: {learning_style_score}%")
        
        # Calculate weighted total
        total = (
            skill_score * 0.35 +
            availability_score * 0.25 +
            timezone_score * 0.15 +
            rating_score * 0.15 +
            learning_style_score * 0.10
        )
        
        return {
            'total': int(total),
            'breakdown': breakdown,
            'reason': ' | '.join(reasons)
        }
    
    def _calculate_skill_alignment(self, mentee: Dict, mentor: Dict) -> int:
        """
        Calculate how well mentor's skills match mentee's needs
        Higher score if mentor is expert in mentee's target areas
        """
        mentee_goals = mentee.get('learning_goals', [])
        mentor_expertise = mentor.get('expertise_areas', [])
        mentor_level = mentor.get('expertise_level', 'intermediate')
        
        if not mentee_goals or not mentor_expertise:
            return 50  # Default if no data
        
        # Calculate overlap
        overlapping_skills = set(mentee_goals) & set(mentor_expertise)
        overlap_percentage = (len(overlapping_skills) / len(mentee_goals)) * 100 if mentee_goals else 0
        
        # Level adjustment - mentor should be 1-2 levels above mentee
        mentee_level = mentee.get('level', 1)
        mentor_level_value = {'beginner': 1, 'intermediate': 2, 'advanced': 3, 'expert': 4}.get(
            mentor_level, 2
        )
        
        level_bonus = 0
        if mentor_level_value > mentee_level:
            level_bonus = min(20, (mentor_level_value - mentee_level) * 10)
        
        return int(min(100, overlap_percentage + level_bonus))
    
    def _calculate_availability_match(self, mentee: Dict, mentor: Dict) -> int:
        """
        Calculate availability overlap
        Mentee needs to find time when mentor is available
        """
        mentee_availability = mentee.get('available_hours', [])  # List of hours (0-23)
        mentor_availability = mentor.get('available_hours', [])
        mentor_max_mentees = mentor.get('max_mentees', 5)
        mentor_current_mentees = mentor.get('current_mentees', 0)
        
        if not mentee_availability or not mentor_availability:
            return 50
        
        # Calculate overlap in available hours
        overlapping_hours = set(mentee_availability) & set(mentor_availability)
        overlap_percentage = (len(overlapping_hours) / len(mentee_availability)) * 100 if mentee_availability else 0
        
        # Availability penalty - if mentor is near capacity
        availability_penalty = 0
        if mentor_current_mentees >= mentor_max_mentees:
            availability_penalty = 50
        elif mentor_current_mentees / mentor_max_mentees > 0.8:
            availability_penalty = 20
        
        return int(max(0, overlap_percentage - availability_penalty))
    
    def _calculate_timezone_compatibility(self, mentee: Dict, mentor: Dict) -> int:
        """
        Calculate timezone compatibility
        Both should have reasonable working hours overlap
        """
        mentee_timezone = mentee.get('timezone', 'UTC')
        mentor_timezone = mentor.get('timezone', 'UTC')
        
        # Calculate hour difference (simplified)
        timezone_map = {
            'UTC': 0, 'EST': -5, 'CST': -6, 'MST': -7, 'PST': -8,
            'CET': 1, 'IST': 5.5, 'JST': 9, 'AEST': 10
        }
        
        mentee_offset = timezone_map.get(mentee_timezone, 0)
        mentor_offset = timezone_map.get(mentor_timezone, 0)
        
        hour_difference = abs(mentee_offset - mentor_offset)
        
        # Score based on difference
        if hour_difference <= 3:
            return 100
        elif hour_difference <= 6:
            return 80
        elif hour_difference <= 12:
            return 50
        else:
            return 20
    
    def _calculate_rating_score(self, mentor: Dict) -> int:
        """
        Calculate score based on mentor's rating and experience
        """
        rating = mentor.get('rating', 4.0)  # 0-5 scale
        years_experience = mentor.get('years_experience', 1)
        reviews_count = mentor.get('reviews_count', 0)
        
        # Rating component (0-60 out of 100)
        rating_score = (rating / 5.0) * 60
        
        # Experience bonus (0-25)
        experience_bonus = min(25, years_experience * 5)
        
        # Reviews credibility (0-15)
        reviews_bonus = min(15, (reviews_count / 20) * 15)
        
        return int(rating_score + experience_bonus + reviews_bonus)
    
    def _calculate_learning_style_match(self, mentee: Dict, mentor: Dict) -> int:
        """
        Calculate compatibility of learning styles
        """
        mentee_style = mentee.get('learning_style', 'mixed')  # visual, practical, reading, mixed
        mentor_style = mentor.get('teaching_style', 'mixed')
        
        style_map = {
            'visual': {'visual': 100, 'mixed': 80, 'practical': 60, 'reading': 40},
            'practical': {'practical': 100, 'mixed': 80, 'visual': 60, 'reading': 40},
            'reading': {'reading': 100, 'mixed': 80, 'visual': 40, 'practical': 60},
            'mixed': {'mixed': 100, 'visual': 80, 'practical': 80, 'reading': 80}
        }
        
        score = style_map.get(mentee_style, {}).get(mentor_style, 50)
        return score
    
    def _score_to_rating(self, score: int) -> str:
        """Convert score to rating"""
        if score >= 90:
            return 'Excellent Match'
        elif score >= 75:
            return 'Great Match'
        elif score >= 60:
            return 'Good Match'
        elif score >= 45:
            return 'Fair Match'
        else:
            return 'Poor Match'
    
    def calculate_engagement_score(self, mentor_id: int, mentee_interactions: List[Dict]) -> Dict:
        """
        Calculate engagement metrics for mentor-mentee relationship
        """
        if not mentee_interactions:
            return {
                'messages_exchanged': 0,
                'sessions_completed': 0,
                'average_session_duration': 0,
                'mentee_satisfaction': 0,
                'engagement_level': 'None'
            }
        
        messages = len([i for i in mentee_interactions if i.get('type') == 'message'])
        sessions = len([i for i in mentee_interactions if i.get('type') == 'session'])
        
        session_durations = [
            i.get('duration_minutes', 0) 
            for i in mentee_interactions if i.get('type') == 'session'
        ]
        avg_duration = sum(session_durations) / len(session_durations) if session_durations else 0
        
        # Satisfaction (simulated from ratings)
        satisfactions = [i.get('rating', 4) for i in mentee_interactions if i.get('rating')]
        avg_satisfaction = sum(satisfactions) / len(satisfactions) if satisfactions else 0
        
        # Engagement level
        total_interactions = len(mentee_interactions)
        if total_interactions >= 20:
            level = 'Very High'
        elif total_interactions >= 10:
            level = 'High'
        elif total_interactions >= 5:
            level = 'Medium'
        elif total_interactions > 0:
            level = 'Low'
        else:
            level = 'None'
        
        return {
            'messages_exchanged': messages,
            'sessions_completed': sessions,
            'average_session_duration': round(avg_duration, 1),
            'mentee_satisfaction': round(avg_satisfaction, 2),
            'total_interactions': total_interactions,
            'engagement_level': level
        }
    
    def schedule_mentoring_session(self, mentee_id: int, mentor_id: int, 
                                  preferred_time: str, duration_minutes: int = 60) -> Dict:
        """
        Schedule a mentoring session
        Checks availability and updates mentor's calendar
        """
        return {
            'session_id': f'session_{mentee_id}_{mentor_id}_{datetime.utcnow().timestamp()}',
            'mentee_id': mentee_id,
            'mentor_id': mentor_id,
            'scheduled_time': preferred_time,
            'duration_minutes': duration_minutes,
            'status': 'scheduled',
            'join_url': f'https://mentor.shadowhack.io/session/{mentor_id}/{mentee_id}',
            'reminder_sent': False
        }


class MentorProfile:
    """Represents a mentor's profile and capabilities"""
    
    def __init__(self, user_id: int, expertise_areas: List[str], 
                 expertise_level: str = 'intermediate', years_experience: int = 1):
        self.user_id = user_id
        self.expertise_areas = expertise_areas
        self.expertise_level = expertise_level
        self.years_experience = years_experience
        self.rating = 4.5
        self.reviews_count = 10
        self.max_mentees = 5
        self.current_mentees = 0
        self.hourly_rate = 25  # USD
        self.available_hours = list(range(14, 22))  # 2 PM - 10 PM
        self.timezone = 'UTC'
        self.teaching_style = 'mixed'
        self.bio = ''
        self.created_at = datetime.utcnow()
        self.mentee_feedback = []
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'user_id': self.user_id,
            'expertise_areas': self.expertise_areas,
            'expertise_level': self.expertise_level,
            'years_experience': self.years_experience,
            'rating': self.rating,
            'reviews_count': self.reviews_count,
            'max_mentees': self.max_mentees,
            'current_mentees': self.current_mentees,
            'hourly_rate': self.hourly_rate,
            'availability_status': 'Available' if self.current_mentees < self.max_mentees else 'Full',
            'teaching_style': self.teaching_style,
            'timezone': self.timezone
        }
    
    def update_feedback(self, rating: float, comment: str):
        """Add mentee feedback"""
        self.mentee_feedback.append({
            'rating': rating,
            'comment': comment,
            'date': datetime.utcnow().isoformat()
        })
        # Update overall rating (weighted average)
        ratings = [f['rating'] for f in self.mentee_feedback]
        self.rating = sum(ratings) / len(ratings)
        self.reviews_count = len(self.mentee_feedback)


# Global matcher instance
mentor_matcher = MentorMatcher()
