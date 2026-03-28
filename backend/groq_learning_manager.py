"""
Groq Learning Manager
Generates AI-powered learning curricula using Groq API (Llama 3.3 70B)
"""

import os
import json
from groq import Groq
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class GroqLearningManager:
    """Manages AI curriculum generation via Groq API"""

    def __init__(self):
        """Initialize Groq client"""
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            logger.warning("GROQ_API_KEY not set. AI features will be limited.")
            self.client = None
        else:
            self.client = Groq(api_key=api_key)

        self.domains = {
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
        }

    def generate_curriculum(self, domain, difficulty, duration_weeks=8, learning_style='mixed'):
        """
        Generate an 8-week learning curriculum using Groq AI
        
        Args:
            domain: Security domain (web-security, networks, etc.)
            difficulty: beginner, intermediate, advanced, expert
            duration_weeks: Number of weeks (default 8)
            learning_style: visual, practical, reading, mixed
            
        Returns:
            dict: Curriculum plan with weeks, topics, labs, etc.
        """
        if not self.client:
            return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

        domain_name = self.domains.get(domain, domain)
        
        prompt = f"""
        You are an expert cybersecurity instructor. Create a comprehensive {duration_weeks}-week 
        learning curriculum for {domain_name} at {difficulty} difficulty level.
        
        Learning Style: {learning_style}
        
        For EACH WEEK, provide:
        - Week number and title
        - Learning objectives (2-3 sentences)
        - Topics to cover (list 5-7 topics)
        - Recommended labs/challenges (3-5 names)
        - Time estimate in hours
        - XP reward (100-500 depending on difficulty)
        
        Requirements:
        1. Start simple, progressively increase difficulty
        2. Mix theory with hands-on labs (60% hands-on for practical style)
        3. Include real-world scenarios
        4. Add milestone tests every 2-3 weeks
        5. Format as valid JSON
        
        IMPORTANT: Respond with ONLY valid JSON, no other text. Start with {{ and end with }}.
        
        Format:
        {{
            "title": "Curriculum Title",
            "domain": "{domain}",
            "difficulty": "{difficulty}",
            "duration_weeks": {duration_weeks},
            "total_hours": estimate,
            "total_labs": count,
            "weeks": [
                {{
                    "week": 1,
                    "title": "Week Title",
                    "objectives": "Learning objectives here",
                    "topics": ["Topic 1", "Topic 2", "Topic 3"],
                    "labs": ["Lab 1", "Lab 2", "Lab 3"],
                    "hours": 15,
                    "xp_reward": 250,
                    "summary": "Brief summary"
                }},
                ... more weeks
            ]
        }}
        """

        try:
            message = self.client.messages.create(
                model="mixtral-8x7b-32768",  # Using Mixtral instead of Llama for faster responses
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=4096,
            )

            response_text = message.content[0].text.strip()
            
            # Try to parse JSON
            try:
                curriculum = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response if it has extra text
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    curriculum = json.loads(json_match.group())
                else:
                    logger.error(f"Failed to parse Groq response: {response_text[:200]}")
                    return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

            # Validate and enrich curriculum
            curriculum = self._validate_curriculum(curriculum, domain, difficulty, duration_weeks)
            return curriculum

        except Exception as e:
            logger.error(f"Error generating curriculum with Groq: {str(e)}")
            return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

    def _validate_curriculum(self, curriculum, domain, difficulty, duration_weeks):
        """Validate and enrich curriculum data"""
        
        # Ensure required fields
        curriculum.setdefault('domain', domain)
        curriculum.setdefault('difficulty', difficulty)
        curriculum.setdefault('duration_weeks', duration_weeks)
        curriculum.setdefault('created_at', datetime.utcnow().isoformat())
        
        # Validate weeks
        weeks = curriculum.get('weeks', [])
        if not weeks or len(weeks) < duration_weeks:
            logger.warning(f"Curriculum has {len(weeks)} weeks, expected {duration_weeks}")
            # Pad with fallback weeks if needed
            while len(weeks) < duration_weeks:
                weeks.append(self._generate_fallback_week(len(weeks) + 1, difficulty))
        
        curriculum['weeks'] = weeks[:duration_weeks]
        
        # Calculate totals
        total_hours = sum(w.get('hours', 15) for w in weeks)
        total_labs = sum(len(w.get('labs', [])) for w in weeks)
        
        curriculum['total_hours'] = total_hours
        curriculum['total_labs'] = total_labs
        curriculum['xp_total'] = sum(w.get('xp_reward', 250) for w in weeks)
        
        return curriculum

    def _generate_fallback_week(self, week_num, difficulty):
        """Generate a fallback week if AI generation fails"""
        
        difficulty_multipliers = {
            'beginner': 1.0,
            'intermediate': 1.5,
            'advanced': 2.0,
            'expert': 2.5
        }
        
        multiplier = difficulty_multipliers.get(difficulty, 1.5)
        
        return {
            'week': week_num,
            'title': f'Week {week_num}: Core Concepts & Practice',
            'objectives': 'Understand fundamental concepts and apply them in practical scenarios',
            'topics': [
                'Concept Overview',
                'Tools & Frameworks',
                'Hands-On Practice',
                'Common Pitfalls',
                'Best Practices',
                'Real-World Case Study',
                'Troubleshooting'
            ],
            'labs': [f'Lab {week_num}-1', f'Lab {week_num}-2', f'Lab {week_num}-3'],
            'hours': int(15 * multiplier),
            'xp_reward': int(250 * multiplier),
            'summary': f'Week {week_num} focuses on building foundational skills with hands-on labs'
        }

    def _generate_fallback_curriculum(self, domain, difficulty, duration_weeks):
        """Generate fallback curriculum when Groq API is unavailable"""
        logger.info(f"Using fallback curriculum for {domain} - {difficulty}")
        
        weeks = []
        for i in range(1, duration_weeks + 1):
            weeks.append(self._generate_fallback_week(i, difficulty))
        
        return {
            'title': f'{self.domains.get(domain, domain)} - {difficulty.title()}',
            'domain': domain,
            'difficulty': difficulty,
            'duration_weeks': duration_weeks,
            'weeks': weeks,
            'total_hours': sum(w['hours'] for w in weeks),
            'total_labs': sum(len(w['labs']) for w in weeks),
            'xp_total': sum(w['xp_reward'] for w in weeks),
            'note': 'Fallback curriculum - Groq API unavailable',
            'created_at': datetime.utcnow().isoformat()
        }


# Singleton instance
groq_learning_manager = GroqLearningManager()
