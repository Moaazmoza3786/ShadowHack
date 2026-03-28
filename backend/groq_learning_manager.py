"""
Groq Learning Manager - Enhanced with qwen3-32b
Generates AI-powered learning curricula using Groq API
Powered by qwen3-32b model for superior reasoning and coding
"""

import os
import json
from groq import Groq
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class GroqLearningManager:
    """Manages AI curriculum generation via Groq API with qwen3-32b model"""

    def __init__(self):
        """Initialize Groq client with qwen3-32b model"""
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            logger.warning("GROQ_API_KEY not set. AI features will be limited.")
            self.client = None
        else:
            self.client = Groq(api_key=api_key)
        
        # Model to use: qwen3-32b for superior reasoning
        self.model = "qwen-qwq"  # qwen3-32b equivalent in Groq

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
            'iot-security': 'IoT Security',
            'mobile-security': 'Mobile Security',
            'devsecops': 'DevSecOps',
            'supply-chain': 'Supply Chain Security',
        }

    def generate_curriculum(self, domain, difficulty, duration_weeks=8, learning_style='mixed', user_experience=None):
        """
        Generate a learning curriculum using Groq AI with qwen3-32b
        
        Args:
            domain: Security domain (web-security, networks, etc.)
            difficulty: beginner, intermediate, advanced, expert
            duration_weeks: Number of weeks (default 8)
            learning_style: visual, practical, reading, mixed
            user_experience: Previous experience level for personalization
            
        Returns:
            dict: Comprehensive curriculum plan with weeks, topics, labs, etc.
        """
        if not self.client:
            return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

        domain_name = self.domains.get(domain, domain)
        
        prompt = f"""
You are a world-class cybersecurity instructor and course designer with 20+ years of experience.
Create a comprehensive, progressive {duration_weeks}-week learning curriculum for {domain_name} at {difficulty} difficulty level.

LEARNER PROFILE:
- Learning Style: {learning_style}
- Prior Experience: {user_experience or 'Not specified - assume intermediate'}
- Goal: Develop professional-grade expertise in {domain_name}

CURRICULUM REQUIREMENTS:
1. Progressive difficulty (start foundational, end with advanced scenarios)
2. Mix theory (30%) with hands-on labs (70% for practical style, 50% for mixed)
3. Include real-world attack/defense scenarios
4. Add milestone assessments every 2-3 weeks
5. Provide resource recommendations (books, tools, documentation)
6. Include common mistakes and how to avoid them
7. Add prerequisites for each week

FOR EACH WEEK PROVIDE:
- Week number and compelling title
- Clear learning objectives (2-3 sentences)
- Prerequisites and assumed knowledge
- Core topics (5-7 items, progressively building)
- Hands-on labs/challenges (3-5 with difficulty levels)
- Estimated hours (reality-based)
- XP reward calculation
- Key tools to master
- Real-world application scenario
- Assessment/quiz focus areas
- Advanced topic for self-study

CONTENT STRATEGY:
- Week 1-2: Fundamentals and setup
- Week 3-5: Core skills and techniques
- Week 6-7: Advanced scenarios and integration
- Week 8: Capstone project and real-world application

RESPONSE FORMAT - MUST BE VALID JSON ONLY:
{{
    "title": "Comprehensive Curriculum Title",
    "domain": "{domain}",
    "difficulty": "{difficulty}",
    "duration_weeks": {duration_weeks},
    "total_hours": estimated_sum,
    "total_labs": count,
    "learning_style": "{learning_style}",
    "prerequisites": ["Prerequisite 1", "Prerequisite 2"],
    "tools_to_learn": ["Tool 1", "Tool 2", "Tool 3"],
    "resources": {{
        "books": ["Book 1", "Book 2"],
        "websites": ["Site 1", "Site 2"],
        "tools": ["Tool 1", "Tool 2"]
    }},
    "weeks": [
        {{
            "week": 1,
            "title": "Engaging Week Title",
            "objectives": "Clear 2-3 sentence learning objectives",
            "prerequisites": ["What students should know before this week"],
            "topics": ["Topic 1", "Topic 2", "Topic 3", "Topic 4", "Topic 5"],
            "labs": [
                {{"name": "Lab 1", "difficulty": "beginner", "hours": 2}},
                {{"name": "Lab 2", "difficulty": "intermediate", "hours": 3}},
                {{"name": "Lab 3", "difficulty": "intermediate", "hours": 3}}
            ],
            "tools": ["Tool 1", "Tool 2"],
            "real_world_scenario": "Describe a real attack or defense scenario",
            "common_mistakes": ["Mistake 1", "Mistake 2"],
            "hours": 15,
            "xp_reward": 250,
            "assessment": "How students will be assessed this week",
            "advanced_study": "Optional advanced topics for self-study",
            "summary": "One sentence summarizing this week"
        }},
        ... more weeks (total of {duration_weeks})
    ],
    "capstone_project": {{
        "title": "Final Project Title",
        "description": "Comprehensive capstone project description",
        "deliverables": ["Deliverable 1", "Deliverable 2"],
        "estimated_hours": 40
    }}
}}

CRITICAL: Return ONLY valid JSON. No explanation, no markdown, no extra text.
Start with {{ and end with }}. Ensure all arrays and objects are properly formatted.
"""

        try:
            logger.info(f"Generating curriculum for {domain} at {difficulty} level using qwen3-32b")
            
            message = self.client.messages.create(
                model="qwen-qwq",  # Using qwen3-32b equivalent
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.8,  # Higher for more creative curriculum design
                max_tokens=8192,  # Larger for comprehensive response
                top_p=0.9,
            )

            response_text = message.content[0].text.strip()
            
            # Try to parse JSON
            try:
                curriculum = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                import re
                json_match = re.search(r'\{[\s\S]*\}', response_text)
                if json_match:
                    curriculum = json.loads(json_match.group())
                else:
                    logger.error(f"Failed to parse Groq response: {response_text[:300]}")
                    return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

            # Validate and enrich curriculum
            curriculum = self._validate_curriculum(curriculum, domain, difficulty, duration_weeks)
            return curriculum

        except Exception as e:
            logger.error(f"Error generating curriculum with Groq: {str(e)}")
            return self._generate_fallback_curriculum(domain, difficulty, duration_weeks)

    def generate_learning_hints(self, topic, difficulty, context=None):
        """Generate AI hints for struggling students"""
        if not self.client:
            return None
        
        try:
            prompt = f"""
You are a helpful tutoring AI. Provide a helpful hint (not the answer) for a student struggling with:
Topic: {topic}
Difficulty: {difficulty}
{f'Context: {context}' if context else ''}

Provide a concise hint that guides them toward the solution without giving it away.
Response should be 1-2 sentences maximum.
"""
            
            message = self.client.messages.create(
                model="qwen-qwq",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=200,
            )
            
            return message.content[0].text.strip()
        except Exception as e:
            logger.error(f"Error generating hint: {str(e)}")
            return None

    def generate_challenge(self, topic, difficulty, type_='coding'):
        """Generate dynamic challenges for mini-games"""
        if not self.client:
            return None
        
        try:
            challenge_types = {
                'coding': 'Write code to solve this security challenge',
                'theory': 'Answer this security theory question',
                'scenario': 'How would you handle this security scenario?',
                'exploit': 'Explain how to exploit this vulnerability'
            }
            
            prompt = f"""
Generate a {difficulty} difficulty {type_} challenge for {topic}.
{challenge_types.get(type_, '')}

Format as JSON:
{{
    "challenge": "Challenge description",
    "hint": "Optional hint",
    "solution": "Solution explanation",
    "xp_reward": number
}}

Return ONLY valid JSON.
"""
            
            message = self.client.messages.create(
                model="qwen-qwq",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=1000,
            )
            
            response_text = message.content[0].text.strip()
            return json.loads(response_text)
        except Exception as e:
            logger.error(f"Error generating challenge: {str(e)}")
            return None

    def _validate_curriculum(self, curriculum, domain, difficulty, duration_weeks):
        """Validate and enrich curriculum data"""
        
        # Ensure required fields
        curriculum.setdefault('domain', domain)
        curriculum.setdefault('difficulty', difficulty)
        curriculum.setdefault('duration_weeks', duration_weeks)
        curriculum.setdefault('created_at', datetime.utcnow().isoformat())
        curriculum.setdefault('learning_style', 'mixed')
        
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
