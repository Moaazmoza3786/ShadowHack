"""
Groq-Powered Games Engine
Generates dynamic security challenges using Groq AI (qwen3-32b)
Real vulnerabilities, variable difficulty, AI hints
"""

from groq_learning_manager import groq_learning_manager
import logging
import json

logger = logging.getLogger(__name__)


class GroqGamesEngine:
    """Generates AI-powered security challenges for mini-games"""
    
    def __init__(self):
        self.groq_manager = groq_learning_manager
    
    def generate_ctf_challenge(self, difficulty='intermediate'):
        """Generate a Capture The Flag challenge with variable difficulty"""
        modes = ['SQL Injection Hunt', 'XSS Challenge', 'CORS Bypass', 'JWT Bypass', 'SSRF Attack']
        
        challenges = []
        for mode in modes:
            challenge = self.groq_manager.generate_challenge(
                topic=mode,
                difficulty=difficulty,
                type_='exploit'
            )
            if challenge:
                challenges.append({
                    'mode': mode,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 500)
                })
        
        return {
            'game': 'CTF',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def generate_exploit_challenge(self, difficulty='advanced'):
        """Generate an exploitation scenario challenge"""
        techniques = [
            'Buffer Overflow',
            'Privilege Escalation',
            'RCE Chain',
            'Format String',
            'Use-After-Free'
        ]
        
        challenges = []
        for technique in techniques:
            challenge = self.groq_manager.generate_challenge(
                topic=f'Exploitation: {technique}',
                difficulty=difficulty,
                type_='exploit'
            )
            if challenge:
                challenges.append({
                    'technique': technique,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 750)
                })
        
        return {
            'game': 'Exploit Simulator',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def generate_code_challenge(self, difficulty='intermediate'):
        """Generate secure coding challenges"""
        topics = [
            'Cryptography Best Practices',
            'Input Validation',
            'Output Encoding',
            'Authentication Bypass Prevention',
            'Secure File Upload'
        ]
        
        challenges = []
        for topic in topics:
            challenge = self.groq_manager.generate_challenge(
                topic=topic,
                difficulty=difficulty,
                type_='coding'
            )
            if challenge:
                challenges.append({
                    'topic': topic,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 300)
                })
        
        return {
            'game': 'Code Challenge',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def generate_malware_challenge(self, difficulty='hard'):
        """Generate malware analysis challenges"""
        scenarios = [
            'Ransomware Detection',
            'Botnet Command & Control',
            'Worm Propagation Pattern',
            'Trojan Behavior Analysis',
            'Rootkit Detection'
        ]
        
        challenges = []
        for scenario in scenarios:
            challenge = self.groq_manager.generate_challenge(
                topic=f'Malware Analysis: {scenario}',
                difficulty=difficulty,
                type_='scenario'
            )
            if challenge:
                challenges.append({
                    'scenario': scenario,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 600)
                })
        
        return {
            'game': 'Malware Defuser',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def generate_network_challenge(self, difficulty='intermediate'):
        """Generate network forensics challenges"""
        analysis_types = [
            'Packet Analysis for Protocol Anomalies',
            'DDoS Attack Pattern Detection',
            'Man-in-the-Middle Attack Identification',
            'DNS Spoofing Detection',
            'Traffic Classification'
        ]
        
        challenges = []
        for analysis in analysis_types:
            challenge = self.groq_manager.generate_challenge(
                topic=f'Network Forensics: {analysis}',
                difficulty=difficulty,
                type_='scenario'
            )
            if challenge:
                challenges.append({
                    'analysis_type': analysis,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 450)
                })
        
        return {
            'game': 'Network Forensics',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def generate_cipher_challenge(self, difficulty='beginner'):
        """Generate cryptography challenges"""
        cipher_types = [
            'Caesar Cipher',
            'Substitution Cipher',
            'Vigenère Cipher',
            'Base64 Encoding',
            'Simple XOR'
        ]
        
        challenges = []
        for cipher in cipher_types:
            challenge = self.groq_manager.generate_challenge(
                topic=f'Cryptography: {cipher}',
                difficulty=difficulty,
                type_='coding'
            )
            if challenge:
                challenges.append({
                    'cipher_type': cipher,
                    'challenge': challenge.get('challenge', ''),
                    'hint': challenge.get('hint', ''),
                    'solution': challenge.get('solution', ''),
                    'xp_reward': challenge.get('xp_reward', 250)
                })
        
        return {
            'game': 'Cipher Breaker',
            'difficulty': difficulty,
            'challenges': challenges
        }
    
    def get_game_challenge(self, game_id, difficulty='intermediate'):
        """Get AI-generated challenge for a specific game"""
        game_handlers = {
            'ctf': self.generate_ctf_challenge,
            'exploit': self.generate_exploit_challenge,
            'code': self.generate_code_challenge,
            'defuse': self.generate_malware_challenge,
            'network': self.generate_network_challenge,
            'cipher': self.generate_cipher_challenge,
        }
        
        handler = game_handlers.get(game_id)
        if handler:
            return handler(difficulty)
        
        return {
            'error': f'Unknown game: {game_id}',
            'available_games': list(game_handlers.keys())
        }
    
    def calculate_dynamic_xp(self, game_id, difficulty, score, max_score=1000, time_spent_seconds=None):
        """
        Calculate XP reward based on difficulty, score, and time
        Uses Groq-informed difficulty multipliers
        """
        difficulty_multipliers = {
            'beginner': 1.0,
            'intermediate': 1.5,
            'advanced': 2.0,
            'hard': 2.5,
            'expert': 3.0
        }
        
        base_xp = {
            'ctf': 500,
            'exploit': 750,
            'code': 300,
            'defuse': 600,
            'network': 450,
            'cipher': 250,
        }
        
        multiplier = difficulty_multipliers.get(difficulty, 1.5)
        base = base_xp.get(game_id, 400)
        
        # Score multiplier (0.5x to 1.5x)
        score_multiplier = 0.5 + (score / max_score) * 1.0
        
        # Time bonus (faster = better)
        time_multiplier = 1.0
        if time_spent_seconds:
            # If completed in under 5 minutes, get 1.2x bonus
            if time_spent_seconds < 300:
                time_multiplier = 1.2
            # If completed in under 2 minutes, get 1.5x bonus (for easier challenges)
            elif time_spent_seconds < 120:
                time_multiplier = 1.5
        
        xp = int(base * multiplier * score_multiplier * time_multiplier)
        
        return {
            'base_xp': base,
            'difficulty_multiplier': multiplier,
            'score_multiplier': score_multiplier,
            'time_multiplier': time_multiplier,
            'total_xp': max(50, xp)  # Minimum 50 XP
        }
    
    def generate_daily_challenge(self):
        """Generate a featured daily challenge"""
        games = ['ctf', 'exploit', 'code', 'defuse', 'network', 'cipher']
        difficulties = ['beginner', 'intermediate', 'advanced', 'hard']
        
        import random
        game_id = random.choice(games)
        difficulty = random.choice(difficulties)
        
        challenge_data = self.get_game_challenge(game_id, difficulty)
        
        if 'challenges' in challenge_data and challenge_data['challenges']:
            featured = challenge_data['challenges'][0]
            return {
                'success': True,
                'daily_challenge': {
                    'game_id': game_id,
                    'difficulty': difficulty,
                    'featured': featured,
                    'xp_bonus': int(featured.get('xp_reward', 300) * 1.5),
                    'expiry': 'Tomorrow at 00:00 UTC'
                }
            }
        
        return {
            'success': False,
            'error': 'Failed to generate daily challenge'
        }


# Global instance
groq_games_engine = GroqGamesEngine()
