"""
Games Engine - Unified AI Architecture
Generates dynamic security challenges using the central AI infrastructure
"""

from learning_manager import learning_manager
import logging
import json

logger = logging.getLogger(__name__)


class GamesEngine:
    """Generates AI-powered security challenges for mini-games"""
    
    def __init__(self):
        self.learning_manager = learning_manager
    
    def generate_ctf_challenge(self, difficulty='intermediate'):
        """Generate a Capture The Flag challenge with variable difficulty"""
        modes = ['SQL Injection Hunt', 'XSS Challenge', 'CORS Bypass', 'JWT Bypass', 'SSRF Attack']
        
        challenges = []
        for mode in modes:
            challenge = self.learning_manager.generate_challenge(
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
            challenge = self.learning_manager.generate_challenge(
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
            challenge = self.learning_manager.generate_challenge(
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
            challenge = self.learning_manager.generate_challenge(
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
            'challenges': scenarios
        }

    def get_game_challenge(self, game_id, difficulty='intermediate'):
        """Get AI-generated challenge for a specific game"""
        game_handlers = {
            'ctf': self.generate_ctf_challenge,
            'exploit': self.generate_exploit_challenge,
            'code': self.generate_code_challenge,
            'defuse': self.generate_malware_challenge,
        }
        
        handler = game_handlers.get(game_id)
        if handler:
            return handler(difficulty)
        
        return {
            'error': f'Unknown game: {game_id}',
            'available_games': list(game_handlers.keys())
        }

    def generate_daily_challenge(self):
        """Generate a featured daily challenge"""
        import random
        games = ['ctf', 'exploit', 'code', 'defuse']
        game_id = random.choice(games)
        difficulty = 'intermediate'
        
        challenge_data = self.get_game_challenge(game_id, difficulty)
        
        if 'challenges' in challenge_data and challenge_data['challenges']:
            featured = challenge_data['challenges'][0]
            if isinstance(featured, dict):
                 return {
                    'success': True,
                    'daily_challenge': {
                        'game_id': game_id,
                        'difficulty': difficulty,
                        'featured': featured,
                        'xp_bonus': 500,
                        'expiry': 'Tomorrow'
                    }
                }
        
        return {'success': False, 'error': 'Failed to generate'}


# Global instance
games_engine = GamesEngine()
