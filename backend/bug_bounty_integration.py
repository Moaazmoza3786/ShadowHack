"""
Bug Bounty Platform Integrations
Connects to HackerOne, Bugcrowd, and Intigriti
Handles OAuth, program fetching, submissions, and earnings tracking
"""

import os
import requests
import json
from datetime import datetime, timedelta
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class BugBountyIntegration:
    """Base class for bug bounty platform integrations"""
    
    def __init__(self, platform_name):
        self.platform_name = platform_name
        self.base_url = None
        self.api_key = None
        self.access_token = None
        
    def authenticate(self):
        """Authenticate with the platform"""
        raise NotImplementedError
        
    def get_programs(self, filters=None):
        """Fetch available bug bounty programs"""
        raise NotImplementedError
        
    def get_submissions(self, user_id):
        """Fetch user's submissions and statuses"""
        raise NotImplementedError
        
    def get_earnings(self, user_id):
        """Get earnings breakdown by severity and platform"""
        raise NotImplementedError
        
    def submit_report(self, program_id, vulnerability_data):
        """Submit a vulnerability report"""
        raise NotImplementedError


class HackerOneIntegration(BugBountyIntegration):
    """HackerOne platform integration"""
    
    def __init__(self):
        super().__init__('HackerOne')
        self.base_url = 'https://api.hackerone.com/v1'
        self.api_key = os.getenv('HACKERONE_API_KEY')
        self.api_username = os.getenv('HACKERONE_API_USERNAME')
        
    def authenticate(self):
        """Verify API credentials"""
        try:
            headers = self._get_headers()
            response = requests.get(
                f'{self.base_url}/me',
                headers=headers,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"HackerOne auth failed: {str(e)}")
            return False
    
    def _get_headers(self):
        """Get authentication headers for HackerOne"""
        return {
            'Accept': 'application/json',
            'X-Requested-With': 'ShadowHack',
            'Authorization': f'Basic {self.api_key}' if self.api_key else None
        }
    
    def get_programs(self, filters=None):
        """Fetch HackerOne programs with caching"""
        try:
            headers = self._get_headers()
            
            # Build query parameters
            params = {
                'page[size]': 100,
                'page[number]': 1
            }
            
            if filters:
                if filters.get('minimum_bounty'):
                    params['min_bounty'] = filters['minimum_bounty']
                if filters.get('keywords'):
                    params['keyword'] = filters['keywords']
            
            response = requests.get(
                f'{self.base_url}/programs/trending',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                programs = []
                
                for program in data.get('data', []):
                    programs.append({
                        'platform': 'HackerOne',
                        'id': program.get('id'),
                        'name': program.get('attributes', {}).get('name'),
                        'handle': program.get('attributes', {}).get('handle'),
                        'url': f"https://hackerone.com/{program.get('attributes', {}).get('handle')}",
                        'minimum_bounty': program.get('attributes', {}).get('minimum_bounty', 0),
                        'maximum_bounty': program.get('attributes', {}).get('maximum_bounty', 0),
                        'average_response_time': program.get('attributes', {}).get('average_response_time_to_report_in_calendar_days'),
                        'success_resolution_rate': program.get('attributes', {}).get('submission_state'),
                        'scope': program.get('attributes', {}).get('domain'),
                        'status': program.get('attributes', {}).get('state'),
                        'submission_state': program.get('attributes', {}).get('submission_state'),
                        'synchronous_notification': program.get('attributes', {}).get('synchronous_notification'),
                        'description': program.get('attributes', {}).get('briefDescription'),
                        'rating': program.get('attributes', {}).get('number_of_reports'),
                        'is_verified': program.get('attributes', {}).get('allows_bounty_splitting', False),
                        'accepts_submissions': program.get('attributes', {}).get('accepts_submissions', True),
                        'has_ibb': program.get('attributes', {}).get('has_ibb', False),
                        'severity_levels': ['critical', 'high', 'medium', 'low', 'info']
                    })
                
                return {
                    'success': True,
                    'platform': 'HackerOne',
                    'programs': programs,
                    'count': len(programs)
                }
            else:
                logger.error(f"HackerOne API error: {response.status_code}")
                return {
                    'success': False,
                    'error': f'HackerOne API returned {response.status_code}',
                    'programs': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching HackerOne programs: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'programs': []
            }
    
    def get_submissions(self, user_handle):
        """Get user's HackerOne submissions"""
        try:
            headers = self._get_headers()
            
            response = requests.get(
                f'{self.base_url}/hackers/{user_handle}/reports',
                headers=headers,
                params={'page[size]': 50},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                submissions = []
                
                for report in data.get('data', []):
                    submissions.append({
                        'id': report.get('id'),
                        'title': report.get('attributes', {}).get('title'),
                        'status': report.get('attributes', {}).get('state'),
                        'severity': report.get('attributes', {}).get('severity_rating'),
                        'bounty_amount': report.get('attributes', {}).get('bounty_amount'),
                        'bounty_split_amount': report.get('attributes', {}).get('bounty_split_amount'),
                        'program_handle': report.get('relationships', {}).get('program', {}).get('data', {}).get('attributes', {}).get('handle'),
                        'submitted_at': report.get('attributes', {}).get('created_at'),
                        'last_activity': report.get('attributes', {}).get('updated_at'),
                        'url': f"https://hackerone.com/reports/{report.get('id')}"
                    })
                
                return {
                    'success': True,
                    'platform': 'HackerOne',
                    'submissions': submissions,
                    'count': len(submissions)
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}',
                    'submissions': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching HackerOne submissions: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'submissions': []
            }
    
    def get_earnings(self, user_handle):
        """Get user's HackerOne earnings breakdown"""
        try:
            submissions_data = self.get_submissions(user_handle)
            
            if not submissions_data['success']:
                return {
                    'success': False,
                    'error': 'Could not fetch submissions',
                    'earnings': {}
                }
            
            earnings = {
                'platform': 'HackerOne',
                'user': user_handle,
                'total_earned': 0,
                'total_reports': len(submissions_data['submissions']),
                'by_severity': {},
                'by_status': {},
                'reports': []
            }
            
            severity_stats = {}
            status_stats = {}
            
            for submission in submissions_data['submissions']:
                bounty = submission.get('bounty_amount', 0) or 0
                severity = submission.get('severity', 'unknown').lower()
                status = submission.get('status', 'unknown').lower()
                
                earnings['total_earned'] += bounty
                
                # By severity
                if severity not in severity_stats:
                    severity_stats[severity] = {'count': 0, 'earned': 0}
                severity_stats[severity]['count'] += 1
                severity_stats[severity]['earned'] += bounty
                
                # By status
                if status not in status_stats:
                    status_stats[status] = {'count': 0, 'earned': 0}
                status_stats[status]['count'] += 1
                status_stats[status]['earned'] += bounty
                
                earnings['reports'].append({
                    'id': submission.get('id'),
                    'title': submission.get('title'),
                    'severity': severity,
                    'bounty': bounty,
                    'status': status
                })
            
            earnings['by_severity'] = severity_stats
            earnings['by_status'] = status_stats
            
            return {
                'success': True,
                'earnings': earnings
            }
        
        except Exception as e:
            logger.error(f"Error calculating HackerOne earnings: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'earnings': {}
            }


class BugcrowdIntegration(BugBountyIntegration):
    """Bugcrowd platform integration"""
    
    def __init__(self):
        super().__init__('Bugcrowd')
        self.base_url = 'https://api.bugcrowd.com'
        self.api_token = os.getenv('BUGCROWD_API_TOKEN')
    
    def authenticate(self):
        """Verify Bugcrowd API token"""
        try:
            headers = {'Authorization': f'Token {self.api_token}'}
            response = requests.get(
                f'{self.base_url}/user',
                headers=headers,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Bugcrowd auth failed: {str(e)}")
            return False
    
    def get_programs(self, filters=None):
        """Fetch Bugcrowd programs"""
        try:
            headers = {'Authorization': f'Token {self.api_token}'}
            
            response = requests.get(
                f'{self.base_url}/programs',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                programs = []
                
                for program in data.get('programs', []):
                    programs.append({
                        'platform': 'Bugcrowd',
                        'id': program.get('id'),
                        'name': program.get('name'),
                        'code': program.get('code'),
                        'url': program.get('url'),
                        'description': program.get('description'),
                        'status': program.get('status'),
                        'accepts_submissions': program.get('accepts_submissions', True),
                        'bounty_range': {
                            'min': program.get('min_bounty', 0),
                            'max': program.get('max_bounty', 0)
                        },
                        'target_metrics': program.get('target_metrics', {}),
                        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
                        'rating': program.get('rating', 4.5)
                    })
                
                return {
                    'success': True,
                    'platform': 'Bugcrowd',
                    'programs': programs,
                    'count': len(programs)
                }
            else:
                return {
                    'success': False,
                    'error': f'Bugcrowd API error: {response.status_code}',
                    'programs': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching Bugcrowd programs: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'programs': []
            }
    
    def get_submissions(self, researcher_id):
        """Get researcher's Bugcrowd submissions"""
        try:
            headers = {'Authorization': f'Token {self.api_token}'}
            
            response = requests.get(
                f'{self.base_url}/researchers/{researcher_id}/submissions',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                submissions = []
                
                for submission in data.get('submissions', []):
                    submissions.append({
                        'id': submission.get('id'),
                        'title': submission.get('vulnerability', {}).get('title'),
                        'status': submission.get('status'),
                        'severity': submission.get('vulnerability', {}).get('severity_rating'),
                        'bounty_amount': submission.get('bounty', {}).get('amount'),
                        'program': submission.get('program', {}).get('name'),
                        'submitted_at': submission.get('created_at'),
                        'url': submission.get('url')
                    })
                
                return {
                    'success': True,
                    'platform': 'Bugcrowd',
                    'submissions': submissions,
                    'count': len(submissions)
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}',
                    'submissions': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching Bugcrowd submissions: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'submissions': []
            }


class IntigritiIntegration(BugBountyIntegration):
    """Intigriti platform integration"""
    
    def __init__(self):
        super().__init__('Intigriti')
        self.base_url = 'https://api.intigriti.io/core/v1'
        self.api_key = os.getenv('INTIGRITI_API_KEY')
    
    def authenticate(self):
        """Verify Intigriti API key"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            response = requests.get(
                f'{self.base_url}/profile',
                headers=headers,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Intigriti auth failed: {str(e)}")
            return False
    
    def get_programs(self, filters=None):
        """Fetch Intigriti programs"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            
            response = requests.get(
                f'{self.base_url}/programs',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                programs = []
                
                for program in data.get('results', []):
                    programs.append({
                        'platform': 'Intigriti',
                        'id': program.get('id'),
                        'name': program.get('name'),
                        'url': program.get('domain'),
                        'type': program.get('type'),
                        'status': program.get('status'),
                        'min_bounty': program.get('min_bounty', 0),
                        'max_bounty': program.get('max_bounty', 0),
                        'response_time_days': program.get('response_time', 0),
                        'resolution_time_days': program.get('resolution_time', 0),
                        'accepts_submissions': True,
                        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
                        'rating': program.get('rating', 4.5)
                    })
                
                return {
                    'success': True,
                    'platform': 'Intigriti',
                    'programs': programs,
                    'count': len(programs)
                }
            else:
                return {
                    'success': False,
                    'error': f'Intigriti API error: {response.status_code}',
                    'programs': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching Intigriti programs: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'programs': []
            }
    
    def get_submissions(self, researcher_id):
        """Get researcher's Intigriti submissions"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            
            response = requests.get(
                f'{self.base_url}/researchers/{researcher_id}/submissions',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                submissions = []
                
                for submission in data.get('results', []):
                    submissions.append({
                        'id': submission.get('id'),
                        'title': submission.get('title'),
                        'status': submission.get('status'),
                        'severity': submission.get('severity'),
                        'bounty_amount': submission.get('bounty'),
                        'program_name': submission.get('program_name'),
                        'submitted_at': submission.get('created_at'),
                        'url': f"https://intigriti.com/submissions/{submission.get('id')}"
                    })
                
                return {
                    'success': True,
                    'platform': 'Intigriti',
                    'submissions': submissions,
                    'count': len(submissions)
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}',
                    'submissions': []
                }
        
        except Exception as e:
            logger.error(f"Error fetching Intigriti submissions: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'submissions': []
            }


# Manager to handle multiple integrations
class BugBountyManager:
    """Manages all bug bounty platform integrations"""
    
    def __init__(self):
        self.hackerone = HackerOneIntegration()
        self.bugcrowd = BugcrowdIntegration()
        self.intigriti = IntigritiIntegration()
        self.platforms = {
            'hackerone': self.hackerone,
            'bugcrowd': self.bugcrowd,
            'intigriti': self.intigriti
        }
    
    def get_all_programs(self, filters=None):
        """Get programs from all platforms"""
        all_programs = []
        
        for platform_name, integration in self.platforms.items():
            try:
                result = integration.get_programs(filters)
                if result.get('success'):
                    all_programs.extend(result.get('programs', []))
            except Exception as e:
                logger.error(f"Error fetching from {platform_name}: {str(e)}")
        
        # Sort by maximum bounty
        all_programs.sort(
            key=lambda x: x.get('maximum_bounty', 0) or x.get('max_bounty', 0),
            reverse=True
        )
        
        return {
            'success': True,
            'programs': all_programs,
            'count': len(all_programs),
            'platforms_count': len([p for p in self.platforms.values() if p.authenticate()])
        }
    
    def get_user_all_submissions(self, user_profiles):
        """
        Get submissions from all platforms for a user
        user_profiles: dict with keys 'hackerone', 'bugcrowd', 'intigriti'
        """
        all_submissions = []
        
        if 'hackerone' in user_profiles and user_profiles['hackerone']:
            result = self.hackerone.get_submissions(user_profiles['hackerone'])
            if result.get('success'):
                all_submissions.extend(result.get('submissions', []))
        
        if 'bugcrowd' in user_profiles and user_profiles['bugcrowd']:
            result = self.bugcrowd.get_submissions(user_profiles['bugcrowd'])
            if result.get('success'):
                all_submissions.extend(result.get('submissions', []))
        
        if 'intigriti' in user_profiles and user_profiles['intigriti']:
            result = self.intigriti.get_submissions(user_profiles['intigriti'])
            if result.get('success'):
                all_submissions.extend(result.get('submissions', []))
        
        return {
            'success': True,
            'submissions': all_submissions,
            'count': len(all_submissions)
        }
    
    def get_all_earnings(self, user_profiles):
        """Get total earnings from all platforms"""
        total_earnings = {
            'total': 0,
            'by_platform': {},
            'by_severity': {},
            'reports_count': 0,
            'platforms': []
        }
        
        if 'hackerone' in user_profiles and user_profiles['hackerone']:
            result = self.hackerone.get_earnings(user_profiles['hackerone'])
            if result.get('success'):
                earnings = result['earnings']
                total_earnings['total'] += earnings.get('total_earned', 0)
                total_earnings['reports_count'] += earnings.get('total_reports', 0)
                total_earnings['by_platform']['hackerone'] = earnings
                total_earnings['platforms'].append('HackerOne')
        
        if 'bugcrowd' in user_profiles and user_profiles['bugcrowd']:
            result = self.bugcrowd.get_submissions(user_profiles['bugcrowd'])
            if result.get('success'):
                total_bounty = sum(
                    s.get('bounty_amount', 0) or 0 
                    for s in result.get('submissions', [])
                )
                total_earnings['total'] += total_bounty
                total_earnings['reports_count'] += result.get('count', 0)
                total_earnings['by_platform']['bugcrowd'] = {'total_earned': total_bounty}
                total_earnings['platforms'].append('Bugcrowd')
        
        if 'intigriti' in user_profiles and user_profiles['intigriti']:
            result = self.intigriti.get_submissions(user_profiles['intigriti'])
            if result.get('success'):
                total_bounty = sum(
                    s.get('bounty_amount', 0) or 0 
                    for s in result.get('submissions', [])
                )
                total_earnings['total'] += total_bounty
                total_earnings['reports_count'] += result.get('count', 0)
                total_earnings['by_platform']['intigriti'] = {'total_earned': total_bounty}
                total_earnings['platforms'].append('Intigriti')
        
        return total_earnings


# Global manager instance
bug_bounty_manager = BugBountyManager()
