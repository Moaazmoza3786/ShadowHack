"""
Smart Recommendations Engine
Provides intelligent tool and strategy recommendations based on target analysis
"""

from flask import Blueprint, request, jsonify
import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass

from ai_openrouter import get_pentester_ai_engine

logger = logging.getLogger(__name__)

recommendations_bp = Blueprint('recommendations', __name__, url_prefix='/api/recommendations')

@dataclass
class Tool:
    """Tool recommendation"""
    name: str
    purpose: str
    category: str
    url: str
    alternative: Optional[str] = None
    skill_level: str = "intermediate"
    
@dataclass
class Recommendation:
    """General recommendation"""
    title: str
    description: str
    priority: str  # critical, high, medium, low
    category: str
    action_items: List[str]
    expected_outcome: str

class SmartRecommendationEngine:
    """Generate intelligent recommendations based on target analysis"""
    
    TOOL_DATABASE = {
        "reconnaissance": [
            Tool("Nmap", "Network scanning and host discovery", "scanning", "https://nmap.org", "Masscan"),
            Tool("Shodan", "Internet-connected device search", "recon", "https://shodan.io"),
            Tool("theHarvester", "Email, subdomain enumeration", "recon", "https://github.com/laramies/theHarvester"),
            Tool("Amass", "Subdomain enumeration and mapping", "recon", "https://github.com/OWASP/Amass"),
            Tool("Whois", "Domain information lookup", "recon", "https://whois.domaintools.com"),
        ],
        "vulnerability_scanning": [
            Tool("Nessus", "Comprehensive vulnerability scanner", "scanning", "https://www.tenable.com/products/nessus", "OpenVAS"),
            Tool("OpenVAS", "Open-source vulnerability scanner", "scanning", "https://www.openvas.org"),
            Tool("Qualys", "Cloud-based vulnerability management", "scanning", "https://www.qualys.com"),
            Tool("Nexpose", "Dynamic application scanning", "scanning", "https://www.rapid7.com/products/insightvm"),
        ],
        "web_testing": [
            Tool("Burp Suite", "Comprehensive web testing platform", "web", "https://portswigger.net/burp", "OWASP ZAP"),
            Tool("OWASP ZAP", "Free web application security scanner", "web", "https://www.zaproxy.org"),
            Tool("SQLMap", "SQL injection detection and exploitation", "web", "http://sqlmap.org"),
            Tool("Nikto", "Web server scanner", "web", "https://cirt.net/Nikto2"),
            Tool("W3af", "Web attack framework", "web", "http://w3af.org"),
        ],
        "network_testing": [
            Tool("Metasploit Framework", "Penetration testing framework", "exploitation", "https://www.metasploit.com", "Cobalt Strike"),
            Tool("Aircrack-ng", "WiFi security assessment", "wireless", "https://www.aircrack-ng.org"),
            Tool("Wireshark", "Network traffic analysis", "analysis", "https://www.wireshark.org"),
            Tool("tcpdump", "Packet capture tool", "analysis", "https://www.tcpdump.org"),
        ],
        "password_testing": [
            Tool("Hashcat", "GPU-accelerated password cracking", "password", "https://hashcat.net/hashcat"),
            Tool("John the Ripper", "Password cracking tool", "password", "https://www.openwall.com/john"),
            Tool("Hydra", "Online password cracking", "password", "https://github.com/vanhauser-thc/thc-hydra"),
            Tool("Medusa", "Parallel network login auditor", "password", "http://foofus.net/goons/medusa/medusa.html"),
        ],
        "social_engineering": [
            Tool("SET (Social-Engineer Toolkit)", "Social engineering toolkit", "social", "https://github.com/trustedsec/social-engineer-toolkit"),
            Tool("Gophish", "Phishing simulation platform", "social", "https://getgophish.com"),
        ],
        "exploitation": [
            Tool("Metasploit", "Full exploitation framework", "exploitation", "https://www.metasploit.com"),
            Tool("Canvas", "Exploitation toolkit", "exploitation", "https://www.immunityinc.com/products/canvas"),
        ],
        "post_exploitation": [
            Tool("PowerShell Empire", "Post-exploitation framework", "post-exploit", "https://github.com/BC-SECURITY/Empire"),
            Tool("Mimikatz", "Credential dumper", "post-exploit", "https://github.com/gentilkiwi/mimikatz"),
        ],
        "reporting": [
            Tool("ReportNG", "Test report generation", "reporting", "https://reportng.com"),
            Tool("CherryTree", "Note-taking application", "reporting", "https://www.giuspen.com/cherrytree"),
        ],
    }
    
    def __init__(self):
        self.engine = get_pentester_ai_engine()
    
    async def get_tool_recommendations(
        self,
        target_type: str,
        os_type: Optional[str] = None,
        services: Optional[List[str]] = None,
        skill_level: str = "intermediate"
    ) -> Dict:
        """
        Get recommended tools based on target characteristics
        
        Args:
            target_type: "web_app", "network", "mobile", "api", "cloud", etc.
            os_type: "windows", "linux", "macos", etc.
            services: List of identified services
            skill_level: "beginner", "intermediate", "advanced"
        """
        
        try:
            recommendations = []
            
            # Map target type to tool categories
            category_map = {
                "web_app": ["reconnaissance", "web_testing", "reporting"],
                "network": ["reconnaissance", "vulnerability_scanning", "network_testing", "password_testing"],
                "mobile": ["reconnaissance", "vulnerability_scanning"],
                "api": ["web_testing", "vulnerability_scanning"],
                "cloud": ["reconnaissance", "vulnerability_scanning"],
                "wifi": ["reconnaissance", "network_testing", "password_testing"],
            }
            
            categories = category_map.get(target_type, ["reconnaissance", "vulnerability_scanning"])
            
            # Get tools for each category
            all_recommendations = []
            for category in categories:
                if category in self.TOOL_DATABASE:
                    tools = self.TOOL_DATABASE[category]
                    all_recommendations.extend(tools)
            
            # Use AI to provide strategic recommendations
            ai_strategy = await self.engine.client.call_model(
                prompt=f"""Based on this target profile:
Target Type: {target_type}
OS: {os_type or 'Unknown'}
Services: {', '.join(services) if services else 'Not identified'}
Skill Level: {skill_level}

Provide:
1. Recommended tool categories
2. Suggested tool sequence
3. Expected outcomes
4. Time estimates
5. Risk considerations""",
                system_prompt="You are an expert penetration tester advising on tool selection.",
                temperature=0.6,
                max_tokens=1500
            )
            
            return {
                'success': True,
                'target_type': target_type,
                'recommendations': [
                    {
                        'name': tool.name,
                        'purpose': tool.purpose,
                        'category': tool.category,
                        'url': tool.url,
                        'alternative': tool.alternative,
                        'skill_level': tool.skill_level
                    }
                    for tool in all_recommendations[:5]  # Top 5 tools
                ],
                'ai_strategy': ai_strategy,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Tool recommendation error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_attack_roadmap(
        self,
        target_info: str,
        goals: List[str]
    ) -> Dict:
        """
        Generate attack roadmap/strategy
        """
        
        try:
            roadmap = await self.engine.client.call_model(
                prompt=f"""Create a detailed attack roadmap for:

Target: {target_info}
Goals: {', '.join(goals)}

Include:
1. Phase 1: Reconnaissance
2. Phase 2: Scanning & Enumeration
3. Phase 3: Vulnerability Assessment
4. Phase 4: Exploitation
5. Phase 5: Post-Exploitation
6. Phase 6: Reporting

For each phase, specify:
- Objectives
- Tools to use
- Expected timeframe
- Success criteria
- Risk assessment""",
                system_prompt="You are a master penetration tester creating an attack plan.",
                temperature=0.7,
                max_tokens=3000
            )
            
            return {
                'success': True,
                'roadmap': roadmap,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Attack roadmap error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_remediation_recommendations(
        self,
        vulnerability_type: str,
        severity: str,
        affected_component: str
    ) -> Dict:
        """
        Get remediation recommendations for vulnerabilities
        """
        
        try:
            recommendations = await self.engine.client.call_model(
                prompt=f"""Provide remediation guidance for:

Vulnerability Type: {vulnerability_type}
Severity: {severity}
Affected Component: {affected_component}

Include:
1. Immediate actions (emergency response)
2. Short-term fixes
3. Long-term solutions
4. Best practices to prevent recurrence
5. Testing methodology to verify fixes
6. Tools to validate remediation
7. Compliance implications""",
                system_prompt="You are a security remediation expert.",
                temperature=0.5,
                max_tokens=2000
            )
            
            return {
                'success': True,
                'recommendations': recommendations,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Remediation recommendation error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_learning_path(
        self,
        current_skills: List[str],
        target_skills: List[str],
        available_time: str = "3 months"
    ) -> Dict:
        """
        Get learning path recommendations
        """
        
        try:
            path = await self.engine.client.call_model(
                prompt=f"""Create a learning path for pentesting:

Current Skills: {', '.join(current_skills)}
Target Skills: {', '.join(target_skills)}
Available Time: {available_time}

Include:
1. Priority areas to focus on
2. Recommended courses and resources
3. Practice labs to set up
4. Tools to become proficient with
5. Certifications to pursue
6. Practice exercises
7. Timeline and milestones""",
                system_prompt="You are a pentesting trainer designing a curriculum.",
                temperature=0.6,
                max_tokens=2000
            )
            
            return {
                'success': True,
                'learning_path': path,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Learning path error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# Global instance
_rec_engine = None

def get_recommendation_engine():
    """Get global recommendation engine"""
    global _rec_engine
    if _rec_engine is None:
        _rec_engine = SmartRecommendationEngine()
    return _rec_engine

# ============================================================================
# API Routes
# ============================================================================

@recommendations_bp.route('/tools', methods=['POST'])
def get_tool_recommendations():
    """
    Get tool recommendations
    
    Request body:
    {
        "target_type": "web_app",
        "os_type": "linux",
        "services": ["Apache", "PHP", "MySQL"],
        "skill_level": "intermediate"
    }
    """
    try:
        data = request.get_json()
        
        target_type = data.get('target_type', 'web_app')
        os_type = data.get('os_type')
        services = data.get('services', [])
        skill_level = data.get('skill_level', 'intermediate')
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            engine = get_recommendation_engine()
            result = loop.run_until_complete(
                engine.get_tool_recommendations(
                    target_type=target_type,
                    os_type=os_type,
                    services=services,
                    skill_level=skill_level
                )
            )
            return jsonify(result)
        finally:
            loop.close()
    
    except Exception as e:
        logger.error(f"Tool recommendation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@recommendations_bp.route('/attack-roadmap', methods=['POST'])
def get_attack_roadmap():
    """Get attack roadmap/strategy"""
    try:
        data = request.get_json()
        
        target_info = data.get('target_info', '')
        goals = data.get('goals', [])
        
        if not target_info:
            return jsonify({'error': 'Missing target_info'}), 400
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            engine = get_recommendation_engine()
            result = loop.run_until_complete(
                engine.get_attack_roadmap(target_info, goals)
            )
            return jsonify(result)
        finally:
            loop.close()
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@recommendations_bp.route('/remediation', methods=['POST'])
def get_remediation():
    """Get remediation recommendations"""
    try:
        data = request.get_json()
        
        vuln_type = data.get('vulnerability_type', '')
        severity = data.get('severity', 'medium')
        component = data.get('affected_component', '')
        
        if not vuln_type:
            return jsonify({'error': 'Missing vulnerability_type'}), 400
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            engine = get_recommendation_engine()
            result = loop.run_until_complete(
                engine.get_remediation_recommendations(vuln_type, severity, component)
            )
            return jsonify(result)
        finally:
            loop.close()
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@recommendations_bp.route('/learning-path', methods=['POST'])
def get_learning_path():
    """Get learning path recommendations"""
    try:
        data = request.get_json()
        
        current_skills = data.get('current_skills', [])
        target_skills = data.get('target_skills', [])
        available_time = data.get('available_time', '3 months')
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            engine = get_recommendation_engine()
            result = loop.run_until_complete(
                engine.get_learning_path(current_skills, target_skills, available_time)
            )
            return jsonify(result)
        finally:
            loop.close()
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
