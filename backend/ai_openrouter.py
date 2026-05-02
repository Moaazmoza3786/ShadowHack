"""
OpenRouter API Integration for MiniMax M2.5 AI Model
Provides advanced reasoning capabilities for pentesting and security analysis
"""

import os
import json
import aiohttp
import asyncio
from typing import Optional, List, Dict, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

@dataclass
class Message:
    role: str  # "user" or "assistant"
    content: str

@dataclass
class ConversationContext:
    """Maintains conversation history for context-aware responses"""
    messages: List[Message] = field(default_factory=list)
    model: str = "minimax/minicpm-4b"
    created_at: datetime = field(default_factory=datetime.now)
    conversation_id: str = ""
    
    def add_message(self, role: str, content: str):
        """Add message to conversation history"""
        self.messages.append(Message(role=role, content=content))
    
    def get_history(self) -> List[Dict]:
        """Get conversation history in API format"""
        return [
            {"role": msg.role, "content": msg.content}
            for msg in self.messages
        ]
    
    def clear(self):
        """Clear conversation history"""
        self.messages = []

class OpenRouterClient:
    """
    Client for OpenRouter API with MiniMax M2.5 support
    Handles all interactions with the LLM
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set in environment variables")
        
        self.base_url = "https://openrouter.io/api/v1"
        self.model = "minimax/minicpm-4b"  # MiniMax M2.5
        self.max_retries = 3
        self.timeout = 60
        self.rate_limit_remaining = 100
        
    async def call_model(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        stream: bool = False,
        context: Optional[ConversationContext] = None
    ) -> str | AsyncGenerator:
        """
        Call OpenRouter API with MiniMax M2.5 model
        Supports both regular and streaming responses
        """
        
        messages = []
        
        # Add system prompt if provided
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        # Add conversation history if context provided
        if context:
            messages.extend(context.get_history())
        
        # Add current prompt
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://shadowhack.io",
            "X-Title": "ShadowHack Elite",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream
        }
        
        if stream:
            return await self._stream_response(payload, headers, context)
        else:
            return await self._get_response(payload, headers, context)
    
    async def _get_response(self, payload: Dict, headers: Dict, context: Optional[ConversationContext]) -> str:
        """Get non-streaming response from OpenRouter"""
        
        async with aiohttp.ClientSession() as session:
            for attempt in range(self.max_retries):
                try:
                    async with session.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            response_text = data['choices'][0]['message']['content']
                            
                            # Update rate limit
                            self.rate_limit_remaining = int(resp.headers.get('x-ratelimit-remaining', 100))
                            
                            # Add to conversation context if provided
                            if context:
                                context.add_message("assistant", response_text)
                            
                            logger.info(f"✓ OpenRouter API call successful (Model: {self.model})")
                            return response_text
                        
                        elif resp.status == 429:
                            wait_time = int(resp.headers.get('retry-after', 60))
                            logger.warning(f"Rate limited, waiting {wait_time}s")
                            await asyncio.sleep(wait_time)
                        
                        elif resp.status >= 500:
                            logger.warning(f"Server error {resp.status}, retrying...")
                            await asyncio.sleep(2 ** attempt)
                        
                        else:
                            error_data = await resp.text()
                            logger.error(f"API Error {resp.status}: {error_data}")
                            raise Exception(f"API Error: {error_data}")
                
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}")
                    if attempt == self.max_retries - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)
                
                except Exception as e:
                    logger.error(f"Error on attempt {attempt + 1}: {str(e)}")
                    if attempt == self.max_retries - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)
        
        raise Exception("Failed to get response after retries")
    
    async def _stream_response(self, payload: Dict, headers: Dict, context: Optional[ConversationContext]) -> AsyncGenerator:
        """Stream response from OpenRouter"""
        
        full_response = ""
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status != 200:
                    error_data = await resp.text()
                    raise Exception(f"API Error {resp.status}: {error_data}")
                
                async for line in resp.content:
                    line = line.decode('utf-8').strip()
                    if line.startswith('data: '):
                        data_str = line[6:]
                        if data_str == '[DONE]':
                            break
                        
                        try:
                            data = json.loads(data_str)
                            if 'choices' in data and len(data['choices']) > 0:
                                delta = data['choices'][0].get('delta', {})
                                chunk = delta.get('content', '')
                                if chunk:
                                    full_response += chunk
                                    yield chunk
                        except json.JSONDecodeError:
                            continue
        
        # Add to conversation context if provided
        if context:
            context.add_message("assistant", full_response)

class PentesterAIEngine:
    """
    High-level AI engine for penetration testing tasks
    Uses OpenRouter API with MiniMax M2.5 model
    """
    
    SYSTEM_PROMPTS = {
        "pentester": """You are an expert penetration tester and cybersecurity professional with 15+ years of experience.
You provide strategic security analysis, attack strategies, and vulnerability research recommendations.
Always think step-by-step and explain your reasoning clearly.
Consider both offensive and defensive perspectives.
Provide actionable recommendations with real-world applicability.""",
        
        "analyst": """You are a security analyst specializing in vulnerability analysis and threat modeling.
Analyze security findings, provide risk assessment, and recommend remediation strategies.
Be concise but thorough in your analysis.
Focus on impact and likelihood when discussing risks.""",
        
        "payload_generator": """You are an expert in security testing payloads and exploit development.
Generate effective payloads for various vulnerability types when requested.
Always include explanation of what the payload does and its security implications.
Never generate payloads for illegal activities or without proper authorization.""",
        
        "report_writer": """You are a professional security report writer.
Create clear, concise, and actionable security assessment reports.
Structure reports with executive summary, detailed findings, and recommendations.
Use professional language and industry-standard terminology."""
    }
    
    def __init__(self, api_key: Optional[str] = None):
        self.client = OpenRouterClient(api_key)
        self.conversations: Dict[str, ConversationContext] = {}
    
    async def analyze_vulnerability(self, vulnerability_description: str) -> str:
        """Analyze a vulnerability and provide assessment"""
        
        prompt = f"""Analyze the following vulnerability and provide:
1. Vulnerability type and CVE classification
2. Attack vector and complexity
3. Potential impact
4. Remediation steps

Vulnerability: {vulnerability_description}"""
        
        return await self.client.call_model(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPTS["analyst"],
            temperature=0.3,
            max_tokens=1024
        )
    
    async def get_attack_strategy(self, target_info: str) -> str:
        """Generate attack strategy for a target"""
        
        prompt = f"""Based on the following target information, provide a comprehensive attack strategy:

Target Info: {target_info}

Include:
1. Reconnaissance approach
2. Vulnerability assessment plan
3. Exploitation strategy (if applicable)
4. Post-exploitation steps
5. Lateral movement possibilities
6. Data exfiltration approach (if applicable)"""
        
        return await self.client.call_model(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPTS["pentester"],
            temperature=0.7,
            max_tokens=2048
        )
    
    async def generate_payload(self, vulnerability_type: str, target_info: str) -> str:
        """Generate payload for specific vulnerability"""
        
        prompt = f"""Generate a payload for the following:
Vulnerability Type: {vulnerability_type}
Target Info: {target_info}

Include:
1. Payload code/content
2. Explanation of what it does
3. How to use it
4. Detection evasion tips"""
        
        return await self.client.call_model(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPTS["payload_generator"],
            temperature=0.5,
            max_tokens=1500
        )
    
    async def generate_security_report(self, findings: str, target: str) -> str:
        """Generate professional security report"""
        
        prompt = f"""Create a professional security assessment report:

Target: {target}

Findings to Include:
{findings}

Structure the report with:
1. Executive Summary
2. Assessment Scope
3. Detailed Findings (organized by severity)
4. Risk Assessment
5. Recommendations
6. Conclusion"""
        
        return await self.client.call_model(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPTS["report_writer"],
            temperature=0.3,
            max_tokens=3000
        )
    
    async def chat(self, conversation_id: str, user_message: str, role: str = "pentester") -> str:
        """
        Maintain conversation context across multiple messages
        """
        
        # Create or retrieve conversation
        if conversation_id not in self.conversations:
            self.conversations[conversation_id] = ConversationContext(
                conversation_id=conversation_id,
                model=self.client.model
            )
        
        context = self.conversations[conversation_id]
        
        # Add user message to context
        context.add_message("user", user_message)
        
        # Get response
        response = await self.client.call_model(
            prompt=user_message,
            system_prompt=self.SYSTEM_PROMPTS.get(role, self.SYSTEM_PROMPTS["pentester"]),
            temperature=0.7,
            max_tokens=2048,
            context=context
        )
        
        return response
    
    async def chat_stream(self, conversation_id: str, user_message: str, role: str = "pentester") -> AsyncGenerator:
        """
        Stream conversation responses in real-time
        """
        
        # Create or retrieve conversation
        if conversation_id not in self.conversations:
            self.conversations[conversation_id] = ConversationContext(
                conversation_id=conversation_id,
                model=self.client.model
            )
        
        context = self.conversations[conversation_id]
        context.add_message("user", user_message)
        
        async for chunk in await self.client.call_model(
            prompt=user_message,
            system_prompt=self.SYSTEM_PROMPTS.get(role, self.SYSTEM_PROMPTS["pentester"]),
            temperature=0.7,
            max_tokens=2048,
            stream=True,
            context=context
        ):
            yield chunk
    
    def clear_conversation(self, conversation_id: str):
        """Clear conversation history"""
        if conversation_id in self.conversations:
            self.conversations[conversation_id].clear()
            logger.info(f"Cleared conversation: {conversation_id}")
    
    def get_conversation_history(self, conversation_id: str) -> List[Dict]:
        """Get conversation history"""
        if conversation_id in self.conversations:
            return self.conversations[conversation_id].get_history()
        return []

# Global instance
_pentester_ai_engine: Optional[PentesterAIEngine] = None

def get_pentester_ai_engine(api_key: Optional[str] = None) -> PentesterAIEngine:
    """Get or create global PentesterAIEngine instance"""
    global _pentester_ai_engine
    if _pentester_ai_engine is None:
        _pentester_ai_engine = PentesterAIEngine(api_key)
    return _pentester_ai_engine

if __name__ == "__main__":
    # Test the API integration
    async def test():
        engine = get_pentester_ai_engine()
        
        # Test vulnerability analysis
        print("Testing vulnerability analysis...")
        result = await engine.analyze_vulnerability("SQL injection in login form")
        print(result)
    
    asyncio.run(test())
