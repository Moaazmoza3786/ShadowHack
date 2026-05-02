"""
AI Proxy Routes — Secure backend proxy for AI requests
Supports:
  - Ollama (local, private, no rate limits) — preferred when available
  - Groq (cloud, fast, free tier) — fallback when Ollama is down
  - Auto mode: tries local first, falls back to cloud
"""

import os
import json
import logging
import requests
from flask import Blueprint, request, jsonify, Response, stream_with_context
from groq import Groq

logger = logging.getLogger(__name__)

ai_proxy_bp = Blueprint('ai_proxy', __name__, url_prefix='/api/ai-proxy')

# ─── Config ───────────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv('OLLAMA_URL',   'http://localhost:11434')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b')
GROQ_MODEL   = os.getenv('GROQ_MODEL',   'llama-3.3-70b-versatile')

# AI_MODE: "local" | "cloud" | "auto"
# "local"  → Ollama only (private, no rate limits)
# "cloud"  → Groq only
# "auto"   → Ollama first, Groq fallback (default)
AI_MODE = os.getenv('AI_MODE', 'auto')


# ─── Ollama ───────────────────────────────────────────────────────────────────
def is_ollama_available():
    """Quick health check for Ollama."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=1) # Reduced timeout
        return r.status_code == 200
    except Exception:
        return False


def get_ollama_models():
    """List available Ollama models."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        if r.status_code == 200:
            return [m['name'] for m in r.json().get('models', [])]
    except Exception:
        pass
    return []


def call_ollama(messages, temperature=0.7, max_tokens=4096, model=None):
    """Call local Ollama instance (non-streaming)."""
    m = model or OLLAMA_MODEL
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": m,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "num_ctx": 8192,
                }
            },
            timeout=180
        )
        resp.raise_for_status()
        return resp.json().get('message', {}).get('content', '')
    except Exception as e:
        logger.error(f"Ollama error: {e}")
        return None


def stream_ollama(messages, temperature=0.7, max_tokens=4096, model=None):
    """Stream from Ollama using SSE."""
    m = model or OLLAMA_MODEL
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": m,
                "messages": messages,
                "stream": True,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "num_ctx": 8192,
                }
            },
            stream=True,
            timeout=180
        )
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                data = json.loads(line)
                chunk = data.get('message', {}).get('content', '')
                if chunk:
                    yield f"data: {json.dumps({'chunk': chunk, 'provider': 'ollama', 'model': m})}\n\n"
                if data.get('done'):
                    yield "data: [DONE]\n\n"
                    return
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Ollama stream error: {e}")
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


# ─── Groq ─────────────────────────────────────────────────────────────────────
def get_groq_client():
    key = os.getenv('GROQ_API_KEY')
    if not key:
        return None
    return Groq(api_key=key)


def call_groq(messages, temperature=0.7, max_tokens=4096):
    """Call Groq API (non-streaming)."""
    client = get_groq_client()
    if not client:
        return None
    try:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return completion.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq error: {e}")
        return None


def stream_groq(messages, temperature=0.7, max_tokens=4096):
    """Stream from Groq using SSE."""
    client = get_groq_client()
    if not client:
        yield f"data: {json.dumps({'error': 'Groq API key not configured'})}\n\n"
        return
    try:
        stream = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        for chunk in stream:
            delta = chunk.choices[0].delta
            if delta.content:
                yield f"data: {json.dumps({'chunk': delta.content, 'provider': 'groq', 'model': GROQ_MODEL})}\n\n"
        yield "data: [DONE]\n\n"
    except Exception as e:
        logger.error(f"Groq stream error: {e}")
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


# ─── Unified call ─────────────────────────────────────────────────────────────
def call_ai(messages, temperature=0.7, max_tokens=4096, preferred=None):
    """
    Call AI based on mode/preference.
    Returns (content, provider) tuple.
    """
    mode = preferred or AI_MODE

    if mode == 'local':
        result = call_ollama(messages, temperature, max_tokens)
        return (result, 'ollama') if result else (None, None)

    if mode == 'cloud':
        result = call_groq(messages, temperature, max_tokens)
        return (result, 'groq') if result else (None, None)

    # auto: try local first, then cloud
    if is_ollama_available():
        result = call_ollama(messages, temperature, max_tokens)
        if result:
            return result, 'ollama'

    result = call_groq(messages, temperature, max_tokens)
    return (result, 'groq') if result else (None, None)


def stream_ai(messages, temperature=0.7, max_tokens=4096, preferred=None):
    """Stream AI response based on mode/preference."""
    mode = preferred or AI_MODE

    if mode == 'local':
        yield from stream_ollama(messages, temperature, max_tokens)
        return

    if mode == 'cloud':
        yield from stream_groq(messages, temperature, max_tokens)
        return

    # auto: try local first
    if is_ollama_available():
        yield from stream_ollama(messages, temperature, max_tokens)
        return

    yield from stream_groq(messages, temperature, max_tokens)


# ─── Endpoints ────────────────────────────────────────────────────────────────

@ai_proxy_bp.route('/status', methods=['GET'])
def status():
    """Check which AI providers are available."""
    ollama_ok = is_ollama_available()
    groq_ok   = bool(os.getenv('GROQ_API_KEY'))
    models    = get_ollama_models() if ollama_ok else []

    # Determine active provider based on mode
    if AI_MODE == 'local':
        primary = 'ollama' if ollama_ok else 'none'
    elif AI_MODE == 'cloud':
        primary = 'groq' if groq_ok else 'none'
    else:  # auto
        primary = 'ollama' if ollama_ok else ('groq' if groq_ok else 'none')

    return jsonify({
        'ollama':       ollama_ok,
        'groq':         groq_ok,
        'primary':      primary,
        'mode':         AI_MODE,
        'groq_model':   GROQ_MODEL,
        'ollama_model': OLLAMA_MODEL,
        'ollama_models': models,
    })


@ai_proxy_bp.route('/models', methods=['GET'])
def list_models():
    """List available Ollama models."""
    return jsonify({
        'ollama_models': get_ollama_models(),
        'groq_models': [GROQ_MODEL],
        'current_ollama': OLLAMA_MODEL,
        'current_groq': GROQ_MODEL,
    })


@ai_proxy_bp.route('/chat', methods=['POST'])
def chat():
    """
    Unified chat endpoint.
    Body: {
        messages: [...],
        temperature: 0.7,
        max_tokens: 4096,
        provider: "local" | "cloud" | "auto"  (optional, overrides AI_MODE)
    }
    """
    data = request.get_json()
    if not data or 'messages' not in data:
        return jsonify({'error': 'Missing messages'}), 400

    messages     = data['messages']
    temperature  = float(data.get('temperature', 0.7))
    max_tokens   = int(data.get('max_tokens', 4096))
    preferred    = data.get('provider')  # optional override

    result, provider = call_ai(messages, temperature, max_tokens, preferred)

    if not result:
        return jsonify({'error': 'All AI providers unavailable. Start Ollama or configure Groq API key.'}), 503

    model = OLLAMA_MODEL if provider == 'ollama' else GROQ_MODEL
    return jsonify({
        'content':  result,
        'provider': provider,
        'model':    model,
    })


@ai_proxy_bp.route('/stream', methods=['POST'])
def stream():
    """
    Streaming chat endpoint (Server-Sent Events).
    Body: {
        messages: [...],
        temperature: 0.7,
        max_tokens: 4096,
        provider: "local" | "cloud" | "auto"
    }
    """
    data = request.get_json()
    if not data or 'messages' not in data:
        return jsonify({'error': 'Missing messages'}), 400

    messages    = data['messages']
    temperature = float(data.get('temperature', 0.7))
    max_tokens  = int(data.get('max_tokens', 4096))
    preferred   = data.get('provider')

    def generate():
        yield from stream_ai(messages, temperature, max_tokens, preferred)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':        'no-cache',
            'X-Accel-Buffering':    'no',
            'Access-Control-Allow-Origin': '*',
        }
    )


@ai_proxy_bp.route('/pull-model', methods=['POST'])
def pull_model():
    """
    Pull an Ollama model (download it locally).
    Body: { model: "llama3.2:3b" }
    """
    data = request.get_json()
    model = data.get('model', OLLAMA_MODEL)

    def generate():
        try:
            resp = requests.post(
                f"{OLLAMA_URL}/api/pull",
                json={"name": model, "stream": True},
                stream=True,
                timeout=600
            )
            for line in resp.iter_lines():
                if line:
                    yield f"data: {line.decode()}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )
