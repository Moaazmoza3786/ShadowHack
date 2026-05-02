from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
import os
import requests

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ShadowHack CTF API")

# Feature flag to enable/disable AI query endpoint (default enabled)
ENABLE_AI_QUERY = os.getenv('ENABLE_AI_QUERY', 'true').lower() in ('1', 'true', 'yes')

# Allow frontend on localhost:3000 to call backend during development
origins = ["http://localhost:3000", "http://localhost:5173"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class FlagSubmission(BaseModel):
    machine_id: str
    flag: str
    user_id: Optional[str] = None

# In a real scenario, these would be in a secure database or hashed
FLAGS = {
    "apollo-01": "SH{w3lc0m3_t0_th3_m00n}",
    "zeus-frame": "SH{g0d_0f_thund3r_str1k3s}",
    "cronos": "SH{t1m3_1s_r3l4t1v3}",
    # Add more flags here
}

@app.get("/")
def read_root():
    return {"status": "active", "system": "ShadowHack Verification Node"}

@app.post("/verify")
def verify_flag(submission: FlagSubmission):
    correct_flag = FLAGS.get(submission.machine_id)
    
    if not correct_flag:
        raise HTTPException(status_code=404, detail="Machine ID not found")
    
    if submission.flag.strip() == correct_flag:
        return {
            "valid": True, 
            "message": "Flag Accepted. Neural Link Established.", 
            "xp": 100 # This could be dynamic based on machine
        }
    else:
        return {"valid": False, "message": "Invalid Flag."}

class AIQuerySubmission(BaseModel):
    model: str
    prompt: str
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 256

@app.post("/api/ai/query")
def ai_query(submission: AIQuerySubmission):
    if not ENABLE_AI_QUERY:
        raise HTTPException(status_code=403, detail="AI query endpoint is disabled by feature flag")
    payload = {
        "model": submission.model,
        "prompt": submission.prompt,
        "temperature": submission.temperature,
        "max_tokens": submission.max_tokens,
    }
    try:
        # Ollama internal API for generation
        resp = requests.post("http://ollama:11434/api/generate", json=payload, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama backend unavailable: {e}")

    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Ollama failed: {resp.status_code} {resp.text[:200]}")

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    text = None
    if isinstance(data, dict):
        if "text" in data:
            text = data["text"]
        elif "choices" in data and isinstance(data["choices"], list) and data["choices"]:
            first = data["choices"][0]
            if isinstance(first, dict) and "text" in first:
                text = first["text"]
        elif "result" in data:
            text = data["result"]
    if text is None:
        text = str(data)
    return {"model": submission.model, "result": text}


@app.get("/api/health/status")
def health_status():
    status = {"backend": "healthy"}
    # Quick probe of Ollama health
    try:
        r = requests.get("http://ollama:11434/api/tags", timeout=5)
        status["ollama"] = "healthy" if r.status_code == 200 else "unhealthy"
    except Exception:
        status["ollama"] = "unreachable"
    # Frontend health can't be proven from backend; assume reachable when backend is up
    status["frontend"] = "reachable"
    return status

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
