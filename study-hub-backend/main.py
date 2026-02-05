from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Optional
import os

app = FastAPI(title="ShadowHack CTF API")

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
