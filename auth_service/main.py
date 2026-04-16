# auth_service/main.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hmac
import hashlib
import json
import time
import random

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.crypto import P, G, HMAC_SECRET, TRUST_LOW_THRESHOLD
from auth_service.schnorr import verify_proof, generate_public_key
from auth_service.trust import (
    compute_trust, get_expiry,
    record_failure, record_request, record_reuse_attempt
)

app = FastAPI()

# ── In-memory databases ──
public_keys = {}   # { user_id: X }
challenges  = {}   # { user_id: c }
device_ids  = {}   # { user_id: device_id }

# ── Request models ──
class RegisterRequest(BaseModel):
    user_id: str
    public_key: int
    device_id: str

class ChallengeRequest(BaseModel):
    user_id: str

class VerifyRequest(BaseModel):
    user_id: str
    t: int
    s: int
    device_id: str

# ── Helper: create signed token ──
def create_token(user_id: str, trust_score: int, expiry: int, device_id: str) -> str:
    claims = {
        "sub": user_id,
        "resource": "/secret",
        "device_id": device_id,
        "trust_score": trust_score,
        "exp": int(time.time()) + expiry
    }
    claims_str = json.dumps(claims, separators=(",", ":"))
    claims_b64 = claims_str.encode().hex()
    signature = hmac.new(
        HMAC_SECRET,
        claims_b64.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{claims_b64}.{signature}"

# ── Endpoints ──

@app.post("/register")
def register(req: RegisterRequest):
    public_keys[req.user_id] = req.public_key
    device_ids[req.user_id]  = req.device_id
    return {"message": f"user {req.user_id} registered successfully"}

@app.post("/challenge")
def challenge(req: ChallengeRequest):
    if req.user_id not in public_keys:
        raise HTTPException(status_code=404, detail="user not registered")
    c = random.randint(1, P - 2)
    challenges[req.user_id] = c
    return {"challenge": c}

@app.post("/verify")
def verify(req: VerifyRequest):
    if req.user_id not in public_keys:
        raise HTTPException(status_code=404, detail="user not registered")

    X = public_keys[req.user_id]
    c = challenges.get(req.user_id)

    if c is None:
        raise HTTPException(status_code=400, detail="no challenge found — request one first")

    record_request(req.user_id)

    # Verify Schnorr proof
    valid = verify_proof(X, req.t, req.s, c)

    if not valid:
        record_failure(req.user_id)
        raise HTTPException(status_code=401, detail="invalid proof — authentication failed")

    # Clear challenge so it can't be reused
    del challenges[req.user_id]

    # Check device
    device_match = (device_ids.get(req.user_id) == req.device_id)

    # Compute trust
    trust_score = compute_trust(req.user_id, device_match)
    expiry      = get_expiry(trust_score)

    if expiry == 0:
        raise HTTPException(status_code=403, detail=f"trust score too low ({trust_score}) — access denied")

    token = create_token(req.user_id, trust_score, expiry, req.device_id)

    return {
        "token": token,
        "trust_score": trust_score,
        "expires_in": expiry
    }