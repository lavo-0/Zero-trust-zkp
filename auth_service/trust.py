# auth_service/trust.py

import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto import (
    TRUST_HIGH_THRESHOLD,
    TRUST_LOW_THRESHOLD,
    TOKEN_EXPIRY_HIGH,
    TOKEN_EXPIRY_LOW
)

# In-memory store — tracks behavior per user
# { user_id: { "failures": int, "last_requests": [timestamps], "reuse_attempts": int } }
trust_store = {}

def _init_user(user_id: str):
    if user_id not in trust_store:
        trust_store[user_id] = {
            "failures": 0,
            "last_requests": [],
            "reuse_attempts": 0
        }

def record_failure(user_id: str):
    """Call this when a login attempt fails."""
    _init_user(user_id)
    trust_store[user_id]["failures"] += 1

def record_request(user_id: str):
    """Call this on every incoming request to track frequency."""
    _init_user(user_id)
    now = time.time()
    # keep only requests from last 10 seconds
    trust_store[user_id]["last_requests"] = [
        t for t in trust_store[user_id]["last_requests"]
        if now - t < 10
    ]
    trust_store[user_id]["last_requests"].append(now)

def record_reuse_attempt(user_id: str):
    """Call this when someone tries to reuse an expired/invalid token."""
    _init_user(user_id)
    trust_store[user_id]["reuse_attempts"] += 1

def compute_trust(user_id: str, device_match: bool) -> int:
    """
    Compute trust score for a user.
    Starts at 100, deductions for bad behavior.
    """
    _init_user(user_id)
    score = 100

    # device match is a strong positive signal
    if not device_match:
        score -= 40

    # each failed login costs 10 points
    failures = trust_store[user_id]["failures"]
    score -= failures * 10

    # flooding: more than 5 requests in 10 seconds
    recent_requests = len(trust_store[user_id]["last_requests"])
    if recent_requests > 5:
        score -= 20

    # token reuse attempts
    reuse = trust_store[user_id]["reuse_attempts"]
    score -= reuse * 15

    return max(score, 0)  # never below 0

def get_expiry(trust_score: int) -> int:
    """Return token expiry in seconds based on trust score."""
    if trust_score >= TRUST_HIGH_THRESHOLD:
        return TOKEN_EXPIRY_HIGH
    elif trust_score >= TRUST_LOW_THRESHOLD:
        return TOKEN_EXPIRY_LOW
    else:
        return 0  # denied