# gateway/token_verify.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hmac
import hashlib
import json
import time

from shared.crypto import HMAC_SECRET, TRUST_LOW_THRESHOLD

def parse_token(token: str) -> dict:
    """Split token into claims and signature, return claims as dict."""
    try:
        claims_b64, signature = token.split(".")
        claims_str = bytes.fromhex(claims_b64).decode()
        claims = json.loads(claims_str)
        return claims, claims_b64, signature
    except Exception:
        return None, None, None

def verify_hmac(token: str) -> dict:
    """
    Check 1 — Is the token genuine?
    Re-compute HMAC and compare with token's signature.
    """
    claims, claims_b64, signature = parse_token(token)

    if claims is None:
        raise Exception("invalid token format")

    expected = hmac.new(
        HMAC_SECRET,
        claims_b64.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise Exception("invalid HMAC signature — token forged or tampered")

    return claims

def verify_expiry(claims: dict):
    """
    Check 2 — Has the token expired?
    """
    if time.time() > claims["exp"]:
        raise Exception("token expired")

def verify_device(claims: dict, device_id: str):
    """
    Check 3 — Is this the same device that got the token?
    """
    if claims["device_id"] != device_id:
        raise Exception("device mismatch — token stolen or used from wrong device")

def verify_trust(claims: dict):
    """
    Check 4 — Is trust score above threshold?
    """
    if claims["trust_score"] < TRUST_LOW_THRESHOLD:
        raise Exception(f"trust score too low ({claims['trust_score']}) — access denied")