# gateway/main.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from fastapi import FastAPI, Request, HTTPException

from gateway.token_verify import verify_hmac, verify_expiry, verify_device, verify_trust

app = FastAPI()

RESOURCE_API_URL = "http://127.0.0.1:8002"

@app.get("/resource")
async def access_resource(request: Request):
    # ── Extract token from Authorization header ──
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization header")

    token = auth_header.split(" ")[1]

    # ── Extract device_id from custom header ──
    device_id = request.headers.get("X-Device-ID")
    if not device_id:
        raise HTTPException(status_code=401, detail="missing X-Device-ID header")

    # ── Run all four Zero Trust checks ──
    try:
        claims = verify_hmac(token)       # Check 1
        verify_expiry(claims)             # Check 2
        verify_device(claims, device_id)  # Check 3
        verify_trust(claims)              # Check 4
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))

    # ── All checks passed — forward to Resource API ──
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{RESOURCE_API_URL}/secret")
        return response.json()