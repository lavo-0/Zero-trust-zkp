# client/client.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import random
import httpx

from shared.crypto import P, G

# ── Service URLs ──
AUTH_URL     = "http://127.0.0.1:8001"
GATEWAY_URL  = "http://127.0.0.1:8000"

# ── Client identity ──
USER_ID   = "lavanya"
DEVICE_ID = "device-001"

# ── Secret key (never leaves this file) ──
SECRET_X  = 6  # in real system this is a huge random number

def compute_public_key(x: int) -> int:
    return pow(G, x, P)

def register():
    print("\n[1] Registering client...")
    X = compute_public_key(SECRET_X)
    response = httpx.post(f"{AUTH_URL}/register", json={
        "user_id": USER_ID,
        "public_key": X,
        "device_id": DEVICE_ID
    })
    print(f"    Public key X = {X}")
    print(f"    Response: {response.json()}")
    return X

def login():
    print("\n[2] Logging in via Schnorr ZKP...")

    # Step 1: request challenge
    res = httpx.post(f"{AUTH_URL}/challenge", json={"user_id": USER_ID})
    c = res.json()["challenge"]
    print(f"    Challenge received: c = {c}")

    # Step 2: generate proof
    r = random.randint(1, P - 2)        # fresh random every login
    t = pow(G, r, P)                    # commitment
    s = (r + c * SECRET_X) % (P - 1)   # response
    print(f"    Proof generated: t = {t}, s = {s}")

    # Step 3: send proof
    res = httpx.post(f"{AUTH_URL}/verify", json={
        "user_id": USER_ID,
        "t": t,
        "s": s,
        "device_id": DEVICE_ID
    })

    data = res.json()
    if res.status_code == 200:
        print(f"    ✓ Proof verified!")
        print(f"    Trust score : {data['trust_score']}")
        print(f"    Token expiry: {data['expires_in']} seconds")
        print(f"    Token       : {data['token'][:40]}...")
        return data["token"]
    else:
        print(f"    ✗ Login failed: {data['detail']}")
        return None

def access_resource(token: str):
    print("\n[3] Accessing protected resource via Gateway...")
    response = httpx.get(
        f"{GATEWAY_URL}/resource",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Device-ID": DEVICE_ID
        }
    )
    if response.status_code == 200:
        print(f"    ✓ Access granted!")
        print(f"    Data: {response.json()}")
    else:
        print(f"    ✗ Access denied: {response.json()['detail']}")

def run():
    print("=" * 50)
    print("  ZERO TRUST ZKP — HAPPY PATH DEMO")
    print("=" * 50)
    register()
    token = login()
    if token:
        access_resource(token)
    print("\n" + "=" * 50)

if __name__ == "__main__":
    run()