# client/attack_demos.py

import sys
import os

# add root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import time
import random
import httpx
import hmac as hmac_lib
import hashlib
import json

from shared.crypto import P, G, HMAC_SECRET

# directly import from file path instead of package
import importlib.util

spec = importlib.util.spec_from_file_location(
    "client_module",
    os.path.join(ROOT, "client", "client.py")
)
client_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_module)

register         = client_module.register
login            = client_module.login
access_resource  = client_module.access_resource
AUTH_URL         = client_module.AUTH_URL
GATEWAY_URL      = client_module.GATEWAY_URL
USER_ID          = client_module.USER_ID
DEVICE_ID        = client_module.DEVICE_ID
SECRET_X         = client_module.SECRET_X

def divider(title: str):
    print(f"\n{'=' * 50}")
    print(f"  ATTACK: {title}")
    print(f"{'=' * 50}")

# ── Attack 1: Replay ZKP proof ──
def attack_replay_proof():
    divider("Replay old ZKP proof")
    print("Scenario: attacker captures proof (t, s) and resends it")

    # get a real challenge
    res = httpx.post(f"{AUTH_URL}/challenge", json={"user_id": USER_ID})
    c = res.json()["challenge"]

    # generate a valid proof for this challenge
    r = random.randint(1, P - 2)
    t = pow(G, r, P)
    s = (r + c * SECRET_X) % (P - 1)
    print(f"\n    Captured proof: t={t}, s={s}, c={c}")

    # use it once legitimately (consumes the challenge)
    httpx.post(f"{AUTH_URL}/verify", json={
        "user_id": USER_ID, "t": t, "s": s, "device_id": DEVICE_ID
    })

    # now request a NEW challenge — different c
    res = httpx.post(f"{AUTH_URL}/challenge", json={"user_id": USER_ID})
    new_c = res.json()["challenge"]
    print(f"    New challenge issued: c={new_c}")
    print(f"    Replaying old proof with new challenge...")

    # replay the OLD proof against the NEW challenge
    res = httpx.post(f"{AUTH_URL}/verify", json={
        "user_id": USER_ID, "t": t, "s": s, "device_id": DEVICE_ID
    })

    if res.status_code != 200:
        print(f"    ✗ Replay rejected: {res.json()['detail']}")
    else:
        print(f"    ✓ Replay succeeded (this should not happen!)")

# ── Attack 2: Expired token ─
def attack_expired_token():
    divider("Expired token usage")
    print("Scenario: client waits for token to expire then tries to use it")

    token = login()
    if not token:
        return

    print(f"\n    Token obtained. Waiting 65 seconds for it to expire...")
    print(f"    (in real demo, token expires in 60s)")

    # instead of waiting, we manually forge an expired token
    import hmac as hmac_lib
    import hashlib
    import json
    from shared.crypto import HMAC_SECRET

    claims = {
        "sub": USER_ID,
        "resource": "/secret",
        "device_id": DEVICE_ID,
        "trust_score": 100,
        "exp": int(time.time()) - 10  # already expired 10 seconds ago
    }
    claims_str = json.dumps(claims, separators=(",", ":"))
    claims_b64 = claims_str.encode().hex()
    signature = hmac_lib.new(
        HMAC_SECRET, claims_b64.encode(), hashlib.sha256
    ).hexdigest()
    expired_token = f"{claims_b64}.{signature}"

    print(f"    Sending expired token to Gateway...")
    response = httpx.get(
        f"{GATEWAY_URL}/resource",
        headers={
            "Authorization": f"Bearer {expired_token}",
            "X-Device-ID": DEVICE_ID
        }
    )

    if response.status_code != 200:
        print(f"    ✗ Rejected: {response.json()['detail']}")
    else:
        print(f"    ✓ Access granted (this should not happen!)")

# ── Attack 3: Stolen token, wrong device ──
def attack_device_mismatch():
    divider("Stolen token — wrong device")
    print("Scenario: attacker steals a valid token but uses it from wrong device")

    token = login()
    if not token:
        return

    fake_device = "attacker-device-999"
    print(f"\n    Valid token stolen.")
    print(f"    Using it from fake device: {fake_device}")

    response = httpx.get(
        f"{GATEWAY_URL}/resource",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Device-ID": fake_device  # wrong device
        }
    )

    if response.status_code != 200:
        print(f"    ✗ Rejected: {response.json()['detail']}")
    else:
        print(f"    ✓ Access granted (this should not happen!)")

# ── Attack 4: Request flooding ──
def attack_request_flood():
    divider("Request flooding — trust degradation")
    print("Scenario: attacker floods requests to degrade trust score")

    print(f"\n    Sending 10 rapid requests to Auth...")
    for i in range(10):
        httpx.post(f"{AUTH_URL}/challenge", json={"user_id": USER_ID})

    print(f"    Flooding done. Now logging in...")
    token = login()

    if token:
        print(f"    Attempting resource access with degraded trust token...")
        access_resource(token)
    else:
        print(f"    ✗ Token denied due to low trust score")

# ── Run all attacks ──
if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  ZERO TRUST ZKP — ATTACK DEMOS")
    print("=" * 50)

    # make sure client is registered first
    register()

    attack_replay_proof()
    attack_expired_token()
    attack_device_mismatch()
    attack_request_flood()

    print("\n" + "=" * 50)
    print("  ALL ATTACKS COMPLETE")
    print("=" * 50)