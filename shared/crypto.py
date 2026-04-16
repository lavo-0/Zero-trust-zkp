# shared/crypto.py

# ── Schnorr ZKP parameters ──
# p is a large prime number (the field we do math in)
# g is the generator (base for exponentiation)
P = 23  # small value for demo — in production this is 2048-bit
G = 5   # generator

# ── HMAC secret ──
# Auth and Gateway both know this. Nobody else.
HMAC_SECRET = b"zero-trust-super-secret-key"

# ── Token settings ──
TRUST_HIGH_THRESHOLD = 70
TRUST_LOW_THRESHOLD = 40
TOKEN_EXPIRY_HIGH = 60   # seconds
TOKEN_EXPIRY_LOW = 30    # seconds