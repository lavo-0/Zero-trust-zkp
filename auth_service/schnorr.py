# auth_service/schnorr.py

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto import P, G

def verify_proof(X: int, t: int, s: int, c: int) -> bool:
    """
    Verify a Schnorr ZKP proof.
    
    X = public key (g^x mod p)
    t = commitment (g^r mod p)
    s = response (r + c*x)
    c = challenge (random number from server)
    
    Verification equation:
    g^s mod p == (t * X^c) mod p
    """
    left  = pow(G, s, P)
    right = (t * pow(X, c, P)) % P
    return left == right


def generate_public_key(x: int) -> int:
    """Compute public key X = g^x mod p"""
    return pow(G, x, P)