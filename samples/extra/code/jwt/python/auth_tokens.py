"""Auth service: issues and verifies session / partner tokens."""
import os

import jwt

JWT_SECRET = "changeme123"


def issue_session(user_id):
    return jwt.encode({"sub": user_id}, JWT_SECRET, algorithm="HS256")


def issue_partner_token(private_key, claims):
    return jwt.encode(claims, private_key, algorithm="RS256")


def verify_partner_token(token, public_key):
    return jwt.decode(token, public_key, algorithms=["RS256", "ES256"])


def verify_internal(token):
    # secret comes from the environment: not hard-coded
    return jwt.decode(token, os.environ["INTERNAL_JWT_KEY"], algorithms=["HS512"])


def debug_peek(token):
    return jwt.decode(token, options={"verify_signature": False})


def log_config():
    # mentions an algorithm name but uses no crypto API
    print("partner tokens are signed with RS256")
