"""JWT algorithm names (JOSE: JWA RFC 7518, RFC 8037, draft-ietf-cose-dilithium) -> (category, KB algorithm, params).

Shared by the Python, Java and Go scanners: a token library call only tells us the JOSE
name ("RS256"); the primitive behind it is what gets classified.
"""
from __future__ import annotations

_SHA = {"256": "SHA-256", "384": "SHA-384", "512": "SHA-512"}
_ES_CURVE = {"256": "P-256", "384": "P-384", "512": "P-521"}

JOSE = {}
for _n in ("256", "384", "512"):
    JOSE[f"RS{_n}"] = ("signature", "RSA", dict(padding="PKCS1v15", hash=_SHA[_n]))
    JOSE[f"PS{_n}"] = ("signature", "RSA", dict(padding="PSS", hash=_SHA[_n]))
    JOSE[f"ES{_n}"] = ("signature", "ECDSA", dict(curve=_ES_CURVE[_n], hash=_SHA[_n]))
    JOSE[f"HS{_n}"] = ("mac", "HMAC", dict(hash=_SHA[_n]))
JOSE.update({
    "ES256K": ("signature", "ECDSA", dict(curve="secp256k1", hash="SHA-256")),
    "EdDSA": ("signature", "Ed25519", {}), "Ed25519": ("signature", "Ed25519", {}), "Ed448": ("signature", "Ed448", {}),
    "ML-DSA-44": ("signature", "ML-DSA", dict(parameter_set="ML-DSA-44")),
    "ML-DSA-65": ("signature", "ML-DSA", dict(parameter_set="ML-DSA-65")),
    "ML-DSA-87": ("signature", "ML-DSA", dict(parameter_set="ML-DSA-87")),
    # JWE key management
    "RSA1_5": ("encryption", "RSA", dict(padding="PKCS1v15")),
    "RSA-OAEP": ("encryption", "RSA", dict(padding="OAEP", hash="SHA-1")),
    "RSA-OAEP-256": ("encryption", "RSA", dict(padding="OAEP", hash="SHA-256")),
    "ECDH-ES": ("key-exchange", "ECDH", {}),
    # unsigned token: no integrity at all
    "none": ("signature", "NULL", {}),
})

# library spellings: SignatureAlgorithm.RS256, SigningMethodES256, Algorithm.HMAC256 (auth0), JWEAlgorithm.RSA_OAEP_256
_ALIASES = {"NONE": "none", "EDDSA": "EdDSA", "RSA_OAEP": "RSA-OAEP", "RSA_OAEP_256": "RSA-OAEP-256", "ECDH_ES": "ECDH-ES"}
_AUTH0 = {"RSA": "RS", "ECDSA": "ES", "HMAC": "HS"}


def normalize(name) -> str | None:
    """'RS256' / 'SigningMethodRS256' / 'RSA256' (auth0) / 'RSA_OAEP_256' / 'none' -> JOSE name, or None."""
    n = str(name or "").strip()
    if n.startswith("SigningMethod"):
        n = n[len("SigningMethod"):]
    for long, short in _AUTH0.items():
        if n.upper().startswith(long) and n[len(long):] in _SHA:
            n = short + n[len(long):]
    n = _ALIASES.get(n.upper(), n)
    return n if n in JOSE else None


def finding_args(name: str):
    """JOSE name -> (category, algorithm, params, flags) for a scanner's add()."""
    category, alg, params = JOSE[name]
    return category, alg, dict(params, jose=name), ["jwt"] + (["unsigned-token"] if name == "none" else [])
