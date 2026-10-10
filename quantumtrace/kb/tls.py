"""TLS registries (IANA codepoints) and cipher-suite decomposition.

Never trust tshark/Wireshark *names*: older versions print X25519MLKEM768 (0x11EC)
as "Unknown". Always extract numeric codepoints and map them here.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

_HERE = os.path.dirname(__file__)

VERSIONS = {0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

# GREASE values (RFC 8701) must be ignored everywhere (ciphers, groups, versions, sigalgs, extensions)
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}

HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"

# Supported groups (IANA "TLS Supported Groups" registry + PQ drafts)
# ks = expected key_share key_exchange length (client, server) for validation.
GROUPS = {
    0x0015: dict(name="secp224r1", algorithm="ECDH", params={"curve": "P-224"}, pq=False, ks=(57, 57)),
    0x0016: dict(name="secp256k1", algorithm="ECDH", params={"curve": "secp256k1"}, pq=False, ks=(65, 65)),
    0x0017: dict(name="secp256r1", algorithm="ECDH", params={"curve": "P-256"}, pq=False, ks=(65, 65)),
    0x0018: dict(name="secp384r1", algorithm="ECDH", params={"curve": "P-384"}, pq=False, ks=(97, 97)),
    0x0019: dict(name="secp521r1", algorithm="ECDH", params={"curve": "P-521"}, pq=False, ks=(133, 133)),
    0x001A: dict(name="brainpoolP256r1", algorithm="ECDH", params={"curve": "brainpoolP256r1"}, pq=False, ks=(65, 65)),
    0x001B: dict(name="brainpoolP384r1", algorithm="ECDH", params={"curve": "brainpoolP384r1"}, pq=False, ks=(97, 97)),
    0x001C: dict(name="brainpoolP512r1", algorithm="ECDH", params={"curve": "brainpoolP512r1"}, pq=False, ks=(129, 129)),
    0x001D: dict(name="x25519", algorithm="X25519", params={"curve": "Curve25519"}, pq=False, ks=(32, 32)),
    0x001E: dict(name="x448", algorithm="X448", params={"curve": "Curve448"}, pq=False, ks=(56, 56)),
    0x0100: dict(name="ffdhe2048", algorithm="DH", params={"key_bits": 2048, "group": "ffdhe2048"}, pq=False, ks=(256, 256)),
    0x0101: dict(name="ffdhe3072", algorithm="DH", params={"key_bits": 3072, "group": "ffdhe3072"}, pq=False, ks=(384, 384)),
    0x0102: dict(name="ffdhe4096", algorithm="DH", params={"key_bits": 4096, "group": "ffdhe4096"}, pq=False, ks=(512, 512)),
    0x0103: dict(name="ffdhe6144", algorithm="DH", params={"key_bits": 6144, "group": "ffdhe6144"}, pq=False, ks=(768, 768)),
    0x0104: dict(name="ffdhe8192", algorithm="DH", params={"key_bits": 8192, "group": "ffdhe8192"}, pq=False, ks=(1024, 1024)),
    # Pure ML-KEM (draft-connolly-tls-mlkem-key-agreement)
    0x0200: dict(name="MLKEM512", algorithm="ML-KEM", params={"parameter_set": "ML-KEM-512"}, pq=True, ks=(800, 768)),
    0x0201: dict(name="MLKEM768", algorithm="ML-KEM", params={"parameter_set": "ML-KEM-768"}, pq=True, ks=(1184, 1088)),
    0x0202: dict(name="MLKEM1024", algorithm="ML-KEM", params={"parameter_set": "ML-KEM-1024"}, pq=True, ks=(1568, 1568)),
    # Hybrids (draft-ietf-tls-ecdhe-mlkem)
    0x11EB: dict(name="SecP256r1MLKEM768", algorithm="SecP256r1MLKEM768", params={"parameter_set": "ML-KEM-768", "curve": "P-256"}, pq=True, hybrid=True, ks=(1249, 1153)),
    0x11EC: dict(name="X25519MLKEM768", algorithm="X25519MLKEM768", params={"parameter_set": "ML-KEM-768", "curve": "Curve25519"}, pq=True, hybrid=True, ks=(1216, 1120)),
    0x11ED: dict(name="SecP384r1MLKEM1024", algorithm="SecP384r1MLKEM1024", params={"parameter_set": "ML-KEM-1024", "curve": "P-384"}, pq=True, hybrid=True, ks=(1665, 1665)),
    # Pre-standard Kyber drafts (obsolete, not FIPS 203)
    0x6399: dict(name="X25519Kyber768Draft00", algorithm="X25519Kyber768Draft00", params={"parameter_set": "Kyber768-r3"}, pq=True, hybrid=True, prestandard=True, ks=(1216, 1120)),
    0x639A: dict(name="SecP256r1Kyber768Draft00", algorithm="X25519Kyber768Draft00", params={"parameter_set": "Kyber768-r3", "curve": "P-256"}, pq=True, hybrid=True, prestandard=True, ks=(1249, 1153)),
}

# Signature schemes (TLS 1.2 signature_algorithms / TLS 1.3 SignatureScheme)
SIGSCHEMES = {
    0x0201: ("rsa_pkcs1_sha1", "RSA", {"padding": "PKCS1v15", "hash": "SHA-1"}),
    0x0203: ("ecdsa_sha1", "ECDSA", {"hash": "SHA-1"}),
    0x0202: ("dsa_sha1", "DSA", {"hash": "SHA-1"}),
    0x0301: ("rsa_pkcs1_sha224", "RSA", {"padding": "PKCS1v15", "hash": "SHA-224"}),
    0x0302: ("dsa_sha224", "DSA", {"hash": "SHA-224"}),
    0x0303: ("ecdsa_sha224", "ECDSA", {"hash": "SHA-224"}),
    0x0402: ("dsa_sha256", "DSA", {"hash": "SHA-256"}),
    0x0502: ("dsa_sha384", "DSA", {"hash": "SHA-384"}),
    0x0602: ("dsa_sha512", "DSA", {"hash": "SHA-512"}),
    0x0401: ("rsa_pkcs1_sha256", "RSA", {"padding": "PKCS1v15", "hash": "SHA-256"}),
    0x0501: ("rsa_pkcs1_sha384", "RSA", {"padding": "PKCS1v15", "hash": "SHA-384"}),
    0x0601: ("rsa_pkcs1_sha512", "RSA", {"padding": "PKCS1v15", "hash": "SHA-512"}),
    0x0403: ("ecdsa_secp256r1_sha256", "ECDSA", {"curve": "P-256", "hash": "SHA-256"}),
    0x0503: ("ecdsa_secp384r1_sha384", "ECDSA", {"curve": "P-384", "hash": "SHA-384"}),
    0x0603: ("ecdsa_secp521r1_sha512", "ECDSA", {"curve": "P-521", "hash": "SHA-512"}),
    0x0804: ("rsa_pss_rsae_sha256", "RSA", {"padding": "PSS", "hash": "SHA-256"}),
    0x0805: ("rsa_pss_rsae_sha384", "RSA", {"padding": "PSS", "hash": "SHA-384"}),
    0x0806: ("rsa_pss_rsae_sha512", "RSA", {"padding": "PSS", "hash": "SHA-512"}),
    0x0807: ("ed25519", "Ed25519", {}),
    0x0808: ("ed448", "Ed448", {}),
    0x0809: ("rsa_pss_pss_sha256", "RSA", {"padding": "PSS", "hash": "SHA-256"}),
    0x080A: ("rsa_pss_pss_sha384", "RSA", {"padding": "PSS", "hash": "SHA-384"}),
    0x080B: ("rsa_pss_pss_sha512", "RSA", {"padding": "PSS", "hash": "SHA-512"}),
    0x081A: ("ecdsa_brainpoolP256r1tls13_sha256", "ECDSA", {"curve": "brainpoolP256r1", "hash": "SHA-256"}),
    0x081B: ("ecdsa_brainpoolP384r1tls13_sha384", "ECDSA", {"curve": "brainpoolP384r1", "hash": "SHA-384"}),
    0x081C: ("ecdsa_brainpoolP512r1tls13_sha512", "ECDSA", {"curve": "brainpoolP512r1", "hash": "SHA-512"}),
    # ML-DSA in TLS (draft-ietf-tls-mldsa)
    0x0904: ("mldsa44", "ML-DSA", {"parameter_set": "ML-DSA-44"}),
    0x0905: ("mldsa65", "ML-DSA", {"parameter_set": "ML-DSA-65"}),
    0x0906: ("mldsa87", "ML-DSA", {"parameter_set": "ML-DSA-87"}),
}


@lru_cache(maxsize=1)
def _suites() -> dict:
    with open(os.path.join(_HERE, "tls_ciphersuites.json")) as fh:
        raw = json.load(fh)
    return {int(k, 16): v for k, v in raw.items()}


@lru_cache(maxsize=1)
def _openssl_to_iana() -> dict:
    return {v["openssl"]: v["iana"] for v in _suites().values() if v.get("openssl")}


def suite_name(code: int) -> str:
    s = _suites().get(code)
    return s["iana"] if s else f"UNKNOWN_0x{code:04X}"


def iana_from_openssl(name: str) -> str:
    """'ECDHE-RSA-AES128-GCM-SHA256' -> 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'."""
    if name.startswith("TLS_"):
        return name
    return _openssl_to_iana().get(name, name)


_MACS = {"SHA": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5"}


def decompose(iana: str) -> dict:
    """Split a cipher suite into its cryptographic roles.

    Returns dict(kex, auth, cipher, cipher_bits, mode, mac, prf, fs, tls13, anon, export).
    kex/auth are canonical KB ids or None when they are negotiated elsewhere (TLS 1.3).
    """
    out = dict(name=iana, kex=None, auth=None, cipher=None, cipher_bits=None, mode=None,
               mac=None, prf=None, fs=None, tls13=False, anon=False, export=False)
    n = iana[4:] if iana.startswith("TLS_") else iana
    if "_WITH_" not in n:  # TLS 1.3 style: TLS_AES_128_GCM_SHA256
        out["tls13"] = True
        out["fs"] = True  # (EC)DHE / KEM is mandatory in TLS 1.3 (except psk_ke)
        enc, _, h = n.rpartition("_")
        out["prf"] = _MACS.get(h, h)
        _parse_enc(enc, out)
        return out
    kxau, enc_mac = n.split("_WITH_", 1)
    toks = enc_mac.split("_")
    if toks[-1] in _MACS:
        mac = _MACS[toks[-1]]
        enc = "_".join(toks[:-1])
    else:
        mac, enc = None, enc_mac
    _parse_enc(enc, out)
    aead = out["mode"] in ("GCM", "CCM", "CCM_8") or out["cipher"] == "ChaCha20-Poly1305"
    if aead:
        out["prf"] = mac or "SHA-256"
    else:
        out["mac"] = mac  # HMAC-<hash> record MAC (TLS <= 1.2 non-AEAD suites)
        out["prf"] = "SHA-256" if mac in ("SHA-1", "MD5", None) else mac
    if "EXPORT" in kxau:
        out["export"] = True
        kxau = kxau.replace("_EXPORT", "").replace("EXPORT_", "")
    parts = kxau.split("_")
    kx = parts[0]
    au = parts[1] if len(parts) > 1 else None
    kx_map = {"RSA": "RSA", "ECDHE": "ECDHE", "DHE": "DHE", "ECDH": "ECDH-static", "DH": "DH-static",
              "PSK": "PSK", "SRP": "SRP", "ECCPWD": "ECCPWD", "KRB5": "KRB5"}
    out["kex"] = kx_map.get(kx, kx)
    if au == "anon" and kx in ("DH", "ECDH"):
        out["kex"] = "DHE" if kx == "DH" else "ECDHE"  # anonymous ephemeral (no authentication!)
    if kx == "RSA" and au == "PSK":
        out["kex"], au = "RSA", "PSK"
    au_map = {"RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA", "anon": None, "PSK": "PSK", "SHA": None}
    if au is None:
        out["auth"] = "RSA" if kx == "RSA" else ("PSK" if kx == "PSK" else None)
    else:
        out["auth"] = au_map.get(au, au)
    if au == "anon":
        out["anon"] = True
    out["fs"] = out["kex"] in ("ECDHE", "DHE")
    return out


def _parse_enc(enc: str, out: dict) -> None:
    t = enc.split("_")
    if t[0] == "AES":
        out["cipher"], out["cipher_bits"] = "AES", int(t[1])
        out["mode"] = "_".join(t[2:]) or "CBC"
    elif t[0] == "CHACHA20":
        out["cipher"], out["cipher_bits"], out["mode"] = "ChaCha20-Poly1305", 256, "AEAD"
    elif t[0] == "3DES":
        out["cipher"], out["cipher_bits"], out["mode"] = "3DES", 168, "CBC"
    elif t[0] == "RC4":
        out["cipher"], out["cipher_bits"], out["mode"] = "RC4", int(t[1]), "STREAM"
    elif t[0] in ("DES", "DES40"):
        out["cipher"], out["cipher_bits"], out["mode"] = "DES", 56 if t[0] == "DES" else 40, "CBC"
    elif t[0] in ("CAMELLIA", "ARIA"):
        out["cipher"], out["cipher_bits"] = t[0].capitalize(), int(t[1])
        out["mode"] = "_".join(t[2:]) or "CBC"
    elif t[0] == "NULL":
        out["cipher"], out["cipher_bits"], out["mode"] = "NULL", 0, None
    else:  # SEED, IDEA, RC2...
        out["cipher"] = t[0]
        out["cipher_bits"] = 128 if t[0] in ("SEED", "IDEA") else (40 if "40" in enc else None)
        out["mode"] = "CBC"


def group(code: int) -> dict:
    g = GROUPS.get(code)
    if g:
        return dict(code=code, **g)
    return dict(code=code, name=f"unknown_0x{code:04X}", algorithm="UNKNOWN-GROUP", params={}, pq=False, ks=None)


def sigscheme(code: int) -> tuple:
    return SIGSCHEMES.get(code, (f"unknown_0x{code:04X}", "UNKNOWN-SIG", {}))
