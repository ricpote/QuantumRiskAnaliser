"""AWS reference tables: ELB SslPolicy -> protocols/ciphers, KMS KeySpec, ACM algorithms.

Source: AWS ELB docs "Security policies for your Application Load Balancer"
(docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html),
retrieved 2026-10-10. FS-* rows from the "FS supported policies" table of the same page.
Verify any policy with:  aws elbv2 describe-ssl-policies --names <policy>
"""
from __future__ import annotations

_T13 = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
_GCM_ECDHE = ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
              "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384"]
_ECDHE_SHA2 = ["ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256",
               "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384"]
_ECDHE_SHA1 = ["ECDHE-ECDSA-AES128-SHA", "ECDHE-RSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA", "ECDHE-RSA-AES256-SHA"]
_RSA_SHA2 = ["AES128-GCM-SHA256", "AES128-SHA256", "AES256-GCM-SHA384", "AES256-SHA256"]
_RSA_SHA1 = ["AES128-SHA", "AES256-SHA"]

_LEGACY18 = _GCM_ECDHE + _ECDHE_SHA2 + _ECDHE_SHA1 + _RSA_SHA2 + _RSA_SHA1

PQ_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]

# policy -> dict(protocols, ciphers (OpenSSL/IANA names), pq: bool)
SSL_POLICIES = {
    "ELBSecurityPolicy-2016-08": dict(protocols=["TLS 1.0", "TLS 1.1", "TLS 1.2"], ciphers=_LEGACY18),
    "ELBSecurityPolicy-TLS-1-1-2017-01": dict(protocols=["TLS 1.1", "TLS 1.2"], ciphers=_LEGACY18),
    "ELBSecurityPolicy-TLS-1-2-2017-01": dict(protocols=["TLS 1.2"], ciphers=_GCM_ECDHE + _ECDHE_SHA2 + _RSA_SHA2),
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06": dict(protocols=["TLS 1.2"], ciphers=_LEGACY18),
    "ELBSecurityPolicy-FS-2018-06": dict(protocols=["TLS 1.0", "TLS 1.1", "TLS 1.2"], ciphers=_GCM_ECDHE + _ECDHE_SHA2 + _ECDHE_SHA1),
    "ELBSecurityPolicy-FS-1-1-2019-08": dict(protocols=["TLS 1.1", "TLS 1.2"], ciphers=_GCM_ECDHE + _ECDHE_SHA2 + _ECDHE_SHA1),
    "ELBSecurityPolicy-FS-1-2-2019-08": dict(protocols=["TLS 1.2"], ciphers=_GCM_ECDHE + _ECDHE_SHA2 + _ECDHE_SHA1),
    "ELBSecurityPolicy-FS-1-2-Res-2019-08": dict(protocols=["TLS 1.2"], ciphers=_GCM_ECDHE + _ECDHE_SHA2),
    "ELBSecurityPolicy-FS-1-2-Res-2020-10": dict(protocols=["TLS 1.2"], ciphers=_GCM_ECDHE),
    "ELBSecurityPolicy-TLS13-1-3-2021-06": dict(protocols=["TLS 1.3"], ciphers=_T13),
    "ELBSecurityPolicy-TLS13-1-2-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2"], ciphers=_T13 + _GCM_ECDHE + _ECDHE_SHA2),
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2"], ciphers=_T13 + _GCM_ECDHE),
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2"], ciphers=_T13 + _GCM_ECDHE + _ECDHE_SHA2 + _RSA_SHA2),
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2"], ciphers=_T13 + _LEGACY18),
    "ELBSecurityPolicy-TLS13-1-1-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2", "TLS 1.1"], ciphers=_T13 + _LEGACY18),
    "ELBSecurityPolicy-TLS13-1-0-2021-06": dict(protocols=["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"], ciphers=_T13 + _LEGACY18),
}
# PQ variants (2025-09) share the cipher lists of their 2021-06 counterparts and add ML-KEM hybrid groups
for _base, _pq in [("ELBSecurityPolicy-TLS13-1-3-2021-06", "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09"),
                   ("ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"),
                   ("ELBSecurityPolicy-TLS13-1-2-Res-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"),
                   ("ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09"),
                   ("ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09"),
                   ("ELBSecurityPolicy-TLS13-1-0-2021-06", "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09")]:
    SSL_POLICIES[_pq] = dict(SSL_POLICIES[_base], pq=True)
for _p in SSL_POLICIES.values():
    _p.setdefault("pq", False)

def derive_policy(name: str | None) -> dict | None:
    """Best-effort reading of an SslPolicy that is NOT in SSL_POLICIES, from AWS's naming scheme.

    Used for policies we have no verified cipher table for (the *-FIPS-2023-04, *-FIPS-PQ-2025-09
    and *-RFC9151-* families, legacy ELBSecurityPolicy-TLS-1-0-2015-04, future ones). The name
    reliably gives the minimum TLS version, whether TLS 1.3 is on and whether ML-KEM hybrids are
    offered ("-PQ-"). Cipher lists are a LOWER BOUND (what every policy of that kind allows); the
    real policy may allow more, so findings built from this carry the flag "policy-derived-from-name".
    Returns None when the name says nothing usable.
    """
    import re
    if not isinstance(name, str):
        return None
    m13 = re.search(r"TLS13-1-([0-3])", name)
    m12 = re.search(r"(?:TLS|FS)-1-([0-2])", name)
    if m13:
        lo, hi = int(m13.group(1)), 3
    elif m12:
        lo, hi = int(m12.group(1)), 2
    elif re.search(r"ELBSecurityPolicy-20\d\d-\d\d", name):
        lo, hi = 0, 2   # dated legacy policies (2015-05, 2016-08 style) start at TLS 1.0
    else:
        return None
    protocols = [f"TLS 1.{v}" for v in range(hi, lo - 1, -1)]
    fips, cnsa = "FIPS" in name, "RFC9151" in name
    restricted = "-Res-" in name or cnsa
    ciphers = []
    if "TLS 1.3" in protocols:
        ciphers += ["TLS_AES_256_GCM_SHA384"] if cnsa else (["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"] if fips else _T13)
    if "TLS 1.2" in protocols:
        ciphers += ["ECDHE-ECDSA-AES256-GCM-SHA384"] if cnsa else _GCM_ECDHE
        if not restricted:
            ciphers += _ECDHE_SHA2
    if lo < 2 and not restricted:
        ciphers += _ECDHE_SHA1   # TLS 1.0/1.1 cannot negotiate GCM: CBC-SHA1 suites must be on
    return dict(protocols=protocols, ciphers=ciphers, pq="-PQ-" in name, derived=True)


RECOMMENDED_POLICY = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"   # AWS console default / recommendation
RECOMMENDED_POLICY_FIPS = "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09"

# KMS KeySpec -> (algorithm, params)
KMS_KEYSPEC = {
    "SYMMETRIC_DEFAULT": ("AES", {"key_bits": 256, "mode": "GCM"}),   # AWS KMS symmetric keys are AES-256-GCM
    "RSA_2048": ("RSA", {"key_bits": 2048}),
    "RSA_3072": ("RSA", {"key_bits": 3072}),
    "RSA_4096": ("RSA", {"key_bits": 4096}),
    "ECC_NIST_P256": ("ECDSA", {"curve": "P-256"}),
    "ECC_NIST_P384": ("ECDSA", {"curve": "P-384"}),
    "ECC_NIST_P521": ("ECDSA", {"curve": "P-521"}),
    "ECC_SECG_P256K1": ("ECDSA", {"curve": "secp256k1"}),
    "HMAC_224": ("HMAC", {"hash": "SHA-224", "key_bits": 224}),
    "HMAC_256": ("HMAC", {"hash": "SHA-256", "key_bits": 256}),
    "HMAC_384": ("HMAC", {"hash": "SHA-384", "key_bits": 384}),
    "HMAC_512": ("HMAC", {"hash": "SHA-512", "key_bits": 512}),
    "SM2": ("SM2", {}),
    "ML_DSA_44": ("ML-DSA", {"parameter_set": "ML-DSA-44"}),
    "ML_DSA_65": ("ML-DSA", {"parameter_set": "ML-DSA-65"}),
    "ML_DSA_87": ("ML-DSA", {"parameter_set": "ML-DSA-87"}),
}

KMS_SIGNING_ALG = {
    "RSASSA_PKCS1_V1_5_SHA_256": {"padding": "PKCS1v15", "hash": "SHA-256"},
    "RSASSA_PKCS1_V1_5_SHA_384": {"padding": "PKCS1v15", "hash": "SHA-384"},
    "RSASSA_PKCS1_V1_5_SHA_512": {"padding": "PKCS1v15", "hash": "SHA-512"},
    "RSASSA_PSS_SHA_256": {"padding": "PSS", "hash": "SHA-256"},
    "RSASSA_PSS_SHA_384": {"padding": "PSS", "hash": "SHA-384"},
    "RSASSA_PSS_SHA_512": {"padding": "PSS", "hash": "SHA-512"},
    "ECDSA_SHA_256": {"hash": "SHA-256"},
    "ECDSA_SHA_384": {"hash": "SHA-384"},
    "ECDSA_SHA_512": {"hash": "SHA-512"},
    "ML_DSA_SHAKE_256": {"hash": "SHAKE256"},
}
KMS_ENCRYPTION_ALG = {
    "SYMMETRIC_DEFAULT": {"mode": "GCM"},
    "RSAES_OAEP_SHA_1": {"padding": "OAEP", "hash": "SHA-1"},
    "RSAES_OAEP_SHA_256": {"padding": "OAEP", "hash": "SHA-256"},
}

# ACM KeyAlgorithm / SignatureAlgorithm
ACM_KEY = {
    "RSA_1024": ("RSA", {"key_bits": 1024}), "RSA_2048": ("RSA", {"key_bits": 2048}),
    "RSA_3072": ("RSA", {"key_bits": 3072}), "RSA_4096": ("RSA", {"key_bits": 4096}),
    "EC_prime256v1": ("ECDSA", {"curve": "P-256"}), "EC_secp384r1": ("ECDSA", {"curve": "P-384"}),
    "EC_secp521r1": ("ECDSA", {"curve": "P-521"}),
}
ACM_SIG = {
    "SHA256WITHRSA": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-256"}),
    "SHA384WITHRSA": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-384"}),
    "SHA512WITHRSA": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-512"}),
    "SHA1WITHRSA": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-1"}),
    "MD5WITHRSA": ("RSA", {"padding": "PKCS1v15", "hash": "MD5"}),
    "SHA256WITHRSAANDMGF1": ("RSA", {"padding": "PSS", "hash": "SHA-256"}),
    "ECDSA_WITH_SHA256": ("ECDSA", {"hash": "SHA-256"}),
    "ECDSA_WITH_SHA384": ("ECDSA", {"hash": "SHA-384"}),
    "ECDSA_WITH_SHA512": ("ECDSA", {"hash": "SHA-512"}),
}
