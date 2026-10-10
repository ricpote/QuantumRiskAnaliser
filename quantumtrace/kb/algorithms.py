"""Cryptographic knowledge base: canonical algorithms -> quantum threat, OIDs, NIST levels.

Quantum threat model:
  shor   : asymmetric schemes broken by Shor (RSA, DSA, DH, ECDH, ECDSA, EdDSA, X25519...)
  grover : symmetric ciphers / hashes / MACs whose security is roughly halved by Grover
  none   : post-quantum schemes (FIPS 203/204/205...) and hybrids that include one

Tier rules (challenge taxonomy):
  critical : threat == shor
  medium   : threat == grover and post-quantum effective strength < 128 bits (AES-128, 3DES, SHA-1, MD5...)
  safe     : threat == grover with >= 128-bit post-quantum strength (AES-256, SHA-384...) or threat == none
Classical problems (MD5 collisions, ECB, weak PRNG, RSA-1024...) are reported SEPARATELY
in classical_status / flags / CWE so we never mislabel a classical issue as a quantum one.
"""

# canonical id -> catalog entry
CATALOG = {
    # ---------------- asymmetric, Shor-vulnerable ----------------
    "RSA":      dict(family="RSA", primitive=None, threat="shor", standard="RFC 8017 / FIPS 186-5", oid="1.2.840.113549.1.1.1"),
    "DSA":      dict(family="DSA", primitive="signature", threat="shor", standard="FIPS 186-4 (withdrawn in 186-5)", oid="1.2.840.10040.4.1"),
    "ECDSA":    dict(family="ECDSA", primitive="signature", threat="shor", standard="FIPS 186-5", oid="1.2.840.10045.2.1"),
    "Ed25519":  dict(family="EdDSA", primitive="signature", threat="shor", standard="RFC 8032 / FIPS 186-5", oid="1.3.101.112"),
    "Ed448":    dict(family="EdDSA", primitive="signature", threat="shor", standard="RFC 8032 / FIPS 186-5", oid="1.3.101.113"),
    "ECDH":     dict(family="ECDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A", oid="1.2.840.10045.2.1"),
    "ECDHE":    dict(family="ECDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A", oid="1.2.840.10045.2.1"),
    "ECDH-static": dict(family="ECDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A", oid="1.2.840.10045.2.1"),
    "X25519":   dict(family="ECDH", primitive="key-agree", threat="shor", standard="RFC 7748", oid="1.3.101.110"),
    "X448":     dict(family="ECDH", primitive="key-agree", threat="shor", standard="RFC 7748", oid="1.3.101.111"),
    "DH":       dict(family="FFDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A / RFC 7919", oid="1.2.840.10046.2.1"),
    "DHE":      dict(family="FFDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A / RFC 7919", oid="1.2.840.10046.2.1"),
    "DH-static": dict(family="FFDH", primitive="key-agree", threat="shor", standard="NIST SP 800-56A", oid="1.2.840.10046.2.1"),
    "SRP":      dict(family="SRP", primitive="key-agree", threat="shor", standard="RFC 5054", oid=None),
    "SM2":      dict(family="SM2", primitive="signature", threat="shor", standard="GB/T 32918", oid="1.2.156.10197.1.301"),
    "CLASSICAL-SIG": dict(family="RSA/ECDSA", primitive="signature", threat="shor", standard="FIPS 186-5", oid=None),
    # ---------------- post-quantum ----------------
    "ML-KEM":   dict(family="ML-KEM", primitive="kem", threat="none", standard="FIPS 203", oid=None),
    "ML-DSA":   dict(family="ML-DSA", primitive="signature", threat="none", standard="FIPS 204", oid=None),
    "SLH-DSA":  dict(family="SLH-DSA", primitive="signature", threat="none", standard="FIPS 205", oid=None),
    "FN-DSA":   dict(family="FN-DSA", primitive="signature", threat="none", standard="FIPS 206 (draft)", oid=None),
    "LMS":      dict(family="LMS", primitive="signature", threat="none", standard="NIST SP 800-208 / RFC 8554", oid="1.2.840.113549.1.9.16.3.17"),
    "XMSS":     dict(family="XMSS", primitive="signature", threat="none", standard="NIST SP 800-208 / RFC 8391", oid=None),
    "HQC":      dict(family="HQC", primitive="kem", threat="none", standard="NIST selection 2025 (draft)", oid=None),
    "X25519MLKEM768":     dict(family="Hybrid ECDH+ML-KEM", primitive="kem", threat="none", standard="FIPS 203 + RFC 7748 (draft-ietf-tls-ecdhe-mlkem)", oid=None, hybrid=True),
    "SecP256r1MLKEM768":  dict(family="Hybrid ECDH+ML-KEM", primitive="kem", threat="none", standard="FIPS 203 + SP 800-56A (draft-ietf-tls-ecdhe-mlkem)", oid=None, hybrid=True),
    "SecP384r1MLKEM1024": dict(family="Hybrid ECDH+ML-KEM", primitive="kem", threat="none", standard="FIPS 203 + SP 800-56A (draft-ietf-tls-ecdhe-mlkem)", oid=None, hybrid=True),
    "mlkem768x25519":     dict(family="Hybrid ECDH+ML-KEM", primitive="kem", threat="none", standard="FIPS 203 + RFC 7748 (draft-ietf-sshm-mlkem-hybrid-kex)", oid=None, hybrid=True),
    "sntrup761x25519":    dict(family="Hybrid ECDH+NTRU Prime", primitive="kem", threat="none", standard="OpenSSH (not NIST-standardized)", oid=None, hybrid=True, nonstandard=True),
    "X25519Kyber768Draft00": dict(family="Hybrid ECDH+Kyber (pre-standard)", primitive="kem", threat="none", standard="draft-tls-westerbaan-xyber768d00 (obsolete, not FIPS 203)", oid=None, hybrid=True, prestandard=True),
    # ---------------- symmetric ciphers ----------------
    "AES":      dict(family="AES", primitive="block-cipher", threat="grover", standard="FIPS 197", oid=None),
    "3DES":     dict(family="TDEA", primitive="block-cipher", threat="grover", standard="NIST SP 800-67 (withdrawn)", oid="1.2.840.113549.3.7"),
    "DES":      dict(family="DES", primitive="block-cipher", threat="grover", standard="FIPS 46-3 (withdrawn)", oid="1.3.14.3.2.7"),
    "RC4":      dict(family="RC4", primitive="stream-cipher", threat="grover", standard="RFC 7465 (prohibited in TLS)", oid="1.2.840.113549.3.4"),
    "Blowfish": dict(family="Blowfish", primitive="block-cipher", threat="grover", standard="-", oid=None),
    "Camellia": dict(family="Camellia", primitive="block-cipher", threat="grover", standard="RFC 3713", oid=None),
    "Aria":     dict(family="ARIA", primitive="block-cipher", threat="grover", standard="RFC 5794", oid=None),
    "SEED":     dict(family="SEED", primitive="block-cipher", threat="grover", standard="RFC 4269", oid=None),
    "IDEA":     dict(family="IDEA", primitive="block-cipher", threat="grover", standard="-", oid=None),
    "ChaCha20-Poly1305": dict(family="ChaCha20", primitive="ae", threat="grover", standard="RFC 8439", oid="1.2.840.113549.1.9.16.3.18"),
    "NULL":     dict(family="NULL", primitive="other", threat="none", standard="-", oid=None),
    # ---------------- hashes ----------------
    "MD5":      dict(family="MD5", primitive="hash", threat="grover", standard="RFC 1321 / RFC 6151", oid="1.2.840.113549.2.5", out=128),
    "MD4":      dict(family="MD4", primitive="hash", threat="grover", standard="RFC 6150 (historic)", oid="1.2.840.113549.2.4", out=128),
    "SHA-1":    dict(family="SHA-1", primitive="hash", threat="grover", standard="FIPS 180-4", oid="1.3.14.3.2.26", out=160),
    "RIPEMD-160": dict(family="RIPEMD", primitive="hash", threat="grover", standard="ISO/IEC 10118-3", oid="1.3.36.3.2.1", out=160),
    "SHA-224":  dict(family="SHA-2", primitive="hash", threat="grover", standard="FIPS 180-4", oid="2.16.840.1.101.3.4.2.4", out=224),
    "SHA-256":  dict(family="SHA-2", primitive="hash", threat="grover", standard="FIPS 180-4", oid="2.16.840.1.101.3.4.2.1", out=256),
    "SHA-384":  dict(family="SHA-2", primitive="hash", threat="grover", standard="FIPS 180-4", oid="2.16.840.1.101.3.4.2.2", out=384),
    "SHA-512":  dict(family="SHA-2", primitive="hash", threat="grover", standard="FIPS 180-4", oid="2.16.840.1.101.3.4.2.3", out=512),
    "SHA-512/256": dict(family="SHA-2", primitive="hash", threat="grover", standard="FIPS 180-4", oid="2.16.840.1.101.3.4.2.6", out=256),
    "SHA3-256": dict(family="SHA-3", primitive="hash", threat="grover", standard="FIPS 202", oid="2.16.840.1.101.3.4.2.8", out=256),
    "SHA3-384": dict(family="SHA-3", primitive="hash", threat="grover", standard="FIPS 202", oid="2.16.840.1.101.3.4.2.9", out=384),
    "SHA3-512": dict(family="SHA-3", primitive="hash", threat="grover", standard="FIPS 202", oid="2.16.840.1.101.3.4.2.10", out=512),
    "SHAKE128": dict(family="SHA-3", primitive="xof", threat="grover", standard="FIPS 202", oid="2.16.840.1.101.3.4.2.11", out=256),
    "SHAKE256": dict(family="SHA-3", primitive="xof", threat="grover", standard="FIPS 202", oid="2.16.840.1.101.3.4.2.12", out=512),
    "BLAKE2b":  dict(family="BLAKE2", primitive="hash", threat="grover", standard="RFC 7693", oid=None, out=512),
    "BLAKE2s":  dict(family="BLAKE2", primitive="hash", threat="grover", standard="RFC 7693", oid=None, out=256),
    # ---------------- MAC / KDF / RNG ----------------
    "HMAC":     dict(family="HMAC", primitive="mac", threat="grover", standard="FIPS 198-1 / RFC 2104", oid=None),
    "UMAC":     dict(family="UMAC", primitive="mac", threat="grover", standard="RFC 4418", oid=None),
    "CMAC":     dict(family="CMAC", primitive="mac", threat="grover", standard="NIST SP 800-38B", oid=None),
    "Poly1305": dict(family="Poly1305", primitive="mac", threat="grover", standard="RFC 8439", oid=None),
    "PBKDF2":   dict(family="PBKDF2", primitive="kdf", threat="grover", standard="NIST SP 800-132 / RFC 8018", oid="1.2.840.113549.1.5.12"),
    "HKDF":     dict(family="HKDF", primitive="kdf", threat="grover", standard="RFC 5869 / SP 800-56C", oid=None),
    "scrypt":   dict(family="scrypt", primitive="kdf", threat="grover", standard="RFC 7914", oid=None),
    "bcrypt":   dict(family="bcrypt", primitive="kdf", threat="grover", standard="-", oid=None),
    "Argon2":   dict(family="Argon2", primitive="kdf", threat="grover", standard="RFC 9106", oid=None),
    "CSPRNG":   dict(family="CSPRNG", primitive="drbg", threat="none", standard="NIST SP 800-90A / OS entropy", oid=None),
    "NON-CSPRNG": dict(family="PRNG (non-cryptographic)", primitive="drbg", threat="none", standard="-", oid=None),
    "PSK":      dict(family="PSK", primitive="other", threat="grover", standard="RFC 4279", oid=None),
    # ---------------- protocols / transport ----------------
    "TLS":      dict(family="TLS", primitive=None, threat="none", standard="RFC 8446 / RFC 5246", oid=None),
    "SSL":      dict(family="SSL", primitive=None, threat="none", standard="RFC 6176 / RFC 7568 (prohibited)", oid=None),
    "SSH":      dict(family="SSH", primitive=None, threat="none", standard="RFC 4253", oid=None),
    "PLAINTEXT": dict(family="none", primitive=None, threat="none", standard="-", oid=None),
    # ---------------- hygiene / inventory (not algorithms) ----------------
    "UNIDENTIFIED": dict(family="Unidentified protocol", primitive=None, threat="none", standard="-", oid=None),
    "HARDCODED-KEY": dict(family="Secret in source code", primitive=None, threat="none", standard="-", oid=None),
    "LIBRARY":  dict(family="Crypto library", primitive=None, threat="none", standard="-", oid=None),
    "PBKDF1":   dict(family="PBES1", primitive="kdf", threat="grover", standard="RFC 8018 (PBES1, legacy)", oid=None),
    "MD2":      dict(family="MD2", primitive="hash", threat="grover", standard="RFC 6149 (historic)", oid="1.2.840.113549.2.2", out=128),
    "RC2":      dict(family="RC2", primitive="block-cipher", threat="grover", standard="RFC 2268", oid="1.2.840.113549.3.2"),
    "CAST5":    dict(family="CAST5", primitive="block-cipher", threat="grover", standard="RFC 2144", oid=None),
    "SM4":      dict(family="SM4", primitive="block-cipher", threat="grover", standard="GB/T 32907", oid=None),
}

# OIDs that depend on parameters ------------------------------------------------
AES_OIDS = {  # (bits, mode) -> oid
    (128, "ECB"): "2.16.840.1.101.3.4.1.1", (128, "CBC"): "2.16.840.1.101.3.4.1.2", (128, "GCM"): "2.16.840.1.101.3.4.1.6", (128, "CCM"): "2.16.840.1.101.3.4.1.7",
    (192, "ECB"): "2.16.840.1.101.3.4.1.21", (192, "CBC"): "2.16.840.1.101.3.4.1.22", (192, "GCM"): "2.16.840.1.101.3.4.1.26", (192, "CCM"): "2.16.840.1.101.3.4.1.27",
    (256, "ECB"): "2.16.840.1.101.3.4.1.41", (256, "CBC"): "2.16.840.1.101.3.4.1.42", (256, "GCM"): "2.16.840.1.101.3.4.1.46", (256, "CCM"): "2.16.840.1.101.3.4.1.47",
}
MLKEM = {"ML-KEM-512": ("2.16.840.1.101.3.4.4.1", 1), "ML-KEM-768": ("2.16.840.1.101.3.4.4.2", 3), "ML-KEM-1024": ("2.16.840.1.101.3.4.4.3", 5)}
MLDSA = {"ML-DSA-44": ("2.16.840.1.101.3.4.3.17", 2), "ML-DSA-65": ("2.16.840.1.101.3.4.3.18", 3), "ML-DSA-87": ("2.16.840.1.101.3.4.3.19", 5)}
CURVE_OIDS = {"P-256": "1.2.840.10045.3.1.7", "P-384": "1.3.132.0.34", "P-521": "1.3.132.0.35", "secp256k1": "1.3.132.0.10",
              "P-224": "1.3.132.0.33", "brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7", "brainpoolP384r1": "1.3.36.3.3.2.8.1.1.11",
              "brainpoolP512r1": "1.3.36.3.3.2.8.1.1.13"}
CURVE_BITS = {"P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256, "secp256k1": 128, "Curve25519": 128, "Curve448": 224,
              "brainpoolP256r1": 128, "brainpoolP384r1": 192, "brainpoolP512r1": 256}
SIG_OIDS = {  # (alg, padding, hash) -> signature algorithm OID
    ("RSA", "PKCS1v15", "SHA-1"): "1.2.840.113549.1.1.5", ("RSA", "PKCS1v15", "SHA-256"): "1.2.840.113549.1.1.11",
    ("RSA", "PKCS1v15", "SHA-384"): "1.2.840.113549.1.1.12", ("RSA", "PKCS1v15", "SHA-512"): "1.2.840.113549.1.1.13",
    ("RSA", "PKCS1v15", "MD5"): "1.2.840.113549.1.1.4", ("RSA", "PSS", None): "1.2.840.113549.1.1.10",
    ("RSA", "OAEP", None): "1.2.840.113549.1.1.7",
    ("ECDSA", None, "SHA-1"): "1.2.840.10045.4.1", ("ECDSA", None, "SHA-256"): "1.2.840.10045.4.3.2",
    ("ECDSA", None, "SHA-384"): "1.2.840.10045.4.3.3", ("ECDSA", None, "SHA-512"): "1.2.840.10045.4.3.4",
}
HMAC_OIDS = {"SHA-1": "1.2.840.113549.2.7", "SHA-224": "1.2.840.113549.2.8", "SHA-256": "1.2.840.113549.2.9",
             "SHA-384": "1.2.840.113549.2.10", "SHA-512": "1.2.840.113549.2.11"}


def rsa_bits(n):
    """NIST SP 800-57 Pt.1 Table 2 classical strength for RSA / FFDH modulus size."""
    if n is None:
        return None
    for limit, bits in ((15360, 256), (7680, 192), (4096, 152), (3072, 128), (2048, 112), (1024, 80)):
        if n >= limit:
            return bits
    return 40 if n >= 512 else 0
