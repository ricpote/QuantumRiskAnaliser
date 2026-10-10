"""SSH algorithm registry (RFC 4253 / 8731 / 9142 + OpenSSH extensions).

Negotiation rule (RFC 4253 7.1): for each list, the chosen algorithm is the FIRST
algorithm in the CLIENT's list that is also present in the SERVER's list.
"""
from __future__ import annotations

# pseudo-algorithms that are NOT real crypto: never report them
PSEUDO = {"ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com",
          "kex-strict-c", "kex-strict-s"}

KEX = {
    "diffie-hellman-group1-sha1": ("DH", {"key_bits": 1024, "group": "modp1024 (Oakley 2)", "hash": "SHA-1"}),
    "diffie-hellman-group14-sha1": ("DH", {"key_bits": 2048, "group": "modp2048 (group14)", "hash": "SHA-1"}),
    "diffie-hellman-group14-sha256": ("DH", {"key_bits": 2048, "group": "modp2048 (group14)", "hash": "SHA-256"}),
    "diffie-hellman-group16-sha512": ("DH", {"key_bits": 4096, "group": "modp4096 (group16)", "hash": "SHA-512"}),
    "diffie-hellman-group18-sha512": ("DH", {"key_bits": 8192, "group": "modp8192 (group18)", "hash": "SHA-512"}),
    "diffie-hellman-group-exchange-sha1": ("DH", {"key_bits": None, "group": "gex", "hash": "SHA-1"}),
    "diffie-hellman-group-exchange-sha256": ("DH", {"key_bits": None, "group": "gex", "hash": "SHA-256"}),
    "ecdh-sha2-nistp256": ("ECDH", {"curve": "P-256", "hash": "SHA-256"}),
    "ecdh-sha2-nistp384": ("ECDH", {"curve": "P-384", "hash": "SHA-384"}),
    "ecdh-sha2-nistp521": ("ECDH", {"curve": "P-521", "hash": "SHA-512"}),
    "curve25519-sha256": ("X25519", {"curve": "Curve25519", "hash": "SHA-256"}),
    "curve25519-sha256@libssh.org": ("X25519", {"curve": "Curve25519", "hash": "SHA-256"}),
    "curve448-sha512": ("X448", {"curve": "Curve448", "hash": "SHA-512"}),
    # post-quantum hybrids
    "sntrup761x25519-sha512@openssh.com": ("sntrup761x25519", {"parameter_set": "sntrup761", "curve": "Curve25519", "hash": "SHA-512"}),
    "sntrup761x25519-sha512": ("sntrup761x25519", {"parameter_set": "sntrup761", "curve": "Curve25519", "hash": "SHA-512"}),
    "mlkem768x25519-sha256": ("mlkem768x25519", {"parameter_set": "ML-KEM-768", "curve": "Curve25519", "hash": "SHA-256"}),
    "mlkem768nistp256-sha256": ("SecP256r1MLKEM768", {"parameter_set": "ML-KEM-768", "curve": "P-256", "hash": "SHA-256"}),
    "mlkem1024nistp384-sha384": ("SecP384r1MLKEM1024", {"parameter_set": "ML-KEM-1024", "curve": "P-384", "hash": "SHA-384"}),
}

HOSTKEY = {
    "ssh-rsa": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-1"}),          # RSA with SHA-1 signatures
    "rsa-sha2-256": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-256"}),
    "rsa-sha2-512": ("RSA", {"padding": "PKCS1v15", "hash": "SHA-512"}),
    "ssh-dss": ("DSA", {"key_bits": 1024, "hash": "SHA-1"}),
    "ecdsa-sha2-nistp256": ("ECDSA", {"curve": "P-256", "hash": "SHA-256"}),
    "ecdsa-sha2-nistp384": ("ECDSA", {"curve": "P-384", "hash": "SHA-384"}),
    "ecdsa-sha2-nistp521": ("ECDSA", {"curve": "P-521", "hash": "SHA-512"}),
    "ssh-ed25519": ("Ed25519", {}),
    "ssh-ed448": ("Ed448", {}),
    "sk-ssh-ed25519@openssh.com": ("Ed25519", {"hardware": "FIDO"}),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", {"curve": "P-256", "hardware": "FIDO"}),
}

CIPHER = {
    "aes128-ctr": ("AES", {"key_bits": 128, "mode": "CTR"}),
    "aes192-ctr": ("AES", {"key_bits": 192, "mode": "CTR"}),
    "aes256-ctr": ("AES", {"key_bits": 256, "mode": "CTR"}),
    "aes128-cbc": ("AES", {"key_bits": 128, "mode": "CBC"}),
    "aes192-cbc": ("AES", {"key_bits": 192, "mode": "CBC"}),
    "aes256-cbc": ("AES", {"key_bits": 256, "mode": "CBC"}),
    "aes128-gcm@openssh.com": ("AES", {"key_bits": 128, "mode": "GCM"}),
    "aes256-gcm@openssh.com": ("AES", {"key_bits": 256, "mode": "GCM"}),
    "chacha20-poly1305@openssh.com": ("ChaCha20-Poly1305", {"key_bits": 256}),
    "3des-cbc": ("3DES", {"key_bits": 168, "mode": "CBC"}),
    "blowfish-cbc": ("Blowfish", {"key_bits": 128, "mode": "CBC"}),
    "arcfour": ("RC4", {"key_bits": 128}),
    "arcfour128": ("RC4", {"key_bits": 128}),
    "arcfour256": ("RC4", {"key_bits": 256}),
    "none": ("NULL", {}),
}

MAC = {
    "hmac-sha1": ("HMAC", {"hash": "SHA-1"}),
    "hmac-sha1-96": ("HMAC", {"hash": "SHA-1", "truncated": 96}),
    "hmac-md5": ("HMAC", {"hash": "MD5"}),
    "hmac-md5-96": ("HMAC", {"hash": "MD5", "truncated": 96}),
    "hmac-sha2-256": ("HMAC", {"hash": "SHA-256"}),
    "hmac-sha2-512": ("HMAC", {"hash": "SHA-512"}),
    "hmac-sha1-etm@openssh.com": ("HMAC", {"hash": "SHA-1", "etm": True}),
    "hmac-sha2-256-etm@openssh.com": ("HMAC", {"hash": "SHA-256", "etm": True}),
    "hmac-sha2-512-etm@openssh.com": ("HMAC", {"hash": "SHA-512", "etm": True}),
    "umac-64@openssh.com": ("UMAC", {"tag_bits": 64}),
    "umac-128@openssh.com": ("UMAC", {"tag_bits": 128}),
    "umac-64-etm@openssh.com": ("UMAC", {"tag_bits": 64, "etm": True}),
    "umac-128-etm@openssh.com": ("UMAC", {"tag_bits": 128, "etm": True}),
}

AEAD_CIPHERS = {"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}


def negotiate(client: list[str], server: list[str]) -> str | None:
    """RFC 4253 7.1: first client algorithm that the server also supports."""
    srv = set(server)
    for alg in client:
        if alg in PSEUDO:
            continue
        if alg in srv:
            return alg
    return None


def clean(algs: list[str]) -> list[str]:
    return [a for a in algs if a and a not in PSEUDO]
