"""Deterministic fix suggestions for code / config findings (no LLM: same input, same suggestion).

Each rule matches a finding (language + what was found) and rewrites the finding's source
line with a regex. The result goes to finding.context["fix"]:

    {"rule": id, "before": line, "after": new line | "" (delete) | None (note only), "note": ..., "requires": ...}

A rule only rewrites what is safe to change on that one line. When the real fix needs more
(a nonce for GCM, a different API for ML-DSA), the line gets the immediate classical fix and
the note says what else to do. When no line rewrite applies, the suggestion is note-only.
"""
from __future__ import annotations

import re

from ...kb import aws as AWS

PY, JAVA, GO, JS = ("python",), ("java",), ("go",), ("javascript", "typescript", "tsx")
NGINX, APACHE, SSH, TF = ("nginx",), ("apache",), ("sshd_config", "ssh_config"), ("terraform",)

NOTE_JWT_PQ = ("No standardized post-quantum JWT algorithm yet (ML-DSA for JOSE is an IETF draft). "
               "Keep these tokens short-lived and move to ML-DSA once your JWT library supports it.")
NOTE_HARDCODED = "Load the key from a secret manager (AWS Secrets Manager / KMS) or the environment, and rotate the exposed key."
GOOD_TLS12_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
PQ_SSH_KEX = "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256"


def _has(f, *flags):
    return any(x in f.flags for x in flags)


def _alg(f, *algs):
    return f.algorithm in algs


# Fixes run at ingest time, BEFORE classify.py adds flags such as short-key / weak-signature-hash,
# so rules look at the params the scanner observed.
def _short_rsa(f):
    return f.algorithm == "RSA" and (f.params.get("key_bits") or 4096) < 2048


def _sha1_sig(f):
    return f.category in ("signature", "authentication") and f.params.get("hash") in ("SHA-1", "MD5")


# (id, languages, predicate, pattern, replacement, note, requires)
RULES = [
    # ------------------------------------------------------------------ key material at rest (ingest/code/keys.py)
    ("key-file-committed", None, lambda f: f.asset.get("kind") == "key-file" and _has(f, "hardcoded-key"), None, None,
     "Remove this private key from the repository and its history (git filter-repo), revoke and rotate it (anyone with read access "
     "holds a copy), and load keys from a secret manager or HSM at runtime.", None),
    ("cert-reissue", None, lambda f: f.asset.get("kind") == "certificate-file" and f.algorithm in ("RSA", "ECDSA", "DSA", "Ed25519", "Ed448"), None, None,
     "Re-issue: today ECDSA P-384 or RSA-3072 for anything expired or short; plan ML-DSA-65 (FIPS 204) certificates, hybrid or "
     "composite during the transition, as soon as your CA issues them. Long-lived roots and code-signing first.", None),
    ("key-file-pq", None, lambda f: f.asset.get("kind") == "key-file" and f.algorithm in ("RSA", "ECDSA", "DSA", "DH", "Ed25519", "Ed448", "X25519", "X448")
     and f.context.get("format") != "OpenSSH", None, None,
     "Shor-vulnerable key: when it is rotated, move signatures to ML-DSA-65 (FIPS 204) and key transport to ML-KEM-768 (FIPS 203), "
     "or hybrids while peers catch up. Keep the passphrase out of the repository.", None),
    ("ssh-key", None, lambda f: f.asset.get("kind") == "key-file" and f.context.get("format") == "OpenSSH", None, None,
     "Retire RSA keys below 3072 bits and DSA keys; Ed25519 is fine for SSH login today. OpenSSH has no PQ user keys yet: "
     "protect the sessions with mlkem768x25519-sha256 key exchange (OpenSSH >= 9.9, default in 10.0).", None),
    # ------------------------------------------------------------------ hard-coded secrets / JWT
    ("static-iv", None, lambda f: _has(f, "static-iv"), None, None,
     "Generate a fresh random IV / nonce for every encryption (crypto/rand, SecureRandom, os.urandom, crypto.randomBytes) and "
     "store it next to the ciphertext; with GCM / CTR a repeated nonce under the same key leaks the plaintext.", None),
    ("static-salt", None, lambda f: _has(f, "static-salt"), None, None,
     "Use a random 16-byte salt per password / derivation and store it with the hash.", None),
    ("hardcoded-key", None, lambda f: f.algorithm == "HARDCODED-KEY", None, None, NOTE_HARDCODED, None),
    ("jwt-unverified", None, lambda f: _has(f, "signature-not-verified", "unsigned-token"), None, None,
     "Never accept unsigned tokens: verify with the issuer's key and an explicit algorithm allow-list.", None),
    ("jwt-hs-secret", None, lambda f: _has(f, "jwt") and _alg(f, "HMAC") and _has(f, "hardcoded-key"), None, None,
     "JWT HMAC secret is in the source: load a random 256-bit secret from the environment / secret manager and rotate it.", None),
    ("jwt-pq", None, lambda f: _has(f, "jwt") and f.algorithm in ("RSA", "ECDSA", "Ed25519"), None, None, NOTE_JWT_PQ, None),

    # ------------------------------------------------------------------ Python
    ("py-rsa-pkcs1-enc", PY, lambda f: f.category == "encryption" and _alg(f, "RSA") and f.params.get("padding") == "PKCS1v15",
     r"padding\.PKCS1v15\(\)", "padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)",
     "PKCS#1 v1.5 encryption is open to padding-oracle attacks (Bleichenbacher): OAEP now. Quantum fix: replace RSA key "
     "transport with ML-KEM-768 (FIPS 203), e.g. HPKE or a hybrid X25519 + ML-KEM-768 encapsulation.", None),
    ("py-rsa-enc-pq", PY, lambda f: f.category == "encryption" and _alg(f, "RSA"), None, None,
     "RSA key transport is broken by Shor and exposed to harvest-now-decrypt-later: wrap keys with ML-KEM-768 (FIPS 203) "
     "instead, e.g. HPKE or a hybrid X25519 + ML-KEM-768 encapsulation (cryptography >= 47 ships ML-KEM).", None),
    ("py-ecb", PY, lambda f: _has(f, "ecb-mode"), r"modes\.ECB\(\)", "modes.GCM(nonce)",
     "nonce = os.urandom(12), unique per message; store encryptor.tag. Simpler: AESGCM(key).encrypt(nonce, data, None) with a 256-bit key.", None),
    ("py-crypt", PY, lambda f: f.params.get("scheme", "").startswith("METHOD_"), None, None,
     "crypt(3) DES / MD5 schemes are broken and the module is gone in Python 3.13: hash passwords with argon2-cffi "
     "PasswordHasher().hash(password) and verify with .verify(stored, password).", "pip install argon2-cffi"),
    ("py-password-hash", PY, lambda f: _has(f, "password-hashing"),
     r"hashlib\.\w+\((\w+)(?:\.encode\([^)]*\))?\)\.hexdigest\(\)", r"PasswordHasher().hash(\1)",
     "Argon2id (RFC 9106). Rehash existing users on next login; check with PasswordHasher().verify(stored, password).",
     "pip install argon2-cffi; from argon2 import PasswordHasher"),
    ("py-weak-hash", PY, lambda f: f.category == "hash" and _alg(f, "MD5", "SHA-1"), r"hashlib\.(md5|sha1)\(", "hashlib.sha256(",
     "If this digest protects downloads or artifacts, sign them instead: a bare hash only detects accidental changes.", None),
    ("py-random", PY, lambda f: _alg(f, "NON-CSPRNG"), r"bytes\(random\.getrandbits\(8\) for _ in range\((\w+)\)\)", r"secrets.token_bytes(\1)",
     "Use the secrets module (secrets.token_bytes / token_urlsafe) for anything an attacker must not guess.", "import secrets"),
    ("py-rsa-size", PY, _short_rsa, r"key_size=\d+", "key_size=3072",
     "Interim classical fix. Quantum fix: ML-DSA-65 (FIPS 204), e.g. liboqs-python oqs.Signature('ML-DSA-65'), dual-signing during the transition.", None),
    ("py-sig-hash", PY, _sha1_sig, r"hashes\.SHA1\(\)", "hashes.SHA256()",
     "Interim classical fix; the signature itself must still move to ML-DSA (FIPS 204).", None),
    ("py-weak-cipher", PY, lambda f: f.category == "encryption" and _alg(f, "DES", "3DES", "RC2", "RC4", "Blowfish", "CAST5"),
     r"\b(?:DES3?|ARC2|ARC4|Blowfish|CAST)\.new\((\w+),\s*\w+\.MODE_\w+", r"AES.new(\1, AES.MODE_GCM",
     "Legacy cipher: use AES-256-GCM with a 32-byte key and a fresh nonce (cipher.nonce) per message.", "from Crypto.Cipher import AES"),
    ("py-small-curve", PY, lambda f: _alg(f, "ECDSA", "ECDH") and f.params.get("curve") in ("P-192", "P-224", "sect163k1", "sect163r2"),
     r"ec\.(?:SECP192R1|SECP224R1|SECT163K1|SECT163R2)", "ec.SECP384R1",
     "Interim classical fix (curve below 128-bit security); the quantum fix is ML-DSA (FIPS 204).", None),
    ("py-dsa", PY, lambda f: _alg(f, "DSA"), None, None,
     "DSA signature generation is no longer approved (FIPS 186-5): use Ed25519 / ECDSA P-384 now and ML-DSA-65 for post-quantum.", None),
    ("py-tls-ciphers", PY, lambda f: re.search(r"set_cipher|ciphers=", f.location.get("snippet", "")) is not None,
     r"""(set_ciphers\(|set_cipher_list\(b?|ciphers=)(['"])[^'"]*\2""", rf"\g<1>\g<2>{GOOD_TLS12_CIPHERS}\g<2>",
     "TLS 1.2 key exchange stays classical whatever the list: post-quantum needs TLS 1.3 with X25519MLKEM768 (OpenSSL >= 3.5).", None),
    ("py-pbkdf2", PY, lambda f: _alg(f, "PBKDF2") and (f.params.get("iterations") or 10**9) < 600_000,
     r"(pbkdf2_hmac\([^,]+,[^,]+,[^,]+,\s*)[\w_]+|(\.using\()\)", lambda f: r"\g<1>600_000" if "pbkdf2_hmac" in f.location.get("snippet", "")
     else r"\g<2>rounds=600_000)", "OWASP: >= 600,000 iterations of PBKDF2-HMAC-SHA256 (or Argon2id).", None),
    ("py-ed25519", PY, lambda f: _alg(f, "Ed25519", "Ed448"), None, None,
     "EdDSA is broken by Shor like RSA: migrate to ML-DSA-65 (FIPS 204), e.g. liboqs-python oqs.Signature('ML-DSA-65').", None),

    # ------------------------------------------------------------------ Java
    ("java-ecb", JAVA, lambda f: _has(f, "ecb-mode"), r'"AES(?:/ECB/\w+)?"', '"AES/GCM/NoPadding"',
     "Initialise with new GCMParameterSpec(128, iv) and a fresh 12-byte IV per message; use a 256-bit key. "
     "If the transformation comes from a constant, change the constant.", None),
    ("java-password-hash", JAVA, lambda f: _has(f, "password-hashing"), None, None,
     "Replace the digest with Argon2id, e.g. Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(password).", "Spring Security >= 5.8 or BouncyCastle Argon2"),
    ("java-weak-hash", JAVA, lambda f: f.category == "hash" and _alg(f, "MD5", "SHA-1"), r'getInstance\("(?:MD5|SHA-?1)"\)', 'getInstance("SHA-256")',
     "If the algorithm name comes from a variable or a .properties file, change it where it is set.", None),
    ("java-pbe-iterations", JAVA, lambda f: _alg(f, "PBKDF2") and (f.params.get("iterations") or 10**9) < 600_000,
     r"(PBEParameterSpec\([^,]+,\s*)[\w.]+(\s*\))", r"\g<1>600_000\2", "OWASP: >= 600,000 iterations (PBKDF2-HMAC-SHA256), or Argon2id.", None),
    ("java-rsa-nopad", JAVA, lambda f: f.params.get("padding") == "none", r'"RSA/ECB/NoPadding"', '"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"',
     "Textbook RSA is deterministic and malleable. Post-quantum: ML-KEM (KEM.getInstance(\"ML-KEM\"), JDK 24+) for key transport.", None),
    ("java-weak-cipher", JAVA, lambda f: f.category == "encryption" and _alg(f, "DES", "3DES", "RC2", "RC4", "Blowfish", "CAST5"),
     r'Cipher\.getInstance\("(?:DES|DESede|TripleDES|RC2|ARC2|RC4|ARCFOUR|ARC4|Blowfish|CAST5)[^"]*"', 'Cipher.getInstance("AES/GCM/NoPadding"',
     "Legacy cipher: AES-256-GCM with a fresh 12-byte IV (GCMParameterSpec(128, iv)). If the instance is replaced before use "
     "(flag overwritten-before-use), just delete this line.", None),
    ("java-null-cipher", JAVA, lambda f: _alg(f, "NULL"), r"new (?:javax\.crypto\.)?NullCipher\(\)", 'Cipher.getInstance("AES/GCM/NoPadding")',
     "NullCipher does not encrypt anything. Init the AES-GCM cipher with a 256-bit key and new GCMParameterSpec(128, iv).", None),
    ("java-keygen-size", JAVA, lambda f: f.context.get("api") == "KeyGenerator" and _alg(f, "AES") and (f.params.get("key_bits") or 256) < 128,
     r"\.init\(\s*\d+\s*\)", ".init(256)", "AES keys are 128, 192 or 256 bits; 256 also keeps a 128-bit margin against Grover.", None),
    ("java-keygen", JAVA, lambda f: f.category in ("encryption", "key") and f.context.get("api") == "KeyGenerator",
     r'KeyGenerator\.getInstance\("\w+"\)', 'KeyGenerator.getInstance("AES")', "Then keyGen.init(256) and use AES/GCM/NoPadding.", None),
    ("java-digestutils", JAVA, lambda f: f.category == "hash" and f.context.get("api") == "DigestUtils",
     r"DigestUtils\.(?:get)?(?:md2|md5|sha1?|Md2|Md5|Sha1?)(Hex|Digest)?\(", r"DigestUtils.sha256\1(", None, None),
    ("java-random", JAVA, lambda f: _alg(f, "NON-CSPRNG"), r"new (?:java\.util\.)?Random\(\)", "new java.security.SecureRandom()",
     "java.util.Random is predictable (48-bit LCG); SecureRandom for tokens, session ids and keys.", None),
    ("java-kpg-size", JAVA, lambda f: _short_rsa(f) or (_alg(f, "DSA", "DH") and (f.params.get("key_bits") or 4096) < 2048),
     r"(\.initialize\()\s*\d+", r"\g<1>3072",
     "Interim classical fix. Quantum fix: KeyPairGenerator.getInstance(\"ML-DSA-65\") for signatures / KEM \"ML-KEM\" for key exchange.",
     "JDK 24+ (JEP 496 / 497) for the post-quantum fix"),
    ("java-kpg-pq", JAVA, lambda f: f.context.get("api") == "KeyPairGenerator" and _alg(f, "RSA", "ECDSA", "DSA", "DH", "Ed25519"), None, None,
     "Broken by Shor at any size: KeyPairGenerator.getInstance(\"ML-DSA-65\") (signatures) or KEM.getInstance(\"ML-KEM\") (key exchange).",
     "JDK 24+ (JEP 496 / 497)"),
    ("java-keypair-pq", JAVA, lambda f: f.category == "signature" and _alg(f, "RSA", "ECDSA", "DSA", "Ed25519"),
     r'KeyPairGenerator\.getInstance\("(?:RSA|EC|DSA|Ed25519|EdDSA)"\)', 'KeyPairGenerator.getInstance("ML-DSA-65")',
     "ML-DSA (FIPS 204) is built into the JDK; Signature.getInstance(\"ML-DSA\") for signing.", "JDK 24+ (JEP 497)"),
    ("java-sig-pq", JAVA, lambda f: f.category == "signature" and _alg(f, "RSA", "ECDSA", "DSA", "Ed25519"),
     r'Signature\.getInstance\("(?:\w+with(?:RSA|ECDSA|DSA)|Ed25519|EdDSA)"\)', 'Signature.getInstance("ML-DSA")',
     "Generate the key pair with KeyPairGenerator.getInstance(\"ML-DSA-65\").", "JDK 24+ (JEP 497)"),
    ("java-kex-pq", JAVA, lambda f: f.category == "key-exchange" and _alg(f, "ECDH", "DH", "X25519"),
     r'KeyAgreement\.getInstance\("\w+"\)', 'KEM.getInstance("ML-KEM")',
     "KEM API: the sender calls encapsulate(), the receiver decapsulate(); there is no shared doPhase().", "JDK 24+ (JEP 496)"),

    ("py-tls-protocol", PY, lambda f: f.category == "protocol", r"\bssl\.PROTOCOL_(?:SSLv[23]|TLSv1(?:_1)?)\b", "ssl.PROTOCOL_TLS_CLIENT",
     "PROTOCOL_TLS_CLIENT negotiates TLS 1.2 / 1.3 only and checks certificates (use PROTOCOL_TLS_SERVER on the server side).", None),
    ("py-tls-min", PY, lambda f: f.category == "protocol", r"\bTLSVersion\.(?:SSLv3|TLSv1(?:_1)?)\b", "TLSVersion.TLSv1_2",
     "TLS 1.0 / 1.1 are deprecated (RFC 8996).", None),
    ("py-openssl-method", PY, lambda f: f.category == "protocol", r"\bSSL\.(?:SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)_METHOD\b", "SSL.TLS_METHOD",
     "Then ctx.set_min_proto_version(SSL.TLS1_2_VERSION).", None),

    # ------------------------------------------------------------------ Go
    ("go-ecb", GO, lambda f: _has(f, "ecb-mode"), None, None,
     "Wrap the block with gcm, _ := cipher.NewGCM(block) and use gcm.Seal(nil, nonce, plaintext, nil) with a random 12-byte nonce; "
     "never encrypt block by block. Use a 32-byte key.", None),
    ("go-password-hash", GO, lambda f: _has(f, "password-hashing"), r"\b(?:md5|sha1)\.Sum\((.*)\)\s*$", r"argon2.IDKey(\1, salt, 1, 64*1024, 4, 32)",
     "Argon2id with a random 16-byte salt stored next to the hash.", "golang.org/x/crypto/argon2"),
    ("go-weak-hash", GO, lambda f: f.category == "hash" and _alg(f, "MD5", "SHA-1"), r"\b(?:md5|sha1)\.Sum\(", "sha256.Sum256(",
     "Import crypto/sha256; the result is [32]byte.", None),
    ("go-random", GO, lambda f: _alg(f, "NON-CSPRNG"), None, None,
     'Import "crypto/rand" instead of "math/rand": rand.Read has the same signature.', None),
    ("go-rsa-size", GO, lambda f: _short_rsa(f) and "GenerateKey" in (f.context.get("api") or ""),
     r"rsa\.GenerateKey\(([^,]+),\s*\d+\)", r"rsa.GenerateKey(\1, 3072)",
     "Interim classical fix. Quantum fix: ML-DSA-65, e.g. mldsa65.GenerateKey(rand.Reader).", "github.com/cloudflare/circl/sign/mldsa/mldsa65"),
    ("go-sig-hash", GO, _sha1_sig, r"crypto\.SHA1\b", "crypto.SHA256",
     "Hash the message with sha256.Sum256 too; the signature itself must still move to ML-DSA.", None),
    ("go-sha224", GO, lambda f: _alg(f, "SHA-224", "SHA3-224"), r"\b(sha3\.|sha256\.)(Sum|New)224\(", r"\1\g<2>256(",
     "224-bit digests give only 112-bit collision resistance against Grover-assisted attacks; the result size changes to 32 bytes.", None),
    ("go-rsa-pq", GO, lambda f: _alg(f, "RSA") and "GenerateKey" in (f.context.get("api") or ""), None, None,
     "RSA is broken by Shor at any size: plan ML-DSA-65 (circl mldsa65) for signatures / ML-KEM (crypto/mlkem) for key transport.",
     "github.com/cloudflare/circl/sign/mldsa/mldsa65"),
    ("go-ed25519", GO, lambda f: _alg(f, "Ed25519"), None, None,
     "Ed25519 is broken by Shor like RSA: migrate to ML-DSA-65 (mldsa65.GenerateKey / mldsa65.SignTo).", "github.com/cloudflare/circl/sign/mldsa/mldsa65"),
    ("go-kex-pq", GO, lambda f: f.category == "key-exchange" and _alg(f, "ECDH", "X25519"), r"ecdh\.\w+\(\)\.GenerateKey\([^)]*\)", "mlkem.GenerateKey768()",
     "ML-KEM is a KEM: the peer calls Encapsulate() on your public key and you Decapsulate() the ciphertext.", "Go 1.24+ (crypto/mlkem)"),

    ("go-tls-version", GO, lambda f: f.category == "protocol", r"(MinVersion:\s*)\w+\.Version(?:SSL30|TLS10|TLS11)\b", r"\1tls.VersionTLS12",
     "TLS 1.0 / 1.1 are deprecated (RFC 8996). MinVersion 0 also means TLS 1.2 on Go 1.22+.", None),
    ("go-tls-max", GO, lambda f: f.category == "protocol", r"(MaxVersion:\s*)\w+\.Version(?:SSL30|TLS10|TLS11)\b", r"\1tls.VersionTLS13",
     "Do not cap the version: TLS 1.3 is the only version where Go negotiates the X25519MLKEM768 hybrid (Go 1.24+).", None),
    ("go-tls-suites", GO, lambda f: "crypto/tls.Config" == f.context.get("api"), None, None,
     "Drop the TLS_RSA_WITH_* / 3DES / RC4 suites (no forward secrecy); keep ECDHE + AES-GCM / ChaCha20. "
     "TLS 1.3 suites are not configurable and always forward-secret.", None),

    # ------------------------------------------------------------------ JavaScript / TypeScript
    ("js-forge-cipher", JS, lambda f: f.context.get("api") == "node-forge" and f.category == "encryption" and _alg(f, "3DES", "DES", "RC2"),
     r"createCipher\('(?:3DES|DES)-\w+'", "createCipher('AES-GCM'",
     "Use a 32-byte key (forge.random.getBytesSync(32)) and a fresh 12-byte IV per message; read the tag from cipher.mode.tag.", None),
    ("js-node-rsa", JS, lambda f: f.context.get("api") == "node-rsa" and _short_rsa(f), r"(new NodeRSA\(\{\s*b:\s*)\d+", r"\g<1>3072",
     "Interim classical fix; RSA is broken by Shor at any size: plan ML-DSA for signatures.", None),
    ("js-session-secret", JS, lambda f: f.context.get("api") == "express-session" and _has(f, "hardcoded-key"), None, None,
     "secret: process.env.SESSION_SECRET (at least 32 random bytes); pass an array [new, old] to rotate without logging users out.", None),
    ("js-ecb", JS, lambda f: _has(f, "ecb-mode"), r"createCipheriv\('aes-\d+-ecb',\s*([^,]+),\s*null\)", r"createCipheriv('aes-256-gcm', \1, iv)",
     "32-byte key; iv = crypto.randomBytes(12), unique per message; store cipher.getAuthTag() with the ciphertext.", None),
    ("js-password-hash", JS, lambda f: _has(f, "password-hashing"), r"createHash\('\w+'\)\.update\((\w+)\)\.digest\('\w+'\)",
     r"await argon2.hash(\1, { type: argon2.argon2id })", "The function becomes async; check with argon2.verify(stored, password).", "npm install argon2"),
    ("js-weak-hash", JS, lambda f: f.category == "hash" and _alg(f, "MD5", "SHA-1"), r"""(createHash\(|digest\()(['"])(?:md5|sha1|SHA-1)\2""", r"\1\2SHA-256\2",
     None, None),
    ("js-random", JS, lambda f: _alg(f, "NON-CSPRNG"), r"Math\.random\(\)\.toString\(36\)\.slice\(2\)", "crypto.randomBytes(32).toString('base64url')",
     "Math.random() is predictable; use crypto.randomBytes / crypto.getRandomValues.", None),
    ("js-pbkdf2", JS, lambda f: _alg(f, "PBKDF2") and ((f.params.get("iterations") or 0) < 600_000 or f.params.get("hash") in ("SHA-1", "MD5")),
     r"pbkdf2Sync\(([^,]+),\s*([^,]+),\s*[\d_]+,\s*(\d+),\s*'\w+'\)", r"pbkdf2Sync(\1, \2, 600000, \3, 'sha256')",
     "OWASP: >= 600,000 iterations of PBKDF2-HMAC-SHA256 (or Argon2id).", None),
    ("js-rsa-pq", JS, lambda f: _alg(f, "RSA") and "generateKeyPair" in (f.context.get("api") or ""),
     r"generateKeyPair(Sync)?\('rsa',\s*\{[^}]*\}\)", r"generateKeyPair\1('ml-dsa-65')",
     "Sign with crypto.sign(null, data, privateKey).", "Node.js >= 24.7 built with OpenSSL >= 3.5"),
    ("js-sig-hash", JS, _sha1_sig, r"createSign\('RSA-SHA1'\)", "createSign('RSA-SHA256')",
     "Interim classical fix; move the signature to ML-DSA-65 (generateKeyPair('ml-dsa-65') + crypto.sign).", None),
    ("js-webcrypto-aes", JS, lambda f: _alg(f, "AES") and f.params.get("mode") == "CBC" and "subtle" in (f.context.get("api") or ""),
     r"name:\s*'AES-CBC',\s*length:\s*128", "name: 'AES-GCM', length: 256",
     "AES-GCM needs a fresh 12-byte iv per encrypt() call.", None),
    ("js-webcrypto-pq", JS, lambda f: f.algorithm in ("RSA", "ECDSA", "ECDH", "X25519", "Ed25519") and "subtle" in (f.context.get("api") or ""), None, None,
     "Browsers' WebCrypto has no standardized ML-KEM / ML-DSA yet: use a vetted library (e.g. @noble/post-quantum) or keep the "
     "key exchange server-side behind TLS 1.3 with X25519MLKEM768.", None),

    ("aes-key-size", None, lambda f: _alg(f, "AES") and f.params.get("key_bits") is None and f.source == "code", None, None,
     "Key size not visible here (assumed 128-bit): make sure the key is 256-bit (32 bytes) for 128-bit post-quantum security.", None),

    # ------------------------------------------------------------------ nginx / Apache
    ("nginx-protocols", NGINX, lambda f: f.category == "protocol", r"ssl_protocols\s+[^;]+;", "ssl_protocols TLSv1.2 TLSv1.3;", None, None),
    ("nginx-pq-unreachable", NGINX, lambda f: _has(f, "pq-unreachable"), None, None,
     "Enable TLS 1.3 (ssl_protocols TLSv1.2 TLSv1.3;): the hybrid group only exists in TLS 1.3.", None),
    ("nginx-groups", NGINX, lambda f: _has(f, "pq-not-configured"), r"ssl_ecdh_curve\s+[^;]+;", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;",
     "Clients without ML-KEM fall back to X25519 / P-256.", "nginx linked against OpenSSL >= 3.5"),
    ("nginx-ecdhe", NGINX, lambda f: _alg(f, "ECDHE"), None, None,
     "TLS 1.2 key exchange stays classical whatever the cipher list: post-quantum needs TLS 1.3 + ssl_ecdh_curve X25519MLKEM768.", None),
    ("nginx-ciphers", NGINX, lambda f: f.location.get("snippet", "").startswith("ssl_ciphers") and not _alg(f, "ECDHE"), r"ssl_ciphers\s+[^;]+;",
     f"ssl_ciphers {GOOD_TLS12_CIPHERS};", None, None),
    ("apache-protocols", APACHE, lambda f: f.category == "protocol", r"SSLProtocol\s+.*", "SSLProtocol -all +TLSv1.2 +TLSv1.3", None, None),
    ("apache-groups", APACHE, lambda f: _has(f, "pq-not-configured"), r"(SSLOpenSSLConfCmd\s+(?:Curves|Groups)\s+)\S+", r"\1X25519MLKEM768:X25519:secp384r1",
     None, "mod_ssl linked against OpenSSL >= 3.5"),
    ("apache-ciphers", APACHE, lambda f: f.location.get("snippet", "").lower().startswith("sslciphersuite"), r"(SSLCipherSuite\s+(?:SSL\s+)?)\S+",
     rf"\g<1>{GOOD_TLS12_CIPHERS}", None, None),

    # ------------------------------------------------------------------ OpenSSH
    ("ssh-kex", SSH, lambda f: _has(f, "pq-capable-not-enabled", "sha1-kex"), r"^(\s*KexAlgorithms\s+).*$", rf"\g<1>{PQ_SSH_KEX}",
     "Or delete the line: OpenSSH's default list is already post-quantum.", "OpenSSH >= 9.9 (mlkem768x25519-sha256)"),
    ("ssh-ciphers", SSH, lambda f: f.category == "encryption", r"^(\s*Ciphers\s+).*$", r"\g<1>chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr", None, None),
    ("ssh-macs", SSH, lambda f: f.category == "mac", r"^(\s*MACs\s+).*$", r"\g<1>hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com", None, None),
    ("ssh-rsa-sha1", SSH, _sha1_sig, r"^.*\+ssh-rsa\s*$", "",
     "Delete the line: clients can use rsa-sha2-256/512 (OpenSSH >= 7.2) or an Ed25519 key.", None),
    ("ssh-hostkey", SSH, lambda f: f.category == "authentication" and "HostKey" in (f.location.get("symbol") or ""), None, None,
     "OpenSSH has no post-quantum host-key signatures yet: keep Ed25519, retire RSA host keys when clients allow.", None),

    # ------------------------------------------------------------------ Terraform
    ("tf-elb-policy", TF, lambda f: "ssl_policy" in f.location.get("snippet", "") and f.context.get("ssl_policy") != AWS.RECOMMENDED_POLICY,
     r'(ssl_policy\s*=\s*).*$', rf'\g<1>"{AWS.RECOMMENDED_POLICY}"', "TLS 1.3 with hybrid ML-KEM groups, TLS 1.2 fallback with AEAD only.", None),
    ("tf-kms-sign", TF, lambda f: f.category == "signature" and _alg(f, "RSA", "ECDSA"), r'(customer_master_key_spec\s*=\s*)"[^"]+"',
     lambda f: rf'\g<1>"{"ML_DSA_87" if "long-lived" in f.flags else "ML_DSA_65"}"',
     "New key, signing algorithm ML_DSA_SHAKE_256; dual-sign with the old key while verifiers migrate.", "AWS KMS ML-DSA (2025)"),
    ("tf-tls-key", TF, lambda f: f.category == "key" and _alg(f, "ECDSA", "RSA"), r'^(\s*)algorithm(\s*)=\s*"ECDSA"\s*$',
     r'\1algorithm\2= "ECDSA"\n\1ecdsa_curve = "P384"', "Interim: P-224 is below 128-bit security; the key is still classical (Shor).", None),
    ("tf-cloudfront", TF, lambda f: f.category == "protocol" and "minimum_protocol_version" in f.location.get("snippet", ""),
     r'(minimum_protocol_version\s*=\s*)"[^"]+"', r'\1"TLSv1.2_2021"', None, None),
    ("tf-plaintext", TF, lambda f: _alg(f, "PLAINTEXT"), None, None,
     f'Serve HTTPS (protocol = "HTTPS", ssl_policy = "{AWS.RECOMMENDED_POLICY}") or redirect HTTP to HTTPS.', None),
    ("tf-acm", TF, lambda f: f.category == "certificate", None, None,
     'Set key_algorithm = "EC_secp384r1" for new certificates; public CAs do not issue ML-DSA certificates yet.', None),
]


def suggest(f, line: str) -> dict | None:
    """First matching rule that rewrites `line` (indentation kept) -> fix dict; else the first matching note; else None."""
    lang = f.asset.get("language") or f.context.get("language")
    note_only = None
    for rid, langs, when, pattern, repl, note, requires in RULES:
        if langs and lang not in langs:
            continue
        try:
            if not when(f):
                continue
        except (TypeError, AttributeError):
            continue
        if pattern:
            new, n = re.subn(pattern, repl(f) if callable(repl) else repl, line, count=1)
            if n and new != line:
                return dict(rule=rid, before=line, after=new, note=note, requires=requires)
        if note and note_only is None:
            note_only = dict(rule=rid, before=line, after=None, note=note, requires=requires)
    return note_only


def annotate(findings: list, path: str) -> None:
    """Attach context["fix"] to the findings of one file."""
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return
    for f in findings:
        ln = f.location.get("line")
        if isinstance(ln, int) and 0 < ln <= len(lines):
            fix = suggest(f, lines[ln - 1])
            if fix:
                f.context["fix"] = fix
