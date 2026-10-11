"""Inventory recall on real projects, without labels: find every line that calls a cryptographic API (by pattern) and
check whether QuantumTrace reported anything on it. An uncovered line is a candidate miss: an API, a library or a
pattern the scanner does not know yet. Production code only (test folders, vendored and minified code are skipped);
comments and imports are not uses. Random-number APIs are left out on purpose: QuantumTrace inventories them only
where the value is used for security.

    python scripts/recall_audit.py <projects-dir> [--misses] [--per-api]
"""
from __future__ import annotations

import collections
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402
from quantumtrace.ingest.code.common import is_test_path  # noqa: E402

PY, JAVA, GO, JS = (".py",), (".java",), (".go",), (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
APIS = [  # (language extensions, API name, pattern on the line)
    (PY, "hashlib", r"\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\w+|blake2\w|new|pbkdf2_hmac|scrypt)\s*\("),
    (PY, "hmac.new", r"\bhmac\.(new|digest)\s*\("),
    (PY, "pycryptodome", r"\b(AES|DES3?|ARC4|Blowfish|ChaCha20|Salsa20|PKCS1_OAEP|PKCS1_v1_5|pss)\.new\s*\(|\bRSA\.(generate|import_key|importKey)\s*\("),
    (PY, "cryptography", r"\b(Cipher|AESGCM|ChaCha20Poly1305|Fernet|PBKDF2HMAC|Scrypt|HKDF)\s*\(|\b(rsa|ec|dsa|ed25519|x25519)\.\w*generate\w*\s*\("),
    (PY, "jwt", r"\bjwt\.(encode|decode)\s*\("),
    (PY, "ssl", r"\bssl\.(wrap_socket|SSLContext|create_default_context|_create_unverified_context)\s*\("),
    (PY, "passwords", r"\b(bcrypt\.(hashpw|gensalt)|PasswordHasher|make_password|generate_password_hash|pbkdf2_sha\d+\.(hash|using))\s*\("),
    (JAVA, "jca getInstance", r"\b(MessageDigest|Cipher|Mac|KeyGenerator|KeyPairGenerator|Signature|SecretKeyFactory|KeyAgreement)\.getInstance\s*\("),
    (JAVA, "jca specs", r"\bnew\s+(SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|PBEParameterSpec)\s*\("),
    (JAVA, "DigestUtils", r"\bDigestUtils\.\w+\s*\("),
    (JAVA, "jwt", r"\b(Jwts\.(builder|parser\w*)|JWT\.(create|require)|Algorithm\.(HMAC|RSA|ECDSA)\w*)\s*\("),
    (JAVA, "tls", r"\bSSLContext\.getInstance\s*\("),
    (JAVA, "passwords", r"\bnew\s+(BCryptPasswordEncoder|Pbkdf2PasswordEncoder|SCryptPasswordEncoder|Argon2PasswordEncoder)\s*\(|\bBCrypt\.(hashpw|gensalt)\s*\("),
    (GO, "hash", r"\b(md5|sha1|sha256|sha512|sha3)\.(New\w*|Sum\w*)\s*\("),
    (GO, "cipher", r"\b(aes|des|rc4|chacha20poly1305)\.(NewCipher|NewTripleDESCipher|New\w*)\s*\("),
    (GO, "public-key", r"\b(rsa|ecdsa|ed25519|ecdh)\.(GenerateKey|Sign\w*|Verify\w*|Encrypt\w*|Decrypt\w*|P256|P384|P521|X25519)\s*\("),
    (GO, "hmac/kdf", r"\b(hmac\.New|pbkdf2\.Key|scrypt\.Key|argon2\.(ID)?Key|bcrypt\.GenerateFromPassword)\s*\("),
    (GO, "tls.Config", r"(?<!\*)\btls\.Config\s*\{"),  # a literal, not a *tls.Config return type
    (GO, "jwt", r"\bjwt\.(NewWithClaims|New|Parse|ParseWithClaims|ParseSigned)\s*\(|\bjwt\.SigningMethod\w+\b"),
    (JS, "node crypto", r"\b(createHash|createHmac|createCipheriv|createDecipheriv|createSign|createVerify|generateKeyPair(Sync)?|pbkdf2(Sync)?|scrypt(Sync)?|createECDH|createDiffieHellman|hkdf(Sync)?)\s*\("),
    (JS, "webcrypto", r"\bsubtle\.(encrypt|decrypt|sign|verify|digest|generateKey|importKey|deriveKey|deriveBits|wrapKey|unwrapKey)\s*\("),
    (JS, "jwt", r"\bjwt\.(sign|verify|decode)\s*\("),
    (JS, "libraries", r"\b(CryptoJS\.\w+|forge\.(md|cipher|pki|hmac)\.\w+|bcrypt\.(hash|hashSync|genSalt\w*))\b"),
]
COMMENT = re.compile(r"^\s*(#|//|\*|/\*)")
IMPORT = re.compile(r"^\s*(import\b|from\s+\S+\s+import\b|package\b|require\(|const\s+\{?[\w\s,]*\}?\s*=\s*require\()")
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", "site-packages"}


def crypto_lines(root):
    """-> {relative path: [(line number, api, text)]} for every production line that calls a crypto API."""
    out = collections.defaultdict(list)
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in files:
            path = os.path.join(d, fn)
            rel = os.path.relpath(path, root)
            if is_test_path(rel) or fn.endswith(".min.js"):
                continue
            apis = [(name, re.compile(rx)) for exts, name, rx in APIS if fn.endswith(exts)]
            if not apis:
                continue
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            if lines and max(len(x) for x in lines) > 1000:
                continue  # minified bundle
            for i, text in enumerate(lines, 1):
                if COMMENT.match(text) or IMPORT.match(text):
                    continue
                for name, rx in apis:
                    if rx.search(text):
                        out[os.path.normpath(rel)].append((i, name, text.strip()))
                        break
    return out


def main(projects, show=False, per_api=False):
    stats, misses = collections.Counter(), []
    for repo in sorted(os.listdir(projects)):
        root = os.path.join(projects, repo)
        if not os.path.isdir(root):
            continue
        hits = crypto_lines(root)
        if not hits:
            continue
        found = collections.defaultdict(list)
        for f in classify_all(code.scan(root, base=root)):
            loc = f.location
            found[os.path.normpath(loc.get("file", ""))].append(
                (loc.get("line") or 0, loc.get("end_line") or loc.get("line") or 0, tuple(loc.get("related_lines", ()))))
        covered = 0
        total = 0
        for rel, rows in hits.items():
            for ln, api, text in rows:
                total += 1
                ok = any(s - 2 <= ln <= e + 2 or ln in rel_lines for s, e, rel_lines in found.get(rel, []))
                covered += ok
                stats[(api, "covered" if ok else "missed")] += 1
                if not ok:
                    misses.append((repo, api, f"{rel}:{ln}", text[:110]))
        stats[(repo, "total")], stats[(repo, "covered")] = total, covered
        print(f"{repo:<14} {covered:>4} / {total:<4} crypto API lines covered ({covered / max(total, 1):.0%})")
    tot = sum(v for (k, t), v in stats.items() if t == "total")
    cov = sum(v for (k, t), v in stats.items() if t == "covered" and (k, "total") in stats)
    print(f"{'= ALL':<14} {cov:>4} / {tot:<4} ({cov / max(tot, 1):.0%})")
    if per_api:
        print()
        apis = {name for _, name, _ in APIS}
        for api in sorted({a for (a, t) in stats if t in ("covered", "missed") and a in apis}):
            c, m = stats[(api, "covered")], stats[(api, "missed")]
            print(f"  {api:<18} {c:>4} covered {m:>4} missed  ({c / max(c + m, 1):.0%})")
    if show:
        print()
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv, "--per-api" in sys.argv)
