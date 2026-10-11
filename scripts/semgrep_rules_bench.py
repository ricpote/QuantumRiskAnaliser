"""Score QuantumTrace on the line-annotated test files of the official Semgrep rule registry (crypto rules).

    git clone --depth 1 --filter=blob:none --sparse https://github.com/semgrep/semgrep-rules.git /tmp/sgr
    (cd /tmp/sgr && git sparse-checkout set python javascript go java)
    python scripts/semgrep_rules_bench.py /tmp/sgr [--misses]

Each test file marks the line after `# ruleid: <rule>` as vulnerable and the line after `# ok: <rule>` as safe.
A rule id is mapped to a kind (weak hash, weak cipher, ECB, short key, weak PRNG, static IV, NULL cipher);
rules about TLS settings, sockets or AEAD API usage are out of scope and reported separately.
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
from quantumtrace.kb.algorithms import CATALOG  # noqa: E402

DIRS = ["python/cryptography/security", "python/pycryptodome/security", "python/lang/security", "java/lang/security/audit/crypto",
        "go/lang/security/audit/crypto", "javascript/node-crypto/security",
        # JWT libraries and remaining JS crypto rules
        "javascript/jsonwebtoken", "javascript/jose", "javascript/express/security", "javascript/passport-jwt", "javascript/jwt-simple",
        "javascript/lang/security", "python/jwt", "java/java-jwt", "java/jjwt", "go/jwt-go"]
EXT = (".py", ".java", ".go", ".js", ".ts")
WEAK = ("broken", "deprecated")

KINDS = [  # (regex on the rule id, kind)
    (r"none-alg|noverify|without-verify|unverified|jwt-decode-without|python-jwt-none", "jwt-unverified"),
    (r"jwt.*hardcode|hardcoded-secret|passport-hardcode|hardcoded-jwt|jwt-python-hardcoded", "hardcoded-key"),
    (r"md5|md2|md4|sha1|sha224|hash", "weak-hash"),
    (r"ecb|default-aes", "ecb"),
    (r"cipher-algorithm|des-is|desede|rc2|rc4|arc4|blowfish|weak-crypto", "weak-cipher"),
    (r"key-size|weak-rsa", "short-key"),
    (r"random", "weak-prng"),
    (r"initialization-vector", "static-iv"),
    (r"null-cipher", "null-cipher"),
    (r"empty-aes-key", "hardcoded-key"),
]
OUT_OF_SCOPE = (r"ssl|tls|socket|ssh|gcm|aead|no-iv|mode-without-authentication|rsa-no-padding|custom-digests|httpclient|bad.imports|"
                r"insecure-module|uuid|exposed-data|not-revoked|jwt-exposed|jose-exposed|intercom|sequelize")

PRED = {
    "weak-hash": lambda f: f.category == "hash" and (f.classical_status in WEAK or f.risk_tier == "medium" and f.algorithm in CATALOG) and "not-for-security" not in f.flags,
    "ecb": lambda f: "ecb-mode" in f.flags,
    "weak-cipher": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",
    "short-key": lambda f: (f.params.get("key_bits") or 4096) < 2048 and f.algorithm in ("RSA", "DSA", "DH")
                           or f.algorithm in ("ECDSA", "ECDH") and (f.classical_bits or 128) < 112,
    "weak-prng": lambda f: f.algorithm == "NON-CSPRNG",
    "static-iv": lambda f: "static-iv" in f.flags,
    "null-cipher": lambda f: f.algorithm == "NULL" and f.category == "encryption",
    "hardcoded-key": lambda f: "hardcoded-key" in f.flags,
    "jwt-unverified": lambda f: f.algorithm == "NULL" and "jwt" in f.flags,
}


def kind_of(rule: str) -> str | None:
    if re.search(OUT_OF_SCOPE, rule):
        return None
    return next((k for rx, k in KINDS if re.search(rx, rule)), None)


def annotations(path):
    """-> [(kind | None, rule, expected_vulnerable, [candidate lines])].

    Candidates: the statement after the annotation (up to the next annotation or blank line, max 4 lines) and, when the
    annotation sits inside a multi-line call (`rsa.generate_private_key(65537,` / `# ruleid` / `1024,`), the lines back
    to where that call starts - findings are reported on the line where a call begins."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    marks = [(i + 1, m.group(1), m.group(2)) for i, l in enumerate(lines) for m in [re.search(r"\b(ruleid|ok|todoruleid|todook):\s*([\w.\-]+)", l)] if m]
    out = []
    for j, (ln, tag, rule) in enumerate(marks):
        if tag.startswith("todo"):
            continue  # cases the Semgrep authors themselves mark as not handled yet
        end = marks[j + 1][0] if j + 1 < len(marks) else len(lines) + 1
        cand = []
        for k in range(ln + 1, min(end, ln + 5)):
            if not lines[k - 1].strip():
                break
            if not re.match(r"\s*(#|//)", lines[k - 1]):
                cand.append(k)
        k = ln - 1
        while k >= 1 and re.search(r"[(,]\s*$", lines[k - 1]):  # inside a multi-line call
            cand.append(k)
            k -= 1
        out.append((kind_of(rule), rule, tag == "ruleid", cand))
    return out


# `ok:` means "this rule does not fire here", not "this line is safe": these lines are weak for ANOTHER Semgrep rule
CROSS_RULE_OK = {
    ("java/lang/security/audit/crypto/use-of-md5-digest-utils.java", 7): "MessageDigest MD5: weak, flagged by Semgrep's use-of-md5 rule",
    ("java/lang/security/audit/crypto/use-of-md5.java", 23): "DigestUtils.getMd5Digest() in bad3(): weak, flagged by Semgrep's use-of-md5-digest-utils rule",
    ("javascript/lang/security/audit/md5-used-as-password.js", 12): "SHA-256 digest stored as a password: still a fast hash "
                                                                   "(CodeQL js/insufficient-password-hash flags it); ok only for the MD5 rule",
}


def main(root, show=False):
    stats = collections.defaultdict(lambda: dict(tp=0, fp=0, tn=0, fn=0))
    misses, cross = [], []
    for d in DIRS:
        for dirpath, _, files in os.walk(os.path.join(root, d)):
            for fname in sorted(files):
                if not fname.endswith(EXT) or ".fixed." in fname:
                    continue
                path = os.path.join(dirpath, fname)
                anns = annotations(path)
                if not anns:
                    continue
                fs = classify_all(code.scan(path, base=root))
                lang = os.path.relpath(path, root).split(os.sep)[0]
                rel = os.path.relpath(path, root)
                for kind, rule, vuln, cand in anns:
                    group = kind or "out-of-scope"
                    if not vuln and cand and (rel, cand[0]) in CROSS_RULE_OK:
                        cross.append(f"{rel}:{cand[0]} ({CROSS_RULE_OK[(rel, cand[0])]})")
                        continue
                    got = bool(kind) and any((f.location.get("line") in cand or any(r in cand for r in f.location.get("related_lines", ()))) and PRED[kind](f) for f in fs)
                    key = ("tp" if vuln else "fp") if got else ("fn" if vuln else "tn")
                    stats[(lang, group)][key] += 1
                    if key in ("fp", "fn") and kind:
                        misses.append((lang, group, key, rule, f"{os.path.relpath(path, root)}:{cand[0] if cand else '?'}"))

    def line(label, s):
        p, r = s["tp"] / max(s["tp"] + s["fp"], 1), s["tp"] / max(s["tp"] + s["fn"], 1)
        print(f"{label:<28} {s['tp']:>3} {s['fp']:>3} {s['tn']:>3} {s['fn']:>3}  {p:8.1%} {r:7.1%}")

    print(f"{'language / kind':<28} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  precision  recall")
    total, by_lang = dict(tp=0, fp=0, tn=0, fn=0), collections.defaultdict(lambda: dict(tp=0, fp=0, tn=0, fn=0))
    for (lang, group), s in sorted(stats.items()):
        if group == "out-of-scope":
            continue
        line(f"{lang} / {group}", s)
        for k in total:
            total[k] += s[k]
            by_lang[lang][k] += s[k]
    print()
    for lang, s in sorted(by_lang.items()):
        line(f"= {lang}", s)
    line("= ALL IN SCOPE", total)
    oos = sum(s["tp"] + s["fn"] + s["fp"] + s["tn"] for (l, g), s in stats.items() if g == "out-of-scope")
    print(f"(out of scope: {oos} annotations on TLS / socket / AEAD-API rules, not scored)")
    for c in cross:
        print(f"(not scored, cross-rule ok: {c})")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
