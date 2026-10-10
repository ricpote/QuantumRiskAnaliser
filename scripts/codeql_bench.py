"""Score QuantumTrace on GitHub CodeQL's own crypto query tests (Java, Python, JavaScript, Go), line by line.

    git clone --depth 1 --filter=blob:none --sparse https://github.com/github/codeql.git /tmp/codeql
    (cd /tmp/codeql && git sparse-checkout set java/ql/test/query-tests/security/CWE-326 java/ql/test/query-tests/security/CWE-327 \
        java/ql/test/query-tests/security/CWE-338 go/ql/test/query-tests/Security/CWE-326 go/ql/test/query-tests/Security/CWE-327 \
        go/ql/test/query-tests/Security/CWE-338 javascript/ql/test/query-tests/Security/CWE-326 \
        javascript/ql/test/query-tests/Security/CWE-327 javascript/ql/test/query-tests/Security/CWE-338 \
        javascript/ql/test/query-tests/Security/CWE-916 python/ql/test/query-tests/Security)
    python scripts/codeql_bench.py /tmp/codeql [--misses]

Each query test has a `.expected` file: the `#select` rows are the alerts CodeQL's authors accept (positives). A
QuantumTrace finding of the same kind on a line the `.expected` file never mentions counts as a false positive.
Inline `$ MISSING:` comments (issues the authors say CodeQL misses) are positives, `$ SPURIOUS:` ones negatives
(only where the directory holds a single query, so the comment's query is unambiguous).

CodeQL alerts on every OPERATION (cipher.encrypt, hasher.update, block.Encrypt); QuantumTrace reports the algorithm
INSTANCE once, where it is created. An alert is covered by a finding when that instance reaches the alert line: Go tests
say so ("init from N lines above"); elsewhere the variable assigned on the finding's line (or one derived from it,
cipher -> encryptor) is used on the alert line, at most 15 lines later.
"""
from __future__ import annotations

import collections
import glob
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402
from quantumtrace.kb.algorithms import CATALOG  # noqa: E402

WEAK = ("broken", "deprecated")
WEAK_HASH = ("MD2", "MD4", "MD5", "SHA-1", "RIPEMD-160")
QUERIES = {  # query name -> kind
    "InsufficientKeySize": "short-key", "InsufficientKeySizeTest": "short-key", "WeakCryptoKey": "short-key",
    "BrokenCryptoAlgorithm": "broken-algo", "MaybeBrokenCryptoAlgorithm": "maybe-broken",
    "WeakSensitiveDataHashing": "weak-hash", "InsufficientPasswordHash": "weak-hash",
    "InsecureRandomness": "weak-prng", "JHipsterGeneratedPRNG": "weak-prng",
    "InsecureProtocol": "tls", "InsecureDefaultProtocol": "tls", "UnsafeTLS": "tls",
}
POLICY = {"maybe-broken": "CodeQL's 'maybe broken' = any algorithm not on its allow-list; QuantumTrace grades each algorithm instead",
          "inventory": "MD5 / SHA-1 on non-sensitive data: CodeQL inventories the same operation (CryptographicOperation) without alerting",
          "kdf-cost": "PBKDF2 below OWASP's iteration count: QuantumTrace is stricter than CodeQL",
          "go-default-min": "tls.Config MinVersion 0: TLS 1.2 by default since Go 1.22 (CodeQL assumes the older TLS 1.0 default)",
          "deliberate": "CodeQL skips settings guarded by a flag / case named like 'insecure' or 'legacy'; QuantumTrace reports them",
          "py-default-min": "SSLContext(PROTOCOL_TLS*) / wrap_socket() without a version: TLS 1.2 minimum by default since Python 3.10",
          "sslv23": "pyOpenSSL SSLv23_METHOD: Bandit flags it, CodeQL does not; QuantumTrace reports it at confidence 0.7",
          "ec-224": "P-224 (112-bit): allowed by NIST SP 800-57 until 2030; CodeQL requires 256-bit curves",
          "test-file": "RSA-1024 in test_example.py: CodeQL skips tests; QuantumTrace inventories it flagged test-code"}
SRC = (".java", ".py", ".js", ".ts", ".go")


def _hash(f):
    return f.algorithm if f.category == "hash" else f.params.get("hash")


PRED = {
    "short-key": lambda f: (f.params.get("key_bits") or 4096) < 2048 and f.algorithm in ("RSA", "DSA", "DH", "ElGamal")
                           or f.algorithm in ("ECDSA", "ECDH") and (f.classical_bits or 128) < 112
                           or f.category in ("encryption", "mac", "kdf", "key") and f.algorithm != "HARDCODED-KEY"
                           and (f.params.get("key_bits") or 256) < 128,
    "broken-algo": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm in CATALOG and f.algorithm != "AES"
                             or "ecb-mode" in f.flags
                             or f.category in ("hash", "mac", "signature") and _hash(f) in WEAK_HASH and "not-for-security" not in f.flags,
    "maybe-broken": lambda f: f.classical_status in WEAK,
    "weak-hash": lambda f: "not-for-security" not in f.flags and (
        f.category in ("hash", "signature", "mac") and _hash(f) in WEAK_HASH
        or "password-hashing" in f.flags and (f.classical_status in WEAK or f.category == "hash") or "reversible-password" in f.flags
        or f.category == "kdf" and f.classical_status in WEAK),
    "weak-prng": lambda f: f.algorithm == "NON-CSPRNG" and "csprng-fallback" not in f.flags,
    "tls": lambda f: f.category in ("protocol", "encryption", "key-exchange", "mac") and f.location.get("file", "").endswith(SRC)
                     and (f.category == "protocol" and f.classical_status in WEAK or "no-forward-secrecy" in f.flags or "insecure-cipher-suite" in f.flags
                          or f.context.get("api", "") and "tls" in (f.context.get("api") or "").lower() and f.classical_status in WEAK),
}


def _flows(src, fline, aline):
    """Does the object created on line fline reach line aline (fline < aline <= fline + 10) through local variables?"""
    if not 0 < fline < aline <= min(fline + 15, len(src)):
        return False
    m = re.match(r"\s*(?:[\w<>\[\],.]+\s+)*?(\w+)[\w.]*(?:\s*,\s*\w+)*\s*(?::=|[-+*/|&^]?=)(?!=)", src[fline - 1])
    names = {m.group(1)} if m else set()
    for i in range(fline + 1, aline + 1):
        line = src[i - 1]
        used = any(re.search(rf"\b{re.escape(n)}\b", line) for n in names)
        if i == aline:
            return used
        a = re.match(r"\s*(?:[\w<>\[\],.]+\s+)*?(\w+)[\w.]*(?:\s*,\s*\w+)*\s*(?::=|[-+*/|&^]?=)(?!=)", line)
        if used and a:
            names.add(a.group(1))
    return False


def covers(f, ln):
    loc = f.location
    return (loc.get("line") or 0) <= ln <= (loc.get("end_line") or loc.get("line") or 0) or ln in loc.get("related_lines", ())


def expected_rows(path):
    """-> (alerts {(file, line)}, every (file, line) the file mentions)."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    alerts, mentioned, inits = set(), set(), {}
    in_select = not any(re.match(r"(#select|edges|nodes|subpaths)\b", x) for x in lines)  # one result set: no header
    for line in lines:
        if line.startswith("#select"):
            in_select = True
            continue
        if not line.startswith("|"):
            in_select = False if line.strip() and not line.startswith("|") else in_select
            continue
        locs = re.findall(r"([\w./-]+\.(?:java|py|js|ts|go|xsjs)):(\d+):\d+:\d+:\d+", line)
        for f, ln in locs:
            mentioned.add((os.path.normpath(f), int(ln)))
        if in_select and locs:
            alerts.add((os.path.normpath(locs[0][0]), int(locs[0][1])))
            if re.search(r"allowed by|does not specify a protocol", line):
                DEFAULT_ONLY.add((os.path.normpath(locs[0][0]), int(locs[0][1])))
    return alerts, mentioned


DEFAULT_ONLY: set = set()  # alerts about a runtime default (no explicit legacy version in the code)


def inline(src):
    """-> ({line: [init lines]} from Go's 'init from N lines above', MISSING lines, SPURIOUS lines)."""
    inits, missing, spurious = {}, set(), set()
    for i, line in enumerate(src, 1):
        m = re.search(r"init from ([\d,]+) lines above", line)
        if m:
            inits[i] = [i - int(n) for n in m.group(1).split(",")]
        if re.search(r"\$\s*MISSING:", line):
            missing.add(i)
        if re.search(r"\$\s*SPURIOUS:", line):
            spurious.add(i)
    return inits, missing, spurious


def main(root, show=False):
    stats, misses = collections.Counter(), []
    dirs = collections.defaultdict(list)
    for exp in glob.glob(os.path.join(root, "*", "ql", "test", "query-tests", "*", "CWE-3*", "**", "*.expected"), recursive=True) \
            + glob.glob(os.path.join(root, "*", "ql", "test", "query-tests", "*", "CWE-916", "**", "*.expected"), recursive=True):
        q = os.path.basename(exp)[:-len(".expected")]
        if q in QUERIES and "/vendor/" not in exp:
            dirs[os.path.dirname(exp)].append((q, exp))
    for d, queries in sorted(dirs.items()):
        lang = os.path.relpath(d, root).split(os.sep)[0]
        files = [p for p in glob.glob(os.path.join(d, "**", "*"), recursive=True) if p.endswith(SRC) and "/vendor/" not in p]
        fs = classify_all([f for p in files for f in code.scan(p, base=d)])
        # every file here lives under ql/test/: the test-code flag (lower confidence) is expected, findings still count
        mentioned_all = set()
        parsed = []
        for q, exp in queries:
            alerts, mentioned = expected_rows(exp)
            mentioned_all |= mentioned
            parsed.append((q, alerts))
        srcs = {os.path.relpath(p, d): open(p, encoding="utf-8", errors="replace").read().splitlines() for p in files}
        notes = {fn: inline(src) for fn, src in srcs.items()}
        if len(parsed) == 1:
            q, alerts = parsed[0]
            for fn, (_, missing, spurious) in notes.items():
                alerts |= {(fn, ln) for ln in missing}
                alerts -= {(fn, ln) for ln in spurious}
        for fn, (_, missing, spurious) in notes.items():
            mentioned_all |= {(fn, ln) for ln in missing | spurious}

        def reaches(f, fname, ln):
            if os.path.normpath(f.location["file"]) != fname:
                return False
            if covers(f, ln) or any(covers(f, x) for x in notes.get(fname, ({}, 0, 0))[0].get(ln, [])):
                return True
            text = srcs.get(fname, [""] * ln)[ln - 1] if 0 < ln <= len(srcs.get(fname, [])) else ""
            sym = f.location.get("symbol") or ""
            if sym and re.search(rf"\b{re.escape(sym)}\s*\(.*\{{", text) and ln < f.location["line"] <= ln + 30:
                return True  # alert on the method declaration, finding inside that method
            return _flows(srcs.get(fname, []), f.location.get("end_line") or f.location["line"], ln)

        fs = [f for f in fs if "unreachable" not in f.flags]  # dead code: inventoried, not a live finding

        def policy(fname, ln, f=None):
            text = srcs.get(fname, [""] * ln)[ln - 1] if 0 < ln <= len(srcs.get(fname, [])) else ""
            if re.search(r"MinVersion(:|\s*=)\s*0\b", text):
                return "go-default-min"
            if re.search(r"OK \(.*suggest", text):
                return "deliberate"
            if f is not None and "CryptographicOperation=" in text and "Alert" not in text:
                return "inventory"
            if f is not None and f.category == "kdf":
                return "kdf-cost"
            if f is not None and "SSLv23" in f.evidence:
                return "sslv23"
            if f is not None and os.path.basename(fname).startswith("test_") and not any(fn == fname for fn, _ in mentioned_all):
                return "test-file"
            return None

        for q, alerts in parsed:
            kind = QUERIES[q]
            for fname, ln in sorted(alerts):
                if policy(fname, ln):
                    stats[(lang, policy(fname, ln), "fn")] += 1
                    continue
                got = any(reaches(f, fname, ln) and PRED[kind](f) for f in fs)
                if not got and (fname, ln) in DEFAULT_ONLY:
                    stats[(lang, "py-default-min", "fn")] += 1
                    continue
                if not got and any(reaches(f, fname, ln) and f.params.get("curve") == "P-224" for f in fs):
                    stats[(lang, "ec-224", "fn")] += 1
                    continue
                stats[(lang, kind, "tp" if got else "fn")] += 1
                if not got:
                    misses.append((lang, kind, "fn", f"{os.path.relpath(d, root)}/{fname}:{ln}"))
            if kind in POLICY:
                continue
            for f in fs:
                fname = os.path.normpath(f.location["file"])
                if PRED[kind](f) and not any((fname, ln) in mentioned_all for ln in
                                             range(f.location["line"], (f.location.get("end_line") or f.location["line"]) + 1)) \
                        and not any((fname, ln) in mentioned_all for ln in f.location.get("related_lines", ())) \
                        and not any(fn == fname and reaches(f, fn, ln) for fn, ln in mentioned_all):
                    pol = policy(fname, f.location["line"], f) or next(
                        (p for ln in range(f.location["line"], f.location["line"] + 8) for p in [policy(fname, ln)] if p == "deliberate"), None)
                    if pol:
                        stats[(lang, pol, "fp")] += 1
                        continue
                    stats[(lang, kind, "fp")] += 1
                    misses.append((lang, kind, "fp", f"{os.path.relpath(d, root)}/{fname}:{f.location['line']} {f.display_name}"))
    print(f"{'language / kind':<26} {'TP':>4} {'FP':>4} {'FN':>4}  precision  recall")
    tot, by_lang = collections.Counter(), collections.defaultdict(collections.Counter)
    for lang, kind in sorted({(l, k) for l, k, _ in stats}):
        tp, fp, fn = (stats[(lang, kind, x)] for x in ("tp", "fp", "fn"))
        note = "   (policy, not scored)" if kind in POLICY else ""
        print(f"{lang + ' / ' + kind:<26} {tp:>4} {fp:>4} {fn:>4}  {tp / max(tp + fp, 1):8.1%} {tp / max(tp + fn, 1):7.1%}{note}")
        if kind not in POLICY:
            tot.update(tp=tp, fp=fp, fn=fn)
            by_lang[lang].update(tp=tp, fp=fp, fn=fn)
    for lang, s in sorted(by_lang.items()):
        print(f"{'= ' + lang:<26} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4}  {s['tp'] / max(s['tp'] + s['fp'], 1):8.1%} {s['tp'] / max(s['tp'] + s['fn'], 1):7.1%}")
    print(f"{'= SCORED':<26} {tot['tp']:>4} {tot['fp']:>4} {tot['fn']:>4}  {tot['tp'] / max(tot['tp'] + tot['fp'], 1):8.1%} "
          f"{tot['tp'] / max(tot['tp'] + tot['fn'], 1):7.1%}")
    for k, why in POLICY.items():
        print(f"(policy: {k} - {why})")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
