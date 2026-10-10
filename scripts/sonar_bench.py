"""Score QuantumTrace on SonarSource's own rule test files (Java, Python, JavaScript crypto rules).

    for r in sonar-java sonar-python SonarJS; do
      git clone --depth 1 --filter=blob:none --no-checkout https://github.com/SonarSource/$r.git /tmp/sonar/$r; done
    (see SPARSE below for the sparse-checkout paths), then:
    python scripts/sonar_bench.py /tmp/sonar [--misses]

Java/Python fixtures mark the expected lines with `Noncompliant` (`@+1` / `@-1` = another line); every other line of the
file is implicitly compliant. SonarJS unit tests are RuleTester `valid` / `invalid` code snippets.
Policy differences are reported, not scored: Sonar flags EVERY java.util.Random / Math.random (QuantumTrace only in a
security context) and CBC with padding (QuantumTrace: CBC is a mode concern, not a broken algorithm).
"""
from __future__ import annotations

import collections
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402
from quantumtrace.kb.algorithms import CATALOG  # noqa: E402

SPARSE = {
    "sonar-java": "java-checks-test-sources/default/src/main/java/checks",
    "sonar-python": "python-checks/src/test/resources/checks",
    "SonarJS": "packages/analysis/src/jsts/rules",
}
WEAK = ("broken", "deprecated")

FILES = [  # (path regex, kind)
    (r"StrongCipherAlgorithmCheckSample\.java$|robustCipherAlgorithm\.py$|/S5547/", "weak-cipher"),
    (r"DataHashingCheckSample.*\.java$|hashing/hashingData\.py$|/S4790/", "weak-hash"),
    (r"fastHashingOrPlainText.*\.py$", "weak-kdf"),
    (r"CryptographicKeySizeCheck.*\.java$|strongCryptographicKeys\.py$|/S4426/", "short-key"),
    (r"EncryptionAlgorithmCheckSample\.java$|secureModeEncryptionAlgorithms\.py$|/S5542/", "mode"),
    (r"PseudoRandomCheck.*\.java$|hotspots/pseudoRandom\.py$|/S2245/", "weak-prng"),
    (r"CipherBlockChainingCheck.*\.java$|cipherBlockChaining\.py$", "static-iv"),
    (r"UnpredictableSaltCheck\.java$|predictableSalt\.py$", "static-salt"),
]
PRED = {
    "weak-cipher": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",
    "weak-hash": lambda f: "not-for-security" not in f.flags and (
        f.category in ("hash", "kdf") and (f.classical_status in WEAK or f.risk_tier == "medium" and f.algorithm in CATALOG)
        or f.category == "signature" and ("weak-signature-hash" in f.flags or f.algorithm == "DSA")),
    "weak-kdf": lambda f: f.category in ("kdf", "hash") and f.classical_status in WEAK,
    "short-key": lambda f: (f.params.get("key_bits") or 4096) < 2048 and f.algorithm in ("RSA", "DSA", "DH", "ElGamal")
                           or f.algorithm in ("ECDSA", "ECDH") and (f.classical_bits or 128) < 112 or "small-public-exponent" in f.flags,
    "mode": lambda f: "ecb-mode" in f.flags or "rsa-no-padding" in f.flags,
    "weak-prng": lambda f: f.algorithm == "NON-CSPRNG",
    "static-iv": lambda f: "static-iv" in f.flags,
    "static-salt": lambda f: "static-salt" in f.flags,
}
POLICY = {"inventory": "line really uses MD5/SHA-1 (inventoried); Sonar accepts it there (file checksums, truncated ids)",
          "hmac-sha1": "HMAC-SHA-1 / HMAC-MD5: still allowed by NIST SP 800-131A; QuantumTrace reports them as acceptable, migrate",
          "weak-prng": "Sonar flags every non-CSPRNG call; QuantumTrace only in a security context",
          "mode-cbc": "Sonar flags CBC+padding / RSA without OAEP; QuantumTrace reports CBC as a mode concern, not a broken algorithm"}


def covers(f, ln):
    """The finding's call spans line ln, or ln is a related line (where the key size / IV / salt is defined)."""
    loc = f.location
    start, end = loc.get("line") or 0, loc.get("end_line") or loc.get("line") or 0
    return start <= ln <= end or ln in loc.get("related_lines", ())


def kind_of(path):
    return next((k for rx, k in FILES if re.search(rx, path.replace("\\", "/"))), None)


# lines where Sonar's expectation is a project-specific policy, not the default rule
POLICY_LINES = {("CryptographicKeySizeCheckCustom.java", 11): "custom threshold: RSA 4096 required by this test's rule parameters"}
# lines Sonar leaves unflagged that ARE fixed material (QuantumTrace follows helper methods / every path): listed, never scored
STRICTER = {("UnpredictableSaltCheck.java", 31): "salt from secureSalt(), which returns new byte[0]: an empty, fixed salt",
            ("UnpredictableSaltCheck.java", 34): "salt from secureSalt(), which returns new byte[0]: an empty, fixed salt",
            ("UnpredictableSaltCheck.java", 37): "salt3 = new byte[]{}: an empty, fixed salt",
            ("CipherBlockChainingCheck.java", 255): 'IV is "111" or an empty array on every path: fixed'}


def admitted_lines(src):
    """Lines Sonar marks `Compliant, FN` / `Unknown`: its own authors say the issue is real (or unknown) but not reported."""
    lines = src.splitlines()
    return {i for i, line in enumerate(lines, 1) if re.search(r"Compliant,?\s*FN|\bFN\b.*(?:accepted|known)|Unknown:", line)
            or re.search(r"only supports? when", line) or re.search(r"//\s*FN\s*$", line)
            or any(re.match(r"\s*(#|//)\s*FP\b", lines[j]) for j in range(max(0, i - 4), i - 1))}


def noncompliant_lines(src):
    out = {}
    for i, line in enumerate(src.splitlines(), 1):
        m = re.search(r"Noncompliant(?:@([+-]\d+))?", line)
        if m and not re.match(r"\s*(//|#)\s*Noncompliant\s*$", line) or m and m.group(1):
            out[i + int(m.group(1) or 0)] = line
        elif m:  # a comment line on its own: `// Noncompliant` refers to the next line
            out[i + 1] = line
    return out


stricter: list = []


def score_file(path, kind, stats, misses, root):
    src = open(path, encoding="utf-8", errors="replace").read()
    pos = noncompliant_lines(src)
    admitted = admitted_lines(src)
    for (fname, ln), _why in POLICY_LINES.items():
        if path.endswith(fname):
            pos.pop(ln, None)
            admitted.add(ln)
    for (fname, ln), why in STRICTER.items():
        if path.endswith(fname):
            admitted.add(ln)
            stricter.append(f"{fname}:{ln} {why}")
    for ln in admitted:
        pos.pop(ln, None)  # Sonar's own authors say the expected issue is a false positive / unknown
    fs = classify_all(code.scan(path, base=root))
    lines = src.splitlines()
    for ln in pos:
        k = kind
        text = lines[ln - 1] if 0 < ln <= len(lines) else ""
        if kind == "weak-hash" and re.search(r"(?i)hmac\s*-?\s*(md5|sha-?1)|HmacSHA1|HmacMD5", text):
            k = "hmac-sha1"  # policy: NIST SP 800-131A still allows HMAC-SHA-1
        if kind == "mode" and not re.search(r"ECB|MODE_ECB|ecb", lines[ln - 1] if 0 < ln <= len(lines) else ""):
            k = "mode-cbc"  # policy difference, not scored
        got = k in PRED and any(covers(f, ln) and PRED[k](f) for f in fs)
        stats[(k, "tp" if got else "fn")] += 1
        if not got and k in PRED:
            misses.append((k, "fn", f"{os.path.relpath(path, root)}:{ln}", lines[ln - 1].strip()[:90] if ln <= len(lines) else ""))
    for f in fs:
        if PRED.get(kind, lambda _: False)(f) and not any(covers(f, ln) for ln in set(pos) | admitted) and "test-code" not in f.flags:
            ln = f.location.get("line")
            text = lines[ln - 1] if ln and ln <= len(lines) else ""
            if kind == "weak-hash" and re.search(r"(?i)md5|sha-?1\b|sha1|ripemd|md2|md4", text):
                stats[("inventory", "fp")] += 1  # policy: the algorithm IS weak; Sonar accepts it in this context (files, short ids)
                continue
            stats[(kind, "fp")] += 1
            misses.append((kind, "fp", f"{os.path.relpath(path, root)}:{ln}", lines[ln - 1].strip()[:90] if ln and ln <= len(lines) else ""))


def rule_tester_cases(ts_src):
    """SonarJS unit.test.ts: (is_invalid, code) for every `code: `...`` inside the valid / invalid arrays."""
    out = []
    for m in re.finditer(r"code:\s*`((?:[^`\\]|\\.)*)`", ts_src):
        before = ts_src[:m.start()]
        last_valid = max((x.start() for x in re.finditer(r"\bvalid\s*:", before)), default=-1)
        last_invalid = max((x.start() for x in re.finditer(r"\binvalid\s*:", before)), default=-1)
        out.append((last_invalid > last_valid, m.group(1).replace("\\`", "`")))
    return out


def main(root, show=False):
    stats = collections.Counter()
    misses = []
    for repo, sub in SPARSE.items():
        base = os.path.join(root, repo, sub)
        for d, _, files in os.walk(base):
            for fname in sorted(files):
                path = os.path.join(d, fname)
                kind = kind_of(path)
                if not kind:
                    continue
                if fname.endswith((".java", ".py")) or fname.endswith(".fixture.js"):
                    score_file(path, kind, stats, misses, root)
                elif fname == "unit.test.ts":
                    for i, (invalid, snippet) in enumerate(rule_tester_cases(open(path, encoding="utf-8").read())):
                        with tempfile.TemporaryDirectory() as tmp:
                            p = os.path.join(tmp, "snippet.js")
                            open(p, "w").write(snippet)
                            fs = classify_all(code.scan(p, base=tmp))
                        k = kind
                        if kind == "mode" and invalid and not re.search(r"ecb", snippet, re.I):
                            k = "mode-cbc"
                        got = k in PRED and any(PRED[k](f) for f in fs)
                        key = ("tp" if got else "fn") if invalid else ("fp" if got else "tn")
                        stats[(k, key)] += 1
                        if key in ("fp", "fn") and k in PRED:
                            misses.append((k, key, f"{os.path.relpath(path, root)}#case{i}", " ".join(snippet.split())[:90]))
    print(f"{'kind':<14} {'TP':>4} {'FP':>4} {'FN':>4}  precision  recall")
    tot = collections.Counter()
    for k in list(dict.fromkeys(list(PRED) + list(POLICY))):
        tp, fp, fn = stats[(k, "tp")], stats[(k, "fp")], stats[(k, "fn")]
        if not tp + fp + fn:
            continue
        note = f"   (policy: {POLICY[k]})" if k in POLICY else ""
        print(f"{k:<14} {tp:>4} {fp:>4} {fn:>4}  {tp / max(tp + fp, 1):8.1%} {tp / max(tp + fn, 1):7.1%}{note}")
        if k not in POLICY:
            tot.update(tp=tp, fp=fp, fn=fn)
    print(f"{'= SCORED':<14} {tot['tp']:>4} {tot['fp']:>4} {tot['fn']:>4}  {tot['tp'] / max(tot['tp'] + tot['fp'], 1):8.1%} "
          f"{tot['tp'] / max(tot['tp'] + tot['fn'], 1):7.1%}")
    for x in sorted(set(stricter)):
        print(f"(not scored, QuantumTrace stricter than the annotation: {x})")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
