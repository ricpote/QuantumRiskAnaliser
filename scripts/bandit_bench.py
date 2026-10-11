"""Score QuantumTrace against Bandit (PyCQA) on Bandit's own example files, line by line.

    git clone --depth 1 --filter=blob:none --sparse https://github.com/PyCQA/bandit.git /tmp/bandit
    (cd /tmp/bandit && git sparse-checkout set examples)
    pip install bandit && (cd /tmp/bandit/examples && bandit -q -f json -o /tmp/bandit.json -r .)
    python scripts/bandit_bench.py /tmp/bandit/examples /tmp/bandit.json [--misses]

Bandit's functional tests pin its output on these examples, so its findings are the expected positives. A QuantumTrace
finding of a scored kind on a line Bandit does not flag is counted as a false positive (and listed, for review).
Policy differences are reported, not scored: B311 flags every `random` call (QuantumTrace: only in a security context),
B413 flags the pycrypto import itself (QuantumTrace reports the algorithms used, not the library).
"""
from __future__ import annotations

import collections
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402

WEAK = ("broken", "deprecated")
KINDS = {"B303": "weak-hash", "B324": "weak-hash", "B304": "weak-cipher", "B305": "ecb", "B502": "tls-version",
         "B503": "tls-version", "B505": "short-key", "B311": "weak-prng", "B413": "pycrypto-import"}
POLICY = {"crypt-blowfish": "Bandit flags crypt.METHOD_BLOWFISH; it is bcrypt, an acceptable password hash (inventoried)",
          "weak-prng": "Bandit flags every `random` call; QuantumTrace only in a security context",
          "pycrypto-import": "Bandit flags the pycrypto import; QuantumTrace reports the algorithms used, not the library"}
PRED = {
    "weak-hash": lambda f: f.category in ("hash", "mac", "signature") and "not-for-security" not in f.flags
                           and (f.algorithm in ("MD2", "MD4", "MD5", "SHA-1") or f.params.get("hash") in ("MD2", "MD4", "MD5", "SHA-1"))
                           or f.category == "kdf" and "password-hashing" in f.flags and f.classical_status in WEAK,
    "weak-cipher": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",
    "ecb": lambda f: "ecb-mode" in f.flags,
    "tls-version": lambda f: f.category == "protocol" and f.classical_status in WEAK,
    "short-key": lambda f: (f.params.get("key_bits") or 4096) < 2048 and f.algorithm in ("RSA", "DSA")
                           or f.algorithm in ("ECDSA", "ECDH") and (f.classical_bits or 128) < 112,
    "weak-prng": lambda f: f.algorithm == "NON-CSPRNG",
    "pycrypto-import": lambda f: False,
    "crypt-blowfish": lambda f: f.algorithm == "bcrypt",
}


def covers(f, ln):
    loc = f.location
    return (loc.get("line") or 0) <= ln <= (loc.get("end_line") or loc.get("line") or 0) or ln in loc.get("related_lines", ())


def main(examples, bandit_json, show=False):
    res = json.load(open(bandit_json))["results"]
    expected = collections.defaultdict(set)  # file -> {(line, kind)}
    for r in res:
        if r["test_id"] in KINDS:
            expected[os.path.normpath(r["filename"])].add((r["line_number"], KINDS[r["test_id"]]))
    flagged = collections.defaultdict(set)   # every line Bandit flags for any crypto test: never an FP for us
    for r in res:
        if r["test_id"] in KINDS or r["test_id"] in ("B501", "B504", "B507", "B509"):
            flagged[os.path.normpath(r["filename"])].update(range(r["line_number"], max(r.get("line_range") or [r["line_number"]]) + 1))
    stats, misses = collections.Counter(), []
    for fname in sorted(os.listdir(examples)):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(examples, fname)
        fs = classify_all(code.scan(path, base=examples))
        exp = expected.get(os.path.normpath(fname), set()) | expected.get(os.path.normpath("./" + fname), set())
        src = open(path, encoding="utf-8", errors="replace").read().splitlines()
        for ln, kind in sorted(exp):
            if "METHOD_BLOWFISH" in src[ln - 1]:
                kind = "crypt-blowfish"
            got = any(covers(f, ln) and PRED[kind](f) for f in fs)
            stats[(kind, "tp" if got else "fn")] += 1
            if not got and kind not in POLICY:
                misses.append((kind, "fn", f"{fname}:{ln}"))
        lines = flagged.get(os.path.normpath(fname), set()) | flagged.get(os.path.normpath("./" + fname), set())
        for f in fs:
            for kind, pred in PRED.items():
                if kind not in POLICY and pred(f) and not any(covers(f, ln) for ln in lines):
                    if "nosec" in src[f.location["line"] - 1]:
                        stats["nosec"] += 1  # Bandit's suppression comment: QuantumTrace inventories every use
                        break
                    stats[(kind, "fp")] += 1
                    misses.append((kind, "fp", f"{fname}:{f.location.get('line')} {f.display_name}"))
                    break
    print(f"{'kind':<16} {'TP':>4} {'FP':>4} {'FN':>4}  precision  recall")
    tot = collections.Counter()
    for k in PRED:
        tp, fp, fn = stats[(k, "tp")], stats[(k, "fp")], stats[(k, "fn")]
        if not tp + fp + fn:
            continue
        note = f"   (policy: {POLICY[k]})" if k in POLICY else ""
        print(f"{k:<16} {tp:>4} {fp:>4} {fn:>4}  {tp / max(tp + fp, 1):8.1%} {tp / max(tp + fn, 1):7.1%}{note}")
        if k not in POLICY:
            tot.update(tp=tp, fp=fp, fn=fn)
    print(f"{'= SCORED':<16} {tot['tp']:>4} {tot['fp']:>4} {tot['fn']:>4}  {tot['tp'] / max(tot['tp'] + tot['fp'], 1):8.1%} "
          f"{tot['tp'] / max(tot['tp'] + tot['fn'], 1):7.1%}")
    print(f"(not scored: {stats['nosec']} findings on lines with a `# nosec` suppression comment)")
    print("(out of scope: B501 / B507 / B509 certificate, SSH host key and SNMP checks; B504 ssl.wrap_socket without a version)")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], "--misses" in sys.argv)
