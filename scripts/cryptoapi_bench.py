"""Score QuantumTrace on CryptoAPI-Bench (Afrose et al., IEEE SecDev 2019) - Java JCA/JSSE misuse test cases.

    git clone --depth 1 https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git /tmp/cab
    pip install openpyxl
    python scripts/cryptoapi_bench.py /tmp/cab [--misses]

Ground truth: CryptoAPI-Bench_details.xlsx (one row per test case; multi-class cases list several files).
Case names: BB = basic, ABI = inter-procedural, ABS/ABF = field-sensitive, ABPS = path-sensitive, ABMC = multi-class.
TLS trust/hostname, plain HTTP and credential-in-String categories are reported separately: QuantumTrace inventories algorithms and key material,
it does not audit certificate-validation logic.
"""
from __future__ import annotations

import collections
import os
import sys

import openpyxl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402

WEAK = ("broken", "deprecated")
STATIC = ("hardcoded-key", "static-iv", "static-salt", "constant-seed", "hardcoded-password")


def _live(fs):
    """CryptoAPI-Bench scores vulnerabilities: an instance replaced before any use is inventoried, not exploitable."""
    return [f for f in fs if "overwritten-before-use" not in f.flags]


def _has_flag(fs, *flags):
    return any(set(flags) & set(f.flags) for f in fs)


RULES = {  # benchmark folder -> "is this test case flagged?"
    "brokencrypto": lambda fs: any(f.category == "encryption" and f.classical_status in WEAK for f in fs),
    "brokenhash": lambda fs: any(f.category == "hash" and f.classical_status in WEAK for f in fs),
    "brokenmac": lambda fs: any(f.category == "mac" and f.params.get("hash") in ("MD5", "SHA-1") for f in fs),
    "ecbcrypto": lambda fs: _has_flag(fs, "ecb-mode"),
    "insecureasymmetriccrypto": lambda fs: _has_flag(fs, "short-key"),
    "untrustedprng": lambda fs: any(f.algorithm == "NON-CSPRNG" for f in fs),
    "pbeiteration": lambda fs: any(f.category == "kdf" and (f.params.get("iterations") or 10**9) < 1000 for f in fs),
    "predictablecryptographickey": lambda fs: _has_flag(fs, "hardcoded-key"),
    "predictablepbepassword": lambda fs: _has_flag(fs, "hardcoded-password"),
    "predictablekeystorepassword": lambda fs: _has_flag(fs, "hardcoded-password"),
    "staticinitializationvector": lambda fs: _has_flag(fs, "static-iv"),
    "staticsalts": lambda fs: _has_flag(fs, "static-salt"),
    "predictableseeds": lambda fs: _has_flag(fs, "constant-seed"),
    "dummycertvalidation": lambda fs: any(f.algorithm == "NO-CERT-VERIFY" for f in fs),
    "dummyhostnameverifier": lambda fs: any(f.algorithm == "NO-CERT-VERIFY" for f in fs),
}
# SSLSocketFactory without a hostname check, plain-HTTP URLs, and "credential in String" (Java memory hygiene: a key held in an
# immutable String cannot be wiped, even when it is random) are not about algorithms or fixed key material.
OUT_OF_SCOPE = ("impropersslsocketfactory", "http", "credentialinstring")


def load_cases(bench):
    files = {f: os.path.join(d, f) for d, _, fs in os.walk(os.path.join(bench, "src")) for f in fs if f.endswith(".java")}
    ws = openpyxl.load_workbook(os.path.join(bench, "CryptoAPI-Bench_details.xlsx"), read_only=True)["Vulnerabilities"]
    cases = []
    for r in ws.iter_rows(values_only=True):
        if not (r[1] and str(r[1]).strip().endswith(".java") and r[3] is not None):
            continue
        names = [n.strip() for n in str(r[1]).split("\n") if n.strip()]
        paths = [files[n] for n in names if n in files]
        if paths:
            cases.append((names[0], paths, str(r[3]).strip() == "True", os.path.basename(os.path.dirname(paths[0]))))
    return cases


def main(bench, show=False):
    stats = collections.defaultdict(lambda: dict(tp=0, fp=0, tn=0, fn=0))
    misses = []
    for name, paths, real, cat in load_cases(bench):
        fs = classify_all([f for p in paths for f in code.scan(p, base=bench)])
        got = RULES[cat](_live(fs)) if cat in RULES else False
        key = ("tp" if real else "fp") if got else ("fn" if real else "tn")
        stats[cat][key] += 1
        if key in ("fp", "fn"):
            misses.append((cat, key, name))

    def line(label, s):
        p, r = s["tp"] / max(s["tp"] + s["fp"], 1), s["tp"] / max(s["tp"] + s["fn"], 1)
        print(f"{label:<30} {s['tp']:>3} {s['fp']:>3} {s['tn']:>3} {s['fn']:>3}  {p:8.1%} {r:7.1%}")

    print(f"{'category':<30} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  precision  recall")
    for group, cats in (("IN SCOPE", sorted(RULES)), ("OUT OF SCOPE", OUT_OF_SCOPE)):
        tot = dict(tp=0, fp=0, tn=0, fn=0)
        for c in cats:
            if c in stats:
                line(c, stats[c])
                for k in tot:
                    tot[k] += stats[c][k]
        line(f"= {group}", tot)
        print()
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
