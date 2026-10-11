"""Held-out score on the NIST Juliet Test Suite for Java 1.3 (SARD), crypto CWEs, case by case.

    curl -sSLo juliet.zip https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip
    unzip -q juliet.zip "*/testcases/CWE3[2-3]*" "*/testcases/CWE7[56]*"
    python scripts/juliet_bench.py <...>/Java/src/testcases [--misses]

Every test case has a flawed bad() and fixed good*() variants (flow variants spread them over files a..e, or over
*_bad.java / *_good*.java). A case is detected when a finding of its CWE's kind lies in a bad method; it is a false
positive when one lies in a good method. The kinds below were fixed before the first run.
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

WEAK = ("broken", "deprecated")
RULES = {
    "CWE321": lambda f: "hardcoded-key" in f.flags,
    "CWE327": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",  # the algorithm, not the mode
    "CWE328": lambda f: f.category == "hash" and f.classical_status in WEAK,
    "CWE329": lambda f: "static-iv" in f.flags,
    "CWE336": lambda f: "constant-seed" in f.flags,
    "CWE760": lambda f: "static-salt" in f.flags or f.algorithm == "NON-CSPRNG",
}
POLICY = {"CWE338": (lambda f: f.algorithm == "NON-CSPRNG",
                     "Juliet flags every Math.random / java.util.Random; QuantumTrace only in a security context")}
OUT_OF_SCOPE = {"CWE759": "unsalted hash of a non-password value", "CWE325": "missing step (KeyGenerator without init, digest without update)"}


def case_of(path):
    """CWE327_Use_Broken_Crypto__3DES_54b.java -> CWE327_Use_Broken_Crypto__3DES_54; *_81_bad.java -> *_81."""
    return re.sub(r"(_\d+)([a-e]|_bad|_base|_good\w*)?\.java$", r"\1", os.path.basename(path))


def side(f):
    """'bad' | 'good' | None: which variant a finding sits in."""
    fn = os.path.basename(f.location["file"])
    if re.search(r"_\d+_bad\.java$", fn):
        return "bad"
    if re.search(r"_\d+_good\w*\.java$", fn):
        return "good"
    sym = (f.location.get("symbol") or "").split(".")[-1]
    return "bad" if sym.startswith("bad") else "good" if sym.startswith("good") else None


def main(root, show=False):
    stats = collections.defaultdict(lambda: dict(tp=0, fp=0, tn=0, fn=0))
    misses = []
    for d in sorted(os.listdir(root)):
        cwe = d.split("_")[0]
        pred = RULES.get(cwe) or POLICY.get(cwe, (None,))[0]
        if pred is None and cwe not in OUT_OF_SCOPE:
            continue
        cases = collections.defaultdict(list)
        for p in sorted(os.listdir(os.path.join(root, d))):
            if p.startswith(cwe) and p.endswith(".java"):
                cases[case_of(p)].append(os.path.join(root, d, p))
        for case, paths in sorted(cases.items()):
            fs = classify_all([f for p in paths for f in code.scan(p, base=os.path.join(root, d))])
            hit = collections.Counter(side(f) for f in fs if pred and pred(f))
            s = stats[cwe]
            s["tp" if hit["bad"] else "fn"] += 1
            s["fp" if hit["good"] else "tn"] += 1
            if not hit["bad"]:
                misses.append((cwe, "fn", case))
            if hit["good"]:
                misses.append((cwe, "fp", case))

    def line(label, s, note=""):
        p, r = s["tp"] / max(s["tp"] + s["fp"], 1), s["tp"] / max(s["tp"] + s["fn"], 1)
        print(f"{label:<10} {s['tp']:>4} {s['fp']:>4} {s['tn']:>4} {s['fn']:>4}  {p:8.1%} {r:7.1%}  {note}")

    print(f"{'CWE':<10} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  precision  recall")
    tot = dict(tp=0, fp=0, tn=0, fn=0)
    for cwe in sorted(RULES):
        if cwe in stats:
            line(cwe, stats[cwe])
            for k in tot:
                tot[k] += stats[cwe][k]
    line("= SCORED", tot)
    for cwe, (_, why) in POLICY.items():
        if cwe in stats:
            line(cwe, stats[cwe], f"(policy, not scored: {why})")
    for cwe, why in OUT_OF_SCOPE.items():
        print(f"(out of scope: {cwe} {why})")
    if show:
        print()
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
