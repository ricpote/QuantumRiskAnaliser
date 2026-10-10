"""Score QuantumTrace on the OWASP Benchmark (Java) crypto categories.

    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git /tmp/BenchmarkJava
    python scripts/owasp_benchmark.py /tmp/BenchmarkJava [--fp]

Categories scored (expectedresults-1.2.csv): crypto (CWE-327 weak cipher), hash (CWE-328 weak hash),
weakrand (CWE-330 weak randomness). A test case counts as "flagged" when its file has a finding of the
matching kind that is classically weak. --fp lists every false positive / false negative.
"""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402

CATEGORIES = ("crypto", "hash", "weakrand")
WEAK = ("broken", "deprecated")


def flagged(category, findings) -> bool:
    if category == "crypto":
        return any(f.category == "encryption" and f.classical_status in WEAK for f in findings)
    if category == "hash":
        return any(f.category == "hash" and f.classical_status in WEAK for f in findings)
    return any(f.algorithm == "NON-CSPRNG" for f in findings)


def main(bench: str, show: bool = False) -> dict:
    src = os.path.join(bench, "src", "main", "java", "org", "owasp", "benchmark", "testcode")
    rows = [r for r in csv.reader(open(os.path.join(bench, "expectedresults-1.2.csv"))) if r and not r[0].startswith("#")]
    stats = {c: dict(tp=0, fp=0, tn=0, fn=0) for c in CATEGORIES}
    misses = []
    for name, cat, real, _cwe in rows:
        if cat not in CATEGORIES:
            continue
        fs = classify_all(code.scan(os.path.join(src, f"{name}.java"), base=bench))
        got, want = flagged(cat, fs), real == "true"
        key = ("tp" if want else "fp") if got else ("fn" if want else "tn")
        stats[cat][key] += 1
        if key in ("fp", "fn"):
            misses.append((cat, key, name, [(f.category, f.display_name, f.classical_status) for f in fs if f.category in ("encryption", "hash", "rng")]))
    total = {k: sum(s[k] for s in stats.values()) for k in ("tp", "fp", "tn", "fn")}
    print(f"{'category':<10} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  precision  recall  benchmark(TPR-FPR)")
    for cat, s in list(stats.items()) + [("ALL", total)]:
        p = s["tp"] / max(s["tp"] + s["fp"], 1)
        r = s["tp"] / max(s["tp"] + s["fn"], 1)
        fpr = s["fp"] / max(s["fp"] + s["tn"], 1)
        print(f"{cat:<10} {s['tp']:>4} {s['fp']:>4} {s['tn']:>4} {s['fn']:>4}  {p:9.1%}  {r:6.1%}  {r - fpr:8.1%}")
    if show:
        for m in misses:
            print(*m)
    return stats


if __name__ == "__main__":
    main(sys.argv[1], "--fp" in sys.argv)
