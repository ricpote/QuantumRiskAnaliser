"""Differential test on real projects: compare QuantumTrace's crypto findings with Semgrep, Bandit and gosec.

There is no ground truth for real code, so this measures disagreement, not accuracy: every finding another tool
reports and QuantumTrace does not is a candidate miss to review by hand (a bug, or a documented policy difference).

    # results of the other tools, one JSON per project and tool, in <out>:
    semgrep scan --config <semgrep-rules>/python/cryptography/security ... --json -o <out>/semgrep-<repo>.json <repo>
    bandit -r <repo> -t B303,B304,B305,B311,B324,B413,B502,B503,B504,B505 -f json -o <out>/bandit-<repo>.json
    (cd <repo> && gosec -include G401,...,G507 -fmt json -out <out>/gosec-<repo>.json ./...)
    python scripts/crosscheck_tools.py <projects-dir> <out> [--misses]
"""
from __future__ import annotations

import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402
from quantumtrace.ingest.code.common import is_test_path  # noqa: E402
from semgrep_rules_bench import kind_of as semgrep_kind  # noqa: E402

WEAK = ("broken", "deprecated")
WEAK_HASH = ("MD2", "MD4", "MD5", "SHA-1", "RIPEMD-160", "RIPEMD-128")


def _hash(f):
    return f.algorithm if f.category == "hash" else f.params.get("hash")


PRED = {
    "weak-hash": lambda f: _hash(f) in WEAK_HASH or "password-hashing" in f.flags,
    "weak-cipher": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",
    "ecb": lambda f: "ecb-mode" in f.flags,
    "short-key": lambda f: "short-key" in f.flags,
    "weak-prng": lambda f: f.algorithm == "NON-CSPRNG",
    "static-iv": lambda f: "static-iv" in f.flags,
    "tls": lambda f: f.category == "protocol" or "no-forward-secrecy" in f.flags or "insecure-cipher-suite" in f.flags,
    "hardcoded-key": lambda f: "hardcoded-key" in f.flags,
    "jwt-unverified": lambda f: "signature-not-verified" in f.flags,
    "null-cipher": lambda f: f.algorithm == "NULL",
}
BANDIT = {"B303": "weak-hash", "B324": "weak-hash", "B304": "weak-cipher", "B305": "ecb", "B311": "weak-prng",
          "B502": "tls", "B503": "tls", "B504": "tls", "B505": "short-key", "B413": "import"}
GOSEC = {"G401": "weak-hash", "G406": "weak-hash", "G405": "weak-cipher", "G403": "short-key", "G404": "weak-prng",
         "G407": "static-iv", "G402": "tls", "G501": "import", "G502": "import", "G503": "import", "G505": "import",
         "G506": "import", "G507": "import"}
# never QuantumTrace's job: an import is not a use, and certificate checks are not algorithm choices
OUT_OF_SCOPE = {"import"}


def tool_findings(out, repo, root):
    """-> [(tool, rule, kind, relative file, line)]"""
    rows = []
    p = os.path.join(out, f"semgrep-{repo}.json")
    if os.path.exists(p):
        for r in json.load(open(p)).get("results", []):
            rule = r["check_id"].split(".")[-1]
            rows.append(("semgrep", rule, semgrep_kind(rule), os.path.relpath(r["path"], repo) if not os.path.isabs(r["path"])
                         else os.path.relpath(r["path"], root), r["start"]["line"]))
    p = os.path.join(out, f"bandit-{repo}.json")
    if os.path.exists(p):
        for r in json.load(open(p)).get("results", []):
            rows.append(("bandit", r["test_id"], BANDIT.get(r["test_id"]), os.path.relpath(r["filename"], repo), r["line_number"]))
    p = os.path.join(out, f"gosec-{repo}.json")
    if os.path.exists(p):
        for r in json.load(open(p)).get("Issues") or []:
            rows.append(("gosec", r["rule_id"], GOSEC.get(r["rule_id"]), os.path.relpath(r["file"], root),
                         int(str(r["line"]).split("-")[0])))
    return rows


def near(f, ln, slack=3):
    loc = f.location
    start, end = loc.get("line") or 0, loc.get("end_line") or loc.get("line") or 0
    return start - slack <= ln <= end + slack or ln in loc.get("related_lines", ())


def main(projects, out, show=False):
    stats = collections.Counter()
    misses = []
    for repo in sorted(os.listdir(projects)):
        root = os.path.join(projects, repo)
        rows = tool_findings(out, repo, root)
        if not os.path.isdir(root) or not rows:
            continue
        fs = classify_all(code.scan(root, base=root))
        by_file = collections.defaultdict(list)
        for f in fs:
            by_file[os.path.normpath(f.location.get("file", ""))].append(f)
        for tool, rule, kind, rel, ln in rows:
            rel = os.path.normpath(rel)
            if kind is None or kind in OUT_OF_SCOPE:
                stats[(tool, "out-of-scope")] += 1
                continue
            bucket = "test" if is_test_path(rel) else "prod"
            got = any(near(f, ln) and PRED[kind](f) for f in by_file.get(rel, []))
            stats[(tool, kind, bucket, "both" if got else "tool-only")] += 1
            if not got and bucket == "prod":
                text = ""
                try:
                    text = open(os.path.join(root, rel), encoding="utf-8", errors="replace").read().splitlines()[ln - 1].strip()
                except (OSError, IndexError):
                    pass
                misses.append((tool, kind, rule, f"{repo}/{rel}:{ln}", text[:110]))
    print(f"{'tool / kind':<26} {'both':>5} {'tool-only':>10} {'agreement':>10}   (production code; test code below)")
    tot = collections.Counter()
    keys = sorted({(t, k) for (t, k, *rest) in stats if rest})
    for t, k in keys:
        both, only = stats[(t, k, "prod", "both")], stats[(t, k, "prod", "tool-only")]
        if both + only:
            print(f"{t + ' / ' + k:<26} {both:>5} {only:>10} {both / (both + only):>9.0%}")
            tot.update(both=both, only=only)
    print(f"{'= ALL (production)':<26} {tot['both']:>5} {tot['only']:>10} {tot['both'] / max(tot['both'] + tot['only'], 1):>9.0%}")
    test = sum(v for (t, *rest), v in stats.items() if len(rest) == 3 and rest[1] == "test")
    print(f"(test code: {test} tool findings, not compared - QuantumTrace inventories them flagged test-code)")
    print(f"(out of scope: {sum(v for k, v in stats.items() if k[-1] == 'out-of-scope')} import-only / unmapped rules)")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], "--misses" in sys.argv)
