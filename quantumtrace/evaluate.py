"""Accuracy evaluation against tests/ground_truth.json (precision / recall / tier accuracy).

  python -m quantumtrace.evaluate            # prints the report, exit 1 on any failure
Used by the dashboard's "Accuracy" tab and by tests/test_accuracy.py.
"""
from __future__ import annotations

import json
import os
import re
import sys

from .schema import Finding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(ROOT, "tests", "ground_truth.json")
SAMPLES = os.path.join(ROOT, "samples", "official")
EXTRA_CODE = os.path.join(ROOT, "samples", "extra", "code")  # our own code/config fixtures (expectations in ground_truth.json)

RELEVANT_TIERS = ("critical", "medium", "unencrypted")


def _match(f: Finding, e: dict, check_class=False) -> bool:
    if "category" in e and f.category != e["category"]:
        return False
    if "algorithm" in e and f.algorithm != e["algorithm"]:
        return False
    if "display" in e and f.display_name != e["display"]:
        return False
    for k, v in (e.get("params") or {}).items():
        if f.params.get(k) != v:
            return False
    if check_class:
        if "tier" in e and f.risk_tier != e["tier"]:
            return False
        if "classical" in e and f.classical_status != e["classical"]:
            return False
        if "hndl" in e and f.hndl != e["hndl"]:
            return False
        if not set(e.get("flags", [])) <= set(f.flags):
            return False
    return True


def evaluate(findings: list[Finding], gt: dict | None = None) -> dict:
    gt = gt or json.load(open(GT))
    fails, rep = [], {}

    # ------------------------------------------------------------------ code
    code = [f for f in findings if f.source == "code"]
    by_file = lambda name: [f for f in code if f.location.get("file", "").replace("\\", "/").endswith(name)]
    det = cls = 0
    for e in gt["code"]:
        cands = [f for f in by_file(e["file"]) if _match(f, e)]
        if cands:
            det += 1
            if any(_match(f, e, True) for f in cands):
                cls += 1
            else:
                f = cands[0]
                fails.append(f"[code] {e['file']}: {e['algorithm']} classified {f.risk_tier}/{f.classical_status} flags={f.flags}, expected {e.get('tier')}/{e.get('classical')} {e.get('flags', [])}")
        else:
            fails.append(f"[code] MISSED {e['file']}: {e['category']} {e['algorithm']} {e.get('params', '')}")
    for e in gt.get("code_absent", []):
        bad = [f for f in by_file(e["file"]) if _match(f, e) and ("tier" not in e or f.risk_tier == e["tier"])]
        if bad:
            fails.append(f"[code] FALSE POSITIVE {e['file']}: {bad[0].display_name} ({e['why']})")
    allowed = [dict(file="go/invoice-service/main.go", algorithm="SHA-1")]
    relevant = [f for f in code if (f.risk_tier in RELEVANT_TIERS or f.classical_status in ("broken", "deprecated")) and "demo-code" not in f.flags]
    expected_all = gt["code"] + allowed
    tp = [f for f in relevant if any(f.location.get("file", "").endswith(e["file"]) and _match(f, {k: v for k, v in e.items() if k in ("category", "algorithm")}) for e in expected_all)]
    fp = [f for f in relevant if f not in tp]
    for f in fp:
        fails.append(f"[code] UNEXPECTED {f.location.get('file')}:{f.location.get('line')} {f.display_name} {f.risk_tier}/{f.classical_status}")
    n = len(gt["code"])
    rep["code"] = dict(expected=n, detected=det, correctly_classified=cls, recall=round(det / n, 3), classification_accuracy=round(cls / max(det, 1), 3),
                       precision=round(len(tp) / max(len(relevant), 1), 3), false_positives=len(fp), traps_checked=len(gt.get("code_absent", [])))

    # ------------------------------------------------------------------ network
    net = [f for f in findings if f.source == "network"]
    groups = {g["name"]: g for g in gt["network"]}
    ok_eps = tot_eps = 0
    for g in gt["network"]:
        exp = groups[g["same_as"]]["expect"] if "same_as" in g else g["expect"]
        rx = re.compile(g["host_regex"])
        eps = {}
        for f in net:
            if rx.match(str(f.asset.get("host"))) and f.asset.get("port") == g["port"]:
                eps.setdefault((f.asset.get("host"), f.location.get("stream")), []).append(f)
        if len(eps) != g["count"]:
            fails.append(f"[network] {g['name']}: found {len(eps)} sessions, expected {g['count']}")
        for key, fs in eps.items():
            good = True
            for cat, e in exp.items():
                cands = [f for f in fs if f.category == cat]
                if not cands or not all(_match(f, dict(e, category=cat), True) for f in cands):
                    good = False
                    got = [(f.display_name, f.risk_tier, f.flags) for f in cands]
                    fails.append(f"[network] {g['name']} {key[0]}: {cat} got {got[:2]} expected {e}")
                    break
            ok_eps += good
        tot_eps += g["count"]
    rep["network"] = dict(expected_sessions=tot_eps, sessions_found=len({(f.asset.get('host'), f.location.get('stream')) for f in net}),
                          sessions_correct=ok_eps, accuracy=round(ok_eps / max(tot_eps, 1), 3))

    # ------------------------------------------------------------------ cloud
    cl = [f for f in findings if f.source == "cloud"]

    def rid(f):
        a = f.asset
        if a.get("kind") == "aws-elb-listener":
            return f"{a.get('load_balancer')}:{a.get('port')}"
        return a.get("alias") or a.get("domain")

    cok = 0
    for e in gt["cloud"]:
        cands = [f for f in cl if rid(f) == e["id"] and _match(f, e)]
        if cands and any(_match(f, e, True) for f in cands):
            cok += 1
        else:
            got = [(f.category, f.display_name, f.risk_tier, f.classical_status, f.flags) for f in cl if rid(f) == e["id"]]
            fails.append(f"[cloud] {e['id']}: expected {e} got {got[:3]}")
    for e in gt.get("cloud_absent", []):
        bad = [f for f in cl if rid(f) == e["id"] and _match(f, e)]
        if bad:
            fails.append(f"[cloud] FALSE POSITIVE {e['id']}: {bad[0].display_name} ({e['why']})")
    rep["cloud"] = dict(expected=len(gt["cloud"]), correct=cok, accuracy=round(cok / len(gt["cloud"]), 3), traps_checked=len(gt.get("cloud_absent", [])))
    rep["failures"] = fails
    rep["passed"] = not fails
    return rep


def run() -> dict:
    gt = json.load(open(GT))
    os.environ.setdefault("QT_NOW", gt["now"])
    from .cli import collect
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        findings = collect([os.path.relpath(SAMPLES, ROOT), os.path.relpath(EXTRA_CODE, ROOT)])
    finally:
        os.chdir(cwd)
    return evaluate(findings, gt)


if __name__ == "__main__":
    r = run()
    print(json.dumps({k: v for k, v in r.items() if k != "failures"}, indent=2))
    for x in r["failures"]:
        print(" -", x)
    sys.exit(0 if r["passed"] else 1)
