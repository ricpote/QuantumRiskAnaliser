"""Quantum Readiness Score + summary + migration plan.

Model (explainable, shown in the UI):
  finding.risk_points (urgency): 100 = Shor + HNDL (key exchange / encryption) or no encryption at all
                                  90 = Shor + long-lived signature (root CA, code/firmware signing, attestation)
                                  75 = other Shor uses (handshake authentication, short-lived tokens)
                                  40 = Grover-weakened (<128-bit post-quantum strength)
                                   0 = quantum-safe
  asset risk   = max(risk_points of its findings)
  source score = 100 - mean(asset risk)          (network endpoints, code files, cloud resources)
  QRS          = mean(source scores)             (each ingested source weighs the same)
  mosca        = per Shor-vulnerable asset: at risk when shelf-life X + migration Y > years to Q-Day (kb/mosca.py)
"""
from __future__ import annotations

import copy
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .kb import mosca as M
from .schema import Finding

INVENTORY_ONLY = {"LIBRARY", "SCAN-ERROR", "CSPRNG", "UNIDENTIFIED"}


def asset_key(f: Finding) -> str:
    a = f.asset or {}
    if f.source in ("network", "probe"):
        return f"{a.get('host')}:{a.get('port')}"
    if f.source == "code":
        return a.get("path", "?")
    return a.get("arn") or a.get("alias") or a.get("domain") or "?"


def asset_label(f: Finding) -> str:
    a = f.asset or {}
    if f.source in ("network", "probe"):
        return f"{a.get('host')}:{a.get('port')} ({a.get('service')})"
    if f.source == "code":
        return a.get("path", "?")
    if a.get("kind") == "aws-kms-key":
        return f"KMS {a.get('alias') or a.get('key_id')}"
    if a.get("kind") == "aws-acm-certificate":
        return f"ACM {a.get('domain')}"
    if a.get("kind") == "aws-elb-listener":
        return f"ELB {a.get('load_balancer')}:{a.get('port')}"
    return asset_key(f)


def summarize(findings: list[Finding]) -> dict:
    real = [f for f in findings if f.algorithm not in INVENTORY_ONLY]
    by_asset = defaultdict(list)
    for f in real:
        by_asset[(f.source, asset_key(f))].append(f)
    src_assets = defaultdict(dict)
    for (src, key), fs in by_asset.items():
        worst = max(fs, key=lambda x: x.risk_points)
        kex = [x for x in fs if x.category in ("key-exchange", "transport")]
        src_assets[src][key] = dict(
            label=asset_label(fs[0]), risk=worst.risk_points, worst_tier=worst.risk_tier,
            hndl=any(x.hndl for x in fs), pq_kex=any(x.category == "key-exchange" and x.risk_tier == "safe" and x.quantum_threat == "none" for x in kex),
            plaintext=any(x.algorithm == "PLAINTEXT" for x in fs),
            classical_broken=sum(1 for x in fs if x.classical_status == "broken"),
            findings=len(fs))
    sources = {}
    for src, assets in src_assets.items():
        risks = [a["risk"] for a in assets.values()]
        sources[src] = dict(score=round(100 - sum(risks) / len(risks), 1) if risks else 100.0, assets=len(assets),
                            tiers=dict(Counter(f.risk_tier for f in real if f.source == src)),
                            hndl_assets=sum(1 for a in assets.values() if a["hndl"]),
                            pq_assets=sum(1 for a in assets.values() if a["pq_kex"]),
                            plaintext_assets=sum(1 for a in assets.values() if a["plaintext"]))
    qrs = round(sum(s["score"] for s in sources.values()) / len(sources), 1) if sources else None
    net = src_assets.get("network", {})
    return dict(
        quantum_readiness_score=qrs,
        grade=_grade(qrs),
        sources=sources,
        tiers=dict(Counter(f.risk_tier for f in real)),
        threats=dict(Counter(f.quantum_threat for f in real)),
        classical=dict(Counter(f.classical_status for f in real)),
        findings=len(real),
        assets=sum(len(a) for a in src_assets.values()),
        network=dict(endpoints=len(net), hndl_exposed=sum(1 for a in net.values() if a["hndl"]),
                     pq_protected=sum(1 for a in net.values() if a["pq_kex"]),
                     plaintext=sum(1 for a in net.values() if a["plaintext"])),
        top_assets=sorted(({"source": s, "key": k, **v} for s, d in src_assets.items() for k, v in d.items()),
                          key=lambda a: (-a["risk"], -a["classical_broken"], a["label"]))[:15],
        plan=migration_plan(real),
        mosca=mosca(real),
    )


def _grade(q):
    if q is None:
        return "-"
    return "A" if q >= 85 else "B" if q >= 70 else "C" if q >= 55 else "D" if q >= 40 else "E" if q >= 25 else "F"


def _now_year() -> int:
    env = os.environ.get("QT_NOW")
    return datetime.fromisoformat(env.replace("Z", "+00:00")).year if env else datetime.now(timezone.utc).year


def _long_lived_sig(shor: list[Finding]) -> bool:
    # "long-lived" is about signatures (roots, code/firmware signing); on an encryption key it only means "important"
    return any("long-lived" in f.flags and f.category not in ("key-exchange", "encryption") for f in shor)


def _shelf_life(a: dict, shor: list[Finding]):
    """X: the longest time any Shor-vulnerable use on this asset must stay secure."""
    cands = []
    if any(f.hndl for f in shor):
        svc = str(a.get("service") or "").split("+")[0]
        cands.append(M.SHELF_LIFE_SERVICE.get(svc) or M.SHELF_LIFE_KIND.get(a.get("kind")) or M.SHELF_LIFE_CONFIDENTIALITY_DEFAULT)
    if _long_lived_sig(shor):
        cands.append(M.SHELF_LIFE_LONG_LIVED_SIG)
    return max(cands or [M.SHELF_LIFE_SHORT_SIG], key=lambda c: c[0])


def _migration(a: dict, shor: list[Finding]):
    if _long_lived_sig(shor):
        return M.MIGRATION_LONG_LIVED
    if all("fallback-for-legacy-clients" in f.flags for f in shor):
        return M.MIGRATION_PQ_FALLBACK
    return M.MIGRATION_KIND.get(a.get("kind")) or M.MIGRATION_DEFAULT


def mosca(findings: list[Finding], qday_year: int | None = None, now_year: int | None = None) -> dict:
    """Mosca's inequality per Shor-vulnerable asset: at risk when shelf-life X + migration Y > Z years to Q-Day.

    start_by = Q-Day - X - Y is the last year to START migrating; years_late > 0 means it is already too late
    for data recorded today. Assumptions (X, Y, Q-Day scenarios) live in kb/mosca.py.
    """
    qday = qday_year or M.QDAY_DEFAULT
    now = now_year or _now_year()
    by_asset = defaultdict(list)
    for f in findings:
        if f.algorithm not in INVENTORY_ONLY:
            by_asset[(f.source, asset_key(f))].append(f)
    rows = []
    for (src, key), fs in by_asset.items():
        shor = [f for f in fs if f.quantum_threat == "shor"]
        if not shor:
            continue
        a = fs[0].asset or {}
        xa, ya = _shelf_life(a, shor), _migration(a, shor)  # kb/mosca.py Assumption: years, why, sources
        x, xwhy, y, ywhy = xa.years, xa.why, ya.years, ya.why
        start_by = qday - x - y
        rows.append(dict(source=src, key=key, label=asset_label(fs[0]), shelf_life=x, migration_years=y,
                         qday_year=qday, start_by=start_by, finish_by=qday - x, years_late=max(0, now - start_by),
                         at_risk=start_by < now, status="late" if start_by < now else ("start-now" if start_by == now else "ok"),
                         hndl=any(f.hndl for f in shor),
                         deadline_year=min((f.deadline_year for f in fs if f.deadline_year), default=None),
                         why=[f"X = {x}y: {xwhy}", f"Y = {y}y: {ywhy}", f"Z = {qday - now}y: Q-Day {qday} - {now}"]))
    rows.sort(key=lambda r: (-r["years_late"], r["start_by"], r["label"]))
    return dict(qday_year=qday, now=now, evaluated=len(rows), at_risk=sum(r["at_risk"] for r in rows),
                status=dict(Counter(r["status"] for r in rows)),
                scenarios={name: dict(qday_year=yr, at_risk=sum(r["shelf_life"] + r["migration_years"] > yr - now for r in rows))
                           for name, yr in M.QDAY_SCENARIOS.items()},
                cleartext_assets=len({k for k, fs in by_asset.items() if any(f.algorithm == "PLAINTEXT" for f in fs)}),
                assets=rows)


def _plan_key(f: Finding):
    """The migration action a finding belongs to: (source, category, replacement, how), or None if it needs none."""
    if not f.replacement or (f.risk_points == 0 and f.classical_status not in ("broken", "deprecated")):
        return None
    how = f.context.get("migration_hint") if f.source == "cloud" and f.context.get("migration_hint") else f.replacement.get("how")
    return (f.source, f.category if f.category != "authentication" else "signature", f.replacement["algorithm"], how)


def migration_plan(findings: list[Finding]) -> list[dict]:
    """Group findings into concrete actions, ordered by total risk removed."""
    groups = defaultdict(list)
    for f in findings:
        key = _plan_key(f)
        if key:
            groups[key].append(f)
    plan = []
    for (src, cat, alg, how), fs in groups.items():
        assets = sorted({asset_label(f) for f in fs})
        plan.append(dict(source=src, category=cat, action=fs[0].replacement.get("action") or f"Migrate {cat} to {alg}", replacement=alg,
                         standard=fs[0].replacement.get("standard"), how=how,
                         from_algorithms=sorted({f.display_name for f in fs}), assets=assets, asset_count=len(assets),
                         risk_removed=round(sum(f.risk_points for f in fs), 1), hndl=any(f.hndl for f in fs),
                         priority="P0" if any(f.hndl or f.algorithm == "PLAINTEXT" for f in fs) else ("P1" if any(f.risk_tier == "critical" or f.classical_status == "broken" for f in fs) else "P2")))
    plan.sort(key=lambda p: ({"P0": 0, "P1": 1, "P2": 2}[p["priority"]], -p["risk_removed"]))
    return plan


def what_if(findings: list[Finding], actions: list[int]) -> dict:
    """Simulate applying migration actions (indices into summarize()["plan"]): their findings become quantum-safe."""
    plan = migration_plan([f for f in findings if f.algorithm not in INVENTORY_ONLY])
    if not isinstance(actions, list) or any(type(i) is not int or not 0 <= i < len(plan) for i in actions):
        raise ValueError(f"actions must be plan indices between 0 and {len(plan) - 1}")
    keys = {(plan[i]["source"], plan[i]["category"], plan[i]["replacement"], plan[i]["how"]) for i in actions}
    simulated = []
    for f in findings:
        if _plan_key(f) in keys:
            f = copy.deepcopy(f)
            f.risk_points, f.risk_tier, f.hndl, f.quantum_threat, f.classical_status = 0.0, "safe", False, "none", "recommended"
            if f.algorithm == "PLAINTEXT":
                f.algorithm = "TLS"
        simulated.append(f)

    def headline(s):
        return dict(score=s["quantum_readiness_score"], grade=s["grade"], critical=s["tiers"].get("critical", 0),
                    hndl_exposed=s["network"]["hndl_exposed"], plaintext=s["network"]["plaintext"],
                    late=s["mosca"]["status"].get("late", 0))
    return dict(actions=len(keys), before=headline(summarize(findings)), after=headline(summarize(simulated)))
