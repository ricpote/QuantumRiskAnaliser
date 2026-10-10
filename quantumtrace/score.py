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
"""
from __future__ import annotations

from collections import Counter, defaultdict

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
    )


def _grade(q):
    if q is None:
        return "-"
    return "A" if q >= 85 else "B" if q >= 70 else "C" if q >= 55 else "D" if q >= 40 else "E" if q >= 25 else "F"


def migration_plan(findings: list[Finding]) -> list[dict]:
    """Group findings into concrete actions, ordered by total risk removed."""
    groups = defaultdict(list)
    for f in findings:
        if not f.replacement or (f.risk_points == 0 and f.classical_status not in ("broken", "deprecated")):
            continue
        how = f.context.get("migration_hint") if f.source == "cloud" and f.context.get("migration_hint") else f.replacement.get("how")
        groups[(f.source, f.category if f.category != "authentication" else "signature", f.replacement["algorithm"], how)].append(f)
    plan = []
    for (src, cat, alg, how), fs in groups.items():
        assets = sorted({asset_label(f) for f in fs})
        plan.append(dict(source=src, category=cat, action=f"Migrate {cat} to {alg}", replacement=alg,
                         standard=fs[0].replacement.get("standard"), how=how,
                         from_algorithms=sorted({f.display_name for f in fs}), assets=assets, asset_count=len(assets),
                         risk_removed=round(sum(f.risk_points for f in fs), 1), hndl=any(f.hndl for f in fs),
                         priority="P0" if any(f.hndl or f.algorithm == "PLAINTEXT" for f in fs) else ("P1" if any(f.risk_tier == "critical" or f.classical_status == "broken" for f in fs) else "P2")))
    plan.sort(key=lambda p: ({"P0": 0, "P1": 1, "P2": 2}[p["priority"]], -p["risk_removed"]))
    return plan
