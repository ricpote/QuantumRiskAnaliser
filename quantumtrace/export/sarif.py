"""SARIF 2.1.0 export for code findings (GitHub code scanning / IDEs)."""
from __future__ import annotations

from ..schema import Finding

LEVEL = {"critical": "error", "unencrypted": "error", "medium": "warning", "safe": "note"}


def build(findings: list[Finding]) -> dict:
    rules, results = {}, []
    for f in findings:
        if f.source != "code" or f.algorithm in ("LIBRARY", "CSPRNG", "SCAN-ERROR"):
            continue
        if f.risk_tier == "safe" and f.classical_status not in ("broken", "deprecated"):
            continue
        rid = f"QT/{f.quantum_threat}/{f.category}/{f.display_name}".replace(" ", "_")
        rules.setdefault(rid, {"id": rid, "name": f.display_name,
                               "shortDescription": {"text": f"{f.display_name} ({f.risk_tier}, classical {f.classical_status})"},
                               "fullDescription": {"text": "; ".join(f.rationale)[:1000]},
                               "help": {"text": f"Replace with {(f.replacement or {}).get('algorithm')} ({(f.replacement or {}).get('standard')}): {(f.replacement or {}).get('how')}"},
                               "properties": {"tags": ["cryptography", "post-quantum", f.quantum_threat] + f.cwe}})
        lvl = "error" if f.classical_status == "broken" else LEVEL.get(f.risk_tier, "note")
        results.append({"ruleId": rid, "level": lvl, "message": {"text": f.evidence},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.get("file")},
                                                            "region": {"startLine": f.location.get("line", 1), "startColumn": f.location.get("column", 1)}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "QuantumTrace", "informationUri": "https://github.com/", "rules": list(rules.values())}},
                      "results": results}]}
