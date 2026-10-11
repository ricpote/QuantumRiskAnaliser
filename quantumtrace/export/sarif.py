"""SARIF 2.1.0 export for code findings (GitHub code scanning / IDEs)."""
from __future__ import annotations

from ..schema import Finding

LEVEL = {"critical": "error", "unencrypted": "error", "medium": "warning", "safe": "note"}


REPO = "https://github.com/ricpote/QuantumRiskAnaliser"


def _sarif_fix(f: Finding, fix: dict) -> dict | None:
    """SARIF 2.1.0 `fix`: replace the whole flagged line with the rewritten one (after == "" deletes it)."""
    before, after, line, uri = fix.get("before"), fix.get("after"), f.location.get("line"), f.location.get("file")
    if after is None or not isinstance(before, str) or not isinstance(line, int) or not uri:
        return None
    return {"description": {"text": fix.get("note") or f"QuantumTrace fix {fix.get('rule')}"},
            "artifactChanges": [{"artifactLocation": {"uri": uri},
                                 "replacements": [{"deletedRegion": {"startLine": line, "startColumn": 1,
                                                                     "endLine": line, "endColumn": len(before) + 1},
                                                   "insertedContent": {"text": after}}]}]}


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
        result = {"ruleId": rid, "level": lvl, "message": {"text": f.evidence},
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.get("file")},
                                                      "region": {"startLine": f.location.get("line", 1), "startColumn": f.location.get("column", 1)}}}]}
        fix = (f.context or {}).get("fix")
        if fix:
            result["properties"] = {"fixRule": fix.get("rule"), "fixNote": fix.get("note"), "fixRequires": fix.get("requires")}
            sarif_fix = _sarif_fix(f, fix)
            if sarif_fix:
                result["fixes"] = [sarif_fix]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "QuantumTrace", "informationUri": REPO, "rules": list(rules.values())}},
                      "results": results}]}
