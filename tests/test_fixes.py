"""Fix suggestions must actually fix: apply each suggested line to a copy of its file, rescan,
and check the line got strictly less severe (quantum tier, classical status, problem flags)."""
import os
import shutil

import pytest

from quantumtrace.classify import classify_all
from quantumtrace.ingest import code
from quantumtrace.ingest.code import fixes

ROOT = os.path.join(os.path.dirname(__file__), "..")
SAMPLES = [os.path.join(ROOT, "samples", "official", "sample-repos"), os.path.join(ROOT, "samples", "extra", "code")]

TIER = {"unencrypted": 3, "critical": 2, "medium": 1, "safe": 0}
CLASSICAL = {"broken": 3, "deprecated": 2, "acceptable": 1, "recommended": 0}
BAD_FLAGS = {"ecb-mode", "hardcoded-key", "short-key", "weak-signature-hash", "password-hashing", "unsalted", "weak-prng",
             "no-forward-secrecy", "sha1-kex", "pq-capable-not-enabled", "pq-not-configured", "plaintext"}


def relevant(f):
    return (f.risk_tier in ("critical", "medium", "unencrypted") or f.classical_status in ("broken", "deprecated")) and "demo-code" not in f.flags


def severity(fs):
    return sum(TIER[f.risk_tier] * 100 + CLASSICAL[f.classical_status] * 10 + len(BAD_FLAGS & set(f.flags)) for f in fs)


def scan_all():
    os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")
    return classify_all([f for root in SAMPLES for f in code.scan(root, base=ROOT)])


DIFFS = {}
for _f in scan_all():
    _fix = _f.context.get("fix")
    if relevant(_f) and _fix and _fix["after"] is not None:
        DIFFS.setdefault((_f.location["file"], _f.location["line"]), _fix)


@pytest.mark.parametrize("key", sorted(DIFFS), ids=lambda k: f"{k[0]}:{k[1]}")
def test_applying_the_fix_reduces_severity(key, tmp_path):
    rel, line = key
    fix = DIFFS[key]
    src = os.path.join(ROOT, rel)
    # copy the whole directory: Terraform resolves var.* from sibling files
    work = tmp_path / "d"
    shutil.copytree(os.path.dirname(src), work)
    path = work / os.path.basename(src)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[line - 1] == fix["before"]
    lines[line - 1] = fix["after"]  # "" blanks the line (deletion) and keeps the numbering of the lines that follow
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def at_line(findings):
        return [f for f in findings if f.location.get("line") == line and relevant(f)]

    before = at_line([f for f in scan_all() if f.location.get("file") == rel])
    after = at_line(classify_all(code.scan(str(path), base=str(work))))
    assert severity(after) < severity(before), f"{fix['rule']}: {[f.display_name for f in after]}"


def test_coverage():
    """Every relevant finding gets a suggestion, except configs that are already post-quantum."""
    fs = [f for f in scan_all() if relevant(f)]
    missing = [f for f in fs if "fix" not in f.context and "fallback-for-legacy-clients" not in f.flags
               and f.context.get("ssl_policy") != fixes.AWS.RECOMMENDED_POLICY]
    assert not missing, [(f.location["file"], f.display_name) for f in missing]
