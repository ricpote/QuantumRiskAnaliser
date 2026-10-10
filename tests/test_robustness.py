"""Inputs we do not control: a bad file must be reported, never abort the scan or be called safe.

Covers the P0 fixes: per-file resilience (#1), ELB policies outside the table (#2),
accuracy split by origin (#3) and warnings / exit codes (#4).
"""
import json
import os

import pytest

from quantumtrace import cli
from quantumtrace.classify import classify_all
from quantumtrace.ingest import cloud

ROOT = os.path.join(os.path.dirname(__file__), "..")
OFFICIAL_CLOUD = os.path.join(ROOT, "samples", "official", "cloud-posture")


@pytest.fixture(autouse=True)
def _now(monkeypatch):
    monkeypatch.setenv("QT_NOW", "2026-10-10T12:00:00Z")


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return str(p)


def _listener_doc(policy):
    return {"LoadBalancers": [{"LoadBalancerName": "x-alb", "Type": "application", "Scheme": "internet-facing",
                               "Listeners": [{"Protocol": "HTTPS", "Port": 443, "SslPolicy": policy,
                                              "ListenerArn": "arn:x", "Certificates": []}]}]}


def _policy_findings(tmp_path, policy):
    return classify_all(cloud.ingest([_write(tmp_path, "lb.json", _listener_doc(policy))]))


# ------------------------------------------------------------------ #1 one bad file never aborts the scan
def test_incomplete_aws_json_is_reported_not_fatal(tmp_path):
    bad = _write(tmp_path, "listeners.json", {"Listeners": [{"ListenerArn": "arn:x", "Port": 443, "Protocol": "HTTPS",
                                                             "SslPolicy": "ELBSecurityPolicy-2016-08"}]})
    problems = []
    fs = cli.collect([OFFICIAL_CLOUD, bad], problems, quiet=True)
    assert any(f.asset.get("kind") == "aws-kms-key" for f in fs)            # the official exports are still scanned
    assert any(f.location.get("json", "").endswith("listeners.json") for f in fs)  # and so is the partial one


def test_load_balancer_name_from_a_listener_arn(tmp_path):
    arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:listener/app/shop-lb/50dc6c495c0c9188/f2f7dc8efc522ab2"
    p = _write(tmp_path, "l.json", {"Listeners": [{"ListenerArn": arn, "Port": 443, "Protocol": "HTTPS",
                                                    "SslPolicy": "ELBSecurityPolicy-2016-08"}]})
    fs = cloud.ingest([p])
    assert fs and {f.asset["load_balancer"] for f in fs} == {"shop-lb"}


def test_malformed_record_is_skipped_and_reported(tmp_path):
    p = _write(tmp_path, "lb.json", {"LoadBalancers": [{"LoadBalancerName": "ok", "Listeners": [None, {"Protocol": "HTTP", "Port": 80}]}]})
    problems = []
    fs = cloud.ingest([p], problems)
    assert any(f.algorithm == "PLAINTEXT" for f in fs)                    # the good listener is kept
    assert any("listener" in x["reason"] for x in problems)               # the broken one is reported


def test_unreadable_capture_is_reported_and_the_rest_is_scanned(tmp_path):
    bad = _write(tmp_path, "broken.pcap", "not a capture")
    problems = []
    fs = cli.collect([bad, OFFICIAL_CLOUD], problems, quiet=True)
    assert fs and any(x["path"] == bad and "unreadable capture" in x["reason"] for x in problems)


# ------------------------------------------------------------------ #2 a policy we cannot read is never "safe"
def test_fips_policy_is_derived_from_its_name(tmp_path):
    fs = _policy_findings(tmp_path, "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04")
    kex = [f for f in fs if f.category == "key-exchange"]
    assert kex and all(f.risk_tier == "critical" for f in kex)            # classical ECDHE: HNDL-exposed
    assert all("policy-derived-from-name" in f.flags and f.confidence < 1 for f in fs)
    assert {f.params.get("version") for f in fs if f.category == "protocol"} == {"TLS 1.2"}
    assert not any(f.algorithm == "ChaCha20-Poly1305" for f in fs)        # FIPS: no ChaCha20


def test_fips_pq_policy_offers_ml_kem(tmp_path):
    fs = _policy_findings(tmp_path, "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09")
    assert any(f.algorithm == "X25519MLKEM768" and f.risk_tier == "safe" for f in fs)


def test_cnsa_policy_is_aes_256_only(tmp_path):
    fs = _policy_findings(tmp_path, "ELBSecurityPolicy-TLS13-1-2-RFC9151-FIPS-2023-07")
    enc = {(f.algorithm, f.params.get("key_bits")) for f in fs if f.category == "encryption"}
    assert enc == {("AES", 256)}


def test_legacy_policy_keeps_tls_1_0(tmp_path):
    fs = _policy_findings(tmp_path, "ELBSecurityPolicy-TLS-1-0-2015-04")
    proto = [f for f in fs if f.category == "protocol"]
    assert proto and proto[0].params["version"] == "TLS 1.0" and proto[0].classical_status == "deprecated"


def test_unrecognisable_policy_is_assumed_classical(tmp_path):
    fs = _policy_findings(tmp_path, "CustomCorpPolicy-v7")
    assert any(f.category == "key-exchange" and f.risk_tier == "critical" and "assumed" in f.flags for f in fs)
    assert not any(f.classical_status == "recommended" for f in fs)


def test_table_policies_are_unchanged(tmp_path):
    fs = _policy_findings(tmp_path, "ELBSecurityPolicy-2016-08")
    assert not any("policy-derived-from-name" in f.flags for f in fs)
    assert any(f.algorithm == "RSA" and f.category == "key-exchange" for f in fs)


# ------------------------------------------------------------------ #3 accuracy reported by origin
def test_accuracy_split_official_vs_own_fixtures():
    from quantumtrace.evaluate import run
    r = run()
    off, own = r["code_by_origin"]["official"], r["code_by_origin"]["own_fixtures"]
    assert off["expected"] == 36 and off["correctly_classified"] == 36
    assert own["correctly_classified"] == own["expected"] > 0
    assert "config" not in r                                              # the dead block that showed 0.0 is gone


# ------------------------------------------------------------------ #4 warnings and exit codes
def test_scan_of_nothing_exits_3(tmp_path, capsys):
    code = cli.main(["scan", str(tmp_path / "does-not-exist"), "--out", str(tmp_path / "out")])
    assert code == 3
    assert "path not found" in capsys.readouterr().err
    summary = json.load(open(tmp_path / "out" / "summary.json"))
    assert summary["warnings"][0]["reason"] == "path not found"


def test_partial_scan_warns_but_succeeds(tmp_path, capsys):
    bad = _write(tmp_path, "broken.pcap", "not a capture")
    code = cli.main(["scan", OFFICIAL_CLOUD, bad, "--out", str(tmp_path / "out")])
    assert code == 0
    assert "broken.pcap" in capsys.readouterr().err


def test_probe_exits_1_when_no_target_answers():
    assert cli.main(["probe", "127.0.0.1:9", "--timeout", "1"]) == 1


def test_json_that_is_not_an_aws_export_is_reported(tmp_path):
    problems = []
    cli.collect([_write(tmp_path, "random.json", {"foo": [1, 2, 3]})], problems, quiet=True)
    assert problems and "not a recognised AWS export" in problems[0]["reason"]


def test_kms_list_keys_output_gets_a_hint(tmp_path):
    problems = []
    cloud.ingest([_write(tmp_path, "keys.json", {"Keys": [{"KeyId": "1", "KeyArn": "arn:k"}]})], problems)
    assert problems and "describe-key" in problems[0]["reason"]


def test_missing_schema_checker_does_not_crash_the_scan(tmp_path, monkeypatch, capsys):
    """jsonschema is an optional extra of cyclonedx-python-lib: without it the CBOM is written, flagged unchecked."""
    from quantumtrace.export import cyclonedx
    monkeypatch.setattr(cyclonedx, "validate", lambda bom: [cyclonedx.NOT_VALIDATED])
    code = cli.main(["scan", OFFICIAL_CLOUD, "--out", str(tmp_path / "out")])
    assert code == 0 and os.path.exists(tmp_path / "out" / "cbom.cdx.json")
    assert "not validated" in capsys.readouterr().err
