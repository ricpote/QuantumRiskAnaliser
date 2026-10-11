"""Mosca's inequality per asset (score.mosca): X shelf-life + Y migration > Z years to Q-Day."""
import pytest

from quantumtrace.classify import classify
from quantumtrace.schema import Finding
from quantumtrace.score import mosca, summarize, what_if

WEB = dict(kind="network-endpoint", host="app.lab", port=443, service="https")
DB = dict(kind="network-endpoint", host="db.lab", port=5432, service="postgresql")
KMS_ROOT = dict(kind="aws-kms-key", arn="arn:aws:kms:eu-west-1:1:key/root", alias="alias/internal-ca-root")
KMS_ENC = dict(kind="aws-kms-key", arn="arn:aws:kms:eu-west-1:1:key/enc", alias="alias/partner-feed-decrypt")


def f(source, category, alg, asset, flags=(), **p):
    return classify(Finding(source=source, category=category, algorithm=alg, params=p, asset=asset, flags=list(flags)))


def one(findings, **kw):
    m = mosca(findings, now_year=2026, **kw)
    assert m["evaluated"] == 1
    return m["assets"][0]


def test_hndl_web_endpoint_must_start_now_and_is_late_if_qday_2030():
    kex = [f("network", "key-exchange", "X25519", WEB)]
    a = one(kex)                                   # X=5 + Y=2 = 7 = 2033 - 2026
    assert (a["shelf_life"], a["migration_years"], a["start_by"], a["status"]) == (5, 2, 2026, "start-now")
    a = one(kex, qday_year=2030)
    assert a["at_risk"] and a["years_late"] == 3 and a["status"] == "late"


def test_database_traffic_lives_longer_than_web():
    a = one([f("network", "key-exchange", "ECDHE", DB, curve="P-256")])
    assert a["shelf_life"] == 10 and a["at_risk"] and a["years_late"] == 5


def test_long_lived_signature_root_is_most_urgent():
    a = one([f("cloud", "signature", "RSA", KMS_ROOT, flags=["long-lived"], key_bits=4096)])
    # X = 15: root programs trust a root CA at most 15 years after key generation; Y = 5: CNSA 2.0 firmware signing
    assert (a["shelf_life"], a["migration_years"], a["years_late"]) == (15, 5, 13)
    assert a["deadline_year"] == 2030                # EU high-risk (long-lived signature)


def test_long_lived_flag_on_encryption_key_is_not_a_trust_anchor():
    a = one([f("cloud", "encryption", "RSA", KMS_ENC, flags=["long-lived"], key_bits=2048)])
    assert a["shelf_life"] == 10 and a["migration_years"] == 3 and "data at rest" in a["why"][0]


def test_short_signature_is_ok():
    a = one([f("network", "authentication", "ECDSA", WEB, curve="P-256")])
    assert a["shelf_life"] == 1 and a["status"] == "ok"   # certificates last at most 200 days (CA/B SC-081v3)


def test_only_shor_assets_are_evaluated_cleartext_counted_apart():
    fs = [f("network", "encryption", "AES", WEB, key_bits=128, mode="GCM"),
          f("network", "transport", "PLAINTEXT", dict(WEB, port=80, service="http"))]
    m = mosca(fs, now_year=2026)
    assert m["evaluated"] == 0 and m["cleartext_assets"] == 1


def test_summary_carries_mosca_and_scenarios_are_ordered(monkeypatch):
    monkeypatch.setenv("QT_NOW", "2026-10-10T12:00:00Z")
    fs = [f("network", "key-exchange", "X25519", WEB), f("network", "key-exchange", "ECDHE", DB, curve="P-256"),
          f("cloud", "signature", "RSA", KMS_ROOT, flags=["long-lived"], key_bits=4096)]
    s = summarize(fs)["mosca"]
    sc = s["scenarios"]
    assert s["qday_year"] == 2033 and s["now"] == 2026
    assert sc["pessimistic"]["at_risk"] >= sc["default"]["at_risk"] >= sc["optimistic"]["at_risk"]
    assert sc["pessimistic"]["at_risk"] == 3


def test_what_if_maps_plan_indices_to_their_findings(monkeypatch):
    monkeypatch.setenv("QT_NOW", "2026-10-10T12:00:00Z")
    http = dict(WEB, port=80, service="http")
    fs = [f("network", "key-exchange", "X25519", WEB), f("network", "transport", "PLAINTEXT", http),
          f("network", "encryption", "AES", WEB, key_bits=128, mode="GCM")]
    plan = summarize(fs)["plan"]
    cleartext = next(i for i, p in enumerate(plan) if p["category"] == "transport")
    only = what_if(fs, [cleartext])
    assert only["before"]["plaintext"] == 1 and only["after"]["plaintext"] == 0
    assert only["after"]["hndl_exposed"] == only["before"]["hndl_exposed"] == 1     # the other actions untouched
    assert what_if(fs, [])["after"] == what_if(fs, [])["before"]
    everything = what_if(fs, list(range(len(plan))))["after"]
    assert everything["score"] == 100.0 and everything["late"] == 0 and everything["critical"] == 0
    for bad in ([len(plan)], [-1], [True], "0"):
        with pytest.raises(ValueError):
            what_if(fs, bad)



def test_every_mosca_assumption_is_sourced():
    """X, Y and Z defaults each name at least one source, and every source has a link and a summary."""
    from quantumtrace.kb import mosca as M
    table = M.assumptions()
    ids = {s["id"] for s in table["sources"]}
    rows = table["shelf_life"] + table["migration"] + table["qday"]
    assert rows and all(r["sources"] and set(r["sources"]) <= ids for r in rows)
    assert all(r["basis"] in ("stated", "derived", "estimate") for r in table["shelf_life"] + table["migration"])
    assert all(s["url"].startswith("https://") and s["says"] and s["title"] for s in table["sources"])
    used = {i for r in rows for i in r["sources"]}
    assert used == ids                                   # no orphan reference on the Sources page
    assert {q["year"] for q in table["qday"]} == set(M.QDAY_SCENARIOS.values())


def test_sources_page_lists_the_values_the_timeline_uses():
    from quantumtrace.kb import mosca as M
    shelf = {r["label"]: r["years"] for r in M.assumptions()["shelf_life"]}
    assert shelf["E-mail (IMAP, POP3, SMTP and their TLS variants)"] == M.SHELF_LIFE_SERVICE["imaps"].years == 10
    assert shelf["Long-lived signatures: root CA, code and firmware signing"] == 15
    move = {r["label"]: r["years"] for r in M.assumptions()["migration"]}
    assert move["AWS ACM certificate"] == 3                 # no public post-quantum certificates before ~2027
    a = one([f("network", "key-exchange", "X25519", WEB)])
    assert "NIST SP 800-57" in a["why"][0]                  # the hover text names its source
