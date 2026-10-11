"""Key material at rest (ingest/code/keys.py): certificates, keys, SSH keys, warnings, CBOM and uploads."""
import os
from pathlib import Path

import pytest

from quantumtrace.cli import collect
from quantumtrace.export import cyclonedx, sarif
from quantumtrace.score import summarize
from quantumtrace import uploads

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "samples" / "extra" / "code" / "keys"


@pytest.fixture(scope="module")
def scanned():
    os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")
    problems = []
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        findings = collect([os.path.relpath(KEYS, ROOT)], problems, quiet=True)
    finally:
        os.chdir(cwd)
    return findings, problems


def by_file(findings, name):
    return [f for f in findings if f.location.get("file", "").replace("\\", "/").endswith(name)]


def test_certificates_and_chain(scanned):
    findings, _ = scanned
    chain = by_file(findings, "certs/shop-chain.pem")
    assert sorted((f.algorithm, f.location["line"] > 1) for f in chain) == [("ECDSA", False), ("RSA", True)]
    root = by_file(findings, "certs/legacy-root-ca.pem")[0]
    assert root.category == "certificate" and root.classical_status == "broken"
    assert {"expired", "long-lived", "short-key"} <= set(root.flags)
    der = by_file(findings, "certs/device.der")[0]
    assert der.algorithm == "Ed25519" and der.risk_tier == "critical"


def test_post_quantum_certificate_is_safe(scanned):
    pq = by_file(scanned[0], "certs/pq-signing.pem")
    assert len(pq) == 1 and pq[0].algorithm == "ML-DSA" and pq[0].risk_tier == "safe"
    assert pq[0].params["parameter_set"] == "ML-DSA-65" and pq[0].nist_quantum_level == 3


def test_keys_private_public_and_ssh(scanned):
    findings, _ = scanned
    deploy = by_file(findings, "deploy.key")[0]
    assert deploy.params["key_type"] == "private" and "hardcoded-key" in deploy.flags and deploy.classical_status == "broken"
    protected = by_file(findings, "legacy-enc.key")[0]
    assert "passphrase-protected" in protected.flags and protected.classical_status != "broken"
    assert by_file(findings, "ssh/id_ed25519")[0].algorithm == "Ed25519"
    auth = sorted((f.algorithm, f.params.get("key_bits")) for f in by_file(findings, "ssh/authorized_keys"))
    assert auth == [("Ed25519", None), ("RSA", 1024)]
    assert by_file(findings, "app-config.yaml")[0].category == "certificate"  # PEM found by content in a YAML file


def test_unreadable_material_is_a_warning_not_a_guess(scanned):
    findings, problems = scanned
    assert not by_file(findings, "vault-enc.key") and not by_file(findings, "truststore.jks")
    warned = {p["path"].replace("\\", "/").rsplit("/", 1)[-1] for p in problems}
    assert {"vault-enc.key", "truststore.jks"} <= warned


def test_cbom_has_certificates_and_typed_keys(scanned):
    findings, _ = scanned
    bom = cyclonedx.build(findings, summarize(findings), target="keys")
    assert not cyclonedx.validate(bom)
    comps = bom["components"]
    certs = [c for c in comps if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert len(certs) == 5  # the issuing CA in shop-chain.pem and app-config.yaml is one certificate, seen twice
    ca = next(c for c in certs if "Issuing CA 2" in c["name"])
    assert len(ca["evidence"]["occurrences"]) == 2
    types = {c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] for c in comps
             if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"}
    assert {"private-key", "public-key"} <= types


def test_every_key_finding_has_a_fix_note(scanned):
    relevant = [f for f in scanned[0] if f.risk_tier == "critical"]
    assert relevant and all("fix" in f.context for f in relevant)


def test_sarif_carries_line_fixes():
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        findings = collect(["samples/official/sample-repos"], [], quiet=True)
    finally:
        os.chdir(cwd)
    results = sarif.build(findings)["runs"][0]["results"]
    fixed = [r for r in results if r.get("fixes")]
    assert fixed
    rep = fixed[0]["fixes"][0]["artifactChanges"][0]["replacements"][0]
    assert rep["deletedRegion"]["startLine"] == fixed[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert isinstance(rep["insertedContent"]["text"], str)


def test_uploads_accept_certificates_and_keys(tmp_path):
    der = (KEYS / "certs" / "device.der").read_bytes()
    assert uploads.validate_content(tmp_path / "device.der", der) is True
    pem_in_yaml = (KEYS / "app-config.yaml").read_bytes()
    assert uploads.validate_content(tmp_path / "app-config.yaml", pem_in_yaml) is True
    assert uploads.validate_content(tmp_path / "id_ed25519", (KEYS / "ssh" / "id_ed25519").read_bytes()) is True
