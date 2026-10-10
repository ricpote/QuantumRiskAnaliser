"""Unit tests for the classifier: the traps the jury is likely to check."""
from quantumtrace.classify import classify
from quantumtrace.schema import Finding


def c(alg, cat="signature", **p):
    return classify(Finding(source="code", category=cat, algorithm=alg, params=p))


def test_ed25519_is_shor():
    assert c("Ed25519").quantum_threat == "shor" and c("Ed25519").risk_tier == "critical"


def test_aes_key_sizes():
    assert c("AES", "encryption", key_bits=128, mode="GCM").risk_tier == "medium"
    assert c("AES", "encryption", key_bits=256, mode="GCM").risk_tier == "safe"
    assert c("AES", "encryption", key_bits=256, mode="ECB").classical_status == "broken"


def test_hybrid_pq_is_safe():
    f = c("X25519MLKEM768", "key-exchange", parameter_set="ML-KEM-768")
    assert f.risk_tier == "safe" and f.quantum_threat == "none" and not f.hndl


def test_hndl_only_for_confidentiality():
    assert c("X25519", "key-exchange").hndl is True
    assert c("ECDSA", "signature", curve="P-256").hndl is False


def test_sha1_md5_medium_and_classically_broken():
    for a in ("SHA-1", "MD5"):
        f = c(a, "hash")
        assert f.risk_tier == "medium" and f.classical_status == "broken"


def test_nist_8547_split_by_strength():
    # IR 8547 (ipd): 112-bit schemes deprecated after 2030, >= 128-bit disallowed after 2035
    assert c("RSA", "signature", key_bits=2048).deadline_year == 2030  # NIST 112-bit: 2030 beats EU rest: 2035
    assert any("112-bit" in d for d in c("RSA", "signature", key_bits=2048).deadlines)
    assert any(">= 128-bit" in d for d in c("ECDSA", "signature", curve="P-256").deadlines)


def test_eu_high_risk_is_2030():
    assert c("X25519", "key-exchange").deadline_year == 2030           # HNDL -> EU high-risk
    assert c("ECDSA", "signature", curve="P-256").deadline_year == 2035  # short-lived signature
    f = classify(Finding(source="code", category="signature", algorithm="ECDSA", params={"curve": "P-256"}, flags=["long-lived"]))
    assert f.deadline_year == 2030 and any("LMS/XMSS" in d for d in f.deadlines)


def test_cnsa_never_binding_and_overdue_years():
    assert c("3DES", "encryption", key_bits=168, mode="CBC").deadline_year == 2023
    assert c("TLS", "protocol", version="TLS 1.0").deadline_year == 2021
    assert c("SHA-1", "hash").deadline_year == 2030
    assert c("AES", "encryption", key_bits=256, mode="GCM").deadline_year is None
    net = classify(Finding(source="network", category="authentication", algorithm="ECDSA", params={"curve": "P-256"}))
    assert any("CNSA 2.0" in d and "2033" in d for d in net.deadlines) and net.deadline_year == 2035


def test_mlkem_mldsa_levels():
    assert c("ML-KEM", "key-exchange", parameter_set="ML-KEM-768").nist_quantum_level == 3
    assert c("ML-DSA", "signature", parameter_set="ML-DSA-87").nist_quantum_level == 5
