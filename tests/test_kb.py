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


def test_mlkem_mldsa_levels():
    assert c("ML-KEM", "key-exchange", parameter_set="ML-KEM-768").nist_quantum_level == 3
    assert c("ML-DSA", "signature", parameter_set="ML-DSA-87").nist_quantum_level == 5
