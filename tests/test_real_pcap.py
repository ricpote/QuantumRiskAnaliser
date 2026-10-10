"""Regression test on a REAL capture (samples/extra/pcap/lab-handshakes.pcapng, recorded with record.py):
real Go/OpenSSL clients vs the TLS lab, incl. HRR, STARTTLS on a non-standard port and certificates in clear."""
import os

import pytest

from quantumtrace.classify import classify_all
from quantumtrace.ingest import pcap

PCAP = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "pcap", "lab-handshakes.pcapng")


@pytest.fixture(scope="module")
def fs():
    os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")
    return classify_all(pcap.ingest(PCAP))


def by_stream(fs, s, cat):
    return [f for f in fs if f.location.get("stream") == s and f.category == cat]


def test_hybrid_pq_sessions(fs):
    for s in (0, 6, 8, 9):  # Go default client, PQ-only server, HRR, Postgres SSLRequest
        k = by_stream(fs, s, "key-exchange")[0]
        assert k.algorithm == "X25519MLKEM768" and k.risk_tier == "safe"
    assert "hrr" in by_stream(fs, 8, "key-exchange")[0].flags


def test_offered_vs_negotiated(fs):
    assert "pq-offered-not-negotiated" in by_stream(fs, 1, "key-exchange")[0].flags   # PQ client -> classical server
    assert "client-offered-no-pq" in by_stream(fs, 2, "key-exchange")[0].flags        # classical client -> PQ server


def test_tls12_certificates_in_clear(fs):
    k = by_stream(fs, 4, "key-exchange")[0]
    assert k.display_name == "RSA-2048" and "no-forward-secrecy" in k.flags and k.hndl
    cert = by_stream(fs, 4, "certificate")[0]
    assert {"expired", "weak-signature-hash"} <= set(cert.flags) and cert.classical_status == "broken"
    assert by_stream(fs, 5, "protocol")[0].display_name == "TLS 1.0"
    assert by_stream(fs, 5, "encryption")[0].display_name.startswith("3DES")


def test_starttls_on_any_port(fs):
    services = {f.location["stream"]: f.asset["service"] for f in fs}
    assert services[10] == "smtp-starttls" and services[9] == "postgresql"


SSH_PCAP = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "pcap", "lab-ssh.pcapng")


def test_real_ssh_on_custom_port():
    """OpenSSH 9.6 on port 2222: SSH must be recognised by its banner (never 'cleartext')."""
    fs = classify_all(pcap.ingest(SSH_PCAP))
    assert not [f for f in fs if f.algorithm == "PLAINTEXT"]
    kex = {f.location["stream"]: f for f in fs if f.category == "key-exchange"}
    assert kex[0].algorithm == "sntrup761x25519" and kex[0].risk_tier == "safe"           # OpenSSH default = PQ hybrid
    assert kex[2].algorithm == "X25519" and "pq-capable-not-enabled" in kex[2].flags      # PQ disabled by config
    assert kex[3].display_name == "DH-2048" and "sha1-kex" in kex[3].flags                # legacy group14-sha1
