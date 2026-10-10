"""Live-probe tests against the local TLS lab (samples/extra/tls-lab, needs Go >= 1.24).

The lab is started automatically if `go` is available, otherwise these tests are skipped.
"""
import os
import shutil
import socket
import subprocess
import time

import pytest

from quantumtrace.classify import classify_all
from quantumtrace.ingest import probe as P

LAB = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "tls-lab")


def _up(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def lab():
    proc = None
    if not _up(8443):
        go = shutil.which("go")
        if not go:
            pytest.skip("Go not installed: cannot start the TLS lab")
        env = dict(os.environ, GODEBUG="tlsrsakex=1,tls3des=1,tls10server=1")
        binary = os.path.join(LAB, "tlslab-test")
        subprocess.run([go, "build", "-o", binary, "."], cwd=LAB, check=True, env=env)
        proc = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if _up(8443) and _up(5433):
                break
            time.sleep(0.1)
    yield
    if proc:
        proc.terminate()
        os.remove(os.path.join(LAB, "tlslab-test"))


def run(target, **kw):
    rep = P.probe(target, **kw)
    return rep, classify_all(P.to_findings(rep))


def kex(fs):
    return [f for f in fs if f.category == "key-exchange"]


def test_pq_modern(lab):
    rep, fs = run("127.0.0.1:8443")
    assert rep["modern"]["group_name"] == "X25519MLKEM768"
    assert rep["modern"]["key_share_len"] == 1120              # FIPS 203 ML-KEM-768 ciphertext + X25519
    assert rep["modern"]["cert_verify_name"] == "ecdsa_secp256r1_sha256"  # read by decrypting our own handshake
    assert rep["versions"] == {"TLS 1.3": True, "TLS 1.2": False, "TLS 1.1": False, "TLS 1.0": False, "SSL 3.0": False}
    main = kex(fs)[0]
    assert main.algorithm == "X25519MLKEM768" and main.risk_tier == "safe" and not main.hndl
    fb = [f for f in kex(fs) if "fallback-for-legacy-clients" in f.flags]
    assert fb and all(f.risk_points == 60 for f in fb)
    auth = [f for f in fs if f.category == "authentication"][0]
    assert auth.display_name == "ECDSA-P-256" and auth.risk_tier == "critical"


def test_pq_only(lab):
    rep, fs = run("127.0.0.1:8447")
    assert [k for k, v in rep["groups"].items() if v["supported"]] == ["X25519MLKEM768"]
    assert "pq-only" in kex(fs)[0].flags


def test_classical_tls13(lab):
    rep, fs = run("127.0.0.1:8444")
    main = kex(fs)[0]
    assert main.algorithm == "X25519" and main.risk_tier == "critical" and main.hndl
    assert "pq-not-supported" in main.flags


def test_legacy(lab):
    rep, fs = run("127.0.0.1:8445")
    assert rep["versions"]["TLS 1.0"] and rep["versions"]["TLS 1.1"] and not rep["versions"]["TLS 1.3"]
    assert any(f.algorithm == "RSA" and "no-forward-secrecy" in f.flags for f in kex(fs))
    assert any(f.display_name.startswith("3DES") for f in fs if f.category == "encryption")
    cert = [f for f in fs if f.category == "certificate"][0]
    assert {"expired", "weak-signature-hash"} <= set(cert.flags) and cert.classical_status == "broken"
    assert {f.display_name for f in fs if f.category == "protocol" and f.classical_status == "deprecated"} == {"TLS 1.0", "TLS 1.1"}


def test_pq_with_tls12_fallback(lab):
    rep, fs = run("127.0.0.1:8446")
    assert rep["modern"]["group_name"] == "X25519MLKEM768" and rep["modern"]["cert_verify_name"] == "rsa_pss_rsae_sha256"
    assert any(f.algorithm == "RSA" and f.hndl for f in kex(fs))   # TLS 1.2 RSA key transport still accepted


def test_starttls_smtp_and_postgres(lab):
    rep, fs = run("127.0.0.1:2525")
    assert rep["starttls"] == "smtp" and rep["modern"]["group_name"] == "x25519"
    rep, fs = run("127.0.0.1:5433")
    assert rep["starttls"] == "postgres" and rep["modern"]["group_name"] == "X25519MLKEM768"


def test_pq_supported_not_preferred_logic():
    """Go >= 1.24 always prefers PQ, so this case is checked on a synthetic report."""
    rep = dict(target="x:443", host="x", ip="10.0.0.1", port=443, starttls=None, started="2026-10-10T12:00:00+00:00", connections=1,
               versions={"TLS 1.3": True}, tls13_ciphers=["TLS_AES_128_GCM_SHA256"], tls12_ciphers=[], sigalg_families={}, certs=[], errors=[],
               groups={"X25519MLKEM768": dict(code=0x11EC, supported=True), "x25519": dict(code=0x001D, supported=True)},
               modern=dict(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256", group=0x001D, group_name="x25519", hrr=False, key_share_len=32))
    fs = classify_all(P.to_findings(rep))
    main = kex(fs)[0]
    assert main.algorithm == "X25519" and "pq-supported-not-preferred" in main.flags and main.hndl
