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
    # Two binaries, same installed Go (>= 1.24): `modern` for X25519MLKEM768;
    # `legacy` declares `go 1.21.13` in its go.mod, so it gets Go 1.21's default
    # GODEBUG (RSA key-transport, 3DES and TLS 1.0 enabled). No download needed.
    procs = []
    if not _up(8443) or not _up(8445):
        go = shutil.which("go")
        if not go:
            pytest.skip("Go not installed: cannot start the TLS lab")
        for name, ports in (("modern", (8443, 8444, 8446, 8447, 2525, 5433)), ("legacy", (8445,))):
            if all(_up(p) for p in ports):
                continue
            src = os.path.join(LAB, name)
            binary = os.path.join(src, f"tlslab-{name}-test")
            subprocess.run([go, "build", "-o", binary, "."], cwd=src, check=True)
            procs.append((binary, subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)))
        for _ in range(50):
            if _up(8443) and _up(8445) and _up(5433):
                break
            time.sleep(0.1)
    yield
    for binary, proc in procs:
        proc.terminate()
        proc.wait(timeout=5)  # Windows keeps the .exe locked for a moment after the process exits
        for attempt in range(10):
            try:
                os.remove(binary)
                break
            except PermissionError:
                if attempt == 9:
                    break  # leftover binary is harmless (rebuilt next run); never fail the suite over cleanup
                time.sleep(0.2)


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
    """Modern clients get PQ; legacy clients fall back to TLS 1.2 ECDHE (still forward-secret
    within the session, RSA only for authentication). Go >= 1.22 disabled plain RSA
    key-transport by default (only the legacy/ half, port 8445, still serves it), so this
    profile no longer offers that cipher (see tls-lab/modern/main.go) — ECDHE+RSA-auth is
    the realistic classical fallback now. It's still HNDL-exposed: forward secrecy defeats a
    passive eavesdropper today, but not "harvest now, break the classical ECDH with Shor's
    algorithm later" — only the PQ group above is actually safe from that."""
    rep, fs = run("127.0.0.1:8446")
    assert rep["modern"]["group_name"] == "X25519MLKEM768" and rep["modern"]["cert_verify_name"] == "rsa_pss_rsae_sha256"
    assert any(f.algorithm.startswith("ECDH") and f.hndl for f in kex(fs))   # TLS 1.2 ECDHE fallback, still HNDL-exposed


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
