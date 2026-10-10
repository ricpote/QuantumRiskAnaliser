"""Rules added after testing on files the scanner had never seen (P1 #5, #6, #7).

Each test writes a small file the way it appears in the wild and checks what is reported,
and just as important, what is NOT reported.
"""
import pytest

from quantumtrace.classify import classify_all
from quantumtrace.ingest import code
from quantumtrace.ingest.code import config
from quantumtrace.kb import ssh as SSH


@pytest.fixture(autouse=True)
def _now(monkeypatch):
    monkeypatch.setenv("QT_NOW", "2026-10-10T12:00:00Z")


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return classify_all(code.scan(str(p), str(tmp_path)))


# ------------------------------------------------------------------ #5 OpenSSH '+' '-' '^' against the defaults
def test_resolve_list_follows_openssh_semantics():
    base = SSH.DEFAULTS["kexalgorithms"]
    assert SSH.resolve_list("+diffie-hellman-group1-sha1", "KexAlgorithms")[0] == base + ["diffie-hellman-group1-sha1"]
    assert SSH.resolve_list("^curve25519-sha256", "kexalgorithms")[0][0] == "curve25519-sha256"
    removed, mode = SSH.resolve_list("-sntrup761x25519*", "kexalgorithms")
    assert mode == "remove" and not any(a.startswith("sntrup") for a in removed)
    assert SSH.resolve_list("curve25519-sha256", "kexalgorithms") == (["curve25519-sha256"], "replace")


def test_append_keeps_the_default_pq_hybrid(tmp_path):
    fs = _scan(tmp_path, "etc/ssh/sshd_config", "KexAlgorithms +diffie-hellman-group1-sha1\n")
    dh = next(f for f in fs if f.algorithm == "DH")
    assert "fallback-for-legacy-clients" in dh.flags and dh.risk_points < 100   # legacy clients only
    pq = next(f for f in fs if f.algorithm == "sntrup761x25519")
    assert pq.risk_tier == "safe" and "openssh-default" in pq.flags


def test_removing_the_pq_hybrid_is_reported(tmp_path):
    fs = _scan(tmp_path, "sshd_config", "KexAlgorithms -sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256\n")
    assert [(f.algorithm, f.risk_tier) for f in fs] == [("X25519", "critical")]
    assert "pq-removed" in fs[0].flags


def test_removing_other_algorithms_reports_nothing(tmp_path):
    assert _scan(tmp_path, "sshd_config", "KexAlgorithms -diffie-hellman-group14-sha256\nHostKeyAlgorithms -ssh-dss\n") == []


def test_client_prepend_takes_over_from_pq(tmp_path):
    fs = _scan(tmp_path, "ssh_config", "Host *\n    KexAlgorithms ^ecdh-sha2-nistp256\n")
    assert [f.flags for f in fs if f.algorithm == "ECDH"] == [["preferred-over-pq"]]
    assert not any(f.algorithm == "sntrup761x25519" for f in fs)


def test_explicit_list_still_flags_missing_pq(tmp_path):
    fs = _scan(tmp_path, "sshd_config", "KexAlgorithms curve25519-sha256\n")
    assert fs[0].flags == ["pq-capable-not-enabled"]


@pytest.mark.parametrize("name", ["sshd_config_hardened", "sshd_config.bak", "etc/ssh/server.conf"])
def test_sshd_config_found_by_name_or_content(tmp_path, name):
    fs = _scan(tmp_path, name, "Port 22\nPermitRootLogin no\nKexAlgorithms diffie-hellman-group14-sha1\n")
    assert any(f.algorithm == "DH" for f in fs)


@pytest.mark.parametrize("text", ["Ciphers are fun\n", "notes about MACs\nand more\n", "KexAlgorithms only\n"])
def test_prose_is_not_an_ssh_config(tmp_path, text):
    p = tmp_path / "notes.txt"
    p.write_text(text)
    assert config.kind(str(p)) is None


# ------------------------------------------------------------------ #7 nginx: cleartext vhosts and DH size
NGINX = """
server { listen 80; server_name blog.example.com; location / { root /var/www; } }
server { listen 80; server_name shop.example.com; return 301 https://$host$request_uri; }
server { listen 443 ssl; server_name api.example.com; ssl_dhparam /etc/nginx/dhparam-1024.pem; }
stream { server { listen 5432; proxy_pass db:5432; } }
"""


def test_plain_http_vhost_without_redirect(tmp_path):
    fs = _scan(tmp_path, "sites-enabled/site.conf", NGINX)
    plain = [f for f in fs if f.algorithm == "PLAINTEXT"]
    assert [f.asset.get("server_name") for f in plain] == ["blog.example.com"]   # not the redirect, not stream{}
    assert plain[0].risk_tier == "unencrypted"


def test_http_only_nginx_file_is_detected(tmp_path):
    fs = _scan(tmp_path, "conf.d/intranet.conf", "server {\n    server_name intranet.local;\n    root /srv;\n}\n")
    assert [f.algorithm for f in fs] == ["PLAINTEXT"] and fs[0].confidence < 1


def test_weak_dhparam(tmp_path):
    fs = _scan(tmp_path, "sites-enabled/site.conf", NGINX)
    dh = next(f for f in fs if f.algorithm == "DH")
    assert dh.params["key_bits"] == 1024 and "short-key" in dh.flags


def test_https_only_fixture_has_no_cleartext():
    assert not any(f.algorithm == "PLAINTEXT" for f in code.scan("samples/extra/code/nginx", "."))


# ------------------------------------------------------------------ #6 code rules
GO_TLS = """package main

import "crypto/tls"

func client() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	return cfg
}

func classical() *tls.Config {
	return &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
}

func hybrid() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
}
"""


def test_go_tls_config(tmp_path):
    fs = [f for f in _scan(tmp_path, "svc/main.go", GO_TLS) if f.context.get("api") == "crypto/tls.Config"]
    by = lambda fn: {(f.category, f.algorithm) for f in fs if f.location["symbol"] == fn}
    assert {("protocol", "TLS"), ("key-exchange", "RSA"), ("authentication", "NO-CERT-VERIFY")} <= by("client")
    assert all("pq-not-configured" in f.flags for f in fs if f.location["symbol"] == "classical")
    hy = [f for f in fs if f.location["symbol"] == "hybrid"]
    assert {f.algorithm: f.risk_tier for f in hy}["X25519MLKEM768"] == "safe"
    assert "fallback-for-legacy-clients" in next(f for f in hy if f.algorithm == "X25519").flags
    assert not any(f.category == "protocol" for f in hy)                      # TLS 1.3 minimum: nothing to report


def test_no_cert_verify_is_classically_broken(tmp_path):
    f = next(f for f in _scan(tmp_path, "svc/main.go", GO_TLS) if f.algorithm == "NO-CERT-VERIFY")
    assert f.classical_status == "broken" and "CWE-295" in f.cwe


JAVA = """import javax.crypto.*;
class K { void make() throws Exception { KeyGenerator kg = KeyGenerator.getInstance("AES"); kg.init(128); } }
"""


def test_java_keygenerator_size(tmp_path):
    fs = _scan(tmp_path, "K.java", JAVA)
    assert [(f.category, f.algorithm, f.params.get("key_bits"), f.risk_tier) for f in fs] == [("key", "AES", 128, "medium")]


PY = """import random, ssl, requests
def build():
    reset_token = random.randint(0, 10**9)
    apiKey = "".join(random.choices("abc", k=32))
    sort_key = random.random()
    delay = random.uniform(0.1, 0.5)
    requests.get("https://example.com", verify=False)
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_NONE
    class Opt: pass
    o = Opt(); o.verify = False
"""


def test_python_prng_by_variable_name(tmp_path):
    fs = _scan(tmp_path, "t.py", PY)
    prng = sorted(f.location["line"] for f in fs if f.algorithm == "NON-CSPRNG")
    assert prng == [3, 4]                                                     # sort_key and delay are not secrets


def test_python_tls_verification_bypass(tmp_path):
    fs = _scan(tmp_path, "t.py", PY)
    assert sorted(f.location["line"] for f in fs if f.algorithm == "NO-CERT-VERIFY") == [7, 9]
