"""Config scanners (nginx / Apache / sshd / Terraform): traps that ground_truth.json cannot express."""
import os

from quantumtrace.classify import classify_all
from quantumtrace.ingest.code import config

EXTRA = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "code")


def scan(rel):
    return classify_all(config.scan(os.path.join(EXTRA, rel), rel))


def test_terraform_redirect_is_not_cleartext():
    plain = [f for f in scan("terraform/main.tf") if f.algorithm == "PLAINTEXT"]
    assert [f.asset["address"] for f in plain] == ["aws_lb_listener.batch_http"]  # http_redirect only redirects to HTTPS


def test_terraform_resolves_policy_variable_and_lb_scheme():
    fs = [f for f in scan("terraform/main.tf") if f.asset.get("address") == "aws_lb_listener.https"]
    assert fs and all(f.context["ssl_policy"] == "ELBSecurityPolicy-2016-08" for f in fs)  # var.legacy_tls_policy
    assert all("internet-facing" in f.flags for f in fs)  # aws_lb.public has internal = false


def test_sshd_removal_and_comments_are_ignored():
    fs = scan("ssh/sshd_config")
    assert not [f for f in fs if f.algorithm == "DSA"]
    assert {f.location["line"] for f in fs} == {4, 5, 7, 8, 9, 14}


def test_cipher_string_semantics():
    names = lambda spec: [n for n, _ in config._expand_ciphers(spec)[0]]
    assert names("DES-CBC3-SHA:RC4-SHA") == ["DES-CBC3-SHA", "RC4-SHA"]  # legacy names resolved without the local OpenSSL
    assert names("ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:!RC4") == ["ECDHE-RSA-AES128-GCM-SHA256"]  # "!" removes permanently


def test_only_tls_configs_are_sniffed(tmp_path):
    other = tmp_path / "app.conf"
    other.write_text("[database]\nhost = db.internal\nssl = true\n")
    assert config.kind(str(other)) is None
