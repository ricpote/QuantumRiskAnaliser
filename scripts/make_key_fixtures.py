"""Regenerate samples/extra/code/keys/ (certificate and key fixtures for the key-material scanner).

  python scripts/make_key_fixtures.py

Expectations live in tests/ground_truth.json ("extra/code/keys/..."). Dates are fixed so the
verdicts do not drift with the clock (QT_NOW in the tests is 2026-10-10).
"""
from __future__ import annotations

import datetime as dt
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "extra", "code", "keys")
UTC = dt.timezone.utc


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumTrace Fixtures")])


def cert(subject, key, issuer, issuer_key, start, end, ca=False, h=hashes.SHA256()):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(issuer_key, h)


def write(rel, data, mode="wb"):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as fh:
        fh.write(data)


def pem(c):
    return c.public_bytes(S.Encoding.PEM)


def main():
    t0, t_old, t_new = dt.datetime(2020, 1, 1, tzinfo=UTC), dt.datetime(2025, 6, 30, tzinfo=UTC), dt.datetime(2030, 1, 1, tzinfo=UTC)
    # 1. legacy root CA: RSA-1024, expired (2025-06-30). (cryptography no longer signs with SHA-1.)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    write("certs/legacy-root-ca.pem", pem(cert("Legacy Root CA", ca_key, "Legacy Root CA", ca_key, t0, t_old, ca=True)))
    # 2. chain file: ECDSA P-256 leaf issued by an RSA-3072 intermediate (two certificates, one file)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    inter = cert("Issuing CA 2", int_key, "Issuing CA 2", int_key, t0, t_new, ca=True)
    leaf = cert("shop.example.com", leaf_key, "Issuing CA 2", int_key, t0, t_new)
    write("certs/shop-chain.pem", pem(leaf) + pem(inter))
    # 3. DER certificate (binary): Ed25519 device certificate
    dev_key = ed25519.Ed25519PrivateKey.generate()
    write("certs/device.der", cert("device-0042", dev_key, "device-0042", dev_key, t0, t_new, h=None).public_bytes(S.Encoding.DER))
    # 4. ML-DSA-65 certificate (FIPS 204): quantum-safe
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        pq_key = mldsa.MLDSA65PrivateKey.generate()
        write("certs/pq-signing.pem", pem(cert("pq-signing.example.com", pq_key, "pq-signing.example.com", pq_key, t0, t_new, h=None)))
    except Exception as e:  # older OpenSSL builds
        print("ML-DSA certificate not generated:", e)
    # 5. unencrypted PKCS#8 RSA private key committed with the code
    deploy = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write("deploy.key", deploy.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()))
    # 6. passphrase-protected traditional RSA key (algorithm readable, key protected)
    write("legacy-enc.key", rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        S.Encoding.PEM, S.PrivateFormat.TraditionalOpenSSL, S.BestAvailableEncryption(b"fixture-passphrase")))
    # 7. encrypted PKCS#8: algorithm hidden -> warning, no finding (trap)
    write("vault-enc.key", ec.generate_private_key(ec.SECP384R1()).private_bytes(
        S.Encoding.PEM, S.PrivateFormat.PKCS8, S.BestAvailableEncryption(b"fixture-passphrase")))
    # 8. OpenSSH keys
    ssh_priv = ed25519.Ed25519PrivateKey.generate()
    write("ssh/id_ed25519", ssh_priv.private_bytes(S.Encoding.PEM, S.PrivateFormat.OpenSSH, S.NoEncryption()))
    ecdsa_pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH)
    write("ssh/id_ecdsa.pub", ecdsa_pub + b" deploy@ci\n")
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH)
    ok = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(S.Encoding.OpenSSH, S.PublicFormat.OpenSSH)
    write("ssh/authorized_keys", b"# team keys\n" + weak + b" legacy-admin@old-laptop\n" + ok + b" alice@laptop\n")
    # 9. certificate embedded in a YAML config (found by content, not by extension)
    write("app-config.yaml", b"service: payments\ntls:\n  ca_bundle: |\n" +
          b"".join(b"    " + ln + b"\n" for ln in pem(inter).splitlines()))
    # 10. Java keystore: cannot be read without the store password -> warning only (trap)
    write("truststore.jks", bytes.fromhex("feedfeed00000002") + os.urandom(64))
    print("fixtures written to", OUT)


if __name__ == "__main__":
    main()
