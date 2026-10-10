"""JavaScript / TypeScript scanner (node:crypto, WebCrypto, jsonwebtoken, jose): traps ground_truth.json cannot express."""
import os

from quantumtrace.ingest.code import treesitter

JS = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "code", "js")


def scan(rel):
    return treesitter.scan_js(os.path.join(JS, rel), rel)


def test_non_security_random_and_log_strings_are_ignored():
    fs = scan("payments-api/src/crypto-utils.js")
    assert not [f for f in fs if f.location.get("symbol") in ("shuffleCards", "logMigration")]


def test_webcrypto_params_resolved_through_typed_constant():
    rsa = [f for f in scan("web-client/src/vault.ts") if f.algorithm == "RSA"]
    assert rsa and rsa[0].params["key_bits"] == 2048  # const SHARE_ALGO: RsaHashedKeyGenParams = {...}


def test_cipher_names():
    assert treesitter.js_cipher("aes-128-ecb") == ("AES", 128, "ECB")
    assert treesitter.js_cipher("aes256") == ("AES", 256, "CBC")  # OpenSSL alias: CBC
    assert treesitter.js_cipher("id-aes128-GCM") == ("AES", 128, "GCM")
    assert treesitter.js_cipher("des-ede3-cbc") == ("3DES", 168, "CBC")
    assert treesitter.js_cipher("camellia-128-cbc") is None
