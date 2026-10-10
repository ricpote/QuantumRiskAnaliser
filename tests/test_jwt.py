"""JWT detection (PyJWT, jjwt, auth0, golang-jwt): traps that ground_truth.json cannot express."""
import os

from quantumtrace.ingest.code import jwt_algorithms, python_ast, treesitter

JWT = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "code", "jwt")


def lines(fs):
    return {f.location["line"] for f in fs}


def test_python_traps():
    fs = python_ast.scan(os.path.join(JWT, "python", "auth_tokens.py"), "auth_tokens.py")
    assert 32 not in lines(fs)  # print("... RS256") is text, not an API call
    hs512 = [f for f in fs if f.params.get("jose") == "HS512"]
    assert hs512 and "hardcoded-key" not in hs512[0].flags  # secret read from os.environ


def test_go_method_type_check_is_not_an_algorithm():
    fs = treesitter.scan_go(os.path.join(JWT, "go", "session", "main.go"), "main.go")
    assert 20 not in lines(fs)  # t.Method.(*jwt.SigningMethodRSA): family check, no algorithm chosen
    assert {f.params.get("jose") for f in fs if "jwt" in f.flags} == {"HS256", "RS256", "PS256", "none"}


def test_normalize_library_spellings():
    assert jwt_algorithms.normalize("SigningMethodES384") == "ES384"
    assert jwt_algorithms.normalize("RSA256") == "RS256"        # auth0 Algorithm.RSA256
    assert jwt_algorithms.normalize("HMAC512") == "HS512"       # auth0 Algorithm.HMAC512
    assert jwt_algorithms.normalize("RSA_OAEP_256") == "RSA-OAEP-256"
    assert jwt_algorithms.normalize("NONE") == "none"
    assert jwt_algorithms.normalize("SigningMethodRSA") is None  # family type, not an algorithm
