"""Regressions found by running QuantumTrace on external code (OWASP Benchmark, OWASP Juice Shop)."""
import os

from quantumtrace.classify import classify_all
from quantumtrace.ingest import code
from quantumtrace.ingest.code.common import is_test_path, looks_secret

EXTRA = os.path.join(os.path.dirname(__file__), "..", "samples", "extra", "code")


def scan(rel):
    return classify_all(code.scan(os.path.join(EXTRA, rel), base=EXTRA))


def test_java_fully_qualified_calls_and_properties():
    fs = scan("java-props")
    assert any(f.algorithm == "DES" and f.params.get("mode") == "ECB" for f in fs)  # javax.crypto.Cipher + crypto.properties
    assert any(f.category == "hash" and f.algorithm == "SHA-256" for f in fs)        # properties override the MD5 default


def test_random_flagged_by_what_the_method_does():
    rng = [f for f in scan("java-props") if f.algorithm == "NON-CSPRNG"]
    assert [f.location["symbol"] for f in rng] == ["doPost"]  # sets a session cookie; pickTip() does not


def test_test_code_is_inventoried_but_not_production():
    fs = scan("js/payments-api/test")
    assert fs and all({"test-code", "demo-code"} <= set(f.flags) and f.confidence <= 0.5 for f in fs)


def test_secret_likeness():
    assert not looks_secret("juiceshop_chat_conversations") and not looks_secret("scoreBoardChallenge")
    assert looks_secret("changeme123") and looks_secret("pa4qacea4VK9t9nGv7yZtwmj")
    assert is_test_path("frontend/src/app/x.service.spec.ts") and is_test_path("src/test/java/FooTest.java")
    assert not is_test_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java")


def test_terraform_pem_key_is_parsed():
    rsa = [f for f in scan("terraform/secrets.tf") if f.algorithm == "RSA"]
    assert len(rsa) == 2 and all(f.params["key_bits"] == 1024 for f in rsa)  # plain literal and base64decode(...)


def test_cryptoapi_bench_patterns():
    """Inter-procedural, cross-file, path-sensitive and static-material cases (patterns from CryptoAPI-Bench)."""
    fs = scan("java-flow")
    lines = lambda what: [f.location["line"] for f in fs if f.params.get("what") == what]
    assert any(f.algorithm == "DES" and f.location["file"].endswith("LegacyCipher.java") for f in fs)  # value from Checkout.java
    assert lines("IV") == [37]           # randomMaterial(): IV replaced by nextBytes() before use -> not reported
    assert lines("salt") == [39]         # PBEParameterSpec(iv, count) in randomMaterial() is random too
    rc4 = [f for f in fs if f.algorithm == "RC4"]  # instantiated (inventory) but replaced before any use
    assert rc4 and all("overwritten-before-use" in f.flags and f.confidence <= 0.4 for f in rc4)


def test_api_variants_from_semgrep_rules():
    """Patterns from the Semgrep rule tests: pycryptodomex, hashlib.new(name=), usedforsecurity=False, DigestUtils,
    NullCipher, one key size per KeyPairGenerator / rsa.GenerateKey call."""
    fs = scan("api-variants")
    sizes = sorted(f.params.get("key_bits") for f in fs if f.algorithm == "RSA")
    assert sizes == [512, 1024, 1024, 3072, 4096]
    md5 = [f for f in fs if f.algorithm == "MD5" and f.location["file"].endswith(".py")]
    assert sorted("not-for-security" in f.flags for f in md5) == [False, True]
    assert any(f.algorithm == "NULL" for f in fs) and any(f.algorithm == "SHA3-224" for f in fs)


def test_hardening_patterns():
    """Patterns from the SonarSource / Semgrep rule tests (see scripts/sonar_bench.py, scripts/semgrep_rules_bench.py)."""
    fs = scan("hardening")
    by = lambda file: [f for f in fs if f.location["file"].endswith(file)]
    gw, py = by("Gateway.java"), by("accounts.py")
    assert [f.location["line"] for f in gw if f.params.get("what") == "IV"] == [33]   # ZERO_IV from CryptoConstants; open() is decrypt-only
    assert sorted(f.params.get("key_bits") for f in gw if f.algorithm == "RSA" and "padding" not in f.params) == [1024, 3072]
    assert [f.location["line"] for f in py if f.params.get("what") == "IV"] == [31]   # seal() encrypts; open_box() only decrypts
    assert not [f for f in by("sessions.js") if f.algorithm == "SHA-1"]               # notCrypto.subtle


def test_python2_file_still_scanned(tmp_path):
    p = tmp_path / "legacy.py"
    p.write_text("import hashlib\nprint 'start'\nKEY_SIZE = 1024L\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n")
    assert [f.algorithm for f in code.scan(str(p), base=str(tmp_path))] == ["MD5"]


def test_go_fixed_iv_and_tls_config():
    """gosec G407 / G402 patterns (see scripts/gosec_bench.py)."""
    fs = [f for f in scan("hardening") if f.location["file"].endswith("transport.go")]
    ivs = {f.location["symbol"]: f for f in fs if "static-iv" in f.flags}
    assert set(ivs) == {"sealRecord", "legacyStream"}           # seal() reads crypto/rand; openLegacy() only decrypts
    assert ivs["legacyStream"].location["related_lines"] == [11]  # where legacyIV is written
    assert [f.params["version"] for f in fs if f.category == "protocol"] == ["TLS 1.1"]  # modernTLS(): TLS 1.3 only
    assert any(f.algorithm == "RSA" and "no-forward-secrecy" in f.flags for f in fs)


def test_go_iv_buffer_simulation(tmp_path):
    src = '''package main
import ("crypto/cipher"; "crypto/rand"; "io")
func full(r io.Reader, b cipher.Block) { iv := make([]byte, 16); r.Read(iv); _ = cipher.NewCTR(b, iv) }
func half(b cipher.Block) { iv := make([]byte, 16); rand.Read(iv[:8]); _ = cipher.NewCTR(b, iv) }
func touched(b cipher.Block) { iv := make([]byte, 16); rand.Read(iv); iv[0] = 1; _ = cipher.NewCTR(b, iv) }
func helper() []byte { b := make([]byte, 12); rand.Read(b); return b }
func viaHelper(a cipher.AEAD) []byte { return a.Seal(nil, helper(), nil, nil) }
func zeroArray(b cipher.Block) { var iv [16]byte; _ = cipher.NewCTR(b, iv[:]) }
func main() {}
'''
    (tmp_path / "m.go").write_text(src)
    hit = {f.location["symbol"] for f in code.scan(str(tmp_path), base=str(tmp_path)) if "static-iv" in f.flags}
    assert hit == {"half", "touched", "zeroArray"}


def test_python_legacy_protocol_and_crypt_references():
    """Bandit B502 / B324 / B305 patterns (see scripts/bandit_bench.py)."""
    fs = scan("hardening/legacy_tls.py")
    assert sorted((f.location["line"], f.params["version"]) for f in fs if f.category == "protocol") == [(10, "TLS 1.1"), (15, "TLS 1.0"), (40, "TLS 1.1")]
    assert not [f for f in fs if f.location["line"] == 19]  # ctx.protocol == ssl.PROTOCOL_TLSv1 is a check
    assert any(f.algorithm == "MD5" and "password-hashing" in f.flags for f in fs)
    assert any("ecb-mode" in f.flags for f in fs)


def test_java_generator_belongs_to_its_own_getinstance():
    """CodeQL InsufficientKeySize patterns: the same variable name in two { } blocks, a re-assigned generator."""
    fs = scan("hardening/javasrc/com/example/hard/KeyMaterial.java")
    got = sorted((f.location["line"], f.algorithm, f.params.get("key_bits") or f.params.get("curve")) for f in fs)
    assert got == [(13, "RSA", 3072), (17, "DSA", 1024), (20, "RSA", 4096), (22, "ECDSA", "prime192v2"), (25, "DH", 1024), (28, "AES", 64)]
    assert all("short-key" in f.flags for f in fs if f.location["line"] in (17, 25, 28))


def test_go_paths_guards_and_predictable_randomness():
    fs = scan("hardening/gosvc/keys.go")
    at = lambda ln: [f for f in fs if f.location["line"] == ln]
    assert [f.params.get("key_bits") for f in at(22)] == [1024]                    # bits = small on one path
    assert [f.params.get("key_bits") for f in at(34)] == [None]                    # `if bits >= 2048` guards every path
    assert all("unreachable" in f.flags and f.confidence <= 0.3 for f in at(41))   # size := 1024; if size >= 2048 {...}
    assert len([f for f in at(49) if f.algorithm == "NON-CSPRNG"]) == 1             # rand.New(rand.NewSource(42)): one finding
    assert any(f.algorithm == "NON-CSPRNG" for f in at(51))                        # nonce filled from math/rand reaches Seal
    assert any(f.algorithm == "NON-CSPRNG" for f in at(63))                        # ed25519 seed from a math/rand helper
    assert [f.params["version"] for f in fs if f.category == "protocol"] == ["SSL 3.0"]
    assert any("insecure-cipher-suite" in f.flags for f in at(68))


def test_js_libraries_and_secret_names():
    fs = scan("hardening/web/client.js")
    by = {f.location["line"]: f for f in fs}
    assert "ecb-mode" in by[9].flags and by[13].params["key_bits"] == 64            # crypto-js
    assert by[18].algorithm == "3DES" and by[24].params["key_bits"] == 512          # node-forge, node-rsa
    assert 27 in by and 28 not in by                                                # sessionUid yes, liquid no
    assert "csprng-fallback" in by[36].flags and by[36].confidence <= 0.4
    assert "signature-not-verified" in by[40].flags                                 # jwt-simple noVerify = 'HS256' (truthy)
    assert "hardcoded-key" in by[44].flags                                          # express-session secret
    assert by[47].location["related_lines"] == [48]                                 # md5 digest stored with setPassword()


def test_python_aliases_and_variables():
    fs = scan("hardening/legacy_tls.py")
    by = {f.location["line"]: f for f in fs}
    assert by[40].params["version"] == "TLS 1.1"                                    # from ssl import PROTOCOL_TLSv1_1
    assert not [f for f in fs if 43 <= f.location["line"] <= 46]                    # SSLv23 + OP_NO_SSLv3: switched off
    assert by[50].params["key_bits"] == 1024                                        # new_rsa_key = rsa.generate_private_key
    assert by[55].algorithm == "RC4"                                                # algorithm = algorithms.ARC4(key)
    assert "password-hashing" in by[59].flags                                       # hashes.Hash(SHA256) in hash_password()


# ---- found by scanning real projects (gitea, saleor, Ghost, halo, JeecgBoot, jumpserver, pocketbase, directus, mitmproxy,
# ---- gogs, NodeBB, mall, paramiko, smallstep/certificates, Apache Shiro, parse-server)

def test_names_and_values_that_are_not_secrets():
    from quantumtrace.ingest.code.common import fake_data, is_keyish, sec_name
    for v in [b"acme_keyID_accountID_index", "__flush_db__", "javascript-key=", "USER__INFO__", "@activeBackup", "$trigger",
              ".data-api", "[orderby", "s3_test_request", 'command="%s serv key-%d" %s', r"^(?=.*\d).{8,}$"]:
        assert not looks_secret(v), v
    for v in ["JEECGBOOT1423670", "1234567890adbcde", "pa4qacea4VK9t9nGv7yZtwmj", b"0123456789abcdef"]:
        assert looks_secret(v), v
    for n in ["accountByKeyIDTable", "FLUSH_DB_KEY", "jsKeyPrefix", "KEY_CHARS_ALLOWED", "PASSWORD_REGEX"]:
        assert not is_keyish(n), n
    assert [sec_name(n) for n in ["press_key", "keyCode", "derivePrivateArchive", "generateAuthCode", "genIv"]] == [False, False, False, True, True]
    assert fake_data("generate_fake") and fake_data("", "utils/generate_fake_data/x.py") and not fake_data("", "samples/official/x.py")
    assert is_test_path("e2e/helpers/playwright/fixture.ts")


def test_python_value_resolution_is_not_exponential(tmp_path):
    import time
    chain = "\n".join(f"def f{i}(a, b, c):\n    return f{i + 1}(a, b, c) or f{i + 1}(b, c, a) or f{i + 1}(c, a, b)" for i in range(12))
    (tmp_path / "deep.py").write_text("import hashlib\n" + chain + "\ndef f12(a, b, c):\n    return hashlib.pbkdf2_hmac('sha256', a, b, c)\n"
                                      + "\n".join(f"f0(x{i}, y{i}, z{i})" for i in range(30)) + "\n")
    t = time.time()
    code.scan(str(tmp_path), base=str(tmp_path))
    assert time.time() - t < 5


def test_python_ssh_names_and_prehash(tmp_path):
    (tmp_path / "t.py").write_text(
        "import hashlib\n"
        "PREFERRED = ('aes256-ctr', '3des-cbc', 'hmac-md5')\n"
        "COMPRESSION = ('none', 'zlib')\n"
        "def encode(password, salt):\n"
        "    d = hashlib.sha512(password).digest()\n"
        "    return hashlib.pbkdf2_hmac('sha256', d, salt, 600000)\n")
    fs = classify_all(code.scan(str(tmp_path), base=str(tmp_path)))
    assert {f.params.get("ssh_name") for f in fs if f.params.get("ssh_name")} == {"aes256-ctr", "3des-cbc", "hmac-md5"}
    assert not any("password-hashing" in f.flags for f in fs if f.algorithm == "SHA-512")  # pre-hash for PBKDF2


def test_java_shiro_key_setters_and_algorithm_constants(tmp_path):
    d = tmp_path / "src" / "main" / "java" / "app"
    d.mkdir(parents=True)
    (tmp_path / "pom.xml").write_text("<project/>")
    (d / "Security.java").write_text(
        "package app;\n"
        "import org.apache.shiro.crypto.hash.Md5Hash;\n"
        "import org.apache.shiro.web.mgt.CookieRememberMeManager;\n"
        "import org.apache.shiro.codec.Base64;\n"
        "public class Security {\n"
        "    public static final String DIGEST_ALGORITHM = \"SHA-1\";\n"
        "    public static final String USED_ALGORITHM = \"MD5\";\n"
        "    String hash(String password, String salt) { return new Md5Hash(password, salt).toHex(); }\n"
        "    void remember(CookieRememberMeManager mgr) { mgr.setCipherKey(Base64.decode(\"kPH+bIxk5D2deZiIxcaaaA==\")); }\n"
        "    byte[] d(byte[] x) throws Exception { return java.security.MessageDigest.getInstance(USED_ALGORITHM).digest(x); }\n"
        "}\n")
    fs = classify_all(code.scan(str(tmp_path), base=str(tmp_path)))
    by = {f.location["line"]: f for f in fs}
    assert by[6].algorithm == "SHA-1" and by[6].confidence <= 0.6       # constant used indirectly
    assert 7 not in by                                                  # MD5 constant: reported where getInstance uses it
    assert by[8].algorithm == "MD5" and "password-hashing" in by[8].flags
    assert "hardcoded-key" in by[9].flags                               # the CVE-2016-4437 default rememberMe key


def test_js_minified_bundles_and_wrapped_random(tmp_path):
    (tmp_path / "bundle.js").write_text("var pw=\"__closure_events_fn_\"+(1E9*Math.random()>>>0);" + "var x=1;" * 400 + "\n")
    (tmp_path / "login.js").write_text("function thirdLoginUserCreate(info, token) {\n"
                                       "  info.suffix = parseInt(Math.random() * 98 + 1);\n"
                                       "  const aesKey = (Math.random() + 1).toString(36);\n  return [token, aesKey];\n}\n")
    fs = classify_all(code.scan(str(tmp_path), base=str(tmp_path)))
    rng = sorted((f.location["file"], f.location["line"]) for f in fs if f.algorithm == "NON-CSPRNG")
    assert rng == [("login.js", 3)]  # minified: no name heuristics; .suffix is not a secret; aesKey is


def test_go_ssh_algorithm_lists(tmp_path):
    (tmp_path / "s.go").write_text('package main\nimport "golang.org/x/crypto/ssh"\n'
                                   'var cfg = ssh.Config{Ciphers: []string{"aes128-ctr", "arcfour"}, MACs: []string{"hmac-sha1"}}\n')
    fs = classify_all(code.scan(str(tmp_path), base=str(tmp_path)))
    assert {f.params["ssh_name"] for f in fs} == {"aes128-ctr", "arcfour", "hmac-sha1"}
