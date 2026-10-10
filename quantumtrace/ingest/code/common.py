"""Shared helpers for the code scanners."""
from __future__ import annotations

import re

# identifiers that indicate a security-sensitive use of randomness
SEC_WORDS = ("token", "key", "secret", "salt", "nonce", "iv", "session", "password", "passwd", "otp", "csrf", "auth", "cookie")
# words next to "key" that make it a keyboard / dictionary key: press_key, keyCode, hotkey, keymap, sortByKey
NOT_CRYPTO_KEY = {"press", "pressed", "down", "up", "board", "stroke", "strokes", "map", "hot", "event", "events", "code", "binding",
                   "bind", "shortcut", "release", "handler", "listener", "input", "sort", "by", "value", "values", "name", "names",
                   "path", "lookup", "cache", "prefix", "exists", "primary", "foreign", "dict", "type"}


def name_words(name: str) -> list[str]:
    """generateAuthCode -> [generate, auth, code]; press_key -> [press, key]; MY_UID -> [my, uid]."""
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", name or "")]


def sec_name(name: str) -> bool:
    """Does a function name say it produces a security value? Whole words only: 'private' / 'archive' / 'derive' do not
    contain the word 'iv', and press_key / keyCode are keyboard keys."""
    words = name_words(name)
    hit = [w for w in words if w in SEC_WORDS or w in ("passwd", "pwd", "credential", "credentials", "authentication", "apikey")]
    if hit == ["key"] or set(hit) <= {"key"} and hit:
        return not (set(words) & NOT_CRYPTO_KEY)
    return bool(hit)
# words in a function BODY that show its randomness ends up in a security value (e.g. a doPost() that sets a
# session cookie). Narrower than SEC_WORDS: "key"/"iv"/"auth" are too common in ordinary code.
SEC_BODY_WORDS = ("cookie", "session", "token", "password", "passwd", "secret", "nonce", "salt", "csrf", "otp", "credential")


def sec_body(text: str) -> bool:
    t = text.lower()
    return any(w in t for w in SEC_BODY_WORDS)


_KEYISH = re.compile(r"(^|_)(key|secret|passwd|password|psk)($|_)|(key|secret)$", re.I)


def is_keyish(name: str) -> bool:
    n = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)  # camelCase -> snake
    return bool(_KEYISH.search(n)) and not re.search(r"(len|length|size|bits|bytes|id|name|path|file|type)$", n, re.I) \
        and not re.search(r"(table|prefix|suffix|index|header|field|column|param|label|attr|prop|url|uri|env|format|pattern|"
                          r"(db|cache|storage|redis|map|dict|lookup|store)_key|chars|charset|alphabet|regex|regexp|re|allowed)s?$", n, re.I)  # not secrets


def snippet(src: str, line: int) -> str:
    lines = src.splitlines()
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


def parse_int(text: str):
    t = text.strip().replace("_", "").rstrip("lL")
    try:
        return int(t, 0)
    except ValueError:
        return None


def unquote(text: str) -> str:
    t = text.strip()
    if len(t) >= 2 and t[0] in "\"'`" and t[-1] == t[0]:
        return t[1:-1]
    return t


# 'juiceshop_chat_conversations', 'scoreBoardChallenge', 'testChallenge1': names, not key material
# storage / cache / table names: acme_keyID_accountID_index, __flush_db__, javascript-key=, user:session:
_TEMPLATE = re.compile(r"%[sdvqx]|\{\w*\}|\$\{|\s--?\w|\(\?[=!:]|\\[dwsS]|^\^.*\$$")  # format strings, command lines, regexes
# (USER__INFO__, @activeBackup, $trigger, .data-api, [orderby, s3_test_request); real keys mix in many digits (JEECGBOOT1423670)
_IDENTIFIER_LIKE = re.compile(r"[\[@$._#:]*[A-Za-z]+\d{0,2}(?:[_\-.:/]+[A-Za-z]+\d{0,2})*[_=:\-./\]]*")


def looks_secret(value) -> bool:
    """Could this literal be key material? Rejects identifier-like strings (storage keys, cache keys, enum names)."""
    if isinstance(value, (bytes, bytearray)):
        try:  # Go []byte("acme_accounts"): a readable identifier is a name, not key material
            return len(value) >= 8 and not _IDENTIFIER_LIKE.fullmatch(value.decode("ascii"))
        except UnicodeDecodeError:
            return len(value) >= 8
    if isinstance(value, str) and (_TEMPLATE.search(value) or " " in value.strip() and "-----BEGIN" not in value):
        return False
    return isinstance(value, str) and len(value) >= 8 and not _IDENTIFIER_LIKE.fullmatch(value)


_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|testdata|test-fixtures|fixtures?|e2e|cypress|playwright)/|(^|/)src/test/|"
                        r"[._-](test|spec)\.[jt]sx?$|_test\.go$|(^|/)test_[^/]*\.py$|_test\.py$|Test\.java$")


def is_test_path(rel: str) -> bool:
    return bool(_TEST_PATH.search(rel.replace("\\", "/")))


def ssh_algorithm(name):
    """'3des-cbc' / 'hmac-md5' / 'diffie-hellman-group1-sha1' -> (category, algorithm, params) from the SSH knowledge base."""
    from ...kb import ssh as SSH
    if name == "none":
        return None  # also SSH's "no compression": too generic outside a Ciphers / MACs directive
    for category, table in (("key-exchange", SSH.KEX), ("encryption", SSH.CIPHER), ("mac", SSH.MAC), ("authentication", SSH.HOSTKEY)):
        if isinstance(name, str) and name in table:
            alg, params = table[name]
            return category, alg, dict(params)
    return None


_FAKE_WORDS = {"fake", "faker", "mock", "mocks", "dummy", "demo", "sample", "samples", "example", "stub", "jitter", "shuffle", "color", "colour"}


def fake_data(name: str = "", path: str = "") -> bool:
    """generate_fake() / utils/generate_fake_data/...: randomness for test data, not for secrets."""
    path_words = set(name_words(re.sub(r"[/\\._-]", " ", path)))  # a folder named samples/ or com/example/ says nothing
    return bool(set(name_words(name)) & _FAKE_WORDS or path_words & {"fake", "faker", "mock", "mocks", "dummy"})
