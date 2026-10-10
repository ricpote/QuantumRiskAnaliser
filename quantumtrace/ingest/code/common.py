"""Shared helpers for the code scanners."""
from __future__ import annotations

import re

# identifiers that indicate a security-sensitive use of randomness
SEC_WORDS = ("token", "key", "secret", "salt", "nonce", "iv", "session", "password", "passwd", "otp", "csrf", "auth", "cookie")

_KEYISH = re.compile(r"(^|_)(key|secret|passwd|password|psk)($|_)|(key|secret)$", re.I)


def is_keyish(name: str) -> bool:
    n = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)  # camelCase -> snake
    return bool(_KEYISH.search(n)) and not re.search(r"(len|length|size|bits|bytes|id|name|path|file|type)$", n, re.I)


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
