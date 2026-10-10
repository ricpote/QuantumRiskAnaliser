"""Python SAST via the stdlib `ast` module (no regex on raw text -> no hits in comments/strings).

Resolves imports to fully-qualified names, propagates constants (module, function,
default parameters, simple one-level call-site/return resolution) to infer key sizes,
modes, hashes and iteration counts.
"""
from __future__ import annotations

import ast
import re
import os
import re
import warnings

from ...schema import Finding
from . import jwt_algorithms
from .common import fake_data, is_keyish, looks_secret, sec_body, sec_name, snippet, ssh_algorithm

HASHLIB = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
           "sha512": "SHA-512", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
           "blake2b": "BLAKE2b", "blake2s": "BLAKE2s", "shake_128": "SHAKE128", "shake_256": "SHAKE256",
           "md4": "MD4", "ripemd160": "RIPEMD-160", "sha512_256": "SHA-512/256", "sha3_224": "SHA3-224",
           "sha": "SHA-1"}  # hashlib.new('sha'): OpenSSL's old alias
# legacy protocol versions: ssl.PROTOCOL_*, pyOpenSSL SSL.*_METHOD, ssl.TLSVersion.* (SSLv23_METHOD negotiates down to SSL 3.0)
PY_TLS_VERSIONS = {"PROTOCOL_SSLv2": "SSL 2.0", "PROTOCOL_SSLv3": "SSL 3.0", "PROTOCOL_TLSv1": "TLS 1.0", "PROTOCOL_TLSv1_1": "TLS 1.1",
                   "SSLv2_METHOD": "SSL 2.0", "SSLv3_METHOD": "SSL 3.0", "SSLv23_METHOD": "TLS 1.0", "TLSv1_METHOD": "TLS 1.0",
                   "TLSv1_1_METHOD": "TLS 1.1", "TLSVersion.SSLv3": "SSL 3.0", "TLSVersion.TLSv1": "TLS 1.0", "TLSVersion.TLSv1_1": "TLS 1.1"}
PY_TLS_MODULES = ("ssl.", "OpenSSL.SSL.", "pyOpenSSL.SSL.")
# Unix crypt(3) schemes: DES-crypt (56-bit, 8-character passwords) and MD5-crypt are broken; METHOD_BLOWFISH is bcrypt
PY_CRYPT = {"METHOD_CRYPT": ("kdf", "DES"), "METHOD_MD5": ("hash", "MD5"), "METHOD_BLOWFISH": ("kdf", "bcrypt")}
CRY_HASHES = {"MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
              "SHA512_256": "SHA-512/256", "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512",
              "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256", "BLAKE2b": "BLAKE2b", "BLAKE2s": "BLAKE2s"}
CRY_CIPHERS = {"AES": "AES", "AES128": "AES", "AES256": "AES", "TripleDES": "3DES", "ChaCha20": "ChaCha20-Poly1305",
               "ARC4": "RC4", "Blowfish": "Blowfish", "CAST5": "CAST5", "SEED": "SEED", "IDEA": "IDEA", "Camellia": "Camellia", "SM4": "SM4"}
CRY_AEAD = {"AESGCM": ("AES", "GCM"), "AESCCM": ("AES", "CCM"), "AESOCB3": ("AES", "OCB"), "AESSIV": ("AES", "SIV"),
            "AESGCMSIV": ("AES", "GCM-SIV"), "ChaCha20Poly1305": ("ChaCha20-Poly1305", None)}
P = "cryptography.hazmat.primitives."
PYCRYPTO_HASH = {"MD2": "MD2", "MD4": "MD4", "MD5": "MD5", "SHA": "SHA-1", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256",
                 "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA3_224": "SHA3-224", "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384",
                 "SHA3_512": "SHA3-512", "BLAKE2b": "BLAKE2b", "BLAKE2s": "BLAKE2s", "RIPEMD160": "RIPEMD-160", "RIPEMD": "RIPEMD-160",
                 "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256"}
EC_CURVES = {"SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521", "SECP256K1": "secp256k1", "SECP224R1": "P-224",
             "SECP192R1": "P-192", "BRAINPOOLP256R1": "brainpoolP256r1", "BRAINPOOLP384R1": "brainpoolP384r1", "BRAINPOOLP512R1": "brainpoolP512r1"}
RANDOM_FUNCS = {"random", "randint", "getrandbits", "randbytes", "choice", "choices", "randrange", "sample", "uniform"}


class _Ctx:
    def __init__(self, tree, path, src):
        self.tree, self.path, self.src = tree, path, src
        self.imports = {}       # local name -> fqn (module-level imports win; function-level ones are only a fallback)
        self.scoped_imports = {}  # function node -> {local name -> fqn} for imports written inside that function
        self.consts = {}        # (func or None, name) -> ast expr
        self.funcs = {}         # name -> FunctionDef
        self.calls = []         # (fqn, call node, enclosing func)
        self.call_targets = {}  # id(call) -> names it is assigned to (token = random.randint(...))
        self.no_verify = []     # (node, text, func): TLS certificate checks switched off
        self.parent = {}
        self.trace = []         # names resolved during the last _value() call
        self.main_names = set() # names assigned inside `if __name__ == "__main__":`
        for node in ast.walk(tree):
            for ch in ast.iter_child_nodes(node):
                self.parent[ch] = node
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        self.main_names.update(t.id for t in sub.targets if isinstance(t, ast.Name))


def _fqn(node, ctx):
    if isinstance(node, ast.Name):
        scope = _enclosing_func(node, ctx)
        while scope is not None:  # `import scrypt` inside a function shadows a module-level name
            if node.id in ctx.scoped_imports.get(scope, {}):
                return ctx.scoped_imports[scope][node.id]
            scope = _enclosing_func(scope, ctx)
        alias = ctx.consts.get((None, node.id)) if node.id not in ctx.imports else None
        if isinstance(alias, ast.Attribute):  # rsa_gen_key = rsa.generate_private_key; rsa_gen_key(65537, 1024)
            root = alias
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in ctx.imports:
                return _fqn(alias, ctx)
        return ctx.imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _fqn(node.value, ctx)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        inner = _fqn(node.func, ctx)
        return inner + "()" if inner else None  # x[0]() / (lambda: ...)()
    return None


def _enclosing_func(node, ctx):
    while node in ctx.parent:
        node = ctx.parent[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def _value(node, ctx, func=None, depth=0):
    """Best-effort constant evaluation. Returns int | str | bytes | ('bytes', n) | None.

    Memoized per (node, function, depth): parameters resolve through every call site, which resolves its own parameters
    the same way - without the cache that is exponential (2.3M calls for one 12 KB file). The cache also replays the
    names the evaluation went through (ctx.trace), which decide whether a literal lives in demo code."""
    if node is None or depth > 6:
        return None
    memo = ctx.__dict__.setdefault("_vmemo", {})
    key = (id(node), id(func), depth)
    if key in memo:
        v, names = memo[key]
        ctx.trace.extend(names)
        return v
    memo[key] = (None, [])  # in progress: a cycle resolves to "unknown"
    start = len(ctx.trace)
    v = _value_uncached(node, ctx, func, depth)
    memo[key] = (v, ctx.trace[start:])
    return v


def _value_uncached(node, ctx, func, depth):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        fn = func.name if func is not None else None
        for key in ((fn, node.id), (None, node.id)):
            if key in ctx.consts:
                ctx.trace.append(key)
                return _value(ctx.consts[key], ctx, func if key[0] else None, depth + 1)
        # function parameter -> default value or call-site argument
        if func is not None:
            args = func.args
            names = [a.arg for a in args.args]
            if node.id in names:
                idx = names.index(node.id)
                defaults = [None] * (len(names) - len(args.defaults)) + list(args.defaults)
                vals = [_value(c, ctx, cf, depth + 1) for c, cf in _callsite_args(func.name, idx, node.id, ctx)]
                vals = [v for v in vals if v is not None]
                if vals:
                    return vals[0]
                if defaults[idx] is not None:
                    return _value(defaults[idx], ctx, None, depth + 1)
        return None
    if isinstance(node, ast.Attribute) and node.attr == "block_size":  # AES.block_size / algorithms.AES.block_size
        return 16
    if isinstance(node, ast.BinOp):
        a, b = _value(node.left, ctx, func, depth + 1), _value(node.right, ctx, func, depth + 1)
        if isinstance(node.op, ast.Mult) and isinstance(a, (bytes, str)) and isinstance(b, int) and 0 <= b <= 4096:
            return a * b  # b'x' * 16
        if isinstance(node.op, ast.Add) and isinstance(a, (bytes, str)) and type(a) is type(b):
            return a + b
        if isinstance(a, int) and isinstance(b, int):
            try:
                return {ast.Mult: a * b, ast.Add: a + b, ast.Sub: a - b, ast.FloorDiv: a // b if b else None,
                        ast.LShift: a << b if 0 <= b < 4096 else None, ast.Pow: a ** b if 0 <= b < 4096 else None}.get(type(node.op))
            except Exception:
                return None
        return None
    if isinstance(node, ast.Call):
        f = _fqn(node.func, ctx) or ""
        if f in ("os.urandom", "secrets.token_bytes") and node.args:
            n = _value(node.args[0], ctx, func, depth + 1)
            return ("bytes", n) if isinstance(n, int) else None
        if f.endswith(".generate_key"):  # AESGCM.generate_key(bit_length=256)
            for kw in node.keywords:
                if kw.arg == "bit_length":
                    n = _value(kw.value, ctx, func, depth + 1)
                    return ("bytes", n // 8) if isinstance(n, int) else None
        name = f.split(".")[-1]
        if name in ctx.funcs:  # local helper: resolve its return value
            fd = ctx.funcs[name]
            for r in ast.walk(fd):
                if isinstance(r, ast.Return):
                    v = _value(r.value, ctx, fd, depth + 1)
                    if v is not None:
                        return v
        if isinstance(node.func, ast.Attribute) and node.func.attr == "encode":
            v = _value(node.func.value, ctx, func, depth + 1)
            return v.encode() if isinstance(v, str) else None
        if re.fullmatch(r"base64\.(b16|b32|b64|urlsafe_b64)(en|de)code", f) and node.args:  # base64.b64decode("abc"): still a literal
            v = _value(node.args[0], ctx, func, depth + 1)
            return v.encode() if isinstance(v, str) else v if isinstance(v, bytes) else None
        if f in ("bytes.fromhex", "bytearray.fromhex") and node.args:  # bytes.fromhex("00ff..."): built from a literal
            v = _value(node.args[0], ctx, func, depth + 1)
            return v.encode() if isinstance(v, str) else v if isinstance(v, bytes) else None
        if f in ("bytes", "bytearray") and node.args:
            v = _value(node.args[0], ctx, func, depth + 1)
            return v.encode() if isinstance(v, str) else (bytes(v) if isinstance(v, int) and 0 <= v <= 4096 else v if isinstance(v, bytes) else None)
    return None


def _callsite_args(fname, idx, pname, ctx):
    out = []
    for fqn, call, encl in ctx.calls:
        if fqn.split(".")[-1] == fname:
            if idx < len(call.args):
                out.append((call.args[idx], encl))
            for kw in call.keywords:
                if kw.arg == pname:
                    out.append((kw.value, encl))
    return out


_PY2 = [(re.compile(r"\b(\d+)[lL]\b"), r"\1"),                                    # 1024L
        (re.compile(r"^(\s*)print\s+(?![\s(=])(.+?)\s*$", re.M), r"\1print(\2)"),    # print x
        (re.compile(r"^(\s*except\s+[\w.]+)\s*,\s*(\w+)\s*:", re.M), r"\1 as \2:"),  # except E, e:
        (re.compile(r"\b[uU][rR](['\"])"), r"r\1"),                                  # ur'...'
        (re.compile(r"\bexec\s+(['\"])"), r"exec(\1")]


def _parse_tolerant(src, attempts=50):
    """ast.parse that survives Python 2 files and the odd broken line: rewrite common Python 2 syntax, then replace
    each line that still does not parse with `pass` (same indentation, so line numbers never move)."""
    try:
        with warnings.catch_warnings():  # "\d" in the scanned code's own strings: its problem, not ours
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(src), src
    except (SyntaxError, ValueError):
        pass
    for rx, repl in _PY2:
        src = rx.sub(repl, src)
    lines = src.splitlines()
    for _ in range(attempts):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                return ast.parse("\n".join(lines)), "\n".join(lines)
        except SyntaxError as e:
            i = (e.lineno or 0) - 1
            if not 0 <= i < len(lines) or lines[i].strip() == "pass":
                return None, src
            lines[i] = lines[i][:len(lines[i]) - len(lines[i].lstrip())] + "pass"
        except ValueError:
            return None, src
    return None, src


def _truncated(call, ctx):
    """hashlib.md5(x).hexdigest()[:8]: a few characters of a digest are an identifier (cache key, short id), not a
    security digest -> inventoried but flagged not-for-security."""
    node, digest = call, False
    for _ in range(4):
        parent = ctx.parent.get(node)
        if isinstance(parent, ast.Subscript) and parent.value is node and isinstance(parent.slice, ast.Slice):
            up = parent.slice.upper
            short = isinstance(up, ast.Constant) and isinstance(up.value, int) and 1 <= up.value <= 16
            return ["not-for-security", "truncated-digest"] if digest and short else []
        if isinstance(parent, ast.Attribute):
            digest = digest or parent.attr in ("hexdigest", "digest")
            node = parent
            continue
        if isinstance(parent, ast.Call):
            node = parent
            continue
        break
    return []


# Django hashers / passlib schemes built on a fast digest (or none)
DJANGO_WEAK_HASHERS = {"MD5PasswordHasher": "MD5", "UnsaltedMD5PasswordHasher": "MD5", "SHA1PasswordHasher": "SHA-1",
                       "UnsaltedSHA1PasswordHasher": "SHA-1", "CryptPasswordHasher": "DES"}
DJANGO_HASHER_NAMES = {"md5": "MD5", "unsalted_md5": "MD5", "sha1": "SHA-1", "unsalted_sha1": "SHA-1", "crypt": "DES"}
PASSLIB_WEAK = {"apr_md5_crypt": "MD5", "md5_crypt": "MD5", "hex_md5": "MD5", "ldap_md5": "MD5", "ldap_salted_md5": "MD5",
                "hex_sha1": "SHA-1", "ldap_sha1": "SHA-1", "ldap_salted_sha1": "SHA-1", "sha1_crypt": "SHA-1", "des_crypt": "DES",
                "bsdi_crypt": "DES", "bigcrypt": "DES", "crypt16": "DES", "mysql323": "MD5", "lmhash": "DES", "nthash": "MD4"}


def _legacy_references(tree, ctx, add):
    """Constants that choose a legacy protocol / scheme wherever they appear (a call argument, a default parameter,
    ctx.minimum_version = ...): ssl.PROTOCOL_TLSv1, SSL.SSLv3_METHOD, crypt.METHOD_MD5; and modes.ECB() on its own."""
    ssh_seen = set()
    for node in ast.walk(tree):
        parent = ctx.parent.get(node)
        if isinstance(node, ast.Constant) and isinstance(parent, (ast.Tuple, ast.List, ast.Set, ast.Dict)) \
                and node.value not in ssh_seen and ssh_algorithm(node.value):
            # SSH algorithm names offered by an SSH implementation: _preferred_ciphers = ("aes128-ctr", "3des-cbc")
            ssh_seen.add(node.value)
            cat, alg, params = ssh_algorithm(node.value)
            add(node, cat, alg, dict(params, ssh_name=node.value), f"SSH algorithm '{node.value}' listed in code", confidence=0.8,
                api="ssh", func=_enclosing_func(node, ctx))
            continue
        if isinstance(node, (ast.Attribute, ast.Name)) and isinstance(node.ctx, ast.Load) and isinstance(parent, (ast.Dict, ast.Tuple, ast.List)):
            fqn = _fqn(node, ctx) or ""
            m = re.match(r"cryptography\.hazmat\.(?:primitives|decrepit)\.ciphers\.algorithms\.(\w+)$", fqn)
            if m and m.group(1) in CRY_CIPHERS and CRY_CIPHERS[m.group(1)] != "AES":
                # {"3des-cbc": {"class": TripleDES, ...}}: a cipher class offered from a table, instantiated elsewhere
                add(node, "encryption", CRY_CIPHERS[m.group(1)], {}, f"cipher class {m.group(1)} offered in a lookup table",
                    confidence=0.8, api=fqn, func=_enclosing_func(node, ctx))
                continue
        if isinstance(node, (ast.Attribute, ast.Name)) and not isinstance(parent, ast.Attribute) \
                and not (isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)):
            fqn = _fqn(node, ctx) or ""  # ssl.PROTOCOL_TLSv1, or PROTOCOL_TLSv1 after `from ssl import PROTOCOL_TLSv1`
            mod = next((m for m in PY_TLS_MODULES if fqn.startswith(m)), None)
            up, in_compare = node, False
            while up in ctx.parent and not isinstance(up, ast.stmt):
                up = ctx.parent[up]
                in_compare = in_compare or isinstance(up, ast.Compare)
            if in_compare:
                continue  # if ctx.protocol == ssl.PROTOCOL_TLSv1: a check, not a choice
            func = _enclosing_func(node, ctx)
            if mod and fqn[len(mod):] in PY_TLS_VERSIONS:
                v, name = PY_TLS_VERSIONS[fqn[len(mod):]], fqn[len(mod):]
                scope_src = ast.get_source_segment(ctx.src, func) if func is not None else ctx.src
                if "SSLv23" in name and "OP_NO_SSLv3" in (scope_src or ""):
                    continue  # SSL.Context(SSLv23_METHOD) + set_options(OP_NO_SSLv3): legacy versions switched off
                add(node, "protocol", "SSL" if v.startswith("SSL") else "TLS", dict(version=v),
                    f"{fqn} enables {v}" + (" (SSLv23_METHOD: the lowest version the OpenSSL build allows - SSL 3.0 before OpenSSL 1.1, "
                                            "TLS 1.0 after - unless set_min_proto_version / OP_NO_* restrict it)" if "SSLv23" in name else ""),
                    confidence=0.5 if "SSLv23" in name else 1.0, api=fqn, func=func)
            elif fqn.startswith("crypt.") and fqn[6:] in PY_CRYPT:
                cat, alg = PY_CRYPT[fqn[6:]]
                add(node, cat, alg, dict(scheme=fqn[6:]), f"crypt(3) password scheme {fqn}", ["password-hashing"], api=fqn, func=func)
        elif isinstance(node, ast.Call) and (_fqn(node.func, ctx) or "").endswith("modes.ECB") \
                and not (isinstance(parent, ast.Call) and node in parent.args):
            # mode = modes.ECB(): the cipher it is combined with is decided elsewhere (inside Cipher(...) it is reported there)
            add(node, "encryption", "UNKNOWN-CIPHER", dict(mode="ECB"), "cipher mode ECB selected (modes.ECB())", ["ecb-mode"],
                confidence=0.6, api=_fqn(node.func, ctx), func=_enclosing_func(node, ctx))


def _password_frameworks(tree, ctx, add):
    """Django PASSWORD_HASHERS / hasher subclasses / make_password(hasher=), Werkzeug generate_password_hash(method=),
    passlib weak schemes, and weak hashlib constructors referenced without being called (hasher = hashlib.md5)."""
    pw = ["password-hashing"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):  # 'django.contrib.auth.hashers.UnsaltedMD5PasswordHasher'
            cls = node.value.rsplit(".", 1)[-1]
            if cls in DJANGO_WEAK_HASHERS and node.value.startswith("django."):
                add(node, "hash", DJANGO_WEAK_HASHERS[cls], {}, f"Django password hasher {cls}", pw + (["unsalted"] if "Unsalted" in cls else []),
                    api="django.contrib.auth.hashers")
        elif isinstance(node, ast.ClassDef):
            for b in node.bases:
                base = (_fqn(b, ctx) or "").rsplit(".", 1)[-1]
                if base in DJANGO_WEAK_HASHERS:
                    add(node, "hash", DJANGO_WEAK_HASHERS[base], {}, f"password hasher subclass of {base}", pw, api="django.contrib.auth.hashers")
        elif isinstance(node, ast.Call):
            fqn = _fqn(node.func, ctx) or ""
            kw = {k.arg: k.value for k in node.keywords}
            if fqn.endswith("make_password") and "hasher" in kw:
                h = _value(kw["hasher"], ctx, _enclosing_func(node, ctx))
                if isinstance(h, str) and h in DJANGO_HASHER_NAMES:
                    add(node, "hash", DJANGO_HASHER_NAMES[h], {}, f"make_password(hasher={h!r})", pw, api="django.contrib.auth.hashers.make_password")
            elif fqn.endswith("generate_password_hash") and (kw.get("method") is not None or len(node.args) > 1):
                m = _value(kw.get("method", node.args[1] if len(node.args) > 1 else None), ctx)
                if isinstance(m, str) and m.split(":")[0].lower() in HASHLIB:  # werkzeug: a bare digest name instead of pbkdf2:/scrypt
                    add(node, "hash", HASHLIB[m.split(":")[0].lower()], {}, f"generate_password_hash(method={m!r})", pw,
                        api="werkzeug.security.generate_password_hash")
        elif isinstance(node, (ast.Attribute, ast.Name)) and not isinstance(ctx.parent.get(node), ast.Attribute):
            fqn = _fqn(node, ctx) or ""
            parent = ctx.parent.get(node)
            if fqn.startswith("passlib.hash.") and fqn.rsplit(".", 1)[-1] in PASSLIB_WEAK:
                add(node, "hash", PASSLIB_WEAK[fqn.rsplit(".", 1)[-1]], {}, f"passlib {fqn.rsplit('.', 1)[-1]} password scheme", pw, api="passlib.hash")
            elif isinstance(parent, ast.Call) and parent.func is node:
                continue  # a called hashlib constructor: handled by the call loop
            elif fqn.startswith("hashlib.") and fqn.split(".")[-1] in HASHLIB and HASHLIB[fqn.split(".")[-1]] in ("MD5", "SHA-1", "MD4", "SHA-224") \
                    and isinstance(ctx.parent.get(node), (ast.Expr, ast.Assign, ast.Return, ast.keyword)) \
                    and not (isinstance(ctx.parent.get(node), ast.keyword) and ctx.parent.get(node).arg == "digestmod"):
                # hasher = hashlib.md5 / return hashlib.sha1: the constructor itself is handed out (digestmod= is the HMAC branch)
                add(node, "hash", HASHLIB[fqn.split(".")[-1]], {}, f"{fqn} referenced", api=fqn)


def _fixed(node, ctx, func):
    """A literal (or something built only from literals), resolved through constants -> (fixed?, value)."""
    if node is None:
        return False, None
    v = _value(node, ctx, func)
    return isinstance(v, (bytes, str)) and not isinstance(v, bool), v


# salt sinks: fqn suffix -> (password position/keyword, salt position/keyword)
SALT_SINKS = {"hashlib.pbkdf2_hmac": ((1, "password"), (2, "salt")), "hashlib.scrypt": ((0, "password"), (None, "salt")),
              "Crypto.Protocol.KDF.PBKDF2": ((0, "password"), (1, "salt")), "Crypto.Protocol.KDF.scrypt": ((0, "password"), (1, "salt")),
              "Crypto.Protocol.KDF.bcrypt": ((0, "password"), (2, "salt")), "kdf.pbkdf2.PBKDF2HMAC": ((None, None), (2, "salt")),
              "kdf.scrypt.Scrypt": ((None, None), (0, "salt")), "bcrypt.hashpw": ((0, "password"), (1, "salt")),
              "crypt.crypt": ((0, "word"), (1, "salt"))}
IV_MODES = {"CBC", "CFB", "CFB8", "OFB", "CTR", "GCM", "OCB", "EAX", "SIV"}


def _derive_arg(call, ctx, func):
    """Scrypt(...).derive(x) or kdf = Scrypt(...); kdf.derive(x) in the same function -> the x node."""
    parent = ctx.parent.get(call)
    if isinstance(parent, ast.Attribute) and parent.attr == "derive":
        outer = ctx.parent.get(parent)
        if isinstance(outer, ast.Call):
            return _arg(outer, 0, "key_material")
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name):
        name = parent.targets[0].id
        for _f, c, fn2 in ctx.calls:
            if fn2 is func and isinstance(c.func, ast.Attribute) and c.func.attr == "derive" \
                    and isinstance(c.func.value, ast.Name) and c.func.value.id == name:
                return _arg(c, 0, "key_material")
    return None


def _arg(call, pos, kw):
    if kw:
        for k in call.keywords:
            if k.arg == kw:
                return k.value
    return call.args[pos] if pos is not None and len(call.args) > pos else None


def _static_material(ctx, add, findings):
    """Fixed salts (or salt == password) and fixed IVs / nonces in Python (CWE-760 / CWE-329)."""
    for fqn, call, func in ctx.calls:
        sink = next((v for k, v in SALT_SINKS.items() if fqn == k or fqn.endswith("." + k)), None)
        if sink:
            (ppos, pkw), (spos, skw) = sink
            salt, pw = _arg(call, spos, skw), _arg(call, ppos, pkw) if (ppos is not None or pkw) else None
            if pw is None and salt is not None:  # cryptography KDF objects: the key material arrives later in .derive(x)
                pw = _derive_arg(call, ctx, func)
            fixed, v = _fixed(salt, ctx, func)
            same = salt is not None and pw is not None and ast.dump(salt) == ast.dump(pw)
            if fixed or same:
                why = "the salt is the password itself" if same and not fixed else f"fixed salt {(v[:24] if isinstance(v, (bytes, str)) else v)!r}"
                add(call, "key", "HARDCODED-KEY", dict(name=ast.unparse(salt)[:40], what="salt"), f"{fqn}(): {why}", ["static-salt"], api=fqn, func=func)
            continue
        # IV / nonce: Cipher(algorithms.X(key), modes.CBC(iv)) / AES.new(key, AES.MODE_CBC, iv)
        iv_node, mode = None, None
        if (fqn.endswith("ciphers.Cipher") or fqn == "Cipher") and len(call.args) > 1 or any(k.arg == "mode" for k in call.keywords) and fqn.endswith("Cipher"):
            m = call.args[1] if len(call.args) > 1 else next(k.value for k in call.keywords if k.arg == "mode")
            if isinstance(m, ast.Call):
                mode = (_fqn(m.func, ctx) or "").split(".")[-1]
                iv_node = m.args[0] if m.args else next((k.value for k in m.keywords if k.arg in ("initialization_vector", "nonce", "tweak")), None)
        elif fqn.startswith("Crypto.Cipher.") and fqn.endswith(".new"):
            mn = _arg(call, 1, "mode")
            mode = (_fqn(mn, ctx) or "").split(".")[-1].replace("MODE_", "") if mn is not None else None
            iv_node = _arg(call, 2, "iv") or _arg(call, None, "IV") or _arg(call, None, "nonce")
        if mode not in IV_MODES or iv_node is None:
            continue
        fixed, v = _fixed(iv_node, ctx, func)
        if not fixed:
            continue
        # only when the cipher object encrypts: decryption must reuse the IV that came with the ciphertext
        var = ctx.parent.get(call)
        name = var.targets[0].id if isinstance(var, ast.Assign) and len(var.targets) == 1 and isinstance(var.targets[0], ast.Name) else None
        uses = [c for f2, c, fn2 in ctx.calls if name and fn2 is func and isinstance(c.func, ast.Attribute)
                and isinstance(c.func.value, ast.Name) and c.func.value.id == name]
        enc = [c for c in uses if c.func.attr in ("encrypt", "encryptor", "encrypt_and_digest")]
        if name and not enc:
            continue  # only decrypt / not used here
        add(call, "key", "HARDCODED-KEY", dict(name=ast.unparse(iv_node)[:40], what="IV", mode=mode),
            f"fixed {'nonce' if mode in ('CTR', 'GCM', 'EAX', 'OCB', 'SIV') else 'IV'} in {mode} mode", ["static-iv"], api=fqn, func=func)
        if enc:
            findings[-1].location["related_lines"] = sorted({c.lineno for c in enc})


PASSLIB_PBKDF2_DEFAULT = {"pbkdf2_sha1": ("SHA-1", 131000), "pbkdf2_sha256": ("SHA-256", 29000), "pbkdf2_sha512": ("SHA-512", 25000)}
# OWASP Password Storage Cheat Sheet: Argon2id minimum memory (KiB) for a given number of passes (p=1)
ARGON2_MIN_MEMORY = {1: 47104, 2: 19456, 3: 12288, 4: 9216}


def _argon2_ok(t, m):
    return t is None or m is None or m >= ARGON2_MIN_MEMORY.get(t, 7168)


def _password_cost(ctx, add):
    """Work factors of password hashes: passlib pbkdf2_*/scrypt/bcrypt .using()/.hash(), argon2-cffi (OWASP minimums)."""
    for fqn, call, func in ctx.calls:
        kw = {k.arg: _value(k.value, ctx, func) for k in call.keywords}
        base, _, meth = fqn.rpartition(".")
        scheme = base.rsplit(".", 1)[-1]
        if base.startswith("passlib.hash.") and meth in ("using", "hash", "encrypt"):
            if scheme in PASSLIB_PBKDF2_DEFAULT:
                h, default = PASSLIB_PBKDF2_DEFAULT[scheme]
                rounds = kw.get("rounds", _value(call.args[1], ctx, func) if meth == "using" and len(call.args) > 1 else None)
                it = rounds if isinstance(rounds, int) else default
                add(call, "kdf", "PBKDF2", dict(hash=h, iterations=it), f"passlib {scheme}.{meth}(rounds={it})", api=fqn, func=func)
            elif scheme == "scrypt":  # passlib: rounds = log2(N), block_size = r
                rounds = kw.get("rounds", _value(call.args[2], ctx, func) if len(call.args) > 2 else None)
                bs = kw.get("block_size", _value(call.args[3], ctx, func) if len(call.args) > 3 else None)
                add(call, "kdf", "scrypt", {k: v for k, v in dict(cost_n=2 ** rounds if isinstance(rounds, int) and rounds < 64 else None,
                                                                  block_size=bs if isinstance(bs, int) else None).items() if v},
                    f"passlib scrypt.{meth}(rounds={rounds}, block_size={bs})", api=fqn, func=func)
            elif scheme in ("bcrypt", "bcrypt_sha256"):
                rounds = kw.get("rounds")
                if isinstance(rounds, int):
                    add(call, "kdf", "bcrypt", dict(cost=rounds), f"passlib {scheme}.{meth}(rounds={rounds})", api=fqn, func=func)
            elif scheme == "argon2":
                t, m = kw.get("time_cost"), kw.get("memory_cost")
                add(call, "kdf", "Argon2", {k: v for k, v in dict(time_cost=t, memory_kib=m).items() if isinstance(v, int)},
                    f"passlib argon2.{meth}(time_cost={t}, memory_cost={m})", [] if _argon2_ok(t, m) else ["weak-kdf-params"], api=fqn, func=func)
        elif fqn in ("bcrypt.gensalt",) and (call.args or "rounds" in kw):
            rounds = kw.get("rounds", _value(call.args[0], ctx, func) if call.args else None)
            if isinstance(rounds, int):
                add(call, "kdf", "bcrypt", dict(cost=rounds), f"bcrypt.gensalt({rounds})", api=fqn, func=func)
        elif fqn in ("argon2.PasswordHasher", "argon2.low_level.hash_secret", "argon2.low_level.hash_secret_raw") or \
                fqn.endswith(("argon2.PasswordHasher",)):
            t = kw.get("time_cost", _value(call.args[2], ctx, func) if "hash_secret" in fqn and len(call.args) > 2 else
                       _value(call.args[0], ctx, func) if call.args and "PasswordHasher" in fqn else None)
            m = kw.get("memory_cost", _value(call.args[3], ctx, func) if "hash_secret" in fqn and len(call.args) > 3 else
                       _value(call.args[1], ctx, func) if len(call.args) > 1 and "PasswordHasher" in fqn else None)
            add(call, "kdf", "Argon2", {k: v for k, v in dict(time_cost=t, memory_kib=m).items() if isinstance(v, int)},
                f"argon2 time_cost={t}, memory_cost={m} KiB", [] if _argon2_ok(t, m) else ["weak-kdf-params"], api=fqn, func=func)
    for node in ast.walk(ctx.tree):  # argon2.profiles.CHEAPEST: a test-only profile
        if isinstance(node, (ast.Attribute, ast.Name)) and (_fqn(node, ctx) or "") == "argon2.profiles.CHEAPEST" \
                and not isinstance(ctx.parent.get(node), ast.Attribute):
            add(node, "kdf", "Argon2", dict(profile="CHEAPEST"), "argon2.profiles.CHEAPEST (meant for tests only)", ["weak-kdf-params"],
                api="argon2.profiles")


def _cipher_string_findings(spec):
    """OpenSSL cipher string -> weak primitives it enables (same expansion as the nginx / Apache scanner)."""
    from . import config
    suites, expanded = config._expand_ciphers(spec)
    conf = 0.8 if expanded else 1.0
    out, seen = [], set()
    rsa = [n for n, s in suites if s["kex"] == "RSA"]
    if rsa:
        out.append(("key-exchange", "RSA", dict(transport=True), f"RSA key transport without forward secrecy ({', '.join(rsa[:3])})",
                    ["no-forward-secrecy"], conf))
    for n, s in suites:
        key = (s["cipher"], s["cipher_bits"], s["mode"])
        if s["cipher"] and key not in seen and s["cipher"] in ("3DES", "DES", "RC4", "NULL", "RC2", "IDEA", "SEED") or s["export"] and key not in seen:
            seen.add(key)
            out.append(("encryption", s["cipher"], dict(key_bits=s["cipher_bits"], mode=s["mode"]), f"enables {n}", [], conf))
    return out


def _scrypt_params(call, fqn, ctx, func):
    """N / r / output length of an scrypt call -> params (classify: weak when N < 2^13, r < 8 or < 32 bytes of output)."""
    kw = {k.arg: k.value for k in call.keywords}
    if fqn == "hashlib.scrypt":                      # scrypt(password, *, salt, n, r, p, maxmem, dklen)
        names = {"n": "n", "r": "r", "dklen": "dklen"}
        pos = {"n": 2, "r": 3, "dklen": 6}  # keyword-only in CPython; positional forms still appear in code
    elif "Protocol.KDF" in fqn:                       # pycryptodome scrypt(password, salt, key_len, N, r, p)
        names, pos = {"n": "N", "r": "r", "dklen": "key_len"}, {"dklen": 2, "n": 3, "r": 4}
    else:                                             # py-scrypt hash(password, salt, N=1<<14, r=8, p=1, buflen=64)
        names, pos = {"n": "N", "r": "r", "dklen": "buflen"}, {"n": 2, "r": 3, "dklen": 5}
    out = {}
    for key, kwname in names.items():
        node = kw.get(kwname, call.args[pos[key]] if key in pos and len(call.args) > pos[key] else None)
        v = _value(node, ctx, func) if node is not None else None
        if isinstance(v, int):
            out[{"n": "cost_n", "r": "block_size", "dklen": "key_bits"}[key]] = v * 8 if key == "dklen" else v
    return out


def _as_call(node, ctx, func):
    """algorithm = algorithms.ARC4(key); Cipher(algorithm, ...): the call a variable holds (same function or module)."""
    if isinstance(node, ast.Name):
        for key in ((func.name if func is not None else None, node.id), (None, node.id)):
            if isinstance(ctx.consts.get(key), ast.Call):
                return ctx.consts[key]
    return node


def _ec_name(name):
    """'secp192r1' / 'P-192' / 'NIST P-256' / 'prime256v1' / 'p256' -> canonical curve name."""
    n = str(name).lower().replace("nist ", "").replace("-", "")
    return {"p192": "P-192", "secp192r1": "P-192", "prime192v1": "P-192", "p224": "P-224", "secp224r1": "P-224",
            "p256": "P-256", "secp256r1": "P-256", "prime256v1": "P-256", "p384": "P-384", "secp384r1": "P-384",
            "p521": "P-521", "secp521r1": "P-521", "ed25519": "Curve25519"}.get(n, str(name))


def _not_for_security(call, ctx, func):
    """hashlib.md5(..., usedforsecurity=False): the code itself declares a non-security use (Python >= 3.9)."""
    kw = next((k.value for k in call.keywords if k.arg == "usedforsecurity"), None)
    return ["not-for-security"] if kw is not None and _value(kw, ctx, func) is False else []


def _nbytes(v):
    if isinstance(v, (bytes, bytearray)):
        return len(v)
    if isinstance(v, str):
        return len(v.encode())
    if isinstance(v, tuple) and v and v[0] == "bytes":
        return v[1]
    return None


_SECRET_WORDS = {"token", "secret", "salt", "nonce", "iv", "session", "password", "passwd", "otp", "csrf", "apikey", "pin", "key"}
_NOT_SECRET_BEFORE_KEY = {"sort", "cache", "lookup", "dict", "map", "index", "row", "col", "partition", "shard", "group", "order",
                          "primary", "foreign", "hash", "sample", "random", "seed"}


def _secret_name(name: str) -> bool:
    """reset_token / apiKey / otp_code / session_id -> True; sort_key / jitter / delay -> False."""
    words = [w.lower() for w in re.split(r"_|(?<=[a-z0-9])(?=[A-Z])", name) if w]
    for i, w in enumerate(words):
        if w == "key":
            if i and words[i - 1] in _NOT_SECRET_BEFORE_KEY:
                continue
            return True
        if w in _SECRET_WORDS:
            return True
    return False


def _is_http_session(owner, ctx, func) -> bool:
    """s.verify = False only matters when s is a requests.Session / httpx.Client."""
    if isinstance(owner, ast.Name):
        v = ctx.consts.get((func.name if func else None, owner.id)) or ctx.consts.get((None, owner.id))
        return isinstance(v, ast.Call) and (_fqn(v.func, ctx) or "").startswith(("requests.", "httpx."))
    return isinstance(owner, ast.Attribute) and "session" in owner.attr.lower()


def _is_literal_key(node, ctx, func):
    """True if the key resolves to a bytes/str literal defined outside the __main__ demo block."""
    ctx.trace = []
    v = _value(node, ctx, func)
    if not isinstance(v, (bytes, str)):
        return False
    return not any(fn is None and name in ctx.main_names for fn, name in ctx.trace)


def scan(path: str, rel: str) -> list[Finding]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    tree, src = _parse_tolerant(src)
    if tree is None:
        return []
    ctx = _Ctx(tree, rel, src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                pairs = [(a.asname or a.name.split(".")[0], a.name if a.asname else a.name.split(".")[0]) for a in node.names]
            elif node.module:
                pairs = [(a.asname or a.name, f"{node.module}.{a.name}") for a in node.names]
            else:
                pairs = []
            scope = _enclosing_func(node, ctx)
            for local, fq in pairs:
                if scope is None:
                    ctx.imports[local] = fq
                else:
                    ctx.scoped_imports.setdefault(scope, {})[local] = fq
                    ctx.imports.setdefault(local, fq)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ctx.funcs[node.name] = node
    ctx.imports = {k: re.sub(r"^Cryptodome(?=\.|$)", "Crypto", v) for k, v in ctx.imports.items()}  # pycryptodomex == pycryptodome
    ctx.scoped_imports = {sc: {k: re.sub(r"^Cryptodome(?=\.|$)", "Crypto", v) for k, v in d.items()} for sc, d in ctx.scoped_imports.items()}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            encl = _enclosing_func(node, ctx)
            for t in targets:
                if isinstance(t, ast.Name) and node.value is not None:
                    ctx.consts.setdefault((encl.name if encl else None, t.id), node.value)
            names = [t.id if isinstance(t, ast.Name) else t.attr for t in targets if isinstance(t, (ast.Name, ast.Attribute))]
            if node.value is not None and names:
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Call):
                        ctx.call_targets.setdefault(id(sub), names)
            # ctx.verify_mode = ssl.CERT_NONE / session.verify = False
            for t in targets:
                if isinstance(t, ast.Attribute) and node.value is not None and (
                        (t.attr == "verify_mode" and (_fqn(node.value, ctx) or "").endswith("CERT_NONE"))
                        or (t.attr == "verify" and isinstance(node.value, ast.Constant) and node.value.value is False
                            and _is_http_session(t.value, ctx, encl))):
                    ctx.no_verify.append((node, f"{ast.unparse(t)} = {ast.unparse(node.value)}", encl))
        elif isinstance(node, ast.Call):
            ctx.calls.append((_fqn(node.func, ctx) or "", node, _enclosing_func(node, ctx)))

    findings: list[Finding] = []
    lang_asset = dict(kind="source-file", path=rel, language="python")

    def add(node, category, algorithm, params, evidence, flags=(), confidence=1.0, api=None, func=None):
        if not isinstance(params.get("key_bits"), (int, type(None))) or isinstance(params.get("key_bits"), bool):
            params = dict(params, key_bits=None)  # key_size=3.14 or a resolved string: unknown, never a crash
        findings.append(Finding(source="code", category=category, algorithm=algorithm, params={k: v for k, v in params.items() if v is not None},
                                asset=dict(lang_asset), location=dict(file=rel, line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno), column=node.col_offset + 1,
                                                                      snippet=snippet(src, node.lineno), symbol=func.name if func else "<module>"),
                                context=dict(api=api, language="python"), evidence=evidence, flags=list(flags), confidence=confidence))

    rsa_bits = {}
    for fqn, call, func in ctx.calls:
        if fqn.endswith("rsa.generate_private_key"):
            ks = next((kw.value for kw in call.keywords if kw.arg == "key_size"), call.args[1] if len(call.args) > 1 else None)
            rsa_bits[None] = _value(ks, ctx, func)

    # what is the RSA key used for in this module? (sign/verify vs encrypt/decrypt)
    def rsa_role():
        for fqn, call, _ in ctx.calls:
            if fqn.endswith(".sign") or fqn.endswith(".verify"):
                return "signature"
            if fqn.endswith(".encrypt") or fqn.endswith(".decrypt"):
                if any("OAEP" in (_fqn(a.func, ctx) or "") for a in call.args if isinstance(a, ast.Call)):
                    return "encryption"
        return "signature"

    def jwt_call(call, name, fqn, func):
        """PyJWT / python-jose: jwt.encode(payload, key, algorithm=...) / jwt.decode(token, key, algorithms=[...])."""
        kw = {k.arg: k.value for k in call.keywords}
        key = call.args[1] if len(call.args) > 1 else kw.get("key")
        if name == "encode":
            a = kw.get("algorithm", call.args[2] if len(call.args) > 2 else None)
            algs = [_value(a, ctx, func) if a is not None else "HS256"]  # HS256 is the PyJWT / python-jose default
        else:
            lst = kw.get("algorithms")
            algs = [_value(e, ctx, func) for e in lst.elts] if isinstance(lst, (ast.List, ast.Tuple)) else []
            opts = kw.get("options")
            if isinstance(opts, ast.Dict) and any(_value(k, ctx, func) == "verify_signature" and _value(v, ctx, func) is False
                                                  for k, v in zip(opts.keys, opts.values)):
                add(call, "signature", "NULL", dict(jose="none"), f"{fqn}(..., options={{'verify_signature': False}}): token signature is never checked",
                    ["jwt", "signature-not-verified"], api=fqn, func=func)
        for a in algs:
            jn = jwt_algorithms.normalize(a)
            if not jn:
                continue
            category, alg, params, flags = jwt_algorithms.finding_args(jn)
            if alg == "HMAC" and key is not None:
                kb = _nbytes(_value(key, ctx, func))
                params["key_bits"] = kb * 8 if kb else None
                if _is_literal_key(key, ctx, func):
                    flags.append("hardcoded-key")
            add(call, category, alg, params, f"{fqn}(..., {'algorithm' if name == 'encode' else 'algorithms'}={jn!r})", flags, api=fqn, func=func)

    for fqn, call, func in ctx.calls:
        name = fqn.split(".")[-1]
        fname = (func.name if func else "").lower()
        fname_ = func.name if func is not None else ""
        sec_ctx = not fake_data(fname_, ctx.path) and (sec_name(fname_) or (func is not None and sec_body(ast.get_source_segment(src, func) or "")))
        # ---------------- JWT ----------------
        if fqn.startswith(("jwt.", "jose.jwt.")) and name in ("encode", "decode"):
            jwt_call(call, name, fqn, func)
        # ---------------- hashlib ----------------
        elif fqn.startswith("hashlib.") and name in HASHLIB:
            flags = []
            argnames = " ".join(ast.unparse(a) for a in call.args).lower()
            prehash = func is not None and re.search(r"pbkdf2|bcrypt|argon2|scrypt", ast.get_source_segment(src, func) or "", re.I)
            if ("password" in fname or "passwd" in fname or "password" in argnames) and not prehash:
                flags += ["password-hashing", "unsalted"]  # (a digest then fed to PBKDF2 / bcrypt is a pre-hash, not the storage hash)
            add(call, "hash", HASHLIB[name], {}, f"hashlib.{name}() call", flags + _not_for_security(call, ctx, func) + _truncated(call, ctx),
                api=fqn, func=func)
        elif fqn == "hashlib.new" and (call.args or any(k.arg == "name" for k in call.keywords)):
            v = _value(call.args[0] if call.args else next(k.value for k in call.keywords if k.arg == "name"), ctx, func)
            if isinstance(v, str):
                add(call, "hash", HASHLIB.get(v.lower().replace("-", ""), v.upper()), {}, f"hashlib.new({v!r})",
                    _not_for_security(call, ctx, func), api=fqn, func=func)
        elif fqn == "hashlib.pbkdf2_hmac":
            h = _value(call.args[0], ctx, func) if call.args else None
            it = _value(call.args[3], ctx, func) if len(call.args) > 3 else None
            add(call, "kdf", "PBKDF2", dict(hash=HASHLIB.get(str(h).lower(), str(h).upper()), iterations=it), "hashlib.pbkdf2_hmac()", api=fqn, func=func)
        elif fqn == "hashlib.scrypt" or fqn in ("scrypt.hash", "scrypt.scrypt.hash") or fqn.endswith(".Protocol.KDF.scrypt") \
                or fqn == "Crypto.Protocol.KDF.scrypt":
            add(call, "kdf", "scrypt", _scrypt_params(call, fqn, ctx, func), f"{fqn}()", api=fqn, func=func)
        # ---------------- hmac ----------------
        elif fqn in ("hmac.new", "hmac.digest"):
            dm = call.args[2] if len(call.args) > 2 else next((kw.value for kw in call.keywords if kw.arg == "digestmod"), None)
            h = None
            if dm is not None:
                d = _fqn(dm, ctx) or ""
                h = HASHLIB.get(d.split(".")[-1]) if d.startswith("hashlib.") else (_value(dm, ctx, func) or None)
                if isinstance(h, str) and h.lower() in HASHLIB:
                    h = HASHLIB[h.lower()]
            key = call.args[0] if call.args else None
            kb = _nbytes(_value(key, ctx, func))
            flags = ["hardcoded-key"] if key is not None and _is_literal_key(key, ctx, func) else []
            add(call, "mac", "HMAC", dict(hash=h or "MD5", key_bits=kb * 8 if kb else None),
                f"hmac.new(..., {ast.unparse(dm) if dm is not None else 'default MD5'})", flags, api=fqn, func=func)
        # ---------------- cryptography: asymmetric ----------------
        elif fqn.endswith("rsa.generate_private_key"):
            ks = next((kw.value for kw in call.keywords if kw.arg == "key_size"), call.args[1] if len(call.args) > 1 else None)
            kb = _value(ks, ctx, func)
            e = _value(next((kw.value for kw in call.keywords if kw.arg == "public_exponent"), call.args[0] if call.args else None), ctx, func)
            add(call, rsa_role(), "RSA", dict(key_bits=kb, public_exponent=e if isinstance(e, int) else None),
                f"rsa.generate_private_key(key_size={kb}, public_exponent={e})", api=fqn, func=func)
        elif fqn.endswith(".sign") or fqn.endswith(".verify"):
            pad = next((_fqn(a.func, ctx) for a in call.args if isinstance(a, ast.Call) and "padding." in (_fqn(a.func, ctx) or "")), None)
            hsh = next((_fqn(a.func, ctx) for a in call.args if isinstance(a, ast.Call) and "hashes." in (_fqn(a.func, ctx) or "")), None)
            ecdsa = next((a for a in call.args if isinstance(a, ast.Call) and (_fqn(a.func, ctx) or "").endswith("ECDSA")), None)
            if pad:
                add(call, "signature", "RSA", dict(key_bits=rsa_bits.get(None), padding={"PKCS1v15": "PKCS1v15", "PSS": "PSS"}.get(pad.split(".")[-1], pad.split(".")[-1]),
                                                   hash=CRY_HASHES.get(hsh.split(".")[-1]) if hsh else None),
                    f"RSA {name}() with {pad.split('.')[-1]} / {hsh.split('.')[-1] if hsh else '?'}", api=fqn, func=func)
            elif ecdsa is not None:
                inner = ecdsa.args[0] if ecdsa.args else None
                h = CRY_HASHES.get((_fqn(inner.func, ctx) or "").split(".")[-1]) if isinstance(inner, ast.Call) else None
                add(call, "signature", "ECDSA", dict(hash=h), f"ECDSA {name}()", api=fqn, func=func)
        elif fqn.endswith("ec.generate_private_key"):
            cn = _as_call(next((kw.value for kw in call.keywords if kw.arg == "curve"), call.args[0] if call.args else None), ctx, func)
            cn = cn.func if isinstance(cn, ast.Call) else cn  # ec.SECP256R1() or the class ec.SECP256R1
            curve = (_fqn(cn, ctx) or "").split(".")[-1] if isinstance(cn, (ast.Attribute, ast.Name)) else None
            if curve and curve.upper() == curve:  # a curve class name, not a variable such as os.getenv(...)
                add(call, "signature", "ECDSA", dict(curve=EC_CURVES.get(curve, curve.lower())), f"ec.generate_private_key({curve})", api=fqn, func=func)
        elif fqn.endswith(".exchange") and any(isinstance(a, ast.Call) and (_fqn(a.func, ctx) or "").endswith("ECDH") for a in call.args):
            add(call, "key-exchange", "ECDH", {}, "ECDH exchange()", api=fqn, func=func)
        elif "Ed25519PrivateKey.generate" in fqn or fqn.endswith("Ed25519PrivateKey.from_private_bytes"):
            add(call, "signature", "Ed25519", {}, "Ed25519PrivateKey.generate()", api=fqn, func=func)
        elif "Ed448PrivateKey.generate" in fqn:
            add(call, "signature", "Ed448", {}, "Ed448PrivateKey.generate()", api=fqn, func=func)
        elif "X25519PrivateKey.generate" in fqn:
            add(call, "key-exchange", "X25519", {}, "X25519PrivateKey.generate()", api=fqn, func=func)
        elif "X448PrivateKey.generate" in fqn:
            add(call, "key-exchange", "X448", {}, "X448PrivateKey.generate()", api=fqn, func=func)
        elif fqn.endswith("dsa.generate_private_key") and ".ec." not in fqn and "rsa" not in fqn:
            kb = _value(next((kw.value for kw in call.keywords if kw.arg == "key_size"), call.args[0] if call.args else None), ctx, func)
            add(call, "signature", "DSA", dict(key_bits=kb), "dsa.generate_private_key()", api=fqn, func=func)
        elif fqn.endswith("dh.generate_parameters"):
            ks = next((kw.value for kw in call.keywords if kw.arg == "key_size"), call.args[1] if len(call.args) > 1 else None)
            add(call, "key-exchange", "DH", dict(key_bits=_value(ks, ctx, func)), "dh.generate_parameters()", api=fqn, func=func)
        # ---------------- post-quantum (liboqs / pyca) ----------------
        elif fqn.split(".")[-1] in ("KeyEncapsulation", "Signature") and fqn.startswith("oqs") and call.args:
            v = str(_value(call.args[0], ctx, func) or "")
            alg = "ML-KEM" if "ML-KEM" in v.upper() or "KYBER" in v.upper() else ("ML-DSA" if "ML-DSA" in v.upper() or "DILITHIUM" in v.upper() else ("SLH-DSA" if "SPHINCS" in v.upper() or "SLH" in v.upper() else v))
            add(call, "key-exchange" if "KeyEncapsulation" in fqn else "signature", alg, dict(parameter_set=v), f"liboqs {v}", api=fqn, func=func)
        elif "mlkem" in fqn.lower() and name.lower().startswith("generate"):
            add(call, "key-exchange", "ML-KEM", dict(parameter_set="ML-KEM-1024" if "1024" in fqn else "ML-KEM-768"), f"{fqn}()", api=fqn, func=func)
        elif "mldsa" in fqn.lower() and name.lower().startswith("generate"):
            ps = "ML-DSA-87" if "87" in fqn else ("ML-DSA-44" if "44" in fqn else "ML-DSA-65")
            add(call, "signature", "ML-DSA", dict(parameter_set=ps), f"{fqn}()", api=fqn, func=func)
        # ---------------- cryptography: symmetric ----------------
        elif fqn.endswith("ciphers.Cipher") or fqn == "Cipher" or fqn.endswith(".Cipher") and P in fqn:
            algn = _as_call(call.args[0] if call.args else next((kw.value for kw in call.keywords if kw.arg == "algorithm"), None), ctx, func)
            moden = _as_call(call.args[1] if len(call.args) > 1 else next((kw.value for kw in call.keywords if kw.arg == "mode"), None), ctx, func)
            a = (_fqn(algn.func, ctx) or "").split(".")[-1] if isinstance(algn, ast.Call) else None
            m = (_fqn(moden.func, ctx) or "").split(".")[-1] if isinstance(moden, ast.Call) else None
            alg = CRY_CIPHERS.get(a, a or "UNKNOWN-CIPHER")
            keyn = algn.args[0] if isinstance(algn, ast.Call) and algn.args else None
            kb = _nbytes(_value(keyn, ctx, func))
            if a == "AES128":
                kb = 16
            if a == "AES256":
                kb = 32
            flags = []
            if keyn is not None and _is_literal_key(keyn, ctx, func):
                flags.append("hardcoded-key")
            if m == "ECB":
                flags.append("ecb-mode")
            add(call, "encryption", alg, dict(key_bits=kb * 8 if kb else None, mode=m),
                f"Cipher(algorithms.{a}(key), modes.{m}())" + (f" with {kb * 8}-bit key" if kb else " (key size unresolved)"),
                flags, confidence=1.0 if kb else 0.6, api=fqn, func=func)
        elif name in CRY_AEAD and (fqn.startswith(P) or fqn == name):
            alg, mode = CRY_AEAD[name]
            keyn = call.args[0] if call.args else None
            kb = _nbytes(_value(keyn, ctx, func))
            conf = 1.0 if kb else 0.6
            if not kb:  # fall back to a module constant like KEY_LEN / KEY_SIZE / KEY_BITS
                for (fn, cname), expr in ctx.consts.items():
                    if fn is None and cname.upper() in ("KEY_LEN", "KEY_SIZE", "KEY_LENGTH", "KEY_BYTES", "KEYLEN"):
                        v = _value(expr, ctx)
                        kb, conf = (v if isinstance(v, int) else None), 0.85
                    elif fn is None and cname.upper() in ("KEY_BITS",):
                        v = _value(expr, ctx)
                        kb, conf = ((v // 8) if isinstance(v, int) else None), 0.85
            if alg == "ChaCha20-Poly1305":
                kb = 32
            flags = ["hardcoded-key"] if keyn is not None and _is_literal_key(keyn, ctx, func) else []
            add(call, "encryption", alg, dict(key_bits=kb * 8 if kb else None, mode=mode),
                f"{name}(key)" + (f" with {kb * 8}-bit key" if kb else " (key size unresolved)"), flags, confidence=conf, api=fqn, func=func)
        elif name == "PBKDF2HMAC":
            kw = {k.arg: k.value for k in call.keywords}
            h = kw.get("algorithm")
            hname = CRY_HASHES.get((_fqn(h.func, ctx) or "").split(".")[-1]) if isinstance(h, ast.Call) else None
            it = _value(kw.get("iterations"), ctx, func)
            add(call, "kdf", "PBKDF2", dict(hash=hname, iterations=it), f"PBKDF2HMAC({hname}, iterations={it})", api=fqn, func=func)
        elif name in ("Scrypt", "Argon2id", "HKDF", "HKDFExpand") and fqn.startswith(P):
            add(call, "kdf", {"Scrypt": "scrypt", "Argon2id": "Argon2", "HKDF": "HKDF", "HKDFExpand": "HKDF"}[name], {}, f"{name}()", api=fqn, func=func)
        elif fqn.startswith(P + "hashes.") and name in CRY_HASHES and not isinstance(ctx.parent.get(call), (ast.Call, ast.keyword)):
            add(call, "hash", CRY_HASHES[name], {}, f"hashes.{name}()", api=fqn, func=func)
        elif fqn.startswith(P + "hashes.Hash") and call.args and isinstance(call.args[0], ast.Call):
            h = CRY_HASHES.get((_fqn(call.args[0].func, ctx) or "").split(".")[-1])
            if h:
                pw = ["password-hashing", "unsalted"] if func is not None and "password" in func.name.lower() else []
                add(call, "hash", h, {}, f"hashes.Hash({h})" + (f" in {func.name}(): a fast digest for passwords" if pw else ""), pw,
                    api=fqn, func=func)
        # ---------------- PyCryptodome ----------------
        elif fqn.startswith("Crypto.Cipher.") and name == "new":
            mod = fqn.split(".")[2]
            alg = {"AES": "AES", "DES": "DES", "DES3": "3DES", "ARC4": "RC4", "ARC2": "RC2", "CAST": "CAST5", "Blowfish": "Blowfish",
                   "ChaCha20_Poly1305": "ChaCha20-Poly1305", "ChaCha20": "ChaCha20-Poly1305"}.get(mod, mod)
            kw = {k.arg: k.value for k in call.keywords}
            mnode = call.args[1] if len(call.args) > 1 else kw.get("mode")
            knode = call.args[0] if call.args else kw.get("key")
            mode = (_fqn(mnode, ctx) or "").split(".")[-1].replace("MODE_", "") if mnode is not None else None
            kb = _nbytes(_value(knode, ctx, func)) if knode is not None else None
            flags = (["ecb-mode"] if mode == "ECB" else []) + (["hardcoded-key"] if knode is not None and _is_literal_key(knode, ctx, func) else [])
            add(call, "encryption", alg, dict(key_bits=kb * 8 if kb else None, mode=mode), f"{mod}.new(key, MODE_{mode})", flags, api=fqn, func=func)
        elif fqn.startswith(("Crypto.PublicKey.RSA.generate", "Crypto.PublicKey.DSA.generate", "Crypto.PublicKey.ElGamal.generate")):
            alg = "RSA" if ".RSA." in fqn else ("DSA" if ".DSA." in fqn else "ElGamal")
            bits = _value(next((kw.value for kw in call.keywords if kw.arg == "bits"), call.args[0] if call.args else None), ctx, func)
            e = None
            if alg == "RSA":  # pycryptodome generate(bits, randfunc, e) / pycrypto generate(bits, randfunc, progress_func, e)
                e = _value(next((kw.value for kw in call.keywords if kw.arg == "e"), call.args[-1] if len(call.args) > 2 else None), ctx, func)
            add(call, "encryption" if alg == "ElGamal" else "signature", alg,
                dict(key_bits=bits if isinstance(bits, int) else None, public_exponent=e if isinstance(e, int) else None),
                f"{alg}.generate({bits})", api=fqn, func=func)
        elif fqn.startswith("Crypto.PublicKey.ECC.generate"):
            cv = _value(next((kw.value for kw in call.keywords if kw.arg == "curve"), call.args[0] if call.args else None), ctx, func)
            if isinstance(cv, str):
                add(call, "signature", "ECDSA", dict(curve=_ec_name(cv)), f"ECC.generate(curve={cv!r})", api=fqn, func=func)
        elif name == "generate_key" and (call.args or call.keywords):  # pyOpenSSL: PKey().generate_key(crypto.TYPE_RSA, 1024)
            kt = next((kw.value for kw in call.keywords if kw.arg == "type"), call.args[0] if call.args else None)
            kind = (_fqn(kt, ctx) or "").split(".")[-1] if isinstance(kt, (ast.Attribute, ast.Name)) else ""
            if kind in ("TYPE_RSA", "TYPE_DSA"):
                bits = _value(next((kw.value for kw in call.keywords if kw.arg == "bits"), call.args[1] if len(call.args) > 1 else None), ctx, func)
                add(call, "signature", kind[5:], dict(key_bits=bits if isinstance(bits, int) else None), f"PKey.generate_key({kind}, {bits})", api="OpenSSL.crypto.PKey", func=func)
        elif fqn.startswith("Crypto.Hash.") and name == "new" and fqn.split(".")[2] in PYCRYPTO_HASH:
            h = fqn.split(".")[2]
            add(call, "hash", PYCRYPTO_HASH[h], {}, f"{h}.new()", api=fqn, func=func)
        # ---------------- pyDes (pure-Python DES / 3DES) ----------------
        elif fqn in ("pyDes.des", "pyDes.triple_des"):
            mnode = _arg(call, 1, "mode")
            mode = "CBC" if mnode is not None and (_fqn(mnode, ctx) or "").endswith("CBC") else "ECB"  # pyDes defaults to ECB
            kb = _nbytes(_value(call.args[0], ctx, func)) if call.args else None
            alg = "DES" if fqn == "pyDes.des" else "3DES"
            bits = 56 if alg == "DES" else (112 if kb == 16 else 168)
            flags = (["ecb-mode"] if mode == "ECB" else []) + (["hardcoded-key"] if call.args and _is_literal_key(call.args[0], ctx, func) else [])
            add(call, "encryption", alg, dict(key_bits=bits, mode=mode), f"{fqn}(key, {mode})", flags, api=fqn, func=func)
        # ---------------- TLS cipher strings set from code (ssl / pyOpenSSL / urllib3) ----------------
        elif name in ("set_ciphers", "set_cipher_list") and call.args or fqn.endswith("create_urllib3_context") and any(k.arg == "ciphers" for k in call.keywords):
            spec = _value(call.args[0] if name in ("set_ciphers", "set_cipher_list") else next(k.value for k in call.keywords if k.arg == "ciphers"), ctx, func)
            if isinstance(spec, bytes):
                spec = spec.decode(errors="replace")
            if isinstance(spec, str):
                for category, alg, params, ev, flags, conf in _cipher_string_findings(spec):
                    add(call, category, alg, params, f"{name or fqn}({spec[:40]!r}): {ev}", flags, confidence=conf, api=fqn, func=func)
        # ---------------- randomness ----------------
        elif fqn.startswith("random.") and name in RANDOM_FUNCS:
            names = ctx.call_targets.get(id(call), [])
            target = next((t for t in names if _secret_name(t)), None)
            if target:
                add(call, "rng", "NON-CSPRNG", dict(api=fqn), f"{fqn}() generates {target}: the random module is predictable, use secrets",
                    ["weak-prng"], confidence=0.9, api=fqn, func=func)
            elif sec_ctx and (sec_name(fname_) or not names):
                # a function that only LOOKS sensitive from its body (reset_token = ... somewhere) and stores this value under a
                # plain name (sort_key, delay) is not generating a secret here: the variable name is the better evidence
                add(call, "rng", "NON-CSPRNG", dict(api=fqn), f"{fqn}() used in security-sensitive function {func.name if func else ''}()",
                    ["weak-prng"], api=fqn, func=func)
        elif fqn in ("os.urandom", "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe", "secrets.randbits"):
            add(call, "rng", "CSPRNG", dict(api=fqn), f"{fqn}()", api=fqn, func=func, confidence=1.0)
        # ---------------- TLS certificate verification switched off ----------------
        elif fqn == "ssl._create_unverified_context":
            add(call, "authentication", "NO-CERT-VERIFY", dict(api=fqn), f"{fqn}() disables certificate and hostname verification",
                ["no-cert-verify"], api=fqn, func=func)
        elif fqn.startswith(("requests.", "httpx.")) and any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                                                           for kw in call.keywords):
            add(call, "authentication", "NO-CERT-VERIFY", dict(api=fqn), f"{fqn}(..., verify=False) disables certificate verification",
                ["no-cert-verify"], api=fqn, func=func)

    for node, text, func in ctx.no_verify:
        add(node, "authentication", "NO-CERT-VERIFY", dict(api=text.split(" =")[0]), f"{text} disables certificate verification",
            ["no-cert-verify"], api="ssl", func=func)

    # ---------------- password hashing frameworks / references to weak hash constructors ----------------
    _password_frameworks(tree, ctx, add)
    _legacy_references(tree, ctx, add)
    _password_cost(ctx, add)
    _static_material(ctx, add, findings)

    # ---------------- hard-coded keys (module constants with key-ish names) ----------------
    for (fn, cname), expr in ctx.consts.items():
        if fn is None and is_keyish(cname) and isinstance(expr, ast.Constant) and looks_secret(expr.value):
            demo = cname in ctx.main_names
            findings.append(Finding(source="code", category="key", algorithm="HARDCODED-KEY",
                                    params=dict(key_bits=len(expr.value) * 8 if isinstance(expr.value, bytes) else len(expr.value.encode()) * 8, name=cname),
                                    asset=dict(lang_asset), location=dict(file=rel, line=expr.lineno, column=expr.col_offset + 1, snippet=snippet(src, expr.lineno), symbol=cname),
                                    context=dict(language="python"), evidence=f"secret key literal assigned to {cname}" + (" (inside __main__: demo/test code)" if demo else ""),
                                    flags=["hardcoded-key"] + (["demo-code"] if demo else []), confidence=0.6 if demo else 1.0))
    return findings
