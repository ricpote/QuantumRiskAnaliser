"""Python SAST via the stdlib `ast` module (no regex on raw text -> no hits in comments/strings).

Resolves imports to fully-qualified names, propagates constants (module, function,
default parameters, simple one-level call-site/return resolution) to infer key sizes,
modes, hashes and iteration counts.
"""
from __future__ import annotations

import ast
import re
import os

from ...schema import Finding
from . import jwt_algorithms
from .common import SEC_WORDS, is_keyish, snippet

HASHLIB = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
           "sha512": "SHA-512", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
           "blake2b": "BLAKE2b", "blake2s": "BLAKE2s", "shake_128": "SHAKE128", "shake_256": "SHAKE256",
           "md4": "MD4", "ripemd160": "RIPEMD-160", "sha512_256": "SHA-512/256"}
CRY_HASHES = {"MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
              "SHA512_256": "SHA-512/256", "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512",
              "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256", "BLAKE2b": "BLAKE2b", "BLAKE2s": "BLAKE2s"}
CRY_CIPHERS = {"AES": "AES", "AES128": "AES", "AES256": "AES", "TripleDES": "3DES", "ChaCha20": "ChaCha20-Poly1305",
               "ARC4": "RC4", "Blowfish": "Blowfish", "CAST5": "CAST5", "SEED": "SEED", "IDEA": "IDEA", "Camellia": "Camellia", "SM4": "SM4"}
CRY_AEAD = {"AESGCM": ("AES", "GCM"), "AESCCM": ("AES", "CCM"), "AESOCB3": ("AES", "OCB"), "AESSIV": ("AES", "SIV"),
            "AESGCMSIV": ("AES", "GCM-SIV"), "ChaCha20Poly1305": ("ChaCha20-Poly1305", None)}
P = "cryptography.hazmat.primitives."
RANDOM_FUNCS = {"random", "randint", "getrandbits", "randbytes", "choice", "choices", "randrange", "sample", "uniform"}


class _Ctx:
    def __init__(self, tree, path, src):
        self.tree, self.path, self.src = tree, path, src
        self.imports = {}       # local name -> fqn
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
        return ctx.imports.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _fqn(node.value, ctx)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _fqn(node.func, ctx) + "()"
    return None


def _enclosing_func(node, ctx):
    while node in ctx.parent:
        node = ctx.parent[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def _value(node, ctx, func=None, depth=0):
    """Best-effort constant evaluation. Returns int | str | bytes | ('bytes', n) | None."""
    if node is None or depth > 6:
        return None
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
    if isinstance(node, ast.BinOp):
        a, b = _value(node.left, ctx, func, depth + 1), _value(node.right, ctx, func, depth + 1)
        if isinstance(a, int) and isinstance(b, int):
            try:
                return {ast.Mult: a * b, ast.Add: a + b, ast.Sub: a - b, ast.FloorDiv: a // b if b else None}.get(type(node.op))
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
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    ctx = _Ctx(tree, rel, src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                ctx.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                ctx.imports[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ctx.funcs[node.name] = node
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
        findings.append(Finding(source="code", category=category, algorithm=algorithm, params={k: v for k, v in params.items() if v is not None},
                                asset=dict(lang_asset), location=dict(file=rel, line=node.lineno, column=node.col_offset + 1,
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
        sec_ctx = any(w in fname for w in SEC_WORDS)
        # ---------------- JWT ----------------
        if fqn.startswith(("jwt.", "jose.jwt.")) and name in ("encode", "decode"):
            jwt_call(call, name, fqn, func)
        # ---------------- hashlib ----------------
        elif fqn.startswith("hashlib.") and name in HASHLIB:
            flags = []
            argnames = " ".join(ast.unparse(a) for a in call.args).lower()
            if "password" in fname or "passwd" in fname or "password" in argnames:
                flags += ["password-hashing", "unsalted"]
            add(call, "hash", HASHLIB[name], {}, f"hashlib.{name}() call", flags, api=fqn, func=func)
        elif fqn == "hashlib.new" and call.args:
            v = _value(call.args[0], ctx, func)
            if isinstance(v, str):
                add(call, "hash", HASHLIB.get(v.lower().replace("-", ""), v.upper()), {}, f"hashlib.new({v!r})", api=fqn, func=func)
        elif fqn == "hashlib.pbkdf2_hmac":
            h = _value(call.args[0], ctx, func) if call.args else None
            it = _value(call.args[3], ctx, func) if len(call.args) > 3 else None
            add(call, "kdf", "PBKDF2", dict(hash=HASHLIB.get(str(h).lower(), str(h).upper()), iterations=it), "hashlib.pbkdf2_hmac()", api=fqn, func=func)
        elif fqn == "hashlib.scrypt":
            add(call, "kdf", "scrypt", {}, "hashlib.scrypt()", api=fqn, func=func)
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
            add(call, rsa_role(), "RSA", dict(key_bits=kb), f"rsa.generate_private_key(key_size={kb})", api=fqn, func=func)
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
            curve = (_fqn(call.args[0].func, ctx) or "").split(".")[-1] if call.args and isinstance(call.args[0], ast.Call) else None
            cmap = {"SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521", "SECP256K1": "secp256k1"}
            add(call, "signature", "ECDSA", dict(curve=cmap.get(curve, curve)), f"ec.generate_private_key({curve})", api=fqn, func=func)
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
            kb = _value(call.args[0], ctx, func) if call.args else None
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
            algn = call.args[0] if call.args else None
            moden = call.args[1] if len(call.args) > 1 else next((kw.value for kw in call.keywords if kw.arg == "mode"), None)
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
        elif fqn.startswith(P + "hashes.Hash") and call.args and isinstance(call.args[0], ast.Call):
            h = CRY_HASHES.get((_fqn(call.args[0].func, ctx) or "").split(".")[-1])
            if h:
                add(call, "hash", h, {}, f"hashes.Hash({h})", api=fqn, func=func)
        # ---------------- PyCryptodome ----------------
        elif fqn.startswith("Crypto.Cipher.") and name == "new":
            mod = fqn.split(".")[2]
            alg = {"AES": "AES", "DES": "DES", "DES3": "3DES", "ARC4": "RC4", "Blowfish": "Blowfish", "ChaCha20_Poly1305": "ChaCha20-Poly1305"}.get(mod, mod)
            mode = None
            if len(call.args) > 1:
                mode = (_fqn(call.args[1], ctx) or "").split(".")[-1].replace("MODE_", "")
            kb = _nbytes(_value(call.args[0], ctx, func)) if call.args else None
            flags = (["ecb-mode"] if mode == "ECB" else []) + (["hardcoded-key"] if call.args and _is_literal_key(call.args[0], ctx, func) else [])
            add(call, "encryption", alg, dict(key_bits=kb * 8 if kb else None, mode=mode), f"{mod}.new(key, MODE_{mode})", flags, api=fqn, func=func)
        elif fqn.startswith("Crypto.PublicKey.RSA.generate"):
            add(call, "signature", "RSA", dict(key_bits=_value(call.args[0], ctx, func) if call.args else None), "RSA.generate()", api=fqn, func=func)
        elif fqn.startswith("Crypto.Hash.") and name == "new":
            h = fqn.split(".")[2]
            add(call, "hash", {"MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}.get(h, h), {}, f"{h}.new()", api=fqn, func=func)
        # ---------------- randomness ----------------
        elif fqn.startswith("random.") and name in RANDOM_FUNCS:
            target = next((t for t in ctx.call_targets.get(id(call), []) if _secret_name(t)), None)
            if sec_ctx:
                add(call, "rng", "NON-CSPRNG", dict(api=fqn), f"{fqn}() used in security-sensitive function {func.name if func else ''}()",
                    ["weak-prng"], api=fqn, func=func)
            elif target:
                add(call, "rng", "NON-CSPRNG", dict(api=fqn), f"{fqn}() generates {target}: the random module is predictable, use secrets",
                    ["weak-prng"], confidence=0.9, api=fqn, func=func)
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

    # ---------------- hard-coded keys (module constants with key-ish names) ----------------
    for (fn, cname), expr in ctx.consts.items():
        if fn is None and is_keyish(cname) and isinstance(expr, ast.Constant) and isinstance(expr.value, (bytes, str)) and len(expr.value) >= 8:
            demo = cname in ctx.main_names
            findings.append(Finding(source="code", category="key", algorithm="HARDCODED-KEY",
                                    params=dict(key_bits=len(expr.value) * 8 if isinstance(expr.value, bytes) else len(expr.value.encode()) * 8, name=cname),
                                    asset=dict(lang_asset), location=dict(file=rel, line=expr.lineno, column=expr.col_offset + 1, snippet=snippet(src, expr.lineno), symbol=cname),
                                    context=dict(language="python"), evidence=f"secret key literal assigned to {cname}" + (" (inside __main__: demo/test code)" if demo else ""),
                                    flags=["hardcoded-key"] + (["demo-code"] if demo else []), confidence=0.6 if demo else 1.0))
    return findings
