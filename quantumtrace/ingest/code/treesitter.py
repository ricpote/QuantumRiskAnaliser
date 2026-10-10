"""Go and Java SAST via tree-sitter (tree-sitter-language-pack).

Both scanners build a tiny "IR" per file: imports, constants/variables (per scope),
functions (+ params), calls (+ enclosing function). A small evaluator resolves
identifiers -> constants, function params -> call-site arguments, local helper calls
-> return values. That is enough to infer key sizes / modes / iteration counts that
the sample code hides behind constants (KEY_LEN = 32, exportKey = []byte("...")).
"""
from __future__ import annotations

import re

from ...schema import Finding
from . import jwt_algorithms
from .common import SEC_WORDS, is_keyish, parse_int, snippet, unquote

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover
    get_parser = None


class TSFile:
    lang = ""
    FUNC_TYPES: tuple = ()
    CALL_TYPES: tuple = ()

    def __init__(self, src: bytes, rel: str):
        self.src, self.rel = src, rel
        self.text_src = src.decode("utf-8", errors="replace")
        self.tree = get_parser(self.lang).parse(src)
        self.root = self.tree.root_node
        self.imports = {}   # alias -> import path / fqn
        self.consts = {}    # (func_name|None, name) -> value node
        self.funcs = {}     # name -> (node, [param names])
        self.calls = []     # dict(node, callee, obj, name, args, func)
        self.findings: list[Finding] = []
        self._index(self.root, None)

    # ---------------------------------------------------------------- utils
    def t(self, n) -> str:
        return self.src[n.start_byte:n.end_byte].decode("utf-8", errors="replace") if n is not None else ""

    def line(self, n) -> int:
        return n.start_point[0] + 1

    def walk(self, n):
        stack = [n]
        while stack:
            x = stack.pop()
            yield x
            stack.extend(reversed(x.children))

    def ancestors(self, n):
        p = n.parent
        while p is not None:
            yield p
            p = p.parent

    def in_loop(self, n, stop=None) -> bool:
        for a in self.ancestors(n):
            if a is stop:
                return False
            if a.type in ("for_statement", "while_statement", "enhanced_for_statement", "do_statement"):
                return True
        return False

    def add(self, node, category, algorithm, params, evidence, flags=(), confidence=1.0, api=None, func=None):
        self.findings.append(Finding(
            source="code", category=category, algorithm=algorithm, params={k: v for k, v in params.items() if v is not None},
            asset=dict(kind="source-file", path=self.rel, language=self.lang),
            location=dict(file=self.rel, line=self.line(node), column=node.start_point[1] + 1,
                          snippet=snippet(self.text_src, self.line(node)), symbol=func or "<file>"),
            context=dict(api=api, language=self.lang), evidence=evidence, flags=list(flags), confidence=confidence))

    def _index(self, root, func):  # overridden
        raise NotImplementedError

    # ---------------------------------------------------------------- evaluator
    def value(self, n, func=None, depth=0):
        """-> int | str | bytes | ('bytes', n) | None"""
        if n is None or depth > 8:
            return None
        ty = n.type
        if ty in ("int_literal", "decimal_integer_literal", "hex_integer_literal"):
            return parse_int(self.t(n))
        if ty in ("interpreted_string_literal", "raw_string_literal", "string_literal"):
            return unquote(self.t(n))
        if ty in ("parenthesized_expression",):
            return self.value(n.named_children[0], func, depth + 1) if n.named_children else None
        if ty == "binary_expression" and len(n.named_children) == 2:
            a, b = (self.value(c, func, depth + 1) for c in n.named_children)
            op = self.t(n.child_by_field_name("operator")) if n.child_by_field_name("operator") else self.t(n.children[1])
            if isinstance(a, int) and isinstance(b, int):
                return {"*": a * b, "+": a + b, "-": a - b, "/": a // b if b else None, "<<": a << b}.get(op)
            return None
        if ty == "identifier":
            return self.resolve_name(self.t(n), func, depth)
        return self.value_special(n, func, depth)

    def value_special(self, n, func, depth):
        return None

    def resolve_name(self, name, func, depth):
        for key in ((func, name), (None, name)):
            if key in self.consts:
                self._trace.append(key)
                return self.value(self.consts[key], key[0], depth + 1)
        if func in self.funcs:
            _, params = self.funcs[func]
            if name in params:
                idx = params.index(name)
                for c in self.calls:
                    if c["name"] == func and c["obj"] in (None, "this") and idx < len(c["args"]):
                        v = self.value(c["args"][idx], c["func"], depth + 1)
                        if v is not None:
                            return v
        return None

    def call_return(self, fname, depth):
        if fname not in self.funcs:
            return None
        node, _ = self.funcs[fname]
        for r in self.walk(node):
            if r.type == "return_statement":
                for c in r.named_children:
                    v = self.value(c.named_children[0] if c.type == "expression_list" and c.named_children else c, fname, depth + 1)
                    if v is not None:
                        return v
        return None

    @staticmethod
    def nbytes(v):
        if isinstance(v, (bytes, bytearray)):
            return len(v)
        if isinstance(v, str):
            return len(v.encode())
        if isinstance(v, tuple) and v and v[0] == "bytes" and isinstance(v[1], int):
            return v[1]
        return None

    _trace: list = []

    def is_literal(self, n, func):
        """True if `n` resolves to a str/bytes literal defined OUTSIDE main()/demo code (a real hard-coded key)."""
        self._trace = []
        v = self.value(n, func)
        if not isinstance(v, (str, bytes)):
            return False
        return not any(scope == "main" for scope, _ in self._trace)

    def add_jwt(self, node, jn, func, api, key=None):
        """One JWT algorithm use; for HMAC (HS256...) also the secret's size and whether it is a literal.

        key = (node, enclosing function) of the secret expression, which may live in another function."""
        category, alg, params, flags = jwt_algorithms.finding_args(jn)
        if alg == "HMAC" and key is not None:
            kb = self.nbytes(self.value(*key))
            params["key_bits"] = kb * 8 if kb else None
            if self.is_literal(*key):
                flags.append("hardcoded-key")
        self.add(node, category, alg, params, f"{api} ({jn})", flags, api=api, func=func)

    def hardcoded_keys(self):
        for (fn, name), vnode in self.consts.items():
            if not is_keyish(name):
                continue
            v = self.value(vnode, fn)
            if isinstance(v, (str, bytes)) and len(v) >= 8:
                demo = fn == "main"
                self.add(vnode, "key", "HARDCODED-KEY", dict(key_bits=self.nbytes(v) * 8, name=name),
                         f"secret key literal assigned to {name}" + (" (inside main(): demo/test code)" if demo else ""),
                         ["hardcoded-key"] + (["demo-code"] if demo else []), confidence=0.6 if demo else 1.0, func=fn)


# =============================================================================================== Go
GO_HASH = {
    "crypto/md5": {"Sum": "MD5", "New": "MD5"},
    "crypto/sha1": {"Sum": "SHA-1", "New": "SHA-1"},
    "crypto/sha256": {"Sum256": "SHA-256", "New": "SHA-256", "Sum224": "SHA-224", "New224": "SHA-224"},
    "crypto/sha512": {"Sum512": "SHA-512", "New": "SHA-512", "Sum384": "SHA-384", "New384": "SHA-384",
                      "Sum512_256": "SHA-512/256", "New512_256": "SHA-512/256"},
    "crypto/sha3": {"Sum256": "SHA3-256", "Sum384": "SHA3-384", "Sum512": "SHA3-512", "New256": "SHA3-256", "New384": "SHA3-384", "New512": "SHA3-512"},
    "golang.org/x/crypto/sha3": {"Sum256": "SHA3-256", "Sum512": "SHA3-512", "New256": "SHA3-256", "New512": "SHA3-512"},
    "golang.org/x/crypto/md4": {"New": "MD4"},
    "golang.org/x/crypto/ripemd160": {"New": "RIPEMD-160"},
}
GO_CRYPTO_HASH = {"SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5",
                  "SHA3_256": "SHA3-256", "SHA512_256": "SHA-512/256"}
GO_CURVES = {"P224": "P-224", "P256": "P-256", "P384": "P-384", "P521": "P-521"}
GO_MODES = {"NewGCM": "GCM", "NewGCMWithNonceSize": "GCM", "NewGCMWithTagSize": "GCM", "NewGCMWithRandomNonce": "GCM",
            "NewCBCEncrypter": "CBC", "NewCBCDecrypter": "CBC", "NewCTR": "CTR", "NewCFBEncrypter": "CFB",
            "NewCFBDecrypter": "CFB", "NewOFB": "OFB"}
GO_MATH_RAND = {"math/rand", "math/rand/v2"}


class GoFile(TSFile):
    lang = "go"

    def _index(self, root, func):
        for n in self.walk(root):
            ty = n.type
            if ty == "import_spec":
                path = unquote(self.t(n.child_by_field_name("path")))
                alias = n.child_by_field_name("name")
                segs = path.split("/")
                default = segs[-2] if len(segs) > 1 and re.fullmatch(r"v\d+", segs[-1]) else segs[-1]  # .../jwt/v5 -> jwt
                self.imports[self.t(alias) if alias is not None else default] = path
            elif ty in ("function_declaration", "method_declaration"):
                name = self.t(n.child_by_field_name("name"))
                params = []
                pl = n.child_by_field_name("parameters")
                for pd in (pl.named_children if pl is not None else []):
                    params += [self.t(c) for c in pd.named_children if c.type == "identifier"]
                self.funcs[name] = (n, params)
        for n in self.walk(root):
            ty = n.type
            fn = self.enclosing(n)
            if ty in ("const_spec", "var_spec"):
                names = [c for c in n.children_by_field_name("name")]
                vals = n.child_by_field_name("value")
                vals = vals.named_children if vals is not None else []
                for i, nm in enumerate(names):
                    if i < len(vals):
                        self.consts.setdefault((fn, self.t(nm)), vals[i])
            elif ty == "short_var_declaration" or (ty == "assignment_statement" and self.t(n.children[1]) == "="):
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and right is not None:
                    ls, rs = left.named_children, right.named_children
                    for i, l in enumerate(ls):
                        if l.type == "identifier" and i < len(rs):
                            self.consts.setdefault((fn, self.t(l)), rs[i])
                        elif l.type == "identifier" and len(rs) == 1:  # block, err := aes.NewCipher(key)
                            self.consts.setdefault((fn, self.t(l)), rs[0] if i == 0 else None)
            elif ty == "call_expression":
                f = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                args = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
                obj = name = None
                if f is not None and f.type == "selector_expression":
                    obj = self.t(f.child_by_field_name("operand"))
                    name = self.t(f.child_by_field_name("field"))
                elif f is not None:
                    name = self.t(f)
                self.calls.append(dict(node=n, obj=obj, name=name, args=args, func=fn,
                                       pkg=self.imports.get(obj) if obj else None))

    def enclosing(self, n):
        for a in self.ancestors(n):
            if a.type in ("function_declaration", "method_declaration"):
                return self.t(a.child_by_field_name("name"))
        return None

    def value_special(self, n, func, depth):
        if n.type == "type_conversion_expression":  # []byte("...")
            inner = [c for c in n.named_children if c.type not in ("slice_type", "type_identifier", "array_type")]
            v = self.value(inner[0], func, depth + 1) if inner else None
            return v.encode() if isinstance(v, str) else v
        if n.type == "call_expression":
            f = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            args = args.named_children if args is not None else []
            fname = self.t(f)
            if fname == "make" and len(args) >= 2 and "byte" in self.t(args[0]):
                k = self.value(args[1], func, depth + 1)
                return ("bytes", k) if isinstance(k, int) else None
            if f is not None and f.type in ("slice_type", "array_type") and args:  # []byte("x") parsed as call
                v = self.value(args[0], func, depth + 1)
                return v.encode() if isinstance(v, str) else v
            if f is not None and f.type == "identifier":
                return self.call_return(fname, depth)
        return None

    def hash_from_fn(self, n):
        """sha256.New -> SHA-256 (function value passed to hmac.New / pbkdf2)."""
        if n is None:
            return None
        if n.type == "selector_expression":
            pkg = self.imports.get(self.t(n.child_by_field_name("operand")))
            fld = self.t(n.child_by_field_name("field"))
            if pkg in GO_HASH:
                return GO_HASH[pkg].get(fld)
            if pkg == "crypto":
                return GO_CRYPTO_HASH.get(fld)
        if n.type == "call_expression":
            return self.hash_from_fn(n.child_by_field_name("function"))
        return None

    def scan(self) -> list[Finding]:
        custom_pbkdf2 = self.detect_custom_pbkdf2()
        rsa_bits = None
        for c in self.calls:
            if c["pkg"] == "crypto/rsa" and c["name"] == "GenerateKey" and len(c["args"]) > 1:
                rsa_bits = self.value(c["args"][1], c["func"])
        for c in self.calls:
            pkg, name, args, fn, node = c["pkg"], c["name"], c["args"], c["func"], c["node"]
            fl = (fn or "").lower()
            sec = any(w in fl for w in SEC_WORDS)
            api = f"{pkg}.{name}" if pkg else name
            if pkg in GO_HASH and name in GO_HASH[pkg]:
                flags = ["password-hashing", "unsalted"] if "password" in fl else []
                self.add(node, "hash", GO_HASH[pkg][name], {}, f"{api}()", flags, api=api, func=fn)
            elif pkg == "crypto/hmac" and name == "New":
                if fn in custom_pbkdf2:
                    continue
                h = self.hash_from_fn(args[0]) if args else None
                kb = self.nbytes(self.value(args[1], fn)) if len(args) > 1 else None
                flags = ["hardcoded-key"] if len(args) > 1 and self.is_literal(args[1], fn) else []
                self.add(node, "mac", "HMAC", dict(hash=h, key_bits=kb * 8 if kb else None), f"hmac.New({self.t(args[0]) if args else '?'}, key)", flags, api=api, func=fn)
            elif pkg == "crypto/aes" and name == "NewCipher":
                kb = self.nbytes(self.value(args[0], fn)) if args else None
                mode, mflags = self.block_mode(node, fn)
                flags = list(mflags)
                if args and self.is_literal(args[0], fn):
                    flags.append("hardcoded-key")
                ev = f"aes.NewCipher(key)" + (f" with {kb * 8}-bit key" if kb else " (key size unresolved)") + (f", mode {mode}" if mode else "")
                if "custom-implementation" in flags:
                    ev += " (ECB implemented by hand: Block.Encrypt over each 16-byte block)"
                self.add(node, "encryption", "AES", dict(key_bits=kb * 8 if kb else None, mode=mode), ev, flags,
                         confidence=1.0 if kb else 0.6, api=api, func=fn)
            elif pkg == "crypto/des":
                alg = "3DES" if name == "NewTripleDESCipher" else "DES"
                mode, mflags = self.block_mode(node, fn)
                self.add(node, "encryption", alg, dict(key_bits=168 if alg == "3DES" else 56, mode=mode), f"des.{name}()", mflags, api=api, func=fn)
            elif pkg == "crypto/rc4" and name == "NewCipher":
                self.add(node, "encryption", "RC4", {}, "rc4.NewCipher()", api=api, func=fn)
            elif pkg == "crypto/rsa":
                if name == "GenerateKey":
                    self.add(node, self.rsa_role(), "RSA", dict(key_bits=rsa_bits), f"rsa.GenerateKey(rand, {rsa_bits})", api=api, func=fn)
                elif name in ("SignPKCS1v15", "VerifyPKCS1v15", "SignPSS", "VerifyPSS"):
                    hidx = 2 if name.startswith("Sign") else 1
                    h = self.hash_from_fn(args[hidx]) if len(args) > hidx else None
                    self.add(node, "signature", "RSA", dict(key_bits=rsa_bits, padding="PSS" if "PSS" in name else "PKCS1v15", hash=h),
                             f"rsa.{name}(..., {self.t(args[hidx]) if len(args) > hidx else '?'}, ...)", api=api, func=fn)
                elif name in ("EncryptOAEP", "DecryptOAEP"):
                    self.add(node, "encryption", "RSA", dict(key_bits=rsa_bits, padding="OAEP", hash=self.hash_from_fn(args[0]) if args else None), f"rsa.{name}()", api=api, func=fn)
                elif name in ("EncryptPKCS1v15", "DecryptPKCS1v15"):
                    self.add(node, "encryption", "RSA", dict(key_bits=rsa_bits, padding="PKCS1v15"), f"rsa.{name}()", api=api, func=fn)
            elif pkg == "crypto/ecdsa" and name in ("GenerateKey", "Sign", "SignASN1", "Verify", "VerifyASN1"):
                curve = None
                if name == "GenerateKey" and args and args[0].type == "call_expression":
                    curve = GO_CURVES.get(self.t(args[0].child_by_field_name("function")).split(".")[-1])
                self.add(node, "signature", "ECDSA", dict(curve=curve), f"ecdsa.{name}()", api=api, func=fn)
            elif pkg == "crypto/elliptic" and name in ("GenerateKey", "Marshal"):
                pass
            elif pkg == "crypto/ecdh" and name in ("P256", "P384", "P521", "X25519"):
                if name == "X25519":
                    self.add(node, "key-exchange", "X25519", {}, "ecdh.X25519()", api=api, func=fn)
                else:
                    self.add(node, "key-exchange", "ECDH", dict(curve=GO_CURVES.get(name)), f"ecdh.{name}()", api=api, func=fn)
            elif pkg == "crypto/ed25519" and name in ("GenerateKey", "Sign", "Verify", "NewKeyFromSeed"):
                self.add(node, "signature", "Ed25519", {}, f"ed25519.{name}()", api=api, func=fn)
            elif pkg in ("crypto/mlkem", "filippo.io/mlkem768") and name.startswith(("GenerateKey", "NewDecapsulationKey", "NewEncapsulationKey")):
                ps = "ML-KEM-1024" if "1024" in name else "ML-KEM-768"
                self.add(node, "key-exchange", "ML-KEM", dict(parameter_set=ps), f"mlkem.{name}()", api=api, func=fn)
            elif pkg and "circl/sign/mldsa" in pkg:
                ps = "ML-DSA-87" if "87" in pkg else ("ML-DSA-44" if "44" in pkg else "ML-DSA-65")
                self.add(node, "signature", "ML-DSA", dict(parameter_set=ps), f"{pkg}.{name}()", api=api, func=fn)
            elif pkg in ("golang.org/x/crypto/pbkdf2", "crypto/pbkdf2") and name == "Key":
                if pkg == "crypto/pbkdf2":  # Go 1.24: Key(h, password, salt, iter, keyLen)
                    h, it = (self.hash_from_fn(args[0]) if args else None), (self.value(args[3], fn) if len(args) > 3 else None)
                else:                        # x/crypto: Key(password, salt, iter, keyLen, h)
                    h, it = (self.hash_from_fn(args[4]) if len(args) > 4 else None), (self.value(args[2], fn) if len(args) > 2 else None)
                self.add(node, "kdf", "PBKDF2", dict(hash=h, iterations=it), f"pbkdf2.Key(..., {it}, ...)", api=api, func=fn)
            elif pkg == "golang.org/x/crypto/bcrypt" and name == "GenerateFromPassword":
                self.add(node, "kdf", "bcrypt", {}, "bcrypt.GenerateFromPassword()", api=api, func=fn)
            elif pkg == "golang.org/x/crypto/argon2" and name in ("IDKey", "Key"):
                self.add(node, "kdf", "Argon2", {}, f"argon2.{name}()", api=api, func=fn)
            elif pkg == "golang.org/x/crypto/scrypt" and name == "Key":
                self.add(node, "kdf", "scrypt", {}, "scrypt.Key()", api=api, func=fn)
            elif pkg in GO_MATH_RAND:
                if sec:
                    self.add(node, "rng", "NON-CSPRNG", dict(api=api), f"{pkg}.{name}() used in security-sensitive function {fn}() (math/rand is NOT crypto/rand)",
                             ["weak-prng"], api=api, func=fn)
            elif pkg == "crypto/rand" and name in ("Read", "Int", "Prime", "Text"):
                self.add(node, "rng", "CSPRNG", dict(api=api), f"crypto/rand.{name}()", api=api, func=fn)
        for fn, (node, h, it) in custom_pbkdf2.items():
            self.add(node, "kdf", "PBKDF2", dict(hash=h, iterations=it),
                     f"hand-rolled PBKDF2 in {fn}(): HMAC-{h} iterated {it} times with XOR accumulation (RFC 8018 F function)",
                     ["custom-implementation"], confidence=0.85, api="custom", func=fn)
        self.tls_configs()
        self.jwt()
        self.hardcoded_keys()
        return self.findings

    # ---------------------------------------------------------------- crypto/tls
    def tls_configs(self):
        """tls.Config{...} literals and cfg.Field = ... assignments: protocol range, cipher suites,
        curve preferences (an explicit list without X25519MLKEM768 turns off Go's default PQ hybrid)
        and InsecureSkipVerify."""
        tls_alias = {a for a, path in self.imports.items() if path == "crypto/tls"}
        if not tls_alias:
            return
        types = {f"{a}.Config" for a in tls_alias}
        configs = {}  # (func, var or node id) -> {field: (value node, anchor node)}
        for n in self.walk(self.root):
            if n.type == "composite_literal":
                ty = n.child_by_field_name("type")
                if ty is None or ty.type != "qualified_type" or self.t(ty) not in types:
                    continue
                fields = {}
                body = n.child_by_field_name("body")
                for ke in (body.named_children if body is not None else []):
                    if ke.type != "keyed_element" or len(ke.named_children) < 2:
                        continue
                    k, v = ke.named_children[0], ke.named_children[1]
                    v = v.named_children[0] if v.type == "literal_element" and v.named_children else v
                    fields[self.t(k)] = (v, ke)
                var = self._assigned_var(n)
                configs.setdefault((self.enclosing(n), var or id(n)), {}).update(fields)
            elif n.type == "assignment_statement":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is None or right is None or len(left.named_children) != 1 or len(right.named_children) != 1:
                    continue
                lhs = left.named_children[0]
                if lhs.type != "selector_expression":
                    continue
                field = self.t(lhs.child_by_field_name("field"))
                if field in ("MinVersion", "MaxVersion", "CipherSuites", "CurvePreferences", "InsecureSkipVerify"):
                    var = self.t(lhs.child_by_field_name("operand"))
                    configs.setdefault((self.enclosing(n), var), {})[field] = (right.named_children[0], n)
        for (fn, _var), fields in configs.items():
            if fields:
                self._tls_config(fn, fields)

    def _assigned_var(self, lit):
        """cfg := &tls.Config{...} -> 'cfg' (None when the literal is passed straight to a call)."""
        for a in self.ancestors(lit):
            if a.type == "var_spec":
                names = a.children_by_field_name("name")
                return self.t(names[0]) if names else None
            if a.type in ("short_var_declaration", "assignment_statement"):
                left = a.child_by_field_name("left")
                return self.t(left.named_children[0]) if left is not None and left.named_children else None
            if a.type in ("call_expression", "block", "return_statement", "keyed_element", "argument_list"):
                return None
        return None

    _GO_TLS_VERSIONS = {"VersionSSL30": "SSL 3.0", "VersionTLS10": "TLS 1.0", "VersionTLS11": "TLS 1.1",
                        "VersionTLS12": "TLS 1.2", "VersionTLS13": "TLS 1.3"}
    _GO_CURVES = {"X25519MLKEM768": "x25519mlkem768", "SecP256r1MLKEM768": "secp256r1mlkem768", "SecP384r1MLKEM1024": "secp384r1mlkem1024",
                  "X25519": "x25519", "CurveP256": "secp256r1", "CurveP384": "secp384r1", "CurveP521": "secp521r1"}

    def _sel_field(self, n):
        return self.t(n.child_by_field_name("field")) if n is not None and n.type == "selector_expression" else None

    def _list_fields(self, v):
        """[]uint16{tls.A, tls.B} -> ['A', 'B']"""
        body = v.child_by_field_name("body") if v is not None and v.type == "composite_literal" else None
        return [self._sel_field(e.named_children[0] if e.type == "literal_element" and e.named_children else e)
                for e in (body.named_children if body is not None else [])]

    def _tls_config(self, fn, fields):
        from ...kb import tls as TLS
        groups_by_name = {g["name"].lower(): g for g in TLS.GROUPS.values()}
        order = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
        api = "crypto/tls.Config"
        vmin = self._GO_TLS_VERSIONS.get(self._sel_field(fields["MinVersion"][0])) if "MinVersion" in fields else None
        vmax = self._GO_TLS_VERSIONS.get(self._sel_field(fields["MaxVersion"][0])) if "MaxVersion" in fields else None
        if vmin and order.index(vmin) < order.index("TLS 1.2"):
            hi = vmax if vmax and order.index(vmax) < order.index("TLS 1.2") else "TLS 1.1"
            for v in order[order.index(vmin):order.index(hi) + 1]:
                self.add(fields["MinVersion"][1], "protocol", "SSL" if v.startswith("SSL") else "TLS", dict(version=v),
                         f"tls.Config MinVersion {vmin} accepts {v}", api=api, func=fn)
        # MaxVersion below 1.3: no TLS 1.3, so no ML-KEM hybrid (versions < 1.2 are already reported via MinVersion)
        if vmax and (vmax == "TLS 1.2" or (order.index(vmax) < order.index("TLS 1.2") and not vmin)):
            self.add(fields["MaxVersion"][1], "protocol", "SSL" if vmax.startswith("SSL") else "TLS", dict(version=vmax),
                     f"tls.Config MaxVersion {vmax}: TLS 1.3 is off, so the X25519MLKEM768 hybrid can never be negotiated",
                     ["pq-unreachable"], api=api, func=fn)
        if "CipherSuites" in fields:
            names = self._list_fields(fields["CipherSuites"][0])
            suites = [(nm, TLS.decompose(nm)) for nm in names if nm and nm.startswith("TLS_") and "_WITH_" in nm]
            anchor = fields["CipherSuites"][1]
            rsa = [nm for nm, s in suites if s["kex"] == "RSA"]
            if rsa:
                self.add(anchor, "key-exchange", "RSA", dict(transport=True),
                         f"tls.Config CipherSuites allows RSA key transport (no forward secrecy): {', '.join(rsa[:4])}",
                         ["no-forward-secrecy"], api=api, func=fn)
            seen = set()
            for nm, s in suites:
                key = (s["cipher"], s["cipher_bits"], s["mode"])
                if s["cipher"] and key not in seen:
                    seen.add(key)
                    self.add(anchor, "encryption", s["cipher"], dict(key_bits=s["cipher_bits"], mode=s["mode"]),
                             f"tls.Config CipherSuites allows {nm} (TLS 1.2 and below; Go ignores the list for TLS 1.3)",
                             api=api, func=fn)
            sha1 = [nm for nm, s in suites if s["mac"] == "SHA-1"]
            if sha1:
                self.add(anchor, "mac", "HMAC", dict(hash="SHA-1"), f"tls.Config CipherSuites allows HMAC-SHA1 suites: {', '.join(sha1[:3])}",
                         api=api, func=fn)
        if "CurvePreferences" in fields:
            names = self._list_fields(fields["CurvePreferences"][0])
            gs = [groups_by_name[self._GO_CURVES[nm]] for nm in names if nm in self._GO_CURVES and self._GO_CURVES[nm] in groups_by_name]
            pq = [g for g in gs if g["pq"]]
            tls13 = not vmax or vmax == "TLS 1.3"
            anchor = fields["CurvePreferences"][1]
            for g in gs:
                if g["pq"] and not tls13:
                    continue  # never negotiated: the MaxVersion finding and the classical groups carry it
                if g["pq"]:
                    flags, ev = (["pq-hybrid"] if g.get("hybrid") else []), f"tls.Config CurvePreferences offers {g['name']}"
                elif pq and tls13:
                    flags, ev = ["fallback-for-legacy-clients"], f"tls.Config CurvePreferences offers {g['name']} (fallback; PQ-capable peers get {pq[0]['name']})"
                elif pq:
                    flags, ev = ["pq-unreachable"], f"tls.Config CurvePreferences offers {g['name']}; the PQ groups listed need TLS 1.3, which MaxVersion disables"
                else:
                    flags = ["pq-not-configured"]
                    ev = (f"tls.Config CurvePreferences offers {g['name']}; an explicit list without X25519MLKEM768 "
                          "turns off the PQ hybrid Go enables by default (>= 1.24)")
                self.add(anchor, "key-exchange", g["algorithm"], dict(g["params"], group=g["name"]), ev, flags, api=api, func=fn)
        if "InsecureSkipVerify" in fields and self.t(fields["InsecureSkipVerify"][0]) == "true":
            self.add(fields["InsecureSkipVerify"][1], "authentication", "NO-CERT-VERIFY", dict(api="tls.Config.InsecureSkipVerify"),
                     "tls.Config InsecureSkipVerify: true disables certificate and hostname verification",
                     ["no-cert-verify"], api=api, func=fn)

    def jwt(self):
        """golang-jwt / jwt-go (jwt.SigningMethodRS256, jwt.UnsafeAllowNoneSignatureType) and go-jose (jose.RS256)."""
        libs = {alias for alias, path in self.imports.items() if "jwt" in path or "go-jose" in path}
        if not libs:
            return
        # HMAC secret: token.SignedString([]byte("secret"))
        secret = next(((c["args"][0], c["func"]) for c in self.calls if c["name"] == "SignedString" and c["args"]), None)
        for n in self.walk(self.root):
            if n.type != "selector_expression" or self.t(n.child_by_field_name("operand")) not in libs:
                continue
            field = self.t(n.child_by_field_name("field"))
            jn = "none" if field == "UnsafeAllowNoneSignatureType" else jwt_algorithms.normalize(field)
            if jn:
                self.add_jwt(n, jn, self.enclosing(n), self.t(n), secret)
        # jwt.WithValidMethods([]string{"RS256", "PS256"}): the algorithms a parser accepts
        for c in self.calls:
            if c["obj"] in libs and c["name"] == "WithValidMethods":
                for s in (x for a in c["args"] for x in self.walk(a) if x.type in ("interpreted_string_literal", "raw_string_literal")):
                    jn = jwt_algorithms.normalize(unquote(self.t(s)))
                    if jn:
                        self.add_jwt(s, jn, c["func"], f"jwt.WithValidMethods({jn!r})", secret)

    def block_mode(self, call_node, fn):
        """Which mode wraps the block returned by aes.NewCipher? (GCM/CBC/CTR... or hand-rolled ECB)."""
        var = None
        p = call_node.parent
        while p is not None and p.type in ("expression_list",):
            p = p.parent
        if p is not None and p.type in ("short_var_declaration", "assignment_statement"):
            left = p.child_by_field_name("left")
            if left is not None and left.named_children:
                var = self.t(left.named_children[0])
        if var is None:
            return None, []
        fnode = self.funcs.get(fn, (None,))[0]
        for c in self.calls:
            if c["func"] != fn:
                continue
            if c["pkg"] == "crypto/cipher" and c["name"] in GO_MODES and c["args"] and self.t(c["args"][0]) == var:
                return GO_MODES[c["name"]], []
        for c in self.calls:
            if c["func"] == fn and c["obj"] == var and c["name"] in ("Encrypt", "Decrypt"):
                if self.in_loop(c["node"], fnode):
                    return "ECB", ["ecb-mode", "custom-implementation"]
                return "ECB", ["ecb-mode"]
        return None, []

    def detect_custom_pbkdf2(self):
        out = {}
        for fname, (fnode, params) in self.funcs.items():
            hm = [c for c in self.calls if c["func"] == fname and c["pkg"] == "crypto/hmac" and c["name"] == "New"]
            if not hm or not any(self.in_loop(c["node"], fnode) for c in hm):
                continue
            xor = any(n.type == "assignment_statement" and any(self.t(ch) == "^=" for ch in n.children) for n in self.walk(fnode))
            if not xor:
                continue
            h = self.hash_from_fn(hm[0]["args"][0]) if hm[0]["args"] else None
            it = None
            for n in self.walk(fnode):
                if n.type == "for_clause":
                    cond = n.child_by_field_name("condition")
                    if cond is not None and cond.type == "binary_expression":
                        v = self.value(cond.named_children[-1], fname)
                        if isinstance(v, int) and (it is None or v > it):
                            it = v
            out[fname] = (fnode, h, it)
        return out

    def rsa_role(self):
        for c in self.calls:
            if c["pkg"] == "crypto/rsa" and c["name"].startswith(("Sign", "Verify")):
                return "signature"
            if c["pkg"] == "crypto/rsa" and c["name"].startswith(("Encrypt", "Decrypt")):
                return "encryption"
        return "signature"


# =============================================================================================== Java
J_HASH = {"MD5": "MD5", "MD2": "MD2", "SHA": "SHA-1", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA-224": "SHA-224", "SHA-256": "SHA-256",
          "SHA-384": "SHA-384", "SHA-512": "SHA-512", "SHA-512/256": "SHA-512/256", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
          "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}
J_CIPHER = {"AES": "AES", "AES_128": "AES", "AES_256": "AES", "DESEDE": "3DES", "TRIPLEDES": "3DES", "DES": "DES", "RC4": "RC4", "ARCFOUR": "RC4",
            "BLOWFISH": "Blowfish", "CHACHA20-POLY1305": "ChaCha20-Poly1305", "CHACHA20": "ChaCha20-Poly1305", "RSA": "RSA", "RC2": "RC2"}
J_KPG = {"RSA": ("RSA", "signature"), "EC": ("ECDSA", "signature"), "ECDSA": ("ECDSA", "signature"), "ED25519": ("Ed25519", "signature"),
         "ED448": ("Ed448", "signature"), "EDDSA": ("Ed25519", "signature"), "DSA": ("DSA", "signature"), "DH": ("DH", "key-exchange"),
         "DIFFIEHELLMAN": ("DH", "key-exchange"), "X25519": ("X25519", "key-exchange"), "X448": ("X448", "key-exchange"), "XDH": ("X25519", "key-exchange"),
         "ML-KEM": ("ML-KEM", "key-exchange"), "ML-KEM-512": ("ML-KEM", "key-exchange"), "ML-KEM-768": ("ML-KEM", "key-exchange"), "ML-KEM-1024": ("ML-KEM", "key-exchange"),
         "ML-DSA": ("ML-DSA", "signature"), "ML-DSA-44": ("ML-DSA", "signature"), "ML-DSA-65": ("ML-DSA", "signature"), "ML-DSA-87": ("ML-DSA", "signature")}
J_CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "nistp256": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "secp256k1"}


class JavaFile(TSFile):
    lang = "java"

    def _index(self, root, func):
        for n in self.walk(root):
            if n.type == "import_declaration":
                fq = self.t(n).replace("import", "").replace("static", "").replace(";", "").strip()
                self.imports[fq.split(".")[-1]] = fq
            elif n.type in ("method_declaration", "constructor_declaration"):
                name = self.t(n.child_by_field_name("name"))
                params = []
                fp = n.child_by_field_name("parameters")
                for p in (fp.named_children if fp is not None else []):
                    nm = p.child_by_field_name("name")
                    if nm is not None:
                        params.append(self.t(nm))
                self.funcs[name] = (n, params)
        for n in self.walk(root):
            fn = self.enclosing(n)
            if n.type == "variable_declarator":
                nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                if nm is not None and val is not None:
                    self.consts.setdefault((fn, self.t(nm)), val)
            elif n.type == "assignment_expression":
                l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
                if l is not None and r is not None and l.type == "identifier":
                    self.consts.setdefault((fn, self.t(l)), r)
            elif n.type == "method_invocation":
                obj = n.child_by_field_name("object")
                args = n.child_by_field_name("arguments")
                self.calls.append(dict(node=n, obj=self.t(obj) if obj is not None else None, name=self.t(n.child_by_field_name("name")),
                                       args=args.named_children if args is not None else [], func=fn, new=False))
            elif n.type == "object_creation_expression":
                args = n.child_by_field_name("arguments")
                self.calls.append(dict(node=n, obj="new", name=self.t(n.child_by_field_name("type")),
                                       args=args.named_children if args is not None else [], func=fn, new=True))

    def enclosing(self, n):
        for a in self.ancestors(n):
            if a.type in ("method_declaration", "constructor_declaration"):
                return self.t(a.child_by_field_name("name"))
        return None

    def value_special(self, n, func, depth):
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) == "getBytes":
            v = self.value(n.child_by_field_name("object"), func, depth + 1)
            return v.encode() if isinstance(v, str) else None
        if n.type == "array_creation_expression":
            dims = [c for c in n.named_children if c.type == "dimensions_expr"]
            if dims and dims[0].named_children:
                k = self.value(dims[0].named_children[0], func, depth + 1)
                return ("bytes", k) if isinstance(k, int) else None
            init = [c for c in n.named_children if c.type == "array_initializer"]
            if init:
                return bytes(len(init[0].named_children))
        if n.type == "field_access":
            return self.resolve_name(self.t(n.child_by_field_name("field")), func, depth)
        if n.type == "method_invocation" and n.child_by_field_name("object") is None:
            return self.call_return(self.t(n.child_by_field_name("name")), depth)
        return None

    def str_arg(self, c, i=0):
        return self.value(c["args"][i], c["func"]) if len(c["args"]) > i else None

    def var_of(self, node):
        p = node.parent
        if p is not None and p.type == "variable_declarator":
            return self.t(p.child_by_field_name("name"))
        if p is not None and p.type == "assignment_expression":
            return self.t(p.child_by_field_name("left"))
        return None

    def scan(self) -> list[Finding]:
        # ---- key-size knowledge for the file ----
        aes_bits, aes_literal = None, False
        kpg_bits = {}
        keygens = []  # KeyGenerator.getInstance("AES") + init(128): the key size of every AES key the code makes
        for c in self.calls:
            if c["new"] and c["name"] == "SecretKeySpec" and len(c["args"]) >= 2:
                alg = str(self.str_arg(c, len(c["args"]) - 1) or "").upper()
                if alg.startswith("AES"):
                    kb = self.nbytes(self.value(c["args"][0], c["func"]))
                    if kb:
                        aes_bits = kb * 8
                    aes_literal = aes_literal or self.is_literal(c["args"][0], c["func"])
            if not c["new"] and c["name"] in ("getInstance",) and c["obj"] in ("KeyGenerator", "KeyPairGenerator"):
                var = self.var_of(c["node"])
                alg = str(self.str_arg(c) or "").upper()
                for d in self.calls:
                    if d["obj"] == var and d["name"] in ("init", "initialize") and d["args"]:
                        a0 = d["args"][0]
                        v = self.value(a0, d["func"])
                        if a0.type == "object_creation_expression" and a0.child_by_field_name("arguments") is not None:
                            inner = a0.child_by_field_name("arguments").named_children
                            v = self.value(inner[0], d["func"]) if inner else None
                        if c["obj"] == "KeyGenerator" and alg.startswith("AES") and isinstance(v, int):
                            aes_bits = v
                            keygens.append((d["node"], "AES", v, d["func"]))
                        elif c["obj"] == "KeyGenerator" and alg in ("DES", "DESEDE", "TRIPLEDES", "BLOWFISH", "RC4", "ARCFOUR"):
                            keygens.append((d["node"], J_CIPHER.get(alg, alg), v if isinstance(v, int) else None, d["func"]))
                        else:
                            kpg_bits[alg] = v
        for node, alg, bits, fn in keygens:
            self.add(node, "key", alg, dict(key_bits=bits), f'KeyGenerator.getInstance("{alg}").init({bits}): generates {alg}-{bits} keys'
                     if bits else f'KeyGenerator.getInstance("{alg}") generates {alg} keys', api="KeyGenerator", func=fn)
        sig_algs = [str(self.str_arg(c) or "") for c in self.calls if c["obj"] == "Signature" and c["name"] == "getInstance"]
        for c in self.calls:
            obj, name, fn, node = c["obj"], c["name"], c["func"], c["node"]
            fl = (fn or "").lower()
            sec = any(w in fl for w in SEC_WORDS)
            if name == "getInstance" and obj == "MessageDigest":
                a = str(self.str_arg(c) or "")
                flags = ["password-hashing", "unsalted"] if "password" in fl else []
                self.add(node, "hash", J_HASH.get(a.upper(), J_HASH.get(a, a)), {}, f'MessageDigest.getInstance("{a}")', flags, api="MessageDigest", func=fn)
            elif name == "getInstance" and obj == "Cipher":
                tr = str(self.str_arg(c) or "")
                parts = tr.split("/")
                alg = J_CIPHER.get(parts[0].upper(), parts[0])
                mode = parts[1].upper() if len(parts) > 1 else None
                pad = parts[2] if len(parts) > 2 else None
                flags = []
                if alg == "RSA":
                    padding = "OAEP" if pad and "OAEP" in pad.upper() else "PKCS1v15"
                    self.add(node, "encryption", "RSA", dict(key_bits=kpg_bits.get("RSA"), padding=padding),
                             f'Cipher.getInstance("{tr}") (RSA "ECB" is a JCE naming quirk, not a block mode)', api="Cipher", func=fn)
                    continue
                if alg == "AES" and mode is None:
                    mode, pad = "ECB", "PKCS5Padding"
                    flags.append("jce-default-ecb")
                if mode == "ECB":
                    flags.append("ecb-mode")
                if alg == "AES" and aes_literal:
                    flags.append("hardcoded-key")
                bits = aes_bits if alg == "AES" else ({"3DES": 168, "DES": 56}.get(alg))
                ev = f'Cipher.getInstance("{tr}")' + (f" with {bits}-bit key" if bits else " (key size unresolved)")
                if "jce-default-ecb" in flags:
                    ev += ' - bare "AES" defaults to AES/ECB/PKCS5Padding in the JCE'
                self.add(node, "encryption", alg, dict(key_bits=bits, mode=mode, padding=pad), ev, flags,
                         confidence=1.0 if bits else 0.6, api="Cipher", func=fn)
            elif name == "getInstance" and obj == "KeyPairGenerator":
                a = str(self.str_arg(c) or "").upper()
                alg, cat = J_KPG.get(a, (a, "key"))
                params = {}
                v = kpg_bits.get(a)
                if alg in ("RSA", "DSA", "DH"):
                    params["key_bits"] = v
                elif alg == "ECDSA" and isinstance(v, str):
                    params["curve"] = J_CURVES.get(v, v)
                elif alg in ("ML-KEM", "ML-DSA"):
                    params["parameter_set"] = a if a[-2:].isdigit() else ("ML-KEM-768" if alg == "ML-KEM" else "ML-DSA-65")
                if alg == "RSA" and not any("RSA" in s.upper() for s in sig_algs):
                    cat = "encryption" if any(str(self.str_arg(d) or "").upper().startswith("RSA") for d in self.calls if d["obj"] == "Cipher") else cat
                self.add(node, cat, alg, params, f'KeyPairGenerator.getInstance("{a}")' + (f" initialize({v})" if v else ""), api="KeyPairGenerator", func=fn)
            elif name == "getInstance" and obj == "Signature":
                a = str(self.str_arg(c) or "")
                u = a.upper()
                if "WITH" in u:
                    h, _, k = u.partition("WITH")
                    h = J_HASH.get(h, J_HASH.get(h.replace("SHA", "SHA-"), h))
                    alg = {"RSA": "RSA", "ECDSA": "ECDSA", "DSA": "DSA", "RSA/PSS": "RSA", "RSAANDMGF1": "RSA"}.get(k, k)
                    params = dict(hash=h, padding="PSS" if "PSS" in k or "MGF1" in k else ("PKCS1v15" if alg == "RSA" else None),
                                  key_bits=kpg_bits.get("RSA") if alg == "RSA" else None)
                elif u in ("ED25519", "EDDSA"):
                    alg, params = "Ed25519", {}
                elif u == "ED448":
                    alg, params = "Ed448", {}
                elif u.startswith("ML-DSA"):
                    alg, params = "ML-DSA", dict(parameter_set=u if u[-2:].isdigit() else "ML-DSA-65")
                elif u == "RSASSA-PSS":
                    alg, params = "RSA", dict(padding="PSS", key_bits=kpg_bits.get("RSA"))
                else:
                    alg, params = u, {}
                self.add(node, "signature", alg, params, f'Signature.getInstance("{a}")', api="Signature", func=fn)
            elif name == "getInstance" and obj == "Mac":
                a = str(self.str_arg(c) or "")
                h = a.upper().replace("HMAC", "")
                h = J_HASH.get(h, J_HASH.get(h.replace("SHA", "SHA-"), h))
                self.add(node, "mac", "HMAC", dict(hash=h), f'Mac.getInstance("{a}")', api="Mac", func=fn)
            elif name == "getInstance" and obj == "SecretKeyFactory":
                a = str(self.str_arg(c) or "")
                u = a.upper()
                if u.startswith("PBKDF2WITHHMAC"):
                    h = u.replace("PBKDF2WITHHMAC", "")
                    h = J_HASH.get(h, J_HASH.get(h.replace("SHA", "SHA-"), h))
                    it = None
                    for d in self.calls:
                        if d["new"] and d["name"] == "PBEKeySpec" and len(d["args"]) >= 3:
                            it = self.value(d["args"][2], d["func"])
                    self.add(node, "kdf", "PBKDF2", dict(hash=h, iterations=it), f'SecretKeyFactory.getInstance("{a}") iterations={it}', api="SecretKeyFactory", func=fn)
                elif u.startswith("PBEWITH"):
                    self.add(node, "kdf", "PBKDF1", dict(scheme=a), f'SecretKeyFactory.getInstance("{a}") (PBES1: weak)', ["weak-kdf"], api="SecretKeyFactory", func=fn)
            elif name == "getInstance" and obj in ("KeyAgreement",):
                a = str(self.str_arg(c) or "").upper()
                alg = {"ECDH": "ECDH", "DH": "DH", "DIFFIEHELLMAN": "DH", "X25519": "X25519", "XDH": "X25519", "X448": "X448"}.get(a, a)
                self.add(node, "key-exchange", alg, {}, f'KeyAgreement.getInstance("{a}")', api="KeyAgreement", func=fn)
            elif name == "getInstance" and obj == "KEM":
                a = str(self.str_arg(c) or "").upper()
                alg = "ML-KEM" if a.startswith("ML-KEM") else ("DH" if a.startswith("DHKEM") else a)
                self.add(node, "key-exchange", alg, dict(parameter_set=a if a[-3:].isdigit() else ("ML-KEM-768" if alg == "ML-KEM" else None)), f'KEM.getInstance("{a}")', api="KEM", func=fn)
            elif name == "getInstance" and obj == "SSLContext":
                a = str(self.str_arg(c) or "")
                v = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3", "SSLv3": "SSL 3.0", "SSL": "SSL 3.0"}.get(a)
                if v:
                    self.add(node, "protocol", "SSL" if v.startswith("SSL") else "TLS", dict(version=v), f'SSLContext.getInstance("{a}")', api="SSLContext", func=fn)
            elif c["new"] and name in ("Random", "java.util.Random"):
                if sec and self.imports.get("Random", "java.util.Random") == "java.util.Random":
                    self.add(node, "rng", "NON-CSPRNG", dict(api="java.util.Random"), f"new java.util.Random() in security-sensitive method {fn}()", ["weak-prng"], api="java.util.Random", func=fn)
            elif obj == "Math" and name == "random" and sec:
                self.add(node, "rng", "NON-CSPRNG", dict(api="Math.random"), f"Math.random() in security-sensitive method {fn}()", ["weak-prng"], api="Math.random", func=fn)
            elif (c["new"] and name == "SecureRandom") or (obj == "SecureRandom" and name in ("getInstanceStrong", "getInstance")):
                self.add(node, "rng", "CSPRNG", dict(api="SecureRandom"), "java.security.SecureRandom", api="SecureRandom", func=fn)
        self.jwt()
        self.hardcoded_keys()
        return self.findings

    J_JWT_LIBS = ("io.jsonwebtoken", "com.auth0.jwt", "com.nimbusds.jose")

    def jwt(self):
        """jjwt (SignatureAlgorithm.RS256, Jwts.SIG.ES256), Nimbus (JWSAlgorithm.PS256), auth0 (Algorithm.RSA256(...))."""
        if not any(v.startswith(self.J_JWT_LIBS) for v in self.imports.values()):
            return
        # HMAC secret: jjwt Keys.hmacShaKeyFor("...".getBytes())
        secret = next(((c["args"][0], c["func"]) for c in self.calls if c["name"] == "hmacShaKeyFor" and c["args"]), None)
        for n in self.walk(self.root):
            if n.type != "field_access":
                continue
            if self.t(n.child_by_field_name("object")).split(".")[-1] not in ("SignatureAlgorithm", "SIG", "JWSAlgorithm", "JWEAlgorithm"):
                continue
            jn = jwt_algorithms.normalize(self.t(n.child_by_field_name("field")))
            if jn:
                # legacy jjwt: signWith(SignatureAlgorithm.HS256, "secret") -> the sibling argument is the key
                sib = [a for a in (n.parent.named_children if n.parent is not None and n.parent.type == "argument_list" else []) if a != n]
                fn = self.enclosing(n)
                self.add_jwt(n, jn, fn, self.t(n), (sib[0], fn) if sib else secret)
        for c in self.calls:
            if c["obj"] == "Algorithm" and not c["new"]:
                jn = jwt_algorithms.normalize(c["name"])
                if jn:
                    self.add_jwt(c["node"], jn, c["func"], f"Algorithm.{c['name']}()", (c["args"][0], c["func"]) if c["args"] else None)


def scan_go(path, rel):
    with open(path, "rb") as fh:
        return GoFile(fh.read(), rel).scan()


def scan_java(path, rel):
    with open(path, "rb") as fh:
        return JavaFile(fh.read(), rel).scan()
