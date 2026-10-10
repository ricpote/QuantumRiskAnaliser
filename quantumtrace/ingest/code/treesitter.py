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
        self.jwt()
        self.hardcoded_keys()
        return self.findings

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
                        else:
                            kpg_bits[alg] = v
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


# =============================================================================================== JavaScript / TypeScript
JS_HASH = {"md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha-1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha-256": "SHA-256",
           "sha384": "SHA-384", "sha-384": "SHA-384", "sha512": "SHA-512", "sha-512": "SHA-512", "sha512-256": "SHA-512/256",
           "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512", "ripemd160": "RIPEMD-160", "rmd160": "RIPEMD-160",
           "shake128": "SHAKE128", "shake256": "SHAKE256", "blake2b512": "BLAKE2b", "blake2s256": "BLAKE2s"}
JS_CURVES = {"prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256", "secp384r1": "P-384", "p-384": "P-384",
             "secp521r1": "P-521", "p-521": "P-521", "secp256k1": "secp256k1", "secp224r1": "P-224"}
# OpenSSL cipher names accepted by createCipheriv (besides aes-<bits>-<mode>)
JS_CIPHERS = {"des-ede3-cbc": ("3DES", 168, "CBC"), "des-ede3": ("3DES", 168, "ECB"), "des3": ("3DES", 168, "CBC"),
              "des-ede-cbc": ("3DES", 112, "CBC"), "des-ede": ("3DES", 112, "ECB"), "des-cbc": ("DES", 56, "CBC"),
              "des-ecb": ("DES", 56, "ECB"), "des": ("DES", 56, "CBC"), "rc4": ("RC4", 128, None), "rc4-40": ("RC4", 40, None),
              "bf-cbc": ("Blowfish", 128, "CBC"), "bf-ecb": ("Blowfish", 128, "ECB"), "bf": ("Blowfish", 128, "CBC"),
              "chacha20-poly1305": ("ChaCha20-Poly1305", 256, None), "chacha20": ("ChaCha20-Poly1305", 256, None)}
# generateKeyPair(type) -> (algorithm, default category, option holding the size)
JS_KEYPAIR = {"rsa": ("RSA", "signature", "modulusLength"), "rsa-pss": ("RSA", "signature", "modulusLength"),
              "dsa": ("DSA", "signature", "modulusLength"), "ec": ("ECDSA", "signature", "namedCurve"),
              "ed25519": ("Ed25519", "signature", None), "ed448": ("Ed448", "signature", None),
              "x25519": ("X25519", "key-exchange", None), "x448": ("X448", "key-exchange", None), "dh": ("DH", "key-exchange", "primeLength"),
              "ml-kem-512": ("ML-KEM", "key-exchange", None), "ml-kem-768": ("ML-KEM", "key-exchange", None), "ml-kem-1024": ("ML-KEM", "key-exchange", None),
              "ml-dsa-44": ("ML-DSA", "signature", None), "ml-dsa-65": ("ML-DSA", "signature", None), "ml-dsa-87": ("ML-DSA", "signature", None)}
JS_MODP = {"modp1": 768, "modp2": 1024, "modp5": 1536, "modp14": 2048, "modp15": 3072, "modp16": 4096, "modp17": 6144, "modp18": 8192}
# WebCrypto algorithm names -> (category, algorithm, fixed params)
WEBCRYPTO = {"RSA-OAEP": ("encryption", "RSA", {"padding": "OAEP"}), "RSASSA-PKCS1-v1_5": ("signature", "RSA", {"padding": "PKCS1v15"}),
             "RSA-PSS": ("signature", "RSA", {"padding": "PSS"}), "ECDSA": ("signature", "ECDSA", {}), "ECDH": ("key-exchange", "ECDH", {}),
             "Ed25519": ("signature", "Ed25519", {}), "Ed448": ("signature", "Ed448", {}), "X25519": ("key-exchange", "X25519", {}),
             "X448": ("key-exchange", "X448", {}), "AES-GCM": ("encryption", "AES", {"mode": "GCM"}), "AES-CBC": ("encryption", "AES", {"mode": "CBC"}),
             "AES-CTR": ("encryption", "AES", {"mode": "CTR"}), "AES-KW": ("encryption", "AES", {"mode": "KW"}), "HMAC": ("mac", "HMAC", {}),
             "PBKDF2": ("kdf", "PBKDF2", {}), "HKDF": ("kdf", "HKDF", {})}
JS_JWT_LIBS = ("jsonwebtoken", "jose")


def js_cipher(name: str):
    """'aes-128-ecb' / 'aes256' / 'id-aes128-GCM' / 'des-ede3-cbc' -> (algorithm, key bits, mode) or None."""
    n = name.lower().removeprefix("id-")
    m = re.fullmatch(r"aes-?(128|192|256)(?:-([a-z0-9]+))?", n)
    if m:
        return "AES", int(m.group(1)), (m.group(2) or "cbc").upper()
    return JS_CIPHERS.get(n)


class JsFile(TSFile):
    """node:crypto, WebCrypto (crypto.subtle) and jsonwebtoken in .js/.mjs/.cjs/.jsx/.ts/.tsx."""

    def __init__(self, src: bytes, rel: str, lang: str):
        self.lang = lang
        super().__init__(src, rel)

    def _index(self, root, func):
        for n in self.walk(root):
            if n.type == "import_statement":
                src = self.module_name(n.child_by_field_name("source"))
                for x in self.walk(n):
                    if x.type == "import_specifier":
                        nm, alias = x.child_by_field_name("name"), x.child_by_field_name("alias")
                        self.imports[self.t(alias if alias is not None else nm)] = f"{src}.{self.t(nm)}"
                    elif x.type == "namespace_import" or (x.type == "identifier" and x.parent is not None and x.parent.type == "import_clause"):
                        ident = x if x.type == "identifier" else next((c for c in x.named_children if c.type == "identifier"), None)
                        if ident is not None:
                            self.imports[self.t(ident)] = src
            elif n.type == "variable_declarator":
                name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                if val is not None and val.type == "call_expression" and self.t(val.child_by_field_name("function")) == "require":
                    args = val.child_by_field_name("arguments").named_children
                    src = self.module_name(args[0]) if args else ""
                    if name.type == "identifier":
                        self.imports[self.t(name)] = src
                    for p in (name.named_children if name.type == "object_pattern" else []):
                        if p.type == "shorthand_property_identifier_pattern":
                            self.imports[self.t(p)] = f"{src}.{self.t(p)}"
                        elif p.type == "pair_pattern":
                            self.imports[self.t(p.child_by_field_name("value"))] = f"{src}.{self.t(p.child_by_field_name('key'))}"
                elif val is not None and name.type == "identifier":
                    if val.type in ("arrow_function", "function_expression", "function"):
                        self.funcs[self.t(name)] = (val, self.params(val))
                    self.consts.setdefault((self.enclosing(n), self.t(name)), val)
            elif n.type in ("function_declaration", "generator_function_declaration", "method_definition"):
                self.funcs[self.t(n.child_by_field_name("name"))] = (n, self.params(n))
        for n in self.walk(root):
            if n.type == "call_expression":
                f = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                args = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
                obj, name = (self.t(f.child_by_field_name("object")), self.t(f.child_by_field_name("property"))) if f.type == "member_expression" else (None, self.t(f))
                self.calls.append(dict(node=n, obj=obj, name=name, args=args, func=self.enclosing(n), mod=self.module_of(obj, name)))

    def module_name(self, n) -> str:
        return unquote(self.t(n)).removeprefix("node:") if n is not None else ""

    def module_of(self, obj, name):
        """Which library a call belongs to: 'crypto' | 'webcrypto' | 'jsonwebtoken' | 'jose' | other import | None."""
        if obj is None:
            imp = self.imports.get(name, "")
            return imp.rsplit(".", 1)[0] if "." in imp else None
        if obj.split(".")[-1] == "subtle":
            return "webcrypto"  # crypto.subtle / window.crypto.subtle / globalThis.crypto.subtle
        root = obj.split(".")[0]
        if root in self.imports:
            return self.imports[root]
        return "crypto" if root == "crypto" else None  # global `crypto` (Node REPL / CommonJS habit)

    def params(self, fn_node):
        ps = fn_node.child_by_field_name("parameters") or fn_node.child_by_field_name("parameter")
        out = []
        for p in ([ps] if ps is not None and ps.type == "identifier" else (ps.named_children if ps is not None else [])):
            ident = p if p.type == "identifier" else (p.child_by_field_name("pattern") or p.child_by_field_name("left"))
            if ident is not None and ident.type == "identifier":
                out.append(self.t(ident))
        return out

    def enclosing(self, n):
        for a in self.ancestors(n):
            if a.type in ("function_declaration", "generator_function_declaration", "method_definition"):
                return self.t(a.child_by_field_name("name"))
            if a.type in ("arrow_function", "function_expression", "function") and a.parent is not None and a.parent.type == "variable_declarator":
                return self.t(a.parent.child_by_field_name("name"))
        return None

    def value_special(self, n, func, depth):
        ty = n.type
        if ty == "string":
            return unquote(self.t(n))
        if ty == "template_string" and not any(c.type == "template_substitution" for c in n.named_children):
            return unquote(self.t(n))
        if ty == "number":
            return parse_int(self.t(n))
        if ty in ("true", "false"):
            return ty == "true"
        if ty in ("as_expression", "satisfies_expression", "non_null_expression") and n.named_children:
            return self.value(n.named_children[0], func, depth + 1)
        if ty == "call_expression":
            f = n.child_by_field_name("function")
            args = [a for a in n.child_by_field_name("arguments").named_children if a.type != "comment"]
            ft = self.t(f)
            if ft == "Buffer.from" and args:  # Buffer.from('00ff..', 'hex')
                v = self.value(args[0], func, depth + 1)
                enc = self.value(args[1], func, depth + 1) if len(args) > 1 else None
                if isinstance(v, str) and enc == "hex" and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", v):
                    return bytes.fromhex(v)
                if isinstance(v, str) and enc == "base64":
                    return ("bytes", len(v.rstrip("=")) * 3 // 4)
                return v.encode() if isinstance(v, str) else None
            if ft.endswith("randomBytes") and args:
                k = self.value(args[0], func, depth + 1)
                return ("bytes", k) if isinstance(k, int) else None
            if f.type == "member_expression" and self.t(f.child_by_field_name("property")) == "encode" and args:  # new TextEncoder().encode('...')
                v = self.value(args[0], func, depth + 1)
                return v.encode() if isinstance(v, str) else None
            if f.type == "identifier":
                return self.call_return(ft, depth)
        return None

    def node_of(self, n, func, depth=0):
        """Follow identifiers to the expression they are bound to (object literals such as WebCrypto params)."""
        while n is not None and n.type == "identifier" and depth < 6:
            key = next(((s, self.t(n)) for s in (func, None) if (s, self.t(n)) in self.consts), None)
            if key is None:
                return n
            n, func, depth = self.consts[key], key[0], depth + 1
        return n

    def prop(self, obj, key, func):
        """Value node of `key` in an object literal (after resolving identifiers), else None."""
        o = self.node_of(obj, func)
        for p in (o.named_children if o is not None and o.type == "object" else []):
            if p.type == "pair" and unquote(self.t(p.child_by_field_name("key"))) == key:
                return p.child_by_field_name("value")
        return None

    def pval(self, obj, key, func):
        v = self.prop(obj, key, func)
        return self.value(v, func) if v is not None else None

    def scan(self) -> list[Finding]:
        kp = next((c for c in self.calls if c["mod"] == "crypto" and c["name"] in ("generateKeyPairSync", "generateKeyPair")), None)
        rsa_bits = self.pval(kp["args"][1], "modulusLength", kp["func"]) if kp and len(kp["args"]) > 1 else None
        rsa_encrypts = any(c["mod"] == "crypto" and c["name"] in ("publicEncrypt", "privateDecrypt") for c in self.calls)
        rsa_signs = any(c["mod"] == "crypto" and c["name"] in ("createSign", "sign") for c in self.calls)
        uses_jose = any(v == "jose" or v.startswith("jose.") for v in self.imports.values())
        for c in self.calls:
            mod, name, args, fn, node = c["mod"], c["name"], c["args"], c["func"], c["node"]
            fl = (fn or "").lower()
            arg = lambda i: self.value(args[i], fn) if len(args) > i else None
            api = f"{mod}.{name}"
            if mod == "crypto":
                if name == "createHash" and isinstance(arg(0), str):
                    h = JS_HASH.get(arg(0).lower(), arg(0).upper())
                    self.add(node, "hash", h, {}, f"createHash('{arg(0)}')", ["password-hashing", "unsalted"] if "password" in fl else [], api=api, func=fn)
                elif name == "createHmac" and isinstance(arg(0), str):
                    kb = self.nbytes(arg(1))
                    flags = ["hardcoded-key"] if len(args) > 1 and self.is_literal(args[1], fn) else []
                    self.add(node, "mac", "HMAC", dict(hash=JS_HASH.get(arg(0).lower(), arg(0).upper()), key_bits=kb * 8 if kb else None),
                             f"createHmac('{arg(0)}', key)", flags, api=api, func=fn)
                elif name in ("createCipheriv", "createDecipheriv", "createCipher", "createDecipher") and isinstance(arg(0), str):
                    spec = js_cipher(arg(0))
                    if not spec:
                        continue
                    alg, bits, mode = spec
                    flags = (["ecb-mode"] if mode == "ECB" else []) + (["hardcoded-key"] if len(args) > 1 and self.is_literal(args[1], fn) else [])
                    if name in ("createCipher", "createDecipher"):
                        flags.append("weak-kdf")  # removed in Node 22: key = EVP_BytesToKey(MD5, password), no salt
                    self.add(node, "encryption", alg, dict(key_bits=bits, mode=mode), f"{name}('{arg(0)}', key, ...)", flags, api=api, func=fn)
                elif name in ("generateKeyPairSync", "generateKeyPair") and isinstance(arg(0), str) and arg(0).lower() in JS_KEYPAIR:
                    t = arg(0).lower()
                    alg, cat, opt = JS_KEYPAIR[t]
                    v = self.pval(args[1], opt, fn) if opt and len(args) > 1 else None
                    params = {"rsa-pss": dict(padding="PSS")}.get(t, {})
                    if opt == "namedCurve":
                        params["curve"] = JS_CURVES.get(str(v).lower(), v)
                    elif opt:
                        params["key_bits"] = v
                    if t.startswith(("ml-kem", "ml-dsa")):
                        params["parameter_set"] = t.upper()
                    if alg == "RSA" and rsa_encrypts and not rsa_signs:
                        cat = "encryption"
                    self.add(node, cat, alg, params, f"{name}('{arg(0)}'" + (f", {{{opt}: {v}}})" if opt else ")"), api=api, func=fn)
                elif name in ("createSign", "createVerify") and isinstance(arg(0), str):
                    # 'RSA-SHA1' names the key type; plain 'sha256' does not: use the file's generateKeyPair type, else unknown
                    h = JS_HASH.get(arg(0).lower().removeprefix("rsa-"))
                    kp_type = str(self.value(kp["args"][0], kp["func"])).lower() if kp else ""
                    alg = "RSA" if arg(0).upper().startswith("RSA-") else JS_KEYPAIR.get(kp_type, ("CLASSICAL-SIG",))[0]
                    params = dict(hash=h, key_bits=rsa_bits if alg == "RSA" else None, candidates=["RSA", "ECDSA"] if alg == "CLASSICAL-SIG" else None)
                    self.add(node, "signature", alg, params, f"{name}('{arg(0)}')", api=api, func=fn)
                elif name in ("publicEncrypt", "privateDecrypt"):
                    pad = self.prop(args[0], "padding", fn) if args else None
                    padding = "PKCS1v15" if pad is not None and "PKCS1_PADDING" in self.t(pad) else "OAEP"  # Node default: OAEP
                    self.add(node, "encryption", "RSA", dict(key_bits=rsa_bits, padding=padding), f"{name}() with {padding}", api=api, func=fn)
                elif name == "createECDH" and isinstance(arg(0), str):
                    self.add(node, "key-exchange", "ECDH", dict(curve=JS_CURVES.get(arg(0).lower(), arg(0))), f"createECDH('{arg(0)}')", api=api, func=fn)
                elif name == "createDiffieHellman":
                    self.add(node, "key-exchange", "DH", dict(key_bits=arg(0) if isinstance(arg(0), int) else None), "createDiffieHellman()", api=api, func=fn)
                elif name in ("getDiffieHellman", "createDiffieHellmanGroup") and isinstance(arg(0), str):
                    self.add(node, "key-exchange", "DH", dict(key_bits=JS_MODP.get(arg(0)), group=arg(0)), f"{name}('{arg(0)}')", api=api, func=fn)
                elif name in ("pbkdf2Sync", "pbkdf2"):
                    h = arg(4)
                    self.add(node, "kdf", "PBKDF2", dict(hash=JS_HASH.get(str(h).lower()) if h else None, iterations=arg(2)),
                             f"{name}(..., {arg(2)} iterations, '{h}')", api=api, func=fn)
                elif name in ("scryptSync", "scrypt"):
                    self.add(node, "kdf", "scrypt", {}, f"{name}()", api=api, func=fn)
                elif name in ("hkdfSync", "hkdf"):
                    self.add(node, "kdf", "HKDF", dict(hash=JS_HASH.get(str(arg(0)).lower())), f"{name}()", api=api, func=fn)
                elif name in ("randomBytes", "randomUUID", "getRandomValues", "randomInt"):
                    self.add(node, "rng", "CSPRNG", dict(api=api), f"crypto.{name}()", api=api, func=fn)
            elif mod == "webcrypto":
                self.webcrypto(c)
            elif mod in JS_JWT_LIBS or (name == "setProtectedHeader" and uses_jose):  # jose: new SignJWT(..).setProtectedHeader({alg})
                self.jwt(c)
            elif c["obj"] == "Math" and name == "random" and any(w in fl for w in SEC_WORDS):
                self.add(node, "rng", "NON-CSPRNG", dict(api="Math.random"), f"Math.random() in security-sensitive function {fn}()", ["weak-prng"],
                         api="Math.random", func=fn)
        self.hardcoded_keys()
        return self.findings

    def webcrypto(self, c):
        """crypto.subtle.generateKey / importKey / deriveKey / digest: the algorithm is a string or a params object."""
        name, args, fn, node = c["name"], c["args"], c["func"], c["node"]
        idx = {"generateKey": 0, "importKey": 2, "deriveKey": 2, "digest": 0}.get(name)
        if idx is None or len(args) <= idx:
            return
        a = self.node_of(args[idx], fn)
        algo = self.value(a, fn) if a.type != "object" else self.pval(a, "name", fn)
        if name == "digest":
            if isinstance(algo, str) and algo.lower() in JS_HASH:
                self.add(node, "hash", JS_HASH[algo.lower()], {}, f"crypto.subtle.digest('{algo}')", api="crypto.subtle.digest", func=fn)
            return
        if algo not in WEBCRYPTO:
            return
        category, alg, params = WEBCRYPTO[algo]
        params = dict(params)
        h = self.pval(a, "hash", fn)
        if isinstance(h, str):
            params["hash"] = JS_HASH.get(h.lower(), h)
        if alg == "RSA":
            params["key_bits"] = self.pval(a, "modulusLength", fn)
        elif alg in ("ECDSA", "ECDH"):
            params["curve"] = JS_CURVES.get(str(self.pval(a, "namedCurve", fn)).lower())
        elif alg in ("AES", "HMAC"):
            bits = self.pval(a, "length", fn)
            if bits is None and name == "importKey" and len(args) > 1:  # importKey('raw', keyBytes, 'AES-GCM', ...)
                kb = self.nbytes(self.value(args[1], fn))
                bits = kb * 8 if kb else None
            params["key_bits"] = bits
        elif alg == "PBKDF2":
            params["iterations"] = self.pval(a, "iterations", fn)
        flags = ["hardcoded-key"] if name == "importKey" and len(args) > 1 and self.is_literal(args[1], fn) else []
        self.add(node, category, alg, params, f"crypto.subtle.{name}({algo})", flags, api=f"crypto.subtle.{name}", func=fn)

    def jwt(self, c):
        """jsonwebtoken: jwt.sign(payload, key, {algorithm}) / jwt.verify(token, key, {algorithms}); jose: setProtectedHeader({alg})."""
        name, args, fn, node = c["name"], c["args"], c["func"], c["node"]
        if c["mod"] == "jsonwebtoken" and name in ("sign", "verify"):
            opts = args[2] if len(args) > 2 else None
            if name == "sign":
                v = self.pval(opts, "algorithm", fn) if opts is not None else None
                algs = [v or "HS256"]  # jsonwebtoken default
            else:
                lst = self.prop(opts, "algorithms", fn) if opts is not None else None
                algs = [self.value(x, fn) for x in lst.named_children] if lst is not None and lst.type == "array" else []
            for a in algs:
                jn = jwt_algorithms.normalize(a)
                if jn:
                    self.add_jwt(node, jn, fn, f"jwt.{name}", (args[1], fn) if len(args) > 1 else None)
        elif name == "setProtectedHeader" and args:
            jn = jwt_algorithms.normalize(self.pval(args[0], "alg", fn))
            if jn:
                self.add_jwt(node, jn, fn, "jose setProtectedHeader")


def scan_js(path, rel):
    lang = "typescript" if path.endswith(".ts") else ("tsx" if path.endswith(".tsx") else "javascript")
    with open(path, "rb") as fh:
        return JsFile(fh.read(), rel, lang).scan()


def scan_go(path, rel):
    with open(path, "rb") as fh:
        return GoFile(fh.read(), rel).scan()


def scan_java(path, rel):
    with open(path, "rb") as fh:
        return JavaFile(fh.read(), rel).scan()
