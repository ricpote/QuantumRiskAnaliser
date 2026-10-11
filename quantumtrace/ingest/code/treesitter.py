"""Go and Java SAST via tree-sitter (tree-sitter-language-pack).

Both scanners build a tiny "IR" per file: imports, constants/variables (per scope),
functions (+ params), calls (+ enclosing function). A small evaluator resolves
identifiers -> constants, function params -> call-site arguments, local helper calls
-> return values. That is enough to infer key sizes / modes / iteration counts that
the sample code hides behind constants (KEY_LEN = 32, exportKey = []byte("...")).
"""
from __future__ import annotations

import os
import re

from ...schema import Finding
from . import jwt_algorithms
from .common import (NOT_CRYPTO_KEY, fake_data, is_keyish, looks_secret, parse_int, sec_body, sec_name, snippet, ssh_algorithm,
                     unquote)

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
        if not isinstance(params.get("key_bits"), (int, type(None))) or isinstance(params.get("key_bits"), bool):
            params = dict(params, key_bits=None)  # a resolved value of the wrong type is "unknown", never a crash
        self.findings.append(Finding(
            source="code", category=category, algorithm=algorithm, params={k: v for k, v in params.items() if v is not None},
            asset=dict(kind="source-file", path=self.rel, language=self.lang),
            location=dict(file=self.rel, line=self.line(node), end_line=node.end_point[0] + 1, column=node.start_point[1] + 1,
                          snippet=snippet(self.text_src, self.line(node)), symbol=func or "<file>"),
            context=dict(api=api, language=self.lang), evidence=evidence, flags=list(flags), confidence=confidence))

    def jwt_unknown(self, node, func, api, why):
        """A JWT library call whose algorithm is chosen at run time: inventoried for review, unless this function
        already reported a JWT algorithm."""
        if any("jwt" in f.flags and f.location.get("symbol") == (func or "<file>") for f in self.findings):
            return
        self.add(node, "signature", "UNKNOWN-JWT", {}, f"{api}: {why}", ["jwt"], confidence=0.5, api=api, func=func)

    def sec_fn(self, fn) -> bool:
        """Does the body of function `fn` handle security values (cookies, sessions, tokens, passwords...)?"""
        return fn in self.funcs and sec_body(self.t(self.funcs[fn][0])) and not fake_data(fn, self.rel)

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
            if isinstance(a, str) and isinstance(b, str) and op == "+":
                return a + b
            if isinstance(a, int) and isinstance(b, int):
                return {"*": a * b, "+": a + b, "-": a - b, "/": a // b if b else None, "<<": a << b,
                        ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b, "==": a == b, "!=": a != b}.get(op)
            return None
        if ty == "unary_expression" and n.named_children:  # {118, 111, -70}: negative byte literals
            v = self.value(n.named_children[-1], func, depth + 1)
            op = self.t(n.children[0])
            return -v if isinstance(v, int) and op == "-" else (v if isinstance(v, int) and op == "+" else None)
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
                    if c["name"] == func and idx < len(c["args"]) and self.calls_local(c, func):
                        v = self.value(c["args"][idx], c["func"], depth + 1)
                        if v is not None:
                            if c["args"][idx].type != "identifier":  # literal written at the call site: derive("hunter2"...) in main()
                                self._trace.append((c["func"], name))
                            return v
        return None

    def calls_local(self, c, func) -> bool:
        """Can call `c` reach the function `func` defined in this file? go(x) / this.go(x) yes; jwt.sign(...) on an
        imported module never reaches a local sign(). Languages refine this (Java: the receiver's class)."""
        return c["obj"] in (None, "this") or (c.get("pkg") is None and c.get("mod") is None and c["obj"].split(".")[0] not in self.imports)

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
        related = []
        if alg == "HMAC" and key is not None:
            kb = self.nbytes(self.value(*key))
            params["key_bits"] = kb * 8 if kb else None
            if self.is_literal(*key):
                flags.append("hardcoded-key")
                related = [self.line(self.consts[k]) for k in self._trace if k in self.consts and self.consts[k] is not None][:1]
        self.add(node, category, alg, params, f"{api} ({jn})", flags, api=api, func=func)
        if related:
            self.findings[-1].location["related_lines"] = related

    def hardcoded_keys(self):
        for (fn, name), vnode in self.consts.items():
            if not is_keyish(name):
                continue
            v = self.value(vnode, fn)
            if looks_secret(v):
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
    "crypto/sha3": {"Sum224": "SHA3-224", "New224": "SHA3-224", "Sum256": "SHA3-256", "Sum384": "SHA3-384", "Sum512": "SHA3-512", "New256": "SHA3-256", "New384": "SHA3-384", "New512": "SHA3-512"},
    "golang.org/x/crypto/sha3": {"Sum224": "SHA3-224", "New224": "SHA3-224", "Sum256": "SHA3-256", "Sum384": "SHA3-384", "Sum512": "SHA3-512",
                                 "New256": "SHA3-256", "New384": "SHA3-384", "New512": "SHA3-512"},
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
GO_IV_SINKS = {"NewCBCEncrypter", "NewCFBEncrypter", "NewOFB", "NewCTR"}  # cipher.X(block, iv); the Decrypters are not sinks
# crypto/tls.InsecureCipherSuites() (besides the RC4 / 3DES / RSA-kex ones the generic suite check already reports)
GO_INSECURE_SUITES = {"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA256",
                      "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}
# calls whose argument is key / seed material: math/rand reaching them is a predictable key
GO_KEY_SINKS = {("crypto/ed25519", "NewKeyFromSeed"), ("crypto/aes", "NewCipher"), ("crypto/hmac", "New"), ("crypto/des", "NewCipher"),
                ("crypto/des", "NewTripleDESCipher"), ("crypto/rc4", "NewCipher")}
GO_BUILTINS = {"len", "cap", "append", "copy", "make", "new", "panic", "print", "println", "string", "byte", "int", "delete", "close"}


class _Buf:
    """A byte buffer while simulating one Go function: which of its bytes hold random data at this point.
    known=False: the content comes from somewhere we cannot see (a file, the network, a helper that returns random bytes)."""

    def __init__(self, size=None, known=True):
        self.size, self.known, self.rnd, self.all, self.dirty = size, known, set(), False, False
        self.weak = False  # filled from math/rand: unpredictable-looking, but predictable

    def fill(self, lo, hi):
        """rand.Read(buf[lo:hi]); hi None = to the end."""
        if lo == 0 and (hi is None or hi == self.size):
            self.all, self.dirty, self.rnd = True, False, set()
        elif isinstance(lo, int) and (isinstance(hi, int) or self.size is not None):
            self.rnd |= set(range(lo, hi if hi is not None else self.size))

    def write(self, i):
        """buf[i] = constant (i None: an index we cannot resolve)."""
        if self.all and self.size is not None:
            self.all, self.rnd = False, set(range(self.size))
        if isinstance(i, int) and not self.all:
            self.rnd.discard(i)
        else:
            self.dirty = True

    def fixed(self, lo, hi) -> bool:
        if not self.known:
            return False
        if self.dirty:
            return True
        if self.all:
            return False
        if self.size is None or self.size == 0:
            return True  # never (fully) filled, or empty
        lo, hi = (lo, hi if hi is not None else self.size) if isinstance(lo, int) else (0, self.size)
        return any(b not in self.rnd for b in range(lo, hi))


class GoFile(TSFile):
    lang = "go"

    def __init__(self, src: bytes, rel: str):
        self.assigns = {}  # (func, name) -> every value assigned to it, in source order
        super().__init__(src, rel)

    def _index(self, root, func):
        for n in self.walk(root):
            ty = n.type
            if ty == "import_spec":
                path = unquote(self.t(n.child_by_field_name("path")))
                alias = n.child_by_field_name("name")
                segs = path.split("/")
                default = segs[-2] if len(segs) > 1 and re.fullmatch(r"v\d+", segs[-1]) else segs[-1]  # .../jwt/v5 -> jwt
                default = re.sub(r"^go-|[-.]go$", "", default)  # .../jwt-go -> jwt, .../go-jose -> jose (Go package naming)
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
                        self.assigns.setdefault((fn, self.t(nm)), []).append(vals[i])
            elif ty == "short_var_declaration" or (ty == "assignment_statement" and self.t(n.children[1]) == "="):
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None and right is not None:
                    ls, rs = left.named_children, right.named_children
                    for i, l in enumerate(ls):
                        if l.type == "identifier" and i < len(rs):
                            self.consts.setdefault((fn, self.t(l)), rs[i])
                            self.assigns.setdefault((fn, self.t(l)), []).append(rs[i])
                        elif l.type == "identifier" and len(rs) == 1:  # block, err := aes.NewCipher(key)
                            self.consts.setdefault((fn, self.t(l)), rs[0] if i == 0 else None)
                            self.assigns.setdefault((fn, self.t(l)), []).append(rs[0] if i == 0 else None)
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
        key_fns = {c["func"] for c in self.calls if (c["pkg"], c["name"]) in GO_KEY_SINKS}
        rsa_bits = None
        for c in self.calls:
            if c["pkg"] == "crypto/rsa" and c["name"] == "GenerateKey" and len(c["args"]) > 1:
                rsa_bits = self.value(c["args"][1], c["func"])
        for c in self.calls:
            pkg, name, args, fn, node = c["pkg"], c["name"], c["args"], c["func"], c["node"]
            fl = (fn or "").lower()
            sec = (sec_name(fn) or self.sec_fn(fn) or fn in key_fns) and not fake_data(fn, self.rel)  # the function builds key material
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
                    bits = self.int_arg(args[1], fn) if len(args) > 1 else rsa_bits  # this call's own size, not the file's last one
                    self.add(node, self.rsa_role(), "RSA", dict(key_bits=bits), f"rsa.GenerateKey(rand, {bits})", api=api, func=fn)
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
            elif pkg == "golang.org/x/crypto/chacha20poly1305" and name in ("New", "NewX"):
                self.add(node, "encryption", "ChaCha20-Poly1305", dict(key_bits=256), f"chacha20poly1305.{name}()", api=api, func=fn)
            elif pkg == "golang.org/x/crypto/scrypt" and name == "Key":
                self.add(node, "kdf", "scrypt", {}, "scrypt.Key()", api=api, func=fn)
            elif pkg in GO_MATH_RAND:
                if any(a.type == "call_expression" and (a.child_by_field_name("function") or a).type == "selector_expression"
                       and self.imports.get(self.t(a.child_by_field_name("function").child_by_field_name("operand"))) in GO_MATH_RAND
                       for a in self.ancestors(node)):
                    continue  # rand.New(rand.NewSource(42)): one finding for the outer call
                if sec:
                    self.add(node, "rng", "NON-CSPRNG", dict(api=api), f"{pkg}.{name}() used in security-sensitive function {fn}() (math/rand is NOT crypto/rand)",
                             ["weak-prng"], api=api, func=fn)
            elif pkg == "crypto/rand" and name in ("Read", "Int", "Prime", "Text"):
                self.add(node, "rng", "CSPRNG", dict(api=api), f"crypto/rand.{name}()", api=api, func=fn)
        for fn, (node, h, it) in custom_pbkdf2.items():
            self.add(node, "kdf", "PBKDF2", dict(hash=h, iterations=it),
                     f"hand-rolled PBKDF2 in {fn}(): HMAC-{h} iterated {it} times with XOR accumulation (RFC 8018 F function)",
                     ["custom-implementation"], confidence=0.85, api="custom", func=fn)
        self.static_iv()
        self.tls_configs()
        self.weak_seeds()
        self.ssh_config()
        self.jwt()
        self.hardcoded_keys()
        dead = self.dead_spans()
        for f in self.findings:  # inventoried, but code that never runs is not a live risk
            if any(a <= f.location["line"] <= b for a, b in dead):
                f.flags.append("unreachable")
                f.confidence = min(f.confidence, 0.3)
        return self.findings

    def ssh_config(self):
        """golang.org/x/crypto/ssh: Config{Ciphers: []string{"aes128-cbc"}, KeyExchanges: ..., MACs: ...}."""
        if "golang.org/x/crypto/ssh" not in self.imports.values():
            return
        seen = set()
        for n in self.walk(self.root):
            if n.type == "interpreted_string_literal" and n.parent is not None and n.parent.type in ("literal_element", "literal_value") \
                    and not (n.parent.parent is not None and n.parent.parent.type == "keyed_element"):  # Type: "ssh-rsa" is a label
                v = unquote(self.t(n))
                if v not in seen and ssh_algorithm(v):
                    seen.add(v)
                    cat, alg, params = ssh_algorithm(v)
                    self.add(n, cat, alg, dict(params, ssh_name=v), f"SSH algorithm '{v}' configured (x/crypto/ssh)", confidence=0.8,
                             api="golang.org/x/crypto/ssh", func=self.enclosing(n))

    def int_arg(self, n, fn):
        """A key size: when the variable is assigned on several paths (bits := 0; if x { bits = 1024 } else { bits = n }),
        the smallest non-zero constant any path gives."""
        if n.type == "identifier" and len(self.assigns.get((fn, self.t(n)), [])) > 1:
            if any(v is not None and any(a.type in ("expression_case", "default_case", "type_case") for a in self.ancestors(v))
                   for v in self.assigns[(fn, self.t(n))]):
                return None  # switch alg { case RS256: bits = 2048 ... case ES256: bits = 256 }: one value per case, none is "the" size
            vals = [self.value(v, fn) for v in self.assigns[(fn, self.t(n))] if v is not None]
            vals = [v for v in vals if isinstance(v, int) and not isinstance(v, bool) and v > 0]
            for a in self.ancestors(n):  # if bits >= 2048 { rsa.GenerateKey(r, bits) }: the guard bounds every path
                cond = a.child_by_field_name("condition") if a.type == "if_statement" else None
                m = re.search(rf"\b{re.escape(self.t(n))}\s*(>=?)\s*(\d+)", self.t(cond)) if cond is not None else None
                if m and a.child_by_field_name("consequence") is not None and \
                        a.child_by_field_name("consequence").start_byte <= n.start_byte < a.child_by_field_name("consequence").end_byte:
                    bound = int(m.group(2)) + (m.group(1) == ">")
                    vals = [v for v in vals if v >= bound]
            return min(vals) if vals else None
        return self.value(n, fn)

    def dead_spans(self):
        """Line ranges that never run: `if bits >= 2048 { ... }` with bits := 1024 (each variable assigned once)."""
        out = []
        for n in self.walk(self.root):
            if n.type not in ("if_statement", "expression_case"):
                continue
            cond = n.child_by_field_name("condition") if n.type == "if_statement" else n.child_by_field_name("value")
            if cond is None or n.type == "if_statement" and n.child_by_field_name("initializer") is not None:
                continue
            fn = self.enclosing(n)
            names = [self.t(x) for x in self.walk(cond) if x.type == "identifier"]
            if not names or any(len(self.assigns.get((fn, x), [])) != 1 for x in names):
                continue
            v = self.value(cond.named_children[0] if cond.type == "expression_list" and cond.named_children else cond, fn)
            if v is False:
                body = n.child_by_field_name("consequence") if n.type == "if_statement" else n
                out.append((body.start_point[0] + 1, body.end_point[0] + 1))
            elif v is True and n.type == "if_statement" and n.child_by_field_name("alternative") is not None:
                alt = n.child_by_field_name("alternative")
                out.append((alt.start_point[0] + 1, alt.end_point[0] + 1))
        return out

    def weak_seeds(self):
        """ed25519.NewKeyFromSeed(Guid()) / aes.NewCipher(makeKey()) where the helper draws from math/rand."""
        rand_fns = {c["func"] for c in self.calls if c["pkg"] in GO_MATH_RAND}
        for c in self.calls:
            if (c["pkg"], c["name"]) not in GO_KEY_SINKS:
                continue
            helpers = [self.t(x.child_by_field_name("function")) for a in c["args"] for x in self.walk(a) if x.type == "call_expression"]
            bad = [h for h in helpers if h in rand_fns and h != c["func"]]
            if bad:
                self.add(c["node"], "rng", "NON-CSPRNG", dict(api="math/rand"),
                         f"{c['pkg']}.{c['name']}() gets key material from {bad[0]}(), which uses math/rand (predictable)",
                         ["weak-prng"], api=f"{c['pkg']}.{c['name']}", func=c["func"])
                self.findings[-1].location["related_lines"] = [self.line(self.funcs[bad[0]][0])]

    # ------------------------------------------------------------ fixed IV / nonce (CWE-329)
    def static_iv(self):
        """IV / nonce that is the same on every run: a literal, a constant, or a buffer from make() / var [16]byte that
        crypto/rand never filled completely (or that was overwritten after the fill) when it reaches the cipher.
        Sinks: cipher.NewCBCEncrypter / NewCFBEncrypter / NewOFB / NewCTR and AEAD.Seal; decryption is not a sink."""
        alias = next((a for a, p in self.imports.items() if p == "crypto/cipher"), None)
        if alias is None:
            return
        fvars = {(fn, m.group(1)) for fn, (node, _) in self.funcs.items()  # f = cipher.NewCTR; f(block, iv)
                 for m in re.finditer(rf"(\w+)\s*:?=\s*{alias}\.(\w+)\b(?!\s*\()", self.t(node)) if m.group(2) in GO_IV_SINKS}
        for c in self.calls:
            name, args, fn, node = c["name"], c["args"], c["func"], c["node"]
            if fn not in self.funcs or len(args) < 2 or not (
                    c["pkg"] == "crypto/cipher" and name in GO_IV_SINKS or c["obj"] and c["pkg"] is None and name == "Seal" and len(args) == 4
                    or c["obj"] is None and (fn, name) in fvars):
                continue
            env = {}
            self._go_sim(fn, node.start_byte, env, 0)
            v = self._go_view(args[1], fn, env, 0)
            if v is not None and not v[0].fixed(v[1], v[2]) and v[0].weak:
                self.add(node, "rng", "NON-CSPRNG", dict(api="math/rand"),
                         f"{'nonce' if name == 'Seal' else 'IV'} passed to {name}() was filled from math/rand: predictable",
                         ["weak-prng"], api=f"cipher.{name}", func=fn)
                continue
            if v is None or not v[0].fixed(v[1], v[2]):
                continue
            what = "nonce" if name == "Seal" else "IV"
            demo = fn == "main"
            self.add(node, "key", "HARDCODED-KEY", dict(name=self.t(args[1])[:40], what=what),
                     f"{what} passed to {name}() is the same on every run: {self.t(args[1])[:60]}",
                     ["static-iv"] + (["demo-code"] if demo else []), confidence=0.6 if demo else 1.0, api=f"cipher.{name}", func=fn)
            src = next((self.consts[k] for k in ((fn, self.t(args[1])), (None, self.t(args[1]))) if k in self.consts), None)
            if args[1].type == "identifier" and src is not None:  # also where the fixed value is written
                self.findings[-1].location["related_lines"] = [self.line(src)]

    def _arr_len(self, typ):
        if typ is not None and typ.type == "array_type" and typ.named_children:
            n = self.value(typ.named_children[0])
            return n if isinstance(n, int) else None
        return None

    def _go_sim(self, fn, stop, env, depth):
        """Run the statements of fn that start before byte offset `stop`: bind names to buffer views, apply random
        fills (rand.Read, io.ReadFull, r.Read, helpers that call them) and constant writes (buf[i] = 0)."""
        fnode = self.funcs[fn][0]
        res = fnode.child_by_field_name("result")
        if res is not None and res.type == "parameter_list":  # named results: func f() (nonce [12]byte)
            for pd in res.named_children:
                typ = pd.child_by_field_name("type")
                for nm in pd.children_by_field_name("name"):
                    env.setdefault(self.t(nm), (_Buf(self._arr_len(typ)), 0, None) if typ is not None and typ.type == "array_type" else None)
        body = fnode.child_by_field_name("body")
        for n in (self.walk(body) if body is not None else ()):
            if n.start_byte >= stop:
                break
            if n.type == "var_spec":
                val, typ = n.child_by_field_name("value"), n.child_by_field_name("type")
                vals = val.named_children if val is not None else []
                for i, nm in enumerate(n.children_by_field_name("name")):
                    env[self.t(nm)] = self._go_view(vals[i], fn, env, depth) if i < len(vals) else (
                        (_Buf(self._arr_len(typ)), 0, None) if typ is not None and typ.type == "array_type" else None)
            elif n.type in ("short_var_declaration", "assignment_statement"):
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is None or right is None:
                    continue
                ls, rs = left.named_children, right.named_children
                views = [self._go_view(r, fn, env, depth) for r in rs] if len(rs) == len(ls) else [None] * len(ls)
                for lhs, v in zip(ls, views):
                    if lhs.type == "identifier" and self.t(lhs) != "_":
                        env[self.t(lhs)] = v
                    elif lhs.type == "index_expression":
                        tv = self._go_view(lhs.child_by_field_name("operand"), fn, env, depth)
                        if tv:
                            i = self.value(lhs.child_by_field_name("index"), fn)
                            tv[0].write(tv[1] + i if isinstance(tv[1], int) and isinstance(i, int) else None)
            elif n.type == "call_expression":
                self._go_fill(n, fn, env, depth)

    def _go_fill(self, call, fn, env, depth):
        f = call.child_by_field_name("function")
        al = call.child_by_field_name("arguments")
        args = [a for a in (al.named_children if al is not None else []) if a.type != "comment"]
        if f is None or not args:
            return
        ft = self.t(f)
        if f.type == "identifier" and ft in self.funcs:  # local helper: it works on the caller's buffers
            if depth < 4:
                sub = {p: self._go_view(a, fn, env, depth + 1) for p, a in zip(self.funcs[ft][1], args)}
                if any(sub.values()):
                    self._go_sim(ft, self.funcs[ft][0].end_byte, sub, depth + 1)
            return
        if ft == "copy" and len(args) == 2:
            src = self._go_view(args[1], fn, env, depth)
            if src is not None and src[0].fixed(src[1], src[2]):
                return
        elif not (ft.split(".")[-1] in ("Read", "ReadFull") or f.type == "identifier" and ft not in GO_BUILTINS):
            return  # fmt.Println(iv), hex.Encode(...): do not change the buffer's content
        v = self._go_view(args[0] if ft == "copy" else args[-1], fn, env, depth)
        if v is not None:
            v[0].fill(v[1], v[2])
            reader = args[0] if ft.endswith("ReadFull") and len(args) > 1 else (f.child_by_field_name("operand") if f.type == "selector_expression" else None)
            v[0].weak = v[0].weak or reader is not None and self._math_rand(reader, fn)

    def _math_rand(self, n, fn) -> bool:
        """Is reader n math/rand (the package, or a rand.New(...) source)?"""
        if self.imports.get(self.t(n)) in GO_MATH_RAND:
            return True
        src = self.consts.get((fn, self.t(n))) if n.type == "identifier" else None
        f = src.child_by_field_name("function") if src is not None and src.type == "call_expression" else None
        return f is not None and f.type == "selector_expression" and self.imports.get(self.t(f.child_by_field_name("operand"))) in GO_MATH_RAND

    def _go_view(self, e, fn, env, depth):
        """-> (buffer, lo, hi) that expression e denotes (hi None = to the end), or None (not a buffer / unknown)."""
        if e is None or depth > 6:
            return None
        t = e.type
        if t == "parenthesized_expression" and e.named_children:
            return self._go_view(e.named_children[0], fn, env, depth)
        if t == "unary_expression" and self.t(e.children[0]) in ("&", "*"):
            return self._go_view(e.child_by_field_name("operand"), fn, env, depth)
        if t == "identifier" and self.t(e) in env:
            return env[self.t(e)]
        if t == "identifier" and (fn not in self.funcs or self.t(e) not in self.funcs[fn][1]) and (None, self.t(e)) in self.consts:
            return self._go_view(self.consts[(None, self.t(e))], None, {}, depth + 1)  # package-level var
        if t == "slice_expression":
            v = self._go_view(e.child_by_field_name("operand"), fn, env, depth)
            if v is None:
                return None
            s, end = e.child_by_field_name("start"), e.child_by_field_name("end")
            a = self.value(s, fn) if s is not None else 0
            c = self.value(end, fn) if end is not None else None
            b, lo, hi = v
            nlo = lo + a if isinstance(lo, int) and isinstance(a, int) else None
            nhi = (lo + c if isinstance(lo, int) and isinstance(c, int) else None) if end is not None else hi
            return b, nlo, nhi
        if t == "composite_literal":  # []byte{1, 2, ...} / [16]byte{...}
            typ, body = e.child_by_field_name("type"), e.child_by_field_name("body")
            elems = body.named_children if body is not None else []
            if typ is not None and "byte" in self.t(typ) and all(
                    isinstance(self.value(x.named_children[0] if x.named_children else x, fn, depth + 1), int) for x in elems):
                return _Buf(self._arr_len(typ) or len(elems)), 0, None
            return None
        if t == "call_expression":
            f = e.child_by_field_name("function")
            al = e.child_by_field_name("arguments")
            args = al.named_children if al is not None else []
            ft = self.t(f)
            if ft == "make" and args and "byte" in self.t(args[0]):
                n = self.value(args[1], fn) if len(args) > 1 else None
                return _Buf(n if isinstance(n, int) else None), 0, None
            if ft == "new" and args and args[0].type == "array_type":
                return _Buf(self._arr_len(args[0])), 0, None
            if f is not None and f.type == "func_literal":  # func() []byte { return []byte("x") }()
                rets = [r.named_children[0] for r in self.walk(f) if r.type == "return_statement" and r.named_children]
                views = [self._go_view(r.named_children[0] if r.type == "expression_list" and r.named_children else r, fn, {}, depth + 1)
                         for r in rets]
                return views[0] if views and all(v is not None and v[0].fixed(v[1], v[2]) for v in views) else None
            if f is not None and f.type == "identifier" and ft in self.funcs and depth < 4:  # helper: its buffer when it returns
                rets = [r for r in self.walk(self.funcs[ft][0]) if r.type == "return_statement" and r.named_children]
                if not rets:
                    return None
                sub = {}
                self._go_sim(ft, rets[-1].start_byte, sub, depth + 1)
                r = rets[-1].named_children[0]
                v = self._go_view(r.named_children[0] if r.type == "expression_list" and r.named_children else r, ft, sub, depth + 1)
                if v is None:
                    return None
                return v if v[0].fixed(v[1], v[2]) else (_Buf(known=False), 0, None)
        v = self.value(e, fn)  # literal, constant, []byte("..."), or what every call site passes for a parameter
        if isinstance(v, (str, bytes)) or isinstance(v, tuple) and v and v[0] == "bytes":
            return _Buf(self.nbytes(v)), 0, None
        return None

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
        literals = {}  # same key -> the tls.Config{...} literal itself
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
                key = (self.enclosing(n), var or id(n), self._decl_block(n, var))
                configs.setdefault(key, {}).update(fields)
                literals.setdefault(key, n)
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
                    configs.setdefault((self.enclosing(n), var, self._decl_block(n, var)), {})[field] = (right.named_children[0], n)
        for key, fields in configs.items():
            fn = key[0]
            if fields:
                before = len(self.findings)
                self._tls_config(fn, fields)
                chosen = {"MinVersion", "MaxVersion", "CipherSuites", "CurvePreferences"} & set(fields)
                if chosen and len(self.findings) == before:
                    # a modern, explicit range (MinVersion: tls.VersionTLS12): nothing weak, still part of the inventory
                    lo = self._tls_version(fields["MinVersion"][0], fn) if "MinVersion" in fields else "TLS 1.2"
                    hi = self._tls_version(fields["MaxVersion"][0], fn) if "MaxVersion" in fields else "TLS 1.3"
                    self.add(fields[sorted(chosen)[0]][1], "protocol", "TLS", dict(version=hi or "TLS 1.3", min_version=lo or "TLS 1.2"),
                             f"tls.Config allows {lo or 'TLS 1.2'} to {hi or 'TLS 1.3'}", api="crypto/tls.Config", func=fn)
            if key in literals and not {"MinVersion", "MaxVersion", "CipherSuites", "CurvePreferences"} & set(fields):
                # nothing chosen: crypto/tls defaults (TLS 1.2-1.3, X25519MLKEM768 offered first since Go 1.24) - inventoried
                self.add(literals[key], "protocol", "TLS", dict(version="TLS 1.3", min_version="TLS 1.2", defaults=True),
                         "tls.Config with crypto/tls defaults: TLS 1.2-1.3; Go >= 1.24 offers the X25519MLKEM768 hybrid first",
                         confidence=0.7, api="crypto/tls.Config", func=fn)

    def _decl_block(self, node, var):
        """The block that declares the `var` node refers to: `config := &tls.Config{}` in two { } blocks are two configs."""
        if not var:
            return None
        for a in self.ancestors(node):
            if a.type not in ("block", "source_file", "expression_case", "default_case", "type_case", "communication_case"):
                continue  # each { } block and each switch case is its own scope
            for x in self.walk(a):
                if x.start_byte > node.start_byte:
                    break
                if x.type in ("short_var_declaration", "var_spec") and next(
                        (b for b in self.ancestors(x) if b.type in ("block", "source_file", "expression_case", "default_case", "type_case",
                                                                     "communication_case")), None) == a:
                    names = x.child_by_field_name("left").named_children if x.type == "short_var_declaration" else x.children_by_field_name("name")
                    if any(self.t(nm) == var for nm in names):
                        return a.start_byte
        return None

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

    def _sel_field(self, n, fn=None):
        """tls.VersionTLS10 -> 'VersionTLS10', also through a variable or constant holding it (MaxVersion: lowMax)."""
        for _ in range(4):
            if n is None or n.type != "identifier":
                break
            n = self.consts.get((fn, self.t(n))) or self.consts.get((None, self.t(n)))
        return self.t(n.child_by_field_name("field")) if n is not None and n.type == "selector_expression" else None

    def _tls_version(self, n, fn):
        """tls.VersionTLS10, a variable holding it, or the raw number (MinVersion: 0x0300) -> 'SSL 3.0' / 'TLS 1.x'."""
        name = self._GO_TLS_VERSIONS.get(self._sel_field(n, fn))
        if name is None:
            v = self.value(n, fn)
            name = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(v) if isinstance(v, int) else None
        return name

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
        vmin = self._tls_version(fields["MinVersion"][0], fn) if "MinVersion" in fields else None
        vmax = self._tls_version(fields["MaxVersion"][0], fn) if "MaxVersion" in fields else None
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
            v = fields["CipherSuites"][0]
            # written here, appended (append(cs, tls.X)), or built in a variable assigned in this function
            texts = [self.t(v)] + ([self.t(x) for x in self.assigns.get((fn, self.t(v)), []) if x is not None] if v.type == "identifier" else [])
            names = list(dict.fromkeys(self._list_fields(v) + re.findall(r"\bTLS_\w+_WITH_\w+", " ".join(texts))))
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
            insecure = [nm for nm in names if nm in GO_INSECURE_SUITES and not re.search(r"RC4|3DES|^TLS_RSA_WITH_", nm)]
            body = self.t(self.funcs[fn][0]) if fn in self.funcs else ""
            if re.search(r"\.ID\b", " ".join(texts)) and "InsecureCipherSuites()" in body:
                insecure.append("tls.InsecureCipherSuites()")
            if insecure:
                self.add(anchor, "encryption", "AES", dict(key_bits=128, mode="CBC"),
                         f"tls.Config CipherSuites: {', '.join(insecure[:3])} - in Go's tls.InsecureCipherSuites() "
                         "(CBC-SHA256 has no Lucky13 countermeasures in crypto/tls)", ["insecure-cipher-suite"], api=api, func=fn)
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
        for n in self.walk(self.root):
            if n.type != "selector_expression" or self.t(n.child_by_field_name("operand")) not in libs:
                continue
            field = self.t(n.child_by_field_name("field"))
            jn = "none" if field == "UnsafeAllowNoneSignatureType" else jwt_algorithms.normalize(field)
            if jn:
                self.add_jwt(n, jn, self.enclosing(n), self.t(n))
        for c in self.calls:
            if c["name"] == "SignedString" and c["args"] and self.is_literal(c["args"][0], c["func"]):
                # token.SignedString([]byte("secret")): the HMAC key is in the source; algorithm from the token's SigningMethodHSxxx
                hs = next((jwt_algorithms.normalize(self.t(x.child_by_field_name("field"))) for x in self.walk(self.funcs[c["func"]][0])
                           if x.type == "selector_expression" and self.t(x.child_by_field_name("field")).startswith("SigningMethodHS")),
                          None) if c["func"] in self.funcs else None
                self.add_jwt(c["node"], hs or "HS256", c["func"], "token.SignedString", (c["args"][0], c["func"]))
            elif c["name"] == "ParseUnverified" and self.imports.get(c["obj"] or "", "") and "jwt" in self.imports.get(c["obj"], "") \
                    or c["name"] == "ParseUnverified" and "jwt.Parser" in (c["obj"] or ""):
                self.add(c["node"], "signature", "NULL", dict(jose="none"), "jwt Parser.ParseUnverified: signature never checked",
                         ["jwt", "signature-not-verified"], api="jwt.ParseUnverified", func=c["func"])
        # jwt.WithValidMethods([]string{"RS256", "PS256"}): the algorithms a parser accepts
        for c in self.calls:
            if c["obj"] in libs and c["name"] == "WithValidMethods":
                for s in (x for a in c["args"] for x in self.walk(a) if x.type in ("interpreted_string_literal", "raw_string_literal")):
                    jn = jwt_algorithms.normalize(unquote(self.t(s)))
                    if jn:
                        self.add_jwt(s, jn, c["func"], f"jwt.WithValidMethods({jn!r})")
        for c in self.calls:
            if c["obj"] in libs and c["name"] in ("Parse", "ParseWithClaims", "ParseSigned", "NewWithClaims", "New"):
                self.jwt_unknown(c["node"], c["func"], f"jwt.{c['name']}", "signing method chosen at run time")

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
J_HASH = {"MD5": "MD5", "MD2": "MD2", "MD4": "MD4", "SHA": "SHA-1", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA-0": "SHA-0", "SHA0": "SHA-0",
          "RIPEMD": "RIPEMD-128", "RIPEMD-128": "RIPEMD-128", "RIPEMD128": "RIPEMD-128", "RIPEMD160": "RIPEMD-160", "RIPEMD-160": "RIPEMD-160",
          "HAVAL-128": "HAVAL-128", "HMAC-MD5": "MD5", "HMACMD5": "MD5", "HMACRIPEMD160": "RIPEMD-160", "SHA224": "SHA-224",
          "SHA3-224": "SHA3-224", "SHA-224": "SHA-224", "SHA-256": "SHA-256",
          "SHA-384": "SHA-384", "SHA-512": "SHA-512", "SHA-512/256": "SHA-512/256", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
          "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}
J_CIPHER = {"AES": "AES", "AES_128": "AES", "AES_256": "AES", "DESEDE": "3DES", "TRIPLEDES": "3DES", "DES": "DES", "RC4": "RC4", "ARCFOUR": "RC4",
            "BLOWFISH": "Blowfish", "CHACHA20-POLY1305": "ChaCha20-Poly1305", "CHACHA20": "ChaCha20-Poly1305", "RSA": "RSA", "RC2": "RC2",
            "ARC2": "RC2", "ARC4": "RC4", "DESEDEWRAP": "3DES", "DESWRAP": "DES", "CAST5": "CAST5", "IDEA": "IDEA", "AESWRAP": "AES"}
# Spring Security password encoders built on a fast digest (deprecated / removed in Spring Security 5+)
# Apache Shiro: new Md5Hash(password, salt) / new AesCipherService()
SHIRO_HASHES = {"Md2Hash": "MD2", "Md5Hash": "MD5", "Sha1Hash": "SHA-1", "Sha256Hash": "SHA-256", "Sha384Hash": "SHA-384", "Sha512Hash": "SHA-512"}
SHIRO_CIPHERS = {"AesCipherService": "AES", "BlowfishCipherService": "Blowfish"}
# constants that hold an algorithm name used indirectly: ALGORITHM_NAME = "MD5", TRANSFORMATION = "AES/ECB/PKCS5Padding"
J_ALG_CONST = re.compile(r"(?:^|_)(ALGORITHM|ALGO|ALG|DIGEST|HASH_ALGORITHM|CIPHER|TRANSFORMATION)(?:_|$)")
J_ENCODED_LITERAL = re.compile(r'^[\w.()]*(?:Base64|Hex|DatatypeConverter)[\w.()]*\.(?:decode|decodeBase64|decodeHex|parseBase64Binary|parseHexBinary)\w*\(\s*"[^"]+"\s*\)$')
J_PASSWORD_ENCODERS = {"Md5PasswordEncoder": "MD5", "Md4PasswordEncoder": "MD4", "ShaPasswordEncoder": "SHA-1", "LdapShaPasswordEncoder": "SHA-1",
                       "MessageDigestPasswordEncoder": "SHA-1", "PlaintextPasswordEncoder": "PLAINTEXT", "NoOpPasswordEncoder": "PLAINTEXT",
                       "StandardPasswordEncoder": "SHA-256"}  # StandardPasswordEncoder: SHA-256 x1024, deprecated by Spring
J_SPRING_ENCODERS = {"BCryptPasswordEncoder": "bcrypt", "Pbkdf2PasswordEncoder": "PBKDF2", "SCryptPasswordEncoder": "scrypt",
                     "Argon2PasswordEncoder": "Argon2"}


def pbe_cipher(name: str):
    """'PBEWithMD5AndDES' / 'PBEWithSHA1AndDESede' / 'PBEWithSHA1AndRC2_40' / 'PBEWithHmacSHA256AndAES_256' -> cipher id."""
    m = re.match(r"PBEWITH(?:HMAC)?\w+?AND(DESEDE|TRIPLEDES|DES|RC2|RC4|AES)", str(name or "").upper())
    return {"DESEDE": "3DES", "TRIPLEDES": "3DES", "DES": "DES", "RC2": "RC2", "RC4": "RC4", "AES": "AES"}[m.group(1)] if m else None


J_KPG = {"RSA": ("RSA", "signature"), "EC": ("ECDSA", "signature"), "ECDSA": ("ECDSA", "signature"), "ED25519": ("Ed25519", "signature"),
         "ED448": ("Ed448", "signature"), "EDDSA": ("Ed25519", "signature"), "DSA": ("DSA", "signature"), "DH": ("DH", "key-exchange"),
         "DIFFIEHELLMAN": ("DH", "key-exchange"), "X25519": ("X25519", "key-exchange"), "X448": ("X448", "key-exchange"), "XDH": ("X25519", "key-exchange"),
         "ML-KEM": ("ML-KEM", "key-exchange"), "ML-KEM-512": ("ML-KEM", "key-exchange"), "ML-KEM-768": ("ML-KEM", "key-exchange"), "ML-KEM-1024": ("ML-KEM", "key-exchange"),
         "ML-DSA": ("ML-DSA", "signature"), "ML-DSA-44": ("ML-DSA", "signature"), "ML-DSA-65": ("ML-DSA", "signature"), "ML-DSA-87": ("ML-DSA", "signature")}
J_CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "nistp256": "P-256", "secp384r1": "P-384", "nistp384": "P-384", "secp521r1": "P-521",
            "nistp521": "P-521", "secp256k1": "secp256k1", "secp224r1": "P-224", "nistp224": "P-224", "secp192r1": "P-192", "prime192v1": "P-192",
            "nistp192": "P-192", "secp112r1": "secp112r1", "secp128r1": "secp128r1", "secp160r1": "secp160r1", "sect163k1": "sect163k1",
            "sect163r2": "sect163r2", "sect233k1": "sect233k1", "sect233r1": "sect233r1"}
J_EC_SIZE = {192: "P-192", 224: "P-224", 256: "P-256", 384: "P-384", 521: "P-521"}  # KeyPairGenerator("EC").initialize(256)


class JavaFile(TSFile):
    lang = "java"

    def __init__(self, src: bytes, rel: str):
        self.fields, self.var_types, self.func_class = set(), {}, {}
        super().__init__(src, rel)

    def calls_local(self, c, func) -> bool:
        return c["obj"] in (None, "this") or self.receiver_class(c) == self.func_class.get(func)

    def scope_of(self, n):
        """Start byte of the enclosing method / constructor / lambda (None at class level)."""
        a = next((a for a in self.ancestors(n) if a.type in ("method_declaration", "constructor_declaration", "lambda_expression")), None)
        return a.start_byte if a is not None else None

    def receiver_class(self, c):
        """Class a call goes to: bc.go() -> declared type of bc; Crypto2.go() -> Crypto2; new Crypto2() -> Crypto2."""
        obj = c["obj"]
        if c["new"]:
            return c["name"].split(".")[-1]
        if obj is None or obj == "this":
            return self.func_class.get(c["name"])
        return self.var_types.get((c["func"], obj)) or self.var_types.get((None, obj)) or (obj if obj[:1].isupper() else None)

    def _index(self, root, func):
        for n in self.walk(root):
            if n.type == "import_declaration":
                fq = self.t(n).replace("import", "").replace("static", "").replace(";", "").strip()
                self.imports[fq.split(".")[-1]] = fq
            elif n.type in ("field_declaration", "local_variable_declaration"):
                names = [self.t(d.child_by_field_name("name")) for d in n.named_children if d.type == "variable_declarator"]
                if n.type == "field_declaration":
                    self.fields.update(names)
                ty = self.t(n.child_by_field_name("type")).split("<")[0].split(".")[-1]
                for nm in names:
                    self.var_types[(self.enclosing(n) if n.type == "local_variable_declaration" else None, nm)] = ty
            elif n.type in ("method_declaration", "constructor_declaration"):
                name = self.t(n.child_by_field_name("name"))
                params = []
                fp = n.child_by_field_name("parameters")
                for p in (fp.named_children if fp is not None else []):
                    nm = p.child_by_field_name("name")
                    if nm is not None:
                        params.append(self.t(nm))
                        self.var_types[(name, self.t(nm))] = self.t(p.child_by_field_name("type")).split("<")[0].split(".")[-1]
                self.funcs[name] = (n, params)
                cls = next((a for a in self.ancestors(n) if a.type in ("class_declaration", "enum_declaration")), None)
                self.func_class[name] = self.t(cls.child_by_field_name("name")) if cls is not None else None
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
                elif l is not None and r is not None and l.type == "field_access" and self.t(l.child_by_field_name("object")) == "this":
                    self.consts.setdefault((fn, self.t(l)), r)  # this.transformation = transformation: kept apart from the parameter
            elif n.type == "method_invocation":
                obj = n.child_by_field_name("object")
                args = n.child_by_field_name("arguments")
                o = self.t(obj) if obj is not None else None
                if o and "." in o and o.rsplit(".", 1)[1][:1].isupper():  # javax.crypto.Cipher.getInstance -> Cipher
                    o = o.rsplit(".", 1)[1]
                self.calls.append(dict(node=n, obj=o, name=self.t(n.child_by_field_name("name")),
                                       args=args.named_children if args is not None else [], func=fn, new=False, scope=self.scope_of(n)))
            elif n.type == "explicit_constructor_invocation" and self.t(n.child_by_field_name("constructor")) == "this":
                args = n.child_by_field_name("arguments")
                cls = next((a for a in self.ancestors(n) if a.type in ("class_declaration", "enum_declaration")), None)
                self.calls.append(dict(node=n, obj="new", name=self.t(cls.child_by_field_name("name")) if cls is not None else "",
                                       args=args.named_children if args is not None else [], func=fn, new=True, scope=self.scope_of(n)))
            elif n.type == "object_creation_expression":
                args = n.child_by_field_name("arguments")
                self.calls.append(dict(node=n, obj="new", name=self.t(n.child_by_field_name("type")),
                                       args=args.named_children if args is not None else [], func=fn, new=True, scope=self.scope_of(n)))

    def enclosing(self, n):
        for a in self.ancestors(n):
            if a.type in ("method_declaration", "constructor_declaration"):
                return self.t(a.child_by_field_name("name"))
        return None

    def value_special(self, n, func, depth):
        if n.type in ("method_invocation", "object_creation_expression") and (
                self.t(n.child_by_field_name("name")) == "valueOf" and self.t(n.child_by_field_name("object")) == "String"
                or self.t(n.child_by_field_name("type")) == "String"):  # String.valueOf(chars) / new String(chars)
            a = n.child_by_field_name("arguments").named_children
            return self.value(a[0], func, depth + 1) if a else None
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) in ("getBytes", "toCharArray"):
            v = self.value(n.child_by_field_name("object"), func, depth + 1)
            if not isinstance(v, str):
                return None
            return v.encode() if self.t(n.child_by_field_name("name")) == "getBytes" else v  # char[] is text
        if n.type == "array_creation_expression":
            dims = [c for c in n.named_children if c.type == "dimensions_expr"]
            if dims and dims[0].named_children:
                k = self.value(dims[0].named_children[0], func, depth + 1)
                return ("bytes", k) if isinstance(k, int) else None
            init = [c for c in n.named_children if c.type == "array_initializer"]
            if init:
                return self.value(init[0], func, depth + 1)
        if n.type == "array_initializer":  # {20, 10, (byte) 0xa2}: fixed bytes only if every element is a constant
            vals = [self.value(c, func, depth + 1) for c in n.named_children]
            if all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
                return bytes(v & 0xFF for v in vals)
            return ("bytes", len(vals))
        if n.type == "character_literal":  # {'s'}
            c = unquote(self.t(n))
            return ord(c) if len(c) == 1 else None
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) in ("requireNonNull", "notNull", "checkNotNull", "notEmpty", "notBlank"):
            a = n.child_by_field_name("arguments").named_children  # Objects.requireNonNull(x) / Args.notNull(x, "msg") return x
            return self.value(a[0], func, depth + 1) if a else None
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) == "parseInt" and self.t(n.child_by_field_name("object")) == "Integer":
            a = n.child_by_field_name("arguments").named_children
            v = self.value(a[0], func, depth + 1) if a else None
            return int(v) if isinstance(v, str) and v.strip().lstrip("-").isdigit() else (v if isinstance(v, int) else None)
        if n.type == "cast_expression":  # (byte) 0xa2
            return self.value(n.child_by_field_name("value"), func, depth + 1)
        if n.type == "field_access":
            obj, field = self.t(n.child_by_field_name("object")).split(".")[-1], self.t(n.child_by_field_name("field"))
            if obj[:1].isupper() and obj in self.project_classes:  # CryptoConstants.ALGORITHM in another file
                v = self.class_constant(obj, field, depth)
                if v is not None:
                    return v
            return self.resolve_name(field, func, depth)
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) == "getProperty":
            # props.getProperty("hashAlg1", "SHA512"): the project's .properties files win over the default
            args = n.child_by_field_name("arguments").named_children
            key = self.value(args[0], func, depth + 1) if args else None
            if isinstance(key, str) and key in self.props:
                return self.props[key]
            return self.value(args[1], func, depth + 1) if len(args) > 1 else None
        if n.type == "method_invocation" and n.child_by_field_name("object") is None:
            return self.call_return(self.t(n.child_by_field_name("name")), depth)
        return None

    props: dict = {}

    project_calls: dict = {}
    project_classes: dict = {}

    def call_return(self, fname, depth):
        """Value returned by a local helper, flow-sensitive: `iv = "111".getBytes(); iv = generateSeed(16); return iv` is
        random; `return new byte[12]` is zeros. If any return may be non-fixed, the result is unknown."""
        if fname not in self.funcs or depth > 6:
            return None
        node, _ = self.funcs[fname]
        vals = []
        for r in self.walk(node):
            if r.type != "return_statement" or not r.named_children:
                continue
            e = r.named_children[0]
            if e.type == "identifier":
                v = self.current_value(e, fname)
            elif e.type == "array_creation_expression" and not any(c.type == "array_initializer" for c in e.named_children):
                v = b"\0"
            else:
                v = self.value(e, fname, depth + 1)
            vals.append(v)
        return vals[0] if vals and all(v is not None for v in vals) else None

    def class_constant(self, cls, field, depth):
        """CryptoConstants.ALGORITHM / `import static ...CryptoConstants.ALGORITHM`: the constant in that class's file."""
        other = self.project_classes.get(cls)
        if other is None or other is self or depth > 6:
            return None
        node = other.consts.get((None, field))
        if node is not None and node.type == "array_creation_expression" and not any(c.type == "array_initializer" for c in node.named_children):
            return b"\0"  # static final byte[] ZERO_IV = new byte[16]: zeros
        return other.value(node, None, depth + 1) if node is not None else None

    def resolve_name(self, name, func, depth):
        v = super().resolve_name(name, func, depth)
        if v is None and func in self.funcs and name in self.funcs[func][1] and depth < 4:
            idx = self.funcs[func][1].index(name)
            for other, c in self.project_calls.get(func, []):  # bc.go(crypto) in another class of the project
                if other is not self and idx < len(c["args"]) and other.receiver_class(c) == self.func_class.get(func):
                    v = other.value(c["args"][idx], c["func"], depth + 1)
                    if v is not None:
                        if c["args"][idx].type != "identifier":
                            self._trace.append((c["func"], name))
                        return v
        imp = self.imports.get(name, "")
        if v is None and imp.endswith("." + name) and imp.count(".") >= 2:  # import static pkg.Class.NAME
            v = self.class_constant(imp.split(".")[-2], name, depth)
        if v is None and name in self.fields and (func, name) not in self.var_types:  # a local / parameter shadows the field
            # Crypto2(String defAlgo) { defaultAlgo = defAlgo; } ... getInstance(defaultAlgo)
            for (fn, n), node in self.consts.items():
                if n in (name, f"this.{name}") and fn not in (func, None) and (n != name or (fn, name) not in self.var_types):
                    v = self.value(node, fn, depth + 1)
                    if v is not None:
                        return v
        return v

    DIGEST_UTILS = {"md2": "MD2", "md5": "MD5", "sha": "SHA-1", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
                    "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
                    "sha512_256": "SHA-512/256"}
    GUAVA_HASHING = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}

    def digest_utils(self, c):
        """Apache commons-codec / Spring DigestUtils: md5Hex, getMd5Digest, sha1, md5DigestAsHex, getSha3_224Digest,
        getDigest("SHA-1"), new DigestUtils(SHA_224 | "MD5") -> hash name."""
        if c["new"] or c["name"] == "getDigest":
            arg = c["args"][0] if c["args"] else None
            v = self.value(arg, c["func"]) if arg is not None else None
            key = v if isinstance(v, str) else (self.t(arg).split(".")[-1] if arg is not None else "")
            return J_HASH.get(key.upper().replace("_", "-"), J_HASH.get(key.upper().replace("_", "")))
        m = re.match(r"(?:get|append)?(md2|md5|sha3_(?:224|256|384|512)|sha512_256|sha(?:1|224|256|384|512)?)(?![0-9_])", c["name"].lower())
        return self.DIGEST_UTILS.get(m.group(1)) if m else None

    def str_arg(self, c, i=0):
        """Argument value at the call: for a local variable, its LAST assignment before the call (algo = "DES"; algo = "AES")."""
        if len(c["args"]) <= i:
            return None
        a = c["args"][i]
        return self.current_value(a, c["func"]) if a.type == "identifier" else self.value(a, c["func"])

    def overwritten_before_use(self, call_node, fn) -> bool:
        """`c = Cipher.getInstance("DES"); if (choice > 1) c = Cipher.getInstance("AES");` with choice always > 1:
        the first instance is replaced before any use, so it is never used."""
        var = self.var_of(call_node)
        stmt = next((a for a in self.ancestors(call_node) if a.type in ("local_variable_declaration", "expression_statement")), None)
        if not var or stmt is None or stmt.parent is None:
            return False
        sibs = stmt.parent.named_children
        assign = re.compile(rf"\s*\{{?\s*{re.escape(var)}\s*=[^=]")
        for s in sibs[sibs.index(stmt) + 1:]:
            if s.type == "if_statement" and s.child_by_field_name("alternative") is None:
                cons = s.child_by_field_name("consequence")
                if assign.match(self.t(cons)) and self.value(s.child_by_field_name("condition"), fn) is True:
                    return True
            elif assign.match(self.t(s)):
                return True
            if re.search(rf"\b{re.escape(var)}\b", self.t(s)):
                return False
        return False

    def initializers(self, c, method="initialize"):
        """[(initialize call node, size or curve name, line of the ECGenParameterSpec it uses)] for this getInstance call:
        `kpg.initialize(2048)` in the same method, or chained `KeyPairGenerator.getInstance("RSA").initialize(1024)`."""
        p = c["node"].parent
        chained = p if p is not None and p.type == "method_invocation" and self.t(p.child_by_field_name("name")) == method else None
        var = self.var_of(c["node"])
        calls = [chained] if chained is not None else [
            d["node"] for d in self.calls if var and d["obj"] == var and d["scope"] == c["scope"] and d["name"] == method and self.owns(c, d)]
        out = []
        for n in calls:
            args = n.child_by_field_name("arguments").named_children
            if not args:
                continue
            a0, spec_line = args[0], None
            if a0.type == "identifier":
                key = next(((s, self.t(a0)) for s in (c["func"], None) if (s, self.t(a0)) in self.consts), None)
                if key and self.consts[key].type == "object_creation_expression":
                    spec_line = self.line(self.consts[key])
                    a0 = self.consts[key]
            if a0.type == "object_creation_expression":  # new ECGenParameterSpec("secp256r1") / new RSAKeyGenParameterSpec(2048, e)
                inner = a0.child_by_field_name("arguments").named_children
                v = self.value(inner[0], c["func"]) if inner else None
            else:
                v = self.value(a0, c["func"])
            out.append((n, v, spec_line))
        return out

    def shiro(self, cls) -> bool:
        return self.imports.get(cls, "").startswith("org.apache.shiro") or "org/apache/shiro/" in self.rel.replace("\\", "/")

    def algorithm_constants(self):
        """static final String ALGORITHM_NAME = "MD5": an algorithm chosen in a constant and used indirectly (passed to a
        superclass, a factory, reflection). Inventoried at lower confidence when the file reports nothing else for it."""
        reported = {f.algorithm for f in self.findings}
        for (fn, name), v in list(self.consts.items()):
            if fn is not None or v is None or not J_ALG_CONST.search(name) or re.search(r"KEY|PARAM|PROPERTY|HEADER", name) \
                    or name in getattr(self, "alg_args", ()):  # passed to a getInstance(...): reported there
                continue
            val = self.value(v, None)
            if not isinstance(val, str):
                continue
            u = val.upper()
            h = J_HASH.get(u, J_HASH.get(u.replace("SHA", "SHA-")) if re.fullmatch(r"SHA\d+", u) else None)
            base = J_CIPHER.get(u.split("/")[0])
            mode = u.split("/")[1] if u.count("/") == 2 else None
            if h and h not in reported:
                self.add(v, "hash", h, {}, f'algorithm name in constant {name} = "{val}"', confidence=0.6, api="constant")
            elif base and base not in reported and base != "RSA":
                self.add(v, "encryption", base, dict(mode=mode), f'algorithm name in constant {name} = "{val}"',
                         ["ecb-mode"] if mode == "ECB" else [], confidence=0.6, api="constant")

    def owns(self, c, d):
        """Is getInstance call c the instance that call d (kpg.initialize(...)) acts on? The latest assignment of the
        variable before d whose declaration block encloses d: `kpg` re-assigned, or the same name in two { } blocks."""
        var = self.var_of(c["node"])
        best = None
        for e in self.calls:
            if e["name"] == "getInstance" and e["scope"] == d["scope"] and e["node"].start_byte < d["node"].start_byte \
                    and self.var_of(e["node"]) == var and self._visible(e["node"], d["node"]):
                if best is None or e["node"].start_byte > best["node"].start_byte:
                    best = e
        return best is c

    def _visible(self, decl, use) -> bool:
        p = decl.parent
        if p is None or p.type != "variable_declarator":
            return True  # plain assignment: the variable was declared elsewhere
        block = next((a for a in self.ancestors(p) if a.type in ("block", "constructor_body", "switch_block_statement_group")), None)
        return block is None or block.start_byte <= use.start_byte < block.end_byte

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
        kpg_at = {}  # KeyPairGenerator.getInstance call -> size given to ITS initialize()
        kpg_lines = {}  # KeyGenerator / KeyPairGenerator getInstance (line, col) -> lines of its init/initialize calls
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
                    if d["obj"] == var and d["scope"] == c["scope"] and d["name"] in ("init", "initialize") and d["args"] and self.owns(c, d):
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
                            kpg_at[c["node"].start_byte] = v
                        kpg_lines.setdefault((self.line(c["node"]), c["node"].start_point[1] + 1), []).append(self.line(d["node"]))
        for node, alg, bits, fn in keygens:
            self.add(node, "key", alg, dict(key_bits=bits), f'KeyGenerator.getInstance("{alg}").init({bits}): generates {alg}-{bits} keys'
                     if bits else f'KeyGenerator.getInstance("{alg}") generates {alg} keys', api="KeyGenerator", func=fn)
        sig_algs = [str(self.str_arg(c) or "") for c in self.calls if c["obj"] == "Signature" and c["name"] == "getInstance"]
        dead = set()  # (line, column) of instances replaced before any use
        for c in self.calls:
            obj, name, fn, node = c["obj"], c["name"], c["func"], c["node"]
            fl = (fn or "").lower()
            sec = (sec_name(fn) or self.sec_fn(fn)) and not fake_data(fn, self.rel)
            if name == "getInstance" and obj in ("Cipher", "MessageDigest", "Mac", "Signature") and self.overwritten_before_use(node, fn):
                dead.add((self.line(node), node.start_point[1] + 1))
            if name == "getInstance" and obj == "MessageDigest":
                a = str(self.str_arg(c) or "")
                flags = ["password-hashing", "unsalted"] if "password" in fl else []
                h = J_HASH.get(a.upper(), J_HASH.get(a, a)) if a else "UNKNOWN-HASH"  # name from a parameter / config: inventoried, not judged
                self.add(node, "hash", h, {}, f'MessageDigest.getInstance("{a}")' if a else "MessageDigest.getInstance(<not resolved>)", flags,
                         confidence=1.0 if a else 0.3, api="MessageDigest", func=fn)
            elif name == "getInstance" and obj == "Cipher":
                tr = str(self.str_arg(c) or "")
                parts = tr.split("/")
                alg = J_CIPHER.get(parts[0].upper(), parts[0]) if tr else "UNKNOWN-CIPHER"
                pbe = pbe_cipher(parts[0])
                if pbe:  # PBEWithMD5AndDES: DES keyed from a password through MD5
                    alg = pbe
                mode = parts[1].upper() if len(parts) > 1 else None
                pad = parts[2] if len(parts) > 2 else None
                flags = []
                if alg == "RSA":
                    padding = "OAEP" if pad and "OAEP" in pad.upper() else ("none" if pad and pad.upper() == "NOPADDING" else "PKCS1v15")
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
            elif name == "getInstance" and obj == "KeyGenerator":
                # a DES / RC4 / HmacMD5 key generated here; skipped when a Cipher/Mac in the same method already reports it
                a = str(self.str_arg(c) or "").upper()
                base = J_CIPHER.get(a.split("/")[0])
                same = [d for d in self.calls if d["func"] == fn and d["obj"] in ("Cipher", "Mac") and d["name"] == "getInstance"]
                if base and base not in ("AES", "RSA") and not any(J_CIPHER.get(str(self.str_arg(d) or "").upper().split("/")[0]) == base for d in same):
                    self.add(node, "encryption", base, {}, f'KeyGenerator.getInstance("{a}")', api="KeyGenerator", func=fn)
                elif a.startswith("HMAC") and not same:
                    h = a.replace("HMAC", "")
                    self.add(node, "mac", "HMAC", dict(hash=J_HASH.get(h, J_HASH.get(h.replace("SHA", "SHA-"), h))), f'KeyGenerator.getInstance("{a}")', api="KeyGenerator", func=fn)
            elif obj == "Hashing" and self.imports.get("Hashing", "com.google.common.hash.Hashing").startswith("com.google") \
                    and re.sub(r"^hmac", "", name.lower()) in self.GUAVA_HASHING:  # Guava Hashing.md5() / sha1() / hmacMd5(key)
                h = self.GUAVA_HASHING[re.sub(r"^hmac", "", name.lower())]
                if name.lower().startswith("hmac"):
                    self.add(node, "mac", "HMAC", dict(hash=h), f"Hashing.{name}()", api="Hashing", func=fn)
                else:
                    self.add(node, "hash", h, {}, f"Hashing.{name}()", api="Hashing", func=fn)
            elif name == "getInstance" and obj in ("KeyFactory", "AlgorithmParameters", "AlgorithmParameterGenerator"):
                a = str(self.str_arg(c) or "").upper()
                if a in J_KPG:  # DSA / RSA / EC / DH key material handled here
                    alg, cat = J_KPG[a]
                    inits = self.initializers(c, "init") if obj == "AlgorithmParameterGenerator" else []
                    for init, v, _ in inits or [(None, None, None)]:  # AlgorithmParameterGenerator.getInstance("DH").init(1024)
                        params = dict(key_bits=v) if isinstance(v, int) and alg in ("DH", "DSA") else {}
                        self.add(init or node, cat, alg, params, f'{obj}.getInstance("{a}")' + (f" init({v})" if params else ""), api=obj, func=fn)
                        if init is not None:
                            self.findings[-1].location["related_lines"] = [self.line(node)]
            elif (c["new"] or name == "getInstance") and (name if c["new"] else obj).split(".")[-1] in J_PASSWORD_ENCODERS:
                cls = (name if c["new"] else obj).split(".")[-1]
                h = J_PASSWORD_ENCODERS[cls]
                if cls == "MessageDigestPasswordEncoder" and c["args"]:
                    v = self.str_arg(c)
                    h = J_HASH.get(str(v).upper(), "SHA-1") if v else "SHA-1"
                self.add(node, "hash", h, {}, f"{cls}: fast, unsalted digest used to store passwords", ["password-hashing", "unsalted"],
                         api=cls, func=fn)
            elif obj == "DigestUtils" or (c["new"] and name.split(".")[-1] == "DigestUtils") or \
                    (obj is None and self.imports.get(name, "").endswith(f"DigestUtils.{name}")):
                # Apache commons-codec: DigestUtils.md5Hex(x), getSha1Digest(), new DigestUtils(SHA_224)
                h = self.digest_utils(c)
                if h:
                    self.add(node, "hash", h, {}, f"DigestUtils.{name}()" if not c["new"] else "new DigestUtils(...)", api="DigestUtils", func=fn)
            elif c["new"] and name.split(".")[-1] == "SecretKeySpec" and len(c["args"]) > 1:
                a = str(self.str_arg(c, len(c["args"]) - 1) or "").upper()
                base = J_CIPHER.get(a.split("/")[0]) or pbe_cipher(a)
                same = [d for d in self.calls if d["scope"] == c["scope"] and d["obj"] in ("Cipher",) and d["name"] == "getInstance"]
                if base and base not in ("AES", "RSA") and not any(
                        (J_CIPHER.get(str(self.str_arg(d) or "").upper().split("/")[0]) or pbe_cipher(self.str_arg(d))) == base for d in same):
                    self.add(node, "encryption", base, {}, f'SecretKeySpec(key, "{a}")', api="SecretKeySpec", func=fn)
            elif c["new"] and self.shiro(name.split(".")[-1]) and name.split(".")[-1] in SHIRO_HASHES:
                cls = name.split(".")[-1]
                pw = len(c["args"]) >= 2 or bool(c["args"]) and re.search(r"(?i)pass(word|wd)?|pwd", self.t(c["args"][0])) is not None
                # new Md5Hash(password, salt[, iterations]) / new Sha256Hash(password).toHex(): Shiro credential hashing
                self.add(node, "hash", SHIRO_HASHES[cls], {}, f"Shiro new {cls}(...)" + (" (salted credential hash)" if pw else ""),
                         ["password-hashing"] if pw else [], api="shiro", func=fn)
            elif c["new"] and self.shiro("SimpleHash") and name.split(".")[-1] == "SimpleHash" and c["args"]:
                a = str(self.str_arg(c) or "").upper()
                h = J_HASH.get(a, J_HASH.get(a.replace("SHA", "SHA-")))
                if h:
                    self.add(node, "hash", h, {}, f'Shiro new SimpleHash("{a}", ...)', ["password-hashing"] if len(c["args"]) >= 3 else [],
                             api="shiro", func=fn)
            elif c["new"] and self.shiro(name.split(".")[-1]) and name.split(".")[-1] in SHIRO_CIPHERS:
                self.add(node, "encryption", SHIRO_CIPHERS[name.split(".")[-1]], {}, f"Shiro new {name.split('.')[-1]}()", api="shiro", func=fn)
            elif not c["new"] and re.fullmatch(r"set\w*(?:Cipher|Encryption|Signing|Secret|Hmac|Aes)Key", name) and c["args"] \
                    and (self.is_literal(c["args"][0], fn) or J_ENCODED_LITERAL.match(self.t(c["args"][0]))):
                # mgr.setCipherKey(Base64.decode("kPH+bIxk5D2deZiIxcaaaA==")): the key is in the source
                self.add(node, "key", "HARDCODED-KEY", dict(name=name), f"{name}() gets a key literal: {self.t(c['args'][0])[:60]}",
                         ["hardcoded-key"], api=name, func=fn)
            elif c["new"] and name.split(".")[-1] == "NullCipher":
                self.add(node, "encryption", "NULL", {}, "new NullCipher(): 'encrypts' nothing (identity transform)", api="NullCipher", func=fn)
            elif name == "getInstance" and obj == "KeyPairGenerator":
                # one finding per initialize(size): the size is chosen there, and one generator may be initialized twice
                a = str(self.str_arg(c) or "").upper()
                alg, cat = J_KPG.get(a, (a, "key"))
                if alg == "RSA" and not any("RSA" in s.upper() for s in sig_algs):
                    cat = "encryption" if any(str(self.str_arg(d) or "").upper().startswith("RSA") for d in self.calls if d["obj"] == "Cipher") else cat
                inits = self.initializers(c)
                for init, v, spec_line in inits or [(None, None, None)]:
                    params = {}
                    if alg in ("RSA", "DSA", "DH"):
                        params["key_bits"] = v
                    elif alg == "ECDSA" and isinstance(v, str):
                        v = re.sub(r"(?i)^x9\.62\s+", "", v)  # "X9.62 prime192v2": the JCE's ANSI X9.62 names
                        params["curve"] = J_CURVES.get(v.lower(), v)
                    elif alg == "ECDSA" and isinstance(v, int):
                        params["curve"] = J_EC_SIZE.get(v, f"EC-{v}")
                    elif alg in ("ML-KEM", "ML-DSA"):
                        params["parameter_set"] = a if a[-2:].isdigit() else ("ML-KEM-768" if alg == "ML-KEM" else "ML-DSA-65")
                    self.add(init or node, cat, alg, params, f'KeyPairGenerator.getInstance("{a}")' + (f" initialize({v})" if v else ""),
                             api="KeyPairGenerator", func=fn)
                    if init is not None:
                        self.findings[-1].location["related_lines"] = [self.line(node)] + ([spec_line] if spec_line else [])
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
                    if pbe_cipher(u) not in (None, "AES"):
                        self.add(node, "encryption", pbe_cipher(u), {}, f'SecretKeyFactory.getInstance("{a}")', api="SecretKeyFactory", func=fn)
                elif J_CIPHER.get(u) in ("DES", "3DES") and not any(
                        d["func"] == fn and d["obj"] == "Cipher" and J_CIPHER.get(str(self.str_arg(d) or "").upper().split("/")[0]) == J_CIPHER[u]
                        for d in self.calls):
                    self.add(node, "encryption", J_CIPHER[u], {}, f'SecretKeyFactory.getInstance("{a}"): {J_CIPHER[u]} keys', api="SecretKeyFactory", func=fn)
            elif c["new"] and name.split(".")[-1] in J_SPRING_ENCODERS:
                cls = name.split(".")[-1]
                alg = J_SPRING_ENCODERS[cls]
                strength = self.value(c["args"][0], fn) if cls == "BCryptPasswordEncoder" and c["args"] else None
                params = dict(cost=strength if isinstance(strength, int) else 10) if alg == "bcrypt" else {}
                self.add(node, "kdf", alg, params, f"new {cls}()" + (f" strength {params['cost']}" if alg == "bcrypt" else ""),
                         api=cls, func=fn)  # Spring Security password hashing (BCrypt default strength 10)
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
            elif obj in ("RandomStringUtils", "RandomStringUtils.insecure()") and name.startswith("random") and sec \
                    and not any("SecureRandom" in self.t(a) for a in c["args"]):
                # commons-lang3 RandomStringUtils.randomAlphanumeric(): java.util.Random underneath (secure() / secureStrong() are fine)
                self.add(node, "rng", "NON-CSPRNG", dict(api="RandomStringUtils"), f"RandomStringUtils.{name}() in security-sensitive method {fn}()",
                         ["weak-prng"], api="RandomStringUtils", func=fn)
            elif (c["new"] and name == "SecureRandom") or (obj == "SecureRandom" and name in ("getInstanceStrong", "getInstance")):
                self.add(node, "rng", "CSPRNG", dict(api="SecureRandom"), "java.security.SecureRandom", api="SecureRandom", func=fn)
        for f in self.findings:
            if (f.location["line"], f.location["column"]) in dead:  # inventoried (it IS instantiated) but never used for data
                f.flags.append("overwritten-before-use")
                f.confidence = min(f.confidence, 0.4)
        for f in self.findings:  # KeyPairGenerator findings: the initialize(size) line is where the size is chosen
            rel = kpg_lines.get((f.location["line"], f.location["column"]))
            if rel:
                f.location["related_lines"] = rel
        self.jwt()
        self.trust_all()
        self.static_material()
        self.algorithm_constants()
        self.hardcoded_keys()
        return self.findings

    # (receiver class, method) -> index of the password argument
    J_PASSWORD_ARGS = {("KeyStore", "load"): 1, ("KeyStore", "store"): 1, ("KeyStore", "getKey"): 1, ("KeyStore", "setKeyEntry"): 2,
                       ("KeyManagerFactory", "init"): 1}

    def fixed(self, n, fn):
        """-> (is the value fixed in the source, is it only in main()/demo code).

        Fixed: literals, constants, `null`, and a `new byte[n]` that nothing fills before this point (all zeros).
        Not fixed: anything filled by nextBytes / generateSeed / buffer.get(arr) / in.read(arr), passed to any method
        before this point (it may fill it), or replaced on a path that always runs before this point."""
        self._trace = []
        if n.type == "null_literal":
            return True, fn == "main"
        base = n
        if n.type == "method_invocation" and self.t(n.child_by_field_name("name")) in ("toCharArray", "getBytes"):
            base = n.child_by_field_name("object")  # defaultKey.toCharArray()
        if base.type in ("identifier", "field_access"):
            v = self.current_value(base, fn)
        elif base.type == "array_creation_expression" and not any(c.type == "array_initializer" for c in base.named_children):
            v = b"\0"  # new IvParameterSpec(new byte[16]): zeros
        else:
            v = self.value(n, fn)
        fixed = isinstance(v, (str, bytes, int)) and not isinstance(v, bool)
        return fixed, fixed and (fn == "main" or any(scope == "main" for scope, _ in self._trace))

    RANDOM = object()
    _CONTROL = ("if_statement", "while_statement", "for_statement", "enhanced_for_statement", "do_statement", "switch_expression",
                "try_statement", "catch_clause", "lambda_expression")

    def current_value(self, ident, fn):
        """Value of a variable (or `obj.field`) where `ident` is used, from the LAST write before that point in the same
        function: declarations, assignments, rng.nextBytes(var) and any call that receives the array. A write inside a
        branch counts only if that branch also contains the use, or is an `if` whose condition is always true."""
        var = self.t(ident)
        func_node = next((a for a in self.ancestors(ident) if a.type in ("method_declaration", "constructor_declaration", "lambda_expression")), None)
        use = next((a for a in self.ancestors(ident) if a.type in ("local_variable_declaration", "expression_statement", "return_statement")), ident)
        if func_node is None:
            return self.value(ident, fn)

        def reaches(node):  # does `node` always run before the use (or on the same path)?
            for a in self.ancestors(node):
                if a is func_node:
                    return True
                if a.type in self._CONTROL and not (a.start_byte <= use.start_byte < a.end_byte):
                    if a.type != "if_statement" or a.child_by_field_name("alternative") is not None \
                            or self.value(a.child_by_field_name("condition"), fn) is not True:
                        return False
            return True

        writes = []  # (position, value node | RANDOM)
        for a in self.walk(func_node):
            if a.start_byte >= use.start_byte:
                continue
            if a.type == "variable_declarator" and self.t(a.child_by_field_name("name")) == var and a.child_by_field_name("value") is not None:
                writes.append((a.start_byte, a.child_by_field_name("value"), a))
            elif a.type == "assignment_expression" and self.t(a.child_by_field_name("left")) == var:
                rhs = a.child_by_field_name("right")
                if not any(self.t(i) == var for i in self.walk(rhs) if i.type in ("identifier", "field_access")):  # copyOf(var): unchanged
                    writes.append((a.start_byte, rhs, a))
            elif a.type == "method_invocation" and "[]" in (self.var_types.get((fn, var)) or "[]"):  # a String cannot be filled in place
                args = a.child_by_field_name("arguments")
                if args is not None and any(self.t(x) == var for x in args.named_children) \
                        and self.t(a.child_by_field_name("name")) not in ("getInstance", "toCharArray", "getBytes", "valueOf", "copyOf"):
                    writes.append((a.start_byte, self.RANDOM, a))  # nextBytes(var), buf.get(var), in.read(var): may be filled
        writes = [w for w in writes if reaches(w[2])]
        if not writes:
            return self.value(ident, fn)
        _, last, _ = max(writes, key=lambda w: w[0])
        if last is self.RANDOM:
            return None
        if last.type == "array_creation_expression" and not any(c.type == "array_initializer" for c in last.named_children):
            return b"\0"  # new byte[16] never filled: all zeros
        return self.value(last, fn)

    def decrypt_only(self, spec_node, fn) -> bool:
        """Is this IV/parameter spec only ever given to cipher.init(DECRYPT_MODE | UNWRAP_MODE, ...)? A fixed IV is then
        expected: decryption must reuse the IV that came with the ciphertext."""
        def mode_of(init):
            a = init.child_by_field_name("arguments").named_children
            if a and a[0].type == "identifier":  # int opMode = Cipher.DECRYPT_MODE; cipher.init(opMode, ...)
                node = next((v for (f, nm), v in self.consts.items() if nm == self.t(a[0]) and f in (fn, None)), None)
                return self.t(node) if node is not None else self.t(a[0])
            return self.t(a[0]) if a else ""
        parent = spec_node.parent.parent if spec_node.parent is not None else None
        if parent is not None and parent.type == "method_invocation" and self.t(parent.child_by_field_name("name")) == "init":
            return re.search(r"DECRYPT|UNWRAP", mode_of(parent)) is not None
        var = self.var_of(spec_node)
        func_node = next((a for a in self.ancestors(spec_node) if a.type in ("method_declaration", "constructor_declaration")), None)
        if not var or func_node is None:
            return False
        inits = [a for a in self.walk(func_node) if a.type == "method_invocation" and self.t(a.child_by_field_name("name")) == "init"
                 and any(self.t(x) == var for x in a.child_by_field_name("arguments").named_children)]
        return bool(inits) and all(re.search(r"DECRYPT|UNWRAP", mode_of(i)) for i in inits)

    def static_material(self):
        """IV / salt / seed / password / key that never changes (CWE-329/760/336/259/321): the same value on every run."""
        def report(c, arg, what, flag):
            fixed, demo = self.fixed(arg, c["func"])
            if fixed:
                ev = (f"SecureRandom seeded with {self.t(arg)[:50]}: its output, and any key drawn from it, is fully determined by "
                      "that value. Derive keys with PBKDF2 / Argon2, or leave SecureRandom unseeded"
                      if what == "seed" else f"{what} passed to {c['name']}() is fixed in the source: {self.t(arg)[:60]}")
                self.add(c["node"], "key", "HARDCODED-KEY", dict(name=f"{self.t(arg)[:40]}", what=what), ev,
                         [flag] + (["demo-code"] if demo else []), confidence=0.6 if demo else 1.0, func=c["func"])
                key = next(((s, self.t(arg)) for s in (c["func"], None) if (s, self.t(arg)) in self.consts), None) \
                    if arg.type in ("identifier", "field_access") else None
                if key:  # also where the fixed value is written
                    self.findings[-1].location["related_lines"] = [self.line(self.consts[key])]
        has_pbkdf2 = any(c["obj"] == "SecretKeyFactory" for c in self.calls)
        for c in self.calls:
            name, args, fn = c["name"].split(".")[-1], c["args"], c["func"]
            if c["new"] and name == "IvParameterSpec" and args and not self.decrypt_only(c["node"], fn):
                report(c, args[0], "IV", "static-iv")
            elif c["new"] and name == "GCMParameterSpec" and len(args) > 1 and not self.decrypt_only(c["node"], fn):
                report(c, args[1], "IV", "static-iv")
            elif c["new"] and name in ("PBEParameterSpec", "PBEKeySpec"):
                salt_i, count_i = (0, 1) if name == "PBEParameterSpec" else (1, 2)
                if len(args) > salt_i:
                    report(c, args[salt_i], "salt", "static-salt")
                if name == "PBEKeySpec" and args:
                    report(c, args[0], "password", "hardcoded-password")
                it = (self.current_value(args[count_i], fn) if args[count_i].type == "identifier" else self.value(args[count_i], fn)) \
                    if len(args) > count_i else None
                if isinstance(it, int) and (name == "PBEParameterSpec" or not has_pbkdf2):
                    self.add(c["node"], "kdf", "PBKDF2", dict(iterations=it), f"new {name}(..., {it} iterations)", api=name, func=fn)
            elif c["new"] and name == "SecureRandom" and args:
                report(c, args[0], "seed", "constant-seed")
            elif name == "setSeed" and args and self.receiver_class(c) == "SecureRandom":
                report(c, args[0], "seed", "constant-seed")
            elif c["new"] and name == "SecretKeySpec" and args:
                report(c, args[0], "key", "hardcoded-key")
            elif (self.receiver_class(c), name) in self.J_PASSWORD_ARGS:
                i = self.J_PASSWORD_ARGS[(self.receiver_class(c), name)]
                if len(args) > i:
                    report(c, args[i], "password", "hardcoded-password")

    J_JWT_LIBS = ("io.jsonwebtoken", "com.auth0.jwt", "com.nimbusds.jose")

    def trust_all(self):
        """X509TrustManager whose checkServerTrusted() is empty; HostnameVerifier whose verify() only returns true."""
        for n in self.walk(self.root):
            body = n.child_by_field_name("body") if n.type == "method_declaration" else None
            if body is None:
                continue
            name = self.t(n.child_by_field_name("name"))
            stmts = [c for c in body.named_children if c.type not in ("line_comment", "block_comment")]
            if name == "checkServerTrusted" and not stmts:
                what = "X509TrustManager.checkServerTrusted() is empty: every server certificate is accepted"
            elif name == "verify" and "SSLSession" in self.t(n.child_by_field_name("parameters")) and len(stmts) == 1 \
                    and re.fullmatch(r"return\s+true\s*;", self.t(stmts[0])):
                what = "HostnameVerifier.verify() always returns true: any host name is accepted"
            else:
                continue
            self.add(n.child_by_field_name("name"), "authentication", "NO-CERT-VERIFY", dict(api=name), what, ["no-cert-verify"],
                     api=name, func=self.enclosing(n))

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
            elif c["name"] == "compact" and "Jwts.builder()" in (c["obj"] or "") and ".signWith(" not in (c["obj"] or "") \
                    and ".encryptWith(" not in (c["obj"] or ""):
                self.add_jwt(c["node"], "none", c["func"], "Jwts.builder()...compact() without signWith(): unsigned JWT")
        for c in self.calls:
            if c["obj"] == "Jwts" and c["name"] in ("builder", "parser", "parserBuilder") \
                    or c["obj"] == "JWT" and c["name"] in ("create", "require"):
                self.jwt_unknown(c["node"], c["func"], f"{c['obj']}.{c['name']}()", "signing algorithm chosen at run time")


# =============================================================================================== JavaScript / TypeScript
JS_HASH = {"md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha-1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha-256": "SHA-256",
           "sha384": "SHA-384", "sha-384": "SHA-384", "sha512": "SHA-512", "sha-512": "SHA-512", "sha512-256": "SHA-512/256",
           "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512", "ripemd160": "RIPEMD-160", "rmd160": "RIPEMD-160",
           "shake128": "SHAKE128", "shake256": "SHAKE256", "blake2b512": "BLAKE2b", "blake2s256": "BLAKE2s", "md2": "MD2",
           "ripemd": "RIPEMD-128", "ripemd128": "RIPEMD-128", "ripemd-160": "RIPEMD-160", "haval128": "HAVAL-128", "hmacmd5": "MD5",
           "hmacripemd160": "RIPEMD-160", "sha3-224": "SHA3-224", "sha-224": "SHA-224"}
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
JS_JWT_LIBS = ("jsonwebtoken", "jose", "express-jwt", "jwt-simple", "passport-jwt")
# crypto-js: CryptoJS.<X>.encrypt(...), CryptoJS.<H>(msg), CryptoJS.Hmac<H>(msg, key)
CRYPTOJS_CIPHERS = {"AES": "AES", "DES": "DES", "TripleDES": "3DES", "RC4": "RC4", "RC4Drop": "RC4", "Rabbit": "Rabbit",
                    "RabbitLegacy": "Rabbit", "Blowfish": "Blowfish"}
CRYPTOJS_HASHES = {"MD5": "MD5", "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
                   "SHA3": "SHA3-512", "RIPEMD160": "RIPEMD-160"}
# node-forge cipher names: forge.cipher.createCipher('3DES-CBC', key)
FORGE_CIPHERS = {"AES": "AES", "3DES": "3DES", "DES": "DES", "RC2": "RC2"}
# variable / property names that say a random value is a secret (React's `key: Math.random()` is deliberately not one)
JS_SECRET_WORDS = {"pw", "pwd", "pass", "password", "passwd", "secret", "token", "salt", "nonce", "uuid", "uid", "otp", "csrf", "session",
                   "sid", "apikey", "coupon", "voucher", "invite", "activation", "verification"}


def js_secret_name(name: str) -> bool:
    """sessionUid / MY_UID / pw -> True; liquid / keyboard -> False (whole words of the camelCase / snake_case name)."""
    words = [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", name or "")]
    if any(w in JS_SECRET_WORDS for w in words):
        return True
    # aesKey / secretKey / hmacKey yes; a bare `key` (React's key prop), itemKey / rowKey / cacheKey no
    return "key" in words and len(words) > 1 and not set(words) & (NOT_CRYPTO_KEY | {"item", "row", "list", "unique", "render", "react", "node"})


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
        lines = self.text_src.splitlines() or [""]
        self.minified = rel.endswith(".min.js") or max(len(x) for x in lines) > 1000 and len(self.text_src) / len(lines) > 300

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
                req = val.child_by_field_name("object") if val is not None and val.type == "member_expression" else None
                if req is not None and req.type == "call_expression" and self.t(req.child_by_field_name("function")) == "require" \
                        and name.type == "identifier":  # const createHash = require('crypto').createHash
                    rargs = req.child_by_field_name("arguments").named_children
                    self.imports[self.t(name)] = f"{self.module_name(rargs[0]) if rargs else ''}.{self.t(val.child_by_field_name('property'))}"
                elif val is not None and val.type == "call_expression" and self.t(val.child_by_field_name("function")) == "require":
                    args = val.child_by_field_name("arguments").named_children
                    src = self.module_name(args[0]) if args else ""
                    if name.type == "identifier":
                        self.imports[self.t(name)] = src
                    for p in (name.named_children if name.type == "object_pattern" else []):
                        if p.type == "shorthand_property_identifier_pattern":
                            self.imports[self.t(p)] = f"{src}.{self.t(p)}"
                        elif p.type == "pair_pattern":
                            self.imports[self.t(p.child_by_field_name("value"))] = f"{src}.{self.t(p.child_by_field_name('key'))}"
                elif val is not None and val.type == "identifier" and name.type == "object_pattern" and self.t(val) in self.imports:
                    src = self.imports[self.t(val)]  # const { JWK, JWT } = jose
                    for p in name.named_children:
                        if p.type == "shorthand_property_identifier_pattern":
                            self.imports[self.t(p)] = f"{src}.{self.t(p)}"
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
            return imp.rsplit(".", 1)[0] if "." in imp else (imp or None)  # expressJwt(...) where expressJwt = require('express-jwt')
        if re.search(r"\)\s*\.subtle$|^webcrypto\.subtle$", obj):
            return "webcrypto"  # (await getWebcrypto()).subtle.sign(...) / const webcrypto = ...; webcrypto.subtle
        if re.fullmatch(r"(?:(?:window|globalThis|self)\.)?crypto(?:\.webcrypto)?\.subtle|subtle", obj) and \
                (obj != "subtle" or self.imports.get("subtle", "").startswith("crypto")):
            return "webcrypto"  # crypto.subtle / window.crypto.subtle / require('crypto').webcrypto.subtle (not notCrypto.subtle)
        m = re.match(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", obj)
        if m:  # require('crypto').createHash(...)
            return m.group(1).removeprefix("node:")
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
            if re.search(r"(?:randomBytes|getBytesSync|getBytes)$", ft) and args:  # node / forge.random.getBytesSync(16)
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
                    fed = self.chained_input(node)  # createHash('sha256').update(password)
                    pw = "password" in fl or fed is not None and re.search(r"(?i)pass(word|wd)?\b|\bpw|pwd", fed) is not None
                    stored = self.stored_as_password(node, fn)  # digest = md5(x); user.setPassword(digest)
                    pw = pw or stored is not None
                    if pw and self.prehash(node, fn):  # password = sha512(password); bcrypt.hash(password): bcrypt does the work
                        pw = False
                    self.add(node, "hash", h, {}, f"createHash('{arg(0)}')" + (f" over {fed}" if fed and pw else ""),
                             ["password-hashing", "unsalted"] if pw else [], api=api, func=fn)
                    if stored is not None:
                        self.findings[-1].location["related_lines"] = [stored]
                elif name == "createHmac" and isinstance(arg(0), str):
                    kb = self.nbytes(arg(1))
                    flags = ["hardcoded-key"] if len(args) > 1 and self.is_literal(args[1], fn) else []
                    self.add(node, "mac", "HMAC", dict(hash=JS_HASH.get(arg(0).lower(), arg(0).upper()), key_bits=kb * 8 if kb else None),
                             f"createHmac('{arg(0)}', key)", flags, api=api, func=fn)
                elif name in ("createCipheriv", "createDecipheriv") and args and not isinstance(arg(0), str):
                    self.add(node, "encryption", "UNKNOWN-CIPHER", {}, f"{name}(<algorithm chosen at run time>)", confidence=0.5,
                             api=api, func=fn)  # createDecipheriv(this._algorithm, ...): inventoried, not judged
                elif name in ("createCipheriv", "createDecipheriv", "createCipher", "createDecipher") and isinstance(arg(0), str):
                    spec = js_cipher(arg(0))
                    if not spec:
                        continue
                    alg, bits, mode = spec
                    flags = (["ecb-mode"] if mode == "ECB" else []) + (["hardcoded-key"] if len(args) > 1 and self.is_literal(args[1], fn) else [])
                    if name in ("createCipher", "createDecipher"):
                        flags.append("weak-kdf")  # removed in Node 22: key = EVP_BytesToKey(MD5, password), no salt
                    fed = self.chained_input(node)
                    if fed and re.search(r"(?i)pass(word|wd)?\b|\bpw|pwd", fed):
                        flags.append("reversible-password")  # createCipher(..).write(password): stored decryptable
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
                elif name in ("generateKeySync", "generateKey") and isinstance(arg(0), str) and arg(0).lower() in ("hmac", "aes"):
                    bits = self.pval(args[1], "length", fn) if len(args) > 1 else None
                    cat, alg = ("mac", "HMAC") if arg(0).lower() == "hmac" else ("encryption", "AES")
                    self.add(node, cat, alg, dict(key_bits=bits if isinstance(bits, int) else None), f"{name}('{arg(0)}', {{length: {bits}}})",
                             api=api, func=fn)
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
            elif (mod or "").split(".")[0] in JS_JWT_LIBS or (name == "setProtectedHeader" and uses_jose):  # jose: new SignJWT(..).setProtectedHeader({alg})
                self.jwt(c)
            elif c["obj"] == "Math" and name == "random":
                self.math_random(c)
            elif (mod or "").split("/")[0] in ("bcrypt", "bcryptjs") and name in ("hash", "hashSync"):
                # bcrypt.hash(password, 10), or a salt from genSalt(rounds) in the same function
                cost = arg(1) if isinstance(arg(1), int) else next(
                    (self.value(d["args"][0], fn) for d in self.calls if d["func"] == fn and d["name"] in ("genSalt", "genSaltSync")
                     and d["args"] and isinstance(self.value(d["args"][0], fn), int)), None)
                self.add(node, "kdf", "bcrypt", dict(cost=cost), f"bcrypt.{name}(password, {cost if cost is not None else 'cost'})",
                         api=api, func=fn)
            elif (mod or "").startswith("crypto-js") or mod is None and (c["obj"] or "").startswith("CryptoJS."):  # also the browser global
                self.cryptojs(c)
            elif (mod or "").startswith("express-session") and args:  # session({secret: 'keyboard cat'}): HMAC key of the session cookie
                sec = self.prop(args[0], "secret", fn)
                if sec is not None and self.is_literal(sec, fn):
                    kb = self.nbytes(self.value(sec, fn))
                    self.add(sec.parent if sec.parent is not None and sec.parent.type == "pair" else sec, "mac", "HMAC",
                             dict(hash="SHA-256", key_bits=kb * 8 if kb else None), "express-session secret (signs the session cookie) is in the source",
                             ["hardcoded-key"], api="express-session", func=fn)
            elif (mod or "").startswith("node-forge"):
                self.forge(c)
            elif name == "generateKeyPair" and c["obj"] and self.node_rsa(self.node_of(self.ident_node(c), fn)):
                bits = arg(0)  # key = new NodeRSA(); key.generateKeyPair(512, 65537)
                self.add(node, "signature", "RSA", dict(key_bits=bits if isinstance(bits, int) else None), f"NodeRSA.generateKeyPair({bits})",
                         api="node-rsa", func=fn)
        for n in self.walk(self.root):  # new NodeRSA({b: 512})
            if self.node_rsa(n):
                a = n.child_by_field_name("arguments")
                opts = a.named_children[0] if a is not None and a.named_children else None
                bits = self.pval(opts, "b", self.enclosing(n)) if opts is not None and opts.type in ("object", "identifier") else None
                if isinstance(bits, int):
                    self.add(n, "signature", "RSA", dict(key_bits=bits), f"new NodeRSA({{b: {bits}}})", api="node-rsa", func=self.enclosing(n))
        self.jwt_objects()
        self.hardcoded_keys()
        return self.findings

    def chained_input(self, call):
        """createHash('md5').update(x) / .write(x): the text of x."""
        p = call.parent
        if p is not None and p.type == "member_expression" and self.t(p.child_by_field_name("property")) in ("update", "write") \
                and p.parent is not None and p.parent.type == "call_expression":
            a = p.parent.child_by_field_name("arguments")
            return self.t(a.named_children[0]) if a is not None and a.named_children else None
        return None

    def prehash(self, call, fn) -> bool:
        """Is this digest only a pre-hash fed to a slow password hash (bcrypt / argon2 / scrypt / pbkdf2) later on?"""
        var = next((self.t(a.child_by_field_name("name") if a.type == "variable_declarator" else a.child_by_field_name("left"))
                    for a in self.ancestors(call) if a.type in ("variable_declarator", "assignment_expression")), None)
        body = next((a for a in self.ancestors(call) if a.type in ("function_declaration", "function_expression", "function",
                                                                    "arrow_function", "method_definition")), None)
        if not var or body is None:  # exports.hash = async function (...) {...}: anonymous, so use the node itself
            return False
        after = self.src[call.end_byte:body.end_byte].decode("utf-8", errors="replace")
        return re.search(rf"(?i)(bcrypt|argon2?|scrypt|pbkdf2|['\"](?:hash|compare|verify)['\"])[^;]*\b{re.escape(var)}\b", after) is not None

    def stored_as_password(self, call, fn):
        """digest = crypto.createHash('md5').update(x).digest('hex'); user.setPassword(digest) -> line of setPassword."""
        var = None
        for a in self.ancestors(call):
            if a.type == "variable_declarator":
                var = self.t(a.child_by_field_name("name"))
                break
            if a.type == "assignment_expression":
                var = self.t(a.child_by_field_name("left"))
                break
            if a.type in ("statement_block", "program", "expression_statement") and a.type != "expression_statement":
                break
        if not var:
            return None
        for d in self.calls:
            if d["func"] == fn and re.search(r"(?i)password", d["name"] or "") and any(self.t(x) == var for x in d["args"]):
                return self.line(d["node"])
        return None

    def ident_node(self, c):
        o = c["node"].child_by_field_name("function").child_by_field_name("object")
        return o

    def node_rsa(self, n) -> bool:
        if n is None or n.type != "new_expression":
            return False
        ctor = self.t(n.child_by_field_name("constructor"))
        return self.imports.get(ctor, "").startswith("node-rsa")

    def math_random(self, c):
        """Math.random() whose value becomes a secret: in a security function, assigned to a secret-looking name
        (pw, sessionUid, o.password), passed to a secret-looking parameter, or used directly as a key (createHmac(.., Math.random()))."""
        node, fn = c["node"], c["func"]
        if any(a.type in ("jsx_attribute", "jsx_expression") for a in self.ancestors(node)):
            return  # <img src={`...seed=${Math.random()}`}>: a value drawn into the page, not a secret
        fl = (fn or "").lower()
        why, related = None, []
        by_name = sec_name(fn) and not fake_data(fn, self.rel)
        if by_name or self.sec_fn(fn):
            why = f"in security-sensitive function {fn}()"
        target = None
        for a in self.ancestors(node):  # the name the value is stored under
            if a.type == "variable_declarator":
                target = self.t(a.child_by_field_name("name"))
                break
            if a.type == "assignment_expression":
                target = self.t(a.child_by_field_name("left")).split(".")[-1]
                break
            if a.type == "pair":
                target = unquote(self.t(a.child_by_field_name("key")))
                break
            if a.type == "arguments":
                call = a.parent
                f = call.child_by_field_name("function") if call is not None else None
                callee = self.t(f)
                idx = next((i for i, x in enumerate(a.named_children) if x.start_byte <= node.start_byte < x.end_byte), None)
                if callee in self.funcs and idx is not None and idx < len(self.funcs[callee][1]):
                    target = self.funcs[callee][1][idx]  # f(Math.random()) -> function f(secret)
                    related = [self.line(self.funcs[callee][0])]
                elif re.search(r"\.(createHmac|createCipheriv|createDecipheriv|pbkdf2(Sync)?|scrypt(Sync)?)$|^(createHmac|createCipheriv)$", callee or ""):
                    why = f"used as key material in {callee}()"
                else:
                    continue  # parseInt(Math.random() * 98) / Math.floor(...): keep climbing to where the value is stored
                break
            if a.type in ("statement_block", "program", "expression_statement"):
                break
        if self.minified and not (why or "").startswith("used as key"):
            return  # minified bundle: function / variable names are mangled (var pw = "__closure_events_fn_" + Math.random())
        if why is None and target and js_secret_name(target):
            why = f"stored as '{target}'"
        elif why and not by_name and target and not js_secret_name(target) and not related:
            return  # function only looks sensitive from its body; this value goes to a plainly named variable (`liquid`)
        if why is None:
            return
        body = self.t(self.funcs[fn][0]) if fn in self.funcs else ""
        fallback = re.search(r"getRandomValues|randomBytes|randomUUID", body) is not None
        flags = ["csprng-fallback"] if fallback else ["weak-prng"]
        self.add(node, "rng", "NON-CSPRNG", dict(api="Math.random"),
                 f"Math.random() {why}" + (" (only a fallback when crypto.getRandomValues is unavailable)" if fallback else ""),
                 flags, confidence=0.4 if fallback else 1.0, api="Math.random", func=fn)
        if related:
            self.findings[-1].location["related_lines"] = related

    def cryptojs(self, c):
        """crypto-js: CryptoJS.AES.encrypt(msg, passphrase, {mode}), CryptoJS.MD5(x), HmacSHA1, PBKDF2 / EvpKDF {keySize}."""
        node, fn, args, name = c["node"], c["func"], c["args"], c["name"]
        path = (c["obj"] or "").split(".")
        api = "crypto-js"
        if name in ("encrypt", "decrypt") and path and path[-1] in CRYPTOJS_CIPHERS:
            alg = CRYPTOJS_CIPHERS[path[-1]]
            opts = args[2] if len(args) > 2 else None
            mode = self.prop(opts, "mode", fn) if opts is not None else None
            mode = self.t(mode).split(".")[-1].upper() if mode is not None else ("CBC" if alg in ("AES", "DES", "3DES", "Blowfish") else None)
            flags = ["ecb-mode"] if mode == "ECB" else []
            key = self.value(args[1], fn) if len(args) > 1 else None
            if isinstance(key, str):
                flags.append("weak-kdf")  # a string key is a passphrase: EVP_BytesToKey(MD5, 1 iteration)
            if len(args) > 1 and self.is_literal(args[1], fn):
                flags.append("hardcoded-key")
            bits = {"AES": 256, "DES": 56, "3DES": 168}.get(alg) if isinstance(key, str) or key is None else None
            self.add(node, "encryption", alg, dict(key_bits=bits, mode=mode), f"CryptoJS.{path[-1]}.{name}()" +
                     (" with a passphrase (EvpKDF / MD5 key derivation)" if isinstance(key, str) else ""), flags, api=api, func=fn)
        elif name in CRYPTOJS_HASHES and path[-1:] != ["algo"]:
            self.add(node, "hash", CRYPTOJS_HASHES[name], {}, f"CryptoJS.{name}()", api=api, func=fn)
        elif name.startswith("Hmac") and name[4:] in CRYPTOJS_HASHES:
            self.add(node, "mac", "HMAC", dict(hash=CRYPTOJS_HASHES[name[4:]]), f"CryptoJS.{name}()", api=api, func=fn)
        elif name in ("PBKDF2", "EvpKDF") or name == "create" and path[-1:] and path[-1] in ("PBKDF2", "EvpKDF"):
            kind = name if name != "create" else path[-1]
            cfg = args[2] if name != "create" and len(args) > 2 else (args[0] if name == "create" and args else None)
            ks = self.pval(cfg, "keySize", fn) if cfg is not None else None
            it = self.pval(cfg, "iterations", fn) if cfg is not None else None
            params = dict(key_bits=ks * 32 if isinstance(ks, int) else 128, iterations=it if isinstance(it, int) else 1)
            if kind == "PBKDF2":
                self.add(node, "kdf", "PBKDF2", params, f"CryptoJS.PBKDF2(keySize: {ks} words)", api=api, func=fn)
            else:
                self.add(node, "kdf", "PBKDF1", dict(params, hash="MD5"), f"CryptoJS.EvpKDF(keySize: {ks} words): OpenSSL EVP_BytesToKey over MD5",
                         ["weak-kdf"], api=api, func=fn)

    def forge(self, c):
        """node-forge: cipher.createCipher('3DES-CBC', key), rc2.createEncryptionCipher(key, bits), md.md5.create(),
        pki.rsa.generateKeyPair({bits})."""
        node, fn, args, name = c["node"], c["func"], c["args"], c["name"]
        path = (c["obj"] or "").split(".")
        api = "node-forge"
        if name in ("createCipher", "createDecipher") and path[-1:] == ["cipher"] and args:
            spec = str(self.value(args[0], fn) or "")
            alg, _, mode = spec.upper().partition("-")
            if alg in FORGE_CIPHERS:
                kb = self.nbytes(self.value(args[1], fn)) if len(args) > 1 else None
                self.add(node, "encryption", FORGE_CIPHERS[alg], dict(key_bits=kb * 8 if kb else None, mode=mode or None),
                         f"forge.cipher.{name}('{spec}', key)", ["ecb-mode"] if mode == "ECB" else [], api=api, func=fn)
        elif name in ("createEncryptionCipher", "createDecryptionCipher") and path[-1:] == ["rc2"]:
            bits = self.value(args[1], fn) if len(args) > 1 else None
            kb = self.nbytes(self.value(args[0], fn)) if args else None
            self.add(node, "encryption", "RC2", dict(key_bits=bits if isinstance(bits, int) else (kb * 8 if kb else None)),
                     f"forge.rc2.{name}(key, {bits})", api=api, func=fn)
        elif name == "create" and len(path) >= 2 and path[-2] == "md" and path[-1].upper() in CRYPTOJS_HASHES:
            self.add(node, "hash", CRYPTOJS_HASHES[path[-1].upper()], {}, f"forge.md.{path[-1]}.create()", api=api, func=fn)
        elif name == "generateKeyPair" and path[-2:] == ["pki", "rsa"]:
            bits = self.value(args[0], fn) if args else None
            if not isinstance(bits, int) and args:
                bits = self.pval(args[0], "bits", fn)
            self.add(node, "signature", "RSA", dict(key_bits=bits if isinstance(bits, int) else None), f"forge.pki.rsa.generateKeyPair({bits})",
                     api=api, func=fn)

    def jwt_objects(self):
        """JWK.None (jose v1: unsigned tokens) and new JwtStrategy({secretOrKey: '...'}) (passport-jwt)."""
        for n in self.walk(self.root):
            if n.type == "member_expression" and self.t(n.child_by_field_name("property")) == "None" \
                    and self.imports.get(self.t(n.child_by_field_name("object")), "").startswith("jose"):
                self.add_jwt(n, "none", self.enclosing(n), "jose JWK.None")
            elif n.type == "new_expression":
                ctor = self.t(n.child_by_field_name("constructor"))
                if self.imports.get(ctor.split(".")[0], "").startswith("passport-jwt"):
                    args = n.child_by_field_name("arguments")
                    opts = args.named_children[0] if args is not None and args.named_children else None
                    sec = self.prop(opts, "secretOrKey", self.enclosing(n)) if opts is not None else None
                    if sec is not None:
                        self.add_jwt(n, "HS256", self.enclosing(n), "passport-jwt Strategy", (sec, self.enclosing(n)))

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
        lib = (c["mod"] or "").split(".")[0]
        key = (args[1], fn) if len(args) > 1 else None
        askey = self.node_of(args[1], fn) if len(args) > 1 else None  # key = JWK.asKey('secret'); JWT.verify(payload, key)
        askey = askey.child_by_field_name("arguments").named_children[0] if askey is not None and askey.type == "call_expression" \
            and self.t(askey.child_by_field_name("function")).endswith("JWK.asKey") and askey.child_by_field_name("arguments").named_children else None
        literal_key = key is not None and self.is_literal(*key) or askey is not None and self.is_literal(askey, fn)
        if lib == "jsonwebtoken" and name in ("sign", "verify"):
            opts = args[2] if len(args) > 2 else None
            if name == "sign":
                v = self.pval(opts, "algorithm", fn) if opts is not None else None
                algs = [v or "HS256"]  # jsonwebtoken default
            else:
                lst = self.prop(opts, "algorithms", fn) if opts is not None else None
                algs = [self.value(x, fn) for x in lst.named_children] if lst is not None and lst.type == "array" else []
                if not algs and literal_key:
                    algs = ["HS256"]  # a string secret means HMAC
            jns = [jn for jn in map(jwt_algorithms.normalize, algs) if jn]
            for jn in jns:
                self.add_jwt(node, jn, fn, f"jwt.{name}", key)
            if not jns:
                self.jwt_unknown(node, fn, f"jwt.{name}", "algorithm chosen at run time" if algs else
                                 "no algorithms option: the algorithm comes from the token header (limited by the key type)")
        elif lib == "jsonwebtoken" and name == "decode" and not any(
                d["name"] == "verify" and (d["mod"] or "").startswith("jsonwebtoken") and d["func"] == fn for d in self.calls):
            self.add(node, "signature", "NULL", dict(jose="none"), "jwt.decode() without jwt.verify(): the signature is never checked",
                     ["jwt", "signature-not-verified"], api="jwt.decode", func=fn)
        elif lib == "jose" and name in ("sign", "verify") and (c["obj"] or "").split(".")[-1] == "JWT":  # jose v1: JWT.sign(payload, key)
            if len(args) > 1 and self.t(args[1]).endswith("JWK.None"):
                return  # reported by jwt_objects()
            if literal_key:
                self.add_jwt(node, "HS256", fn, f"jose JWT.{name}", key if key and self.is_literal(*key) else (askey, fn))
        elif lib == "express-jwt" and args:  # expressJwt({ secret: 'shhhh', algorithms: [...] })
            sec = self.prop(args[0], "secret", fn)
            if sec is not None and self.is_literal(sec, fn):
                self.add_jwt(node, "HS256", fn, "express-jwt", (sec, fn))
        elif lib == "jwt-simple" and name in ("encode", "decode"):
            nv = self.value(args[2], fn) if name == "decode" and len(args) > 2 else None
            if nv is True or isinstance(nv, str) and nv:  # decode(token, key, noVerify): any truthy value, even 'HS256' or 'false'
                self.add(node, "signature", "NULL", dict(jose="none"), f"jwt-simple decode(..., noVerify={self.t(args[2])}): truthy, so the signature is not checked",
                         ["jwt", "signature-not-verified"], api="jwt-simple.decode", func=fn)
            elif literal_key:
                self.add_jwt(node, "HS256", fn, f"jwt-simple.{name}", key)
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
        jf = JavaFile(fh.read(), rel)
    jf.props, jf.project_calls = project_properties(path), project_calls(path)
    jf.project_classes = _CLASSES_CACHE.get(project_root(path), {})
    jf.alg_args = project_algorithm_args(path)
    return jf.scan()


_PROPS_CACHE: dict = {}
_PROJECT_MARKERS = ("pom.xml", "build.gradle", "build.gradle.kts", ".git")


_SKIP = (".git", "target", "build", "node_modules", ".gradle", ".venv", "venv", "vendor", "dist")
_CALLS_CACHE: dict = {}
_CLASSES_CACHE: dict = {}


def project_root(path: str) -> str | None:
    """Nearest ancestor with pom.xml / build.gradle / .git."""
    d = os.path.dirname(os.path.abspath(path))
    while d != os.path.dirname(d) and not any(os.path.exists(os.path.join(d, m)) for m in _PROJECT_MARKERS):
        d = os.path.dirname(d)
    return d if any(os.path.exists(os.path.join(d, m)) for m in _PROJECT_MARKERS) else None


_ALG_ARGS_CACHE: dict = {}


def project_algorithm_args(path: str) -> set:
    """Names passed to getInstance(...) anywhere in the project (MessageDigest.getInstance(CryptoConstants.LEGACY_DIGEST)):
    such a constant is already reported where it is used."""
    d = project_root(path) or os.path.dirname(os.path.abspath(path))
    if d not in _ALG_ARGS_CACHE:
        names = set()
        for dirpath, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in _SKIP]
            for fn in files:
                if fn.endswith(".java"):
                    try:
                        src = open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    names |= {m.split(".")[-1] for m in re.findall(r"getInstance\(\s*([\w.]+)", src)}
        _ALG_ARGS_CACHE[d] = names
    return _ALG_ARGS_CACHE[d]


def project_calls(path: str) -> dict:
    """method name -> [(JavaFile, call)] over every .java file of the project: lets a parameter be resolved from a
    call site in another class (inter-file constant propagation, one level per hop)."""
    d = project_root(path)
    if d is None:
        return {}
    if d not in _CALLS_CACHE:
        index: dict = {}
        classes: dict = {}
        _CALLS_CACHE[d] = index  # set first: files parsed below may resolve through it
        _CLASSES_CACHE[d] = classes
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in _SKIP]
            for f in sorted(files):
                if f.endswith(".java"):
                    try:
                        with open(os.path.join(root, f), "rb") as fh:
                            jf = JavaFile(fh.read(), f)
                    except (OSError, ValueError):
                        continue
                    jf.props, jf.project_calls, jf.project_classes = project_properties(os.path.join(root, f)), index, classes
                    for c in jf.calls:
                        index.setdefault(c["name"], []).append((jf, c))
                    for n in jf.walk(jf.root):
                        if n.type in ("class_declaration", "interface_declaration", "enum_declaration"):
                            classes.setdefault(jf.t(n.child_by_field_name("name")), jf)
    return _CALLS_CACHE[d]


def project_properties(path: str) -> dict:
    """key -> value from every *.properties file of the Java project that contains `path` (nearest pom.xml / build.gradle / .git)."""
    d = project_root(path)
    if d is None:
        return {}
    if d not in _PROPS_CACHE:
        props = {}
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in _SKIP]
            for f in sorted(files):
                if f.endswith(".properties"):
                    for raw in open(os.path.join(root, f), encoding="utf-8", errors="replace"):
                        line = raw.strip()
                        m = re.match(r"([^#!=:\s][^=:\s]*)\s*[=:]\s*(.*)$", line)
                        if m:
                            props.setdefault(m.group(1), m.group(2).strip())
        _PROPS_CACHE[d] = props
    return _PROPS_CACHE[d]
