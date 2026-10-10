"""Code ingestor: walks a directory and dispatches by language."""
from __future__ import annotations

import os
import re

from ...schema import Finding
from . import config, fixes, python_ast
from .common import is_test_path

try:
    from . import treesitter
except Exception:  # tree-sitter not installed
    treesitter = None

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "vendor", "build", "dist", "target"}
EXT = {".py": "python", ".java": "java", ".go": "go"}
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def scan(root: str, base: str | None = None) -> list[Finding]:
    base = base or os.getcwd()
    files = [root] if os.path.isfile(root) else [
        os.path.join(d, f) for d, ds, fs in os.walk(root) if not ds.__setitem__(slice(None), [x for x in ds if x not in SKIP_DIRS]) for f in fs]
    out: list[Finding] = []
    for path in sorted(files):
        rel = os.path.relpath(path, base)
        ext = os.path.splitext(path)[1]
        start = len(out)
        try:
            if ext == ".py":
                out += python_ast.scan(path, rel)
            elif ext == ".go" and treesitter:
                out += treesitter.scan_go(path, rel)
            elif ext == ".java" and treesitter:
                out += treesitter.scan_java(path, rel)
            elif ext in JS_EXT and treesitter and not path.endswith((".d.ts", ".min.js")):  # skip type stubs / minified bundles
                out += treesitter.scan_js(path, rel)
            elif os.path.basename(path) in ("requirements.txt", "go.mod", "pom.xml", "build.gradle", "package.json"):
                out += _deps(path, rel)
            elif config.kind(path):
                out += config.scan(path, rel)
            fixes.annotate(out[start:], path)
            if is_test_path(rel):  # tests / specs: inventoried, but not production risk
                for f in out[start:]:
                    f.flags += [x for x in ("test-code", "demo-code") if x not in f.flags]
                    f.confidence = min(f.confidence, 0.5)
        except Exception as e:  # never let one file kill the scan
            out.append(Finding(source="code", category="protocol", algorithm="SCAN-ERROR", asset=dict(kind="source-file", path=rel),
                               location=dict(file=rel, line=1), evidence=f"scanner error: {e}", confidence=0.0))
    return out


CRYPTO_LIBS = {"cryptography", "pycryptodome", "pycryptodomex", "pyopenssl", "liboqs-python", "oqs", "pynacl", "bcrypt", "argon2-cffi",
               "golang.org/x/crypto", "github.com/cloudflare/circl", "org.bouncycastle", "bcprov-jdk18on"}


def _deps(path, rel) -> list[Finding]:
    """Crypto library inventory (CycloneDX: library components) + PQ-readiness hints."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []
    name = os.path.basename(path)
    if name == "requirements.txt":
        for line in txt.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*(==|>=|~=)?\s*([\w.]+)?", line)
            if m and m.group(1).lower() in CRYPTO_LIBS:
                out.append(Finding(source="code", category="protocol", algorithm="LIBRARY", params=dict(library=m.group(1), version=m.group(3)),
                                   asset=dict(kind="dependency-manifest", path=rel, language="python"),
                                   location=dict(file=rel, line=txt.splitlines().index(line) + 1, snippet=line.strip()),
                                   context=dict(ecosystem="pypi"), evidence=f"crypto library {m.group(1)} {m.group(3) or ''}".strip()))
    elif name == "go.mod":
        m = re.search(r"^go\s+(\d+)\.(\d+)", txt, re.M)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            note = ("Go >= 1.24: crypto/tls enables X25519MLKEM768 by default and crypto/mlkem (FIPS 203) is in the stdlib"
                    if (major, minor) >= (1, 24) else "Go < 1.24: upgrade to get X25519MLKEM768 by default in crypto/tls and crypto/mlkem")
            out.append(Finding(source="code", category="protocol", algorithm="LIBRARY", params=dict(library="go-stdlib", version=f"{major}.{minor}"),
                               asset=dict(kind="dependency-manifest", path=rel, language="go"), location=dict(file=rel, line=txt[:m.start()].count("\n") + 1, snippet=m.group(0)),
                               context=dict(ecosystem="go", pq_ready=(major, minor) >= (1, 24)), evidence=note))
    return out
