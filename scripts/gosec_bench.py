"""Score QuantumTrace on gosec's own rule samples (Go crypto rules), sample by sample.

    git clone --depth 1 --filter=blob:none --sparse https://github.com/securego/gosec.git /tmp/gosec
    (cd /tmp/gosec && git sparse-checkout set testutils)
    python scripts/gosec_bench.py /tmp/gosec [--misses]

Each sample (testutils/gNNN_samples.go) is one or more Go files plus the number of issues gosec expects; a sample is
positive when that number is > 0. Samples that expect 0 only because of a `#nosec` comment are not scored (QuantumTrace inventories every use).
Policy differences are reported separately (G404: gosec flags every math/rand use,
QuantumTrace only in a security context).
"""
from __future__ import annotations

import collections
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402

WEAK = ("broken", "deprecated")
RULES = {  # rule -> (description, predicate)
    "g401": ("weak hash MD5/SHA-1", lambda f: f.category in ("hash", "mac") and f.params.get("hash", f.algorithm) in ("MD5", "SHA-1")
             or f.category == "hash" and f.algorithm in ("MD5", "SHA-1")),
    "g403": ("RSA key < 2048", lambda f: f.algorithm == "RSA" and (f.params.get("key_bits") or 4096) < 2048),
    "g404": ("non-CSPRNG", lambda f: f.algorithm == "NON-CSPRNG"),
    "g405": ("DES / RC4", lambda f: f.category == "encryption" and f.algorithm in ("DES", "3DES", "RC4")),
    "g406": ("MD4 / RIPEMD-160", lambda f: f.category == "hash" and f.algorithm in ("MD4", "RIPEMD-160")),
    "g407": ("hard-coded IV / nonce", lambda f: "static-iv" in f.flags),
    "g501": ("crypto/md5 import", lambda f: f.algorithm == "MD5"),
    "g502": ("crypto/des import", lambda f: f.algorithm in ("DES", "3DES")),
    "g503": ("crypto/rc4 import", lambda f: f.algorithm == "RC4"),
    "g504": ("net/http/cgi import", None),
    "g505": ("crypto/sha1 import", lambda f: f.algorithm == "SHA-1" or f.params.get("hash") == "SHA-1"),
    "g506": ("md4 import", lambda f: f.algorithm == "MD4"),
    "g507": ("ripemd160 import", lambda f: f.algorithm == "RIPEMD-160"),
    "g402": ("weak TLS config", lambda f: f.category in ("protocol", "encryption", "key-exchange", "mac")
             and (f.classical_status in WEAK or "no-forward-secrecy" in f.flags)),
}
# G402 also covers certificate checking (InsecureSkipVerify) and PreferServerCipherSuites: settings, not algorithms
OUT_OF_SCOPE = {"g402": lambda body: not re.search(r"MinVersion|MaxVersion|\bCipherSuites\s*:", body)}
POLICY = {"g404": "gosec flags every math/rand use; QuantumTrace only when the value is used for security"}
SAMPLE = re.compile(r"\{\s*\[\]string\{((?:\s*`[^`]*`\s*,?)+)\s*\},\s*(\d+)\s*,", re.S)


def samples(path):
    src = open(path, encoding="utf-8").read()
    for m in SAMPLE.finditer(src):
        yield re.findall(r"`([^`]*)`", m.group(1)), int(m.group(2))


def main(root, show=False):
    stats, misses = collections.Counter(), []
    for rule, (desc, pred) in RULES.items():
        path = os.path.join(root, "testutils", f"{rule}_samples.go")
        if pred is None or not os.path.exists(path):
            continue
        for i, (files, expected) in enumerate(samples(path)):
            if rule in OUT_OF_SCOPE and all(OUT_OF_SCOPE[rule](body) for body in files):
                stats[(rule, "oos")] += 1
                continue
            if not expected and any("#nosec" in body for body in files):
                stats[(rule, "nosec")] += 1  # expected 0 only because of a suppression comment: not scored
                continue
            with tempfile.TemporaryDirectory() as tmp:
                for j, body in enumerate(files):
                    open(os.path.join(tmp, f"f{j}.go"), "w").write(body)
                fs = classify_all(code.scan(tmp, base=tmp))
            got = any(pred(f) for f in fs if "test-code" not in f.flags)
            key = ("tp" if expected else "fp") if got else ("fn" if expected else "tn")
            stats[(rule, key)] += 1
            if key in ("fp", "fn"):
                first = next((l.strip() for l in files[0].splitlines() if re.search(r"md5|sha1|des|rc4|rand|rsa|tls|md4|ripemd|nonce|iv\b", l, re.I)
                              and not l.strip().startswith(("import", '"'))), "")
                misses.append((rule, key, f"sample{i}", first[:90]))
    print(f"{'rule':<6} {'description':<24} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  precision  recall")
    tot = collections.Counter()
    for rule, (desc, pred) in RULES.items():
        s = {k: stats[(rule, k)] for k in ("tp", "fp", "tn", "fn")}
        if not sum(s.values()):
            continue
        note = f"   (policy: {POLICY[rule]})" if rule in POLICY else ""
        print(f"{rule:<6} {desc:<24} {s['tp']:>3} {s['fp']:>3} {s['tn']:>3} {s['fn']:>3}  {s['tp'] / max(s['tp'] + s['fp'], 1):8.1%} "
              f"{s['tp'] / max(s['tp'] + s['fn'], 1):7.1%}{note}")
        if rule not in POLICY:
            tot.update(s)
    print(f"{'= SCORED':<31} {tot['tp']:>3} {tot['fp']:>3} {tot['tn']:>3} {tot['fn']:>3}  {tot['tp'] / max(tot['tp'] + tot['fp'], 1):8.1%} "
          f"{tot['tp'] / max(tot['tp'] + tot['fn'], 1):7.1%}")
    nosec = sum(v for (r, k), v in stats.items() if k == "nosec")
    print(f"(out of scope: {stats[('g402', 'oos')]} G402 samples about certificate checking / PreferServerCipherSuites only)")
    print(f"(not scored: {nosec} samples where gosec expects nothing only because of a `#nosec` suppression comment)")
    if show:
        for m in misses:
            print(*m)


if __name__ == "__main__":
    main(sys.argv[1], "--misses" in sys.argv)
