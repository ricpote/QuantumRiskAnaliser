"""Blind (held-out) score on ApacheCryptoAPI-Bench: 121 labelled crypto uses in 10 real Apache projects.

The benchmark ships compiled jars only, so the labelled classes are decompiled first (CFR), then scanned as source:
    git clone --depth 1 https://github.com/CryptoAPI-Bench/ApacheCryptoAPI-Bench.git /tmp/apache
    python scripts/apache_bench.py /tmp/apache /tmp/cfr.jar /tmp/apache_src
Cases are matched by class + method (decompiled line numbers differ from the original). Labels: "Crypto context" =
should be reported, "Non-crypto context" = should not.
"""
from __future__ import annotations

import collections
import glob
import os
import re
import subprocess
import sys
import zipfile

import openpyxl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("QT_NOW", "2026-10-10T12:00:00Z")

from quantumtrace.classify import classify_all  # noqa: E402
from quantumtrace.ingest import code  # noqa: E402

WEAK = ("broken", "deprecated")
PRED = {
    "Random": lambda f: f.algorithm == "NON-CSPRNG",
    "MessageDigest": lambda f: f.category == "hash" and f.classical_status in WEAK and "not-for-security" not in f.flags,
    "CipherAlgo": lambda f: f.category == "encryption" and f.classical_status in WEAK and f.algorithm != "AES",
    "ModeofOperation": lambda f: "ecb-mode" in f.flags,
    "static IV": lambda f: "static-iv" in f.flags,
    "Constantkey": lambda f: "hardcoded-key" in f.flags or "hardcoded-password" in f.flags,
    "PBESalt": lambda f: "static-salt" in f.flags,
    "PBEIteration": lambda f: f.category == "kdf" and (f.params.get("iterations") or 10**9) < 1000,
}
POLICY = {"Mac": "HMAC-MD5 / HMAC-SHA1: still allowed by NIST SP 800-131A, reported as acceptable"}
OUT_OF_SCOPE = ("http", "HostnameVerifier", "TrustManager")


def decompile(bench, cfr, out, classes):
    for jar in glob.glob(os.path.join(bench, "apache_codes", "**", "*.jar"), recursive=True):
        names = set(zipfile.ZipFile(jar).namelist())
        wanted = [c for c in classes if c.replace(".", "/") + ".class" in names]
        if wanted:
            rx = "|".join(re.escape(c) + r"(\$.*)?" for c in wanted)
            subprocess.run(["java", "-jar", cfr, jar, "--outputdir", out, "--jarfilter", f"^({rx})$", "--silent", "true"],
                           capture_output=True, timeout=600)


def main(bench, cfr, out):
    rows = [r for r in openpyxl.load_workbook(os.path.join(bench, "ApacheCryptoAPI-Bench_detail_list.xlsx"), read_only=True)["all cases"]
            .iter_rows(values_only=True)][1:]
    rows = [r for r in rows if r and r[1] and r[6]]
    classes = sorted({str(r[6]).split("$")[0].strip() for r in rows})
    if not glob.glob(os.path.join(out, "**", "*.java"), recursive=True):
        decompile(bench, cfr, out, classes)
    cache, stats, misses = {}, collections.Counter(), []
    for r in rows:
        kind, label, cls, method = str(r[1]).strip(), str(r[3] or ""), str(r[6]).split("$")[0].strip(), str(r[7] or "").strip()
        method = re.sub(r"\(.*", "", method)
        vuln = "crypto" in label.lower() and "non" not in label.lower()
        if kind in OUT_OF_SCOPE:
            stats[("out-of-scope", "n")] += 1
            continue
        path = os.path.join(out, cls.replace(".", "/") + ".java")
        if not os.path.exists(path):
            stats[("not-decompiled", "n")] += 1
            continue
        if path not in cache:
            cache[path] = classify_all(code.scan(path, base=out))
        fs = cache[path]
        in_method = [f for f in fs if not method or method == "<clinit>" or f.location.get("symbol") == method]
        if kind in POLICY:
            stats[(kind, "policy")] += 1
            continue
        got = any(PRED[kind](f) for f in in_method)
        key = ("tp" if vuln else "fp") if got else ("fn" if vuln else "tn")
        stats[(kind, key)] += 1
        if key in ("fp", "fn"):
            misses.append((kind, key, cls.rsplit(".", 1)[-1], method, str(r[2])[:60].replace("\n", " ")))
    print(f"{'kind':<16} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  precision  recall")
    tot = collections.Counter()
    for k in PRED:
        s = {x: stats[(k, x)] for x in ("tp", "fp", "tn", "fn")}
        if sum(s.values()):
            print(f"{k:<16} {s['tp']:>3} {s['fp']:>3} {s['tn']:>3} {s['fn']:>3}  {s['tp'] / max(s['tp'] + s['fp'], 1):8.1%} "
                  f"{s['tp'] / max(s['tp'] + s['fn'], 1):7.1%}")
            tot.update(s)
    print(f"{'= ALL':<16} {tot['tp']:>3} {tot['fp']:>3} {tot['tn']:>3} {tot['fn']:>3}  {tot['tp'] / max(tot['tp'] + tot['fp'], 1):8.1%} "
          f"{tot['tp'] / max(tot['tp'] + tot['fn'], 1):7.1%}")
    for k, why in POLICY.items():
        print(f"(policy, not scored: {stats[(k, 'policy')]} {k} cases - {why})")
    print(f"(out of scope: {stats[('out-of-scope', 'n')]} TLS/HTTP cases; not decompiled: {stats[('not-decompiled', 'n')]})")
    for m in misses:
        print(*m)


if __name__ == "__main__":
    main(*sys.argv[1:4])
