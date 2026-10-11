"""qtrace CLI.

  python -m quantumtrace scan samples/official --out out/
  python -m quantumtrace validate out/cbom.cdx.json
  python -m quantumtrace explain Ed25519 category=signature
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .classify import classify_all
from .export import cyclonedx, sarif
from .schema import Finding, dump
from .score import summarize

PCAP_EXT = (".pcap", ".pcapng", ".cap")


def collect(paths: list[str], problems: list | None = None, quiet: bool = False) -> list[Finding]:
    """Scan every path. A file that cannot be read never aborts the scan: it is added to
    `problems` as dict(path, reason) and, unless quiet, printed as a warning on stderr."""
    from .ingest import cloud, code, pcap
    problems = problems if problems is not None else []
    start = len(problems)
    findings: list[Finding] = []
    pcaps, jsons, code_roots = [], [], []
    for p in paths:
        if not os.path.exists(p):
            problems.append(dict(path=p, reason="path not found"))
        elif os.path.isdir(p):
            code_roots.append(p)
            for d, ds, fs in os.walk(p):
                ds[:] = [x for x in ds if x not in code.SKIP_DIRS]
                for f in fs:
                    fp = os.path.join(d, f)
                    if f.lower().endswith(PCAP_EXT):
                        pcaps.append(fp)
                    elif f.lower().endswith(".json") and cloud.is_cloud_json(fp):
                        jsons.append(fp)
        elif p.lower().endswith(PCAP_EXT):
            pcaps.append(p)
        elif p.lower().endswith(".json"):
            jsons.append(p)
        else:
            code_roots.append(p)
    for p in pcaps:
        try:
            findings += pcap.ingest(p)
        except pcap.TsharkMissing as e:
            problems.append(dict(path=p, reason=str(e)))
        except Exception as e:  # unreadable or corrupt capture: report it, keep scanning the rest
            problems.append(dict(path=p, reason=f"unreadable capture ({e})"))
    if jsons:
        findings += cloud.ingest(jsons, problems)
    for r in code_roots:
        try:
            found = code.scan(r, problems=problems)
        except Exception as e:
            problems.append(dict(path=r, reason=f"code scan failed ({type(e).__name__}: {e})"))
            continue
        for f in found:
            if f.algorithm == "SCAN-ERROR":
                problems.append(dict(path=f.location.get("file", r), reason=f.evidence or "scanner error"))
        findings += found
    if not quiet:
        for x in problems[start:]:
            print(f"[!] skipped {x['path']}: {x['reason']}", file=sys.stderr)
    return classify_all(findings)


def verdict(rep: dict) -> tuple[str, str]:
    """One-line verdict for a probed endpoint -> (tier-ish color, text)."""
    from .kb import tls as TLS
    m = rep.get("modern") or {}
    if rep.get("errors") and not m:
        e = rep["errors"][0]
        if "connection closed" in e:
            return "grey", "no TLS: the server closed the connection on our ClientHello (not TLS on this port? try --starttls)"
        return "grey", f"unreachable: {e}"
    old = [v for v in ("SSL 3.0", "TLS 1.0", "TLS 1.1") if rep["versions"].get(v)]
    g = TLS.group(m["group"]) if m.get("group") else None
    rsa = any(c["kex"] == "RSA" for c in rep.get("tls12_ciphers", []))
    tail = []
    if old:
        tail.append(f"still accepts {', '.join(old)}")
    if rsa:
        tail.append("RSA key transport (no forward secrecy)")
    if rep.get("interception_suspected"):
        tail.append("TLS INTERCEPTION suspected (you are seeing a proxy)")
    if g and g["pq"]:
        classical = [k for k, v in rep["groups"].items() if v["supported"] and not TLS.GROUPS.get(v["code"], {}).get("pq")]
        fb = f"; classical fallback for legacy clients ({', '.join(classical)})" if classical else "; PQ-only (classical clients rejected)"
        return "green", f"PQ-protected: modern clients get {g['name']}{fb}" + (f"; {'; '.join(tail)}" if tail else "")
    if g:
        pqs = [k for k, v in rep["groups"].items() if v["supported"] and TLS.GROUPS.get(v["code"], {}).get("pq")]
        why = f"supports {', '.join(pqs)} but negotiates classical" if pqs else "no ML-KEM group supported"
        return "red", f"HNDL-exposed: modern clients get {g['name']} ({why})" + (f"; {'; '.join(tail)}" if tail else "")
    if rep["versions"].get("TLS 1.2") or old:
        return "red", "classical TLS <= 1.2 only: no PQ possible" + (f"; {'; '.join(tail)}" if tail else "")
    return "grey", f"no TLS handshake ({m.get('alert') or 'no answer'})"


def _print_probe(reports):
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for r in reports:
            print(r["target"], verdict(r)[1])
        return
    con = Console()
    for r in reports:
        color, text = verdict(r)
        t = Table(title=f"[bold]{r['target']}[/]" + (f"  (STARTTLS {r['starttls']})" if r.get("starttls") else "") + f"  {r.get('connections', 0)} handshakes, {r.get('duration_s', 0)}s",
                  show_header=False, title_justify="left")
        t.add_column(style="bold")
        t.add_column()
        m = r.get("modern") or {}
        t.add_row("Verdict", f"[{ {'green': 'green', 'red': 'red'}.get(color, 'white') }]{text}[/]")
        if m.get("version"):
            t.add_row("Modern client gets", f"{m['version']} · {m['cipher']} · {m.get('group_name') or '?'}" + (f" · CertificateVerify {m['cert_verify_name']}" if m.get("cert_verify_name") else ""))
        gs = r.get("groups") or {}
        if gs:
            t.add_row("Key exchange groups", "  ".join(("[green]✓[/] " if v["supported"] else "[dim]✗ ") + k + ("" if v["supported"] else "[/]") for k, v in gs.items()))
        t.add_row("Protocol versions", "  ".join(("[green]✓[/] " if ok else "[dim]✗ ") + v + ("" if ok else "[/]") for v, ok in r["versions"].items()))
        if r.get("tls13_ciphers"):
            t.add_row("TLS 1.3 ciphers", ", ".join(r["tls13_ciphers"]))
        if r.get("tls12_ciphers"):
            t.add_row("TLS 1.2 ciphers", ", ".join(c["name"].replace("TLS_", "") + (f" ({c['curve']})" if c.get("curve") else "") for c in r["tls12_ciphers"]))
        for i, c in enumerate(r.get("certs") or []):
            if c.get("algorithm"):
                t.add_row("Certificate" if i == 0 else f"  chain[{i}]", f"{c['subject'][:60]} · {c['algorithm']}-{c.get('key_bits') or c.get('curve')} · sig {c.get('sig_hash')} · expires {c['not_after'][:10]}")
        if r.get("sigalg_families"):
            t.add_row("Can authenticate with", ", ".join(f"{k}" for k, v in r["sigalg_families"].items() if v) or "-")
        con.print(t)


def cmd_probe(a):
    from .ingest import probe as P
    findings, reports = P.ingest(a.targets, starttls=a.starttls, timeout=a.timeout, deep=a.deep)
    findings = classify_all(findings)
    _print_probe(reports)
    failed = [r["target"] for r in reports if r.get("errors") and not r.get("modern")]
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        summary = summarize(findings)
        dump(findings, os.path.join(a.out, "probe_findings.json"))
        with open(os.path.join(a.out, "probe_reports.json"), "w") as fh:
            json.dump(reports, fh, indent=2, default=str)
        bom = cyclonedx.build(findings, summary, target="live probe: " + ", ".join(a.targets))
        with open(os.path.join(a.out, "probe_cbom.cdx.json"), "w") as fh:
            json.dump(bom, fh, indent=2)
        errs = cyclonedx.validate(bom)
        print(f"Outputs: {a.out}/probe_reports.json, probe_findings.json, probe_cbom.cdx.json (CycloneDX 1.6 {'valid' if not errs else 'NOT VALIDATED' if cyclonedx.unvalidated(errs) else 'INVALID'})")
    if failed:
        print(f"[!] no TLS handshake with: {', '.join(failed)}", file=sys.stderr)
    return 1 if reports and len(failed) == len(reports) else 0


def cmd_scan(a):
    t0 = time.time()
    problems: list = []
    findings = collect(a.paths, problems)
    if a.probe:
        from .ingest import probe as P
        pf, reports = P.ingest(a.probe, timeout=4.0, deep=False)
        findings += classify_all(pf)
        _print_probe(reports)
    summary = summarize(findings)
    summary["warnings"] = problems
    os.makedirs(a.out, exist_ok=True)
    dump(findings, os.path.join(a.out, "findings.json"))
    with open(os.path.join(a.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2, default=str)
    bom = cyclonedx.build(findings, summary, target=a.target or ", ".join(os.path.basename(os.path.normpath(p)) for p in a.paths))
    with open(os.path.join(a.out, "cbom.cdx.json"), "w") as fh:
        json.dump(bom, fh, indent=2)
    with open(os.path.join(a.out, "results.sarif"), "w") as fh:
        json.dump(sarif.build(findings), fh, indent=2)
    errs = cyclonedx.validate(bom)
    _print_summary(summary, findings, time.time() - t0, errs, a.out)
    if problems:
        print(f"[!] {len(problems)} input(s) could not be analysed (listed above and in {a.out}/summary.json \"warnings\")", file=sys.stderr)
    if not findings and problems:
        print("[!] nothing was analysed: check the paths and the files", file=sys.stderr)
        return 3
    if cyclonedx.unvalidated(errs):
        print(f"[!] CBOM written but {errs[0]}", file=sys.stderr)
        return 0
    return 0 if not errs else 2


def _print_summary(s, findings, dt, errs, out):
    try:
        from rich.console import Console
        from rich.table import Table
        con = Console()
        con.print(f"\n[bold]QuantumTrace {__version__}[/] scanned {s['assets']} assets, {s['findings']} findings in {dt:.1f}s")
        qrs = s["quantum_readiness_score"]
        con.print(f"[bold]Quantum Readiness Score: {qrs} / 100  (grade {s['grade']})[/]" if qrs is not None
                  else "[bold]Quantum Readiness Score: n/a (nothing was analysed)[/]")
        t = Table("source", "assets", "score", "critical", "medium", "safe", "unencrypted")
        for src, d in s["sources"].items():
            tr = d["tiers"]
            t.add_row(src, str(d["assets"]), str(d["score"]), str(tr.get("critical", 0)), str(tr.get("medium", 0)),
                      str(tr.get("safe", 0)), str(tr.get("unencrypted", 0)))
        con.print(t)
        n = s["network"]
        if n["endpoints"]:
            con.print(f"Network: {n['pq_protected']}/{n['endpoints']} endpoints PQ-protected, {n['hndl_exposed']} exposed to HNDL, {n['plaintext']} cleartext")
        p = Table("prio", "action", "assets", "how", title="Migration plan (top 8)")
        for x in s["plan"][:8]:
            p.add_row(x["priority"], f"{x['source']}: {x['action']}", str(x["asset_count"]), (x["how"] or "")[:70])
        con.print(p)
    except ImportError:
        print(json.dumps({k: s[k] for k in ("quantum_readiness_score", "grade", "tiers", "network")}, indent=2))
    print(f"CBOM schema validation (CycloneDX 1.6): {'OK' if not errs else 'SKIPPED (' + errs[0] + ')' if cyclonedx.unvalidated(errs) else 'FAILED: ' + errs[0][:300]}")
    print(f"Outputs: {out}/findings.json, summary.json, cbom.cdx.json, results.sarif")


def cmd_validate(a):
    with open(a.file) as fh:
        errs = cyclonedx.validate(json.load(fh))
    if cyclonedx.unvalidated(errs):
        print(errs[0], file=sys.stderr)
        return 1
    print("valid CycloneDX 1.6" if not errs else f"INVALID: {errs[0]}")
    return 0 if not errs else 1


def cmd_explain(a):
    from .classify import classify
    kv = dict(x.split("=", 1) for x in a.params)
    cat = kv.pop("category", "signature")
    params = {k: (int(v) if v.isdigit() else v) for k, v in kv.items()}
    f = classify(Finding(source="code", category=cat, algorithm=a.algorithm, params=params))
    print(json.dumps({k: v for k, v in f.to_dict().items() if k in ("display_name", "quantum_threat", "risk_tier", "classical_status", "classical_bits",
                                                                    "nist_quantum_level", "oid", "replacement", "cwe", "deadlines", "hndl", "risk_points", "rationale")}, indent=2))
    return 0


def cmd_serve(a):
    launcher = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "ui.py")
    os.execvp(sys.executable, [sys.executable, launcher, "--production", "--port", str(a.port), "--results", a.data])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="qtrace", description="QuantumTrace: crypto inventory + PQC readiness")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan pcaps, code and cloud exports")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out", default="out")
    s.add_argument("--target", default=None)
    s.add_argument("--probe", action="append", default=[], metavar="HOST[:PORT]", help="also live-probe this TLS endpoint (repeatable)")
    s.set_defaults(fn=cmd_scan)
    pr = sub.add_parser("probe", help="live TLS probe: PQ key exchange, versions, ciphers, certificate chain")
    pr.add_argument("targets", nargs="+", metavar="HOST[:PORT]")
    pr.add_argument("--starttls", default="auto", choices=["auto", "smtp", "imap", "pop3", "ftp", "postgres", "none"])
    pr.add_argument("--deep", action="store_true", help="also test which signature schemes (incl. ML-DSA) the server can authenticate with")
    pr.add_argument("--timeout", type=float, default=4.0)
    pr.add_argument("--out", default=None, help="write probe_reports.json / probe_findings.json / probe_cbom.cdx.json here")
    pr.set_defaults(fn=cmd_probe)
    v = sub.add_parser("validate", help="validate a CycloneDX 1.6 CBOM")
    v.add_argument("file")
    v.set_defaults(fn=cmd_validate)
    e = sub.add_parser("explain", help="classify one algorithm, e.g. explain AES key_bits=128 mode=ECB category=encryption")
    e.add_argument("algorithm")
    e.add_argument("params", nargs="*")
    e.set_defaults(fn=cmd_explain)
    w = sub.add_parser("serve", help="launch the React dashboard (build frontend first)")
    w.add_argument("--data", default="out")
    w.add_argument("--port", default=8501, type=int)
    w.set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
