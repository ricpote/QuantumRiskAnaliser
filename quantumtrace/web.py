"""Local dashboard API. The scanner, scoring and export modules remain authoritative.

Bound to loopback; the TanStack server proxies /api on the public UI port.
No arbitrary filesystem paths are accepted from the browser. The live probe (like `qtrace probe`)
connects to the host:port the user types, so run the dashboard locally or on a trusted network.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .uploads import unpack
from .classify import classify, classify_all
from .cli import collect, verdict
from .kb import tls as TLSKB
from .kb.algorithms import CATALOG
from .schema import CATEGORIES, Finding
from .score import mosca, summarize, what_if
from .export import cyclonedx, sarif

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 48 * 1024 * 1024
MAX_TARGETS = 8
TARGET = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::(\d{1,5}))?$")
# internal pseudo-algorithms the scanner emits; not useful in the "Explain an algorithm" picker
EXPLAIN_HIDDEN = {"CLASSICAL-SIG", "CSPRNG", "HARDCODED-KEY", "LIBRARY", "NO-CERT-VERIFY", "NON-CSPRNG", "PLAINTEXT", "UNIDENTIFIED"}


def report(findings: list[Finding], *, origin: str, warnings=None, generated_at=None) -> dict:
    summary = summarize(findings)
    summary["warnings"] = warnings or []
    return dict(schema_version=1, origin=origin,
                generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
                findings=[f.to_dict() for f in findings], summary=summary)


class NoReport(Exception):
    """An endpoint that needs the current report was called before any results were loaded."""


def parse_targets(raw) -> list[str]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_TARGETS or not all(isinstance(t, str) for t in raw):
        raise ValueError(f"Give 1 to {MAX_TARGETS} targets as host[:port]")
    targets = []
    for t in (t.strip() for t in raw):
        m = TARGET.match(t)
        if not m or (m.group(1) and not 1 <= int(m.group(1)) <= 65535):
            raise ValueError(f"Invalid target {t[:80]!r}: use host[:port], e.g. example.com or 127.0.0.1:8443")
        targets.append(t)
    return targets


def parse_params(text: str) -> dict:
    """'key_bits=2048, mode=GCM' -> {'key_bits': 2048, 'mode': 'GCM'} (same syntax as `qtrace explain`)."""
    if len(text) > 300:
        raise ValueError("Parameters are too long")
    params = {}
    for item in (x for x in text.split(",") if x.strip()):
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"Parameter {item.strip()!r} must look like key=value")
        value = value.strip()
        params[key.strip()] = int(value) if value.isdigit() else value
    return params


def explain(query: dict) -> dict:
    """Classify one algorithm in one role, exactly as the scanner would (dashboard "Explain" page)."""
    options = dict(algorithms=sorted(a for a in CATALOG if a not in EXPLAIN_HIDDEN), categories=list(CATEGORIES))
    algorithm = (query.get("algorithm") or [""])[0]
    if not algorithm:
        return dict(options=options)
    category = (query.get("category") or ["signature"])[0]
    if algorithm not in CATALOG or algorithm in EXPLAIN_HIDDEN:
        raise ValueError(f"Unknown algorithm {algorithm[:40]!r}")
    if category not in CATEGORIES:
        raise ValueError(f"Unknown role {category[:40]!r}")
    finding = classify(Finding(source="code", category=category, algorithm=algorithm,
                               params=parse_params((query.get("params") or [""])[0])))
    return dict(options=options, finding=finding.to_dict())


class Store:
    def __init__(self, results: Path):
        self.results = results
        self.lock = threading.Lock()
        self.current = None
        self.job = {"state": "idle", "error": None}
        self.probe_job = {"state": "idle", "error": None, "result": None}
        self.accuracy_lock = threading.Lock()
        self.accuracy_result = None
        if (results / "findings.json").exists():
            try:
                self.reload()
            except (OSError, ValueError, TypeError, KeyError):
                self.job = {"state": "error", "error": "Saved results could not be loaded. Run qtrace scan again, then reload."}

    def reload(self):
        raw = json.loads((self.results / "findings.json").read_text(encoding="utf-8"))
        findings = [Finding.from_dict(f) for f in raw]
        # Recalculate only in the backend, avoiding a stale findings/summary pair.
        if any(f.risk_tier is None or f.quantum_threat is None for f in findings):
            raise ValueError("Results must contain classified findings from qtrace scan")
        warnings = []
        summary_path = self.results / "summary.json"
        if summary_path.exists():
            warnings = json.loads(summary_path.read_text(encoding="utf-8")).get("warnings", [])
        fixture = any("samples/" in json.dumps(f.location).replace("\\\\", "/") for f in findings)
        value = report(findings, origin="sample" if fixture else "cli", warnings=warnings,
                       generated_at=datetime.fromtimestamp((self.results / "findings.json").stat().st_mtime, timezone.utc).isoformat())
        with self.lock:
            if self.job["state"] == "running":
                raise ValueError("A scan is already running")
            self.current = value
            self.job = {"state": "idle", "error": None}
        return value

    def findings(self, at=None) -> list[Finding]:
        """Findings of the current report; `at` (the report's generated_at seen by the browser) must still match."""
        with self.lock:
            current = self.current
        if current is None:
            raise NoReport("Load results or run a scan first")
        if at and at != current["generated_at"]:
            raise NoReport("The backend report changed. Reload results first.")
        return [Finding.from_dict(f) for f in current["findings"]]

    def accuracy(self) -> dict:
        """Score the scanner against tests/ground_truth.json (computed once). Runs in a child process because
        evaluate.run() changes the working directory and QT_NOW, which would leak into concurrent scans."""
        with self.accuracy_lock:
            if self.accuracy_result is None:
                code = ("import contextlib, json, sys\n"
                        "from quantumtrace.evaluate import run\n"
                        "with contextlib.redirect_stdout(sys.stderr):\n    result = run()\n"
                        "json.dump(result, sys.stdout)")
                done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=600)
                if done.returncode:
                    raise RuntimeError("Accuracy evaluation failed: " + done.stderr.strip()[-400:])
                self.accuracy_result = json.loads(done.stdout)
            return self.accuracy_result

    def start_probe(self, body):
        if not isinstance(body, dict) or not isinstance(body.get("deep", False), bool):
            raise ValueError("Expected a JSON object with targets and a boolean deep field")
        targets = parse_targets(body.get("targets"))
        with self.lock:
            if self.probe_job["state"] == "running":
                raise ValueError("A probe is already running")
            self.probe_job = {"state": "running", "error": None, "result": None}
        threading.Thread(target=self._probe, args=(targets, body.get("deep", False)), daemon=True).start()

    def _probe(self, targets, deep):
        try:
            from .ingest import probe as P
            findings, reports = P.ingest(targets, deep=deep, timeout=4.0)
            findings = classify_all(findings)
            for r in reports:
                color, text = verdict(r)
                r["verdict"] = dict(color=color, text=text)
                for g in (r.get("groups") or {}).values():
                    g["pq"] = bool(TLSKB.GROUPS.get(g.get("code"), {}).get("pq"))
            bom = cyclonedx.build(findings, summarize(findings), target="live probe: " + ", ".join(targets))
            result = dict(generated_at=datetime.now(timezone.utc).isoformat(), targets=targets, deep=deep, reports=reports,
                          findings=[f.to_dict() for f in findings], cbom=bom, cbom_valid=not cyclonedx.validate(bom))
            with self.lock:
                self.probe_job = {"state": "complete", "error": None, "result": result}
        except Exception as exc:
            with self.lock:
                self.probe_job = {"state": "error", "error": str(exc), "result": None}

    def start(self, body):
        if not isinstance(body, dict) or not isinstance(body.get("demo", False), bool):
            raise ValueError("Expected a JSON object with a boolean demo field")
        with self.lock:
            if self.job["state"] == "running":
                raise ValueError("A scan is already running")
            self.job = {"state": "running", "error": None, "phase": "validating"}
        threading.Thread(target=self._scan, args=(body,), daemon=True).start()

    def _scan(self, body):
        try:
            warnings = []
            if body.get("demo") is True:
                findings = collect([str(ROOT / "samples" / "official")], warnings, quiet=True)
                origin = "sample"
            else:
                with tempfile.TemporaryDirectory(prefix="quantumtrace-upload-") as tmp:
                    warnings += unpack(body.get("files"), Path(tmp))
                    with self.lock:
                        self.job["phase"] = "analyzing"
                    findings = collect([tmp], warnings, quiet=True)
                    # Preserve useful archive-relative evidence, not deleted temp paths.
                    prefix = os.path.relpath(tmp).replace("\\", "/") + "/"
                    for f in findings:
                        for mapping in (f.location, f.asset):
                            for key in ("file", "path", "pcap", "json"):
                                value = mapping.get(key)
                                if isinstance(value, str):
                                    normal = value.replace("\\", "/")
                                    mapping[key] = normal.removeprefix(prefix).removeprefix(tmp.replace("\\", "/") + "/")
                origin = "upload"
            if (not findings and any(w["reason"] != "Unsupported archive entry ignored" for w in warnings)) or (findings and all(f.algorithm == "SCAN-ERROR" for f in findings)):
                raise ValueError("No cryptographic findings. Check supported input formats and scanner warnings. " + "; ".join(w["reason"] for w in warnings)[:500])
            value = report(findings, origin=origin, warnings=warnings)
            with self.lock:
                self.current = value
                self.job = {"state": "complete", "error": None}
        except Exception as exc:
            with self.lock:
                self.job = {"state": "error", "error": str(exc)}


def handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, payload, filename=None):
            data = json.dumps(payload, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            with store.lock:
                current, job = store.current, dict(store.job)
            if path == "/api/health":
                return self.send_json(200, {"status": "ok", "service": "quantumtrace"})
            if path == "/api/status":
                return self.send_json(200, job)
            if path == "/api/report":
                return self.send_json(200, current)
            query = parse_qs(urlsplit(self.path).query)
            try:
                if path == "/api/explain":
                    return self.send_json(200, explain(query))
                if path == "/api/accuracy":
                    return self.send_json(200, store.accuracy())
                if path == "/api/probe":
                    with store.lock:
                        return self.send_json(200, dict(store.probe_job))
                if path == "/api/mosca":
                    qday = int((query.get("qday") or ["0"])[0])
                    if not 2026 <= qday <= 2060:
                        raise ValueError("qday must be a year between 2026 and 2060")
                    return self.send_json(200, mosca(store.findings((query.get("at") or [None])[0]), qday_year=qday))
            except NoReport as exc:
                return self.send_json(409, {"error": str(exc)})
            except (ValueError, TypeError, KeyError) as exc:
                return self.send_json(400, {"error": str(exc)})
            except Exception as exc:  # never drop the connection: the proxy would report "service unavailable"
                return self.send_json(500, {"error": f"{type(exc).__name__}: {exc}"})
            if path.startswith("/api/export/"):
                if current is None:
                    return self.send_json(409, {"error": "Load results or run a scan first"})
                requested = parse_qs(urlsplit(self.path).query).get("at", [None])[0]
                if requested and requested != current["generated_at"]:
                    return self.send_json(409, {"error": "The backend report changed. Reload results before exporting."})
                fs = [Finding.from_dict(f) for f in current["findings"]]
                kind = path.rsplit("/", 1)[-1]
                if kind == "report":
                    return self.send_json(200, current, "quantumtrace-report.json")
                if kind == "sarif":
                    return self.send_json(200, sarif.build(fs), "results.sarif")
                if kind == "cbom":
                    bom = cyclonedx.build(fs, current["summary"], target=f"QuantumTrace {current['origin']} results")
                    errors = cyclonedx.validate(bom)
                    if errors:
                        return self.send_json(422, {"error": "CBOM validation unavailable or failed", "details": errors})
                    return self.send_json(200, bom, "cbom.cdx.json")
            return self.send_json(404, {"error": "Not found"})

        def do_POST(self):
            # Proxy removes Origin only after same-origin verification. Direct browser POSTs are rejected.
            if self.headers.get("Origin") or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send_json(403, {"error": "Use the dashboard on its own origin"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    return self.send_json(413, {"error": "Upload must be less than 48 MiB encoded"})
                body = json.loads(self.rfile.read(length))
                if self.path == "/api/refresh":
                    return self.send_json(200, store.reload())
                if self.path == "/api/scan":
                    store.start(body)
                    return self.send_json(202, {"state": "running"})
                if self.path == "/api/probe":
                    store.start_probe(body)
                    return self.send_json(202, {"state": "running"})
                if self.path == "/api/whatif":
                    if not isinstance(body, dict):
                        raise ValueError("Expected a JSON object with an actions list")
                    return self.send_json(200, what_if(store.findings(body.get("at")), body.get("actions")))
                return self.send_json(404, {"error": "Not found"})
            except NoReport as exc:
                return self.send_json(409, {"error": str(exc)})
            except (ValueError, TypeError, OSError, KeyError) as exc:
                return self.send_json(400, {"error": str(exc)})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8502)
    parser.add_argument("--results", type=Path, default=Path(os.environ.get("QT_RESULTS_DIR", "out")))
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(Store(args.results)))
    print(f"QuantumTrace API on 127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
