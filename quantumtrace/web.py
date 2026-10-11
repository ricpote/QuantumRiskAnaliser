"""Local dashboard API. The scanner, scoring and export modules remain authoritative.

Bound to loopback; the TanStack server proxies /api on the public UI port.
No arbitrary filesystem paths or network targets are accepted from the browser.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zipfile import ZipFile, BadZipFile
from urllib.parse import parse_qs, urlsplit

from .cli import collect
from .schema import Finding
from .score import summarize
from .export import cyclonedx, sarif

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 48 * 1024 * 1024
MAX_FILES = 2000
MAX_EXPANDED = 128 * 1024 * 1024


def report(findings: list[Finding], *, origin: str, warnings=None, generated_at=None) -> dict:
    summary = summarize(findings)
    summary["warnings"] = warnings or []
    return dict(schema_version=1, origin=origin,
                generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
                findings=[f.to_dict() for f in findings], summary=summary)


def unpack(files: list, destination: Path) -> None:
    """Bounded extraction; reject traversal, symlinks, duplicates and ZIP bombs."""
    count, total = 0, 0
    seen = set()

    def write(name, data):
        nonlocal count, total
        name = name.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or any(p in ("..", ".") or ":" in p for p in path.parts) or not path.parts:
            raise ValueError("Upload contains an unsafe filename")
        target = (destination / Path(*path.parts)).resolve()
        if not target.is_relative_to(destination.resolve()) or target in seen:
            raise ValueError("Upload contains an unsafe or duplicate filename")
        count += 1
        total += len(data)
        if count > MAX_FILES or total > MAX_EXPANDED:
            raise ValueError("Upload exceeds 2,000 files or 128 MiB expanded")
        seen.add(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Choose at least one file (maximum 2,000)")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("content"), str):
            raise ValueError("Each upload requires a name and base64 content")
        try:
            data = base64.b64decode(item["content"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Invalid base64 upload") from exc
        if item["name"].lower().endswith(".zip"):
            try:
                with ZipFile(io.BytesIO(data)) as archive:
                    if len(archive.infolist()) + count > MAX_FILES:
                        raise ValueError("Too many files in ZIP")
                    for entry in archive.infolist():
                        if entry.is_dir():
                            continue
                        if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                            raise ValueError("ZIP symlinks are not supported")
                        if entry.file_size + total > MAX_EXPANDED:
                            raise ValueError("ZIP expands beyond 128 MiB")
                        write(entry.filename, archive.read(entry))
            except BadZipFile as exc:
                raise ValueError("Invalid ZIP archive") from exc
        else:
            write(item["name"], data)


class Store:
    def __init__(self, results: Path):
        self.results = results
        self.lock = threading.Lock()
        self.current = None
        self.job = {"state": "idle", "error": None}
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

    def start(self, body):
        if not isinstance(body, dict) or not isinstance(body.get("demo", False), bool):
            raise ValueError("Expected a JSON object with a boolean demo field")
        with self.lock:
            if self.job["state"] == "running":
                raise ValueError("A scan is already running")
            self.job = {"state": "running", "error": None}
        threading.Thread(target=self._scan, args=(body,), daemon=True).start()

    def _scan(self, body):
        try:
            warnings = []
            if body.get("demo") is True:
                findings = collect([str(ROOT / "samples" / "official")], warnings, quiet=True)
                origin = "sample"
            else:
                with tempfile.TemporaryDirectory(prefix="quantumtrace-upload-") as tmp:
                    unpack(body.get("files"), Path(tmp))
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
            if not findings:
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
                return self.send_json(404, {"error": "Not found"})
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
