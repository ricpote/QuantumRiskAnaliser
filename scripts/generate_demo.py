"""Regenerate the labelled offline demo with the actual Python scanner."""
import json
import os
from pathlib import Path

from quantumtrace.cli import collect
from quantumtrace.web import report

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
os.environ['QT_NOW'] = '2026-10-10T12:00:00Z'
warnings = []
findings = collect([
    'samples/official/sample-repos/python/secure_transfer.py',
    'samples/official/sample-repos/python/webhook_signature.py',
    'samples/official/cloud-posture/kms_key_inventory.json',
], warnings)
if warnings:
    raise RuntimeError(warnings)
output = report(findings, origin='sample', generated_at='2026-10-10T12:00:00Z')
(ROOT / 'frontend/public/demo-report.json').write_text(json.dumps(output, indent=2), encoding='utf-8')
print(f'Wrote {len(findings)} explicitly labelled sample findings')
