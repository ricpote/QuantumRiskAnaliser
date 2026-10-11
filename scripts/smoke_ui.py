"""Smoke-test a running production UI: routes, API, upload scan, exports, what-if, Mosca, accuracy, explain, live probe."""
import base64
import json
import sys
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

base = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8501'
def request(path, body=None):
    req = Request(base+path, data=json.dumps(body).encode() if body is not None else None,
                  headers={'Content-Type':'application/json', 'Origin':base})
    with urlopen(req, timeout=30) as response:
        return response.read()

for attempt in range(60):
    try:
        assert json.loads(request('/api/health'))['service']=='quantumtrace'
        break
    except Exception:
        if attempt == 59:
            raise
        time.sleep(1)
for route in ('/', '/inventory', '/migration', '/probe', '/accuracy', '/explain', '/reports'):
    html = request(route).decode()
    assert 'QuantumTrace' in html and 'workspace' in html and '<html' in html, route
sample = json.loads(request('/demo-report.json'))
assert sample['origin']=='sample' and sample['findings']
content=base64.b64encode(b'import hashlib\nx=hashlib.md5(b"smoke").hexdigest()\n').decode()
request('/api/scan', {'files':[{'name':'smoke.py','content':content}]})
for _ in range(100):
    status=json.loads(request('/api/status'))
    if status['state']!='running':
        break
    time.sleep(.1)
assert status['state']=='complete', status
report=json.loads(request('/api/report'))
assert report['origin']=='upload' and any(f['algorithm']=='MD5' for f in report['findings'])
assert json.loads(request('/api/export/cbom'))['specVersion']=='1.6'
assert json.loads(request('/api/export/sarif'))['version']=='2.1.0'
at = quote(report['generated_at'])
what = json.loads(request('/api/whatif', {'actions': [0], 'at': report['generated_at']}))
assert set(what) == {'actions', 'before', 'after'}, what
assert json.loads(request(f'/api/mosca?qday=2030&at={at}'))['qday_year'] == 2030
explained = json.loads(request('/api/explain?algorithm=Ed25519&category=signature'))['finding']
assert explained['risk_tier'] == 'critical', explained
assert json.loads(request('/api/accuracy'))['passed'] is True
request('/api/probe', {'targets': ['127.0.0.1:8443', '127.0.0.1:8445']})   # the image runs the TLS lab
for _ in range(200):
    job = json.loads(request('/api/probe'))
    if job['state'] != 'running':
        break
    time.sleep(.3)
assert job['state'] == 'complete', job
assert [r['verdict']['color'] for r in job['result']['reports']] == ['green', 'red'], job['result']['reports']
print('PASS: SSR routes, API, demo, upload scan, CBOM, SARIF, what-if, Mosca, accuracy, explain, live probe')
