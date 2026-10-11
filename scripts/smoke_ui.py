"""Smoke-test a running production UI, API, upload scan and backend exports."""
import base64
import json
import sys
import time
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
for route in ('/', '/inventory', '/migration', '/reports'):
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
print('PASS: React SSR routes, API, labelled demo, upload scan, CBOM and SARIF')
