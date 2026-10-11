import base64
import io
import json
import os
from pathlib import Path
import threading
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote
from zipfile import ZipFile

import pytest

from quantumtrace.classify import classify
from quantumtrace.schema import Finding
from quantumtrace.score import summarize
from quantumtrace.web import Store, handler, report, unpack
from http.server import ThreadingHTTPServer


@pytest.fixture
def api(tmp_path):
    store = Store(tmp_path)
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler(store))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def call(path, body=None, origin=None):
        headers = {'Content-Type': 'application/json'}
        if origin:
            headers['Origin'] = origin
        req = Request(f'http://127.0.0.1:{server.server_port}{path}',
                      data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            response = urlopen(req, timeout=10)
        except HTTPError as e:
            response = e
        with response:
            return response.status, json.load(response)
    yield store, call
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def test_empty_and_refresh_preserve_python_values(api, tmp_path):
    store, call = api
    assert call('/api/report') == (200, None)
    assert call('/api/export/cbom')[0] == 409
    f = classify(Finding(source='code', category='signature', algorithm='RSA',
                         params={'key_bits': 2048}, asset={'path': 'app.py'}, location={'file': 'app.py', 'line': 1}))
    (tmp_path / 'findings.json').write_text(json.dumps([f.to_dict()]))
    status, value = call('/api/refresh', {})
    assert status == 200
    assert value['origin'] == 'cli'
    assert value['summary']['quantum_readiness_score'] == summarize([f])['quantum_readiness_score']
    assert value['findings'][0]['risk_points'] == f.risk_points
    assert call('/api/export/sarif')[1]['version'] == '2.1.0'
    assert call('/api/export/cbom')[0] == 200
    assert call('/api/export/report')[1] == value
    assert call('/api/export/cbom?at=stale-report')[0] == 409


def test_upload_runs_scanner_and_bad_upload_keeps_previous_report(api):
    store, call = api
    content = base64.b64encode(b'import hashlib\ndigest = hashlib.md5(b"hello").hexdigest()\n').decode()
    assert call('/api/scan', {'files': [{'name': 'sample.py', 'content': content}]})[0] == 202
    def finish():
        for _ in range(100):
            status = call('/api/status')[1]
            if status['state'] != 'running':
                return status
            time.sleep(.02)
        pytest.fail('scan did not finish')
    assert finish()['state'] == 'complete'
    previous = call('/api/report')[1]
    assert previous['origin'] == 'upload'
    assert any(f['algorithm'] == 'MD5' for f in previous['findings'])
    assert all(f['location']['file'] == 'sample.py' for f in previous['findings'])
    call('/api/scan', {'files': []})
    assert finish()['state'] == 'error'
    assert call('/api/report')[1] == previous


def test_reject_cross_origin_and_duplicate_jobs(api):
    store, call = api
    assert call('/api/scan', {'demo': True}, origin='https://other.example')[0] == 403
    store.job = {'state': 'running', 'error': None}
    assert call('/api/scan', {'demo': True})[0] == 400


@pytest.mark.parametrize('name', ['../escape.py', '/absolute.py', 'C:/escape.py', '..\\escape.py'])
def test_zip_cannot_escape_upload_directory(tmp_path, name):
    archive = io.BytesIO()
    with ZipFile(archive, 'w') as z:
        z.writestr(name, 'bad')
    with pytest.raises(ValueError, match='unsafe'):
        unpack([{'name':'input.zip', 'content':base64.b64encode(archive.getvalue()).decode()}], tmp_path)
    assert not list(tmp_path.iterdir())


def test_bad_saved_results_do_not_crash_server(tmp_path):
    (tmp_path/'findings.json').write_text('invalid')
    store = Store(tmp_path)
    assert store.current is None
    assert store.job['state'] == 'error'


@pytest.mark.parametrize('name,content,empty', [
    ('Example.java', b'public class Example { public static void main(String[] args) {} }', True),
    ('digest.py', b'import hashlib\nx = hashlib.md5(b"hello").hexdigest()\n', False),
])
def test_saved_upload_restores_after_reference_scan_and_restart(api, tmp_path, name, content, empty):
    store, call = api
    store._scan({'files': [{'name': name, 'content': base64.b64encode(content).decode()}]})
    assert store.job['state'] == 'complete', store.job
    uploaded = call('/api/report')[1]
    assert (uploaded['findings'] == []) == empty
    assert (tmp_path / 'uploaded-report.json').exists()
    store._scan({'demo': True})
    assert store.job['state'] == 'complete', store.job
    assert store.current['origin'] == 'sample'
    assert call('/api/refresh', {}) == (200, uploaded)
    assert call('/api/export/report')[1] == uploaded
    assert call('/api/export/cbom')[0] == 200
    assert Store(tmp_path).current == uploaded
    # A later CLI scan takes precedence, including empty CLI results.
    cli_path = tmp_path / 'findings.json'
    cli_path.write_text('[]')
    stamp = (tmp_path / 'uploaded-report.json').stat().st_mtime_ns + 1_000_000_000
    os.utime(cli_path, ns=(stamp, stamp))
    assert call('/api/refresh', {})[1]['origin'] == 'cli'
    assert store.current['findings'] == []


def test_failed_save_keeps_previous_saved_and_active_results(api, monkeypatch):
    store, call = api
    body = {'files': [{'name': 'Example.java', 'content': base64.b64encode(b'public class Example {}').decode()}]}
    store._scan(body)
    previous = store.current
    assert store.job['state'] == 'complete'
    def fail(value):
        raise OSError('Results directory is not writable')
    monkeypatch.setattr(store, 'save_upload', fail)
    store._scan(body)
    assert store.job['state'] == 'error'
    assert store.current == previous
    assert call('/api/refresh', {}) == (200, previous)


def test_explain_whatif_and_mosca_use_the_python_engine(api, monkeypatch):
    monkeypatch.setenv('QT_NOW', '2026-10-10T12:00:00Z')
    store, call = api
    status, value = call('/api/explain')
    assert status == 200 and 'AES' in value['options']['algorithms'] and 'PLAINTEXT' not in value['options']['algorithms']
    finding = call('/api/explain?algorithm=Ed25519&category=signature')[1]['finding']
    assert (finding['risk_tier'], finding['quantum_threat']) == ('critical', 'shor')
    assert call('/api/explain?algorithm=AES&params=key_bits')[0] == 400
    assert call('/api/explain?algorithm=NOPE')[0] == 400
    assert call('/api/mosca?qday=2030')[0] == 409                       # nothing loaded yet
    assert call('/api/whatif', {'actions': [0]})[0] == 409
    web = {'kind': 'network-endpoint', 'host': 'app.lab', 'port': 443, 'service': 'https'}
    f = classify(Finding(source='network', category='key-exchange', algorithm='X25519', asset=web, location={'pcap': 'x.pcap'}))
    (store.results / 'findings.json').write_text(json.dumps([f.to_dict()]))
    report = call('/api/refresh', {})[1]
    at = report['generated_at']
    status, mosca = call(f'/api/mosca?qday=2030&at={quote(at)}')
    assert status == 200 and mosca['qday_year'] == 2030 and mosca['assets'][0]['status'] == 'late'
    assert report['summary']['mosca']['assets'][0]['status'] == 'start-now'  # default Q-Day 2033
    assert call('/api/mosca?qday=2030&at=stale')[0] == 409
    assert call('/api/mosca?qday=1990')[0] == 400
    status, what = call('/api/whatif', {'actions': [0], 'at': at})
    assert status == 200 and what['before']['hndl_exposed'] == 1 and what['after']['hndl_exposed'] == 0
    assert what['after']['score'] > what['before']['score']
    assert call('/api/whatif', {'actions': [5], 'at': at})[0] == 400
    assert call('/api/whatif', {'actions': [0], 'at': 'stale'})[0] == 409


def test_accuracy_runs_in_a_child_process_and_is_cached(api, monkeypatch):
    store, call = api
    monkeypatch.delenv('QT_NOW', raising=False)
    cwd = os.getcwd()
    result = store.accuracy()                      # direct call: the first run scans the official samples
    assert result['passed'] and result['code_by_origin']['official']['expected'] > 0
    assert 'QT_NOW' not in os.environ and os.getcwd() == cwd   # evaluate.run() side effects stay in the child
    assert call('/api/accuracy') == (200, result)


def test_probe_validates_targets(api):
    store, call = api
    assert call('/api/probe')[1]['state'] == 'idle'
    for bad in (['https://example.com'], [], ['host:70000'], ['x'] * 9, 'example.com', [1], ['a b']):
        assert call('/api/probe', {'targets': bad})[0] == 400, bad
    assert call('/api/probe', {'targets': ['example.com'], 'deep': 'yes'})[0] == 400
    assert call('/api/probe')[1]['state'] == 'idle'

