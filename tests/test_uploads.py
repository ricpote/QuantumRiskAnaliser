"""Content and archive boundaries for the local upload bridge."""
import base64
import io
from zipfile import ZipFile, ZipInfo

import pytest

from quantumtrace import uploads
from quantumtrace.web import Store


def upload(name, data):
    return {'name': name, 'content': base64.b64encode(data).decode()}


def archive(entries):
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w') as z:
        for name, data in entries:
            z.writestr(name, data)
    return upload('repository.zip', buffer.getvalue())


@pytest.mark.parametrize('name,data,reason', [
    ('capture.pcap', b'not a capture', 'capture header'),
    ('source.py', b'MZ\x00\x01binary', 'binary data'),
    ('broken.py', b'def broken(', 'syntax'),
    ('config.json', b'{broken', 'invalid JSON'),
    ('config.json', b'{"unrelated": true}', 'unsupported input'),
    ('source.PY', b'print(1)', 'lowercase'),
    ('source.py', b'', 'empty'),
])
def test_rejects_mislabeled_or_invalid_content(tmp_path, name, data, reason):
    with pytest.raises(ValueError, match=reason):
        uploads.unpack([upload(name, data)], tmp_path)


def test_total_limit_uses_decoded_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads, 'MAX_UPLOAD', 16)
    uploads.unpack([upload('a.py', b'x=1\n'), upload('b.py', b'y=2\n')], tmp_path)
    with pytest.raises(ValueError, match='32 MiB'):
        uploads.unpack([upload('c.py', b'#' * 17)], tmp_path)


def test_repository_archive_keeps_supported_files_and_warns_for_others(tmp_path):
    warnings = uploads.unpack([archive([
        ('src/a.py', b'import hashlib\nhashlib.md5(b"x")'),
        ('README.md', b'# Project'),
        ('node_modules/bad.py', b'invalid python !'),
    ])], tmp_path)
    assert (tmp_path / 'src/a.py').exists()
    assert not (tmp_path / 'README.md').exists()
    assert not (tmp_path / 'node_modules').exists()
    assert warnings == [{'path': 'README.md', 'reason': 'Unsupported archive entry ignored'}]


def test_zip_symlinks_duplicates_and_expansion_limit(tmp_path, monkeypatch):
    link = ZipInfo('link.py')
    link.external_attr = 0o120777 << 16
    with pytest.raises(ValueError, match='symlinks'):
        uploads.unpack([archive([(link, b'outside')])], tmp_path)
    with pytest.raises(ValueError, match='duplicate'):
        uploads.unpack([archive([('a.py', b'x=1'), ('a.py', b'x=2')])], tmp_path)
    monkeypatch.setattr(uploads, 'MAX_EXPANDED', 4)
    with pytest.raises(ValueError, match='expands'):
        uploads.unpack([archive([('big.py', b'#' * 5)])], tmp_path)


def test_empty_findings_are_valid_and_failure_preserves_report(tmp_path):
    store = Store(tmp_path)
    store._scan({'files': [upload('plain.py', b'print("no cryptography")')]})
    assert store.job['state'] == 'complete'
    assert store.current['origin'] == 'upload'
    assert store.current['findings'] == []
    previous = store.current
    store._scan({'files': [upload('bad.py', b'def broken(')]})
    assert store.job['state'] == 'error'
    assert store.current is previous


def test_javascript_uses_existing_engine(tmp_path):
    store = Store(tmp_path)
    store._scan({'files': [upload('crypto.js', b'const crypto = require("crypto"); crypto.createHash("md5");')]})
    assert store.job['state'] == 'complete', store.job
    assert any(f['algorithm'] == 'MD5' for f in store.current['findings'])
