"""Upload validation only; detection and classification remain in ingest/ and classify.py."""
from __future__ import annotations

import ast
import base64
import binascii
import io
import json
from pathlib import Path, PurePosixPath
import re
from zipfile import ZipFile, BadZipFile

from .ingest import cloud
from .ingest.code import config, keys

MAX_UPLOAD = 32 * 1024 * 1024
MAX_FILES = 2000
MAX_EXPANDED = 128 * 1024 * 1024
CAPTURE_MAGIC = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'}
MANIFESTS = {'requirements.txt', 'go.mod', 'pom.xml', 'build.gradle', 'package.json'}
SOURCE_PARSERS = {'.go': 'go', '.java': 'java', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'tsx'}


def validate_content(path: Path, data: bytes) -> bool:
    """Return False for unsupported archive entries; reject corrupt supported inputs."""
    suffix = path.suffix.lower()
    if suffix in {'.py', '.tf', *SOURCE_PARSERS} and path.suffix != suffix:
        raise ValueError(f'{path.name}: use a lowercase {suffix} extension so the scanner recognizes this file')
    if path.name.endswith(('.d.ts', '.min.js')):
        return False  # the scanner intentionally skips type declarations and minified bundles
    if suffix in ('.pcap', '.cap', '.pcapng'):
        if not ((data[:4] in CAPTURE_MAGIC and len(data) >= 24) or
                (data[:4] == b'\x0a\x0d\x0d\x0a' and len(data) >= 28 and data[8:12] in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'))):
            raise ValueError(f'{path.name}: not a valid PCAP/PCAPNG capture header')
        return True  # tshark performs complete packet validation
    if keys.kind(str(path)) == 'keys':
        if not data:
            raise ValueError(f'{path.name}: file is empty')
        return True  # certificates and keys (PEM, DER, OpenSSH, PKCS#12): the scanner parses and warns per block
    if suffix not in SOURCE_PARSERS and suffix != '.py' and b'-----BEGIN ' in data[:262144] and len(data) <= 262144:
        return True  # a text file (.yaml, .txt, .env...) that embeds a PEM certificate or key
    named = suffix in {'.py', '.json', '.tf', '.conf', *SOURCE_PARSERS} or path.name in MANIFESTS or 'ssh_config' in path.name or 'sshd_config' in path.name
    if not data:
        if named:
            raise ValueError(f'{path.name}: file is empty')
        return False
    try:
        text = data.decode('utf-8-sig')
        if '\x00' in text or any(ord(c) < 32 and c not in '\r\n\t\f' for c in text):
            raise UnicodeError()
    except UnicodeError:
        if named:
            raise ValueError(f'{path.name}: expected a UTF-8 text file, not binary data') from None
        return False
    if suffix == '.py':
        try:
            ast.parse(text, filename=path.name)
        except SyntaxError as exc:
            raise ValueError(f'{path.name}: invalid Python syntax at line {exc.lineno}') from None
        return True
    if suffix in SOURCE_PARSERS:
        # Use the same parsers as the engine, never execute uploaded code.
        from tree_sitter_language_pack import get_parser
        if get_parser(SOURCE_PARSERS[suffix]).parse(data).root_node.has_error:
            raise ValueError(f'{path.name}: invalid {suffix[1:]} source syntax')
        return True
    if suffix == '.json':
        try:
            json.loads(text)
        except ValueError:
            raise ValueError(f'{path.name}: invalid JSON') from None
        return path.name == 'package.json' or cloud.is_cloud_json(str(path))
    if path.name in MANIFESTS:
        return True
    if suffix == '.tf' and not re.search(r'(?m)^\s*(resource|data|variable|provider|terraform|locals|module|output)\b[^\n]*\{', text):
        raise ValueError(f'{path.name}: expected Terraform configuration blocks')
    return config.kind(str(path)) is not None


def unpack(files: list, destination: Path) -> list[dict]:
    """Extract bounded inputs, return warnings for ignored repository ZIP entries."""
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('Choose at least one file (maximum 2,000)')
    decoded = []
    uploaded = 0
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not isinstance(item.get('content'), str):
            raise ValueError('Each upload requires a name and base64 content')
        # Reject oversized encoding before allocating its decoded bytes.
        if len(item['content']) > ((MAX_UPLOAD - uploaded + 2) // 3) * 4:
            raise ValueError('Selected files exceed the 32 MiB total upload limit')
        try:
            data = base64.b64decode(item['content'], validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('Invalid base64 upload') from None
        uploaded += len(data)
        if uploaded > MAX_UPLOAD:
            raise ValueError('Selected files exceed the 32 MiB total upload limit')
        decoded.append((item['name'], data))
    total, count, supported = 0, 0, 0
    seen = set()
    warnings = []

    def safe_path(name):
        name = name.replace('\\', '/')
        parts = PurePosixPath(name).parts
        reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
        if not parts or name.startswith('/') or any(p in ('.', '..') or ':' in p or '\x00' in p or p.endswith((' ', '.')) or p.split('.')[0].upper() in reserved for p in parts):
            raise ValueError('Upload contains an unsafe filename')
        target = (destination / Path(*parts)).resolve()
        if not target.is_relative_to(destination.resolve()):
            raise ValueError('Upload contains an unsafe filename')
        return target

    def write(name, data, archive=False):
        nonlocal count, total, supported
        target = safe_path(name)
        key = str(target).casefold()
        if key in seen:
            raise ValueError('Upload contains a duplicate filename')
        seen.add(key)
        count += 1
        total += len(data)
        if count > MAX_FILES or total > MAX_EXPANDED:
            raise ValueError('Upload exceeds 2,000 files or 128 MiB expanded')
        # Ignore dependency/build/metadata directories exactly as the scanner does.
        from .ingest.code import SKIP_DIRS
        if archive and any(p in SKIP_DIRS or p == '__MACOSX' for p in PurePosixPath(name.replace('\\', '/')).parts):
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if validate_content(target, data):
            supported += 1
        elif archive:
            target.unlink()  # only this freshly created, validated temporary file
            warnings.append({'path': name, 'reason': 'Unsupported archive entry ignored'})
        else:
            raise ValueError(f'{name}: unsupported input. Choose captures, Python/Java/Go/JS/TS, AWS JSON, supported config files, certificates/keys or ZIP.')

    for name, data in decoded:
        safe_path(name)
        if name.lower().endswith('.zip'):
            try:
                with ZipFile(io.BytesIO(data)) as archive:
                    if len(archive.infolist()) + count > MAX_FILES:
                        raise ValueError('ZIP contains more than 2,000 entries')
                    for entry in archive.infolist():
                        safe_path(entry.filename)
                        if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                            raise ValueError('ZIP symlinks are not supported')
                        if entry.is_dir():
                            continue
                        if entry.flag_bits & 1:
                            raise ValueError('Encrypted ZIP files are not supported')
                        if entry.file_size + total > MAX_EXPANDED:
                            raise ValueError('ZIP expands beyond 128 MiB')
                        write(entry.filename, archive.read(entry), archive=True)
            except BadZipFile:
                raise ValueError(f'{name}: invalid ZIP archive') from None
        else:
            write(name, data)
    if not supported:
        raise ValueError('No supported inputs found. ZIP files must contain captures, source code, AWS exports, supported configuration or certificates/keys.')
    return warnings
