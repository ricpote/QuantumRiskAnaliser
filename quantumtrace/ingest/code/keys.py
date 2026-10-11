"""Key material at rest: X.509 certificates, CSRs, private / public keys, SSH keys, PKCS#12.

Reads PEM (any number of blocks per file), DER, OpenSSH and authorized_keys / known_hosts
lines with `cryptography`. Nothing is decrypted or executed: an encrypted key is reported
from its unencrypted header when the format has one (OpenSSH, legacy PEM), otherwise as a
warning. The algorithm also comes from the SubjectPublicKeyInfo / PKCS#8 OID, so PQ keys
(ML-DSA, SLH-DSA, ML-KEM) are recognised even where the local OpenSSL cannot load them.

One Finding per certificate (category "certificate") or key (category "key").
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import struct
import warnings
from datetime import datetime, timezone

from ...schema import Finding

CERT_EXT = (".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle", ".csr", ".req")
KEY_EXT = (".key", ".pub", ".p8", ".pk8")
P12_EXT = (".p12", ".pfx")
KEYSTORE_EXT = (".jks", ".keystore", ".bks", ".jceks", ".kdb", ".gpg", ".pgp")
BINARY_EXT = (".jar", ".war", ".ear", ".class", ".so", ".dll", ".dylib", ".exe", ".bin", ".apk", ".aar", ".a", ".o", ".wasm")
KEY_NAMES = re.compile(r"^(id_(rsa|dsa|ecdsa|ecdsa_sk|ed25519|ed25519_sk|xmss)(\.pub)?|ssh_host_\w+_key(\.pub)?|authorized_keys2?|known_hosts)$")
PEM_RX = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)
SSH_KEY_RX = re.compile(r"(?:^|\s)((?:sk-)?(?:ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp(?:256|384|521))(?:@openssh\.com)?)\s+(AAAA[0-9A-Za-z+/=]+)")
MAX_BYTES = 2 * 1024 * 1024

CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "secp256k1"}
CURVE_OIDS = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1"}
# SubjectPublicKeyInfo / PKCS#8 algorithm OIDs -> (algorithm, params)
KEY_OIDS = {
    "1.2.840.113549.1.1.1": ("RSA", {}), "1.2.840.113549.1.1.10": ("RSA", {"padding": "PSS"}),
    "1.2.840.10045.2.1": ("ECDSA", {}), "1.2.840.10040.4.1": ("DSA", {}), "1.2.840.113549.1.3.1": ("DH", {}),
    "1.3.101.110": ("X25519", {}), "1.3.101.111": ("X448", {}), "1.3.101.112": ("Ed25519", {}), "1.3.101.113": ("Ed448", {}),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA", {"parameter_set": "ML-DSA-44"}),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA", {"parameter_set": "ML-DSA-65"}),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA", {"parameter_set": "ML-DSA-87"}),
    "2.16.840.1.101.3.4.4.1": ("ML-KEM", {"parameter_set": "ML-KEM-512"}),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM", {"parameter_set": "ML-KEM-768"}),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM", {"parameter_set": "ML-KEM-1024"}),
    **{f"2.16.840.1.101.3.4.3.{n}": ("SLH-DSA", {"parameter_set": ps}) for n, ps in zip(range(20, 32), (
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"))},
}
SSH_TYPES = {"ssh-rsa": ("RSA", {}), "ssh-dss": ("DSA", {"key_bits": 1024}), "ssh-ed25519": ("Ed25519", {}), "ssh-ed448": ("Ed448", {}),
             "ecdsa-sha2-nistp256": ("ECDSA", {"curve": "P-256"}), "ecdsa-sha2-nistp384": ("ECDSA", {"curve": "P-384"}),
             "ecdsa-sha2-nistp521": ("ECDSA", {"curve": "P-521"}),
             "sk-ssh-ed25519@openssh.com": ("Ed25519", {"hardware": "FIDO"}), "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", {"curve": "P-256", "hardware": "FIDO"})}


def kind(path: str) -> str | None:
    """'keys' for key material we read, 'keystore' / 'binary' for files we can only report, else None."""
    name = os.path.basename(path)
    low = name.lower()
    if KEY_NAMES.match(name) or low.endswith(CERT_EXT + KEY_EXT + P12_EXT):
        return "keys"
    if low.endswith(KEYSTORE_EXT):
        return "keystore"
    if low.endswith(BINARY_EXT):
        return "binary"
    return None


def sniff(path: str) -> bool:
    """A small text file of another type (.txt, .env, .yaml...) that embeds a PEM block."""
    try:
        if os.path.getsize(path) > 256 * 1024:
            return False
        with open(path, "rb") as fh:
            return b"-----BEGIN " in fh.read()
    except OSError:
        return False


# ----------------------------------------------------------------------------- DER helpers
def _der_oids(der: bytes, limit: int = 4) -> list[str]:
    """OIDs in DER order (enough to read the algorithm and EC curve of an SPKI / PKCS#8 / cert)."""
    out, i = [], 0
    while i < len(der) - 2 and len(out) < limit:
        tag = der[i]
        n, j = der[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            if k == 0 or k > 4 or j + k > len(der):
                return out
            n, j = int.from_bytes(der[j:j + k], "big"), j + k
        if tag == 0x06 and j + n <= len(der):
            b = der[j:j + n]
            parts, v = [b[0] // 40, b[0] % 40], 0
            for x in b[1:]:
                v = (v << 7) | (x & 0x7F)
                if not x & 0x80:
                    parts.append(v)
                    v = 0
            out.append(".".join(map(str, parts)))
            i = j + n
        elif tag in (0x30, 0x31, 0xA0, 0xA1, 0xA3):  # constructed: walk inside
            i = j
        else:
            i = j + n
    return out


def _from_oids(der: bytes) -> tuple[str, dict] | None:
    oids = _der_oids(der, 6)
    for k, oid in enumerate(oids):
        if oid in KEY_OIDS:
            alg, params = KEY_OIDS[oid]
            params = dict(params)
            if alg == "ECDSA" and k + 1 < len(oids):
                params["curve"] = CURVE_OIDS.get(oids[k + 1], oids[k + 1])
            return alg, params
    return None


def _describe_key(key) -> tuple[str, dict]:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
    with warnings.catch_warnings():  # cryptography deprecates FFDH; we only recognise it, never use it
        warnings.simplefilter("ignore")
        from cryptography.hazmat.primitives.asymmetric import dh
        dh_types = (dh.DHPublicKey, dh.DHPrivateKey)
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        pub = key if isinstance(key, rsa.RSAPublicKey) else key.public_key()
        return "RSA", {"key_bits": key.key_size, "public_exponent": pub.public_numbers().e}
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ECDSA", {"curve": CURVES.get(key.curve.name, key.curve.name)}
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", {"key_bits": key.key_size}
    if isinstance(key, dh_types):
        return "DH", {"key_bits": key.key_size}
    for types, alg in (((ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey), "Ed25519"), ((ed448.Ed448PublicKey, ed448.Ed448PrivateKey), "Ed448"),
                       ((x25519.X25519PublicKey, x25519.X25519PrivateKey), "X25519"), ((x448.X448PublicKey, x448.X448PrivateKey), "X448")):
        if isinstance(key, types):
            return alg, {}
    name = type(key).__name__.lower()
    for tag, alg in (("mldsa", "ML-DSA"), ("mlkem", "ML-KEM")):
        if tag in name:
            m = re.search(r"(\d+)", type(key).__name__)
            return alg, ({"parameter_set": f"{alg}-{m.group(1)}"} if m else {})
    return "UNKNOWN-KEY", {}


def _hash_name(h) -> str | None:
    return h.name.upper().replace("SHA", "SHA-").replace("SHA-3", "SHA3") if h is not None else None


# ----------------------------------------------------------------------------- findings
def _cert_finding(c, rel, line, fmt, csr=False) -> Finding:
    from cryptography import x509
    try:
        alg, params = _describe_key(c.public_key())
    except Exception:  # e.g. a PQ key the local OpenSSL cannot load: read the SPKI OID instead
        alg, params = KEY_OIDS.get(c.public_key_algorithm_oid.dotted_string, ("UNKNOWN-KEY", {}))
        params = dict(params)
    try:
        h = _hash_name(c.signature_hash_algorithm)
    except Exception:
        h = None
    sig_oid = c.signature_algorithm_oid
    sig_name = getattr(sig_oid, "_name", None) or sig_oid.dotted_string
    if sig_oid.dotted_string in KEY_OIDS:  # ML-DSA / SLH-DSA / EdDSA signatures carry no separate hash
        sig_name = KEY_OIDS[sig_oid.dotted_string][1].get("parameter_set") or KEY_OIDS[sig_oid.dotted_string][0]
    params.update(hash=h, signature_algorithm=sig_name, key_algorithm=alg)
    cn = next((a.value for a in c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)), None)
    flags, ctx = [], dict(format=fmt)
    if csr:
        ev = f"certificate signing request CN={cn} ({alg}{' ' + str(params.get('key_bits')) if params.get('key_bits') else ''}), signed {sig_name}"
        return Finding(source="code", category="key", algorithm=alg, params=dict(params, key_type="public"),
                       asset=dict(kind="key-file", path=rel, language="pem", alias=f"CSR {cn or os.path.basename(rel)}"),
                       location=dict(file=rel, line=line), context=dict(ctx, csr=True), evidence=ev)
    nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    now = _now()
    info = dict(subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(), not_before=nb.isoformat(), not_after=na.isoformat(),
                serial=hex(c.serial_number), self_signed=c.subject == c.issuer)
    ev = f"X.509 certificate {info['subject']} ({alg}{'-' + str(params['key_bits']) if params.get('key_bits') else ''}), signed {sig_name}"
    if na < now:
        flags.append("expired")
        ev += f"; EXPIRED on {na.date()} ({(now - na).days} days ago)"
    elif (na - now).days <= 45:
        flags.append("expiring-soon")
        ev += f"; expires in {(na - now).days} days ({na.date()})"
    try:
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            flags.append("long-lived")
            ctx["ca"] = True
            ev += "; CA certificate"
    except x509.ExtensionNotFound:
        pass
    try:
        eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.CODE_SIGNING in eku:
            flags.append("long-lived")
            ev += "; code signing"
    except x509.ExtensionNotFound:
        pass
    return Finding(source="code", category="certificate", algorithm=alg, params=params,
                   asset=dict(kind="certificate-file", path=rel, language="pem", domain=cn or info["subject"]),
                   location=dict(file=rel, line=line), context=dict(ctx, certificate=info, not_before=info["not_before"], not_after=info["not_after"]),
                   evidence=ev, flags=sorted(set(flags)))


def _key_finding(alg, params, rel, line, private, fmt, encrypted=False, what="") -> Finding:
    flags = []
    ev = f"{'private' if private else 'public'} {alg} key{' ' + str(params['key_bits']) + '-bit' if params.get('key_bits') else ''}" \
         f"{' (' + params['curve'] + ')' if params.get('curve') else ''} in {fmt} {what}".strip()
    if private and not encrypted:
        flags.append("hardcoded-key")
        ev += ": unencrypted private key stored in the scanned tree (treat it as compromised)"
    elif private:
        flags.append("passphrase-protected")
        ev += " (passphrase-protected)"
    return Finding(source="code", category="key", algorithm=alg, params=dict(params, key_type="private" if private else "public"),
                   asset=dict(kind="key-file", path=rel, language="pem", alias=f"{os.path.basename(rel)}" + (f":{line}" if line > 1 else "")),
                   location=dict(file=rel, line=line), context=dict(format=fmt, encrypted=encrypted), evidence=ev, flags=flags)


def _openssh_private(blob: bytes) -> tuple[str, dict, bool] | None:
    """openssh-key-v1: cipher name and the public key are stored unencrypted."""
    magic = b"openssh-key-v1\x00"
    if not blob.startswith(magic):
        return None
    i = len(magic)

    def string():
        nonlocal i
        (n,) = struct.unpack(">I", blob[i:i + 4])
        s = blob[i + 4:i + 4 + n]
        i += 4 + n
        return s
    cipher = string()
    string()  # kdf name
    string()  # kdf options
    i += 4    # number of keys
    pub = string()
    ktype = pub[4:4 + struct.unpack(">I", pub[:4])[0]].decode(errors="replace")
    alg, params = SSH_TYPES.get(ktype, (ktype, {}))
    params = dict(params)
    if alg == "RSA":
        try:
            from cryptography.hazmat.primitives.serialization import load_ssh_public_key
            alg, params = _describe_key(load_ssh_public_key(ktype.encode() + b" " + base64.b64encode(pub)))
        except Exception:
            pass
    return alg, params, cipher != b"none"


def _pem_block(label: str, der: bytes, header: bytes, pem: bytes, rel: str, line: int, problems: list | None) -> list[Finding]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as S
    label = label.upper()
    try:
        if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
            return [_cert_finding(x509.load_der_x509_certificate(der), rel, line, "PEM")]
        if label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
            return [_cert_finding(x509.load_der_x509_csr(der), rel, line, "PEM", csr=True)]
        if label == "OPENSSH PRIVATE KEY":
            r = _openssh_private(der)
            if r:
                return [_key_finding(r[0], r[1], rel, line, True, "OpenSSH", encrypted=r[2])]
        if label == "ENCRYPTED PRIVATE KEY":
            _warn(problems, rel, "encrypted PKCS#8 private key: its algorithm is not readable without the passphrase (not analysed)")
            return []
        if label.endswith("PRIVATE KEY"):
            encrypted = b"ENCRYPTED" in header
            legacy = {"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "ECDSA", "DSA PRIVATE KEY": "DSA"}.get(label)
            if encrypted and legacy:
                return [_key_finding(legacy, {}, rel, line, True, "PEM", encrypted=True)]
            try:
                key = S.load_der_private_key(der, password=None) if not legacy else S.load_pem_private_key(pem, password=None)
                alg, params = _describe_key(key)
            except Exception:
                alg, params = _from_oids(der) or (legacy or "UNKNOWN-KEY", {})
            return [_key_finding(alg, params, rel, line, True, "PEM")]
        if label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            try:
                key = S.load_der_public_key(der) if label == "PUBLIC KEY" else S.load_pem_public_key(pem)
                alg, params = _describe_key(key)
            except Exception:
                alg, params = _from_oids(der) or ("RSA" if label.startswith("RSA") else "UNKNOWN-KEY", {})
            return [_key_finding(alg, params, rel, line, False, "PEM")]
        if label in ("DH PARAMETERS", "X9.42 DH PARAMETERS"):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                p = S.load_pem_parameters(pem)
            bits = p.parameter_numbers().p.bit_length()
            return [Finding(source="code", category="key-exchange", algorithm="DH", params=dict(key_bits=bits),
                            asset=dict(kind="key-file", path=rel, language="pem"), location=dict(file=rel, line=line),
                            evidence=f"DH parameters ({bits}-bit prime) in PEM")]
    except Exception as e:
        _warn(problems, rel, f"unreadable {label.title()} block at line {line} ({type(e).__name__})")
        return []
    if label not in ("PKCS7", "X509 CRL", "PARAMETERS", "EC PARAMETERS", "PGP SIGNATURE", "SIGNATURE"):
        _warn(problems, rel, f"PEM block '{label}' at line {line} is not analysed")
    return []


def _warn(problems, path, reason):
    if problems is not None:
        problems.append(dict(path=path, reason=reason))


def _now():
    v = os.environ.get("QT_NOW")
    if v:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    return datetime.now(timezone.utc)


def scan(path: str, rel: str, problems: list | None = None) -> list[Finding]:
    """Every certificate / key in one file. Never raises for bad content: it warns instead."""
    k = kind(path)
    if k == "keystore":
        _warn(problems, rel, "Java/PGP keystore: not analysed (export the certificates as PEM to include them)")
        return []
    if k == "binary":
        _warn(problems, rel, "binary artifact: not analysed (QuantumTrace reads source code, configs, captures, cloud exports and key material)")
        return []
    if os.path.getsize(path) > MAX_BYTES:
        _warn(problems, rel, "key/certificate file larger than 2 MiB: not analysed")
        return []
    data = open(path, "rb").read()
    low = path.lower()
    out: list[Finding] = []
    if low.endswith(P12_EXT):
        from cryptography.hazmat.primitives.serialization import pkcs12
        for pw in (None, b""):
            try:
                key, cert, extra = pkcs12.load_key_and_certificates(data, pw)
            except Exception:
                continue
            if key is not None:
                alg, params = _describe_key(key)
                out.append(_key_finding(alg, params, rel, 1, True, "PKCS#12 (no password)"))
            for c in [cert, *(extra or [])]:
                if c is not None:
                    out.append(_cert_finding(c, rel, 1, "PKCS#12"))
            return out
        _warn(problems, rel, "password-protected PKCS#12 keystore: not analysed")
        return []
    blocks = list(PEM_RX.finditer(data))
    if blocks:
        for m in blocks:
            line = data[:m.start()].count(b"\n") + 1
            body = m.group(2).replace(b"\r\n", b"\n")
            header, _, b64 = body.rpartition(b"\n\n") if b"Proc-Type" in body else (b"", b"", body)
            try:
                der = base64.b64decode(re.sub(rb"\s+", b"", b64), validate=True)
            except (binascii.Error, ValueError):
                _warn(problems, rel, f"invalid base64 in PEM block at line {line}")
                continue
            out += _pem_block(m.group(1).decode(), der, header, m.group(0), rel, line, problems)
        return out
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        for n, ln in enumerate(text.splitlines(), 1):
            if ln.lstrip().startswith("#"):
                continue
            for m in SSH_KEY_RX.finditer(ln):
                ktype, b64 = m.group(1), m.group(2)
                alg, params = SSH_TYPES.get(ktype, (ktype, {}))
                params = dict(params)
                try:
                    if not ktype.startswith("sk-"):
                        alg, params = _describe_key(load_ssh_public_key(f"{ktype} {b64}".encode()))
                except Exception:
                    pass
                what = "known_hosts entry" if "known_hosts" in low else "authorized_keys entry" if "authorized_keys" in low else ""
                out.append(_key_finding(alg, params, rel, n, False, "OpenSSH", what=what))
        if out or not low.endswith((".der", ".cer", ".crt")):
            if not out and kind(path) == "keys":
                _warn(problems, rel, "no certificate or key found in this file")
            return out
    # DER: certificate, then public / private key
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as S
    for loader in (lambda: [_cert_finding(x509.load_der_x509_certificate(data), rel, 1, "DER")],
                   lambda: [_key_finding(*_describe_key(S.load_der_public_key(data)), rel, 1, False, "DER")],
                   lambda: [_key_finding(*_describe_key(S.load_der_private_key(data, None)), rel, 1, True, "DER")]):
        try:
            return loader()
        except Exception:
            continue
    guess = _from_oids(data)
    if guess:
        return [_key_finding(guess[0], guess[1], rel, 1, False, "DER")]
    _warn(problems, rel, "not a readable certificate or key (PEM, DER, OpenSSH or PKCS#12)")
    return []
