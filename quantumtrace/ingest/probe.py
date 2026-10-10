"""Active TLS probe: raw ClientHellos built by hand (no OpenSSL PQ support needed).

What it measures for host:port (optionally through STARTTLS / Postgres SSLRequest):
  * protocol versions accepted (TLS 1.3 / 1.2 / 1.1 / 1.0 / SSL 3.0)
  * what a MODERN client gets: Chrome-like hello offering X25519MLKEM768 + X25519 key shares
    -> negotiated group & cipher. We then DECRYPT our own TLS 1.3 handshake (ML-KEM
    decapsulation + TLS 1.3 key schedule) to read the certificate chain and the
    CertificateVerify signature scheme, so authentication is measured, not guessed.
  * every key-exchange group the server accepts (ML-KEM hybrids, pure ML-KEM, pre-standard
    Kyber, ECDH curves, FFDHE), one ClientHello per group with a real key share
  * TLS 1.3 cipher suites, TLS 1.2 cipher suites (iterative: offer all, remove the chosen one)
  * --deep: signature schemes the server can authenticate with (incl. ML-DSA)
Only ClientHello/ServerHello-level traffic plus decryption of the server's first flight;
we never send application data.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import time
from datetime import datetime, timezone

from ..kb import tls as TLS
from ..schema import Finding

# ---------------------------------------------------------------------------- constants
TLS13_SUITES = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate",
          47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
          80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
          110: "unsupported_extension", 112: "unrecognized_name", 120: "no_application_protocol"}
# groups tested one by one, PQ first
PROBE_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202, 0x0200, 0x6399,
                0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102]
CHROME_GROUPS = [0x11EC, 0x001D, 0x0017, 0x0018]
# Chrome 131+ cipher list (TLS 1.3 + TLS 1.2 fallback incl. legacy CBC/RSA suites)
CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SIGALGS_ALL = [0x0905, 0x0904, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
               0x0807, 0x0808, 0x0603, 0x0201, 0x0203]
SIG_FAMILIES = {"ML-DSA": [0x0904, 0x0905, 0x0906], "Ed25519": [0x0807], "Ed448": [0x0808],
                "ECDSA": [0x0403, 0x0503, 0x0603], "RSA-PSS": [0x0804, 0x0805, 0x0806], "RSA-PKCS1": [0x0401, 0x0501, 0x0601, 0x0201]}
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 2525: "smtp", 143: "imap", 110: "pop3", 21: "ftp", 5432: "postgres", 5433: "postgres"}


def _tls12_suites():
    out = []
    for code in TLS._suites():
        if code in TLS13_SUITES or code in (0x00FF, 0x5600) or code in TLS.GREASE:
            continue
        out.append(code)
    return out


# ---------------------------------------------------------------------------- encoding helpers
def _u8(n):
    return struct.pack("!B", n)


def _u16(n):
    return struct.pack("!H", n)


def _u24(n):
    return struct.pack("!I", n)[1:]


def _v8(b):
    return _u8(len(b)) + b


def _v16(b):
    return _u16(len(b)) + b


def _v24(b):
    return _u24(len(b)) + b


def _ext(t, body):
    return _u16(t) + _v16(body)


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------- key shares
class KeyShare:
    """Client key share for one group, able to compute the shared secret afterwards."""

    def __init__(self, group: int):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
        self.group, self.parts = group, []
        raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
        pt = serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        curves = {0x0017: ec.SECP256R1(), 0x0018: ec.SECP384R1(), 0x0019: ec.SECP521R1()}

        def x25519_part():
            k = x25519.X25519PrivateKey.generate()
            return ("x25519", k, k.public_key().public_bytes(*raw))

        def ec_part(code):
            k = ec.generate_private_key(curves[code])
            return ("ec", k, k.public_key().public_bytes(*pt))

        def mlkem_part(level):
            try:
                from cryptography.hazmat.primitives.asymmetric import mlkem
                k = (mlkem.MLKEM768PrivateKey if level == 768 else mlkem.MLKEM1024PrivateKey).generate()
                return ("mlkem", k, k.public_key().public_bytes_raw())
            except Exception:  # no ML-KEM in this cryptography build: valid-encoding probe key (cannot decrypt)
                n = {512: 2, 768: 3, 1024: 4}[level]
                return ("mlkem-probe", None, b"\x00" * (384 * n) + os.urandom(32))

        if group == 0x001D:
            self.parts = [x25519_part()]
        elif group in curves:
            self.parts = [ec_part(group)]
        elif group == 0x001E:
            k = x448.X448PrivateKey.generate()
            self.parts = [("x448", k, k.public_key().public_bytes(*raw))]
        elif group == 0x11EC:      # X25519MLKEM768: ML-KEM first, then X25519
            self.parts = [mlkem_part(768), x25519_part()]
        elif group == 0x11EB:      # SecP256r1MLKEM768: ECDH first
            self.parts = [ec_part(0x0017), mlkem_part(768)]
        elif group == 0x11ED:      # SecP384r1MLKEM1024: ECDH first
            self.parts = [ec_part(0x0018), mlkem_part(1024)]
        elif group == 0x0201:
            self.parts = [mlkem_part(768)]
        elif group == 0x0202:
            self.parts = [mlkem_part(1024)]
        elif group == 0x0200:
            self.parts = [mlkem_part(512)]
        elif group == 0x6399:      # X25519Kyber768Draft00: X25519 first (pre-standard Kyber; probe-only key)
            self.parts = [x25519_part(), ("mlkem-probe", None, b"\x00" * 1152 + os.urandom(32))]
        elif group in (0x0100, 0x0101, 0x0102):
            size = {0x0100: 256, 0x0101: 384, 0x0102: 512}[group]
            self.parts = [("ffdhe-probe", None, b"\x7f" + os.urandom(size - 1))]
        else:
            self.parts = []
        self.data = b"".join(p[2] for p in self.parts)

    def shared_secret(self, server: bytes) -> bytes | None:
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        out, off = b"", 0
        for kind, key, pub in self.parts:
            if kind == "x25519":
                out += key.exchange(x25519.X25519PublicKey.from_public_bytes(server[off:off + 32]))
                off += 32
            elif kind == "ec":
                n = len(pub)
                peer = ec.EllipticCurvePublicKey.from_encoded_point(key.curve, server[off:off + n])
                out += key.exchange(ec.ECDH(), peer)
                off += n
            elif kind == "mlkem":
                n = 1088 if len(pub) == 1184 else 1568
                out += key.decapsulate(server[off:off + n])
                off += n
            else:
                return None
        return out


# ---------------------------------------------------------------------------- ClientHello
def client_hello(host: str | None, *, versions=(0x0304, 0x0303), ciphers=(0x1301, 0x1302, 0x1303), groups=CHROME_GROUPS,
                 shares=(), sigalgs=SIGALGS_ALL, legacy_version=0x0303, alpn=("h2", "http/1.1")) -> bytes:
    exts = b""
    if host and not _is_ip(host):
        exts += _ext(0x0000, _v16(_u8(0) + _v16(host.encode())))
    if groups:
        exts += _ext(0x000A, _v16(b"".join(_u16(g) for g in groups)))
    exts += _ext(0x000B, _v8(b"\x00"))
    exts += _ext(0x000D, _v16(b"".join(_u16(s) for s in sigalgs)))
    if alpn:
        exts += _ext(0x0010, _v16(b"".join(_v8(p.encode()) for p in alpn)))
    exts += _ext(0x0017, b"")
    exts += _ext(0xFF01, b"\x00")
    if 0x0304 in versions:
        exts += _ext(0x002B, _v8(b"".join(_u16(v) for v in versions)))
        exts += _ext(0x002D, _v8(b"\x01"))
        exts += _ext(0x0033, _v16(b"".join(_u16(s.group) + _v16(s.data) for s in shares)))
    body = _u16(legacy_version) + os.urandom(32) + _v8(os.urandom(32)) + _v16(b"".join(_u16(c) for c in ciphers)) + _v8(b"\x00") + _v16(exts)
    return _u8(1) + _v24(body)  # handshake message (record framing added by caller)


def _record(ctype: int, payload: bytes, version=0x0301) -> bytes:
    return _u8(ctype) + _u16(version) + _v16(payload)


# ---------------------------------------------------------------------------- TLS 1.3 key schedule
def _hkdf_extract(h, salt, ikm):
    return hmac.new(salt, ikm, h).digest()


def _hkdf_expand_label(h, secret, label, context, length):
    info = _u16(length) + _v8(b"tls13 " + label) + _v8(context)
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def _server_hs_keys(suite: int, shared: bytes, transcript: bytes):
    h = hashlib.sha384 if suite == 0x1302 else hashlib.sha256
    hl = h().digest_size
    early = _hkdf_extract(h, b"\x00" * hl, b"\x00" * hl)
    derived = _hkdf_expand_label(h, early, b"derived", h(b"").digest(), hl)
    hs = _hkdf_extract(h, derived, shared)
    s_hs = _hkdf_expand_label(h, hs, b"s hs traffic", h(transcript).digest(), hl)
    klen = 16 if suite in (0x1301, 0x1304, 0x1305) else 32
    return _hkdf_expand_label(h, s_hs, b"key", b"", klen), _hkdf_expand_label(h, s_hs, b"iv", b"", 12)


def _aead(suite, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
    if suite == 0x1303:
        return ChaCha20Poly1305(key)
    if suite in (0x1304, 0x1305):
        return AESCCM(key, tag_length=16 if suite == 0x1304 else 8)
    return AESGCM(key)


# ---------------------------------------------------------------------------- one connection
class Conn:
    def __init__(self, host, port, ip=None, starttls=None, timeout=4.0):
        self.host, self.port, self.ip, self.starttls, self.timeout = host, port, ip or host, starttls, timeout
        self.sock = None
        self.buf = b""

    def __enter__(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        if self.starttls:
            _starttls(self.sock, self.starttls)
        return self

    def __exit__(self, *a):
        try:
            self.sock.close()
        except Exception:
            pass

    def send(self, b):
        self.sock.sendall(b)

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def record(self):
        hdr = self._read(5)
        ctype, ver, ln = struct.unpack("!BHH", hdr)
        return ctype, hdr, self._read(ln)


def _starttls(sock, proto):
    f = sock.makefile("rb")

    def line():
        return f.readline().decode(errors="replace")

    def until(prefix_ok):
        while True:
            l = line()
            if not l:
                raise ConnectionError("STARTTLS: connection closed")
            if prefix_ok(l):
                return l

    if proto == "smtp":
        until(lambda l: l[:3] == "220" and l[3:4] == " ")
        sock.sendall(b"EHLO qtrace.local\r\n")
        l = until(lambda l: l[:3] == "250" and l[3:4] == " " or l[:1] in "45")
        sock.sendall(b"STARTTLS\r\n")
        l = until(lambda l: l[3:4] == " ")
        if not l.startswith("220"):
            raise ConnectionError(f"SMTP STARTTLS refused: {l.strip()}")
    elif proto == "imap":
        until(lambda l: l.startswith("* "))
        sock.sendall(b"a1 STARTTLS\r\n")
        l = until(lambda l: l.startswith("a1 "))
        if "OK" not in l.upper():
            raise ConnectionError(f"IMAP STARTTLS refused: {l.strip()}")
    elif proto == "pop3":
        until(lambda l: l.startswith(("+OK", "-ERR")))
        sock.sendall(b"STLS\r\n")
        if not until(lambda l: l.startswith(("+OK", "-ERR"))).startswith("+OK"):
            raise ConnectionError("POP3 STLS refused")
    elif proto == "ftp":
        until(lambda l: l[:3] == "220" and l[3:4] == " ")
        sock.sendall(b"AUTH TLS\r\n")
        if not until(lambda l: l[3:4] == " ").startswith("234"):
            raise ConnectionError("FTP AUTH TLS refused")
    elif proto == "postgres":
        sock.sendall(struct.pack("!II", 8, 80877103))
        r = sock.recv(1)
        if r != b"S":
            raise ConnectionError("Postgres server refused SSLRequest")
    # NB: makefile shares the socket; we never read past the server's final STARTTLS line
    f.detach() if hasattr(f, "detach") else None


def _parse_server_hello(msg: bytes) -> dict:
    ver = struct.unpack("!H", msg[0:2])[0]
    rnd = msg[2:34]
    sid_len = msg[34]
    p = 35 + sid_len
    cipher = struct.unpack("!H", msg[p:p + 2])[0]
    p += 3
    exts = {}
    if p + 2 <= len(msg):
        end = p + 2 + struct.unpack("!H", msg[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            t, ln = struct.unpack("!HH", msg[p:p + 4])
            exts[t] = msg[p + 4:p + 4 + ln]
            p += 4 + ln
    hrr = rnd.hex() == TLS.HRR_RANDOM
    out = dict(legacy_version=ver, version=ver, cipher=cipher, hrr=hrr, extensions=sorted(exts),
               downgrade=rnd[-8:] in (b"DOWNGRD\x01", b"DOWNGRD\x00"))
    if 0x002B in exts and len(exts[0x002B]) >= 2:
        out["version"] = struct.unpack("!H", exts[0x002B][:2])[0]
    if 0x0033 in exts:
        ks = exts[0x0033]
        out["group"] = struct.unpack("!H", ks[:2])[0]
        if not hrr and len(ks) >= 4:
            n = struct.unpack("!H", ks[2:4])[0]
            out["key_share"] = ks[4:4 + n]
    return out


def _certs12(msg):
    p, end, out = 3, 3 + int.from_bytes(msg[:3], "big"), []
    while p + 3 <= end:
        n = int.from_bytes(msg[p:p + 3], "big")
        out.append(msg[p + 3:p + 3 + n])
        p += 3 + n
    return out


def _certs13(msg):
    ctx_len = msg[0]
    p = 1 + ctx_len
    end = p + 3 + int.from_bytes(msg[p:p + 3], "big")
    p += 3
    out = []
    while p + 3 <= end:
        n = int.from_bytes(msg[p:p + 3], "big")
        out.append(msg[p + 3:p + 3 + n])
        p += 3 + n
        p += 2 + struct.unpack("!H", msg[p:p + 2])[0]  # per-certificate extensions
    return out


def handshake(host, port, *, ip=None, starttls=None, timeout=4.0, decrypt=False, **hello_kw) -> dict:
    """Send one ClientHello and collect the server's answer (ServerHello/HRR/alert/certs...)."""
    shares = hello_kw.get("shares", ())
    res = dict(ok=False, alert=None, error=None, sh=None, certs=[], ske=None, cert_verify=None, encrypted_extensions=None)
    ch = client_hello(host, **hello_kw)
    try:
        with Conn(host, port, ip, starttls, timeout) as c:
            c.send(_record(0x16, ch))
            hs_buf = b""
            transcript = ch
            keys = None
            seq = 0
            t_end = time.time() + timeout
            while time.time() < t_end:
                ctype, hdr, payload = c.record()
                if ctype == 0x15:
                    res["alert"] = ALERTS.get(payload[1], str(payload[1])) if len(payload) >= 2 else "alert"
                    return res
                if ctype == 0x14:  # ChangeCipherSpec (compat)
                    continue
                if ctype == 0x17:  # encrypted (TLS 1.3)
                    if not keys:
                        return res
                    nonce = bytes(a ^ b for a, b in zip(keys[1], b"\x00" * 4 + seq.to_bytes(8, "big")))
                    seq += 1
                    try:
                        plain = _aead(res["sh"]["cipher"], keys[0]).decrypt(nonce, payload, hdr)
                    except Exception:
                        res["error"] = "could not decrypt server handshake"
                        return res
                    plain = plain.rstrip(b"\x00")
                    inner_type, plain = plain[-1], plain[:-1]
                    if inner_type == 0x15:
                        res["alert"] = ALERTS.get(plain[1], str(plain[1])) if len(plain) >= 2 else "alert"
                        return res
                    hs_buf += plain
                elif ctype == 0x16:
                    hs_buf += payload
                else:
                    return res
                while len(hs_buf) >= 4:
                    mtype, mlen = hs_buf[0], int.from_bytes(hs_buf[1:4], "big")
                    if len(hs_buf) < 4 + mlen:
                        break
                    msg, whole, hs_buf = hs_buf[4:4 + mlen], hs_buf[:4 + mlen], hs_buf[4 + mlen:]
                    if mtype == 2:
                        sh = _parse_server_hello(msg)
                        res["sh"], res["ok"] = sh, True
                        transcript += whole
                        if sh["hrr"]:
                            return res
                        if sh["version"] != 0x0304:
                            continue  # TLS <= 1.2: keep reading Certificate / ServerKeyExchange / ServerHelloDone
                        if not decrypt:
                            return res
                        share = next((s for s in shares if s.group == sh.get("group")), None)
                        ss = share.shared_secret(sh.get("key_share", b"")) if share else None
                        if not ss:
                            return res
                        keys = _server_hs_keys(sh["cipher"], ss, transcript)
                    elif mtype == 8:
                        res["encrypted_extensions"] = msg
                    elif mtype == 11:
                        res["certs"] = _certs13(msg) if keys else _certs12(msg)
                    elif mtype == 12:
                        res["ske"] = msg
                    elif mtype == 15:
                        res["cert_verify"] = struct.unpack("!H", msg[:2])[0]
                        return res
                    elif mtype in (14, 20):  # ServerHelloDone / Finished
                        return res
    except (OSError, ConnectionError, struct.error, IndexError, ValueError) as e:
        res["error"] = f"{type(e).__name__}: {e}"[:200]
    return res


# ---------------------------------------------------------------------------- the probe
def probe(target: str, *, starttls: str | None = "auto", timeout: float = 4.0, deep: bool = False, log=None) -> dict:
    """Probe one endpoint. target = host[:port]. Returns a raw report dict (see to_findings)."""
    host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "443")
    if target.startswith("["):  # [ipv6]:port
        host, port = target[1:].split("]:")
    port = int(port or 443)
    if starttls == "auto":
        starttls = STARTTLS_PORTS.get(port)
    elif starttls == "none":
        starttls = None
    ip = socket.gethostbyname(host) if not _is_ip(host) else host
    sni = None if _is_ip(host) else host
    t0 = time.time()
    rep = dict(target=f"{host}:{port}", host=host, ip=ip, port=port, starttls=starttls, started=datetime.now(timezone.utc).isoformat(),
               versions={}, groups={}, tls13_ciphers=[], tls12_ciphers=[], modern=None, sigalg_families={}, certs=[], errors=[], connections=0)
    say = log or (lambda *_: None)

    def hs(**kw):
        rep["connections"] += 1
        return handshake(sni, port, ip=ip, starttls=starttls, timeout=timeout, **kw)

    # 1) modern client (Chrome-like): PQ hybrid + X25519 key shares; decrypt to read cert + CertificateVerify
    say("modern client hello")
    shares = [KeyShare(0x11EC), KeyShare(0x001D)]
    r = hs(versions=(0x0304, 0x0303), ciphers=CHROME_CIPHERS,
           groups=CHROME_GROUPS, shares=shares, decrypt=True)
    if r["error"] and not r["ok"]:
        rep["errors"].append(f"modern hello: {r['error']}")
        if r["error"].startswith(("ConnectionRefusedError", "TimeoutError", "timeout", "OSError", "gaierror")):
            rep["duration_s"] = round(time.time() - t0, 2)
            return rep  # dead host/port: do not burn 30 more timeouts
    if r["ok"]:
        sh = r["sh"]
        rep["modern"] = dict(version=TLS.VERSIONS.get(sh["version"], hex(sh["version"])), cipher=TLS.suite_name(sh["cipher"]),
                             cipher_code=sh["cipher"], group=sh.get("group"), group_name=TLS.group(sh["group"])["name"] if sh.get("group") else None,
                             hrr=sh["hrr"], key_share_len=len(sh.get("key_share", b"")), cert_verify=r["cert_verify"],
                             cert_verify_name=TLS.sigscheme(r["cert_verify"])[0] if r["cert_verify"] else None, downgrade=sh["downgrade"])
        if r["certs"]:
            rep["certs"] = [_cert_info(d) for d in r["certs"]]
        if sh["version"] != 0x0304 and r["ske"] and r["ske"][0] == 3:  # TLS 1.2 fallback: ECDHE curve from ServerKeyExchange
            rep["modern"]["group"] = struct.unpack("!H", r["ske"][1:3])[0]
            rep["modern"]["group_name"] = TLS.group(rep["modern"]["group"])["name"]
    elif r["alert"]:
        rep["modern"] = dict(alert=r["alert"])

    # 2) versions
    for v, name in ((0x0304, "TLS 1.3"), (0x0303, "TLS 1.2"), (0x0302, "TLS 1.1"), (0x0301, "TLS 1.0"), (0x0300, "SSL 3.0")):
        say(f"version {name}")
        if v == 0x0304:
            rr = hs(versions=(0x0304,), groups=[0x11EC, 0x001D, 0x0017, 0x0018], shares=[KeyShare(0x001D)])
        else:
            rr = hs(versions=(), legacy_version=v, ciphers=_tls12_suites(), groups=[0x001D, 0x0017, 0x0018, 0x0019, 0x0100], alpn=None)
        got = rr["ok"] and rr["sh"]["version"] == v
        rep["versions"][name] = bool(got)
        if v == 0x0303 and got:
            if rr["certs"] and not rep["certs"]:
                rep["certs"] = [_cert_info(d) for d in rr["certs"]]

    # 3) key-exchange groups (TLS 1.3, one group + real key share per hello)
    if rep["versions"].get("TLS 1.3"):
        for g in PROBE_GROUPS:
            say(f"group 0x{g:04x}")
            ks = KeyShare(g)
            rr = hs(versions=(0x0304,), groups=[g], shares=[ks] if ks.data else [])
            ok = rr["ok"] and rr["sh"].get("group") == g
            rep["groups"][TLS.group(g)["name"]] = dict(code=g, supported=bool(ok), via="hrr" if ok and rr["sh"]["hrr"] else ("serverhello" if ok else (rr["alert"] or rr["error"])),
                                                      key_share_len=len(rr["sh"].get("key_share", b"")) if ok else None)
        # 4) TLS 1.3 cipher suites
        for c in TLS13_SUITES:
            rr = hs(versions=(0x0304,), ciphers=[c], groups=[0x11EC, 0x001D, 0x0017], shares=[KeyShare(0x001D)])
            if rr["ok"] and rr["sh"]["cipher"] == c:
                rep["tls13_ciphers"].append(TLS.suite_name(c))
        # 5) signature schemes (deep): which certificate types can the server authenticate with?
        if deep:
            for fam, algs in SIG_FAMILIES.items():
                shs = [KeyShare(0x11EC), KeyShare(0x001D)]
                rr = hs(versions=(0x0304,), groups=CHROME_GROUPS, shares=shs, sigalgs=algs, decrypt=True)
                rep["sigalg_families"][fam] = TLS.sigscheme(rr["cert_verify"])[0] if rr["cert_verify"] else False

    # 6) TLS 1.2 cipher suites (iterative removal: server preference order)
    if rep["versions"].get("TLS 1.2"):
        remaining = _tls12_suites()
        for _ in range(48):
            rr = hs(versions=(), legacy_version=0x0303, ciphers=remaining, groups=[0x001D, 0x0017, 0x0018, 0x0019, 0x0100], alpn=None)
            if not (rr["ok"] and rr["sh"]["cipher"] in remaining):
                break
            c = rr["sh"]["cipher"]
            name = TLS.suite_name(c)
            d = TLS.decompose(name)
            entry = dict(name=name, code=c, kex=d["kex"])
            if rr["ske"] and d["kex"] in ("ECDHE", "ECDH-static") and rr["ske"][0] == 3:
                entry["curve"] = TLS.group(struct.unpack("!H", rr["ske"][1:3])[0])["name"]
            elif rr["ske"] and d["kex"] in ("DHE",):
                entry["dh_bits"] = struct.unpack("!H", rr["ske"][:2])[0] * 8
            rep["tls12_ciphers"].append(entry)
            remaining.remove(c)
            say(f"tls1.2 {name}")
    if not rep["certs"]:
        rep["certs"] = _python_ssl_chain(host, ip, port, starttls, timeout)
    if rep["certs"] and sni:
        rep["name_match"] = _name_match(sni, rep["certs"][0].get("names", []))
    rep["interception_suspected"] = any(_looks_like_interception(c) for c in rep["certs"])
    rep["duration_s"] = round(time.time() - t0, 2)
    return rep


def _name_match(host, names):
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower()
        if n == host or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:]):
            return True
    return False


_INTERCEPT_HINTS = ("egress", "proxy", "zscaler", "netskope", "fortinet", "fortigate", "palo alto", "bluecoat", "forcepoint",
                    "mitmproxy", "charles", "sophos", "cisco umbrella", "untangle", "kaspersky", "eset ssl filter", "avast", "default.domain")


def _looks_like_interception(ci):
    text = (ci.get("subject", "") + " " + ci.get("issuer", "")).lower()
    return any(h in text for h in _INTERCEPT_HINTS)


def _python_ssl_chain(host, ip, port, starttls, timeout):
    """Fallback cert retrieval via the local OpenSSL (works for classical servers)."""
    import ssl
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if starttls:
            _starttls(s, starttls)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=None if _is_ip(host) else host)
        chain = ss.get_unverified_chain() if hasattr(ss, "get_unverified_chain") else [ss.getpeercert(binary_form=True)]
        ss.close()
        return [_cert_info(c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(c, "public_bytes") else c) for c in chain]
    except Exception:
        return []


def _cert_info(der: bytes) -> dict:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
        c = x509.load_der_x509_certificate(der)
    except Exception as e:
        return dict(error=str(e))
    pk = c.public_key()
    try:
        names = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        names = []
    cn = [a.value for a in c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]
    info = dict(names=list(names) + [str(x) for x in cn], subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(), not_before=c.not_valid_before_utc.isoformat(),
                not_after=c.not_valid_after_utc.isoformat(), self_signed=c.subject == c.issuer, serial=hex(c.serial_number),
                sha256=hashlib.sha256(der).hexdigest())
    if isinstance(pk, rsa.RSAPublicKey):
        info.update(algorithm="RSA", key_bits=pk.key_size)
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        info.update(algorithm="ECDSA", curve={"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(pk.curve.name, pk.curve.name))
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        info.update(algorithm="Ed25519")
    elif isinstance(pk, ed448.Ed448PublicKey):
        info.update(algorithm="Ed448")
    elif isinstance(pk, dsa.DSAPublicKey):
        info.update(algorithm="DSA", key_bits=pk.key_size)
    else:
        oid = c.public_key_algorithm_oid.dotted_string if hasattr(c, "public_key_algorithm_oid") else "?"
        info.update(algorithm={"2.16.840.1.101.3.4.3.17": "ML-DSA", "2.16.840.1.101.3.4.3.18": "ML-DSA", "2.16.840.1.101.3.4.3.19": "ML-DSA"}.get(oid, "UNKNOWN-KEY"), oid=oid)
    try:
        h = c.signature_hash_algorithm
        info["sig_hash"] = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}.get(h.name, h.name) if h else None
    except Exception:
        info["sig_hash"] = None
    info["sig_oid"] = c.signature_algorithm_oid.dotted_string
    try:
        info["is_ca"] = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except Exception:
        info["is_ca"] = False
    return info


# ---------------------------------------------------------------------------- report -> Findings
def _now():
    env = os.environ.get("QT_NOW")
    return datetime.fromisoformat(env.replace("Z", "+00:00")) if env else datetime.now(timezone.utc)


def to_findings(rep: dict) -> list[Finding]:
    asset = dict(kind="network-endpoint", host=rep["host"], ip=rep["ip"], port=rep["port"],
                 service=rep["starttls"] + "+starttls" if rep["starttls"] else ("https" if rep["port"] in (443, 8443) else f"tls/{rep['port']}"), probe=True)
    loc = dict(probe=rep["target"], time=rep["started"], connections=rep["connections"])
    ctx = dict(protocol="TLS", probe=True, versions=rep["versions"], groups={k: v["supported"] for k, v in rep["groups"].items()},
               tls13_ciphers=rep["tls13_ciphers"], tls12_ciphers=[c["name"] for c in rep["tls12_ciphers"]], modern=rep["modern"],
               sigalg_families=rep["sigalg_families"])
    base = dict(source="probe", asset=asset, location=loc, context=ctx)
    out: list[Finding] = []
    if not any(rep["versions"].values()) and not rep["modern"]:
        return out
    for v, ok in rep["versions"].items():
        if ok:
            out.append(Finding(category="protocol", algorithm="SSL" if v.startswith("SSL") else "TLS", params=dict(version=v),
                               evidence=f"server accepted a {v} ClientHello", **base))
    m = rep["modern"] or {}
    if rep.get("interception_suspected"):
        ctx["warning"] = "certificate chain looks like a TLS-intercepting proxy: results describe the PROXY, not the target"
    supported = [k for k, v in rep["groups"].items() if v["supported"]]
    pq = [k for k in supported if TLS.GROUPS.get(rep["groups"][k]["code"], {}).get("pq")]
    classical = [k for k in supported if k not in pq]
    # --- key exchange that a modern (PQ-capable) client gets
    if m.get("group"):
        g = TLS.group(m["group"])
        flags = []
        ev = f"modern client (offering X25519MLKEM768 + X25519) negotiated {m['version']} {m['cipher']} with group {g['name']}"
        if g["pq"]:
            flags.append("pq-hybrid" if g.get("hybrid") else "pq")
            exp = (g.get("ks") or (None, None))[1]
            if exp and m.get("key_share_len") == exp:
                ev += f" (server key_share {m['key_share_len']} B = FIPS 203 size)"
        elif pq:
            flags.append("pq-supported-not-preferred")
            ev += f"; the server supports {', '.join(pq)} but PREFERS classical {g['name']}: browsers get no PQ protection"
        else:
            flags.append("pq-not-supported")
        if m.get("hrr"):
            ev += " (after HelloRetryRequest)"
        out.append(Finding(category="key-exchange", algorithm=g["algorithm"], params=dict(g["params"], group=g["name"], group_id=f"0x{m['group']:04X}"),
                           evidence=ev, flags=flags, **base))
        # classical groups still accepted = exposure for clients without PQ support
        if g["pq"]:
            for name in classical:
                cg = TLS.group(rep["groups"][name]["code"])
                out.append(Finding(category="key-exchange", algorithm=cg["algorithm"], params=dict(cg["params"], group=name),
                                   evidence=f"{name} still accepted: clients without ML-KEM support fall back to classical key exchange",
                                   flags=["fallback-for-legacy-clients"], confidence=0.9, **base))
            if not classical:
                out[-1].flags.append("pq-only")
    elif m.get("alert"):
        out.append(Finding(category="key-exchange", algorithm="UNKNOWN-GROUP", params={}, confidence=0.3,
                           evidence=f"modern ClientHello rejected with alert {m['alert']}", **base))
    # --- TLS 1.2 key exchange families (any TLS 1.2 client is classical)
    seen = set()
    if m.get("version") == "TLS 1.2" and m.get("group"):
        seen.add("ECDHE")  # the modern-client finding above already covers TLS 1.2 ECDHE
    for c in rep["tls12_ciphers"]:
        k = c["kex"]
        if k in seen:
            continue
        seen.add(k)
        if k == "RSA":
            out.append(Finding(category="key-exchange", algorithm="RSA", params=dict(transport=True), flags=["no-forward-secrecy"],
                               evidence=f"TLS 1.2 RSA key transport accepted ({c['name']})", **base))
        elif k in ("ECDHE", "ECDH-static"):
            curve = c.get("curve")
            if curve and any(f.category == "key-exchange" and f.params.get("group") == curve for f in out):
                continue  # same group already reported (TLS 1.3 fallback or modern client)
            code = next((cc for cc, gg in TLS.GROUPS.items() if gg["name"] == curve), None)
            gg = TLS.group(code) if code is not None else dict(algorithm="ECDHE", params={})
            alg = "ECDHE" if gg["algorithm"] in ("ECDH", "UNKNOWN-GROUP") else gg["algorithm"]
            out.append(Finding(category="key-exchange", algorithm=alg,
                               params=dict(gg["params"], group=curve),
                               flags=["fallback-for-legacy-clients"] if pq else [],
                               evidence=f"TLS 1.2 {c['name']} ECDHE over {curve or '?'}", **base))
        elif k == "DHE":
            out.append(Finding(category="key-exchange", algorithm="DHE", params=dict(key_bits=c.get("dh_bits")),
                               evidence=f"TLS 1.2 {c['name']} finite-field DHE {c.get('dh_bits') or '?'}-bit", **base))
    # --- authentication: measured CertificateVerify (TLS 1.3) or cert key
    leaf = rep["certs"][0] if rep["certs"] else None
    if m.get("cert_verify"):
        name, alg, params = TLS.sigscheme(m["cert_verify"])
        p = dict(params)
        if leaf and leaf.get("key_bits"):
            p["key_bits"] = leaf["key_bits"]
        out.append(Finding(category="authentication", algorithm=alg, params=p,
                           evidence=f"CertificateVerify signed with {name} (read by decrypting our own TLS 1.3 handshake)", **base))
    elif leaf and leaf.get("algorithm"):
        out.append(Finding(category="authentication", algorithm=leaf["algorithm"], params={k: leaf[k] for k in ("key_bits", "curve") if leaf.get(k)},
                           evidence=f"server certificate key {leaf['algorithm']}", **base))
    for fam, got in (rep["sigalg_families"] or {}).items():
        if got and fam == "ML-DSA":
            out.append(Finding(category="authentication", algorithm="ML-DSA", params=dict(parameter_set=got.replace("mldsa", "ML-DSA-")),
                               evidence=f"server can authenticate with {got} (post-quantum certificate)", flags=["pq-auth"], **base))
    # --- certificates (chain)
    now = _now()
    for i, ci in enumerate(rep["certs"]):
        if not ci.get("algorithm"):
            continue
        flags = []
        na = datetime.fromisoformat(ci["not_after"])
        if na < now:
            flags.append("expired")
        elif (na - now).days <= 30:
            flags.append("expiring-soon")
        if ci.get("self_signed"):
            flags.append("self-signed")
        if i > 0 or ci.get("is_ca"):
            flags.append("long-lived")
        if i == 0 and rep.get("name_match") is False:
            flags.append("name-mismatch")
        if _looks_like_interception(ci):
            flags.append("tls-interception-suspected")
        p = {k: ci[k] for k in ("key_bits", "curve") if ci.get(k)}
        p["hash"] = ci.get("sig_hash")
        out.append(Finding(category="certificate", algorithm=ci["algorithm"], params=p, flags=flags,
                           evidence=f"{'leaf' if i == 0 else 'chain[' + str(i) + ']'} certificate {ci['subject']} issued by {ci['issuer']}, expires {ci['not_after'][:10]}",
                           source="probe", asset=dict(asset, domain=ci["subject"]), location=loc, context=dict(ctx, certificate=ci, not_after=ci["not_after"], not_before=ci["not_before"])))
    # --- bulk ciphers
    seen = set()
    for name in rep["tls13_ciphers"] + [c["name"] for c in rep["tls12_ciphers"]]:
        d = TLS.decompose(name)
        key = (d["cipher"], d["cipher_bits"], d["mode"])
        if not d["cipher"] or key in seen:
            continue
        seen.add(key)
        out.append(Finding(category="encryption", algorithm=d["cipher"], params=dict(key_bits=d["cipher_bits"], mode=d["mode"]),
                           evidence=f"accepted {name}", **base))
    if any(TLS.decompose(c["name"])["mac"] == "SHA-1" for c in rep["tls12_ciphers"]):
        out.append(Finding(category="mac", algorithm="HMAC", params=dict(hash="SHA-1"), evidence="accepts HMAC-SHA1 CBC suites", **base))
    return out


def ingest(targets: list[str], **kw) -> tuple[list[Finding], list[dict]]:
    from concurrent.futures import ThreadPoolExecutor
    reports = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as ex:
        for rep in ex.map(lambda t: _safe_probe(t, **kw), targets):
            reports.append(rep)
    findings = [f for r in reports for f in to_findings(r)]
    return findings, reports


def _safe_probe(t, **kw):
    try:
        return probe(t, **kw)
    except Exception as e:  # unreachable / DNS
        host, _, port = t.partition(":")
        return dict(target=t, host=host, ip=None, port=int(port or 443), starttls=None, started=datetime.now(timezone.utc).isoformat(),
                    versions={}, groups={}, tls13_ciphers=[], tls12_ciphers=[], modern=None, sigalg_families={}, certs=[],
                    errors=[f"{type(e).__name__}: {e}"], connections=0)
