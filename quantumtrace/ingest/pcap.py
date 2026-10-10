"""Network ingestor: PCAP/PCAPNG -> Findings, using tshark (numeric fields only).

Per TCP stream:
  TLS  : negotiated version / cipher / group (ServerHello) vs offered (ClientHello), HRR,
         GREASE filtering, key_share length validation, certificate parsing (TLS <= 1.2),
         authentication inference for TLS 1.3 (cert is encrypted).
  SSH  : negotiated kex / host key / cipher / mac per RFC 4253 7.1 (first client alg supported by server).
  else : cleartext application protocol (HTTP, SMTP without STARTTLS, ...).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache

from ..kb import ssh as SSH
from ..kb import tls as TLS
from ..schema import Finding

AGG = "\x1f"  # occurrence aggregator that never appears in field values

PORT_SERVICE = {443: "https", 8443: "https-alt", 636: "ldaps", 993: "imaps", 995: "pop3s", 465: "smtps",
                587: "smtp-submission", 25: "smtp", 5432: "postgresql", 3306: "mysql", 22: "ssh", 80: "http",
                8080: "http-alt", 389: "ldap", 143: "imap", 110: "pop3", 21: "ftp", 23: "telnet", 1433: "mssql",
                5671: "amqps", 8883: "mqtts", 853: "dns-over-tls", 3389: "rdp"}

TLS_FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions.supported_version",
              "tls.handshake.ciphersuite", "tls.handshake.extensions_supported_group",
              "tls.handshake.extensions_key_share_group", "tls.handshake.extensions_key_share_key_exchange_length",
              "tls.handshake.extensions_key_share_selected_group",
              "tls.handshake.sig_hash_alg", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
              "tls.handshake.random", "tls.handshake.server_named_curve", "tls.handshake.p_len",
              "tls.handshake.certificate", "tls.alert_message.desc"]
SSH_FIELDS = ["frame.number", "tcp.stream", "tcp.srcport", "tcp.dstport", "ssh.protocol", "ssh.message_code",
              "ssh.kex_algorithms", "ssh.server_host_key_algorithms",
              "ssh.encryption_algorithms_client_to_server", "ssh.encryption_algorithms_server_to_client",
              "ssh.mac_algorithms_client_to_server", "ssh.mac_algorithms_server_to_client"]


class TsharkMissing(RuntimeError):
    pass


class PcapUnreadable(RuntimeError):
    """tshark could not read the file at all (not a capture, empty, corrupt)."""


def _tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        raise TsharkMissing("tshark not found: apt install tshark / brew install wireshark (or use the Docker image)")
    return exe


@lru_cache(maxsize=1)
def _valid_fields() -> frozenset:
    out = subprocess.run([_tshark(), "-G", "fields"], capture_output=True, text=True).stdout
    return frozenset(line.split("\t")[2] for line in out.splitlines() if line.startswith("F\t"))


def _fields(pcap: str, display_filter: str, fields: list[str], extra: list[str] | None = None) -> list[dict]:
    valid = _valid_fields()
    fields = [f for f in fields if f in valid]
    cmd = [_tshark(), "-r", pcap, "-n", "-Y", display_filter, "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=a", "-E", f"aggregator={AGG}"] + (extra or [])
    for f in fields:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 and not res.stdout.strip():
        noise = ("Running as user", "This could be dangerous")  # tshark's root warning is not the reason
        msg = next((ln.strip() for ln in res.stderr.splitlines() if ln.strip() and not ln.strip().startswith(noise)),
                   f"tshark exit code {res.returncode}")
        raise PcapUnreadable(msg)
    rows = []
    for line in res.stdout.splitlines():
        vals = line.split("\t")
        rows.append({f: (vals[i].split(AGG) if i < len(vals) and vals[i] != "" else []) for i, f in enumerate(fields)})
    return rows


def _ints(vals) -> list[int]:
    out = []
    for v in vals:
        for x in str(v).split(","):
            x = x.strip()
            if x:
                try:
                    out.append(int(x, 0))
                except ValueError:
                    pass
    return out


def _first(vals, default=None):
    return vals[0] if vals else default


def _payload_hints(pcap: str):
    """Look at the first payload of each direction of each stream (no port assumptions):
    - TLS ClientHello on a non-standard port            -> decode-as tls
    - SMTP / IMAP / POP3 banner, Postgres SSLRequest    -> STARTTLS service name (+ decode-as for the app protocol)
    Returns (decode_as_args, app_by_stream)."""
    rows = _fields(pcap, "tcp.len > 0", ["tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.payload"])
    first = {}
    for r in rows:
        s, sp, dp = int(_first(r["tcp.stream"])), int(_first(r["tcp.srcport"])), int(_first(r["tcp.dstport"]))
        key = (s, sp, dp)
        if key not in first:
            first[key] = (_first(r.get("tcp.payload", [])) or "").replace(":", "")
    tls_ports, decode, app = set(), {}, {}
    for (s, sp, dp), pl in first.items():
        txt = bytes.fromhex(pl[:200]).decode("latin-1") if pl else ""
        if pl.startswith("1603") and pl[10:12] == "01" and dp not in PORT_SERVICE:
            tls_ports.add(dp)
        elif txt.startswith("SSH-") and min(sp, dp) != 22:   # SSH on a non-standard port
            decode[min(sp, dp)] = "ssh"
        elif pl.startswith("0000000804d2162f"):            # Postgres SSLRequest (client -> server)
            app[s] = "postgresql"
            decode[dp] = "pgsql"
        elif txt.startswith("220") and "SMTP" in txt.upper():
            app[s] = "smtp-starttls"
            decode[sp] = "smtp"
        elif txt.startswith("* OK"):
            app[s] = "imap-starttls"
            decode[sp] = "imap"
        elif txt.startswith("+OK"):
            app[s] = "pop3-starttls"
            decode[sp] = "pop"
    args = []
    for port in sorted(tls_ports):
        args += ["-d", f"tcp.port=={port},tls"]
    for port, proto in sorted(decode.items()):
        if port not in PORT_SERVICE:
            args += ["-d", f"tcp.port=={port},{proto}"]
    return args, app


def ingest(pcap: str) -> list[Finding]:
    pcap = os.path.abspath(pcap)
    rel = os.path.basename(pcap)
    extra, app_hint = _payload_hints(pcap)

    # ---- TCP streams (server = SYN destination) ----
    streams = {}
    for r in _fields(pcap, "tcp.flags.syn==1 && tcp.flags.ack==0", ["tcp.stream", "ip.dst", "tcp.dstport", "frame.number"]):
        s = int(_first(r["tcp.stream"]))
        streams.setdefault(s, dict(ip=_first(r["ip.dst"]), port=int(_first(r["tcp.dstport"])), syn=int(_first(r["frame.number"]))))

    # ---- DNS: ip -> name ----
    ip2name = {}
    for r in _fields(pcap, "dns.flags.response==1", ["dns.qry.name", "dns.a", "dns.aaaa"]):
        for ip in r.get("dns.a", []) + r.get("dns.aaaa", []):
            for x in ip.split(","):
                ip2name.setdefault(x, _first(r["dns.qry.name"]))

    # ---- protocols seen per stream (payload frames) ----
    protos = defaultdict(set)
    for r in _fields(pcap, "tcp.len > 0", ["tcp.stream", "frame.protocols"], extra):
        s = int(_first(r["tcp.stream"]))
        for p in _first(r["frame.protocols"], "").split(":"):
            protos[s].add(p)

    findings: list[Finding] = []
    for s, ps in protos.items():
        if s in streams:
            streams[s]["app"] = app_hint.get(s) or next((n for p, n in (("smtp", "smtp-starttls"), ("imap", "imap-starttls"), ("pop", "pop3-starttls"),
                                                                         ("pgsql", "postgresql"), ("ftp", "ftp-starttls"), ("ldap", "ldap-starttls")) if p in ps), None)
    tls_streams = _tls(pcap, rel, extra, streams, ip2name, findings)
    ssh_streams = _ssh(pcap, rel, streams, ip2name, findings, extra)

    # ---- cleartext streams ----
    http = {int(_first(r["tcp.stream"])): r for r in _fields(pcap, "http.request", ["tcp.stream", "http.host", "http.request.method", "http.request.uri", "frame.number", "http.authorization"])}
    for s, info in sorted(streams.items()):
        if s in tls_streams or s in ssh_streams or not protos.get(s):
            continue
        app = _app_proto(protos[s])
        host = ip2name.get(info["ip"], info["ip"])
        h = http.get(s)
        if app == "tcp":  # unidentified payload: never claim "cleartext" without evidence
            findings.append(Finding(source="network", category="transport", algorithm="UNIDENTIFIED", asset=_asset(info, host, f"tcp/{info['port']}"),
                                    location=dict(pcap=rel, stream=s, frame=info["syn"]), context=dict(protocol="unknown"), confidence=0.2,
                                    evidence="payload not recognised as TLS, SSH or a known cleartext protocol: manual review"))
            continue
        ev = f"{app.upper()} session in cleartext"
        loc = dict(pcap=rel, stream=s, frame=info["syn"])
        flags = ["plaintext"]
        if h:
            host = _first(h["http.host"], host)
            ev = f"HTTP {_first(h['http.request.method'], 'GET')} {_first(h['http.request.uri'], '/')} sent in cleartext (Host: {host})"
            loc["frame"] = int(_first(h["frame.number"]))
            if h.get("http.authorization"):
                flags.append("cleartext-credentials")
        findings.append(Finding(source="network", category="transport", algorithm="PLAINTEXT",
                                asset=_asset(info, host, app), location=loc,
                                context=dict(protocol=app), evidence=ev, flags=flags))
    return findings


def _app_proto(ps: set) -> str:
    for p in ("http", "smtp", "pgsql", "mysql", "ldap", "imap", "pop", "ftp", "telnet", "dns", "data"):
        if p in ps:
            return {"pgsql": "postgresql", "data": "tcp"}.get(p, p)
    return "tcp"


def _asset(info, host, service):
    return dict(kind="network-endpoint", host=host, ip=info["ip"], port=info["port"],
                service=service or PORT_SERVICE.get(info["port"], f"tcp/{info['port']}"))


# =============================================================================== TLS
def _tls(pcap, rel, extra, streams, ip2name, findings) -> set:
    rows = _fields(pcap, "tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11 || tls.handshake.type==12 || tls.alert_message", TLS_FIELDS, extra)
    by = defaultdict(lambda: dict(ch=None, sh=None, hrr=None, certs=[], ske=None, alerts=[]))
    for r in rows:
        s = int(_first(r["tcp.stream"]))
        types = _ints(r["tls.handshake.type"])
        if 1 in types and by[s]["ch"] is None:
            by[s]["ch"] = r
        if 2 in types:
            rnd = (_first(r["tls.handshake.random"], "") or "").replace(":", "").lower()
            if rnd == TLS.HRR_RANDOM:
                by[s]["hrr"] = r
            else:
                by[s]["sh"] = r
        if 11 in types:
            by[s]["certs"] = r.get("tls.handshake.certificate", [])
        if 12 in types:
            by[s]["ske"] = r
        if r.get("tls.alert_message.desc"):
            by[s]["alerts"] += r["tls.alert_message.desc"]

    for s, h in sorted(by.items()):
        ch, sh = h["ch"], h["sh"]
        info = streams.get(s) or dict(ip=_first((sh or ch)["ip.dst" if ch else "ip.src"]), port=int(_first((ch or sh)["tcp.dstport"])), syn=None)
        sni = _first(ch["tls.handshake.extensions_server_name"]) if ch else None
        host = sni or ip2name.get(info["ip"], info["ip"])
        service = PORT_SERVICE.get(info["port"]) or info.get("app") or f"tls/{info['port']}"
        asset = _asset(info, host, service)
        loc_ch = dict(pcap=rel, stream=s, frame=int(_first(ch["frame.number"]))) if ch else None

        offered = {}
        if ch:
            offered = dict(
                versions=[TLS.VERSIONS.get(v, hex(v)) for v in _ints(ch["tls.handshake.extensions.supported_version"]) if v not in TLS.GREASE]
                or [TLS.VERSIONS.get(v, hex(v)) for v in _ints(ch["tls.handshake.version"])],
                ciphers=[TLS.suite_name(c) for c in _ints(ch["tls.handshake.ciphersuite"]) if c not in TLS.GREASE and c not in (0x00FF, 0x5600)],
                groups=[TLS.group(g)["name"] for g in _ints(ch["tls.handshake.extensions_supported_group"]) if g not in TLS.GREASE],
                key_shares=[TLS.group(g)["name"] for g in _ints(ch["tls.handshake.extensions_key_share_group"]) if g not in TLS.GREASE],
                sigalgs=[TLS.sigscheme(a)[0] for a in _ints(ch["tls.handshake.sig_hash_alg"]) if a not in TLS.GREASE],
                alpn=ch.get("tls.handshake.extensions_alpn_str", []),
            )
        pq_offered = [g for g in offered.get("groups", []) if any(TLS.GROUPS[c]["name"] == g and TLS.GROUPS[c]["pq"] for c in TLS.GROUPS)]

        if sh is None and h["hrr"] is not None:
            sh = h["hrr"]  # HRR is a ServerHello: it reveals version, cipher and the group the server insists on
            h["hrr_only"] = True
        if sh is None:
            # handshake never completed: only report what the CLIENT offered
            findings.append(Finding(source="network", category="protocol", algorithm="TLS",
                                    params=dict(version=(offered.get("versions") or ["?"])[0]),
                                    asset=asset, location=loc_ch or {}, confidence=0.5,
                                    context=dict(protocol="TLS", negotiated=False, offered=offered, alerts=h["alerts"]),
                                    evidence="ClientHello without ServerHello (handshake failed or capture truncated)",
                                    flags=["handshake-incomplete"]))
            continue

        loc = dict(pcap=rel, stream=s, frame=int(_first(sh["frame.number"])))
        sv = [v for v in _ints(sh["tls.handshake.extensions.supported_version"]) if v not in TLS.GREASE]
        ver_code = sv[0] if sv else _first(_ints(sh["tls.handshake.version"]), 0x0303)
        version = TLS.VERSIONS.get(ver_code, hex(ver_code))
        suite_code = _first(_ints(sh["tls.handshake.ciphersuite"]))
        suite = TLS.suite_name(suite_code) if suite_code is not None else "UNKNOWN"
        d = TLS.decompose(suite)
        ctx = dict(protocol="TLS", version=version, cipher_suite=suite, cipher_suite_code=f"0x{suite_code:04X}" if suite_code is not None else None,
                   negotiated=True, offered=offered, sni=sni, hrr=h["hrr"] is not None, client_hello_frame=loc_ch and loc_ch["frame"])
        base = dict(source="network", asset=asset, location=loc, context=ctx)

        # protocol version
        findings.append(Finding(category="protocol", algorithm="TLS", params=dict(version=version),
                                evidence=f"ServerHello negotiated {version} with {suite}", **base))

        # certificate (visible only in TLS <= 1.2)
        cert_info = _certs(h["certs"])
        # ---------------- key exchange ----------------
        if version == "TLS 1.3":
            ksg = [g for g in _ints(sh["tls.handshake.extensions_key_share_group"]) if g not in TLS.GREASE]
            ksl = _ints(sh["tls.handshake.extensions_key_share_key_exchange_length"])
            if not ksg and h["hrr"] is not None:  # HRR carries only selected_group
                ksg = _ints(h["hrr"].get("tls.handshake.extensions_key_share_selected_group", [])) or _ints(h["hrr"]["tls.handshake.extensions_key_share_group"])
            gcode = _first(ksg)
            g = TLS.group(gcode) if gcode is not None else dict(code=None, name="psk_ke?", algorithm="PSK", params={}, pq=False, ks=None)
            flags = []
            ev = f"ServerHello key_share selected group 0x{gcode:04X} ({g['name']})" if gcode is not None else "no key_share in ServerHello (PSK-only resumption)"
            if h.get("hrr_only"):
                flags.append("hrr")
                ksl = []
                ev = (f"HelloRetryRequest: server demanded group 0x{gcode:04X} ({g['name']}) after the client offered key shares only for "
                      f"{', '.join(offered.get('key_shares', [])) or 'nothing'} (handshake not completed in capture)")
            elif h["hrr"] is not None:
                flags.append("hrr")
                ev += " (after HelloRetryRequest)"
            conf = 1.0
            if g.get("ks") and ksl:
                exp = g["ks"][1]
                if ksl[0] == exp:
                    ev += f"; key_share length {ksl[0]} B matches spec"
                else:
                    flags.append("keyshare-length-mismatch")
                    conf = 0.6
                    ev += f"; WARNING key_share length {ksl[0]} B != expected {exp} B"
            if g["pq"]:
                flags.append("pq-hybrid" if g.get("hybrid") else "pq")
            elif pq_offered:
                flags.append("pq-offered-not-negotiated")
                ev += f"; client offered {', '.join(pq_offered)} but server chose classical"
            elif offered.get("groups"):
                flags.append("client-offered-no-pq")
                ev += "; the client did not offer any ML-KEM group (client-side upgrade needed)"
            findings.append(Finding(category="key-exchange", algorithm=g["algorithm"], params=dict(g["params"], group=g["name"], group_id=f"0x{gcode:04X}" if gcode is not None else None),
                                    evidence=ev, confidence=conf, flags=flags, **base))
            # authentication: CertificateVerify must use one of the client's signature_algorithms (RFC 8446 4.4.3)
            sigs = [TLS.sigscheme(a) for a in _ints(ch["tls.handshake.sig_hash_alg"]) if a not in TLS.GREASE] if ch else []
            pq_sig = [s_ for s_ in sigs if s_[1] in ("ML-DSA", "SLH-DSA")]
            if sigs and not pq_sig:
                algs = sorted({s_[1] for s_ in sigs})
                cand = [s_[0] for s_ in sigs]
                if len(algs) == 1:
                    a0 = sigs[0]
                    findings.append(Finding(category="authentication", algorithm=a0[1], params=dict(a0[2]), confidence=0.9,
                                            evidence=f"TLS 1.3 certificate is encrypted; client offered only {', '.join(cand)} so the server must have signed with {a0[1]}",
                                            flags=["inferred"], **base))
                else:
                    fam = {"RSA": "RSA", "ECDSA": "ECDSA", "Ed25519": "EdDSA", "Ed448": "EdDSA", "DSA": "DSA"}
                    families = sorted({fam.get(s_[1], s_[1]) for s_ in sigs if s_[1] != "UNKNOWN-SIG"}, key=["RSA", "ECDSA", "EdDSA", "DSA"].index)
                    findings.append(Finding(category="authentication", algorithm="CLASSICAL-SIG", params=dict(candidates=families, schemes=cand), confidence=0.9,
                                            evidence=f"TLS 1.3 certificate is encrypted; client offered only classical schemes ({', '.join(cand)}) so the server signature is necessarily Shor-vulnerable",
                                            flags=["inferred"], **base))
        else:
            kex = d["kex"]
            if kex == "RSA":
                kb = cert_info.get("key_bits") if cert_info else None
                findings.append(Finding(category="key-exchange", algorithm="RSA", params=dict(key_bits=kb, padding="PKCS1v15", transport=True),
                                        evidence=f"{suite}: RSA key transport (pre-master secret encrypted to the server certificate key)",
                                        flags=["no-forward-secrecy"], **base))
            elif kex in ("ECDHE", "ECDH-static"):
                curve = _first(_ints(h["ske"]["tls.handshake.server_named_curve"])) if h["ske"] else None
                gg = TLS.group(curve) if curve is not None else None
                if gg:
                    alg, params, ev = gg["algorithm"] if gg["algorithm"] != "ECDH" else "ECDHE", dict(gg["params"], group=gg["name"]), f"ServerKeyExchange named_curve {gg['name']}"
                else:
                    alg, params, ev = "ECDHE", dict(curve=None, offered_groups=offered.get("groups")), f"{suite}: ECDHE (curve not captured; client offered {offered.get('groups')})"
                findings.append(Finding(category="key-exchange", algorithm=alg, params=params, evidence=ev,
                                        flags=[] if kex == "ECDHE" else ["no-forward-secrecy"], **base))
            elif kex in ("DHE", "DH-static"):
                plen = _first(_ints(h["ske"]["tls.handshake.p_len"])) if h["ske"] else None
                findings.append(Finding(category="key-exchange", algorithm="DHE", params=dict(key_bits=plen * 8 if plen else None),
                                        evidence=f"{suite}: finite-field DHE" + (f" with {plen * 8}-bit prime" if plen else ""), **base))
            elif kex:
                findings.append(Finding(category="key-exchange", algorithm=kex, params={}, evidence=f"{suite}: {kex} key exchange", **base))
            # authentication from suite (+ certificate if captured)
            if d["auth"] and d["auth"] != "PSK":
                params = dict(cert_info.get("params", {})) if cert_info else {}
                if cert_info and cert_info.get("key_bits"):
                    params["key_bits"] = cert_info["key_bits"]
                findings.append(Finding(category="authentication", algorithm=cert_info.get("algorithm", d["auth"]) if cert_info else d["auth"], params=params,
                                        evidence=f"{suite}: server authenticated with {d['auth']}" + (" (certificate parsed)" if cert_info else " certificate (implied by suite)"),
                                        confidence=1.0 if cert_info else 0.9, flags=[] if cert_info else ["inferred"], **base))
            if d["anon"]:
                findings[-1].flags.append("anonymous")
        # ---------------- bulk cipher ----------------
        if d["cipher"]:
            flags = []
            if version != "TLS 1.3" and offered.get("ciphers"):
                offered_bits = [TLS.decompose(c)["cipher_bits"] or 0 for c in offered["ciphers"]]
                if d["cipher_bits"] and max(offered_bits, default=0) > d["cipher_bits"]:
                    flags.append("weaker-than-offered")
            elif version == "TLS 1.3" and offered.get("ciphers"):
                if any(TLS.decompose(c)["cipher_bits"] == 256 for c in offered["ciphers"]) and d["cipher_bits"] == 128:
                    flags.append("weaker-than-offered")
            ev = f"{suite}: bulk encryption {d['cipher']}-{d['cipher_bits']} {d['mode'] or ''}".strip()
            if "weaker-than-offered" in flags:
                ev += " (client also offered 256-bit ciphers: server preference picked the weaker one)"
            findings.append(Finding(category="encryption", algorithm=d["cipher"], params=dict(key_bits=d["cipher_bits"], mode=d["mode"]),
                                    evidence=ev, flags=flags, **base))
        if d["mac"]:
            findings.append(Finding(category="mac", algorithm="HMAC", params=dict(hash=d["mac"]),
                                    evidence=f"{suite}: record MAC HMAC-{d['mac']}", **base))
        if cert_info:
            findings.append(Finding(category="certificate", algorithm=cert_info["algorithm"],
                                    params=dict(cert_info.get("params", {}), key_bits=cert_info.get("key_bits")),
                                    evidence=f"Server certificate {cert_info.get('subject')} (expires {cert_info.get('not_after')})",
                                    flags=cert_info.get("flags", []), context=dict(ctx, certificate=cert_info),
                                    source="network", asset=asset, location=loc))
    return set(by)


def _certs(hexcerts: list) -> dict:
    """Parse the leaf certificate (DER, hex) with `cryptography` if available."""
    if not hexcerts:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, dsa
    except ImportError:
        return {}
    der = bytes.fromhex(hexcerts[0].replace(":", ""))
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception:
        return {}
    pk = c.public_key()
    info = dict(subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(),
                not_before=c.not_valid_before_utc.isoformat(), not_after=c.not_valid_after_utc.isoformat(), flags=[])
    if isinstance(pk, rsa.RSAPublicKey):
        info.update(algorithm="RSA", key_bits=pk.key_size)
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        info.update(algorithm="ECDSA", params={"curve": {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(pk.curve.name, pk.curve.name)})
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        info.update(algorithm="Ed25519")
    elif isinstance(pk, ed448.Ed448PublicKey):
        info.update(algorithm="Ed448")
    elif isinstance(pk, dsa.DSAPublicKey):
        info.update(algorithm="DSA", key_bits=pk.key_size)
    else:
        info.update(algorithm="UNKNOWN-KEY")
    h = c.signature_hash_algorithm.name.upper().replace("SHA", "SHA-") if c.signature_hash_algorithm else None
    info.setdefault("params", {})["hash"] = h
    if c.not_valid_after_utc < datetime.now(timezone.utc):
        info["flags"].append("expired")
    return info


# =============================================================================== SSH
_VER = re.compile(r"OpenSSH_(\d+)\.(\d+)")


def _ssh(pcap, rel, streams, ip2name, findings, extra=None) -> set:
    rows = _fields(pcap, "ssh.protocol || ssh.message_code==20", SSH_FIELDS, extra)
    by = defaultdict(lambda: dict(cbanner=None, sbanner=None, ckex=None, skex=None, frame=None))
    for r in rows:
        s = int(_first(r["tcp.stream"]))
        info = streams.get(s)
        to_server = info and int(_first(r["tcp.dstport"])) == info["port"]
        if r.get("ssh.protocol"):
            by[s]["cbanner" if to_server else "sbanner"] = _first(r["ssh.protocol"])
        if "20" in r.get("ssh.message_code", []):
            by[s]["ckex" if to_server else "skex"] = r
            if not to_server:
                by[s]["frame"] = int(_first(r["frame.number"]))
    for s, h in sorted(by.items()):
        info = streams.get(s)
        if not info or not (h["ckex"] and h["skex"]):
            continue
        host = ip2name.get(info["ip"], info["ip"])
        asset = _asset(info, host, "ssh")
        loc = dict(pcap=rel, stream=s, frame=h["frame"])

        def lst(r, f):
            return SSH.clean((_first(r.get(f, []), "") or "").split(","))

        c, sv = h["ckex"], h["skex"]
        neg = dict(
            kex=SSH.negotiate(lst(c, "ssh.kex_algorithms"), lst(sv, "ssh.kex_algorithms")),
            hostkey=SSH.negotiate(lst(c, "ssh.server_host_key_algorithms"), lst(sv, "ssh.server_host_key_algorithms")),
            cipher_c2s=SSH.negotiate(lst(c, "ssh.encryption_algorithms_client_to_server"), lst(sv, "ssh.encryption_algorithms_client_to_server")),
            cipher_s2c=SSH.negotiate(lst(c, "ssh.encryption_algorithms_server_to_client"), lst(sv, "ssh.encryption_algorithms_server_to_client")),
            mac_c2s=SSH.negotiate(lst(c, "ssh.mac_algorithms_client_to_server"), lst(sv, "ssh.mac_algorithms_client_to_server")),
        )
        offered = dict(client_kex=lst(c, "ssh.kex_algorithms"), server_kex=lst(sv, "ssh.kex_algorithms"),
                       client_hostkey=lst(c, "ssh.server_host_key_algorithms"), server_hostkey=lst(sv, "ssh.server_host_key_algorithms"),
                       client_ciphers=lst(c, "ssh.encryption_algorithms_client_to_server"), server_ciphers=lst(sv, "ssh.encryption_algorithms_client_to_server"),
                       client_macs=lst(c, "ssh.mac_algorithms_client_to_server"), server_macs=lst(sv, "ssh.mac_algorithms_client_to_server"))
        ctx = dict(protocol="SSH", version="2.0", client_software=h["cbanner"], server_software=h["sbanner"], negotiated=neg, offered=offered)
        base = dict(source="network", asset=asset, location=loc, context=ctx)
        sw_flags = []
        m = _VER.search(h["sbanner"] or "")
        if m and (int(m.group(1)), int(m.group(2))) < (8, 0):
            sw_flags.append("outdated-software")
        weak = sorted({a for a in offered["server_kex"] if a in ("diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1")}
                      | {a for a in offered["server_ciphers"] if a in ("3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "none")}
                      | {a for a in offered["server_macs"] if a in ("hmac-md5", "hmac-md5-96", "hmac-sha1-96")}
                      | {a for a in offered["server_hostkey"] if a == "ssh-dss"})
        ev = f"SSH server {h['sbanner']} / client {h['cbanner']}"
        if weak:
            sw_flags.append("weak-algorithms-supported")
            ev += f"; server still accepts {', '.join(weak)}"
        ctx["weak_supported"] = weak
        findings.append(Finding(category="protocol", algorithm="SSH", params=dict(version="2.0", software=h["sbanner"]),
                                evidence=ev, flags=sw_flags, **base))
        if neg["kex"]:
            alg, params = SSH.KEX.get(neg["kex"], ("UNKNOWN-KEX", {}))
            flags = []
            if alg not in ("sntrup761x25519", "mlkem768x25519", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"):
                sm = _VER.search(h["sbanner"] or "")
                cm = _VER.search(h["cbanner"] or "")
                if sm and cm and (int(sm.group(1)), int(sm.group(2))) >= (9, 0) and (int(cm.group(1)), int(cm.group(2))) >= (9, 0):
                    flags.append("pq-capable-not-enabled")
            ev = f"KEXINIT negotiation selected {neg['kex']} (first client algorithm supported by server)"
            if "pq-capable-not-enabled" in flags:
                ev += "; both peers run OpenSSH >= 9.0 which supports sntrup761x25519-sha512 but it is not offered (config hardening disabled it)"
            findings.append(Finding(category="key-exchange", algorithm=alg, params=dict(params, ssh_name=neg["kex"]), evidence=ev, flags=flags, **base))
        if neg["hostkey"]:
            alg, params = SSH.HOSTKEY.get(neg["hostkey"], ("UNKNOWN-SIG", {}))
            findings.append(Finding(category="authentication", algorithm=alg, params=dict(params, ssh_name=neg["hostkey"]),
                                    evidence=f"host key algorithm {neg['hostkey']}", **base))
        for k in ("cipher_c2s",) + (("cipher_s2c",) if neg["cipher_s2c"] != neg["cipher_c2s"] else ()):
            if neg[k]:
                alg, params = SSH.CIPHER.get(neg[k], ("UNKNOWN-CIPHER", {}))
                findings.append(Finding(category="encryption", algorithm=alg, params=dict(params, ssh_name=neg[k]),
                                        evidence=f"cipher {neg[k]} ({k.split('_')[1]})", **base))
        if neg["mac_c2s"] and neg["cipher_c2s"] not in SSH.AEAD_CIPHERS:
            alg, params = SSH.MAC.get(neg["mac_c2s"], ("UNKNOWN-MAC", {}))
            findings.append(Finding(category="mac", algorithm=alg, params=dict(params, ssh_name=neg["mac_c2s"]),
                                    evidence=f"MAC {neg['mac_c2s']}", **base))
    return {s for s, h in by.items() if h["ckex"] and h["skex"]}
