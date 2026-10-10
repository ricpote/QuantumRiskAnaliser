"""Config-file scanners: nginx / Apache httpd TLS, OpenSSH sshd_config / ssh_config, Terraform (AWS + tls provider).

Most production crypto is not chosen in code but in config: the TLS protocols and cipher
string of a reverse proxy, the KexAlgorithms line copied from a 2019 hardening guide (which
silently turns off OpenSSH's default PQ hybrid), the ELB SslPolicy pinned in Terraform.

Only EXPLICIT settings are reported: a missing directive means "product default", which
depends on a version we cannot see.
"""
from __future__ import annotations

import base64
import os
import re
import ssl

from ...kb import aws as AWS
from ...kb import ssh as SSH
from ...kb import tls as TLS
from ...schema import Finding
from .. import cloud
from .common import looks_secret, snippet, unquote

# ============================================================== file detection
SSH_NAMES = ("sshd_config", "ssh_config")
_NGINX_RX = re.compile(r"^\s*(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_conf_command)\b", re.M)
_APACHE_RX = re.compile(r"^\s*(SSLProtocol|SSLCipherSuite|SSLOpenSSLConfCmd)\b", re.M | re.I)


def kind(path: str) -> str | None:
    """Which config scanner handles this file (None = not a config we understand)."""
    name = os.path.basename(path)
    parent = os.path.basename(os.path.dirname(path))
    if name.endswith(".tf"):
        return "terraform"
    if name in SSH_NAMES or (parent in ("sshd_config.d", "ssh_config.d") and name.endswith(".conf")):
        return "ssh"
    if name.endswith(".conf") or parent in ("sites-available", "sites-enabled", "conf.d"):
        try:
            head = open(path, encoding="utf-8", errors="replace").read(200_000)
        except OSError:
            return None
        if _NGINX_RX.search(head):
            return "nginx"
        if _APACHE_RX.search(head):
            return "apache"
    return None


def scan(path: str, rel: str) -> list[Finding]:
    k = kind(path)
    if k is None:
        return []
    src = open(path, encoding="utf-8", errors="replace").read()
    return {"terraform": _terraform, "ssh": _ssh, "nginx": _nginx, "apache": _apache}[k](path, rel, src)


def _mk(rel, src, lang, line, category, algorithm, params, evidence, flags=(), confidence=1.0, symbol=None, asset_extra=None, ctx=None):
    asset = dict(kind="config-file", path=rel, language=lang, **(asset_extra or {}))
    return Finding(source="code", category=category, algorithm=algorithm, params={k: v for k, v in params.items() if v is not None},
                   asset=asset, location=dict(file=rel, line=line, snippet=snippet(src, line), symbol=symbol),
                   context=dict(language=lang, **(ctx or {})), evidence=evidence, flags=list(flags), confidence=confidence)


# ============================================================== TLS (nginx / Apache)
PROTO = {"sslv2": "SSL 2.0", "sslv3": "SSL 3.0", "tlsv1": "TLS 1.0", "tlsv1.0": "TLS 1.0", "tlsv1.1": "TLS 1.1",
         "tlsv1.2": "TLS 1.2", "tlsv1.3": "TLS 1.3"}

_GROUP_ALIASES = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1", "p-521": "secp521r1",
                  "p256": "secp256r1", "p384": "secp384r1", "p521": "secp521r1"}
_GROUPS_BY_NAME = {g["name"].lower(): dict(code=c, **g) for c, g in TLS.GROUPS.items()}

# OpenSSL cipher-string exclusions ("!RC4", "-kRSA" ...) as predicates on a decomposed suite
_FAMILY = {
    "anull": lambda s: s["anon"], "enull": lambda s: s["cipher"] == "NULL", "null": lambda s: s["cipher"] == "NULL",
    "md5": lambda s: s["mac"] == "MD5", "sha1": lambda s: s["mac"] == "SHA-1", "sha": lambda s: s["mac"] == "SHA-1",
    "rc4": lambda s: s["cipher"] == "RC4", "3des": lambda s: s["cipher"] == "3DES", "des": lambda s: s["cipher"] == "DES",
    "export": lambda s: s["export"], "exp": lambda s: s["export"], "exportable": lambda s: s["export"],
    "rsa": lambda s: s["kex"] == "RSA", "krsa": lambda s: s["kex"] == "RSA",
    "dss": lambda s: s["auth"] == "DSA", "adss": lambda s: s["auth"] == "DSA",
    "psk": lambda s: "PSK" in (s["kex"], s["auth"]), "srp": lambda s: s["kex"] == "SRP",
    "edh": lambda s: s["kex"] == "DHE", "dhe": lambda s: s["kex"] == "DHE", "kdhe": lambda s: s["kex"] == "DHE",
    "camellia": lambda s: s["cipher"] == "Camellia", "seed": lambda s: s["cipher"] == "SEED", "idea": lambda s: s["cipher"] == "IDEA",
    "aria": lambda s: s["cipher"] == "Aria", "cbc": lambda s: s["mode"] == "CBC",
}


# legacy OpenSSL names missing from the KB table and unknown to a modern OpenSSL (exactly the ones we must catch)
_LEGACY_SUITES = {
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "EDH-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "DHE-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-ECDSA-DES-CBC3-SHA": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "ADH-DES-CBC3-SHA": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA", "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5", "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "ECDHE-ECDSA-RC4-SHA": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ADH-RC4-MD5": "TLS_DH_anon_WITH_RC4_128_MD5",
    "EXP-RC4-MD5": "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "DES-CBC-SHA": "TLS_RSA_WITH_DES_CBC_SHA", "EDH-RSA-DES-CBC-SHA": "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "EXP-DES-CBC-SHA": "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "NULL-MD5": "TLS_RSA_WITH_NULL_MD5", "NULL-SHA": "TLS_RSA_WITH_NULL_SHA", "NULL-SHA256": "TLS_RSA_WITH_NULL_SHA256",
    "ADH-AES128-SHA": "TLS_DH_anon_WITH_AES_128_CBC_SHA", "ADH-AES256-SHA": "TLS_DH_anon_WITH_AES_256_CBC_SHA",
}


# cipher-string keyword -> (cipher family, representative suite)
_WEAK_KEYWORDS = {"3DES": ("3DES", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"), "RC4": ("RC4", "TLS_RSA_WITH_RC4_128_SHA"),
                  "DES": ("DES", "TLS_RSA_WITH_DES_CBC_SHA"), "LOW": ("DES", "TLS_RSA_WITH_DES_CBC_SHA"),
                  "NULL": ("NULL", "TLS_RSA_WITH_NULL_SHA"), "ENULL": ("NULL", "TLS_RSA_WITH_NULL_SHA"),
                  "EXPORT": ("RC4", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"), "EXP": ("RC4", "TLS_RSA_EXPORT_WITH_RC4_40_MD5")}


def _iana(tok: str) -> str | None:
    """OpenSSL (or IANA) suite name -> IANA name; None for keywords like HIGH / ECDHE+AESGCM."""
    if tok.startswith("TLS_") and "_WITH_" in tok:
        return tok
    if tok in _LEGACY_SUITES:
        return _LEGACY_SUITES[tok]
    name = TLS.iana_from_openssl(tok)
    if name != tok:
        return name
    try:  # a name the linked OpenSSL knows: its numeric id is the IANA codepoint
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.set_ciphers(tok + ":@SECLEVEL=0")
        hit = [x for x in c.get_ciphers() if x["name"] == tok]
        if len(hit) == 1:
            return TLS.suite_name(hit[0]["id"] & 0xFFFF)
    except (ssl.SSLError, ValueError):
        pass
    return None


def _expand_ciphers(spec: str) -> tuple[list[tuple[str, dict]], bool]:
    """OpenSSL cipher string -> [(name, decomposed suite)], and whether the local OpenSSL had to expand keywords.

    Explicit suite names resolve through our own IANA table (deterministic, and the local OpenSSL
    silently drops 3DES/RC4, which are exactly the ones we must report). Keywords like HIGH or
    ECDHE+AESGCM are expanded by the linked OpenSSL with @SECLEVEL=0."""
    toks = [t for t in re.split(r"[:,\s]+", spec.strip().strip("\"'")) if t]
    explicit, excl, keywords = [], [], []
    for t in toks:
        if t.startswith("@") or t.startswith("+"):
            continue
        if t[0] in "!-":
            excl.append(t[1:])
        elif _iana(t):
            explicit.append(t)
        else:
            keywords.append(t)
    names = list(explicit)
    if keywords:
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            c.set_ciphers(":".join(toks) + ":@SECLEVEL=0")
            names += [x["name"] for x in c.get_ciphers() if x.get("protocol") != "TLSv1.3" and x["name"] not in names]
        except (ssl.SSLError, ValueError):
            pass
    out = []
    for n in names:
        iana = _iana(n)
        if not iana or iana.startswith("UNKNOWN"):
            continue
        s = TLS.decompose(iana)
        if n in excl or any(_FAMILY.get(e.lower(), lambda _: False)(s) for e in excl):
            continue
        out.append((n, s))
    # weak families requested by keyword (ECDH+3DES, LOW, eNULL...) that THIS machine's OpenSSL no longer ships: the config
    # still asks for them, and a server linked against another OpenSSL will offer them
    have = {s["cipher"] for _, s in out}
    for tok in keywords:
        for part in tok.split("+"):
            fam = _WEAK_KEYWORDS.get(part.upper())
            if fam and fam[0] not in have and not any(e.upper() in (part.upper(), fam[0].upper()) for e in excl):
                s = dict(TLS.decompose(fam[1]), kex=None, auth=None, fs=None, mac=None)  # only the cipher is known
                out.append((tok, s))
                have.add(fam[0])
    return out, bool(keywords)


def _parse_groups(spec: str) -> tuple[list[dict], list[str]]:
    """'X25519MLKEM768:X25519:prime256v1' (also OpenSSL 3.5 '*X25519MLKEM768 / ?X25519') -> known groups, unknown names."""
    known, unknown = [], []
    for t in re.split(r"[:/,\s]+", spec.strip().strip("\"'")):
        t = t.lstrip("*?")
        if not t or t.startswith("-") or t.lower() in ("auto", "default"):
            continue
        g = _GROUPS_BY_NAME.get(_GROUP_ALIASES.get(t.lower(), t.lower()))
        if g:
            known.append(g)
        else:
            unknown.append(t)
    return known, unknown


def _tls_scope(rel, src, lang, scope, protos, ciphers, groups, asset_extra) -> list[Finding]:
    """Findings for one effective TLS scope (nginx server{} / Apache <VirtualHost>).

    protos/ciphers/groups = (value, line, own) or None; own=False means inherited from an outer
    block: it is used for cross-checks but reported only where it is written."""
    out = []
    mk = lambda line, *a, **k: _mk(rel, src, lang, line, *a, symbol=scope, asset_extra=asset_extra, **k)
    enabled = protos[0] if protos else None
    tls13 = enabled is None or "TLS 1.3" in enabled
    if protos and protos[2]:
        for v in enabled:
            out.append(mk(protos[1], "protocol", "SSL" if v.startswith("SSL") else "TLS", dict(version=v),
                          f"{lang} enables {v}" + (f" ({scope})" if scope else ""), ctx=dict(protocols=enabled)))
    if ciphers and ciphers[2]:
        suites, expanded = _expand_ciphers(ciphers[0])
        conf = 0.8 if expanded else 1.0
        ctx = dict(cipher_string=ciphers[0], expanded_with=ssl.OPENSSL_VERSION if expanded else None)
        rsa = [n for n, s in suites if s["kex"] == "RSA"]
        if rsa:
            out.append(mk(ciphers[1], "key-exchange", "RSA", dict(transport=True),
                          f"cipher string allows RSA key-transport suites without forward secrecy: {', '.join(rsa[:6])}",
                          flags=["no-forward-secrecy"], confidence=conf, ctx=ctx))
        dhe = [n for n, s in suites if s["kex"] == "DHE"]
        if dhe:
            out.append(mk(ciphers[1], "key-exchange", "DHE", {}, f"cipher string allows finite-field DHE suites: {', '.join(dhe[:4])}",
                          flags=["anonymous"] if any(s["anon"] for _, s in suites if s["kex"] == "DHE") else [], confidence=conf, ctx=ctx))
        if any(s["kex"] == "ECDHE" for _, s in suites) and not groups:
            # without ssl_ecdh_curve the curves come from the linked OpenSSL (>= 3.5 puts X25519MLKEM768 first for TLS 1.3)
            out.append(mk(ciphers[1], "key-exchange", "ECDHE", dict(curve=None), "cipher string allows ECDHE suites (TLS 1.2: always a classical curve)",
                          confidence=conf, ctx=ctx))
        seen = set()
        for n, s in suites:
            key = (s["cipher"], s["cipher_bits"], s["mode"])
            if key in seen or not s["cipher"]:
                continue
            seen.add(key)
            out.append(mk(ciphers[1], "encryption", s["cipher"], dict(key_bits=s["cipher_bits"], mode=s["mode"]),
                          f"cipher string allows {n}", confidence=conf, ctx=ctx))
        for h in ("SHA-1", "MD5"):
            hs = [n for n, s in suites if s["mac"] == h]
            if hs:
                out.append(mk(ciphers[1], "mac", "HMAC", dict(hash=h), f"cipher string allows HMAC-{h} suites: {', '.join(hs[:4])}",
                              confidence=conf, ctx=ctx))
    if groups and groups[2]:
        known, unknown = _parse_groups(groups[0])
        pq = [g for g in known if g["pq"]]
        ctx = dict(groups=groups[0], unknown_groups=unknown or None)
        if pq and not tls13:
            # hybrid groups only exist in TLS 1.3: with TLS 1.3 disabled they are never negotiated
            note = f"PQ groups {', '.join(g['name'] for g in pq)} are configured but TLS 1.3 is disabled, so they are never used"
            for g in known:
                if not g["pq"]:
                    out.append(mk(groups[1], "key-exchange", g["algorithm"], dict(g["params"], group=g["name"]),
                                  f"{g['name']} key exchange; {note}", flags=["pq-unreachable"], ctx=ctx))
            return out
        for g in known:
            flags, ev = [], f"configured group {g['name']}"
            if g["pq"]:
                flags = ["pq-hybrid"] if g.get("hybrid") else []
            elif pq:
                flags, ev = ["fallback-for-legacy-clients"], ev + f" (fallback; PQ-capable clients get {pq[0]['name']})"
            else:
                flags, ev = ["pq-not-configured"], ev + "; no ML-KEM hybrid group configured (X25519MLKEM768 needs OpenSSL >= 3.5)"
            out.append(mk(groups[1], "key-exchange", g["algorithm"], dict(g["params"], group=g["name"]), ev, flags=flags, ctx=ctx))
    return out


def _nginx_directives(src: str):
    """Tiny nginx tokenizer -> [(name, args, line, block_path)]. Handles quotes, comments and multi-line directives."""
    out, words, path = [], [], []
    i, line, wline, n = 0, 1, None, len(src)
    while i < n:
        ch = src[i]
        if ch == "\n":
            line += 1
        if ch == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch in "\"'":
            j = src.find(ch, i + 1)
            j = n if j < 0 else j
            if wline is None:
                wline = line
            words.append(src[i + 1:j])
            line += src[i:j].count("\n")
            i = j + 1
            continue
        if ch in ";{}":
            if ch == ";" and words:
                out.append((words[0], words[1:], wline, tuple(path)))
            elif ch == "{":
                path.append((" ".join(words) or "?", i))  # offset makes every block unique (two server{} blocks)
            elif ch == "}" and path:
                path.pop()
            words, wline = [], None
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        j = i
        while j < n and not src[j].isspace() and src[j] not in ";{}#\"'":
            j += 1
        if wline is None:
            wline = line
        words.append(src[i:j])
        i = j
    return out


def _nginx(path, rel, src) -> list[Finding]:
    ds = _nginx_directives(src)
    # scope = the enclosing server{} block (None = http/main level, inherited by every server)
    scopes: dict = {None: {}}
    names: dict = {}
    for name, args, line, bpath in ds:
        sv = next((i for i, b in enumerate(bpath) if b[0] == "server"), None)
        key = bpath[:sv + 1] if sv is not None else None
        scopes.setdefault(key, {})
        if name == "server_name" and key is not None:
            names[key] = " ".join(args)
        elif name == "ssl_protocols":
            scopes[key]["protos"] = ([PROTO[a.lower()] for a in args if a.lower() in PROTO], line)
        elif name == "ssl_ciphers" and args:
            scopes[key]["ciphers"] = (args[0], line)
        elif name == "ssl_ecdh_curve" and args:
            scopes[key]["groups"] = (args[0], line)
        elif name == "ssl_conf_command" and len(args) >= 2 and args[0].lower() in ("groups", "curves"):
            scopes[key]["groups"] = (args[1], line)
    out = []
    for key, own in scopes.items():
        if not own:  # nothing written here: inherited settings are reported where they are written
            continue
        label = f"server {names.get(key, '?')}" if key is not None else "http"
        out += _tls_scope(rel, src, "nginx", label, *_effective(own, scopes[None], key), dict(server_name=names.get(key)) if key is not None else None)
    return out


def _effective(own: dict, top: dict, key) -> list:
    """(value, line, own?) for protos/ciphers/groups: the block's own setting, else the one inherited from the top level."""
    return [own[k] + (True,) if k in own else (top[k] + (False,) if k in top and key is not None else None)
            for k in ("protos", "ciphers", "groups")]


def _apache(path, rel, src) -> list[Finding]:
    scopes: dict = {None: {}}
    key = None
    for line, raw in enumerate(src.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"<VirtualHost\s+([^>]+)>", s, re.I)
        if m:
            key = f"VirtualHost {m.group(1).strip()}"
            scopes.setdefault(key, {})
            continue
        if re.match(r"</VirtualHost>", s, re.I):
            key = None
            continue
        parts = s.split()
        d, args = parts[0].lower(), parts[1:]
        if d == "sslprotocol":
            on = set()
            for a in args:
                a = a.lower()
                if a.lstrip("+-") == "all":
                    vs = {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
                else:
                    vs = {PROTO[a.lstrip("+-")]} if a.lstrip("+-") in PROTO else set()
                on = on - vs if a.startswith("-") else on | vs
            scopes[key]["protos"] = (sorted(on), line)
        elif d == "sslciphersuite" and args:
            # "SSLCipherSuite [protocol] spec": TLSv1.3 = TLS 1.3 suites (always AEAD, skipped); SSL = TLS <= 1.2 (same as no tag)
            if len(args) > 1 and args[0].upper() == "TLSV1.3":
                continue
            scopes[key]["ciphers"] = (args[1] if len(args) > 1 and args[0].upper() == "SSL" else args[0], line)
        elif d == "sslopensslconfcmd" and len(args) >= 2 and args[0].lower() in ("curves", "groups"):
            scopes[key]["groups"] = (args[1], line)
    out = []
    for key, own in scopes.items():
        if not own:
            continue
        out += _tls_scope(rel, src, "apache", key or "global", *_effective(own, scopes[None], key), dict(vhost=key) if key else None)
    return out


# ============================================================== OpenSSH
_SSH_DIRECTIVES = {"kexalgorithms": ("key-exchange", SSH.KEX), "ciphers": ("encryption", SSH.CIPHER), "macs": ("mac", SSH.MAC),
                   "hostkeyalgorithms": ("authentication", SSH.HOSTKEY), "pubkeyacceptedalgorithms": ("authentication", SSH.HOSTKEY),
                   "pubkeyacceptedkeytypes": ("authentication", SSH.HOSTKEY), "casignaturealgorithms": ("authentication", SSH.HOSTKEY)}
_HOSTKEY_FILE = [(re.compile(r"ed25519"), "Ed25519", {}), (re.compile(r"ecdsa"), "ECDSA", {}),
                 (re.compile(r"dsa"), "DSA", {"key_bits": 1024}), (re.compile(r"rsa"), "RSA", {})]


def _ssh(path, rel, src) -> list[Finding]:
    lang = "ssh_config" if os.path.basename(path).startswith("ssh_config") or "ssh_config.d" in path else "sshd_config"
    out, match = [], None
    for line, raw in enumerate(src.splitlines(), 1):
        s = raw.split("#", 1)[0].strip()
        m = re.match(r"(\w+)\s*(?:=\s*|\s+)(.+)", s)
        if not m:
            continue
        d, val = m.group(1).lower(), m.group(2).strip().strip("\"")
        if d in ("match", "host"):
            match = f"{m.group(1)} {val}"
            continue
        mk = lambda *a, **k: _mk(rel, src, lang, line, *a, symbol=m.group(1), asset_extra=dict(block=match) if match else None, **k)
        if d == "hostkey":
            alg, params = next(((a, p) for rx, a, p in _HOSTKEY_FILE if rx.search(os.path.basename(val).lower())), (None, None))
            if alg:
                out.append(mk("authentication", alg, dict(params), f"host key {val} (type inferred from file name)", confidence=0.8))
            continue
        if d not in _SSH_DIRECTIVES:
            continue
        category, table = _SSH_DIRECTIVES[d]
        mode = val[0] if val[0] in "+-^" else "="
        if mode == "-":
            continue  # removing algorithms from the default list only makes it stronger
        names = [x.strip() for x in val.lstrip("+-^").split(",") if x.strip()]
        algs = []
        for n in names:
            base = n.replace("-cert-v01@openssh.com", "")
            if n in SSH.PSEUDO or "*" in n or base not in table:
                continue
            algs.append((n, *table[base]))
        pq = [a for n, a, p in algs if category == "key-exchange" and a in ("sntrup761x25519", "mlkem768x25519", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")]
        for n, alg, params in algs:
            flags, ev = [], f"{m.group(1)} {'adds' if mode in '+^' else 'allows'} {n}"
            if category == "key-exchange" and alg not in pq:
                if pq:
                    flags, ev = ["fallback-for-legacy-clients"], ev + f" (fallback; PQ-capable clients negotiate {pq[0]})"
                elif mode == "=":
                    flags = ["pq-capable-not-enabled"]
                    ev += "; explicit KexAlgorithms replaces OpenSSH's default PQ hybrid (sntrup761x25519 since 9.0, mlkem768x25519 default since 10.0)"
            out.append(mk(category, alg, dict(params), ev, flags=flags, ctx=dict(directive=m.group(1), mode=mode, block=match)))
    return out


# ============================================================== Terraform
_TF_BLOCK = re.compile(r'^\s*(resource|data)\s+"([\w-]+)"\s+"([\w-]+)"\s*\{|^\s*(variable|provider)\s+"([\w-]+)"\s*\{|^\s*(locals)\s*\{', re.M)
# attributes whose literal value is a credential (aws_iam_server_certificate.private_key, provider "aws" secret_key...)
_TF_SECRET_ATTRS = ("private_key", "secret_key", "access_key", "password", "master_password", "client_secret", "api_key", "token", "secret")


def _strip_hcl_comments(src: str) -> str:
    """Blank out # // /* */ comments, keeping offsets and line numbers."""
    out, i, n, q = list(src), 0, len(src), None
    while i < n:
        c = src[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c == '"':
            q = c
        elif c == "#" or src.startswith("//", i):
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        elif src.startswith("/*", i):
            j = src.find("*/", i)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _blocks(src: str):
    """Top-level HCL blocks -> [(kind, type, name, body, start_line, body_offset)]."""
    out = []
    for m in _TF_BLOCK.finditer(src):
        start = m.end()
        depth, i, q = 1, start, False
        while i < len(src) and depth:
            c = src[i]
            if c == '"' and src[i - 1] != "\\":
                q = not q
            elif not q:
                depth += c == "{"
                depth -= c == "}"
            i += 1
        g = next(k for k in (1, 4, 6) if m.group(k))
        out.append((m.group(g), m.group(2), m.group(3) or m.group(5), src[start:i - 1], src[:m.start(g)].count("\n") + 1, start))
    return out


def _attrs(body: str, offset: int, src: str) -> dict:
    """Top-level `key = value` attributes of a block body -> {key: (raw value, line)}."""
    out, depth, pos = {}, 0, 0
    for raw in body.split("\n"):
        if depth == 0:
            m = re.match(r'\s*([\w-]+)\s*=\s*(.+?)\s*$', raw)
            if m:
                out[m.group(1)] = (m.group(2), src[:offset + pos].count("\n") + 1)
        depth += raw.count("{") - raw.count("}")
        pos += len(raw) + 1
    return out


def _nested(body: str, name: str) -> str | None:
    m = re.search(r'(?m)^\s*' + re.escape(name) + r'\s*\{', body)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(body) and depth:
        depth += body[i] == "{"
        depth -= body[i] == "}"
        i += 1
    return body[m.end():i - 1]


def _terraform(path, rel, src) -> list[Finding]:
    code = _strip_hcl_comments(src)
    blocks = _blocks(code)
    # variables / locals from every .tf file in the module directory (Terraform merges them)
    env = {}
    d = os.path.dirname(path) or "."
    for f in sorted(os.listdir(d)):
        if f.endswith(".tf"):
            other = code if os.path.join(d, f) == path else _strip_hcl_comments(open(os.path.join(d, f), encoding="utf-8", errors="replace").read())
            for k, _t, name, body, _l, off in (_blocks(other) if other is not code else blocks):
                if k == "variable":
                    a = _attrs(body, off, other)
                    if "default" in a:
                        env[f"var.{name}"] = a["default"][0]
                elif k == "locals":
                    for lk, (lv, _ln) in _attrs(body, off, other).items():
                        env[f"local.{lk}"] = lv
    res = {(t, n): (body, line, off) for k, t, n, body, line, off in blocks if k == "resource"}
    res.update({("provider", n): (body, line, off) for k, _, n, body, line, off in blocks if k == "provider"})

    def val(raw, depth=0):
        if raw is None or depth > 4:
            return None
        r = raw.strip().rstrip(",")
        if r in env:
            return val(env[r], depth + 1)
        if r.startswith('"') and r.endswith('"') and "${" not in r:
            return unquote(r)
        if re.fullmatch(r"-?\d+", r):
            return int(r)
        if r in ("true", "false"):
            return r == "true"
        m = re.fullmatch(r'base64decode\(\s*(".*")\s*\)', r)  # base64decode("LS0tLS1CRUdJTi...") hides a literal, it does not protect it
        if m:
            inner = val(m.group(1), depth + 1)
            if not isinstance(inner, str):
                return None
            b64 = re.sub(r"[^A-Za-z0-9+/]", "", inner)  # tolerate truncated / redacted blobs
            try:
                return base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", errors="replace")
            except ValueError:
                return None
        return None

    out = []
    for (rtype, rname), (body, line, off) in res.items():
        a = _attrs(body, off, code)
        get = lambda k: val(a[k][0]) if k in a else None
        at = lambda k: a[k][1] if k in a else line
        addr = f"{rtype}.{rname}"
        mk = lambda ln, *x, **kw: _mk(rel, src, "terraform", ln, *x, symbol=addr, asset_extra=dict(address=addr), **kw)
        for attr in _TF_SECRET_ATTRS:
            v = get(attr)
            if isinstance(v, str) and looks_secret(v):
                out += _tf_secret(mk, at(attr), addr, attr, v)

        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            proto = get("protocol") or ("HTTPS" if "ssl_policy" in a or "certificate_arn" in a else "HTTP")
            port = get("port")
            lb_ref = re.match(r"aws_a?lb\.([\w-]+)\.", (a.get("load_balancer_arn") or ("", 0))[0])
            lb = res.get(("aws_lb", lb_ref.group(1))) or res.get(("aws_alb", lb_ref.group(1))) if lb_ref else None
            lb_attrs = _attrs(lb[0], lb[2], code) if lb else {}
            internal = val(lb_attrs["internal"][0]) if "internal" in lb_attrs else False
            name = (val(lb_attrs["name"][0]) if "name" in lb_attrs else None) or (lb_ref.group(1) if lb_ref else rname)
            exposure = [] if internal else ["internet-facing"]
            ctx = dict(service="AWS ELB", terraform_address=addr, load_balancer=name, recommended_policy=AWS.RECOMMENDED_POLICY,
                       migration_hint=f'ssl_policy = "{AWS.RECOMMENDED_POLICY}"')
            base = dict(source="code", asset=dict(kind="config-file", path=rel, language="terraform", address=addr, load_balancer=name, port=port),
                        location=dict(file=rel, line=at("ssl_policy") if "ssl_policy" in a else line,
                                      snippet=snippet(src, at("ssl_policy") if "ssl_policy" in a else line), symbol=addr))
            if proto in ("HTTP", "TCP", "UDP", "TCP_UDP"):
                redirect = _nested(_nested(body, "default_action") or "", "redirect") or ""
                if re.search(r'protocol\s*=\s*"HTTPS"', redirect):
                    continue
                out.append(Finding(category="transport", algorithm="PLAINTEXT", context=dict(ctx, protocol=proto), flags=["plaintext"] + exposure,
                                   evidence=f"{addr}: {proto}:{port} listener forwards traffic without TLS", **base))
                continue
            policy = get("ssl_policy")
            if policy is None:
                raw = a["ssl_policy"][0] if "ssl_policy" in a else None
                out.append(Finding(category="protocol", algorithm="TLS", params=dict(version="unknown"), context=ctx, confidence=0.3, flags=["implicit-ssl-policy"],
                                   evidence=f"{addr}: {proto} listener " + (f"ssl_policy = {raw} could not be resolved" if raw else "does not pin ssl_policy (provider/API default applies)"),
                                   **base))
                continue
            ctx["ssl_policy"] = policy
            out += cloud.elb_policy_findings(policy, f"{addr} ({name}:{port})", base, ctx, exposure)
            cert = re.match(r"aws_acm_certificate\.([\w-]+)\.", (a.get("certificate_arn") or ("", 0))[0])
            if cert and ("aws_acm_certificate", cert.group(1)) in res:
                cb, _cl, coff = res[("aws_acm_certificate", cert.group(1))]
                ka = val(_attrs(cb, coff, code).get("key_algorithm", ('"RSA_2048"', 0))[0]) or "RSA_2048"
                alg, params = AWS.ACM_KEY.get(ka, ("UNKNOWN-KEY", {}))
                out.append(Finding(category="authentication", algorithm=alg, params=dict(params), context=dict(ctx, certificate=cert.group(1)), flags=list(exposure),
                                   evidence=f"{addr} authenticates with ACM certificate {cert.group(1)} ({ka})", **base))

        elif rtype == "aws_kms_key":
            spec = get("customer_master_key_spec") or get("key_spec") or "SYMMETRIC_DEFAULT"
            usage = get("key_usage") or "ENCRYPT_DECRYPT"
            alg, params = AWS.KMS_KEYSPEC.get(spec, ("UNKNOWN-KEY", {}))
            category = {"SIGN_VERIFY": "signature", "ENCRYPT_DECRYPT": "encryption", "KEY_AGREEMENT": "key-exchange",
                        "GENERATE_VERIFY_MAC": "mac"}.get(usage, "key")
            desc = get("description") or ""
            flags = []
            if alg == "AES" and get("enable_key_rotation") is not True:
                flags.append("rotation-disabled")
            if any(w in f"{rname} {desc}".lower() for w in cloud.LONG_LIVED_WORDS):
                flags.append("long-lived")
            ln = at("customer_master_key_spec") if "customer_master_key_spec" in a else at("key_spec")
            hint = None
            if alg in ("RSA", "ECDSA"):
                hint = ('customer_master_key_spec = "ML_DSA_65" (FIPS 204, supported by AWS KMS)' if category == "signature" else
                        "KMS has no ML-KEM KeySpec: wrap data with a SYMMETRIC_DEFAULT key and move key transport to ML-KEM")
            out.append(mk(ln, category, alg, dict(params, key_spec=spec), f"{addr}: KMS key {spec} / {usage}" + (f" ({desc})" if desc else ""),
                          flags=flags, ctx=dict(service="AWS KMS", key_usage=usage, migration_hint=hint)))

        elif rtype == "aws_acm_certificate" and "private_key" not in a:
            ka = get("key_algorithm") or "RSA_2048"  # ACM default for requested certificates
            alg, params = AWS.ACM_KEY.get(ka, ("UNKNOWN-KEY", {}))
            out.append(mk(at("key_algorithm"), "certificate", alg, dict(params, key_algorithm=ka),
                          f"{addr}: ACM certificate key {ka}" + ("" if "key_algorithm" in a else " (ACM default)"),
                          ctx=dict(service="AWS ACM", domain=get("domain_name"))))

        elif rtype == "tls_private_key":
            algo = (get("algorithm") or "").upper()
            if algo == "RSA":
                bits = get("rsa_bits") or 2048
                out.append(mk(at("algorithm"), "key", "RSA", dict(key_bits=bits), f"{addr}: tls_private_key RSA-{bits}"))
            elif algo == "ECDSA":
                curve = {"P224": "P-224", "P256": "P-256", "P384": "P-384", "P521": "P-521"}.get(get("ecdsa_curve") or "P224")
                out.append(mk(at("algorithm"), "key", "ECDSA", dict(curve=curve), f"{addr}: tls_private_key ECDSA {curve}" + ("" if "ecdsa_curve" in a else " (provider default P224)")))
            elif algo == "ED25519":
                out.append(mk(at("algorithm"), "key", "Ed25519", {}, f"{addr}: tls_private_key ED25519"))

        elif rtype == "aws_cloudfront_distribution":
            vc = _nested(body, "viewer_certificate")
            m = re.search(r'minimum_protocol_version\s*=\s*"([^"]+)"', vc or "")
            if m:
                v = m.group(1)
                ver = "SSL 3.0" if v.startswith("SSLv3") else {"TLSv1": "TLS 1.0", "TLSv1_2016": "TLS 1.0", "TLSv1.1_2016": "TLS 1.1"}.get(v, "TLS 1.3" if v.startswith("TLSv1.3") else "TLS 1.2")
                ln = line + body[:body.find(m.group(0))].count("\n")
                out.append(mk(ln, "protocol", "SSL" if ver.startswith("SSL") else "TLS", dict(version=ver), f"{addr}: CloudFront minimum_protocol_version {v} accepts {ver}",
                              ctx=dict(service="AWS CloudFront", security_policy=v)))

        elif rtype in ("aws_api_gateway_domain_name", "aws_apigatewayv2_domain_name"):
            raw = re.search(r'security_policy\s*=\s*"([^"]+)"', body)
            if raw:
                ver = "TLS 1.0" if "1_0" in raw.group(1) else ("TLS 1.3" if "1_3" in raw.group(1) else "TLS 1.2")
                ln = line + body[:raw.start()].count("\n")
                out.append(mk(ln, "protocol", "TLS", dict(version=ver), f"{addr}: API Gateway security_policy {raw.group(1)}", ctx=dict(service="AWS API Gateway")))
    return out


def _tf_secret(mk, line, addr, attr, value) -> list[Finding]:
    """A credential written in Terraform: always a hard-coded secret; a PEM private key also tells us its algorithm and size."""
    out = [mk(line, "key", "HARDCODED-KEY", dict(name=f"{addr}.{attr}", key_bits=len(value.encode()) * 8),
              f"{addr}: {attr} is a literal in the Terraform source", flags=["hardcoded-key"])]
    if "PRIVATE KEY-----" in value:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key = load_pem_private_key(value.replace("\\n", "\n").encode(), password=None)
        except Exception:  # truncated / encrypted / unsupported PEM: the hard-coded finding stands alone
            return out
        if isinstance(key, rsa.RSAPrivateKey):
            out.append(mk(line, "key", "RSA", dict(key_bits=key.key_size), f"{addr}: hard-coded RSA-{key.key_size} private key", flags=["hardcoded-key"]))
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            curve = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(key.curve.name, key.curve.name)
            out.append(mk(line, "key", "ECDSA", dict(curve=curve), f"{addr}: hard-coded ECDSA {curve} private key", flags=["hardcoded-key"]))
    return out
