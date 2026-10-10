"""CycloneDX 1.6 CBOM exporter (cryptographic-asset components + vulnerabilities).

- algorithms               -> assetType "algorithm" (+ OID, primitive, NIST quantum level, occurrences)
- TLS/SSH configurations   -> assetType "protocol" with cipherSuites referencing the algorithms
- certificates (ACM/pcap)  -> assetType "certificate"
- keys (KMS, hard-coded)   -> assetType "related-crypto-material"
- crypto libraries         -> component type "library"
- risks                    -> "vulnerabilities" (QuantumTrace source, CWE, FIPS 203/204/205 recommendation)
Validated against the official 1.6 JSON schema (cyclonedx-python-lib).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

from ..kb.algorithms import CATALOG
from ..schema import Finding
from .. import __version__

FUNCS = {"signature": ["sign", "verify"], "authentication": ["sign", "verify"], "encryption": ["encrypt", "decrypt"],
         "key-exchange": ["keygen", "encapsulate", "decapsulate"], "hash": ["digest"], "mac": ["tag"], "kdf": ["keyderive"],
         "rng": ["generate"], "certificate": ["verify"], "key": ["sign", "verify"]}
MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
PADS = {"PKCS1V15": "pkcs1v15", "OAEP": "oaep", "PKCS5PADDING": "pkcs5", "PKCS5": "pkcs5", "PKCS7": "pkcs7", "NOPADDING": "raw"}


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def _ref(prefix, *parts):
    h = hashlib.sha1(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:8]
    return f"crypto/{prefix}/{_slug(parts[0])}@{h}"


def _primitive(f: Finding):
    cat = CATALOG.get(f.algorithm, {})
    p = cat.get("primitive")
    if f.algorithm == "RSA":
        return "signature" if f.category in ("signature", "authentication", "certificate", "key") and f.params.get("padding") != "OAEP" else "pke"
    if f.algorithm in ("ECDSA",) and f.category == "key-exchange":
        return "key-agree"
    return p or "other"


def _occ(f: Finding) -> dict:
    loc = f.location or {}
    if "file" in loc:
        o = dict(location=loc["file"], line=loc.get("line"), symbol=loc.get("symbol"))
    elif "probe" in loc:
        o = dict(location=f"tls-probe://{loc['probe']}", symbol=f"probed {loc.get('time', '')[:19]}Z, {loc.get('connections')} handshakes")
    elif "pcap" in loc:
        o = dict(location=f"{loc['pcap']}#tcp.stream=={loc.get('stream')}&frame={loc.get('frame')}",
                 symbol=f"{f.asset.get('host')}:{f.asset.get('port')}")
    else:
        o = dict(location=f.asset.get("arn") or f"{loc.get('json')}#{loc.get('pointer')}", symbol=loc.get("pointer"))
    o["additionalContext"] = f.evidence[:500]
    return {k: v for k, v in o.items() if v is not None}


def _props(d: dict):
    return [{"name": f"quantumtrace:{k}", "value": str(v)} for k, v in d.items() if v not in (None, "", [], {})]


def build(findings: list[Finding], summary: dict, target: str = "scan") -> dict:
    comps = OrderedDict()
    occ = defaultdict(list)
    alg_ref_of = {}
    vulns = OrderedDict()
    deps = defaultdict(set)

    def algo_component(f: Finding):
        p = f.params or {}
        key = (f.display_name, _primitive(f), p.get("mode"), p.get("padding"), p.get("curve"), p.get("parameter_set"),
               f.classical_bits, f.nist_quantum_level, f.quantum_threat)
        if key in alg_ref_of:
            return alg_ref_of[key]
        ref = _ref("algorithm", f.display_name, *key[1:])
        ap = {"primitive": _primitive(f)}
        ps = p.get("parameter_set") or (str(p["key_bits"]) if p.get("key_bits") else None)
        if ps:
            ap["parameterSetIdentifier"] = str(ps).replace("ML-KEM-", "").replace("ML-DSA-", "")
        if p.get("curve"):
            ap["curve"] = {"P-256": "nist/P-256", "P-384": "nist/P-384", "P-521": "nist/P-521", "Curve25519": "x25519"}.get(p["curve"], p["curve"])
        m = str(p.get("mode") or "").lower()
        if m:
            ap["mode"] = m if m in MODES else "other"
        pad = str(p.get("padding") or "").upper()
        if pad:
            ap["padding"] = PADS.get(pad, "other")
        ap["cryptoFunctions"] = FUNCS.get(f.category, ["other"])
        if f.classical_bits is not None:
            ap["classicalSecurityLevel"] = int(f.classical_bits)
        if f.nist_quantum_level is not None:
            ap["nistQuantumSecurityLevel"] = int(f.nist_quantum_level)
        ap["executionEnvironment"] = "hardware" if "hsm-backed" in f.flags else ("software-plain-ram" if f.source == "code" else "unknown")
        ap["implementationPlatform"] = "unknown"
        cp = {"assetType": "algorithm", "algorithmProperties": ap}
        if f.oid:
            cp["oid"] = f.oid
        comps[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": f.display_name, "cryptoProperties": cp,
                      "properties": _props(dict(quantumThreat=f.quantum_threat, riskTier=f.risk_tier, classicalStatus=f.classical_status,
                                                standard=CATALOG.get(f.algorithm, {}).get("standard"),
                                                replacement=(f.replacement or {}).get("algorithm"),
                                                replacementStandard=(f.replacement or {}).get("standard")))}
        alg_ref_of[key] = ref
        return ref

    for f in findings:
        if f.algorithm in ("SCAN-ERROR",):
            continue
        if f.algorithm == "LIBRARY":
            ref = f"lib/{_slug(f.params.get('library'))}@{f.params.get('version') or 'unknown'}"
            eco = f.context.get("ecosystem")
            purl = f"pkg:{eco}/{f.params.get('library')}@{f.params.get('version')}" if eco == "pypi" and f.params.get("version") else None
            comps.setdefault(ref, {k: v for k, v in {"type": "library", "bom-ref": ref, "name": f.params.get("library"), "version": f.params.get("version"),
                                                     "purl": purl, "properties": _props(dict(note=f.evidence))}.items() if v})
            continue
        if f.algorithm == "PLAINTEXT":
            ref = "risk/cleartext-transport"
            comps.setdefault(ref, {"type": "cryptographic-asset", "bom-ref": ref, "name": "Cleartext transport (no TLS)",
                                   "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "other", "version": "none"}},
                                   "properties": _props(dict(riskTier="unencrypted", classicalStatus="broken"))})
            occ[ref].append(_occ(f))
            _vuln(vulns, f, ref)
            continue
        if f.category == "protocol" and f.algorithm in ("TLS", "SSH", "SSL"):
            continue  # protocol components are built per configuration below
        if f.category == "key" or f.source == "cloud" and f.asset.get("kind") == "aws-kms-key":
            aref = algo_component(f)
            ref = _ref("key", f.asset.get("arn") or f.location.get("file", "") + str(f.location.get("line")), f.algorithm)
            asym = f.algorithm not in ("AES", "HMAC", "HARDCODED-KEY")
            state = "compromised" if f.algorithm == "HARDCODED-KEY" else ("deactivated" if "pending-deletion" in f.flags else "active")
            rp = {"type": "private-key" if asym else "secret-key", "state": state, "algorithmRef": aref}
            if f.asset.get("key_id"):
                rp["id"] = f.asset["key_id"]
            if f.context.get("created"):
                rp["creationDate"] = f.context["created"]
                rp["activationDate"] = f.context["created"]
            exp = f.context.get("deletion_date") or f.context.get("valid_to")
            if exp:
                rp["expirationDate"] = exp
            if f.params.get("key_bits"):
                rp["size"] = int(f.params["key_bits"])
            if f.source == "cloud":
                rp["securedBy"] = {"mechanism": "HSM" if "hsm-backed" in f.flags else "AWS KMS"}
            name = f.asset.get("alias") or f"hard-coded key {f.params.get('name', '')}".strip()
            comps[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                          "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp},
                          "properties": _props(dict(flags=",".join(f.flags), riskTier=f.risk_tier, hndl=f.hndl, keyUsage=f.context.get("key_usage"),
                                                    origin=f.context.get("origin"), rotation=f.context.get("rotation")))}
            deps[ref].add(aref)
            occ[ref].append(_occ(f))
            if f.algorithm != "HARDCODED-KEY":
                occ[aref].append(_occ(f))
            _vuln(vulns, f, ref)
            continue
        if f.category == "certificate":
            aref = algo_component(f)
            ref = _ref("certificate", f.asset.get("arn") or f.evidence, f.algorithm)
            cert = f.context.get("certificate") or {}
            cpp = {"subjectName": f"CN={f.asset.get('domain')}" if f.asset.get("domain") else cert.get("subject", "unknown"),
                   "notValidBefore": f.context.get("not_before") or cert.get("not_before"),
                   "notValidAfter": f.context.get("not_after") or cert.get("not_after"),
                   "signatureAlgorithmRef": aref, "certificateFormat": "X.509"}
            if cert.get("issuer"):
                cpp["issuerName"] = cert["issuer"]
            comps[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": f.asset.get("domain") or cert.get("subject", "certificate"),
                          "cryptoProperties": {"assetType": "certificate", "certificateProperties": {k: v for k, v in cpp.items() if v}},
                          "properties": _props(dict(flags=",".join(f.flags), keyAlgorithm=f.params.get("key_algorithm"),
                                                    signatureAlgorithm=f.params.get("signature_algorithm"), inUseBy=",".join(f.context.get("in_use_by", []))))}
            deps[ref].add(aref)
            occ[ref].append(_occ(f))
            _vuln(vulns, f, ref)
            continue
        ref = algo_component(f)
        occ[ref].append(_occ(f))
        _vuln(vulns, f, ref)

    # ---- protocol configurations (TLS / SSH sessions, ELB listeners) ----
    proto_groups = defaultdict(list)
    for f in findings:
        if f.source == "probe":
            if f.category in ("key-exchange", "authentication", "encryption", "mac", "protocol"):
                proto_groups[("tls-probe", None, f.location.get("probe"))].append(f)
            continue
        if f.category in ("key-exchange", "authentication", "encryption", "mac", "protocol") and f.context.get("protocol") in ("TLS", "SSH"):
            ctx = f.context
            if ctx.get("protocol") == "TLS":
                k = ("tls", ctx.get("version"), ctx.get("cipher_suite"))
            else:
                n = ctx.get("negotiated", {})
                k = ("ssh", "2.0", f"{n.get('kex')} / {n.get('hostkey')} / {n.get('cipher_c2s')} / {n.get('mac_c2s')}")
            proto_groups[k].append(f)
        elif f.source == "cloud" and f.context.get("ssl_policy"):
            proto_groups[("tls-policy", None, f.context["ssl_policy"])].append(f)
    for (ptype, ver, name), fs in proto_groups.items():
        refs = []
        for f in fs:
            if f.category != "protocol":
                key_ref = [r for k, r in alg_ref_of.items() if k[0] == f.display_name]
                refs += key_ref[:1]
        refs = sorted(set(refs))
        if ptype == "tls-probe":
            ctx = fs[0].context
            suites = [{"name": c, "identifiers": [c]} for c in ctx.get("tls13_ciphers", []) + ctx.get("tls12_ciphers", [])]
            ref = _ref("protocol", "probe", name)
            vers = [v.replace("TLS ", "") for v, ok in (ctx.get("versions") or {}).items() if ok]
            pp = {"type": "tls", "version": ",".join(vers) or "unknown", "cipherSuites": suites, "cryptoRefArray": refs}
            groups = [g for g, ok in (ctx.get("groups") or {}).items() if ok]
            cname = f"TLS endpoint {name} (live probe; groups: {', '.join(groups) or 'n/a'})"
        elif ptype == "tls-policy":
            ctx = fs[0].context
            suites = [{"name": c, "identifiers": [c]} for c in ctx.get("ciphers", [])]
            ref = _ref("protocol", name)
            pp = {"type": "tls", "version": ",".join(v.replace("TLS ", "") for v in ctx.get("protocols", [])), "cipherSuites": suites, "cryptoRefArray": refs}
            cname = f"TLS policy {name}"
        else:
            kexs = sorted({f.display_name for f in fs if f.category == "key-exchange"})
            ref = _ref("protocol", ptype, ver, name, kexs)
            ident = fs[0].context.get("cipher_suite_code")
            suite = {"name": name, "algorithms": refs}
            if ident:
                suite["identifiers"] = [ident]
            pp = {"type": ptype, "version": str(ver).replace("TLS ", ""), "cipherSuites": [suite], "cryptoRefArray": refs}
            cname = f"{ptype.upper()} {str(ver).replace('TLS ', '')} {name}" + (f" [{', '.join(kexs)}]" if kexs else "")
        comps[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": cname,
                      "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
                      "properties": _props(dict(endpoints=len({(f.asset.get('host'), f.asset.get('port'), f.asset.get('arn')) for f in fs}),
                                                pqKeyExchange=any(f.category == "key-exchange" and f.quantum_threat == "none" for f in fs)))}
        seen = set()
        for f in fs:
            o = _occ(f)
            if o["location"] not in seen and f.category == "protocol":
                seen.add(o["location"])
                occ[ref].append(o)
        deps[ref].update(refs)

    for ref, os_ in occ.items():
        if ref in comps:
            uniq, seen = [], set()
            for o in os_:
                k = (o.get("location"), o.get("line"))
                if k not in seen:
                    seen.add(k)
                    uniq.append(o)
            comps[ref]["evidence"] = {"occurrences": uniq}

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "QuantumTrace", "version": __version__,
                                      "description": "Cryptographic inventory & post-quantum readiness scanner"}]},
            "component": {"type": "application", "bom-ref": "scan-target", "name": target},
            "properties": _props(dict(quantumReadinessScore=summary.get("quantum_readiness_score"), grade=summary.get("grade"),
                                      findings=summary.get("findings"), assets=summary.get("assets"),
                                      hndlExposedEndpoints=summary.get("network", {}).get("hndl_exposed"),
                                      pqProtectedEndpoints=summary.get("network", {}).get("pq_protected"))),
        },
        "components": list(comps.values()),
        "dependencies": [{"ref": "scan-target", "dependsOn": [r for r in comps]}] +
                        [{"ref": r, "dependsOn": sorted(d)} for r, d in deps.items() if d],
        "vulnerabilities": list(vulns.values()),
    }
    return bom


SEV = {"critical": "critical", "unencrypted": "critical", "medium": "medium"}


def _vuln(vulns, f: Finding, ref: str):
    """One vulnerability per (issue, component); affected occurrences accumulate."""
    issues = []
    if f.risk_tier in ("critical", "medium", "unencrypted"):
        kind = "SHOR" if f.quantum_threat == "shor" else ("GROVER" if f.quantum_threat == "grover" else "CLEARTEXT")
        issues.append((kind, SEV[f.risk_tier], f.rationale[:3]))
    if f.classical_status in ("broken", "deprecated") and f.risk_tier != "unencrypted":
        issues.append(("CLASSICAL", "high" if f.classical_status == "broken" else "low", [r for r in f.rationale if "Grover" not in r and "Shor" not in r][:3]))
    for kind, sev, why in issues:
        vid = f"QT-{kind}-{_slug(f.display_name)[:40]}"
        if kind == "SHOR" and f.hndl:
            vid += "-hndl"
        key = (vid, ref)
        if key not in vulns:
            cwes = sorted({int(c.split("-")[1]) for c in f.cwe if c.startswith("CWE-")} if kind != "SHOR" else {327})
            rec = f.replacement or {}
            v = {"bom-ref": f"vuln/{_slug(vid)}/{ref.split('@')[-1]}", "id": vid,
                 "source": {"name": "QuantumTrace", "url": "https://github.com/"},
                 "ratings": [{"source": {"name": "QuantumTrace"}, "severity": sev, "method": "other",
                              "justification": f"{f.quantum_threat}-threat, tier={f.risk_tier}, classical={f.classical_status}, hndl={f.hndl}"}],
                 "cwes": cwes,
                 "description": "; ".join(why) or f.evidence,
                 "recommendation": f"{rec.get('algorithm')} ({rec.get('standard')}): {rec.get('how')}" if rec else "Review",
                 "affects": [{"ref": ref}],
                 "properties": _props(dict(deadlines=" | ".join(f.deadlines), deadline_year=f.deadline_year, occurrences=0))}
            if not cwes:
                v.pop("cwes")
            vulns[key] = v
        p = vulns[key]["properties"]
        for item in p:
            if item["name"] == "quantumtrace:occurrences":
                item["value"] = str(int(item["value"]) + 1)
        if not any(i["name"] == "quantumtrace:occurrences" for i in p):
            p.append({"name": "quantumtrace:occurrences", "value": "1"})


def validate(bom: dict) -> list[str]:
    """Validate against the official CycloneDX 1.6 JSON schema. Returns a list of errors (empty = valid)."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return ["cyclonedx-python-lib not installed: pip install cyclonedx-python-lib"]
    err = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    return [] if err is None else [str(err)]
