"""Cloud posture ingestor: AWS KMS / ELB (ALB+NLB) / ACM JSON exports -> Findings.

Accepts the challenge's aggregated exports ({"Keys": [...]}, {"LoadBalancers": [...]},
{"Certificates": [...]}) and also raw AWS CLI outputs ({"KeyMetadata": ...},
{"Listeners": [...]}, {"Certificate": ...}).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from ..kb import aws as AWS
from ..kb import tls as TLS
from ..schema import Finding


def _now() -> datetime:
    env = os.environ.get("QT_NOW")
    return datetime.fromisoformat(env.replace("Z", "+00:00")) if env else datetime.now(timezone.utc)


def _dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


_AWS_KEYS = ("Keys", "KeyMetadata", "LoadBalancers", "Listeners", "Certificates", "Certificate")


def ingest(paths: list[str], problems: list | None = None) -> list[Finding]:
    """problems (optional): receives dict(path, reason) for every file or record that could not be read.
    One bad file or record never aborts the scan: it is reported and the rest is still analysed."""
    problems = problems if problems is not None else []
    docs = []
    for p in paths:
        try:
            with open(p) as fh:
                docs.append((p, json.load(fh)))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            problems.append(dict(path=p, reason=f"unreadable JSON ({type(e).__name__}: {e})"))
    for p, d in docs:
        if not (isinstance(d, dict) and any(k in d for k in _AWS_KEYS)):
            problems.append(dict(path=p, reason="not a recognised AWS export (expected ACM, KMS or ELBv2 describe-* output)"))
        elif isinstance(d.get("Keys"), list) and d["Keys"] and not _as_list(d, "Keys", "KeyMetadata"):
            problems.append(dict(path=p, reason="KMS key list has no key specs (list-keys output?): export with `aws kms describe-key`"))
    certs = {}
    findings: list[Finding] = []

    def guarded(p, what, fn, *args):
        try:
            return fn(*args)
        except Exception as e:  # malformed record: report it, keep going
            problems.append(dict(path=p, reason=f"{what} skipped ({type(e).__name__}: {e})"))
            return []

    for p, d in docs:  # certificates first (listeners reference them)
        for i, c in enumerate(_as_list(d, "Certificates", "Certificate")):
            certs[c.get("CertificateArn")] = c
            findings += guarded(p, f"certificate #{i}", _acm, p, i, c, d)
    for p, d in docs:
        for i, k in enumerate(_as_list(d, "Keys", "KeyMetadata")):
            findings += guarded(p, f"KMS key #{i}", _kms, p, i, k, d)
        lbs = d.get("LoadBalancers", []) if isinstance(d, dict) else []
        for i, lb in enumerate(lbs if isinstance(lbs, list) else []):
            if not isinstance(lb, dict):
                problems.append(dict(path=p, reason=f"load balancer #{i} is not an object"))
                continue
            for j, lst in enumerate(lb.get("Listeners") or []):
                findings += guarded(p, f"listener {i}/{j}", _listener, p, f"/LoadBalancers/{i}/Listeners/{j}", lb, lst, certs, d)
        if isinstance(d, dict) and "Listeners" in d and "LoadBalancers" not in d:
            for j, lst in enumerate(d.get("Listeners") or []):
                findings += guarded(p, f"listener #{j}", _listener, p, f"/Listeners/{j}",
                                    {"LoadBalancerArn": lst.get("LoadBalancerArn") if isinstance(lst, dict) else None}, lst, certs, d)
    return findings


def is_cloud_json(path: str) -> bool:
    try:
        with open(path) as fh:
            d = json.load(fh)
    except Exception:
        return False
    return isinstance(d, dict) and any(k in d for k in _AWS_KEYS)


def _as_list(d, plural, singular):
    if not isinstance(d, dict):
        return []
    if plural in d and isinstance(d[plural], list):
        return [x for x in d[plural] if isinstance(x, dict) and (plural != "Keys" or "KeySpec" in x or "KeyUsage" in x)]
    if singular in d and isinstance(d[singular], dict):
        return [d[singular]]
    return []


def _rel(p):
    return os.path.relpath(p) if not os.path.isabs(p) else os.path.basename(p)


# ------------------------------------------------------------------------- KMS
# key name/description words that mark a long-lived key (roots, code/firmware signing...): migrate first
LONG_LIVED_WORDS = ("root", "certificate authority", "codesign", "release", "firmware", "attestation", "iot", "settlement")


def _kms(path, i, k, doc):
    spec = k.get("KeySpec") or k.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT"
    alg, params = AWS.KMS_KEYSPEC.get(spec, ("UNKNOWN-KEY", {}))
    params = dict(params, key_spec=spec)
    usage = k.get("KeyUsage", "ENCRYPT_DECRYPT")
    sig = k.get("SigningAlgorithms") or []
    enc = k.get("EncryptionAlgorithms") or []
    if sig:
        params.update(AWS.KMS_SIGNING_ALG.get(sig[0], {}))
        params["signing_algorithms"] = sig
    if enc:
        params.update({kk: vv for kk, vv in AWS.KMS_ENCRYPTION_ALG.get(enc[0], {}).items() if alg == "RSA" or kk != "padding"})
        params["encryption_algorithms"] = enc
    category = {"SIGN_VERIFY": "signature", "ENCRYPT_DECRYPT": "encryption", "KEY_AGREEMENT": "key-exchange",
                "GENERATE_VERIFY_MAC": "mac"}.get(usage, "key")
    flags = []
    now = _now()
    desc = (k.get("Description") or "")
    alias = k.get("AliasName") or ""
    if k.get("KeyState") == "PendingDeletion":
        flags.append("pending-deletion")
    if alg in ("AES",) and k.get("KeyRotationStatus") == "DISABLED":
        flags.append("rotation-disabled")
    if k.get("Origin") == "EXTERNAL":
        flags.append("external-key-material")
    if k.get("Origin") == "AWS_CLOUDHSM":
        flags.append("hsm-backed")
    if k.get("MultiRegion"):
        flags.append("multi-region")
    if any(w in (alias + " " + desc).lower() for w in LONG_LIVED_WORDS):
        flags.append("long-lived")
    if "no longer staffed" in desc.lower() or "unowned" in desc.lower():
        flags.append("orphaned-owner")
    created = _dt(k.get("CreationDate"))
    age = round((now - created).days / 365.25, 1) if created else None
    notes = []
    if "pending-deletion" in flags and k.get("DeletionDate"):
        days = (_dt(k["DeletionDate"]) - now).days
        notes.append(f"scheduled for deletion on {k['DeletionDate'][:10]} ({days} days): data still encrypted under it becomes unrecoverable")
    if k.get("ValidTo"):
        notes.append(f"imported key material expires {k['ValidTo'][:10]}: natural migration window")
    ev = f"KMS key {alias or k.get('KeyId')} KeySpec={spec} KeyUsage={usage}" + (f" ({', '.join(sig or enc)})" if (sig or enc) else "")
    if notes:
        ev += "; " + "; ".join(notes)
    asset = dict(kind="aws-kms-key", arn=k.get("KeyArn"), alias=alias, key_id=k.get("KeyId"), account=doc.get("Account"),
                 region=doc.get("Region"), description=desc, tags={t.get("TagKey"): t.get("TagValue") for t in k.get("Tags", [])})
    ctx = dict(service="AWS KMS", key_usage=usage, origin=k.get("Origin"), key_state=k.get("KeyState"),
               rotation=k.get("KeyRotationStatus"), created=k.get("CreationDate"), age_years=age,
               valid_to=k.get("ValidTo"), deletion_date=k.get("DeletionDate"), multi_region=k.get("MultiRegion"))
    if alg in ("RSA", "ECDSA"):
        ctx["migration_hint"] = ("Create a new KMS key with KeySpec ML_DSA_65 (FIPS 204, supported by AWS KMS) and dual-sign during transition"
                                 if category == "signature" else
                                 "KMS has no ML-KEM KeySpec for asymmetric encryption: move partner exchange to an ML-KEM/hybrid KEM-DEM scheme and wrap data with a SYMMETRIC_DEFAULT (AES-256-GCM) key")
    return [Finding(source="cloud", category=category, algorithm=alg, params=params, asset=asset,
                    location=dict(json=_rel(path), pointer=f"/Keys/{i}"), context=ctx, evidence=ev, flags=flags)]


# ------------------------------------------------------------------------- ACM
def _acm(path, i, c, doc):
    alg, params = AWS.ACM_KEY.get(c.get("KeyAlgorithm"), ("UNKNOWN-KEY", {}))
    salg, sparams = AWS.ACM_SIG.get((c.get("SignatureAlgorithm") or "").upper(), (alg, {}))
    params = dict(params, **sparams, signature_algorithm=c.get("SignatureAlgorithm"), key_algorithm=c.get("KeyAlgorithm"))
    now = _now()
    na = _dt(c.get("NotAfter"))
    flags = []
    ev = f"ACM certificate {c.get('DomainName')} {c.get('KeyAlgorithm')} signed {c.get('SignatureAlgorithm')}"
    if na:
        days = (na - now).days
        if days < 0:
            flags.append("expired")
            ev += f"; EXPIRED on {c['NotAfter'][:10]} ({-days} days ago)"
        elif days <= 45:
            flags.append("expiring-soon")
            ev += f"; expires in {days} days ({c['NotAfter'][:10]})"
    if c.get("Type") == "IMPORTED":
        flags.append("imported")
        if c.get("RenewalEligibility") == "INELIGIBLE":
            flags.append("no-auto-renewal")
            ev += "; imported, not eligible for managed renewal"
    asset = dict(kind="aws-acm-certificate", arn=c.get("CertificateArn"), domain=c.get("DomainName"),
                 sans=c.get("SubjectAlternativeNames"), account=doc.get("Account"), region=doc.get("Region"))
    ctx = dict(service="AWS ACM", type=c.get("Type"), status=c.get("Status"), not_before=c.get("NotBefore"),
               not_after=c.get("NotAfter"), in_use_by=c.get("InUseBy", []), renewal=c.get("RenewalEligibility"))
    return [Finding(source="cloud", category="certificate", algorithm=alg, params=params, asset=asset,
                    location=dict(json=_rel(path), pointer=f"/Certificates/{i}"), context=ctx, evidence=ev, flags=flags)]


# ------------------------------------------------------------------------- ELB
def _lb_name(lb_arn, listener_arn=None) -> str:
    """Load balancer name from its ARN (.../loadbalancer/app/NAME/id) or a listener ARN
    (.../listener/app/NAME/lb-id/listener-id). Never raises: hand-made or partial exports
    must not abort the scan."""
    for arn, back in ((lb_arn, 2), (listener_arn, 3)):
        parts = (arn or "").split("/")
        if len(parts) > back:
            return parts[-back]
    return lb_arn or listener_arn or "unknown-load-balancer"


def _listener(path, pointer, lb, lst, certs, doc):
    proto = lst.get("Protocol")
    port = lst.get("Port")
    name = lb.get("LoadBalancerName") or _lb_name(lb.get("LoadBalancerArn"), lst.get("ListenerArn"))
    asset = dict(kind="aws-elb-listener", arn=lst.get("ListenerArn"), load_balancer=name, lb_type=lb.get("Type"),
                 scheme=lb.get("Scheme"), port=port, protocol=proto, account=doc.get("Account"), region=doc.get("Region"))
    loc = dict(json=_rel(path), pointer=pointer)
    out = []
    if proto in ("HTTP", "TCP", "UDP", "TCP_UDP"):
        acts = lst.get("DefaultActions") or []
        if any(a.get("Type") == "redirect" and (a.get("RedirectConfig") or {}).get("Protocol") == "HTTPS" for a in acts):
            return []  # HTTP->HTTPS redirect only: no data served in cleartext
        out.append(Finding(source="cloud", category="transport", algorithm="PLAINTEXT", asset=asset, location=loc,
                           context=dict(service="AWS ELB", default_actions=acts),
                           evidence=f"{name} listener {proto}:{port} forwards traffic without TLS ({lb.get('Scheme')})",
                           flags=["plaintext"] + (["internet-facing"] if lb.get("Scheme") == "internet-facing" else [])))
        return out
    policy = lst.get("SslPolicy")
    ctx = dict(service="AWS ELB", ssl_policy=policy, load_balancer=name, scheme=lb.get("Scheme"),
               recommended_policy=AWS.RECOMMENDED_POLICY,
               migration_hint=f"aws elbv2 modify-listener --listener-arn <arn> --ssl-policy {AWS.RECOMMENDED_POLICY}")
    base = dict(source="cloud", asset=asset, location=loc)
    exposure = ["internet-facing"] if lb.get("Scheme") == "internet-facing" else []
    out += elb_policy_findings(policy, f"{name}:{port}", base, ctx, exposure)
    pol = AWS.SSL_POLICIES.get(policy) or AWS.derive_policy(policy)
    if not pol:
        return out
    ctx = dict(ctx, protocols=pol["protocols"], ciphers=pol["ciphers"], pq=pol["pq"])
    # authentication: certificate key used by this listener
    for c in lst.get("Certificates", []):
        cert = certs.get(c.get("CertificateArn"))
        if cert:
            alg, params = AWS.ACM_KEY.get(cert.get("KeyAlgorithm"), ("UNKNOWN-KEY", {}))
            out.append(Finding(category="authentication", algorithm=alg, params=dict(params), context=dict(ctx, certificate_arn=c.get("CertificateArn")),
                               flags=list(exposure), evidence=f"{name}:{port} authenticates with {cert.get('KeyAlgorithm')} certificate {cert.get('DomainName')}", **base))
    return out


def elb_policy_findings(policy, label, base, ctx, exposure) -> list[Finding]:
    """ELB SslPolicy -> protocol / key-exchange / cipher / MAC Findings. Shared by the AWS JSON and Terraform ingestors.

    base = dict(source, asset, location); label names the listener in evidence (e.g. "web-alb:443")."""
    out = []
    pol = AWS.SSL_POLICIES.get(policy) or AWS.derive_policy(policy)
    if not pol:
        # Nothing usable in the name. Never report it as safe: every ELB TLS policy offers classical
        # ECDHE, and without "-PQ-" there is no evidence of ML-KEM, so assume HNDL exposure.
        check = f"check `aws elbv2 describe-ssl-policies --names {policy}`"
        out.append(Finding(category="protocol", algorithm="TLS", params=dict(version="unknown"), context=ctx, confidence=0.3,
                           evidence=f"Unknown SslPolicy {policy}: {check}", flags=["unknown-policy"] + exposure, **base))
        out.append(Finding(category="key-exchange", algorithm="ECDHE", params=dict(curve=None), context=ctx, confidence=0.5,
                           evidence=f"Unknown SslPolicy {policy}: assumed classical ECDHE (no evidence of ML-KEM); {check}",
                           flags=["unknown-policy", "assumed"] + exposure, **base))
        return out
    derived = bool(pol.get("derived"))
    conf = 0.6 if derived else 1.0
    note = " (deduced from the policy name; it may allow more suites, verify with `aws elbv2 describe-ssl-policies`)" if derived else ""
    exposure = exposure + (["policy-derived-from-name"] if derived else [])
    suites = [TLS.decompose(TLS.iana_from_openssl(c)) for c in pol["ciphers"]]
    ctx = dict(ctx, protocols=pol["protocols"], ciphers=pol["ciphers"], pq=pol["pq"], policy_derived_from_name=derived)
    lowest = min(pol["protocols"], key=lambda v: v)  # "TLS 1.0" < "TLS 1.2"
    out.append(Finding(category="protocol", algorithm="TLS", params=dict(version=lowest), context=ctx, flags=list(exposure), confidence=conf,
                       evidence=f"{label} SslPolicy {policy} allows {', '.join(sorted(pol['protocols']))}{note}", **base))
    # key exchange families supported by the policy
    kex = sorted({s["kex"] or "TLS13" for s in suites})
    if pol["pq"]:
        out.append(Finding(category="key-exchange", algorithm="X25519MLKEM768", params=dict(parameter_set="ML-KEM-768", groups=AWS.PQ_GROUPS),
                           context=ctx, flags=exposure + ["pq-hybrid"], evidence=f"{policy} supports hybrid ML-KEM groups ({', '.join(AWS.PQ_GROUPS)})", **base))
    if "ECDHE" in kex or ("TLS13" in kex and not pol["pq"]):
        out.append(Finding(category="key-exchange", algorithm="ECDHE", params=dict(curve=None), context=ctx, flags=exposure,
                           evidence=f"{policy}: classical (EC)DHE key exchange" + ("" if pol["pq"] else "; no ML-KEM hybrid groups (not a PQ policy)"), **base))
    if "RSA" in kex:
        rsa_suites = [c for c, s in zip(pol["ciphers"], suites) if s["kex"] == "RSA"]
        out.append(Finding(category="key-exchange", algorithm="RSA", params=dict(transport=True), context=ctx,
                           flags=exposure + ["no-forward-secrecy"],
                           evidence=f"{policy} still allows RSA key-transport suites without forward secrecy: {', '.join(rsa_suites)}", **base))
    # bulk ciphers (distinct cipher/bits/mode) and MACs
    seen = set()
    for s in suites:
        key = (s["cipher"], s["cipher_bits"], s["mode"])
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(category="encryption", algorithm=s["cipher"], params=dict(key_bits=s["cipher_bits"], mode=s["mode"]),
                           context=ctx, flags=list(exposure), evidence=f"{policy} allows {s['cipher']}-{s['cipher_bits']}-{s['mode']}", **base))
    if any(s["mac"] == "SHA-1" for s in suites):
        out.append(Finding(category="mac", algorithm="HMAC", params=dict(hash="SHA-1"), context=ctx, flags=list(exposure),
                           evidence=f"{policy} allows HMAC-SHA1 CBC suites", **base))
    if derived:
        for f in out:
            f.confidence = min(f.confidence, conf)
    return out
