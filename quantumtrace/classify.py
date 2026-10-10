"""Classification engine: fills the assessment fields of each Finding from the KB.

Single source of truth for: quantum threat, risk tier, classical status, NIST level,
OID, display name, replacement (FIPS 203/204/205), CWE, deadlines, HNDL, risk points.
"""
from __future__ import annotations

from .kb import deadlines as DL
from .kb.algorithms import (AES_OIDS, CATALOG, CURVE_BITS, CURVE_OIDS, HMAC_OIDS, MLDSA, MLKEM,
                            SIG_OIDS, rsa_bits)
from .schema import Finding

# ----------------------------------------------------------------- replacements
REP_KEM = dict(algorithm="ML-KEM-768", standard="FIPS 203",
               how="Hybrid X25519MLKEM768 in TLS 1.3 / mlkem768x25519-sha256 in SSH (ML-KEM-1024 for CNSA 2.0)")
REP_PKE = dict(algorithm="ML-KEM-768 + AES-256-GCM", standard="FIPS 203",
               how="Replace RSA encryption with a KEM/DEM construction (e.g. HPKE with ML-KEM) and AES-256-GCM")
REP_SIG = dict(algorithm="ML-DSA-65", standard="FIPS 204",
               how="Migrate signatures to ML-DSA-65 (hybrid/composite during transition)")
REP_SIG_LONG = dict(algorithm="ML-DSA-87 or SLH-DSA", standard="FIPS 204 / FIPS 205",
                    how="Long-lived roots, code and firmware signing: ML-DSA-87, SLH-DSA, or LMS/XMSS (SP 800-208)")
REP_AES = dict(algorithm="AES-256-GCM", standard="FIPS 197 + SP 800-38D", how="Use 256-bit keys with an AEAD mode")
REP_HASH = dict(algorithm="SHA-384 (or SHA-256/SHA3-256)", standard="FIPS 180-4 / FIPS 202", how="Replace the digest; sign artifacts instead of bare checksums")
REP_PWD = dict(algorithm="Argon2id (or PBKDF2-HMAC-SHA256 >= 600k)", standard="RFC 9106 / SP 800-132", how="Salted, memory-hard password hashing; rehash on next login")
REP_HMAC = dict(algorithm="HMAC-SHA-256", standard="FIPS 198-1", how="Use SHA-2 based HMAC with >= 256-bit keys")
REP_RNG = dict(algorithm="CSPRNG", standard="NIST SP 800-90A", how="secrets / os.urandom (Python), SecureRandom (Java), crypto/rand (Go)")
REP_TLS = dict(algorithm="TLS 1.3 + X25519MLKEM768", standard="RFC 8446 + FIPS 203", how="Encrypt the channel with TLS 1.3 and a hybrid PQ group")

QUANTUM_POINTS = {"critical": 80.0, "medium": 40.0, "safe": 0.0, "unencrypted": 100.0}
CLASSICAL_POINTS = {"broken": 70.0, "deprecated": 35.0, "acceptable": 0.0, "recommended": 0.0}

LONG_LIVED_HINTS = ("root", "ca", "codesign", "code-sign", "release", "firmware", "attestation", "settlement")


def classify(f: Finding) -> Finding:
    p = dict(f.params or {})
    alg = f.algorithm
    cat = CATALOG.get(alg)
    why = []
    flags = set(f.flags)
    if cat is None:
        f.quantum_threat, f.risk_tier, f.classical_status = "none", "medium", "acceptable"
        f.display_name = alg
        f.confidence = min(f.confidence, 0.3)
        f.rationale = [f"Unknown algorithm '{alg}': not in knowledge base (manual review)"]
        f.risk_points = 40.0
        return f

    threat = cat["threat"]
    classical = "recommended"
    cbits = None
    level = None
    oid = cat.get("oid")
    name = alg
    rep = None
    cwe = set(f.cwe)
    deadlines = []

    # ---------------- asymmetric (Shor) ----------------
    if threat == "shor":
        tier = "critical"
        why.append(f"{cat['family']} relies on factoring/discrete-log: broken by Shor's algorithm")
        if alg in ("RSA", "DH", "DHE", "DH-static", "DSA"):
            kb = p.get("key_bits")
            cbits = rsa_bits(kb)
            name = f"{'RSA' if alg == 'RSA' else ('DSA' if alg == 'DSA' else 'DH')}-{kb}" if kb else alg
            if kb and kb < 2048:
                classical = "deprecated"
                flags.add("short-key")
                cwe.add("CWE-326")
                why.append(f"{kb}-bit modulus is below the 2048-bit classical minimum")
            else:
                classical = "acceptable"
            if alg == "DSA":
                classical = "deprecated"
                why.append("DSA signature generation is no longer approved (FIPS 186-5)")
        elif alg in ("ECDSA", "ECDH", "ECDHE", "ECDH-static"):
            curve = p.get("curve")
            cbits = CURVE_BITS.get(curve)
            name = f"{alg}-{curve}" if curve else alg
            if curve in CURVE_OIDS and alg.startswith("ECDH"):
                oid = CURVE_OIDS[curve]
            classical = "acceptable" if (cbits or 128) >= 128 else "deprecated"
        elif alg in ("X25519", "Ed25519"):
            cbits, classical = 128, "recommended"
        elif alg in ("X448", "Ed448"):
            cbits, classical = 224, "recommended"
        elif alg == "CLASSICAL-SIG":
            cands = p.get("candidates") or []
            name = ("/".join(cands) + " (inferred)") if cands else "classical signature (inferred)"
            classical = "acceptable"
        else:
            classical = "acceptable"
        h = p.get("hash")
        if h in ("SHA-1", "MD5") and f.category in ("signature", "authentication", "certificate", "key"):
            classical = "broken" if h == "MD5" else "deprecated"
            flags.add("weak-signature-hash")
            cwe.add("CWE-328")
            why.append(f"signature uses {h} (collision attacks)")
            name += f" with {h}"
            if h == "SHA-1":
                deadlines.append(DL.SHA1)
        if f.category == "key-exchange" and p.get("hash") == "SHA-1":
            classical = "deprecated"
            flags.add("sha1-kex")
            why.append("key exchange hash is SHA-1 (deprecated, RFC 9142)")
        if alg == "RSA" and p.get("padding") == "PKCS1v15" and f.category == "encryption":
            classical = "deprecated"
            why.append("RSA PKCS#1 v1.5 encryption is vulnerable to padding-oracle attacks (Bleichenbacher)")
        level = 0
        long_lived = "long-lived" in flags  # set by ingestors (root CA, code/firmware signing, attestation...)
        # replacement depends on the ROLE
        if f.category == "key-exchange":
            rep = REP_KEM
        elif f.category == "encryption":
            rep = REP_PKE
        else:
            rep = REP_SIG_LONG if long_lived else REP_SIG
            if long_lived:
                why.append("long-lived trust anchor / signing key: migrate early (signatures cannot be re-issued retroactively)")
        deadlines += DL.for_shor(cbits, high_risk=f.category in ("key-exchange", "encryption") or long_lived,
                                 long_lived=long_lived, web_or_cloud=f.source in ("network", "probe", "cloud"))
        cwe.add("CWE-327")

    # ---------------- post-quantum ----------------
    elif threat == "none" and cat.get("primitive") in ("kem", "signature") and alg not in ("CSPRNG", "NON-CSPRNG"):
        tier = "safe"
        ps = p.get("parameter_set")
        if alg == "ML-KEM" and ps in MLKEM:
            oid, level = MLKEM[ps]
            name = ps
        elif alg == "ML-DSA" and ps in MLDSA:
            oid, level = MLDSA[ps]
            name = ps
        elif cat.get("hybrid"):
            level = 5 if "1024" in alg else 3
        else:
            level = 3
        why.append(f"{name}: post-quantum ({cat['standard']})")
        if cat.get("hybrid"):
            why.append("hybrid: secure if EITHER the classical or the PQ component holds")
        if cat.get("prestandard"):
            classical = "deprecated"
            flags.add("pre-standard-pq")
            why.append("pre-standard Kyber draft: not FIPS 203, being removed by browsers; move to X25519MLKEM768")
            rep = dict(algorithm="X25519MLKEM768", standard="FIPS 203", how="Replace draft codepoint 0x6399 with 0x11EC")
        elif cat.get("nonstandard"):
            classical = "acceptable"
            why.append("PQ-safe but not NIST-standardized; prefer mlkem768x25519-sha256 (OpenSSH >= 9.9)")
            rep = dict(algorithm="mlkem768x25519-sha256", standard="FIPS 203", how="OpenSSH >= 9.9 (default in 10.0)")
    # ---------------- symmetric / hashes / MAC / KDF (Grover) ----------------
    elif threat == "grover":
        tier, classical, cbits, level, name, oid, rep, extra = _grover(f, alg, p, cat, flags, cwe, why)
        deadlines += extra
    # ---------------- protocols / rng / plaintext ----------------
    else:
        tier, classical, name, rep, extra = _misc(f, alg, p, flags, cwe, why)
        deadlines += extra

    # ---------------- context flags (from ingestors) ----------------
    if "no-forward-secrecy" in flags:
        why.append("no forward secrecy: compromise of the server key (classically or by Shor) decrypts ALL recorded sessions")
    if "hardcoded-key" in flags and "demo-code" not in flags:
        classical = "broken"
        cwe.add("CWE-321")
        why.append("hard-coded key in source code")
    if "ecb-mode" in flags and classical != "broken":
        classical = "broken"
    if "tls-interception-suspected" in flags:
        why.append("issuer looks like a TLS-intercepting proxy: the endpoint seen is the middlebox (it may strip PQ key exchange)")
    if "name-mismatch" in flags:
        why.append("certificate does not match the probed hostname")
    if "expired" in flags:
        classical = "broken"
        cwe.add("CWE-298")
        why.append("certificate is expired")
    if "custom-implementation" in flags:
        why.append("hand-rolled crypto construction: prefer a vetted library primitive")
        cwe.add("CWE-1240")

    # ---------------- HNDL ----------------
    hndl = False
    if threat == "shor" and f.category in ("key-exchange", "encryption"):
        hndl = True
        why.append("Harvest-Now-Decrypt-Later: traffic/data recorded today can be decrypted once a CRQC exists")
    if f.category == "transport" and alg == "PLAINTEXT":
        hndl = False  # worse: readable today

    f.quantum_threat = threat if alg != "PLAINTEXT" else "none"
    f.risk_tier = tier
    f.classical_status = classical
    f.classical_bits = cbits
    f.nist_quantum_level = level
    f.oid = oid
    f.display_name = name
    f.replacement = rep
    f.cwe = sorted(cwe)
    f.deadlines = [d["text"] for d in deadlines]
    f.deadline_year = DL.earliest_year(deadlines)
    f.hndl = hndl
    f.flags = sorted(flags)
    # urgency model: HNDL first, then long-lived signatures, then other Shor uses, then Grover
    if tier == "critical" and "fallback-for-legacy-clients" in flags:
        qp = 60.0
        why.append("fallback only: modern PQ-capable clients are protected, legacy clients are not")
    elif tier == "critical":
        qp = 100.0 if hndl else (90.0 if "long-lived" in flags else 75.0)
    else:
        qp = QUANTUM_POINTS[tier]
    f.risk_points = qp
    f.rationale = why
    return f


def _grover(f, alg, p, cat, flags, cwe, why):
    """Symmetric ciphers, hashes, MACs, KDFs. Post-quantum strength ~= classical/2 (Grover)."""
    deadlines = []
    classical = "recommended"
    oid = cat.get("oid")
    rep = None
    name = alg
    if cat["primitive"] in ("block-cipher", "stream-cipher", "ae"):
        kb = p.get("key_bits")
        mode = (p.get("mode") or "").upper() or None
        if alg == "AES":
            if kb is None:
                why.append("AES key size could not be resolved: assuming worst case (128-bit)")
                f.confidence = min(f.confidence, 0.6)
            kb_eff = kb or 128
            name = f"AES-{kb or '?'}" + (f"-{mode}" if mode else "")
            oid = AES_OIDS.get((kb_eff, mode), "2.16.840.1.101.3.4.1")
            cbits = kb_eff
            level = {128: 1, 192: 3, 256: 5}.get(kb_eff, 0)
        elif alg == "3DES":
            name, cbits, level, classical = "3DES-EDE" + (f"-{mode}" if mode else ""), 112, 0, "deprecated"
            deadlines.append(DL.TDEA)
            cwe.add("CWE-327")
            why.append("3DES: 64-bit block (Sweet32) and only 112-bit classical strength")
        elif alg in ("DES", "RC4"):
            name, cbits, level, classical = alg, (kb or 56) if alg == "DES" else 0, 0, "broken"
            cwe.add("CWE-327")
            why.append(f"{alg} is classically broken")
        elif alg == "ChaCha20-Poly1305":
            cbits, level = 256, 5
        else:
            cbits = kb or 128
            level = {128: 1, 192: 3, 256: 5}.get(cbits, 0)
            if alg == "Blowfish":
                classical = "deprecated"
        pq_bits = (cbits or 0) / 2
        tier = "safe" if pq_bits >= 128 else "medium"
        why.append(f"Grover reduces a {cbits}-bit key to ~{int(pq_bits)}-bit post-quantum strength")
        if mode == "ECB":
            flags.add("ecb-mode")
            classical = "broken"
            cwe.add("CWE-327")
            deadlines.append(DL.ECB)
            why.append("ECB mode leaks plaintext patterns (identical blocks -> identical ciphertext)")
        elif mode == "CBC" and classical == "recommended":
            classical = "acceptable"
            if f.source == "network":
                why.append("CBC in TLS/SSH is legacy (padding-oracle / Lucky13 class attacks); prefer AEAD")
        if tier != "safe" or classical in ("broken", "deprecated"):
            rep = REP_AES
        return tier, classical, cbits, level, name, oid, rep, deadlines

    if cat["primitive"] in ("hash", "xof"):
        out = cat.get("out", 256)
        cbits = out // 2  # collision resistance
        level = {256: 2, 384: 4, 512: 5}.get(out, 0)
        pq_pre = out / 2
        tier = "safe" if pq_pre >= 128 and alg not in ("MD5", "MD4", "SHA-1") else "medium"
        why.append(f"{alg}: {out}-bit digest; Grover gives ~{int(pq_pre)}-bit preimage resistance")
        if alg in ("MD5", "MD4"):
            classical, level = "broken", 0
            cwe.update({"CWE-327", "CWE-328"})
            why.append(f"{alg} collisions are practical (classically broken)")
            rep = REP_HASH
        elif alg == "SHA-1":
            classical, level = "broken", 0
            cwe.update({"CWE-327", "CWE-328"})
            deadlines.append(DL.SHA1)
            why.append("SHA-1 collisions are practical (SHAttered 2017, chosen-prefix 2020)")
            rep = REP_HASH
        elif alg == "SHA-224":
            classical = "acceptable"
        if "password-hashing" in flags:
            cwe.add("CWE-916")
            classical = "broken"
            if "unsalted" in flags:
                cwe.add("CWE-759")
            why.append("fast unsalted digest used for password storage (GPU brute force)")
            rep = REP_PWD
        return tier, classical, cbits, level, name, oid, rep, deadlines

    if cat["primitive"] == "mac":
        h = p.get("hash", "SHA-256")
        name = f"HMAC-{h}" if alg == "HMAC" else alg
        oid = HMAC_OIDS.get(h) if alg == "HMAC" else None
        hbits = {"MD5": 128, "SHA-1": 160, "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512}.get(h, 256)
        kbits = p.get("key_bits") or hbits
        eff = min(kbits, hbits) / 2
        tier = "safe" if eff >= 128 else "medium"
        cbits = min(kbits, hbits)
        level = 5 if eff >= 128 else 0
        classical = "acceptable" if h in ("SHA-1", "MD5") else "recommended"
        why.append(f"{name}: Grover on the key gives ~{int(eff)}-bit post-quantum strength")
        if h in ("SHA-1", "MD5"):
            why.append(f"HMAC-{h} is still unbroken as a MAC but deprecated; move to HMAC-SHA-256")
            rep = REP_HMAC
        return tier, classical, cbits, level, name, oid, rep, deadlines

    if cat["primitive"] == "kdf":
        h = p.get("hash")
        it = p.get("iterations")
        name = f"PBKDF2-HMAC-{h}" if alg == "PBKDF2" and h else alg
        tier = "safe"
        cbits, level = 128, None
        classical = "recommended"
        if alg == "PBKDF1":
            classical = "broken"
            cwe.add("CWE-916")
            rep = REP_PWD
        if alg == "PBKDF2":
            if it is not None and it < 100_000:
                classical = "deprecated"
                cwe.add("CWE-916")
                why.append(f"only {it} iterations (OWASP 2023: >= 600,000 for PBKDF2-HMAC-SHA256)")
                rep = REP_PWD
            elif it is not None:
                why.append(f"{it:,} iterations meets OWASP guidance")
            if h in ("SHA-1", "MD5"):
                classical = "deprecated"
                rep = REP_PWD
        why.append("password-based KDF: security bound by password entropy, Grover gives no practical speed-up over GPUs")
        return tier, classical, cbits, level, name, oid, rep, deadlines

    # PSK, other
    tier = "medium" if (p.get("key_bits") or 128) < 256 else "safe"
    return tier, "acceptable", p.get("key_bits"), None, name, oid, rep, deadlines


def _misc(f, alg, p, flags, cwe, why):
    deadlines = []
    if alg == "PLAINTEXT":
        cwe.add("CWE-319")
        flags.add("plaintext")
        why.append("no encryption in transit: data is readable by any on-path observer TODAY")
        return "unencrypted", "broken", "Cleartext (no TLS)", REP_TLS, deadlines
    if alg == "UNIDENTIFIED":
        why.append("protocol could not be identified from the capture: not scored, review manually")
        return "safe", "acceptable", "Unidentified TCP protocol", None, deadlines
    if alg == "HARDCODED-KEY":
        cwe.update({"CWE-321", "CWE-798"})
        why.append(f"key material embedded in source ({p.get('name', '?')}, {p.get('key_bits', '?')} bits): anyone with the repo can decrypt/forge")
        return "safe", ("deprecated" if "demo-code" in flags else "broken"), f"Hard-coded key ({p.get('name', '?')})", dict(algorithm="KMS / secret manager", standard="-", how="Load keys from AWS KMS / a secret manager; rotate the exposed key"), deadlines
    if alg == "NO-CERT-VERIFY":
        cwe.add("CWE-295")
        why.append(f"{p.get('api', 'TLS client')} skips certificate and hostname checks: anyone on the path can impersonate the server "
                   "and read everything, today, with no quantum computer needed")
        return "safe", "broken", "TLS without certificate verification", dict(
            algorithm="Certificate verification", standard="RFC 5280 / RFC 6125", action="Re-enable TLS certificate verification",
            how="Remove the bypass; for a private CA load it explicitly (Go: tls.Config.RootCAs, Python: ssl.create_default_context(cafile=...))"), deadlines
    if alg == "LIBRARY":
        why.append(f.evidence)
        return "safe", "acceptable", f"{p.get('library')} {p.get('version') or ''}".strip(), None, deadlines
    if alg == "NON-CSPRNG":
        cwe.add("CWE-338")
        flags.add("weak-prng")
        why.append(f"non-cryptographic PRNG ({p.get('api', '?')}) used for security tokens: predictable output")
        return "safe", "broken", "Non-cryptographic PRNG", REP_RNG, deadlines
    if alg == "CSPRNG":
        return "safe", "recommended", "CSPRNG", None, deadlines
    if alg == "NULL":
        cwe.add("CWE-319")
        why.append("NULL cipher: no confidentiality")
        return "unencrypted", "broken", "NULL cipher", REP_AES, deadlines
    if alg in ("TLS", "SSL"):
        v = str(p.get("version", ""))
        name = v or alg
        if alg == "SSL" or v in ("SSL 2.0", "SSL 3.0"):
            cwe.add("CWE-327")
            return "safe", "broken", name, REP_TLS, deadlines
        if v in ("TLS 1.0", "TLS 1.1"):
            deadlines.append(DL.TLS_OLD)
            cwe.add("CWE-327")
            why.append(f"{v} is deprecated (RFC 8996)")
            return "safe", "deprecated", name, REP_TLS, deadlines
        if v == "unknown":
            why.append("the TLS configuration could not be identified, so nothing about it is assumed safe: verify it")
            return "safe", "unknown", "TLS (unidentified policy)", REP_TLS, deadlines
        if v == "TLS 1.2":
            why.append("TLS 1.2 cannot negotiate the standardized ML-KEM hybrid groups: TLS 1.3 required for PQ key exchange")
            return "safe", "acceptable", name, dict(algorithm="TLS 1.3", standard="RFC 8446", how="Enable TLS 1.3 (prerequisite for PQ hybrid key exchange)"), deadlines
        return "safe", "recommended", name, None, deadlines
    if alg == "SSH":
        return "safe", "acceptable", f"SSH {p.get('version', '2.0')}", None, deadlines
    return "safe", "acceptable", alg, None, deadlines


def classify_all(findings: list[Finding]) -> list[Finding]:
    return [classify(f) for f in findings]
