"""Regulatory / standards deadlines cited by the classifier.

Each entry: the text shown in reports, the year it bites (None = no fixed date) and
whether it counts for Finding.deadline_year (the earliest binding deadline).

Status checked 2026-10-10:
  - NIST IR 8547 is still the initial public draft (Nov 2024): its 2030/2035 dates are PROPOSED.
    112-bit schemes (RSA-2048, DH-2048) deprecated after 2030; all quantum-vulnerable public-key
    crypto disallowed after 2035.
  - EU PQC Roadmap (NIS Cooperation Group, Jun 2025): inventory by end-2026, high-risk use cases
    by end-2030, the rest by end-2035.
  - NSA CNSA 2.0 binds US National Security Systems only: cited for context, never binding here.
"""

NIST_8547_112 = dict(id="NIST-IR-8547", year=2030, binding=True,
                     text="NIST IR 8547 (ipd, proposed): 112-bit quantum-vulnerable public-key crypto (RSA-2048, DH-2048) deprecated after 2030, disallowed after 2035")
NIST_8547_128 = dict(id="NIST-IR-8547", year=2035, binding=True,
                     text="NIST IR 8547 (ipd, proposed): quantum-vulnerable public-key crypto at >= 128-bit (ECC P-256+, RSA-3072+) disallowed after 2035")
EU_HIGH = dict(id="EU-PQC-ROADMAP", year=2030, binding=True,
               text="EU PQC Roadmap (NIS CG, Jun 2025): inventory by end-2026; high-risk use cases (HNDL-exposed data, long-lived signatures) quantum-safe by end-2030")
EU_REST = dict(id="EU-PQC-ROADMAP", year=2035, binding=True,
               text="EU PQC Roadmap (NIS CG, Jun 2025): inventory by end-2026; remaining use cases quantum-safe by end-2035")
CNSA_SIGNING = dict(id="CNSA-2.0", year=2030, binding=False,
                    text="NSA CNSA 2.0 (US NSS): software/firmware signing exclusively LMS/XMSS (SP 800-208) or ML-DSA-87 by 2030")
CNSA_WEB = dict(id="CNSA-2.0", year=2033, binding=False,
                text="NSA CNSA 2.0 (US NSS): web browsers/servers and cloud services exclusively ML-KEM-1024 / ML-DSA-87 by 2033")
CNSA_NSS = dict(id="CNSA-2.0", year=2035, binding=False,
                text="NSA CNSA 2.0 (US NSS): all National Security Systems quantum-resistant by 2035 (ML-KEM-1024 / ML-DSA-87 / AES-256 / SHA-384)")
SHA1 = dict(id="NIST-SHA1", year=2030, binding=True,
            text="NIST: SHA-1 retired by 31 Dec 2030 (FIPS 180-5 / SP 800-131A r3)")
TDEA = dict(id="NIST-SP800-131A", year=2023, binding=True,
            text="NIST SP 800-131A r2: TDEA (3DES) encryption disallowed after 2023")
TLS_OLD = dict(id="RFC-8996", year=2021, binding=True,
               text="RFC 8996 (Mar 2021): TLS 1.0 and TLS 1.1 deprecated")
ECB = dict(id="NIST-SP800-131A", year=None, binding=True,
           text="NIST SP 800-131A r3 (ipd): ECB retired for confidentiality")


def for_shor(classical_bits, high_risk: bool, long_lived: bool, web_or_cloud: bool) -> list[dict]:
    """Deadlines for a Shor-vulnerable primitive.

    high_risk: HNDL-exposed (key exchange / encryption) or long-lived signature.
    web_or_cloud: seen on the network / live probe or in a cloud service (CNSA 2.0 web/cloud row).
    Unknown strength counts as 112-bit (worst case).
    """
    nist = NIST_8547_112 if (classical_bits or 112) <= 112 else NIST_8547_128
    eu = EU_HIGH if high_risk else EU_REST
    cnsa = CNSA_SIGNING if long_lived else (CNSA_WEB if web_or_cloud else CNSA_NSS)
    return [nist, eu, cnsa]


def earliest_year(deadlines: list[dict]):
    years = [d["year"] for d in deadlines if d["binding"] and d["year"] is not None]
    return min(years) if years else None
