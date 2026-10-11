"""Mosca's inequality per asset: at risk when  X + Y > Z.

  X  shelf-life        years the data must stay secret (HNDL) or a signature must stay trusted
  Y  migration time    years needed to move this asset to PQC
  Z  years to Q-Day    Q-Day year - now

Only Shor-vulnerable assets are evaluated: Grover does not break AES-128 / SHA-256 class
primitives in practice, and cleartext needs no quantum computer at all (reported apart).

Every number below is an explicit default with its reasoning and sources (SOURCES), not a
measurement; an organisation tunes them to its own retention duties. The dashboard's
"Sources" page (/migration/sources, served by /api/assumptions) lists them all. `basis` says
how a number relates to its sources:
  stated    the number is written in the source (a law's retention period, a policy limit)
  derived   computed from numbers in the source (e.g. SP 800-57: 2 + 3 years)
  estimate  engineering estimate bounded by the sources (no source gives the exact number)
"""
from __future__ import annotations

from typing import NamedTuple


class Assumption(NamedTuple):
    years: int
    why: str
    sources: tuple[str, ...]
    basis: str = "derived"


# ---------------------------------------------------------------- sources
SOURCES = {
    "nist-ir8547": dict(
        title="NIST IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards",
        publisher="NIST", date="2024-11", primary=True,
        url="https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf",
        says="Describes Mosca's theorem (X + Y > Z). Quantum-vulnerable signatures and key establishment at 112-bit "
             "strength: deprecated after 2030, disallowed after 2035; 128-bit and above: disallowed after 2035. "
             "Authentication only has to be secure when it is performed (no harvest-now-decrypt-later). Past "
             "cryptographic migrations took over a decade; full integration can take 10 to 20 years."),
    "nist-sp800-57": dict(
        title="NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management (Table 1, suggested cryptoperiods)",
        publisher="NIST", date="2020-05", primary=True,
        url="https://doi.org/10.6028/NIST.SP.800-57pt1r5",
        says="Symmetric data-encryption keys: originator-usage period up to 2 years, recipient-usage period up to "
             "3 years beyond it, so data protected under one key stays in use about 5 years. Private signature "
             "keys: 1 to 3 years."),
    "gri-2025": dict(
        title="Quantum Threat Timeline Report 2025 (M. Mosca, M. Piani)",
        publisher="Global Risk Institute", date="2026-03-09", primary=True,
        url="https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/",
        says="Experts consider a cryptographically relevant quantum computer quite possible (28-49%) within "
             "10 years and likely (51-70%) within 15 years."),
    "eu-roadmap": dict(
        title="A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography (Part 1, v1.1)",
        publisher="EU NIS Cooperation Group, PQC work stream (European Commission)", date="2025-06-11", primary=True,
        url="https://ec.europa.eu/newsroom/dae/redirection/document/117507",
        says="Member States start a national PQC transition strategy by the end of 2026; high-risk use cases are "
             "transitioned as soon as possible, no later than the end of 2030; by 2035 the transition is completed "
             "for as many systems as practically feasible."),
    "ncsc-timelines": dict(
        title="Timelines for migration to post-quantum cryptography",
        publisher="UK NCSC", date="2025-03-20", primary=True,
        url="https://www.ncsc.gov.uk/guidance/pqc-migration-timelines",
        says="By 2028 define migration goals, run a full discovery and build an initial plan; by 2031 carry out the "
             "highest-priority migrations; by 2035 complete migration of all systems, services and products."),
    "nsa-cnsa2": dict(
        title="CNSA 2.0 FAQ (Cybersecurity Information Sheet)",
        publisher="NSA", date="2024-12", primary=True,
        url="https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
        says="The NSA's own CNSA 2.0 document (algorithms and transition for National Security Systems). It opens in "
             "a browser but refuses automated downloads, so its timetable is cited through the summary above."),
    "cnsa2-timeline": dict(
        title="NSA suite against cryptanalytically relevant quantum computers (summary of the CNSA 2.0 timetable)",
        publisher="Utimaco", date="2023-03-13", primary=False,
        url="https://utimaco.com/news/blog-posts/NSA-suite-against-cryptanalytically-relevant-quantum-computers",
        says="Software and firmware signing: begin transitioning immediately, CNSA 2.0 by 2025, exclusively by 2030. "
             "Cloud services and web browsers/servers: support and prefer by 2025, only CNSA 2.0 by 2033."),
    "pt-codigo-comercial": dict(
        title="Código Comercial (Portugal), art. 40.º n.º 1: correspondence and commercial records",
        publisher="InvoiceXpress (quotes the article)", date="2025", primary=False,
        url="https://invoicexpress.com/blog/arquivo-documentos-quanto-tempo-deve-guardar-documentos-contabilisticos/",
        says="Every merchant keeps the correspondence sent and received, its commercial records and related "
             "documents, for 10 years."),
    "pt-circ-123": dict(
        title="Código do IRC (Portugal), art. 123.º n.º 4: accounting books, records and supporting documents",
        publisher="Autoridade Tributária, Portal das Finanças", date="2017", primary=True,
        url="https://info.portaldasfinancas.gov.pt/pt/informacao_fiscal/codigos_tributarios/circ_rep/Pages/irc123.aspx",
        says="Accounting books, records and their supporting documents are kept for 10 years."),
    "de-hgb-257": dict(
        title="Aufbewahrungspflicht (HGB § 257, AO § 147): retention periods in Germany",
        publisher="Steuer-Berater.de", date="2025", primary=False,
        url="https://www.steuer-berater.de/lexikon/aufbewahrungspflicht",
        says="Books and annual accounts 10 years, accounting vouchers 8 years since 2025, business letters 6 years."),
    "cabf-sc081": dict(
        title="Ballot SC-081v3: Introduce Schedule of Reducing Validity and Data Reuse Periods",
        publisher="CA/Browser Forum", date="2025-04-11", primary=True,
        url="https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/",
        says="Passed: the maximum validity of publicly trusted TLS certificates falls from 398 days to 47 days, in "
             "steps starting in March 2026 and concluding in March 2029."),
    "cabf-br": dict(
        title="Baseline Requirements for TLS Server Certificates, section 6.3.2 (maximum validity periods)",
        publisher="CA/Browser Forum", date="2025", primary=True,
        url="https://github.com/cabforum/servercert/blob/main/docs/BR.md",
        says="Subscriber certificates issued from 2026-03-15 are valid at most 200 days, from 2027-03-15 at most "
             "100 days, from 2029-03-15 at most 47 days."),
    "mozilla-root-lifecycle": dict(
        title="Root CA Lifecycles (Mozilla Root Store Policy § 7.4)",
        publisher="Mozilla", date="2023", primary=True,
        url="https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
        says="The websites trust bit of a root CA is removed when its key material is more than 15 years old."),
    "chrome-root-term": dict(
        title="Root CA term limits in the Chrome and Mozilla root programs",
        publisher="Sectigo", date="2025", primary=False,
        url="https://www.sectigo.com/resource-library/enhancements-to-root-ca-and-hierarchies",
        says="Chrome and Mozilla limit a root CA certificate's usability to at most 15 years after its private "
             "key was generated."),
    "aws-elb-pq": dict(
        title="Application and Network Load Balancers now support post-quantum key exchange for TLS",
        publisher="AWS", date="2025-11-21", primary=True,
        url="https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls",
        says="Hybrid ML-KEM key exchange for ALB and NLB through new, opt-in TLS security policies, at no additional "
             "cost: an existing listener is migrated by switching it to a PQ policy."),
    "aws-elb-policies": dict(
        title="Security policies for your Network Load Balancer",
        publisher="AWS documentation", date="2025", primary=True,
        url="https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html",
        says="Policies with PQ in their name (console default ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09) offer "
             "SecP256r1MLKEM768, SecP384r1MLKEM1024 and X25519MLKEM768 alongside classical key exchange."),
    "aws-kms-mldsa": dict(
        title="AWS KMS adds support for post-quantum ML-DSA digital signatures",
        publisher="AWS", date="2025-06-13", primary=True,
        url="https://aws.amazon.com/about-aws/whats-new/2025/06/aws-kms-post-quantum-ml-dsa-digital-signatures",
        says="Three ML-DSA key specs (ML_DSA_44, ML_DSA_65, ML_DSA_87) through the existing CreateKey and Sign APIs."),
    "openssl-35": dict(
        title="OpenSSL 3.5 Alpha release announcement",
        publisher="OpenSSL Library", date="2025-03-12", primary=True,
        url="https://openssl-library.org/post/2025-03-11-openssl-3.5-alpha/",
        says="The default TLS key shares offer X25519MLKEM768 and X25519: servers on OpenSSL 3.5 (nginx, "
             "Apache...) negotiate hybrid ML-KEM by default."),
    "openssh-10": dict(
        title="OpenSSH 10.0 release notes",
        publisher="OpenSSH", date="2025-04-09", primary=True,
        url="https://www.openssh.org/txt/release-10.0",
        says="ssh(1) now uses the hybrid post-quantum algorithm mlkem768x25519-sha256 by default for key agreement."),
    "google-mlkem": dict(
        title="A new path for Kyber on the web",
        publisher="Google Security Blog", date="2024-09-13", primary=True,
        url="https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html",
        says="Chrome 131 moves its hybrid post-quantum key exchange from Kyber (codepoint 0x6399) to "
             "ML-KEM768+X25519 (0x11EC)."),
    "chrome-mtc": dict(
        title="Inside DigiCert's MTC Playground (Merkle Tree Certificates)",
        publisher="DigiCert", date="2026-03-06", primary=False,
        url="https://www.digicert.com/blog/digicert-mtc-playground",
        says="Chrome has no immediate plan to add post-quantum X.509 certificates to its root store; a Chrome "
             "Quantum-resistant Root Store accepting only Merkle Tree Certificates is planned for Q3 2027."),
}

# ---------------------------------------------------------------- Z: Q-Day scenarios
QDAY_SCENARIOS = {"pessimistic": 2030, "default": 2033, "optimistic": 2035}
QDAY_DEFAULT = QDAY_SCENARIOS["default"]
QDAY_REASONS = {
    "pessimistic": ("2030: NIST deprecates 112-bit RSA/ECC/DH after 2030, the EU wants high-risk use cases "
                    "protected by the end of 2030, CNSA 2.0 requires PQ firmware signing by 2030",
                    ("nist-ir8547", "eu-roadmap", "cnsa2-timeline")),
    "default": ("2033: inside the 10-year window in which experts consider a CRQC quite possible (28-49%); "
                "CNSA 2.0 requires PQ for web servers and cloud services by 2033",
                ("gri-2025", "cnsa2-timeline")),
    "optimistic": ("2035: NIST disallows quantum-vulnerable public-key crypto after 2035, the US (NSM-10), UK and "
                   "EU goal for completing the migration",
                   ("nist-ir8547", "ncsc-timelines", "eu-roadmap")),
}

# ---------------------------------------------------------------- X: shelf-life (years)
# confidentiality (HNDL-exposed key exchange / encryption), by network service or asset kind
_DATA_KEY_WINDOW = Assumption(
    5, "traffic and data with no legal retention period: a data-encryption key is used up to 2 years and its data "
       "read up to 3 more (NIST SP 800-57, 2 + 3 years)", ("nist-sp800-57",))
_CORRESPONDENCE = Assumption(
    10, "e-mail is business correspondence, kept 10 years (Código Comercial art. 40.º; 6 years in Germany)",
    ("pt-codigo-comercial", "de-hgb-257"), "stated")
_RECORDS = Assumption(
    10, "database traffic carries business records, kept 10 years (CIRC art. 123.º n.º 4; HGB § 257)",
    ("pt-circ-123", "de-hgb-257"), "stated")

SHELF_LIFE_SERVICE = {
    "https": _DATA_KEY_WINDOW,
    "ssh": _DATA_KEY_WINDOW,
    "ldaps": _DATA_KEY_WINDOW,
    "imaps": _CORRESPONDENCE, "pop3s": _CORRESPONDENCE, "smtp": _CORRESPONDENCE, "smtp-submission": _CORRESPONDENCE,
    "smtps": _CORRESPONDENCE, "imap": _CORRESPONDENCE, "pop3": _CORRESPONDENCE,
    "postgresql": _RECORDS, "postgres": _RECORDS,
}
SHELF_LIFE_KIND = {
    "aws-kms-key": Assumption(
        10, "KMS key protects data at rest: business records are kept 10 years (CIRC art. 123.º n.º 4)",
        ("pt-circ-123", "de-hgb-257")),
    "aws-elb-listener": _DATA_KEY_WINDOW,
    "aws-acm-certificate": _DATA_KEY_WINDOW,
    "source-file": _DATA_KEY_WINDOW,
    "config-file": _DATA_KEY_WINDOW,
}
SHELF_LIFE_CONFIDENTIALITY_DEFAULT = _DATA_KEY_WINDOW
# authenticity (signatures): forgery only matters while the signature must still be trusted
SHELF_LIFE_LONG_LIVED_SIG = Assumption(
    15, "long-lived trust anchor / code or firmware signing: browsers trust a root CA at most 15 years after its "
        "key was generated (Mozilla and Chrome root programs)",
    ("mozilla-root-lifecycle", "chrome-root-term", "nist-ir8547"), "stated")
SHELF_LIFE_SHORT_SIG = Assumption(
    1, "short-lived signature (TLS handshake, token, certificate): certificates last at most 200 days since March "
       "2026, and authentication only has to hold while it is performed",
    ("cabf-br", "cabf-sc081", "nist-ir8547"))

# ---------------------------------------------------------------- Y: migration time (years)
MIGRATION_KIND = {
    "aws-elb-listener": Assumption(
        1, "swap the ELB SslPolicy to a PQ policy (*-PQ-2025-09, available since November 2025)",
        ("aws-elb-pq", "aws-elb-policies")),
    "config-file": Assumption(
        1, "upgrade to a PQ-capable library (OpenSSL 3.5, OpenSSH 10 offer ML-KEM by default) and redeploy the "
           "server config (nginx / Apache / sshd / Terraform)", ("openssl-35", "openssh-10")),
    "aws-acm-certificate": Assumption(
        3, "no publicly trusted post-quantum certificates yet: wait for the post-quantum WebPKI (Chrome targets "
           "2027), then re-issue", ("chrome-mtc", "nist-ir8547"), "estimate"),
    "network-endpoint": Assumption(
        2, "upgrade the server TLS/SSH stack (OpenSSL 3.5 / OpenSSH 10) and coordinate clients (Chrome already "
           "negotiates ML-KEM)", ("openssl-35", "openssh-10", "google-mlkem"), "estimate"),
    "source-file": Assumption(
        2, "code change, library upgrade, test and release, within the 3-year priority phase of national roadmaps",
        ("ncsc-timelines", "nist-ir8547"), "estimate"),
    "aws-kms-key": Assumption(
        3, "new ML-DSA key spec (KMS supports it since June 2025), re-encrypt or re-sign everything that depends "
           "on the key, within the 3-year priority phase (NCSC 2028-2031)", ("aws-kms-mldsa", "ncsc-timelines"),
        "estimate"),
}
MIGRATION_DEFAULT = Assumption(
    2, "default migration time: code or stack upgrade within the 3-year priority phase of national roadmaps",
    ("ncsc-timelines", "nist-ir8547"), "estimate")
MIGRATION_LONG_LIVED = Assumption(
    5, "trust anchors / firmware signing: new PKI hierarchy and device roll-out; CNSA 2.0 gives firmware signing "
       "5 years (prefer by 2025, exclusive by 2030)", ("cnsa2-timeline", "nsa-cnsa2"))
MIGRATION_PQ_FALLBACK = Assumption(
    1, "PQ already served: only the classical fallback must be retired (a policy or config change)",
    ("aws-elb-pq", "openssl-35"), "estimate")

_SERVICE_LABEL = {"https": "Web / API traffic (HTTPS)", "ssh": "SSH sessions", "ldaps": "Directory traffic (LDAPS)",
                  "postgresql": "Database traffic (PostgreSQL)", "postgres": "Database traffic (PostgreSQL)"}
_KIND_LABEL = {"aws-kms-key": "AWS KMS key", "aws-elb-listener": "AWS load balancer listener",
               "aws-acm-certificate": "AWS ACM certificate", "source-file": "Application source code",
               "config-file": "Server configuration (nginx, Apache, sshd, Terraform)",
               "network-endpoint": "Network endpoint (TLS / SSH server)"}


def _row(label: str, a: Assumption) -> dict:
    return dict(label=label, years=a.years, why=a.why, basis=a.basis, sources=list(a.sources))


def assumptions() -> dict:
    """Every Z, X and Y default with its reasoning and sources (the dashboard's Sources page)."""
    # one row per distinct assumption, naming every service and asset kind it covers
    window = [_SERVICE_LABEL[n] for n, a in SHELF_LIFE_SERVICE.items() if a is _DATA_KEY_WINDOW]
    window += [_KIND_LABEL[k] for k, a in SHELF_LIFE_KIND.items() if a is _DATA_KEY_WINDOW]
    shelf = [_row("E-mail (IMAP, POP3, SMTP and their TLS variants)", _CORRESPONDENCE),
             _row("Database traffic (PostgreSQL)", _RECORDS),
             _row(_KIND_LABEL["aws-kms-key"] + " (data at rest)", SHELF_LIFE_KIND["aws-kms-key"]),
             _row(", ".join(window) + "; any other confidential traffic", _DATA_KEY_WINDOW)]
    shelf.append(_row("Long-lived signatures: root CA, code and firmware signing", SHELF_LIFE_LONG_LIVED_SIG))
    shelf.append(_row("Short-lived signatures: TLS handshake, token, certificate", SHELF_LIFE_SHORT_SIG))
    migration = [_row(_KIND_LABEL[k], a) for k, a in MIGRATION_KIND.items()]
    migration += [_row("Trust anchors and firmware signing", MIGRATION_LONG_LIVED),
                  _row("Already serves PQ, classical fallback still on", MIGRATION_PQ_FALLBACK),
                  _row("Anything else", MIGRATION_DEFAULT)]
    qday = [dict(scenario=name, year=year, why=QDAY_REASONS[name][0], sources=list(QDAY_REASONS[name][1]))
            for name, year in QDAY_SCENARIOS.items()]
    return dict(qday=qday, shelf_life=shelf, migration=migration,
                sources=[dict(id=k, **v) for k, v in SOURCES.items()])
