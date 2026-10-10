"""Mosca's inequality per asset: at risk when  X + Y > Z.

  X  shelf-life        years the data must stay secret (HNDL) or a signature must stay trusted
  Y  migration time    years needed to move this asset to PQC
  Z  years to Q-Day    Q-Day year - now

Only Shor-vulnerable assets are evaluated: Grover does not break AES-128 / SHA-256 class
primitives in practice, and cleartext needs no quantum computer at all (reported apart).

All numbers below are explicit, explainable ASSUMPTIONS (defaults an organisation would tune),
not measurements. Every result carries the reason for its X and Y.

Q-Day scenarios. Global Risk Institute, Quantum Threat Timeline Report 2025 (published Mar 2026):
experts put a CRQC within 10 years at 28-49% and within 15 years at 51-70%.
  2030 pessimistic | 2033 default (inside GRI's 10-year window) | 2035 NIST IR 8547 / EU final deadline
"""

QDAY_SCENARIOS = {"pessimistic": 2030, "default": 2033, "optimistic": 2035}
QDAY_DEFAULT = QDAY_SCENARIOS["default"]

# ---------------------------------------------------------------- X: shelf-life (years)
# confidentiality (HNDL-exposed key exchange / encryption), by network service or asset kind
SHELF_LIFE_SERVICE = {
    "https": (5, "web/API traffic: session data, credentials and PII stay sensitive ~5 years"),
    "imaps": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "pop3s": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "smtp": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "smtp-submission": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "smtps": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "ldaps": (10, "directory traffic carries credentials and identity data (~10 years)"),
    "postgresql": (10, "database traffic carries business records (~10 years retention)"),
    "postgres": (10, "database traffic carries business records (~10 years retention)"),
    "imap": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "pop3": (10, "e-mail content is kept and stays sensitive ~10 years"),
    "ssh": (5, "admin sessions: commands, credentials and config secrets (~5 years)"),
}
SHELF_LIFE_KIND = {
    "aws-kms-key": (10, "KMS key protects data at rest: kept and sensitive ~10 years"),
    "aws-elb-listener": (5, "internet-facing web traffic: ~5 years"),
    "aws-acm-certificate": (5, "web traffic behind this certificate: ~5 years"),
    "source-file": (7, "data encrypted / key-agreed by application code: ~7 years"),
    "config-file": (5, "traffic protected by this server config: ~5 years"),
}
SHELF_LIFE_CONFIDENTIALITY_DEFAULT = (5, "default confidentiality shelf-life: 5 years")
# authenticity (signatures): forgery only matters while the signature must still be trusted
SHELF_LIFE_LONG_LIVED_SIG = (20, "long-lived trust anchor / code or firmware signing: trusted ~20 years")
SHELF_LIFE_SHORT_SIG = (2, "short-lived signature (TLS handshake, token, certificate): trusted ~2 years")

# ---------------------------------------------------------------- Y: migration time (years)
MIGRATION_KIND = {
    "aws-elb-listener": (1, "swap the ELB SslPolicy to a PQ policy (*-PQ-2025-09)"),
    "config-file": (1, "edit and redeploy a server config (nginx / Apache / sshd / Terraform)"),
    "aws-acm-certificate": (1, "re-issue the certificate"),
    "network-endpoint": (2, "upgrade server TLS/SSH stack and coordinate clients"),
    "source-file": (2, "code change, library upgrade, test and release"),
    "aws-kms-key": (3, "new key spec, re-encrypt or re-sign everything that depends on the key"),
}
MIGRATION_DEFAULT = (2, "default migration time: 2 years")
MIGRATION_LONG_LIVED = (5, "trust anchors / firmware signing: new PKI hierarchy and device roll-out (~5 years)")
MIGRATION_PQ_FALLBACK = (1, "PQ already served: only the classical fallback must be retired")
