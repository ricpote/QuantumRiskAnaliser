"""The Finding contract. Every ingestor (network, code, cloud, probe) emits Findings.

Ingestors fill only the "observation" fields (what was seen and where).
The classifier (quantumtrace.classify) fills the "assessment" fields from the
knowledge base, so classification logic lives in ONE place.

Rule of thumb for ingestors: one Finding = one cryptographic primitive in one
role at one location. A TLS session is decomposed into several Findings
(key-exchange, authentication, encryption, mac/prf, protocol).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# --- vocabularies ---------------------------------------------------------
SOURCES = ("network", "code", "cloud", "probe")

# role the primitive plays (drives HNDL logic and the replacement advice)
CATEGORIES = (
    "key-exchange",    # ECDH(E), DH(E), RSA key transport, ML-KEM, hybrids
    "authentication",  # signature used to authenticate a peer (TLS/SSH host key)
    "signature",       # application-level signing (tokens, receipts, firmware)
    "encryption",      # symmetric or asymmetric encryption of data
    "hash",            # unkeyed digest (checksums, password hashing)
    "mac",             # HMAC / record MAC / PRF hash
    "kdf",             # PBKDF2, HKDF, scrypt, argon2
    "rng",             # randomness source
    "protocol",        # protocol version (TLS 1.0 ... 1.3, SSH-2)
    "certificate",     # X.509 certificate
    "key",             # managed key (KMS)
    "transport",       # e.g. cleartext HTTP (no crypto at all)
)

THREATS = ("shor", "grover", "none")              # quantum threat
TIERS = ("critical", "medium", "safe", "unencrypted")  # challenge tiers + "no crypto at all"
CLASSICAL = ("broken", "deprecated", "acceptable", "recommended")


@dataclass
class Finding:
    # ---------- observation (filled by ingestors) ----------
    source: str                       # one of SOURCES
    category: str                     # one of CATEGORIES
    algorithm: str                    # canonical KB id, e.g. "RSA", "X25519", "AES", "SHA-1", "X25519MLKEM768"
    params: dict = field(default_factory=dict)    # key_bits, mode, curve, padding, hash, iterations, group_id...
    asset: dict = field(default_factory=dict)     # WHAT system: {"kind": "tls-endpoint", "host": "app03.lab", "port": 443}
    location: dict = field(default_factory=dict)  # WHERE the evidence is: file+line | pcap+frame | json+pointer
    context: dict = field(default_factory=dict)   # protocol details, offered vs negotiated, etc.
    evidence: str = ""                # one human-readable sentence: why we say this
    confidence: float = 1.0           # 0..1 (inferred facts < 1.0)
    flags: list = field(default_factory=list)     # e.g. no-forward-secrecy, hardcoded-key, weak-prng, ecb-mode, expired

    # ---------- assessment (filled by classify.py) ----------
    quantum_threat: Optional[str] = None      # shor | grover | none
    risk_tier: Optional[str] = None           # critical | medium | safe | unencrypted
    classical_status: Optional[str] = None    # broken | deprecated | acceptable | recommended
    classical_bits: Optional[int] = None      # classical security strength (bits)
    nist_quantum_level: Optional[int] = None  # 0..5 (CycloneDX nistQuantumSecurityLevel)
    oid: Optional[str] = None
    display_name: Optional[str] = None        # e.g. "AES-128-CBC", "RSA-1024", "X25519MLKEM768"
    replacement: Optional[dict] = None        # {"algorithm": "ML-KEM-768", "standard": "FIPS 203", "how": "..."}
    cwe: list = field(default_factory=list)
    deadlines: list = field(default_factory=list)
    deadline_year: Optional[int] = None       # earliest binding deadline (NIST / EU / RFC); CNSA 2.0 not counted
    hndl: bool = False                        # exposed to Harvest-Now-Decrypt-Later
    risk_points: float = 0.0                  # 0..100, used by score.py
    rationale: list = field(default_factory=list)  # classifier explanations (shown in UI)

    @property
    def id(self) -> str:
        key = json.dumps([self.source, self.category, self.algorithm, self.params,
                          self.asset, self.location], sort_keys=True, default=str)
        return hashlib.sha1(key.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d.pop("id", None)
        return cls(**d)


def dump(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2, default=str)


def load(path: str) -> list[Finding]:
    with open(path) as fh:
        return [Finding.from_dict(d) for d in json.load(fh)]
