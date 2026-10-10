# QuantumTrace

**Cryptographic inventory (CBOM) and post-quantum readiness scanner.** It reads network captures,
source code (Python, Java, Go), config files (nginx, Apache, OpenSSH, Terraform) and AWS cloud exports. It classifies every primitive as
**Shor-vulnerable / Grover-weakened / quantum-safe** and exports a **CycloneDX 1.6 CBOM** that
validates against the official schema. Each finding maps to its NIST replacement:
FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA).

## Quick start (Docker only, nothing else to install)

```bash
git clone https://github.com/ricpote/QuantumRiskAnaliser.git && cd QuantumRiskAnaliser
docker build -t quantumtrace .

# 1. Dashboard -> open http://localhost:8501
docker run --rm -p 8501:8501 quantumtrace

# 2. CLI scan of the official samples -> CBOM, findings, SARIF, summary in ./out
docker run --rm -v "$PWD:/data" quantumtrace qtrace scan /data/samples/official --out /data/out

# 3. Live TLS probe against the bundled offline lab (PQ vs legacy endpoint)
docker run --rm quantumtrace sh -c "tlslab >/dev/null 2>&1 & sleep 2; qtrace probe 127.0.0.1:8443 127.0.0.1:8445"
```

> Linux with SELinux (Fedora/RHEL): add `:Z` to the volume, `-v "$PWD:/data:Z"`.
> Windows PowerShell: use `-v "${PWD}:/data"`.

The image pins every Python dependency (`constraints.txt`) and bundles tshark and the TLS lab.
CI builds it and runs the three commands above on every pull request.

## Results on the official challenge data

These numbers come from `python -m quantumtrace.evaluate`, which compares the scan
against `tests/ground_truth.json`.

| Source | Input | Result |
|---|---|---|
| Network | `network.pcap`: 2000 packets, 135 TCP sessions | 135/135 sessions classified correctly. Only **7/135 (5%)** use hybrid X25519MLKEM768. **114** are exposed to Harvest-Now-Decrypt-Later and **14** are cleartext HTTP |
| Code | 24 files: 8 patterns × Python/Java/Go | 36/36 expected findings, **100% precision and recall**, 10 false-positive traps checked |
| Cloud | KMS (10 keys), ELB (6 load balancers), ACM (5 certs) | 23/23 expectations, 3 traps checked |

These are the only numbers measured on data we did not write. Our own fixtures are scored
separately (`code_by_origin` in the report) so they never inflate the official result:

| Our fixtures (`samples/extra/code/`) | Result |
|---|---|
| nginx, Apache, sshd_config, Terraform, JWT in Python/Java/Go | 60/60 expectations, 5 traps checked |

The synthetic data contains traps on purpose. QuantumTrace handles each of them:

- Ed25519 is "modern" but **Shor-vulnerable**, so it is classified Critical.
- AES key sizes hidden behind constants are resolved: `KEY_LEN = 32`, `KEY_BITS = 256`,
  and `exportKey = []byte("0123456789ABCDEF")` (16 bytes, so AES-128).
- Hand-rolled constructions in Go are recognised by their semantics:
  - **ECB**: a `block.Encrypt` loop with no "ECB" string anywhere;
  - **PBKDF2**: HMAC in a loop with XOR accumulation, 600,000 iterations resolved from the call site.
- `sha512.Sum384` is SHA-384, not SHA-512.
- `signing_tag()` is an HMAC, not a digital signature.
- `rand.Read` resolves to **math/rand** or crypto/rand through the import table.
- Hard-coded keys in demo `main()` code are separated from production constants.
- **tshark 4.2 prints X25519MLKEM768 (0x11EC) as "Unknown".** QuantumTrace reads raw
  codepoints and maps them with its own IANA table.
- TLS 1.3 certificates are encrypted on the wire. Authentication is inferred from the client's
  `signature_algorithms`: only classical schemes were offered, so the server signature is
  necessarily Shor-vulnerable.
- Each key_share length is validated against FIPS 203 sizes (1216/1120 bytes for X25519MLKEM768).
- Offered and negotiated values are kept apart. For example, the client offered AES-256 but the
  server picked AES-128. SSH negotiation follows RFC 4253 §7.1.
- AWS `SslPolicy` is mapped to protocols and ciphers from the official AWS table.
  `ELBSecurityPolicy-2016-08` still allows TLS 1.0 and RSA key transport.
- KMS `SYMMETRIC_DEFAULT` is AES-256-GCM, so it is safe.
- The legacy NLB certificate is **SHA1WITHRSA and expired**.
- The KMS key `legacy-reports-export` is **scheduled for deletion on 2026-10-12**.

## Live TLS probe

```bash
docker run --rm -v "$PWD:/data" quantumtrace qtrace probe example.com mail.example.com:587 db.internal:5432 --deep --out /data/out
```

The probe builds its ClientHellos by hand, so it does not depend on the local OpenSSL supporting PQ.
For each endpoint it measures:

- **What a modern client gets.** A Chrome-like hello offers X25519MLKEM768 and X25519 key shares.
  QuantumTrace then **decrypts its own TLS 1.3 handshake** (ML-KEM decapsulation plus the RFC 8446
  key schedule). That reveals the certificate chain and the real `CertificateVerify` signature scheme,
  even on PQ-only servers that classical clients cannot reach.
- **Each key-exchange group, one hello per group with a real key share:**
  - X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024;
  - pure ML-KEM-512/768/1024;
  - pre-standard Kyber;
  - X25519/X448, P-256/384/521;
  - FFDHE.
- **Protocol versions** from SSL 3.0 to TLS 1.3. **TLS 1.3 ciphers.** **TLS 1.2 ciphers** in server
  preference order (offer all, then remove the chosen one), with the ECDHE curve or DH size taken from
  ServerKeyExchange.
- **With `--deep`**, the signature families the server can authenticate with, including **ML-DSA**
  certificates.
- **STARTTLS** is used automatically on ports 25, 587, 143, 110 and 21. Postgres `SSLRequest` is used on 5432.
- **TLS-interception detection.** If the chain is issued by a proxy or egress CA, the result describes
  the middlebox, which may be stripping PQ.

Every result becomes a normal `Finding` with source `probe`, so it lands in the same score and CBOM.
Classical groups that a PQ server still accepts are reported as *fallback for legacy clients*.
They are real exposure, but client-dependent, so they score 60 instead of 100.

### Offline TLS lab (demo sandbox, also used by the tests)

The lab has two halves in `samples/extra/tls-lab/`: `modern/` (Go ≥ 1.24, which has X25519MLKEM768
in `crypto/tls`) and `legacy/` (port 8445, built with Go 1.21 defaults so TLS 1.0, 3DES and RSA key
transport still work). The Docker image builds both with Go 1.24 and `tlslab` starts them together.
`make lab` and the tests run the same code. Probe every endpoint in one container:

```bash
docker run --rm quantumtrace sh -c "tlslab >/dev/null 2>&1 & sleep 2; qtrace probe 127.0.0.1:8443 127.0.0.1:8444 127.0.0.1:8445 127.0.0.1:8446 127.0.0.1:8447 127.0.0.1:2525 127.0.0.1:5433"
```

| Endpoint | Profile |
|---|---|
| 127.0.0.1:8443 | TLS 1.3 only, X25519MLKEM768 preferred, ECDSA P-256 |
| 127.0.0.1:8444 | Classical TLS 1.2/1.3 (X25519, P-256 only) |
| 127.0.0.1:8445 | Legacy: TLS 1.0–1.2, RSA key transport, CBC, 3DES, **RSA-2048 SHA-1 expired** certificate |
| 127.0.0.1:8446 | PQ for modern clients + classical TLS 1.2 ECDHE fallback, RSA certificate (typical migration state) |
| 127.0.0.1:8447 | **PQ-only**: classical clients are rejected |
| 127.0.0.1:2525 | SMTP + STARTTLS |
| 127.0.0.1:5433 | Postgres SSLRequest + hybrid PQ |

### Real reference captures (`samples/extra/pcap/`)

The pcap ingestor is also validated on **real** traffic. `record.py` and `record_ssh.py` regenerate these files.

**`lab-handshakes.pcapng`**: Go 1.24 and OpenSSL clients against the lab:
- hybrid PQ;
- PQ offered but not negotiated;
- classical client to a PQ server;
- TLS 1.2 certificates in clear;
- TLS 1.0 with 3DES;
- **HelloRetryRequest**;
- SMTP STARTTLS on a **non-standard port**;
- Postgres SSLRequest.

**`lab-ssh.pcapng`**: OpenSSH 9.6 on port 2222:
- default `sntrup761x25519` (PQ hybrid);
- curve25519 with PQ disabled;
- legacy group14-sha1, ssh-rsa, aes128-cbc and hmac-sha1.

Two lessons came from these real captures:
- **Protocols are identified by payload, not port.** SSH or SMTP on any port is recognised from its
  banner, and Postgres from its SSLRequest.
- **Unidentified streams are never called "cleartext".** QuantumTrace only reports cleartext when it
  has positive evidence.

## Config files, JWT and TLS settings in code

Most production crypto is chosen in config, not in code. The code scanner also reads:

| Format | What is checked |
|---|---|
| nginx / Apache | `ssl_protocols`, cipher strings (expanded like OpenSSL, `!`/`-` exclusions applied), `ssl_ecdh_curve` / `Groups`, `ssl_dhparam` size, and `server{}` blocks that answer plain HTTP without a redirect |
| sshd_config / ssh_config | `KexAlgorithms`, `Ciphers`, `MACs`, host-key and pubkey algorithms, `HostKey`. The `+` `-` `^` prefixes modify OpenSSH's default list, so they are resolved against it (`sshd -T`, OpenSSH 9.6): `+diffie-hellman-group1-sha1` keeps the default PQ hybrid in front, `-sntrup761x25519-sha512@openssh.com` removes it. Files are recognised by content too (`sshd_config_hardened`, `server.conf`) |
| Terraform | `aws_lb_listener` SslPolicy, `aws_kms_key` KeySpec, `tls_private_key`, ACM resources |
| JWT | PyJWT / python-jose, jjwt / auth0, golang-jwt: `alg`, `none`, disabled verification, HMAC key size |
| TLS settings in code | Go `tls.Config`: `MinVersion`/`MaxVersion`, `CipherSuites`, `CurvePreferences` (a list without X25519MLKEM768 turns off Go's default PQ hybrid), `InsecureSkipVerify`. Python: `ssl._create_unverified_context()`, `verify_mode = CERT_NONE`, `requests`/`httpx` with `verify=False` |

A setting that is not written is not reported: the product default depends on a version the
scanner cannot see. OpenSSH's `+`/`-`/`^` are the exception, because they only make sense
against the default list.

## Deadlines

Every finding carries the regulatory dates that apply to it and the earliest binding year:

- **NIST IR 8547** (initial public draft, so the dates are proposed): 112-bit quantum-vulnerable
  public-key crypto deprecated after 2030, all of it disallowed after 2035.
- **EU PQC Roadmap** (NIS Cooperation Group, June 2025): inventory by end-2026, high-risk uses
  (HNDL-exposed data, long-lived signatures) by end-2030, the rest by end-2035.
- **NSA CNSA 2.0**: cited for context only, since it binds US National Security Systems.
- Classical retirements: SHA-1 by 2030, 3DES since 2023, TLS 1.0/1.1 (RFC 8996).

## Classification model

| Tier | Rule | Examples |
|---|---|---|
| **Critical** | Shor breaks it | RSA (any size), DSA, DH, ECDH/X25519, ECDSA, Ed25519 |
| **Medium** | Grover leaves under 128-bit post-quantum strength | AES-128, 3DES, SHA-1, MD5, HMAC-SHA1 |
| **Safe** | ≥128-bit post-quantum strength, or a PQC/hybrid scheme | AES-256, ChaCha20, SHA-384, ML-KEM, ML-DSA, X25519MLKEM768 |
| **Unencrypted** | No cryptography at all | Cleartext HTTP, HTTP listeners |

Classical problems are reported **separately** (`classical_status`, flags, CWE): MD5 collisions,
ECB, non-CSPRNG, RSA-1024, expired certificates. A classical issue is never labelled as a
quantum one.

**Urgency and score.** Each finding gets risk points:

| Points | Meaning |
|---|---|
| 100 | Shor + HNDL (key exchange or encryption), or cleartext |
| 90 | Shor on a long-lived signature (root CA, code signing, attestation) |
| 75 | Other Shor use |
| 40 | Grover-weakened |
| 0 | Quantum-safe |

The **Quantum Readiness Score** is the mean over sources of (100 − mean asset risk).

## Outputs

| File | Content |
|---|---|
| `out/cbom.cdx.json` | CycloneDX 1.6 CBOM, described below |
| `out/findings.json` | Normalised findings, with evidence pointing to file:line, pcap stream/frame or ARN |
| `out/results.sarif` | Code findings for GitHub code scanning |
| `out/summary.json` | Score, tiers, HNDL exposure and the prioritised migration plan |

The CBOM contains these CycloneDX objects:

- algorithms with OID, primitive, NIST quantum level and occurrences;
- TLS/SSH protocol components with their cipher suites;
- certificates;
- keys (related-crypto-material);
- libraries;
- `vulnerabilities` entries with CWE and the FIPS 203/204/205 recommendation.

## Architecture

```
ingest/pcap.py   (tshark, numeric fields)   ┐
ingest/code/*    (ast + tree-sitter)        ├─> Finding (schema.py) ─> classify.py (kb/*) ─> score.py ─> export/{cyclonedx,sarif}
ingest/cloud.py  (AWS KMS / ELB / ACM)      ┘                                              └─> app/streamlit_app.py
```

The knowledge base in `quantumtrace/kb/` is the only place where classification rules live:

| File | Content |
|---|---|
| `algorithms.py` | Algorithm catalog, OIDs, NIST levels |
| `tls.py` | IANA cipher suites, groups (incl. ML-KEM hybrids, GREASE, HRR), signature schemes |
| `ssh.py` | SSH algorithm registry |
| `aws.py` | SslPolicy tables, incl. the 2025-09 PQ policies |

## Bad input

One file that cannot be read never stops the scan. It is skipped, reported on stderr as
`[!] skipped <path>: <reason>` and listed under `warnings` in `summary.json`: corrupt captures,
truncated or non-AWS JSON, `kms list-keys` output without key specs, missing paths. An ELB
policy outside the AWS table is derived from its name and marked `policy-derived-from-name`;
a name that cannot be parsed is assumed to be classical ECDHE, never safe.

| Exit code | Meaning |
|---|---|
| 0 | Scan done (warnings, if any, are in `summary.json`) |
| 1 | `probe`: no target answered a TLS handshake |
| 2 | The CBOM failed CycloneDX 1.6 validation |
| 3 | Nothing could be analysed |

## Tests

The accuracy report also runs inside the image:

```bash
docker run --rm quantumtrace python -m quantumtrace.evaluate   # accuracy vs tests/ground_truth.json
```

For development (needs Python ≥ 3.10, tshark and Go ≥ 1.24 installed locally):

```
pip install -e ".[ui,dev]"
make test   # unit tests + ground truth (QT_NOW=2026-10-10)
make eval   # accuracy report
```

Official samples are in `samples/official/`, copied from the upstream repo at commit `39e8f18`.
Put new fixtures in `samples/extra/`.
