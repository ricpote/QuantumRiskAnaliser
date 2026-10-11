# QuantumTrace

**Find every cryptographic primitive in your network traffic, code, configs and cloud, rate it against
quantum attacks, and export a CycloneDX 1.6 CBOM.**

QuantumTrace separates what **Shor's algorithm breaks** (RSA, ECC, DH) from what **Grover's algorithm
weakens** (AES-128, 3DES, SHA-1), flags traffic that can be *harvested now and decrypted later*, and maps
every finding to its NIST replacement: **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)**.

## Quick start

Only Docker is needed.

```bash
git clone https://github.com/ricpote/QuantumRiskAnaliser.git && cd QuantumRiskAnaliser
docker build -t quantumtrace .
docker run --rm -p 127.0.0.1:8501:8501 quantumtrace
```

Open **http://localhost:8501** and click **Analyze reference dataset** (the official challenge samples),
or **New scan** to upload your own files. The image pins every Python dependency (`constraints.txt`) and
bundles tshark and an offline TLS lab for the live probe.

> The dashboard has no authentication and the live probe connects to whatever host you type: keep the
> port on 127.0.0.1 as above, or on a trusted network.

## What it reads

| Input | What QuantumTrace extracts |
|---|---|
| **Network captures** (PCAP/PCAPNG) | TLS 1.0–1.3 Client/Server Hello: offered vs negotiated groups, cipher suites and signature schemes, ML-KEM hybrids (key-share sizes checked against FIPS 203), certificates; SSH key exchange; STARTTLS; cleartext sessions |
| **Live TLS endpoints** | A probe that builds its own handshakes (see [Live TLS probe](#live-tls-probe)) |
| **Source code** (Python, Java, Go, JS/TS) | Crypto API calls with resolved key sizes, modes, IVs, salts and iteration counts; hard-coded keys; weak randomness; JWT algorithms; TLS settings in code |
| **Server configs** | nginx, Apache, OpenSSH (`sshd_config`), Terraform |
| **Cloud exports** (AWS JSON) | KMS key specs, load balancer TLS policies (incl. the 2025 PQ policies), ACM certificates |
| **Certificates and keys** | PEM, DER, OpenSSH, PKCS#12 |

Uploads accept single files or a ZIP (32 MiB, 2,000 files). One unreadable file never stops a scan: it is
skipped and listed as a warning.

## How it rates risk

| Tier | Rule | Examples |
|---|---|---|
| **Critical** | Broken by Shor's algorithm | RSA, DSA, DH, ECDH, X25519, ECDSA, Ed25519 |
| **Medium** | Weakened by Grover's algorithm below 128-bit post-quantum strength | AES-128, 3DES, SHA-1, HMAC-SHA1 |
| **Quantum-resilient** | 128-bit post-quantum strength or more, or a PQC / hybrid scheme | AES-256, ChaCha20, SHA-384, ML-KEM, ML-DSA, X25519MLKEM768 |
| **Unencrypted** | No cryptography at all | Cleartext HTTP |

Classical weaknesses (MD5, ECB, RSA-1024, expired certificates...) are reported separately and never
labelled as quantum ones.

- **Quantum Readiness Score (0–100, grades A–F):** for each source, 100 minus the average risk of its
  assets, then averaged over sources. Risk points per finding: 100 for Shor-vulnerable traffic that can be
  recorded today (or cleartext), 90 for long-lived signatures, 75 for other Shor uses, 60 when only the
  fallback for legacy clients is classical, 40 for Grover, 0 if safe.
- **Migration timeline (Mosca's rule):** for each Shor-vulnerable system, *years the data must stay secret +
  years to migrate > years to Q-Day* means it is already late. Every assumption has a source (NIST, EU, UK NCSC,
  CA/Browser Forum, retention law), listed on the dashboard's **Migration plan → Sources** page.
- **Migration plan:** findings grouped into actions, prioritised P0 (data recordable or readable today) →
  P1 (other Shor uses and broken crypto) → P2, with a what-if that re-scores the report as if the selected
  actions were done.
- **Deadlines:** every finding carries the regulatory dates that apply to it: NIST IR 8547 (proposed:
  112-bit RSA/ECC deprecated after 2030, all quantum-vulnerable public-key crypto disallowed after 2035),
  the EU PQC roadmap (high-risk uses by the end of 2030) and NSA CNSA 2.0.

## Accuracy

On the official challenge data (`python -m quantumtrace.evaluate`, against `tests/ground_truth.json`):

| Source | Result |
|---|---|
| Network (`network.pcap`, 135 TCP sessions) | **135/135** sessions classified correctly: only 7 use hybrid X25519MLKEM768, 114 can be recorded now and decrypted later, 14 are cleartext HTTP |
| Code (24 files, Python / Java / Go) | **36/36** findings, 100% precision and recall, 10 false-positive traps passed |
| Cloud (KMS, load balancers, ACM) | **23/23**, 3 traps passed |

Our own fixtures (181 findings, 18 traps) are scored separately, so they never inflate these numbers.

The official data contains traps on purpose. QuantumTrace handles each of them:

- Ed25519 is "modern" but **Shor-vulnerable**, so it is Critical.
- AES key sizes hidden behind constants are resolved: `KEY_LEN = 32`, `KEY_BITS = 256`, and
  `[]byte("0123456789ABCDEF")` (16 bytes, so AES-128).
- Hand-rolled Go constructions are recognised by what they do: **ECB** (a `block.Encrypt` loop, no "ECB"
  anywhere) and **PBKDF2** (HMAC in a loop with XOR, 600,000 iterations resolved from the call site).
- `sha512.Sum384` is SHA-384; `signing_tag()` is an HMAC, not a signature; `rand.Read` is resolved to
  `math/rand` or `crypto/rand` through the imports.
- **tshark 4.2 prints X25519MLKEM768 (0x11EC) as "Unknown"**: QuantumTrace reads the raw codepoints with its
  own IANA table and checks key-share sizes against FIPS 203 (1216/1120 bytes).
- TLS 1.3 certificates are encrypted on the wire: the server signature is inferred from the client's
  `signature_algorithms`. Offered and negotiated values are kept apart (AES-256 offered, AES-128 chosen).
- AWS: `ELBSecurityPolicy-2016-08` still allows TLS 1.0 and RSA key transport; KMS `SYMMETRIC_DEFAULT` is
  AES-256-GCM (safe); the legacy NLB certificate is SHA-1 and expired; one KMS key is scheduled for deletion.

On public third-party benchmarks (`scripts/run_benchmarks.sh` rebuilds and runs them all):

| Benchmark | Precision | Recall |
|---|---|---|
| OWASP Benchmark (Java crypto, hash, weak random) | 100% | 100% |
| CryptoAPI-Bench | 100% | 91.4% |
| Semgrep crypto rules (Python, Java, Go, JS) | 100% | 91.9% |
| SonarSource rule samples | 100% | 91.2% |
| CodeQL crypto query tests | 100% | 95.9% |
| Bandit examples | 100% | 100% |
| gosec samples | 98.7% | 100% |
| ApacheCryptoAPI-Bench (real Apache projects) | 97.9% | 88.7% |
| NIST Juliet Test Suite, Java crypto CWEs (held-out, first run) | 88.2% | 90.8% |

Except for the NIST Juliet suite, which we ran once after development, we used these benchmarks while building
QuantumTrace to find and fix gaps, so the numbers above are current results, not first attempts: on
ApacheCryptoAPI-Bench, for example, the first run scored 97.5% precision and 73.6% recall. The official challenge
samples were also available during development.

## Outputs

| File | Content |
|---|---|
| `cbom.cdx.json` | **CycloneDX 1.6 CBOM**, validated against the official schema: algorithms (OID, NIST quantum level), TLS/SSH protocols, certificates, keys, libraries, and vulnerabilities with the FIPS 203/204/205 replacement |
| `findings.json` | Every finding with its evidence (file:line, capture stream, ARN), risk tier, replacement and regulatory deadlines |
| `summary.json` | Score, tiers, harvest-now-decrypt-later exposure, migration plan |
| `results.sarif` | Code findings for GitHub code scanning |

The dashboard's **Reports** page downloads the CBOM, the SARIF, the full JSON report and a CSV inventory.

## Dashboard

| Page | Shows |
|---|---|
| Overview | Readiness score, findings per tier, systems late for Q-Day, network exposure, riskiest systems |
| Migration plan | Q-Day scenarios or any custom year, timeline per system, prioritised actions with what-if, sources |
| Crypto inventory | Every finding with evidence, reasoning, replacement, line-level fix and deadlines |
| Live probe | Post-quantum check of any TLS endpoint |
| Explain | How any algorithm is classified in a given role, and why |
| Reports | JSON, CSV, CBOM and SARIF downloads |

The browser never computes a risk, a score or a priority: a small Python API (`quantumtrace/web.py`) runs the
same scanner, scorer and exporters as the CLI.

## Live TLS probe

The probe builds its ClientHellos by hand, so it does not depend on the local OpenSSL supporting PQ:

- **What a modern client gets.** A Chrome-like hello offers X25519MLKEM768 and X25519. QuantumTrace then
  **decrypts its own TLS 1.3 handshake** (ML-KEM decapsulation and the RFC 8446 key schedule) to read the
  certificate chain and the real `CertificateVerify` signature, even on PQ-only servers.
- **Every key-exchange group**, one hello each: the ML-KEM hybrids, pure ML-KEM-512/768/1024, pre-standard
  Kyber, X25519/X448, P-256/384/521 and FFDHE. Classical groups a PQ server still accepts are reported as a
  fallback for legacy clients.
- **Protocol versions** from SSL 3.0 to TLS 1.3, TLS 1.3 ciphers and TLS 1.2 ciphers in server preference order;
  with `--deep`, the signature schemes the server can use, including **ML-DSA**.
- **STARTTLS** on ports 25, 587, 143, 110 and 21, Postgres on 5432, and detection of TLS-intercepting proxies.

The offline lab inside the image can be probed at `127.0.0.1`: **8443** PQ, **8444** classical, **8445** legacy
(TLS 1.0, 3DES, expired SHA-1 certificate), **8446** PQ with classical fallback, **8447** PQ only, **2525** SMTP
STARTTLS, **5433** Postgres.

## Command line

The same image runs the CLI:

```bash
docker run --rm -v "$PWD:/data" quantumtrace qtrace scan /data/samples/official --out /data/out
docker run --rm quantumtrace qtrace probe google.com --deep
docker run --rm quantumtrace qtrace explain AES key_bits=128 mode=ECB category=encryption
```

To open CLI results in the dashboard, and keep uploaded scans after the container is removed, mount a results
folder: `docker run --rm -p 127.0.0.1:8501:8501 -v "$PWD/out:/results" -e QT_RESULTS_DIR=/results quantumtrace`.

On SELinux systems (Fedora, RHEL) add `:Z` to the volume (`-v "$PWD:/data:Z"`); in Windows PowerShell use
`${PWD}` instead of `$PWD`.

## Development

Not needed to run QuantumTrace. CI runs all of this, and builds and tests the Docker image, on every pull request.

<details>
<summary>Run locally without Docker (Python ≥ 3.10, Node 24, tshark, Go ≥ 1.24 for the TLS lab)</summary>

```bash
pip install -e ".[dev]" && npm --prefix frontend ci
make ui       # Python API + dashboard with hot reload on http://localhost:8501
make test     # unit and ground-truth tests
make eval     # accuracy report on the official samples
npm --prefix frontend run typecheck && npm --prefix frontend run lint
npm --prefix frontend test && npm --prefix frontend run build
python scripts/smoke_ui.py http://localhost:8501   # against a running UI: routes, API, upload scan, exports
scripts/run_benchmarks.sh                          # the third-party benchmarks above
```

</details>

```
ingest/pcap.py · ingest/code/* · ingest/cloud.py ─> Finding ─> classify.py (kb/) ─> score.py ─> export/ (CycloneDX, SARIF)
                                                                                           └─> web.py (API) ─> frontend/ (React)
```

The knowledge base (algorithm catalog and OIDs, TLS/SSH registries, AWS policies, Mosca assumptions and their
sources) is in `quantumtrace/kb/`. The official samples are in `samples/official/` (upstream commit `39e8f18`);
our own fixtures are in `samples/extra/`.
