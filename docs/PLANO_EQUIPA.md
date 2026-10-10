# QuantumTrace: plano da equipa (JunctionX Lisboa, 10–11 out 2026)

## Ponto de partida (14:30 de sábado)
O baseline funciona end-to-end, ou seja, ninguém começa do zero:
- `python -m quantumtrace scan samples/official --out out` corre em cerca de 3 s.
- Produz findings, CBOM CycloneDX 1.6 (válido no schema oficial), SARIF e o plano de migração.
- `make eval` dá **100%** nos dados oficiais:
  - código: 36/36, precisão 100%;
  - rede: 135/135 sessões;
  - cloud: 23/23;
  - 13 armadilhas de falso positivo verificadas.
- O dashboard Streamlit tem 8 tabs: overview, rede, código, cloud, plano + what-if, CBOM, accuracy e explain.

**A partir de agora, a regra é: cada feature nova traz um fixture em `samples/extra/` e uma entrada em `tests/ground_truth.json`.** Nunca deixamos a accuracy baixar. É isso que vale 40% da nota.

## Atualização 14:40: B1 (probe ao vivo) FEITO
- O `qtrace probe host[:port]` faz ClientHellos crus, enumera grupos PQ, versões e ciphers, usa STARTTLS
  automático e **decifra o próprio handshake TLS 1.3** para ler o certificado e o CertificateVerify.
  Também deteta proxies que intercetam TLS.
- O laboratório TLS offline está em `samples/extra/tls-lab` (`make lab`). Também está no Docker: é a
  **sandbox de reserva para a demo** se a wifi falhar.
- Há capturas reais em `samples/extra/pcap/` (TLS e SSH) e o ingestor foi corrigido com elas:
  protocolo identificado pelo payload, HRR, e nunca "cleartext" sem prova.
- O dashboard tem um tab novo, **Live probe**. Correm 19 testes, todos verdes.
- **Próximo para B:** apontar o probe aos endpoints sandbox oficiais assim que os mentores os derem, e
  testar com `cloudflare.com`/`google.com` na wifi do evento (deve dar X25519MLKEM768). Depois, QUIC.

## Quem faz o quê
| Pessoa | Dono de | Próximas tarefas (por ordem) |
|---|---|---|
| **A, Core** | `classify.py`, `kb/`, `export/`, `score.py`, testes, Docker | 1) Testar o `Dockerfile` numa máquina limpa. 2) `pyproject.toml` com entrypoint `qtrace`. 3) GitHub Actions a correr `make test`. 4) Rever as regras e os textos da KB (deadlines NIST IR 8547, EU, CNSA 2.0). 5) Timeline de Mosca por asset (shelf-life × ano Q-Day). |
| **B, Rede** | `ingest/pcap.py` + probe ativo | 1) **Probe TLS ao vivo** aos endpoints sandbox: ClientHello cru com só 1 grupo oferecido, o servidor responde com HRR/ServerHello/alert. Enumera X25519MLKEM768, SecP256r1MLKEM768, MLKEM768 e x25519, versões e ciphers. 2) Gerar pcaps reais em `samples/extra/` com OpenSSL ≥ 3.5 e Go 1.24: TLS 1.2 com certificado e ECDHE, HRR, PQ oferecido mas não negociado, SSH com sntrup761/mlkem768. 3) QUIC/HTTP3: o ClientHello vai dentro do Initial. |
| **C, Código** | `ingest/code/*` | 1) Ficheiros de config: nginx (`ssl_ciphers`, `ssl_ecdh_curve`), `sshd_config` (`KexAlgorithms`), Terraform (`aws_lb_listener.ssl_policy`, `aws_kms_key.customer_master_key_spec`). Reutilizar `kb/aws.py` e `kb/ssh.py`. 2) JWT (`RS256`/`HS256`/`ES256`). 3) JS/TS (`node:crypto`, WebCrypto). 4) Sugestões de correção (diff) para ECB→GCM, MD5→Argon2id, RSA→ML-DSA. |
| **D, Demo** | `app/streamlit_app.py`, pitch | 1) Polir a UI: modo "história" para a demo, cores, logo. 2) Gráfico HNDL/Mosca. 3) Export do relatório executivo (HTML/PDF). 4) Deck + guião + **vídeo de backup**. |

## Horário (hora de Lisboa)
| Hora | Marco |
|---|---|
| 16:30 | Checkpoint 1: cada um mostra 1 feature nova a passar nos testes |
| 19:00–19:30 | **Submissão rascunho** (repo + README) |
| 20:00 | Jantar |
| 20:45–01:00 | Diferenciadores (probe ao vivo, configs, relatório) |
| 01:00–07:00 | Sono por turnos 2+2 |
| **09:30** | **Feature freeze**: só bugs e polimento |
| 09:30–12:00 | Deck, 3 ensaios, gravar vídeo |
| **12:30** | Submissão final (o deadline é às 13:00) |
| 14:30 | Pitch |

## Perguntas para os mentores (Inspiring Solutions)
1. Quais são os **endpoints sandbox** (o PDF fala em 2–3, mas não estão no repo)?
2. Os jurados vão correr a ferramenta com **dados escondidos**?
3. Qual é a duração e o formato do pitch, e há demo ao vivo?
4. O Dockerfile é obrigatório?

## História do pitch (3–4 min)
1. **Gancho.** "Das 135 sessões que gravámos, 114 podem ser decifradas no dia em que existir um computador quântico. 14 nem precisam de esperar: vão em texto claro. A UE quer o inventário criptográfico começado até 31/12/2026, daqui a 82 dias."
2. **Problema.** Ninguém sabe onde está a sua criptografia: na rede, no código, na cloud.
3. **Demo**, com um só comando:
   - QRS 31.9 (E);
   - rede: 7 sessões vault PQ ✓;
   - código: a armadilha Ed25519 e o ECB feito à mão em Go;
   - cloud: cert SHA-1 expirado, chave KMS apagada daqui a 2 dias, política ELB de 2016;
   - tab Accuracy a 100%;
   - CBOM válido;
   - what-if: mudar a política ELB e ativar X25519MLKEM768 faz o score subir.
4. **Rigor.**
   - Mapeamento para FIPS 203/204/205, NIST IR 8547, roadmap UE, CNSA 2.0, CWE e SARIF.
   - O tshark mostra "Unknown 0x11EC" e nós não caímos nisso.
   - A autenticação TLS 1.3 é inferida, não inventada.
5. **Fecho.** "QuantumTrace transforma dívida criptográfica num plano de migração."

## Factos verificados (para o pitch)
- **AWS ELB.** Existem políticas PQ (`*-PQ-2025-09`). A recomendada é `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`, que suporta X25519MLKEM768, SecP256r1MLKEM768 e SecP384r1MLKEM1024.
- **AWS KMS.** Suporta ML-DSA (`ML_DSA_44/65/87`) desde junho de 2025.
- **NIST IR 8547** (ainda draft). Os algoritmos vulneráveis a quântica ficam deprecated depois de 2030 (112 bits) e disallowed depois de 2035.
- **Roadmap PQC da UE** (NIS Cooperation Group, junho de 2025):
  - inventário até ao fim de 2026;
  - casos de alto risco até ao fim de 2030;
  - o resto até 2035.
- **Go 1.24.** X25519MLKEM768 vem ligado por omissão em `crypto/tls`, e há `crypto/mlkem`.
- **JDK 24+.** ML-KEM (JEP 496) e ML-DSA (JEP 497).
- **OpenSSH.** O 9.0+ tem sntrup761x25519 por omissão. O 9.9+ tem mlkem768x25519-sha256, que é o default a partir do 10.0.
