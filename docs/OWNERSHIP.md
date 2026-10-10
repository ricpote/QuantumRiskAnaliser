# Quem mexe em quê (para não termos conflitos)

Somos 4 a trabalhar ao mesmo tempo no mesmo repo. A regra que evita 90% dos conflitos é simples:
**cada pessoa só escreve nos ficheiros da sua coluna.** Se precisares de mudar um ficheiro de outra
pessoa, mete uma mensagem no grupo em vez de editares à sorte.

| Dono | Escreve nestes ficheiros | Nunca mexe em |
|---|---|---|
| **A, Core** | `quantumtrace/classify.py`, `quantumtrace/kb/*`, `quantumtrace/score.py`, `quantumtrace/export/*`, `quantumtrace/schema.py`, `Dockerfile`, `pyproject.toml`, `.github/*`, `Makefile` | `ingest/*`, `app/*` |
| **B, Rede** | `quantumtrace/ingest/pcap.py`, `quantumtrace/ingest/probe.py`, `samples/extra/tls-lab/*`, `samples/extra/pcap/*` | `classify.py`, `kb/*`, `app/*` |
| **C, Código** | `quantumtrace/ingest/code/*`, `quantumtrace/ingest/cloud.py` | `classify.py`, `kb/*`, `app/*` |
| **D, Demo** | `app/streamlit_app.py`, `.streamlit/*`, `docs/*`, `README.md` | tudo em `quantumtrace/` |

## Ficheiros partilhados (avisa antes de mexer)

Estes três são os únicos onde toda a gente tem motivo para mexer, por isso são os únicos que dão
conflito a sério:

- **`quantumtrace/schema.py`** — o contrato `Finding`. Acrescentar um campo é seguro, mudar ou apagar
  um campo parte o trabalho dos outros três. Fala com o A primeiro.
- **`tests/ground_truth.json`** — cada um acrescenta entradas na SUA secção (`code`, `network`, `cloud`).
  É um JSON grande: acrescenta no fim da tua lista, não reorganizes o ficheiro.
- **`requirements.txt`** — acrescenta a tua linha no fim, não reordenes.

## Regras de branch

```bash
git checkout main && git pull            # SEMPRE antes de criar a branch
git checkout -b b/probe-sandbox          # a/..., b/..., c/..., d/... conforme a pessoa
# trabalha, commita várias vezes
git push -u origin b/probe-sandbox
```

1. **Integra de 2 em 2 horas, no máximo.** Uma branch que vive 6 horas é um conflito garantido.
   Mais vale 4 merges pequenos do que um grande no fim.
2. **Antes de abrir PR:** `git pull --rebase origin main` e corre `make test`. Se os testes falham,
   não abres PR.
3. **Review rápida:** 1 aprovação de qualquer colega chega. Não esperes pela pessoa perfeita.
4. **A partir do feature freeze (09:30 de domingo)** só entram correções de bugs em `main`,
   com os 4 a ver.

## A regra que não se quebra

**Os testes nunca ficam vermelhos em `main`.** O nosso argumento de venda é "100% de precisão
verificada"; se `main` estiver partida durante a demo, perdemos isso.

Cada feature nova traz sempre as duas coisas juntas:
1. um ficheiro de teste em `samples/extra/`;
2. as expectativas em `tests/ground_truth.json`.
