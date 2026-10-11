import { useEffect, useState } from "react";
import { Fact, Notice, PageHead, RiskBadge } from "@/components/Bits";
import { apiRequest, errorText, type ExplainResult } from "@/lib/api";
import { classicalText, findingBadge, threatText } from "@/lib/labels";

const presets = [
  { label: "RSA-2048 signature", algorithm: "RSA", category: "signature", params: "key_bits=2048" },
  { label: "Ed25519 signature", algorithm: "Ed25519", category: "signature", params: "" },
  { label: "X25519 key exchange", algorithm: "X25519", category: "key-exchange", params: "" },
  {
    label: "X25519MLKEM768 key exchange",
    algorithm: "X25519MLKEM768",
    category: "key-exchange",
    params: "parameter_set=ML-KEM-768",
  },
  {
    label: "AES-128-GCM",
    algorithm: "AES",
    category: "encryption",
    params: "key_bits=128, mode=GCM",
  },
  {
    label: "AES-256-GCM",
    algorithm: "AES",
    category: "encryption",
    params: "key_bits=256, mode=GCM",
  },
  { label: "SHA-1", algorithm: "SHA-1", category: "hash", params: "" },
  {
    label: "ML-DSA-65",
    algorithm: "ML-DSA",
    category: "signature",
    params: "parameter_set=ML-DSA-65",
  },
];

const FIRST_EXPLAIN = { algorithm: "RSA", category: "signature", params: "key_bits=2048" };

export function ExplainPanel() {
  const [form, setForm] = useState(FIRST_EXPLAIN);
  const [data, setData] = useState<ExplainResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function explain(next: typeof form) {
    setForm(next);
    setBusy(true);
    setError(null);
    try {
      setData(
        await apiRequest<ExplainResult>(`/api/explain?${new URLSearchParams(next).toString()}`),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    apiRequest<ExplainResult>(`/api/explain?${new URLSearchParams(FIRST_EXPLAIN).toString()}`)
      .then(setData)
      .catch((e) => setError(errorText(e)));
  }, []);
  const f = data?.finding;
  return (
    <div className="mx-auto max-w-5xl space-y-10">
      <PageHead title="Explain an algorithm">
        How QuantumTrace rates any algorithm, and why. Pick an algorithm and the role it plays: it
        is classified with the same rules used on real scans.
      </PageHead>
      <section className="space-y-4">
        <div className="flex flex-wrap gap-2" aria-label="Examples">
          {presets.map((p) => (
            <button
              key={p.label}
              type="button"
              className="btn-ghost"
              disabled={busy}
              onClick={() =>
                void explain({ algorithm: p.algorithm, category: p.category, params: p.params })
              }
            >
              {p.label}
            </button>
          ))}
        </div>
        <form
          className="panel grid-paper grid grid-cols-1 items-end gap-4 p-5 md:grid-cols-[1fr_1fr_1.6fr_auto]"
          onSubmit={(e) => {
            e.preventDefault();
            void explain(form);
          }}
        >
          <label className="text-sm text-muted-foreground">
            Algorithm
            <select
              value={form.algorithm}
              onChange={(e) => setForm({ ...form, algorithm: e.target.value })}
              className="field mt-1 w-full text-foreground"
            >
              {(data?.options.algorithms ?? [form.algorithm]).map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </label>
          <label className="text-sm text-muted-foreground">
            Role
            <select
              value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}
              className="field mt-1 w-full text-foreground"
            >
              {(data?.options.categories ?? [form.category]).map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
          <label className="text-sm text-muted-foreground">
            Parameters (key=value, comma separated)
            <input
              value={form.params}
              onChange={(e) => setForm({ ...form, params: e.target.value })}
              placeholder="key_bits=2048, mode=GCM"
              className="field mt-1 w-full font-mono text-foreground"
            />
          </label>
          <button type="submit" className="btn-primary justify-center" disabled={busy}>
            {busy ? "Classifying…" : "Explain"}
          </button>
        </form>
        {error && <Notice tone="critical">{error}</Notice>}
      </section>
      {f && (
        <article className="grid grid-cols-1 gap-8 md:grid-cols-[1fr_1.2fr]">
          <div className="space-y-4">
            <h2 className="font-mono text-4xl">{f.display_name ?? f.algorithm}</h2>
            <div className="flex flex-wrap items-center gap-3">
              <RiskBadge finding={f} />
            </div>
            <p>{findingBadge(f).meaning}</p>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Fact
                label="Quantum threat"
                value={threatText[f.quantum_threat] ?? f.quantum_threat}
              />
              <Fact
                label="Problem even without quantum?"
                value={classicalText[f.classical_status] ?? f.classical_status}
              />
              <Fact label="Recordable now, readable later (HNDL)" value={f.hndl ? "Yes" : "No"} />
              <Fact label="Risk points" value={`${f.risk_points} of 100`} />
              <Fact
                label="Classical strength"
                value={f.classical_bits ? `${f.classical_bits} bits` : "—"}
              />
              <Fact label="NIST post-quantum level" value={f.nist_quantum_level ?? "—"} />
              <Fact label="OID" value={<span className="font-mono text-xs">{f.oid ?? "—"}</span>} />
              {f.cwe?.length ? <Fact label="Weaknesses" value={f.cwe.join(", ")} /> : null}
            </dl>
          </div>
          <div className="space-y-4">
            {!!f.rationale.length && (
              <div>
                <h3 className="text-lg">Why</h3>
                <ul className="mt-2 space-y-2 text-sm">
                  {f.rationale.map((r) => (
                    <li key={r} className="border-l-2 border-primary pl-3">
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {f.replacement && (
              <div className="panel p-4">
                <p className="text-sm text-muted-foreground">Replace with</p>
                <p className="font-display text-3xl font-semibold text-safe">
                  {f.replacement.algorithm}
                </p>
                {f.replacement.standard && (
                  <p className="text-sm text-muted-foreground">{f.replacement.standard}</p>
                )}
                {f.replacement.how && <p className="mt-2">{f.replacement.how}</p>}
              </div>
            )}
            {!!f.deadlines?.length && (
              <div>
                <h3 className="text-lg">
                  Deadlines{f.deadline_year ? ` · earliest binding: ${f.deadline_year}` : ""}
                </h3>
                <ul className="mt-2 space-y-2 text-sm">
                  {f.deadlines.map((d) => (
                    <li key={d} className="border-l-2 border-border pl-3">
                      {d}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </article>
      )}
    </div>
  );
}
