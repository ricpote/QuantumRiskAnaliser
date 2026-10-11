import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowDownToLine, CircleCheck, CircleX, Radar } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  apiRequest,
  type AccuracyResult,
  type ExplainResult,
  type ProbeJob,
  type ProbeReport,
  type WhatIfResult,
} from "@/lib/api";
import {
  moscaSchema,
  saveDownload,
  sourceLabels,
  type Finding,
  type Mosca,
  type Report,
  type Tier,
} from "@/lib/quantumtrace-data";
import { classicalText, threatText, tierClass, tierLabel, tierMeaning } from "@/lib/labels";
import { useReport } from "@/lib/report-context";

// Every number on this page comes from the Python API: the browser only lays it out.

export function TierBadge({ tier }: { tier: Tier }) {
  return <span className={`risk-badge ${tierClass[tier]}`}>{tierLabel[tier]}</span>;
}

function errorText(e: unknown) {
  return e instanceof Error ? e.message : "Request failed";
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground mb-1">{label}</dt>
      <dd className="text-sm break-words">{value}</dd>
    </div>
  );
}

// ------------------------------------------------------------------ overview

export function ExposureStrip({ report }: { report: Report }) {
  const s = report.summary;
  const net = s.network;
  const items = [
    ...(net && net.endpoints
      ? [
          {
            value: `${net.pq_protected}/${net.endpoints}`,
            label: "network endpoints already use post-quantum key exchange",
            tone: "text-safe",
          },
          {
            value: net.hndl_exposed,
            label: "endpoints whose traffic can be recorded today and decrypted later",
            tone: "text-critical",
          },
          {
            value: net.plaintext,
            label: "endpoints with no encryption at all",
            tone: "text-critical",
          },
        ]
      : []),
    {
      value: s.classical["broken"] ?? 0,
      label: "findings already broken today, quantum or not",
      tone: "text-medium",
    },
  ];
  return (
    <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
      {items.map((i) => (
        <div className="stat-card" key={i.label}>
          <p className={`text-2xl font-medium ${i.tone}`}>{i.value}</p>
          <p className="text-xs text-muted-foreground mt-2">{i.label}</p>
        </div>
      ))}
    </div>
  );
}

export function TopAssets({ report }: { report: Report }) {
  const rows = (report.summary.top_assets ?? []).slice(0, 8);
  if (!rows.length) return null;
  return (
    <section className="panel overflow-hidden mb-6">
      <div className="panel-heading pb-4">
        <h2 className="text-sm font-semibold">Highest-risk systems</h2>
        <span className="text-[10px] text-muted-foreground">Worst finding per system</span>
      </div>
      <div className="overflow-x-auto">
        <table className="asset-table">
          <thead>
            <tr>
              <th>System</th>
              <th>Source</th>
              <th>Worst risk</th>
              <th>Risk points</th>
              <th>Recordable now, readable later</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={`${a.source}:${a.label}`} style={{ cursor: "default" }}>
                <td className="font-mono text-[11px]">{a.label}</td>
                <td>{sourceLabels[a.source as keyof typeof sourceLabels] ?? a.source}</td>
                <td>
                  <TierBadge tier={a.worst_tier} />
                </td>
                <td>{a.risk}</td>
                <td>{a.worst_tier === "unencrypted" ? "Readable today" : a.hndl ? "Yes" : "No"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ------------------------------------------------------------------ Mosca timeline

const scenarioLabel: Record<string, string> = {
  pessimistic: "Pessimistic",
  default: "Expected",
  optimistic: "Optimistic",
};

export function MoscaPanel({ report }: { report: Report }) {
  const { offlineDemo } = useReport();
  const [data, setData] = useState<Mosca | undefined>(report.summary.mosca);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => {
    setData(report.summary.mosca);
    setError(null);
  }, [report]);
  if (!data) return null;
  const mosca = data;
  async function choose(year: number) {
    if (year === mosca.qday_year || pending) return;
    setPending(true);
    setError(null);
    try {
      const at = encodeURIComponent(report.generated_at);
      setData(moscaSchema.parse(await apiRequest(`/api/mosca?qday=${year}&at=${at}`)));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending(false);
    }
  }
  const { now, qday_year: qday } = mosca;
  const horizon =
    Math.max(qday, ...mosca.assets.map((a) => now + a.migration_years + a.shelf_life)) + 1;
  const at = (year: number) => `${((Math.min(year, horizon) - now) / (horizon - now)) * 100}%`;
  const width = (from: number, to: number) =>
    `${(Math.max(0, Math.min(to, horizon) - Math.min(from, horizon)) / (horizon - now)) * 100}%`;
  const rows = all ? mosca.assets : mosca.assets.slice(0, 12);
  const scenarios = Object.entries(mosca.scenarios).sort((a, b) => a[1].qday_year - b[1].qday_year);
  const late = mosca.status["late"] ?? 0;
  return (
    <section className="panel p-6 mb-7">
      <div className="flex flex-wrap gap-4 justify-between items-start">
        <div className="max-w-2xl">
          <h2 className="text-sm font-semibold">When does each system become a problem?</h2>
          <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
            Mosca's rule: a system is late if the years its data must stay secret plus the years
            needed to migrate it reach past Q-Day, the year a quantum computer can break today's
            public-key cryptography. Anything recorded before the migration becomes readable after
            Q-Day.
          </p>
        </div>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Q-Day scenario">
          {scenarios.map(([name, sc]) => (
            <Button
              key={name}
              size="sm"
              variant={sc.qday_year === qday ? "default" : "outline"}
              disabled={offlineDemo || pending}
              aria-pressed={sc.qday_year === qday}
              onClick={() => void choose(sc.qday_year)}
            >
              {scenarioLabel[name] ?? name} · Q-Day {sc.qday_year} · {sc.at_risk} late
            </Button>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap gap-3 mt-5 text-xs">
        <span className="risk-badge risk-critical">{late} already late</span>
        <span className="risk-badge risk-medium">
          {mosca.status["start-now"] ?? 0} must start this year
        </span>
        <span className="risk-badge risk-safe">{mosca.status["ok"] ?? 0} on time</span>
        <span className="text-muted-foreground">
          {mosca.evaluated} quantum-vulnerable systems evaluated
          {mosca.cleartext_assets
            ? ` · ${mosca.cleartext_assets} more send data in clear text and are exposed today`
            : ""}
        </span>
      </div>
      {offlineDemo && (
        <p className="text-xs mt-3">
          Switching scenarios needs the scanner API (not the bundled demo).
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs mt-3 text-critical">
          {error}
        </p>
      )}
      <ul className="mt-6 space-y-2.5" aria-label="Mosca timeline per system">
        {rows.map((a) => {
          const migrated = now + a.migration_years;
          const secretUntil = migrated + a.shelf_life;
          const verdict =
            a.status === "late"
              ? `${a.years_late} ${a.years_late === 1 ? "year" : "years"} late`
              : a.status === "start-now"
                ? "Start this year"
                : `On time (start by ${a.start_by})`;
          return (
            <li
              key={`${a.source}:${a.key}`}
              className="grid grid-cols-[minmax(0,1fr)_auto] sm:grid-cols-[minmax(0,13rem)_1fr_8.5rem] gap-x-3 gap-y-1 items-center"
              title={a.why.join("\n")}
            >
              <span className="text-xs truncate order-1 sm:order-none">{a.label}</span>
              <div
                className="relative h-4 rounded-sm bg-muted col-span-2 sm:col-span-1 order-3 sm:order-none"
                role="img"
                aria-label={`${a.label}: ${a.migration_years} years to migrate, data stays sensitive until ${secretUntil}, Q-Day ${qday}: ${verdict}`}
              >
                <span
                  className="absolute inset-y-0 bg-medium/60"
                  style={{ left: at(now), width: width(now, migrated) }}
                />
                {migrated < qday && (
                  <span
                    className="absolute inset-y-0 bg-safe/50"
                    style={{
                      left: at(migrated),
                      width: width(migrated, Math.min(secretUntil, qday)),
                    }}
                  />
                )}
                {secretUntil > qday && (
                  <span
                    className="absolute inset-y-0 bg-critical"
                    style={{
                      left: at(Math.max(qday, migrated)),
                      width: width(Math.max(qday, migrated), secretUntil),
                    }}
                  />
                )}
                <span
                  className="absolute -inset-y-1 w-0.5 bg-foreground"
                  style={{ left: at(qday) }}
                />
              </div>
              <span
                className={`text-[11px] order-2 sm:order-none ${a.status === "late" ? "text-critical" : a.status === "start-now" ? "text-medium" : "text-safe"}`}
              >
                {verdict}
              </span>
            </li>
          );
        })}
      </ul>
      <div className="grid sm:grid-cols-[minmax(0,13rem)_1fr_8.5rem] gap-3 mt-2 text-[10px] text-muted-foreground whitespace-nowrap">
        <span className="hidden sm:block" />
        <div className="relative h-4">
          <span className="absolute" style={{ left: 0 }}>
            {now}
          </span>
          <span
            className="absolute -translate-x-1/2 font-semibold text-foreground"
            style={{ left: at(qday) }}
          >
            Q-Day {qday}
          </span>
          <span className="absolute right-0">{horizon}</span>
        </div>
        <span className="hidden sm:block" />
      </div>
      <div className="flex flex-wrap gap-5 mt-4 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-2">
          <span className="h-2.5 w-4 rounded-sm bg-medium/60" /> Migration time
        </span>
        <span className="flex items-center gap-2">
          <span className="h-2.5 w-4 rounded-sm bg-safe/50" /> Must stay secret, still safe
        </span>
        <span className="flex items-center gap-2">
          <span className="h-2.5 w-4 rounded-sm bg-critical" /> Must stay secret after Q-Day:
          exposed
        </span>
        <span>Hover a row for the assumptions behind it.</span>
      </div>
      {mosca.assets.length > 12 && (
        <Button variant="ghost" size="sm" className="mt-3" onClick={() => setAll(!all)}>
          {all ? "Show the 12 most urgent" : `Show all ${mosca.assets.length} systems`}
        </Button>
      )}
    </section>
  );
}

// ------------------------------------------------------------------ what-if

function Change({
  label,
  from,
  to,
  better,
}: {
  label: string;
  from: ReactNode;
  to: ReactNode;
  better: boolean;
}) {
  return (
    <li>
      <span className="text-muted-foreground">{label}: </span>
      {from} → <span className={better ? "text-safe font-semibold" : "font-semibold"}>{to}</span>
    </li>
  );
}

export function WhatIfSummary({ result }: { result: WhatIfResult }) {
  const { before: b, after: a } = result;
  return (
    <div className="insight-band p-5 mb-5" role="status">
      <p className="text-sm font-semibold">
        Applying {result.actions} {result.actions === 1 ? "action" : "actions"}: readiness score{" "}
        {b.score ?? "—"} ({b.grade}) → {a.score ?? "—"} ({a.grade})
      </p>
      <ul className="mt-3 grid sm:grid-cols-2 xl:grid-cols-4 gap-2 text-xs">
        <Change
          label="Critical findings"
          from={b.critical}
          to={a.critical}
          better={a.critical < b.critical}
        />
        <Change
          label="Recordable endpoints (HNDL)"
          from={b.hndl_exposed}
          to={a.hndl_exposed}
          better={a.hndl_exposed < b.hndl_exposed}
        />
        <Change
          label="Cleartext endpoints"
          from={b.plaintext}
          to={a.plaintext}
          better={a.plaintext < b.plaintext}
        />
        <Change label="Late for Q-Day" from={b.late} to={a.late} better={a.late < b.late} />
      </ul>
    </div>
  );
}

// ------------------------------------------------------------------ accuracy

const percent = (x: number) => `${Math.round(x * 1000) / 10}%`;

export function AccuracyPanel() {
  const [data, setData] = useState<AccuracyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<AccuracyResult>("/api/accuracy", undefined, controller.signal)
      .then(setData)
      .catch((e) => {
        if (!controller.signal.aborted) setError(errorText(e));
      });
    return () => controller.abort();
  }, []);
  if (error)
    return (
      <div role="alert" className="panel p-5 text-critical">
        {error}
        <p className="text-xs mt-2 text-muted-foreground">
          The accuracy check runs the scanner on the bundled official samples, so it needs the
          Python API.
        </p>
      </div>
    );
  if (!data)
    return (
      <p role="status" className="panel p-5">
        Scanning the official samples and comparing every result with the answer key…
      </p>
    );
  const off = data.code_by_origin.official;
  const own = data.code_by_origin.own_fixtures;
  const cards = [
    {
      label: "Code findings · official repositories",
      value: `${off.correctly_classified}/${off.expected}`,
      detail: `${off.traps_checked} false-positive traps checked`,
    },
    {
      label: "Network sessions · official capture",
      value: `${data.network.sessions_correct}/${data.network.expected_sessions}`,
      detail: "Every TLS/SSH session classified",
    },
    {
      label: "Cloud resources · official exports",
      value: `${data.cloud.correct}/${data.cloud.expected}`,
      detail: `${data.cloud.traps_checked} traps checked`,
    },
    {
      label: "Our own fixtures · configs, JWT",
      value: `${own.correctly_classified}/${own.expected}`,
      detail: `${own.traps_checked} traps checked · scored separately`,
    },
    {
      label: "Precision · all code",
      value: percent(data.code.precision),
      detail: `${data.code.false_positives} false positives`,
    },
    {
      label: "Recall · all code",
      value: percent(data.code.recall),
      detail: `${data.code.detected}/${data.code.expected} expected findings found`,
    },
  ];
  return (
    <>
      <div className="insight-band p-5 mb-6 flex items-center gap-4">
        {data.passed ? (
          <CircleCheck size={24} className="text-safe" />
        ) : (
          <CircleX size={24} className="text-critical" />
        )}
        <div>
          <p className="text-sm font-semibold">
            {data.passed
              ? "Every expectation passes, including the false-positive traps."
              : `${data.failures.length} expectations fail.`}
          </p>
          <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">
            Each result is compared with tests/ground_truth.json: the expected classification of
            every cryptographic use in the official challenge samples, including deliberate traps
            (Ed25519 is Shor-vulnerable, sha512.Sum384 is SHA-384, an HMAC is not a signature). The
            same check runs in CI on every change.
          </p>
        </div>
      </div>
      <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {cards.map((c) => (
          <div className="stat-card" key={c.label}>
            <p className="text-xs text-muted-foreground">{c.label}</p>
            <p className="text-[34px] font-medium mt-3">{c.value}</p>
            <p className="text-[10px] text-muted-foreground mt-1">{c.detail}</p>
          </div>
        ))}
      </div>
      {!!data.failures.length && (
        <ul role="alert" className="panel p-5 mt-6 text-xs text-critical space-y-1 break-all">
          {data.failures.slice(0, 30).map((f) => (
            <li key={f}>{f}</li>
          ))}
        </ul>
      )}
    </>
  );
}

// ------------------------------------------------------------------ explain

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
      const query = new URLSearchParams(next).toString();
      setData(await apiRequest<ExplainResult>(`/api/explain?${query}`));
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
    <>
      <section className="panel p-6 mb-6">
        <p className="text-xs text-muted-foreground mb-4">
          Pick an algorithm and the role it plays. QuantumTrace classifies it with the same rules it
          uses on real scans.
        </p>
        <div className="flex flex-wrap gap-2 mb-5">
          {presets.map((p) => (
            <Button
              key={p.label}
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() =>
                void explain({ algorithm: p.algorithm, category: p.category, params: p.params })
              }
            >
              {p.label}
            </Button>
          ))}
        </div>
        <form
          className="grid md:grid-cols-[1fr_1fr_2fr_auto] gap-3 items-end"
          onSubmit={(e) => {
            e.preventDefault();
            void explain(form);
          }}
        >
          <label className="text-xs space-y-1.5">
            <span className="block text-muted-foreground">Algorithm</span>
            <select
              value={form.algorithm}
              onChange={(e) => setForm({ ...form, algorithm: e.target.value })}
              className="border bg-background rounded-md text-xs px-3 h-9 w-full"
            >
              {(data?.options.algorithms ?? [form.algorithm]).map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </label>
          <label className="text-xs space-y-1.5">
            <span className="block text-muted-foreground">Role</span>
            <select
              value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}
              className="border bg-background rounded-md text-xs px-3 h-9 w-full"
            >
              {(data?.options.categories ?? [form.category]).map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
          <label className="text-xs space-y-1.5">
            <span className="block text-muted-foreground">
              Parameters (key=value, comma separated)
            </span>
            <input
              value={form.params}
              onChange={(e) => setForm({ ...form, params: e.target.value })}
              placeholder="key_bits=2048, mode=GCM"
              className="h-9 w-full border rounded-md bg-background px-3 text-xs font-mono"
            />
          </label>
          <Button type="submit" disabled={busy}>
            Explain
          </Button>
        </form>
        {error && (
          <p role="alert" className="text-xs mt-3 text-critical">
            {error}
          </p>
        )}
      </section>
      {f && (
        <section className="panel p-6 space-y-6">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-xl font-semibold font-mono">{f.display_name ?? f.algorithm}</h2>
              <TierBadge tier={f.risk_tier} />
            </div>
            <p className="text-sm mt-2">{tierMeaning[f.risk_tier]}</p>
          </div>
          <dl className="grid sm:grid-cols-3 gap-5">
            <Fact label="Quantum threat" value={threatText[f.quantum_threat] ?? f.quantum_threat} />
            <Fact
              label="Problem even without quantum?"
              value={classicalText[f.classical_status] ?? f.classical_status}
            />
            <Fact label="Recordable now, readable later (HNDL)" value={f.hndl ? "Yes" : "No"} />
            <Fact
              label="Classical strength"
              value={f.classical_bits ? `${f.classical_bits} bits` : "—"}
            />
            <Fact label="NIST post-quantum level" value={f.nist_quantum_level ?? "—"} />
            <Fact label="OID" value={<span className="font-mono text-xs">{f.oid ?? "—"}</span>} />
          </dl>
          <div>
            <h3 className="text-sm font-semibold mb-2">Why</h3>
            <ul className="list-disc pl-5 space-y-1 text-xs">
              {f.rationale.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
          {f.replacement && (
            <div className="bg-secondary p-4 rounded-md">
              <h3 className="text-sm font-semibold">Replace with</h3>
              <p className="text-sm mt-2">
                {f.replacement.algorithm}
                {f.replacement.standard ? ` (${f.replacement.standard})` : ""}
              </p>
              {f.replacement.how && (
                <p className="text-xs mt-1 text-muted-foreground">{f.replacement.how}</p>
              )}
            </div>
          )}
          {!!f.deadlines?.length && (
            <div>
              <h3 className="text-sm font-semibold mb-2">
                Deadlines{f.deadline_year ? ` · earliest binding: ${f.deadline_year}` : ""}
              </h3>
              <ul className="list-disc pl-5 space-y-1 text-xs text-muted-foreground">
                {f.deadlines.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
            </div>
          )}
          {!!f.cwe?.length && (
            <p className="text-xs text-muted-foreground">Weaknesses: {f.cwe.join(", ")}</p>
          )}
        </section>
      )}
    </>
  );
}

// ------------------------------------------------------------------ live probe

const LAB = ["8443", "8444", "8445", "8446", "8447", "2525", "5433"].map((p) => `127.0.0.1:${p}`);
const OLD_VERSIONS = new Set(["SSL 3.0", "TLS 1.0", "TLS 1.1"]);

async function followProbe(update: (job: ProbeJob) => void, alive: { current: boolean }) {
  while (alive.current) {
    const job = await apiRequest<ProbeJob>("/api/probe");
    if (!alive.current) return;
    update(job);
    if (job.state !== "running") return;
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

function Pills({ title, items }: { title: string; items: { text: string; className: string }[] }) {
  return (
    <div className="mt-4">
      <p className="text-xs text-muted-foreground mb-2">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((i) => (
          <span key={i.text} className={`risk-badge ${i.className}`}>
            {i.text}
          </span>
        ))}
      </div>
    </div>
  );
}

function ProbeCard({ report: r, findings }: { report: ProbeReport; findings: Finding[] }) {
  const tone =
    r.verdict.color === "green"
      ? "var(--safe)"
      : r.verdict.color === "red"
        ? "var(--critical)"
        : "var(--muted-foreground)";
  const m = r.modern;
  return (
    <section className="panel p-5 mb-4" style={{ borderLeft: `6px solid ${tone}` }}>
      <p className="text-[10px] uppercase text-muted-foreground">
        {r.target}
        {r.starttls ? ` · STARTTLS ${r.starttls}` : ""} · {r.connections ?? 0} handshakes ·{" "}
        {r.duration_s ?? 0} s
      </p>
      <p className="text-base font-semibold mt-1">{r.verdict.text}</p>
      <dl className="grid sm:grid-cols-3 gap-4 mt-4">
        <Fact label="Key exchange a modern browser gets" value={m?.group_name ?? m?.alert ?? "—"} />
        <Fact
          label="Negotiated"
          value={[m?.version, m?.cipher].filter(Boolean).join(" · ") || "—"}
        />
        <Fact label="Server signature (CertificateVerify)" value={m?.cert_verify_name ?? "—"} />
      </dl>
      {!!Object.keys(r.groups).length && (
        <Pills
          title="Key-exchange groups (green = post-quantum)"
          items={Object.entries(r.groups).map(([name, g]) => ({
            text: `${g.supported ? "✓" : "✗"} ${name}`,
            className: g.supported
              ? g.pq
                ? "risk-safe"
                : "risk-critical"
              : "bg-muted text-muted-foreground",
          }))}
        />
      )}
      {!!Object.keys(r.versions).length && (
        <Pills
          title="Protocol versions"
          items={Object.entries(r.versions).map(([v, ok]) => ({
            text: `${ok ? "✓" : "✗"} ${v}`,
            // only TLS 1.3 can negotiate post-quantum key exchange; TLS 1.2 is neutral, older is deprecated
            className: !ok
              ? "bg-muted text-muted-foreground"
              : OLD_VERSIONS.has(v)
                ? "risk-medium"
                : v === "TLS 1.3"
                  ? "risk-safe"
                  : "bg-secondary text-foreground",
          }))}
        />
      )}
      {!!r.errors?.length && (
        <p className="text-xs mt-3 text-muted-foreground">{r.errors.join("; ")}</p>
      )}
      <details className="mt-4 text-xs">
        <summary className="cursor-pointer">Details: ciphers, certificate chain, findings</summary>
        <div className="mt-3 space-y-3">
          {!!r.tls13_ciphers?.length && <p>TLS 1.3: {r.tls13_ciphers.join(", ")}</p>}
          {!!r.tls12_ciphers?.length && (
            <p>
              TLS 1.2 (server preference order): {r.tls12_ciphers.map((c) => c.name).join(", ")}
            </p>
          )}
          {!!r.certs?.length && (
            <div className="overflow-x-auto">
              <table className="asset-table">
                <thead>
                  <tr>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th>Key</th>
                    <th>Signature hash</th>
                    <th>Expires</th>
                  </tr>
                </thead>
                <tbody>
                  {r.certs.map((c, i) => (
                    <tr key={i} style={{ cursor: "default" }}>
                      <td>{c.subject}</td>
                      <td>{c.issuer}</td>
                      <td>{[c.algorithm, c.key_bits ?? c.curve].filter(Boolean).join("-")}</td>
                      <td>{c.sig_hash}</td>
                      <td>{(c.not_after ?? "").slice(0, 10)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={f.id} className="flex flex-wrap gap-2 items-center">
                <TierBadge tier={f.risk_tier} />
                <span className="font-mono">{f.display_name ?? f.algorithm}</span>
                <span className="text-muted-foreground">{f.evidence}</span>
              </li>
            ))}
          </ul>
        </div>
      </details>
    </section>
  );
}

export function ProbePanel() {
  const [targets, setTargets] = useState("127.0.0.1:8443, 127.0.0.1:8446, 127.0.0.1:8445");
  const [deep, setDeep] = useState(false);
  const [job, setJob] = useState<ProbeJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    followProbe(setJob, alive).catch(() => {}); // show the last probe result, if any
    return () => {
      alive.current = false;
    };
  }, []);
  async function start() {
    setError(null);
    try {
      const list = targets.split(/[\s,]+/).filter(Boolean);
      await apiRequest("/api/probe", { targets: list, deep });
      setJob({ state: "running", error: null, result: null });
      await followProbe(setJob, alive);
    } catch (e) {
      setError(errorText(e));
    }
  }
  const running = job?.state === "running";
  const result = job?.result;
  return (
    <>
      <section className="panel p-6 mb-6">
        <p className="text-xs text-muted-foreground leading-relaxed max-w-3xl">
          Connects to each endpoint the way a browser would, once per key-exchange group, version
          and cipher, and reports whether a modern client gets post-quantum protection. STARTTLS is
          used automatically on mail, FTP and Postgres ports. The Docker image runs a small lab:
          8443 post-quantum, 8444 classical, 8445 legacy, 8446 post-quantum with a classical
          fallback, 8447 post-quantum only, 2525 SMTP, 5433 Postgres. Public sites work too when
          online.
        </p>
        <form
          className="flex flex-wrap gap-3 items-center mt-5"
          onSubmit={(e) => {
            e.preventDefault();
            void start();
          }}
        >
          <input
            aria-label="Targets"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="example.com, 127.0.0.1:8443"
            className="h-9 flex-1 min-w-64 border rounded-md bg-background px-3 text-xs font-mono"
          />
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
            Also test signature schemes (slower)
          </label>
          <Button
            type="button"
            variant="outline"
            disabled={running}
            onClick={() => setTargets(LAB.join(", "))}
          >
            Whole lab
          </Button>
          <Button type="submit" disabled={running}>
            <Radar />
            {running ? "Probing…" : "Probe"}
          </Button>
        </form>
        {error && (
          <p role="alert" className="text-xs mt-3 text-critical">
            {error}
          </p>
        )}
      </section>
      {running && (
        <p role="status" className="panel p-5 mb-5">
          Probing… a few seconds per endpoint.
        </p>
      )}
      {job?.state === "error" && (
        <p role="alert" className="panel p-5 mb-5 text-critical">
          {job.error}
        </p>
      )}
      {result && (
        <>
          <div className="flex flex-wrap gap-3 items-center justify-between mb-4">
            <p className="text-xs text-muted-foreground">
              {result.reports.length} endpoint(s) ·{" "}
              {new Date(result.generated_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                saveDownload(
                  JSON.stringify(result.cbom, null, 2),
                  "probe_cbom.cdx.json",
                  "application/json",
                )
              }
            >
              <ArrowDownToLine />
              Probe CBOM{result.cbom_valid ? " (valid CycloneDX 1.6)" : ""}
            </Button>
          </div>
          {result.reports.map((r) => (
            <ProbeCard
              key={r.target}
              report={r}
              findings={result.findings.filter((f) => f.location["probe"] === r.target)}
            />
          ))}
        </>
      )}
    </>
  );
}
