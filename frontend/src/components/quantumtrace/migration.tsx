import { Link } from "@tanstack/react-router";
import { motion, useReducedMotion } from "framer-motion";
import { BookOpen } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Notice, PageHead, Pager, Readout } from "@/components/Bits";
import { apiRequest, errorText, type WhatIfResult } from "@/lib/api";
import { moscaSchema, type Mosca, type Report } from "@/lib/quantumtrace-data";
import { sourceName } from "@/lib/labels";

// Every number on this page comes from the Python API (score.mosca / score.what_if): the browser only lays it out.

export function Migration({ report }: { report: Report }) {
  return (
    <div className="mx-auto max-w-6xl space-y-16">
      <PageHead title="Migration plan">
        A practical path from discovery to quantum resilience: who is late for Q-Day, and the
        actions that remove the most risk first.
      </PageHead>
      {report.summary.mosca && <Timeline base={report.summary.mosca} at={report.generated_at} />}
      <Steps report={report} />
    </div>
  );
}

const scenarioName: Record<string, string> = {
  pessimistic: "Early",
  default: "Expected",
  optimistic: "Late",
};

function Timeline({ base, at }: { base: Mosca; at: string }) {
  const reduce = useReducedMotion();
  const [data, setData] = useState<Mosca>(base);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => {
    setData(base);
    setError(null);
  }, [base]);
  const scenarios = Object.entries(base.scenarios).sort((a, b) => a[1].qday_year - b[1].qday_year);
  async function choose(year: number) {
    if (year === data.qday_year || pending) return;
    setPending(true);
    setError(null);
    try {
      setData(
        year === base.qday_year
          ? base
          : moscaSchema.parse(
              await apiRequest(`/api/mosca?qday=${year}&at=${encodeURIComponent(at)}`),
            ),
      );
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPending(false);
    }
  }
  const { now, qday_year: qday } = data;
  const horizon =
    Math.max(qday, ...data.assets.map((a) => now + a.migration_years + a.shelf_life)) + 1;
  const pos = (year: number) => `${((Math.min(year, horizon) - now) / (horizon - now)) * 100}%`;
  const span = (from: number, to: number) =>
    `${(Math.max(0, Math.min(to, horizon) - Math.min(from, horizon)) / (horizon - now)) * 100}%`;
  // Q-Day's place on the axis: near either end its label takes the end label's spot instead of overlapping it
  const qdayAt = (Math.min(qday, horizon) - now) / (horizon - now);
  const rows = all ? data.assets : data.assets.slice(0, 12);
  const bands = [
    {
      k: "late",
      n: data.status["late"] ?? 0,
      l: "too late, even if work starts today",
      cls: "bg-critical",
      tone: "text-critical",
    },
    {
      k: "start-now",
      n: data.status["start-now"] ?? 0,
      l: "must start this year",
      cls: "bg-medium",
      tone: "text-medium",
    },
    {
      k: "ok",
      n: data.status["ok"] ?? 0,
      l: "on time, with years to spare",
      cls: "bg-safe",
      tone: "text-safe",
    },
  ];
  return (
    <section aria-labelledby="qday" className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="max-w-2xl">
          <h2 id="qday" className="text-3xl">
            If Q-Day comes in <span className="text-primary">{qday}</span>,{" "}
            <span className="text-critical">
              {data.at_risk} of {data.evaluated}
            </span>{" "}
            systems are already late.
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Mosca's rule: a system is late if the years its data must stay secret plus the years
            needed to migrate it reach past Q-Day, the year a quantum computer can break today's
            public-key cryptography. Anything recorded before the migration becomes readable after
            Q-Day.
          </p>
          <Link to="/migration/sources" className="btn-link mt-2 text-sm">
            <BookOpen className="h-3.5 w-3.5" aria-hidden />
            Where these numbers come from: the source of every X, Y and Q-Day value
          </Link>
        </div>
        <ScenarioPicker
          scenarios={scenarios}
          qday={qday}
          now={now}
          pending={pending}
          onChoose={(y) => void choose(y)}
        />
      </div>
      {error && <Notice tone="critical">{error}</Notice>}
      <div
        className={`grid grid-cols-1 gap-4 sm:grid-cols-3 transition ${pending ? "opacity-50" : ""}`}
      >
        {bands.map((b, i) => (
          <div key={b.k} className="panel grid-paper p-4">
            <div className={`font-display text-4xl font-semibold tabular-nums ${b.tone}`}>
              {b.n}
              <span className="text-lg text-muted-foreground"> of {data.evaluated}</span>
            </div>
            <div className="mt-1 text-sm text-muted-foreground">{b.l}</div>
            <div className="mt-3 h-2 rounded-sm bg-muted">
              <motion.div
                key={`${qday}-${b.k}`}
                className={`h-full rounded-sm ${b.cls}`}
                initial={reduce ? false : { width: 0 }}
                animate={{ width: `${data.evaluated ? (b.n / data.evaluated) * 100 : 0}%` }}
                transition={{ duration: 0.7, delay: i * 0.1 }}
              />
            </div>
          </div>
        ))}
      </div>
      <p className="text-sm text-muted-foreground">
        {data.evaluated} quantum-vulnerable systems evaluated
        {data.cleartext_assets
          ? ` · ${data.cleartext_assets} more send data in clear text and are exposed today`
          : ""}
      </p>

      {data.assets.length > 0 && (
        <div className={`panel p-4 transition ${pending ? "opacity-50" : ""}`}>
          <h3 className="text-lg">When does each system become a problem?</h3>
          <ul className="mt-4 space-y-3" aria-label="Mosca timeline per system">
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
                  className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 sm:grid-cols-[minmax(0,15rem)_1fr_9rem]"
                  title={a.why.join("\n")}
                >
                  <span className="order-1 min-w-0 sm:order-none">
                    <span className="block truncate text-sm">{a.label}</span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {sourceName[a.source] ?? a.source} · secret {a.shelf_life} yrs · migrate{" "}
                      {a.migration_years} yrs{a.hndl ? " · recordable now" : ""}
                    </span>
                  </span>
                  <div
                    className="relative order-3 col-span-2 h-4 rounded-sm bg-muted sm:order-none sm:col-span-1"
                    role="img"
                    aria-label={`${a.label}: ${a.migration_years} years to migrate, data stays sensitive until ${secretUntil}, Q-Day ${qday}: ${verdict}`}
                  >
                    <span
                      className="absolute inset-y-0 bg-medium/60"
                      style={{ left: pos(now), width: span(now, migrated) }}
                    />
                    {migrated < qday && (
                      <span
                        className="absolute inset-y-0 bg-safe/50"
                        style={{
                          left: pos(migrated),
                          width: span(migrated, Math.min(secretUntil, qday)),
                        }}
                      />
                    )}
                    {secretUntil > qday && (
                      <span
                        className="hatch-critical absolute inset-y-0"
                        style={{
                          left: pos(Math.max(qday, migrated)),
                          width: span(Math.max(qday, migrated), secretUntil),
                        }}
                      />
                    )}
                    <span
                      className="absolute -inset-y-1 w-0.5 bg-primary"
                      style={{ left: pos(qday) }}
                    />
                  </div>
                  <span
                    className={`order-2 text-sm sm:order-none ${a.status === "late" ? "text-critical" : a.status === "start-now" ? "text-medium" : "text-safe"}`}
                  >
                    <span aria-hidden>
                      {a.status === "late" ? "✕ " : a.status === "start-now" ? "~ " : "✓ "}
                    </span>
                    {verdict}
                  </span>
                </li>
              );
            })}
          </ul>
          <div className="mt-2 grid gap-3 whitespace-nowrap text-xs text-muted-foreground sm:grid-cols-[minmax(0,15rem)_1fr_9rem]">
            <span className="hidden sm:block" />
            <div className="relative h-4">
              {qdayAt >= 0.15 && (
                <span className="absolute" style={{ left: 0 }}>
                  {now}
                </span>
              )}
              <span
                className={`absolute font-semibold text-primary ${qdayAt > 0.85 ? "-translate-x-full" : qdayAt < 0.15 ? "" : "-translate-x-1/2"}`}
                style={{ left: pos(qday) }}
              >
                Q-Day {qday}
              </span>
              {qdayAt <= 0.85 && <span className="absolute right-0">{horizon}</span>}
            </div>
            <span className="hidden sm:block" />
          </div>
          <div className="mt-4 flex flex-wrap gap-5 text-xs text-muted-foreground">
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-4 rounded-sm bg-medium/60" /> Migration time
            </span>
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-4 rounded-sm bg-safe/50" /> Must stay secret, still safe
            </span>
            <span className="flex items-center gap-2">
              <span className="hatch-critical h-2.5 w-4 rounded-sm" /> Must stay secret after Q-Day:
              exposed
            </span>
            <span>
              Hover a row for the assumptions behind it ·{" "}
              <Link to="/migration/sources" className="btn-link">
                sources
              </Link>
            </span>
          </div>
          {data.assets.length > 12 && (
            <button className="btn-link mt-3 text-sm" onClick={() => setAll(!all)}>
              {all ? "Show the 12 most urgent" : `Show all ${data.assets.length} systems`}
            </button>
          )}
        </div>
      )}
    </section>
  );
}

// Q-Day years /api/mosca accepts (quantumtrace/web.py).
const QDAY_MAX = 9999; // any four-digit year from the current one

function ScenarioPicker({
  scenarios,
  qday,
  now,
  pending,
  onChoose,
}: {
  scenarios: [string, { qday_year: number; at_risk: number }][];
  qday: number;
  now: number;
  pending: boolean;
  onChoose: (year: number) => void;
}) {
  const [text, setText] = useState(String(qday));
  const [invalid, setInvalid] = useState<string | null>(null);
  useEffect(() => {
    setText(String(qday));
    setInvalid(null);
  }, [qday]);
  const min = now;
  const custom = !scenarios.some(([, sc]) => sc.qday_year === qday);
  function submit() {
    const year = Number(text);
    if (!Number.isInteger(year) || year < min || year > QDAY_MAX) {
      setInvalid(
        Number.isInteger(year) && year > QDAY_MAX
          ? `Choose a year of four digits at most (up to ${QDAY_MAX}).`
          : `Choose a year from ${min} onwards: Q-Day cannot be in the past.`,
      );
      return;
    }
    setInvalid(null);
    onChoose(year);
  }
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <div
          role="group"
          aria-label="Q-Day scenario"
          className="inline-flex flex-wrap rounded-sm border border-border p-0.5"
        >
          {scenarios.map(([name, sc]) => (
            <button
              key={name}
              type="button"
              aria-pressed={sc.qday_year === qday}
              disabled={pending}
              onClick={() => onChoose(sc.qday_year)}
              className={`rounded-sm px-3 py-1.5 text-sm transition disabled:opacity-50 ${sc.qday_year === qday ? "bg-primary font-semibold text-primary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
            >
              {scenarioName[name] ?? name} · Q-Day {sc.qday_year} · {sc.at_risk} late
            </button>
          ))}
        </div>
        <form
          noValidate // our own range message, in the app's style, instead of the browser's bubble
          className={`inline-flex items-center gap-1.5 rounded-sm border p-0.5 pl-3 transition ${custom ? "border-primary" : "border-border"}`}
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <label htmlFor="qday-custom" className="text-sm text-muted-foreground">
            Custom year
          </label>
          <input
            id="qday-custom"
            type="number"
            inputMode="numeric"
            min={min}
            max={QDAY_MAX}
            step={1}
            value={text}
            disabled={pending}
            aria-invalid={!!invalid}
            onChange={(e) => {
              setText(e.target.value);
              setInvalid(null);
            }}
            className="field w-24 py-1 tabular-nums"
          />
          <button
            type="submit"
            disabled={pending}
            className={`rounded-sm px-3 py-1.5 text-sm transition disabled:opacity-50 ${custom ? "bg-primary font-semibold text-primary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
          >
            Show
          </button>
        </form>
      </div>
      {invalid && (
        <p role="alert" className="text-sm text-critical">
          {invalid}
        </p>
      )}
    </div>
  );
}

const ACTIONS_PER_PAGE = 10;

const PRIORITY = {
  P0: {
    word: "First",
    cls: "border-critical text-critical",
    text: "protects data that can be recorded today",
  },
  P1: {
    word: "Next",
    cls: "border-medium text-medium",
    text: "fixes quantum-vulnerable signatures and broken crypto",
  },
  P2: { word: "Later", cls: "border-border text-muted-foreground", text: "is hygiene" },
} as const;

function Steps({ report }: { report: Report }) {
  const plan = report.summary.plan;
  const [chosen, setChosen] = useState<number[]>([]);
  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [page, setPage] = useState(0);
  const latest = useRef(0);
  const top = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    setChosen([]);
    setResult(null);
    setError(null);
    setPage(0);
  }, [report]);
  const pages = Math.ceil(plan.length / ACTIONS_PER_PAGE);
  const start = page * ACTIONS_PER_PAGE;
  function goTo(next: number) {
    setPage(next);
    top.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }
  function clear() {
    latest.current++; // ignore any answer still on its way
    setChosen([]);
    setResult(null);
    setError(null);
    setPending(false);
  }
  // What-if: Python re-scores the report as if the ticked actions were done.
  async function simulate(next: number[]) {
    setChosen(next);
    setError(null);
    const request = ++latest.current;
    if (!next.length) {
      setResult(null);
      setPending(false);
      return;
    }
    setPending(true);
    try {
      const value = await apiRequest<WhatIfResult>("/api/whatif", {
        actions: next,
        at: report.generated_at,
      });
      if (request === latest.current) setResult(value);
    } catch (e) {
      if (request === latest.current) setError(errorText(e));
    } finally {
      if (request === latest.current) setPending(false);
    }
  }
  function toggle(i: number) {
    return simulate(
      chosen.includes(i) ? chosen.filter((x) => x !== i) : [...chosen, i].sort((a, b) => a - b),
    );
  }
  const allChosen = plan.length > 0 && chosen.length === plan.length;
  function toggleAll() {
    return allChosen ? clear() : simulate(plan.map((_, i) => i)); // every page, not only this one
  }
  const first = plan.filter((p) => p.priority === "P0").length;
  if (!plan.length)
    return (
      <section className="panel grid-paper p-8">
        No migration actions were recommended for this report.
      </section>
    );
  return (
    <section aria-labelledby="steps" className="grid grid-cols-1 gap-10 lg:grid-cols-[1.5fr_1fr]">
      <div>
        <h2 id="steps" ref={top} className="scroll-mt-28 text-3xl">
          {plan.length} prioritized actions, {first} of them first.
        </h2>
        <p className="mt-2 text-muted-foreground">
          Priorities and recommendations are supplied by the Python scanner. Tick actions to see how
          much they would improve the score; nothing is changed on your systems.
        </p>
        <ul
          aria-label="Migration priority explanations"
          className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-3"
        >
          {(Object.keys(PRIORITY) as (keyof typeof PRIORITY)[]).map((p) => (
            <li key={p} className="panel flex flex-col items-start gap-1.5 p-3 text-sm">
              <span className={`shrink-0 rounded-sm border px-1.5 text-xs ${PRIORITY[p].cls}`}>
                {p} · {PRIORITY[p].word}
              </span>
              <span>{PRIORITY[p].text}.</span>
            </li>
          ))}
        </ul>
        <label className="mt-6 flex w-fit cursor-pointer items-center gap-3 rounded-sm border border-border px-3 py-2 text-sm hover:bg-accent">
          <input
            type="checkbox"
            className="h-4 w-4 accent-[var(--primary)]"
            checked={allChosen}
            ref={(el) => {
              if (el) el.indeterminate = chosen.length > 0 && !allChosen;
            }}
            onChange={() => void toggleAll()}
          />
          Select all {plan.length} actions{pages > 1 ? ", on every page" : ""}
        </label>
        <ol className="mt-3 space-y-2" aria-label="Migration actions">
          {plan.slice(start, start + ACTIONS_PER_PAGE).map((p, k) => {
            const i = start + k; // index in the whole plan: the what-if works on these
            const on = chosen.includes(i);
            return (
              <li key={i} className={`panel p-3 transition ${on ? "border-primary" : ""}`}>
                <label className="grid cursor-pointer grid-cols-[1.5rem_1fr_auto] items-start gap-3">
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4 accent-[var(--primary)]"
                    aria-label={`Simulate: ${p.action}`}
                    checked={on}
                    onChange={() => void toggle(i)}
                  />
                  <span>
                    <span className="block font-semibold">{p.action}</span>
                    <span className="block text-sm text-muted-foreground">
                      {p.asset_count} {p.asset_count === 1 ? "asset" : "assets"} in{" "}
                      {sourceName[p.source] ?? p.source}
                      {p.hndl ? ", stops harvest now, decrypt later" : ""}
                    </span>
                    {p.how && <span className="mt-1 block text-sm">{p.how}</span>}
                    <span className="mt-1 block text-sm text-muted-foreground">
                      {p.standard ? `${p.standard} · ` : ""}
                      {p.from_algorithms.join(", ")} → {p.replacement}
                    </span>
                  </span>
                  <span className={`rounded-sm border px-1.5 text-xs ${PRIORITY[p.priority].cls}`}>
                    {p.priority} · {PRIORITY[p.priority].word}
                  </span>
                </label>
                <details className="ml-9 mt-2 text-sm">
                  <summary className="cursor-pointer text-muted-foreground">
                    Affected assets
                  </summary>
                  <ul className="mt-1 space-y-0.5 break-all font-mono text-xs">
                    {p.assets.map((a) => (
                      <li key={a}>{a}</li>
                    ))}
                  </ul>
                </details>
              </li>
            );
          })}
        </ol>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-muted-foreground" aria-live="polite">
            Showing {start + 1}–{Math.min(plan.length, start + ACTIONS_PER_PAGE)} of {plan.length}{" "}
            actions
          </p>
          <Pager page={page} pages={pages} onPage={goTo} />
        </div>
      </div>
      <aside className="space-y-4 lg:sticky lg:top-24 lg:self-start" aria-live="polite">
        {!result && !error && (
          <div className="panel grid-paper p-4 text-sm text-muted-foreground">
            {pending ? "Working it out…" : "Tick one or more actions to simulate them."}
          </div>
        )}
        {error && <Notice tone="critical">{error}</Notice>}
        {result && <WhatIfSummary result={result} pending={pending} />}
        {chosen.length > 0 && (
          <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            {chosen.length} {chosen.length === 1 ? "action" : "actions"} ticked, on any page.
            <button type="button" className="btn-link" onClick={clear}>
              Clear selection
            </button>
          </p>
        )}
      </aside>
    </section>
  );
}

function WhatIfSummary({ result, pending }: { result: WhatIfResult; pending: boolean }) {
  const { before: b, after: a } = result;
  const pair = (x: number | null, y: number | null) => (
    <>
      {x ?? "—"} <span className="text-muted-foreground">→</span> {y ?? "—"}
    </>
  );
  return (
    <div role="status" className={`space-y-3 transition ${pending ? "opacity-50" : ""}`}>
      <p className="text-lg">
        Applying {result.actions} {result.actions === 1 ? "action" : "actions"}: readiness score{" "}
        {b.score ?? "—"} ({b.grade}) → <b className="text-safe">{a.score ?? "—"}</b> ({a.grade})
      </p>
      <div className="grid grid-cols-2 gap-3">
        <Readout value={pair(b.score, a.score)} label="Readiness score" tone="safe" />
        <Readout
          value={pair(b.critical, a.critical)}
          label="Critical findings"
          tone={a.critical < b.critical ? "safe" : undefined}
        />
        <Readout
          value={pair(b.hndl_exposed, a.hndl_exposed)}
          label="Recordable endpoints (HNDL)"
          tone={a.hndl_exposed < b.hndl_exposed ? "safe" : undefined}
        />
        <Readout
          value={pair(b.late, a.late)}
          label="Late for Q-Day"
          tone={a.late < b.late ? "safe" : undefined}
        />
      </div>
      <p className="text-sm text-muted-foreground">
        Cleartext endpoints: {b.plaintext} → {a.plaintext}
      </p>
    </div>
  );
}
