import { Link, useNavigate } from "@tanstack/react-router";
import { motion, useReducedMotion } from "framer-motion";
import { useState } from "react";
import { ScoreDial } from "@/components/ScoreDial";
import { RiskBadge, TierBadge } from "@/components/Bits";
import { adaptFindings, type Report } from "@/lib/quantumtrace-data";
import {
  TIER_ORDER,
  scoreTone,
  sourceName,
  tierIcon,
  tierLabel,
  tierMeaning,
  tierSwatch,
  verdictOf,
} from "@/lib/labels";

// Every number on this page comes from the Python report: the browser only lays it out and counts.
const pct = (a: number, b: number) => (b ? Math.round((a / b) * 100) : 0);
const toneText = { critical: "text-critical", medium: "text-medium", safe: "text-safe" } as const;

export function Overview({ report }: { report: Report }) {
  return (
    <div className="mx-auto max-w-6xl space-y-20">
      <Hero r={report} />
      <Findings r={report} />
      <Exposure r={report} />
      <TopSystems r={report} />
      <NextSteps r={report} />
    </div>
  );
}

function Hero({ r }: { r: Report }) {
  const s = r.summary;
  const score = s.quantum_readiness_score;
  const nav = useNavigate();
  const [peek, setPeek] = useState<string | null>(null);
  const peekScore = peek ? s.sources[peek]?.score : undefined;
  const mosca = s.mosca;
  return (
    <section
      aria-label="Readiness metrics"
      className="grid grid-cols-1 items-center gap-10 md:grid-cols-[1.05fr_1fr]"
    >
      <div>
        {score === null ? (
          <div className="panel grid-paper py-16 text-center">
            <p className="font-display text-5xl font-semibold">Not assessed</p>
            <p className="mt-2 text-sm text-muted-foreground">
              No quantum-relevant cryptography was found in these inputs, so there is no readiness
              score to show.
            </p>
          </div>
        ) : (
          <ScoreDial
            score={peekScore ?? score}
            grade={peek ? undefined : s.grade}
            caption={
              peek ? `${sourceName[peek] ?? peek} score` : "out of 100, grade A starts at 85"
            }
          />
        )}
        <div
          className="mt-2 flex flex-wrap justify-center gap-2"
          role="group"
          aria-label="Score by source: open the inventory for a source"
        >
          {Object.entries(s.sources).map(([k, v]) => (
            <button
              key={k}
              onMouseEnter={() => setPeek(k)}
              onMouseLeave={() => setPeek(null)}
              onFocus={() => setPeek(k)}
              onBlur={() => setPeek(null)}
              onClick={() => void nav({ to: "/inventory", search: { source: k } })}
              className="panel px-4 py-1.5 text-sm transition hover:border-primary hover:bg-accent"
            >
              {sourceName[k] ?? k} <b className="font-semibold">{v.score}</b>
              <span className="text-muted-foreground"> across {v.assets} assets</span>
            </button>
          ))}
        </div>
      </div>
      <div>
        {score === null ? (
          <h1 className="text-4xl leading-tight md:text-5xl">
            Your quantum readiness, at a glance.
          </h1>
        ) : (
          <>
            <h1 className="text-4xl leading-tight md:text-5xl">
              Grade {s.grade}:{" "}
              <span className={toneText[scoreTone(score)]}>{verdictOf(s.grade)}</span>.
            </h1>
            <p className="mt-4 text-lg text-muted-foreground">
              {score} out of 100{" "}
              {score < 85
                ? `puts you ${Math.round((85 - score) * 10) / 10} points short of an A`
                : "puts you in the top band"}
              . Hover a source to see its own score, click it to open those findings.
            </p>
          </>
        )}
        <p className="mt-6 text-xl">
          {mosca && mosca.evaluated
            ? `${mosca.at_risk} of ${mosca.evaluated} quantum-vulnerable systems will still be exposed when Q-Day arrives in ${mosca.qday_year}.`
            : "No quantum-vulnerable system needs a migration timeline in these inputs."}
        </p>
        <p className="mt-3 text-sm text-muted-foreground">
          Python scanner assessment · {Object.keys(s.sources).length} discovery sources · {s.assets}{" "}
          cryptographic assets
        </p>
      </div>
    </section>
  );
}

function Findings({ r }: { r: Report }) {
  const s = r.summary;
  const reduce = useReducedMotion();
  const total = s.findings;
  const nav = useNavigate();
  const count = (t: string) => s.tiers[t] ?? 0;
  return (
    <section aria-labelledby="found">
      <h2 id="found" className="text-3xl">
        {total} uses of cryptography in {s.assets} assets.{" "}
        <span className="text-critical">{count("critical")}</span> of them fall to a quantum
        computer.
      </h2>
      <div
        className="mt-6 flex h-10 gap-0.5 overflow-hidden rounded-sm bg-muted"
        role="img"
        aria-label={TIER_ORDER.map((t) => `${count(t)} ${tierLabel[t]}`).join(", ")}
      >
        {TIER_ORDER.map((t, i) => (
          <motion.button
            key={t}
            className={`${tierSwatch[t]} min-w-0 transition hover:brightness-110`}
            aria-label={`${count(t)} ${tierLabel[t]} findings: open in inventory`}
            onClick={() => void nav({ to: "/inventory", search: { tier: t } })}
            initial={reduce ? false : { flexGrow: 0 }}
            animate={{ flexGrow: count(t) }}
            style={{ flexBasis: 0 }}
            transition={{ delay: 0.9 + i * 0.12, duration: 0.7, ease: "easeOut" }}
          />
        ))}
      </div>
      <ul className="mt-4 grid grid-cols-1 gap-x-8 gap-y-2 sm:grid-cols-2">
        {TIER_ORDER.map((t) => (
          <li key={t}>
            <Link
              to="/inventory"
              search={{ tier: t }}
              className="group flex items-start gap-3 rounded-sm p-1 hover:bg-accent"
            >
              <span
                className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-sm text-xs text-background ${tierSwatch[t]}`}
                aria-hidden
              >
                {tierIcon[t]}
              </span>
              <span>
                <b>{count(t)}</b> {tierLabel[t].toLowerCase()}{" "}
                <span className="text-muted-foreground">({pct(count(t), total)}% of findings)</span>
                <span className="block text-sm text-muted-foreground">{tierMeaning[t]}</span>
              </span>
            </Link>
          </li>
        ))}
      </ul>
      <p className="mt-6 border-l-2 border-critical pl-3">
        Even before Q-Day,{" "}
        <b>
          {s.classical["broken"] ?? 0} of {total}
        </b>{" "}
        findings are broken today and {s.classical["deprecated"] ?? 0} are deprecated.{" "}
        <span className="text-muted-foreground">
          Quantum-resilient findings may still have classical weaknesses.
        </span>
      </p>
    </section>
  );
}

function Exposure({ r }: { r: Report }) {
  const m = r.summary.mosca;
  const n = r.summary.network;
  const reduce = useReducedMotion();
  const statusBars = m
    ? [
        { n: m.status["late"] ?? 0, cls: "bg-critical", l: "too late, even if work starts today" },
        {
          n: m.status["start-now"] ?? 0,
          cls: "bg-medium",
          l: "fine only if migration starts this year",
        },
        { n: m.status["ok"] ?? 0, cls: "bg-safe", l: "have time to spare" },
      ]
    : [];
  const netBars = n
    ? [
        {
          label: "already use post-quantum key exchange",
          v: n.pq_protected,
          cls: "bg-safe",
          good: true,
        },
        {
          label: "can be recorded now and read after Q-Day",
          v: n.hndl_exposed,
          cls: "hatch-critical",
          good: false,
        },
        {
          label: "send everything in cleartext, readable today",
          v: n.plaintext,
          cls: "hatch-plain",
          good: false,
        },
      ]
    : [];
  return (
    <section className="grid grid-cols-1 gap-12 md:grid-cols-2" aria-labelledby="exp">
      <div>
        <h2 id="exp" className="text-3xl">
          {m && m.evaluated ? (
            <>
              <span className="text-critical">
                {m.at_risk} of {m.evaluated}
              </span>{" "}
              systems at risk before Q-Day ({m.qday_year}).
            </>
          ) : (
            "No system needs a Q-Day migration timeline."
          )}
        </h2>
        {m && m.evaluated > 0 && (
          <div
            className="panel mt-6 p-4"
            role="img"
            aria-label={statusBars.map((b) => `${b.n} ${b.l}`).join(", ")}
          >
            <div className="relative h-24 border-b border-border">
              {statusBars.map((b, i) => (
                <motion.div
                  key={b.l}
                  className={`absolute left-0 h-6 ${b.cls}`}
                  style={{ top: i * 32 }}
                  initial={reduce ? false : { width: 0 }}
                  animate={{ width: `${pct(b.n, m.evaluated) * 0.6}%` }}
                  transition={{ duration: 0.8, delay: 0.4 + i * 0.15 }}
                >
                  <span className="absolute left-full ml-2 whitespace-nowrap text-sm leading-6">
                    <b>{b.n}</b> {b.l}
                  </span>
                </motion.div>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Bar length is the share of {m.evaluated} quantum-vulnerable systems evaluated
              {m.cleartext_assets
                ? ` · ${m.cleartext_assets} more send data in clear text and are exposed today`
                : ""}
            </p>
          </div>
        )}
        <Link to="/migration" className="btn-link mt-4 text-sm">
          See what changes if Q-Day comes earlier or later
        </Link>
      </div>
      <div>
        {n && n.endpoints > 0 ? (
          <>
            <h2 className="text-3xl">
              <span className="text-safe">
                {n.pq_protected} of {n.endpoints}
              </span>{" "}
              network endpoints already use post-quantum key exchange.
            </h2>
            <ul className="mt-6 space-y-4">
              {netBars.map((b) => (
                <li key={b.label}>
                  <p>
                    <b>{b.v}</b> of {n.endpoints} endpoints {b.label}{" "}
                    <span className="sr-only">{b.good ? "(good)" : "(bad)"}</span>
                  </p>
                  <div className="mt-1 h-3 rounded-sm bg-muted">
                    <motion.div
                      className={`h-full rounded-sm ${b.cls}`}
                      initial={reduce ? false : { width: 0 }}
                      whileInView={{ width: `${pct(b.v, n.endpoints)}%` }}
                      viewport={{ once: true }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <>
            <h2 className="text-3xl">No network traffic in these inputs.</h2>
            <p className="mt-4 text-muted-foreground">
              Add a PCAP/PCAPNG capture to a new scan, or check a running server with the live
              probe, to see whether connections already use post-quantum key exchange.
            </p>
            <Link to="/probe" className="btn-link mt-4 text-sm">
              Open the live probe
            </Link>
          </>
        )}
      </div>
    </section>
  );
}

function TopSystems({ r }: { r: Report }) {
  const top = (r.summary.top_assets ?? []).slice(0, 8);
  return (
    <section aria-labelledby="top">
      <h2 id="top" className="text-3xl">
        Highest-risk systems
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">Worst finding per system</p>
      {top.length === 0 ? (
        <p className="mt-3 text-muted-foreground">
          This report doesn't list its highest-risk systems.
        </p>
      ) : (
        <ol className="mt-6 divide-y divide-border">
          {top.map((a, i) => (
            <li
              key={a.key ?? `${a.source}:${a.label}`}
              className="grid grid-cols-[2rem_1fr] items-center gap-x-4 gap-y-2 py-3 sm:grid-cols-[2rem_1fr_auto]"
            >
              <span className="font-display text-xl text-muted-foreground">{i + 1}</span>
              <span className="min-w-0">
                <span className="block break-all font-mono text-sm">{a.label}</span>
                <span className="text-sm text-muted-foreground">
                  {sourceName[a.source] ?? a.source}
                  {a.worst_tier === "unencrypted" || a.plaintext
                    ? ", readable today"
                    : a.hndl
                      ? ", recordable now, readable later"
                      : ""}
                </span>
              </span>
              <span className="col-start-2 flex items-center gap-3 sm:col-start-auto">
                <TierBadge tier={a.worst_tier} />
                <span className="w-24" title={`${a.risk} of 100 risk points`}>
                  <span className="block text-right text-sm tabular-nums">
                    {a.risk}
                    <span className="text-muted-foreground"> / 100</span>
                  </span>
                  <span className="block h-1 rounded-full bg-muted">
                    <span
                      className="block h-full rounded-full bg-critical"
                      style={{ width: `${Math.min(100, a.risk)}%` }}
                    />
                  </span>
                </span>
              </span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function NextSteps({ r }: { r: Report }) {
  const s = r.summary;
  const rows = adaptFindings(r)
    .sort((a, b) => b.finding.risk_points - a.finding.risk_points)
    .slice(0, 5);
  const first = s.plan.filter((p) => p.priority === "P0").length;
  return (
    <section className="grid grid-cols-1 gap-12 md:grid-cols-[1fr_1.4fr]">
      <div>
        <h2 className="text-3xl">
          {s.plan.length} migration actions, {first} of them first.
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Visibility is the first step to resilience · {s.classical["broken"] ?? 0} classically
          broken findings.
        </p>
        <ol className="mt-4 space-y-2">
          {s.plan.slice(0, 3).map((p, i) => (
            <li key={i} className="flex gap-3">
              <span className="font-display text-xl text-muted-foreground">{i + 1}</span>
              <span>
                {p.action}
                <span className="block text-sm text-muted-foreground">
                  {p.asset_count} {p.asset_count === 1 ? "asset" : "assets"}
                  {p.standard ? `, ${p.standard}` : ""}
                </span>
              </span>
            </li>
          ))}
        </ol>
        <Link to="/migration" className="btn-primary mt-6">
          View migration plan
        </Link>
      </div>
      <div>
        <h2 className="text-3xl">Riskiest findings</h2>
        <div className="overflow-x-auto">
          <table className="mt-4 w-full min-w-[30rem] text-left text-sm">
            <thead className="text-muted-foreground">
              <tr>
                <th className="py-2 font-normal">Asset</th>
                <th className="font-normal">Algorithm</th>
                <th className="font-normal">Source</th>
                <th className="font-normal">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((a) => (
                <tr key={a.id}>
                  <td className="max-w-48 truncate py-2 pr-3" title={a.location}>
                    {a.name}
                  </td>
                  <td className="pr-3">
                    {a.algorithm}{" "}
                    <span className="text-muted-foreground">
                      {a.keySize !== "—" ? a.keySize : ""}
                    </span>
                  </td>
                  <td className="pr-3">{a.source}</td>
                  <td>
                    <RiskBadge finding={a.finding} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Link to="/inventory" className="btn-link mt-4 text-sm">
          See all {r.findings.length} findings in the inventory
        </Link>
      </div>
    </section>
  );
}
