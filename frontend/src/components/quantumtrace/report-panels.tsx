import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowDownToLine, ArrowRight, Shield, FileText } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { apiRequest, type WhatIfResult } from "@/lib/api";
import { downloadReport, saveDownload, sourceLabels, type Report } from "@/lib/quantumtrace-data";
import { MoscaPanel, TopAssets, WhatIfSummary } from "./analysis-panels";

export function Overview({ report }: { report: Report }) {
  const s = report.summary;
  const tiers = [
    { key: "critical", label: "Critical", color: "var(--critical)" },
    { key: "medium", label: "Medium", color: "var(--medium)" },
    { key: "safe", label: "Quantum-safe", color: "var(--safe)" },
    { key: "unencrypted", label: "Unencrypted", color: "var(--foreground)" },
  ];
  let offset = 0;
  return (
    <>
      <section aria-label="Readiness metrics" className="grid lg:grid-cols-[2fr_3fr] gap-4 mb-5">
        <div className="stat-card flex flex-col justify-between gap-5">
          <h2 className="text-sm font-medium">Quantum Readiness Score</h2>
          {s.quantum_readiness_score === null ? (
            <p className="text-3xl font-medium py-4">Not assessed</p>
          ) : (
            <>
              <div className="flex flex-wrap items-baseline gap-x-3">
                <p className="text-[76px] sm:text-[88px] leading-none tracking-tight font-medium">
                  {s.quantum_readiness_score}
                </p>
                <span className="text-lg text-muted-foreground">/ 100</span>
                {s.grade && s.grade !== "—" && (
                  <span className="text-sm font-medium">Grade {s.grade}</span>
                )}
              </div>
              <div
                role="meter"
                aria-label="Quantum Readiness Score"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={s.quantum_readiness_score}
                className="h-2 rounded-full bg-secondary overflow-hidden"
              >
                <div
                  className="h-full bg-khaki rounded-full"
                  style={{ width: `${s.quantum_readiness_score}%` }}
                />
              </div>
            </>
          )}
          <p className="text-xs leading-relaxed text-muted-foreground">
            Python scanner assessment · {Object.keys(s.sources).length} discovery sources
          </p>
        </div>
        <div className="grid sm:grid-cols-2 gap-4">
          {[
            {
              label: "Cryptographic assets",
              value: s.assets,
              detail: `${s.findings} assessed findings`,
            },
            {
              label: "Critical findings",
              value: s.tiers["critical"] ?? 0,
              detail: "Quantum-vulnerable findings",
            },
            {
              label: "Systems at risk before Q-Day",
              value: s.mosca?.at_risk ?? "Not assessed",
              detail: s.mosca
                ? `Q-Day ${s.mosca.qday_year} · ${s.mosca.evaluated} systems evaluated`
                : "No timeline assessment available",
            },
            {
              label: "Classical security weaknesses",
              value: s.classical["broken"] ?? "Not assessed",
              detail: "Findings already broken today",
            },
          ].map((item) => (
            <div className="stat-card flex flex-col gap-2" key={item.label}>
              <h3 className="text-xs font-medium text-muted-foreground leading-relaxed">
                {item.label}
              </h3>
              <p className="text-[28px] font-medium leading-tight">{item.value}</p>
              <p className="text-xs text-muted-foreground leading-relaxed">{item.detail}</p>
            </div>
          ))}
        </div>
      </section>
      <div className="grid lg:grid-cols-[1.1fr_1fr] gap-5 mb-6">
        <section className="panel">
          <div className="panel-heading">
            <h2 className="text-sm font-semibold">Quantum risk distribution</h2>
            <span className="text-[10px] text-muted-foreground">
              {s.findings} assessed findings
            </span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-8 p-6">
            <div className="relative w-[174px] h-[174px]">
              <svg
                viewBox="0 0 180 180"
                className="w-full h-full -rotate-90"
                role="img"
                aria-label={tiers.map((t) => `${s.tiers[t.key] ?? 0} ${t.label}`).join(", ")}
              >
                <circle
                  cx="90"
                  cy="90"
                  r="69"
                  fill="none"
                  strokeWidth="16"
                  className="donut-track"
                />
                {tiers.map((t) => {
                  const size = s.findings ? ((s.tiers[t.key] ?? 0) / s.findings) * 100 : 0;
                  const start = offset;
                  offset += size;
                  return (
                    <circle
                      key={t.key}
                      cx="90"
                      cy="90"
                      r="69"
                      pathLength="100"
                      fill="none"
                      strokeWidth="16"
                      stroke={t.color}
                      strokeDasharray={`${size} ${100 - size}`}
                      strokeDashoffset={-start}
                    />
                  );
                })}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-[35px] font-medium">{s.findings}</span>
                <span className="text-[10px] text-muted-foreground">findings</span>
              </div>
            </div>
            <div className="space-y-4 flex-1 min-w-36 max-w-56">
              {tiers.map((t) => (
                <div key={t.key} className="flex items-center gap-2 text-xs">
                  <span className="h-2 w-2 rounded-sm" style={{ background: t.color }} />
                  <span className="text-muted-foreground">{t.label}</span>
                  <span className="ml-auto font-semibold">{s.tiers[t.key] ?? 0}</span>
                </div>
              ))}
              <p className="border-t pt-3 text-[10px] text-muted-foreground">
                Quantum-safe findings may still have classical weaknesses.
              </p>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2 className="text-sm font-semibold">Discovery coverage</h2>
            <span className="text-[10px] text-muted-foreground">Backend source scores</span>
          </div>
          <div className="px-6 py-6 space-y-6">
            {Object.entries(s.sources).map(([name, source]) => (
              <div key={name}>
                <div className="flex justify-between text-xs mb-2">
                  <span>{sourceLabels[name as keyof typeof sourceLabels] ?? name}</span>
                  <span>
                    {source.assets} assets · {source.score}/100
                  </span>
                </div>
                <div className="source-line">
                  <span className="bg-safe" style={{ width: `${source.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
      <TopAssets report={report} />
      <div className="insight-band p-5 mb-7 flex items-center gap-4">
        <Shield size={22} />
        <div className="flex-1">
          <p className="text-sm font-semibold">Visibility is the first step to resilience.</p>
          <p className="text-xs text-muted-foreground mt-1.5">
            {s.plan.length} migration actions · {s.classical["broken"] ?? 0} classically broken
            findings.
          </p>
        </div>
        <Link to="/migration" className={buttonVariants({ variant: "ghost" })}>
          View migration plan
          <ArrowRight />
        </Link>
      </div>
    </>
  );
}
const priorityClass = { P0: "risk-critical", P1: "risk-medium", P2: "risk-safe" } as const;

export function Migration({ report }: { report: Report }) {
  const [chosen, setChosen] = useState<number[]>([]);
  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);
  useEffect(() => {
    setChosen([]);
    setResult(null);
    setError(null);
  }, [report]);
  // What-if: Python re-scores the report as if the ticked actions were done.
  async function toggle(i: number) {
    const next = chosen.includes(i)
      ? chosen.filter((x) => x !== i)
      : [...chosen, i].sort((a, b) => a - b);
    setChosen(next);
    setError(null);
    const request = ++latest.current;
    if (!next.length) {
      setResult(null);
      return;
    }
    try {
      const value = await apiRequest<WhatIfResult>("/api/whatif", {
        actions: next,
        at: report.generated_at,
      });
      if (request === latest.current) setResult(value);
    } catch (e) {
      if (request === latest.current) setError(e instanceof Error ? e.message : "What-if failed");
    }
  }
  return (
    <section>
      <MoscaPanel report={report} />
      <h2 className="text-sm font-semibold mb-4">Prioritized migration actions</h2>
      <p className="text-xs text-muted-foreground mb-5">
        Priorities and recommendations are supplied by the Python scanner. P0 protects data that can
        be recorded today, P1 fixes quantum-vulnerable signatures and broken crypto, P2 is hygiene.
        Tick actions to see how much they would improve the score; nothing is changed on your
        systems.
      </p>
      {result ? (
        <WhatIfSummary result={result} />
      ) : (
        <p className="text-xs mb-5">Tick one or more actions to simulate them.</p>
      )}
      {error && (
        <p role="alert" className="text-xs mb-5 text-critical">
          {error}
        </p>
      )}
      <div className="space-y-3">
        {report.summary.plan.map((action, i) => (
          <div className="panel p-5" key={i}>
            <div className="flex flex-wrap items-center gap-4">
              <input
                type="checkbox"
                className="h-4 w-4"
                aria-label={`Simulate: ${action.action}`}
                checked={chosen.includes(i)}
                disabled={false}
                onChange={() => void toggle(i)}
              />
              <span className={`risk-badge ${priorityClass[action.priority]}`}>
                {action.priority}
              </span>
              <h3 className="text-sm font-medium flex-1">{action.action}</h3>
              <span className="text-xs text-muted-foreground">
                {action.asset_count} {action.asset_count === 1 ? "asset" : "assets"} ·{" "}
                {action.source}
              </span>
            </div>
            <p className="mt-3 text-xs text-muted-foreground">{action.how}</p>
            <p className="mt-2 text-xs">
              {action.standard} · {action.from_algorithms.join(", ")} → {action.replacement}
            </p>
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer">Affected assets</summary>
              <ul className="mt-2 space-y-1 break-all">
                {action.assets.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
            </details>
          </div>
        ))}
      </div>
      {!report.summary.plan.length && (
        <p className="panel p-8">No migration actions were recommended for this report.</p>
      )}
    </section>
  );
}
export function Reports({ report }: { report: Report }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  async function exportBackend(kind: "cbom" | "sarif") {
    setError(null);
    setPending(kind);
    try {
      const response = await fetch(
        `/api/export/${kind}?at=${encodeURIComponent(report.generated_at)}`,
      );
      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.error);
      }
      saveDownload(
        await response.text(),
        kind === "cbom" ? "cbom.cdx.json" : "results.sarif",
        "application/json",
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setPending(null);
    }
  }
  return (
    <>
      <div className="grid md:grid-cols-2 gap-5">
        {(["json", "csv", "cbom", "sarif"] as const).map((format) => (
          <div className="stat-card" key={format}>
            <FileText size={26} />
            <h2 className="font-semibold mt-6">
              {format === "cbom"
                ? "CycloneDX 1.6 CBOM"
                : format === "sarif"
                  ? "Code scanning SARIF"
                  : format === "json"
                    ? "Complete scan report"
                    : "Finding inventory CSV"}
            </h2>
            <p className="text-xs text-muted-foreground mt-3 mb-5">
              {report.summary.assets} assets
            </p>
            <Button
              variant="outline"
              disabled={pending !== null}
              onClick={() =>
                format === "json" || format === "csv"
                  ? downloadReport(report, format)
                  : void exportBackend(format)
              }
            >
              <ArrowDownToLine />
              {pending === format ? "Preparing…" : `Download ${format.toUpperCase()}`}
            </Button>
          </div>
        ))}
      </div>

      {error && (
        <p role="alert" className="mt-4 text-critical">
          {error}
        </p>
      )}
    </>
  );
}
