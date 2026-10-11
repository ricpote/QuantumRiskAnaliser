import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowDownToLine, ArrowRight, Shield, FileText } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { useReport } from "@/lib/report-context";
import { downloadReport, saveDownload, sourceLabels, type Report } from "@/lib/quantumtrace-data";

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
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        {[
          {
            label: "Cryptographic assets",
            value: s.assets,
            detail: `${s.findings} assessed findings`,
          },
          {
            label: "Critical findings",
            value: s.tiers["critical"] ?? 0,
            detail: "Backend quantum risk classification",
          },
          {
            label: "Readiness score",
            value: s.quantum_readiness_score ?? "—",
            detail: `Out of 100 · grade ${s.grade}`,
          },
          {
            label: "Discovery sources",
            value: Object.keys(s.sources).length,
            detail: "Sources represented in this report",
          },
        ].map((item) => (
          <div className="stat-card" key={item.label}>
            <p className="text-xs text-muted-foreground">{item.label}</p>
            <p className="text-[34px] font-medium mt-3">{item.value}</p>
            <p className="text-[10px] text-muted-foreground mt-1">{item.detail}</p>
          </div>
        ))}
      </div>
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
export function Migration({ report }: { report: Report }) {
  return (
    <section>
      <h2 className="text-sm font-semibold mb-4">Prioritized migration actions</h2>
      <p className="text-xs text-muted-foreground mb-5">
        Priorities and recommendations are supplied by the Python scanner. These actions do not
        modify your systems.
      </p>
      <div className="space-y-3">
        {report.summary.plan.map((action, i) => (
          <div className="panel p-5" key={i}>
            <div className="flex flex-wrap items-center gap-4">
              <span className="risk-badge risk-critical">{action.priority}</span>
              <h3 className="text-sm font-medium flex-1">{action.action}</h3>
              <span className="text-xs text-muted-foreground">
                {action.asset_count} assets · {action.source}
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
  const { offlineDemo } = useReport();
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
              {report.summary.assets} assets ·{" "}
              {report.origin === "sample"
                ? "Sample data"
                : report.origin === "cli"
                  ? "Loaded CLI results"
                  : "Uploaded inputs"}
            </p>
            <Button
              variant="outline"
              disabled={
                pending !== null || (offlineDemo && (format === "cbom" || format === "sarif"))
              }
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
      {offlineDemo && (
        <p className="text-xs mt-4">
          Bundled demo: JSON and CSV are available. Run a backend scan for validated CBOM and SARIF
          exports.
        </p>
      )}
      {error && (
        <p role="alert" className="mt-4 text-critical">
          {error}
        </p>
      )}
    </>
  );
}
