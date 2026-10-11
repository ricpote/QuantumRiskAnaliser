import { Download } from "lucide-react";
import { useState } from "react";
import { Notice, PageHead, Readout } from "@/components/Bits";
import { downloadReport, saveDownload, type Report } from "@/lib/quantumtrace-data";

const EXPORTS = [
  {
    k: "cbom",
    name: "CycloneDX 1.6 CBOM",
    what: "Cryptographic bill of materials: hand it to auditors or feed it to dependency tracking.",
  },
  {
    k: "sarif",
    name: "Code scanning SARIF",
    what: "Upload to GitHub or GitLab so findings appear on the exact lines of code.",
  },
  {
    k: "json",
    name: "Complete scan report",
    what: "The raw JSON this dashboard shows, for your own tooling.",
  },
  {
    k: "csv",
    name: "Finding inventory CSV",
    what: "One row per finding: asset, algorithm, key size, source, risk, replacement.",
  },
] as const;

export function Reports({ report }: { report: Report }) {
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const s = report.summary;
  // CBOM and SARIF are built by the Python backend for exactly this report (?at= guards against a newer one).
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
    <div className="mx-auto max-w-5xl space-y-12">
      <PageHead title="Reports">
        Your cryptographic findings, ready to share. Scan from{" "}
        {new Date(report.generated_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC.
      </PageHead>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <Readout
          value={s.quantum_readiness_score ?? "—"}
          label={
            s.quantum_readiness_score === null ? "Score not assessed" : `Score, grade ${s.grade}`
          }
        />
        <Readout value={s.findings} label={`Findings in ${s.assets} assets`} />
        <Readout value={s.tiers["critical"] ?? 0} label="Critical findings" tone="critical" />
        <Readout value={s.plan.length} label="Migration actions" />
      </div>
      <section className="space-y-3">
        <h2 className="text-3xl">Download</h2>
        {EXPORTS.map((e) => (
          <div key={e.k} className="panel flex flex-wrap items-center justify-between gap-4 p-4">
            <div>
              <p className="font-semibold">{e.name}</p>
              <p className="text-sm text-muted-foreground">
                {e.what} {s.assets} assets.
              </p>
            </div>
            <button
              className="btn-ghost"
              disabled={pending !== null}
              onClick={() =>
                e.k === "json" || e.k === "csv"
                  ? downloadReport(report, e.k)
                  : void exportBackend(e.k)
              }
            >
              <Download className="h-4 w-4" aria-hidden />
              {pending === e.k ? "Preparing…" : `Download ${e.k.toUpperCase()}`}
            </button>
          </div>
        ))}
        {error && <Notice tone="critical">{error}</Notice>}
      </section>
    </div>
  );
}
