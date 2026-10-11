import { z } from "zod";

export const findingSchema = z
  .object({
    id: z.string(),
    source: z.enum(["network", "code", "cloud", "probe"]),
    category: z.string(),
    algorithm: z.string(),
    display_name: z.string().nullable(),
    params: z.record(z.unknown()),
    asset: z.record(z.unknown()),
    location: z.record(z.unknown()),
    evidence: z.string(),
    risk_tier: z.enum(["critical", "medium", "safe", "unencrypted"]),
    risk_points: z.number(),
    classical_status: z.string(),
    quantum_threat: z.string(),
    hndl: z.boolean(),
    replacement: z
      .object({ algorithm: z.string(), how: z.string().optional() })
      .passthrough()
      .nullable(),
    rationale: z.array(z.string()),
    flags: z.array(z.string()),
  })
  .passthrough();
const migrationSchema = z.object({
  source: z.string(),
  category: z.string(),
  action: z.string(),
  replacement: z.string(),
  standard: z.string().nullable(),
  how: z.string().nullable(),
  assets: z.array(z.string()),
  asset_count: z.number(),
  priority: z.enum(["P0", "P1", "P2"]),
  risk_removed: z.number(),
  hndl: z.boolean(),
  from_algorithms: z.array(z.string()),
});
export const reportSchema = z.object({
  schema_version: z.literal(1),
  origin: z.enum(["sample", "cli", "upload"]),
  generated_at: z.string(),
  findings: z.array(findingSchema),
  summary: z
    .object({
      quantum_readiness_score: z.number().nullable(),
      grade: z.string(),
      assets: z.number(),
      findings: z.number(),
      tiers: z.record(z.number()),
      classical: z.record(z.number()),
      sources: z.record(
        z
          .object({ score: z.number(), assets: z.number(), tiers: z.record(z.number()) })
          .passthrough(),
      ),
      plan: z.array(migrationSchema),
      warnings: z.array(z.object({ path: z.string(), reason: z.string() })).default([]),
    })
    .passthrough(),
});
export type Report = z.infer<typeof reportSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type Risk = "Critical" | "Medium" | "Resilient" | "Unencrypted";
export type Source = "Network" | "Code" | "Cloud" | "Probe";
export interface Asset {
  id: string;
  name: string;
  location: string;
  algorithm: string;
  keySize: string;
  source: Source;
  risk: Risk;
  replacement: string;
  evidence: string;
  finding: Finding;
}
const riskLabels = {
  critical: "Critical",
  medium: "Medium",
  safe: "Resilient",
  unencrypted: "Unencrypted",
} as const;
export const sourceLabels = {
  network: "Network",
  code: "Code",
  cloud: "Cloud",
  probe: "Probe",
} as const;
// Each row is one finding. Classification, risk points and priorities come from Python.
export function adaptFindings(report: Report): Asset[] {
  return report.findings.map((f) => {
    const a = f.asset,
      l = f.location,
      path = l["file"] ?? l["pcap"] ?? l["json"];
    return {
      id: f.id,
      name: String(a["alias"] ?? a["domain"] ?? a["host"] ?? a["path"] ?? a["arn"] ?? f.algorithm),
      location: path
        ? `${path}${l["line"] ? `:${l["line"]}` : ""}`
        : String(a["arn"] ?? `${a["host"] ?? ""}:${a["port"] ?? ""}`),
      algorithm: f.display_name ?? f.algorithm,
      keySize: f.params["key_bits"]
        ? `${f.params["key_bits"]}-bit`
        : String(f.params["curve"] ?? "—"),
      source: sourceLabels[f.source],
      risk: riskLabels[f.risk_tier],
      replacement:
        f.replacement?.how ??
        f.replacement?.algorithm ??
        "No replacement recommended by the scanner",
      evidence: f.evidence,
      finding: f,
    };
  });
}
export function filterAssets(assets: Asset[], query: string, risk: string, source: string) {
  const term = query.trim().toLowerCase();
  return assets.filter(
    (a) =>
      (risk === "All risks" || a.risk === risk) &&
      (source === "All sources" || a.source === source) &&
      `${a.name} ${a.location} ${a.algorithm}`.toLowerCase().includes(term),
  );
}
export function saveDownload(text: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function downloadReport(report: Report, format: "json" | "csv") {
  const cell = (v: string) => `"${(/^[=+@\-\t\r]/.test(v) ? `'${v}` : v).replaceAll('"', '""')}"`;
  const text =
    format === "json"
      ? JSON.stringify(report, null, 2)
      : [
          "ID,Asset,Algorithm,Key size,Source,Risk,Replacement",
          ...adaptFindings(report).map((a) =>
            [a.id, a.name, a.algorithm, a.keySize, a.source, a.risk, a.replacement]
              .map(cell)
              .join(","),
          ),
        ].join("\n");
  saveDownload(
    text,
    `quantumtrace-${report.origin === "sample" ? "sample-" : ""}report.${format}`,
    format === "json" ? "application/json" : "text/csv",
  );
}
