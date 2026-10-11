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
      .object({
        algorithm: z.string(),
        how: z.string().optional(),
        standard: z.string().nullable().optional(),
      })
      .passthrough()
      .nullable(),
    rationale: z.array(z.string()),
    flags: z.array(z.string()),
    deadlines: z.array(z.string()).optional(),
    deadline_year: z.number().nullable().optional(),
    cwe: z.array(z.string()).optional(),
    context: z.record(z.unknown()).optional(),
  })
  .passthrough();
const tierSchema = z.enum(["critical", "medium", "safe", "unencrypted"]);
// Mosca's inequality per Shor-vulnerable asset, computed by score.mosca() in Python.
const moscaAssetSchema = z.object({
  source: z.string(),
  key: z.string(),
  label: z.string(),
  shelf_life: z.number(),
  migration_years: z.number(),
  qday_year: z.number(),
  start_by: z.number(),
  finish_by: z.number(),
  years_late: z.number(),
  at_risk: z.boolean(),
  status: z.enum(["late", "start-now", "ok"]),
  hndl: z.boolean(),
  deadline_year: z.number().nullable(),
  why: z.array(z.string()),
});
export const moscaSchema = z.object({
  qday_year: z.number(),
  now: z.number(),
  evaluated: z.number(),
  at_risk: z.number(),
  status: z.record(z.number()),
  scenarios: z.record(z.object({ qday_year: z.number(), at_risk: z.number() })),
  cleartext_assets: z.number(),
  assets: z.array(moscaAssetSchema),
});
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
      network: z
        .object({
          endpoints: z.number(),
          hndl_exposed: z.number(),
          pq_protected: z.number(),
          plaintext: z.number(),
        })
        .optional(),
      top_assets: z
        .array(
          z.object({
            source: z.string(),
            key: z.string().optional(),
            label: z.string(),
            risk: z.number(),
            worst_tier: tierSchema,
            hndl: z.boolean(),
            plaintext: z.boolean().optional(),
            classical_broken: z.number(),
          }),
        )
        .optional(),
      mosca: moscaSchema.optional(),
      warnings: z.array(z.object({ path: z.string(), reason: z.string() })).default([]),
    })
    .passthrough(),
});
export type Report = z.infer<typeof reportSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type Tier = z.infer<typeof tierSchema>;
export type Mosca = z.infer<typeof moscaSchema>;
export type Risk =
  "Critical" | "Medium" | "Resilient" | "Unencrypted" | "Classical issue" | "Protocol";
export const riskFilters: readonly Risk[] = [
  "Critical",
  "Medium",
  "Classical issue",
  "Unencrypted",
  "Resilient",
  "Protocol",
];
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
type Rated = Pick<Finding, "risk_tier" | "quantum_threat" | "classical_status" | "category">;
// A finding no quantum algorithm touches is not "quantum-resilient" when it is weak today
// (hard-coded key, math/rand, TLS 1.0) or when it is a protocol rated through its parts.
export function displayRisk(f: Rated): Risk {
  if (f.risk_tier === "safe" && f.quantum_threat === "none") {
    if (f.classical_status === "broken" || f.classical_status === "deprecated")
      return "Classical issue";
    if (f.category === "protocol") return "Protocol";
  }
  return riskLabels[f.risk_tier];
}
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
      risk: displayRisk(f),
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
