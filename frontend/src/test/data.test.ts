import { describe, expect, it } from "vitest";
import demo from "../../public/demo-report.json";
import { adaptFindings, filterAssets, reportSchema } from "@/lib/quantumtrace-data";

describe("Python report adapter", () => {
  it("preserves backend scores, tiers and migration ordering", () => {
    const report = reportSchema.parse(demo);
    expect(report.summary.quantum_readiness_score).toBe(demo.summary.quantum_readiness_score);
    expect(report.summary.plan).toEqual(demo.summary.plan);
    const rows = adaptFindings(report);
    expect(rows).toHaveLength(demo.findings.length);
    expect(rows.map((r) => r.finding.risk_points)).toEqual(demo.findings.map((f) => f.risk_points));
    expect(report.origin).toBe("sample");
  });
  it("keeps unencrypted and probe findings distinct", () => {
    const report = reportSchema.parse(demo);
    const first = report.findings[0]!;
    first.source = "probe";
    first.risk_tier = "unencrypted";
    first.risk_points = 100;
    const row = adaptFindings(report)[0]!;
    expect(row.risk).toBe("Unencrypted");
    expect(row.source).toBe("Probe");
    expect(filterAssets([row], "", "Unencrypted", "Probe")).toEqual([row]);
  });
  it("keeps the Mosca timeline and exposure figures computed by Python", () => {
    const report = reportSchema.parse(demo);
    const mosca = report.summary.mosca!;
    expect(mosca.status).toEqual(demo.summary.mosca.status);
    expect(mosca.assets.map((a) => a.start_by)).toEqual(
      demo.summary.mosca.assets.map((a) => a.start_by),
    );
    expect(report.summary.top_assets).toHaveLength(demo.summary.top_assets.length);
    expect(report.summary.network).toEqual(demo.summary.network);
  });
  it("still accepts reports saved before the Mosca timeline existed", () => {
    const newer = ["mosca", "network", "top_assets"];
    const older = Object.fromEntries(
      Object.entries(demo.summary).filter(([k]) => !newer.includes(k)),
    );
    expect(reportSchema.parse({ ...demo, summary: older }).summary.mosca).toBeUndefined();
  });
  it("rejects malformed data instead of silently substituting samples", () => {
    expect(() => reportSchema.parse({ findings: [] })).toThrow();
    expect(() => reportSchema.parse({ ...demo, origin: "live" })).toThrow();
  });
  it("does not omit inventory-only or classically broken findings", () => {
    const report = reportSchema.parse(demo);
    expect(adaptFindings(report)).toHaveLength(report.findings.length);
    expect(
      filterAssets(adaptFindings(report), "no-match-value", "All risks", "All sources"),
    ).toEqual([]);
  });
});
