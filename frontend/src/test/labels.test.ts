import { describe, expect, it } from "vitest";
import demo from "./fixtures/scanner-report.json";
import { adaptFindings, reportSchema, type Finding } from "@/lib/quantumtrace-data";
import { findingBadge } from "@/lib/labels";

function withRating(patch: Partial<Finding>): Finding {
  const report = reportSchema.parse(demo);
  return { ...report.findings[0]!, ...patch };
}

describe("finding badges", () => {
  it("never calls a finding that is weak today quantum-resilient", () => {
    const prng = withRating({
      risk_tier: "safe",
      quantum_threat: "none",
      classical_status: "broken",
      category: "rng",
    });
    expect(findingBadge(prng)).toMatchObject({ label: "Broken today", className: "risk-critical" });
    const tls10 = withRating({
      risk_tier: "safe",
      quantum_threat: "none",
      classical_status: "deprecated",
      category: "protocol",
      params: { version: "TLS 1.0" },
    });
    expect(findingBadge(tls10).label).toBe("Deprecated");
  });
  it("rates protocols through their parts and flags TLS 1.2 as unable to do PQ", () => {
    const base = {
      risk_tier: "safe",
      quantum_threat: "none",
      classical_status: "acceptable",
      category: "protocol",
    } as const;
    expect(findingBadge(withRating({ ...base, params: { version: "TLS 1.2" } })).label).toBe(
      "Protocol · no PQ possible",
    );
    expect(findingBadge(withRating({ ...base, params: { version: "TLS 1.3" } })).label).toBe(
      "Protocol",
    );
  });
  it("keeps the quantum tiers for real quantum ratings", () => {
    expect(findingBadge(withRating({ risk_tier: "critical", quantum_threat: "shor" })).label).toBe(
      "Critical",
    );
    const pq = withRating({
      risk_tier: "safe",
      quantum_threat: "none",
      classical_status: "recommended",
      category: "key-exchange",
    });
    expect(findingBadge(pq).label).toBe("Quantum-resilient");
  });
  it("filters by the displayed risk", () => {
    const report = reportSchema.parse(demo);
    report.findings[0] = {
      ...report.findings[0]!,
      risk_tier: "safe",
      quantum_threat: "none",
      classical_status: "broken",
      category: "rng",
    };
    expect(adaptFindings(report)[0]!.risk).toBe("Classical issue");
  });
});
