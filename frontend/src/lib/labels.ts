import { displayRisk, type Finding, type Tier } from "./quantumtrace-data";

// Plain-language labels shared by the dashboard pages.
export const tierLabel: Record<Tier, string> = {
  critical: "Critical",
  medium: "Medium",
  safe: "Quantum-resilient",
  unencrypted: "Unencrypted",
};
export const tierClass: Record<Tier, string> = {
  critical: "risk-critical",
  medium: "risk-medium",
  safe: "risk-safe",
  unencrypted: "risk-critical",
};
// What each tier means for someone outside security.
export const tierMeaning: Record<Tier, string> = {
  critical: "A quantum computer running Shor's algorithm breaks this.",
  medium: "Grover's algorithm weakens this: a larger key or digest fixes it.",
  safe: "Holds up against known quantum attacks.",
  unencrypted: "No encryption at all: readable today, no quantum computer needed.",
};
export const threatText: Record<string, string> = {
  shor: "Shor's algorithm breaks it",
  grover: "Grover's algorithm weakens it",
  none: "None known",
};
export const classicalText: Record<string, string> = {
  broken: "Yes: already broken today",
  deprecated: "Deprecated",
  acceptable: "No (acceptable)",
  recommended: "No (recommended)",
};
// Tiers in display order, each with an icon and a fill so colour is never the only signal.
export const TIER_ORDER: readonly Tier[] = ["unencrypted", "critical", "medium", "safe"];
export const tierIcon: Record<Tier, string> = {
  unencrypted: "!",
  critical: "✕",
  medium: "~",
  safe: "✓",
};
export const tierSwatch: Record<Tier, string> = {
  unencrypted: "hatch-plain",
  critical: "bg-critical",
  medium: "bg-medium",
  safe: "bg-safe",
};
export const sourceName: Record<string, string> = {
  network: "Network traffic",
  code: "Source code & configs",
  cloud: "Cloud (AWS)",
  probe: "Live probe",
};
// Display colour requested for the readiness score: below 40 critical, up to 50 medium, above 50 safe.
export function scoreTone(score: number): "critical" | "medium" | "safe" {
  return score < 40 ? "critical" : score <= 50 ? "medium" : "safe";
}
// Plain-language verdict for the grade the backend assigned (copy only, no scoring).
const gradeVerdict: Record<string, string> = {
  A: "Ready for Q-Day",
  B: "Mostly ready",
  C: "Halfway there",
  D: "Exposed in places",
  E: "Largely exposed",
  F: "Not ready",
};
export const verdictOf = (grade: string) => gradeVerdict[grade] ?? `Grade ${grade}`;
// Badge for one finding: the quantum tier, except where the quantum axis says nothing useful.
type Badgeable = Pick<
  Finding,
  "risk_tier" | "quantum_threat" | "classical_status" | "category" | "params"
>;
export function findingBadge(f: Badgeable): { label: string; className: string; meaning: string } {
  const risk = displayRisk(f);
  if (risk === "Classical issue") {
    const broken = f.classical_status === "broken";
    return {
      label: broken ? "Broken today" : "Deprecated",
      className: broken ? "risk-critical" : "risk-medium",
      meaning: broken
        ? "Not a quantum problem: this is already insecure today, no quantum computer needed."
        : "Not a quantum problem, but current guidance deprecates it: plan its replacement.",
    };
  }
  if (risk === "Protocol") {
    const version = String(f.params["version"] ?? "");
    const legacy = /TLS 1\.[0-2]|SSL/.test(version);
    return {
      label: legacy ? "Protocol · no PQ possible" : "Protocol",
      className: legacy ? "risk-medium" : "risk-neutral",
      meaning: legacy
        ? `${version} itself is not broken by a quantum computer, but it cannot negotiate ML-KEM: its key exchange and signature, rated separately, stay quantum-vulnerable.`
        : "A protocol is rated through its key exchange, signature and cipher, listed separately for the same connection.",
    };
  }
  return {
    label: tierLabel[f.risk_tier],
    className: tierClass[f.risk_tier],
    meaning: tierMeaning[f.risk_tier],
  };
}
