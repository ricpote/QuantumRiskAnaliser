import type { Tier } from "./quantumtrace-data";

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
