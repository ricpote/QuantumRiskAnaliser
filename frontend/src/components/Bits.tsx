import type { ReactNode } from "react";
import { displayRisk, type Finding, type Tier } from "@/lib/quantumtrace-data";
import { findingBadge, tierClass, tierIcon, tierLabel } from "@/lib/labels";

/** Page heading used by every inner page. */
export function PageHead({
  title,
  children,
  aside,
}: {
  title: string;
  children?: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-6 border-b border-border pb-6">
      <div className="max-w-2xl">
        <h1 className="text-4xl leading-tight md:text-5xl">{title}</h1>
        {children && <p className="mt-3 text-lg text-muted-foreground">{children}</p>}
      </div>
      {aside}
    </header>
  );
}

/** Segmented control styled as instrument switches. */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
  disabled,
}: {
  value: T;
  options: { v: T; l: ReactNode }[];
  onChange: (v: T) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className="inline-flex flex-wrap rounded-sm border border-border p-0.5"
    >
      {options.map((o) => (
        <button
          key={o.v}
          type="button"
          role="radio"
          aria-checked={value === o.v}
          disabled={disabled}
          onClick={() => onChange(o.v)}
          className={`rounded-sm px-3 py-1.5 text-sm transition disabled:opacity-50 ${value === o.v ? "bg-primary font-semibold text-primary-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground"}`}
        >
          {o.l}
        </button>
      ))}
    </div>
  );
}

/** Large readout: a value with a small label beneath, like an instrument display. */
export function Readout({
  value,
  label,
  tone,
}: {
  value: ReactNode;
  label: ReactNode;
  tone?: "critical" | "safe" | "medium" | undefined;
}) {
  const c =
    tone === "critical"
      ? "text-critical"
      : tone === "safe"
        ? "text-safe"
        : tone === "medium"
          ? "text-medium"
          : "";
  return (
    <div className="panel grid-paper p-4">
      <div className={`font-display text-4xl font-semibold tabular-nums ${c}`}>{value}</div>
      <div className="mt-1 text-sm text-muted-foreground">{label}</div>
    </div>
  );
}

export function Notice({
  children,
  tone = "muted",
}: {
  children: ReactNode;
  tone?: "muted" | "critical";
}) {
  return (
    <p
      role={tone === "critical" ? "alert" : undefined}
      className={`border-l-2 pl-3 text-sm ${tone === "critical" ? "border-critical text-critical" : "border-border text-muted-foreground"}`}
    >
      {children}
    </p>
  );
}

/** Quantum tier of a system (no finding at hand): icon and word, never colour alone. */
export function TierBadge({ tier }: { tier: Tier }) {
  return (
    <span className={`risk-badge ${tierClass[tier]}`}>
      <span aria-hidden>{tierIcon[tier]}</span>
      {tierLabel[tier]}
    </span>
  );
}

/** Badge for one finding, worded by findingBadge(): "Broken today" or "Protocol" where the quantum axis says nothing useful. */
export function RiskBadge({ finding }: { finding: Finding }) {
  const b = findingBadge(finding);
  const risk = displayRisk(finding);
  const icon =
    risk === "Classical issue"
      ? finding.classical_status === "broken"
        ? "✕"
        : "~"
      : risk === "Protocol"
        ? "•"
        : tierIcon[finding.risk_tier];
  return (
    <span className={`risk-badge ${b.className}`} title={b.meaning}>
      <span aria-hidden>{icon}</span>
      {b.label}
    </span>
  );
}

export function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  );
}
