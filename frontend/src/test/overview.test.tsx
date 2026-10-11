import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Overview } from "@/components/quantumtrace/report-panels";
import { reportSchema } from "@/lib/quantumtrace-data";
import fixture from "./fixtures/scanner-report.json";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a>,
}));
afterEach(cleanup);

it("presents backend readiness and supporting metrics without recomputing them", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  render(<Overview report={report} />);
  const metrics = within(screen.getByRole("region", { name: "Readiness metrics" }));
  expect(metrics.getByRole("meter")).toHaveAttribute(
    "aria-valuenow",
    String(report.summary.quantum_readiness_score),
  );
  expect(metrics.getByText(`Grade ${report.summary.grade}`)).toBeInTheDocument();
  expect(metrics.getByText(String(report.summary.assets))).toBeInTheDocument();
  expect(metrics.getByText("Systems at risk before Q-Day")).toBeInTheDocument();
});

it("does not imply an unavailable assessment is a measured zero", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  report.findings = [];
  report.summary.quantum_readiness_score = null;
  render(<Overview report={report} />);
  expect(screen.queryByRole("meter")).not.toBeInTheDocument();
  expect(screen.getAllByText("Not assessed").length).toBeGreaterThan(0);
  expect(screen.queryByText(/^Grade /)).not.toBeInTheDocument();
});

it("preserves zero as a valid measured readiness score", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  report.summary.quantum_readiness_score = 0;
  render(<Overview report={report} />);
  expect(screen.getByRole("meter")).toHaveAttribute("aria-valuenow", "0");
});
