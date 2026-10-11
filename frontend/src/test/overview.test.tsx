import { renderToStaticMarkup } from "react-dom/server";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Overview } from "@/components/quantumtrace/overview";
import { reportSchema } from "@/lib/quantumtrace-data";
import fixture from "./fixtures/scanner-report.json";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a>,
  useNavigate: () => () => {},
}));
afterEach(cleanup);

it.each([
  [39.9, "critical"],
  [40, "medium"],
  [50, "medium"],
  [50.1, "safe"],
])("uses the requested display color for score %s", (score, tone) => {
  const report = reportSchema.parse(structuredClone(fixture));
  report.summary.quantum_readiness_score = score as number;
  const html = renderToStaticMarkup(<Overview report={report} />);
  expect(html).toContain(`data-tone="${tone}"`);
});

it("presents backend readiness and supporting metrics without recomputing them", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  render(<Overview report={report} />);
  const metrics = within(screen.getByRole("region", { name: "Readiness metrics" }));
  expect(metrics.getByRole("meter")).toHaveAttribute(
    "aria-valuenow",
    String(report.summary.quantum_readiness_score),
  );
  expect(metrics.getByRole("heading", { level: 1 })).toHaveTextContent(
    `Grade ${report.summary.grade}`,
  );
  expect(
    screen.getByRole("heading", { name: new RegExp(`in ${report.summary.assets} assets`) }),
  ).toBeInTheDocument();
  expect(screen.queryByText(/Python scanner assessment/)).not.toBeInTheDocument();
  const mosca = report.summary.mosca!;
  expect(
    metrics.getByText(
      new RegExp(`${mosca.at_risk} of ${mosca.evaluated} quantum-vulnerable systems`),
    ),
  ).toBeInTheDocument();
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

it("explains a report without network traffic instead of showing 0 of 0 endpoints", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  report.summary.network = { endpoints: 0, hndl_exposed: 0, pq_protected: 0, plaintext: 0 };
  render(<Overview report={report} />);
  expect(screen.getByText("No network traffic in these inputs.")).toBeInTheDocument();
  expect(screen.queryByText(/of 0 network endpoints/)).not.toBeInTheDocument();
});
