import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { Inventory, type InventorySearch } from "@/components/quantumtrace/inventory";
import { reportSchema, type Report } from "@/lib/quantumtrace-data";
import fixture from "./fixtures/scanner-report.json";

afterEach(cleanup);
const load = () => reportSchema.parse(structuredClone(fixture));

function Harness({
  report = load(),
  initial = {},
}: {
  report?: Report;
  initial?: InventorySearch;
}) {
  const [search, setSearch] = useState<InventorySearch>(initial);
  return <Inventory report={report} search={search} onSearch={setSearch} />;
}
const shown = () => screen.getByText(/^Showing \d+–\d+ of \d+ findings/).textContent;

it("filters by risk and source, then resets every filter", () => {
  const report = load();
  const critical = report.findings.filter((f) => f.risk_tier === "critical");
  const criticalCloud = critical.filter((f) => f.source === "cloud");
  render(<Harness report={report} />);
  expect(shown()).toBe(`Showing 1–${report.findings.length} of ${report.findings.length} findings`);
  fireEvent.click(screen.getByRole("radio", { name: "Critical" }));
  expect(shown()).toContain(
    `of ${critical.length} findings (filtered from ${report.findings.length})`,
  );
  fireEvent.click(screen.getByRole("radio", { name: "Cloud (AWS)" }));
  expect(shown()).toContain(`of ${criticalCloud.length} findings`);
  fireEvent.click(screen.getByRole("button", { name: "Reset filters" }));
  expect(shown()).toBe(`Showing 1–${report.findings.length} of ${report.findings.length} findings`);
});

it("narrows to the quantum tier picked on the overview until it is cleared", () => {
  const report = load();
  const safe = report.findings.filter((f) => f.risk_tier === "safe").length;
  render(<Harness report={report} initial={{ tier: "safe" }} />);
  expect(screen.getByText(/Showing quantum tier:/)).toBeInTheDocument();
  expect(shown()).toContain(`of ${safe} findings`);
  fireEvent.click(screen.getByRole("button", { name: "Show every tier" }));
  expect(shown()).toBe(`Showing 1–${report.findings.length} of ${report.findings.length} findings`);
});

it("searches names, algorithms and locations", () => {
  const report = load();
  const ecdsa = report.findings.filter((f) =>
    (f.display_name ?? f.algorithm).includes("ECDSA"),
  ).length;
  render(<Harness report={report} />);
  fireEvent.change(screen.getByRole("textbox", { name: "Search assets" }), {
    target: { value: "ECDSA" },
  });
  expect(shown()).toContain(`of ${ecdsa} findings`);
  fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
  expect(shown()).toContain(`of ${report.findings.length} findings`);
});

it("opens a finding with its evidence, reasoning and suggested next step", () => {
  render(<Harness />);
  fireEvent.click(screen.getAllByRole("button", { expanded: false })[0]!);
  expect(screen.getByText("Evidence")).toBeInTheDocument();
  expect(screen.getByText("Problem even without quantum?")).toBeInTheDocument();
  expect(screen.getByText("Suggested next step")).toBeInTheDocument();
});

it("pages through long inventories 25 findings at a time", () => {
  const report = load();
  const base = report.findings;
  report.findings = Array.from({ length: 30 }, (_, i) => ({
    ...base[i % base.length]!,
    id: `f${i}`,
  }));
  render(<Harness report={report} />);
  expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { expanded: false })).toHaveLength(25);
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(shown()).toBe("Showing 26–30 of 30 findings");
});

it("moves through the risk filter with the arrow keys, as one tab stop", () => {
  render(<Harness />);
  const group = screen.getByRole("radiogroup", { name: "Filter by risk" });
  const all = screen.getByRole("radio", { name: "All risks" });
  expect(all).toHaveAttribute("tabindex", "0");
  expect(screen.getByRole("radio", { name: "Critical" })).toHaveAttribute("tabindex", "-1");
  fireEvent.keyDown(group, { key: "ArrowRight" });
  expect(screen.getByRole("radio", { name: "Critical" })).toHaveAttribute("aria-checked", "true");
  expect(screen.getByRole("radio", { name: "Critical" })).toHaveFocus();
  fireEvent.keyDown(group, { key: "ArrowLeft" });
  expect(all).toHaveAttribute("aria-checked", "true");
});
