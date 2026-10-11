import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Migration } from "@/components/quantumtrace/migration";
import { reportSchema } from "@/lib/quantumtrace-data";
import fixture from "./fixtures/scanner-report.json";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: React.ReactNode; to: string }) => (
    <a href={to}>{children}</a>
  ),
}));
const response = (value: unknown) => ({ ok: true, json: async () => value });
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("asks the backend what ticking an action changes and shows its answer", async () => {
  const report = reportSchema.parse(structuredClone(fixture));
  const headline = { score: 54.5, grade: "D", critical: 7, hndl_exposed: 0, plaintext: 0, late: 5 };
  const fetch = vi.fn().mockResolvedValue(
    response({
      actions: 1,
      before: headline,
      after: { ...headline, score: 71, grade: "B", critical: 3 },
    }),
  );
  vi.stubGlobal("fetch", fetch);
  render(<Migration report={report} />);
  expect(screen.getByText("Tick one or more actions to simulate them.")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("checkbox", { name: `Simulate: ${report.summary.plan[0]!.action}` }),
  );
  expect(
    await screen.findByText(/Applying 1 action: readiness score 54.5 \(D\)/),
  ).toBeInTheDocument();
  const [path, init] = fetch.mock.calls[0]!;
  expect(path).toBe("/api/whatif");
  expect(JSON.parse(init.body)).toEqual({ actions: [0], at: report.generated_at });
});

it("re-runs Mosca's rule in the backend for another Q-Day scenario", async () => {
  const report = reportSchema.parse(structuredClone(fixture));
  const mosca = report.summary.mosca!;
  const early = { ...mosca, qday_year: 2030, at_risk: 6 };
  const fetch = vi.fn().mockResolvedValue(response(early));
  vi.stubGlobal("fetch", fetch);
  render(<Migration report={report} />);
  expect(screen.getByRole("heading", { name: /If Q-Day comes in 2033/ })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Early · Q-Day 2030/ }));
  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /If Q-Day comes in 2030/ })).toBeInTheDocument(),
  );
  expect(fetch.mock.calls[0]![0]).toBe(
    `/api/mosca?qday=2030&at=${encodeURIComponent(report.generated_at)}`,
  );
});

it("lists every affected asset of an action and the per-system timeline", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  render(<Migration report={report} />);
  expect(screen.getAllByText("Affected assets")).toHaveLength(report.summary.plan.length);
  expect(screen.getByRole("list", { name: "Mosca timeline per system" }).children).toHaveLength(
    Math.min(12, report.summary.mosca!.assets.length),
  );
});

it("lets the user type any Q-Day year, even past 2060, and asks the backend for it", async () => {
  const report = reportSchema.parse(structuredClone(fixture));
  const mosca = report.summary.mosca!;
  const fetch = vi.fn().mockResolvedValue(response({ ...mosca, qday_year: 2075, at_risk: 3 }));
  vi.stubGlobal("fetch", fetch);
  render(<Migration report={report} />);
  fireEvent.change(screen.getByLabelText("Custom year"), { target: { value: "2075" } });
  fireEvent.click(screen.getByRole("button", { name: "Show" }));
  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /If Q-Day comes in 2075/ })).toBeInTheDocument(),
  );
  expect(fetch.mock.calls[0]![0]).toBe(
    `/api/mosca?qday=2075&at=${encodeURIComponent(report.generated_at)}`,
  );
});

it("refuses a Q-Day in the past or beyond four digits instead of sending it", () => {
  const report = reportSchema.parse(structuredClone(fixture));
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  render(<Migration report={report} />);
  fireEvent.change(screen.getByLabelText("Custom year"), { target: { value: "2020" } });
  fireEvent.click(screen.getByRole("button", { name: "Show" }));
  expect(screen.getByRole("alert")).toHaveTextContent(/from \d{4} onwards/);
  fireEvent.change(screen.getByLabelText("Custom year"), { target: { value: "12000" } });
  fireEvent.click(screen.getByRole("button", { name: "Show" }));
  expect(screen.getByRole("alert")).toHaveTextContent(/four digits/);
  expect(fetch).not.toHaveBeenCalled();
});

it("links every number of the timeline to its sources", () => {
  render(<Migration report={reportSchema.parse(structuredClone(fixture))} />);
  const link = screen.getByRole("link", { name: /Where these numbers come from/ });
  expect(link).toHaveAttribute("href", "/migration/sources");
});

it("pages long plans 10 actions at a time and keeps ticked actions across pages", async () => {
  const report = reportSchema.parse(structuredClone(fixture));
  const base = report.summary.plan[0]!;
  report.summary.plan = Array.from({ length: 25 }, (_, i) => ({
    ...base,
    action: `Action ${i + 1}`,
  }));
  const headline = { score: 50, grade: "D", critical: 7, hndl_exposed: 0, plaintext: 0, late: 5 };
  const fetch = vi.fn().mockImplementation(async (_path: string, init: { body: string }) =>
    response({
      actions: JSON.parse(init.body).actions.length,
      before: headline,
      after: headline,
    }),
  );
  vi.stubGlobal("fetch", fetch);
  render(<Migration report={report} />);
  const list = () => screen.getByRole("list", { name: "Migration actions" });
  expect(list().children).toHaveLength(10);
  expect(screen.getByText(/Showing 1–10 of 25 actions/)).toBeInTheDocument();
  expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox", { name: "Simulate: Action 1" }));
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(screen.getByText(/Showing 11–20 of 25 actions/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox", { name: "Simulate: Action 11" }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(JSON.parse(fetch.mock.calls[1]![1]!.body).actions).toEqual([0, 10]);
  expect(await screen.findByText(/2 actions ticked, on any page/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(list().children).toHaveLength(5);
  fireEvent.click(screen.getByRole("button", { name: "Previous" }));
  fireEvent.click(screen.getByRole("button", { name: "Previous" }));
  expect(screen.getByRole("checkbox", { name: "Simulate: Action 1" })).toBeChecked();
  fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
  expect(screen.getByText("Tick one or more actions to simulate them.")).toBeInTheDocument();
  expect(screen.getByRole("checkbox", { name: "Simulate: Action 1" })).not.toBeChecked();
});
