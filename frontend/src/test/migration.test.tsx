import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Migration } from "@/components/quantumtrace/migration";
import { reportSchema } from "@/lib/quantumtrace-data";
import fixture from "./fixtures/scanner-report.json";

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
