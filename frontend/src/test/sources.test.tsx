import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MoscaSources } from "@/components/quantumtrace/sources";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: React.ReactNode; to: string }) => (
    <a href={to}>{children}</a>
  ),
}));
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const table = {
  qday: [{ scenario: "default", year: 2033, why: "inside the 10-year window", sources: ["gri"] }],
  shelf_life: [
    { label: "E-mail", years: 10, why: "kept 10 years", basis: "stated", sources: ["law", "gri"] },
  ],
  migration: [
    {
      label: "AWS ACM certificate",
      years: 3,
      why: "no PQ WebPKI yet",
      basis: "estimate",
      sources: ["law"],
    },
  ],
  sources: [
    {
      id: "gri",
      title: "Quantum Threat Timeline",
      publisher: "GRI",
      date: "2026",
      url: "https://gri.example/r",
      primary: true,
      says: "28-49%",
    },
    {
      id: "law",
      title: "Código Comercial",
      publisher: "PT",
      date: "2025",
      url: "https://law.example/40",
      primary: false,
      says: "10 years",
    },
  ],
};

it("shows each value with its reason, basis and numbered sources, from the backend", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => table }));
  render(<MoscaSources />);
  const email = (await screen.findByText("E-mail")).closest("tr")!;
  expect(within(email).getByText("kept 10 years")).toBeInTheDocument();
  expect(within(email).getByText("Stated by the source")).toBeInTheDocument();
  expect(within(email).getByRole("link", { name: "Source 2" })).toHaveAttribute("href", "#src-law");
  expect(screen.getByText("Estimate within the sources' bounds")).toBeInTheDocument();
  const ref = screen.getByRole("link", { name: /Código Comercial/ });
  expect(ref).toHaveAttribute("href", "https://law.example/40");
  expect(ref).toHaveAttribute("target", "_blank");
  expect(screen.getByText(/secondary summary/)).toBeInTheDocument();
});

it("says so when the scanner service cannot answer", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
  render(<MoscaSources />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the scanner service");
});
