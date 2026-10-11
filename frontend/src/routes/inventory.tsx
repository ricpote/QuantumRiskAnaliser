import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Inventory, type InventorySearch } from "@/components/quantumtrace/inventory";
import { WithReport } from "@/components/shell/AppShell";

const text = (v: unknown) => (typeof v === "string" && v ? v : undefined);

export const Route = createFileRoute("/inventory")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Crypto Inventory" },
      {
        name: "description",
        content: "Inspect cryptographic algorithms, evidence, and risk across your assets.",
      },
      { property: "og:title", content: "QuantumTrace | Crypto Inventory" },
      {
        property: "og:description",
        content: "Inspect cryptographic algorithms, evidence, and risk across your assets.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  // ?risk=Critical (risk filter), ?source=code, ?tier=safe (quantum tier, from the overview)
  validateSearch: (s: Record<string, unknown>): InventorySearch => ({
    risk: text(s["risk"]),
    source: text(s["source"]),
    tier: text(s["tier"]),
  }),
  component: InventoryPage,
});

function InventoryPage() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/inventory" });
  return (
    <WithReport>
      {(r) => (
        <Inventory
          report={r}
          search={search}
          onSearch={(next) => void navigate({ search: next, replace: true })}
        />
      )}
    </WithReport>
  );
}
