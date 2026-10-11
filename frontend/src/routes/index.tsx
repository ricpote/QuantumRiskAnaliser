import { createFileRoute } from "@tanstack/react-router";
import { Overview } from "@/components/quantumtrace/overview";
import { WithReport } from "@/components/shell/AppShell";
export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Quantum Readiness Overview" },
      {
        name: "description",
        content: "A clear view of cryptographic assets, quantum risk, and discovery coverage.",
      },
      { property: "og:title", content: "QuantumTrace | Quantum Readiness Overview" },
      {
        property: "og:description",
        content:
          "Discover your cryptographic footprint and prioritize your post-quantum transition.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <WithReport>{(r) => <Overview key={r.generated_at} report={r} />}</WithReport>,
});
