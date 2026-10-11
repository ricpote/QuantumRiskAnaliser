import { createFileRoute } from "@tanstack/react-router";
import { Migration } from "@/components/quantumtrace/migration";
import { WithReport } from "@/components/shell/AppShell";
export const Route = createFileRoute("/migration")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Migration Plan" },
      {
        name: "description",
        content: "Prioritize cryptographic replacements for your post-quantum transition.",
      },
      { property: "og:title", content: "QuantumTrace | Migration Plan" },
      {
        property: "og:description",
        content: "Prioritize cryptographic replacements for your post-quantum transition.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: () => <WithReport>{(r) => <Migration key={r.generated_at} report={r} />}</WithReport>,
});
