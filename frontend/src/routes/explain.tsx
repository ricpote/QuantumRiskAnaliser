import { createFileRoute } from "@tanstack/react-router";
import { ExplainPanel } from "@/components/quantumtrace/explain";
export const Route = createFileRoute("/explain")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Explain" },
      {
        name: "description",
        content: "How QuantumTrace rates any cryptographic algorithm, and why.",
      },
      { property: "og:title", content: "QuantumTrace | Explain" },
      {
        property: "og:description",
        content: "How QuantumTrace rates any cryptographic algorithm, and why.",
      },
      { property: "og:type", content: "website" },
    ],
  }),
  component: ExplainPanel,
});
