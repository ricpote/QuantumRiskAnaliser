import { createFileRoute } from "@tanstack/react-router";
import { Workspace } from "@/components/quantumtrace/workspace";
export const Route = createFileRoute("/accuracy")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Accuracy" },
      {
        name: "description",
        content: "QuantumTrace results checked against the labelled challenge data.",
      },
      { property: "og:title", content: "QuantumTrace | Accuracy" },
      {
        property: "og:description",
        content: "QuantumTrace results checked against the labelled challenge data.",
      },
      { property: "og:type", content: "website" },
    ],
  }),
  component: () => <Workspace view="accuracy" />,
});
