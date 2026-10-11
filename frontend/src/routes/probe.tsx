import { createFileRoute } from "@tanstack/react-router";
import { ProbePanel } from "@/components/quantumtrace/probe";
export const Route = createFileRoute("/probe")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Live probe" },
      {
        name: "description",
        content: "Test whether a live server already uses post-quantum key exchange.",
      },
      { property: "og:title", content: "QuantumTrace | Live probe" },
      {
        property: "og:description",
        content: "Test whether a live server already uses post-quantum key exchange.",
      },
      { property: "og:type", content: "website" },
    ],
  }),
  component: ProbePanel,
});
