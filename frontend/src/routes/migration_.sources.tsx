import { createFileRoute } from "@tanstack/react-router";
import { MoscaSources } from "@/components/quantumtrace/sources";

// /migration/sources: not nested inside the migration page layout (the "_" suffix), but under its URL.
export const Route = createFileRoute("/migration_/sources")({
  head: () => ({
    meta: [
      { title: "QuantumTrace | Migration Timeline Sources" },
      {
        name: "description",
        content:
          "The source behind every Q-Day, shelf-life and migration-time value of the Mosca timeline.",
      },
      { property: "og:title", content: "QuantumTrace | Migration Timeline Sources" },
      {
        property: "og:description",
        content: "The source behind every Q-Day, shelf-life and migration-time value.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: MoscaSources,
});
