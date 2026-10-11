import { createRouter, rootRouteId } from "@tanstack/react-router";
import { describe, expect, it } from "vitest";

import { routeTree } from "@/routeTree.gen";

// Match routes without running loaders or rendering: loaders may need a server or
// network the test run lacks, and jsdom never loads the stylesheets React waits on.
describe("App routing", () => {
  it("does not expose the internal accuracy evaluation as a page", () => {
    const router = createRouter({ routeTree });
    expect(router.matchRoutes("/accuracy").at(-1)?.routeId).toBe(rootRouteId);
  });
  it.each([
    "/",
    "/inventory",
    "/migration",
    "/migration/sources",
    "/probe",
    "/explain",
    "/reports",
  ])("matches a page for %s instead of falling back to not found", (path) => {
    const router = createRouter({ routeTree });

    const matches = router.matchRoutes(path);

    expect(matches.at(-1)?.routeId).not.toBe(rootRouteId);
  });
});
