import "./lib/error-capture";

import { consumeLastCapturedError } from "./lib/error-capture";
import { renderErrorPage } from "./lib/error-page";

type ServerEntry = {
  fetch: (request: Request, env: unknown, ctx: unknown) => Promise<Response> | Response;
};

let serverEntryPromise: Promise<ServerEntry> | undefined;

async function getServerEntry(): Promise<ServerEntry> {
  if (!serverEntryPromise) {
    serverEntryPromise = import("@tanstack/react-start/server-entry").then(
      (m) => (m.default ?? m) as ServerEntry,
    );
  }
  return serverEntryPromise;
}

// h3 swallows in-handler throws into a normal 500 Response with body
// {"unhandled":true,"message":"HTTPError"} — try/catch alone never fires for those.
async function normalizeCatastrophicSsrResponse(response: Response): Promise<Response> {
  if (response.status < 500) return response;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  const body = await response.clone().text();
  if (!isH3SwallowedErrorBody(body)) return response;

  console.error(consumeLastCapturedError() ?? new Error(`h3 swallowed SSR error: ${body}`));
  return new Response(renderErrorPage(), {
    status: 500,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function isH3SwallowedErrorBody(body: string): boolean {
  try {
    const payload = JSON.parse(body) as { unhandled?: unknown; message?: unknown };
    return payload.unhandled === true && payload.message === "HTTPError";
  } catch {
    return false;
  }
}

export default {
  async fetch(request: Request, env: unknown, ctx: unknown) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      if (!["GET", "POST"].includes(request.method))
        return new Response("Method not allowed", { status: 405 });
      if (
        request.method === "POST" &&
        (request.headers.get("origin") !== url.origin ||
          request.headers.get("content-type")?.split(";")[0] !== "application/json")
      ) {
        return new Response(JSON.stringify({ error: "Same-origin JSON requests required" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      }
      try {
        const limit = 48 * 1024 * 1024;
        if (Number(request.headers.get("content-length") ?? 0) > limit)
          return new Response(JSON.stringify({ error: "Upload too large" }), {
            status: 413,
            headers: { "content-type": "application/json" },
          });
        let body: string | undefined;
        if (request.method === "POST") {
          const reader = request.body?.getReader();
          const chunks: Uint8Array[] = [];
          let size = 0;
          if (reader) {
            while (true) {
              const chunk = await reader.read();
              if (chunk.done) break;
              size += chunk.value.byteLength;
              if (size > limit) {
                await reader.cancel();
                return new Response(JSON.stringify({ error: "Upload too large" }), {
                  status: 413,
                  headers: { "content-type": "application/json" },
                });
              }
              chunks.push(chunk.value);
            }
          }
          body = Buffer.concat(chunks).toString("utf8");
        }
        return await fetch(
          new URL(
            url.pathname + url.search,
            process.env["QT_API_ORIGIN"] ?? "http://127.0.0.1:8502",
          ),
          {
            method: request.method,
            headers: { "Content-Type": "application/json" },
            ...(body === undefined ? {} : { body }),
            signal: AbortSignal.timeout(30000),
          },
        );
      } catch {
        return new Response(
          JSON.stringify({
            error: "Python scanner service is unavailable. Start the API and retry.",
          }),
          { status: 503, headers: { "content-type": "application/json" } },
        );
      }
    }
    try {
      const handler = await getServerEntry();
      const response = await handler.fetch(request, env, ctx);
      return await normalizeCatastrophicSsrResponse(response);
    } catch (error) {
      console.error(error);
      return new Response(renderErrorPage(), {
        status: 500,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
  },
};
