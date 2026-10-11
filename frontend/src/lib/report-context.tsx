import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { reportSchema, type Report } from "./quantumtrace-data";

async function request(path: string, body?: unknown, signal?: AbortSignal) {
  const response = await fetch(path, {
    ...(body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
    ...(signal ? { signal } : {}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ?? `Request failed (${response.status})`);
  return value;
}
function useReportState() {
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offlineDemo, setOfflineDemo] = useState(false);
  const active = useRef<AbortController | null>(null);
  const running = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    active.current = controller;
    request("/api/report", undefined, controller.signal)
      .then((value) => setReport(value === null ? null : reportSchema.parse(value)))
      .catch((e) => {
        if (!controller.signal.aborted) setError(`Could not load scan results: ${e.message}`);
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => {
      active.current?.abort();
    };
  }, []);
  async function run(operation: (signal: AbortSignal) => Promise<Report | null>, demo = false) {
    if (running.current) return;
    running.current = true;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(null);
    try {
      const value = await operation(controller.signal);
      if (!controller.signal.aborted) {
        setReport(value);
        setOfflineDemo(demo);
      }
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      running.current = false;
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  const reload = () =>
    run(async (signal) => reportSchema.parse(await request("/api/refresh", {}, signal)));
  const demo = () =>
    run(
      async (signal) => reportSchema.parse(await request("/demo-report.json", undefined, signal)),
      true,
    );
  const scan = (files: File[], sample = false) =>
    run(async (signal) => {
      if (!sample && !files.length)
        throw new Error("Choose source files, captures, AWS exports, or a ZIP.");
      if (files.reduce((sum, f) => sum + f.size, 0) > 32 * 1024 * 1024)
        throw new Error("Choose files totalling at most 32 MiB.");
      const uploads = await Promise.all(
        files.map(async (file) => {
          const bytes = new Uint8Array(await file.arrayBuffer());
          let binary = "";
          for (let offset = 0; offset < bytes.length; offset += 8192)
            binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
          return { name: file.name, content: btoa(binary) };
        }),
      );
      await request("/api/scan", { demo: sample, files: uploads }, signal);
      while (!signal.aborted) {
        const status = await request("/api/status", undefined, signal);
        if (status.state === "error") throw new Error(status.error);
        if (status.state !== "running")
          return reportSchema.parse(await request("/api/report", undefined, signal));
        await new Promise((resolve) => setTimeout(resolve, 700));
      }
      return null;
    });
  return { report, busy, error, offlineDemo, reload, demo, scan };
}
const Context = createContext<ReturnType<typeof useReportState> | null>(null);
export function ReportProvider({ children }: { children: ReactNode }) {
  return <Context.Provider value={useReportState()}>{children}</Context.Provider>;
}
export function useReport() {
  const value = useContext(Context);
  if (!value) throw new Error("ReportProvider is required");
  return value;
}
