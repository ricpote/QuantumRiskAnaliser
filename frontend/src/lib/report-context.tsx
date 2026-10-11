import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { apiRequest as request } from "./api";
import { reportSchema, type Report } from "./quantumtrace-data";
import { readFile, MAX_UPLOAD_BYTES } from "./uploads";
function useReportState() {
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState("");
  const active = useRef<AbortController | null>(null);
  const running = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    active.current = controller;
    request("/api/report", undefined, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted)
          setReport(value === null ? null : reportSchema.parse(value));
      })
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
  async function run(operation: (signal: AbortSignal) => Promise<Report | null>) {
    if (running.current) return false;
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
        return true;
      }
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Request failed");
      return false;
    } finally {
      running.current = false;
      if (!controller.signal.aborted) setBusy(false);
      setScanning(false);
    }
    return false;
  }
  const reload = () =>
    run(async (signal) => reportSchema.parse(await request("/api/refresh", {}, signal)));
  const scan = (files: File[], sample = false) =>
    run(async (signal) => {
      setScanning(true);
      setProgress("Preparing files…");
      if (!sample && !files.length)
        throw new Error("Choose source files, captures, AWS exports, or a ZIP.");
      if (files.reduce((sum, f) => sum + f.size, 0) > MAX_UPLOAD_BYTES)
        throw new Error("Choose files totalling at most 32 MiB.");
      const uploads = await Promise.all(
        files.map(async (file) => {
          const bytes = new Uint8Array(await readFile(file));
          let binary = "";
          for (let offset = 0; offset < bytes.length; offset += 8192)
            binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
          return { name: file.name, content: btoa(binary) };
        }),
      );
      setProgress("Uploading and validating files…");
      await request("/api/scan", { demo: sample, files: uploads }, signal);
      const deadline = Date.now() + 10 * 60 * 1000;
      while (!signal.aborted) {
        if (Date.now() > deadline)
          throw new Error(
            "Analysis is taking longer than ten minutes. The previous report is unchanged; check the scanner before retrying.",
          );
        const status = await request<{ state: string; error: string; phase?: string }>(
          "/api/status",
          undefined,
          signal,
        );
        if (status.state === "error") throw new Error(status.error);
        if (status.state === "complete") {
          setProgress("Loading scan results…");
          return reportSchema.parse(await request("/api/report", undefined, signal));
        }
        if (status.state !== "running")
          throw new Error("The scan was interrupted. Please try again.");
        setProgress(
          status.phase === "validating"
            ? "Validating files and ZIP contents…"
            : "Analyzing with the Python scanner…",
        );
        await new Promise((resolve) => setTimeout(resolve, 700));
      }
      return null;
    });
  return { report, busy, error, reload, scan, scanning, progress };
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
