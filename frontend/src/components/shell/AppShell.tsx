import { Link, useRouterState } from "@tanstack/react-router";
import { AnimatePresence, motion } from "framer-motion";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  CircleHelp,
  Download,
  FolderOpen,
  Menu,
  Radar,
  RefreshCw,
  X,
} from "lucide-react";
import { useReport } from "@/lib/report-context";
import { downloadReport, type Report } from "@/lib/quantumtrace-data";
import { ScanDialog } from "@/components/quantumtrace/scan-dialog";
import { HelpDialog } from "./HelpDialog";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { to: "/", label: "Overview" },
  { to: "/migration", label: "Migration plan" },
  { to: "/inventory", label: "Crypto inventory", count: true },
  { to: "/probe", label: "Live probe" },
  { to: "/explain", label: "Explain" },
  { to: "/reports", label: "Reports" },
] as const;
// Pages about the loaded report; probe and explain are tools that work without one.
const REPORT_PAGES = ["/", "/inventory", "/migration", "/reports"];

const OpenScan = createContext<() => void>(() => {});

function originLabel(report: Report | null) {
  return report?.origin === "sample"
    ? "Official reference samples"
    : report?.origin === "upload"
      ? "Uploaded scan results"
      : report
        ? "Loaded CLI results"
        : "No results loaded";
}

function datasetOf(report: Report) {
  if (report.origin === "sample") return "samples/official/";
  return Array.from(
    new Set(
      report.findings.flatMap((f) =>
        [f.location["file"], f.location["pcap"], f.location["json"]].filter(
          (v): v is string => typeof v === "string",
        ),
      ),
    ),
  )
    .slice(0, 3)
    .join(", ");
}

function Nav({ onPick }: { onPick?: () => void }) {
  const { report } = useReport();
  return (
    <ul className="space-y-0.5">
      {NAV.map((n) => (
        <li key={n.to}>
          <Link
            to={n.to}
            onClick={onPick}
            activeOptions={{ exact: n.to === "/" }}
            className="group flex items-center justify-between rounded-sm px-3 py-2 text-sidebar-muted transition hover:bg-sidebar-accent hover:text-sidebar-foreground data-[status=active]:bg-sidebar-accent data-[status=active]:text-sidebar-foreground"
          >
            <span className="flex items-center gap-2">
              <span
                className="h-1.5 w-1.5 rounded-full bg-transparent group-data-[status=active]:bg-sidebar-primary"
                aria-hidden
              />
              {n.label}
            </span>
            {"count" in n && report && (
              <span
                className="text-sm tabular-nums"
                aria-label={`${report.findings.length} findings`}
              >
                {report.findings.length}
              </span>
            )}
          </Link>
        </li>
      ))}
    </ul>
  );
}

export function QuantumMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      <path d="M16 2 28 9v14l-12 7-12-7V9L16 2Z" stroke="currentColor" strokeWidth="1.5" />
      <path d="m10 12 6-3 6 3v8l-6 3-6-3v-8Z" stroke="currentColor" strokeWidth="1.5" />
      <path
        d="m17 18 10 10M16 2v7M4 9l6 3M28 9l-6 3M4 23l6-3"
        stroke="currentColor"
        strokeWidth="1.5"
      />
    </svg>
  );
}

// Logo of the previous dashboard: the hexagon mark and "QuantumTrace." with an accent dot.
function Wordmark({ tone = "sidebar" }: { tone?: "sidebar" | "page" }) {
  const accent = tone === "sidebar" ? "text-sidebar-primary" : "text-primary";
  return (
    <Link to="/" className="flex items-center gap-2.5" aria-label="QuantumTrace home">
      <QuantumMark className={`h-8 w-8 shrink-0 ${accent}`} />
      <span className="text-[19px] font-semibold">
        QuantumTrace<span className={accent}>.</span>
      </span>
    </Link>
  );
}

const SIDE_ITEM =
  "flex w-full items-center gap-2 rounded-sm px-3 py-2 text-left text-sidebar-muted transition hover:bg-sidebar-accent hover:text-sidebar-foreground";

/** Bottom of the sidebar: results status, help (as in the previous dashboard) and the light-mode switch. */
function SideFooter({
  status,
  live,
  onHelp,
}: {
  status: string;
  live: boolean;
  onHelp: () => void;
}) {
  return (
    <div className="mt-auto space-y-1 border-t border-sidebar-border pt-4">
      <StatusPill label={status} live={live} className="px-3 pb-2" />
      <button type="button" className={SIDE_ITEM} onClick={onHelp}>
        <CircleHelp className="h-4 w-4" aria-hidden />
        Help & resources
        <ArrowRight className="ml-auto h-4 w-4" aria-hidden />
      </button>
      <ThemeToggle className={SIDE_ITEM} />
    </div>
  );
}

function StatusPill({
  label,
  live,
  className = "",
}: {
  label: string;
  live: boolean;
  className?: string;
}) {
  return (
    <p className={`flex items-center gap-2 text-sm ${className}`} aria-live="polite">
      <span
        className={`h-2 w-2 rounded-full ${live ? "bg-safe" : "border border-current opacity-60"}`}
        aria-hidden
      />
      {label}
    </p>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const data = useReport();
  const { report, busy, error } = data;
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [menu, setMenu] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [warnOpen, setWarnOpen] = useState(false);
  useEffect(() => setWarnOpen(false), [report]);
  const warnings = report?.summary.warnings ?? [];
  const onReportPage = REPORT_PAGES.includes(path);
  const status = originLabel(report);
  const dataset = report ? datasetOf(report) : "";
  const generated = report
    ? new Date(report.generated_at).toLocaleString("en-GB", { timeZone: "UTC" }) + " UTC"
    : "";

  return (
    <OpenScan.Provider value={() => setScanOpen(true)}>
      <div className="workspace min-h-screen lg:grid lg:grid-cols-[15rem_1fr]">
        <aside className="sticky top-0 hidden h-screen flex-col overflow-y-auto border-r border-sidebar-border bg-sidebar px-4 py-6 text-sidebar-foreground lg:flex">
          <Wordmark />
          <nav aria-label="Main" className="mt-8">
            <Nav />
          </nav>
          <SideFooter status={status} live={!!report} onHelp={() => setHelpOpen(true)} />
        </aside>

        <AnimatePresence>
          {menu && (
            <motion.div
              className="fixed inset-0 z-40 flex flex-col overflow-y-auto bg-sidebar p-6 text-sidebar-foreground lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <div className="flex items-center justify-between">
                <Wordmark />
                <button
                  onClick={() => setMenu(false)}
                  aria-label="Close menu"
                  className="rounded-sm p-2 hover:bg-sidebar-accent"
                >
                  <X />
                </button>
              </div>
              <nav aria-label="Main" className="mt-8 text-lg">
                <Nav onPick={() => setMenu(false)} />
              </nav>
              <SideFooter
                status={status}
                live={!!report}
                onHelp={() => {
                  setMenu(false);
                  setHelpOpen(true);
                }}
              />
            </motion.div>
          )}
        </AnimatePresence>

        <div className="flex min-h-screen min-w-0 flex-col">
          <header className="sticky top-0 z-30 border-b border-border bg-background/85 backdrop-blur">
            <div className="flex items-center gap-2 px-4 py-3 sm:gap-3 sm:px-5 md:px-8">
              <button
                onClick={() => setMenu(true)}
                aria-label="Open navigation"
                className="rounded-sm p-2 hover:bg-accent lg:hidden"
              >
                <Menu />
              </button>
              <span className="lg:hidden">
                <Wordmark tone="page" />
              </span>
              <StatusPill label={status} live={!!report} className="hidden md:flex lg:hidden" />
              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={() => report && downloadReport(report, "json")}
                  disabled={!report}
                  className="inline-flex items-center gap-1.5 rounded-sm border border-border p-2 text-sm transition hover:bg-accent disabled:cursor-not-allowed disabled:opacity-45 sm:px-[0.9rem] sm:py-[0.45rem]"
                  aria-label="Export report"
                >
                  <Download className="h-4 w-4" />
                  <span className="hidden sm:inline">Export report</span>
                </button>
                <button
                  onClick={() => setScanOpen(true)}
                  disabled={data.scanning}
                  className="btn-primary"
                >
                  <Radar className="h-4 w-4" />
                  New scan
                </button>
              </div>
            </div>
            {onReportPage && (
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-5 py-2 text-sm text-muted-foreground md:px-8">
                <span className="break-all">
                  {status}
                  {dataset && ` · ${dataset}`}
                  {generated && ` · ${generated}`}
                </span>
                <span className="ml-auto flex flex-wrap gap-3">
                  <button onClick={() => void data.reload()} disabled={busy} className="btn-link">
                    <RefreshCw className="h-3.5 w-3.5" />
                    Load saved scan results
                  </button>
                  <button
                    onClick={() => void data.scan([], true)}
                    disabled={busy}
                    className="btn-link"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    Analyze reference dataset
                  </button>
                </span>
              </div>
            )}
            <AnimatePresence>
              {busy && (
                <motion.div
                  role="status"
                  initial={{ height: 0 }}
                  animate={{ height: "auto" }}
                  exit={{ height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="relative flex items-center gap-2 px-5 py-2 text-sm md:px-8">
                    <span className="scan-sweep absolute inset-x-0 bottom-0 h-0.5" aria-hidden />
                    {data.scanning ? data.progress : "Loading or scanning inputs…"}{" "}
                    {report && "Existing results remain visible until this finishes."}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </header>

          <main className="flex-1 px-5 pb-16 pt-6 md:px-8">
            {onReportPage && error && (
              <div
                role="alert"
                className="mb-6 flex flex-wrap items-start gap-3 border-l-4 border-critical bg-critical/10 px-4 py-3"
              >
                <AlertTriangle className="mt-0.5 h-5 w-5 text-critical" />
                <div className="flex-1">
                  <p className="font-semibold">{error}</p>
                  <p className="text-sm text-muted-foreground">
                    Check the inputs or backend service, then retry.
                  </p>
                </div>
              </div>
            )}
            {onReportPage && warnings.length > 0 && (
              <div className="mb-6 border-l-4 border-medium px-4 py-2">
                <button
                  onClick={() => setWarnOpen(!warnOpen)}
                  aria-expanded={warnOpen}
                  className="flex items-center gap-2 text-sm"
                >
                  <AlertTriangle className="h-4 w-4 text-medium" />
                  {warnings.length} scanner {warnings.length === 1 ? "warning" : "warnings"}:
                  coverage may be incomplete
                  <ChevronDown className={`h-4 w-4 transition ${warnOpen ? "rotate-180" : ""}`} />
                </button>
                {warnOpen && (
                  <ul className="mt-2 space-y-1 break-all text-sm text-muted-foreground">
                    {warnings.map((w, i) => (
                      <li key={i}>
                        <code className="font-mono text-foreground">{w.path}</code>: {w.reason}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {children}
          </main>
          <footer className="flex flex-wrap justify-between gap-3 border-t border-border px-5 py-4 text-xs text-muted-foreground md:px-8">
            <span>QuantumTrace · Discover today. Secure tomorrow.</span>
            <span>Evidence reflects the supplied inputs</span>
          </footer>
        </div>

        <ScanDialog open={scanOpen} onOpenChange={setScanOpen} onComplete={() => {}} />
        <HelpDialog open={helpOpen} onOpenChange={setHelpOpen} />
      </div>
    </OpenScan.Provider>
  );
}

/** Empty state shown on report pages when nothing is loaded. */
export function EmptyReport() {
  const data = useReport();
  const openScan = useContext(OpenScan);
  return (
    <section className="mx-auto max-w-xl py-24 text-center">
      <h1 className="text-4xl">No scan results available</h1>
      <p className="mt-3 text-muted-foreground">
        Upload files or analyze the reference dataset to discover your cryptographic exposure.
      </p>
      <div className="mt-8 flex flex-wrap justify-center gap-3">
        <button className="btn-primary" disabled={data.busy} onClick={openScan}>
          <Radar className="h-4 w-4" />
          Upload files
        </button>
        <button className="btn-ghost" disabled={data.busy} onClick={() => void data.scan([], true)}>
          Analyze reference dataset
        </button>
        <button className="btn-ghost" disabled={data.busy} onClick={() => void data.reload()}>
          Load saved scan results
        </button>
      </div>
    </section>
  );
}

/** Renders a report page, or the loading / empty state while there is no report. */
export function WithReport({ children }: { children: (report: Report) => ReactNode }) {
  const { report, busy } = useReport();
  if (report) return <>{children(report)}</>;
  if (busy) return <p className="py-24 text-center text-muted-foreground">Loading scan results…</p>;
  return <EmptyReport />;
}
