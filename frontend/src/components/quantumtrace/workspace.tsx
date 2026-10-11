import { useState, useRef } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  BadgeCheck,
  Box,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  FileText,
  Globe,
  Layers,
  LayoutDashboard,
  Lightbulb,
  Menu,
  Plus,
  Radar,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import {
  adaptFindings,
  filterAssets,
  downloadReport,
  type Asset,
  type Risk,
} from "@/lib/quantumtrace-data";

import { ScanDialog } from "./scan-dialog";
import { useReport } from "@/lib/report-context";
import { Overview, Migration, Reports } from "./report-panels";
import { AccuracyPanel, ExplainPanel, ProbePanel } from "./analysis-panels";
import { classicalText, tierMeaning } from "@/lib/labels";

type View = "overview" | "inventory" | "migration" | "reports" | "probe" | "accuracy" | "explain";
const nav = [
  { view: "overview", label: "Overview", icon: LayoutDashboard, to: "/" },
  { view: "inventory", label: "Crypto inventory", icon: Layers, to: "/inventory" },
  { view: "migration", label: "Migration plan", icon: ShieldCheck, to: "/migration" },
  { view: "probe", label: "Live probe", icon: Radar, to: "/probe" },
  { view: "accuracy", label: "Accuracy", icon: BadgeCheck, to: "/accuracy" },
  { view: "explain", label: "Explain", icon: Lightbulb, to: "/explain" },
  { view: "reports", label: "Reports", icon: FileText, to: "/reports" },
] as const;
// Pages about the loaded report; probe, accuracy and explain are tools that work without one.
const reportViews: readonly View[] = ["overview", "inventory", "migration", "reports"];
const riskClass = (risk: Risk) =>
  risk === "Critical" || risk === "Unencrypted"
    ? "risk-critical"
    : risk === "Medium"
      ? "risk-medium"
      : "risk-safe";
const sourceIcon = { Network: Globe, Code: Code2, Cloud: Box, Probe: Activity };
export function QuantumMark() {
  return (
    <svg viewBox="0 0 32 32" fill="none" className="brand-symbol" aria-hidden="true">
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
function Badge({ risk }: { risk: Risk }) {
  return (
    <span className={`risk-badge ${riskClass(risk)}`}>
      {risk === "Resilient" ? "Quantum-resilient" : risk}
    </span>
  );
}
export function Workspace({ view }: { view: View }) {
  const [menu, setMenu] = useState(false);
  const [scan, setScan] = useState(false);
  const [help, setHelp] = useState(false);
  const [notification, setNotification] = useState(false);
  const data = useReport();
  const { report, busy, error } = data;
  const assets = report ? adaptFindings(report) : [];
  const [page, setPage] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const label =
    report?.origin === "sample"
      ? "Demo · sample data"
      : report?.origin === "upload"
        ? "Uploaded scan results"
        : report
          ? "Loaded CLI results"
          : "No results loaded";
  const generated = report
    ? new Date(report.generated_at).toLocaleString("en-GB", { timeZone: "UTC" }) + " UTC"
    : "";
  const [selected, setSelected] = useState<Asset | null>(null);
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState("All risks");
  const [source, setSource] = useState("All sources");
  const filtered = filterAssets(assets, query, risk, source);
  const title = nav.find((n) => n.view === view)?.label ?? "Overview";
  const reportView = reportViews.includes(view);
  const menuRef = useRef<HTMLButtonElement>(null);
  const navigation = (
    <>
      <Link to="/" className="flex items-center gap-2.5 px-2">
        <QuantumMark />
        <span className="text-[19px] font-semibold">
          QuantumTrace<span className="text-khaki">.</span>
        </span>
      </Link>
      <div className="mt-10 px-3 text-[10px] font-medium uppercase text-sidebar-muted">
        Workspace
      </div>
      <nav className="mt-3 space-y-1.5">
        {nav.map((n) => (
          <Link
            to={n.to}
            onClick={() => setMenu(false)}
            className={buttonVariants({ variant: "ghost", className: "nav-item" })}
            data-active={view === n.view}
            key={n.view}
          >
            <n.icon />
            <span>{n.label}</span>
            {n.view === "inventory" && (
              <span className="ml-auto text-[10px] text-sidebar-muted">
                {report?.summary.assets ?? 0}
              </span>
            )}
          </Link>
        ))}
      </nav>
      <div className="mt-9 border-t border-sidebar-accent pt-6 px-3">
        <p className="text-[10px] uppercase text-sidebar-muted">Supported sources</p>
        <div className="mt-5 space-y-5 text-xs text-sidebar-muted">
          {(["Network", "Code", "Cloud"] as const).map((s) => {
            const Icon = sourceIcon[s];
            return (
              <div key={s} className="flex items-center gap-3">
                <Icon size={15} />
                {s === "Code"
                  ? "Source code"
                  : s === "Cloud"
                    ? "Cloud infrastructure"
                    : "Network traffic"}
              </div>
            );
          })}
        </div>
        <p className="mt-4 text-[10px] text-sidebar-muted">{label}</p>
      </div>
      <div className="mt-auto">
        <div className="mx-2 mb-6 border border-sidebar-accent rounded-md p-4">
          <Shield size={20} className="text-khaki" />
          <p className="mt-3 text-xs font-medium">
            Discover today.
            <br />
            Secure tomorrow.
          </p>
          <p className="mt-2 text-[10px] leading-relaxed text-sidebar-muted">
            Your post-quantum transition
            <br />
            starts with visibility.
          </p>
        </div>
        <Button variant="ghost" className="nav-item" onClick={() => setHelp(true)}>
          <CircleHelp />
          Help & resources
          <ArrowRight className="ml-auto" />
        </Button>
        <div className="mt-5 border-t border-sidebar-accent pt-5 flex gap-3 px-3 items-center">
          <span className="bg-sidebar-accent text-khaki w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium">
            QT
          </span>
          <div>
            <p className="text-xs">Scan workspace</p>
            <p className="text-[10px] text-sidebar-muted mt-1">{label}</p>
          </div>
          <ChevronDown size={13} className="ml-auto text-sidebar-muted" />
        </div>
      </div>
    </>
  );
  return (
    <div className="workspace">
      <aside className="side-nav desktop-nav">{navigation}</aside>
      <Sheet open={menu} onOpenChange={setMenu}>
        <SheetContent
          side="left"
          className="sheet-navigation"
          onCloseAutoFocus={(e) => {
            e.preventDefault();
            menuRef.current?.focus();
          }}
        >
          <SheetTitle className="sr-only">Workspace navigation</SheetTitle>
          <SheetDescription className="sr-only">Navigate QuantumTrace reports</SheetDescription>
          {navigation}
        </SheetContent>
      </Sheet>

      <div className="workspace-main">
        <header className="topbar">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              className="mobile-menu"
              ref={menuRef}
              aria-label="Open navigation"
              onClick={() => setMenu(!menu)}
            >
              <Menu />
            </Button>
            <span className="text-xs text-muted-foreground">Workspace</span>
            <ChevronRight size={13} className="text-muted-foreground" />
            <span className="text-xs font-medium">{title}</span>
          </div>
          <div className="flex items-center gap-5">
            <span className="hidden sm:flex items-center gap-2 text-[11px] text-muted-foreground">
              <span className="w-1.5 h-1.5 bg-safe rounded-full" />
              {label}
            </span>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Report status"
              onClick={() => setNotification(true)}
            >
              <Activity size={17} />
            </Button>
          </div>
        </header>
        <main className="page-content">
          <div className="flex flex-wrap gap-5 items-end justify-between mb-7">
            <div>
              <p className="text-[10px] uppercase text-muted-foreground mb-2">
                Cryptographic posture
              </p>
              <h1 className="text-[30px] font-semibold leading-tight">
                {view === "overview" ? "Your quantum readiness, at a glance." : title}
              </h1>
              <p className="mt-2 text-sm text-muted-foreground">
                {view === "overview"
                  ? "Discover your cryptographic footprint. Prioritize what matters."
                  : view === "inventory"
                    ? "Every cryptographic asset. One clear view."
                    : view === "migration"
                      ? "A practical path from discovery to quantum resilience."
                      : view === "probe"
                        ? "Does a live server already protect its traffic against quantum computers?"
                        : view === "accuracy"
                          ? "Every result checked against the labelled answers for the challenge data."
                          : view === "explain"
                            ? "How QuantumTrace rates any algorithm, and why."
                            : "Your cryptographic findings, ready to share."}
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                disabled={!report}
                onClick={() => report && downloadReport(report, "json")}
              >
                <ArrowDownToLine />
                Export report
              </Button>
              <Button disabled={data.scanning} onClick={() => setScan(true)}>
                <Plus />
                New scan
              </Button>
            </div>
          </div>
          {reportView && (
            <div className="flex flex-wrap items-center gap-3 mb-6">
              <span className="risk-badge risk-medium">{label}</span>
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() => void data.reload()}
              >
                Reload CLI results
              </Button>
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => void data.demo()}>
                Use bundled demo
              </Button>
              <span className="text-xs text-muted-foreground">{generated}</span>
            </div>
          )}
          {reportView && busy && (
            <p role="status" className="panel p-5 mb-5">
              Loading or scanning inputs… Existing results remain visible until this finishes.
            </p>
          )}
          {reportView && error && (
            <div role="alert" className="panel p-5 mb-5 text-critical">
              {error}
              <p className="text-xs mt-2">
                Check the inputs or backend service, then retry. You can also use the explicitly
                labelled bundled demo.
              </p>
            </div>
          )}
          {reportView && !report && !busy && (
            <div className="panel p-8 mb-5">
              <h2 className="font-semibold">Start with a scan or saved results</h2>
              <p className="mt-2 text-sm">
                Upload captures, source files, AWS JSON exports or a ZIP using New scan. Reload CLI
                results after running qtrace scan with the configured output directory.
              </p>
            </div>
          )}
          {reportView && !!report?.summary.warnings.length && (
            <details className="panel p-4 mb-5">
              <summary>
                {report.summary.warnings.length} scanner warnings — coverage may be incomplete
              </summary>
              <ul className="text-xs mt-3 space-y-2 break-all">
                {report.summary.warnings.map((w, i) => (
                  <li key={i}>
                    {w.path}: {w.reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {view === "overview" && report && <Overview report={report} />}
          {report && (view === "overview" || view === "inventory") && (
            <section className="panel overflow-hidden">
              <div className="px-6 py-5 flex flex-wrap gap-3 justify-between items-center">
                <div className="flex items-center gap-3">
                  <h2 className="text-sm font-semibold">
                    {view === "overview" ? "Cryptographic inventory" : "Cryptographic findings"}
                  </h2>
                  <span className="text-[10px] bg-muted rounded px-2 py-1 text-muted-foreground">
                    {assets.length} findings
                  </span>
                </div>
                {view === "overview" && (
                  <Link
                    to="/inventory"
                    className={buttonVariants({ variant: "ghost", size: "sm" })}
                  >
                    View all findings
                    <ArrowRight />
                  </Link>
                )}
              </div>
              <div className="px-6 pb-5 flex flex-wrap gap-3">
                <div className="relative flex-1 min-w-40">
                  <Search size={14} className="absolute top-3 left-3 text-muted-foreground" />
                  <input
                    aria-label="Search assets"
                    placeholder="Search assets, algorithms, or locations..."
                    ref={searchRef}
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setPage(0);
                    }}
                    className="h-9 w-full border rounded-md bg-background pl-9 pr-9 text-xs outline-none focus:ring-1 focus:ring-ring"
                  />
                  {query && (
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="Clear search"
                      className="absolute right-0 top-0 h-9 w-9"
                      onClick={() => {
                        setQuery("");
                        setPage(0);
                        searchRef.current?.focus();
                      }}
                    >
                      <X size={14} />
                    </Button>
                  )}
                </div>
                <select
                  aria-label="Filter by risk"
                  value={risk}
                  onChange={(e) => {
                    setRisk(e.target.value);
                    setPage(0);
                  }}
                  className="border bg-background rounded-md text-xs px-3 h-9"
                >
                  {["All risks", "Critical", "Medium", "Resilient", "Unencrypted"].map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
                <select
                  aria-label="Filter by source"
                  value={source}
                  onChange={(e) => {
                    setSource(e.target.value);
                    setPage(0);
                  }}
                  className="border bg-background rounded-md text-xs px-3 h-9"
                >
                  {["All sources", "Network", "Code", "Cloud", "Probe"].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="Reset filters"
                  title="Reset filters"
                  onClick={() => {
                    setQuery("");
                    setRisk("All risks");
                    setSource("All sources");
                    setPage(0);
                  }}
                >
                  <SlidersHorizontal />
                </Button>
              </div>
              <div className="overflow-x-auto">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>Asset / location</th>
                      <th>Algorithm</th>
                      <th>Key size</th>
                      <th>Source</th>
                      <th>Quantum risk</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {filtered
                      .slice(
                        view === "overview" ? 0 : page * 25,
                        view === "overview" ? 5 : (page + 1) * 25,
                      )
                      .map((a) => {
                        const Icon = sourceIcon[a.source];
                        return (
                          <tr key={a.id}>
                            <td>
                              <Button
                                variant="link"
                                className="p-0 h-auto text-xs text-foreground"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelected(a);
                                }}
                              >
                                {a.name}
                              </Button>
                              <p className="font-mono text-[10px] text-muted-foreground mt-1.5">
                                {a.location}
                              </p>
                            </td>
                            <td>
                              <span className="font-mono bg-muted px-2 py-1 rounded text-[11px]">
                                {a.algorithm}
                              </span>
                            </td>
                            <td className="font-mono text-muted-foreground text-[11px]">
                              {a.keySize}
                            </td>
                            <td>
                              <span className="flex gap-2 items-center text-muted-foreground">
                                <Icon size={13} />
                                {a.source}
                              </span>
                            </td>
                            <td>
                              <Badge risk={a.risk} />
                            </td>
                            <td>
                              <ChevronRight size={14} className="text-muted-foreground" />
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
                {filtered.length === 0 && (
                  <p className="p-10 text-sm text-center text-muted-foreground">
                    No assets match your filters.
                  </p>
                )}
              </div>
              <div className="px-6 py-4 border-t flex justify-between text-[10px] text-muted-foreground">
                <span>
                  Showing {Math.min(filtered.length, view === "overview" ? 5 : (page + 1) * 25)} of{" "}
                  {filtered.length} findings
                </span>
                <span>{generated}</span>
              </div>
            </section>
          )}
          {view === "inventory" && report && (
            <div className="flex justify-end items-center gap-3 mt-4">
              <Button variant="outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <span className="text-xs">Page {page + 1}</span>
              <Button
                variant="outline"
                disabled={(page + 1) * 25 >= filtered.length}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          )}
          {view === "migration" && report && <Migration report={report} />}
          {view === "reports" && report && <Reports report={report} />}
          {view === "probe" && <ProbePanel />}
          {view === "accuracy" && <AccuracyPanel />}
          {view === "explain" && <ExplainPanel />}
          <footer className="flex flex-wrap gap-3 justify-between mt-6 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={12} />
              QuantumTrace · Discover today. Secure tomorrow.
            </span>
            <span>{label} · Evidence reflects the supplied inputs</span>
          </footer>
        </main>
      </div>
      <Dialog
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="max-h-[85vh] overflow-y-auto">
          {selected && (
            <>
              <DialogTitle>{selected.name}</DialogTitle>
              <DialogDescription>{selected.location}</DialogDescription>
              <div className="flex flex-wrap items-center gap-3">
                <Badge risk={selected.risk} />
                <span className="text-xs">{tierMeaning[selected.finding.risk_tier]}</span>
              </div>
              <dl className="grid grid-cols-2 text-sm gap-5 py-3">
                <div>
                  <dt className="text-xs text-muted-foreground mb-2">Algorithm</dt>
                  <dd className="font-mono">
                    {selected.algorithm} · {selected.keySize}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground mb-2">Discovery source</dt>
                  <dd>{selected.source}</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground mb-2">
                    Problem even without quantum?
                  </dt>
                  <dd>
                    {classicalText[selected.finding.classical_status] ??
                      selected.finding.classical_status}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground mb-2">Risk points (0-100)</dt>
                  <dd>
                    {selected.finding.risk_points}
                    {selected.finding.hndl ? " · recordable now, readable later" : ""}
                  </dd>
                </div>
              </dl>
              <div className="border-t pt-4">
                <h3 className="text-sm font-semibold mb-2">Evidence</h3>
                <p className="text-xs font-mono leading-relaxed text-muted-foreground">
                  {selected.evidence}
                </p>
                {typeof selected.finding.location["snippet"] === "string" && (
                  <pre className="mt-3 bg-muted p-3 rounded text-[11px] overflow-x-auto">
                    {selected.finding.location["snippet"]}
                  </pre>
                )}
              </div>
              {!!selected.finding.rationale.length && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">Why</h3>
                  <ul className="list-disc pl-5 space-y-1 text-xs">
                    {selected.finding.rationale.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="bg-secondary p-4 rounded-md">
                <h3 className="text-sm font-semibold">Suggested next step</h3>
                {selected.finding.replacement ? (
                  <>
                    <p className="text-sm mt-2">
                      {selected.finding.replacement.algorithm}
                      {selected.finding.replacement.standard
                        ? ` (${selected.finding.replacement.standard})`
                        : ""}
                    </p>
                    {selected.finding.replacement.how && (
                      <p className="text-xs mt-1 text-muted-foreground">
                        {selected.finding.replacement.how}
                      </p>
                    )}
                  </>
                ) : (
                  <p className="text-sm mt-2">{selected.replacement}</p>
                )}
              </div>
              {!!selected.finding.deadlines?.length && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">
                    Deadlines
                    {selected.finding.deadline_year
                      ? ` · earliest binding: ${selected.finding.deadline_year}`
                      : ""}
                  </h3>
                  <ul className="list-disc pl-5 space-y-1 text-xs text-muted-foreground">
                    {selected.finding.deadlines.map((d) => (
                      <li key={d}>{d}</li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="text-[10px] text-muted-foreground">
                {label}
                {selected.finding.cwe?.length ? ` · ${selected.finding.cwe.join(", ")}` : ""}
                {selected.finding.flags.length ? ` · ${selected.finding.flags.join(", ")}` : ""}
              </p>
            </>
          )}
        </DialogContent>
      </Dialog>
      <ScanDialog
        open={scan}
        onOpenChange={setScan}
        onComplete={() => {
          setPage(0);
          setQuery("");
          setRisk("All risks");
          setSource("All sources");
          setSelected(null);
        }}
      />
      <Dialog open={help} onOpenChange={setHelp}>
        <DialogContent>
          <DialogTitle>Help & resources</DialogTitle>
          <DialogDescription>QuantumTrace · Post-quantum readiness</DialogDescription>
          <p className="text-sm leading-relaxed">
            Review cryptographic evidence, assess exposure, and validate replacements against your
            environment before migrating.
          </p>
          <a
            className={buttonVariants({ variant: "outline" })}
            href="https://csrc.nist.gov/projects/post-quantum-cryptography"
            target="_blank"
            rel="noreferrer"
          >
            NIST post-quantum standards
            <ArrowRight />
          </a>
        </DialogContent>
      </Dialog>
      <Dialog open={notification} onOpenChange={setNotification}>
        <DialogContent>
          <DialogTitle>Report status</DialogTitle>
          <DialogDescription>Current report status</DialogDescription>
          <div className="flex gap-3 py-4">
            <CheckCheck size={20} className="text-safe" />
            <div>
              <p className="text-sm font-medium">
                {busy ? "Scan in progress" : error ? "Attention required" : "Report status"}
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                {error ?? `${report?.summary.assets ?? 0} assets. ${label}.`}
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
