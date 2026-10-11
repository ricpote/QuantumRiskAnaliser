import { motion } from "framer-motion";
import { ChevronDown, Download, Radar } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Fact, Notice, PageHead, RiskBadge } from "@/components/Bits";
import { apiRequest, errorText, type ProbeJob, type ProbeReport } from "@/lib/api";
import { saveDownload, type Finding } from "@/lib/quantumtrace-data";

const LAB = ["8443", "8444", "8445", "8446", "8447", "2525", "5433"].map((p) => `127.0.0.1:${p}`);
const OLD_VERSIONS = new Set(["SSL 3.0", "TLS 1.0", "TLS 1.1"]);

async function followProbe(update: (job: ProbeJob) => void, alive: { current: boolean }) {
  while (alive.current) {
    const job = await apiRequest<ProbeJob>("/api/probe");
    if (!alive.current) return;
    update(job);
    if (job.state !== "running") return;
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

export function ProbePanel() {
  const [showExplanation, setShowExplanation] = useState(false);
  const [targets, setTargets] = useState("127.0.0.1:8443, 127.0.0.1:8446, 127.0.0.1:8445");
  const [deep, setDeep] = useState(false);
  const [job, setJob] = useState<ProbeJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    followProbe(setJob, alive).catch(() => {}); // show the last probe result, if any
    return () => {
      alive.current = false;
    };
  }, []);
  const list = targets.split(/[\s,]+/).filter(Boolean);
  async function start() {
    setError(null);
    try {
      await apiRequest("/api/probe", { targets: list, deep });
      setJob({ state: "running", error: null, result: null });
      await followProbe(setJob, alive);
    } catch (e) {
      setError(errorText(e));
    }
  }
  const running = job?.state === "running";
  const result = job?.result;
  const green = result?.reports.filter((r) => r.verdict.color === "green").length ?? 0;
  return (
    <div className="mx-auto max-w-6xl space-y-10">
      <PageHead title="Live probe">
        Does a live server already protect its traffic against quantum computers?
      </PageHead>
      <section className="panel grid-paper space-y-4 p-5">
        <form
          className="grid gap-4 md:grid-cols-[1fr_auto]"
          onSubmit={(e) => {
            e.preventDefault();
            void start();
          }}
        >
          <label className="block">
            <span className="text-sm text-muted-foreground">
              Targets: host or host:port, separated by commas or new lines (port 443 by default)
            </span>
            <textarea
              aria-label="Targets"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              rows={3}
              placeholder="example.com, 127.0.0.1:8443"
              className="field mt-1 w-full font-mono"
            />
          </label>
          <div className="flex flex-col justify-end gap-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={deep}
                onChange={(e) => setDeep(e.target.checked)}
                className="accent-[var(--primary)]"
              />
              Also test signature schemes (slower)
            </label>
            <button
              type="button"
              className="btn-ghost justify-center"
              disabled={running}
              onClick={() => setTargets(LAB.join(", "))}
            >
              Whole lab
            </button>
            <button
              type="submit"
              className="btn-primary justify-center"
              disabled={running || !list.length}
            >
              <Radar className="h-4 w-4" />
              {running
                ? "Probing…"
                : `Probe ${list.length} ${list.length === 1 ? "target" : "targets"}`}
            </button>
          </div>
        </form>
        {running && (
          <div className="relative h-0.5 overflow-hidden">
            <div className="scan-sweep absolute inset-0" />
          </div>
        )}
        <button
          type="button"
          className="btn-link text-sm"
          aria-expanded={showExplanation}
          aria-controls="probe-process-explanation"
          onClick={() => setShowExplanation((shown) => !shown)}
        >
          {showExplanation ? "Hide probe explanation" : "Understand probe process"}
          <ChevronDown
            aria-hidden
            className={`h-4 w-4 transition ${showExplanation ? "rotate-180" : ""}`}
          />
        </button>
        <div id="probe-process-explanation" hidden={!showExplanation} className="space-y-4">
          <h2 className="text-xl">Is this server's connection ready for quantum threats?</h2>
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
            Enter a server address. QuantumTrace connects to it and checks how it establishes an
            encrypted connection: does a modern client get post-quantum key exchange, or could its
            traffic be recorded today and decrypted by a future quantum computer?
          </p>
          <div className="grid grid-cols-1 gap-4 text-sm leading-relaxed md:grid-cols-3">
            <div>
              <h3 className="mb-2 text-base">1. Choose a server</h3>
              <p className="text-muted-foreground">
                An endpoint is a hostname or IP address, optionally followed by a port:{" "}
                <code>example.com:443</code> or <code>127.0.0.1:8443</code>. Separate multiple
                addresses with commas. Without a port, we use 443. Enter addresses, without{" "}
                <code>https://</code> or page paths.
              </p>
            </div>
            <div>
              <h3 className="mb-2 text-base">2. Check its encryption</h3>
              <p className="text-muted-foreground">
                The probe makes several TLS handshake attempts to check supported protocol versions,
                key-exchange methods and ciphers. It also checks which method the server actually
                chooses for a modern client. TLS 1.3 alone does not guarantee post-quantum
                protection.
              </p>
            </div>
            <div>
              <h3 className="mb-2 text-base">3. Understand the result</h3>
              <ul className="space-y-2">
                <li>
                  <span className="risk-badge risk-safe">✓ PQ-protected</span> Modern-client key
                  exchange uses a post-quantum method.
                </li>
                <li>
                  <span className="risk-badge risk-critical">✕ HNDL-exposed</span> The connection
                  uses classical key exchange: “harvest now, decrypt later” is a risk.
                </li>
                <li>
                  <span className="risk-badge risk-neutral">~ Inconclusive</span> The server could
                  not be reached or a TLS handshake could not be established.
                </li>
              </ul>
            </div>
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground">
            This tests the connection, not the whole application. A green result does not mean every
            certificate, signature or older-client connection is quantum-safe. Read the fallback and
            certificate details below. The probe does not send application content or scan server
            files.
          </p>
          <details className="text-sm leading-relaxed">
            <summary className="cursor-pointer font-semibold">
              Try the local lab · advanced checks
            </summary>
            <p className="mt-2 text-muted-foreground">
              The Docker lab provides real servers with known configurations. Use “Whole lab” to
              fill in their addresses, then click “Probe”: 8443 post-quantum, 8444 classical, 8445
              legacy, 8446 post-quantum with classical fallback, 8447 post-quantum only, 2525 SMTP
              and 5433 Postgres. These lab servers must be running; public servers need network
              access.
            </p>
            <p className="mt-2 text-muted-foreground">
              STARTTLS automatically upgrades the connection to TLS on recognized mail, FTP and
              Postgres ports. “Also test signature schemes” makes extra handshake attempts to check
              how the server can authenticate itself, including post-quantum signatures; it takes
              longer.
            </p>
          </details>
        </div>
      </section>
      {error && <Notice tone="critical">{error}</Notice>}
      {running && (
        <p role="status" className="text-muted-foreground">
          Probing… a few seconds per endpoint.
        </p>
      )}
      {job?.state === "error" && <Notice tone="critical">{job.error}</Notice>}
      {result && (
        <section className="space-y-6" aria-live="polite">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 className="text-3xl">
                <span className="text-safe">
                  {green} of {result.reports.length}
                </span>{" "}
                {result.reports.length === 1 ? "server protects" : "servers protect"} modern clients
                with post-quantum key exchange.
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {result.reports.length} endpoint(s) ·{" "}
                {new Date(result.generated_at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC
              </p>
            </div>
            <button
              className="btn-ghost"
              onClick={() =>
                saveDownload(
                  JSON.stringify(result.cbom, null, 2),
                  "probe_cbom.cdx.json",
                  "application/json",
                )
              }
            >
              <Download className="h-4 w-4" />
              Probe CBOM{result.cbom_valid ? " (valid CycloneDX 1.6)" : ""}
            </button>
          </div>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {result.reports.map((r, i) => (
              <ProbeCard
                key={r.target}
                r={r}
                i={i}
                findings={result.findings.filter((f) => f.location["probe"] === r.target)}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function ProbeCard({ r, i, findings }: { r: ProbeReport; i: number; findings: Finding[] }) {
  const tone =
    r.verdict.color === "green" ? "safe" : r.verdict.color === "red" ? "critical" : "medium";
  const text = { safe: "text-safe", critical: "text-critical", medium: "text-muted-foreground" }[
    tone
  ];
  const border = { safe: "border-safe", critical: "border-critical", medium: "border-border" }[
    tone
  ];
  const icon = tone === "safe" ? "✓" : tone === "critical" ? "✕" : "~";
  const m = r.modern;
  return (
    <motion.article
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: i * 0.1 }}
      className="panel p-5"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="font-mono text-lg">{r.target}</h3>
        <span className="text-xs text-muted-foreground">
          {r.starttls ? `STARTTLS ${r.starttls} · ` : ""}
          {r.connections ?? 0} handshakes · {r.duration_s ?? 0} s
        </span>
      </div>
      <p className={`mt-3 flex gap-2 border-l-2 pl-3 font-semibold ${border}`}>
        <span className={text} aria-hidden>
          {icon}
        </span>
        {r.verdict.text}
      </p>
      <dl className="mt-4 grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
        <Fact label="Key exchange a modern browser gets" value={m?.group_name ?? m?.alert ?? "—"} />
        <Fact
          label="Negotiated"
          value={[m?.version, m?.cipher].filter(Boolean).join(" · ") || "—"}
        />
        <Fact label="Server signature (CertificateVerify)" value={m?.cert_verify_name ?? "—"} />
      </dl>
      {!!Object.keys(r.versions).length && (
        <div className="mt-4">
          <p className="text-sm text-muted-foreground">Protocol versions</p>
          <div className="mt-1 flex flex-wrap gap-1.5" aria-label="Protocol versions">
            {Object.entries(r.versions).map(([v, ok]) => (
              <span
                key={v}
                className={`risk-badge ${!ok ? "text-muted-foreground line-through" : OLD_VERSIONS.has(v) ? "risk-medium" : v === "TLS 1.3" ? "risk-safe" : ""}`}
              >
                <span aria-hidden>{ok ? "✓" : "✕"}</span>
                {v}
                <span className="sr-only">{ok ? " supported" : " not supported"}</span>
              </span>
            ))}
          </div>
        </div>
      )}
      {!!Object.keys(r.groups).length && (
        <div className="mt-4">
          <p className="text-sm text-muted-foreground">
            Key-exchange groups (green = post-quantum)
          </p>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {Object.entries(r.groups).map(([name, g]) => (
              <span
                key={name}
                className={`risk-badge ${!g.supported ? "text-muted-foreground line-through" : g.pq ? "risk-safe" : "risk-critical"}`}
              >
                <span aria-hidden>{g.supported ? "✓" : "✕"}</span>
                {name}
                <span className="sr-only">{g.supported ? " supported" : " not supported"}</span>
              </span>
            ))}
          </div>
        </div>
      )}
      {r.interception_suspected && (
        <p className="mt-3 text-sm text-critical">✕ Possible TLS interception on the path.</p>
      )}
      {!!r.errors?.length && (
        <p className="mt-3 text-sm text-muted-foreground">{r.errors.join("; ")}</p>
      )}
      <details className="mt-4 text-sm">
        <summary className="cursor-pointer text-muted-foreground">
          Details: ciphers, certificate chain, findings
        </summary>
        <div className="mt-3 space-y-3">
          {!!r.tls13_ciphers?.length && <p>TLS 1.3: {r.tls13_ciphers.join(", ")}</p>}
          {!!r.tls12_ciphers?.length && (
            <p>
              TLS 1.2 (server preference order): {r.tls12_ciphers.map((c) => c.name).join(", ")}
            </p>
          )}
          {!!r.certs?.length && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[32rem] text-left text-xs">
                <thead className="text-muted-foreground">
                  <tr className="border-b border-border">
                    <th className="py-1 pr-2 font-normal">Subject</th>
                    <th className="pr-2 font-normal">Issuer</th>
                    <th className="pr-2 font-normal">Key</th>
                    <th className="pr-2 font-normal">Signature hash</th>
                    <th className="font-normal">Expires</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {r.certs.map((c, k) => (
                    <tr key={k}>
                      <td className="py-1 pr-2">
                        {c.subject}
                        {c.self_signed ? " (self-signed)" : ""}
                      </td>
                      <td className="pr-2">{c.issuer}</td>
                      <td className="pr-2">
                        {[c.algorithm, c.key_bits ?? c.curve].filter(Boolean).join("-")}
                      </td>
                      <td className="pr-2">{c.sig_hash}</td>
                      <td>{(c.not_after ?? "").slice(0, 10)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2">
                <RiskBadge finding={f} />
                <span className="font-mono">{f.display_name ?? f.algorithm}</span>
                <span className="text-muted-foreground">{f.evidence}</span>
              </li>
            ))}
          </ul>
        </div>
      </details>
    </motion.article>
  );
}
