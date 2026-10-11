import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, Search, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { PageHead, Pager, RiskBadge, Segmented } from "@/components/Bits";
import {
  adaptFindings,
  filterAssets,
  riskFilters,
  sourceLabels,
  type Asset,
  type Finding,
  type Report,
} from "@/lib/quantumtrace-data";
import { classicalText, findingBadge, sourceName, tierLabel } from "@/lib/labels";

export type InventorySearch = {
  risk?: string | undefined;
  source?: string | undefined;
  tier?: string | undefined;
};
const PAGE = 25;

// Line-level fix computed by the Python scanner (ingest/code/fixes.py); the browser only shows it.
function FixSuggestion({ finding }: { finding: Finding }) {
  const raw = finding.context?.["fix"];
  if (!raw || typeof raw !== "object") return null;
  const fix = raw as {
    before?: string;
    after?: string | null;
    note?: string | null;
    requires?: string | null;
  };
  const line = finding.location["line"];
  return (
    <div className="space-y-2">
      <h3 className="text-base">
        Suggested fix{typeof line === "number" ? ` · line ${line}` : ""}
      </h3>
      {typeof fix.before === "string" && typeof fix.after === "string" && (
        <pre className="fix-diff" aria-label="Line before and after the fix">
          <span className="fix-del">- {fix.before.trim()}</span>
          <span className="fix-add">+ {fix.after.trim() || "(delete this line)"}</span>
        </pre>
      )}
      {fix.note && <p className="text-muted-foreground">{fix.note}</p>}
      {fix.requires && (
        <p className="text-muted-foreground">
          Requires: <span className="font-mono">{fix.requires}</span>
        </p>
      )}
    </div>
  );
}

export function Inventory({
  report,
  search,
  onSearch,
}: {
  report: Report;
  search: InventorySearch;
  onSearch: (next: InventorySearch) => void;
}) {
  const assets = useMemo(() => adaptFindings(report), [report]);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    setQuery("");
    setPage(0);
    setOpen(null);
  }, [report]);
  useEffect(() => setPage(0), [search.risk, search.source, search.tier]);
  const risk = search.risk ?? "All risks";
  const source = search.source
    ? (sourceLabels[search.source as keyof typeof sourceLabels] ?? search.source)
    : "All sources";
  const rows = useMemo(
    () =>
      filterAssets(
        search.tier ? assets.filter((a) => a.finding.risk_tier === search.tier) : assets,
        query,
        risk,
        source,
      ).sort((a, b) => b.finding.risk_points - a.finding.risk_points),
    [assets, query, risk, source, search.tier],
  );
  const sources = Array.from(new Set(report.findings.map((f) => f.source)));
  const shown = rows.slice(page * PAGE, (page + 1) * PAGE);
  const set = (next: InventorySearch) => onSearch({ ...search, ...next });

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <PageHead title="Crypto inventory">
        Every cryptographic asset, riskiest first. Open a row for why it is at risk and how to fix
        it.
      </PageHead>
      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label="Filter by risk"
          value={risk}
          onChange={(v) => set({ risk: v === "All risks" ? undefined : v })}
          options={["All risks", ...riskFilters].map((r) => ({ v: r, l: r }))}
        />
        <Segmented
          label="Filter by source"
          value={search.source ?? "all"}
          onChange={(v) => set({ source: v === "all" ? undefined : v })}
          options={[
            { v: "all", l: "All sources" },
            ...sources.map((s) => ({ v: s, l: sourceName[s] ?? s })),
          ]}
        />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex min-w-60 flex-1 items-center gap-2 rounded-sm border border-border px-3 py-1.5 focus-within:border-primary">
          <Search className="h-4 w-4 text-muted-foreground" aria-hidden />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            placeholder="Search assets, algorithms, or locations..."
            className="w-full bg-transparent text-sm outline-none"
            aria-label="Search assets"
          />
          {query && (
            <button
              type="button"
              aria-label="Clear search"
              className="rounded-sm p-0.5 hover:bg-accent"
              onClick={() => {
                setQuery("");
                setPage(0);
                searchRef.current?.focus();
              }}
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </label>
        <button
          type="button"
          className="btn-ghost"
          aria-label="Reset filters"
          onClick={() => {
            setQuery("");
            setPage(0);
            onSearch({});
          }}
        >
          <SlidersHorizontal className="h-4 w-4" />
          Reset filters
        </button>
      </div>
      {search.tier && (
        <p className="flex flex-wrap items-center gap-2 text-sm">
          Showing quantum tier:{" "}
          <b>{tierLabel[search.tier as keyof typeof tierLabel] ?? search.tier}</b>
          <button type="button" className="btn-link" onClick={() => set({ tier: undefined })}>
            Show every tier
          </button>
        </p>
      )}
      <p className="text-sm text-muted-foreground" aria-live="polite">
        Showing {rows.length ? page * PAGE + 1 : 0}–{Math.min(rows.length, (page + 1) * PAGE)} of{" "}
        {rows.length} findings
        {rows.length !== assets.length ? ` (filtered from ${assets.length})` : ""}
      </p>

      {rows.length === 0 ? (
        <div className="panel grid-paper py-16 text-center text-muted-foreground">
          No assets match your filters.
        </div>
      ) : (
        <ul className="panel divide-y divide-border" aria-label="Cryptographic findings">
          {shown.map((a) => (
            <Row
              key={a.id}
              a={a}
              open={open === a.id}
              toggle={() => setOpen(open === a.id ? null : a.id)}
            />
          ))}
        </ul>
      )}
      <Pager page={page} pages={Math.ceil(rows.length / PAGE)} onPage={setPage} />
    </div>
  );
}

function Row({ a, open, toggle }: { a: Asset; open: boolean; toggle: () => void }) {
  const f = a.finding;
  return (
    <li>
      <button
        onClick={toggle}
        aria-expanded={open}
        className="grid w-full grid-cols-[1fr_auto] items-center gap-4 px-4 py-3 text-left transition hover:bg-accent md:grid-cols-[1.4fr_1fr_11rem_5rem_1.5rem]"
      >
        <span className="min-w-0">
          <span className="block truncate font-semibold">
            {a.algorithm}{" "}
            <span className="font-normal text-muted-foreground">
              {a.keySize !== "—" ? a.keySize : ""}
            </span>
          </span>
          <span className="block truncate text-sm text-muted-foreground">{a.name}</span>
          <span className="block truncate font-mono text-xs text-muted-foreground">
            {a.location}
          </span>
        </span>
        <span className="hidden truncate text-sm text-muted-foreground md:block">
          {a.source}, {f.category}
        </span>
        <span className="hidden md:block">
          <RiskBadge finding={f} />
        </span>
        <span className="hidden text-right text-sm tabular-nums md:block">
          {f.risk_points}
          <span className="text-muted-foreground"> pts</span>
        </span>
        <ChevronDown
          className={`h-4 w-4 text-muted-foreground transition ${open ? "rotate-180" : ""}`}
          aria-hidden
        />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <Details a={a} />
          </motion.div>
        )}
      </AnimatePresence>
    </li>
  );
}

function Details({ a }: { a: Asset }) {
  const f = a.finding;
  const badge = findingBadge(f);
  const snippet = f.location["snippet"];
  return (
    <div className="grid grid-cols-1 gap-6 border-t border-border bg-background/40 px-4 py-5 md:grid-cols-2">
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap items-center gap-3">
          <RiskBadge finding={f} />
          <span>{badge.meaning}</span>
        </div>
        <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1">
          <dt className="text-muted-foreground">Algorithm</dt>
          <dd className="font-mono">
            {a.algorithm} · {a.keySize}
          </dd>
          <dt className="text-muted-foreground">Discovery source</dt>
          <dd>{a.source}</dd>
          <dt className="text-muted-foreground">Problem even without quantum?</dt>
          <dd>{classicalText[f.classical_status] ?? f.classical_status}</dd>
          <dt className="text-muted-foreground">Risk points (0-100)</dt>
          <dd>
            {f.risk_points}
            {f.hndl ? " · recordable now, readable later" : ""}
          </dd>
          <dt className="text-muted-foreground">Where</dt>
          <dd className="break-all font-mono text-xs">{a.location}</dd>
          {f.deadline_year ? (
            <>
              <dt className="text-muted-foreground">Earliest deadline</dt>
              <dd>{f.deadline_year}</dd>
            </>
          ) : null}
        </dl>
        <div>
          <h3 className="text-base">Evidence</h3>
          <p className="mt-1 break-words font-mono text-xs leading-relaxed text-muted-foreground">
            {a.evidence}
          </p>
          {typeof snippet === "string" && (
            <pre className="mt-2 overflow-x-auto rounded-sm bg-background p-2 font-mono text-xs">
              {snippet}
            </pre>
          )}
        </div>
        {!!f.rationale.length && (
          <div>
            <h3 className="text-base">Why</h3>
            <ul className="mt-1 list-disc space-y-1 pl-5">
              {f.rationale.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <div className="space-y-4 text-sm">
        <div className="panel p-3">
          <p className="text-muted-foreground">Suggested next step</p>
          {f.replacement ? (
            <>
              <p className="font-display text-xl font-semibold text-safe">
                {f.replacement.algorithm}{" "}
                {f.replacement.standard && (
                  <span className="text-sm font-normal text-muted-foreground">
                    ({f.replacement.standard})
                  </span>
                )}
              </p>
              {f.replacement.how && <p className="mt-1">{f.replacement.how}</p>}
            </>
          ) : (
            <p className="mt-1">{a.replacement}</p>
          )}
        </div>
        <FixSuggestion finding={f} />
        {!!f.deadlines?.length && (
          <div>
            <h3 className="text-base">
              Deadlines{f.deadline_year ? ` · earliest binding: ${f.deadline_year}` : ""}
            </h3>
            <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
              {f.deadlines.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </div>
        )}
        {(!!f.cwe?.length || !!f.flags.length) && (
          <p className="text-xs text-muted-foreground">
            {[...(f.cwe ?? []), ...f.flags].join(" · ")}
          </p>
        )}
      </div>
    </div>
  );
}
