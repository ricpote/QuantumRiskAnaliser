import { Link } from "@tanstack/react-router";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Notice, PageHead } from "@/components/Bits";
import { apiRequest, errorText, type AssumptionRow, type Assumptions } from "@/lib/api";

// The numbers and their sources live in the Python knowledge base (kb/mosca.py); this page only lays them out.

const scenarioName: Record<string, string> = {
  pessimistic: "Early",
  default: "Expected",
  optimistic: "Late",
};
const basisText: Record<AssumptionRow["basis"], string> = {
  stated: "Stated by the source",
  derived: "Derived from the source's numbers",
  estimate: "Estimate within the sources' bounds",
};

function Refs({ ids, number }: { ids: string[]; number: Map<string, number> }) {
  return (
    <span className="flex flex-wrap gap-1">
      {ids.map((id) => (
        <a
          key={id}
          href={`#src-${id}`}
          className="rounded-sm border border-border px-1.5 text-xs tabular-nums hover:border-primary hover:bg-accent"
          aria-label={`Source ${number.get(id)}`}
        >
          [{number.get(id)}]
        </a>
      ))}
    </span>
  );
}

function Table({
  id,
  title,
  intro,
  head,
  children,
}: {
  id: string;
  title: string;
  intro: ReactNode;
  head: string[];
  children: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="space-y-3">
      <h2 id={id} className="text-3xl">
        {title}
      </h2>
      <p className="max-w-3xl text-muted-foreground">{intro}</p>
      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[44rem] text-left text-sm">
          <thead className="text-muted-foreground">
            <tr className="border-b border-border">
              {head.map((h) => (
                <th key={h} className="px-4 py-2 font-normal">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border align-top">{children}</tbody>
        </table>
      </div>
    </section>
  );
}

function Rows({ rows, number }: { rows: AssumptionRow[]; number: Map<string, number> }) {
  return rows.map((r) => (
    <tr key={r.label}>
      <td className="px-4 py-3 font-semibold">{r.label}</td>
      <td className="px-4 py-3 font-display text-xl tabular-nums">
        {r.years}
        <span className="text-sm text-muted-foreground"> {r.years === 1 ? "yr" : "yrs"}</span>
      </td>
      <td className="px-4 py-3">{r.why}</td>
      <td className="px-4 py-3 text-muted-foreground">{basisText[r.basis]}</td>
      <td className="px-4 py-3">
        <Refs ids={r.sources} number={number} />
      </td>
    </tr>
  ));
}

export function MoscaSources() {
  const [data, setData] = useState<Assumptions | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiRequest<Assumptions>("/api/assumptions")
      .then(setData)
      .catch((e) => setError(errorText(e)));
  }, []);
  const number = useMemo(
    () => new Map((data?.sources ?? []).map((s, i) => [s.id, i + 1] as const)),
    [data],
  );
  const nist = number.get("nist-ir8547");
  return (
    <div className="mx-auto max-w-6xl space-y-14">
      <PageHead
        title="Sources for the migration timeline"
        aside={
          <Link to="/migration" className="btn-ghost">
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Migration plan
          </Link>
        }
      >
        Mosca's rule flags a system when X + Y &gt; Z. Every value below is an explicit default with
        its reason and its sources; an organisation tunes them to its own retention duties.
      </PageHead>
      {error && <Notice tone="critical">{error}</Notice>}
      {!data && !error && <p className="text-muted-foreground">Loading the assumptions…</p>}
      {data && (
        <>
          <Table
            id="z"
            title="Z · When Q-Day comes"
            intro="The year a quantum computer can break today's public-key cryptography. You can also type any year on the migration plan."
            head={["Scenario", "Year", "Why", "Sources"]}
          >
            {data.qday.map((q) => (
              <tr key={q.scenario}>
                <td className="px-4 py-3 font-semibold">
                  {scenarioName[q.scenario] ?? q.scenario}
                </td>
                <td className="px-4 py-3 font-display text-xl tabular-nums">{q.year}</td>
                <td className="px-4 py-3">{q.why}</td>
                <td className="px-4 py-3">
                  <Refs ids={q.sources} number={number} />
                </td>
              </tr>
            ))}
          </Table>
          <Table
            id="x"
            title="X · How long the data must stay secret"
            intro="For traffic that can be recorded today, the years its content stays sensitive; for signatures, the years they must stay trusted. The longest value that applies to a system is used."
            head={["Applies to", "X", "Why", "Basis", "Sources"]}
          >
            <Rows rows={data.shelf_life} number={number} />
          </Table>
          <Table
            id="y"
            title="Y · How long the migration takes"
            intro="The years needed to move one system to post-quantum cryptography once PQ-capable products exist."
            head={["Applies to", "Y", "Why", "Basis", "Sources"]}
          >
            <Rows rows={data.migration} number={number} />
          </Table>
          {nist && (
            <Notice>
              Y measures one system, not a whole programme: NIST notes that past cryptographic
              migrations took over a decade and that full integration can take 10 to 20 years{" "}
              {`[${nist}]`}.
            </Notice>
          )}
          <section aria-labelledby="refs" className="space-y-3">
            <h2 id="refs" className="text-3xl">
              References
            </h2>
            <ol className="panel divide-y divide-border">
              {data.sources.map((s, i) => (
                <li key={s.id} id={`src-${s.id}`} className="scroll-mt-28 px-4 py-3 text-sm">
                  <span className="mr-2 tabular-nums text-muted-foreground">[{i + 1}]</span>
                  <a
                    href={s.url}
                    target="_blank"
                    rel="noreferrer"
                    className="font-semibold underline decoration-border underline-offset-4 hover:decoration-primary"
                  >
                    {s.title}
                    <ExternalLink className="ml-1 inline h-3.5 w-3.5" aria-hidden />
                  </a>
                  <span className="text-muted-foreground">
                    {" "}
                    · {s.publisher}, {s.date} · {s.primary ? "primary source" : "secondary summary"}
                  </span>
                  <p className="mt-1 text-muted-foreground">{s.says}</p>
                </li>
              ))}
            </ol>
          </section>
        </>
      )}
    </div>
  );
}
