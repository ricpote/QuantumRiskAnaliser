# QuantumTrace UI contract

The Python Finding and summary schemas are authoritative. Frontend adapters format
fields; they do not calculate risk, readiness scores or migration priorities.
Inventory rows are findings; dashboard asset counts come from the backend summary.
Sample provenance remains visible in every route and JSON/CSV export.

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Select/Listbox | Workspace native select | UX contract | OS popup geometry accepted; labelled keyboard controls | browser filters |
| Form | Workspace scan dialog | Python API contract | label, bounded files, disabled duplicate submission | upload integration tests |
| Scrollbar | src/styles.css | DESIGN.md | global visible scrollbar; stable gutter | computed browser styles |
| Navigation | Workspace + shared Sheet | UX contract | four router links; mobile dialog restores focus | browser keyboard |
| Dialog | src/components/ui/dialog.tsx | UX contract | Radix focus trap, Escape, restore focus | browser evidence dialog |
| Data loading | ReportProvider | Python report | same report across routes; explicit reload; preserve report on failure | provider tests |
| Feedback | Workspace alerts | UX contract | persistent textual errors and loading status | provider tests |

No automatic transition to sample data after a failure. The user chooses bundled
demo or scans the official samples explicitly. Uploaded scan results live in memory
until replaced or the service restarts; the user can download them. CLI results
are read from a configured directory only. The browser cannot select arbitrary
server paths or network targets. Live probes continue to use the CLI.

Search/filtering is local to the loaded snapshot; URLs do not store evidence or
asset search terms because they may expose private infrastructure names. Clear
search restores focus. Filters reset pagination. Pagination is client-side because
the API deliberately serves a complete immutable report, also used by exports.
Native selects are intentionally retained from the import; platform appearance is accepted.
