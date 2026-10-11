import { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ScanDialog } from "@/components/quantumtrace/scan-dialog";
import { ReportProvider, useReport } from "@/lib/report-context";
import demo from "./fixtures/scanner-report.json";

function Workspace() {
  const [open, setOpen] = useState(true);
  const { report } = useReport();
  return (
    <>
      <output data-testid="origin">{report?.origin}</output>
      <ScanDialog open={open} onOpenChange={setOpen} onComplete={() => {}} />
    </>
  );
}
const response = (value: unknown) => ({ ok: true, json: async () => value });
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("lists valid files, excludes invalid content, sends bytes and updates the report", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(response(demo))
    .mockResolvedValueOnce(response({ state: "running" }))
    .mockResolvedValueOnce(response({ state: "running", phase: "analyzing" }))
    .mockResolvedValueOnce(response({ state: "complete" }))
    .mockResolvedValueOnce(response({ ...demo, origin: "upload" }));
  vi.stubGlobal("fetch", fetch);
  render(
    <ReportProvider>
      <Workspace />
    </ReportProvider>,
  );
  expect(screen.getByRole("button", { name: "Analyze files" })).toBeDisabled();
  const source = 'import hashlib\nhashlib.md5(b"x")';
  fireEvent.change(screen.getByLabelText("Choose files to analyze"), {
    target: { files: [new File([source], "scan.py"), new File(["fake"], "bad.pcap")] },
  });
  await screen.findByText("Not a valid PCAP/PCAPNG capture header.");
  expect(screen.getByText("scan.py")).toBeInTheDocument();
  expect(screen.getByText(/32 B · Ready/)).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole("button", { name: "Analyze files" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Analyze files" }));
  await screen.findByText("Analyzing with the Python scanner…");
  await waitFor(() => expect(screen.getByTestId("origin")).toHaveTextContent("upload"));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  const sent = JSON.parse(fetch.mock.calls[1]![1]!.body);
  expect(sent.files).toEqual([{ name: "scan.py", content: btoa(source) }]);
});

it("keeps the dialog and previous results after a failed scan, then allows retry", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(response(demo))
      .mockResolvedValueOnce(response({ state: "running" }))
      .mockResolvedValueOnce(
        response({ state: "error", error: "invalid Python syntax at line 1" }),
      ),
  );
  render(
    <ReportProvider>
      <Workspace />
    </ReportProvider>,
  );
  fireEvent.change(screen.getByLabelText("Choose files to analyze"), {
    target: { files: [new File(["def broken("], "broken.py")] },
  });
  await waitFor(() => expect(screen.getByRole("button", { name: "Analyze files" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Analyze files" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("previous results have been kept");
  expect(screen.getByTestId("origin")).toHaveTextContent("sample");
  expect(screen.getByRole("button", { name: "Analyze files" })).toBeEnabled();
  fireEvent.click(screen.getByRole("button", { name: "Remove broken.py" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Analyze files" })).toBeDisabled());
});
