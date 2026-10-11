import { fireEvent, render, screen, waitFor, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportProvider, useReport } from "@/lib/report-context";
import demo from "../../public/demo-report.json";

function View() {
  const state = useReport();
  return (
    <>
      <span>{state.report?.origin ?? "empty"}</span>
      {state.error && <p role="alert">{state.error}</p>}
      <button disabled={state.busy} onClick={() => void state.demo()}>
        Demo
      </button>
      <button disabled={state.busy} onClick={() => void state.reload()}>
        Reload
      </button>
    </>
  );
}
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
describe("report lifecycle", () => {
  it("keeps an empty workspace empty until demo is explicitly requested", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => null })
      .mockResolvedValueOnce({ ok: true, json: async () => demo });
    vi.stubGlobal("fetch", fetch);
    render(
      <ReportProvider>
        <View />
      </ReportProvider>,
    );
    await waitFor(() => expect(screen.getByText("Demo")).not.toBeDisabled());
    expect(screen.getByText("empty")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("Demo"));
    await screen.findByText("sample");
  });
  it("preserves the existing report and displays reload failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce({ ok: true, json: async () => demo })
        .mockResolvedValueOnce({
          ok: false,
          json: async () => ({ error: "Saved results unavailable" }),
        }),
    );
    render(
      <ReportProvider>
        <View />
      </ReportProvider>,
    );
    await screen.findByText("sample");
    await waitFor(() => expect(screen.getByText("Reload")).not.toBeDisabled());
    fireEvent.click(screen.getByText("Reload"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Saved results unavailable");
    expect(screen.getByText("sample")).toBeInTheDocument();
  });
});
