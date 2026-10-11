import { useEffect, useRef, useState } from "react";
import { FileText, LoaderCircle, Upload, X } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { useReport } from "@/lib/report-context";
import {
  formatBytes,
  MAX_UPLOAD_BYTES,
  MAX_UPLOAD_FILES,
  UPLOAD_HELP,
  validateFile,
} from "@/lib/uploads";

export function ScanDialog({
  open,
  onOpenChange,
  onComplete,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onComplete: () => void;
}) {
  const data = useReport();
  const [files, setFiles] = useState<File[]>([]);
  const [errors, setErrors] = useState<(string | null)[]>([]);
  const [checking, setChecking] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const picker = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let current = true;
    setChecking(true);
    Promise.all(
      files.map((file, index) =>
        files.some((other, i) => i < index && other.name.toLowerCase() === file.name.toLowerCase())
          ? Promise.resolve("Duplicate filename. Rename this file before adding it.")
          : validateFile(file).catch(() => "File could not be read. Select it again."),
      ),
    ).then((result) => {
      if (current) {
        setErrors(result);
        setChecking(false);
      }
    });
    return () => {
      current = false;
    };
  }, [files]);
  const valid = files.filter((_, i) => errors[i] === null);
  const total = valid.reduce((sum, file) => sum + file.size, 0);
  const selectionError =
    files.length > MAX_UPLOAD_FILES
      ? "Select no more than 2,000 files."
      : total > MAX_UPLOAD_BYTES
        ? "Selected files exceed 32 MiB in total. Remove files before analyzing."
        : null;
  async function analyze(sample = false) {
    setAttempted(true);
    const success = await data.scan(sample ? [] : valid, sample);
    if (success) {
      setFiles([]);
      setAttempted(false);
      onComplete();
      onOpenChange(false);
    }
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!data.scanning) {
          onOpenChange(next);
          if (next) setAttempted(false);
        }
      }}
    >
      <DialogContent className="max-h-[90dvh] w-[calc(100%-2rem)] max-w-lg overflow-y-auto">
        <DialogTitle className="font-display text-2xl font-medium">New scan</DialogTitle>
        <DialogDescription>
          {UPLOAD_HELP} Files are checked before the existing Python scanner analyzes them.
        </DialogDescription>
        <label htmlFor="scan-files" className="text-sm font-semibold">
          Choose files to analyze
        </label>
        <input
          ref={picker}
          id="scan-files"
          type="file"
          multiple
          disabled={data.scanning}
          aria-describedby="scan-selection-help"
          className="sr-only"
          tabIndex={-1}
          onChange={(event) => {
            const added = Array.from(event.target.files ?? []);
            setChecking(true);
            setFiles((previous) => [
              ...previous,
              ...added.filter(
                (f) =>
                  !previous.some(
                    (p) =>
                      p.name === f.name && p.size === f.size && p.lastModified === f.lastModified,
                  ),
              ),
            ]);
            setAttempted(false);
            event.target.value = "";
          }}
        />
        <button
          type="button"
          disabled={data.scanning}
          onClick={() => picker.current?.click()}
          className="block w-full cursor-pointer rounded-sm border border-dashed border-input p-6 text-center transition hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span className="flex items-center justify-center gap-2">
            <Upload size={16} /> Choose files
          </span>
          <span className="mt-1 block text-sm text-muted-foreground">
            {valid.length} ready · {formatBytes(total)} / 32 MiB
          </span>
        </button>
        <p id="scan-selection-help" className="text-xs text-muted-foreground">
          You can add more files or remove individual selections. ZIP contents are validated by the
          scanner service.
        </p>
        {!!files.length && (
          <ul aria-label="Selected files" className="max-h-56 space-y-2 overflow-y-auto">
            {files.map((file, index) => (
              <li key={`${file.name}-${index}`} className="panel flex items-start gap-3 p-3">
                <FileText size={16} className="mt-1 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <p className="break-all text-sm">{file.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatBytes(file.size)} ·{" "}
                    {checking ? "Checking…" : errors[index] ? "Not included" : "Ready"}
                  </p>
                  {!checking && errors[index] && (
                    <p className="mt-1 text-xs text-critical">{errors[index]}</p>
                  )}
                </div>
                <button
                  type="button"
                  aria-label={`Remove ${file.name}`}
                  disabled={data.scanning}
                  className="rounded-sm p-1.5 hover:bg-accent disabled:opacity-45"
                  onClick={() => {
                    setChecking(true);
                    setFiles((previous) => previous.filter((_, i) => i !== index));
                  }}
                >
                  <X size={16} />
                </button>
              </li>
            ))}
          </ul>
        )}
        {errors.some(Boolean) && (
          <p className="text-xs text-muted-foreground">
            Files marked “Not included” will not be sent.
          </p>
        )}
        {selectionError && (
          <p role="alert" className="text-sm text-critical">
            {selectionError}
          </p>
        )}
        {attempted && data.error && (
          <div
            role="alert"
            className="border-l-4 border-critical bg-critical/10 px-3 py-2 text-sm text-critical"
          >
            {data.error}
            <p className="mt-1 text-xs text-muted-foreground">
              Your previous results have been kept. Adjust the files and try again.
            </p>
          </div>
        )}
        {data.scanning && (
          <div
            role="status"
            aria-live="polite"
            className="relative flex gap-2 overflow-hidden rounded-sm bg-secondary p-3 text-sm"
          >
            <span className="scan-sweep absolute inset-x-0 bottom-0 h-0.5" aria-hidden />
            <LoaderCircle size={18} className="shrink-0 animate-spin" />
            {data.progress}
          </div>
        )}
        <div className="flex flex-wrap justify-end gap-2">
          <button
            type="button"
            className="btn-ghost"
            disabled={data.scanning}
            onClick={() => void analyze(true)}
          >
            Analyze official samples (demo)
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={checking || data.scanning || !valid.length || !!selectionError}
            onClick={() => void analyze()}
          >
            <Upload size={16} />
            {data.scanning ? "Analyzing…" : "Analyze files"}
          </button>
        </div>
        <p className="text-xs text-muted-foreground">
          Files are analyzed locally and temporary uploads are deleted after analysis. Results
          update automatically when the scan completes.
        </p>
      </DialogContent>
    </Dialog>
  );
}
