import { useEffect, useRef, useState } from "react";
import { FileText, LoaderCircle, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
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
      <DialogContent className="max-h-[90dvh] overflow-y-auto w-[calc(100%-2rem)] rounded-lg">
        <DialogTitle>New scan</DialogTitle>
        <DialogDescription>
          {UPLOAD_HELP} Files are checked before the existing Python scanner analyzes them.
        </DialogDescription>
        <label htmlFor="scan-files" className="text-sm font-medium">
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
        <Button variant="outline" disabled={data.scanning} onClick={() => picker.current?.click()}>
          <Upload size={16} /> Choose files
        </Button>
        <p id="scan-selection-help" className="text-xs text-muted-foreground">
          You can add more files or remove individual selections. ZIP contents are validated by the
          scanner service.
        </p>
        {!!files.length && (
          <ul aria-label="Selected files" className="max-h-56 overflow-y-auto space-y-2">
            {files.map((file, index) => (
              <li
                key={`${file.name}-${index}`}
                className="rounded-md border p-3 flex items-start gap-3"
              >
                <FileText size={16} className="mt-1 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm break-all">{file.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatBytes(file.size)} ·{" "}
                    {checking ? "Checking…" : errors[index] ? "Not included" : "Ready"}
                  </p>
                  {!checking && errors[index] && (
                    <p className="text-xs text-critical mt-1">{errors[index]}</p>
                  )}
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`Remove ${file.name}`}
                  disabled={data.scanning}
                  onClick={() => {
                    setChecking(true);
                    setFiles((previous) => previous.filter((_, i) => i !== index));
                  }}
                >
                  <X size={16} />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">
          {valid.length} ready · {formatBytes(total)} / 32 MiB
          {errors.some(Boolean) ? " · Files marked “Not included” will not be sent." : ""}
        </p>
        {selectionError && (
          <p role="alert" className="text-sm text-critical">
            {selectionError}
          </p>
        )}
        {attempted && data.error && (
          <div role="alert" className="rounded-md border p-3 text-sm text-critical">
            {data.error}
            <p className="mt-1 text-xs">
              Your previous results have been kept. Adjust the files and try again.
            </p>
          </div>
        )}
        {data.scanning && (
          <div
            role="status"
            aria-live="polite"
            className="rounded-md bg-secondary p-3 text-sm flex gap-2"
          >
            <LoaderCircle size={18} className="animate-spin shrink-0" />
            {data.progress}
          </div>
        )}
        <Button
          disabled={checking || data.scanning || !valid.length || !!selectionError}
          onClick={() => void analyze()}
        >
          <Upload size={16} />
          {data.scanning ? "Analyzing…" : "Analyze files"}
        </Button>
        <Button variant="outline" disabled={data.scanning} onClick={() => void analyze(true)}>
          Analyze official samples (demo)
        </Button>
        <p className="text-xs text-muted-foreground">
          Files are analyzed locally and temporary uploads are deleted after analysis. Results
          update automatically when the scan completes.
        </p>
      </DialogContent>
    </Dialog>
  );
}
