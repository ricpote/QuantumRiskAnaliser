import type { Finding } from "./quantumtrace-data";

// GET when body is undefined, otherwise a same-origin JSON POST (the Node server proxies /api to Python).
export async function apiRequest<T = unknown>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const timeout = AbortSignal.timeout(30000);
  const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  let response: Response;
  try {
    response = await fetch(path, {
      ...(body === undefined
        ? {}
        : {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          }),
      signal: requestSignal,
    });
  } catch (error) {
    if (timeout.aborted)
      throw new Error(
        "The scanner service did not respond within 30 seconds. Check that it is running and try again.",
      );
    if (signal?.aborted) throw error;
    throw new Error("Cannot reach the scanner service. Check the local server and try again.");
  }
  let value;
  try {
    value = await response.json();
  } catch {
    throw new Error(
      `The scanner returned an unreadable response (${response.status}). Check the server and retry.`,
    );
  }
  if (!response.ok) throw new Error(value?.error ?? `Request failed (${response.status})`);
  return value as T;
}

export interface Headline {
  score: number | null;
  grade: string;
  critical: number;
  hndl_exposed: number;
  plaintext: number;
  late: number;
}
export interface WhatIfResult {
  actions: number;
  before: Headline;
  after: Headline;
}

export type ExplainedFinding = Finding & {
  classical_bits?: number | null;
  nist_quantum_level?: number | null;
  oid?: string | null;
};
export interface ExplainResult {
  options: { algorithms: string[]; categories: string[] };
  finding?: ExplainedFinding;
}

export interface ProbeReport {
  target: string;
  starttls?: string | null;
  connections?: number;
  duration_s?: number;
  errors?: string[];
  versions: Record<string, boolean>;
  groups: Record<string, { code: number; supported: boolean; pq: boolean }>;
  tls13_ciphers?: string[];
  tls12_ciphers?: { name: string }[];
  modern?: {
    group_name?: string | null;
    version?: string | null;
    cipher?: string | null;
    cert_verify_name?: string | null;
    alert?: string | null;
  } | null;
  certs?: {
    subject?: string;
    issuer?: string;
    algorithm?: string;
    key_bits?: number;
    curve?: string;
    sig_hash?: string;
    not_after?: string;
  }[];
  verdict: { color: "green" | "red" | "grey"; text: string };
}
export interface ProbeJob {
  state: "idle" | "running" | "complete" | "error";
  error: string | null;
  result: {
    generated_at: string;
    targets: string[];
    deep: boolean;
    reports: ProbeReport[];
    findings: Finding[];
    cbom: unknown;
    cbom_valid: boolean;
  } | null;
}
