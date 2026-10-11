import type { Finding } from "./quantumtrace-data";

// GET when body is undefined, otherwise a same-origin JSON POST (the Node server proxies /api to Python).
export async function apiRequest<T = unknown>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(path, {
    ...(body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
    ...(signal ? { signal } : {}),
  });
  const value = await response.json();
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

interface OriginScore {
  expected: number;
  detected: number;
  correctly_classified: number;
  traps_checked: number;
}
export interface AccuracyResult {
  code: {
    expected: number;
    detected: number;
    correctly_classified: number;
    recall: number;
    precision: number;
    false_positives: number;
    traps_checked: number;
  };
  code_by_origin: { official: OriginScore; own_fixtures: OriginScore };
  network: { expected_sessions: number; sessions_correct: number; accuracy: number };
  cloud: { expected: number; correct: number; accuracy: number; traps_checked: number };
  failures: string[];
  passed: boolean;
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
