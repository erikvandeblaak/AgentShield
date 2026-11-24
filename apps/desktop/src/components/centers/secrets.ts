import { maxIso, minIso } from "./shared";
import type { EventRow, RiskCategory } from "../../lib/types";

export interface SecretRef { kind: string; fingerprint: string }

const PLACEHOLDER = /\[([a-z][a-z0-9_]*):([0-9a-f]{6,})\]/gi;

/** Extracts `[kind:fingerprint]` placeholders from a text. The raw secret never reaches the UI. */
export function extractSecretRefs(text: string): SecretRef[] {
  const out = new Map<string, SecretRef>();
  for (const m of text.matchAll(PLACEHOLDER)) {
    const kind = (m[1] ?? "").toLowerCase();
    const fingerprint = (m[2] ?? "").toLowerCase();
    if (kind && fingerprint) out.set(`${kind}:${fingerprint}`, { kind, fingerprint });
  }
  return [...out.values()];
}

export function secretRefsOfRow(row: EventRow): SecretRef[] {
  const r = row.record;
  let input: string;
  try {
    input = JSON.stringify(r.input_redacted) ?? "";
  } catch {
    input = "";
  }
  const text = [r.summary, input, ...r.risk.findings.map((f) => f.evidence ?? "")].join("\n");
  return extractSecretRefs(text);
}

export interface FingerprintGroup {
  key: string;
  kind: string;
  fingerprint: string;
  count: number;
  first: string;
  last: string;
  workspaces: string[];
  maxScore: number;
  eventIds: Set<number>;
}

export interface FindingGroup {
  id: string;
  category: RiskCategory;
  count: number;
  maxScore: number;
  explanation: string;
}

export interface SecretSummary {
  fingerprints: FingerprintGroup[];
  findings: FindingGroup[];
  kinds: number;
  projects: number;
  withoutFingerprint: number;
}

const SECRET_CATEGORIES = new Set<RiskCategory>(["credential_exposure", "secret_access"]);

export function summariseSecrets(rows: EventRow[]): SecretSummary {
  const fps = new Map<string, FingerprintGroup & { ws: Set<string> }>();
  const findings = new Map<string, FindingGroup>();
  const projects = new Set<string>();
  let withoutFingerprint = 0;
  for (const row of rows) {
    const r = row.record;
    if (r.workspace) projects.add(r.workspace);
    const refs = secretRefsOfRow(row);
    if (refs.length === 0) withoutFingerprint++;
    for (const ref of refs) {
      const key = `${ref.kind}:${ref.fingerprint}`;
      let g = fps.get(key);
      if (!g) {
        g = { key, ...ref, count: 0, first: r.ts_utc, last: r.ts_utc, workspaces: [], maxScore: 0, eventIds: new Set(), ws: new Set() };
        fps.set(key, g);
      }
      g.count++;
      g.first = minIso(g.first, r.ts_utc);
      g.last = maxIso(g.last, r.ts_utc);
      g.maxScore = Math.max(g.maxScore, r.risk.score);
      g.eventIds.add(r.id);
      if (r.workspace) g.ws.add(r.workspace);
    }
    for (const f of r.risk.findings) {
      if (!SECRET_CATEGORIES.has(f.category)) continue;
      let g = findings.get(f.id);
      if (!g) {
        g = { id: f.id, category: f.category, count: 0, maxScore: 0, explanation: f.explanation };
        findings.set(f.id, g);
      }
      g.count++;
      g.maxScore = Math.max(g.maxScore, f.score);
    }
  }
  const fingerprints = [...fps.values()]
    .map(({ ws, ...g }) => ({ ...g, workspaces: [...ws].sort() }))
    .sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : 1));
  return {
    fingerprints,
    findings: [...findings.values()].sort((a, b) => b.count - a.count),
    kinds: new Set(fingerprints.map((f) => f.kind)).size,
    projects: projects.size,
    withoutFingerprint,
  };
}
