import { create } from "zustand";
import type { EventRow } from "../lib/types";

export const LIVE_MAX = 5000;

interface LiveState {
  /** Newest first. Ring buffer capped at LIVE_MAX. */
  rows: EventRow[];
  /** Total rows received through the live subscription since start (for rate displays). */
  received: number;
  seed: (rows: EventRow[]) => void;
  appendOlder: (rows: EventRow[]) => void;
  push: (rows: EventRow[]) => void;
  clear: () => void;
}

/** A post event carries the observed outcome of the pre event with the same correlation id. */
export function applyObserved(rows: EventRow[], incoming: EventRow): EventRow[] {
  const r = incoming.record;
  if (r.phase !== "post" || !r.correlation_id) return rows;
  const limit = Math.min(rows.length, 400);
  for (let i = 0; i < limit; i++) {
    const cand = rows[i];
    if (cand && cand.record.phase === "pre" && cand.record.correlation_id === r.correlation_id) {
      if (cand.observed_outcome === r.outcome) return rows;
      const next = rows.slice();
      next[i] = { ...cand, observed_outcome: r.outcome };
      return next;
    }
  }
  return rows;
}

export function mergeLive(existing: EventRow[], incoming: EventRow[], max = LIVE_MAX): EventRow[] {
  let rows = existing;
  const known = new Set<number>();
  const head = Math.min(rows.length, 600);
  for (let i = 0; i < head; i++) known.add((rows[i] as EventRow).record.id);
  const fresh: EventRow[] = [];
  for (const row of incoming) {
    if (known.has(row.record.id)) continue;
    known.add(row.record.id);
    rows = applyObserved(rows, row);
    fresh.unshift(row);
  }
  if (fresh.length === 0) return rows;
  const merged = fresh.concat(rows);
  return merged.length > max ? merged.slice(0, max) : merged;
}

export const useLive = create<LiveState>((set) => ({
  rows: [],
  received: 0,
  seed: (rows) => set({ rows: rows.slice(0, LIVE_MAX) }),
  appendOlder: (older) =>
    set((s) => {
      const minId = s.rows.length ? (s.rows[s.rows.length - 1] as EventRow).record.id : Infinity;
      const add = older.filter((r) => r.record.id < minId);
      return add.length ? { rows: s.rows.concat(add).slice(0, LIVE_MAX) } : s;
    }),
  push: (incoming) => set((s) => ({ rows: mergeLive(s.rows, incoming), received: s.received + incoming.length })),
  clear: () => set({ rows: [], received: 0 }),
}));

// Batch pushes so a burst of events causes one render, not hundreds.
let pending: EventRow[] = [];
let timer: ReturnType<typeof setTimeout> | null = null;

export function queueLive(row: EventRow): void {
  pending.push(row);
  if (timer) return;
  timer = setTimeout(() => {
    const batch = pending;
    pending = [];
    timer = null;
    useLive.getState().push(batch);
  }, 180);
}
