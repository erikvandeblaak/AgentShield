import { useCallback, useEffect, useRef, useState } from "react";
import { subscribeEvents } from "./backend";
import { errorMessage } from "./format";
import { useApp } from "../store/app";
import type { EventRow } from "./types";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean; // true only while there is no data yet
  refreshing: boolean; // true during any in-flight request
  reload: () => void;
}

/**
 * Runs an async backend call, re-running when deps change, when the global data epoch changes
 * (demo toggled / daemon reconnected / data deleted) and optionally on an interval.
 * Previous data stays visible while refreshing.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: readonly unknown[], opts?: { refreshMs?: number; enabled?: boolean }): AsyncState<T> {
  const epoch = useApp((s) => s.epoch);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const enabled = opts?.enabled ?? true;

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setRefreshing(true);
    fnRef.current()
      .then((d) => {
        if (cancelled) return;
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(errorMessage(e));
      })
      .finally(() => {
        if (!cancelled) setRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, epoch, tick, enabled]);

  // A changed epoch means the previous data belongs to another data source: drop it.
  const firstEpoch = useRef(epoch);
  useEffect(() => {
    if (firstEpoch.current !== epoch) {
      firstEpoch.current = epoch;
      setData(null);
      setError(null);
    }
  }, [epoch]);

  const refreshMs = opts?.refreshMs;
  useEffect(() => {
    if (!refreshMs || !enabled) return;
    const id = setInterval(() => {
      if (!document.hidden) setTick((t) => t + 1);
    }, refreshMs);
    return () => clearInterval(id);
  }, [refreshMs, enabled]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading: data === null && error === null, refreshing, reload };
}

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

/** Re-render on an interval (relative timestamps, live clocks). */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** Subscribe to live events for the lifetime of the component (re-subscribes when the data source changes). */
export function useLiveEvents(cb: (row: EventRow) => void, enabled = true): void {
  const epoch = useApp((s) => s.epoch);
  const ref = useRef(cb);
  ref.current = cb;
  useEffect(() => {
    if (!enabled) return;
    return subscribeEvents((row) => ref.current(row));
  }, [epoch, enabled]);
}

export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
