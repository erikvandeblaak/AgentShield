// The single data access point for the UI.
//   real mode → `api` (Tauri commands → daemon)
//   Demo Mode → in-memory fictional dataset (lazy-loaded; never touches `api`)
// Components must import `backend`, never `api` directly, so Demo Mode can never mutate real state.

import { api, onConnection, onEvent, onTrayNavigate } from "./api";
import type { EventRow } from "./types";

type Api = typeof api;

const DEMO_KEY = "agentshield.demo";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

let demo = false;
try {
  demo = typeof localStorage !== "undefined" && localStorage.getItem(DEMO_KEY) === "1";
} catch {
  demo = false;
}

export function isDemo(): boolean {
  return demo;
}

export function setDemoFlag(on: boolean): void {
  demo = on;
  try {
    if (on) localStorage.setItem(DEMO_KEY, "1");
    else localStorage.removeItem(DEMO_KEY);
  } catch {
    /* storage unavailable: flag stays in memory */
  }
}

const loadDemo = () => import("../demo/api");

function wrap<K extends keyof Api>(key: K): Api[K] {
  const fn = async (...args: unknown[]) => {
    const impl: Api = demo ? (await loadDemo()).demoApi : api;
    return (impl[key] as (...a: unknown[]) => Promise<unknown>)(...args);
  };
  return fn as unknown as Api[K];
}

export const backend: Api = Object.fromEntries(
  (Object.keys(api) as (keyof Api)[]).map((k) => [k, wrap(k)]),
) as unknown as Api;

type Unsub = () => void;

function fromPromise(p: Promise<Unsub>): Unsub {
  let cancelled = false;
  let un: Unsub | null = null;
  p.then((u) => {
    if (cancelled) u();
    else un = u;
  }).catch(() => {
    /* not running inside Tauri or the subscription failed; status polling reports the state */
  });
  return () => {
    cancelled = true;
    un?.();
  };
}

/** Live events (real push in Tauri, generated feed in Demo Mode). Returns an unsubscribe function. */
export function subscribeEvents(cb: (row: EventRow) => void): Unsub {
  if (demo) return fromPromise(loadDemo().then((m) => m.subscribeDemoFeed(cb)));
  if (!isTauri()) return () => undefined;
  return fromPromise(onEvent(cb));
}

export function subscribeConnection(cb: (state: string) => void): Unsub {
  if (demo || !isTauri()) return () => undefined;
  return fromPromise(onConnection(cb));
}

export function subscribeTrayNavigate(cb: (route: string) => void): Unsub {
  if (!isTauri()) return () => undefined;
  return fromPromise(onTrayNavigate(cb));
}
