import { useSyncExternalStore } from "react";

export const ROUTES = [
  "overview", "live", "threats", "sessions", "agents", "approvals", "policy", "simulator",
  "secrets", "mcp", "supply-chain", "network", "reports", "settings", "about",
] as const;
export type RouteId = (typeof ROUTES)[number];

export interface Route { id: RouteId; params: URLSearchParams }

export function parseRoute(hash: string): Route {
  const raw = hash.replace(/^#\/?/, "");
  const [path = "", query = ""] = raw.split("?");
  const id = (ROUTES as readonly string[]).includes(path) ? (path as RouteId) : "overview";
  return { id, params: new URLSearchParams(query) };
}

let current: Route = parseRoute(typeof window === "undefined" ? "" : window.location.hash);
const listeners = new Set<() => void>();

if (typeof window !== "undefined") {
  window.addEventListener("hashchange", () => {
    current = parseRoute(window.location.hash);
    listeners.forEach((l) => l());
  });
}

export function navigate(id: RouteId, params?: Record<string, string | undefined>): void {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) if (v != null && v !== "") q.set(k, v);
  const qs = q.toString();
  window.location.hash = `/${id}${qs ? `?${qs}` : ""}`;
}

export function useRoute(): Route {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current,
  );
}
