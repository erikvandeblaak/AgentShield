import type { ActionKind, AuditRecord, EventRow, Outcome, RiskLevel } from "./types";

export function levelForScore(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

export function basename(path: string | null | undefined): string {
  if (!path) return "";
  const parts = path.replace(/[\\/]+$/, "").split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "";
  return id.length > n ? id.slice(0, n) : id;
}

export function truncateMiddle(s: string, max = 16): string {
  if (s.length <= max) return s;
  const half = Math.floor((max - 1) / 2);
  return `${s.slice(0, half)}…${s.slice(-half)}`;
}

const nfCache = new Map<string, Intl.NumberFormat>();
export function formatNumber(n: number, locale = "en"): string {
  let nf = nfCache.get(locale);
  if (!nf) {
    nf = new Intl.NumberFormat(locale);
    nfCache.set(locale, nf);
  }
  return nf.format(n);
}

export function formatCompact(n: number, locale = "en"): string {
  if (Math.abs(n) < 10000) return formatNumber(n, locale);
  return new Intl.NumberFormat(locale, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

/** Microseconds → human string ("840 µs", "3.2 ms", "1.4 s"). */
export function formatLatency(us: number): string {
  if (!Number.isFinite(us)) return "–";
  if (us < 1000) return `${Math.round(us)} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(us < 10_000 ? 2 : 1)} ms`;
  return `${(us / 1_000_000).toFixed(2)} s`;
}

export function formatTime(ts: string, locale = "en"): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function formatDateTime(ts: string | null | undefined, locale = "en"): string {
  if (!ts) return "–";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(locale, {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}

export function formatDay(ts: string, locale = "en"): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleDateString(locale, { month: "short", day: "2-digit" });
}

/** Smart timestamp for tables: time only when today, otherwise date + time. */
export function formatSmartTime(ts: string, locale = "en"): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return formatTime(ts, locale);
  return `${formatDay(ts, locale)} ${d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false })}`;
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "–";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/** Relative "x ago" parts; the caller localises via i18n. */
export function relativeParts(ts: string, now = Date.now()): { value: number; unit: "s" | "m" | "h" | "d" } {
  const diff = Math.max(0, (now - new Date(ts).getTime()) / 1000);
  if (diff < 60) return { value: Math.floor(diff), unit: "s" };
  if (diff < 3600) return { value: Math.floor(diff / 60), unit: "m" };
  if (diff < 86400) return { value: Math.floor(diff / 3600), unit: "h" };
  return { value: Math.floor(diff / 86400), unit: "d" };
}

/** The "primary text" of an action (command, path, URL…) – already redacted by the backend. */
export function actionTarget(a: ActionKind): string {
  switch (a.type) {
    case "shell_exec": return a.command;
    case "file_read": case "file_write": case "file_edit": return a.path;
    case "file_search": return a.path ? `${a.pattern}  in ${a.path}` : a.pattern;
    case "network_fetch": return a.url;
    case "web_search": return a.query;
    case "mcp_call": return `${a.server} › ${a.tool}`;
    case "sub_agent": return a.description;
    case "user_prompt": return `${a.length} chars`;
    case "session_start": return a.source;
    case "session_end": return a.reason;
    case "notification": return a.message;
    case "stop": return "";
    case "permission_request": case "permission_denied": return a.tool;
    case "mode_change": return `${a.from} → ${a.to}`;
    case "other_tool": return a.tool;
  }
}

export function effectiveOutcome(row: EventRow): Outcome {
  return row.observed_outcome ?? row.record.outcome;
}

export function hostOf(url: string): string | null {
  try {
    return new URL(url).host || null;
  } catch {
    const m = url.match(/^(?:[a-z]+:\/\/)?([^/\s:]+(?::\d+)?)/i);
    return m?.[1] ?? null;
  }
}

/** Hosts an event reveals: a fetch URL or URLs/IPs inside a shell command. Nothing is inferred. */
export function hostsOfRecord(r: AuditRecord): string[] {
  if (r.action.type === "network_fetch") {
    const h = hostOf(r.action.url);
    return h ? [h] : [];
  }
  if (r.action.type === "shell_exec") {
    const out = new Set<string>();
    for (const m of r.action.command.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/([^\s/'"|;&)]+)/gi)) if (m[1]) out.add(m[1]);
    for (const m of r.action.command.matchAll(/(?<![\w.@=-])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.-])/g)) if (m[1]) out.add(m[1]);
    return [...out];
  }
  return [];
}

export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? "null";
  } catch {
    return String(value);
  }
}

export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return prettyJson(e);
}
