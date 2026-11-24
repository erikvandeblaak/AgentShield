// In-memory implementation of the backend contract for Demo Mode.
// It NEVER calls the real `api` object: mutations only change this module's local state.

import {
  DEMO_PREFIX, DEMO_SEED, Rng, RISKY, draftToolCall, finalize, generateDemoDataset, type DemoDataset,
} from "./dataset";
import { DEMO_PRESETS, DEMO_RULES, demoSimulate } from "./engine";
import { hostsOfRecord } from "../lib/format";
import type { api as realApi } from "../lib/api";
import type {
  Bucket, Config, CountItem, EventQuery, EventRow, Mode, PolicyDecision, PolicyInfo, PresetInfo, ReplayResult,
  SessionSummary, SimInput, Stats, Status, ValidationResult,
} from "../lib/types";
import { demoPolicy } from "./engine";

type Api = typeof realApi;

interface DemoState {
  data: DemoDataset;
  mode: Mode;
  paused: boolean;
  config: Config;
  userPolicy: string;
  startedAt: number;
  liveRng: Rng;
  installed: boolean;
  failClosed: boolean;
}

let state: DemoState | null = null;

const USER_POLICY_TEMPLATE = `# Demo user policy layer (fictional). Rules here are merged on top of the active preset.
schema_version = 1

[[rules]]
id = "demo-ask-production-env"
name = "Ask before touching production env files"
[rules.match]
event_types = ["file.read", "file.edit", "file.write"]
path_globs = ["**/.env.production"]
[rules.effect]
action = "ask"
reason = "Production secrets"
`;

function st(): DemoState {
  if (!state) {
    const data = generateDemoDataset(DEMO_SEED, Date.now());
    state = {
      data, mode: "monitor", paused: false, startedAt: Date.now() - 3 * 86400_000 - 4 * 3600_000,
      config: { mode: "monitor", preset: data.preset, paused: false, retention_days: 90, language: "en", theme: "dark", notifications: true, correlation_window_minutes: 15 },
      userPolicy: USER_POLICY_TEMPLATE, liveRng: new Rng(DEMO_SEED ^ 0x9e3779b9), installed: true, failClosed: false,
    };
  }
  return state;
}

export function resetDemo(): void {
  state = null;
}

const delay = <T>(value: T, ms = 60): Promise<T> => new Promise((r) => setTimeout(() => r(value), ms));
const SECRET_CATS = new Set(["credential_exposure", "secret_access"]);

export function matchesQuery(row: EventRow, q: EventQuery): boolean {
  const r = row.record;
  if (q.after_id != null && r.id <= q.after_id) return false;
  if (q.before_id != null && r.id >= q.before_id) return false;
  if (q.agent && r.agent !== q.agent) return false;
  if (q.session_id && r.session_id !== q.session_id) return false;
  if (q.workspace && r.workspace !== q.workspace) return false;
  if (q.action_type && r.action_type !== q.action_type) return false;
  if (q.phase && r.phase !== q.phase) return false;
  if (q.min_score != null && r.risk.score < q.min_score) return false;
  if (q.category && !r.risk.categories.includes(q.category)) return false;
  if (q.simulated_decision && r.simulated_decision !== q.simulated_decision) return false;
  if (q.actual_decision && r.actual_decision !== q.actual_decision) return false;
  if (q.since && r.ts_utc < q.since) return false;
  if (q.correlation_id && r.correlation_id !== q.correlation_id) return false;
  if (q.secrets_only && !r.risk.categories.some((c) => SECRET_CATS.has(c))) return false;
  if (q.packages_only && !r.risk.findings.some((f) => f.id.startsWith("package."))) return false;
  if (q.network_only && !(r.action.type === "network_fetch" || r.action.type === "web_search" || hostsOfRecord(r).length > 0)) return false;
  if (q.mcp_only && r.action.type !== "mcp_call") return false;
  if (q.search) {
    const needle = q.search.toLowerCase();
    const hay = `${r.summary} ${r.tool ?? ""} ${r.action_type} ${r.workspace ?? ""} ${r.session_id ?? ""} ${r.risk.findings.map((f) => f.id).join(" ")}`.toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

function listEvents(q: EventQuery): EventRow[] {
  const { events } = st().data;
  const limit = Math.min(q.limit ?? 200, 5000);
  const out: EventRow[] = [];
  if (q.after_id != null && q.before_id == null) {
    for (const e of events) {
      if (matchesQuery(e, q)) out.push(e);
      if (out.length >= limit) break;
    }
    return out.reverse();
  }
  for (let i = events.length - 1; i >= 0 && out.length < limit; i--) {
    const e = events[i];
    if (e && matchesQuery(e, q)) out.push(e);
  }
  return out; // newest first
}

const pad = (n: number) => String(n).padStart(2, "0");
const minuteKey = (d: Date) => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
const hourKey = (d: Date) => minuteKey(d).slice(0, 13);

function top(map: Map<string, number>, n = 50): CountItem[] {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));
}

function bump(map: Map<string, Bucket>, key: string, score: number): void {
  let b = map.get(key);
  if (!b) {
    b = { key, count: 0, max_score: 0, risky: 0 };
    map.set(key, b);
  }
  b.count++;
  if (score > b.max_score) b.max_score = score;
  if (score >= 40) b.risky++;
}

export function computeStats(events: EventRow[], windowHours: number, now: number): Stats {
  const since = now - windowHours * 3600_000;
  const lvl = new Map<string, number>(), cat = new Map<string, number>(), agent = new Map<string, number>();
  const act = new Map<string, number>(), ws = new Map<string, number>();
  const perMin = new Map<string, Bucket>(), perHour = new Map<string, Bucket>(), heat = new Map<string, Bucket>();
  const sessionsOpen = new Map<string, number>();
  let inWindow = 0, risky = 0, wouldBlock = 0, wouldAsk = 0, blocked = 0, asked = 0, degraded = 0;
  for (const { record: r } of events) {
    const t = Date.parse(r.ts_utc);
    const d = new Date(t);
    if (t >= now - 28 * 86400_000) bump(heat, `${d.getUTCDay()}:${d.getUTCHours()}`, r.risk.score);
    if (r.session_id) {
      if (r.action_type === "session.end") sessionsOpen.delete(r.session_id);
      else sessionsOpen.set(r.session_id, t);
    }
    if (t >= now - 3600_000) bump(perMin, minuteKey(d), r.risk.score);
    if (t < since) continue;
    inWindow++;
    bump(perHour, hourKey(d), r.risk.score);
    lvl.set(r.risk.level, (lvl.get(r.risk.level) ?? 0) + 1);
    agent.set(r.agent, (agent.get(r.agent) ?? 0) + 1);
    act.set(r.action_type, (act.get(r.action_type) ?? 0) + 1);
    if (r.workspace) ws.set(r.workspace, (ws.get(r.workspace) ?? 0) + 1);
    if (r.phase === "pre") for (const c of r.risk.categories) cat.set(c, (cat.get(c) ?? 0) + 1);
    if (r.risk.score >= 40 && r.phase !== "post") risky++;
    if (r.phase === "pre") {
      if (r.simulated_decision === "deny" || r.simulated_decision === "require_sandbox") wouldBlock++;
      if (r.simulated_decision === "ask") wouldAsk++;
      if (r.actual_decision === "deny") blocked++;
      if (r.actual_decision === "ask") asked++;
    }
    if (r.coverage === "degraded") degraded++;
  }
  const active = [...sessionsOpen.values()].filter((t) => t >= now - 30 * 60_000).length;
  const sortB = (m: Map<string, Bucket>) => [...m.values()].sort((a, b) => (a.key < b.key ? -1 : 1));
  return {
    total_events: events.length, events_in_window: inWindow, window_hours: windowHours, risky_events: risky,
    would_block: wouldBlock, would_ask: wouldAsk, actually_blocked: blocked, actually_asked: asked,
    degraded_events: degraded, dropped_events: 2,
    by_level: top(lvl), by_category: top(cat), by_agent: top(agent), by_action: top(act), top_workspaces: top(ws, 8),
    per_minute: sortB(perMin), per_hour: sortB(perHour), heatmap: [...heat.values()],
    active_sessions: active, first_event: events[0]?.record.ts_utc ?? null, last_event: events[events.length - 1]?.record.ts_utc ?? null,
  };
}

export function computeSessions(events: EventRow[], limit: number): SessionSummary[] {
  const map = new Map<string, SessionSummary>();
  for (const { record: r } of events) {
    if (!r.session_id) continue;
    let s = map.get(r.session_id);
    if (!s) {
      s = { session_id: r.session_id, agent: r.agent, workspace: r.workspace, first_ts: r.ts_utc, last_ts: r.ts_utc, events: 0, max_score: 0, would_block: 0, blocked: 0, ended: false };
      map.set(r.session_id, s);
    }
    s.events++;
    s.last_ts = r.ts_utc;
    if (r.risk.score > s.max_score) s.max_score = r.risk.score;
    if (r.phase === "pre" && (r.simulated_decision === "deny" || r.simulated_decision === "require_sandbox")) s.would_block++;
    if (r.actual_decision === "deny") s.blocked++;
    if (r.action_type === "session.end") s.ended = true;
  }
  return [...map.values()].sort((a, b) => (a.last_ts < b.last_ts ? 1 : -1)).slice(0, limit);
}

function status(): Status {
  const s = st();
  return {
    daemon_running: true, daemon_version: "0.1.0-demo", pid: 4242, uptime_s: Math.floor((Date.now() - s.startedAt) / 1000),
    mode: s.mode, preset: s.config.preset, paused: s.paused, policy_name: s.config.preset, policy_version: "demo-1",
    policy_warnings: [], events_total: s.data.events.length, dropped_events: 2,
    hook_latency: { count: s.data.events.length, p50_us: 1180, p95_us: 3900, p99_us: 9400, max_us: 21800 },
    eval_latency: { count: s.data.events.length, p50_us: 240, p95_us: 910, p99_us: 2300, max_us: 6100 },
    degraded: false, degraded_reasons: [],
    data_dir: "/demo/home/.local/share/agentshield", config_dir: "/demo/home/.config/agentshield",
    db_path: "/demo/home/.local/share/agentshield/audit.db", version: "0.1.0", build: "demo",
  };
}

function presets(): PresetInfo[] {
  return DEMO_PRESETS.map((p) => ({
    id: p.id, title: p.title, description: p.description,
    text: [
      `# DEMO preset (fictional): ${p.id}`, "schema_version = 1", `name = "${p.id}"`, `description = "${p.description}"`, "",
      "[thresholds]",
      ...(p.warn != null ? [`warn_at = ${p.warn}`] : []), ...(p.ask != null ? [`ask_at = ${p.ask}`] : []), ...(p.deny != null ? [`deny_at = ${p.deny}`] : []),
      ...(p.rules
        ? DEMO_RULES.flatMap((r) => [
            "", "[[rules]]", `id = "${r.id}"`, `name = "${r.name}"`, ...(r.hard ? ["hard = true"] : []), "[rules.match]",
            `finding_ids = ["${r.finding.source.replace(/\\/g, "").replace(/[\^$()]/g, "")}"]`, "[rules.effect]", `action = "${r.decision}"`, `reason = "${r.reason}"`,
          ])
        : []),
      "",
    ].join("\n"),
  }));
}

function policy(): PolicyInfo {
  const s = st();
  const p = DEMO_PRESETS.find((x) => x.id === s.config.preset) ?? DEMO_PRESETS[0]!;
  const userRules = [...s.userPolicy.matchAll(/^\s*id\s*=\s*"([^"]+)"[\s\S]*?(?:name\s*=\s*"([^"]*)")?[\s\S]*?action\s*=\s*"(\w+)"/gm)];
  return {
    name: p.id, version: "demo-1", thresholds: { warn_at: p.warn, ask_at: p.ask, deny_at: p.deny },
    rules: [
      ...(p.rules ? DEMO_RULES.map((r) => ({ id: r.id, name: r.name, decision: r.decision, enabled: true, hard: r.hard, layer: "preset" as const })) : []),
      ...userRules.map((m) => ({ id: m[1] ?? "rule", name: m[2] ?? null, decision: (m[3] ?? "warn") as PolicyDecision, enabled: true, hard: false, layer: "user" as const })),
    ],
    warnings: p.rules ? [] : ["This preset never asks or denies; it is observation only."],
    sources: [["preset", `${p.id}.toml`], ["user", "/demo/home/.config/agentshield/policy.toml"]],
    user_policy_path: "/demo/home/.config/agentshield/policy.toml", user_policy_text: s.userPolicy,
  };
}

const VALID_ACTIONS = new Set(["allow", "warn", "ask", "require_sandbox", "deny"]);

/** Very small demo validator: structure checks only (the real validator is the Rust TOML parser). */
export function demoValidate(text: string): ValidationResult {
  const warnings: string[] = [];
  const lines = text.split(/\r?\n/);
  let inRule = false;
  let ruleHasId = true;
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? "").trim();
    if (!line || line.startsWith("#")) continue;
    const quotes = (line.replace(/\\"/g, "").match(/"/g) ?? []).length;
    if (quotes % 2 === 1) return { ok: false, warnings, error: `line ${i + 1}: unterminated string` };
    if (line.startsWith("[")) {
      if (!/^\[\[?[A-Za-z0-9_.-]+\]?\]$/.test(line)) return { ok: false, warnings, error: `line ${i + 1}: invalid table header` };
      if (line === "[[rules]]") {
        if (inRule && !ruleHasId) return { ok: false, warnings, error: `line ${i + 1}: previous [[rules]] block has no id` };
        inRule = true;
        ruleHasId = false;
      }
      continue;
    }
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.+)$/);
    if (!m) return { ok: false, warnings, error: `line ${i + 1}: expected key = value` };
    if (m[1] === "id") ruleHasId = true;
    if (m[1] === "action" && !VALID_ACTIONS.has((m[2] ?? "").replace(/"/g, ""))) return { ok: false, warnings, error: `line ${i + 1}: unknown action ${m[2]}` };
    if (m[1] === "hard" && m[2] === "true") warnings.push(`line ${i + 1}: hard rules cannot be overridden by project policies.`);
  }
  if (inRule && !ruleHasId) return { ok: false, warnings, error: "last [[rules]] block has no id" };
  if (!text.includes("[[rules]]")) warnings.push("No rules defined; only the preset applies.");
  return { ok: true, warnings, error: null };
}

function replay(preset: string, sessionId: string | null, limit: number): ReplayResult {
  const rows = listEvents({ session_id: sessionId ?? undefined, phase: "pre", limit });
  const zero = (): Record<PolicyDecision, number> => ({ allow: 0, warn: 0, ask: 0, require_sandbox: 0, deny: 0 });
  const by = zero(), orig = zero();
  const changed: ReplayResult["changed"] = [];
  for (const { record: r } of rows) {
    const after = demoPolicy(r.risk, preset).decision;
    by[after]++;
    orig[r.simulated_decision]++;
    if (after !== r.simulated_decision) changed.push({ event_id: r.id, summary: r.summary, before: r.simulated_decision, after });
  }
  return { preset, evaluated: rows.length, by_decision: by, original_by_decision: orig, changed };
}

function withCalls() {
  const s = st();
  const counts = new Map<string, { n: number; tools: Set<string> }>();
  for (const { record: r } of s.data.events) {
    if (r.action.type !== "mcp_call" || r.phase !== "pre") continue;
    const c = counts.get(r.action.server) ?? { n: 0, tools: new Set<string>() };
    c.n++;
    c.tools.add(r.action.tool);
    counts.set(r.action.server, c);
  }
  return s.data.mcpServers.map((m) => ({ ...m, observed_calls: counts.get(m.name)?.n ?? 0, tools_seen: [...(counts.get(m.name)?.tools ?? [])] }));
}

function agents() {
  const s = st();
  return s.data.agents.map((a) =>
    a.id !== "claude-code" || !a.integration ? a : {
      ...a,
      integration: s.installed
        ? { ...a.integration, fail_closed: s.failClosed }
        : { ...a.integration, installed: false, verified: false, events: [], missing_events: a.integration.events, binary_path: null },
      capabilities: s.installed ? a.capabilities : a.capabilities.map((c) => ({ ...c, status: "unverified" as const, reason: "Integration is not installed." })),
    });
}

const hooksJson = (on: boolean, failClosed: boolean) =>
  JSON.stringify(on ? {
    hooks: Object.fromEntries(["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", "SessionEnd"].map((e) => [e, [{ matcher: "*", hooks: [{ type: "command", command: `/demo/opt/agentshield/agentshield-hook${failClosed ? " --fail-closed" : ""}`, timeout: 5 }] }]])),
  } : { hooks: {} }, null, 2);

export const demoApi: Api = {
  status: () => delay(status()),
  startDaemon: () => delay(status()),
  listEvents: (query) => delay(listEvents(query)),
  getEvent: (id) => delay(st().data.events.find((e) => e.record.id === id) ?? null),
  stats: (windowHours) => delay(computeStats(st().data.events, windowHours, Date.now())),
  sessions: (limit) => delay(computeSessions(st().data.events, limit)),
  incidents: (limit) => delay(st().data.incidents.slice(0, limit)),
  setMode: (mode) => { st().mode = mode; st().config.mode = mode; return delay(status()); },
  setPreset: (preset) => { st().config.preset = preset; return delay(status()); },
  setPaused: (paused) => { st().paused = paused; st().config.paused = paused; return delay(status()); },
  presets: () => delay(presets()),
  policy: () => delay(policy()),
  validatePolicy: (text) => delay(demoValidate(text), 40),
  saveUserPolicy: (text) => { st().userPolicy = text; return delay(policy()); },
  simulate: (input: SimInput) => delay(demoSimulate(input, st().config.preset), 120),
  replay: (preset, sessionId, limit) => delay(replay(preset, sessionId, limit), 200),
  agents: () => delay(agents(), 150),
  installPreview: (agentId, failClosed) => delay({
    agent_id: agentId, settings_path: "/demo/home/.claude/settings.json",
    changes: [
      "Add AgentShield hook command to PreToolUse (matcher *)", "Add AgentShield hook command to PostToolUse (matcher *)",
      "Add AgentShield hook command to UserPromptSubmit, SessionStart, SessionEnd",
      failClosed ? "Hook is registered fail-closed: if the hook binary is missing, tool calls are blocked" : "Hook is registered fail-open: if the hook binary is missing, Claude Code continues unmonitored",
      "Existing hooks and permissions are preserved", "A timestamped backup of settings.json is written first",
    ],
    before: hooksJson(st().installed, st().failClosed), after: hooksJson(true, failClosed),
    already_installed: st().installed, backup_dir: "/demo/home/.config/agentshield/backups",
  }),
  install: (_agentId, failClosed) => { st().installed = true; st().failClosed = failClosed; return delay({ ok: true, message: "Demo: integration installed (nothing was written).", backup_path: "/demo/home/.config/agentshield/backups/settings.demo.json", verified: true, problems: [] }, 300); },
  uninstall: () => { st().installed = false; return delay({ ok: true, message: "Demo: integration removed (nothing was written).", backup_path: null, verified: true, problems: [] }, 300); },
  mcpServers: () => delay(withCalls()),
  verifyIntegrity: () => delay({ checked: st().data.events.length, ok: true, bridged_breaks: 0, first_bad_id: null, problem: null, sqlite_integrity: "ok" }, 500),
  exportEvents: (format, query) => delay({ path: `/demo/exports/agentshield-events.${format}`, count: listEvents({ ...query, limit: 5000 }).length }, 300),
  generateReport: (kind) => delay({ path: `/demo/reports/agentshield-${kind}.html`, title: `Demo ${kind.replace("_", " ")} report` }, 400),
  config: () => delay({ ...st().config }),
  setConfig: (patch) => { Object.assign(st().config, patch); return delay({ ...st().config }); },
  deleteSession: (sessionId) => {
    const s = st();
    const before = s.data.events.length;

    s.data.events = s.data.events.filter((e) => e.record.session_id !== sessionId);
    return delay(before - s.data.events.length);
  },
  deleteAllData: () => { const n = st().data.events.length; st().data.events = []; st().data.incidents = []; return delay(n); },
  selfTest: () => {
    const row = emitOne({ command: "echo agentshield-self-test", shell: "bash" });
    return delay({ ok: true, event_id: row?.record.id ?? null, latency_ms: 3.4, message: "Demo self-test event recorded.", decision: "no_opinion" }, 400);
  },
  openPath: () => delay(undefined),
  backupDatabase: () => delay("/demo/backups/agentshield-audit.demo.db", 400),
};

// ---------------------------------------------------------------- live feed

const feedListeners = new Set<(row: EventRow) => void>();
let feedTimer: ReturnType<typeof setInterval> | null = null;

function emitOne(input: SimInput): EventRow | null {
  const s = st();
  const sessions = computeSessions(s.data.events, 6).filter((x) => !x.ended);
  const session = sessions[s.liveRng.int(0, Math.max(0, sessions.length - 1))];
  const last = s.data.events[s.data.events.length - 1];
  const drafts = draftToolCall(input, {
    ts: Date.now(), session: session?.session_id ?? `${DEMO_PREFIX}live`, workspace: session?.workspace ?? "/demo/acme-webshop",
    mode: s.mode, preset: s.config.preset, rng: s.liveRng,
  });
  const [pre, post] = finalize(drafts, (last?.record.id ?? 0) + 1, last?.record.hash ?? "0".repeat(64), s.liveRng);
  if (!pre) return null;
  // Demo ids are positional; pad if rows were deleted so getEvent(id) stays valid.
  s.data.events.push(pre);
  feedListeners.forEach((l) => l(pre));
  if (post) {
    setTimeout(() => {
      s.data.events.push(post);
      feedListeners.forEach((l) => l(post));
    }, 500);
  }
  return pre;
}

function tick(): void {
  const s = st();
  if (s.paused || !s.liveRng.chance(0.55)) return;
  const risky = s.liveRng.chance(0.1);
  const src = s.data.events[s.liveRng.int(0, Math.max(0, s.data.events.length - 1))]?.record;
  if (risky) emitOne(RISKY[s.liveRng.int(0, 13)] ?? { command: "git status", shell: "bash" });
  else if (src && src.phase === "pre" && src.risk.score < 20) {
    emitOne(src.action.type === "shell_exec" ? { command: src.action.command, shell: "bash" } : { tool: src.tool ?? "Read", tool_input: src.input_redacted });
  }
}

export function subscribeDemoFeed(cb: (row: EventRow) => void): () => void {
  feedListeners.add(cb);
  if (!feedTimer) feedTimer = setInterval(tick, 1500);
  return () => {
    feedListeners.delete(cb);
    if (feedListeners.size === 0 && feedTimer) {
      clearInterval(feedTimer);
      feedTimer = null;
    }
  };
}
