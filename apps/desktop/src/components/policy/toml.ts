import type { PolicyDecision, RiskCategory } from "../../lib/types";

// Valid `event_types` values accepted by the policy engine.
export const EVENT_TYPES = [
  "shell.exec", "file.read", "file.write", "file.edit", "file.search", "network.fetch", "network.search", "mcp.call",
  "agent.subagent", "agent.prompt", "session.start", "session.end", "agent.notification", "agent.stop",
  "agent.permission_request", "agent.permission_denied", "agentshield.mode_change", "tool.other",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const ACTIONS: PolicyDecision[] = ["allow", "warn", "ask", "require_sandbox", "deny"];

export interface RuleDraft {
  id: string;
  name: string;
  hard: boolean;
  event_types: EventType[];
  programs: string[];
  path_globs: string[];
  categories: RiskCategory[];
  finding_ids: string[];
  min_score: number | null;
  action: PolicyDecision;
  reason: string;
  suggestion: string;
}

export const EMPTY_RULE: RuleDraft = {
  id: "", name: "", hard: false, event_types: [], programs: [], path_globs: [], categories: [], finding_ids: [],
  min_score: null, action: "ask", reason: "", suggestion: "",
};

/** TOML basic string with full escaping (quotes, backslashes, control characters). */
export function tomlString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

export function tomlArray(values: readonly string[]): string {
  return `[${values.map(tomlString).join(", ")}]`;
}

/** "a, b ,, c" → ["a", "b", "c"] (commas inside {braces} are kept, so globs like *.{js,ts} work). */
export function splitList(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  let depth = 0;
  for (const ch of text) {
    if (ch === "{") depth++;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    if ((ch === "," && depth === 0) || ch === "\n") {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function isValidRuleId(id: string): boolean {
  return /^[a-z0-9][a-z0-9._-]*$/.test(id);
}

export function hasMatch(d: RuleDraft): boolean {
  return d.event_types.length + d.programs.length + d.path_globs.length + d.categories.length + d.finding_ids.length > 0 || d.min_score != null;
}

/** Generates one `[[rules]]` block in the AgentShield policy format. Pure and deterministic. */
export function ruleToToml(d: RuleDraft): string {
  const lines: string[] = ["[[rules]]", `id = ${tomlString(d.id.trim())}`];
  if (d.name.trim()) lines.push(`name = ${tomlString(d.name.trim())}`);
  if (d.hard) lines.push("hard = true");
  lines.push("[rules.match]");
  if (d.event_types.length) lines.push(`event_types = ${tomlArray(d.event_types)}`);
  if (d.programs.length) lines.push(`programs = ${tomlArray(d.programs)}`);
  if (d.path_globs.length) lines.push(`path_globs = ${tomlArray(d.path_globs)}`);
  if (d.categories.length) lines.push(`categories = ${tomlArray(d.categories)}`);
  if (d.finding_ids.length) lines.push(`finding_ids = ${tomlArray(d.finding_ids)}`);
  if (d.min_score != null && Number.isFinite(d.min_score)) lines.push(`min_score = ${Math.max(0, Math.min(100, Math.round(d.min_score)))}`);
  lines.push("[rules.effect]", `action = ${tomlString(d.action)}`);
  if (d.reason.trim()) lines.push(`reason = ${tomlString(d.reason.trim())}`);
  if (d.suggestion.trim()) lines.push(`suggestion = ${tomlString(d.suggestion.trim())}`);
  return `${lines.join("\n")}\n`;
}

/** Appends a block to existing policy text with exactly one blank line in between. */
export function appendBlock(text: string, block: string): string {
  const base = text.replace(/\s+$/, "");
  return base ? `${base}\n\n${block}` : block;
}

export type TemplateId = "env" | "forcePush" | "packages" | "metadata" | "mcp";

export const TEMPLATES: Record<TemplateId, RuleDraft> = {
  env: {
    ...EMPTY_RULE, id: "ask-env-files", name: "Ask before reading .env files", event_types: ["file.read"],
    path_globs: ["**/.env", "**/.env.*"], action: "ask", reason: "Environment files usually contain secrets",
    suggestion: "Give the agent a redacted .env.example instead.",
  },
  forcePush: {
    ...EMPTY_RULE, id: "deny-force-push-main", name: "Deny force-push to protected branches", event_types: ["shell.exec"],
    programs: ["git"], finding_ids: ["git.force_push*"], action: "deny", hard: true,
    reason: "Force-pushing a protected branch can destroy other people's work", suggestion: "Use --force-with-lease on a feature branch.",
  },
  packages: {
    ...EMPTY_RULE, id: "ask-package-installs", name: "Ask on package installs", event_types: ["shell.exec"],
    categories: ["suspicious_package_installation", "supply_chain_compromise"], action: "ask",
    reason: "New dependencies run code with your privileges", suggestion: "Install from the lockfile, or review the package first.",
  },
  metadata: {
    ...EMPTY_RULE, id: "deny-cloud-metadata", name: "Deny cloud metadata endpoints", event_types: ["network.fetch", "shell.exec"],
    finding_ids: ["network.metadata_endpoint"], action: "deny", reason: "Instance metadata endpoints hand out cloud credentials",
  },
  mcp: {
    ...EMPTY_RULE, id: "warn-mcp-calls", name: "Warn on MCP tool calls", event_types: ["mcp.call"], action: "warn",
    reason: "MCP calls go directly to the server; only the arguments are visible",
  },
};
