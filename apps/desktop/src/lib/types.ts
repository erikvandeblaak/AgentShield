// AgentShield desktop ↔ backend contract.
// These types mirror the Rust serde shapes (crates/event-model, crates/audit-log,
// crates/policy-engine, crates/core, crates/ipc). Keep them in sync.
// All string content in events is ALREADY REDACTED by the backend; still render it as text
// (never as HTML) because it originates from untrusted agents/tools.

export type Mode = "monitor" | "shadow" | "interactive" | "enforce" | "lockdown";
export type PolicyDecision = "allow" | "warn" | "ask" | "require_sandbox" | "deny";
export type ActualDecision = "no_opinion" | "ask" | "deny" | "not_applicable";
export type Phase = "pre" | "post" | "lifecycle";
export type Outcome = "pending" | "executed" | "failed" | "blocked" | "asked_user" | "not_applicable";
export type Coverage = "enforceable" | "observed" | "partial" | "degraded";
export type RiskLevel = "informational" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type ShellKind = "bash" | "power_shell" | "cmd" | "unknown";

export type RiskCategory =
  | "destructive_operation" | "credential_exposure" | "secret_access" | "data_exfiltration"
  | "privilege_escalation" | "unsafe_network_access" | "supply_chain_compromise"
  | "suspicious_package_installation" | "mcp_tool_poisoning" | "prompt_injection_indicator"
  | "unauthorized_file_change" | "git_repository_damage" | "infrastructure_modification"
  | "persistence_indicator" | "security_configuration_change" | "agent_configuration_tampering"
  | "database_destructive" | "obfuscated_execution";

export type ActionKind =
  | { type: "shell_exec"; command: string; shell: ShellKind }
  | { type: "file_read"; path: string }
  | { type: "file_write"; path: string; content_len: number | null }
  | { type: "file_edit"; path: string }
  | { type: "file_search"; pattern: string; path: string | null }
  | { type: "network_fetch"; url: string }
  | { type: "web_search"; query: string }
  | { type: "mcp_call"; server: string; tool: string }
  | { type: "sub_agent"; description: string }
  | { type: "user_prompt"; length: number }
  | { type: "session_start"; source: string }
  | { type: "session_end"; reason: string }
  | { type: "notification"; message: string }
  | { type: "stop" }
  | { type: "permission_request"; tool: string }
  | { type: "permission_denied"; tool: string }
  | { type: "mode_change"; from: Mode; to: Mode }
  | { type: "other_tool"; tool: string };

export interface Finding {
  id: string; // e.g. "shell.rm_recursive_root"
  category: RiskCategory;
  score: number; // 0-100
  confidence: Confidence;
  explanation: string;
  evidence: string | null; // redacted
  mitigation: string | null;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  confidence: Confidence;
  categories: RiskCategory[];
  findings: Finding[];
  explanation: string[]; // step-by-step score explanation
  uncertainties: string[];
}

export interface AuditRecord {
  id: number;
  uuid: string;
  schema_version: number;
  ts_utc: string; // RFC3339 UTC; display in local time
  agent: string; // "claude-code"
  agent_version: string | null;
  session_id: string | null;
  workspace: string | null;
  hook_event: string; // native, e.g. "PreToolUse"
  phase: Phase;
  action_type: string; // "shell.exec", "file.read", ...
  tool: string | null; // "Bash", "Read", "mcp__github__create_issue"
  summary: string; // one-line, redacted
  action: ActionKind;
  input_redacted: unknown; // JSON
  risk: RiskAssessment;
  policy_version: string;
  policy_name: string;
  matched_rules: string[];
  mode: Mode; // mode at the time of the event
  simulated_decision: PolicyDecision; // what the policy says (would ...)
  decision_reason: string | null;
  actual_decision: ActualDecision; // what AgentShield actually told the agent
  outcome: Outcome;
  coverage: Coverage;
  latency_us: number;
  correlation_id: string | null;
  via_daemon: boolean;
  prev_hash: string;
  hash: string;
}

export interface EventRow {
  record: AuditRecord;
  observed_outcome: Outcome | null; // from the matching post event, if any
}

export interface EventQuery {
  after_id?: number;
  before_id?: number;
  limit?: number;
  agent?: string;
  session_id?: string;
  workspace?: string;
  action_type?: string;
  phase?: Phase;
  min_score?: number;
  category?: RiskCategory;
  simulated_decision?: PolicyDecision;
  actual_decision?: ActualDecision;
  search?: string;
  since?: string;
  correlation_id?: string;
  secrets_only?: boolean;
  packages_only?: boolean;
  network_only?: boolean;
  mcp_only?: boolean;
}

export interface CountItem { key: string; count: number }
export interface Bucket { key: string; count: number; max_score: number; risky: number }

export interface Stats {
  total_events: number;
  events_in_window: number;
  window_hours: number;
  risky_events: number; // score >= 40
  would_block: number; // simulated deny / require_sandbox on pre events
  would_ask: number;
  actually_blocked: number;
  actually_asked: number;
  degraded_events: number;
  dropped_events: number;
  by_level: CountItem[];
  by_category: CountItem[];
  by_agent: CountItem[];
  by_action: CountItem[];
  top_workspaces: CountItem[];
  per_minute: Bucket[]; // key "YYYY-MM-DDTHH:MM" (UTC), last 60 min
  per_hour: Bucket[]; // key "YYYY-MM-DDTHH" (UTC), window
  heatmap: Bucket[]; // key "d:h" d=0(Sun)..6, h=0..23 (UTC), last 28 days
  active_sessions: number;
  first_event: string | null;
  last_event: string | null;
}

export interface SessionSummary {
  session_id: string;
  agent: string;
  workspace: string | null;
  first_ts: string;
  last_ts: string;
  events: number;
  max_score: number;
  would_block: number;
  blocked: number;
  ended: boolean;
}

export interface Incident {
  id: number;
  ts_utc: string;
  session_id: string | null;
  rule_id: string;
  title: string;
  severity: string; // "medium" | "high" | "critical"
  score: number;
  confidence: string;
  explanation: string; // always states correlation ≠ proven causality
  event_ids: number[]; // evidence: navigate to these events
}

export interface IntegrityReport {
  checked: number;
  ok: boolean;
  bridged_breaks: number;
  first_bad_id: number | null;
  problem: string | null;
  sqlite_integrity: string;
}

export interface LatencySummary { count: number; p50_us: number; p95_us: number; p99_us: number; max_us: number }

export type CapabilityState = "enforced" | "observed" | "partial" | "unsupported" | "unverified" | "degraded";

export interface Capability {
  capability: string; // e.g. "Shell monitoring"
  status: CapabilityState;
  reason: string; // why (always filled for non-"enforced")
}

export interface IntegrationState {
  installed: boolean; // our hooks present in the agent config
  verified: boolean; // all expected hook entries present & binary exists
  settings_path: string;
  events: string[]; // hook events we are registered for
  missing_events: string[];
  fail_closed: boolean;
  binary_path: string | null;
  problems: string[];
}

export interface AgentInfo {
  id: string; // "claude-code"
  name: string;
  detected: boolean;
  version: string | null;
  executable: string | null;
  supported: boolean; // false => shown as "not supported" in the matrix
  experimental: boolean;
  integration: IntegrationState | null;
  capabilities: Capability[];
  last_event: string | null;
  notes: string[];
}

export interface Status {
  daemon_running: boolean;
  daemon_version: string | null;
  pid: number | null;
  uptime_s: number | null;
  mode: Mode;
  preset: string;
  paused: boolean;
  policy_name: string;
  policy_version: string;
  policy_warnings: string[];
  events_total: number;
  dropped_events: number;
  hook_latency: LatencySummary;
  eval_latency: LatencySummary;
  degraded: boolean;
  degraded_reasons: string[];
  data_dir: string;
  config_dir: string;
  db_path: string;
  version: string; // AgentShield version
  build: string; // git/profile info
}

export interface PresetInfo { id: string; title: string; description: string; text: string }

export interface RuleSummary {
  id: string;
  name: string | null;
  decision: PolicyDecision;
  enabled: boolean;
  hard: boolean;
  layer: "preset" | "user" | "project";
}

export interface PolicyInfo {
  name: string;
  version: string;
  thresholds: { warn_at: number | null; ask_at: number | null; deny_at: number | null };
  rules: RuleSummary[];
  warnings: string[];
  sources: [string, string][];
  user_policy_path: string;
  user_policy_text: string; // editable layer (empty template if none)
}

export interface ValidationResult { ok: boolean; warnings: string[]; error: string | null }

export interface RuleMatch {
  id: string;
  name: string | null;
  decision: PolicyDecision;
  hard: boolean;
  reason: string | null;
  suggestion: string | null;
  layer: "preset" | "user" | "project";
  source: string;
}

export interface PolicyOutcome {
  decision: PolicyDecision;
  hard: boolean;
  matched: RuleMatch[];
  reason: string;
  suggestion: string | null;
  policy_version: string;
  policy_name: string;
  threshold: string | null;
}

export interface ModeOutcome { actual: ActualDecision; message: string | null }

export interface ParsedSegment {
  program: string;
  raw_program: string;
  args: string[];
  redirections: { op: string; target: string }[];
  wrappers: string[];
  env_assignments: string[];
  pipes_to_next: boolean;
  piped_from_prev: boolean;
}

export interface ParsedCommand {
  shell: ShellKind;
  segments: ParsedSegment[];
  operators: string[];
  nested: ParsedCommand[];
  decoded_payloads: string[];
  inline_code: string[];
  uncertainties: string[];
  syntax_errors: string[];
}

export interface SimInput {
  command?: string; // shell command (simulated tool: Bash/PowerShell)
  shell?: "bash" | "power_shell" | "cmd";
  tool?: string; // OR a structured tool call, e.g. "Read", "Write", "WebFetch", "mcp__x__y"
  tool_input?: unknown; // JSON for the tool call
  preset?: string; // default: active preset
  workspace?: string;
}

export interface SimResult {
  summary: string; // redacted
  action_type: string;
  parsed: ParsedCommand | null;
  risk: RiskAssessment;
  policy: PolicyOutcome;
  modes: Record<Mode, ModeOutcome>;
  limitations: string[];
  sensitive_targets: string[];
}

export interface ReplayChange { event_id: number; summary: string; before: PolicyDecision; after: PolicyDecision }

export interface ReplayResult {
  preset: string;
  evaluated: number;
  by_decision: Record<PolicyDecision, number>;
  original_by_decision: Record<PolicyDecision, number>;
  changed: ReplayChange[];
}

export interface McpServerInfo {
  name: string;
  scope: string; // "user" | "project" | "local" | "plugin"
  source: string; // config file path
  transport: string; // "stdio" | "http" | "sse" | "unknown"
  command: string | null; // redacted
  args: string[]; // redacted
  url_host: string | null;
  env_keys: string[]; // only names, never values
  fingerprint: string; // config hash
  changed_since_last_seen: boolean;
  first_seen: string | null;
  routed_via_agentshield: boolean; // always false for now (no proxy configured)
  findings: Finding[];
  observed_calls: number;
  tools_seen: string[];
}

export interface Config {
  mode: Mode;
  preset: string;
  paused: boolean;
  retention_days: number;
  language: "en" | "nl";
  theme: "dark" | "light" | "system";
  notifications: boolean;
  correlation_window_minutes: number;
}

export interface ExportResult { path: string; count: number }
export interface ReportResult { path: string; title: string }

export type ExportFormat = "json" | "csv" | "sarif" | "html";
export type ReportKind = "daily" | "weekly" | "project" | "agent_comparison" | "shadow" | "incident" | "coverage";

export interface InstallPlan {
  agent_id: string;
  settings_path: string;
  changes: string[]; // human-readable
  before: string; // pretty JSON of the hooks section before
  after: string; // pretty JSON after
  already_installed: boolean;
  backup_dir: string;
}

export interface InstallResult { ok: boolean; message: string; backup_path: string | null; verified: boolean; problems: string[] }

export interface SelfTestResult { ok: boolean; event_id: number | null; latency_ms: number; message: string; decision: ActualDecision | null }
