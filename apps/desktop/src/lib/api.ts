// Typed wrappers around the Tauri commands implemented in src-tauri/src/commands.rs.
// Every call goes: GUI -> Tauri backend -> (authenticated local IPC) -> agentshield daemon.
// Calls reject with a string error message when the daemon is unreachable or a request fails.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AgentInfo, Config, EventQuery, EventRow, ExportFormat, ExportResult, Incident, InstallPlan,
  InstallResult, IntegrityReport, McpServerInfo, Mode, PolicyInfo, PresetInfo, ReplayResult,
  ReportKind, ReportResult, SelfTestResult, SessionSummary, SimInput, SimResult, Stats, Status,
  ValidationResult,
} from "./types";

export const api = {
  status: () => invoke<Status>("get_status"),
  startDaemon: () => invoke<Status>("start_daemon"),
  listEvents: (query: EventQuery) => invoke<EventRow[]>("list_events", { query }),
  getEvent: (id: number) => invoke<EventRow | null>("get_event", { id }),
  countEvents: (query: EventQuery) => invoke<number>("count_events", { query }),
  getSession: (sessionId: string) => invoke<SessionSummary | null>("get_session", { sessionId }),
  stats: (windowHours: number) => invoke<Stats>("get_stats", { windowHours }),
  sessions: (limit: number) => invoke<SessionSummary[]>("list_sessions", { limit }),
  incidents: (limit: number) => invoke<Incident[]>("list_incidents", { limit }),
  setMode: (mode: Mode) => invoke<Status>("set_mode", { mode }),
  setPreset: (preset: string) => invoke<Status>("set_preset", { preset }),
  setPaused: (paused: boolean) => invoke<Status>("set_paused", { paused }),
  presets: () => invoke<PresetInfo[]>("list_presets"),
  policy: () => invoke<PolicyInfo>("get_policy"),
  validatePolicy: (text: string) => invoke<ValidationResult>("validate_policy", { text }),
  saveUserPolicy: (text: string) => invoke<PolicyInfo>("save_user_policy", { text }),
  simulate: (input: SimInput) => invoke<SimResult>("simulate", { input }),
  replay: (preset: string, sessionId: string | null, limit: number) =>
    invoke<ReplayResult>("replay", { preset, sessionId, limit }),
  agents: () => invoke<AgentInfo[]>("agents_detect"),
  installPreview: (agentId: string, failClosed: boolean) =>
    invoke<InstallPlan>("agent_install_preview", { agentId, failClosed }),
  install: (agentId: string, failClosed: boolean) => invoke<InstallResult>("agent_install", { agentId, failClosed }),
  uninstall: (agentId: string) => invoke<InstallResult>("agent_uninstall", { agentId }),
  mcpServers: () => invoke<McpServerInfo[]>("mcp_servers"),
  verifyIntegrity: () => invoke<IntegrityReport>("verify_integrity"),
  exportEvents: (format: ExportFormat, query: EventQuery) => invoke<ExportResult>("export_events", { format, query }),
  generateReport: (kind: ReportKind, windowHours: number) =>
    invoke<ReportResult>("generate_report", { kind, windowHours }),
  config: () => invoke<Config>("get_config"),
  setConfig: (patch: Partial<Config>) => invoke<Config>("set_config", { patch }),
  deleteSession: (sessionId: string) => invoke<number>("delete_session", { sessionId }),
  deleteAllData: () => invoke<number>("delete_all_data"),
  selfTest: () => invoke<SelfTestResult>("self_test"),
  openPath: (path: string) => invoke<void>("open_path", { path }),
  backupDatabase: () => invoke<string>("backup_database"),
};

/** Live events pushed by the backend subscription (already redacted). */
export function onEvent(cb: (row: EventRow) => void): Promise<UnlistenFn> {
  return listen<EventRow>("agentshield://event", (e) => cb(e.payload));
}

/** Connection state of the live subscription: "connected" | "disconnected" | "lagged". */
export function onConnection(cb: (state: string) => void): Promise<UnlistenFn> {
  return listen<string>("agentshield://connection", (e) => cb(e.payload));
}

/** Tray menu actions forwarded to the UI (e.g. "open:approvals"). */
export function onTrayNavigate(cb: (route: string) => void): Promise<UnlistenFn> {
  return listen<string>("agentshield://navigate", (e) => cb(e.payload));
}
