import type {
  ActualDecision, CapabilityState, Confidence, Coverage, Mode, Outcome, PolicyDecision, RiskCategory, RiskLevel,
} from "../lib/types";

// All colours are CSS custom properties (see styles.css) so dark/light swap in one place.
export const MODE_VAR: Record<Mode, string> = {
  monitor: "--mode-monitor",
  shadow: "--mode-shadow",
  interactive: "--mode-interactive",
  enforce: "--mode-enforce",
  lockdown: "--mode-lockdown",
};

export const LEVEL_VAR: Record<RiskLevel, string> = {
  informational: "--risk-informational",
  low: "--risk-low",
  medium: "--risk-medium",
  high: "--risk-high",
  critical: "--risk-critical",
};

export const LEVELS: RiskLevel[] = ["informational", "low", "medium", "high", "critical"];

export const DECISION_VAR: Record<PolicyDecision, string> = {
  allow: "--ok",
  warn: "--warn",
  ask: "--mode-interactive",
  require_sandbox: "--mode-shadow",
  deny: "--danger",
};

export const ACTUAL_VAR: Record<ActualDecision, string> = {
  no_opinion: "--fg-3",
  ask: "--mode-interactive",
  deny: "--danger",
  not_applicable: "--fg-3",
};

export const OUTCOME_VAR: Record<Outcome, string> = {
  pending: "--fg-3",
  executed: "--info",
  failed: "--warn",
  blocked: "--danger",
  asked_user: "--mode-interactive",
  not_applicable: "--fg-3",
};

export const COVERAGE_VAR: Record<Coverage, string> = {
  enforceable: "--ok",
  observed: "--info",
  partial: "--warn",
  degraded: "--danger",
};

export const CAPABILITY_VAR: Record<CapabilityState, string> = {
  enforced: "--ok",
  observed: "--info",
  partial: "--warn",
  unsupported: "--fg-3",
  unverified: "--mode-shadow",
  degraded: "--danger",
};

export const CONFIDENCE_VAR: Record<Confidence, string> = { low: "--fg-3", medium: "--fg-2", high: "--fg" };

// 18 categories are too many to tell apart by colour; charts colour by FAMILY (fixed order, never
// cycled) and name the exact category in labels/tooltips.
export type Family = "destructive" | "secrets" | "network" | "supply" | "agent" | "system" | "none";

export const FAMILIES: Family[] = ["network", "destructive", "supply", "secrets", "agent", "system", "none"];

export const FAMILY_VAR: Record<Family, string> = {
  network: "--series-1",
  destructive: "--series-2",
  supply: "--series-3",
  secrets: "--series-4",
  agent: "--series-5",
  system: "--series-6",
  none: "--series-7",
};

export const CATEGORY_FAMILY: Record<RiskCategory, Family> = {
  destructive_operation: "destructive",
  database_destructive: "destructive",
  git_repository_damage: "destructive",
  unauthorized_file_change: "destructive",
  credential_exposure: "secrets",
  secret_access: "secrets",
  data_exfiltration: "network",
  unsafe_network_access: "network",
  supply_chain_compromise: "supply",
  suspicious_package_installation: "supply",
  mcp_tool_poisoning: "agent",
  prompt_injection_indicator: "agent",
  agent_configuration_tampering: "agent",
  privilege_escalation: "system",
  persistence_indicator: "system",
  security_configuration_change: "system",
  infrastructure_modification: "system",
  obfuscated_execution: "system",
};

export const ALL_CATEGORIES = Object.keys(CATEGORY_FAMILY) as RiskCategory[];

export function familyOf(categories: readonly RiskCategory[]): Family {
  const first = categories[0];
  return first ? CATEGORY_FAMILY[first] : "none";
}

export function severityVar(severity: string): string {
  return severity === "critical" ? "--risk-critical" : severity === "high" ? "--risk-high" : severity === "medium" ? "--risk-medium" : "--risk-low";
}

/** `var(--x)` helper for inline `--tone`. */
export const v = (name: string): string => `var(${name})`;

/** Resolve a CSS variable to its concrete value (canvas charts cannot use var()). */
export function cssVar(name: string): string {
  if (typeof document === "undefined") return "#888";
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || "#888";
}
