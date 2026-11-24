//! AgentShield event model.
//!
//! Every adapter turns agent-specific hook payloads into a [`NormalizedEvent`]. All
//! downstream components (risk engine, policy engine, audit log, GUI) only see this model.
//! Strings in here are *untrusted data* until redacted by the core pipeline.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Version of the serialized event schema stored in the audit log.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// Operational mode of AgentShield. Default after installation: [`Mode::Monitor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Observe, never block.
    #[default]
    Monitor,
    /// Simulate the policy; record what *would* happen; never block.
    Shadow,
    /// Delegate risky actions to the agent's native approval prompt.
    Interactive,
    /// Enforce policy on supported pre-execution surfaces.
    Enforce,
    /// Emergency: deny all risky / mutating actions on supported surfaces.
    Lockdown,
}

impl Mode {
    pub const ALL: [Mode; 5] = [
        Mode::Monitor,
        Mode::Shadow,
        Mode::Interactive,
        Mode::Enforce,
        Mode::Lockdown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Monitor => "monitor",
            Mode::Shadow => "shadow",
            Mode::Interactive => "interactive",
            Mode::Enforce => "enforce",
            Mode::Lockdown => "lockdown",
        }
    }

    /// Whether AgentShield may ever influence the agent's decision in this mode.
    pub fn can_block(self) -> bool {
        matches!(self, Mode::Interactive | Mode::Enforce | Mode::Lockdown)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "monitor" => Ok(Mode::Monitor),
            "shadow" => Ok(Mode::Shadow),
            "interactive" => Ok(Mode::Interactive),
            "enforce" => Ok(Mode::Enforce),
            "lockdown" => Ok(Mode::Lockdown),
            other => Err(format!(
                "unknown mode '{other}' (expected monitor, shadow, interactive, enforce or lockdown)"
            )),
        }
    }
}

/// Decision produced by the policy engine, independent of mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Warn,
    Ask,
    RequireSandbox,
    Deny,
}

impl PolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Warn => "warn",
            PolicyDecision::Ask => "ask",
            PolicyDecision::RequireSandbox => "require_sandbox",
            PolicyDecision::Deny => "deny",
        }
    }
    /// Strictness rank used for precedence: higher wins.
    pub fn rank(self) -> u8 {
        match self {
            PolicyDecision::Allow => 0,
            PolicyDecision::Warn => 1,
            PolicyDecision::Ask => 2,
            PolicyDecision::RequireSandbox => 3,
            PolicyDecision::Deny => 4,
        }
    }
}

impl std::str::FromStr for PolicyDecision {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(PolicyDecision::Allow),
            "warn" => Ok(PolicyDecision::Warn),
            "ask" => Ok(PolicyDecision::Ask),
            "require_sandbox" => Ok(PolicyDecision::RequireSandbox),
            "deny" => Ok(PolicyDecision::Deny),
            other => Err(format!("unknown decision '{other}'")),
        }
    }
}

/// What AgentShield actually told the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualDecision {
    /// No output; the agent's native flow decides. (AgentShield never sends an explicit "allow".)
    NoOpinion,
    /// Agent was told to ask the user via its native approval prompt.
    Ask,
    /// Agent was told to deny the action.
    Deny,
    /// Event was not a decision point (post-execution, lifecycle).
    NotApplicable,
}

impl ActualDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            ActualDecision::NoOpinion => "no_opinion",
            ActualDecision::Ask => "ask",
            ActualDecision::Deny => "deny",
            ActualDecision::NotApplicable => "not_applicable",
        }
    }
}

/// Phase of the event relative to execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Intended action, before execution (a decision point if the hook supports it).
    Pre,
    /// Confirmed execution result reported by the agent.
    Post,
    /// Session / lifecycle / notification events.
    Lifecycle,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Pre => "pre",
            Phase::Post => "post",
            Phase::Lifecycle => "lifecycle",
        }
    }
}

/// Execution outcome as far as AgentShield knows. Intent and confirmed execution are
/// kept strictly separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Pre-execution event; outcome not (yet) known.
    Pending,
    /// Agent reported the tool ran successfully.
    Executed,
    /// Agent reported the tool ran and failed.
    Failed,
    /// AgentShield denied it on a pre-execution surface.
    Blocked,
    /// AgentShield asked the agent to prompt the user; result unknown until a post event.
    AskedUser,
    /// Not applicable (lifecycle).
    NotApplicable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Pending => "pending",
            Outcome::Executed => "executed",
            Outcome::Failed => "failed",
            Outcome::Blocked => "blocked",
            Outcome::AskedUser => "asked_user",
            Outcome::NotApplicable => "not_applicable",
        }
    }
}

/// How well the surface that produced this event is covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Pre-execution hook with a documented, tested deny path.
    Enforceable,
    /// Observed only (post-execution, or hook without deny semantics).
    Observed,
    /// Partially visible (e.g. dynamic shell content that cannot be resolved statically).
    Partial,
    /// AgentShield ran degraded (daemon unreachable, policy failed to load, ...).
    Degraded,
}

impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Coverage::Enforceable => "enforceable",
            Coverage::Observed => "observed",
            Coverage::Partial => "partial",
            Coverage::Degraded => "degraded",
        }
    }
}

/// Shell dialect of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    #[default]
    Bash,
    PowerShell,
    Cmd,
    Unknown,
}

/// Normalized action category. Policy `event_types` match on [`ActionKind::type_name`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionKind {
    ShellExec {
        command: String,
        shell: ShellKind,
    },
    FileRead {
        path: String,
    },
    FileWrite {
        path: String,
        content_len: Option<usize>,
    },
    FileEdit {
        path: String,
    },
    FileSearch {
        pattern: String,
        path: Option<String>,
    },
    NetworkFetch {
        url: String,
    },
    WebSearch {
        query: String,
    },
    McpCall {
        server: String,
        tool: String,
    },
    SubAgent {
        description: String,
    },
    UserPrompt {
        length: usize,
    },
    SessionStart {
        source: String,
    },
    SessionEnd {
        reason: String,
    },
    Notification {
        message: String,
    },
    Stop,
    PermissionRequest {
        tool: String,
    },
    PermissionDenied {
        tool: String,
    },
    ModeChange {
        from: Mode,
        to: Mode,
    },
    OtherTool {
        tool: String,
    },
}

impl ActionKind {
    /// All type names, for policy validation.
    pub const TYPE_NAMES: [&'static str; 18] = [
        "shell.exec",
        "file.read",
        "file.write",
        "file.edit",
        "file.search",
        "network.fetch",
        "network.search",
        "mcp.call",
        "agent.subagent",
        "agent.prompt",
        "session.start",
        "session.end",
        "agent.notification",
        "agent.stop",
        "agent.permission_request",
        "agent.permission_denied",
        "agentshield.mode_change",
        "tool.other",
    ];

    /// Stable dotted type name used in policies and the database.
    pub fn type_name(&self) -> &'static str {
        match self {
            ActionKind::ShellExec { .. } => "shell.exec",
            ActionKind::FileRead { .. } => "file.read",
            ActionKind::FileWrite { .. } => "file.write",
            ActionKind::FileEdit { .. } => "file.edit",
            ActionKind::FileSearch { .. } => "file.search",
            ActionKind::NetworkFetch { .. } => "network.fetch",
            ActionKind::WebSearch { .. } => "network.search",
            ActionKind::McpCall { .. } => "mcp.call",
            ActionKind::SubAgent { .. } => "agent.subagent",
            ActionKind::UserPrompt { .. } => "agent.prompt",
            ActionKind::SessionStart { .. } => "session.start",
            ActionKind::SessionEnd { .. } => "session.end",
            ActionKind::Notification { .. } => "agent.notification",
            ActionKind::Stop => "agent.stop",
            ActionKind::PermissionRequest { .. } => "agent.permission_request",
            ActionKind::PermissionDenied { .. } => "agent.permission_denied",
            ActionKind::ModeChange { .. } => "agentshield.mode_change",
            ActionKind::OtherTool { .. } => "tool.other",
        }
    }

    /// Paths this action targets (for path-glob policy matching).
    pub fn paths(&self) -> Vec<&str> {
        match self {
            ActionKind::FileRead { path }
            | ActionKind::FileWrite { path, .. }
            | ActionKind::FileEdit { path } => vec![path.as_str()],
            ActionKind::FileSearch { path: Some(p), .. } => vec![p.as_str()],
            _ => Vec::new(),
        }
    }

    /// Whether the action may mutate state. Used by Lockdown and Read Only.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            ActionKind::ShellExec { .. }
                | ActionKind::FileWrite { .. }
                | ActionKind::FileEdit { .. }
                | ActionKind::McpCall { .. }
                | ActionKind::SubAgent { .. }
                | ActionKind::OtherTool { .. }
        )
    }
}

/// Risk categories (spec §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    DestructiveOperation,
    CredentialExposure,
    SecretAccess,
    DataExfiltration,
    PrivilegeEscalation,
    UnsafeNetworkAccess,
    SupplyChainCompromise,
    SuspiciousPackageInstallation,
    McpToolPoisoning,
    PromptInjectionIndicator,
    UnauthorizedFileChange,
    GitRepositoryDamage,
    InfrastructureModification,
    PersistenceIndicator,
    SecurityConfigurationChange,
    AgentConfigurationTampering,
    DatabaseDestructive,
    ObfuscatedExecution,
}

impl RiskCategory {
    pub const ALL: [RiskCategory; 18] = [
        RiskCategory::DestructiveOperation,
        RiskCategory::CredentialExposure,
        RiskCategory::SecretAccess,
        RiskCategory::DataExfiltration,
        RiskCategory::PrivilegeEscalation,
        RiskCategory::UnsafeNetworkAccess,
        RiskCategory::SupplyChainCompromise,
        RiskCategory::SuspiciousPackageInstallation,
        RiskCategory::McpToolPoisoning,
        RiskCategory::PromptInjectionIndicator,
        RiskCategory::UnauthorizedFileChange,
        RiskCategory::GitRepositoryDamage,
        RiskCategory::InfrastructureModification,
        RiskCategory::PersistenceIndicator,
        RiskCategory::SecurityConfigurationChange,
        RiskCategory::AgentConfigurationTampering,
        RiskCategory::DatabaseDestructive,
        RiskCategory::ObfuscatedExecution,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RiskCategory::DestructiveOperation => "destructive_operation",
            RiskCategory::CredentialExposure => "credential_exposure",
            RiskCategory::SecretAccess => "secret_access",
            RiskCategory::DataExfiltration => "data_exfiltration",
            RiskCategory::PrivilegeEscalation => "privilege_escalation",
            RiskCategory::UnsafeNetworkAccess => "unsafe_network_access",
            RiskCategory::SupplyChainCompromise => "supply_chain_compromise",
            RiskCategory::SuspiciousPackageInstallation => "suspicious_package_installation",
            RiskCategory::McpToolPoisoning => "mcp_tool_poisoning",
            RiskCategory::PromptInjectionIndicator => "prompt_injection_indicator",
            RiskCategory::UnauthorizedFileChange => "unauthorized_file_change",
            RiskCategory::GitRepositoryDamage => "git_repository_damage",
            RiskCategory::InfrastructureModification => "infrastructure_modification",
            RiskCategory::PersistenceIndicator => "persistence_indicator",
            RiskCategory::SecurityConfigurationChange => "security_configuration_change",
            RiskCategory::AgentConfigurationTampering => "agent_configuration_tampering",
            RiskCategory::DatabaseDestructive => "database_destructive",
            RiskCategory::ObfuscatedExecution => "obfuscated_execution",
        }
    }
}

impl std::str::FromStr for RiskCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RiskCategory::ALL
            .into_iter()
            .find(|c| c.as_str() == s.trim())
            .ok_or_else(|| format!("unknown risk category '{s}'"))
    }
}

/// Risk level bands (spec §9). A score is a policy classification, not a probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => RiskLevel::Informational,
            20..=39 => RiskLevel::Low,
            40..=59 => RiskLevel::Medium,
            60..=79 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Informational => "informational",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// Detection confidence, stored separately from the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// One explainable detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable detector id, e.g. `shell.rm_recursive_root`.
    pub id: String,
    pub category: RiskCategory,
    pub score: u8,
    pub confidence: Confidence,
    /// Human readable explanation.
    pub explanation: String,
    /// Redacted evidence snippet.
    pub evidence: Option<String>,
    /// Suggested safer alternative, if any.
    pub mitigation: Option<String>,
}

/// Complete, explainable risk assessment of one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u8,
    pub level: RiskLevel,
    pub confidence: Confidence,
    pub categories: Vec<RiskCategory>,
    pub findings: Vec<Finding>,
    /// Step by step explanation of how the score was computed.
    pub explanation: Vec<String>,
    /// Things that could not be determined statically (lowers confidence).
    pub uncertainties: Vec<String>,
}

impl RiskAssessment {
    pub fn none() -> Self {
        RiskAssessment {
            score: 0,
            level: RiskLevel::Informational,
            confidence: Confidence::High,
            categories: Vec::new(),
            findings: Vec::new(),
            explanation: vec!["No detector matched.".into()],
            uncertainties: Vec::new(),
        }
    }
}

/// Agent identity and context as *claimed* by the hook payload (telemetry, not authenticated).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentContext {
    /// Adapter id, e.g. `claude-code`.
    pub agent: String,
    pub agent_version: Option<String>,
    pub session_id: Option<String>,
    /// Working directory / project root reported by the agent.
    pub workspace: Option<String>,
    /// Agent's native permission mode, if reported (e.g. `default`, `acceptEdits`).
    pub permission_mode: Option<String>,
    /// Native hook event name, e.g. `PreToolUse`.
    pub hook_event: String,
    /// Native tool name, e.g. `Bash`.
    pub tool: Option<String>,
    /// Native id linking pre and post events (e.g. Claude Code `tool_use_id`).
    pub correlation_id: Option<String>,
}

/// An agent event after adapter normalization (not yet redacted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub ctx: AgentContext,
    pub phase: Phase,
    pub action: ActionKind,
    /// Tool input as JSON (redacted by the core before storage).
    pub input: serde_json::Value,
    /// For post events: whether the tool reported an error.
    pub post_failed: Option<bool>,
    /// For post events: tool response text (used only for secret detection; never stored raw).
    pub response_text: Option<String>,
    /// Whether this event is a decision point that the adapter can actually enforce.
    pub enforceable: bool,
}

/// The fully evaluated record that ends up in the audit log and the GUI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Database row id (0 before insert).
    pub id: i64,
    pub uuid: String,
    pub schema_version: u32,
    /// RFC 3339 UTC timestamp.
    pub ts_utc: String,
    pub agent: String,
    pub agent_version: Option<String>,
    pub session_id: Option<String>,
    pub workspace: Option<String>,
    pub hook_event: String,
    pub phase: Phase,
    pub action_type: String,
    pub tool: Option<String>,
    /// Short redacted one-line summary for tables.
    pub summary: String,
    /// Redacted action.
    pub action: ActionKind,
    /// Redacted input.
    pub input_redacted: serde_json::Value,
    pub risk: RiskAssessment,
    pub policy_version: String,
    pub policy_name: String,
    pub matched_rules: Vec<String>,
    pub mode: Mode,
    pub simulated_decision: PolicyDecision,
    pub decision_reason: Option<String>,
    pub actual_decision: ActualDecision,
    pub outcome: Outcome,
    pub coverage: Coverage,
    pub latency_us: u64,
    pub correlation_id: Option<String>,
    /// True when evaluated by the daemon, false when the hook used the local fallback.
    pub via_daemon: bool,
    pub prev_hash: String,
    pub hash: String,
}

/// Generate a new random event UUID.
pub fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current time as RFC 3339 UTC with millisecond precision.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_bands() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Informational);
        assert_eq!(RiskLevel::from_score(19), RiskLevel::Informational);
        assert_eq!(RiskLevel::from_score(20), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(40), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(60), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(80), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    #[test]
    fn mode_roundtrip() {
        for m in Mode::ALL {
            assert_eq!(m.as_str().parse::<Mode>().unwrap(), m);
            let j = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<Mode>(&j).unwrap(), m);
        }
        assert!("MONITOR".parse::<Mode>().is_ok());
        assert!("off".parse::<Mode>().is_err());
        assert_eq!(Mode::default(), Mode::Monitor);
    }

    #[test]
    fn only_blocking_modes_can_block() {
        assert!(!Mode::Monitor.can_block());
        assert!(!Mode::Shadow.can_block());
        assert!(Mode::Interactive.can_block());
        assert!(Mode::Enforce.can_block());
        assert!(Mode::Lockdown.can_block());
    }

    #[test]
    fn category_roundtrip() {
        for c in RiskCategory::ALL {
            assert_eq!(c.as_str().parse::<RiskCategory>().unwrap(), c);
            let j = serde_json::to_value(c).unwrap();
            assert_eq!(j.as_str().unwrap(), c.as_str());
        }
        assert!("nope".parse::<RiskCategory>().is_err());
    }

    #[test]
    fn type_names_complete() {
        let samples = [
            ActionKind::Stop,
            ActionKind::ShellExec {
                command: "x".into(),
                shell: ShellKind::Bash,
            },
            ActionKind::OtherTool { tool: "x".into() },
        ];
        for s in samples {
            assert!(ActionKind::TYPE_NAMES.contains(&s.type_name()));
        }
    }

    #[test]
    fn decision_rank_order() {
        assert!(PolicyDecision::Deny.rank() > PolicyDecision::RequireSandbox.rank());
        assert!(PolicyDecision::RequireSandbox.rank() > PolicyDecision::Ask.rank());
        assert!(PolicyDecision::Ask.rank() > PolicyDecision::Warn.rank());
        assert!(PolicyDecision::Warn.rank() > PolicyDecision::Allow.rank());
    }
}
