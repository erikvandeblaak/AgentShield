//! AgentShield core: the evaluation pipeline shared by the daemon and the hook fallback.
//!
//! ```text
//! NormalizedEvent → correlation (recent session events) → risk engine → policy engine
//!   → mode decision → redaction → AuditRecord
//! ```
//!
//! The pipeline is pure (no I/O) except for reading policy files, so the daemon and the
//! hook fallback produce identical decisions for the same input.

pub mod config;
pub mod correlation;
pub mod paths;

pub use config::{Config, ConfigError, ConfigPatch};
pub use paths::Paths;

use agentshield_event_model::*;
use agentshield_policy_engine::{
    LayerKind, ModeOutcome, PolicyOutcome, PolicySet, PolicySetBuilder, apply_mode, preset_text,
};
use agentshield_risk_engine::RiskContext;
use agentshield_secret_detector::{Redactor, truncate};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Max bytes of any single string stored in `input_redacted`.
pub const MAX_STORED_STRING: usize = 4096;

/// Load or create the per-install fingerprint key.
pub fn load_or_create_key(paths: &Paths) -> std::io::Result<[u8; 32]> {
    let p = paths.key_file();
    if let Ok(bytes) = std::fs::read(&p)
        && bytes.len() == 32
    {
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        return Ok(k);
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::create_dir_all(&paths.data_dir)?;
    paths::write_atomic(&p, &k)?;
    let _ = paths::restrict_file(&p);
    Ok(k)
}

/// Result of evaluating one event.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub record: AuditRecord,
    pub mode_outcome: ModeOutcome,
    pub policy: PolicyOutcome,
}

/// Policy cache keyed by (preset, user policy mtime, project policy path+mtime).
struct PolicyCache {
    key: String,
    set: PolicySet,
}

/// The evaluation engine. Cheap to share behind an `Arc`; policy sets are cached.
pub struct Engine {
    pub paths: Paths,
    redactor: Redactor,
    home: Option<String>,
    cache: std::sync::Mutex<Vec<PolicyCache>>,
}

fn mtime(p: &Path) -> String {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| format!("{:?}", t))
        .unwrap_or_else(|_| "none".into())
}

impl Engine {
    pub fn new(paths: Paths, key: [u8; 32]) -> Self {
        Engine {
            paths,
            redactor: Redactor::new(key),
            home: dirs::home_dir().map(|h| h.to_string_lossy().into_owned()),
            cache: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    fn project_policy(workspace: Option<&str>) -> Option<PathBuf> {
        let ws = workspace?;
        let p = Path::new(ws).join(".agentshield").join("policy.toml");
        p.is_file().then_some(p)
    }

    /// Build (or reuse) the layered policy set for a preset and workspace.
    pub fn policy_set(&self, preset: &str, workspace: Option<&str>) -> Result<PolicySet, String> {
        let user = self.paths.user_policy_file();
        let project = Self::project_policy(workspace);
        let key = format!(
            "{preset}|{}|{}|{}",
            mtime(&user),
            project
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            project.as_ref().map(|p| mtime(p)).unwrap_or_default()
        );
        if let Ok(c) = self.cache.lock()
            && let Some(hit) = c.iter().find(|c| c.key == key)
        {
            return Ok(hit.set.clone());
        }
        let text = preset_text(preset).ok_or_else(|| format!("unknown preset '{preset}'"))?;
        let mut b =
            PolicySetBuilder::new().layer(LayerKind::Preset, format!("preset:{preset}"), text);
        if let Ok(t) = std::fs::read_to_string(&user) {
            b = b.layer(LayerKind::User, user.display().to_string(), t);
        }
        if let Some(p) = &project {
            // Project files are untrusted: cap size.
            match std::fs::metadata(p) {
                Ok(m) if m.len() <= 256 * 1024 => {
                    if let Ok(t) = std::fs::read_to_string(p) {
                        b = b.layer(LayerKind::Project, p.display().to_string(), t);
                    }
                }
                _ => {}
            }
        }
        let set = b.build().map_err(|e| e.to_string())?;
        if let Ok(mut c) = self.cache.lock() {
            if c.len() > 32 {
                c.clear();
            }
            c.push(PolicyCache {
                key,
                set: set.clone(),
            });
        }
        Ok(set)
    }

    fn risk_context(&self, ev: &NormalizedEvent) -> RiskContext {
        RiskContext {
            workspace: ev.ctx.workspace.clone(),
            home: self.home.clone(),
        }
    }

    /// Build a record for an event whose findings were computed elsewhere (e.g. the MCP
    /// proxy's tool-definition analysis). Goes through the same policy, redaction and record
    /// path as every other event; never a decision point.
    pub fn record_with_findings(
        &self,
        ev: &NormalizedEvent,
        findings: Vec<Finding>,
        cfg: &Config,
        started: Instant,
    ) -> AuditRecord {
        let risk = agentshield_risk_engine::finalize(findings, Vec::new());
        let set = self
            .policy_set(&cfg.preset, ev.ctx.workspace.as_deref())
            .or_else(|_| PolicySet::from_preset("developer-balanced").map_err(|e| e.to_string()))
            .unwrap_or_else(|_| unreachable_policy());
        let policy = set.evaluate(ev, &risk);
        let mode = if cfg.paused { Mode::Monitor } else { cfg.mode };
        let mo = apply_mode(mode, &policy, ev, &risk);
        self.build_record(ev, risk, &policy, &mo, mode, true, &[], started)
    }

    /// Evaluate a normalized event.
    ///
    /// * `recent` — recent records of the same session (newest first) for correlation.
    /// * `degraded` — reasons the evaluation is degraded (e.g. daemon unreachable).
    pub fn evaluate(
        &self,
        ev: &NormalizedEvent,
        cfg: &Config,
        recent: &[AuditRecord],
        via_daemon: bool,
        degraded: &[String],
        started: Instant,
    ) -> Evaluation {
        let mut risk = agentshield_risk_engine::assess(ev, &self.risk_context(ev), &self.redactor);
        let corr = correlation::correlate(ev, &risk, recent, cfg.correlation_window_minutes);
        if !corr.is_empty() {
            let mut findings = risk.findings.clone();
            findings.extend(corr);
            risk = agentshield_risk_engine::finalize(findings, risk.uncertainties.clone());
        }
        let mut policy_errors = Vec::new();
        let set = match self.policy_set(&cfg.preset, ev.ctx.workspace.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                policy_errors.push(format!("policy error: {e}"));
                // Fall back to the built-in preset alone (never to "no policy").
                PolicySet::from_preset(&cfg.preset)
                    .or_else(|_| PolicySet::from_preset("developer-balanced"))
                    .unwrap_or_else(|_| {
                        PolicySetBuilder::new()
                            .layer(LayerKind::Preset, "empty", "schema_version = 1")
                            .build()
                            .unwrap_or_else(|_| unreachable_policy())
                    })
            }
        };
        let policy = set.evaluate(ev, &risk);
        let mode = if cfg.paused { Mode::Monitor } else { cfg.mode };
        let mode_outcome = apply_mode(mode, &policy, ev, &risk);
        let mut all_degraded: Vec<String> = degraded.to_vec();
        all_degraded.extend(policy_errors);
        let record = self.build_record(
            ev,
            risk,
            &policy,
            &mode_outcome,
            mode,
            via_daemon,
            &all_degraded,
            started,
        );
        Evaluation {
            record,
            mode_outcome,
            policy,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_record(
        &self,
        ev: &NormalizedEvent,
        mut risk: RiskAssessment,
        policy: &PolicyOutcome,
        mo: &ModeOutcome,
        mode: Mode,
        via_daemon: bool,
        degraded: &[String],
        started: Instant,
    ) -> AuditRecord {
        // Redact findings evidence.
        for f in &mut risk.findings {
            if let Some(e) = &f.evidence {
                f.evidence = Some(truncate(&self.redactor.redact(e).0, 300));
            }
            f.explanation = self.redactor.redact(&f.explanation).0;
        }
        let action = self.redact_action(&ev.action);
        let input_redacted = self.redact_input(ev);
        let outcome = match (ev.phase, mo.actual) {
            (Phase::Pre, ActualDecision::Deny) => Outcome::Blocked,
            (Phase::Pre, ActualDecision::Ask) => Outcome::AskedUser,
            (Phase::Pre, _) => Outcome::Pending,
            (Phase::Post, _) => {
                if ev.post_failed == Some(true) {
                    Outcome::Failed
                } else {
                    Outcome::Executed
                }
            }
            (Phase::Lifecycle, _) => Outcome::NotApplicable,
        };
        let coverage = if !degraded.is_empty() {
            Coverage::Degraded
        } else if ev.phase == Phase::Pre && ev.enforceable {
            if risk.uncertainties.is_empty() {
                Coverage::Enforceable
            } else {
                Coverage::Partial
            }
        } else {
            Coverage::Observed
        };
        let mut reason = Some(policy.reason.clone());
        if !degraded.is_empty() {
            reason = Some(format!(
                "{} [degraded: {}]",
                policy.reason,
                degraded.join("; ")
            ));
        }
        AuditRecord {
            id: 0,
            uuid: new_uuid(),
            schema_version: EVENT_SCHEMA_VERSION,
            ts_utc: now_rfc3339(),
            agent: truncate(&ev.ctx.agent, 64),
            agent_version: ev.ctx.agent_version.as_ref().map(|v| truncate(v, 64)),
            session_id: ev.ctx.session_id.as_ref().map(|v| truncate(v, 128)),
            workspace: ev.ctx.workspace.as_ref().map(|v| truncate(v, 1024)),
            hook_event: truncate(&ev.ctx.hook_event, 64),
            phase: ev.phase,
            action_type: ev.action.type_name().to_string(),
            tool: ev.ctx.tool.as_ref().map(|v| truncate(v, 256)),
            summary: summarize(&action),
            action,
            input_redacted,
            risk,
            policy_version: policy.policy_version.clone(),
            policy_name: policy.policy_name.clone(),
            matched_rules: policy.matched.iter().map(|m| m.id.clone()).collect(),
            mode,
            simulated_decision: policy.decision,
            decision_reason: reason.map(|r| self.redactor.redact(&r).0),
            actual_decision: mo.actual,
            outcome,
            coverage,
            latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            correlation_id: ev.ctx.correlation_id.as_ref().map(|v| truncate(v, 128)),
            via_daemon,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    fn red(&self, s: &str, max: usize) -> String {
        truncate(&self.redactor.redact(s).0, max)
    }

    /// Redact all free-text fields of an action.
    pub fn redact_action(&self, a: &ActionKind) -> ActionKind {
        match a {
            ActionKind::ShellExec { command, shell } => ActionKind::ShellExec {
                command: self.red(command, MAX_STORED_STRING),
                shell: *shell,
            },
            ActionKind::FileRead { path } => ActionKind::FileRead {
                path: self.red(path, 1024),
            },
            ActionKind::FileWrite { path, content_len } => ActionKind::FileWrite {
                path: self.red(path, 1024),
                content_len: *content_len,
            },
            ActionKind::FileEdit { path } => ActionKind::FileEdit {
                path: self.red(path, 1024),
            },
            ActionKind::FileSearch { pattern, path } => ActionKind::FileSearch {
                pattern: self.red(pattern, 512),
                path: path.as_ref().map(|p| self.red(p, 1024)),
            },
            ActionKind::NetworkFetch { url } => ActionKind::NetworkFetch {
                url: self.red(url, 2048),
            },
            ActionKind::WebSearch { query } => ActionKind::WebSearch {
                query: self.red(query, 512),
            },
            ActionKind::McpCall { server, tool } => ActionKind::McpCall {
                server: truncate(server, 128),
                tool: truncate(tool, 256),
            },
            ActionKind::SubAgent { description } => ActionKind::SubAgent {
                description: self.red(description, 512),
            },
            ActionKind::Notification { message } => ActionKind::Notification {
                message: self.red(message, 512),
            },
            ActionKind::SessionStart { source } => ActionKind::SessionStart {
                source: truncate(source, 64),
            },
            ActionKind::SessionEnd { reason } => ActionKind::SessionEnd {
                reason: truncate(reason, 64),
            },
            ActionKind::PermissionRequest { tool } => ActionKind::PermissionRequest {
                tool: truncate(tool, 256),
            },
            ActionKind::PermissionDenied { tool } => ActionKind::PermissionDenied {
                tool: truncate(tool, 256),
            },
            ActionKind::OtherTool { tool } => ActionKind::OtherTool {
                tool: truncate(tool, 256),
            },
            other => other.clone(),
        }
    }

    /// Redacted, privacy-reduced copy of the tool input. File contents and prompts are
    /// never stored — only their size and a hash.
    pub fn redact_input(&self, ev: &NormalizedEvent) -> serde_json::Value {
        use serde_json::Value;
        if let ActionKind::UserPrompt { length } = ev.action {
            return serde_json::json!({ "prompt": format!("[not stored: {length} chars]") });
        }
        let mut v = ev.input.clone();
        if let Value::Object(map) = &mut v {
            for key in [
                "content",
                "new_string",
                "old_string",
                "new_str",
                "old_str",
                "new_source",
                "patch",
                "diff",
            ] {
                if let Some(Value::String(s)) = map.get(key) {
                    let h = hex::encode(&Sha256::digest(s.as_bytes())[..6]);
                    let placeholder = format!("[not stored: {} bytes, sha256:{h}]", s.len());
                    map.insert(key.to_string(), Value::String(placeholder));
                }
            }
            if let Some(Value::Array(edits)) = map.get_mut("edits") {
                for e in edits.iter_mut() {
                    if let Value::Object(m) = e {
                        for key in ["new_string", "old_string"] {
                            if let Some(Value::String(s)) = m.get(key) {
                                let ph = format!("[not stored: {} bytes]", s.len());
                                m.insert(key.to_string(), Value::String(ph));
                            }
                        }
                    }
                }
            }
        }
        let (red, _) = self.redactor.redact_json(&v);
        cap_json(red, 0)
    }

    /// Evaluate a hypothetical event for the simulator (nothing is executed or stored).
    pub fn simulate(&self, ev: &NormalizedEvent, preset: &str) -> Result<SimulationResult, String> {
        let risk = agentshield_risk_engine::assess(ev, &self.risk_context(ev), &self.redactor);
        let set = self.policy_set(preset, ev.ctx.workspace.as_deref())?;
        let policy = set.evaluate(ev, &risk);
        let mut modes = std::collections::BTreeMap::new();
        for m in Mode::ALL {
            modes.insert(m.as_str().to_string(), apply_mode(m, &policy, ev, &risk));
        }
        let parsed = match &ev.action {
            ActionKind::ShellExec { command, shell } => {
                Some(agentshield_command_parser::parse(command, *shell))
            }
            _ => None,
        };
        let mut limitations = vec![
            "Static analysis only: nothing was executed.".to_string(),
            "Runtime values (variables, globs, symlinks, PATH lookups, aliases) cannot be resolved statically.".to_string(),
        ];
        limitations.extend(risk.uncertainties.iter().cloned());
        if matches!(ev.action, ActionKind::McpCall { .. }) {
            limitations.push("MCP tool behaviour is defined by the server; only the call and its arguments are visible.".into());
        }
        let sensitive_targets = risk
            .findings
            .iter()
            .filter(|f| f.id.starts_with("path.") || f.id.starts_with("mcp.path."))
            .filter_map(|f| f.evidence.clone())
            .map(|e| self.red(&e, 300))
            .collect();
        let mut red_risk = risk.clone();
        for f in &mut red_risk.findings {
            f.evidence = f.evidence.as_ref().map(|e| self.red(e, 300));
        }
        Ok(SimulationResult {
            summary: summarize(&self.redact_action(&ev.action)),
            action_type: ev.action.type_name().to_string(),
            parsed,
            risk: red_risk,
            policy,
            modes,
            limitations,
            sensitive_targets,
        })
    }

    /// Re-evaluate stored (redacted) records against another preset without executing
    /// anything. Records are re-normalized from their stored redacted action.
    pub fn replay(&self, records: &[AuditRecord], preset: &str) -> Result<ReplayResult, String> {
        let mut out = ReplayResult {
            preset: preset.into(),
            ..Default::default()
        };
        for r in records.iter().filter(|r| r.phase == Phase::Pre) {
            let ev = NormalizedEvent {
                ctx: AgentContext {
                    agent: r.agent.clone(),
                    session_id: r.session_id.clone(),
                    workspace: r.workspace.clone(),
                    hook_event: r.hook_event.clone(),
                    tool: r.tool.clone(),
                    ..Default::default()
                },
                phase: r.phase,
                action: r.action.clone(),
                input: r.input_redacted.clone(),
                post_failed: None,
                response_text: None,
                enforceable: true,
            };
            let risk =
                agentshield_risk_engine::assess(&ev, &self.risk_context(&ev), &self.redactor);
            let set = self.policy_set(preset, r.workspace.as_deref())?;
            let after = set.evaluate(&ev, &risk).decision;
            out.evaluated += 1;
            *out.by_decision
                .entry(after.as_str().to_string())
                .or_default() += 1;
            *out.original_by_decision
                .entry(r.simulated_decision.as_str().to_string())
                .or_default() += 1;
            if after != r.simulated_decision && out.changed.len() < 500 {
                out.changed.push(ReplayChange {
                    event_id: r.id,
                    summary: r.summary.clone(),
                    before: r.simulated_decision,
                    after,
                });
            }
        }
        Ok(out)
    }
}

fn unreachable_policy() -> PolicySet {
    // The empty policy text above always parses; this exists only to satisfy the type.
    PolicySet::from_preset("observe-everything")
        .unwrap_or_else(|e| panic!("built-in preset broken: {e}"))
}

fn cap_json(v: serde_json::Value, depth: usize) -> serde_json::Value {
    use serde_json::Value;
    if depth > 12 {
        return Value::String("[truncated: depth]".into());
    }
    match v {
        Value::String(s) => Value::String(truncate(&s, MAX_STORED_STRING)),
        Value::Array(a) => {
            let n = a.len();
            let mut out: Vec<Value> = a
                .into_iter()
                .take(100)
                .map(|x| cap_json(x, depth + 1))
                .collect();
            if n > 100 {
                out.push(Value::String(format!("[+{} more items]", n - 100)));
            }
            Value::Array(out)
        }
        Value::Object(o) => Value::Object(
            o.into_iter()
                .take(100)
                .map(|(k, x)| (truncate(&k, 128), cap_json(x, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

/// One-line human summary of a (redacted) action.
pub fn summarize(a: &ActionKind) -> String {
    let one = |s: &str| truncate(&s.replace(['\n', '\r'], " ⏎ "), 240);
    match a {
        ActionKind::ShellExec { command, .. } => one(command),
        ActionKind::FileRead { path } => format!("read {}", one(path)),
        ActionKind::FileWrite { path, content_len } => match content_len {
            Some(n) => format!("write {} ({n} bytes)", one(path)),
            None => format!("write {}", one(path)),
        },
        ActionKind::FileEdit { path } => format!("edit {}", one(path)),
        ActionKind::FileSearch { pattern, path } => format!(
            "search '{}' in {}",
            one(pattern),
            path.as_deref().map(one).unwrap_or_else(|| ".".into())
        ),
        ActionKind::NetworkFetch { url } => format!("fetch {}", one(url)),
        ActionKind::WebSearch { query } => format!("web search '{}'", one(query)),
        ActionKind::McpCall { server, tool } => format!("mcp {server} → {tool}"),
        ActionKind::SubAgent { description } => format!("subagent: {}", one(description)),
        ActionKind::UserPrompt { length } => format!("user prompt ({length} chars, not stored)"),
        ActionKind::SessionStart { source } => format!("session start ({source})"),
        ActionKind::SessionEnd { reason } => format!("session end ({reason})"),
        ActionKind::Notification { message } => format!("notification: {}", one(message)),
        ActionKind::Stop => "agent stopped responding".into(),
        ActionKind::PermissionRequest { tool } => format!("permission prompt for {tool}"),
        ActionKind::PermissionDenied { tool } => format!("permission denied for {tool}"),
        ActionKind::ModeChange { from, to } => format!("mode changed {from} → {to}"),
        ActionKind::OtherTool { tool } => format!("tool {tool}"),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SimulationResult {
    pub summary: String,
    pub action_type: String,
    pub parsed: Option<agentshield_command_parser::ParsedCommand>,
    pub risk: RiskAssessment,
    pub policy: PolicyOutcome,
    pub modes: std::collections::BTreeMap<String, ModeOutcome>,
    pub limitations: Vec<String>,
    pub sensitive_targets: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayChange {
    pub event_id: i64,
    pub summary: String,
    pub before: PolicyDecision,
    pub after: PolicyDecision,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReplayResult {
    pub preset: String,
    pub evaluated: u64,
    pub by_decision: std::collections::BTreeMap<String, u64>,
    pub original_by_decision: std::collections::BTreeMap<String, u64>,
    pub changed: Vec<ReplayChange>,
}

/// Build a record for a mode change (logged like any other event).
pub fn mode_change_record(engine: &Engine, from: Mode, to: Mode, actor: &str) -> AuditRecord {
    let ev = NormalizedEvent {
        ctx: AgentContext {
            agent: "agentshield".into(),
            hook_event: "ModeChange".into(),
            tool: Some(truncate(actor, 64)),
            ..Default::default()
        },
        phase: Phase::Lifecycle,
        action: ActionKind::ModeChange { from, to },
        input: serde_json::json!({ "from": from, "to": to, "actor": truncate(actor, 64) }),
        post_failed: None,
        response_text: None,
        enforceable: false,
    };
    let cfg = Config {
        mode: to,
        ..Config::default()
    };
    engine
        .evaluate(&ev, &cfg, &[], true, &[], Instant::now())
        .record
}

#[cfg(test)]
mod tests;
