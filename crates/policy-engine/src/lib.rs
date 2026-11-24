//! Declarative policy engine.
//!
//! Policies are TOML files (see `policies/*.toml` and docs/POLICIES.md). A [`PolicySet`] is
//! built from layers in this order:
//!
//! 1. the selected built-in **preset**,
//! 2. the **user** policy file (`<config>/policies/user.toml`),
//! 3. the **project** policy (`<workspace>/.agentshield/policy.toml`).
//!
//! Project policies live inside the repository the agent can edit, so they may only make
//! things *stricter*: `allow` rules from a project layer are dropped and thresholds can only
//! be lowered. This prevents an agent from disabling global security by editing a file in
//! the project.
//!
//! Precedence: `deny > require_sandbox > ask > warn > allow`. An explicit `allow` rule
//! suppresses the score thresholds but never a stricter rule. `hard = true` rules deny even
//! in Interactive mode.

mod mode;
mod presets;

pub use mode::{ModeOutcome, apply_mode};
pub use presets::{PRESETS, Preset, preset, preset_text};

use agentshield_command_parser::{guess_shell, parse};
use agentshield_event_model::{
    ActionKind, NormalizedEvent, PolicyDecision, RiskAssessment, RiskCategory,
};
use agentshield_secret_detector::normalize_path;
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{source_name}: TOML error: {message}")]
    Parse {
        source_name: String,
        message: String,
    },
    #[error("{source_name}: {message}")]
    Invalid {
        source_name: String,
        message: String,
    },
}

/// Raw policy file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub schema_version: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Informational only; the active mode lives in the AgentShield config.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub thresholds: Option<Thresholds>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Score thresholds for default decisions when no rule decides.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub warn_at: Option<u8>,
    pub ask_at: Option<u8>,
    pub deny_at: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Hard rules deny even in Interactive mode and cannot be overridden by allow rules.
    #[serde(default)]
    pub hard: bool,
    #[serde(rename = "match", default)]
    pub matcher: Matcher,
    #[serde(default)]
    pub unless: Option<Matcher>,
    pub effect: Effect,
}

fn yes() -> bool {
    true
}

/// All specified fields must match (AND); within a field any entry may match (OR).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub event_types: Vec<String>,
    /// Glob on the agent's native tool name (`Bash`, `mcp__github__*`).
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub agents: Vec<String>,
    /// Globs on target paths (file tools) and on path-like shell arguments.
    #[serde(default)]
    pub path_globs: Vec<String>,
    /// Any program in the command (normalized: lowercase, no .exe).
    #[serde(default)]
    pub programs: Vec<String>,
    /// Every program in the command is in this list.
    #[serde(default)]
    pub programs_all_in: Vec<String>,
    /// Case-insensitive substrings of the full command line.
    #[serde(default)]
    pub command_contains: Vec<String>,
    /// Every simple command (program + args) matches one of these regexes.
    #[serde(default)]
    pub all_segments_match: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    /// Globs on finding ids (`shell.rm_*`, `tamper.*`).
    #[serde(default)]
    pub finding_ids: Vec<String>,
    #[serde(default)]
    pub min_score: Option<u8>,
    #[serde(default)]
    pub max_score: Option<u8>,
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    /// Globs on URL hosts (WebFetch and URLs in commands).
    #[serde(default)]
    pub url_hosts: Vec<String>,
    /// Globs on the workspace path.
    #[serde(default)]
    pub workspaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub action: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Safer alternative shown to the user / agent.
    #[serde(default)]
    pub suggestion: Option<String>,
}

/// Where a layer comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerKind {
    Preset,
    User,
    Project,
}

#[derive(Debug, Clone)]
struct CompiledMatcher {
    raw: Matcher,
    tools: Vec<GlobMatcher>,
    agents: Vec<GlobMatcher>,
    paths: Vec<GlobMatcher>,
    findings: Vec<GlobMatcher>,
    mcp: Vec<GlobMatcher>,
    hosts: Vec<GlobMatcher>,
    workspaces: Vec<GlobMatcher>,
    segment_res: Vec<Regex>,
    categories: Vec<RiskCategory>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: Rule,
    layer: LayerKind,
    source: String,
    decision: PolicyDecision,
    matcher: CompiledMatcher,
    unless: Option<CompiledMatcher>,
}

/// A validated, layered set of rules.
#[derive(Debug, Clone)]
pub struct PolicySet {
    pub name: String,
    /// Short content hash of all layers (changes whenever any policy text changes).
    pub version: String,
    pub thresholds: Thresholds,
    rules: Vec<CompiledRule>,
    pub warnings: Vec<String>,
    pub sources: Vec<(LayerKind, String)>,
}

/// Information about one matched rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub id: String,
    pub name: Option<String>,
    pub decision: PolicyDecision,
    pub hard: bool,
    pub reason: Option<String>,
    pub suggestion: Option<String>,
    pub layer: LayerKind,
    pub source: String,
}

/// Result of policy evaluation (mode-independent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    pub hard: bool,
    pub matched: Vec<RuleMatch>,
    pub reason: String,
    pub suggestion: Option<String>,
    pub policy_version: String,
    pub policy_name: String,
    /// The threshold that produced the decision, if any.
    pub threshold: Option<String>,
}

/// Facts about an action extracted once for matching.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub type_name: String,
    pub tool: Option<String>,
    pub agent: String,
    pub workspace: Option<String>,
    pub paths: Vec<String>,
    pub programs: Vec<String>,
    pub segments: Vec<String>,
    pub command: Option<String>,
    pub mcp_server: Option<String>,
    pub hosts: Vec<String>,
}

impl Facts {
    pub fn from_event(ev: &NormalizedEvent) -> Self {
        let mut f = Facts {
            type_name: ev.action.type_name().to_string(),
            tool: ev.ctx.tool.clone(),
            agent: ev.ctx.agent.clone(),
            workspace: ev.ctx.workspace.clone(),
            paths: ev.action.paths().into_iter().map(normalize_path).collect(),
            ..Default::default()
        };
        match &ev.action {
            ActionKind::ShellExec { command, shell } => {
                let pc = parse(command, *shell);
                for s in pc.all_segments() {
                    f.programs.push(s.program.clone());
                    f.segments.push(s.joined());
                    for a in &s.args {
                        if a.contains('/')
                            || a.contains('\\')
                            || a.starts_with('.')
                            || a.starts_with('~')
                        {
                            f.paths.push(normalize_path(a));
                        }
                    }
                    for r in &s.redirections {
                        if !r.target.is_empty() {
                            f.paths.push(normalize_path(&r.target));
                        }
                    }
                }
                for u in agentshield_risk_engine::extract_urls(command) {
                    if let Some(h) = agentshield_risk_engine::assess_url(&u).host {
                        f.hosts.push(h);
                    }
                }
                f.command = Some(command.clone());
            }
            ActionKind::NetworkFetch { url } => {
                if let Some(h) = agentshield_risk_engine::assess_url(url).host {
                    f.hosts.push(h);
                }
            }
            ActionKind::McpCall { server, .. } => f.mcp_server = Some(server.clone()),
            _ => {}
        }
        f
    }

    /// Facts for a bare command (simulator).
    pub fn from_command(command: &str) -> Self {
        let ev = NormalizedEvent {
            ctx: Default::default(),
            phase: agentshield_event_model::Phase::Pre,
            action: ActionKind::ShellExec {
                command: command.to_string(),
                shell: guess_shell(command, None),
            },
            input: serde_json::Value::Null,
            post_failed: None,
            response_text: None,
            enforceable: true,
        };
        Facts::from_event(&ev)
    }
}

fn glob(pattern: &str, source: &str) -> Result<GlobMatcher, PolicyError> {
    globset::GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(false)
        .build()
        .map(|g: Glob| g.compile_matcher())
        .map_err(|e| PolicyError::Invalid {
            source_name: source.into(),
            message: format!("invalid glob '{pattern}': {e}"),
        })
}

fn compile_matcher(
    m: &Matcher,
    source: &str,
    rule_id: &str,
) -> Result<CompiledMatcher, PolicyError> {
    let inv = |message: String| PolicyError::Invalid {
        source_name: source.into(),
        message: format!("rule '{rule_id}': {message}"),
    };
    for t in &m.event_types {
        if !ActionKind::TYPE_NAMES.contains(&t.as_str()) && !t.ends_with(".*") {
            return Err(inv(format!(
                "unknown event type '{t}' (valid: {})",
                ActionKind::TYPE_NAMES.join(", ")
            )));
        }
    }
    let mut categories = Vec::new();
    for c in &m.categories {
        categories.push(c.parse::<RiskCategory>().map_err(inv)?);
    }
    if let (Some(a), Some(b)) = (m.min_score, m.max_score)
        && a > b
    {
        return Err(inv("min_score > max_score".into()));
    }
    for s in [m.min_score, m.max_score].into_iter().flatten() {
        if s > 100 {
            return Err(inv("scores must be 0..=100".into()));
        }
    }
    let globs = |v: &Vec<String>, normalize: bool| -> Result<Vec<GlobMatcher>, PolicyError> {
        v.iter()
            .map(|p| {
                let p = if normalize {
                    p.replace('\\', "/").to_ascii_lowercase()
                } else {
                    p.clone()
                };
                glob(&p, source)
            })
            .collect()
    };
    let mut segment_res = Vec::new();
    for r in &m.all_segments_match {
        let re = regex::RegexBuilder::new(r)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| inv(format!("invalid regex '{r}': {e}")))?;
        segment_res.push(re);
    }
    Ok(CompiledMatcher {
        raw: m.clone(),
        tools: globs(&m.tools, false)?,
        agents: globs(&m.agents, false)?,
        paths: globs(&m.path_globs, true)?,
        findings: globs(&m.finding_ids, false)?,
        mcp: globs(&m.mcp_servers, false)?,
        hosts: globs(&m.url_hosts, true)?,
        workspaces: globs(&m.workspaces, true)?,
        segment_res,
        categories,
    })
}

fn any_glob(gs: &[GlobMatcher], values: &[&str]) -> bool {
    gs.iter().any(|g| values.iter().any(|v| g.is_match(v)))
}

impl CompiledMatcher {
    fn is_empty(&self) -> bool {
        self.raw == Matcher::default()
    }

    fn matches(&self, f: &Facts, risk: &RiskAssessment) -> bool {
        let m = &self.raw;
        if !m.event_types.is_empty()
            && !m.event_types.iter().any(|t| {
                t == &f.type_name
                    || (t.ends_with(".*") && f.type_name.starts_with(t.trim_end_matches('*')))
            })
        {
            return false;
        }
        if !self.tools.is_empty()
            && !f
                .tool
                .as_deref()
                .is_some_and(|t| any_glob(&self.tools, &[t]))
        {
            return false;
        }
        if !self.agents.is_empty() && !any_glob(&self.agents, &[f.agent.as_str()]) {
            return false;
        }
        if !self.paths.is_empty() {
            let ps: Vec<&str> = f.paths.iter().map(|s| s.as_str()).collect();
            if !any_glob(&self.paths, &ps) {
                return false;
            }
        }
        if !m.programs.is_empty()
            && !f
                .programs
                .iter()
                .any(|p| m.programs.iter().any(|q| q.eq_ignore_ascii_case(p)))
        {
            return false;
        }
        if !m.programs_all_in.is_empty()
            && (f.programs.is_empty()
                || !f
                    .programs
                    .iter()
                    .all(|p| m.programs_all_in.iter().any(|q| q.eq_ignore_ascii_case(p))))
        {
            return false;
        }
        if !m.command_contains.is_empty() {
            let Some(cmd) = &f.command else { return false };
            let lc = cmd.to_ascii_lowercase();
            if !m
                .command_contains
                .iter()
                .any(|s| lc.contains(&s.to_ascii_lowercase()))
            {
                return false;
            }
        }
        if !self.segment_res.is_empty()
            && (f.segments.is_empty()
                || !f
                    .segments
                    .iter()
                    .all(|s| self.segment_res.iter().any(|r| r.is_match(s))))
        {
            return false;
        }
        if !self.categories.is_empty()
            && !risk.categories.iter().any(|c| self.categories.contains(c))
        {
            return false;
        }
        if !self.findings.is_empty() {
            let ids: Vec<&str> = risk.findings.iter().map(|x| x.id.as_str()).collect();
            if !any_glob(&self.findings, &ids) {
                return false;
            }
        }
        if m.min_score.is_some_and(|s| risk.score < s)
            || m.max_score.is_some_and(|s| risk.score > s)
        {
            return false;
        }
        if !self.mcp.is_empty()
            && !f
                .mcp_server
                .as_deref()
                .is_some_and(|s| any_glob(&self.mcp, &[s]))
        {
            return false;
        }
        if !self.hosts.is_empty() {
            let hs: Vec<&str> = f.hosts.iter().map(|s| s.as_str()).collect();
            if !any_glob(&self.hosts, &hs) {
                return false;
            }
        }
        if !self.workspaces.is_empty() {
            let ws = f
                .workspace
                .as_deref()
                .map(normalize_path)
                .unwrap_or_default();
            if !any_glob(&self.workspaces, &[ws.as_str()]) {
                return false;
            }
        }
        true
    }
}

/// Parse one policy file (no layering).
pub fn parse_policy(text: &str, source_name: &str) -> Result<PolicyFile, PolicyError> {
    let pf: PolicyFile = toml::from_str(text).map_err(|e| PolicyError::Parse {
        source_name: source_name.into(),
        message: e.to_string(),
    })?;
    if pf.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::Invalid {
            source_name: source_name.into(),
            message: format!(
                "unsupported schema_version {} (expected {POLICY_SCHEMA_VERSION})",
                pf.schema_version
            ),
        });
    }
    Ok(pf)
}

/// Builder for a layered [`PolicySet`].
#[derive(Default)]
pub struct PolicySetBuilder {
    layers: Vec<(LayerKind, String, String)>,
}

impl PolicySetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn layer(
        mut self,
        kind: LayerKind,
        source_name: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        self.layers.push((kind, source_name.into(), text.into()));
        self
    }

    pub fn build(self) -> Result<PolicySet, PolicyError> {
        let mut hasher = Sha256::new();
        let mut rules: Vec<CompiledRule> = Vec::new();
        let mut thresholds = Thresholds::default();
        let mut warnings = Vec::new();
        let mut name = String::from("custom");
        let mut sources = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for (kind, source, text) in &self.layers {
            hasher.update(source.as_bytes());
            hasher.update([0]);
            hasher.update(text.as_bytes());
            hasher.update([0]);
            let pf = parse_policy(text, source)?;
            sources.push((*kind, source.clone()));
            if *kind == LayerKind::Preset {
                name = pf.name.clone().unwrap_or_else(|| source.clone());
            }
            if let Some(t) = pf.thresholds {
                for v in [t.warn_at, t.ask_at, t.deny_at].into_iter().flatten() {
                    if v > 100 {
                        return Err(PolicyError::Invalid {
                            source_name: source.clone(),
                            message: "thresholds must be 0..=100".into(),
                        });
                    }
                }
                if let (Some(a), Some(d)) = (t.ask_at, t.deny_at)
                    && a > d
                {
                    return Err(PolicyError::Invalid {
                        source_name: source.clone(),
                        message: "ask_at must be <= deny_at".into(),
                    });
                }
                if *kind == LayerKind::Project {
                    // Only stricter (lower) thresholds are accepted from a project layer.
                    let stricter = |cur: Option<u8>, new: Option<u8>| match (cur, new) {
                        (Some(c), Some(n)) => Some(c.min(n)),
                        (None, Some(n)) => Some(n),
                        (c, None) => c,
                    };
                    thresholds.warn_at = stricter(thresholds.warn_at, t.warn_at);
                    thresholds.ask_at = stricter(thresholds.ask_at, t.ask_at);
                    thresholds.deny_at = stricter(thresholds.deny_at, t.deny_at);
                } else {
                    if t.warn_at.is_some() {
                        thresholds.warn_at = t.warn_at;
                    }
                    if t.ask_at.is_some() {
                        thresholds.ask_at = t.ask_at;
                    }
                    if t.deny_at.is_some() {
                        thresholds.deny_at = t.deny_at;
                    }
                }
            }
            for r in pf.rules {
                let decision: PolicyDecision =
                    r.effect
                        .action
                        .parse()
                        .map_err(|e: String| PolicyError::Invalid {
                            source_name: source.clone(),
                            message: format!("rule '{}': {e}", r.id),
                        })?;
                if r.id.trim().is_empty() {
                    return Err(PolicyError::Invalid {
                        source_name: source.clone(),
                        message: "rule with empty id".into(),
                    });
                }
                if !ids.insert(r.id.clone()) {
                    // Later layers override earlier rules with the same id (except project allow).
                    if *kind == LayerKind::Project {
                        warnings.push(format!("{source}: rule '{}' redefines an existing rule; project layers cannot replace rules, ignored", r.id));
                        continue;
                    }
                    rules.retain(|x| x.rule.id != r.id);
                    warnings.push(format!(
                        "{source}: rule '{}' overrides an earlier definition",
                        r.id
                    ));
                }
                if *kind == LayerKind::Project && matches!(decision, PolicyDecision::Allow) {
                    warnings.push(format!("{source}: allow rule '{}' ignored — project policies may only add restrictions", r.id));
                    continue;
                }
                let matcher = compile_matcher(&r.matcher, source, &r.id)?;
                let unless = r
                    .unless
                    .as_ref()
                    .map(|u| compile_matcher(u, source, &r.id))
                    .transpose()?;
                if matcher.is_empty() && r.enabled {
                    warnings.push(format!(
                        "{source}: rule '{}' has an empty match block and applies to every event",
                        r.id
                    ));
                }
                if r.hard && decision != PolicyDecision::Deny {
                    warnings.push(format!("{source}: rule '{}' is hard but its action is '{}'; 'hard' only affects deny rules", r.id, decision.as_str()));
                }
                rules.push(CompiledRule {
                    decision,
                    layer: *kind,
                    source: source.clone(),
                    matcher,
                    unless,
                    rule: r,
                });
            }
        }
        // Conflict detection: identical match blocks with different actions.
        for i in 0..rules.len() {
            for j in i + 1..rules.len() {
                if rules[i].rule.enabled
                    && rules[j].rule.enabled
                    && rules[i].rule.matcher == rules[j].rule.matcher
                    && rules[i].rule.unless == rules[j].rule.unless
                    && rules[i].decision != rules[j].decision
                {
                    warnings.push(format!(
                        "conflict: rules '{}' ({}) and '{}' ({}) match exactly the same events; the stricter one wins",
                        rules[i].rule.id, rules[i].decision.as_str(), rules[j].rule.id, rules[j].decision.as_str()
                    ));
                }
            }
        }
        let version = hex::encode(&hasher.finalize()[..6]);
        Ok(PolicySet {
            name,
            version,
            thresholds,
            rules,
            warnings,
            sources,
        })
    }
}

impl PolicySet {
    /// Build a set from a single preset.
    pub fn from_preset(id: &str) -> Result<Self, PolicyError> {
        let text = preset_text(id).ok_or_else(|| PolicyError::Invalid {
            source_name: id.into(),
            message: format!("unknown preset '{id}'"),
        })?;
        PolicySetBuilder::new()
            .layer(LayerKind::Preset, format!("preset:{id}"), text)
            .build()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Rule summaries for display.
    pub fn rules(&self) -> Vec<(String, Option<String>, String, bool, bool, LayerKind)> {
        self.rules
            .iter()
            .map(|r| {
                (
                    r.rule.id.clone(),
                    r.rule.name.clone(),
                    r.decision.as_str().to_string(),
                    r.rule.enabled,
                    r.rule.hard,
                    r.layer,
                )
            })
            .collect()
    }

    /// Evaluate an event + its risk assessment.
    pub fn evaluate(&self, ev: &NormalizedEvent, risk: &RiskAssessment) -> PolicyOutcome {
        self.evaluate_facts(&Facts::from_event(ev), risk)
    }

    pub fn evaluate_facts(&self, facts: &Facts, risk: &RiskAssessment) -> PolicyOutcome {
        let mut matched: Vec<RuleMatch> = Vec::new();
        for r in &self.rules {
            if !r.rule.enabled || !r.matcher.matches(facts, risk) {
                continue;
            }
            if let Some(u) = &r.unless
                && u.matches(facts, risk)
            {
                continue;
            }
            matched.push(RuleMatch {
                id: r.rule.id.clone(),
                name: r.rule.name.clone(),
                decision: r.decision,
                hard: r.rule.hard && r.decision == PolicyDecision::Deny,
                reason: r.rule.effect.reason.clone(),
                suggestion: r.rule.effect.suggestion.clone(),
                layer: r.layer,
                source: r.source.clone(),
            });
        }
        let strictest = matched
            .iter()
            .filter(|m| m.decision != PolicyDecision::Allow)
            .max_by_key(|m| (m.hard, m.decision.rank()))
            .cloned();
        let explicit_allow = matched
            .iter()
            .find(|m| m.decision == PolicyDecision::Allow)
            .cloned();
        let t = self.thresholds;
        let threshold_decision = if risk.score > 0 && t.deny_at.is_some_and(|d| risk.score >= d) {
            Some((
                PolicyDecision::Deny,
                format!(
                    "risk score {} >= deny threshold {}",
                    risk.score,
                    t.deny_at.unwrap_or_default()
                ),
            ))
        } else if risk.score > 0 && t.ask_at.is_some_and(|d| risk.score >= d) {
            Some((
                PolicyDecision::Ask,
                format!(
                    "risk score {} >= ask threshold {}",
                    risk.score,
                    t.ask_at.unwrap_or_default()
                ),
            ))
        } else if risk.score > 0 && t.warn_at.is_some_and(|d| risk.score >= d) {
            Some((
                PolicyDecision::Warn,
                format!(
                    "risk score {} >= warn threshold {}",
                    risk.score,
                    t.warn_at.unwrap_or_default()
                ),
            ))
        } else {
            None
        };
        let top_reason = |m: &RuleMatch| {
            m.reason
                .clone()
                .unwrap_or_else(|| format!("matched rule '{}'", m.id))
        };
        let (decision, hard, reason, suggestion, threshold) =
            match (&strictest, &explicit_allow, &threshold_decision) {
                (Some(s), _, Some((td, tr)))
                    if td.rank() > s.decision.rank() && explicit_allow.is_none() =>
                {
                    (
                        *td,
                        s.hard,
                        tr.clone(),
                        s.suggestion.clone(),
                        Some(tr.clone()),
                    )
                }
                (Some(s), _, _) => (
                    s.decision,
                    s.hard,
                    top_reason(s),
                    s.suggestion.clone(),
                    None,
                ),
                (None, Some(a), _) => (PolicyDecision::Allow, false, top_reason(a), None, None),
                (None, None, Some((td, tr))) => (
                    *td,
                    false,
                    tr.clone(),
                    risk.findings.first().and_then(|f| f.mitigation.clone()),
                    Some(tr.clone()),
                ),
                (None, None, None) => (
                    PolicyDecision::Allow,
                    false,
                    "no rule or threshold matched".into(),
                    None,
                    None,
                ),
            };
        let suggestion =
            suggestion.or_else(|| risk.findings.first().and_then(|f| f.mitigation.clone()));
        PolicyOutcome {
            decision,
            hard,
            matched,
            reason,
            suggestion,
            policy_version: self.version.clone(),
            policy_name: self.name.clone(),
            threshold,
        }
    }
}

/// Validate policy text (used by `agentshield policy validate` and the Policy Studio).
pub fn validate(text: &str, kind: LayerKind) -> Result<Vec<String>, PolicyError> {
    let set = PolicySetBuilder::new().layer(kind, "input", text).build()?;
    Ok(set.warnings)
}

#[cfg(test)]
mod tests;
