//! Deterministic, explainable risk engine.
//!
//! Each detector produces [`Finding`]s with a fixed score (0-100), a category, a confidence
//! and a human readable explanation. The final score is:
//!
//! ```text
//! score = max(finding scores)
//!       + 5 for every additional distinct category with a finding >= 40 (max +15)
//!       (+ correlation bonus applied by the core, see agentshield-core)
//! ```
//!
//! A score is a **policy classification**, not a probability of an attack. Confidence is
//! stored separately and is lowered when the command contains constructs that can only be
//! resolved at runtime (variables, substitutions, inline interpreter code).

mod mcp;
mod shell;
mod url;

pub use mcp::tool_definition_findings;
pub use url::{UrlAssessment, assess_url, extract_urls};

use agentshield_command_parser::{ParsedCommand, guess_shell, parse};
use agentshield_event_model::{
    ActionKind, Confidence, Finding, NormalizedEvent, RiskAssessment, RiskCategory, RiskLevel,
    ShellKind,
};
use agentshield_secret_detector::{Redactor, classify_path, normalize_path};
use regex::Regex;
use std::sync::OnceLock;

/// Context available to the engine (all optional).
#[derive(Debug, Clone, Default)]
pub struct RiskContext {
    /// Project root reported by the agent (used for "write outside workspace").
    pub workspace: Option<String>,
    /// User home directory (to expand `~`).
    pub home: Option<String>,
}

/// Build a finding.
pub(crate) fn finding(
    id: &str,
    category: RiskCategory,
    score: u8,
    confidence: Confidence,
    explanation: impl Into<String>,
    evidence: Option<String>,
    mitigation: Option<&str>,
) -> Finding {
    Finding {
        id: id.to_string(),
        category,
        score: score.min(100),
        confidence,
        explanation: explanation.into(),
        evidence: evidence.map(|e| agentshield_secret_detector::truncate(&e, 300)),
        mitigation: mitigation.map(Into::into),
    }
}

/// Assess a normalized event. `redactor` is used to detect secrets in content; evidence in
/// findings is redacted by the caller (core) together with the rest of the record.
pub fn assess(event: &NormalizedEvent, ctx: &RiskContext, redactor: &Redactor) -> RiskAssessment {
    let mut findings: Vec<Finding> = Vec::new();
    let mut uncertainties: Vec<String> = Vec::new();
    match &event.action {
        ActionKind::ShellExec { command, shell } => {
            let pc = parse(command, *shell);
            findings.extend(shell::assess_parsed(&pc, command, ctx));
            uncertainties.extend(pc.all_uncertainties());
            for m in redactor.scan(command) {
                findings.push(finding(
                    "secret.in_command",
                    RiskCategory::CredentialExposure,
                    if m.confidence == "low" { 35 } else { 60 },
                    conf_of(m.confidence),
                    format!("Command line contains a credential ({}); it ends up in shell history, process lists and agent transcripts", m.name),
                    Some(format!("[{}:{}]", m.kind, m.fingerprint)),
                    Some("Pass credentials via environment variables or a secret manager, not on the command line."),
                ));
            }
        }
        ActionKind::FileRead { path } => findings.extend(assess_path(path, false, ctx)),
        ActionKind::FileWrite { path, .. } | ActionKind::FileEdit { path } => {
            findings.extend(assess_path(path, true, ctx));
            let content = content_of(&event.input);
            for m in redactor.scan(&content) {
                findings.push(finding(
                    "secret.written_to_file",
                    RiskCategory::CredentialExposure,
                    if m.confidence == "low" { 30 } else { 55 },
                    conf_of(m.confidence),
                    format!(
                        "Content written to a file contains a credential ({})",
                        m.name
                    ),
                    Some(format!("[{}:{}]", m.kind, m.fingerprint)),
                    Some("Keep secrets in an ignored .env file or a secret manager."),
                ));
            }
        }
        ActionKind::FileSearch { pattern, path } => {
            if let Some(p) = path {
                findings.extend(assess_path(p, false, ctx).into_iter().map(|mut f| {
                    f.score = f.score.saturating_sub(15);
                    f.explanation = format!("Search inside sensitive location: {}", f.explanation);
                    f
                }));
            }
            let lp = pattern.to_ascii_lowercase();
            if [
                "password",
                "secret",
                "api_key",
                "apikey",
                "token",
                "private key",
                "aws_access",
            ]
            .iter()
            .any(|k| lp.contains(k))
            {
                findings.push(finding(
                    "secret.credential_hunting",
                    RiskCategory::SecretAccess,
                    35,
                    Confidence::Low,
                    "Search pattern looks for credentials",
                    Some(pattern.clone()),
                    None,
                ));
            }
        }
        ActionKind::NetworkFetch { url } => {
            let a = assess_url(url);
            findings.extend(a.findings);
            if findings.is_empty() {
                findings.push(finding(
                    "network.fetch",
                    RiskCategory::UnsafeNetworkAccess,
                    10,
                    Confidence::High,
                    format!(
                        "Agent fetches external content from {}",
                        a.host.unwrap_or_default()
                    ),
                    Some(url.clone()),
                    None,
                ));
            }
            if let Some(q) = url.split_once('?').map(|x| x.1)
                && !redactor.scan(q).is_empty()
            {
                findings.push(finding(
                    "network.secret_in_url",
                    RiskCategory::DataExfiltration,
                    85,
                    Confidence::High,
                    "A credential is embedded in the URL that is being requested",
                    None,
                    Some("Never put secrets in URLs."),
                ));
            }
        }
        ActionKind::WebSearch { query } => {
            if !redactor.scan(query).is_empty() {
                findings.push(finding(
                    "network.secret_in_search",
                    RiskCategory::DataExfiltration,
                    70,
                    Confidence::High,
                    "A credential appears in a web search query sent to a third party",
                    None,
                    None,
                ));
            }
        }
        ActionKind::McpCall { server, tool } => {
            findings.extend(assess_mcp(server, tool, &event.input, ctx, redactor));
        }
        ActionKind::SubAgent { .. } => {}
        ActionKind::OtherTool { tool } if tool == "hook:ConfigChange" => {
            findings.push(finding(
                "agentconfig.change_observed",
                RiskCategory::AgentConfigurationTampering,
                30,
                Confidence::Low,
                "Claude Code settings changed during the session (by you or by the agent); verify AgentShield hooks are still active",
                event.input.get("source").and_then(|s| s.as_str()).map(|s| s.to_string()),
                Some("Run `agentshield doctor`."),
            ));
        }
        ActionKind::UserPrompt { .. } => {
            // Prompt content is not stored; only scanned for secrets by the adapter caller.
            let text = event.response_text.clone().unwrap_or_default();
            for m in redactor.scan(&text) {
                findings.push(finding(
                    "secret.in_prompt",
                    RiskCategory::CredentialExposure,
                    45,
                    conf_of(m.confidence),
                    format!(
                        "Prompt contains a credential ({}), which is sent to the model provider",
                        m.name
                    ),
                    Some(format!("[{}:{}]", m.kind, m.fingerprint)),
                    Some("Rotate the credential if it was not meant to be shared."),
                ));
            }
        }
        _ => {}
    }

    // Post-execution: secrets and prompt-injection indicators in tool responses.
    if let Some(resp) = &event.response_text
        && !matches!(event.action, ActionKind::UserPrompt { .. })
    {
        let secrets = redactor.scan(resp);
        let strong: Vec<_> = secrets.iter().filter(|m| m.confidence != "low").collect();
        if !strong.is_empty() {
            let kinds: Vec<&str> = strong.iter().map(|m| m.name).collect();
            findings.push(finding(
                    "secret.in_tool_output",
                    RiskCategory::CredentialExposure,
                    65,
                    Confidence::Medium,
                    format!("Tool output returned to the agent contains {} credential(s): {}. The value is now in the model context.", strong.len(), dedup_join(&kinds)),
                    Some(strong.iter().map(|m| format!("[{}:{}]", m.kind, m.fingerprint)).collect::<Vec<_>>().join(" ")),
                    Some("Rotate exposed credentials; restrict the agent from reading credential files."),
                ));
        }
        findings.extend(prompt_injection(resp));
    }

    finalize(findings, uncertainties)
}

fn dedup_join(v: &[&str]) -> String {
    let mut v: Vec<&str> = v.to_vec();
    v.sort();
    v.dedup();
    v.join(", ")
}

fn conf_of(c: &str) -> Confidence {
    match c {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Concatenate all string content in a JSON tool input (for Write/Edit secret scanning).
fn content_of(v: &serde_json::Value) -> String {
    let mut out = String::new();
    for key in ["content", "new_string", "new_str", "text", "patch", "diff"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            out.push_str(s);
            out.push('\n');
        }
    }
    if let Some(edits) = v.get("edits").and_then(|e| e.as_array()) {
        for e in edits {
            if let Some(s) = e.get("new_string").and_then(|x| x.as_str()) {
                out.push_str(s);
                out.push('\n');
            }
        }
    }
    out
}

/// Path-based findings for read (`write == false`) or write access.
pub fn assess_path(path: &str, write: bool, ctx: &RiskContext) -> Vec<Finding> {
    let mut out = Vec::new();
    let expanded = expand_home(path, ctx);
    if let Some(sp) = classify_path(&expanded) {
        let (score, cat) = if write {
            (sp.write_score, sp.write_category)
        } else {
            (sp.read_score, sp.read_category)
        };
        let verb = if write { "Modifies" } else { "Reads" };
        let mitigation = match (sp.kind.as_str(), write) {
            ("agent_configuration" | "agentshield_configuration", true) => Some(
                "Agents should never change their own hooks, permissions or security tooling. Make this change yourself.",
            ),
            (_, false) if sp.kind.read_is_secret_access() => {
                Some("Keep credential files out of the agent's reach (deny rule for this path).")
            }
            _ => None,
        };
        out.push(finding(
            &format!(
                "path.{}.{}",
                sp.kind.as_str(),
                if write { "write" } else { "read" }
            ),
            cat,
            score,
            conf_of(sp.confidence),
            format!("{verb} {}", sp.label.to_lowercase()),
            Some(path.to_string()),
            mitigation,
        ));
    }
    if write {
        if let Some(ws) = &ctx.workspace {
            let np = normalize_path(&expanded);
            let nws = normalize_path(ws);
            let absolute = np.starts_with('/') || (np.len() > 2 && np.as_bytes()[1] == b':');
            if absolute
                && !nws.is_empty()
                && !np.starts_with(nws.trim_end_matches('/'))
                && !is_temp_path(&np)
            {
                out.push(finding(
                    "path.write_outside_workspace",
                    RiskCategory::UnauthorizedFileChange,
                    45,
                    Confidence::High,
                    "Writes a file outside the current project workspace",
                    Some(path.to_string()),
                    Some("Restrict agent writes to the project directory."),
                ));
            }
        }
        if path.contains("..") {
            out.push(finding(
                "path.traversal",
                RiskCategory::UnauthorizedFileChange,
                35,
                Confidence::Medium,
                "Path contains '..' traversal segments",
                Some(path.to_string()),
                None,
            ));
        }
    }
    out
}

/// Locations an agent legitimately writes outside the project: temp dirs and Claude Code's
/// own per-project memory/todo files (`~/.claude/projects/<p>/memory/`, `~/.claude/todos/`).
/// Settings and hooks under `~/.claude` are NOT included (they are agent configuration).
fn is_temp_path(np: &str) -> bool {
    np.starts_with("/tmp/")
        || np.contains("/appdata/local/temp/")
        || np.starts_with("/var/tmp/")
        || (np.contains("/.claude/projects/") && np.contains("/memory/"))
        || np.contains("/.claude/todos/")
}

pub(crate) fn expand_home(p: &str, ctx: &RiskContext) -> String {
    let t = p.trim().trim_matches(['"', '\'']);
    let home = ctx.home.clone().unwrap_or_else(|| "/home/user".into());
    if let Some(rest) = t.strip_prefix("~/").or_else(|| t.strip_prefix("~\\")) {
        return format!("{home}/{rest}");
    }
    for var in [
        "$HOME/",
        "${HOME}/",
        "$env:USERPROFILE\\",
        "$env:USERPROFILE/",
        "%USERPROFILE%\\",
        "%USERPROFILE%/",
        "$env:HOME/",
        "$env:HOME\\",
    ] {
        if let Some(rest) = t.strip_prefix(var) {
            return format!("{home}/{rest}");
        }
    }
    t.to_string()
}

fn assess_mcp(
    server: &str,
    tool: &str,
    input: &serde_json::Value,
    ctx: &RiskContext,
    redactor: &Redactor,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let lt = tool.to_ascii_lowercase();
    let ev = Some(format!("mcp__{server}__{tool}"));
    if [
        "exec",
        "shell",
        "command",
        "terminal",
        "run_code",
        "eval",
        "execute",
        "spawn",
        "powershell",
        "bash",
    ]
    .iter()
    .any(|k| lt.contains(k))
    {
        out.push(finding("mcp.exec_capability", RiskCategory::PrivilegeEscalation, 50, Confidence::Medium,
            "MCP tool appears to execute commands or code outside the agent's own shell tool (bypasses shell monitoring)", ev.clone(),
            Some("Prefer the agent's native shell tool so commands are visible to hooks; restrict this MCP server.")));
    } else if ["delete", "remove", "drop", "destroy", "purge", "truncate"]
        .iter()
        .any(|k| lt.contains(k))
    {
        out.push(finding(
            "mcp.destructive_capability",
            RiskCategory::DestructiveOperation,
            45,
            Confidence::Medium,
            "MCP tool name indicates a destructive operation",
            ev.clone(),
            None,
        ));
    } else if [
        "send",
        "post",
        "upload",
        "email",
        "publish",
        "webhook",
        "http_request",
        "fetch",
    ]
    .iter()
    .any(|k| lt.contains(k))
    {
        out.push(finding(
            "mcp.egress_capability",
            RiskCategory::DataExfiltration,
            35,
            Confidence::Low,
            "MCP tool can send data to external parties",
            ev.clone(),
            None,
        ));
    } else if [
        "write", "create", "update", "edit", "set", "put", "insert", "move", "rename",
    ]
    .iter()
    .any(|k| lt.contains(k))
    {
        out.push(finding(
            "mcp.write_capability",
            RiskCategory::UnauthorizedFileChange,
            25,
            Confidence::Low,
            "MCP tool modifies external state",
            ev.clone(),
            None,
        ));
    }
    // Inspect string arguments.
    let mut strings = Vec::new();
    collect_strings(input, &mut strings, 0);
    for s in &strings {
        if looks_like_path(s) {
            for mut f in assess_path(
                s,
                lt.contains("write") || lt.contains("edit") || lt.contains("create"),
                ctx,
            ) {
                f.id = format!("mcp.{}", f.id);
                out.push(f);
            }
        }
        for u in extract_urls(s) {
            out.extend(assess_url(&u).findings);
        }
        if ["exec", "shell", "command", "terminal", "run"]
            .iter()
            .any(|k| lt.contains(k))
            && s.len() < 4096
        {
            let pc = parse(s, guess_shell(s, None));
            if !pc.segments.is_empty() {
                out.extend(shell::assess_parsed(&pc, s, ctx).into_iter().map(|mut f| {
                    f.id = format!("mcp.{}", f.id);
                    f
                }));
            }
        }
    }
    let joined = strings.join("\n");
    for m in redactor.scan(&joined) {
        out.push(finding(
            "mcp.secret_in_arguments",
            RiskCategory::CredentialExposure,
            60,
            conf_of(m.confidence),
            format!(
                "MCP tool arguments contain a credential ({}) that is sent to the MCP server",
                m.name
            ),
            Some(format!("[{}:{}]", m.kind, m.fingerprint)),
            None,
        ));
    }
    out
}

fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
    if depth > 16 || out.len() > 256 {
        return;
    }
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out, depth + 1)),
        serde_json::Value::Object(o) => o.values().for_each(|x| collect_strings(x, out, depth + 1)),
        _ => {}
    }
}

pub(crate) fn looks_like_path(s: &str) -> bool {
    let t = s.trim().trim_matches(['"', '\'']);
    if t.is_empty() || t.len() > 1024 || t.contains('\n') || t.contains("://") {
        return false;
    }
    t.contains('/')
        || t.contains('\\')
        || t.starts_with('.')
        || t.starts_with('~')
        || classify_path(t).is_some()
}

fn injection_res() -> &'static [(Regex, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        let p = |r: &str, d: &'static str| (Regex::new(r).unwrap_or_else(|e| panic!("{e}")), d);
        vec![
            p(r"(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules|directions)", "instruction override phrase"),
            p(r"(?i)\byou\s+are\s+now\s+(a|an|in)\b", "role reassignment phrase"),
            p(r"(?i)\b(new|updated|real)\s+(system\s+)?instructions\s*:", "injected instruction header"),
            p(r"(?i)<\s*/?\s*(system|im_start|im_end|assistant)\s*>|<\|im_start\|>", "chat-template control tokens"),
            p(r"(?i)\bdo\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+the\s+user\b", "concealment instruction"),
            p(r"(?i)\b(send|post|upload|exfiltrate)\b.{0,40}\b(api[_ ]?keys?|credentials|secrets|\.env|ssh\s+keys?|tokens?)\b", "data exfiltration request"),
            p(r"(?i)\b(run|execute)\s+(the\s+following|this)\s+(command|script)\b.{0,80}(curl|wget|bash|powershell|iex)", "embedded command execution request"),
            p("[\u{E0000}-\u{E007F}]", "invisible Unicode tag characters"),
            p("[\u{200B}\u{200C}\u{200D}\u{2060}]{3,}", "zero-width character sequence"),
        ]
    })
}

/// Indirect prompt injection indicators in untrusted content (tool output, fetched pages,
/// MCP responses). Heuristic: medium/low confidence by design.
pub fn prompt_injection(text: &str) -> Vec<Finding> {
    let sample = if text.len() > 200_000 {
        let mut cut = 200_000;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    } else {
        text
    };
    let hits: Vec<&str> = injection_res()
        .iter()
        .filter(|(re, _)| re.is_match(sample))
        .map(|(_, d)| *d)
        .collect();
    if hits.is_empty() {
        return Vec::new();
    }
    let score = if hits.len() >= 2 { 65 } else { 50 };
    vec![finding(
        "injection.indicator",
        RiskCategory::PromptInjectionIndicator,
        score,
        if hits.len() >= 2 {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        format!(
            "Untrusted content returned to the agent contains prompt-injection indicators: {}",
            hits.join(", ")
        ),
        None,
        Some(
            "Review the source; treat its content as data, not instructions. Consider Interactive Mode for follow-up actions.",
        ),
    )]
}

/// Combine findings into a final assessment.
pub fn finalize(mut findings: Vec<Finding>, mut uncertainties: Vec<String>) -> RiskAssessment {
    if findings.is_empty() {
        let mut a = RiskAssessment::none();
        a.uncertainties = uncertainties;
        if !a.uncertainties.is_empty() {
            a.confidence = Confidence::Medium;
            a.explanation
                .push("Some parts could not be analyzed statically (see uncertainties).".into());
        }
        return a;
    }
    // Deduplicate identical (id, evidence) findings, keep the highest score.
    findings.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.cmp(&b.id)));
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.id.clone(), f.evidence.clone())));

    let top = &findings[0];
    let mut score = u32::from(top.score);
    let mut explanation = vec![format!(
        "Base score {} from '{}' ({}): {}",
        top.score,
        top.id,
        top.category.as_str(),
        top.explanation
    )];
    let mut cats: Vec<RiskCategory> = Vec::new();
    for f in &findings {
        if !cats.contains(&f.category) {
            cats.push(f.category);
        }
    }
    let extra: Vec<RiskCategory> = cats
        .iter()
        .copied()
        .filter(|c| {
            *c != top.category && findings.iter().any(|f| f.category == *c && f.score >= 40)
        })
        .collect();
    let bonus = (extra.len() as u32 * 5).min(15);
    if bonus > 0 {
        score += bonus;
        explanation.push(format!(
            "+{bonus} for {} additional risk categor{} with medium+ findings ({})",
            extra.len(),
            if extra.len() == 1 { "y" } else { "ies" },
            extra
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let score = score.min(100) as u8;
    let mut confidence = top.confidence;
    uncertainties.sort();
    uncertainties.dedup();
    if !uncertainties.is_empty() && confidence == Confidence::High {
        confidence = Confidence::Medium;
        explanation.push(format!(
            "Confidence lowered to medium: {} runtime-dependent construct(s)",
            uncertainties.len()
        ));
    }
    explanation.push(format!(
        "Final score {score} => {}",
        RiskLevel::from_score(score).as_str()
    ));
    RiskAssessment {
        score,
        level: RiskLevel::from_score(score),
        confidence,
        categories: cats,
        findings,
        explanation,
        uncertainties,
    }
}

/// Convenience for the simulator / CLI: assess a raw command line.
pub fn assess_command(
    command: &str,
    shell: Option<ShellKind>,
    ctx: &RiskContext,
    redactor: &Redactor,
) -> (ParsedCommand, RiskAssessment) {
    let shell = shell.unwrap_or_else(|| guess_shell(command, None));
    let ev = NormalizedEvent {
        ctx: Default::default(),
        phase: agentshield_event_model::Phase::Pre,
        action: ActionKind::ShellExec {
            command: command.to_string(),
            shell,
        },
        input: serde_json::json!({ "command": command }),
        post_failed: None,
        response_text: None,
        enforceable: true,
    };
    (parse(command, shell), assess(&ev, ctx, redactor))
}

#[cfg(test)]
mod tests;
