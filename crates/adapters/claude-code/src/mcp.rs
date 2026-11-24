//! MCP server discovery from Claude Code configuration (read-only).
//!
//! Sources: `~/.claude.json` (`mcpServers` = user scope, `projects.<path>.mcpServers` = local
//! scope) and `<project>/.mcp.json` (project scope). Only metadata is returned: env *names*
//! (never values), redacted command lines, URL host. Nothing is started or connected to.

use agentshield_event_model::{Confidence, Finding, RiskCategory};
use agentshield_secret_detector::Redactor;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpServerInfo {
    pub name: String,
    pub scope: String,
    pub source: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url_host: Option<String>,
    pub env_keys: Vec<String>,
    pub fingerprint: String,
    pub changed_since_last_seen: bool,
    pub first_seen: Option<String>,
    pub routed_via_agentshield: bool,
    pub findings: Vec<Finding>,
    pub observed_calls: u64,
    pub tools_seen: Vec<String>,
}

fn f(
    id: &str,
    cat: RiskCategory,
    score: u8,
    conf: Confidence,
    expl: &str,
    mit: Option<&str>,
) -> Finding {
    Finding {
        id: id.into(),
        category: cat,
        score,
        confidence: conf,
        explanation: expl.into(),
        evidence: None,
        mitigation: mit.map(Into::into),
    }
}

/// Assess one server config.
pub fn assess_server(
    name: &str,
    cfg: &Value,
    scope: &str,
    source: &Path,
    redactor: &Redactor,
) -> McpServerInfo {
    let transport = cfg
        .get("type")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if cfg.get("url").is_some() {
                "http".into()
            } else if cfg.get("command").is_some() {
                "stdio".into()
            } else {
                "unknown".into()
            }
        });
    let command = cfg
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| redactor.redact(c).0);
    let args: Vec<String> = cfg
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(|x| redactor.redact(x).0)
                .collect()
        })
        .unwrap_or_default();
    let url = cfg.get("url").and_then(|u| u.as_str()).unwrap_or("");
    let url_host = (!url.is_empty())
        .then(|| agentshield_risk_engine::assess_url(url).host)
        .flatten();
    let env = cfg.get("env").and_then(|e| e.as_object());
    let env_keys: Vec<String> = env.map(|e| e.keys().cloned().collect()).unwrap_or_default();
    let headers = cfg.get("headers").and_then(|h| h.as_object());
    let fingerprint = hex::encode(&Sha256::digest(cfg.to_string().as_bytes())[..8]);
    let mut findings = Vec::new();
    let cmd_l = command.clone().unwrap_or_default().to_ascii_lowercase();
    let base = Path::new(&cmd_l)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if matches!(base.as_str(), "npx" | "bunx" | "uvx" | "pnpx")
        || (base == "pnpm" && args.first().is_some_and(|a| a == "dlx"))
    {
        let pkg = args
            .iter()
            .find(|a| !a.starts_with('-') && *a != "dlx")
            .cloned()
            .unwrap_or_default();
        let pinned = pkg
            .rsplit_once('@')
            .is_some_and(|(n, v)| !n.is_empty() && !v.is_empty() && v != "latest");
        if !pinned {
            findings.push(f("mcp.unpinned_package", RiskCategory::SupplyChainCompromise, 45, Confidence::High, "Server is downloaded and started from a package registry without a pinned version: a compromised or changed release runs automatically", Some("Pin an exact version (pkg@1.2.3).")));
        }
    }
    if base == "docker"
        && args.iter().any(|a| {
            a == "--privileged"
                || a.contains("docker.sock")
                || a == "--net=host"
                || a == "--network=host"
        })
    {
        findings.push(f(
            "mcp.privileged_container",
            RiskCategory::PrivilegeEscalation,
            75,
            Confidence::High,
            "Server runs in a privileged container or with the Docker socket mounted",
            None,
        ));
    }
    if url.starts_with("http://") {
        let h = url_host.clone().unwrap_or_default();
        let local = h == "localhost" || h.starts_with("127.") || h == "::1";
        if !local {
            findings.push(f(
                "mcp.plaintext_remote",
                RiskCategory::UnsafeNetworkAccess,
                55,
                Confidence::High,
                "Remote MCP server over unencrypted HTTP",
                Some("Use https."),
            ));
        }
    }
    for (k, v) in env
        .into_iter()
        .flatten()
        .chain(headers.into_iter().flatten())
    {
        if let Some(s) = v.as_str() {
            let literal = !s.starts_with("${") && !s.is_empty();
            if literal
                && (!redactor.scan(s).is_empty()
                    || agentshield_secret_detector::is_sensitive_key(k)
                    || k.to_ascii_lowercase().contains("token")
                    || k.to_ascii_lowercase().contains("key")
                    || k.to_ascii_lowercase().contains("authorization"))
            {
                findings.push(f("mcp.literal_secret_in_config", RiskCategory::CredentialExposure, 55, Confidence::Medium, &format!("Credential stored as a literal value in the MCP config ({k}); the value is not shown"), Some("Reference an environment variable (${VAR}) instead of storing the secret in the file.")));
            }
        }
    }
    McpServerInfo {
        name: name.to_string(),
        scope: scope.into(),
        source: source.display().to_string(),
        transport,
        command,
        args,
        url_host,
        env_keys,
        fingerprint,
        changed_since_last_seen: false,
        first_seen: None,
        routed_via_agentshield: false,
        findings,
        observed_calls: 0,
        tools_seen: vec![],
    }
}

/// Discover MCP servers. `projects` limits per-project lookups (e.g. recently seen workspaces).
pub fn discover(redactor: &Redactor, projects: &[String]) -> Vec<McpServerInfo> {
    let mut out = Vec::new();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let claude_json = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(|d| PathBuf::from(d).join(".claude.json"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| home.join(".claude.json"));
    if let Some(v) = read_json(&claude_json) {
        if let Some(m) = v.get("mcpServers").and_then(|m| m.as_object()) {
            for (name, cfg) in m {
                out.push(assess_server(name, cfg, "user", &claude_json, redactor));
            }
        }
        if let Some(p) = v.get("projects").and_then(|p| p.as_object()) {
            for (path, pv) in p {
                if let Some(m) = pv.get("mcpServers").and_then(|m| m.as_object()) {
                    for (name, cfg) in m {
                        let mut info = assess_server(name, cfg, "local", &claude_json, redactor);
                        info.scope = format!("local ({path})");
                        out.push(info);
                    }
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for p in projects {
        let f = Path::new(p).join(".mcp.json");
        if !seen.insert(f.clone()) {
            continue;
        }
        if let Some(v) = read_json(&f)
            && let Some(m) = v.get("mcpServers").and_then(|m| m.as_object())
        {
            for (name, cfg) in m {
                out.push(assess_server(name, cfg, "project", &f, redactor));
            }
        }
    }
    out
}

fn read_json(p: &Path) -> Option<Value> {
    let meta = std::fs::metadata(p).ok()?;
    if meta.len() > 32 * 1024 * 1024 {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}
