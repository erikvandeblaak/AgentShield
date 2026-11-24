//! Route stdio MCP servers through `agentshield mcp proxy` (and back), in a Claude Code MCP
//! config file (`~/.claude.json` top-level `mcpServers`, or a project's `.mcp.json`).
//!
//! Same guarantees as the hook installer: refuses invalid JSON, preserves every other key
//! and their order, backs up first, writes atomically, and unwrap restores the original
//! command exactly (it is kept verbatim after `--`).

use agentshield_core::paths::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WrapResult {
    pub ok: bool,
    pub message: String,
    pub changed: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub backup_path: Option<String>,
}

/// Is this server entry already routed through the AgentShield proxy?
pub fn is_wrapped(cfg: &Value) -> bool {
    let cmd = cfg.get("command").and_then(|c| c.as_str()).unwrap_or("");
    let stem = Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args: Vec<&str> = cfg
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    stem == "agentshield" && args.first() == Some(&"mcp") && args.get(1) == Some(&"proxy")
}

/// Original (command, args) of a wrapped entry.
pub fn original_command(cfg: &Value) -> Option<(String, Vec<String>)> {
    if !is_wrapped(cfg) {
        return None;
    }
    let args: Vec<String> = cfg
        .get("args")?
        .as_array()?
        .iter()
        .filter_map(|x| x.as_str().map(|s| s.to_string()))
        .collect();
    let sep = args.iter().position(|a| a == "--")?;
    let rest = &args[sep + 1..];
    let (cmd, a) = rest.split_first()?;
    Some((cmd.clone(), a.to_vec()))
}

fn load(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{} is not valid JSON ({e}); refusing to modify it",
            path.display()
        )
    })?;
    if !v.is_object() {
        return Err(format!("{} is not a JSON object", path.display()));
    }
    Ok(v)
}

fn save(path: &Path, v: &Value, backup_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(backup_dir).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("mcp")
        .trim_start_matches('.');
    let b = backup_dir.join(format!(
        "{name}-{}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    ));
    std::fs::copy(path, &b).map_err(|e| format!("backup failed: {e}"))?;
    let mut text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    text.push('\n');
    write_atomic(path, text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(b.display().to_string())
}

/// Compute the wrapped config (pure; used for dry-run and tests).
pub fn wrap_value(
    config: &Value,
    servers: &[String],
    binary: &Path,
) -> (Value, Vec<String>, Vec<(String, String)>) {
    let mut out = config.clone();
    let mut changed = Vec::new();
    let mut skipped = Vec::new();
    let Some(map) = out.get_mut("mcpServers").and_then(|m| m.as_object_mut()) else {
        return (
            out,
            changed,
            vec![("*".into(), "no mcpServers object in this file".into())],
        );
    };
    let names: Vec<String> = if servers.is_empty() {
        map.keys().cloned().collect()
    } else {
        servers.to_vec()
    };
    for name in names {
        let Some(entry) = map.get_mut(&name) else {
            skipped.push((name, "not found".into()));
            continue;
        };
        if is_wrapped(entry) {
            skipped.push((name, "already routed via AgentShield".into()));
            continue;
        }
        let Some(cmd) = entry
            .get("command")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
        else {
            skipped.push((
                name,
                "not a stdio server (http/sse servers cannot be proxied yet)".into(),
            ));
            continue;
        };
        let mut args = vec![
            json!("mcp"),
            json!("proxy"),
            json!("--name"),
            json!(name),
            json!("--"),
            json!(cmd),
        ];
        if let Some(a) = entry.get("args").and_then(|a| a.as_array()) {
            args.extend(a.iter().cloned());
        }
        entry["command"] = json!(binary.to_string_lossy());
        entry["args"] = Value::Array(args);
        changed.push(name);
    }
    (out, changed, skipped)
}

/// Compute the unwrapped config (pure).
pub fn unwrap_value(config: &Value, servers: &[String]) -> (Value, Vec<String>) {
    let mut out = config.clone();
    let mut changed = Vec::new();
    if let Some(map) = out.get_mut("mcpServers").and_then(|m| m.as_object_mut()) {
        let names: Vec<String> = if servers.is_empty() {
            map.keys().cloned().collect()
        } else {
            servers.to_vec()
        };
        for name in names {
            let Some(entry) = map.get_mut(&name) else {
                continue;
            };
            if let Some((cmd, args)) = original_command(entry) {
                entry["command"] = json!(cmd);
                if args.is_empty() {
                    if let Some(o) = entry.as_object_mut() {
                        o.remove("args");
                    }
                } else {
                    entry["args"] = json!(args);
                }
                changed.push(name);
            }
        }
    }
    (out, changed)
}

pub fn wrap(
    path: &Path,
    servers: &[String],
    binary: &Path,
    backup_dir: &Path,
    dry_run: bool,
) -> WrapResult {
    let run = || -> Result<WrapResult, String> {
        if !binary.is_file() {
            return Err(format!("{} does not exist", binary.display()));
        }
        let cur = load(path)?;
        let (next, changed, skipped) = wrap_value(&cur, servers, binary);
        if changed.is_empty() || dry_run {
            return Ok(WrapResult {
                ok: true,
                message: if dry_run {
                    "dry run — nothing written".into()
                } else {
                    "nothing to change".into()
                },
                changed,
                skipped,
                backup_path: None,
            });
        }
        let b = save(path, &next, backup_dir)?;
        Ok(WrapResult {
            ok: true,
            message: format!(
                "{} server(s) now routed through the AgentShield MCP proxy",
                changed.len()
            ),
            changed,
            skipped,
            backup_path: Some(b),
        })
    };
    run().unwrap_or_else(|e| WrapResult {
        ok: false,
        message: e,
        changed: vec![],
        skipped: vec![],
        backup_path: None,
    })
}

pub fn unwrap(path: &Path, servers: &[String], backup_dir: &Path) -> WrapResult {
    let run = || -> Result<WrapResult, String> {
        let cur = load(path)?;
        let (next, changed) = unwrap_value(&cur, servers);
        if changed.is_empty() {
            return Ok(WrapResult {
                ok: true,
                message: "no server was routed via AgentShield".into(),
                changed,
                skipped: vec![],
                backup_path: None,
            });
        }
        let b = save(path, &next, backup_dir)?;
        Ok(WrapResult {
            ok: true,
            message: format!(
                "{} server(s) restored to their original command",
                changed.len()
            ),
            changed,
            skipped: vec![],
            backup_path: Some(b),
        })
    };
    run().unwrap_or_else(|e| WrapResult {
        ok: false,
        message: e,
        changed: vec![],
        skipped: vec![],
        backup_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"{
  "numStartups": 3,
  "mcpServers": {
    "fs": { "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"], "env": { "A": "1" } },
    "web": { "type": "http", "url": "https://mcp.example.com/mcp" },
    "plain": { "command": "my-server" }
  },
  "zzz": true
}"#;

    #[test]
    fn wrap_unwrap_roundtrip_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".claude.json");
        std::fs::write(&file, CFG).unwrap();
        let bin = dir.path().join("agentshield.exe");
        std::fs::write(&bin, b"x").unwrap();
        let dry = wrap(&file, &[], &bin, &dir.path().join("b"), true);
        assert_eq!(dry.changed, vec!["fs", "plain"]);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            CFG,
            "dry run writes nothing"
        );
        let r = wrap(&file, &[], &bin, &dir.path().join("b"), false);
        assert!(r.ok && r.backup_path.is_some(), "{r:?}");
        assert!(
            r.skipped
                .iter()
                .any(|(n, why)| n == "web" && why.contains("stdio"))
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert!(is_wrapped(&v["mcpServers"]["fs"]));
        assert_eq!(v["mcpServers"]["fs"]["env"]["A"], "1");
        assert_eq!(original_command(&v["mcpServers"]["fs"]).unwrap().0, "npx");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys.last().unwrap().as_str(), "zzz");
        // idempotent
        assert!(
            wrap(&file, &[], &bin, &dir.path().join("b"), false)
                .changed
                .is_empty()
        );
        let u = unwrap(&file, &[], &dir.path().join("b"));
        assert_eq!(u.changed.len(), 2);
        let back: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let orig: Value = serde_json::from_str(CFG).unwrap();
        assert_eq!(back, orig);
    }

    #[test]
    fn refuses_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".mcp.json");
        std::fs::write(&file, "{ broken").unwrap();
        let bin = dir.path().join("agentshield.exe");
        std::fs::write(&bin, b"x").unwrap();
        let r = wrap(&file, &[], &bin, dir.path(), false);
        assert!(!r.ok);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{ broken");
    }
}
