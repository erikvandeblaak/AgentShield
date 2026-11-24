//! `agentshield mcp proxy --name <server> -- <command> [args…]`
//!
//! A transparent stdio proxy between Claude Code and an MCP server (newline-delimited
//! JSON-RPC). It relays every message unchanged, except:
//!
//! * `tools/list` responses: tool definitions are sent to the daemon, which pins them,
//!   flags poisoning / changed definitions, and records an audit event. In Enforce/Lockdown
//!   flagged tools are removed from the list the model sees.
//! * `tools/call` requests for a hidden tool are answered with a JSON-RPC error and never
//!   reach the server.
//!
//! If the daemon is unreachable the proxy analyzes the definitions locally (no pinning,
//! marked in stderr) and applies the configured mode the same way. Batches (JSON arrays,
//! removed from MCP in 2025-06) are relayed unchanged.

use agentshield_core::{Config, Paths};
use agentshield_event_model::Mode;
use agentshield_ipc::{McpToolDef, McpToolsVerdict, Method};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_LINE: u64 = 32 * 1024 * 1024;

fn log(server: &str, msg: &str) {
    let _ = writeln!(std::io::stderr(), "[agentshield mcp proxy:{server}] {msg}");
}

fn read_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.clear();
    r.by_ref().take(MAX_LINE).read_until(b'\n', buf)
}

fn tool_defs(result: &Value) -> Vec<McpToolDef> {
    result
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .map(|t| McpToolDef {
                    name: t
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string(),
                    description: t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                    schema: t
                        .get("inputSchema")
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Verdict without the daemon: same detectors, no pinning.
fn local_verdict(paths: &Paths, server: &str, tools: &[McpToolDef]) -> McpToolsVerdict {
    let cfg = Config::load(paths).unwrap_or_default();
    let enforced = !cfg.paused && matches!(cfg.mode, Mode::Enforce | Mode::Lockdown);
    let mut v = McpToolsVerdict {
        enforced,
        ..Default::default()
    };
    for t in tools {
        let f = agentshield_risk_engine::tool_definition_findings(
            server,
            &t.name,
            &t.description,
            &t.schema,
        );
        if let Some(top) = f.iter().max_by_key(|x| x.score) {
            v.flagged.push((t.name.clone(), top.explanation.clone()));
            if enforced && top.score >= 70 {
                v.blocked.push(t.name.clone());
            }
        }
    }
    v
}

fn resolve(cmd: &str, args: &[String]) -> Command {
    // Windows: npx/uvx are .cmd shims that CreateProcess cannot start directly.
    #[cfg(windows)]
    {
        let path =
            agentshield_adapter_claude_code::detect::which(cmd).unwrap_or_else(|| cmd.into());
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
        {
            let mut c = Command::new("cmd");
            c.arg("/d").arg("/c").arg(path).args(args);
            return c;
        }
        let mut c = Command::new(path);
        c.args(args);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new(cmd);
        c.args(args);
        c
    }
}

pub fn run(server: &str, command: &[String]) -> i32 {
    let Some((cmd, args)) = command.split_first() else {
        log(server, "no server command given after --");
        return 2;
    };
    let paths = Paths::resolve();
    let mut child = match resolve(cmd, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log(server, &format!("cannot start '{cmd}': {e}"));
            return 1;
        }
    };
    let Some(mut child_in) = child.stdin.take() else {
        return 1;
    };
    let Some(child_out) = child.stdout.take() else {
        return 1;
    };
    let blocked: Arc<Mutex<HashSet<String>>> = Arc::default();
    let pending: Arc<Mutex<HashSet<String>>> = Arc::default();
    let out = Arc::new(Mutex::new(std::io::stdout()));

    // client (Claude Code) -> server
    {
        let blocked = blocked.clone();
        let pending = pending.clone();
        let out = out.clone();
        let server = server.to_string();
        std::thread::spawn(move || {
            let mut stdin = BufReader::new(std::io::stdin());
            let mut buf = Vec::new();
            while let Ok(n) = read_line(&mut stdin, &mut buf) {
                if n == 0 {
                    break;
                }
                let mut forward = true;
                if let Ok(msg) = serde_json::from_slice::<Value>(&buf) {
                    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    if let Some(id) = msg.get("id") {
                        if method == "tools/list" {
                            if let Ok(mut p) = pending.lock() {
                                p.insert(id.to_string());
                            }
                        } else if method == "tools/call" {
                            let tool = msg
                                .pointer("/params/name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("");
                            if blocked.lock().map(|b| b.contains(tool)).unwrap_or(false) {
                                forward = false;
                                let err = json!({
                                    "jsonrpc": "2.0", "id": id,
                                    "error": { "code": -32001, "message": format!("Blocked by AgentShield: the definition of MCP tool '{tool}' was flagged (tool poisoning or changed definition). Review it and run `agentshield mcp trust {server}` to accept.") }
                                });
                                if let Ok(mut o) = out.lock() {
                                    let _ = writeln!(o, "{err}");
                                    let _ = o.flush();
                                }
                                log(
                                    &server,
                                    &format!("refused tools/call for hidden tool '{tool}'"),
                                );
                            }
                        }
                    }
                }
                if forward && (child_in.write_all(&buf).is_err() || child_in.flush().is_err()) {
                    break;
                }
            }
            // EOF from Claude Code: close the server's stdin so it can exit.
        });
    }

    // server -> client
    let mut reader = BufReader::new(child_out);
    let mut buf = Vec::new();
    while let Ok(n) = read_line(&mut reader, &mut buf) {
        if n == 0 {
            break;
        }
        let mut line = buf.clone();
        if let Ok(mut msg) = serde_json::from_slice::<Value>(&buf) {
            let is_list = msg
                .get("id")
                .map(|id| {
                    pending
                        .lock()
                        .map(|mut p| p.remove(&id.to_string()))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if is_list && msg.pointer("/result/tools").is_some() {
                let defs = tool_defs(&msg["result"]);
                let verdict = match agentshield_ipc::client::call_with_timeout::<McpToolsVerdict>(
                    &paths.data_dir,
                    &format!("mcp-proxy/{server}"),
                    Method::McpTools {
                        server: server.to_string(),
                        tools: defs.clone(),
                    },
                    Duration::from_secs(5),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        log(
                            server,
                            &format!("daemon unavailable ({e}); analyzing locally without pinning"),
                        );
                        local_verdict(&paths, server, &defs)
                    }
                };
                for (tool, why) in &verdict.flagged {
                    log(server, &format!("flagged tool '{tool}': {why}"));
                }
                if let Ok(mut b) = blocked.lock() {
                    b.extend(verdict.blocked.iter().cloned());
                }
                if !verdict.blocked.is_empty() {
                    if let Some(arr) = msg
                        .pointer_mut("/result/tools")
                        .and_then(|t| t.as_array_mut())
                    {
                        arr.retain(|t| {
                            !verdict
                                .blocked
                                .iter()
                                .any(|b| t.get("name").and_then(|n| n.as_str()) == Some(b))
                        });
                    }
                    log(
                        server,
                        &format!(
                            "hid {} tool(s) from the model: {}",
                            verdict.blocked.len(),
                            verdict.blocked.join(", ")
                        ),
                    );
                    line = serde_json::to_vec(&msg).unwrap_or(line);
                    line.push(b'\n');
                }
            }
        }
        if let Ok(mut o) = out.lock()
            && (o.write_all(&line).is_err() || o.flush().is_err())
        {
            break;
        }
    }
    match child.wait() {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    }
}
