//! Claude Code adapter.
//!
//! Based on the official hooks reference (https://code.claude.com/docs/en/hooks, read
//! 2026-11-24, Claude Code 2.1.331). Facts this adapter relies on:
//!
//! * Hooks receive one JSON object on stdin with `session_id`, `cwd`, `hook_event_name`,
//!   `permission_mode`, and per event `tool_name`, `tool_input`, `tool_use_id`,
//!   `tool_response`, `prompt`, ...
//! * `PreToolUse` may print `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
//!   "permissionDecision":"deny"|"ask", "permissionDecisionReason": ...}}` with exit 0.
//!   Deny/ask *rules* of Claude Code are still evaluated regardless of hook output, so a
//!   hook cannot weaken native permissions — and AgentShield never sends `allow` or
//!   `updatedInput` at all.
//! * A hook that times out or exits with a code other than 0/2 does **not** block the tool
//!   (fail-open) unless the handler sets `"onFailure": "block"` (Claude Code >= 2.1.295).
//! * Exec form (`command` + `args`) runs without a shell, which avoids the Windows Git-Bash
//!   dependency of shell-form hooks.

pub mod detect;
pub mod install;
pub mod mcp;
pub mod mcp_wrap;

use agentshield_command_parser::guess_shell;
use agentshield_event_model::{
    ActionKind, ActualDecision, AgentContext, NormalizedEvent, Phase, ShellKind,
};
use agentshield_policy_engine::ModeOutcome;
use serde_json::Value;

pub const AGENT_ID: &str = "claude-code";
/// Max size of a tool response kept in memory for secret / injection scanning.
pub const MAX_RESPONSE_SCAN: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("hook payload is not a JSON object")]
    NotObject,
    #[error("hook payload has no hook_event_name")]
    NoEvent,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string())
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn cap(mut t: String, max: usize) -> String {
    if t.len() > max {
        let mut cut = max;
        while !t.is_char_boundary(cut) {
            cut -= 1;
        }
        t.truncate(cut);
    }
    t
}

/// Split `mcp__server__tool` (and `mcp__plugin_<p>_<server>__tool`) into (server, tool).
pub fn split_mcp(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    Some((server.to_string(), tool.to_string()))
}

fn action_for_tool(tool: &str, input: &Value) -> ActionKind {
    let path = |k: &str| s(input, k).unwrap_or_default();
    match tool {
        "Bash" | "Monitor" => {
            let c = path("command");
            let shell = guess_shell(&c, Some("bash"));
            ActionKind::ShellExec {
                command: c,
                shell: if shell == ShellKind::PowerShell {
                    ShellKind::PowerShell
                } else {
                    ShellKind::Bash
                },
            }
        }
        "PowerShell" => ActionKind::ShellExec {
            command: path("command"),
            shell: ShellKind::PowerShell,
        },
        "Read" => ActionKind::FileRead {
            path: path("file_path"),
        },
        "Write" => ActionKind::FileWrite {
            path: path("file_path"),
            content_len: input
                .get("content")
                .and_then(|c| c.as_str())
                .map(|c| c.len()),
        },
        "Edit" | "MultiEdit" => ActionKind::FileEdit {
            path: path("file_path"),
        },
        "NotebookEdit" => ActionKind::FileEdit {
            path: s(input, "notebook_path").unwrap_or_else(|| path("file_path")),
        },
        "Glob" | "Grep" => ActionKind::FileSearch {
            pattern: path("pattern"),
            path: s(input, "path"),
        },
        "WebFetch" => ActionKind::NetworkFetch { url: path("url") },
        "WebSearch" => ActionKind::WebSearch {
            query: path("query"),
        },
        "Agent" | "Task" => ActionKind::SubAgent {
            description: s(input, "description")
                .or_else(|| s(input, "subagent_type"))
                .unwrap_or_default(),
        },
        t if t.starts_with("mcp__") => match split_mcp(t) {
            Some((server, tool)) => ActionKind::McpCall { server, tool },
            None => ActionKind::OtherTool {
                tool: t.to_string(),
            },
        },
        other => ActionKind::OtherTool {
            tool: other.to_string(),
        },
    }
}

/// Normalize a Claude Code hook payload.
pub fn normalize(
    payload: &Value,
    hook_event_hint: Option<&str>,
) -> Result<NormalizedEvent, AdapterError> {
    if !payload.is_object() {
        return Err(AdapterError::NotObject);
    }
    let hook_event = s(payload, "hook_event_name")
        .or_else(|| hook_event_hint.map(|h| h.to_string()))
        .ok_or(AdapterError::NoEvent)?;
    let tool = s(payload, "tool_name");
    let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
    let mut ctx = AgentContext {
        agent: AGENT_ID.into(),
        agent_version: None,
        session_id: s(payload, "session_id"),
        workspace: s(payload, "cwd"),
        permission_mode: s(payload, "permission_mode"),
        hook_event: hook_event.clone(),
        tool: tool.clone(),
        correlation_id: s(payload, "tool_use_id"),
    };
    // MCP server identity reported by Claude Code (preferred over parsing the name).
    let mcp_server = payload
        .get("mcp_server")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .map(|x| x.to_string());
    let tool_action = |t: &str| {
        let mut a = action_for_tool(t, &input);
        if let (ActionKind::McpCall { server, .. }, Some(real)) = (&mut a, &mcp_server) {
            *server = real.clone();
        }
        a
    };
    let ev = match hook_event.as_str() {
        "PreToolUse" => NormalizedEvent {
            phase: Phase::Pre,
            action: tool_action(tool.as_deref().unwrap_or("unknown")),
            input: input.clone(),
            post_failed: None,
            response_text: None,
            enforceable: true,
            ctx: ctx.clone(),
        },
        "PostToolUse" | "PostToolUseFailure" => {
            let failed = hook_event == "PostToolUseFailure"
                || payload
                    .get("tool_response")
                    .and_then(|r| r.get("is_error").or_else(|| r.get("isError")))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
                || payload
                    .get("tool_response")
                    .is_some_and(|r| r.is_string() && payload.get("error").is_some());
            let resp = if hook_event == "PostToolUseFailure" {
                payload.get("error").map(text_of).unwrap_or_default()
            } else {
                payload
                    .get("tool_response")
                    .map(text_of)
                    .unwrap_or_default()
            };
            NormalizedEvent {
                phase: Phase::Post,
                action: tool_action(tool.as_deref().unwrap_or("unknown")),
                input: input.clone(),
                post_failed: Some(failed),
                response_text: Some(cap(resp, MAX_RESPONSE_SCAN)),
                enforceable: false,
                ctx: ctx.clone(),
            }
        }
        "PermissionRequest" => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::PermissionRequest {
                tool: tool.clone().unwrap_or_default(),
            },
            input: input.clone(),
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
        "PermissionDenied" => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::PermissionDenied {
                tool: tool.clone().unwrap_or_default(),
            },
            input: Value::Null,
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
        "UserPromptSubmit" => {
            let prompt = s(payload, "prompt").unwrap_or_default();
            NormalizedEvent {
                phase: Phase::Lifecycle,
                action: ActionKind::UserPrompt {
                    length: prompt.chars().count(),
                },
                input: Value::Null,
                post_failed: None,
                response_text: Some(cap(prompt, MAX_RESPONSE_SCAN)),
                enforceable: false,
                ctx: ctx.clone(),
            }
        }
        "SessionStart" => {
            if let Some(m) = s(payload, "model") {
                ctx.agent_version = None;
                let _ = m; // model is not stored: not needed for security analysis
            }
            NormalizedEvent {
                phase: Phase::Lifecycle,
                action: ActionKind::SessionStart {
                    source: s(payload, "source").unwrap_or_else(|| "unknown".into()),
                },
                input: Value::Null,
                post_failed: None,
                response_text: None,
                enforceable: false,
                ctx: ctx.clone(),
            }
        }
        "SessionEnd" => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::SessionEnd {
                reason: s(payload, "reason").unwrap_or_else(|| "unknown".into()),
            },
            input: Value::Null,
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
        "Notification" => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::Notification {
                message: s(payload, "message").unwrap_or_default(),
            },
            input: Value::Null,
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
        "Stop" | "SubagentStop" => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::Stop,
            input: Value::Null,
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
        other => NormalizedEvent {
            phase: Phase::Lifecycle,
            action: ActionKind::OtherTool {
                tool: format!("hook:{other}"),
            },
            // Only small, non-content metadata (e.g. ConfigChange source / file path).
            input: serde_json::json!({
                "source": payload.get("source").and_then(|x| x.as_str()),
                "file_path": payload.get("file_path").and_then(|x| x.as_str()),
            }),
            post_failed: None,
            response_text: None,
            enforceable: false,
            ctx: ctx.clone(),
        },
    };
    Ok(ev)
}

/// What the hook process prints and exits with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HookOutput {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: i32,
}

/// Render the decision for Claude Code. Only `deny` and `ask` are ever emitted, and only for
/// `PreToolUse`. Everything else produces no output and exit code 0.
pub fn render(hook_event: &str, outcome: &ModeOutcome) -> HookOutput {
    if hook_event != "PreToolUse" {
        return HookOutput::default();
    }
    let decision = match outcome.actual {
        ActualDecision::Deny => "deny",
        ActualDecision::Ask => "ask",
        ActualDecision::NoOpinion | ActualDecision::NotApplicable => return HookOutput::default(),
    };
    let reason = outcome
        .message
        .clone()
        .unwrap_or_else(|| "AgentShield policy".into());
    let reason = cap(reason, 9_000); // Claude Code caps JSON string fields at 10,000 chars
    let json = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    HookOutput {
        stdout: Some(json.to_string()),
        stderr: None,
        exit_code: 0,
    }
}

#[cfg(test)]
mod tests;
