//! Agent detection and the capability matrix.
//!
//! The matrix is static knowledge about each integration surface, combined with the live
//! integration state. A capability is only "enforced" when there is a documented
//! pre-execution deny path that AgentShield uses *and* the hooks are installed & verified.

use crate::install::{IntegrationState, settings_path, state};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub capability: String,
    /// enforced | observed | partial | unsupported | unverified | degraded
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub detected: bool,
    pub version: Option<String>,
    pub executable: Option<String>,
    pub supported: bool,
    pub experimental: bool,
    pub integration: Option<IntegrationState>,
    pub capabilities: Vec<Capability>,
    pub last_event: Option<String>,
    pub notes: Vec<String>,
}

fn cap(c: &str, status: &str, reason: &str) -> Capability {
    Capability {
        capability: c.into(),
        status: status.into(),
        reason: reason.into(),
    }
}

/// Find an executable on PATH (Windows: also .exe/.cmd/.bat).
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
        if cfg!(windows) {
            let p = dir.join(name);
            if p.is_file() && p.extension().is_some() {
                return Some(p);
            }
        }
    }
    let home = dirs::home_dir()?;
    [
        home.join(".local").join("bin").join(name),
        home.join(".claude").join("local").join(name),
    ]
    .into_iter()
    .find(|cand| cand.is_file())
}

/// Run `<exe> --version` with a timeout; never passes user input.
pub fn version_of(exe: &std::path::Path) -> Option<String> {
    let mut cmd = if cfg!(windows)
        && exe
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
    {
        let mut c = Command::new("cmd");
        c.arg("/d").arg("/c").arg(exe).arg("--version");
        c
    } else {
        let mut c = Command::new(exe);
        c.arg("--version");
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().ok()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?.trim().to_string();
    (!first.is_empty()).then(|| first.chars().take(80).collect())
}

/// Claude Code capability matrix given the integration state.
pub fn claude_capabilities(st: Option<&IntegrationState>) -> Vec<Capability> {
    let installed = st.is_some_and(|s| s.installed);
    let verified = st.is_some_and(|s| s.verified);
    let pre = st.is_some_and(|s| s.events.iter().any(|e| e == "PreToolUse"));
    let post = st.is_some_and(|s| s.events.iter().any(|e| e == "PostToolUse"));
    let session = st.is_some_and(|s| s.events.iter().any(|e| e == "SessionStart"));
    let not_installed = "AgentShield hooks are not installed in Claude Code";
    let enforce_or = |what: &str| -> Capability {
        if !installed {
            cap(what, "unsupported", not_installed)
        } else if !verified || !pre {
            cap(
                what,
                "degraded",
                "Hooks installed but not verified (see integration problems)",
            )
        } else {
            cap(
                what,
                "enforced",
                "PreToolUse hook can return deny/ask before the tool runs (Enforce/Interactive/Lockdown modes)",
            )
        }
    };
    let observe_or = |what: &str, ok: bool, reason: &str| -> Capability {
        if !installed {
            cap(what, "unsupported", not_installed)
        } else if ok {
            cap(what, "observed", reason)
        } else {
            cap(what, "degraded", "Required hook event is not registered")
        }
    };
    vec![
        observe_or(
            "Shell monitoring",
            pre,
            "Bash/PowerShell tool calls via PreToolUse + PostToolUse",
        ),
        enforce_or("Shell blocking"),
        observe_or(
            "File read monitoring",
            pre,
            "Read/Glob/Grep tool calls (not reads done inside shell commands' child processes beyond what the command line shows)",
        ),
        observe_or(
            "File write monitoring",
            pre,
            "Write/Edit/MultiEdit/NotebookEdit tool calls",
        ),
        enforce_or("File blocking"),
        if installed {
            cap(
                "Package detection",
                "partial",
                "Package manager commands are detected from the command line; installs triggered indirectly by scripts are not visible",
            )
        } else {
            cap("Package detection", "unsupported", not_installed)
        },
        observe_or(
            "MCP observation",
            pre,
            "mcp__<server>__<tool> calls via PreToolUse/PostToolUse; tool descriptions are not inspected (no proxy)",
        ),
        enforce_or("MCP enforcement"),
        observe_or(
            "Session correlation",
            session,
            "session_id on every hook payload",
        ),
        if installed {
            cap(
                "Network metadata",
                "partial",
                "Only intended destinations visible in WebFetch URLs and command lines; no connection-level telemetry",
            )
        } else {
            cap("Network metadata", "unsupported", not_installed)
        },
        cap(
            "Network enforcement",
            if installed { "partial" } else { "unsupported" },
            "Only tool calls whose destination is visible can be denied; connections made by child processes are not controlled (no firewall integration by design)",
        ),
        cap(
            "Process monitoring",
            "unsupported",
            "No OS-level process telemetry yet (ETW / eBPF planned, see docs/TECHNICAL_DEBT.md TD-006)",
        ),
        cap(
            "Sandbox integration",
            "unsupported",
            "AgentShield does not provide a sandbox; Claude Code's own sandbox settings remain authoritative",
        ),
        if post {
            cap(
                "Execution outcome",
                "observed",
                "PostToolUse / PostToolUseFailure confirm whether a tool actually ran",
            )
        } else {
            cap(
                "Execution outcome",
                if installed { "degraded" } else { "unsupported" },
                if installed {
                    "PostToolUse not registered"
                } else {
                    not_installed
                },
            )
        },
    ]
}

/// Detect Claude Code and list other agents honestly as unsupported.
pub fn detect_all() -> Vec<AgentInfo> {
    let exe = which("claude");
    let version = exe.as_deref().and_then(version_of);
    let sp = settings_path();
    let st = state(&sp);
    let detected = exe.is_some() || sp.parent().is_some_and(|p| p.is_dir());
    let mut notes = vec![
        "Monitoring covers Claude Code CLI and IDE sessions that load ~/.claude/settings.json hooks.".to_string(),
        "Hooks run with your user rights; an agent that can edit settings files could remove them. AgentShield flags such edits as agent configuration tampering.".to_string(),
    ];
    if st.fail_closed {
        notes.push("Fail-closed is on: if the AgentShield binary is missing or crashes, Claude Code blocks tool calls.".into());
    }
    let mut out = vec![AgentInfo {
        id: crate::AGENT_ID.into(),
        name: "Claude Code".into(),
        detected,
        version,
        executable: exe.map(|p| p.display().to_string()),
        supported: true,
        experimental: false,
        capabilities: claude_capabilities(Some(&st)),
        integration: Some(st),
        last_event: None,
        notes,
    }];
    for (id, name, bin) in [
        ("codex", "OpenAI Codex CLI", "codex"),
        ("cursor", "Cursor", "cursor"),
        ("opencode", "OpenCode", "opencode"),
        ("copilot", "GitHub Copilot CLI", "copilot"),
    ] {
        let e = which(bin);
        out.push(AgentInfo {
            id: id.into(),
            name: name.into(),
            detected: e.is_some(),
            version: None,
            executable: e.map(|p| p.display().to_string()),
            supported: false,
            experimental: false,
            integration: None,
            capabilities: ["Shell monitoring", "Shell blocking", "File read monitoring", "File write monitoring", "MCP observation", "Session correlation"]
                .iter()
                .map(|c| cap(c, "unsupported", "No AgentShield adapter for this agent (scope: Claude Code only). Activity of this agent is NOT monitored."))
                .collect(),
            last_event: None,
            notes: vec!["Not monitored by AgentShield.".into()],
        });
    }
    out
}
