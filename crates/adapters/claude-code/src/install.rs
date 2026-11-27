//! Safe, idempotent, reversible hook installation into Claude Code's user settings.
//!
//! * Reads `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`); refuses to touch
//!   a file that is not valid JSON.
//! * Preserves every existing key, hook and permission rule (key order preserved).
//! * Adds one matcher group per event containing only the AgentShield handler, in exec form
//!   (`command` + `args`, no shell).
//! * Backs up the original file before every change, writes atomically, verifies afterwards.
//! * Uninstall removes only handlers whose command is an `agentshield` binary invoked with
//!   `hook` (see [`HOOK_ARGS`]); groups/events left empty by that removal are removed too.

use agentshield_core::paths::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

/// Hook events AgentShield registers for, with matcher (None = event has no matcher).
pub const EVENTS: &[(&str, Option<&str>)] = &[
    ("PreToolUse", Some("*")),
    ("PostToolUse", Some("*")),
    ("PostToolUseFailure", Some("*")),
    ("PermissionRequest", Some("*")),
    ("UserPromptSubmit", None),
    ("SessionStart", None),
    ("SessionEnd", None),
    ("Notification", None),
    ("Stop", None),
    ("SubagentStop", None),
    // Tamper tripwire: settings changed during a session (observed, never blocked).
    ("ConfigChange", None),
];

/// Registered in addition to [`EVENTS`] when Claude Code is new enough: shell commands that a
/// skill or command injects while it loads (PreToolUse does not fire for those).
pub const SKILL_SHELL_EVENT: (&str, Option<&str>) =
    (crate::SKILL_SHELL_EVENT, Some("Bash|PowerShell"));
/// First Claude Code version that knows `PreSkillShellCommand`. Older versions show a warning
/// dialog for an unknown hook event at every interactive start, so it is not registered there.
pub const SKILL_SHELL_MIN_VERSION: (u64, u64, u64) = (2, 1, 332);

/// Parse a Claude Code version string such as `2.1.332 (Claude Code)`.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let first = v.split_whitespace().next()?;
    let mut it = first.trim_start_matches('v').split('.');
    let n = |x: Option<&str>| x.and_then(|p| p.parse::<u64>().ok());
    Some((n(it.next())?, n(it.next())?, n(it.next())?))
}

/// Whether this Claude Code version supports the `PreSkillShellCommand` hook.
/// Unknown version: `false` (better a documented gap than a warning on every start).
pub fn supports_skill_shell(claude_version: Option<&str>) -> bool {
    claude_version
        .and_then(parse_version)
        .is_some_and(|v| v >= SKILL_SHELL_MIN_VERSION)
}

/// The events to register.
pub fn events(skill_shell: bool) -> Vec<(&'static str, Option<&'static str>)> {
    let mut e = EVENTS.to_vec();
    if skill_shell {
        e.push(SKILL_SHELL_EVENT);
    }
    e
}

/// Timeout (seconds) per event. PreToolUse must stay short: a slow hook delays the agent.
fn timeout_for(event: &str) -> u64 {
    match event {
        "PreToolUse" | "PreSkillShellCommand" | "PermissionRequest" => 10,
        "SessionEnd" => 5,
        _ => 10,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallPlan {
    pub agent_id: String,
    pub settings_path: String,
    pub changes: Vec<String>,
    pub before: String,
    pub after: String,
    pub already_installed: bool,
    pub backup_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallResult {
    pub ok: bool,
    pub message: String,
    pub backup_path: Option<String>,
    pub verified: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrationState {
    pub installed: bool,
    pub verified: bool,
    pub settings_path: String,
    pub events: Vec<String>,
    pub missing_events: Vec<String>,
    pub fail_closed: bool,
    pub binary_path: Option<String>,
    pub problems: Vec<String>,
}

/// Claude Code's user settings file.
pub fn settings_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("settings.json");
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
        .join("settings.json")
}

/// Is this handler ours?
pub fn is_agentshield_handler(h: &Value) -> bool {
    let cmd = h.get("command").and_then(|c| c.as_str()).unwrap_or("");
    let stem = Path::new(cmd.trim_matches('"'))
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let args: Vec<&str> = h
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if stem == "agentshield" && args.first() == Some(&"hook") {
        // Current form: ["hook"]; legacy: ["hook", "claude-code"]; explicit: ["hook", "--agent", "claude-code"].
        return args.len() == 1 || args.contains(&"claude-code");
    }
    // Shell-form legacy entries: "...agentshield... hook claude-code"
    let l = cmd.to_ascii_lowercase();
    l.contains("agentshield") && l.contains(" hook claude-code")
}

/// Hook arguments registered in Claude Code. The agent defaults to `claude-code`.
///
/// The literal argument sequence `hook claude-code` is deliberately avoided: Norton
/// Antivirus was observed (2026-11-24, Windows 11) to delay process creation of unsigned
/// binaries with exactly that command line by ~26 s, which exceeds the hook timeout and would
/// silently disable monitoring. See docs/SECURITY_FINDINGS.md (SF-003).
pub const HOOK_ARGS: &[&str] = &["hook"];

/// Whether a registered handler uses an outdated argument form.
pub fn is_legacy_form(h: &Value) -> bool {
    match h.get("args").and_then(|a| a.as_array()) {
        Some(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>() != HOOK_ARGS,
        None => true,
    }
}

fn handler(binary: &Path, event: &str, fail_closed: bool) -> Value {
    let mut h = json!({
        "type": "command",
        "command": binary.to_string_lossy(),
        "args": HOOK_ARGS,
        "timeout": timeout_for(event),
    });
    if fail_closed && crate::is_pre_event(event) {
        h["onFailure"] = json!("block");
    }
    h
}

fn read_settings(path: &Path) -> Result<Value, String> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(json!({})),
        Ok(t) => {
            let v: Value = serde_json::from_str(&t).map_err(|e| {
                format!(
                    "{} is not valid JSON ({e}); refusing to modify it",
                    path.display()
                )
            })?;
            if !v.is_object() {
                return Err(format!(
                    "{} is not a JSON object; refusing to modify it",
                    path.display()
                ));
            }
            Ok(v)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Remove our handlers. Returns (new settings, number removed). Matcher groups and event
/// arrays are removed only when *our* removal emptied them; the `hooks` object is removed
/// only when our removal left it empty.
pub fn strip(settings: &Value) -> (Value, usize) {
    strip_for(settings, None)
}

/// Normalize a binary path for comparison (case, separators, quotes, `\\?\` prefix).
pub fn same_binary(a: &str, b: &Path) -> bool {
    let norm = |s: &str| {
        s.trim()
            .trim_matches('"')
            .trim_start_matches(r"\\?\")
            .replace('\\', "/")
            .to_ascii_lowercase()
    };
    norm(a) == norm(&b.to_string_lossy())
}

/// Like [`strip`], but when `only` is given, removes only handlers that run that exact binary
/// (so uninstalling one installation never touches another one).
pub fn strip_for(settings: &Value, only: Option<&Path>) -> (Value, usize) {
    let ours = |h: &Value| {
        is_agentshield_handler(h)
            && only.is_none_or(|b| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| same_binary(c, b))
            })
    };
    let mut out = settings.clone();
    let mut removed = 0;
    let mut hooks_emptied_by_us = false;
    if let Some(hooks) = out.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        let mut emptied_events = Vec::new();
        for (event, groups) in hooks.iter_mut() {
            let Some(arr) = groups.as_array_mut() else {
                continue;
            };
            let before_groups = arr.len();
            let mut removed_here = 0;
            arr.retain_mut(|g| {
                let Some(hs) = g.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
                    return true;
                };
                let before = hs.len();
                hs.retain(|h| !ours(h));
                let n = before - hs.len();
                removed_here += n;
                !(n > 0 && hs.is_empty())
            });
            removed += removed_here;
            if removed_here > 0 && arr.is_empty() && before_groups > 0 {
                emptied_events.push(event.clone());
            }
        }
        for e in emptied_events {
            hooks.remove(&e);
        }
        hooks_emptied_by_us = removed > 0 && hooks.is_empty();
    }
    if hooks_emptied_by_us && let Some(o) = out.as_object_mut() {
        o.remove("hooks");
    }
    (out, removed)
}

/// Compute the settings with AgentShield installed (idempotent).
pub fn apply(
    settings: &Value,
    binary: &Path,
    fail_closed: bool,
    skill_shell: bool,
) -> Result<Value, String> {
    let (mut out, _) = strip(settings);
    let obj = out.as_object_mut().ok_or("settings is not an object")?;
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks = hooks
        .as_object_mut()
        .ok_or("settings.hooks is not an object; refusing to modify it")?;
    for (event, matcher) in events(skill_shell) {
        let groups = hooks
            .entry(event.to_string())
            .or_insert_with(|| Value::Array(vec![]));
        let arr = groups.as_array_mut().ok_or_else(|| {
            format!("settings.hooks.{event} is not an array; refusing to modify it")
        })?;
        let mut group = json!({ "hooks": [handler(binary, event, fail_closed)] });
        if let Some(m) = matcher {
            group = json!({ "matcher": m, "hooks": [handler(binary, event, fail_closed)] });
        }
        arr.push(group);
    }
    Ok(out)
}

fn hooks_pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v.get("hooks").unwrap_or(&Value::Null)).unwrap_or_default()
}

/// Inspect the current integration state.
pub fn state(path: &Path) -> IntegrationState {
    let mut st = IntegrationState {
        installed: false,
        verified: false,
        settings_path: path.display().to_string(),
        events: vec![],
        missing_events: vec![],
        fail_closed: false,
        binary_path: None,
        problems: vec![],
    };
    let v = match read_settings(path) {
        Ok(v) => v,
        Err(e) => {
            st.problems.push(e);
            return st;
        }
    };
    if v.get("disableAllHooks").and_then(|x| x.as_bool()) == Some(true) {
        st.problems.push("disableAllHooks is true in this settings file: Claude Code runs NO hooks, nothing is monitored".into());
    }
    let hooks = v.get("hooks").and_then(|h| h.as_object());
    // PreSkillShellCommand is optional (depends on the Claude Code version): checked when
    // present, never reported as missing here (see detect.rs for the version-aware check).
    let skill_present = hooks.is_some_and(|h| h.contains_key(SKILL_SHELL_EVENT.0));
    for (event, _) in events(skill_present) {
        let ours: Vec<&Value> = hooks
            .and_then(|h| h.get(event))
            .and_then(|g| g.as_array())
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|g| g.get("hooks").and_then(|h| h.as_array()))
                    .flatten()
                    .filter(|h| is_agentshield_handler(h))
                    .collect()
            })
            .unwrap_or_default();
        if ours.is_empty() {
            if event != SKILL_SHELL_EVENT.0 {
                st.missing_events.push(event.to_string());
            }
        } else {
            st.events.push(event.to_string());
            if ours.len() > 1 {
                st.problems.push(format!(
                    "{event}: AgentShield is registered {} times",
                    ours.len()
                ));
            }
            for h in ours {
                if event == "PreToolUse"
                    && h.get("onFailure").and_then(|x| x.as_str()) == Some("block")
                {
                    st.fail_closed = true;
                }
                if let Some(c) = h.get("command").and_then(|c| c.as_str()) {
                    if h.get("args").is_none() {
                        st.problems.push(format!("{event}: legacy shell-form hook (may need Git Bash on Windows); run repair"));
                    } else if is_legacy_form(h) {
                        st.problems.push(format!("{event}: outdated hook arguments (can be delayed by antivirus heuristics); run repair"));
                    }
                    let p = PathBuf::from(c.trim_matches('"'));
                    if h.get("args").is_some() && !p.is_file() {
                        st.problems
                            .push(format!("{event}: hook binary not found: {}", p.display()));
                    }
                    st.binary_path = Some(p.display().to_string());
                }
            }
        }
    }
    st.installed = !st.events.is_empty();
    st.verified = st.installed && st.missing_events.is_empty() && st.problems.is_empty();
    st
}

/// Dry run.
pub fn plan(
    path: &Path,
    binary: &Path,
    fail_closed: bool,
    skill_shell: bool,
    backup_dir: &Path,
) -> Result<InstallPlan, String> {
    let current = read_settings(path)?;
    let next = apply(&current, binary, fail_closed, skill_shell)?;
    let already = current == next;
    let mut changes = Vec::new();
    if already {
        changes
            .push("No changes: AgentShield hooks are already installed exactly like this.".into());
    } else {
        if !path.exists() {
            changes.push(format!("Create {}", path.display()));
        }
        let (_, removed) = strip(&current);
        if removed > 0 {
            changes.push(format!(
                "Replace {removed} existing AgentShield hook entr{} (repair)",
                if removed == 1 { "y" } else { "ies" }
            ));
        }
        for (event, matcher) in events(skill_shell) {
            changes.push(format!(
                "Add hook {event}{}: {} hook{}",
                matcher
                    .map(|m| format!(" (matcher \"{m}\")"))
                    .unwrap_or_default(),
                binary.display(),
                if fail_closed && crate::is_pre_event(event) {
                    " [onFailure: block — fail-closed]"
                } else {
                    ""
                }
            ));
        }
        if !skill_shell {
            changes.push(format!(
                "Skip {}: needs Claude Code {}.{}.{} or later (older versions warn about an unknown hook event at every start)",
                SKILL_SHELL_EVENT.0,
                SKILL_SHELL_MIN_VERSION.0,
                SKILL_SHELL_MIN_VERSION.1,
                SKILL_SHELL_MIN_VERSION.2
            ));
        }
        let other = current
            .get("hooks")
            .and_then(|h| h.as_object())
            .map(|h| {
                h.values()
                    .filter_map(|g| g.as_array())
                    .flatten()
                    .filter_map(|g| g.get("hooks").and_then(|x| x.as_array()))
                    .flatten()
                    .filter(|h| !is_agentshield_handler(h))
                    .count()
            })
            .unwrap_or(0);
        changes.push(format!("Keep {other} existing hook handler(s) from other tools and all other settings unchanged"));
        changes.push(format!(
            "Back up the current file to {} first",
            backup_dir.display()
        ));
    }
    Ok(InstallPlan {
        agent_id: crate::AGENT_ID.into(),
        settings_path: path.display().to_string(),
        changes,
        before: hooks_pretty(&current),
        after: hooks_pretty(&next),
        already_installed: already,
        backup_dir: backup_dir.display().to_string(),
    })
}

fn backup(path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| format!("cannot create {}: {e}", backup_dir.display()))?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let dest = backup_dir.join(format!("claude-settings-{ts}.json"));
    std::fs::copy(path, &dest).map_err(|e| format!("backup failed: {e}"))?;
    Ok(Some(dest))
}

fn write(path: &Path, v: &Value) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    text.push('\n');
    write_atomic(path, text.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Install (or repair). Never call without explicit user consent.
pub fn install(
    path: &Path,
    binary: &Path,
    fail_closed: bool,
    skill_shell: bool,
    backup_dir: &Path,
) -> InstallResult {
    let run = || -> Result<InstallResult, String> {
        if !binary.is_file() {
            return Err(format!("hook binary {} does not exist", binary.display()));
        }
        let current = read_settings(path)?;
        let next = apply(&current, binary, fail_closed, skill_shell)?;
        if current == next {
            let st = state(path);
            return Ok(InstallResult {
                ok: true,
                message: "Already installed; nothing changed.".into(),
                backup_path: None,
                verified: st.verified,
                problems: st.problems,
            });
        }
        let b = backup(path, backup_dir)?;
        write(path, &next)?;
        let st = state(path);
        if !st.verified {
            // Roll back.
            if let Some(b) = &b {
                let _ = std::fs::copy(b, path);
            }
            return Ok(InstallResult {
                ok: false,
                message: "Verification failed after writing; original settings restored.".into(),
                backup_path: b.map(|p| p.display().to_string()),
                verified: false,
                problems: st.problems,
            });
        }
        Ok(InstallResult {
            ok: true,
            message: format!(
                "Installed AgentShield hooks for {} events.",
                events(skill_shell).len()
            ),
            backup_path: b.map(|p| p.display().to_string()),
            verified: true,
            problems: vec![],
        })
    };
    run().unwrap_or_else(|e| InstallResult {
        ok: false,
        message: e,
        backup_path: None,
        verified: false,
        problems: vec![],
    })
}

/// Remove only AgentShield's handlers.
pub fn uninstall(path: &Path, backup_dir: &Path) -> InstallResult {
    uninstall_for(path, backup_dir, None)
}

/// Remove AgentShield's handlers; with `only`, just those running that binary.
pub fn uninstall_for(path: &Path, backup_dir: &Path, only: Option<&Path>) -> InstallResult {
    let run = || -> Result<InstallResult, String> {
        let current = read_settings(path)?;
        let (next, removed) = strip_for(&current, only);
        if removed == 0 {
            return Ok(InstallResult {
                ok: true,
                message: "AgentShield hooks were not installed; nothing changed.".into(),
                backup_path: None,
                verified: true,
                problems: vec![],
            });
        }
        let b = backup(path, backup_dir)?;
        write(path, &next)?;
        let st = state(path);
        Ok(InstallResult {
            ok: if only.is_some() {
                strip_for(&read_settings(path)?, only).1 == 0
            } else {
                !st.installed
            },
            message: format!(
                "Removed {removed} AgentShield hook handler(s); other hooks and settings unchanged."
            ),
            backup_path: b.map(|p| p.display().to_string()),
            verified: if only.is_some() {
                strip_for(&read_settings(path)?, only).1 == 0
            } else {
                !st.installed
            },
            problems: st.problems,
        })
    };
    run().unwrap_or_else(|e| InstallResult {
        ok: false,
        message: e,
        backup_path: None,
        verified: false,
        problems: vec![],
    })
}
