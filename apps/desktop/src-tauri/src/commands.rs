//! Tauri commands. Thin, validated wrappers around daemon IPC methods, plus the few
//! operations that are local by nature (agent detection / hook install, opening folders).

use crate::AppState;
use agentshield_adapter_claude_code as claude;
use agentshield_audit_log::EventQuery;
use agentshield_core::{Config, Paths};
use agentshield_event_model::Mode;
use agentshield_ipc::{Method, client::call_with_timeout};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tauri::State;

type R<T> = Result<T, String>;

fn ipc(paths: &Paths, m: Method) -> R<Value> {
    call_with_timeout::<Value>(&paths.data_dir, "desktop", m, Duration::from_secs(30))
        .map_err(|e| e.to_string())
}

/// Locate the `agentshield` CLI: bundled sidecar next to the app, repo build, or PATH.
pub fn cli_path() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "agentshield.exe"
    } else {
        "agentshield"
    };
    if let Some(p) = std::env::var_os("AGENTSHIELD_CLI")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    {
        return Some(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
        // Development: apps/desktop/src-tauri/target/<profile>/ -> repo target/release|debug
        for up in dir.ancestors().skip(1) {
            for profile in ["release", "debug"] {
                let c = up.join("target").join(profile).join(name);
                if c.is_file() && up.join("crates").is_dir() {
                    return Some(c);
                }
            }
        }
    }
    claude::detect::which("agentshield")
}

fn no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Start the daemon through the CLI (which detaches it correctly).
pub fn ensure_daemon(paths: &Paths) -> R<()> {
    if ipc(paths, Method::Ping).is_ok() {
        return Ok(());
    }
    let cli =
        cli_path().ok_or("agentshield CLI not found (expected next to the app or on PATH)")?;
    let mut cmd = Command::new(cli);
    cmd.args(["daemon", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    no_window(&mut cmd);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn offline_status(paths: &Paths, err: &str) -> Value {
    let cfg = Config::load(paths).unwrap_or_default();
    json!({
        "daemon_running": false, "daemon_version": null, "pid": null, "uptime_s": null,
        "mode": cfg.mode, "preset": cfg.preset, "paused": cfg.paused,
        "policy_name": cfg.preset, "policy_version": "", "policy_warnings": [],
        "events_total": 0, "dropped_events": 0,
        "hook_latency": {"count": 0, "p50_us": 0, "p95_us": 0, "p99_us": 0, "max_us": 0},
        "eval_latency": {"count": 0, "p50_us": 0, "p95_us": 0, "p99_us": 0, "max_us": 0},
        "degraded": true, "degraded_reasons": [format!("Daemon not reachable: {err}. Hooks still evaluate locally (degraded) until it runs.")],
        "data_dir": paths.data_dir, "config_dir": paths.config_dir, "db_path": paths.db_file(),
        "version": agentshield_core::VERSION, "build": if cfg!(debug_assertions) { "debug" } else { "release" },
    })
}

#[tauri::command]
pub fn get_status(s: State<AppState>) -> R<Value> {
    Ok(ipc(&s.paths, Method::Status).unwrap_or_else(|e| offline_status(&s.paths, &e)))
}

#[tauri::command]
pub fn start_daemon(s: State<AppState>) -> R<Value> {
    ensure_daemon(&s.paths)?;
    ipc(&s.paths, Method::Status)
}

#[tauri::command]
pub fn list_events(s: State<AppState>, query: EventQuery) -> R<Value> {
    ipc(&s.paths, Method::ListEvents { query })
}

#[tauri::command]
pub fn get_event(s: State<AppState>, id: i64) -> R<Value> {
    ipc(&s.paths, Method::GetEvent { id })
}

#[tauri::command]
pub fn count_events(s: State<AppState>, query: EventQuery) -> R<Value> {
    ipc(&s.paths, Method::CountEvents { query })
}

#[tauri::command]
pub fn get_session(s: State<AppState>, session_id: String) -> R<Value> {
    ipc(&s.paths, Method::GetSession { session_id })
}

#[tauri::command]
pub fn get_stats(s: State<AppState>, window_hours: u32) -> R<Value> {
    ipc(&s.paths, Method::Stats { window_hours })
}

#[tauri::command]
pub fn list_sessions(s: State<AppState>, limit: u32) -> R<Value> {
    ipc(&s.paths, Method::Sessions { limit })
}

#[tauri::command]
pub fn list_incidents(s: State<AppState>, limit: u32) -> R<Value> {
    ipc(&s.paths, Method::Incidents { limit })
}

#[tauri::command]
pub fn set_mode(s: State<AppState>, mode: Mode) -> R<Value> {
    ipc(
        &s.paths,
        Method::SetMode {
            mode,
            actor: "desktop".into(),
        },
    )
}

#[tauri::command]
pub fn set_preset(s: State<AppState>, preset: String) -> R<Value> {
    ipc(
        &s.paths,
        Method::SetPreset {
            preset,
            actor: "desktop".into(),
        },
    )
}

#[tauri::command]
pub fn set_paused(s: State<AppState>, paused: bool) -> R<Value> {
    ipc(
        &s.paths,
        Method::SetPaused {
            paused,
            actor: "desktop".into(),
        },
    )
}

#[tauri::command]
pub fn list_presets() -> Value {
    json!(agentshield_policy_engine::PRESETS.iter().map(|p| json!({"id": p.id, "title": p.title, "description": p.description, "text": p.text})).collect::<Vec<_>>())
}

#[tauri::command]
pub fn get_policy(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::PolicyInfo)
}

#[tauri::command]
pub fn validate_policy(text: String) -> Value {
    // Local: validation never needs the daemon.
    match agentshield_policy_engine::validate(&text, agentshield_policy_engine::LayerKind::User) {
        Ok(w) => json!({"ok": true, "warnings": w, "error": null}),
        Err(e) => json!({"ok": false, "warnings": [], "error": e.to_string()}),
    }
}

#[tauri::command]
pub fn save_user_policy(s: State<AppState>, text: String) -> R<Value> {
    ipc(&s.paths, Method::SaveUserPolicy { text })
}

#[tauri::command]
pub fn simulate(s: State<AppState>, input: Value) -> R<Value> {
    ipc(&s.paths, Method::Simulate { input })
}

#[tauri::command]
pub fn replay(
    s: State<AppState>,
    preset: String,
    session_id: Option<String>,
    limit: u32,
) -> R<Value> {
    ipc(
        &s.paths,
        Method::Replay {
            preset,
            session_id,
            limit,
        },
    )
}

#[tauri::command]
pub fn agents_detect(s: State<AppState>) -> R<Value> {
    let mut agents = claude::detect::detect_all();
    if let Ok(v) = ipc(
        &s.paths,
        Method::ListEvents {
            query: EventQuery {
                agent: Some(claude::AGENT_ID.into()),
                limit: Some(1),
                ..Default::default()
            },
        },
    ) && let Some(ts) = v.get(0).and_then(|r| r["record"]["ts_utc"].as_str())
        && let Some(a) = agents.iter_mut().find(|a| a.id == claude::AGENT_ID)
    {
        a.last_event = Some(ts.to_string());
    }
    serde_json::to_value(agents).map_err(|e| e.to_string())
}

fn check_agent(id: &str) -> R<()> {
    if id == claude::AGENT_ID {
        Ok(())
    } else {
        Err(format!(
            "unsupported agent '{id}': AgentShield integrates with Claude Code only"
        ))
    }
}

#[tauri::command]
pub fn agent_install_preview(s: State<AppState>, agent_id: String, fail_closed: bool) -> R<Value> {
    check_agent(&agent_id)?;
    let bin = cli_path().ok_or("agentshield CLI not found")?;
    let plan = claude::install::plan(
        &claude::install::settings_path(),
        &bin,
        fail_closed,
        claude::install::supports_skill_shell(claude::detect::claude_version().as_deref()),
        &s.paths.backups_dir(),
    )?;
    serde_json::to_value(plan).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_install(s: State<AppState>, agent_id: String, fail_closed: bool) -> R<Value> {
    check_agent(&agent_id)?;
    let bin = cli_path().ok_or("agentshield CLI not found")?;
    let r = claude::install::install(
        &claude::install::settings_path(),
        &bin,
        fail_closed,
        claude::install::supports_skill_shell(claude::detect::claude_version().as_deref()),
        &s.paths.backups_dir(),
    );
    if r.ok {
        let _ = ensure_daemon(&s.paths);
    }
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_uninstall(s: State<AppState>, agent_id: String) -> R<Value> {
    check_agent(&agent_id)?;
    let r = claude::install::uninstall(&claude::install::settings_path(), &s.paths.backups_dir());
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn mcp_servers(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::McpServers)
}

#[tauri::command]
pub fn verify_integrity(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::Verify)
}

#[tauri::command]
pub fn export_events(s: State<AppState>, format: String, query: EventQuery) -> R<Value> {
    if !matches!(format.as_str(), "json" | "csv" | "sarif" | "html") {
        return Err(format!("unknown export format '{format}'"));
    }
    ipc(&s.paths, Method::Export { format, query })
}

#[tauri::command]
pub fn generate_report(s: State<AppState>, kind: String, window_hours: u32) -> R<Value> {
    ipc(&s.paths, Method::Report { kind, window_hours })
}

#[tauri::command]
pub fn get_config(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::GetConfig).or_else(|_| {
        serde_json::to_value(Config::load(&s.paths).unwrap_or_default()).map_err(|e| e.to_string())
    })
}

#[tauri::command]
pub fn set_config(s: State<AppState>, patch: Value) -> R<Value> {
    // Mode / preset / paused have dedicated, logged methods; strip them from generic patches.
    let mut p = patch;
    if let Some(o) = p.as_object_mut() {
        for k in ["mode", "preset", "paused"] {
            o.remove(k);
        }
    }
    ipc(&s.paths, Method::SetConfig { patch: p })
}

#[tauri::command]
pub fn delete_session(s: State<AppState>, session_id: String) -> R<Value> {
    ipc(&s.paths, Method::DeleteSession { session_id })
}

#[tauri::command]
pub fn delete_all_data(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::DeleteAll)
}

#[tauri::command]
pub fn backup_database(s: State<AppState>) -> R<Value> {
    ipc(&s.paths, Method::Backup)
}

/// Run the real hook binary through `agentshield selftest` (end-to-end check).
#[tauri::command]
pub async fn self_test() -> R<Value> {
    tauri::async_runtime::spawn_blocking(|| {
        let cli = cli_path().ok_or("agentshield CLI not found")?;
        let mut cmd = Command::new(cli);
        cmd.args(["--json", "selftest"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        no_window(&mut cmd);
        let out = cmd.output().map_err(|e| e.to_string())?;
        let v: Value =
            serde_json::from_slice(&out.stdout).map_err(|e| format!("selftest output: {e}"))?;
        Ok(json!({
            "ok": v["ok"].as_bool().unwrap_or(false),
            "event_id": v["event_id"],
            "latency_ms": v["latency_ms"].as_u64().unwrap_or(0),
            "message": v["message"],
            "decision": v["decision"],
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Open a folder/file in the OS file manager — only inside AgentShield's own directories
/// (never arbitrary paths coming from event data).
#[tauri::command]
pub fn open_path(s: State<AppState>, path: String) -> R<()> {
    let p = PathBuf::from(&path);
    let canon = std::fs::canonicalize(&p).map_err(|e| format!("{path}: {e}"))?;
    let allowed: Vec<PathBuf> = [&s.paths.data_dir, &s.paths.config_dir]
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .collect();
    let settings = std::fs::canonicalize(claude::install::settings_path()).ok();
    let ok = allowed.iter().any(|d| canon.starts_with(d))
        || settings.as_deref() == Some(canon.as_path())
        || settings.as_deref().and_then(Path::parent) == Some(canon.as_path());
    if !ok {
        return Err("refusing to open a path outside AgentShield's data/config directories".into());
    }
    let target = if canon.is_file() && canon.extension().is_some_and(|e| e == "html") {
        canon.clone()
    } else if canon.is_file() {
        canon
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(canon.clone())
    } else {
        canon.clone()
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("explorer");
        c.arg(&target);
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(&target);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(&target);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}
