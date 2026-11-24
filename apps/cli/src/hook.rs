//! `agentshield hook` — the process Claude Code runs for every hook event.
//!
//! Contract with Claude Code: stdout carries at most one JSON decision object, exit code 0.
//! Nothing else is ever written to stdout. The hook must be fast and must not hang:
//!
//! 1. Ask the daemon (authenticated IPC, 3 s deadline).
//! 2. Otherwise evaluate locally with the same engine (marked degraded, stored directly in
//!    the audit DB) and try to start the daemon in the background for next time.
//! 3. If AgentShield itself fails (panic), fail-open in Monitor/Shadow/Interactive and
//!    fail-closed (deny) for PreToolUse in Enforce/Lockdown.

use agentshield_adapter_claude_code as claude;
use agentshield_core::{Config, Engine, Paths};
use agentshield_event_model::{ActualDecision, Mode, Phase};
use agentshield_ipc::{HookReply, IpcError, Method};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

pub const MAX_STDIN: usize = 4 * 1024 * 1024;
const DAEMON_DEADLINE: Duration = Duration::from_millis(3000);

fn emit(reply: &HookReply) -> i32 {
    if let Some(s) = &reply.stdout {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(s.as_bytes());
        let _ = out.flush();
    }
    if let Some(e) = &reply.stderr {
        let _ = std::io::stderr().write_all(e.as_bytes());
    }
    reply.exit_code
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_STDIN as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() > MAX_STDIN {
        return Err(format!("hook payload larger than {MAX_STDIN} bytes"));
    }
    Ok(buf)
}

fn configured_mode(paths: &Paths) -> Mode {
    Config::load(paths)
        .map(|c| if c.paused { Mode::Monitor } else { c.mode })
        .unwrap_or(Mode::Monitor)
}

/// Try to start the daemon in the background, at most once every 30 seconds.
fn maybe_autostart(paths: &Paths) {
    let marker = paths.run_dir().join("autostart.attempt");
    if let Ok(m) = std::fs::metadata(&marker).and_then(|m| m.modified())
        && m.elapsed()
            .map(|e| e < Duration::from_secs(30))
            .unwrap_or(true)
    {
        return;
    }
    let _ = std::fs::create_dir_all(paths.run_dir());
    let _ = std::fs::write(&marker, b"");
    let _ = crate::daemon_ctl::spawn_detached(paths);
}

fn local(
    paths: &Paths,
    payload: &serde_json::Value,
    hint: Option<&str>,
    reason: String,
    t0: Instant,
) -> HookReply {
    let ev = match claude::normalize(payload, hint) {
        Ok(e) => e,
        Err(_) => return HookReply::default(),
    };
    let mut degraded = vec![reason];
    let cfg = match Config::load(paths) {
        Ok(c) => c,
        Err(e) => {
            degraded.push(format!("{e}; using defaults"));
            Config::default()
        }
    };
    let key = match agentshield_core::load_or_create_key(paths) {
        Ok(k) => k,
        Err(e) => {
            degraded.push(format!("fingerprint key unavailable: {e}"));
            [0u8; 32]
        }
    };
    let engine = Engine::new(paths.clone(), key);
    let mut db = agentshield_audit_log::AuditLog::open(&paths.db_file()).ok();
    let recent = match (&db, &ev.ctx.session_id, ev.phase) {
        (Some(db), Some(sid), Phase::Pre) => {
            let since = (chrono::Utc::now()
                - chrono::Duration::minutes(i64::from(cfg.correlation_window_minutes)))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            db.recent_session_events(sid, &since, 200)
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let eval = engine.evaluate(&ev, &cfg, &recent, false, &degraded, t0);
    let out = claude::render(&ev.ctx.hook_event, &eval.mode_outcome);
    let mut rec = eval.record;
    let id = match db.as_mut() {
        Some(db) => match db.insert(&mut rec) {
            Ok(id) => id,
            Err(_) => {
                let _ = db.add_dropped(1);
                0
            }
        },
        None => 0,
    };
    HookReply {
        stdout: out.stdout,
        stderr: out.stderr,
        exit_code: out.exit_code,
        event_id: id,
    }
}

fn fail_closed_reply(
    paths: &Paths,
    payload: Option<&serde_json::Value>,
    hint: Option<&str>,
    what: &str,
) -> HookReply {
    let is_pre = payload
        .and_then(|p| p.get("hook_event_name"))
        .and_then(|v| v.as_str())
        .or(hint)
        == Some("PreToolUse");
    match configured_mode(paths) {
        Mode::Enforce | Mode::Lockdown if is_pre => {
            let out = claude::render(
                "PreToolUse",
                &agentshield_policy_engine::ModeOutcome {
                    actual: ActualDecision::Deny,
                    message: Some(format!(
                        "AgentShield internal error ({what}); denying because Enforce/Lockdown mode is fail-closed. Run `agentshield doctor`."
                    )),
                },
            );
            HookReply {
                stdout: out.stdout,
                stderr: None,
                exit_code: 0,
                event_id: 0,
            }
        }
        _ => HookReply::default(),
    }
}

/// Entry point. Returns the process exit code.
pub fn run(agent: &str, hint: Option<&str>) -> i32 {
    let paths = Paths::resolve();
    if agent != claude::AGENT_ID {
        // Unknown adapter: never interfere.
        return 0;
    }
    let t0 = Instant::now();
    let raw = read_stdin();
    let raw = match raw {
        Ok(r) => r,
        Err(e) => return emit(&fail_closed_reply(&paths, None, hint, &e)),
    };
    let payload: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return 0, // not JSON: nothing we can evaluate; never block on garbage
    };
    let hint_owned = hint.map(|s| s.to_string());
    let p2 = paths.clone();
    let pl = payload.clone();
    let result = std::panic::catch_unwind(move || {
        let method = Method::Hook {
            agent: claude::AGENT_ID.into(),
            hook_event: hint_owned.clone(),
            payload: pl.clone(),
        };
        match agentshield_ipc::client::call_with_timeout::<HookReply>(
            &p2.data_dir,
            "hook/claude-code",
            method,
            DAEMON_DEADLINE,
        ) {
            Ok(r) => r,
            Err(IpcError::Remote { code, .. }) if code == "bad_request" => HookReply::default(),
            Err(e) => {
                maybe_autostart(&p2);
                local(
                    &p2,
                    &pl,
                    hint_owned.as_deref(),
                    format!("daemon unreachable: {e}"),
                    t0,
                )
            }
        }
    });
    if std::env::var_os("AGENTSHIELD_HOOK_DEBUG").is_some() {
        eprintln!(
            "[agentshield hook] decided in {:?} (since main: excludes process start)",
            t0.elapsed()
        );
    }
    match result {
        Ok(reply) => emit(&reply),
        Err(_) => emit(&fail_closed_reply(&paths, Some(&payload), hint, "panic")),
    }
}
