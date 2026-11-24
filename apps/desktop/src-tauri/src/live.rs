//! Live event subscription: one dedicated IPC connection pushes new (redacted) events to the
//! window as `agentshield://event`. Reconnects with backoff; connection state is emitted as
//! `agentshield://connection` so the UI never shows a stale feed as live.

use agentshield_audit_log::EventQuery;
use agentshield_core::Paths;
use agentshield_ipc::{Client, Method, Push};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

pub fn spawn(app: AppHandle, paths: Paths) {
    std::thread::Builder::new()
        .name("agentshield-live".into())
        .spawn(move || {
            let mut last_id: i64 = -1;
            let mut backoff = Duration::from_millis(500);
            loop {
                match run_once(&app, &paths, &mut last_id) {
                    Ok(()) => backoff = Duration::from_millis(500),
                    Err(e) => {
                        let _ = app.emit("agentshield://connection", "disconnected");
                        crate::tray::set_health(&app, &format!("Daemon: not connected ({e})"));
                    }
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        })
        .ok();
}

fn run_once(app: &AppHandle, paths: &Paths, last_id: &mut i64) -> Result<(), String> {
    let mut c = Client::connect(&paths.data_dir, "desktop/live").map_err(|e| e.to_string())?;
    if *last_id < 0 {
        // Start at the newest event; the UI loads history itself.
        let rows: Vec<agentshield_audit_log::EventRow> = c
            .call(Method::ListEvents {
                query: EventQuery {
                    limit: Some(1),
                    ..Default::default()
                },
            })
            .map_err(|e| e.to_string())?;
        *last_id = rows.first().map(|r| r.record.id).unwrap_or(0);
    }
    c.call_raw(Method::Subscribe { after_id: *last_id })
        .map_err(|e| e.to_string())?;
    let _ = app.emit("agentshield://connection", "connected");
    crate::tray::set_health(app, "Daemon: connected");
    loop {
        match c.next_push().map_err(|e| e.to_string())? {
            Push::Event { row } => {
                let id = row["record"]["id"].as_i64().unwrap_or(0);
                if id <= *last_id {
                    continue;
                }
                *last_id = id;
                let score = row["record"]["risk"]["score"].as_u64().unwrap_or(0);
                if score >= 60 {
                    let summary: String = row["record"]["summary"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(60)
                        .collect();
                    crate::tray::set_last_warning(
                        app,
                        &format!("Last warning: {score} — {summary}"),
                    );
                }
                if row["record"]["action_type"] == "agentshield.mode_change" {
                    crate::tray::refresh_mode(app);
                }
                let _ = app.emit("agentshield://event", row);
            }
            Push::Lagged { .. } => {
                let _ = app.emit("agentshield://connection", "lagged");
            }
            Push::Heartbeat => {}
        }
    }
}
