//! System tray: mode, health, last warning, open dashboard / approvals, switch mode,
//! pause/resume, exit GUI (the daemon keeps running).

use crate::AppState;
use agentshield_event_model::Mode;
use agentshield_ipc::Method;
use std::sync::Mutex;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

struct TrayItems {
    mode: MenuItem<Wry>,
    health: MenuItem<Wry>,
    warning: MenuItem<Wry>,
    modes: Vec<(Mode, CheckMenuItem<Wry>)>,
    pause: MenuItem<Wry>,
}

static ITEMS: Mutex<Option<TrayItems>> = Mutex::new(None);

fn mode_label(m: Mode, paused: bool) -> String {
    if paused {
        return "⏸ MONITORING PAUSED — nothing enforced".into();
    }
    match m {
        Mode::Monitor => "● MONITOR — observing, not blocking",
        Mode::Shadow => "● SHADOW — simulating, not blocking",
        Mode::Interactive => "● INTERACTIVE — risky actions ask",
        Mode::Enforce => "● ENFORCE — policies enforced",
        Mode::Lockdown => "● LOCKDOWN — risky actions denied",
    }
    .into()
}

fn show_main(app: &AppHandle, route: Option<&str>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    if let Some(r) = route {
        let _ = app.emit("agentshield://navigate", format!("open:{r}"));
    }
}

pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let mode = MenuItem::with_id(app, "mode", "Mode: …", false, None::<&str>)?;
    let health = MenuItem::with_id(app, "health", "Daemon: connecting…", false, None::<&str>)?;
    let warning = MenuItem::with_id(app, "warning", "No warnings yet", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open dashboard", true, None::<&str>)?;
    let approvals =
        MenuItem::with_id(app, "approvals", "Open approval center", true, None::<&str>)?;
    let mut modes = Vec::new();
    for m in Mode::ALL {
        let label = match m {
            Mode::Lockdown => "Lockdown (emergency)".to_string(),
            other => {
                let s = other.as_str();
                format!("{}{}", s[..1].to_uppercase(), &s[1..])
            }
        };
        modes.push((
            m,
            CheckMenuItem::with_id(
                app,
                format!("mode:{}", m.as_str()),
                label,
                true,
                false,
                None::<&str>,
            )?,
        ));
    }
    let refs: Vec<&dyn tauri::menu::IsMenuItem<Wry>> = modes
        .iter()
        .map(|(_, i)| i as &dyn tauri::menu::IsMenuItem<Wry>)
        .collect();
    let switch = Submenu::with_id_and_items(app, "switch", "Switch mode", true, &refs)?;
    let pause = MenuItem::with_id(app, "pause", "Pause monitoring", true, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        "quit",
        "Exit GUI (daemon keeps running)",
        true,
        None::<&str>,
    )?;
    let sep = || PredefinedMenuItem::separator(app);
    let menu = Menu::with_items(
        app,
        &[
            &mode,
            &health,
            &warning,
            &sep()?,
            &open,
            &approvals,
            &switch,
            &pause,
            &sep()?,
            &quit,
        ],
    )?;
    if let Ok(mut g) = ITEMS.lock() {
        *g = Some(TrayItems {
            mode,
            health,
            warning,
            modes,
            pause,
        });
    }
    let mut tb = TrayIconBuilder::with_id("agentshield")
        .tooltip("Erik's AgentShield")
        .menu(&menu)
        .show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        tb = tb.icon(icon.clone());
    }
    tb.on_menu_event(|app, ev| {
        let id = ev.id().as_ref().to_string();
        match id.as_str() {
            "open" => show_main(app, None),
            "approvals" => show_main(app, Some("approvals")),
            "pause" => {
                let paths = app.state::<AppState>().paths.clone();
                let paused = agentshield_core::Config::load(&paths)
                    .map(|c| c.paused)
                    .unwrap_or(false);
                let _ = agentshield_ipc::client::call_with_timeout::<serde_json::Value>(
                    &paths.data_dir,
                    "desktop/tray",
                    Method::SetPaused {
                        paused: !paused,
                        actor: "tray".into(),
                    },
                    std::time::Duration::from_secs(5),
                );
                refresh_mode(app);
            }
            "quit" => app.exit(0),
            m if m.starts_with("mode:") => {
                if let Ok(mode) = m.trim_start_matches("mode:").parse::<Mode>() {
                    let paths = app.state::<AppState>().paths.clone();
                    let _ = agentshield_ipc::client::call_with_timeout::<serde_json::Value>(
                        &paths.data_dir,
                        "desktop/tray",
                        Method::SetMode {
                            mode,
                            actor: "tray".into(),
                        },
                        std::time::Duration::from_secs(5),
                    );
                }
                refresh_mode(app);
            }
            _ => {}
        }
    })
    .on_tray_icon_event(|tray, ev| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = ev
        {
            show_main(tray.app_handle(), None);
        }
    })
    .build(app)?;
    refresh_mode(app);
    Ok(())
}

/// Re-read mode/paused (config is the source of truth) and update labels/check marks.
pub fn refresh_mode(app: &AppHandle) {
    let paths = app.state::<AppState>().paths.clone();
    let cfg = agentshield_core::Config::load(&paths).unwrap_or_default();
    if let Ok(g) = ITEMS.lock()
        && let Some(t) = g.as_ref()
    {
        let _ = t.mode.set_text(mode_label(cfg.mode, cfg.paused));
        for (m, item) in &t.modes {
            let _ = item.set_checked(*m == cfg.mode);
        }
        let _ = t.pause.set_text(if cfg.paused {
            "Resume monitoring"
        } else {
            "Pause monitoring"
        });
    }
    if let Some(tray) = app.tray_by_id("agentshield") {
        let _ = tray.set_tooltip(Some(format!(
            "Erik's AgentShield — {}",
            mode_label(cfg.mode, cfg.paused)
        )));
    }
}

pub fn set_health(_app: &AppHandle, text: &str) {
    if let Ok(g) = ITEMS.lock()
        && let Some(t) = g.as_ref()
    {
        let _ = t.health.set_text(text);
    }
}

pub fn set_last_warning(_app: &AppHandle, text: &str) {
    if let Ok(g) = ITEMS.lock()
        && let Some(t) = g.as_ref()
    {
        let _ = t.warning.set_text(text);
    }
}
