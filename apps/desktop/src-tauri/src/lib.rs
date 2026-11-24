//! AgentShield desktop backend.
//!
//! The GUI is a *client*: every security decision is made by the daemon / hook. The GUI
//! talks to the daemon over the authenticated local IPC and never changes the mode on its
//! own. Closing (or crashing) the window does not stop the daemon or change the mode; the
//! window hides to the tray, and "Exit GUI" only quits this process.

mod commands;
mod live;
mod tray;

use agentshield_core::Paths;
use tauri::Manager;

pub struct AppState {
    pub paths: Paths,
}

pub fn run() {
    let paths = Paths::resolve();
    tauri::Builder::default()
        .manage(AppState {
            paths: paths.clone(),
        })
        .setup(move |app| {
            tray::build(app.handle())?;
            live::spawn(app.handle().clone(), paths.clone());
            // Make sure the daemon runs; the GUI itself never evaluates hooks.
            let p = paths.clone();
            std::thread::spawn(move || {
                let _ = commands::ensure_daemon(&p);
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide instead of quitting: monitoring continues in the daemon, the tray stays.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::start_daemon,
            commands::list_events,
            commands::get_event,
            commands::get_stats,
            commands::count_events,
            commands::get_session,
            commands::list_sessions,
            commands::list_incidents,
            commands::set_mode,
            commands::set_preset,
            commands::set_paused,
            commands::list_presets,
            commands::get_policy,
            commands::validate_policy,
            commands::save_user_policy,
            commands::simulate,
            commands::replay,
            commands::agents_detect,
            commands::agent_install_preview,
            commands::agent_install,
            commands::agent_uninstall,
            commands::mcp_servers,
            commands::verify_integrity,
            commands::export_events,
            commands::generate_report,
            commands::get_config,
            commands::set_config,
            commands::delete_session,
            commands::delete_all_data,
            commands::self_test,
            commands::open_path,
            commands::backup_database,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| panic!("error while building AgentShield desktop: {e}"))
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                // Closing the last window must not quit (tray keeps running); explicit
                // "Exit GUI" passes an exit code.
                if code.is_none() {
                    api.prevent_exit();
                }
            }
            let _ = app.state::<AppState>();
        });
}
