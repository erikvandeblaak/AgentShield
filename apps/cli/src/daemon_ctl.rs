//! Starting / stopping the background daemon.

use agentshield_core::Paths;
use agentshield_ipc::Method;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn ping(paths: &Paths) -> bool {
    agentshield_ipc::client::call_with_timeout::<serde_json::Value>(
        &paths.data_dir,
        "cli",
        Method::Ping,
        Duration::from_millis(1500),
    )
    .is_ok()
}

/// Windows: every *inheritable* handle of this process is inherited by children. The hook
/// runs with stdin/stdout pipes owned by Claude Code; if the daemon inherited them, Claude
/// Code would wait for EOF until the hook timeout. Mark our standard handles
/// non-inheritable before spawning the long-lived daemon.
#[cfg(windows)]
#[allow(unsafe_code)]
fn std_handles_not_inheritable() {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY (documented exception, see docs/SECURITY_ARCHITECTURE.md "unsafe code"):
        // GetStdHandle has no preconditions and returns a handle owned by this process (or
        // null/INVALID_HANDLE_VALUE, which we skip). SetHandleInformation only clears the
        // inherit flag of that handle; it does not close or transfer it.
        unsafe {
            let h = GetStdHandle(id);
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// Spawn `agentshield daemon run` detached from the current console/session.
pub fn spawn_detached(paths: &Paths) -> std::io::Result<u32> {
    let exe = std::env::current_exe()?;
    #[cfg(windows)]
    std_handles_not_inheritable();
    paths.ensure()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.logs_dir().join("daemon.log"))?;
    let log2 = log.try_clone()?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2));
    if let Some(h) = std::env::var_os("AGENTSHIELD_HOME") {
        cmd.env("AGENTSHIELD_HOME", h);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    Ok(cmd.spawn()?.id())
}

/// Start the daemon if needed and wait until it answers.
pub fn start(paths: &Paths) -> Result<String, String> {
    if ping(paths) {
        return Ok("daemon already running".into());
    }
    let pid = spawn_detached(paths).map_err(|e| format!("cannot start daemon: {e}"))?;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(8) {
        std::thread::sleep(Duration::from_millis(100));
        if ping(paths) {
            return Ok(format!("daemon started (pid {pid})"));
        }
    }
    Err(format!(
        "daemon (pid {pid}) did not answer within 8 s; see {}",
        paths.logs_dir().join("daemon.log").display()
    ))
}

pub fn stop(paths: &Paths) -> Result<String, String> {
    if !ping(paths) {
        return Ok("daemon is not running".into());
    }
    agentshield_ipc::client::call_with_timeout::<serde_json::Value>(
        &paths.data_dir,
        "cli",
        Method::Shutdown {
            actor: "cli".into(),
        },
        Duration::from_secs(5),
    )
    .map_err(|e| e.to_string())?;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(100));
        if !ping(paths) {
            return Ok("daemon stopped".into());
        }
    }
    Err("daemon did not stop within 5 s".into())
}
