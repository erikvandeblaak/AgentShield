//! Local directories. Everything is per-user; nothing requires admin/root.
//!
//! | | Windows | Linux |
//! |---|---|---|
//! | config | `%APPDATA%\AgentShield` | `$XDG_CONFIG_HOME/agentshield` |
//! | data   | `%LOCALAPPDATA%\AgentShield` | `$XDG_DATA_HOME/agentshield` |
//!
//! `AGENTSHIELD_HOME` overrides both (config in `<home>/config`, data in `<home>/data`);
//! tests and the VS Code launch configurations use it so the real profile stays untouched.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn resolve() -> Paths {
        if let Some(home) = std::env::var_os("AGENTSHIELD_HOME").filter(|v| !v.is_empty()) {
            let home = PathBuf::from(home);
            return Paths {
                config_dir: home.join("config"),
                data_dir: home.join("data"),
            };
        }
        let config = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        let data = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        let name = if cfg!(windows) {
            "AgentShield"
        } else {
            "agentshield"
        };
        Paths {
            config_dir: config.join(name),
            data_dir: data.join(name),
        }
    }

    pub fn under(home: &Path) -> Paths {
        Paths {
            config_dir: home.join("config"),
            data_dir: home.join("data"),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn user_policy_file(&self) -> PathBuf {
        self.config_dir.join("policies").join("user.toml")
    }
    pub fn policies_dir(&self) -> PathBuf {
        self.config_dir.join("policies")
    }
    pub fn db_file(&self) -> PathBuf {
        self.data_dir.join("audit.db")
    }
    pub fn token_file(&self) -> PathBuf {
        self.data_dir.join("daemon.token")
    }
    pub fn key_file(&self) -> PathBuf {
        self.data_dir.join("fingerprint.key")
    }
    pub fn pid_file(&self) -> PathBuf {
        self.data_dir.join("daemon.pid")
    }
    pub fn backups_dir(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
    pub fn exports_dir(&self) -> PathBuf {
        self.data_dir.join("exports")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }
    pub fn run_dir(&self) -> PathBuf {
        self.data_dir.join("run")
    }

    /// Create directories with restrictive permissions (0700 on Unix; on Windows the
    /// per-user profile directories are already private to the user).
    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [
            &self.config_dir,
            &self.data_dir,
            &self.policies_dir(),
            &self.backups_dir(),
            &self.exports_dir(),
            &self.logs_dir(),
            &self.run_dir(),
        ] {
            std::fs::create_dir_all(d)?;
            restrict_dir(d)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
pub fn restrict_dir(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn restrict_dir(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn restrict_file(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn restrict_file(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Write a file atomically: write a temp file in the same directory, flush, then rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut rnd = [0u8; 6];
    let _ = getrandom::fill(&mut rnd);
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        hex::encode(rnd)
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}
