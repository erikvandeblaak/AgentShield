//! `config.toml`: operational mode, preset and preferences.

use crate::paths::{Paths, restrict_file, write_atomic};
use agentshield_event_model::Mode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub mode: Mode,
    pub preset: String,
    pub paused: bool,
    pub retention_days: u32,
    pub language: String,
    pub theme: String,
    pub notifications: bool,
    pub correlation_window_minutes: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: 1,
            mode: Mode::Monitor,
            preset: "developer-balanced".into(),
            paused: false,
            retention_days: 90,
            language: "en".into(),
            theme: "dark".into(),
            notifications: true,
            correlation_window_minutes: 15,
        }
    }
}

/// Partial update from the GUI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigPatch {
    pub retention_days: Option<u32>,
    pub language: Option<String>,
    pub theme: Option<String>,
    pub notifications: Option<bool>,
    pub correlation_window_minutes: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {message}")]
    Invalid { path: String, message: String },
    #[error("cannot write {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if agentshield_policy_engine::preset(&self.preset).is_none() {
            return Err(format!("unknown preset '{}'", self.preset));
        }
        if !(1..=3650).contains(&self.retention_days) {
            return Err("retention_days must be between 1 and 3650".into());
        }
        if !matches!(self.language.as_str(), "en" | "nl") {
            return Err("language must be 'en' or 'nl'".into());
        }
        if !matches!(self.theme.as_str(), "dark" | "light" | "system") {
            return Err("theme must be dark, light or system".into());
        }
        if !(1..=1440).contains(&self.correlation_window_minutes) {
            return Err("correlation_window_minutes must be 1..=1440".into());
        }
        Ok(())
    }

    /// Load; a missing file yields defaults. An invalid file is an error (never silently
    /// replaced: the caller decides; the hook falls back to defaults + degraded flag).
    pub fn load(paths: &Paths) -> Result<Config, ConfigError> {
        let p = paths.config_file();
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => {
                return Err(ConfigError::Read {
                    path: p.display().to_string(),
                    source: e,
                });
            }
        };
        let cfg: Config = toml::from_str(&text).map_err(|e| ConfigError::Invalid {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;
        cfg.validate().map_err(|m| ConfigError::Invalid {
            path: p.display().to_string(),
            message: m,
        })?;
        Ok(cfg)
    }

    pub fn save(&self, paths: &Paths) -> Result<(), ConfigError> {
        let p = paths.config_file();
        self.validate().map_err(|m| ConfigError::Invalid {
            path: p.display().to_string(),
            message: m,
        })?;
        let body = toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;
        let text = format!(
            "# AgentShield configuration. Change the mode with `agentshield mode <mode>` or the dashboard.\n{body}"
        );
        write_atomic(&p, text.as_bytes()).map_err(|e| ConfigError::Write {
            path: p.display().to_string(),
            source: e,
        })?;
        let _ = restrict_file(&p);
        Ok(())
    }

    pub fn apply(&mut self, patch: &ConfigPatch) -> Result<(), String> {
        let mut c = self.clone();
        if let Some(v) = patch.retention_days {
            c.retention_days = v;
        }
        if let Some(v) = &patch.language {
            c.language = v.clone();
        }
        if let Some(v) = &patch.theme {
            c.theme = v.clone();
        }
        if let Some(v) = patch.notifications {
            c.notifications = v;
        }
        if let Some(v) = patch.correlation_window_minutes {
            c.correlation_window_minutes = v;
        }
        c.validate()?;
        *self = c;
        Ok(())
    }
}
