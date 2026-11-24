//! Built-in policy presets (embedded from `policies/*.toml`).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub text: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "observe-everything",
        title: "Observe Everything",
        description: "Record everything, never block. Pairs with Monitor Mode.",
        text: include_str!("../../../policies/observe-everything.toml"),
    },
    Preset {
        id: "developer-balanced",
        title: "Developer Balanced",
        description: "Normal development is allowed; risky actions are flagged, dangerous ones need approval.",
        text: include_str!("../../../policies/developer-balanced.toml"),
    },
    Preset {
        id: "strict-security",
        title: "Strict Security",
        description: "Tighter rules for secrets, outbound connections and system changes.",
        text: include_str!("../../../policies/strict-security.toml"),
    },
    Preset {
        id: "laravel-developer",
        title: "Laravel Developer",
        description: "Balanced + artisan, Composer, migrations, .env, MySQL, Vite, PHPUnit/Pest awareness.",
        text: include_str!("../../../policies/laravel-developer.toml"),
    },
    Preset {
        id: "python-developer",
        title: "Python Developer",
        description: "Balanced + pip/uv/Poetry, venv, pytest awareness.",
        text: include_str!("../../../policies/python-developer.toml"),
    },
    Preset {
        id: "rust-developer",
        title: "Rust Developer",
        description: "Balanced + Cargo, rustc, rustfmt, Clippy, build scripts awareness.",
        text: include_str!("../../../policies/rust-developer.toml"),
    },
    Preset {
        id: "read-only",
        title: "Read Only",
        description: "Observe; deny file changes and non read-only commands where enforceable.",
        text: include_str!("../../../policies/read-only.toml"),
    },
    Preset {
        id: "production-server",
        title: "Production Server",
        description: "Very restrictive: read-only inspection commands only.",
        text: include_str!("../../../policies/production-server.toml"),
    },
    Preset {
        id: "database-safety",
        title: "Database Safety",
        description: "Balanced + strict handling of destructive database commands.",
        text: include_str!("../../../policies/database-safety.toml"),
    },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

pub fn preset_text(id: &str) -> Option<&'static str> {
    preset(id).map(|p| p.text)
}
