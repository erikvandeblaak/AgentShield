//! Sensitive path classification (credential stores, keys, agent configuration, ...).

use agentshield_event_model::RiskCategory;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    EnvFile,
    SshPrivateKey,
    SshConfig,
    PrivateKeyFile,
    CloudCredentials,
    KubeConfig,
    DockerCredentials,
    PackageManagerAuth,
    GitCredentials,
    NetrcOrDbPass,
    PasswordManagerExport,
    SystemCredentialStore,
    BrowserCredentialStore,
    AgentConfiguration,
    AgentShieldConfiguration,
    InfrastructureState,
    GitHooks,
    CiWorkflow,
    ShellStartup,
    GenericSecretFile,
}

impl SensitiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SensitiveKind::EnvFile => "env_file",
            SensitiveKind::SshPrivateKey => "ssh_private_key",
            SensitiveKind::SshConfig => "ssh_config",
            SensitiveKind::PrivateKeyFile => "private_key_file",
            SensitiveKind::CloudCredentials => "cloud_credentials",
            SensitiveKind::KubeConfig => "kube_config",
            SensitiveKind::DockerCredentials => "docker_credentials",
            SensitiveKind::PackageManagerAuth => "package_manager_auth",
            SensitiveKind::GitCredentials => "git_credentials",
            SensitiveKind::NetrcOrDbPass => "netrc_or_db_password_file",
            SensitiveKind::PasswordManagerExport => "password_manager_export",
            SensitiveKind::SystemCredentialStore => "system_credential_store",
            SensitiveKind::BrowserCredentialStore => "browser_credential_store",
            SensitiveKind::AgentConfiguration => "agent_configuration",
            SensitiveKind::AgentShieldConfiguration => "agentshield_configuration",
            SensitiveKind::InfrastructureState => "infrastructure_state",
            SensitiveKind::GitHooks => "git_hooks",
            SensitiveKind::CiWorkflow => "ci_workflow",
            SensitiveKind::ShellStartup => "shell_startup",
            SensitiveKind::GenericSecretFile => "generic_secret_file",
        }
    }

    /// Whether *reading* this path exposes credentials.
    pub fn read_is_secret_access(self) -> bool {
        !matches!(
            self,
            SensitiveKind::AgentConfiguration
                | SensitiveKind::AgentShieldConfiguration
                | SensitiveKind::GitHooks
                | SensitiveKind::CiWorkflow
                | SensitiveKind::ShellStartup
                | SensitiveKind::SshConfig
        )
    }
}

/// Classification of a sensitive path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SensitivePath {
    pub kind: SensitiveKind,
    pub label: &'static str,
    /// Score when the file is read.
    pub read_score: u8,
    /// Score when the file is written/edited.
    pub write_score: u8,
    pub read_category: RiskCategory,
    pub write_category: RiskCategory,
    /// `high` if the name is unambiguous, `medium` otherwise (e.g. `*.pem` may be a certificate).
    pub confidence: &'static str,
}

/// Normalize for matching: lowercase, forward slashes, collapse `//`, strip quotes.
pub fn normalize_path(p: &str) -> String {
    let mut s = p
        .trim()
        .trim_matches(['"', '\''])
        .replace('\\', "/")
        .to_ascii_lowercase();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    s
}

fn sp(
    kind: SensitiveKind,
    label: &'static str,
    read_score: u8,
    write_score: u8,
    write_category: RiskCategory,
    confidence: &'static str,
) -> SensitivePath {
    let read_category = if kind.read_is_secret_access() {
        RiskCategory::SecretAccess
    } else {
        RiskCategory::AgentConfigurationTampering
    };
    SensitivePath {
        kind,
        label,
        read_score,
        write_score,
        read_category,
        write_category,
        confidence,
    }
}

/// Classify a path. Returns `None` for ordinary files.
pub fn classify_path(path: &str) -> Option<SensitivePath> {
    use RiskCategory as C;
    use SensitiveKind as K;
    let n = normalize_path(path);
    if n.is_empty() {
        return None;
    }
    let base = n.rsplit('/').next().unwrap_or(&n);
    let has = |seg: &str| n.contains(seg);

    // Agent / AgentShield configuration first (writing it = tampering).
    if has("/agentshield/")
        && (base.ends_with(".toml")
            || base.ends_with(".token")
            || base.ends_with(".db")
            || base.ends_with(".key"))
        || has("/.agentshield/")
    {
        return Some(sp(
            K::AgentShieldConfiguration,
            "AgentShield configuration or data",
            30,
            95,
            C::AgentConfigurationTampering,
            "high",
        ));
    }
    if (has("/.claude/") && (base.starts_with("settings") && base.ends_with(".json")))
        || base == ".claude.json"
        || (has("/.claude/hooks/"))
        || (has("/.codex/") && base == "config.toml")
        || (has("/.cursor/") && (base == "mcp.json" || base == "hooks.json"))
        || base == ".mcp.json"
        || base == "claude_desktop_config.json"
    {
        return Some(sp(
            K::AgentConfiguration,
            "AI agent configuration (hooks, permissions, MCP)",
            20,
            90,
            C::AgentConfigurationTampering,
            "high",
        ));
    }

    // .env files (templates are fine).
    if base == ".env"
        || (base.starts_with(".env.")
            && !matches!(
                base,
                ".env.example"
                    | ".env.sample"
                    | ".env.template"
                    | ".env.dist"
                    | ".env.defaults"
                    | ".env.schema"
            ))
        || base.ends_with(".env") && !base.contains("example")
    {
        return Some(sp(
            K::EnvFile,
            "Environment file with credentials",
            70,
            55,
            C::UnauthorizedFileChange,
            "high",
        ));
    }

    if has("/.ssh/") || n.starts_with(".ssh/") || n.starts_with("~/.ssh/") {
        if base.starts_with("id_") && !base.ends_with(".pub") {
            return Some(sp(
                K::SshPrivateKey,
                "SSH private key",
                92,
                85,
                C::UnauthorizedFileChange,
                "high",
            ));
        }
        if base == "authorized_keys" {
            return Some(sp(
                K::SshConfig,
                "SSH authorized_keys",
                30,
                90,
                C::PersistenceIndicator,
                "high",
            ));
        }
        return Some(sp(
            K::SshConfig,
            "SSH configuration",
            35,
            70,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if (base.starts_with("id_rsa")
        || base.starts_with("id_ed25519")
        || base.starts_with("id_ecdsa")
        || base.starts_with("id_dsa"))
        && !base.ends_with(".pub")
    {
        return Some(sp(
            K::SshPrivateKey,
            "SSH private key",
            90,
            85,
            C::UnauthorizedFileChange,
            "high",
        ));
    }
    for ext in [
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".ppk",
        ".asc",
        ".gpg",
    ] {
        if base.ends_with(ext) {
            let conf = if ext == ".pem" || ext == ".asc" || ext == ".gpg" {
                "medium"
            } else {
                "high"
            };
            return Some(sp(
                K::PrivateKeyFile,
                "Private key / keystore file",
                80,
                70,
                C::UnauthorizedFileChange,
                conf,
            ));
        }
    }
    if has("/.aws/") && (base == "credentials" || base == "config") {
        let s = if base == "credentials" { 92 } else { 55 };
        return Some(sp(
            K::CloudCredentials,
            "AWS credentials",
            s,
            85,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if has("/.azure/")
        && (base.contains("token")
            || base.contains("profile")
            || base.contains("msal")
            || base.ends_with(".json")
            || base.ends_with(".bin"))
    {
        return Some(sp(
            K::CloudCredentials,
            "Azure CLI credentials",
            85,
            80,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if has("/gcloud/")
        && (base.contains("credentials") || base.ends_with(".db") || base == "access_tokens.db")
    {
        return Some(sp(
            K::CloudCredentials,
            "Google Cloud credentials",
            88,
            80,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if base.contains("service-account") && base.ends_with(".json")
        || base == "application_default_credentials.json"
    {
        return Some(sp(
            K::CloudCredentials,
            "Cloud service account key",
            85,
            70,
            C::UnauthorizedFileChange,
            "medium",
        ));
    }
    if (has("/.kube/") && base == "config") || base == "kubeconfig" || base.ends_with(".kubeconfig")
    {
        return Some(sp(
            K::KubeConfig,
            "Kubernetes credentials",
            85,
            80,
            C::InfrastructureModification,
            "high",
        ));
    }
    if has("/.docker/") && base == "config.json" {
        return Some(sp(
            K::DockerCredentials,
            "Docker registry credentials",
            75,
            70,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if matches!(
        base,
        ".npmrc"
            | ".yarnrc"
            | ".yarnrc.yml"
            | ".pypirc"
            | "pip.conf"
            | "pip.ini"
            | ".gem/credentials"
            | "nuget.config"
            | ".cargo/credentials"
            | ".cargo/credentials.toml"
    ) || (has("/.cargo/") && base.starts_with("credentials"))
        || (has("/composer/") && base == "auth.json")
        || (base == "auth.json" && has("composer"))
    {
        return Some(sp(
            K::PackageManagerAuth,
            "Package manager authentication",
            65,
            75,
            C::SupplyChainCompromise,
            "high",
        ));
    }
    if base == ".git-credentials" || (base == "credentials" && has("/.config/git/")) {
        return Some(sp(
            K::GitCredentials,
            "Git credentials",
            92,
            80,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if matches!(
        base,
        ".netrc" | "_netrc" | ".pgpass" | ".my.cnf" | ".mylogin.cnf"
    ) {
        return Some(sp(
            K::NetrcOrDbPass,
            "Stored network/database passwords",
            85,
            70,
            C::SecurityConfigurationChange,
            "high",
        ));
    }
    if base.ends_with(".kdbx")
        || base.ends_with(".1pux")
        || base.ends_with(".1pif")
        || base.ends_with(".agilekeychain")
        || (base.contains("bitwarden") && base.contains("export"))
        || (base.contains("lastpass") && base.ends_with(".csv"))
        || (base.contains("passwords") && base.ends_with(".csv"))
    {
        return Some(sp(
            K::PasswordManagerExport,
            "Password manager vault or export",
            96,
            80,
            C::UnauthorizedFileChange,
            "high",
        ));
    }
    if matches!(
        n.as_str(),
        "/etc/shadow" | "/etc/gshadow" | "/etc/sudoers" | "/etc/master.passwd"
    ) || n.starts_with("/etc/sudoers.d/")
        || n.ends_with("/windows/system32/config/sam")
        || n.ends_with("/windows/system32/config/security")
        || n.ends_with("/windows/system32/config/system")
        || has("/microsoft/credentials/")
        || has("/microsoft/protect/")
    {
        return Some(sp(
            K::SystemCredentialStore,
            "System credential store",
            95,
            95,
            C::PrivilegeEscalation,
            "high",
        ));
    }
    if (base == "login data"
        || base == "cookies"
        || base == "web data"
        || base == "key4.db"
        || base == "logins.json"
        || base == "local state")
        && (has("/chrome/")
            || has("/chromium/")
            || has("/edge/")
            || has("/brave")
            || has("/firefox/")
            || has("/mozilla/")
            || has("google-chrome"))
    {
        return Some(sp(
            K::BrowserCredentialStore,
            "Browser credential/cookie store",
            95,
            85,
            C::CredentialExposure,
            "high",
        ));
    }
    if base == "terraform.tfstate"
        || base == "terraform.tfstate.backup"
        || base.ends_with(".tfvars")
    {
        return Some(sp(
            K::InfrastructureState,
            "Infrastructure state (may contain secrets)",
            70,
            75,
            C::InfrastructureModification,
            "high",
        ));
    }
    if has("/.git/hooks/") {
        return Some(sp(
            K::GitHooks,
            "Git hook (code executed on git operations)",
            15,
            75,
            C::PersistenceIndicator,
            "high",
        ));
    }
    if has("/.github/workflows/")
        || base == ".gitlab-ci.yml"
        || has("/.circleci/")
        || base == "azure-pipelines.yml"
    {
        return Some(sp(
            K::CiWorkflow,
            "CI/CD workflow",
            10,
            55,
            C::SupplyChainCompromise,
            "high",
        ));
    }
    if matches!(
        base,
        ".bashrc"
            | ".bash_profile"
            | ".profile"
            | ".zshrc"
            | ".zprofile"
            | ".zshenv"
            | ".bash_login"
            | "config.fish"
    ) || base == "microsoft.powershell_profile.ps1"
        || base == "profile.ps1"
        || n.starts_with("/etc/profile")
        || has("/autostart/") && base.ends_with(".desktop")
        || has("/start menu/programs/startup/")
    {
        return Some(sp(
            K::ShellStartup,
            "Shell / login startup file",
            15,
            75,
            C::PersistenceIndicator,
            "high",
        ));
    }
    if matches!(
        base,
        "credentials.json"
            | "credentials.yml"
            | "credentials.yaml"
            | "secrets.json"
            | "secrets.yml"
            | "secrets.yaml"
            | "secrets.toml"
            | ".secrets"
            | "secret.json"
            | "master.key"
            | "credentials.yml.enc"
    ) || base.starts_with("secrets.")
    {
        return Some(sp(
            K::GenericSecretFile,
            "Likely secret file",
            60,
            50,
            C::UnauthorizedFileChange,
            "medium",
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(p: &str) -> Option<SensitiveKind> {
        classify_path(p).map(|s| s.kind)
    }

    #[test]
    fn env_files() {
        assert_eq!(kind("/home/u/app/.env"), Some(SensitiveKind::EnvFile));
        assert_eq!(
            kind("C:\\proj\\.env.production"),
            Some(SensitiveKind::EnvFile)
        );
        assert_eq!(kind("/app/.env.example"), None);
        assert_eq!(kind("/app/.env.template"), None);
        assert_eq!(kind("/app/environment.ts"), None);
    }

    #[test]
    fn ssh_and_keys() {
        assert_eq!(
            kind("~/.ssh/id_ed25519"),
            Some(SensitiveKind::SshPrivateKey)
        );
        assert_eq!(
            kind("C:\\Users\\x\\.ssh\\id_rsa"),
            Some(SensitiveKind::SshPrivateKey)
        );
        assert_eq!(
            kind("/home/x/.ssh/id_rsa.pub"),
            Some(SensitiveKind::SshConfig)
        );
        let ak = classify_path("/home/x/.ssh/authorized_keys").unwrap();
        assert_eq!(ak.write_category, RiskCategory::PersistenceIndicator);
        assert_eq!(
            kind("/srv/tls/server.key"),
            Some(SensitiveKind::PrivateKeyFile)
        );
    }

    #[test]
    fn cloud_and_tools() {
        assert_eq!(
            kind("/home/x/.aws/credentials"),
            Some(SensitiveKind::CloudCredentials)
        );
        assert_eq!(
            kind("/home/x/.kube/config"),
            Some(SensitiveKind::KubeConfig)
        );
        assert_eq!(
            kind("C:\\Users\\x\\.docker\\config.json"),
            Some(SensitiveKind::DockerCredentials)
        );
        assert_eq!(
            kind("/home/x/.npmrc"),
            Some(SensitiveKind::PackageManagerAuth)
        );
        assert_eq!(
            kind("/home/x/.config/composer/auth.json"),
            Some(SensitiveKind::PackageManagerAuth)
        );
        assert_eq!(
            kind("/home/x/.git-credentials"),
            Some(SensitiveKind::GitCredentials)
        );
        assert_eq!(
            kind("/home/x/vault.kdbx"),
            Some(SensitiveKind::PasswordManagerExport)
        );
        assert_eq!(
            kind("/etc/shadow"),
            Some(SensitiveKind::SystemCredentialStore)
        );
    }

    #[test]
    fn agent_config_is_tampering_on_write() {
        let c = classify_path("C:\\Users\\x\\.claude\\settings.json").unwrap();
        assert_eq!(c.kind, SensitiveKind::AgentConfiguration);
        assert_eq!(c.write_category, RiskCategory::AgentConfigurationTampering);
        assert!(c.write_score >= 80);
        assert_eq!(
            kind("/proj/.claude/settings.local.json"),
            Some(SensitiveKind::AgentConfiguration)
        );
        assert_eq!(
            kind("/proj/.mcp.json"),
            Some(SensitiveKind::AgentConfiguration)
        );
        assert_eq!(
            kind("C:\\Users\\x\\AppData\\Roaming\\AgentShield\\config.toml"),
            Some(SensitiveKind::AgentShieldConfiguration)
        );
    }

    #[test]
    fn persistence_and_ci() {
        assert_eq!(
            kind("/repo/.git/hooks/pre-commit"),
            Some(SensitiveKind::GitHooks)
        );
        assert_eq!(
            kind("/repo/.github/workflows/ci.yml"),
            Some(SensitiveKind::CiWorkflow)
        );
        assert_eq!(kind("/home/x/.bashrc"), Some(SensitiveKind::ShellStartup));
    }

    #[test]
    fn ordinary_files() {
        for p in [
            "/repo/src/main.rs",
            "README.md",
            "C:\\proj\\package.json",
            "/repo/Cargo.toml",
            "",
        ] {
            assert_eq!(kind(p), None, "{p}");
        }
    }
}
