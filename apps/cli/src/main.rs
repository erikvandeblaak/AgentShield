//! AgentShield command line interface.
//!
//! Exit codes: 0 success · 1 error · 2 usage error · 3 daemon unavailable ·
//! 4 check failed / risky result · 10 aborted by the user.

mod daemon_ctl;
mod hook;

use agentshield_adapter_claude_code as claude;
use agentshield_audit_log::{EventQuery, EventRow};
use agentshield_core::{Config, Engine, Paths};
use agentshield_event_model::{Mode, ShellKind};
use agentshield_ipc::{Method, client::call_with_timeout};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

const EXIT_ERR: i32 = 1;
const EXIT_DAEMON: i32 = 3;
const EXIT_CHECK: i32 = 4;
const EXIT_ABORT: i32 = 10;

const BANNER: &str = r"
   ___                    __  ______   _      __   __
  / _ |___ ____ ___  ____/ /_/ __/ /  (_)__  / /__/ /
 / __ / _ `/ -_) _ \/ __/ __/\ \/ _ \/ / -_)/ / _  /
/_/ |_\_, /\__/_//_/\__/\__/___/_//_/_/\__//_/\_,_/
     /___/   Erik's AgentShield · Local AI Agent Security & Observability
";

#[derive(Parser)]
#[command(name = "agentshield", version, about = "Erik's AgentShield — Local AI Agent Security & Observability.\nYour AI. Your machine. Your rules.", long_about = None, after_help = "Developed by Erik van de Blaak · vandeblaak.com")]
struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show mode, daemon, integration and coverage status.
    Status,
    /// Diagnose the installation (paths, config, policy, daemon, Claude Code integration).
    Doctor,
    /// Detect installed AI agents and their capabilities.
    Detect,
    /// Stream live events from the daemon.
    Watch {
        /// Only show events with at least this risk score.
        #[arg(long, default_value_t = 0)]
        min_score: u8,
    },
    /// Open the desktop dashboard.
    Dashboard,
    /// Change the operational mode (monitor, shadow, interactive, enforce, lockdown).
    Mode {
        mode: ModeArg,
        /// Confirm without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Pause monitoring (nothing is enforced while paused).
    Pause {
        #[arg(long)]
        yes: bool,
    },
    /// Resume monitoring.
    Resume,
    /// Manage agent integrations.
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Policies and presets.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Analyze commands without executing them.
    #[command(subcommand)]
    Command(CommandCmd),
    /// Audit events.
    #[command(subcommand)]
    Events(EventsCmd),
    /// Agent sessions.
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// Security checks (audit log integrity, integration, configuration).
    #[command(subcommand)]
    Security(SecurityCmd),
    /// Reports.
    #[command(subcommand)]
    Report(ReportCmd),
    /// Export redacted events (json, csv, sarif, html).
    Export {
        format: String,
        #[arg(long)]
        min_score: Option<u8>,
        #[arg(long)]
        session: Option<String>,
    },
    /// Run an end-to-end self test through the real hook binary (no agent needed).
    Selftest,
    /// Daemon control.
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// Hook entry point used by agents (reads the hook payload from stdin).
    #[command(hide = true)]
    Hook {
        #[arg(default_value = "claude-code")]
        agent: String,
        #[arg(long)]
        event: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Monitor,
    Shadow,
    Interactive,
    Enforce,
    Lockdown,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Mode {
        match m {
            ModeArg::Monitor => Mode::Monitor,
            ModeArg::Shadow => Mode::Shadow,
            ModeArg::Interactive => Mode::Interactive,
            ModeArg::Enforce => Mode::Enforce,
            ModeArg::Lockdown => Mode::Lockdown,
        }
    }
}

#[derive(Subcommand)]
enum AgentCmd {
    /// List agents and integration state.
    List,
    /// Install the AgentShield hooks (preview with --dry-run).
    Install(InstallArgs),
    /// Re-install hooks (e.g. after moving the binary).
    Repair(InstallArgs),
    /// Remove only AgentShield's hooks.
    Uninstall {
        agent: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args)]
struct InstallArgs {
    agent: String,
    /// Show the exact changes without writing anything.
    #[arg(long)]
    dry_run: bool,
    /// Make Claude Code block tool calls when the AgentShield hook fails (onFailure: block).
    #[arg(long)]
    fail_closed: bool,
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// List built-in presets.
    List,
    /// Show a preset (or the active one) as TOML.
    Show { preset: Option<String> },
    /// Validate a policy file.
    Validate { file: std::path::PathBuf },
    /// Simulate a command against a preset (nothing is executed).
    Simulate {
        command: String,
        #[arg(long)]
        preset: Option<String>,
    },
    /// Select the active preset.
    Use {
        preset: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum CommandCmd {
    /// Parse and risk-score a command. Never executes it.
    Analyze {
        command: String,
        #[arg(long, value_parser = ["bash", "powershell", "cmd"])]
        shell: Option<String>,
        #[arg(long)]
        preset: Option<String>,
    },
}

#[derive(Subcommand)]
enum EventsCmd {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        min_score: Option<u8>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        search: Option<String>,
    },
    /// Show one event in full (redacted).
    Show { id: i64 },
    /// Permanently delete events (privacy). The deletion is recorded in the hash chain.
    Delete {
        #[arg(required = true)]
        ids: Vec<i64>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum SessionsCmd {
    List {
        #[arg(long, default_value_t = 30)]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum SecurityCmd {
    /// Verify audit log hash chain, configuration and integration.
    Check,
}

#[derive(Subcommand)]
enum ReportCmd {
    /// Generate an HTML report: daily, weekly, project, agent_comparison, shadow, incident, coverage.
    Generate {
        #[arg(default_value = "daily")]
        kind: String,
        #[arg(long, default_value_t = 24)]
        hours: u32,
    },
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Run in the foreground.
    Run,
    /// Start in the background.
    Start,
    /// Stop the background daemon.
    Stop,
    /// Is the daemon running?
    Status,
}

struct Ctx {
    paths: Paths,
    json: bool,
    color: bool,
}

impl Ctx {
    fn out(&self, v: &Value, human: impl FnOnce() -> String) {
        if self.json {
            println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        } else {
            println!("{}", human());
        }
    }
    fn c(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn call(&self, m: Method) -> Result<Value, agentshield_ipc::IpcError> {
        call_with_timeout::<Value>(&self.paths.data_dir, "cli", m, Duration::from_secs(30))
    }
}

fn level_color(score: u8) -> &'static str {
    match score {
        80..=100 => "1;31",
        60..=79 => "31",
        40..=59 => "33",
        20..=39 => "36",
        _ => "2",
    }
}

fn mode_color(m: &str) -> &'static str {
    match m {
        "monitor" => "1;34",
        "shadow" => "1;35",
        "interactive" => "1;33",
        "enforce" => "1;32",
        _ => "1;31",
    }
}

fn mode_line(m: &str) -> String {
    match m {
        "monitor" => "MONITOR MODE — Observing, not blocking".into(),
        "shadow" => "SHADOW MODE — Simulating policy, not blocking".into(),
        "interactive" => {
            "INTERACTIVE MODE — Risky actions go to Claude Code's approval prompt".into()
        }
        "enforce" => "ENFORCE MODE — Policies enforced on supported surfaces".into(),
        "lockdown" => "LOCKDOWN MODE — Risky and mutating actions denied".into(),
        o => o.to_uppercase(),
    }
}

/// Ask for confirmation on a TTY; in non-interactive contexts `--yes` is required.
fn confirm(ctx: &Ctx, yes: bool, what: &str) -> bool {
    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{what}\nRefusing without confirmation in a non-interactive context; re-run with --yes."
        );
        return false;
    }
    eprint!("{what}\nType 'yes' to continue: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let ok = line.trim().eq_ignore_ascii_case("yes");
    if !ok {
        eprintln!("{}", ctx.c("33", "Aborted."));
    }
    ok
}

fn event_line(ctx: &Ctx, r: &EventRow) -> String {
    let x = &r.record;
    let local = chrono::DateTime::parse_from_rfc3339(&x.ts_utc)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default();
    let score = ctx.c(level_color(x.risk.score), &format!("{:>3}", x.risk.score));
    let would = match x.simulated_decision.as_str() {
        "deny" | "require_sandbox" => ctx.c("31", "would-deny"),
        "ask" => ctx.c("33", "would-ask "),
        "warn" => ctx.c("36", "warn      "),
        _ => "          ".into(),
    };
    let actual = match x.actual_decision.as_str() {
        "deny" => ctx.c("1;31", "BLOCKED"),
        "ask" => ctx.c("1;33", "ASKED  "),
        _ => "       ".into(),
    };
    let mut summary: String = x
        .summary
        .chars()
        .filter(|c| !c.is_control())
        .take(110)
        .collect();
    if x.summary.chars().count() > 110 {
        summary.push('…');
    }
    let phase = match x.phase.as_str() {
        "pre" => "pre ",
        "post" => "post",
        _ => "    ",
    };
    format!(
        "{:>6} {local} {} {score} {would} {actual} {:<16} {summary}",
        x.id,
        ctx.c("2", phase),
        x.action_type
    )
}

fn local_engine(paths: &Paths) -> anyhow::Result<Engine> {
    paths.ensure()?;
    Ok(Engine::new(
        paths.clone(),
        agentshield_core::load_or_create_key(paths)?,
    ))
}

fn hook_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .map(dunce)
        .unwrap_or_else(|_| "agentshield".into())
}

/// Strip the Windows verbatim prefix (\\?\) that current_exe may return.
fn dunce(p: std::path::PathBuf) -> std::path::PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => std::path::PathBuf::from(rest),
        _ => p,
    }
}

fn main() {
    // The hook path must stay silent and fast: dispatch before anything else.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("hook") {
        // `agentshield hook` (default agent claude-code), `hook <agent>` or `hook --agent <agent>`.
        let agent = match args.get(2).map(|s| s.as_str()) {
            Some("--agent") => args.get(3).cloned().unwrap_or_default(),
            Some(a) if !a.starts_with("--") => a.to_string(),
            _ => claude::AGENT_ID.to_string(),
        };
        let event = args
            .iter()
            .position(|a| a == "--event")
            .and_then(|i| args.get(i + 1))
            .cloned();
        std::process::exit(hook::run(&agent, event.as_deref()));
    }
    let cli = Cli::parse();
    let paths = Paths::resolve();
    let color =
        !cli.json && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let ctx = Ctx {
        paths,
        json: cli.json,
        color,
    };
    let code = match run(&ctx, cli.cmd) {
        Ok(c) => c,
        Err(e) => {
            if ctx.json {
                println!("{}", json!({ "error": e.to_string() }));
            } else {
                eprintln!("{} {e:#}", ctx.c("1;31", "error:"));
            }
            EXIT_ERR
        }
    };
    std::process::exit(code);
}

fn daemon_err(ctx: &Ctx, e: agentshield_ipc::IpcError) -> i32 {
    if ctx.json {
        println!(
            "{}",
            json!({ "error": e.to_string(), "daemon_running": false })
        );
    } else {
        eprintln!(
            "{} {e}\nStart it with: agentshield daemon start",
            ctx.c("1;31", "daemon unavailable:")
        );
    }
    EXIT_DAEMON
}

fn run(ctx: &Ctx, cmd: Cmd) -> anyhow::Result<i32> {
    match cmd {
        Cmd::Hook { agent, event } => Ok(hook::run(&agent, event.as_deref())),
        Cmd::Daemon(d) => match d {
            DaemonCmd::Run => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_env("AGENTSHIELD_LOG")
                            .unwrap_or_else(|_| "info".into()),
                    )
                    .with_writer(std::io::stderr)
                    .init();
                agentshield_daemon::run(ctx.paths.clone()).map_err(anyhow::Error::msg)?;
                Ok(0)
            }
            DaemonCmd::Start => match daemon_ctl::start(&ctx.paths) {
                Ok(m) => {
                    ctx.out(&json!({ "ok": true, "message": m }), || m.clone());
                    Ok(0)
                }
                Err(e) => {
                    eprintln!("{e}");
                    Ok(EXIT_DAEMON)
                }
            },
            DaemonCmd::Stop => {
                let m = daemon_ctl::stop(&ctx.paths).map_err(anyhow::Error::msg)?;
                ctx.out(&json!({ "ok": true, "message": m }), || m.clone());
                Ok(0)
            }
            DaemonCmd::Status => {
                let up = daemon_ctl::ping(&ctx.paths);
                ctx.out(&json!({ "running": up }), || {
                    if up {
                        "daemon running".into()
                    } else {
                        "daemon not running".into()
                    }
                });
                Ok(if up { 0 } else { EXIT_DAEMON })
            }
        },
        Cmd::Status => {
            let st = match ctx.call(Method::Status) {
                Ok(s) => s,
                Err(e) => {
                    let cfg = Config::load(&ctx.paths).unwrap_or_default();
                    let integ = claude::install::state(&claude::install::settings_path());
                    let v = json!({ "daemon_running": false, "error": e.to_string(), "mode": cfg.mode, "preset": cfg.preset, "integration": integ });
                    ctx.out(&v, || {
                        format!(
                            "{}\n  daemon     {}  ({e})\n  preset     {}\n  claude     hooks {}\n  note       hooks still evaluate locally (degraded) while the daemon is down",
                            ctx.c(mode_color(cfg.mode.as_str()), &mode_line(cfg.mode.as_str())),
                            ctx.c("1;31", "NOT RUNNING"),
                            cfg.preset,
                            if integ.verified { "installed & verified" } else if integ.installed { "installed, NOT verified" } else { "NOT installed" }
                        )
                    });
                    return Ok(EXIT_DAEMON);
                }
            };
            ctx.out(&st, || {
                let mode = st["mode"].as_str().unwrap_or("?");
                let mut s = format!("{}\n", ctx.c(mode_color(mode), &mode_line(mode)));
                if st["paused"].as_bool() == Some(true) {
                    s.push_str(&format!("{}\n", ctx.c("1;33", "MONITORING PAUSED — nothing is enforced")));
                }
                s.push_str(&format!(
                    "  daemon     running (pid {}, up {}s, v{})\n  policy     {} ({}), version {}\n  events     {} stored, {} dropped\n  hook p50/p95/p99  {} / {} / {} µs ({} samples)\n",
                    st["pid"], st["uptime_s"], st["daemon_version"].as_str().unwrap_or(""),
                    st["preset"].as_str().unwrap_or(""), st["policy_name"].as_str().unwrap_or(""), st["policy_version"].as_str().unwrap_or(""),
                    st["events_total"], st["dropped_events"],
                    st["hook_latency"]["p50_us"], st["hook_latency"]["p95_us"], st["hook_latency"]["p99_us"], st["hook_latency"]["count"]
                ));
                for r in st["degraded_reasons"].as_array().into_iter().flatten() {
                    s.push_str(&format!("  {} {}\n", ctx.c("33", "degraded:"), r.as_str().unwrap_or("")));
                }
                s.push_str(&format!("  data       {}", st["data_dir"].as_str().unwrap_or("")));
                s
            });
            Ok(0)
        }
        Cmd::Doctor => doctor(ctx),
        Cmd::Detect => {
            let agents = claude::detect::detect_all();
            let v = serde_json::to_value(&agents)?;
            ctx.out(&v, || {
                let mut s = String::new();
                for a in &agents {
                    s.push_str(&format!(
                        "{} {:<22} {:<10} {}\n",
                        if a.detected {
                            ctx.c("32", "●")
                        } else {
                            ctx.c("2", "○")
                        },
                        a.name,
                        if a.supported {
                            ctx.c("32", "supported")
                        } else {
                            ctx.c("2", "not supported")
                        },
                        a.version.clone().unwrap_or_default()
                    ));
                    if a.supported {
                        for c in &a.capabilities {
                            let col = match c.status.as_str() {
                                "enforced" => "32",
                                "observed" => "36",
                                "partial" | "unverified" => "33",
                                _ => "31",
                            };
                            s.push_str(&format!(
                                "    {:<24} {}  {}\n",
                                c.capability,
                                ctx.c(col, &format!("{:<11}", c.status)),
                                ctx.c("2", &c.reason)
                            ));
                        }
                    }
                }
                s
            });
            Ok(0)
        }
        Cmd::Watch { min_score } => watch(ctx, min_score),
        Cmd::Dashboard => {
            let exe = std::env::current_exe()?;
            let dir = exe.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let names = if cfg!(windows) {
                vec![
                    "Erik's AgentShield.exe",
                    "AgentShield.exe",
                    "agentshield-desktop.exe",
                ]
            } else {
                vec!["agentshield-desktop", "AgentShield"]
            };
            for n in names {
                let p = dir.join(n);
                if p.is_file() {
                    std::process::Command::new(&p).spawn()?;
                    println!("Opening {}", p.display());
                    return Ok(0);
                }
            }
            eprintln!(
                "Desktop app not found next to {}. Install the AgentShield desktop package or run it from apps/desktop.",
                exe.display()
            );
            Ok(EXIT_ERR)
        }
        Cmd::Mode { mode, yes } => {
            let mode: Mode = mode.into();
            let warn = match mode {
                Mode::Enforce => Some(
                    "Enforce Mode will DENY actions that the active policy rejects, on surfaces where Claude Code hooks can block (PreToolUse).",
                ),
                Mode::Lockdown => Some(
                    "Lockdown Mode denies ALL shell commands, file writes, MCP calls and web access from Claude Code until you switch back. Actions outside Claude Code hooks are NOT covered.",
                ),
                Mode::Monitor | Mode::Shadow => {
                    Some("This turns off blocking. If an AI agent asked you to run this, do not.")
                }
                Mode::Interactive => None,
            };
            if let Some(w) = warn
                && !confirm(ctx, yes, w)
            {
                return Ok(EXIT_ABORT);
            }
            match ctx.call(Method::SetMode {
                mode,
                actor: "cli".into(),
            }) {
                Ok(st) => {
                    ctx.out(&st, || {
                        ctx.c(mode_color(mode.as_str()), &mode_line(mode.as_str()))
                    });
                    Ok(0)
                }
                Err(_) => {
                    // Daemon down: change the config directly and log locally.
                    let mut cfg = Config::load(&ctx.paths).unwrap_or_default();
                    let from = cfg.mode;
                    cfg.mode = mode;
                    cfg.save(&ctx.paths)?;
                    let engine = local_engine(&ctx.paths)?;
                    let mut rec = agentshield_core::mode_change_record(
                        &engine,
                        from,
                        mode,
                        "cli (daemon offline)",
                    );
                    if let Ok(mut db) = agentshield_audit_log::AuditLog::open(&ctx.paths.db_file())
                    {
                        let _ = db.insert(&mut rec);
                    }
                    ctx.out(&json!({ "mode": mode, "daemon_running": false }), || {
                        format!(
                            "{} (daemon offline: saved to config)",
                            ctx.c(mode_color(mode.as_str()), &mode_line(mode.as_str()))
                        )
                    });
                    Ok(0)
                }
            }
        }
        Cmd::Pause { yes } => {
            if !confirm(ctx, yes, "Pausing stops all enforcement until you resume.") {
                return Ok(EXIT_ABORT);
            }
            match ctx.call(Method::SetPaused {
                paused: true,
                actor: "cli".into(),
            }) {
                Ok(v) => {
                    ctx.out(&v, || ctx.c("1;33", "MONITORING PAUSED"));
                    Ok(0)
                }
                Err(e) => Ok(daemon_err(ctx, e)),
            }
        }
        Cmd::Resume => match ctx.call(Method::SetPaused {
            paused: false,
            actor: "cli".into(),
        }) {
            Ok(v) => {
                ctx.out(&v, || "Monitoring resumed".into());
                Ok(0)
            }
            Err(e) => Ok(daemon_err(ctx, e)),
        },
        Cmd::Agent(a) => agent_cmd(ctx, a),
        Cmd::Policy(p) => policy_cmd(ctx, p),
        Cmd::Command(CommandCmd::Analyze {
            command,
            shell,
            preset,
        }) => {
            let engine = local_engine(&ctx.paths)?;
            let cfg = Config::load(&ctx.paths).unwrap_or_default();
            let shell = match shell.as_deref() {
                Some("powershell") => ShellKind::PowerShell,
                Some("cmd") => ShellKind::Cmd,
                Some("bash") => ShellKind::Bash,
                _ => agentshield_command_parser::guess_shell(&command, None),
            };
            let ev = agentshield_event_model::NormalizedEvent {
                ctx: agentshield_event_model::AgentContext {
                    agent: "cli".into(),
                    hook_event: "PreToolUse".into(),
                    tool: Some("Bash".into()),
                    workspace: std::env::current_dir()
                        .ok()
                        .map(|p| p.display().to_string()),
                    ..Default::default()
                },
                phase: agentshield_event_model::Phase::Pre,
                action: agentshield_event_model::ActionKind::ShellExec {
                    command: command.clone(),
                    shell,
                },
                input: json!({ "command": command }),
                post_failed: None,
                response_text: None,
                enforceable: true,
            };
            let r = engine
                .simulate(&ev, preset.as_deref().unwrap_or(&cfg.preset))
                .map_err(anyhow::Error::msg)?;
            let v = serde_json::to_value(&r)?;
            ctx.out(&v, || {
                let mut s = format!(
                    "{}  (nothing was executed)\n",
                    ctx.c("1", "Command analysis")
                );
                if let Some(p) = &r.parsed {
                    for seg in p.all_segments() {
                        s.push_str(&format!(
                            "  ▸ {} {}{}\n",
                            ctx.c("1", &seg.program),
                            seg.args.join(" "),
                            if seg.elevated() {
                                ctx.c("31", "  [elevated]")
                            } else {
                                String::new()
                            }
                        ));
                    }
                }
                s.push_str(&format!(
                    "\n  risk       {} ({}, confidence {})\n",
                    ctx.c(level_color(r.risk.score), &r.risk.score.to_string()),
                    r.risk.level.as_str(),
                    r.risk.confidence.as_str()
                ));
                for f in &r.risk.findings {
                    s.push_str(&format!(
                        "    {} {:<34} {}\n",
                        ctx.c(level_color(f.score), &format!("{:>3}", f.score)),
                        f.id,
                        f.explanation
                    ));
                }
                for e in &r.risk.explanation {
                    s.push_str(&format!("    {}\n", ctx.c("2", e)));
                }
                s.push_str(&format!(
                    "\n  policy     {} → {} ({})\n",
                    r.policy.policy_name,
                    ctx.c("1", r.policy.decision.as_str()),
                    r.policy.reason
                ));
                for (m, o) in &r.modes {
                    s.push_str(&format!("    {:<12} {}\n", m, o.actual.as_str()));
                }
                if let Some(sug) = &r.policy.suggestion {
                    s.push_str(&format!("\n  safer      {sug}\n"));
                }
                for l in &r.limitations {
                    s.push_str(&format!("  {} {l}\n", ctx.c("2", "note")));
                }
                s
            });
            Ok(if r.risk.score >= 60 { EXIT_CHECK } else { 0 })
        }
        Cmd::Events(EventsCmd::List {
            limit,
            min_score,
            session,
            search,
        }) => {
            let q = EventQuery {
                limit: Some(limit),
                min_score,
                session_id: session,
                search,
                ..Default::default()
            };
            let rows: Vec<EventRow> = match ctx.call(Method::ListEvents { query: q.clone() }) {
                Ok(v) => serde_json::from_value(v)?,
                Err(_) => agentshield_audit_log::AuditLog::open_readonly(&ctx.paths.db_file())
                    .and_then(|db| db.list(&q))
                    .unwrap_or_default(),
            };
            ctx.out(&serde_json::to_value(&rows)?, || {
                rows.iter()
                    .rev()
                    .map(|r| event_line(ctx, r))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(0)
        }
        Cmd::Events(EventsCmd::Show { id }) => {
            let row: Option<EventRow> = match ctx.call(Method::GetEvent { id }) {
                Ok(v) => serde_json::from_value(v)?,
                Err(_) => agentshield_audit_log::AuditLog::open_readonly(&ctx.paths.db_file())
                    .ok()
                    .and_then(|db| db.get(id).ok().flatten()),
            };
            match row {
                Some(r) => {
                    println!("{}", serde_json::to_string_pretty(&r)?);
                    Ok(0)
                }
                None => {
                    eprintln!("event {id} not found");
                    Ok(EXIT_ERR)
                }
            }
        }
        Cmd::Events(EventsCmd::Delete { ids, yes }) => {
            if !confirm(
                ctx,
                yes,
                &format!(
                    "Permanently delete {} event(s)? The deletion itself is recorded in the audit chain.",
                    ids.len()
                ),
            ) {
                return Ok(EXIT_ABORT);
            }
            let n: u64 = match ctx.call(Method::DeleteEvents { ids: ids.clone() }) {
                Ok(v) => serde_json::from_value(v)?,
                Err(_) => agentshield_audit_log::AuditLog::open(&ctx.paths.db_file())
                    .and_then(|mut db| db.delete_events(&ids))
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            };
            ctx.out(&json!({ "deleted": n }), || {
                format!("Deleted {n} event(s); residue purged from disk.")
            });
            Ok(0)
        }
        Cmd::Sessions(SessionsCmd::List { limit }) => {
            let v = match ctx.call(Method::Sessions { limit }) {
                Ok(v) => v,
                Err(_) => serde_json::to_value(
                    agentshield_audit_log::AuditLog::open_readonly(&ctx.paths.db_file())
                        .and_then(|db| db.sessions(limit))
                        .unwrap_or_default(),
                )?,
            };
            ctx.out(&v, || {
                v.as_array()
                    .into_iter()
                    .flatten()
                    .map(|s| {
                        format!(
                            "{:<38} {:>5} events  max {:>3}  would-block {:>3}  blocked {:>3}  {}",
                            s["session_id"].as_str().unwrap_or(""),
                            s["events"],
                            s["max_score"],
                            s["would_block"],
                            s["blocked"],
                            s["workspace"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(0)
        }
        Cmd::Security(SecurityCmd::Check) => {
            let mut failed = false;
            let mut out = json!({});
            let integrity = match ctx.call(Method::Verify) {
                Ok(v) => v,
                Err(_) => serde_json::to_value(
                    agentshield_audit_log::AuditLog::open_readonly(&ctx.paths.db_file())
                        .and_then(|db| db.verify())
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                )?,
            };
            failed |= integrity["ok"].as_bool() != Some(true);
            out["audit_log"] = integrity.clone();
            let cfg = Config::load(&ctx.paths);
            out["config_ok"] = json!(cfg.is_ok());
            failed |= cfg.is_err();
            let integ = claude::install::state(&claude::install::settings_path());
            out["claude_code_integration"] = serde_json::to_value(&integ)?;
            failed |= !integ.verified;
            ctx.out(&out, || {
                format!(
                    "audit log   {} ({} events checked, {} recorded deletions bridged){}\nconfig      {}\nintegration {}",
                    if integrity["ok"].as_bool() == Some(true) { ctx.c("32", "OK") } else { ctx.c("1;31", "FAILED") },
                    integrity["checked"], integrity["bridged_breaks"],
                    integrity["problem"].as_str().map(|p| format!(" — {p} at event #{}", integrity["first_bad_id"])).unwrap_or_default(),
                    if cfg.is_ok() { ctx.c("32", "OK") } else { ctx.c("1;31", "INVALID") },
                    if integ.verified { ctx.c("32", "Claude Code hooks verified") } else { ctx.c("33", &format!("not verified: missing {:?} problems {:?}", integ.missing_events, integ.problems)) }
                )
            });
            Ok(if failed { EXIT_CHECK } else { 0 })
        }
        Cmd::Report(ReportCmd::Generate { kind, hours }) => match ctx.call(Method::Report {
            kind,
            window_hours: hours,
        }) {
            Ok(v) => {
                ctx.out(&v, || {
                    format!("Report written to {}", v["path"].as_str().unwrap_or(""))
                });
                Ok(0)
            }
            Err(e) => Ok(daemon_err(ctx, e)),
        },
        Cmd::Export {
            format,
            min_score,
            session,
        } => match ctx.call(Method::Export {
            format,
            query: EventQuery {
                min_score,
                session_id: session,
                ..Default::default()
            },
        }) {
            Ok(v) => {
                ctx.out(&v, || {
                    format!(
                        "Exported {} events to {}",
                        v["count"],
                        v["path"].as_str().unwrap_or("")
                    )
                });
                Ok(0)
            }
            Err(e) => Ok(daemon_err(ctx, e)),
        },
        Cmd::Selftest => selftest(ctx),
    }
}

fn watch(ctx: &Ctx, min_score: u8) -> anyhow::Result<i32> {
    let mut c = match agentshield_ipc::Client::connect(&ctx.paths.data_dir, "cli/watch") {
        Ok(c) => c,
        Err(e) => return Ok(daemon_err(ctx, e)),
    };
    let start = match c.call_raw(Method::Status) {
        Ok(s) => s["events_total"].as_i64().unwrap_or(0),
        Err(e) => return Ok(daemon_err(ctx, e)),
    };
    let max_id: i64 = serde_json::from_value::<Vec<EventRow>>(c.call_raw(Method::ListEvents {
        query: EventQuery {
            limit: Some(1),
            ..Default::default()
        },
    })?)?
    .first()
    .map(|r| r.record.id)
    .unwrap_or(0);
    let _ = start;
    c.call_raw(Method::Subscribe { after_id: max_id })?;
    if !ctx.json {
        eprintln!("{}", ctx.c("2", BANNER));
        eprintln!("{}", ctx.c("2", "Watching live events (Ctrl-C to stop)…"));
    }
    let mut last = max_id;
    loop {
        match c.next_push()? {
            agentshield_ipc::Push::Event { row } => {
                let r: EventRow = serde_json::from_value(row)?;
                if r.record.id <= last {
                    continue;
                }
                last = r.record.id;
                if r.record.risk.score < min_score {
                    continue;
                }
                if ctx.json {
                    println!("{}", serde_json::to_string(&r)?);
                } else {
                    println!("{}", event_line(ctx, &r));
                }
            }
            agentshield_ipc::Push::Lagged { skipped } => eprintln!(
                "{}",
                ctx.c(
                    "33",
                    &format!("(skipped {skipped} events; use `agentshield events list`)")
                )
            ),
            agentshield_ipc::Push::Heartbeat => {}
        }
    }
}

fn agent_cmd(ctx: &Ctx, a: AgentCmd) -> anyhow::Result<i32> {
    let check_agent = |id: &str| -> anyhow::Result<()> {
        if id != claude::AGENT_ID {
            anyhow::bail!(
                "unsupported agent '{id}'. AgentShield currently integrates with Claude Code only (id: claude-code)."
            );
        }
        Ok(())
    };
    let sp = claude::install::settings_path();
    let backups = ctx.paths.backups_dir();
    match a {
        AgentCmd::List => {
            let agents = claude::detect::detect_all();
            let v = serde_json::to_value(&agents)?;
            ctx.out(&v, || {
                agents
                    .iter()
                    .map(|a| {
                        let integ = a
                            .integration
                            .as_ref()
                            .map(|i| {
                                if i.verified {
                                    ctx.c("32", "hooks verified")
                                } else if i.installed {
                                    ctx.c("33", "hooks installed, not verified")
                                } else {
                                    ctx.c("2", "hooks not installed")
                                }
                            })
                            .unwrap_or_else(|| ctx.c("2", "not supported"));
                        format!(
                            "{:<14} {:<22} {:<8} {}",
                            a.id,
                            a.name,
                            if a.detected { "detected" } else { "-" },
                            integ
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(0)
        }
        AgentCmd::Install(args) | AgentCmd::Repair(args) => {
            check_agent(&args.agent)?;
            let bin = hook_binary();
            let plan = claude::install::plan(&sp, &bin, args.fail_closed, &backups)
                .map_err(anyhow::Error::msg)?;
            if args.dry_run || ctx.json && !args.yes {
                ctx.out(&serde_json::to_value(&plan)?, || {
                    let mut s = format!(
                        "Planned changes to {} (dry run — nothing written):\n",
                        plan.settings_path
                    );
                    for c in &plan.changes {
                        s.push_str(&format!("  • {c}\n"));
                    }
                    s
                });
                return Ok(0);
            }
            if plan.already_installed {
                println!(
                    "AgentShield hooks are already installed and up to date in {}",
                    plan.settings_path
                );
                return Ok(0);
            }
            eprintln!("AgentShield will modify {}:", plan.settings_path);
            for c in &plan.changes {
                eprintln!("  • {c}");
            }
            if args.fail_closed {
                eprintln!("{}", ctx.c("1;33", "Fail-closed: if the AgentShield binary is moved, deleted or crashes, Claude Code will block every tool call until you repair or uninstall."));
            }
            if !confirm(ctx, args.yes, "Install these hooks?") {
                return Ok(EXIT_ABORT);
            }
            let r = claude::install::install(&sp, &bin, args.fail_closed, &backups);
            ctx.out(&serde_json::to_value(&r)?, || {
                format!(
                    "{} {}{}",
                    if r.ok {
                        ctx.c("32", "✔")
                    } else {
                        ctx.c("31", "✘")
                    },
                    r.message,
                    r.backup_path
                        .as_ref()
                        .map(|b| format!("\n  backup: {b}"))
                        .unwrap_or_default()
                )
            });
            if r.ok && !daemon_ctl::ping(&ctx.paths) {
                let _ = daemon_ctl::start(&ctx.paths);
            }
            Ok(if r.ok { 0 } else { EXIT_ERR })
        }
        AgentCmd::Uninstall { agent, yes } => {
            check_agent(&agent)?;
            if !confirm(
                ctx,
                yes,
                &format!(
                    "Remove AgentShield's hooks from {}? Other hooks and settings stay unchanged.",
                    sp.display()
                ),
            ) {
                return Ok(EXIT_ABORT);
            }
            let r = claude::install::uninstall(&sp, &backups);
            ctx.out(&serde_json::to_value(&r)?, || {
                format!(
                    "{} {}",
                    if r.ok {
                        ctx.c("32", "✔")
                    } else {
                        ctx.c("31", "✘")
                    },
                    r.message
                )
            });
            Ok(if r.ok { 0 } else { EXIT_ERR })
        }
    }
}

fn policy_cmd(ctx: &Ctx, p: PolicyCmd) -> anyhow::Result<i32> {
    match p {
        PolicyCmd::List => {
            let active = Config::load(&ctx.paths).unwrap_or_default().preset;
            let v: Vec<Value> = agentshield_policy_engine::PRESETS.iter().map(|p| json!({ "id": p.id, "title": p.title, "description": p.description, "active": p.id == active })).collect();
            ctx.out(&json!(v), || {
                agentshield_policy_engine::PRESETS
                    .iter()
                    .map(|p| {
                        format!(
                            "{} {:<20} {}",
                            if p.id == active {
                                ctx.c("32", "●")
                            } else {
                                " ".into()
                            },
                            p.id,
                            p.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(0)
        }
        PolicyCmd::Show { preset } => {
            let id = preset.unwrap_or_else(|| Config::load(&ctx.paths).unwrap_or_default().preset);
            let text = agentshield_policy_engine::preset_text(&id)
                .ok_or_else(|| anyhow::anyhow!("unknown preset '{id}'"))?;
            println!("{text}");
            Ok(0)
        }
        PolicyCmd::Validate { file } => {
            let text = std::fs::read_to_string(&file)?;
            match agentshield_policy_engine::validate(
                &text,
                agentshield_policy_engine::LayerKind::User,
            ) {
                Ok(w) => {
                    ctx.out(&json!({ "ok": true, "warnings": w }), || {
                        let mut s = ctx.c("32", "✔ policy is valid");
                        for x in &w {
                            s.push_str(&format!("\n  {} {x}", ctx.c("33", "warning:")));
                        }
                        s
                    });
                    Ok(0)
                }
                Err(e) => {
                    ctx.out(&json!({ "ok": false, "error": e.to_string() }), || {
                        format!("{} {e}", ctx.c("31", "✘ invalid:"))
                    });
                    Ok(EXIT_CHECK)
                }
            }
        }
        PolicyCmd::Simulate { command, preset } => run(
            ctx,
            Cmd::Command(CommandCmd::Analyze {
                command,
                shell: None,
                preset,
            }),
        ),
        PolicyCmd::Use { preset, yes } => {
            agentshield_policy_engine::preset(&preset)
                .ok_or_else(|| anyhow::anyhow!("unknown preset '{preset}'"))?;
            if !confirm(
                ctx,
                yes,
                &format!("Switch the active policy preset to '{preset}'?"),
            ) {
                return Ok(EXIT_ABORT);
            }
            match ctx.call(Method::SetPreset {
                preset: preset.clone(),
                actor: "cli".into(),
            }) {
                Ok(v) => ctx.out(&v, || format!("Active preset: {preset}")),
                Err(_) => {
                    let mut cfg = Config::load(&ctx.paths).unwrap_or_default();
                    cfg.preset = preset.clone();
                    cfg.save(&ctx.paths)?;
                    ctx.out(&json!({ "preset": preset }), || {
                        format!("Active preset: {preset} (daemon offline: saved to config)")
                    });
                }
            }
            Ok(0)
        }
    }
}

fn doctor(ctx: &Ctx) -> anyhow::Result<i32> {
    let mut checks: Vec<(String, bool, String)> = Vec::new();
    let p = &ctx.paths;
    checks.push((
        "data directory".into(),
        p.ensure().is_ok(),
        p.data_dir.display().to_string(),
    ));
    let cfg = Config::load(p);
    checks.push((
        "configuration".into(),
        cfg.is_ok(),
        cfg.as_ref()
            .map(|c| format!("mode {}, preset {}", c.mode, c.preset))
            .unwrap_or_else(|e| e.to_string()),
    ));
    let cfg = cfg.unwrap_or_default();
    match local_engine(p).and_then(|e| e.policy_set(&cfg.preset, None).map_err(anyhow::Error::msg))
    {
        Ok(s) => checks.push((
            "policy".into(),
            true,
            format!(
                "{} v{} ({} rules, {} warnings)",
                s.name,
                s.version,
                s.rule_count(),
                s.warnings.len()
            ),
        )),
        Err(e) => checks.push(("policy".into(), false, e.to_string())),
    }
    let daemon = ctx.call(Method::Status);
    checks.push((
        "daemon".into(),
        daemon.is_ok(),
        daemon
            .as_ref()
            .map(|s| {
                format!(
                    "v{} pid {}",
                    s["daemon_version"].as_str().unwrap_or(""),
                    s["pid"]
                )
            })
            .unwrap_or_else(|e| format!("{e} (hooks fall back to local evaluation)")),
    ));
    let claude_exe = claude::detect::which("claude");
    let ver = claude_exe.as_deref().and_then(claude::detect::version_of);
    checks.push((
        "Claude Code".into(),
        claude_exe.is_some(),
        claude_exe
            .as_ref()
            .map(|e| format!("{} {}", e.display(), ver.clone().unwrap_or_default()))
            .unwrap_or_else(|| "not found on PATH".into()),
    ));
    let st = claude::install::state(&claude::install::settings_path());
    let bin = hook_binary();
    let same_bin = st
        .binary_path
        .as_deref()
        .map(|b| std::path::Path::new(b) == bin)
        .unwrap_or(false);
    checks.push((
        "hooks installed".into(),
        st.installed,
        format!("{} events in {}", st.events.len(), st.settings_path),
    ));
    checks.push((
        "hooks verified".into(),
        st.verified,
        if st.problems.is_empty() {
            format!("missing: {:?}", st.missing_events)
        } else {
            st.problems.join("; ")
        },
    ));
    if st.installed {
        checks.push((
            "hook binary is this binary".into(),
            same_bin,
            format!(
                "settings: {} / this: {}",
                st.binary_path.unwrap_or_default(),
                bin.display()
            ),
        ));
    }
    let db = agentshield_audit_log::AuditLog::open_readonly(&p.db_file());
    match db.and_then(|d| d.verify()) {
        Ok(r) => checks.push((
            "audit log integrity".into(),
            r.ok,
            format!(
                "{} events checked{}",
                r.checked,
                r.problem.map(|x| format!(": {x}")).unwrap_or_default()
            ),
        )),
        Err(e) => checks.push((
            "audit log integrity".into(),
            false,
            format!("{e} (no events yet?)"),
        )),
    }
    let ok = checks.iter().all(|c| c.1);
    let v = json!({ "ok": ok, "checks": checks.iter().map(|(n, o, d)| json!({ "check": n, "ok": o, "detail": d })).collect::<Vec<_>>() });
    ctx.out(&v, || {
        checks
            .iter()
            .map(|(n, o, d)| {
                format!(
                    "{} {:<28} {}",
                    if *o {
                        ctx.c("32", "✔")
                    } else {
                        ctx.c("31", "✘")
                    },
                    n,
                    ctx.c("2", d)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(if ok { 0 } else { EXIT_CHECK })
}

/// Run the real hook binary with a synthetic, harmless PreToolUse payload and verify the
/// event arrives in the audit log. Uses a dedicated session id so it is clearly a test.
fn selftest(ctx: &Ctx) -> anyhow::Result<i32> {
    let exe = hook_binary();
    let sid = format!(
        "agentshield-selftest-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    let tuid = format!("selftest-{}", chrono::Utc::now().timestamp_millis());
    let payload = json!({
        "session_id": sid, "cwd": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        "hook_event_name": "PreToolUse", "permission_mode": "default",
        "tool_name": "Bash", "tool_input": { "command": "echo agentshield-selftest", "description": "AgentShield self test" },
        "tool_use_id": tuid,
    });
    let t = std::time::Instant::now();
    let mut child = std::process::Command::new(&exe)
        .args(claude::install::HOOK_ARGS)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .map(|mut s| s.write_all(payload.to_string().as_bytes()))
        .transpose()?;
    let out = child.wait_with_output()?;
    let ms = t.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let q = EventQuery {
        correlation_id: Some(tuid.clone()),
        ..Default::default()
    };
    let mut found: Option<EventRow> = None;
    for _ in 0..20 {
        let rows: Vec<EventRow> = match ctx.call(Method::ListEvents { query: q.clone() }) {
            Ok(v) => serde_json::from_value(v).unwrap_or_default(),
            Err(_) => agentshield_audit_log::AuditLog::open_readonly(&ctx.paths.db_file())
                .and_then(|db| db.list(&q))
                .unwrap_or_default(),
        };
        if let Some(r) = rows.into_iter().next() {
            found = Some(r);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let ok = out.status.code() == Some(0) && found.is_some() && !stdout.contains("\"allow\"");
    let v = json!({
        "ok": ok, "latency_ms": ms, "exit_code": out.status.code(), "stdout": stdout,
        "event_id": found.as_ref().map(|r| r.record.id), "via_daemon": found.as_ref().map(|r| r.record.via_daemon),
        "decision": found.as_ref().map(|r| r.record.actual_decision), "message": if ok { "Hook → engine → audit log path works" } else { "Self test failed" },
    });
    ctx.out(&v, || {
        format!(
            "{} self test: hook exit {:?}, {} ms, event #{} ({}), decision {}",
            if ok {
                ctx.c("32", "✔")
            } else {
                ctx.c("31", "✘")
            },
            out.status.code(),
            ms,
            found.as_ref().map(|r| r.record.id).unwrap_or(0),
            if found.as_ref().is_some_and(|r| r.record.via_daemon) {
                "via daemon"
            } else {
                "local fallback"
            },
            found
                .as_ref()
                .map(|r| r.record.actual_decision.as_str())
                .unwrap_or("-")
        )
    });
    Ok(if ok { 0 } else { EXIT_CHECK })
}
