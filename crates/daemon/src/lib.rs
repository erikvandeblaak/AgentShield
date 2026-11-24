//! The AgentShield daemon.
//!
//! Owns the audit database (single writer in normal operation), evaluates hook events
//! from the Claude Code adapter, streams new records to subscribers (the desktop app),
//! records mode changes, applies retention and creates correlation incidents.
//!
//! The daemon is independent from the GUI: closing or crashing the GUI never changes the
//! mode or stops evaluation.

use agentshield_adapter_claude_code as claude;
use agentshield_audit_log::{AuditLog, EventQuery, EventRow, Incident};
use agentshield_core::{Config, ConfigPatch, Engine, Paths};
use agentshield_event_model::*;
use agentshield_ipc::server::{Handler, HandlerError, ServerConfig, serve};
use agentshield_ipc::{HookReply, LatencySummary, Method};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::broadcast;

const LATENCY_SAMPLES: usize = 5000;

pub struct Daemon {
    pub paths: Paths,
    engine: Arc<Engine>,
    db: Mutex<AuditLog>,
    cfg: RwLock<Config>,
    tx: broadcast::Sender<Value>,
    started: Instant,
    hook_lat: Mutex<VecDeque<u64>>,
    eval_lat: Mutex<VecDeque<u64>>,
    degraded: Mutex<Vec<String>>,
    shutdown: tokio::sync::Notify,
}

fn hs(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::internal(e.to_string())
}

fn push_sample(q: &Mutex<VecDeque<u64>>, v: u64) {
    if let Ok(mut q) = q.lock() {
        if q.len() >= LATENCY_SAMPLES {
            q.pop_front();
        }
        q.push_back(v);
    }
}

fn summary(q: &Mutex<VecDeque<u64>>) -> LatencySummary {
    q.lock()
        .map(|q| LatencySummary::from_samples(&q.iter().copied().collect::<Vec<_>>()))
        .unwrap_or_default()
}

impl Daemon {
    pub fn new(paths: Paths) -> Result<Arc<Daemon>, String> {
        paths
            .ensure()
            .map_err(|e| format!("cannot create AgentShield directories: {e}"))?;
        let key = agentshield_core::load_or_create_key(&paths)
            .map_err(|e| format!("fingerprint key: {e}"))?;
        let mut degraded = Vec::new();
        let cfg = match Config::load(&paths) {
            Ok(c) => c,
            Err(e) => {
                // Never silently replace a broken config; run with safe defaults and say so.
                degraded.push(format!(
                    "{e}; running with default configuration (Monitor mode)"
                ));
                Config::default()
            }
        };
        let db = AuditLog::open(&paths.db_file()).map_err(|e| format!("audit database: {e}"))?;
        let (tx, _) = broadcast::channel(4096);
        Ok(Arc::new(Daemon {
            engine: Arc::new(Engine::new(paths.clone(), key)),
            paths,
            db: Mutex::new(db),
            cfg: RwLock::new(cfg),
            tx,
            started: Instant::now(),
            hook_lat: Mutex::new(VecDeque::new()),
            eval_lat: Mutex::new(VecDeque::new()),
            degraded: Mutex::new(degraded),
            shutdown: tokio::sync::Notify::new(),
        }))
    }

    fn cfg(&self) -> Config {
        self.cfg.read().map(|c| c.clone()).unwrap_or_default()
    }

    fn db(&self) -> Result<std::sync::MutexGuard<'_, AuditLog>, HandlerError> {
        self.db
            .lock()
            .map_err(|_| HandlerError::internal("database lock poisoned"))
    }

    fn store(&self, rec: &mut AuditRecord) -> Result<(), HandlerError> {
        let mut db = self.db()?;
        if let Err(e) = db.insert(rec) {
            let _ = db.add_dropped(1);
            return Err(hs(format!(
                "could not store event (counted as dropped): {e}"
            )));
        }
        drop(db);
        let row = EventRow {
            record: rec.clone(),
            observed_outcome: None,
        };
        if let Ok(v) = serde_json::to_value(&row) {
            let _ = self.tx.send(v);
        }
        Ok(())
    }

    fn incidents_for(&self, rec: &AuditRecord) {
        let mut out = Vec::new();
        for f in &rec.risk.findings {
            let is_corr = f.id.starts_with("correlation.");
            let is_tamper = f.id.starts_with("tamper.")
                || f.category == RiskCategory::AgentConfigurationTampering && f.score >= 85;
            if !(is_corr || is_tamper) {
                continue;
            }
            let mut ids = vec![rec.id];
            if let Some(e) = &f.evidence
                && let Some(n) = e
                    .strip_prefix("event #")
                    .and_then(|x| x.parse::<i64>().ok())
            {
                ids.insert(0, n);
            }
            let title = match f.id.as_str() {
                "correlation.secret_then_egress" => {
                    "Credential access followed by network activity"
                }
                "correlation.injection_then_risky_action" => {
                    "Risky action after prompt-injection indicators"
                }
                "correlation.repeated_denied_attempts" => {
                    "Agent repeatedly attempts denied actions"
                }
                _ if is_tamper => "Agent attempted to change security configuration",
                _ => "Correlated suspicious activity",
            };
            let sev = match RiskLevel::from_score(rec.risk.score.max(f.score)) {
                RiskLevel::Critical => "critical",
                RiskLevel::High => "high",
                _ => "medium",
            };
            out.push(Incident {
                id: 0,
                ts_utc: rec.ts_utc.clone(),
                session_id: rec.session_id.clone(),
                rule_id: f.id.clone(),
                title: title.into(),
                severity: sev.into(),
                score: rec.risk.score.max(f.score),
                confidence: f.confidence.as_str().into(),
                explanation: format!("{} Correlation and detections indicate risk; they do not prove intent or that harm occurred.", f.explanation),
                event_ids: ids,
            });
        }
        if out.is_empty() {
            return;
        }
        let window = i64::from(self.cfg().correlation_window_minutes);
        let since = (chrono::Utc::now() - chrono::Duration::minutes(window))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Ok(mut db) = self.db.lock() {
            for i in out {
                let _ = db.insert_incident(&i, Some(&since));
            }
        }
    }

    /// Evaluate a hook payload end-to-end.
    pub fn handle_hook(
        &self,
        agent: &str,
        hint: Option<&str>,
        payload: &Value,
    ) -> Result<HookReply, HandlerError> {
        let t0 = Instant::now();
        if agent != claude::AGENT_ID {
            return Err(HandlerError::bad_request(format!(
                "unsupported agent '{agent}'"
            )));
        }
        let ev = match claude::normalize(payload, hint) {
            Ok(e) => e,
            Err(e) => {
                if let Ok(db) = self.db.lock() {
                    let _ = db.add_dropped(1);
                }
                return Err(HandlerError::bad_request(format!(
                    "malformed hook payload: {e}"
                )));
            }
        };
        let cfg = self.cfg();
        let recent = match (&ev.ctx.session_id, ev.phase) {
            (Some(sid), Phase::Pre) => {
                let since = (chrono::Utc::now()
                    - chrono::Duration::minutes(i64::from(cfg.correlation_window_minutes)))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                self.db()?
                    .recent_session_events(sid, &since, 200)
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        };
        let degraded = self.degraded.lock().map(|d| d.clone()).unwrap_or_default();
        let te = Instant::now();
        let eval = self
            .engine
            .evaluate(&ev, &cfg, &recent, true, &degraded, t0);
        push_sample(&self.eval_lat, te.elapsed().as_micros() as u64);
        let mut rec = eval.record;
        // Rendering happens before storage so a DB problem can never change the decision.
        let out = claude::render(&ev.ctx.hook_event, &eval.mode_outcome);
        let stored = self.store(&mut rec);
        if stored.is_ok() {
            self.incidents_for(&rec);
        }
        push_sample(&self.hook_lat, t0.elapsed().as_micros() as u64);
        Ok(HookReply {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            event_id: rec.id,
        })
    }

    pub fn status(&self) -> Value {
        let cfg = self.cfg();
        let (events_total, dropped) = self
            .db
            .lock()
            .map(|db| {
                (
                    db.count().unwrap_or(0),
                    db.meta_get("dropped_events")
                        .ok()
                        .flatten()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));
        let mut degraded = self.degraded.lock().map(|d| d.clone()).unwrap_or_default();
        let (policy_name, policy_version, warnings) =
            match self.engine.policy_set(&cfg.preset, None) {
                Ok(s) => (s.name.clone(), s.version.clone(), s.warnings.clone()),
                Err(e) => {
                    degraded.push(format!("policy: {e}"));
                    (cfg.preset.clone(), "error".into(), vec![])
                }
            };
        let st = claude::install::state(&claude::install::settings_path());
        if !st.installed {
            degraded.push("Claude Code hooks are not installed: nothing is being observed".into());
        } else if !st.verified {
            degraded.push(format!(
                "Claude Code integration not verified: {}",
                st.problems.join("; ")
            ));
        }
        if cfg.paused {
            degraded.push("Monitoring is paused: decisions are not enforced".into());
        }
        json!({
            "daemon_running": true,
            "daemon_version": agentshield_core::VERSION,
            "pid": std::process::id(),
            "uptime_s": self.started.elapsed().as_secs(),
            "mode": cfg.mode,
            "preset": cfg.preset,
            "paused": cfg.paused,
            "policy_name": policy_name,
            "policy_version": policy_version,
            "policy_warnings": warnings,
            "events_total": events_total,
            "dropped_events": dropped,
            "hook_latency": summary(&self.hook_lat),
            "eval_latency": summary(&self.eval_lat),
            "degraded": !degraded.is_empty(),
            "degraded_reasons": degraded,
            "data_dir": self.paths.data_dir,
            "config_dir": self.paths.config_dir,
            "db_path": self.paths.db_file(),
            "version": agentshield_core::VERSION,
            "build": format!("{} {}", if cfg!(debug_assertions) { "debug" } else { "release" }, std::env::consts::OS),
        })
    }

    fn update_cfg(
        &self,
        f: impl FnOnce(&mut Config) -> Result<(), String>,
    ) -> Result<Config, HandlerError> {
        let mut guard = self
            .cfg
            .write()
            .map_err(|_| HandlerError::internal("config lock poisoned"))?;
        let mut next = guard.clone();
        f(&mut next).map_err(HandlerError::bad_request)?;
        next.save(&self.paths).map_err(hs)?;
        *guard = next.clone();
        // A successful save fixes an earlier invalid config.
        if let Ok(mut d) = self.degraded.lock() {
            d.retain(|x| !x.contains("running with default configuration"));
        }
        Ok(next)
    }

    fn set_mode(&self, mode: Mode, actor: &str) -> Result<Value, HandlerError> {
        let from = self.cfg().mode;
        self.update_cfg(|c| {
            c.mode = mode;
            Ok(())
        })?;
        let mut rec = agentshield_core::mode_change_record(&self.engine, from, mode, actor);
        self.store(&mut rec)?;
        tracing::info!("mode changed {from} -> {mode} by {actor}");
        Ok(self.status())
    }

    fn policy_info(&self) -> Result<Value, HandlerError> {
        let cfg = self.cfg();
        let set = self
            .engine
            .policy_set(&cfg.preset, None)
            .map_err(HandlerError::bad_request)?;
        let user_path = self.paths.user_policy_file();
        let user_text = std::fs::read_to_string(&user_path)
            .unwrap_or_else(|_| USER_POLICY_TEMPLATE.to_string());
        let rules: Vec<Value> = set.rules().into_iter().map(|(id, name, decision, enabled, hard, layer)| json!({ "id": id, "name": name, "decision": decision, "enabled": enabled, "hard": hard, "layer": layer })).collect();
        Ok(json!({
            "name": set.name,
            "version": set.version,
            "thresholds": set.thresholds,
            "rules": rules,
            "warnings": set.warnings,
            "sources": set.sources.iter().map(|(k, s)| json!([k, s])).collect::<Vec<_>>(),
            "user_policy_path": user_path,
            "user_policy_text": user_text,
        }))
    }

    fn simulate(&self, input: &Value) -> Result<Value, HandlerError> {
        let cfg = self.cfg();
        let preset = input
            .get("preset")
            .and_then(|p| p.as_str())
            .unwrap_or(&cfg.preset)
            .to_string();
        let workspace = input
            .get("workspace")
            .and_then(|w| w.as_str())
            .map(|s| s.to_string());
        let ev = if let Some(cmd) = input.get("command").and_then(|c| c.as_str()) {
            let shell = match input.get("shell").and_then(|s| s.as_str()) {
                Some("power_shell") | Some("powershell") => ShellKind::PowerShell,
                Some("cmd") => ShellKind::Cmd,
                Some("bash") => ShellKind::Bash,
                _ if cmd.trim_start().to_ascii_lowercase().starts_with("cmd ") => ShellKind::Cmd,
                _ => agentshield_command_parser::guess_shell(cmd, None),
            };
            NormalizedEvent {
                ctx: AgentContext {
                    agent: "simulator".into(),
                    workspace,
                    hook_event: "PreToolUse".into(),
                    tool: Some(
                        if shell == ShellKind::PowerShell {
                            "PowerShell"
                        } else {
                            "Bash"
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
                phase: Phase::Pre,
                action: ActionKind::ShellExec {
                    command: cmd.to_string(),
                    shell,
                },
                input: json!({ "command": cmd }),
                post_failed: None,
                response_text: None,
                enforceable: true,
            }
        } else if let Some(tool) = input.get("tool").and_then(|t| t.as_str()) {
            let payload = json!({ "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input.get("tool_input").cloned().unwrap_or(json!({})), "cwd": workspace });
            claude::normalize(&payload, None)
                .map_err(|e| HandlerError::bad_request(e.to_string()))?
        } else {
            return Err(HandlerError::bad_request("provide 'command' or 'tool'"));
        };
        let r = self
            .engine
            .simulate(&ev, &preset)
            .map_err(HandlerError::bad_request)?;
        serde_json::to_value(r).map_err(hs)
    }

    fn mcp_servers(&self) -> Result<Value, HandlerError> {
        let (workspaces, calls) = {
            let db = self.db()?;
            let ws: Vec<String> = db
                .sessions(200)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| s.workspace)
                .collect();
            let rows = db
                .list(&EventQuery {
                    mcp_only: true,
                    phase: Some("pre".into()),
                    limit: Some(5000),
                    ..Default::default()
                })
                .unwrap_or_default();
            (ws, rows)
        };
        let mut servers = claude::mcp::discover(self.engine.redactor(), &workspaces);
        let db = self.db()?;
        for s in &mut servers {
            let key = format!("mcp_fp:{}:{}", s.scope, s.name);
            match db.meta_get(&key).ok().flatten() {
                Some(v) => {
                    let (fp, first) = v.split_once('|').unwrap_or((v.as_str(), ""));
                    s.first_seen = (!first.is_empty()).then(|| first.to_string());
                    if fp != s.fingerprint {
                        s.changed_since_last_seen = true;
                        let _ = db.meta_set(&key, &format!("{}|{}", s.fingerprint, first));
                    }
                }
                None => {
                    let now = now_rfc3339();
                    let _ = db.meta_set(&key, &format!("{}|{now}", s.fingerprint));
                    s.first_seen = Some(now);
                }
            }
            let mut tools = std::collections::BTreeSet::new();
            for r in &calls {
                if let ActionKind::McpCall { server, tool } = &r.record.action
                    && server == &s.name
                {
                    s.observed_calls += 1;
                    tools.insert(tool.clone());
                }
            }
            s.tools_seen = tools.into_iter().collect();
        }
        // Servers seen in events but not in config (e.g. plugin servers).
        let known: std::collections::HashSet<String> =
            servers.iter().map(|s| s.name.clone()).collect();
        let mut extra: std::collections::BTreeMap<
            String,
            (u64, std::collections::BTreeSet<String>),
        > = Default::default();
        for r in &calls {
            if let ActionKind::McpCall { server, tool } = &r.record.action
                && !known.contains(server)
            {
                let e = extra.entry(server.clone()).or_default();
                e.0 += 1;
                e.1.insert(tool.clone());
            }
        }
        for (name, (n, tools)) in extra {
            servers.push(claude::mcp::McpServerInfo {
                name,
                scope: "observed (plugin or unknown config)".into(),
                source: "observed in hook events".into(),
                transport: "unknown".into(),
                command: None,
                args: vec![],
                url_host: None,
                env_keys: vec![],
                fingerprint: String::new(),
                changed_since_last_seen: false,
                first_seen: None,
                routed_via_agentshield: false,
                findings: vec![],
                observed_calls: n,
                tools_seen: tools.into_iter().collect(),
            });
        }
        serde_json::to_value(servers).map_err(hs)
    }

    fn export(&self, format: &str, query: &EventQuery) -> Result<Value, HandlerError> {
        let mut q = query.clone();
        q.limit = Some(q.limit.unwrap_or(5000).min(5000));
        q.after_id = None;
        let rows = self.db()?.list(&q).map_err(hs)?;
        let (body, ext) = match format {
            "json" => (agentshield_reporting::to_json(&rows), "json"),
            "csv" => (agentshield_reporting::to_csv(&rows), "csv"),
            "sarif" => (
                agentshield_reporting::to_sarif(&rows, agentshield_core::VERSION),
                "sarif",
            ),
            "html" => (
                agentshield_reporting::to_html(&rows, agentshield_core::VERSION),
                "html",
            ),
            other => {
                return Err(HandlerError::bad_request(format!(
                    "unknown export format '{other}'"
                )));
            }
        };
        let path = self.paths.exports_dir().join(format!(
            "agentshield-events-{}.{ext}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        ));
        agentshield_core::paths::write_atomic(&path, body.as_bytes()).map_err(hs)?;
        Ok(json!({ "path": path, "count": rows.len() }))
    }

    fn report(&self, kind: &str, window_hours: u32) -> Result<Value, HandlerError> {
        let kind: agentshield_reporting::ReportKind =
            kind.parse().map_err(HandlerError::bad_request)?;
        let wh = match kind {
            agentshield_reporting::ReportKind::Daily => 24,
            agentshield_reporting::ReportKind::Weekly => 168,
            _ => window_hours.clamp(1, 24 * 90),
        };
        let since = (chrono::Utc::now() - chrono::Duration::hours(i64::from(wh)))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (stats, risky, sessions, incidents) = {
            let db = self.db()?;
            (
                db.stats(wh).map_err(hs)?,
                db.list(&EventQuery {
                    min_score: Some(40),
                    since: Some(since.clone()),
                    limit: Some(1000),
                    ..Default::default()
                })
                .map_err(hs)?,
                db.sessions(100)
                    .map_err(hs)?
                    .into_iter()
                    .filter(|s| s.last_ts >= since)
                    .collect::<Vec<_>>(),
                db.incidents(500)
                    .map_err(hs)?
                    .into_iter()
                    .filter(|i| i.ts_utc >= since)
                    .collect::<Vec<_>>(),
            )
        };
        let st = claude::install::state(&claude::install::settings_path());
        let coverage: Vec<(String, String, String)> =
            claude::detect::claude_capabilities(Some(&st))
                .into_iter()
                .map(|c| (c.capability, c.status, c.reason))
                .collect();
        let cfg = self.cfg();
        let html = agentshield_reporting::report_html(&agentshield_reporting::ReportData {
            kind,
            window_hours: wh,
            stats: &stats,
            risky: &risky,
            sessions: &sessions,
            incidents: &incidents,
            coverage: &coverage,
            mode: cfg.mode.as_str(),
            policy: &cfg.preset,
            version: agentshield_core::VERSION,
        });
        let path = self.paths.exports_dir().join(format!(
            "agentshield-{}-report-{}.html",
            kind.slug(),
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        ));
        agentshield_core::paths::write_atomic(&path, html.as_bytes()).map_err(hs)?;
        Ok(json!({ "path": path, "title": kind.title() }))
    }

    pub fn apply_retention(&self) -> Result<u64, HandlerError> {
        let days = self.cfg().retention_days;
        self.db()?.apply_retention(days).map_err(hs)
    }
}

pub const USER_POLICY_TEMPLATE: &str = r#"# AgentShield user policy (layered on top of the selected preset).
# Rules here apply to every project. See docs/POLICIES.md for the full reference.
schema_version = 1

# Example: never let the agent read your production env file.
# [[rules]]
# id = "protect-prod-env"
# name = "Production env file"
# [rules.match]
# event_types = ["file.read", "shell.exec"]
# path_globs = ["**/.env.production"]
# [rules.effect]
# action = "deny"
# severity = "critical"
# reason = "Production credentials"
"#;

impl Handler for Daemon {
    fn handle(&self, method: Method, client: &str) -> Result<Value, HandlerError> {
        match method {
            Method::Ping => Ok(json!({ "pong": true, "version": agentshield_core::VERSION })),
            Method::Status => Ok(self.status()),
            Method::Hook {
                agent,
                hook_event,
                payload,
            } => serde_json::to_value(self.handle_hook(&agent, hook_event.as_deref(), &payload)?)
                .map_err(hs),
            Method::ListEvents { query } => {
                serde_json::to_value(self.db()?.list(&query).map_err(hs)?).map_err(hs)
            }
            Method::GetEvent { id } => {
                serde_json::to_value(self.db()?.get(id).map_err(hs)?).map_err(hs)
            }
            Method::CountEvents { query } => Ok(json!(self.db()?.count_matching(&query).map_err(hs)?)),
            Method::GetSession { session_id } => {
                serde_json::to_value(self.db()?.session(&session_id).map_err(hs)?).map_err(hs)
            }
            Method::Stats { window_hours } => {
                serde_json::to_value(self.db()?.stats(window_hours).map_err(hs)?).map_err(hs)
            }
            Method::Sessions { limit } => {
                serde_json::to_value(self.db()?.sessions(limit).map_err(hs)?).map_err(hs)
            }
            Method::Incidents { limit } => {
                serde_json::to_value(self.db()?.incidents(limit).map_err(hs)?).map_err(hs)
            }
            Method::SetMode { mode, actor } => {
                self.set_mode(mode, &format!("{actor} via {client}"))
            }
            Method::SetPreset { preset, actor } => {
                agentshield_policy_engine::preset(&preset).ok_or_else(|| {
                    HandlerError::bad_request(format!("unknown preset '{preset}'"))
                })?;
                self.update_cfg(|c| {
                    c.preset = preset.clone();
                    Ok(())
                })?;
                tracing::info!("preset changed to {preset} by {actor}");
                Ok(self.status())
            }
            Method::SetPaused { paused, actor } => {
                self.update_cfg(|c| {
                    c.paused = paused;
                    Ok(())
                })?;
                let m = self.cfg().mode;
                let mut rec = agentshield_core::mode_change_record(
                    &self.engine,
                    m,
                    if paused { Mode::Monitor } else { m },
                    &format!(
                        "{} by {actor} via {client}",
                        if paused { "pause" } else { "resume" }
                    ),
                );
                self.store(&mut rec)?;
                Ok(self.status())
            }
            Method::GetConfig => serde_json::to_value(self.cfg()).map_err(hs),
            Method::SetConfig { patch } => {
                let p: ConfigPatch = serde_json::from_value(patch)
                    .map_err(|e| HandlerError::bad_request(e.to_string()))?;
                serde_json::to_value(self.update_cfg(|c| c.apply(&p))?).map_err(hs)
            }
            Method::PolicyInfo => self.policy_info(),
            Method::ValidatePolicy { text } => Ok(
                match agentshield_policy_engine::validate(
                    &text,
                    agentshield_policy_engine::LayerKind::User,
                ) {
                    Ok(w) => json!({ "ok": true, "warnings": w, "error": null }),
                    Err(e) => json!({ "ok": false, "warnings": [], "error": e.to_string() }),
                },
            ),
            Method::SaveUserPolicy { text } => {
                if text.len() > 512 * 1024 {
                    return Err(HandlerError::bad_request("policy too large"));
                }
                agentshield_policy_engine::validate(
                    &text,
                    agentshield_policy_engine::LayerKind::User,
                )
                .map_err(|e| HandlerError::bad_request(e.to_string()))?;
                let p = self.paths.user_policy_file();
                if p.exists() {
                    let b = self.paths.backups_dir().join(format!(
                        "user-policy-{}.toml",
                        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f")
                    ));
                    let _ = std::fs::copy(&p, b);
                }
                agentshield_core::paths::write_atomic(&p, text.as_bytes()).map_err(hs)?;
                tracing::info!("user policy saved by {client}");
                self.policy_info()
            }
            Method::Simulate { input } => self.simulate(&input),
            Method::Replay {
                preset,
                session_id,
                limit,
            } => {
                let rows = self
                    .db()?
                    .list(&EventQuery {
                        session_id,
                        phase: Some("pre".into()),
                        limit: Some(limit.clamp(1, 5000)),
                        ..Default::default()
                    })
                    .map_err(hs)?;
                let recs: Vec<AuditRecord> = rows.into_iter().map(|r| r.record).collect();
                serde_json::to_value(
                    self.engine
                        .replay(&recs, &preset)
                        .map_err(HandlerError::bad_request)?,
                )
                .map_err(hs)
            }
            Method::Verify => serde_json::to_value(self.db()?.verify().map_err(hs)?).map_err(hs),
            Method::Backup => {
                let dest = self.paths.backups_dir().join(format!(
                    "audit-{}.db",
                    chrono::Utc::now().format("%Y%m%d-%H%M%S")
                ));
                self.db()?.backup(&dest).map_err(hs)?;
                Ok(json!(dest))
            }
            Method::DeleteSession { session_id } => {
                Ok(json!(self.db()?.delete_session(&session_id).map_err(hs)?))
            }
            Method::DeleteEvents { ids } => {
                if ids.len() > 10_000 {
                    return Err(HandlerError::bad_request("too many ids"));
                }
                Ok(json!(self.db()?.delete_events(&ids).map_err(hs)?))
            }
            Method::DeleteAll => Ok(json!(self.db()?.delete_all().map_err(hs)?)),
            Method::ApplyRetention => Ok(json!(self.apply_retention()?)),
            Method::McpServers => self.mcp_servers(),
            Method::Export { format, query } => self.export(&format, &query),
            Method::Report { kind, window_hours } => self.report(&kind, window_hours),
            Method::Subscribe { .. } => Err(HandlerError::bad_request(
                "subscribe is handled by the transport",
            )),
            Method::Shutdown { actor } => {
                tracing::info!("shutdown requested by {actor} via {client}");
                Ok(json!({ "stopping": true }))
            }
        }
    }

    fn subscribe(
        &self,
        after_id: i64,
    ) -> Result<(Vec<Value>, broadcast::Receiver<Value>), HandlerError> {
        // Subscribe first, then read the backlog, so nothing falls in between; the client
        // de-duplicates by id.
        let rx = self.tx.subscribe();
        let rows = self
            .db()?
            .list(&EventQuery {
                after_id: Some(after_id.max(0)),
                limit: Some(500),
                ..Default::default()
            })
            .map_err(hs)?;
        let backlog = rows
            .into_iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect();
        Ok((backlog, rx))
    }

    fn shutdown_requested(&self) {
        self.shutdown.notify_one();
    }
}

/// Run the daemon in the foreground until Ctrl-C or a Shutdown request.
pub fn run(paths: Paths) -> Result<(), String> {
    let daemon = Daemon::new(paths.clone())?;
    let token = agentshield_ipc::new_token().map_err(|e| e.to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("agentshield-daemon")
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        // Token & pid files (user-private directory).
        let tp = paths.token_file();
        agentshield_core::paths::write_atomic(&tp, token.as_bytes())
            .map_err(|e| format!("token file: {e}"))?;
        let _ = agentshield_core::paths::restrict_file(&tp);
        let _ = agentshield_core::paths::write_atomic(
            &paths.pid_file(),
            std::process::id().to_string().as_bytes(),
        );
        match daemon.apply_retention() {
            Ok(n) if n > 0 => tracing::info!("retention removed {n} old events"),
            Ok(_) => {}
            Err(e) => tracing::warn!("retention failed: {}", e.message),
        }
        let d2 = daemon.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            t.tick().await;
            loop {
                t.tick().await;
                let d = d2.clone();
                let _ = tokio::task::spawn_blocking(move || d.apply_retention()).await;
            }
        });
        let cfg = ServerConfig::new(&paths.data_dir, token, agentshield_core::VERSION);
        let handler: Arc<dyn Handler> = daemon.clone();
        let d3 = daemon.clone();
        tracing::info!(
            "AgentShield daemon {} listening on {}",
            agentshield_core::VERSION,
            agentshield_ipc::endpoint(&paths.data_dir).display()
        );
        let res = serve(cfg, handler, async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("Ctrl-C received"),
                _ = d3.shutdown.notified() => {},
            }
        })
        .await;
        let _ = std::fs::remove_file(paths.token_file());
        let _ = std::fs::remove_file(paths.pid_file());
        res.map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests;
