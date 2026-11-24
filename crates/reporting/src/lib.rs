//! Exports and reports. Input records are already redacted by the core; these functions
//! only format. HTML output is static (no scripts) and escapes every value.

use agentshield_audit_log::{EventRow, Incident, SessionSummary, Stats};
use agentshield_event_model::{AuditRecord, RiskLevel};
use std::fmt::Write as _;

pub const TOOL_URI: &str = "https://www.vandeblaak.com";

/// HTML-escape.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn csv_field(s: &str) -> String {
    // Prevent CSV/formula injection in spreadsheet apps.
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn to_json(rows: &[EventRow]) -> String {
    let v: Vec<&AuditRecord> = rows.iter().map(|r| &r.record).collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "agentshield-export",
        "version": 1,
        "generated_utc": agentshield_event_model::now_rfc3339(),
        "note": "All values are redacted by AgentShield before storage. File contents and prompts are never stored.",
        "count": v.len(),
        "events": v,
    }))
    .unwrap_or_default()
}

pub fn to_csv(rows: &[EventRow]) -> String {
    let mut o = String::from(
        "id,ts_utc,agent,session_id,workspace,hook_event,phase,action_type,tool,summary,risk_score,risk_level,confidence,categories,mode,simulated_decision,actual_decision,outcome,observed_outcome,coverage,policy_version,matched_rules,latency_us,hash\n",
    );
    for r in rows {
        let x = &r.record;
        let fields = [
            x.id.to_string(),
            x.ts_utc.clone(),
            x.agent.clone(),
            x.session_id.clone().unwrap_or_default(),
            x.workspace.clone().unwrap_or_default(),
            x.hook_event.clone(),
            x.phase.as_str().into(),
            x.action_type.clone(),
            x.tool.clone().unwrap_or_default(),
            x.summary.clone(),
            x.risk.score.to_string(),
            x.risk.level.as_str().into(),
            x.risk.confidence.as_str().into(),
            x.risk
                .categories
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(";"),
            x.mode.as_str().into(),
            x.simulated_decision.as_str().into(),
            x.actual_decision.as_str().into(),
            x.outcome.as_str().into(),
            r.observed_outcome
                .map(|o| o.as_str().to_string())
                .unwrap_or_default(),
            x.coverage.as_str().into(),
            x.policy_version.clone(),
            x.matched_rules.join(";"),
            x.latency_us.to_string(),
            x.hash.clone(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        o.push_str(&line.join(","));
        o.push('\n');
    }
    o
}

/// SARIF 2.1.0: one result per finding of events with score >= 20.
pub fn to_sarif(rows: &[EventRow], version: &str) -> String {
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for r in rows {
        let x = &r.record;
        if x.risk.score < 20 {
            continue;
        }
        for f in &x.risk.findings {
            if seen.insert(f.id.clone()) {
                rules.push(serde_json::json!({
                    "id": f.id,
                    "shortDescription": { "text": f.explanation.chars().take(120).collect::<String>() },
                    "properties": { "category": f.category.as_str() },
                    "help": { "text": f.mitigation.clone().unwrap_or_default() },
                }));
            }
            let level = match RiskLevel::from_score(f.score) {
                RiskLevel::Critical | RiskLevel::High => "error",
                RiskLevel::Medium => "warning",
                _ => "note",
            };
            let mut res = serde_json::json!({
                "ruleId": f.id,
                "level": level,
                "message": { "text": format!("{} — {}", f.explanation, x.summary) },
                "properties": {
                    "eventId": x.id, "score": f.score, "eventScore": x.risk.score, "confidence": f.confidence.as_str(),
                    "category": f.category.as_str(), "session": x.session_id, "agent": x.agent,
                    "simulatedDecision": x.simulated_decision.as_str(), "actualDecision": x.actual_decision.as_str(),
                    "timestampUtc": x.ts_utc,
                },
            });
            if let Some(p) = x.action.paths().first() {
                res["locations"] = serde_json::json!([{ "physicalLocation": { "artifactLocation": { "uri": p.replace('\\', "/") } } }]);
            }
            results.push(res);
        }
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "Erik's AgentShield", "version": version, "informationUri": TOOL_URI, "rules": rules } },
            "results": results,
        }],
    }))
    .unwrap_or_default()
}

const CSS: &str = r#"
:root{--bg:#0b1020;--panel:#121a2e;--line:#22304d;--text:#e6ecf8;--muted:#93a1bd;--crit:#f43f5e;--high:#fb923c;--med:#fbbf24;--low:#22d3ee;--info:#64748b;--ok:#34d399}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 "Segoe UI",Inter,system-ui,sans-serif;background:var(--bg);color:var(--text)}
header{padding:32px 40px;background:linear-gradient(135deg,#111a33,#0b1020 60%);border-bottom:1px solid var(--line)}
h1{margin:0 0 4px;font-size:26px}h2{font-size:18px;margin:32px 0 12px}.sub{color:var(--muted)}
main{padding:8px 40px 40px;max-width:1280px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}.kpi b{display:block;font-size:24px}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
code{font:12.5px/1.4 "JetBrains Mono",Consolas,monospace;word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.critical{background:#f43f5e22;color:var(--crit)}.high{background:#fb923c22;color:var(--high)}.medium{background:#fbbf2422;color:var(--med)}.low{background:#22d3ee22;color:var(--low)}.informational{background:#64748b22;color:#cbd5e1}
.note{background:#fbbf2414;border:1px solid #fbbf2455;border-radius:10px;padding:10px 14px;color:#fde68a}
footer{padding:24px 40px;color:var(--muted);border-top:1px solid var(--line)}
@media print{body{background:#fff;color:#111}header,table,.kpi{background:#fff}}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Daily,
    Weekly,
    Project,
    AgentComparison,
    Shadow,
    Incident,
    Coverage,
}

impl std::str::FromStr for ReportKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "daily" => ReportKind::Daily,
            "weekly" => ReportKind::Weekly,
            "project" => ReportKind::Project,
            "agent_comparison" | "agents" => ReportKind::AgentComparison,
            "shadow" => ReportKind::Shadow,
            "incident" | "incidents" => ReportKind::Incident,
            "coverage" => ReportKind::Coverage,
            o => return Err(format!("unknown report kind '{o}'")),
        })
    }
}

impl ReportKind {
    pub fn title(self) -> &'static str {
        match self {
            ReportKind::Daily => "Daily security report",
            ReportKind::Weekly => "Weekly security report",
            ReportKind::Project => "Project security report",
            ReportKind::AgentComparison => "Agent comparison report",
            ReportKind::Shadow => "Shadow Mode report",
            ReportKind::Incident => "Incident report",
            ReportKind::Coverage => "Security coverage report",
        }
    }
    pub fn slug(self) -> &'static str {
        match self {
            ReportKind::Daily => "daily",
            ReportKind::Weekly => "weekly",
            ReportKind::Project => "project",
            ReportKind::AgentComparison => "agent-comparison",
            ReportKind::Shadow => "shadow",
            ReportKind::Incident => "incident",
            ReportKind::Coverage => "coverage",
        }
    }
}

/// Inputs for a report.
pub struct ReportData<'a> {
    pub kind: ReportKind,
    pub window_hours: u32,
    pub stats: &'a Stats,
    pub risky: &'a [EventRow],
    pub sessions: &'a [SessionSummary],
    pub incidents: &'a [Incident],
    /// (capability, status, reason)
    pub coverage: &'a [(String, String, String)],
    pub mode: &'a str,
    pub policy: &'a str,
    pub version: &'a str,
}

fn kpi(o: &mut String, label: &str, v: impl std::fmt::Display) {
    let _ = write!(
        o,
        r#"<div class="kpi"><span>{}</span><b>{}</b></div>"#,
        esc(label),
        esc(&v.to_string())
    );
}

fn events_table(o: &mut String, rows: &[EventRow], limit: usize) {
    if rows.is_empty() {
        o.push_str("<p class=\"sub\">No events in this period.</p>");
        return;
    }
    o.push_str("<table><tr><th>Time (UTC)</th><th>Risk</th><th>Action</th><th>Summary</th><th>Would</th><th>Actual</th><th>Top finding</th></tr>");
    for r in rows.iter().take(limit) {
        let x = &r.record;
        let lvl = x.risk.level.as_str();
        let top = x
            .risk
            .findings
            .first()
            .map(|f| format!("{} — {}", f.id, f.explanation))
            .unwrap_or_default();
        let _ = write!(
            o,
            "<tr><td><code>{}</code></td><td><span class=\"pill {lvl}\">{} {}</span></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&x.ts_utc),
            x.risk.score,
            esc(lvl),
            esc(&x.action_type),
            esc(&x.summary),
            esc(x.simulated_decision.as_str()),
            esc(x.actual_decision.as_str()),
            esc(&top)
        );
    }
    o.push_str("</table>");
}

/// Render a self-contained HTML report.
pub fn report_html(d: &ReportData) -> String {
    let s = d.stats;
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>{}</title><style>{CSS}</style></head><body>",
        esc(d.kind.title())
    );
    let _ = write!(
        o,
        "<header><h1>{}</h1><div class=\"sub\">Erik&#39;s AgentShield {} · generated {} UTC · window {} h · mode <b>{}</b> · policy <b>{}</b></div></header><main>",
        esc(d.kind.title()),
        esc(d.version),
        esc(&chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string()),
        d.window_hours,
        esc(d.mode),
        esc(d.policy)
    );
    o.push_str("<p class=\"note\">Risk scores are policy classifications, not probabilities. Correlations are not proof of causality. A network event shows an intended or observed connection, never that data was leaked. All values were redacted before storage.</p>");
    o.push_str("<div class=\"kpis\">");
    kpi(&mut o, "Events", s.events_in_window);
    kpi(&mut o, "Risky (≥40)", s.risky_events);
    kpi(&mut o, "Would block", s.would_block);
    kpi(&mut o, "Would ask", s.would_ask);
    kpi(&mut o, "Actually blocked", s.actually_blocked);
    kpi(&mut o, "Asked user", s.actually_asked);
    kpi(&mut o, "Degraded", s.degraded_events);
    kpi(&mut o, "Dropped", s.dropped_events);
    o.push_str("</div>");
    match d.kind {
        ReportKind::Daily | ReportKind::Weekly => {
            o.push_str(
                "<h2>Top risk categories</h2><table><tr><th>Category</th><th>Events</th></tr>",
            );
            for c in s.by_category.iter().take(12) {
                let _ = write!(o, "<tr><td>{}</td><td>{}</td></tr>", esc(&c.key), c.count);
            }
            o.push_str("</table><h2>Highest-risk events</h2>");
            events_table(&mut o, d.risky, 50);
            o.push_str("<h2>Sessions</h2>");
            sessions_table(&mut o, d.sessions);
        }
        ReportKind::Project => {
            o.push_str("<h2>Projects</h2><table><tr><th>Workspace</th><th>Events</th></tr>");
            for c in &s.top_workspaces {
                let _ = write!(
                    o,
                    "<tr><td><code>{}</code></td><td>{}</td></tr>",
                    esc(&c.key),
                    c.count
                );
            }
            o.push_str("</table><h2>Risky events per project</h2>");
            let mut by_ws: std::collections::BTreeMap<String, Vec<EventRow>> = Default::default();
            for r in d.risky {
                by_ws
                    .entry(
                        r.record
                            .workspace
                            .clone()
                            .unwrap_or_else(|| "(unknown)".into()),
                    )
                    .or_default()
                    .push(r.clone());
            }
            for (ws, rows) in by_ws {
                let _ = write!(o, "<h2><code>{}</code></h2>", esc(&ws));
                events_table(&mut o, &rows, 25);
            }
        }
        ReportKind::AgentComparison => {
            o.push_str("<h2>Agents</h2><table><tr><th>Agent</th><th>Events</th></tr>");
            for c in &s.by_agent {
                let _ = write!(o, "<tr><td>{}</td><td>{}</td></tr>", esc(&c.key), c.count);
            }
            o.push_str("</table><p class=\"sub\">AgentShield currently integrates with Claude Code only; other agents are not monitored.</p>");
        }
        ReportKind::Shadow => {
            o.push_str("<h2>What Enforce Mode would have done</h2><p>Events below were rated <b>deny</b> or <b>ask</b> by the active policy while AgentShield was observing. In Enforce Mode they would have been blocked or sent to Claude Code's approval prompt.</p>");
            let would: Vec<EventRow> = d
                .risky
                .iter()
                .filter(|r| {
                    r.record.simulated_decision.rank()
                        >= agentshield_event_model::PolicyDecision::Ask.rank()
                })
                .cloned()
                .collect();
            events_table(&mut o, &would, 200);
        }
        ReportKind::Incident => {
            o.push_str("<h2>Incidents</h2>");
            if d.incidents.is_empty() {
                o.push_str("<p class=\"sub\">No incidents in this period.</p>");
            } else {
                o.push_str("<table><tr><th>Time</th><th>Severity</th><th>Title</th><th>Explanation</th><th>Evidence events</th></tr>");
                for i in d.incidents {
                    let ids = i
                        .event_ids
                        .iter()
                        .map(|x| format!("#{x}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = write!(
                        o,
                        "<tr><td><code>{}</code></td><td><span class=\"pill {}\">{} ({})</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        esc(&i.ts_utc),
                        esc(&i.severity),
                        esc(&i.severity),
                        i.score,
                        esc(&i.title),
                        esc(&i.explanation),
                        esc(&ids)
                    );
                }
                o.push_str("</table>");
            }
            o.push_str("<h2>Related high-risk events</h2>");
            events_table(&mut o, d.risky, 50);
        }
        ReportKind::Coverage => {
            o.push_str("<h2>Integration coverage</h2><table><tr><th>Capability</th><th>Status</th><th>Why</th></tr>");
            for (c, st, why) in d.coverage {
                let cls = match st.as_str() {
                    "enforced" => "low",
                    "observed" => "informational",
                    "partial" | "unverified" => "medium",
                    _ => "high",
                };
                let _ = write!(
                    o,
                    "<tr><td>{}</td><td><span class=\"pill {cls}\">{}</span></td><td>{}</td></tr>",
                    esc(c),
                    esc(st),
                    esc(why)
                );
            }
            o.push_str("</table><p class=\"note\">AgentShield never claims complete protection. Unsupported capabilities are not monitored.</p>");
        }
    }
    let _ = write!(
        o,
        "</main><footer>Erik&#39;s AgentShield — Local AI Agent Security &amp; Observability · Developed by Erik van de Blaak · vandeblaak.com</footer></body></html>"
    );
    o
}

fn sessions_table(o: &mut String, sessions: &[SessionSummary]) {
    if sessions.is_empty() {
        o.push_str("<p class=\"sub\">No sessions.</p>");
        return;
    }
    o.push_str("<table><tr><th>Session</th><th>Workspace</th><th>Start</th><th>Events</th><th>Max risk</th><th>Would block</th><th>Blocked</th></tr>");
    for s in sessions.iter().take(50) {
        let _ = write!(
            o,
            "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&s.session_id.chars().take(12).collect::<String>()),
            esc(s.workspace.as_deref().unwrap_or("")),
            esc(&s.first_ts),
            s.events,
            s.max_score,
            s.would_block,
            s.blocked
        );
    }
    o.push_str("</table>");
}

/// Export as standalone HTML table.
pub fn to_html(rows: &[EventRow], version: &str) -> String {
    let stats = Stats {
        events_in_window: rows.len() as u64,
        risky_events: rows.iter().filter(|r| r.record.risk.score >= 40).count() as u64,
        ..Default::default()
    };
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Erik&#39;s AgentShield export</title><style>{CSS}</style></head><body><header><h1>Erik&#39;s AgentShield — event export</h1><div class=\"sub\">{} events · AgentShield {} · redacted</div></header><main>",
        stats.events_in_window,
        esc(version)
    );
    events_table(&mut o, rows, usize::MAX);
    o.push_str("</main></body></html>");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentshield_event_model::*;

    fn row(summary: &str, score: u8) -> EventRow {
        let r = AuditRecord {
            id: 1,
            uuid: "u".into(),
            schema_version: 1,
            ts_utc: now_rfc3339(),
            agent: "claude-code".into(),
            agent_version: None,
            session_id: Some("s".into()),
            workspace: Some("/w".into()),
            hook_event: "PreToolUse".into(),
            phase: Phase::Pre,
            action_type: "file.read".into(),
            tool: Some("Read".into()),
            summary: summary.into(),
            action: ActionKind::FileRead {
                path: "/w/.env".into(),
            },
            input_redacted: serde_json::json!({}),
            risk: RiskAssessment {
                score,
                level: RiskLevel::from_score(score),
                findings: vec![Finding {
                    id: "path.env_file.read".into(),
                    category: RiskCategory::SecretAccess,
                    score,
                    confidence: Confidence::High,
                    explanation: "Reads env".into(),
                    evidence: None,
                    mitigation: None,
                }],
                ..RiskAssessment::none()
            },
            policy_version: "v".into(),
            policy_name: "p".into(),
            matched_rules: vec![],
            mode: Mode::Monitor,
            simulated_decision: PolicyDecision::Ask,
            decision_reason: None,
            actual_decision: ActualDecision::NoOpinion,
            outcome: Outcome::Pending,
            coverage: Coverage::Enforceable,
            latency_us: 1,
            correlation_id: None,
            via_daemon: true,
            prev_hash: String::new(),
            hash: "h".into(),
        };
        EventRow {
            record: r,
            observed_outcome: None,
        }
    }

    #[test]
    fn html_is_escaped() {
        let h = to_html(&[row("<script>alert(1)</script>", 70)], "0.1");
        assert!(!h.contains("<script>alert"));
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.to_lowercase().contains("<script"));
    }

    #[test]
    fn csv_injection_guard() {
        let c = to_csv(&[row("=HYPERLINK(\"http://x\")", 10)]);
        assert!(c.contains("\"'=HYPERLINK(\"\"http://x\"\")\""), "{c}");
    }

    #[test]
    fn sarif_shape() {
        let s: serde_json::Value =
            serde_json::from_str(&to_sarif(&[row("read .env", 70), row("ls", 0)], "0.1")).unwrap();
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/w/.env"
        );
    }

    #[test]
    fn reports_render_all_kinds() {
        let st = Stats::default();
        let rows = vec![row("<b>x</b>", 85)];
        for k in [
            "daily",
            "weekly",
            "project",
            "agent_comparison",
            "shadow",
            "incident",
            "coverage",
        ] {
            let kind: ReportKind = k.parse().unwrap();
            let cov = vec![(
                "Shell blocking".to_string(),
                "enforced".to_string(),
                "<why>".to_string(),
            )];
            let h = report_html(&ReportData {
                kind,
                window_hours: 24,
                stats: &st,
                risky: &rows,
                sessions: &[],
                incidents: &[],
                coverage: &cov,
                mode: "monitor",
                policy: "p",
                version: "0.1",
            });
            assert!(h.contains(kind.title()));
            assert!(!h.contains("<b>x</b>"));
            assert!(!h.contains("<why>"));
        }
    }
}
