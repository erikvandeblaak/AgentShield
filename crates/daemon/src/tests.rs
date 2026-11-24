use super::*;

fn daemon() -> (tempfile::TempDir, Arc<Daemon>) {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::new(Paths::under(dir.path())).unwrap();
    (dir, d)
}

fn fixture(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/claude-code")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn hook_flow_monitor_then_enforce() {
    let (_d, d) = daemon();
    // Monitor (default): no output even for a critical action.
    let r = d
        .handle_hook("claude-code", None, &fixture("pre_tool_use_exfil.json"))
        .unwrap();
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.is_none());
    assert!(r.event_id > 0);
    let row = d.db().unwrap().get(r.event_id).unwrap().unwrap();
    assert_eq!(row.record.simulated_decision, PolicyDecision::Deny);
    assert_eq!(row.record.actual_decision, ActualDecision::NoOpinion);
    // Enforce: deny JSON.
    d.set_mode(Mode::Enforce, "test").unwrap();
    let r = d
        .handle_hook("claude-code", None, &fixture("pre_tool_use_exfil.json"))
        .unwrap();
    let v: Value = serde_json::from_str(r.stdout.as_deref().unwrap()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    // Benign command: still no output in enforce.
    let ok = d
        .handle_hook("claude-code", None, &fixture("pre_tool_use_bash.json"))
        .unwrap();
    assert!(ok.stdout.is_none());
    // Post event correlates outcome.
    d.handle_hook("claude-code", None, &fixture("post_tool_use_bash.json"))
        .unwrap();
    let pre = d.db().unwrap().get(ok.event_id).unwrap().unwrap();
    assert_eq!(pre.observed_outcome, Some(Outcome::Executed));
    // Mode change was logged.
    let changes = d
        .db()
        .unwrap()
        .list(&EventQuery {
            action_type: Some("agentshield.mode_change".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert!(d.db().unwrap().verify().unwrap().ok);
}

#[test]
fn malformed_payload_is_rejected_and_counted() {
    let (_d, d) = daemon();
    assert!(d.handle_hook("claude-code", None, &json!("nope")).is_err());
    assert!(d.handle_hook("other-agent", None, &json!({})).is_err());
    assert_eq!(d.status()["dropped_events"], 1);
}

#[test]
fn correlation_creates_incident() {
    let (_d, d) = daemon();
    d.handle_hook("claude-code", None, &json!({"session_id": "s9", "cwd": "/p", "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/home/x/.aws/credentials"}, "tool_use_id": "a"})).unwrap();
    d.handle_hook("claude-code", None, &json!({"session_id": "s9", "cwd": "/p", "hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://example.com/u", "prompt": "x"}, "tool_use_id": "b"})).unwrap();
    let inc = d.db().unwrap().incidents(10).unwrap();
    assert_eq!(inc.len(), 1, "{inc:?}");
    assert_eq!(inc[0].event_ids.len(), 2);
    assert!(inc[0].explanation.contains("do not prove"));
}

#[test]
fn handler_methods() {
    let (_d, d) = daemon();
    let s = d.handle(Method::Status, "t").unwrap();
    assert_eq!(s["mode"], "monitor");
    assert_eq!(s["preset"], "developer-balanced");
    let sim = d
        .handle(
            Method::Simulate {
                input: json!({"command": "rm -rf /"}),
            },
            "t",
        )
        .unwrap();
    assert_eq!(sim["modes"]["enforce"]["actual"], "deny");
    assert_eq!(sim["modes"]["monitor"]["actual"], "no_opinion");
    let sim2 = d
        .handle(
            Method::Simulate {
                input: json!({"tool": "Read", "tool_input": {"file_path": "/p/.env"}}),
            },
            "t",
        )
        .unwrap();
    assert_eq!(sim2["policy"]["decision"], "ask");
    assert!(
        d.handle(Method::Simulate { input: json!({}) }, "t")
            .is_err()
    );
    let v = d
        .handle(
            Method::ValidatePolicy {
                text: "schema_version = 1".into(),
            },
            "t",
        )
        .unwrap();
    assert_eq!(v["ok"], true);
    let bad = d
        .handle(Method::ValidatePolicy { text: "x".into() }, "t")
        .unwrap();
    assert_eq!(bad["ok"], false);
    assert!(
        d.handle(
            Method::SaveUserPolicy {
                text: "nope".into()
            },
            "t"
        )
        .is_err()
    );
    let p = d.handle(Method::SaveUserPolicy { text: "schema_version = 1\n[[rules]]\nid='x'\n[rules.match]\nprograms=['make']\n[rules.effect]\naction='deny'\n".into() }, "t").unwrap();
    assert!(
        p["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "x")
    );
    assert!(
        d.handle(
            Method::SetPreset {
                preset: "nope".into(),
                actor: "t".into()
            },
            "t"
        )
        .is_err()
    );
    d.handle(
        Method::SetPreset {
            preset: "strict-security".into(),
            actor: "t".into(),
        },
        "t",
    )
    .unwrap();
    assert_eq!(
        d.handle(Method::GetConfig, "t").unwrap()["preset"],
        "strict-security"
    );
    assert!(
        d.handle(
            Method::SetConfig {
                patch: json!({"retention_days": 0})
            },
            "t"
        )
        .is_err()
    );
    assert_eq!(
        d.handle(
            Method::SetConfig {
                patch: json!({"language": "nl"})
            },
            "t"
        )
        .unwrap()["language"],
        "nl"
    );
    d.handle(
        Method::SetPaused {
            paused: true,
            actor: "t".into(),
        },
        "t",
    )
    .unwrap();
    assert_eq!(d.status()["paused"], true);
    // exports & reports
    d.handle_hook("claude-code", None, &fixture("pre_tool_use_read_env.json"))
        .unwrap();
    for f in ["json", "csv", "sarif", "html"] {
        let r = d
            .handle(
                Method::Export {
                    format: f.into(),
                    query: EventQuery::default(),
                },
                "t",
            )
            .unwrap();
        assert!(std::path::Path::new(r["path"].as_str().unwrap()).is_file());
    }
    for k in [
        "daily",
        "weekly",
        "project",
        "agent_comparison",
        "shadow",
        "incident",
        "coverage",
    ] {
        let r = d
            .handle(
                Method::Report {
                    kind: k.into(),
                    window_hours: 24,
                },
                "t",
            )
            .unwrap();
        assert!(
            std::path::Path::new(r["path"].as_str().unwrap()).is_file(),
            "{k}"
        );
    }
    let rep = d
        .handle(
            Method::Replay {
                preset: "observe-everything".into(),
                session_id: None,
                limit: 100,
            },
            "t",
        )
        .unwrap();
    assert!(rep["evaluated"].as_u64().unwrap() >= 1);
    assert_eq!(d.handle(Method::Verify, "t").unwrap()["ok"], true);
    let b = d.handle(Method::Backup, "t").unwrap();
    assert!(std::path::Path::new(b.as_str().unwrap()).is_file());
    let _ = d.handle(Method::McpServers, "t").unwrap();
}

#[test]
fn invalid_config_degrades_instead_of_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let p = Paths::under(dir.path());
    p.ensure().unwrap();
    std::fs::write(p.config_file(), "mode = 'bogus'").unwrap();
    let d = Daemon::new(p.clone()).unwrap();
    assert_eq!(d.status()["degraded"], true);
    assert_eq!(
        std::fs::read_to_string(p.config_file()).unwrap(),
        "mode = 'bogus'"
    );
}
